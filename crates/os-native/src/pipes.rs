//! POSIX pipe buffer (`Send + Sync`) with 64 KiB ring capacity, `PIPE_BUF = 4096` atomic writes,
//! EOF markers (for PTY canonical `Ctrl-D`), blocking/nonblocking semantics, and wakeups.

use abi::Errno;
use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

pub const PIPE_CAPACITY: usize = 64 * 1024;
pub const PIPE_BUF: usize = 4096;

struct Inner {
    buf: VecDeque<u8>,
    /// Queued EOF positions (byte counts before a zero-length read boundary, used by PTY VEOF).
    eof_marks: VecDeque<usize>,
    readers: usize,
    writers: usize,
    read_nonblock: bool,
    write_nonblock: bool,
    version: u64,
}

/// Shared POSIX pipe backing both `fd_pipe` and PTY slave input queues.
pub struct PipeBuf {
    inner: Mutex<Inner>,
    cv: Condvar,
}

impl PipeBuf {
    pub fn new(readers: usize, writers: usize) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                buf: VecDeque::with_capacity(4096),
                eof_marks: VecDeque::new(),
                readers,
                writers,
                read_nonblock: false,
                write_nonblock: false,
                version: 0,
            }),
            cv: Condvar::new(),
        })
    }

    pub fn add_reader(&self) {
        let mut g = self.inner.lock().unwrap();
        g.readers += 1;
        g.version = g.version.wrapping_add(1);
        self.cv.notify_all();
    }

    pub fn add_writer(&self) {
        let mut g = self.inner.lock().unwrap();
        g.writers += 1;
        g.version = g.version.wrapping_add(1);
        self.cv.notify_all();
    }

    pub fn drop_reader(&self) {
        let mut g = self.inner.lock().unwrap();
        g.readers = g.readers.saturating_sub(1);
        g.version = g.version.wrapping_add(1);
        self.cv.notify_all();
    }

    pub fn drop_writer(&self) {
        let mut g = self.inner.lock().unwrap();
        g.writers = g.writers.saturating_sub(1);
        g.version = g.version.wrapping_add(1);
        self.cv.notify_all();
    }

    pub fn set_nonblock(&self, reader_side: bool, nonblock: bool) {
        let mut g = self.inner.lock().unwrap();
        if reader_side {
            g.read_nonblock = nonblock;
        } else {
            g.write_nonblock = nonblock;
        }
    }

    pub fn is_nonblock(&self, reader_side: bool) -> bool {
        let g = self.inner.lock().unwrap();
        if reader_side {
            g.read_nonblock
        } else {
            g.write_nonblock
        }
    }

    pub fn queued(&self) -> usize {
        self.inner.lock().unwrap().buf.len()
    }

    pub fn room(&self) -> usize {
        PIPE_CAPACITY.saturating_sub(self.inner.lock().unwrap().buf.len())
    }

    pub fn reader_gone(&self) -> bool {
        self.inner.lock().unwrap().readers == 0
    }

    pub fn writer_gone(&self) -> bool {
        self.inner.lock().unwrap().writers == 0
    }

    /// Discard all buffered input bytes and pending EOF marks (e.g., on `SIGINT` / `TCSETSF`).
    pub fn discard(&self) {
        let mut g = self.inner.lock().unwrap();
        g.buf.clear();
        g.eof_marks.clear();
        g.version = g.version.wrapping_add(1);
        self.cv.notify_all();
    }

    /// Push a canonical EOF boundary after all currently buffered bytes.
    pub fn push_eof(&self) {
        let mut g = self.inner.lock().unwrap();
        let len = g.buf.len();
        g.eof_marks.push_back(len);
        g.version = g.version.wrapping_add(1);
        self.cv.notify_all();
    }

    /// Non-blocking put used by the PTY master pump. Returns bytes accepted.
    pub fn try_put(&self, data: &[u8]) -> usize {
        let mut g = self.inner.lock().unwrap();
        if g.readers == 0 {
            return 0;
        }
        let room = PIPE_CAPACITY.saturating_sub(g.buf.len());
        let take = data.len().min(room);
        if take > 0 {
            g.buf.extend(&data[..take]);
            g.version = g.version.wrapping_add(1);
            self.cv.notify_all();
        }
        take
    }

    /// Poll readability/writability. Returns `(ready, nbytes, hangup)`.
    pub fn poll(&self, writing: bool) -> (bool, usize, bool) {
        let g = self.inner.lock().unwrap();
        if writing {
            let hangup = g.readers == 0;
            let room = PIPE_CAPACITY.saturating_sub(g.buf.len());
            let ready = hangup || room > 0;
            (ready, if hangup { 0 } else { room }, hangup)
        } else {
            let hangup = g.writers == 0;
            let has_eof = g.eof_marks.front().copied() == Some(0);
            let nbytes = g.buf.len();
            let ready = nbytes > 0 || has_eof || hangup;
            (ready, nbytes, hangup)
        }
    }

    /// Read from the pipe, invoking `check_interrupt` periodically while blocked.
    pub fn read(
        &self,
        out: &mut [u8],
        nonblock_override: bool,
        mut check_interrupt: impl FnMut() -> Result<(), Errno>,
    ) -> Result<usize, Errno> {
        if out.is_empty() {
            return Ok(0);
        }
        let mut g = self.inner.lock().unwrap();
        loop {
            if let Some(&0) = g.eof_marks.front() {
                g.eof_marks.pop_front();
                return Ok(0);
            }
            if !g.buf.is_empty() {
                let limit = g
                    .eof_marks
                    .front()
                    .copied()
                    .unwrap_or(g.buf.len())
                    .min(out.len())
                    .min(g.buf.len());
                for (i, slot) in out.iter_mut().take(limit).enumerate() {
                    *slot = g.buf.pop_front().unwrap();
                    let _ = i;
                }
                for mark in &mut g.eof_marks {
                    *mark = mark.saturating_sub(limit);
                }
                g.version = g.version.wrapping_add(1);
                self.cv.notify_all();
                return Ok(limit);
            }
            if g.writers == 0 {
                return Ok(0);
            }
            if nonblock_override || g.read_nonblock {
                return Err(Errno::EAGAIN);
            }
            drop(g);
            check_interrupt()?;
            g = self.inner.lock().unwrap();
            if g.buf.is_empty() && g.eof_marks.front().copied() != Some(0) && g.writers > 0 {
                let (next_g, _) = self.cv.wait_timeout(g, Duration::from_millis(20)).unwrap();
                g = next_g;
            }
        }
    }

    /// Write to the pipe. Returns `Err(Errno::EPIPE)` if all readers are gone.
    pub fn write(
        &self,
        data: &[u8],
        nonblock_override: bool,
        mut check_interrupt: impl FnMut() -> Result<(), Errno>,
    ) -> Result<usize, Errno> {
        if data.is_empty() {
            let g = self.inner.lock().unwrap();
            return if g.readers == 0 {
                Err(Errno::EPIPE)
            } else {
                Ok(0)
            };
        }
        let atomic = data.len() <= PIPE_BUF;
        let mut written = 0usize;
        let mut g = self.inner.lock().unwrap();
        loop {
            if g.readers == 0 {
                return if written > 0 {
                    Ok(written)
                } else {
                    Err(Errno::EPIPE)
                };
            }
            let room = PIPE_CAPACITY.saturating_sub(g.buf.len());
            let want = data.len() - written;
            if atomic && written == 0 {
                if room >= want {
                    g.buf.extend(data);
                    g.version = g.version.wrapping_add(1);
                    self.cv.notify_all();
                    return Ok(data.len());
                }
                if nonblock_override || g.write_nonblock {
                    return Err(Errno::EAGAIN);
                }
            } else if room > 0 {
                let take = want.min(room);
                g.buf.extend(&data[written..written + take]);
                written += take;
                g.version = g.version.wrapping_add(1);
                self.cv.notify_all();
                if written == data.len() || nonblock_override || g.write_nonblock {
                    return Ok(written);
                }
                continue;
            } else if nonblock_override || g.write_nonblock {
                return if written > 0 {
                    Ok(written)
                } else {
                    Err(Errno::EAGAIN)
                };
            }
            drop(g);
            if let Err(err) = check_interrupt() {
                return if written > 0 { Ok(written) } else { Err(err) };
            }
            g = self.inner.lock().unwrap();
            let room_now = PIPE_CAPACITY.saturating_sub(g.buf.len());
            if g.readers > 0 && ((atomic && room_now < data.len()) || (!atomic && room_now == 0)) {
                let (next_g, _) = self.cv.wait_timeout(g, Duration::from_millis(20)).unwrap();
                g = next_g;
            }
        }
    }

    pub fn notify_all(&self) {
        self.cv.notify_all();
    }
}

/// RAII handle for one end of a `PipeBuf` (ref-counted symmetrically across `Clone` and `Drop`).
pub struct PipeHandle {
    pub buf: Arc<PipeBuf>,
    pub is_writer: bool,
}

impl Clone for PipeHandle {
    fn clone(&self) -> Self {
        self.clone_end()
    }
}

impl PipeHandle {
    pub fn pair() -> (Self, Self) {
        let buf = PipeBuf::new(1, 1);
        (
            Self {
                buf: Arc::clone(&buf),
                is_writer: false,
            },
            Self {
                buf,
                is_writer: true,
            },
        )
    }

    pub fn clone_end(&self) -> Self {
        if self.is_writer {
            self.buf.add_writer();
        } else {
            self.buf.add_reader();
        }
        Self {
            buf: Arc::clone(&self.buf),
            is_writer: self.is_writer,
        }
    }
}

impl Drop for PipeHandle {
    fn drop(&mut self) {
        if self.is_writer {
            self.buf.drop_writer();
        } else {
            self.buf.drop_reader();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_clone_drop_refcounting_and_epipe() {
        let (r, w) = PipeHandle::pair();
        {
            let r2 = r.clone();
            let w2 = w.clone();
            assert_eq!(w2.buf.write(b"hello", false, || Ok(())), Ok(5));
            drop(r2);
            drop(w2);
        }
        assert!(
            !w.buf.reader_gone(),
            "dropping clone must keep original reader alive"
        );
        assert!(
            !r.buf.writer_gone(),
            "dropping clone must keep original writer alive"
        );

        let mut buf = [0u8; 16];
        let n = r.buf.read(&mut buf, false, || Ok(())).unwrap();
        assert_eq!(&buf[..n], b"hello");

        drop(r);
        assert_eq!(w.buf.write(b"x", false, || Ok(())), Err(Errno::EPIPE));
    }
}

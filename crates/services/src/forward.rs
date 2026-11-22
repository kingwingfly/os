//! Best-effort live output must never hold up service management. The separate
//! journal retains its bounded history even when a viewer stops consuming bytes.
use std::{
    collections::VecDeque,
    io,
    time::{Duration, Instant},
};

const LIMIT: usize = 65536;
const FINAL_FLUSH_BUDGET: Duration = Duration::from_millis(500);
const FINAL_FLUSH_POLL: Duration = Duration::from_millis(5);

#[derive(Copy, Clone, Eq, PartialEq)]
enum DrainOutcome {
    Empty,
    More,
    Blocked,
}

#[derive(Default)]
struct Queue {
    bytes: VecDeque<u8>,
    dropped: u64,
    closed: bool,
}
impl Queue {
    fn push(&mut self, bytes: &[u8]) {
        let keep = if self.closed {
            0
        } else {
            bytes.len().min(LIMIT - self.bytes.len())
        };
        self.bytes.extend(&bytes[..keep]);
        self.dropped = self.dropped.saturating_add((bytes.len() - keep) as u64);
    }
    fn drain(&mut self, mut write: impl FnMut(&[u8]) -> io::Result<usize>) -> DrainOutcome {
        for _ in 0..4 {
            let bytes = self.bytes.as_slices().0;
            if bytes.is_empty() {
                return DrainOutcome::Empty;
            }
            match write(&bytes[..bytes.len().min(4096)]) {
                Ok(0) => return DrainOutcome::Blocked,
                Ok(n) => {
                    self.bytes.drain(..n);
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    return DrainOutcome::Blocked;
                }
                Err(_) => {
                    self.closed = true;
                    self.discard();
                    return DrainOutcome::Empty;
                }
            }
        }
        if self.bytes.is_empty() {
            DrainOutcome::Empty
        } else {
            DrainOutcome::More
        }
    }
    fn discard(&mut self) {
        self.dropped = self.dropped.saturating_add(self.bytes.len() as u64);
        self.bytes.clear();
    }
}

fn flush_queues(
    queues: &mut [Queue; 2],
    budget: Duration,
    mut write: impl FnMut(usize, &[u8]) -> io::Result<usize>,
) {
    let deadline = Instant::now() + budget;
    loop {
        let mut any_more = false;
        let mut any_blocked = false;
        for (i, queue) in queues.iter_mut().enumerate() {
            match queue.drain(|bytes| write(i, bytes)) {
                DrainOutcome::Empty => {}
                DrainOutcome::More => any_more = true,
                DrainOutcome::Blocked => any_blocked = true,
            }
        }
        if !any_more && !any_blocked {
            break;
        }
        if any_more {
            continue;
        }
        if Instant::now() >= deadline {
            for queue in queues.iter_mut() {
                queue.discard();
            }
            break;
        }
        std::thread::sleep(FINAL_FLUSH_POLL);
    }
}

pub struct Forward {
    queues: [Queue; 2],
    outputs: [host::Output; 2],
}
impl Forward {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            queues: Default::default(),
            outputs: [host::Output::open(1)?, host::Output::open(2)?],
        })
    }
    pub fn push(&mut self, fd: u32, bytes: &[u8]) {
        self.queues[fd as usize - 1].push(bytes);
    }
    pub fn pump(&mut self, final_pass: bool) {
        if !final_pass {
            for (i, queue) in self.queues.iter_mut().enumerate() {
                let _ = queue.drain(|bytes| self.outputs[i].write(bytes));
            }
            return;
        }
        // On final exit, allow active viewers a bounded window to drain in-flight output
        // credits without ever hanging on a permanently stalled pipe.
        let outputs = &self.outputs;
        flush_queues(&mut self.queues, FINAL_FLUSH_BUDGET, |i, bytes| {
            outputs[i].write(bytes)
        });
    }
    pub fn dropped(&self) -> [u64; 2] {
        self.queues.each_ref().map(|q| q.dropped)
    }
}
#[cfg(target_os = "wasi")]
mod host {
    use std::{fs::File, io, os::wasi::io::AsRawFd};
    #[link(wasm_import_module = "wasi_snapshot_preview1")]
    unsafe extern "C" {
        fn fd_fdstat_get(fd: u32, stat: *mut u8) -> u32;
        fn fd_fdstat_set_flags(fd: u32, flags: u16) -> u32;
        fn fd_write(fd: u32, iovs: *const IoVec, count: usize, written: *mut usize) -> u32;
    }
    #[repr(C)]
    struct IoVec {
        data: *const u8,
        len: usize,
    }
    fn check(code: u32) -> io::Result<()> {
        if code == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(code as i32))
        }
    }
    pub struct Output {
        fd: u32,
        _file: Option<File>,
    }
    impl Output {
        pub fn open(fd: u32) -> io::Result<Self> {
            #[repr(C, align(8))]
            struct Stat([u8; 24]);
            let mut stat = Stat([0; 24]);
            // SAFETY: preview-1 writes a 24-byte fdstat to this aligned buffer.
            check(unsafe { fd_fdstat_get(fd, stat.0.as_mut_ptr()) })?;
            let rights = u64::from_le_bytes(stat.0[8..16].try_into().unwrap());
            // Runtime pipes/page output have type UNKNOWN; terminals are non-seekable
            // character devices. Regular files and byte devices retain their offsets.
            let live = stat.0[0] == 0 || stat.0[0] == 2 && rights & (1 << 2) == 0;
            if !live {
                return Ok(Self { fd, _file: None });
            }
            // O_NONBLOCK belongs to an open description, shared by dup/fork. Reopen
            // privately so even SIGKILL cannot change the parent shell's flags.
            let file = File::options()
                .write(true)
                .open(format!("/proc/self/fd/{fd}"))?;
            os_posix::pipe::close_on_exec(&file)?;
            let fd = file.as_raw_fd() as u32;
            // SAFETY: file owns this private output descriptor.
            check(unsafe { fd_fdstat_set_flags(fd, 4) })?;
            Ok(Self {
                fd,
                _file: Some(file),
            })
        }
        pub fn write(&self, bytes: &[u8]) -> io::Result<usize> {
            let iov = IoVec {
                data: bytes.as_ptr(),
                len: bytes.len(),
            };
            let mut written = 0;
            // SAFETY: input and output storage remain valid for this nonblocking write.
            check(unsafe { fd_write(self.fd, &iov, 1, &mut written) })?;
            Ok(written)
        }
    }
}
#[cfg(not(target_os = "wasi"))]
mod host {
    pub struct Output;
    impl Output {
        pub fn open(_: u32) -> std::io::Result<Self> {
            Ok(Self)
        }
        pub fn write(&self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::Unsupported.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn blocked_viewers_are_bounded_and_partial_writes_preserve_order() {
        let mut queue = Queue::default();
        let input: Vec<u8> = (0..LIMIT + 100).map(|n| n as u8).collect();
        queue.push(&input);
        queue.drain(|_| Err(io::ErrorKind::WouldBlock.into()));
        assert_eq!(queue.bytes.len(), LIMIT);
        assert_eq!(queue.dropped, 100);
        let mut received = Vec::new();
        while !queue.bytes.is_empty() {
            queue.drain(|bytes| {
                let n = bytes.len().min(37);
                received.extend_from_slice(&bytes[..n]);
                Ok(n)
            });
        }
        assert_eq!(received, input[..LIMIT]);
        queue.push(b"pending");
        queue.discard();
        assert_eq!(queue.dropped, 107);
    }
    #[test]
    fn closed_viewers_do_not_abort_supervision_or_grow_queues() {
        let mut queue = Queue::default();
        queue.push(b"old");
        queue.drain(|_| Err(io::ErrorKind::BrokenPipe.into()));
        queue.push(b"new");
        assert!(queue.bytes.is_empty());
        assert_eq!(queue.dropped, 6);
    }

    #[test]
    fn final_flush_recovers_from_transient_wouldblock_and_bounds_stalled_viewers() {
        let mut queues: [Queue; 2] = Default::default();
        queues[0].push(b"CHILD_DONE_1\nCHILD_DONE_2\n");
        queues[1].push(b"supervise: quick-1: exited 0\n");
        let mut calls = 0usize;
        let mut received = [Vec::new(), Vec::new()];
        flush_queues(&mut queues, Duration::from_millis(200), |i, bytes| {
            calls += 1;
            if calls <= 3 {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let n = bytes.len().min(7);
            received[i].extend_from_slice(&bytes[..n]);
            Ok(n)
        });
        assert_eq!(received[0], b"CHILD_DONE_1\nCHILD_DONE_2\n");
        assert_eq!(received[1], b"supervise: quick-1: exited 0\n");
        assert_eq!(queues[0].dropped, 0);
        assert_eq!(queues[1].dropped, 0);

        let mut stalled: [Queue; 2] = Default::default();
        stalled[0].push(b"never-drained");
        flush_queues(&mut stalled, Duration::from_millis(15), |_, _| {
            Err(io::ErrorKind::WouldBlock.into())
        });
        assert!(stalled[0].bytes.is_empty());
        assert_eq!(stalled[0].dropped, b"never-drained".len() as u64);
    }
}

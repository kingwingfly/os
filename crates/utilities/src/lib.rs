//! Portable `wasm32-wasip1`-compatible local account and Service Manager v2 CLI applets
//! (`#57` `L3d`, Contract v2 §2.4, §2.8).
//!
//! Exported as a library target so all 6 applets compile, lint, and unit-test cleanly in Wave 4A
//! without conflicting with Wave 4A Track 2 edits to `src/main.rs` or `crates/core/src/bin.rs`.
//! Wave 4B wires each `::run(&args[1..])` directly into the `utilities` multicall dispatcher.

use abi::{Call, Errno};
use serde_json::Value;
use std::io::{self, BufRead, Write};

pub mod desktop_actions;
pub mod login;
pub mod newgrp;
pub mod passwd;
pub mod service;
pub mod su;
pub mod sudo;

const IOCTL_TCGETS: u32 = 0x5401;
const IOCTL_TCSETS: u32 = 0x5402;
const TERMIOS_ECHO_BIT: u64 = 8;

pub(crate) trait TermiosBackend {
    fn tcgets(&self, fd: u32) -> Result<Value, Errno>;
    fn tcsets(&self, fd: u32, termios: Value) -> Result<(), Errno>;
}

struct OsTermiosBackend;

impl TermiosBackend for OsTermiosBackend {
    fn tcgets(&self, fd: u32) -> Result<Value, Errno> {
        let mut reply = os_posix::batch(&[Call::Ioctl {
            fd: fd.into(),
            request: IOCTL_TCGETS,
            arg: Value::Null,
        }])
        .map_err(|e| os_posix::errno_of(&e).unwrap_or(Errno::ENOTTY))?;
        reply.results.remove(0).into_result().map_err(|e| e.errno)
    }

    fn tcsets(&self, fd: u32, termios: Value) -> Result<(), Errno> {
        let mut reply = os_posix::batch(&[Call::Ioctl {
            fd: fd.into(),
            request: IOCTL_TCSETS,
            arg: termios,
        }])
        .map_err(|e| os_posix::errno_of(&e).unwrap_or(Errno::ENOTTY))?;
        reply
            .results
            .remove(0)
            .into_result()
            .map(|_| ())
            .map_err(|e| e.errno)
    }
}

struct EchoRestoreGuard<'a, T: TermiosBackend> {
    tty: &'a T,
    fd: u32,
    original: Option<Value>,
}

impl<T: TermiosBackend> Drop for EchoRestoreGuard<'_, T> {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            let _ = self.tty.tcsets(self.fd, original);
        }
    }
}

pub(crate) fn prompt_password_with<T: TermiosBackend, R: BufRead, W: Write>(
    prompt: &str,
    tty: &T,
    reader: &mut R,
    writer: &mut W,
) -> Result<String, String> {
    let mut echo_disabled = false;
    let _guard = match tty.tcgets(0) {
        Ok(orig) => {
            if let Some(lflag) = orig.get("lflag").and_then(Value::as_u64)
                && (lflag & TERMIOS_ECHO_BIT) != 0
            {
                let mut muted = orig.clone();
                if let Some(obj) = muted.as_object_mut() {
                    obj.insert("lflag".to_owned(), Value::from(lflag & !TERMIOS_ECHO_BIT));
                }
                tty.tcsets(0, muted).map_err(|errno| {
                    format!("failed to disable terminal echo ({})", errno.text())
                })?;
                echo_disabled = true;
                Some(EchoRestoreGuard {
                    tty,
                    fd: 0,
                    original: Some(orig),
                })
            } else {
                None
            }
        }
        Err(Errno::ENOTTY | Errno::ENOSYS | Errno::EOPNOTSUPP | Errno::EBADF) => None,
        Err(errno) => {
            return Err(format!("failed to query terminal mode ({})", errno.text()));
        }
    };

    let _ = write!(writer, "{prompt}");
    let _ = writer.flush();
    let mut line = String::new();
    let read_res = reader.read_line(&mut line);
    if echo_disabled {
        let _ = writeln!(writer);
        let _ = writer.flush();
    }
    drop(_guard);

    let n = read_res.map_err(|e| format!("failed to read password: {e}"))?;
    if n == 0 {
        return Err("aborted (EOF)".into());
    }
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}

/// Prompt for a secret on stderr and read a line from stdin with terminal `ECHO` disabled
/// when stdin (`fd 0`) is a TTY, restoring the original termios unconditionally via RAII.
pub(crate) fn prompt_password(prompt: &str) -> Result<String, String> {
    let tty = OsTermiosBackend;
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut stderr = io::stderr();
    prompt_password_with(prompt, &tty, &mut reader, &mut stderr)
}

/// Parsed record from local `/etc/passwd` shared by `su`, `login`, and `newgrp`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalPasswdRecord {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
}

/// Parsed record from local `/etc/group` shared by `newgrp`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalGroupRecord {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

pub(crate) fn parse_passwd_line(line: &str) -> Option<LocalPasswdRecord> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let fields: Vec<&str> = trimmed.split(':').collect();
    if fields.len() != 7 || fields[0].is_empty() {
        return None;
    }
    Some(LocalPasswdRecord {
        name: fields[0].to_owned(),
        uid: fields[2].parse().ok()?,
        gid: fields[3].parse().ok()?,
        home: fields[5].to_owned(),
        shell: fields[6].to_owned(),
    })
}

pub(crate) fn parse_group_line(line: &str) -> Option<LocalGroupRecord> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let fields: Vec<&str> = trimmed.split(':').collect();
    if fields.len() != 4 || fields[0].is_empty() {
        return None;
    }
    let members = fields[3]
        .split(',')
        .filter(|m| !m.is_empty())
        .map(str::to_owned)
        .collect();
    Some(LocalGroupRecord {
        name: fields[0].to_owned(),
        gid: fields[2].parse().ok()?,
        members,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::cell::RefCell;
    use std::io::Cursor;

    struct MockTty {
        initial: Result<Value, Errno>,
        fail_set: Option<Errno>,
        current: RefCell<Option<Value>>,
        sets: RefCell<Vec<Value>>,
    }

    impl MockTty {
        fn tty_with_echo() -> Self {
            let termios = json!({
                "iflag": 256,
                "oflag": 5,
                "cflag": 176,
                "lflag": 1 | 2 | 8 | 16 | 32 | 512,
                "cc": vec![0u64; 32],
            });
            Self {
                initial: Ok(termios.clone()),
                fail_set: None,
                current: RefCell::new(Some(termios)),
                sets: RefCell::new(Vec::new()),
            }
        }

        fn pipe() -> Self {
            Self {
                initial: Err(Errno::ENOTTY),
                fail_set: None,
                current: RefCell::new(None),
                sets: RefCell::new(Vec::new()),
            }
        }
    }

    impl TermiosBackend for MockTty {
        fn tcgets(&self, fd: u32) -> Result<Value, Errno> {
            assert_eq!(fd, 0);
            self.initial.clone()
        }

        fn tcsets(&self, fd: u32, termios: Value) -> Result<(), Errno> {
            assert_eq!(fd, 0);
            if let Some(errno) = self.fail_set {
                return Err(errno);
            }
            *self.current.borrow_mut() = Some(termios.clone());
            self.sets.borrow_mut().push(termios);
            Ok(())
        }
    }

    struct FailingReader;
    impl io::Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "input closed"))
        }
    }
    impl BufRead for FailingReader {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "input closed"))
        }
        fn consume(&mut self, _amt: usize) {}
    }

    #[test]
    fn prompt_password_disables_echo_on_tty_and_restores_on_return_eof_and_error() {
        let tty = MockTty::tty_with_echo();
        let orig_lflag = tty.initial.as_ref().unwrap()["lflag"].as_u64().unwrap();
        assert_ne!(orig_lflag & TERMIOS_ECHO_BIT, 0);

        let mut reader = Cursor::new(b"super-secret\r\n".to_vec());
        let mut stderr = Vec::new();
        let pw = prompt_password_with("Password: ", &tty, &mut reader, &mut stderr).unwrap();
        assert_eq!(pw, "super-secret");
        assert_eq!(String::from_utf8(stderr).unwrap(), "Password: \n");
        let sets = tty.sets.borrow();
        assert_eq!(sets.len(), 2);
        assert_eq!(sets[0]["lflag"].as_u64().unwrap() & TERMIOS_ECHO_BIT, 0);
        assert_eq!(
            sets[0]["lflag"].as_u64().unwrap(),
            orig_lflag & !TERMIOS_ECHO_BIT
        );
        assert_eq!(sets[1], *tty.initial.as_ref().unwrap());
        drop(sets);

        // EOF still restores exact original termios via RAII Drop guard.
        let tty_eof = MockTty::tty_with_echo();
        let mut empty = Cursor::new(Vec::<u8>::new());
        let mut stderr_eof = Vec::new();
        let err =
            prompt_password_with("Password: ", &tty_eof, &mut empty, &mut stderr_eof).unwrap_err();
        assert!(err.contains("EOF"));
        assert_eq!(tty_eof.sets.borrow().len(), 2);
        assert_eq!(
            *tty_eof.current.borrow(),
            Some(tty_eof.initial.as_ref().unwrap().clone())
        );

        // Read error still restores exact original termios via RAII Drop guard.
        let tty_err = MockTty::tty_with_echo();
        let mut failing = FailingReader;
        let mut stderr_err = Vec::new();
        assert!(
            prompt_password_with("Password: ", &tty_err, &mut failing, &mut stderr_err).is_err()
        );
        assert_eq!(tty_err.sets.borrow().len(), 2);
        assert_eq!(
            *tty_err.current.borrow(),
            Some(tty_err.initial.as_ref().unwrap().clone())
        );
    }

    #[test]
    fn prompt_password_handles_non_tty_pipe_and_fails_closed_when_tcsets_fails() {
        let pipe = MockTty::pipe();
        let mut reader = Cursor::new(b"piped-pass\n".to_vec());
        let mut stderr = Vec::new();
        let pw = prompt_password_with("Password: ", &pipe, &mut reader, &mut stderr).unwrap();
        assert_eq!(pw, "piped-pass");
        assert_eq!(String::from_utf8(stderr).unwrap(), "Password: ");
        assert!(pipe.sets.borrow().is_empty());

        let mut broken_tty = MockTty::tty_with_echo();
        broken_tty.fail_set = Some(Errno::EIO);
        let mut reader2 = Cursor::new(b"leaked?\n".to_vec());
        let mut stderr2 = Vec::new();
        let err = prompt_password_with("Password: ", &broken_tty, &mut reader2, &mut stderr2)
            .unwrap_err();
        assert!(err.contains("echo"));
        assert!(stderr2.is_empty());
    }
}

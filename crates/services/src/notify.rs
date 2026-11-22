//! An inherited pipe capability for one service launch, using existing descriptor APIs.
use os_posix::pipe::{pipe, readable};
#[cfg(not(target_os = "wasi"))]
use std::os::fd::AsRawFd;
#[cfg(target_os = "wasi")]
use std::os::wasi::io::AsRawFd;
use std::{
    fs::File,
    io::{self, Read},
};

const READY: &[u8] = b"READY=1\n";

pub struct Notification {
    reader: File,
    writer: Option<File>,
    matched: usize,
}
impl Notification {
    pub fn open() -> io::Result<Self> {
        let (reader, writer) = pipe()?;
        Ok(Self {
            reader,
            writer: Some(writer),
            matched: 0,
        })
    }
    pub fn fd(&self) -> String {
        self.writer
            .as_ref()
            .expect("writer before spawn")
            .as_raw_fd()
            .to_string()
    }
    /// Close the parent's writer before launching any sibling. Only this child and
    /// helpers to which it deliberately passes the descriptor may notify readiness.
    pub fn spawned(&mut self) {
        self.writer.take();
    }
    pub fn check(&mut self) -> io::Result<bool> {
        while self.matched < READY.len() {
            if !readable(&self.reader)? {
                return Ok(false);
            }
            let mut bytes = [0; READY.len()];
            let count = self.reader.read(&mut bytes[..READY.len() - self.matched])?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "readiness pipe closed before READY=1",
                ));
            }
            if bytes[..count] != READY[self.matched..self.matched + count] {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "expected READY=1 followed by newline",
                ));
            }
            self.matched += count;
        }
        Ok(true)
    }
}

/// Send a systemd-compatible `NOTIFY_SOCKET` datagram (`READY=1`, optional `STATUS=...`) over
/// `AF_UNIX` `SOCK_DGRAM` (`#57` `L3d`, Contract v2 §2.8). Peer identity is stamped by the kernel
/// via `SO_PEERCRED`, never forged in the payload.
#[allow(dead_code)]
pub fn notify_socket_ready(status: Option<&str>) -> io::Result<bool> {
    let Ok(path) = std::env::var("NOTIFY_SOCKET") else {
        return Ok(false);
    };
    if path.is_empty() {
        return Ok(false);
    }
    let sock = os_posix::socket::UnixDatagram::unbound()
        .map_err(|e| io::Error::other(format!("notify socket create failed: {}", e.text())))?;
    let mut payload = String::from("READY=1\n");
    if let Some(text) = status
        && !text.is_empty()
    {
        payload.push_str("STATUS=");
        payload.push_str(&text.replace(['\n', '\r'], " "));
        payload.push('\n');
    }
    sock.send_to(payload.as_bytes(), &path)
        .map_err(|e| io::Error::other(format!("notify send to {path} failed: {}", e.text())))?;
    Ok(true)
}

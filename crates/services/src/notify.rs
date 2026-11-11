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

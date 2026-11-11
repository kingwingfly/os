//! Ordinary inherited pipes and nonblocking readiness through WASI descriptors.
#[cfg(target_os = "wasi")]
use std::os::wasi::io::{AsRawFd, FromRawFd};
use std::{fs::File, io};

#[cfg(target_os = "wasi")]
pub fn pipe() -> io::Result<(File, File)> {
    #[link(wasm_import_module = "wasix_32v1")]
    unsafe extern "C" {
        fn fd_pipe(reader: *mut u32, writer: *mut u32) -> u32;
        fn fd_fdflags_set(fd: u32, flags: u32) -> u32;
    }
    let (mut reader, mut writer) = (0, 0);
    // SAFETY: the host writes two valid, owned descriptor numbers on success.
    errno(unsafe { fd_pipe(&mut reader, &mut writer) })?;
    // SAFETY: these newly allocated descriptors have no other Rust owners.
    let (reader, writer) = unsafe {
        (
            File::from_raw_fd(reader as i32),
            File::from_raw_fd(writer as i32),
        )
    };
    // SAFETY: reader is open. FD_CLOEXEC excludes the parent's read end from spawn.
    errno(unsafe { fd_fdflags_set(reader.as_raw_fd() as u32, 1) })?;
    Ok((reader, writer))
}

#[cfg(target_os = "wasi")]
pub fn readable(file: &File) -> io::Result<bool> {
    #[link(wasm_import_module = "wasi_snapshot_preview1")]
    unsafe extern "C" {
        fn poll_oneoff(input: *const u8, output: *mut u8, count: usize, events: *mut usize) -> u32;
    }
    // Preview-1 subscriptions are 48 bytes and events 32 bytes, both 8-byte aligned.
    #[repr(C, align(8))]
    struct Buffer<const N: usize>([u8; N]);
    let mut input = Buffer([0; 96]);
    input.0[8] = 1; // fd_read
    input.0[16..20].copy_from_slice(&file.as_raw_fd().to_le_bytes());
    input.0[64..68].copy_from_slice(&1u32.to_le_bytes()); // monotonic clock, timeout 0
    let mut output = Buffer([0; 64]);
    let mut events = 0;
    // SAFETY: buffers hold exactly two subscriptions/events; events is writable.
    errno(unsafe { poll_oneoff(input.0.as_ptr(), output.0.as_mut_ptr(), 2, &mut events) })?;
    for event in output.0.as_chunks::<32>().0.iter().take(events) {
        errno(u16::from_le_bytes([event[8], event[9]]) as u32)?;
        if event[10] == 1 {
            return Ok(true);
        }
    }
    Ok(false)
}
#[cfg(target_os = "wasi")]
fn errno(code: u32) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}
#[cfg(not(target_os = "wasi"))]
pub fn pipe() -> io::Result<(File, File)> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "requires the OS WASI runtime",
    ))
}
#[cfg(not(target_os = "wasi"))]
pub fn readable(_: &File) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "requires the OS WASI runtime",
    ))
}

/// Exclude an owned descriptor from exec inheritance, while allowing explicit dup2.
#[cfg(target_os = "wasi")]
pub fn close_on_exec(file: &File) -> io::Result<()> {
    #[link(wasm_import_module = "wasix_32v1")]
    unsafe extern "C" {
        fn fd_fdflags_set(fd: u32, flags: u32) -> u32;
    }
    // SAFETY: file owns this live descriptor.
    errno(unsafe { fd_fdflags_set(file.as_raw_fd() as u32, 1) })
}
#[cfg(not(target_os = "wasi"))]
pub fn close_on_exec(_: &File) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "requires the OS WASI runtime",
    ))
}

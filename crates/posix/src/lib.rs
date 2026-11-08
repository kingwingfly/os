//! POSIX metadata missing from WASI preview 1, obtained through the existing OS ABI.
//! This compatibility layer has no command names, UI callbacks or session credentials.

use std::io;
use std::path::Path;

pub mod process;

pub use abi::Stat;

/// Read the full metadata of a path, following its last symlink only when requested.
pub fn stat(path: &Path, follow: bool) -> io::Result<Stat> {
    let path = absolute(path)?;
    let call = if follow {
        abi::Call::Stat { path }
    } else {
        abi::Call::Lstat { path }
    };
    metadata(&request(&[call])?)
}

fn absolute(path: &Path) -> io::Result<String> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let path = path
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid UTF-8 path"))?
        .to_owned();
    Ok(path)
}

/// mkdir(2), retaining mode bits that WASI preview 1 cannot carry.
pub fn mkdir(path: &Path, mode: u32) -> io::Result<()> {
    let mut result = batch(&[abi::Call::Mkdir {
        path: absolute(path)?,
        mode: (mode & 0o7777) as u16,
    }])?;
    result.results.remove(0).into_result().map_err(os_error)?;
    Ok(())
}

/// chmod(2), including permissions that WASI preview 1 cannot represent.
pub fn chmod(path: &Path, mode: u32) -> io::Result<()> {
    let mut result = batch(&[abi::Call::Chmod {
        path: absolute(path)?,
        mode: (mode & 0o7777) as u16,
    }])?;
    result.results.remove(0).into_result().map_err(os_error)?;
    Ok(())
}

/// Change this process's creation mask and return its previous value, as umask(2) does.
/// The mask is process-local; the authoritative filesystem still checks every operation.
#[cfg(target_os = "wasi")]
pub fn umask(mask: u32) -> u32 {
    #[link(wasm_import_module = "os")]
    unsafe extern "C" {
        #[link_name = "umask"]
        fn host_umask(mask: u32) -> u32;
    }
    // SAFETY: this scalar-only host call reads or writes no guest memory.
    unsafe { host_umask(mask & 0o777) }
}

fn os_error(error: abi::Error) -> io::Error {
    let kind = match error.errno {
        abi::Errno::ENOENT => io::ErrorKind::NotFound,
        abi::Errno::EACCES | abi::Errno::EPERM => io::ErrorKind::PermissionDenied,
        abi::Errno::EEXIST => io::ErrorKind::AlreadyExists,
        abi::Errno::ENOTDIR => io::ErrorKind::NotADirectory,
        abi::Errno::ENOTEMPTY => io::ErrorKind::DirectoryNotEmpty,
        abi::Errno::EINVAL => io::ErrorKind::InvalidInput,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, error.to_string())
}

/// Make an OS call batch with this process's credentials. No browser session is borrowed.
pub fn batch(calls: &[abi::Call]) -> io::Result<abi::Results> {
    let reply: abi::Results = serde_json::from_slice(&request(calls)?)?;
    if reply.results.len() != calls.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incomplete OS reply",
        ));
    }
    Ok(reply)
}

#[cfg(target_os = "wasi")]
fn request(calls: &[abi::Call]) -> io::Result<Vec<u8>> {
    #[link(wasm_import_module = "os")]
    unsafe extern "C" {
        fn sys(calls: *const u8, len: usize) -> usize;
        fn reply(to: *mut u8);
    }
    let calls = serde_json::to_vec(calls)?;
    // SAFETY: the host reads only this buffer and reports the size of its pending reply.
    let len = unsafe { sys(calls.as_ptr(), calls.len()) };
    if len > 16 << 20 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversized OS reply",
        ));
    }
    let mut out = vec![0; len];
    // SAFETY: out has the length returned by sys; no intervening call replaces that reply.
    unsafe { reply(out.as_mut_ptr()) };
    Ok(out)
}

#[cfg(not(target_os = "wasi"))]
fn request(_: &[abi::Call]) -> io::Result<Vec<u8>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "requires the WASI OS adapter",
    ))
}

fn metadata(bytes: &[u8]) -> io::Result<Stat> {
    let mut results: abi::Results = serde_json::from_slice(bytes)?;
    if results.results.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid stat reply",
        ));
    }
    let result = results
        .results
        .pop()
        .unwrap()
        .into_result()
        .map_err(os_error)?;
    serde_json::from_value(result).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_preserves_identity_modes_links_and_acl() {
        let stat = Stat {
            ino: 19,
            mode: 0o106750,
            nlink: 3,
            uid: 42,
            gid: 7,
            user: "ann".into(),
            group: "staff".into(),
            acl: true,
            ..Stat::default()
        };
        let reply = serde_json::json!({"results": [{"ok": stat}]}).to_string();
        assert_eq!(metadata(reply.as_bytes()).unwrap(), stat);
    }

    #[test]
    fn malformed_and_denied_metadata_never_become_placeholder_owners() {
        for bytes in [
            b"{}".as_slice(),
            b"{\"results\":[]}",
            b"{\"results\":[{\"ok\":{}}]}",
        ] {
            assert!(metadata(bytes).is_err());
        }
        let reply = serde_json::json!({"results": [{"err": {"errno": "EACCES"}}]}).to_string();
        assert_eq!(
            metadata(reply.as_bytes()).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}

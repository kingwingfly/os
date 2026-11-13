//! Thin call adapters only; no emulation of missing OS semantics.
use serde_json::{Value, json};
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::os::unix::{fs::MetadataExt, io::AsRawFd};
#[cfg(target_os = "wasi")]
use std::os::wasi::io::AsRawFd;
use std::{fs::File, io, path::Path};

pub type Result<T> = std::result::Result<T, String>;
pub fn error(e: io::Error) -> String {
    let n = e.raw_os_error();
    for (code, name) in [
        (libc::EPERM, "EPERM"),
        (libc::ENOENT, "ENOENT"),
        (libc::ESRCH, "ESRCH"),
        (libc::EIO, "EIO"),
        (libc::ENXIO, "ENXIO"),
        (libc::E2BIG, "E2BIG"),
        (libc::EBADF, "EBADF"),
        (libc::EAGAIN, "EAGAIN"),
        (libc::EACCES, "EACCES"),
        (libc::EBUSY, "EBUSY"),
        (libc::EEXIST, "EEXIST"),
        (libc::EXDEV, "EXDEV"),
        (libc::ENODEV, "ENODEV"),
        (libc::ENOTDIR, "ENOTDIR"),
        (libc::EISDIR, "EISDIR"),
        (libc::EINVAL, "EINVAL"),
        (libc::EMFILE, "EMFILE"),
        (libc::ENOTTY, "ENOTTY"),
        (libc::ETXTBSY, "ETXTBSY"),
        (libc::EFBIG, "EFBIG"),
        (libc::ENOSPC, "ENOSPC"),
        (libc::EROFS, "EROFS"),
        (libc::EMLINK, "EMLINK"),
        (libc::EPIPE, "EPIPE"),
        (libc::ERANGE, "ERANGE"),
        (libc::ENAMETOOLONG, "ENAMETOOLONG"),
        (libc::ENOSYS, "ENOSYS"),
        (libc::ENOTEMPTY, "ENOTEMPTY"),
        (libc::ELOOP, "ELOOP"),
        #[cfg(target_os = "linux")]
        (libc::ENODATA, "ENODATA"),
        (libc::EOPNOTSUPP, "EOPNOTSUPP"),
        (libc::ESTALE, "ESTALE"),
        (libc::ETIMEDOUT, "ETIMEDOUT"),
        (libc::ECANCELED, "ECANCELED"),
        (libc::ENOEXEC, "ENOEXEC"),
        (libc::ECHILD, "ECHILD"),
    ] {
        if n == Some(code) {
            return name.into();
        }
    }
    // Preview 1 has no ENODATA number: this runtime aliases it to ENOENT.
    // ABI errors preserve ENODATA by name; never invent a distinction in raw 44.
    match n {
        Some(n) => format!("UNMAPPED_ERRNO:{}:{n}", std::env::consts::OS),
        None => "NO_OS_ERRNO".into(),
    }
}

pub fn io<T>(r: io::Result<T>) -> Result<T> {
    r.map_err(error)
}
#[cfg(target_os = "wasi")]
fn call(c: abi::Call) -> Result<Value> {
    let mut r = io(os_posix::batch(&[c]))?;
    r.results
        .remove(0)
        .into_result()
        .map_err(|e| format!("{:?}", e.errno))
}
fn c(path: &Path) -> CString {
    CString::new(path.as_os_str().as_encoded_bytes()).unwrap()
}
fn rc(n: i32) -> Result<()> {
    if n < 0 {
        Err(error(io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

fn rawstat(path: Option<&Path>, file: Option<&File>) -> Result<libc::stat> {
    let mut value = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        match (path, file) {
            (Some(path), _) => libc::stat(c(path).as_ptr(), value.as_mut_ptr()),
            (_, Some(file)) => libc::fstat(file.as_raw_fd(), value.as_mut_ptr()),
            _ => unreachable!(),
        }
    };
    rc(result)?;
    Ok(unsafe { value.assume_init() })
}
#[derive(Clone, Copy)]
pub struct Identity {
    dev: Option<u64>,
    ino: Option<u64>,
}
#[cfg(any(target_os = "wasi", test))]
fn identity_from_json(value: &Value) -> Identity {
    Identity {
        dev: value["dev"].as_u64(),
        ino: value["ino"].as_u64().filter(|n| *n != 0),
    }
}
pub fn identity_relation(a: Identity, b: Identity) -> Value {
    fn equal(a: Option<u64>, b: Option<u64>, field: &str) -> Value {
        match (a, b) {
            (Some(a), Some(b)) => json!(a == b),
            _ => json!({"unavailable":format!("{field} not exposed by both observations")}),
        }
    }
    json!({"same_dev":equal(a.dev,b.dev,"st_dev"),"same_ino":equal(a.ino,b.ino,"st_ino")})
}
pub fn identity(path: &Path) -> Result<Identity> {
    #[cfg(target_os = "linux")]
    {
        let s = rawstat(Some(path), None)?;
        Ok(Identity {
            dev: Some(s.st_dev),
            ino: Some(s.st_ino),
        })
    }
    #[cfg(target_os = "wasi")]
    {
        let value = call(abi::Call::Stat {
            path: path.to_string_lossy().into_owned(),
        })?;
        Ok(identity_from_json(&value))
    }
}
pub fn fdidentity(file: &File) -> Result<Identity> {
    let s = rawstat(None, Some(file))?;
    #[cfg(target_os = "linux")]
    {
        Ok(Identity {
            dev: Some(s.st_dev),
            ino: Some(s.st_ino),
        })
    }
    #[cfg(target_os = "wasi")]
    {
        // There is no abi::Call::Fstat and ABI descriptor numbers are distinct
        // from libc fds. Preview 1 exposes the inode, but writeFilestat invents
        // dev=1 and substitutes ino=0 when absent. Neither is identity evidence.
        Ok(Identity {
            dev: None,
            ino: (s.st_ino != 0).then_some(s.st_ino),
        })
    }
}
pub fn fdstat(f: &File) -> Result<Value> {
    let s = rawstat(None, Some(f))?;
    Ok(json!({"size":s.st_size,"nlink":s.st_nlink}))
}
pub fn stat(path: &Path) -> Result<Value> {
    #[cfg(target_os = "linux")]
    {
        let m = io(fs::metadata(path))?;
        Ok(
            json!({"mode":format!("{:04o}",m.mode() & 0o7777),"size":m.len(),"nlink":m.nlink(),"uid":m.uid(),"gid":m.gid()}),
        )
    }
    #[cfg(target_os = "wasi")]
    {
        let m = call(abi::Call::Stat {
            path: path.to_string_lossy().into_owned(),
        })?;
        Ok(
            json!({"mode":format!("{:04o}",m["mode"].as_u64().unwrap() & 0o7777),"size":m["size"],"nlink":m["nlink"],"uid":m["uid"],"gid":m["gid"]}),
        )
    }
}
pub fn chmod(path: &Path, mode: u32) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        rc(unsafe { libc::chmod(c(path).as_ptr(), mode) })
    }
    #[cfg(target_os = "wasi")]
    {
        call(abi::Call::Chmod {
            path: path.to_string_lossy().into_owned(),
            mode: mode as u16,
        })
        .map(|_| ())
    }
}
pub fn umask(mode: u32) {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::umask(mode);
    }
    #[cfg(target_os = "wasi")]
    os_posix::umask(mode);
}
pub fn symlink(target: &Path, path: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        io(std::os::unix::fs::symlink(target, path))
    }
    #[cfg(target_os = "wasi")]
    {
        call(abi::Call::Symlink {
            target: target.to_string_lossy().into_owned(),
            path: path.to_string_lossy().into_owned(),
        })
        .map(|_| ())
    }
}
pub fn noreplace(from: &Path, to: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        rc(unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                c(from).as_ptr(),
                libc::AT_FDCWD,
                c(to).as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        })
    }
    #[cfg(target_os = "wasi")]
    {
        call(abi::Call::Rename {
            from: from.to_string_lossy().into_owned(),
            to: to.to_string_lossy().into_owned(),
            noreplace: true,
        })
        .map(|_| ())
    }
}
pub fn setacl(path: &Path, default: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // Linux POSIX ACL xattr v2: owner rwx, group r-x, named group 65534 r--,
        // mask r-x, other ---. Named IDs are fixed fixture IDs, not host accounts.
        let mut bytes = 2u32.to_le_bytes().to_vec();
        for (tag, perm, id) in [
            (1u16, 7u16, u32::MAX),
            (4, 5, u32::MAX),
            (8, 4, 65534),
            (16, 5, u32::MAX),
            (32, 0, u32::MAX),
        ] {
            bytes.extend(tag.to_le_bytes());
            bytes.extend(perm.to_le_bytes());
            bytes.extend(id.to_le_bytes());
        }
        let name = CString::new(if default {
            "system.posix_acl_default"
        } else {
            "system.posix_acl_access"
        })
        .unwrap();
        rc(unsafe {
            libc::setxattr(
                c(path).as_ptr(),
                name.as_ptr(),
                bytes.as_ptr().cast(),
                bytes.len(),
                0,
            )
        })
    }
    #[cfg(target_os = "wasi")]
    {
        call(abi::Call::Setxattr {
            path: path.to_string_lossy().into_owned(),
            name: if default {
                abi::ACL_DEFAULT
            } else {
                abi::ACL_ACCESS
            }
            .into(),
            value: serde_json::to_vec(
                &json!({"user":7,"group":5,"other":0,"mask":5,"users":{},"groups":{"65534":4}}),
            )
            .unwrap()
            .into(),
            flags: 0,
            nofollow: false,
        })
        .map(|_| ())
    }
}
pub fn acl(path: &Path) -> Result<Value> {
    #[cfg(target_os = "linux")]
    {
        let name = CString::new("system.posix_acl_access").unwrap();
        let mut bytes = [0u8; 256];
        let n = unsafe {
            libc::getxattr(
                c(path).as_ptr(),
                name.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if n < 0 {
            return if io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA) {
                Ok(json!(null))
            } else {
                Err(error(io::Error::last_os_error()))
            };
        }
        let mut out = json!({"user":0,"group":0,"other":0,"mask":null,"users":{},"groups":{}});
        for entry in bytes[4..n as usize].as_chunks::<8>().0 {
            let tag = u16::from_le_bytes(entry[..2].try_into().unwrap());
            let perm = u16::from_le_bytes(entry[2..4].try_into().unwrap());
            let id = u32::from_le_bytes(entry[4..].try_into().unwrap());
            match tag {
                1 => out["user"] = json!(perm),
                4 => out["group"] = json!(perm),
                32 => out["other"] = json!(perm),
                16 => out["mask"] = json!(perm),
                2 => out["users"][id.to_string()] = json!(perm),
                8 => out["groups"][id.to_string()] = json!(perm),
                _ => return Err("unknown ACL tag".into()),
            }
        }
        Ok(out)
    }
    #[cfg(target_os = "wasi")]
    {
        let result = call(abi::Call::Getxattr {
            path: path.to_string_lossy().into_owned(),
            name: abi::ACL_ACCESS.into(),
            nofollow: false,
        });
        match result {
            Err(e) if e == "ENODATA" => Ok(json!(null)),
            Err(e) => Err(e),
            Ok(v) => {
                let bytes: abi::Bytes = serde_json::from_value(v).map_err(|e| e.to_string())?;
                serde_json::from_slice(&bytes.0).map_err(|e| e.to_string())
            }
        }
    }
}
#[cfg(target_os = "wasi")]
#[link(wasm_import_module = "wasix_32v1")]
unsafe extern "C" {
    fn chdir(ptr: *const u8, len: usize) -> u32;
    fn getcwd(ptr: *mut u8, len: *mut u32) -> u32;
}
pub fn cd(path: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        io(std::env::set_current_dir(path))
    }
    #[cfg(target_os = "wasi")]
    {
        let s = path.to_string_lossy();
        let n = unsafe { chdir(s.as_ptr(), s.len()) };
        if n == 0 {
            Ok(())
        } else {
            Err(error(io::Error::from_raw_os_error(n as i32)))
        }
    }
}
pub fn cwd() -> Result<String> {
    #[cfg(target_os = "linux")]
    {
        io(std::env::current_dir()).map(|p| p.to_string_lossy().into_owned())
    }
    #[cfg(target_os = "wasi")]
    {
        let mut bytes = vec![0u8; 4096];
        let mut n = bytes.len() as u32;
        let e = unsafe { getcwd(bytes.as_mut_ptr(), &mut n) };
        if e != 0 {
            return Err(error(io::Error::from_raw_os_error(e as i32)));
        }
        Ok(String::from_utf8_lossy(&bytes[..n as usize - 1]).into_owned())
    }
}
#[cfg(target_os = "linux")]
pub fn mount(source: &Path, target: &Path, tmpfs: bool) -> Result<()> {
    let kind = CString::new("tmpfs").unwrap();
    rc(unsafe {
        libc::mount(
            c(source).as_ptr(),
            c(target).as_ptr(),
            if tmpfs {
                kind.as_ptr()
            } else {
                std::ptr::null()
            },
            if tmpfs { 0 } else { libc::MS_BIND },
            std::ptr::null(),
        )
    })
}
#[cfg(target_os = "linux")]
pub fn unmount(path: &Path) -> Result<()> {
    rc(unsafe { libc::umount(c(path).as_ptr()) })
}
#[cfg(target_os = "linux")]
pub fn chroot(path: &Path) -> Result<()> {
    rc(unsafe { libc::chroot(c(path).as_ptr()) })
}

pub fn invalid_sync(data: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        rc(unsafe {
            if data {
                libc::fdatasync(-1)
            } else {
                libc::fsync(-1)
            }
        })
    }
    #[cfg(target_os = "wasi")]
    {
        #[link(wasm_import_module = "wasi_snapshot_preview1")]
        unsafe extern "C" {
            fn fd_sync(fd: u32) -> u32;
            fn fd_datasync(fd: u32) -> u32;
        }
        let n = unsafe {
            if data {
                fd_datasync(u32::MAX)
            } else {
                fd_sync(u32::MAX)
            }
        };
        if n == 0 {
            Ok(())
        } else {
            Err(error(io::Error::from_raw_os_error(n as i32)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn absent_identity_never_compares_equal() {
        let missing = identity_from_json(&json!({"ino":0}));
        let known = identity_from_json(&json!({"dev":2,"ino":3}));
        assert!(identity_relation(missing, missing)["same_ino"].is_object());
        assert!(identity_relation(missing, known)["same_dev"].is_object());
        assert_eq!(
            identity_relation(known, known),
            json!({"same_dev":true,"same_ino":true})
        );
        assert_eq!(
            identity_relation(known, identity_from_json(&json!({"dev":4,"ino":5}))),
            json!({"same_dev":false,"same_ino":false})
        );
    }
    #[test]
    fn errors_use_stable_names() {
        for (code, name) in [
            (libc::ENOSPC, "ENOSPC"),
            (libc::ENAMETOOLONG, "ENAMETOOLONG"),
            (libc::EMLINK, "EMLINK"),
            (libc::ERANGE, "ERANGE"),
            (libc::ETXTBSY, "ETXTBSY"),
            (libc::EAGAIN, "EAGAIN"),
            (libc::ENODATA, "ENODATA"),
        ] {
            assert_eq!(error(io::Error::from_raw_os_error(code)), name);
        }
        assert_eq!(error(io::Error::other("details")), "NO_OS_ERRNO");
    }
}

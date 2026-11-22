//! `switch_root` utility: `switch_root <newroot> <init> [args...]`
//!
//! Implements `docs/architecture/contract.md` §5 and Blueprint §2.2 steps 1–10 verbatim:
//! - Preconditions: caller MUST be PID 1 (`uid 0`, `getpid() == 1` -> else `EPERM`), and `/` MUST
//!   be `tmpfs` (`TMPFS_MAGIC` -> else `EINVAL`).
//! - Pre-flight BEFORE moving any mounts: verify `<newroot>` is a mountpoint directory (`EINVAL`),
//!   `<newroot><init>` exists and is executable (`ENOENT`/`EACCES`), and target mount directories
//!   (`<newroot>/proc`, `<newroot>/dev`, `<newroot>/run`) are real directories without following
//!   symlinks.
//! - Detach Stage 1 `/usr` (`MNT_DETACH`), open old `/` (`O_RDONLY | O_DIRECTORY | O_CLOEXEC`),
//!   move `/proc`, `/dev` (carrying `/dev/pts`), and `/run` onto `<newroot>` with rollback on
//!   failure before pivot, then `chdir(<newroot>)`, `mount(".", "/", MS_MOVE)`, `chroot(".")`,
//!   `chdir("/")`.
//! - Recursively unlink all non-mountpoint entries under `oldroot_fd`, strictly comparing `st_dev`
//!   so traversal NEVER crosses a mount boundary into `<newroot>` or moved mounts, then close
//!   `oldroot_fd`.
//! - `execve(<init>, [init, args...], env)` preserving PID 1 and original `start_time`.

use abi::Errno;
use abi::contract::{fs_magic, mount_flags, umount_flags};
use std::collections::VecDeque;
use std::io::{self, Read};
use std::path::Path;

const USAGE: &str = "Usage: switch_root NEWROOT INIT [ARG]...\n\n\
Switch from Stage 1 tmpfs initramfs to NEWROOT and exec INIT as PID 1.\n";

const MAX_SYMLINK_DEPTH: usize = 40;
const MAX_SHEBANG_DEPTH: usize = 4;
const BINPRM_BUF_SIZE: usize = 256;
const STAGE1_RESCUE_SRC: &str = "/bin/sh";
pub(crate) const RETAINED_RESCUE_PATH: &str = "/run/os/.rescue";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NodeInfo {
    pub dev: u64,
    pub mode: u32,
}

impl NodeInfo {
    pub fn is_dir(&self) -> bool {
        (self.mode & abi::S_IFMT) == abi::S_IFDIR
    }

    pub fn is_file(&self) -> bool {
        (self.mode & abi::S_IFMT) == abi::S_IFREG
    }

    pub fn is_symlink(&self) -> bool {
        (self.mode & abi::S_IFMT) == abi::S_IFLNK
    }

    pub fn is_executable(&self) -> bool {
        (self.mode & 0o111) != 0
    }
}

pub(crate) trait SwitchRootBackend {
    fn getpid(&self) -> io::Result<u32>;
    fn getuid(&self) -> io::Result<u32>;
    fn statfs_type(&self, path: &str) -> io::Result<u64>;
    fn stat(&self, path: &str, follow: bool) -> io::Result<NodeInfo>;
    fn readlink(&self, path: &str) -> io::Result<String>;
    fn read_head(&self, path: &str, max_bytes: usize) -> io::Result<Vec<u8>>;
    fn stage_rescue(&mut self, src: &str, dst: &str, mode: u32) -> io::Result<()>;
    fn remove_file(&mut self, path: &str) -> io::Result<()>;
    fn open_dir(&mut self, dirfd: Option<u32>, path: &str, nofollow: bool) -> io::Result<u32>;
    fn fstat_dir(&self, fd: u32) -> io::Result<NodeInfo>;
    fn fstatat(&self, dirfd: u32, name: &str, follow: bool) -> io::Result<NodeInfo>;
    fn readdir(&self, dirfd: u32) -> io::Result<Vec<String>>;
    fn unlinkat(&mut self, dirfd: u32, name: &str, rmdir: bool) -> io::Result<()>;
    fn close_dir(&mut self, fd: u32) -> io::Result<()>;
    fn mount(
        &mut self,
        source: Option<&str>,
        target: &str,
        fstype: Option<&str>,
        flags: u64,
        data: Option<&str>,
    ) -> io::Result<()>;
    fn umount2(&mut self, target: &str, flags: u32) -> io::Result<()>;
    fn chdir(&mut self, path: &str) -> io::Result<()>;
    fn chroot(&mut self, path: &str) -> io::Result<()>;
    fn execve(&mut self, path: &str, argv: &[String], env: &[String]) -> Result<(), io::Error>;
    fn current_env(&self) -> Vec<String>;
}

fn errno_io(errno: Errno, detail: &str) -> io::Error {
    let kind = match errno {
        Errno::EPERM | Errno::EACCES => io::ErrorKind::PermissionDenied,
        Errno::ENOENT => io::ErrorKind::NotFound,
        Errno::EINVAL => io::ErrorKind::InvalidInput,
        Errno::ENOTDIR => io::ErrorKind::NotADirectory,
        Errno::EBUSY => io::ErrorKind::ResourceBusy,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(
        kind,
        os_posix::OsCallError(abi::Error::because(errno, detail)),
    )
}

struct OsSwitchRootBackend;

impl SwitchRootBackend for OsSwitchRootBackend {
    fn getpid(&self) -> io::Result<u32> {
        #[cfg(target_os = "wasi")]
        {
            #[link(wasm_import_module = "wasix_32v1")]
            unsafe extern "C" {
                fn proc_id(pid: *mut u32) -> u32;
            }
            let mut pid = 0u32;
            // SAFETY: scalar output pointer is live for the duration of the import.
            if unsafe { proc_id(&mut pid) } == 0 && pid != 0 {
                return Ok(pid);
            }
        }
        let mut reply = os_posix::batch(&[abi::Call::Getpid])?;
        let val = reply
            .results
            .remove(0)
            .into_result()
            .map_err(|e| errno_io(e.errno, e.detail.as_deref().unwrap_or("")))?;
        val.as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| errno_io(Errno::EIO, "invalid getpid reply"))
    }

    fn getuid(&self) -> io::Result<u32> {
        let mut reply = os_posix::batch(&[abi::Call::Getcreds])?;
        let val = reply
            .results
            .remove(0)
            .into_result()
            .map_err(|e| errno_io(e.errno, e.detail.as_deref().unwrap_or("")))?;
        val.get("uid")
            .or_else(|| val.get("id"))
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| errno_io(Errno::EIO, "invalid getcreds reply"))
    }

    fn statfs_type(&self, path: &str) -> io::Result<u64> {
        Ok(os_posix::statfs(Path::new(path))?.f_type)
    }

    fn stat(&self, path: &str, follow: bool) -> io::Result<NodeInfo> {
        let st = os_posix::stat(Path::new(path), follow)?;
        Ok(NodeInfo {
            dev: st.dev,
            mode: st.mode,
        })
    }

    fn readlink(&self, path: &str) -> io::Result<String> {
        os_posix::readlinkat(None, Path::new(path))?
            .into_os_string()
            .into_string()
            .map_err(|_| errno_io(Errno::EINVAL, "non-UTF8 symlink target"))
    }

    fn read_head(&self, path: &str, max_bytes: usize) -> io::Result<Vec<u8>> {
        let file = std::fs::File::open(path)?;
        let mut buf = Vec::new();
        file.take(max_bytes as u64).read_to_end(&mut buf)?;
        Ok(buf)
    }

    fn stage_rescue(&mut self, src: &str, dst: &str, mode: u32) -> io::Result<()> {
        let bytes = std::fs::read(src)?;
        if !is_valid_binary_header(&bytes) {
            return Err(errno_io(
                Errno::ENOEXEC,
                "Stage 1 rescue binary is not a valid executable",
            ));
        }
        if let Some(parent) = Path::new(dst).parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(dst, &bytes)?;
        os_posix::chmod(Path::new(dst), mode)?;
        let st = os_posix::stat(Path::new(dst), false)?;
        let info = NodeInfo {
            dev: st.dev,
            mode: st.mode,
        };
        if !info.is_file() || !info.is_executable() {
            let _ = std::fs::remove_file(dst);
            return Err(errno_io(
                Errno::EACCES,
                "staged rescue binary is not an executable regular file",
            ));
        }
        Ok(())
    }

    fn remove_file(&mut self, path: &str) -> io::Result<()> {
        std::fs::remove_file(path)
    }

    fn open_dir(&mut self, dirfd: Option<u32>, path: &str, nofollow: bool) -> io::Result<u32> {
        #[cfg(target_os = "wasi")]
        {
            #[link(wasm_import_module = "wasi_snapshot_preview1")]
            unsafe extern "C" {
                fn path_open(
                    dirfd: u32,
                    dirflags: u32,
                    path: *const u8,
                    path_len: usize,
                    oflags: u16,
                    fs_rights_base: u64,
                    fs_rights_inheriting: u64,
                    fdflags: u16,
                    opened_fd: *mut u32,
                ) -> u32;
            }
            let anchor = dirfd.unwrap_or(if path.starts_with('/') {
                abi::OS_FD_ROOT as u32
            } else {
                abi::OS_FD_CWD as u32
            });
            let lookup_flags = if nofollow { 0 } else { 1 };
            // WASI OFLAG_DIRECTORY = 2; rights: PATH_OPEN | FD_READDIR | PATH_FILESTAT_GET | PATH_UNLINK_FILE | PATH_REMOVE_DIRECTORY
            const WASI_OFLAG_DIRECTORY: u16 = 2;
            const DIR_RIGHTS: u64 = 0x0fff_ffff;
            let mut out_fd = 0u32;
            // SAFETY: `path` and `out_fd` live across the synchronous WASI host call.
            let rc = unsafe {
                path_open(
                    anchor,
                    lookup_flags,
                    path.as_ptr(),
                    path.len(),
                    WASI_OFLAG_DIRECTORY,
                    DIR_RIGHTS,
                    DIR_RIGHTS,
                    0,
                    &mut out_fd,
                )
            };
            if rc != 0 {
                return Err(io::Error::from_raw_os_error(rc as i32));
            }
            Ok(out_fd)
        }
        #[cfg(not(target_os = "wasi"))]
        {
            let _ = (dirfd, path, nofollow);
            Err(errno_io(Errno::ENOSYS, "requires WASI runtime"))
        }
    }

    fn fstat_dir(&self, fd: u32) -> io::Result<NodeInfo> {
        let st = os_posix::statat(Some(fd), Path::new("."), false)?;
        Ok(NodeInfo {
            dev: st.dev,
            mode: st.mode,
        })
    }

    fn fstatat(&self, dirfd: u32, name: &str, follow: bool) -> io::Result<NodeInfo> {
        let st = os_posix::statat(Some(dirfd), Path::new(name), follow)?;
        Ok(NodeInfo {
            dev: st.dev,
            mode: st.mode,
        })
    }

    fn readdir(&self, dirfd: u32) -> io::Result<Vec<String>> {
        #[cfg(target_os = "wasi")]
        {
            #[link(wasm_import_module = "wasi_snapshot_preview1")]
            unsafe extern "C" {
                fn fd_readdir(
                    fd: u32,
                    buf: *mut u8,
                    buf_len: usize,
                    cookie: u64,
                    bufused: *mut usize,
                ) -> u32;
            }
            let mut names = Vec::new();
            let mut cookie = 0u64;
            let mut buf = vec![0u8; 8192];
            loop {
                let mut used = 0usize;
                // SAFETY: `buf` and `used` are valid writable buffers.
                let rc =
                    unsafe { fd_readdir(dirfd, buf.as_mut_ptr(), buf.len(), cookie, &mut used) };
                if rc != 0 {
                    return Err(io::Error::from_raw_os_error(rc as i32));
                }
                if used == 0 {
                    break;
                }
                let mut pos = 0usize;
                let mut progressed = false;
                while pos + 24 <= used {
                    let d_next = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
                    let d_namlen =
                        u32::from_le_bytes(buf[pos + 16..pos + 20].try_into().unwrap()) as usize;
                    pos += 24;
                    if pos + d_namlen > used {
                        break;
                    }
                    let name = String::from_utf8_lossy(&buf[pos..pos + d_namlen]).into_owned();
                    pos += d_namlen;
                    cookie = d_next;
                    progressed = true;
                    if name != "." && name != ".." {
                        names.push(name);
                    }
                }
                if used < buf.len() || !progressed {
                    break;
                }
            }
            Ok(names)
        }
        #[cfg(not(target_os = "wasi"))]
        {
            let _ = dirfd;
            Err(errno_io(Errno::ENOSYS, "requires WASI runtime"))
        }
    }

    fn unlinkat(&mut self, dirfd: u32, name: &str, rmdir: bool) -> io::Result<()> {
        os_posix::unlinkat(Some(dirfd), Path::new(name), rmdir)
    }

    fn close_dir(&mut self, fd: u32) -> io::Result<()> {
        #[cfg(target_os = "wasi")]
        {
            #[link(wasm_import_module = "wasi_snapshot_preview1")]
            unsafe extern "C" {
                fn fd_close(fd: u32) -> u32;
            }
            // SAFETY: closing caller-owned directory descriptor.
            let rc = unsafe { fd_close(fd) };
            if rc != 0 {
                return Err(io::Error::from_raw_os_error(rc as i32));
            }
            Ok(())
        }
        #[cfg(not(target_os = "wasi"))]
        {
            let _ = fd;
            Err(errno_io(Errno::ENOSYS, "requires WASI runtime"))
        }
    }

    fn mount(
        &mut self,
        source: Option<&str>,
        target: &str,
        fstype: Option<&str>,
        flags: u64,
        data: Option<&str>,
    ) -> io::Result<()> {
        os_posix::mount(
            source.map(Path::new),
            Path::new(target),
            fstype,
            flags,
            data,
        )
    }

    fn umount2(&mut self, target: &str, flags: u32) -> io::Result<()> {
        os_posix::umount2(Path::new(target), flags)
    }

    fn chdir(&mut self, path: &str) -> io::Result<()> {
        os_posix::chdir(Path::new(path))
    }

    fn chroot(&mut self, path: &str) -> io::Result<()> {
        os_posix::chroot(Path::new(path))
    }

    fn execve(&mut self, path: &str, argv: &[String], env: &[String]) -> Result<(), io::Error> {
        Err(os_posix::process::execve(path, argv, env))
    }

    fn current_env(&self) -> Vec<String> {
        std::env::vars().map(|(k, v)| format!("{k}={v}")).collect()
    }
}

fn join_newroot(newroot: &str, rel: &str) -> String {
    let base = newroot.trim_end_matches('/');
    let suffix = rel.trim_start_matches('/');
    if base.is_empty() {
        format!("/{suffix}")
    } else if suffix.is_empty() {
        base.to_string()
    } else {
        format!("{base}/{suffix}")
    }
}

fn is_valid_binary_header(header: &[u8]) -> bool {
    (header.starts_with(b"\0asm") && header.len() >= 8)
        || (header.starts_with(b"\x7fELF") && header.len() >= 4)
}

fn parse_shebang_interpreter(header: &[u8]) -> io::Result<String> {
    if !header.starts_with(b"#!") {
        return Err(errno_io(Errno::ENOEXEC, "missing shebang prefix"));
    }
    let rest = &header[2..];
    let line_bytes = match rest.iter().position(|&b| b == b'\n') {
        Some(pos) => &rest[..pos],
        None if header.len() >= BINPRM_BUF_SIZE => {
            return Err(errno_io(Errno::ENOEXEC, "unterminated shebang line"));
        }
        None => rest,
    };
    let line_bytes = line_bytes.strip_suffix(b"\r").unwrap_or(line_bytes);
    let line = std::str::from_utf8(line_bytes)
        .map_err(|_| errno_io(Errno::ENOEXEC, "shebang line is not valid UTF-8"))?;
    let trimmed = line.trim_start_matches([' ', '\t']);
    let interp = trimmed.split([' ', '\t']).next().unwrap_or("");
    if interp.is_empty() || !interp.starts_with('/') {
        return Err(errno_io(
            Errno::ENOEXEC,
            "shebang interpreter must be an absolute path",
        ));
    }
    Ok(interp.to_string())
}

/// Resolve `abs_path` strictly inside `newroot`, following relative and absolute symlinks without
/// ever allowing traversal (`..` or `/...`) to escape `newroot`.
fn resolve_in_newroot(
    backend: &impl SwitchRootBackend,
    newroot: &str,
    abs_path: &str,
) -> io::Result<(String, NodeInfo)> {
    if !abs_path.starts_with('/') {
        return Err(errno_io(
            Errno::EINVAL,
            "path inside newroot must be absolute",
        ));
    }
    let mut resolved: Vec<String> = Vec::new();
    let mut queue: VecDeque<String> = abs_path
        .split('/')
        .filter(|seg| !seg.is_empty())
        .map(str::to_owned)
        .collect();
    let mut symlinks = 0usize;

    while let Some(seg) = queue.pop_front() {
        match seg.as_str() {
            "" | "." => continue,
            ".." => {
                // Clamp at `newroot` so `..` never escapes into the Stage 1 root.
                resolved.pop();
                continue;
            }
            _ => {}
        }
        resolved.push(seg);
        let rel = format!("/{}", resolved.join("/"));
        let host_path = join_newroot(newroot, &rel);
        let info = backend.stat(&host_path, false)?;
        if info.is_symlink() {
            symlinks += 1;
            if symlinks > MAX_SYMLINK_DEPTH {
                return Err(errno_io(Errno::ELOOP, "too many levels of symbolic links"));
            }
            let target = backend.readlink(&host_path)?;
            if target.is_empty() {
                return Err(errno_io(Errno::ENOENT, "empty symlink target"));
            }
            resolved.pop();
            if target.starts_with('/') {
                resolved.clear();
            }
            let target_segs: Vec<String> = target
                .split('/')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
            for s in target_segs.into_iter().rev() {
                queue.push_front(s);
            }
        } else if !queue.is_empty() && !info.is_dir() {
            return Err(errno_io(
                Errno::ENOTDIR,
                "non-directory component while resolving executable in newroot",
            ));
        }
    }

    let final_rel = if resolved.is_empty() {
        String::new()
    } else {
        format!("/{}", resolved.join("/"))
    };
    let final_host = join_newroot(newroot, &final_rel);
    let final_info = backend.stat(&final_host, false)?;
    Ok((final_host, final_info))
}

/// Pre-flight check `<newroot><init>` and any `#!` interpreter chain strictly inside `newroot`
/// BEFORE detaching `/usr`, moving mounts, or reclaiming the Stage 1 initramfs.
fn preflight_validate_init(
    backend: &impl SwitchRootBackend,
    newroot: &str,
    init_path: &str,
) -> io::Result<()> {
    let mut cur_path = init_path.to_string();
    for depth in 0..=MAX_SHEBANG_DEPTH {
        let (resolved_host, info) = resolve_in_newroot(backend, newroot, &cur_path)?;
        if !info.is_file() || !info.is_executable() {
            return Err(errno_io(
                Errno::EACCES,
                "target init or interpreter is not an executable regular file",
            ));
        }
        let head = backend.read_head(&resolved_host, BINPRM_BUF_SIZE)?;
        if head.is_empty() {
            return Err(errno_io(
                Errno::ENOEXEC,
                "target init or interpreter is empty",
            ));
        }
        if head.starts_with(b"#!") {
            if depth >= MAX_SHEBANG_DEPTH {
                return Err(errno_io(
                    Errno::ELOOP,
                    "too many levels of #! interpreters in target init",
                ));
            }
            cur_path = parse_shebang_interpreter(&head)?;
            continue;
        }
        if is_valid_binary_header(&head) {
            return Ok(());
        }
        return Err(errno_io(
            Errno::ENOEXEC,
            "target init or interpreter is not a valid executable binary or #! script",
        ));
    }
    Err(errno_io(Errno::ELOOP, "exceeded #! recursion limit"))
}

/// Recursively unlink every non-mountpoint entry under `dirfd`, strictly checking `st_dev == root_dev`
/// so traversal NEVER crosses into `<newroot>` or moved filesystems.
fn recursive_clean_oldroot(
    backend: &mut impl SwitchRootBackend,
    dirfd: u32,
    root_dev: u64,
    depth: usize,
) -> io::Result<()> {
    if depth > 64 {
        return Ok(());
    }
    let entries = backend.readdir(dirfd)?;
    for name in entries {
        if name == "." || name == ".." {
            continue;
        }
        let Ok(info) = backend.fstatat(dirfd, &name, false) else {
            continue;
        };
        // Strictly bound traversal by `st_dev`: NEVER cross a mount boundary!
        if info.dev != root_dev {
            continue;
        }
        if info.is_dir() {
            if let Ok(subfd) = backend.open_dir(Some(dirfd), &name, true) {
                let same_dev = backend
                    .fstat_dir(subfd)
                    .is_ok_and(|sub| sub.dev == root_dev && sub.is_dir());
                if same_dev {
                    let _ = recursive_clean_oldroot(backend, subfd, root_dev, depth + 1);
                }
                let _ = backend.close_dir(subfd);
                if same_dev {
                    let _ = backend.unlinkat(dirfd, &name, true);
                }
            }
        } else {
            let _ = backend.unlinkat(dirfd, &name, false);
        }
    }
    Ok(())
}

pub(crate) fn switch_root_with(
    newroot: &str,
    init_path: &str,
    init_args: &[String],
    backend: &mut impl SwitchRootBackend,
) -> io::Result<()> {
    // Precondition 1: caller MUST be PID 1 and uid 0 (else EPERM).
    let pid = backend.getpid()?;
    let uid = backend.getuid()?;
    if pid != 1 || uid != 0 {
        return Err(errno_io(
            Errno::EPERM,
            "switch_root must be executed by PID 1 as root",
        ));
    }

    // Precondition 2: `/` MUST be tmpfs (`TMPFS_MAGIC`, else EINVAL).
    let root_magic = backend.statfs_type("/")?;
    if root_magic != fs_magic::TMPFS_MAGIC {
        return Err(errno_io(
            Errno::EINVAL,
            "current root is not tmpfs (initramfs)",
        ));
    }

    // Validate arguments.
    if newroot.is_empty() || newroot == "/" || !init_path.starts_with('/') {
        return Err(errno_io(
            Errno::EINVAL,
            "invalid newroot or init path (init must be absolute)",
        ));
    }

    let root_info = backend.stat("/", false)?;
    let newroot_info = backend.stat(newroot, false)?;
    if !newroot_info.is_dir() {
        return Err(errno_io(Errno::ENOTDIR, "newroot is not a directory"));
    }
    if newroot_info.dev == root_info.dev {
        return Err(errno_io(
            Errno::EINVAL,
            "newroot must be a mounted filesystem distinct from /",
        ));
    }

    // Step 1 (Pre-flight BEFORE moving any mounts or detaching `/usr`!):
    // Resolve `<newroot><init>` and any `#!` interpreter strictly inside `<newroot>`, verifying
    // executable permissions and binary/shebang validity.
    preflight_validate_init(backend, newroot, init_path)?;

    // Determine which Stage 1 system mounts (`/proc`, `/dev`, `/run`) are mounted and verify their
    // destination directories under `<newroot>` are real directories (without following symlinks)
    // BEFORE moving anything!
    let mut to_move: Vec<(&str, String)> = Vec::new();
    for mount_dir in ["/proc", "/dev", "/run"] {
        if let Ok(src_info) = backend.stat(mount_dir, false)
            && src_info.is_dir()
            && src_info.dev != root_info.dev
        {
            let dst = join_newroot(newroot, mount_dir);
            let dst_info = backend.stat(&dst, false)?;
            if !dst_info.is_dir() {
                return Err(errno_io(
                    Errno::ENOTDIR,
                    "move target under newroot is not a directory",
                ));
            }
            to_move.push((mount_dir, dst));
        }
    }

    // Retain a verified Stage 1 rescue executable across the pivot BEFORE detaching `/usr` or
    // reclaiming `oldroot_fd`, so a post-pivot `execve` failure can transfer PID 1 cleanly into
    // recovery instead of exiting PID 1 without a recovery environment.
    let run_moved = to_move.iter().any(|(src, _)| *src == "/run");
    let rescue_stage_dst = if run_moved {
        RETAINED_RESCUE_PATH.to_string()
    } else {
        join_newroot(newroot, RETAINED_RESCUE_PATH)
    };
    backend.stage_rescue(STAGE1_RESCUE_SRC, &rescue_stage_dst, 0o700)?;

    // Step 2: Detach Stage 1 `/usr` (`MNT_DETACH`) if mounted (never move Stage 1 `/usr` or `/tmp`).
    if let Ok(usr_info) = backend.stat("/usr", false)
        && usr_info.dev != root_info.dev
        && let Err(err) = backend.umount2("/usr", umount_flags::MNT_DETACH)
    {
        let _ = backend.remove_file(&rescue_stage_dst);
        return Err(err);
    }

    // Step 3: Open initial root (`/`) as a descriptor so Stage 1 tmpfs can be cleaned post-pivot.
    let oldroot_fd = match backend.open_dir(None, "/", false) {
        Ok(fd) => fd,
        Err(err) => {
            let _ = backend.remove_file(&rescue_stage_dst);
            return Err(err);
        }
    };
    let oldroot_dev = match backend.fstat_dir(oldroot_fd) {
        Ok(info) => info.dev,
        Err(err) => {
            let _ = backend.close_dir(oldroot_fd);
            let _ = backend.remove_file(&rescue_stage_dst);
            return Err(err);
        }
    };

    // Step 4: Move live mounts (`/proc`, `/dev` carrying `/dev/pts`, `/run`) onto `<newroot>`.
    // Roll back completed moves on error BEFORE step 6 pivot.
    let mut moved: Vec<(&str, String)> = Vec::new();
    for (src, dst) in to_move {
        if let Err(err) = backend.mount(Some(src), &dst, None, mount_flags::MS_MOVE, None) {
            for (orig_src, moved_dst) in moved.into_iter().rev() {
                let _ = backend.mount(Some(&moved_dst), orig_src, None, mount_flags::MS_MOVE, None);
            }
            let _ = backend.close_dir(oldroot_fd);
            let _ = backend.remove_file(&rescue_stage_dst);
            return Err(err);
        }
        moved.push((src, dst));
    }

    // Steps 5–8: `chdir(<newroot>)`, `mount(".", "/", MS_MOVE)`, `chroot(".")`, `chdir("/")`.
    if let Err(err) = backend.chdir(newroot) {
        for (orig_src, moved_dst) in moved.into_iter().rev() {
            let _ = backend.mount(Some(&moved_dst), orig_src, None, mount_flags::MS_MOVE, None);
        }
        let _ = backend.close_dir(oldroot_fd);
        let _ = backend.remove_file(&rescue_stage_dst);
        return Err(err);
    }
    if let Err(err) = backend.mount(Some("."), "/", None, mount_flags::MS_MOVE, None) {
        let _ = backend.chdir("/");
        for (orig_src, moved_dst) in moved.into_iter().rev() {
            let _ = backend.mount(Some(&moved_dst), orig_src, None, mount_flags::MS_MOVE, None);
        }
        let _ = backend.close_dir(oldroot_fd);
        let _ = backend.remove_file(&rescue_stage_dst);
        return Err(err);
    }
    backend.chroot(".")?;
    backend.chdir("/")?;

    // Step 9: Recursively unlink every non-mountpoint entry under `oldroot_fd` (strictly comparing
    // `st_dev == oldroot_dev` so traversal never crosses into `<newroot>`), then close `oldroot_fd`.
    let _ = recursive_clean_oldroot(backend, oldroot_fd, oldroot_dev, 0);
    let _ = backend.close_dir(oldroot_fd);

    // Step 10: `execve(<init>, [init, args...], env)` preserving PID 1 and original `start_time`.
    // If post-pivot `execve` fails after oldroot was reclaimed, transfer PID 1 directly to the
    // retained Stage 1 rescue executable instead of exiting PID 1.
    let mut argv = Vec::with_capacity(1 + init_args.len());
    argv.push(init_path.to_string());
    argv.extend(init_args.iter().cloned());
    let env = backend.current_env();
    if let Err(init_err) = backend.execve(init_path, &argv, &env) {
        eprintln!(
            "switch_root: execve({init_path}) failed after pivot ({init_err}); transferring PID 1 to {RETAINED_RESCUE_PATH}"
        );
        let rescue_argv = vec![RETAINED_RESCUE_PATH.to_string(), "-i".to_string()];
        return backend
            .execve(RETAINED_RESCUE_PATH, &rescue_argv, &env)
            .map_err(|_| init_err);
    }
    Ok(())
}

pub(crate) fn run_with(
    args: &[String],
    backend: &mut impl SwitchRootBackend,
) -> (Option<String>, Option<String>, i32) {
    if let Some(first) = args.first()
        && (first == "-h" || first == "--help")
    {
        return (Some(USAGE.to_string()), None, 0);
    }
    if args.len() < 2 {
        return (
            None,
            Some("switch_root: usage: switch_root NEWROOT INIT [ARG]...".into()),
            2,
        );
    }
    let newroot = &args[0];
    let init_path = &args[1];
    let init_args = &args[2..];
    match switch_root_with(newroot, init_path, init_args, backend) {
        Ok(()) => (None, None, 0),
        Err(err) => {
            let code = match os_posix::errno_of(&err) {
                Some(Errno::ENOENT) => 127,
                Some(Errno::EACCES | Errno::EPERM) => 126,
                _ => 1,
            };
            (None, Some(format!("switch_root: {err}")), code)
        }
    }
}

pub fn run(args: &[String]) -> i32 {
    let mut backend = OsSwitchRootBackend;
    let (out, err, code) = run_with(args, &mut backend);
    if let Some(msg) = out {
        print!("{msg}");
    }
    if let Some(msg) = err {
        eprintln!("{msg}");
    }
    // If PID 1 failed pre-pivot after `early_init` already replaced itself with `switch_root`,
    // transfer PID 1 into the Stage 1 recovery shell instead of terminating PID 1.
    if code != 0
        && args.len() >= 2
        && backend.getpid().ok() == Some(1)
        && backend.getuid().ok() == Some(0)
        && backend.statfs_type("/").ok() == Some(fs_magic::TMPFS_MAGIC)
    {
        let env = backend.current_env();
        let rescue_argv = vec![STAGE1_RESCUE_SRC.to_string(), "-i".to_string()];
        let _ = backend.execve(STAGE1_RESCUE_SRC, &rescue_argv, &env);
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    struct MockSwitchRoot {
        pid: u32,
        uid: u32,
        root_magic: u64,
        nodes: BTreeMap<String, NodeInfo>,
        symlinks: BTreeMap<String, String>,
        files: BTreeMap<String, Vec<u8>>,
        dir_entries: BTreeMap<u32, Vec<(String, NodeInfo)>>,
        dir_dev: BTreeMap<u32, u64>,
        sub_fds: BTreeMap<(u32, String), u32>,
        next_fd: u32,
        fail_move_src: Option<String>,
        fail_execve_paths: BTreeSet<String>,
        steps: Vec<String>,
        unlinked: Vec<(u32, String, bool)>,
    }

    impl MockSwitchRoot {
        fn healthy_stage1() -> Self {
            let mut nodes = BTreeMap::new();
            let mut files = BTreeMap::new();
            nodes.insert(
                "/".into(),
                NodeInfo {
                    dev: 1,
                    mode: abi::S_IFDIR | 0o755,
                },
            );
            nodes.insert(
                "/bin/sh".into(),
                NodeInfo {
                    dev: 1,
                    mode: abi::S_IFREG | 0o755,
                },
            );
            files.insert("/bin/sh".into(), b"\0asm\x01\0\0\0stage1-dash".to_vec());
            nodes.insert(
                "/proc".into(),
                NodeInfo {
                    dev: 2,
                    mode: abi::S_IFDIR | 0o555,
                },
            );
            nodes.insert(
                "/dev".into(),
                NodeInfo {
                    dev: 3,
                    mode: abi::S_IFDIR | 0o755,
                },
            );
            nodes.insert(
                "/run".into(),
                NodeInfo {
                    dev: 4,
                    mode: abi::S_IFDIR | 0o755,
                },
            );
            nodes.insert(
                "/usr".into(),
                NodeInfo {
                    dev: 5,
                    mode: abi::S_IFDIR | 0o755,
                },
            );
            nodes.insert(
                "/sysroot".into(),
                NodeInfo {
                    dev: 10,
                    mode: abi::S_IFDIR | 0o755,
                },
            );
            nodes.insert(
                "/sysroot/proc".into(),
                NodeInfo {
                    dev: 10,
                    mode: abi::S_IFDIR | 0o555,
                },
            );
            nodes.insert(
                "/sysroot/dev".into(),
                NodeInfo {
                    dev: 10,
                    mode: abi::S_IFDIR | 0o755,
                },
            );
            nodes.insert(
                "/sysroot/run".into(),
                NodeInfo {
                    dev: 10,
                    mode: abi::S_IFDIR | 0o755,
                },
            );
            nodes.insert(
                "/sysroot/usr".into(),
                NodeInfo {
                    dev: 11,
                    mode: abi::S_IFDIR | 0o755,
                },
            );
            nodes.insert(
                "/sysroot/usr/bin".into(),
                NodeInfo {
                    dev: 11,
                    mode: abi::S_IFDIR | 0o755,
                },
            );
            nodes.insert(
                "/sysroot/usr/bin/init".into(),
                NodeInfo {
                    dev: 11,
                    mode: abi::S_IFREG | 0o755,
                },
            );
            files.insert(
                "/sysroot/usr/bin/init".into(),
                b"\0asm\x01\0\0\0stage2-init".to_vec(),
            );

            // Old root fd 100 contains: initramfs_marker (dev 1), bin/ (dev 1 -> fd 101), sysroot/ (dev 10 -> MUST NOT BE TRAVERSED!)
            let mut dir_entries = BTreeMap::new();
            dir_entries.insert(
                100,
                vec![
                    (
                        "initramfs_marker".into(),
                        NodeInfo {
                            dev: 1,
                            mode: abi::S_IFREG | 0o644,
                        },
                    ),
                    (
                        "bin".into(),
                        NodeInfo {
                            dev: 1,
                            mode: abi::S_IFDIR | 0o755,
                        },
                    ),
                    (
                        "sysroot".into(),
                        NodeInfo {
                            dev: 10,
                            mode: abi::S_IFDIR | 0o755,
                        },
                    ),
                ],
            );
            dir_entries.insert(
                101,
                vec![(
                    "sh".into(),
                    NodeInfo {
                        dev: 1,
                        mode: abi::S_IFLNK | 0o777,
                    },
                )],
            );
            let mut dir_dev = BTreeMap::new();
            dir_dev.insert(100, 1);
            dir_dev.insert(101, 1);
            let mut sub_fds = BTreeMap::new();
            sub_fds.insert((100, "bin".into()), 101);

            Self {
                pid: 1,
                uid: 0,
                root_magic: fs_magic::TMPFS_MAGIC,
                nodes,
                symlinks: BTreeMap::new(),
                files,
                dir_entries,
                dir_dev,
                sub_fds,
                next_fd: 100,
                fail_move_src: None,
                fail_execve_paths: BTreeSet::new(),
                steps: Vec::new(),
                unlinked: Vec::new(),
            }
        }
    }

    impl SwitchRootBackend for MockSwitchRoot {
        fn getpid(&self) -> io::Result<u32> {
            Ok(self.pid)
        }
        fn getuid(&self) -> io::Result<u32> {
            Ok(self.uid)
        }
        fn statfs_type(&self, _path: &str) -> io::Result<u64> {
            Ok(self.root_magic)
        }
        fn stat(&self, path: &str, _follow: bool) -> io::Result<NodeInfo> {
            self.nodes
                .get(path)
                .cloned()
                .ok_or_else(|| errno_io(Errno::ENOENT, path))
        }
        fn readlink(&self, path: &str) -> io::Result<String> {
            self.symlinks
                .get(path)
                .cloned()
                .ok_or_else(|| errno_io(Errno::EINVAL, path))
        }
        fn read_head(&self, path: &str, max_bytes: usize) -> io::Result<Vec<u8>> {
            let bytes = self
                .files
                .get(path)
                .ok_or_else(|| errno_io(Errno::ENOENT, path))?;
            Ok(bytes[..bytes.len().min(max_bytes)].to_vec())
        }
        fn stage_rescue(&mut self, src: &str, dst: &str, mode: u32) -> io::Result<()> {
            let bytes = self
                .files
                .get(src)
                .cloned()
                .ok_or_else(|| errno_io(Errno::ENOENT, src))?;
            if !is_valid_binary_header(&bytes) {
                return Err(errno_io(Errno::ENOEXEC, "invalid rescue binary"));
            }
            self.files.insert(dst.to_string(), bytes);
            self.nodes.insert(
                dst.to_string(),
                NodeInfo {
                    dev: 4,
                    mode: abi::S_IFREG | mode,
                },
            );
            self.steps
                .push(format!("stage_rescue:{src}->{dst}:0o{mode:o}"));
            Ok(())
        }
        fn remove_file(&mut self, path: &str) -> io::Result<()> {
            self.files.remove(path);
            self.nodes.remove(path);
            self.steps.push(format!("remove_file:{path}"));
            Ok(())
        }
        fn open_dir(&mut self, dirfd: Option<u32>, path: &str, _nofollow: bool) -> io::Result<u32> {
            if let Some(dfd) = dirfd {
                let fd = self
                    .sub_fds
                    .get(&(dfd, path.to_string()))
                    .copied()
                    .ok_or_else(|| errno_io(Errno::ENOENT, path))?;
                return Ok(fd);
            }
            let fd = self.next_fd;
            self.next_fd += 1;
            self.steps.push(format!("open_dir:{path}->{fd}"));
            Ok(fd)
        }
        fn fstat_dir(&self, fd: u32) -> io::Result<NodeInfo> {
            let dev = self
                .dir_dev
                .get(&fd)
                .copied()
                .ok_or_else(|| errno_io(Errno::EBADF, "bad dirfd"))?;
            Ok(NodeInfo {
                dev,
                mode: abi::S_IFDIR | 0o755,
            })
        }
        fn fstatat(&self, dirfd: u32, name: &str, _follow: bool) -> io::Result<NodeInfo> {
            self.dir_entries
                .get(&dirfd)
                .and_then(|v| v.iter().find(|(n, _)| n == name))
                .map(|(_, info)| info.clone())
                .ok_or_else(|| errno_io(Errno::ENOENT, name))
        }
        fn readdir(&self, dirfd: u32) -> io::Result<Vec<String>> {
            Ok(self
                .dir_entries
                .get(&dirfd)
                .map(|v| v.iter().map(|(n, _)| n.clone()).collect())
                .unwrap_or_default())
        }
        fn unlinkat(&mut self, dirfd: u32, name: &str, rmdir: bool) -> io::Result<()> {
            self.unlinked.push((dirfd, name.to_string(), rmdir));
            Ok(())
        }
        fn close_dir(&mut self, fd: u32) -> io::Result<()> {
            self.steps.push(format!("close_dir:{fd}"));
            Ok(())
        }
        fn mount(
            &mut self,
            source: Option<&str>,
            target: &str,
            _fstype: Option<&str>,
            flags: u64,
            _data: Option<&str>,
        ) -> io::Result<()> {
            if let Some(src) = source
                && self.fail_move_src.as_deref() == Some(src)
            {
                return Err(errno_io(Errno::EBUSY, "simulated move failure"));
            }
            self.steps.push(format!(
                "mount:{:?}->{}:0x{:x}",
                source.unwrap_or(""),
                target,
                flags
            ));
            Ok(())
        }
        fn umount2(&mut self, target: &str, flags: u32) -> io::Result<()> {
            self.steps.push(format!("umount2:{target}:{flags}"));
            Ok(())
        }
        fn chdir(&mut self, path: &str) -> io::Result<()> {
            self.steps.push(format!("chdir:{path}"));
            Ok(())
        }
        fn chroot(&mut self, path: &str) -> io::Result<()> {
            self.steps.push(format!("chroot:{path}"));
            Ok(())
        }
        fn execve(
            &mut self,
            path: &str,
            argv: &[String],
            _env: &[String],
        ) -> Result<(), io::Error> {
            self.steps.push(format!("execve:{path}:{}", argv.join(" ")));
            if self.fail_execve_paths.contains(path) {
                return Err(errno_io(Errno::ENOEXEC, "simulated execve failure"));
            }
            Ok(())
        }
        fn current_env(&self) -> Vec<String> {
            vec!["PATH=/usr/bin".into()]
        }
    }

    #[test]
    fn switch_root_executes_contract_steps_and_respects_st_dev_boundary() {
        let mut mock = MockSwitchRoot::healthy_stage1();
        switch_root_with("/sysroot", "/usr/bin/init", &["--boot".into()], &mut mock).unwrap();

        assert_eq!(
            mock.steps,
            vec![
                "stage_rescue:/bin/sh->/run/os/.rescue:0o700",
                "umount2:/usr:2",
                "open_dir:/->100",
                "mount:\"/proc\"->/sysroot/proc:0x2000",
                "mount:\"/dev\"->/sysroot/dev:0x2000",
                "mount:\"/run\"->/sysroot/run:0x2000",
                "chdir:/sysroot",
                "mount:\".\"->/:0x2000",
                "chroot:.",
                "chdir:/",
                "close_dir:101",
                "close_dir:100",
                "execve:/usr/bin/init:/usr/bin/init --boot",
            ]
        );
        // Only dev==1 entries were unlinked; `sysroot` (dev 10) was NEVER touched!
        assert_eq!(
            mock.unlinked,
            vec![
                (100, "initramfs_marker".into(), false),
                (101, "sh".into(), false),
                (100, "bin".into(), true),
            ]
        );
    }

    #[test]
    fn switch_root_refuses_non_pid1_non_tmpfs_missing_init_and_rolls_back_on_move_error() {
        // Non-PID 1 -> EPERM
        let mut m1 = MockSwitchRoot::healthy_stage1();
        m1.pid = 42;
        let err = switch_root_with("/sysroot", "/usr/bin/init", &[], &mut m1).unwrap_err();
        assert_eq!(os_posix::errno_of(&err), Some(Errno::EPERM));
        assert!(m1.steps.is_empty());

        // Non-tmpfs root (cowfs) -> EINVAL
        let mut m2 = MockSwitchRoot::healthy_stage1();
        m2.root_magic = fs_magic::OS_COWFS_MAGIC;
        let err = switch_root_with("/sysroot", "/usr/bin/init", &[], &mut m2).unwrap_err();
        assert_eq!(os_posix::errno_of(&err), Some(Errno::EINVAL));
        assert!(m2.steps.is_empty());

        // Missing `<newroot><init>` -> ENOENT BEFORE any mounts are moved!
        let mut m3 = MockSwitchRoot::healthy_stage1();
        m3.nodes.remove("/sysroot/usr/bin/init");
        let err = switch_root_with("/sysroot", "/usr/bin/init", &[], &mut m3).unwrap_err();
        assert_eq!(os_posix::errno_of(&err), Some(Errno::ENOENT));
        assert!(m3.steps.is_empty());

        // Non-executable `<newroot><init>` -> EACCES BEFORE any mounts are moved!
        let mut m4 = MockSwitchRoot::healthy_stage1();
        m4.nodes.get_mut("/sysroot/usr/bin/init").unwrap().mode = abi::S_IFREG | 0o644;
        let err = switch_root_with("/sysroot", "/usr/bin/init", &[], &mut m4).unwrap_err();
        assert_eq!(os_posix::errno_of(&err), Some(Errno::EACCES));
        assert!(m4.steps.is_empty());

        // Move failure on `/run` rolls back `/dev` and `/proc` and cleans up staged rescue!
        let mut m5 = MockSwitchRoot::healthy_stage1();
        m5.fail_move_src = Some("/run".into());
        let err = switch_root_with("/sysroot", "/usr/bin/init", &[], &mut m5).unwrap_err();
        assert_eq!(os_posix::errno_of(&err), Some(Errno::EBUSY));
        assert!(
            m5.steps
                .contains(&"mount:\"/sysroot/dev\"->/dev:0x2000".to_string())
        );
        assert!(
            m5.steps
                .contains(&"mount:\"/sysroot/proc\"->/proc:0x2000".to_string())
        );
        assert!(
            m5.steps
                .contains(&"remove_file:/run/os/.rescue".to_string())
        );
    }

    #[test]
    fn switch_root_preflight_validates_shebang_interpreters_strictly_inside_newroot() {
        // 1. Executable `#!` script whose interpreter is missing inside `/sysroot` MUST fail
        //    ENOENT in preflight BEFORE detaching `/usr`, moving mounts, or cleaning oldroot!
        //    Even though `/bin/sh` exists on Stage 1 `/`, `/sysroot/bin/sh` does NOT exist!
        let mut missing_interp = MockSwitchRoot::healthy_stage1();
        missing_interp.files.insert(
            "/sysroot/usr/bin/init".into(),
            b"#!/bin/sh -e\necho hi\n".to_vec(),
        );
        let err =
            switch_root_with("/sysroot", "/usr/bin/init", &[], &mut missing_interp).unwrap_err();
        assert_eq!(os_posix::errno_of(&err), Some(Errno::ENOENT));
        assert!(missing_interp.steps.is_empty());
        assert!(missing_interp.unlinked.is_empty());

        // 2. Broken non-`#!`, non-Wasm executable file fails ENOEXEC in preflight!
        let mut broken = MockSwitchRoot::healthy_stage1();
        broken.files.insert(
            "/sysroot/usr/bin/init".into(),
            b"not a valid wasm or shebang script\n".to_vec(),
        );
        let err = switch_root_with("/sysroot", "/usr/bin/init", &[], &mut broken).unwrap_err();
        assert_eq!(os_posix::errno_of(&err), Some(Errno::ENOEXEC));
        assert!(broken.steps.is_empty());

        // 3. Valid `#!` script resolving through symlinks confined inside `/sysroot`
        //    (`/sysroot/bin -> usr/bin`, `/sysroot/usr/bin/sh -> /usr/bin/dash`) succeeds!
        let mut valid_script = MockSwitchRoot::healthy_stage1();
        valid_script.files.insert(
            "/sysroot/usr/bin/init".into(),
            b"#! /bin/sh   -eu \nexec /usr/bin/real-init\n".to_vec(),
        );
        valid_script.nodes.insert(
            "/sysroot/bin".into(),
            NodeInfo {
                dev: 10,
                mode: abi::S_IFLNK | 0o777,
            },
        );
        valid_script
            .symlinks
            .insert("/sysroot/bin".into(), "usr/bin".into());
        valid_script.nodes.insert(
            "/sysroot/usr/bin/sh".into(),
            NodeInfo {
                dev: 11,
                mode: abi::S_IFLNK | 0o777,
            },
        );
        valid_script
            .symlinks
            .insert("/sysroot/usr/bin/sh".into(), "../../usr/bin/dash".into());
        valid_script.nodes.insert(
            "/sysroot/usr/bin/dash".into(),
            NodeInfo {
                dev: 11,
                mode: abi::S_IFREG | 0o755,
            },
        );
        valid_script.files.insert(
            "/sysroot/usr/bin/dash".into(),
            b"\0asm\x01\0\0\0stage2-dash".to_vec(),
        );
        switch_root_with("/sysroot", "/usr/bin/init", &[], &mut valid_script).unwrap();
        assert_eq!(
            valid_script.steps.last().map(String::as_str),
            Some("execve:/usr/bin/init:/usr/bin/init")
        );
    }

    #[test]
    fn switch_root_transfers_pid1_to_retained_rescue_when_post_pivot_execve_fails() {
        let mut mock = MockSwitchRoot::healthy_stage1();
        mock.fail_execve_paths.insert("/usr/bin/init".into());

        // Post-pivot `execve("/usr/bin/init")` fails after oldroot cleanup; `switch_root` MUST
        // hand PID 1 directly to the retained `/run/os/.rescue` executable!
        switch_root_with("/sysroot", "/usr/bin/init", &["--boot".into()], &mut mock).unwrap();

        let rescue_stage_pos = mock
            .steps
            .iter()
            .position(|s| s == "stage_rescue:/bin/sh->/run/os/.rescue:0o700")
            .expect("rescue binary must be staged before pivot");
        let pivot_pos = mock
            .steps
            .iter()
            .position(|s| s == "chroot:.")
            .expect("chroot step");
        assert!(rescue_stage_pos < pivot_pos);
        assert_eq!(
            &mock.steps[mock.steps.len() - 2..],
            &[
                "execve:/usr/bin/init:/usr/bin/init --boot".to_string(),
                "execve:/run/os/.rescue:/run/os/.rescue -i".to_string(),
            ]
        );
    }
}

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
use std::io;
use std::path::Path;

const USAGE: &str = "Usage: switch_root NEWROOT INIT [ARG]...\n\n\
Switch from Stage 1 tmpfs initramfs to NEWROOT and exec INIT as PID 1.\n";

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

    pub fn is_executable(&self) -> bool {
        (self.mode & 0o111) != 0
    }
}

pub(crate) trait SwitchRootBackend {
    fn getpid(&self) -> io::Result<u32>;
    fn getuid(&self) -> io::Result<u32>;
    fn statfs_type(&self, path: &str) -> io::Result<u64>;
    fn stat(&self, path: &str, follow: bool) -> io::Result<NodeInfo>;
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

    // Step 1 (Pre-flight BEFORE moving any mounts!):
    // Verify `<newroot><init>` exists, is a regular file, and is executable.
    let target_init = join_newroot(newroot, init_path);
    let init_info = backend.stat(&target_init, true)?;
    if !init_info.is_file() || !init_info.is_executable() {
        return Err(errno_io(
            Errno::EACCES,
            "target init is not an executable regular file",
        ));
    }

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

    // Step 2: Detach Stage 1 `/usr` (`MNT_DETACH`) if mounted (never move Stage 1 `/usr` or `/tmp`).
    if let Ok(usr_info) = backend.stat("/usr", false)
        && usr_info.dev != root_info.dev
    {
        backend.umount2("/usr", umount_flags::MNT_DETACH)?;
    }

    // Step 3: Open initial root (`/`) as a descriptor so Stage 1 tmpfs can be cleaned post-pivot.
    let oldroot_fd = backend.open_dir(None, "/", false)?;
    let oldroot_dev = backend.fstat_dir(oldroot_fd)?.dev;

    // Step 4: Move live mounts (`/proc`, `/dev` carrying `/dev/pts`, `/run`) onto `<newroot>`.
    // Roll back completed moves on error BEFORE step 6 pivot.
    let mut moved: Vec<(&str, String)> = Vec::new();
    for (src, dst) in to_move {
        if let Err(err) = backend.mount(Some(src), &dst, None, mount_flags::MS_MOVE, None) {
            for (orig_src, moved_dst) in moved.into_iter().rev() {
                let _ = backend.mount(Some(&moved_dst), orig_src, None, mount_flags::MS_MOVE, None);
            }
            let _ = backend.close_dir(oldroot_fd);
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
        return Err(err);
    }
    if let Err(err) = backend.mount(Some("."), "/", None, mount_flags::MS_MOVE, None) {
        let _ = backend.chdir("/");
        for (orig_src, moved_dst) in moved.into_iter().rev() {
            let _ = backend.mount(Some(&moved_dst), orig_src, None, mount_flags::MS_MOVE, None);
        }
        let _ = backend.close_dir(oldroot_fd);
        return Err(err);
    }
    backend.chroot(".")?;
    backend.chdir("/")?;

    // Step 9: Recursively unlink every non-mountpoint entry under `oldroot_fd` (strictly comparing
    // `st_dev == oldroot_dev` so traversal never crosses into `<newroot>`), then close `oldroot_fd`.
    let _ = recursive_clean_oldroot(backend, oldroot_fd, oldroot_dev, 0);
    let _ = backend.close_dir(oldroot_fd);

    // Step 10: `execve(<init>, [init, args...], env)` preserving PID 1 and original `start_time`.
    let mut argv = Vec::with_capacity(1 + init_args.len());
    argv.push(init_path.to_string());
    argv.extend(init_args.iter().cloned());
    let env = backend.current_env();
    backend.execve(init_path, &argv, &env)
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
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct MockSwitchRoot {
        pid: u32,
        uid: u32,
        root_magic: u64,
        nodes: BTreeMap<String, NodeInfo>,
        dir_entries: BTreeMap<u32, Vec<(String, NodeInfo)>>,
        dir_dev: BTreeMap<u32, u64>,
        sub_fds: BTreeMap<(u32, String), u32>,
        next_fd: u32,
        fail_move_src: Option<String>,
        steps: Vec<String>,
        unlinked: Vec<(u32, String, bool)>,
    }

    impl MockSwitchRoot {
        fn healthy_stage1() -> Self {
            let mut nodes = BTreeMap::new();
            nodes.insert(
                "/".into(),
                NodeInfo {
                    dev: 1,
                    mode: abi::S_IFDIR | 0o755,
                },
            );
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
                "/sysroot/usr/bin/init".into(),
                NodeInfo {
                    dev: 11,
                    mode: abi::S_IFREG | 0o755,
                },
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
                dir_entries,
                dir_dev,
                sub_fds,
                next_fd: 100,
                fail_move_src: None,
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

        // Move failure on `/run` rolls back `/dev` and `/proc` cleanly!
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
    }
}

//! Isolated OCI container lifecycle runtime for `containerd-shim-os-v1` (#85).
//!
//! Each [`OciContainerHandle`] boots an isolated `KernelActor` with:
//! - Isolated `LocalProcessTable` + cgroup `memory.max` & `pids.max` enforced on `/`
//! - OCI `process.user` (`uid`/`gid`/`umask`) applied to PID 1 in both `LocalProcessTable` and `Vfs`
//! - Isolated `Vfs` + `MountNamespace` over an ephemeral `CowFs` root safely imported from the
//!   OCI bundle's `rootfs/` using `O_NOFOLLOW | O_CLOEXEC` (rejecting host devices, FIFOs,
//!   sockets, symlink escapes, and setuid/setgid bits, with file/dir/byte budgets)
//! - Minimal `/dev` (`null`, `zero`, `full`, `random`, `urandom` ONLY + explicitly attached CSI
//!   `/dev/vdN` raw block volumes — ZERO `/dev/tty`, `/dev/ptmx`, `/dev/loop*`, or host devices)
//! - Single-writer coordinated CSI volume attachment:
//!   - CSI block volumes attach through `OsCsiNode`'s live fenced `os-nbd` Unix socket (`NbdBlockDevice`)
//!     plus per-volume exclusive `flock` (zero self-fencing, zero blind `ForceTakeover`)
//!   - CSI `cowfs` volumes coordinate lease handoff (`ACQUIRE`/`RELEASE`) + exclusive `flock` +
//!     strict `WriterMode::Exclusive` (never stealing an active container's lease!)
//!   - Live CSI `FenceStateFile` verification checked on attach, writes, flushes, and `delete()`
//! - Explicit rejection of Linux ELF (`\x7fELF`) / non-`\0asm` executables with `Errno::ENOEXEC`
//! - Wasmtime 51 `EpochTickerGuard` preemption (`< 200 ms` on `Kill(SIGKILL)`)
//! - Safe `O_NOFOLLOW` host FIFO/regular-file stdio pumping with non-blocking `poll` teardown.

use crate::dev_backend::{build_native_dev_backend_with_vblk, new_uuid_v4, random_hex};
use crate::export_host::NativeExportBridge;
use crate::kernel_actor::{KernelActor, NativeBootProfile, now_timespec};
use crate::kernel_rpc::{
    GuestFdEntry, GuestFdKind, KernelClient, KernelCmd, LoadedImage, SpawnProcessReq, WakeBus,
};
use crate::mount_host::MountHostServer;
use crate::pipes::PipeHandle;
use crate::proc_runner::{EpochTickerGuard, WasmRuntime, spawn_process_thread_with_exit};
use crate::pty::PtyTable;
use crate::signals::SignalControl;
use abi::Errno;
use abi::contract::{Durability, InstanceIdentity, WriterModel, mount_flags};
use abi::fs::{OpenOptions, SetAttr, WriteAt};
use abi::volume::{
    BlkInfoResp, BlkLeaseResp, CowfsForkReq, CowfsForkResp, CowfsInfoResp, CowfsSnapshotReq,
    CowfsSnapshotResp,
};
use cowtree::{HeadStore, VolumeId, WriterMode};
use os_core::permissions::Identity;
use os_cowfs::native_sqlite::{NativePackStore, NativeSqliteHeadStore};
use os_cowfs::{
    CowFs, CowFsConfig, CowFsOpenMode, RawBlockConfig, RawBlockOpenMode, RawBlockVolume,
    RawBlockVolumeDevice,
};
use os_kernel::accounts::LocalAccountStore;
use os_kernel::proc_table::{LocalProcessTable, ReexecSpec};
use os_nbd::{NBD_EPERM, NbdClient, NbdClientError};
use serde::Deserialize;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::{CStr, CString};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Semaphore, mpsc};
use vfs::devfs::{DefaultDeviceBackend, DevPtsFs, DevTmpFs};
use vfs::gui_headless::HeadlessHostAdapter;
use vfs::guidev::GuiDeviceRegistry;
use vfs::loopdev::LoopRegistry;
use vfs::memfs::MemFs;
use vfs::procfs::{EmptyProcProvider, ProcFs, ProcMetaSnapshot};
use vfs::unix_sock::UnixSocketTable;
use vfs::vblk::{VblkRegistry, VolumeDevice};
use vfs::{
    BoxFuture, Cred, DefaultFilesystemFactory, Filesystem, FsId, FsType, Handle, MountBacking,
    MountFlags, Timespec, Vfs,
};

const OCI_HOST_LABEL: &str = crate::kernel_actor::HOST_LABEL;
const MAX_ROOTFS_FILES: usize = 10_000;
const MAX_ROOTFS_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ROOTFS_DEPTH: usize = 64;

/// Lifecycle state of an OCI container or exec process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OciContainerState {
    Created,
    Running,
    Stopped,
}

/// Live CSI publish-lease fencing state descriptor checked on attach, writes, flushes, and delete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OciCsiFenceCheck {
    pub fence_file: PathBuf,
    pub expected_epoch: u64,
    pub expected_lease_id: u64,
}

#[derive(Deserialize)]
struct DiskFenceState {
    fence_epoch: u64,
    lease_id: u64,
    fenced: bool,
}

impl OciCsiFenceCheck {
    pub fn verify(&self) -> Result<(), Errno> {
        const MAX_FENCE_FILE_BYTES: u64 = 64 * 1024;
        validate_host_path_no_symlinks(&self.fence_file, false)?;
        let cpath =
            CString::new(self.fence_file.as_os_str().as_bytes()).map_err(|_| Errno::ESTALE)?;
        let fd = unsafe {
            libc::open(
                cpath.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(Errno::ESTALE);
        }
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } != 0
            || (st.st_mode & libc::S_IFMT) != libc::S_IFREG
            || st.st_size < 0
            || (st.st_size as u64) > MAX_FENCE_FILE_BYTES
        {
            return Err(Errno::ESTALE);
        }
        let mut bytes = Vec::new();
        file.take(MAX_FENCE_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Errno::ESTALE)?;
        if (bytes.len() as u64) > MAX_FENCE_FILE_BYTES {
            return Err(Errno::ESTALE);
        }
        let dst: DiskFenceState = serde_json::from_slice(&bytes).map_err(|_| Errno::ESTALE)?;
        if dst.fenced
            || dst.fence_epoch != self.expected_epoch
            || dst.lease_id != self.expected_lease_id
        {
            return Err(Errno::ESTALE);
        }
        Ok(())
    }
}

/// Volume mount attached to an OCI container.
#[derive(Clone, Debug)]
pub enum OciVolumeMount {
    /// Live CSI `cowfs` filesystem volume mounted directly at `container_path` (strictly
    /// `WriterMode::Exclusive` with optional CSI handoff socket, exclusive lock file, and live
    /// CSI fence-state verification).
    CowFsVolume {
        store_dir: PathBuf,
        volume_id: String,
        container_path: String,
        readonly: bool,
        fence_flag: Option<Arc<AtomicBool>>,
        lock_file: Option<PathBuf>,
        handoff_socket: Option<PathBuf>,
        csi_fence: Option<OciCsiFenceCheck>,
    },
    /// Live CSI raw LBA block volume attached at `/dev/<dev_name>` directly via `RawBlockVolume`
    /// (`WriterMode::Exclusive` for non-NBD direct volumes).
    RawBlockDevice {
        store_dir: PathBuf,
        volume_id: String,
        dev_name: String,
        readonly: bool,
        fence_flag: Option<Arc<AtomicBool>>,
        lock_file: Option<PathBuf>,
        csi_fence: Option<OciCsiFenceCheck>,
    },
    /// Live CSI raw block volume routed through `OsCsiNode`'s `0600` `os-nbd` Unix socket
    /// (zero self-fencing, live `ClusterState` fencing enforced end-to-end).
    NbdBlockDevice {
        nbd_socket: PathBuf,
        export_name: String,
        dev_name: String,
        readonly: bool,
        lock_file: Option<PathBuf>,
        csi_fence: Option<OciCsiFenceCheck>,
    },
    /// Small read-only host directory safely imported into an in-memory `MemFs` (e.g. ConfigMap).
    ReadOnlyHostDir {
        host_path: PathBuf,
        container_path: String,
    },
}

/// Specification for creating an OCI container via [`OciContainerHandle::create`].
#[derive(Clone, Debug)]
pub struct OciBundleRunSpec {
    pub container_id: String,
    pub bundle_dir: PathBuf,
    pub rootfs_dir: PathBuf,
    pub work_store_dir: PathBuf,
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub cwd: String,
    pub uid: u32,
    pub gid: u32,
    pub umask: u16,
    pub memory_max_bytes: u64,
    pub pids_max: u32,
    pub stdin_path: Option<PathBuf>,
    pub stdout_path: Option<PathBuf>,
    pub stderr_path: Option<PathBuf>,
    pub terminal: bool,
    pub is_sandbox: bool,
    pub volumes: Vec<OciVolumeMount>,
}

/// Specification for launching an `exec` process inside a running container.
#[derive(Clone, Debug)]
pub struct OciExecSpec {
    pub exec_id: String,
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub cwd: String,
    pub uid: Option<u32>,
    pub stdin_path: Option<PathBuf>,
    pub stdout_path: Option<PathBuf>,
    pub stderr_path: Option<PathBuf>,
}

/// Exit status reported once a container or exec process transitions to [`OciContainerState::Stopped`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OciExitStatus {
    pub exit_code: i32,
    pub signal: Option<u8>,
    pub exited_at_ns: u64,
}

/// Point-in-time status snapshot returned by [`OciContainerHandle::state`] / [`OciExecHandle::state`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OciStatusSnapshot {
    pub state: OciContainerState,
    pub pid: u32,
    pub exit_status: Option<OciExitStatus>,
}

fn now_unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Safe Host Path / Rootfs / Stdio Validation (`O_NOFOLLOW | O_CLOEXEC`)
// ---------------------------------------------------------------------------

struct ImportBudget {
    files: usize,
    bytes: u64,
}

struct OwnedFd(libc::c_int);
impl Drop for OwnedFd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            unsafe {
                libc::close(self.0);
            }
        }
    }
}

fn validate_host_path_no_symlinks(path: &Path, must_exist: bool) -> Result<(), Errno> {
    if path.as_os_str().is_empty() || path.as_os_str().as_bytes().contains(&0) {
        return Err(Errno::EINVAL);
    }
    let mut cur = PathBuf::new();
    for comp in path.components() {
        if matches!(comp, Component::ParentDir) {
            return Err(Errno::EPERM);
        }
        cur.push(comp);
        if matches!(comp, Component::RootDir) {
            continue;
        }
        match std::fs::symlink_metadata(&cur) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(Errno::EPERM);
                }
            }
            Err(_) if !must_exist && cur == path => {
                // Final component may not exist yet (e.g., regular log file to be created).
            }
            Err(_) => return Err(Errno::ENOENT),
        }
    }
    Ok(())
}

/// Validate a host stdio path (`stdin`, `stdout`, `stderr`): must be absolute, contain no `..` or
/// NUL, have no symlinked ancestor or target, and if existing must be `S_IFIFO` or `S_IFREG`.
pub fn validate_stdio_path(path: &Path, is_input: bool) -> Result<(), Errno> {
    if !path.is_absolute() {
        return Err(Errno::EPERM);
    }
    validate_host_path_no_symlinks(path, is_input)?;
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        let mode = std::os::unix::fs::MetadataExt::mode(&meta) & libc::S_IFMT;
        if mode != libc::S_IFIFO && mode != libc::S_IFREG {
            return Err(Errno::EPERM);
        }
    }
    Ok(())
}

fn open_dir_nofollow(path: &Path) -> Result<OwnedFd, Errno> {
    validate_host_path_no_symlinks(path, true)?;
    let cpath = CString::new(path.as_os_str().as_bytes()).map_err(|_| Errno::EINVAL)?;
    let fd = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(Errno::ENOENT);
    }
    Ok(OwnedFd(fd))
}

fn acquire_volume_flock(lock_file: &Path) -> Result<OwnedFd, Errno> {
    if let Some(parent) = lock_file.parent() {
        std::fs::create_dir_all(parent).map_err(|_| Errno::EIO)?;
    }
    validate_host_path_no_symlinks(lock_file, false)?;
    let cpath = CString::new(lock_file.as_os_str().as_bytes()).map_err(|_| Errno::EINVAL)?;
    let fd = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_CREAT | libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(Errno::EPERM);
    }
    let guard = OwnedFd(fd);
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(guard.0, &mut st) } != 0 || (st.st_mode & libc::S_IFMT) != libc::S_IFREG
    {
        return Err(Errno::EPERM);
    }
    let rc = unsafe { libc::flock(guard.0, libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        return Err(Errno::EBUSY);
    }
    Ok(guard)
}

fn handoff_rpc(sock: &Path, verb: &str) -> Result<(), Errno> {
    validate_host_path_no_symlinks(sock, true)?;
    let mut stream = StdUnixStream::connect(sock).map_err(|_| Errno::EIO)?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    stream
        .write_all(format!("{verb}\n").as_bytes())
        .map_err(|_| Errno::EIO)?;
    stream.flush().map_err(|_| Errno::EIO)?;
    let mut br = BufReader::new(stream);
    let mut line = String::new();
    br.read_line(&mut line).map_err(|_| Errno::EIO)?;
    match line.trim() {
        "OK" => Ok(()),
        "ESTALE" => Err(Errno::ESTALE),
        "EBUSY" => Err(Errno::EBUSY),
        "EROFS" => Err(Errno::EROFS),
        _ => Err(Errno::EIO),
    }
}

fn list_dir_entries_from_fd(dir_fd: libc::c_int) -> Result<Vec<CString>, Errno> {
    let dup_fd = unsafe { libc::fcntl(dir_fd, libc::F_DUPFD_CLOEXEC, 0) };
    if dup_fd < 0 {
        return Err(Errno::EIO);
    }
    let dirp = unsafe { libc::fdopendir(dup_fd) };
    if dirp.is_null() {
        unsafe {
            libc::close(dup_fd);
        }
        return Err(Errno::EIO);
    }
    let mut names = Vec::new();
    loop {
        let ent = unsafe { libc::readdir(dirp) };
        if ent.is_null() {
            break;
        }
        let cstr = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
        let b = cstr.to_bytes();
        if b == b"." || b == b".." {
            continue;
        }
        names.push(cstr.to_owned());
    }
    unsafe {
        libc::closedir(dirp);
    }
    Ok(names)
}

fn read_all_from_fd(fd: libc::c_int, budget: &mut ImportBudget) -> Result<Vec<u8>, Errno> {
    let mut out = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Errno::EIO);
        }
        if n == 0 {
            break;
        }
        let got = n as usize;
        budget.bytes = budget.bytes.checked_add(got as u64).ok_or(Errno::EFBIG)?;
        if budget.bytes > MAX_ROOTFS_BYTES {
            return Err(Errno::EFBIG);
        }
        out.extend_from_slice(&buf[..got]);
    }
    Ok(out)
}

async fn import_host_fd_into_fs<F: Filesystem>(
    dir_fd: libc::c_int,
    fs: &F,
    dst_dir: &Handle,
    depth: usize,
    budget: &mut ImportBudget,
) -> Result<(), Errno> {
    if depth > MAX_ROOTFS_DEPTH {
        return Err(Errno::ELOOP);
    }
    let mut root_cred = Cred::root();
    root_cred.umask = 0;

    let names = list_dir_entries_from_fd(dir_fd)?;
    for cname in names {
        let name_str = cname.to_str().map_err(|_| Errno::EINVAL)?;
        if name_str.is_empty() || name_str.contains(['/', '\0']) {
            return Err(Errno::EINVAL);
        }

        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc =
            unsafe { libc::fstatat(dir_fd, cname.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
        if rc != 0 {
            return Err(Errno::EIO);
        }

        // Explicitly reject setuid/setgid bits on any entry.
        if (st.st_mode & 0o6000) != 0 {
            return Err(Errno::EPERM);
        }

        let ftype = st.st_mode & libc::S_IFMT;
        let perms = (st.st_mode & 0o777) as u16;

        match ftype {
            libc::S_IFDIR => {
                budget.files += 1;
                if budget.files > MAX_ROOTFS_FILES {
                    return Err(Errno::ENOSPC);
                }
                let child_fd = unsafe {
                    libc::openat(
                        dir_fd,
                        cname.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if child_fd < 0 {
                    return Err(Errno::EPERM);
                }
                let child_fd = OwnedFd(child_fd);
                let mut cst: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(child_fd.0, &mut cst) } != 0
                    || (cst.st_mode & libc::S_IFMT) != libc::S_IFDIR
                    || (cst.st_mode & 0o6000) != 0
                {
                    return Err(Errno::EPERM);
                }
                let sub = match fs.lookup(&root_cred, dst_dir, name_str).await {
                    Ok(ent) => ent.handle,
                    Err(_) => fs.mkdir(&root_cred, dst_dir, name_str, perms).await?.handle,
                };
                Box::pin(import_host_fd_into_fs(
                    child_fd.0,
                    fs,
                    &sub,
                    depth + 1,
                    budget,
                ))
                .await?;
            }
            libc::S_IFREG => {
                budget.files += 1;
                if budget.files > MAX_ROOTFS_FILES {
                    return Err(Errno::ENOSPC);
                }
                let f_fd = unsafe {
                    libc::openat(
                        dir_fd,
                        cname.as_ptr(),
                        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if f_fd < 0 {
                    return Err(Errno::EPERM);
                }
                let f_fd = OwnedFd(f_fd);
                let mut fst: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(f_fd.0, &mut fst) } != 0
                    || (fst.st_mode & libc::S_IFMT) != libc::S_IFREG
                    || (fst.st_mode & 0o6000) != 0
                {
                    return Err(Errno::EPERM);
                }
                let data = read_all_from_fd(f_fd.0, budget)?;
                let mut create_opts = OpenOptions::new();
                create_opts.write(true).create(true).truncate(true);
                let (ent, open_ref) = fs
                    .create(&root_cred, dst_dir, name_str, perms, &create_opts)
                    .await?;
                let _ = ent;
                if !data.is_empty() {
                    let mut off = 0usize;
                    while off < data.len() {
                        let w = fs
                            .write_at(&open_ref, &data[off..], WriteAt::Offset(off as u64))
                            .await?;
                        if w.len == 0 {
                            let _ = fs.release(&open_ref).await;
                            return Err(Errno::EIO);
                        }
                        off += w.len;
                    }
                }
                fs.release(&open_ref).await?;
            }
            libc::S_IFLNK => {
                budget.files += 1;
                if budget.files > MAX_ROOTFS_FILES {
                    return Err(Errno::ENOSPC);
                }
                let mut link_buf = [0u8; 4096];
                let n = unsafe {
                    libc::readlinkat(
                        dir_fd,
                        cname.as_ptr(),
                        link_buf.as_mut_ptr().cast(),
                        link_buf.len(),
                    )
                };
                if n < 0 || (n as usize) >= link_buf.len() {
                    return Err(Errno::EINVAL);
                }
                let target =
                    std::str::from_utf8(&link_buf[..n as usize]).map_err(|_| Errno::EINVAL)?;
                if target.contains('\0') {
                    return Err(Errno::EINVAL);
                }
                let _ = fs.symlink(&root_cred, dst_dir, name_str, target).await?;
            }
            // Reject host block devices, char devices, FIFOs, and Unix sockets!
            libc::S_IFBLK | libc::S_IFCHR | libc::S_IFIFO | libc::S_IFSOCK => {
                return Err(Errno::EPERM);
            }
            _ => return Err(Errno::EPERM),
        }
    }
    Ok(())
}

async fn ensure_dir_chain_on_cowfs(
    fs: &CowFs<NativeSqliteHeadStore, NativePackStore>,
    abs_path: &str,
) -> Result<(), Errno> {
    let mut root_cred = Cred::root();
    root_cred.umask = 0;
    let mut cur = fs.root();
    for seg in abs_path.split('/').filter(|s| !s.is_empty()) {
        if seg == "." || seg == ".." {
            return Err(Errno::EINVAL);
        }
        cur = match fs.lookup(&root_cred, &cur, seg).await {
            Ok(ent) => ent.handle,
            Err(_) => fs.mkdir(&root_cred, &cur, seg, 0o755).await?.handle,
        };
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// NBD-backed `/dev/vdN` `VolumeDevice` (for CSI block volumes staged on `os-nbd`)
// ---------------------------------------------------------------------------

struct NbdVolumeDevice {
    volume_id: String,
    size_bytes: u64,
    block_size: u32,
    readonly: bool,
    csi_fence: Option<OciCsiFenceCheck>,
    fenced: Cell<bool>,
    client: RefCell<Option<NbdClient<tokio::net::UnixStream>>>,
    io_sem: Semaphore,
}

impl NbdVolumeDevice {
    async fn connect(
        nbd_socket: &Path,
        export_name: &str,
        readonly: bool,
        csi_fence: Option<OciCsiFenceCheck>,
    ) -> Result<Self, Errno> {
        validate_host_path_no_symlinks(nbd_socket, true)?;
        if let Some(ref f) = csi_fence {
            f.verify()?;
        }
        let mut client = NbdClient::connect_unix(nbd_socket)
            .await
            .map_err(|_| Errno::EIO)?;
        let info = client.go(export_name).await.map_err(|_| Errno::EIO)?;
        let eff_ro = readonly || (info.transmission_flags & os_nbd::NBD_FLAG_READ_ONLY) != 0;
        Ok(Self {
            volume_id: export_name.to_string(),
            size_bytes: info.size_bytes,
            block_size: info.preferred_block_size.unwrap_or(4096),
            readonly: eff_ro,
            csi_fence,
            fenced: Cell::new(false),
            client: RefCell::new(Some(client)),
            io_sem: Semaphore::new(1),
        })
    }

    fn check_write_fence(&self) -> Result<(), Errno> {
        if self.readonly {
            return Err(Errno::EROFS);
        }
        if self.fenced.get() {
            return Err(Errno::ESTALE);
        }
        if let Some(ref f) = self.csi_fence
            && f.verify().is_err()
        {
            self.fenced.set(true);
            return Err(Errno::ESTALE);
        }
        Ok(())
    }

    fn map_nbd_err(&self, err: NbdClientError, is_write_op: bool) -> Errno {
        match err {
            NbdClientError::ServerError(code) if code == NBD_EPERM => {
                if self.readonly {
                    Errno::EROFS
                } else {
                    self.fenced.set(true);
                    Errno::ESTALE
                }
            }
            NbdClientError::ServerError(code) if code == os_nbd::NBD_EIO => {
                if is_write_op
                    && !self.readonly
                    && self.csi_fence.as_ref().is_some_and(|f| f.verify().is_err())
                {
                    self.fenced.set(true);
                    Errno::ESTALE
                } else {
                    Errno::EIO
                }
            }
            NbdClientError::ServerError(code) if code == os_nbd::NBD_EINVAL => Errno::EINVAL,
            NbdClientError::ServerError(code) if code == os_nbd::NBD_ENOSPC => Errno::ENOSPC,
            NbdClientError::ServerError(code) if code == os_nbd::NBD_EOVERFLOW => Errno::EFBIG,
            _ => Errno::EIO,
        }
    }

    async fn flush_and_close(&self) -> Result<(), Errno> {
        let _permit = self.io_sem.acquire().await.map_err(|_| Errno::EIO)?;
        let mut flush_res = Ok(());
        let client_opt = self.client.borrow_mut().take();
        if !self.readonly {
            if let Err(e) = self.check_write_fence() {
                flush_res = Err(e);
            } else if let Some(mut c) = client_opt {
                if let Err(e) = c.flush().await {
                    flush_res = Err(self.map_nbd_err(e, true));
                }
                let _ = c.disconnect().await;
                return flush_res;
            }
        }
        if let Some(c) = client_opt {
            let _ = c.disconnect().await;
        }
        flush_res
    }
}

impl VolumeDevice for NbdVolumeDevice {
    fn volume_id(&self) -> &str {
        &self.volume_id
    }

    fn is_read_only(&self) -> bool {
        self.readonly
    }

    fn is_raw_block(&self) -> bool {
        true
    }

    fn read_raw<'a>(&'a self, buf: &'a mut [u8], offset: u64) -> BoxFuture<'a, usize> {
        Box::pin(async move {
            if buf.is_empty() || offset >= self.size_bytes {
                return Ok(0);
            }
            let _permit = self.io_sem.acquire().await.map_err(|_| Errno::EIO)?;
            let mut client = self.client.borrow_mut().take().ok_or(Errno::EBADF)?;
            let total = (self.size_bytes - offset).min(buf.len() as u64) as usize;
            let max_chunk = os_nbd::MAX_NBD_IO_BYTES as usize;
            let mut done = 0usize;
            while done < total {
                let chunk = (total - done).min(max_chunk);
                match client.read(offset + done as u64, chunk as u32).await {
                    Ok(data) => {
                        let n = data.len().min(chunk);
                        buf[done..done + n].copy_from_slice(&data[..n]);
                        done += n;
                        if n < chunk {
                            break;
                        }
                    }
                    Err(e) => {
                        if !matches!(e, NbdClientError::Io(_)) {
                            *self.client.borrow_mut() = Some(client);
                        }
                        return Err(self.map_nbd_err(e, false));
                    }
                }
            }
            *self.client.borrow_mut() = Some(client);
            Ok(done)
        })
    }

    fn write_raw<'a>(&'a self, buf: &'a [u8], offset: u64) -> BoxFuture<'a, usize> {
        Box::pin(async move {
            self.check_write_fence()?;
            if buf.is_empty() {
                return Ok(0);
            }
            let _permit = self.io_sem.acquire().await.map_err(|_| Errno::EIO)?;
            let mut client = self.client.borrow_mut().take().ok_or(Errno::EBADF)?;
            let max_chunk = os_nbd::MAX_NBD_IO_BYTES as usize;
            let mut done = 0usize;
            while done < buf.len() {
                let chunk = (buf.len() - done).min(max_chunk);
                match client
                    .write(offset + done as u64, &buf[done..done + chunk], false)
                    .await
                {
                    Ok(()) => done += chunk,
                    Err(e) => {
                        if !matches!(e, NbdClientError::Io(_)) {
                            *self.client.borrow_mut() = Some(client);
                        }
                        return Err(self.map_nbd_err(e, true));
                    }
                }
            }
            *self.client.borrow_mut() = Some(client);
            Ok(done)
        })
    }

    fn sync_raw(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if self.readonly {
                return Ok(());
            }
            self.check_write_fence()?;
            let _permit = self.io_sem.acquire().await.map_err(|_| Errno::EIO)?;
            let mut client = self.client.borrow_mut().take().ok_or(Errno::EBADF)?;
            let res = client.flush().await;
            if !matches!(res, Err(NbdClientError::Io(_))) {
                *self.client.borrow_mut() = Some(client);
            }
            res.map_err(|e| self.map_nbd_err(e, true))
        })
    }

    fn trim_raw(&self, offset: u64, len: u64) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.check_write_fence()?;
            if len == 0 {
                return Ok(());
            }
            let _permit = self.io_sem.acquire().await.map_err(|_| Errno::EIO)?;
            let mut client = self.client.borrow_mut().take().ok_or(Errno::EBADF)?;
            let mut done = 0u64;
            while done < len {
                let chunk = (len - done).min(u32::MAX as u64) as u32;
                match client.trim(offset + done, chunk, false).await {
                    Ok(()) => done += u64::from(chunk),
                    Err(e) => {
                        if !matches!(e, NbdClientError::Io(_)) {
                            *self.client.borrow_mut() = Some(client);
                        }
                        return Err(self.map_nbd_err(e, true));
                    }
                }
            }
            *self.client.borrow_mut() = Some(client);
            Ok(())
        })
    }

    fn blk_info<'a>(&'a self, dev_name: &'a str) -> BoxFuture<'a, BlkInfoResp> {
        Box::pin(async move {
            Ok(BlkInfoResp {
                device: format!("/dev/{dev_name}"),
                volume: self.volume_id.clone(),
                size: self.size_bytes,
                sector: self.block_size,
                writer_model: WriterModel::Fenced,
                durability: Durability::FencedCommit,
                read_only: self.readonly,
                formatted: true,
            })
        })
    }

    fn blk_lease(&self) -> BoxFuture<'_, BlkLeaseResp> {
        Box::pin(async move {
            let fenced =
                self.fenced.get() || self.csi_fence.as_ref().is_some_and(|f| f.verify().is_err());
            let epoch = self
                .csi_fence
                .as_ref()
                .map(|f| f.expected_epoch)
                .unwrap_or(0);
            Ok(BlkLeaseResp {
                volume: self.volume_id.clone(),
                held: !self.readonly && !fenced,
                fenced,
                expired: fenced,
                lease_expires_at: None,
                incarnation: 0,
                fence: epoch,
                epoch,
                read_only: self.readonly,
            })
        })
    }

    fn cowfs_info(&self) -> BoxFuture<'_, CowfsInfoResp> {
        Box::pin(async { Err(Errno::EOPNOTSUPP) })
    }

    fn cowfs_snapshot<'a>(
        &'a self,
        _req: &'a CowfsSnapshotReq,
    ) -> BoxFuture<'a, CowfsSnapshotResp> {
        Box::pin(async { Err(Errno::EOPNOTSUPP) })
    }

    fn cowfs_fork<'a>(&'a self, _req: &'a CowfsForkReq) -> BoxFuture<'a, CowfsForkResp> {
        Box::pin(async { Err(Errno::EOPNOTSUPP) })
    }

    fn mkfs(&self, _force: bool) -> BoxFuture<'_, CowfsInfoResp> {
        Box::pin(async { Err(Errno::EOPNOTSUPP) })
    }
}

// ---------------------------------------------------------------------------
// Live-Fenced `CowFs` Wrapper (`vfs::Filesystem`) enforcing `FenceStateFile` mid-run (P1-4)
// ---------------------------------------------------------------------------

struct FencedCowFs {
    inner: Rc<CowFs<NativeSqliteHeadStore, NativePackStore>>,
    fence_flag: Option<Arc<AtomicBool>>,
    csi_fence: Option<OciCsiFenceCheck>,
    fenced: Cell<bool>,
}

impl FencedCowFs {
    fn check_mut_fence(&self) -> Result<(), Errno> {
        if self.fenced.get() {
            return Err(Errno::ESTALE);
        }
        if self
            .fence_flag
            .as_ref()
            .is_some_and(|f| f.load(Ordering::SeqCst))
        {
            self.fenced.set(true);
            return Err(Errno::ESTALE);
        }
        if self.csi_fence.as_ref().is_some_and(|c| c.verify().is_err()) {
            self.fenced.set(true);
            return Err(Errno::ESTALE);
        }
        Ok(())
    }

    fn latch_if_stale<T>(&self, res: Result<T, Errno>) -> Result<T, Errno> {
        if matches!(res, Err(Errno::ESTALE)) {
            self.fenced.set(true);
        }
        res
    }
}

impl Filesystem for FencedCowFs {
    fn id(&self) -> &FsId {
        self.inner.id()
    }

    fn capabilities(&self) -> abi::contract::FsCapabilities {
        self.inner.capabilities()
    }

    fn root(&self) -> Handle {
        self.inner.root()
    }

    fn lookup<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, vfs::Entry> {
        self.inner.lookup(cred, dir, name)
    }

    fn walk<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        names: &'a [String],
    ) -> BoxFuture<'a, vfs::Walked> {
        self.inner.walk(cred, dir, names)
    }

    fn parent<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
    ) -> BoxFuture<'a, Option<(vfs::Entry, String)>> {
        self.inner.parent(cred, dir)
    }

    fn metadata<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, vfs::Metadata> {
        self.inner.metadata(cred, handle)
    }

    fn setattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        attr: &'a SetAttr,
    ) -> BoxFuture<'a, vfs::Metadata> {
        Box::pin(async move {
            self.check_mut_fence()?;
            self.latch_if_stale(self.inner.setattr(cred, handle, attr).await)
        })
    }

    fn setattr_open<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        open: &'a vfs::OpenRef,
        attr: &'a SetAttr,
    ) -> BoxFuture<'a, vfs::Metadata> {
        Box::pin(async move {
            self.check_mut_fence()?;
            self.latch_if_stale(self.inner.setattr_open(cred, handle, open, attr).await)
        })
    }

    fn read_dir<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
    ) -> BoxFuture<'a, Vec<vfs::DirEntry>> {
        self.inner.read_dir(cred, dir)
    }

    fn read_dir_page<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        cookie: u64,
        max_entries: usize,
    ) -> BoxFuture<'a, vfs::DirPage> {
        self.inner.read_dir_page(cred, dir, cookie, max_entries)
    }

    fn read_link<'a>(&'a self, cred: &'a Cred, link: &'a Handle) -> BoxFuture<'a, String> {
        self.inner.read_link(cred, link)
    }

    fn create<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        options: &'a OpenOptions,
    ) -> BoxFuture<'a, (vfs::Entry, vfs::OpenRef)> {
        Box::pin(async move {
            self.check_mut_fence()?;
            self.latch_if_stale(self.inner.create(cred, dir, name, mode, options).await)
        })
    }

    fn mkdir<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
    ) -> BoxFuture<'a, vfs::Entry> {
        Box::pin(async move {
            self.check_mut_fence()?;
            self.latch_if_stale(self.inner.mkdir(cred, dir, name, mode).await)
        })
    }

    fn mknod<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        rdev: &'a str,
    ) -> BoxFuture<'a, vfs::Entry> {
        Box::pin(async move {
            self.check_mut_fence()?;
            self.latch_if_stale(self.inner.mknod(cred, dir, name, mode, rdev).await)
        })
    }

    fn mksock<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
    ) -> BoxFuture<'a, vfs::Entry> {
        Box::pin(async move {
            self.check_mut_fence()?;
            self.latch_if_stale(self.inner.mksock(cred, dir, name, mode).await)
        })
    }

    fn symlink<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        target: &'a str,
    ) -> BoxFuture<'a, vfs::Entry> {
        Box::pin(async move {
            self.check_mut_fence()?;
            self.latch_if_stale(self.inner.symlink(cred, dir, name, target).await)
        })
    }

    fn link<'a>(
        &'a self,
        cred: &'a Cred,
        target: &'a Handle,
        dir: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, vfs::Entry> {
        Box::pin(async move {
            self.check_mut_fence()?;
            self.latch_if_stale(self.inner.link(cred, target, dir, name).await)
        })
    }

    fn unlink<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.check_mut_fence()?;
            self.latch_if_stale(self.inner.unlink(cred, dir, name).await)
        })
    }

    fn unlink_if<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        node: vfs::NodeId,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.check_mut_fence()?;
            self.latch_if_stale(self.inner.unlink_if(cred, dir, name, node).await)
        })
    }

    fn rmdir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.check_mut_fence()?;
            self.latch_if_stale(self.inner.rmdir(cred, dir, name).await)
        })
    }

    fn rename<'a>(
        &'a self,
        cred: &'a Cred,
        from_dir: &'a Handle,
        from: &'a str,
        to_dir: &'a Handle,
        to: &'a str,
        flags: vfs::RenameFlags,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.check_mut_fence()?;
            self.latch_if_stale(
                self.inner
                    .rename(cred, from_dir, from, to_dir, to, flags)
                    .await,
            )
        })
    }

    fn getxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Vec<u8>> {
        self.inner.getxattr(cred, handle, name)
    }

    fn setxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
        value: &'a [u8],
        flags: vfs::XattrFlags,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.check_mut_fence()?;
            self.latch_if_stale(self.inner.setxattr(cred, handle, name, value, flags).await)
        })
    }

    fn listxattr<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Vec<String>> {
        self.inner.listxattr(cred, handle)
    }

    fn removexattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.check_mut_fence()?;
            self.latch_if_stale(self.inner.removexattr(cred, handle, name).await)
        })
    }

    fn statfs<'a>(&'a self, cred: &'a Cred) -> BoxFuture<'a, vfs::StatFs> {
        self.inner.statfs(cred)
    }

    fn open<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        options: &'a OpenOptions,
    ) -> BoxFuture<'a, vfs::OpenRef> {
        Box::pin(async move {
            let mutating = options.access().is_ok_and(|a| a.writes())
                || options.is_truncate()
                || options.is_create()
                || options.is_create_new();
            if mutating {
                self.check_mut_fence()?;
            }
            self.latch_if_stale(self.inner.open(cred, handle, options).await)
        })
    }

    fn open_metadata<'a>(&'a self, open: &'a vfs::OpenRef) -> BoxFuture<'a, vfs::Metadata> {
        self.inner.open_metadata(open)
    }

    fn read_at<'a>(
        &'a self,
        open: &'a vfs::OpenRef,
        buf: &'a mut [u8],
        offset: u64,
    ) -> BoxFuture<'a, usize> {
        self.inner.read_at(open, buf, offset)
    }

    fn write_at<'a>(
        &'a self,
        open: &'a vfs::OpenRef,
        buf: &'a [u8],
        at: WriteAt,
    ) -> BoxFuture<'a, vfs::Written> {
        Box::pin(async move {
            self.check_mut_fence()?;
            self.latch_if_stale(self.inner.write_at(open, buf, at).await)
        })
    }

    fn set_len<'a>(&'a self, open: &'a vfs::OpenRef, size: u64) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.check_mut_fence()?;
            self.latch_if_stale(self.inner.set_len(open, size).await)
        })
    }

    fn sync_all<'a>(&'a self, open: &'a vfs::OpenRef) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.check_mut_fence()?;
            self.latch_if_stale(self.inner.sync_all(open).await)
        })
    }

    fn sync_data<'a>(&'a self, open: &'a vfs::OpenRef) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.check_mut_fence()?;
            self.latch_if_stale(self.inner.sync_data(open).await)
        })
    }

    fn sync_handle<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.check_mut_fence()?;
            self.latch_if_stale(self.inner.sync_handle(cred, handle).await)
        })
    }

    fn lock<'a>(
        &'a self,
        open: &'a vfs::OpenRef,
        family: vfs::LockFamily,
        kind: vfs::LockKind,
        range: vfs::LockRange,
    ) -> BoxFuture<'a, ()> {
        self.inner.lock(open, family, kind, range)
    }

    fn try_lock<'a>(
        &'a self,
        open: &'a vfs::OpenRef,
        family: vfs::LockFamily,
        kind: vfs::LockKind,
        range: vfs::LockRange,
    ) -> BoxFuture<'a, ()> {
        self.inner.try_lock(open, family, kind, range)
    }

    fn unlock<'a>(
        &'a self,
        open: &'a vfs::OpenRef,
        family: vfs::LockFamily,
        range: vfs::LockRange,
    ) -> BoxFuture<'a, ()> {
        self.inner.unlock(open, family, range)
    }

    fn test_lock<'a>(
        &'a self,
        open: &'a vfs::OpenRef,
        kind: vfs::LockKind,
        range: vfs::LockRange,
    ) -> BoxFuture<'a, Option<vfs::Conflict>> {
        self.inner.test_lock(open, kind, range)
    }

    fn release<'a>(&'a self, open: &'a vfs::OpenRef) -> BoxFuture<'a, ()> {
        self.inner.release(open)
    }

    fn reflink<'a>(
        &'a self,
        cred: &'a Cred,
        src_open: &'a vfs::OpenRef,
        dst_open: &'a vfs::OpenRef,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.check_mut_fence()?;
            self.latch_if_stale(self.inner.reflink(cred, src_open, dst_open).await)
        })
    }

    fn clone_source<'a>(&'a self, open: &'a vfs::OpenRef) -> BoxFuture<'a, vfs::CloneSource> {
        self.inner.clone_source(open)
    }

    fn reflink_range<'a>(
        &'a self,
        src: &'a vfs::CloneSource,
        dst: &'a vfs::OpenRef,
        range: abi::volume::FileCloneRangeReq,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.check_mut_fence()?;
            self.latch_if_stale(self.inner.reflink_range(src, dst, range).await)
        })
    }

    fn sync_fs<'a>(&'a self, cred: &'a Cred) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.check_mut_fence()?;
            self.latch_if_stale(self.inner.sync_fs(cred).await)
        })
    }
}

// ---------------------------------------------------------------------------
// Safe Non-Blocking Host FIFO / Regular-File Stdio Pumping (P0-3 + P1-5)
// ---------------------------------------------------------------------------

struct StdioHandles {
    fds: BTreeMap<u32, GuestFdEntry>,
    stop: Arc<AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl StdioHandles {
    fn setup(
        stdin_path: Option<PathBuf>,
        stdout_path: Option<PathBuf>,
        stderr_path: Option<PathBuf>,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let mut fds = BTreeMap::new();
        let mut threads = Vec::new();

        // Stdin (fd 0)
        if let Some(path) = stdin_path {
            let (stdin_r, stdin_w) = PipeHandle::pair();
            fds.insert(
                0,
                GuestFdEntry {
                    kind: GuestFdKind::Pipe {
                        handle: stdin_r,
                        nonblock: false,
                    },
                    cloexec: false,
                },
            );
            let stop_c = Arc::clone(&stop);
            if let Ok(th) = std::thread::Builder::new()
                .name("os-oci-stdin".into())
                .spawn(move || pump_host_stdin(path, stdin_w, stop_c))
            {
                threads.push(th);
            }
        } else {
            fds.insert(
                0,
                GuestFdEntry {
                    kind: GuestFdKind::NullIn,
                    cloexec: false,
                },
            );
        }

        // Stdout (fd 1)
        let (stdout_r, stdout_w) = PipeHandle::pair();
        fds.insert(
            1,
            GuestFdEntry {
                kind: GuestFdKind::Pipe {
                    handle: stdout_w,
                    nonblock: false,
                },
                cloexec: false,
            },
        );
        let stop_out = Arc::clone(&stop);
        if let Ok(th) = std::thread::Builder::new()
            .name("os-oci-stdout".into())
            .spawn(move || pump_host_output(stdout_path, stdout_r, stop_out))
        {
            threads.push(th);
        }

        // Stderr (fd 2)
        let (stderr_r, stderr_w) = PipeHandle::pair();
        fds.insert(
            2,
            GuestFdEntry {
                kind: GuestFdKind::Pipe {
                    handle: stderr_w,
                    nonblock: false,
                },
                cloexec: false,
            },
        );
        let stop_err = Arc::clone(&stop);
        if let Ok(th) = std::thread::Builder::new()
            .name("os-oci-stderr".into())
            .spawn(move || pump_host_output(stderr_path, stderr_r, stop_err))
        {
            threads.push(th);
        }

        Self { fds, stop, threads }
    }
}

fn pump_host_stdin(path: PathBuf, stdin_w: PipeHandle, stop: Arc<AtomicBool>) {
    if validate_stdio_path(&path, true).is_err() {
        drop(stdin_w);
        return;
    }
    let Ok(cpath) = CString::new(path.as_os_str().as_bytes()) else {
        drop(stdin_w);
        return;
    };
    let fd = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        drop(stdin_w);
        return;
    }
    let guard = OwnedFd(fd);
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(guard.0, &mut st) } != 0 {
        drop(stdin_w);
        return;
    }
    let ftype = st.st_mode & libc::S_IFMT;
    if ftype != libc::S_IFIFO && ftype != libc::S_IFREG {
        drop(stdin_w);
        return;
    }

    let mut buf = [0u8; 4096];
    if ftype == libc::S_IFIFO {
        let mut saw_writer = false;
        while !stop.load(Ordering::SeqCst) && !stdin_w.buf.reader_gone() {
            let mut pfd = libc::pollfd {
                fd: guard.0,
                events: libc::POLLIN,
                revents: 0,
            };
            let prc = unsafe { libc::poll(&mut pfd, 1, 20) };
            if prc < 0 {
                break;
            }
            if prc == 0 {
                continue;
            }
            if (pfd.revents & libc::POLLIN) != 0 {
                let n = unsafe { libc::read(guard.0, buf.as_mut_ptr().cast(), buf.len()) };
                if n > 0 {
                    saw_writer = true;
                    let mut off = 0usize;
                    let len = n as usize;
                    while off < len && !stop.load(Ordering::SeqCst) {
                        match stdin_w.buf.write(&buf[off..len], false, || {
                            if stop.load(Ordering::SeqCst) {
                                Err(Errno::EINTR)
                            } else {
                                Ok(())
                            }
                        }) {
                            Ok(0) | Err(_) => return,
                            Ok(w) => off += w,
                        }
                    }
                } else if n == 0 {
                    if saw_writer || (pfd.revents & libc::POLLHUP) != 0 {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            } else if (pfd.revents & libc::POLLHUP) != 0 && !saw_writer {
                // No writer has opened the FIFO yet: sleep to avoid 100% CPU busy-spin (P1-5).
                std::thread::sleep(Duration::from_millis(10));
            } else if ((pfd.revents & libc::POLLHUP) != 0 && saw_writer)
                || (pfd.revents & (libc::POLLERR | libc::POLLNVAL)) != 0
            {
                break;
            }
        }
    } else {
        while !stop.load(Ordering::SeqCst) && !stdin_w.buf.reader_gone() {
            let n = unsafe { libc::read(guard.0, buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break;
            }
            let len = n as usize;
            let mut off = 0usize;
            while off < len && !stop.load(Ordering::SeqCst) {
                match stdin_w.buf.write(&buf[off..len], false, || {
                    if stop.load(Ordering::SeqCst) {
                        Err(Errno::EINTR)
                    } else {
                        Ok(())
                    }
                }) {
                    Ok(0) | Err(_) => return,
                    Ok(w) => off += w,
                }
            }
        }
    }
    drop(stdin_w);
}

struct OpenedOutput {
    fd: OwnedFd,
    is_fifo: bool,
}

fn open_host_output_fd(path: &Path, stop: &AtomicBool) -> Option<OpenedOutput> {
    if validate_stdio_path(path, false).is_err() {
        return None;
    }
    let cpath = CString::new(path.as_os_str().as_bytes()).ok()?;
    let existing_mode = std::fs::symlink_metadata(path)
        .ok()
        .map(|m| std::os::unix::fs::MetadataExt::mode(&m) & libc::S_IFMT);

    if existing_mode == Some(libc::S_IFIFO) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let fd = unsafe {
                libc::open(
                    cpath.as_ptr(),
                    libc::O_WRONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd >= 0 {
                let owned = OwnedFd(fd);
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(owned.0, &mut st) } == 0
                    && (st.st_mode & libc::S_IFMT) == libc::S_IFIFO
                {
                    // Keep O_NONBLOCK enabled so stalled readers never deadlock Wait/Delete (P1-5).
                    return Some(OpenedOutput {
                        fd: owned,
                        is_fifo: true,
                    });
                }
                return None;
            }
            if stop.load(Ordering::SeqCst) || std::time::Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    } else {
        let fd = unsafe {
            libc::open(
                cpath.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600 as libc::c_uint,
            )
        };
        if fd < 0 {
            return None;
        }
        let owned = OwnedFd(fd);
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(owned.0, &mut st) } != 0
            || (st.st_mode & libc::S_IFMT) != libc::S_IFREG
        {
            return None;
        }
        Some(OpenedOutput {
            fd: owned,
            is_fifo: false,
        })
    }
}

fn write_output_nonblock(out: &OpenedOutput, mut data: &[u8], stop: &AtomicBool) -> bool {
    while !data.is_empty() {
        let n = unsafe { libc::write(out.fd.0, data.as_ptr().cast(), data.len()) };
        if n > 0 {
            data = &data[n as usize..];
            continue;
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if out.is_fifo && err.kind() == std::io::ErrorKind::WouldBlock {
            if stop.load(Ordering::SeqCst) {
                return false;
            }
            let mut pfd = libc::pollfd {
                fd: out.fd.0,
                events: libc::POLLOUT,
                revents: 0,
            };
            let prc = unsafe { libc::poll(&mut pfd, 1, 20) };
            if prc < 0 || (pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)) != 0 {
                return false;
            }
            continue;
        }
        return false;
    }
    true
}

fn pump_host_output(path: Option<PathBuf>, pipe_r: PipeHandle, stop: Arc<AtomicBool>) {
    let mut sink = path.as_deref().and_then(|p| open_host_output_fd(p, &stop));
    let mut buf = [0u8; 4096];
    loop {
        match pipe_r.buf.read(&mut buf, false, || {
            if stop.load(Ordering::SeqCst) {
                Err(Errno::EINTR)
            } else {
                Ok(())
            }
        }) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if let Some(ref out) = sink
                    && !write_output_nonblock(out, &buf[..n], &stop)
                {
                    sink = None;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Lifecycle State Machine for Container & Exec Processes
// ---------------------------------------------------------------------------

struct LifecycleState {
    state: OciContainerState,
    pid: u32,
    exit_status: Option<OciExitStatus>,
    deleted: bool,
}

struct PendingPid1 {
    sig_ctrl: Arc<SignalControl>,
    image: Option<LoadedImage>,
    umask: u16,
    stdin_path: Option<PathBuf>,
    stdout_path: Option<PathBuf>,
    stderr_path: Option<PathBuf>,
}

struct RunningPid1 {
    _epoch_ticker: Option<EpochTickerGuard>,
    reaper_thread: Option<std::thread::JoinHandle<()>>,
    stdio_stop: Option<Arc<AtomicBool>>,
}

/// Handle to an `exec` process created inside an [`OciContainerHandle`].
pub struct OciExecHandle {
    pub exec_id: String,
    kernel: KernelClient,
    runtime: Arc<WasmRuntime>,
    lifecycle: Arc<(Mutex<LifecycleState>, Condvar)>,
    cancel_flag: Arc<AtomicBool>,
    pending: Mutex<Option<PendingExec>>,
    running: Mutex<Option<RunningPid1>>,
}

struct PendingExec {
    pid: u32,
    sig_ctrl: Arc<SignalControl>,
    fds: BTreeMap<u32, GuestFdEntry>,
    image: LoadedImage,
    stdio_stop: Arc<AtomicBool>,
    stdio_threads: Vec<std::thread::JoinHandle<()>>,
}

impl OciExecHandle {
    pub fn state(&self) -> OciStatusSnapshot {
        let g = self.lifecycle.0.lock().unwrap();
        OciStatusSnapshot {
            state: g.state,
            pid: g.pid,
            exit_status: g.exit_status,
        }
    }

    pub fn start(&self) -> Result<u32, Errno> {
        let pending = self.pending.lock().unwrap().take().ok_or(Errno::EINVAL)?;
        let pid = pending.pid;
        {
            let mut g = self.lifecycle.0.lock().unwrap();
            if g.state != OciContainerState::Created {
                return Err(Errno::EINVAL);
            }
            g.state = OciContainerState::Running;
        }
        let ticker = EpochTickerGuard::start(self.runtime.engine.clone());
        let proc_h = spawn_process_thread_with_exit(
            pid,
            pending.sig_ctrl,
            pending.fds,
            pending.image,
            0o022,
            None,
            self.kernel.clone(),
            Arc::clone(&self.runtime),
            Some(Arc::clone(&self.cancel_flag)),
        );
        let kernel = self.kernel.clone();
        let lifecycle = Arc::clone(&self.lifecycle);
        let cancel = Arc::clone(&self.cancel_flag);
        let runtime = Arc::clone(&self.runtime);
        let stdio_stop = Arc::clone(&pending.stdio_stop);
        let stdio_threads = pending.stdio_threads;

        let reaper = std::thread::Builder::new()
            .name(format!("os-oci-exec-reap-{pid}"))
            .spawn(move || {
                let status = wait_and_reap_pid(pid, proc_h, &kernel, &runtime, &cancel);
                stdio_stop.store(true, Ordering::SeqCst);
                for th in stdio_threads {
                    let _ = th.join();
                }
                let mut g = lifecycle.0.lock().unwrap();
                g.state = OciContainerState::Stopped;
                g.exit_status = Some(status);
                lifecycle.1.notify_all();
            })
            .ok();

        *self.running.lock().unwrap() = Some(RunningPid1 {
            _epoch_ticker: Some(ticker),
            reaper_thread: reaper,
            stdio_stop: Some(pending.stdio_stop),
        });
        Ok(pid)
    }

    pub fn kill(&self, signal: u8) -> Result<(), Errno> {
        let pid = self.lifecycle.0.lock().unwrap().pid;
        if signal == 9 {
            self.cancel_flag.store(true, Ordering::SeqCst);
            self.runtime.engine.increment_epoch();
        }
        let _ = self.kernel.try_call_sync(|reply| KernelCmd::Kill {
            pid: 1,
            target: pid.to_string(),
            signal,
            reply,
        });
        if signal == 9 {
            self.runtime.engine.increment_epoch();
        }
        Ok(())
    }

    pub fn wait(&self) -> OciExitStatus {
        let mut g = self.lifecycle.0.lock().unwrap();
        while g.state != OciContainerState::Stopped {
            g = self.lifecycle.1.wait(g).unwrap();
        }
        g.exit_status.unwrap_or(OciExitStatus {
            exit_code: 0,
            signal: None,
            exited_at_ns: now_unix_nanos(),
        })
    }

    pub fn delete(&self) -> Result<OciExitStatus, Errno> {
        if let Some(pending) = self.pending.lock().unwrap().take() {
            let PendingExec {
                fds,
                stdio_stop,
                stdio_threads,
                ..
            } = pending;
            stdio_stop.store(true, Ordering::SeqCst);
            // Drop write ends of stdio pipes BEFORE joining stdio threads so `pump_host_output`
            // sees EOF immediately and can never deadlock on an unstarted exec! (P1-2)
            drop(fds);
            for th in stdio_threads {
                let _ = th.join();
            }
            let mut g = self.lifecycle.0.lock().unwrap();
            let st = OciExitStatus {
                exit_code: 0,
                signal: None,
                exited_at_ns: now_unix_nanos(),
            };
            g.state = OciContainerState::Stopped;
            g.exit_status = Some(st);
            g.deleted = true;
            self.lifecycle.1.notify_all();
            return Ok(st);
        }
        if self.lifecycle.0.lock().unwrap().state == OciContainerState::Running {
            let _ = self.kill(9);
        }
        let st = self.wait();
        if let Some(mut r) = self.running.lock().unwrap().take() {
            if let Some(stop) = r.stdio_stop.take() {
                stop.store(true, Ordering::SeqCst);
            }
            if let Some(th) = r.reaper_thread.take() {
                let _ = th.join();
            }
        }
        self.lifecycle.0.lock().unwrap().deleted = true;
        Ok(st)
    }
}

/// Handle to an isolated OCI container running on a dedicated `KernelActor`.
pub struct OciContainerHandle {
    pub container_id: String,
    is_sandbox: bool,
    kernel: KernelClient,
    runtime: Arc<WasmRuntime>,
    lifecycle: Arc<(Mutex<LifecycleState>, Condvar)>,
    cancel_flag: Arc<AtomicBool>,
    pending: Mutex<Option<PendingPid1>>,
    running: Mutex<Option<RunningPid1>>,
    actor_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    done_rx: Mutex<Option<std::sync::mpsc::Receiver<Result<(), Errno>>>>,
}

impl OciContainerHandle {
    /// Boot an isolated `KernelActor`, import `rootfs_dir` safely, mount CSI `CowFs` and raw
    /// `/dev/vdN` volumes, apply OCI `process.user`, validate & load the PID 1 Wasm binary
    /// (rejecting `\x7fELF` with `Errno::ENOEXEC`), and return a handle in
    /// [`OciContainerState::Created`].
    pub fn create(spec: OciBundleRunSpec) -> Result<Self, Errno> {
        if !spec.is_sandbox && spec.argv.is_empty() {
            return Err(Errno::EINVAL);
        }
        // Validate host stdio paths upfront (P0-3: rejects `..`, symlinks, special files).
        if let Some(ref p) = spec.stdin_path {
            validate_stdio_path(p, true)?;
        }
        if let Some(ref p) = spec.stdout_path {
            validate_stdio_path(p, false)?;
        }
        if let Some(ref p) = spec.stderr_path {
            validate_stdio_path(p, false)?;
        }

        std::fs::create_dir_all(&spec.work_store_dir).map_err(|_| Errno::EIO)?;
        let runtime = WasmRuntime::shared().map_err(|_| Errno::EIO)?;

        let (ready_tx, ready_rx) =
            std::sync::mpsc::channel::<Result<(Arc<SignalControl>, Option<LoadedImage>), Errno>>();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<Result<(), Errno>>();

        let wake = WakeBus::new();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<KernelCmd>();
        let hook_tx = cmd_tx.clone();
        let hangup_tx = cmd_tx.clone();
        let ptys = PtyTable::new(
            Arc::new(move |pgrp, signal| {
                let _ = hook_tx.send(KernelCmd::KillPgrp { pgrp, signal });
            }),
            Arc::new(move |number, pgrp, sid| {
                let _ = hangup_tx.send(KernelCmd::PtyHangup { number, pgrp, sid });
            }),
        );

        let actor_spec = spec.clone();
        let actor_wake = Arc::clone(&wake);
        let actor_ptys = Arc::clone(&ptys);

        let short_id: String = spec.container_id.chars().take(16).collect();
        let actor_thread = std::thread::Builder::new()
            .name(format!("os-oci-{short_id}"))
            .stack_size(8 * 1024 * 1024)
            .spawn(move || {
                let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    let _ = ready_tx.send(Err(Errno::EIO));
                    return;
                };
                let local = tokio::task::LocalSet::new();
                local.block_on(&rt, async move {
                    match boot_oci_actor(&actor_spec, actor_wake, actor_ptys).await {
                        Ok(mut booted) => {
                            let _ = ready_tx.send(Ok((booted.pid1_sig, booted.pid1_img)));
                            booted.actor.run_sandbox_loop(cmd_rx).await;

                            // Flush & fence-verify ALL writable CSI CowFs, RawBlock, and NBD mounts!
                            let mut flush_err: Option<Errno> = None;
                            for csi_fs in &booted.csi_cowfs {
                                if !csi_fs.readonly {
                                    let csi_fenced = csi_fs
                                        .fence_flag
                                        .as_ref()
                                        .is_some_and(|f| f.load(Ordering::SeqCst))
                                        || csi_fs
                                            .csi_fence
                                            .as_ref()
                                            .is_some_and(|f| f.verify().is_err());
                                    if csi_fenced {
                                        flush_err = Some(Errno::ESTALE);
                                    } else {
                                        if let Err(e) = csi_fs.fs.renew_lease().await
                                            && (e == Errno::ESTALE || flush_err.is_none())
                                        {
                                            flush_err = Some(e);
                                        }
                                        if let Err(e) = csi_fs.fs.commit_tx_group().await
                                            && (e == Errno::ESTALE || flush_err.is_none())
                                        {
                                            flush_err = Some(e);
                                        }
                                    }
                                }
                            }
                            for csi_raw in &booted.csi_raw {
                                if !csi_raw.readonly {
                                    let csi_fenced = csi_raw
                                        .fence_flag
                                        .as_ref()
                                        .is_some_and(|f| f.load(Ordering::SeqCst))
                                        || csi_raw
                                            .csi_fence
                                            .as_ref()
                                            .is_some_and(|f| f.verify().is_err());
                                    if csi_fenced {
                                        flush_err = Some(Errno::ESTALE);
                                    } else if let Err(e) = csi_raw.vol.flush().await
                                        && (e == Errno::ESTALE || flush_err.is_none())
                                    {
                                        flush_err = Some(e);
                                    }
                                }
                            }
                            for csi_nbd in &booted.csi_nbd {
                                if let Err(e) = csi_nbd.flush_and_close().await
                                    && (e == Errno::ESTALE || flush_err.is_none())
                                {
                                    flush_err = Some(e);
                                }
                            }

                            // Cleanly release all volumes, then hand off back to CSI node, then release flocks.
                            for csi_raw in &booted.csi_raw {
                                let _ = csi_raw.vol.close_clean().await;
                            }
                            let work_hs = Rc::clone(&booted.actor.head_store);
                            let _ = booted.actor.close_all_cowfs_clean_pub().await;
                            let handoff_sockets: Vec<PathBuf> = booted
                                .csi_cowfs
                                .iter()
                                .filter_map(|c| c.handoff_socket.clone())
                                .collect();
                            drop(booted.csi_cowfs);
                            drop(booted.csi_raw);
                            drop(booted.csi_nbd);
                            drop(booted.actor);
                            let _ = work_hs.delete_volume(&booted.root_vol).await;
                            for sock in handoff_sockets {
                                let _ = handoff_rpc(&sock, "RELEASE");
                            }
                            drop(booted.lock_guards);

                            let _ = done_tx.send(match flush_err {
                                Some(e) => Err(e),
                                None => Ok(()),
                            });
                        }
                        Err(e) => {
                            let _ = ready_tx.send(Err(e));
                        }
                    }
                });
            })
            .map_err(|_| Errno::EIO)?;

        let (pid1_sig, pid1_img) = match ready_rx.recv() {
            Ok(Ok(pair)) => pair,
            Ok(Err(e)) => {
                let _ = actor_thread.join();
                return Err(e);
            }
            Err(_) => {
                let _ = actor_thread.join();
                return Err(Errno::EIO);
            }
        };

        let kernel = KernelClient {
            tx: cmd_tx,
            wake,
            ptys,
        };

        Ok(Self {
            container_id: spec.container_id,
            is_sandbox: spec.is_sandbox,
            kernel,
            runtime,
            lifecycle: Arc::new((
                Mutex::new(LifecycleState {
                    state: OciContainerState::Created,
                    pid: 1,
                    exit_status: None,
                    deleted: false,
                }),
                Condvar::new(),
            )),
            cancel_flag: Arc::new(AtomicBool::new(false)),
            pending: Mutex::new(Some(PendingPid1 {
                sig_ctrl: pid1_sig,
                image: pid1_img,
                umask: spec.umask,
                stdin_path: spec.stdin_path,
                stdout_path: spec.stdout_path,
                stderr_path: spec.stderr_path,
            })),
            running: Mutex::new(None),
            actor_thread: Mutex::new(Some(actor_thread)),
            done_rx: Mutex::new(Some(done_rx)),
        })
    }

    /// Transition container from [`OciContainerState::Created`] -> [`OciContainerState::Running`].
    pub fn start(&self) -> Result<u32, Errno> {
        let pending = self.pending.lock().unwrap().take().ok_or(Errno::EINVAL)?;
        {
            let mut g = self.lifecycle.0.lock().unwrap();
            if g.state != OciContainerState::Created {
                return Err(Errno::EINVAL);
            }
            g.state = OciContainerState::Running;
        }

        let Some(image) = pending.image else {
            return Ok(1);
        };

        let stdio =
            StdioHandles::setup(pending.stdin_path, pending.stdout_path, pending.stderr_path);
        let stdio_stop = Arc::clone(&stdio.stop);
        let fds = stdio.fds;
        let stdio_threads = stdio.threads;

        let ticker = EpochTickerGuard::start(self.runtime.engine.clone());
        let proc_h = spawn_process_thread_with_exit(
            1,
            pending.sig_ctrl,
            fds,
            image,
            pending.umask,
            None,
            self.kernel.clone(),
            Arc::clone(&self.runtime),
            Some(Arc::clone(&self.cancel_flag)),
        );

        let kernel = self.kernel.clone();
        let runtime = Arc::clone(&self.runtime);
        let cancel = Arc::clone(&self.cancel_flag);
        let lifecycle = Arc::clone(&self.lifecycle);
        let reaper_stop = Arc::clone(&stdio_stop);

        let reaper = std::thread::Builder::new()
            .name("os-oci-reap-pid1".into())
            .spawn(move || {
                let status = wait_and_reap_pid(1, proc_h, &kernel, &runtime, &cancel);
                reaper_stop.store(true, Ordering::SeqCst);
                for th in stdio_threads {
                    let _ = th.join();
                }
                let mut g = lifecycle.0.lock().unwrap();
                g.state = OciContainerState::Stopped;
                g.exit_status = Some(status);
                lifecycle.1.notify_all();
            })
            .ok();

        *self.running.lock().unwrap() = Some(RunningPid1 {
            _epoch_ticker: Some(ticker),
            reaper_thread: reaper,
            stdio_stop: Some(stdio_stop),
        });
        Ok(1)
    }

    pub fn state(&self) -> OciStatusSnapshot {
        let g = self.lifecycle.0.lock().unwrap();
        OciStatusSnapshot {
            state: g.state,
            pid: g.pid,
            exit_status: g.exit_status,
        }
    }

    pub fn pids(&self) -> Vec<u32> {
        let st = self.lifecycle.0.lock().unwrap().state;
        if st == OciContainerState::Stopped {
            return Vec::new();
        }
        self.kernel
            .try_call_sync(|reply| KernelCmd::Inspect { reply })
            .map(|i| i.pids)
            .unwrap_or_else(|| vec![1])
    }

    /// Return PID 1's effective `(uid, gid)` inside the container kernel.
    pub fn process_uid_gid(&self) -> Result<(u32, u32), Errno> {
        self.kernel
            .try_call_sync(|reply| KernelCmd::GetProcCredAndCtty { pid: 1, reply })
            .ok_or(Errno::EIO)?
            .map(|(u, g, _)| (u, g))
    }

    /// Prepare an `exec` process inside the container (rejects `\x7fELF` with `Errno::ENOEXEC`).
    pub fn exec(&self, spec: OciExecSpec) -> Result<Arc<OciExecHandle>, Errno> {
        if spec.argv.is_empty() {
            return Err(Errno::EINVAL);
        }
        if let Some(ref p) = spec.stdin_path {
            validate_stdio_path(p, true)?;
        }
        if let Some(ref p) = spec.stdout_path {
            validate_stdio_path(p, false)?;
        }
        if let Some(ref p) = spec.stderr_path {
            validate_stdio_path(p, false)?;
        }
        if self.lifecycle.0.lock().unwrap().state == OciContainerState::Stopped {
            return Err(Errno::ESRCH);
        }
        let stdio = StdioHandles::setup(spec.stdin_path, spec.stdout_path, spec.stderr_path);
        let stdio_stop = Arc::clone(&stdio.stop);
        let stdio_threads = stdio.threads;

        let prepared = self.kernel.try_call_sync(|reply| KernelCmd::PrepareSpawn {
            req: Box::new(SpawnProcessReq {
                parent_pid: 1,
                argv: spec.argv,
                env: spec.env,
                cwd: spec.cwd,
                pgroup: None,
                cgroup: None,
                service_grant: None,
                umask: 0o022,
                fds: stdio.fds,
                dup_kfds: Vec::new(),
                close_kfds: Vec::new(),
                clear_cloexec_kfds: Vec::new(),
                signals: None,
                ctty: None,
                setsid: false,
                host_owned: true,
                host_uid: spec.uid,
            }),
            reply,
        });

        let (pid, sig_ctrl, fds, image) = match prepared {
            Some(Ok(v)) => v,
            Some(Err(e)) => {
                stdio_stop.store(true, Ordering::SeqCst);
                for th in stdio_threads {
                    let _ = th.join();
                }
                return Err(e);
            }
            None => {
                stdio_stop.store(true, Ordering::SeqCst);
                for th in stdio_threads {
                    let _ = th.join();
                }
                return Err(Errno::EIO);
            }
        };

        Ok(Arc::new(OciExecHandle {
            exec_id: spec.exec_id,
            kernel: self.kernel.clone(),
            runtime: Arc::clone(&self.runtime),
            lifecycle: Arc::new((
                Mutex::new(LifecycleState {
                    state: OciContainerState::Created,
                    pid,
                    exit_status: None,
                    deleted: false,
                }),
                Condvar::new(),
            )),
            cancel_flag: Arc::new(AtomicBool::new(false)),
            pending: Mutex::new(Some(PendingExec {
                pid,
                sig_ctrl,
                fds,
                image,
                stdio_stop,
                stdio_threads,
            })),
            running: Mutex::new(None),
        }))
    }

    pub fn kill(&self, signal: u8, all: bool) -> Result<(), Errno> {
        let is_pause = {
            let mut g = self.lifecycle.0.lock().unwrap();
            if g.state == OciContainerState::Stopped {
                return Ok(());
            }
            let has_runner = self.running.lock().unwrap().is_some();
            if self.is_sandbox && !has_runner && matches!(signal, 9 | 15 | 2) {
                g.state = OciContainerState::Stopped;
                g.exit_status = Some(OciExitStatus {
                    exit_code: 128 + i32::from(signal),
                    signal: Some(signal),
                    exited_at_ns: now_unix_nanos(),
                });
                self.lifecycle.1.notify_all();
                true
            } else {
                false
            }
        };
        if is_pause {
            return Ok(());
        }

        if signal == 9 {
            self.cancel_flag.store(true, Ordering::SeqCst);
            self.runtime.engine.increment_epoch();
        }
        let target = if all { "-1" } else { "1" }.to_string();
        let _ = self.kernel.try_call_sync(|reply| KernelCmd::Kill {
            pid: 1,
            target,
            signal,
            reply,
        });
        if signal == 9 {
            self.runtime.engine.increment_epoch();
        }
        Ok(())
    }

    pub fn wait(&self) -> OciExitStatus {
        let mut g = self.lifecycle.0.lock().unwrap();
        while g.state != OciContainerState::Stopped {
            g = self.lifecycle.1.wait(g).unwrap();
        }
        g.exit_status.unwrap_or(OciExitStatus {
            exit_code: 0,
            signal: None,
            exited_at_ns: now_unix_nanos(),
        })
    }

    pub fn delete(&self) -> Result<OciExitStatus, Errno> {
        if self.pending.lock().unwrap().take().is_some() {
            let mut g = self.lifecycle.0.lock().unwrap();
            if g.state != OciContainerState::Stopped {
                g.state = OciContainerState::Stopped;
                g.exit_status = Some(OciExitStatus {
                    exit_code: 0,
                    signal: None,
                    exited_at_ns: now_unix_nanos(),
                });
                self.lifecycle.1.notify_all();
            }
        } else if self.lifecycle.0.lock().unwrap().state == OciContainerState::Running {
            let _ = self.kill(9, true);
        }

        let status = self.wait();

        if let Some(mut running) = self.running.lock().unwrap().take() {
            if let Some(stop) = running.stdio_stop.take() {
                stop.store(true, Ordering::SeqCst);
            }
            if let Some(th) = running.reaper_thread.take() {
                let _ = th.join();
            }
        }

        let _ = self
            .kernel
            .try_call_sync(|reply| KernelCmd::Shutdown { reply });

        if let Some(actor_th) = self.actor_thread.lock().unwrap().take() {
            let _ = actor_th.join();
        }

        self.lifecycle.0.lock().unwrap().deleted = true;

        if let Some(rx) = self.done_rx.lock().unwrap().take() {
            match rx.recv() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(Errno::EIO),
            }
        }
        Ok(status)
    }
}

impl Drop for OciContainerHandle {
    fn drop(&mut self) {
        if !self.lifecycle.0.lock().unwrap().deleted {
            let _ = self.delete();
        }
    }
}

fn wait_and_reap_pid(
    pid: u32,
    proc_handle: Option<std::thread::JoinHandle<(i32, Option<u8>)>>,
    kernel: &KernelClient,
    runtime: &WasmRuntime,
    cancel_flag: &AtomicBool,
) -> OciExitStatus {
    let mut exit_code = 0i32;
    let mut exit_sig: Option<u8> = None;
    let mut canceled = false;

    loop {
        if cancel_flag.load(Ordering::SeqCst) {
            for _ in 0..20 {
                runtime.engine.increment_epoch();
                if proc_handle.as_ref().is_none_or(|h| h.is_finished()) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            canceled = true;
            exit_code = 128 + 9;
            exit_sig = Some(9);
            break;
        }
        let seq = kernel.wake.current();
        if pid > 1
            && let Some(Ok(res)) = kernel.try_call_sync(|reply| KernelCmd::Waitpid {
                pid: 0,
                target: pid as i32,
                options: 1, // WNOHANG
                host_reap: true,
                reply,
            })
            && !res.nothing
        {
            if let Some(sig) = res.signal {
                exit_code = 128 + i32::from(sig);
                exit_sig = Some(sig);
            } else {
                exit_code = res.status;
            }
            break;
        }
        if proc_handle.as_ref().is_some_and(|h| h.is_finished()) {
            break;
        }
        kernel.wake.wait_since(seq, Duration::from_millis(10));
    }

    if let Some(h) = proc_handle
        && let Ok((code, sig)) = h.join()
        && !canceled
    {
        exit_code = code;
        exit_sig = sig;
    }

    // Reap any child zombie (`pid > 1`) from the kernel process table.
    if pid > 1 {
        let _ = kernel.try_call_sync(|reply| KernelCmd::Waitpid {
            pid: 0,
            target: pid as i32,
            options: 1,
            host_reap: true,
            reply,
        });
    }

    OciExitStatus {
        exit_code,
        signal: exit_sig,
        exited_at_ns: now_unix_nanos(),
    }
}

// ---------------------------------------------------------------------------
// Isolated `KernelActor` Bootstrap for OCI Bundles
// ---------------------------------------------------------------------------

struct MountedCsiCowFs {
    fs: Rc<CowFs<NativeSqliteHeadStore, NativePackStore>>,
    readonly: bool,
    fence_flag: Option<Arc<AtomicBool>>,
    csi_fence: Option<OciCsiFenceCheck>,
    handoff_socket: Option<PathBuf>,
}

struct MountedCsiRaw {
    vol: Rc<RawBlockVolume<NativeSqliteHeadStore, NativePackStore>>,
    readonly: bool,
    fence_flag: Option<Arc<AtomicBool>>,
    csi_fence: Option<OciCsiFenceCheck>,
}

struct BootedOciActor {
    actor: KernelActor,
    pid1_sig: Arc<SignalControl>,
    pid1_img: Option<LoadedImage>,
    root_vol: VolumeId,
    csi_cowfs: Vec<MountedCsiCowFs>,
    csi_raw: Vec<MountedCsiRaw>,
    csi_nbd: Vec<Rc<NbdVolumeDevice>>,
    lock_guards: Vec<OwnedFd>,
}

async fn boot_oci_actor(
    spec: &OciBundleRunSpec,
    wake: Arc<WakeBus>,
    ptys: Arc<PtyTable>,
) -> Result<BootedOciActor, Errno> {
    let work_head_store = Rc::new(NativeSqliteHeadStore::open(&spec.work_store_dir)?);
    let work_pack_store = Rc::new(NativePackStore::open(&spec.work_store_dir)?);
    let clock: Rc<dyn Fn() -> Timespec> = Rc::new(now_timespec);
    let clock_pair: Rc<dyn Fn() -> (u64, u32)> = Rc::new(|| {
        let ts = now_timespec();
        (ts.sec, ts.nsec)
    });
    let boot_ts = (clock)();

    // 1. Format fresh ephemeral rootfs CowFs volume & safely import OCI rootfs.
    let suffix = random_hex(4);
    let root_vol = VolumeId(format!("oci-root-{suffix}"));
    CowFs::format_volume(
        &*work_head_store,
        &*work_pack_store,
        root_vol.clone(),
        0,
        0,
        0o755,
        boot_ts,
    )
    .await?;

    let root_fs = match CowFs::open(
        Rc::clone(&work_head_store),
        Rc::clone(&work_pack_store),
        root_vol.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_native(Rc::clone(&clock)),
    )
    .await
    {
        Ok(fs) => Rc::new(fs),
        Err(e) => {
            let _ = work_head_store.delete_volume(&root_vol).await;
            return Err(e);
        }
    };

    let mut csi_cowfs_mounts: Vec<MountedCsiCowFs> = Vec::new();
    let mut csi_raw_mounts: Vec<MountedCsiRaw> = Vec::new();
    let mut csi_nbd_mounts: Vec<Rc<NbdVolumeDevice>> = Vec::new();
    let mut lock_guards: Vec<OwnedFd> = Vec::new();
    let mut acquired_handoffs: Vec<PathBuf> = Vec::new();

    let setup_res: Result<(KernelActor, Arc<SignalControl>, Option<LoadedImage>), Errno> = async {
        if spec.rootfs_dir.exists() {
            let root_fd = open_dir_nofollow(&spec.rootfs_dir)?;
            let mut budget = ImportBudget { files: 0, bytes: 0 };
            let r_handle = root_fs.root();
            import_host_fd_into_fs(root_fd.0, &*root_fs, &r_handle, 0, &mut budget).await?;
        }

        for dir in ["/dev", "/proc", "/tmp"] {
            ensure_dir_chain_on_cowfs(&root_fs, dir).await?;
        }
        if !spec.cwd.is_empty() && spec.cwd != "/" {
            let _ = ensure_dir_chain_on_cowfs(&root_fs, &spec.cwd).await;
        }

        // 2. Isolated `LocalProcessTable` + cgroup `memory.max` & `pids.max` on `/`.
        let container_instance_id = new_uuid_v4();
        let proc_table = Rc::new(RefCell::new(LocalProcessTable::new(
            InstanceIdentity {
                instance: container_instance_id.clone(),
                host: OCI_HOST_LABEL.to_string(),
            },
            boot_ts.sec,
        )));
        let root_ident = Identity {
            id: 0,
            group: 0,
            groups: BTreeSet::from([0]),
        };
        {
            let mut tbl = proc_table.borrow_mut();
            if spec.memory_max_bytes > 0 {
                tbl.cgroup_set(
                    &root_ident,
                    "/",
                    "memory.max",
                    &spec.memory_max_bytes.to_string(),
                    boot_ts.sec,
                )
                .map_err(|e| e.errno)?;
            }
            if spec.pids_max > 0 {
                tbl.cgroup_set(
                    &root_ident,
                    "/",
                    "pids.max",
                    &spec.pids_max.to_string(),
                    boot_ts.sec,
                )
                .map_err(|e| e.errno)?;
            }
            tbl.boot_init(OCI_HOST_LABEL, boot_ts.sec)
                .map_err(|e| e.errno)?;
        }

        let mut env_vec = spec.env.clone();
        if !env_vec.iter().any(|e| e.starts_with("PATH=")) {
            env_vec.push("PATH=/usr/local/bin:/usr/bin:/bin".to_string());
        }
        let argv0 = spec
            .argv
            .first()
            .cloned()
            .unwrap_or_else(|| "/pause".to_string());
        {
            let mut tbl = proc_table.borrow_mut();
            let _ = tbl
                .reexec(
                    OCI_HOST_LABEL,
                    1,
                    ReexecSpec {
                        path: argv0.clone(),
                        argv: if spec.argv.is_empty() {
                            vec![argv0.clone()]
                        } else {
                            spec.argv.clone()
                        },
                        env: env_vec.clone(),
                        cwd: Some(spec.cwd.clone()),
                        runtime: Some("resources-v1".to_string()),
                        cloud_access: false,
                        new_remote: None,
                    },
                    boot_ts.sec,
                )
                .map_err(|e| e.errno)?;
        }

        // 3. Isolated VFS booted on ephemeral rootfs `CowFs`.
        let factory = Rc::new(DefaultFilesystemFactory::new(Rc::clone(&clock_pair)));
        let root_backing = Rc::new(MountBacking::new(
            Rc::clone(&root_fs) as Rc<dyn Filesystem>,
            FsType::Cowfs,
        ));
        let vfs = Vfs::boot(&container_instance_id, root_backing, "oci-root", factory).await?;

        {
            let pt1 = Rc::clone(&proc_table);
            vfs.set_proc_snapshot_hook(Rc::new(move |pid| {
                let tbl = pt1.try_borrow().ok()?;
                let snap = tbl.proc_snapshot(pid)?;
                Some(ProcMetaSnapshot {
                    ppid: snap.ppid,
                    pgid: snap.pgid,
                    sid: snap.sid,
                    uid: snap.uid,
                    gid: snap.gid,
                    state: snap.state,
                    cgroup: snap.cgroup,
                    comm: snap.comm,
                    argv: snap.argv,
                    start_ticks: snap.started_ticks,
                    tty: snap.tty,
                    tty_fds: snap.tty_fds,
                })
            }));
            let pt2 = Rc::clone(&proc_table);
            vfs.set_proc_list_hook(Rc::new(move || {
                pt2.try_borrow()
                    .map(|tbl| tbl.all_pids())
                    .unwrap_or_default()
            }));
            let pt3 = Rc::clone(&proc_table);
            let clk = Rc::clone(&clock);
            vfs.set_uptime_hook(Rc::new(move || {
                pt3.try_borrow()
                    .map(|tbl| tbl.uptime_secs((clk)().sec))
                    .unwrap_or(0)
            }));
        }

        let sys_ns = vfs.system_namespace();
        let mut root_cred = Cred::root();
        root_cred.umask = 0;

        // 4. Isolated `/proc`.
        let proc_fs = Rc::new(ProcFs::new(
            FsId("proc:oci".to_string()),
            boot_ts,
            EmptyProcProvider,
        ));
        proc_fs.bind_bridge(vfs.proc_bridge());
        let proc_backing = Rc::new(
            MountBacking::new(proc_fs as Rc<dyn Filesystem>, FsType::Proc)
                .with_ceilings(true, true),
        );
        vfs.mount_on_namespace(
            &sys_ns,
            &root_cred,
            proc_backing,
            None,
            "proc",
            "/proc",
            MountFlags {
                rdonly: true,
                nosuid: true,
                nodev: true,
                noexec: true,
                ..MountFlags::default()
            },
            mount_flags::MS_RDONLY
                | mount_flags::MS_NOSUID
                | mount_flags::MS_NODEV
                | mount_flags::MS_NOEXEC,
            None,
        )
        .await?;

        // 5. Minimal `/dev` (`null`, `zero`, `full`, `random`, `urandom` ONLY + attached CSI `/dev/vdN`).
        let vblk = Rc::new(VblkRegistry::new());
        let loop_reg = LoopRegistry::new();
        let gui_caller = Rc::new(Cell::new(None));
        let headless_gui = Rc::new(HeadlessHostAdapter::default());
        let gui_reg = GuiDeviceRegistry::new(
            Rc::clone(&headless_gui) as Rc<dyn abi::gui::GuiHostSink>,
            Rc::clone(&gui_caller),
        );
        let dev_backend =
            build_native_dev_backend_with_vblk(loop_reg.clone(), gui_reg, Rc::clone(&vblk));
        let dev_fs = Rc::new(DevTmpFs::new(
            FsId("devtmpfs:oci".to_string()),
            1,
            Box::new(|| {
                let ts = now_timespec();
                (ts.sec, ts.nsec)
            }),
            dev_backend,
        ));
        let gui_reg = Rc::clone(&dev_fs.backend().registry);
        {
            let dev_root = dev_fs.root();
            for drop_name in ["tty", "console", "ptmx", "system"] {
                let _ = dev_fs.unlink(&root_cred, &dev_root, drop_name).await;
            }
            for drop_dir in ["pts", "shm"] {
                let _ = dev_fs.rmdir(&root_cred, &dev_root, drop_dir).await;
            }
        }
        let dev_backing = Rc::new(MountBacking::new(
            Rc::clone(&dev_fs) as Rc<dyn Filesystem>,
            FsType::DevTmpFs,
        ));
        vfs.mount_on_namespace(
            &sys_ns,
            &root_cred,
            dev_backing,
            None,
            "devtmpfs",
            "/dev",
            MountFlags {
                nosuid: true,
                noexec: true,
                ..MountFlags::default()
            },
            mount_flags::MS_NOSUID | mount_flags::MS_NOEXEC,
            None,
        )
        .await?;

        let dev_pts = Rc::new(DevPtsFs::new(
            FsId("devpts:oci".to_string()),
            1,
            Box::new(|| {
                let ts = now_timespec();
                (ts.sec, ts.nsec)
            }),
            DefaultDeviceBackend,
        ));

        // 6. Fresh `/tmp` (`tmpfs`, `01777`).
        let tmp_fs = Rc::new(MemFs::new(
            FsId("tmpfs:oci-tmp".to_string()),
            2,
            0,
            0,
            0o1777,
            Box::new(|| {
                let ts = now_timespec();
                (ts.sec, ts.nsec)
            }),
        ));
        let tmp_backing = Rc::new(MountBacking::new(
            tmp_fs as Rc<dyn Filesystem>,
            FsType::TmpFs,
        ));
        vfs.mount_on_namespace(
            &sys_ns,
            &root_cred,
            tmp_backing,
            None,
            "tmpfs",
            "/tmp",
            MountFlags {
                nosuid: true,
                nodev: true,
                ..MountFlags::default()
            },
            mount_flags::MS_NOSUID | mount_flags::MS_NODEV,
            None,
        )
        .await?;

        // 7. Attach CSI `CowFs` volumes, CSI raw/NBD `/dev/vdN` devices, and RO host dirs.
        let mut store_cache: HashMap<PathBuf, (Rc<NativeSqliteHeadStore>, Rc<NativePackStore>)> =
            HashMap::new();
        let mut cowfs_list: Vec<Rc<CowFs<NativeSqliteHeadStore, NativePackStore>>> =
            vec![Rc::clone(&root_fs)];

        for (idx, vol_mount) in spec.volumes.iter().enumerate() {
            match vol_mount {
                OciVolumeMount::CowFsVolume {
                    store_dir,
                    volume_id,
                    container_path,
                    readonly,
                    fence_flag,
                    lock_file,
                    handoff_socket,
                    csi_fence,
                } => {
                    if !container_path.starts_with('/')
                        || matches!(container_path.as_str(), "/" | "/dev" | "/proc")
                    {
                        return Err(Errno::EINVAL);
                    }
                    if let Some(cf) = csi_fence {
                        cf.verify()?;
                    }
                    if !*readonly && let Some(lf) = lock_file {
                        lock_guards.push(acquire_volume_flock(lf)?);
                    }
                    if !*readonly && let Some(ho) = handoff_socket {
                        handoff_rpc(ho, "ACQUIRE")?;
                        acquired_handoffs.push(ho.clone());
                    }

                    ensure_dir_chain_on_cowfs(&root_fs, container_path).await?;
                    let (hs, ps) = if let Some(pair) = store_cache.get(store_dir) {
                        (Rc::clone(&pair.0), Rc::clone(&pair.1))
                    } else {
                        let hs = Rc::new(NativeSqliteHeadStore::open(store_dir)?);
                        let ps = Rc::new(NativePackStore::open(store_dir)?);
                        store_cache.insert(store_dir.clone(), (Rc::clone(&hs), Rc::clone(&ps)));
                        (hs, ps)
                    };
                    // Strictly `WriterMode::Exclusive` — never blind `ForceTakeover`! (P0-5)
                    let open_mode = if *readonly {
                        CowFsOpenMode::ReadOnly
                    } else {
                        CowFsOpenMode::ReadWrite(WriterMode::Exclusive)
                    };
                    let fs = Rc::new(
                        CowFs::open(
                            hs,
                            ps,
                            VolumeId(volume_id.clone()),
                            open_mode,
                            CowFsConfig::remote(Rc::clone(&clock)),
                        )
                        .await?,
                    );
                    let mounted_fs: Rc<dyn Filesystem> =
                        if !*readonly && (fence_flag.is_some() || csi_fence.is_some()) {
                            Rc::new(FencedCowFs {
                                inner: Rc::clone(&fs),
                                fence_flag: fence_flag.clone(),
                                csi_fence: csi_fence.clone(),
                                fenced: Cell::new(false),
                            })
                        } else {
                            Rc::clone(&fs) as Rc<dyn Filesystem>
                        };
                    let mut backing = MountBacking::new(mounted_fs, FsType::Cowfs);
                    if *readonly {
                        backing = backing.with_ceilings(true, true);
                    }
                    let mut mflags = MountFlags {
                        rdonly: *readonly,
                        nosuid: true,
                        nodev: true,
                        ..MountFlags::default()
                    };
                    let mut raw_flags = mount_flags::MS_NOSUID | mount_flags::MS_NODEV;
                    if *readonly {
                        mflags.noexec = true;
                        raw_flags |= mount_flags::MS_RDONLY | mount_flags::MS_NOEXEC;
                    }
                    vfs.mount_on_namespace(
                        &sys_ns,
                        &root_cred,
                        Rc::new(backing),
                        None,
                        &format!("csi:{volume_id}"),
                        container_path,
                        mflags,
                        raw_flags,
                        None,
                    )
                    .await?;
                    cowfs_list.push(Rc::clone(&fs));
                    csi_cowfs_mounts.push(MountedCsiCowFs {
                        fs,
                        readonly: *readonly,
                        fence_flag: fence_flag.clone(),
                        csi_fence: csi_fence.clone(),
                        handoff_socket: if *readonly {
                            None
                        } else {
                            handoff_socket.clone()
                        },
                    });
                }
                OciVolumeMount::RawBlockDevice {
                    store_dir,
                    volume_id,
                    dev_name,
                    readonly,
                    fence_flag,
                    lock_file,
                    csi_fence,
                } => {
                    if let Some(cf) = csi_fence {
                        cf.verify()?;
                    }
                    if !*readonly && let Some(lf) = lock_file {
                        lock_guards.push(acquire_volume_flock(lf)?);
                    }
                    let (hs, ps) = if let Some(pair) = store_cache.get(store_dir) {
                        (Rc::clone(&pair.0), Rc::clone(&pair.1))
                    } else {
                        let hs = Rc::new(NativeSqliteHeadStore::open(store_dir)?);
                        let ps = Rc::new(NativePackStore::open(store_dir)?);
                        store_cache.insert(store_dir.clone(), (Rc::clone(&hs), Rc::clone(&ps)));
                        (hs, ps)
                    };
                    // Strictly `WriterMode::Exclusive` (P0-5).
                    let open_mode = if *readonly {
                        RawBlockOpenMode::ReadOnly
                    } else {
                        RawBlockOpenMode::ReadWrite(WriterMode::Exclusive)
                    };
                    let mut cfg = RawBlockConfig::remote_fenced(Rc::clone(&clock));
                    if fence_flag.is_some() || csi_fence.is_some() {
                        let flag = fence_flag.clone();
                        let cf = csi_fence.clone();
                        cfg = cfg.with_fence_validator(Rc::new(move || {
                            if flag.as_ref().is_some_and(|f| f.load(Ordering::SeqCst)) {
                                return Err(Errno::ESTALE);
                            }
                            if let Some(ref c) = cf {
                                c.verify()?;
                            }
                            Ok(())
                        }));
                    }
                    let raw_vol = Rc::new(
                        RawBlockVolume::open(hs, ps, VolumeId(volume_id.clone()), open_mode, cfg)
                            .await?,
                    );
                    let dev = Rc::new(RawBlockVolumeDevice::new(Rc::clone(&raw_vol)));
                    vblk.attach_named(dev_name, dev as Rc<dyn VolumeDevice>)?;
                    let mode = if *readonly { 0o444 } else { 0o660 };
                    vblk.register_node(&dev_fs, dev_name, mode)?;
                    if spec.uid != 0 || spec.gid != 0 {
                        let dev_root = dev_fs.root();
                        if let Ok(ent) = dev_fs.lookup(&root_cred, &dev_root, dev_name).await {
                            let _ = dev_fs
                                .setattr(
                                    &root_cred,
                                    &ent.handle,
                                    &SetAttr {
                                        uid: Some(spec.uid),
                                        gid: Some(spec.gid),
                                        ..SetAttr::default()
                                    },
                                )
                                .await;
                        }
                    }
                    csi_raw_mounts.push(MountedCsiRaw {
                        vol: raw_vol,
                        readonly: *readonly,
                        fence_flag: fence_flag.clone(),
                        csi_fence: csi_fence.clone(),
                    });
                }
                OciVolumeMount::NbdBlockDevice {
                    nbd_socket,
                    export_name,
                    dev_name,
                    readonly,
                    lock_file,
                    csi_fence,
                } => {
                    if let Some(cf) = csi_fence {
                        cf.verify()?;
                    }
                    if !*readonly && let Some(lf) = lock_file {
                        lock_guards.push(acquire_volume_flock(lf)?);
                    }
                    let nbd_dev = Rc::new(
                        NbdVolumeDevice::connect(
                            nbd_socket,
                            export_name,
                            *readonly,
                            csi_fence.clone(),
                        )
                        .await?,
                    );
                    vblk.attach_named(dev_name, Rc::clone(&nbd_dev) as Rc<dyn VolumeDevice>)?;
                    let mode = if *readonly { 0o444 } else { 0o660 };
                    vblk.register_node(&dev_fs, dev_name, mode)?;
                    if spec.uid != 0 || spec.gid != 0 {
                        let dev_root = dev_fs.root();
                        if let Ok(ent) = dev_fs.lookup(&root_cred, &dev_root, dev_name).await {
                            let _ = dev_fs
                                .setattr(
                                    &root_cred,
                                    &ent.handle,
                                    &SetAttr {
                                        uid: Some(spec.uid),
                                        gid: Some(spec.gid),
                                        ..SetAttr::default()
                                    },
                                )
                                .await;
                        }
                    }
                    csi_nbd_mounts.push(nbd_dev);
                }
                OciVolumeMount::ReadOnlyHostDir {
                    host_path,
                    container_path,
                } => {
                    if !container_path.starts_with('/')
                        || matches!(container_path.as_str(), "/" | "/dev" | "/proc")
                    {
                        return Err(Errno::EINVAL);
                    }
                    ensure_dir_chain_on_cowfs(&root_fs, container_path).await?;
                    let mem = Rc::new(MemFs::new(
                        FsId(format!("tmpfs:oci-ro-{idx}")),
                        10 + idx as u64,
                        0,
                        0,
                        0o555,
                        Box::new(|| {
                            let ts = now_timespec();
                            (ts.sec, ts.nsec)
                        }),
                    ));
                    let host_fd = open_dir_nofollow(host_path)?;
                    let mut budget = ImportBudget { files: 0, bytes: 0 };
                    let m_root = mem.root();
                    import_host_fd_into_fs(host_fd.0, &*mem, &m_root, 0, &mut budget).await?;
                    let backing = Rc::new(
                        MountBacking::new(mem as Rc<dyn Filesystem>, FsType::TmpFs)
                            .with_ceilings(true, true),
                    );
                    vfs.mount_on_namespace(
                        &sys_ns,
                        &root_cred,
                        backing,
                        None,
                        "oci-ro-bind",
                        container_path,
                        MountFlags {
                            rdonly: true,
                            nosuid: true,
                            nodev: true,
                            noexec: true,
                            ..MountFlags::default()
                        },
                        mount_flags::MS_RDONLY
                            | mount_flags::MS_NOSUID
                            | mount_flags::MS_NODEV
                            | mount_flags::MS_NOEXEC,
                        None,
                    )
                    .await?;
                }
            }
        }

        // Apply OCI cwd and `process.user` (`spec.uid`/`spec.gid`/`spec.umask`) to PID 1 (P1-3).
        if !spec.cwd.is_empty() && spec.cwd != "/" {
            let _ = vfs.chdir(1, &spec.cwd).await;
        }
        let user_ident = Identity {
            id: spec.uid,
            group: spec.gid,
            groups: BTreeSet::from([spec.gid]),
        };
        if spec.uid != 0 || spec.gid != 0 {
            proc_table
                .borrow_mut()
                .set_authenticated_cred(OCI_HOST_LABEL, 1, user_ident.clone(), None)
                .map_err(|e| e.errno)?;
        }
        vfs.set_cred(
            1,
            Cred {
                identity: user_ident,
                umask: spec.umask & 0o777,
                token: None,
            },
        )?;

        let cowfs_mounts = Rc::new(RefCell::new(cowfs_list));
        let root_cowfs = Rc::new(RefCell::new(Some(Rc::clone(&root_fs))));
        let root_volume_uuid = Rc::new(RefCell::new(Some(root_vol.0.clone())));
        let pid1_sig = SignalControl::new();
        let mut sig_ctrls = HashMap::new();
        sig_ctrls.insert(1, Arc::clone(&pid1_sig));

        let actor = KernelActor {
            instance_id: container_instance_id,
            state_dir: spec.work_store_dir.clone(),
            release: None,
            boot_profile: NativeBootProfile::default(),
            vfs,
            proc_table,
            accounts: LocalAccountStore::new(),
            head_store: Rc::clone(&work_head_store),
            pack_store: Rc::clone(&work_pack_store),
            cowfs_mounts,
            root_cowfs,
            root_volume_uuid,
            dev_fs,
            dev_pts,
            vblk,
            loop_reg,
            gui_reg,
            gui_caller,
            _headless_gui: headless_gui,
            socks: UnixSocketTable::new(),
            mount_host: MountHostServer::new(),
            kubelet_host: crate::kubelet::KubeletHostServer::new(),
            export_bridge: NativeExportBridge::default(),
            exportd_pids: HashSet::new(),
            exportd_sha256: None,
            init_pids: HashSet::new(),
            init_sha256: None,
            kubelet_pids: HashSet::new(),
            kubelet_sha256: None,
            sig_ctrls,
            rights_side_table: HashMap::new(),
            next_rights_handle: 1,
            wake,
            ptys,
            clock,
            closed: false,
        };

        // 8. Validate & load PID 1 executable (explicitly rejects `\x7fELF` with `Errno::ENOEXEC`!).
        let pid1_img = if spec.is_sandbox {
            if let Some(entry) = spec.argv.first() {
                match actor
                    .load_executable_pub(1, entry, spec.argv.clone(), env_vec, true)
                    .await
                {
                    Ok(img) => Some(img),
                    Err(Errno::ENOENT) => None,
                    Err(e) => return Err(e),
                }
            } else {
                None
            }
        } else {
            let img = actor
                .load_executable_pub(1, &spec.argv[0], spec.argv.clone(), env_vec, true)
                .await?;
            Some(img)
        };

        Ok((actor, pid1_sig, pid1_img))
    }
    .await;

    match setup_res {
        Ok((actor, pid1_sig, pid1_img)) => Ok(BootedOciActor {
            actor,
            pid1_sig,
            pid1_img,
            root_vol,
            csi_cowfs: csi_cowfs_mounts,
            csi_raw: csi_raw_mounts,
            csi_nbd: csi_nbd_mounts,
            lock_guards,
        }),
        Err(e) => {
            for n in &csi_nbd_mounts {
                let _ = n.flush_and_close().await;
            }
            for r in &csi_raw_mounts {
                let _ = r.vol.close_clean().await;
            }
            for f in &csi_cowfs_mounts {
                let _ = f.fs.close_clean().await;
            }
            let _ = root_fs.close_clean().await;
            let _ = work_head_store.delete_volume(&root_vol).await;
            for sock in acquired_handoffs {
                let _ = handoff_rpc(&sock, "RELEASE");
            }
            drop(lock_guards);
            Err(e)
        }
    }
}

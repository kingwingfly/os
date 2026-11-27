//! `Send`-safe typed RPC protocol between Wasm guest OS threads and the single-threaded
//! `!Send` Kernel Actor (`tokio::LocalSet`).

use crate::pipes::PipeHandle;
use crate::pty::{PtyMasterHandle, PtySlaveHandle, PtyTable};
use crate::signals::{SignalControl, SignalSnapshot};
use abi::socket::PeerCred;
use abi::{Call, Creds, Errno, Error, Stat, StatFs, Time};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

/// Global monotonic notification counter + Condvar used to wake threads blocked in
/// `poll_oneoff`, `sock_accept`, `sock_recvmsg`, `waitpid`, etc.
#[derive(Default)]
pub struct WakeBus {
    seq: Mutex<u64>,
    cv: Condvar,
}

impl WakeBus {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn notify(&self) {
        let mut g = self.seq.lock().unwrap();
        *g = g.wrapping_add(1);
        self.cv.notify_all();
    }

    pub fn current(&self) -> u64 {
        *self.seq.lock().unwrap()
    }

    pub fn wait_since(&self, seen: u64, timeout: Duration) {
        let g = self.seq.lock().unwrap();
        if *g != seen {
            return;
        }
        let _ = self.cv.wait_timeout(g, timeout);
    }
}

/// Guest descriptor kind passed across `fork`/`spawn`/`exec` and `SCM_RIGHTS`.
#[derive(Clone)]
pub enum GuestFdKind {
    /// Kernel VFS descriptor (`os_vfs::Fd` number in `pid`'s `Vfs` `FdTable`).
    Kfd {
        kfd: u32,
        is_dir: bool,
        path_only: bool,
        readable: bool,
        writable: bool,
        append: bool,
        nonblock: bool,
        device: Option<String>,
    },
    /// Kernel `UnixSockTable` socket id.
    UnixSock {
        sock_id: u64,
        sock_type: u32,
        nonblock: bool,
    },
    /// Unconnected WASIX `AF_INET`/`AF_INET6` outbound stream descriptor (Phase 10a `#86`),
    /// promoted to `UnixSock` connected to `/run/netd.sock` on `wasix_32v1::sock_connect`.
    InetSock {
        af: u8,
        sock_type: u8,
        nonblock: bool,
    },
    /// Pure-Rust POSIX pipe end (`fd_pipe`).
    Pipe { handle: PipeHandle, nonblock: bool },
    /// PTY master end (`/dev/ptmx`).
    PtyMaster {
        pty: PtyMasterHandle,
        nonblock: bool,
    },
    /// PTY slave end (`/dev/pts/<N>` or `/dev/tty`).
    PtySlave {
        pty: PtySlaveHandle,
        readable: bool,
        writable: bool,
        nonblock: bool,
    },
    /// Preopen root `/` sentinel (guest fd 3 when no explicit kfd).
    Preopen,
    /// Non-TTY `/dev/null`-like empty stdin (or fixed buffer).
    NullIn,
    /// Fallback host stdout/stderr logger sink (used before console PTY attaches or for PID 1).
    HostLog { fd: u32 },
}

#[derive(Clone)]
pub struct GuestFdEntry {
    pub kind: GuestFdKind,
    pub cloexec: bool,
}

/// Ancillary descriptor sent/received over `AF_UNIX` `SCM_RIGHTS`.
#[derive(Clone)]
pub enum RightsFd {
    Kfd {
        kfd: u32,
        is_dir: bool,
        path_only: bool,
        readable: bool,
        writable: bool,
        append: bool,
        nonblock: bool,
        device: Option<String>,
    },
    UnixSock {
        sock_id: u64,
        sock_type: u32,
    },
    Pipe {
        handle: PipeHandle,
    },
    PtyMaster {
        pty: PtyMasterHandle,
    },
    PtySlave {
        pty: PtySlaveHandle,
        readable: bool,
        writable: bool,
    },
}

/// Anchor passed to `*at` VFS operations (`OS_FD_ROOT`, `OS_FD_CWD`, or kernel `kfd`).
#[derive(Clone, Copy, Debug)]
pub enum KAnchor {
    Root,
    Cwd,
    Kfd(u32),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceBindSpec {
    pub source: String,
    pub target: String,
    #[serde(rename = "readOnly", default)]
    pub read_only: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceGrantSpec {
    #[serde(rename = "mountNamespace", default)]
    pub mount_namespace: String,
    #[serde(rename = "exportImpersonate", default)]
    pub export_impersonate: bool,
    #[serde(rename = "bindMounts", default)]
    pub bind_mounts: Vec<ServiceBindSpec>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub devices: Vec<String>,
}

/// Request from a parent process (`posix_spawn`) or host (`run`/`exec`) to launch a new process.
#[derive(Clone)]
pub struct SpawnProcessReq {
    pub parent_pid: u32,
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub cwd: String,
    pub pgroup: Option<u32>,
    pub cgroup: Option<String>,
    pub service_grant: Option<ServiceGrantSpec>,
    pub umask: u16,
    /// Inherited guest fds (already filtered for `cloexec` & `dup2`).
    pub fds: BTreeMap<u32, GuestFdEntry>,
    /// Parent kernel fds that were `dup2`-copied from another slot (`(new_guest_fd, parent_kfd)`).
    pub dup_kfds: Vec<(u32, u32, bool)>,
    /// Inherited signal snapshot (if any).
    /// Kernel fds overwritten by `dup2` / stdio redirection that must be closed in the child.
    pub close_kfds: Vec<u32>,
    /// Existing child kernel fds whose `cloexec` flag must be explicitly cleared (e.g. `dup2(fd, fd)`).
    pub clear_cloexec_kfds: Vec<u32>,
    pub signals: Option<SignalSnapshot>,
    /// Optional explicit PTY number to attach as controlling terminal.
    pub ctty: Option<u32>,
    /// If true, child becomes a new session leader (`setsid`).
    pub setsid: bool,
    /// If true, run as host-owned console/exec child (`WaitOwner::Host`).
    pub host_owned: bool,
    /// Optional explicit uid override for host-owned spawn (validated by host seat auth).
    pub host_uid: Option<u32>,
}

/// Loaded Wasm executable image + resolved argv returned by the Kernel Actor.
#[derive(Clone, Debug)]
pub struct LoadedImage {
    pub resolved_path: String,
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub raw_sha256: String,
    pub wasm_bytes: Vec<u8>,
    pub is_rv1: bool,
    pub memory_limit_bytes: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct OpenFileReply {
    pub kfd: u32,
    pub is_dir: bool,
    pub path_only: bool,
    pub device: Option<String>,
    pub stat: Stat,
}

#[derive(Clone, Debug)]
pub struct ReaddirEntry {
    pub name: String,
    pub ino: u64,
    pub filetype: u8,
}

#[derive(Clone, Debug)]
pub struct WaitResult {
    pub pid: u32,
    pub status: i32,
    pub signal: Option<u8>,
    pub stopped: bool,
    pub continued: bool,
    pub nothing: bool,
}

#[derive(Clone, Debug)]
pub struct SockPollReply {
    pub ready: bool,
    pub nbytes: usize,
    pub hangup: bool,
}

pub struct SockRecvReply {
    pub data: Vec<u8>,
    pub reported_len: usize,
    pub fds: Vec<RightsFd>,
    pub peer_cred: PeerCred,
    pub out_flags: u32,
}

/// Snapshot of running OS host status for `os-native inspect` and tests.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostInspect {
    pub instance_id: String,
    pub release_id: String,
    pub stage: String,
    pub boot_healthy: bool,
    pub root_volume: Option<String>,
    pub root_epoch: u64,
    pub pids: Vec<u32>,
    pub pty_numbers: Vec<u32>,
    pub shutdown_clean: Option<bool>,
}

/// Every operation a guest Wasm process (or host/seat task) can ask of the Kernel Actor.
/// Prepared fork child state returned by `KernelCmd::PrepareFork`.
pub type PreparedFork = (u32, Arc<SignalControl>, BTreeMap<u32, GuestFdEntry>);
/// Prepared spawn child state returned by `KernelCmd::PrepareSpawn`.
pub type PreparedSpawn = (
    u32,
    Arc<SignalControl>,
    BTreeMap<u32, GuestFdEntry>,
    LoadedImage,
);

/// `(uid, gid, controlling_tty)` tuple returned by `KernelCmd::GetProcCredAndCtty`.
pub type ProcCredAndCtty = (u32, u32, Option<u32>);

pub enum KernelCmd {
    // ---- VFS Operations ----
    OpenAt {
        pid: u32,
        anchor: KAnchor,
        path: String,
        flags: u32,
        mode: u16,
        cloexec: bool,
        reply: oneshot::Sender<Result<OpenFileReply, Errno>>,
    },
    CloseKfd {
        pid: u32,
        kfd: u32,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    DupKfd {
        pid: u32,
        kfd: u32,
        cloexec: bool,
        reply: oneshot::Sender<Result<u32, Errno>>,
    },
    SetKfdCloexec {
        pid: u32,
        kfd: u32,
        cloexec: bool,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    GetKfdCloexec {
        pid: u32,
        kfd: u32,
        reply: oneshot::Sender<Result<bool, Errno>>,
    },
    SetKfdAppend {
        pid: u32,
        kfd: u32,
        append: bool,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    IsKfdAppend {
        pid: u32,
        kfd: u32,
        reply: oneshot::Sender<Result<bool, Errno>>,
    },
    ReadKfd {
        pid: u32,
        kfd: u32,
        offset: Option<u64>,
        len: usize,
        reply: oneshot::Sender<Result<Vec<u8>, Errno>>,
    },
    WriteKfd {
        pid: u32,
        kfd: u32,
        offset: Option<u64>,
        data: Vec<u8>,
        reply: oneshot::Sender<Result<usize, Errno>>,
    },
    SeekKfd {
        pid: u32,
        kfd: u32,
        offset: i64,
        whence: u8,
        reply: oneshot::Sender<Result<u64, Errno>>,
    },
    FtruncateKfd {
        pid: u32,
        kfd: u32,
        size: u64,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    FsyncKfd {
        pid: u32,
        kfd: u32,
        data_only: bool,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    FstatKfd {
        pid: u32,
        kfd: u32,
        reply: oneshot::Sender<Result<Stat, Errno>>,
    },
    FutimensKfd {
        pid: u32,
        kfd: u32,
        atime: Time,
        mtime: Time,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    ReaddirKfd {
        pid: u32,
        kfd: u32,
        reply: oneshot::Sender<Result<Vec<ReaddirEntry>, Errno>>,
    },
    StatAt {
        pid: u32,
        anchor: KAnchor,
        path: String,
        follow: bool,
        reply: oneshot::Sender<Result<Stat, Errno>>,
    },
    MkdirAt {
        pid: u32,
        anchor: KAnchor,
        path: String,
        mode: u16,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    UnlinkAt {
        pid: u32,
        anchor: KAnchor,
        path: String,
        rmdir: bool,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    RenameAt {
        pid: u32,
        from_anchor: KAnchor,
        from: String,
        to_anchor: KAnchor,
        to: String,
        noreplace: bool,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    LinkAt {
        pid: u32,
        from_anchor: KAnchor,
        from: String,
        to_anchor: KAnchor,
        to: String,
        follow: bool,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    SymlinkAt {
        pid: u32,
        target: String,
        anchor: KAnchor,
        path: String,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    ReadlinkAt {
        pid: u32,
        anchor: KAnchor,
        path: String,
        reply: oneshot::Sender<Result<String, Errno>>,
    },
    UtimensAt {
        pid: u32,
        anchor: KAnchor,
        path: String,
        atime: Time,
        mtime: Time,
        follow: bool,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    Chdir {
        pid: u32,
        path: String,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    Fchdir {
        pid: u32,
        kfd: u32,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    Getcwd {
        pid: u32,
        reply: oneshot::Sender<Result<String, Errno>>,
    },
    Chroot {
        pid: u32,
        path: String,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    Mount {
        pid: u32,
        source: Option<String>,
        target: String,
        fstype: Option<String>,
        flags: u64,
        data: Option<String>,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    Umount2 {
        pid: u32,
        target: String,
        flags: u32,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    Statfs {
        pid: u32,
        anchor: KAnchor,
        path: String,
        reply: oneshot::Sender<Result<StatFs, Errno>>,
    },
    Fstatfs {
        pid: u32,
        kfd: u32,
        reply: oneshot::Sender<Result<StatFs, Errno>>,
    },
    Unshare {
        pid: u32,
        flags: u32,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    Setns {
        pid: u32,
        kfd: u32,
        nstype: u32,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    SetUmask {
        pid: u32,
        umask: u16,
        reply: oneshot::Sender<u16>,
    },
    GuiPoll {
        pid: u32,
        kfd: u32,
        writing: bool,
        reply: oneshot::Sender<Result<usize, Errno>>,
    },
    TunPoll {
        pid: u32,
        kfd: u32,
        writing: bool,
        reply: oneshot::Sender<Result<SockPollReply, Errno>>,
    },

    // ---- AF_UNIX Sockets ----
    SockCreate {
        pid: u32,
        sock_type: u32,
        nonblock: bool,
        reply: oneshot::Sender<Result<u64, Errno>>,
    },
    SockPair {
        pid: u32,
        sock_type: u32,
        nonblock: bool,
        reply: oneshot::Sender<Result<(u64, u64), Errno>>,
    },
    SockSetNonblock {
        pid: u32,
        sock_id: u64,
        nonblock: bool,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    SockBind {
        pid: u32,
        sock_id: u64,
        path: String,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    SockListen {
        pid: u32,
        sock_id: u64,
        backlog: u32,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    SockAccept {
        pid: u32,
        sock_id: u64,
        nonblock_new: bool,
        reply: oneshot::Sender<Result<Option<(u64, PeerCred)>, Errno>>,
    },
    SockConnect {
        pid: u32,
        sock_id: u64,
        path: String,
        reply: oneshot::Sender<Result<PeerCred, Errno>>,
    },
    SockShutdown {
        pid: u32,
        sock_id: u64,
        how: u32,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    SockSendMsg {
        pid: u32,
        sock_id: u64,
        data: Vec<u8>,
        fds: Vec<RightsFd>,
        addr: Option<String>,
        flags: u32,
        reply: oneshot::Sender<Result<usize, Errno>>,
    },
    SockRecvMsg {
        pid: u32,
        sock_id: u64,
        max_bytes: usize,
        max_fds: usize,
        flags: u32,
        reply: oneshot::Sender<Result<SockRecvReply, Errno>>,
    },
    SockPeerCred {
        pid: u32,
        sock_id: u64,
        reply: oneshot::Sender<Result<PeerCred, Errno>>,
    },
    SockGetsockname {
        pid: u32,
        sock_id: u64,
        reply: oneshot::Sender<Result<String, Errno>>,
    },
    SockGetpeername {
        pid: u32,
        sock_id: u64,
        reply: oneshot::Sender<Result<String, Errno>>,
    },
    SockGetsockopt {
        pid: u32,
        sock_id: u64,
        level: u32,
        optname: u32,
        reply: oneshot::Sender<Result<i32, Errno>>,
    },
    SockSetsockopt {
        pid: u32,
        sock_id: u64,
        level: u32,
        optname: u32,
        val: i32,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    SockPoll {
        pid: u32,
        sock_id: u64,
        writing: bool,
        reply: oneshot::Sender<Result<SockPollReply, Errno>>,
    },
    SockHold {
        pid: u32,
        sock_id: u64,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    SockClose {
        pid: u32,
        sock_id: u64,
        reply: oneshot::Sender<Result<(), Errno>>,
    },

    // ---- Process / Signals / Credentials / Batch ----
    SysBatch {
        pid: u32,
        umask: u16,
        calls: Vec<Call>,
        /// Mapping from guest fd -> kernel fd / sock / pty for `Call::Ioctl`, `Close`, `Fchmod`, etc.
        guest_fds: BTreeMap<u32, GuestFdKind>,
        reply: oneshot::Sender<Vec<abi::Return>>,
    },
    GetCreds {
        pid: u32,
        reply: oneshot::Sender<Result<Creds, Error>>,
    },
    GetProcParent {
        pid: u32,
        target: u32,
        reply: oneshot::Sender<Result<u32, Errno>>,
    },
    GetPgid {
        pid: u32,
        target: i32,
        reply: oneshot::Sender<Result<u32, Errno>>,
    },
    GetSid {
        pid: u32,
        target: i32,
        reply: oneshot::Sender<Result<u32, Errno>>,
    },
    SetPgid {
        pid: u32,
        target: i32,
        pgid: i32,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    SetSid {
        pid: u32,
        reply: oneshot::Sender<Result<u32, Errno>>,
    },
    Kill {
        pid: u32,
        target: String,
        signal: u8,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    KillPgrp {
        pgrp: u32,
        signal: u8,
    },
    ReportStopped {
        pid: u32,
        signal: u8,
    },
    Waitpid {
        pid: u32,
        target: i32,
        options: u32,
        host_reap: bool,
        reply: oneshot::Sender<Result<WaitResult, Errno>>,
    },
    ReserveMemory {
        pid: u32,
        bytes: u64,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    PrepareFork {
        parent_pid: u32,
        fds: BTreeMap<u32, GuestFdEntry>,
        reply: oneshot::Sender<Result<PreparedFork, Errno>>,
    },
    PrepareExec {
        pid: u32,
        file: String,
        argv: Vec<String>,
        env: Vec<String>,
        search: bool,
        reply: oneshot::Sender<Result<LoadedImage, Errno>>,
    },
    PrepareSpawn {
        req: Box<SpawnProcessReq>,
        reply: oneshot::Sender<Result<PreparedSpawn, Errno>>,
    },
    ProcessExited {
        pid: u32,
        code: i32,
        signal: Option<u8>,
        reply: oneshot::Sender<()>,
    },
    SetTty {
        pid: u32,
        tty: Option<u32>,
        tty_fds: Vec<u32>,
        reply: oneshot::Sender<()>,
    },
    GetProcTtyInfo {
        pid: u32,
        reply: oneshot::Sender<(u32, u32, Option<u32>)>, // (pgid, sid, ctty)
    },
    PtyHangup {
        number: u32,
        pgrp: u32,
        sid: u32,
    },
    /// Allocate a PTY owned by `pid`'s uid/gid and register `/dev/pts/<N>` in `DevPtsFs`.
    AllocPty {
        pid: u32,
        locked: bool,
        reply: oneshot::Sender<Result<PtyMasterHandle, Errno>>,
    },
    /// Register (or update owner of) `/dev/pts/<number>` in `DevPtsFs` (e.g. console/seat PTY).
    RegisterPty {
        number: u32,
        uid: u32,
        gid: u32,
        mode: u16,
        reply: oneshot::Sender<()>,
    },
    /// Check caller's uid/gid/ctty for opening `/dev/tty` or `/dev/pts/<N>`.
    GetProcCredAndCtty {
        pid: u32,
        reply: oneshot::Sender<Result<ProcCredAndCtty, Errno>>,
    },

    // ---- Host Control & Inspection ----
    CommitCowfsNow {
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    Inspect {
        reply: oneshot::Sender<HostInspect>,
    },
    Shutdown {
        reply: oneshot::Sender<Result<bool, String>>,
    },
}

/// Cloneable `Send + Sync` handle used by guest threads, seat servers, and CLI tests
/// to communicate with the Kernel Actor.
#[derive(Clone)]
pub struct KernelClient {
    pub tx: mpsc::UnboundedSender<KernelCmd>,
    pub wake: Arc<WakeBus>,
    pub ptys: Arc<PtyTable>,
}

impl KernelClient {
    /// Blocking RPC helper for synchronous Wasmtime host functions.
    pub fn call_sync<R>(&self, make: impl FnOnce(oneshot::Sender<R>) -> KernelCmd) -> R {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(make(tx));
        rx.blocking_recv().expect("kernel actor shut down")
    }

    /// Non-panicking blocking RPC helper for teardown/cleanup paths after shutdown.
    pub fn try_call_sync<R>(
        &self,
        make: impl FnOnce(oneshot::Sender<R>) -> KernelCmd,
    ) -> Option<R> {
        let (tx, rx) = oneshot::channel();
        self.tx.send(make(tx)).ok()?;
        rx.blocking_recv().ok()
    }

    /// Async RPC helper for Tokio tasks (seat server, CLI, tests).
    pub async fn call_async<R>(&self, make: impl FnOnce(oneshot::Sender<R>) -> KernelCmd) -> R {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(make(tx));
        rx.await.expect("kernel actor shut down")
    }

    pub fn send_fire_and_forget(&self, cmd: KernelCmd) {
        let _ = self.tx.send(cmd);
    }
}

/// Helper to build a JSON `abi::Return::Ok`.
pub fn ret_ok<T: Serialize>(val: T) -> abi::Return {
    abi::Return::Ok(serde_json::to_value(val).unwrap_or(Value::Null))
}

/// Helper to build a JSON `abi::Return::Err`.
pub fn ret_err(err: impl Into<Error>) -> abi::Return {
    abi::Return::Err(err.into())
}

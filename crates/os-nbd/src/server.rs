//! Bounded NBD Fixed Newstyle Unix-socket server backed by a `LocalSet` `RawBlockVolume` actor.

use crate::proto::{
    DEFAULT_HANDSHAKE_TIMEOUT, MAX_HANDSHAKE_OPTIONS, MAX_NBD_IO_BYTES, MAX_OPTION_LEN,
    NBD_CMD_DISC, NBD_CMD_FLAG_FUA, NBD_CMD_FLUSH, NBD_CMD_READ, NBD_CMD_TRIM, NBD_CMD_WRITE,
    NBD_CMD_WRITE_ZEROES, NBD_EINVAL, NBD_EIO, NBD_ENOSPC, NBD_EOVERFLOW, NBD_EPERM,
    NBD_FLAG_C_FIXED_NEWSTYLE, NBD_FLAG_C_NO_ZEROES, NBD_FLAG_FIXED_NEWSTYLE, NBD_FLAG_HAS_FLAGS,
    NBD_FLAG_NO_ZEROES, NBD_FLAG_READ_ONLY, NBD_FLAG_SEND_FLUSH, NBD_FLAG_SEND_FUA,
    NBD_FLAG_SEND_TRIM, NBD_FLAG_SEND_WRITE_ZEROES, NBD_OK, NBD_OPT_ABORT, NBD_OPT_EXPORT_NAME,
    NBD_OPT_GO, NBD_OPT_INFO, NBD_OPT_LIST, NBD_REP_ACK, NBD_REP_ERR_INVALID, NBD_REP_ERR_UNKNOWN,
    NBD_REP_ERR_UNSUP, NBD_REP_INFO, NBD_REP_SERVER, encode_info_block_size, encode_info_export,
    encode_info_name, errno_to_nbd_error, read_client_option, read_request,
    write_newstyle_greeting, write_option_reply, write_simple_reply,
};
use abi::Errno;
use abi::fs::Timespec;
use cowtree::{HeadStore, PackStore, VolumeId};
use os_cowfs::native_sqlite::{NativePackStore, NativeSqliteHeadStore};
use os_cowfs::raw_lba::{RawBlockConfig, RawBlockOpenMode, RawBlockVolume};
use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::{mpsc, oneshot, watch};

/// Configuration for an NBD export.
#[derive(Clone, Debug)]
pub struct NbdExportConfig {
    pub export_name: String,
    pub handshake_timeout: Duration,
    pub max_io_bytes: u32,
}

impl NbdExportConfig {
    pub fn new(export_name: impl Into<String>) -> Self {
        Self {
            export_name: export_name.into(),
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            max_io_bytes: MAX_NBD_IO_BYTES,
        }
    }
}

/// Validate a Unix socket bind path: reject `..`, reject symlinked parent directories, and reject
/// replacing an existing non-socket or symlink path.
pub fn validate_safe_unix_socket_path(path: &Path) -> io::Result<()> {
    if path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty NBD socket path",
        ));
    }
    for comp in path.components() {
        if matches!(comp, Component::ParentDir) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "NBD socket path must not contain '..'",
            ));
        }
    }
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "NBD socket path has no parent")
    })?;
    if !parent.as_os_str().is_empty() {
        let mut cur = PathBuf::new();
        for comp in parent.components() {
            cur.push(comp);
            if matches!(comp, Component::RootDir) {
                continue;
            }
            let meta = std::fs::symlink_metadata(&cur)?;
            if meta.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("refusing symlink parent component {}", cur.display()),
                ));
            }
            if !meta.file_type().is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    format!("parent component is not a directory: {}", cur.display()),
                ));
            }
        }
    }
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && (meta.file_type().is_symlink() || !meta.file_type().is_socket())
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing to unlink existing non-socket or symlink path",
        ));
    }
    Ok(())
}

/// Ensure a private `0o700` runtime directory under `/tmp` owned by the current effective UID.
pub fn ensure_private_runtime_dir(prefix: &str) -> io::Result<PathBuf> {
    let uid = unsafe { libc::geteuid() };
    let dir = PathBuf::from("/tmp").join(format!("{prefix}-{uid}"));
    let cdir = CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in runtime dir"))?;
    let rc = unsafe { libc::mkdir(cdir.as_ptr(), 0o700) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::AlreadyExists {
            return Err(err);
        }
    }
    let meta = std::fs::symlink_metadata(&dir)?;
    if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("refusing non-directory runtime dir {}", dir.display()),
        ));
    }
    if meta.uid() != uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("runtime dir {} not owned by current uid", dir.display()),
        ));
    }
    if (meta.permissions().mode() & 0o077) != 0 {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}

pub fn bind_unix_socket_0600(path: &Path) -> io::Result<UnixListener> {
    static STAGE_SEQ: AtomicU64 = AtomicU64::new(1);
    validate_safe_unix_socket_path(path)?;
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "NBD socket path has no parent")
    })?;
    let seq = STAGE_SEQ.fetch_add(1, Ordering::Relaxed);
    let stage_dir = parent.join(format!(".n{}-{seq}", std::process::id()));
    let stage_sock = stage_dir.join("s");
    if stage_sock.as_os_str().len() < 104 {
        let cstage = CString::new(stage_dir.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in stage dir"))?;
        let rc = unsafe { libc::mkdir(cstage.as_ptr(), 0o700) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let bind_res = (|| -> io::Result<UnixListener> {
            let listener = UnixListener::bind(&stage_sock)?;
            std::fs::set_permissions(&stage_sock, std::fs::Permissions::from_mode(0o600))?;
            // Re-verify target wasn't swapped with a non-socket/symlink before atomic rename.
            validate_safe_unix_socket_path(path)?;
            std::fs::rename(&stage_sock, path)?;
            Ok(listener)
        })();
        let _ = std::fs::remove_file(&stage_sock);
        let _ = std::fs::remove_dir(&stage_dir);
        return bind_res;
    }

    // Path too close to SUN_LEN for a nested stage dir: require private 0o700 parent owned by self.
    let pmeta = std::fs::symlink_metadata(parent)?;
    let uid = unsafe { libc::geteuid() };
    if pmeta.uid() != uid || (pmeta.permissions().mode() & 0o077) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing to bind long socket path in non-private parent directory",
        ));
    }
    if std::fs::symlink_metadata(path).is_ok() {
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

enum ActorCmd {
    Read {
        offset: u64,
        len: usize,
        reply: oneshot::Sender<Result<Vec<u8>, Errno>>,
    },
    Write {
        offset: u64,
        data: Vec<u8>,
        fua: bool,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    Flush {
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    Trim {
        offset: u64,
        len: u64,
        fua: bool,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    WriteZeroes {
        offset: u64,
        len: u64,
        fua: bool,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    MarkFenced,
    Shutdown {
        reply: oneshot::Sender<Result<(), Errno>>,
    },
}

/// Thread-safe handle communicating with the `LocalSet` [`RawBlockVolume`] actor.
#[derive(Clone)]
pub struct NbdVolumeActorHandle {
    tx: mpsc::UnboundedSender<ActorCmd>,
    size_bytes: u64,
    block_size: u32,
    read_only: bool,
    fenced: Arc<AtomicBool>,
}

impl NbdVolumeActorHandle {
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    pub fn is_fenced(&self) -> bool {
        self.fenced.load(Ordering::SeqCst)
    }

    pub fn mark_fenced(&self) {
        self.fenced.store(true, Ordering::SeqCst);
        let _ = self.tx.send(ActorCmd::MarkFenced);
    }

    pub async fn read(&self, offset: u64, len: usize) -> Result<Vec<u8>, Errno> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(ActorCmd::Read { offset, len, reply })
            .map_err(|_| Errno::EIO)?;
        rx.await.map_err(|_| Errno::EIO)?
    }

    pub async fn write(&self, offset: u64, data: Vec<u8>, fua: bool) -> Result<(), Errno> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(ActorCmd::Write {
                offset,
                data,
                fua,
                reply,
            })
            .map_err(|_| Errno::EIO)?;
        rx.await.map_err(|_| Errno::EIO)?
    }

    pub async fn flush(&self) -> Result<(), Errno> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(ActorCmd::Flush { reply })
            .map_err(|_| Errno::EIO)?;
        rx.await.map_err(|_| Errno::EIO)?
    }

    pub async fn trim(&self, offset: u64, len: u64, fua: bool) -> Result<(), Errno> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(ActorCmd::Trim {
                offset,
                len,
                fua,
                reply,
            })
            .map_err(|_| Errno::EIO)?;
        rx.await.map_err(|_| Errno::EIO)?
    }

    pub async fn write_zeroes(&self, offset: u64, len: u64, fua: bool) -> Result<(), Errno> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(ActorCmd::WriteZeroes {
                offset,
                len,
                fua,
                reply,
            })
            .map_err(|_| Errno::EIO)?;
        rx.await.map_err(|_| Errno::EIO)?
    }

    pub async fn shutdown(&self) -> Result<(), Errno> {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(ActorCmd::Shutdown { reply }).is_err() {
            return Ok(());
        }
        rx.await.unwrap_or(Ok(()))
    }
}

/// Optional callback fired whenever the NBD raw-block actor detects fencing (`ESTALE`).
pub type OnFencedCallback = Arc<dyn Fn() + Send + Sync>;

/// Spawn a `!Send` [`RawBlockVolume`] actor onto the active `tokio::task::LocalSet`.
pub fn spawn_raw_volume_actor_on_local<H: HeadStore + 'static, P: PackStore + 'static>(
    vol: Rc<RawBlockVolume<H, P>>,
) -> NbdVolumeActorHandle {
    spawn_raw_volume_actor_on_local_with_fence(vol, None, None)
}

/// Spawn a `!Send` [`RawBlockVolume`] actor onto the active `tokio::task::LocalSet`, propagating
/// CAS/validator `ESTALE` fencing back to `external_fence_flag` and `on_fenced`.
pub fn spawn_raw_volume_actor_on_local_with_fence<
    H: HeadStore + 'static,
    P: PackStore + 'static,
>(
    vol: Rc<RawBlockVolume<H, P>>,
    external_fence_flag: Option<Arc<AtomicBool>>,
    on_fenced: Option<OnFencedCallback>,
) -> NbdVolumeActorHandle {
    let info = vol.info();
    let fenced = Arc::new(AtomicBool::new(info.fenced));
    let fenced_actor = Arc::clone(&fenced);
    let (tx, mut rx) = mpsc::unbounded_channel::<ActorCmd>();

    tokio::task::spawn_local(async move {
        let trip_fence = || {
            fenced_actor.store(true, Ordering::SeqCst);
            if let Some(ref ext) = external_fence_flag {
                ext.store(true, Ordering::SeqCst);
            }
            if let Some(ref cb) = on_fenced {
                cb();
            }
        };
        while let Some(cmd) = rx.recv().await {
            match cmd {
                ActorCmd::Read { offset, len, reply } => {
                    let mut buf = vec![0u8; len];
                    let res = vol.read_at(offset, &mut buf).await.map(|n| {
                        buf.truncate(n);
                        buf
                    });
                    let _ = reply.send(res);
                }
                ActorCmd::Write {
                    offset,
                    data,
                    fua,
                    reply,
                } => {
                    let mut res = vol.write_at(offset, &data).await.map(|_| ());
                    if res.is_ok() && fua {
                        res = vol.flush().await.map(|_| ());
                    }
                    if res == Err(Errno::ESTALE) || vol.fencing_state().fenced {
                        trip_fence();
                    }
                    let _ = reply.send(res);
                }
                ActorCmd::Flush { reply } => {
                    let res = vol.flush().await.map(|_| ());
                    if res == Err(Errno::ESTALE) || vol.fencing_state().fenced {
                        trip_fence();
                    }
                    let _ = reply.send(res);
                }
                ActorCmd::Trim {
                    offset,
                    len,
                    fua,
                    reply,
                } => {
                    let mut res = vol.trim(offset, len).await;
                    if res.is_ok() && fua {
                        res = vol.flush().await.map(|_| ());
                    }
                    if res == Err(Errno::ESTALE) || vol.fencing_state().fenced {
                        trip_fence();
                    }
                    let _ = reply.send(res);
                }
                ActorCmd::WriteZeroes {
                    offset,
                    len,
                    fua,
                    reply,
                } => {
                    let mut res = vol.write_zeroes(offset, len).await;
                    if res.is_ok() && fua {
                        res = vol.flush().await.map(|_| ());
                    }
                    if res == Err(Errno::ESTALE) || vol.fencing_state().fenced {
                        trip_fence();
                    }
                    let _ = reply.send(res);
                }
                ActorCmd::MarkFenced => {
                    vol.mark_fenced();
                    trip_fence();
                }
                ActorCmd::Shutdown { reply } => {
                    let res = vol.close_clean().await;
                    if res == Err(Errno::ESTALE) || vol.fencing_state().fenced {
                        trip_fence();
                    }
                    let _ = reply.send(res);
                    break;
                }
            }
        }
        let res = vol.close_clean().await;
        if res == Err(Errno::ESTALE) || vol.fencing_state().fenced {
            trip_fence();
        }
    });

    NbdVolumeActorHandle {
        tx,
        size_bytes: info.size_bytes,
        block_size: info.block_size,
        read_only: info.read_only,
        fenced,
    }
}

/// Live NBD Unix-socket server handle; automatically signals shutdown and unlinks the socket on drop.
pub struct NbdServerHandle {
    socket_path: PathBuf,
    shutdown_tx: watch::Sender<bool>,
    actor: NbdVolumeActorHandle,
    thread: Option<std::thread::JoinHandle<()>>,
    stopped: AtomicBool,
}

impl NbdServerHandle {
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn actor(&self) -> &NbdVolumeActorHandle {
        &self.actor
    }

    pub fn is_fenced(&self) -> bool {
        self.actor.is_fenced()
    }

    pub fn mark_fenced(&self) {
        self.actor.mark_fenced();
    }

    /// Start an NBD Unix-socket server on a dedicated OS thread with its own single-threaded Tokio
    /// `LocalSet` owning a native SQLite+packs [`RawBlockVolume`].
    pub fn start_unix_native(
        socket_path: PathBuf,
        store_dir: PathBuf,
        volume_id: VolumeId,
        config: NbdExportConfig,
        mode: RawBlockOpenMode,
        external_fence_flag: Option<Arc<AtomicBool>>,
    ) -> io::Result<Self> {
        Self::start_unix_native_with_on_fenced(
            socket_path,
            store_dir,
            volume_id,
            config,
            mode,
            external_fence_flag,
            None,
        )
    }

    /// Start an NBD Unix-socket server with an optional `on_fenced` callback fired whenever the
    /// underlying [`RawBlockVolume`] trips sticky `ESTALE` fencing.
    pub fn start_unix_native_with_on_fenced(
        socket_path: PathBuf,
        store_dir: PathBuf,
        volume_id: VolumeId,
        config: NbdExportConfig,
        mode: RawBlockOpenMode,
        external_fence_flag: Option<Arc<AtomicBool>>,
        on_fenced: Option<OnFencedCallback>,
    ) -> io::Result<Self> {
        validate_safe_unix_socket_path(&socket_path)?;
        let (ready_tx, ready_rx) =
            std::sync::mpsc::channel::<io::Result<(watch::Sender<bool>, NbdVolumeActorHandle)>>();
        let sock_for_thread = socket_path.clone();

        let thread = std::thread::Builder::new()
            .name(format!("os-nbd-{}", config.export_name))
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                let local = tokio::task::LocalSet::new();
                local.block_on(&rt, async move {
                    let setup: io::Result<(
                        UnixListener,
                        watch::Sender<bool>,
                        watch::Receiver<bool>,
                        NbdVolumeActorHandle,
                    )> = async {
                        let hs =
                            Rc::new(NativeSqliteHeadStore::open(&store_dir).map_err(|e| {
                                io::Error::other(format!("open head store: {e:?}"))
                            })?);
                        let ps =
                            Rc::new(NativePackStore::open(&store_dir).map_err(|e| {
                                io::Error::other(format!("open pack store: {e:?}"))
                            })?);
                        let clock: os_cowfs::CowFsClock = Rc::new(|| {
                            SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .map(|d| Timespec {
                                    sec: d.as_secs(),
                                    nsec: d.subsec_nanos(),
                                })
                                .unwrap_or(Timespec {
                                    sec: 1_700_000_000,
                                    nsec: 0,
                                })
                        });
                        let mut raw_cfg = RawBlockConfig::remote_fenced(clock);
                        if let Some(ref flag) = external_fence_flag {
                            let flag_c = Arc::clone(flag);
                            raw_cfg = raw_cfg.with_fence_validator(Rc::new(move || {
                                if flag_c.load(Ordering::SeqCst) {
                                    Err(Errno::ESTALE)
                                } else {
                                    Ok(())
                                }
                            }));
                        }
                        let vol = Rc::new(
                            RawBlockVolume::open(hs, ps, volume_id, mode, raw_cfg)
                                .await
                                .map_err(|e| io::Error::other(format!("open raw volume: {e:?}")))?,
                        );
                        let listener = bind_unix_socket_0600(&sock_for_thread)?;
                        let actor = spawn_raw_volume_actor_on_local_with_fence(
                            vol,
                            external_fence_flag,
                            on_fenced,
                        );
                        let (shutdown_tx, shutdown_rx) = watch::channel(false);
                        Ok((listener, shutdown_tx, shutdown_rx, actor))
                    }
                    .await;

                    let (listener, shutdown_tx, shutdown_rx, actor) = match setup {
                        Ok(t) => t,
                        Err(e) => {
                            let _ = ready_tx.send(Err(e));
                            return;
                        }
                    };
                    let _ = ready_tx.send(Ok((shutdown_tx, actor.clone())));
                    run_accept_loop(listener, actor.clone(), config, shutdown_rx).await;
                    let _ = actor.shutdown().await;
                });
            })?;

        let (shutdown_tx, actor) = ready_rx
            .recv()
            .map_err(|_| io::Error::other("os-nbd server thread terminated before ready"))??;

        Ok(Self {
            socket_path,
            shutdown_tx,
            actor,
            thread: Some(thread),
            stopped: AtomicBool::new(false),
        })
    }

    pub async fn shutdown(&mut self) -> Result<(), Errno> {
        if self.stopped.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let _ = self.shutdown_tx.send(true);
        let res = self.actor.shutdown().await;
        if let Some(th) = self.thread.take() {
            let _ = th.join();
        }
        let _ = std::fs::remove_file(&self.socket_path);
        res
    }

    pub fn shutdown_blocking(&mut self) {
        if self.stopped.swap(true, Ordering::SeqCst) {
            return;
        }
        let _ = self.shutdown_tx.send(true);
        if let Some(th) = self.thread.take() {
            let _ = th.join();
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

impl Drop for NbdServerHandle {
    fn drop(&mut self) {
        self.shutdown_blocking();
    }
}

/// Spawn an NBD Fixed Newstyle Unix-socket server inside the caller's active `LocalSet`.
pub fn serve_unix_on_local_set<H: HeadStore + 'static, P: PackStore + 'static>(
    socket_path: PathBuf,
    config: NbdExportConfig,
    vol: Rc<RawBlockVolume<H, P>>,
) -> io::Result<NbdServerHandle> {
    let listener = bind_unix_socket_0600(&socket_path)?;
    let actor = spawn_raw_volume_actor_on_local(vol);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let actor_loop = actor.clone();
    tokio::task::spawn_local(async move {
        run_accept_loop(listener, actor_loop, config, shutdown_rx).await;
    });
    Ok(NbdServerHandle {
        socket_path,
        shutdown_tx,
        actor,
        thread: None,
        stopped: AtomicBool::new(false),
    })
}

async fn run_accept_loop(
    listener: UnixListener,
    actor: NbdVolumeActorHandle,
    config: NbdExportConfig,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _addr)) => {
                        let conn_actor = actor.clone();
                        let conn_cfg = config.clone();
                        let conn_shutdown = shutdown_rx.clone();
                        tokio::task::spawn_local(async move {
                            let _ = handle_connection(stream, conn_actor, conn_cfg, conn_shutdown).await;
                        });
                    }
                    Err(_) => break,
                }
            }
        }
    }
}

fn transmission_flags(read_only: bool) -> u16 {
    let mut flags = NBD_FLAG_HAS_FLAGS
        | NBD_FLAG_SEND_FLUSH
        | NBD_FLAG_SEND_FUA
        | NBD_FLAG_SEND_TRIM
        | NBD_FLAG_SEND_WRITE_ZEROES;
    if read_only {
        flags |= NBD_FLAG_READ_ONLY;
    }
    flags
}

fn parse_info_or_go_export_name(data: &[u8]) -> Option<String> {
    if data.len() < 4 {
        return None;
    }
    let name_len = u32::from_be_bytes(data[0..4].try_into().unwrap()) as usize;
    let name_end = 4usize.checked_add(name_len)?;
    if data.len() < name_end + 2 {
        return None;
    }
    let name = std::str::from_utf8(&data[4..name_end]).ok()?.to_string();
    let req_count = u16::from_be_bytes([data[name_end], data[name_end + 1]]) as usize;
    let expected_end = name_end + 2 + req_count.checked_mul(2)?;
    if data.len() != expected_end {
        return None;
    }
    Some(name)
}

async fn run_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    actor: &NbdVolumeActorHandle,
    config: &NbdExportConfig,
) -> io::Result<bool> {
    write_newstyle_greeting(stream, NBD_FLAG_FIXED_NEWSTYLE | NBD_FLAG_NO_ZEROES).await?;
    let mut cflags_buf = [0u8; 4];
    stream.read_exact(&mut cflags_buf).await?;
    let client_flags = u32::from_be_bytes(cflags_buf);
    if (client_flags & NBD_FLAG_C_FIXED_NEWSTYLE) == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "client did not set NBD_FLAG_C_FIXED_NEWSTYLE",
        ));
    }

    let tflags = transmission_flags(actor.is_read_only());
    for _ in 0..MAX_HANDSHAKE_OPTIONS {
        let (opt, len) = read_client_option(stream).await?;
        if len > MAX_OPTION_LEN {
            write_option_reply(stream, opt, NBD_REP_ERR_INVALID, b"option too large").await?;
            return Ok(false);
        }
        let mut data = vec![0u8; len as usize];
        if !data.is_empty() {
            stream.read_exact(&mut data).await?;
        }

        match opt {
            NBD_OPT_ABORT => {
                write_option_reply(stream, opt, NBD_REP_ACK, &[]).await?;
                return Ok(false);
            }
            NBD_OPT_LIST => {
                if !data.is_empty() {
                    write_option_reply(stream, opt, NBD_REP_ERR_INVALID, &[]).await?;
                    continue;
                }
                let name_bytes = config.export_name.as_bytes();
                let mut payload = Vec::with_capacity(4 + name_bytes.len());
                payload.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
                payload.extend_from_slice(name_bytes);
                write_option_reply(stream, opt, NBD_REP_SERVER, &payload).await?;
                write_option_reply(stream, opt, NBD_REP_ACK, &[]).await?;
            }
            NBD_OPT_INFO | NBD_OPT_GO => {
                let Some(name) = parse_info_or_go_export_name(&data) else {
                    write_option_reply(stream, opt, NBD_REP_ERR_INVALID, &[]).await?;
                    continue;
                };
                if !name.is_empty() && name != config.export_name {
                    write_option_reply(stream, opt, NBD_REP_ERR_UNKNOWN, &[]).await?;
                    continue;
                }
                let exp_info = encode_info_export(actor.size_bytes(), tflags);
                write_option_reply(stream, opt, NBD_REP_INFO, &exp_info).await?;
                let name_info = encode_info_name(&config.export_name);
                write_option_reply(stream, opt, NBD_REP_INFO, &name_info).await?;
                let bs = actor.block_size();
                let blk_info = encode_info_block_size(bs, bs.max(4096), config.max_io_bytes);
                write_option_reply(stream, opt, NBD_REP_INFO, &blk_info).await?;
                write_option_reply(stream, opt, NBD_REP_ACK, &[]).await?;
                if opt == NBD_OPT_GO {
                    return Ok(true);
                }
            }
            NBD_OPT_EXPORT_NAME => {
                let Ok(name) = std::str::from_utf8(&data) else {
                    return Ok(false);
                };
                if !name.is_empty() && name != config.export_name {
                    return Ok(false);
                }
                let mut hdr = [0u8; 10];
                hdr[0..8].copy_from_slice(&actor.size_bytes().to_be_bytes());
                hdr[8..10].copy_from_slice(&tflags.to_be_bytes());
                stream.write_all(&hdr).await?;
                if (client_flags & NBD_FLAG_C_NO_ZEROES) == 0 {
                    stream.write_all(&[0u8; 124]).await?;
                }
                stream.flush().await?;
                return Ok(true);
            }
            _ => {
                write_option_reply(stream, opt, NBD_REP_ERR_UNSUP, &[]).await?;
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "exceeded maximum NBD handshake option count",
    ))
}

/// Serve one NBD Fixed Newstyle connection (handshake + transmission phase).
pub async fn handle_connection<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    actor: NbdVolumeActorHandle,
    config: NbdExportConfig,
    mut shutdown_rx: watch::Receiver<bool>,
) -> io::Result<()> {
    let entered = tokio::time::timeout(
        config.handshake_timeout,
        run_handshake(&mut stream, &actor, &config),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "NBD handshake timed out"))??;
    if !entered {
        return Ok(());
    }

    let size_bytes = actor.size_bytes();
    let max_io = config.max_io_bytes;

    loop {
        let req = tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
                continue;
            }
            r = read_request(&mut stream) => {
                match r? {
                    Some(req) => req,
                    None => break,
                }
            }
        };

        let fua = (req.flags & NBD_CMD_FLAG_FUA) != 0;
        match req.cmd {
            NBD_CMD_DISC => break,
            NBD_CMD_READ => {
                if req.length > max_io {
                    write_simple_reply(&mut stream, NBD_EOVERFLOW, req.handle, None).await?;
                    continue;
                }
                if req
                    .offset
                    .checked_add(u64::from(req.length))
                    .is_none_or(|e| e > size_bytes)
                {
                    write_simple_reply(&mut stream, NBD_EINVAL, req.handle, None).await?;
                    continue;
                }
                match actor.read(req.offset, req.length as usize).await {
                    Ok(bytes) => {
                        if bytes.len() != req.length as usize {
                            write_simple_reply(&mut stream, NBD_EIO, req.handle, None).await?;
                        } else {
                            write_simple_reply(&mut stream, NBD_OK, req.handle, Some(&bytes))
                                .await?;
                        }
                    }
                    Err(e) => {
                        write_simple_reply(&mut stream, errno_to_nbd_error(e), req.handle, None)
                            .await?;
                    }
                }
            }
            NBD_CMD_WRITE => {
                if req.length > max_io {
                    // Reject oversize write without allocating or buffering unbounded payloads.
                    write_simple_reply(&mut stream, NBD_EOVERFLOW, req.handle, None).await?;
                    break;
                }
                let mut payload = vec![0u8; req.length as usize];
                if !payload.is_empty() {
                    stream.read_exact(&mut payload).await?;
                }
                if actor.is_read_only() {
                    write_simple_reply(&mut stream, NBD_EPERM, req.handle, None).await?;
                    continue;
                }
                if req
                    .offset
                    .checked_add(u64::from(req.length))
                    .is_none_or(|e| e > size_bytes)
                {
                    write_simple_reply(&mut stream, NBD_ENOSPC, req.handle, None).await?;
                    continue;
                }
                match actor.write(req.offset, payload, fua).await {
                    Ok(()) => {
                        write_simple_reply(&mut stream, NBD_OK, req.handle, None).await?;
                    }
                    Err(e) => {
                        write_simple_reply(&mut stream, errno_to_nbd_error(e), req.handle, None)
                            .await?;
                    }
                }
            }
            NBD_CMD_FLUSH => {
                if req.offset != 0 || req.length != 0 {
                    write_simple_reply(&mut stream, NBD_EINVAL, req.handle, None).await?;
                    continue;
                }
                if actor.is_read_only() {
                    write_simple_reply(&mut stream, NBD_OK, req.handle, None).await?;
                    continue;
                }
                match actor.flush().await {
                    Ok(()) => {
                        write_simple_reply(&mut stream, NBD_OK, req.handle, None).await?;
                    }
                    Err(e) => {
                        write_simple_reply(&mut stream, errno_to_nbd_error(e), req.handle, None)
                            .await?;
                    }
                }
            }
            NBD_CMD_TRIM => {
                if actor.is_read_only() {
                    write_simple_reply(&mut stream, NBD_EPERM, req.handle, None).await?;
                    continue;
                }
                if req
                    .offset
                    .checked_add(u64::from(req.length))
                    .is_none_or(|e| e > size_bytes)
                {
                    write_simple_reply(&mut stream, NBD_EINVAL, req.handle, None).await?;
                    continue;
                }
                match actor.trim(req.offset, u64::from(req.length), fua).await {
                    Ok(()) => {
                        write_simple_reply(&mut stream, NBD_OK, req.handle, None).await?;
                    }
                    Err(e) => {
                        write_simple_reply(&mut stream, errno_to_nbd_error(e), req.handle, None)
                            .await?;
                    }
                }
            }
            NBD_CMD_WRITE_ZEROES => {
                if actor.is_read_only() {
                    write_simple_reply(&mut stream, NBD_EPERM, req.handle, None).await?;
                    continue;
                }
                if req
                    .offset
                    .checked_add(u64::from(req.length))
                    .is_none_or(|e| e > size_bytes)
                {
                    write_simple_reply(&mut stream, NBD_ENOSPC, req.handle, None).await?;
                    continue;
                }
                match actor
                    .write_zeroes(req.offset, u64::from(req.length), fua)
                    .await
                {
                    Ok(()) => {
                        write_simple_reply(&mut stream, NBD_OK, req.handle, None).await?;
                    }
                    Err(e) => {
                        write_simple_reply(&mut stream, errno_to_nbd_error(e), req.handle, None)
                            .await?;
                    }
                }
            }
            _ => {
                write_simple_reply(&mut stream, NBD_EINVAL, req.handle, None).await?;
            }
        }
    }

    Ok(())
}

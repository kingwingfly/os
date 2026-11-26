//! CSI v1.9 Node plugin (`OsCsiNode<C: ClusterStore>`):
//! - Path confinement, traversal, and symlink-rejection checks on staging & target paths
//! - `ClusterState` publish-context fencing verification BEFORE opening storage
//! - Filesystem volumes (`StageMode::Fuse` / `StageMode::HostSubvol` / `StageMode::Auto`) synced
//!   through a live fenced `CowFs` actor
//! - Raw block volumes exported over per-volume `0600` `os-nbd` Unix sockets (`$NODE_STATE/nbd/<vol>.sock`)
//! - Lease keepalive + local monotonic self-fencing watchdog.

use crate::controller::{ClockFn, system_clock_secs};
use crate::fencing::{CsiVolumeKind, sha256_hex, verify_volume_fence};
use crate::fuse_cowfs::{
    FuseControlCmd, FuseCowFsSession, mount_via_fusermount3, serve_fuse_fd_with_control,
    unmount_via_fusermount3,
};
use crate::spec::*;
use crate::{CSI_DRIVER_NAME, CSI_DRIVER_VERSION};
use abi::Errno;
use abi::cluster_state::ClusterCall;
use abi::fs::{FileType, OpenOptions, Timespec, WriteAt};
use cowtree::{VolumeId, WriterMode};
use os_cluster_state::{ClusterGrant, ClusterStore};
use os_cowfs::native_sqlite::{NativePackStore, NativeSqliteHeadStore};
use os_cowfs::{CowFs, CowFsConfig, CowFsOpenMode, RawBlockOpenMode};
use os_nbd::{NbdExportConfig, NbdServerHandle, bind_unix_socket_0600, ensure_private_runtime_dir};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::{CStr, CString};
use std::io::Write as _;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot, watch};
use vfs::{Cred, Filesystem};

static TMP_FILE_SEQ: AtomicU64 = AtomicU64::new(1);

fn atomic_write_0600(final_path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = final_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let stem = final_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("state");
    let seq = TMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp_path = parent.join(format!(".{stem}.tmp.{}.{seq}", std::process::id()));
    let write_res = (|| -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)?;
        f.write_all(bytes)?;
        f.flush()?;
        drop(f);
        std::fs::rename(&tmp_path, final_path)?;
        Ok(())
    })();
    if write_res.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    write_res
}

const BTRFS_SUPER_MAGIC: i64 = 0x9123_683e;
const ZFS_SUPER_MAGIC: i64 = 0x2fc1_2fc1;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageMode {
    #[default]
    Auto,
    Fuse,
    HostSubvol,
}

impl StageMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "auto" => Some(Self::Auto),
            "fuse" => Some(Self::Fuse),
            "host-subvol" | "host_subvol" => Some(Self::HostSubvol),
            _ => None,
        }
    }
}

/// Live CSI publish-lease fencing state file stored in `$NODE_STATE/fences/<hash>.json` (`0600`).
/// Updated atomically by `OsCsiNode` whenever a volume is staged, fenced by `ClusterState`
/// keepalive/failover, or unstaged so external processes (`containerd-shim-os-v1`) immediately
/// observe CSI fencing transitions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FenceStateFile {
    pub volume_id: String,
    pub fence_epoch: u64,
    pub lease_id: u64,
    pub node_id: String,
    pub fenced: bool,
}

pub fn write_fence_state_file(path: &Path, state: &FenceStateFile) -> CsiResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| CsiError::internal(format!("create fence dir: {e}")))?;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }
    let bytes = serde_json::to_vec(state)
        .map_err(|e| CsiError::internal(format!("serialize fence state: {e}")))?;
    atomic_write_0600(path, &bytes)
        .map_err(|e| CsiError::internal(format!("write fence state: {e}")))?;
    Ok(())
}

/// Verify a CSI `FenceStateFile` on disk matches the expected `(fence_epoch, lease_id)` and is
/// not fenced. Returns `Err(Errno::ESTALE)` if missing, symlinked, fenced, or epoch/lease shifted.
pub fn check_fence_state_file(
    path: &Path,
    expected_epoch: u64,
    expected_lease_id: u64,
) -> Result<(), Errno> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| Errno::ESTALE)?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err(Errno::ESTALE);
    }
    let bytes = std::fs::read(path).map_err(|_| Errno::ESTALE)?;
    let state: FenceStateFile = serde_json::from_slice(&bytes).map_err(|_| Errno::ESTALE)?;
    if state.fenced || state.fence_epoch != expected_epoch || state.lease_id != expected_lease_id {
        return Err(Errno::ESTALE);
    }
    Ok(())
}

/// Published volume descriptor stored strictly in `$NODE_STATE/published/<hash>.json` (NEVER in
/// the user volume root) so `containerd-shim-os-v1` and node diagnostics can locate the live
/// fenced backing volume or NBD socket without polluting guest filesystem contents.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedVolumeDescriptor {
    pub volume_id: String,
    pub volume_kind: CsiVolumeKind,
    pub store_dir: PathBuf,
    pub staging_target_path: PathBuf,
    pub target_path: PathBuf,
    pub readonly: bool,
    pub fence_epoch: u64,
    pub lease_id: u64,
    pub node_id: String,
    pub block_size: u32,
    pub capacity_bytes: u64,
    pub stage_backend: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbd_socket: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fence_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handoff_socket: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock_file: Option<PathBuf>,
}

/// Look up a CSI published volume descriptor from `$NODE_STATE/published/` by target path.
pub fn load_published_descriptor(
    node_state_dir: &Path,
    target_path: &Path,
) -> Option<PublishedVolumeDescriptor> {
    let key = sha256_hex(&target_path.to_string_lossy());
    let path = node_state_dir.join("published").join(format!("{key}.json"));
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Configuration for [`OsCsiNode`].
#[derive(Clone)]
pub struct CsiNodeConfig {
    pub node_id: String,
    pub tenant: String,
    pub grant: ClusterGrant,
    pub state_dir: PathBuf,
    pub default_store_dir: PathBuf,
    pub allowed_mount_root: Option<PathBuf>,
    pub stage_mode: StageMode,
    pub max_volumes_per_node: i64,
    pub clock: ClockFn,
    pub keepalive_interval_override: Option<Duration>,
}

impl CsiNodeConfig {
    pub fn new(
        node_id: impl Into<String>,
        tenant: impl Into<String>,
        grant: ClusterGrant,
        state_dir: PathBuf,
        default_store_dir: PathBuf,
    ) -> Self {
        Self {
            node_id: node_id.into(),
            tenant: tenant.into(),
            grant,
            state_dir,
            default_store_dir,
            allowed_mount_root: None,
            stage_mode: StageMode::Auto,
            max_volumes_per_node: 64,
            clock: system_clock_secs(),
            keepalive_interval_override: None,
        }
    }
}

/// Validate a CSI staging/target path: must be absolute, contain no NUL or `..`, have no symlink
/// components along its existing prefix, and stay confined within `allowed_root` if configured.
pub fn validate_node_path(raw: &str, allowed_root: Option<&Path>) -> CsiResult<PathBuf> {
    if raw.is_empty() || raw.contains('\0') {
        return Err(CsiError::invalid_argument("empty or NUL mount path"));
    }
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return Err(CsiError::invalid_argument(format!(
            "mount path must be absolute: {raw}"
        )));
    }
    for comp in path.components() {
        if matches!(comp, Component::ParentDir) {
            return Err(CsiError::invalid_argument(format!(
                "mount path must not contain '..': {raw}"
            )));
        }
    }
    // Verify no existing ancestor or final component is a symlink.
    let mut cur = PathBuf::new();
    for comp in path.components() {
        cur.push(comp);
        if matches!(comp, Component::RootDir) {
            continue;
        }
        if let Ok(meta) = std::fs::symlink_metadata(&cur)
            && meta.file_type().is_symlink()
        {
            return Err(CsiError::permission_denied(format!(
                "refusing symlink component in mount path: {}",
                cur.display()
            )));
        }
    }
    if let Some(root) = allowed_root
        && !path.starts_with(root)
    {
        return Err(CsiError::permission_denied(format!(
            "mount path {} escapes allowed root {}",
            path.display(),
            root.display()
        )));
    }
    Ok(path)
}

fn detect_host_subvol_backend(path: &Path) -> &'static str {
    let Ok(cpath) = CString::new(path.to_string_lossy().as_bytes()) else {
        return "host_subvol_dir";
    };
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(cpath.as_ptr(), &mut st) } == 0 {
        let magic = st.f_type as i64;
        if magic == BTRFS_SUPER_MAGIC {
            return "host_subvol_btrfs";
        }
        if magic == ZFS_SUPER_MAGIC {
            return "host_subvol_zfs";
        }
    }
    "host_subvol_dir"
}

// ---------------------------------------------------------------------------
// Live fenced CowFs actor (for HostSubvol & direct node-staged FS operations)
// ---------------------------------------------------------------------------

enum CowFsActorCmd {
    WriteFile {
        rel_path: String,
        bytes: Vec<u8>,
        flush: bool,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    ReadFile {
        rel_path: String,
        reply: oneshot::Sender<Result<Vec<u8>, Errno>>,
    },
    ProjectToDir {
        dir: PathBuf,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    SyncFromDir {
        dir: PathBuf,
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    Flush {
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    Stats {
        reply: oneshot::Sender<Result<(u64, u64, u64), Errno>>,
    },
    HandoffAcquire {
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    HandoffRelease {
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    CloseClean {
        reply: oneshot::Sender<Result<(), Errno>>,
    },
}

struct CowFsActorHandle {
    tx: mpsc::UnboundedSender<CowFsActorCmd>,
    handoff_socket: Option<PathBuf>,
    _fence_flag: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl CowFsActorHandle {
    #[allow(clippy::too_many_arguments)]
    fn start(
        store_dir: PathBuf,
        volume_id: VolumeId,
        readonly: bool,
        writer_mode: WriterMode,
        fence_flag: Arc<AtomicBool>,
        fence_file: PathBuf,
        fence_state_base: FenceStateFile,
        handoff_socket: Option<PathBuf>,
        clock: ClockFn,
    ) -> CsiResult<Self> {
        let (tx, mut rx) = mpsc::unbounded_channel::<CowFsActorCmd>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), Errno>>();
        let actor_fence = Arc::clone(&fence_flag);
        let ho_sock_for_actor = handoff_socket.clone();
        let tx_for_handoff = tx.clone();

        let thread = std::thread::Builder::new()
            .name(format!(
                "os-csi-fs-{}",
                volume_id.0.chars().take(12).collect::<String>()
            ))
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
                    let clk_for_reopen = Arc::clone(&clock);
                    let open_cowfs = |wm: WriterMode| {
                        let store_dir = store_dir.clone();
                        let volume_id = volume_id.clone();
                        let clk_fn = Arc::clone(&clk_for_reopen);
                        async move {
                            let hs = Rc::new(NativeSqliteHeadStore::open(&store_dir)?);
                            let ps = Rc::new(NativePackStore::open(&store_dir)?);
                            let clk: os_cowfs::CowFsClock = Rc::new(move || Timespec {
                                sec: (clk_fn)(),
                                nsec: 0,
                            });
                            let mode = if readonly {
                                CowFsOpenMode::ReadOnly
                            } else {
                                CowFsOpenMode::ReadWrite(wm)
                            };
                            let fs = CowFs::open(hs, ps, volume_id, mode, CowFsConfig::remote(clk))
                                .await?;
                            Ok::<_, Errno>(Rc::new(fs))
                        }
                    };

                    let mut fs_opt: Option<Rc<CowFs<NativeSqliteHeadStore, NativePackStore>>> =
                        match open_cowfs(writer_mode).await {
                            Ok(fs) => Some(fs),
                            Err(e) => {
                                let _ = ready_tx.send(Err(e));
                                return;
                            }
                        };

                    let (ho_stop_tx, mut ho_stop_rx) = watch::channel(false);
                    if let Some(sock_path) = ho_sock_for_actor.clone() {
                        match bind_unix_socket_0600(&sock_path) {
                            Ok(listener) => {
                                let cmd_tx = tx_for_handoff.clone();
                                tokio::task::spawn_local(async move {
                                    loop {
                                        tokio::select! {
                                            changed = ho_stop_rx.changed() => {
                                                if changed.is_err() || *ho_stop_rx.borrow() {
                                                    break;
                                                }
                                            }
                                            acc = listener.accept() => {
                                                let Ok((stream, _)) = acc else {
                                                    break;
                                                };
                                                let c_tx = cmd_tx.clone();
                                                tokio::task::spawn_local(async move {
                                                    let (r, mut w) = stream.into_split();
                                                    let mut br = BufReader::new(r.take(64));
                                                    let mut line = String::new();
                                                    if br.read_line(&mut line).await.is_ok() {
                                                        let trimmed = line.trim();
                                                        let (rep_tx, rep_rx) = oneshot::channel();
                                                        let cmd = match trimmed {
                                                            "ACQUIRE" => Some(CowFsActorCmd::HandoffAcquire { reply: rep_tx }),
                                                            "RELEASE" => Some(CowFsActorCmd::HandoffRelease { reply: rep_tx }),
                                                            _ => None,
                                                        };
                                                        let resp = if let Some(c) = cmd {
                                                            if c_tx.send(c).is_ok() {
                                                                match rep_rx.await {
                                                                    Ok(Ok(())) => "OK\n",
                                                                    Ok(Err(Errno::ESTALE)) => "ESTALE\n",
                                                                    Ok(Err(Errno::EBUSY)) => "EBUSY\n",
                                                                    _ => "ERR\n",
                                                                }
                                                            } else {
                                                                "ERR\n"
                                                            }
                                                        } else {
                                                            "EINVAL\n"
                                                        };
                                                        let _ = w.write_all(resp.as_bytes()).await;
                                                        let _ = w.flush().await;
                                                    }
                                                });
                                            }
                                        }
                                    }
                                });
                            }
                            Err(_) => {
                                if let Some(fs) = fs_opt.take() {
                                    let _ = fs.close_clean().await;
                                }
                                let _ = ready_tx.send(Err(Errno::EIO));
                                return;
                            }
                        }
                    }

                    let _ = ready_tx.send(Ok(()));

                    let trip_fence = || {
                        actor_fence.store(true, Ordering::SeqCst);
                        let mut st = fence_state_base.clone();
                        st.fenced = true;
                        let _ = write_fence_state_file(&fence_file, &st);
                    };

                    let mut handed_off = false;
                    while let Some(cmd) = rx.recv().await {
                        match cmd {
                            CowFsActorCmd::WriteFile {
                                rel_path,
                                bytes,
                                flush,
                                reply,
                            } => {
                                let res = if readonly {
                                    Err(Errno::EROFS)
                                } else if actor_fence.load(Ordering::SeqCst) {
                                    Err(Errno::ESTALE)
                                } else if let Some(ref fs) = fs_opt {
                                    let res = match write_cowfs_rel_file(fs, &rel_path, &bytes)
                                        .await
                                    {
                                        Ok(()) if flush => fs.commit_tx_group().await.map(|_| ()),
                                        other => other,
                                    };
                                    if res == Err(Errno::ESTALE) {
                                        trip_fence();
                                    }
                                    res
                                } else {
                                    Err(Errno::EBUSY)
                                };
                                let _ = reply.send(res);
                            }
                            CowFsActorCmd::ReadFile { rel_path, reply } => {
                                let res = if let Some(ref fs) = fs_opt {
                                    read_cowfs_rel_file(fs, &rel_path).await
                                } else {
                                    Err(Errno::EBUSY)
                                };
                                let _ = reply.send(res);
                            }
                            CowFsActorCmd::ProjectToDir { dir, reply } => {
                                let res = if let Some(ref fs) = fs_opt {
                                    project_cowfs_to_host_dir(fs, &dir).await
                                } else {
                                    Ok(())
                                };
                                let _ = reply.send(res);
                            }
                            CowFsActorCmd::SyncFromDir { dir, reply } => {
                                let res = if readonly {
                                    Err(Errno::EROFS)
                                } else if actor_fence.load(Ordering::SeqCst) {
                                    Err(Errno::ESTALE)
                                } else if handed_off {
                                    // Container exclusively owns CowFs writes during handoff.
                                    Ok(())
                                } else if let Some(ref fs) = fs_opt {
                                    let res = match sync_host_dir_into_cowfs(fs, &dir).await {
                                        Ok(()) => fs.commit_tx_group().await.map(|_| ()),
                                        Err(e) => Err(e),
                                    };
                                    if res == Err(Errno::ESTALE) {
                                        trip_fence();
                                    }
                                    res
                                } else {
                                    Err(Errno::EBUSY)
                                };
                                let _ = reply.send(res);
                            }
                            CowFsActorCmd::Flush { reply } => {
                                let res = if readonly {
                                    Ok(())
                                } else if actor_fence.load(Ordering::SeqCst) {
                                    Err(Errno::ESTALE)
                                } else if handed_off {
                                    Ok(())
                                } else if let Some(ref fs) = fs_opt {
                                    let cr = fs.commit_tx_group().await.map(|_| ());
                                    if cr == Err(Errno::ESTALE) {
                                        trip_fence();
                                    }
                                    cr
                                } else {
                                    Err(Errno::EBUSY)
                                };
                                let _ = reply.send(res);
                            }
                            CowFsActorCmd::Stats { reply } => {
                                let res = if let Some(ref fs) = fs_opt {
                                    fs.statfs(&Cred::root()).await.map(|st| {
                                        let bsz = st.block_size;
                                        let total = st.blocks.saturating_mul(bsz);
                                        let avail = st.blocks_free.saturating_mul(bsz);
                                        let used = total.saturating_sub(avail);
                                        (total, used, avail)
                                    })
                                } else {
                                    Err(Errno::EBUSY)
                                };
                                let _ = reply.send(res);
                            }
                            CowFsActorCmd::HandoffAcquire { reply } => {
                                let res = if readonly {
                                    Err(Errno::EROFS)
                                } else if actor_fence.load(Ordering::SeqCst) {
                                    Err(Errno::ESTALE)
                                } else if handed_off {
                                    Err(Errno::EBUSY)
                                } else if let Some(ref fs) = fs_opt {
                                    let r1 = fs.renew_lease().await;
                                    let r2 = if r1.is_ok() {
                                        fs.commit_tx_group().await.map(|_| ())
                                    } else {
                                        r1
                                    };
                                    if r2 == Err(Errno::ESTALE) {
                                        trip_fence();
                                        if let Some(fs_owned) = fs_opt.take() {
                                            let _ = fs_owned.close_clean().await;
                                        }
                                        Err(Errno::ESTALE)
                                    } else if let Err(e) = r2 {
                                        // Keep `fs_opt` intact on transient errors so the actor
                                        // is never wedged! (P2-3)
                                        Err(e)
                                    } else {
                                        if let Some(fs_owned) = fs_opt.take() {
                                            let _ = fs_owned.close_clean().await;
                                        }
                                        handed_off = true;
                                        Ok(())
                                    }
                                } else {
                                    Err(Errno::EBUSY)
                                };
                                let _ = reply.send(res);
                            }
                            CowFsActorCmd::HandoffRelease { reply } => {
                                if handed_off {
                                    handed_off = false;
                                    if !actor_fence.load(Ordering::SeqCst) {
                                        match open_cowfs(WriterMode::Exclusive).await {
                                            Ok(fs) => fs_opt = Some(fs),
                                            Err(Errno::ESTALE) => trip_fence(),
                                            Err(_) => {}
                                        }
                                    }
                                }
                                let _ = reply.send(Ok(()));
                            }
                            CowFsActorCmd::CloseClean { reply } => {
                                let _ = ho_stop_tx.send(true);
                                let res = if let Some(fs) = fs_opt.take() {
                                    if !readonly && !actor_fence.load(Ordering::SeqCst) {
                                        let r = fs.commit_tx_group().await.map(|_| ());
                                        let c = fs.close_clean().await;
                                        if r == Err(Errno::ESTALE) {
                                            trip_fence();
                                            Err(Errno::ESTALE)
                                        } else {
                                            c
                                        }
                                    } else {
                                        let _ = fs.close_clean().await;
                                        if actor_fence.load(Ordering::SeqCst) {
                                            Err(Errno::ESTALE)
                                        } else {
                                            Ok(())
                                        }
                                    }
                                } else {
                                    Ok(())
                                };
                                let _ = reply.send(res);
                                break;
                            }
                        }
                    }
                    if let Some(ref p) = ho_sock_for_actor {
                        let _ = std::fs::remove_file(p);
                    }
                });
            })
            .map_err(|e| CsiError::internal(format!("spawn cowfs actor: {e}")))?;

        ready_rx
            .recv()
            .map_err(|_| CsiError::internal("cowfs actor exited during open"))?
            .map_err(|e| {
                CsiError::failed_precondition(format!("open cowfs volume failed: {e:?}"))
            })?;

        Ok(Self {
            tx,
            handoff_socket,
            _fence_flag: fence_flag,
            thread: Some(thread),
        })
    }

    async fn write_file(&self, rel_path: String, bytes: Vec<u8>, flush: bool) -> Result<(), Errno> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(CowFsActorCmd::WriteFile {
                rel_path,
                bytes,
                flush,
                reply,
            })
            .map_err(|_| Errno::EIO)?;
        rx.await.map_err(|_| Errno::EIO)?
    }

    async fn read_file(&self, rel_path: String) -> Result<Vec<u8>, Errno> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(CowFsActorCmd::ReadFile { rel_path, reply })
            .map_err(|_| Errno::EIO)?;
        rx.await.map_err(|_| Errno::EIO)?
    }

    async fn project_to_dir(&self, dir: PathBuf) -> Result<(), Errno> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(CowFsActorCmd::ProjectToDir { dir, reply })
            .map_err(|_| Errno::EIO)?;
        rx.await.map_err(|_| Errno::EIO)?
    }

    async fn sync_from_dir(&self, dir: PathBuf) -> Result<(), Errno> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(CowFsActorCmd::SyncFromDir { dir, reply })
            .map_err(|_| Errno::EIO)?;
        rx.await.map_err(|_| Errno::EIO)?
    }

    async fn flush(&self) -> Result<(), Errno> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(CowFsActorCmd::Flush { reply })
            .map_err(|_| Errno::EIO)?;
        rx.await.map_err(|_| Errno::EIO)?
    }

    async fn stats(&self) -> Result<(u64, u64, u64), Errno> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(CowFsActorCmd::Stats { reply })
            .map_err(|_| Errno::EIO)?;
        rx.await.map_err(|_| Errno::EIO)?
    }

    async fn close_clean(&mut self) -> Result<(), Errno> {
        let (reply, rx) = oneshot::channel();
        let res = if self.tx.send(CowFsActorCmd::CloseClean { reply }).is_ok() {
            rx.await.unwrap_or(Ok(()))
        } else {
            Ok(())
        };
        if let Some(th) = self.thread.take() {
            let _ = th.join();
        }
        if let Some(ref p) = self.handoff_socket {
            let _ = std::fs::remove_file(p);
        }
        res
    }

    fn shutdown(&mut self) {
        let (reply, _rx) = oneshot::channel();
        let _ = self.tx.send(CowFsActorCmd::CloseClean { reply });
        if let Some(th) = self.thread.take() {
            let _ = th.join();
        }
        if let Some(ref p) = self.handoff_socket {
            let _ = std::fs::remove_file(p);
        }
    }
}

impl Drop for CowFsActorHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

async fn write_cowfs_rel_file(
    fs: &CowFs<NativeSqliteHeadStore, NativePackStore>,
    rel_path: &str,
    bytes: &[u8],
) -> Result<(), Errno> {
    let mut root_cred = Cred::root();
    root_cred.umask = 0;
    let parts: Vec<&str> = rel_path.split('/').filter(|p| !p.is_empty()).collect();
    if parts.is_empty() || parts.iter().any(|&p| p == "." || p == "..") {
        return Err(Errno::EINVAL);
    }
    let mut dir_h = fs.root();
    for seg in &parts[..parts.len() - 1] {
        dir_h = match fs.lookup(&root_cred, &dir_h, seg).await {
            Ok(e) => e.handle,
            Err(Errno::ENOENT) => fs.mkdir(&root_cred, &dir_h, seg, 0o755).await?.handle,
            Err(e) => return Err(e),
        };
    }
    let fname = parts[parts.len() - 1];
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    let open = match fs.lookup(&root_cred, &dir_h, fname).await {
        Ok(ent) => {
            let o = fs.open(&root_cred, &ent.handle, &opts).await?;
            fs.set_len(&o, 0).await?;
            o
        }
        Err(Errno::ENOENT) => fs.create(&root_cred, &dir_h, fname, 0o644, &opts).await?.1,
        Err(e) => return Err(e),
    };
    let mut off = 0u64;
    while (off as usize) < bytes.len() {
        let w = fs
            .write_at(&open, &bytes[off as usize..], WriteAt::Offset(off))
            .await?;
        if w.len == 0 {
            let _ = fs.release(&open).await;
            return Err(Errno::EIO);
        }
        off += w.len as u64;
    }
    fs.release(&open).await
}

async fn read_cowfs_rel_file(
    fs: &CowFs<NativeSqliteHeadStore, NativePackStore>,
    rel_path: &str,
) -> Result<Vec<u8>, Errno> {
    let root_cred = Cred::root();
    let parts: Vec<&str> = rel_path.split('/').filter(|p| !p.is_empty()).collect();
    if parts.is_empty() || parts.iter().any(|&p| p == "." || p == "..") {
        return Err(Errno::EINVAL);
    }
    let mut cur_h = fs.root();
    for seg in parts {
        cur_h = fs.lookup(&root_cred, &cur_h, seg).await?.handle;
    }
    let mut opts = OpenOptions::new();
    opts.read(true);
    let open = fs.open(&root_cred, &cur_h, &opts).await?;
    let mut out = Vec::new();
    let mut off = 0u64;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = fs.read_at(&open, &mut buf, off).await?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
        off += n as u64;
    }
    let _ = fs.release(&open).await;
    Ok(out)
}

async fn project_cowfs_to_host_dir(
    fs: &CowFs<NativeSqliteHeadStore, NativePackStore>,
    host_dir: &Path,
) -> Result<(), Errno> {
    std::fs::create_dir_all(host_dir).map_err(|_| Errno::EIO)?;
    let root_cred = Cred::root();
    let mut stack = vec![(fs.root(), host_dir.to_path_buf())];
    while let Some((dir_h, host_p)) = stack.pop() {
        let entries = fs.read_dir(&root_cred, &dir_h).await?;
        for ent in entries {
            if ent.name == "." || ent.name == ".." {
                continue;
            }
            let child = fs.lookup(&root_cred, &dir_h, &ent.name).await?;
            let dst = host_p.join(&ent.name);
            match child.metadata.file_type {
                FileType::Dir => {
                    std::fs::create_dir_all(&dst).map_err(|_| Errno::EIO)?;
                    stack.push((child.handle, dst));
                }
                FileType::File => {
                    let mut opts = OpenOptions::new();
                    opts.read(true);
                    let open = fs.open(&root_cred, &child.handle, &opts).await?;
                    let mut data = Vec::new();
                    let mut off = 0u64;
                    let mut buf = vec![0u8; 64 * 1024];
                    loop {
                        let n = fs.read_at(&open, &mut buf, off).await?;
                        if n == 0 {
                            break;
                        }
                        data.extend_from_slice(&buf[..n]);
                        off += n as u64;
                    }
                    let _ = fs.release(&open).await;
                    std::fs::write(&dst, &data).map_err(|_| Errno::EIO)?;
                }
                _ => {}
            }
        }
    }
    Ok(())
}

const MAX_HOST_SYNC_FILES: usize = 10_000;
const MAX_HOST_SYNC_BYTES: u64 = 64 * 1024 * 1024;
const MAX_HOST_SYNC_DEPTH: usize = 64;

struct HostOwnedFd(libc::c_int);
impl Drop for HostOwnedFd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            unsafe {
                libc::close(self.0);
            }
        }
    }
}

fn list_dir_cnames(dir_fd: libc::c_int) -> Result<Vec<CString>, Errno> {
    let dup = unsafe { libc::fcntl(dir_fd, libc::F_DUPFD_CLOEXEC, 0) };
    if dup < 0 {
        return Err(Errno::EIO);
    }
    let dirp = unsafe { libc::fdopendir(dup) };
    if dirp.is_null() {
        unsafe {
            libc::close(dup);
        }
        return Err(Errno::EIO);
    }
    let mut out = Vec::new();
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
        out.push(cstr.to_owned());
    }
    unsafe {
        libc::closedir(dirp);
    }
    Ok(out)
}

fn read_bounded_fd(fd: libc::c_int, total_bytes: &mut u64) -> Result<Vec<u8>, Errno> {
    let mut out = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Errno::EIO);
        }
        if n == 0 {
            break;
        }
        let got = n as usize;
        *total_bytes = total_bytes.checked_add(got as u64).ok_or(Errno::EFBIG)?;
        if *total_bytes > MAX_HOST_SYNC_BYTES {
            return Err(Errno::EFBIG);
        }
        out.extend_from_slice(&buf[..got]);
    }
    Ok(out)
}

async fn sync_host_fd_into_cowfs(
    fs: &CowFs<NativeSqliteHeadStore, NativePackStore>,
    dir_fd: libc::c_int,
    dst_dir: &vfs::Handle,
    depth: usize,
    files_seen: &mut usize,
    bytes_seen: &mut u64,
) -> Result<(), Errno> {
    if depth > MAX_HOST_SYNC_DEPTH {
        return Err(Errno::ELOOP);
    }
    let mut root_cred = Cred::root();
    root_cred.umask = 0;

    let mut host_names = HashSet::new();
    for cname in list_dir_cnames(dir_fd)? {
        let Ok(name) = cname.to_str() else {
            continue;
        };
        if name.is_empty() || name.contains(['/', '\0']) {
            continue;
        }
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatat(dir_fd, cname.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0
        {
            return Err(Errno::EIO);
        }
        let ftype = st.st_mode & libc::S_IFMT;
        match ftype {
            libc::S_IFDIR => {
                *files_seen += 1;
                if *files_seen > MAX_HOST_SYNC_FILES {
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
                let child_fd = HostOwnedFd(child_fd);
                host_names.insert(name.to_string());
                let sub = match fs.lookup(&root_cred, dst_dir, name).await {
                    Ok(e) if e.metadata.file_type == FileType::Dir => e.handle,
                    Ok(_) => {
                        fs.unlink(&root_cred, dst_dir, name).await?;
                        fs.mkdir(&root_cred, dst_dir, name, 0o755).await?.handle
                    }
                    Err(Errno::ENOENT) => fs.mkdir(&root_cred, dst_dir, name, 0o755).await?.handle,
                    Err(e) => return Err(e),
                };
                Box::pin(sync_host_fd_into_cowfs(
                    fs,
                    child_fd.0,
                    &sub,
                    depth + 1,
                    files_seen,
                    bytes_seen,
                ))
                .await?;
            }
            libc::S_IFREG => {
                *files_seen += 1;
                if *files_seen > MAX_HOST_SYNC_FILES {
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
                let f_fd = HostOwnedFd(f_fd);
                let mut fst: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(f_fd.0, &mut fst) } != 0
                    || (fst.st_mode & libc::S_IFMT) != libc::S_IFREG
                {
                    return Err(Errno::EPERM);
                }
                let data = read_bounded_fd(f_fd.0, bytes_seen)?;
                host_names.insert(name.to_string());
                let mut opts = OpenOptions::new();
                opts.write(true).create(true).truncate(true);
                let open = match fs.lookup(&root_cred, dst_dir, name).await {
                    Ok(ent) => {
                        let o = fs.open(&root_cred, &ent.handle, &opts).await?;
                        fs.set_len(&o, 0).await?;
                        o
                    }
                    Err(Errno::ENOENT) => {
                        fs.create(&root_cred, dst_dir, name, 0o644, &opts).await?.1
                    }
                    Err(e) => return Err(e),
                };
                let mut off = 0u64;
                while (off as usize) < data.len() {
                    let w = fs
                        .write_at(&open, &data[off as usize..], WriteAt::Offset(off))
                        .await?;
                    if w.len == 0 {
                        let _ = fs.release(&open).await;
                        return Err(Errno::EIO);
                    }
                    off += w.len as u64;
                }
                fs.release(&open).await?;
            }
            // Skip symlinks and refuse special host files.
            libc::S_IFLNK => continue,
            _ => return Err(Errno::EPERM),
        }
    }

    // Reconcile deletions: remove entries present in CowFs that no longer exist in `host_dir`.
    let existing = fs.read_dir(&root_cred, dst_dir).await?;
    for ent in existing {
        if ent.name == "." || ent.name == ".." || host_names.contains(&ent.name) {
            continue;
        }
        if ent.file_type == FileType::Dir {
            if let Ok(child) = fs.lookup(&root_cred, dst_dir, &ent.name).await {
                Box::pin(remove_cowfs_subtree(fs, &child.handle)).await?;
            }
            let _ = fs.rmdir(&root_cred, dst_dir, &ent.name).await;
        } else {
            let _ = fs.unlink(&root_cred, dst_dir, &ent.name).await;
        }
    }
    Ok(())
}

async fn remove_cowfs_subtree(
    fs: &CowFs<NativeSqliteHeadStore, NativePackStore>,
    dir_h: &vfs::Handle,
) -> Result<(), Errno> {
    let root_cred = Cred::root();
    let entries = fs.read_dir(&root_cred, dir_h).await?;
    for ent in entries {
        if ent.name == "." || ent.name == ".." {
            continue;
        }
        if ent.file_type == FileType::Dir {
            if let Ok(child) = fs.lookup(&root_cred, dir_h, &ent.name).await {
                Box::pin(remove_cowfs_subtree(fs, &child.handle)).await?;
            }
            let _ = fs.rmdir(&root_cred, dir_h, &ent.name).await;
        } else {
            let _ = fs.unlink(&root_cred, dir_h, &ent.name).await;
        }
    }
    Ok(())
}

async fn sync_host_dir_into_cowfs(
    fs: &CowFs<NativeSqliteHeadStore, NativePackStore>,
    host_dir: &Path,
) -> Result<(), Errno> {
    if !host_dir.exists() {
        return Ok(());
    }
    let cpath = CString::new(host_dir.as_os_str().as_bytes()).map_err(|_| Errno::EINVAL)?;
    let root_fd = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return Err(Errno::EPERM);
    }
    let root_fd = HostOwnedFd(root_fd);
    let mut files_seen = 0usize;
    let mut bytes_seen = 0u64;
    let root_h = fs.root();
    sync_host_fd_into_cowfs(fs, root_fd.0, &root_h, 0, &mut files_seen, &mut bytes_seen).await
}

// ---------------------------------------------------------------------------
// Live FUSE3 background handle
// ---------------------------------------------------------------------------

struct FuseDaemonHandle {
    mountpoint: PathBuf,
    handoff_socket: Option<PathBuf>,
    ctrl_tx: mpsc::UnboundedSender<FuseControlCmd>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl FuseDaemonHandle {
    #[allow(clippy::too_many_arguments)]
    fn start(
        mountpoint: PathBuf,
        store_dir: PathBuf,
        volume_id: VolumeId,
        readonly: bool,
        writer_mode: WriterMode,
        fence_flag: Arc<AtomicBool>,
        fence_file: PathBuf,
        fence_state_base: FenceStateFile,
        handoff_socket: Option<PathBuf>,
        clock: ClockFn,
    ) -> std::io::Result<Self> {
        let fd = mount_via_fusermount3(&mountpoint, &volume_id.0, readonly)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop);
        let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel::<FuseControlCmd>();
        let ctrl_tx_for_handoff = ctrl_tx.clone();
        let ho_sock_for_thread = handoff_socket.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
        let thread = std::thread::Builder::new()
            .name(format!(
                "os-csi-fuse-{}",
                volume_id.0.chars().take(12).collect::<String>()
            ))
            .spawn(move || {
                let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    let _ = ready_tx.send(Err("tokio runtime init failed".into()));
                    return;
                };
                let local = tokio::task::LocalSet::new();
                local.block_on(&rt, async move {
                    let open_cowfs = |wm: WriterMode| {
                        let store_dir = store_dir.clone();
                        let volume_id = volume_id.clone();
                        let clk_fn = Arc::clone(&clock);
                        async move {
                            let hs = NativeSqliteHeadStore::open(&store_dir)?;
                            let ps = NativePackStore::open(&store_dir)?;
                            let clk: os_cowfs::CowFsClock = Rc::new(move || Timespec {
                                sec: (clk_fn)(),
                                nsec: 0,
                            });
                            let mode = if readonly {
                                CowFsOpenMode::ReadOnly
                            } else {
                                CowFsOpenMode::ReadWrite(wm)
                            };
                            let fs = CowFs::open(
                                Rc::new(hs),
                                Rc::new(ps),
                                volume_id,
                                mode,
                                CowFsConfig::remote(clk),
                            )
                            .await?;
                            Ok::<_, Errno>(Rc::new(fs))
                        }
                    };

                    let fs = match open_cowfs(writer_mode).await {
                        Ok(fs) => fs,
                        Err(e) => {
                            let _ =
                                ready_tx.send(Err(format!("open cowfs for FUSE failed: {e:?}")));
                            return;
                        }
                    };

                    let (ho_stop_tx, mut ho_stop_rx) = watch::channel(false);
                    if let Some(sock_path) = ho_sock_for_thread.clone() {
                        match bind_unix_socket_0600(&sock_path) {
                            Ok(listener) => {
                                let c_tx = ctrl_tx_for_handoff.clone();
                                tokio::task::spawn_local(async move {
                                    loop {
                                        tokio::select! {
                                            changed = ho_stop_rx.changed() => {
                                                if changed.is_err() || *ho_stop_rx.borrow() {
                                                    break;
                                                }
                                            }
                                            acc = listener.accept() => {
                                                let Ok((stream, _)) = acc else {
                                                    break;
                                                };
                                                let c_tx2 = c_tx.clone();
                                                tokio::task::spawn_local(async move {
                                                    let (r, mut w) = stream.into_split();
                                                    let mut br = BufReader::new(r.take(64));
                                                    let mut line = String::new();
                                                    if br.read_line(&mut line).await.is_ok() {
                                                        let (rep_tx, rep_rx) = oneshot::channel();
                                                        let cmd = match line.trim() {
                                                            "ACQUIRE" => Some(FuseControlCmd::HandoffAcquire { reply: rep_tx }),
                                                            "RELEASE" => Some(FuseControlCmd::HandoffRelease { reply: rep_tx }),
                                                            _ => None,
                                                        };
                                                        let resp = if let Some(c) = cmd {
                                                            if c_tx2.send(c).is_ok() {
                                                                match rep_rx.await {
                                                                    Ok(Ok(())) => "OK\n",
                                                                    Ok(Err(Errno::ESTALE)) => "ESTALE\n",
                                                                    Ok(Err(Errno::EBUSY)) => "EBUSY\n",
                                                                    Ok(Err(Errno::EROFS)) => "EROFS\n",
                                                                    _ => "ERR\n",
                                                                }
                                                            } else {
                                                                "ERR\n"
                                                            }
                                                        } else {
                                                            "EINVAL\n"
                                                        };
                                                        let _ = w.write_all(resp.as_bytes()).await;
                                                        let _ = w.flush().await;
                                                    }
                                                });
                                            }
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                let _ = fs.close_clean().await;
                                let _ = ready_tx
                                    .send(Err(format!("bind FUSE handoff socket failed: {e}")));
                                return;
                            }
                        }
                    }

                    let _ = ready_tx.send(Ok(()));
                    let ff = fence_file.clone();
                    let fsb = fence_state_base.clone();
                    let session = FuseCowFsSession::new(fs, fence_flag).with_on_fenced(Arc::new(
                        move || {
                            let mut st = fsb.clone();
                            st.fenced = true;
                            let _ = write_fence_state_file(&ff, &st);
                        },
                    ));
                    let _ = serve_fuse_fd_with_control(
                        fd,
                        session,
                        stop_clone,
                        ctrl_rx,
                        || open_cowfs(WriterMode::Exclusive),
                    )
                    .await;
                    let _ = ho_stop_tx.send(true);
                    if let Some(ref p) = ho_sock_for_thread {
                        let _ = std::fs::remove_file(p);
                    }
                });
            })?;
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                mountpoint,
                handoff_socket,
                ctrl_tx,
                stop,
                thread: Some(thread),
            }),
            Ok(Err(e)) => {
                stop.store(true, Ordering::SeqCst);
                let _ = unmount_via_fusermount3(&mountpoint);
                let _ = thread.join();
                Err(std::io::Error::other(e))
            }
            Err(_) => {
                stop.store(true, Ordering::SeqCst);
                let _ = unmount_via_fusermount3(&mountpoint);
                let _ = thread.join();
                Err(std::io::Error::other("FUSE daemon exited during startup"))
            }
        }
    }

    async fn shutdown_checked(&mut self) -> Result<(), Errno> {
        let (reply, rx) = oneshot::channel();
        let res = if self
            .ctrl_tx
            .send(FuseControlCmd::Shutdown { reply })
            .is_ok()
        {
            rx.await.unwrap_or(Ok(()))
        } else {
            Ok(())
        };
        self.stop.store(true, Ordering::SeqCst);
        let _ = unmount_via_fusermount3(&self.mountpoint);
        if let Some(th) = self.thread.take() {
            let _ = th.join();
        }
        if let Some(ref p) = self.handoff_socket {
            let _ = std::fs::remove_file(p);
        }
        res
    }

    fn shutdown(&mut self) {
        let (reply, _rx) = oneshot::channel();
        let _ = self.ctrl_tx.send(FuseControlCmd::Shutdown { reply });
        self.stop.store(true, Ordering::SeqCst);
        let _ = unmount_via_fusermount3(&self.mountpoint);
        if let Some(th) = self.thread.take() {
            let _ = th.join();
        }
        if let Some(ref p) = self.handoff_socket {
            let _ = std::fs::remove_file(p);
        }
    }
}

impl Drop for FuseDaemonHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

// ---------------------------------------------------------------------------
// Staged Volume Runtime State & Watchdog
// ---------------------------------------------------------------------------

enum StagedBackend {
    Fuse(FuseDaemonHandle),
    HostSubvol {
        actor: Arc<tokio::sync::Mutex<CowFsActorHandle>>,
        backend_label: &'static str,
    },
    NbdBlock(NbdServerHandle),
}

struct StagedVolume {
    volume_id: String,
    volume_kind: CsiVolumeKind,
    store_dir: PathBuf,
    staging_target_path: PathBuf,
    readonly: bool,
    fence_epoch: u64,
    lease_id: u64,
    block_size: u32,
    capacity_bytes: u64,
    fence_flag: Arc<AtomicBool>,
    fence_file: PathBuf,
    handoff_socket: Option<PathBuf>,
    lock_file: PathBuf,
    keepalive_stop: watch::Sender<bool>,
    keepalive_task: Option<tokio::task::JoinHandle<()>>,
    backend: StagedBackend,
}

impl StagedVolume {
    fn stage_backend_name(&self) -> String {
        match &self.backend {
            StagedBackend::Fuse(_) => "fuse3".into(),
            StagedBackend::HostSubvol { backend_label, .. } => (*backend_label).into(),
            StagedBackend::NbdBlock(_) => "nbd_unix".into(),
        }
    }

    fn nbd_socket(&self) -> Option<PathBuf> {
        match &self.backend {
            StagedBackend::NbdBlock(h) => Some(h.socket_path().to_path_buf()),
            _ => None,
        }
    }

    fn stop_all(&mut self) {
        let _ = self.keepalive_stop.send(true);
        if let Some(t) = self.keepalive_task.take() {
            t.abort();
        }
        match &mut self.backend {
            StagedBackend::Fuse(f) => f.shutdown(),
            StagedBackend::HostSubvol { .. } => {}
            StagedBackend::NbdBlock(nbd) => nbd.shutdown_blocking(),
        }
        if let Some(ref p) = self.handoff_socket
            && std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_socket())
        {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// CSI v1.9 Node plugin generic over `ClusterStore`.
pub struct OsCsiNode<C: ClusterStore + Send + Sync + 'static> {
    store: Arc<C>,
    cfg: CsiNodeConfig,
    staged: Mutex<HashMap<String, StagedVolume>>,
    published: Mutex<HashMap<PathBuf, PublishedVolumeDescriptor>>,
}

impl<C: ClusterStore + Send + Sync + 'static> OsCsiNode<C> {
    pub fn new(store: Arc<C>, cfg: CsiNodeConfig) -> Self {
        for sub in ["nbd", "published", "fences", "handoff", "locks"] {
            let p = cfg.state_dir.join(sub);
            let _ = std::fs::create_dir_all(&p);
            let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700));
        }
        Self {
            store,
            cfg,
            staged: Mutex::new(HashMap::new()),
            published: Mutex::new(HashMap::new()),
        }
    }

    pub fn state_dir(&self) -> &Path {
        &self.cfg.state_dir
    }

    pub fn nbd_socket_for_volume(&self, volume_id: &str) -> Option<PathBuf> {
        self.staged
            .lock()
            .unwrap()
            .get(volume_id)
            .and_then(StagedVolume::nbd_socket)
    }

    pub fn is_volume_fenced(&self, volume_id: &str) -> bool {
        self.staged
            .lock()
            .unwrap()
            .get(volume_id)
            .is_some_and(|s| s.fence_flag.load(Ordering::SeqCst))
    }

    /// Directly exercise a staged `HostSubvol` volume's live fenced `CowFs` actor: write + commit.
    pub async fn write_staged_file(
        &self,
        volume_id: &str,
        rel_path: &str,
        bytes: &[u8],
        flush: bool,
    ) -> Result<(), Errno> {
        let actor = {
            let guard = self.staged.lock().unwrap();
            let staged = guard.get(volume_id).ok_or(Errno::ENOENT)?;
            match &staged.backend {
                StagedBackend::HostSubvol { actor, .. } => Arc::clone(actor),
                _ => return Err(Errno::EINVAL),
            }
        };
        let a = actor.lock().await;
        a.write_file(rel_path.to_string(), bytes.to_vec(), flush)
            .await
    }

    /// Read a file from a staged `HostSubvol` volume's live `CowFs` actor.
    pub async fn read_staged_file(
        &self,
        volume_id: &str,
        rel_path: &str,
    ) -> Result<Vec<u8>, Errno> {
        let actor = {
            let guard = self.staged.lock().unwrap();
            let staged = guard.get(volume_id).ok_or(Errno::ENOENT)?;
            match &staged.backend {
                StagedBackend::HostSubvol { actor, .. } => Arc::clone(actor),
                _ => return Err(Errno::EINVAL),
            }
        };
        let a = actor.lock().await;
        a.read_file(rel_path.to_string()).await
    }

    /// Sync host directory changes at `staging_target_path` through the live fenced `CowFs` actor.
    pub async fn sync_staged_host_dir(&self, volume_id: &str) -> Result<(), Errno> {
        let (actor, dir) = {
            let guard = self.staged.lock().unwrap();
            let staged = guard.get(volume_id).ok_or(Errno::ENOENT)?;
            match &staged.backend {
                StagedBackend::HostSubvol { actor, .. } => {
                    (Arc::clone(actor), staged.staging_target_path.clone())
                }
                _ => return Err(Errno::EINVAL),
            }
        };
        let a = actor.lock().await;
        a.sync_from_dir(dir).await
    }

    /// Re-verify a staged volume's fencing lease against `ClusterState`; trips local sticky fence
    /// AND atomically marks the CSI fence state file fenced (`ESTALE`).
    pub async fn check_and_enforce_fence(&self, volume_id: &str) -> Result<(), Errno> {
        let (fence_epoch, lease_id, readonly, fence_flag, fence_file) = {
            let guard = self.staged.lock().unwrap();
            let staged = guard.get(volume_id).ok_or(Errno::ENOENT)?;
            (
                staged.fence_epoch,
                staged.lease_id,
                staged.readonly,
                Arc::clone(&staged.fence_flag),
                staged.fence_file.clone(),
            )
        };
        let now = (self.cfg.clock)();
        match verify_volume_fence(
            &*self.store,
            &self.cfg.grant,
            &self.cfg.tenant,
            volume_id,
            &self.cfg.node_id,
            fence_epoch,
            lease_id,
            readonly,
            now,
        )
        .await
        {
            Ok(_) => Ok(()),
            Err(_) => {
                fence_flag.store(true, Ordering::SeqCst);
                let _ = write_fence_state_file(
                    &fence_file,
                    &FenceStateFile {
                        volume_id: volume_id.to_string(),
                        fence_epoch,
                        lease_id,
                        node_id: self.cfg.node_id.clone(),
                        fenced: true,
                    },
                );
                Err(Errno::ESTALE)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_keepalive_watchdog(
        &self,
        volume_id: String,
        fence_epoch: u64,
        lease_id: u64,
        lease_ttl_secs: u64,
        readonly: bool,
        fence_flag: Arc<AtomicBool>,
        fence_file: PathBuf,
    ) -> (watch::Sender<bool>, tokio::task::JoinHandle<()>) {
        let (stop_tx, mut stop_rx) = watch::channel(false);
        let store = Arc::clone(&self.store);
        let grant = self.cfg.grant.clone();
        let tenant = self.cfg.tenant.clone();
        let node_id = self.cfg.node_id.clone();
        let clock = Arc::clone(&self.cfg.clock);
        let interval = self
            .cfg
            .keepalive_interval_override
            .unwrap_or_else(|| Duration::from_secs((lease_ttl_secs / 3).max(1)));
        let margin_secs = (lease_ttl_secs / 3).clamp(1, 5);

        let task = tokio::spawn(async move {
            let mut last_confirmed = Instant::now();
            let mark_fenced = || {
                fence_flag.store(true, Ordering::SeqCst);
                let _ = write_fence_state_file(
                    &fence_file,
                    &FenceStateFile {
                        volume_id: volume_id.clone(),
                        fence_epoch,
                        lease_id,
                        node_id: node_id.clone(),
                        fenced: true,
                    },
                );
            };
            loop {
                tokio::select! {
                    changed = stop_rx.changed() => {
                        if changed.is_err() || *stop_rx.borrow() {
                            break;
                        }
                    }
                    _ = tokio::time::sleep(interval) => {
                        if fence_flag.load(Ordering::SeqCst) {
                            mark_fenced();
                            break;
                        }
                        let now = (clock)();
                        // Local monotonic self-fencing check.
                        if last_confirmed.elapsed() >= Duration::from_secs(lease_ttl_secs.saturating_sub(margin_secs).max(1))
                            && verify_volume_fence(&*store, &grant, &tenant, &volume_id, &node_id, fence_epoch, lease_id, readonly, now).await.is_err()
                        {
                            mark_fenced();
                            break;
                        }
                        let ka = store
                            .rpc(&grant, ClusterCall::LeaseKeepAlive { lease_id }, now)
                            .await;
                        if ka.is_err()
                            || verify_volume_fence(&*store, &grant, &tenant, &volume_id, &node_id, fence_epoch, lease_id, readonly, now).await.is_err()
                        {
                            mark_fenced();
                            break;
                        }
                        last_confirmed = Instant::now();
                    }
                }
            }
        });
        (stop_tx, task)
    }

    fn persist_published_descriptor(&self, desc: &PublishedVolumeDescriptor) -> CsiResult<()> {
        let dir = self.cfg.state_dir.join("published");
        std::fs::create_dir_all(&dir)
            .map_err(|e| CsiError::internal(format!("create published state dir: {e}")))?;
        let key = sha256_hex(&desc.target_path.to_string_lossy());
        let final_path = dir.join(format!("{key}.json"));
        let bytes = serde_json::to_vec_pretty(desc)
            .map_err(|e| CsiError::internal(format!("serialize descriptor: {e}")))?;
        atomic_write_0600(&final_path, &bytes)
            .map_err(|e| CsiError::internal(format!("write descriptor: {e}")))?;
        Ok(())
    }

    fn remove_published_descriptor(&self, target_path: &Path) {
        let key = sha256_hex(&target_path.to_string_lossy());
        let path = self
            .cfg
            .state_dir
            .join("published")
            .join(format!("{key}.json"));
        let _ = std::fs::remove_file(path);
    }
}

impl<C: ClusterStore + Send + Sync + 'static> Drop for OsCsiNode<C> {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.staged.lock() {
            for (_, mut sv) in guard.drain() {
                sv.stop_all();
            }
        }
    }
}

impl<C: ClusterStore + Send + Sync + 'static> CsiIdentity for OsCsiNode<C> {
    fn get_plugin_info<'a>(
        &'a self,
        _req: GetPluginInfoRequest,
    ) -> BoxFuture<'a, CsiResult<GetPluginInfoResponse>> {
        Box::pin(async move {
            let mut manifest = BTreeMap::new();
            manifest.insert("node_id".into(), self.cfg.node_id.clone());
            Ok(GetPluginInfoResponse {
                name: CSI_DRIVER_NAME.to_string(),
                vendor_version: CSI_DRIVER_VERSION.to_string(),
                manifest,
            })
        })
    }

    fn get_plugin_capabilities<'a>(
        &'a self,
        _req: GetPluginCapabilitiesRequest,
    ) -> BoxFuture<'a, CsiResult<GetPluginCapabilitiesResponse>> {
        Box::pin(async move {
            Ok(GetPluginCapabilitiesResponse {
                service_capabilities: Vec::new(),
            })
        })
    }

    fn probe<'a>(&'a self, _req: ProbeRequest) -> BoxFuture<'a, CsiResult<ProbeResponse>> {
        Box::pin(async move { Ok(ProbeResponse { ready: Some(true) }) })
    }
}

impl<C: ClusterStore + Send + Sync + 'static> CsiNode for OsCsiNode<C> {
    fn node_stage_volume<'a>(
        &'a self,
        req: NodeStageVolumeRequest,
    ) -> BoxFuture<'a, CsiResult<NodeStageVolumeResponse>> {
        Box::pin(async move {
            if req.volume_id.is_empty() || req.staging_target_path.is_empty() {
                return Err(CsiError::invalid_argument(
                    "volume_id and staging_target_path are required",
                ));
            }
            let cap = req
                .volume_capability
                .as_ref()
                .ok_or_else(|| CsiError::invalid_argument("volume_capability is required"))?;
            if cap.access_mode.is_multi_node_multi_writer() {
                return Err(CsiError::invalid_argument(
                    "MULTI_NODE_MULTI_WRITER is not supported",
                ));
            }

            let staging_path = validate_node_path(
                &req.staging_target_path,
                self.cfg.allowed_mount_root.as_deref(),
            )?;

            // Parse fencing token from publish_context and verify against ClusterState BEFORE opening storage!
            let fence_epoch = req
                .publish_context
                .get("os.csi/fence_epoch")
                .and_then(|s| s.parse::<u64>().ok())
                .ok_or_else(|| {
                    CsiError::invalid_argument("publish_context missing os.csi/fence_epoch")
                })?;
            let lease_id = req
                .publish_context
                .get("os.csi/lease_id")
                .and_then(|s| s.parse::<u64>().ok())
                .ok_or_else(|| {
                    CsiError::invalid_argument("publish_context missing os.csi/lease_id")
                })?;
            let lease_ttl_secs = req
                .publish_context
                .get("os.csi/lease_ttl_secs")
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(30);
            let ctx_readonly = req
                .publish_context
                .get("os.csi/readonly")
                .is_some_and(|s| s == "true");
            let readonly = ctx_readonly || cap.access_mode.is_read_only();
            let volume_kind = req
                .publish_context
                .get("os.csi/volume_kind")
                .and_then(|s| CsiVolumeKind::parse(s))
                .unwrap_or(if cap.is_block() {
                    CsiVolumeKind::Block
                } else {
                    CsiVolumeKind::Cowfs
                });
            // Confine `store_dir` strictly within configured `default_store_dir` (P1-2).
            let store_dir = if let Some(raw_store) = req
                .publish_context
                .get("os.csi/store_dir")
                .or_else(|| req.volume_context.get("os.csi/store_dir"))
                .filter(|s| !s.is_empty())
            {
                validate_node_path(raw_store, Some(&self.cfg.default_store_dir))?
            } else {
                self.cfg.default_store_dir.clone()
            };
            let block_size = req
                .publish_context
                .get("os.csi/block_size")
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(4096);
            let capacity_bytes = req
                .publish_context
                .get("os.csi/capacity_bytes")
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(64 * 1024 * 1024);

            // Idempotent re-stage check if already staged with identical lease.
            if let Some(existing) = self.staged.lock().unwrap().get(&req.volume_id)
                && existing.staging_target_path == staging_path
                && existing.lease_id == lease_id
                && existing.fence_epoch == fence_epoch
            {
                return Ok(NodeStageVolumeResponse {});
            }

            let now = (self.cfg.clock)();
            verify_volume_fence(
                &*self.store,
                &self.cfg.grant,
                &self.cfg.tenant,
                &req.volume_id,
                &self.cfg.node_id,
                fence_epoch,
                lease_id,
                readonly,
                now,
            )
            .await?;

            // P1-6: Stop & drop any previously staged instance BEFORE writing the new fence_file
            // or binding new sockets/FUSE so `old.stop_all()` never unlinks/unmounts the new stage!
            if let Some(mut old) = self.staged.lock().unwrap().remove(&req.volume_id) {
                old.stop_all();
            }

            std::fs::create_dir_all(&staging_path)
                .map_err(|e| CsiError::internal(format!("create staging dir: {e}")))?;

            let vol_hash = sha256_hex(&req.volume_id);
            let short_hash = &vol_hash[..16];
            let fence_file = self
                .cfg
                .state_dir
                .join("fences")
                .join(format!("{short_hash}.json"));
            let lock_file = self
                .cfg
                .state_dir
                .join("locks")
                .join(format!("{short_hash}.lock"));
            let fence_state_init = FenceStateFile {
                volume_id: req.volume_id.clone(),
                fence_epoch,
                lease_id,
                node_id: self.cfg.node_id.clone(),
                fenced: false,
            };
            write_fence_state_file(&fence_file, &fence_state_init)?;

            // Use `Exclusive` on initial publish (`fence_epoch <= 1`) and `ForceTakeover` ONLY
            // after `ClusterState` authoritatively advanced `fence_epoch > 1` on failover (P0-5).
            let writer_mode = if fence_epoch > 1 {
                WriterMode::ForceTakeover
            } else {
                WriterMode::Exclusive
            };

            let fence_flag = Arc::new(AtomicBool::new(false));
            let mut handoff_socket: Option<PathBuf> = None;

            let backend = match volume_kind {
                CsiVolumeKind::Block => {
                    let nbd_dir = self.cfg.state_dir.join("nbd");
                    std::fs::create_dir_all(&nbd_dir)
                        .map_err(|e| CsiError::internal(format!("create nbd dir: {e}")))?;
                    let _ =
                        std::fs::set_permissions(&nbd_dir, std::fs::Permissions::from_mode(0o700));
                    let short_name = format!("{short_hash}.sock");
                    let candidate = nbd_dir.join(&short_name);
                    let sock_path = if candidate.as_os_str().len() < 96 {
                        candidate
                    } else {
                        ensure_private_runtime_dir("os-nbd-rt")
                            .map_err(|e| {
                                CsiError::internal(format!("private nbd runtime dir: {e}"))
                            })?
                            .join(&short_name)
                    };
                    let open_mode = if readonly {
                        RawBlockOpenMode::ReadOnly
                    } else {
                        RawBlockOpenMode::ReadWrite(writer_mode)
                    };
                    // P1-3: Propagate NBD CAS `ESTALE` fencing back into `fence_flag` AND `fence_file`.
                    let ff_cb = fence_file.clone();
                    let fsb_cb = fence_state_init.clone();
                    let on_fenced: os_nbd::OnFencedCallback = Arc::new(move || {
                        let mut st = fsb_cb.clone();
                        st.fenced = true;
                        let _ = write_fence_state_file(&ff_cb, &st);
                    });
                    let handle = NbdServerHandle::start_unix_native_with_on_fenced(
                        sock_path,
                        store_dir.clone(),
                        VolumeId(req.volume_id.clone()),
                        NbdExportConfig::new(req.volume_id.clone()),
                        open_mode,
                        Some(Arc::clone(&fence_flag)),
                        Some(on_fenced),
                    )
                    .map_err(|e| CsiError::internal(format!("start os-nbd server: {e}")))?;
                    StagedBackend::NbdBlock(handle)
                }
                CsiVolumeKind::Cowfs => {
                    let use_fuse = match self.cfg.stage_mode {
                        StageMode::Fuse => true,
                        StageMode::HostSubvol => false,
                        StageMode::Auto => Path::new("/dev/fuse").exists(),
                    };
                    let alloc_handoff_sock = || -> CsiResult<Option<PathBuf>> {
                        if readonly {
                            return Ok(None);
                        }
                        let ho_dir = self.cfg.state_dir.join("handoff");
                        std::fs::create_dir_all(&ho_dir)
                            .map_err(|e| CsiError::internal(format!("create handoff dir: {e}")))?;
                        let _ = std::fs::set_permissions(
                            &ho_dir,
                            std::fs::Permissions::from_mode(0o700),
                        );
                        let short_name = format!("{short_hash}.sock");
                        let cand = ho_dir.join(&short_name);
                        let p = if cand.as_os_str().len() < 96 {
                            cand
                        } else {
                            ensure_private_runtime_dir("os-csi-ho")
                                .map_err(|e| {
                                    CsiError::internal(format!("private handoff dir: {e}"))
                                })?
                                .join(&short_name)
                        };
                        Ok(Some(p))
                    };
                    // P1-5: Allocate handoff socket for BOTH `Fuse` and `HostSubvol` so RW shim
                    // attachments work seamlessly under default `StageMode::Auto`/`Fuse` too!
                    handoff_socket = alloc_handoff_sock()?;
                    if use_fuse {
                        match FuseDaemonHandle::start(
                            staging_path.clone(),
                            store_dir.clone(),
                            VolumeId(req.volume_id.clone()),
                            readonly,
                            writer_mode,
                            Arc::clone(&fence_flag),
                            fence_file.clone(),
                            fence_state_init.clone(),
                            handoff_socket.clone(),
                            Arc::clone(&self.cfg.clock),
                        ) {
                            Ok(fuse_h) => StagedBackend::Fuse(fuse_h),
                            Err(e) if self.cfg.stage_mode == StageMode::Fuse => {
                                return Err(CsiError::internal(format!(
                                    "FUSE3 stage mount failed: {e}"
                                )));
                            }
                            Err(_) => {
                                let label = detect_host_subvol_backend(&staging_path);
                                let actor = CowFsActorHandle::start(
                                    store_dir.clone(),
                                    VolumeId(req.volume_id.clone()),
                                    readonly,
                                    writer_mode,
                                    Arc::clone(&fence_flag),
                                    fence_file.clone(),
                                    fence_state_init.clone(),
                                    handoff_socket.clone(),
                                    Arc::clone(&self.cfg.clock),
                                )?;
                                let _ = actor.project_to_dir(staging_path.clone()).await;
                                StagedBackend::HostSubvol {
                                    actor: Arc::new(tokio::sync::Mutex::new(actor)),
                                    backend_label: label,
                                }
                            }
                        }
                    } else {
                        let label = detect_host_subvol_backend(&staging_path);
                        let actor = CowFsActorHandle::start(
                            store_dir.clone(),
                            VolumeId(req.volume_id.clone()),
                            readonly,
                            writer_mode,
                            Arc::clone(&fence_flag),
                            fence_file.clone(),
                            fence_state_init.clone(),
                            handoff_socket.clone(),
                            Arc::clone(&self.cfg.clock),
                        )?;
                        let _ = actor.project_to_dir(staging_path.clone()).await;
                        StagedBackend::HostSubvol {
                            actor: Arc::new(tokio::sync::Mutex::new(actor)),
                            backend_label: label,
                        }
                    }
                }
            };

            let (keepalive_stop, keepalive_task) = self.spawn_keepalive_watchdog(
                req.volume_id.clone(),
                fence_epoch,
                lease_id,
                lease_ttl_secs,
                readonly,
                Arc::clone(&fence_flag),
                fence_file.clone(),
            );

            let sv = StagedVolume {
                volume_id: req.volume_id.clone(),
                volume_kind,
                store_dir,
                staging_target_path: staging_path,
                readonly,
                fence_epoch,
                lease_id,
                block_size,
                capacity_bytes,
                fence_flag,
                fence_file,
                handoff_socket,
                lock_file,
                keepalive_stop,
                keepalive_task: Some(keepalive_task),
                backend,
            };
            let prev = self.staged.lock().unwrap().insert(req.volume_id, sv);
            if let Some(mut old) = prev {
                old.stop_all();
            }
            Ok(NodeStageVolumeResponse {})
        })
    }

    fn node_unstage_volume<'a>(
        &'a self,
        req: NodeUnstageVolumeRequest,
    ) -> BoxFuture<'a, CsiResult<NodeUnstageVolumeResponse>> {
        Box::pin(async move {
            if req.volume_id.is_empty() || req.staging_target_path.is_empty() {
                return Err(CsiError::invalid_argument(
                    "volume_id and staging_target_path are required",
                ));
            }
            let staging_path = validate_node_path(
                &req.staging_target_path,
                self.cfg.allowed_mount_root.as_deref(),
            )?;

            {
                let guard = self.staged.lock().unwrap();
                if let Some(sv) = guard.get(&req.volume_id)
                    && sv.staging_target_path != staging_path
                {
                    return Err(CsiError::failed_precondition(format!(
                        "staging_target_path mismatch for volume {}",
                        req.volume_id
                    )));
                }
            }

            let removed = self.staged.lock().unwrap().remove(&req.volume_id);
            if let Some(mut sv) = removed {
                let mut stale_err = sv.fence_flag.load(Ordering::SeqCst);
                // P1-1: Flush and cleanly shut down each backend BEFORE flipping `sv.fence_flag`
                // so final non-FUA buffered writes commit cleanly AND genuine `ESTALE` propagates!
                match &mut sv.backend {
                    StagedBackend::HostSubvol { actor, .. } => {
                        let mut a = actor.lock().await;
                        if !sv.readonly && !stale_err {
                            if a.sync_from_dir(sv.staging_target_path.clone()).await
                                == Err(Errno::ESTALE)
                            {
                                stale_err = true;
                            }
                            if a.flush().await == Err(Errno::ESTALE) {
                                stale_err = true;
                            }
                        }
                        if a.close_clean().await == Err(Errno::ESTALE) {
                            stale_err = true;
                        }
                    }
                    StagedBackend::NbdBlock(nbd) => {
                        if nbd.is_fenced() {
                            stale_err = true;
                            let _ = nbd.shutdown().await;
                        } else if !sv.readonly && !stale_err {
                            if nbd.shutdown().await == Err(Errno::ESTALE) {
                                stale_err = true;
                            }
                        } else {
                            let _ = nbd.shutdown().await;
                        }
                    }
                    StagedBackend::Fuse(fuse) => {
                        if fuse.shutdown_checked().await == Err(Errno::ESTALE) {
                            stale_err = true;
                        }
                        if sv.fence_flag.load(Ordering::SeqCst) {
                            stale_err = true;
                        }
                    }
                }
                sv.fence_flag.store(true, Ordering::SeqCst);
                let _ = write_fence_state_file(
                    &sv.fence_file,
                    &FenceStateFile {
                        volume_id: sv.volume_id.clone(),
                        fence_epoch: sv.fence_epoch,
                        lease_id: sv.lease_id,
                        node_id: self.cfg.node_id.clone(),
                        fenced: true,
                    },
                );
                let _ = std::fs::remove_file(&sv.fence_file);
                sv.stop_all();
                if stale_err {
                    return Err(CsiError::failed_precondition(
                        "ESTALE: volume was fenced before unstage completed",
                    ));
                }
            }
            Ok(NodeUnstageVolumeResponse {})
        })
    }

    fn node_publish_volume<'a>(
        &'a self,
        req: NodePublishVolumeRequest,
    ) -> BoxFuture<'a, CsiResult<NodePublishVolumeResponse>> {
        Box::pin(async move {
            if req.volume_id.is_empty() || req.target_path.is_empty() {
                return Err(CsiError::invalid_argument(
                    "volume_id and target_path are required",
                ));
            }
            let target_path =
                validate_node_path(&req.target_path, self.cfg.allowed_mount_root.as_deref())?;
            if !req.staging_target_path.is_empty() {
                let _ = validate_node_path(
                    &req.staging_target_path,
                    self.cfg.allowed_mount_root.as_deref(),
                )?;
            }

            // Authoritatively verify live ClusterState fence before publishing (P2-2).
            self.check_and_enforce_fence(&req.volume_id)
                .await
                .map_err(|e| match e {
                    Errno::ENOENT => CsiError::failed_precondition(format!(
                        "volume {} is not staged on node {}",
                        req.volume_id, self.cfg.node_id
                    )),
                    _ => CsiError::failed_precondition("ESTALE: staged volume is fenced"),
                })?;

            let (desc, staged_readonly) = {
                let guard = self.staged.lock().unwrap();
                let sv = guard.get(&req.volume_id).ok_or_else(|| {
                    CsiError::failed_precondition(format!(
                        "volume {} is not staged on node {}",
                        req.volume_id, self.cfg.node_id
                    ))
                })?;
                if sv.fence_flag.load(Ordering::SeqCst) {
                    return Err(CsiError::failed_precondition(
                        "ESTALE: staged volume is fenced",
                    ));
                }
                (
                    PublishedVolumeDescriptor {
                        volume_id: sv.volume_id.clone(),
                        volume_kind: sv.volume_kind,
                        store_dir: sv.store_dir.clone(),
                        staging_target_path: sv.staging_target_path.clone(),
                        target_path: target_path.clone(),
                        readonly: sv.readonly || req.readonly,
                        fence_epoch: sv.fence_epoch,
                        lease_id: sv.lease_id,
                        node_id: self.cfg.node_id.clone(),
                        block_size: sv.block_size,
                        capacity_bytes: sv.capacity_bytes,
                        stage_backend: sv.stage_backend_name(),
                        nbd_socket: sv.nbd_socket(),
                        fence_file: Some(sv.fence_file.clone()),
                        handoff_socket: sv.handoff_socket.clone(),
                        lock_file: Some(sv.lock_file.clone()),
                    },
                    sv.readonly,
                )
            };

            match desc.volume_kind {
                CsiVolumeKind::Cowfs => {
                    std::fs::create_dir_all(&target_path)
                        .map_err(|e| CsiError::internal(format!("create target dir: {e}")))?;
                    if desc.stage_backend == "fuse3" && desc.staging_target_path != target_path {
                        let c_src =
                            CString::new(desc.staging_target_path.as_os_str().as_bytes())
                                .map_err(|_| CsiError::invalid_argument("NUL in staging path"))?;
                        let c_dst = CString::new(target_path.as_os_str().as_bytes())
                            .map_err(|_| CsiError::invalid_argument("NUL in target path"))?;
                        let rc = unsafe {
                            libc::mount(
                                c_src.as_ptr(),
                                c_dst.as_ptr(),
                                std::ptr::null(),
                                libc::MS_BIND,
                                std::ptr::null(),
                            )
                        };
                        if rc != 0 {
                            let err = std::io::Error::last_os_error();
                            return Err(CsiError::internal(format!(
                                "bind-mount FUSE staging {} -> {} failed: {err}",
                                desc.staging_target_path.display(),
                                target_path.display()
                            )));
                        }
                        if desc.readonly && !staged_readonly {
                            let remount_rc = unsafe {
                                libc::mount(
                                    c_src.as_ptr(),
                                    c_dst.as_ptr(),
                                    std::ptr::null(),
                                    libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
                                    std::ptr::null(),
                                )
                            };
                            if remount_rc != 0 {
                                let err = std::io::Error::last_os_error();
                                let _ = unsafe { libc::umount2(c_dst.as_ptr(), 0) };
                                return Err(CsiError::internal(format!(
                                    "RO remount FUSE bind {} failed: {err}",
                                    target_path.display()
                                )));
                            }
                        }
                    } else {
                        // Project staged directory contents into target_path when using HostSubvol.
                        let actor_opt = {
                            let guard = self.staged.lock().unwrap();
                            guard.get(&req.volume_id).and_then(|sv| match &sv.backend {
                                StagedBackend::HostSubvol { actor, .. } => Some(Arc::clone(actor)),
                                _ => None,
                            })
                        };
                        if let Some(actor) = actor_opt {
                            let a = actor.lock().await;
                            let _ = a.project_to_dir(target_path.clone()).await;
                        }
                    }
                }
                CsiVolumeKind::Block => {
                    if let Some(parent) = target_path.parent() {
                        std::fs::create_dir_all(parent).map_err(|e| {
                            CsiError::internal(format!("create target parent: {e}"))
                        })?;
                    }
                    // Write a 0600 binding descriptor file at target_path only if it is not a directory.
                    if !target_path.is_dir() {
                        let meta_bytes = serde_json::to_vec_pretty(&desc).map_err(|e| {
                            CsiError::internal(format!("encode block binding: {e}"))
                        })?;
                        std::fs::write(&target_path, &meta_bytes).map_err(|e| {
                            CsiError::internal(format!("write target binding: {e}"))
                        })?;
                        let _ = std::fs::set_permissions(
                            &target_path,
                            std::fs::Permissions::from_mode(0o600),
                        );
                    }
                }
            }

            // Always persist descriptor strictly inside $NODE_STATE/published/.
            self.persist_published_descriptor(&desc)?;
            self.published.lock().unwrap().insert(target_path, desc);
            Ok(NodePublishVolumeResponse {})
        })
    }

    fn node_unpublish_volume<'a>(
        &'a self,
        req: NodeUnpublishVolumeRequest,
    ) -> BoxFuture<'a, CsiResult<NodeUnpublishVolumeResponse>> {
        Box::pin(async move {
            if req.volume_id.is_empty() || req.target_path.is_empty() {
                return Err(CsiError::invalid_argument(
                    "volume_id and target_path are required",
                ));
            }
            let target_path =
                validate_node_path(&req.target_path, self.cfg.allowed_mount_root.as_deref())?;
            let removed = self.published.lock().unwrap().remove(&target_path);
            if let Some(desc) = removed {
                if desc.volume_kind == CsiVolumeKind::Cowfs {
                    if desc.stage_backend == "fuse3" && desc.staging_target_path != target_path {
                        if let Ok(c_dst) = CString::new(target_path.as_os_str().as_bytes()) {
                            let _ = unsafe { libc::umount2(c_dst.as_ptr(), 0) };
                        }
                    } else if !desc.readonly {
                        let actor_opt = {
                            let guard = self.staged.lock().unwrap();
                            guard.get(&req.volume_id).and_then(|sv| {
                                if sv.fence_flag.load(Ordering::SeqCst) {
                                    None
                                } else if let StagedBackend::HostSubvol { actor, .. } = &sv.backend
                                {
                                    Some(Arc::clone(actor))
                                } else {
                                    None
                                }
                            })
                        };
                        if let Some(actor) = actor_opt {
                            let a = actor.lock().await;
                            let _ = a.sync_from_dir(target_path.clone()).await;
                        }
                    }
                } else if desc.volume_kind == CsiVolumeKind::Block && target_path.is_file() {
                    let _ = std::fs::remove_file(&target_path);
                }
            }
            self.remove_published_descriptor(&target_path);
            Ok(NodeUnpublishVolumeResponse {})
        })
    }

    fn node_get_volume_stats<'a>(
        &'a self,
        req: NodeGetVolumeStatsRequest,
    ) -> BoxFuture<'a, CsiResult<NodeGetVolumeStatsResponse>> {
        Box::pin(async move {
            if req.volume_id.is_empty() || req.volume_path.is_empty() {
                return Err(CsiError::invalid_argument(
                    "volume_id and volume_path are required",
                ));
            }
            let _ = validate_node_path(&req.volume_path, self.cfg.allowed_mount_root.as_deref())?;
            let (cap, actor_opt) = {
                let guard = self.staged.lock().unwrap();
                let sv = guard
                    .get(&req.volume_id)
                    .ok_or_else(|| CsiError::not_found("volume not staged"))?;
                let actor = match &sv.backend {
                    StagedBackend::HostSubvol { actor, .. } => Some(Arc::clone(actor)),
                    _ => None,
                };
                (sv.capacity_bytes, actor)
            };
            let (total, used, avail) = if let Some(actor) = actor_opt {
                let a = actor.lock().await;
                a.stats().await.unwrap_or((cap, 0, cap))
            } else {
                (cap, 0, cap)
            };
            Ok(NodeGetVolumeStatsResponse {
                usage: vec![VolumeUsage {
                    available: avail as i64,
                    total: total as i64,
                    used: used as i64,
                    unit: VolumeUsageUnit::Bytes,
                }],
            })
        })
    }

    fn node_get_capabilities<'a>(
        &'a self,
        _req: NodeGetCapabilitiesRequest,
    ) -> BoxFuture<'a, CsiResult<NodeGetCapabilitiesResponse>> {
        Box::pin(async move {
            Ok(NodeGetCapabilitiesResponse {
                capabilities: vec![
                    NodeRpcCapability::StageUnstageVolume,
                    NodeRpcCapability::GetVolumeStats,
                ],
            })
        })
    }

    fn node_get_info<'a>(
        &'a self,
        _req: NodeGetInfoRequest,
    ) -> BoxFuture<'a, CsiResult<NodeGetInfoResponse>> {
        Box::pin(async move {
            let mut segments = BTreeMap::new();
            segments.insert(
                "topology.cowfs.csi.os.dev/node".into(),
                self.cfg.node_id.clone(),
            );
            Ok(NodeGetInfoResponse {
                node_id: self.cfg.node_id.clone(),
                max_volumes_per_node: self.cfg.max_volumes_per_node,
                accessible_topology: Some(Topology { segments }),
            })
        })
    }
}

//! Single-threaded `tokio::LocalSet` Kernel Actor owning all `!Send` OS state (`Vfs`,
//! `CowFs<NativeSqliteHeadStore, NativePackStore>`, `LocalProcessTable`, `LocalAccountStore`,
//! `UnixSockTable`, `DevTmpFs`, `DevPtsFs`, `VblkRegistry`, `LoopRegistry`, `GuiDeviceRegistry`
//! with `HeadlessHostAdapter`, and `MountHostServer`).

use crate::accounts::{VfsAccountFs, random_salt, read_vfs_file_as_root};
use crate::dev_backend::{NativeDevBackend, build_native_dev_backend_with_vblk, new_uuid_v4};
use crate::errno::wasi_filetype_from_mode;
use crate::export_host::{NativeExportBridge, NativeExportGrant};
use crate::kernel_rpc::{
    GuestFdEntry, GuestFdKind, HostInspect, KAnchor, KernelCmd, LoadedImage, OpenFileReply,
    PreparedFork, PreparedSpawn, ReaddirEntry, RightsFd, SockPollReply, SockRecvReply,
    SpawnProcessReq, WaitResult, WakeBus, ret_err, ret_ok,
};
use crate::mount_host::MountHostServer;
use crate::pty::{PtyTable, ioctl as pty_ioctl};
use crate::release::{
    LocalFileBlobStore, VerifiedReleaseBundle, compose_system_image_entries, image_to_vfs_entries,
};
use crate::signals::SignalControl;
use abi::contract::{
    Durability, InstanceIdentity, WriterModel, cowfs_ioctl, fs_magic, loop_ioctl, mount_flags,
    unshare_flags,
};
use abi::gui::gui_ioctl;
use abi::socket::{MSG_DONTWAIT, PeerCred, SOCK_STREAM};
use abi::{Call, Creds, Errno, Error, FdRef, ProcState, Target};
use cowtree::{COWFS_FORMAT_VERSION, HeadStore, VolumeId, WriterMode};
use os_core::permissions::Identity;
use os_cowfs::native_sqlite::{NativePackStore, NativeSqliteHeadStore};
use os_cowfs::{CowFs, CowFsConfig, CowFsOpenMode, CowFsVolumeDevice, open_archive_cowfs};
use os_image::{Image, Node};
use os_kernel::accounts::{LocalAccountStore, UseraddReq, UsermodReq};
use os_kernel::proc_table::{LocalCred, LocalProcessTable, ReexecSpec, SpawnSpec, WaitOutcome};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use vfs::devfs::{DefaultDeviceBackend, DevPtsFs, DevTmpFs};
use vfs::gui_headless::HeadlessHostAdapter;
use vfs::guidev::{GuiDevice, GuiDeviceRegistry};
use vfs::imagefs::ImageFs;
use vfs::loopdev::{LoopRegistry, is_loop_control_rdev, parse_loop_device_path, parse_loop_rdev};
use vfs::memfs::MemFs;
use vfs::procfs::{EmptyProcProvider, ProcFs, ProcMetaSnapshot};
use vfs::unix_sock::{InFlightFd, SockId, SockType, SocketInodeKey, UnixSocketTable};
use vfs::vblk::{
    CowfsMountOptions, VblkRegistry, is_cowfs_or_blk_ioctl, is_non_block_tree_source,
    parse_vblk_rdev,
};
use vfs::{
    Cred, DefaultFilesystemFactory, FileType, Filesystem, FsId, FsType, MountBacking, MountFlags,
    MountedFs, OpenOptions, RenameFlags, SeekFrom, SetAttr, StartAnchor, Timespec, Vfs, WriteAt,
    XattrFlags,
};

pub const HOST_LABEL: &str = "os-native";
pub const BOOT_PROFILE_PATH: &str = "/run/os/boot-profile.json";
pub const MOUNTED_ROOT_PATH: &str = "/run/os/root";
pub const BOOT_HEALTHY_PATH: &str = "/run/os/boot-healthy";
/// Offset applied to kernel fds returned by `abi::Call::Open` / `Call::OpenAt` so they never
/// collide with WASI guest fds (`0..1024`) when later passed to `Call::Ioctl` / `Call::Close`.
const SYS_KFD_OFFSET: u32 = 10_000;

/// Persisted `$STATE/boot-profile.json` matching `early_init.rs` & `boot_stage.rs`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeRootSpec {
    CowFs {
        volume_uuid: Option<String>,
        #[serde(default)]
        writer_mode: NativeWriterMode,
    },
    Snapshot {
        volume_uuid: String,
        snapshot: String,
    },
    Ephemeral,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeWriterMode {
    #[default]
    ForkOnBusy,
    Exclusive,
}

impl NativeWriterMode {
    pub fn to_cowtree(self) -> WriterMode {
        match self {
            Self::ForkOnBusy => WriterMode::ForkOnBusy,
            Self::Exclusive => WriterMode::Exclusive,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeBootProfile {
    pub version: u32,
    pub root: NativeRootSpec,
    pub default_user: String,
    pub generation: Option<String>,
    pub recovery: bool,
}

impl Default for NativeBootProfile {
    fn default() -> Self {
        Self {
            version: 1,
            root: NativeRootSpec::CowFs {
                volume_uuid: None,
                writer_mode: NativeWriterMode::ForkOnBusy,
            },
            default_user: "user".to_string(),
            generation: None,
            recovery: false,
        }
    }
}

pub fn now_timespec() -> Timespec {
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
}

pub fn now_secs() -> u64 {
    now_timespec().sec
}

pub type NativeCowFs = Rc<CowFs<NativeSqliteHeadStore, NativePackStore>>;
type CowFsMountList = Rc<RefCell<Vec<NativeCowFs>>>;
type RootCowFsCell = Rc<RefCell<Option<NativeCowFs>>>;

/// Complete `!Send` kernel state owned exclusively by the single-threaded Kernel Actor.
pub struct KernelActor {
    pub instance_id: String,
    pub state_dir: PathBuf,
    pub release: Option<VerifiedReleaseBundle>,
    pub boot_profile: NativeBootProfile,
    pub vfs: Vfs,
    pub proc_table: Rc<RefCell<LocalProcessTable>>,
    pub accounts: LocalAccountStore,
    pub head_store: Rc<NativeSqliteHeadStore>,
    pub pack_store: Rc<NativePackStore>,
    pub cowfs_mounts: CowFsMountList,
    pub root_cowfs: RootCowFsCell,
    pub root_volume_uuid: Rc<RefCell<Option<String>>>,
    pub dev_fs: Rc<DevTmpFs<NativeDevBackend>>,
    pub dev_pts: Rc<DevPtsFs<DefaultDeviceBackend>>,
    pub vblk: Rc<VblkRegistry>,
    pub loop_reg: LoopRegistry,
    pub gui_reg: Rc<GuiDeviceRegistry>,
    pub gui_caller: Rc<Cell<Option<u32>>>,
    pub _headless_gui: Rc<HeadlessHostAdapter>,
    pub socks: UnixSocketTable,
    pub mount_host: MountHostServer,
    pub kubelet_host: crate::kubelet::KubeletHostServer,
    pub export_bridge: NativeExportBridge,
    pub exportd_pids: HashSet<u32>,
    pub exportd_sha256: Option<String>,
    pub init_pids: HashSet<u32>,
    pub init_sha256: Option<String>,
    pub kubelet_pids: HashSet<u32>,
    pub kubelet_sha256: Option<String>,
    pub sig_ctrls: HashMap<u32, Arc<SignalControl>>,
    pub rights_side_table: HashMap<u32, RightsFd>,
    pub next_rights_handle: u32,
    pub wake: Arc<WakeBus>,
    pub ptys: Arc<PtyTable>,
    pub clock: Rc<dyn Fn() -> Timespec>,
    pub closed: bool,
}

fn persist_boot_profile(state_dir: &Path, profile: &NativeBootProfile) -> Result<(), Errno> {
    let bytes = serde_json::to_vec_pretty(profile).map_err(|_| Errno::EIO)?;
    let tmp = state_dir.join(format!(".boot-profile.tmp.{}", std::process::id()));
    let dst = state_dir.join("boot-profile.json");
    fs::write(&tmp, &bytes).map_err(|e| crate::errno::io_err_to_abi(&e))?;
    if let Ok(f) = fs::File::open(&tmp) {
        let _ = f.sync_all();
    }
    fs::rename(&tmp, &dst).map_err(|e| crate::errno::io_err_to_abi(&e))?;
    Ok(())
}

async fn populate_stage1_tmpfs(
    fs: &MemFs,
    initramfs: &Image,
    blobs: &LocalFileBlobStore,
) -> vfs::Result<()> {
    let mut root_cred = Cred::root();
    root_cred.umask = 0;
    let mut handles: HashMap<String, abi::fs::Handle> = HashMap::new();
    handles.insert("/".to_string(), fs.root());

    for entry in &initramfs.entries {
        if entry.path == "/" || entry.path.starts_with("/usr/") {
            continue;
        }
        let (parent_path, name) = match entry.path.rsplit_once('/') {
            Some(("", n)) => ("/", n),
            Some((p, n)) => (p, n),
            None => return Err(Errno::EINVAL),
        };
        let parent_h = handles.get(parent_path).cloned().ok_or(Errno::ENOENT)?;
        match &entry.node {
            Node::Directory => {
                let created = match fs.mkdir(&root_cred, &parent_h, name, entry.mode).await {
                    Ok(e) => e,
                    Err(Errno::EEXIST) => fs.lookup(&root_cred, &parent_h, name).await?,
                    Err(e) => return Err(e),
                };
                fs.setattr(
                    &root_cred,
                    &created.handle,
                    &SetAttr {
                        mode: Some(entry.mode),
                        uid: Some(entry.uid),
                        gid: Some(entry.gid),
                        ..SetAttr::default()
                    },
                )
                .await?;
                handles.insert(entry.path.clone(), created.handle);
            }
            Node::File {
                sha256,
                size,
                chunk_size,
                chunks,
            } => {
                let data = blobs.read_verified_whole(sha256, *size, *chunk_size, chunks)?;
                let mut opts = OpenOptions::new();
                opts.write(true).create(true).truncate(true);
                let (created, open) = fs
                    .create(&root_cred, &parent_h, name, entry.mode, &opts)
                    .await?;
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
                fs.setattr(
                    &root_cred,
                    &created.handle,
                    &SetAttr {
                        mode: Some(entry.mode),
                        uid: Some(entry.uid),
                        gid: Some(entry.gid),
                        ..SetAttr::default()
                    },
                )
                .await?;
                handles.insert(entry.path.clone(), created.handle);
            }
            Node::Symlink { target } => {
                let created = fs.symlink(&root_cred, &parent_h, name, target).await?;
                handles.insert(entry.path.clone(), created.handle);
            }
        }
    }

    let root_h = fs.root();
    for (name, mode) in [
        ("proc", 0o555),
        ("dev", 0o755),
        ("run", 0o755),
        ("sysroot", 0o755),
        ("usr", 0o755),
        ("tmp", 0o1777),
    ] {
        if fs.lookup(&root_cred, &root_h, name).await.is_err() {
            let created = fs.mkdir(&root_cred, &root_h, name, mode).await?;
            if mode & 0o7000 != 0 {
                let _ = fs
                    .setattr(
                        &root_cred,
                        &created.handle,
                        &SetAttr {
                            mode: Some(mode),
                            ..SetAttr::default()
                        },
                    )
                    .await;
            }
        }
    }
    Ok(())
}

async fn seed_root_template_cowfs(
    fs: &CowFs<NativeSqliteHeadStore, NativePackStore>,
    template: &Image,
    blobs: &LocalFileBlobStore,
) -> vfs::Result<()> {
    let mut root_cred = Cred::root();
    root_cred.umask = 0;
    let mut handles: HashMap<String, abi::fs::Handle> = HashMap::new();
    handles.insert("/".to_string(), fs.root());

    for entry in &template.entries {
        if entry.path == "/" {
            continue;
        }
        let (parent_path, name) = match entry.path.rsplit_once('/') {
            Some(("", n)) => ("/", n),
            Some((p, n)) => (p, n),
            None => return Err(Errno::EINVAL),
        };
        let parent_h = handles.get(parent_path).cloned().ok_or(Errno::ENOENT)?;
        match &entry.node {
            Node::Directory => {
                let created = match fs.mkdir(&root_cred, &parent_h, name, entry.mode).await {
                    Ok(e) => e,
                    Err(Errno::EEXIST) => fs.lookup(&root_cred, &parent_h, name).await?,
                    Err(e) => return Err(e),
                };
                fs.setattr(
                    &root_cred,
                    &created.handle,
                    &SetAttr {
                        mode: Some(entry.mode),
                        uid: Some(entry.uid),
                        gid: Some(entry.gid),
                        ..SetAttr::default()
                    },
                )
                .await?;
                handles.insert(entry.path.clone(), created.handle);
            }
            Node::File {
                sha256,
                size,
                chunk_size,
                chunks,
            } => {
                let data = blobs.read_verified_whole(sha256, *size, *chunk_size, chunks)?;
                let mut opts = OpenOptions::new();
                opts.write(true).create(true).truncate(true);
                let (created, open) = fs
                    .create(&root_cred, &parent_h, name, entry.mode, &opts)
                    .await?;
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
                fs.setattr(
                    &root_cred,
                    &created.handle,
                    &SetAttr {
                        mode: Some(entry.mode),
                        uid: Some(entry.uid),
                        gid: Some(entry.gid),
                        ..SetAttr::default()
                    },
                )
                .await?;
                handles.insert(entry.path.clone(), created.handle);
            }
            Node::Symlink { target } => {
                let created = fs.symlink(&root_cred, &parent_h, name, target).await?;
                handles.insert(entry.path.clone(), created.handle);
            }
        }
    }

    // Ensure merged-`/usr` compatibility symlinks exist on the local cowfs root so `/bin/sh` etc.
    // work immediately after `switch_root` once Release v2 `/usr` is mounted.
    let root_h = fs.root();
    for (name, target) in [
        ("bin", "usr/bin"),
        ("sbin", "usr/bin"),
        ("lib", "usr/lib"),
        ("lib64", "usr/lib"),
    ] {
        if fs.lookup(&root_cred, &root_h, name).await.is_err() {
            let _ = fs.symlink(&root_cred, &root_h, name, target).await;
        }
    }

    fs.commit_tx_group().await.map(|_| ())
}

async fn write_file_on_vfs(vfs: &Vfs, path: &str, bytes: &[u8], mode: u16) -> vfs::Result<()> {
    let _ = vfs.unlinkat(1, StartAnchor::Root, path, false).await;
    let fd = vfs
        .openat(
            1,
            StartAnchor::Root,
            path,
            abi::O_CREAT | abi::O_WRONLY | abi::O_TRUNC,
            mode,
        )
        .await?;
    let mut off = 0u64;
    while (off as usize) < bytes.len() {
        let n = match vfs.pwrite(1, fd, &bytes[off as usize..], off).await {
            Ok(n) => n,
            Err(e) => {
                let _ = vfs.close(1, fd).await;
                return Err(e);
            }
        };
        if n == 0 {
            let _ = vfs.close(1, fd).await;
            return Err(Errno::EIO);
        }
        off += n as u64;
    }
    vfs.close(1, fd).await?;
    vfs.setattrat(
        1,
        StartAnchor::Root,
        path,
        &SetAttr {
            mode: Some(mode),
            uid: Some(0),
            gid: Some(0),
            ..SetAttr::default()
        },
        false,
    )
    .await?;
    Ok(())
}

impl KernelActor {
    /// Bootstrap Stage 1 (`initramfs`) VFS, local `/dev`, `/proc`, `/run`, `NativeSqliteHeadStore`,
    /// `NativePackStore`, and PID 1 (`early_init`) completely offline.
    pub async fn boot_stage1(
        instance_id: String,
        state_dir: PathBuf,
        release: VerifiedReleaseBundle,
        mut boot_profile: NativeBootProfile,
        wake: Arc<WakeBus>,
        ptys: Arc<PtyTable>,
    ) -> Result<(Self, Arc<SignalControl>, LoadedImage), String> {
        fs::create_dir_all(&state_dir)
            .map_err(|e| format!("create state dir {}: {e}", state_dir.display()))?;

        // Load persisted `$STATE/boot-profile.json` if present (preserving volume_uuid across boots).
        let profile_path = state_dir.join("boot-profile.json");
        if profile_path.exists() {
            let raw = fs::read(&profile_path)
                .map_err(|e| format!("read {}: {e}", profile_path.display()))?;
            let persisted: NativeBootProfile = serde_json::from_slice(&raw)
                .map_err(|e| format!("parse {}: {e}", profile_path.display()))?;
            // Preserve persisted volume UUID unless caller explicitly overrode root or recovery.
            let caller_recovery = boot_profile.recovery;
            let caller_root = boot_profile.root.clone();
            boot_profile = persisted;
            if caller_recovery {
                boot_profile.recovery = true;
            }
            if !matches!(
                caller_root,
                NativeRootSpec::CowFs {
                    volume_uuid: None,
                    ..
                }
            ) {
                boot_profile.root = caller_root;
            }
        }

        let head_store = Rc::new(
            NativeSqliteHeadStore::open(&state_dir)
                .map_err(|e| format!("open NativeSqliteHeadStore: {e:?}"))?,
        );
        if !boot_profile.recovery
            && matches!(
                boot_profile.root,
                NativeRootSpec::CowFs { .. } | NativeRootSpec::Snapshot { .. }
            )
            && let Some(ver) = head_store
                .format_version()
                .await
                .map_err(|e| format!("read cowfs format_version: {e:?}"))?
            && ver != COWFS_FORMAT_VERSION
        {
            return Err(format!(
                "incompatible os-cowfs format_version {ver} (expected {COWFS_FORMAT_VERSION}): \
                 EPROTONOSUPPORT; refusing to mount or format (volume preserved untouched)"
            ));
        }
        let pack_store = Rc::new(
            NativePackStore::open(&state_dir)
                .map_err(|e| format!("open NativePackStore: {e:?}"))?,
        );

        let clock: Rc<dyn Fn() -> Timespec> = Rc::new(now_timespec);
        let clock_pair: Rc<dyn Fn() -> (u64, u32)> = Rc::new(|| {
            let ts = now_timespec();
            (ts.sec, ts.nsec)
        });
        let boot_ts = (clock)();

        // 1. Process table with PID 1 running `/init` (Stage 1 `early_init.wasm`).
        let proc_table = Rc::new(RefCell::new(LocalProcessTable::new(
            InstanceIdentity {
                instance: instance_id.clone(),
                host: HOST_LABEL.to_string(),
            },
            boot_ts.sec,
        )));
        {
            let mut tbl = proc_table.borrow_mut();
            tbl.boot_init(HOST_LABEL, boot_ts.sec)
                .map_err(|e| format!("boot_init: {e}"))?;
            let _ = tbl
                .reexec(
                    HOST_LABEL,
                    1,
                    ReexecSpec {
                        path: "/init".to_string(),
                        argv: vec!["/init".to_string()],
                        env: vec![
                            "PATH=/usr/bin:/bin:/sbin".to_string(),
                            "OS_BOOT_STAGE=1".to_string(),
                        ],
                        cwd: Some("/".to_string()),
                        runtime: Some("wasmtime".to_string()),
                        cloud_access: false,
                        new_remote: None,
                    },
                    boot_ts.sec,
                )
                .map_err(|e| format!("reexec pid 1: {e}"))?;
        }

        // 2. Stage 1 `tmpfs` `/` populated from signed `Kind::Initramfs`.
        let stage1_fs = Rc::new(MemFs::new(
            FsId("tmpfs:stage1-initramfs".to_string()),
            1,
            0,
            0,
            0o755,
            Box::new(|| {
                let ts = now_timespec();
                (ts.sec, ts.nsec)
            }),
        ));
        populate_stage1_tmpfs(&stage1_fs, &release.initramfs, &release.blobs)
            .await
            .map_err(|e| format!("populate stage1 tmpfs: {e:?}"))?;

        let factory = Rc::new(DefaultFilesystemFactory::new(Rc::clone(&clock_pair)));

        // Shared registries used by system mounters & ioctls.
        let vblk = Rc::new(VblkRegistry::new());
        let loop_reg = LoopRegistry::new();
        let gui_caller = Rc::new(Cell::new(None));
        let headless_gui = Rc::new(HeadlessHostAdapter::default());
        let gui_reg = GuiDeviceRegistry::new(
            Rc::clone(&headless_gui) as Rc<dyn abi::gui::GuiHostSink>,
            Rc::clone(&gui_caller),
        );
        let cowfs_mounts: CowFsMountList = Rc::new(RefCell::new(Vec::new()));
        let root_cowfs: RootCowFsCell = Rc::new(RefCell::new(None));
        let root_volume_uuid: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));

        let dev_backend =
            build_native_dev_backend_with_vblk(loop_reg.clone(), gui_reg, Rc::clone(&vblk));
        let dev_fs = Rc::new(DevTmpFs::new(
            FsId("devtmpfs".to_string()),
            1,
            Box::new(|| {
                let ts = now_timespec();
                (ts.sec, ts.nsec)
            }),
            dev_backend,
        ));
        let gui_reg = Rc::clone(&dev_fs.backend().registry);

        // Seed `/dev/loop-control`, `/dev/loop0..7`, `/dev/display`, `/dev/input`, and placeholder
        // `/dev/vd0` (attached to the native head/pack store so `cowfsck` works before root mount!).
        {
            let mut root_cred = Cred::root();
            root_cred.umask = 0;
            let dev_root = dev_fs.root();
            let _ = dev_fs
                .mknod(&root_cred, &dev_root, "loop-control", 0o660, "loop:control")
                .await;
            for i in 0..8 {
                let name = format!("loop{i}");
                let rdev = format!("loop:loop{i}");
                let _ = dev_fs
                    .mknod(&root_cred, &dev_root, &name, 0o660, &rdev)
                    .await;
            }
            let _ = dev_fs
                .mknod(&root_cred, &dev_root, "display", 0o600, "gui:display")
                .await;
            let _ = dev_fs
                .mknod(&root_cred, &dev_root, "input", 0o600, "gui:input")
                .await;
            // Attach `/dev/vd0` to the unmounted store volume (if known) or store-wide probe device
            // so Stage 1 `early_init` -> `/bin/cowfsck volume:<uuid>` can invoke `COWFS_IOC_FSCK`
            // on `/dev/vd0` BEFORE mounting `/sysroot`!
            let initial_vol = match &boot_profile.root {
                NativeRootSpec::CowFs {
                    volume_uuid: Some(u),
                    ..
                }
                | NativeRootSpec::Snapshot { volume_uuid: u, .. } => u.clone(),
                _ => "unprovisioned".to_string(),
            };
            let pre_dev = Rc::new(CowFsVolumeDevice::unmounted(
                VolumeId(initial_vol),
                Rc::clone(&head_store),
                Rc::clone(&pack_store),
                WriterModel::Local,
                Durability::TreeCommit,
                Rc::clone(&clock),
            ));
            let _ = vblk.attach_named("vd0", pre_dev);
            let _ = dev_fs
                .mknod(&root_cred, &dev_root, "vd0", 0o660, "vblk:vd0")
                .await;
        }

        let run_fs = Rc::new(MemFs::new(
            FsId("tmpfs:run".to_string()),
            2,
            0,
            0,
            0o755,
            Box::new(|| {
                let ts = now_timespec();
                (ts.sec, ts.nsec)
            }),
        ));

        // Register async `FsType::Cowfs` mounter (handles `/dev/vd0`, `volume:<uuid>`,
        // `snapshot:<uuid>@<snap>`, `/dev/loopN` `.cowpack`, `subvol=@home`, first-boot seeding!).
        {
            let hs = Rc::clone(&head_store);
            let ps = Rc::clone(&pack_store);
            let clk = Rc::clone(&clock);
            let root_tpl = release.root_template.clone();
            let blobs = release.blobs.clone();
            let vblk_m = Rc::clone(&vblk);
            let dev_m = Rc::clone(&dev_fs);
            let run_m = Rc::clone(&run_fs);
            let loop_m = loop_reg.clone();
            let mounts_m = Rc::clone(&cowfs_mounts);
            let root_cf_m = Rc::clone(&root_cowfs);
            let root_uuid_m = Rc::clone(&root_volume_uuid);
            let state_dir_m = state_dir.clone();
            let profile_m = boot_profile.clone();

            factory.register_async_system_mounter(
                FsType::Cowfs,
                move |cred, source, flags, data| {
                    let hs = Rc::clone(&hs);
                    let ps = Rc::clone(&ps);
                    let clk = Rc::clone(&clk);
                    let root_tpl = root_tpl.clone();
                    let blobs = blobs.clone();
                    let vblk_m = Rc::clone(&vblk_m);
                    let dev_m = Rc::clone(&dev_m);
                    let run_m = Rc::clone(&run_m);
                    let loop_m = loop_m.clone();
                    let mounts_m = Rc::clone(&mounts_m);
                    let root_cf_m = Rc::clone(&root_cf_m);
                    let root_uuid_m = Rc::clone(&root_uuid_m);
                    let state_dir_m = state_dir_m.clone();
                    let mut profile_m = profile_m.clone();

                    Box::pin(async move {
                        if cred.identity.id != 0 {
                            return Err(Errno::EPERM);
                        }
                        if is_non_block_tree_source(&source) {
                            return Err(Errno::ENOTBLK);
                        }
                        let opts = CowfsMountOptions::parse(data.as_deref())?;
                        let ro = flags.rdonly || opts.ro;

                        // Case 1: `/dev/loopN` read-only `.cowpack` archive mount.
                        if let Some(loop_idx) = parse_loop_device_path(&source) {
                            if !ro {
                                return Err(Errno::EROFS);
                            }
                            let (file, _ro, _fmt, guard) = loop_m.acquire_mount(loop_idx, false)?;
                            let cfg = CowFsConfig::local_native(Rc::clone(&clk))
                                .with_subvol(&opts.subvol);
                            let reader = Rc::new(os_cowfs::FileRefArchiveReader(file));
                            let fs = Rc::new(
                                open_archive_cowfs(reader, format!("loop{loop_idx}"), cfg).await?,
                            );
                            let root = fs.root();
                            let backing = Rc::new(
                                MountBacking::new(fs as Rc<dyn Filesystem>, FsType::Cowfs)
                                    .with_ceilings(true, false)
                                    .with_on_release(move || drop(guard)),
                            );
                            return Ok(MountedFs {
                                backing,
                                root,
                                root_in_fs: "/".to_string(),
                            });
                        }

                        // Always verify on-disk format version FIRST (never silently wipe/format!).
                        if let Some(ver) = hs.format_version().await?
                            && ver != COWFS_FORMAT_VERSION
                        {
                            return Err(Errno::EPROTONOSUPPORT);
                        }

                        // Case 2: `snapshot:<uuid>@<snap>` read-only mount.
                        if let Some(rest) = source.strip_prefix("snapshot:") {
                            let (vol, snap) = rest.split_once('@').ok_or(Errno::EINVAL)?;
                            if vol.is_empty() || snap.is_empty() {
                                return Err(Errno::EINVAL);
                            }
                            let cfg = CowFsConfig::local_native(Rc::clone(&clk))
                                .with_subvol(&opts.subvol);
                            let fs = Rc::new(
                                CowFs::open(
                                    Rc::clone(&hs),
                                    Rc::clone(&ps),
                                    VolumeId(vol.to_string()),
                                    CowFsOpenMode::Snapshot(snap.to_string()),
                                    cfg,
                                )
                                .await?,
                            );
                            let root = fs.root();
                            let dev = Rc::new(CowFsVolumeDevice::from_mounted(Rc::clone(&fs)));
                            let backing = Rc::new(
                                MountBacking::new(fs as Rc<dyn Filesystem>, FsType::Cowfs)
                                    .with_ceilings(true, false)
                                    .with_volume_device(dev),
                            );
                            return Ok(MountedFs {
                                backing,
                                root,
                                root_in_fs: "/".to_string(),
                            });
                        }

                        // Case 3: Existing already-mounted root volume subvolume view (e.g. `subvol=@home`).
                        if opts.subvol != "@"
                            && let Some(existing) = root_cf_m.borrow().clone()
                        {
                            let target_vol = source
                                .strip_prefix("volume:")
                                .unwrap_or(&existing.volume_id().0);
                            if target_vol == existing.volume_id().0 {
                                if !existing.has_subvol(&opts.subvol) {
                                    return Err(Errno::ENOENT);
                                }
                                let view = existing.open_subvol_view(&opts.subvol)?;
                                let root = view.root();
                                let dev =
                                    Rc::new(CowFsVolumeDevice::from_mounted(Rc::clone(&existing)));
                                let backing = Rc::new(
                                    MountBacking::new(view, FsType::Cowfs)
                                        .with_ceilings(ro, false)
                                        .with_volume_device(dev),
                                );
                                return Ok(MountedFs {
                                    backing,
                                    root,
                                    root_in_fs: "/".to_string(),
                                });
                            }
                        }

                        // Case 4: Primary RW/RO `os-cowfs` volume (`/dev/vd0` or `volume:<uuid>`).
                        let requested_vol: Option<String> =
                            if let Some(u) = source.strip_prefix("volume:") {
                                if u.is_empty() {
                                    return Err(Errno::EINVAL);
                                }
                                Some(u.to_string())
                            } else if source == "/dev/vd0" {
                                match &profile_m.root {
                                    NativeRootSpec::CowFs { volume_uuid, .. } => {
                                        volume_uuid.clone().or_else(|| root_uuid_m.borrow().clone())
                                    }
                                    _ => None,
                                }
                            } else if let Some(slot) = source.strip_prefix("/dev/") {
                                vblk_m.get(slot).map(|d| d.volume_id().to_string())
                            } else {
                                return Err(Errno::ENOTBLK);
                            };

                        let writer_mode = if opts.excl {
                            WriterMode::Exclusive
                        } else {
                            WriterMode::ForkOnBusy
                        };

                        let (fs, vol_uuid, first_seeded) = match requested_vol {
                            None => {
                                // First boot: format new volume & seed RootTemplate atomically.
                                let uuid = new_uuid_v4();
                                let vid = VolumeId(uuid.clone());
                                let now = (clk)();
                                CowFs::format_volume(&*hs, &*ps, vid.clone(), 0, 0, 0o755, now)
                                    .await?;
                                let cfg = CowFsConfig::local_native(Rc::clone(&clk))
                                    .with_subvol(&opts.subvol);
                                let fs = Rc::new(
                                    CowFs::open(
                                        Rc::clone(&hs),
                                        Rc::clone(&ps),
                                        vid,
                                        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
                                        cfg,
                                    )
                                    .await?,
                                );
                                if let Err(e) =
                                    seed_root_template_cowfs(&fs, &root_tpl, &blobs).await
                                {
                                    let _ = fs.close_clean().await;
                                    return Err(e);
                                }
                                if let NativeRootSpec::CowFs {
                                    ref mut volume_uuid,
                                    ..
                                } = profile_m.root
                                {
                                    *volume_uuid = Some(uuid.clone());
                                }
                                let _ = persist_boot_profile(&state_dir_m, &profile_m);
                                (fs, uuid, true)
                            }
                            Some(uuid) => {
                                let vid = VolumeId(uuid.clone());
                                let mode = if ro {
                                    CowFsOpenMode::ReadOnly
                                } else {
                                    CowFsOpenMode::ReadWrite(writer_mode)
                                };
                                let cfg = CowFsConfig::local_native(Rc::clone(&clk))
                                    .with_subvol(&opts.subvol)
                                    .with_defer_orphan_reap(!ro);
                                let fs = Rc::new(
                                    CowFs::open(Rc::clone(&hs), Rc::clone(&ps), vid, mode, cfg)
                                        .await?,
                                );
                                let mounted_head = fs.current_head();
                                match os_cowfs::fsck::verify_head(&*hs, &*ps, &mounted_head).await {
                                    Ok(rep) if rep.ok => {}
                                    Ok(_) => {
                                        let _ = fs.close_clean().await;
                                        return Err(Errno::EIO);
                                    }
                                    Err(e) => {
                                        let _ = fs.close_clean().await;
                                        return Err(e);
                                    }
                                }
                                if !ro && let Err(e) = fs.reap_orphans().await {
                                    let _ = fs.close_clean().await;
                                    return Err(e);
                                }
                                let actual_uuid = fs.volume_id().0.clone();
                                (fs, actual_uuid, false)
                            }
                        };

                        // Update `/dev/vd0` and `/run/os/root` for the live mounted root `CowFs`!
                        let vol_dev = Rc::new(CowFsVolumeDevice::from_mounted(Rc::clone(&fs)));
                        if source == "/dev/vd0" || root_cf_m.borrow().is_none() {
                            let _ = vblk_m.replace_named(
                                "vd0",
                                Rc::clone(&vol_dev) as Rc<dyn vfs::vblk::VolumeDevice>,
                            );
                            let mut rcred = Cred::root();
                            rcred.umask = 0;
                            let _ = dev_m.unlink(&rcred, &dev_m.root(), "vd0").await;
                            let _ = dev_m
                                .mknod(&rcred, &dev_m.root(), "vd0", 0o660, "vblk:vd0")
                                .await;
                            // Write `/run/os/root` onto `/run` so `early_init` sees the provisioned
                            // `volume_uuid`, `forked_from`, and `base_epoch` immediately!
                            let head = fs.current_head();
                            let root_meta_json = serde_json::to_vec_pretty(&json!({
                                "fstype": "cowfs",
                                "volume_uuid": vol_uuid,
                                "forked_from": fs.forked_from().map(|v| v.0),
                                "base_epoch": head.epoch,
                                "ephemeral_if_unmodified": head.ephemeral_if_unmodified,
                                "writer_mode": if opts.excl { "exclusive" } else { "fork_on_busy" },
                                "first_boot_seeded": first_seeded,
                                "mounted_at": (clk)().sec,
                            }))
                            .unwrap_or_default();
                            let os_dir = match run_m.lookup(&rcred, &run_m.root(), "os").await {
                                Ok(e) => Ok(e.handle),
                                Err(_) => run_m
                                    .mkdir(&rcred, &run_m.root(), "os", 0o755)
                                    .await
                                    .map(|e| e.handle),
                            };
                            if let Ok(os_h) = os_dir {
                                let _ = run_m.unlink(&rcred, &os_h, "root").await;
                                let mut o = OpenOptions::new();
                                o.write(true).create(true).truncate(true);
                                if let Ok((ent, open)) =
                                    run_m.create(&rcred, &os_h, "root", 0o444, &o).await
                                {
                                    let _ = run_m
                                        .write_at(&open, &root_meta_json, WriteAt::Offset(0))
                                        .await;
                                    let _ = run_m.release(&open).await;
                                    let _ = run_m
                                        .setattr(
                                            &rcred,
                                            &ent.handle,
                                            &SetAttr {
                                                mode: Some(0o444),
                                                uid: Some(0),
                                                gid: Some(0),
                                                ..SetAttr::default()
                                            },
                                        )
                                        .await;
                                }
                            }
                            *root_cf_m.borrow_mut() = Some(Rc::clone(&fs));
                            *root_uuid_m.borrow_mut() = Some(vol_uuid);
                        }
                        mounts_m.borrow_mut().push(Rc::clone(&fs));

                        let root = fs.root();
                        let backing = Rc::new(
                            MountBacking::new(fs as Rc<dyn Filesystem>, FsType::Cowfs)
                                .with_ceilings(ro, false)
                                .with_volume_device(vol_dev),
                        );
                        Ok(MountedFs {
                            backing,
                            root,
                            root_in_fs: "/".to_string(),
                        })
                    })
                },
            );
        }

        // Register `FsType::Image` mounter for Stage 2 `/sysroot/usr` (`source == "release-v2"`).
        {
            let base_img = release.base.clone();
            let ext_imgs = release.extensions.clone();
            let blobs = release.blobs.clone();
            let clk = Rc::clone(&clock);
            factory.register_system_mounter(FsType::Image, move |cred, source, _flags, _data| {
                if cred.identity.id != 0 {
                    return Err(Errno::EPERM);
                }
                if source != "release-v2" && source != "usr" {
                    return Err(Errno::ENOENT);
                }
                let entries = compose_system_image_entries(&base_img, &ext_imgs)
                    .map_err(|_| Errno::EINVAL)?;
                let img_fs = ImageFs::new(
                    FsId("image:stage2-usr".to_string()),
                    true,
                    (clk)(),
                    entries,
                    blobs.clone(),
                )?;
                let usr_root = img_fs.handle_at("/usr").ok_or(Errno::ENOENT)?;
                let backing = Rc::new(
                    MountBacking::new(Rc::new(img_fs), FsType::Image).with_ceilings(true, false),
                );
                Ok(MountedFs {
                    backing,
                    root: usr_root,
                    root_in_fs: "/usr".to_string(),
                })
            });
        }

        // Register async `FsType::TmpFs` mounter so `--root ephemeral` (`source == "ephemeral"`)
        // seeds `Kind::RootTemplate` onto a fresh in-memory root `tmpfs`, while normal `tmpfs`
        // mounts (like `/sysroot/tmp`) honor `mode=01777` etc.
        {
            let root_tpl = release.root_template.clone();
            let blobs = release.blobs.clone();
            let tmpfs_counter = Rc::new(Cell::new(10u64));
            factory.register_async_system_mounter(
                FsType::TmpFs,
                move |cred, source, flags, data| {
                    let root_tpl = root_tpl.clone();
                    let blobs = blobs.clone();
                    let dev_id = tmpfs_counter.get();
                    tmpfs_counter.set(dev_id + 1);
                    let uid = cred.identity.id;
                    let gid = cred.identity.group;
                    Box::pin(async move {
                        let mut mode = 0o1777u16;
                        if let Some(opts) = data.as_deref() {
                            for item in opts.split(',').filter(|s| !s.is_empty()) {
                                if let Some(m) = item.strip_prefix("mode=")
                                    && let Ok(parsed) = u16::from_str_radix(m, 8)
                                {
                                    mode = parsed & 0o7777;
                                }
                            }
                        }
                        let mem = Rc::new(MemFs::new(
                            FsId(format!("tmpfs:{source}:{dev_id}")),
                            dev_id,
                            if source == "ephemeral" { 0 } else { uid },
                            if source == "ephemeral" { 0 } else { gid },
                            if source == "ephemeral" { 0o755 } else { mode },
                            Box::new(|| {
                                let ts = now_timespec();
                                (ts.sec, ts.nsec)
                            }),
                        ));
                        if source == "ephemeral" {
                            populate_stage1_tmpfs(&mem, &root_tpl, &blobs).await?;
                        }
                        let root = mem.root();
                        let backing = Rc::new(
                            MountBacking::new(mem as Rc<dyn Filesystem>, FsType::TmpFs)
                                .with_ceilings(flags.rdonly, false),
                        );
                        Ok(MountedFs {
                            backing,
                            root,
                            root_in_fs: "/".to_string(),
                        })
                    })
                },
            );
        }

        let root_backing = Rc::new(MountBacking::new(
            stage1_fs as Rc<dyn Filesystem>,
            FsType::TmpFs,
        ));
        let vfs = Vfs::boot(&instance_id, root_backing, "initramfs", factory)
            .await
            .map_err(|e| format!("Vfs::boot: {e:?}"))?;

        // Wire 100% local `ProcBridge` hooks.
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

        // 3. `/proc` (100% local).
        let proc_fs = Rc::new(ProcFs::new(
            FsId("proc".to_string()),
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
        .await
        .map_err(|e| format!("mount /proc: {e:?}"))?;

        // 4. Local `/dev` and `/dev/pts`.
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
        .await
        .map_err(|e| format!("mount /dev: {e:?}"))?;

        let dev_pts = Rc::new(DevPtsFs::new(
            FsId("devpts".to_string()),
            1,
            Box::new(|| {
                let ts = now_timespec();
                (ts.sec, ts.nsec)
            }),
            DefaultDeviceBackend,
        ));
        let pts_backing = Rc::new(MountBacking::new(
            Rc::clone(&dev_pts) as Rc<dyn Filesystem>,
            FsType::DevPts,
        ));
        vfs.mount_on_namespace(
            &sys_ns,
            &root_cred,
            pts_backing,
            None,
            "devpts",
            "/dev/pts",
            MountFlags {
                nosuid: true,
                noexec: true,
                ..MountFlags::default()
            },
            mount_flags::MS_NOSUID | mount_flags::MS_NOEXEC,
            None,
        )
        .await
        .map_err(|e| format!("mount /dev/pts: {e:?}"))?;

        // 5. `/run` (`tmpfs` carrying `/run/os/boot-profile.json`, `/run/os/root`, sockets).
        let run_backing = Rc::new(MountBacking::new(run_fs, FsType::TmpFs));
        vfs.mount_on_namespace(
            &sys_ns,
            &root_cred,
            run_backing,
            None,
            "tmpfs",
            "/run",
            MountFlags {
                nosuid: true,
                nodev: true,
                ..MountFlags::default()
            },
            mount_flags::MS_NOSUID | mount_flags::MS_NODEV,
            None,
        )
        .await
        .map_err(|e| format!("mount /run: {e:?}"))?;

        // 6. Stage 1 `/usr` (`ro,nodev` `ImageFs` from signed `Kind::Initramfs`).
        let s1_usr_entries = image_to_vfs_entries(&release.initramfs);
        let s1_usr_fs = ImageFs::new(
            FsId("image:stage1-usr".to_string()),
            true,
            boot_ts,
            s1_usr_entries,
            release.blobs.clone(),
        )
        .map_err(|e| format!("stage1 ImageFs: {e:?}"))?;
        if let Some(h) = s1_usr_fs.handle_at("/usr") {
            let usr_backing = Rc::new(
                MountBacking::new(Rc::new(s1_usr_fs), FsType::Image).with_ceilings(true, false),
            );
            vfs.mount_on_namespace(
                &sys_ns,
                &root_cred,
                usr_backing,
                Some((h, "/usr".to_string())),
                "initramfs-usr",
                "/usr",
                MountFlags {
                    rdonly: true,
                    nodev: true,
                    ..MountFlags::default()
                },
                mount_flags::MS_RDONLY | mount_flags::MS_NODEV,
                None,
            )
            .await
            .map_err(|e| format!("mount stage1 /usr: {e:?}"))?;
        }

        // 7. Write `/run/os/boot-profile.json` (`0444`).
        let _ = vfs.mkdirat(1, StartAnchor::Root, "/run/os", 0o755).await;
        let profile_bytes =
            serde_json::to_vec_pretty(&boot_profile).map_err(|e| format!("profile json: {e}"))?;
        write_file_on_vfs(&vfs, BOOT_PROFILE_PATH, &profile_bytes, 0o444)
            .await
            .map_err(|e| format!("write {BOOT_PROFILE_PATH}: {e:?}"))?;

        let pid1_sig = SignalControl::new();
        let mut sig_ctrls = HashMap::new();
        sig_ctrls.insert(1, Arc::clone(&pid1_sig));

        let exportd_sha256 = release
            .base
            .entries
            .iter()
            .find(|e| e.path == "/usr/bin/exportd" || e.path == "/usr/bin/exportd.wasm")
            .and_then(|e| match &e.node {
                Node::File { sha256, .. } => Some(sha256.clone()),
                _ => None,
            });
        let init_sha256 = release
            .base
            .entries
            .iter()
            .find(|e| e.path == "/usr/bin/init" || e.path == "/usr/bin/init.wasm")
            .and_then(|e| match &e.node {
                Node::File { sha256, .. } => Some(sha256.clone()),
                _ => None,
            });
        let kubelet_sha256 = release
            .base
            .entries
            .iter()
            .find(|e| e.path == "/usr/bin/kubelet" || e.path == "/usr/bin/kubelet.wasm")
            .and_then(|e| match &e.node {
                Node::File { sha256, .. } => Some(sha256.clone()),
                _ => None,
            });

        let actor = Self {
            instance_id,
            state_dir,
            release: Some(release),
            boot_profile,
            vfs,
            proc_table,
            accounts: LocalAccountStore::new(),
            head_store,
            pack_store,
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
            exportd_sha256,
            init_pids: HashSet::new(),
            init_sha256,
            kubelet_pids: HashSet::new(),
            kubelet_sha256,
            sig_ctrls,
            rights_side_table: HashMap::new(),
            next_rights_handle: 1,
            wake,
            ptys,
            clock,
            closed: false,
        };

        // Load `/init` (`early_init.wasm`) for PID 1.
        let pid1_image = actor
            .load_executable(
                1,
                "/init",
                vec!["/init".to_string()],
                vec![
                    "PATH=/usr/bin:/bin:/sbin".to_string(),
                    "OS_BOOT_STAGE=1".to_string(),
                ],
                false,
            )
            .await
            .map_err(|e| format!("load Stage 1 /init: {e:?}"))?;

        Ok((actor, pid1_sig, pid1_image))
    }

    fn anchor_to_start(anchor: KAnchor) -> StartAnchor {
        match anchor {
            KAnchor::Root => StartAnchor::Root,
            KAnchor::Cwd => StartAnchor::AtFdCwd,
            KAnchor::Kfd(fd) => StartAnchor::DirFd(fd),
        }
    }

    fn peer_cred_for(&self, pid: u32) -> Result<PeerCred, Errno> {
        let tbl = self.proc_table.borrow();
        let snap = tbl.proc_snapshot(pid).ok_or(Errno::ESRCH)?;
        Ok(PeerCred {
            pid: snap.pid,
            uid: snap.uid,
            gid: snap.gid,
        })
    }

    fn identity_for(&self, pid: u32) -> Result<Identity, Errno> {
        self.vfs.process_cred(pid).map(|c| c.identity).or_else(|_| {
            let tbl = self.proc_table.borrow();
            let snap = tbl.proc_snapshot(pid).ok_or(Errno::ESRCH)?;
            Ok(Identity {
                id: snap.uid,
                group: snap.gid,
                groups: BTreeSet::from([snap.gid]),
            })
        })
    }

    fn deliver_signals(&self, deliveries: Vec<os_kernel::proc_table::SignalDelivery>) {
        let mut any = false;
        for d in deliveries {
            if let Some(ctrl) = self.sig_ctrls.get(&d.pid) {
                ctrl.deliver(d.signal);
                any = true;
            }
        }
        if any {
            self.wake.notify();
        }
    }

    fn effective_memory_limit(&self, cgroup: &str) -> Option<u64> {
        let tbl = self.proc_table.borrow();
        let mut best: Option<u64> = None;
        for anc in os_kernel::local_cgroups::ancestors(cgroup) {
            if let Ok(val) = tbl.cgroup_stat(&anc)
                && let Some(lim) = val.get("memory_max").and_then(|v| v.as_u64())
                && lim > 0
            {
                best = Some(best.map_or(lim, |b| b.min(lim)));
            }
        }
        best
    }

    async fn load_executable(
        &self,
        pid: u32,
        file: &str,
        argv: Vec<String>,
        env: Vec<String>,
        search: bool,
    ) -> Result<LoadedImage, Errno> {
        let path_env = env
            .iter()
            .find_map(|e| e.strip_prefix("PATH="))
            .map(str::to_string);
        let resolved = self
            .vfs
            .resolve_exec(pid, file, argv, path_env.as_deref(), search)
            .await?;
        let cred = self.vfs.process_cred(pid)?;
        let size = resolved.entry.metadata.size;
        if size > abi::EXEC_MAX {
            let _ = resolved.file.close().await;
            return Err(Errno::EFBIG);
        }
        let mut raw = Vec::with_capacity(size as usize);
        let mut off = 0u64;
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            match resolved.file.read_at_as(&cred, &mut buf, off).await {
                Ok(0) => break,
                Ok(n) => {
                    raw.extend_from_slice(&buf[..n]);
                    off += n as u64;
                }
                Err(e) => {
                    let _ = resolved.file.close().await;
                    return Err(e);
                }
            }
        }
        let _ = resolved.file.close().await;

        if raw.starts_with(b"\x7fELF") || !raw.starts_with(b"\0asm") {
            return Err(Errno::ENOEXEC);
        }

        let raw_sha256 = os_image::digest(&raw);
        let (wasm_bytes, is_rv1) = match self
            .release
            .as_ref()
            .map(|r| r.load_rv1_for_raw_sha256(&raw_sha256))
            .transpose()?
            .flatten()
        {
            Some(rv1) => (rv1, true),
            None => (raw, false),
        };
        let cgroup = self
            .proc_table
            .borrow()
            .proc_snapshot(pid)
            .map(|s| s.cgroup)
            .unwrap_or_else(|| "/".to_string());
        let memory_limit_bytes = self.effective_memory_limit(&cgroup);

        Ok(LoadedImage {
            resolved_path: resolved.resolved_path,
            argv: resolved.argv,
            env,
            raw_sha256,
            wasm_bytes,
            is_rv1,
            memory_limit_bytes,
        })
    }

    fn encode_rights_fd(&mut self, pid: u32, rfd: RightsFd) -> Result<InFlightFd, Errno> {
        match rfd {
            RightsFd::Kfd {
                kfd,
                is_dir,
                path_only,
                readable,
                writable,
                append,
                device,
                ..
            } => {
                let file = self.vfs.get_file(pid, kfd)?;
                Ok(InFlightFd::VfsFile {
                    file,
                    origin_pid: pid,
                    origin_token: None,
                    picker: None,
                    is_dir,
                    mount_ns: false,
                    device,
                    read: readable,
                    writable,
                    append,
                    path_only,
                })
            }
            RightsFd::UnixSock { sock_id, .. } => Ok(InFlightFd::UnixSocket(sock_id as SockId)),
            other @ (RightsFd::Pipe { .. }
            | RightsFd::PtyMaster { .. }
            | RightsFd::PtySlave { .. }) => {
                let handle = self.next_rights_handle;
                self.next_rights_handle = self.next_rights_handle.wrapping_add(1).max(1);
                let (master, number, readable, writable) = match &other {
                    RightsFd::PtyMaster { pty } => (true, pty.number, true, true),
                    RightsFd::PtySlave {
                        pty,
                        readable,
                        writable,
                    } => (false, pty.number, *readable, *writable),
                    RightsFd::Pipe { handle: ph } => (false, u32::MAX, !ph.is_writer, ph.is_writer),
                    _ => unreachable!(),
                };
                self.rights_side_table.insert(handle, other);
                Ok(InFlightFd::Pty {
                    handle,
                    master,
                    number,
                    readable,
                    writable,
                })
            }
        }
    }

    fn decode_rights_fd(
        &mut self,
        receiver_pid: u32,
        cloexec: bool,
        in_fd: InFlightFd,
    ) -> Result<RightsFd, Errno> {
        match in_fd {
            InFlightFd::VfsFile {
                file,
                is_dir,
                device,
                read,
                writable,
                append,
                path_only,
                ..
            } => {
                let kfd = self.vfs.insert_file(receiver_pid, file, cloexec)?;
                Ok(RightsFd::Kfd {
                    kfd,
                    is_dir,
                    path_only,
                    readable: read,
                    writable,
                    append,
                    nonblock: false,
                    device,
                })
            }
            InFlightFd::UnixSocket(sock_id) => {
                let info = self.socks.describe(receiver_pid, sock_id)?;
                Ok(RightsFd::UnixSock {
                    sock_id: u64::from(sock_id),
                    sock_type: info.sock_type.to_raw(),
                })
            }
            InFlightFd::Pty { handle, .. } => {
                self.rights_side_table.remove(&handle).ok_or(Errno::EBADF)
            }
            _ => Err(Errno::EOPNOTSUPP),
        }
    }

    pub(crate) async fn load_executable_pub(
        &self,
        pid: u32,
        file: &str,
        argv: Vec<String>,
        env: Vec<String>,
        search: bool,
    ) -> Result<LoadedImage, Errno> {
        self.load_executable(pid, file, argv, env, search).await
    }

    pub(crate) async fn close_all_cowfs_clean_pub(&mut self) -> Result<bool, String> {
        self.close_all_cowfs_clean().await
    }

    pub(crate) async fn run_sandbox_loop(&mut self, mut rx: mpsc::UnboundedReceiver<KernelCmd>) {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                KernelCmd::Shutdown { reply } => {
                    for ctrl in self.sig_ctrls.values() {
                        ctrl.deliver(abi::SIGKILL);
                    }
                    self.wake.notify();
                    let _ = reply.send(Ok(true));
                    break;
                }
                other => {
                    self.handle_cmd(other).await;
                }
            }
        }
    }

    async fn flush_dirty_cowfs_if_due(&self) {
        let mounts: Vec<_> = self.cowfs_mounts.borrow().clone();
        for fs in mounts {
            if fs.dirty_deadline_elapsed() {
                let _ = fs.commit_tx_group().await;
            }
        }
    }

    async fn commit_all_cowfs(&self) -> Result<(), Errno> {
        let mounts: Vec<_> = self.cowfs_mounts.borrow().clone();
        for fs in mounts {
            fs.commit_tx_group().await.map(|_| ())?;
        }
        Ok(())
    }

    async fn close_all_cowfs_clean(&mut self) -> Result<bool, String> {
        if self.closed {
            return Ok(true);
        }
        self.closed = true;
        let mounts: Vec<_> = self.cowfs_mounts.borrow_mut().drain(..).collect();
        let mut all_ok = true;
        for fs in mounts {
            if let Err(e) = fs.close_clean().await {
                eprintln!("os-native: cowfs close_clean error: {e:?}");
                all_ok = false;
            }
        }
        *self.root_cowfs.borrow_mut() = None;
        Ok(all_ok)
    }

    /// Check if PID 1 has pivoted into Stage 2 (`statfs("/").f_type != TMPFS_MAGIC`) and
    /// `/run/os/boot-healthy` exists.
    async fn inspect_snapshot(&self) -> HostInspect {
        let root_f_type = self
            .vfs
            .statfs(1, StartAnchor::Root, "/")
            .await
            .map(|s| s.f_type)
            .unwrap_or(0);
        let has_stage2_init = self
            .vfs
            .statat(1, StartAnchor::Root, "/usr/bin/init", false)
            .await
            .is_ok();
        let stage = if root_f_type == fs_magic::OS_COWFS_MAGIC || has_stage2_init {
            "stage2".to_string()
        } else if root_f_type == fs_magic::TMPFS_MAGIC {
            "stage1".to_string()
        } else {
            "unknown".to_string()
        };
        let boot_healthy = self
            .vfs
            .statat(1, StartAnchor::Root, BOOT_HEALTHY_PATH, false)
            .await
            .is_ok();
        let shutdown_clean = read_vfs_file_as_root(&self.vfs, "/run/os/shutdown")
            .await
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .and_then(|v| v.get("clean").and_then(|c| c.as_bool()));
        let root_epoch = self
            .root_cowfs
            .borrow()
            .as_ref()
            .map(|fs| fs.current_head().epoch)
            .unwrap_or(0);
        HostInspect {
            instance_id: self.instance_id.clone(),
            release_id: self
                .release
                .as_ref()
                .map(|r| r.release_id.clone())
                .unwrap_or_else(|| "sandbox".to_string()),
            stage,
            boot_healthy,
            root_volume: self.root_volume_uuid.borrow().clone(),
            root_epoch,
            pids: self.proc_table.borrow().all_pids(),
            pty_numbers: self.ptys.list_numbers(),
            shutdown_clean,
        }
    }

    /// Execute one `KernelCmd` inside the single-threaded `LocalSet` Kernel Actor.
    pub async fn handle_cmd(&mut self, cmd: KernelCmd) {
        match cmd {
            KernelCmd::OpenAt {
                pid,
                anchor,
                path,
                flags,
                mode,
                cloexec,
                reply,
            } => {
                self.gui_caller.set(Some(pid));
                let res = async {
                    let kfd = self
                        .vfs
                        .openat(pid, Self::anchor_to_start(anchor), &path, flags, mode)
                        .await?;
                    if cloexec {
                        let _ = self
                            .vfs
                            .process_fds(pid)?
                            .borrow_mut()
                            .set_cloexec(kfd, true);
                    }
                    let stat = self.vfs.fstat(pid, kfd).await?;
                    let is_dir = stat.is_dir();
                    let path_only = (flags & abi::O_PATH) != 0;
                    let device = stat.rdev.clone();
                    Ok(OpenFileReply {
                        kfd,
                        is_dir,
                        path_only,
                        device,
                        stat,
                    })
                }
                .await;
                self.gui_caller.set(None);
                let _ = reply.send(res);
            }
            KernelCmd::CloseKfd { pid, kfd, reply } => {
                let res = self.vfs.close(pid, kfd).await;
                let _ = reply.send(res);
            }
            KernelCmd::DupKfd {
                pid,
                kfd,
                cloexec,
                reply,
            } => {
                let res = self.vfs.dup(pid, kfd, 0, cloexec);
                let _ = reply.send(res);
            }
            KernelCmd::SetKfdCloexec {
                pid,
                kfd,
                cloexec,
                reply,
            } => {
                let res = self
                    .vfs
                    .process_fds(pid)
                    .and_then(|t| t.borrow_mut().set_cloexec(kfd, cloexec));
                let _ = reply.send(res);
            }
            KernelCmd::GetKfdCloexec { pid, kfd, reply } => {
                let res = self
                    .vfs
                    .process_fds(pid)
                    .and_then(|t| t.borrow().get_cloexec(kfd));
                let _ = reply.send(res);
            }
            KernelCmd::SetKfdAppend {
                pid,
                kfd,
                append,
                reply,
            } => {
                let res = self.vfs.get_file(pid, kfd).map(|f| {
                    f.set_append(append);
                });
                let _ = reply.send(res);
            }
            KernelCmd::IsKfdAppend { pid, kfd, reply } => {
                let res = self.vfs.get_file(pid, kfd).map(|f| f.is_append());
                let _ = reply.send(res);
            }
            KernelCmd::ReadKfd {
                pid,
                kfd,
                offset,
                len,
                reply,
            } => {
                self.gui_caller.set(Some(pid));
                let capped = len.min(4 * 1024 * 1024);
                let mut buf = vec![0u8; capped];
                let res = match offset {
                    Some(off) => self.vfs.pread(pid, kfd, &mut buf, off).await,
                    None => self.vfs.read(pid, kfd, &mut buf).await,
                }
                .map(|n| {
                    buf.truncate(n);
                    buf
                });
                self.gui_caller.set(None);
                let _ = reply.send(res);
            }
            KernelCmd::WriteKfd {
                pid,
                kfd,
                offset,
                data,
                reply,
            } => {
                self.gui_caller.set(Some(pid));
                let res = match offset {
                    Some(off) => self.vfs.pwrite(pid, kfd, &data, off).await,
                    None => self.vfs.write(pid, kfd, &data).await,
                };
                self.gui_caller.set(None);
                let _ = reply.send(res);
            }
            KernelCmd::SeekKfd {
                pid,
                kfd,
                offset,
                whence,
                reply,
            } => {
                let from = match whence {
                    0 => {
                        if offset < 0 {
                            let _ = reply.send(Err(Errno::EINVAL));
                            return;
                        }
                        SeekFrom::Start(offset as u64)
                    }
                    1 => SeekFrom::Current(offset),
                    2 => SeekFrom::End(offset),
                    _ => {
                        let _ = reply.send(Err(Errno::EINVAL));
                        return;
                    }
                };
                let res = self.vfs.lseek(pid, kfd, from).await;
                let _ = reply.send(res);
            }
            KernelCmd::FtruncateKfd {
                pid,
                kfd,
                size,
                reply,
            } => {
                let res = self.vfs.ftruncate(pid, kfd, size).await;
                let _ = reply.send(res);
            }
            KernelCmd::FsyncKfd {
                pid,
                kfd,
                data_only,
                reply,
            } => {
                let res = if data_only {
                    self.vfs.fdatasync(pid, kfd).await
                } else {
                    self.vfs.fsync(pid, kfd).await
                };
                let _ = reply.send(res);
            }
            KernelCmd::FstatKfd { pid, kfd, reply } => {
                let res = self.vfs.fstat(pid, kfd).await;
                let _ = reply.send(res);
            }
            KernelCmd::FutimensKfd {
                pid,
                kfd,
                atime,
                mtime,
                reply,
            } => {
                let res = self
                    .vfs
                    .fsetattr(
                        pid,
                        kfd,
                        &SetAttr {
                            atime,
                            mtime,
                            ..SetAttr::default()
                        },
                    )
                    .await
                    .map(|_| ());
                let _ = reply.send(res);
            }
            KernelCmd::ReaddirKfd { pid, kfd, reply } => {
                let res = self.vfs.fd_readdir(pid, kfd).await.map(|list| {
                    list.into_iter()
                        .map(|e| ReaddirEntry {
                            name: e.name,
                            ino: e.node.ino,
                            filetype: match e.file_type {
                                FileType::Dir => crate::errno::WASI_FILETYPE_DIRECTORY,
                                FileType::File => crate::errno::WASI_FILETYPE_REGULAR_FILE,
                                FileType::Symlink => crate::errno::WASI_FILETYPE_SYMBOLIC_LINK,
                                FileType::CharDevice => {
                                    crate::errno::WASI_FILETYPE_CHARACTER_DEVICE
                                }
                                FileType::Socket => crate::errno::WASI_FILETYPE_SOCKET_STREAM,
                            },
                        })
                        .collect()
                });
                let _ = reply.send(res);
            }
            KernelCmd::StatAt {
                pid,
                anchor,
                path,
                follow,
                reply,
            } => {
                let res = self
                    .vfs
                    .statat(pid, Self::anchor_to_start(anchor), &path, follow)
                    .await;
                let _ = reply.send(res);
            }
            KernelCmd::MkdirAt {
                pid,
                anchor,
                path,
                mode,
                reply,
            } => {
                let res = self
                    .vfs
                    .mkdirat(pid, Self::anchor_to_start(anchor), &path, mode)
                    .await
                    .map(|_| ());
                let _ = reply.send(res);
            }
            KernelCmd::UnlinkAt {
                pid,
                anchor,
                path,
                rmdir,
                reply,
            } => {
                let res = self
                    .vfs
                    .unlinkat(pid, Self::anchor_to_start(anchor), &path, rmdir)
                    .await;
                let _ = reply.send(res);
            }
            KernelCmd::RenameAt {
                pid,
                from_anchor,
                from,
                to_anchor,
                to,
                noreplace,
                reply,
            } => {
                let rflags = if noreplace {
                    RenameFlags::NOREPLACE
                } else {
                    RenameFlags::empty()
                };
                let res = self
                    .vfs
                    .renameat(
                        pid,
                        Self::anchor_to_start(from_anchor),
                        &from,
                        Self::anchor_to_start(to_anchor),
                        &to,
                        rflags,
                    )
                    .await;
                let _ = reply.send(res);
            }
            KernelCmd::LinkAt {
                pid,
                from_anchor,
                from,
                to_anchor,
                to,
                follow,
                reply,
            } => {
                let res = self
                    .vfs
                    .linkat(
                        pid,
                        Self::anchor_to_start(from_anchor),
                        &from,
                        Self::anchor_to_start(to_anchor),
                        &to,
                        follow,
                    )
                    .await
                    .map(|_| ());
                let _ = reply.send(res);
            }
            KernelCmd::SymlinkAt {
                pid,
                target,
                anchor,
                path,
                reply,
            } => {
                let res = self
                    .vfs
                    .symlinkat(pid, &target, Self::anchor_to_start(anchor), &path)
                    .await
                    .map(|_| ());
                let _ = reply.send(res);
            }
            KernelCmd::ReadlinkAt {
                pid,
                anchor,
                path,
                reply,
            } => {
                let res = self
                    .vfs
                    .readlinkat(pid, Self::anchor_to_start(anchor), &path)
                    .await;
                let _ = reply.send(res);
            }
            KernelCmd::UtimensAt {
                pid,
                anchor,
                path,
                atime,
                mtime,
                follow,
                reply,
            } => {
                let res = self
                    .vfs
                    .setattrat(
                        pid,
                        Self::anchor_to_start(anchor),
                        &path,
                        &SetAttr {
                            atime,
                            mtime,
                            ..SetAttr::default()
                        },
                        follow,
                    )
                    .await
                    .map(|_| ());
                let _ = reply.send(res);
            }
            KernelCmd::Chdir { pid, path, reply } => {
                let res = self.vfs.chdir(pid, &path).await;
                let _ = reply.send(res);
            }
            KernelCmd::Fchdir { pid, kfd, reply } => {
                let res = self.vfs.fchdir(pid, kfd).await;
                let _ = reply.send(res);
            }
            KernelCmd::Getcwd { pid, reply } => {
                let res = self.vfs.getcwd(pid).await;
                let _ = reply.send(res);
            }
            KernelCmd::Chroot { pid, path, reply } => {
                let res = self.vfs.chroot(pid, &path).await;
                let _ = reply.send(res);
            }
            KernelCmd::Mount {
                pid,
                source,
                target,
                fstype,
                flags,
                data,
                reply,
            } => {
                let res = self
                    .vfs
                    .mount(
                        pid,
                        source.as_deref().unwrap_or(""),
                        &target,
                        fstype.as_deref(),
                        flags,
                        data.as_deref(),
                    )
                    .await;
                let _ = reply.send(res);
            }
            KernelCmd::Umount2 {
                pid,
                target,
                flags,
                reply,
            } => {
                let res = self.vfs.umount2(pid, &target, flags).await;
                let _ = reply.send(res);
            }
            KernelCmd::Statfs {
                pid,
                anchor,
                path,
                reply,
            } => {
                let res = self
                    .vfs
                    .statfs(pid, Self::anchor_to_start(anchor), &path)
                    .await;
                let _ = reply.send(res);
            }
            KernelCmd::Fstatfs { pid, kfd, reply } => {
                let res = self.vfs.fstatfs(pid, kfd).await;
                let _ = reply.send(res);
            }
            KernelCmd::Unshare { pid, flags, reply } => {
                let res = self.vfs.unshare(pid, flags);
                let _ = reply.send(res);
            }
            KernelCmd::Setns {
                pid,
                kfd,
                nstype,
                reply,
            } => {
                let res = self.vfs.setns(pid, kfd, nstype);
                let _ = reply.send(res);
            }
            KernelCmd::SetUmask { pid, umask, reply } => {
                let prev = self.vfs.set_umask(pid, umask & 0o777).unwrap_or(0o022);
                let _ = reply.send(prev);
            }
            KernelCmd::GuiPoll {
                pid,
                kfd,
                writing,
                reply,
            } => {
                let res = self.vfs.get_file(pid, kfd).and_then(|f| {
                    let dev = self.gui_reg.check(pid, f.open_ref())?;
                    Ok(match (dev, writing) {
                        (GuiDevice::Input, false) => self.gui_reg.ready(),
                        (GuiDevice::Display, true) => 1,
                        _ => 0,
                    })
                });
                let _ = reply.send(res);
            }

            // ---- AF_UNIX ----
            KernelCmd::SockCreate {
                pid,
                sock_type,
                nonblock,
                reply,
            } => {
                let res = (|| {
                    let st = SockType::from_raw(sock_type)?;
                    let cred = self.peer_cred_for(pid)?;
                    let id = self.socks.create(pid, st, cred)?;
                    if nonblock {
                        self.socks.set_nonblock(pid, id, true)?;
                    }
                    Ok(u64::from(id))
                })();
                let _ = reply.send(res);
            }
            KernelCmd::SockPair {
                pid,
                sock_type,
                nonblock,
                reply,
            } => {
                let res = (|| {
                    let st = SockType::from_raw(sock_type)?;
                    let cred = self.peer_cred_for(pid)?;
                    let pair = self.socks.socketpair(pid, st, cred)?;
                    if nonblock {
                        let _ = self.socks.set_nonblock(pid, pair.sock_a, true);
                        let _ = self.socks.set_nonblock(pid, pair.sock_b, true);
                    }
                    Ok((u64::from(pair.sock_a), u64::from(pair.sock_b)))
                })();
                let _ = reply.send(res);
            }
            KernelCmd::SockSetNonblock {
                pid,
                sock_id,
                nonblock,
                reply,
            } => {
                let res = self
                    .socks
                    .set_nonblock(pid, sock_id as SockId, nonblock)
                    .map(|_| ());
                let _ = reply.send(res);
            }
            KernelCmd::SockBind {
                pid,
                sock_id,
                path,
                reply,
            } => {
                let sid = sock_id as SockId;
                let res = async {
                    self.socks.begin_bind(pid, sid, &path)?;
                    match self
                        .vfs
                        .mksockat_with_parent(pid, StartAnchor::AtFdCwd, &path, 0o777)
                        .await
                    {
                        Ok((entry, pin, parent, name)) => {
                            let key = SocketInodeKey {
                                fs_id: entry.handle.fs.clone(),
                                node: entry.handle.node,
                            };
                            if let Err(e) = self.socks.finish_bind(pid, sid, key, path.clone()) {
                                self.socks.abort_bind(sid);
                                let _ = self
                                    .vfs
                                    .rollback_created_inode(
                                        pid,
                                        &pin,
                                        &parent,
                                        &name,
                                        entry.handle.node,
                                    )
                                    .await;
                                return Err(e);
                            }
                            Ok(())
                        }
                        Err(e) => {
                            self.socks.abort_bind(sid);
                            Err(e)
                        }
                    }
                }
                .await;
                self.wake.notify();
                let _ = reply.send(res);
            }
            KernelCmd::SockListen {
                pid,
                sock_id,
                backlog,
                reply,
            } => {
                let res = (|| {
                    let cred = self.peer_cred_for(pid)?;
                    self.socks.listen(pid, sock_id as SockId, backlog, cred)
                })();
                self.wake.notify();
                let _ = reply.send(res);
            }
            KernelCmd::SockAccept {
                pid,
                sock_id,
                nonblock_new,
                reply,
            } => {
                let res = (|| {
                    let cred = self.peer_cred_for(pid)?;
                    match self.socks.accept(pid, sock_id as SockId, cred) {
                        Ok(acc) => {
                            if nonblock_new {
                                let _ = self.socks.set_nonblock(pid, acc.sock_id, true);
                            }
                            Ok(Some((u64::from(acc.sock_id), acc.peer_cred)))
                        }
                        Err(Errno::EAGAIN) => Ok(None),
                        Err(e) => Err(e),
                    }
                })();
                self.wake.notify();
                let _ = reply.send(res);
            }
            KernelCmd::SockConnect {
                pid,
                sock_id,
                path,
                reply,
            } => {
                let res = async {
                    let cred = self.peer_cred_for(pid)?;
                    let entry = self
                        .vfs
                        .resolve_socket_inode(pid, StartAnchor::AtFdCwd, &path)
                        .await?;
                    let key = SocketInodeKey {
                        fs_id: entry.handle.fs.clone(),
                        node: entry.handle.node,
                    };
                    let conn = self
                        .socks
                        .connect(pid, sock_id as SockId, &key, path, cred)?;
                    Ok(conn.peer_cred)
                }
                .await;
                self.wake.notify();
                let _ = reply.send(res);
            }
            KernelCmd::SockShutdown {
                pid,
                sock_id,
                how,
                reply,
            } => {
                let res = self.socks.shutdown(pid, sock_id as SockId, how).map(|_| ());
                self.wake.notify();
                let _ = reply.send(res);
            }
            KernelCmd::SockSendMsg {
                pid,
                sock_id,
                data,
                fds,
                addr,
                flags,
                reply,
            } => {
                let _ = flags;
                let res = async {
                    let cred = self.peer_cred_for(pid)?;
                    let dest_key = if let Some(ref path) = addr {
                        let entry = self
                            .vfs
                            .resolve_socket_inode(pid, StartAnchor::AtFdCwd, path)
                            .await?;
                        Some(SocketInodeKey {
                            fs_id: entry.handle.fs.clone(),
                            node: entry.handle.node,
                        })
                    } else {
                        None
                    };
                    let mut encoded = Vec::with_capacity(fds.len());
                    let mut side_keys = Vec::new();
                    for rfd in fds {
                        match self.encode_rights_fd(pid, rfd) {
                            Ok(in_fd) => {
                                if let InFlightFd::Pty { handle, .. } = &in_fd {
                                    side_keys.push(*handle);
                                }
                                encoded.push(in_fd);
                            }
                            Err(e) => {
                                for k in side_keys {
                                    self.rights_side_table.remove(&k);
                                }
                                return Err(e);
                            }
                        }
                    }
                    let outcome = match self.socks.sendmsg(
                        pid,
                        sock_id as SockId,
                        &data,
                        encoded,
                        dest_key.as_ref(),
                        cred,
                        None,
                    ) {
                        Ok(o) => o,
                        Err(e) => {
                            for k in side_keys {
                                self.rights_side_table.remove(&k);
                            }
                            return Err(e);
                        }
                    };
                    Ok(outcome.sent)
                }
                .await;
                self.wake.notify();
                let _ = reply.send(res);
            }
            KernelCmd::SockRecvMsg {
                pid,
                sock_id,
                max_bytes,
                max_fds,
                flags,
                reply,
            } => {
                let cloexec = (flags & abi::socket::MSG_CMSG_CLOEXEC) != 0;
                let res = (|| {
                    let out = self.socks.recvmsg(
                        pid,
                        sock_id as SockId,
                        max_bytes,
                        max_fds,
                        flags,
                        None,
                    )?;
                    for dropped in out.dropped_fds {
                        if let InFlightFd::Pty { handle, .. } = dropped {
                            self.rights_side_table.remove(&handle);
                        }
                    }
                    let mut out_fds = Vec::with_capacity(out.fds.len());
                    let mut out_flags = out.out_flags;
                    for in_fd in out.fds {
                        match self.decode_rights_fd(pid, cloexec, in_fd) {
                            Ok(r) => out_fds.push(r),
                            Err(_) => out_flags |= abi::socket::MSG_CTRUNC,
                        }
                    }
                    let reported_len = if (flags & abi::socket::MSG_TRUNC) != 0 {
                        out.orig_len
                    } else {
                        out.data.len()
                    };
                    Ok(SockRecvReply {
                        data: out.data,
                        reported_len,
                        fds: out_fds,
                        peer_cred: out.peer_cred,
                        out_flags,
                    })
                })();
                self.wake.notify();
                let _ = reply.send(res);
            }
            KernelCmd::SockPeerCred {
                pid,
                sock_id,
                reply,
            } => {
                let res = self.socks.peer_cred(pid, sock_id as SockId);
                let _ = reply.send(res);
            }
            KernelCmd::SockGetsockname {
                pid,
                sock_id,
                reply,
            } => {
                let res = self.socks.getsockname(pid, sock_id as SockId);
                let _ = reply.send(res);
            }
            KernelCmd::SockGetpeername {
                pid,
                sock_id,
                reply,
            } => {
                let res = self.socks.getpeername(pid, sock_id as SockId);
                let _ = reply.send(res);
            }
            KernelCmd::SockGetsockopt {
                pid,
                sock_id,
                level,
                optname,
                reply,
            } => {
                let res = self
                    .socks
                    .getsockopt(pid, sock_id as SockId, level, optname);
                let _ = reply.send(res);
            }
            KernelCmd::SockSetsockopt {
                pid,
                sock_id,
                level,
                optname,
                val,
                reply,
            } => {
                let res = self
                    .socks
                    .setsockopt(pid, sock_id as SockId, level, optname, val)
                    .map(|_| ());
                let _ = reply.send(res);
            }
            KernelCmd::SockPoll {
                pid,
                sock_id,
                writing,
                reply,
            } => {
                let res =
                    self.socks
                        .poll(pid, sock_id as SockId, writing)
                        .map(|st| SockPollReply {
                            ready: st.ready,
                            nbytes: st.nbytes,
                            hangup: st.hangup,
                        });
                let _ = reply.send(res);
            }
            KernelCmd::SockHold {
                pid,
                sock_id,
                reply,
            } => {
                let res = self.socks.hold(pid, sock_id as SockId, 1);
                let _ = reply.send(res);
            }
            KernelCmd::SockClose {
                pid,
                sock_id,
                reply,
            } => {
                let res = self.socks.close(pid, sock_id as SockId, 1).map(|batch| {
                    for fd in batch.dropped_fds {
                        if let InFlightFd::Pty { handle, .. } = fd {
                            self.rights_side_table.remove(&handle);
                        }
                    }
                });
                self.wake.notify();
                let _ = reply.send(res);
            }

            // ---- Process / Signals / Credentials / Batch ----
            KernelCmd::SysBatch {
                pid,
                umask,
                calls,
                guest_fds,
                reply,
            } => {
                let results = self.eval_batch(pid, umask, calls, &guest_fds).await;
                let _ = reply.send(results);
            }
            KernelCmd::GetCreds { pid, reply } => {
                let res = self.eval_getcreds(pid).await;
                let _ = reply.send(res);
            }
            KernelCmd::GetProcParent {
                pid: _,
                target,
                reply,
            } => {
                let res = self
                    .proc_table
                    .borrow()
                    .proc_snapshot(target)
                    .map(|s| s.ppid)
                    .ok_or(Errno::ESRCH);
                let _ = reply.send(res);
            }
            KernelCmd::GetPgid { pid, target, reply } => {
                let res = self
                    .proc_table
                    .borrow()
                    .getpgid(HOST_LABEL, pid, target)
                    .map_err(|e| e.errno);
                let _ = reply.send(res);
            }
            KernelCmd::GetSid { pid, target, reply } => {
                let res = self
                    .proc_table
                    .borrow()
                    .getsid(HOST_LABEL, pid, target)
                    .map_err(|e| e.errno);
                let _ = reply.send(res);
            }
            KernelCmd::SetPgid {
                pid,
                target,
                pgid,
                reply,
            } => {
                let res = self
                    .proc_table
                    .borrow_mut()
                    .setpgid(HOST_LABEL, pid, target, pgid)
                    .map_err(|e| e.errno);
                let _ = reply.send(res);
            }
            KernelCmd::SetSid { pid, reply } => {
                let res = self
                    .proc_table
                    .borrow_mut()
                    .setsid(HOST_LABEL, pid)
                    .map_err(|e| e.errno);
                let _ = reply.send(res);
            }
            KernelCmd::Kill {
                pid,
                target,
                signal,
                reply,
            } => {
                let res = (|| {
                    let cred = self.identity_for(pid)?;
                    let deliveries = self
                        .proc_table
                        .borrow_mut()
                        .kill(&cred, Some(pid), Target::of(&target), signal, now_secs())
                        .map_err(|e| e.errno)?;
                    self.deliver_signals(deliveries);
                    Ok(())
                })();
                let _ = reply.send(res);
            }
            KernelCmd::KillPgrp { pgrp, signal } => {
                if pgrp != 0
                    && let Ok(deliveries) = self.proc_table.borrow_mut().kill(
                        &Identity::root(),
                        None,
                        Target::Group(pgrp),
                        signal,
                        now_secs(),
                    )
                {
                    self.deliver_signals(deliveries);
                }
            }
            KernelCmd::ReportStopped { pid, signal } => {
                let _ = self
                    .proc_table
                    .borrow_mut()
                    .report_stopped(HOST_LABEL, pid, signal);
                self.wake.notify();
            }
            KernelCmd::Waitpid {
                pid,
                target,
                options,
                host_reap,
                reply,
            } => {
                let res = if host_reap {
                    let target_pid = target.max(0) as u32;
                    let mut tbl = self.proc_table.borrow_mut();
                    match tbl.reap_init_child(HOST_LABEL, &Identity::root(), target_pid) {
                        Ok(proc) => Ok(WaitResult {
                            pid: proc.pid,
                            status: proc.status,
                            signal: proc.signal,
                            stopped: false,
                            continued: false,
                            nothing: false,
                        }),
                        Err(e) if e.errno == Errno::EAGAIN => Ok(WaitResult {
                            pid: 0,
                            status: 0,
                            signal: None,
                            stopped: false,
                            continued: false,
                            nothing: true,
                        }),
                        Err(e) => Err(e.errno),
                    }
                } else {
                    match self
                        .proc_table
                        .borrow_mut()
                        .waitpid(HOST_LABEL, pid, target, options)
                    {
                        Ok(WaitOutcome::Pending) => Ok(WaitResult {
                            pid: 0,
                            status: 0,
                            signal: None,
                            stopped: false,
                            continued: false,
                            nothing: true,
                        }),
                        Ok(WaitOutcome::Reaped(proc)) => Ok(WaitResult {
                            pid: proc.pid,
                            status: proc.status,
                            signal: proc.signal,
                            stopped: false,
                            continued: false,
                            nothing: false,
                        }),
                        Ok(WaitOutcome::Event { pid, status }) => {
                            let stopped = (status & 0xff) == 0x7f;
                            let continued = status == 0xffff;
                            let signal = stopped.then_some(((status >> 8) & 0xff) as u8);
                            Ok(WaitResult {
                                pid,
                                status,
                                signal,
                                stopped,
                                continued,
                                nothing: false,
                            })
                        }
                        Err(e) => Err(e.errno),
                    }
                };
                let _ = reply.send(res);
            }
            KernelCmd::ReserveMemory { pid, bytes, reply } => {
                let res = self
                    .proc_table
                    .borrow_mut()
                    .reserve_memory(HOST_LABEL, pid, bytes)
                    .map_err(|e| e.errno);
                let _ = reply.send(res);
            }
            KernelCmd::PrepareFork {
                parent_pid,
                fds,
                reply,
            } => {
                let res = self.prepare_fork(parent_pid, fds).await;
                let _ = reply.send(res);
            }
            KernelCmd::PrepareExec {
                pid,
                file,
                argv,
                env,
                search,
                reply,
            } => {
                let res = self.prepare_exec(pid, &file, argv, env, search).await;
                let _ = reply.send(res);
            }
            KernelCmd::PrepareSpawn { req, reply } => {
                let res = self.prepare_spawn(*req).await;
                let _ = reply.send(res);
            }
            KernelCmd::ProcessExited {
                pid,
                code,
                signal,
                reply,
            } => {
                self.handle_process_exit(pid, code, signal).await;
                let _ = reply.send(());
            }
            KernelCmd::SetTty {
                pid,
                tty,
                tty_fds,
                reply,
            } => {
                if let Some(tty_num) = tty {
                    let _ = self
                        .proc_table
                        .borrow_mut()
                        .set_tty(HOST_LABEL, pid, tty_num, tty_fds);
                }
                let _ = reply.send(());
            }
            KernelCmd::GetProcTtyInfo { pid, reply } => {
                let info = self
                    .proc_table
                    .borrow()
                    .proc_snapshot(pid)
                    .map(|s| (s.pgid, s.sid, s.tty))
                    .unwrap_or((pid, pid, None));
                let _ = reply.send(info);
            }
            KernelCmd::PtyHangup { number, pgrp, sid } => {
                self.dev_pts.close_pty(number);
                self.ptys.remove(number);
                if pgrp != 0 {
                    let d1 = self.proc_table.borrow_mut().kill(
                        &Identity::root(),
                        None,
                        Target::Group(pgrp),
                        abi::SIGHUP,
                        now_secs(),
                    );
                    if let Ok(d) = d1 {
                        self.deliver_signals(d);
                    }
                    let d2 = self.proc_table.borrow_mut().kill(
                        &Identity::root(),
                        None,
                        Target::Group(pgrp),
                        abi::SIGCONT,
                        now_secs(),
                    );
                    if let Ok(d) = d2 {
                        self.deliver_signals(d);
                    }
                }
                if sid != 0 && sid != pgrp {
                    let d1 = self.proc_table.borrow_mut().kill(
                        &Identity::root(),
                        None,
                        Target::Pid(sid),
                        abi::SIGHUP,
                        now_secs(),
                    );
                    if let Ok(d) = d1 {
                        self.deliver_signals(d);
                    }
                    let d2 = self.proc_table.borrow_mut().kill(
                        &Identity::root(),
                        None,
                        Target::Pid(sid),
                        abi::SIGCONT,
                        now_secs(),
                    );
                    if let Ok(d) = d2 {
                        self.deliver_signals(d);
                    }
                }
            }
            KernelCmd::AllocPty { pid, locked, reply } => {
                let res = self.identity_for(pid).map(|ident| {
                    let master = self.ptys.allocate_owned(ident.id, ident.group, locked);
                    self.dev_pts
                        .register_pty(master.number, ident.id, ident.group, 0o620);
                    master
                });
                let _ = reply.send(res);
            }
            KernelCmd::RegisterPty {
                number,
                uid,
                gid,
                mode,
                reply,
            } => {
                if let Some(pty) = self.ptys.get(number) {
                    pty.set_owner(uid, gid);
                }
                self.dev_pts.register_pty(number, uid, gid, mode);
                let _ = reply.send(());
            }
            KernelCmd::GetProcCredAndCtty { pid, reply } => {
                let res = self.identity_for(pid).map(|ident| {
                    let ctty = self
                        .proc_table
                        .borrow()
                        .proc_snapshot(pid)
                        .and_then(|s| s.tty);
                    (ident.id, ident.group, ctty)
                });
                let _ = reply.send(res);
            }
            KernelCmd::CommitCowfsNow { reply } => {
                let res = self.commit_all_cowfs().await;
                let _ = reply.send(res);
            }
            KernelCmd::Inspect { reply } => {
                let snap = self.inspect_snapshot().await;
                let _ = reply.send(snap);
            }
            KernelCmd::Shutdown { reply } => {
                // Terminate any remaining guest process threads cleanly before closing CowFs.
                for ctrl in self.sig_ctrls.values() {
                    ctrl.deliver(abi::SIGKILL);
                }
                self.wake.notify();
                let clean = self.close_all_cowfs_clean().await;
                let _ = reply.send(clean);
            }
        }
    }

    async fn prepare_fork(
        &mut self,
        parent_pid: u32,
        parent_fds: BTreeMap<u32, GuestFdEntry>,
    ) -> Result<PreparedFork, Errno> {
        let child = self
            .proc_table
            .borrow_mut()
            .fork(HOST_LABEL, parent_pid, false, now_secs())
            .map_err(|e| e.errno)?;
        let child_pid = child.pid;
        if let Err(e) = self.vfs.fork_process(parent_pid, child_pid, 0) {
            let _ = self.proc_table.borrow_mut().exit(
                HOST_LABEL,
                child_pid,
                1,
                Some(abi::SIGKILL),
                now_secs(),
            );
            let _ =
                self.proc_table
                    .borrow_mut()
                    .waitpid(HOST_LABEL, parent_pid, child_pid as i32, 1);
            return Err(e);
        }

        // Hold AF_UNIX sockets for the forked child; PipeHandle / PtyMasterHandle / PtySlaveHandle
        // maintain refcounts automatically via RAII Clone/Drop.
        let mut child_fds = BTreeMap::new();
        for (gfd, entry) in parent_fds {
            let new_kind = match entry.kind {
                GuestFdKind::UnixSock {
                    sock_id,
                    sock_type,
                    nonblock,
                } => {
                    if let Err(e) = self.socks.hold(child_pid, sock_id as SockId, 1) {
                        self.socks.release_process(child_pid);
                        let _ = self.vfs.exit_process(child_pid).await;
                        let _ = self.proc_table.borrow_mut().exit(
                            HOST_LABEL,
                            child_pid,
                            1,
                            Some(abi::SIGKILL),
                            now_secs(),
                        );
                        let _ = self.proc_table.borrow_mut().waitpid(
                            HOST_LABEL,
                            parent_pid,
                            child_pid as i32,
                            1,
                        );
                        return Err(e);
                    }
                    GuestFdKind::UnixSock {
                        sock_id,
                        sock_type,
                        nonblock,
                    }
                }
                other => other,
            };
            child_fds.insert(
                gfd,
                GuestFdEntry {
                    kind: new_kind,
                    cloexec: entry.cloexec,
                },
            );
        }

        let ctrl = SignalControl::new();
        self.sig_ctrls.insert(child_pid, Arc::clone(&ctrl));
        self.wake.notify();
        Ok((child_pid, ctrl, child_fds))
    }

    async fn prepare_exec(
        &mut self,
        pid: u32,
        file: &str,
        argv: Vec<String>,
        env: Vec<String>,
        search: bool,
    ) -> Result<LoadedImage, Errno> {
        let loaded = self.load_executable(pid, file, argv, env, search).await?;
        let _ = self.vfs.exec_preserve(pid).await;
        // `exec` NEVER grants `export_impersonate`; only PID 1 pivoting into Stage 2 `/usr/bin/init`
        // acquires verified `init` status.
        self.exportd_pids.remove(&pid);
        self.init_pids.remove(&pid);
        self.kubelet_pids.remove(&pid);
        if pid == 1
            && loaded.resolved_path == "/usr/bin/init"
            && self
                .init_sha256
                .as_deref()
                .is_some_and(|h| h == loaded.raw_sha256)
        {
            self.init_pids.insert(1);
        }
        let cwd = self.vfs.getcwd(pid).await.ok();
        let _ = self
            .proc_table
            .borrow_mut()
            .reexec(
                HOST_LABEL,
                pid,
                ReexecSpec {
                    path: loaded.resolved_path.clone(),
                    argv: loaded.argv.clone(),
                    env: loaded.env.clone(),
                    cwd,
                    runtime: Some(
                        if self.release.is_none() {
                            "resources-v1:wasmtime"
                        } else {
                            "wasmtime"
                        }
                        .to_string(),
                    ),
                    cloud_access: false,
                    new_remote: None,
                },
                now_secs(),
            )
            .map_err(|e| e.errno)?;
        // Once PID 1 pivots into Stage 2 `/usr/bin/init`, ensure `/run/mount/host.sock` is bound.
        // `/run/kubelet/host.sock` is bound LAZILY only when verified `/usr/bin/kubelet` runs!
        if pid == 1 {
            self.mount_host
                .ensure_bound(&self.vfs, &mut self.socks)
                .await;
        }
        self.wake.notify();
        Ok(loaded)
    }

    async fn prepare_spawn(&mut self, req: SpawnProcessReq) -> Result<PreparedSpawn, Errno> {
        let parent_pid = req.parent_pid;
        let parent_cred = self.vfs.process_cred(parent_pid)?;
        let parent_snap = self
            .proc_table
            .borrow()
            .proc_snapshot(parent_pid)
            .ok_or(Errno::ESRCH)?;

        // Resolve target credentials (honoring `ServiceGrant.user/group` for root or `host_uid` for host).
        let mut child_ident = parent_cred.identity.clone();
        if let Some(uid) = req.host_uid {
            let snap = VfsAccountFs::load(&self.vfs, &[])
                .await
                .map_err(|e| e.errno)?;
            if let Ok(pw) = self.accounts.resolve_uid(&snap, uid)
                && let Ok(id) = self.accounts.resolve_user(&snap, &pw.name)
            {
                child_ident = id;
            } else {
                child_ident = Identity {
                    id: uid,
                    group: uid,
                    groups: BTreeSet::from([uid]),
                };
            }
        }
        let parent_is_init = parent_pid == 1 || self.init_pids.contains(&parent_pid);
        if let Some(ref grant) = req.service_grant {
            if grant.export_impersonate && !parent_is_init {
                return Err(Errno::EPERM);
            }
            if parent_cred.identity.id != 0
                && (!grant.devices.is_empty()
                    || grant.mount_namespace == "isolated"
                    || grant.user.is_some()
                    || grant.group.is_some())
            {
                return Err(Errno::EPERM);
            }
            if let Some(ref user_spec) = grant.user {
                if parent_cred.identity.id != 0 {
                    return Err(Errno::EPERM);
                }
                let snap = VfsAccountFs::load(&self.vfs, &[])
                    .await
                    .map_err(|e| e.errno)?;
                if let Ok(uid_num) = user_spec.parse::<u32>() {
                    let pw = self
                        .accounts
                        .resolve_uid(&snap, uid_num)
                        .map_err(|e| e.errno)?;
                    child_ident = self
                        .accounts
                        .resolve_user(&snap, &pw.name)
                        .map_err(|e| e.errno)?;
                } else {
                    child_ident = self
                        .accounts
                        .resolve_user(&snap, user_spec)
                        .map_err(|e| e.errno)?;
                }
            }
            if let Some(ref grp_spec) = grant.group {
                if parent_cred.identity.id != 0 {
                    return Err(Errno::EPERM);
                }
                let snap = VfsAccountFs::load(&self.vfs, &[])
                    .await
                    .map_err(|e| e.errno)?;
                let groups = self.accounts.list_groups(&snap).map_err(|e| e.errno)?;
                let gid = if let Ok(gnum) = grp_spec.parse::<u32>() {
                    groups
                        .iter()
                        .find(|g| g.gid == gnum)
                        .map(|g| g.gid)
                        .ok_or(Errno::ENOENT)?
                } else {
                    groups
                        .iter()
                        .find(|g| g.name == *grp_spec)
                        .map(|g| g.gid)
                        .ok_or(Errno::ENOENT)?
                };
                child_ident.group = gid;
                child_ident.groups.insert(gid);
            }
        }

        // Allocate PID in `LocalProcessTable`.
        let child_pid = if req.host_owned {
            let mut spec = SpawnSpec::new(
                req.argv[0].clone(),
                LocalCred::local_only(child_ident.clone(), req.umask),
                HOST_LABEL,
            );
            spec.argv = req.argv.clone();
            spec.env = req.env.clone();
            spec.cwd = req.cwd.clone();
            spec.cgroup = req.cgroup.clone();
            spec.runtime = Some(
                if self.release.is_none() {
                    "resources-v1:wasmtime"
                } else {
                    "wasmtime"
                }
                .to_string(),
            );
            spec.ppid = Some(1);
            spec.pgid = req.pgroup;
            let spawned = self
                .proc_table
                .borrow_mut()
                .spawn(spec, now_secs())
                .map_err(|e| e.errno)?;
            spawned.pid
        } else {
            let forked = self
                .proc_table
                .borrow_mut()
                .fork(HOST_LABEL, parent_pid, true, now_secs())
                .map_err(|e| e.errno)?;
            let pid = forked.pid;
            if let Some(ref cg) = req.cgroup {
                let _ = self
                    .proc_table
                    .borrow_mut()
                    .cgroup_attach(&parent_cred.identity, pid, cg);
            }
            if child_ident.id != parent_cred.identity.id
                || child_ident.group != parent_cred.identity.group
            {
                let _ = self.proc_table.borrow_mut().set_authenticated_cred(
                    HOST_LABEL,
                    pid,
                    child_ident.clone(),
                    None,
                );
            }
            pid
        };

        if let Some(pg) = req.pgroup {
            let target_pg = if pg == 0 { child_pid } else { pg };
            let _ = self.proc_table.borrow_mut().setpgid(
                HOST_LABEL,
                child_pid,
                child_pid as i32,
                target_pg as i32,
            );
        }
        if req.setsid {
            let _ = self.proc_table.borrow_mut().setsid(HOST_LABEL, child_pid);
        }

        // Set up VFS context for child (fork from parent, apply privileged ServiceGrant
        // mount isolation BEFORE dropping child credentials, then apply fd redirections & load).
        if let Err(e) = self.vfs.fork_process(parent_pid, child_pid, 0) {
            let _ = self.proc_table.borrow_mut().exit(
                HOST_LABEL,
                child_pid,
                1,
                Some(abi::SIGKILL),
                now_secs(),
            );
            if req.host_owned {
                let _ = self.proc_table.borrow_mut().reap_init_child(
                    HOST_LABEL,
                    &Identity::root(),
                    child_pid,
                );
            } else {
                let _ = self.proc_table.borrow_mut().waitpid(
                    HOST_LABEL,
                    parent_pid,
                    child_pid as i32,
                    1,
                );
            }
            return Err(e);
        }

        // Helper macro-style closure for rolling back a partially created child on error.
        let mut spawn_err: Option<Errno> = None;

        // Apply `ServiceGrant` devices and isolated mount namespace + bind mounts while child
        // still inherits root (`parent_cred.identity.id == 0`) credentials!
        if let Some(ref grant) = req.service_grant {
            if !grant.devices.is_empty() {
                self.gui_reg.grant(child_pid, &grant.devices);
            }
            if grant.mount_namespace == "isolated" {
                if let Err(e) = self.vfs.unshare(child_pid, unshare_flags::CLONE_NEWNS) {
                    spawn_err = Some(e);
                } else {
                    for bm in &grant.bind_mounts {
                        let mut mflags = mount_flags::MS_BIND;
                        if bm.read_only {
                            mflags |= mount_flags::MS_RDONLY;
                        }
                        if let Err(e) = self
                            .vfs
                            .mount(child_pid, &bm.source, &bm.target, None, mflags, None)
                            .await
                        {
                            spawn_err = Some(e);
                            break;
                        }
                    }
                }
            }
        }

        let child_vfs_cred = Cred {
            identity: child_ident.clone(),
            umask: req.umask & 0o777,
            token: None,
        };
        let _ = self.vfs.set_cred(child_pid, child_vfs_cred);

        // Apply `dup_kfds` (dup2), `clear_cloexec_kfds` (`dup2(fd, fd)`), and `close_kfds`
        // (overwritten kernel fds) before `exec_preserve` closes CLOEXEC kfds.
        let mut child_fds = req.fds;
        if spawn_err.is_none() {
            for (guest_fd, src_kfd, cloexec) in req.dup_kfds {
                if let Ok(new_kfd) = self.vfs.dup(child_pid, src_kfd, 0, cloexec)
                    && let Some(entry) = child_fds.get_mut(&guest_fd)
                    && let GuestFdKind::Kfd { ref mut kfd, .. } = entry.kind
                {
                    *kfd = new_kfd;
                }
            }
            for kfd in req.clear_cloexec_kfds {
                if let Ok(tbl) = self.vfs.process_fds(child_pid) {
                    let _ = tbl.borrow_mut().set_cloexec(kfd, false);
                }
            }
            for kfd in req.close_kfds {
                let _ = self.vfs.close(child_pid, kfd).await;
            }
            // Hold inherited AF_UNIX sockets; PipeHandle / PtyMasterHandle / PtySlaveHandle
            // are RAII-counted automatically.
            for entry in child_fds.values() {
                if let GuestFdKind::UnixSock { sock_id, .. } = entry.kind
                    && let Err(e) = self.socks.hold(child_pid, sock_id as SockId, 1)
                {
                    spawn_err = Some(e);
                    break;
                }
            }
        }

        if let Some(e) = spawn_err {
            self.gui_reg.process_exit(child_pid);
            self.socks.release_process(child_pid);
            let _ = self.vfs.exit_process(child_pid).await;
            let _ = self
                .proc_table
                .borrow_mut()
                .exit(HOST_LABEL, child_pid, 127, None, now_secs());
            if req.host_owned {
                let _ = self.proc_table.borrow_mut().reap_init_child(
                    HOST_LABEL,
                    &Identity::root(),
                    child_pid,
                );
            } else {
                let _ = self.proc_table.borrow_mut().waitpid(
                    HOST_LABEL,
                    parent_pid,
                    child_pid as i32,
                    1,
                );
            }
            return Err(e);
        }

        // Close CLOEXEC kernel fds on the child.
        let _ = self.vfs.exec_preserve(child_pid).await;

        if !req.cwd.is_empty() {
            let _ = self.vfs.chdir(child_pid, &req.cwd).await;
        }
        if let Some(tty) = req.ctty.or(parent_snap.tty) {
            let tty_fds: Vec<u32> = child_fds
                .iter()
                .filter_map(|(&fd, e)| matches!(e.kind, GuestFdKind::PtySlave { .. }).then_some(fd))
                .collect();
            let _ = self
                .proc_table
                .borrow_mut()
                .set_tty(HOST_LABEL, child_pid, tty, tty_fds);
        }

        // Resolve & load executable strictly inside the child's namespace & credentials!
        let search = !req.argv[0].contains('/');
        let loaded = match self
            .load_executable(
                child_pid,
                &req.argv[0],
                req.argv.clone(),
                req.env.clone(),
                search,
            )
            .await
        {
            Ok(img) => img,
            Err(e) => {
                // Clean up ALL child resources on failed spawn (including gui_reg & Host reaper).
                self.gui_reg.process_exit(child_pid);
                self.socks.release_process(child_pid);
                let _ = self.vfs.exit_process(child_pid).await;
                let _ =
                    self.proc_table
                        .borrow_mut()
                        .exit(HOST_LABEL, child_pid, 127, None, now_secs());
                if req.host_owned {
                    let _ = self.proc_table.borrow_mut().reap_init_child(
                        HOST_LABEL,
                        &Identity::root(),
                        child_pid,
                    );
                } else {
                    let _ = self.proc_table.borrow_mut().waitpid(
                        HOST_LABEL,
                        parent_pid,
                        child_pid as i32,
                        1,
                    );
                }
                return Err(e);
            }
        };

        let child_cwd = self.vfs.getcwd(child_pid).await.ok();
        let _ = self.proc_table.borrow_mut().reexec(
            HOST_LABEL,
            child_pid,
            ReexecSpec {
                path: loaded.resolved_path.clone(),
                argv: loaded.argv.clone(),
                env: loaded.env.clone(),
                cwd: child_cwd,
                runtime: Some(
                    if self.release.is_none() {
                        "resources-v1:wasmtime"
                    } else {
                        "wasmtime"
                    }
                    .to_string(),
                ),
                cloud_access: false,
                new_remote: None,
            },
            now_secs(),
        );

        let ctrl = SignalControl::new();
        self.sig_ctrls.insert(child_pid, Arc::clone(&ctrl));
        let wants_export_impersonate = req
            .service_grant
            .as_ref()
            .is_some_and(|g| g.export_impersonate);
        if parent_is_init
            && wants_export_impersonate
            && loaded.resolved_path == "/usr/bin/exportd"
            && self
                .exportd_sha256
                .as_deref()
                .is_some_and(|h| h == loaded.raw_sha256)
        {
            self.exportd_pids.insert(child_pid);
        }
        if parent_is_init
            && loaded.resolved_path == "/usr/bin/init"
            && self
                .init_sha256
                .as_deref()
                .is_some_and(|h| h == loaded.raw_sha256)
        {
            self.init_pids.insert(child_pid);
        }
        if parent_is_init
            && req.service_grant.is_some()
            && child_ident.id == 0
            && loaded.resolved_path == "/usr/bin/kubelet"
            && self
                .kubelet_sha256
                .as_deref()
                .is_some_and(|h| h == loaded.raw_sha256)
        {
            self.kubelet_pids.insert(child_pid);
            self.kubelet_host
                .ensure_bound(&self.vfs, &mut self.socks)
                .await;
        }
        self.wake.notify();
        Ok((child_pid, ctrl, child_fds, loaded))
    }

    async fn handle_process_exit(&mut self, pid: u32, code: i32, signal: Option<u8>) {
        self.sig_ctrls.remove(&pid);
        self.exportd_pids.remove(&pid);
        self.init_pids.remove(&pid);
        self.kubelet_pids.remove(&pid);
        self.export_bridge.release_process(pid).await;
        self.gui_reg.process_exit(pid);
        let batch = self.socks.release_process(pid);
        for fd in batch.dropped_fds {
            if let InFlightFd::Pty { handle, .. } = fd {
                self.rights_side_table.remove(&handle);
            }
        }
        let _ = self.vfs.exit_process(pid).await;
        if let Ok(report) =
            self.proc_table
                .borrow_mut()
                .exit(HOST_LABEL, pid, code, signal, now_secs())
        {
            self.deliver_signals(report.signals);
        }
        self.wake.notify();
    }

    async fn eval_getcreds(&self, pid: u32) -> Result<Creds, Error> {
        let (uid, sid) = {
            let tbl = self.proc_table.borrow();
            let snap = tbl.proc_snapshot(pid).ok_or(Errno::ESRCH)?;
            (snap.uid, snap.sid)
        };
        let snap = VfsAccountFs::load(&self.vfs, &[]).await?;
        match self.accounts.build_creds(&snap, uid, sid, now_secs()) {
            Ok(creds) => Ok(creds),
            Err(e) if e.errno == Errno::ENOENT && uid == 0 => {
                // Stage 1 initramfs has no `/etc/passwd` yet; PID 1 is root.
                Ok(Creds {
                    uid: 0,
                    gid: 0,
                    groups: vec![0],
                    user: "root".into(),
                    group: "root".into(),
                    group_names: vec!["root".into()],
                    home: "/root".into(),
                    signed_in: true,
                    can_sudo: true,
                    sudo_active: true,
                })
            }
            Err(e) => Err(e),
        }
    }

    async fn eval_batch(
        &mut self,
        pid: u32,
        umask: u16,
        calls: Vec<Call>,
        guest_fds: &BTreeMap<u32, GuestFdKind>,
    ) -> Vec<abi::Return> {
        let prev_umask = self.vfs.set_umask(pid, umask & 0o777).ok();
        let mut results: Vec<abi::Return> = Vec::with_capacity(calls.len());
        let mut opened_kfds: HashMap<usize, u32> = HashMap::new();

        for (idx, call) in calls.into_iter().enumerate() {
            let res = self
                .eval_single_call(pid, idx, call, guest_fds, &mut opened_kfds)
                .await;
            results.push(res);
        }

        if let Some(prev) = prev_umask {
            let _ = self.vfs.set_umask(pid, prev);
        }
        results
    }

    fn resolve_fdref(
        fdref: FdRef,
        guest_fds: &BTreeMap<u32, GuestFdKind>,
        opened_kfds: &HashMap<usize, u32>,
    ) -> Result<u32, Errno> {
        match fdref {
            FdRef::Ref { call } => opened_kfds.get(&call).copied().ok_or(Errno::EBADF),
            FdRef::Fd(n) => {
                if n == abi::OS_FD_ROOT as u32 || n == abi::OS_FD_CWD as u32 {
                    return Ok(n);
                }
                if n >= SYS_KFD_OFFSET {
                    return Ok(n - SYS_KFD_OFFSET);
                }
                if let Some(GuestFdKind::Kfd { kfd, .. }) = guest_fds.get(&n) {
                    return Ok(*kfd);
                }
                Err(Errno::EBADF)
            }
        }
    }

    fn anchor_from_dirfd(
        dirfd: FdRef,
        guest_fds: &BTreeMap<u32, GuestFdKind>,
        opened_kfds: &HashMap<usize, u32>,
    ) -> Result<StartAnchor, Errno> {
        let raw = Self::resolve_fdref(dirfd, guest_fds, opened_kfds)?;
        if raw == abi::OS_FD_ROOT as u32 {
            Ok(StartAnchor::Root)
        } else if raw == abi::OS_FD_CWD as u32 {
            Ok(StartAnchor::AtFdCwd)
        } else {
            Ok(StartAnchor::DirFd(raw))
        }
    }

    async fn eval_single_call(
        &mut self,
        pid: u32,
        idx: usize,
        call: Call,
        guest_fds: &BTreeMap<u32, GuestFdKind>,
        opened_kfds: &mut HashMap<usize, u32>,
    ) -> abi::Return {
        match call {
            Call::Getcreds => match self.eval_getcreds(pid).await {
                Ok(c) => ret_ok(c),
                Err(e) => ret_err(e),
            },
            Call::Stat { path } => match self.vfs.statat(pid, StartAnchor::Root, &path, true).await
            {
                Ok(st) => ret_ok(st),
                Err(e) => ret_err(e),
            },
            Call::Lstat { path } => {
                match self.vfs.statat(pid, StartAnchor::Root, &path, false).await {
                    Ok(st) => ret_ok(st),
                    Err(e) => ret_err(e),
                }
            }
            Call::Getdents {
                path,
                cookie,
                count,
            } => {
                let lim = count.unwrap_or(1024).min(4096) as usize;
                match self
                    .vfs
                    .read_dir_page(pid, StartAnchor::Root, &path, cookie, lim)
                    .await
                {
                    Ok(page) => {
                        let mut out = Vec::with_capacity(page.entries.len());
                        for e in page.entries {
                            let child = if path == "/" {
                                format!("/{}", e.name)
                            } else {
                                format!("{}/{}", path.trim_end_matches('/'), e.name)
                            };
                            let st = self
                                .vfs
                                .statat(pid, StartAnchor::Root, &child, false)
                                .await
                                .ok();
                            out.push(abi::Dirent {
                                name: e.name,
                                stat: st,
                            });
                        }
                        ret_ok(out)
                    }
                    Err(e) => ret_err(e),
                }
            }
            Call::Access { path, mode } => {
                match self
                    .vfs
                    .accessat(pid, StartAnchor::Root, &path, mode, true)
                    .await
                {
                    Ok(()) => ret_ok(Value::Null),
                    Err(e) => ret_err(e),
                }
            }
            Call::Readlink { path } => {
                match self.vfs.readlinkat(pid, StartAnchor::Root, &path).await {
                    Ok(target) => ret_ok(target),
                    Err(e) => ret_err(e),
                }
            }
            Call::Mkdir { path, mode } => {
                match self.vfs.mkdirat(pid, StartAnchor::Root, &path, mode).await {
                    Ok(_) => ret_ok(Value::Null),
                    Err(e) => ret_err(e),
                }
            }
            Call::Mknod { path, mode, rdev } => {
                if let Some(dev) = rdev {
                    match self
                        .vfs
                        .mknodat(pid, StartAnchor::Root, &path, mode, &dev)
                        .await
                    {
                        Ok(_) => ret_ok(Value::Null),
                        Err(e) => ret_err(e),
                    }
                } else {
                    match self
                        .vfs
                        .openat(
                            pid,
                            StartAnchor::Root,
                            &path,
                            abi::O_CREAT | abi::O_EXCL | abi::O_WRONLY,
                            mode,
                        )
                        .await
                    {
                        Ok(fd) => {
                            let _ = self.vfs.close(pid, fd).await;
                            ret_ok(Value::Null)
                        }
                        Err(e) => ret_err(e),
                    }
                }
            }
            Call::Rmdir { path } => {
                match self.vfs.unlinkat(pid, StartAnchor::Root, &path, true).await {
                    Ok(()) => ret_ok(Value::Null),
                    Err(e) => ret_err(e),
                }
            }
            Call::Unlink { path } => {
                match self
                    .vfs
                    .unlinkat(pid, StartAnchor::Root, &path, false)
                    .await
                {
                    Ok(()) => ret_ok(Value::Null),
                    Err(e) => ret_err(e),
                }
            }
            Call::Rename {
                from,
                to,
                noreplace,
            } => {
                let rflags = if noreplace {
                    RenameFlags::NOREPLACE
                } else {
                    RenameFlags::empty()
                };
                match self
                    .vfs
                    .renameat(
                        pid,
                        StartAnchor::Root,
                        &from,
                        StartAnchor::Root,
                        &to,
                        rflags,
                    )
                    .await
                {
                    Ok(()) => ret_ok(Value::Null),
                    Err(e) => ret_err(e),
                }
            }
            Call::Link { from, to, follow } => match self
                .vfs
                .linkat(
                    pid,
                    StartAnchor::Root,
                    &from,
                    StartAnchor::Root,
                    &to,
                    follow,
                )
                .await
            {
                Ok(_) => ret_ok(Value::Null),
                Err(e) => ret_err(e),
            },
            Call::Symlink { target, path } => {
                match self
                    .vfs
                    .symlinkat(pid, &target, StartAnchor::Root, &path)
                    .await
                {
                    Ok(_) => ret_ok(Value::Null),
                    Err(e) => ret_err(e),
                }
            }
            Call::Chmod { path, mode } => match self
                .vfs
                .setattrat(
                    pid,
                    StartAnchor::Root,
                    &path,
                    &SetAttr {
                        mode: Some(mode & 0o7777),
                        ..SetAttr::default()
                    },
                    true,
                )
                .await
            {
                Ok(_) => ret_ok(Value::Null),
                Err(e) => ret_err(e),
            },
            Call::Chown {
                path,
                uid,
                gid,
                nofollow,
            } => match self
                .vfs
                .setattrat(
                    pid,
                    StartAnchor::Root,
                    &path,
                    &SetAttr {
                        uid,
                        gid,
                        ..SetAttr::default()
                    },
                    !nofollow,
                )
                .await
            {
                Ok(_) => ret_ok(Value::Null),
                Err(e) => ret_err(e),
            },
            Call::Utimens {
                path,
                atime,
                mtime,
                nofollow,
            } => match self
                .vfs
                .setattrat(
                    pid,
                    StartAnchor::Root,
                    &path,
                    &SetAttr {
                        atime,
                        mtime,
                        ..SetAttr::default()
                    },
                    !nofollow,
                )
                .await
            {
                Ok(_) => ret_ok(Value::Null),
                Err(e) => ret_err(e),
            },
            Call::Statfs { path } => match self.vfs.statfs(pid, StartAnchor::Root, &path).await {
                Ok(s) => ret_ok(s),
                Err(e) => ret_err(e),
            },
            Call::Fstatfs { fd } => match Self::resolve_fdref(fd, guest_fds, opened_kfds) {
                Ok(kfd) => match self.vfs.fstatfs(pid, kfd).await {
                    Ok(s) => ret_ok(s),
                    Err(e) => ret_err(e),
                },
                Err(e) => ret_err(e),
            },
            Call::Mount {
                source,
                target,
                fstype,
                flags,
                data,
            } => match self
                .vfs
                .mount(
                    pid,
                    &source,
                    &target,
                    fstype.as_deref(),
                    flags,
                    data.as_deref(),
                )
                .await
            {
                Ok(()) => ret_ok(Value::Null),
                Err(e) => ret_err(e),
            },
            Call::Umount2 { target, flags } => match self.vfs.umount2(pid, &target, flags).await {
                Ok(()) => ret_ok(Value::Null),
                Err(e) => ret_err(e),
            },
            Call::Chdir { path } => match self.vfs.chdir(pid, &path).await {
                Ok(()) => ret_ok(Value::Null),
                Err(e) => ret_err(e),
            },
            Call::Fchdir { fd } => match Self::resolve_fdref(fd, guest_fds, opened_kfds) {
                Ok(kfd) => match self.vfs.fchdir(pid, kfd).await {
                    Ok(()) => ret_ok(Value::Null),
                    Err(e) => ret_err(e),
                },
                Err(e) => ret_err(e),
            },
            Call::Getcwd => match self.vfs.getcwd(pid).await {
                Ok(cwd) => ret_ok(cwd),
                Err(e) => ret_err(e),
            },
            Call::Chroot { path } => match self.vfs.chroot(pid, &path).await {
                Ok(()) => ret_ok(Value::Null),
                Err(e) => ret_err(e),
            },
            Call::Unshare { flags } => match self.vfs.unshare(pid, flags) {
                Ok(()) => ret_ok(Value::Null),
                Err(e) => ret_err(e),
            },
            Call::Setns { fd, nstype } => match Self::resolve_fdref(fd, guest_fds, opened_kfds) {
                Ok(kfd) => match self.vfs.setns(pid, kfd, nstype) {
                    Ok(()) => ret_ok(Value::Null),
                    Err(e) => ret_err(e),
                },
                Err(e) => ret_err(e),
            },
            Call::OpenAt {
                dirfd,
                path,
                flags,
                mode,
            } => match Self::anchor_from_dirfd(dirfd, guest_fds, opened_kfds) {
                Ok(anchor) => match self.vfs.openat(pid, anchor, &path, flags, mode).await {
                    Ok(kfd) => {
                        opened_kfds.insert(idx, kfd);
                        let st = self.vfs.fstat(pid, kfd).await.unwrap_or_default();
                        ret_ok(abi::Opened {
                            fd: SYS_KFD_OFFSET + kfd,
                            size: st.size,
                            device: st.rdev,
                            ..abi::Opened::default()
                        })
                    }
                    Err(e) => ret_err(e),
                },
                Err(e) => ret_err(e),
            },
            Call::FstatAt {
                dirfd,
                path,
                nofollow,
            } => match Self::anchor_from_dirfd(dirfd, guest_fds, opened_kfds) {
                Ok(anchor) => match self.vfs.statat(pid, anchor, &path, !nofollow).await {
                    Ok(st) => ret_ok(st),
                    Err(e) => ret_err(e),
                },
                Err(e) => ret_err(e),
            },
            Call::MkdirAt { dirfd, path, mode } => {
                match Self::anchor_from_dirfd(dirfd, guest_fds, opened_kfds) {
                    Ok(anchor) => match self.vfs.mkdirat(pid, anchor, &path, mode).await {
                        Ok(_) => ret_ok(Value::Null),
                        Err(e) => ret_err(e),
                    },
                    Err(e) => ret_err(e),
                }
            }
            Call::UnlinkAt { dirfd, path, rmdir } => {
                match Self::anchor_from_dirfd(dirfd, guest_fds, opened_kfds) {
                    Ok(anchor) => match self.vfs.unlinkat(pid, anchor, &path, rmdir).await {
                        Ok(()) => ret_ok(Value::Null),
                        Err(e) => ret_err(e),
                    },
                    Err(e) => ret_err(e),
                }
            }
            Call::RenameAt {
                from_dirfd,
                from,
                to_dirfd,
                to,
                noreplace,
            } => {
                let rflags = if noreplace {
                    RenameFlags::NOREPLACE
                } else {
                    RenameFlags::empty()
                };
                match (
                    Self::anchor_from_dirfd(from_dirfd, guest_fds, opened_kfds),
                    Self::anchor_from_dirfd(to_dirfd, guest_fds, opened_kfds),
                ) {
                    (Ok(fa), Ok(ta)) => {
                        match self.vfs.renameat(pid, fa, &from, ta, &to, rflags).await {
                            Ok(()) => ret_ok(Value::Null),
                            Err(e) => ret_err(e),
                        }
                    }
                    (Err(e), _) | (_, Err(e)) => ret_err(e),
                }
            }
            Call::LinkAt {
                from_dirfd,
                from,
                to_dirfd,
                to,
                follow,
            } => match (
                Self::anchor_from_dirfd(from_dirfd, guest_fds, opened_kfds),
                Self::anchor_from_dirfd(to_dirfd, guest_fds, opened_kfds),
            ) {
                (Ok(fa), Ok(ta)) => match self.vfs.linkat(pid, fa, &from, ta, &to, follow).await {
                    Ok(_) => ret_ok(Value::Null),
                    Err(e) => ret_err(e),
                },
                (Err(e), _) | (_, Err(e)) => ret_err(e),
            },
            Call::SymlinkAt {
                target,
                dirfd,
                path,
            } => match Self::anchor_from_dirfd(dirfd, guest_fds, opened_kfds) {
                Ok(anchor) => match self.vfs.symlinkat(pid, &target, anchor, &path).await {
                    Ok(_) => ret_ok(Value::Null),
                    Err(e) => ret_err(e),
                },
                Err(e) => ret_err(e),
            },
            Call::ReadlinkAt { dirfd, path } => {
                match Self::anchor_from_dirfd(dirfd, guest_fds, opened_kfds) {
                    Ok(anchor) => match self.vfs.readlinkat(pid, anchor, &path).await {
                        Ok(target) => ret_ok(target),
                        Err(e) => ret_err(e),
                    },
                    Err(e) => ret_err(e),
                }
            }
            Call::UtimensAt {
                dirfd,
                path,
                atime,
                mtime,
                nofollow,
            } => match Self::anchor_from_dirfd(dirfd, guest_fds, opened_kfds) {
                Ok(anchor) => match self
                    .vfs
                    .setattrat(
                        pid,
                        anchor,
                        &path,
                        &SetAttr {
                            atime,
                            mtime,
                            ..SetAttr::default()
                        },
                        !nofollow,
                    )
                    .await
                {
                    Ok(_) => ret_ok(Value::Null),
                    Err(e) => ret_err(e),
                },
                Err(e) => ret_err(e),
            },
            Call::Getxattr {
                path,
                name,
                nofollow,
            } => match self
                .vfs
                .getxattrat(pid, StartAnchor::Root, &path, &name, !nofollow)
                .await
            {
                Ok(val) => ret_ok(abi::Bytes(val)),
                Err(e) => ret_err(e),
            },
            Call::Setxattr {
                path,
                name,
                value,
                flags,
                nofollow,
            } => {
                let xf = match flags {
                    0 => XattrFlags::empty(),
                    abi::XATTR_CREATE => XattrFlags::CREATE,
                    abi::XATTR_REPLACE => XattrFlags::REPLACE,
                    _ => return ret_err(Errno::EINVAL),
                };
                match self
                    .vfs
                    .setxattrat(
                        pid,
                        StartAnchor::Root,
                        &path,
                        &name,
                        &value.0,
                        xf,
                        !nofollow,
                    )
                    .await
                {
                    Ok(()) => ret_ok(Value::Null),
                    Err(e) => ret_err(e),
                }
            }
            Call::Listxattr { path, nofollow } => match self
                .vfs
                .listxattrat(pid, StartAnchor::Root, &path, !nofollow)
                .await
            {
                Ok(names) => ret_ok(names),
                Err(e) => ret_err(e),
            },
            Call::Removexattr {
                path,
                name,
                nofollow,
            } => match self
                .vfs
                .removexattrat(pid, StartAnchor::Root, &path, &name, !nofollow)
                .await
            {
                Ok(()) => ret_ok(Value::Null),
                Err(e) => ret_err(e),
            },
            Call::Open {
                path, flags, mode, ..
            } => {
                self.gui_caller.set(Some(pid));
                let res = self
                    .vfs
                    .openat(pid, StartAnchor::Root, &path, flags, mode)
                    .await;
                self.gui_caller.set(None);
                match res {
                    Ok(kfd) => {
                        opened_kfds.insert(idx, kfd);
                        let st = self.vfs.fstat(pid, kfd).await.unwrap_or_default();
                        ret_ok(abi::Opened {
                            fd: SYS_KFD_OFFSET + kfd,
                            size: st.size,
                            device: st.rdev,
                            ..abi::Opened::default()
                        })
                    }
                    Err(e) => ret_err(e),
                }
            }
            Call::Close { fd } | Call::Discard { fd } => {
                match Self::resolve_fdref(fd, guest_fds, opened_kfds) {
                    Ok(kfd) => match self.vfs.close(pid, kfd).await {
                        Ok(()) => ret_ok(abi::Closed::default()),
                        Err(e) => ret_err(e),
                    },
                    Err(e) => ret_err(e),
                }
            }
            Call::Fchmod { fd, mode } => match Self::resolve_fdref(fd, guest_fds, opened_kfds) {
                Ok(kfd) => match self
                    .vfs
                    .fsetattr(
                        pid,
                        kfd,
                        &SetAttr {
                            mode: Some(mode & 0o7777),
                            ..SetAttr::default()
                        },
                    )
                    .await
                {
                    Ok(_) => ret_ok(Value::Null),
                    Err(e) => ret_err(e),
                },
                Err(e) => ret_err(e),
            },
            Call::Pread {
                fd,
                path,
                offset,
                count,
            } => {
                let lim = count.min(abi::INLINE_MAX) as usize;
                let mut buf = vec![0u8; lim];
                if let Some(fdref) = fd {
                    match Self::resolve_fdref(fdref, guest_fds, opened_kfds) {
                        Ok(kfd) => match self.vfs.pread(pid, kfd, &mut buf, offset).await {
                            Ok(n) => {
                                buf.truncate(n);
                                let size = self
                                    .vfs
                                    .fstat(pid, kfd)
                                    .await
                                    .map(|s| s.size)
                                    .unwrap_or(n as u64);
                                ret_ok(abi::Data {
                                    data: abi::Bytes(buf),
                                    size,
                                })
                            }
                            Err(e) => ret_err(e),
                        },
                        Err(e) => ret_err(e),
                    }
                } else if let Some(p) = path {
                    match self
                        .vfs
                        .openat(pid, StartAnchor::Root, &p, abi::O_RDONLY, 0)
                        .await
                    {
                        Ok(kfd) => {
                            let st = self.vfs.fstat(pid, kfd).await.unwrap_or_default();
                            let r = self.vfs.pread(pid, kfd, &mut buf, offset).await;
                            let _ = self.vfs.close(pid, kfd).await;
                            match r {
                                Ok(n) => {
                                    buf.truncate(n);
                                    ret_ok(abi::Data {
                                        data: abi::Bytes(buf),
                                        size: st.size,
                                    })
                                }
                                Err(e) => ret_err(e),
                            }
                        }
                        Err(e) => ret_err(e),
                    }
                } else {
                    ret_err(Errno::EINVAL)
                }
            }
            Call::Pwrite { fd, index, data } => {
                match Self::resolve_fdref(fd, guest_fds, opened_kfds) {
                    Ok(kfd) => {
                        let off = index.saturating_mul(abi::INLINE_MAX);
                        match self.vfs.pwrite(pid, kfd, &data.0, off).await {
                            Ok(n) => ret_ok(json!({ "written": n })),
                            Err(e) => ret_err(e),
                        }
                    }
                    Err(e) => ret_err(e),
                }
            }

            // ---- Local OS Account Syscalls ----
            Call::Login {
                username,
                password,
                force,
            } => {
                let caller = match self.identity_for(pid) {
                    Ok(id) => id,
                    Err(e) => return ret_err(e),
                };
                if force && caller.id != 0 {
                    return ret_err(Errno::EPERM);
                }
                let snap = match VfsAccountFs::load(&self.vfs, &[]).await {
                    Ok(s) => s,
                    Err(e) => return ret_err(e),
                };
                let target_id = if force {
                    self.accounts.resolve_user(&snap, &username)
                } else {
                    self.accounts.authenticate(&snap, &username, &password)
                };
                match target_id {
                    Ok(ident) => {
                        self.exportd_pids.remove(&pid);
                        self.init_pids.remove(&pid);
                        self.kubelet_pids.remove(&pid);
                        let umask = self.vfs.process_cred(pid).map(|c| c.umask).unwrap_or(0o022);
                        let _ = self.proc_table.borrow_mut().set_authenticated_cred(
                            HOST_LABEL,
                            pid,
                            ident.clone(),
                            None,
                        );
                        let _ = self.vfs.set_cred(
                            pid,
                            Cred {
                                identity: ident,
                                umask,
                                token: None,
                            },
                        );
                        match self.eval_getcreds(pid).await {
                            Ok(c) => ret_ok(c),
                            Err(e) => ret_err(e),
                        }
                    }
                    Err(e) => ret_err(e),
                }
            }
            Call::Logout => ret_ok(Value::Null),
            Call::Sudo { password, revoke } => {
                let (caller, sid) = match (
                    self.identity_for(pid),
                    self.proc_table.borrow().proc_snapshot(pid),
                ) {
                    (Ok(c), Some(s)) => (c, s.sid),
                    _ => return ret_err(Errno::ESRCH),
                };
                if revoke {
                    self.accounts.sudo_revoke(caller.id, sid);
                    return ret_ok(Value::Null);
                }
                let snap = match VfsAccountFs::load(&self.vfs, &[]).await {
                    Ok(s) => s,
                    Err(e) => return ret_err(e),
                };
                let pw_opt = (!password.is_empty()).then_some(password.as_str());
                match self
                    .accounts
                    .sudo_authenticate(&snap, &caller, sid, pw_opt, now_secs())
                {
                    Ok(()) => {
                        self.exportd_pids.remove(&pid);
                        self.init_pids.remove(&pid);
                        self.kubelet_pids.remove(&pid);
                        let umask = self.vfs.process_cred(pid).map(|c| c.umask).unwrap_or(0o022);
                        let root_id = Identity::root();
                        let _ = self.proc_table.borrow_mut().set_authenticated_cred(
                            HOST_LABEL,
                            pid,
                            root_id.clone(),
                            None,
                        );
                        let _ = self.vfs.set_cred(
                            pid,
                            Cred {
                                identity: root_id,
                                umask,
                                token: None,
                            },
                        );
                        ret_ok(Value::Null)
                    }
                    Err(e) => ret_err(e),
                }
            }
            Call::Passwd {
                username,
                password,
                current_password,
                force,
            } => {
                let caller = match self.identity_for(pid) {
                    Ok(c) => c,
                    Err(e) => return ret_err(e),
                };
                let mut snap = match VfsAccountFs::load(&self.vfs, &[]).await {
                    Ok(s) => s,
                    Err(e) => return ret_err(e),
                };
                let res = self.accounts.passwd(
                    &mut snap,
                    &caller,
                    username.as_deref(),
                    current_password.as_deref(),
                    &password,
                    force,
                    random_salt(),
                );
                match res {
                    Ok(()) => match snap.flush(&self.vfs).await {
                        Ok(()) => ret_ok(Value::Null),
                        Err(e) => ret_err(e),
                    },
                    Err(e) => ret_err(e),
                }
            }
            Call::Useradd {
                name,
                create_home,
                home,
                group,
                groups,
                password,
                short_password,
            } => {
                let caller = match self.identity_for(pid) {
                    Ok(c) => c,
                    Err(e) => return ret_err(e),
                };
                let extra = home.as_deref().unwrap_or("");
                let mut snap = match VfsAccountFs::load(&self.vfs, &[extra]).await {
                    Ok(s) => s,
                    Err(e) => return ret_err(e),
                };
                let supp: Vec<String> = groups
                    .as_deref()
                    .unwrap_or("")
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect();
                let res = self.accounts.useradd(
                    &mut snap,
                    &caller,
                    UseraddReq {
                        name,
                        uid: None,
                        group,
                        groups: supp,
                        gecos: None,
                        home,
                        shell: None,
                        create_home,
                        password,
                        short_password,
                    },
                    random_salt(),
                );
                match res {
                    Ok(entry) => match snap.flush(&self.vfs).await {
                        Ok(()) => ret_ok(json!({
                            "name": entry.name,
                            "uid": entry.uid,
                            "gid": entry.gid,
                            "home": entry.home,
                        })),
                        Err(e) => ret_err(e),
                    },
                    Err(e) => ret_err(e),
                }
            }
            Call::Usermod {
                name,
                append,
                groups,
                group,
                home,
                move_home,
                rename,
                lock,
                unlock,
            } => {
                let caller = match self.identity_for(pid) {
                    Ok(c) => c,
                    Err(e) => return ret_err(e),
                };
                let extra = home.as_deref().unwrap_or("");
                let mut snap = match VfsAccountFs::load(&self.vfs, &[extra]).await {
                    Ok(s) => s,
                    Err(e) => return ret_err(e),
                };
                let supp = groups.map(|g| {
                    g.split(',')
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned)
                        .collect()
                });
                let res = self.accounts.usermod(
                    &mut snap,
                    &caller,
                    UsermodReq {
                        name,
                        rename,
                        group,
                        groups: supp,
                        append,
                        gecos: None,
                        home,
                        move_home,
                        shell: None,
                        lock,
                        unlock,
                    },
                );
                match res {
                    Ok(_) => match snap.flush(&self.vfs).await {
                        Ok(()) => ret_ok(Value::Null),
                        Err(e) => ret_err(e),
                    },
                    Err(e) => ret_err(e),
                }
            }
            Call::Userdel { name, remove, .. } => {
                let caller = match self.identity_for(pid) {
                    Ok(c) => c,
                    Err(e) => return ret_err(e),
                };
                let mut snap = match VfsAccountFs::load(&self.vfs, &[]).await {
                    Ok(s) => s,
                    Err(e) => return ret_err(e),
                };
                let res = self.accounts.userdel(&mut snap, &caller, &name, remove);
                match res {
                    Ok(()) => match snap.flush(&self.vfs).await {
                        Ok(()) => ret_ok(Value::Null),
                        Err(e) => ret_err(e),
                    },
                    Err(e) => ret_err(e),
                }
            }
            Call::Groupadd { name } => {
                let caller = match self.identity_for(pid) {
                    Ok(c) => c,
                    Err(e) => return ret_err(e),
                };
                let mut snap = match VfsAccountFs::load(&self.vfs, &[]).await {
                    Ok(s) => s,
                    Err(e) => return ret_err(e),
                };
                match self.accounts.groupadd(&mut snap, &caller, &name) {
                    Ok(_) => match snap.flush(&self.vfs).await {
                        Ok(()) => ret_ok(Value::Null),
                        Err(e) => ret_err(e),
                    },
                    Err(e) => ret_err(e),
                }
            }
            Call::Groupmod { name, new_name } => {
                let caller = match self.identity_for(pid) {
                    Ok(c) => c,
                    Err(e) => return ret_err(e),
                };
                let mut snap = match VfsAccountFs::load(&self.vfs, &[]).await {
                    Ok(s) => s,
                    Err(e) => return ret_err(e),
                };
                match self.accounts.groupmod(&mut snap, &caller, &name, &new_name) {
                    Ok(_) => match snap.flush(&self.vfs).await {
                        Ok(()) => ret_ok(Value::Null),
                        Err(e) => ret_err(e),
                    },
                    Err(e) => ret_err(e),
                }
            }
            Call::Groupdel { name } => {
                let caller = match self.identity_for(pid) {
                    Ok(c) => c,
                    Err(e) => return ret_err(e),
                };
                let mut snap = match VfsAccountFs::load(&self.vfs, &[]).await {
                    Ok(s) => s,
                    Err(e) => return ret_err(e),
                };
                match self.accounts.groupdel(&mut snap, &caller, &name) {
                    Ok(()) => match snap.flush(&self.vfs).await {
                        Ok(()) => ret_ok(Value::Null),
                        Err(e) => ret_err(e),
                    },
                    Err(e) => ret_err(e),
                }
            }
            Call::InotifyAddWatch { .. } | Call::InotifyRmWatch { .. } => ret_err(Errno::ENOSYS),

            // ---- Process / Cgroup Registry Syscalls ----
            Call::Getpid => ret_ok(pid),
            Call::Getpgid { pid: target } => {
                match self.proc_table.borrow().getpgid(HOST_LABEL, pid, target) {
                    Ok(pgid) => ret_ok(json!({ "pgid": pgid })),
                    Err(e) => ret_err(e),
                }
            }
            Call::Getsid { pid: target } => {
                match self.proc_table.borrow().getsid(HOST_LABEL, pid, target) {
                    Ok(sid) => ret_ok(json!({ "sid": sid })),
                    Err(e) => ret_err(e),
                }
            }
            Call::Setpgid { pid: target, pgid } => {
                match self
                    .proc_table
                    .borrow_mut()
                    .setpgid(HOST_LABEL, pid, target, pgid)
                {
                    Ok(()) => ret_ok(Value::Null),
                    Err(e) => ret_err(e),
                }
            }
            Call::Setsid => match self.proc_table.borrow_mut().setsid(HOST_LABEL, pid) {
                Ok(sid) => ret_ok(json!({ "sid": sid })),
                Err(e) => ret_err(e),
            },
            Call::Prctl { option, value } => {
                match self
                    .proc_table
                    .borrow_mut()
                    .prctl(HOST_LABEL, pid, option, value)
                {
                    Ok(v) => ret_ok(v),
                    Err(e) => ret_err(e),
                }
            }
            Call::ProcStopped { signal } => {
                match self
                    .proc_table
                    .borrow_mut()
                    .report_stopped(HOST_LABEL, pid, signal)
                {
                    Ok(()) => ret_ok(Value::Null),
                    Err(e) => ret_err(e),
                }
            }
            Call::Waitpid {
                pid: selector,
                options,
            } => match self
                .proc_table
                .borrow_mut()
                .waitpid(HOST_LABEL, pid, selector, options)
            {
                Ok(WaitOutcome::Pending) => ret_ok(json!({ "nothing": true })),
                Ok(WaitOutcome::Reaped(proc)) => ret_ok(proc),
                Ok(WaitOutcome::Event { pid, status }) => {
                    let stopped = (status & 0xff) == 0x7f;
                    let continued = status == 0xffff;
                    let signal = stopped.then_some(((status >> 8) & 0xff) as u8);
                    ret_ok(json!({
                        "pid": pid,
                        "stopped": stopped,
                        "continued": continued,
                        "signal": signal,
                        "status": status,
                    }))
                }
                Err(e) => ret_err(e),
            },
            Call::CgroupCreate {
                path,
                controllers,
                lifetime,
            } => {
                let cred = match self.identity_for(pid) {
                    Ok(c) => c,
                    Err(e) => return ret_err(e),
                };
                match self.proc_table.borrow_mut().cgroup_create(
                    &cred,
                    Some(pid),
                    &path,
                    controllers.as_deref(),
                    lifetime,
                ) {
                    Ok(()) => ret_ok(Value::Null),
                    Err(e) => ret_err(e),
                }
            }
            Call::CgroupRemove { path } => {
                let cred = match self.identity_for(pid) {
                    Ok(c) => c,
                    Err(e) => return ret_err(e),
                };
                match self.proc_table.borrow_mut().cgroup_remove(&cred, &path) {
                    Ok(()) => ret_ok(Value::Null),
                    Err(e) => ret_err(e),
                }
            }
            Call::CgroupSet { path, key, value } => {
                let cred = match self.identity_for(pid) {
                    Ok(c) => c,
                    Err(e) => return ret_err(e),
                };
                match self.proc_table.borrow_mut().cgroup_set(
                    &cred,
                    &path,
                    &key,
                    &value,
                    now_secs(),
                ) {
                    Ok(deliveries) => {
                        self.deliver_signals(deliveries);
                        ret_ok(Value::Null)
                    }
                    Err(e) => ret_err(e),
                }
            }
            Call::CgroupAttach { pid: target, path } => {
                let cred = match self.identity_for(pid) {
                    Ok(c) => c,
                    Err(e) => return ret_err(e),
                };
                match self
                    .proc_table
                    .borrow_mut()
                    .cgroup_attach(&cred, target, &path)
                {
                    Ok(()) => ret_ok(Value::Null),
                    Err(e) => ret_err(e),
                }
            }
            Call::CgroupStat { path } => match self.proc_table.borrow().cgroup_stat(&path) {
                Ok(v) => ret_ok(v),
                Err(e) => ret_err(e),
            },
            Call::CgroupList { path } => ret_ok(self.proc_table.borrow().cgroup_list(&path)),
            Call::Kill {
                pid: target,
                signal,
            } => {
                let cred = match self.identity_for(pid) {
                    Ok(c) => c,
                    Err(e) => return ret_err(e),
                };
                let sig = signal.unwrap_or(abi::SIGTERM);
                match self.proc_table.borrow_mut().kill(
                    &cred,
                    Some(pid),
                    Target::of(&target),
                    sig,
                    now_secs(),
                ) {
                    Ok(deliveries) => {
                        self.deliver_signals(deliveries);
                        ret_ok(Value::Null)
                    }
                    Err(e) => ret_err(e),
                }
            }
            Call::Wait { pid: target, .. } => {
                let sel = target.parse::<i32>().unwrap_or(-1);
                match self
                    .proc_table
                    .borrow_mut()
                    .waitpid(HOST_LABEL, pid, sel, 1)
                {
                    Ok(WaitOutcome::Reaped(proc)) => ret_ok(proc),
                    Ok(_) => ret_err(Errno::EAGAIN),
                    Err(e) => ret_err(e),
                }
            }

            // ---- Ioctl dispatch (FICLONE, COWFS_IOC_*, BLK_*, LOOP_*, GUI_IOC_*, PTY) ----
            Call::Ioctl { fd, request, arg } => {
                self.eval_ioctl(pid, fd, request, arg, guest_fds, opened_kfds)
                    .await
            }
        }
    }

    async fn eval_ioctl(
        &mut self,
        pid: u32,
        fd: FdRef,
        request: u32,
        arg: Value,
        guest_fds: &BTreeMap<u32, GuestFdKind>,
        opened_kfds: &HashMap<usize, u32>,
    ) -> abi::Return {
        // 1. Check PTY ioctls on guest PTY descriptors (only for real guest WASI fds < SYS_KFD_OFFSET).
        if let FdRef::Fd(gfd) = fd
            && gfd < SYS_KFD_OFFSET
            && let Some(kind) = guest_fds.get(&gfd)
        {
            match kind {
                GuestFdKind::PtyMaster { pty, .. } => {
                    return self.eval_pty_ioctl(pid, &pty.pty, true, request, arg);
                }
                GuestFdKind::PtySlave { pty, .. } => {
                    return self.eval_pty_ioctl(pid, &pty.pty, false, request, arg);
                }
                _ => {}
            }
        }

        // 2. Kernel fd ioctls (`FICLONE`, `COWFS_IOC_*`, `BLK_*`, `LOOP_*`, `GUI_IOC_*`).
        let kfd = match Self::resolve_fdref(fd, guest_fds, opened_kfds) {
            Ok(k) => k,
            Err(e) => return ret_err(e),
        };

        if request == abi::export_ctl::EXPORT_DIR_IOCTL {
            let mut call: abi::export_ctl::ExportDirCall = match serde_json::from_value(arg) {
                Ok(c) => c,
                Err(_) => return ret_err(Errno::EINVAL),
            };
            if let abi::export_ctl::ExportDirCall::AdmitLocal {
                ref mut socket_fd, ..
            } = call
            {
                let gfd = *socket_fd;
                match guest_fds.get(&gfd) {
                    Some(GuestFdKind::UnixSock { sock_id, .. }) => *socket_fd = *sock_id as u32,
                    _ => return ret_err(Errno::ENOTSOCK),
                }
            }
            let ident = match self.identity_for(pid) {
                Ok(i) => i,
                Err(e) => return ret_err(e),
            };
            let unit = NativeExportGrant {
                peer: PeerCred {
                    pid,
                    uid: ident.id,
                    gid: ident.group,
                },
                export_impersonate: self.exportd_pids.contains(&pid),
            };
            return match self
                .export_bridge
                .dispatch(&self.vfs, &self.socks, &unit, kfd, call)
                .await
            {
                Ok(v) => ret_ok(v),
                Err(e) => ret_err(e),
            };
        }

        if request == abi::FICLONE {
            let src_raw = match arg.as_u64().and_then(|v| u32::try_from(v).ok()) {
                Some(n) => n,
                None => return ret_err(Errno::EINVAL),
            };
            let src_kfd = match Self::resolve_fdref(FdRef::Fd(src_raw), guest_fds, opened_kfds) {
                Ok(k) => k,
                Err(e) => return ret_err(e),
            };
            return match self.vfs.ficlone(pid, kfd, src_kfd).await {
                Ok(()) => ret_ok(Value::Null),
                Err(e) => ret_err(e),
            };
        }

        if request == cowfs_ioctl::FICLONERANGE {
            let mut range_arg = arg.clone();
            if let Some(obj) = range_arg.as_object_mut()
                && let Some(sf) = obj.get("src_fd").cloned()
                && let Ok(src_ref) = serde_json::from_value::<FdRef>(sf)
                && let Ok(src_kfd) = Self::resolve_fdref(src_ref, guest_fds, opened_kfds)
            {
                obj.insert("src_fd".to_string(), json!(src_kfd));
            }
            let req: abi::volume::FileCloneRangeReq = match serde_json::from_value(range_arg) {
                Ok(r) => r,
                Err(_) => return ret_err(Errno::EINVAL),
            };
            return match self.vfs.ficlone_range(pid, kfd, req).await {
                Ok(()) => ret_ok(Value::Null),
                Err(e) => ret_err(e),
            };
        }

        // Check `GUI_IOC_*`.
        if (0x4755_0000..=0x4755_00ff).contains(&request) {
            return self.eval_gui_ioctl(pid, kfd, request, arg, guest_fds);
        }

        let stat = match self.vfs.fstat(pid, kfd).await {
            Ok(s) => s,
            Err(e) => return ret_err(e),
        };

        // Check `LOOP_*`.
        if matches!(
            request,
            loop_ioctl::LOOP_CTL_GET_FREE
                | loop_ioctl::LOOP_SET_FD
                | loop_ioctl::LOOP_CLR_FD
                | loop_ioctl::LOOP_GET_STATUS64
        ) || stat
            .rdev
            .as_deref()
            .is_some_and(|r| is_loop_control_rdev(r) || parse_loop_rdev(r).is_some())
        {
            let mut effective_arg = arg.clone();
            if request == loop_ioctl::LOOP_SET_FD
                && let Some(g) = arg.as_u64().and_then(|v| u32::try_from(v).ok())
                && let Ok(backing_kfd) = Self::resolve_fdref(FdRef::Fd(g), guest_fds, opened_kfds)
            {
                effective_arg = json!(backing_kfd);
            }
            let payload = serde_json::to_vec(&effective_arg).unwrap_or_default();
            return match self
                .loop_reg
                .ioctl_fd(&self.vfs, pid, kfd, request, &payload)
                .await
            {
                Ok(bytes) => {
                    let val: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                    ret_ok(val)
                }
                Err(e) => ret_err(e),
            };
        }

        // Check `COWFS_IOC_*` & `BLK_*`.
        if is_cowfs_or_blk_ioctl(request) {
            let mut effective_arg = arg.clone();
            if matches!(
                request,
                cowfs_ioctl::COWFS_IOC_SEND
                    | cowfs_ioctl::COWFS_IOC_RECEIVE
                    | cowfs_ioctl::COWFS_IOC_OCI_IMPORT
                    | cowfs_ioctl::COWFS_IOC_OCI_EXPORT
            ) && let Some(obj) = effective_arg.as_object_mut()
                && let Some(sf) = obj.get("stream_fd").cloned()
                && let Ok(stream_ref) = serde_json::from_value::<FdRef>(sf)
                && let Ok(stream_kfd) = Self::resolve_fdref(stream_ref, guest_fds, opened_kfds)
            {
                obj.insert("stream_fd".to_string(), json!(stream_kfd));
            }
            let payload = if effective_arg.is_null() {
                Vec::new()
            } else {
                serde_json::to_vec(&effective_arg).unwrap_or_default()
            };
            if stat
                .rdev
                .as_deref()
                .is_some_and(|r| parse_vblk_rdev(r).is_some())
            {
                return match self
                    .vblk
                    .ioctl_fd(&self.vfs, pid, kfd, request, &payload)
                    .await
                {
                    Ok(bytes) => {
                        let val: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                        ret_ok(val)
                    }
                    Err(e) => ret_err(e),
                };
            }
            // Mounted `CowFs` directory/file `COWFS_IOC_*`.
            if let Ok(file) = self.vfs.get_file(pid, kfd)
                && let Some(pin) = file.mount_pin()
                && let Some(vol_dev) = pin.backing().cowfs_volume_device()
                && let Ok(cred) = self.vfs.process_cred(pid)
            {
                return match VblkRegistry::dispatch_volume_ioctl(
                    &**vol_dev,
                    None,
                    Some((&self.vfs, pid)),
                    &cred,
                    file.access().reads(),
                    pin.effective_flags().rdonly,
                    request,
                    &payload,
                )
                .await
                {
                    Ok(bytes) => {
                        let val: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                        ret_ok(val)
                    }
                    Err(e) => ret_err(e),
                };
            }
            return ret_err(Errno::ENOTTY);
        }

        ret_err(Errno::ENOTTY)
    }

    fn eval_gui_ioctl(
        &mut self,
        pid: u32,
        kfd: u32,
        request: u32,
        arg: Value,
        guest_fds: &BTreeMap<u32, GuestFdKind>,
    ) -> abi::Return {
        let file = match self.vfs.get_file(pid, kfd) {
            Ok(f) => f,
            Err(e) => return ret_err(e),
        };
        let dev = match self.gui_reg.check(pid, file.open_ref()) {
            Ok(d) => d,
            Err(e) => return ret_err(e),
        };
        match request {
            gui_ioctl::INFO => {
                let versions = serde_json::from_value::<Vec<u32>>(
                    arg.get("versions").cloned().unwrap_or(json!([1])),
                )
                .unwrap_or_else(|_| vec![1]);
                let caps = serde_json::from_value::<Vec<String>>(
                    arg.get("required").cloned().unwrap_or(json!([])),
                )
                .unwrap_or_default();
                match abi::gui::negotiate(&versions, &caps) {
                    Ok(ver) => ret_ok(json!({
                        "version": ver,
                        "capabilities": abi::gui::CAPABILITIES,
                        "epoch": self.gui_reg.epoch(),
                    })),
                    Err(e) => ret_err(e),
                }
            }
            gui_ioctl::NEXT_EVENT => {
                if dev != GuiDevice::Input {
                    return ret_err(Errno::ENOTTY);
                }
                match self.gui_reg.next() {
                    Ok(ev) => ret_ok(ev),
                    Err(e) => ret_err(e),
                }
            }
            gui_ioctl::POLL => {
                if dev != GuiDevice::Input {
                    return ret_err(Errno::ENOTTY);
                }
                ret_ok(self.gui_reg.ready())
            }
            gui_ioctl::DISPLAY_CMD => {
                if dev != GuiDevice::Display {
                    return ret_err(Errno::ENOTTY);
                }
                let cmd: abi::gui::DisplayCmd = match serde_json::from_value(arg) {
                    Ok(c) => c,
                    Err(_) => return ret_err(Errno::EINVAL),
                };
                match self.gui_reg.present(cmd) {
                    Ok(()) => ret_ok(Value::Null),
                    Err(e) => ret_err(e),
                }
            }
            gui_ioctl::PEER_ROLES => {
                if dev != GuiDevice::Display {
                    return ret_err(Errno::ENOTTY);
                }
                let sock_gfd = match arg.as_u64().and_then(|v| u32::try_from(v).ok()) {
                    Some(n) => n,
                    None => return ret_err(Errno::EINVAL),
                };
                let sock_id = match guest_fds.get(&sock_gfd) {
                    Some(GuestFdKind::UnixSock { sock_id, .. }) => *sock_id as SockId,
                    _ => return ret_err(Errno::EBADF),
                };
                let peer_cred = match self.socks.peer_cred(pid, sock_id) {
                    Ok(c) => c,
                    Err(e) => return ret_err(e),
                };
                self.gui_reg.track_peer(peer_cred.pid);
                ret_ok(abi::gui::PeerGrants::default())
            }
            _ => ret_err(Errno::EOPNOTSUPP),
        }
    }

    fn eval_pty_ioctl(
        &mut self,
        pid: u32,
        pty: &Arc<crate::pty::PtyInstance>,
        is_master: bool,
        request: u32,
        arg: Value,
    ) -> abi::Return {
        match request {
            pty_ioctl::TCGETS => ret_ok(pty.termios()),
            pty_ioctl::TCSETS | pty_ioctl::TCSETSW | pty_ioctl::TCSETSF => {
                let termios: crate::pty::Termios = match serde_json::from_value(arg) {
                    Ok(t) => t,
                    Err(_) => return ret_err(Errno::EINVAL),
                };
                match pty.set_termios(termios, request == pty_ioctl::TCSETSF) {
                    Ok(()) => ret_ok(Value::Null),
                    Err(e) => ret_err(e),
                }
            }
            pty_ioctl::TIOCGWINSZ => ret_ok(pty.winsize()),
            pty_ioctl::TIOCSWINSZ => {
                let ws: crate::pty::WinSize = match serde_json::from_value(arg) {
                    Ok(w) => w,
                    Err(_) => return ret_err(Errno::EINVAL),
                };
                match pty.set_winsize(ws) {
                    Ok(()) => ret_ok(Value::Null),
                    Err(e) => ret_err(e),
                }
            }
            pty_ioctl::TIOCGPTN => {
                if !is_master {
                    return ret_err(Errno::ENOTTY);
                }
                ret_ok(pty.number)
            }
            pty_ioctl::TIOCSPTLCK => {
                if !is_master {
                    return ret_err(Errno::ENOTTY);
                }
                let lock = arg.as_i64().unwrap_or(0) != 0;
                pty.set_locked(lock);
                ret_ok(Value::Null)
            }
            pty_ioctl::TIOCGPTLCK => {
                if !is_master {
                    return ret_err(Errno::ENOTTY);
                }
                ret_ok(if pty.is_locked() { 1 } else { 0 })
            }
            pty_ioctl::TIOCGPGRP => ret_ok(json!({ "pgrp": pty.pgrp() })),
            pty_ioctl::TIOCSPGRP => {
                let pgid = match arg.as_u64().and_then(|v| u32::try_from(v).ok()) {
                    Some(p) if p > 0 => p,
                    _ => return ret_err(Errno::EINVAL),
                };
                pty.set_pgrp(pgid);
                ret_ok(Value::Null)
            }
            pty_ioctl::TIOCGSID => {
                let sid = pty.session();
                if sid == 0 {
                    ret_err(Errno::ENOTTY)
                } else {
                    ret_ok(json!({ "sid": sid }))
                }
            }
            pty_ioctl::TIOCSCTTY => {
                let snap = match self.proc_table.borrow().proc_snapshot(pid) {
                    Some(s) => s,
                    None => return ret_err(Errno::ESRCH),
                };
                if snap.sid != pid {
                    return ret_err(Errno::EPERM);
                }
                pty.set_session(snap.sid, snap.pgid);
                let _ = self.proc_table.borrow_mut().set_tty(
                    HOST_LABEL,
                    pid,
                    pty.number,
                    vec![0, 1, 2],
                );
                ret_ok(Value::Null)
            }
            pty_ioctl::TIOCNOTTY => ret_ok(Value::Null),
            _ => ret_err(Errno::ENOTTY),
        }
    }

    /// Run the single-threaded Kernel Actor event loop until `Shutdown` or channel close.
    pub async fn run_loop(mut self, mut rx: mpsc::UnboundedReceiver<KernelCmd>) {
        let mut tick_interval = tokio::time::interval(Duration::from_millis(25));
        let mut flush_interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                cmd = rx.recv() => {
                    match cmd {
                        Some(KernelCmd::Shutdown { reply }) => {
                            for ctrl in self.sig_ctrls.values() {
                                ctrl.deliver(abi::SIGKILL);
                            }
                            self.wake.notify();
                            let res = self.close_all_cowfs_clean().await;
                            let _ = reply.send(res);
                            break;
                        }
                        Some(cmd) => {
                            self.handle_cmd(cmd).await;
                        }
                        None => {
                            let _ = self.close_all_cowfs_clean().await;
                            break;
                        }
                    }
                }
                _ = tick_interval.tick() => {
                    let vol = self.root_volume_uuid.borrow().clone();
                    let m = self.mount_host.tick(&self.vfs, &mut self.socks, &self.proc_table, vol.as_deref()).await;
                    let k = self
                        .kubelet_host
                        .tick(&self.state_dir, &mut self.socks, &self.kubelet_pids)
                        .await;
                    if m || k {
                        self.wake.notify();
                    }
                }
                _ = flush_interval.tick() => {
                    self.flush_dirty_cowfs_if_due().await;
                }
            }
        }
    }
}

// Keep unused imports silent if feature flags differ.
#[allow(dead_code)]
fn _touch_imports() {
    let _ = (
        MSG_DONTWAIT,
        SOCK_STREAM,
        ProcState::Running,
        wasi_filetype_from_mode(0),
    );
}

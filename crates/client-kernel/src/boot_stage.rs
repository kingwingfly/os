//! Two-Stage Standalone Offline Boot (`#56` L3c, Blueprint §1.2, §2.2, `contract.md` §5):
//!
//! `Stage 0 -> Stage 1 initramfs (tmpfs) -> cowfsck -> os-cowfs root / ForkOnBusy -> switch_root -> Stage 2`
//!
//! Zero network RPCs, zero `RootCloudDriver`, zero `seed_from_authority`:
//! - Stage 0 verifies a local Release v2 bundle (signature, digests, monotonic generation) and
//!   creates a Stage 1 `tmpfs` `/` populated from `Kind::Initramfs`, mounting `/proc` (`ProcFs`
//!   backed 100% locally by `LocalProcessTable`), local `/dev` (`DevTmpFs` + `/dev/vdN` `VblkRegistry`,
//!   ZERO remote devices), `/dev/pts`, `/run` (`tmpfs`), and Stage 1 `/usr` (`ro,nodev`), injecting
//!   `/run/os/boot-profile.json` (`0444`), and starting PID 1 (`uid 0`, `start_time = boot_ns`)
//!   running `/init`.
//! - Stage 1 (`early_init`) verifies `COWFS_FORMAT_VERSION` FIRST (`EPROTONOSUPPORT` -> Stage 1
//!   recovery chooser; NEVER wipes or reformats user data), runs `cowfsck` pre-mount integrity
//!   check (corruption -> recovery/snapshot rollback), provisions and atomically seeds
//!   `RootTemplate` on first boot (epoch 1), or opens an existing volume (`ForkOnBusy` creates an
//!   O(1) persistent fork with `ephemeral_if_unmodified = true`; `Exclusive` fails `EBUSY` into
//!   recovery), mounts `os-cowfs` at `/sysroot`, mounts Stage 2 Release v2 `/usr` (`ro,nodev`) at
//!   `/sysroot/usr`, mounts fresh `tmpfs` (`01777`) at `/sysroot/tmp`, writes `/run/os/root`
//!   (`0444`), and executes Contract §5 `switch_root` verbatim (preserving PID 1 & `start_time`,
//!   reclaiming Stage 1 `tmpfs` strictly within `st_dev`).

use crate::cowfs_bridge::{
    CloseCleanPruneOutcome, JsCowfsStore, close_clean_with_prune_fs, cowfsck_volume_stores,
    now_timespec, open_for_boot_stores,
};
use crate::mounts::{js_errno, map_vfs_err};
use crate::release_v2::{
    VerifiedAssetBlobStore, compose_system_image_entries, image_to_vfs_entries,
    read_verified_image_file,
};
use abi::contract::{InstanceIdentity, fs_magic, mount_flags, umount_flags};
use abi::fs::{FsId, OpenOptions, SetAttr, Timespec, WriteAt};
use abi::{Errno, ProcState, S_IFDIR, S_IFREG, Stat, StatFs};
use cowfs::{CowFs, CowFsConfig, CowFsVolumeDevice};
use cowtree::{
    ArenaConfig, COWFS_FORMAT_VERSION, ForkRequest, HeadStore, PackStore, RootObject, VolumeId,
    WriterMode,
};
use image::{Image, Kind, Node};
use kernel::accounts::{
    AccountFs, LocalAccountStore, MemoryAccountFs, parse_group, parse_passwd,
};
use kernel::proc_table::{LocalCred, LocalProcessTable, ReexecSpec, SpawnSpec};
use os_core::permissions::Identity;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::rc::{Rc, Weak};
use vfs::devfs::{DefaultDeviceBackend, DevPtsFs, DevTmpFs};
use vfs::imagefs::{BlobStore, ImageFs};
use vfs::memfs::MemFs;
use vfs::procfs::{EmptyProcProvider, ProcFs, ProcMetaSnapshot};
use vfs::vblk::{VblkDeviceBackend, VblkRegistry};
use vfs::{
    Cred, DefaultFilesystemFactory, Filesystem, FsType, MountBacking, MountFlags, StartAnchor, Vfs,
};
use wasm_bindgen::prelude::*;

/// Current schema version of `/run/os/boot-profile.json` and `os-boot-profile-v1` IDB store.
pub const BOOT_PROFILE_VERSION: u32 = 1;
/// Read-only runtime path where Stage 0 injects the persisted boot profile (`0444`).
pub const BOOT_PROFILE_PATH: &str = "/run/os/boot-profile.json";
/// Read-only runtime path where Stage 1 records the active `os-cowfs` root metadata (`0444`).
pub const MOUNTED_ROOT_INFO_PATH: &str = "/run/os/root";
/// Read-only runtime path where Stage 1 writes the `cowfsck` report when verification runs (`0444`).
pub const COWFSCK_REPORT_PATH: &str = "/run/os/cowfsck.json";
/// Default Stage 2 PID 1 executable path after `switch_root`.
pub const DEFAULT_STAGE2_INIT: &str = "/usr/bin/init";

const HOST_LABEL: &str = "browser";

/// Writer lock acquisition policy stored in [`RootSpec::CowFs`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootWriterMode {
    /// If another tab holds the Web Lock, create an O(1) persistent fork (`ephemeral_if_unmodified = true`).
    #[default]
    ForkOnBusy,
    /// Fail with `EBUSY` into the Stage 1 recovery chooser if another tab holds the Web Lock.
    Exclusive,
}

impl BootWriterMode {
    pub fn to_cowtree_mode(self) -> WriterMode {
        match self {
            Self::ForkOnBusy => WriterMode::ForkOnBusy,
            Self::Exclusive => WriterMode::Exclusive,
        }
    }
}

/// Root filesystem specification persisted in the local `os-boot-profile-v1` IndexedDB store.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootSpec {
    CowFs {
        /// `None` on first boot (Stage 1 creates a new volume UUID, persists it, and seeds `RootTemplate`).
        volume_uuid: Option<String>,
        #[serde(default)]
        writer_mode: BootWriterMode,
    },
    /// Read-only immutable snapshot root (`contract.md` §1, §5; Codex Finding #32).
    Snapshot {
        volume_uuid: String,
        snapshot: String,
    },
    /// Ephemeral `tmpfs`-backed root populated from `RootTemplate` (nothing persisted to `os-cowfs`).
    Ephemeral,
    /// Legacy explicit opt-in cloud root (NOT used by standalone offline boot).
    CloudOptIn {
        #[serde(default)]
        subpath: Option<String>,
    },
}

impl Default for RootSpec {
    fn default() -> Self {
        Self::CowFs {
            volume_uuid: None,
            writer_mode: BootWriterMode::ForkOnBusy,
        }
    }
}

/// Persisted local boot profile (`os-boot-profile-v1`), injected by Stage 0 at `/run/os/boot-profile.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootProfile {
    pub version: u32,
    pub root: RootSpec,
    /// `"user"` (default) or `"root"`.
    pub default_user: String,
    /// Optional pinned Release v2 generation SHA-256 (`None` = active installed generation).
    pub generation: Option<String>,
    /// When `true`, Stage 1 pauses in the interactive recovery chooser before mounting `/sysroot`.
    pub recovery: bool,
}

impl Default for BootProfile {
    fn default() -> Self {
        Self {
            version: BOOT_PROFILE_VERSION,
            root: RootSpec::default(),
            default_user: "user".to_string(),
            generation: None,
            recovery: false,
        }
    }
}

impl BootProfile {
    pub fn validate(&self) -> vfs::Result<()> {
        if self.version != BOOT_PROFILE_VERSION {
            return Err(Errno::EPROTONOSUPPORT);
        }
        if self.default_user != "user" && self.default_user != "root" {
            return Err(Errno::EINVAL);
        }
        match &self.root {
            RootSpec::CowFs {
                volume_uuid: Some(uuid),
                ..
            } if uuid.is_empty() || uuid.len() > 128 || uuid.contains('/') || uuid.contains('\0') => {
                return Err(Errno::EINVAL);
            }
            RootSpec::Snapshot {
                volume_uuid,
                snapshot,
            } if volume_uuid.is_empty()
                || volume_uuid.len() > 128
                || volume_uuid.contains('/')
                || volume_uuid.contains('\0')
                || snapshot.is_empty()
                || snapshot.len() > 128
                || snapshot.contains('/')
                || snapshot.contains('\0') =>
            {
                return Err(Errno::EINVAL);
            }
            _ => {}
        }
        if let Some(generation) = &self.generation
            && (generation.len() != 64 || !generation.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(Errno::EINVAL);
        }
        Ok(())
    }
}

/// Metadata written atomically to `/run/os/root` (`0444`) before `switch_root`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedRootInfo {
    pub fstype: String,
    pub volume_uuid: String,
    pub forked_from: Option<String>,
    pub base_epoch: u64,
    pub ephemeral_if_unmodified: bool,
    pub first_boot_seeded: bool,
    pub writer_mode: BootWriterMode,
    pub mounted_at: u64,
}

/// Current lifecycle stage of a two-stage standalone boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootStage {
    Stage0,
    Stage1,
    Stage1Recovery,
    Stage2,
}

/// Structured reason why Stage 1 entered the recovery chooser instead of mounting `/sysroot`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RecoveryReason {
    Requested,
    IncompatibleFormat {
        found_version: Option<u32>,
        expected_version: u32,
    },
    CorruptVolume {
        detail: String,
        snapshots: Vec<String>,
    },
    VolumeBusy {
        volume_uuid: String,
    },
    AccountResolutionFailed {
        default_user: String,
        detail: String,
    },
    IoError {
        errno: String,
        detail: String,
    },
}

/// Recovery state exposed to the Stage 1 interactive recovery shell / UI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryState {
    pub reason: RecoveryReason,
    pub volume_uuid: Option<String>,
    pub available_snapshots: Vec<String>,
    pub message: String,
}

/// Snapshot of PID 1 identity and timestamps (`contract.md` §5: preserved across `switch_root`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pid1Snapshot {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub path: String,
    pub argv: Vec<String>,
    pub started: u64,
    pub started_ticks: u64,
    pub cwd: String,
}

/// Snapshot of the separate Stage 2 non-PID-1 console login process (`Codex Finding #2`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleProcSnapshot {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
    pub user: String,
    pub home: String,
    pub shell: String,
    pub cwd: String,
    pub tty: Option<String>,
}

/// Complete observable status snapshot of a [`TwoStageBoot`] instance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BootStatusSnapshot {
    pub stage: BootStage,
    pub instance_id: String,
    pub pid1: Pid1Snapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub console_proc: Option<ConsoleProcSnapshot>,
    pub boot_profile: BootProfile,
    pub mounted_root: Option<MountedRootInfo>,
    pub recovery: Option<RecoveryState>,
    pub banners: Vec<String>,
    pub fsck_report: Option<cowfs::FsckReport>,
    pub stage1_reclaimed_entries: usize,
    pub stage1_tmpfs_dropped: bool,
}

/// Parsed Release v2 images required for a standalone offline boot.
#[derive(Clone, Debug)]
pub struct ReleaseImages {
    pub initramfs: Image,
    pub root_template: Image,
    pub base: Image,
    pub extensions: Vec<Image>,
}

/// Portable two-stage standalone offline boot runtime.
///
/// Works identically over in-memory stores (`MemoryHeadStore`/`MemoryPackStore`/`MemoryBlobStore`)
/// in native Rust integration tests and over OPFS + strict IndexedDB + Web Locks (`JsCowfsStore`
/// + `VerifiedAssetBlobStore`) inside a browser Worker via [`OfflineBootRuntime`].
pub struct TwoStageBoot<
    H: HeadStore + 'static,
    P: PackStore + 'static,
    B: BlobStore + Clone + 'static,
> {
    instance_id: String,
    boot_profile: BootProfile,
    stage: BootStage,
    vfs: Vfs,
    proc_table: Rc<RefCell<LocalProcessTable>>,
    dev_fs: Rc<DevTmpFs<VblkDeviceBackend<DefaultDeviceBackend>>>,
    _dev_pts: Rc<DevPtsFs<DefaultDeviceBackend>>,
    vblk: Rc<VblkRegistry>,
    head_store: Rc<H>,
    pack_store: Rc<P>,
    blobs: B,
    release: ReleaseImages,
    cowfs: Option<Rc<CowFs<H, P>>>,
    home_cowfs: Option<Rc<dyn Filesystem>>,
    mounted_root: Option<MountedRootInfo>,
    recovery: Option<RecoveryState>,
    fsck_report: Option<cowfs::FsckReport>,
    banners: Vec<String>,
    clock_fn: Rc<dyn Fn() -> Timespec>,
    stage1_fs_weak: Weak<MemFs>,
    stage1_reclaimed_entries: usize,
    console_pid: u32,
    console_pty: Option<u32>,
    console_user: Option<String>,
    console_home: Option<String>,
    console_shell: Option<String>,
    closed: bool,
}

fn timespec_pair(clock: &Rc<dyn Fn() -> Timespec>) -> Box<dyn Fn() -> (u64, u32)> {
    let clock = Rc::clone(clock);
    Box::new(move || {
        let ts = (clock)();
        (ts.sec, ts.nsec)
    })
}

fn timespec_pair_rc(clock: &Rc<dyn Fn() -> Timespec>) -> Rc<dyn Fn() -> (u64, u32)> {
    let clock = Rc::clone(clock);
    Rc::new(move || {
        let ts = (clock)();
        (ts.sec, ts.nsec)
    })
}

fn errno_name(e: Errno) -> String {
    serde_json::to_value(e)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{e:?}"))
}

fn make_uuid() -> String {
    let hex = crate::random_hex(16);
    format!(
        "{}-{}-4{}-8{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[13..16],
        &hex[17..20],
        &hex[20..32]
    )
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
        true,
    )
    .await?;
    Ok(())
}

async fn ensure_dir_on_vfs(vfs: &Vfs, path: &str, mode: u16) -> vfs::Result<()> {
    if let Ok(st) = vfs.statat(1, StartAnchor::Root, path, false).await {
        return if st.kind() == S_IFDIR {
            Ok(())
        } else {
            Err(Errno::ENOTDIR)
        };
    }
    match vfs.mkdirat(1, StartAnchor::Root, path, mode).await {
        Ok(_) | Err(Errno::EEXIST) => Ok(()),
        Err(e) => Err(e),
    }
}

async fn read_file_as_pid(vfs: &Vfs, pid: u32, path: &str) -> vfs::Result<Vec<u8>> {
    let fd = vfs
        .openat(pid, StartAnchor::Root, path, abi::O_RDONLY, 0)
        .await?;
    let mut out = Vec::new();
    let mut off = 0u64;
    let mut chunk = vec![0u8; 65_536];
    loop {
        let n = match vfs.pread(pid, fd, &mut chunk, off).await {
            Ok(n) => n,
            Err(e) => {
                let _ = vfs.close(pid, fd).await;
                return Err(e);
            }
        };
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
        off += n as u64;
    }
    vfs.close(pid, fd).await?;
    Ok(out)
}

async fn write_file_as_pid(
    vfs: &Vfs,
    pid: u32,
    path: &str,
    bytes: &[u8],
    mode: u16,
) -> vfs::Result<usize> {
    let fd = vfs
        .openat(
            pid,
            StartAnchor::Root,
            path,
            abi::O_CREAT | abi::O_WRONLY | abi::O_TRUNC,
            mode,
        )
        .await?;
    let mut off = 0u64;
    while (off as usize) < bytes.len() {
        let n = match vfs.pwrite(pid, fd, &bytes[off as usize..], off).await {
            Ok(n) => n,
            Err(e) => {
                let _ = vfs.close(pid, fd).await;
                return Err(e);
            }
        };
        if n == 0 {
            let _ = vfs.close(pid, fd).await;
            return Err(Errno::EIO);
        }
        off += n as u64;
    }
    vfs.close(pid, fd).await?;
    Ok(bytes.len())
}

#[derive(Clone, Debug)]
struct ResolvedConsoleAccount {
    uid: u32,
    gid: u32,
    groups: BTreeSet<u32>,
    user: String,
    home: String,
    shell: String,
}

async fn resolve_default_account_at_prefix(
    vfs: &Vfs,
    prefix: &str,
    default_user: &str,
) -> Result<ResolvedConsoleAccount, String> {
    let passwd_path = if prefix.is_empty() || prefix == "/" {
        "/etc/passwd".to_string()
    } else {
        format!("{prefix}/etc/passwd")
    };
    let group_path = if prefix.is_empty() || prefix == "/" {
        "/etc/group".to_string()
    } else {
        format!("{prefix}/etc/group")
    };
    let passwd_bytes = read_file_as_pid(vfs, 1, &passwd_path)
        .await
        .map_err(|e| format!("failed to read {passwd_path}: {}", e.text()))?;
    let passwd_text = std::str::from_utf8(&passwd_bytes)
        .map_err(|_| format!("{passwd_path} is not valid UTF-8"))?;
    let passwd_entries =
        parse_passwd(passwd_text).map_err(|e| format!("invalid {passwd_path}: {e}"))?;
    let entry = passwd_entries
        .into_iter()
        .find(|e| e.name == default_user)
        .ok_or_else(|| format!("configured default_user {default_user:?} not found in {passwd_path}"))?;

    let group_bytes = read_file_as_pid(vfs, 1, &group_path)
        .await
        .map_err(|e| format!("failed to read {group_path}: {}", e.text()))?;
    let group_text = std::str::from_utf8(&group_bytes)
        .map_err(|_| format!("{group_path} is not valid UTF-8"))?;
    let group_entries =
        parse_group(group_text).map_err(|e| format!("invalid {group_path}: {e}"))?;
    let mut groups = BTreeSet::from([entry.gid]);
    for g in &group_entries {
        if g.members.iter().any(|m| m == &entry.name) {
            groups.insert(g.gid);
        }
    }
    Ok(ResolvedConsoleAccount {
        uid: entry.uid,
        gid: entry.gid,
        groups,
        user: entry.name,
        home: if entry.home.is_empty() {
            "/".to_string()
        } else {
            entry.home
        },
        shell: if entry.shell.is_empty() {
            "/bin/sh".to_string()
        } else {
            entry.shell
        },
    })
}

async fn validate_init_executable_in_root(
    vfs: &Vfs,
    clean_newroot: &str,
    init_path: &str,
) -> vfs::Result<()> {
    let init_candidate = format!("{clean_newroot}{init_path}");
    let init_st = vfs
        .statat(1, StartAnchor::Root, &init_candidate, true)
        .await?;
    if init_st.kind() != S_IFREG || (init_st.mode & 0o111) == 0 {
        return Err(Errno::EACCES);
    }
    let fd = vfs
        .openat(1, StartAnchor::Root, &init_candidate, abi::O_RDONLY, 0)
        .await?;
    let mut hdr = [0u8; 256];
    let n = vfs.pread(1, fd, &mut hdr, 0).await;
    let _ = vfs.close(1, fd).await;
    let n = n?;
    let head = &hdr[..n];
    if head.starts_with(b"\0asm") {
        return Ok(());
    }
    if let Some(rest) = head.strip_prefix(b"#!") {
        let line_end = rest.iter().position(|&b| b == b'\n').unwrap_or(rest.len());
        let line = std::str::from_utf8(&rest[..line_end]).map_err(|_| Errno::ENOEXEC)?;
        let interp = line.trim().split_whitespace().next().ok_or(Errno::ENOEXEC)?;
        if !interp.starts_with('/') || interp.contains('\0') {
            return Err(Errno::ENOEXEC);
        }
        let interp_candidate = format!("{clean_newroot}{interp}");
        let interp_st = vfs
            .statat(1, StartAnchor::Root, &interp_candidate, true)
            .await?;
        if interp_st.kind() != S_IFREG || (interp_st.mode & 0o111) == 0 {
            return Err(Errno::EACCES);
        }
        return Ok(());
    }
    Err(Errno::ENOEXEC)
}

async fn populate_stage1_tmpfs<B: BlobStore>(
    fs: &MemFs,
    initramfs: &Image,
    blobs: &B,
) -> vfs::Result<()> {
    let mut root_cred = Cred::root();
    root_cred.umask = 0;

    let mut handles: HashMap<String, abi::fs::Handle> = HashMap::new();
    handles.insert("/".to_string(), fs.root());

    for entry in &initramfs.entries {
        if entry.path == "/" {
            continue;
        }
        // Leave `/usr/*` contents on the read-only Stage 1 `ImageFs` mounted at `/usr` so
        // multi-MiB Wasm binaries are paged chunk-verified on demand rather than duplicated in tmpfs.
        if entry.path.starts_with("/usr/") {
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
                let data =
                    read_verified_image_file(blobs, sha256, *size, *chunk_size, chunks).await?;
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

    // Ensure Stage 1 mountpoints exist on tmpfs root.
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

/// Recursively unlink every entry reachable from `dir_fd`, strictly bounded by `oldroot_dev`
/// (`contract.md` §5 step 9). Never crosses mount boundaries.
fn unlink_oldroot_recursive<'a>(
    vfs: &'a Vfs,
    dir_fd: u32,
    oldroot_dev: u64,
    reclaimed: &'a mut usize,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = vfs::Result<()>> + 'a>> {
    Box::pin(async move {
        let mut names = Vec::new();
        let mut cookie = 0u64;
        loop {
            let page = vfs
                .read_dir_page(1, StartAnchor::DirFd(dir_fd), ".", cookie, 256)
                .await?;
            for entry in page.entries {
                if entry.name != "." && entry.name != ".." {
                    names.push(entry.name);
                }
            }
            match page.next_cookie {
                Some(next) if next != cookie => cookie = next,
                _ => break,
            }
        }
        for name in names {
            let st = match vfs
                .statat(1, StartAnchor::DirFd(dir_fd), &name, false)
                .await
            {
                Ok(st) => st,
                Err(Errno::ENOENT) => continue,
                Err(_) => continue,
            };
            // STRICT `st_dev` boundary check: NEVER descend into or unlink across mountpoints!
            if st.dev != oldroot_dev {
                continue;
            }
            if st.kind() == S_IFDIR {
                if let Ok(child_fd) = vfs
                    .openat(
                        1,
                        StartAnchor::DirFd(dir_fd),
                        &name,
                        abi::O_RDONLY | abi::O_DIRECTORY | abi::O_NOFOLLOW,
                        0,
                    )
                    .await
                {
                    let child_same_dev = vfs
                        .fstat(1, child_fd)
                        .await
                        .map(|fst| fst.dev == oldroot_dev)
                        .unwrap_or(false);
                    if child_same_dev {
                        let _ =
                            unlink_oldroot_recursive(vfs, child_fd, oldroot_dev, reclaimed).await;
                    }
                    let _ = vfs.close(1, child_fd).await;
                }
                if vfs
                    .unlinkat(1, StartAnchor::DirFd(dir_fd), &name, true)
                    .await
                    .is_ok()
                {
                    *reclaimed += 1;
                }
            } else if vfs
                .unlinkat(1, StartAnchor::DirFd(dir_fd), &name, false)
                .await
                .is_ok()
            {
                *reclaimed += 1;
            }
        }
        Ok(())
    })
}

impl<H: HeadStore + 'static, P: PackStore + 'static, B: BlobStore + Clone + 'static>
    TwoStageBoot<H, P, B>
{
    /// Top-level standalone offline root bootstrap (`new_cowfs_root` per Blueprint §1.2 Track 2):
    /// boots Stage 1 (`initramfs`), executes Stage 1 `early_init` (`cowfsck`, first-boot
    /// `RootTemplate` seeding or existing `os-cowfs` mount / `ForkOnBusy`, Stage 2 `/usr` & `/tmp`),
    /// and pivots into Stage 2 via Contract §5 `switch_root` (or stays in `Stage1Recovery` on
    /// `EPROTONOSUPPORT`, corruption, `EBUSY`, or explicit `profile.recovery`).
    #[allow(clippy::too_many_arguments)]
    pub async fn new_cowfs_root(
        instance_id: impl Into<String>,
        boot_profile: BootProfile,
        release: ReleaseImages,
        head_store: Rc<H>,
        pack_store: Rc<P>,
        blobs: B,
        clock: Rc<dyn Fn() -> Timespec>,
        new_volume_uuid: impl FnOnce() -> String,
    ) -> vfs::Result<Self> {
        let mut boot = Self::boot_stage1(
            instance_id,
            boot_profile,
            release,
            head_store,
            pack_store,
            blobs,
            clock,
        )
        .await?;
        let stage = boot.prepare_cowfs_root(new_volume_uuid).await?;
        if stage == BootStage::Stage1 {
            let args = vec![DEFAULT_STAGE2_INIT.to_string()];
            boot.switch_root(1, "/sysroot", DEFAULT_STAGE2_INIT, &args)
                .await?;
        }
        Ok(boot)
    }

    /// Stage 0 -> Stage 1 handoff (`contract.md` §5):
    /// creates Stage 1 `tmpfs` `/`, populates it from `Kind::Initramfs`, mounts `/proc` (100%
    /// local), local `/dev` (zero remote devices), `/dev/pts`, `/run`, Stage 1 `/usr` (`ro,nodev`),
    /// writes `/run/os/boot-profile.json` (`0444`), and starts PID 1 running `/init`.
    #[allow(clippy::too_many_arguments)]
    pub async fn boot_stage1(
        instance_id: impl Into<String>,
        boot_profile: BootProfile,
        release: ReleaseImages,
        head_store: Rc<H>,
        pack_store: Rc<P>,
        blobs: B,
        clock: Rc<dyn Fn() -> Timespec>,
    ) -> vfs::Result<Self> {
        boot_profile.validate()?;
        if release.initramfs.kind != Kind::Initramfs
            || release.root_template.kind != Kind::RootTemplate
            || release.base.kind != Kind::Base
        {
            return Err(Errno::EINVAL);
        }

        let instance_id = instance_id.into();
        let boot_ts = (clock)();
        let boot_secs = boot_ts.sec;

        // 1. Local process table with PID 1 (`uid 0`, `gid 0`, `started = boot_secs`, `/init`).
        let proc_table = Rc::new(RefCell::new(LocalProcessTable::new(
            InstanceIdentity {
                instance: instance_id.clone(),
                host: HOST_LABEL.to_string(),
            },
            boot_secs,
        )));
        {
            let mut tbl = proc_table.borrow_mut();
            tbl.boot_init(HOST_LABEL, boot_secs).map_err(|e| e.errno)?;
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
                        runtime: None,
                        cloud_access: false,
                        new_remote: None,
                    },
                    boot_secs,
                )
                .map_err(|e| e.errno)?;
        }

        // 2. Stage 1 `tmpfs` `/` populated from `Kind::Initramfs`.
        let stage1_fs = Rc::new(MemFs::new(
            FsId("tmpfs:stage1-initramfs".to_string()),
            1,
            0,
            0,
            0o755,
            timespec_pair(&clock),
        ));
        populate_stage1_tmpfs(&stage1_fs, &release.initramfs, &blobs).await?;
        let stage1_fs_weak = Rc::downgrade(&stage1_fs);

        let factory = Rc::new(DefaultFilesystemFactory::new(timespec_pair_rc(&clock)));
        let root_backing = Rc::new(MountBacking::new(
            stage1_fs as Rc<dyn Filesystem>,
            FsType::TmpFs,
        ));
        let vfs = Vfs::boot(&instance_id, root_backing, "initramfs", factory).await?;

        // Wire 100% local `ProcBridge` hooks (ZERO network RPCs!).
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

        // 3. `/proc` (`ProcFs` with `EmptyProcProvider` — 100% local, zero network!).
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
        .await?;

        // 4. Local `/dev` (`DevTmpFs` + `VblkDeviceBackend`, ZERO remote devices) and `/dev/pts`.
        let vblk = Rc::new(VblkRegistry::new());
        let dev_backend = VblkDeviceBackend::new(DefaultDeviceBackend);
        let dev_fs = Rc::new(DevTmpFs::new(
            FsId("devtmpfs".to_string()),
            1,
            timespec_pair(&clock),
            dev_backend,
        ));
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
            FsId("devpts".to_string()),
            1,
            timespec_pair(&clock),
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
        .await?;

        // 5. `/run` (`tmpfs` carrying `/run/os/boot-profile.json`, `/run/os/root`, `/run/os/cowfsck.json`).
        let run_fs = Rc::new(MemFs::new(
            FsId("tmpfs:run".to_string()),
            2,
            0,
            0,
            0o755,
            timespec_pair(&clock),
        ));
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
        .await?;

        // 6. Stage 1 `/usr` (`ro,nodev` `ImageFs` from verified `Kind::Initramfs`).
        let stage1_usr_entries = image_to_vfs_entries(&release.initramfs);
        let stage1_usr_fs = ImageFs::new(
            FsId("image:stage1-usr".to_string()),
            true,
            boot_ts,
            stage1_usr_entries,
            blobs.clone(),
        )?;
        let stage1_usr_subroot = stage1_usr_fs
            .handle_at("/usr")
            .map(|h| (h, "/usr".to_string()));
        if stage1_usr_subroot.is_some() {
            let usr_backing = Rc::new(
                MountBacking::new(Rc::new(stage1_usr_fs), FsType::Image).with_ceilings(true, false),
            );
            vfs.mount_on_namespace(
                &sys_ns,
                &root_cred,
                usr_backing,
                stage1_usr_subroot,
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
            .await?;
        }

        // 7. Inject `/run/os/boot-profile.json` (`0444`).
        ensure_dir_on_vfs(&vfs, "/run/os", 0o755).await?;
        let profile_bytes = serde_json::to_vec_pretty(&boot_profile).map_err(|_| Errno::EIO)?;
        write_file_on_vfs(&vfs, BOOT_PROFILE_PATH, &profile_bytes, 0o444).await?;

        Ok(Self {
            instance_id,
            boot_profile,
            stage: BootStage::Stage1,
            vfs,
            proc_table,
            dev_fs,
            _dev_pts: dev_pts,
            vblk,
            head_store,
            pack_store,
            blobs,
            release,
            cowfs: None,
            home_cowfs: None,
            mounted_root: None,
            recovery: None,
            fsck_report: None,
            banners: Vec::new(),
            clock_fn: clock,
            stage1_fs_weak,
            stage1_reclaimed_entries: 0,
            console_pid: 1,
            console_pty: None,
            console_user: None,
            console_home: None,
            console_shell: None,
            closed: false,
        })
    }

    async fn enter_recovery(
        &mut self,
        reason: RecoveryReason,
        volume_uuid: Option<String>,
        available_snapshots: Vec<String>,
        message: impl Into<String>,
    ) -> BootStage {
        let state = RecoveryState {
            reason,
            volume_uuid,
            available_snapshots,
            message: message.into(),
        };
        self.recovery = Some(state);
        self.stage = BootStage::Stage1Recovery;
        BootStage::Stage1Recovery
    }

    /// Stage 1 `early_init` root preparation:
    /// - Checks `profile.recovery` -> Stage 1 recovery.
    /// - Checks `COWFS_FORMAT_VERSION` FIRST -> `EPROTONOSUPPORT` recovery (NEVER wipes!).
    /// - On first boot: provisions volume + atomically seeds `RootTemplate` (epoch 1).
    /// - On existing volume: runs `cowfsck` first (corruption -> recovery with snapshot list),
    ///   then opens `CowFs` with `ForkOnBusy` or `Exclusive` (`EBUSY` -> recovery chooser).
    /// - Mounts `os-cowfs` at `/sysroot`, Stage 2 Release v2 `/usr` (`ro,nodev`) at `/sysroot/usr`,
    ///   fresh `tmpfs` (`01777`) at `/sysroot/tmp`, attaches `/dev/vd0`, and writes `/run/os/root`.
    pub async fn prepare_cowfs_root(
        &mut self,
        new_volume_uuid: impl FnOnce() -> String,
    ) -> vfs::Result<BootStage> {
        if self.stage == BootStage::Stage2 {
            return Err(Errno::EINVAL);
        }
        if self.boot_profile.recovery {
            let vol = match &self.boot_profile.root {
                RootSpec::CowFs { volume_uuid, .. } => volume_uuid.clone(),
                RootSpec::Snapshot { volume_uuid, .. } => Some(volume_uuid.clone()),
                RootSpec::Ephemeral | RootSpec::CloudOptIn { .. } => None,
            };
            let snaps = match &vol {
                Some(v) => self
                    .head_store
                    .list_snapshots(&VolumeId(v.clone()))
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .map(|s| s.name)
                    .collect(),
                None => Vec::new(),
            };
            return Ok(self
                .enter_recovery(
                    RecoveryReason::Requested,
                    vol,
                    snaps,
                    "Boot profile requested Stage 1 recovery mode.",
                )
                .await);
        }

        match self.boot_profile.root.clone() {
            RootSpec::Ephemeral => {
                return self.prepare_ephemeral_root().await;
            }
            RootSpec::Snapshot {
                volume_uuid,
                snapshot,
            } => {
                return self.prepare_snapshot_root(&volume_uuid, &snapshot).await;
            }
            RootSpec::CloudOptIn { .. } => {
                return Ok(self
                    .enter_recovery(
                        RecoveryReason::IoError {
                            errno: "EOPNOTSUPP".to_string(),
                            detail: "CloudOptIn root requires an explicit remote login session."
                                .to_string(),
                        },
                        None,
                        Vec::new(),
                        "Standalone offline boot requires a local CowFs, Snapshot, or Ephemeral root.",
                    )
                    .await);
            }
            RootSpec::CowFs { .. } => {}
        }

        let (volume_uuid, writer_mode) = match &self.boot_profile.root {
            RootSpec::CowFs {
                volume_uuid,
                writer_mode,
            } => (volume_uuid.clone(), *writer_mode),
            _ => unreachable!(),
        };

        // 1. Format version check FIRST — NEVER silently wipe or reformat user data!
        match self.head_store.format_version().await {
            Ok(Some(ver)) if ver != COWFS_FORMAT_VERSION => {
                return Ok(self
                    .enter_recovery(
                        RecoveryReason::IncompatibleFormat {
                            found_version: Some(ver),
                            expected_version: COWFS_FORMAT_VERSION,
                        },
                        volume_uuid,
                        Vec::new(),
                        format!(
                            "Refusing to mount or reformat incompatible os-cowfs format version {ver} (expected {COWFS_FORMAT_VERSION}): EPROTONOSUPPORT."
                        ),
                    )
                    .await);
            }
            Ok(_) => {}
            Err(Errno::EPROTONOSUPPORT) => {
                return Ok(self
                    .enter_recovery(
                        RecoveryReason::IncompatibleFormat {
                            found_version: None,
                            expected_version: COWFS_FORMAT_VERSION,
                        },
                        volume_uuid,
                        Vec::new(),
                        format!(
                            "Refusing to mount or reformat incompatible os-cowfs store (expected version {COWFS_FORMAT_VERSION}): EPROTONOSUPPORT."
                        ),
                    )
                    .await);
            }
            Err(e) => {
                return Ok(self
                    .enter_recovery(
                        RecoveryReason::IoError {
                            errno: errno_name(e),
                            detail: format!("format version probe failed: {e:?}"),
                        },
                        volume_uuid,
                        Vec::new(),
                        format!("Failed to probe os-cowfs store format version ({e:?})."),
                    )
                    .await);
            }
        }

        // 2. If opening an existing volume, run `cowfsck` pre-mount integrity check BEFORE
        //    mounting read-write so corrupt volumes NEVER mount and ALWAYS offer recovery/rollback.
        if let Some(ref existing_uuid) = volume_uuid {
            let vol_id = VolumeId(existing_uuid.clone());
            match cowfsck_volume_stores(&*self.head_store, &*self.pack_store, &vol_id).await {
                Ok(report) => {
                    let report_bytes =
                        serde_json::to_vec_pretty(&report).unwrap_or_else(|_| b"{}".to_vec());
                    let _ = write_file_on_vfs(&self.vfs, COWFSCK_REPORT_PATH, &report_bytes, 0o444)
                        .await;
                    let ok = report.ok;
                    let detail = if report.errors.is_empty() {
                        "cowfsck reported volume corruption".to_string()
                    } else {
                        report.errors.join("; ")
                    };
                    self.fsck_report = Some(report);
                    if !ok {
                        let snaps: Vec<String> = self
                            .head_store
                            .list_snapshots(&vol_id)
                            .await
                            .unwrap_or_default()
                            .into_iter()
                            .map(|s| s.name)
                            .collect();
                        return Ok(self
                            .enter_recovery(
                                RecoveryReason::CorruptVolume {
                                    detail: detail.clone(),
                                    snapshots: snaps.clone(),
                                },
                                Some(existing_uuid.clone()),
                                snaps,
                                format!(
                                    "Stage 1 cowfsck detected corruption on volume {existing_uuid}: {detail}"
                                ),
                            )
                            .await);
                    }
                }
                Err(Errno::EPROTONOSUPPORT) => {
                    return Ok(self
                        .enter_recovery(
                            RecoveryReason::IncompatibleFormat {
                                found_version: None,
                                expected_version: COWFS_FORMAT_VERSION,
                            },
                            Some(existing_uuid.clone()),
                            Vec::new(),
                            format!(
                                "cowfsck rejected volume {existing_uuid}: incompatible format version (EPROTONOSUPPORT)."
                            ),
                        )
                        .await);
                }
                Err(e) => {
                    let snaps: Vec<String> = self
                        .head_store
                        .list_snapshots(&vol_id)
                        .await
                        .unwrap_or_default()
                        .into_iter()
                        .map(|s| s.name)
                        .collect();
                    return Ok(self
                        .enter_recovery(
                            RecoveryReason::CorruptVolume {
                                detail: format!("cowfsck failed: {}", errno_name(e)),
                                snapshots: snaps.clone(),
                            },
                            Some(existing_uuid.clone()),
                            snaps,
                            format!(
                                "Stage 1 cowfsck failed on volume {existing_uuid} ({e:?}); refusing to mount."
                            ),
                        )
                        .await);
                }
            }
        }

        // 3. Provision or open `os-cowfs` root volume.
        let config = CowFsConfig::local_browser(Rc::clone(&self.clock_fn))
            .with_arena(ArenaConfig::fixed_32mib());
        let opened = match open_for_boot_stores(
            Rc::clone(&self.head_store),
            Rc::clone(&self.pack_store),
            volume_uuid.clone(),
            writer_mode.to_cowtree_mode(),
            Some(&self.release.root_template),
            Some(&self.blobs),
            config,
            new_volume_uuid,
        )
        .await
        {
            Ok(res) => res,
            Err(Errno::EPROTONOSUPPORT) => {
                return Ok(self
                    .enter_recovery(
                        RecoveryReason::IncompatibleFormat {
                            found_version: None,
                            expected_version: COWFS_FORMAT_VERSION,
                        },
                        volume_uuid,
                        Vec::new(),
                        "Incompatible os-cowfs format version (EPROTONOSUPPORT).",
                    )
                    .await);
            }
            Err(Errno::EBUSY) => {
                let busy_uuid = volume_uuid.clone().unwrap_or_default();
                let snaps = self
                    .head_store
                    .list_snapshots(&VolumeId(busy_uuid.clone()))
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .map(|s| s.name)
                    .collect();
                return Ok(self
                    .enter_recovery(
                        RecoveryReason::VolumeBusy {
                            volume_uuid: busy_uuid.clone(),
                        },
                        volume_uuid,
                        snaps,
                        format!(
                            "Volume {busy_uuid} is locked exclusively by another active tab (EBUSY). Choose 'Fork & Boot' to open on an isolated copy-on-write fork."
                        ),
                    )
                    .await);
            }
            Err(e) => {
                return Ok(self
                    .enter_recovery(
                        RecoveryReason::IoError {
                            errno: errno_name(e),
                            detail: format!("os-cowfs open failed: {e:?}"),
                        },
                        volume_uuid,
                        Vec::new(),
                        format!("Failed to open os-cowfs root volume ({e:?})."),
                    )
                    .await);
            }
        };

        self.mount_opened_cowfs_at_sysroot(opened, writer_mode)
            .await?;
        // Fail closed BEFORE pivoting if `/sysroot/etc/passwd` is missing/corrupt or the
        // configured `default_user` cannot be resolved (Codex Finding #24).
        if let Err(detail) = resolve_default_account_at_prefix(
            &self.vfs,
            "/sysroot",
            &self.boot_profile.default_user,
        )
        .await
        {
            self.teardown_sysroot_mounts().await;
            let vol = self
                .mounted_root
                .take()
                .map(|r| r.volume_uuid)
                .or(volume_uuid);
            if let Some(fs) = self.cowfs.take() {
                let _ = fs.close_clean().await;
            }
            self.home_cowfs = None;
            let default_user = self.boot_profile.default_user.clone();
            return Ok(self
                .enter_recovery(
                    RecoveryReason::AccountResolutionFailed {
                        default_user: default_user.clone(),
                        detail: detail.clone(),
                    },
                    vol,
                    Vec::new(),
                    format!("Refusing to auto-login synthetic user for {default_user:?}: {detail}"),
                )
                .await);
        }
        self.recovery = None;
        self.stage = BootStage::Stage1;
        Ok(BootStage::Stage1)
    }

    async fn teardown_sysroot_mounts(&self) {
        let _ = self
            .vfs
            .umount2(1, "/sysroot/tmp", umount_flags::MNT_DETACH)
            .await;
        let _ = self
            .vfs
            .umount2(1, "/sysroot/usr", umount_flags::MNT_DETACH)
            .await;
        let _ = self
            .vfs
            .umount2(1, "/sysroot/home", umount_flags::MNT_DETACH)
            .await;
        let _ = self
            .vfs
            .umount2(1, "/sysroot", umount_flags::MNT_DETACH)
            .await;
    }

    async fn mount_stage2_usr_and_tmp(&self, now: Timespec) -> vfs::Result<()> {
        let sys_ns = self.vfs.system_namespace();
        let mut root_cred = Cred::root();
        root_cred.umask = 0;

        for (sub, mode) in [
            ("/sysroot/proc", 0o555),
            ("/sysroot/dev", 0o755),
            ("/sysroot/run", 0o755),
            ("/sysroot/usr", 0o755),
            ("/sysroot/tmp", 0o1777),
        ] {
            ensure_dir_on_vfs(&self.vfs, sub, mode).await?;
        }

        let stage2_usr_entries =
            compose_system_image_entries(&self.release.base, &self.release.extensions)
                .map_err(|_| Errno::EINVAL)?;
        let stage2_usr_fs = ImageFs::new(
            FsId("image:stage2-usr".to_string()),
            true,
            now,
            stage2_usr_entries,
            self.blobs.clone(),
        )?;
        let usr_subroot = stage2_usr_fs
            .handle_at("/usr")
            .map(|h| (h, "/usr".to_string()))
            .ok_or(Errno::ENOENT)?;
        let usr_backing = Rc::new(
            MountBacking::new(Rc::new(stage2_usr_fs), FsType::Image).with_ceilings(true, false),
        );
        self.vfs
            .mount_on_namespace(
                &sys_ns,
                &root_cred,
                usr_backing,
                Some(usr_subroot),
                "usr",
                "/sysroot/usr",
                MountFlags {
                    rdonly: true,
                    nodev: true,
                    ..MountFlags::default()
                },
                mount_flags::MS_RDONLY | mount_flags::MS_NODEV,
                None,
            )
            .await?;

        let tmp_fs = Rc::new(MemFs::new(
            FsId("tmpfs:stage2-tmp".to_string()),
            3,
            0,
            0,
            0o1777,
            timespec_pair(&self.clock_fn),
        ));
        let tmp_root = tmp_fs.root();
        let _ = tmp_fs
            .setattr(
                &root_cred,
                &tmp_root,
                &SetAttr {
                    mode: Some(0o1777),
                    ..SetAttr::default()
                },
            )
            .await;
        let tmp_backing = Rc::new(MountBacking::new(tmp_fs, FsType::TmpFs));
        self.vfs
            .mount_on_namespace(
                &sys_ns,
                &root_cred,
                tmp_backing,
                None,
                "tmpfs",
                "/sysroot/tmp",
                MountFlags {
                    nosuid: true,
                    nodev: true,
                    ..MountFlags::default()
                },
                mount_flags::MS_NOSUID | mount_flags::MS_NODEV,
                None,
            )
            .await?;
        Ok(())
    }

    async fn prepare_ephemeral_root(&mut self) -> vfs::Result<BootStage> {
        let now = (self.clock_fn)();
        let eph_fs = Rc::new(MemFs::new(
            FsId("tmpfs:ephemeral-root".to_string()),
            4,
            0,
            0,
            0o755,
            timespec_pair(&self.clock_fn),
        ));
        populate_stage1_tmpfs(&eph_fs, &self.release.root_template, &self.blobs).await?;
        let sys_ns = self.vfs.system_namespace();
        let mut root_cred = Cred::root();
        root_cred.umask = 0;
        let backing = Rc::new(MountBacking::new(
            eph_fs as Rc<dyn Filesystem>,
            FsType::TmpFs,
        ));
        self.vfs
            .mount_on_namespace(
                &sys_ns,
                &root_cred,
                backing,
                None,
                "tmpfs:ephemeral",
                "/sysroot",
                MountFlags::default(),
                0,
                None,
            )
            .await?;
        self.mount_stage2_usr_and_tmp(now).await?;
        if let Err(detail) = resolve_default_account_at_prefix(
            &self.vfs,
            "/sysroot",
            &self.boot_profile.default_user,
        )
        .await
        {
            self.teardown_sysroot_mounts().await;
            let default_user = self.boot_profile.default_user.clone();
            return Ok(self
                .enter_recovery(
                    RecoveryReason::AccountResolutionFailed {
                        default_user: default_user.clone(),
                        detail: detail.clone(),
                    },
                    None,
                    Vec::new(),
                    format!("Refusing to auto-login synthetic user for {default_user:?}: {detail}"),
                )
                .await);
        }
        let info = MountedRootInfo {
            fstype: "tmpfs".to_string(),
            volume_uuid: "ephemeral".to_string(),
            forked_from: None,
            base_epoch: 0,
            ephemeral_if_unmodified: true,
            first_boot_seeded: true,
            writer_mode: BootWriterMode::ForkOnBusy,
            mounted_at: now.sec,
        };
        let info_bytes = serde_json::to_vec_pretty(&info).map_err(|_| Errno::EIO)?;
        write_file_on_vfs(&self.vfs, MOUNTED_ROOT_INFO_PATH, &info_bytes, 0o444).await?;
        self.cowfs = None;
        self.home_cowfs = None;
        self.mounted_root = Some(info);
        self.recovery = None;
        self.stage = BootStage::Stage1;
        Ok(BootStage::Stage1)
    }

    async fn prepare_snapshot_root(
        &mut self,
        volume_uuid: &str,
        snapshot_name: &str,
    ) -> vfs::Result<BootStage> {
        let now = (self.clock_fn)();
        match self.head_store.format_version().await {
            Ok(Some(ver)) if ver != COWFS_FORMAT_VERSION => {
                return Ok(self
                    .enter_recovery(
                        RecoveryReason::IncompatibleFormat {
                            found_version: Some(ver),
                            expected_version: COWFS_FORMAT_VERSION,
                        },
                        Some(volume_uuid.to_string()),
                        Vec::new(),
                        format!(
                            "Refusing to mount incompatible os-cowfs format version {ver} (expected {COWFS_FORMAT_VERSION}): EPROTONOSUPPORT."
                        ),
                    )
                    .await);
            }
            Ok(_) => {}
            Err(Errno::EPROTONOSUPPORT) => {
                return Ok(self
                    .enter_recovery(
                        RecoveryReason::IncompatibleFormat {
                            found_version: None,
                            expected_version: COWFS_FORMAT_VERSION,
                        },
                        Some(volume_uuid.to_string()),
                        Vec::new(),
                        format!(
                            "Refusing to mount incompatible os-cowfs store (expected version {COWFS_FORMAT_VERSION}): EPROTONOSUPPORT."
                        ),
                    )
                    .await);
            }
            Err(e) => {
                return Ok(self
                    .enter_recovery(
                        RecoveryReason::IoError {
                            errno: errno_name(e),
                            detail: format!("format version probe failed: {e:?}"),
                        },
                        Some(volume_uuid.to_string()),
                        Vec::new(),
                        format!("Failed to probe os-cowfs store format version ({e:?})."),
                    )
                    .await);
            }
        }

        let vol_id = VolumeId(volume_uuid.to_string());
        let snap_rec = match self.head_store.get_snapshot(&vol_id, snapshot_name).await {
            Ok(s) => s,
            Err(e) => {
                let snaps = self
                    .head_store
                    .list_snapshots(&vol_id)
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .map(|s| s.name)
                    .collect();
                return Ok(self
                    .enter_recovery(
                        RecoveryReason::IoError {
                            errno: errno_name(e),
                            detail: format!("snapshot {snapshot_name:?} on {volume_uuid} unavailable: {e:?}"),
                        },
                        Some(volume_uuid.to_string()),
                        snaps,
                        format!("Snapshot {snapshot_name:?} on volume {volume_uuid} could not be opened ({e:?})."),
                    )
                    .await);
            }
        };

        let config = CowFsConfig::local_browser(Rc::clone(&self.clock_fn))
            .with_arena(ArenaConfig::fixed_32mib());
        let snap_fs = match CowFs::open(
            Rc::clone(&self.head_store),
            Rc::clone(&self.pack_store),
            vol_id.clone(),
            cowfs::CowFsOpenMode::Snapshot(snapshot_name.to_string()),
            config,
        )
        .await
        {
            Ok(fs) => Rc::new(fs),
            Err(e) => {
                return Ok(self
                    .enter_recovery(
                        RecoveryReason::CorruptVolume {
                            detail: format!("failed to open snapshot {snapshot_name}: {e:?}"),
                            snapshots: vec![snapshot_name.to_string()],
                        },
                        Some(volume_uuid.to_string()),
                        vec![snapshot_name.to_string()],
                        format!("Snapshot {snapshot_name:?} failed verification/open ({e:?})."),
                    )
                    .await);
            }
        };

        let sys_ns = self.vfs.system_namespace();
        let mut root_cred = Cred::root();
        root_cred.umask = 0;
        let backing = Rc::new(
            MountBacking::new(Rc::clone(&snap_fs) as Rc<dyn Filesystem>, FsType::Cowfs)
                .with_ceilings(true, false),
        );
        self.vfs
            .mount_on_namespace(
                &sys_ns,
                &root_cred,
                backing,
                None,
                &format!("snapshot:{volume_uuid}@{snapshot_name}"),
                "/sysroot",
                MountFlags {
                    rdonly: true,
                    ..MountFlags::default()
                },
                mount_flags::MS_RDONLY,
                None,
            )
            .await?;

        // Discover & mount `@home` subvolume if present in the snapshot root object (Codex #32).
        let mut home_cowfs: Option<Rc<dyn Filesystem>> = None;
        if let Ok(raw_root) = self.head_store.get_node(&snap_rec.root).await
            && let Ok(root_obj) = RootObject::decode_verified(&snap_rec.root, &raw_root)
            && root_obj.subvols.contains_key("@home")
            && self
                .vfs
                .statat(1, StartAnchor::Root, "/sysroot/home", false)
                .await
                .is_ok_and(|st| st.kind() == S_IFDIR)
        {
            let home_cfg = CowFsConfig::local_browser(Rc::clone(&self.clock_fn))
                .with_arena(ArenaConfig::fixed_32mib())
                .with_subvol("@home");
            if let Ok(home_fs) = CowFs::open(
                Rc::clone(&self.head_store),
                Rc::clone(&self.pack_store),
                vol_id.clone(),
                cowfs::CowFsOpenMode::Snapshot(snapshot_name.to_string()),
                home_cfg,
            )
            .await
            {
                let home_rc: Rc<dyn Filesystem> = Rc::new(home_fs);
                let home_backing = Rc::new(
                    MountBacking::new(Rc::clone(&home_rc), FsType::Cowfs)
                        .with_ceilings(true, false),
                );
                self.vfs
                    .mount_on_namespace(
                        &sys_ns,
                        &root_cred,
                        home_backing,
                        None,
                        &format!("snapshot:{volume_uuid}@{snapshot_name}:@home"),
                        "/sysroot/home",
                        MountFlags {
                            rdonly: true,
                            ..MountFlags::default()
                        },
                        mount_flags::MS_RDONLY,
                        None,
                    )
                    .await?;
                home_cowfs = Some(home_rc);
            }
        }

        self.mount_stage2_usr_and_tmp(now).await?;
        if let Err(detail) = resolve_default_account_at_prefix(
            &self.vfs,
            "/sysroot",
            &self.boot_profile.default_user,
        )
        .await
        {
            self.teardown_sysroot_mounts().await;
            let _ = snap_fs.close_clean().await;
            let default_user = self.boot_profile.default_user.clone();
            return Ok(self
                .enter_recovery(
                    RecoveryReason::AccountResolutionFailed {
                        default_user: default_user.clone(),
                        detail: detail.clone(),
                    },
                    Some(volume_uuid.to_string()),
                    Vec::new(),
                    format!("Refusing to auto-login synthetic user for {default_user:?}: {detail}"),
                )
                .await);
        }

        let info = MountedRootInfo {
            fstype: "cowfs-snapshot".to_string(),
            volume_uuid: format!("{volume_uuid}@{snapshot_name}"),
            forked_from: None,
            base_epoch: snap_rec.epoch,
            ephemeral_if_unmodified: false,
            first_boot_seeded: false,
            writer_mode: BootWriterMode::Exclusive,
            mounted_at: now.sec,
        };
        let info_bytes = serde_json::to_vec_pretty(&info).map_err(|_| Errno::EIO)?;
        write_file_on_vfs(&self.vfs, MOUNTED_ROOT_INFO_PATH, &info_bytes, 0o444).await?;
        self.cowfs = Some(snap_fs);
        self.home_cowfs = home_cowfs;
        self.mounted_root = Some(info);
        self.recovery = None;
        self.stage = BootStage::Stage1;
        Ok(BootStage::Stage1)
    }

    async fn mount_opened_cowfs_at_sysroot(
        &mut self,
        opened: crate::cowfs_bridge::BootOpenResult<H, P>,
        writer_mode: BootWriterMode,
    ) -> vfs::Result<()> {
        let now = (self.clock_fn)();
        if let Some(report) = opened.fsck_report {
            self.fsck_report = Some(report);
        }

        // Persist first-boot minted volume UUID in the active BootProfile & `/run/os/boot-profile.json`.
        if opened.first_boot_seeded
            && let RootSpec::CowFs {
                ref mut volume_uuid,
                ..
            } = self.boot_profile.root
        {
            *volume_uuid = Some(opened.volume_uuid.clone());
            let profile_bytes =
                serde_json::to_vec_pretty(&self.boot_profile).map_err(|_| Errno::EIO)?;
            write_file_on_vfs(&self.vfs, BOOT_PROFILE_PATH, &profile_bytes, 0o444).await?;
        }

        let info = MountedRootInfo {
            fstype: "cowfs".to_string(),
            volume_uuid: opened.volume_uuid.clone(),
            forked_from: opened.forked_from.clone(),
            base_epoch: opened.base_epoch,
            ephemeral_if_unmodified: opened.ephemeral_if_unmodified,
            first_boot_seeded: opened.first_boot_seeded,
            writer_mode,
            mounted_at: now.sec,
        };
        let info_bytes = serde_json::to_vec_pretty(&info).map_err(|_| Errno::EIO)?;
        write_file_on_vfs(&self.vfs, MOUNTED_ROOT_INFO_PATH, &info_bytes, 0o444).await?;

        if let Some(ref parent) = info.forked_from {
            self.banners.push(format!(
                "ForkOnBusy: booted on O(1) copy-on-write fork {} (parent {}); unmodified forks are pruned automatically on clean exit.",
                info.volume_uuid, parent
            ));
        }

        // Attach `/dev/vd0` (`CowFsVolumeDevice`) to local `/dev` (`VblkRegistry`).
        let mut root_cred = Cred::root();
        root_cred.umask = 0;
        let _ = self.vblk.detach("vd0");
        let _ = self
            .dev_fs
            .unlink(&root_cred, &self.dev_fs.root(), "vd0")
            .await;
        self.vblk.attach_named(
            "vd0",
            Rc::new(CowFsVolumeDevice::from_mounted(Rc::clone(&opened.fs))),
        )?;
        let _ = self
            .dev_fs
            .mknod(&root_cred, &self.dev_fs.root(), "vd0", 0o660, "vblk:vd0")
            .await;

        // Mount `os-cowfs` at `/sysroot`.
        let sys_ns = self.vfs.system_namespace();
        let cowfs_backing = Rc::new(MountBacking::new(
            Rc::clone(&opened.fs) as Rc<dyn Filesystem>,
            FsType::Cowfs,
        ));
        self.vfs
            .mount_on_namespace(
                &sys_ns,
                &root_cred,
                cowfs_backing,
                None,
                &format!("cowfs:{}", info.volume_uuid),
                "/sysroot",
                MountFlags::default(),
                0,
                None,
            )
            .await?;

        self.mount_stage2_usr_and_tmp(now).await?;
        self.cowfs = Some(opened.fs);
        self.home_cowfs = None;
        self.mounted_root = Some(info);
        Ok(())
    }

    /// Execute `switch_root` implementing `docs/architecture/contract.md` §5 steps 1–10 verbatim.
    pub async fn switch_root(
        &mut self,
        caller_pid: u32,
        newroot: &str,
        init_path: &str,
        init_args: &[String],
    ) -> vfs::Result<()> {
        // Step 1: PID 1 only.
        if caller_pid != 1 {
            return Err(Errno::EPERM);
        }
        // Step 2: Current `/` MUST be `tmpfs` (`TMPFS_MAGIC`).
        let root_fs = self.vfs.statfs(1, StartAnchor::Root, "/").await?;
        if root_fs.f_type != fs_magic::TMPFS_MAGIC {
            return Err(Errno::EINVAL);
        }
        // Validate `newroot` and `init_path` arguments.
        let clean_newroot = newroot.trim_end_matches('/');
        if clean_newroot.is_empty() || !clean_newroot.starts_with('/') {
            return Err(Errno::EINVAL);
        }
        if init_path.is_empty() || !init_path.starts_with('/') || init_path.contains('\0') {
            return Err(Errno::EINVAL);
        }

        // Step 3 (pre-flight BEFORE moving any mounts!):
        // (a) `newroot` must be a mounted directory on a different `st_dev` than `/`.
        let oldroot_st = self.vfs.statat(1, StartAnchor::Root, "/", false).await?;
        let newroot_st = self
            .vfs
            .statat(1, StartAnchor::Root, clean_newroot, false)
            .await?;
        if newroot_st.kind() != S_IFDIR || newroot_st.dev == oldroot_st.dev {
            return Err(Errno::EINVAL);
        }

        // (b) Move targets (`<newroot>/proc`, `<newroot>/dev`, `<newroot>/run`) must be real
        //     directories (not symlinks).
        let submounts = ["/proc", "/dev", "/run"];
        for sub in submounts {
            let dst = format!("{clean_newroot}{sub}");
            let dst_st = self.vfs.statat(1, StartAnchor::Root, &dst, false).await?;
            if dst_st.kind() != S_IFDIR {
                return Err(Errno::ENOTDIR);
            }
        }

        // (c) `<newroot><init>` must exist as a valid executable regular file (Wasm or `#!` with
        //     resolvable executable interpreter inside `<newroot>`) BEFORE any mounts move!
        validate_init_executable_in_root(&self.vfs, clean_newroot, init_path).await?;

        // Step 4: Detach Stage 1 `/usr` before pivoting so no Stage 1 `ImageFs` mount remains.
        let _ = self.vfs.umount2(1, "/usr", umount_flags::MNT_DETACH).await;

        // Step 5: Retain a directory descriptor on the old Stage 1 `tmpfs` `/` and record `st_dev`.
        let oldroot_fd = self
            .vfs
            .openat(
                1,
                StartAnchor::Root,
                "/",
                abi::O_RDONLY | abi::O_DIRECTORY,
                0,
            )
            .await?;
        let oldroot_dev = match self.vfs.fstat(1, oldroot_fd).await {
            Ok(st) => st.dev,
            Err(e) => {
                let _ = self.vfs.close(1, oldroot_fd).await;
                return Err(e);
            }
        };

        // Step 6: `MS_MOVE` `/proc`, `/dev` (with `/dev/pts`), and `/run` onto `<newroot>`.
        // Roll back any already-moved mounts if a subsequent move fails!
        let mut moved: Vec<(&str, String)> = Vec::new();
        for sub in submounts {
            let dst = format!("{clean_newroot}{sub}");
            if let Err(e) = self
                .vfs
                .mount(1, sub, &dst, None, mount_flags::MS_MOVE, None)
                .await
            {
                for (orig, target) in moved.into_iter().rev() {
                    let _ = self
                        .vfs
                        .mount(1, &target, orig, None, mount_flags::MS_MOVE, None)
                        .await;
                }
                let _ = self.vfs.close(1, oldroot_fd).await;
                return Err(e);
            }
            moved.push((sub, dst));
        }

        // Step 7: `chdir(newroot)` and `mount(".", "/", MS_MOVE)` — if either fails before the
        // root pivot succeeds, restore cwd to `/` and roll back moved `/proc`, `/dev`, `/run`.
        if let Err(e) = async {
            self.vfs.chdir(1, clean_newroot).await?;
            self.vfs
                .mount(1, ".", "/", None, mount_flags::MS_MOVE, None)
                .await?;
            Ok::<(), Errno>(())
        }
        .await
        {
            let _ = self.vfs.chdir(1, "/").await;
            for (orig, target) in moved.into_iter().rev() {
                let _ = self
                    .vfs
                    .mount(1, &target, orig, None, mount_flags::MS_MOVE, None)
                    .await;
            }
            let _ = self.vfs.close(1, oldroot_fd).await;
            return Err(e);
        }

        // Step 8: `chroot(".")`, `chdir("/")`.
        if let Err(e) = async {
            self.vfs.chroot(1, ".").await?;
            self.vfs.chdir(1, "/").await?;
            Ok::<(), Errno>(())
        }
        .await
        {
            let _ = self.vfs.close(1, oldroot_fd).await;
            return Err(e);
        }

        // Step 9: Recursively unlink every entry in Stage 1 `tmpfs` strictly bounded by `oldroot_dev`,
        // then close `oldroot_fd` so the Stage 1 `tmpfs` is freed completely.
        let mut reclaimed = 0usize;
        let _ = unlink_oldroot_recursive(&self.vfs, oldroot_fd, oldroot_dev, &mut reclaimed).await;
        let _ = self.vfs.close(1, oldroot_fd).await;
        self.stage1_reclaimed_entries = reclaimed;

        // Step 10: `execve` Stage 2 init, preserving PID 1, `started`, and `started_ticks` verbatim!
        self.vfs.exec_preserve(1).await?;
        let argv = if init_args.is_empty() {
            vec![init_path.to_string()]
        } else {
            init_args.to_vec()
        };
        let now_sec = (self.clock_fn)().sec;
        self.proc_table
            .borrow_mut()
            .reexec(
                HOST_LABEL,
                1,
                ReexecSpec {
                    path: init_path.to_string(),
                    argv,
                    env: vec![
                        "PATH=/usr/bin:/bin:/sbin".to_string(),
                        "OS_BOOT_STAGE=2".to_string(),
                        format!("OS_DEFAULT_USER={}", self.boot_profile.default_user),
                    ],
                    cwd: Some("/".to_string()),
                    runtime: None,
                    cloud_access: false,
                    new_remote: None,
                },
                now_sec,
            )
            .map_err(|e| e.errno)?;

        // Spawn a separate non-PID-1 Stage 2 console login process on a local PTY (`/dev/pts/0`)
        // with the resolved `default_user` identity (Codex Findings #2 & #24).
        let acct = resolve_default_account_at_prefix(&self.vfs, "", &self.boot_profile.default_user)
            .await
            .map_err(|_| Errno::ENOENT)?;
        self._dev_pts
            .register_pty(0, acct.uid, acct.gid, 0o620);
        let identity = Identity {
            id: acct.uid,
            group: acct.gid,
            groups: acct.groups.clone(),
        };
        let mut spec = SpawnSpec::new(
            acct.shell.clone(),
            LocalCred {
                identity: identity.clone(),
                umask: 0o022,
                cloud_access: false,
                allowed_remote_scope: None,
                remote: None,
            },
            HOST_LABEL,
        );
        spec.argv = vec![acct.shell.clone()];
        spec.cwd = acct.home.clone();
        spec.ppid = Some(1);
        spec.initial_state = ProcState::Running;
        spec.env = vec![
            format!("USER={}", acct.user),
            format!("HOME={}", acct.home),
            format!("SHELL={}", acct.shell),
            "PATH=/usr/bin:/bin".to_string(),
            "TERM=xterm-256color".to_string(),
        ];
        let login_pid = {
            let mut tbl = self.proc_table.borrow_mut();
            let pid = tbl.spawn(spec, now_sec).map_err(|e| e.errno)?.pid;
            let _ = tbl.set_tty(HOST_LABEL, pid, 1, vec![0, 1, 2]);
            pid
        };
        let login_cred = Cred {
            identity,
            umask: 0o022,
            token: None,
        };
        self.vfs
            .spawn_process(login_pid, 1, login_cred, None, None, None)?;
        if self.vfs.chdir(login_pid, &acct.home).await.is_err() {
            let _ = self.vfs.chdir(login_pid, "/").await;
        }
        self.console_pid = login_pid;
        self.console_pty = Some(0);
        self.console_user = Some(acct.user);
        self.console_home = Some(acct.home);
        self.console_shell = Some(acct.shell);
        self.stage = BootStage::Stage2;
        Ok(())
    }

    /// Stage 1 recovery action: roll back a corrupt volume by forking a clean new volume from
    /// `snapshot_name`, verifying it via `cowfsck`, mounting it, and pivoting to Stage 2.
    /// The original corrupt volume is left untouched (never silently wiped).
    pub async fn rollback_to_snapshot(
        &mut self,
        snapshot_name: &str,
        new_volume_uuid: impl FnOnce() -> String,
    ) -> vfs::Result<BootStage> {
        if self.stage != BootStage::Stage1Recovery {
            return Err(Errno::EINVAL);
        }
        let source_uuid = self
            .recovery
            .as_ref()
            .and_then(|r| r.volume_uuid.clone())
            .or_else(|| match &self.boot_profile.root {
                RootSpec::CowFs { volume_uuid, .. } => volume_uuid.clone(),
                RootSpec::Snapshot { volume_uuid, .. } => Some(volume_uuid.clone()),
                RootSpec::Ephemeral | RootSpec::CloudOptIn { .. } => None,
            })
            .ok_or(Errno::ENOENT)?;

        let rolled_uuid = new_volume_uuid();
        let now = (self.clock_fn)();
        let source_vol = VolumeId(source_uuid);
        let snap = self
            .head_store
            .get_snapshot(&source_vol, snapshot_name)
            .await?;
        self.head_store
            .fork_volume(&ForkRequest {
                source_volume: source_vol,
                source_snapshot: Some(snapshot_name.to_string()),
                source_root: snap.root,
                new_volume: VolumeId(rolled_uuid.clone()),
                ephemeral_if_unmodified: false,
                created_at: now,
            })
            .await?;

        self.boot_profile.recovery = false;
        self.boot_profile.root = RootSpec::CowFs {
            volume_uuid: Some(rolled_uuid),
            writer_mode: BootWriterMode::ForkOnBusy,
        };
        let profile_bytes =
            serde_json::to_vec_pretty(&self.boot_profile).map_err(|_| Errno::EIO)?;
        write_file_on_vfs(&self.vfs, BOOT_PROFILE_PATH, &profile_bytes, 0o444).await?;

        let stage = self.prepare_cowfs_root(make_uuid).await?;
        if stage == BootStage::Stage1 {
            let args = vec![DEFAULT_STAGE2_INIT.to_string()];
            self.switch_root(1, "/sysroot", DEFAULT_STAGE2_INIT, &args)
                .await?;
            return Ok(BootStage::Stage2);
        }
        Ok(stage)
    }

    /// Stage 1 recovery action (for `Exclusive` `EBUSY`): switch writer mode to `ForkOnBusy`,
    /// open an O(1) persistent fork, and complete `switch_root` into Stage 2.
    pub async fn fork_from_recovery(&mut self) -> vfs::Result<BootStage> {
        if self.stage != BootStage::Stage1Recovery {
            return Err(Errno::EINVAL);
        }
        self.boot_profile.recovery = false;
        if let RootSpec::CowFs {
            ref mut writer_mode,
            ..
        } = self.boot_profile.root
        {
            *writer_mode = BootWriterMode::ForkOnBusy;
        }
        let profile_bytes =
            serde_json::to_vec_pretty(&self.boot_profile).map_err(|_| Errno::EIO)?;
        write_file_on_vfs(&self.vfs, BOOT_PROFILE_PATH, &profile_bytes, 0o444).await?;

        let stage = self.prepare_cowfs_root(make_uuid).await?;
        if stage == BootStage::Stage1 {
            let args = vec![DEFAULT_STAGE2_INIT.to_string()];
            self.switch_root(1, "/sysroot", DEFAULT_STAGE2_INIT, &args)
                .await?;
            return Ok(BootStage::Stage2);
        }
        Ok(stage)
    }

    /// Clean shutdown: flushes dirty transactions if modified and runs `close_clean_with_prune_fs`,
    /// automatically pruning an unmodified `ForkOnBusy` fork while retaining any modified fork.
    ///
    /// Codex Finding #15: retains the `CowFs` handle in a retryable state until durable close
    /// actually succeeds so a transient `ENOSPC`/`EIO` leaves dirty data retryable rather than
    /// marking `closed = true` prematurely.
    pub async fn close_clean_with_prune(&mut self) -> vfs::Result<Option<CloseCleanPruneOutcome>> {
        if self.closed {
            return Ok(None);
        }
        let Some(cowfs) = self.cowfs.clone() else {
            self.closed = true;
            return Ok(None);
        };
        let base_epoch = self.mounted_root.as_ref().map_or(0, |info| info.base_epoch);
        let outcome = close_clean_with_prune_fs(&cowfs, base_epoch).await?;
        self.closed = true;
        Ok(Some(outcome))
    }

    /// Flush dirty writes for bfcache suspension (`pagehide` with `event.persisted === true`,
    /// Codex Finding #16) WITHOUT closing `CowFs` or releasing its writer lock, and WITHOUT
    /// forcing an unmodified ephemeral fork to become modified.
    pub async fn flush_for_suspend(&self) -> vfs::Result<Option<cowtree::VolumeHead>> {
        if self.closed {
            return Ok(None);
        }
        let Some(cowfs) = self.cowfs.as_ref() else {
            return Ok(None);
        };
        if cowfs.is_read_only() || cowfs.is_closed() {
            return Ok(None);
        }
        if cowfs.ms_until_dirty_deadline().is_none() {
            return Ok(None);
        }
        let head = cowfs.commit_tx_group().await?;
        Ok(Some(head))
    }

    // -------------------------------------------------------------------------
    // Observability & VFS operations
    // -------------------------------------------------------------------------

    pub fn active_console_pid(&self) -> u32 {
        if self.stage == BootStage::Stage2 {
            self.console_pid
        } else {
            1
        }
    }

    pub fn console_proc_snapshot(&self) -> Option<ConsoleProcSnapshot> {
        if self.stage != BootStage::Stage2 || self.console_pid == 1 {
            return None;
        }
        let tbl = self.proc_table.borrow();
        let p = tbl.proc(self.console_pid)?;
        let mut groups: Vec<u32> = p.cred.identity.groups.iter().copied().collect();
        groups.sort_unstable();
        Some(ConsoleProcSnapshot {
            pid: p.pid,
            ppid: p.ppid,
            uid: p.cred.identity.id,
            gid: p.cred.identity.group,
            groups,
            user: self
                .console_user
                .clone()
                .unwrap_or_else(|| self.boot_profile.default_user.clone()),
            home: self.console_home.clone().unwrap_or_else(|| "/".to_string()),
            shell: self
                .console_shell
                .clone()
                .unwrap_or_else(|| "/bin/sh".to_string()),
            cwd: p.cwd.clone(),
            tty: self.console_pty.map(|n| format!("/dev/pts/{n}")),
        })
    }

    async fn check_console_sudo_nopasswd(&self) -> vfs::Result<()> {
        let pid = self.active_console_pid();
        let identity = {
            let tbl = self.proc_table.borrow();
            tbl.proc(pid).ok_or(Errno::ESRCH)?.cred.identity.clone()
        };
        if identity.id == 0 {
            return Ok(());
        }
        let mut mem = MemoryAccountFs::default();
        for (path, mode) in [
            ("/etc/passwd", 0o644u16),
            ("/etc/group", 0o644u16),
            ("/etc/shadow", 0o600u16),
            ("/etc/sudoers", 0o440u16),
        ] {
            if let Ok(bytes) = read_file_as_pid(&self.vfs, 1, path).await {
                let _ = mem.write_file(path, &bytes, mode, 0, 0);
            }
        }
        let mut store = LocalAccountStore::new();
        let now = (self.clock_fn)().sec;
        store
            .sudo_authenticate(&mem, &identity, pid, None, now)
            .map_err(|e| e.errno)?;
        Ok(())
    }

    pub fn stage(&self) -> BootStage {
        self.stage
    }

    pub fn vfs(&self) -> &Vfs {
        &self.vfs
    }

    pub fn cowfs(&self) -> Option<&Rc<CowFs<H, P>>> {
        self.cowfs.as_ref()
    }

    pub fn boot_profile(&self) -> &BootProfile {
        &self.boot_profile
    }

    pub fn mounted_root(&self) -> Option<&MountedRootInfo> {
        self.mounted_root.as_ref()
    }

    pub fn recovery(&self) -> Option<&RecoveryState> {
        self.recovery.as_ref()
    }

    pub fn banners(&self) -> &[String] {
        &self.banners
    }

    pub fn stage1_reclaimed_entries(&self) -> usize {
        self.stage1_reclaimed_entries
    }

    pub fn stage1_tmpfs_dropped(&self) -> bool {
        self.stage1_fs_weak.strong_count() == 0
    }

    pub fn pid1_snapshot(&self) -> Pid1Snapshot {
        let tbl = self.proc_table.borrow();
        let p = tbl.proc(1).expect("PID 1 must exist");
        Pid1Snapshot {
            pid: p.pid,
            ppid: p.ppid,
            uid: p.cred.identity.id,
            gid: p.cred.identity.group,
            path: p.path.clone(),
            argv: p.argv.clone(),
            started: p.started,
            started_ticks: p.started_ticks,
            cwd: p.cwd.clone(),
        }
    }

    pub fn status(&self) -> BootStatusSnapshot {
        BootStatusSnapshot {
            stage: self.stage,
            instance_id: self.instance_id.clone(),
            pid1: self.pid1_snapshot(),
            console_proc: self.console_proc_snapshot(),
            boot_profile: self.boot_profile.clone(),
            mounted_root: self.mounted_root.clone(),
            recovery: self.recovery.clone(),
            banners: self.banners.clone(),
            fsck_report: self.fsck_report.clone(),
            stage1_reclaimed_entries: self.stage1_reclaimed_entries,
            stage1_tmpfs_dropped: self.stage1_tmpfs_dropped(),
        }
    }

    pub async fn read_file(&self, path: &str) -> vfs::Result<Vec<u8>> {
        read_file_as_pid(&self.vfs, self.active_console_pid(), path).await
    }

    pub async fn read_file_sudo(&self, path: &str) -> vfs::Result<Vec<u8>> {
        self.check_console_sudo_nopasswd().await?;
        read_file_as_pid(&self.vfs, 1, path).await
    }

    pub async fn write_file(&self, path: &str, bytes: &[u8], mode: u16) -> vfs::Result<usize> {
        write_file_as_pid(&self.vfs, self.active_console_pid(), path, bytes, mode).await
    }

    pub async fn write_file_sudo(&self, path: &str, bytes: &[u8], mode: u16) -> vfs::Result<usize> {
        self.check_console_sudo_nopasswd().await?;
        write_file_as_pid(&self.vfs, 1, path, bytes, mode).await
    }

    pub async fn mkdir(&self, path: &str, mode: u16) -> vfs::Result<()> {
        self.vfs
            .mkdirat(self.active_console_pid(), StartAnchor::Root, path, mode)
            .await
            .map(|_| ())
    }

    pub async fn mkdir_sudo(&self, path: &str, mode: u16) -> vfs::Result<()> {
        self.check_console_sudo_nopasswd().await?;
        self.vfs
            .mkdirat(1, StartAnchor::Root, path, mode)
            .await
            .map(|_| ())
    }

    pub async fn unlink(&self, path: &str) -> vfs::Result<()> {
        self.vfs
            .unlinkat(self.active_console_pid(), StartAnchor::Root, path, false)
            .await
    }

    pub async fn unlink_sudo(&self, path: &str) -> vfs::Result<()> {
        self.check_console_sudo_nopasswd().await?;
        self.vfs.unlinkat(1, StartAnchor::Root, path, false).await
    }

    pub async fn stat(&self, path: &str, follow: bool) -> vfs::Result<Stat> {
        self.vfs
            .statat(self.active_console_pid(), StartAnchor::Root, path, follow)
            .await
    }

    pub async fn stat_sudo(&self, path: &str, follow: bool) -> vfs::Result<Stat> {
        self.check_console_sudo_nopasswd().await?;
        self.vfs.statat(1, StartAnchor::Root, path, follow).await
    }

    pub async fn statfs(&self, path: &str) -> vfs::Result<StatFs> {
        self.vfs
            .statfs(self.active_console_pid(), StartAnchor::Root, path)
            .await
    }

    pub async fn readdir(&self, path: &str) -> vfs::Result<Vec<String>> {
        self.readdir_as_pid(self.active_console_pid(), path).await
    }

    pub async fn readdir_sudo(&self, path: &str) -> vfs::Result<Vec<String>> {
        self.check_console_sudo_nopasswd().await?;
        self.readdir_as_pid(1, path).await
    }

    async fn readdir_as_pid(&self, pid: u32, path: &str) -> vfs::Result<Vec<String>> {
        let mut names = Vec::new();
        let mut cookie = 0u64;
        loop {
            let page = self
                .vfs
                .read_dir_page(pid, StartAnchor::Root, path, cookie, 256)
                .await?;
            for e in page.entries {
                names.push(e.name);
            }
            match page.next_cookie {
                Some(next) if next != cookie => cookie = next,
                _ => break,
            }
        }
        Ok(names)
    }

    pub async fn sync_fs(&self) -> vfs::Result<cowtree::VolumeHead> {
        let cowfs = self.cowfs.as_ref().ok_or(Errno::ENODEV)?;
        cowfs.commit_tx_group().await
    }

    pub async fn create_snapshot(&self, name: &str) -> vfs::Result<cowtree::SnapshotRecord> {
        let cowfs = self.cowfs.as_ref().ok_or(Errno::ENODEV)?;
        cowfs.create_snapshot(name).await
    }

    pub async fn run_cowfsck(&self, volume_uuid: Option<&str>) -> vfs::Result<cowfs::FsckReport> {
        let uuid = volume_uuid
            .map(str::to_string)
            .or_else(|| self.mounted_root.as_ref().map(|r| r.volume_uuid.clone()))
            .ok_or(Errno::ENOENT)?;
        cowfsck_volume_stores(&*self.head_store, &*self.pack_store, &VolumeId(uuid)).await
    }

    /// Execute a minimal built-in interactive console command against the live VFS using the
    /// active non-PID-1 Stage 2 console login process (or PID 1 only in Stage 1 recovery).
    /// Supports `sudo <cmd...>` evaluated against real `/etc/sudoers`.
    pub async fn exec_console_command(&self, line: &str) -> (i32, String) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return (0, String::new());
        }
        let mut parts = trimmed.split_whitespace();
        let mut cmd = parts.next().unwrap_or("");
        let mut use_sudo = false;
        if cmd == "sudo" {
            if let Err(e) = self.check_console_sudo_nopasswd().await {
                return (1, format!("sudo: {}\n", e.text()));
            }
            use_sudo = true;
            cmd = parts.next().unwrap_or("");
            if cmd.is_empty() {
                return (2, "usage: sudo <command> [args...]\n".to_string());
            }
        }
        let args: Vec<&str> = parts.collect();
        let exec_pid = if use_sudo {
            1
        } else {
            self.active_console_pid()
        };
        match cmd {
            "help" => (
                0,
                "Built-in standalone console commands: uname, id, pwd, tty, ls [path], cat <path>, stat <path>, statfs [path], mount, ps, cowfsck, sync, mkdir <path>, rm <path>, write <path> <text>, sudo <cmd>\n"
                    .to_string(),
            ),
            "uname" => (0, "OS 2.0 standalone wasm32-browser os-cowfs\n".to_string()),
            "id" => {
                let (uid, gid, groups) = {
                    let tbl = self.proc_table.borrow();
                    if let Some(p) = tbl.proc(exec_pid) {
                        let mut gs: Vec<u32> = p.cred.identity.groups.iter().copied().collect();
                        gs.sort_unstable();
                        (p.cred.identity.id, p.cred.identity.group, gs)
                    } else {
                        return (1, "id: process not found\n".to_string());
                    }
                };
                let user_map: HashMap<u32, String> = read_file_as_pid(&self.vfs, 1, "/etc/passwd")
                    .await
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
                    .and_then(|t| parse_passwd(&t).ok())
                    .map(|es| es.into_iter().map(|e| (e.uid, e.name)).collect())
                    .unwrap_or_default();
                let group_map: HashMap<u32, String> = read_file_as_pid(&self.vfs, 1, "/etc/group")
                    .await
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
                    .and_then(|t| parse_group(&t).ok())
                    .map(|es| es.into_iter().map(|e| (e.gid, e.name)).collect())
                    .unwrap_or_default();
                let uname = user_map
                    .get(&uid)
                    .cloned()
                    .unwrap_or_else(|| uid.to_string());
                let gname = group_map
                    .get(&gid)
                    .cloned()
                    .unwrap_or_else(|| gid.to_string());
                let g_list: Vec<String> = groups
                    .iter()
                    .map(|g| match group_map.get(g) {
                        Some(n) => format!("{g}({n})"),
                        None => g.to_string(),
                    })
                    .collect();
                (
                    0,
                    format!("uid={uid}({uname}) gid={gid}({gname}) groups={}\n", g_list.join(",")),
                )
            }
            "pwd" => match self.vfs.getcwd(exec_pid).await {
                Ok(cwd) => (0, format!("{cwd}\n")),
                Err(e) => (1, format!("pwd: {}\n", e.text())),
            },
            "tty" => match self.console_pty {
                Some(n) if self.stage == BootStage::Stage2 => (0, format!("/dev/pts/{n}\n")),
                _ => (1, "not a tty\n".to_string()),
            },
            "ls" => {
                let target = args.first().copied().unwrap_or("/");
                match self.readdir_as_pid(exec_pid, target).await {
                    Ok(mut entries) => {
                        entries.sort();
                        (0, format!("{}\n", entries.join("  ")))
                    }
                    Err(e) => (1, format!("ls: {target}: {}\n", e.text())),
                }
            }
            "cat" => {
                let Some(&target) = args.first() else {
                    return (2, "usage: cat <path>\n".to_string());
                };
                match read_file_as_pid(&self.vfs, exec_pid, target).await {
                    Ok(bytes) => (0, String::from_utf8_lossy(&bytes).into_owned()),
                    Err(e) => (1, format!("cat: {target}: {}\n", e.text())),
                }
            }
            "stat" => {
                let Some(&target) = args.first() else {
                    return (2, "usage: stat <path>\n".to_string());
                };
                match self
                    .vfs
                    .statat(exec_pid, StartAnchor::Root, target, false)
                    .await
                {
                    Ok(st) => (
                        0,
                        format!(
                            "file={} mode={:04o} uid={} gid={} size={} dev={} ino={}\n",
                            target,
                            st.mode & 0o7777,
                            st.uid,
                            st.gid,
                            st.size,
                            st.dev,
                            st.ino
                        ),
                    ),
                    Err(e) => (1, format!("stat: {target}: {}\n", e.text())),
                }
            }
            "statfs" => {
                let target = args.first().copied().unwrap_or("/");
                match self.vfs.statfs(exec_pid, StartAnchor::Root, target).await {
                    Ok(sf) => (
                        0,
                        format!(
                            "path={} f_type=0x{:08x} f_bsize={} f_blocks={} f_bfree={}\n",
                            target, sf.f_type, sf.bsize, sf.blocks, sf.bfree
                        ),
                    ),
                    Err(e) => (1, format!("statfs: {target}: {}\n", e.text())),
                }
            }
            "mount" => match read_file_as_pid(&self.vfs, exec_pid, "/proc/mounts").await {
                Ok(bytes) => (0, String::from_utf8_lossy(&bytes).into_owned()),
                Err(e) => (1, format!("mount: {}\n", e.text())),
            },
            "ps" => {
                let tbl = self.proc_table.borrow();
                let mut pids = tbl.all_pids();
                pids.sort_unstable();
                let mut out = String::from("PID  PPID UID  STARTED CMD\n");
                for pid in pids {
                    if let Some(p) = tbl.proc(pid) {
                        out.push_str(&format!(
                            "{:<4} {:<4} {:<4} {:<7} {}\n",
                            p.pid,
                            p.ppid,
                            p.cred.identity.id,
                            p.started,
                            p.argv.join(" ")
                        ));
                    }
                }
                (0, out)
            }
            "cowfsck" => match self.run_cowfsck(args.first().copied()).await {
                Ok(rep) => (
                    if rep.ok { 0 } else { 4 },
                    format!(
                        "cowfsck: ok={} volume={} epoch={} nodes={} packs={} errors={}\n",
                        rep.ok,
                        rep.volume,
                        rep.epoch,
                        rep.nodes_verified,
                        rep.packs_verified,
                        rep.errors.len()
                    ),
                ),
                Err(e) => (8, format!("cowfsck: {}\n", e.text())),
            },
            "sync" => match self.sync_fs().await {
                Ok(head) => (
                    0,
                    format!("synced volume={} epoch={}\n", head.volume.0, head.epoch),
                ),
                Err(e) => (1, format!("sync: {}\n", e.text())),
            },
            "mkdir" => {
                let Some(&target) = args.first() else {
                    return (2, "usage: mkdir <path>\n".to_string());
                };
                match self.vfs.mkdirat(exec_pid, StartAnchor::Root, target, 0o755).await {
                    Ok(_) => (0, String::new()),
                    Err(e) => (1, format!("mkdir: {target}: {}\n", e.text())),
                }
            }
            "rm" => {
                let Some(&target) = args.first() else {
                    return (2, "usage: rm <path>\n".to_string());
                };
                match self.vfs.unlinkat(exec_pid, StartAnchor::Root, target, false).await {
                    Ok(()) => (0, String::new()),
                    Err(e) => (1, format!("rm: {target}: {}\n", e.text())),
                }
            }
            "write" => {
                if args.len() < 2 {
                    return (2, "usage: write <path> <text>\n".to_string());
                }
                let target = args[0];
                let body = format!("{}\n", args[1..].join(" "));
                match write_file_as_pid(&self.vfs, exec_pid, target, body.as_bytes(), 0o644).await {
                    Ok(n) => (0, format!("wrote {n} bytes to {target}\n")),
                    Err(e) => (1, format!("write: {target}: {}\n", e.text())),
                }
            }
            other => (127, format!("sh: {other}: command not found\n")),
        }
    }
}

// -----------------------------------------------------------------------------
// Browser `wasm-bindgen` bindings for Stage 0 -> Stage 1 -> Stage 2 Offline Boot
// -----------------------------------------------------------------------------

fn parse_extensions_array(val: &JsValue) -> Result<Vec<Image>, JsValue> {
    if val.is_undefined() || val.is_null() {
        return Ok(Vec::new());
    }
    let arr = js_sys::Array::from(val);
    let mut out = Vec::with_capacity(arr.length() as usize);
    for i in 0..arr.length() {
        let item = arr.get(i);
        let text = item.as_string().ok_or_else(|| {
            js_errno(Errno::EINVAL, "extensions_json must be an array of strings")
        })?;
        let img = Image::parse(text.as_bytes())
            .map_err(|e| js_errno(Errno::EINVAL, &format!("invalid extension image: {e}")))?;
        out.push(img);
    }
    Ok(out)
}

/// Browser-facing `wasm-bindgen` wrapper over [`TwoStageBoot`] backed by `JsCowfsStore`
/// (OPFS + strict IndexedDB + Web Locks) and `VerifiedAssetBlobStore` (`self.imageBlobRead`).
#[wasm_bindgen]
pub struct OfflineBootRuntime {
    inner: TwoStageBoot<JsCowfsStore, JsCowfsStore, VerifiedAssetBlobStore>,
}

#[wasm_bindgen]
impl OfflineBootRuntime {
    /// Execute a full standalone offline boot (`Stage 0 -> Stage 1 -> cowfsck -> os-cowfs ->
    /// switch_root -> Stage 2`) or pause in `Stage1Recovery` when `EPROTONOSUPPORT`, corruption,
    /// `EBUSY`, or `boot_profile.recovery` occurs.
    pub async fn boot(
        store: JsValue,
        boot_profile_json: String,
        initramfs_json: String,
        root_template_json: String,
        base_json: String,
        extensions_json: JsValue,
    ) -> Result<OfflineBootRuntime, JsValue> {
        let profile: BootProfile = serde_json::from_str(&boot_profile_json)
            .map_err(|e| js_errno(Errno::EINVAL, &format!("invalid boot profile: {e}")))?;
        let initramfs = Image::parse(initramfs_json.as_bytes())
            .map_err(|e| js_errno(Errno::EINVAL, &format!("invalid initramfs image: {e}")))?;
        let root_template = Image::parse(root_template_json.as_bytes())
            .map_err(|e| js_errno(Errno::EINVAL, &format!("invalid root_template image: {e}")))?;
        let base = Image::parse(base_json.as_bytes())
            .map_err(|e| js_errno(Errno::EINVAL, &format!("invalid base image: {e}")))?;
        let extensions = parse_extensions_array(&extensions_json)?;

        let adapter = Rc::new(JsCowfsStore { obj: store });
        let instance_id = format!("os-{}", crate::random_hex(12));
        let inner = TwoStageBoot::new_cowfs_root(
            instance_id,
            profile,
            ReleaseImages {
                initramfs,
                root_template,
                base,
                extensions,
            },
            Rc::clone(&adapter),
            adapter,
            VerifiedAssetBlobStore,
            Rc::new(now_timespec),
            make_uuid,
        )
        .await
        .map_err(map_vfs_err)?;

        Ok(Self { inner })
    }

    pub fn status(&self) -> Result<JsValue, JsValue> {
        crate::cowfs_bridge::to_js_json(&self.inner.status())
    }

    pub async fn read_file(&self, path: String, sudo: Option<bool>) -> Result<Vec<u8>, JsValue> {
        let res = if sudo.unwrap_or(false) {
            self.inner.read_file_sudo(&path).await
        } else {
            self.inner.read_file(&path).await
        };
        res.map_err(map_vfs_err)
    }

    pub async fn write_file(
        &self,
        path: String,
        bytes: &[u8],
        mode: Option<u16>,
        sudo: Option<bool>,
    ) -> Result<usize, JsValue> {
        let m = mode.unwrap_or(0o644);
        let res = if sudo.unwrap_or(false) {
            self.inner.write_file_sudo(&path, bytes, m).await
        } else {
            self.inner.write_file(&path, bytes, m).await
        };
        res.map_err(map_vfs_err)
    }

    pub async fn mkdir(
        &self,
        path: String,
        mode: Option<u16>,
        sudo: Option<bool>,
    ) -> Result<(), JsValue> {
        let m = mode.unwrap_or(0o755);
        let res = if sudo.unwrap_or(false) {
            self.inner.mkdir_sudo(&path, m).await
        } else {
            self.inner.mkdir(&path, m).await
        };
        res.map_err(map_vfs_err)
    }

    pub async fn unlink(&self, path: String, sudo: Option<bool>) -> Result<(), JsValue> {
        let res = if sudo.unwrap_or(false) {
            self.inner.unlink_sudo(&path).await
        } else {
            self.inner.unlink(&path).await
        };
        res.map_err(map_vfs_err)
    }

    pub async fn stat(
        &self,
        path: String,
        follow: Option<bool>,
        sudo: Option<bool>,
    ) -> Result<JsValue, JsValue> {
        let f = follow.unwrap_or(true);
        let st = if sudo.unwrap_or(false) {
            self.inner.stat_sudo(&path, f).await
        } else {
            self.inner.stat(&path, f).await
        }
        .map_err(map_vfs_err)?;
        crate::cowfs_bridge::to_js_json(&st)
    }

    pub async fn statfs(&self, path: String) -> Result<JsValue, JsValue> {
        let sf = self.inner.statfs(&path).await.map_err(map_vfs_err)?;
        crate::cowfs_bridge::to_js_json(&sf)
    }

    pub async fn readdir(&self, path: String, sudo: Option<bool>) -> Result<JsValue, JsValue> {
        let entries = if sudo.unwrap_or(false) {
            self.inner.readdir_sudo(&path).await
        } else {
            self.inner.readdir(&path).await
        }
        .map_err(map_vfs_err)?;
        crate::cowfs_bridge::to_js_json(&entries)
    }

    pub async fn flush_for_suspend(&self) -> Result<JsValue, JsValue> {
        let head = self
            .inner
            .flush_for_suspend()
            .await
            .map_err(map_vfs_err)?;
        crate::cowfs_bridge::to_js_json(&head)
    }

    pub async fn sync_fs(&self) -> Result<JsValue, JsValue> {
        let head = self.inner.sync_fs().await.map_err(map_vfs_err)?;
        crate::cowfs_bridge::to_js_json(&head)
    }

    pub async fn snapshot(&self, name: String) -> Result<JsValue, JsValue> {
        let snap = self
            .inner
            .create_snapshot(&name)
            .await
            .map_err(map_vfs_err)?;
        crate::cowfs_bridge::to_js_json(&snap)
    }

    pub async fn run_cowfsck(&self, volume_uuid: Option<String>) -> Result<JsValue, JsValue> {
        let rep = self
            .inner
            .run_cowfsck(volume_uuid.as_deref())
            .await
            .map_err(map_vfs_err)?;
        crate::cowfs_bridge::to_js_json(&rep)
    }

    pub async fn rollback_snapshot(&mut self, snapshot_name: String) -> Result<JsValue, JsValue> {
        self.inner
            .rollback_to_snapshot(&snapshot_name, make_uuid)
            .await
            .map_err(map_vfs_err)?;
        self.status()
    }

    pub async fn fork_from_recovery(&mut self) -> Result<JsValue, JsValue> {
        self.inner.fork_from_recovery().await.map_err(map_vfs_err)?;
        self.status()
    }

    /// Expose `switch_root` directly so tests (`B-08`) can assert `EPERM` (non-PID-1) and
    /// `EINVAL` (when `/` is already `os-cowfs` instead of `tmpfs`).
    pub async fn switch_root_attempt(
        &mut self,
        caller_pid: u32,
        newroot: String,
        init_path: String,
    ) -> Result<(), JsValue> {
        let args = vec![init_path.clone()];
        self.inner
            .switch_root(caller_pid, &newroot, &init_path, &args)
            .await
            .map_err(map_vfs_err)
    }

    pub async fn exec_command(&self, line: String) -> Result<JsValue, JsValue> {
        let (code, output) = self.inner.exec_console_command(&line).await;
        crate::cowfs_bridge::to_js_json(&json!({ "code": code, "output": output }))
    }

    pub async fn close_clean_with_prune(&mut self) -> Result<JsValue, JsValue> {
        let outcome = self
            .inner
            .close_clean_with_prune()
            .await
            .map_err(map_vfs_err)?;
        crate::cowfs_bridge::to_js_json(&outcome)
    }
}

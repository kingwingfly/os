//! Versions, filesystem types, and capability descriptions from the architecture contract
//! (`docs/architecture/contract.md`), defined in L0b (#47) and amended to Contract v2 in L0c
//! (#76) for the steps that follow. `Errno` carries the names the contract adds (`ENOTCONN`,
//! `ENOLCK`, `EDQUOT`, `EPROTONOSUPPORT`, `ENOTBLK`).

use crate::Errno;
use serde::{Deserialize, Serialize};

/// An interface whose two sides carry and negotiate a version (contract §6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Boundary {
    /// Applications and the kernel: `Call` and the WASI/WASIX imports.
    Syscall,
    /// The portable kernel and its host (`browser`, `os-native`, `container`): host/page protocol,
    /// Worker/process spawning, offline install, `cowfs` store, and volume locks.
    HostAdapter,
    /// Filesystem clients and optional `cloud` (`/mnt/cloud`) or `sharefs` filesystem services.
    RemoteFilesystem,
    /// The helper driver and `os-local-helper`.
    LocalHelper,
    /// Userspace cloud/cluster clients and remote auth services: acquiring, renewing, scoping,
    /// and revoking explicit cloud service credentials (decoupled from local `/etc/passwd`;
    /// formerly `Identity` in Contract v1).
    ServiceAuth,
    /// Typed devices and remote tasks.
    DeviceTask,
    /// Signed offline boot sets, images, and release manifests.
    Release,
    /// GUI clients, the compositor, `/dev/display` and `/dev/input`.
    Gui,
    /// Fenced remote `cowfs` volume head/lease/pin protocol and R2 pack gateway (#80).
    Volume,
    /// OCI Distribution v1.1 subset and `cowfs` snapshot artifact v1 over the shared pack store
    /// (#81).
    Registry,
    /// `ClusterState` Durable Object revisioned KV/Watch/Lease/Compact store (reserved, Phase 9
    /// #83).
    ClusterState,
    /// `netd` outbound stream socket gateway (#86) and `/dev/net/tun` L3 tenant overlay (#87)
    /// (reserved, Phase 10).
    Network,
}

impl Boundary {
    /// The version of this boundary that Contract v2 defines (contract §6).
    pub const fn version(self) -> u32 {
        match self {
            Boundary::Syscall => SYSCALL_VERSION,
            Boundary::HostAdapter => HOST_ADAPTER_VERSION,
            Boundary::RemoteFilesystem => REMOTE_FILESYSTEM_VERSION,
            Boundary::LocalHelper => LOCAL_HELPER_VERSION,
            Boundary::ServiceAuth => SERVICE_AUTH_VERSION,
            Boundary::DeviceTask => DEVICE_TASK_VERSION,
            Boundary::Release => RELEASE_VERSION,
            Boundary::Gui => GUI_VERSION,
            Boundary::Volume => VOLUME_VERSION,
            Boundary::Registry => REGISTRY_VERSION,
            Boundary::ClusterState => CLUSTER_STATE_VERSION,
            Boundary::Network => NETWORK_VERSION,
        }
    }
}

pub const SYSCALL_VERSION: u32 = 1;
/// Bumped from 1 -> 2 in Contract v2 (#76) for offline release pinning, local `cowfs` store,
/// volume locks, and browser/`os-native`/container host symmetry (#77, #78, #82).
pub const HOST_ADAPTER_VERSION: u32 = 2;
/// Handle-addressed calls for optional `cloud` (`/mnt/cloud`) and `sharefs` (contract §2.3).
pub const REMOTE_FILESYSTEM_VERSION: u32 = 2;
/// The helper's `protocol` field, negotiated via `Hello` (`crates/local-helper`).
pub const LOCAL_HELPER_VERSION: u32 = 1;
/// Explicit cloud/cluster service credential acquisition, scoping, renewal, and revocation
/// (formerly `IDENTITY_VERSION = 1` in Contract v1; decoupled from local `/etc/passwd`).
pub const SERVICE_AUTH_VERSION: u32 = 2;
/// The device/task boundary as a whole. Each device's own formats, such as the accelerator
/// ioctl (`accelerator::VERSION`), are versioned separately within it.
pub const DEVICE_TASK_VERSION: u32 = 1;
/// Bumped from 1 -> 2 in Contract v2 (#76) for the complete signed offline boot set (`#78`).
/// `os_image::PROTOCOL` (`crates/image`) adopts v2 when `#78` lands.
pub const RELEASE_VERSION: u32 = 2;
/// Negotiated seat and surface protocol implemented by the compositor and host adapters (§2.9).
pub const GUI_VERSION: u32 = 1;
/// Fenced remote `cowfs` volume protocol (`incarnation`, `fence`, `epoch`, R2 pack gateway; #80).
pub const VOLUME_VERSION: u32 = 1;
/// OCI Distribution v1.1 subset + `cowfs` snapshot artifact v1 (#81).
pub const REGISTRY_VERSION: u32 = 1;
/// Reserved for Phase 9 `ClusterState` DO store (#83).
pub const CLUSTER_STATE_VERSION: u32 = 1;
/// Reserved for Phase 10 `netd` stream gateway (#86) and `/dev/net/tun` overlay (#87).
pub const NETWORK_VERSION: u32 = 1;

/// Stored on-disk/IndexedDB format version for `os-cowfs` v1 (`OSCOWFS1`; contract §2.15, §6).
/// Incompatible formats are refused with `EPROTONOSUPPORT` without silently resetting user data.
pub const COWFS_FORMAT_VERSION: u32 = 1;

/// The first message on a connection: the boundary, and the versions this side speaks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub boundary: Boundary,
    pub versions: Vec<u32>,
}

/// The version two sides use: the highest both offer for the same boundary. `None` means the
/// connection is refused with EPROTONOSUPPORT; a page recovers as contract §2.10 says.
pub fn negotiate(ours: &Hello, theirs: &Hello) -> Option<u32> {
    if ours.boundary != theirs.boundary {
        return None;
    }
    ours.versions
        .iter()
        .filter(|version| theirs.versions.contains(version))
        .max()
        .copied()
}

/// Canonical filesystem types defined by `contract.md` §2.7 and §5 (11 types in Contract v2).
/// Unknown types (explicitly including `"sysfs"`) return `Err(Errno::ENODEV)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FsType {
    /// Optional, feature-frozen remote shared file tree (`/mnt/cloud` or explicit `chroot`).
    Cloud,
    /// MIT pure-Rust single-map Merkle CoW B+tree filesystem (default `/` root and volumes).
    Cowfs,
    /// Browser profile OPFS tree (`os-workspace`).
    Opfs,
    /// Host folder mounted via browser directory handle.
    HostFs,
    /// Host folder mounted via `os-local-helper`.
    HelperFs,
    /// Publisher-hosted userspace export mount.
    ShareFs,
    /// Read-only signed release or private extension image.
    Image,
    /// Instance-local in-memory filesystem.
    TmpFs,
    /// Instance-local process/mount virtual filesystem (`/proc`).
    Proc,
    /// Instance-local device node filesystem (`/dev`).
    DevTmpFs,
    /// Instance-local slave PTY filesystem (`/dev/pts`).
    DevPts,
}

impl FsType {
    /// Parse a canonical contract §5 fstype string. Unknown types (explicitly including `"sysfs"`)
    /// return `Err(Errno::ENODEV)`.
    pub fn parse(name: &str) -> Result<Self, Errno> {
        match name {
            "cloud" => Ok(Self::Cloud),
            "cowfs" => Ok(Self::Cowfs),
            "opfs" => Ok(Self::Opfs),
            "hostfs" => Ok(Self::HostFs),
            "helperfs" => Ok(Self::HelperFs),
            "sharefs" => Ok(Self::ShareFs),
            "image" => Ok(Self::Image),
            "tmpfs" => Ok(Self::TmpFs),
            "proc" => Ok(Self::Proc),
            "devtmpfs" => Ok(Self::DevTmpFs),
            "devpts" => Ok(Self::DevPts),
            _ => Err(Errno::ENODEV),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cloud => "cloud",
            Self::Cowfs => "cowfs",
            Self::Opfs => "opfs",
            Self::HostFs => "hostfs",
            Self::HelperFs => "helperfs",
            Self::ShareFs => "sharefs",
            Self::Image => "image",
            Self::TmpFs => "tmpfs",
            Self::Proc => "proc",
            Self::DevTmpFs => "devtmpfs",
            Self::DevPts => "devpts",
        }
    }

    pub const fn magic(self) -> u64 {
        match self {
            Self::Cloud => fs_magic::OS_CLOUD_MAGIC,
            Self::Cowfs => fs_magic::OS_COWFS_MAGIC,
            Self::Opfs | Self::HostFs | Self::HelperFs | Self::ShareFs => {
                fs_magic::FUSE_SUPER_MAGIC
            }
            Self::Image => fs_magic::SQUASHFS_MAGIC,
            Self::TmpFs => fs_magic::TMPFS_MAGIC,
            Self::Proc => fs_magic::PROC_SUPER_MAGIC,
            Self::DevTmpFs => fs_magic::DEVTMPFS_MAGIC,
            Self::DevPts => fs_magic::DEVPTS_SUPER_MAGIC,
        }
    }

    /// Whether an ordinary (non-root) local user with an explicit mount grant may invoke
    /// `mount(2)` directly for this filesystem type (contract §2.7).
    pub const fn is_user_mountable(self) -> bool {
        matches!(
            self,
            Self::Opfs | Self::HostFs | Self::HelperFs | Self::ShareFs | Self::Image
        )
    }
}

/// How widely a filesystem's identity holds (contract §2.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityScope {
    /// The same everywhere the filesystem is reached.
    Global,
    /// Exists only within one instance, as tmpfs and procfs.
    Instance,
    /// Stable on one host: the helper's folder UUID or native local `cowfs` volume UUID.
    HostLocal,
    /// Stable only within one browser profile.
    ProfileLocal,
    /// The publisher's, passed through.
    Publisher,
}

/// Whether a driver provides a behaviour (contract §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Support {
    Yes,
    /// Provided by the OS's own metadata, coordinated across the browser profile's tabs; a
    /// change made outside the OS can still show the difference.
    Emulated,
    /// Not provided: the operation fails with this errno.
    Refused(Errno),
    /// The operation succeeds, but later access through a file already open fails with this
    /// errno.
    Stale(Errno),
    /// Not provided, and declared so: the operation runs without the guarantee.
    Declared,
    /// Whatever the publisher of a shared mount provides.
    Publisher,
}

/// Concurrency and writer ownership model of a filesystem driver (contract §2.15, §3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WriterModel {
    /// Single local exclusive writer: instance-local filesystems (`tmpfs`, `proc`, `devtmpfs`,
    /// `devpts`) or a local `cowfs` volume gated by profile Web Lock `os-vol:<uuid>` / host
    /// `flock` + `local_fence`.
    #[default]
    Local,
    /// Single remotely fenced RW writer (`incarnation` + `fence` + `epoch`, 60 s DO-clock lease)
    /// with unlimited concurrent pinned RO readers and O(1) forks (remote `cowfs` volume).
    Fenced,
    /// Immutable read-only image or pinned snapshot (`image`, `cowfs` snapshot / RO pinned view).
    Immutable,
    /// Concurrent multi-writer filesystem coordinated by a remote authority, browser profile
    /// locks, or host kernel (`cloud`, `opfs`, `hostfs`, `helperfs`, or any future distinct RWX
    /// cloud filesystem driver/tier — explicitly not `cowfs`).
    MultiWriter,
    /// Whatever writer concurrency model the publisher of a shared export (`sharefs`) provides.
    Publisher,
}

/// When `fsync` / `syncfs` may return (contract §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Durability {
    /// The cloud filesystem authority's transaction and chunk commit.
    ServiceCommit,
    /// Closing a browser writable stream, or a sync handle's flush.
    WritableClose,
    /// The host's `fsync(2)`.
    HostFsync,
    /// The publisher's acknowledgement.
    PublisherAck,
    /// None: the content is in the instance's memory and goes with it (`tmpfs`), so `fsync` has
    /// nothing to wait for.
    Volatile,
    /// Local `os-cowfs` crash-safe tree commit: immutable pack flush (`FileSystemSyncAccessHandle`
    /// `flush()` + `close()` in browser, `fsync(2)` natively) followed by one atomic head CAS
    /// (`{durability: "strict"}` IndexedDB txn in browser, SQLite `WAL` + `synchronous=FULL`
    /// natively) checked against `local_fence`.
    TreeCommit,
    /// Remote `os-cowfs` fenced commit: verified R2 pack PUT acknowledgements followed by a
    /// triple-fenced (`incarnation`, `fence`, `parent_epoch`) Storage DO SQLite head transaction
    /// recording an idempotent `receipts[op_id]`.
    FencedCommit,
}

/// Who keeps a filesystem's locks (`flock` and `fcntl` byte ranges), so every client of it sees
/// them (contract §3). A driver that cannot reach its keeper fails with ENOLCK; none fakes a lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LockScope {
    /// The filesystem service (the cloud authority), for every instance.
    Service,
    /// A filesystem that exists only within one instance (`tmpfs`) or has a single exclusive
    /// writer instance (`cowfs`), so its locks are seen by every writer client.
    Instance,
    /// Every tab of the browser profile, through Web Locks and the metadata store.
    Profile,
    /// The host's own locks, held by the helper, seen by every host program.
    Host,
    /// The publisher of a shared mount.
    Publisher,
}

fn default_unsupported() -> Support {
    Support::Refused(Errno::EOPNOTSUPP)
}

/// What one filesystem driver provides; every gate is read against it (contract §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsCapabilities {
    pub identity: IdentityScope,
    pub open_survives_unlink: Support,
    pub open_survives_rename: Support,
    pub hard_links: Support,
    pub symlinks: Support,
    /// Atomic `O_EXCL` creation.
    pub exclusive_create: Support,
    /// Rename that replaces its target atomically.
    pub atomic_rename: Support,
    /// `RENAME_NOREPLACE`.
    pub rename_noreplace: Support,
    /// O(1) snapshot and fork support (contract §2.15, §3).
    #[serde(default = "default_unsupported")]
    pub snapshots: Support,
    /// Intra-filesystem `FICLONE` reflink support (contract §2.15, §3).
    #[serde(default = "default_unsupported")]
    pub reflink: Support,
    /// Writer concurrency model (contract §2.15, §3).
    #[serde(default)]
    pub writer_model: WriterModel,
    pub durability: Durability,
    pub locks: LockScope,
}

/// Identities an instance carries (contract §1). None of them is a credential: a remote
/// service acts only on an explicit cloud service credential (or revocable node credential) it
/// issued. Remote seat/PTY attachment to a hosted `os-native` instance is reserved for Phase 9
/// (#82).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceIdentity {
    /// Random per boot, created locally with zero remote requests; an instance has one boot.
    pub instance: String,
    /// The execution host running it (`browser`, `os-native`, or `container`).
    pub host: String,
}

/// mount(2) flags, with Linux's values (contract §5).
pub mod mount_flags {
    use crate::Errno;

    pub const MS_RDONLY: u64 = 1;
    pub const MS_NOSUID: u64 = 2;
    pub const MS_NODEV: u64 = 4;
    pub const MS_NOEXEC: u64 = 8;
    /// Every write waits for the driver's durability point.
    pub const MS_SYNCHRONOUS: u64 = 16;
    pub const MS_REMOUNT: u64 = 32;
    /// Directory changes wait for the driver's durability point.
    pub const MS_DIRSYNC: u64 = 128;
    /// Path walks through this mount refuse symlinks.
    pub const MS_NOSYMFOLLOW: u64 = 256;
    pub const MS_NOATIME: u64 = 1024;
    pub const MS_NODIRATIME: u64 = 2048;
    pub const MS_BIND: u64 = 4096;
    pub const MS_MOVE: u64 = 8192;
    pub const MS_REC: u64 = 16384;
    /// Accepted and ignored, as Linux does.
    pub const MS_SILENT: u64 = 32768;
    /// Accepted and ignored: ACLs are always enabled.
    pub const MS_POSIXACL: u64 = 1 << 16;
    pub const MS_PRIVATE: u64 = 1 << 18;
    pub const MS_RELATIME: u64 = 1 << 21;
    /// Accepted and ignored.
    pub const MS_I_VERSION: u64 = 1 << 23;
    pub const MS_STRICTATIME: u64 = 1 << 24;
    pub const MS_LAZYTIME: u64 = 1 << 25;
    /// Rejected with EINVAL: propagation is private only.
    pub const MS_UNBINDABLE: u64 = 1 << 17;
    pub const MS_SLAVE: u64 = 1 << 19;
    pub const MS_SHARED: u64 = 1 << 20;
    /// The old magic number callers may put in the top 16 bits; Linux discards it.
    pub const MS_MGC_VAL: u64 = 0xC0ED_0000;
    pub const MS_MGC_MSK: u64 = 0xFFFF_0000;
    /// Every flag the contract gives meaning to.
    pub const SUPPORTED: u64 = MS_RDONLY
        | MS_NOSUID
        | MS_NODEV
        | MS_NOEXEC
        | MS_SYNCHRONOUS
        | MS_REMOUNT
        | MS_DIRSYNC
        | MS_NOSYMFOLLOW
        | MS_NOATIME
        | MS_NODIRATIME
        | MS_BIND
        | MS_MOVE
        | MS_REC
        | MS_PRIVATE
        | MS_RELATIME
        | MS_STRICTATIME
        | MS_LAZYTIME;

    /// Flags Linux accepts that change nothing here.
    pub const IGNORED: u64 = MS_SILENT | MS_POSIXACL | MS_I_VERSION;

    /// The flags a mount(2) call means: the magic number and the ignored flags dropped, anything
    /// the contract does not support refused with EINVAL.
    pub fn accepted(flags: u64) -> Result<u64, Errno> {
        let flags = if flags & MS_MGC_MSK == MS_MGC_VAL {
            flags & !MS_MGC_MSK
        } else {
            flags
        } & !IGNORED;
        if flags & !SUPPORTED == 0 {
            Ok(flags)
        } else {
            Err(Errno::EINVAL)
        }
    }
}

/// umount2(2) flags, with Linux's values (contract §5).
pub mod umount_flags {
    use crate::Errno;

    /// Instance root only (EPERM otherwise): fails the provider's outstanding requests with EIO,
    /// then unmounts as without it.
    pub const MNT_FORCE: u32 = 1;
    pub const MNT_DETACH: u32 = 2;
    /// Rejected with EINVAL.
    pub const MNT_EXPIRE: u32 = 4;
    pub const UMOUNT_NOFOLLOW: u32 = 8;
    pub const SUPPORTED: u32 = MNT_FORCE | MNT_DETACH | UMOUNT_NOFOLLOW;

    /// Validate umount2(2) flags, rejecting MNT_EXPIRE and any unknown bit with EINVAL.
    pub const fn accepted(flags: u32) -> Result<u32, Errno> {
        if flags & !SUPPORTED == 0 {
            Ok(flags)
        } else {
            Err(Errno::EINVAL)
        }
    }
}

/// unshare(2) and setns(2) flags, with Linux's values (contract §5). CLONE_NEWNS is the only
/// namespace; CLONE_FS and CLONE_FILES unshare process-local state.
pub mod unshare_flags {
    use crate::Errno;

    pub const CLONE_FS: u32 = 0x0200;
    pub const CLONE_FILES: u32 = 0x0400;
    pub const CLONE_NEWNS: u32 = 0x0002_0000;
    pub const SUPPORTED: u32 = CLONE_FS | CLONE_FILES | CLONE_NEWNS;

    /// unshare(2): 0 is a valid no-op; any unknown bit (CLONE_NEWUSER, CLONE_NEWPID, etc.) -> EINVAL.
    pub const fn accepted_unshare(flags: u32) -> Result<u32, Errno> {
        if flags & !SUPPORTED == 0 {
            Ok(flags)
        } else {
            Err(Errno::EINVAL)
        }
    }

    /// setns(2): nstype is 0 (any/mount ns) or CLONE_NEWNS; any other flag -> EINVAL.
    pub const fn accepted_setns(nstype: u32) -> Result<u32, Errno> {
        if nstype == 0 || nstype == CLONE_NEWNS {
            Ok(nstype)
        } else {
            Err(Errno::EINVAL)
        }
    }
}

/// statvfs / statfs f_flag bits (Linux ST_* values, matching MS_* for the low bits).
pub mod statfs_flags {
    pub const ST_RDONLY: u64 = 1;
    pub const ST_NOSUID: u64 = 2;
    pub const ST_NODEV: u64 = 4;
    pub const ST_NOEXEC: u64 = 8;
    pub const ST_SYNCHRONOUS: u64 = 16;
    pub const ST_NOATIME: u64 = 1024;
    pub const ST_NODIRATIME: u64 = 2048;
    pub const ST_RELATIME: u64 = 4096;
    pub const ST_NOSYMFOLLOW: u64 = 8192;
}

/// Linux and OS `f_type` magic numbers returned by `StatFs`.
pub mod fs_magic {
    pub const TMPFS_MAGIC: u64 = 0x0102_1994;
    pub const PROC_SUPER_MAGIC: u64 = 0x0000_9fa0;
    pub const DEVPTS_SUPER_MAGIC: u64 = 0x0000_1cd1;
    pub const DEVTMPFS_MAGIC: u64 = 0x0102_1994;
    pub const SQUASHFS_MAGIC: u64 = 0x7371_7368;
    pub const FUSE_SUPER_MAGIC: u64 = 0x6573_5546;
    /// `"OSCL"`: optional `FsType::Cloud` shared tree.
    pub const OS_CLOUD_MAGIC: u64 = 0x4f53_434c;
    /// `"OSCW"`: MIT pure-Rust `os-cowfs` Merkle CoW B+tree volume.
    pub const OS_COWFS_MAGIC: u64 = 0x4f53_4357;
}

/// ioctl(2) request numbers defined by Contract v2 for `cowfs` volumes and `/dev/vdN` devices
/// (contract §2.15, §2.16, §5).
pub mod cowfs_ioctl {
    /// Linux `FICLONERANGE` (`_IOW(0x94, 13, struct file_clone_range)`).
    pub const FICLONERANGE: u32 = 0x4020_940d;
    /// Create an O(1) named snapshot (`name -> root_digest`) of a mounted `cowfs` volume.
    pub const COWFS_IOC_SNAPSHOT: u32 = 0x5457_0201;
    /// Create an O(1) fork volume UUID seeded from a snapshot root.
    pub const COWFS_IOC_FORK: u32 = 0x5457_0202;
    /// Query volume UUID, root digest, epoch, writer model, and durability metadata.
    pub const COWFS_IOC_INFO: u32 = 0x5457_0203;
    /// Run a read-only Merkle integrity check (`os_cowfs::fsck`) against a pinned volume head.
    pub const COWFS_IOC_FSCK: u32 = 0x5457_0204;
    /// Format `/dev/vdN` or `volume:<id>` as a clean `os-cowfs` volume (root only).
    pub const COWFS_IOC_MKFS: u32 = 0x5457_0205;
    /// List, create, or delete subvolumes on a `cowfs` volume (`List` readable; `Create`/`Delete` root only).
    pub const COWFS_IOC_SUBVOL: u32 = 0x5457_0206;
    /// List named snapshots on a `cowfs` volume.
    pub const COWFS_IOC_SNAP_LIST: u32 = 0x5457_0207;
    /// Delete a named snapshot on a `cowfs` volume (root only).
    pub const COWFS_IOC_SNAP_DELETE: u32 = 0x5457_0208;
    /// Stream Merkle delta (`OSCOWS1`) or read-only pack archive (`OSCOWA1`) to `stream_fd`.
    pub const COWFS_IOC_SEND: u32 = 0x5457_0209;
    /// Ingest and atomically verify/commit an `OSCOWS1` stream from `stream_fd` (root only).
    pub const COWFS_IOC_RECEIVE: u32 = 0x5457_020a;
    /// Run reachability mark-and-sweep GC preserving pinned snapshots and active mounts (root only).
    pub const COWFS_IOC_GC: u32 = 0x5457_020b;
    /// Query `/dev/vdN` managed volume device metadata.
    pub const BLK_INFO: u32 = 0x5457_0210;
    /// Query `/dev/vdN` writer lease state.
    pub const BLK_LEASE: u32 = 0x5457_0211;
}

/// Linux-numbered ioctl(2) constants for `/dev/loop-control` and `/dev/loopN` devices
/// (contract §2.16, §5, #79).
pub mod loop_ioctl {
    /// Bind a regular readable backing file descriptor to `/dev/loopN` (arg: JSON u32 fd; root only).
    pub const LOOP_SET_FD: u32 = 0x4C00;
    /// Detach `/dev/loopN` (`EBUSY` while mounted; root only).
    pub const LOOP_CLR_FD: u32 = 0x4C01;
    /// Query `/dev/loopN` binding status (`LoopStatus64` JSON; `ENXIO` if unbound).
    pub const LOOP_GET_STATUS64: u32 = 0x4C05;
    /// Query `/dev/loop-control` for the lowest unbound loop device index `0..8` (root only).
    pub const LOOP_CTL_GET_FREE: u32 = 0x4C82;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(boundary: Boundary, versions: &[u32]) -> Hello {
        Hello {
            boundary,
            versions: versions.to_vec(),
        }
    }

    #[test]
    fn negotiation_picks_the_highest_common_version_of_one_boundary() {
        let fs = Boundary::RemoteFilesystem;
        assert_eq!(negotiate(&hello(fs, &[1, 2]), &hello(fs, &[2, 3])), Some(2));
        assert_eq!(negotiate(&hello(fs, &[2]), &hello(fs, &[1])), None);
        assert_eq!(
            negotiate(&hello(fs, &[2]), &hello(Boundary::ServiceAuth, &[2])),
            None
        );
    }

    #[test]
    fn boundaries_keep_their_contract_values() {
        let expected = [
            (Boundary::Syscall, 1, "\"syscall\""),
            (Boundary::HostAdapter, 2, "\"host-adapter\""),
            (Boundary::RemoteFilesystem, 2, "\"remote-filesystem\""),
            (Boundary::LocalHelper, 1, "\"local-helper\""),
            (Boundary::ServiceAuth, 2, "\"service-auth\""),
            (Boundary::DeviceTask, 1, "\"device-task\""),
            (Boundary::Release, 2, "\"release\""),
            (Boundary::Gui, 1, "\"gui\""),
            (Boundary::Volume, 1, "\"volume\""),
            (Boundary::Registry, 1, "\"registry\""),
            (Boundary::ClusterState, 1, "\"cluster-state\""),
            (Boundary::Network, 1, "\"network\""),
        ];
        for (boundary, version, wire) in expected {
            assert_eq!(boundary.version(), version, "{boundary:?}");
            assert_eq!(serde_json::to_string(&boundary).unwrap(), wire);
            assert_eq!(serde_json::from_str::<Boundary>(wire).unwrap(), boundary);
        }
        assert_eq!(COWFS_FORMAT_VERSION, 1);
        assert_eq!(
            serde_json::to_string(&Support::Stale(Errno::ESTALE)).unwrap(),
            "{\"stale\":\"ESTALE\"}"
        );
    }

    #[test]
    fn fs_types_durability_and_capabilities_match_contract_v2() {
        for (name, fstype, magic, user_ok) in [
            ("cloud", FsType::Cloud, fs_magic::OS_CLOUD_MAGIC, false),
            ("cowfs", FsType::Cowfs, fs_magic::OS_COWFS_MAGIC, false),
            ("opfs", FsType::Opfs, fs_magic::FUSE_SUPER_MAGIC, true),
            ("hostfs", FsType::HostFs, fs_magic::FUSE_SUPER_MAGIC, true),
            (
                "helperfs",
                FsType::HelperFs,
                fs_magic::FUSE_SUPER_MAGIC,
                true,
            ),
            ("sharefs", FsType::ShareFs, fs_magic::FUSE_SUPER_MAGIC, true),
            ("image", FsType::Image, fs_magic::SQUASHFS_MAGIC, true),
            ("tmpfs", FsType::TmpFs, fs_magic::TMPFS_MAGIC, false),
            ("proc", FsType::Proc, fs_magic::PROC_SUPER_MAGIC, false),
            (
                "devtmpfs",
                FsType::DevTmpFs,
                fs_magic::DEVTMPFS_MAGIC,
                false,
            ),
            (
                "devpts",
                FsType::DevPts,
                fs_magic::DEVPTS_SUPER_MAGIC,
                false,
            ),
        ] {
            assert_eq!(FsType::parse(name), Ok(fstype));
            assert_eq!(fstype.as_str(), name);
            assert_eq!(fstype.magic(), magic);
            assert_eq!(fstype.is_user_mountable(), user_ok);
        }
        for bad in ["sysfs", "", "ext4", "btrfs", "overlay", "COWFS"] {
            assert_eq!(FsType::parse(bad), Err(Errno::ENODEV), "for {bad}");
        }

        // New Durability and WriterModel variants serialize in kebab-case.
        assert_eq!(
            serde_json::to_string(&Durability::TreeCommit).unwrap(),
            "\"tree-commit\""
        );
        assert_eq!(
            serde_json::to_string(&Durability::FencedCommit).unwrap(),
            "\"fenced-commit\""
        );
        for (model, wire) in [
            (WriterModel::Local, "\"local\""),
            (WriterModel::Fenced, "\"fenced\""),
            (WriterModel::Immutable, "\"immutable\""),
            (WriterModel::MultiWriter, "\"multi-writer\""),
            (WriterModel::Publisher, "\"publisher\""),
        ] {
            assert_eq!(serde_json::to_string(&model).unwrap(), wire);
            assert_eq!(serde_json::from_str::<WriterModel>(wire).unwrap(), model);
        }

        // Legacy v1 FsCapabilities JSON without snapshots/reflink/writer_model deserializes with
        // safe defaults (EOPNOTSUPP / Local).
        let legacy = serde_json::json!({
            "identity": "host-local",
            "open_survives_unlink": "yes",
            "open_survives_rename": "yes",
            "hard_links": "yes",
            "symlinks": "yes",
            "exclusive_create": "yes",
            "atomic_rename": "yes",
            "rename_noreplace": "yes",
            "durability": "host-fsync",
            "locks": "host"
        });
        let parsed: FsCapabilities = serde_json::from_value(legacy).unwrap();
        assert_eq!(parsed.snapshots, Support::Refused(Errno::EOPNOTSUPP));
        assert_eq!(parsed.reflink, Support::Refused(Errno::EOPNOTSUPP));
        assert_eq!(parsed.writer_model, WriterModel::Local);

        // ENOTBLK carries glibc's exact strerror string.
        assert_eq!(Errno::ENOTBLK.text(), "Block device required");
    }

    #[test]
    fn mount_flags_follow_linux() {
        use mount_flags::*;
        // busybox `mount -o bind` adds MS_SILENT; old callers add the magic number.
        assert_eq!(accepted(MS_BIND | MS_SILENT), Ok(MS_BIND));
        // `mount -o remount,sync`, `-o nosymfollow`, and flags Linux ignores.
        assert_eq!(
            accepted(MS_REMOUNT | MS_SYNCHRONOUS | MS_POSIXACL | MS_I_VERSION),
            Ok(MS_REMOUNT | MS_SYNCHRONOUS)
        );
        assert_eq!(accepted(MS_NOSYMFOLLOW), Ok(MS_NOSYMFOLLOW));
        assert_eq!(
            accepted(MS_MGC_VAL | MS_RDONLY | MS_NOATIME),
            Ok(MS_RDONLY | MS_NOATIME)
        );
        // Non-magic upper bits are rejected rather than masked away.
        assert_eq!(accepted(0xDEAD_0000 | MS_RDONLY), Err(Errno::EINVAL));
        for propagation in [MS_SHARED, MS_SLAVE, MS_UNBINDABLE] {
            assert_eq!(accepted(MS_REC | propagation), Err(Errno::EINVAL));
        }
        assert_eq!(accepted(MS_PRIVATE | MS_REC), Ok(MS_PRIVATE | MS_REC));
        assert_eq!(accepted(0), Ok(0));
    }

    #[test]
    fn umount_and_unshare_flags_enforce_contract_subset() {
        {
            use umount_flags::*;
            assert_eq!(SUPPORTED & MNT_EXPIRE, 0);
            assert_ne!(SUPPORTED & MNT_FORCE, 0);
            assert_eq!(accepted(0), Ok(0));
            assert_eq!(
                accepted(MNT_FORCE | MNT_DETACH | UMOUNT_NOFOLLOW),
                Ok(MNT_FORCE | MNT_DETACH | UMOUNT_NOFOLLOW)
            );
            assert_eq!(accepted(MNT_EXPIRE), Err(Errno::EINVAL));
            assert_eq!(accepted(MNT_DETACH | MNT_EXPIRE), Err(Errno::EINVAL));
            assert_eq!(accepted(0x10), Err(Errno::EINVAL));
        }

        {
            use unshare_flags::*;
            assert_eq!(accepted_unshare(0), Ok(0));
            assert_eq!(accepted_unshare(CLONE_NEWNS), Ok(CLONE_NEWNS));
            assert_eq!(
                accepted_unshare(CLONE_FS | CLONE_FILES | CLONE_NEWNS),
                Ok(CLONE_FS | CLONE_FILES | CLONE_NEWNS)
            );
            // CLONE_NEWUSER (0x1000_0000), CLONE_NEWPID (0x2000_0000), etc. -> EINVAL.
            assert_eq!(accepted_unshare(0x1000_0000), Err(Errno::EINVAL));
            assert_eq!(
                accepted_unshare(CLONE_NEWNS | 0x2000_0000),
                Err(Errno::EINVAL)
            );

            assert_eq!(accepted_setns(0), Ok(0));
            assert_eq!(accepted_setns(CLONE_NEWNS), Ok(CLONE_NEWNS));
            assert_eq!(accepted_setns(CLONE_FS), Err(Errno::EINVAL));
            assert_eq!(accepted_setns(CLONE_FILES), Err(Errno::EINVAL));
            assert_eq!(accepted_setns(CLONE_NEWNS | CLONE_FS), Err(Errno::EINVAL));
            assert_eq!(accepted_setns(0x1000_0000), Err(Errno::EINVAL));
        }
    }
}

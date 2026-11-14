//! Versions and capability descriptions from the architecture contract
//! (docs/architecture/contract.md), defined in L0b (#47) for the steps that follow. Nothing uses
//! them yet; each later step adopts what it needs. Errno names that `Errno` lacks today
//! (ENOTCONN, ENOLCK, EDQUOT, EPROTONOSUPPORT) are added by the step that first returns them.

use crate::Errno;
use serde::{Deserialize, Serialize};

/// An interface whose two sides carry and negotiate a version (contract §6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Boundary {
    /// Applications and the kernel: `Call` and the WASI/WASIX imports.
    Syscall,
    /// The portable kernel and its host: the page protocol, Worker spawning, file handles.
    HostAdapter,
    /// Filesystem clients and filesystem services.
    RemoteFilesystem,
    /// The helper driver and `os-local-helper`.
    LocalHelper,
    /// Instances and the identity service: login, credentials, revocation.
    Identity,
    /// Typed devices and remote tasks.
    DeviceTask,
    /// Images and release manifests.
    Release,
    /// GUI clients, the compositor, `/dev/display` and `/dev/input`.
    Gui,
}

impl Boundary {
    /// The version of this boundary that the contract defines.
    pub const fn version(self) -> u32 {
        match self {
            Boundary::Syscall => SYSCALL_VERSION,
            Boundary::HostAdapter => HOST_ADAPTER_VERSION,
            Boundary::RemoteFilesystem => REMOTE_FILESYSTEM_VERSION,
            Boundary::LocalHelper => LOCAL_HELPER_VERSION,
            Boundary::Identity => IDENTITY_VERSION,
            Boundary::DeviceTask => DEVICE_TASK_VERSION,
            Boundary::Release => RELEASE_VERSION,
            Boundary::Gui => GUI_VERSION,
        }
    }
}

pub const SYSCALL_VERSION: u32 = 1;
pub const HOST_ADAPTER_VERSION: u32 = 1;
/// Handle-addressed calls (contract §2.3). The path-addressed calls in use today are version 1.
pub const REMOTE_FILESYSTEM_VERSION: u32 = 2;
/// The helper's `protocol` field, which web/kernel/native-mount.js checks today.
pub const LOCAL_HELPER_VERSION: u32 = 1;
pub const IDENTITY_VERSION: u32 = 1;
/// The device/task boundary as a whole. Each device's own formats, such as the accelerator
/// ioctl (`accelerator::VERSION`), are versioned separately within it.
pub const DEVICE_TASK_VERSION: u32 = 1;
/// The same number as `os_image::PROTOCOL` (crates/image), which this crate does not depend on.
pub const RELEASE_VERSION: u32 = 1;
/// Reserved for #60.
pub const GUI_VERSION: u32 = 1;

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

/// How widely a filesystem's identity holds (contract §2.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityScope {
    /// The same everywhere the filesystem is reached.
    Global,
    /// Exists only within one instance, as tmpfs and procfs.
    Instance,
    /// Stable on one host: the helper's folder UUID.
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

/// When `fsync` may return (contract §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Durability {
    /// The authority's transaction and chunk commit.
    ServiceCommit,
    /// Closing a browser writable stream, or a sync handle's flush.
    WritableClose,
    /// The host's fsync(2).
    HostFsync,
    /// The publisher's acknowledgement.
    PublisherAck,
}

/// Who keeps a filesystem's locks (`flock` and `fcntl` byte ranges), so every client of it sees
/// them (contract §3). A driver that cannot reach its keeper fails with ENOLCK; none fakes a lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LockScope {
    /// The filesystem service (the cloud authority), for every instance.
    Service,
    /// A filesystem that exists only within one instance (tmpfs), so its locks are seen by all
    /// of its clients.
    Instance,
    /// Every tab of the browser profile, through Web Locks and the metadata store.
    Profile,
    /// The host's own locks, held by the helper, seen by every host program.
    Host,
    /// The publisher of a shared mount.
    Publisher,
}

/// What one filesystem driver provides; every gate is read against it (contract §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsCapabilities {
    pub identity: IdentityScope,
    pub open_survives_unlink: Support,
    pub open_survives_rename: Support,
    pub hard_links: Support,
    pub symlinks: Support,
    /// Atomic O_EXCL creation.
    pub exclusive_create: Support,
    /// Rename that replaces its target atomically.
    pub atomic_rename: Support,
    /// RENAME_NOREPLACE.
    pub rename_noreplace: Support,
    pub durability: Durability,
    pub locks: LockScope,
}

/// Identities an instance carries (contract §1). None of them is a credential: a remote
/// service acts only on a credential it issued. Attaching to another instance is reserved.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceIdentity {
    /// Random per boot; an instance has one boot.
    pub instance: String,
    /// The execution host running it.
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
    /// Instance root only (EPERM otherwise): fails the provider's outstanding requests with EIO,
    /// then unmounts as without it.
    pub const MNT_FORCE: u32 = 1;
    pub const MNT_DETACH: u32 = 2;
    /// Rejected with EINVAL.
    pub const MNT_EXPIRE: u32 = 4;
    pub const UMOUNT_NOFOLLOW: u32 = 8;
    pub const SUPPORTED: u32 = MNT_FORCE | MNT_DETACH | UMOUNT_NOFOLLOW;
}

/// unshare(2) and setns(2) flags, with Linux's values (contract §5). CLONE_NEWNS is the only
/// namespace; CLONE_FS and CLONE_FILES unshare process-local state.
pub mod unshare_flags {
    pub const CLONE_FS: u32 = 0x0200;
    pub const CLONE_FILES: u32 = 0x0400;
    pub const CLONE_NEWNS: u32 = 0x0002_0000;
    pub const SUPPORTED: u32 = CLONE_FS | CLONE_FILES | CLONE_NEWNS;
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
            negotiate(&hello(fs, &[1]), &hello(Boundary::Identity, &[1])),
            None
        );
    }

    #[test]
    fn boundaries_keep_their_contract_values() {
        assert_eq!(Boundary::RemoteFilesystem.version(), 2);
        assert_eq!(Boundary::DeviceTask.version(), 1);
        assert_eq!(
            serde_json::to_string(&Boundary::HostAdapter).unwrap(),
            "\"host-adapter\""
        );
        assert_eq!(
            serde_json::to_string(&Support::Stale(Errno::ESTALE)).unwrap(),
            "{\"stale\":\"ESTALE\"}"
        );
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
        for propagation in [MS_SHARED, MS_SLAVE, MS_UNBINDABLE] {
            assert_eq!(accepted(MS_REC | propagation), Err(Errno::EINVAL));
        }
        assert_eq!(accepted(MS_PRIVATE | MS_REC), Ok(MS_PRIVATE | MS_REC));
        assert_eq!(umount_flags::SUPPORTED & umount_flags::MNT_EXPIRE, 0);
        assert_ne!(umount_flags::SUPPORTED & umount_flags::MNT_FORCE, 0);
    }
}

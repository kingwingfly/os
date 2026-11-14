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
    /// Instances and the identity service: login, credentials, revocation.
    Identity,
    /// Typed devices and remote tasks.
    DeviceTask,
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
            Boundary::Identity => IDENTITY_VERSION,
            Boundary::DeviceTask => DEVICE_TASK_VERSION,
            Boundary::Gui => GUI_VERSION,
        }
    }
}

pub const SYSCALL_VERSION: u32 = 1;
pub const HOST_ADAPTER_VERSION: u32 = 1;
/// Handle-addressed calls (contract §2.3). The path-addressed calls in use today are version 1.
pub const REMOTE_FILESYSTEM_VERSION: u32 = 2;
pub const IDENTITY_VERSION: u32 = 1;
pub const DEVICE_TASK_VERSION: u32 = crate::accelerator::VERSION;
/// Reserved for #60.
pub const GUI_VERSION: u32 = 1;

/// The first message on a connection: the boundary, and the versions this side speaks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub boundary: Boundary,
    pub versions: Vec<u32>,
}

/// The version two sides use: the highest both offer for the same boundary. `None` means the
/// connection is refused with EPROTONOSUPPORT and a browser page reloads (contract §2.10).
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
    /// Stable only on one host, as `st_dev`.
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
    /// Provided by the OS's own metadata within one instance; another instance, or a change
    /// made outside the OS, can see the difference.
    Emulated,
    /// Not provided: the call fails with this errno.
    No(Errno),
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
    /// Atomic rename, and RENAME_NOREPLACE.
    pub atomic_rename: Support,
    pub durability: Durability,
    /// Locks are visible within one instance only, for every driver.
    pub instance_local_locks: bool,
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

/// mount(2) flags the contract supports, with Linux's values (contract §5).
pub mod mount_flags {
    pub const MS_RDONLY: u64 = 1;
    pub const MS_NOSUID: u64 = 2;
    pub const MS_NODEV: u64 = 4;
    pub const MS_NOEXEC: u64 = 8;
    pub const MS_REMOUNT: u64 = 32;
    pub const MS_BIND: u64 = 4096;
    pub const MS_MOVE: u64 = 8192;
    pub const MS_REC: u64 = 16384;
    pub const MS_PRIVATE: u64 = 1 << 18;
    /// Rejected with EINVAL: propagation is private only.
    pub const MS_UNBINDABLE: u64 = 1 << 17;
    pub const MS_SLAVE: u64 = 1 << 19;
    pub const MS_SHARED: u64 = 1 << 20;
    /// Every flag the contract accepts.
    pub const SUPPORTED: u64 = MS_RDONLY
        | MS_NOSUID
        | MS_NODEV
        | MS_NOEXEC
        | MS_REMOUNT
        | MS_BIND
        | MS_MOVE
        | MS_REC
        | MS_PRIVATE;
}

/// umount2(2) flags, with Linux's values (contract §5).
pub mod umount_flags {
    /// Rejected with EINVAL.
    pub const MNT_FORCE: u32 = 1;
    pub const MNT_DETACH: u32 = 2;
    /// Rejected with EINVAL.
    pub const MNT_EXPIRE: u32 = 4;
    pub const UMOUNT_NOFOLLOW: u32 = 8;
    pub const SUPPORTED: u32 = MNT_DETACH | UMOUNT_NOFOLLOW;
}

/// The only namespace unshare(2) and setns(2) accept, with Linux's value (contract §5).
pub const CLONE_NEWNS: u32 = 0x0002_0000;

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
    fn boundaries_and_flags_keep_their_contract_values() {
        assert_eq!(Boundary::RemoteFilesystem.version(), 2);
        assert_eq!(Boundary::DeviceTask.version(), crate::accelerator::VERSION);
        assert_eq!(
            serde_json::to_string(&Boundary::HostAdapter).unwrap(),
            "\"host-adapter\""
        );
        assert_eq!(mount_flags::SUPPORTED & mount_flags::MS_SHARED, 0);
        assert_eq!(umount_flags::SUPPORTED & umount_flags::MNT_FORCE, 0);
        assert_eq!(
            serde_json::to_string(&Support::No(Errno::EPERM)).unwrap(),
            "{\"no\":\"EPERM\"}"
        );
    }
}

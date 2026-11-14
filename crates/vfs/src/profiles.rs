//! The capability profiles of the architecture contract §3, one per driver. Gates are read
//! against these: a `Refused` capability fails with its errno, a `Stale` one lets the call
//! succeed and fails later access through a file already open, and nothing fakes success.

use abi::Errno;
use abi::contract::{Durability, FsCapabilities, IdentityScope, LockScope, Support};

/// The cloud tree served by the authority.
pub const CLOUD: FsCapabilities = FsCapabilities {
    identity: IdentityScope::Global,
    open_survives_unlink: Support::Yes,
    open_survives_rename: Support::Yes,
    hard_links: Support::Yes,
    symlinks: Support::Yes,
    exclusive_create: Support::Yes,
    atomic_rename: Support::Yes,
    rename_noreplace: Support::Yes,
    durability: Durability::ServiceCommit,
    locks: LockScope::Service,
};

/// Browser storage (`os-workspace` in OPFS).
pub const OPFS: FsCapabilities = FsCapabilities {
    identity: IdentityScope::ProfileLocal,
    open_survives_unlink: Support::Emulated,
    open_survives_rename: Support::Yes,
    hard_links: Support::Emulated,
    symlinks: Support::Emulated,
    exclusive_create: Support::Emulated,
    atomic_rename: Support::Emulated,
    rename_noreplace: Support::Emulated,
    durability: Durability::WritableClose,
    locks: LockScope::Profile,
};

/// A host folder through a browser directory handle.
pub const DIRECTORY_HANDLE: FsCapabilities = FsCapabilities {
    identity: IdentityScope::ProfileLocal,
    open_survives_unlink: Support::Stale(Errno::ESTALE),
    open_survives_rename: Support::Yes,
    hard_links: Support::Refused(Errno::EPERM),
    symlinks: Support::Refused(Errno::EPERM),
    exclusive_create: Support::Emulated,
    atomic_rename: Support::Declared,
    rename_noreplace: Support::Emulated,
    durability: Durability::WritableClose,
    locks: LockScope::Profile,
};

/// A host folder through the Linux helper.
pub const HELPER: FsCapabilities = FsCapabilities {
    identity: IdentityScope::HostLocal,
    open_survives_unlink: Support::Yes,
    open_survives_rename: Support::Yes,
    hard_links: Support::Yes,
    symlinks: Support::Yes,
    exclusive_create: Support::Yes,
    atomic_rename: Support::Yes,
    rename_noreplace: Support::Yes,
    durability: Durability::HostFsync,
    locks: LockScope::Host,
};

/// A shared mount: the publisher's guarantees, passed through.
pub const EXPORT: FsCapabilities = FsCapabilities {
    identity: IdentityScope::Publisher,
    open_survives_unlink: Support::Publisher,
    open_survives_rename: Support::Publisher,
    hard_links: Support::Publisher,
    symlinks: Support::Publisher,
    exclusive_create: Support::Publisher,
    atomic_rename: Support::Publisher,
    rename_noreplace: Support::Publisher,
    durability: Durability::PublisherAck,
    locks: LockScope::Publisher,
};

/// An instance's in-memory filesystem ([`crate::memfs`]): full semantics, gone with the instance.
pub const MEMORY: FsCapabilities = FsCapabilities {
    identity: IdentityScope::Instance,
    open_survives_unlink: Support::Yes,
    open_survives_rename: Support::Yes,
    hard_links: Support::Yes,
    symlinks: Support::Yes,
    exclusive_create: Support::Yes,
    atomic_rename: Support::Yes,
    rename_noreplace: Support::Yes,
    durability: Durability::ServiceCommit,
    locks: LockScope::Instance,
};

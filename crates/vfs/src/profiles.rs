//! The capability profiles of the architecture contract §3, one per driver. Gates are read
//! against these: a `Refused` capability fails with its errno, a `Stale` one lets the call
//! succeed and fails later access through a file already open, and nothing fakes success.

use abi::Errno;
use abi::contract::{Durability, FsCapabilities, IdentityScope, LockScope, Support, WriterModel};

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
    snapshots: Support::Refused(Errno::EOPNOTSUPP),
    reflink: Support::Yes,
    writer_model: WriterModel::MultiWriter,
    durability: Durability::ServiceCommit,
    locks: LockScope::Service,
};

/// Local browser-profile MIT pure-Rust `os-cowfs` volume (OPFS packs + strict IDB + Web Locks).
pub const COWFS_LOCAL_BROWSER: FsCapabilities = FsCapabilities {
    identity: IdentityScope::ProfileLocal,
    open_survives_unlink: Support::Yes,
    open_survives_rename: Support::Yes,
    hard_links: Support::Yes,
    symlinks: Support::Yes,
    exclusive_create: Support::Yes,
    atomic_rename: Support::Yes,
    rename_noreplace: Support::Yes,
    snapshots: Support::Yes,
    reflink: Support::Yes,
    writer_model: WriterModel::Local,
    durability: Durability::TreeCommit,
    locks: LockScope::Instance,
};

/// Local native-host MIT pure-Rust `os-cowfs` volume (SQLite WAL+FULL + pack files + flock).
pub const COWFS_LOCAL_NATIVE: FsCapabilities = FsCapabilities {
    identity: IdentityScope::HostLocal,
    ..COWFS_LOCAL_BROWSER
};

/// Remote fenced `os-cowfs` volume (R2 packs + Storage DO triple-fenced head; #80).
pub const COWFS_REMOTE: FsCapabilities = FsCapabilities {
    identity: IdentityScope::Global,
    writer_model: WriterModel::Fenced,
    durability: Durability::FencedCommit,
    ..COWFS_LOCAL_BROWSER
};

/// Read-only pinned `os-cowfs` snapshot / RO view (immutable content-addressed root).
pub const COWFS_SNAPSHOT: FsCapabilities = FsCapabilities {
    identity: IdentityScope::Global,
    open_survives_unlink: Support::Refused(Errno::EROFS),
    open_survives_rename: Support::Refused(Errno::EROFS),
    hard_links: Support::Refused(Errno::EROFS),
    symlinks: Support::Refused(Errno::EROFS),
    exclusive_create: Support::Refused(Errno::EROFS),
    atomic_rename: Support::Refused(Errno::EROFS),
    rename_noreplace: Support::Refused(Errno::EROFS),
    snapshots: Support::Refused(Errno::EROFS),
    reflink: Support::Refused(Errno::EROFS),
    writer_model: WriterModel::Immutable,
    durability: Durability::TreeCommit,
    locks: LockScope::Instance,
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
    snapshots: Support::Refused(Errno::EOPNOTSUPP),
    reflink: Support::Refused(Errno::EOPNOTSUPP),
    writer_model: WriterModel::MultiWriter,
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
    snapshots: Support::Refused(Errno::EOPNOTSUPP),
    reflink: Support::Refused(Errno::EOPNOTSUPP),
    writer_model: WriterModel::MultiWriter,
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
    snapshots: Support::Refused(Errno::EOPNOTSUPP),
    reflink: Support::Refused(Errno::EOPNOTSUPP),
    writer_model: WriterModel::MultiWriter,
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
    snapshots: Support::Publisher,
    reflink: Support::Publisher,
    writer_model: WriterModel::Publisher,
    durability: Durability::PublisherAck,
    locks: LockScope::Publisher,
};

/// An instance's in-memory filesystem ([`crate::memfs`]): full semantics, and nothing durable,
/// since it goes with the instance.
pub const MEMORY: FsCapabilities = FsCapabilities {
    identity: IdentityScope::Instance,
    open_survives_unlink: Support::Yes,
    open_survives_rename: Support::Yes,
    hard_links: Support::Yes,
    symlinks: Support::Yes,
    exclusive_create: Support::Yes,
    atomic_rename: Support::Yes,
    rename_noreplace: Support::Yes,
    snapshots: Support::Refused(Errno::EOPNOTSUPP),
    reflink: Support::Refused(Errno::EOPNOTSUPP),
    writer_model: WriterModel::Local,
    durability: Durability::Volatile,
    locks: LockScope::Instance,
};

/// Signed release image (`image` fstype, global digest identity): read-only, content-addressed.
pub const IMAGE_GLOBAL: FsCapabilities = FsCapabilities {
    identity: IdentityScope::Global,
    open_survives_unlink: Support::Refused(Errno::EROFS),
    open_survives_rename: Support::Refused(Errno::EROFS),
    hard_links: Support::Refused(Errno::EROFS),
    symlinks: Support::Refused(Errno::EROFS),
    exclusive_create: Support::Refused(Errno::EROFS),
    atomic_rename: Support::Refused(Errno::EROFS),
    rename_noreplace: Support::Refused(Errno::EROFS),
    snapshots: Support::Refused(Errno::EROFS),
    reflink: Support::Refused(Errno::EROFS),
    writer_model: WriterModel::Immutable,
    durability: Durability::ServiceCommit,
    locks: LockScope::Instance,
};

/// Unsigned/private extension image (`image` fstype, instance-local identity): read-only.
pub const IMAGE_PRIVATE: FsCapabilities = FsCapabilities {
    identity: IdentityScope::Instance,
    ..IMAGE_GLOBAL
};

/// Instance `/proc` virtual filesystem (`proc` fstype).
pub const PROC: FsCapabilities = FsCapabilities {
    identity: IdentityScope::Instance,
    open_survives_unlink: Support::Refused(Errno::EPERM),
    open_survives_rename: Support::Refused(Errno::EPERM),
    hard_links: Support::Refused(Errno::EPERM),
    symlinks: Support::Refused(Errno::EPERM),
    exclusive_create: Support::Refused(Errno::EPERM),
    atomic_rename: Support::Refused(Errno::EPERM),
    rename_noreplace: Support::Refused(Errno::EPERM),
    snapshots: Support::Refused(Errno::EPERM),
    reflink: Support::Refused(Errno::EPERM),
    writer_model: WriterModel::Local,
    durability: Durability::Volatile,
    locks: LockScope::Instance,
};

/// Instance `/dev` filesystem (`devtmpfs` fstype).
pub const DEVTMPFS: FsCapabilities = MEMORY;

/// Instance `/dev/pts` slave PTY filesystem (`devpts` fstype).
pub const DEVPTS: FsCapabilities = FsCapabilities {
    identity: IdentityScope::Instance,
    open_survives_unlink: Support::Refused(Errno::EPERM),
    open_survives_rename: Support::Refused(Errno::EPERM),
    hard_links: Support::Refused(Errno::EPERM),
    symlinks: Support::Refused(Errno::EPERM),
    exclusive_create: Support::Refused(Errno::EPERM),
    atomic_rename: Support::Refused(Errno::EPERM),
    rename_noreplace: Support::Refused(Errno::EPERM),
    snapshots: Support::Refused(Errno::EPERM),
    reflink: Support::Refused(Errno::EPERM),
    writer_model: WriterModel::Local,
    durability: Durability::Volatile,
    locks: LockScope::Instance,
};

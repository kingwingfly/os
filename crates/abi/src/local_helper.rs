//! The local helper protocol (contract §6): versioned boundary handshake plus handle-addressed
//! filesystem calls between `os_vfs::helperfs::HelperFs` and `os-local-helper`.

use crate::Bytes;
use crate::contract::{Boundary, FsCapabilities, Hello, LOCAL_HELPER_VERSION};
use crate::fs::{
    FsId, Handle, LockFamily, LockKind, LockRange, OpenOptions, OpenRef, RenameFlags, SetAttr,
    WriteAt, XattrFlags,
};
use serde::{Deserialize, Serialize};

/// Current local-helper wire protocol version (`contract::LOCAL_HELPER_VERSION`).
pub const VERSION: u32 = LOCAL_HELPER_VERSION;

/// Maximum serialized control envelope size accepted by the local helper.
pub const CONTROL_MAX: usize = 4 * 1024 * 1024;

/// Maximum raw byte payload per `ReadAt` or `WriteAt` chunk.
pub const DATA_MAX: u64 = 1024 * 1024;

/// Session inactivity lease before the helper tears down held descriptors and locks.
pub const LEASE_SECONDS: u64 = 60;

/// How often an attached helper driver renews its session lease.
pub const RENEW_MILLIS: u32 = 20_000;

/// Poll interval while waiting for a queued blocking host lock ticket.
pub const LOCK_POLL_MILLIS: u32 = 25;

/// Calling OS credentials forwarded with helper calls.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireCred {
    pub id: u32,
    pub group: u32,
    pub groups: Vec<u32>,
    pub umask: u16,
}

/// Host-enforced grant ceiling for a helper or attachment session.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperGrant {
    pub write: bool,
    pub execute: bool,
}

/// Reply to [`Request::Hello`] after negotiating [`Boundary::LocalHelper`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloReply {
    pub boundary: Boundary,
    pub version: u32,
    pub write: bool,
    pub execute: bool,
    pub handshake: String,
}

/// Reply to [`Request::Attach`] returning the persistent filesystem identity and root handle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachReply {
    pub version: u32,
    pub session: String,
    pub fs: FsId,
    pub root: Handle,
    pub capabilities: FsCapabilities,
    pub grant: HelperGrant,
    pub lease_seconds: u64,
}

/// Reply to [`Request::Renew`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewReply {
    pub lease_seconds: u64,
}

/// Reply to [`Call::ReadAt`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadReply {
    pub data: Bytes,
}

/// Outcome of a blocking or non-blocking lock request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockOutcome {
    Acquired,
    Pending,
}

/// Handle-addressed calls sent inside [`Request::Call`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Call {
    Lookup {
        dir: Handle,
        name: String,
    },
    Walk {
        dir: Handle,
        names: Vec<String>,
    },
    Parent {
        dir: Handle,
    },
    Metadata {
        handle: Handle,
    },
    OpenMetadata {
        open: OpenRef,
    },
    Setattr {
        handle: Handle,
        attr: SetAttr,
    },
    ReadDir {
        dir: Handle,
    },
    ReadLink {
        link: Handle,
    },
    Create {
        ticket: String,
        dir: Handle,
        name: String,
        mode: u16,
        options: OpenOptions,
    },
    Mkdir {
        dir: Handle,
        name: String,
        mode: u16,
    },
    Mknod {
        dir: Handle,
        name: String,
        mode: u16,
        rdev: String,
    },
    Symlink {
        dir: Handle,
        name: String,
        target: String,
    },
    Link {
        target: Handle,
        dir: Handle,
        name: String,
    },
    Unlink {
        dir: Handle,
        name: String,
    },
    Rmdir {
        dir: Handle,
        name: String,
    },
    Rename {
        from_dir: Handle,
        from: String,
        to_dir: Handle,
        to: String,
        flags: RenameFlags,
    },
    Getxattr {
        handle: Handle,
        name: String,
    },
    Setxattr {
        handle: Handle,
        name: String,
        value: Bytes,
        flags: XattrFlags,
    },
    Listxattr {
        handle: Handle,
    },
    Removexattr {
        handle: Handle,
        name: String,
    },
    Statfs,
    Open {
        ticket: String,
        handle: Handle,
        options: OpenOptions,
    },
    CancelOpen {
        ticket: String,
    },
    ReadAt {
        open: OpenRef,
        offset: u64,
        count: u64,
    },
    WriteAt {
        open: OpenRef,
        data: Bytes,
        at: WriteAt,
    },
    SetLen {
        open: OpenRef,
        size: u64,
    },
    Sync {
        open: OpenRef,
        data_only: bool,
    },
    Lock {
        open: OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
        ticket: String,
    },
    TryLock {
        open: OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    },
    Unlock {
        open: OpenRef,
        family: LockFamily,
        range: LockRange,
    },
    TestLock {
        open: OpenRef,
        kind: LockKind,
        range: LockRange,
    },
    CancelLock {
        open: OpenRef,
        ticket: String,
    },
    Release {
        open: OpenRef,
    },
}

/// Top-level request envelope sent to the local helper HTTP endpoint.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Request {
    Hello(Hello),
    Attach {
        version: u32,
        handshake: String,
        client_id: String,
        cred: WireCred,
        grant: HelperGrant,
    },
    Renew {
        version: u32,
        session: String,
    },
    Detach {
        version: u32,
        session: String,
    },
    Call {
        version: u32,
        session: String,
        cred: WireCred,
        call: Call,
    },
}

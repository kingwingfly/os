//! Remote filesystem v2. Authentication belongs to the service; no uid, PID or pathname
//! supplied by a client is authority. Data travels in a separate streaming request.
use crate::{Errno, contract::FsCapabilities, fs::*};
use serde::{Deserialize, Serialize};

pub const VERSION: u32 = crate::contract::REMOTE_FILESYSTEM_VERSION;
pub const LEASE_SECONDS: u64 = 120;
pub const DATA_MAX: u64 = 8 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub id: String,
    pub secret: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Connected {
    pub version: u32,
    pub session: Session,
    pub root: Handle,
    pub capabilities: FsCapabilities,
    pub lease_seconds: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u32,
    pub credential: String,
    pub session: Option<Session>,
    pub call: Call,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Call {
    Connect,
    Renew,
    Disconnect,
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
    Setattr {
        handle: Handle,
        attr: SetAttr,
    },
    ReadDir {
        dir: Handle,
    },
    ReadLink {
        handle: Handle,
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
        value: Vec<u8>,
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
    SetLen {
        open: OpenRef,
        size: u64,
    },
    Sync {
        open: OpenRef,
        data_only: bool,
    },
    Release {
        open: OpenRef,
    },
    TryLock {
        open: OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    },
    /// A durable queued wait. A retry with the same ticket observes its grant; it never
    /// enqueues twice. Cancel also undoes a grant not yet acknowledged by the client.
    Lock {
        open: OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
        ticket: String,
    },
    /// Receipt of a granted lock; retires its queued-wait record.
    AckLock {
        open: OpenRef,
        ticket: String,
    },
    CancelLock {
        open: OpenRef,
        ticket: String,
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
}

/// The JSON header of a data request. The body is raw bytes, never JSON/base64. A write
/// commits only after R2 receives the entire body; append resolves its offset at commit.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataRequest {
    pub version: u32,
    pub credential: String,
    /// The current caller, validated against this credential's issuer namespace. A fork
    /// shares a credential, not a PID or I/O budget. Only job credentials may omit it.
    pub pid: Option<u32>,
    pub session: Session,
    pub open: OpenRef,
    pub operation: DataOperation,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum DataOperation {
    Read { offset: u64, length: u64 },
    Write { at: WriteAt, length: u64 },
}
pub type Response<T> = Result<T, Errno>;

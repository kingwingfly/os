//! Userspace export service control and osfs v2. The only identity on a data
//! connection is the one established when the kernel admitted its socket.
use crate::{Bytes, Errno, fs::*};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub const EXPORT_CONTROL_VERSION: u32 = 1;
pub const OSFS_VERSION: u32 = 2;
pub const SYSTEM_EXPORT_SOCK: &str = "/run/export/control.sock";
pub const EXPORT_TRANSPORT_SOCK: &str = "/run/export/transport.sock";
pub const OSFS_MAX_FRAME_BYTES: usize = 384 * 1024;
pub const OSFS_MAX_INFLIGHT: usize = 4;
pub const OSFS_MAX_HANDLES: usize = 128;
pub const OSFS_CHUNK: usize = 24 * 1024;
pub const CONTROL_MAX: usize = 64 * 1024;
/// Private ioctl on the received directory description. It takes an
/// ExportDirCall, authenticated against the calling process's unit grant.
pub const EXPORT_DIR_IOCTL: u32 = 0x4558_0001;

pub fn user_export_sock(uid: u32) -> String {
    format!("/run/user/{uid}/export.sock")
}
pub fn export_ipc_sock(id: &str) -> String {
    format!("/run/export/share/{id}.sock")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum TransportKind {
    Ipc,
    P2p,
    Relay,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportRule {
    pub writable: bool,
    pub execute: bool,
}

impl ExportRule {
    pub fn intersect(self, other: Self) -> Self {
        Self {
            writable: self.writable && other.writable,
            execute: self.execute && other.execute,
        }
    }
    pub fn mask(self, meta: &mut Metadata) {
        if !self.writable {
            meta.mode &= !0o222;
        }
        if !self.execute && meta.is_file() {
            meta.mode &= !0o111;
        }
    }
}

/// Stop serialization at the bound, including for very large directory lists.
fn bounded_json<T: Serialize>(value: &T, prefix: usize, limit: usize) -> Result<Vec<u8>, Errno> {
    struct Buffer {
        data: Vec<u8>,
        limit: usize,
    }
    impl std::io::Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.limit - self.data.len() {
                return Err(std::io::ErrorKind::FileTooLarge.into());
            }
            self.data.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut out = Buffer {
        data: vec![0; prefix],
        limit: limit + prefix,
    };
    serde_json::to_writer(&mut out, value).map_err(|e| {
        if e.io_error_kind() == Some(std::io::ErrorKind::FileTooLarge) {
            Errno::E2BIG
        } else {
            Errno::EIO
        }
    })?;
    Ok(out.data)
}
pub fn encode_control<T: Serialize>(value: &T) -> Result<Vec<u8>, Errno> {
    let mut data = bounded_json(value, 0, CONTROL_MAX - 1)?;
    data.push(b'\n');
    Ok(data)
}
pub fn decode_control<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Errno> {
    if bytes.len() > CONTROL_MAX {
        return Err(Errno::E2BIG);
    }
    let line = bytes.strip_suffix(b"\n").ok_or(Errno::EINVAL)?;
    if line.contains(&b'\n') {
        return Err(Errno::EINVAL);
    }
    serde_json::from_slice(line).map_err(|_| Errno::EINVAL)
}
pub fn default_lease_secs() -> u64 {
    300
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExportRequest {
    Publish {
        name: String,
        source_path: String,
        #[serde(default)]
        writable: bool,
        #[serde(default)]
        execute: bool,
        #[serde(default = "default_lease_secs")]
        seconds: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
        #[serde(default)]
        transports: Vec<TransportKind>,
    },
    List {},
    Revoke {
        id: String,
    },
    Status {
        id: String,
    },
    ListClients {
        id: String,
    },
    Transports {},
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportEntry {
    pub id: String,
    pub name: String,
    pub source_path: String,
    pub owner_uid: u32,
    pub rule: ExportRule,
    pub password: bool,
    pub transports: Vec<TransportKind>,
    /// Unix time, in milliseconds.
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerIdentity {
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
}

/// Opaque bearer handle. The kernel retains the binding and consumes a
/// transport admission once. A UID or a directory descriptor is not a token.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerIdentityCap {
    pub token: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportSessionHeader {
    pub version: u32,
    pub export_id: String,
    pub manager_uid: Option<u32>,
    pub transport: TransportKind,
    pub cap: PeerIdentityCap,
    pub expires_at: u64,
    pub rule: ExportRule,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSessionView {
    pub id: u64,
    pub peer_uid: u32,
    pub transport: TransportKind,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportTransportView {
    pub id: String,
    pub clients: Vec<ClientSessionView>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExportResponse {
    Published { export: ExportEntry },
    Exports { exports: Vec<ExportEntry> },
    Entry { export: ExportEntry },
    Clients { clients: Vec<ClientSessionView> },
    Transports { exports: Vec<ExportTransportView> },
    Revoked {},
    Accepted {},
    Error { errno: Errno },
}

/// Names are single components relative to a verified directory handle. A
/// wire Handle's proof is its path *beneath* this session's root. A receiver
/// must verify fs and inode/generation after walking it without following links.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum AtOp {
    Lookup {
        name: String,
    },
    Walk {
        names: Vec<String>,
    },
    Parent {},
    Metadata {},
    Access {
        mask: u16,
    },
    ReadDir {},
    ReadLink {},
    Statfs {},
    Open {
        options: OpenOptions,
    },
    Create {
        name: String,
        mode: u16,
        umask: u16,
        options: OpenOptions,
    },
    Mkdir {
        name: String,
        mode: u16,
        umask: u16,
    },
    Mknod {
        name: String,
        mode: u16,
        umask: u16,
        rdev: String,
    },
    Symlink {
        name: String,
        target: String,
    },
    Link {
        name: String,
        target: Handle,
    },
    #[serde(alias = "remove")]
    Unlink {
        name: String,
    },
    Rmdir {
        name: String,
    },
    #[serde(alias = "removeIf", alias = "remove_if")]
    UnlinkIf {
        name: String,
        node: NodeId,
    },
    Rename {
        name: String,
        to_dir: Handle,
        to: String,
        flags: RenameFlags,
    },
    Setattr {
        attr: SetAttr,
    },
    Getxattr {
        name: String,
    },
    Listxattr {},
    Setxattr {
        name: String,
        value: Bytes,
        flags: XattrFlags,
    },
    Removexattr {
        name: String,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum FdOp {
    Fstat {},
    ReadDir {},
    Read {
        offset: u64,
        count: usize,
    },
    Write {
        at: WriteAt,
        data: Bytes,
    },
    Ftruncate {
        size: u64,
    },
    Sync {
        data_only: bool,
    },
    Release {},
    Lock {
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
        wait: bool,
    },
    Unlock {
        family: LockFamily,
        range: LockRange,
    },
    TestLock {
        kind: LockKind,
        range: LockRange,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum OsfsRequest {
    Root {},
    At { base: Handle, call: AtOp },
    Fd { handle: u64, call: FdOp },
    Cancel { target_id: u64 },
}
impl OsfsRequest {
    pub fn is_mutation(&self) -> bool {
        match self {
            Self::At { call, .. } => match call {
                AtOp::Open { options } | AtOp::Create { options, .. } => {
                    options.access() != Ok(Access::Path)
                        && (options.is_create() || options.is_truncate())
                }
                AtOp::Mkdir { .. }
                | AtOp::Mknod { .. }
                | AtOp::Symlink { .. }
                | AtOp::Link { .. }
                | AtOp::Unlink { .. }
                | AtOp::Rmdir { .. }
                | AtOp::UnlinkIf { .. }
                | AtOp::Rename { .. }
                | AtOp::Setattr { .. }
                | AtOp::Setxattr { .. }
                | AtOp::Removexattr { .. } => true,
                _ => false,
            },
            Self::Fd { call, .. } => matches!(call, FdOp::Write { .. } | FdOp::Ftruncate { .. }),
            _ => false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum OsfsResponse {
    Unit,
    Root { entry: Entry, rule: ExportRule },
    Entry(Entry),
    Parent(Option<(Entry, String)>),
    Walked(Walked),
    Metadata(Metadata),
    Directory(Vec<DirEntry>),
    Link(String),
    Bytes(Bytes),
    Names(Vec<String>),
    Statfs(StatFs),
    Opened { entry: Entry, open: OpenRef },
    Written(Written),
    Lock(Option<Conflict>),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum OsfsFrame {
    Request {
        request_id: u64,
        request: OsfsRequest,
    },
    Reply {
        request_id: u64,
        result: Result<OsfsResponse, Errno>,
    },
    Closed {
        errno: Errno,
    },
}

pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, Errno> {
    let mut frame = bounded_json(value, 4, OSFS_MAX_FRAME_BYTES)?;
    let len = frame.len() - 4;
    frame[..4].copy_from_slice(&(len as u32).to_be_bytes());
    Ok(frame)
}
/// Returns the complete frame length including the prefix, as soon as the
/// prefix is available. Check it before reserving or reading payload bytes.
pub fn frame_length(bytes: &[u8]) -> Result<Option<usize>, Errno> {
    let Some(prefix) = bytes.first_chunk::<4>() else {
        return Ok(None);
    };
    let n = u32::from_be_bytes(*prefix) as usize;
    if n == 0 {
        return Err(Errno::EIO);
    }
    if n > OSFS_MAX_FRAME_BYTES {
        return Err(Errno::E2BIG);
    }
    Ok(Some(n + 4))
}
pub fn decode_frame<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Errno> {
    if frame_length(bytes)? != Some(bytes.len()) {
        return Err(Errno::EIO);
    }
    serde_json::from_slice(&bytes[4..]).map_err(|_| Errno::EIO)
}

/// Incremental decoder for a byte stream. The prefix is validated before
/// allocating the payload, and coalesced frames are delivered individually.
#[derive(Default)]
pub struct FrameReader {
    bytes: Vec<u8>,
}
impl FrameReader {
    pub fn feed<T: DeserializeOwned>(
        &mut self,
        mut input: &[u8],
        mut emit: impl FnMut(T) -> Result<(), Errno>,
    ) -> Result<(), Errno> {
        while !input.is_empty() {
            let needed = frame_length(&self.bytes)?.unwrap_or(4) - self.bytes.len();
            let n = needed.min(input.len());
            self.bytes.extend_from_slice(&input[..n]);
            input = &input[n..];
            if frame_length(&self.bytes)? == Some(self.bytes.len()) {
                let msg = decode_frame(&self.bytes)?;
                self.bytes.clear();
                emit(msg)?;
            }
        }
        Ok(())
    }
}

pub fn component(s: &str) -> Result<(), Errno> {
    if s.contains(['/', '\\', '\0']) || s == ".." {
        return Err(Errno::EACCES);
    }
    check_component(s)
}
pub fn relative_path(path: &str) -> Result<(), Errno> {
    if path.len() >= crate::PATH_MAX {
        return Err(Errno::ENAMETOOLONG);
    }
    if path.starts_with('/') {
        return Err(Errno::EACCES);
    }
    if !path.is_empty() {
        for name in path.split('/') {
            component(name)?;
        }
    }
    Ok(())
}

/// Directory-fd operations used by the daemon. These never carry ambient
/// paths, user-supplied credentials, osfs frames, or protocol request IDs.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExportDirCall {
    TrackListener {
        name: String,
        dev: u64,
        ino: u64,
    },
    UnlinkListener {
        dev: u64,
        ino: u64,
    },
    Inspect {},
    Publish {
        id: String,
        name: String,
        publisher_pid: u32,
        manager_uid: Option<u32>,
        expires_at: u64,
        rule: ExportRule,
        password: Option<String>,
        transports: Vec<TransportKind>,
    },
    AdmitLocal {
        id: String,
        socket_fd: u32,
    },
    AdmitRemote {
        header: TransportSessionHeader,
    },
    At {
        cap: PeerIdentityCap,
        base: Handle,
        call: AtOp,
    },
    OnOpen {
        cap: PeerIdentityCap,
        open: OpenRef,
        call: FdOp,
    },
    End {
        cap: PeerIdentityCap,
    },
    Revoke {
        id: String,
        reason: Errno,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootInfo {
    pub root: Entry,
    pub publisher_uid: u32,
    pub stable_ino: bool,
    pub ceiling: ExportRule,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Admission {
    pub cap: PeerIdentityCap,
    pub peer_uid: u32,
    pub rule: ExportRule,
    pub expires_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn framing_and_strict_control() {
        let req: ExportRequest =
            serde_json::from_str(r#"{"op":"publish","name":"a","source_path":"/a"}"#).unwrap();
        assert_eq!(
            decode_frame::<ExportRequest>(&encode_frame(&req).unwrap()).unwrap(),
            req
        );
        for bad in [
            r#"{"op":"list","uid":0}"#,
            r#"{"op":"publish","name":"a","source_path":"/a","root_dirfd":9}"#,
        ] {
            assert!(serde_json::from_str::<ExportRequest>(bad).is_err());
        }
        assert!(
            serde_json::from_str::<OsfsFrame>(
                r#"{"type":"request","request_id":1,"request":{"op":"root","cred":{}}}"#
            )
            .is_err()
        );
        assert_eq!(frame_length(&[0xff; 4]), Err(Errno::E2BIG));
        let frame = OsfsFrame::Request {
            request_id: u64::MAX,
            request: OsfsRequest::Root {},
        };
        let mut bytes = encode_frame(&frame).unwrap();
        assert_eq!(decode_frame::<OsfsFrame>(&bytes), Ok(frame));
        bytes.push(0);
        assert_eq!(decode_frame::<OsfsFrame>(&bytes), Err(Errno::EIO));
    }
}

#[cfg(test)]
mod classification_tests {
    use super::*;
    #[test]
    fn open_and_create_flags_only_unconfirmed_changes_are_uncertain() {
        let base = Handle {
            fs: FsId("fs".into()),
            node: NodeId {
                ino: 1,
                generation: 2,
            },
            proof: String::new(),
        };
        for flags in [
            0,
            crate::O_WRONLY,
            crate::O_CREAT,
            crate::O_TRUNC,
            crate::O_PATH | crate::O_CREAT | crate::O_TRUNC,
        ] {
            let options = OpenOptions::from_flags(flags).unwrap();
            for call in [
                AtOp::Open { options },
                AtOp::Create {
                    name: "x".into(),
                    mode: 0o600,
                    umask: 0o077,
                    options,
                },
            ] {
                assert_eq!(
                    (OsfsRequest::At {
                        base: base.clone(),
                        call
                    })
                    .is_mutation(),
                    flags & crate::O_PATH == 0 && flags & (crate::O_CREAT | crate::O_TRUNC) != 0
                );
            }
        }
        let ops = [
            (serde_json::json!({"op":"remove","name":"f"}), true),
            (
                serde_json::json!({"op":"removeIf","name":"f","node":base.node}),
                true,
            ),
            (
                serde_json::json!({"op":"setxattr","name":"user.x","value":"","flags":""}),
                true,
            ),
            (
                serde_json::json!({"op":"removexattr","name":"user.x"}),
                true,
            ),
            (serde_json::json!({"op":"listxattr"}), false),
            (serde_json::json!({"op":"getxattr","name":"user.x"}), false),
            (serde_json::json!({"op":"read_dir"}), false),
            (serde_json::json!({"op":"read_link"}), false),
            (serde_json::json!({"op":"statfs"}), false),
            (serde_json::json!({"op":"access","mask":2}), false),
        ];
        for (json, mutation) in ops {
            let call = serde_json::from_value(json).unwrap();
            assert_eq!(
                OsfsRequest::At {
                    base: base.clone(),
                    call
                }
                .is_mutation(),
                mutation
            );
        }
    }
}

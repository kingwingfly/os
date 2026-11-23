//! Local mount service control protocol, version 1. All IDs are names, never credentials.
use crate::{Errno, Error};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::io::{self, Write};

// Serde's default internally tagged unit visitor discards extra keys.
fn empty_variant<'de, D: serde::Deserializer<'de>>(d: D) -> Result<(), D::Error> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Empty {}
    Empty::deserialize(d).map(|_| ())
}

pub const MOUNT_CONTROL_VERSION: u32 = 1;
pub const SYSTEM_MOUNT_SOCK: &str = "/run/mount/control.sock";
pub fn user_mount_sock(uid: u32) -> String {
    format!("/run/user/{uid}/mount.sock")
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceKind {
    Hostfs,
    SelectedFiles,
    Opfs,
    Helperfs,
    Sharefs,
    CowfsVolume,
    CowfsSnapshot,
    LoopDevice,
    Cloud,
    Image,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceState {
    Granted,
    NeedsRenewal,
    Revoked,
    Offline,
    Unavailable,
}

/// Object 1: Source (backing grant/device — NEVER contains raw handles or secrets).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceInfo {
    pub id: String, // opaque "src:<uuid>" | "volume:<id>" | "loop0" | "opfs:root" | "cloud:default"
    pub kind: SourceKind,
    pub label: String,
    pub location: String, // human-readable origin/helper path/device/address
    pub state: SourceState,
    pub writable: bool,
    pub execute: bool,
    pub saved: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_uid: Option<u32>,
}

/// Object 2: Filesystem (formatted volume/driver identity & capacity).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemInfo {
    pub fs_id: u64,
    pub fstype: String,
    pub source: String,
    pub label: String,
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub bsize: u32,
    pub files: u64,
    pub ffree: u64,
    pub capabilities: crate::contract::FsCapabilities,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cowfs: Option<CowfsFsSummary>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CowfsFsSummary {
    pub volume: String,
    pub root: String,
    pub epoch: u64,
    pub writer_model: crate::contract::WriterModel,
    pub durability: crate::contract::Durability,
    pub subvols: Vec<String>,
    pub snapshots: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BusyProcess {
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub reasons: Vec<String>, // subset of ["cwd", "root", "fd"]
}

/// Object 3: Attachment (mounted VFS node in a mount namespace).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentInfo {
    pub mount_id: u64,
    pub parent_id: u64,
    pub ns_id: u64,
    pub fs_id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    pub target: String,
    pub fstype: String,
    pub source_label: String,
    pub options: Vec<String>,
    pub read_only: bool,
    pub nosuid: bool,
    pub nodev: bool,
    pub noexec: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_uid: Option<u32>,
    pub user_mount: bool,
    pub health: String, // "connected" | "revoked" | "lost"
    pub uncertain_writes: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub busy_pids: Vec<BusyProcess>,
}

/// Object 4: Export summary (read-only view synchronized from #59 exportd).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportSummary {
    pub id: String,
    pub address: String,
    pub name: String,
    pub source_path: String,
    pub owner_uid: u32,
    pub writable: bool,
    pub execute: bool,
    pub password_protected: bool,
    pub expires_at: u64,
    pub active_clients: u32,
    pub transports: Vec<String>, // ["ipc", "p2p", "relay"]
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum MountRequest {
    #[serde(deserialize_with = "empty_variant")]
    ListSources,
    #[serde(deserialize_with = "empty_variant")]
    ListFilesystems,
    ListAttachments {
        #[serde(default)]
        include_busy: bool,
    },
    ListAll {
        #[serde(default)]
        include_busy: bool,
    },
    BusyProcesses {
        target: String,
    },
    Attach {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_id: Option<String>,
        source: String,
        target: String,
        fstype: String,
        #[serde(default)]
        flags: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        options: Option<String>,
        /// Target mount namespace pid (defaults to peer cred.pid).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target_pid: Option<u32>,
    },
    Detach {
        target: String,
        #[serde(default)]
        lazy: bool,
        #[serde(default)]
        force: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target_pid: Option<u32>,
    },
    Remount {
        target: String,
        flags: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        options: Option<String>,
    },
    ActivatePrivate {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        additional_sources: Vec<String>,
        source_id: String,
        name: String,
        #[serde(default)]
        execute: bool,
    },
    ForgetSource {
        source_id: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MountErrorKind {
    #[serde(deserialize_with = "empty_variant")]
    Denied,
    #[serde(deserialize_with = "empty_variant")]
    Cancelled,
    Busy {
        processes: Vec<BusyProcess>,
    },
    #[serde(deserialize_with = "empty_variant")]
    Offline,
    #[serde(deserialize_with = "empty_variant")]
    Revoked,
    #[serde(deserialize_with = "empty_variant")]
    Unsupported,
    HostGrantRequired {
        hint: String,
    },
    NeedsRenewal {
        source_id: String,
        hint: String,
    },
    #[serde(deserialize_with = "empty_variant")]
    NotFound,
    #[serde(deserialize_with = "empty_variant")]
    InvalidArgument,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum MountResponse {
    Ok {},
    Sources {
        sources: Vec<SourceInfo>,
    },
    Filesystems {
        filesystems: Vec<FilesystemInfo>,
    },
    Attachments {
        attachments: Vec<AttachmentInfo>,
    },
    All {
        sources: Vec<SourceInfo>,
        filesystems: Vec<FilesystemInfo>,
        attachments: Vec<AttachmentInfo>,
        exports: Vec<ExportSummary>,
    },
    Busy {
        processes: Vec<BusyProcess>,
    },
    Error {
        errno: Errno,
        error: MountErrorKind,
        message: String,
    },
}

pub const MAX_FRAME_BYTES: usize = 65_536;

/// Limit allocation while serializing, including when a namespace contains many mounts.
pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    struct Frame(Vec<u8>);
    impl Write for Frame {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if buf.len() >= MAX_FRAME_BYTES - self.0.len() {
                return Err(io::ErrorKind::FileTooLarge.into());
            }
            self.0.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut frame = Frame(Vec::new());
    serde_json::to_writer(&mut frame, value).map_err(|e| {
        Error::because(
            if e.io_error_kind() == Some(io::ErrorKind::FileTooLarge) {
                Errno::E2BIG
            } else {
                Errno::EINVAL
            },
            e.to_string(),
        )
    })?;
    frame.0.push(b'\n');
    Ok(frame.0)
}

pub fn decode_frame<T: DeserializeOwned>(frame: &[u8]) -> Result<T, Error> {
    if frame.len() > MAX_FRAME_BYTES {
        return Err(Errno::E2BIG.into());
    }
    let body = frame
        .strip_suffix(b"\n")
        .ok_or_else(|| Error::because(Errno::EINVAL, "incomplete mount control frame"))?;
    if body.contains(&b'\n') {
        return Err(Errno::EINVAL.into());
    }
    serde_json::from_slice(body).map_err(|e| Error::because(Errno::EINVAL, e.to_string()))
}

/// Read exactly one bounded line. Callers serve a single request per connection.
pub fn read_frame(
    mut recv: impl FnMut(&mut [u8]) -> Result<usize, Errno>,
) -> Result<Vec<u8>, Error> {
    let mut frame = Vec::new();
    let mut buf = [0; 4096];
    loop {
        let cap = buf.len().min(MAX_FRAME_BYTES - frame.len());
        if cap == 0 {
            return Err(Errno::E2BIG.into());
        }
        match recv(&mut buf[..cap]) {
            Ok(0) => {
                return Err(Error::because(
                    Errno::ECONNRESET,
                    "peer closed before newline",
                ));
            }
            Ok(n) => {
                frame.extend_from_slice(&buf[..n]);
                if buf[..n].contains(&b'\n') {
                    return Ok(frame);
                }
            }
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

pub fn write_frame(
    frame: &[u8],
    mut send: impl FnMut(&[u8]) -> Result<usize, Errno>,
) -> Result<(), Error> {
    let mut remaining = frame;
    while !remaining.is_empty() {
        match send(remaining) {
            Ok(0) => return Err(Errno::EPIPE.into()),
            Ok(n) => remaining = &remaining[n..],
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Decode Linux `/proc/self/mountinfo` octal escapes (`\040`, `\011`, `\012`, `\134`, etc.).
pub fn unescape_mountinfo(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && (b'0'..=b'7').contains(&bytes[i + 1])
            && (b'0'..=b'7').contains(&bytes[i + 2])
            && (b'0'..=b'7').contains(&bytes[i + 3])
        {
            let val =
                ((bytes[i + 1] - b'0') << 6) | ((bytes[i + 2] - b'0') << 3) | (bytes[i + 3] - b'0');
            out.push(val);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_wire_objects_round_trip() {
        let req = MountRequest::ListAll { include_busy: true };
        assert_eq!(
            decode_frame::<MountRequest>(&encode_frame(&req).unwrap()),
            Ok(req)
        );
        let resp = MountResponse::Error {
            errno: Errno::EBUSY,
            error: MountErrorKind::Busy {
                processes: vec![BusyProcess {
                    pid: 19,
                    uid: 1000,
                    comm: "sh".into(),
                    reasons: vec!["cwd".into()],
                }],
            },
            message: "busy".into(),
        };
        assert_eq!(
            decode_frame::<MountResponse>(&encode_frame(&resp).unwrap()),
            Ok(resp)
        );
        for json in [
            r#"{"op":"list_sources","uid":0}"#,
            r#"{"op":"detach","target":"/tmp","cred":{}}"#,
            r#"{"op":"list_all","session":"other"}"#,
        ] {
            assert!(serde_json::from_str::<MountRequest>(json).is_err());
        }
        assert!(serde_json::from_str::<MountResponse>(r#"{"status":"ok","extra":1}"#).is_err());
        assert!(serde_json::from_str::<SourceInfo>(r#"{"id":"x","kind":"opfs","state":"granted","location":"local","label":"x","saved":false,"writable":true,"execute":false,"token":"secret"}"#).is_err());
    }

    #[test]
    fn framing_handles_partial_io_and_bounds() {
        let value = "x".repeat(MAX_FRAME_BYTES - 3);
        let frame = encode_frame(&value).unwrap();
        assert_eq!(frame.len(), MAX_FRAME_BYTES);
        assert_eq!(
            encode_frame(&(value + "x")).unwrap_err().errno,
            Errno::E2BIG
        );
        let mut sent = vec![];
        write_frame(&frame, |buf| {
            let n = buf.len().min(17);
            sent.extend_from_slice(&buf[..n]);
            Ok(n)
        })
        .unwrap();
        let mut reader = sent.as_slice();
        let read = read_frame(|buf| {
            let n = reader.len().min(buf.len()).min(31);
            buf[..n].copy_from_slice(&reader[..n]);
            reader = &reader[n..];
            Ok(n)
        })
        .unwrap();
        assert_eq!(read, frame);
        assert!(decode_frame::<String>(&frame[..frame.len() - 1]).is_err());
        assert!(decode_frame::<MountRequest>(b"{}\n{}\n").is_err());
    }
}

/// Local host adapter listener. Each operation transfers the accepted client socket as
/// SCM_RIGHTS. The adapter checks both peers before resolving a UID or namespace.
pub const MOUNT_HOST_SOCK: &str = "/run/mount/host.sock";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MountBackendRequest {
    pub target_pid: Option<u32>,
    pub op: MountBackendOp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum MountBackendOp {
    Peer {},
    Sources {},
    Filesystems {},
    Attachments {
        include_busy: bool,
    },
    Exports {},
    Attach {
        source: String,
        target: String,
        fstype: String,
        flags: u64,
        options: Option<String>,
        owner_uid: Option<u32>,
    },
    Detach {
        target: String,
        mount_id: u64,
        lazy: bool,
        force: bool,
    },
    Remount {
        target: String,
        mount_id: u64,
        flags: u64,
        options: Option<String>,
    },
    Activate {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        additional_sources: Vec<String>,
        source_id: String,
        name: String,
        execute: bool,
    },
    Forget {
        source_id: String,
    },
}

impl SourceKind {
    pub fn fstype(&self) -> &'static str {
        match self {
            Self::Hostfs | Self::SelectedFiles => "hostfs",
            Self::Opfs => "opfs",
            Self::Helperfs => "helperfs",
            Self::Sharefs => "sharefs",
            Self::CowfsVolume | Self::CowfsSnapshot | Self::LoopDevice => "cowfs",
            Self::Cloud => "cloud",
            Self::Image => "image",
        }
    }
}

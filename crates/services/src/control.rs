//! Framed JSON control socket protocol (`/run/init/control.sock`, `/run/user/<uid>/manager.sock`),
//! `NOTIFY_SOCKET` datagram parser (`/run/init/notify.sock`), and kernel `SO_PEERCRED`
//! authorization rules (`#57` `L3d`, Contract v2 §2.8).

use crate::unit::{UnitKind, UnitSpec};
use abi::{Errno, Error};
use serde::{Deserialize, Serialize};

/// Protocol version spoken over `/run/init/control.sock` and `/run/user/<uid>/manager.sock`.
pub const CONTROL_PROTOCOL_VERSION: u32 = 2;

/// Canonical system PID 1 control socket path (`SOCK_STREAM`, kernel-checked `SO_PEERCRED`).
pub const SYSTEM_CONTROL_SOCKET: &str = "/run/init/control.sock";

/// Canonical system PID 1 readiness notify socket path (`SOCK_DGRAM`, mode `0666`,
/// strictly authenticated via `SO_PEERCRED` `cred.pid == unit.pid`).
pub const SYSTEM_NOTIFY_SOCKET: &str = "/run/init/notify.sock";

/// Canonical per-user manager control socket path (dir `/run/user/<uid>` mode `0700`).
pub fn user_manager_socket(uid: u32) -> String {
    format!("/run/user/{uid}/manager.sock")
}

/// Maximum bytes in a single framed JSON control request or response.
pub const MAX_CONTROL_FRAME_BYTES: usize = 65_536;

/// Maximum bytes in a single `NOTIFY_SOCKET` datagram.
pub const MAX_NOTIFY_DATAGRAM_BYTES: usize = 4_096;

/// Kernel-authenticated peer credentials (`SO_PEERCRED`, matching `struct ucred`).
/// Always populated by the kernel from `LocalProcessTable`, never trusted from client payloads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerCred {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

/// Runtime state summary reported over the control socket.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitStatusView {
    pub name: String,
    pub kind: UnitKind,
    pub state: String,
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    pub attempts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Control request sent by `service` CLI or local orchestrators over `AF_UNIX`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlRequest {
    List,
    Status {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        unit: Option<String>,
    },
    Start {
        unit: String,
    },
    Stop {
        unit: String,
    },
    Restart {
        unit: String,
    },
    Enable {
        unit: String,
    },
    Disable {
        unit: String,
    },
    RegisterUnit {
        spec: Box<UnitSpec>,
    },
    Poweroff,
    Reboot,
}

impl ControlRequest {
    /// True for operations that mutate service manager or system lifecycle state.
    pub fn is_mutating(&self) -> bool {
        !matches!(self, Self::List | Self::Status { .. })
    }
}

/// Control response returned by the PID 1 or per-user service manager.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ControlResponse {
    Ok {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
    Units {
        units: Vec<UnitStatusView>,
    },
    Unit {
        unit: UnitStatusView,
    },
    Error {
        errno: Errno,
        message: String,
    },
}

/// Encode a `ControlRequest` as a bounded newline-delimited JSON frame.
pub fn encode_request_frame(req: &ControlRequest) -> Result<Vec<u8>, Error> {
    let mut bytes = serde_json::to_vec(req)
        .map_err(|e| Error::because(Errno::EINVAL, format!("encode request: {e}")))?;
    if bytes.len() + 1 > MAX_CONTROL_FRAME_BYTES {
        return Err(Error::because(
            Errno::E2BIG,
            "control request frame too large",
        ));
    }
    bytes.push(b'\n');
    Ok(bytes)
}

/// Decode a bounded newline-delimited JSON `ControlRequest` frame.
pub fn decode_request_frame(frame: &[u8]) -> Result<ControlRequest, Error> {
    if frame.is_empty() || frame.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(Error::because(Errno::EINVAL, "invalid control frame size"));
    }
    let trimmed = frame.strip_suffix(b"\n").unwrap_or(frame);
    serde_json::from_slice(trimmed)
        .map_err(|e| Error::because(Errno::EINVAL, format!("invalid control request: {e}")))
}

/// Encode a `ControlResponse` as a bounded newline-delimited JSON frame.
pub fn encode_response_frame(resp: &ControlResponse) -> Result<Vec<u8>, Error> {
    let mut bytes = serde_json::to_vec(resp)
        .map_err(|e| Error::because(Errno::EINVAL, format!("encode response: {e}")))?;
    if bytes.len() + 1 > MAX_CONTROL_FRAME_BYTES {
        return Err(Error::because(
            Errno::E2BIG,
            "control response frame too large",
        ));
    }
    bytes.push(b'\n');
    Ok(bytes)
}

/// Decode a bounded newline-delimited JSON `ControlResponse` frame.
pub fn decode_response_frame(frame: &[u8]) -> Result<ControlResponse, Error> {
    if frame.is_empty() || frame.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(Error::because(Errno::EINVAL, "invalid control frame size"));
    }
    let trimmed = frame.strip_suffix(b"\n").unwrap_or(frame);
    serde_json::from_slice(trimmed)
        .map_err(|e| Error::because(Errno::EINVAL, format!("invalid control response: {e}")))
}

/// Enforce kernel `SO_PEERCRED` authorization for control requests:
/// - System PID 1 manager (`manager_uid == 0`): read-only `List`/`Status` allowed for any local
///   UID; all mutating operations (`Start`, `Stop`, `Restart`, `Enable`, `Disable`, `RegisterUnit`,
///   `Poweroff`, `Reboot`) strictly require `cred.uid == 0` (`EPERM` otherwise).
/// - Per-user manager (`manager_uid != 0`): strictly requires `cred.uid == manager_uid`, forbids
///   `Poweroff`/`Reboot` (`EPERM`), and enforces `UnitSpec::authorize_for_manager(manager_uid)`
///   on `RegisterUnit` (rejecting `grant.user` elevation with `EPERM`).
pub fn authorize_control(
    manager_uid: u32,
    cred: PeerCred,
    req: &ControlRequest,
) -> Result<(), Error> {
    if manager_uid == 0 {
        if req.is_mutating() && cred.uid != 0 {
            return Err(Error::because(
                Errno::EPERM,
                format!(
                    "uid {} is not permitted to perform mutating system service operations",
                    cred.uid
                ),
            ));
        }
        if let ControlRequest::RegisterUnit { spec } = req {
            spec.authorize_for_manager(0)?;
        }
        return Ok(());
    }

    if cred.uid != manager_uid {
        return Err(Error::because(
            Errno::EPERM,
            format!(
                "peer uid {} does not match user service manager uid {manager_uid}",
                cred.uid
            ),
        ));
    }
    match req {
        ControlRequest::Poweroff | ControlRequest::Reboot => Err(Error::because(
            Errno::EPERM,
            "per-user service manager cannot poweroff or reboot the instance",
        )),
        ControlRequest::RegisterUnit { spec } => spec.authorize_for_manager(manager_uid),
        _ => Ok(()),
    }
}

/// Parsed systemd-compatible `NOTIFY_SOCKET` datagram payload (`READY=1`, `STATUS=...`, etc.).
/// `MAINPID` is never trusted over kernel `SO_PEERCRED`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NotifyMessage {
    pub ready: bool,
    pub stopping: bool,
    pub reloading: bool,
    pub status: Option<String>,
    pub errno: Option<u32>,
}

impl NotifyMessage {
    pub fn parse(payload: &[u8]) -> Result<Self, Error> {
        if payload.is_empty() || payload.len() > MAX_NOTIFY_DATAGRAM_BYTES {
            return Err(Error::because(Errno::EINVAL, "invalid notify payload size"));
        }
        if payload.contains(&0) {
            return Err(Error::because(
                Errno::EINVAL,
                "notify payload contains NUL byte",
            ));
        }
        let text = std::str::from_utf8(payload)
            .map_err(|_| Error::because(Errno::EINVAL, "notify payload is not valid UTF-8"))?;
        let mut msg = Self::default();
        let mut saw_assignment = false;
        for raw_line in text.lines() {
            let line = raw_line.trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }
            let Some((key, val)) = line.split_once('=') else {
                return Err(Error::because(
                    Errno::EINVAL,
                    "notify line missing '=' separator",
                ));
            };
            saw_assignment = true;
            match key {
                "READY" => msg.ready = val == "1",
                "STOPPING" => msg.stopping = val == "1",
                "RELOADING" => msg.reloading = val == "1",
                "STATUS" => {
                    if val.len() > 256 {
                        return Err(Error::because(Errno::EINVAL, "STATUS exceeds 256 bytes"));
                    }
                    msg.status = Some(val.to_owned());
                }
                "ERRNO" => {
                    msg.errno = val.parse::<u32>().ok();
                }
                _ => {
                    // Unknown extension keys (including untrusted MAINPID) are ignored safely.
                }
            }
        }
        if !saw_assignment {
            return Err(Error::because(Errno::EINVAL, "empty notify datagram"));
        }
        Ok(msg)
    }
}

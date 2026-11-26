//! Local `kubelet` host control protocol, version 1 (`Phase 9.1b #84`).
//!
//! Spoken between the opt-in userspace `/usr/bin/kubelet` WASI service and the host
//! kubelet runtime (browser `kubelet-agent.js` or native `os-native` `KubeletHostServer`)
//! over `/run/kubelet/host.sock` (`AF_UNIX`, `SOCK_STREAM`, `0600`, `SO_PEERCRED.uid == 0`).
//!
//! Wire framing: big-endian 4-byte length prefix followed by UTF-8 JSON (`<= MAX_FRAME_BYTES`).
use crate::{Errno, Error};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::BTreeMap;

/// Active local `kubelet` host control protocol version.
pub const KUBELET_CTL_VERSION: u32 = 1;

/// Host-side Unix domain socket path bound by the host runtime (`0600`, root-only).
pub const KUBELET_HOST_SOCK: &str = "/run/kubelet/host.sock";

/// Hard upper bound for a single framed JSON control message (64 KiB).
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// Request sent from `/usr/bin/kubelet` to the host adapter over `/run/kubelet/host.sock`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum KubeletHostRequest {
    Hello {
        versions: Vec<u32>,
    },
    Enroll {
        bootstrap_token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        node_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cluster: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        control_plane_url: Option<String>,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        labels: BTreeMap<String, String>,
    },
    Start {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        control_plane_url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cluster: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        node_id: Option<String>,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        labels: BTreeMap<String, String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        lease_ttl_secs: Option<u64>,
    },
    Status {},
    Drain {},
    Stop {},
}

/// Snapshot of the host kubelet runtime returned by `KubeletHostReply::Status`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubeletStatus {
    pub state: String, // "stopped" | "enrolled" | "running" | "draining" | "revoked"
    pub enrolled: bool,
    pub running: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    #[serde(default)]
    pub node_generation: u64,
    #[serde(default)]
    pub active_attempts: u32,
    #[serde(default)]
    pub completed_attempts: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Reply returned by the host adapter over `/run/kubelet/host.sock`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum KubeletHostReply {
    Welcome {
        version: u32,
        host_kind: String,
    },
    Enrolled {
        node_id: String,
        cluster: String,
        tenant: String,
        enrollment_id: String,
        instance_id: String,
    },
    Started {
        status: KubeletStatus,
    },
    Status {
        status: KubeletStatus,
    },
    Draining {
        status: KubeletStatus,
    },
    Stopped {
        status: KubeletStatus,
    },
    Error {
        errno: Errno,
        message: String,
    },
}

/// Encode a length-prefixed JSON frame (`[u32_be_len][json_bytes]`).
pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let payload =
        serde_json::to_vec(value).map_err(|e| Error::because(Errno::EINVAL, e.to_string()))?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(Error::because(
            Errno::E2BIG,
            format!("kubelet control frame exceeds {MAX_FRAME_BYTES} bytes"),
        ));
    }
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Decode a JSON payload from a length-prefixed frame body (without the 4-byte header).
pub fn decode_payload<T: DeserializeOwned>(payload: &[u8]) -> Result<T, Error> {
    if payload.len() > MAX_FRAME_BYTES {
        return Err(Errno::E2BIG.into());
    }
    serde_json::from_slice(payload).map_err(|e| Error::because(Errno::EINVAL, e.to_string()))
}

/// Read one length-prefixed frame from a blocking/nonblocking byte reader closure.
pub fn read_frame(
    mut recv: impl FnMut(&mut [u8]) -> Result<usize, Errno>,
) -> Result<Vec<u8>, Error> {
    let mut hdr = [0u8; 4];
    let mut got = 0usize;
    while got < 4 {
        match recv(&mut hdr[got..]) {
            Ok(0) => {
                return Err(Error::because(
                    Errno::ECONNRESET,
                    "peer closed before kubelet frame header",
                ));
            }
            Ok(n) => got += n,
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    let len = u32::from_be_bytes(hdr) as usize;
    if len == 0 || len > MAX_FRAME_BYTES {
        return Err(Error::because(
            if len == 0 {
                Errno::EINVAL
            } else {
                Errno::E2BIG
            },
            "invalid kubelet control frame length",
        ));
    }
    let mut payload = vec![0u8; len];
    let mut pos = 0usize;
    while pos < len {
        match recv(&mut payload[pos..]) {
            Ok(0) => {
                return Err(Error::because(
                    Errno::ECONNRESET,
                    "peer closed mid kubelet control frame",
                ));
            }
            Ok(n) => pos += n,
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(payload)
}

/// Write a complete length-prefixed frame.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kubelet_ctl_round_trip_and_deny_unknown_fields() {
        let req = KubeletHostRequest::Hello {
            versions: vec![KUBELET_CTL_VERSION],
        };
        let frame = encode_frame(&req).unwrap();
        let mut cursor = frame.as_slice();
        let payload = read_frame(|buf| {
            let n = buf.len().min(cursor.len()).min(7);
            buf[..n].copy_from_slice(&cursor[..n]);
            cursor = &cursor[n..];
            Ok(n)
        })
        .unwrap();
        assert_eq!(decode_payload::<KubeletHostRequest>(&payload).unwrap(), req);

        // Unknown fields rejected strictly.
        assert!(serde_json::from_str::<KubeletHostRequest>(r#"{"op":"status","uid":0}"#).is_err());
        assert!(
            serde_json::from_str::<KubeletHostReply>(
                r#"{"kind":"welcome","version":1,"host_kind":"browser","extra":1}"#
            )
            .is_err()
        );
    }
}

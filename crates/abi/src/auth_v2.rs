//! ServiceAuth v2 wire protocol for narrowed remote service authentication,
//! instance host fencing, remote credential minting/derivation/revocation,
//! and per-credential remote `io.max` accounting (`docs/architecture/contract.md` §2.3, §2.7, §2.10).
use crate::contract::{Boundary, Hello, InstanceIdentity, SERVICE_AUTH_VERSION, negotiate};
use crate::{Errno, Error};
use serde::{Deserialize, Serialize};

/// Current `ServiceAuth` wire protocol version (`contract::SERVICE_AUTH_VERSION`).
pub const VERSION: u32 = SERVICE_AUTH_VERSION;

/// Negotiated `ServiceAuth` handshake reply (`contract::Hello` -> `Welcome`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Welcome {
    pub boundary: Boundary,
    pub version: u32,
}

/// Bounded host-attachment lease in seconds. When an instance host vanishes
/// without cleanly detaching, remote leases & open-refs expire within this bound.
pub const INSTANCE_LEASE_SECONDS: u64 = 90;

/// Maximum tokens accepted in a single renew or revoke request.
pub const TOKENS_MAX: usize = 256;

/// Maximum length of an `instance_id`, `host_proof`, or `cgroup` path.
pub const ID_MAX: usize = 128;

/// Explicit remote capabilities granted to a minted or derived service credential.
/// Local `uid 0` NEVER synthesizes a remote root credential; every remote capability
/// must be minted from an authenticated cloud session or explicitly attenuated from
/// a parent remote credential.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteScope {
    /// Cloud filesystem (`/api/fs`, `/api/file`, `/api/pwrite`, `/api/sys` cloud paths).
    #[serde(default)]
    pub cloud_fs: bool,
    /// Explicitly attached remote device drivers (`archive`, `media`, `present`, `snd`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<String>,
    /// Server-hosted container jobs.
    #[serde(default)]
    pub containers: bool,
    /// Shared-mount relay transport.
    #[serde(default)]
    pub relay: bool,
}

impl RemoteScope {
    pub fn cloud_only() -> Self {
        Self {
            cloud_fs: true,
            devices: Vec::new(),
            containers: false,
            relay: false,
        }
    }

    pub fn full() -> Self {
        Self {
            cloud_fs: true,
            devices: vec![
                "archive".into(),
                "media".into(),
                "present".into(),
                "snd".into(),
            ],
            containers: true,
            relay: true,
        }
    }

    pub fn is_empty(&self) -> bool {
        !self.cloud_fs && self.devices.is_empty() && !self.containers && !self.relay
    }

    pub fn allows_device(&self, driver: &str) -> bool {
        self.devices.iter().any(|d| d == driver)
    }

    /// Monotonic attenuation: a derived scope can never exceed its parent scope.
    pub fn attenuate(&self, requested: &RemoteScope) -> RemoteScope {
        RemoteScope {
            cloud_fs: self.cloud_fs && requested.cloud_fs,
            devices: requested
                .devices
                .iter()
                .filter(|d| self.allows_device(d))
                .cloned()
                .collect(),
            containers: self.containers && requested.containers,
            relay: self.relay && requested.relay,
        }
    }
}

/// Lazy first-remote-use instance attachment & host fencing.
/// One live host per `instance_id`; presenting a mismatched or stale `host_proof`
/// fails closed with `ESTALE` / `EACCES`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachInstance {
    pub instance: InstanceIdentity,
    /// Opaque secret proof generated locally by the owning host; the server stores
    /// only its SHA-256 hash.
    pub host_proof: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachResult {
    pub version: u32,
    pub instance_id: String,
    pub lease_seconds: u64,
    pub host_epoch: u64,
}

/// Mint a remote service credential bound to an attached `(instance_id, host_proof)`
/// from the caller's authenticated cloud session cookie (never from local uid claims).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintServiceCred {
    pub instance_id: String,
    pub host_proof: String,
    #[serde(default)]
    pub scope: RemoteScope,
    #[serde(default = "default_true")]
    pub cloud_access: bool,
    #[serde(default = "default_umask")]
    pub umask: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<String>,
    /// Whether the cloud session's active sudo timestamp elevates this credential to remote root.
    #[serde(default)]
    pub sudo: bool,
}

/// Derive a monotonically attenuated remote credential from an existing live parent token
/// (for re-exec attenuation or explicit privilege-drop remote identity binding).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeriveServiceCred {
    pub instance_id: String,
    pub host_proof: String,
    pub parent_token: String,
    #[serde(default)]
    pub scope: RemoteScope,
    #[serde(default = "default_true")]
    pub cloud_access: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub umask: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<String>,
    #[serde(default)]
    pub revoke_parent: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceCredIssued {
    pub version: u32,
    pub token: String,
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
    pub umask: u16,
    pub cloud_access: bool,
    pub scope: RemoteScope,
    pub expires: u64,
    pub instance_id: String,
    pub lineage: String,
}

/// Renew an attached instance's lease and its active remote service tokens.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewInstance {
    pub instance_id: String,
    pub host_proof: String,
    #[serde(default)]
    pub active_tokens: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewResult {
    pub version: u32,
    pub lease_seconds: u64,
    /// Token hashes (or raw tokens echoed from `active_tokens`) that are no longer valid
    /// (e.g. account locked, password changed, deleted, or revoked).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked: Vec<String>,
}

/// Immediately revoke one or more remote service tokens when their last local process
/// holder exits, is SIGKILLed, or drops local privilege.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeTokens {
    pub instance_id: String,
    pub host_proof: String,
    pub tokens: Vec<String>,
}

/// Detach an instance cleanly on orderly shutdown, revoking all of its remote credentials
/// and releasing its host fence immediately.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetachInstance {
    pub instance_id: String,
    pub host_proof: String,
}

/// Register or update server-side remote `io.max` accounting policy for a remote service
/// credential (enforced by the server on every remote storage/container/relay I/O regardless
/// of client claims).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteIoQuota {
    pub instance_id: String,
    pub host_proof: String,
    pub token: String,
    pub cgroup: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rbps: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wbps: Option<u64>,
}

/// Wire request envelope for `/api/service-auth`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Request {
    Hello(Hello),
    AttachInstance(AttachInstance),
    MintServiceCred(MintServiceCred),
    DeriveServiceCred(DeriveServiceCred),
    RenewInstance(RenewInstance),
    RevokeTokens(RevokeTokens),
    DetachInstance(DetachInstance),
    SetRemoteIoQuota(RemoteIoQuota),
}

/// Wire response envelope for `/api/service-auth`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Response {
    Welcome(Welcome),
    Attached(AttachResult),
    Cred(ServiceCredIssued),
    Renewed(RenewResult),
    Revoked { count: usize },
    Detached { revoked: usize },
    QuotaSet,
}

fn default_true() -> bool {
    true
}

fn default_umask() -> u16 {
    0o022
}

/// Validate a `Hello` message for `Boundary::ServiceAuth` version `VERSION` (2).
/// Returns `Errno::EPROTONOSUPPORT` on boundary or version mismatch (Contract §2.10).
pub fn negotiate_hello(hello: &Hello) -> Result<Welcome, Error> {
    let ours = Hello {
        boundary: Boundary::ServiceAuth,
        versions: vec![VERSION],
    };
    let Some(version) = negotiate(&ours, hello) else {
        return Err(Error::because(
            Errno::EPROTONOSUPPORT,
            format!("ServiceAuth v{VERSION} required"),
        ));
    };
    Ok(Welcome {
        boundary: Boundary::ServiceAuth,
        version,
    })
}

/// Validate an identifier (`instance_id`, `host_proof`, etc.) for non-empty safe ASCII.
pub fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= ID_MAX
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_negotiation_accepts_v2_and_refuses_mismatch_with_eprotonosupport() {
        let ok = negotiate_hello(&Hello {
            boundary: Boundary::ServiceAuth,
            versions: vec![1, 2],
        })
        .unwrap();
        assert_eq!(ok.boundary, Boundary::ServiceAuth);
        assert_eq!(ok.version, 2);

        let old = negotiate_hello(&Hello {
            boundary: Boundary::ServiceAuth,
            versions: vec![1],
        })
        .unwrap_err();
        assert_eq!(old.errno, Errno::EPROTONOSUPPORT);

        let wrong_boundary = negotiate_hello(&Hello {
            boundary: Boundary::HostAdapter,
            versions: vec![2],
        })
        .unwrap_err();
        assert_eq!(wrong_boundary.errno, Errno::EPROTONOSUPPORT);
    }

    #[test]
    fn scope_attenuation_is_strictly_monotonic() {
        let parent = RemoteScope {
            cloud_fs: true,
            devices: vec!["archive".into(), "present".into()],
            containers: false,
            relay: true,
        };
        let requested = RemoteScope {
            cloud_fs: true,
            devices: vec!["archive".into(), "snd".into()],
            containers: true,
            relay: false,
        };
        let child = parent.attenuate(&requested);
        assert!(child.cloud_fs);
        assert_eq!(child.devices, vec!["archive".to_string()]);
        assert!(!child.containers);
        assert!(!child.relay);
    }

    #[test]
    fn request_and_response_round_trip() {
        let req = Request::AttachInstance(AttachInstance {
            instance: InstanceIdentity {
                instance: "inst-abc".into(),
                host: "browser".into(),
            },
            host_proof: "proof-deadbeef".into(),
        });
        let raw = serde_json::to_string(&req).unwrap();
        assert_eq!(serde_json::from_str::<Request>(&raw).unwrap(), req);

        let resp = Response::Attached(AttachResult {
            version: VERSION,
            instance_id: "inst-abc".into(),
            lease_seconds: INSTANCE_LEASE_SECONDS,
            host_epoch: 1,
        });
        let raw_resp = serde_json::to_string(&resp).unwrap();
        assert_eq!(serde_json::from_str::<Response>(&raw_resp).unwrap(), resp);
    }
}

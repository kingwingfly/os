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
    #[serde(default)]
    pub volumes: bool,
    /// An empty list grants all volumes in the authenticated tenant when volumes is enabled.
    #[serde(default)]
    pub volume_ids: Vec<String>,
    #[serde(default)]
    pub volumes_ro: bool,
    /// Pull manifests, blobs, tags, and referrers from the OCI v1.1 registry (`/v2/`).
    #[serde(default)]
    pub registry_pull: bool,
    /// Push manifests, blobs, and referrers to (or delete from) the OCI v1.1 registry (`/v2/`).
    #[serde(default)]
    pub registry_push: bool,
    /// Permitted repository names or prefix globs (`"app/web"`, `"team/*"`).
    /// Empty list grants all repositories in the authenticated tenant when pull/push is enabled.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub registry_repos: Vec<String>,
    /// Read (`Range`, `Txn` compare/range) keys in `ClusterState`.
    #[serde(default)]
    pub cluster_read: bool,
    /// Mutate (`Txn` put/delete) keys in `ClusterState`.
    #[serde(default)]
    pub cluster_write: bool,
    /// Subscribe to key/prefix change streams (`Watch`) in `ClusterState`.
    #[serde(default)]
    pub cluster_watch: bool,
    /// Grant, keep alive, revoke, and inspect node/object leases (`Lease*`) in `ClusterState`.
    #[serde(default)]
    pub cluster_lease: bool,
    /// Compact MVCC revision history (`Compact`; admin-only unrestricted).
    #[serde(default)]
    pub cluster_compact: bool,
    /// Permitted tenant-relative key patterns (`"nodes/node-1"`, `"workloads/*"`, `"workloads/"`).
    /// Empty list grants all keys in the authenticated tenant when cluster capabilities are enabled.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cluster_prefixes: Vec<String>,
    /// Optional node binding restricting node-record writes (`/t/<tenant>/nodes/<id>`,
    /// `/t/<tenant>/node-meta/<id>`) and lease ownership to this node identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_node_id: Option<String>,
}

/// Validate a single cluster key segment or record identifier (e.g. `node_id`, `workload_id`).
/// Non-empty, `<= 128` bytes, never `.` or `..`, ASCII `[A-Za-z0-9._:@-]`.
pub fn valid_cluster_record_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= ID_MAX
        && id != "."
        && id != ".."
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'@' | b'-'))
}

fn valid_cluster_rel_path(rel: &str) -> bool {
    !rel.is_empty()
        && rel.len() <= 512
        && !rel.starts_with('/')
        && !rel.ends_with('/')
        && rel.split('/').all(valid_cluster_record_id)
}

/// If `pattern` is a valid subtree prefix (`"foo/*"` or `"foo/"`), returns its base path (`"foo"`).
fn cluster_prefix_base(pattern: &str) -> Option<&str> {
    if let Some(base) = pattern.strip_suffix("/*") {
        valid_cluster_rel_path(base).then_some(base)
    } else if let Some(base) = pattern.strip_suffix('/') {
        valid_cluster_rel_path(base).then_some(base)
    } else {
        None
    }
}

/// Validate a tenant-relative `RemoteScope.cluster_prefixes` entry (no regexes, zero ReDoS risk).
/// Accepts either an exact relative key (`"nodes/n1"`) or a subtree prefix (`"nodes/*"` / `"nodes/"`).
pub fn valid_cluster_prefix_pattern(pattern: &str) -> bool {
    if pattern.is_empty() || pattern.len() > 512 || pattern.starts_with('/') {
        return false;
    }
    if let Some(base) = pattern.strip_suffix("/*") {
        valid_cluster_rel_path(base)
    } else if let Some(base) = pattern.strip_suffix('/') {
        valid_cluster_rel_path(base)
    } else {
        valid_cluster_rel_path(pattern)
    }
}

/// Match a tenant-relative cluster key (e.g. `"nodes/n1"`) against a validated prefix pattern.
pub fn cluster_prefix_matches(pattern: &str, rel_key: &str) -> bool {
    if !valid_cluster_prefix_pattern(pattern) || !valid_cluster_rel_path(rel_key) {
        return false;
    }
    if let Some(base) = cluster_prefix_base(pattern) {
        rel_key
            .strip_prefix(base)
            .and_then(|rest| rest.strip_prefix('/'))
            .is_some_and(|tail| !tail.is_empty())
    } else {
        pattern == rel_key
    }
}

/// True when every tenant-relative key matched by `inner` is also matched by `outer`.
pub fn cluster_prefix_covers(outer: &str, inner: &str) -> bool {
    if !valid_cluster_prefix_pattern(outer) || !valid_cluster_prefix_pattern(inner) {
        return false;
    }
    match (cluster_prefix_base(outer), cluster_prefix_base(inner)) {
        (Some(ob), Some(ib)) => {
            ib == ob
                || ib
                    .strip_prefix(ob)
                    .and_then(|rest| rest.strip_prefix('/'))
                    .is_some_and(|tail| !tail.is_empty())
        }
        (Some(_), None) => cluster_prefix_matches(outer, inner),
        (None, Some(_)) => false,
        (None, None) => outer == inner,
    }
}

/// Match an OCI repository name against either an exact repository name (`"team/app"`)
/// or a prefix glob (`"team/*"`). No regexes (zero ReDoS risk).
pub fn repo_pattern_matches(pattern: &str, repo: &str) -> bool {
    if pattern.is_empty() || repo.is_empty() {
        return false;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        !prefix.is_empty()
            && repo
                .strip_prefix(prefix)
                .and_then(|rest| rest.strip_prefix('/'))
                .is_some_and(|tail| !tail.is_empty())
    } else {
        pattern == repo
    }
}

/// True when every repository matched by `inner` is also matched by `outer`.
pub fn repo_pattern_covers(outer: &str, inner: &str) -> bool {
    if outer.is_empty() || inner.is_empty() {
        return false;
    }
    if outer == inner {
        return true;
    }
    if let Some(outer_prefix) = outer.strip_suffix("/*") {
        if outer_prefix.is_empty() {
            return false;
        }
        if let Some(inner_prefix) = inner.strip_suffix("/*") {
            return inner_prefix == outer_prefix
                || inner_prefix
                    .strip_prefix(outer_prefix)
                    .and_then(|rest| rest.strip_prefix('/'))
                    .is_some_and(|tail| !tail.is_empty());
        }
        return repo_pattern_matches(outer, inner);
    }
    false
}

impl RemoteScope {
    pub fn cloud_only() -> Self {
        Self {
            cloud_fs: true,
            devices: Vec::new(),
            containers: false,
            relay: false,
            ..Self::default()
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
            volumes: true,
            registry_pull: true,
            registry_push: true,
            registry_repos: Vec::new(),
            cluster_read: true,
            cluster_write: true,
            cluster_watch: true,
            cluster_lease: true,
            cluster_compact: true,
            cluster_prefixes: Vec::new(),
            cluster_node_id: None,
            ..Self::default()
        }
    }

    pub fn is_empty(&self) -> bool {
        !self.cloud_fs
            && self.devices.is_empty()
            && !self.containers
            && !self.relay
            && !self.volumes
            && !self.registry_pull
            && !self.registry_push
            && !self.cluster_read
            && !self.cluster_write
            && !self.cluster_watch
            && !self.cluster_lease
            && !self.cluster_compact
    }

    pub fn has_cluster(&self) -> bool {
        self.cluster_read
            || self.cluster_write
            || self.cluster_watch
            || self.cluster_lease
            || self.cluster_compact
    }

    pub fn allows_cluster_prefix(&self, rel_key: &str) -> bool {
        self.cluster_prefixes.is_empty()
            || self
                .cluster_prefixes
                .iter()
                .any(|p| cluster_prefix_matches(p, rel_key))
    }

    pub fn allows_volume(&self, id: &str, write: bool) -> bool {
        self.volumes
            && !(write && self.volumes_ro)
            && (self.volume_ids.is_empty() || self.volume_ids.iter().any(|v| v == id))
    }

    pub fn allows_registry(&self, repo: &str, push: bool) -> bool {
        let enabled = if push {
            self.registry_push
        } else {
            self.registry_pull
        };
        enabled
            && (self.registry_repos.is_empty()
                || self
                    .registry_repos
                    .iter()
                    .any(|p| repo_pattern_matches(p, repo)))
    }

    pub fn allows_device(&self, driver: &str) -> bool {
        self.devices.iter().any(|d| d == driver)
    }

    /// Monotonic attenuation: a derived scope can never exceed its parent scope.
    pub fn attenuate(&self, requested: &RemoteScope) -> RemoteScope {
        let volume_ids = if self.volume_ids.is_empty() {
            requested.volume_ids.clone()
        } else if requested.volume_ids.is_empty() {
            self.volume_ids.clone()
        } else {
            requested
                .volume_ids
                .iter()
                .filter(|id| self.volume_ids.contains(id))
                .cloned()
                .collect()
        };
        let registry_repos = if self.registry_repos.is_empty() {
            requested.registry_repos.clone()
        } else if requested.registry_repos.is_empty() {
            self.registry_repos.clone()
        } else {
            let mut out = Vec::new();
            for r in &requested.registry_repos {
                if self
                    .registry_repos
                    .iter()
                    .any(|p| repo_pattern_covers(p, r))
                    && !out.contains(r)
                {
                    out.push(r.clone());
                }
            }
            for p in &self.registry_repos {
                if requested
                    .registry_repos
                    .iter()
                    .any(|r| repo_pattern_covers(r, p))
                    && !out.contains(p)
                {
                    out.push(p.clone());
                }
            }
            out
        };
        let has_repo = self.registry_repos.is_empty()
            || requested.registry_repos.is_empty()
            || !registry_repos.is_empty();
        let max_prefixes = crate::cluster_state::CLUSTER_MAX_PREFIX_GRANTS;
        let prefixes_valid = self.cluster_prefixes.len() <= max_prefixes
            && requested.cluster_prefixes.len() <= max_prefixes
            && self
                .cluster_prefixes
                .iter()
                .all(|p| valid_cluster_prefix_pattern(p))
            && requested
                .cluster_prefixes
                .iter()
                .all(|r| valid_cluster_prefix_pattern(r));
        let (raw_cluster_prefixes, prefix_ok) = if !prefixes_valid {
            (Vec::new(), false)
        } else if self.cluster_prefixes.is_empty() {
            let mut out: Vec<String> = Vec::new();
            for r in &requested.cluster_prefixes {
                if !out
                    .iter()
                    .any(|e| cluster_prefix_covers(e, r) && cluster_prefix_covers(r, e))
                {
                    out.push(r.clone());
                }
            }
            if out.len() <= max_prefixes {
                (out, true)
            } else {
                (Vec::new(), false)
            }
        } else if requested.cluster_prefixes.is_empty() {
            let mut out: Vec<String> = Vec::new();
            for p in &self.cluster_prefixes {
                if !out
                    .iter()
                    .any(|e| cluster_prefix_covers(e, p) && cluster_prefix_covers(p, e))
                {
                    out.push(p.clone());
                }
            }
            if out.len() <= max_prefixes {
                (out, true)
            } else {
                (Vec::new(), false)
            }
        } else {
            let mut out: Vec<String> = Vec::new();
            for r in &requested.cluster_prefixes {
                if self
                    .cluster_prefixes
                    .iter()
                    .any(|p| cluster_prefix_covers(p, r))
                    && !out
                        .iter()
                        .any(|e| cluster_prefix_covers(e, r) && cluster_prefix_covers(r, e))
                {
                    out.push(r.clone());
                }
            }
            for p in &self.cluster_prefixes {
                if requested
                    .cluster_prefixes
                    .iter()
                    .any(|r| cluster_prefix_covers(r, p))
                    && !out
                        .iter()
                        .any(|e| cluster_prefix_covers(e, p) && cluster_prefix_covers(p, e))
                {
                    out.push(p.clone());
                }
            }
            if !out.is_empty() && out.len() <= max_prefixes {
                (out, true)
            } else {
                (Vec::new(), false)
            }
        };
        let (raw_node_id, node_ok) = match (&self.cluster_node_id, &requested.cluster_node_id) {
            (None, None) => (None, true),
            (None, Some(r)) => {
                if valid_cluster_record_id(r) {
                    (Some(r.clone()), true)
                } else {
                    (None, false)
                }
            }
            (Some(p), None) => {
                if valid_cluster_record_id(p) {
                    (Some(p.clone()), true)
                } else {
                    (None, false)
                }
            }
            (Some(p), Some(r)) if p == r && valid_cluster_record_id(p) => (Some(p.clone()), true),
            (Some(_), Some(_)) => (None, false),
        };
        let cluster_ok = prefix_ok && node_ok;
        let (cluster_prefixes, cluster_node_id) = if cluster_ok {
            (raw_cluster_prefixes, raw_node_id)
        } else {
            (Vec::new(), None)
        };
        RemoteScope {
            volumes: self.volumes
                && requested.volumes
                && (self.volume_ids.is_empty()
                    || requested.volume_ids.is_empty()
                    || !volume_ids.is_empty()),
            volume_ids,
            volumes_ro: self.volumes_ro || requested.volumes_ro,
            registry_pull: self.registry_pull && requested.registry_pull && has_repo,
            registry_push: self.registry_push && requested.registry_push && has_repo,
            registry_repos,
            cluster_read: self.cluster_read && requested.cluster_read && cluster_ok,
            cluster_write: self.cluster_write && requested.cluster_write && cluster_ok,
            cluster_watch: self.cluster_watch && requested.cluster_watch && cluster_ok,
            cluster_lease: self.cluster_lease && requested.cluster_lease && cluster_ok,
            cluster_compact: self.cluster_compact
                && requested.cluster_compact
                && cluster_ok
                && cluster_prefixes.is_empty()
                && cluster_node_id.is_none(),
            cluster_prefixes,
            cluster_node_id,
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
    /// Optional initial server-side read bytes-per-second quota installed atomically at mint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rbps: Option<u64>,
    /// Optional initial server-side write bytes-per-second quota installed atomically at mint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wbps: Option<u64>,
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
    /// Optional server-side read bytes-per-second quota installed atomically on derive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rbps: Option<u64>,
    /// Optional server-side write bytes-per-second quota installed atomically on derive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wbps: Option<u64>,
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
#[allow(clippy::large_enum_variant)]
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
#[allow(clippy::large_enum_variant)]
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
            ..Default::default()
        };
        let requested = RemoteScope {
            cloud_fs: true,
            devices: vec!["archive".into(), "snd".into()],
            containers: true,
            relay: false,
            ..Default::default()
        };
        let child = parent.attenuate(&requested);
        assert!(child.cloud_fs);
        assert_eq!(child.devices, vec!["archive".to_string()]);
        assert!(!child.containers);
        assert!(!child.relay);
    }

    #[test]
    fn volume_grants_only_narrow() {
        let full = RemoteScope::full();
        let a = RemoteScope {
            volume_ids: vec!["a".into()],
            volumes_ro: true,
            ..full.clone()
        };
        let b = RemoteScope {
            volume_ids: vec!["b".into()],
            ..full.clone()
        };
        assert_eq!(a.attenuate(&full), a);
        assert_eq!(full.attenuate(&a), a);
        assert!(!a.allows_volume("a", true));
        assert!(a.allows_volume("a", false));
        assert!(!a.attenuate(&b).volumes);
        assert!(!a.attenuate(&b).attenuate(&full).volumes);
        assert!(
            !serde_json::from_str::<RemoteScope>(r#"{"cloud_fs":true}"#)
                .unwrap()
                .volumes
        );
    }

    #[test]
    fn registry_scope_attenuation_is_exact_and_monotonic() {
        let full = RemoteScope::full();
        assert!(full.allows_registry("team/app", false));
        assert!(full.allows_registry("team/app", true));
        assert!(!full.is_empty());

        let team_ro = RemoteScope {
            registry_pull: true,
            registry_push: false,
            registry_repos: vec!["team/*".into()],
            ..Default::default()
        };
        assert!(!team_ro.is_empty());
        assert!(team_ro.allows_registry("team/app", false));
        assert!(team_ro.allows_registry("team/sub/app", false));
        assert!(!team_ro.allows_registry("team/app", true));
        assert!(!team_ro.allows_registry("team", false));
        assert!(!team_ro.allows_registry("other/app", false));

        // Full -> team_ro narrows cleanly
        let n1 = full.attenuate(&team_ro);
        assert_eq!(n1, team_ro);
        // Attempting to widen back with full never grants push or other repos
        let n2 = team_ro.attenuate(&full);
        assert_eq!(n2, team_ro);

        // prefix/* ∩ exact -> exact
        let exact_app = RemoteScope {
            registry_pull: true,
            registry_push: true,
            registry_repos: vec!["team/app".into()],
            ..Default::default()
        };
        let inter1 = team_ro.attenuate(&exact_app);
        assert!(inter1.registry_pull);
        assert!(!inter1.registry_push);
        assert_eq!(inter1.registry_repos, vec!["team/app".to_string()]);

        // exact ∩ prefix/* -> exact
        let inter2 = exact_app.attenuate(&team_ro);
        assert!(inter2.registry_pull);
        assert!(!inter2.registry_push);
        assert_eq!(inter2.registry_repos, vec!["team/app".to_string()]);

        // a/* ∩ a/b/* -> a/b/*
        let a_glob = RemoteScope {
            registry_pull: true,
            registry_push: true,
            registry_repos: vec!["a/*".into()],
            ..Default::default()
        };
        let ab_glob = RemoteScope {
            registry_pull: true,
            registry_push: true,
            registry_repos: vec!["a/b/*".into()],
            ..Default::default()
        };
        assert_eq!(a_glob.attenuate(&ab_glob).registry_repos, vec!["a/b/*"]);
        assert_eq!(ab_glob.attenuate(&a_glob).registry_repos, vec!["a/b/*"]);

        // Disjoint repos collapse BOTH registry_pull and registry_push to false
        let other = RemoteScope {
            registry_pull: true,
            registry_push: true,
            registry_repos: vec!["other/*".into()],
            ..Default::default()
        };
        let disjoint = a_glob.attenuate(&other);
        assert!(!disjoint.registry_pull);
        assert!(!disjoint.registry_push);
        assert!(disjoint.registry_repos.is_empty());
        // Never revives on subsequent attenuation
        let after_disjoint = disjoint.attenuate(&full);
        assert!(!after_disjoint.registry_pull);
        assert!(!after_disjoint.registry_push);
    }

    #[test]
    fn cluster_scope_attenuation_is_exact_and_monotonic() {
        assert!(valid_cluster_record_id("node-1"));
        assert!(valid_cluster_record_id("wl:2@v1.0_a"));
        assert!(!valid_cluster_record_id(""));
        assert!(!valid_cluster_record_id("."));
        assert!(!valid_cluster_record_id(".."));
        assert!(!valid_cluster_record_id("a/b"));

        assert!(valid_cluster_prefix_pattern("nodes/*"));
        assert!(valid_cluster_prefix_pattern("nodes/"));
        assert!(valid_cluster_prefix_pattern("nodes/n1"));
        assert!(!valid_cluster_prefix_pattern(""));
        assert!(!valid_cluster_prefix_pattern("/nodes/*"));
        assert!(!valid_cluster_prefix_pattern("*"));
        assert!(!valid_cluster_prefix_pattern("nodes/../x"));
        assert!(!valid_cluster_prefix_pattern("nodes//a"));

        assert!(cluster_prefix_matches("nodes/*", "nodes/n1"));
        assert!(cluster_prefix_matches("nodes/", "nodes/n1"));
        assert!(!cluster_prefix_matches("nodes/*", "nodes"));
        assert!(!cluster_prefix_matches("nodes/*", "nodes2/n1"));
        assert!(cluster_prefix_matches("nodes/n1", "nodes/n1"));
        assert!(!cluster_prefix_matches("nodes/n1", "nodes/n1/sub"));

        assert!(cluster_prefix_covers("a/*", "a/b/*"));
        assert!(cluster_prefix_covers("a/*", "a/b/c"));
        assert!(cluster_prefix_covers("a/*", "a/"));
        assert!(cluster_prefix_covers("a/", "a/*"));
        assert!(!cluster_prefix_covers("a/b/*", "a/*"));
        assert!(!cluster_prefix_covers("a/b", "a/b/*"));

        let full = RemoteScope::full();
        assert!(full.cluster_compact);
        assert!(full.has_cluster());
        assert!(!full.is_empty());

        // Prefix restriction drops cluster_compact automatically.
        let prefixed = RemoteScope {
            cluster_read: true,
            cluster_write: true,
            cluster_watch: true,
            cluster_lease: true,
            cluster_compact: true,
            cluster_prefixes: vec!["workloads/*".into()],
            ..Default::default()
        };
        let n1 = full.attenuate(&prefixed);
        assert!(n1.cluster_read && n1.cluster_write && n1.cluster_watch && n1.cluster_lease);
        assert!(!n1.cluster_compact);
        assert_eq!(n1.cluster_prefixes, vec!["workloads/*"]);
        assert_eq!(n1.attenuate(&full), n1);

        // Node binding narrows monotonically and drops cluster_compact.
        let node1 = RemoteScope {
            cluster_read: true,
            cluster_write: true,
            cluster_lease: true,
            cluster_compact: true,
            cluster_node_id: Some("node-1".into()),
            ..Default::default()
        };
        let bound = full.attenuate(&node1);
        assert!(bound.cluster_read && bound.cluster_write && bound.cluster_lease);
        assert!(!bound.cluster_compact);
        assert_eq!(bound.cluster_node_id.as_deref(), Some("node-1"));
        assert_eq!(bound.attenuate(&full), bound);

        // Conflicting node IDs collapse all cluster capabilities and clear node_id.
        let node2 = RemoteScope {
            cluster_read: true,
            cluster_write: true,
            cluster_lease: true,
            cluster_node_id: Some("node-2".into()),
            ..Default::default()
        };
        let conflict = bound.attenuate(&node2);
        assert!(!conflict.has_cluster());
        assert!(conflict.cluster_node_id.is_none());
        assert!(conflict.cluster_prefixes.is_empty());
        assert!(!conflict.attenuate(&full).has_cluster());

        // Disjoint prefixes collapse all cluster capabilities and clear prefixes.
        let other_prefix = RemoteScope {
            cluster_read: true,
            cluster_write: true,
            cluster_prefixes: vec!["nodes/*".into()],
            ..Default::default()
        };
        let disjoint = n1.attenuate(&other_prefix);
        assert!(!disjoint.has_cluster());
        assert!(disjoint.cluster_prefixes.is_empty());
        assert!(!disjoint.attenuate(&full).has_cluster());

        // Invalid requested node_id or prefix fails closed.
        let bad_node = RemoteScope {
            cluster_read: true,
            cluster_node_id: Some("../evil".into()),
            ..Default::default()
        };
        assert!(!full.attenuate(&bad_node).has_cluster());
        let bad_prefix = RemoteScope {
            cluster_read: true,
            cluster_prefixes: vec!["/t/u0/secret".into()],
            ..Default::default()
        };
        assert!(!full.attenuate(&bad_prefix).has_cluster());

        // Mixed [valid, invalid] or > CLUSTER_MAX_PREFIX_GRANTS prefixes fail closed (never revive).
        let mixed_parent = RemoteScope {
            cluster_read: true,
            cluster_write: true,
            cluster_prefixes: vec!["workloads/*".into(), "/t/u0/evil".into()],
            ..Default::default()
        };
        assert!(!mixed_parent.attenuate(&full).has_cluster());
        assert!(!full.attenuate(&mixed_parent).has_cluster());

        let oversized = RemoteScope {
            cluster_read: true,
            cluster_prefixes: (0..=crate::cluster_state::CLUSTER_MAX_PREFIX_GRANTS)
                .map(|i| format!("p{i}/*"))
                .collect(),
            ..Default::default()
        };
        assert!(!oversized.attenuate(&full).has_cluster());
        assert!(!full.attenuate(&oversized).has_cluster());

        // Intersection whose result would exceed CLUSTER_MAX_PREFIX_GRANTS also fails closed.
        let mut p_many = vec!["a/*".to_string()];
        p_many.extend((0..20).map(|i| format!("b/k{i}")));
        let mut r_many = vec!["b/*".to_string()];
        r_many.extend((0..20).map(|i| format!("a/k{i}")));
        let parent_many = RemoteScope {
            cluster_read: true,
            cluster_prefixes: p_many,
            ..Default::default()
        };
        let req_many = RemoteScope {
            cluster_read: true,
            cluster_prefixes: r_many,
            ..Default::default()
        };
        let overflow_inter = parent_many.attenuate(&req_many);
        assert!(!overflow_inter.has_cluster());
        assert!(overflow_inter.cluster_prefixes.is_empty());

        // Legacy JSON without cluster_* fields defaults all cluster booleans to false.
        let legacy: RemoteScope = serde_json::from_str(r#"{"cloud_fs":true}"#).unwrap();
        assert!(!legacy.has_cluster());
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

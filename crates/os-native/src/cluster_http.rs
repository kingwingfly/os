//! Control-plane HTTP & WebSocket clients for `os-native` kubelet:
//! - `NativeServiceAuthClient` (`/api/service-auth` bootstrap exchange, renew, derive, revoke)
//! - `HttpClusterClient` (`impl ClusterStore` over `/api/cluster/rpc` + `/api/cluster/watch` WS)
//! - `NativeOciTransport` (`impl os_cowfs::OciTransport` over `/v2/*`)
//! - `NativeVolumeTransport` (`impl os_cowfs::RemoteVolumeTransport` over `/api/volumes/*`)

use crate::http_client::{HttpClient, ParsedHttpUrl, WsClientConn};
use abi::Errno;
use abi::auth_v2::{
    BootstrapTokenIssued, DeriveServiceCred, DetachInstance, ExchangeBootstrapToken,
    MintBootstrapToken, NodeCredIssued, RemoteScope, RenewInstance, RenewResult,
    Request as AuthRequest, Response as AuthResponse, RevokeNode, RevokeTokens, ServiceCredIssued,
};
use abi::cluster_state::{
    CLUSTER_STATE_PROTOCOL, ClusterCall, ClusterError, ClusterReply, ClusterRpcRequest, RangeEnd,
    WatchClientFrame, WatchServerFrame,
};
use abi::contract::InstanceIdentity;
use os_cluster_state::{
    BoxFuture as ClusterBoxFuture, ClusterGrant, ClusterStore, WatchBatch, WatchCursor,
};
use os_cowfs::{OciHttpReply, OciTransport, RemoteHttpReply, RemoteVolumeTransport};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Persisted node enrollment state stored at `$STATE/kubelet/enrollment.json` (`0600`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeEnrollment {
    pub base_url: String,
    pub cluster: String,
    pub node_id: String,
    pub tenant: String,
    pub enrollment_id: String,
    pub ns: String,
    pub instance_id: String,
    pub host_proof: String,
    pub token: String,
    pub scope: RemoteScope,
    pub lease_seconds: u64,
    pub expires: u64,
}

impl NodeEnrollment {
    pub fn load(path: &Path) -> Result<Self, String> {
        let raw =
            std::fs::read(path).map_err(|e| format!("read enrollment {}: {e}", path.display()))?;
        serde_json::from_slice(&raw)
            .map_err(|e| format!("parse enrollment {}: {e}", path.display()))
    }

    pub fn save_0600(&self, path: &Path) -> Result<(), String> {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create dir {}: {e}", parent.display()))?;
        }
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("create {}: {e}", tmp.display()))?;
        f.write_all(&bytes)
            .map_err(|e| format!("write {}: {e}", tmp.display()))?;
        let _ = f.sync_all();
        drop(f);
        std::fs::rename(&tmp, path)
            .map_err(|e| format!("rename {} -> {}: {e}", tmp.display(), path.display()))?;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        Ok(())
    }
}

/// Client for `/api/service-auth` (`ServiceAuth v2` including Phase 9.1b worker-node enrollment).
#[derive(Clone, Debug)]
pub struct NativeServiceAuthClient {
    http: HttpClient,
    pub base_url: String,
}

impl NativeServiceAuthClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            http: HttpClient::default(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
        }
    }

    async fn post_auth(
        &self,
        req: &AuthRequest,
        extra_headers: &[(String, String)],
    ) -> Result<AuthResponse, String> {
        let url = format!("{}/api/service-auth", self.base_url);
        let body = serde_json::to_vec(req).map_err(|e| e.to_string())?;
        let mut hdrs = vec![("Content-Type".into(), "application/json".into())];
        hdrs.extend(extra_headers.iter().cloned());
        let resp = self.http.request("POST", &url, &hdrs, &body).await?;
        if !(200..300).contains(&resp.status) {
            let txt = String::from_utf8_lossy(&resp.body);
            return Err(format!("service-auth HTTP {}: {txt}", resp.status));
        }
        serde_json::from_slice::<AuthResponse>(&resp.body)
            .map_err(|e| format!("parse service-auth reply: {e}"))
    }

    /// Exchange a single-use `osbt_*` bootstrap token for a durable `node.<enrollment_id>` credential.
    pub async fn exchange_bootstrap(
        &self,
        bootstrap_token: &str,
        instance_id: &str,
        host_proof: &str,
    ) -> Result<NodeCredIssued, String> {
        let req = AuthRequest::ExchangeBootstrapToken(ExchangeBootstrapToken {
            bootstrap_token: bootstrap_token.to_string(),
            instance: InstanceIdentity {
                instance: instance_id.to_string(),
                host: "os-native".to_string(),
            },
            host_proof: host_proof.to_string(),
        });
        match self.post_auth(&req, &[]).await? {
            AuthResponse::NodeEnrolled(issued) => Ok(issued),
            other => Err(format!("unexpected exchange-bootstrap reply: {other:?}")),
        }
    }

    /// Renew an enrolled node's `Machine` instance lease (`X-OS-Node-Enrollment` routing).
    pub async fn renew_node_instance(
        &self,
        enroll: &NodeEnrollment,
    ) -> Result<RenewResult, String> {
        let req = AuthRequest::RenewInstance(RenewInstance {
            instance_id: enroll.instance_id.clone(),
            host_proof: enroll.host_proof.clone(),
            active_tokens: vec![enroll.token.clone()],
        });
        let hdrs = vec![("X-OS-Node-Enrollment".into(), enroll.enrollment_id.clone())];
        match self.post_auth(&req, &hdrs).await? {
            AuthResponse::Renewed(r) => Ok(r),
            other => Err(format!("unexpected renew-instance reply: {other:?}")),
        }
    }

    /// Derive a strictly attenuated per-attempt storage credential (OCI pull/push + RO remote volume
    /// ONLY; ALL cluster permissions and cloud_fs stripped!).
    pub async fn derive_attempt_storage_cred(
        &self,
        enroll: &NodeEnrollment,
        _workload_id: &str,
        _ttl_secs: u64,
    ) -> Result<ServiceCredIssued, String> {
        let scope = RemoteScope {
            cloud_fs: false,
            devices: Vec::new(),
            containers: false,
            relay: false,
            volumes: true,
            volume_ids: enroll.scope.volume_ids.clone(),
            volumes_ro: true,
            registry_pull: true,
            registry_push: true,
            registry_repos: enroll.scope.registry_repos.clone(),
            cluster_read: false,
            cluster_write: false,
            cluster_watch: false,
            cluster_lease: false,
            cluster_compact: false,
            cluster_prefixes: Vec::new(),
            cluster_node_id: None,
        };
        let req = AuthRequest::DeriveServiceCred(DeriveServiceCred {
            instance_id: enroll.instance_id.clone(),
            host_proof: enroll.host_proof.clone(),
            parent_token: enroll.token.clone(),
            scope,
            cloud_access: false,
            umask: None,
            cgroup: Some("/services/kubelet".into()),
            revoke_parent: false,
            rbps: None,
            wbps: None,
        });
        let hdrs = vec![("X-OS-Node-Enrollment".into(), enroll.enrollment_id.clone())];
        match self.post_auth(&req, &hdrs).await? {
            AuthResponse::Cred(issued) => Ok(issued),
            other => Err(format!("unexpected derive-service-cred reply: {other:?}")),
        }
    }

    /// Revoke derived storage token(s) immediately after an attempt completes or aborts.
    pub async fn revoke_tokens(
        &self,
        enroll: &NodeEnrollment,
        tokens: Vec<String>,
    ) -> Result<usize, String> {
        if tokens.is_empty() {
            return Ok(0);
        }
        let req = AuthRequest::RevokeTokens(RevokeTokens {
            instance_id: enroll.instance_id.clone(),
            host_proof: enroll.host_proof.clone(),
            tokens,
        });
        let hdrs = vec![("X-OS-Node-Enrollment".into(), enroll.enrollment_id.clone())];
        match self.post_auth(&req, &hdrs).await? {
            AuthResponse::Revoked { count } => Ok(count),
            other => Err(format!("unexpected revoke-tokens reply: {other:?}")),
        }
    }

    /// Detach an enrolled node's `Machine` instance on clean shutdown.
    pub async fn detach_node_instance(&self, enroll: &NodeEnrollment) -> Result<(), String> {
        let req = AuthRequest::DetachInstance(DetachInstance {
            instance_id: enroll.instance_id.clone(),
            host_proof: enroll.host_proof.clone(),
        });
        let hdrs = vec![("X-OS-Node-Enrollment".into(), enroll.enrollment_id.clone())];
        let _ = self.post_auth(&req, &hdrs).await?;
        Ok(())
    }

    /// Mint a bootstrap token (requires an authenticated user session cookie + attached instance).
    #[allow(clippy::too_many_arguments)]
    pub async fn mint_bootstrap_token(
        &self,
        cookie: &str,
        instance_id: &str,
        host_proof: &str,
        node_id: &str,
        cluster: &str,
        ttl_secs: u64,
        scope: Option<RemoteScope>,
    ) -> Result<BootstrapTokenIssued, String> {
        let parsed = ParsedHttpUrl::parse(&self.base_url)?;
        let req = AuthRequest::MintBootstrapToken(MintBootstrapToken {
            instance_id: instance_id.to_string(),
            host_proof: host_proof.to_string(),
            node_id: node_id.to_string(),
            cluster: cluster.to_string(),
            ttl_secs,
            scope: scope.unwrap_or_else(|| RemoteScope::node_ceiling(node_id)),
            sudo: false,
        });
        let hdrs = vec![
            ("Cookie".into(), cookie.to_string()),
            ("Origin".into(), parsed.origin),
        ];
        match self.post_auth(&req, &hdrs).await? {
            AuthResponse::BootstrapToken(issued) => Ok(issued),
            other => Err(format!("unexpected mint-bootstrap reply: {other:?}")),
        }
    }

    /// Revoke an enrolled node's credentials & immediately sever its live watches/tokens.
    pub async fn revoke_node(
        &self,
        cookie: &str,
        instance_id: &str,
        host_proof: &str,
        node_id: &str,
        enrollment_id: Option<String>,
    ) -> Result<usize, String> {
        let parsed = ParsedHttpUrl::parse(&self.base_url)?;
        let req = AuthRequest::RevokeNode(RevokeNode {
            instance_id: instance_id.to_string(),
            host_proof: host_proof.to_string(),
            node_id: node_id.to_string(),
            enrollment_id,
        });
        let hdrs = vec![
            ("Cookie".into(), cookie.to_string()),
            ("Origin".into(), parsed.origin),
        ];
        match self.post_auth(&req, &hdrs).await? {
            AuthResponse::NodeRevoked { revoked } => Ok(revoked),
            other => Err(format!("unexpected revoke-node reply: {other:?}")),
        }
    }
}

/// HTTP + WebSocket `ClusterStore` client speaking `POST /api/cluster/rpc` and
/// `GET /api/cluster/watch` with cookie-less `X-Process-Token` + `X-OS-Instance`.
#[derive(Clone)]
pub struct HttpClusterClient {
    http: HttpClient,
    pub base_url: String,
    pub cluster: String,
    token: Arc<RwLock<String>>,
    pub instance_id: String,
}

impl HttpClusterClient {
    pub fn new(
        base_url: impl Into<String>,
        cluster: impl Into<String>,
        token: impl Into<String>,
        instance_id: impl Into<String>,
    ) -> Self {
        Self {
            http: HttpClient {
                timeout: Duration::from_secs(20),
                max_body_bytes: 8 * 1024 * 1024,
            },
            base_url: base_url.into().trim_end_matches('/').to_string(),
            cluster: cluster.into(),
            token: Arc::new(RwLock::new(token.into())),
            instance_id: instance_id.into(),
        }
    }

    pub fn from_enrollment(enroll: &NodeEnrollment) -> Self {
        Self::new(
            enroll.base_url.clone(),
            enroll.cluster.clone(),
            enroll.token.clone(),
            enroll.instance_id.clone(),
        )
    }

    pub fn set_token(&self, token: String) {
        *self.token.write().unwrap() = token;
    }

    pub fn current_token(&self) -> String {
        self.token.read().unwrap().clone()
    }

    fn auth_headers(&self) -> Vec<(String, String)> {
        vec![
            ("X-Process-Token".into(), self.current_token()),
            ("X-OS-Instance".into(), self.instance_id.clone()),
        ]
    }

    /// Open a live RFC-6455 WebSocket watch connection to `/api/cluster/watch`, complete the
    /// `Boundary::ClusterState` v1 `Hello` handshake, and subscribe to all given key prefixes.
    pub async fn connect_watch(
        &self,
        prefixes: &[(u64, String, u64)],
    ) -> Result<WsClientConn, String> {
        let ws_base = self
            .base_url
            .strip_prefix("http://")
            .map(|r| format!("ws://{r}"))
            .unwrap_or_else(|| self.base_url.clone());
        let url = format!("{ws_base}/api/cluster/watch?cluster={}", self.cluster);
        let hdrs = self.auth_headers();
        let mut ws = self.http.connect_ws(&url, &hdrs).await?;

        let hello = serde_json::to_string(&WatchClientFrame::Hello {
            versions: vec![CLUSTER_STATE_PROTOCOL],
        })
        .map_err(|e| e.to_string())?;
        ws.send_text(&hello).await?;

        let Some(first) = ws.recv_text().await? else {
            return Err("cluster watch closed before Welcome".into());
        };
        let frame: WatchServerFrame =
            serde_json::from_str(&first).map_err(|e| format!("parse watch Welcome: {e}"))?;
        match frame {
            WatchServerFrame::Welcome { .. } => {}
            WatchServerFrame::Error { error, .. } => {
                return Err(format!("cluster watch hello error: {error}"));
            }
            other => return Err(format!("unexpected cluster watch hello frame: {other:?}")),
        }

        for (watch_id, key, from_revision) in prefixes {
            let sub = serde_json::to_string(&WatchClientFrame::Subscribe {
                watch_id: *watch_id,
                key: key.clone(),
                range_end: RangeEnd::Prefix,
                from_revision: *from_revision,
                prev_kv: false,
            })
            .map_err(|e| e.to_string())?;
            ws.send_text(&sub).await?;
        }
        Ok(ws)
    }
}

impl ClusterStore for HttpClusterClient {
    fn rpc<'a>(
        &'a self,
        _grant: &'a ClusterGrant,
        call: ClusterCall,
        _now_secs: u64,
    ) -> ClusterBoxFuture<'a, Result<ClusterReply, ClusterError>> {
        Box::pin(async move {
            let url = format!("{}/api/cluster/rpc", self.base_url);
            let req = ClusterRpcRequest {
                version: CLUSTER_STATE_PROTOCOL,
                cluster: self.cluster.clone(),
                call,
            };
            let body = serde_json::to_vec(&req)
                .map_err(|e| ClusterError::because(Errno::EINVAL, e.to_string()))?;
            let mut hdrs = self.auth_headers();
            hdrs.push(("Content-Type".into(), "application/json".into()));

            let resp = self
                .http
                .request("POST", &url, &hdrs, &body)
                .await
                .map_err(|e| ClusterError::because(Errno::EIO, e))?;

            if (200..300).contains(&resp.status) {
                serde_json::from_slice::<ClusterReply>(&resp.body)
                    .map_err(|e| ClusterError::because(Errno::EIO, format!("parse reply: {e}")))
            } else {
                if let Ok(err) = serde_json::from_slice::<ClusterError>(&resp.body) {
                    return Err(err);
                }
                let errno = match resp.status {
                    401 | 403 => Errno::EACCES,
                    404 => Errno::ENOENT,
                    409 => Errno::EEXIST,
                    412 => Errno::ESTALE,
                    413 => Errno::EFBIG,
                    507 => Errno::EDQUOT,
                    _ => Errno::EIO,
                };
                let msg = String::from_utf8_lossy(&resp.body).into_owned();
                Err(ClusterError::because(errno, msg))
            }
        })
    }

    fn poll_watch<'a>(
        &'a self,
        _grant: &'a ClusterGrant,
        cursor: &'a mut WatchCursor,
        _limit: u32,
        _now_secs: u64,
    ) -> ClusterBoxFuture<'a, Result<WatchBatch, ClusterError>> {
        // Real-time watches over HTTP use `connect_watch` WebSocket; trait `poll_watch` returns an
        // empty batch at the cursor revision so callers fall back cleanly.
        let rev = cursor.next_revision;
        Box::pin(async move {
            Ok(WatchBatch {
                revision: rev,
                events: Vec::new(),
                compacted_floor: 0,
                more: false,
            })
        })
    }
}

/// Native `os_cowfs::OciTransport` backed by `HttpClient` + ServiceAuth v2 token headers.
#[derive(Clone, Debug)]
pub struct NativeOciTransport {
    http: HttpClient,
    pub base_url: String,
    token: String,
    instance_id: String,
}

impl NativeOciTransport {
    pub fn new(
        base_url: impl Into<String>,
        token: impl Into<String>,
        instance_id: impl Into<String>,
    ) -> Self {
        Self {
            http: HttpClient::default(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
            token: token.into(),
            instance_id: instance_id.into(),
        }
    }
}

impl OciTransport for NativeOciTransport {
    fn request<'a>(
        &'a self,
        method: &'a str,
        url: &'a str,
        headers: &'a [(String, String)],
        body: &'a [u8],
    ) -> vfs::BoxFuture<'a, OciHttpReply> {
        let full_url = HttpClient::resolve_url(&self.base_url, url);
        let method_s = method.to_string();
        let hdrs = headers.to_vec();
        let body_v = body.to_vec();
        Box::pin(async move {
            let resp = self
                .http
                .request(&method_s, &full_url, &hdrs, &body_v)
                .await
                .map_err(|_| Errno::EIO)?;
            Ok(OciHttpReply {
                status: resp.status,
                headers: resp.headers,
                body: resp.body,
            })
        })
    }

    fn token_auth_headers(&self) -> Vec<(String, String)> {
        vec![
            ("X-Process-Token".into(), self.token.clone()),
            ("X-OS-Instance".into(), self.instance_id.clone()),
        ]
    }
}

/// Native `os_cowfs::RemoteVolumeTransport` speaking cookie-less `X-Process-Token` +
/// `X-OS-Instance` to `/api/volumes/*`.
#[derive(Clone, Debug)]
pub struct NativeVolumeTransport {
    http: HttpClient,
    pub base_url: String,
    token: String,
    instance_id: String,
    started: Instant,
}

impl NativeVolumeTransport {
    pub fn new(
        base_url: impl Into<String>,
        token: impl Into<String>,
        instance_id: impl Into<String>,
    ) -> Self {
        Self {
            http: HttpClient::default(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
            token: token.into(),
            instance_id: instance_id.into(),
            started: Instant::now(),
        }
    }
}

impl RemoteVolumeTransport for NativeVolumeTransport {
    fn monotonic_seconds(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    fn fetch<'a>(
        &'a self,
        method: &'a str,
        path: &'a str,
        headers: &'a [(String, String)],
        body: &'a [u8],
    ) -> vfs::BoxFuture<'a, RemoteHttpReply> {
        let full_url = HttpClient::resolve_url(&self.base_url, path);
        let method_s = method.to_string();
        let mut hdrs = headers.to_vec();
        hdrs.push(("X-Process-Token".into(), self.token.clone()));
        hdrs.push(("X-OS-Instance".into(), self.instance_id.clone()));
        let body_v = body.to_vec();
        Box::pin(async move {
            let resp = self
                .http
                .request(&method_s, &full_url, &hdrs, &body_v)
                .await
                .map_err(|_| Errno::EIO)?;
            let content_length = resp
                .header("Content-Length")
                .and_then(|s| s.parse::<u64>().ok());
            Ok(RemoteHttpReply {
                status: resp.status,
                body: resp.body,
                content_length,
            })
        })
    }
}

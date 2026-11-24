//! OCI Distribution v1.1 wire types, validation helpers, `cowfs` snapshot artifact v1 config,
//! and `COWFS_IOC_OCI_*` ioctl payloads (`docs/architecture/contract.md` §2.15, §5, §6; #81).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// `Boundary::Registry` wire protocol version (`contract::REGISTRY_VERSION`).
pub const REGISTRY_PROTOCOL_VERSION: u32 = crate::contract::REGISTRY_VERSION;

/// Standard OCI Distribution v1.1 and Docker Registry v2 media types.
pub const OCI_IMAGE_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
pub const OCI_IMAGE_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";
pub const OCI_IMAGE_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";
pub const OCI_EMPTY_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.empty.v1+json";
pub const OCI_LAYER_TAR_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar";
pub const OCI_LAYER_TAR_GZIP_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
pub const DOCKER_MANIFEST_V2_MEDIA_TYPE: &str =
    "application/vnd.docker.distribution.manifest.v2+json";
pub const DOCKER_MANIFEST_LIST_V2_MEDIA_TYPE: &str =
    "application/vnd.docker.distribution.manifest.list.v2+json";
pub const DOCKER_CONFIG_V1_MEDIA_TYPE: &str = "application/vnd.docker.container.image.v1+json";
pub const DOCKER_LAYER_TAR_GZIP_MEDIA_TYPE: &str =
    "application/vnd.docker.image.rootfs.diff.tar.gzip";

/// `cowfs` Snapshot Artifact v1 media types over the shared immutable `COWP` pack store.
pub const COWFS_SNAPSHOT_ARTIFACT_TYPE: &str = "application/vnd.os.cowfs.snapshot.v1";
pub const COWFS_SNAPSHOT_SHARD_ARTIFACT_TYPE: &str = "application/vnd.os.cowfs.snapshot.shard.v1";
pub const COWFS_SNAPSHOT_CONFIG_MEDIA_TYPE: &str =
    "application/vnd.os.cowfs.snapshot.config.v1+json";
pub const COWFS_PACK_LAYER_MEDIA_TYPE: &str = "application/vnd.os.cowfs.pack.v1";
pub const COWFS_NODEPACK_LAYER_MEDIA_TYPE: &str = "application/vnd.os.cowfs.nodepack.v1";
pub const COWFS_BLOCKDIR_LAYER_MEDIA_TYPE: &str = "application/vnd.os.cowfs.blockdir.v1";

/// Detached Ed25519 signature referrer media / artifact type (`os_image::Detached`).
pub const OS_SIGNATURE_ARTIFACT_TYPE: &str = "application/vnd.os.signature.v1+json";

/// Canonical OCI empty config payload (`"{}"`) and its SHA-256 digest.
pub const OCI_EMPTY_JSON_BYTES: &[u8] = b"{}";
pub const OCI_EMPTY_JSON_DIGEST: &str =
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";

/// Registry hard bounds & timeouts.
pub const REGISTRY_MANIFEST_MAX_BYTES: usize = 4 * 1024 * 1024;
pub const REGISTRY_DEFAULT_MAX_BLOB_BYTES: u64 = 64 * 1024 * 1024;
pub const REGISTRY_UPLOAD_TTL_SECS: u64 = 1800;
pub const REGISTRY_TOKEN_TTL_SECS: u64 = 300;
pub const REGISTRY_TAGS_MAX_N: usize = 1000;
pub const REGISTRY_TAGS_DEFAULT_N: usize = 100;
pub const REGISTRY_MAX_REPO_LEN: usize = 255;

/// Validate an OCI Distribution v1.1 repository name:
/// `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*(\/[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*)*` (1..=255 bytes).
pub fn valid_repo_name(name: &str) -> bool {
    if name.is_empty() || name.len() > REGISTRY_MAX_REPO_LEN || !name.is_ascii() {
        return false;
    }
    name.split('/').all(valid_repo_segment)
}

fn valid_repo_segment(seg: &str) -> bool {
    let bytes = seg.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let is_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let mut i = 0usize;
    if !is_alnum(bytes[i]) {
        return false;
    }
    while i < bytes.len() && is_alnum(bytes[i]) {
        i += 1;
    }
    while i < bytes.len() {
        match bytes[i] {
            b'.' => i += 1,
            b'_' => {
                i += 1;
                if i < bytes.len() && bytes[i] == b'_' {
                    i += 1;
                }
            }
            b'-' => {
                while i < bytes.len() && bytes[i] == b'-' {
                    i += 1;
                }
            }
            _ => return false,
        }
        if i >= bytes.len() || !is_alnum(bytes[i]) {
            return false;
        }
        while i < bytes.len() && is_alnum(bytes[i]) {
            i += 1;
        }
    }
    true
}

/// Validate an OCI Distribution v1.1 tag: `[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}`.
pub fn valid_tag(tag: &str) -> bool {
    let bytes = tag.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 {
        return false;
    }
    let first = bytes[0];
    if !(first.is_ascii_alphanumeric() || first == b'_') {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Parse `"sha256:<64 lowercase hex>"`, returning the bare 64-char hex digest.
pub fn parse_sha256_digest(digest: &str) -> Option<&str> {
    let hex = digest.strip_prefix("sha256:")?;
    if hex.len() != 64 {
        return None;
    }
    hex.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        .then_some(hex)
}

/// Parsed OCI reference (`[oci:]<repo>@sha256:<hex>` or `[oci:]<repo>:<tag>`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciReference {
    pub repo: String,
    pub reference: String,
    pub is_digest: bool,
}

impl OciReference {
    /// Parse an OCI mount source or CLI reference (`oci:<repo>@sha256:<hex>`, `oci:<repo>:<tag>`,
    /// or bare `<repo>@sha256:<hex>` / `<repo>:<tag>`).
    pub fn parse(raw: &str) -> Option<Self> {
        let stripped = raw.strip_prefix("oci:").unwrap_or(raw).trim();
        if let Some((repo, digest)) = stripped.split_once('@') {
            if valid_repo_name(repo) && parse_sha256_digest(digest).is_some() {
                return Some(Self {
                    repo: repo.to_string(),
                    reference: digest.to_string(),
                    is_digest: true,
                });
            }
            return None;
        }
        if let Some((repo, tag)) = stripped.rsplit_once(':') {
            if valid_repo_name(repo) && valid_tag(tag) {
                return Some(Self {
                    repo: repo.to_string(),
                    reference: tag.to_string(),
                    is_digest: false,
                });
            }
            return None;
        }
        None
    }
}

/// OCI Content Descriptor (`application/vnd.oci.descriptor.v1+json`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciDescriptor {
    pub media_type: String,
    pub digest: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub urls: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<OciPlatform>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

/// OCI Platform descriptor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciPlatform {
    pub architecture: String,
    pub os: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
}

/// OCI Image Manifest v1 (`application/vnd.oci.image.manifest.v1+json`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciImageManifest {
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
    pub config: OciDescriptor,
    pub layers: Vec<OciDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<OciDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
}

impl OciImageManifest {
    /// Effective OCI 1.1 `artifactType`: `manifest.artifactType ?? manifest.config.mediaType`.
    pub fn effective_artifact_type(&self) -> Option<&str> {
        self.artifact_type
            .as_deref()
            .filter(|s| !s.is_empty())
            .or_else(|| {
                (!self.config.media_type.is_empty()).then_some(self.config.media_type.as_str())
            })
    }
}

/// OCI Image Index v1 (`application/vnd.oci.image.index.v1+json`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciImageIndex {
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
    pub manifests: Vec<OciDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<OciDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
}

/// OCI Image Configuration (`application/vnd.oci.image.config.v1+json`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciImageConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    pub architecture: String,
    pub os: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<OciRuntimeConfig>,
    pub rootfs: OciRootFs,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct OciRuntimeConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmd: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciRootFs {
    #[serde(rename = "type")]
    pub kind: String,
    pub diff_ids: Vec<String>,
}

/// Standard OCI Distribution v1.1 error envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciErrorEntry {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciErrorBody {
    pub errors: Vec<OciErrorEntry>,
}

/// `GET /v2/<name>/tags/list` response body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciTagsList {
    pub name: String,
    pub tags: Vec<String>,
}

/// Repository access claim inside a short-lived registry Bearer JWT.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciAccessEntry {
    #[serde(rename = "type")]
    pub kind: String,
    pub name: String,
    pub actions: Vec<String>,
}

/// `GET /v2/token` JSON response body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciTokenResponse {
    pub token: String,
    pub access_token: String,
    pub expires_in: u64,
    pub issued_at: String,
}

/// Config blob JSON for `cowfs` snapshot artifacts (`application/vnd.os.cowfs.snapshot.config.v1+json`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CowfsSnapshotConfig {
    pub format: String,
    pub version: u32,
    pub cowfs_format_version: u32,
    pub volume_uuid: String,
    pub root_digest: String,
    pub subvols: BTreeMap<String, String>,
    pub shard_index: u32,
    pub shard_count: u32,
    pub node_count: u64,
    pub pack_count: u64,
    pub total_bytes: u64,
}

/// Payload for `COWFS_IOC_OCI_PUSH`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CowfsOciPushReq {
    /// OCI reference (`<repo>:<tag>` or `<repo>@sha256:<hex>`).
    pub reference: String,
    /// Optional snapshot name (default: current committed head).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<String>,
    /// When `true`, export and push as a standard runnable OCI tar+gzip image instead of a native
    /// `cowfs` snapshot artifact.
    #[serde(default)]
    pub tar: bool,
    /// Optional max layers per shard for native `cowfs` snapshot artifacts (default 128).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_layers_per_shard: Option<usize>,
}

/// Response for `COWFS_IOC_OCI_PUSH`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CowfsOciPushResp {
    pub repo: String,
    pub reference: String,
    pub manifest_digest: String,
    pub media_type: String,
    pub shards: u32,
    pub packs_pushed: u64,
    pub bytes_pushed: u64,
}

/// Payload for `COWFS_IOC_OCI_PULL`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CowfsOciPullReq {
    /// OCI reference (`<repo>:<tag>` or `<repo>@sha256:<hex>`).
    pub reference: String,
    /// Optional target snapshot name to create atomically on completion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_name: Option<String>,
    /// Optional target volume UUID (default: the device's volume).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_volume: Option<String>,
    /// Optional raw JSON of `os_image::Trust` requiring a verified Ed25519 referrer signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_json: Option<String>,
}

/// Response for `COWFS_IOC_OCI_PULL`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CowfsOciPullResp {
    pub volume: String,
    pub root: String,
    pub epoch: u64,
    pub manifest_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_key: Option<String>,
    pub packs_pulled: u64,
    pub nodes_pulled: u64,
}

/// Payload for `COWFS_IOC_OCI_IMPORT` (stream a tar or tar+gzip layer from `stream_fd`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CowfsOciImportReq {
    pub stream_fd: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_volume: Option<String>,
    #[serde(default)]
    pub strip_setuid: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_diff_id: Option<String>,
}

/// Response for `COWFS_IOC_OCI_IMPORT`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CowfsOciImportResp {
    pub volume: String,
    pub root: String,
    pub epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<String>,
    pub diff_id: String,
    pub entries_imported: u64,
    pub uncompressed_bytes: u64,
}

/// Payload for `COWFS_IOC_OCI_EXPORT` (stream reproducible OCI tar/tar+gzip layer to `stream_fd`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CowfsOciExportReq {
    pub stream_fd: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<String>,
    #[serde(default)]
    pub uncompressed: bool,
}

/// Response for `COWFS_IOC_OCI_EXPORT`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CowfsOciExportResp {
    pub volume: String,
    pub root: String,
    pub media_type: String,
    pub diff_id: String,
    pub blob_digest: String,
    pub blob_size: u64,
    pub uncompressed_size: u64,
    pub entries_exported: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256::sha256_hex;

    #[test]
    fn empty_json_digest_matches_sha256() {
        assert_eq!(
            format!("sha256:{}", sha256_hex(OCI_EMPTY_JSON_BYTES)),
            OCI_EMPTY_JSON_DIGEST
        );
    }

    #[test]
    fn repo_name_and_tag_validation_follow_oci_spec() {
        for ok in [
            "app",
            "team/app",
            "org/sub.team/my_app__v1---rc1",
            "a/b/c/d",
            "0/1",
        ] {
            assert!(valid_repo_name(ok), "expected valid repo: {ok}");
        }
        for bad in [
            "",
            "/app",
            "app/",
            "team//app",
            "Team/app",
            "team/..app",
            "team/.app",
            "team/app.",
            "team/app___1",
            "team/app_",
            "team/-app",
            "team/app-",
            "team/app:tag",
            "team/*",
            &"a".repeat(256),
        ] {
            assert!(!valid_repo_name(bad), "expected invalid repo: {bad}");
        }

        for ok in ["latest", "v1.2.3-rc_1", "_internal", "0", &"a".repeat(128)] {
            assert!(valid_tag(ok), "expected valid tag: {ok}");
        }
        for bad in ["", ".hidden", "-dash", "a/b", "a:b", &"a".repeat(129)] {
            assert!(!valid_tag(bad), "expected invalid tag: {bad}");
        }
    }

    #[test]
    fn oci_reference_parsing_handles_tags_and_digests() {
        let d = format!("sha256:{}", "a".repeat(64));
        let r1 = OciReference::parse(&format!("oci:team/app@{d}")).unwrap();
        assert_eq!(r1.repo, "team/app");
        assert_eq!(r1.reference, d);
        assert!(r1.is_digest);

        let r2 = OciReference::parse("team/app:v1.0").unwrap();
        assert_eq!(r2.repo, "team/app");
        assert_eq!(r2.reference, "v1.0");
        assert!(!r2.is_digest);

        assert!(OciReference::parse("team/app").is_none());
        assert!(OciReference::parse("BadRepo:v1").is_none());
        assert!(OciReference::parse("team/app@sha256:short").is_none());
    }

    #[test]
    fn ioctl_payloads_deny_unknown_fields() {
        assert!(
            serde_json::from_str::<CowfsOciPushReq>(r#"{"reference":"a/b:v1","extra":1}"#).is_err()
        );
        assert!(
            serde_json::from_str::<CowfsOciPullReq>(r#"{"reference":"a/b:v1","extra":1}"#).is_err()
        );
        assert!(serde_json::from_str::<CowfsOciImportReq>(r#"{"stream_fd":0,"extra":1}"#).is_err());
        assert!(serde_json::from_str::<CowfsOciExportReq>(r#"{"stream_fd":1,"extra":1}"#).is_err());
    }
}

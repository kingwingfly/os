//! Exact-byte image verification shared by build tools and the runtime.
//! A verified publisher is not an authorization to mount or execute anything.
mod composition;
mod strict;
pub use composition::Composition;
pub use strict::parse;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const MANIFEST_MAX: usize = 4 * 1024 * 1024;
pub const ENTRIES_MAX: usize = 16_384;
pub const ABI: u32 = 1;
/// Matches `abi::contract::RELEASE_VERSION` (Release v2, Contract v2 #76/#78).
pub const PROTOCOL: u32 = 2;
pub const IMAGE_VERSION: u32 = 2;
pub const RELEASE_VERSION: u32 = 2;
/// Matches `abi::contract::HOST_ADAPTER_VERSION` (HostAdapter v2, Contract v2).
pub const HOST_ADAPTER: u32 = 2;
/// `OsAuthority` schema version (kept at 10 during parallel L2.5b).
pub const SCHEMA: u32 = 10;
pub const LEVEL: u32 = 1;
pub const CHUNK_SIZE_MIN: u32 = 64 * 1024;
pub const CHUNK_SIZE_DEFAULT: u32 = 256 * 1024;
pub const CHUNK_SIZE_MAX: u32 = 1024 * 1024;
pub const MAX_CONCURRENT_CHUNK_FETCHES: usize = 4;
pub const SIGNING_DOMAIN_IMAGE_V2: &str = "os.image.v2";
pub const SIGNING_DOMAIN_RELEASE_V2: &str = "os.release.v2";
pub const SIGNING_DOMAIN_OCI_ARTIFACT_V1: &str = "os.oci.artifact.v1";
pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
pub const FEATURES: &[&str] = &["wasi-preview1", "os-abi-1", "wasix-fork-v4"];
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}
impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self(value.to_string())
    }
}
pub(crate) fn require(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error(message.into()))
    }
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn digest(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
pub fn unhex<const N: usize>(s: &str) -> Result<[u8; N]> {
    require(
        s.len() == N * 2
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid lowercase hexadecimal value",
    )?;
    let mut out = [0; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| Error("invalid hex".into()))?;
    }
    Ok(out)
}
pub fn valid_chunk_size(chunk_size: u32) -> bool {
    (CHUNK_SIZE_MIN..=CHUNK_SIZE_MAX).contains(&chunk_size) && chunk_size.is_power_of_two()
}
pub fn expected_chunk_count(size: u64, chunk_size: u32) -> Result<usize> {
    require(
        valid_chunk_size(chunk_size),
        "invalid chunk size (must be power of two in 64 KiB..=1 MiB)",
    )?;
    if size == 0 {
        return Ok(0);
    }
    let count = size.div_ceil(u64::from(chunk_size));
    usize::try_from(count).map_err(|_| Error("chunk count overflow".into()))
}
pub fn chunk_digests(bytes: &[u8], chunk_size: u32) -> Result<Vec<String>> {
    require(
        valid_chunk_size(chunk_size),
        "invalid chunk size (must be power of two in 64 KiB..=1 MiB)",
    )?;
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    Ok(bytes.chunks(chunk_size as usize).map(digest).collect())
}
/// Stream-verifies a content reader against its declared whole-file SHA-256, exact size,
/// chunk size, and every ordered chunk SHA-256 digest using bounded 64 KiB buffering.
pub fn verify_reader_chunks<R: std::io::Read>(
    mut reader: R,
    expected_sha256: &str,
    expected_size: u64,
    chunk_size: u32,
    expected_chunks: &[String],
) -> Result<()> {
    let expected_count = expected_chunk_count(expected_size, chunk_size)?;
    require(
        expected_chunks.len() == expected_count,
        "chunk digest count mismatch",
    )?;
    unhex::<32>(expected_sha256)?;
    for c in expected_chunks {
        unhex::<32>(c)?;
    }
    let cs = chunk_size as usize;
    let mut whole_hash = Sha256::new();
    let mut chunk_hash = Sha256::new();
    let mut chunk_filled = 0usize;
    let mut chunk_index = 0usize;
    let mut total_len = 0u64;
    let mut buf = [0u8; 65_536];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| Error(format!("content read error: {e}")))?;
        if n == 0 {
            break;
        }
        total_len = total_len
            .checked_add(n as u64)
            .ok_or_else(|| Error("content length overflow".into()))?;
        require(total_len <= expected_size, "content length mismatch")?;
        whole_hash.update(&buf[..n]);
        let mut slice = &buf[..n];
        while !slice.is_empty() {
            let take = slice.len().min(cs - chunk_filled);
            chunk_hash.update(&slice[..take]);
            chunk_filled += take;
            slice = &slice[take..];
            if chunk_filled == cs {
                let expected = expected_chunks
                    .get(chunk_index)
                    .ok_or_else(|| Error("chunk index out of range".into()))?;
                require(
                    hex(&chunk_hash.finalize_reset()) == *expected,
                    "chunk digest mismatch",
                )?;
                chunk_filled = 0;
                chunk_index += 1;
            }
        }
    }
    if chunk_filled > 0 {
        let expected = expected_chunks
            .get(chunk_index)
            .ok_or_else(|| Error("chunk index out of range".into()))?;
        require(
            hex(&chunk_hash.finalize()) == *expected,
            "chunk digest mismatch",
        )?;
        chunk_index += 1;
    }
    require(
        total_len == expected_size
            && chunk_index == expected_chunks.len()
            && hex(&whole_hash.finalize()) == expected_sha256,
        "content digest or length mismatch",
    )?;
    Ok(())
}
pub fn valid_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 4096
        && !path.contains('\0')
        && (path == "/"
            || path[1..]
                .split('/')
                .all(|p| !p.is_empty() && p != "." && p != ".." && p.len() <= 255))
}
pub fn below(path: &str, root: &str) -> bool {
    path == root || path.strip_prefix(root).is_some_and(|s| s.starts_with('/'))
}
pub fn parent(path: &str) -> &str {
    path.rsplit_once('/')
        .map_or("/", |(p, _)| if p.is_empty() { "/" } else { p })
}
pub fn protected(path: &str) -> bool {
    [
        "/etc/passwd",
        "/etc/group",
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/sudoers",
        "/etc/sudoers.d",
        "/etc/os-trust",
    ]
    .iter()
    .any(|p| below(path, p))
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Boot,
    Initramfs,
    RootTemplate,
    Base,
    Sysext,
    Confext,
    Workload,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub path: String,
    pub uid: u32,
    pub gid: u32,
    pub mode: u16,
    pub node: Node,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum Node {
    Directory,
    File {
        sha256: String,
        size: u64,
        /// Power-of-two chunk size in `[64 KiB, 1 MiB]` (default `256 KiB`).
        chunk_size: u32,
        /// Ordered lowercase hex SHA-256 of each chunk (`ceil(size / chunk_size)` entries; empty iff `size == 0`).
        /// Enables streaming range verification of any slice without buffering the whole blob.
        chunks: Vec<String>,
    },
    Symlink {
        target: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Image {
    pub format: String,
    pub version: u32,
    pub kind: Kind,
    pub name: String,
    pub revision: String,
    pub abi: u32,
    pub features: Vec<String>,
    pub level: u32,
    pub provenance: BTreeMap<String, String>,
    pub entries: Vec<Entry>,
}
impl Image {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let image: Self = parse(bytes)?;
        image.validate()?;
        Ok(image)
    }
    pub fn validate(&self) -> Result<()> {
        self.validate_shallow()?;
        if matches!(self.kind, Kind::Initramfs | Kind::RootTemplate) {
            Composition::standalone(self)?;
        }
        Ok(())
    }
    pub(crate) fn validate_shallow(&self) -> Result<()> {
        require(
            self.format == "os.image" && self.version == IMAGE_VERSION,
            "unsupported image format/version",
        )?;
        require(
            self.abi == ABI && self.level == LEVEL,
            "incompatible image ABI/level",
        )?;
        bounded(&self.name, 128)?;
        bounded(&self.revision, 128)?;
        provenance(&self.provenance)?;
        let mut features = BTreeSet::new();
        for feature in &self.features {
            require(
                FEATURES.contains(&feature.as_str()) && features.insert(feature),
                "unknown/duplicate required feature",
            )?;
        }
        require(self.entries.len() <= ENTRIES_MAX, "too many image entries")?;
        let mut previous = None;
        let mut total = 0u64;
        for entry in &self.entries {
            require(valid_path(&entry.path), "invalid image path")?;
            require(
                previous.is_none_or(|p: &str| p < entry.path.as_str()),
                "entries must be sorted and unique",
            )?;
            previous = Some(entry.path.as_str());
            require(
                entry.mode <= 0o1777,
                "unsupported permission bits (set-ID images are not supported)",
            )?;
            require(
                self.allows(&entry.path, matches!(entry.node, Node::Directory)),
                "entry outside image roots or protected identity path",
            )?;
            match &entry.node {
                Node::Directory => {}
                Node::File {
                    sha256,
                    size,
                    chunk_size,
                    chunks,
                } => {
                    unhex::<32>(sha256)?;
                    require(*size <= i64::MAX as u64, "file too large")?;
                    let expected = expected_chunk_count(*size, *chunk_size)?;
                    require(chunks.len() == expected, "chunk digest count mismatch")?;
                    for chunk in chunks {
                        unhex::<32>(chunk)?;
                    }
                    if *size == 0 {
                        require(
                            sha256 == EMPTY_SHA256 && chunks.is_empty(),
                            "empty file digest/chunks mismatch",
                        )?;
                    } else if chunks.len() == 1 {
                        require(
                            chunks[0] == *sha256,
                            "single-chunk digest must match file sha256",
                        )?;
                    }
                    total = total
                        .checked_add(*size)
                        .ok_or_else(|| Error("image size overflow".into()))?;
                }
                Node::Symlink { target } => {
                    bounded(target, 4096)?;
                }
            }
        }
        Ok(())
    }
    pub fn allows(&self, path: &str, directory: bool) -> bool {
        if path == "/" {
            return directory;
        }
        match self.kind {
            Kind::Boot => !below(path, "/boot") && !below(path, "/api"),
            Kind::Initramfs => {
                path == "/init"
                    || below(path, "/bin")
                    || below(path, "/sbin")
                    || below(path, "/lib")
                    || below(path, "/lib64")
                    || below(path, "/usr")
                    || (below(path, "/etc") && !protected(path))
                    || (directory
                        && matches!(path, "/dev" | "/proc" | "/run" | "/sysroot" | "/tmp"))
            }
            Kind::RootTemplate => {
                !below(path, "/etc/os-trust")
                    && (below(path, "/etc")
                        || below(path, "/var")
                        || below(path, "/root")
                        || below(path, "/home")
                        || (directory
                            && matches!(
                                path,
                                "/boot"
                                    | "/dev"
                                    | "/dev/pts"
                                    | "/mnt"
                                    | "/mnt/cloud"
                                    | "/mnt/local"
                                    | "/mnt/shared"
                                    | "/opt"
                                    | "/opt/private"
                                    | "/proc"
                                    | "/run"
                                    | "/srv"
                                    | "/sys"
                                    | "/tmp"
                                    | "/usr"
                            )))
            }
            Kind::Base => {
                below(path, "/usr")
                    || below(path, "/sys")
                    || matches!(path, "/bin" | "/sbin" | "/lib" | "/lib64")
                    || (directory && matches!(path, "/opt" | "/etc"))
            }
            Kind::Sysext => below(path, "/usr") || below(path, "/opt"),
            Kind::Confext => below(path, "/etc") && !protected(path),
            Kind::Workload => below(path, "/workload"),
        }
    }
    /// Stream-verifies every regular file in the image against its whole-file SHA-256, exact size,
    /// and every per-chunk SHA-256 digest in `entry.chunks`.
    pub fn verify_content<R: std::io::Read>(
        &self,
        mut open: impl FnMut(&str) -> Result<R>,
    ) -> Result<()> {
        for entry in &self.entries {
            if let Node::File {
                sha256,
                size,
                chunk_size,
                chunks,
            } = &entry.node
            {
                let reader = open(sha256)?;
                verify_reader_chunks(reader, sha256, *size, *chunk_size, chunks)?;
            }
        }
        Ok(())
    }
}
fn bounded(s: &str, max: usize) -> Result<()> {
    require(
        !s.is_empty() && s.len() <= max && !s.contains('\0'),
        "empty/oversized/NUL string",
    )
}
fn provenance(p: &BTreeMap<String, String>) -> Result<()> {
    require(p.len() <= 32, "too many provenance fields")?;
    for (k, v) in p {
        bounded(k, 128)?;
        bounded(v, 4096)?;
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Range {
    pub min: u32,
    pub max: u32,
}
impl Range {
    pub fn contains(&self, value: u32) -> bool {
        self.min <= value && value <= self.max
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LoaderMeta {
    pub entry: String,
    pub client_kernel_js: String,
    pub client_kernel_wasm: String,
    pub client_kernel_sha256: String,
    pub host_adapter: Range,
}
impl LoaderMeta {
    pub fn validate(&self) -> Result<()> {
        for path in [
            &self.entry,
            &self.client_kernel_js,
            &self.client_kernel_wasm,
        ] {
            require(
                valid_path(path) && path != "/" && !below(path, "/boot") && !below(path, "/api"),
                "invalid loader asset path",
            )?;
        }
        unhex::<32>(&self.client_kernel_sha256)?;
        require(
            self.host_adapter.contains(HOST_ADAPTER),
            "incompatible host adapter version range",
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseV2 {
    pub format: String,
    pub version: u32,
    pub name: String,
    pub loader: LoaderMeta,
    pub boot: String,
    pub initramfs: String,
    pub root_template: String,
    pub base: String,
    pub sysext: Vec<String>,
    pub confext: Vec<String>,
    pub protocol: Range,
    pub schema: Range,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_seq: Option<u64>,
    pub provenance: BTreeMap<String, String>,
}

pub type Release = ReleaseV2;

impl ReleaseV2 {
    pub const REQUIRED_INITRAMFS_BINS: &'static [&'static str] = &[
        "/init",
        "/bin/mount",
        "/bin/switch_root",
        "/bin/cowfsck",
        "/bin/sh",
    ];

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let release: Self = parse(bytes)?;
        release.validate()?;
        Ok(release)
    }

    pub fn validate(&self) -> Result<()> {
        require(
            self.format == "os.release" && self.version == RELEASE_VERSION,
            "unsupported release format/version",
        )?;
        bounded(&self.name, 128)?;
        self.loader.validate()?;
        provenance(&self.provenance)?;
        require(
            self.protocol.contains(PROTOCOL) && self.schema.contains(SCHEMA),
            "incompatible authority protocol or state schema",
        )?;
        require(
            self.sysext.len() + self.confext.len() <= 32,
            "too many extensions",
        )?;
        let mut seen = BTreeSet::new();
        for id in self.images() {
            unhex::<32>(id)?;
            require(seen.insert(id), "duplicate release image")?;
        }
        Ok(())
    }

    /// Yields `[boot, initramfs, root_template, base, sysext..., confext...]`.
    pub fn images(&self) -> impl Iterator<Item = &str> {
        [&self.boot, &self.initramfs, &self.root_template, &self.base]
            .into_iter()
            .chain(&self.sysext)
            .chain(&self.confext)
            .map(String::as_str)
    }

    /// Verifies that the signed `Kind::Boot` image carries every loader asset named in
    /// `self.loader` and binds `client_kernel_sha256` to the exact Wasm artifact digest.
    pub fn verify_boot_loader(&self, boot: &Image) -> Result<()> {
        require(boot.kind == Kind::Boot, "expected boot image")?;
        let find_file = |path: &str| -> Result<&str> {
            boot.entries
                .iter()
                .find_map(|entry| {
                    if entry.path == path
                        && let Node::File { sha256, .. } = &entry.node
                    {
                        return Some(sha256.as_str());
                    }
                    None
                })
                .ok_or_else(|| Error(format!("boot loader asset missing: {path}")))
        };
        let _ = find_file(&self.loader.entry)?;
        let _ = find_file(&self.loader.client_kernel_js)?;
        let wasm_sha = find_file(&self.loader.client_kernel_wasm)?;
        require(
            wasm_sha == self.loader.client_kernel_sha256,
            "loader client_kernel_sha256 mismatch",
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Detached {
    pub format: String,
    pub version: u32,
    pub key: String,
    pub signature: String,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trust {
    pub keys: BTreeMap<String, String>,
    pub revoked: BTreeSet<String>,
}
pub fn signing_message(domain: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    require(
        matches!(
            domain,
            SIGNING_DOMAIN_IMAGE_V2 | SIGNING_DOMAIN_RELEASE_V2 | SIGNING_DOMAIN_OCI_ARTIFACT_V1
        ),
        "unknown signing domain",
    )?;
    require(bytes.len() <= MANIFEST_MAX, "manifest too large")?;
    let mut message = domain.as_bytes().to_vec();
    message.push(0);
    message.extend_from_slice(bytes);
    Ok(message)
}
impl Trust {
    pub fn verify(&self, domain: &str, bytes: &[u8], detached: &[u8]) -> Result<String> {
        let signature: Detached = parse(detached)?;
        require(
            signature.format == "os.signature" && signature.version == 1,
            "unsupported signature format",
        )?;
        require(
            !self.revoked.contains(&signature.key),
            "publisher key revoked",
        )?;
        let public = self
            .keys
            .get(&signature.key)
            .ok_or_else(|| Error("untrusted publisher".into()))?;
        let public = unhex::<32>(public)?;
        require(digest(&public) == signature.key, "key identifier mismatch")?;
        let key =
            VerifyingKey::from_bytes(&public).map_err(|_| Error("invalid publisher key".into()))?;
        let signature_bytes = Signature::from_bytes(&unhex::<64>(&signature.signature)?);
        key.verify_strict(&signing_message(domain, bytes)?, &signature_bytes)
            .map_err(|_| Error("invalid signature".into()))?;
        Ok(signature.key)
    }
}

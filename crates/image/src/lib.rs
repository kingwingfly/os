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
pub const PROTOCOL: u32 = 1;
pub const SCHEMA: u32 = 7;
pub const LEVEL: u32 = 1;
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
fn require(ok: bool, message: &str) -> Result<()> {
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
    File { sha256: String, size: u64 },
    Symlink { target: String },
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
        require(
            self.format == "os.image" && self.version == 1,
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
                Node::File { sha256, size } => {
                    unhex::<32>(sha256)?;
                    require(*size <= i64::MAX as u64, "file too large")?;
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
    pub fn verify_content(&self, mut read: impl FnMut(&str, u64) -> Result<()>) -> Result<()> {
        for entry in &self.entries {
            if let Node::File { sha256, size } = &entry.node {
                read(sha256, *size)?;
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
pub struct Release {
    pub format: String,
    pub version: u32,
    pub name: String,
    pub boot: String,
    pub base: String,
    pub sysext: Vec<String>,
    pub confext: Vec<String>,
    pub protocol: Range,
    pub schema: Range,
    pub provenance: BTreeMap<String, String>,
}
impl Release {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let release: Self = parse(bytes)?;
        release.validate()?;
        Ok(release)
    }
    pub fn validate(&self) -> Result<()> {
        require(
            self.format == "os.release" && self.version == 1,
            "unsupported release format/version",
        )?;
        bounded(&self.name, 128)?;
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
    pub fn images(&self) -> impl Iterator<Item = &str> {
        [&self.boot, &self.base]
            .into_iter()
            .chain(&self.sysext)
            .chain(&self.confext)
            .map(String::as_str)
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
        matches!(domain, "os.image.v1" | "os.release.v1"),
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

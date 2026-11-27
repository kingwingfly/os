//! CNI Spec v1.0.0 types, environment parsing, configuration hygiene, and atomic attachment state.

use abi::auth_v2::valid_cluster_record_id;
use abi::cluster_state::{valid_cluster_name, valid_tenant_name};
use abi::overlay::{
    OVERLAY_DEFAULT_LEASE_TTL_SECS, TUN_DEFAULT_MTU, TUN_MAX_MTU, TUN_MIN_MTU,
    valid_overlay_network_name, valid_tun_ifname,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::FromRawFd;
use std::path::{Component, Path, PathBuf};

/// Supported CNI specification version.
pub const CNI_SPEC_VERSION: &str = "1.0.0";
/// Maximum CNI JSON configuration size read from stdin (`256 KiB`).
pub const CNI_STDIN_MAX_BYTES: usize = 256 * 1024;
/// Maximum attachment JSON file size (`64 KiB`).
pub const ATTACHMENT_FILE_MAX_BYTES: usize = 64 * 1024;
/// Maximum token file size (`16 KiB`).
pub const TOKEN_FILE_MAX_BYTES: usize = 16 * 1024;

// Standard CNI v1.0.0 well-known error codes.
pub const CNI_ERR_INCOMPATIBLE_VERSION: u32 = 1;
pub const CNI_ERR_UNSUPPORTED_FIELD: u32 = 2;
pub const CNI_ERR_UNKNOWN_CONTAINER: u32 = 3;
pub const CNI_ERR_INVALID_ENV: u32 = 4;
pub const CNI_ERR_IO_FAILURE: u32 = 5;
pub const CNI_ERR_DECODING_FAILURE: u32 = 6;
pub const CNI_ERR_INVALID_CONFIG: u32 = 7;
pub const CNI_ERR_TRY_AGAIN_LATER: u32 = 11;
pub const CNI_ERR_INTERNAL: u32 = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CniCommand {
    Version,
    Add,
    Check,
    Del,
}

impl CniCommand {
    pub fn parse(raw: &str) -> Result<Self, CniError> {
        match raw.trim() {
            "VERSION" => Ok(Self::Version),
            "ADD" => Ok(Self::Add),
            "CHECK" => Ok(Self::Check),
            "DEL" => Ok(Self::Del),
            other => Err(CniError::new(
                CNI_ERR_INVALID_ENV,
                "invalid CNI_COMMAND",
                format!("unsupported CNI_COMMAND '{other}' (expected VERSION|ADD|CHECK|DEL)"),
            )),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct CniEnv {
    pub command: String,
    pub container_id: String,
    pub netns: String,
    pub ifname: String,
    pub args: String,
    pub path: String,
}

impl CniEnv {
    pub fn from_process_env() -> Self {
        Self {
            command: std::env::var("CNI_COMMAND").unwrap_or_default(),
            container_id: std::env::var("CNI_CONTAINERID").unwrap_or_default(),
            netns: std::env::var("CNI_NETNS").unwrap_or_default(),
            ifname: std::env::var("CNI_IFNAME").unwrap_or_default(),
            args: std::env::var("CNI_ARGS").unwrap_or_default(),
            path: std::env::var("CNI_PATH").unwrap_or_default(),
        }
    }

    /// Parse semicolon-separated `KEY=VALUE` pairs from `CNI_ARGS`.
    pub fn parsed_args(&self) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        for part in self.args.split(';') {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some((k, v)) = trimmed.split_once('=') {
                let k = k.trim();
                let v = v.trim();
                if !k.is_empty() {
                    map.insert(k.to_string(), v.to_string());
                }
            }
        }
        map
    }

    pub fn validate(&self) -> Result<CniCommand, CniError> {
        let cmd = CniCommand::parse(&self.command)?;
        if cmd == CniCommand::Version {
            return Ok(cmd);
        }
        if !valid_cluster_record_id(&self.container_id) {
            return Err(CniError::new(
                CNI_ERR_INVALID_ENV,
                "invalid CNI_CONTAINERID",
                format!(
                    "CNI_CONTAINERID '{}' is empty or contains disallowed characters",
                    self.container_id
                ),
            ));
        }
        if !valid_tun_ifname(&self.ifname) {
            return Err(CniError::new(
                CNI_ERR_INVALID_ENV,
                "invalid CNI_IFNAME",
                format!(
                    "CNI_IFNAME '{}' must be 1..=15 ASCII [a-zA-Z0-9_-] starting with alphanumeric",
                    self.ifname
                ),
            ));
        }
        match cmd {
            CniCommand::Add | CniCommand::Check => {
                if self.netns.trim().is_empty() {
                    return Err(CniError::new(
                        CNI_ERR_INVALID_ENV,
                        "missing CNI_NETNS",
                        "CNI_NETNS is required for ADD and CHECK",
                    ));
                }
                validate_path_no_traversal(Path::new(&self.netns), "CNI_NETNS")?;
            }
            CniCommand::Del => {
                if !self.netns.trim().is_empty() {
                    validate_path_no_traversal(Path::new(&self.netns), "CNI_NETNS")?;
                }
            }
            CniCommand::Version => {}
        }
        Ok(cmd)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DriverMode {
    #[default]
    Auto,
    Userspace,
    Linux,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CniDns {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nameservers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub search: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
}

/// Network configuration JSON passed on stdin per CNI v1.0.0.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CniNetConfig {
    pub cni_version: String,
    #[serde(default = "default_network_name")]
    pub name: String,
    #[serde(rename = "type", default = "default_plugin_type")]
    pub plugin_type: String,
    #[serde(default = "default_tenant_name")]
    pub tenant: String,
    #[serde(default = "default_cluster")]
    pub cluster: String,
    #[serde(default = "default_node_id")]
    pub node_id: String,
    /// Optional Worker / ClusterState HTTP base URL (e.g. `http://127.0.0.1:8787`).
    #[serde(default)]
    pub endpoint_url: Option<String>,
    /// Optional inline ServiceAuth v2 token (prefer `tokenFile` in production).
    #[serde(default)]
    pub token: Option<String>,
    /// Optional path to a `0600` file containing the ServiceAuth v2 token.
    #[serde(default)]
    pub token_file: Option<String>,
    /// Optional `X-OS-Instance` header value.
    #[serde(default)]
    pub instance_id: Option<String>,
    /// State directory for `$stateDir/attachments/<container_id>.json`.
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    #[serde(default)]
    pub driver: DriverMode,
    #[serde(default)]
    pub mtu: Option<u16>,
    #[serde(default)]
    pub lease_ttl_secs: Option<u64>,
    #[serde(default)]
    pub static_ip: Option<String>,
    #[serde(default)]
    pub cidr: Option<String>,
    #[serde(default)]
    pub dns: Option<CniDns>,
    #[serde(default)]
    pub prev_result: Option<serde_json::Value>,
}

fn default_network_name() -> String {
    "default".to_string()
}

fn default_plugin_type() -> String {
    "os-cni".to_string()
}

fn default_tenant_name() -> String {
    "u0".to_string()
}

fn default_cluster() -> String {
    "default".to_string()
}

fn default_node_id() -> String {
    "node-0".to_string()
}

fn default_state_dir() -> PathBuf {
    PathBuf::from("/var/lib/os-cni")
}

impl CniNetConfig {
    pub fn parse_json(stdin_bytes: &[u8]) -> Result<Self, CniError> {
        if stdin_bytes.len() > CNI_STDIN_MAX_BYTES {
            return Err(CniError::new(
                CNI_ERR_DECODING_FAILURE,
                "CNI config exceeds maximum size",
                format!(
                    "stdin length {} exceeds {CNI_STDIN_MAX_BYTES}",
                    stdin_bytes.len()
                ),
            ));
        }
        let cfg: Self = serde_json::from_slice(stdin_bytes).map_err(|e| {
            CniError::new(
                CNI_ERR_DECODING_FAILURE,
                "failed to decode CNI network configuration JSON",
                e.to_string(),
            )
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), CniError> {
        if self.cni_version != CNI_SPEC_VERSION {
            return Err(CniError::new(
                CNI_ERR_INCOMPATIBLE_VERSION,
                "incompatible CNI version",
                format!(
                    "unsupported cniVersion '{}' (supported: [\"{CNI_SPEC_VERSION}\"])",
                    self.cni_version
                ),
            ));
        }
        if !valid_overlay_network_name(&self.name) {
            return Err(CniError::new(
                CNI_ERR_INVALID_CONFIG,
                "invalid network name",
                format!("network name '{}' must match [a-z0-9_-]{{1,32}}", self.name),
            ));
        }
        if !valid_tenant_name(&self.tenant) {
            return Err(CniError::new(
                CNI_ERR_INVALID_CONFIG,
                "invalid tenant",
                format!("tenant '{}' is not a valid tenant identifier", self.tenant),
            ));
        }
        if !valid_cluster_name(&self.cluster) {
            return Err(CniError::new(
                CNI_ERR_INVALID_CONFIG,
                "invalid cluster name",
                format!("cluster '{}' is not a valid cluster name", self.cluster),
            ));
        }
        if !valid_cluster_record_id(&self.node_id) {
            return Err(CniError::new(
                CNI_ERR_INVALID_CONFIG,
                "invalid nodeId",
                format!("nodeId '{}' is not a valid record identifier", self.node_id),
            ));
        }
        validate_path_no_traversal(&self.state_dir, "stateDir")?;
        if let Some(ref tf) = self.token_file {
            validate_path_no_traversal(Path::new(tf), "tokenFile")?;
        }
        if let Some(mtu) = self.mtu
            && !(TUN_MIN_MTU..=TUN_MAX_MTU).contains(&mtu)
        {
            return Err(CniError::new(
                CNI_ERR_INVALID_CONFIG,
                "invalid mtu",
                format!("mtu {mtu} outside allowed range {TUN_MIN_MTU}..={TUN_MAX_MTU}"),
            ));
        }
        if let Some(ttl) = self.lease_ttl_secs
            && !(5..=3600).contains(&ttl)
        {
            return Err(CniError::new(
                CNI_ERR_INVALID_CONFIG,
                "invalid leaseTtlSecs",
                format!("leaseTtlSecs {ttl} outside allowed range 5..=3600"),
            ));
        }
        if let Some(ref raw_ip) = self.static_ip {
            raw_ip.parse::<Ipv4Addr>().map_err(|_| {
                CniError::new(
                    CNI_ERR_INVALID_CONFIG,
                    "invalid staticIp",
                    format!("staticIp '{raw_ip}' is not a valid IPv4 address"),
                )
            })?;
        }
        Ok(())
    }

    pub fn effective_mtu(&self) -> u16 {
        self.mtu
            .unwrap_or(TUN_DEFAULT_MTU)
            .clamp(TUN_MIN_MTU, TUN_MAX_MTU)
    }

    pub fn effective_lease_ttl(&self) -> u64 {
        self.lease_ttl_secs
            .unwrap_or(OVERLAY_DEFAULT_LEASE_TTL_SECS)
            .clamp(5, 3600)
    }

    /// Resolve the requested static IPv4 from config or `CNI_ARGS` (`IP=...`).
    pub fn requested_static_ip(&self, env: &CniEnv) -> Result<Option<Ipv4Addr>, CniError> {
        if let Some(ref s) = self.static_ip {
            let ip = s.parse::<Ipv4Addr>().map_err(|_| {
                CniError::new(
                    CNI_ERR_INVALID_CONFIG,
                    "invalid staticIp",
                    format!("staticIp '{s}' is not a valid IPv4 address"),
                )
            })?;
            return Ok(Some(ip));
        }
        if let Some(s) = env.parsed_args().get("IP") {
            let ip = s.parse::<Ipv4Addr>().map_err(|_| {
                CniError::new(
                    CNI_ERR_INVALID_ENV,
                    "invalid CNI_ARGS IP",
                    format!("CNI_ARGS IP '{s}' is not a valid IPv4 address"),
                )
            })?;
            return Ok(Some(ip));
        }
        Ok(None)
    }

    /// Resolve auth token from `token` or `tokenFile` (strictly using `O_NOFOLLOW`).
    pub fn resolve_token(&self) -> Result<Option<String>, CniError> {
        if let Some(ref t) = self.token {
            let trimmed = t.trim();
            if !trimmed.is_empty() {
                return Ok(Some(trimmed.to_string()));
            }
        }
        if let Some(ref tf) = self.token_file {
            let p = Path::new(tf);
            validate_no_symlinks_on_existing_path(p, "tokenFile")?;
            let raw = read_file_nofollow(p, TOKEN_FILE_MAX_BYTES, "tokenFile")?;
            let text = String::from_utf8(raw).map_err(|_| {
                CniError::new(
                    CNI_ERR_INVALID_CONFIG,
                    "invalid tokenFile",
                    "tokenFile is not valid UTF-8",
                )
            })?;
            let trimmed = text.trim();
            if trimmed.is_empty() {
                return Err(CniError::new(
                    CNI_ERR_INVALID_CONFIG,
                    "empty tokenFile",
                    "tokenFile is empty",
                ));
            }
            return Ok(Some(trimmed.to_string()));
        }
        Ok(None)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CniVersionResult {
    pub cni_version: String,
    pub supported_versions: Vec<String>,
}

impl Default for CniVersionResult {
    fn default() -> Self {
        Self {
            cni_version: CNI_SPEC_VERSION.to_string(),
            supported_versions: vec![CNI_SPEC_VERSION.to_string()],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CniInterface {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CniIpConfig {
    pub interface: usize,
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CniRoute {
    pub dst: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gw: Option<String>,
}

/// CNI v1.0.0 `ADD` result JSON.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CniResult {
    pub cni_version: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<CniInterface>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ips: Vec<CniIpConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<CniRoute>,
    #[serde(default)]
    pub dns: CniDns,
}

/// CNI v1.0.0 structured error JSON.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CniError {
    pub cni_version: String,
    pub code: u32,
    pub msg: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub details: String,
}

impl CniError {
    pub fn new(code: u32, msg: impl Into<String>, details: impl Into<String>) -> Self {
        Self {
            cni_version: CNI_SPEC_VERSION.to_string(),
            code,
            msg: msg.into(),
            details: details.into(),
        }
    }
}

impl std::fmt::Display for CniError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.details.is_empty() {
            write!(f, "CNI error {}: {}", self.code, self.msg)
        } else {
            write!(
                f,
                "CNI error {}: {} ({})",
                self.code, self.msg, self.details
            )
        }
    }
}

impl std::error::Error for CniError {}

/// Attachment descriptor persisted atomically (`0600`) at `$stateDir/attachments/<container_id>.json`.
///
/// Mirrors `os-csi`'s `$CSI_STATE/published/<id>.json` and is consumed by `containerd-shim-os`
/// and `os-native` when attaching a pod sandbox to `NativeOverlaySwitch`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CniAttachmentDescriptor {
    pub version: u32,
    pub container_id: String,
    pub ifname: String,
    pub netns: String,
    pub tenant: String,
    pub cluster: String,
    pub network: String,
    pub node_id: String,
    pub ip: String,
    pub prefix_len: u8,
    pub gateway: String,
    pub cidr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<String>,
    pub mtu: u16,
    pub lease_id: u64,
    pub fence_epoch: u64,
    pub driver: String,
    pub created_at: u64,
}

pub fn validate_path_no_traversal(path: &Path, label: &str) -> Result<(), CniError> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.contains(&0) {
        return Err(CniError::new(
            CNI_ERR_INVALID_CONFIG,
            format!("invalid {label}"),
            format!("{label} is empty or contains NUL bytes"),
        ));
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(CniError::new(
            CNI_ERR_INVALID_CONFIG,
            format!("invalid {label}"),
            format!("{label} must not contain '..' path traversal"),
        ));
    }
    Ok(())
}

/// Verify that no existing path component (up to and including `path`) is a symlink.
pub fn validate_no_symlinks_on_existing_path(path: &Path, label: &str) -> Result<(), CniError> {
    validate_path_no_traversal(path, label)?;
    let mut cur = PathBuf::new();
    for comp in path.components() {
        cur.push(comp);
        if matches!(comp, Component::RootDir | Component::CurDir) {
            continue;
        }
        match std::fs::symlink_metadata(&cur) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(CniError::new(
                        CNI_ERR_INVALID_CONFIG,
                        format!("symlink rejected in {label}"),
                        format!("path component '{}' is a symlink", cur.display()),
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) => {
                return Err(CniError::new(
                    CNI_ERR_IO_FAILURE,
                    format!("stat failed on {label}"),
                    format!("{}: {e}", cur.display()),
                ));
            }
        }
    }
    Ok(())
}

pub fn read_file_nofollow(path: &Path, max_bytes: usize, label: &str) -> Result<Vec<u8>, CniError> {
    validate_no_symlinks_on_existing_path(path, label)?;
    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        CniError::new(
            CNI_ERR_INVALID_CONFIG,
            format!("invalid {label}"),
            "path contains NUL",
        )
    })?;
    // SAFETY: `c_path` is a valid NUL-terminated C string.
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(CniError::new(
            CNI_ERR_IO_FAILURE,
            format!("failed to open {label}"),
            format!("{}: {err}", path.display()),
        ));
    }
    // SAFETY: `fd` is a newly opened owned file descriptor.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let meta = file.metadata().map_err(|e| {
        CniError::new(
            CNI_ERR_IO_FAILURE,
            format!("failed to stat {label}"),
            e.to_string(),
        )
    })?;
    if !meta.is_file() {
        return Err(CniError::new(
            CNI_ERR_INVALID_CONFIG,
            format!("{label} is not a regular file"),
            path.display().to_string(),
        ));
    }
    let mut buf = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take((max_bytes as u64) + 1)
        .read_to_end(&mut buf)
        .map_err(|e| {
            CniError::new(
                CNI_ERR_IO_FAILURE,
                format!("failed to read {label}"),
                e.to_string(),
            )
        })?;
    if buf.len() > max_bytes {
        return Err(CniError::new(
            CNI_ERR_INVALID_CONFIG,
            format!("{label} exceeds maximum size"),
            format!("exceeded {max_bytes} bytes"),
        ));
    }
    Ok(buf)
}

pub fn attachment_path(state_dir: &Path, container_id: &str) -> Result<PathBuf, CniError> {
    validate_path_no_traversal(state_dir, "stateDir")?;
    if !valid_cluster_record_id(container_id) {
        return Err(CniError::new(
            CNI_ERR_INVALID_ENV,
            "invalid container_id",
            format!("invalid container_id '{container_id}'"),
        ));
    }
    Ok(state_dir
        .join("attachments")
        .join(format!("{container_id}.json")))
}

/// Atomically persist `$stateDir/attachments/<container_id>.json` with mode `0600`.
pub fn save_cni_attachment(
    state_dir: &Path,
    desc: &CniAttachmentDescriptor,
) -> Result<PathBuf, CniError> {
    validate_no_symlinks_on_existing_path(state_dir, "stateDir")?;
    let attach_dir = state_dir.join("attachments");
    std::fs::create_dir_all(&attach_dir).map_err(|e| {
        CniError::new(
            CNI_ERR_IO_FAILURE,
            "failed to create attachments directory",
            format!("{}: {e}", attach_dir.display()),
        )
    })?;
    validate_no_symlinks_on_existing_path(&attach_dir, "attachmentsDir")?;
    let final_path = attachment_path(state_dir, &desc.container_id)?;
    if let Ok(meta) = std::fs::symlink_metadata(&final_path)
        && meta.file_type().is_symlink()
    {
        return Err(CniError::new(
            CNI_ERR_INVALID_CONFIG,
            "refusing to overwrite symlink attachment file",
            final_path.display().to_string(),
        ));
    }
    let tmp_path = attach_dir.join(format!(".{}.tmp.{}", desc.container_id, std::process::id()));
    let payload = serde_json::to_vec_pretty(desc).map_err(|e| {
        CniError::new(
            CNI_ERR_INTERNAL,
            "failed to serialize attachment descriptor",
            e.to_string(),
        )
    })?;
    let _ = std::fs::remove_file(&tmp_path);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&tmp_path)
        .map_err(|e| {
            CniError::new(
                CNI_ERR_IO_FAILURE,
                "failed to create temp attachment file",
                format!("{}: {e}", tmp_path.display()),
            )
        })?;
    f.write_all(&payload)
        .and_then(|_| f.sync_all())
        .map_err(|e| {
            let _ = std::fs::remove_file(&tmp_path);
            CniError::new(
                CNI_ERR_IO_FAILURE,
                "failed to write attachment descriptor",
                e.to_string(),
            )
        })?;
    drop(f);
    std::fs::rename(&tmp_path, &final_path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        CniError::new(
            CNI_ERR_IO_FAILURE,
            "failed to rename attachment descriptor",
            e.to_string(),
        )
    })?;
    Ok(final_path)
}

/// Safely load `$stateDir/attachments/<container_id>.json` with `O_NOFOLLOW`.
/// Returns `Ok(None)` if the attachment file does not exist.
pub fn load_cni_attachment(
    state_dir: &Path,
    container_id: &str,
) -> Result<Option<CniAttachmentDescriptor>, CniError> {
    let path = attachment_path(state_dir, container_id)?;
    validate_no_symlinks_on_existing_path(state_dir, "stateDir")?;
    match std::fs::symlink_metadata(&path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(CniError::new(
                    CNI_ERR_INVALID_CONFIG,
                    "attachment descriptor is a symlink",
                    path.display().to_string(),
                ));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(CniError::new(
                CNI_ERR_IO_FAILURE,
                "failed to stat attachment descriptor",
                format!("{}: {e}", path.display()),
            ));
        }
    }
    let bytes = read_file_nofollow(&path, ATTACHMENT_FILE_MAX_BYTES, "attachment")?;
    let desc: CniAttachmentDescriptor = serde_json::from_slice(&bytes).map_err(|e| {
        CniError::new(
            CNI_ERR_DECODING_FAILURE,
            "corrupt attachment descriptor",
            e.to_string(),
        )
    })?;
    if desc.container_id != container_id {
        return Err(CniError::new(
            CNI_ERR_INVALID_CONFIG,
            "attachment container_id mismatch",
            format!("expected '{container_id}', found '{}'", desc.container_id),
        ));
    }
    Ok(Some(desc))
}

/// Remove `$stateDir/attachments/<container_id>.json`, ignoring `ENOENT`.
pub fn remove_cni_attachment(state_dir: &Path, container_id: &str) -> Result<(), CniError> {
    let path = attachment_path(state_dir, container_id)?;
    // Walk `stateDir`, `stateDir/attachments`, and the attachment file itself rejecting symlinks.
    validate_no_symlinks_on_existing_path(&path, "attachment")?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(CniError::new(
            CNI_ERR_IO_FAILURE,
            "failed to remove attachment descriptor",
            format!("{}: {e}", path.display()),
        )),
    }
}

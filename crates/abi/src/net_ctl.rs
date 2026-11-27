//! Phase 10a `netd` outbound stream socket gateway protocol, egress policy,
//! SSRF/private-IP/bogon/obfuscation validator, framing, and WASIX `AddrPort` codecs
//! (`#86`, `docs/architecture/contract.md` §2.16, §6 `Boundary::Network` v1).

use crate::contract::NETWORK_VERSION;
use crate::{Errno, Error};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Active `Boundary::Network` v1 `netd` wire protocol version.
pub const NETD_VERSION: u32 = NETWORK_VERSION;

/// Public local Unix stream socket served by `/usr/bin/netd` (`0666`, `SO_PEERCRED`-checked).
pub const NETD_SOCK: &str = "/run/netd.sock";

/// Privileged host bridge Unix stream socket (`0600`, uid 0 + verified `/usr/bin/netd` image).
pub const NET_HOST_SOCK: &str = "/run/net/host.sock";

/// Hard upper bound for a single length-prefixed JSON control message (16 KiB).
pub const NET_CONTROL_MAX_BYTES: usize = 16 * 1024;

/// Maximum payload bytes carried in a single stream `DATA` frame (16 KiB).
pub const NET_DATA_CHUNK_MAX: usize = 16 * 1024;

/// Initial per-direction flow-control window granted at stream open (64 KiB).
pub const NET_INITIAL_WINDOW_BYTES: u32 = 64 * 1024;

/// Maximum egress rules permitted inside one `NetScope`.
pub const NET_MAX_RULES: usize = 64;

/// Maximum port ranges permitted inside one `EgressRule`.
pub const NET_MAX_PORT_RANGES: usize = 16;

/// Server-enforced hard ceilings that no client-requested quota may exceed.
pub const MAX_CONCURRENT_STREAMS_CEILING: u32 = 32;
pub const MAX_BYTES_PER_STREAM_CEILING: u64 = 256 * 1024 * 1024;
pub const CONNECT_TIMEOUT_MS_CEILING: u64 = 30_000;
pub const IDLE_TIMEOUT_MS_CEILING: u64 = 300_000;
pub const MAX_STREAM_LIFETIME_MS_CEILING: u64 = 1_800_000;

/// Default quota values when omitted from `NetScope`.
pub const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 8;
pub const DEFAULT_MAX_BYTES_PER_STREAM: u64 = 16 * 1024 * 1024;
pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 10_000;
pub const DEFAULT_IDLE_TIMEOUT_MS: u64 = 60_000;
pub const DEFAULT_MAX_STREAM_LIFETIME_MS: u64 = 300_000;

/// Binary data-plane frame tags shared between Unix socket (`[u8 tag][u32_be len][payload]`)
/// and WebSocket binary messages (`[u8 tag][payload]`).
pub const FRAME_DATA: u8 = 0x01;
pub const FRAME_CREDIT: u8 = 0x02;
pub const FRAME_HALF_CLOSE: u8 = 0x03;
pub const FRAME_CANCEL: u8 = 0x04;
pub const FRAME_CLOSED: u8 = 0x05;

/// Canonical WASIX `wasix_32v1` address family discriminants.
pub const WASIX_AF_UNSPEC: u8 = 0;
pub const WASIX_AF_INET4: u8 = 1;
pub const WASIX_AF_INET6: u8 = 2;
pub const WASIX_AF_UNIX: u8 = 3;

/// Canonical WASIX `wasix_32v1` socket type discriminants.
pub const WASIX_SOCK_UNKNOWN: u8 = 0;
pub const WASIX_SOCK_DGRAM: u8 = 1;
pub const WASIX_SOCK_STREAM: u8 = 2;
pub const WASIX_SOCK_RAW: u8 = 3;
pub const WASIX_SOCK_SEQPACKET: u8 = 4;

/// Canonical WASIX `AddrPort` (`__wasi_addr_port_t`) byte size & tags.
pub const WASIX_ADDR_PORT_SIZE: usize = 20;
pub const WASIX_ADDR_UNSPEC: u8 = 0;
pub const WASIX_ADDR_INET4: u8 = 1;
pub const WASIX_ADDR_INET6: u8 = 2;

/// WASI `sdflags` shutdown bitmask (`sock_shutdown`).
pub const WASI_SD_RD: u8 = 1;
pub const WASI_SD_WR: u8 = 2;

fn default_max_concurrent_streams() -> u32 {
    DEFAULT_MAX_CONCURRENT_STREAMS
}
fn default_max_bytes_per_stream() -> u64 {
    DEFAULT_MAX_BYTES_PER_STREAM
}
fn default_connect_timeout_ms() -> u64 {
    DEFAULT_CONNECT_TIMEOUT_MS
}
fn default_idle_timeout_ms() -> u64 {
    DEFAULT_IDLE_TIMEOUT_MS
}
fn default_max_stream_lifetime_ms() -> u64 {
    DEFAULT_MAX_STREAM_LIFETIME_MS
}

/// Outbound network egress policy embedded in `RemoteScope.net` (default-deny when `None` or empty).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetScope {
    pub rules: Vec<EgressRule>,
    #[serde(default)]
    pub quota: NetQuota,
}

/// Single allowlist rule permitting outbound stream connections matching `(host, ports, tls)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressRule {
    pub host: HostMatch,
    pub ports: Vec<PortRange>,
    #[serde(default)]
    pub tls: TlsPolicy,
}

/// Target host matcher for an [`EgressRule`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum HostMatch {
    /// Exact canonical hostname (case-insensitive) or canonical IP literal.
    Exact(String),
    /// Strict subdomain suffix (`>= 2` valid DNS labels; matches `*.<suffix>` only,
    /// NEVER the bare domain itself and NEVER IP literals).
    Suffix(String),
    /// IPv4 or IPv6 CIDR block.
    Cidr { addr: String, prefix_len: u8 },
    /// Any public hostname or public IP (still subject to SSRF/private-IP/bogon denials
    /// and NEVER satisfies the two-key loopback test allowlist).
    AnyPublic,
}

/// Inclusive TCP port range (`1 <= start <= end`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub const fn single(port: u16) -> Self {
        Self {
            start: port,
            end: port,
        }
    }

    pub const fn is_valid(&self) -> bool {
        self.start >= 1 && self.start <= self.end
    }

    pub const fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }

    pub fn intersect(&self, other: &Self) -> Option<Self> {
        let start = self.start.max(other.start);
        let end = self.end.min(other.end);
        (start >= 1 && start <= end).then_some(Self { start, end })
    }
}

/// TLS policy permitted by an [`EgressRule`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsPolicy {
    #[default]
    PlainOnly,
    TlsOnly,
    Any,
}

impl TlsPolicy {
    pub const fn allows(self, mode: TlsMode) -> bool {
        match self {
            Self::PlainOnly => matches!(mode, TlsMode::Off),
            Self::TlsOnly => matches!(mode, TlsMode::On),
            Self::Any => true,
        }
    }

    pub const fn intersect(self, other: Self) -> Option<Self> {
        match (self, other) {
            (Self::PlainOnly, Self::PlainOnly) => Some(Self::PlainOnly),
            (Self::TlsOnly, Self::TlsOnly) => Some(Self::TlsOnly),
            (Self::Any, x) | (x, Self::Any) => Some(x),
            (Self::PlainOnly, Self::TlsOnly) | (Self::TlsOnly, Self::PlainOnly) => None,
        }
    }
}

/// Requested TLS mode on a stream open request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    #[default]
    Off,
    On,
    StartTls,
}

/// Data-plane mode between a local guest and `netd` over `/run/netd.sock`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamMode {
    #[default]
    Raw,
    Framed,
}

/// Per-credential outbound stream resource quotas (strictly clamped to server ceilings).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetQuota {
    #[serde(default = "default_max_concurrent_streams")]
    pub max_concurrent_streams: u32,
    #[serde(default = "default_max_bytes_per_stream")]
    pub max_bytes_per_stream: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes_per_sec: Option<u64>,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
    #[serde(default = "default_max_stream_lifetime_ms")]
    pub max_stream_lifetime_ms: u64,
}

impl Default for NetQuota {
    fn default() -> Self {
        Self {
            max_concurrent_streams: DEFAULT_MAX_CONCURRENT_STREAMS,
            max_bytes_per_stream: DEFAULT_MAX_BYTES_PER_STREAM,
            max_bytes_per_sec: None,
            connect_timeout_ms: DEFAULT_CONNECT_TIMEOUT_MS,
            idle_timeout_ms: DEFAULT_IDLE_TIMEOUT_MS,
            max_stream_lifetime_ms: DEFAULT_MAX_STREAM_LIFETIME_MS,
        }
    }
}

impl NetQuota {
    pub fn validate(&self) -> Result<(), Error> {
        if self.max_concurrent_streams == 0
            || self.max_bytes_per_stream == 0
            || self.max_bytes_per_sec == Some(0)
            || self.connect_timeout_ms == 0
            || self.idle_timeout_ms == 0
            || self.max_stream_lifetime_ms == 0
        {
            return Err(Error::because(
                Errno::EINVAL,
                "network quota values must be non-zero",
            ));
        }
        Ok(())
    }

    pub fn clamped(&self) -> Result<Self, Error> {
        self.validate()?;
        Ok(Self {
            max_concurrent_streams: self
                .max_concurrent_streams
                .min(MAX_CONCURRENT_STREAMS_CEILING),
            max_bytes_per_stream: self.max_bytes_per_stream.min(MAX_BYTES_PER_STREAM_CEILING),
            max_bytes_per_sec: self.max_bytes_per_sec,
            connect_timeout_ms: self.connect_timeout_ms.min(CONNECT_TIMEOUT_MS_CEILING),
            idle_timeout_ms: self.idle_timeout_ms.min(IDLE_TIMEOUT_MS_CEILING),
            max_stream_lifetime_ms: self
                .max_stream_lifetime_ms
                .min(MAX_STREAM_LIFETIME_MS_CEILING),
        })
    }

    pub fn attenuate(&self, requested: &Self) -> Option<Self> {
        let a = self.clamped().ok()?;
        let b = requested.clamped().ok()?;
        let max_bytes_per_sec = match (a.max_bytes_per_sec, b.max_bytes_per_sec) {
            (Some(x), Some(y)) => Some(x.min(y)),
            (Some(x), None) | (None, Some(x)) => Some(x),
            (None, None) => None,
        };
        Some(Self {
            max_concurrent_streams: a.max_concurrent_streams.min(b.max_concurrent_streams),
            max_bytes_per_stream: a.max_bytes_per_stream.min(b.max_bytes_per_stream),
            max_bytes_per_sec,
            connect_timeout_ms: a.connect_timeout_ms.min(b.connect_timeout_ms),
            idle_timeout_ms: a.idle_timeout_ms.min(b.idle_timeout_ms),
            max_stream_lifetime_ms: a.max_stream_lifetime_ms.min(b.max_stream_lifetime_ms),
        })
    }
}

/// Structured network error classification returned alongside POSIX `Errno`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetErrorKind {
    PolicyDenied,
    PrivateAddressDenied,
    Offline,
    QuotaExceeded,
    Unsupported,
    Timeout,
    ConnectFailed,
    Canceled,
    ProtocolError,
    HostUnavailable,
    InvalidArgument,
    StreamReset,
}

/// Structured error returned by SSRF & policy evaluators.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetFailure {
    pub errno: Errno,
    pub kind: NetErrorKind,
    pub message: String,
}

impl NetFailure {
    pub fn new(errno: Errno, kind: NetErrorKind, message: impl Into<String>) -> Self {
        Self {
            errno,
            kind,
            message: message.into(),
        }
    }

    pub fn into_error(self) -> Error {
        Error::because(self.errno, self.message)
    }
}

impl From<Errno> for NetFailure {
    fn from(errno: Errno) -> Self {
        let kind = match errno {
            Errno::EACCES | Errno::EPERM => NetErrorKind::PolicyDenied,
            Errno::ENOTCONN => NetErrorKind::Offline,
            Errno::EDQUOT | Errno::ENOSPC => NetErrorKind::QuotaExceeded,
            Errno::EOPNOTSUPP
            | Errno::EPROTONOSUPPORT
            | Errno::EAFNOSUPPORT
            | Errno::EPROTOTYPE => NetErrorKind::Unsupported,
            Errno::ETIMEDOUT => NetErrorKind::Timeout,
            Errno::ECANCELED => NetErrorKind::Canceled,
            Errno::ECONNREFUSED | Errno::ECONNABORTED | Errno::EADDRNOTAVAIL => {
                NetErrorKind::ConnectFailed
            }
            Errno::ECONNRESET | Errno::EPIPE => NetErrorKind::StreamReset,
            Errno::ENOENT | Errno::ENODEV => NetErrorKind::HostUnavailable,
            _ => NetErrorKind::InvalidArgument,
        };
        Self::new(errno, kind, errno.text())
    }
}

/// Control request sent from a local guest to `/usr/bin/netd` over `/run/netd.sock`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum NetdReq {
    Hello {
        versions: Vec<u32>,
    },
    Connect {
        host: String,
        port: u16,
        #[serde(default)]
        tls: TlsMode,
        #[serde(default)]
        mode: StreamMode,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout_ms: Option<u64>,
    },
    Resolve {
        host: String,
        #[serde(default)]
        port: u16,
    },
    Status {},
}

/// Control reply sent from `/usr/bin/netd` to a local guest over `/run/netd.sock`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NetdResp {
    Welcome {
        version: u32,
        max_chunk: usize,
        initial_window: u32,
    },
    Connected {
        stream_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer_addr: Option<String>,
        mode: StreamMode,
        initial_window: u32,
        quota: NetQuota,
    },
    Resolved {
        addrs: Vec<String>,
    },
    Status {
        version: u32,
        host_kind: String,
        active_streams: u32,
        ready: bool,
    },
    Error {
        errno: Errno,
        error: NetErrorKind,
        message: String,
    },
}

/// Control request sent from `/usr/bin/netd` to the host bridge over `/run/net/host.sock`
/// (with `SCM_RIGHTS = [client_sock_fd]` on `Open` and `Resolve`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostNetReq {
    Hello {
        versions: Vec<u32>,
    },
    Open {
        host: String,
        port: u16,
        #[serde(default)]
        tls: TlsMode,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout_ms: Option<u64>,
    },
    Resolve {
        host: String,
        #[serde(default)]
        port: u16,
    },
    Status {},
}

/// Control reply sent from the host bridge to `/usr/bin/netd` over `/run/net/host.sock`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostNetResp {
    Welcome {
        version: u32,
        host_kind: String,
    },
    Opened {
        stream_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer_addr: Option<String>,
        initial_window: u32,
        quota: NetQuota,
    },
    Resolved {
        addrs: Vec<String>,
    },
    Status {
        version: u32,
        host_kind: String,
        active_streams: u32,
        ready: bool,
    },
    Error {
        errno: Errno,
        error: NetErrorKind,
        message: String,
    },
}

/// Terminal stream closure payload carried in `FRAME_CLOSED` (`0x05`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamClosed {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errno: Option<Errno>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<NetErrorKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default)]
    pub bytes_sent: u64,
    #[serde(default)]
    pub bytes_received: u64,
}

/// Parsed data-plane frame exchanged across `/run/net/host.sock`, WebSocket, and `Framed` clients.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DataFrame {
    Data(Vec<u8>),
    Credit(u32),
    HalfClose,
    Cancel,
    Closed(StreamClosed),
}

// =============================================================================
// Hostname, IP, CIDR & SSRF / Private-IP / Bogon / Obfuscation Validation
// =============================================================================

/// Parsed target host (either canonical IP address or canonical lowercase DNS hostname).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParsedHost {
    Ip(IpAddr),
    Domain(String),
}

/// Returns true if a single DNS label looks like an integer/octal/hex numeric IP component.
fn is_numeric_or_hex_label(label: &str) -> bool {
    if label.is_empty() {
        return false;
    }
    if label.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    if let Some(rest) = label
        .strip_prefix("0x")
        .or_else(|| label.strip_prefix("0X"))
        && !rest.is_empty()
        && rest.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return true;
    }
    false
}

/// Returns true when a raw input string contains forbidden characters, whitespace, zone IDs,
/// URL delimiters, or control characters.
fn has_forbidden_host_chars(raw: &str) -> bool {
    raw.bytes().any(|b| {
        b <= 0x20
            || b >= 0x7f
            || matches!(
                b,
                b'%' | b'@'
                    | b'/'
                    | b'\\'
                    | b'?'
                    | b'#'
                    | b'['
                    | b']'
                    | b' '
                    | b'\t'
                    | b'\r'
                    | b'\n'
            )
    })
}

/// Validate a canonical DNS hostname (never an IP literal, never an obfuscated/short/octal/hex IP).
/// Returns canonical lowercase ASCII hostname without trailing dot.
pub fn parse_valid_hostname(raw: &str) -> Result<String, NetFailure> {
    if raw.is_empty() || has_forbidden_host_chars(raw) || raw.contains(':') {
        return Err(NetFailure::new(
            Errno::EINVAL,
            NetErrorKind::InvalidArgument,
            "invalid hostname syntax",
        ));
    }
    // Reject IPv4 literals outright here (callers should parse IpAddr first if IPs are allowed).
    if raw.parse::<Ipv4Addr>().is_ok() {
        return Err(NetFailure::new(
            Errno::EINVAL,
            NetErrorKind::InvalidArgument,
            "IP literal is not a DNS hostname",
        ));
    }
    // Reject trailing `..` or leading `.`
    if raw.starts_with('.') || raw.ends_with("..") {
        return Err(NetFailure::new(
            Errno::EINVAL,
            NetErrorKind::InvalidArgument,
            "invalid empty label in hostname",
        ));
    }
    let trimmed = raw.strip_suffix('.').unwrap_or(raw);
    if trimmed.is_empty() || trimmed.len() > 253 {
        return Err(NetFailure::new(
            Errno::EINVAL,
            NetErrorKind::InvalidArgument,
            "hostname length out of bounds",
        ));
    }
    let lower = trimmed.to_ascii_lowercase();
    let labels: Vec<&str> = lower.split('.').collect();
    if labels.is_empty() {
        return Err(NetFailure::new(
            Errno::EINVAL,
            NetErrorKind::InvalidArgument,
            "empty hostname",
        ));
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return Err(NetFailure::new(
                Errno::EINVAL,
                NetErrorKind::InvalidArgument,
                "invalid DNS label length",
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(NetFailure::new(
                Errno::EINVAL,
                NetErrorKind::InvalidArgument,
                "DNS label cannot start or end with hyphen",
            ));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(NetFailure::new(
                Errno::EINVAL,
                NetErrorKind::InvalidArgument,
                "invalid character in DNS label",
            ));
        }
    }
    // Reject obfuscated IP forms: all labels numeric/hex (e.g. `2130706433`, `0177.0.0.1`,
    // `127.1`, `0x7f000001`, `0x7f.1`) or trailing numeric/hex TLD (RFC 1123 / WHATWG URL).
    if labels.iter().all(|l| is_numeric_or_hex_label(l))
        || labels.last().is_some_and(|l| is_numeric_or_hex_label(l))
    {
        return Err(NetFailure::new(
            Errno::EINVAL,
            NetErrorKind::InvalidArgument,
            "non-canonical numeric or obfuscated IP host rejected",
        ));
    }
    Ok(lower)
}

/// Parse a target `host` string as either a canonical IP literal or a valid DNS hostname.
/// Strictly rejects obfuscated IPs (`2130706433`, `0177.0.0.1`, `127.1`, `0x7f000001`),
/// zone IDs (`%`), brackets, whitespace, control characters, and URL metacharacters.
pub fn parse_target_host(raw: &str) -> Result<ParsedHost, NetFailure> {
    if raw.is_empty() || has_forbidden_host_chars(raw) {
        return Err(NetFailure::new(
            Errno::EINVAL,
            NetErrorKind::InvalidArgument,
            "invalid host syntax",
        ));
    }
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Ok(ParsedHost::Ip(ip));
    }
    if raw.contains(':') {
        // Any string containing `:` that failed `IpAddr::from_str` is a malformed IPv6 or host:port.
        return Err(NetFailure::new(
            Errno::EINVAL,
            NetErrorKind::InvalidArgument,
            "malformed IPv6 literal",
        ));
    }
    Ok(ParsedHost::Domain(parse_valid_hostname(raw)?))
}

/// Returns true if `ip` falls inside any denied private, loopback, link-local, multicast,
/// carrier-grade NAT, documentation, benchmarking, translation, or reserved bogon range.
pub fn is_denied_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _d] = ip.octets();
    // 0.0.0.0/8 (This network)
    if a == 0 {
        return true;
    }
    // 10.0.0.0/8 (RFC 1918)
    if a == 10 {
        return true;
    }
    // 100.64.0.0/10 (RFC 6598 CGNAT)
    if a == 100 && (b & 0xc0) == 64 {
        return true;
    }
    // 127.0.0.0/8 (Loopback)
    if a == 127 {
        return true;
    }
    // 169.254.0.0/16 (Link-local / Cloud IMDS)
    if a == 169 && b == 254 {
        return true;
    }
    // 172.16.0.0/12 (RFC 1918)
    if a == 172 && (b & 0xf0) == 16 {
        return true;
    }
    // 192.0.0.0/24 (IETF Protocol Assignments)
    if a == 192 && b == 0 && c == 0 {
        return true;
    }
    // 192.0.2.0/24 (TEST-NET-1)
    if a == 192 && b == 0 && c == 2 {
        return true;
    }
    // 192.88.99.0/24 (6to4 Relay Anycast)
    if a == 192 && b == 88 && c == 99 {
        return true;
    }
    // 192.168.0.0/16 (RFC 1918)
    if a == 192 && b == 168 {
        return true;
    }
    // 198.18.0.0/15 (Benchmarking)
    if a == 198 && (b & 0xfe) == 18 {
        return true;
    }
    // 198.51.100.0/24 (TEST-NET-2)
    if a == 198 && b == 51 && c == 100 {
        return true;
    }
    // 203.0.113.0/24 (TEST-NET-3)
    if a == 203 && b == 0 && c == 113 {
        return true;
    }
    // 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved / Broadcast)
    if a >= 224 {
        return true;
    }
    false
}

/// Returns true if `ip` falls inside any denied IPv6 special, private, loopback, link-local,
/// mapped/translated/NAT64/Teredo/6to4/documentation/multicast/reserved range.
pub fn is_denied_ipv6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    // ::/128 (unspecified) & ::1/128 (loopback)
    if ip.is_unspecified() || ip.is_loopback() {
        return true;
    }
    // ::ffff:0:0/96 (IPv4-mapped IPv6): unmap and check IPv4 (and ALWAYS deny mapped loopback)
    if let Some(v4) = ip.to_ipv4_mapped() {
        if v4.is_loopback() || is_denied_ipv4(v4) {
            return true;
        }
        // Reject ALL IPv4-mapped IPv6 addresses to prevent policy/allowlist bypass via ::ffff:x.x.x.x
        return true;
    }
    // ::/96 (deprecated IPv4-compatible IPv6)
    if s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
        return true;
    }
    // ::ffff:0:0:0/96 (IPv4-translated SIIT)
    if s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0xffff && s[5] == 0 {
        return true;
    }
    // 64:ff9b::/96 (NAT64 well-known prefix)
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
        return true;
    }
    // 64:ff9b:1::/48 (NAT64 local-use prefix)
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001 {
        return true;
    }
    // 100::/64 (Discard-only)
    if s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0 {
        return true;
    }
    // 2001::/32 (Teredo)
    if s[0] == 0x2001 && s[1] == 0x0000 {
        return true;
    }
    // 2001:2::/48 (Benchmarking)
    if s[0] == 0x2001 && s[1] == 0x0002 && s[2] == 0x0000 {
        return true;
    }
    // 2001:10::/28 (ORCHID) & 2001:20::/28 (ORCHIDv2)
    if s[0] == 0x2001 && ((s[1] & 0xfff0) == 0x0010 || (s[1] & 0xfff0) == 0x0020) {
        return true;
    }
    // 2001:db8::/32 (Documentation)
    if s[0] == 0x2001 && s[1] == 0x0db8 {
        return true;
    }
    // 2002::/16 (6to4)
    if s[0] == 0x2002 {
        return true;
    }
    // fc00::/7 (Unique Local Address)
    if (s[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    // fe80::/10 (Link-local)
    if (s[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    // fec0::/10 (Deprecated site-local)
    if (s[0] & 0xffc0) == 0xfec0 {
        return true;
    }
    // ff00::/8 (Multicast)
    if (s[0] & 0xff00) == 0xff00 {
        return true;
    }
    false
}

/// Returns true if `ip` is denied by the shared SSRF/private/bogon filter.
pub fn is_denied_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_denied_ipv4(v4),
        IpAddr::V6(v6) => is_denied_ipv6(v6),
    }
}

/// Denied internal/local DNS hostnames and suffixes.
const DENIED_HOST_SUFFIXES: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "localdomain",
    "local",
    "internal",
    "home.arpa",
    "arpa",
    "lan",
    "home",
    "corp",
    "intranet",
    "metadata.goog",
];

/// Returns true if a canonical lowercase DNS hostname is single-label (preventing
/// `/etc/resolv.conf` search-domain SSRF) or matches any denied local/internal suffix.
pub fn is_denied_hostname(lower_host: &str) -> bool {
    if !lower_host.contains('.') {
        return true;
    }
    for suffix in DENIED_HOST_SUFFIXES {
        if lower_host == *suffix {
            return true;
        }
        if let Some(prefix) = lower_host.strip_suffix(suffix)
            && prefix.ends_with('.')
        {
            return true;
        }
    }
    false
}

/// Two-key test-only loopback allowlist (empty by default).
///
/// Only accepts exact `127.0.0.1:<port>` or `[::1]:<port>` (`port != 0`).
/// Egress to a loopback address is permitted ONLY when BOTH:
/// 1. This host-side allowlist contains that exact `SocketAddr`, AND
/// 2. The caller's `NetScope` contains an explicit `HostMatch::Exact("127.0.0.1" | "::1")` rule
///    matching that port and TLS mode.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LoopbackTestAllowlist {
    addrs: BTreeSet<SocketAddr>,
}

impl LoopbackTestAllowlist {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.addrs.is_empty()
    }

    pub fn insert(&mut self, addr: SocketAddr) -> Result<(), Error> {
        if addr.port() == 0 {
            return Err(Error::because(
                Errno::EINVAL,
                "loopback test allowlist port must be non-zero",
            ));
        }
        let ok_ip = match addr.ip() {
            IpAddr::V4(v4) => v4 == Ipv4Addr::LOCALHOST,
            IpAddr::V6(v6) => v6 == Ipv6Addr::LOCALHOST,
        };
        if !ok_ip {
            return Err(Error::because(
                Errno::EINVAL,
                format!(
                    "loopback test allowlist only accepts exact 127.0.0.1:<port> or [::1]:<port> (got {addr})"
                ),
            ));
        }
        self.addrs.insert(addr);
        Ok(())
    }

    /// Parse comma-separated `127.0.0.1:<port>,[::1]:<port>` list; rejects any non-loopback entry.
    pub fn parse_csv(raw: &str) -> Result<Self, Error> {
        let mut out = Self::new();
        for item in raw.split(',') {
            let trimmed = item.trim();
            if trimmed.is_empty() {
                continue;
            }
            let addr: SocketAddr = trimmed.parse().map_err(|_| {
                Error::because(
                    Errno::EINVAL,
                    format!("invalid loopback test address '{trimmed}'"),
                )
            })?;
            out.insert(addr)?;
        }
        Ok(out)
    }

    pub fn contains(&self, addr: &SocketAddr) -> bool {
        self.addrs.contains(addr)
    }

    pub fn iter(&self) -> impl Iterator<Item = &SocketAddr> {
        self.addrs.iter()
    }
}

// =============================================================================
// CIDR & HostMatch Validation / Matching / Intersection
// =============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ParsedCidr {
    V4 { net: u32, prefix_len: u8 },
    V6 { net: u128, prefix_len: u8 },
}

impl ParsedCidr {
    fn parse(addr: &str, prefix_len: u8) -> Option<Self> {
        if has_forbidden_host_chars(addr) {
            return None;
        }
        match addr.parse::<IpAddr>().ok()? {
            IpAddr::V4(v4) => {
                if prefix_len > 32 {
                    return None;
                }
                let mask = if prefix_len == 0 {
                    0u32
                } else {
                    !0u32 << (32 - prefix_len)
                };
                Some(Self::V4 {
                    net: u32::from(v4) & mask,
                    prefix_len,
                })
            }
            IpAddr::V6(v6) => {
                if prefix_len > 128 {
                    return None;
                }
                let mask = if prefix_len == 0 {
                    0u128
                } else {
                    !0u128 << (128 - prefix_len)
                };
                Some(Self::V6 {
                    net: u128::from(v6) & mask,
                    prefix_len,
                })
            }
        }
    }

    fn contains(self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::V4 { net, prefix_len }, IpAddr::V4(v4)) => {
                let mask = if prefix_len == 0 {
                    0u32
                } else {
                    !0u32 << (32 - prefix_len)
                };
                (u32::from(v4) & mask) == net
            }
            (Self::V6 { net, prefix_len }, IpAddr::V6(v6)) => {
                let mask = if prefix_len == 0 {
                    0u128
                } else {
                    !0u128 << (128 - prefix_len)
                };
                (u128::from(v6) & mask) == net
            }
            _ => false,
        }
    }

    fn intersect(self, other: Self) -> Option<Self> {
        match (self, other) {
            (
                Self::V4 {
                    net: n1,
                    prefix_len: p1,
                },
                Self::V4 {
                    net: n2,
                    prefix_len: p2,
                },
            ) => {
                let p_min = p1.min(p2);
                let mask = if p_min == 0 {
                    0u32
                } else {
                    !0u32 << (32 - p_min)
                };
                if (n1 & mask) != (n2 & mask) {
                    return None;
                }
                if p1 >= p2 {
                    Some(Self::V4 {
                        net: n1,
                        prefix_len: p1,
                    })
                } else {
                    Some(Self::V4 {
                        net: n2,
                        prefix_len: p2,
                    })
                }
            }
            (
                Self::V6 {
                    net: n1,
                    prefix_len: p1,
                },
                Self::V6 {
                    net: n2,
                    prefix_len: p2,
                },
            ) => {
                let p_min = p1.min(p2);
                let mask = if p_min == 0 {
                    0u128
                } else {
                    !0u128 << (128 - p_min)
                };
                if (n1 & mask) != (n2 & mask) {
                    return None;
                }
                if p1 >= p2 {
                    Some(Self::V6 {
                        net: n1,
                        prefix_len: p1,
                    })
                } else {
                    Some(Self::V6 {
                        net: n2,
                        prefix_len: p2,
                    })
                }
            }
            _ => None,
        }
    }

    fn to_host_match(self) -> HostMatch {
        match self {
            Self::V4 { net, prefix_len } => HostMatch::Cidr {
                addr: Ipv4Addr::from(net).to_string(),
                prefix_len,
            },
            Self::V6 { net, prefix_len } => HostMatch::Cidr {
                addr: Ipv6Addr::from(net).to_string(),
                prefix_len,
            },
        }
    }

    /// True if the entire CIDR is wholly contained within a single denied
    /// private/loopback/bogon range (used when intersecting with `AnyPublic`).
    fn is_wholly_denied(self) -> bool {
        match self {
            Self::V4 { net, prefix_len } => {
                // Exact list matching `is_denied_ipv4` (224.0.0.0/4 + 240.0.0.0/4 == 224.0.0.0/3).
                const DENIED_V4: &[(u32, u8)] = &[
                    (u32::from_be_bytes([0, 0, 0, 0]), 8),
                    (u32::from_be_bytes([10, 0, 0, 0]), 8),
                    (u32::from_be_bytes([100, 64, 0, 0]), 10),
                    (u32::from_be_bytes([127, 0, 0, 0]), 8),
                    (u32::from_be_bytes([169, 254, 0, 0]), 16),
                    (u32::from_be_bytes([172, 16, 0, 0]), 12),
                    (u32::from_be_bytes([192, 0, 0, 0]), 24),
                    (u32::from_be_bytes([192, 0, 2, 0]), 24),
                    (u32::from_be_bytes([192, 88, 99, 0]), 24),
                    (u32::from_be_bytes([192, 168, 0, 0]), 16),
                    (u32::from_be_bytes([198, 18, 0, 0]), 15),
                    (u32::from_be_bytes([198, 51, 100, 0]), 24),
                    (u32::from_be_bytes([203, 0, 113, 0]), 24),
                    (u32::from_be_bytes([224, 0, 0, 0]), 3),
                ];
                DENIED_V4.iter().any(|&(d_net, d_len)| {
                    if prefix_len < d_len {
                        return false;
                    }
                    let mask = if d_len == 0 { 0 } else { !0u32 << (32 - d_len) };
                    (net & mask) == d_net
                })
            }
            Self::V6 { net, prefix_len } => {
                // Exact list matching `is_denied_ipv6`.
                const DENIED_V6: &[(u128, u8)] = &[
                    (0u128, 96),                                         // ::/96 (covers ::/128, ::1/128)
                    (0x0000_0000_0000_0000_0000_ffff_0000_0000u128, 96), // ::ffff:0:0/96
                    (0x0000_0000_0000_0000_ffff_0000_0000_0000u128, 96), // ::ffff:0:0:0/96
                    (0x0064_ff9b_0000_0000_0000_0000_0000_0000u128, 96), // 64:ff9b::/96
                    (0x0064_ff9b_0001_0000_0000_0000_0000_0000u128, 48), // 64:ff9b:1::/48
                    (0x0100_0000_0000_0000_0000_0000_0000_0000u128, 64), // 100::/64
                    (0x2001_0000_0000_0000_0000_0000_0000_0000u128, 32), // 2001::/32
                    (0x2001_0002_0000_0000_0000_0000_0000_0000u128, 48), // 2001:2::/48
                    (0x2001_0010_0000_0000_0000_0000_0000_0000u128, 28), // 2001:10::/28
                    (0x2001_0020_0000_0000_0000_0000_0000_0000u128, 28), // 2001:20::/28
                    (0x2001_0db8_0000_0000_0000_0000_0000_0000u128, 32), // 2001:db8::/32
                    (0x2002_0000_0000_0000_0000_0000_0000_0000u128, 16), // 2002::/16
                    (0xfc00_0000_0000_0000_0000_0000_0000_0000u128, 7),  // fc00::/7
                    (0xfe80_0000_0000_0000_0000_0000_0000_0000u128, 10), // fe80::/10
                    (0xfec0_0000_0000_0000_0000_0000_0000_0000u128, 10), // fec0::/10
                    (0xff00_0000_0000_0000_0000_0000_0000_0000u128, 8),  // ff00::/8
                ];
                DENIED_V6.iter().any(|&(d_net, d_len)| {
                    if prefix_len < d_len {
                        return false;
                    }
                    let mask = if d_len == 0 {
                        0
                    } else {
                        !0u128 << (128 - d_len)
                    };
                    (net & mask) == d_net
                })
            }
        }
    }
}

fn valid_suffix_domain(raw: &str) -> Result<String, Error> {
    let lower = parse_valid_hostname(raw).map_err(|f| f.into_error())?;
    let label_count = lower.split('.').count();
    if label_count < 2 {
        return Err(Error::because(
            Errno::EINVAL,
            "HostMatch::Suffix requires at least 2 DNS labels",
        ));
    }
    Ok(lower)
}

fn is_strict_subdomain(candidate: &str, suffix: &str) -> bool {
    candidate
        .strip_suffix(suffix)
        .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() >= 2)
}

impl HostMatch {
    /// Validate and canonicalize this `HostMatch`.
    pub fn canonicalize(&self) -> Result<Self, Error> {
        match self {
            Self::Exact(s) => match parse_target_host(s).map_err(|f| f.into_error())? {
                ParsedHost::Ip(ip) => Ok(Self::Exact(ip.to_string())),
                ParsedHost::Domain(d) => Ok(Self::Exact(d)),
            },
            Self::Suffix(s) => Ok(Self::Suffix(valid_suffix_domain(s)?)),
            Self::Cidr { addr, prefix_len } => {
                let parsed = ParsedCidr::parse(addr, *prefix_len).ok_or_else(|| {
                    Error::because(Errno::EINVAL, "invalid CIDR address or prefix length")
                })?;
                Ok(parsed.to_host_match())
            }
            Self::AnyPublic => Ok(Self::AnyPublic),
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        self.canonicalize().map(|_| ())
    }

    /// True if this matcher matches a canonical target host (excluding SSRF/loopback checks).
    /// Note: `AnyPublic` matches only non-denied public hosts/IPs.
    pub fn matches_parsed(&self, target: &ParsedHost) -> bool {
        match (self, target) {
            (Self::Exact(rule), ParsedHost::Ip(ip)) => rule.parse::<IpAddr>().ok() == Some(*ip),
            (Self::Exact(rule), ParsedHost::Domain(dom)) => {
                parse_valid_hostname(rule).ok().as_deref() == Some(dom.as_str())
            }
            (Self::Suffix(suf), ParsedHost::Domain(dom)) => valid_suffix_domain(suf)
                .ok()
                .is_some_and(|s| is_strict_subdomain(dom, &s)),
            (Self::Suffix(_), ParsedHost::Ip(_)) => false,
            (Self::Cidr { addr, prefix_len }, ParsedHost::Ip(ip)) => {
                ParsedCidr::parse(addr, *prefix_len).is_some_and(|c| c.contains(*ip))
            }
            (Self::Cidr { .. }, ParsedHost::Domain(_)) => false,
            (Self::AnyPublic, ParsedHost::Ip(ip)) => !is_denied_ip(*ip),
            (Self::AnyPublic, ParsedHost::Domain(dom)) => !is_denied_hostname(dom),
        }
    }

    /// Exact monotonic intersection of two validated `HostMatch` matchers.
    pub fn intersect(&self, other: &Self) -> Option<Self> {
        let a = self.canonicalize().ok()?;
        let b = other.canonicalize().ok()?;
        match (a, b) {
            (Self::AnyPublic, Self::AnyPublic) => Some(Self::AnyPublic),
            (Self::AnyPublic, other) | (other, Self::AnyPublic) => match &other {
                Self::Exact(s) => match parse_target_host(s).ok()? {
                    ParsedHost::Ip(ip) if !is_denied_ip(ip) => Some(other),
                    ParsedHost::Domain(d) if !is_denied_hostname(&d) => Some(other),
                    _ => None,
                },
                Self::Suffix(s) => (!is_denied_hostname(s)).then_some(other),
                Self::Cidr { addr, prefix_len } => {
                    let c = ParsedCidr::parse(addr, *prefix_len)?;
                    (!c.is_wholly_denied()).then_some(other)
                }
                Self::AnyPublic => Some(Self::AnyPublic),
            },
            (Self::Exact(x), Self::Exact(y)) => (x == y).then_some(Self::Exact(x)),
            (Self::Exact(x), Self::Suffix(s)) | (Self::Suffix(s), Self::Exact(x)) => {
                match parse_target_host(&x).ok()? {
                    ParsedHost::Domain(d) if is_strict_subdomain(&d, &s) => Some(Self::Exact(d)),
                    _ => None,
                }
            }
            (Self::Exact(x), Self::Cidr { addr, prefix_len })
            | (Self::Cidr { addr, prefix_len }, Self::Exact(x)) => {
                let ip = x.parse::<IpAddr>().ok()?;
                // Never allow `Cidr` (e.g. `0.0.0.0/0` or `::/0` obtained via `AnyPublic`) to
                // elevate into an explicit `Exact` grant for a private/loopback/bogon IP!
                // Only `Exact(ip) ∩ Exact(ip)` preserves a loopback grant.
                if is_denied_ip(ip) {
                    return None;
                }
                let c = ParsedCidr::parse(&addr, prefix_len)?;
                c.contains(ip).then_some(Self::Exact(ip.to_string()))
            }
            (Self::Suffix(s1), Self::Suffix(s2)) => {
                if s1 == s2 || is_strict_subdomain(&s1, &s2) {
                    Some(Self::Suffix(s1))
                } else if is_strict_subdomain(&s2, &s1) {
                    Some(Self::Suffix(s2))
                } else {
                    None
                }
            }
            (
                Self::Cidr {
                    addr: a1,
                    prefix_len: p1,
                },
                Self::Cidr {
                    addr: a2,
                    prefix_len: p2,
                },
            ) => {
                let c1 = ParsedCidr::parse(&a1, p1)?;
                let c2 = ParsedCidr::parse(&a2, p2)?;
                c1.intersect(c2).map(ParsedCidr::to_host_match)
            }
            (Self::Suffix(_), Self::Cidr { .. }) | (Self::Cidr { .. }, Self::Suffix(_)) => None,
        }
    }
}

fn coalesce_port_ranges(mut ranges: Vec<PortRange>) -> Vec<PortRange> {
    if ranges.is_empty() {
        return ranges;
    }
    ranges.sort();
    let mut out: Vec<PortRange> = Vec::with_capacity(ranges.len());
    for r in ranges {
        if let Some(last) = out.last_mut()
            && r.start <= last.end.saturating_add(1)
        {
            last.end = last.end.max(r.end);
            continue;
        }
        out.push(r);
    }
    out
}

fn intersect_port_ranges(a: &[PortRange], b: &[PortRange]) -> Option<Vec<PortRange>> {
    let mut overlaps = Vec::new();
    for r1 in a {
        for r2 in b {
            if let Some(ov) = r1.intersect(r2) {
                overlaps.push(ov);
            }
        }
    }
    let coalesced = coalesce_port_ranges(overlaps);
    if coalesced.is_empty() || coalesced.len() > NET_MAX_PORT_RANGES {
        return None;
    }
    Some(coalesced)
}

impl EgressRule {
    pub fn validate(&self) -> Result<(), Error> {
        self.host.validate()?;
        if self.ports.is_empty() || self.ports.len() > NET_MAX_PORT_RANGES {
            return Err(Error::because(
                Errno::EINVAL,
                "EgressRule must contain between 1 and NET_MAX_PORT_RANGES port ranges",
            ));
        }
        if self.ports.iter().any(|p| !p.is_valid()) {
            return Err(Error::because(
                Errno::EINVAL,
                "invalid port range (must satisfy 1 <= start <= end)",
            ));
        }
        Ok(())
    }

    fn allows_port_and_tls(&self, port: u16, tls: TlsMode) -> bool {
        port != 0 && self.tls.allows(tls) && self.ports.iter().any(|r| r.contains(port))
    }
}

impl NetScope {
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.rules.len() > NET_MAX_RULES {
            return Err(Error::because(
                Errno::EINVAL,
                format!("NetScope exceeds maximum {NET_MAX_RULES} rules"),
            ));
        }
        for rule in &self.rules {
            rule.validate()?;
        }
        self.quota.validate()?;
        Ok(())
    }

    /// Monotonic pairwise intersection of two `NetScope` policies.
    /// Fails closed to `None` when empty, disjoint, invalid, or exceeding `NET_MAX_RULES`.
    pub fn attenuate(&self, requested: &Self) -> Option<Self> {
        if self.rules.is_empty() || requested.rules.is_empty() {
            return None;
        }
        self.validate().ok()?;
        requested.validate().ok()?;
        let quota = self.quota.attenuate(&requested.quota)?;
        let mut rules: Vec<EgressRule> = Vec::new();
        for r1 in &self.rules {
            for r2 in &requested.rules {
                let Some(host) = r1.host.intersect(&r2.host) else {
                    continue;
                };
                let Some(tls) = r1.tls.intersect(r2.tls) else {
                    continue;
                };
                let Some(ports) = intersect_port_ranges(&r1.ports, &r2.ports) else {
                    continue;
                };
                let candidate = EgressRule { host, ports, tls };
                if !rules.contains(&candidate) {
                    if rules.len() >= NET_MAX_RULES {
                        return None;
                    }
                    rules.push(candidate);
                }
            }
        }
        if rules.is_empty() {
            return None;
        }
        Some(Self { rules, quota })
    }

    /// Evaluate whether an outbound stream request `(host, port, tls)` is permitted under `self`
    /// and the optional two-key `allowlist` (which is empty in production).
    pub fn check_egress(
        &self,
        host: &str,
        port: u16,
        tls: TlsMode,
        allowlist: &LoopbackTestAllowlist,
    ) -> Result<ParsedHost, NetFailure> {
        if port == 0 {
            return Err(NetFailure::new(
                Errno::EINVAL,
                NetErrorKind::InvalidArgument,
                "port 0 is not allowed",
            ));
        }
        let parsed = parse_target_host(host)?;
        if self.rules.is_empty() {
            return Err(NetFailure::new(
                Errno::EACCES,
                NetErrorKind::PolicyDenied,
                "outbound network access denied by policy",
            ));
        }
        if self.validate().is_err() {
            return Err(NetFailure::new(
                Errno::EACCES,
                NetErrorKind::PolicyDenied,
                "invalid network egress policy",
            ));
        }
        match &parsed {
            ParsedHost::Ip(ip) => {
                let addr = SocketAddr::new(*ip, port);
                if allowlist.contains(&addr) {
                    // Two-key test-only loopback gate: requires BOTH allowlist entry AND explicit
                    // `HostMatch::Exact("127.0.0.1" | "::1")` matching `(port, tls)`.
                    let explicit_exact = self.rules.iter().any(|r| {
                        r.allows_port_and_tls(port, tls)
                            && matches!(&r.host, HostMatch::Exact(s) if s.parse::<IpAddr>().ok() == Some(*ip))
                    });
                    if explicit_exact {
                        return Ok(parsed);
                    }
                    return Err(NetFailure::new(
                        Errno::EACCES,
                        NetErrorKind::PolicyDenied,
                        "loopback test target requires explicit Exact host rule in NetScope",
                    ));
                }
                if is_denied_ip(*ip) {
                    return Err(NetFailure::new(
                        Errno::EACCES,
                        NetErrorKind::PrivateAddressDenied,
                        format!("egress to private/bogon/loopback address {ip} is prohibited"),
                    ));
                }
                if self
                    .rules
                    .iter()
                    .any(|r| r.allows_port_and_tls(port, tls) && r.host.matches_parsed(&parsed))
                {
                    Ok(parsed)
                } else {
                    Err(NetFailure::new(
                        Errno::EACCES,
                        NetErrorKind::PolicyDenied,
                        format!("egress to {ip}:{port} denied by policy"),
                    ))
                }
            }
            ParsedHost::Domain(dom) => {
                if is_denied_hostname(dom) {
                    return Err(NetFailure::new(
                        Errno::EACCES,
                        NetErrorKind::PrivateAddressDenied,
                        format!("egress to internal/local hostname '{dom}' is prohibited"),
                    ));
                }
                if self
                    .rules
                    .iter()
                    .any(|r| r.allows_port_and_tls(port, tls) && r.host.matches_parsed(&parsed))
                {
                    Ok(parsed)
                } else {
                    Err(NetFailure::new(
                        Errno::EACCES,
                        NetErrorKind::PolicyDenied,
                        format!("egress to {dom}:{port} denied by policy"),
                    ))
                }
            }
        }
    }

    /// Re-verify a concrete resolved or connected `IpAddr` before/after TCP connect to prevent
    /// DNS rebinding into private, bogon, or loopback ranges.
    pub fn check_resolved_ip(
        &self,
        original: &ParsedHost,
        ip: IpAddr,
        port: u16,
        tls: TlsMode,
        allowlist: &LoopbackTestAllowlist,
    ) -> Result<(), NetFailure> {
        let addr = SocketAddr::new(ip, port);
        if allowlist.contains(&addr) {
            // Never permit a DNS hostname to rebind to an allowlisted loopback address!
            let was_exact_ip = matches!(original, ParsedHost::Ip(orig_ip) if *orig_ip == ip);
            let explicit_exact = self.rules.iter().any(|r| {
                r.allows_port_and_tls(port, tls)
                    && matches!(&r.host, HostMatch::Exact(s) if s.parse::<IpAddr>().ok() == Some(ip))
            });
            if was_exact_ip && explicit_exact {
                return Ok(());
            }
            return Err(NetFailure::new(
                Errno::EACCES,
                NetErrorKind::PrivateAddressDenied,
                "DNS resolution or connection to loopback address is prohibited",
            ));
        }
        if is_denied_ip(ip) {
            return Err(NetFailure::new(
                Errno::EACCES,
                NetErrorKind::PrivateAddressDenied,
                "resolved address is in a prohibited private/bogon range",
            ));
        }
        Ok(())
    }

    /// Evaluate whether resolving `host` is permitted (checks syntax, SSRF hostname denial, and
    /// at least one rule matching `host`; if `port != 0`, requires the rule to also permit `port`).
    pub fn check_resolve(
        &self,
        host: &str,
        port: u16,
        allowlist: &LoopbackTestAllowlist,
    ) -> Result<ParsedHost, NetFailure> {
        let parsed = parse_target_host(host)?;
        if self.rules.is_empty() || self.validate().is_err() {
            return Err(NetFailure::new(
                Errno::EACCES,
                NetErrorKind::PolicyDenied,
                "network resolution denied by policy",
            ));
        }
        let port_ok = |r: &EgressRule| port == 0 || r.ports.iter().any(|pr| pr.contains(port));
        match &parsed {
            ParsedHost::Ip(ip) => {
                if port != 0 && allowlist.contains(&SocketAddr::new(*ip, port)) {
                    let ok = self.rules.iter().any(|r| {
                        port_ok(r)
                            && matches!(&r.host, HostMatch::Exact(s) if s.parse::<IpAddr>().ok() == Some(*ip))
                    });
                    if ok {
                        return Ok(parsed);
                    }
                    return Err(NetFailure::new(
                        Errno::EACCES,
                        NetErrorKind::PolicyDenied,
                        "loopback resolve denied by policy",
                    ));
                }
                if is_denied_ip(*ip) {
                    return Err(NetFailure::new(
                        Errno::EACCES,
                        NetErrorKind::PrivateAddressDenied,
                        format!("private/bogon address {ip} prohibited"),
                    ));
                }
                if self
                    .rules
                    .iter()
                    .any(|r| port_ok(r) && r.host.matches_parsed(&parsed))
                {
                    Ok(parsed)
                } else {
                    Err(NetFailure::new(
                        Errno::EACCES,
                        NetErrorKind::PolicyDenied,
                        "resolve target denied by policy",
                    ))
                }
            }
            ParsedHost::Domain(dom) => {
                if is_denied_hostname(dom) {
                    return Err(NetFailure::new(
                        Errno::EACCES,
                        NetErrorKind::PrivateAddressDenied,
                        format!("internal/local hostname '{dom}' prohibited"),
                    ));
                }
                if self
                    .rules
                    .iter()
                    .any(|r| port_ok(r) && r.host.matches_parsed(&parsed))
                {
                    Ok(parsed)
                } else {
                    Err(NetFailure::new(
                        Errno::EACCES,
                        NetErrorKind::PolicyDenied,
                        "resolve target denied by policy",
                    ))
                }
            }
        }
    }
}

/// Fast client-side / `netd`-side syntactic & SSRF pre-validation (runs before calling host).
/// Note: allows `127.0.0.1` and `::1` through to the host bridge ONLY so the host's two-key
/// `LoopbackTestAllowlist` can decide (the host denies them unless explicitly allowlisted AND
/// permitted by `NetScope`). Always denies non-canonical/obfuscated IPs, port 0, `::ffff:*`,
/// private RFC1918/IMDS ranges, and internal hostnames (`localhost`, `*.local`, etc.).
pub fn prevalidate_connect_target(host: &str, port: u16) -> Result<ParsedHost, NetFailure> {
    if port == 0 {
        return Err(NetFailure::new(
            Errno::EINVAL,
            NetErrorKind::InvalidArgument,
            "port 0 is not allowed",
        ));
    }
    let parsed = parse_target_host(host)?;
    match &parsed {
        ParsedHost::Ip(ip) => {
            let is_exact_loopback = matches!(
                ip,
                IpAddr::V4(v4) if *v4 == Ipv4Addr::LOCALHOST
            ) || matches!(
                ip,
                IpAddr::V6(v6) if *v6 == Ipv6Addr::LOCALHOST
            );
            if !is_exact_loopback && is_denied_ip(*ip) {
                return Err(NetFailure::new(
                    Errno::EACCES,
                    NetErrorKind::PrivateAddressDenied,
                    format!("egress to private/bogon address {ip} is prohibited"),
                ));
            }
        }
        ParsedHost::Domain(dom) => {
            if is_denied_hostname(dom) {
                return Err(NetFailure::new(
                    Errno::EACCES,
                    NetErrorKind::PrivateAddressDenied,
                    format!("egress to internal/local hostname '{dom}' is prohibited"),
                ));
            }
        }
    }
    Ok(parsed)
}

// =============================================================================
// Control & Data Framing Codecs
// =============================================================================

/// Encode a length-prefixed JSON control message (`[u32_be len][json]`, `1 <= len <= NET_CONTROL_MAX_BYTES`).
pub fn encode_control_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let payload =
        serde_json::to_vec(value).map_err(|e| Error::because(Errno::EINVAL, e.to_string()))?;
    if payload.is_empty() || payload.len() > NET_CONTROL_MAX_BYTES {
        return Err(Error::because(
            Errno::E2BIG,
            format!("netd control frame exceeds {NET_CONTROL_MAX_BYTES} bytes"),
        ));
    }
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Decode a JSON control payload (without the 4-byte length prefix).
pub fn decode_control_payload<T: DeserializeOwned>(payload: &[u8]) -> Result<T, Error> {
    if payload.is_empty() {
        return Err(Error::because(Errno::EINVAL, "empty netd control payload"));
    }
    if payload.len() > NET_CONTROL_MAX_BYTES {
        return Err(Errno::E2BIG.into());
    }
    serde_json::from_slice(payload).map_err(|e| Error::because(Errno::EINVAL, e.to_string()))
}

/// Read one `[u32_be len][json]` control frame from a byte reader closure.
pub fn read_control_frame(
    mut recv: impl FnMut(&mut [u8]) -> Result<usize, Errno>,
) -> Result<Vec<u8>, Error> {
    let mut hdr = [0u8; 4];
    let mut got = 0usize;
    while got < 4 {
        match recv(&mut hdr[got..]) {
            Ok(0) => {
                return Err(Error::because(
                    Errno::ECONNRESET,
                    "peer closed before netd control header",
                ));
            }
            Ok(n) => got += n,
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    let len = u32::from_be_bytes(hdr) as usize;
    if len == 0 || len > NET_CONTROL_MAX_BYTES {
        return Err(Error::because(
            if len == 0 {
                Errno::EINVAL
            } else {
                Errno::E2BIG
            },
            "invalid netd control frame length",
        ));
    }
    let mut payload = vec![0u8; len];
    let mut pos = 0usize;
    while pos < len {
        match recv(&mut payload[pos..]) {
            Ok(0) => {
                return Err(Error::because(
                    Errno::ECONNRESET,
                    "peer closed mid netd control frame",
                ));
            }
            Ok(n) => pos += n,
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(payload)
}

/// Write a complete frame to a byte writer closure.
pub fn write_all_frame(
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

/// Encode a `DataFrame` in Unix-socket wire format: `[u8 tag][u32_be len][payload]`.
pub fn encode_unix_data_frame(frame: &DataFrame) -> Result<Vec<u8>, Error> {
    let (tag, payload): (u8, Vec<u8>) = match frame {
        DataFrame::Data(bytes) => {
            if bytes.len() > NET_DATA_CHUNK_MAX {
                return Err(Error::because(
                    Errno::EMSGSIZE,
                    "DATA frame exceeds NET_DATA_CHUNK_MAX",
                ));
            }
            (FRAME_DATA, bytes.clone())
        }
        DataFrame::Credit(n) => {
            if *n == 0 {
                return Err(Error::because(Errno::EINVAL, "CREDIT must be non-zero"));
            }
            (FRAME_CREDIT, n.to_be_bytes().to_vec())
        }
        DataFrame::HalfClose => (FRAME_HALF_CLOSE, Vec::new()),
        DataFrame::Cancel => (FRAME_CANCEL, Vec::new()),
        DataFrame::Closed(info) => {
            let json = serde_json::to_vec(info)
                .map_err(|e| Error::because(Errno::EINVAL, e.to_string()))?;
            if json.len() > NET_CONTROL_MAX_BYTES {
                return Err(Errno::E2BIG.into());
            }
            (FRAME_CLOSED, json)
        }
    };
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(tag);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Decode a `DataFrame` from `(tag, payload)` (shared between Unix-socket and WebSocket codecs).
pub fn decode_data_frame_body(tag: u8, payload: &[u8]) -> Result<DataFrame, Error> {
    match tag {
        FRAME_DATA => {
            if payload.len() > NET_DATA_CHUNK_MAX {
                return Err(Error::because(
                    Errno::EMSGSIZE,
                    "DATA frame exceeds NET_DATA_CHUNK_MAX",
                ));
            }
            Ok(DataFrame::Data(payload.to_vec()))
        }
        FRAME_CREDIT => {
            if payload.len() != 4 {
                return Err(Error::because(
                    Errno::EINVAL,
                    "CREDIT frame must carry 4 bytes",
                ));
            }
            let n = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
            if n == 0 {
                return Err(Error::because(Errno::EINVAL, "CREDIT must be non-zero"));
            }
            Ok(DataFrame::Credit(n))
        }
        FRAME_HALF_CLOSE => {
            if !payload.is_empty() {
                return Err(Error::because(
                    Errno::EINVAL,
                    "HALF_CLOSE frame must be empty",
                ));
            }
            Ok(DataFrame::HalfClose)
        }
        FRAME_CANCEL => {
            if !payload.is_empty() {
                return Err(Error::because(Errno::EINVAL, "CANCEL frame must be empty"));
            }
            Ok(DataFrame::Cancel)
        }
        FRAME_CLOSED => {
            if payload.len() > NET_CONTROL_MAX_BYTES {
                return Err(Errno::E2BIG.into());
            }
            let closed = if payload.is_empty() {
                StreamClosed::default()
            } else {
                serde_json::from_slice(payload)
                    .map_err(|e| Error::because(Errno::EINVAL, e.to_string()))?
            };
            Ok(DataFrame::Closed(closed))
        }
        _ => Err(Error::because(
            Errno::EINVAL,
            format!("unknown netd data frame tag 0x{tag:02x}"),
        )),
    }
}

/// Try decoding one Unix-socket `[u8 tag][u32_be len][payload]` frame from a streaming buffer.
/// Returns `Ok(Some((frame, consumed_bytes)))` if complete, `Ok(None)` if more bytes are needed.
pub fn try_decode_unix_data_frame(buf: &[u8]) -> Result<Option<(DataFrame, usize)>, Error> {
    if buf.len() < 5 {
        return Ok(None);
    }
    let tag = buf[0];
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    let max_len = match tag {
        FRAME_DATA => NET_DATA_CHUNK_MAX,
        FRAME_CREDIT => 4,
        FRAME_HALF_CLOSE | FRAME_CANCEL => 0,
        FRAME_CLOSED => NET_CONTROL_MAX_BYTES,
        _ => {
            return Err(Error::because(
                Errno::EINVAL,
                format!("unknown netd data frame tag 0x{tag:02x}"),
            ));
        }
    };
    if len > max_len {
        return Err(Error::because(
            Errno::EMSGSIZE,
            "netd data frame length exceeds bound",
        ));
    }
    let total = 5 + len;
    if buf.len() < total {
        return Ok(None);
    }
    let frame = decode_data_frame_body(tag, &buf[5..total])?;
    Ok(Some((frame, total)))
}

/// Encode a `DataFrame` in WebSocket binary message format: `[u8 tag][payload]`.
pub fn encode_ws_data_frame(frame: &DataFrame) -> Result<Vec<u8>, Error> {
    let unix = encode_unix_data_frame(frame)?;
    let mut out = Vec::with_capacity(unix.len() - 4);
    out.push(unix[0]);
    out.extend_from_slice(&unix[5..]);
    Ok(out)
}

/// Decode a `DataFrame` from a WebSocket binary message (`[u8 tag][payload]`).
pub fn decode_ws_data_frame(msg: &[u8]) -> Result<DataFrame, Error> {
    if msg.is_empty() {
        return Err(Error::because(
            Errno::EINVAL,
            "empty WebSocket binary data frame",
        ));
    }
    decode_data_frame_body(msg[0], &msg[1..])
}

// =============================================================================
// WASIX `AddrPort` (`__wasi_addr_port_t`) Codec
// =============================================================================

/// Encode a `SocketAddr` into the 20-byte WASIX `wasix_32v1` `__wasi_addr_port_t` layout:
/// - byte 0: tag (`1 = Inet4`, `2 = Inet6`)
/// - byte 1: 0 (alignment padding)
/// - bytes 2..4: `port` (u16 LE)
/// - bytes 4..8 (Inet4): 4 IPv4 octets `[n0, n1, n2, n3]`
/// - bytes 4..20 (Inet6): 8 `u16` segments in LE
pub fn encode_wasix_addr_port(addr: SocketAddr) -> [u8; WASIX_ADDR_PORT_SIZE] {
    let mut out = [0u8; WASIX_ADDR_PORT_SIZE];
    out[2..4].copy_from_slice(&addr.port().to_le_bytes());
    match addr {
        SocketAddr::V4(v4) => {
            out[0] = WASIX_ADDR_INET4;
            out[4..8].copy_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            out[0] = WASIX_ADDR_INET6;
            for (i, seg) in v6.ip().segments().iter().enumerate() {
                let off = 4 + i * 2;
                out[off..off + 2].copy_from_slice(&seg.to_le_bytes());
            }
        }
    }
    out
}

/// Decode a 20-byte WASIX `wasix_32v1` `__wasi_addr_port_t` buffer into a `SocketAddr`.
pub fn decode_wasix_addr_port(buf: &[u8]) -> Result<SocketAddr, Errno> {
    if buf.len() < WASIX_ADDR_PORT_SIZE {
        return Err(Errno::EINVAL);
    }
    let tag = buf[0];
    let port = u16::from_le_bytes([buf[2], buf[3]]);
    match tag {
        WASIX_ADDR_INET4 => {
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        WASIX_ADDR_INET6 => {
            let mut segs = [0u16; 8];
            for (i, slot) in segs.iter_mut().enumerate() {
                let off = 4 + i * 2;
                *slot = u16::from_le_bytes([buf[off], buf[off + 1]]);
            }
            let ip = Ipv6Addr::from(segs);
            Ok(SocketAddr::new(IpAddr::V6(ip), port))
        }
        WASIX_ADDR_UNSPEC => Err(Errno::EAFNOSUPPORT),
        _ => Err(Errno::EAFNOSUPPORT),
    }
}

/// Parse a `host:port` or `[ipv6]:port` string (such as `SocketInfo.remote_address`) into `IpAddr`.
pub fn extract_ip_from_socket_addr_str(raw: &str) -> Option<IpAddr> {
    let trimmed = raw.trim();
    if let Ok(sa) = trimmed.parse::<SocketAddr>() {
        return Some(sa.ip());
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Some(ip);
    }
    // Handle `[ipv6]` without port
    if let Some(inner) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
        && let Ok(ip) = inner.parse::<Ipv6Addr>()
    {
        return Some(IpAddr::V6(ip));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(host: HostMatch, ports: Vec<PortRange>, tls: TlsPolicy) -> EgressRule {
        EgressRule { host, ports, tls }
    }

    fn scope(rules: Vec<EgressRule>) -> NetScope {
        NetScope {
            rules,
            quota: NetQuota::default(),
        }
    }

    #[test]
    fn nt01_protocol_framing_and_deny_unknown_fields() {
        let req = NetdReq::Connect {
            host: "api.example.com".into(),
            port: 443,
            tls: TlsMode::On,
            mode: StreamMode::Framed,
            timeout_ms: Some(5000),
        };
        let encoded = encode_control_frame(&req).unwrap();
        let mut cursor = encoded.as_slice();
        let body = read_control_frame(|buf| {
            let n = buf.len().min(cursor.len()).min(11);
            buf[..n].copy_from_slice(&cursor[..n]);
            cursor = &cursor[n..];
            Ok(n)
        })
        .unwrap();
        assert_eq!(decode_control_payload::<NetdReq>(&body).unwrap(), req);

        // Unknown fields strictly rejected across all wire types.
        assert!(serde_json::from_str::<NetdReq>(r#"{"op":"status","uid":0}"#).is_err());
        assert!(serde_json::from_str::<HostNetReq>(r#"{"op":"status","token":"x"}"#).is_err());
        assert!(serde_json::from_str::<NetScope>(r#"{"rules":[],"extra":1}"#).is_err());
        assert!(
            serde_json::from_str::<NetQuota>(r#"{"max_concurrent_streams":4,"evil":true}"#)
                .is_err()
        );
        assert!(serde_json::from_str::<PortRange>(r#"{"start":80,"end":443,"extra":1}"#).is_err());

        // Data frames round-trip over both Unix-socket and WebSocket binary codecs.
        let frames = vec![
            DataFrame::Data(b"hello world".to_vec()),
            DataFrame::Credit(4096),
            DataFrame::HalfClose,
            DataFrame::Cancel,
            DataFrame::Closed(StreamClosed {
                errno: Some(Errno::EDQUOT),
                error: Some(NetErrorKind::QuotaExceeded),
                message: Some("byte cap".into()),
                bytes_sent: 100,
                bytes_received: 200,
            }),
        ];
        for f in frames {
            let u = encode_unix_data_frame(&f).unwrap();
            let (decoded_u, consumed) = try_decode_unix_data_frame(&u).unwrap().unwrap();
            assert_eq!(decoded_u, f);
            assert_eq!(consumed, u.len());
            // Partial frame returns Ok(None)
            assert!(
                try_decode_unix_data_frame(&u[..u.len() - 1])
                    .unwrap()
                    .is_none()
            );

            let w = encode_ws_data_frame(&f).unwrap();
            assert_eq!(decode_ws_data_frame(&w).unwrap(), f);
        }

        // Oversized DATA frame rejected.
        assert_eq!(
            encode_unix_data_frame(&DataFrame::Data(vec![0u8; NET_DATA_CHUNK_MAX + 1]))
                .unwrap_err()
                .errno,
            Errno::EMSGSIZE
        );
        // Zero CREDIT rejected.
        assert_eq!(
            encode_unix_data_frame(&DataFrame::Credit(0))
                .unwrap_err()
                .errno,
            Errno::EINVAL
        );

        // WASIX AddrPort roundtrip for IPv4 & IPv6.
        let v4: SocketAddr = "93.184.216.34:443".parse().unwrap();
        assert_eq!(
            decode_wasix_addr_port(&encode_wasix_addr_port(v4)).unwrap(),
            v4
        );
        let v6: SocketAddr = "[2606:2800:220:1:248:1893:25c8:1946]:8443".parse().unwrap();
        assert_eq!(
            decode_wasix_addr_port(&encode_wasix_addr_port(v6)).unwrap(),
            v6
        );
        let lo6: SocketAddr = "[::1]:9999".parse().unwrap();
        assert_eq!(
            decode_wasix_addr_port(&encode_wasix_addr_port(lo6)).unwrap(),
            lo6
        );
    }

    #[test]
    fn nt02_policy_attenuation_is_exact_and_monotonic() {
        let empty = NetScope::default();
        assert!(empty.is_empty());
        let any_https = scope(vec![rule(
            HostMatch::AnyPublic,
            vec![PortRange {
                start: 80,
                end: 443,
            }],
            TlsPolicy::Any,
        )]);
        assert!(empty.attenuate(&any_https).is_none());
        assert!(any_https.attenuate(&empty).is_none());

        // Suffix matching: strict subdomains only, never bare domain or sibling suffix.
        let suf = scope(vec![rule(
            HostMatch::Suffix("example.com".into()),
            vec![PortRange::single(443)],
            TlsPolicy::TlsOnly,
        )]);
        let no_lo = LoopbackTestAllowlist::new();
        assert!(
            suf.check_egress("api.example.com", 443, TlsMode::On, &no_lo)
                .is_ok()
        );
        assert!(
            suf.check_egress("a.b.example.com", 443, TlsMode::On, &no_lo)
                .is_ok()
        );
        // Bare domain MUST NOT match Suffix!
        assert_eq!(
            suf.check_egress("example.com", 443, TlsMode::On, &no_lo)
                .unwrap_err()
                .errno,
            Errno::EACCES
        );
        assert_eq!(
            suf.check_egress("badexample.com", 443, TlsMode::On, &no_lo)
                .unwrap_err()
                .errno,
            Errno::EACCES
        );
        // PlainOnly / Off rejected when TlsOnly!
        assert_eq!(
            suf.check_egress("api.example.com", 443, TlsMode::Off, &no_lo)
                .unwrap_err()
                .errno,
            Errno::EACCES
        );
        // Single-label suffix invalid.
        let single_label = scope(vec![rule(
            HostMatch::Suffix("com".into()),
            vec![PortRange::single(443)],
            TlsPolicy::Any,
        )]);
        assert!(single_label.validate().is_err());
        assert!(any_https.attenuate(&single_label).is_none());

        // Suffix ∩ Exact -> Exact; Suffix ∩ narrower Suffix -> narrower Suffix.
        let exact = scope(vec![rule(
            HostMatch::Exact("API.Example.COM".into()),
            vec![PortRange {
                start: 400,
                end: 500,
            }],
            TlsPolicy::Any,
        )]);
        let inter = suf.attenuate(&exact).unwrap();
        assert_eq!(inter.rules.len(), 1);
        assert_eq!(
            inter.rules[0].host,
            HostMatch::Exact("api.example.com".into())
        );
        assert_eq!(inter.rules[0].ports, vec![PortRange::single(443)]);
        assert_eq!(inter.rules[0].tls, TlsPolicy::TlsOnly);

        // Cannot widen back after attenuation.
        assert_eq!(inter.attenuate(&any_https).unwrap().rules, inter.rules);

        // PlainOnly ∩ TlsOnly -> None.
        let plain = scope(vec![rule(
            HostMatch::Exact("api.example.com".into()),
            vec![PortRange::single(443)],
            TlsPolicy::PlainOnly,
        )]);
        assert!(suf.attenuate(&plain).is_none());

        // CIDR ∩ CIDR -> narrower CIDR; disjoint CIDRs -> None.
        let c16 = scope(vec![rule(
            HostMatch::Cidr {
                addr: "93.184.0.0".into(),
                prefix_len: 16,
            },
            vec![PortRange {
                start: 1,
                end: 1024,
            }],
            TlsPolicy::Any,
        )]);
        let c24 = scope(vec![rule(
            HostMatch::Cidr {
                addr: "93.184.216.99".into(),
                prefix_len: 24,
            },
            vec![PortRange {
                start: 80,
                end: 8080,
            }],
            TlsPolicy::PlainOnly,
        )]);
        let ci = c16.attenuate(&c24).unwrap();
        assert_eq!(
            ci.rules[0].host,
            HostMatch::Cidr {
                addr: "93.184.216.0".into(),
                prefix_len: 24
            }
        );
        assert_eq!(
            ci.rules[0].ports,
            vec![PortRange {
                start: 80,
                end: 1024
            }]
        );
        assert_eq!(ci.rules[0].tls, TlsPolicy::PlainOnly);

        // AnyPublic ∩ Exact("127.0.0.1") MUST fail closed (never elevate into loopback exact!).
        let lo_exact = scope(vec![rule(
            HostMatch::Exact("127.0.0.1".into()),
            vec![PortRange::single(8080)],
            TlsPolicy::PlainOnly,
        )]);
        assert!(any_https.attenuate(&lo_exact).is_none());

        // Multi-step attenuation chain AnyPublic -> Cidr("0.0.0.0/0") -> Exact("127.0.0.1") and
        // AnyPublic -> Cidr("::/0") -> Exact("::1") MUST NEVER elevate into a loopback Exact grant!
        let any_all = scope(vec![rule(
            HostMatch::AnyPublic,
            vec![PortRange {
                start: 1,
                end: 65535,
            }],
            TlsPolicy::Any,
        )]);
        let cidr_v4_all = scope(vec![rule(
            HostMatch::Cidr {
                addr: "0.0.0.0".into(),
                prefix_len: 0,
            },
            vec![PortRange {
                start: 1,
                end: 65535,
            }],
            TlsPolicy::Any,
        )]);
        let step1_v4 = any_all.attenuate(&cidr_v4_all).unwrap();
        assert!(step1_v4.attenuate(&lo_exact).is_none());
        assert!(cidr_v4_all.attenuate(&lo_exact).is_none());

        let cidr_v6_all = scope(vec![rule(
            HostMatch::Cidr {
                addr: "::".into(),
                prefix_len: 0,
            },
            vec![PortRange {
                start: 1,
                end: 65535,
            }],
            TlsPolicy::Any,
        )]);
        let lo6_exact = scope(vec![rule(
            HostMatch::Exact("::1".into()),
            vec![PortRange::single(8080)],
            TlsPolicy::PlainOnly,
        )]);
        let step1_v6 = any_all.attenuate(&cidr_v6_all).unwrap();
        assert!(step1_v6.attenuate(&lo6_exact).is_none());
        assert!(cidr_v6_all.attenuate(&lo6_exact).is_none());

        // Only Exact(loopback) ∩ Exact(loopback) preserves an explicit loopback grant.
        assert_eq!(lo_exact.attenuate(&lo_exact).unwrap().rules, lo_exact.rules);
        assert_eq!(
            lo6_exact.attenuate(&lo6_exact).unwrap().rules,
            lo6_exact.rules
        );

        // Public CIDR ∩ public Exact still intersects cleanly.
        let pub_exact = scope(vec![rule(
            HostMatch::Exact("93.184.216.34".into()),
            vec![PortRange::single(443)],
            TlsPolicy::Any,
        )]);
        assert_eq!(
            c16.attenuate(&pub_exact).unwrap().rules[0].host,
            HostMatch::Exact("93.184.216.34".into())
        );

        // IPv6 CIDR `2001::/27` spans public space (`2001:1::/32..2001:f::/32`) so must NOT be
        // over-denied when intersected with `AnyPublic`, whereas `2001:db8::/32` IS wholly denied.
        let v6_mixed = scope(vec![rule(
            HostMatch::Cidr {
                addr: "2001::".into(),
                prefix_len: 27,
            },
            vec![PortRange::single(443)],
            TlsPolicy::Any,
        )]);
        assert!(any_all.attenuate(&v6_mixed).is_some());
        let v6_doc = scope(vec![rule(
            HostMatch::Cidr {
                addr: "2001:db8::".into(),
                prefix_len: 32,
            },
            vec![PortRange::single(443)],
            TlsPolicy::Any,
        )]);
        assert!(any_all.attenuate(&v6_doc).is_none());

        // Quota clamps to hard ceilings and takes min field-wise.
        let mut big = any_https.clone();
        big.quota = NetQuota {
            max_concurrent_streams: 999,
            max_bytes_per_stream: u64::MAX,
            max_bytes_per_sec: Some(1_000_000),
            connect_timeout_ms: 999_999,
            idle_timeout_ms: 999_999,
            max_stream_lifetime_ms: 999_999_999,
        };
        let mut small = any_https.clone();
        small.quota = NetQuota {
            max_concurrent_streams: 4,
            max_bytes_per_stream: 4096,
            max_bytes_per_sec: None,
            connect_timeout_ms: 5000,
            idle_timeout_ms: 999_999,
            max_stream_lifetime_ms: 60_000,
        };
        let q = big.attenuate(&small).unwrap().quota;
        assert_eq!(q.max_concurrent_streams, 4);
        assert_eq!(q.max_bytes_per_stream, 4096);
        assert_eq!(q.max_bytes_per_sec, Some(1_000_000));
        assert_eq!(q.connect_timeout_ms, 5000);
        assert_eq!(q.idle_timeout_ms, IDLE_TIMEOUT_MS_CEILING);
        assert_eq!(q.max_stream_lifetime_ms, 60_000);
    }

    #[test]
    fn nt05_ssrf_private_bogon_obfuscation_and_two_key_loopback() {
        let any = scope(vec![rule(
            HostMatch::AnyPublic,
            vec![PortRange {
                start: 1,
                end: 65535,
            }],
            TlsPolicy::Any,
        )]);
        let empty_lo = LoopbackTestAllowlist::new();

        // Public IPv4 / IPv6 & domain permitted by AnyPublic.
        assert!(
            any.check_egress("93.184.216.34", 443, TlsMode::On, &empty_lo)
                .is_ok()
        );
        assert!(
            any.check_egress(
                "2606:2800:220:1:248:1893:25c8:1946",
                443,
                TlsMode::On,
                &empty_lo
            )
            .is_ok()
        );
        assert!(
            any.check_egress("example.com", 443, TlsMode::On, &empty_lo)
                .is_ok()
        );

        // Private / bogon IPv4s denied.
        for ip in [
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "100.127.255.254",
            "127.0.0.1",
            "127.12.34.56",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.254",
            "192.0.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.254",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            let err = any
                .check_egress(ip, 80, TlsMode::Off, &empty_lo)
                .unwrap_err();
            assert_eq!(err.errno, Errno::EACCES, "expected EACCES for {ip}");
            assert_eq!(
                err.kind,
                NetErrorKind::PrivateAddressDenied,
                "expected PrivateAddressDenied for {ip}"
            );
        }

        // Private / bogon / mapped IPv6s denied.
        for ip in [
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:93.184.216.34",
            "::127.0.0.1",
            "::ffff:0:127.0.0.1",
            "64:ff9b::127.0.0.1",
            "64:ff9b:1::1",
            "100::1",
            "2001::1",
            "2001:2::1",
            "2001:10::1",
            "2001:20::1",
            "2001:db8::1",
            "2002::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
        ] {
            let err = any
                .check_egress(ip, 80, TlsMode::Off, &empty_lo)
                .unwrap_err();
            assert_eq!(err.errno, Errno::EACCES, "expected EACCES for {ip}");
            assert_eq!(err.kind, NetErrorKind::PrivateAddressDenied, "for {ip}");
        }

        // Internal/local/single-label hostnames denied.
        for host in [
            "localhost",
            "intranet",
            "redis",
            "metadata",
            "metadata.goog",
            "sub.metadata.goog",
            "sub.localhost",
            "localhost.localdomain",
            "a.localdomain",
            "printer.local",
            "metadata.google.internal",
            "router.home.arpa",
            "1.0.0.127.in-addr.arpa",
            "nas.lan",
            "box.home",
            "wiki.corp",
            "hr.intranet",
        ] {
            let err = any
                .check_egress(host, 80, TlsMode::Off, &empty_lo)
                .unwrap_err();
            assert_eq!(err.errno, Errno::EACCES, "for {host}");
            assert_eq!(err.kind, NetErrorKind::PrivateAddressDenied, "for {host}");
        }

        // Redaction check: check_resolved_ip must not echo the resolved private IP.
        let rerr = any
            .check_resolved_ip(
                &ParsedHost::Domain("rebind.example.com".into()),
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 99)),
                443,
                TlsMode::On,
                &empty_lo,
            )
            .unwrap_err();
        assert_eq!(rerr.errno, Errno::EACCES);
        assert_eq!(rerr.kind, NetErrorKind::PrivateAddressDenied);
        assert!(
            !rerr.message.contains("10.42.7.99"),
            "resolved private IP must be redacted from error message: {}",
            rerr.message
        );

        // Obfuscated numeric/octal/hex/short IPs, zone IDs, and bad syntax rejected with EINVAL.
        for bad in [
            "2130706433",
            "0177.0.0.1",
            "127.1",
            "127.0.1",
            "0x7f000001",
            "0x7f.0.0.1",
            "fe80::1%eth0",
            "user@example.com",
            "example.com/path",
            "example.com?q=1",
            "example.com#frag",
            "example..com",
            ".example.com",
            "-bad.example.com",
            "bad-.example.com",
            "exa mple.com",
            "",
        ] {
            let err = any
                .check_egress(bad, 80, TlsMode::Off, &empty_lo)
                .unwrap_err();
            assert_eq!(err.errno, Errno::EINVAL, "expected EINVAL for '{bad}'");
        }
        // Port 0 rejected.
        assert_eq!(
            any.check_egress("example.com", 0, TlsMode::Off, &empty_lo)
                .unwrap_err()
                .errno,
            Errno::EINVAL
        );

        // Two-key test-only loopback allowlist.
        assert!(LoopbackTestAllowlist::parse_csv("10.0.0.1:80").is_err());
        assert!(LoopbackTestAllowlist::parse_csv("127.0.0.2:80").is_err());
        assert!(LoopbackTestAllowlist::parse_csv("[::ffff:127.0.0.1]:80").is_err());
        assert!(LoopbackTestAllowlist::parse_csv("127.0.0.1:0").is_err());
        let lo = LoopbackTestAllowlist::parse_csv("127.0.0.1:19001,[::1]:19002").unwrap();

        // Key 1 alone (allowlist without Exact rule in NetScope) -> DENIED!
        assert_eq!(
            any.check_egress("127.0.0.1", 19001, TlsMode::Off, &lo)
                .unwrap_err()
                .errno,
            Errno::EACCES
        );

        // Key 2 alone (Exact rule in NetScope without allowlist) -> DENIED!
        let lo_scope = scope(vec![
            rule(
                HostMatch::Exact("127.0.0.1".into()),
                vec![PortRange::single(19001)],
                TlsPolicy::PlainOnly,
            ),
            rule(
                HostMatch::Exact("::1".into()),
                vec![PortRange::single(19002)],
                TlsPolicy::PlainOnly,
            ),
        ]);
        assert_eq!(
            lo_scope
                .check_egress("127.0.0.1", 19001, TlsMode::Off, &empty_lo)
                .unwrap_err()
                .errno,
            Errno::EACCES
        );

        // BOTH keys present -> PERMITTED for exact addr:port only!
        let p4 = lo_scope
            .check_egress("127.0.0.1", 19001, TlsMode::Off, &lo)
            .unwrap();
        assert!(
            lo_scope
                .check_resolved_ip(
                    &p4,
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    19001,
                    TlsMode::Off,
                    &lo
                )
                .is_ok()
        );
        assert!(
            lo_scope
                .check_egress("::1", 19002, TlsMode::Off, &lo)
                .is_ok()
        );

        // Wrong port (e.g. 8787) or mapped IPv6 (::ffff:127.0.0.1) STILL DENIED even with test allowlist!
        assert_eq!(
            lo_scope
                .check_egress("127.0.0.1", 8787, TlsMode::Off, &lo)
                .unwrap_err()
                .errno,
            Errno::EACCES
        );
        assert_eq!(
            lo_scope
                .check_egress("::ffff:127.0.0.1", 19001, TlsMode::Off, &lo)
                .unwrap_err()
                .errno,
            Errno::EACCES
        );
        // DNS rebinding from public domain -> allowlisted loopback IP MUST BE DENIED!
        assert_eq!(
            lo_scope
                .check_resolved_ip(
                    &ParsedHost::Domain("rebind.example.com".into()),
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    19001,
                    TlsMode::Off,
                    &lo,
                )
                .unwrap_err()
                .kind,
            NetErrorKind::PrivateAddressDenied
        );
    }
}

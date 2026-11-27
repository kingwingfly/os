//! Phase 10b (`#87`) `/dev/net/tun` L3 interface, tenant L3 overlay capability scope,
//! deterministic tenant subnet allocation (`10.64.0.0/10` + `fd50:6f73::/32`), shared L3
//! packet validation & anti-spoofing/cross-tenant firewall, and `OverlayRelay` wire codecs
//! (`docs/architecture/contract.md` §2.16, §6 `Boundary::Network` v1).

use crate::contract::NETWORK_VERSION;
use crate::sha256::ResumableSha256;
use crate::{Errno, Error};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Active `Boundary::Network` v1 overlay wire protocol version.
pub const OVERLAY_VERSION: u32 = NETWORK_VERSION;

/// Canonical `/dev/net/tun` path and character device driver tag.
pub const TUN_DEV_PATH: &str = "/dev/net/tun";
pub const TUN_RDEV: &str = "net:tun";

/// Negotiable L3 TUN MTU bounds (RFC 8200 minimum 1280, WireGuard/overlay default 1420, Ethernet 1500).
pub const TUN_MIN_MTU: u16 = 1280;
pub const TUN_DEFAULT_MTU: u16 = 1420;
pub const TUN_MAX_MTU: u16 = 1500;

/// Maximum queued payload bytes per direction (RX and TX) on one `/dev/net/tun` open description.
pub const TUN_QUEUE_MAX_BYTES: usize = 1024 * 1024; // 1 MiB

/// Maximum concurrent TUN interfaces per OS instance.
pub const TUN_MAX_INTERFACES: usize = 16;

/// Server-enforced hard ceilings for `OverlayScope`.
pub const OVERLAY_MAX_INTERFACES_CEILING: u16 = 16;
pub const OVERLAY_MAX_BPS_CEILING: u64 = 16 * 1024 * 1024; // 16 MiB/s
pub const OVERLAY_DEFAULT_LEASE_TTL_SECS: u64 = 60;
pub const OVERLAY_MAX_NETWORKS: usize = 8;
pub const OVERLAY_MAX_PEER_CIDRS: usize = 16;

/// Binary WebSocket / WebTransport / DataChannel frame tag for raw L3 IPv4/IPv6 packets.
pub const OVERLAY_FRAME_L3_PACKET: u8 = 0x01;

/// Maximum serialized byte size of a WebRTC `Signal` frame (16 KiB).
pub const OVERLAY_SIGNAL_MAX_BYTES: usize = 16 * 1024;

/// Single-use WebSocket upgrade ticket TTL (seconds).
pub const OVERLAY_TICKET_TTL_SECS: u64 = 30;

/// Maximum concurrent active WebSockets inside one `OverlayRelay` DO shard.
pub const OVERLAY_MAX_SOCKETS_PER_DO: usize = 128;

/// Linux `TUNSETIFF` / `TUNGETIFF` / `TUNGETFEATURES` and OS-specific TUN inspection ioctls.
pub mod tun_ioctl {
    /// Linux `TUNSETIFF` (`_IOW('T', 202, int)`): attach an unbound `/dev/net/tun` clone fd.
    pub const TUNSETIFF: u32 = 0x4004_54ca;
    /// Linux `TUNGETIFF` (`_IOR('T', 210, unsigned int)`): query bound interface name & flags.
    pub const TUNGETIFF: u32 = 0x8004_54d2;
    /// Linux `TUNGETFEATURES` (`_IOR('T', 207, unsigned int)`): query supported `IFF_*` bits.
    pub const TUNGETFEATURES: u32 = 0x8004_54cf;
    /// OS-native query returning full [`super::TunInfo`] JSON.
    pub const TUN_IOC_INFO: u32 = 0x5457_0301;
    /// OS-native query returning [`super::TunStats`] packet/byte/drop counters.
    pub const TUN_IOC_STATS: u32 = 0x5457_0302;
    /// OS-native request updating interface MTU within `1280..=negotiated_max_mtu`.
    pub const TUN_IOC_SET_MTU: u32 = 0x5457_0303;

    /// Linux `IFF_TUN`: Layer-3 raw IP packets (no Ethernet header).
    pub const IFF_TUN: u16 = 0x0001;
    /// Linux `IFF_TAP`: Layer-2 Ethernet frames (explicitly unsupported — rejected with `EINVAL`).
    pub const IFF_TAP: u16 = 0x0002;
    /// Linux `IFF_NO_PI`: omit 4-byte Linux packet info header (required).
    pub const IFF_NO_PI: u16 = 0x1000;
    /// Exact required flag combination accepted by `TUNSETIFF`.
    pub const IFF_REQUIRED: u16 = IFF_TUN | IFF_NO_PI;

    /// Returns `true` if `request` is one of the `/dev/net/tun` ioctl command codes.
    pub const fn is_tun_ioctl(request: u32) -> bool {
        matches!(
            request,
            TUNSETIFF | TUNGETIFF | TUNGETFEATURES | TUN_IOC_INFO | TUN_IOC_STATS | TUN_IOC_SET_MTU
        )
    }
}

fn default_max_interfaces() -> u16 {
    OVERLAY_MAX_INTERFACES_CEILING
}

fn default_overlay_mtu() -> u16 {
    TUN_DEFAULT_MTU
}

fn default_overlay_network() -> String {
    "default".to_string()
}

/// Validate an overlay network name: `[a-z0-9_-]{1,32}`.
pub fn valid_overlay_network_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}

/// Validate an explicit TUN interface name (`^[a-zA-Z][a-zA-Z0-9_-]{0,14}$`, max 15 ASCII bytes).
pub fn valid_tun_ifname(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 15
        && bytes[0].is_ascii_alphabetic()
        && bytes[1..]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

// =============================================================================
// CIDR Types & Deterministic Tenant Subnet Allocation
// =============================================================================

/// Canonical IPv4 CIDR block (`net` always masked to `prefix_len`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ipv4Cidr {
    pub net: Ipv4Addr,
    pub prefix_len: u8,
}

impl Ipv4Cidr {
    pub const fn new(addr: Ipv4Addr, prefix_len: u8) -> Option<Self> {
        if prefix_len > 32 {
            return None;
        }
        let mask = ipv4_mask(prefix_len);
        let net = Ipv4Addr::from_bits(addr.to_bits() & mask);
        Some(Self { net, prefix_len })
    }

    pub fn parse(raw: &str) -> Option<Self> {
        let (ip_str, pfx_str) = raw.split_once('/')?;
        let ip: Ipv4Addr = ip_str.parse().ok()?;
        let pfx: u8 = pfx_str.parse().ok()?;
        Self::new(ip, pfx)
    }

    pub const fn contains(self, ip: Ipv4Addr) -> bool {
        let mask = ipv4_mask(self.prefix_len);
        (ip.to_bits() & mask) == self.net.to_bits()
    }

    pub const fn covers(self, other: Self) -> bool {
        self.prefix_len <= other.prefix_len && self.contains(other.net)
    }

    pub const fn intersect(self, other: Self) -> Option<Self> {
        if self.covers(other) {
            Some(other)
        } else if other.covers(self) {
            Some(self)
        } else {
            None
        }
    }

    pub const fn network_addr(self) -> Ipv4Addr {
        self.net
    }

    pub const fn broadcast_addr(self) -> Ipv4Addr {
        let mask = ipv4_mask(self.prefix_len);
        Ipv4Addr::from_bits(self.net.to_bits() | !mask)
    }

    pub const fn gateway_addr(self) -> Option<Ipv4Addr> {
        if self.prefix_len >= 31 {
            return None;
        }
        Some(Ipv4Addr::from_bits(self.net.to_bits() + 1))
    }

    /// Returns `true` if `ip` is a valid assignable host address inside this subnet
    /// (strictly inside the CIDR, not network `.0`, not gateway `.1`, not broadcast `.255`).
    pub const fn is_valid_host_ip(self, ip: Ipv4Addr) -> bool {
        if self.prefix_len >= 30 || !self.contains(ip) {
            return false;
        }
        let bits = ip.to_bits();
        let net = self.net.to_bits();
        let bcast = self.broadcast_addr().to_bits();
        bits > net + 1 && bits < bcast
    }

    /// Return the `idx`-th host IP (`0`-based -> `.2`, `1` -> `.3`, ...).
    pub const fn host_ip(self, idx: u32) -> Option<Ipv4Addr> {
        if self.prefix_len >= 30 {
            return None;
        }
        let host_bits = 32 - self.prefix_len;
        let max_hosts = (1u32 << host_bits).saturating_sub(3); // excludes .0, .1 (gw), .255 (bcast)
        if idx >= max_hosts {
            return None;
        }
        Some(Ipv4Addr::from_bits(self.net.to_bits() + 2 + idx))
    }
}

impl fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.net, self.prefix_len)
    }
}

const fn ipv4_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else if prefix_len >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

/// Canonical IPv6 CIDR block (`net` always masked to `prefix_len`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ipv6Cidr {
    pub net: Ipv6Addr,
    pub prefix_len: u8,
}

impl Ipv6Cidr {
    pub const fn new(addr: Ipv6Addr, prefix_len: u8) -> Option<Self> {
        if prefix_len > 128 {
            return None;
        }
        let mask = ipv6_mask(prefix_len);
        let net = Ipv6Addr::from_bits(addr.to_bits() & mask);
        Some(Self { net, prefix_len })
    }

    pub fn parse(raw: &str) -> Option<Self> {
        let (ip_str, pfx_str) = raw.split_once('/')?;
        let ip: Ipv6Addr = ip_str.parse().ok()?;
        let pfx: u8 = pfx_str.parse().ok()?;
        Self::new(ip, pfx)
    }

    pub const fn contains(self, ip: Ipv6Addr) -> bool {
        let mask = ipv6_mask(self.prefix_len);
        (ip.to_bits() & mask) == self.net.to_bits()
    }

    pub const fn covers(self, other: Self) -> bool {
        self.prefix_len <= other.prefix_len && self.contains(other.net)
    }

    pub const fn intersect(self, other: Self) -> Option<Self> {
        if self.covers(other) {
            Some(other)
        } else if other.covers(self) {
            Some(self)
        } else {
            None
        }
    }

    /// Subnet router-anycast address (all-zeros host bits).
    pub const fn network_addr(self) -> Ipv6Addr {
        self.net
    }

    pub const fn gateway_addr(self) -> Option<Ipv6Addr> {
        if self.prefix_len >= 127 {
            return None;
        }
        Some(Ipv6Addr::from_bits(self.net.to_bits() + 1))
    }

    /// Return the `idx`-th host IP (`0`-based -> `::2`, `1` -> `::3`, ...).
    pub const fn host_ip(self, idx: u16) -> Option<Ipv6Addr> {
        if self.prefix_len > 64 {
            return None;
        }
        let host = (idx as u128) + 2;
        if host > 0xfffe {
            return None;
        }
        Some(Ipv6Addr::from_bits(self.net.to_bits() | host))
    }
}

impl fmt::Display for Ipv6Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.net, self.prefix_len)
    }
}

const fn ipv6_mask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else if prefix_len >= 128 {
        u128::MAX
    } else {
        u128::MAX << (128 - prefix_len)
    }
}

/// Dual-stack IPv4 or IPv6 CIDR block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpCidr {
    V4(Ipv4Cidr),
    V6(Ipv6Cidr),
}

impl IpCidr {
    pub fn parse(raw: &str) -> Option<Self> {
        if raw.contains(':') {
            Ipv6Cidr::parse(raw).map(Self::V6)
        } else {
            Ipv4Cidr::parse(raw).map(Self::V4)
        }
    }

    pub const fn contains(self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::V4(c), IpAddr::V4(a)) => c.contains(a),
            (Self::V6(c), IpAddr::V6(a)) => c.contains(a),
            _ => false,
        }
    }

    pub const fn intersect(self, other: Self) -> Option<Self> {
        match (self, other) {
            (Self::V4(a), Self::V4(b)) => match a.intersect(b) {
                Some(c) => Some(Self::V4(c)),
                None => None,
            },
            (Self::V6(a), Self::V6(b)) => match a.intersect(b) {
                Some(c) => Some(Self::V6(c)),
                None => None,
            },
            _ => None,
        }
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(c) => fmt::Display::fmt(c, f),
            Self::V6(c) => fmt::Display::fmt(c, f),
        }
    }
}

/// Reserved overlay IPv4 supernet (`10.64.0.0/10`, `10.64.0.0` - `10.127.255.255`).
pub const OVERLAY_V4_SUPERNET: Ipv4Cidr = Ipv4Cidr {
    net: Ipv4Addr::new(10, 64, 0, 0),
    prefix_len: 10,
};

/// Reserved overlay IPv6 ULA supernet (`fd50:6f73::/32`).
pub const OVERLAY_V6_SUPERNET: Ipv6Cidr = Ipv6Cidr {
    net: Ipv6Addr::new(0xfd50, 0x6f73, 0, 0, 0, 0, 0, 0),
    prefix_len: 32,
};

fn sha256_bytes(prefix: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = ResumableSha256::new();
    h.update(prefix);
    h.update(data);
    h.finalize_bytes()
}

/// Deterministically derive a tenant's default IPv4 `/24` inside `10.64.0.0/10`.
/// `h = SHA-256("os-overlay-v1-v4:" || tenant)` -> `10.(64 + (h[0] & 0x3f)).h[1].0/24`.
pub fn derive_tenant_v4_cidr(tenant: &str) -> Ipv4Cidr {
    let h = sha256_bytes(b"os-overlay-v1-v4:", tenant.as_bytes());
    let b = 64 + (h[0] & 0x3f);
    let c = h[1];
    Ipv4Cidr {
        net: Ipv4Addr::new(10, b, c, 0),
        prefix_len: 24,
    }
}

/// Deterministically derive a tenant's default IPv6 `/64` inside `fd50:6f73::/32`.
/// `h = SHA-256("os-overlay-v1-v6:" || tenant)` -> `fd50:6f73:<h0h1>:<h2h3>::/64`.
pub fn derive_tenant_v6_cidr(tenant: &str) -> Ipv6Cidr {
    let h = sha256_bytes(b"os-overlay-v1-v6:", tenant.as_bytes());
    let s2 = u16::from_be_bytes([h[0], h[1]]);
    let s3 = u16::from_be_bytes([h[2], h[3]]);
    Ipv6Cidr {
        net: Ipv6Addr::new(0xfd50, 0x6f73, s2, s3, 0, 0, 0, 0),
        prefix_len: 64,
    }
}

/// Format an IPv4 address for use as a `ClusterState` key segment (`a-b-c-d`).
pub fn ipv4_key_segment(ip: Ipv4Addr) -> String {
    let [a, b, c, d] = ip.octets();
    format!("{a}-{b}-{c}-{d}")
}

/// Parse an IPv4 `ClusterState` key segment (`a-b-c-d`).
pub fn parse_ipv4_key_segment(seg: &str) -> Option<Ipv4Addr> {
    let mut parts = seg.split('-');
    let a: u8 = parts.next()?.parse().ok()?;
    let b: u8 = parts.next()?.parse().ok()?;
    let c: u8 = parts.next()?.parse().ok()?;
    let d: u8 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some(Ipv4Addr::new(a, b, c, d))
}

/// Format an IPv6 address as a 32-char lowercase hex `ClusterState` key segment.
pub fn ipv6_key_segment(ip: Ipv6Addr) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(32);
    for b in ip.octets() {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Canonical `ClusterState` key builders under `/t/<tenant>/overlay/...`.
pub fn overlay_config_key(tenant: &str) -> String {
    format!("/t/{tenant}/overlay/config")
}

pub fn overlay_ipam_v4_prefix(tenant: &str) -> String {
    format!("/t/{tenant}/overlay/ipam/v4/")
}

pub fn overlay_ipam_v4_key(tenant: &str, ip: Ipv4Addr) -> String {
    format!("/t/{tenant}/overlay/ipam/v4/{}", ipv4_key_segment(ip))
}

pub fn overlay_ipam_v6_prefix(tenant: &str) -> String {
    format!("/t/{tenant}/overlay/ipam/v6/")
}

pub fn overlay_ipam_v6_key(tenant: &str, ip: Ipv6Addr) -> String {
    format!("/t/{tenant}/overlay/ipam/v6/{}", ipv6_key_segment(ip))
}

pub fn overlay_endpoint_prefix(tenant: &str) -> String {
    format!("/t/{tenant}/overlay/endpoints/")
}

pub fn overlay_endpoint_key(tenant: &str, endpoint_id: &str) -> String {
    format!("/t/{tenant}/overlay/endpoints/{endpoint_id}")
}

pub fn overlay_node_endpoint_key(tenant: &str, node_id: &str, endpoint_id: &str) -> String {
    format!("/t/{tenant}/overlay/node-endpoints/{node_id}/{endpoint_id}")
}

// =============================================================================
// Capability Scope (`RemoteScope.overlay`)
// =============================================================================

/// Explicit tenant L3 overlay capability embedded in `RemoteScope.overlay`
/// (strictly default-deny when `None`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverlayScope {
    /// Non-empty permitted overlay network names (`[a-z0-9_-]{1,32}`, e.g. `["default"]`).
    pub networks: Vec<String>,
    /// Max concurrent TUN/overlay endpoints (`1..=16`).
    #[serde(default = "default_max_interfaces")]
    pub max_interfaces: u16,
    /// Max negotiated MTU ceiling (`1280..=1500`, default `1420`).
    #[serde(default = "default_overlay_mtu")]
    pub max_mtu: u16,
    /// Optional per-endpoint bandwidth ceiling (bytes/sec, clamped to 16 MiB/s).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes_per_sec: Option<u64>,
    /// Permits `os-cni` / kubelet pod IPAM allocation on bound node.
    #[serde(default)]
    pub cni_ipam: bool,
    /// Optional peer destination CIDR allowlist inside tenant subnet (empty = entire tenant CIDR).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_peer_cidrs: Vec<String>,
}

impl OverlayScope {
    /// Default single-network scope for an authenticated tenant user or service (`"default"`).
    pub fn default_network() -> Self {
        Self {
            networks: vec!["default".to_string()],
            max_interfaces: OVERLAY_MAX_INTERFACES_CEILING,
            max_mtu: TUN_DEFAULT_MTU,
            max_bytes_per_sec: None,
            cni_ipam: false,
            allowed_peer_cidrs: Vec::new(),
        }
    }

    /// Maximum overlay scope ceiling for an enrolled worker node (`RemoteScope::node_ceiling`).
    /// Never granted silently unless the caller explicitly requests `scope.overlay = Some(...)`
    /// (which is then intersected with this ceiling via `.attenuate()`).
    pub fn node_ceiling() -> Self {
        Self {
            networks: vec!["default".to_string()],
            max_interfaces: OVERLAY_MAX_INTERFACES_CEILING,
            max_mtu: TUN_MAX_MTU,
            max_bytes_per_sec: Some(OVERLAY_MAX_BPS_CEILING),
            cni_ipam: true,
            allowed_peer_cidrs: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.networks.is_empty() || self.max_interfaces == 0
    }

    pub fn allows_network(&self, network: &str) -> bool {
        valid_overlay_network_name(network) && self.networks.iter().any(|n| n == network)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.networks.is_empty() || self.networks.len() > OVERLAY_MAX_NETWORKS {
            return Err(Error::because(
                Errno::EINVAL,
                "overlay scope must specify 1..=8 valid network names",
            ));
        }
        if !self.networks.iter().all(|n| valid_overlay_network_name(n)) {
            return Err(Error::because(
                Errno::EINVAL,
                "invalid overlay network name in scope",
            ));
        }
        if self.max_interfaces == 0 || self.max_interfaces > OVERLAY_MAX_INTERFACES_CEILING {
            return Err(Error::because(
                Errno::EINVAL,
                "overlay max_interfaces must be in 1..=16",
            ));
        }
        if !(TUN_MIN_MTU..=TUN_MAX_MTU).contains(&self.max_mtu) {
            return Err(Error::because(
                Errno::EINVAL,
                "overlay max_mtu must be in 1280..=1500",
            ));
        }
        if self.max_bytes_per_sec == Some(0) {
            return Err(Error::because(
                Errno::EINVAL,
                "overlay max_bytes_per_sec must be non-zero",
            ));
        }
        if self.allowed_peer_cidrs.len() > OVERLAY_MAX_PEER_CIDRS {
            return Err(Error::because(
                Errno::EINVAL,
                "too many allowed_peer_cidrs entries",
            ));
        }
        for cidr in &self.allowed_peer_cidrs {
            if IpCidr::parse(cidr).is_none() {
                return Err(Error::because(
                    Errno::EINVAL,
                    format!("invalid CIDR '{cidr}' in overlay allowed_peer_cidrs"),
                ));
            }
        }
        Ok(())
    }

    /// Return a validated & server-ceiling-clamped copy of this scope.
    pub fn clamped(&self) -> Result<Self, Error> {
        self.validate()?;
        let mut networks = Vec::with_capacity(self.networks.len());
        for n in &self.networks {
            if !networks.contains(n) {
                networks.push(n.clone());
            }
        }
        let mut cidrs = Vec::with_capacity(self.allowed_peer_cidrs.len());
        for raw in &self.allowed_peer_cidrs {
            let canonical = IpCidr::parse(raw)
                .ok_or_else(|| Error::because(Errno::EINVAL, "invalid CIDR"))?
                .to_string();
            if !cidrs.contains(&canonical) {
                cidrs.push(canonical);
            }
        }
        Ok(Self {
            networks,
            max_interfaces: self.max_interfaces.clamp(1, OVERLAY_MAX_INTERFACES_CEILING),
            max_mtu: self.max_mtu.clamp(TUN_MIN_MTU, TUN_MAX_MTU),
            max_bytes_per_sec: self
                .max_bytes_per_sec
                .map(|b| b.clamp(1, OVERLAY_MAX_BPS_CEILING)),
            cni_ipam: self.cni_ipam,
            allowed_peer_cidrs: cidrs,
        })
    }

    /// Parse `allowed_peer_cidrs` into typed [`IpCidr`] entries.
    pub fn parsed_peer_cidrs(&self) -> Result<Vec<IpCidr>, Error> {
        let mut out = Vec::with_capacity(self.allowed_peer_cidrs.len());
        for raw in &self.allowed_peer_cidrs {
            let c =
                IpCidr::parse(raw).ok_or_else(|| Error::because(Errno::EINVAL, "invalid CIDR"))?;
            out.push(c);
        }
        Ok(out)
    }

    /// Monotonic attenuation: derived scope can NEVER exceed `self` or server ceilings.
    pub fn attenuate(&self, requested: &OverlayScope) -> Option<OverlayScope> {
        let parent = self.clamped().ok()?;
        let req = requested.clamped().ok()?;

        // Exact set intersection on network names (must be non-empty).
        let networks: Vec<String> = req
            .networks
            .iter()
            .filter(|n| parent.networks.contains(n))
            .cloned()
            .collect();
        if networks.is_empty() {
            return None;
        }

        let max_interfaces = parent
            .max_interfaces
            .min(req.max_interfaces)
            .clamp(1, OVERLAY_MAX_INTERFACES_CEILING);
        let max_mtu = parent.max_mtu.min(req.max_mtu);
        if !(TUN_MIN_MTU..=TUN_MAX_MTU).contains(&max_mtu) {
            return None;
        }
        let max_bytes_per_sec = match (parent.max_bytes_per_sec, req.max_bytes_per_sec) {
            (Some(a), Some(b)) => Some(a.min(b).clamp(1, OVERLAY_MAX_BPS_CEILING)),
            (Some(a), None) | (None, Some(a)) => Some(a.clamp(1, OVERLAY_MAX_BPS_CEILING)),
            (None, None) => None,
        };
        let cni_ipam = parent.cni_ipam && req.cni_ipam;

        let allowed_peer_cidrs = if parent.allowed_peer_cidrs.is_empty() {
            req.allowed_peer_cidrs
        } else if req.allowed_peer_cidrs.is_empty() {
            parent.allowed_peer_cidrs
        } else {
            let p_cidrs: Vec<IpCidr> = parent
                .allowed_peer_cidrs
                .iter()
                .filter_map(|s| IpCidr::parse(s))
                .collect();
            let r_cidrs: Vec<IpCidr> = req
                .allowed_peer_cidrs
                .iter()
                .filter_map(|s| IpCidr::parse(s))
                .collect();
            let mut out = Vec::new();
            for pc in &p_cidrs {
                for rc in &r_cidrs {
                    if let Some(inter) = pc.intersect(*rc) {
                        let s = inter.to_string();
                        if !out.contains(&s) {
                            out.push(s);
                        }
                    }
                }
            }
            if out.is_empty() || out.len() > OVERLAY_MAX_PEER_CIDRS {
                return None;
            }
            out
        };

        Some(OverlayScope {
            networks,
            max_interfaces,
            max_mtu,
            max_bytes_per_sec,
            cni_ipam,
            allowed_peer_cidrs,
        })
    }
}

// =============================================================================
// `/dev/net/tun` Ioctl Request/Response & Stats Schemas
// =============================================================================

/// Request payload for `TUNSETIFF` (`0x4004_54ca`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunSetIffReq {
    /// Interface name (`""` or `"tun%d"` auto-allocates lowest free `tun0..tun15`, or explicit
    /// `^[a-zA-Z][a-zA-Z0-9_-]{0,14}$`).
    #[serde(default)]
    pub name: String,
    /// Must strictly equal `IFF_TUN | IFF_NO_PI` (`0x1001`).
    pub flags: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_ip: Option<String>,
}

/// Parse a `TUNSETIFF` ioctl payload accepting either:
/// - JSON [`TunSetIffReq`]
/// - Raw 40-byte Linux `struct ifreq` (`[u8; 40]`: 16-byte NUL-terminated `ifr_name`, LE `u16` `ifr_flags`)
/// - JSON array of 40 bytes or JSON `{"ifreq_b64": "<base64 of 40 bytes>"}`.
pub fn parse_tun_set_iff_payload(payload: &[u8]) -> Result<TunSetIffReq, Errno> {
    if payload.len() == 40 && !payload.starts_with(b"{") && !payload.starts_with(b"[") {
        return parse_linux_ifreq(payload);
    }
    if let Ok(req) = serde_json::from_slice::<TunSetIffReq>(payload) {
        return Ok(req);
    }
    if let Ok(raw_vec) = serde_json::from_slice::<Vec<u8>>(payload)
        && raw_vec.len() == 40
    {
        return parse_linux_ifreq(&raw_vec);
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct B64Ifreq {
        ifreq_b64: String,
    }
    if let Ok(b64) = serde_json::from_slice::<B64Ifreq>(payload)
        && let Ok(raw) = STANDARD.decode(&b64.ifreq_b64)
        && raw.len() == 40
    {
        return parse_linux_ifreq(&raw);
    }
    Err(Errno::EINVAL)
}

fn parse_linux_ifreq(raw: &[u8]) -> Result<TunSetIffReq, Errno> {
    if raw.len() < 18 {
        return Err(Errno::EINVAL);
    }
    let name_field = &raw[..16];
    let nul_pos = name_field.iter().position(|&b| b == 0).unwrap_or(16);
    if nul_pos == 16 {
        // Linux IFNAMSIZ is 16 including NUL terminator (max 15 chars).
        return Err(Errno::EINVAL);
    }
    let name = std::str::from_utf8(&name_field[..nul_pos])
        .map_err(|_| Errno::EINVAL)?
        .to_string();
    let flags = u16::from_le_bytes([raw[16], raw[17]]);
    Ok(TunSetIffReq {
        name,
        flags,
        mtu: None,
        network: None,
        static_ip: None,
    })
}

/// Response returned by `TUNSETIFF`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunSetIffResp {
    pub name: String,
    pub flags: u16,
    pub mtu: u16,
    pub ip: String,
    pub prefix_len: u8,
    pub gateway: String,
    pub cidr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<String>,
    pub tenant: String,
    pub network: String,
    pub endpoint_id: String,
    pub lease_id: u64,
}

/// Response returned by `TUNGETIFF`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunGetIffResp {
    pub name: String,
    pub flags: u16,
}

/// Operational state of a bound TUN interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunState {
    Up,
    Hungup,
}

/// Full metadata returned by `TUN_IOC_INFO`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunInfo {
    pub name: String,
    pub flags: u16,
    pub mtu: u16,
    pub ip: String,
    pub prefix_len: u8,
    pub gateway: String,
    pub cidr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<String>,
    pub tenant: String,
    pub network: String,
    pub endpoint_id: String,
    pub lease_id: u64,
    pub state: TunState,
    pub rx_queued_bytes: usize,
    pub tx_queued_bytes: usize,
    pub queue_max_bytes: usize,
}

/// Per-interface L3 packet/byte/drop counters returned by `TUN_IOC_STATS`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunStats {
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub tx_dropped_spoofed_src: u64,
    pub tx_dropped_cross_tenant: u64,
    pub tx_dropped_outside_cidr: u64,
    pub tx_dropped_malformed: u64,
    pub tx_dropped_self_loop: u64,
    pub tx_dropped_queue_full: u64,
    pub tx_dropped_no_route: u64,
    pub rx_dropped_queue_full: u64,
    pub rx_dropped_policy: u64,
    pub rx_truncated_reads: u64,
}

/// Request payload for `TUN_IOC_SET_MTU`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunSetMtuReq {
    pub mtu: u16,
}

// =============================================================================
// ClusterState IPAM & Endpoint Records
// =============================================================================

/// Durable (unleased) tenant overlay subnet configuration stored at `/t/<tenant>/overlay/config`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantOverlayConfig {
    pub version: u32,
    pub tenant: String,
    #[serde(default = "default_overlay_network")]
    pub network: String,
    pub cidr_v4: String,
    pub gateway_v4: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr_v6: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_v6: Option<String>,
    pub mtu: u16,
}

impl TenantOverlayConfig {
    /// Construct the deterministic default config for `(tenant, network)`.
    pub fn default_for(tenant: &str, network: &str) -> Self {
        let v4 = derive_tenant_v4_cidr(tenant);
        let v6 = derive_tenant_v6_cidr(tenant);
        Self {
            version: OVERLAY_VERSION,
            tenant: tenant.to_string(),
            network: network.to_string(),
            cidr_v4: v4.to_string(),
            gateway_v4: v4.gateway_addr().unwrap().to_string(),
            cidr_v6: Some(v6.to_string()),
            gateway_v6: Some(v6.gateway_addr().unwrap().to_string()),
            mtu: TUN_DEFAULT_MTU,
        }
    }

    pub fn validate(&self) -> Result<(Ipv4Cidr, Option<Ipv6Cidr>), Error> {
        if self.version != OVERLAY_VERSION {
            return Err(Error::because(
                Errno::EPROTONOSUPPORT,
                "unsupported TenantOverlayConfig version",
            ));
        }
        let v4 = Ipv4Cidr::parse(&self.cidr_v4)
            .filter(|c| OVERLAY_V4_SUPERNET.covers(*c) && c.prefix_len <= 29)
            .ok_or_else(|| {
                Error::because(
                    Errno::EINVAL,
                    "tenant cidr_v4 must lie within 10.64.0.0/10 with prefix <= /29",
                )
            })?;
        let v6 = match &self.cidr_v6 {
            Some(raw) => {
                let parsed = Ipv6Cidr::parse(raw)
                    .filter(|c| OVERLAY_V6_SUPERNET.covers(*c) && c.prefix_len <= 64)
                    .ok_or_else(|| {
                        Error::because(
                            Errno::EINVAL,
                            "tenant cidr_v6 must lie within fd50:6f73::/32 with prefix <= /64",
                        )
                    })?;
                Some(parsed)
            }
            None => None,
        };
        if !(TUN_MIN_MTU..=TUN_MAX_MTU).contains(&self.mtu) {
            return Err(Error::because(Errno::EINVAL, "invalid overlay config mtu"));
        }
        Ok((v4, v6))
    }
}

/// Lease-bound IPAM allocation record stored at `/t/<tenant>/overlay/ipam/v4/<a-b-c-d>`
/// (and `/t/<tenant>/overlay/ipam/v6/<compact_hex>`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpamLeaseRecord {
    pub tenant: String,
    pub network: String,
    pub ip: String,
    pub prefix_len: u8,
    pub endpoint_id: String,
    pub node_id: String,
    pub ifname: String,
    pub host_kind: String,
    pub mtu: u16,
    pub lease_id: u64,
    pub fence_epoch: u64,
    pub allocated_at: u64,
}

/// Lease-bound reverse endpoint index stored at `/t/<tenant>/overlay/endpoints/<endpoint_id>`
/// and `/t/<tenant>/overlay/node-endpoints/<node_id>/<endpoint_id>`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayEndpointRecord {
    pub tenant: String,
    pub network: String,
    pub endpoint_id: String,
    pub ip: String,
    pub prefix_len: u8,
    pub gateway: String,
    pub cidr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<String>,
    pub node_id: String,
    pub ifname: String,
    pub host_kind: String,
    pub mtu: u16,
    pub lease_id: u64,
    pub fence_epoch: u64,
    pub allocated_at: u64,
}

// =============================================================================
// Strict L3 IPv4/IPv6 Parser & Defense-in-Depth Anti-Spoofing/Cross-Tenant Firewall
// =============================================================================

/// Reason an L3 packet was rejected or dropped by the overlay firewall.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DropReason {
    MalformedHeader,
    UnsupportedIpVersion,
    ExceedsMtu,
    ForbiddenAddress,
    SpoofedSource,
    SelfLoop,
    CrossTenant,
    OutsideCidr,
    RxPolicyDenied,
}

impl DropReason {
    /// Local POSIX errno returned synchronously on `write()` to `/dev/net/tun` for header/MTU
    /// errors (`EINVAL` / `EMSGSIZE`). Policy drops (spoofed source, cross-tenant, self-loop,
    /// outside-CIDR) are dropped silently after incrementing stats, mirroring Linux netfilter/TUN
    /// behavior (so callers can observe drop counters without crashing packet loops).
    pub const fn local_write_errno(self) -> Option<Errno> {
        match self {
            Self::ExceedsMtu => Some(Errno::EMSGSIZE),
            Self::MalformedHeader | Self::UnsupportedIpVersion => Some(Errno::EINVAL),
            _ => None,
        }
    }
}

/// Validated L3 header metadata extracted by [`parse_l3_packet`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct L3PacketMeta {
    pub version: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    pub ttl_or_hop: u8,
    pub header_len: usize,
    pub total_len: usize,
}

/// Returns `true` if `ip` is an IPv4 bogon/loopback/link-local/IMDS/multicast/reserved address
/// unconditionally forbidden inside the overlay data plane.
pub const fn is_forbidden_overlay_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, _c, _d] = ip.octets();
    // 0.0.0.0/8 (this network)
    if a == 0 {
        return true;
    }
    // 127.0.0.0/8 (loopback)
    if a == 127 {
        return true;
    }
    // 169.254.0.0/16 (link-local / cloud IMDS)
    if a == 169 && b == 254 {
        return true;
    }
    // 224.0.0.0/4 (multicast) and 240.0.0.0/4 (reserved / limited broadcast)
    if a >= 224 {
        return true;
    }
    false
}

/// Returns `true` if `ip` is an IPv6 unspecified/loopback/link-local/multicast/mapped/NAT64
/// address unconditionally forbidden inside the overlay data plane.
pub const fn is_forbidden_overlay_ipv6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    // ::/128 (unspecified) and ::1/128 (loopback)
    if ip.is_unspecified() || ip.is_loopback() {
        return true;
    }
    // fe80::/10 (link-local)
    if (s[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    // ff00::/8 (multicast)
    if (s[0] & 0xff00) == 0xff00 {
        return true;
    }
    // ::ffff:0:0/96 (IPv4-mapped IPv6)
    if s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0xffff {
        return true;
    }
    // 64:ff9b::/96 (NAT64 well-known prefix)
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
        return true;
    }
    false
}

/// Strictly parse and validate a raw L3 IPv4 or IPv6 packet against `mtu` and bogon rules.
///
/// Blocks truncation, trailing-byte smuggling (`total_len == pkt.len()`), bad IHL, `TTL == 0`,
/// non-IPv4/IPv6 versions, oversized frames (`> mtu`), and forbidden bogon/multicast/IMDS/loopback
/// addresses.
pub fn parse_l3_packet(pkt: &[u8], mtu: u16) -> Result<L3PacketMeta, DropReason> {
    if pkt.is_empty() {
        return Err(DropReason::MalformedHeader);
    }
    if pkt.len() > mtu as usize {
        return Err(DropReason::ExceedsMtu);
    }
    let version = pkt[0] >> 4;
    match version {
        4 => {
            if pkt.len() < 20 {
                return Err(DropReason::MalformedHeader);
            }
            let ihl = ((pkt[0] & 0x0f) as usize) * 4;
            if ihl < 20 || ihl > pkt.len() {
                return Err(DropReason::MalformedHeader);
            }
            let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
            if total_len < ihl || total_len != pkt.len() {
                return Err(DropReason::MalformedHeader);
            }
            let ttl = pkt[8];
            if ttl == 0 {
                return Err(DropReason::MalformedHeader);
            }
            let proto = pkt[9];
            let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
            let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
            if is_forbidden_overlay_ipv4(src) || is_forbidden_overlay_ipv4(dst) {
                return Err(DropReason::ForbiddenAddress);
            }
            Ok(L3PacketMeta {
                version: 4,
                src: IpAddr::V4(src),
                dst: IpAddr::V4(dst),
                proto,
                ttl_or_hop: ttl,
                header_len: ihl,
                total_len,
            })
        }
        6 => {
            if pkt.len() < 40 {
                return Err(DropReason::MalformedHeader);
            }
            let payload_len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
            let Some(total_len) = 40usize.checked_add(payload_len) else {
                return Err(DropReason::MalformedHeader);
            };
            if total_len != pkt.len() {
                return Err(DropReason::MalformedHeader);
            }
            let proto = pkt[6];
            let hop_limit = pkt[7];
            if hop_limit == 0 {
                return Err(DropReason::MalformedHeader);
            }
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[8..24]).unwrap());
            let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).unwrap());
            if is_forbidden_overlay_ipv6(src) || is_forbidden_overlay_ipv6(dst) {
                return Err(DropReason::ForbiddenAddress);
            }
            Ok(L3PacketMeta {
                version: 6,
                src: IpAddr::V6(src),
                dst: IpAddr::V6(dst),
                proto,
                ttl_or_hop: hop_limit,
                header_len: 40,
                total_len,
            })
        }
        _ => Err(DropReason::UnsupportedIpVersion),
    }
}

/// Endpoint L3 identity and tenant subnet policy evaluated identically at:
/// (1) `os-vfs` `TunRegistry`, (2) `os-native` `NativeOverlaySwitch`, and (3) Worker `OverlayRelay`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OverlayEndpointPolicy {
    pub tenant: String,
    pub leased_ip: Ipv4Addr,
    pub tenant_cidr_v4: Ipv4Cidr,
    pub leased_ipv6: Option<Ipv6Addr>,
    pub tenant_cidr_v6: Option<Ipv6Cidr>,
    pub mtu: u16,
    pub allowed_peer_cidrs: Vec<IpCidr>,
}

/// Shared stateless L3 packet firewall enforcing anti-spoofing, cross-tenant denial, and RX checks.
pub struct OverlayFirewall;

impl OverlayFirewall {
    /// Validate an outbound TX packet from an endpoint bound to `policy`.
    pub fn check_tx(
        policy: &OverlayEndpointPolicy,
        pkt: &[u8],
    ) -> Result<L3PacketMeta, DropReason> {
        let meta = parse_l3_packet(pkt, policy.mtu)?;
        match (meta.src, meta.dst) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                // 1. Source-IP anti-spoofing.
                if src != policy.leased_ip {
                    return Err(DropReason::SpoofedSource);
                }
                // 2. Reject self-loop.
                if dst == policy.leased_ip {
                    return Err(DropReason::SelfLoop);
                }
                // 3. Reject own subnet network (.0) and directed broadcast (.255).
                if dst == policy.tenant_cidr_v4.network_addr()
                    || dst == policy.tenant_cidr_v4.broadcast_addr()
                {
                    return Err(DropReason::ForbiddenAddress);
                }
                // 4. Require destination inside tenant CIDR (classify other overlay subnets as CrossTenant).
                if !policy.tenant_cidr_v4.contains(dst) {
                    if OVERLAY_V4_SUPERNET.contains(dst) {
                        return Err(DropReason::CrossTenant);
                    }
                    return Err(DropReason::OutsideCidr);
                }
                // 5. Optional peer destination CIDR allowlist.
                if !policy.allowed_peer_cidrs.is_empty()
                    && !policy
                        .allowed_peer_cidrs
                        .iter()
                        .any(|c| c.contains(IpAddr::V4(dst)))
                {
                    return Err(DropReason::OutsideCidr);
                }
                Ok(meta)
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                let (Some(leased_v6), Some(cidr_v6)) = (policy.leased_ipv6, policy.tenant_cidr_v6)
                else {
                    return Err(DropReason::SpoofedSource);
                };
                if src != leased_v6 {
                    return Err(DropReason::SpoofedSource);
                }
                if dst == leased_v6 {
                    return Err(DropReason::SelfLoop);
                }
                // Reject subnet router-anycast (all-zeros host identifier).
                if dst == cidr_v6.network_addr() {
                    return Err(DropReason::ForbiddenAddress);
                }
                if !cidr_v6.contains(dst) {
                    if OVERLAY_V6_SUPERNET.contains(dst) {
                        return Err(DropReason::CrossTenant);
                    }
                    return Err(DropReason::OutsideCidr);
                }
                if !policy.allowed_peer_cidrs.is_empty()
                    && !policy
                        .allowed_peer_cidrs
                        .iter()
                        .any(|c| c.contains(IpAddr::V6(dst)))
                {
                    return Err(DropReason::OutsideCidr);
                }
                Ok(meta)
            }
            _ => Err(DropReason::MalformedHeader),
        }
    }

    /// Defense-in-depth validation of an inbound RX packet before enqueuing into a local TUN device.
    pub fn check_rx(
        policy: &OverlayEndpointPolicy,
        pkt: &[u8],
    ) -> Result<L3PacketMeta, DropReason> {
        let meta = parse_l3_packet(pkt, policy.mtu).map_err(|_| DropReason::RxPolicyDenied)?;
        match (meta.src, meta.dst) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                if dst != policy.leased_ip
                    || src == policy.leased_ip
                    || !policy.tenant_cidr_v4.contains(src)
                    || src == policy.tenant_cidr_v4.network_addr()
                    || src == policy.tenant_cidr_v4.broadcast_addr()
                {
                    return Err(DropReason::RxPolicyDenied);
                }
                if !policy.allowed_peer_cidrs.is_empty()
                    && !policy
                        .allowed_peer_cidrs
                        .iter()
                        .any(|c| c.contains(IpAddr::V4(src)))
                {
                    return Err(DropReason::RxPolicyDenied);
                }
                Ok(meta)
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                let (Some(leased_v6), Some(cidr_v6)) = (policy.leased_ipv6, policy.tenant_cidr_v6)
                else {
                    return Err(DropReason::RxPolicyDenied);
                };
                if dst != leased_v6
                    || src == leased_v6
                    || !cidr_v6.contains(src)
                    || src == cidr_v6.network_addr()
                {
                    return Err(DropReason::RxPolicyDenied);
                }
                if !policy.allowed_peer_cidrs.is_empty()
                    && !policy
                        .allowed_peer_cidrs
                        .iter()
                        .any(|c| c.contains(IpAddr::V6(src)))
                {
                    return Err(DropReason::RxPolicyDenied);
                }
                Ok(meta)
            }
            _ => Err(DropReason::RxPolicyDenied),
        }
    }
}

// =============================================================================
// Worker Overlay Edge Gateway & `OverlayRelay` DO Wire Protocol
// =============================================================================

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverlayAttachRequest {
    #[serde(default = "default_overlay_network")]
    pub network: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ifname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayAttachReply {
    pub version: u32,
    pub ticket: String,
    pub tenant: String,
    pub network: String,
    pub endpoint_id: String,
    pub ip: String,
    pub prefix_len: u8,
    pub gateway: String,
    pub cidr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<String>,
    pub mtu: u16,
    pub lease_id: u64,
    pub lease_ttl_secs: u64,
    pub expires_at: u64,
    pub ws_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webtransport_url: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverlayRenewRequest {
    pub endpoint_id: String,
    pub lease_id: u64,
    #[serde(default = "default_overlay_network")]
    pub network: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayRenewReply {
    pub version: u32,
    pub endpoint_id: String,
    pub lease_id: u64,
    pub lease_ttl_secs: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverlayDetachRequest {
    pub endpoint_id: String,
    pub lease_id: u64,
    #[serde(default = "default_overlay_network")]
    pub network: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerInfo {
    pub endpoint_id: String,
    pub ip: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<String>,
    pub host_kind: String,
    pub mtu: u16,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayStats {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub dropped_spoofed_src: u64,
    pub dropped_cross_tenant: u64,
    pub dropped_outside_cidr: u64,
    pub dropped_malformed: u64,
    pub dropped_no_route: u64,
    pub active_peers: u32,
}

/// Client-to-server JSON control / WebRTC signaling frame on `/api/overlay/connect`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OverlayClientFrame {
    Hello {
        versions: Vec<u32>,
    },
    Signal {
        to_endpoint_id: String,
        payload: serde_json::Value,
    },
    KeepAlive {
        seq: u64,
    },
    Stats {},
}

/// Server-to-client JSON control / WebRTC signaling frame on `/api/overlay/connect`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OverlayServerFrame {
    Welcome {
        version: u32,
        tenant: String,
        network: String,
        endpoint_id: String,
        ip: String,
        cidr: String,
        gateway: String,
        mtu: u16,
        lease_id: u64,
        peers: Vec<PeerInfo>,
    },
    PeerJoined(PeerInfo),
    PeerLeft {
        endpoint_id: String,
        ip: String,
    },
    Signal {
        from_endpoint_id: String,
        payload: serde_json::Value,
    },
    KeepAliveAck {
        seq: u64,
        lease_expires_at: u64,
    },
    StatsReply(OverlayStats),
    DropNotice {
        reason: DropReason,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        src: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dst: Option<String>,
    },
    Error {
        errno: Errno,
        message: String,
    },
}

/// Encode a raw L3 IPv4/IPv6 packet into an overlay binary datagram (`[0x01][pkt]`).
pub fn encode_overlay_l3_frame(pkt: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + pkt.len());
    out.push(OVERLAY_FRAME_L3_PACKET);
    out.extend_from_slice(pkt);
    out
}

/// Decode an overlay binary datagram (`[0x01][pkt]`) returning the raw L3 packet slice.
pub fn decode_overlay_l3_frame(frame: &[u8]) -> Result<&[u8], DropReason> {
    if frame.len() < 2 || frame[0] != OVERLAY_FRAME_L3_PACKET {
        return Err(DropReason::MalformedHeader);
    }
    Ok(&frame[1..])
}

/// Build a minimal valid IPv4 header + payload (useful for guests, tests, and ICMP/UDP builders).
pub fn build_ipv4_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    ttl: u8,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = (20 + payload.len()) as u16;
    let mut pkt = Vec::with_capacity(total_len as usize);
    pkt.push(0x45); // ver=4, ihl=5 (20 bytes)
    pkt.push(0x00); // dscp/ecn
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01]); // identification
    pkt.extend_from_slice(&[0x40, 0x00]); // DF
    pkt.push(ttl);
    pkt.push(proto);
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
    pkt.extend_from_slice(&src.octets());
    pkt.extend_from_slice(&dst.octets());
    let csum = internet_checksum(&pkt[..20]);
    pkt[10] = (csum >> 8) as u8;
    pkt[11] = (csum & 0xff) as u8;
    pkt.extend_from_slice(payload);
    pkt
}

/// RFC 1071 16-bit one's complement checksum.
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (chunks, rem) = data.as_chunks::<2>();
    for chunk in chunks {
        sum += u32::from(u16::from_be_bytes(*chunk));
    }
    if let Some(&last) = rem.first() {
        sum += u32::from(u16::from_be_bytes([last, 0]));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_v2::RemoteScope;

    fn make_v4(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        build_ipv4_packet(src, dst, 17, 64, payload)
    }

    fn make_v6(src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(40 + payload.len());
        pkt.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        pkt.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        pkt.push(17); // UDP
        pkt.push(64); // hop_limit
        pkt.extend_from_slice(&src.octets());
        pkt.extend_from_slice(&dst.octets());
        pkt.extend_from_slice(payload);
        pkt
    }

    #[test]
    fn ov01_remote_scope_default_deny_and_monotonic_attenuation() {
        // Default / cloud_only / full MUST all set overlay = None.
        assert!(RemoteScope::default().overlay.is_none());
        assert!(RemoteScope::default().is_empty());
        assert!(RemoteScope::cloud_only().overlay.is_none());
        assert!(RemoteScope::full().overlay.is_none());

        // node_ceiling grants overlay/* and OverlayScope::node_ceiling(), but intersecting with
        // default/full keeps overlay = None (default-deny unless explicitly requested).
        let ceil = RemoteScope::node_ceiling("node-1");
        assert!(ceil.overlay.is_some());
        assert!(ceil.cluster_prefixes.iter().any(|p| p == "overlay/*"));
        assert!(ceil.attenuate(&RemoteScope::full()).overlay.is_none());

        // Overlay-only scope is NOT empty!
        let ov_only = RemoteScope {
            overlay: Some(OverlayScope::default_network()),
            ..RemoteScope::default()
        };
        assert!(!ov_only.is_empty());
        assert!(ov_only.has_overlay());

        // Monotonic attenuation clamps ceilings, intersects networks & CIDRs, ANDs cni_ipam.
        let parent = OverlayScope {
            networks: vec!["default".into(), "mesh".into()],
            max_interfaces: 8,
            max_mtu: 1420,
            max_bytes_per_sec: Some(4 * 1024 * 1024),
            cni_ipam: true,
            allowed_peer_cidrs: vec!["10.64.1.0/24".into()],
        };
        let req = OverlayScope {
            networks: vec!["mesh".into(), "other".into()],
            max_interfaces: 16, // tries to escalate -> clamped to 8
            max_mtu: 1500,      // tries to escalate -> clamped to 1420
            max_bytes_per_sec: Some(99 * 1024 * 1024), // clamped to 4 MiB/s
            cni_ipam: false,
            allowed_peer_cidrs: vec!["10.64.1.0/25".into(), "10.64.2.0/24".into()],
        };
        let eff = parent.attenuate(&req).expect("attenuated");
        assert_eq!(eff.networks, vec!["mesh"]);
        assert_eq!(eff.max_interfaces, 8);
        assert_eq!(eff.max_mtu, 1420);
        assert_eq!(eff.max_bytes_per_sec, Some(4 * 1024 * 1024));
        assert!(!eff.cni_ipam);
        assert_eq!(eff.allowed_peer_cidrs, vec!["10.64.1.0/25"]);

        // Disjoint networks -> None.
        let disjoint_net = OverlayScope {
            networks: vec!["isolated".into()],
            ..OverlayScope::default_network()
        };
        assert!(parent.attenuate(&disjoint_net).is_none());

        // Disjoint CIDRs -> None.
        let disjoint_cidr = OverlayScope {
            networks: vec!["default".into()],
            allowed_peer_cidrs: vec!["10.64.99.0/24".into()],
            ..OverlayScope::default_network()
        };
        assert!(parent.attenuate(&disjoint_cidr).is_none());
    }

    #[test]
    fn ov01_ipv4_and_ipv6_parser_strict_validation_and_bogons() {
        let src = Ipv4Addr::new(10, 64, 10, 2);
        let dst = Ipv4Addr::new(10, 64, 10, 3);
        let valid = make_v4(src, dst, b"hello");
        let meta = parse_l3_packet(&valid, 1420).expect("valid v4");
        assert_eq!(meta.version, 4);
        assert_eq!(meta.src, IpAddr::V4(src));
        assert_eq!(meta.dst, IpAddr::V4(dst));
        assert_eq!(meta.total_len, 25);

        // Empty & truncated.
        assert_eq!(parse_l3_packet(&[], 1420), Err(DropReason::MalformedHeader));
        assert_eq!(
            parse_l3_packet(&valid[..19], 1420),
            Err(DropReason::MalformedHeader)
        );
        assert_eq!(
            parse_l3_packet(&valid[..24], 1420),
            Err(DropReason::MalformedHeader)
        );

        // Trailing-byte smuggling (total_len < pkt.len()).
        let mut smuggled = valid.clone();
        smuggled.push(0xaa);
        assert_eq!(
            parse_l3_packet(&smuggled, 1420),
            Err(DropReason::MalformedHeader)
        );

        // Bad IHL (< 5) and IHL > pkt.len().
        let mut bad_ihl = valid.clone();
        bad_ihl[0] = 0x44;
        assert_eq!(
            parse_l3_packet(&bad_ihl, 1420),
            Err(DropReason::MalformedHeader)
        );
        let mut huge_ihl = valid.clone();
        huge_ihl[0] = 0x4f; // 60 bytes > 25 bytes
        assert_eq!(
            parse_l3_packet(&huge_ihl, 1420),
            Err(DropReason::MalformedHeader)
        );

        // TTL == 0 rejected.
        let mut zero_ttl = valid.clone();
        zero_ttl[8] = 0;
        assert_eq!(
            parse_l3_packet(&zero_ttl, 1420),
            Err(DropReason::MalformedHeader)
        );

        // Bad IP version.
        let mut bad_ver = valid.clone();
        bad_ver[0] = 0x55;
        assert_eq!(
            parse_l3_packet(&bad_ver, 1420),
            Err(DropReason::UnsupportedIpVersion)
        );

        // Exceeds MTU.
        let big = make_v4(src, dst, &vec![0u8; 1401]);
        assert_eq!(parse_l3_packet(&big, 1420), Err(DropReason::ExceedsMtu));

        // Forbidden IPv4 bogons/IMDS/loopback/multicast/broadcast.
        for bad_ip in [
            Ipv4Addr::new(0, 0, 0, 1),
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(169, 254, 169, 254),
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::new(240, 0, 0, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        ] {
            assert_eq!(
                parse_l3_packet(&make_v4(src, bad_ip, b"x"), 1420),
                Err(DropReason::ForbiddenAddress)
            );
            assert_eq!(
                parse_l3_packet(&make_v4(bad_ip, dst, b"x"), 1420),
                Err(DropReason::ForbiddenAddress)
            );
        }

        // Valid IPv6 + trailing bytes + hop_limit=0 + forbidden ranges.
        let v6_a = Ipv6Addr::new(0xfd50, 0x6f73, 0x1111, 0x2222, 0, 0, 0, 2);
        let v6_b = Ipv6Addr::new(0xfd50, 0x6f73, 0x1111, 0x2222, 0, 0, 0, 3);
        let valid6 = make_v6(v6_a, v6_b, b"v6!");
        assert_eq!(parse_l3_packet(&valid6, 1420).unwrap().version, 6);

        let mut smug6 = valid6.clone();
        smug6.push(1);
        assert_eq!(
            parse_l3_packet(&smug6, 1420),
            Err(DropReason::MalformedHeader)
        );
        let mut hop0 = valid6.clone();
        hop0[7] = 0;
        assert_eq!(
            parse_l3_packet(&hop0, 1420),
            Err(DropReason::MalformedHeader)
        );
        for bad_v6 in [
            Ipv6Addr::UNSPECIFIED,
            Ipv6Addr::LOCALHOST,
            "fe80::1".parse::<Ipv6Addr>().unwrap(),
            "ff02::1".parse::<Ipv6Addr>().unwrap(),
            "::ffff:10.64.10.3".parse::<Ipv6Addr>().unwrap(),
            "64:ff9b::10.64.10.3".parse::<Ipv6Addr>().unwrap(),
        ] {
            assert_eq!(
                parse_l3_packet(&make_v6(v6_a, bad_v6, b"x"), 1420),
                Err(DropReason::ForbiddenAddress)
            );
        }
    }

    #[test]
    fn ov01_firewall_anti_spoofing_cross_tenant_and_rx_defense() {
        let tenant_a_cidr = Ipv4Cidr::parse("10.64.10.0/24").unwrap();
        let tenant_b_ip = Ipv4Addr::new(10, 64, 20, 2);
        let policy = OverlayEndpointPolicy {
            tenant: "u1000".into(),
            leased_ip: Ipv4Addr::new(10, 64, 10, 2),
            tenant_cidr_v4: tenant_a_cidr,
            leased_ipv6: Some("fd50:6f73:1111:2222::2".parse().unwrap()),
            tenant_cidr_v6: Some(Ipv6Cidr::parse("fd50:6f73:1111:2222::/64").unwrap()),
            mtu: 1420,
            allowed_peer_cidrs: Vec::new(),
        };

        // Allowed intra-tenant TX.
        let ok_pkt = make_v4(
            Ipv4Addr::new(10, 64, 10, 2),
            Ipv4Addr::new(10, 64, 10, 3),
            b"ok",
        );
        assert!(OverlayFirewall::check_tx(&policy, &ok_pkt).is_ok());

        // Spoofed source IP -> SpoofedSource.
        let spoof = make_v4(
            Ipv4Addr::new(10, 64, 10, 9),
            Ipv4Addr::new(10, 64, 10, 3),
            b"bad",
        );
        assert_eq!(
            OverlayFirewall::check_tx(&policy, &spoof),
            Err(DropReason::SpoofedSource)
        );

        // Self-loop -> SelfLoop.
        let sloop = make_v4(
            Ipv4Addr::new(10, 64, 10, 2),
            Ipv4Addr::new(10, 64, 10, 2),
            b"me",
        );
        assert_eq!(
            OverlayFirewall::check_tx(&policy, &sloop),
            Err(DropReason::SelfLoop)
        );

        // Subnet network (.0) & directed broadcast (.255) -> ForbiddenAddress.
        assert_eq!(
            OverlayFirewall::check_tx(
                &policy,
                &make_v4(
                    Ipv4Addr::new(10, 64, 10, 2),
                    Ipv4Addr::new(10, 64, 10, 0),
                    b"n"
                )
            ),
            Err(DropReason::ForbiddenAddress)
        );
        assert_eq!(
            OverlayFirewall::check_tx(
                &policy,
                &make_v4(
                    Ipv4Addr::new(10, 64, 10, 2),
                    Ipv4Addr::new(10, 64, 10, 255),
                    b"b"
                )
            ),
            Err(DropReason::ForbiddenAddress)
        );

        // Cross-tenant (another tenant inside 10.64.0.0/10) -> CrossTenant.
        let xtenant = make_v4(Ipv4Addr::new(10, 64, 10, 2), tenant_b_ip, b"leak");
        assert_eq!(
            OverlayFirewall::check_tx(&policy, &xtenant),
            Err(DropReason::CrossTenant)
        );

        // Outside overlay supernet (public IP) -> OutsideCidr.
        let pub_dst = make_v4(
            Ipv4Addr::new(10, 64, 10, 2),
            Ipv4Addr::new(1, 1, 1, 1),
            b"pub",
        );
        assert_eq!(
            OverlayFirewall::check_tx(&policy, &pub_dst),
            Err(DropReason::OutsideCidr)
        );

        // RX defense-in-depth: valid packet addressed to local.leased_ip from same tenant.
        let rx_ok = make_v4(
            Ipv4Addr::new(10, 64, 10, 3),
            Ipv4Addr::new(10, 64, 10, 2),
            b"hi",
        );
        assert!(OverlayFirewall::check_rx(&policy, &rx_ok).is_ok());
        // RX from another tenant or wrong dst -> RxPolicyDenied.
        assert_eq!(
            OverlayFirewall::check_rx(
                &policy,
                &make_v4(tenant_b_ip, Ipv4Addr::new(10, 64, 10, 2), b"x")
            ),
            Err(DropReason::RxPolicyDenied)
        );
        assert_eq!(
            OverlayFirewall::check_rx(&policy, &ok_pkt),
            Err(DropReason::RxPolicyDenied)
        );

        // IPv6 subnet router-anycast rejected.
        let anycast = make_v6(
            "fd50:6f73:1111:2222::2".parse().unwrap(),
            "fd50:6f73:1111:2222::".parse().unwrap(),
            b"a",
        );
        assert_eq!(
            OverlayFirewall::check_tx(&policy, &anycast),
            Err(DropReason::ForbiddenAddress)
        );

        // Deterministic tenant CIDR derivation stays inside supernets.
        let c1 = derive_tenant_v4_cidr("u1000");
        let c2 = derive_tenant_v4_cidr("u1001");
        assert!(OVERLAY_V4_SUPERNET.covers(c1));
        assert!(OVERLAY_V4_SUPERNET.covers(c2));
        assert_ne!(c1, c2);
        let v6_1 = derive_tenant_v6_cidr("u1000");
        assert!(OVERLAY_V6_SUPERNET.covers(v6_1));
    }

    #[test]
    fn ov01_ifreq_binary_and_json_parsing() {
        let mut ifreq = [0u8; 40];
        ifreq[..4].copy_from_slice(b"tun0");
        ifreq[16..18].copy_from_slice(&tun_ioctl::IFF_REQUIRED.to_le_bytes());
        let parsed = parse_tun_set_iff_payload(&ifreq).expect("raw ifreq");
        assert_eq!(parsed.name, "tun0");
        assert_eq!(parsed.flags, tun_ioctl::IFF_REQUIRED);

        let j = serde_json::json!({"name": "tun%d", "flags": 0x1001, "mtu": 1400});
        let parsed2 = parse_tun_set_iff_payload(&serde_json::to_vec(&j).unwrap()).unwrap();
        assert_eq!(parsed2.name, "tun%d");
        assert_eq!(parsed2.mtu, Some(1400));
    }
}

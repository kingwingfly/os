//! Native L3 overlay switch, Worker `OverlayRelay` binary WebSocket uplink, optional Linux
//! host `/dev/net/tun` driver, and `os-cni` attachment descriptor loading (`Phase 10b #87`).
//!
//! **Zero-boot-network invariant**: by default [`NativeOverlayConfig`] has `overlay_url = None`
//! and performs ZERO network calls at boot or until a process explicitly calls `TUNSETIFF`
//! while an uplink URL is configured.

use crate::dev_backend::new_uuid_v4;
use crate::http_client::{HttpClient, WsClientConn, WsClientMessage};
use crate::kernel_rpc::WakeBus;
use abi::Errno;
use abi::overlay::{
    DropReason, IpCidr, Ipv4Cidr, Ipv6Cidr, OVERLAY_V4_SUPERNET, OVERLAY_VERSION,
    OverlayAttachReply, OverlayAttachRequest, OverlayClientFrame, OverlayDetachRequest,
    OverlayEndpointPolicy, OverlayFirewall, OverlayRenewRequest, OverlayServerFrame,
    TUN_DEFAULT_MTU, TUN_MAX_MTU, TUN_MIN_MTU, decode_overlay_l3_frame, derive_tenant_v4_cidr,
    derive_tenant_v6_cidr, encode_overlay_l3_frame, parse_l3_packet, valid_overlay_network_name,
};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::FromRawFd;
use std::path::{Component, Path, PathBuf};
use std::rc::{Rc, Weak};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use vfs::tundev::{PreparedTunAttach, TunBinding, TunHostSink, TunRegistry};

/// Bounded channel capacity for actor RX events and remote WS TX frames.
const OVERLAY_CHAN_CAP: usize = 1024;

/// Host-side TUN data-plane driver selection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HostTunMode {
    /// Pure userspace L3 switching + remote Worker WS uplink (default, works unprivileged).
    #[default]
    Userspace,
    /// Attempt host Linux `/dev/net/tun` when `CAP_NET_ADMIN` is present, falling back to userspace.
    LinuxAuto,
    /// Require host Linux `/dev/net/tun` (fails if unavailable).
    LinuxRequired,
}

/// CNI attachment descriptor read from `$CNI_STATE/attachments/<container_id>.json`
/// (exact wire match with `os_cni::spec::CniAttachmentDescriptor`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeCniAttachment {
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

impl NativeCniAttachment {
    /// Safely load `$state_dir/attachments/<container_id>.json` enforcing no `..` and `O_NOFOLLOW`.
    pub fn load_nofollow(state_dir: &Path, container_id: &str) -> Result<Option<Self>, Errno> {
        if container_id.is_empty()
            || !abi::auth_v2::valid_cluster_record_id(container_id)
            || state_dir
                .components()
                .any(|c| matches!(c, Component::ParentDir))
        {
            return Err(Errno::EINVAL);
        }
        check_no_symlinks(state_dir)?;
        let attach_dir = state_dir.join("attachments");
        let path = attach_dir.join(format!("{container_id}.json"));
        match std::fs::symlink_metadata(&path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_file() {
                    return Err(Errno::EACCES);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(Errno::EIO),
        }
        check_no_symlinks(&attach_dir)?;
        let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| Errno::EINVAL)?;
        // SAFETY: `c_path` is a valid NUL-terminated path string.
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(Errno::EIO);
        }
        // SAFETY: `fd` is a newly opened owned file descriptor.
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut buf = Vec::new();
        std::io::Read::by_ref(&mut file)
            .take(65_537)
            .read_to_end(&mut buf)
            .map_err(|_| Errno::EIO)?;
        if buf.len() > 65_536 {
            return Err(Errno::EFBIG);
        }
        let parsed: Self = serde_json::from_slice(&buf).map_err(|_| Errno::EINVAL)?;
        if parsed.version != OVERLAY_VERSION
            || parsed.container_id != container_id
            || !abi::cluster_state::valid_tenant_name(&parsed.tenant)
            || !valid_overlay_network_name(&parsed.network)
            || !(TUN_MIN_MTU..=TUN_MAX_MTU).contains(&parsed.mtu)
        {
            return Err(Errno::EINVAL);
        }
        let cidr_v4 = Ipv4Cidr::parse(&parsed.cidr).ok_or(Errno::EINVAL)?;
        if !OVERLAY_V4_SUPERNET.covers(cidr_v4) {
            return Err(Errno::EINVAL);
        }
        let ip_v4: Ipv4Addr = parsed.ip.parse().map_err(|_| Errno::EINVAL)?;
        if !cidr_v4.is_valid_host_ip(ip_v4) {
            return Err(Errno::EINVAL);
        }
        Ok(Some(parsed))
    }
}

fn check_no_symlinks(path: &Path) -> Result<(), Errno> {
    let mut cur = PathBuf::new();
    for comp in path.components() {
        cur.push(comp);
        if matches!(comp, Component::RootDir | Component::CurDir) {
            continue;
        }
        match std::fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() => return Err(Errno::ELOOP),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => return Err(Errno::EIO),
        }
    }
    Ok(())
}

/// Optional overlay configuration attached to `os-native` hosts or pod sandboxes.
#[derive(Clone, Debug)]
pub struct NativeOverlayConfig {
    /// Optional Worker base HTTP URL (`http://...`) for remote `OverlayRelay` uplink.
    /// `None` by default -> ZERO boot or runtime network calls.
    pub overlay_url: Option<String>,
    /// Optional ServiceAuth v2 token for remote `/api/overlay/*`.
    pub token: Option<String>,
    /// Optional `X-OS-Instance` header for remote `/api/overlay/*`.
    pub instance_id: Option<String>,
    /// Tenant identifier for local-only switching (ignored when remote Worker assigns tenant).
    pub tenant: String,
    pub cluster: String,
    pub network: String,
    pub cni_state_dir: Option<PathBuf>,
    pub cni_attachment: Option<NativeCniAttachment>,
    pub shared_switch: Option<Arc<NativeOverlaySwitch>>,
    pub host_driver: HostTunMode,
    pub allowed_peer_cidrs: Vec<String>,
}

impl Default for NativeOverlayConfig {
    fn default() -> Self {
        Self {
            overlay_url: None,
            token: None,
            instance_id: None,
            tenant: "u0".to_string(),
            cluster: "default".to_string(),
            network: "default".to_string(),
            cni_state_dir: None,
            cni_attachment: None,
            shared_switch: None,
            host_driver: HostTunMode::Userspace,
            allowed_peer_cidrs: Vec::new(),
        }
    }
}

/// Events delivered from `NativeOverlaySwitch` or remote `OverlayRelay` WS tasks into the
/// owning `KernelActor`'s single-threaded event loop.
pub enum OverlayActorEvent {
    RxPacket { tun_id: u64, pkt: Vec<u8> },
    DropNotice { tun_id: u64, reason: DropReason },
    Hangup { tun_id: u64, errno: Errno },
}

#[derive(Clone)]
struct SwitchPort {
    endpoint_id: String,
    tenant: String,
    network: String,
    ip: Ipv4Addr,
    cidr: Ipv4Cidr,
    ipv6: Option<Ipv6Addr>,
    cidr_v6: Option<Ipv6Cidr>,
    mtu: u16,
    allowed_peer_cidrs: Vec<IpCidr>,
    tun_id: u64,
    actor_tx: mpsc::Sender<OverlayActorEvent>,
    wake: Arc<WakeBus>,
    remote_tx: Option<mpsc::Sender<Vec<u8>>>,
    host_tun_tx: Option<mpsc::Sender<Vec<u8>>>,
}

impl SwitchPort {
    fn policy(&self) -> OverlayEndpointPolicy {
        OverlayEndpointPolicy {
            tenant: self.tenant.clone(),
            leased_ip: self.ip,
            tenant_cidr_v4: self.cidr,
            leased_ipv6: self.ipv6,
            tenant_cidr_v6: self.cidr_v6,
            mtu: self.mtu,
            allowed_peer_cidrs: self.allowed_peer_cidrs.clone(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct SwitchCounters {
    pub forwarded_local: u64,
    pub forwarded_remote: u64,
    pub dropped_spoofed_src: u64,
    pub dropped_cross_tenant: u64,
    pub dropped_outside_cidr: u64,
    pub dropped_other: u64,
    pub no_route: u64,
}

#[derive(Default)]
struct SwitchInner {
    /// Keyed strictly by `(tenant, network, ip)` (IPv4 or IPv6) -> structurally prevents cross-tenant routing.
    ports: HashMap<(String, String, IpAddr), SwitchPort>,
    by_endpoint: HashMap<String, Vec<(String, String, IpAddr)>>,
    counters: SwitchCounters,
}

/// Result of submitting a validated TX L3 packet into [`NativeOverlaySwitch`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForwardOutcome {
    DeliveredLocal,
    ForwardedRemote,
    Backpressure,
    NoRoute,
}

/// Thread-safe L3 overlay switch shared across host `KernelActor` and isolated pod sandboxes.
///
/// Enforces the exact same [`OverlayFirewall`] anti-spoofing + cross-tenant rules as `os-vfs`
/// `TunRegistry` and Worker `OverlayRelay` DO (defense in depth).
#[derive(Default)]
pub struct NativeOverlaySwitch {
    inner: Mutex<SwitchInner>,
}

impl std::fmt::Debug for NativeOverlaySwitch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let g = self.inner.lock().unwrap();
        f.debug_struct("NativeOverlaySwitch")
            .field("active_ports", &g.ports.len())
            .field("counters", &g.counters)
            .finish()
    }
}

impl NativeOverlaySwitch {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn counters(&self) -> SwitchCounters {
        self.inner.lock().unwrap().counters.clone()
    }

    pub fn active_port_count(&self) -> usize {
        self.inner.lock().unwrap().by_endpoint.len()
    }

    /// Allocate the lowest unused IPv4 host address inside `cidr` for local-only mode.
    pub fn alloc_local_ip(
        &self,
        tenant: &str,
        network: &str,
        cidr: Ipv4Cidr,
    ) -> Result<Ipv4Addr, Errno> {
        let g = self.inner.lock().unwrap();
        let used: HashSet<Ipv4Addr> = g
            .ports
            .keys()
            .filter(|(t, n, _)| t == tenant && n == network)
            .filter_map(|(_, _, ip)| match *ip {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            })
            .collect();
        let mut idx = 0u32;
        while let Some(ip) = cidr.host_ip(idx) {
            if !used.contains(&ip) {
                return Ok(ip);
            }
            idx += 1;
        }
        Err(Errno::ENOSPC)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_port(
        &self,
        endpoint_id: String,
        tenant: String,
        network: String,
        ip: Ipv4Addr,
        cidr: Ipv4Cidr,
        ipv6: Option<Ipv6Addr>,
        cidr_v6: Option<Ipv6Cidr>,
        mtu: u16,
        allowed_peer_cidrs: Vec<IpCidr>,
        tun_id: u64,
        actor_tx: mpsc::Sender<OverlayActorEvent>,
        wake: Arc<WakeBus>,
        remote_tx: Option<mpsc::Sender<Vec<u8>>>,
        host_tun_tx: Option<mpsc::Sender<Vec<u8>>>,
    ) -> Result<(), Errno> {
        let mut g = self.inner.lock().unwrap();
        let key_v4 = (tenant.clone(), network.clone(), IpAddr::V4(ip));
        if let Some(prev) = g.ports.get(&key_v4)
            && prev.endpoint_id != endpoint_id
        {
            return Err(Errno::EADDRINUSE);
        }
        let key_v6 = ipv6.map(|ip6| (tenant.clone(), network.clone(), IpAddr::V6(ip6)));
        if let Some(ref k6) = key_v6
            && let Some(prev) = g.ports.get(k6)
            && prev.endpoint_id != endpoint_id
        {
            return Err(Errno::EADDRINUSE);
        }
        // Clean up any stale keys previously registered for this same `endpoint_id`.
        if let Some(old_keys) = g.by_endpoint.remove(&endpoint_id) {
            for ok in old_keys {
                if g.ports
                    .get(&ok)
                    .is_some_and(|p| p.endpoint_id == endpoint_id)
                {
                    g.ports.remove(&ok);
                }
            }
        }
        let port = SwitchPort {
            endpoint_id: endpoint_id.clone(),
            tenant,
            network,
            ip,
            cidr,
            ipv6,
            cidr_v6,
            mtu,
            allowed_peer_cidrs,
            tun_id,
            actor_tx,
            wake,
            remote_tx,
            host_tun_tx,
        };
        let mut keys = vec![key_v4.clone()];
        g.ports.insert(key_v4, port.clone());
        if let Some(k6) = key_v6 {
            keys.push(k6.clone());
            g.ports.insert(k6, port);
        }
        g.by_endpoint.insert(endpoint_id, keys);
        Ok(())
    }

    pub fn unregister_endpoint(&self, endpoint_id: &str) {
        let mut g = self.inner.lock().unwrap();
        if let Some(keys) = g.by_endpoint.remove(endpoint_id) {
            for key in keys {
                g.ports.remove(&key);
            }
        }
    }

    pub fn update_port_mtu(&self, endpoint_id: &str, mtu: u16) {
        let mut g = self.inner.lock().unwrap();
        if let Some(keys) = g.by_endpoint.get(endpoint_id).cloned() {
            for key in keys {
                if let Some(port) = g.ports.get_mut(&key) {
                    port.mtu = mtu;
                }
            }
        }
    }

    /// Validate and forward an outbound L3 packet from `sender_endpoint_id`.
    pub fn forward_from_port(
        &self,
        sender_endpoint_id: &str,
        pkt: &[u8],
    ) -> Result<ForwardOutcome, DropReason> {
        let (target_opt, remote_opt, host_tun_opt) = {
            let mut g = self.inner.lock().unwrap();
            let Some(sender_key) = g
                .by_endpoint
                .get(sender_endpoint_id)
                .and_then(|v| v.first())
                .cloned()
            else {
                g.counters.dropped_other += 1;
                return Err(DropReason::MalformedHeader);
            };
            let Some(sender) = g.ports.get(&sender_key) else {
                g.counters.dropped_other += 1;
                return Err(DropReason::MalformedHeader);
            };
            let sender_policy = sender.policy();
            let sender_tenant = sender.tenant.clone();
            let sender_network = sender.network.clone();
            let sender_remote = sender.remote_tx.clone();
            let sender_host_tun = sender.host_tun_tx.clone();

            match OverlayFirewall::check_tx(&sender_policy, pkt) {
                Ok(meta) => {
                    let dst_key = (sender_tenant.clone(), sender_network.clone(), meta.dst);
                    if let Some(dst_port) = g.ports.get(&dst_key) {
                        let dst_policy = dst_port.policy();
                        if let Err(rx_err) = OverlayFirewall::check_rx(&dst_policy, pkt) {
                            g.counters.dropped_other += 1;
                            return Err(rx_err);
                        }
                        let delivered = (
                            dst_port.tun_id,
                            dst_port.actor_tx.clone(),
                            Arc::clone(&dst_port.wake),
                        );
                        g.counters.forwarded_local += 1;
                        (Some(delivered), None, None)
                    } else if let Some(rtx) = sender_remote {
                        g.counters.forwarded_remote += 1;
                        (None, Some(rtx), None)
                    } else if let Some(htx) = sender_host_tun {
                        g.counters.forwarded_remote += 1;
                        (None, None, Some(htx))
                    } else {
                        g.counters.no_route += 1;
                        (None, None, None)
                    }
                }
                Err(mut reason) => {
                    // Explicitly detect targeting another tenant's active port on the switch.
                    if reason == DropReason::OutsideCidr
                        && let Ok(meta) = parse_l3_packet(pkt, sender_policy.mtu)
                        && g.ports
                            .keys()
                            .any(|(t, _, ip)| *ip == meta.dst && t != &sender_tenant)
                    {
                        reason = DropReason::CrossTenant;
                    }
                    match reason {
                        DropReason::SpoofedSource => g.counters.dropped_spoofed_src += 1,
                        DropReason::CrossTenant => g.counters.dropped_cross_tenant += 1,
                        DropReason::OutsideCidr => g.counters.dropped_outside_cidr += 1,
                        _ => g.counters.dropped_other += 1,
                    }
                    return Err(reason);
                }
            }
        };

        if let Some((tun_id, actor_tx, wake)) = target_opt {
            // Bounded drop-tail RX delivery (never grows unboundedly).
            let _ = actor_tx.try_send(OverlayActorEvent::RxPacket {
                tun_id,
                pkt: pkt.to_vec(),
            });
            wake.notify();
            return Ok(ForwardOutcome::DeliveredLocal);
        }
        if let Some(rtx) = remote_opt {
            return match rtx.try_send(encode_overlay_l3_frame(pkt)) {
                Ok(()) => Ok(ForwardOutcome::ForwardedRemote),
                Err(mpsc::error::TrySendError::Full(_)) => Ok(ForwardOutcome::Backpressure),
                Err(mpsc::error::TrySendError::Closed(_)) => Ok(ForwardOutcome::NoRoute),
            };
        }
        if let Some(htx) = host_tun_opt {
            return match htx.try_send(pkt.to_vec()) {
                Ok(()) => Ok(ForwardOutcome::ForwardedRemote),
                Err(mpsc::error::TrySendError::Full(_)) => Ok(ForwardOutcome::Backpressure),
                Err(mpsc::error::TrySendError::Closed(_)) => Ok(ForwardOutcome::NoRoute),
            };
        }
        Ok(ForwardOutcome::NoRoute)
    }

    /// Inject a packet arriving from the remote Worker `OverlayRelay` or host TUN into `endpoint_id`.
    pub fn inject_from_remote(&self, tenant: &str, endpoint_id: &str, pkt: &[u8]) -> bool {
        let dest = {
            let g = self.inner.lock().unwrap();
            let Some(key) = g.by_endpoint.get(endpoint_id).and_then(|v| v.first()) else {
                return false;
            };
            let Some(port) = g.ports.get(key) else {
                return false;
            };
            if port.tenant != tenant {
                return false;
            }
            if OverlayFirewall::check_rx(&port.policy(), pkt).is_err() {
                return false;
            }
            (port.tun_id, port.actor_tx.clone(), Arc::clone(&port.wake))
        };
        if dest
            .1
            .try_send(OverlayActorEvent::RxPacket {
                tun_id: dest.0,
                pkt: pkt.to_vec(),
            })
            .is_ok()
        {
            dest.2.notify();
            true
        } else {
            false
        }
    }
}

struct RemoteDetachInfo {
    base_url: String,
    token: String,
    instance_id: String,
    cluster: String,
    network: String,
    endpoint_id: String,
    lease_id: u64,
}

struct PendingRemoteUplink {
    ws: WsClientConn,
    lease_ttl_secs: u64,
    detach: RemoteDetachInfo,
}

/// Prepared attachment ready to be committed into [`TunRegistry::commit_set_iff`] and then
/// activated on [`NativeOverlaySwitch`] with its final assigned `tun_id`.
pub struct PendingNativeAttach {
    pub binding: TunBinding,
    remote: Option<PendingRemoteUplink>,
    host_tun_file: Option<std::fs::File>,
}

impl PendingNativeAttach {
    pub fn abort(self) {
        if let Some(rem) = self.remote {
            spawn_detach_request(rem.detach);
        }
    }
}

struct ActiveNativeTun {
    endpoint_id: String,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    host_tun_stop: Option<Arc<AtomicBool>>,
    detach: Option<RemoteDetachInfo>,
}

/// Per-`KernelActor` runtime bridging `vfs::tundev::TunRegistry` to `NativeOverlaySwitch`
/// and (when explicitly configured) the remote Worker `OverlayRelay` WebSocket uplink.
pub struct NativeOverlayRuntime {
    pub cfg: NativeOverlayConfig,
    pub switch: Arc<NativeOverlaySwitch>,
    actor_tx: mpsc::Sender<OverlayActorEvent>,
    pub actor_rx: mpsc::Receiver<OverlayActorEvent>,
    wake: Arc<WakeBus>,
    active: Rc<RefCell<HashMap<u64, ActiveNativeTun>>>,
    sink_tun_weak: Rc<RefCell<Weak<TunRegistry>>>,
}

impl NativeOverlayRuntime {
    pub fn new(cfg: NativeOverlayConfig, wake: Arc<WakeBus>) -> (Self, Rc<dyn TunHostSink>) {
        let switch = cfg.shared_switch.clone().unwrap_or_default();
        let (actor_tx, actor_rx) = mpsc::channel(OVERLAY_CHAN_CAP);
        let active: Rc<RefCell<HashMap<u64, ActiveNativeTun>>> =
            Rc::new(RefCell::new(HashMap::new()));
        let sink_tun_weak: Rc<RefCell<Weak<TunRegistry>>> = Rc::new(RefCell::new(Weak::new()));
        let sink = Rc::new(NativeTunSink {
            switch: Arc::clone(&switch),
            wake: Arc::clone(&wake),
            active: Rc::clone(&active),
            tun_weak: Rc::clone(&sink_tun_weak),
        });
        let rt = Self {
            cfg,
            switch,
            actor_tx,
            actor_rx,
            wake,
            active,
            sink_tun_weak,
        };
        (rt, sink)
    }

    pub fn bind_tun_registry(&self, reg: &Rc<TunRegistry>) {
        *self.sink_tun_weak.borrow_mut() = Rc::downgrade(reg);
    }

    /// Process a single event delivered from the switch or remote uplink into `tun_reg`.
    pub fn apply_event(&self, tun_reg: &TunRegistry, ev: OverlayActorEvent) {
        match ev {
            OverlayActorEvent::RxPacket { tun_id, pkt } => {
                let _ = tun_reg.inject_rx(tun_id, &pkt);
                self.wake.notify();
            }
            OverlayActorEvent::DropNotice { tun_id, reason } => {
                tun_reg.record_tx_drop(tun_id, reason);
            }
            OverlayActorEvent::Hangup { tun_id, errno } => {
                tun_reg.mark_hungup(tun_id, errno);
                self.wake.notify();
            }
        }
    }

    /// Drain all currently queued overlay events without blocking.
    pub fn drain_pending(&mut self, tun_reg: &TunRegistry) -> bool {
        let mut any = false;
        while let Ok(ev) = self.actor_rx.try_recv() {
            self.apply_event(tun_reg, ev);
            any = true;
        }
        any
    }

    pub fn update_mtu(&self, tun_id: u64, mtu: u16) {
        if let Some(ent) = self.active.borrow().get(&tun_id) {
            self.switch.update_port_mtu(&ent.endpoint_id, mtu);
        }
    }

    /// Abort all background remote WS/renewal tasks on `KernelActor` shutdown.
    pub fn shutdown_all(&self) {
        let entries: Vec<(u64, ActiveNativeTun)> = self.active.borrow_mut().drain().collect();
        for (_tun_id, ent) in entries {
            self.switch.unregister_endpoint(&ent.endpoint_id);
            if let Some(ref stop) = ent.host_tun_stop {
                stop.store(true, Ordering::Relaxed);
            }
            for t in ent.tasks {
                t.abort();
            }
            if let Some(d) = ent.detach {
                spawn_detach_request(d);
            }
        }
    }

    /// Phase 1: obtain binding (remote Worker IPAM+WS, CNI descriptor, or local switch IP).
    pub async fn prepare_attach(
        &self,
        prepared: &PreparedTunAttach,
    ) -> Result<PendingNativeAttach, Errno> {
        let mtu = prepared
            .requested_mtu
            .unwrap_or(TUN_DEFAULT_MTU)
            .clamp(TUN_MIN_MTU, TUN_MAX_MTU);
        let allowed_cidrs: Vec<IpCidr> = self
            .cfg
            .allowed_peer_cidrs
            .iter()
            .filter_map(|s| IpCidr::parse(s))
            .collect();

        // 1. Remote Worker `OverlayRelay` uplink (explicit opt-in via `--overlay-url`).
        if let Some(ref base_url) = self.cfg.overlay_url {
            return self
                .prepare_remote_worker(base_url, prepared, mtu, allowed_cidrs)
                .await;
        }

        // 2. Explicit CNI attachment descriptor (either pre-loaded or lazily resolved from `--cni-state`).
        let loaded_cni = if self.cfg.cni_attachment.is_some() {
            self.cfg.cni_attachment.clone()
        } else if let Some(ref cni_dir) = self.cfg.cni_state_dir {
            let lookup_id = self
                .cfg
                .instance_id
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or(&prepared.name);
            NativeCniAttachment::load_nofollow(cni_dir, lookup_id)?
        } else {
            None
        };
        if let Some(cni) = loaded_cni {
            let ip: Ipv4Addr = cni.ip.parse().map_err(|_| Errno::EINVAL)?;
            let cidr_v4 = Ipv4Cidr::parse(&cni.cidr).ok_or(Errno::EINVAL)?;
            let gateway: Ipv4Addr = cni
                .gateway
                .parse()
                .ok()
                .or_else(|| cidr_v4.gateway_addr())
                .ok_or(Errno::EINVAL)?;
            let ipv6: Option<Ipv6Addr> = cni.ipv6.as_deref().and_then(|s| s.parse().ok());
            let cidr_v6 = ipv6.map(|_| derive_tenant_v6_cidr(&cni.tenant));
            let eff_mtu = mtu.min(cni.mtu).clamp(TUN_MIN_MTU, TUN_MAX_MTU);
            let ep_id = if cni.container_id.is_empty() {
                format!("cni-{}", new_uuid_v4())
            } else {
                cni.container_id.clone()
            };
            let host_tun_file = maybe_open_host_tun(
                self.cfg.host_driver,
                &prepared.name,
                ip,
                cidr_v4.prefix_len,
                eff_mtu,
            )?;
            return Ok(PendingNativeAttach {
                binding: TunBinding {
                    tenant: cni.tenant,
                    network: cni.network,
                    endpoint_id: ep_id,
                    ip,
                    prefix_len: cidr_v4.prefix_len,
                    gateway,
                    cidr_v4,
                    ipv6,
                    cidr_v6,
                    mtu: eff_mtu,
                    max_mtu: cni.mtu.clamp(TUN_MIN_MTU, TUN_MAX_MTU),
                    lease_id: cni.lease_id,
                    allowed_peer_cidrs: allowed_cidrs,
                },
                remote: None,
                host_tun_file,
            });
        }

        // 3. Local-only in-memory `NativeOverlaySwitch` (ZERO network calls!).
        let tenant = self.cfg.tenant.clone();
        let network = if prepared.network.is_empty() {
            self.cfg.network.clone()
        } else {
            prepared.network.clone()
        };
        let cidr_v4 = derive_tenant_v4_cidr(&tenant);
        let gateway = cidr_v4.gateway_addr().ok_or(Errno::EINVAL)?;
        let ip = if let Some(ref req_ip) = prepared.static_ip {
            let parsed: Ipv4Addr = req_ip.parse().map_err(|_| Errno::EINVAL)?;
            if !cidr_v4.is_valid_host_ip(parsed) {
                return Err(Errno::EINVAL);
            }
            parsed
        } else {
            self.switch.alloc_local_ip(&tenant, &network, cidr_v4)?
        };
        let ep_id = format!("local-{}", new_uuid_v4());
        let host_tun_file = maybe_open_host_tun(
            self.cfg.host_driver,
            &prepared.name,
            ip,
            cidr_v4.prefix_len,
            mtu,
        )?;
        Ok(PendingNativeAttach {
            binding: TunBinding {
                tenant,
                network,
                endpoint_id: ep_id,
                ip,
                prefix_len: cidr_v4.prefix_len,
                gateway,
                cidr_v4,
                ipv6: None,
                cidr_v6: None,
                mtu,
                max_mtu: TUN_MAX_MTU,
                lease_id: 0,
                allowed_peer_cidrs: allowed_cidrs,
            },
            remote: None,
            host_tun_file,
        })
    }

    /// Phase 2: after `TunRegistry::commit_set_iff` assigns `tun_id`, register port on
    /// `NativeOverlaySwitch` and spawn remote WS + renewal tasks (if remote-attached).
    pub fn activate_committed(
        &self,
        tun_id: u64,
        pending: PendingNativeAttach,
    ) -> Result<(), Errno> {
        let PendingNativeAttach {
            binding,
            remote,
            host_tun_file,
        } = pending;

        let mut host_tun_tasks = Vec::new();
        let mut host_tun_stop: Option<Arc<AtomicBool>> = None;
        let host_tun_tx = if let Some(file) = host_tun_file {
            let (tx_chan, mut rx_chan) = mpsc::channel::<Vec<u8>>(OVERLAY_CHAN_CAP);
            let read_file = file.try_clone().map_err(|_| Errno::EIO)?;
            let mut write_file = file;
            let stop = Arc::new(AtomicBool::new(false));
            let reader_stop = Arc::clone(&stop);
            host_tun_stop = Some(stop);
            let writer_h = tokio::task::spawn_blocking(move || {
                use std::io::Write;
                while let Some(pkt) = rx_chan.blocking_recv() {
                    let _ = write_file.write(&pkt);
                }
            });
            let rx_switch = Arc::clone(&self.switch);
            let rx_tenant = binding.tenant.clone();
            let rx_ep = binding.endpoint_id.clone();
            let reader_h = tokio::task::spawn_blocking(move || {
                let mut f = read_file;
                let mut buf = vec![0u8; 65_536];
                while !reader_stop.load(Ordering::Relaxed) {
                    match f.read(&mut buf) {
                        Ok(n) if n > 0 => {
                            let _ = rx_switch.inject_from_remote(&rx_tenant, &rx_ep, &buf[..n]);
                        }
                        Ok(_) => break,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            if reader_stop.load(Ordering::Relaxed) {
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
            });
            host_tun_tasks.push(writer_h);
            host_tun_tasks.push(reader_h);
            Some(tx_chan)
        } else {
            None
        };

        if let Some(rem) = remote {
            let (mut ws_reader, mut ws_writer) = rem.ws.into_split();
            let (remote_tx, mut remote_rx) = mpsc::channel::<Vec<u8>>(OVERLAY_CHAN_CAP);
            let (pong_tx, mut pong_rx) = mpsc::channel::<Vec<u8>>(64);

            if let Err(e) = self.switch.register_port(
                binding.endpoint_id.clone(),
                binding.tenant.clone(),
                binding.network.clone(),
                binding.ip,
                binding.cidr_v4,
                binding.ipv6,
                binding.cidr_v6,
                binding.mtu,
                binding.allowed_peer_cidrs.clone(),
                tun_id,
                self.actor_tx.clone(),
                Arc::clone(&self.wake),
                Some(remote_tx),
                host_tun_tx,
            ) {
                if let Some(ref stop) = host_tun_stop {
                    stop.store(true, Ordering::Relaxed);
                }
                for t in host_tun_tasks {
                    t.abort();
                }
                spawn_detach_request(rem.detach);
                return Err(e);
            }

            let writer_task = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        Some(frame) = remote_rx.recv() => {
                            if ws_writer.send_binary(&frame).await.is_err() {
                                break;
                            }
                        }
                        Some(p) = pong_rx.recv() => {
                            if ws_writer.send_pong(&p).await.is_err() {
                                break;
                            }
                        }
                        else => break,
                    }
                }
                ws_writer.close().await;
            });

            let rx_switch = Arc::clone(&self.switch);
            let rx_actor_tx = self.actor_tx.clone();
            let rx_wake = Arc::clone(&self.wake);
            let rx_tenant = binding.tenant.clone();
            let rx_ep = binding.endpoint_id.clone();
            let reader_task = tokio::spawn(async move {
                let mut hangup_errno = Errno::ENOTCONN;
                loop {
                    match ws_reader.recv_message().await {
                        Ok(Some(WsClientMessage::Binary(frame))) => {
                            if let Ok(pkt) = decode_overlay_l3_frame(&frame) {
                                rx_switch.inject_from_remote(&rx_tenant, &rx_ep, pkt);
                            }
                        }
                        Ok(Some(WsClientMessage::Text(txt))) => {
                            if let Ok(frame) = serde_json::from_str::<OverlayServerFrame>(&txt) {
                                match frame {
                                    OverlayServerFrame::Error { errno, .. } => {
                                        if !matches!(errno, Errno::EAGAIN | Errno::EINTR) {
                                            hangup_errno = errno;
                                        }
                                    }
                                    OverlayServerFrame::DropNotice { reason, .. } => {
                                        let _ =
                                            rx_actor_tx.try_send(OverlayActorEvent::DropNotice {
                                                tun_id,
                                                reason,
                                            });
                                    }
                                    _ => {}
                                }
                            }
                        }
                        Ok(Some(WsClientMessage::Ping(p))) => {
                            let _ = pong_tx.try_send(p);
                        }
                        Ok(Some(WsClientMessage::Close)) | Ok(None) | Err(_) => break,
                    }
                }
                let _ = rx_actor_tx
                    .send(OverlayActorEvent::Hangup {
                        tun_id,
                        errno: hangup_errno,
                    })
                    .await;
                rx_wake.notify();
            });

            let renew_secs = (rem.lease_ttl_secs / 3).max(5);
            let renew_base = rem.detach.base_url.clone();
            let renew_tok = rem.detach.token.clone();
            let renew_inst = rem.detach.instance_id.clone();
            let renew_cluster = rem.detach.cluster.clone();
            let renew_net = rem.detach.network.clone();
            let renew_ep = rem.detach.endpoint_id.clone();
            let renew_lease = rem.detach.lease_id;
            let renew_actor_tx = self.actor_tx.clone();
            let renew_wake = Arc::clone(&self.wake);
            let renew_task = tokio::spawn(async move {
                let client = HttpClient {
                    timeout: Duration::from_secs(10),
                    ..HttpClient::default()
                };
                let url = HttpClient::resolve_url(&renew_base, "/api/overlay/renew");
                let hdrs = vec![
                    ("Content-Type".to_string(), "application/json".to_string()),
                    ("X-Process-Token".to_string(), renew_tok),
                    ("X-OS-Instance".to_string(), renew_inst),
                ];
                let body = serde_json::to_vec(&OverlayRenewRequest {
                    cluster: Some(renew_cluster),
                    network: renew_net,
                    endpoint_id: renew_ep,
                    lease_id: renew_lease,
                })
                .unwrap_or_default();
                let mut ticker = tokio::time::interval(Duration::from_secs(renew_secs));
                ticker.tick().await;
                loop {
                    ticker.tick().await;
                    match client.request("POST", &url, &hdrs, &body).await {
                        Ok(r) if r.status == 200 => {}
                        Ok(r) if r.status == 401 || r.status == 403 => {
                            let _ = renew_actor_tx
                                .send(OverlayActorEvent::Hangup {
                                    tun_id,
                                    errno: Errno::EACCES,
                                })
                                .await;
                            renew_wake.notify();
                            break;
                        }
                        Ok(r) if r.status == 404 || r.status == 412 => {
                            let _ = renew_actor_tx
                                .send(OverlayActorEvent::Hangup {
                                    tun_id,
                                    errno: Errno::ESTALE,
                                })
                                .await;
                            renew_wake.notify();
                            break;
                        }
                        _ => {}
                    }
                }
            });

            let mut tasks = vec![writer_task, reader_task, renew_task];
            tasks.extend(host_tun_tasks);
            self.active.borrow_mut().insert(
                tun_id,
                ActiveNativeTun {
                    endpoint_id: binding.endpoint_id,
                    tasks,
                    host_tun_stop,
                    detach: Some(rem.detach),
                },
            );
            return Ok(());
        }

        if let Err(e) = self.switch.register_port(
            binding.endpoint_id.clone(),
            binding.tenant,
            binding.network,
            binding.ip,
            binding.cidr_v4,
            binding.ipv6,
            binding.cidr_v6,
            binding.mtu,
            binding.allowed_peer_cidrs,
            tun_id,
            self.actor_tx.clone(),
            Arc::clone(&self.wake),
            None,
            host_tun_tx,
        ) {
            if let Some(ref stop) = host_tun_stop {
                stop.store(true, Ordering::Relaxed);
            }
            for t in host_tun_tasks {
                t.abort();
            }
            return Err(e);
        }
        self.active.borrow_mut().insert(
            tun_id,
            ActiveNativeTun {
                endpoint_id: binding.endpoint_id,
                tasks: host_tun_tasks,
                host_tun_stop,
                detach: None,
            },
        );
        Ok(())
    }

    async fn prepare_remote_worker(
        &self,
        base_url: &str,
        prepared: &PreparedTunAttach,
        mtu: u16,
        allowed_cidrs: Vec<IpCidr>,
    ) -> Result<PendingNativeAttach, Errno> {
        let token = self.cfg.token.clone().ok_or(Errno::EACCES)?;
        let instance_id = self
            .cfg
            .instance_id
            .clone()
            .unwrap_or_else(|| format!("native-{}", new_uuid_v4()));
        let network = if prepared.network.is_empty() {
            self.cfg.network.clone()
        } else {
            prepared.network.clone()
        };
        let http = HttpClient {
            timeout: Duration::from_secs(15),
            ..HttpClient::default()
        };

        let attach_req = OverlayAttachRequest {
            cluster: Some(self.cfg.cluster.clone()),
            network: network.clone(),
            ifname: Some(prepared.name.clone()),
            mtu: Some(mtu),
            endpoint_id: None,
            static_ip: prepared.static_ip.clone(),
            host_kind: Some("native".to_string()),
        };
        let req_bytes = serde_json::to_vec(&attach_req).map_err(|_| Errno::EINVAL)?;
        let attach_url = HttpClient::resolve_url(base_url, "/api/overlay/attach");
        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("X-Process-Token".to_string(), token.clone()),
            ("X-OS-Instance".to_string(), instance_id.clone()),
        ];
        let resp = http
            .request("POST", &attach_url, &headers, &req_bytes)
            .await
            .map_err(|_| Errno::EIO)?;
        if resp.status == 401 || resp.status == 403 {
            return Err(Errno::EACCES);
        }
        if resp.status == 507 {
            return Err(Errno::ENOSPC);
        }
        if resp.status != 200 {
            return Err(Errno::EIO);
        }
        let attached: OverlayAttachReply =
            serde_json::from_slice(&resp.body).map_err(|_| Errno::EIO)?;

        // Prepare detach info immediately after `/api/overlay/attach` succeeded so any subsequent
        // WS connect / Welcome failure releases the IPAM lease instead of leaking it!
        let detach = RemoteDetachInfo {
            base_url: base_url.to_string(),
            token: token.clone(),
            instance_id: instance_id.clone(),
            cluster: self.cfg.cluster.clone(),
            network: attached.network.clone(),
            endpoint_id: attached.endpoint_id.clone(),
            lease_id: attached.lease_id,
        };

        let parse_res: Result<(Ipv4Addr, Ipv4Cidr, Ipv4Addr, Option<Ipv6Addr>), Errno> = (|| {
            let ip: Ipv4Addr = attached.ip.parse().map_err(|_| Errno::EIO)?;
            let cidr_v4 = Ipv4Cidr::parse(&attached.cidr).ok_or(Errno::EIO)?;
            let gateway: Ipv4Addr = attached
                .gateway
                .parse()
                .ok()
                .or_else(|| cidr_v4.gateway_addr())
                .ok_or(Errno::EIO)?;
            let ipv6 = attached.ipv6.as_deref().and_then(|s| s.parse().ok());
            Ok((ip, cidr_v4, gateway, ipv6))
        })(
        );
        let (ip, cidr_v4, gateway, ipv6) = match parse_res {
            Ok(v) => v,
            Err(e) => {
                spawn_detach_request(detach);
                return Err(e);
            }
        };

        let ws_http_url = HttpClient::resolve_url(base_url, &attached.ws_url);
        let ws_url = ws_http_url
            .strip_prefix("http://")
            .map(|r| format!("ws://{r}"))
            .unwrap_or(ws_http_url);
        let ws_headers = vec![
            ("X-Process-Token".to_string(), token),
            ("X-OS-Instance".to_string(), instance_id),
        ];
        let mut ws = match http.connect_ws(&ws_url, &ws_headers).await {
            Ok(w) => w,
            Err(_) => {
                spawn_detach_request(detach);
                return Err(Errno::EIO);
            }
        };
        let hello = match serde_json::to_string(&OverlayClientFrame::Hello {
            versions: vec![OVERLAY_VERSION],
        }) {
            Ok(h) => h,
            Err(_) => {
                spawn_detach_request(detach);
                return Err(Errno::EINVAL);
            }
        };
        if ws.send_text(&hello).await.is_err() {
            spawn_detach_request(detach);
            return Err(Errno::EIO);
        }
        let welcome_res = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match ws.recv_message().await {
                    Ok(Some(WsClientMessage::Text(txt))) => {
                        if let Ok(OverlayServerFrame::Welcome { .. }) = serde_json::from_str(&txt) {
                            return Ok(());
                        }
                        if let Ok(OverlayServerFrame::Error { errno, .. }) =
                            serde_json::from_str(&txt)
                        {
                            return Err(errno);
                        }
                    }
                    Ok(Some(WsClientMessage::Ping(_))) | Ok(Some(WsClientMessage::Binary(_))) => {}
                    Ok(Some(WsClientMessage::Close)) | Ok(None) | Err(_) => {
                        return Err(Errno::ECONNRESET);
                    }
                }
            }
        })
        .await;
        match welcome_res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                spawn_detach_request(detach);
                return Err(e);
            }
            Err(_) => {
                spawn_detach_request(detach);
                return Err(Errno::ETIMEDOUT);
            }
        }

        let cidr_v6 = ipv6.map(|_| derive_tenant_v6_cidr(&attached.tenant));
        let eff_mtu = attached.mtu.clamp(TUN_MIN_MTU, TUN_MAX_MTU);
        Ok(PendingNativeAttach {
            binding: TunBinding {
                tenant: attached.tenant,
                network: attached.network,
                endpoint_id: attached.endpoint_id,
                ip,
                prefix_len: attached.prefix_len,
                gateway,
                cidr_v4,
                ipv6,
                cidr_v6,
                mtu: eff_mtu,
                max_mtu: eff_mtu,
                lease_id: attached.lease_id,
                allowed_peer_cidrs: allowed_cidrs,
            },
            remote: Some(PendingRemoteUplink {
                ws,
                lease_ttl_secs: attached.lease_ttl_secs,
                detach,
            }),
            host_tun_file: None,
        })
    }
}

struct NativeTunSink {
    switch: Arc<NativeOverlaySwitch>,
    wake: Arc<WakeBus>,
    active: Rc<RefCell<HashMap<u64, ActiveNativeTun>>>,
    tun_weak: Rc<RefCell<Weak<TunRegistry>>>,
}

impl TunHostSink for NativeTunSink {
    fn on_tx(&self, tun_id: u64, pkt: &[u8]) -> vfs::Result<bool> {
        let ep_id = {
            let g = self.active.borrow();
            match g.get(&tun_id) {
                Some(ent) => ent.endpoint_id.clone(),
                None => return Ok(false),
            }
        };
        match self.switch.forward_from_port(&ep_id, pkt) {
            Ok(ForwardOutcome::DeliveredLocal | ForwardOutcome::ForwardedRemote) => Ok(true),
            Ok(ForwardOutcome::Backpressure) => Err(Errno::EAGAIN),
            Ok(ForwardOutcome::NoRoute) => {
                if let Some(reg) = self.tun_weak.borrow().upgrade() {
                    reg.record_tx_no_route(tun_id);
                }
                Ok(true)
            }
            Err(reason) => {
                if let Some(reg) = self.tun_weak.borrow().upgrade() {
                    reg.record_tx_drop(tun_id, reason);
                }
                Ok(true)
            }
        }
    }

    fn on_wake(&self, _tun_id: u64) {
        self.wake.notify();
    }

    fn on_close(&self, tun_id: u64, _endpoint_id: &str) {
        if let Some(ent) = self.active.borrow_mut().remove(&tun_id) {
            self.switch.unregister_endpoint(&ent.endpoint_id);
            if let Some(ref stop) = ent.host_tun_stop {
                stop.store(true, Ordering::Relaxed);
            }
            for t in ent.tasks {
                t.abort();
            }
            if let Some(d) = ent.detach {
                spawn_detach_request(d);
            }
        }
        self.wake.notify();
    }
}

fn spawn_detach_request(info: RemoteDetachInfo) {
    tokio::spawn(async move {
        let client = HttpClient {
            timeout: Duration::from_secs(5),
            ..HttpClient::default()
        };
        let url = HttpClient::resolve_url(&info.base_url, "/api/overlay/detach");
        let hdrs = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("X-Process-Token".to_string(), info.token),
            ("X-OS-Instance".to_string(), info.instance_id),
        ];
        let body = serde_json::to_vec(&OverlayDetachRequest {
            cluster: Some(info.cluster),
            network: info.network,
            endpoint_id: info.endpoint_id,
            lease_id: info.lease_id,
        })
        .unwrap_or_default();
        let _ = client.request("POST", &url, &hdrs, &body).await;
    });
}

fn maybe_open_host_tun(
    mode: HostTunMode,
    ifname: &str,
    ip: Ipv4Addr,
    prefix_len: u8,
    mtu: u16,
) -> Result<Option<std::fs::File>, Errno> {
    if mode == HostTunMode::Userspace {
        return Ok(None);
    }
    #[cfg(target_os = "linux")]
    {
        match open_linux_host_tun(ifname, ip, prefix_len, mtu) {
            Ok(f) => Ok(Some(f)),
            Err(_) if mode == HostTunMode::LinuxAuto => Ok(None),
            Err(e) => Err(e),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (ifname, ip, prefix_len, mtu);
        if mode == HostTunMode::LinuxRequired {
            return Err(Errno::ENOSYS);
        }
        Ok(None)
    }
}

#[cfg(target_os = "linux")]
fn open_linux_host_tun(
    ifname: &str,
    ip: Ipv4Addr,
    prefix_len: u8,
    mtu: u16,
) -> Result<std::fs::File, Errno> {
    if !(1..=32).contains(&prefix_len) {
        return Err(Errno::EINVAL);
    }
    let dev = CString::new("/dev/net/tun").map_err(|_| Errno::EINVAL)?;
    let fd = unsafe {
        libc::open(
            dev.as_ptr(),
            libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(Errno::EPERM);
    }
    let mut ifr = [0u8; 40];
    let nb = ifname.as_bytes();
    let n = nb.len().min(15);
    ifr[..n].copy_from_slice(&nb[..n]);
    let flags: u16 = 0x1001; // IFF_TUN | IFF_NO_PI
    ifr[16..18].copy_from_slice(&flags.to_ne_bytes());
    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    if unsafe { libc::ioctl(fd, TUNSETIFF as _, ifr.as_mut_ptr()) } < 0 {
        unsafe { libc::close(fd) };
        return Err(Errno::EPERM);
    }
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        unsafe { libc::close(fd) };
        return Err(Errno::EIO);
    }
    let cfg_res: Result<(), Errno> = (|| {
        let mut req = [0u8; 40];
        req[..n].copy_from_slice(&nb[..n]);
        req[16..18].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        req[20..24].copy_from_slice(&ip.octets());
        if unsafe { libc::ioctl(sock, libc::SIOCSIFADDR as _, req.as_mut_ptr()) } < 0 {
            return Err(Errno::EPERM);
        }

        let mask = !0u32 << (32 - u32::from(prefix_len));
        let mut req = [0u8; 40];
        req[..n].copy_from_slice(&nb[..n]);
        req[16..18].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        req[20..24].copy_from_slice(&Ipv4Addr::from(mask).octets());
        if unsafe { libc::ioctl(sock, libc::SIOCSIFNETMASK as _, req.as_mut_ptr()) } < 0 {
            return Err(Errno::EPERM);
        }

        let mut req = [0u8; 40];
        req[..n].copy_from_slice(&nb[..n]);
        req[16..20].copy_from_slice(&(mtu as i32).to_ne_bytes());
        if unsafe { libc::ioctl(sock, libc::SIOCSIFMTU as _, req.as_mut_ptr()) } < 0 {
            return Err(Errno::EPERM);
        }

        // Preserve existing interface flags before bringing link UP.
        let mut req = [0u8; 40];
        req[..n].copy_from_slice(&nb[..n]);
        if unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as _, req.as_mut_ptr()) } < 0 {
            return Err(Errno::EPERM);
        }
        let cur_flags = i16::from_ne_bytes([req[16], req[17]]);
        let new_flags = cur_flags | ((libc::IFF_UP | libc::IFF_RUNNING) as i16);
        req[16..18].copy_from_slice(&new_flags.to_ne_bytes());
        if unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS as _, req.as_mut_ptr()) } < 0 {
            return Err(Errno::EPERM);
        }
        Ok(())
    })();
    unsafe { libc::close(sock) };
    if let Err(e) = cfg_res {
        unsafe { libc::close(fd) };
        return Err(e);
    }
    // SAFETY: `fd` is a live owned file descriptor.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

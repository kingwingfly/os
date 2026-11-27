//! Portable `/dev/net/tun` clone character device (`docs/architecture/contract.md` §2.7, §2.16; #87).
//!
//! Semantics match Linux `drivers/net/tun.c` (`IFF_TUN | IFF_NO_PI`):
//! - `/dev/net` (`0o755`, root) and `/dev/net/tun` (`0o600`, root, `rdev = "net:tun"`).
//! - Opening `/dev/net/tun` creates a per-`OpenRef` clone (`open.id`), shared across `dup`/`fork`/
//!   `SCM_RIGHTS`; opening a second time yields an independent unbound clone.
//! - `O_PATH` is permitted for `fstat`; `read`/`write`/`ioctl` on `O_PATH` or unbound fds return `EBADF`.
//! - Non-root opens fail with `EACCES`; root opens require explicit `"tun"` grant or host policy (`EPERM`).
//! - Single-packet `read`/`write`, small-buffer truncation (`rx_truncated_reads++`), `buf.len() == 0`
//!   non-consuming read, `write > mtu -> EMSGSIZE`, exact `1 MiB` RX drop-tail + TX `EAGAIN`,
//!   local `OverlayFirewall` anti-spoofing + cross-tenant drop counters, `poll` + hangup + last-close teardown.

use crate::devfs::{DefaultDeviceBackend, DeviceBackend};
use crate::{Access, BoxFuture, Cred, OpenRef, Result, WriteAt, Written};
use abi::Errno;
use abi::overlay::{
    DropReason, IpCidr, Ipv4Cidr, Ipv6Cidr, OverlayEndpointPolicy, OverlayFirewall,
    TUN_MAX_INTERFACES, TUN_MAX_MTU, TUN_MIN_MTU, TUN_QUEUE_MAX_BYTES, TUN_RDEV, TunGetIffResp,
    TunInfo, TunSetIffResp, TunSetMtuReq, TunState, TunStats, parse_tun_set_iff_payload, tun_ioctl,
    valid_overlay_network_name, valid_tun_ifname,
};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::rc::Rc;

/// Host open policy for `/dev/net/tun`.
#[derive(Clone, Copy, Debug, Default)]
pub struct TunPolicy {
    /// When `false` (default, mandatory in untrusted sandboxes), `uid == 0` processes MUST hold
    /// an explicit `"tun"` entry in `TunRegistry::grant(pid, ...)` or `open()` returns `EPERM`.
    /// When `true` (main OS host / CNI-attached pod), `uid == 0` processes without an explicit
    /// restrictive `grant(pid, ...)` entry may open `/dev/net/tun` (still subject to `RemoteScope.overlay`
    /// when attaching to a remote overlay).
    pub allow_root_open: bool,
}

/// Host callback sink invoked by [`TunRegistry`] on packet TX, readiness wakeups, and last-close teardown.
pub trait TunHostSink {
    /// Called when an outbound L3 packet has passed [`OverlayFirewall::check_tx`].
    /// - Return `Ok(true)` if the host immediately consumed/forwarded the packet (not queued in `tx_queue`).
    /// - Return `Ok(false)` to buffer the packet in the `1 MiB` bounded `tx_queue` for later `pop_tx()`.
    /// - Return `Err(Errno::EAGAIN)` when host transport is backpressured.
    fn on_tx(&self, _tun_id: u64, _pkt: &[u8]) -> Result<bool> {
        Ok(false)
    }

    /// Wake any waiters blocked in `read`, `write`, or `poll_oneoff` on this TUN interface.
    fn on_wake(&self, _tun_id: u64) {}

    /// Invoked when the last fd referencing `tun_id` is closed (or the process exits).
    fn on_close(&self, _tun_id: u64, _endpoint_id: &str) {}
}

/// Default no-op sink that queues TX packets locally in `tx_queue` (used in unit tests).
#[derive(Clone, Copy, Debug, Default)]
pub struct QueueOnlyTunSink;
impl TunHostSink for QueueOnlyTunSink {}

/// Validated `TUNSETIFF` pre-attach parameters produced by [`TunRegistry::prepare_set_iff`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedTunAttach {
    pub open_id: u64,
    pub name: String,
    pub flags: u16,
    pub requested_mtu: Option<u16>,
    pub network: String,
    pub static_ip: Option<String>,
}

/// Host-supplied IPAM / overlay lease binding committed via [`TunRegistry::commit_set_iff`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunBinding {
    pub tenant: String,
    pub network: String,
    pub endpoint_id: String,
    pub ip: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Ipv4Addr,
    pub cidr_v4: Ipv4Cidr,
    pub ipv6: Option<Ipv6Addr>,
    pub cidr_v6: Option<Ipv6Cidr>,
    pub mtu: u16,
    pub max_mtu: u16,
    pub lease_id: u64,
    pub allowed_peer_cidrs: Vec<IpCidr>,
}

/// Readiness snapshot returned by [`TunRegistry::poll_open`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TunPollState {
    pub ready: bool,
    pub nbytes: usize,
    pub hangup: bool,
}

struct TunInterface {
    tun_id: u64,
    _open_id: u64,
    name: String,
    flags: u16,
    network: String,
    endpoint_id: String,
    gateway: Ipv4Addr,
    lease_id: u64,
    max_mtu: u16,
    policy: OverlayEndpointPolicy,
    rx_queue: VecDeque<Vec<u8>>,
    rx_bytes_queued: usize,
    tx_queue: VecDeque<Vec<u8>>,
    tx_bytes_queued: usize,
    stats: TunStats,
    hungup: Option<Errno>,
}

impl TunInterface {
    fn info(&self) -> TunInfo {
        TunInfo {
            name: self.name.clone(),
            flags: self.flags,
            mtu: self.policy.mtu,
            ip: self.policy.leased_ip.to_string(),
            prefix_len: self.policy.tenant_cidr_v4.prefix_len,
            gateway: self.gateway.to_string(),
            cidr: self.policy.tenant_cidr_v4.to_string(),
            ipv6: self.policy.leased_ipv6.map(|v| v.to_string()),
            tenant: self.policy.tenant.clone(),
            network: self.network.clone(),
            endpoint_id: self.endpoint_id.clone(),
            lease_id: self.lease_id,
            state: if self.hungup.is_some() {
                TunState::Hungup
            } else {
                TunState::Up
            },
            rx_queued_bytes: self.rx_bytes_queued,
            tx_queued_bytes: self.tx_bytes_queued,
            queue_max_bytes: TUN_QUEUE_MAX_BYTES,
        }
    }

    fn set_iff_resp(&self) -> TunSetIffResp {
        TunSetIffResp {
            name: self.name.clone(),
            flags: self.flags,
            mtu: self.policy.mtu,
            ip: self.policy.leased_ip.to_string(),
            prefix_len: self.policy.tenant_cidr_v4.prefix_len,
            gateway: self.gateway.to_string(),
            cidr: self.policy.tenant_cidr_v4.to_string(),
            ipv6: self.policy.leased_ipv6.map(|v| v.to_string()),
            tenant: self.policy.tenant.clone(),
            network: self.network.clone(),
            endpoint_id: self.endpoint_id.clone(),
            lease_id: self.lease_id,
        }
    }
}

enum TunSlot {
    Unbound { owner_pid: Option<u32> },
    Bound(Box<TunInterface>),
}

#[derive(Default)]
struct TunTable {
    next_tun_id: u64,
    grants: BTreeMap<u32, Vec<String>>,
    /// Keyed by `OpenRef.id` (clone open-file description identity).
    slots: HashMap<u64, TunSlot>,
    /// Live bound interface names (`"tun0"` -> `open_id`).
    by_name: BTreeMap<String, u64>,
    /// Live `tun_id` -> `open_id`.
    by_tun_id: HashMap<u64, u64>,
}

/// Per-instance registry for `/dev/net/tun` clone descriptors and bound L3 interfaces.
pub struct TunRegistry {
    table: RefCell<TunTable>,
    sink: Rc<dyn TunHostSink>,
    pub caller: Rc<Cell<Option<u32>>>,
    policy: Cell<TunPolicy>,
}

impl TunRegistry {
    pub fn new(sink: Rc<dyn TunHostSink>, caller: Rc<Cell<Option<u32>>>) -> Self {
        Self::with_policy(sink, caller, TunPolicy::default())
    }

    pub fn with_policy(
        sink: Rc<dyn TunHostSink>,
        caller: Rc<Cell<Option<u32>>>,
        policy: TunPolicy,
    ) -> Self {
        Self {
            table: RefCell::new(TunTable {
                next_tun_id: 1,
                ..TunTable::default()
            }),
            sink,
            caller,
            policy: Cell::new(policy),
        }
    }

    pub fn set_policy(&self, policy: TunPolicy) {
        self.policy.set(policy);
    }

    /// Record explicit device grants for `pid` (matching `GuiDeviceRegistry::grant`).
    pub fn grant(&self, pid: u32, devices: &[String]) {
        self.table.borrow_mut().grants.insert(pid, devices.to_vec());
    }

    /// Remove device grant record when `pid` exits.
    pub fn process_exit(&self, pid: u32) {
        self.table.borrow_mut().grants.remove(&pid);
    }

    /// Open a new `/dev/net/tun` clone open-file description.
    pub fn open_clone(&self, cred: &Cred, open: &OpenRef) -> Result<()> {
        // `O_PATH` is allowed strictly for metadata inspection (`fstat`); do not create a TUN slot.
        if open.access == Access::Path {
            return Ok(());
        }
        // DAC `0o600` root-only check (defense in depth).
        if cred.identity.id != 0 {
            return Err(Errno::EACCES);
        }
        let pid = self.caller.get();
        let mut tbl = self.table.borrow_mut();
        let granted = match pid {
            Some(p) => match tbl.grants.get(&p) {
                Some(devs) => devs.iter().any(|d| d == "tun"),
                None => self.policy.get().allow_root_open,
            },
            None => self.policy.get().allow_root_open,
        };
        if !granted {
            return Err(Errno::EPERM);
        }
        tbl.slots
            .insert(open.id, TunSlot::Unbound { owner_pid: pid });
        Ok(())
    }

    /// Release the open description on last-close (or process teardown).
    pub fn release_clone(&self, open: &OpenRef) {
        let closed = {
            let mut tbl = self.table.borrow_mut();
            match tbl.slots.remove(&open.id) {
                Some(TunSlot::Bound(iface)) => {
                    tbl.by_name.remove(&iface.name);
                    tbl.by_tun_id.remove(&iface.tun_id);
                    Some((iface.tun_id, iface.endpoint_id))
                }
                _ => None,
            }
        };
        if let Some((tun_id, endpoint_id)) = closed {
            self.sink.on_close(tun_id, &endpoint_id);
            self.sink.on_wake(tun_id);
        }
    }

    /// Phase 1 of `TUNSETIFF`: validate flags, interface name, MTU, and clone state without
    /// mutating the slot yet (so async host IPAM / Worker attach can run safely).
    pub fn prepare_set_iff(&self, open: &OpenRef, payload: &[u8]) -> Result<PreparedTunAttach> {
        if open.access == Access::Path {
            return Err(Errno::EBADF);
        }
        let req = parse_tun_set_iff_payload(payload)?;
        if req.flags != tun_ioctl::IFF_REQUIRED {
            return Err(Errno::EINVAL);
        }
        let network = req.network.unwrap_or_else(|| "default".to_string());
        if !valid_overlay_network_name(&network) {
            return Err(Errno::EINVAL);
        }
        if let Some(mtu) = req.mtu
            && !(TUN_MIN_MTU..=TUN_MAX_MTU).contains(&mtu)
        {
            return Err(Errno::EINVAL);
        }

        let tbl = self.table.borrow();
        match tbl.slots.get(&open.id) {
            Some(TunSlot::Unbound { .. }) => {}
            Some(TunSlot::Bound(_)) => return Err(Errno::EINVAL),
            None => return Err(Errno::EBADF),
        }
        if tbl.by_name.len() >= TUN_MAX_INTERFACES {
            return Err(Errno::ENOSPC);
        }

        let name = if req.name.is_empty() || req.name == "tun%d" {
            (0..TUN_MAX_INTERFACES)
                .map(|i| format!("tun{i}"))
                .find(|cand| !tbl.by_name.contains_key(cand))
                .ok_or(Errno::ENOSPC)?
        } else {
            if !valid_tun_ifname(&req.name) {
                return Err(Errno::EINVAL);
            }
            if tbl.by_name.contains_key(&req.name) {
                return Err(Errno::EBUSY);
            }
            req.name
        };

        Ok(PreparedTunAttach {
            open_id: open.id,
            name,
            flags: req.flags,
            requested_mtu: req.mtu,
            network,
            static_ip: req.static_ip,
        })
    }

    /// Phase 2 of `TUNSETIFF`: commit the host-allocated [`TunBinding`] to the unbound clone slot.
    pub fn commit_set_iff(
        &self,
        open: &OpenRef,
        name: String,
        binding: TunBinding,
    ) -> Result<(u64, TunSetIffResp)> {
        if open.access == Access::Path {
            return Err(Errno::EBADF);
        }
        if !valid_tun_ifname(&name)
            || !valid_overlay_network_name(&binding.network)
            || !(TUN_MIN_MTU..=TUN_MAX_MTU).contains(&binding.mtu)
            || !(binding.mtu..=TUN_MAX_MTU).contains(&binding.max_mtu)
        {
            return Err(Errno::EINVAL);
        }
        let mut tbl = self.table.borrow_mut();
        match tbl.slots.get(&open.id) {
            Some(TunSlot::Unbound { .. }) => {}
            Some(TunSlot::Bound(_)) => return Err(Errno::EINVAL),
            None => return Err(Errno::EBADF),
        }
        if tbl.by_name.len() >= TUN_MAX_INTERFACES {
            return Err(Errno::ENOSPC);
        }
        if tbl.by_name.contains_key(&name) {
            return Err(Errno::EBUSY);
        }

        let tun_id = tbl.next_tun_id;
        tbl.next_tun_id = tbl.next_tun_id.saturating_add(1);
        let iface = TunInterface {
            tun_id,
            _open_id: open.id,
            name: name.clone(),
            flags: tun_ioctl::IFF_REQUIRED,
            network: binding.network,
            endpoint_id: binding.endpoint_id,
            gateway: binding.gateway,
            lease_id: binding.lease_id,
            max_mtu: binding.max_mtu,
            policy: OverlayEndpointPolicy {
                tenant: binding.tenant,
                leased_ip: binding.ip,
                tenant_cidr_v4: binding.cidr_v4,
                leased_ipv6: binding.ipv6,
                tenant_cidr_v6: binding.cidr_v6,
                mtu: binding.mtu,
                allowed_peer_cidrs: binding.allowed_peer_cidrs,
            },
            rx_queue: VecDeque::new(),
            rx_bytes_queued: 0,
            tx_queue: VecDeque::new(),
            tx_bytes_queued: 0,
            stats: TunStats::default(),
            hungup: None,
        };
        let resp = iface.set_iff_resp();
        tbl.by_name.insert(name, open.id);
        tbl.by_tun_id.insert(tun_id, open.id);
        tbl.slots.insert(open.id, TunSlot::Bound(Box::new(iface)));
        drop(tbl);
        self.sink.on_wake(tun_id);
        Ok((tun_id, resp))
    }

    /// Roll back a committed `TUNSETIFF` when host-side activation fails, restoring the open
    /// descriptor to `Unbound` and releasing the reserved interface name without invoking `on_close`.
    pub fn rollback_set_iff(&self, open: &OpenRef) {
        let mut tbl = self.table.borrow_mut();
        let owner_pid = self.caller.get();
        if let Some(TunSlot::Bound(iface)) = tbl.slots.remove(&open.id) {
            tbl.by_name.remove(&iface.name);
            tbl.by_tun_id.remove(&iface.tun_id);
            tbl.slots.insert(open.id, TunSlot::Unbound { owner_pid });
        }
    }

    /// Convenience synchronous `TUNSETIFF` helper (used by unit tests and local-switch hosts).
    pub fn bind_local_set_iff(
        &self,
        open: &OpenRef,
        payload: &[u8],
        allocate: impl FnOnce(&PreparedTunAttach) -> Result<TunBinding>,
    ) -> Result<(u64, TunSetIffResp)> {
        let prep = self.prepare_set_iff(open, payload)?;
        let binding = allocate(&prep)?;
        self.commit_set_iff(open, prep.name, binding)
    }

    /// Dispatch synchronous TUN ioctls (`TUNGETFEATURES`, `TUNGETIFF`, `TUN_IOC_INFO`,
    /// `TUN_IOC_STATS`, `TUN_IOC_SET_MTU`). Callers dispatch `TUNSETIFF` through
    /// [`Self::prepare_set_iff`] + [`Self::commit_set_iff`].
    pub fn ioctl_sync(&self, open: &OpenRef, request: u32, payload: &[u8]) -> Result<Vec<u8>> {
        if open.access == Access::Path {
            return Err(Errno::EBADF);
        }
        match request {
            tun_ioctl::TUNGETFEATURES => {
                let tbl = self.table.borrow();
                if !tbl.slots.contains_key(&open.id) {
                    return Err(Errno::EBADF);
                }
                serde_json::to_vec(&tun_ioctl::IFF_REQUIRED).map_err(|_| Errno::EIO)
            }
            tun_ioctl::TUNGETIFF => {
                let tbl = self.table.borrow();
                let Some(TunSlot::Bound(iface)) = tbl.slots.get(&open.id) else {
                    return Err(Errno::EBADF);
                };
                serde_json::to_vec(&TunGetIffResp {
                    name: iface.name.clone(),
                    flags: iface.flags,
                })
                .map_err(|_| Errno::EIO)
            }
            tun_ioctl::TUN_IOC_INFO => {
                let tbl = self.table.borrow();
                let Some(TunSlot::Bound(iface)) = tbl.slots.get(&open.id) else {
                    return Err(Errno::EBADF);
                };
                serde_json::to_vec(&iface.info()).map_err(|_| Errno::EIO)
            }
            tun_ioctl::TUN_IOC_STATS => {
                let tbl = self.table.borrow();
                let Some(TunSlot::Bound(iface)) = tbl.slots.get(&open.id) else {
                    return Err(Errno::EBADF);
                };
                serde_json::to_vec(&iface.stats).map_err(|_| Errno::EIO)
            }
            tun_ioctl::TUN_IOC_SET_MTU => {
                let req: TunSetMtuReq =
                    serde_json::from_slice(payload).map_err(|_| Errno::EINVAL)?;
                let mut tbl = self.table.borrow_mut();
                let Some(TunSlot::Bound(iface)) = tbl.slots.get_mut(&open.id) else {
                    return Err(Errno::EBADF);
                };
                if req.mtu < TUN_MIN_MTU || req.mtu > iface.max_mtu {
                    return Err(Errno::EINVAL);
                }
                iface.policy.mtu = req.mtu;
                serde_json::to_vec(&iface.info()).map_err(|_| Errno::EIO)
            }
            _ => Err(Errno::ENOTTY),
        }
    }

    /// Read ONE L3 packet from the TUN RX queue.
    /// - `buf.len() == 0`: returns `Ok(0)` without consuming a packet.
    /// - `0 < buf.len() < pkt.len()`: copies prefix, discards remainder, increments `rx_truncated_reads`.
    /// - Empty queue: returns `Err(hungup_errno)` if hung up, else `Err(Errno::EAGAIN)`.
    pub fn read_packet(&self, open: &OpenRef, buf: &mut [u8]) -> Result<usize> {
        if open.access == Access::Path || !open.access.reads() {
            return Err(Errno::EBADF);
        }
        let mut tbl = self.table.borrow_mut();
        let Some(TunSlot::Bound(iface)) = tbl.slots.get_mut(&open.id) else {
            return Err(Errno::EBADF);
        };
        if buf.is_empty() {
            return Ok(0);
        }
        let Some(pkt) = iface.rx_queue.pop_front() else {
            return Err(iface.hungup.unwrap_or(Errno::EAGAIN));
        };
        iface.rx_bytes_queued = iface.rx_bytes_queued.saturating_sub(pkt.len());
        let copy_len = buf.len().min(pkt.len());
        buf[..copy_len].copy_from_slice(&pkt[..copy_len]);
        if copy_len < pkt.len() {
            iface.stats.rx_truncated_reads = iface.stats.rx_truncated_reads.saturating_add(1);
        }
        Ok(copy_len)
    }

    /// Write ONE L3 packet to the TUN device through [`OverlayFirewall::check_tx`].
    pub fn write_packet(&self, open: &OpenRef, pkt: &[u8]) -> Result<usize> {
        if open.access == Access::Path || !open.access.writes() {
            return Err(Errno::EBADF);
        }
        let (tun_id, tx_queue_empty) = {
            let mut tbl = self.table.borrow_mut();
            let Some(TunSlot::Bound(iface)) = tbl.slots.get_mut(&open.id) else {
                return Err(Errno::EBADF);
            };
            if let Some(err) = iface.hungup {
                return Err(err);
            }
            if let Err(reason) = OverlayFirewall::check_tx(&iface.policy, pkt) {
                match reason {
                    DropReason::ExceedsMtu => {
                        iface.stats.tx_dropped_malformed =
                            iface.stats.tx_dropped_malformed.saturating_add(1);
                        return Err(Errno::EMSGSIZE);
                    }
                    DropReason::MalformedHeader | DropReason::UnsupportedIpVersion => {
                        iface.stats.tx_dropped_malformed =
                            iface.stats.tx_dropped_malformed.saturating_add(1);
                        return Err(Errno::EINVAL);
                    }
                    DropReason::SpoofedSource => {
                        iface.stats.tx_dropped_spoofed_src =
                            iface.stats.tx_dropped_spoofed_src.saturating_add(1);
                        return Ok(pkt.len());
                    }
                    DropReason::SelfLoop => {
                        iface.stats.tx_dropped_self_loop =
                            iface.stats.tx_dropped_self_loop.saturating_add(1);
                        return Ok(pkt.len());
                    }
                    DropReason::CrossTenant => {
                        iface.stats.tx_dropped_cross_tenant =
                            iface.stats.tx_dropped_cross_tenant.saturating_add(1);
                        return Ok(pkt.len());
                    }
                    DropReason::OutsideCidr
                    | DropReason::ForbiddenAddress
                    | DropReason::RxPolicyDenied => {
                        iface.stats.tx_dropped_outside_cidr =
                            iface.stats.tx_dropped_outside_cidr.saturating_add(1);
                        return Ok(pkt.len());
                    }
                }
            }
            if iface.tx_bytes_queued.saturating_add(pkt.len()) > TUN_QUEUE_MAX_BYTES {
                iface.stats.tx_dropped_queue_full =
                    iface.stats.tx_dropped_queue_full.saturating_add(1);
                return Err(Errno::EAGAIN);
            }
            (iface.tun_id, iface.tx_queue.is_empty())
        };

        // Call host TX sink WITHOUT holding `RefCell` borrow so local-switch deliveries to sibling
        // TUN devices on the same registry never re-entrantly panic!
        let consumed = if tx_queue_empty {
            match self.sink.on_tx(tun_id, pkt) {
                Ok(c) => c,
                Err(Errno::EAGAIN) => {
                    if let Ok(mut tbl) = self.table.try_borrow_mut()
                        && let Some(TunSlot::Bound(iface)) = tbl.slots.get_mut(&open.id)
                    {
                        iface.stats.tx_dropped_queue_full =
                            iface.stats.tx_dropped_queue_full.saturating_add(1);
                    }
                    return Err(Errno::EAGAIN);
                }
                Err(e) => return Err(e),
            }
        } else {
            false
        };

        let mut tbl = self.table.borrow_mut();
        let Some(TunSlot::Bound(iface)) = tbl.slots.get_mut(&open.id) else {
            return Err(Errno::EBADF);
        };
        if !consumed {
            if iface.tx_bytes_queued.saturating_add(pkt.len()) > TUN_QUEUE_MAX_BYTES {
                iface.stats.tx_dropped_queue_full =
                    iface.stats.tx_dropped_queue_full.saturating_add(1);
                return Err(Errno::EAGAIN);
            }
            iface.tx_queue.push_back(pkt.to_vec());
            iface.tx_bytes_queued = iface.tx_bytes_queued.saturating_add(pkt.len());
        }
        iface.stats.tx_packets = iface.stats.tx_packets.saturating_add(1);
        iface.stats.tx_bytes = iface.stats.tx_bytes.saturating_add(pkt.len() as u64);
        Ok(pkt.len())
    }

    /// Enqueue an inbound L3 packet into `tun_id`'s `1 MiB` RX queue after enforcing
    /// [`OverlayFirewall::check_rx`]. Returns `Ok(true)` if queued, `Ok(false)` if dropped.
    pub fn inject_rx(&self, tun_id: u64, pkt: &[u8]) -> Result<bool> {
        let accepted = {
            let mut tbl = self.table.borrow_mut();
            let Some(&open_id) = tbl.by_tun_id.get(&tun_id) else {
                return Err(Errno::ENODEV);
            };
            let Some(TunSlot::Bound(iface)) = tbl.slots.get_mut(&open_id) else {
                return Err(Errno::ENODEV);
            };
            if iface.hungup.is_some() {
                return Err(Errno::ENOTCONN);
            }
            if OverlayFirewall::check_rx(&iface.policy, pkt).is_err() {
                iface.stats.rx_dropped_policy = iface.stats.rx_dropped_policy.saturating_add(1);
                return Ok(false);
            }
            if iface.rx_bytes_queued.saturating_add(pkt.len()) > TUN_QUEUE_MAX_BYTES {
                iface.stats.rx_dropped_queue_full =
                    iface.stats.rx_dropped_queue_full.saturating_add(1);
                return Ok(false);
            }
            iface.rx_queue.push_back(pkt.to_vec());
            iface.rx_bytes_queued = iface.rx_bytes_queued.saturating_add(pkt.len());
            iface.stats.rx_packets = iface.stats.rx_packets.saturating_add(1);
            iface.stats.rx_bytes = iface.stats.rx_bytes.saturating_add(pkt.len() as u64);
            true
        };
        if accepted {
            self.sink.on_wake(tun_id);
        }
        Ok(accepted)
    }

    /// Pop the next queued outbound packet from `tun_id`'s TX queue (for async host transports).
    pub fn pop_tx(&self, tun_id: u64) -> Option<Vec<u8>> {
        let pkt = {
            let mut tbl = self.table.borrow_mut();
            let &open_id = tbl.by_tun_id.get(&tun_id)?;
            let Some(TunSlot::Bound(iface)) = tbl.slots.get_mut(&open_id) else {
                return None;
            };
            let pkt = iface.tx_queue.pop_front()?;
            iface.tx_bytes_queued = iface.tx_bytes_queued.saturating_sub(pkt.len());
            pkt
        };
        self.sink.on_wake(tun_id);
        Some(pkt)
    }

    /// Mark an active TUN interface hung up (e.g., lease expired, credential revoked, transport lost).
    /// Coerces transient wait errnos (`EAGAIN` / `EINTR`) to `ENOTCONN` so blocking callers never
    /// livelock retrying a permanently hung-up descriptor.
    pub fn mark_hungup(&self, tun_id: u64, errno: Errno) {
        let terminal_errno = if matches!(errno, Errno::EAGAIN | Errno::EINTR) {
            Errno::ENOTCONN
        } else {
            errno
        };
        let changed = {
            let mut tbl = self.table.borrow_mut();
            let Some(&open_id) = tbl.by_tun_id.get(&tun_id) else {
                return;
            };
            let Some(TunSlot::Bound(iface)) = tbl.slots.get_mut(&open_id) else {
                return;
            };
            if iface.hungup.is_none() {
                iface.hungup = Some(terminal_errno);
                true
            } else {
                false
            }
        };
        if changed {
            self.sink.on_wake(tun_id);
        }
    }

    /// Record a downstream switch/relay drop reason against `tun_id`'s stats.
    pub fn record_tx_drop(&self, tun_id: u64, reason: DropReason) {
        let mut tbl = self.table.borrow_mut();
        let Some(&open_id) = tbl.by_tun_id.get(&tun_id) else {
            return;
        };
        let Some(TunSlot::Bound(iface)) = tbl.slots.get_mut(&open_id) else {
            return;
        };
        match reason {
            DropReason::SpoofedSource => {
                iface.stats.tx_dropped_spoofed_src =
                    iface.stats.tx_dropped_spoofed_src.saturating_add(1);
            }
            DropReason::CrossTenant => {
                iface.stats.tx_dropped_cross_tenant =
                    iface.stats.tx_dropped_cross_tenant.saturating_add(1);
            }
            DropReason::OutsideCidr | DropReason::ForbiddenAddress => {
                iface.stats.tx_dropped_outside_cidr =
                    iface.stats.tx_dropped_outside_cidr.saturating_add(1);
            }
            DropReason::SelfLoop => {
                iface.stats.tx_dropped_self_loop =
                    iface.stats.tx_dropped_self_loop.saturating_add(1);
            }
            DropReason::MalformedHeader
            | DropReason::UnsupportedIpVersion
            | DropReason::ExceedsMtu => {
                iface.stats.tx_dropped_malformed =
                    iface.stats.tx_dropped_malformed.saturating_add(1);
            }
            DropReason::RxPolicyDenied => {
                iface.stats.rx_dropped_policy = iface.stats.rx_dropped_policy.saturating_add(1);
            }
        }
    }

    /// Record an unroutable destination drop (`tx_dropped_no_route++`).
    pub fn record_tx_no_route(&self, tun_id: u64) {
        let mut tbl = self.table.borrow_mut();
        if let Some(&open_id) = tbl.by_tun_id.get(&tun_id)
            && let Some(TunSlot::Bound(iface)) = tbl.slots.get_mut(&open_id)
        {
            iface.stats.tx_dropped_no_route = iface.stats.tx_dropped_no_route.saturating_add(1);
        }
    }

    /// Poll readability or writability of a bound `/dev/net/tun` descriptor for `poll_oneoff`.
    pub fn poll_open(&self, open: &OpenRef, writing: bool) -> Result<TunPollState> {
        if open.access == Access::Path {
            return Err(Errno::EBADF);
        }
        let tbl = self.table.borrow();
        let Some(TunSlot::Bound(iface)) = tbl.slots.get(&open.id) else {
            return Err(Errno::EBADF);
        };
        let hangup = iface.hungup.is_some();
        if !writing {
            if !open.access.reads() {
                return Err(Errno::EBADF);
            }
            let nbytes = iface.rx_queue.front().map_or(0, Vec::len);
            Ok(TunPollState {
                ready: nbytes > 0 || hangup,
                nbytes,
                hangup,
            })
        } else {
            if !open.access.writes() {
                return Err(Errno::EBADF);
            }
            let room = TUN_QUEUE_MAX_BYTES.saturating_sub(iface.tx_bytes_queued);
            let ready = iface
                .tx_bytes_queued
                .saturating_add(usize::from(iface.policy.mtu))
                <= TUN_QUEUE_MAX_BYTES
                || hangup;
            Ok(TunPollState {
                ready,
                nbytes: if hangup { 0 } else { room },
                hangup,
            })
        }
    }

    /// Return all active bound TUN interface IDs and endpoint IDs (used on shutdown/sign-out).
    pub fn active_tuns(&self) -> Vec<(u64, String, String)> {
        let tbl = self.table.borrow();
        tbl.slots
            .values()
            .filter_map(|slot| match slot {
                TunSlot::Bound(i) => Some((i.tun_id, i.name.clone(), i.endpoint_id.clone())),
                TunSlot::Unbound { .. } => None,
            })
            .collect()
    }

    /// Query `TunInfo` by `tun_id`.
    pub fn info_by_tun_id(&self, tun_id: u64) -> Option<TunInfo> {
        let tbl = self.table.borrow();
        let &open_id = tbl.by_tun_id.get(&tun_id)?;
        match tbl.slots.get(&open_id) {
            Some(TunSlot::Bound(i)) => Some(i.info()),
            _ => None,
        }
    }

    /// Query `TunStats` by `tun_id`.
    pub fn stats_by_tun_id(&self, tun_id: u64) -> Option<TunStats> {
        let tbl = self.table.borrow();
        let &open_id = tbl.by_tun_id.get(&tun_id)?;
        match tbl.slots.get(&open_id) {
            Some(TunSlot::Bound(i)) => Some(i.stats.clone()),
            _ => None,
        }
    }

    /// Query owning PID of an unbound/bound open slot (if recorded at `open`).
    pub fn owner_pid_for_open(&self, open: &OpenRef) -> Option<u32> {
        let tbl = self.table.borrow();
        match tbl.slots.get(&open.id) {
            Some(TunSlot::Unbound { owner_pid }) => *owner_pid,
            _ => None,
        }
    }

    /// Query the bound `tun_id` for an open descriptor, if attached.
    pub fn tun_id_for_open(&self, open: &OpenRef) -> Option<u64> {
        let tbl = self.table.borrow();
        match tbl.slots.get(&open.id) {
            Some(TunSlot::Bound(i)) => Some(i.tun_id),
            _ => None,
        }
    }

    /// Mark every currently bound TUN interface as hung up with `errno` (e.g. cloud sign-out/revocation).
    pub fn mark_all_hungup(&self, errno: Errno) {
        let ids: Vec<u64> = self.table.borrow().by_tun_id.keys().copied().collect();
        for id in ids {
            self.mark_hungup(id, errno);
        }
    }

    /// Number of currently bound TUN interfaces.
    pub fn bound_count(&self) -> usize {
        self.table.borrow().by_name.len()
    }
}

/// Outermost `DeviceBackend` decorator handling `/dev/net/tun` (`rdev == "net:tun"`).
pub struct TunDeviceBackend<D = DefaultDeviceBackend> {
    pub registry: Rc<TunRegistry>,
    inner: D,
}

impl<D> TunDeviceBackend<D> {
    pub fn new(inner: D, registry: Rc<TunRegistry>) -> Self {
        Self { registry, inner }
    }

    pub fn inner(&self) -> &D {
        &self.inner
    }

    pub fn registry(&self) -> &Rc<TunRegistry> {
        &self.registry
    }
}

impl<D: DeviceBackend> DeviceBackend for TunDeviceBackend<D> {
    fn open_device(&self, rdev: &str, cred: &Cred, open: &OpenRef) -> Result<()> {
        if rdev == TUN_RDEV {
            return self.registry.open_clone(cred, open);
        }
        self.inner.open_device(rdev, cred, open)
    }

    fn release_device(&self, open: &OpenRef) {
        self.registry.release_clone(open);
        self.inner.release_device(open);
    }

    fn poll_device(&self, rdev: &str, open: &OpenRef, writing: bool) -> Result<Option<usize>> {
        if rdev == TUN_RDEV {
            let st = self.registry.poll_open(open, writing)?;
            return Ok(Some(if st.ready { st.nbytes.max(1) } else { 0 }));
        }
        self.inner.poll_device(rdev, open, writing)
    }

    fn fill_random(&self, buf: &mut [u8]) -> Result<()> {
        self.inner.fill_random(buf)
    }

    fn read_open_device<'a>(
        &'a self,
        rdev: &'a str,
        open: &'a OpenRef,
        buf: &'a mut [u8],
        offset: u64,
    ) -> BoxFuture<'a, usize> {
        if rdev == TUN_RDEV {
            return Box::pin(async move { self.registry.read_packet(open, buf) });
        }
        self.inner.read_open_device(rdev, open, buf, offset)
    }

    fn write_open_device<'a>(
        &'a self,
        rdev: &'a str,
        open: &'a OpenRef,
        buf: &'a [u8],
        at: WriteAt,
    ) -> BoxFuture<'a, Written> {
        if rdev == TUN_RDEV {
            return Box::pin(async move {
                let len = self.registry.write_packet(open, buf)?;
                Ok(Written { offset: 0, len })
            });
        }
        self.inner.write_open_device(rdev, open, buf, at)
    }

    fn read_device<'a>(
        &'a self,
        rdev: &'a str,
        buf: &'a mut [u8],
        offset: u64,
    ) -> BoxFuture<'a, usize> {
        if rdev == TUN_RDEV {
            return Box::pin(async { Err(Errno::EBADF) });
        }
        self.inner.read_device(rdev, buf, offset)
    }

    fn write_device<'a>(
        &'a self,
        rdev: &'a str,
        buf: &'a [u8],
        at: WriteAt,
    ) -> BoxFuture<'a, Written> {
        if rdev == TUN_RDEV {
            return Box::pin(async { Err(Errno::EBADF) });
        }
        self.inner.write_device(rdev, buf, at)
    }

    fn sync_device<'a>(&'a self, rdev: &'a str) -> BoxFuture<'a, ()> {
        if rdev == TUN_RDEV {
            return Box::pin(async { Err(Errno::EINVAL) });
        }
        self.inner.sync_device(rdev)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devfs::DevTmpFs;
    use crate::memfs::MemFs;
    use crate::{
        DefaultFilesystemFactory, FdTable, FileRef, Filesystem, FsId, FsType, MountBacking,
        MountFlags, OpenOptions, ReleaseQueue, SeekFrom, StartAnchor, Vfs, now_or_never,
    };
    use abi::contract::mount_flags;
    use abi::overlay::TUN_DEFAULT_MTU;
    use abi::overlay::{build_ipv4_packet, derive_tenant_v4_cidr};

    #[derive(Default)]
    struct TestSink {
        wakes: RefCell<Vec<u64>>,
        closed: RefCell<Vec<(u64, String)>>,
    }

    impl TunHostSink for TestSink {
        fn on_tx(&self, _tun_id: u64, _pkt: &[u8]) -> Result<bool> {
            Ok(false) // queue in tx_queue so we can test 1 MiB TX bound!
        }
        fn on_wake(&self, tun_id: u64) {
            self.wakes.borrow_mut().push(tun_id);
        }
        fn on_close(&self, tun_id: u64, endpoint_id: &str) {
            self.closed
                .borrow_mut()
                .push((tun_id, endpoint_id.to_string()));
        }
    }

    fn make_binding(tenant: &str, host_idx: u32, ep: &str, mtu: u16) -> TunBinding {
        let cidr = derive_tenant_v4_cidr(tenant);
        TunBinding {
            tenant: tenant.to_string(),
            network: "default".to_string(),
            endpoint_id: ep.to_string(),
            ip: cidr.host_ip(host_idx).unwrap(),
            prefix_len: cidr.prefix_len,
            gateway: cidr.gateway_addr().unwrap(),
            cidr_v4: cidr,
            ipv6: None,
            cidr_v6: None,
            mtu,
            max_mtu: TUN_MAX_MTU,
            lease_id: 100 + u64::from(host_idx),
            allowed_peer_cidrs: Vec::new(),
        }
    }

    fn run<F: std::future::Future>(f: F) -> F::Output {
        now_or_never(f).expect("sync future")
    }

    #[test]
    fn ov02_clone_isolation_acl_ioctl_packets_queues_poll_and_cleanup() {
        let sink = Rc::new(TestSink::default());
        let caller = Rc::new(Cell::new(Some(10)));
        let tun_reg = Rc::new(TunRegistry::new(
            Rc::clone(&sink) as Rc<dyn TunHostSink>,
            Rc::clone(&caller),
        ));
        let dev = Rc::new(DevTmpFs::new(
            FsId("devtmpfs".into()),
            1,
            Box::new(|| (1_700_000_000, 0)),
            TunDeviceBackend::new(DefaultDeviceBackend, Rc::clone(&tun_reg)),
        ));
        dev.register_tun_device().unwrap();

        let root = Cred::root();
        let mut user = Cred::root();
        user.identity.id = 1000;
        user.identity.group = 1000;

        let net_dir = run(dev.lookup(&root, &dev.root(), "net")).unwrap();
        assert_eq!(net_dir.metadata.mode & 0o777, 0o755);
        let tun_ent = run(dev.lookup(&root, &net_dir.handle, "tun")).unwrap();
        assert_eq!(
            (
                tun_ent.metadata.mode & 0o777,
                tun_ent.metadata.uid,
                tun_ent.metadata.gid,
                tun_ent.metadata.rdev.as_deref()
            ),
            (0o600, 0, 0, Some(TUN_RDEV))
        );

        let mut rw = OpenOptions::new();
        rw.read(true).write(true);
        let mut path_opts = OpenOptions::new();
        path_opts.path(true);

        // 1. O_PATH allowed for metadata, fails EBADF on ioctl/read/write.
        let path_open = run(dev.open(&user, &tun_ent.handle, &path_opts)).unwrap();
        assert_eq!(
            tun_reg.ioctl_sync(&path_open, tun_ioctl::TUNGETFEATURES, &[]),
            Err(Errno::EBADF)
        );
        run(dev.release(&path_open)).unwrap();

        // 2. Non-root -> EACCES; root without "tun" grant -> EPERM.
        assert_eq!(
            run(dev.open(&user, &tun_ent.handle, &rw)),
            Err(Errno::EACCES)
        );
        assert_eq!(
            run(dev.open(&root, &tun_ent.handle, &rw)),
            Err(Errno::EPERM)
        );

        // 3. Grant "tun" to pid 10 -> two opens produce independent unbound clones.
        tun_reg.grant(10, &["tun".into()]);
        let open_a = run(dev.open(&root, &tun_ent.handle, &rw)).unwrap();
        let open_b = run(dev.open(&root, &tun_ent.handle, &rw)).unwrap();
        assert_ne!(open_a.id, open_b.id);

        // Unbound fd: TUNGETFEATURES works, TUNGETIFF / read / write / poll fail EBADF.
        let feat: u16 = serde_json::from_slice(
            &tun_reg
                .ioctl_sync(&open_a, tun_ioctl::TUNGETFEATURES, &[])
                .unwrap(),
        )
        .unwrap();
        assert_eq!(feat, tun_ioctl::IFF_REQUIRED);
        assert_eq!(
            tun_reg.ioctl_sync(&open_a, tun_ioctl::TUNGETIFF, &[]),
            Err(Errno::EBADF)
        );
        assert_eq!(
            tun_reg.read_packet(&open_a, &mut [0u8; 64]),
            Err(Errno::EBADF)
        );
        assert_eq!(tun_reg.poll_open(&open_a, false), Err(Errno::EBADF));

        // 4. TUNSETIFF validation: IFF_TAP / missing IFF_NO_PI / bad name -> EINVAL.
        for bad_payload in [
            serde_json::json!({"name": "tun0", "flags": tun_ioctl::IFF_TAP | tun_ioctl::IFF_NO_PI}),
            serde_json::json!({"name": "tun0", "flags": tun_ioctl::IFF_TUN}),
            serde_json::json!({"name": "tun0", "flags": tun_ioctl::IFF_REQUIRED | 0x0004}),
            serde_json::json!({"name": "9badname", "flags": tun_ioctl::IFF_REQUIRED}),
            serde_json::json!({"name": "waytoolonginterfacename", "flags": tun_ioctl::IFF_REQUIRED}),
        ] {
            assert_eq!(
                tun_reg.prepare_set_iff(&open_a, &serde_json::to_vec(&bad_payload).unwrap()),
                Err(Errno::EINVAL)
            );
        }

        // Auto-allocate tun0 and tun1; duplicate name -> EBUSY; re-attach -> EINVAL.
        let (tun_a, resp_a) = tun_reg
            .bind_local_set_iff(
                &open_a,
                &serde_json::to_vec(
                    &serde_json::json!({"name": "", "flags": tun_ioctl::IFF_REQUIRED}),
                )
                .unwrap(),
                |_| Ok(make_binding("u1000", 0, "ep-a", TUN_DEFAULT_MTU)),
            )
            .unwrap();
        assert_eq!(resp_a.name, "tun0");
        assert_eq!(
            tun_reg.prepare_set_iff(
                &open_a,
                &serde_json::to_vec(
                    &serde_json::json!({"name": "tun2", "flags": tun_ioctl::IFF_REQUIRED})
                )
                .unwrap()
            ),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            tun_reg.prepare_set_iff(
                &open_b,
                &serde_json::to_vec(
                    &serde_json::json!({"name": "tun0", "flags": tun_ioctl::IFF_REQUIRED})
                )
                .unwrap()
            ),
            Err(Errno::EBUSY)
        );
        let (tun_b, resp_b) = tun_reg
            .bind_local_set_iff(
                &open_b,
                &serde_json::to_vec(
                    &serde_json::json!({"name": "tun%d", "flags": tun_ioctl::IFF_REQUIRED}),
                )
                .unwrap(),
                |_| Ok(make_binding("u1000", 1, "ep-b", TUN_DEFAULT_MTU)),
            )
            .unwrap();
        assert_eq!(resp_b.name, "tun1");
        assert_ne!(tun_a, tun_b);

        // 5. Packet boundary preservation, 0-byte read, small-buffer truncation, >MTU EMSGSIZE.
        let ip_a: Ipv4Addr = resp_a.ip.parse().unwrap();
        let ip_b: Ipv4Addr = resp_b.ip.parse().unwrap();
        let pkt1 = build_ipv4_packet(ip_b, ip_a, 17, 64, b"packet-one-payload");
        let pkt2 = build_ipv4_packet(ip_b, ip_a, 17, 64, b"second");
        assert!(tun_reg.inject_rx(tun_a, &pkt1).unwrap());
        assert!(tun_reg.inject_rx(tun_a, &pkt2).unwrap());

        // 0-byte read returns 0 without consuming pkt1.
        assert_eq!(tun_reg.read_packet(&open_a, &mut []), Ok(0));
        // Poll reports pkt1 len.
        let p_rd = tun_reg.poll_open(&open_a, false).unwrap();
        assert!(p_rd.ready && !p_rd.hangup && p_rd.nbytes == pkt1.len());

        // Small buffer truncates pkt1 and discards remainder; next read gets pkt2 intact!
        let mut small = [0u8; 10];
        assert_eq!(tun_reg.read_packet(&open_a, &mut small), Ok(10));
        assert_eq!(&small, &pkt1[..10]);
        let mut full = [0u8; 256];
        let n2 = tun_reg.read_packet(&open_a, &mut full).unwrap();
        assert_eq!(&full[..n2], pkt2.as_slice());
        assert_eq!(tun_reg.read_packet(&open_a, &mut full), Err(Errno::EAGAIN));
        assert_eq!(
            tun_reg.stats_by_tun_id(tun_a).unwrap().rx_truncated_reads,
            1
        );

        // Write > MTU -> EMSGSIZE; bad IP header -> EINVAL.
        let oversize = build_ipv4_packet(ip_a, ip_b, 17, 64, &vec![0x5a; 1405]);
        assert_eq!(
            tun_reg.write_packet(&open_a, &oversize),
            Err(Errno::EMSGSIZE)
        );
        assert_eq!(
            tun_reg.write_packet(&open_a, &[0x45, 0x00]),
            Err(Errno::EINVAL)
        );

        // 6. Exact 1 MiB RX drop-tail and 1 MiB TX EAGAIN backpressure!
        let chunk_rx = build_ipv4_packet(ip_b, ip_a, 17, 64, &vec![0x11; 1004]); // 1024 B exact!
        assert_eq!(chunk_rx.len(), 1024);
        for _ in 0..1024 {
            assert!(tun_reg.inject_rx(tun_a, &chunk_rx).unwrap());
        }
        // 1025th packet exceeds 1 MiB -> drop-tail!
        assert!(!tun_reg.inject_rx(tun_a, &chunk_rx).unwrap());
        assert_eq!(
            tun_reg
                .stats_by_tun_id(tun_a)
                .unwrap()
                .rx_dropped_queue_full,
            1
        );

        let chunk_tx = build_ipv4_packet(ip_a, ip_b, 17, 64, &vec![0x22; 1004]); // 1024 B exact!
        for _ in 0..1024 {
            assert_eq!(tun_reg.write_packet(&open_a, &chunk_tx), Ok(1024));
        }
        assert_eq!(tun_reg.write_packet(&open_a, &chunk_tx), Err(Errno::EAGAIN));
        assert!(!tun_reg.poll_open(&open_a, true).unwrap().ready);
        // Pop 2 packets -> writable again!
        assert!(tun_reg.pop_tx(tun_a).is_some());
        assert!(tun_reg.pop_tx(tun_a).is_some());
        assert!(tun_reg.poll_open(&open_a, true).unwrap().ready);

        // 7. Hangup sets poll hangup=true, fails writes, drains RX before returning error.
        tun_reg.mark_hungup(tun_b, Errno::ESTALE);
        assert_eq!(tun_reg.write_packet(&open_b, &pkt1), Err(Errno::ESTALE));
        let hb = tun_reg.poll_open(&open_b, false).unwrap();
        assert!(hb.ready && hb.hangup);
        assert_eq!(tun_reg.read_packet(&open_b, &mut full), Err(Errno::ESTALE));

        // 8. dup shares one interface; last close fires on_close and frees name!
        let clock: Rc<dyn Fn() -> (u64, u32)> = Rc::new(|| (1_700_000_000, 0));
        let root_fs = Rc::new(MemFs::new(
            FsId("mem:root".into()),
            1,
            0,
            0,
            0o755,
            Box::new(|| (1_700_000_000, 0)),
        ));
        let vfs = run(Vfs::boot(
            "tun-test",
            Rc::new(MountBacking::new(root_fs, FsType::TmpFs)),
            "tmpfs",
            Rc::new(DefaultFilesystemFactory::new(clock)),
        ))
        .unwrap();
        run(vfs.mkdirat(1, StartAnchor::Root, "/dev", 0o755)).unwrap();
        run(vfs.mount_on_namespace(
            &vfs.system_namespace(),
            &Cred::root(),
            Rc::new(MountBacking::new(
                Rc::clone(&dev) as Rc<dyn Filesystem>,
                FsType::DevTmpFs,
            )),
            None,
            "devtmpfs",
            "/dev",
            MountFlags::from_accepted(mount_flags::MS_NOSUID),
            0,
            None,
        ))
        .unwrap();
        let releases = ReleaseQueue::new();
        let mut table = FdTable::new();
        let fd_a = table
            .insert(
                FileRef::new(
                    Rc::clone(&dev) as Rc<dyn Filesystem>,
                    open_a.clone(),
                    tun_ent.handle.clone(),
                    root.clone(),
                    &rw,
                    &releases,
                ),
                true,
            )
            .unwrap();
        // seek/pread/pwrite on net:tun return EPIPE at VFS layer (mapped to WASI ESPIPE at host boundary).
        assert_eq!(
            run(table.get(fd_a).unwrap().seek(SeekFrom::Start(0))),
            Err(Errno::EPIPE)
        );
        assert_eq!(
            run(table.get(fd_a).unwrap().read_at(&mut [0u8; 4], 0)),
            Err(Errno::EPIPE)
        );
        assert_eq!(
            run(table.get(fd_a).unwrap().write_at(b"abcd", 0)),
            Err(Errno::EPIPE)
        );

        let dup_a = table.dup(fd_a, 0, true).unwrap();
        run(table.close(fd_a)).unwrap();
        // Still bound while dup_a is open!
        assert_eq!(tun_reg.bound_count(), 2);
        assert!(sink.closed.borrow().is_empty());
        run(table.close(dup_a)).unwrap();
        assert_eq!(tun_reg.bound_count(), 1);
        assert_eq!(sink.closed.borrow().as_slice(), &[(tun_a, "ep-a".into())]);
        run(dev.release(&open_b)).unwrap();
        assert_eq!(tun_reg.bound_count(), 0);
    }

    #[test]
    fn ov02_hangup_coerces_transient_errnos_to_enotconn() {
        let sink = Rc::new(TestSink::default());
        let caller = Rc::new(Cell::new(Some(10)));
        let tun_reg = Rc::new(TunRegistry::with_policy(
            Rc::clone(&sink) as Rc<dyn TunHostSink>,
            Rc::clone(&caller),
            TunPolicy {
                allow_root_open: true,
            },
        ));
        let dev = Rc::new(DevTmpFs::new(
            FsId("devtmpfs-hangup".into()),
            1,
            Box::new(|| (1_700_000_000, 0)),
            TunDeviceBackend::new(DefaultDeviceBackend, Rc::clone(&tun_reg)),
        ));
        dev.register_tun_device().unwrap();
        let root = Cred::root();
        let net_dir = run(dev.lookup(&root, &dev.root(), "net")).unwrap();
        let tun_ent = run(dev.lookup(&root, &net_dir.handle, "tun")).unwrap();
        let mut rw = OpenOptions::new();
        rw.read(true).write(true);
        let open_a = run(dev.open(&root, &tun_ent.handle, &rw)).unwrap();
        let open_b = run(dev.open(&root, &tun_ent.handle, &rw)).unwrap();

        let (tun_a, _) = tun_reg
            .commit_set_iff(
                &open_a,
                "tun0".into(),
                make_binding("u0", 0, "ep-a", TUN_DEFAULT_MTU),
            )
            .unwrap();
        let (_tun_b, _) = tun_reg
            .commit_set_iff(
                &open_b,
                "tun1".into(),
                make_binding("u0", 1, "ep-b", TUN_DEFAULT_MTU),
            )
            .unwrap();

        // Transient EAGAIN on `mark_hungup` MUST be coerced to terminal ENOTCONN.
        let mut rx_buf = [0u8; 64];
        tun_reg.mark_hungup(tun_a, Errno::EAGAIN);
        assert_eq!(
            tun_reg.read_packet(&open_a, &mut rx_buf),
            Err(Errno::ENOTCONN)
        );
        assert_eq!(
            tun_reg.write_packet(&open_a, &[0x45; 20]),
            Err(Errno::ENOTCONN)
        );

        // Transient EINTR on `mark_all_hungup` MUST also coerce to terminal ENOTCONN.
        tun_reg.mark_all_hungup(Errno::EINTR);
        assert_eq!(
            tun_reg.read_packet(&open_b, &mut rx_buf),
            Err(Errno::ENOTCONN)
        );
        assert_eq!(
            tun_reg.write_packet(&open_b, &[0x45; 20]),
            Err(Errno::ENOTCONN)
        );

        run(dev.release(&open_a)).unwrap();
        run(dev.release(&open_b)).unwrap();
    }
}

//! Browser `/dev/net/tun` bridge (`BrowserTunSink`, `TUNSETIFF` async attach via `ServiceAuth v2`
//! + `overlay-transport.js`, `tun_poll`, `tun_inject_rx`, and cloud-revocation hangup).
//!
//! **Zero-boot-network invariant**: `/dev/net/tun` is registered locally in `DevTmpFs` with zero
//! network requests; `globalThis.overlayHost` is only called on explicit `ioctl(TUNSETIFF)`.

use crate::vfs_engine::{json_to_js, map_errno};
use crate::{Kernel, ServiceMintKind, mint_for_service};
use abi::Errno;
use abi::overlay::{
    DropReason, IpCidr, Ipv4Cidr, OverlayAttachReply, TUN_DEFAULT_MTU, TUN_MAX_MTU, TUN_MIN_MTU,
    TUN_RDEV, tun_ioctl,
};
use js_sys::{Function, Promise, Reflect, Uint8Array};
use serde_json::{Value, json};
use std::net::Ipv4Addr;
use std::rc::Rc;
use vfs::Vfs;
use vfs::tundev::{TunBinding, TunHostSink, TunRegistry};
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

fn overlay_host_fn(method: &str) -> Option<(JsValue, Function)> {
    let host = Reflect::get(&js_sys::global(), &"overlayHost".into()).ok()?;
    if host.is_undefined() || host.is_null() {
        return None;
    }
    let f = Reflect::get(&host, &method.into())
        .ok()?
        .dyn_into::<Function>()
        .ok()?;
    Some((host, f))
}

/// Host sink wired into `vfs::tundev::TunRegistry` inside the browser `client-kernel`.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct BrowserTunSink;

impl TunHostSink for BrowserTunSink {
    fn on_tx(&self, tun_id: u64, pkt: &[u8]) -> vfs::Result<bool> {
        let Some((host, func)) = overlay_host_fn("sendTx") else {
            return Err(Errno::ENOTCONN);
        };
        let arr = Uint8Array::from(pkt);
        match func.call2(&host, &JsValue::from_f64(tun_id as f64), &arr.into()) {
            Ok(v) => {
                if v.as_bool() == Some(false) {
                    Err(Errno::EAGAIN)
                } else {
                    Ok(true)
                }
            }
            Err(_) => Err(Errno::EIO),
        }
    }

    fn on_wake(&self, tun_id: u64) {
        if let Some((host, func)) = overlay_host_fn("wake") {
            let _ = func.call1(&host, &JsValue::from_f64(tun_id as f64));
        }
    }

    fn on_close(&self, tun_id: u64, endpoint_id: &str) {
        if let Some((host, func)) = overlay_host_fn("onClose") {
            let _ = func.call2(
                &host,
                &JsValue::from_f64(tun_id as f64),
                &JsValue::from_str(endpoint_id),
            );
        }
    }
}

fn parse_errno_str(name: &str) -> Errno {
    match name {
        "EACCES" => Errno::EACCES,
        "EPERM" => Errno::EPERM,
        "ESTALE" => Errno::ESTALE,
        "ENOTCONN" => Errno::ENOTCONN,
        "ECONNRESET" => Errno::ECONNRESET,
        "ENOSPC" => Errno::ENOSPC,
        "EBUSY" => Errno::EBUSY,
        "EINVAL" => Errno::EINVAL,
        "ETIMEDOUT" => Errno::ETIMEDOUT,
        _ => Errno::EIO,
    }
}

fn parse_drop_reason(reason: &str) -> Option<DropReason> {
    match reason {
        "spoofed_source" => Some(DropReason::SpoofedSource),
        "cross_tenant" => Some(DropReason::CrossTenant),
        "outside_cidr" => Some(DropReason::OutsideCidr),
        "malformed_header" => Some(DropReason::MalformedHeader),
        "self_loop" => Some(DropReason::SelfLoop),
        "exceeds_mtu" => Some(DropReason::ExceedsMtu),
        "forbidden_address" => Some(DropReason::ForbiddenAddress),
        "rx_policy_denied" => Some(DropReason::RxPolicyDenied),
        _ => None,
    }
}

/// Await any in-flight browser `/api/overlay/detach` requests before revoking `ServiceAuth v2`
/// tokens or finishing process exit (no-op resolved future when overlay transport is dormant).
pub(crate) async fn flush_overlay_detaches_js() {
    let Some((host, func)) = overlay_host_fn("flushDetaches") else {
        return;
    };
    if let Ok(res) = func.call0(&host)
        && res.is_instance_of::<Promise>()
    {
        let _ = JsFuture::from(Promise::from(res)).await;
    }
}

impl Kernel {
    pub(crate) fn tun_registry(&self) -> Rc<TunRegistry> {
        Rc::clone(&self.vfs_rt.borrow().dev_fs.backend().registry)
    }

    pub(crate) fn hangup_all_tuns(&self, errno: Errno) {
        self.tun_registry().mark_all_hungup(errno);
        if let Some((host, func)) = overlay_host_fn("detachAll") {
            let _ = func.call0(&host);
        }
    }

    pub(crate) async fn flush_overlay_detaches(&self) {
        flush_overlay_detaches_js().await;
    }

    pub(crate) async fn tun_ioctl(
        &self,
        vfs: &Vfs,
        pid: u32,
        raw_fd: u32,
        request: u32,
        arg: Value,
    ) -> Result<Value, abi::Error> {
        let cred = vfs.process_cred(pid)?;
        let file = vfs.process_fds(pid)?.borrow().get(raw_fd)?;
        if file.access() == vfs::Access::Path {
            return Err(Errno::EBADF.into());
        }
        let meta = file.metadata_as(&cred).await?;
        if meta.rdev.as_deref() != Some(TUN_RDEV) {
            return Err(Errno::ENOTTY.into());
        }
        let payload: Vec<u8> = if let Some(arr) = arg.as_array()
            && arr.len() == 40
            && arr.iter().all(|v| v.as_u64().is_some_and(|n| n <= 255))
        {
            arr.iter().map(|v| v.as_u64().unwrap() as u8).collect()
        } else if arg.is_null() {
            Vec::new()
        } else {
            serde_json::to_vec(&arg).unwrap_or_default()
        };

        let tun_reg = self.tun_registry();
        if request == tun_ioctl::TUNSETIFF {
            let prepared = tun_reg.prepare_set_iff(file.open_ref(), &payload)?;

            // Enforce authenticated, non-revoked ServiceAuth v2 credential with `RemoteScope.overlay`.
            let rem = mint_for_service(&self.state, pid, ServiceMintKind::Overlay).await?;
            let overlay_scope = rem
                .scope
                .overlay
                .clone()
                .ok_or_else(|| abi::Error::because(Errno::EACCES, "overlay scope required"))?;
            if !overlay_scope.allows_network(&prepared.network) {
                return Err(abi::Error::because(
                    Errno::EACCES,
                    format!(
                        "overlay network '{}' not permitted by scope",
                        prepared.network
                    ),
                ));
            }
            if tun_reg.bound_count() >= usize::from(overlay_scope.max_interfaces) {
                return Err(Errno::ENOSPC.into());
            }

            let req_mtu = prepared
                .requested_mtu
                .unwrap_or(TUN_DEFAULT_MTU)
                .min(overlay_scope.max_mtu)
                .clamp(TUN_MIN_MTU, TUN_MAX_MTU);
            let instance_id = self.state.borrow().instance_id.clone();

            let (host, attach_fn) = overlay_host_fn("attach").ok_or_else(|| {
                abi::Error::because(Errno::ENOSYS, "overlay host transport unavailable")
            })?;
            let attach_arg = json!({
                "token": rem.token,
                "instance_id": instance_id,
                "network": prepared.network,
                "ifname": prepared.name,
                "mtu": req_mtu,
                "static_ip": prepared.static_ip,
            });
            let js_arg = json_to_js(&attach_arg).map_err(|_| abi::Error::from(Errno::EINVAL))?;
            let call_res = attach_fn.call1(&host, &js_arg).map_err(|e| {
                let errno = extract_js_errno(&e).unwrap_or(Errno::EIO);
                abi::Error::from(errno)
            })?;
            let resolved = if call_res.is_instance_of::<Promise>() {
                JsFuture::from(Promise::from(call_res)).await.map_err(|e| {
                    let errno = extract_js_errno(&e).unwrap_or(Errno::EIO);
                    abi::Error::from(errno)
                })?
            } else {
                call_res
            };
            let text: String = js_sys::JSON::stringify(&resolved)
                .map_err(|_| abi::Error::from(Errno::EIO))?
                .into();
            let reply: OverlayAttachReply =
                serde_json::from_str(&text).map_err(|_| abi::Error::from(Errno::EIO))?;

            let ip: Ipv4Addr = reply.ip.parse().map_err(|_| Errno::EIO)?;
            let cidr_v4 = Ipv4Cidr::parse(&reply.cidr).ok_or(Errno::EIO)?;
            let gateway: Ipv4Addr = reply
                .gateway
                .parse()
                .ok()
                .or_else(|| cidr_v4.gateway_addr())
                .ok_or(Errno::EIO)?;
            let allowed_peer_cidrs: Vec<IpCidr> = overlay_scope
                .allowed_peer_cidrs
                .iter()
                .filter_map(|s| IpCidr::parse(s))
                .collect();
            let eff_mtu = reply
                .mtu
                .min(overlay_scope.max_mtu)
                .clamp(TUN_MIN_MTU, TUN_MAX_MTU);
            let max_mtu = overlay_scope.max_mtu.clamp(eff_mtu, TUN_MAX_MTU);

            let ipv6 = reply.ipv6.as_deref().and_then(|s| s.parse().ok());
            let cidr_v6 = ipv6.map(|_| abi::overlay::derive_tenant_v6_cidr(&reply.tenant));
            let binding = TunBinding {
                tenant: reply.tenant,
                network: reply.network,
                endpoint_id: reply.endpoint_id.clone(),
                ip,
                prefix_len: reply.prefix_len,
                gateway,
                cidr_v4,
                ipv6,
                cidr_v6,
                mtu: eff_mtu,
                max_mtu,
                lease_id: reply.lease_id,
                allowed_peer_cidrs,
            };

            let (tun_id, resp) =
                match tun_reg.commit_set_iff(file.open_ref(), prepared.name, binding) {
                    Ok(v) => v,
                    Err(e) => {
                        if let Some((h, f)) = overlay_host_fn("onClose") {
                            let _ = f.call2(
                                &h,
                                &JsValue::from_f64(0.0),
                                &JsValue::from_str(&reply.endpoint_id),
                            );
                        }
                        return Err(e.into());
                    }
                };

            if let Some((h, f)) = overlay_host_fn("bindTunId") {
                let _ = f.call2(
                    &h,
                    &JsValue::from_str(&reply.endpoint_id),
                    &JsValue::from_f64(tun_id as f64),
                );
            }
            return serde_json::to_value(&resp).map_err(|_| abi::Error::from(Errno::EIO));
        }

        let bytes = tun_reg.ioctl_sync(file.open_ref(), request, &payload)?;
        let val: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        Ok(val)
    }
}

fn extract_js_errno(val: &JsValue) -> Option<Errno> {
    if let Ok(code) = Reflect::get(val, &"errno".into())
        && let Some(s) = code.as_string()
    {
        return Some(parse_errno_str(&s));
    }
    None
}

#[wasm_bindgen]
impl Kernel {
    /// Poll a `/dev/net/tun` kernel fd for readability (`writing == false`) or writability.
    pub fn tun_poll(&self, pid: u32, kfd: u32, writing: bool) -> Result<JsValue, JsValue> {
        let rt = self.vfs_rt.borrow();
        let file = rt.vfs.get_file(pid, kfd).map_err(map_errno)?;
        let st = rt
            .dev_fs
            .backend()
            .registry
            .poll_open(file.open_ref(), writing)
            .map_err(map_errno)?;
        json_to_js(&json!({
            "ready": st.ready,
            "nbytes": st.nbytes,
            "hangup": st.hangup,
        }))
    }

    /// Inject an inbound L3 packet received by `overlay-transport.js` into a bound TUN interface.
    pub fn tun_inject_rx(&self, tun_id: u32, packet: &[u8]) -> bool {
        self.tun_registry()
            .inject_rx(u64::from(tun_id), packet)
            .is_ok()
    }

    /// Mark a bound TUN interface as hung up (lease expiry, revocation, or WS close).
    pub fn tun_mark_hungup(&self, tun_id: u32, errno_name: &str) {
        self.tun_registry()
            .mark_hungup(u64::from(tun_id), parse_errno_str(errno_name));
    }

    /// Record a server-reported TX drop reason (e.g. `DropNotice` from `OverlayRelay` DO).
    pub fn tun_record_drop(&self, tun_id: u32, reason: &str) {
        if reason == "no_route" {
            self.tun_registry().record_tx_no_route(u64::from(tun_id));
        } else if let Some(r) = parse_drop_reason(reason) {
            self.tun_registry().record_tx_drop(u64::from(tun_id), r);
        }
    }
}

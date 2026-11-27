//! Kernel-side `/run/net/host.sock` (`0600`, root + verified `/usr/bin/netd` image)
//! bridge and egress authorization for the browser OS host (`#86` Phase 10a).
//!
//! Lazily bound ONLY when `/usr/bin/netd` starts (`netd.service`, ZERO network calls on boot).
//! `authorize_netd_open` authenticates BOTH peers via kernel `SO_PEERCRED`, closes the host's
//! duplicated `SCM_RIGHTS` socket ref deterministically, mints/reuses a live `ServiceAuth v2`
//! credential via `ServiceMintKind::NetEgress`, validates `(host, port, tls)` locally against
//! `effective_scope.net` and SSRF rules, and returns `{ token, instance_id, quota }` ONLY to
//! the trusted host adapter (`netd-host.js`), never to `/usr/bin/netd` or guests.

use crate::vfs_engine::{map_errno, vfs_js_err};
use crate::{Kernel, ServiceMintKind, mint_for_service};
use abi::Errno;
use abi::net_ctl::{
    HostMatch, HostNetReq, LoopbackTestAllowlist, NET_HOST_SOCK, NetErrorKind, ParsedHost,
    parse_target_host,
};
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::rc::Rc;
use vfs::unix_sock::{SockId, SockType};
use vfs::{SetAttr, StartAnchor};
use wasm_bindgen::prelude::*;

fn net_err(errno: Errno, kind: NetErrorKind, msg: impl Into<String>) -> JsValue {
    let payload = json!({
        "errno": format!("{errno:?}"),
        "error": kind,
        "message": msg.into(),
    });
    JsValue::from_str(&payload.to_string())
}

#[wasm_bindgen]
impl Kernel {
    /// Bind `/run/net/host.sock` (`0600`, uid 0) inside PID 1's system mount namespace and
    /// return its `SockId` so `netd-host.js` can accept verified `/usr/bin/netd` connections.
    pub async fn bind_netd_host_socket(&self) -> Result<u32, JsValue> {
        let pid = crate::INIT;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let root = StartAnchor::Root;
        match vfs.mkdirat(pid, root.clone(), "/run/net", 0o755).await {
            Ok(_) | Err(Errno::EEXIST) => (),
            Err(e) => return Err(map_errno(e)),
        }
        let dir = vfs
            .statat(pid, root.clone(), "/run/net", false)
            .await
            .map_err(map_errno)?;
        if dir.uid != 0 || dir.mode & abi::S_IFMT != abi::S_IFDIR || dir.mode & 0o022 != 0 {
            return Err(map_errno(Errno::EACCES));
        }
        let _ = vfs.unlinkat(pid, root.clone(), NET_HOST_SOCK, false).await;

        let cred = self.kernel_peer_cred(pid).map_err(map_errno)?;
        let sock = self
            .vfs_rt
            .borrow()
            .unix_sock
            .borrow_mut()
            .create(pid, SockType::Stream, cred)
            .map_err(map_errno)?;

        let bind: Result<u32, JsValue> = async {
            self.sock_bind(pid, sock, NET_HOST_SOCK.into()).await?;
            vfs.setattrat(
                pid,
                root,
                NET_HOST_SOCK,
                &SetAttr {
                    mode: Some(0o600),
                    uid: Some(0),
                    gid: Some(0),
                    ..SetAttr::default()
                },
                false,
            )
            .await
            .map_err(map_errno)?;
            self.sock_listen(pid, sock, 32)?;
            let _ = self.sock_set_nonblock(pid, sock, true);
            Ok(sock)
        }
        .await;

        if bind.is_err() {
            let _ = self.sock_close(pid, sock, 1).await;
            let _ = vfs
                .unlinkat(pid, StartAnchor::Root, NET_HOST_SOCK, false)
                .await;
        }
        bind
    }

    /// Close a previously bound `/run/net/host.sock` listener.
    pub async fn close_netd_host_socket(&self, listener_id: u32) {
        let _ = self.sock_close(crate::INIT, listener_id as SockId, 1).await;
    }

    /// Authorize an outbound stream open forwarded by verified `/usr/bin/netd`.
    ///
    /// ALWAYS closes the host's duplicated `client_sock_id` before returning.
    /// Returns JSON `{"token","instance_id","quota"}` strictly for `netd-host.js`.
    pub async fn authorize_netd_open(
        &self,
        host_sock_id: u32,
        client_sock_id: u32,
        req_json: String,
    ) -> Result<String, JsValue> {
        let result: Result<String, JsValue> = async {
            // 1. Authenticate the `/run/net/host.sock` peer: MUST be live, uid 0, verified `/usr/bin/netd`.
            let host_peer = self
                .vfs_rt
                .borrow()
                .unix_sock
                .borrow()
                .peer_cred(crate::INIT, host_sock_id as SockId)
                .map_err(|e| {
                    net_err(
                        e,
                        NetErrorKind::PolicyDenied,
                        "missing netd peer credentials",
                    )
                })?;
            if host_peer.uid != 0
                || !self.is_proc_live(host_peer.pid)
                || !self.is_service_image(host_peer.pid, "netd")
            {
                return Err(net_err(
                    Errno::EACCES,
                    NetErrorKind::PolicyDenied,
                    "untrusted netd host socket peer",
                ));
            }

            // 2. Authenticate the originating guest via kernel `SO_PEERCRED` on the transferred client socket,
            //    and verify the live process UID still matches `client_peer.uid` (defense in depth).
            let client_peer = self
                .vfs_rt
                .borrow()
                .unix_sock
                .borrow()
                .peer_cred(crate::INIT, client_sock_id as SockId)
                .map_err(|e| {
                    net_err(e, NetErrorKind::PolicyDenied, "invalid client socket peer")
                })?;
            {
                let st = self.state.borrow();
                let Some(proc) = st
                    .table
                    .proc(client_peer.pid)
                    .filter(|p| p.state != abi::ProcState::Zombie)
                else {
                    return Err(net_err(
                        Errno::ESRCH,
                        NetErrorKind::Canceled,
                        "originating client process is no longer alive",
                    ));
                };
                if proc.cred.identity.id != client_peer.uid {
                    return Err(net_err(
                        Errno::EACCES,
                        NetErrorKind::PolicyDenied,
                        "client socket peer UID does not match live process identity",
                    ));
                }
            }

            // 3. Parse the `HostNetReq::Open` payload strictly.
            let req: HostNetReq = serde_json::from_str(&req_json)
                .map_err(|e| vfs_js_err(Errno::EINVAL, format!("invalid HostNetReq: {e}")))?;
            let HostNetReq::Open {
                host,
                port,
                tls,
                timeout_ms: _,
            } = req
            else {
                return Err(net_err(
                    Errno::EINVAL,
                    NetErrorKind::InvalidArgument,
                    "expected HostNetReq::Open",
                ));
            };

            // 4. Acquire or reuse the client's `ServiceAuth v2` remote credential with `NetEgress` scope.
            let rem = mint_for_service(&self.state, client_peer.pid, ServiceMintKind::NetEgress)
                .await
                .map_err(|e| {
                    let kind = match e.errno {
                        Errno::ENOTCONN => NetErrorKind::Offline,
                        Errno::EACCES | Errno::EPERM => NetErrorKind::PolicyDenied,
                        Errno::ESRCH => NetErrorKind::Canceled,
                        _ => NetErrorKind::HostUnavailable,
                    };
                    net_err(e.errno, kind, e.to_string())
                })?;

            let Some(net_scope) = rem.scope.net.as_ref().filter(|n| !n.is_empty()) else {
                return Err(net_err(
                    Errno::EACCES,
                    NetErrorKind::PolicyDenied,
                    "credential has no network egress scope",
                ));
            };

            // 5. Locally validate `(host, port, tls)` against `net_scope` and SSRF/private-IP rules.
            // If the target is exact `127.0.0.1` or `::1` AND the caller's `net_scope` contains an
            // explicit `HostMatch::Exact` rule for that loopback IP, allow the request to reach the
            // Worker gateway where the Worker enforces its second key (`NET_TEST_LOOPBACK_ADDRS`,
            // which is empty in production). All other private/bogon IPs and `AnyPublic` loopback
            // attempts are rejected locally with ZERO remote RPCs!
            let parsed =
                parse_target_host(&host).map_err(|f| net_err(f.errno, f.kind, f.message))?;
            let mut local_lo = LoopbackTestAllowlist::new();
            if let ParsedHost::Ip(ip) = parsed
                && port != 0
                && matches!(ip, IpAddr::V4(v4) if v4 == Ipv4Addr::LOCALHOST)
                    | matches!(ip, IpAddr::V6(v6) if v6 == Ipv6Addr::LOCALHOST)
                && net_scope.rules.iter().any(|r| {
                    matches!(&r.host, HostMatch::Exact(s) if s.parse::<IpAddr>().ok() == Some(ip))
                })
            {
                let _ = local_lo.insert(SocketAddr::new(ip, port));
            }
            net_scope
                .check_egress(&host, port, tls, &local_lo)
                .map_err(|f| net_err(f.errno, f.kind, f.message))?;

            let quota = net_scope
                .quota
                .clamped()
                .map_err(|e| net_err(e.errno, NetErrorKind::PolicyDenied, e.to_string()))?;

            Ok(json!({
                "token": rem.token,
                "instance_id": rem.instance_id,
                "quota": quota,
            })
            .to_string())
        }
        .await;

        // Close host's duplicated client socket ref and record its `CleanupBatch` so no SAB
        // rings / in-flight FDs are ever leaked on the JS side.
        let unix_sock = Rc::clone(&self.vfs_rt.borrow().unix_sock);
        let batch = unix_sock
            .borrow_mut()
            .close(crate::INIT, client_sock_id as SockId, 1);
        if let Ok(batch) = batch {
            self.record_unix_sock_cleanup(batch).await;
        }
        result
    }
}

//! ShareFs uses a persistent session socket for local exports. Negotiated browser
//! transports carry the same framed byte stream through a socketpair.
use crate::{Kernel, cloudfs, export_bridge, vfs_engine::map_errno};
use abi::{
    Errno,
    export_ctl::{ExportRule, TransportKind},
};
use js_sys::Reflect;
use std::rc::Rc;
use wasm_bindgen::prelude::*;

#[derive(serde::Deserialize)]
struct ShareSource {
    session: String,
    caller: u32,
    id: String,
    transport: TransportKind,
    rule: ExportRule,
    #[serde(default)]
    expires_at: u64,
}

impl Kernel {
    pub(crate) async fn share_backing(
        &self,
        source: JsValue,
    ) -> Result<(Rc<vfs::MountBacking>, vfs::Handle, &'static str), JsValue> {
        let description = Reflect::get(&source, &"description".into())?
            .as_string()
            .ok_or_else(|| map_errno(Errno::EINVAL))?;
        let spec: ShareSource =
            serde_json::from_str(&description).map_err(|_| map_errno(Errno::EINVAL))?;
        let proxy = self.mount_page_proxy(&spec.session)?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let proxy_id = vfs.process_cred(proxy).map_err(map_errno)?.identity;
        let peer_id = vfs.process_cred(spec.caller).map_err(map_errno)?.identity;
        if (proxy_id.id, proxy_id.group, proxy_id.groups)
            != (peer_id.id, peer_id.group, peer_id.groups)
        {
            return Err(map_errno(Errno::EACCES));
        }
        let (_, socket) = cloudfs::installed("mountSocketOp").map_err(map_errno)?;
        let port = Reflect::get(&source, &"port".into())?;
        let (backing, root) = if spec.transport == TransportKind::Ipc && port.is_undefined() {
            self.exports
                .connect_share_ipc(proxy, &spec.id, spec.rule, socket)
                .await
        } else {
            export_bridge::connect_share_port(proxy, port, spec.expires_at, spec.rule, socket).await
        }
        .map_err(map_errno)?;
        let mode = match spec.transport {
            TransportKind::Ipc => "ipc",
            TransportKind::P2p => "p2p",
            TransportKind::Relay => "relay",
        };
        Ok((backing, root, mode))
    }
}

#[wasm_bindgen]
impl Kernel {
    pub fn local_export_available(&self, id: &str) -> bool {
        self.exports.has_ipc_export(id)
    }

    pub async fn accept_export_port(
        &self,
        session_id: String,
        header: String,
        port: JsValue,
    ) -> Result<(), JsValue> {
        #[derive(serde::Deserialize)]
        struct Header {
            export_id: String,
            session: String,
            ticket: String,
            transport: TransportKind,
        }
        let h: Header = serde_json::from_str(&header).map_err(|_| map_errno(Errno::EINVAL))?;
        let proxy = self.mount_page_proxy(&session_id)?;
        let (_, relay) = cloudfs::installed("exportRelayCall").map_err(map_errno)?;
        let (_, socket) = cloudfs::installed("mountSocketOp").map_err(map_errno)?;
        self.exports
            .attach_remote_transport_port(
                proxy,
                export_bridge::RemotePort {
                    export_id: h.export_id,
                    session: h.session,
                    ticket: h.ticket,
                    transport: h.transport,
                    port,
                },
                &relay,
                &socket,
            )
            .await
            .map_err(map_errno)
    }
}

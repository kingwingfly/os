//! Kernel-side `/run/kubelet/host.sock` (`0600`, root + verified `/usr/bin/kubelet` image)
//! bridge for the browser OS host (`Phase 9.1b #84`).
//!
//! Lazily bound ONLY when `/usr/bin/kubelet` is started by `kubelet.service` (ZERO overhead and
//! ZERO network calls at default boot!). The host agent accepts connections and exchanges
//! length-prefixed `abi::kubelet_ctl` frames through the canonical SAB-backed `mountSocketOp`
//! stream transport, checking `SO_PEERCRED.uid == 0 && kernel.is_service_image(pid, "kubelet")`.

use crate::Kernel;
use crate::vfs_engine::map_errno;
use abi::Errno;
use abi::kubelet_ctl::KUBELET_HOST_SOCK;
use vfs::unix_sock::{SockId, SockType};
use vfs::{SetAttr, StartAnchor};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
impl Kernel {
    /// Bind `/run/kubelet/host.sock` (`0600`, uid 0) inside PID 1's system mount namespace and
    /// return its `SockId` so the host `kubelet-agent.js` loop can accept authenticated
    /// `/usr/bin/kubelet` connections over the SAB-backed Unix stream transport.
    pub async fn bind_kubelet_host_socket(&self) -> Result<u32, JsValue> {
        let pid = crate::INIT;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let root = StartAnchor::Root;
        match vfs.mkdirat(pid, root.clone(), "/run/kubelet", 0o755).await {
            Ok(_) | Err(Errno::EEXIST) => (),
            Err(e) => return Err(map_errno(e)),
        }
        let dir = vfs
            .statat(pid, root.clone(), "/run/kubelet", false)
            .await
            .map_err(map_errno)?;
        if dir.uid != 0 || dir.mode & abi::S_IFMT != abi::S_IFDIR || dir.mode & 0o022 != 0 {
            return Err(map_errno(Errno::EACCES));
        }
        let _ = vfs
            .unlinkat(pid, root.clone(), KUBELET_HOST_SOCK, false)
            .await;

        let cred = self.kernel_peer_cred(pid).map_err(map_errno)?;
        let sock = self
            .vfs_rt
            .borrow()
            .unix_sock
            .borrow_mut()
            .create(pid, SockType::Stream, cred)
            .map_err(map_errno)?;

        let bind: Result<u32, JsValue> = async {
            self.sock_bind(pid, sock, KUBELET_HOST_SOCK.into()).await?;
            vfs.setattrat(
                pid,
                root,
                KUBELET_HOST_SOCK,
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
            self.sock_listen(pid, sock, 16)?;
            let _ = self.sock_set_nonblock(pid, sock, true);
            Ok(sock)
        }
        .await;

        if bind.is_err() {
            let _ = self.sock_close(pid, sock, 1).await;
            let _ = vfs
                .unlinkat(pid, StartAnchor::Root, KUBELET_HOST_SOCK, false)
                .await;
        }
        bind
    }

    /// Close a previously bound `/run/kubelet/host.sock` listener.
    pub async fn close_kubelet_host_socket(&self, listener_id: u32) {
        let _ = self.sock_close(crate::INIT, listener_id as SockId, 1).await;
    }
}

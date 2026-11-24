//! Kernel-side `/run/mount/host.sock` server so `/usr/bin/mountd` runs 100% offline on `os-native`.

use abi::Errno;
use abi::mount_ctl::{
    MOUNT_HOST_SOCK, MountBackendOp, MountBackendRequest, SourceInfo, SourceKind, SourceState,
    decode_frame, encode_frame,
};
use abi::socket::PeerCred;
use abi::{mount_flags, umount_flags};
use os_kernel::proc_table::LocalProcessTable;
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use vfs::StartAnchor;
use vfs::unix_sock::{InFlightFd, SockId, SockType, SocketInodeKey, UnixSocketTable};
use vfs::{Cred, Vfs};

const KERNEL_HOST_PID: u32 = 1;

pub struct MountHostServer {
    listener_id: Option<SockId>,
    clients: HashMap<SockId, Vec<u8>>,
}

impl Default for MountHostServer {
    fn default() -> Self {
        Self::new()
    }
}

impl MountHostServer {
    pub fn new() -> Self {
        Self {
            listener_id: None,
            clients: HashMap::new(),
        }
    }

    /// Ensure `/run/mount/host.sock` (`0600`, uid 0) is bound and listening on the live `/run` mount.
    pub async fn ensure_bound(&mut self, vfs: &Vfs, socks: &mut UnixSocketTable) {
        if let Some(id) = self.listener_id {
            if socks.describe(KERNEL_HOST_PID, id).is_ok() {
                return;
            }
            self.listener_id = None;
        }
        let _ = vfs
            .mkdirat(KERNEL_HOST_PID, StartAnchor::Root, "/run/mount", 0o755)
            .await;
        let _ = vfs
            .unlinkat(KERNEL_HOST_PID, StartAnchor::Root, MOUNT_HOST_SOCK, false)
            .await;
        let cred = PeerCred {
            pid: 1,
            uid: 0,
            gid: 0,
        };
        let Ok(sock_id) = socks.create(KERNEL_HOST_PID, SockType::Stream, cred) else {
            return;
        };
        let _ = socks.set_nonblock(KERNEL_HOST_PID, sock_id, true);
        if socks
            .begin_bind(KERNEL_HOST_PID, sock_id, MOUNT_HOST_SOCK)
            .is_err()
        {
            let _ = socks.close(KERNEL_HOST_PID, sock_id, 1);
            return;
        }
        match vfs
            .mksockat_with_parent(KERNEL_HOST_PID, StartAnchor::Root, MOUNT_HOST_SOCK, 0o600)
            .await
        {
            Ok((entry, _pin, _parent, _name)) => {
                let key = SocketInodeKey {
                    fs_id: entry.handle.fs.clone(),
                    node: entry.handle.node,
                };
                if socks
                    .finish_bind(KERNEL_HOST_PID, sock_id, key, MOUNT_HOST_SOCK.to_string())
                    .is_ok()
                    && socks.listen(KERNEL_HOST_PID, sock_id, 32, cred).is_ok()
                {
                    let _ = vfs
                        .setattrat(
                            KERNEL_HOST_PID,
                            StartAnchor::Root,
                            MOUNT_HOST_SOCK,
                            &vfs::SetAttr {
                                mode: Some(0o600),
                                uid: Some(0),
                                gid: Some(0),
                                ..vfs::SetAttr::default()
                            },
                            false,
                        )
                        .await;
                    self.listener_id = Some(sock_id);
                } else {
                    socks.abort_bind(sock_id);
                    let _ = socks.close(KERNEL_HOST_PID, sock_id, 1);
                }
            }
            Err(_) => {
                socks.abort_bind(sock_id);
                let _ = socks.close(KERNEL_HOST_PID, sock_id, 1);
            }
        }
    }

    /// Service any pending connections or requests from `mountd`.
    pub async fn tick(
        &mut self,
        vfs: &Vfs,
        socks: &mut UnixSocketTable,
        procs: &Rc<RefCell<LocalProcessTable>>,
        root_volume_uuid: Option<&str>,
    ) -> bool {
        let mut did_work = false;
        let Some(listener_id) = self.listener_id else {
            return false;
        };
        let root_cred = PeerCred {
            pid: 1,
            uid: 0,
            gid: 0,
        };
        while let Ok(accepted) = socks.accept(KERNEL_HOST_PID, listener_id, root_cred) {
            did_work = true;
            if accepted.peer_cred.uid != 0 {
                let _ = socks.close(KERNEL_HOST_PID, accepted.sock_id, 1);
                continue;
            }
            let _ = socks.set_nonblock(KERNEL_HOST_PID, accepted.sock_id, true);
            self.clients.insert(accepted.sock_id, Vec::new());
        }

        let client_ids: Vec<SockId> = self.clients.keys().copied().collect();
        for cid in client_ids {
            match socks.recvmsg(KERNEL_HOST_PID, cid, 65_536, 4, 0, None) {
                Ok(recv) => {
                    did_work = true;
                    let mut forwarded_peer: Option<PeerCred> = None;
                    for in_fd in &recv.fds {
                        if let InFlightFd::UnixSocket(peer_sock) = *in_fd {
                            if let Ok(pc) = socks.peer_cred(KERNEL_HOST_PID, peer_sock) {
                                forwarded_peer = Some(pc);
                            }
                            let _ = socks.close(KERNEL_HOST_PID, peer_sock, 1);
                        }
                    }
                    if recv.data.is_empty() {
                        self.clients.remove(&cid);
                        let _ = socks.close(KERNEL_HOST_PID, cid, 1);
                        continue;
                    }
                    let buf = self.clients.entry(cid).or_default();
                    buf.extend_from_slice(&recv.data);
                    if let Some(nl) = buf.iter().position(|&b| b == b'\n') {
                        let frame = buf[..=nl].to_vec();
                        let caller_peer = forwarded_peer.unwrap_or(recv.peer_cred);
                        let reply: Result<Value, Errno> =
                            match decode_frame::<MountBackendRequest>(&frame) {
                                Ok(req) => {
                                    handle_backend_op(
                                        vfs,
                                        procs,
                                        caller_peer,
                                        req,
                                        root_volume_uuid,
                                    )
                                    .await
                                }
                                Err(e) => Err(e.errno),
                            };
                        if let Ok(encoded) = encode_frame(&reply) {
                            let _ = socks.sendmsg(
                                KERNEL_HOST_PID,
                                cid,
                                &encoded,
                                Vec::new(),
                                None,
                                root_cred,
                                None,
                            );
                        }
                        self.clients.remove(&cid);
                        let _ = socks.close(KERNEL_HOST_PID, cid, 1);
                    }
                }
                Err(Errno::EAGAIN) => {}
                Err(_) => {
                    self.clients.remove(&cid);
                    let _ = socks.close(KERNEL_HOST_PID, cid, 1);
                }
            }
        }
        did_work
    }
}

async fn handle_backend_op(
    vfs: &Vfs,
    procs: &Rc<RefCell<LocalProcessTable>>,
    peer: PeerCred,
    req: MountBackendRequest,
    root_volume_uuid: Option<&str>,
) -> Result<Value, Errno> {
    let target_pid = req.target_pid.unwrap_or(peer.pid);
    match req.op {
        MountBackendOp::Peer {} => {
            let tbl = procs.borrow();
            let snap = tbl.proc_snapshot(target_pid).ok_or(Errno::ESRCH)?;
            Ok(json!(snap.uid))
        }
        MountBackendOp::Sources {} => {
            let mut list = Vec::new();
            if let Some(vol) = root_volume_uuid {
                list.push(SourceInfo {
                    id: format!("volume:{vol}"),
                    kind: SourceKind::CowfsVolume,
                    label: "Root volume".into(),
                    location: format!("cowfs:{vol}"),
                    state: SourceState::Granted,
                    writable: true,
                    execute: true,
                    saved: true,
                    owner_uid: None,
                });
            }
            serde_json::to_value(list).map_err(|_| Errno::EIO)
        }
        MountBackendOp::Filesystems {} => {
            let cred = vfs
                .process_cred(target_pid)
                .unwrap_or_else(|_| Cred::root());
            let ns = vfs.process_namespace(target_pid)?;
            let ns_id = ns.borrow().id();
            let root = vfs.process_fs_context(target_pid)?.borrow().root.clone();
            let fss = vfs.inspect_filesystems_from(ns_id, &cred, &root).await?;
            serde_json::to_value(fss).map_err(|_| Errno::EIO)
        }
        MountBackendOp::Attachments { include_busy } => {
            let cred = vfs
                .process_cred(target_pid)
                .unwrap_or_else(|_| Cred::root());
            let ns = vfs.process_namespace(target_pid)?;
            let ns_id = ns.borrow().id();
            let root = vfs.process_fs_context(target_pid)?.borrow().root.clone();
            let atts = vfs
                .inspect_attachments_from(ns_id, &cred, &root, include_busy)
                .await?;
            serde_json::to_value(atts).map_err(|_| Errno::EIO)
        }
        MountBackendOp::Exports {} => Ok(json!([])),
        MountBackendOp::Attach {
            source,
            target,
            fstype,
            flags,
            options,
            ..
        } => {
            vfs.mount(
                target_pid,
                &source,
                &target,
                Some(fstype.as_str()),
                flags,
                options.as_deref(),
            )
            .await?;
            Ok(Value::Null)
        }
        MountBackendOp::Detach {
            target,
            lazy,
            force,
            ..
        } => {
            let mut flags = 0u32;
            if lazy {
                flags |= umount_flags::MNT_DETACH;
            }
            if force {
                flags |= umount_flags::MNT_FORCE;
            }
            vfs.umount2(target_pid, &target, flags).await?;
            Ok(Value::Null)
        }
        MountBackendOp::Remount {
            target,
            flags,
            options,
            ..
        } => {
            vfs.mount(
                target_pid,
                "",
                &target,
                None,
                flags | mount_flags::MS_REMOUNT,
                options.as_deref(),
            )
            .await?;
            Ok(Value::Null)
        }
        MountBackendOp::Activate { .. } | MountBackendOp::Forget { .. } => Err(Errno::EOPNOTSUPP),
    }
}

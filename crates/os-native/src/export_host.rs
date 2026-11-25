//! Native pure-Rust `EXPORT_DIR_IOCTL` bridge for `exportd.service` (local IPC exports +
//! listener pinning + capability-scoped `vfs::sharefs_ipc::ScopedDir` operations).

use crate::dev_backend::fill_os_random;
use abi::Errno;
use abi::export_ctl::{
    Admission, AtOp, ExportDirCall, ExportRule, FdOp, OSFS_VERSION, PeerIdentity, PeerIdentityCap,
    RootInfo, TransportKind, TransportSessionHeader, component, export_ipc_sock,
};
use abi::socket::PeerCred;
use os_core::permissions::Identity;
use serde::Serialize;
use serde_json::Value;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};
use vfs::sharefs_ipc::ScopedDir;
use vfs::unix_sock::{SockId, UnixSocketTable};
use vfs::{Access, Cred, FileRef, Handle, Vfs};

type Result<T> = std::result::Result<T, Errno>;

/// Verified kernel-side service grant for `EXPORT_DIR_IOCTL`.
pub struct NativeExportGrant {
    pub peer: PeerCred,
    pub export_impersonate: bool,
}

struct Published {
    daemon: u32,
    manager_uid: Option<u32>,
    dirfd: u32,
    root: FileRef,
    expires_at: u64,
    rule: ExportRule,
    transports: Vec<TransportKind>,
}

struct Session {
    header: TransportSessionHeader,
    admitted: Cell<bool>,
    dir: Rc<ScopedDir>,
    peer_uid: u32,
}

struct ListenerPin {
    dir: FileRef,
    name: String,
    node: vfs::NodeId,
}

impl ListenerPin {
    async fn unlink(self) -> Result<()> {
        let cred = self.dir.cred();
        let remove = self
            .dir
            .fs()
            .unlink_if(cred, self.dir.handle(), &self.name, self.node);
        if let Some(pin) = self.dir.mount_pin() {
            pin.guard_op(cred, true, true, remove).await
        } else {
            remove.await
        }
    }
}

#[derive(Default)]
pub struct NativeExportBridge {
    exports: RefCell<BTreeMap<String, Rc<Published>>>,
    caps: RefCell<BTreeMap<String, Rc<Session>>>,
    listeners: RefCell<BTreeMap<(u32, u64, u64), ListenerPin>>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn random_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    fill_os_random(&mut bytes).map_err(|_| Errno::EIO)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn peer_cred_to_vfs(peer: PeerIdentity) -> Cred {
    let mut groups: BTreeSet<u32> = peer.groups.into_iter().collect();
    groups.insert(peer.gid);
    Cred::new(Identity {
        id: peer.uid,
        group: peer.gid,
        groups,
    })
}

fn authorize(unit: &NativeExportGrant) -> Result<()> {
    if unit.export_impersonate && unit.peer.uid != 0 {
        Ok(())
    } else {
        Err(Errno::EPERM)
    }
}

fn valid_id(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}

fn to_value(v: impl Serialize) -> Result<Value> {
    serde_json::to_value(v).map_err(|_| Errno::EIO)
}

impl NativeExportBridge {
    async fn track_listener(
        &self,
        unit: &NativeExportGrant,
        dir: FileRef,
        name: String,
        dev: u64,
        ino: u64,
    ) -> Result<()> {
        authorize(unit)?;
        component(&name)?;
        if dir.cred().identity.id != unit.peer.uid || !dir.metadata().await?.is_dir() {
            return Err(Errno::EACCES);
        }
        let entry = dir.fs().lookup(dir.cred(), dir.handle(), &name).await?;
        if !entry.metadata.is_socket()
            || entry.metadata.uid != unit.peer.uid
            || entry.handle.fs.dev() != dev
            || entry.handle.node.ino != ino
        {
            return Err(Errno::ESTALE);
        }
        let mut listeners = self.listeners.borrow_mut();
        if listeners
            .range((unit.peer.pid, 0, 0)..=(unit.peer.pid, u64::MAX, u64::MAX))
            .count()
            >= 130
        {
            return Err(Errno::ENOSPC);
        }
        listeners.insert(
            (unit.peer.pid, dev, ino),
            ListenerPin {
                dir,
                name,
                node: entry.handle.node,
            },
        );
        Ok(())
    }

    fn binding(
        &self,
        id: &str,
        unit: &NativeExportGrant,
        fd: u32,
        root: &FileRef,
    ) -> Result<Rc<Published>> {
        authorize(unit)?;
        let exports = self.exports.borrow();
        let entry = exports.get(id).ok_or(Errno::ESTALE)?;
        if entry.daemon != unit.peer.pid || entry.dirfd != fd || !entry.root.ptr_eq(root) {
            return Err(Errno::EACCES);
        }
        Ok(entry.clone())
    }

    fn get_cap(&self, cap: &PeerIdentityCap) -> Result<Rc<Session>> {
        self.caps
            .borrow()
            .get(&cap.token)
            .cloned()
            .ok_or(Errno::EACCES)
    }

    fn bound_session(
        &self,
        unit: &NativeExportGrant,
        fd: u32,
        root: &FileRef,
        cap: &PeerIdentityCap,
    ) -> Result<Rc<Session>> {
        let s = self.get_cap(cap)?;
        self.binding(&s.header.export_id, unit, fd, root)?;
        if !s.admitted.get() {
            return Err(Errno::EACCES);
        }
        Ok(s)
    }

    fn check_session(
        &self,
        unit: &NativeExportGrant,
        fd: u32,
        root: &FileRef,
        cap: &PeerIdentityCap,
    ) -> Result<Rc<Session>> {
        let s = self.bound_session(unit, fd, root, cap)?;
        if now_ms() >= s.header.expires_at {
            return Err(Errno::ESTALE);
        }
        Ok(s)
    }

    fn mint_local(
        &self,
        id: &str,
        export: &Rc<Published>,
        identity: PeerIdentity,
    ) -> Result<TransportSessionHeader> {
        let now = now_ms();
        if now >= export.expires_at
            || !self
                .exports
                .borrow()
                .get(id)
                .is_some_and(|e| Rc::ptr_eq(e, export))
        {
            return Err(Errno::ESTALE);
        }
        if !export.transports.contains(&TransportKind::Ipc) {
            return Err(Errno::EACCES);
        }
        if self
            .caps
            .borrow()
            .values()
            .filter(|s| s.header.export_id == id)
            .count()
            >= 16
        {
            return Err(Errno::EBUSY);
        }
        let peer_uid = identity.uid;
        let publisher = export.root.cred();
        let cred = if peer_uid == publisher.identity.id {
            publisher.clone()
        } else {
            peer_cred_to_vfs(identity)
        };
        let scope = ScopedDir::new(export.root.clone(), cred, export.rule)?;
        let cap = PeerIdentityCap {
            token: random_token()?,
        };
        let header = TransportSessionHeader {
            version: OSFS_VERSION,
            export_id: id.into(),
            manager_uid: export.manager_uid,
            transport: TransportKind::Ipc,
            cap,
            expires_at: export.expires_at,
            rule: export.rule,
        };
        self.caps.borrow_mut().insert(
            header.cap.token.clone(),
            Rc::new(Session {
                header: header.clone(),
                admitted: Cell::new(false),
                dir: Rc::new(scope),
                peer_uid,
            }),
        );
        Ok(header)
    }

    async fn redeem(
        &self,
        unit: &NativeExportGrant,
        fd: u32,
        root: &FileRef,
        header: &TransportSessionHeader,
    ) -> Result<Admission> {
        self.binding(&header.export_id, unit, fd, root)?;
        let s = self.get_cap(&header.cap)?;
        if &s.header != header || header.version != OSFS_VERSION || s.admitted.get() {
            return Err(Errno::EACCES);
        }
        if now_ms() >= header.expires_at {
            return Err(Errno::ESTALE);
        }
        s.admitted.set(true);
        let admission = s
            .dir
            .at(
                &s.dir.root(),
                AtOp::Access {
                    mask: abi::R_OK | abi::X_OK,
                },
            )
            .await;
        if let Err(e) = admission {
            self.remove_cap(&header.cap).await;
            return Err(e);
        }
        Ok(Admission {
            cap: header.cap.clone(),
            peer_uid: s.peer_uid,
            rule: header.rule,
            expires_at: header.expires_at,
        })
    }

    async fn remove_cap(&self, cap: &PeerIdentityCap) {
        let removed = self.caps.borrow_mut().remove(&cap.token);
        if let Some(s) = removed {
            s.dir.close().await;
        }
    }

    async fn remove_export(&self, id: &str) {
        let _ = self.exports.borrow_mut().remove(id);
        let tokens: Vec<_> = self
            .caps
            .borrow()
            .values()
            .filter(|s| s.header.export_id == id)
            .map(|s| s.header.cap.clone())
            .collect();
        for cap in tokens {
            self.remove_cap(&cap).await;
        }
    }

    /// Tear down all exports and pinned listener sockets owned by `pid` when it exits.
    pub async fn release_process(&self, pid: u32) {
        let ids: Vec<_> = self
            .exports
            .borrow()
            .iter()
            .filter(|(_, e)| e.daemon == pid)
            .map(|(k, _)| k.clone())
            .collect();
        for id in ids {
            self.remove_export(&id).await;
        }
        let keys: Vec<_> = self
            .listeners
            .borrow()
            .range((pid, 0, 0)..=(pid, u64::MAX, u64::MAX))
            .map(|(k, _)| *k)
            .collect();
        for key in keys {
            let pin = self.listeners.borrow_mut().remove(&key);
            if let Some(pin) = pin {
                let _ = pin.unlink().await;
            }
        }
    }

    /// Execute one `EXPORT_DIR_IOCTL` call on `kfd` inside the native offline kernel.
    pub async fn dispatch(
        &self,
        vfs: &Vfs,
        socks: &UnixSocketTable,
        unit: &NativeExportGrant,
        kfd: u32,
        call: ExportDirCall,
    ) -> Result<Value> {
        authorize(unit)?;
        let root = vfs.get_file(unit.peer.pid, kfd)?;
        if root.open_ref().access != Access::Read {
            return Err(Errno::EBADF);
        }
        match call {
            ExportDirCall::TrackListener { name, dev, ino } => {
                self.track_listener(unit, root, name, dev, ino).await?;
                Ok(Value::Null)
            }
            ExportDirCall::UnlinkListener { dev, ino } => {
                let key = (unit.peer.pid, dev, ino);
                let pin = {
                    let mut listeners = self.listeners.borrow_mut();
                    if !listeners.get(&key).is_some_and(|pin| pin.dir.ptr_eq(&root)) {
                        return Err(Errno::EACCES);
                    }
                    listeners.remove(&key).ok_or(Errno::ENOENT)?
                };
                pin.unlink().await?;
                Ok(Value::Null)
            }
            ExportDirCall::Inspect {} => {
                let meta = root.metadata().await?;
                let pin = root.mount_pin();
                let handle = Handle {
                    proof: String::new(),
                    ..root.handle().clone()
                };
                let stable_ino =
                    !root.fs().id().0.is_empty() && !handle.fs.0.is_empty() && handle.node.ino != 0;
                to_value(RootInfo {
                    root: abi::fs::Entry {
                        handle,
                        metadata: meta,
                    },
                    stable_ino,
                    publisher_uid: root.cred().identity.id,
                    ceiling: ExportRule {
                        writable: !pin.is_some_and(|p| p.effective_rdonly()),
                        execute: !pin.is_some_and(|p| p.effective_noexec()),
                    },
                })
            }
            ExportDirCall::Publish {
                id,
                manager_uid,
                expires_at,
                rule,
                password,
                mut transports,
                ..
            } => {
                let now = now_ms();
                if !valid_id(&id)
                    || expires_at <= now
                    || expires_at - now > 3_600_000
                    || root.cred().identity.id == 0
                    || manager_uid
                        .is_some_and(|uid| uid != root.cred().identity.id || uid != unit.peer.uid)
                {
                    return Err(Errno::EACCES);
                }
                if !root.metadata().await?.is_dir() {
                    return Err(Errno::ENOTDIR);
                }
                if root.fs().id().0.is_empty()
                    || root.handle().fs.0.is_empty()
                    || root.handle().node.ino == 0
                {
                    return Err(Errno::EPROTONOSUPPORT);
                }
                if self.exports.borrow().contains_key(&id) {
                    return Err(Errno::EEXIST);
                }
                if password.as_deref().unwrap_or_default().len() > 256 {
                    return Err(Errno::EINVAL);
                }
                let default_routes = transports.is_empty();
                if default_routes {
                    // Offline native host has no cloud relay; default publish serves local IPC.
                    transports = vec![TransportKind::Ipc];
                } else if transports.iter().any(|t| *t != TransportKind::Ipc) {
                    return Err(Errno::ENOTCONN);
                }
                self.exports.borrow_mut().insert(
                    id,
                    Rc::new(Published {
                        daemon: unit.peer.pid,
                        manager_uid,
                        dirfd: kfd,
                        root,
                        expires_at,
                        rule,
                        transports: transports.clone(),
                    }),
                );
                to_value(transports)
            }
            ExportDirCall::AdmitLocal { id, socket_fd } => {
                let e = self.binding(&id, unit, kfd, &root)?;
                let sid = socket_fd as SockId;
                if socks.getsockname(unit.peer.pid, sid)? != export_ipc_sock(&id) {
                    return Err(Errno::EACCES);
                }
                let peer = socks.peer_cred(unit.peer.pid, sid)?;
                let cred = vfs.process_cred(peer.pid)?;
                if cred.identity.id != peer.uid || cred.identity.group != peer.gid {
                    return Err(Errno::EACCES);
                }
                let identity = PeerIdentity {
                    uid: peer.uid,
                    gid: peer.gid,
                    groups: cred.identity.groups.into_iter().collect(),
                };
                let header = self.mint_local(&id, &e, identity)?;
                to_value(self.redeem(unit, kfd, &root, &header).await?)
            }
            ExportDirCall::AdmitRemote { header } => {
                to_value(self.redeem(unit, kfd, &root, &header).await?)
            }
            ExportDirCall::At { cap, base, call } => {
                let s = self.check_session(unit, kfd, &root, &cap)?;
                let answer = s.dir.at(&base, call).await?;
                self.check_session(unit, kfd, &root, &cap)?;
                to_value(answer)
            }
            ExportDirCall::OnOpen { cap, open, call } => {
                if matches!(call, FdOp::Release {}) {
                    let s = self.bound_session(unit, kfd, &root, &cap)?;
                    return to_value(s.dir.on_open(&open, call).await?);
                }
                let s = self.check_session(unit, kfd, &root, &cap)?;
                let answer = s.dir.on_open(&open, call).await?;
                self.check_session(unit, kfd, &root, &cap)?;
                to_value(answer)
            }
            ExportDirCall::End { cap } => {
                let s = self.get_cap(&cap)?;
                self.binding(&s.header.export_id, unit, kfd, &root)?;
                self.remove_cap(&cap).await;
                Ok(Value::Null)
            }
            ExportDirCall::Revoke { id, reason } => {
                if !matches!(reason, Errno::EACCES | Errno::ESTALE | Errno::ENOTCONN) {
                    return Err(Errno::EINVAL);
                }
                self.binding(&id, unit, kfd, &root)?;
                self.remove_export(&id).await;
                Ok(Value::Null)
            }
        }
    }
}

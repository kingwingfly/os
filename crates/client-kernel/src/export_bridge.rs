//! Kernel end of exportd's capability-scoped directory operations. The unit
//! dispatcher supplies the grant and the pinned FileRef from the caller's fd
//! table. Neither a page nor an osfs frame supplies these arguments.
use crate::Kernel;
use abi::export_ctl::*;
use abi::socket::PeerCred;
use abi::{Bytes, Errno};
use js_sys::{Function, Promise, Reflect, Uint8Array};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;
use vfs::sharefs_ipc::ScopedDir;
use vfs::{Access, Cred, FileRef, Handle, Identity};
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use wasm_bindgen_futures::JsFuture;

type Result<T> = std::result::Result<T, Errno>;

/// Constructed by the unit dispatcher from the signed unit's CapabilityGrant.
/// It is deliberately not deserializable or exposed as a wasm-bindgen method.
pub struct ServiceGrant {
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
    publisher_account: Option<u32>,
    relay: Option<Function>,
}
struct Session {
    header: TransportSessionHeader,
    admitted: Cell<bool>,
    dir: Rc<ScopedDir>,
    peer_uid: u32,
}
/// Pins the directory and inode of a bound socket across an abrupt daemon exit.
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
pub struct ExportBridge {
    exports: RefCell<BTreeMap<String, Rc<Published>>>,
    caps: RefCell<BTreeMap<String, Rc<Session>>>,
    listeners: RefCell<BTreeMap<(u32, u64, u64), ListenerPin>>,
}

fn token() -> Result<String> {
    let mut bytes = [0u8; 32];
    #[cfg(target_arch = "wasm32")]
    {
        let crypto = Reflect::get(&js_sys::global(), &"crypto".into()).map_err(|_| Errno::EIO)?;
        let get: Function = Reflect::get(&crypto, &"getRandomValues".into())
            .map_err(|_| Errno::EIO)?
            .dyn_into()
            .map_err(|_| Errno::EIO)?;
        let out = Uint8Array::new_with_length(32);
        get.call1(&crypto, &out).map_err(|_| Errno::EIO)?;
        out.copy_to(&mut bytes);
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::io::Read;
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut bytes))
            .map_err(|_| Errno::EIO)?;
    }
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn peer_cred(peer: PeerIdentity) -> Cred {
    let mut groups = peer
        .groups
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    groups.insert(peer.gid);
    Cred::new(Identity {
        id: peer.uid,
        group: peer.gid,
        groups,
    })
}
fn authorize(unit: &ServiceGrant) -> Result<()> {
    if unit.export_impersonate && unit.peer.uid != 0 {
        Ok(())
    } else {
        Err(Errno::EPERM)
    }
}

impl ExportBridge {
    async fn track_listener(
        &self,
        unit: &ServiceGrant,
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
        unit: &ServiceGrant,
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
        unit: &ServiceGrant,
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
        unit: &ServiceGrant,
        fd: u32,
        root: &FileRef,
        cap: &PeerIdentityCap,
    ) -> Result<Rc<Session>> {
        let s = self.bound_session(unit, fd, root, cap)?;
        if crate::now_ms() >= s.header.expires_at {
            return Err(Errno::ESTALE);
        }
        Ok(s)
    }
    /// Check the signed unit grant, exact descriptor description and live
    /// inode ancestry. The credential stays inside ScopedDir.
    pub async fn export_impersonate(
        &self,
        unit: &ServiceGrant,
        fd: u32,
        root: &FileRef,
        cap: &PeerIdentityCap,
        target: &Handle,
    ) -> Result<()> {
        self.check_session(unit, fd, root, cap)?
            .dir
            .resolve_beneath(target)
            .await?;
        Ok(())
    }
    fn mint(
        &self,
        id: &str,
        export: &Rc<Published>,
        peer: VerifiedPeer,
        transport: TransportKind,
    ) -> Result<TransportSessionHeader> {
        let now = crate::now_ms();
        if now >= export.expires_at.min(peer.expires_at)
            || !self
                .exports
                .borrow()
                .get(id)
                .is_some_and(|e| Rc::ptr_eq(e, export))
        {
            return Err(Errno::ESTALE);
        }
        if !export.transports.contains(&transport) {
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
        let peer_uid = peer.identity.uid;
        let publisher = export.root.cred();
        let cred = if peer.password_auth || peer.same_account {
            publisher.clone()
        } else {
            peer_cred(peer.identity)
        };
        let rule = export.rule.intersect(peer.rule);
        let scope = ScopedDir::new(export.root.clone(), cred, rule)?;
        let cap = PeerIdentityCap { token: token()? };
        let header = TransportSessionHeader {
            version: OSFS_VERSION,
            export_id: id.into(),
            manager_uid: export.manager_uid,
            transport,
            cap,
            expires_at: export.expires_at.min(peer.expires_at),
            rule,
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
        unit: &ServiceGrant,
        fd: u32,
        root: &FileRef,
        header: &TransportSessionHeader,
    ) -> Result<Admission> {
        self.binding(&header.export_id, unit, fd, root)?;
        let s = self.get_cap(&header.cap)?;
        if &s.header != header || header.version != OSFS_VERSION || s.admitted.get() {
            return Err(Errno::EACCES);
        }
        if crate::now_ms() >= header.expires_at {
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
    async fn remove_export(&self, id: &str) -> Option<Rc<Published>> {
        let removed = self.exports.borrow_mut().remove(id);
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
        removed
    }
    /// Called from process-exit teardown as well as orderly revocation.
    pub async fn release_process(&self, pid: u32) {
        let ids: Vec<_> = self
            .exports
            .borrow()
            .iter()
            .filter(|(_, e)| e.daemon == pid)
            .map(|(k, _)| k.clone())
            .collect();
        for id in ids {
            if let Some(e) = self.remove_export(&id).await
                && let Some(r) = e.relay.clone()
            {
                wasm_bindgen_futures::spawn_local(async move {
                    let _ = js_call(
                        &r,
                        json!({ "op": "revoke", "id": id, "reason": Errno::ENOTCONN }),
                    )
                    .await;
                });
            }
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
}
struct VerifiedPeer {
    identity: PeerIdentity,
    password_auth: bool,
    same_account: bool,
    expires_at: u64,
    rule: ExportRule,
}

async fn js_call(f: &Function, args: Value) -> Result<Value> {
    let js = crate::vfs_engine::json_to_js(&args).map_err(|_| Errno::EINVAL)?;
    let promise = f.call1(&JsValue::UNDEFINED, &js).map_err(js_errno)?;
    let value = JsFuture::from(Promise::resolve(&promise))
        .await
        .map_err(js_errno)?;
    if value.is_undefined() {
        return Ok(Value::Null);
    }
    let text = js_sys::JSON::stringify(&value).map_err(|_| Errno::EIO)?;
    serde_json::from_str(&String::from(text)).map_err(|_| Errno::EIO)
}
fn js_errno(e: JsValue) -> Errno {
    Reflect::get(&e, &"errno".into())
        .ok()
        .and_then(|e| e.as_string())
        .and_then(|s| serde_json::from_value(json!(s)).ok())
        .unwrap_or(Errno::EIO)
}
fn from_value<T: DeserializeOwned>(v: Value) -> Result<T> {
    serde_json::from_value(v).map_err(|_| Errno::EIO)
}
fn value(v: impl serde::Serialize) -> Result<Value> {
    serde_json::to_value(v).map_err(|_| Errno::EIO)
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

impl Kernel {
    /// Handler for EXPORT_DIR_IOCTL. The guest runtime translates socket_fd
    /// to the calling process's kernel socket id before entering here.
    pub async fn export_dir_ioctl(
        &self,
        bridge: &ExportBridge,
        unit: &ServiceGrant,
        fd: u32,
        call: ExportDirCall,
        relay: Option<&Function>,
    ) -> Result<Value> {
        authorize(unit)?;
        if self.kernel_peer_cred(unit.peer.pid)? != unit.peer {
            return Err(Errno::EACCES);
        }
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let root = vfs.get_file(unit.peer.pid, fd)?;
        if root.open_ref().access != Access::Read {
            return Err(Errno::EBADF);
        }
        match call {
            ExportDirCall::TrackListener { name, dev, ino } => {
                bridge.track_listener(unit, root, name, dev, ino).await?;
                Ok(Value::Null)
            }
            ExportDirCall::UnlinkListener { dev, ino } => {
                let key = (unit.peer.pid, dev, ino);
                let pin = {
                    let mut listeners = bridge.listeners.borrow_mut();
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
                value(RootInfo {
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
                name,
                manager_uid,
                expires_at,
                rule,
                password,
                mut transports,
            } => {
                let now = crate::now_ms();
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
                if bridge.exports.borrow().contains_key(&id) {
                    return Err(Errno::EEXIST);
                }
                if transports.is_empty() {
                    transports = vec![TransportKind::Ipc, TransportKind::P2p, TransportKind::Relay];
                }
                let mut account = None;
                if transports.iter().any(|t| *t != TransportKind::Ipc) {
                    let registration = json!({
                        "op": "publish", "id": id, "name": name, "expires_at": expires_at,
                        "transports": transports, "write": rule.writable, "execute": rule.execute,
                        "password": password.unwrap_or_default(),
                    });
                    let registered = match relay {
                        Some(r) => js_call(r, registration).await,
                        None => Err(Errno::ENOTCONN),
                    };
                    match registered {
                        Ok(r) if r["id"] == id => account = Some(from_value(r["uid"].clone())?),
                        Err(Errno::ENOTCONN | Errno::ENODEV | Errno::ETIMEDOUT)
                            if transports.contains(&TransportKind::Ipc) =>
                        {
                            transports = vec![TransportKind::Ipc]
                        }
                        Err(e) => return Err(e),
                        _ => return Err(Errno::EACCES),
                    }
                }
                if self.kernel_peer_cred(unit.peer.pid) != Ok(unit.peer)
                    || !vfs
                        .get_file(unit.peer.pid, fd)
                        .is_ok_and(|open| open.ptr_eq(&root))
                {
                    if account.is_some()
                        && let Some(r) = relay
                    {
                        let _ = js_call(
                            r,
                            json!({ "op": "revoke", "id": id, "reason": Errno::ENOTCONN }),
                        )
                        .await;
                    }
                    return Err(Errno::ESRCH);
                }
                bridge.exports.borrow_mut().insert(
                    id,
                    Rc::new(Published {
                        daemon: unit.peer.pid,
                        manager_uid,
                        dirfd: fd,
                        root,
                        expires_at,
                        rule,
                        transports: transports.clone(),
                        publisher_account: account,
                        relay: account.and_then(|_| relay.cloned()),
                    }),
                );
                value(transports)
            }
            ExportDirCall::AdmitLocal { id, socket_fd } => {
                let e = bridge.binding(&id, unit, fd, &root)?;
                let socket = self.vfs_rt.borrow().unix_sock.clone();
                if socket.borrow().getsockname(unit.peer.pid, socket_fd)? != export_ipc_sock(&id) {
                    return Err(Errno::EACCES);
                }
                let peer = socket.borrow().peer_cred(unit.peer.pid, socket_fd)?;
                let cred = vfs.process_cred(peer.pid)?;
                if cred.identity.id != peer.uid || cred.identity.group != peer.gid {
                    return Err(Errno::EACCES);
                }
                let identity = PeerIdentity {
                    uid: peer.uid,
                    gid: peer.gid,
                    groups: cred.identity.groups.into_iter().collect(),
                };
                let header = bridge.mint(
                    &id,
                    &e,
                    VerifiedPeer {
                        identity,
                        password_auth: false,
                        same_account: peer.uid == root.cred().identity.id,
                        expires_at: e.expires_at,
                        rule: e.rule,
                    },
                    TransportKind::Ipc,
                )?;
                value(bridge.redeem(unit, fd, &root, &header).await?)
            }
            ExportDirCall::AdmitRemote { header } => {
                value(bridge.redeem(unit, fd, &root, &header).await?)
            }
            ExportDirCall::At { cap, base, call } => {
                let s = bridge.check_session(unit, fd, &root, &cap)?;
                let answer = s.dir.at(&base, call).await?;
                bridge.check_session(unit, fd, &root, &cap)?;
                value(answer)
            }
            ExportDirCall::OnOpen { cap, open, call } => {
                if matches!(call, FdOp::Release {}) {
                    let s = bridge.bound_session(unit, fd, &root, &cap)?;
                    return value(s.dir.on_open(&open, call).await?);
                }
                let s = bridge.check_session(unit, fd, &root, &cap)?;
                let answer = s.dir.on_open(&open, call).await?;
                bridge.check_session(unit, fd, &root, &cap)?;
                value(answer)
            }
            ExportDirCall::End { cap } => {
                let s = bridge.get_cap(&cap)?;
                bridge.binding(&s.header.export_id, unit, fd, &root)?;
                bridge.remove_cap(&cap).await;
                Ok(Value::Null)
            }
            ExportDirCall::Revoke { id, reason } => {
                if !matches!(reason, Errno::EACCES | Errno::ESTALE | Errno::ENOTCONN) {
                    return Err(Errno::EINVAL);
                }
                let e = bridge.binding(&id, unit, fd, &root)?;
                bridge.remove_export(&id).await;
                if let Some(r) = &e.relay {
                    js_call(r, json!({ "op": "revoke", "id": id, "reason": reason })).await?;
                }
                Ok(Value::Null)
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayClaim {
    export_id: String,
    session: String,
    transport: TransportKind,
    publisher_account: u32,
    peer_identity: PeerIdentity,
    password_auth: bool,
    expires_at: u64,
    rule: ExportRule,
}

/// An admission ticket comes from the private publisher listener. The worker
/// independently redeems it at the authenticated relay. Port data cannot
/// supply a peer identity or a password verdict.
pub struct RemotePort {
    pub export_id: String,
    pub session: String,
    pub ticket: String,
    pub transport: TransportKind,
    pub port: JsValue,
}

impl ExportBridge {
    pub async fn attach_remote_transport_port(
        self: &Rc<Self>,
        proxy: u32,
        remote: RemotePort,
        relay: &Function,
        socket_op: &Function,
    ) -> Result<()> {
        let e = self
            .exports
            .borrow()
            .get(&remote.export_id)
            .cloned()
            .ok_or(Errno::ESTALE)?;
        let admission = json!({
            "op": "admit", "id": remote.export_id, "session": remote.session, "ticket": remote.ticket,
        });
        let claim: RelayClaim = from_value(js_call(relay, admission).await?)?;
        if claim.export_id != remote.export_id
            || claim.session != remote.session
            || claim.transport != remote.transport
            || e.publisher_account != Some(claim.publisher_account)
        {
            return Err(Errno::EACCES);
        }
        let same_account = claim.peer_identity.uid == claim.publisher_account;
        let header = self.mint(
            &remote.export_id,
            &e,
            VerifiedPeer {
                identity: claim.peer_identity,
                password_auth: claim.password_auth,
                same_account,
                expires_at: claim.expires_at,
                rule: claim.rule,
            },
            remote.transport,
        )?;
        let sock = SocketOps {
            op: socket_op.clone(),
            pid: proxy,
        };
        let setup = async {
            let (a, b) = sock.pair().await?;
            let handed = sock.handoff(b, &header).await;
            sock.close(b).await;
            if let Err(e) = handed {
                sock.close(a).await;
                return Err(e);
            }
            let bridge = self.clone();
            let cap = header.cap.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let _ = pump_port(&sock, a, &remote.port, header.expires_at).await;
                sock.close(a).await;
                bridge.remove_cap(&cap).await;
            });
            Ok(())
        }
        .await;
        if setup.is_err() {
            self.remove_cap(&header.cap).await;
        }
        setup
    }
}

#[derive(Clone)]
struct SocketOps {
    op: Function,
    pid: u32,
}
impl SocketOps {
    async fn pair(&self) -> Result<(u32, u32)> {
        let v = self
            .call(json!({ "op": "socketpair", "sockType": abi::socket::SOCK_STREAM }))
            .await?;
        Ok((
            from_value(v["sockA"].clone())?,
            from_value(v["sockB"].clone())?,
        ))
    }
    async fn call(&self, args: Value) -> Result<Value> {
        js_call(&self.op, json!({"pid":self.pid,"args":args})).await
    }
    async fn close(&self, id: u32) {
        let _ = self.call(json!({"op":"close","sockId":id})).await;
    }
    async fn write(&self, id: u32, data: &[u8], rights: &[u32], deadline: u64) -> Result<()> {
        let mut offset = 0;
        while offset < data.len() {
            if crate::now_ms() >= deadline {
                return Err(Errno::ETIMEDOUT);
            }
            let chunk = &data[offset..data.len().min(offset + 16 * 1024)];
            let fds: Vec<_> = rights
                .iter()
                .filter(|_| offset == 0)
                .map(|sock| json!({"kind":"unix_sock","sockId":sock}))
                .collect();
            match self
                .call(json!({"op":"sendmsg","sockId":id,"fds":fds,"data":Bytes(chunk.to_vec())}))
                .await
            {
                Err(Errno::EAGAIN) => pause().await?,
                Ok(v) if v["wouldBlock"] == true => pause().await?,
                Ok(v) => {
                    let n: usize = from_value(v["sent"].clone())?;
                    if n == 0 || n > chunk.len() {
                        return Err(Errno::EPIPE);
                    }
                    offset += n;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    async fn connect(&self, path: &str) -> Result<(u32, PeerCred)> {
        let v = self
            .call(json!({"op":"create","sockType":abi::socket::SOCK_STREAM}))
            .await?;
        let id = from_value(v["sockId"].clone())?;
        let connected = async {
            let reply = self
                .call(json!({"op":"connect","sockId":id,"path":path}))
                .await?;
            Ok((id, from_value(reply["peerCred"].clone())?))
        }
        .await;
        if connected.is_err() {
            self.close(id).await;
        }
        connected
    }
    async fn read(&self, id: u32, len: usize) -> Result<Option<Vec<u8>>> {
        let r = self
            .call(json!({"op":"recvmsg","sockId":id,"sabStream":true,"bufLen":len,"maxFds":0}))
            .await?;
        if r["wouldBlock"] == true {
            return Ok(None);
        }
        Ok(Some(from_value::<Bytes>(r["data"].clone())?.0))
    }
    async fn acknowledged(&self, id: u32, deadline: u64) -> Result<()> {
        let mut data = vec![];
        while crate::now_ms() < deadline {
            let Some(bytes) = self.read(id, 4096).await? else {
                pause().await?;
                continue;
            };
            if bytes.is_empty() {
                return Err(Errno::ENOTCONN);
            }
            if data.len() + bytes.len() > CONTROL_MAX {
                return Err(Errno::E2BIG);
            }
            data.extend(bytes);
            if data.contains(&b'\n') {
                return match decode_control::<ExportResponse>(&data)? {
                    ExportResponse::Accepted {} => Ok(()),
                    ExportResponse::Error { errno } => Err(errno),
                    _ => Err(Errno::EIO),
                };
            }
        }
        Err(Errno::ETIMEDOUT)
    }
    async fn handoff(&self, fd: u32, h: &TransportSessionHeader) -> Result<()> {
        let (global, _) = self.connect(EXPORT_TRANSPORT_SOCK).await?;
        let mut forward = None;
        let result = async {
            let mut rights = vec![fd];
            // A non-root system daemon cannot connect to another user's 0600
            // control socket. The authenticated publisher proxy supplies that
            // already-connected endpoint with the data socket in one sendmsg.
            if let Some(uid) = h.manager_uid {
                let (id, peer) = self.connect(&user_export_sock(uid)).await?;
                forward = Some(id);
                if peer.uid != uid {
                    return Err(Errno::EACCES);
                }
                rights.push(id);
            }
            let deadline = h.expires_at.min(crate::now_ms() + 5000);
            self.write(global, &encode_control(h)?, &rights, deadline)
                .await?;
            self.acknowledged(global, deadline).await?;
            if let Some(id) = forward {
                self.acknowledged(id, deadline).await?;
            }
            Ok(())
        }
        .await;
        if let Some(id) = forward {
            self.close(id).await;
        }
        self.close(global).await;
        result
    }
}
async fn pause() -> Result<()> {
    let g = js_sys::global();
    let timer: Function = Reflect::get(&g, &"setTimeout".into())
        .map_err(js_errno)?
        .dyn_into()
        .map_err(js_errno)?;
    JsFuture::from(Promise::new(&mut |resolve, reject| {
        if let Err(e) = timer.call2(&g, &resolve, &4.into()) {
            let _ = reject.call1(&JsValue::NULL, &e);
        }
    }))
    .await
    .map_err(js_errno)?;
    Ok(())
}
fn port_method(port: &JsValue, method: &str) -> Result<Function> {
    Reflect::get(port, &method.into())
        .map_err(js_errno)?
        .dyn_into()
        .map_err(js_errno)
}
async fn pump_port(sock: &SocketOps, id: u32, port: &JsValue, expires: u64) -> Result<()> {
    const QUEUE_LIMIT: usize = (OSFS_MAX_FRAME_BYTES + 4) * OSFS_MAX_INFLIGHT;
    let queue = Rc::new(RefCell::new(VecDeque::<u8>::new()));
    let terminal = Rc::new(Cell::new(None::<Errno>));
    let onmessage = Closure::wrap(Box::new({
        let queue = queue.clone();
        let terminal = terminal.clone();
        move |event: JsValue| {
            if terminal.get().is_some() {
                return;
            }
            let data = Reflect::get(&event, &"data".into()).unwrap_or_default();
            let kind = Reflect::get(&data, &"type".into())
                .ok()
                .and_then(|v| v.as_string());
            match kind.as_deref() {
                Some("frame") => {
                    let bytes = Reflect::get(&data, &"bytes".into()).unwrap_or_default();
                    if !bytes.is_instance_of::<js_sys::ArrayBuffer>()
                        && !bytes.is_instance_of::<Uint8Array>()
                    {
                        terminal.set(Some(Errno::EIO));
                        return;
                    }
                    let a = Uint8Array::new(&bytes);
                    let n = a.length() as usize;
                    if n > OSFS_MAX_FRAME_BYTES + 4 || n > QUEUE_LIMIT - queue.borrow().len() {
                        terminal.set(Some(Errno::E2BIG));
                        return;
                    }
                    queue.borrow_mut().extend(a.to_vec());
                }
                Some("message") => {
                    let msg = Reflect::get(&data, &"message".into()).unwrap_or_default();
                    let parsed = js_sys::JSON::stringify(&msg)
                        .ok()
                        .and_then(|s| serde_json::from_str::<OsfsFrame>(&String::from(s)).ok())
                        .and_then(|f| encode_frame(&f).ok());
                    if let Some(bytes) = parsed
                        && bytes.len() <= QUEUE_LIMIT - queue.borrow().len()
                    {
                        queue.borrow_mut().extend(bytes);
                    } else {
                        terminal.set(Some(Errno::EIO));
                    }
                }
                Some("closed") => terminal.set(Some(js_errno(data))),
                _ => {}
            }
        }
    }) as Box<dyn FnMut(JsValue)>);
    let onclose = Closure::wrap(Box::new({
        let terminal = terminal.clone();
        move |_event: JsValue| {
            if terminal.get().is_none() {
                terminal.set(Some(Errno::ENOTCONN));
            }
        }
    }) as Box<dyn FnMut(JsValue)>);
    Reflect::set(port, &"onmessage".into(), onmessage.as_ref()).map_err(js_errno)?;
    let result = async {
        port_method(port, "addEventListener")?
            .call2(port, &"close".into(), onclose.as_ref())
            .map_err(js_errno)?;
        Reflect::set(port, &"onmessageerror".into(), onclose.as_ref()).map_err(js_errno)?;
        port_method(port, "start")?.call0(port).map_err(js_errno)?;
        let post = port_method(port, "postMessage")?;
        let send = |bytes: &[u8]| -> Result<()> {
            let m = js_sys::Object::new();
            Reflect::set(&m, &"type".into(), &"frame".into()).map_err(js_errno)?;
            Reflect::set(&m, &"bytes".into(), &Uint8Array::from(bytes).buffer())
                .map_err(js_errno)?;
            post.call1(port, &m).map_err(js_errno)?;
            Ok(())
        };
        loop {
            if crate::now_ms() >= expires {
                let end = encode_frame(&OsfsFrame::Closed {
                    errno: Errno::ESTALE,
                })?;
                let _ = sock.write(id, &end, &[], crate::now_ms() + 1000).await;
                send(&end)?;
                break;
            }
            let count = queue.borrow().len().min(32768);
            if count > 0 {
                let bytes: Vec<_> = queue.borrow_mut().drain(..count).collect();
                sock.write(id, &bytes, &[], expires).await?;
            }
            // An ordered close can follow acknowledged writes in the same
            // turn. Deliver all received bytes before reporting transport loss.
            if let Some(errno) = terminal.get()
                && queue.borrow().is_empty()
            {
                // EOF preserves a truncated final frame on an interrupted
                // stream so its receiver can classify each outstanding call.
                if !matches!(
                    errno,
                    Errno::ENOTCONN
                        | Errno::ENODEV
                        | Errno::EPIPE
                        | Errno::ECONNRESET
                        | Errno::ETIMEDOUT
                ) {
                    let end = encode_frame(&OsfsFrame::Closed { errno })?;
                    sock.write(id, &end, &[], expires.min(crate::now_ms() + 1000))
                        .await?;
                }
                break;
            }
            let msg = sock
                .call(
                    json!({"op":"recvmsg","sockId":id,"sabStream":true,"bufLen":32768,"maxFds":0}),
                )
                .await?;
            if msg["wouldBlock"] == true {
                if queue.borrow().is_empty() {
                    pause().await?;
                }
                continue;
            }
            let data: Bytes = from_value(msg["data"].clone())?;
            if data.0.is_empty() {
                break;
            }
            send(&data.0)?;
        }
        Ok(())
    }
    .await;
    let _ = Reflect::set(port, &"onmessage".into(), &JsValue::NULL);
    let _ = Reflect::set(port, &"onmessageerror".into(), &JsValue::NULL);
    if let Ok(remove) = port_method(port, "removeEventListener") {
        let _ = remove.call2(port, &"close".into(), onclose.as_ref());
    }
    if let Ok(post) = port_method(port, "postMessage") {
        let _ = post.call1(
            port,
            &crate::vfs_engine::json_to_js(&json!({"type":"close"})).unwrap_or_default(),
        );
    }
    if let Ok(close) = port_method(port, "close") {
        let _ = close.call0(port);
    }
    result
}

/// AF_UNIX adapter used by mountd's same-instance sharefs attach. The
/// callback is the worker's existing sockRequest dispatcher (including SAB
/// ring initialization, SCM_RIGHTS offsets and readiness), owned by proxy.
struct GuestStream {
    socket: SocketOps,
    id: u32,
    reading: RefCell<Option<vfs::BoxFuture<'static, Vec<u8>>>>,
    writing: RefCell<Option<vfs::BoxFuture<'static, usize>>>,
}
impl vfs::sharefs_ipc::ByteStream for GuestStream {
    fn notify_loss(&self, provider: &Rc<vfs::ProviderState>) {
        let provider = provider.clone();
        wasm_bindgen_futures::spawn_local(async move { provider.lose() });
    }
    fn poll_write(
        &self,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<Result<usize>> {
        let mut pending = self.writing.borrow_mut();
        let f = pending.get_or_insert_with(|| {
            let sock = self.socket.clone();
            let id = self.id;
            let part = bytes[..bytes.len().min(16 * 1024)].to_vec();
            Box::pin(async move {
                sock.write(id, &part, &[], crate::now_ms() + 15000).await?;
                Ok(part.len())
            })
        });
        let result = f.as_mut().poll(cx);
        if result.is_ready() {
            *pending = None;
        }
        result
    }
    fn poll_read(
        &self,
        cx: &mut std::task::Context<'_>,
        bytes: &mut [u8],
    ) -> std::task::Poll<Result<usize>> {
        let mut pending = self.reading.borrow_mut();
        let f = pending.get_or_insert_with(|| {
            let sock = self.socket.clone();
            let id = self.id;
            let len = bytes.len();
            Box::pin(async move {
                loop {
                    if let Some(v) = sock.read(id, len).await? {
                        return Ok(v);
                    }
                    pause().await?;
                }
            })
        });
        let result = f.as_mut().poll(cx);
        if result.is_ready() {
            *pending = None;
        }
        result.map(|r| {
            r.and_then(|v| {
                bytes
                    .get_mut(..v.len())
                    .ok_or(Errno::EIO)?
                    .copy_from_slice(&v);
                Ok(v.len())
            })
        })
    }
}
impl Drop for GuestStream {
    fn drop(&mut self) {
        let sock = self.socket.clone();
        let fd = self.id;
        wasm_bindgen_futures::spawn_local(async move {
            sock.close(fd).await;
        });
    }
}

impl ExportBridge {
    /// Mountd tries this local registry and socket first when selecting a transport.
    pub async fn connect_share_ipc(
        &self,
        proxy: u32,
        id: &str,
        rule: ExportRule,
        socket_op: Function,
    ) -> Result<(Rc<vfs::MountBacking>, Handle)> {
        if !valid_id(id) {
            return Err(Errno::EINVAL);
        }
        let export = self
            .exports
            .borrow()
            .get(id)
            .cloned()
            .ok_or(Errno::ENOENT)?;
        if crate::now_ms() >= export.expires_at {
            return Err(Errno::ESTALE);
        }
        if !export.transports.contains(&TransportKind::Ipc) {
            return Err(Errno::EPROTONOSUPPORT);
        }
        let socket = SocketOps {
            pid: proxy,
            op: socket_op,
        };
        let (fd, peer) = socket.connect(&export_ipc_sock(id)).await?;
        if peer.uid == 0 || peer.pid != export.daemon {
            socket.close(fd).await;
            return Err(Errno::EACCES);
        }
        mount_stream(socket, fd, rule.intersect(export.rule)).await
    }
}

/// Receiver for a negotiated WebRTC, relay or cross-tab stream. The host
/// transfers the port from connectExportTransport().takePort() before any RPC.
pub async fn connect_share_port(
    proxy: u32,
    port: JsValue,
    expires_at: u64,
    rule: ExportRule,
    socket_op: Function,
) -> Result<(Rc<vfs::MountBacking>, Handle)> {
    if expires_at <= crate::now_ms() {
        return Err(Errno::ESTALE);
    }
    let socket = SocketOps {
        pid: proxy,
        op: socket_op,
    };
    let (a, b) = socket.pair().await?;
    let pump = socket.clone();
    wasm_bindgen_futures::spawn_local(async move {
        let _ = pump_port(&pump, a, &port, expires_at).await;
        pump.close(a).await;
    });
    mount_stream(socket, b, rule).await
}

async fn mount_stream(
    socket: SocketOps,
    fd: u32,
    rule: ExportRule,
) -> Result<(Rc<vfs::MountBacking>, Handle)> {
    let stream = GuestStream {
        socket,
        id: fd,
        reading: RefCell::default(),
        writing: RefCell::default(),
    };
    Ok(vfs::sharefs_ipc::IpcShareTransport::connect(stream, rule)
        .await?
        .into_backing())
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::fs::{FsId, OpenOptions};
    use vfs::{Filesystem, ReleaseQueue, memfs::MemFs, now_or_never};
    fn dir() -> FileRef {
        let cred = peer_cred(PeerIdentity {
            uid: 1001,
            gid: 42,
            groups: vec![],
        });
        let fs: Rc<dyn Filesystem> = Rc::new(MemFs::new(
            FsId("disk".into()),
            7,
            1001,
            42,
            0o775,
            Box::new(|| (1, 0)),
        ));
        let h = fs.root();
        let opt = *OpenOptions::new().read(true);
        let open = now_or_never(fs.open(&cred, &h, &opt)).unwrap().unwrap();
        FileRef::new(fs, open, h, cred, &opt, &ReleaseQueue::new())
    }
    #[test]
    fn process_exit_unlinks_only_the_original_socket_inodes() {
        let dir = dir();
        let fs = dir.fs();
        let cred = dir.cred();
        let h = dir.handle();
        let bridge = ExportBridge::default();
        let unit = ServiceGrant {
            peer: PeerCred {
                pid: 8,
                uid: 1001,
                gid: 42,
            },
            export_impersonate: true,
        };
        for name in ["control.sock", "transport.sock"] {
            let entry = now_or_never(fs.mksock(cred, h, name, 0o666))
                .unwrap()
                .unwrap();
            now_or_never(bridge.track_listener(
                &unit,
                dir.clone(),
                name.to_owned(),
                entry.handle.fs.dev(),
                entry.handle.node.ino,
            ))
            .unwrap()
            .unwrap();
        }
        now_or_never(fs.unlink(cred, h, "control.sock"))
            .unwrap()
            .unwrap();
        let replacement = now_or_never(fs.mkdir(cred, h, "control.sock", 0o700))
            .unwrap()
            .unwrap();
        now_or_never(bridge.release_process(unit.peer.pid)).unwrap();
        assert_eq!(
            now_or_never(fs.lookup(cred, h, "control.sock"))
                .unwrap()
                .unwrap()
                .handle,
            replacement.handle
        );
        assert_eq!(
            now_or_never(fs.lookup(cred, h, "transport.sock")).unwrap(),
            Err(Errno::ENOENT)
        );
    }

    #[test]
    fn scoped_admission_is_single_use_and_bound_to_root_process_rule_and_lease() {
        let root = dir();
        let unit = ServiceGrant {
            peer: PeerCred {
                pid: 14,
                uid: 500,
                gid: 500,
            },
            export_impersonate: true,
        };
        let rule = ExportRule {
            writable: true,
            execute: false,
        };
        let ex = Rc::new(Published {
            daemon: 14,
            manager_uid: None,
            dirfd: 9,
            root: root.clone(),
            expires_at: crate::now_ms() + 60_000,
            rule,
            transports: vec![TransportKind::Relay],
            publisher_account: Some(9988),
            relay: None,
        });
        let bridge = ExportBridge::default();
        bridge.exports.borrow_mut().insert("one".into(), ex.clone());
        for (password_auth, same_account, uid) in [
            (true, false, 1001),
            (false, true, 1001),
            (false, false, 2002),
        ] {
            let header = bridge
                .mint(
                    "one",
                    &ex,
                    VerifiedPeer {
                        identity: PeerIdentity {
                            uid: 2002,
                            gid: 400,
                            groups: vec![42],
                        },
                        password_auth,
                        same_account,
                        expires_at: ex.expires_at,
                        rule,
                    },
                    TransportKind::Relay,
                )
                .unwrap();
            let mut altered = header.clone();
            altered.rule.execute = true;
            assert_eq!(
                now_or_never(bridge.redeem(&unit, 9, &root, &altered))
                    .unwrap()
                    .unwrap_err(),
                Errno::EACCES
            );
            assert!(
                now_or_never(bridge.redeem(&unit, 9, &dir(), &header))
                    .unwrap()
                    .is_err()
            );
            now_or_never(bridge.redeem(&unit, 9, &root, &header))
                .unwrap()
                .unwrap();
            assert!(
                now_or_never(bridge.redeem(&unit, 9, &root, &header))
                    .unwrap()
                    .is_err()
            );
            let dir = bridge
                .check_session(&unit, 9, &root, &header.cap)
                .unwrap()
                .dir
                .clone();
            let OsfsResponse::Entry(created) = now_or_never(dir.at(
                &dir.root(),
                AtOp::Mkdir {
                    name: format!("dir-{uid}-{password_auth}"),
                    mode: 0o777,
                    umask: 0o077,
                },
            ))
            .unwrap()
            .unwrap() else {
                panic!("expected directory")
            };
            assert_eq!((created.metadata.uid, created.metadata.mode), (uid, 0o700));
            assert!(bridge.check_session(&unit, 10, &root, &header.cap).is_err());
            let untrusted = ServiceGrant {
                peer: unit.peer,
                export_impersonate: false,
            };
            assert!(
                bridge
                    .check_session(&untrusted, 9, &root, &header.cap)
                    .is_err()
            );
            now_or_never(bridge.remove_cap(&header.cap)).unwrap();
            assert!(bridge.check_session(&unit, 9, &root, &header.cap).is_err());
        }
        let forged = PeerIdentityCap {
            token: "00".repeat(32),
        };
        assert!(bridge.get_cap(&forged).is_err());
        now_or_never(bridge.release_process(14)).unwrap();
        assert!(bridge.exports.borrow().is_empty());
        assert_eq!(
            authorize(&ServiceGrant {
                peer: PeerCred {
                    pid: 1,
                    uid: 0,
                    gid: 0
                },
                export_impersonate: true
            }),
            Err(Errno::EPERM)
        );
    }
}

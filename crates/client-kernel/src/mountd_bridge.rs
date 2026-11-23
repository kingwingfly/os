//! The browser supplies host grants and the shared socket arena. Policy and the identity
//! attached to each connection come from the instance kernel.
use crate::Kernel;
use crate::vfs_engine::{json_to_js, map_errno};
use abi::mount_ctl::*;
use abi::socket::{PeerCred, SOCK_STREAM};
use abi::{Bytes, Errno, mount_flags, umount_flags};
use js_sys::{Function, Promise, Reflect};
use serde_json::{Value, json};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

#[wasm_bindgen]
pub struct HostSourceTable {
    uid: Cell<u32>,
    login_epoch: Cell<u32>,
    active: Cell<bool>,
    sources: RefCell<BTreeMap<String, SourceInfo>>,
    // Mount IDs are kernel allocated and never reused. A path can be detached and reused.
    attached: RefCell<BTreeMap<u64, String>>,
    pending_images: RefCell<BTreeSet<(u64, String)>>,
}

struct PendingImage<'a> {
    table: &'a HostSourceTable,
    key: (u64, String),
}

impl Drop for PendingImage<'_> {
    fn drop(&mut self) {
        self.table.pending_images.borrow_mut().remove(&self.key);
    }
}

fn opaque_id(id: &str) -> bool {
    let Some(uuid) = id.strip_prefix("src:") else {
        return false;
    };
    uuid.len() == 36
        && uuid.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

impl HostSourceTable {
    fn insert(&self, epoch: u32, source: SourceInfo, overlaps: &[String]) -> Result<(), Errno> {
        if !self.active.get()
            || epoch != self.login_epoch.get()
            || source.owner_uid != Some(self.uid.get())
        {
            return Err(Errno::EACCES);
        }
        if !opaque_id(&source.id) {
            return Err(Errno::EINVAL);
        }
        let mut table = self.sources.borrow_mut();
        if overlaps.iter().any(|id| table.contains_key(id)) || table.contains_key(&source.id) {
            return Err(Errno::EEXIST);
        }
        table.insert(source.id.clone(), source);
        Ok(())
    }
    fn get(&self, id: &str, uid: u32) -> Result<SourceInfo, Errno> {
        if !self.active.get() || self.uid.get() != uid {
            return Err(Errno::EACCES);
        }
        self.sources.borrow().get(id).cloned().ok_or(Errno::EACCES)
    }
}

#[wasm_bindgen]
impl HostSourceTable {
    #[wasm_bindgen(constructor)]
    pub fn new(uid: u32, login_epoch: u32) -> Self {
        Self {
            uid: uid.into(),
            login_epoch: login_epoch.into(),
            active: true.into(),
            sources: RefCell::default(),
            attached: RefCell::default(),
            pending_images: RefCell::default(),
        }
    }
    pub fn change_session(&self, uid: u32, login_epoch: u32) -> Result<(), JsValue> {
        if login_epoch <= self.login_epoch.get() {
            return Err(map_errno(Errno::ESTALE));
        }
        self.active.set(true);
        self.uid.set(uid);
        self.login_epoch.set(login_epoch);
        self.sources.borrow_mut().clear();
        self.attached.borrow_mut().clear();
        Ok(())
    }
    pub fn end_session(&self, login_epoch: u32) {
        if login_epoch == self.login_epoch.get() {
            self.active.set(false);
            self.sources.borrow_mut().clear();
            self.attached.borrow_mut().clear();
        }
    }
    pub fn register_source_grant(
        &self,
        login_epoch: u32,
        source_json: &str,
        overlaps: Vec<String>,
    ) -> Result<(), JsValue> {
        let source = serde_json::from_str(source_json).map_err(|_| map_errno(Errno::EINVAL))?;
        self.insert(login_epoch, source, &overlaps)
            .map_err(map_errno)
    }
    pub fn set_source_state(
        &self,
        login_epoch: u32,
        source_id: &str,
        state: &str,
    ) -> Result<(), JsValue> {
        if self.login_epoch.get() != login_epoch {
            return Err(map_errno(Errno::ESTALE));
        }
        let mut table = self.sources.borrow_mut();
        let source = table
            .get_mut(source_id)
            .ok_or_else(|| map_errno(Errno::ENOENT))?;
        source.state =
            serde_json::from_value(json!(state)).map_err(|_| map_errno(Errno::EINVAL))?;
        Ok(())
    }
}

async fn host_value(f: &Function, args: Value) -> Result<JsValue, JsValue> {
    let r = f.call1(&JsValue::UNDEFINED, &json_to_js(&args)?)?;
    JsFuture::from(Promise::resolve(&r)).await
}

async fn host_call(f: &Function, args: Value) -> Result<Value, JsValue> {
    let r = host_value(f, args).await?;
    if r.is_undefined() {
        return Ok(Value::Null);
    }
    serde_json::from_str(&String::from(js_sys::JSON::stringify(&r)?))
        .map_err(|_| map_errno(Errno::EIO))
}

async fn socket_wait() -> Result<(), JsValue> {
    let global = js_sys::global();
    let timer: Function = Reflect::get(&global, &"setTimeout".into())?.dyn_into()?;
    JsFuture::from(Promise::new(&mut |resolve, reject| {
        if let Err(e) = timer.call2(&global, &resolve, &4.into()) {
            let _ = reject.call1(&global, &e);
        }
    }))
    .await
    .map(|_| ())
}

/// Read through a pinned source directory. Refuse crossings into a different mount,
/// changes in size, and symlink substitution of the final component.
async fn package_file(
    vfs: &vfs::Vfs,
    pid: u32,
    dir: &vfs::PathAnchor,
    path: &str,
    limit: u64,
) -> Result<Vec<u8>, Errno> {
    let (file, entry) = vfs
        .open_file(
            pid,
            vfs::StartAnchor::Anchor(dir.clone()),
            path,
            abi::O_RDONLY | abi::O_NOFOLLOW,
            0,
        )
        .await?;
    let read = async {
        if file.mount_pin().is_none_or(|p| p.id() != dir.pin.id()) {
            return Err(Errno::EXDEV);
        }
        if !entry.metadata.is_file() {
            return Err(Errno::EINVAL);
        }
        if entry.metadata.size > limit {
            return Err(Errno::EFBIG);
        }
        let mut bytes = vec![0; entry.metadata.size as usize];
        let mut offset = 0;
        for chunk in bytes.chunks_mut(64 * 1024) {
            let mut remaining = chunk;
            while !remaining.is_empty() {
                let n = file.read_at(remaining, offset).await?;
                if n == 0 {
                    return Err(Errno::ESTALE);
                }
                offset += n as u64;
                remaining = &mut remaining[n..];
            }
        }
        if file.read_at(&mut [0], offset).await? != 0 {
            return Err(Errno::ESTALE);
        }
        Ok(bytes)
    }
    .await;
    let closed = file.close().await;
    let bytes = read?;
    closed?;
    Ok(bytes)
}

async fn private_image(
    vfs: &vfs::Vfs,
    pid: u32,
    dir: &vfs::PathAnchor,
    target: &str,
    allow_execute: bool,
) -> Result<Rc<vfs::MountBacking>, Errno> {
    use vfs::imagefs::{ImageEntry, ImageFs, ImageNodeKind, MemoryBlobStore};
    let manifest = package_file(vfs, pid, dir, "manifest.json", image::MANIFEST_MAX as u64).await?;
    let img = image::Image::parse(&manifest).map_err(|_| Errno::EINVAL)?;
    let tree = image::Composition::private(&[img]).map_err(|_| Errno::EINVAL)?;
    let cred = vfs.process_cred(pid)?;
    let mut blobs = MemoryBlobStore::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut blob_dir = None;
    let mut total = 0u64;
    let mut entries = vec![];
    for entry in tree.entries.into_values() {
        let node = match entry.node {
            image::Node::Directory => ImageNodeKind::Directory,
            image::Node::Symlink { target: link } => ImageNodeKind::Symlink {
                target: if link.starts_with('/') {
                    format!("{target}{link}")
                } else {
                    link
                },
            },
            image::Node::File {
                sha256,
                size,
                chunk_size,
                chunks,
            } => {
                if seen.insert(sha256.clone()) {
                    total = total.checked_add(size).ok_or(Errno::EFBIG)?;
                    if total > 128 * 1024 * 1024 {
                        return Err(Errno::EFBIG);
                    }
                    if blob_dir.is_none() {
                        let flags = abi::O_PATH | abi::O_DIRECTORY | abi::O_NOFOLLOW;
                        let (open, entry) = vfs
                            .open_file(
                                pid,
                                vfs::StartAnchor::Anchor(dir.clone()),
                                "blobs",
                                flags,
                                0,
                            )
                            .await?;
                        let pin = open.mount_pin().ok_or(Errno::ESTALE)?;
                        if !entry.metadata.is_dir() || pin.id() != dir.pin.id() {
                            return Err(Errno::EXDEV);
                        }
                        blob_dir = Some(vfs::PathAnchor {
                            pin: pin.clone(),
                            handle: entry.handle,
                            open,
                        });
                    }
                    let bytes =
                        package_file(vfs, pid, blob_dir.as_ref().unwrap(), &sha256, size).await?;
                    if bytes.len() as u64 != size || image::digest(&bytes) != sha256 {
                        return Err(Errno::EIO);
                    }
                    blobs.insert(sha256.clone(), bytes);
                }
                ImageNodeKind::File {
                    blob_id: sha256,
                    size,
                    chunk_size: Some(chunk_size),
                    chunks,
                }
            }
        };
        entries.push(ImageEntry {
            path: entry.path,
            uid: cred.identity.id,
            gid: cred.identity.group,
            mode: entry.mode & 0o777,
            node,
        });
    }
    let id = vfs::FsId(format!("image:private:{}", crate::random_hex(16)));
    let image = ImageFs::new(id, false, (crate::now_secs(), 0).into(), entries, blobs)?;
    Ok(Rc::new(
        vfs::MountBacking::new(Rc::new(image), vfs::FsType::Image)
            .with_ceilings(true, !allow_execute),
    ))
}

/// Read an unattached grant in a scratch mount namespace. The source and its
/// temporary mountpoint are never installed in a session or exposed to another process.
async fn image_from_grant(
    source: &SourceInfo,
    prepared: JsValue,
    cred: &vfs::Cred,
    target: &str,
    execute: bool,
) -> Result<Rc<vfs::MountBacking>, JsValue> {
    let store = Reflect::get(&prepared, &"hostObj".into())?;
    let result = async {
        let kind = match source.kind {
            SourceKind::Hostfs => "directory",
            SourceKind::Opfs => "browser-storage",
            SourceKind::Helperfs => "native-directory",
            SourceKind::Sharefs => "shared",
            _ => return Err(map_errno(Errno::EINVAL)),
        };
        let grant = crate::mounts::Grant {
            kind: kind.into(),
            name: "package".into(),
            read_only: true,
            execute: source.execute,
            owner: cred.identity.clone(),
        };
        let (backing, subroot, executable) = if source.kind == SourceKind::Sharefs {
            let (backing, root, _, _, executable, _) =
                crate::share_bridge::build_share_backing(store, &source.id)
                    .await
                    .map_err(map_errno)?;
            (backing, Some((root, "/".into())), executable)
        } else {
            let spec = serde_json::to_string(&grant).map_err(|_| map_errno(Errno::EINVAL))?;
            let mount = match source.kind {
                SourceKind::Hostfs => crate::hostfs::mount_directory(store, &spec).await?,
                SourceKind::Opfs => crate::hostfs::mount_opfs(store, &spec).await?,
                SourceKind::Helperfs => crate::helper::connect_helper_mount(store, &spec).await?,
                _ => unreachable!(),
            };
            let fstype = vfs::FsType::parse(source.kind.fstype()).map_err(map_errno)?;
            (
                mount.mount_backing(fstype),
                None,
                mount.grant_info().execute,
            )
        };
        if execute && !executable {
            return Err(map_errno(Errno::EACCES));
        }
        let uid = cred.identity.id;
        let tmp = vfs::memfs::MemFs::new(
            vfs::FsId("mountd-stage".into()),
            1,
            uid,
            cred.identity.group,
            0o700,
            Box::new(|| (crate::now_secs(), 0)),
        );
        let scratch = vfs::Vfs::boot(
            "mountd",
            Rc::new(vfs::MountBacking::new(Rc::new(tmp), vfs::FsType::TmpFs)),
            "tmpfs",
            Rc::new(vfs::DefaultFilesystemFactory::default()),
        )
        .await
        .map_err(map_errno)?;
        let reader = 2;
        scratch
            .spawn_process(reader, 1, cred.clone(), None, None, None)
            .map_err(map_errno)?;
        scratch
            .mkdirat(reader, vfs::StartAnchor::Root, "/source", 0o700)
            .await
            .map_err(map_errno)?;
        let ns = scratch.system_namespace();
        let lock = mount_flags::MS_RDONLY
            | mount_flags::MS_NOSUID
            | mount_flags::MS_NODEV
            | mount_flags::MS_NOEXEC;
        scratch
            .mount_on_namespace(
                &ns,
                cred,
                backing,
                subroot,
                &source.id,
                "/source",
                vfs::MountFlags::from_accepted(lock),
                lock,
                Some(uid),
            )
            .await
            .map_err(map_errno)?;
        scratch.chdir(reader, "/source").await.map_err(map_errno)?;
        let dir = scratch
            .process_fs_context(reader)
            .map_err(map_errno)?
            .borrow()
            .cwd
            .clone();
        private_image(&scratch, reader, &dir, target, executable && source.execute)
            .await
            .map_err(map_errno)
    }
    .await;
    if let Ok(cleanup) = Reflect::get(&prepared, &"cleanup".into())
        && let Some(f) = cleanup.dyn_ref::<Function>()
    {
        let _ = f.call0(&JsValue::UNDEFINED);
    }
    result
}

impl Kernel {
    fn check_mount_daemon(&self, peer: PeerCred) -> Result<(), Errno> {
        let state = self.state.borrow();
        let proc = state.table.proc(peer.pid).ok_or(Errno::ESRCH)?;
        if proc.state == abi::ProcState::Zombie
            || proc.path != "/usr/bin/mountd"
            || self.kernel_peer_cred(peer.pid)? != peer
        {
            return Err(Errno::EACCES);
        }
        Ok(())
    }

    fn page_peer(&self, session_id: &str, proxy: u32) -> Result<PeerCred, Errno> {
        let peer = self.kernel_peer_cred(proxy)?;
        let state = self.state.borrow();
        let rt = self.vfs_rt.borrow();
        let session = rt.sessions.get(session_id).ok_or(Errno::EACCES)?;
        if !self.is_proc_live(proxy)
            || state.login_session.shutdown.is_some()
            || state.login_session.id != session_id
            || state.login_session.uid != peer.uid
            || rt.active_session_id.as_deref() != Some(session_id)
            || state
                .table
                .proc(proxy)
                .and_then(|p| p.login_scope.as_deref())
                != Some(session_id)
            || (peer.uid, peer.gid) != (session.uid, session.gid)
            || !Rc::ptr_eq(&rt.vfs.process_namespace(proxy)?, &session.mnt_ns)
        {
            return Err(Errno::EACCES);
        }
        Ok(peer)
    }
}

#[wasm_bindgen]
impl Kernel {
    /// `proxy` and `socket_op` are supplied ONLY by the worker dispatcher. socket_op calls
    /// the same sockRequest used by guest workers, including SAB initialization and wakeups.
    pub async fn page_unix_rpc(
        &self,
        session_id: String,
        proxy: u32,
        socket: String,
        payload: String,
        optional_fd: Option<u32>,
        socket_op: Function,
    ) -> Result<JsValue, JsValue> {
        let peer = self.page_peer(&session_id, proxy).map_err(map_errno)?;
        abi::socket::validate_unix_path(&socket).map_err(map_errno)?;
        if payload.len() >= MAX_FRAME_BYTES {
            return Err(map_errno(Errno::E2BIG));
        }
        let value: Value = serde_json::from_str(&payload).map_err(|_| map_errno(Errno::EINVAL))?;
        let frame = encode_frame(&value).map_err(|e| map_errno(e.errno))?;
        let call = |args: Value| host_call(&socket_op, json!({"pid":proxy,"args":args}));
        let created = call(json!({"op":"create", "sockType":SOCK_STREAM})).await?;
        let id = created["sockId"]
            .as_u64()
            .ok_or_else(|| map_errno(Errno::EIO))?;
        let result = async {
            let deadline = crate::now_ms() + 10_000;
            let check = || {
                self.page_peer(&session_id, proxy).map_err(map_errno)?;
                if crate::now_ms() >= deadline {
                    return Err(map_errno(Errno::ETIMEDOUT));
                }
                Ok(())
            };
            check()?;
            let connection = call(json!({"op":"connect","sockId":id,"path":socket})).await?;
            let expected_uid = if socket == user_mount_sock(peer.uid) {
                Some(peer.uid)
            } else if socket == SYSTEM_MOUNT_SOCK {
                Some(0)
            } else {
                None
            };
            if expected_uid
                .is_some_and(|uid| connection["peerCred"]["uid"].as_u64() != Some(uid.into()))
            {
                return Err(map_errno(Errno::EACCES));
            }
            let mut sent = 0;
            while sent < frame.len() {
                check()?;
                let fds: Vec<_> = optional_fd
                    .filter(|_| sent == 0)
                    .map(|fd| json!({"kind":"kfd","kfd":fd,"isDir":true,"pathOnly":true}))
                    .into_iter()
                    .collect();
                let chunk = &frame[sent..frame.len().min(sent + 4096)];
                let r = call(
                    json!({"op":"sendmsg","sockId":id,"fds":fds,"data":Bytes(chunk.to_vec())}),
                )
                .await;
                match r {
                    Err(e)
                        if Reflect::get(&e, &"errno".into())
                            .ok()
                            .and_then(|s| s.as_string())
                            .as_deref()
                            == Some("EAGAIN") =>
                    {
                        socket_wait().await?
                    }
                    Ok(r) => {
                        let n = r["sent"]
                            .as_u64()
                            .filter(|&n| n > 0 && n <= chunk.len() as u64)
                            .ok_or_else(|| map_errno(Errno::EPIPE))?;
                        sent += n as usize;
                    }
                    Err(e) => return Err(e),
                }
            }
            let mut response = vec![];
            loop {
                check()?;
                let r = call(
                    json!({"op":"recvmsg","sockId":id,"sabStream":true,"bufLen":4096,"maxFds":0}),
                )
                .await?;
                if r["wouldBlock"] == true {
                    socket_wait().await?;
                    continue;
                }
                let bytes: Bytes =
                    serde_json::from_value(r["data"].clone()).map_err(|_| map_errno(Errno::EIO))?;
                if bytes.is_empty() {
                    return Err(map_errno(Errno::ECONNRESET));
                }
                if response.len() + bytes.len() > MAX_FRAME_BYTES {
                    return Err(map_errno(Errno::E2BIG));
                }
                response.extend_from_slice(&bytes);
                if bytes.contains(&b'\n') {
                    check()?;
                    return json_to_js(
                        &decode_frame::<Value>(&response).map_err(|e| map_errno(e.errno))?,
                    );
                }
            }
        }
        .await;
        let closed = call(json!({"op":"close","sockId":id})).await;
        let reply = result?;
        closed?;
        Ok(reply)
    }

    /// Bind the OS host adapter once at boot in the system mount namespace.
    pub async fn mount_host_listener(&self) -> Result<u32, JsValue> {
        let pid = crate::INIT;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let root = vfs::StartAnchor::Root;
        match vfs.mkdirat(pid, root.clone(), "/run/mount", 0o755).await {
            Ok(_) | Err(Errno::EEXIST) => (),
            Err(e) => return Err(map_errno(e)),
        }
        let dir = vfs
            .statat(pid, root.clone(), "/run/mount", false)
            .await
            .map_err(map_errno)?;
        if dir.uid != 0 || dir.mode & abi::S_IFMT != abi::S_IFDIR || dir.mode & 0o022 != 0 {
            return Err(map_errno(Errno::EACCES));
        }
        let cred = self.kernel_peer_cred(pid).map_err(map_errno)?;
        let sock = self
            .vfs_rt
            .borrow()
            .unix_sock
            .borrow_mut()
            .create(pid, vfs::unix_sock::SockType::Stream, cred)
            .map_err(map_errno)?;
        let bind = async {
            self.sock_bind(pid, sock, MOUNT_HOST_SOCK.into()).await?;
            vfs.setattrat(
                pid,
                root,
                MOUNT_HOST_SOCK,
                &vfs::SetAttr {
                    mode: Some(0o666),
                    ..Default::default()
                },
                false,
            )
            .await
            .map_err(map_errno)?;
            self.sock_listen(pid, sock, 32)?;
            Ok(sock)
        }
        .await;
        if bind.is_err() {
            self.sock_close(pid, sock, 1).await?;
        }
        bind
    }

    /// Process a primitive on the private mountd host channel. `accepted` is the actual
    /// client socket received with SCM_RIGHTS; its holder and SO_PEERCRED are kernel checked.
    pub async fn mount_backend_call(
        &self,
        holder: u32,
        channel: u32,
        accepted: u32,
        command: String,
        table: &HostSourceTable,
        adapter: Function,
    ) -> Result<JsValue, JsValue> {
        let req: MountBackendRequest =
            serde_json::from_str(&command).map_err(|_| map_errno(Errno::EINVAL))?;
        let (vfs, daemon, peer) = {
            let rt = self.vfs_rt.borrow();
            let sockets = rt.unix_sock.borrow();
            (
                rt.vfs.clone(),
                sockets.peer_cred(holder, channel).map_err(map_errno)?,
                sockets.peer_cred(holder, accepted).map_err(map_errno)?,
            )
        };
        // The launcher verifies the executing image. Recheck the live process and socket stamp.
        self.check_mount_daemon(daemon).map_err(map_errno)?;
        if daemon.uid != 0 && daemon.uid != peer.uid {
            return Err(map_errno(Errno::EACCES));
        }
        let pid = req.target_pid.unwrap_or(peer.pid);
        if self.kernel_peer_cred(peer.pid).map_err(map_errno)? != peer
            || !self.is_proc_live(peer.pid)
            || (peer.uid != 0 && pid != peer.pid)
        {
            return Err(map_errno(Errno::EACCES));
        }
        let cred = vfs.process_cred(pid).map_err(map_errno)?;
        let uid = cred.identity.id;
        let ns = vfs.process_namespace(pid).map_err(map_errno)?;
        let ns_id = ns.borrow().id();
        let session_id = self
            .vfs_rt
            .borrow()
            .sessions
            .values()
            .find(|s| s.uid == uid && Rc::ptr_eq(&s.mnt_ns, &ns))
            .map(|s| s.session_id.clone());
        let root = vfs
            .process_fs_context(pid)
            .map_err(map_errno)?
            .borrow()
            .root
            .clone();
        let session_root = root.same_anchor(&ns.borrow().root_anchor());
        let epoch = table.login_epoch.get();
        let host = |op: Value| {
            host_call(
                &adapter,
                json!({"uid":uid,"sessionId":session_id,"loginEpoch":epoch,"operation":op}),
            )
        };
        let value = match req.op {
            MountBackendOp::Peer {} => json!(uid),
            MountBackendOp::Sources {} => {
                let mut rows: Vec<_> = if session_root
                    && table.active.get()
                    && table.uid.get() == uid
                    && session_id.is_some()
                {
                    host(json!({"op":"refresh_sources"})).await?;
                    if epoch != table.login_epoch.get() {
                        return Err(map_errno(Errno::ESTALE));
                    }
                    table.sources.borrow().values().cloned().collect()
                } else {
                    vec![]
                };
                for a in vfs
                    .inspect_attachments_from(ns_id, &cred, &root, false)
                    .await
                    .map_err(map_errno)?
                {
                    if a.user_mount {
                        continue;
                    }
                    let kind = match a.fstype.as_str() {
                        "cowfs" if a.source_label.starts_with("snapshot:") => {
                            SourceKind::CowfsSnapshot
                        }
                        "cowfs" if a.source_label.starts_with("/dev/loop") => {
                            SourceKind::LoopDevice
                        }
                        "cowfs" => SourceKind::CowfsVolume,
                        "image" => SourceKind::Image,
                        "cloud" => SourceKind::Cloud,
                        _ => continue,
                    };
                    let (id, label) = match kind {
                        SourceKind::Cloud => ("cloud:default".into(), "Cloud".into()),
                        SourceKind::Image => (format!("image:{}", a.fs_id), "Release image".into()),
                        SourceKind::CowfsVolume => {
                            let device =
                                ns.borrow().entry(vfs::MountId(a.mount_id)).and_then(|e| {
                                    let backing = &e.slot.backing;
                                    (backing.fs.capabilities().durability
                                        != abi::contract::Durability::FencedCommit
                                        && a.health == "connected")
                                        .then(|| backing.cowfs_volume_device())
                                        .flatten()
                                        .cloned()
                                });
                            if let Some(device) = device {
                                let info = device.cowfs_info().await.map_err(map_errno)?;
                                for snap in
                                    device.cowfs_snap_list().await.map_err(map_errno)?.snapshots
                                {
                                    let id = format!("snapshot:{}@{}", info.volume, snap.name);
                                    if !rows.iter().any(|s| s.id == id) {
                                        rows.push(SourceInfo {
                                            id,
                                            kind: SourceKind::CowfsSnapshot,
                                            label: snap.name,
                                            location: a.target.clone(),
                                            state: SourceState::Granted,
                                            writable: false,
                                            execute: !a.noexec,
                                            saved: false,
                                            owner_uid: None,
                                        });
                                    }
                                }
                                (format!("volume:{}", info.volume), info.volume)
                            } else {
                                (a.source_label.clone(), a.source_label.clone())
                            }
                        }
                        _ => (a.source_label.clone(), a.source_label.clone()),
                    };
                    let state = match a.health.as_str() {
                        "lost" => SourceState::Offline,
                        "revoked" => SourceState::Revoked,
                        _ => SourceState::Granted,
                    };
                    if !rows.iter().any(|s| s.id == id) {
                        rows.push(SourceInfo {
                            id,
                            kind,
                            label,
                            location: a.target,
                            state,
                            writable: !a.read_only,
                            execute: !a.noexec,
                            saved: false,
                            owner_uid: None,
                        });
                    }
                }
                json!(rows)
            }
            MountBackendOp::Filesystems {} => json!(
                vfs.inspect_filesystems_from(ns_id, &cred, &root)
                    .await
                    .map_err(map_errno)?
            ),
            MountBackendOp::Attachments { include_busy } => {
                let mut rows = vfs
                    .inspect_attachments_from(ns_id, &cred, &root, include_busy)
                    .await
                    .map_err(map_errno)?;
                for a in &mut rows {
                    if let Some(id) = table.attached.borrow().get(&a.mount_id) {
                        a.source_id = Some(id.clone());
                    }
                }
                json!(rows)
            }
            MountBackendOp::Exports {} if session_root => host(json!({"op":"exports"})).await?,
            MountBackendOp::Exports {} => json!([]),
            MountBackendOp::Forget { source_id } => {
                if !session_root {
                    return Err(map_errno(Errno::EACCES));
                }
                table.get(&source_id, uid).map_err(map_errno)?;
                host(json!({"op":"forget","source_id":source_id})).await?;
                if epoch != table.login_epoch.get() {
                    return Err(map_errno(Errno::ESTALE));
                }
                table.sources.borrow_mut().remove(&source_id);
                Value::Null
            }
            MountBackendOp::Attach {
                source,
                target,
                fstype,
                flags,
                options,
                owner_uid,
            } => {
                if owner_uid.is_some() {
                    if !session_root
                        || owner_uid != Some(uid)
                        || session_id.is_none()
                        || !table.active.get()
                        || table.uid.get() != uid
                    {
                        return Err(map_errno(Errno::EACCES));
                    }
                    if source.starts_with("src:") {
                        let s = table.get(&source, uid).map_err(map_errno)?;
                        if s.state != SourceState::Granted || s.kind.fstype() != fstype {
                            return Err(map_errno(Errno::EACCES));
                        }
                    } else if fstype != "opfs"
                        && !(fstype == "sharefs" && source.starts_with("osfs:"))
                    {
                        return Err(map_errno(Errno::EACCES));
                    }
                    let reply = host(json!({"op":"attach","source_id":source,"target":target,"fstype":fstype,"flags":flags,"options":options})).await?;
                    let mid = reply["mountId"]
                        .as_u64()
                        .ok_or_else(|| map_errno(Errno::EIO))?;
                    if epoch != table.login_epoch.get() {
                        return Err(map_errno(Errno::ESTALE));
                    }
                    table.attached.borrow_mut().insert(mid, source);
                } else {
                    if uid != 0 {
                        return Err(map_errno(Errno::EPERM));
                    }
                    self.sys_mount(
                        pid,
                        Some(source),
                        target,
                        (!fstype.is_empty()).then_some(fstype),
                        JsValue::from_str(&flags.to_string()),
                        options,
                    )
                    .await?;
                }
                Value::Null
            }
            MountBackendOp::Activate {
                source_id,
                name,
                execute,
            } => {
                if !session_root {
                    return Err(map_errno(Errno::EACCES));
                }
                let s = table.get(&source_id, uid).map_err(map_errno)?;
                if s.state != SourceState::Granted || execute && !s.execute {
                    return Err(map_errno(Errno::EACCES));
                }
                let sid = session_id
                    .as_deref()
                    .ok_or_else(|| map_errno(Errno::EACCES))?;
                abi::fs::check_component(&name).map_err(map_errno)?;
                let target = format!("/opt/private/{name}");
                let key = (ns_id.0, target.clone());
                if !table.pending_images.borrow_mut().insert(key.clone()) {
                    return Err(map_errno(Errno::EBUSY));
                }
                let _reservation = PendingImage { table, key };
                let rows = vfs
                    .inspect_attachments_from(ns_id, &cred, &root, false)
                    .await
                    .map_err(map_errno)?;
                if rows.iter().any(|a| a.target == target) {
                    return Err(map_errno(Errno::EBUSY));
                }
                let row = rows.iter().find(|a| {
                    a.fstype != "image"
                        && a.owner_uid == Some(uid)
                        && table.attached.borrow().get(&a.mount_id) == Some(&source_id)
                });
                let backing = if let Some(row) = row {
                    if execute && row.noexec {
                        return Err(map_errno(Errno::EACCES));
                    }
                    let dir = {
                        let ns = ns.borrow();
                        let entry = ns
                            .entry(vfs::MountId(row.mount_id))
                            .ok_or_else(|| map_errno(Errno::ESTALE))?;
                        vfs::PathAnchor {
                            pin: entry.slot.pin(),
                            handle: entry.root.clone(),
                            open: entry.root_open.clone(),
                        }
                    };
                    private_image(&vfs, pid, &dir, &target, s.execute && !row.noexec)
                        .await
                        .map_err(map_errno)?
                } else {
                    let prepared = host_value(&adapter, json!({"uid":uid,"sessionId":sid,"loginEpoch":epoch,
                        "operation":{"op":"image_source","source_id":source_id,"target":target,"fstype":s.kind.fstype(),"flags":mount_flags::MS_RDONLY}})).await?;
                    image_from_grant(&s, prepared, &cred, &target, execute).await?
                };
                let provider = Rc::clone(&backing.provider);
                let check = || {
                    if epoch != table.login_epoch.get()
                        || table.get(&source_id, uid)?.state != SourceState::Granted
                        || !self.is_proc_live(peer.pid)
                        || self.kernel_peer_cred(peer.pid)? != peer
                        || !Rc::ptr_eq(&vfs.process_namespace(pid)?, &ns)
                        || !vfs
                            .process_fs_context(pid)?
                            .borrow()
                            .root
                            .same_anchor(&root)
                        || self
                            .vfs_rt
                            .borrow()
                            .sessions
                            .get(sid)
                            .is_none_or(|s| !Rc::ptr_eq(&s.mnt_ns, &ns))
                        || row
                            .is_some_and(|r| !ns.borrow().contains_mount(vfs::MountId(r.mount_id)))
                    {
                        return Err(Errno::ESTALE);
                    }
                    if self.vfs_rt.borrow().sessions[sid].user_mounts.len() >= 16 {
                        return Err(Errno::ENOSPC);
                    }
                    Ok(())
                };
                check().map_err(map_errno)?;
                let created = match vfs
                    .mkdirat(pid, vfs::StartAnchor::Root, &target, 0o700)
                    .await
                {
                    Ok(entry) => Some(entry.handle.node),
                    Err(Errno::EEXIST) => None,
                    Err(e) => return Err(map_errno(e)),
                };
                let flags = vfs::MountFlags {
                    rdonly: true,
                    nosuid: true,
                    nodev: true,
                    noexec: !execute,
                    ..Default::default()
                };
                let lock = mount_flags::MS_NOSUID | mount_flags::MS_NODEV | mount_flags::MS_RDONLY;
                let mounted = async {
                    check()?;
                    vfs.mount_on_namespace(
                        &ns,
                        &cred,
                        backing,
                        None,
                        &source_id,
                        &target,
                        flags,
                        lock,
                        Some(uid),
                    )
                    .await
                }
                .await;
                let mid = match mounted {
                    Ok(mid) => mid,
                    Err(e) => {
                        if let Some(created) = created
                            && vfs
                                .statat(pid, vfs::StartAnchor::Root, &target, false)
                                .await
                                .is_ok_and(|st| st.ino == created.ino)
                        {
                            let _ = vfs
                                .unlinkat(pid, vfs::StartAnchor::Root, &target, true)
                                .await;
                        }
                        return Err(map_errno(e));
                    }
                };
                if let Err(e) = check() {
                    let _ = ns.borrow_mut().detach_subtree(mid);
                    return Err(map_errno(e));
                }
                let mut rt = self.vfs_rt.borrow_mut();
                let session = rt
                    .sessions
                    .get_mut(sid)
                    .ok_or_else(|| map_errno(Errno::ESTALE))?;
                session.user_mounts.insert(
                    target,
                    crate::vfs_engine::AttachedUserMount {
                        mount_id: mid,
                        kind: "image".into(),
                        name,
                        cloud: false,
                        provider,
                        local_mount: None,
                    },
                );
                session.generation = session.generation.wrapping_add(1);
                table.attached.borrow_mut().insert(mid.0, source_id);
                Value::Null
            }
            MountBackendOp::Remount {
                target,
                mount_id,
                flags,
                options,
            } => {
                if !ns.borrow().contains_mount(vfs::MountId(mount_id)) {
                    return Err(map_errno(Errno::ESTALE));
                }
                self.sys_mount(
                    pid,
                    None,
                    target,
                    None,
                    JsValue::from_str(&(flags | mount_flags::MS_REMOUNT).to_string()),
                    options,
                )
                .await?;
                Value::Null
            }
            MountBackendOp::Detach {
                target,
                mount_id,
                lazy,
                force,
            } => {
                let flags = if lazy { umount_flags::MNT_DETACH } else { 0 }
                    | if force { umount_flags::MNT_FORCE } else { 0 };
                let registered = session_root
                    && session_id.as_ref().is_some_and(|id| {
                        self.vfs_rt
                            .borrow()
                            .sessions
                            .get(id)
                            .and_then(|s| s.user_mounts.get(&target))
                            .is_some_and(|a| a.mount_id.0 == mount_id)
                    });
                if let Some(sid) = session_id.filter(|_| registered) {
                    self.unmount_user(sid, target, flags).await?;
                } else {
                    self.with_proc_scope(
                        pid,
                        vfs.umount2_expected(pid, &target, flags, Some(vfs::MountId(mount_id))),
                    )
                    .await
                    .map_err(map_errno)?;
                }
                table.attached.borrow_mut().remove(&mount_id);
                Value::Null
            }
        };
        json_to_js(&value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_image_verifies_source_bytes_and_sets_ceilings_before_attach() {
        use vfs::{
            DefaultFilesystemFactory, FsId, FsType, MountBacking, StartAnchor, Vfs, memfs::MemFs,
            now_or_never,
        };
        let fs = MemFs::new(FsId("src".into()), 1, 0, 0, 0o755, Box::new(|| (42, 0)));
        let vfs = now_or_never(Vfs::boot(
            "pkg",
            Rc::new(MountBacking::new(Rc::new(fs), FsType::TmpFs)),
            "root",
            Rc::new(DefaultFilesystemFactory::default()),
        ))
        .unwrap()
        .unwrap();
        let root = vfs.system_namespace().borrow().root_anchor();
        let hash = image::digest(b"hello");
        let directory = |path: &str| json!({"path":path,"uid":0,"gid":0,"mode":0o755,"node":{"type":"directory"}});
        let manifest = json!({"format":"os.image","version":2,"kind":"sysext","name":"tools","revision":"local","abi":1,"level":1,"features":[],"provenance":{},
            "entries":[directory("/"),directory("/usr"),{"path":"/usr/tool","uid":0,"gid":0,"mode":0o755,
                "node":{"type":"file","sha256":hash,"size":5,"chunk_size":262144,"chunks":[hash]}}]});
        let write = |path: &str, data: &[u8]| {
            let fd = now_or_never(vfs.openat(
                1,
                StartAnchor::Root,
                path,
                abi::O_CREAT | abi::O_WRONLY | abi::O_TRUNC,
                0o644,
            ))
            .unwrap()
            .unwrap();
            now_or_never(vfs.write(1, fd, data)).unwrap().unwrap();
            now_or_never(vfs.close(1, fd)).unwrap().unwrap();
        };
        now_or_never(vfs.mkdirat(1, StartAnchor::Root, "/blobs", 0o755))
            .unwrap()
            .unwrap();
        write("/manifest.json", &serde_json::to_vec(&manifest).unwrap());
        let path = format!("/blobs/{hash}");
        write(&path, b"hello");
        let load =
            || now_or_never(private_image(&vfs, 1, &root, "/opt/private/tools", false)).unwrap();
        let backing = load().unwrap();
        assert!(backing.ceiling_noexec && backing.ceiling_rdonly);
        write(&path, b"HELLO");
        assert!(matches!(load(), Err(Errno::EIO)));
    }
    #[test]
    fn source_table_fences_owners_epochs_duplicates_and_overlaps() {
        let table = HostSourceTable::new(1000, 9);
        let info = SourceInfo {
            id: "src:11111111-1111-4111-8111-111111111111".into(),
            kind: SourceKind::Hostfs,
            label: "work".into(),
            location: "work".into(),
            state: SourceState::Granted,
            writable: false,
            execute: false,
            saved: true,
            owner_uid: Some(1000),
        };
        assert_eq!(table.insert(8, info.clone(), &[]), Err(Errno::EACCES));
        table.insert(9, info.clone(), &[]).unwrap();
        assert_eq!(table.get(&info.id, 0), Err(Errno::EACCES));
        assert_eq!(table.insert(9, info.clone(), &[]), Err(Errno::EEXIST));
        let child = SourceInfo {
            id: "src:22222222-2222-4222-8222-222222222222".into(),
            ..info.clone()
        };
        assert_eq!(table.insert(9, child, &[info.id]), Err(Errno::EEXIST));
    }
}

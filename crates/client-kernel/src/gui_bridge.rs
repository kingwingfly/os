//! Host-side seat transport. Surface bindings derive both ends from the accepted
//! socket. Public surface numbers alone grant no access to a process Worker.
use crate::{
    Kernel,
    vfs_engine::{json_to_js, map_errno},
};
use abi::{
    Bytes, Errno,
    gui::*,
    gui_ioctl as ioc,
    socket::{PeerCred, SOCK_STREAM},
};
use js_sys::{Function, Promise, Reflect};
use serde_json::{Value, json};
use std::{cell::RefCell, collections::HashMap, rc::Rc};
use vfs::{
    Access, FileType, Vfs,
    guidev::{GuiDevice, GuiDeviceRegistry},
    unix_sock::PickerRecipient,
};
use wasm_bindgen::{JsCast, prelude::*};
use wasm_bindgen_futures::JsFuture;

const MAX_CONTROL_REPLY_BYTES: usize = 65_536;
const MAX_COMPAT_FRAME_BYTES: usize = 256 * 1024;
const MAX_GUI_PINNED_FDS: usize = 128;
const MAX_GUI_PIN_READ_CHUNK: usize = 1 << 20;

/// Kernel-pinned read-only open file handle owned by a GUI surface (`StreamAsset`,
/// `PreviewJob`, or fd-backed `ExportFile`). Never re-opens by path (zero TOCTOU)
/// and is dropped automatically on surface `Unmap`, `SeatReset`, or explicit release.
pub(crate) struct PinnedGuiFd {
    pub(crate) surface_id: SurfaceId,
    pub(crate) owner_pid: u32,
    pub(crate) file: vfs::FileRef,
    pub(crate) size: u64,
}

pub(crate) fn compute_peer_grants(
    live: bool,
    unit_image: Option<&str>,
    compat_gui_host: bool,
    peer_uid: u32,
    session_uid: u32,
    same_login_session: bool,
) -> PeerGrants {
    if !live {
        return PeerGrants::default();
    }
    if unit_image == Some("desktop-shell") && peer_uid == session_uid && same_login_session {
        return PeerGrants {
            roles: vec![
                SurfaceRole::Panel,
                SurfaceRole::Background,
                SurfaceRole::Launcher,
            ],
            allow_host_kind: true,
            allow_compat_apps: false,
        };
    }
    if unit_image == Some("greeter") && peer_uid == 0 {
        return PeerGrants {
            roles: vec![SurfaceRole::Lock, SurfaceRole::Greeter],
            allow_host_kind: true,
            allow_compat_apps: false,
        };
    }
    if compat_gui_host && peer_uid == session_uid && same_login_session {
        return PeerGrants {
            roles: Vec::new(),
            allow_host_kind: false,
            allow_compat_apps: true,
        };
    }
    PeerGrants::default()
}

pub(crate) fn validate_gui_control_request(
    is_system: bool,
    req_json: &str,
) -> Result<Value, Errno> {
    if req_json.len() > 4096 {
        return Err(Errno::E2BIG);
    }
    let val: Value = serde_json::from_str(req_json).map_err(|_| Errno::EINVAL)?;
    let op = val.get("op").and_then(Value::as_str).ok_or(Errno::EINVAL)?;
    let unit = val
        .get("unit")
        .and_then(Value::as_str)
        .ok_or(Errno::EINVAL)?;
    if !matches!(op, "start" | "stop" | "restart" | "status") {
        return Err(Errno::EPERM);
    }
    let allowed = if is_system {
        matches!(
            unit,
            "graphical.target" | "compositor.service" | "greeter.service"
        )
    } else {
        matches!(unit, "graphical.target" | "desktop-shell.service")
    };
    if !allowed {
        return Err(Errno::EPERM);
    }
    Ok(json!({ "op": op, "unit": unit }))
}

async fn host_call(func: &Function, arg: Value) -> Result<Value, JsValue> {
    let val = func.call1(&JsValue::UNDEFINED, &json_to_js(&arg)?)?;
    let resolved = if val.is_instance_of::<Promise>() {
        JsFuture::from(Promise::from(val)).await?
    } else {
        val
    };
    if resolved.is_undefined() || resolved.is_null() {
        return Ok(Value::Null);
    }
    let text: String = js_sys::JSON::stringify(&resolved)
        .map_err(|_| map_errno(Errno::EIO))?
        .into();
    serde_json::from_str(&text).map_err(|_| map_errno(Errno::EIO))
}

async fn socket_wait() -> Result<(), JsValue> {
    let p = Promise::new(&mut |resolve, _| {
        if let Ok(global) = Reflect::get(&js_sys::global(), &"setTimeout".into())
            && let Some(set_timeout) = global.dyn_ref::<Function>()
        {
            let _ = set_timeout.call2(&JsValue::UNDEFINED, &resolve, &JsValue::from(5));
        } else {
            let _ = resolve.call0(&JsValue::UNDEFINED);
        }
    });
    let _ = JsFuture::from(p).await?;
    Ok(())
}

pub(crate) struct PendingBundleRead {
    file: vfs::FileRef,
    offset: Option<u64>,
    future: futures_util::future::LocalBoxFuture<'static, Result<Value, Errno>>,
}
impl PendingBundleRead {
    fn resume(pending: Option<Self>, file: vfs::FileRef, offset: Option<u64>) -> Self {
        if let Some(read) = pending
            && read.file.ptr_eq(&file)
            && read.offset == offset
        {
            return read;
        }
        let source = file.clone();
        let future = Box::pin(async move {
            let meta = source.metadata().await?;
            if meta.file_type != FileType::File {
                return Err(Errno::EINVAL);
            }
            if meta.size > MAX_BUNDLE as u64 {
                return Err(Errno::E2BIG);
            }
            let Some(offset) = offset else {
                return Ok(json!(meta.size));
            };
            let mut bytes = vec![0; 65536.min(meta.size.saturating_sub(offset) as usize)];
            let n = source.read_at(&mut bytes, offset).await?;
            bytes.truncate(n);
            Ok(json!(abi::Bytes(bytes)))
        });
        Self {
            file,
            offset,
            future,
        }
    }
}

pub(crate) struct BrowserGuiSink {
    pinned_fds: Rc<RefCell<HashMap<u64, PinnedGuiFd>>>,
}
impl BrowserGuiSink {
    pub(crate) fn new(pinned_fds: Rc<RefCell<HashMap<u64, PinnedGuiFd>>>) -> Self {
        Self { pinned_fds }
    }
}
impl GuiHostSink for BrowserGuiSink {
    fn display(&self, cmd: DisplayCmd) {
        match &cmd {
            DisplayCmd::Unmap { surface_id } => {
                self.pinned_fds
                    .borrow_mut()
                    .retain(|_, p| p.surface_id != *surface_id);
            }
            DisplayCmd::SeatReset => {
                self.pinned_fds.borrow_mut().clear();
            }
            _ => {}
        }
        if let Ok((global, sink)) = crate::cloudfs::installed("onGuiDisplayCmd")
            && let Ok(raw) = serde_json::to_string(&cmd)
        {
            let _ = sink.call1(&global, &raw.into());
        }
    }
}
impl Kernel {
    fn gui_registry(&self) -> Rc<GuiDeviceRegistry> {
        Rc::clone(&self.vfs_rt.borrow().dev_fs.backend().registry)
    }
    pub(crate) fn check_gui_pick_delivery(
        &self,
        pid: u32,
        socket: u32,
        fd: u32,
    ) -> Result<Option<PickerRecipient>, Errno> {
        let rt = self.vfs_rt.borrow();
        let Some((_, surface, request)) = rt
            .proc_meta
            .get(&pid)
            .and_then(|m| m.gui_pick_fd)
            .filter(|(f, _, _)| *f == fd)
        else {
            return Ok(None);
        };
        let b = rt
            .dev_fs
            .backend()
            .registry
            .binding(surface)
            .map_err(|_| Errno::ECANCELED)?;
        if rt.unix_sock.borrow().peer_socket(pid, socket)? != b.endpoint {
            return Err(Errno::ECANCELED);
        }
        let recipient = {
            let session = &self.state.borrow().login_session;
            let owner = rt.proc_meta.get(&b.pid).ok_or(Errno::ECANCELED)?;
            if owner.login_session.as_deref() != Some(&session.id)
                || owner.login_generation != Some(session.generation())
            {
                return Err(Errno::ECANCELED);
            }
            PickerRecipient {
                pid: b.pid,
                endpoint: b.endpoint,
                surface,
                session: session.id.clone(),
                generation: session.generation(),
            }
        };
        drop(rt);
        let (global, validate) = crate::cloudfs::installed("onGuiPickCurrent")?;
        if validate
            .call1(&global, &(request as f64).into())
            .ok()
            .and_then(|v| v.as_bool())
            != Some(true)
        {
            return Err(Errno::ECANCELED);
        }
        Ok(Some(recipient))
    }
    pub(crate) async fn gui_ioctl(
        &self,
        vfs: &Vfs,
        pid: u32,
        fd: u32,
        request: u32,
        arg: Value,
    ) -> Result<Value, Errno> {
        let file = vfs.process_fds(pid)?.borrow().get(fd)?;
        if file
            .mount_pin()
            .is_none_or(|p| p.fstype() != vfs::FsType::DevTmpFs)
        {
            return Err(Errno::ENOTTY);
        }
        let registry = self.gui_registry();
        let dev = registry.check(pid, file.open_ref())?;
        if request == ioc::INFO {
            let versions = serde_json::from_value::<Vec<u32>>(
                arg.get("versions").cloned().unwrap_or(json!([1])),
            )
            .map_err(|_| Errno::EINVAL)?;
            let caps = serde_json::from_value::<Vec<String>>(
                arg.get("required").cloned().unwrap_or(json!([])),
            )
            .map_err(|_| Errno::EINVAL)?;
            return Ok(
                json!({"version":negotiate(&versions,&caps)?,"capabilities":CAPABILITIES,"epoch":registry.epoch()}),
            );
        }
        if dev == GuiDevice::Input && file.access().reads() {
            return match request {
                ioc::NEXT_EVENT => Ok(json!(registry.next()?)),
                ioc::POLL => Ok(json!(registry.ready())),
                _ => Err(Errno::EOPNOTSUPP),
            };
        }
        if dev != GuiDevice::Display || !file.access().writes() {
            return Err(Errno::EBADF);
        }
        match request {
            ioc::WATCH_SHELL | ioc::TAKE_SHELL => {
                let nominee: u32 = serde_json::from_value(arg).map_err(|_| Errno::EINVAL)?;
                // The named process must predate this compositor's command line. A PID
                // recycled during startup or between accept and event draining is ineligible.
                let live = self.state.borrow().table.alive_at_exec(nominee, pid);
                if request == ioc::TAKE_SHELL {
                    return Ok(json!(registry.take_shell(nominee) && live));
                }
                if live {
                    registry.watch_shell(nominee);
                }
                return Ok(json!(live));
            }
            ioc::PEER_ROLES => {
                let socket_fd: u32 = serde_json::from_value(arg).map_err(|_| Errno::EINVAL)?;
                let rt = self.vfs_rt.borrow();
                let table = rt.unix_sock.borrow();
                if table.getsockname(pid, socket_fd)? != SOCKET {
                    return Err(Errno::EACCES);
                }
                let peer = table.peer_cred(pid, socket_fd)?;
                drop(table);
                registry.track_peer(peer.pid);
                let live = self.is_proc_live(peer.pid);
                let session = &self.state.borrow().login_session;
                let grants = if let Some(meta) = rt.proc_meta.get(&peer.pid) {
                    let same_session = meta.login_session.as_deref() == Some(&session.id)
                        && meta.login_generation == Some(session.generation());
                    compute_peer_grants(
                        live,
                        meta.unit_image,
                        meta.compat_gui_host,
                        peer.uid,
                        session.uid,
                        same_session,
                    )
                } else {
                    PeerGrants::default()
                };
                return Ok(json!(grants));
            }
            ioc::DISPLAY_CMD => {
                let cmd: DisplayCmd = serde_json::from_value(arg).map_err(|_| Errno::EINVAL)?;
                registry.present(cmd)?
            }
            ioc::BIND_SURFACE => {
                let b: BindSurface = serde_json::from_value(arg).map_err(|_| Errno::EINVAL)?;
                let rt = self.vfs_rt.borrow();
                let table = rt.unix_sock.borrow();
                if table.getsockname(pid, b.socket_fd)? != SOCKET {
                    return Err(Errno::EACCES);
                }
                let peer = table.peer_cred(pid, b.socket_fd)?;
                registry.bind(b.surface_id, peer.pid, table.peer_socket(pid, b.socket_fd)?)?;
            }
            ioc::SIMULATE_LOSS => {
                let id = arg.as_u64().ok_or(Errno::EINVAL)?;
                let b = registry.binding(id)?;
                if !b.pixel {
                    return Err(Errno::EINVAL);
                }
                registry.enqueue(SeatEvent::Display(DisplayEvent::SurfaceDeviceLost {
                    surface_id: id,
                    generation: b.generation,
                    reason: "simulated".into(),
                    fallback: PixelBackend::Software2d,
                }))?;
            }
            ioc::ARM_PICK => {
                let (surface, request_id, fd): (u64, u64, u32) =
                    serde_json::from_value(arg).map_err(|_| Errno::EINVAL)?;
                let file = vfs.get_file(pid, fd)?;
                if file.access() != Access::Read {
                    return Err(Errno::EBADF);
                }
                self.vfs_rt
                    .borrow_mut()
                    .proc_meta
                    .get_mut(&pid)
                    .ok_or(Errno::ESRCH)?
                    .gui_pick_fd = Some((fd, surface, request_id));
            }
            ioc::CHECK_BUNDLE | ioc::READ_BUNDLE => {
                let (fd, offset) = if request == ioc::CHECK_BUNDLE {
                    (
                        serde_json::from_value(arg).map_err(|_| Errno::EINVAL)?,
                        None,
                    )
                } else {
                    let (fd, offset): (u32, u64) =
                        serde_json::from_value(arg).map_err(|_| Errno::EINVAL)?;
                    (fd, Some(offset))
                };
                let f = vfs.get_file(pid, fd)?;
                if f.access() != Access::Read
                    || !matches!(
                        f.mount_pin().map(|p| p.fstype()),
                        Some(vfs::FsType::Image | vfs::FsType::TmpFs | vfs::FsType::Cowfs)
                    )
                {
                    return Err(Errno::EACCES);
                }
                // Poll a single local page per client per seat tick. Even a cold image
                // page can need asynchronous I/O. Closing the fd cancels pending work.
                let pending = self
                    .vfs_rt
                    .borrow_mut()
                    .proc_meta
                    .get_mut(&pid)
                    .ok_or(Errno::ESRCH)?
                    .gui_reads
                    .remove(&fd);
                let mut read = PendingBundleRead::resume(pending, f, offset);
                use std::task::{Context, Poll, Waker};
                match read
                    .future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                {
                    Poll::Ready(result) => return result,
                    Poll::Pending => {
                        self.vfs_rt
                            .borrow_mut()
                            .proc_meta
                            .get_mut(&pid)
                            .ok_or(Errno::ESRCH)?
                            .gui_reads
                            .insert(fd, read);
                        return Err(Errno::EAGAIN);
                    }
                }
            }
            ioc::PIN_FD => {
                let (surface_id, fd, max_bytes): (u64, u32, u64) =
                    serde_json::from_value(arg).map_err(|_| Errno::EINVAL)?;
                let cap = max_bytes.min(MAX_STREAM_ASSET_RANGE);
                let binding = registry.binding(surface_id)?;
                let file = vfs.get_file(pid, fd)?;
                if !file.access().reads() {
                    return Err(Errno::EBADF);
                }
                let meta = self
                    .with_proc_scope(binding.pid, async { file.metadata().await })
                    .await?;
                if meta.file_type != FileType::File {
                    return Err(Errno::EINVAL);
                }
                if meta.size > cap {
                    return Err(Errno::E2BIG);
                }
                let current_binding = registry.binding(surface_id)?;
                if current_binding.pid != binding.pid
                    || current_binding.endpoint != binding.endpoint
                {
                    return Err(Errno::ESTALE);
                }
                let mut rt = self.vfs_rt.borrow_mut();
                let pins_rc = Rc::clone(&rt.gui_pinned_fds);
                let mut pins = pins_rc.borrow_mut();
                if pins.len() >= MAX_GUI_PINNED_FDS {
                    return Err(Errno::EMFILE);
                }
                let pin_id = rt.next_gui_pin_id;
                rt.next_gui_pin_id = rt.next_gui_pin_id.saturating_add(1).max(1);
                pins.insert(
                    pin_id,
                    PinnedGuiFd {
                        surface_id,
                        owner_pid: binding.pid,
                        file,
                        size: meta.size,
                    },
                );
                return Ok(json!({ "pin_id": pin_id, "size": meta.size }));
            }
            ioc::UNPIN_SURFACE => {
                let pin_or_surface: Value = arg;
                if let Some(pin_id) = pin_or_surface.get("pin_id").and_then(Value::as_u64) {
                    self.vfs_rt
                        .borrow()
                        .gui_pinned_fds
                        .borrow_mut()
                        .remove(&pin_id);
                } else if let Some(surface_id) =
                    pin_or_surface.get("surface_id").and_then(Value::as_u64)
                {
                    self.vfs_rt
                        .borrow()
                        .gui_pinned_fds
                        .borrow_mut()
                        .retain(|_, p| p.surface_id != surface_id);
                } else {
                    return Err(Errno::EINVAL);
                }
            }
            _ => return Err(Errno::EOPNOTSUPP),
        }
        Ok(Value::Null)
    }
}
#[wasm_bindgen]
impl Kernel {
    pub fn gui_host_event(&self, raw: &str) -> Result<(), JsValue> {
        if raw.len() > 6 * MAX_CLIPBOARD + 1024 {
            return Err(map_errno(Errno::E2BIG));
        }
        let mut input: InputEvent =
            serde_json::from_str(raw).map_err(|_| map_errno(Errno::EINVAL))?;
        match &mut input {
            InputEvent::MediaEvent {
                surface_id: Some(sid),
                payload:
                    MediaEventPayload::PresentState {
                        body_json: Some(body),
                        ..
                    },
            } => {
                if let Ok(b) = self.gui_registry().binding(*sid)
                    && self.is_verified_preview_with_cloud(b.pid)
                {
                    self.update_guest_attending_scope_from_json(b.pid, body.as_bytes());
                }
            }
            InputEvent::SessionEvent {
                surface_id: Some(sid),
                event_json,
            } => {
                if let Ok(b) = self.gui_registry().binding(*sid)
                    && self.is_verified_preview_with_cloud(b.pid)
                    && let Ok(mut parsed) = serde_json::from_str::<Value>(event_json)
                    && let Some(granted) = parsed.get_mut("granted").and_then(Value::as_object_mut)
                    && let Some(sfd) = granted.get("fd").and_then(Value::as_u64)
                    && let Ok(sfd_u32) = u32::try_from(sfd)
                {
                    let pres = granted
                        .get("presentation")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned();
                    if let Some(gfd) = self.adopt_guest_granted_fd(b.pid, pres, sfd_u32) {
                        granted.insert("fd".into(), json!(gfd));
                    } else {
                        granted.remove("fd");
                    }
                    if let Ok(rewritten) = serde_json::to_string(&parsed) {
                        *event_json = rewritten;
                    }
                }
            }
            _ => {}
        }
        self.gui_registry()
            .enqueue(SeatEvent::Input(input))
            .map_err(map_errno)
    }
    pub fn gui_display_event(&self, pid: u32, raw: &str) -> Result<(), JsValue> {
        if raw.len() > 2048 {
            return Err(map_errno(Errno::E2BIG));
        }
        let e = serde_json::from_str(raw).map_err(|_| map_errno(Errno::EINVAL))?;
        let (id, g) = match &e {
            DisplayEvent::SurfaceDeviceLost {
                surface_id,
                generation,
                ..
            }
            | DisplayEvent::SurfaceReady {
                surface_id,
                generation,
                ..
            } => (*surface_id, *generation),
        };
        let r = self.gui_registry();
        let b = r.binding(id).map_err(map_errno)?;
        if b.pid != pid || !b.pixel || g != b.generation {
            return Err(map_errno(Errno::EACCES));
        }
        r.enqueue(SeatEvent::Display(e)).map_err(map_errno)
    }
    pub fn gui_poll(&self, pid: u32, fd: u32, writing: bool) -> Result<u32, JsValue> {
        let rt = self.vfs_rt.borrow();
        let file = rt
            .vfs
            .process_fds(pid)
            .and_then(|fds| fds.borrow().get(fd))
            .map_err(map_errno)?;
        let registry = &rt.dev_fs.backend().registry;
        match (
            registry.check(pid, file.open_ref()).map_err(map_errno)?,
            writing,
        ) {
            (GuiDevice::Display, true) if file.access().writes() => Ok(1),
            (GuiDevice::Input, false) if file.access().reads() => Ok(registry.ready() as u32),
            _ => Err(map_errno(Errno::EBADF)),
        }
    }
    pub fn gui_surface_binding(&self, surface_id: u64) -> Result<String, JsValue> {
        let b = self.gui_registry().binding(surface_id).map_err(map_errno)?;
        let (proc_uid, proc_cloud) = {
            let st = self.state.borrow();
            let proc_rec = st
                .table
                .proc(b.pid)
                .filter(|p| p.state != abi::ProcState::Zombie)
                .ok_or_else(|| map_errno(Errno::ESTALE))?;
            (proc_rec.cred.identity.id, proc_rec.cred.cloud_access)
        };
        let rt = self.vfs_rt.borrow();
        let owner = rt
            .proc_meta
            .get(&b.pid)
            .ok_or_else(|| map_errno(Errno::ESTALE))?;
        let cloud_access =
            proc_cloud && owner.cloud_access && !rt.cloud_mount.is_pid_cloud_denied(b.pid);
        Ok(json!({
            "pid": b.pid,
            "endpoint": b.endpoint,
            "generation": b.generation,
            "pixel": b.pixel,
            "uid": proc_uid,
            "cloudAccess": cloud_access,
            "isMounts": owner.verified_mounts_image,
            "isPreview": owner.verified_preview_image,
            "session": owner.login_session,
            "loginGeneration": owner.login_generation,
        })
        .to_string())
    }

    /// Host-owned compat bridge process in the active login session (`compat_gui_host = true`).
    /// Granted ONLY `SurfaceKind::Host` compat app windows (`roles = []`, zero privileged roles).
    pub fn gui_compat_proxy(&self, session_id: &str) -> Result<u32, JsValue> {
        let mut state = self.state.borrow_mut();
        let mut rt = self.vfs_rt.borrow_mut();
        if state.login_session.shutdown.is_some()
            || state.login_session.id != session_id
            || rt.active_session_id.as_deref() != Some(session_id)
        {
            return Err(map_errno(Errno::EACCES));
        }
        let vfs = rt.vfs.clone();
        let sess = rt
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| map_errno(Errno::EACCES))?;
        let identity = state.account.identity();
        if sess.uid != identity.id
            || sess.gid != identity.group
            || state.login_session.uid != sess.uid
        {
            return Err(map_errno(Errno::EACCES));
        }
        let login_gen = state.login_session.generation();
        if let Some(pid) = sess.gui_compat_proxy
            && state
                .table
                .proc(pid)
                .is_some_and(|p| p.state != abi::ProcState::Zombie)
        {
            if let Some(meta) = rt.proc_meta.get_mut(&pid) {
                meta.login_generation = Some(login_gen);
            }
            return Ok(pid);
        }
        let mut spec = kernel::proc_table::SpawnSpec::new(
            "gui-compat",
            kernel::proc_table::LocalCred {
                identity: identity.clone(),
                umask: 0o022,
                remote: None,
                cloud_access: false,
                allowed_remote_scope: None,
            },
            "gui-compat",
        );
        spec.login_scope = Some(session_id.into());
        spec.initial_state = abi::ProcState::Running;
        let pid = state
            .table
            .spawn(spec, crate::now_secs())
            .map_err(|e| map_errno(e.errno))?
            .pid;
        let cred = vfs::Cred::new(identity);
        if let Err(e) = vfs.spawn_process(
            pid,
            crate::INIT,
            cred.clone(),
            Some(sess.mnt_ns.clone()),
            None,
            None,
        ) {
            let _ = state
                .table
                .exit("gui-compat", pid, 1, None, crate::now_secs());
            return Err(map_errno(e));
        }
        sess.gui_compat_proxy = Some(pid);
        let mut meta =
            crate::vfs_engine::ProcessVfsMeta::with_cred(Some(session_id.into()), false, cred);
        meta.login_generation = Some(login_gen);
        meta.compat_gui_host = true;
        rt.proc_meta.insert(pid, meta);
        Ok(pid)
    }

    /// Whitelisted graphical unit control RPC against PID 1 (`/run/init/control.sock`) or
    /// the per-user manager (`/run/user/<uid>/manager.sock`).
    pub async fn gui_service_control_rpc(
        &self,
        is_system: bool,
        session_id: String,
        req_json: String,
        socket_op: Function,
    ) -> Result<JsValue, JsValue> {
        let req_val = validate_gui_control_request(is_system, &req_json).map_err(map_errno)?;
        let (caller_pid, socket_path, expected_uid) = if is_system {
            (crate::INIT, "/run/init/control.sock".to_owned(), 0u32)
        } else {
            let proxy = self.gui_compat_proxy(&session_id)?;
            let uid = self.state.borrow().login_session.uid;
            (proxy, format!("/run/user/{uid}/manager.sock"), uid)
        };
        let mut frame_bytes = serde_json::to_vec(&req_val).map_err(|_| map_errno(Errno::EINVAL))?;
        frame_bytes.push(b'\n');

        let call = |args: Value| host_call(&socket_op, json!({"pid": caller_pid, "args": args}));
        let created = call(json!({"op":"create", "sockType": SOCK_STREAM})).await?;
        let sock_id = created["sockId"]
            .as_u64()
            .ok_or_else(|| map_errno(Errno::EIO))?;

        let result = async {
            let deadline = crate::now_ms() + 10_000;
            let connection = loop {
                if crate::now_ms() >= deadline {
                    return Err(map_errno(Errno::ETIMEDOUT));
                }
                match call(json!({"op":"connect", "sockId": sock_id, "path": socket_path})).await {
                    Ok(c) => break c,
                    Err(e)
                        if matches!(
                            Reflect::get(&e, &"errno".into())
                                .ok()
                                .and_then(|s| s.as_string())
                                .as_deref(),
                            Some("ENOENT" | "ECONNREFUSED")
                        ) =>
                    {
                        socket_wait().await?;
                    }
                    Err(e) => return Err(e),
                }
            };
            let server: PeerCred = serde_json::from_value(connection["peerCred"].clone())
                .map_err(|_| map_errno(Errno::EACCES))?;
            let valid_server = if is_system {
                server.pid == crate::INIT && server.uid == 0
            } else {
                self.is_service_image(server.pid, "init") && server.uid == expected_uid
            };
            if !valid_server {
                return Err(map_errno(Errno::EACCES));
            }
            let mut sent = 0usize;
            while sent < frame_bytes.len() {
                if crate::now_ms() >= deadline {
                    return Err(map_errno(Errno::ETIMEDOUT));
                }
                let chunk = &frame_bytes[sent..frame_bytes.len().min(sent + 4096)];
                match call(json!({"op":"sendmsg", "sockId": sock_id, "fds": [], "data": Bytes(chunk.to_vec())})).await {
                    Err(e)
                        if Reflect::get(&e, &"errno".into())
                            .ok()
                            .and_then(|s| s.as_string())
                            .as_deref()
                            == Some("EAGAIN") =>
                    {
                        socket_wait().await?;
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
            let mut response = Vec::new();
            loop {
                if crate::now_ms() >= deadline {
                    return Err(map_errno(Errno::ETIMEDOUT));
                }
                let r = call(json!({"op":"recvmsg", "sockId": sock_id, "sabStream": true, "bufLen": 4096, "maxFds": 0})).await?;
                if r["wouldBlock"] == true {
                    socket_wait().await?;
                    continue;
                }
                let bytes: Bytes = serde_json::from_value(r["data"].clone())
                    .map_err(|_| map_errno(Errno::EIO))?;
                if bytes.is_empty() {
                    return Err(map_errno(Errno::ECONNRESET));
                }
                if response.len() + bytes.len() > MAX_CONTROL_REPLY_BYTES {
                    return Err(map_errno(Errno::E2BIG));
                }
                response.extend_from_slice(&bytes);
                if response.ends_with(b"\n") {
                    let parsed: Value = serde_json::from_slice(&response)
                        .map_err(|_| map_errno(Errno::EIO))?;
                    return json_to_js(&parsed);
                }
            }
        }
        .await;
        let _ = call(json!({"op":"close", "sockId": sock_id})).await;
        result
    }

    /// Capability-verify whether `owner_pid` (bound to `surface_id`) is authorized to perform a
    /// resumable cloud upload (`/api/pwrite`) into `dest` inside its own mount namespace and
    /// credentials. Returns `Ok(true)` ONLY when the surface binding, active login session,
    /// cloud access capability, `FsType::Cloud` mount check, and `W_OK | X_OK` permission check
    /// all pass.
    pub async fn gui_verify_cloud_upload(
        &self,
        surface_id: u64,
        owner_pid: u32,
        dest: String,
    ) -> Result<bool, JsValue> {
        if dest.is_empty()
            || !dest.starts_with('/')
            || dest.contains('\0')
            || dest.len() > abi::PATH_MAX
        {
            return Ok(false);
        }
        let check_preconditions = || -> Result<(Vfs, (u32, u32, u64)), ()> {
            let binding = self.gui_registry().binding(surface_id).map_err(|_| ())?;
            if binding.pid != owner_pid || !self.is_proc_live(owner_pid) {
                return Err(());
            }
            let st = self.state.borrow();
            if st.login_session.shutdown.is_some() {
                return Err(());
            }
            let proc_rec = st
                .table
                .proc(owner_pid)
                .filter(|p| p.state != abi::ProcState::Zombie)
                .ok_or(())?;
            if !proc_rec.cred.cloud_access {
                return Err(());
            }
            let cs = st.cloud_session.as_ref().ok_or(())?;
            if cs.revoked
                || cs.local_uid != st.account.uid
                || cs.login_generation != st.account_epoch
            {
                return Err(());
            }
            let expected_binding = (cs.cloud_uid, cs.local_uid, cs.login_generation);
            let session_id = st.login_session.id.clone();
            let session_gen = st.login_session.generation();
            drop(st);

            let rt = self.vfs_rt.borrow();
            if rt.cloud_mount.is_pid_cloud_denied(owner_pid) {
                return Err(());
            }
            let meta = rt.proc_meta.get(&owner_pid).ok_or(())?;
            if !meta.cloud_access
                || meta.login_session.as_deref() != Some(session_id.as_str())
                || meta.login_generation != Some(session_gen)
            {
                return Err(());
            }
            Ok((rt.vfs.clone(), expected_binding))
        };

        let Ok((vfs, expected_binding)) = check_preconditions() else {
            return Ok(false);
        };

        let opened = self
            .with_proc_scope(owner_pid, {
                let vfs = vfs.clone();
                let dest = dest.clone();
                async move {
                    vfs.open_file(
                        owner_pid,
                        vfs::StartAnchor::Root,
                        &dest,
                        abi::O_PATH | abi::O_DIRECTORY,
                        0,
                    )
                    .await
                }
            })
            .await;
        let Ok((file_ref, _)) = opened else {
            return Ok(false);
        };
        let is_writable_cloud = file_ref
            .mount_pin()
            .is_some_and(|p| p.fstype() == vfs::FsType::Cloud && !p.effective_rdonly());
        let _ = file_ref.close().await;
        if !is_writable_cloud {
            return Ok(false);
        }

        // Re-verify process liveness and cloud session binding across the await.
        // Remote POSIX DAC & ACL checks on the cloud directory are enforced authoritatively
        // by `OsAuthority` under the bound cloud session identity (`cs.cloud_uid`), which may
        // legitimately differ from `owner_pid`'s local UID (e.g. local `user` signed into cloud `root`).
        match check_preconditions() {
            Ok((_, current_binding)) => Ok(current_binding == expected_binding),
            Err(()) => Ok(false),
        }
    }

    /// Encode a framed GUI v1 `ClientReq` for the compat bridge proxy.
    pub fn gui_encode_frame(&self, req_json: &str) -> Result<Vec<u8>, JsValue> {
        if req_json.len() > MAX_COMPAT_FRAME_BYTES {
            return Err(map_errno(Errno::E2BIG));
        }
        let req: ClientReq =
            serde_json::from_str(req_json).map_err(|_| map_errno(Errno::EINVAL))?;
        frame(&req).map_err(map_errno)
    }

    /// Decode the next framed GUI v1 `ClientEvent` from buffered bytes.
    /// Returns `{ event, consumed }` or `null` if incomplete.
    pub fn gui_decode_frame(&self, bytes: &[u8]) -> Result<JsValue, JsValue> {
        if bytes.len() < 4 {
            return Ok(JsValue::NULL);
        }
        let len = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
        if len > MAX_FRAME {
            return Err(map_errno(Errno::E2BIG));
        }
        if bytes.len() < 4 + len {
            return Ok(JsValue::NULL);
        }
        let event: ClientEvent =
            serde_json::from_slice(&bytes[4..4 + len]).map_err(|_| map_errno(Errno::EINVAL))?;
        json_to_js(&json!({ "event": event, "consumed": 4 + len }))
    }

    /// Read a bounded slice (`<= 1 MiB`) from a kernel-pinned GUI surface file handle (`pin_id`).
    /// Verifies that the owning surface is still bound to the original `owner_pid` (zero TOCTOU).
    pub async fn gui_read_pinned(
        &self,
        pin_id: u64,
        offset: u64,
        length: u32,
    ) -> Result<Vec<u8>, JsValue> {
        let want = (length as usize).min(MAX_GUI_PIN_READ_CHUNK);
        let (file, surface_id, owner_pid, size) = {
            let rt = self.vfs_rt.borrow();
            let pins = rt.gui_pinned_fds.borrow();
            let pinned = pins.get(&pin_id).ok_or_else(|| map_errno(Errno::ENOENT))?;
            (
                pinned.file.clone(),
                pinned.surface_id,
                pinned.owner_pid,
                pinned.size,
            )
        };
        let binding = match self.gui_registry().binding(surface_id) {
            Ok(b) => b,
            Err(e) => {
                self.vfs_rt
                    .borrow()
                    .gui_pinned_fds
                    .borrow_mut()
                    .remove(&pin_id);
                return Err(map_errno(e));
            }
        };
        if binding.pid != owner_pid {
            self.vfs_rt
                .borrow()
                .gui_pinned_fds
                .borrow_mut()
                .remove(&pin_id);
            return Err(map_errno(Errno::ESTALE));
        }
        if offset >= size || want == 0 {
            return Ok(Vec::new());
        }
        let to_read = (size - offset).min(want as u64) as usize;
        let mut buf = vec![0u8; to_read];
        let n = self
            .with_proc_scope(owner_pid, async { file.read_at(&mut buf, offset).await })
            .await
            .map_err(map_errno)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Release a single kernel-pinned GUI file handle.
    pub fn gui_release_pinned(&self, pin_id: u64) {
        self.vfs_rt
            .borrow()
            .gui_pinned_fds
            .borrow_mut()
            .remove(&pin_id);
    }

    /// Release all kernel-pinned GUI file handles owned by `surface_id` (or all if `surface_id == 0`).
    pub fn gui_release_surface_pins(&self, surface_id: u64) {
        let rt = self.vfs_rt.borrow();
        let mut pins = rt.gui_pinned_fds.borrow_mut();
        if surface_id == 0 {
            pins.clear();
        } else {
            pins.retain(|_, p| p.surface_id != surface_id);
        }
    }

    /// Clear any signed-out guest attending scope/cache held for `pid` (e.g. when unfollowing or unmapping).
    pub fn gui_clear_guest_attending(&self, pid: u32) {
        if let Some(meta) = self.vfs_rt.borrow_mut().proc_meta.get_mut(&pid) {
            meta.guest_attending_scope = None;
            meta.guest_attending_cache = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vfs::{
        Cred, FdTable, FileRef, Filesystem, FsId, OpenOptions, ReleaseQueue, memfs::MemFs,
        now_or_never,
    };

    #[test]
    fn pending_bundle_read_cannot_resume_after_fd_reuse() {
        let fs = Rc::new(MemFs::new(
            FsId("bundle".into()),
            1,
            0,
            0,
            0o755,
            Box::new(|| (0, 0)),
        ));
        let releases = ReleaseQueue::new();
        let create = |name, bytes: &[u8]| {
            let cred = Cred::root();
            let opts = *OpenOptions::new().read(true).write(true).create_new(true);
            let (entry, open) = now_or_never(fs.create(&cred, &fs.root(), name, 0o600, &opts))
                .unwrap()
                .unwrap();
            let file = FileRef::new(fs.clone(), open, entry.handle, cred, &opts, &releases);
            now_or_never(file.write(bytes)).unwrap().unwrap();
            file
        };
        let mut fds = FdTable::new();
        let fd = fds.insert(create("old", b"old"), false).unwrap();
        let pending = PendingBundleRead {
            file: fds.get(fd).unwrap(),
            offset: Some(0),
            future: Box::pin(std::future::pending()),
        };
        now_or_never(fds.close(fd)).unwrap().unwrap();
        assert_eq!(fds.insert(create("new", b"new"), false).unwrap(), fd);
        let read = PendingBundleRead::resume(Some(pending), fds.get(fd).unwrap(), Some(0));
        assert_eq!(
            now_or_never(read.future).unwrap().unwrap(),
            json!(abi::Bytes(b"new".to_vec()))
        );
    }

    #[test]
    fn peer_roles_grants_follow_kernel_privilege_matrix() {
        // desktop-shell.service (matching user + login session) -> Panel/Background/Launcher + host kind
        let shell = compute_peer_grants(true, Some("desktop-shell"), false, 1000, 1000, true);
        assert_eq!(
            shell.roles,
            vec![
                SurfaceRole::Panel,
                SurfaceRole::Background,
                SurfaceRole::Launcher
            ]
        );
        assert!(shell.allow_host_kind);
        assert!(!shell.allow_compat_apps);

        // Manually executed /usr/bin/desktop-shell (unit_image = None) -> ZERO grants
        let manual = compute_peer_grants(true, None, false, 1000, 1000, true);
        assert_eq!(manual, PeerGrants::default());

        // desktop-shell from wrong session -> ZERO grants
        let wrong_sess = compute_peer_grants(true, Some("desktop-shell"), false, 1000, 1000, false);
        assert_eq!(wrong_sess, PeerGrants::default());

        // greeter.service as root -> Lock/Greeter + host kind
        let greeter = compute_peer_grants(true, Some("greeter"), false, 0, 1000, false);
        assert_eq!(greeter.roles, vec![SurfaceRole::Lock, SurfaceRole::Greeter]);
        assert!(greeter.allow_host_kind);
        assert!(!greeter.allow_compat_apps);

        // greeter as non-root -> ZERO grants
        let bad_greeter = compute_peer_grants(true, Some("greeter"), false, 1000, 1000, true);
        assert_eq!(bad_greeter, PeerGrants::default());

        // Compat bridge proxy -> Window compat apps ONLY, NO privileged roles!
        let compat = compute_peer_grants(true, None, true, 1000, 1000, true);
        assert!(compat.roles.is_empty());
        assert!(!compat.allow_host_kind);
        assert!(compat.allow_compat_apps);

        // Exited process -> ZERO grants
        let dead = compute_peer_grants(false, Some("desktop-shell"), true, 1000, 1000, true);
        assert_eq!(dead, PeerGrants::default());
    }

    #[test]
    fn gui_service_control_rpc_whitelists_only_graphical_units() {
        assert!(
            validate_gui_control_request(true, r#"{"op":"start","unit":"graphical.target"}"#)
                .is_ok()
        );
        assert!(
            validate_gui_control_request(true, r#"{"op":"restart","unit":"compositor.service"}"#)
                .is_ok()
        );
        assert!(
            validate_gui_control_request(true, r#"{"op":"start","unit":"greeter.service"}"#)
                .is_ok()
        );
        assert_eq!(
            validate_gui_control_request(true, r#"{"op":"poweroff","unit":"graphical.target"}"#),
            Err(Errno::EPERM)
        );
        assert_eq!(
            validate_gui_control_request(true, r#"{"op":"stop","unit":"mountd.service"}"#),
            Err(Errno::EPERM)
        );
        assert!(
            validate_gui_control_request(false, r#"{"op":"start","unit":"graphical.target"}"#)
                .is_ok()
        );
        assert!(
            validate_gui_control_request(
                false,
                r#"{"op":"status","unit":"desktop-shell.service"}"#
            )
            .is_ok()
        );
        assert_eq!(
            validate_gui_control_request(false, r#"{"op":"start","unit":"compositor.service"}"#),
            Err(Errno::EPERM)
        );
    }
}

//! Host-side seat transport. Surface bindings derive both ends from the accepted
//! socket. Public surface numbers alone grant no access to a process Worker.
use crate::{Kernel, vfs_engine::map_errno};
use abi::{Errno, gui::*, gui_ioctl as ioc};
use serde_json::{Value, json};
use std::rc::Rc;
use vfs::{
    Access, FileType, Vfs,
    guidev::{GuiDevice, GuiDeviceRegistry},
};
use wasm_bindgen::prelude::*;

pub(crate) struct BrowserGuiSink;
impl GuiHostSink for BrowserGuiSink {
    fn display(&self, cmd: DisplayCmd) {
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
    ) -> Result<(), Errno> {
        let rt = self.vfs_rt.borrow();
        let Some((_, surface, request)) = rt
            .proc_meta
            .get(&pid)
            .and_then(|m| m.gui_pick_fd)
            .filter(|(f, _, _)| *f == fd)
        else {
            return Ok(());
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
        let session = &self.state.borrow().login_session;
        let owner = rt.proc_meta.get(&b.pid).ok_or(Errno::ECANCELED)?;
        if owner.login_session.as_deref() != Some(&session.id)
            || owner.login_generation != Some(session.generation())
        {
            return Err(Errno::ECANCELED);
        }
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
        Ok(())
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
            ioc::DISPLAY_CMD => {
                registry.present(serde_json::from_value(arg).map_err(|_| Errno::EINVAL)?)?
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
                let mut read = pending.unwrap_or_else(|| {
                    Box::pin(async move {
                        let meta = f.metadata().await?;
                        if meta.file_type != FileType::File {
                            return Err(Errno::EINVAL);
                        }
                        if meta.size > MAX_BUNDLE as u64 {
                            return Err(Errno::E2BIG);
                        }
                        let Some(offset) = offset else {
                            return Ok(json!(meta.size));
                        };
                        let mut bytes =
                            vec![0; 16384.min(meta.size.saturating_sub(offset) as usize)];
                        let n = f.read_at(&mut bytes, offset).await?;
                        bytes.truncate(n);
                        Ok(json!(abi::Bytes(bytes)))
                    })
                });
                use std::task::{Context, Poll, Waker};
                match read.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
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
        let input = serde_json::from_str(raw).map_err(|_| map_errno(Errno::EINVAL))?;
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
        let rt = self.vfs_rt.borrow();
        let owner = rt
            .proc_meta
            .get(&b.pid)
            .ok_or_else(|| map_errno(Errno::ESTALE))?;
        Ok(
            json!({"pid":b.pid,"endpoint":b.endpoint,"generation":b.generation,"pixel":b.pixel,
                "session":owner.login_session,"loginGeneration":owner.login_generation})
            .to_string(),
        )
    }
}

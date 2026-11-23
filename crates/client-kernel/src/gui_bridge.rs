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
            ioc::CHECK_BUNDLE => {
                let fd = serde_json::from_value(arg).map_err(|_| Errno::EINVAL)?;
                let f = vfs.process_fds(pid)?.borrow().get(fd)?;
                if f.access() != Access::Read {
                    return Err(Errno::EACCES);
                }
                let meta = f.metadata().await?;
                if meta.file_type != FileType::File {
                    return Err(Errno::EINVAL);
                }
                if meta.size > MAX_BUNDLE as u64 {
                    return Err(Errno::E2BIG);
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
        if raw.len() > 8192 {
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
            (GuiDevice::Display, true) => Ok(1),
            (GuiDevice::Input, false) => Ok(registry.ready() as u32),
            _ => Err(map_errno(Errno::EBADF)),
        }
    }
    pub fn gui_surface_binding(&self, surface_id: u64) -> Result<String, JsValue> {
        let b = self.gui_registry().binding(surface_id).map_err(map_errno)?;
        Ok(
            json!({"pid":b.pid,"endpoint":b.endpoint,"generation":b.generation,"pixel":b.pixel})
                .to_string(),
        )
    }
}

//! Browser transport and timer lifetime for an explicitly attached volume.
use abi::{
    Errno,
    remote_volume::{RO_PIN_TTL_SECS, WRITER_RENEW_INTERVAL_SECS},
};
use cowfs::{
    CowFs, CowFsConfig, CowFsOpenMode, RemoteHttpReply, RemoteVolumeStore, RemoteVolumeTransport,
};
use cowtree::{VolumeId, WriterMode};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};
use vfs::{
    BoxFuture, Cred, Filesystem, MountBacking, MountedFs,
    vblk::{CowfsMountOptions, VblkRegistry},
};
use wasm_bindgen::{JsCast, prelude::*};

pub(crate) type BrowserDevFs = vfs::devfs::DevTmpFs<
    vfs::guidev::GuiDeviceBackend<
        vfs::loopdev::LoopDeviceBackend<
            vfs::vblk::VblkDeviceBackend<crate::vfs_engine::JsDeviceBackend>,
        >,
    >,
>;
type Store = RemoteVolumeStore<BrowserVolumeTransport>;
pub(crate) type Mount = CowFs<Store, Store>;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(catch,js_namespace=self,js_name=remoteVolumeFetch)]
    async fn fetch_volume(
        method: &str,
        path: &str,
        headers: &JsValue,
        body: &js_sys::Uint8Array,
    ) -> std::result::Result<JsValue, JsValue>;
    #[wasm_bindgen(js_namespace=performance,js_name=now)]
    fn monotonic_ms() -> f64;
    #[wasm_bindgen(catch,js_namespace=self,js_name=setInterval)]
    fn interval(cb: &js_sys::Function, ms: u32) -> std::result::Result<i32, JsValue>;
    #[wasm_bindgen(js_namespace=self,js_name=clearInterval)]
    fn clear_interval(id: i32);
    #[wasm_bindgen(js_namespace=console)]
    fn warn(msg: &str);
}
pub(crate) struct BrowserVolumeTransport {
    token: String,
    instance: String,
    state: Rc<RefCell<crate::State>>,
}
impl BrowserVolumeTransport {
    /// The mount outlives the process that called mount(2). Give it an attenuated
    /// credential with its own renewal and revocation lifetime.
    async fn derive(
        state: Rc<RefCell<crate::State>>,
        pid: Option<u32>,
        cred: &Cred,
        volume: &str,
        ro: bool,
    ) -> vfs::Result<Self> {
        use abi::auth_v2::{DeriveServiceCred, RemoteScope, Request, Response};
        let parent_token = match &cred.token {
            Some(token) => token.clone(),
            None => {
                crate::mint_for_service(&state, pid.ok_or(Errno::EACCES)?, true)
                    .await
                    .map_err(|e| e.errno)?
                    .token
            }
        };
        let generation = state.borrow().account_epoch;
        let (instance_id, host_proof) = crate::ensure_remote_attached_state(&state)
            .await
            .map_err(|e| e.errno)?;
        let cgroup = pid.and_then(|pid| state.borrow().table.proc(pid).map(|p| p.cgroup.clone()));
        let request = Request::DeriveServiceCred(DeriveServiceCred {
            instance_id: instance_id.clone(),
            host_proof,
            parent_token,
            scope: RemoteScope {
                volumes: true,
                volumes_ro: ro,
                ..Default::default()
            },
            cloud_access: false,
            cgroup,
            umask: None,
            revoke_parent: false,
            rbps: None,
            wbps: None,
        });
        let Response::Cred(issued) = crate::service_auth_request(&request)
            .await
            .map_err(|e| e.errno)?
        else {
            return Err(Errno::EIO);
        };
        let valid = {
            let s = state.borrow();
            s.remote_attached
                && s.account_epoch == generation
                && !s.pending_detach
                && s.cloud_session
                    .as_ref()
                    .is_some_and(|cs| !cs.revoked && cs.cloud_uid == issued.uid)
                && issued.scope.allows_volume(volume, !ro)
        };
        if !valid {
            crate::revoke_remote_tokens_state(&state, vec![issued.token]).await;
            return Err(Errno::EACCES);
        }
        state
            .borrow_mut()
            .volume_tokens
            .insert(issued.token.clone());
        Ok(Self {
            token: issued.token,
            instance: instance_id,
            state,
        })
    }
}
impl Drop for BrowserVolumeTransport {
    fn drop(&mut self) {
        if self.state.borrow_mut().volume_tokens.remove(&self.token) {
            let state = self.state.clone();
            let token = self.token.clone();
            wasm_bindgen_futures::spawn_local(async move {
                crate::revoke_remote_tokens_state(&state, vec![token]).await;
            });
        }
    }
}
impl RemoteVolumeTransport for BrowserVolumeTransport {
    fn keep_alive(
        &self,
        secs: u64,
        renew: cowfs::remote::Renewal,
    ) -> vfs::Result<Box<dyn cowfs::remote::RenewalGuard>> {
        Ok(Box::new(RemoteLeaseGuard::timer(secs, renew)?))
    }
    fn cleanup(&self, cleanup: BoxFuture<'static, ()>) {
        wasm_bindgen_futures::spawn_local(async move {
            let _ = cleanup.await;
        });
    }
    fn monotonic_seconds(&self) -> u64 {
        (monotonic_ms() / 1000.0) as u64
    }
    fn fetch<'a>(
        &'a self,
        method: &'a str,
        path: &'a str,
        headers: &'a [(String, String)],
        body: &'a [u8],
    ) -> BoxFuture<'a, RemoteHttpReply> {
        Box::pin(async move {
            if !self.state.borrow().volume_tokens.contains(&self.token) {
                return Err(Errno::EACCES);
            }
            let fields = js_sys::Object::new();
            for (k, v) in headers
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .chain([
                    ("X-OS-Instance", self.instance.as_str()),
                    ("X-Process-Token", self.token.as_str()),
                ])
            {
                js_sys::Reflect::set(&fields, &k.into(), &v.into()).map_err(|_| Errno::EINVAL)?;
            }
            let r = fetch_volume(method, path, &fields, &js_sys::Uint8Array::from(body))
                .await
                .map_err(|_| Errno::ENOTCONN)?;
            let get = |key: &str| js_sys::Reflect::get(&r, &key.into()).map_err(|_| Errno::EIO);
            Ok(RemoteHttpReply {
                status: get("status")?.as_f64().ok_or(Errno::EIO)? as u16,
                content_length: get("length")?.as_f64().map(|n| n as u64),
                body: get("body")?
                    .dyn_into::<js_sys::Uint8Array>()
                    .map_err(|_| Errno::EIO)?
                    .to_vec(),
            })
        })
    }
}
struct RemoteLeaseGuard {
    id: i32,
    _callback: Closure<dyn FnMut()>,
}
impl RemoteLeaseGuard {
    fn start(fs: &Rc<Mount>) -> vfs::Result<Self> {
        let ro = fs.is_read_only();
        let weak = Rc::downgrade(fs);
        let secs = if ro {
            RO_PIN_TTL_SECS / 3
        } else {
            WRITER_RENEW_INTERVAL_SECS
        };
        Self::timer(
            secs,
            Rc::new(move || {
                let fs = weak.upgrade();
                Box::pin(async move {
                    let Some(fs) = fs else { return Ok(()) };
                    if ro {
                        fs.renew_ro_pin().await
                    } else {
                        fs.renew_lease().await
                    }
                })
            }),
        )
    }
    fn timer(secs: u64, renew: cowfs::remote::Renewal) -> vfs::Result<Self> {
        let running = Rc::new(Cell::new(false));
        let cb = Closure::new(move || {
            if running.replace(true) {
                return;
            }
            let running = running.clone();
            let renewal = renew();
            wasm_bindgen_futures::spawn_local(async move {
                if let Err(e) = renewal.await
                    && e != Errno::EBADF
                {
                    warn(&format!("Remote volume lease renewal: {e:?}"));
                }
                running.set(false);
            });
        });
        Ok(Self {
            id: interval(cb.as_ref().unchecked_ref(), (secs * 1000) as u32)
                .map_err(|_| Errno::EIO)?,
            _callback: cb,
        })
    }
}
impl cowfs::remote::RenewalGuard for RemoteLeaseGuard {}
trait DurableMount {
    fn close(&self) -> BoxFuture<'_, ()>;
}

struct RemoteMount {
    fs: Rc<Mount>,
    _dirty: crate::cowfs_bridge::DirtyFlushGuard,
}
impl DurableMount for RemoteMount {
    fn close(&self) -> BoxFuture<'_, ()> {
        Box::pin(self.fs.close_clean())
    }
}

pub(crate) struct TrackedMount {
    mount: Rc<dyn DurableMount>,
    closing: bool,
    renewal: Option<RemoteLeaseGuard>,
}

pub(crate) async fn close_mounts(
    ctx: &Rc<RefCell<crate::vfs_engine::CowfsMountContext>>,
    all: bool,
) -> vfs::Result<()> {
    let mounts: Vec<_> = ctx
        .borrow()
        .remote_mounts
        .iter()
        .filter(|(_, t)| all || t.closing)
        .map(|(id, t)| (*id, t.mount.clone()))
        .collect();
    let mut result = Ok(());
    for (id, mount) in mounts {
        match mount.close().await {
            Ok(()) => {
                ctx.borrow_mut().remote_mounts.remove(&id);
            }
            Err(e) => {
                result = Err(e);
            }
        }
    }
    result
}

pub(crate) async fn close_for_shutdown<T>(
    ctx: &Rc<RefCell<crate::vfs_engine::CowfsMountContext>>,
    flush_root: impl AsyncFnOnce(bool) -> vfs::Result<T>,
) -> vfs::Result<T> {
    let mut mounts = close_mounts(ctx, true).await;
    let secondary = {
        let ctx = ctx.borrow();
        ctx.pending_close
            .iter()
            .cloned()
            .chain(ctx.mounted_secondary.values().map(|t| t.fs.clone()))
            .collect::<Vec<_>>()
    };
    for fs in secondary {
        mounts = mounts.and(fs.close_clean().await);
    }
    {
        let mut ctx = ctx.borrow_mut();
        ctx.pending_close.retain(|fs| !fs.is_closed());
        ctx.mounted_secondary.retain(|_, t| !t.fs.is_closed());
        ctx.active_volumes.retain(|_, fs| !fs.is_closed());
    }
    let closed = flush_root(mounts.is_ok()).await?;
    mounts.map(|()| closed)
}

impl Drop for RemoteLeaseGuard {
    fn drop(&mut self) {
        clear_interval(self.id);
    }
}

pub(crate) async fn format_remote_cowfs(
    state: Rc<RefCell<crate::State>>,
    pid: u32,
    cred: &Cred,
    id: &str,
    mut req: abi::volume::CowfsMkfsReq,
) -> vfs::Result<abi::volume::CowfsInfoResp> {
    use abi::contract::{Durability, WriterModel};
    use vfs::vblk::VolumeDevice;
    if !abi::auth_v2::valid_id(id) {
        return Err(Errno::EINVAL);
    }
    let transport = BrowserVolumeTransport::derive(state, Some(pid), cred, id, false).await?;
    let volume = VolumeId(id.to_owned());
    let store = Rc::new(Store::new(volume.clone(), transport));
    let device = cowfs::CowFsVolumeDevice::unmounted(
        volume,
        store.clone(),
        store,
        WriterModel::Fenced,
        Durability::FencedCommit,
        Rc::new(crate::cowfs_bridge::now_timespec),
    );
    req.volume = Some(id.to_owned());
    device.cowfs_mkfs(&req).await
}
pub(crate) async fn mount_remote_cowfs(
    (source, pinned): (&str, Option<cowtree::VolumeHead>),
    opts: &CowfsMountOptions,
    ro: bool,
    caller: (Rc<RefCell<crate::State>>, Option<u32>, Cred),
    vblk: Rc<VblkRegistry>,
    devfs: Rc<BrowserDevFs>,
    mounts: Rc<RefCell<crate::vfs_engine::CowfsMountContext>>,
) -> vfs::Result<MountedFs> {
    let src = source.strip_prefix("remote:").unwrap_or(source);
    let (volume, snapshot) = if let Some(id) = src.strip_prefix("volume:") {
        (id, None)
    } else if let Some(s) = src.strip_prefix("snapshot:") {
        let (v, n) = s.split_once('@').ok_or(Errno::EINVAL)?;
        (v, Some(n))
    } else {
        return Err(Errno::ENOTBLK);
    };
    if !abi::auth_v2::valid_id(volume) || snapshot.is_some_and(|s| !abi::auth_v2::valid_id(s)) {
        return Err(Errno::EINVAL);
    }
    if opts.takeover && (ro || snapshot.is_some() || opts.excl) {
        return Err(Errno::EINVAL);
    }
    let (state, pid, cred) = caller;
    let transport =
        BrowserVolumeTransport::derive(state, pid, &cred, volume, ro || snapshot.is_some()).await?;
    let volume = VolumeId(volume.into());
    let store = Rc::new(Store::new(volume.clone(), transport));
    let mode = if let Some(head) = pinned {
        CowFsOpenMode::Pinned {
            head,
            snapshot: snapshot.map(str::to_owned),
        }
    } else if let Some(s) = snapshot {
        CowFsOpenMode::Snapshot(s.into())
    } else if ro {
        CowFsOpenMode::ReadOnly
    } else {
        CowFsOpenMode::ReadWrite(if opts.takeover {
            WriterMode::ForceTakeover
        } else {
            WriterMode::Exclusive
        })
    };
    let cfg =
        CowFsConfig::remote(Rc::new(crate::cowfs_bridge::now_timespec)).with_subvol(&opts.subvol);
    let (cfg, binder) = crate::cowfs_bridge::bind_dirty_flush_timer(cfg);
    let fs = Rc::new(CowFs::open(store.clone(), store, volume, mode, cfg).await?);
    let lease = match RemoteLeaseGuard::start(&fs) {
        Ok(g) => g,
        Err(e) => {
            let _ = fs.close_clean().await;
            return Err(e);
        }
    };
    let dirty = binder.attach(&fs);
    let device: Rc<dyn vfs::vblk::VolumeDevice> =
        Rc::new(cowfs::CowFsVolumeDevice::from_mounted(fs.clone()));
    let name = vblk.attach(device.clone());
    if let Err(e) = vblk.register_node(&devfs, &name, 0o660) {
        let _ = vblk.detach(&name);
        let _ = fs.close_clean().await;
        return Err(e);
    }
    let tag = vblk.registered_rdev(&name)?;
    let root = fs.root();
    let id = Rc::as_ptr(&fs) as usize;
    mounts.borrow_mut().remote_mounts.insert(
        id,
        TrackedMount {
            mount: Rc::new(RemoteMount {
                fs: fs.clone(),
                _dirty: dirty,
            }),
            closing: false,
            renewal: Some(lease),
        },
    );
    let backing = MountBacking::new(fs.clone(), vfs::FsType::Cowfs)
        .with_ceilings(fs.is_read_only(), false)
        .with_volume_device(device)
        .with_on_release(move || {
            if vblk.device_for_rdev(&tag).is_ok() {
                let _ = vfs::now_or_never(devfs.unlink(&Cred::root(), &devfs.root(), &name));
                let _ = vblk.detach(&name);
            }
            if let Some(track) = mounts.borrow_mut().remote_mounts.get_mut(&id) {
                track.closing = true;
                track.renewal.take();
            }
            wasm_bindgen_futures::spawn_local(async move {
                let mut delay = 1000;
                loop {
                    let mount = mounts
                        .borrow()
                        .remote_mounts
                        .get(&id)
                        .map(|t| t.mount.clone());
                    let Some(mount) = mount else { break };
                    match mount.close().await {
                        Ok(()) => {
                            mounts.borrow_mut().remote_mounts.remove(&id);
                            break;
                        }
                        Err(Errno::ENOTCONN | Errno::EIO | Errno::EAGAIN) => {
                            if crate::helper::sleep_ms(delay).await.is_err() {
                                break;
                            }
                            delay = (delay * 2).min(60_000);
                        }
                        Err(_) => break,
                    }
                }
            });
        });
    Ok(MountedFs {
        backing: Rc::new(backing),
        root,
        root_in_fs: "/".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs_engine::CowfsMountContext;

    struct TestMount {
        dirty: Cell<bool>,
        fail: Cell<bool>,
    }
    impl DurableMount for TestMount {
        fn close(&self) -> BoxFuture<'_, ()> {
            Box::pin(async {
                if self.fail.replace(false) {
                    return Err(Errno::EIO);
                }
                self.dirty.set(false);
                Ok(())
            })
        }
    }

    #[test]
    fn shutdown_flushes_active_and_closing_mounts_and_retries_failed_close() {
        vfs::now_or_never(async {
            let ctx = Rc::new(RefCell::new(CowfsMountContext::default()));
            let track = |id, closing, fail| {
                let mount = Rc::new(TestMount {
                    dirty: Cell::new(true),
                    fail: Cell::new(fail),
                });
                ctx.borrow_mut().remote_mounts.insert(
                    id,
                    TrackedMount {
                        mount: mount.clone(),
                        closing,
                        renewal: None,
                    },
                );
                mount
            };
            let active = track(1, false, true);
            let lazy = track(2, true, true);
            assert_eq!(close_mounts(&ctx, false).await, Err(Errno::EIO));
            assert!(active.dirty.get() && lazy.dirty.get());
            let other = track(3, false, false);
            let local_root = TestMount {
                dirty: Cell::new(true),
                fail: Cell::new(false),
            };
            assert_eq!(
                close_for_shutdown(&ctx, async |finish| {
                    assert!(!finish);
                    local_root.close().await
                })
                .await,
                Err(Errno::EIO)
            );
            assert!(!local_root.dirty.get());
            assert!(!lazy.dirty.get() && !other.dirty.get());
            assert!(active.dirty.get());
            assert_eq!(ctx.borrow().remote_mounts.len(), 1);
            close_mounts(&ctx, true).await.unwrap();
            assert!(!active.dirty.get());
            assert!(ctx.borrow().remote_mounts.is_empty());
        })
        .unwrap();
    }
}

//! Browser OCI Distribution v1.1 transport, attenuated `ServiceAuth v2` derivation, and lazy
//! read-only `oci:` `cowfs` snapshot mounter (`docs/architecture/contract.md` §2.15, §6; #81).

use abi::Errno;
use abi::registry::OciReference;
use cowfs::{CowFsConfig, OciClient, OciHttpReply, OciTransport, open_oci_snapshot_cowfs};
use std::{cell::RefCell, rc::Rc};
use vfs::{
    BoxFuture, Cred, Filesystem, MountBacking, MountedFs,
    vblk::{CowfsMountOptions, VblkRegistry},
};
use wasm_bindgen::{JsCast, prelude::*};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(catch, js_namespace = self, js_name = ociRegistryFetch)]
    async fn fetch_oci(
        method: &str,
        url: &str,
        headers: &JsValue,
        body: &js_sys::Uint8Array,
    ) -> std::result::Result<JsValue, JsValue>;
}

/// Browser transport implementing [`OciTransport`] backed by `self.ociRegistryFetch` and an
/// attenuated `ServiceAuth v2` registry credential revoked on drop.
pub(crate) struct BrowserOciTransport {
    token: String,
    instance: String,
    state: Rc<RefCell<crate::State>>,
}

impl BrowserOciTransport {
    pub(crate) async fn derive(
        state: Rc<RefCell<crate::State>>,
        pid: Option<u32>,
        cred: &Cred,
        repo: &str,
        write: bool,
    ) -> vfs::Result<Self> {
        use abi::auth_v2::{DeriveServiceCred, RemoteScope, Request, Response};
        if !abi::registry::valid_repo_name(repo) {
            return Err(Errno::EINVAL);
        }
        let parent_token = match &cred.token {
            Some(token) => token.clone(),
            None => {
                crate::mint_for_registry(&state, pid.ok_or(Errno::EACCES)?, write)
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
                registry_pull: true,
                registry_push: write,
                registry_repos: vec![repo.to_string()],
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
                && issued.scope.allows_registry(repo, write)
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

impl Drop for BrowserOciTransport {
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

impl OciTransport for BrowserOciTransport {
    fn request<'a>(
        &'a self,
        method: &'a str,
        url: &'a str,
        headers: &'a [(String, String)],
        body: &'a [u8],
    ) -> BoxFuture<'a, OciHttpReply> {
        Box::pin(async move {
            if !self.state.borrow().volume_tokens.contains(&self.token) {
                return Err(Errno::EACCES);
            }
            let fields = js_sys::Object::new();
            for (k, v) in headers {
                js_sys::Reflect::set(&fields, &k.as_str().into(), &v.as_str().into())
                    .map_err(|_| Errno::EINVAL)?;
            }
            let reply = fetch_oci(method, url, &fields, &js_sys::Uint8Array::from(body))
                .await
                .map_err(|_| Errno::ENOTCONN)?;
            let get = |key: &str| js_sys::Reflect::get(&reply, &key.into()).map_err(|_| Errno::EIO);
            let status = get("status")?.as_f64().ok_or(Errno::EIO)? as u16;
            let raw_headers = get("headers")?;
            let mut out_headers = Vec::new();
            if js_sys::Array::is_array(&raw_headers) {
                let arr = js_sys::Array::from(&raw_headers);
                for i in 0..arr.length() {
                    let pair = arr.get(i);
                    if js_sys::Array::is_array(&pair) {
                        let pair_arr = js_sys::Array::from(&pair);
                        if let (Some(k), Some(v)) =
                            (pair_arr.get(0).as_string(), pair_arr.get(1).as_string())
                        {
                            out_headers.push((k, v));
                        }
                    }
                }
            }
            let body = get("body")?
                .dyn_into::<js_sys::Uint8Array>()
                .map_err(|_| Errno::EIO)?
                .to_vec();
            Ok(OciHttpReply {
                status,
                headers: out_headers,
                body,
            })
        })
    }

    fn token_auth_headers(&self) -> Vec<(String, String)> {
        vec![
            ("X-OS-Instance".into(), self.instance.clone()),
            ("X-Process-Token".into(), self.token.clone()),
        ]
    }
}

/// Mount an `oci:<repo>@sha256:<digest>` or `oci:<repo>:<tag>` `cowfs` snapshot artifact lazily
/// read-only (`WriterModel::Immutable`, zero data packs downloaded at mount).
pub(crate) async fn mount_oci_cowfs(
    source: &str,
    opts: &CowfsMountOptions,
    caller: (Rc<RefCell<crate::State>>, Option<u32>, Cred),
    vblk: Rc<VblkRegistry>,
    devfs: Rc<crate::remote_volume_bridge::BrowserDevFs>,
) -> vfs::Result<MountedFs> {
    if opts.takeover {
        return Err(Errno::EINVAL);
    }
    let oci_ref = OciReference::parse(source).ok_or(Errno::EINVAL)?;
    let (state, pid, cred) = caller;
    let transport = BrowserOciTransport::derive(state, pid, &cred, &oci_ref.repo, false).await?;
    let client = OciClient::new("", Rc::new(transport));
    let cfg = CowFsConfig::remote(Rc::new(crate::cowfs_bridge::now_timespec))
        .with_arena(cowtree::ArenaConfig::fixed_32mib())
        .with_subvol(&opts.subvol);
    let fs =
        Rc::new(open_oci_snapshot_cowfs(client, &oci_ref.repo, &oci_ref.reference, cfg).await?);
    let device: Rc<dyn vfs::vblk::VolumeDevice> =
        Rc::new(cowfs::CowFsVolumeDevice::from_mounted(fs.clone()).with_source(source.to_string()));
    let name = vblk.attach(device.clone());
    if let Err(e) = vblk.register_node(&devfs, &name, 0o440) {
        let _ = vblk.detach(&name);
        let _ = fs.close_clean().await;
        return Err(e);
    }
    let tag = vblk.registered_rdev(&name)?;
    let root = fs.root();
    let fs_for_close = fs.clone();
    let backing = MountBacking::new(fs as Rc<dyn Filesystem>, vfs::FsType::Cowfs)
        .with_ceilings(true, false)
        .with_volume_device(device)
        .with_on_release(move || {
            if vblk.device_for_rdev(&tag).is_ok() {
                let _ = vfs::now_or_never(devfs.unlink(&Cred::root(), &devfs.root(), &name));
                let _ = vblk.detach(&name);
            }
            wasm_bindgen_futures::spawn_local(async move {
                let _ = fs_for_close.close_clean().await;
            });
        });
    Ok(MountedFs {
        backing: Rc::new(backing),
        root,
        root_in_fs: "/".into(),
    })
}

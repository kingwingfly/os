//! Standalone `os-cowfs` root boot cutover (`boot_cowfs_root`, `close_clean_root`, `boot_status`)
//! and explicit Cloud / Cluster Sign-In lifecycle (`cloud_sign_in`, `cloud_sign_out`,
//! `cloud_status`, `revoke_cloud_tokens_only`, `#56` L3c + `#57` L3d).
//!
//! Enforces Contract v2 invariants:
//! - Default `/` is local `os-cowfs` (with `ForkOnBusy` default and `EPROTONOSUPPORT` -> Stage 1
//!   recovery; NEVER silently wipes incompatible user volumes).
//! - Cloud Sign-In is 100% explicit, NEVER modifies local `/etc/passwd` or local UIDs, writes
//!   `/run/user/<uid>/cloud-creds.json` (`0600`), mounts optional `FsType::Cloud` at `/mnt/cloud`,
//!   and attaches only explicitly scoped remote devices.
//! - Cloud Sign-Out unmounts `/mnt/cloud`, detaches remote devices, revokes all `ServiceAuth v2`
//!   tokens, clears ambient process remote creds WITHOUT killing or signalling any local process.

use crate::boot_stage::{
    BOOT_PROFILE_PATH, BootProfile, BootStage, BootWriterMode, COWFSCK_REPORT_PATH,
    MOUNTED_ROOT_INFO_PATH, MountedRootInfo, RecoveryReason, RecoveryState, RootSpec,
};
use crate::cowfs_bridge::{
    BootOpenError, DirtyFlushGuard, JsCowfsStore, bind_dirty_flush_timer,
    close_clean_with_prune_fs, cowfsck_volume_stores, now_timespec, open_for_boot_stores_detailed,
};
use crate::local_accounts::seed_fresh_cowfs_root;
use crate::release_v2::{VerifiedAssetBlobStore, read_verified_image_file};
use crate::vfs_engine::BootVfsOptions;
use crate::{
    CloudSession, INIT, Kernel, LocalAccount, ensure_remote_attached_state, fail, now_secs,
    revoke_remote_tokens_state, service_auth_request,
};
use abi::auth_v2::{self, DetachInstance, MintServiceCred, RemoteScope};
use abi::contract::{fs_magic, mount_flags, umount_flags};
use abi::{Errno, Error, S_IFDIR, S_IFREG};
use cowfs::{CowFs, CowFsConfig, CowFsVolumeDevice};
use cowtree::{ArenaConfig, COWFS_FORMAT_VERSION, HeadStore, RootObject, VolumeId};
use image::{Image, Kind, Node};
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use vfs::imagefs::{BuildAssetSizes, ImageFs};
use vfs::memfs::MemFs;
use vfs::{
    Cred, Filesystem, FsId, FsType, MountBacking, MountFlags, OpenOptions, SetAttr, StartAnchor,
    Vfs, WriteAt,
};
use wasm_bindgen::prelude::*;

async fn ensure_dir_vfs(vfs: &Vfs, path: &str, mode: u16) -> vfs::Result<()> {
    let mut cur = String::new();
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    for (i, part) in parts.iter().enumerate() {
        cur.push('/');
        cur.push_str(part);
        let is_last = i + 1 == parts.len();
        let m = if is_last { mode } else { 0o755 };
        if let Ok(st) = vfs.statat(INIT, StartAnchor::Root, &cur, false).await {
            if st.kind() != S_IFDIR {
                return Err(Errno::ENOTDIR);
            }
            continue;
        }
        match vfs.mkdirat(INIT, StartAnchor::Root, &cur, m).await {
            Ok(_) | Err(Errno::EEXIST) => {
                let st = vfs.statat(INIT, StartAnchor::Root, &cur, false).await?;
                if st.kind() != S_IFDIR {
                    return Err(Errno::ENOTDIR);
                }
                if is_last {
                    let _ = vfs
                        .setattrat(
                            INIT,
                            StartAnchor::Root,
                            &cur,
                            &SetAttr {
                                mode: Some(mode),
                                ..SetAttr::default()
                            },
                            false,
                        )
                        .await;
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

async fn populate_ephemeral_memfs(fs: &MemFs, root_template: Option<&Image>) -> vfs::Result<()> {
    let Some(tpl) = root_template else {
        return crate::local_accounts::seed_fresh_cowfs_root(fs).await;
    };
    let mut root_cred = Cred::root();
    root_cred.umask = 0;
    let blobs = VerifiedAssetBlobStore;
    let mut handles: HashMap<String, abi::fs::Handle> = HashMap::new();
    handles.insert("/".to_string(), fs.root());
    for entry in &tpl.entries {
        if entry.path == "/" {
            continue;
        }
        let (parent_path, name) = match entry.path.rsplit_once('/') {
            Some(("", n)) => ("/", n),
            Some((p, n)) => (p, n),
            None => return Err(Errno::EINVAL),
        };
        let parent_h = handles.get(parent_path).cloned().ok_or(Errno::ENOENT)?;
        match &entry.node {
            Node::Directory => {
                let created = match fs.mkdir(&root_cred, &parent_h, name, entry.mode).await {
                    Ok(e) => e,
                    Err(Errno::EEXIST) => fs.lookup(&root_cred, &parent_h, name).await?,
                    Err(e) => return Err(e),
                };
                fs.setattr(
                    &root_cred,
                    &created.handle,
                    &SetAttr {
                        mode: Some(entry.mode),
                        uid: Some(entry.uid),
                        gid: Some(entry.gid),
                        ..SetAttr::default()
                    },
                )
                .await?;
                handles.insert(entry.path.clone(), created.handle);
            }
            Node::File {
                sha256,
                size,
                chunk_size,
                chunks,
            } => {
                let data =
                    read_verified_image_file(&blobs, sha256, *size, *chunk_size, chunks).await?;
                let mut opts = OpenOptions::new();
                opts.write(true).create(true).truncate(true);
                let (created, open) = fs
                    .create(&root_cred, &parent_h, name, entry.mode, &opts)
                    .await?;
                let mut off = 0u64;
                while (off as usize) < data.len() {
                    let w = fs
                        .write_at(&open, &data[off as usize..], WriteAt::Offset(off))
                        .await?;
                    if w.len == 0 {
                        let _ = fs.release(&open).await;
                        return Err(Errno::EIO);
                    }
                    off += w.len as u64;
                }
                fs.release(&open).await?;
                fs.setattr(
                    &root_cred,
                    &created.handle,
                    &SetAttr {
                        mode: Some(entry.mode),
                        uid: Some(entry.uid),
                        gid: Some(entry.gid),
                        ..SetAttr::default()
                    },
                )
                .await?;
                handles.insert(entry.path.clone(), created.handle);
            }
            Node::Symlink { target } => {
                let created = fs.symlink(&root_cred, &parent_h, name, target).await?;
                handles.insert(entry.path.clone(), created.handle);
            }
        }
    }
    Ok(())
}

async fn teardown_sysroot_mounts(vfs: &Vfs) {
    for target in ["/sysroot/tmp", "/sysroot/usr", "/sysroot/home", "/sysroot"] {
        let _ = vfs.umount2(INIT, target, umount_flags::MNT_DETACH).await;
    }
}

async fn write_file_vfs(vfs: &Vfs, path: &str, data: &[u8], mode: u16) -> vfs::Result<()> {
    if let Some((parent, _)) = path.rsplit_once('/')
        && !parent.is_empty()
    {
        ensure_dir_vfs(vfs, parent, 0o755).await?;
    }
    let _ = vfs.unlinkat(INIT, StartAnchor::Root, path, false).await;
    let (file, _) = vfs
        .open_file(
            INIT,
            StartAnchor::Root,
            path,
            abi::O_WRONLY | abi::O_CREAT | abi::O_TRUNC,
            mode,
        )
        .await?;
    let mut off = 0usize;
    while off < data.len() {
        let end = (off + 256 * 1024).min(data.len());
        match file.write_at(&data[off..end], off as u64).await {
            Ok(w) if w > 0 => off += w,
            Ok(_) => {
                let _ = file.close().await;
                return Err(Errno::EIO);
            }
            Err(e) => {
                let _ = file.close().await;
                return Err(e);
            }
        }
    }
    let _ = file.close().await;
    let _ = vfs
        .setattrat(
            INIT,
            StartAnchor::Root,
            path,
            &SetAttr {
                mode: Some(mode),
                ..SetAttr::default()
            },
            false,
        )
        .await;
    Ok(())
}

fn unlink_oldroot_bounded<'a>(
    vfs: &'a Vfs,
    dir_fd: u32,
    oldroot_dev: u64,
    reclaimed: &'a mut usize,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>> {
    Box::pin(async move {
        let mut names = Vec::new();
        let mut cookie = 0u64;
        loop {
            let Ok(page) = vfs
                .read_dir_page(INIT, StartAnchor::DirFd(dir_fd), ".", cookie, 256)
                .await
            else {
                break;
            };
            for e in page.entries {
                if e.name != "." && e.name != ".." {
                    names.push(e.name);
                }
            }
            match page.next_cookie {
                Some(next) if next != cookie => cookie = next,
                _ => break,
            }
        }
        for name in names {
            let Ok(st) = vfs
                .statat(INIT, StartAnchor::DirFd(dir_fd), &name, false)
                .await
            else {
                continue;
            };
            if st.dev != oldroot_dev {
                continue;
            }
            if st.kind() == S_IFDIR {
                if let Ok(child_fd) = vfs
                    .openat(
                        INIT,
                        StartAnchor::DirFd(dir_fd),
                        &name,
                        abi::O_RDONLY | abi::O_DIRECTORY | abi::O_NOFOLLOW,
                        0,
                    )
                    .await
                {
                    if vfs
                        .fstat(INIT, child_fd)
                        .await
                        .is_ok_and(|fst| fst.dev == oldroot_dev)
                    {
                        unlink_oldroot_bounded(vfs, child_fd, oldroot_dev, reclaimed).await;
                    }
                    let _ = vfs.close(INIT, child_fd).await;
                }
                if vfs
                    .unlinkat(INIT, StartAnchor::DirFd(dir_fd), &name, true)
                    .await
                    .is_ok()
                {
                    *reclaimed += 1;
                }
            } else if vfs
                .unlinkat(INIT, StartAnchor::DirFd(dir_fd), &name, false)
                .await
                .is_ok()
            {
                *reclaimed += 1;
            }
        }
    })
}

fn extract_service_digests_from_image(img: &Image) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for entry in &img.entries {
        if matches!(
            entry.path.as_str(),
            "/usr/bin/init"
                | "/usr/bin/supervise"
                | "/usr/bin/mountd"
                | "/usr/bin/exportd"
                | "/usr/bin/kubelet"
                | "/usr/bin/compositor"
                | "/usr/bin/desktop-shell"
                | "/usr/bin/greeter"
                | "/usr/bin/gui-sample-doc"
                | "/usr/bin/mounts"
        ) && let Node::File { sha256, .. } = &entry.node
        {
            out.insert(entry.path.clone(), sha256.clone());
        }
    }
    out
}

fn extract_service_digests_from_composition(json_text: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Ok(val) = serde_json::from_str::<Value>(json_text) else {
        return out;
    };
    let entries_val = val.get("entries").unwrap_or(&val);
    let record = |out: &mut HashMap<String, String>, entry: &Value| {
        let Some(path) = entry.get("path").and_then(|v| v.as_str()) else {
            return;
        };
        if !matches!(
            path,
            "/usr/bin/init"
                | "/usr/bin/supervise"
                | "/usr/bin/mountd"
                | "/usr/bin/exportd"
                | "/usr/bin/kubelet"
                | "/usr/bin/compositor"
                | "/usr/bin/desktop-shell"
                | "/usr/bin/greeter"
                | "/usr/bin/gui-sample-doc"
                | "/usr/bin/mounts"
        ) {
            return;
        }
        let sha = entry.get("sha256").and_then(|v| v.as_str()).or_else(|| {
            entry
                .get("node")
                .and_then(|n| n.get("sha256"))
                .and_then(|v| v.as_str())
        });
        if let Some(s) = sha {
            out.insert(path.to_string(), s.to_string());
        }
    };
    if let Some(map) = entries_val.as_object() {
        for entry in map.values() {
            record(&mut out, entry);
        }
    } else if let Some(arr) = entries_val.as_array() {
        for entry in arr {
            record(&mut out, entry);
        }
    }
    out
}

fn default_asset_sizes() -> BuildAssetSizes {
    BuildAssetSizes {
        coreutils: 64 * 1024,
        utilities: 64 * 1024,
        dash: 64 * 1024,
        supervise: 64 * 1024,
        init: 64 * 1024,
        mountd: 64 * 1024,
        exportd: 64 * 1024,
        kubelet: 64 * 1024,
    }
}

impl Kernel {
    fn boot_status_json(&self) -> Value {
        let rt = self.vfs_rt.borrow();
        let st = self.state.borrow();
        json!({
            "stage": rt.boot_stage,
            "boot_profile": rt.boot_profile,
            "mounted_root": rt.mounted_root,
            "recovery": rt.recovery,
            "banners": rt.banners,
            "last_shutdown": rt.last_shutdown,
            "root_fstype": if let Some(ref info) = rt.mounted_root {
                info.fstype.as_str()
            } else if rt.root_cowfs.is_some() {
                "cowfs"
            } else {
                "tmpfs"
            },
            "stage1_reclaimed_entries": rt.stage1_reclaimed_entries,
            "stage1_tmpfs_dropped": rt.stage1_fs_weak.strong_count() == 0,
            "account": st.account.to_creds_json(),
        })
    }

    fn cloud_status_json(&self) -> Value {
        let st = self.state.borrow();
        let rt = self.vfs_rt.borrow();
        let cloud_mounted = rt
            .vfs
            .system_namespace()
            .borrow()
            .mounts()
            .values()
            .any(|m| m.slot.backing.fstype == FsType::Cloud && m.root_in_fs == "/");
        match &st.cloud_session {
            Some(cs) => json!({
                "signed_in": true,
                "cloud_user": cs.cloud_user,
                "cloud_uid": cs.cloud_uid,
                "local_user": st.account.user,
                "local_uid": st.account.uid,
                "scope": cs.scope,
                "cloud_mounted": cloud_mounted,
                "attached_devices": st.attached_devices.keys().cloned().collect::<Vec<_>>(),
                "pending_revocations": st.pending_revocations.len(),
                "pending_detach": st.pending_detach,
                "remote_revoked": st.pending_revocations.is_empty() && !st.pending_detach,
            }),
            None => json!({
                "signed_in": false,
                "cloud_user": Value::Null,
                "cloud_uid": Value::Null,
                "local_user": st.account.user,
                "local_uid": st.account.uid,
                "scope": Value::Null,
                "cloud_mounted": cloud_mounted,
                "attached_devices": st.attached_devices.keys().cloned().collect::<Vec<_>>(),
                "pending_revocations": st.pending_revocations.len(),
                "pending_detach": st.pending_detach,
                "remote_revoked": st.pending_revocations.is_empty() && !st.pending_detach,
            }),
        }
    }

    /// Ensure `/mnt/cloud` (`FsType::Cloud`) is mounted onto `ns` when an active `CloudSession`
    /// with `scope.cloud_fs == true` is present. Safe against concurrent `session_begin` and
    /// `cloud_sign_out` interleavings.
    pub(crate) async fn ensure_cloud_fs_mounted_on(
        &self,
        ns: &Rc<RefCell<vfs::MountNamespace>>,
    ) -> vfs::Result<()> {
        let allowed = || {
            self.state
                .borrow()
                .cloud_session
                .as_ref()
                .is_some_and(|cs| cs.scope.cloud_fs)
        };
        if !allowed() {
            return Err(Errno::ENOTCONN);
        }
        let has_cloud = |target: &Rc<RefCell<vfs::MountNamespace>>| {
            target
                .borrow()
                .mounts()
                .values()
                .any(|m| m.slot.backing.fstype == FsType::Cloud && m.root_in_fs == "/")
        };
        if has_cloud(ns) {
            return Ok(());
        }
        let (vfs, cloud_mount) = {
            let rt = self.vfs_rt.borrow();
            (rt.vfs.clone(), Rc::clone(&rt.cloud_mount))
        };
        let _ = ensure_dir_vfs(&vfs, "/mnt/cloud", 0o755).await;
        if !allowed() {
            return Err(Errno::ENOTCONN);
        }
        if has_cloud(ns) {
            return Ok(());
        }
        let backing = Rc::new(MountBacking::new(
            cloud_mount as Rc<dyn Filesystem>,
            FsType::Cloud,
        ));
        let mut root_cred = Cred::root();
        root_cred.umask = 0;
        self.with_page_scope(
            false,
            vfs.mount_on_namespace(
                ns,
                &root_cred,
                backing,
                None,
                "cloud",
                "/mnt/cloud",
                MountFlags {
                    nosuid: true,
                    nodev: true,
                    ..MountFlags::default()
                },
                mount_flags::MS_NOSUID | mount_flags::MS_NODEV,
                None,
            ),
        )
        .await
        .map(|_| ())
    }

    /// Mount optional `FsType::Cloud` at `/mnt/cloud` in `system_mnt_ns` and every active session
    /// namespace. Requires an active `CloudSession` with `scope.cloud_fs == true`.
    pub(crate) async fn mount_cloud_fs_internal(&self) -> vfs::Result<()> {
        let allowed = || {
            self.state
                .borrow()
                .cloud_session
                .as_ref()
                .is_some_and(|cs| cs.scope.cloud_fs)
        };
        if !allowed() {
            return Err(Errno::ENOTCONN);
        }
        let sys_ns = self.vfs_rt.borrow().vfs.system_namespace();
        let mut mounted_any = self.ensure_cloud_fs_mounted_on(&sys_ns).await.is_ok();
        // Re-scan session namespaces after awaiting so any `session_begin` that completed
        // concurrently while `sys_ns` was being mounted also receives `/mnt/cloud`.
        for _ in 0..4 {
            if !allowed() {
                break;
            }
            let pending: Vec<Rc<RefCell<vfs::MountNamespace>>> =
                {
                    let rt = self.vfs_rt.borrow();
                    let mut list = Vec::new();
                    for sess in rt.sessions.values() {
                        let already =
                            sess.mnt_ns.borrow().mounts().values().any(|m| {
                                m.slot.backing.fstype == FsType::Cloud && m.root_in_fs == "/"
                            });
                        if !already {
                            list.push(Rc::clone(&sess.mnt_ns));
                        }
                    }
                    if let Some(guest) = &rt.guest_page {
                        let already =
                            guest.mnt_ns.borrow().mounts().values().any(|m| {
                                m.slot.backing.fstype == FsType::Cloud && m.root_in_fs == "/"
                            });
                        if !already {
                            list.push(Rc::clone(&guest.mnt_ns));
                        }
                    }
                    list
                };
            if pending.is_empty() {
                break;
            }
            let mut progressed = false;
            for ns in pending {
                if !allowed() {
                    break;
                }
                if self.ensure_cloud_fs_mounted_on(&ns).await.is_ok() {
                    mounted_any = true;
                    progressed = true;
                }
            }
            if !progressed {
                break;
            }
        }
        if mounted_any {
            Ok(())
        } else {
            Err(Errno::ENOTCONN)
        }
    }

    /// Lazily unmount `/mnt/cloud` (`MNT_DETACH`) from `system_mnt_ns` and every session namespace.
    pub(crate) fn unmount_cloud_fs_internal(&self) {
        let rt = self.vfs_rt.borrow();
        let mut nss = vec![rt.vfs.system_namespace()];
        for sess in rt.sessions.values() {
            nss.push(Rc::clone(&sess.mnt_ns));
        }
        if let Some(guest) = &rt.guest_page {
            nss.push(Rc::clone(&guest.mnt_ns));
        }
        for ns in nss {
            let ids: Vec<vfs::MountId> = ns
                .borrow()
                .mounts()
                .iter()
                .filter_map(|(&id, m)| {
                    (m.slot.backing.fstype == FsType::Cloud && m.root_in_fs == "/").then_some(id)
                })
                .collect();
            for id in ids {
                let _ = ns.borrow_mut().detach_subtree(id);
            }
        }
    }
}

#[wasm_bindgen]
impl Kernel {
    /// Return the current standalone boot status (`BootStage`, `BootProfile`, `MountedRootInfo`,
    /// `RecoveryState`, `banners`, `root_fstype`, local `account`). ZERO network RPCs.
    pub fn boot_status(&self) -> String {
        self.boot_status_json().to_string()
    }

    /// Stage 1 -> Stage 2 standalone offline boot onto browser-local persistent `os-cowfs` `/`
    /// (`#56` L3c + `#57` L3d, Contract v2 §5). ZERO network RPCs, ZERO `RootCloudDriver`!
    pub async fn boot_cowfs_root(
        &self,
        store: JsValue,
        boot_profile_json: Option<String>,
        opts_json: Option<String>,
    ) -> Result<String, JsValue> {
        let mut profile: BootProfile = match boot_profile_json.as_deref() {
            Some(s) if !s.is_empty() && s != "null" => serde_json::from_str(s)
                .map_err(|e| fail(Error::because(Errno::EINVAL, e.to_string())))?,
            _ => BootProfile::default(),
        };
        profile.validate().map_err(|e| fail(Error::from(e)))?;

        let opts: Option<BootVfsOptions> = opts_json
            .as_deref()
            .filter(|s| !s.is_empty() && *s != "null")
            .map(|s| {
                serde_json::from_str(s)
                    .map_err(|e| fail(Error::because(Errno::EINVAL, e.to_string())))
            })
            .transpose()?;

        let js_store = Rc::new(JsCowfsStore { obj: store });
        let vfs = self.vfs_rt.borrow().vfs.clone();

        // Record profile in `/run/os/boot-profile.json` (`0444`).
        let profile_bytes = serde_json::to_vec_pretty(&profile).unwrap_or_else(|_| b"{}".to_vec());
        let _ = write_file_vfs(&vfs, BOOT_PROFILE_PATH, &profile_bytes, 0o444).await;

        let enter_recovery =
            |reason: RecoveryReason, vol: Option<String>, snaps: Vec<String>, msg: String| {
                let mut rt = self.vfs_rt.borrow_mut();
                rt.boot_profile = profile.clone();
                rt.boot_stage = BootStage::Stage1Recovery;
                rt.recovery = Some(RecoveryState {
                    reason,
                    volume_uuid: vol,
                    available_snapshots: snaps,
                    message: msg,
                });
                drop(rt);
                self.boot_status_json().to_string()
            };

        let parsed_root_template: Option<Image> = match opts
            .as_ref()
            .and_then(|o| o.root_template.as_deref())
            .filter(|s| !s.is_empty() && *s != "null")
        {
            Some(raw) => {
                let img = Image::parse(raw.as_bytes()).map_err(|e| {
                    fail(Error::because(
                        Errno::EINVAL,
                        format!("invalid root_template: {e}"),
                    ))
                })?;
                if img.kind != Kind::RootTemplate {
                    return Err(fail(Error::because(
                        Errno::EINVAL,
                        "root_template image kind mismatch",
                    )));
                }
                Some(img)
            }
            None => None,
        };

        let mut opened_cowfs: Option<Rc<CowFs<JsCowfsStore, JsCowfsStore>>> = None;
        let mut opened_dirty_guard: Option<DirtyFlushGuard> = None;
        let mut opened_ro_home_cowfs: Option<Rc<dyn Filesystem>> = None;
        let mounted_root_fs: Rc<dyn Filesystem>;
        let mut mounted_root_fstype = FsType::Cowfs;
        let mut mounted_root_rdonly = false;
        let mounted_root_source: String;
        let info: MountedRootInfo;
        let mut banners: Vec<String> = Vec::new();

        if profile.recovery {
            let vol = match &profile.root {
                RootSpec::CowFs { volume_uuid, .. } => volume_uuid.clone(),
                RootSpec::Snapshot { volume_uuid, .. } => Some(volume_uuid.clone()),
                RootSpec::Ephemeral | RootSpec::CloudOptIn { .. } => None,
            };
            let snaps = match &vol {
                Some(v) => js_store
                    .list_snapshots(&VolumeId(v.clone()))
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .map(|s| s.name)
                    .collect(),
                None => Vec::new(),
            };
            return Ok(enter_recovery(
                RecoveryReason::Requested,
                vol,
                snaps,
                "Boot profile requested Stage 1 recovery chooser.".into(),
            ));
        }

        match profile.root.clone() {
            RootSpec::CloudOptIn { .. } => {
                return Ok(enter_recovery(
                    RecoveryReason::IoError {
                        errno: "EOPNOTSUPP".into(),
                        detail: "Standalone boot requires a local CowFs, Snapshot, or Ephemeral root".into(),
                    },
                    None,
                    Vec::new(),
                    "Standalone offline boot requires a local os-cowfs, snapshot, or ephemeral root.".into(),
                ));
            }
            RootSpec::Ephemeral => {
                let eph_fs = Rc::new(MemFs::new(
                    FsId("tmpfs:ephemeral-root".to_string()),
                    4,
                    0,
                    0,
                    0o755,
                    Box::new(|| {
                        let ts = now_timespec();
                        (ts.sec, ts.nsec)
                    }),
                ));
                if let Err(e) =
                    populate_ephemeral_memfs(&eph_fs, parsed_root_template.as_ref()).await
                {
                    return Ok(enter_recovery(
                        RecoveryReason::IoError {
                            errno: format!("{e:?}"),
                            detail: format!("failed to populate ephemeral root: {e:?}"),
                        },
                        None,
                        Vec::new(),
                        format!("Failed to populate ephemeral root ({e:?})."),
                    ));
                }
                mounted_root_fs = eph_fs as Rc<dyn Filesystem>;
                mounted_root_fstype = FsType::TmpFs;
                mounted_root_source = "tmpfs:ephemeral".into();
                info = MountedRootInfo {
                    fstype: "tmpfs".into(),
                    volume_uuid: "ephemeral".into(),
                    forked_from: None,
                    base_epoch: 0,
                    ephemeral_if_unmodified: true,
                    first_boot_seeded: true,
                    writer_mode: BootWriterMode::ForkOnBusy,
                    mounted_at: now_secs(),
                };
            }
            RootSpec::Snapshot {
                volume_uuid,
                snapshot,
            } => {
                match js_store.format_version().await {
                    Ok(Some(ver)) if ver != COWFS_FORMAT_VERSION => {
                        return Ok(enter_recovery(
                            RecoveryReason::IncompatibleFormat {
                                found_version: Some(ver),
                                expected_version: COWFS_FORMAT_VERSION,
                            },
                            Some(volume_uuid),
                            Vec::new(),
                            format!(
                                "Refusing to mount incompatible os-cowfs format version {ver} (expected {COWFS_FORMAT_VERSION}): EPROTONOSUPPORT."
                            ),
                        ));
                    }
                    Ok(_) => {}
                    Err(Errno::EPROTONOSUPPORT) => {
                        return Ok(enter_recovery(
                            RecoveryReason::IncompatibleFormat {
                                found_version: None,
                                expected_version: COWFS_FORMAT_VERSION,
                            },
                            Some(volume_uuid),
                            Vec::new(),
                            format!(
                                "Refusing to mount incompatible os-cowfs store (expected version {COWFS_FORMAT_VERSION}): EPROTONOSUPPORT."
                            ),
                        ));
                    }
                    Err(e) => {
                        return Ok(enter_recovery(
                            RecoveryReason::IoError {
                                errno: format!("{e:?}"),
                                detail: format!("format version probe failed: {e:?}"),
                            },
                            Some(volume_uuid),
                            Vec::new(),
                            format!("Failed to probe os-cowfs format version ({e:?})."),
                        ));
                    }
                }
                let vol_id = VolumeId(volume_uuid.clone());
                let snap_rec = match js_store.get_snapshot(&vol_id, &snapshot).await {
                    Ok(s) => s,
                    Err(e) => {
                        let snaps = js_store
                            .list_snapshots(&vol_id)
                            .await
                            .unwrap_or_default()
                            .into_iter()
                            .map(|s| s.name)
                            .collect();
                        return Ok(enter_recovery(
                            RecoveryReason::IoError {
                                errno: format!("{e:?}"),
                                detail: format!("snapshot {snapshot:?} unavailable: {e:?}"),
                            },
                            Some(volume_uuid),
                            snaps,
                            format!("Snapshot {snapshot:?} could not be opened ({e:?})."),
                        ));
                    }
                };
                let clock: Rc<dyn Fn() -> abi::fs::Timespec> = Rc::new(now_timespec);
                let cfg = CowFsConfig::local_browser(Rc::clone(&clock))
                    .with_arena(ArenaConfig::fixed_32mib());
                let snap_fs = match CowFs::open(
                    Rc::clone(&js_store),
                    Rc::clone(&js_store),
                    vol_id.clone(),
                    cowfs::CowFsOpenMode::Snapshot(snapshot.clone()),
                    cfg,
                )
                .await
                {
                    Ok(fs) => Rc::new(fs),
                    Err(e) => {
                        return Ok(enter_recovery(
                            RecoveryReason::CorruptVolume {
                                detail: format!("snapshot {snapshot:?} failed open: {e:?}"),
                                snapshots: vec![snapshot.clone()],
                            },
                            Some(volume_uuid),
                            vec![snapshot],
                            format!("Snapshot failed open/verification ({e:?})."),
                        ));
                    }
                };
                if let Ok(raw_root) = js_store.get_node(&snap_rec.root).await
                    && let Ok(root_obj) = RootObject::decode_verified(&snap_rec.root, &raw_root)
                    && root_obj.subvols.contains_key("@home")
                {
                    let home_cfg = CowFsConfig::local_browser(Rc::clone(&clock))
                        .with_arena(ArenaConfig::fixed_32mib())
                        .with_subvol("@home");
                    if let Ok(home_fs) = CowFs::open(
                        Rc::clone(&js_store),
                        Rc::clone(&js_store),
                        vol_id,
                        cowfs::CowFsOpenMode::Snapshot(snapshot.clone()),
                        home_cfg,
                    )
                    .await
                    {
                        opened_ro_home_cowfs = Some(Rc::new(home_fs) as Rc<dyn Filesystem>);
                    }
                }
                {
                    let (vblk, dev_fs, cowfs_ctx) = {
                        let rt = self.vfs_rt.borrow();
                        (
                            Rc::clone(&rt.vblk),
                            Rc::clone(&rt.dev_fs),
                            Rc::clone(&rt.cowfs_ctx),
                        )
                    };
                    cowfs_ctx.borrow_mut().store = Some(Rc::clone(&js_store));
                    let _ = vblk.detach("vd0");
                    let _ = vblk.attach_named(
                        "vd0",
                        Rc::new(CowFsVolumeDevice::from_mounted(Rc::clone(&snap_fs))),
                    );
                    let _ = vblk.register_node(&dev_fs, "vd0", 0o660);
                    if vblk.get("vd1").is_none() {
                        let _ = vblk.attach_named(
                            "vd1",
                            Rc::new(CowFsVolumeDevice::unmounted(
                                VolumeId("scratch-vd1".to_string()),
                                Rc::clone(&js_store),
                                Rc::clone(&js_store),
                                abi::contract::WriterModel::Local,
                                abi::contract::Durability::TreeCommit,
                                Rc::new(now_timespec),
                            )),
                        );
                        let _ = vblk.register_node(&dev_fs, "vd1", 0o660);
                    }
                }
                mounted_root_fs = Rc::clone(&snap_fs) as Rc<dyn Filesystem>;
                opened_cowfs = Some(snap_fs);
                mounted_root_fstype = FsType::Cowfs;
                mounted_root_rdonly = true;
                mounted_root_source = format!("snapshot:{volume_uuid}@{snapshot}");
                info = MountedRootInfo {
                    fstype: "cowfs-snapshot".into(),
                    volume_uuid: format!("{volume_uuid}@{snapshot}"),
                    forked_from: None,
                    base_epoch: snap_rec.epoch,
                    ephemeral_if_unmodified: false,
                    first_boot_seeded: false,
                    writer_mode: BootWriterMode::Exclusive,
                    mounted_at: now_secs(),
                };
            }
            RootSpec::CowFs {
                volume_uuid,
                writer_mode,
            } => {
                // 1. Format version check FIRST — NEVER silently wipe or reformat user data!
                match js_store.format_version().await {
                    Ok(Some(ver)) if ver != COWFS_FORMAT_VERSION => {
                        return Ok(enter_recovery(
                            RecoveryReason::IncompatibleFormat {
                                found_version: Some(ver),
                                expected_version: COWFS_FORMAT_VERSION,
                            },
                            volume_uuid,
                            Vec::new(),
                            format!(
                                "Refusing to mount or reformat incompatible os-cowfs format version {ver} (expected {COWFS_FORMAT_VERSION}): EPROTONOSUPPORT."
                            ),
                        ));
                    }
                    Ok(_) => {}
                    Err(Errno::EPROTONOSUPPORT) => {
                        return Ok(enter_recovery(
                            RecoveryReason::IncompatibleFormat {
                                found_version: None,
                                expected_version: COWFS_FORMAT_VERSION,
                            },
                            volume_uuid,
                            Vec::new(),
                            format!(
                                "Refusing to mount or reformat incompatible os-cowfs store (expected version {COWFS_FORMAT_VERSION}): EPROTONOSUPPORT."
                            ),
                        ));
                    }
                    Err(e) => {
                        return Ok(enter_recovery(
                            RecoveryReason::IoError {
                                errno: format!("{e:?}"),
                                detail: format!("format version probe failed: {e:?}"),
                            },
                            volume_uuid,
                            Vec::new(),
                            format!("Failed to probe os-cowfs format version ({e:?})."),
                        ));
                    }
                }

                // 2. Provision or open `os-cowfs` root volume (`ForkOnBusy` default):
                //    - Codex #13: acquires writer/fork FIRST and verifies THAT EXACT live head!
                //    - Codex #14: binds the 5-second dirty commit deadline timer via `on_dirty`.
                //    - Codex #7: when a verified Release v2 `RootTemplate` is supplied, seeds
                //      strictly from it; otherwise on fresh dev boot only, seeds built-in defaults.
                let clock: Rc<dyn Fn() -> abi::fs::Timespec> = Rc::new(now_timespec);
                let mut existing_volume_present = false;
                let (mut opened, dirty_binder) = if let Some(ref existing_uuid) = volume_uuid {
                    let (config, binder) = bind_dirty_flush_timer::<JsCowfsStore, JsCowfsStore>(
                        CowFsConfig::local_browser(Rc::clone(&clock))
                            .with_arena(ArenaConfig::fixed_32mib()),
                    );
                    match open_for_boot_stores_detailed(
                        Rc::clone(&js_store),
                        Rc::clone(&js_store),
                        Some(existing_uuid.clone()),
                        writer_mode.to_cowtree_mode(),
                        parsed_root_template.as_ref(),
                        parsed_root_template
                            .as_ref()
                            .map(|_| &VerifiedAssetBlobStore),
                        config,
                        || existing_uuid.clone(),
                    )
                    .await
                    {
                        Ok(res) => {
                            existing_volume_present = true;
                            (res, binder)
                        }
                        Err(BootOpenError::Errno(Errno::ENOENT))
                            if matches!(
                                js_store.read_head(&VolumeId(existing_uuid.clone())).await,
                                Err(Errno::ENOENT)
                            ) =>
                        {
                            // Pre-minted first-boot UUID does not exist in IDB yet: provision it!
                            let preferred = existing_uuid.clone();
                            let (fresh_cfg, fresh_binder) =
                                bind_dirty_flush_timer::<JsCowfsStore, JsCowfsStore>(
                                    CowFsConfig::local_browser(Rc::clone(&clock))
                                        .with_arena(ArenaConfig::fixed_32mib()),
                                );
                            match open_for_boot_stores_detailed(
                                Rc::clone(&js_store),
                                Rc::clone(&js_store),
                                None,
                                writer_mode.to_cowtree_mode(),
                                parsed_root_template.as_ref(),
                                parsed_root_template
                                    .as_ref()
                                    .map(|_| &VerifiedAssetBlobStore),
                                fresh_cfg,
                                move || preferred,
                            )
                            .await
                            {
                                Ok(res) => (res, fresh_binder),
                                Err(BootOpenError::Errno(Errno::EPROTONOSUPPORT)) => {
                                    return Ok(enter_recovery(
                                        RecoveryReason::IncompatibleFormat {
                                            found_version: None,
                                            expected_version: COWFS_FORMAT_VERSION,
                                        },
                                        volume_uuid,
                                        Vec::new(),
                                        "Incompatible os-cowfs format version (EPROTONOSUPPORT)."
                                            .into(),
                                    ));
                                }
                                Err(e) => {
                                    let errno = e.errno();
                                    return Ok(enter_recovery(
                                        RecoveryReason::IoError {
                                            errno: format!("{errno:?}"),
                                            detail: format!("os-cowfs provision failed: {errno:?}"),
                                        },
                                        volume_uuid,
                                        Vec::new(),
                                        format!("Failed to provision os-cowfs root ({errno:?})."),
                                    ));
                                }
                            }
                        }
                        Err(BootOpenError::Corrupt { volume, report }) => {
                            let report_bytes = serde_json::to_vec_pretty(&report)
                                .unwrap_or_else(|_| b"{}".to_vec());
                            let _ = write_file_vfs(&vfs, COWFSCK_REPORT_PATH, &report_bytes, 0o444)
                                .await;
                            let detail = if report.errors.is_empty() {
                                "cowfsck reported volume corruption".into()
                            } else {
                                report.errors.join("; ")
                            };
                            let snaps: Vec<String> = js_store
                                .list_snapshots(&VolumeId(existing_uuid.clone()))
                                .await
                                .unwrap_or_default()
                                .into_iter()
                                .map(|s| s.name)
                                .collect();
                            return Ok(enter_recovery(
                                RecoveryReason::CorruptVolume {
                                    detail: detail.clone(),
                                    snapshots: snaps.clone(),
                                },
                                Some(existing_uuid.clone()),
                                snaps,
                                format!(
                                    "Stage 1 cowfsck detected corruption on volume {volume}: {detail}"
                                ),
                            ));
                        }
                        Err(BootOpenError::Errno(Errno::EPROTONOSUPPORT)) => {
                            return Ok(enter_recovery(
                                RecoveryReason::IncompatibleFormat {
                                    found_version: None,
                                    expected_version: COWFS_FORMAT_VERSION,
                                },
                                volume_uuid,
                                Vec::new(),
                                "Incompatible os-cowfs format version (EPROTONOSUPPORT).".into(),
                            ));
                        }
                        Err(BootOpenError::Errno(Errno::EBUSY)) => {
                            let busy = existing_uuid.clone();
                            let snaps: Vec<String> = js_store
                                .list_snapshots(&VolumeId(busy.clone()))
                                .await
                                .unwrap_or_default()
                                .into_iter()
                                .map(|s| s.name)
                                .collect();
                            return Ok(enter_recovery(
                                RecoveryReason::VolumeBusy {
                                    volume_uuid: busy.clone(),
                                },
                                volume_uuid,
                                snaps,
                                format!(
                                    "Volume {busy} is locked exclusively by another tab (EBUSY). Choose Fork & Boot or close the other tab."
                                ),
                            ));
                        }
                        Err(BootOpenError::Errno(e)) => {
                            let vol_id = VolumeId(existing_uuid.clone());
                            let snaps: Vec<String> = js_store
                                .list_snapshots(&vol_id)
                                .await
                                .unwrap_or_default()
                                .into_iter()
                                .map(|s| s.name)
                                .collect();
                            match cowfsck_volume_stores(&*js_store, &*js_store, &vol_id).await {
                                Ok(report) => {
                                    let report_bytes = serde_json::to_vec_pretty(&report)
                                        .unwrap_or_else(|_| b"{}".to_vec());
                                    let _ = write_file_vfs(
                                        &vfs,
                                        COWFSCK_REPORT_PATH,
                                        &report_bytes,
                                        0o444,
                                    )
                                    .await;
                                    let detail = if report.errors.is_empty() {
                                        format!("os-cowfs open failed: {e:?}")
                                    } else {
                                        report.errors.join("; ")
                                    };
                                    return Ok(enter_recovery(
                                        RecoveryReason::CorruptVolume {
                                            detail: detail.clone(),
                                            snapshots: snaps.clone(),
                                        },
                                        Some(existing_uuid.clone()),
                                        snaps,
                                        format!(
                                            "Stage 1 cowfsck detected corruption on volume {existing_uuid}: {detail}"
                                        ),
                                    ));
                                }
                                Err(Errno::EPROTONOSUPPORT) => {
                                    return Ok(enter_recovery(
                                        RecoveryReason::IncompatibleFormat {
                                            found_version: None,
                                            expected_version: COWFS_FORMAT_VERSION,
                                        },
                                        Some(existing_uuid.clone()),
                                        Vec::new(),
                                        "Incompatible os-cowfs format version (EPROTONOSUPPORT)."
                                            .into(),
                                    ));
                                }
                                Err(_) => {
                                    return Ok(enter_recovery(
                                        RecoveryReason::CorruptVolume {
                                            detail: format!("os-cowfs open failed: {e:?}"),
                                            snapshots: snaps.clone(),
                                        },
                                        Some(existing_uuid.clone()),
                                        snaps,
                                        format!(
                                            "Stage 1 cowfsck failed on volume {existing_uuid} ({e:?})."
                                        ),
                                    ));
                                }
                            }
                        }
                    }
                } else {
                    let (config, binder) = bind_dirty_flush_timer::<JsCowfsStore, JsCowfsStore>(
                        CowFsConfig::local_browser(Rc::clone(&clock))
                            .with_arena(ArenaConfig::fixed_32mib()),
                    );
                    match open_for_boot_stores_detailed(
                        Rc::clone(&js_store),
                        Rc::clone(&js_store),
                        None,
                        writer_mode.to_cowtree_mode(),
                        parsed_root_template.as_ref(),
                        parsed_root_template
                            .as_ref()
                            .map(|_| &VerifiedAssetBlobStore),
                        config,
                        || format!("vol-{}", crate::random_hex(8)),
                    )
                    .await
                    {
                        Ok(res) => (res, binder),
                        Err(BootOpenError::Errno(Errno::EPROTONOSUPPORT)) => {
                            return Ok(enter_recovery(
                                RecoveryReason::IncompatibleFormat {
                                    found_version: None,
                                    expected_version: COWFS_FORMAT_VERSION,
                                },
                                None,
                                Vec::new(),
                                "Incompatible os-cowfs format version (EPROTONOSUPPORT).".into(),
                            ));
                        }
                        Err(e) => {
                            let errno = e.errno();
                            return Ok(enter_recovery(
                                RecoveryReason::IoError {
                                    errno: format!("{errno:?}"),
                                    detail: format!("os-cowfs open failed: {errno:?}"),
                                },
                                None,
                                Vec::new(),
                                format!("Failed to open os-cowfs root volume ({errno:?})."),
                            ));
                        }
                    }
                };
                if let Some(ref rep) = opened.fsck_report {
                    let report_bytes =
                        serde_json::to_vec_pretty(rep).unwrap_or_else(|_| b"{}".to_vec());
                    let _ = write_file_vfs(&vfs, COWFSCK_REPORT_PATH, &report_bytes, 0o444).await;
                }
                opened_dirty_guard = Some(dirty_binder.attach(&opened.fs));

                // Only seed built-in dev defaults on a freshly formatted volume with NO verified
                // `RootTemplate` (Codex #7 & #24: never overwrite existing volumes or templates!).
                if !existing_volume_present && parsed_root_template.is_none() {
                    if let Err(e) = seed_fresh_cowfs_root(&*opened.fs).await {
                        let _ = opened.fs.close_clean().await;
                        return Ok(enter_recovery(
                            RecoveryReason::IoError {
                                errno: format!("{e:?}"),
                                detail: format!("failed to seed fresh os-cowfs root: {e:?}"),
                            },
                            Some(opened.volume_uuid),
                            Vec::new(),
                            format!("Failed to seed fresh os-cowfs root ({e:?})."),
                        ));
                    }
                    if let Err(e) = opened.fs.commit_tx_group().await {
                        let _ = opened.fs.close_clean().await;
                        return Ok(enter_recovery(
                            RecoveryReason::IoError {
                                errno: format!("{e:?}"),
                                detail: format!("failed to commit fresh os-cowfs seed: {e:?}"),
                            },
                            Some(opened.volume_uuid),
                            Vec::new(),
                            format!("Failed to commit initial os-cowfs root ({e:?})."),
                        ));
                    }
                    opened.first_boot_seeded = true;
                    opened.base_epoch = opened.fs.current_head().epoch;
                }

                // Persist first-boot minted volume UUID into profile & `/run/os/boot-profile.json`.
                if let RootSpec::CowFs {
                    volume_uuid: ref mut vu,
                    ..
                } = profile.root
                    && vu.is_none()
                {
                    *vu = Some(opened.volume_uuid.clone());
                }

                if let Some(ref parent) = opened.forked_from {
                    banners.push(format!(
                        "ForkOnBusy: booted on O(1) copy-on-write fork {} (parent {}); unmodified forks are pruned automatically on clean exit.",
                        opened.volume_uuid, parent
                    ));
                }

                // Attach `/dev/vd0` (`CowFsVolumeDevice`) and scratch `/dev/vd1` to local `/dev`.
                {
                    let (vblk, dev_fs, cowfs_ctx) = {
                        let rt = self.vfs_rt.borrow();
                        (
                            Rc::clone(&rt.vblk),
                            Rc::clone(&rt.dev_fs),
                            Rc::clone(&rt.cowfs_ctx),
                        )
                    };
                    {
                        let mut ctx = cowfs_ctx.borrow_mut();
                        ctx.store = Some(Rc::clone(&js_store));
                        ctx.active_volumes
                            .insert(opened.volume_uuid.clone(), Rc::clone(&opened.fs));
                    }
                    let _ = vblk.detach("vd0");
                    let _ = vblk.attach_named(
                        "vd0",
                        Rc::new(CowFsVolumeDevice::from_mounted(Rc::clone(&opened.fs))),
                    );
                    let _ = vblk.register_node(&dev_fs, "vd0", 0o660);
                    if vblk.get("vd1").is_none() {
                        let _ = vblk.attach_named(
                            "vd1",
                            Rc::new(CowFsVolumeDevice::unmounted(
                                VolumeId("scratch-vd1".to_string()),
                                Rc::clone(&js_store),
                                Rc::clone(&js_store),
                                abi::contract::WriterModel::Local,
                                abi::contract::Durability::TreeCommit,
                                Rc::new(now_timespec),
                            )),
                        );
                        let _ = vblk.register_node(&dev_fs, "vd1", 0o660);
                    }
                }

                mounted_root_source = format!("cowfs:{}", opened.volume_uuid);
                mounted_root_fs = Rc::clone(&opened.fs) as Rc<dyn Filesystem>;
                info = MountedRootInfo {
                    fstype: "cowfs".into(),
                    volume_uuid: opened.volume_uuid.clone(),
                    forked_from: opened.forked_from.clone(),
                    base_epoch: opened.base_epoch,
                    ephemeral_if_unmodified: opened.ephemeral_if_unmodified,
                    first_boot_seeded: opened.first_boot_seeded,
                    writer_mode,
                    mounted_at: now_secs(),
                };
                opened_cowfs = Some(opened.fs);
            }
        }

        let root_fs = mounted_root_fs;
        let profile_bytes = serde_json::to_vec_pretty(&profile).unwrap_or_else(|_| b"{}".to_vec());
        let _ = write_file_vfs(&vfs, BOOT_PROFILE_PATH, &profile_bytes, 0o444).await;
        let info_bytes =
            serde_json::to_vec_pretty(&info).map_err(|_| fail(Error::from(Errno::EIO)))?;
        let _ = write_file_vfs(&vfs, MOUNTED_ROOT_INFO_PATH, &info_bytes, 0o444).await;

        // 4. Mount prepared root at `/sysroot`, optional `@home`, Stage 2 `/usr`, fresh `/tmp`,
        //    preflight EVERY move destination + `/sysroot/usr/bin/init` + local `default_user`
        //    BEFORE detaching or moving any mounts, and roll back cleanly into Stage 1 Recovery
        //    on any pre-pivot failure (Codex Findings #7, #8, #24, #32)!
        let sys_ns = vfs.system_namespace();
        let mut root_cred = Cred::root();
        root_cred.umask = 0;
        let root_statfs = vfs
            .statfs(INIT, StartAnchor::Root, "/")
            .await
            .map_err(|e| fail(Error::from(e)))?;

        if root_statfs.f_type == fs_magic::TMPFS_MAGIC {
            let abort_before_pivot = |reason: RecoveryReason, msg: String| {
                let mut rt = self.vfs_rt.borrow_mut();
                rt.boot_profile = profile.clone();
                rt.boot_stage = BootStage::Stage1Recovery;
                rt.recovery = Some(RecoveryState {
                    reason,
                    volume_uuid: Some(info.volume_uuid.clone()),
                    available_snapshots: Vec::new(),
                    message: msg,
                });
                drop(rt);
                self.boot_status_json().to_string()
            };

            if let Err(e) = ensure_dir_vfs(&vfs, "/sysroot", 0o755).await {
                if let Some(fs) = opened_cowfs.take() {
                    let _ = fs.close_clean().await;
                }
                return Ok(abort_before_pivot(
                    RecoveryReason::IoError {
                        errno: format!("{e:?}"),
                        detail: format!("failed to prepare /sysroot: {e:?}"),
                    },
                    format!("Failed to prepare /sysroot mountpoint ({e:?})."),
                ));
            }
            let mut root_backing = MountBacking::new(root_fs, mounted_root_fstype);
            if let Some(ref cowfs) = opened_cowfs {
                root_backing = root_backing
                    .with_volume_device(Rc::new(CowFsVolumeDevice::from_mounted(Rc::clone(cowfs))));
            }
            if mounted_root_rdonly {
                root_backing = root_backing.with_ceilings(true, false);
            }
            if let Err(e) = vfs
                .mount_on_namespace(
                    &sys_ns,
                    &root_cred,
                    Rc::new(root_backing),
                    None,
                    &mounted_root_source,
                    "/sysroot",
                    MountFlags {
                        rdonly: mounted_root_rdonly,
                        ..MountFlags::default()
                    },
                    if mounted_root_rdonly {
                        mount_flags::MS_RDONLY
                    } else {
                        0
                    },
                    None,
                )
                .await
            {
                if let Some(fs) = opened_cowfs.take() {
                    let _ = fs.close_clean().await;
                }
                return Ok(abort_before_pivot(
                    RecoveryReason::IoError {
                        errno: format!("{e:?}"),
                        detail: format!("mount /sysroot failed: {e:?}"),
                    },
                    format!("Failed to mount root filesystem at /sysroot ({e:?})."),
                ));
            }

            // Mount RO `@home` subvolume on snapshot roots or RW `@home` subvolume on RW roots (Codex #32).
            if let Some(home_fs) = opened_ro_home_cowfs.take()
                && vfs
                    .statat(INIT, StartAnchor::Root, "/sysroot/home", false)
                    .await
                    .is_ok_and(|st| st.kind() == S_IFDIR)
            {
                let mut home_backing =
                    MountBacking::new(home_fs, FsType::Cowfs).with_ceilings(true, false);
                if let Some(ref cowfs) = opened_cowfs {
                    home_backing = home_backing.with_volume_device(Rc::new(
                        CowFsVolumeDevice::from_mounted(Rc::clone(cowfs)),
                    ));
                }
                let home_backing = Rc::new(home_backing);
                if let Err(e) = vfs
                    .mount_on_namespace(
                        &sys_ns,
                        &root_cred,
                        home_backing,
                        None,
                        &format!("{mounted_root_source}:@home"),
                        "/sysroot/home",
                        MountFlags {
                            rdonly: true,
                            ..MountFlags::default()
                        },
                        mount_flags::MS_RDONLY,
                        None,
                    )
                    .await
                {
                    teardown_sysroot_mounts(&vfs).await;
                    if let Some(fs) = opened_cowfs.take() {
                        let _ = fs.close_clean().await;
                    }
                    return Ok(abort_before_pivot(
                        RecoveryReason::IoError {
                            errno: format!("{e:?}"),
                            detail: format!("mount @home on /sysroot/home failed: {e:?}"),
                        },
                        format!("Failed to mount @home subvolume ({e:?})."),
                    ));
                }
            } else if !mounted_root_rdonly
                && let Some(ref cowfs) = opened_cowfs
                && cowfs.has_subvol("@home")
            {
                let mount_home_res: vfs::Result<()> = async {
                    ensure_dir_vfs(&vfs, "/sysroot/home", 0o755).await?;
                    let home_view = cowfs.open_subvol_view("@home")?;
                    let home_backing = Rc::new(
                        MountBacking::new(home_view, FsType::Cowfs).with_volume_device(Rc::new(
                            CowFsVolumeDevice::from_mounted(Rc::clone(cowfs)),
                        )),
                    );
                    vfs.mount_on_namespace(
                        &sys_ns,
                        &root_cred,
                        home_backing,
                        None,
                        &format!("{mounted_root_source}:@home"),
                        "/sysroot/home",
                        MountFlags::default(),
                        0,
                        None,
                    )
                    .await
                    .map(|_| ())
                }
                .await;
                if let Err(e) = mount_home_res {
                    teardown_sysroot_mounts(&vfs).await;
                    if let Some(fs) = opened_cowfs.take() {
                        let _ = fs.close_clean().await;
                    }
                    return Ok(abort_before_pivot(
                        RecoveryReason::IoError {
                            errno: format!("{e:?}"),
                            detail: format!("mount RW @home on /sysroot/home failed: {e:?}"),
                        },
                        format!("Failed to mount @home subvolume ({e:?})."),
                    ));
                }
            }

            // Ensure required `/sysroot` mountpoint directories exist (FAIL on non-dir like file/symlink!).
            let move_candidates = [
                "/proc",
                "/dev",
                "/run",
                "/mnt/local",
                "/mnt/shared",
                "/opt/private",
            ];
            let mut active_moves: Vec<&str> = Vec::new();
            for sub in move_candidates {
                if vfs
                    .statat(INIT, StartAnchor::Root, sub, false)
                    .await
                    .is_ok_and(|st| st.kind() == S_IFDIR)
                {
                    active_moves.push(sub);
                }
            }
            let preflight_dirs: Result<(), Errno> = async {
                for (path, mode) in [
                    ("/sysroot/usr", 0o755u16),
                    ("/sysroot/tmp", 0o1777u16),
                    ("/sysroot/proc", 0o555u16),
                    ("/sysroot/dev", 0o755u16),
                    ("/sysroot/run", 0o755u16),
                ] {
                    ensure_dir_vfs(&vfs, path, mode).await?;
                }
                for sub in &active_moves {
                    let dst = format!("/sysroot{sub}");
                    ensure_dir_vfs(&vfs, &dst, 0o755).await?;
                    let st = vfs.statat(INIT, StartAnchor::Root, &dst, false).await?;
                    if st.kind() != S_IFDIR {
                        return Err(Errno::ENOTDIR);
                    }
                }
                Ok(())
            }
            .await;
            if let Err(e) = preflight_dirs {
                teardown_sysroot_mounts(&vfs).await;
                if let Some(fs) = opened_cowfs.take() {
                    let _ = fs.close_clean().await;
                }
                return Ok(abort_before_pivot(
                    RecoveryReason::IoError {
                        errno: format!("{e:?}"),
                        detail: format!("switch_root preflight destination check failed: {e:?}"),
                    },
                    format!("Refusing to switch_root: destination mountpoint invalid ({e:?})."),
                ));
            }

            // Mount Stage 2 `/usr` (`ImageFs`, `ro,nodev`) at `/sysroot/usr`.
            let mounted_at = now_timespec();
            let usr_fs_id = FsId("image:usr".to_string());
            let sizes = opts
                .as_ref()
                .and_then(|o| o.build_asset_sizes)
                .unwrap_or_else(default_asset_sizes);
            let blob_store = VerifiedAssetBlobStore;
            let has_composition = opts
                .as_ref()
                .is_some_and(|o| o.system_composition.is_some() || o.base_image.is_some());
            let mut trusted_service_digests = HashMap::new();
            let usr_image = if let Some(base_json) =
                opts.as_ref().and_then(|o| o.base_image.as_ref())
            {
                let build_res: vfs::Result<(
                    ImageFs<VerifiedAssetBlobStore>,
                    HashMap<String, String>,
                )> = (|| {
                    let base_img = Image::parse(base_json.as_bytes()).map_err(|_| Errno::EINVAL)?;
                    let sup_digests = extract_service_digests_from_image(&base_img);
                    let mut ext_imgs = Vec::new();
                    if let Some(o) = opts.as_ref() {
                        for ext_json in &o.extension_images {
                            ext_imgs.push(
                                Image::parse(ext_json.as_bytes()).map_err(|_| Errno::EINVAL)?,
                            );
                        }
                    }
                    let entries =
                        crate::release_v2::compose_system_image_entries(&base_img, &ext_imgs)
                            .map_err(|_| Errno::EINVAL)?;
                    Ok((
                        ImageFs::new(usr_fs_id.clone(), true, mounted_at, entries, blob_store)?,
                        sup_digests,
                    ))
                })();
                match build_res {
                    Ok((img, sup)) => {
                        trusted_service_digests = sup;
                        img
                    }
                    Err(e) => {
                        teardown_sysroot_mounts(&vfs).await;
                        if let Some(fs) = opened_cowfs.take() {
                            let _ = fs.close_clean().await;
                        }
                        return Ok(abort_before_pivot(
                            RecoveryReason::IoError {
                                errno: format!("{e:?}"),
                                detail: format!(
                                    "invalid Release v2 base/extension composition: {e:?}"
                                ),
                            },
                            format!("Failed to compose Release v2 /usr ({e:?})."),
                        ));
                    }
                }
            } else if let Some(comp_json) =
                opts.as_ref().and_then(|o| o.system_composition.as_ref())
            {
                match ImageFs::from_composition_json(
                    usr_fs_id.clone(),
                    true,
                    mounted_at,
                    comp_json,
                    blob_store,
                ) {
                    Ok(img) => {
                        trusted_service_digests =
                            extract_service_digests_from_composition(comp_json);
                        img
                    }
                    Err(e) => {
                        teardown_sysroot_mounts(&vfs).await;
                        if let Some(fs) = opened_cowfs.take() {
                            let _ = fs.close_clean().await;
                        }
                        return Ok(abort_before_pivot(
                            RecoveryReason::IoError {
                                errno: format!("{e:?}"),
                                detail: format!("invalid system composition: {e:?}"),
                            },
                            format!("Failed to compose Release v2 /usr ({e:?})."),
                        ));
                    }
                }
            } else {
                ImageFs::from_build_assets_with_gui(
                    usr_fs_id.clone(),
                    sizes,
                    mounted_at,
                    blob_store,
                    opts.as_ref().map(|o| &o.gui_asset_sizes),
                )
            };
            let mut usr_blob_paths = HashMap::new();
            // Only populate build-asset HTTP shortcuts when NO verified Release v2 system
            // composition was supplied (Codex Finding #7).
            if !has_composition {
                for (bin_path, asset_url) in [
                    ("/usr/bin/init", "/usr/bin/init.wasm"),
                    ("/usr/bin/mountd", "/usr/bin/mountd.wasm"),
                    ("/usr/bin/exportd", "/usr/bin/exportd.wasm"),
                    ("/usr/bin/kubelet", "/usr/bin/kubelet.wasm"),
                    ("/usr/bin/compositor", "/usr/bin/compositor.wasm"),
                    ("/usr/bin/desktop-shell", "/usr/bin/desktop-shell.wasm"),
                    ("/usr/bin/greeter", "/usr/bin/greeter.wasm"),
                    ("/usr/bin/gui-sample-doc", "/usr/bin/gui-sample-doc.wasm"),
                    (
                        "/usr/bin/gui-sample-pixel",
                        "/usr/bin/gui-sample-pixel.wasm",
                    ),
                    ("/usr/bin/osh", "/usr/bin/osh.wasm"),
                    ("/usr/bin/terminal", "/usr/bin/terminal.wasm"),
                    ("/usr/bin/files", "/usr/bin/files.wasm"),
                    ("/usr/bin/mounts", "/usr/bin/mounts.wasm"),
                    ("/usr/bin/supervise", "/usr/bin/supervise.wasm"),
                    ("/usr/bin/dash", "/usr/bin/dash.wasm"),
                    ("/usr/bin/coreutils", "/usr/bin/coreutils.wasm"),
                    ("/usr/bin/utilities", "/usr/bin/utilities.wasm"),
                ] {
                    if let Some(h) = usr_image.handle_at(bin_path) {
                        usr_blob_paths.insert(h.node.ino, asset_url.to_string());
                    }
                }
            }
            let usr_subroot = usr_image.handle_at("/usr").map(|h| (h, "/usr".to_string()));
            let usr_backing = Rc::new(
                MountBacking::new(Rc::new(usr_image), FsType::Image).with_ceilings(true, false),
            );
            if let Err(e) = vfs
                .mount_on_namespace(
                    &sys_ns,
                    &root_cred,
                    usr_backing,
                    usr_subroot,
                    "usr",
                    "/sysroot/usr",
                    MountFlags {
                        rdonly: true,
                        nodev: true,
                        ..MountFlags::default()
                    },
                    mount_flags::MS_RDONLY | mount_flags::MS_NODEV,
                    None,
                )
                .await
            {
                teardown_sysroot_mounts(&vfs).await;
                if let Some(fs) = opened_cowfs.take() {
                    let _ = fs.close_clean().await;
                }
                return Ok(abort_before_pivot(
                    RecoveryReason::IoError {
                        errno: format!("{e:?}"),
                        detail: format!("mount /sysroot/usr failed: {e:?}"),
                    },
                    format!("Failed to mount Stage 2 /usr ({e:?})."),
                ));
            }

            // Preflight `/sysroot/usr/bin/init` executable regular file BEFORE moving mounts!
            let init_ok = vfs
                .statat(INIT, StartAnchor::Root, "/sysroot/usr/bin/init", true)
                .await
                .map(|st| st.kind() == S_IFREG && (st.mode & 0o111) != 0)
                .unwrap_or(false);
            if !init_ok {
                teardown_sysroot_mounts(&vfs).await;
                if let Some(fs) = opened_cowfs.take() {
                    let _ = fs.close_clean().await;
                }
                return Ok(abort_before_pivot(
                    RecoveryReason::IoError {
                        errno: "EACCES".into(),
                        detail: "/sysroot/usr/bin/init is missing or not executable".into(),
                    },
                    "Refusing to switch_root: /sysroot/usr/bin/init missing or non-executable."
                        .into(),
                ));
            }

            // Fresh `tmpfs` (`01777`, `nosuid,nodev`) at `/sysroot/tmp`.
            let tmp_fs = Rc::new(MemFs::new(
                FsId("tmpfs:stage2-tmp".to_string()),
                3,
                0,
                0,
                0o1777,
                Box::new(|| {
                    let ts = now_timespec();
                    (ts.sec, ts.nsec)
                }),
            ));
            let tmp_root = tmp_fs.root();
            let _ = tmp_fs
                .setattr(
                    &root_cred,
                    &tmp_root,
                    &SetAttr {
                        mode: Some(0o1777),
                        ..SetAttr::default()
                    },
                )
                .await;
            let tmp_backing = Rc::new(MountBacking::new(tmp_fs, FsType::TmpFs));
            if let Err(e) = vfs
                .mount_on_namespace(
                    &sys_ns,
                    &root_cred,
                    tmp_backing,
                    None,
                    "tmpfs",
                    "/sysroot/tmp",
                    MountFlags {
                        nosuid: true,
                        nodev: true,
                        ..MountFlags::default()
                    },
                    mount_flags::MS_NOSUID | mount_flags::MS_NODEV,
                    None,
                )
                .await
            {
                teardown_sysroot_mounts(&vfs).await;
                if let Some(fs) = opened_cowfs.take() {
                    let _ = fs.close_clean().await;
                }
                return Ok(abort_before_pivot(
                    RecoveryReason::IoError {
                        errno: format!("{e:?}"),
                        detail: format!("mount /sysroot/tmp failed: {e:?}"),
                    },
                    format!("Failed to mount /sysroot/tmp ({e:?})."),
                ));
            }

            // Contract §5 `switch_root` with strict error checking & pre-pivot rollback (Codex #8):
            // Retain `oldroot_fd`, `MS_MOVE` every active mount onto `/sysroot/...` recording each
            // completed move, then `chdir("/sysroot")`, `mount(".", "/", MS_MOVE)`, `chroot(".")`,
            // `chdir("/")`. On ANY failure prior to pivot, undo ALL completed moves in reverse
            // order, unmount `/sysroot/*`, and enter `Stage1Recovery` on the intact Stage 1 root!
            let oldroot_fd = match vfs
                .openat(
                    INIT,
                    StartAnchor::Root,
                    "/",
                    abi::O_RDONLY | abi::O_DIRECTORY,
                    0,
                )
                .await
            {
                Ok(fd) => fd,
                Err(e) => {
                    teardown_sysroot_mounts(&vfs).await;
                    if let Some(fs) = opened_cowfs.take() {
                        let _ = fs.close_clean().await;
                    }
                    return Ok(abort_before_pivot(
                        RecoveryReason::IoError {
                            errno: format!("{e:?}"),
                            detail: format!("open Stage 1 root fd failed: {e:?}"),
                        },
                        format!("Failed to open Stage 1 root ({e:?})."),
                    ));
                }
            };
            let oldroot_dev = match vfs.fstat(INIT, oldroot_fd).await {
                Ok(st) => st.dev,
                Err(e) => {
                    let _ = vfs.close(INIT, oldroot_fd).await;
                    teardown_sysroot_mounts(&vfs).await;
                    if let Some(fs) = opened_cowfs.take() {
                        let _ = fs.close_clean().await;
                    }
                    return Ok(abort_before_pivot(
                        RecoveryReason::IoError {
                            errno: format!("{e:?}"),
                            detail: format!("fstat Stage 1 root failed: {e:?}"),
                        },
                        format!("Failed to fstat Stage 1 root ({e:?})."),
                    ));
                }
            };

            let mut moved: Vec<(&str, String)> = Vec::new();
            let mut move_err: Option<(&str, Errno)> = None;
            for &sub in &active_moves {
                let dst = format!("/sysroot{sub}");
                match vfs
                    .mount(INIT, sub, &dst, None, mount_flags::MS_MOVE, None)
                    .await
                {
                    Ok(()) => moved.push((sub, dst)),
                    Err(e) => {
                        move_err = Some((sub, e));
                        break;
                    }
                }
            }
            if let Some((failed_sub, e)) = move_err {
                for (orig, target) in moved.into_iter().rev() {
                    let _ = vfs
                        .mount(INIT, &target, orig, None, mount_flags::MS_MOVE, None)
                        .await;
                }
                let _ = vfs.close(INIT, oldroot_fd).await;
                teardown_sysroot_mounts(&vfs).await;
                if let Some(fs) = opened_cowfs.take() {
                    let _ = fs.close_clean().await;
                }
                return Ok(abort_before_pivot(
                    RecoveryReason::IoError {
                        errno: format!("{e:?}"),
                        detail: format!(
                            "MS_MOVE {failed_sub} -> /sysroot{failed_sub} failed: {e:?}"
                        ),
                    },
                    format!(
                        "Refusing to switch_root: failed to move {failed_sub} ({e:?}); rolled back to Stage 1."
                    ),
                ));
            }

            // Detach Stage 1-only `/usr` & `/tmp` right before pivot (all moves succeeded!).
            let _ = vfs.umount2(INIT, "/usr", umount_flags::MNT_DETACH).await;
            let _ = vfs.umount2(INIT, "/tmp", umount_flags::MNT_DETACH).await;

            let pivot_res: vfs::Result<()> = async {
                vfs.chdir(INIT, "/sysroot").await?;
                vfs.mount(INIT, ".", "/", None, mount_flags::MS_MOVE, None)
                    .await?;
                Ok(())
            }
            .await;
            if let Err(e) = pivot_res {
                let _ = vfs.chdir(INIT, "/").await;
                for (orig, target) in moved.into_iter().rev() {
                    let _ = vfs
                        .mount(INIT, &target, orig, None, mount_flags::MS_MOVE, None)
                        .await;
                }
                let _ = vfs.close(INIT, oldroot_fd).await;
                teardown_sysroot_mounts(&vfs).await;
                if let Some(fs) = opened_cowfs.take() {
                    let _ = fs.close_clean().await;
                }
                return Ok(abort_before_pivot(
                    RecoveryReason::IoError {
                        errno: format!("{e:?}"),
                        detail: format!("switch_root pivot failed: {e:?}"),
                    },
                    format!("switch_root pivot failed ({e:?}); rolled back to Stage 1."),
                ));
            }

            vfs.chroot(INIT, ".")
                .await
                .map_err(|e| fail(Error::from(e)))?;
            vfs.chdir(INIT, "/")
                .await
                .map_err(|e| fail(Error::from(e)))?;
            let mut reclaimed = 0usize;
            unlink_oldroot_bounded(&vfs, oldroot_fd, oldroot_dev, &mut reclaimed).await;
            let _ = vfs.close(INIT, oldroot_fd).await;

            // Optional bind mounts from `opts`.
            if let Some(o) = opts {
                for bm in o.bind_mounts {
                    let mut mflags = mount_flags::MS_BIND;
                    if bm.read_only {
                        mflags |= mount_flags::MS_RDONLY;
                    }
                    let _ = vfs
                        .mount(INIT, &bm.source, &bm.target, None, mflags, None)
                        .await;
                }
            }

            let mut rt = self.vfs_rt.borrow_mut();
            rt.usr_fs_id = usr_fs_id;
            rt.usr_blob_paths = usr_blob_paths;
            rt.trusted_service_digests = trusted_service_digests;
            rt.stage1_reclaimed_entries = reclaimed;
        }

        // Resolve configured local auto-login user (`BootProfile.default_user`) strictly from
        // local `/etc/passwd` + `/etc/group`. NEVER synthesize hardcoded UID 1000 `wheel` on
        // missing/deleted user or parse error (Codex Finding #24)!
        match self
            .resolve_local_user_account(&vfs, &profile.default_user)
            .await
        {
            Ok(account) => {
                {
                    let mut rt = self.vfs_rt.borrow_mut();
                    rt.root_cowfs = opened_cowfs;
                    rt.root_dirty_guard = opened_dirty_guard;
                    rt.mounted_root = Some(info);
                    rt.boot_profile = profile.clone();
                    rt.boot_stage = BootStage::Stage2;
                    rt.recovery = None;
                    rt.banners = banners;
                }
                self.apply_account_update(account);
                self.refresh_local_account_caches(&vfs).await;
                Ok(self.boot_status_json().to_string())
            }
            Err(err) => {
                let detail = err.text().to_string();
                {
                    let mut rt = self.vfs_rt.borrow_mut();
                    rt.root_cowfs = opened_cowfs;
                    rt.root_dirty_guard = opened_dirty_guard;
                    rt.mounted_root = Some(info.clone());
                    rt.boot_profile = profile.clone();
                    rt.boot_stage = BootStage::Stage1Recovery;
                    rt.recovery = Some(RecoveryState {
                        reason: RecoveryReason::AccountResolutionFailed {
                            default_user: profile.default_user.clone(),
                            detail: detail.clone(),
                        },
                        volume_uuid: Some(info.volume_uuid),
                        available_snapshots: Vec::new(),
                        message: format!(
                            "Failed to resolve configured default_user {:?} from /etc/passwd: {detail}",
                            profile.default_user
                        ),
                    });
                    rt.banners = banners;
                }
                self.apply_account_update(LocalAccount::signed_out_nobody());
                Ok(self.boot_status_json().to_string())
            }
        }
    }

    /// Cleanly commit, prune unmodified `ForkOnBusy` fork if applicable, and release the `os-cowfs`
    /// root volume Web Lock (called on clean shutdown / non-persisted `pagehide`).
    ///
    /// Codex Finding #15: retains `rt.root_cowfs` in a retryable state until durable close succeeds
    /// and preserves honest `shutdown_marker.clean` status.
    pub async fn close_clean_root(&self) -> Result<String, JsValue> {
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let mut shutdown_marker: Option<Value> = None;
        if let Ok(fd) = vfs
            .openat(INIT, StartAnchor::Root, "/run/os/shutdown", 0, 0)
            .await
        {
            let mut buf = [0u8; 4096];
            if let Ok(n) = vfs.read(INIT, fd, &mut buf).await
                && let Ok(val) = serde_json::from_slice::<Value>(&buf[..n])
            {
                shutdown_marker = Some(val);
            }
            let _ = vfs.close(INIT, fd).await;
        }
        let (cowfs, base_epoch) = {
            let rt = self.vfs_rt.borrow();
            let base = rt.mounted_root.as_ref().map_or(0, |m| m.base_epoch);
            (rt.root_cowfs.clone(), base)
        };
        let ctx = Rc::clone(&self.vfs_rt.borrow().cowfs_ctx);
        let outcome = crate::remote_volume_bridge::close_for_shutdown(&ctx, async |finish| {
            let Some(fs) = cowfs else { return Ok(None) };
            if finish {
                close_clean_with_prune_fs(&fs, base_epoch).await.map(Some)
            } else {
                // Persist local writes and keep the root available for a shutdown retry.
                fs.flush_for_suspend().await?;
                Ok(None)
            }
        })
        .await
        .map_err(|e| {
            self.vfs_rt.borrow_mut().last_shutdown = Some(json!({"clean":false, "errno":e}));
            fail(Error::from(e))
        })?;
        let Some(outcome) = outcome else {
            if let Some(marker) = shutdown_marker {
                self.vfs_rt.borrow_mut().last_shutdown = Some(marker);
            }
            return Ok(json!({ "closed": false, "pruned": false }).to_string());
        };
        let recorded = shutdown_marker.unwrap_or_else(|| json!({ "clean": true }));
        let clean = recorded
            .get("clean")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let mut rt = self.vfs_rt.borrow_mut();
        rt.root_dirty_guard = None;
        rt.root_cowfs = None;
        rt.last_shutdown = Some(recorded.clone());
        Ok(json!({
            "closed": true,
            "clean": clean,
            "pruned": outcome.pruned,
            "retained": outcome.retained,
            "volume_uuid": outcome.volume_uuid,
            "shutdown": recorded,
        })
        .to_string())
    }

    /// Flush dirty writes on the mounted `os-cowfs` root WITHOUT closing the volume or releasing
    /// its writer lock, for resumable bfcache suspension (`pagehide` with `event.persisted === true`,
    /// Codex Finding #16). Does not mutate unmodified ephemeral forks.
    pub async fn flush_root(&self) -> Result<String, JsValue> {
        let cowfs = self.vfs_rt.borrow().root_cowfs.clone();
        let Some(fs) = cowfs else {
            return Ok(json!({ "flushed": false }).to_string());
        };
        let before_epoch = fs.current_head().epoch;
        let head = fs
            .flush_for_suspend()
            .await
            .map_err(|e| fail(Error::from(e)))?;
        Ok(json!({
            "flushed": head.epoch != before_epoch,
            "epoch": head.epoch,
            "volume_uuid": head.volume.0,
        })
        .to_string())
    }

    /// Return current Cloud / Cluster Sign-In status (ZERO network RPCs).
    pub fn cloud_status(&self) -> String {
        self.cloud_status_json().to_string()
    }

    /// Worker-private credential for the authenticated local login's relay calls.
    pub fn relay_credential(&self, uid: u32) -> Result<String, JsValue> {
        let st = self.state.borrow();
        let cs = st
            .cloud_session
            .as_ref()
            .filter(|cs| {
                st.account.signed_in
                    && st.account.uid == uid
                    && cs.local_uid == uid
                    && cs.login_generation == st.account_epoch
                    && cs.scope.relay
                    && !cs.revoked
            })
            .ok_or_else(|| crate::vfs_engine::map_errno(abi::Errno::EACCES))?;
        Ok(json!({"X-Process-Token": cs.page_token, "X-OS-Instance": st.instance_id}).to_string())
    }

    /// Explicitly attach a Cloud / Cluster service session AFTER `/api/cloud-auth/login` has set
    /// the browser's cloud session cookie.
    /// - NEVER alters local `/etc/passwd`, local `state.account`, or local process UIDs!
    /// - Writes `/run/user/<local_uid>/cloud-creds.json` (`0600`) owned by local UID.
    /// - Mounts optional `FsType::Cloud` at `/mnt/cloud` (if `scope.cloud_fs`).
    /// - Attaches explicitly scoped remote devices (`scope.devices`).
    pub async fn cloud_sign_in(
        &self,
        cloud_user: &str,
        cloud_uid: u32,
        cloud_gid: u32,
        cloud_groups_json: Option<String>,
        scope_json: Option<String>,
    ) -> Result<String, JsValue> {
        if cloud_user.is_empty() {
            return Err(fail(Error::because(
                Errno::EINVAL,
                "cloud_user is required",
            )));
        }
        let mut cloud_groups: Vec<u32> = match cloud_groups_json.as_deref() {
            Some(s) if !s.is_empty() && s != "null" => serde_json::from_str(s)
                .map_err(|e| fail(Error::because(Errno::EINVAL, e.to_string())))?,
            _ => vec![cloud_gid],
        };
        if !cloud_groups.contains(&cloud_gid) {
            cloud_groups.push(cloud_gid);
        }
        let scope: RemoteScope = match scope_json.as_deref() {
            Some(s) if !s.is_empty() && s != "null" => serde_json::from_str(s)
                .map_err(|e| fail(Error::because(Errno::EINVAL, e.to_string())))?,
            _ => RemoteScope::full(),
        };

        // Capture local `(uid, login_generation)` BEFORE awaiting remote credential minting
        // (Codex Finding #23: reject if the cookie resolved to a different `cloud_uid` OR if the
        // local account changed mid-flight, revoking the orphaned token immediately).
        let (start_local_uid, start_local_gid, start_gen) = {
            let st = self.state.borrow();
            (st.account.uid, st.account.gid, st.account_epoch)
        };

        // Negotiate ServiceAuth v2 instance attachment and mint a non-elevated (`sudo: false`)
        // service credential matching the authenticated cloud cookie!
        let (instance_id, host_proof) = ensure_remote_attached_state(&self.state)
            .await
            .map_err(fail)?;
        let resp = service_auth_request(&auth_v2::Request::MintServiceCred(MintServiceCred {
            instance_id,
            host_proof,
            scope: scope.clone(),
            cloud_access: scope.cloud_fs,
            umask: 0o022,
            cgroup: None,
            generation: None,
            sudo: false,
            rbps: None,
            wbps: None,
        }))
        .await
        .map_err(fail)?;
        let issued = match resp {
            auth_v2::Response::Cred(c) => c,
            _ => {
                return Err(fail(Error::because(
                    Errno::EIO,
                    "unexpected service cred reply",
                )));
            }
        };

        // Verify minted subject matches the authenticated `/api/cloud-auth/login` numeric UID!
        if issued.uid != cloud_uid {
            if !issued.token.is_empty() {
                revoke_remote_tokens_state(&self.state, vec![issued.token]).await;
            }
            return Err(fail(Error::because(
                Errno::EACCES,
                format!(
                    "cloud subject mismatch: login returned uid {cloud_uid}, mint returned uid {}",
                    issued.uid
                ),
            )));
        }

        // Recheck local UID & login generation after async mint (Codex #1 & #23).
        let (cur_local_uid, cur_gen) = {
            let st = self.state.borrow();
            (st.account.uid, st.account_epoch)
        };
        if cur_local_uid != start_local_uid || cur_gen != start_gen {
            if !issued.token.is_empty() {
                revoke_remote_tokens_state(&self.state, vec![issued.token]).await;
            }
            return Err(fail(Error::because(
                Errno::ESTALE,
                "local account changed while completing cloud sign-in",
            )));
        }

        let local_uid = start_local_uid;
        let local_gid = start_local_gid;
        let prev_session = {
            let mut st = self.state.borrow_mut();
            let old = st
                .cloud_session
                .as_ref()
                .map(|c| (c.cloud_uid, c.page_token.clone()));
            st.cloud_session = Some(CloudSession {
                cloud_user: cloud_user.to_string(),
                cloud_uid: issued.uid,
                cloud_gid: issued.gid,
                cloud_groups: issued.groups.clone(),
                local_uid,
                login_generation: start_gen,
                scope: issued.scope.clone(),
                page_token: issued.token.clone(),
                signed_in_at: now_secs(),
                revoked: false,
            });
            old
        };
        if let Some((old_uid, old_tok)) = prev_session {
            self.exports.close_relay();
            if old_uid != issued.uid {
                self.cloud.clear();
                self.vfs_rt.borrow().cloud_mount.clear_cached_state();
            }
            if !old_tok.is_empty() {
                revoke_remote_tokens_state(&self.state, vec![old_tok]).await;
            }
        }

        // Write `/run/user/<local_uid>/cloud-creds.json` with mode `0600` (owned by local UID).
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let user_run_dir = format!("/run/user/{local_uid}");
        let _ = ensure_dir_vfs(&vfs, "/run/user", 0o755).await;
        let _ = ensure_dir_vfs(&vfs, &user_run_dir, 0o700).await;
        let _ = vfs
            .setattrat(
                INIT,
                StartAnchor::Root,
                &user_run_dir,
                &SetAttr {
                    uid: Some(local_uid),
                    gid: Some(local_gid),
                    ..SetAttr::default()
                },
                false,
            )
            .await;
        let creds_path = format!("{user_run_dir}/cloud-creds.json");
        let creds_bytes = serde_json::to_vec_pretty(&json!({
            "signed_in": true,
            "cloud_user": cloud_user,
            "cloud_uid": issued.uid,
            "scope": issued.scope,
            "signed_in_at": now_secs(),
        }))
        .unwrap_or_else(|_| b"{}".to_vec());
        let _ = write_file_vfs(&vfs, &creds_path, &creds_bytes, 0o600).await;
        let _ = vfs
            .setattrat(
                INIT,
                StartAnchor::Root,
                &creds_path,
                &SetAttr {
                    uid: Some(local_uid),
                    gid: Some(local_gid),
                    ..SetAttr::default()
                },
                false,
            )
            .await;

        // Mount optional `/mnt/cloud` when authorized by scope.
        if issued.scope.cloud_fs {
            let _ = self.mount_cloud_fs_internal().await;
        }
        // Attach requested remote devices (`archive`, `media`, `present`, `snd`).
        for dev in &issued.scope.devices {
            if vfs::devfs::REMOTE_DEVICE_DRIVERS.contains(&dev.as_str()) {
                let _ = self.attach_remote_device(dev, None, "browser").await;
            }
        }

        Ok(self.cloud_status_json().to_string())
    }

    /// Explicitly sign out of Cloud / Cluster:
    /// - Clears local authority IMMEDIATELY (unmounts `/mnt/cloud`, detaches all remote devices,
    ///   drops active tokens from `LocalProcessTable`, removes `/run/user/<uid>/cloud-creds.json`).
    /// - Retains pending remote token revocations and instance detach until acknowledged by the
    ///   server (Codex Finding #27 — never drops pending revocations before network ack!).
    /// - NEVER kills, signals, or logs out any local process or local account!
    pub async fn cloud_sign_out(&self) -> Result<String, JsValue> {
        self.exports.close_relay();
        self.unmount_cloud_fs_internal();
        self.detach_all_remote_devices();

        let local_uid = {
            let mut st = self.state.borrow_mut();
            let mut toks = st.table.active_remote_tokens();
            toks.extend(std::mem::take(&mut st.volume_tokens));
            if let Some(cs) = st.cloud_session.take()
                && !cs.page_token.is_empty()
                && !toks.contains(&cs.page_token)
            {
                toks.push(cs.page_token);
            }
            for tok in &toks {
                st.table.drop_revoked_remote_token(tok);
                if !st.pending_revocations.contains(tok) {
                    st.pending_revocations.push(tok.clone());
                }
            }
            if st.remote_attached {
                st.pending_detach = true;
            }
            st.account.uid
        };

        // Sync process VFS creds to clear remote tokens immediately (keeping local processes alive!).
        let pids: Vec<u32> = self.state.borrow().table.all_pids();
        for pid in pids {
            if pid != INIT {
                self.sync_vfs_proc_creds(pid);
            }
        }

        self.cloud.clear();
        self.vfs_rt.borrow().cloud_mount.clear_cached_state();

        let vfs = self.vfs_rt.borrow().vfs.clone();
        let _ = vfs
            .unlinkat(
                INIT,
                StartAnchor::Root,
                &format!("/run/user/{local_uid}/cloud-creds.json"),
                false,
            )
            .await;

        let _ = self.flush_pending_cloud_revocations_internal().await;
        Ok(self.cloud_status_json().to_string())
    }

    async fn flush_pending_cloud_revocations_internal(&self) -> bool {
        if crate::cloudfs::installed("serviceAuthPost").is_err() {
            let st = self.state.borrow();
            return st.pending_revocations.is_empty() && !st.pending_detach;
        }
        let (instance_id, host_proof, pending_tokens, want_detach) = {
            let st = self.state.borrow();
            (
                st.instance_id.clone(),
                st.host_proof.clone(),
                st.pending_revocations.clone(),
                st.pending_detach,
            )
        };
        for chunk in pending_tokens.chunks(auth_v2::TOKENS_MAX.max(1)) {
            let ok = service_auth_request(&auth_v2::Request::RevokeTokens(auth_v2::RevokeTokens {
                instance_id: instance_id.clone(),
                host_proof: host_proof.clone(),
                tokens: chunk.to_vec(),
            }))
            .await
            .is_ok();
            if ok {
                let mut st = self.state.borrow_mut();
                st.pending_revocations.retain(|t| !chunk.contains(t));
            }
        }
        if want_detach {
            let detach_ok =
                service_auth_request(&auth_v2::Request::DetachInstance(DetachInstance {
                    instance_id,
                    host_proof,
                }))
                .await
                .is_ok();
            if detach_ok {
                let mut st = self.state.borrow_mut();
                st.pending_detach = false;
                st.remote_attached = false;
            }
        }
        let st = self.state.borrow();
        st.pending_revocations.is_empty() && !st.pending_detach
    }

    /// Retry any queued remote token revocations and instance detach left over from an offline
    /// or transiently failed `cloud_sign_out` (Codex Finding #27).
    pub async fn flush_pending_cloud_revocations(&self) -> Result<String, JsValue> {
        let _ = self.flush_pending_cloud_revocations_internal().await;
        Ok(self.cloud_status_json().to_string())
    }

    /// Revoke active `ServiceAuth v2` remote tokens on the server while keeping `/mnt/cloud`
    /// mounted and all local processes alive (verifies non-fatal remote revocation -> `EACCES`).
    pub async fn revoke_cloud_tokens_only(&self) -> Result<String, JsValue> {
        self.exports.close_relay();
        let (attached, instance_id, host_proof, tokens) = {
            let mut st = self.state.borrow_mut();
            let mut toks = st.table.active_remote_tokens();
            toks.extend(std::mem::take(&mut st.volume_tokens));
            if let Some(ref mut cs) = st.cloud_session {
                cs.revoked = true;
                if !cs.page_token.is_empty() {
                    if !toks.contains(&cs.page_token) {
                        toks.push(cs.page_token.clone());
                    }
                    cs.page_token.clear();
                }
            }
            for tok in &toks {
                st.table.drop_revoked_remote_token(tok);
                if !st.pending_revocations.contains(tok) {
                    st.pending_revocations.push(tok.clone());
                }
            }
            (
                st.remote_attached,
                st.instance_id.clone(),
                st.host_proof.clone(),
                toks,
            )
        };
        let pids: Vec<u32> = self.state.borrow().table.all_pids();
        for pid in pids {
            if pid != INIT {
                self.sync_vfs_proc_creds(pid);
            }
        }
        let count = tokens.len();
        if attached && !tokens.is_empty() && crate::cloudfs::installed("serviceAuthPost").is_ok() {
            let _ = service_auth_request(&auth_v2::Request::RevokeTokens(auth_v2::RevokeTokens {
                instance_id,
                host_proof,
                tokens,
            }))
            .await;
        }
        self.cloud.clear();
        self.vfs_rt.borrow().cloud_mount.clear_cached_state();
        Ok(json!({ "revoked": count }).to_string())
    }

    // -------------------------------------------------------------------------
    // Standalone Two-Stage Offline Boot (`console-window.js`, Codex Findings #2 & #10):
    // Drives real Stage 1 `/init` (`early_init.wasm`) -> `switch_root` -> Stage 2 `/usr/bin/init`
    // (`init.wasm`) through the executor as PID 1, then attaches console operations to a separate
    // non-PID-1 login process & local `/dev/pts/0` PTY.
    // -------------------------------------------------------------------------

    /// Stage 0 -> Stage 1 setup for standalone offline boot on `Kernel`:
    /// replaces Stage 1 `tmpfs` with verified `Kind::Initramfs`, mounts Stage 1 `/usr`, prepares
    /// `/sysroot` (`os-cowfs` / `snapshot` / `ephemeral`), `/sysroot/usr`, `/sysroot/tmp`, `/dev/vd0`,
    /// `/run/os/boot-profile.json`, and `/run/os/root` — leaving `/` as Stage 1 `tmpfs` so the
    /// executor runs the real packaged `/init` -> `switch_root` -> `/usr/bin/init` chain as PID 1!
    #[allow(clippy::too_many_arguments)]
    pub async fn boot_stage1_standalone(
        &self,
        store: JsValue,
        boot_profile_json: String,
        initramfs_json: String,
        root_template_json: String,
        base_json: String,
        extensions_json: JsValue,
    ) -> Result<String, JsValue> {
        let mut profile: BootProfile = serde_json::from_str(&boot_profile_json).map_err(|e| {
            fail(Error::because(
                Errno::EINVAL,
                format!("invalid boot profile: {e}"),
            ))
        })?;
        profile.validate().map_err(|e| fail(Error::from(e)))?;

        let initramfs = Image::parse(initramfs_json.as_bytes()).map_err(|e| {
            fail(Error::because(
                Errno::EINVAL,
                format!("invalid initramfs: {e}"),
            ))
        })?;
        let root_template = Image::parse(root_template_json.as_bytes()).map_err(|e| {
            fail(Error::because(
                Errno::EINVAL,
                format!("invalid root_template: {e}"),
            ))
        })?;
        let base = Image::parse(base_json.as_bytes())
            .map_err(|e| fail(Error::because(Errno::EINVAL, format!("invalid base: {e}"))))?;
        if initramfs.kind != Kind::Initramfs
            || root_template.kind != Kind::RootTemplate
            || base.kind != Kind::Base
        {
            return Err(fail(Error::from(Errno::EINVAL)));
        }
        let mut extensions = Vec::new();
        if !extensions_json.is_undefined() && !extensions_json.is_null() {
            let arr = js_sys::Array::from(&extensions_json);
            for i in 0..arr.length() {
                let text = arr.get(i).as_string().ok_or_else(|| {
                    fail(Error::because(
                        Errno::EINVAL,
                        "extensions_json must be string array",
                    ))
                })?;
                extensions.push(Image::parse(text.as_bytes()).map_err(|e| {
                    fail(Error::because(
                        Errno::EINVAL,
                        format!("invalid extension: {e}"),
                    ))
                })?);
            }
        }

        // Populate Stage 1 tmpfs `/` cleanly from verified `Kind::Initramfs` and mount Stage 1 `/usr`.
        let now = now_timespec();
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let sys_ns = vfs.system_namespace();
        let mut root_cred = Cred::root();
        root_cred.umask = 0;

        // Replace Stage 1 `/usr` with verified `Kind::Initramfs` `/usr` (`ro,nodev`), remove
        // desktop-only tmpfs carriers from Stage 1 `/` so `switch_root` reclaims Stage 1 `tmpfs`
        // completely, and populate Stage 1 `/` entries (`/init`, `/bin`, `/sbin`, `/lib`, `/lib64`).
        for stage1_drop in ["/usr", "/tmp", "/mnt/local", "/mnt/shared", "/opt/private"] {
            let _ = vfs
                .umount2(INIT, stage1_drop, umount_flags::MNT_DETACH)
                .await;
        }
        let stage1_usr_entries = crate::release_v2::image_to_vfs_entries(&initramfs);
        let stage1_usr_fs = ImageFs::new(
            FsId("image:stage1-usr".to_string()),
            true,
            now,
            stage1_usr_entries,
            VerifiedAssetBlobStore,
        )
        .map_err(|e| fail(Error::from(e)))?;
        if let Some(subroot) = stage1_usr_fs
            .handle_at("/usr")
            .map(|h| (h, "/usr".to_string()))
        {
            let usr_backing = Rc::new(
                MountBacking::new(Rc::new(stage1_usr_fs), FsType::Image).with_ceilings(true, false),
            );
            vfs.mount_on_namespace(
                &sys_ns,
                &root_cred,
                usr_backing,
                Some(subroot),
                "initramfs-usr",
                "/usr",
                MountFlags {
                    rdonly: true,
                    nodev: true,
                    ..MountFlags::default()
                },
                mount_flags::MS_RDONLY | mount_flags::MS_NODEV,
                None,
            )
            .await
            .map_err(|e| fail(Error::from(e)))?;
        }
        // Remove pre-seeded merged-`/usr` symlinks on Stage 1 `tmpfs` so `Kind::Initramfs`
        // directories like `/bin` populate cleanly without hitting `ENOTDIR`!
        for link in ["/bin", "/sbin", "/lib", "/lib64"] {
            let _ = vfs.unlinkat(INIT, StartAnchor::Root, link, false).await;
        }
        // Populate Stage 1 `/init` and initramfs root files/symlinks onto Stage 1 `tmpfs` `/`.
        let mut stage1_entry_count = 0usize;
        for entry in &initramfs.entries {
            if entry.path == "/" || entry.path.starts_with("/usr/") {
                continue;
            }
            stage1_entry_count += 1;
            match &entry.node {
                Node::Directory => {
                    let _ = ensure_dir_vfs(&vfs, &entry.path, entry.mode).await;
                }
                Node::File {
                    sha256,
                    size,
                    chunk_size,
                    chunks,
                } => {
                    let data = read_verified_image_file(
                        &VerifiedAssetBlobStore,
                        sha256,
                        *size,
                        *chunk_size,
                        chunks,
                    )
                    .await
                    .map_err(|e| fail(Error::from(e)))?;
                    write_file_vfs(&vfs, &entry.path, &data, entry.mode)
                        .await
                        .map_err(|e| fail(Error::from(e)))?;
                }
                Node::Symlink { target } => {
                    let _ = vfs
                        .unlinkat(INIT, StartAnchor::Root, &entry.path, false)
                        .await;
                    let _ = vfs
                        .symlinkat(INIT, target, StartAnchor::Root, &entry.path)
                        .await;
                }
            }
        }
        {
            let mut rt = self.vfs_rt.borrow_mut();
            rt.usr_blob_paths.clear();
            rt.stage1_reclaimed_entries = stage1_entry_count.max(1);
            rt.boot_stage = BootStage::Stage1;
            rt.recovery = None;
            rt.banners.clear();
            rt.fsck_report = None;
        }

        // Write `/run/os/boot-profile.json` (`0444`).
        let profile_bytes = serde_json::to_vec_pretty(&profile).unwrap_or_else(|_| b"{}".to_vec());
        let _ = write_file_vfs(&vfs, BOOT_PROFILE_PATH, &profile_bytes, 0o444).await;

        let js_store = Rc::new(JsCowfsStore { obj: store });
        let enter_recovery = |prof: &BootProfile,
                              reason: RecoveryReason,
                              vol: Option<String>,
                              snaps: Vec<String>,
                              msg: String,
                              fsck_rep: Option<cowfs::FsckReport>| {
            let mut rt = self.vfs_rt.borrow_mut();
            rt.boot_profile = prof.clone();
            rt.boot_stage = BootStage::Stage1Recovery;
            rt.fsck_report = fsck_rep;
            rt.recovery = Some(RecoveryState {
                reason,
                volume_uuid: vol,
                available_snapshots: snaps,
                message: msg,
            });
            drop(rt);
            self.standalone_status_json().to_string()
        };

        if profile.recovery {
            let vol = match &profile.root {
                RootSpec::CowFs { volume_uuid, .. } => volume_uuid.clone(),
                RootSpec::Snapshot { volume_uuid, .. } => Some(volume_uuid.clone()),
                RootSpec::Ephemeral | RootSpec::CloudOptIn { .. } => None,
            };
            let snaps = match &vol {
                Some(v) => js_store
                    .list_snapshots(&VolumeId(v.clone()))
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .map(|s| s.name)
                    .collect(),
                None => Vec::new(),
            };
            return Ok(enter_recovery(
                &profile,
                RecoveryReason::Requested,
                vol,
                snaps,
                "Boot profile requested Stage 1 recovery chooser.".into(),
                None,
            ));
        }

        let mut opened_cowfs: Option<Rc<CowFs<JsCowfsStore, JsCowfsStore>>> = None;
        let mut opened_dirty_guard: Option<DirtyFlushGuard> = None;
        let mut opened_ro_home: Option<Rc<dyn Filesystem>> = None;
        let root_fs: Rc<dyn Filesystem>;
        let mut root_fstype = FsType::Cowfs;
        let mut root_rdonly = false;
        let root_source: String;
        let info: MountedRootInfo;
        let mut banners: Vec<String> = Vec::new();
        let mut fsck_report: Option<cowfs::FsckReport> = None;

        match profile.root.clone() {
            RootSpec::CloudOptIn { .. } => {
                return Ok(enter_recovery(
                    &profile,
                    RecoveryReason::IoError {
                        errno: "EOPNOTSUPP".into(),
                        detail: "Standalone boot requires local root".into(),
                    },
                    None,
                    Vec::new(),
                    "Standalone offline boot requires a local CowFs, Snapshot, or Ephemeral root."
                        .into(),
                    None,
                ));
            }
            RootSpec::Ephemeral => {
                let eph = Rc::new(MemFs::new(
                    FsId("tmpfs:ephemeral-root".to_string()),
                    4,
                    0,
                    0,
                    0o755,
                    Box::new(|| {
                        let ts = now_timespec();
                        (ts.sec, ts.nsec)
                    }),
                ));
                if let Err(e) = populate_ephemeral_memfs(&eph, Some(&root_template)).await {
                    return Ok(enter_recovery(
                        &profile,
                        RecoveryReason::IoError {
                            errno: format!("{e:?}"),
                            detail: format!("failed to populate ephemeral root: {e:?}"),
                        },
                        None,
                        Vec::new(),
                        format!("Failed to populate ephemeral root ({e:?})."),
                        None,
                    ));
                }
                root_fs = eph as Rc<dyn Filesystem>;
                root_fstype = FsType::TmpFs;
                root_source = "tmpfs:ephemeral".into();
                info = MountedRootInfo {
                    fstype: "tmpfs".into(),
                    volume_uuid: "ephemeral".into(),
                    forked_from: None,
                    base_epoch: 0,
                    ephemeral_if_unmodified: true,
                    first_boot_seeded: true,
                    writer_mode: BootWriterMode::ForkOnBusy,
                    mounted_at: now_secs(),
                };
            }
            RootSpec::Snapshot {
                volume_uuid,
                snapshot,
            } => {
                match js_store.format_version().await {
                    Ok(Some(ver)) if ver != COWFS_FORMAT_VERSION => {
                        return Ok(enter_recovery(
                            &profile,
                            RecoveryReason::IncompatibleFormat {
                                found_version: Some(ver),
                                expected_version: COWFS_FORMAT_VERSION,
                            },
                            Some(volume_uuid),
                            Vec::new(),
                            format!(
                                "Refusing to mount incompatible os-cowfs format version {ver} (expected {COWFS_FORMAT_VERSION}): EPROTONOSUPPORT."
                            ),
                            None,
                        ));
                    }
                    Ok(_) => {}
                    Err(Errno::EPROTONOSUPPORT) => {
                        return Ok(enter_recovery(
                            &profile,
                            RecoveryReason::IncompatibleFormat {
                                found_version: None,
                                expected_version: COWFS_FORMAT_VERSION,
                            },
                            Some(volume_uuid),
                            Vec::new(),
                            "Incompatible os-cowfs format version (EPROTONOSUPPORT).".into(),
                            None,
                        ));
                    }
                    Err(e) => {
                        return Ok(enter_recovery(
                            &profile,
                            RecoveryReason::IoError {
                                errno: format!("{e:?}"),
                                detail: format!("format version probe failed: {e:?}"),
                            },
                            Some(volume_uuid),
                            Vec::new(),
                            format!("Failed to probe format version ({e:?})."),
                            None,
                        ));
                    }
                }
                let vol_id = VolumeId(volume_uuid.clone());
                let snap_rec = match js_store.get_snapshot(&vol_id, &snapshot).await {
                    Ok(s) => s,
                    Err(e) => {
                        return Ok(enter_recovery(
                            &profile,
                            RecoveryReason::IoError {
                                errno: format!("{e:?}"),
                                detail: format!("snapshot {snapshot:?} unavailable: {e:?}"),
                            },
                            Some(volume_uuid),
                            Vec::new(),
                            format!("Snapshot {snapshot:?} unavailable ({e:?})."),
                            None,
                        ));
                    }
                };
                let clock: Rc<dyn Fn() -> abi::fs::Timespec> = Rc::new(now_timespec);
                let cfg = CowFsConfig::local_browser(Rc::clone(&clock))
                    .with_arena(ArenaConfig::fixed_32mib());
                let snap_fs = match CowFs::open(
                    Rc::clone(&js_store),
                    Rc::clone(&js_store),
                    vol_id.clone(),
                    cowfs::CowFsOpenMode::Snapshot(snapshot.clone()),
                    cfg,
                )
                .await
                {
                    Ok(fs) => Rc::new(fs),
                    Err(e) => {
                        return Ok(enter_recovery(
                            &profile,
                            RecoveryReason::CorruptVolume {
                                detail: format!("snapshot open failed: {e:?}"),
                                snapshots: vec![snapshot.clone()],
                            },
                            Some(volume_uuid),
                            vec![snapshot],
                            format!("Snapshot failed verification/open ({e:?})."),
                            None,
                        ));
                    }
                };
                if let Ok(raw_root) = js_store.get_node(&snap_rec.root).await
                    && let Ok(root_obj) = RootObject::decode_verified(&snap_rec.root, &raw_root)
                    && root_obj.subvols.contains_key("@home")
                {
                    let hcfg = CowFsConfig::local_browser(Rc::clone(&clock))
                        .with_arena(ArenaConfig::fixed_32mib())
                        .with_subvol("@home");
                    if let Ok(hfs) = CowFs::open(
                        Rc::clone(&js_store),
                        Rc::clone(&js_store),
                        vol_id,
                        cowfs::CowFsOpenMode::Snapshot(snapshot.clone()),
                        hcfg,
                    )
                    .await
                    {
                        opened_ro_home = Some(Rc::new(hfs) as Rc<dyn Filesystem>);
                    }
                }
                {
                    let (vblk, dev_fs, cowfs_ctx) = {
                        let rt = self.vfs_rt.borrow();
                        (
                            Rc::clone(&rt.vblk),
                            Rc::clone(&rt.dev_fs),
                            Rc::clone(&rt.cowfs_ctx),
                        )
                    };
                    cowfs_ctx.borrow_mut().store = Some(Rc::clone(&js_store));
                    let _ = vblk.detach("vd0");
                    let _ = vblk.attach_named(
                        "vd0",
                        Rc::new(CowFsVolumeDevice::from_mounted(Rc::clone(&snap_fs))),
                    );
                    let _ = vblk.register_node(&dev_fs, "vd0", 0o660);
                    if vblk.get("vd1").is_none() {
                        let _ = vblk.attach_named(
                            "vd1",
                            Rc::new(CowFsVolumeDevice::unmounted(
                                VolumeId("scratch-vd1".to_string()),
                                Rc::clone(&js_store),
                                Rc::clone(&js_store),
                                abi::contract::WriterModel::Local,
                                abi::contract::Durability::TreeCommit,
                                Rc::new(now_timespec),
                            )),
                        );
                        let _ = vblk.register_node(&dev_fs, "vd1", 0o660);
                    }
                }
                root_fs = Rc::clone(&snap_fs) as Rc<dyn Filesystem>;
                opened_cowfs = Some(snap_fs);
                root_fstype = FsType::Cowfs;
                root_rdonly = true;
                root_source = format!("snapshot:{volume_uuid}@{snapshot}");
                info = MountedRootInfo {
                    fstype: "cowfs-snapshot".into(),
                    volume_uuid: format!("{volume_uuid}@{snapshot}"),
                    forked_from: None,
                    base_epoch: snap_rec.epoch,
                    ephemeral_if_unmodified: false,
                    first_boot_seeded: false,
                    writer_mode: BootWriterMode::Exclusive,
                    mounted_at: now_secs(),
                };
            }
            RootSpec::CowFs {
                volume_uuid,
                writer_mode,
            } => {
                match js_store.format_version().await {
                    Ok(Some(ver)) if ver != COWFS_FORMAT_VERSION => {
                        return Ok(enter_recovery(
                            &profile,
                            RecoveryReason::IncompatibleFormat {
                                found_version: Some(ver),
                                expected_version: COWFS_FORMAT_VERSION,
                            },
                            volume_uuid,
                            Vec::new(),
                            format!(
                                "Refusing to mount or reformat incompatible os-cowfs format version {ver} (expected {COWFS_FORMAT_VERSION}): EPROTONOSUPPORT."
                            ),
                            None,
                        ));
                    }
                    Ok(_) => {}
                    Err(Errno::EPROTONOSUPPORT) => {
                        return Ok(enter_recovery(
                            &profile,
                            RecoveryReason::IncompatibleFormat {
                                found_version: None,
                                expected_version: COWFS_FORMAT_VERSION,
                            },
                            volume_uuid,
                            Vec::new(),
                            format!(
                                "Refusing to mount or reformat incompatible os-cowfs store (expected version {COWFS_FORMAT_VERSION}): EPROTONOSUPPORT."
                            ),
                            None,
                        ));
                    }
                    Err(e) => {
                        return Ok(enter_recovery(
                            &profile,
                            RecoveryReason::IoError {
                                errno: format!("{e:?}"),
                                detail: format!("format version probe failed: {e:?}"),
                            },
                            volume_uuid,
                            Vec::new(),
                            format!("Failed to probe os-cowfs format version ({e:?})."),
                            None,
                        ));
                    }
                }

                let clock: Rc<dyn Fn() -> abi::fs::Timespec> = Rc::new(now_timespec);
                let (cfg, dirty_binder) = bind_dirty_flush_timer::<JsCowfsStore, JsCowfsStore>(
                    CowFsConfig::local_browser(Rc::clone(&clock))
                        .with_arena(ArenaConfig::fixed_32mib()),
                );
                let opened = match open_for_boot_stores_detailed(
                    Rc::clone(&js_store),
                    Rc::clone(&js_store),
                    volume_uuid.clone(),
                    writer_mode.to_cowtree_mode(),
                    Some(&root_template),
                    Some(&VerifiedAssetBlobStore),
                    cfg,
                    || {
                        let hex = crate::random_hex(16);
                        format!(
                            "{}-{}-4{}-8{}-{}",
                            &hex[0..8],
                            &hex[8..12],
                            &hex[13..16],
                            &hex[17..20],
                            &hex[20..32]
                        )
                    },
                )
                .await
                {
                    Ok(res) => res,
                    Err(BootOpenError::Corrupt { volume, report }) => {
                        let report_bytes =
                            serde_json::to_vec_pretty(&report).unwrap_or_else(|_| b"{}".to_vec());
                        let _ =
                            write_file_vfs(&vfs, COWFSCK_REPORT_PATH, &report_bytes, 0o444).await;
                        let detail = if report.errors.is_empty() {
                            "cowfsck reported volume corruption".into()
                        } else {
                            report.errors.join("; ")
                        };
                        let snap_vol = volume_uuid.clone().unwrap_or_else(|| volume.clone());
                        let snaps: Vec<String> = js_store
                            .list_snapshots(&VolumeId(snap_vol.clone()))
                            .await
                            .unwrap_or_default()
                            .into_iter()
                            .map(|s| s.name)
                            .collect();
                        return Ok(enter_recovery(
                            &profile,
                            RecoveryReason::CorruptVolume {
                                detail: detail.clone(),
                                snapshots: snaps.clone(),
                            },
                            Some(snap_vol),
                            snaps,
                            format!(
                                "Stage 1 cowfsck detected corruption on volume {volume}: {detail}"
                            ),
                            Some(*report),
                        ));
                    }
                    Err(BootOpenError::Errno(Errno::EPROTONOSUPPORT)) => {
                        return Ok(enter_recovery(
                            &profile,
                            RecoveryReason::IncompatibleFormat {
                                found_version: None,
                                expected_version: COWFS_FORMAT_VERSION,
                            },
                            volume_uuid,
                            Vec::new(),
                            "Incompatible os-cowfs format version (EPROTONOSUPPORT).".into(),
                            fsck_report,
                        ));
                    }
                    Err(BootOpenError::Errno(Errno::EBUSY)) => {
                        let busy = volume_uuid.clone().unwrap_or_default();
                        let snaps: Vec<String> = js_store
                            .list_snapshots(&VolumeId(busy.clone()))
                            .await
                            .unwrap_or_default()
                            .into_iter()
                            .map(|s| s.name)
                            .collect();
                        return Ok(enter_recovery(
                            &profile,
                            RecoveryReason::VolumeBusy {
                                volume_uuid: busy.clone(),
                            },
                            volume_uuid,
                            snaps,
                            format!(
                                "Volume {busy} is locked exclusively by another tab (EBUSY). Choose 'Fork & Boot' to open on an isolated copy-on-write fork."
                            ),
                            fsck_report,
                        ));
                    }
                    Err(BootOpenError::Errno(e)) => {
                        if let Some(ref existing_uuid) = volume_uuid {
                            let vol_id = VolumeId(existing_uuid.clone());
                            let snaps: Vec<String> = js_store
                                .list_snapshots(&vol_id)
                                .await
                                .unwrap_or_default()
                                .into_iter()
                                .map(|s| s.name)
                                .collect();
                            match cowfsck_volume_stores(&*js_store, &*js_store, &vol_id).await {
                                Ok(report) => {
                                    let report_bytes = serde_json::to_vec_pretty(&report)
                                        .unwrap_or_else(|_| b"{}".to_vec());
                                    let _ = write_file_vfs(
                                        &vfs,
                                        COWFSCK_REPORT_PATH,
                                        &report_bytes,
                                        0o444,
                                    )
                                    .await;
                                    let detail = if report.errors.is_empty() {
                                        format!("os-cowfs open failed: {e:?}")
                                    } else {
                                        report.errors.join("; ")
                                    };
                                    return Ok(enter_recovery(
                                        &profile,
                                        RecoveryReason::CorruptVolume {
                                            detail: detail.clone(),
                                            snapshots: snaps.clone(),
                                        },
                                        Some(existing_uuid.clone()),
                                        snaps,
                                        format!(
                                            "Stage 1 cowfsck detected corruption on volume {existing_uuid}: {detail}"
                                        ),
                                        Some(report),
                                    ));
                                }
                                Err(Errno::EPROTONOSUPPORT) => {
                                    return Ok(enter_recovery(
                                        &profile,
                                        RecoveryReason::IncompatibleFormat {
                                            found_version: None,
                                            expected_version: COWFS_FORMAT_VERSION,
                                        },
                                        Some(existing_uuid.clone()),
                                        Vec::new(),
                                        "Incompatible os-cowfs format version (EPROTONOSUPPORT)."
                                            .into(),
                                        None,
                                    ));
                                }
                                Err(_) => {
                                    return Ok(enter_recovery(
                                        &profile,
                                        RecoveryReason::CorruptVolume {
                                            detail: format!("os-cowfs open failed: {e:?}"),
                                            snapshots: snaps.clone(),
                                        },
                                        Some(existing_uuid.clone()),
                                        snaps,
                                        format!(
                                            "Stage 1 cowfsck failed on volume {existing_uuid} ({e:?})."
                                        ),
                                        None,
                                    ));
                                }
                            }
                        }
                        return Ok(enter_recovery(
                            &profile,
                            RecoveryReason::IoError {
                                errno: format!("{e:?}"),
                                detail: format!("os-cowfs open failed: {e:?}"),
                            },
                            volume_uuid,
                            Vec::new(),
                            format!("Failed to open os-cowfs root volume ({e:?})."),
                            fsck_report,
                        ));
                    }
                };
                if let Some(ref rep) = opened.fsck_report {
                    let report_bytes =
                        serde_json::to_vec_pretty(rep).unwrap_or_else(|_| b"{}".to_vec());
                    let _ = write_file_vfs(&vfs, COWFSCK_REPORT_PATH, &report_bytes, 0o444).await;
                }
                if opened.fsck_report.is_some() {
                    fsck_report = opened.fsck_report;
                }
                opened_dirty_guard = Some(dirty_binder.attach(&opened.fs));
                if opened.first_boot_seeded
                    && let RootSpec::CowFs {
                        volume_uuid: ref mut vu,
                        ..
                    } = profile.root
                {
                    *vu = Some(opened.volume_uuid.clone());
                }
                if let Some(ref parent) = opened.forked_from {
                    banners.push(format!(
                        "ForkOnBusy: booted on O(1) copy-on-write fork {} (parent {}); unmodified forks are pruned automatically on clean exit.",
                        opened.volume_uuid, parent
                    ));
                }
                {
                    let (vblk, dev_fs, cowfs_ctx) = {
                        let rt = self.vfs_rt.borrow();
                        (
                            Rc::clone(&rt.vblk),
                            Rc::clone(&rt.dev_fs),
                            Rc::clone(&rt.cowfs_ctx),
                        )
                    };
                    {
                        let mut ctx = cowfs_ctx.borrow_mut();
                        ctx.store = Some(Rc::clone(&js_store));
                        ctx.active_volumes
                            .insert(opened.volume_uuid.clone(), Rc::clone(&opened.fs));
                    }
                    let _ = vblk.detach("vd0");
                    let _ = vblk.attach_named(
                        "vd0",
                        Rc::new(CowFsVolumeDevice::from_mounted(Rc::clone(&opened.fs))),
                    );
                    let _ = vblk.register_node(&dev_fs, "vd0", 0o660);
                    if vblk.get("vd1").is_none() {
                        let _ = vblk.attach_named(
                            "vd1",
                            Rc::new(CowFsVolumeDevice::unmounted(
                                VolumeId("scratch-vd1".to_string()),
                                Rc::clone(&js_store),
                                Rc::clone(&js_store),
                                abi::contract::WriterModel::Local,
                                abi::contract::Durability::TreeCommit,
                                Rc::new(now_timespec),
                            )),
                        );
                        let _ = vblk.register_node(&dev_fs, "vd1", 0o660);
                    }
                }
                root_source = format!("cowfs:{}", opened.volume_uuid);
                root_fs = Rc::clone(&opened.fs) as Rc<dyn Filesystem>;
                info = MountedRootInfo {
                    fstype: "cowfs".into(),
                    volume_uuid: opened.volume_uuid.clone(),
                    forked_from: opened.forked_from.clone(),
                    base_epoch: opened.base_epoch,
                    ephemeral_if_unmodified: opened.ephemeral_if_unmodified,
                    first_boot_seeded: opened.first_boot_seeded,
                    writer_mode,
                    mounted_at: now_secs(),
                };
                opened_cowfs = Some(opened.fs);
            }
        }

        let profile_bytes = serde_json::to_vec_pretty(&profile).unwrap_or_else(|_| b"{}".to_vec());
        let _ = write_file_vfs(&vfs, BOOT_PROFILE_PATH, &profile_bytes, 0o444).await;
        let info_bytes = serde_json::to_vec_pretty(&info).unwrap_or_else(|_| b"{}".to_vec());
        let _ = write_file_vfs(&vfs, MOUNTED_ROOT_INFO_PATH, &info_bytes, 0o444).await;

        // Mount prepared root at `/sysroot`, optional `@home`, Stage 2 `/usr`, fresh `/tmp`.
        ensure_dir_vfs(&vfs, "/sysroot", 0o755)
            .await
            .map_err(|e| fail(Error::from(e)))?;
        let mut root_backing = MountBacking::new(root_fs, root_fstype);
        if let Some(ref cowfs) = opened_cowfs {
            root_backing = root_backing
                .with_volume_device(Rc::new(CowFsVolumeDevice::from_mounted(Rc::clone(cowfs))));
        }
        if root_rdonly {
            root_backing = root_backing.with_ceilings(true, false);
        }
        vfs.mount_on_namespace(
            &sys_ns,
            &root_cred,
            Rc::new(root_backing),
            None,
            &root_source,
            "/sysroot",
            MountFlags {
                rdonly: root_rdonly,
                ..MountFlags::default()
            },
            if root_rdonly {
                mount_flags::MS_RDONLY
            } else {
                0
            },
            None,
        )
        .await
        .map_err(|e| fail(Error::from(e)))?;

        if let Some(home_fs) = opened_ro_home.take()
            && vfs
                .statat(INIT, StartAnchor::Root, "/sysroot/home", false)
                .await
                .is_ok_and(|st| st.kind() == S_IFDIR)
        {
            let mut home_backing =
                MountBacking::new(home_fs, FsType::Cowfs).with_ceilings(true, false);
            if let Some(ref cowfs) = opened_cowfs {
                home_backing = home_backing
                    .with_volume_device(Rc::new(CowFsVolumeDevice::from_mounted(Rc::clone(cowfs))));
            }
            let home_backing = Rc::new(home_backing);
            vfs.mount_on_namespace(
                &sys_ns,
                &root_cred,
                home_backing,
                None,
                &format!("{root_source}:@home"),
                "/sysroot/home",
                MountFlags {
                    rdonly: true,
                    ..MountFlags::default()
                },
                mount_flags::MS_RDONLY,
                None,
            )
            .await
            .map_err(|e| fail(Error::from(e)))?;
        } else if !root_rdonly
            && let Some(ref cowfs) = opened_cowfs
            && cowfs.has_subvol("@home")
        {
            ensure_dir_vfs(&vfs, "/sysroot/home", 0o755)
                .await
                .map_err(|e| fail(Error::from(e)))?;
            let home_view = cowfs
                .open_subvol_view("@home")
                .map_err(|e| fail(Error::from(e)))?;
            let home_backing = Rc::new(
                MountBacking::new(home_view, FsType::Cowfs)
                    .with_volume_device(Rc::new(CowFsVolumeDevice::from_mounted(Rc::clone(cowfs)))),
            );
            vfs.mount_on_namespace(
                &sys_ns,
                &root_cred,
                home_backing,
                None,
                &format!("{root_source}:@home"),
                "/sysroot/home",
                MountFlags::default(),
                0,
                None,
            )
            .await
            .map_err(|e| fail(Error::from(e)))?;
        }

        for (sub, mode) in [
            ("/sysroot/proc", 0o555),
            ("/sysroot/dev", 0o755),
            ("/sysroot/run", 0o755),
            ("/sysroot/usr", 0o755),
            ("/sysroot/tmp", 0o1777),
        ] {
            if let Err(e) = ensure_dir_vfs(&vfs, sub, mode).await {
                teardown_sysroot_mounts(&vfs).await;
                if let Some(fs) = opened_cowfs.take() {
                    let _ = fs.close_clean().await;
                }
                return Ok(enter_recovery(
                    &profile,
                    RecoveryReason::IoError {
                        errno: format!("{e:?}"),
                        detail: format!("invalid sysroot mountpoint {sub}: {e:?}"),
                    },
                    Some(info.volume_uuid),
                    Vec::new(),
                    format!("Refusing to boot: {sub} is not a directory ({e:?})."),
                    fsck_report,
                ));
            }
        }

        // Compose Stage 2 `/usr` strictly from verified Release v2 `base` + `extensions`.
        let stage2_usr_entries =
            crate::release_v2::compose_system_image_entries(&base, &extensions)
                .map_err(|e| fail(Error::because(Errno::EINVAL, e.to_string())))?;
        let stage2_usr_fs = ImageFs::new(
            FsId("image:stage2-usr".to_string()),
            true,
            now,
            stage2_usr_entries,
            VerifiedAssetBlobStore,
        )
        .map_err(|e| fail(Error::from(e)))?;
        let usr_subroot = stage2_usr_fs
            .handle_at("/usr")
            .map(|h| (h, "/usr".to_string()))
            .ok_or_else(|| fail(Error::from(Errno::ENOENT)))?;
        let usr_backing = Rc::new(
            MountBacking::new(Rc::new(stage2_usr_fs), FsType::Image).with_ceilings(true, false),
        );
        vfs.mount_on_namespace(
            &sys_ns,
            &root_cred,
            usr_backing,
            Some(usr_subroot),
            "usr",
            "/sysroot/usr",
            MountFlags {
                rdonly: true,
                nodev: true,
                ..MountFlags::default()
            },
            mount_flags::MS_RDONLY | mount_flags::MS_NODEV,
            None,
        )
        .await
        .map_err(|e| fail(Error::from(e)))?;

        // Fresh `tmpfs` (`01777`, `nosuid,nodev`) at `/sysroot/tmp`.
        let tmp_fs = Rc::new(MemFs::new(
            FsId("tmpfs:stage2-tmp".to_string()),
            3,
            0,
            0,
            0o1777,
            Box::new(|| {
                let ts = now_timespec();
                (ts.sec, ts.nsec)
            }),
        ));
        let tmp_root = tmp_fs.root();
        let _ = tmp_fs
            .setattr(
                &root_cred,
                &tmp_root,
                &SetAttr {
                    mode: Some(0o1777),
                    ..SetAttr::default()
                },
            )
            .await;
        let tmp_backing = Rc::new(MountBacking::new(tmp_fs, FsType::TmpFs));
        vfs.mount_on_namespace(
            &sys_ns,
            &root_cred,
            tmp_backing,
            None,
            "tmpfs",
            "/sysroot/tmp",
            MountFlags {
                nosuid: true,
                nodev: true,
                ..MountFlags::default()
            },
            mount_flags::MS_NOSUID | mount_flags::MS_NODEV,
            None,
        )
        .await
        .map_err(|e| fail(Error::from(e)))?;

        // Validate `/sysroot/etc/passwd` + `default_user` BEFORE launching `/init` -> `switch_root`
        // (Codex Finding #24: never synthesize hardcoded UID 1000 `wheel`!).
        let passwd_check: Result<(), String> = async {
            let p_fd = vfs
                .openat(
                    INIT,
                    StartAnchor::Root,
                    "/sysroot/etc/passwd",
                    abi::O_RDONLY,
                    0,
                )
                .await
                .map_err(|e| format!("failed to open /sysroot/etc/passwd: {}", e.text()))?;
            let mut p_buf = Vec::new();
            let mut off = 0u64;
            let mut chunk = vec![0u8; 16384];
            loop {
                let n = vfs
                    .pread(INIT, p_fd, &mut chunk, off)
                    .await
                    .map_err(|e| format!("failed to read /sysroot/etc/passwd: {}", e.text()))?;
                if n == 0 {
                    break;
                }
                p_buf.extend_from_slice(&chunk[..n]);
                off += n as u64;
            }
            let _ = vfs.close(INIT, p_fd).await;
            let text = std::str::from_utf8(&p_buf)
                .map_err(|_| "/etc/passwd is not valid UTF-8".to_string())?;
            let entries = kernel::accounts::parse_passwd(text)
                .map_err(|e| format!("invalid /etc/passwd: {e}"))?;
            if !entries.iter().any(|e| e.name == profile.default_user) {
                return Err(format!(
                    "configured default_user {:?} not found in /etc/passwd",
                    profile.default_user
                ));
            }
            Ok(())
        }
        .await;
        if let Err(detail) = passwd_check {
            teardown_sysroot_mounts(&vfs).await;
            if let Some(fs) = opened_cowfs.take() {
                let _ = fs.close_clean().await;
            }
            self.apply_account_update(LocalAccount::signed_out_nobody());
            return Ok(enter_recovery(
                &profile,
                RecoveryReason::AccountResolutionFailed {
                    default_user: profile.default_user.clone(),
                    detail: detail.clone(),
                },
                Some(info.volume_uuid),
                Vec::new(),
                format!("Refusing to auto-login synthetic user: {detail}"),
                fsck_report,
            ));
        }

        {
            let mut rt = self.vfs_rt.borrow_mut();
            rt.root_cowfs = opened_cowfs;
            rt.root_dirty_guard = opened_dirty_guard;
            rt.mounted_root = Some(info);
            rt.boot_profile = profile;
            rt.boot_stage = BootStage::Stage1;
            rt.recovery = None;
            rt.banners = banners;
            rt.fsck_report = fsck_report;
            rt.usr_fs_id = FsId("image:stage2-usr".to_string());
            rt.usr_blob_paths.clear();
            rt.trusted_service_digests = extract_service_digests_from_image(&base);
        }
        Ok(self.standalone_status_json().to_string())
    }

    /// Resolve the actual Stage 2 login before PID 1 launches its user manager.
    pub async fn standalone_prepare_login(&self) -> Result<(), JsValue> {
        let (vfs, user) = {
            let rt = self.vfs_rt.borrow();
            (rt.vfs.clone(), rt.boot_profile.default_user.clone())
        };
        let account = self
            .resolve_local_user_account(&vfs, &user)
            .await
            .map_err(crate::vfs_engine::map_errno)?;
        self.apply_account_update(account);
        Ok(())
    }

    /// Finalize standalone Stage 2 AFTER PID 1 (`/init` -> `switch_root` -> `/usr/bin/init`) has
    /// pivoted `/` and reached `/run/os/boot-healthy`: resolves `default_user` from `/etc/passwd`,
    /// allocates a local PTY `/dev/pts/0`, and spawns a separate non-PID-1 console login process
    /// (`console_pid != 1`) in `LocalProcessTable` + `Vfs` (Codex Findings #2 & #24).
    pub async fn standalone_finalize_stage2(&self, host: &str) -> Result<String, JsValue> {
        let (vfs, default_user) = {
            let rt = self.vfs_rt.borrow();
            (rt.vfs.clone(), rt.boot_profile.default_user.clone())
        };
        let account = match self.resolve_local_user_account(&vfs, &default_user).await {
            Ok(acc) => acc,
            Err(err) => {
                let detail = err.text().to_string();
                {
                    let mut rt = self.vfs_rt.borrow_mut();
                    rt.boot_stage = BootStage::Stage1Recovery;
                    rt.recovery = Some(RecoveryState {
                        reason: RecoveryReason::AccountResolutionFailed {
                            default_user: default_user.clone(),
                            detail: detail.clone(),
                        },
                        volume_uuid: rt.mounted_root.as_ref().map(|r| r.volume_uuid.clone()),
                        available_snapshots: Vec::new(),
                        message: format!(
                            "Failed to resolve configured default_user {default_user:?}: {detail}"
                        ),
                    });
                }
                self.apply_account_update(LocalAccount::signed_out_nobody());
                return Ok(self.standalone_status_json().to_string());
            }
        };
        self.apply_account_update(account.clone());
        self.refresh_local_account_caches(&vfs).await;

        // Allocate a real local PTY `/dev/pts/0` and spawn a separate non-PID-1 login process!
        let pty_index = 0u32;
        self.vfs_rt
            .borrow()
            .dev_pts
            .register_pty(pty_index, account.uid, account.gid, 0o620);
        let identity = account.identity();
        let mut spec = kernel::proc_table::SpawnSpec::new(
            account.shell.clone(),
            kernel::proc_table::LocalCred {
                identity: identity.clone(),
                umask: 0o022,
                cloud_access: false,
                allowed_remote_scope: None,
                remote: None,
            },
            if host.is_empty() { "standalone" } else { host },
        );
        spec.argv = vec![account.shell.clone()];
        spec.cwd = account.home.clone();
        spec.ppid = Some(INIT);
        spec.initial_state = abi::ProcState::Running;
        let login_pid = {
            let mut st = self.state.borrow_mut();
            let pid = st.table.spawn(spec, now_secs()).map_err(fail)?.pid;
            let _ = st.table.set_tty(
                if host.is_empty() { "standalone" } else { host },
                pid,
                pty_index + 1,
                vec![0, 1, 2],
            );
            pid
        };
        let login_cred = Cred {
            identity,
            umask: 0o022,
            token: None,
        };
        vfs.spawn_process(login_pid, INIT, login_cred, None, None, None)
            .map_err(|e| fail(Error::from(e)))?;
        if vfs.chdir(login_pid, &account.home).await.is_err() {
            let _ = vfs.chdir(login_pid, "/").await;
        }
        {
            let mut rt = self.vfs_rt.borrow_mut();
            rt.console_pid = Some(login_pid);
            rt.console_pty = Some(pty_index);
            rt.console_user = Some(account.user);
            rt.console_home = Some(account.home);
            rt.console_shell = Some(account.shell);
            rt.boot_stage = BootStage::Stage2;
            rt.recovery = None;
        }
        Ok(self.standalone_status_json().to_string())
    }

    fn standalone_status_json(&self) -> Value {
        let rt = self.vfs_rt.borrow();
        let st = self.state.borrow();
        let p1 = st.table.proc(INIT);
        let pid1 = p1.map(|p| {
            json!({
                "pid": p.pid,
                "ppid": p.ppid,
                "uid": p.cred.identity.id,
                "gid": p.cred.identity.group,
                "path": p.path,
                "argv": p.argv,
                "started": p.started,
                "started_ticks": p.started_ticks,
                "cwd": p.cwd,
            })
        });
        let console_proc = rt.console_pid.and_then(|cpid| {
            let p = st.table.proc(cpid)?;
            let mut groups: Vec<u32> = p.cred.identity.groups.iter().copied().collect();
            groups.sort_unstable();
            Some(json!({
                "pid": p.pid,
                "ppid": p.ppid,
                "uid": p.cred.identity.id,
                "gid": p.cred.identity.group,
                "groups": groups,
                "user": rt.console_user.clone().unwrap_or_else(|| st.account.user.clone()),
                "home": rt.console_home.clone().unwrap_or_else(|| st.account.home.clone()),
                "shell": rt.console_shell.clone().unwrap_or_else(|| st.account.shell.clone()),
                "cwd": p.cwd,
                "tty": rt.console_pty.map(|n| format!("/dev/pts/{n}")),
            }))
        });
        json!({
            "stage": rt.boot_stage,
            "instance_id": st.instance_id,
            "pid1": pid1,
            "console_proc": console_proc,
            "boot_profile": rt.boot_profile,
            "mounted_root": rt.mounted_root,
            "recovery": rt.recovery,
            "banners": rt.banners,
            "fsck_report": rt.fsck_report,
            "stage1_reclaimed_entries": rt.stage1_reclaimed_entries,
            "stage1_tmpfs_dropped": rt.stage1_fs_weak.strong_count() == 0,
        })
    }

    pub fn standalone_status(&self) -> String {
        self.standalone_status_json().to_string()
    }

    async fn standalone_effective_pid(&self, sudo: bool) -> Result<u32, Errno> {
        let (stage, console_pid, vfs) = {
            let rt = self.vfs_rt.borrow();
            (rt.boot_stage, rt.console_pid, rt.vfs.clone())
        };
        if stage != BootStage::Stage2 {
            return Ok(INIT);
        }
        let cpid = console_pid.ok_or(Errno::ESRCH)?;
        if !sudo {
            return Ok(cpid);
        }
        // Check real `/etc/sudoers` before elevating standalone console API calls!
        let (uid, sid) = {
            let st = self.state.borrow();
            let p = st.table.proc(cpid).ok_or(Errno::ESRCH)?;
            (p.cred.identity.id, p.sid)
        };
        if uid == 0 {
            return Ok(INIT);
        }
        let creds_val = self
            .eval_local_account_call(&vfs, cpid, None, false, abi::Call::Getcreds)
            .await
            .map_err(|e| e.errno)?;
        let can_sudo = creds_val
            .get("can_sudo")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let sudo_active = creds_val
            .get("sudo_active")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let _ = sid;
        if can_sudo && sudo_active {
            return Ok(INIT);
        }
        // Try NOPASSWD sudo evaluation via `Call::Sudo { password: "" }`.
        self.eval_local_account_call(
            &vfs,
            cpid,
            None,
            false,
            abi::Call::Sudo {
                password: String::new(),
                revoke: false,
            },
        )
        .await
        .map_err(|e| e.errno)?;
        Ok(INIT)
    }

    pub async fn standalone_read_file(
        &self,
        path: String,
        sudo: Option<bool>,
    ) -> Result<Vec<u8>, JsValue> {
        let pid = self
            .standalone_effective_pid(sudo.unwrap_or(false))
            .await
            .map_err(|e| fail(Error::from(e)))?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let fd = vfs
            .openat(pid, StartAnchor::Root, &path, abi::O_RDONLY, 0)
            .await
            .map_err(|e| fail(Error::from(e)))?;
        let mut out = Vec::new();
        let mut off = 0u64;
        let mut chunk = vec![0u8; 65_536];
        loop {
            let n = match vfs.pread(pid, fd, &mut chunk, off).await {
                Ok(n) => n,
                Err(e) => {
                    let _ = vfs.close(pid, fd).await;
                    return Err(fail(Error::from(e)));
                }
            };
            if n == 0 {
                break;
            }
            out.extend_from_slice(&chunk[..n]);
            off += n as u64;
        }
        vfs.close(pid, fd).await.map_err(|e| fail(Error::from(e)))?;
        Ok(out)
    }

    pub async fn standalone_write_file(
        &self,
        path: String,
        bytes: &[u8],
        mode: Option<u16>,
        sudo: Option<bool>,
    ) -> Result<usize, JsValue> {
        let pid = self
            .standalone_effective_pid(sudo.unwrap_or(false))
            .await
            .map_err(|e| fail(Error::from(e)))?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let fd = vfs
            .openat(
                pid,
                StartAnchor::Root,
                &path,
                abi::O_CREAT | abi::O_WRONLY | abi::O_TRUNC,
                mode.unwrap_or(0o644),
            )
            .await
            .map_err(|e| fail(Error::from(e)))?;
        let mut off = 0u64;
        while (off as usize) < bytes.len() {
            let n = match vfs.pwrite(pid, fd, &bytes[off as usize..], off).await {
                Ok(n) => n,
                Err(e) => {
                    let _ = vfs.close(pid, fd).await;
                    return Err(fail(Error::from(e)));
                }
            };
            if n == 0 {
                let _ = vfs.close(pid, fd).await;
                return Err(fail(Error::from(Errno::EIO)));
            }
            off += n as u64;
        }
        vfs.close(pid, fd).await.map_err(|e| fail(Error::from(e)))?;
        Ok(bytes.len())
    }

    pub async fn standalone_mkdir(
        &self,
        path: String,
        mode: Option<u16>,
        sudo: Option<bool>,
    ) -> Result<(), JsValue> {
        let pid = self
            .standalone_effective_pid(sudo.unwrap_or(false))
            .await
            .map_err(|e| fail(Error::from(e)))?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        vfs.mkdirat(pid, StartAnchor::Root, &path, mode.unwrap_or(0o755))
            .await
            .map(|_| ())
            .map_err(|e| fail(Error::from(e)))
    }

    pub async fn standalone_unlink(&self, path: String, sudo: Option<bool>) -> Result<(), JsValue> {
        let pid = self
            .standalone_effective_pid(sudo.unwrap_or(false))
            .await
            .map_err(|e| fail(Error::from(e)))?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        vfs.unlinkat(pid, StartAnchor::Root, &path, false)
            .await
            .map_err(|e| fail(Error::from(e)))
    }

    pub async fn standalone_stat(
        &self,
        path: String,
        follow: Option<bool>,
        sudo: Option<bool>,
    ) -> Result<String, JsValue> {
        let pid = self
            .standalone_effective_pid(sudo.unwrap_or(false))
            .await
            .map_err(|e| fail(Error::from(e)))?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let st = vfs
            .statat(pid, StartAnchor::Root, &path, follow.unwrap_or(true))
            .await
            .map_err(|e| fail(Error::from(e)))?;
        serde_json::to_string(&st).map_err(|e| fail(Error::because(Errno::EIO, e.to_string())))
    }

    pub async fn standalone_statfs(&self, path: String) -> Result<String, JsValue> {
        let pid = self
            .standalone_effective_pid(false)
            .await
            .map_err(|e| fail(Error::from(e)))?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let sf = vfs
            .statfs(pid, StartAnchor::Root, &path)
            .await
            .map_err(|e| fail(Error::from(e)))?;
        serde_json::to_string(&sf).map_err(|e| fail(Error::because(Errno::EIO, e.to_string())))
    }

    pub async fn standalone_readdir(
        &self,
        path: String,
        sudo: Option<bool>,
    ) -> Result<String, JsValue> {
        let pid = self
            .standalone_effective_pid(sudo.unwrap_or(false))
            .await
            .map_err(|e| fail(Error::from(e)))?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let mut names = Vec::new();
        let mut cookie = 0u64;
        loop {
            let page = vfs
                .read_dir_page(pid, StartAnchor::Root, &path, cookie, 256)
                .await
                .map_err(|e| fail(Error::from(e)))?;
            for e in page.entries {
                names.push(e.name);
            }
            match page.next_cookie {
                Some(next) if next != cookie => cookie = next,
                _ => break,
            }
        }
        serde_json::to_string(&names).map_err(|e| fail(Error::because(Errno::EIO, e.to_string())))
    }

    pub async fn standalone_sync_fs(&self) -> Result<String, JsValue> {
        let cowfs = self
            .vfs_rt
            .borrow()
            .root_cowfs
            .clone()
            .ok_or_else(|| fail(Error::from(Errno::ENODEV)))?;
        let head = cowfs
            .commit_tx_group()
            .await
            .map_err(|e| fail(Error::from(e)))?;
        serde_json::to_string(&head).map_err(|e| fail(Error::because(Errno::EIO, e.to_string())))
    }

    pub async fn standalone_snapshot(&self, name: String) -> Result<String, JsValue> {
        let cowfs = self
            .vfs_rt
            .borrow()
            .root_cowfs
            .clone()
            .ok_or_else(|| fail(Error::from(Errno::ENODEV)))?;
        let snap = cowfs
            .create_snapshot(&name)
            .await
            .map_err(|e| fail(Error::from(e)))?;
        serde_json::to_string(&snap).map_err(|e| fail(Error::because(Errno::EIO, e.to_string())))
    }

    pub async fn standalone_run_cowfsck(
        &self,
        store: JsValue,
        volume_uuid: Option<String>,
    ) -> Result<String, JsValue> {
        let uuid = volume_uuid
            .or_else(|| {
                self.vfs_rt
                    .borrow()
                    .mounted_root
                    .as_ref()
                    .map(|r| r.volume_uuid.clone())
            })
            .ok_or_else(|| fail(Error::from(Errno::ENOENT)))?;
        let js_store = JsCowfsStore { obj: store };
        let rep = cowfsck_volume_stores(&js_store, &js_store, &VolumeId(uuid))
            .await
            .map_err(|e| fail(Error::from(e)))?;
        serde_json::to_string(&rep).map_err(|e| fail(Error::because(Errno::EIO, e.to_string())))
    }

    pub async fn standalone_switch_root_attempt(
        &self,
        caller_pid: u32,
        newroot: String,
        init_path: String,
    ) -> Result<(), JsValue> {
        if caller_pid != INIT {
            return Err(fail(Error::from(Errno::EPERM)));
        }
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let sf = vfs
            .statfs(INIT, StartAnchor::Root, "/")
            .await
            .map_err(|e| fail(Error::from(e)))?;
        if sf.f_type != fs_magic::TMPFS_MAGIC {
            return Err(fail(Error::from(Errno::EINVAL)));
        }
        let _ = (newroot, init_path);
        Err(fail(Error::from(Errno::EINVAL)))
    }

    pub async fn standalone_rollback_fork(
        &self,
        store: JsValue,
        snapshot_name: String,
    ) -> Result<String, JsValue> {
        let source_uuid = {
            let rt = self.vfs_rt.borrow();
            if rt.boot_stage != BootStage::Stage1Recovery {
                return Err(fail(Error::from(Errno::EINVAL)));
            }
            rt.recovery
                .as_ref()
                .and_then(|r| r.volume_uuid.clone())
                .or_else(|| match &rt.boot_profile.root {
                    RootSpec::CowFs { volume_uuid, .. } => volume_uuid.clone(),
                    RootSpec::Snapshot { volume_uuid, .. } => Some(volume_uuid.clone()),
                    RootSpec::Ephemeral | RootSpec::CloudOptIn { .. } => None,
                })
                .ok_or_else(|| fail(Error::from(Errno::ENOENT)))?
        };
        let js_store = JsCowfsStore { obj: store };
        let source_vol = VolumeId(source_uuid);
        let snap = js_store
            .get_snapshot(&source_vol, &snapshot_name)
            .await
            .map_err(|e| fail(Error::from(e)))?;
        let hex = crate::random_hex(16);
        let rolled_uuid = format!(
            "{}-{}-4{}-8{}-{}",
            &hex[0..8],
            &hex[8..12],
            &hex[13..16],
            &hex[17..20],
            &hex[20..32]
        );
        js_store
            .fork_volume(&cowtree::ForkRequest {
                source_volume: source_vol,
                source_snapshot: Some(snapshot_name),
                source_root: snap.root,
                new_volume: VolumeId(rolled_uuid.clone()),
                ephemeral_if_unmodified: false,
                created_at: now_timespec(),
            })
            .await
            .map_err(|e| fail(Error::from(e)))?;
        Ok(rolled_uuid)
    }
}

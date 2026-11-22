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
    BOOT_PROFILE_PATH, BootProfile, BootStage, COWFSCK_REPORT_PATH, MOUNTED_ROOT_INFO_PATH,
    MountedRootInfo, RecoveryReason, RecoveryState, RootSpec,
};
use crate::cowfs_bridge::{
    JsCowfsStore, close_clean_with_prune_fs, cowfsck_volume_stores, now_timespec,
    open_for_boot_stores,
};
use crate::local_accounts::seed_fresh_cowfs_root;
use crate::vfs_engine::BootVfsOptions;
use crate::{
    CloudSession, INIT, Kernel, ensure_remote_attached_state, fail, now_secs,
    revoke_remote_tokens_state, service_auth_request,
};
use abi::auth_v2::{self, DetachInstance, MintServiceCred, RemoteScope};
use abi::contract::{fs_magic, mount_flags, umount_flags};
use abi::{Errno, Error, S_IFDIR};
use cowfs::CowFsConfig;
use cowtree::{ArenaConfig, COWFS_FORMAT_VERSION, HeadStore, VolumeId};
use serde_json::{Value, json};
use std::rc::Rc;
use vfs::imagefs::{BuildAssetSizes, ImageFs};
use vfs::memfs::MemFs;
use vfs::{Cred, Filesystem, FsId, FsType, MountBacking, MountFlags, SetAttr, StartAnchor, Vfs};
use wasm_bindgen::prelude::*;

async fn ensure_dir_vfs(vfs: &Vfs, path: &str, mode: u16) -> vfs::Result<()> {
    let mut cur = String::new();
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    for (i, part) in parts.iter().enumerate() {
        cur.push('/');
        cur.push_str(part);
        let is_last = i + 1 == parts.len();
        let m = if is_last { mode } else { 0o755 };
        match vfs.mkdirat(INIT, StartAnchor::Root, &cur, m).await {
            Ok(_) | Err(Errno::EEXIST) => {
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
                        unlink_oldroot_bounded(vfs, child_fd, oldroot_dev).await;
                    }
                    let _ = vfs.close(INIT, child_fd).await;
                }
                let _ = vfs
                    .unlinkat(INIT, StartAnchor::DirFd(dir_fd), &name, true)
                    .await;
            } else {
                let _ = vfs
                    .unlinkat(INIT, StartAnchor::DirFd(dir_fd), &name, false)
                    .await;
            }
        }
    })
}

fn default_asset_sizes() -> BuildAssetSizes {
    BuildAssetSizes {
        coreutils: 64 * 1024,
        utilities: 64 * 1024,
        dash: 64 * 1024,
        supervise: 64 * 1024,
        init: 64 * 1024,
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
            "root_fstype": if rt.root_cowfs.is_some() { "cowfs" } else { "tmpfs" },
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
            }),
        }
    }

    /// Mount optional `FsType::Cloud` at `/mnt/cloud` in `system_mnt_ns` and every active session
    /// namespace. Requires an active `CloudSession` with `scope.cloud_fs == true`.
    pub(crate) async fn mount_cloud_fs_internal(&self) -> vfs::Result<()> {
        let allowed = self
            .state
            .borrow()
            .cloud_session
            .as_ref()
            .is_some_and(|cs| cs.scope.cloud_fs);
        if !allowed {
            return Err(Errno::ENOTCONN);
        }
        let (vfs, cloud_mount, namespaces) = {
            let rt = self.vfs_rt.borrow();
            let mut nss = vec![rt.vfs.system_namespace()];
            for sess in rt.sessions.values() {
                nss.push(Rc::clone(&sess.mnt_ns));
            }
            if let Some(guest) = &rt.guest_page {
                nss.push(Rc::clone(&guest.mnt_ns));
            }
            (rt.vfs.clone(), Rc::clone(&rt.cloud_mount), nss)
        };
        let _ = ensure_dir_vfs(&vfs, "/mnt/cloud", 0o755).await;
        let backing = Rc::new(MountBacking::new(
            Rc::clone(&cloud_mount) as Rc<dyn Filesystem>,
            FsType::Cloud,
        ));
        let mut root_cred = Cred::root();
        root_cred.umask = 0;
        let mut mounted_any = false;
        for ns in namespaces {
            let already = ns
                .borrow()
                .mounts()
                .values()
                .any(|m| m.slot.backing.fstype == FsType::Cloud && m.root_in_fs == "/");
            if already {
                mounted_any = true;
                continue;
            }
            if self
                .with_page_scope(
                    false,
                    vfs.mount_on_namespace(
                        &ns,
                        &root_cred,
                        Rc::clone(&backing),
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
                .is_ok()
            {
                mounted_any = true;
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

        let (volume_uuid, writer_mode) = match &profile.root {
            RootSpec::CowFs {
                volume_uuid,
                writer_mode,
            } => (volume_uuid.clone(), *writer_mode),
            RootSpec::CloudOptIn { .. } => {
                return Ok(enter_recovery(
                    RecoveryReason::IoError {
                        errno: "EOPNOTSUPP".into(),
                        detail: "Standalone boot requires a local CowFs root".into(),
                    },
                    None,
                    Vec::new(),
                    "Standalone offline boot requires a local os-cowfs root.".into(),
                ));
            }
        };

        if profile.recovery {
            let snaps = match &volume_uuid {
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
                volume_uuid,
                snaps,
                "Boot profile requested Stage 1 recovery chooser.".into(),
            ));
        }

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

        // 2. If opening an existing volume, run `cowfsck` pre-mount integrity check.
        if let Some(ref existing_uuid) = volume_uuid {
            let vol_id = VolumeId(existing_uuid.clone());
            match cowfsck_volume_stores(&*js_store, &*js_store, &vol_id).await {
                Ok(report) => {
                    let report_bytes =
                        serde_json::to_vec_pretty(&report).unwrap_or_else(|_| b"{}".to_vec());
                    let _ = write_file_vfs(&vfs, COWFSCK_REPORT_PATH, &report_bytes, 0o444).await;
                    if !report.ok {
                        let detail = if report.errors.is_empty() {
                            "cowfsck reported volume corruption".into()
                        } else {
                            report.errors.join("; ")
                        };
                        let snaps: Vec<String> = js_store
                            .list_snapshots(&vol_id)
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
                                "Stage 1 cowfsck detected corruption on volume {existing_uuid}: {detail}"
                            ),
                        ));
                    }
                }
                Err(Errno::EPROTONOSUPPORT) => {
                    return Ok(enter_recovery(
                        RecoveryReason::IncompatibleFormat {
                            found_version: None,
                            expected_version: COWFS_FORMAT_VERSION,
                        },
                        Some(existing_uuid.clone()),
                        Vec::new(),
                        format!(
                            "cowfsck rejected volume {existing_uuid}: incompatible format version (EPROTONOSUPPORT)."
                        ),
                    ));
                }
                Err(Errno::ENOENT) => {
                    // Volume UUID not yet present in store — fall through to provision below.
                }
                Err(e) => {
                    let snaps: Vec<String> = js_store
                        .list_snapshots(&vol_id)
                        .await
                        .unwrap_or_default()
                        .into_iter()
                        .map(|s| s.name)
                        .collect();
                    return Ok(enter_recovery(
                        RecoveryReason::CorruptVolume {
                            detail: format!("cowfsck failed: {e:?}"),
                            snapshots: snaps.clone(),
                        },
                        Some(existing_uuid.clone()),
                        snaps,
                        format!("Stage 1 cowfsck failed on volume {existing_uuid} ({e:?})."),
                    ));
                }
            }
        }

        // 3. Provision or open `os-cowfs` root volume (`ForkOnBusy` default).
        let clock: Rc<dyn Fn() -> abi::fs::Timespec> = Rc::new(now_timespec);
        let config =
            CowFsConfig::local_browser(Rc::clone(&clock)).with_arena(ArenaConfig::fixed_32mib());
        let opened = match open_for_boot_stores(
            Rc::clone(&js_store),
            Rc::clone(&js_store),
            volume_uuid.clone(),
            writer_mode.to_cowtree_mode(),
            None,
            None::<&vfs::imagefs::MemoryBlobStore>,
            config,
            || format!("vol-{}", crate::random_hex(8)),
        )
        .await
        {
            Ok(res) => res,
            Err(Errno::EPROTONOSUPPORT) => {
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
            Err(Errno::EBUSY) => {
                let busy = volume_uuid.clone().unwrap_or_default();
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
            Err(e) => {
                return Ok(enter_recovery(
                    RecoveryReason::IoError {
                        errno: format!("{e:?}"),
                        detail: format!("os-cowfs open failed: {e:?}"),
                    },
                    volume_uuid,
                    Vec::new(),
                    format!("Failed to open os-cowfs root volume ({e:?})."),
                ));
            }
        };

        // Always ensure essential FHS dirs & default `/etc/*` exist on fresh boot without
        // overwriting any existing user files on reboot.
        if let Err(e) = seed_fresh_cowfs_root(&*opened.fs).await {
            return Err(fail(Error::from(e)));
        }
        let _ = opened.fs.commit_tx_group().await;

        // Persist first-boot minted volume UUID into profile & `/run/os/boot-profile.json`.
        if let RootSpec::CowFs {
            volume_uuid: ref mut vu,
            ..
        } = profile.root
            && vu.is_none()
        {
            *vu = Some(opened.volume_uuid.clone());
        }
        let profile_bytes = serde_json::to_vec_pretty(&profile).unwrap_or_else(|_| b"{}".to_vec());
        let _ = write_file_vfs(&vfs, BOOT_PROFILE_PATH, &profile_bytes, 0o444).await;

        let info = MountedRootInfo {
            fstype: "cowfs".into(),
            volume_uuid: opened.volume_uuid.clone(),
            forked_from: opened.forked_from.clone(),
            base_epoch: opened.base_epoch,
            ephemeral_if_unmodified: opened.ephemeral_if_unmodified,
            first_boot_seeded: opened.first_boot_seeded,
            writer_mode,
            mounted_at: now_secs(),
        };
        let info_bytes = serde_json::to_vec_pretty(&info).unwrap_or_else(|_| b"{}".to_vec());
        let _ = write_file_vfs(&vfs, MOUNTED_ROOT_INFO_PATH, &info_bytes, 0o444).await;

        let mut banners = Vec::new();
        if let Some(ref parent) = info.forked_from {
            banners.push(format!(
                "ForkOnBusy: booted on O(1) copy-on-write fork {} (parent {}); unmodified forks are pruned automatically on clean exit.",
                info.volume_uuid, parent
            ));
        }

        // 4. Mount `os-cowfs` at `/sysroot`, Stage 2 `/usr` at `/sysroot/usr`, fresh `/tmp` at
        //    `/sysroot/tmp`, and pivot `/` via Contract §5 `switch_root` when Stage 1 `/` is tmpfs.
        let sys_ns = vfs.system_namespace();
        let mut root_cred = Cred::root();
        root_cred.umask = 0;
        let root_statfs = vfs
            .statfs(INIT, StartAnchor::Root, "/")
            .await
            .map_err(|e| fail(Error::from(e)))?;
        if root_statfs.f_type == fs_magic::TMPFS_MAGIC {
            ensure_dir_vfs(&vfs, "/sysroot", 0o755)
                .await
                .map_err(|e| fail(Error::from(e)))?;
            let cowfs_backing = Rc::new(MountBacking::new(
                Rc::clone(&opened.fs) as Rc<dyn Filesystem>,
                FsType::Cowfs,
            ));
            vfs.mount_on_namespace(
                &sys_ns,
                &root_cred,
                cowfs_backing,
                None,
                &format!("cowfs:{}", info.volume_uuid),
                "/sysroot",
                MountFlags::default(),
                0,
                None,
            )
            .await
            .map_err(|e| fail(Error::from(e)))?;

            // Mount Stage 2 `/usr` (`ImageFs`, `ro,nodev`) at `/sysroot/usr`.
            let mounted_at = now_timespec();
            let usr_fs_id = FsId("image:usr".to_string());
            let sizes = opts
                .as_ref()
                .and_then(|o| o.build_asset_sizes)
                .unwrap_or_else(default_asset_sizes);
            let blob_store = crate::release_v2::VerifiedAssetBlobStore;
            let usr_image = if let Some(comp_json) =
                opts.as_ref().and_then(|o| o.system_composition.as_ref())
            {
                ImageFs::from_composition_json(
                    usr_fs_id.clone(),
                    true,
                    mounted_at,
                    comp_json,
                    blob_store,
                )
                .map_err(|e| fail(Error::from(e)))?
            } else {
                ImageFs::from_build_assets(usr_fs_id.clone(), sizes, mounted_at, blob_store)
            };
            let mut usr_blob_paths = std::collections::HashMap::new();
            for (bin_path, asset_url) in [
                ("/usr/bin/init", "/usr/bin/init.wasm"),
                ("/usr/bin/supervise", "/usr/bin/supervise.wasm"),
                ("/usr/bin/dash", "/usr/bin/dash.wasm"),
                ("/usr/bin/coreutils", "/usr/bin/coreutils.wasm"),
                ("/usr/bin/utilities", "/usr/bin/utilities.wasm"),
            ] {
                if let Some(h) = usr_image.handle_at(bin_path) {
                    usr_blob_paths.insert(h.node.ino, asset_url.to_string());
                }
            }
            let usr_subroot = usr_image.handle_at("/usr").map(|h| (h, "/usr".to_string()));
            let usr_backing = Rc::new(
                MountBacking::new(Rc::new(usr_image), FsType::Image).with_ceilings(true, false),
            );
            vfs.mount_on_namespace(
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

            // Contract §5 `switch_root`:
            // Detach Stage 1 `/usr` & `/tmp`, retain `oldroot_fd`, `MS_MOVE` `/proc`, `/dev`,
            // `/run`, `/mnt/local`, `/mnt/shared`, `/opt/private` onto `/sysroot/...`, then
            // `chdir("/sysroot")`, `mount(".", "/", MS_MOVE)`, `chroot(".")`, `chdir("/")`, and
            // reclaim Stage 1 `tmpfs` strictly bounded by `oldroot_dev`!
            let _ = vfs.umount2(INIT, "/usr", umount_flags::MNT_DETACH).await;
            let _ = vfs.umount2(INIT, "/tmp", umount_flags::MNT_DETACH).await;
            let oldroot_fd = vfs
                .openat(
                    INIT,
                    StartAnchor::Root,
                    "/",
                    abi::O_RDONLY | abi::O_DIRECTORY,
                    0,
                )
                .await
                .map_err(|e| fail(Error::from(e)))?;
            let oldroot_dev = vfs
                .fstat(INIT, oldroot_fd)
                .await
                .map_err(|e| fail(Error::from(e)))?
                .dev;

            for sub in [
                "/proc",
                "/dev",
                "/run",
                "/mnt/local",
                "/mnt/shared",
                "/opt/private",
            ] {
                let dst = format!("/sysroot{sub}");
                let _ = vfs
                    .mount(INIT, sub, &dst, None, mount_flags::MS_MOVE, None)
                    .await;
            }
            vfs.chdir(INIT, "/sysroot")
                .await
                .map_err(|e| fail(Error::from(e)))?;
            vfs.mount(INIT, ".", "/", None, mount_flags::MS_MOVE, None)
                .await
                .map_err(|e| fail(Error::from(e)))?;
            vfs.chroot(INIT, ".")
                .await
                .map_err(|e| fail(Error::from(e)))?;
            vfs.chdir(INIT, "/")
                .await
                .map_err(|e| fail(Error::from(e)))?;
            unlink_oldroot_bounded(&vfs, oldroot_fd, oldroot_dev).await;
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
        }

        {
            let mut rt = self.vfs_rt.borrow_mut();
            rt.root_cowfs = Some(opened.fs);
            rt.mounted_root = Some(info);
            rt.boot_profile = profile.clone();
            rt.boot_stage = BootStage::Stage2;
            rt.recovery = None;
            rt.banners = banners;
        }

        // Load configured local auto-login user (`BootProfile.default_user`) from local `/etc/passwd`.
        let account = self
            .resolve_local_user_account(&vfs, &profile.default_user)
            .await
            .unwrap_or_default();
        self.apply_account_update(account);
        self.refresh_local_account_caches(&vfs).await;
        Ok(self.boot_status_json().to_string())
    }

    /// Cleanly commit, prune unmodified `ForkOnBusy` fork if applicable, and release the `os-cowfs`
    /// root volume Web Lock (called on clean shutdown / `pagehide`).
    pub async fn close_clean_root(&self) -> Result<String, JsValue> {
        let vfs = self.vfs_rt.borrow().vfs.clone();
        // Capture `/run/os/shutdown` written by PID 1 BEFORE closing the `os-cowfs` root volume.
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
            let mut rt = self.vfs_rt.borrow_mut();
            let base = rt.mounted_root.as_ref().map_or(0, |m| m.base_epoch);
            (rt.root_cowfs.take(), base)
        };
        let Some(fs) = cowfs else {
            if let Some(marker) = shutdown_marker {
                self.vfs_rt.borrow_mut().last_shutdown = Some(marker);
            }
            return Ok(json!({ "closed": false, "pruned": false }).to_string());
        };
        let outcome = close_clean_with_prune_fs(&fs, base_epoch)
            .await
            .map_err(|e| fail(Error::from(e)))?;
        let recorded = shutdown_marker.unwrap_or_else(|| json!({ "clean": true }));
        self.vfs_rt.borrow_mut().last_shutdown = Some(recorded.clone());
        Ok(json!({
            "closed": true,
            "pruned": outcome.pruned,
            "volume_uuid": outcome.volume_uuid,
            "shutdown": recorded,
        })
        .to_string())
    }

    /// Return current Cloud / Cluster Sign-In status (ZERO network RPCs).
    pub fn cloud_status(&self) -> String {
        self.cloud_status_json().to_string()
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

        let local_uid = self.state.borrow().account.uid;
        let local_gid = self.state.borrow().account.gid;
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
                login_generation: st.account_epoch,
                scope: issued.scope.clone(),
                page_token: issued.token.clone(),
                signed_in_at: now_secs(),
                revoked: false,
            });
            old
        };
        let _ = cloud_uid;
        if let Some((old_uid, old_tok)) = prev_session {
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
    /// - Unmounts `/mnt/cloud` (`MNT_DETACH`) and detaches all remote devices.
    /// - Revokes all `ServiceAuth v2` tokens + detaches instance lease.
    /// - Removes `/run/user/<uid>/cloud-creds.json`.
    /// - NEVER kills, signals, or logs out any local process or local account!
    pub async fn cloud_sign_out(&self) -> Result<String, JsValue> {
        self.unmount_cloud_fs_internal();
        self.detach_all_remote_devices();

        let (local_uid, tokens, was_attached, instance_id, host_proof) = {
            let mut st = self.state.borrow_mut();
            let mut toks = st.table.active_remote_tokens();
            if let Some(cs) = st.cloud_session.take()
                && !cs.page_token.is_empty()
                && !toks.contains(&cs.page_token)
            {
                toks.push(cs.page_token);
            }
            for tok in &toks {
                st.table.drop_revoked_remote_token(tok);
            }
            let local_uid = st.account.uid;
            let attached = st.remote_attached;
            st.remote_attached = false;
            st.pending_revocations.clear();
            (
                local_uid,
                toks,
                attached,
                st.instance_id.clone(),
                st.host_proof.clone(),
            )
        };

        // Sync process VFS creds to clear remote tokens (keeping local identity & processes alive!).
        let pids: Vec<u32> = self.state.borrow().table.all_pids();
        for pid in pids {
            if pid != INIT {
                self.sync_vfs_proc_creds(pid);
            }
        }

        if was_attached && crate::cloudfs::installed("serviceAuthPost").is_ok() {
            if !tokens.is_empty() {
                let _ =
                    service_auth_request(&auth_v2::Request::RevokeTokens(auth_v2::RevokeTokens {
                        instance_id: instance_id.clone(),
                        host_proof: host_proof.clone(),
                        tokens,
                    }))
                    .await;
            }
            let _ = service_auth_request(&auth_v2::Request::DetachInstance(DetachInstance {
                instance_id,
                host_proof,
            }))
            .await;
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

        Ok(self.cloud_status_json().to_string())
    }

    /// Revoke active `ServiceAuth v2` remote tokens on the server while keeping `/mnt/cloud`
    /// mounted and all local processes alive (verifies non-fatal remote revocation -> `EACCES`).
    pub async fn revoke_cloud_tokens_only(&self) -> Result<String, JsValue> {
        let (attached, instance_id, host_proof, tokens) = {
            let mut st = self.state.borrow_mut();
            let mut toks = st.table.active_remote_tokens();
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
}

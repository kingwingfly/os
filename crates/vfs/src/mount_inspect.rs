//! Namespace-scoped mount inspection for mountd. Take snapshots before awaiting a driver.
use crate::mount::{MountId, NamespaceId, ProviderHealth};
use crate::{Cred, FsType, Result, Vfs, format_mountinfo};
use abi::Errno;
use abi::mount_ctl::{
    AttachmentInfo, BusyProcess, CowfsFsSummary, FilesystemInfo, unescape_mountinfo,
};
use std::collections::BTreeMap;
use std::rc::Rc;

impl Vfs {
    fn mount_holders(
        &self,
        ns_id: NamespaceId,
        caller: &Cred,
    ) -> BTreeMap<MountId, Vec<BusyProcess>> {
        let bridge = self.proc_bridge().upgrade().expect("live VFS");
        let mut holders = BTreeMap::<_, Vec<_>>::new();
        for pid in bridge.local_pids() {
            // The proc bridge also renders zombies whose pins have already been released.
            if self.process_cred(pid).is_err() {
                continue;
            }
            let Some(p) = bridge.process_info(pid) else {
                continue;
            };
            if caller.identity.id != 0 && caller.identity.id != p.uid {
                continue;
            }
            let mut reasons = BTreeMap::<_, Vec<String>>::new();
            let mut record = |pin: &crate::MountPin, reason: &str| {
                if pin.ns_id() == ns_id
                    && pin.owner_uid().is_none_or(|uid| uid == caller.identity.id)
                {
                    let why = reasons.entry(pin.id()).or_default();
                    if !why.iter().any(|r| r == reason) {
                        why.push(reason.into());
                    }
                }
            };
            record(&p.cwd.pin, "cwd");
            record(&p.root.pin, "root");
            let table = p.fds.borrow();
            for fd in table.fds() {
                if let Ok(file) = table.get(fd)
                    && let Some(pin) = file.mount_pin()
                {
                    record(pin, "fd");
                }
            }
            let comm = p
                .snapshot
                .map(|s| s.comm)
                .unwrap_or_else(|| pid.to_string());
            for (id, reasons) in reasons {
                holders.entry(id).or_default().push(BusyProcess {
                    pid,
                    uid: p.uid,
                    comm: comm.clone(),
                    reasons,
                });
            }
        }
        holders
    }

    pub fn busy_pids_for_mount(
        &self,
        ns_id: NamespaceId,
        mount_id: MountId,
        caller_cred: &Cred,
    ) -> Vec<BusyProcess> {
        self.mount_holders(ns_id, caller_cred)
            .remove(&mount_id)
            .unwrap_or_default()
    }

    pub async fn inspect_attachments(
        &self,
        ns_id: NamespaceId,
        caller_cred: &Cred,
    ) -> Result<Vec<AttachmentInfo>> {
        let bridge = self.proc_bridge().upgrade().ok_or(Errno::ESTALE)?;
        let ns = bridge.namespace_by_id(ns_id).ok_or(Errno::ENOENT)?;
        let root = ns.borrow().root_anchor();
        self.inspect_attachments_from(ns_id, caller_cred, &root, true)
            .await
    }

    pub async fn inspect_attachments_from(
        &self,
        ns_id: NamespaceId,
        caller_cred: &Cred,
        root: &crate::PathAnchor,
        include_busy: bool,
    ) -> Result<Vec<AttachmentInfo>> {
        let bridge = self.proc_bridge().upgrade().ok_or(Errno::ESTALE)?;
        let ns = bridge.namespace_by_id(ns_id).ok_or(Errno::ENOENT)?;
        let info = format_mountinfo(caller_cred, &ns, root, false).await;
        let mut holders = if include_busy {
            self.mount_holders(ns_id, caller_cred)
        } else {
            BTreeMap::new()
        };
        let ns = ns.borrow();
        let mut result = vec![];
        for line in info.lines() {
            let mut fields = line.split_ascii_whitespace();
            let Some(id) = fields.next().and_then(|s| s.parse().ok()).map(MountId) else {
                continue;
            };
            let Some(target) = fields.nth(3) else {
                continue;
            };
            let Some(entry) = ns.entry(id) else { continue };
            let slot = &entry.slot;
            let flags = slot.effective_flags();
            let source = slot
                .backing
                .cowfs_volume_device()
                .and_then(|device| device.remote_source())
                .unwrap_or_else(|| entry.source.clone());
            result.push(AttachmentInfo {
                mount_id: id.0,
                ns_id: ns_id.0,
                parent_id: entry.parent.as_ref().map_or(id, |a| a.parent_pin.id()).0,
                fs_id: slot.backing.fs.id().dev(),
                source_id: source_id(&source),
                target: unescape_mountinfo(target),
                fstype: slot.backing.fstype.as_str().into(),
                source_label: source,
                options: flags
                    .format_mount_opts()
                    .split(',')
                    .map(str::to_owned)
                    .collect(),
                read_only: flags.rdonly,
                nosuid: flags.nosuid,
                nodev: flags.nodev,
                noexec: flags.noexec,
                owner_uid: slot.owner_uid,
                user_mount: slot.owner_uid.is_some(),
                health: match slot.backing.provider.health() {
                    ProviderHealth::Connected => "connected",
                    ProviderHealth::Revoked => "revoked",
                    ProviderHealth::Expired => "expired",
                    ProviderHealth::Lost => "lost",
                }
                .into(),
                uncertain_writes: slot.backing.provider.uncertain_writes() > 0,
                busy_pids: holders.remove(&id).unwrap_or_default(),
            });
        }
        Ok(result)
    }

    pub async fn inspect_filesystems(
        &self,
        ns_id: NamespaceId,
        caller_cred: &Cred,
    ) -> Result<Vec<FilesystemInfo>> {
        let bridge = self.proc_bridge().upgrade().ok_or(Errno::ESTALE)?;
        let ns = bridge.namespace_by_id(ns_id).ok_or(Errno::ENOENT)?;
        let root = ns.borrow().root_anchor();
        self.inspect_filesystems_from(ns_id, caller_cred, &root)
            .await
    }

    pub async fn inspect_filesystems_from(
        &self,
        ns_id: NamespaceId,
        caller_cred: &Cred,
        root: &crate::PathAnchor,
    ) -> Result<Vec<FilesystemInfo>> {
        let bridge = self.proc_bridge().upgrade().ok_or(Errno::ESTALE)?;
        let ns = bridge.namespace_by_id(ns_id).ok_or(Errno::ENOENT)?;
        let mut backings = BTreeMap::new();
        for row in self
            .inspect_attachments_from(ns_id, caller_cred, root, false)
            .await?
        {
            if let Some(entry) = ns.borrow().entry(MountId(row.mount_id)) {
                backings
                    .entry(row.fs_id)
                    .or_insert_with(|| (entry.source.clone(), Rc::clone(&entry.slot.backing)));
            }
        }
        let mut result = Vec::new();
        for (fs_id, (source, backing)) in backings {
            let fs = &backing.fs;
            let capabilities = fs.capabilities();
            // Inspection never initiates remote I/O or reconnects a disconnected provider.
            let local = !matches!(
                backing.fstype,
                FsType::Cloud | FsType::ShareFs | FsType::HelperFs
            ) && capabilities.durability != abi::contract::Durability::FencedCommit
                && backing.provider.health() == ProviderHealth::Connected;
            let stat = if local {
                Some(fs.statfs(caller_cred).await?)
            } else {
                None
            };
            let mut cowfs = None;
            if local && let Some(device) = backing.cowfs_volume_device() {
                let info = device.cowfs_info().await?;
                let subvols = device
                    .cowfs_subvol(&abi::volume::CowfsSubvolReq::List {})
                    .await?;
                let snaps = device.cowfs_snap_list().await?;
                cowfs = Some(CowfsFsSummary {
                    volume: info.volume,
                    root: info.root,
                    epoch: info.epoch,
                    writer_model: info.writer_model,
                    durability: info.durability,
                    subvols: subvols.subvols.into_iter().map(|s| s.name).collect(),
                    snapshots: snaps.snapshots.into_iter().map(|s| s.name).collect(),
                });
            }
            result.push(FilesystemInfo {
                fs_id,
                fstype: backing.fstype.as_str().into(),
                label: fs.id().0.clone(),
                source,
                blocks: stat.as_ref().map_or(0, |s| s.blocks.min(abi::fs::JS_SAFE)),
                bfree: stat
                    .as_ref()
                    .map_or(0, |s| s.blocks_free.min(abi::fs::JS_SAFE)),
                bavail: stat
                    .as_ref()
                    .map_or(0, |s| s.blocks_free.min(abi::fs::JS_SAFE)),
                bsize: stat
                    .as_ref()
                    .map_or(0, |s| s.block_size.min(u64::from(u32::MAX)) as u32),
                files: stat.as_ref().map_or(0, |s| s.files.min(abi::fs::JS_SAFE)),
                ffree: stat
                    .as_ref()
                    .map_or(0, |s| s.files_free.min(abi::fs::JS_SAFE)),
                capabilities,
                cowfs,
            });
        }
        Ok(result)
    }
}

fn source_id(source: &str) -> Option<String> {
    [
        "src:",
        "volume:",
        "snapshot:",
        "remote:volume:",
        "remote:snapshot:",
        "opfs:",
        "cloud:",
        "/dev/loop",
    ]
    .iter()
    .any(|p| source.starts_with(p))
    .then(|| source.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DefaultFilesystemFactory, FsId, Identity, MountBacking, MountFlags, StartAnchor,
        memfs::MemFs, now_or_never,
    };
    use std::future::Future;

    fn run<T>(f: impl Future<Output = Result<T>>) -> T {
        now_or_never(f).unwrap().unwrap()
    }
    fn cred(uid: u32) -> Cred {
        Cred::new(Identity {
            id: uid,
            group: uid,
            groups: [uid].into(),
        })
    }
    fn backing(name: &str) -> Rc<MountBacking> {
        Rc::new(MountBacking::new(
            Rc::new(MemFs::new(
                FsId(name.into()),
                1,
                0,
                0,
                0o755,
                Box::new(|| (42, 0)),
            )),
            FsType::TmpFs,
        ))
    }

    #[test]
    fn cwd_root_and_duplicate_fds_are_reported_once_per_visible_process() {
        let vfs = run(Vfs::boot(
            "inspect",
            backing("root"),
            "root",
            Rc::new(DefaultFilesystemFactory::default()),
        ));
        let ns = vfs.system_namespace();
        let ns_id = ns.borrow().id();
        run(vfs.mkdirat(1, StartAnchor::Root, "/space dir", 0o755));
        run(vfs.mount(1, "tmpfs", "/space dir", Some("tmpfs"), 0, None));
        for (pid, uid) in [(2, 0), (3, 1234), (4, 2345)] {
            vfs.spawn_process(pid, 1, cred(uid), None, None, None)
                .unwrap();
            run(vfs.chdir(pid, "/space dir"));
            for _ in 0..2 {
                run(vfs.openat(pid, StartAnchor::AtFdCwd, ".", 0, 0));
            }
        }
        run(vfs.chroot(2, "/space dir"));
        let rows = run(vfs.inspect_attachments(ns_id, &Cred::root()));
        let mounted = rows.iter().find(|a| a.target == "/space dir").unwrap();
        let jail = vfs.process_fs_context(2).unwrap().borrow().root.clone();
        let jailed = run(vfs.inspect_attachments_from(ns_id, &Cred::root(), &jail, false));
        assert_eq!(jailed.len(), 1);
        assert_eq!(jailed[0].target, "/");
        assert!(jailed[0].busy_pids.is_empty());
        assert_eq!(
            run(vfs.inspect_filesystems_from(ns_id, &Cred::root(), &jail))[0].fs_id,
            mounted.fs_id
        );
        assert_eq!(mounted.busy_pids.len(), 3);
        assert_eq!(mounted.busy_pids[0].reasons, ["cwd", "root", "fd"]);
        assert_eq!(mounted.busy_pids[1].reasons, ["cwd", "fd"]);
        let mine = vfs.busy_pids_for_mount(ns_id, MountId(mounted.mount_id), &cred(1234));
        assert_eq!(mine.iter().map(|p| p.pid).collect::<Vec<_>>(), [3]);
        let (other, _) = vfs.clone_namespace(&ns);
        assert!(
            vfs.busy_pids_for_mount(
                other.borrow().id(),
                MountId(mounted.mount_id),
                &Cred::root()
            )
            .is_empty()
        );
    }

    #[test]
    fn private_attachments_and_driver_metadata_are_hidden_even_from_root() {
        let vfs = run(Vfs::boot(
            "inspect",
            backing("root"),
            "root",
            Rc::new(DefaultFilesystemFactory::default()),
        ));
        run(vfs.mkdirat(1, StartAnchor::Root, "/private", 0o755));
        run(vfs.setattrat(
            1,
            StartAnchor::Root,
            "/private",
            &crate::SetAttr {
                uid: Some(1000),
                ..Default::default()
            },
            false,
        ));
        let ns = vfs.system_namespace();
        run(vfs.mount_on_namespace(
            &ns,
            &cred(1000),
            backing("private"),
            None,
            "src:private",
            "/private",
            MountFlags::default(),
            0,
            Some(1000),
        ));
        for (uid, count) in [(0, 1), (2000, 1), (1000, 2)] {
            assert_eq!(
                run(vfs.inspect_attachments(ns.borrow().id(), &cred(uid))).len(),
                count
            );
            assert_eq!(
                run(vfs.inspect_filesystems(ns.borrow().id(), &cred(uid))).len(),
                count
            );
        }
    }
}

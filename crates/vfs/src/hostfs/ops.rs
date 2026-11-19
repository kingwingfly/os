use super::{
    Backing, Fingerprint, HostEntry, HostFs, HostKind, HostTree, InodeRecord, LockGuard, MetaBatch,
    MetaStore, OpenEntry, PendingRename, PendingTruncate, ProfileLocks, ROOT_INO,
    STORE_FORMAT_VERSION, StoreHeader,
};
use crate::{
    Access, Cred, DirEntry, Entry, FILE_MAX, FileType, Handle, LockKind, Metadata, NodeId,
    OpenOptions, OpenRef, RenameFlags, Result, SetAttr, StatFs, Stop, Timespec, Walked, WriteAt,
    Written, XattrFlags, check_component,
};
use abi::Errno;
use os_core::acl::Entries;
use os_core::inode;
use os_core::permissions::{EXEC, Identity, Node, READ, WRITE, created};
use os_core::xattr::{self, Space};
use std::collections::{BTreeMap, BTreeSet};

const PAGE_BYTES: u64 = 4096;
const RW_MAX: usize = 0x7fff_f000;
const CAPACITY_BLOCKS: u64 = (256 << 20) / PAGE_BYTES;
const TRUNCATE_ROLLBACK_MAX: u64 = 16 * 1024 * 1024;

fn join_rel(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

impl<T: HostTree, M: MetaStore, L: ProfileLocks> HostFs<T, M, L> {
    pub(super) fn make_handle(&self, ino: u64) -> Handle {
        Handle {
            fs: self.id.clone(),
            node: NodeId {
                ino,
                generation: self.generation,
            },
            proof: String::new(),
        }
    }

    pub(super) fn metadata_of(inode: &InodeRecord) -> Metadata {
        Metadata {
            file_type: inode.file_type(),
            mode: inode.meta.mode & 0o7777,
            nlink: inode.nlink,
            uid: inode.meta.owner,
            gid: inode.meta.group,
            size: match inode.file_type() {
                FileType::Symlink => inode.meta.link.as_ref().map_or(0, |l| l.len() as u64),
                FileType::Dir => PAGE_BYTES,
                _ => inode.size,
            },
            mtime: Timespec::from(inode.mtime),
            ctime: Timespec::from(inode.ctime),
            atime: Timespec::from(inode.atime),
            rdev: inode.meta.rdev.clone(),
            acl: inode.meta.acl.is_some(),
        }
    }

    fn make_entry(&self, inode: &InodeRecord) -> Entry {
        Entry {
            handle: self.make_handle(inode.ino),
            metadata: Self::metadata_of(inode),
        }
    }

    pub(super) async fn ensure_version(&self) -> Result<()> {
        if let Some(v) = self.meta.read_version().await?
            && v > STORE_FORMAT_VERSION
        {
            return Err(Errno::EPROTONOSUPPORT);
        }
        Ok(())
    }

    pub(super) fn read_ns_kind(&self) -> LockKind {
        match self.kind {
            HostKind::Directory => LockKind::Exclusive,
            HostKind::Opfs => LockKind::Shared,
        }
    }

    async fn acquire_raw_ns(&self, kind: LockKind) -> Result<Box<dyn LockGuard>> {
        let name = format!("os-fs-ns:{}", self.uuid);
        self.locks.acquire(&name, kind).await
    }

    pub(super) async fn ns_lock(&self, kind: LockKind) -> Result<Box<dyn LockGuard>> {
        loop {
            let guard = self.acquire_raw_ns(kind).await?;
            let has_pending = self
                .meta
                .read_header()
                .await?
                .is_some_and(|h| h.pending_rename.is_some() || h.pending_truncate.is_some());
            if !has_pending {
                return Ok(guard);
            }
            // A previous tab crashed mid-rename or mid-truncate: recover under Exclusive lock
            // before any surviving tab reads stale state or starts another mutation.
            if kind == LockKind::Exclusive {
                self.recover_pending().await?;
                return Ok(guard);
            }
            drop(guard);
            let ex_guard = self.acquire_raw_ns(LockKind::Exclusive).await?;
            self.recover_pending().await?;
            drop(ex_guard);
        }
    }

    async fn acquire_open_guard(&self, ino: u64, open_id: u64) -> Result<Box<dyn LockGuard>> {
        let name = format!("os-fs-open:{}:{ino}:{open_id}", self.uuid);
        self.locks.acquire(&name, LockKind::Exclusive).await
    }

    async fn has_external_opens(&self, ino: u64) -> Result<bool> {
        let local_open = self
            .local
            .borrow()
            .opens
            .values()
            .any(|entry| entry.ino == ino);
        if local_open {
            return Ok(true);
        }
        let prefix = format!("os-fs-open:{}:{ino}:", self.uuid);
        let held = self.locks.held_locks().await?;
        Ok(held.iter().any(|name| name.starts_with(&prefix)))
    }

    async fn recover_pending(&self) -> Result<()> {
        let mut header = self.load_header().await?;
        if header.pending_rename.is_none() && header.pending_truncate.is_none() {
            return Ok(());
        }
        let mut batch = MetaBatch::default();

        if let Some(pr) = header.pending_rename.take()
            && self.kind == HostKind::Opfs
        {
            let orphans: std::collections::HashSet<u64> =
                self.tree.list_orphans().await?.into_iter().collect();
            let from_exists = self.tree.stat_path(&pr.from_path).await?.is_some();
            let to_exists = self.tree.stat_path(&pr.to_path).await?.is_some();
            let staged_other_exists = match pr.staged_other_path.as_ref() {
                Some(p) => self.tree.stat_path(p).await?.is_some(),
                None => false,
            };
            let staged_orphan_exists =
                matches!(pr.staged_target_ino, Some(ino) if orphans.contains(&ino));

            // Never remove `to_path` when `from_exists && to_exists`: fallback copy staging
            // can leave an incomplete orphan while `to_path` still holds the intact destination.
            if pr.source_has_path && !from_exists && to_exists {
                self.tree
                    .move_entry(&pr.to_path, &pr.from_path, pr.is_dir)
                    .await?;
            }

            if let Some(ref other) = pr.staged_other_path
                && staged_other_exists
                && self.tree.stat_path(&pr.to_path).await?.is_none()
            {
                self.tree.move_entry(other, &pr.to_path, false).await?;
            }
            if let Some(target_ino) = pr.staged_target_ino
                && staged_orphan_exists
                && self.tree.stat_path(&pr.to_path).await?.is_none()
            {
                self.tree.restore_orphan(target_ino, &pr.to_path).await?;
            }
            if pr.removed_empty_dir && self.tree.stat_path(&pr.to_path).await?.is_none() {
                let _ = self.tree.create_dir(&pr.to_path).await;
            }
        }

        if let Some(pt) = header.pending_truncate.take()
            && let Some(mut inode) = self.meta.get_inode(pt.ino).await?
            && !inode.removed()
        {
            let (expected_fp, expected_ino) = self.dir_expectation(&inode);
            match self
                .fail_if_stale(
                    &inode,
                    self.tree
                        .set_file_len(&pt.backing, 0, expected_fp, expected_ino)
                        .await,
                )
                .await
            {
                Ok(fp) => {
                    inode.size = 0;
                    inode.meta.size = 0;
                    inode.meta.mode = pt.target_mode;
                    if self.kind == HostKind::Directory {
                        inode.fingerprint = Some(fp);
                    }
                    Self::touch(&mut inode, (self.clock)(), true);
                    batch.put_inodes.push(inode);
                }
                Err(Errno::ENOENT | Errno::ESTALE) => {}
                Err(err) => return Err(err),
            }
        }

        batch.header = Some(header);
        self.meta.commit(batch, true).await
    }

    pub(super) async fn sweep_orphans(&self) -> Result<()> {
        let _ns = self.ns_lock(LockKind::Exclusive).await?;
        let held = self.locks.held_locks().await?;

        let inodes = self.meta.list_all_inodes().await?;
        let by_ino: BTreeMap<u64, &InodeRecord> = inodes.iter().map(|r| (r.ino, r)).collect();
        let orphans = self.tree.list_orphans().await?;
        let mut delete_inodes = Vec::new();
        let mut delete_locks = Vec::new();
        for ino in orphans {
            // Restore still-linked files BEFORE checking open guards so interrupted unlinks
            // repair `live_path` even while another tab holds an open descriptor.
            if let Some(rec) = by_ino.get(&ino)
                && (rec.nlink > 0 || matches!(rec.backing, Backing::Path(_)))
            {
                if let Backing::Path(ref live_path) = rec.backing
                    && self.tree.stat_path(live_path).await?.is_none()
                {
                    self.tree.restore_orphan(ino, live_path).await?;
                }
                continue;
            }
            let prefix = format!("os-fs-open:{}:{ino}:", self.uuid);
            if held.iter().any(|name| name.starts_with(&prefix)) {
                continue;
            }
            self.tree.remove_orphan(ino).await?;
            if by_ino.contains_key(&ino) {
                delete_inodes.push(ino);
                delete_locks.push(ino);
            }
        }
        for inode in &inodes {
            if inode.ino != ROOT_INO && inode.nlink == 0 {
                let prefix = format!("os-fs-open:{}:{}:", self.uuid, inode.ino);
                if !held.iter().any(|name| name.starts_with(&prefix)) {
                    if let Backing::Orphan(orphan_ino) = inode.backing {
                        self.tree.remove_orphan(orphan_ino).await?;
                    }
                    if !delete_inodes.contains(&inode.ino) {
                        delete_inodes.push(inode.ino);
                        delete_locks.push(inode.ino);
                    }
                }
            }
        }
        if !delete_inodes.is_empty() {
            self.meta
                .commit(
                    MetaBatch {
                        delete_inodes,
                        delete_locks,
                        ..MetaBatch::default()
                    },
                    true,
                )
                .await?;
        }
        Ok(())
    }

    async fn load_header(&self) -> Result<StoreHeader> {
        self.ensure_version().await?;
        self.meta.read_header().await?.ok_or(Errno::EIO)
    }

    fn alloc_ino(header: &mut StoreHeader) -> Result<u64> {
        let ino = header.next_ino;
        if ino == 0 || ino > abi::fs::JS_SAFE {
            return Err(Errno::ENOSPC);
        }
        header.next_ino = ino + 1;
        Ok(ino)
    }

    fn alloc_open_id(header: &mut StoreHeader) -> Result<u64> {
        let id = header.next_open_id;
        if id == 0 || id > abi::fs::JS_SAFE {
            return Err(Errno::EMFILE);
        }
        header.next_open_id = id + 1;
        Ok(id)
    }

    fn check_handle_identity(&self, handle: &Handle) -> Result<u64> {
        if handle.fs != self.id || !handle.proof.is_empty() {
            return Err(Errno::EACCES);
        }
        if handle.node.generation != self.generation {
            return Err(Errno::ESTALE);
        }
        Ok(handle.node.ino)
    }

    pub(super) async fn check_live_inode(&self, handle: &Handle) -> Result<InodeRecord> {
        let ino = self.check_handle_identity(handle)?;
        self.validate_inode_by_id(ino).await
    }

    pub(super) async fn validate_inode_by_id(&self, ino: u64) -> Result<InodeRecord> {
        let inode = self.meta.get_inode(ino).await?.ok_or(Errno::ESTALE)?;
        if inode.stale {
            return Err(Errno::ESTALE);
        }
        if self.kind == HostKind::Directory {
            if inode.nlink == 0 {
                return Err(Errno::ESTALE);
            }
            if ino != ROOT_INO {
                let Backing::Path(ref path) = inode.backing else {
                    return Err(Errno::ESTALE);
                };
                match self.tree.stat_path(path).await? {
                    Some(host)
                        if host.file_type == inode.file_type()
                            && inode.fingerprint == Some(host.fingerprint) =>
                    {
                        if !self
                            .tree
                            .verify_host_entry(inode.ino, path, host.file_type == FileType::Dir)
                            .await?
                        {
                            self.mark_stale(&inode).await?;
                            return Err(Errno::ESTALE);
                        }
                    }
                    _ => {
                        self.mark_stale(&inode).await?;
                        return Err(Errno::ESTALE);
                    }
                }
            } else if self.tree.stat_path("").await?.is_none() {
                return Err(Errno::ESTALE);
            }
        }
        Ok(inode)
    }

    fn dir_expectation(&self, inode: &InodeRecord) -> (Option<Fingerprint>, Option<u64>) {
        if self.kind == HostKind::Directory {
            (inode.fingerprint, Some(inode.ino))
        } else {
            (None, None)
        }
    }

    async fn fail_if_stale<R>(&self, inode: &InodeRecord, result: Result<R>) -> Result<R> {
        match result {
            Err(Errno::ESTALE) if self.kind == HostKind::Directory => {
                self.mark_stale(inode).await?;
                Err(Errno::ESTALE)
            }
            other => other,
        }
    }

    async fn collect_stale_descendants(
        &self,
        root_stale: &InodeRecord,
        modified: &mut BTreeMap<u64, InodeRecord>,
        forgotten: &mut Vec<u64>,
    ) -> Result<()> {
        if !root_stale.meta.directory {
            return Ok(());
        }
        let prefix = match &root_stale.backing {
            Backing::Path(p) if !p.is_empty() => Some(format!("{p}/")),
            _ => None,
        };
        let all = self.meta.list_all_inodes().await?;
        let by_ino: BTreeMap<u64, InodeRecord> =
            all.into_iter().map(|rec| (rec.ino, rec)).collect();
        let mut queue = vec![root_stale.ino];
        while let Some(dir_ino) = queue.pop() {
            let child_inos: Vec<u64> = by_ino
                .get(&dir_ino)
                .map(|rec| rec.entries.values().copied().collect())
                .unwrap_or_default();
            for child_ino in child_inos {
                if modified.contains_key(&child_ino) {
                    continue;
                }
                if let Some(mut child) = by_ino.get(&child_ino).cloned() {
                    if child.meta.directory {
                        child.stale = true;
                        child.nlink = 0;
                        queue.push(child.ino);
                        forgotten.push(child.ino);
                        modified.insert(child.ino, child);
                    } else {
                        child
                            .parents
                            .retain(|(p, _)| *p != dir_ino && !modified.contains_key(p));
                        if child.parents.is_empty() {
                            child.stale = true;
                            child.nlink = 0;
                            forgotten.push(child.ino);
                        }
                        modified.insert(child.ino, child);
                    }
                }
            }
        }
        if let Some(prefix) = prefix {
            for rec in by_ino.into_values() {
                if modified.contains_key(&rec.ino) {
                    continue;
                }
                if let Backing::Path(ref bp) = rec.backing
                    && bp.starts_with(&prefix)
                {
                    let mut child = rec;
                    child.stale = true;
                    child.nlink = 0;
                    forgotten.push(child.ino);
                    modified.insert(child.ino, child);
                }
            }
        }
        Ok(())
    }

    async fn mark_stale(&self, inode: &InodeRecord) -> Result<()> {
        let mut stale_rec = inode.clone();
        stale_rec.stale = true;
        stale_rec.nlink = 0;
        let mut modified = BTreeMap::from([(stale_rec.ino, stale_rec.clone())]);
        let mut forgotten = vec![stale_rec.ino];
        self.collect_stale_descendants(&stale_rec, &mut modified, &mut forgotten)
            .await?;

        if stale_rec.meta.directory && stale_rec.ino != ROOT_INO && stale_rec.parent != 0 {
            if let Some(mut p) = self.meta.get_inode(stale_rec.parent).await?
                && p.entries.get(&stale_rec.name) == Some(&stale_rec.ino)
            {
                p.entries.remove(&stale_rec.name);
                p.nlink = p.nlink.saturating_sub(1);
                modified.insert(p.ino, p);
            }
        } else {
            for (p_ino, p_name) in &stale_rec.parents {
                if let Some(mut p) = self.meta.get_inode(*p_ino).await?
                    && p.entries.get(p_name) == Some(&stale_rec.ino)
                {
                    p.entries.remove(p_name);
                    modified.insert(p.ino, p);
                }
            }
        }
        self.meta
            .commit(
                MetaBatch {
                    put_inodes: modified.into_values().collect(),
                    ..MetaBatch::default()
                },
                false,
            )
            .await?;
        if self.kind == HostKind::Directory {
            for ino in forgotten {
                self.tree.forget_host_entry(ino).await?;
            }
        }
        Ok(())
    }

    fn default_inode_from_host(
        owner: &Identity,
        ino: u64,
        parent: u64,
        name: &str,
        path: String,
        host: &HostEntry,
    ) -> InodeRecord {
        let is_dir = host.file_type == FileType::Dir;
        let mut meta = if is_dir {
            Node::directory(owner.id, owner.group, 0o700)
        } else {
            // Initialize durable permissions from host metadata independently of mount-level
            // read-only / no-exec ceilings so browsing read-only does not strip owner write/exec bits.
            let mode = 0o600 | if host.executable { 0o100 } else { 0 };
            Node::file(owner.id, owner.group, mode, String::new(), host.size)
        };
        meta.ino = ino;
        let ts = (host.mtime.sec, host.mtime.nsec);
        let mut parents = BTreeSet::new();
        if !is_dir {
            parents.insert((parent, name.to_string()));
        }
        InodeRecord {
            ino,
            meta,
            nlink: if is_dir { 2 } else { 1 },
            size: if is_dir { 0 } else { host.size },
            entries: BTreeMap::new(),
            parent,
            name: if is_dir {
                name.to_string()
            } else {
                String::new()
            },
            parents,
            xattrs: BTreeMap::new(),
            atime: ts,
            mtime: ts,
            ctime: ts,
            backing: Backing::Path(path),
            fingerprint: Some(host.fingerprint),
            stale: false,
        }
    }

    /// Resolve or reconcile child `name` inside live `dir` (assuming caller already verified
    /// search permission on `dir` and `check_component(name)`).
    async fn resolve_child(
        &self,
        dir: &mut InodeRecord,
        name: &str,
    ) -> Result<Option<InodeRecord>> {
        if dir.removed() {
            return Ok(None);
        }
        let Backing::Path(dir_path) = dir.backing.clone() else {
            return Ok(None);
        };
        let child_path = join_rel(&dir_path, name);
        let recorded_ino = dir.entries.get(name).copied();

        match self.kind {
            HostKind::Opfs => {
                if let Some(ino) = recorded_ino
                    && let Some(child) = self.meta.get_inode(ino).await?
                    && !child.stale
                {
                    match &child.backing {
                        Backing::MetaOnly | Backing::Orphan(_) => return Ok(Some(child)),
                        Backing::Path(bp) if bp != &child_path => return Ok(Some(child)),
                        Backing::Path(bp) => {
                            if self.tree.stat_path(bp).await?.is_some() {
                                return Ok(Some(child));
                            }
                            if child.nlink > 0 && self.tree.list_orphans().await?.contains(&ino) {
                                self.tree.restore_orphan(ino, bp).await?;
                                return Ok(Some(child));
                            }
                            // Backing OPFS entry disappeared externally: prune stale mapping.
                            dir.entries.remove(name);
                            if child.meta.directory {
                                dir.nlink = dir.nlink.saturating_sub(1);
                            }
                            self.meta
                                .commit(
                                    MetaBatch {
                                        put_inodes: vec![dir.clone()],
                                        delete_inodes: vec![ino],
                                        delete_locks: vec![ino],
                                        ..MetaBatch::default()
                                    },
                                    false,
                                )
                                .await?;
                        }
                    }
                }
                let Some(host) = self.tree.stat_path(&child_path).await? else {
                    return Ok(None);
                };
                let mut header = self.load_header().await?;
                let ino = Self::alloc_ino(&mut header)?;
                let child = Self::default_inode_from_host(
                    &self.grant.owner,
                    ino,
                    dir.ino,
                    name,
                    child_path,
                    &host,
                );
                dir.entries.insert(name.to_string(), ino);
                if child.meta.directory {
                    dir.nlink += 1;
                }
                self.meta
                    .commit(
                        MetaBatch {
                            header: Some(header),
                            put_inodes: vec![dir.clone(), child.clone()],
                            ..MetaBatch::default()
                        },
                        false,
                    )
                    .await?;
                Ok(Some(child))
            }
            HostKind::Directory => {
                let host_opt = self.tree.stat_path(&child_path).await?;
                let Some(host) = host_opt else {
                    if let Some(old_ino) = recorded_ino {
                        dir.entries.remove(name);
                        let mut modified = BTreeMap::new();
                        let mut forgotten = Vec::new();
                        if let Some(mut old) = self.meta.get_inode(old_ino).await? {
                            if old.meta.directory {
                                dir.nlink = dir.nlink.saturating_sub(1);
                            }
                            old.stale = true;
                            old.nlink = 0;
                            forgotten.push(old.ino);
                            self.collect_stale_descendants(&old, &mut modified, &mut forgotten)
                                .await?;
                            modified.insert(old.ino, old);
                        }
                        modified.insert(dir.ino, dir.clone());
                        self.meta
                            .commit(
                                MetaBatch {
                                    put_inodes: modified.into_values().collect(),
                                    ..MetaBatch::default()
                                },
                                false,
                            )
                            .await?;
                        for stale_ino in forgotten {
                            self.tree.forget_host_entry(stale_ino).await?;
                        }
                    }
                    return Ok(None);
                };

                if let Some(ino) = recorded_ino
                    && let Some(child) = self.meta.get_inode(ino).await?
                    && !child.stale
                    && child.file_type() == host.file_type
                    && child.fingerprint == Some(host.fingerprint)
                    && self
                        .tree
                        .verify_host_entry(ino, &child_path, host.file_type == FileType::Dir)
                        .await?
                {
                    return Ok(Some(child));
                }

                // Either unrecorded or modified/replaced outside the OS: mark any old inode (and
                // any cached descendants) stale and mint a new inode with private defaults.
                let mut header = self.load_header().await?;
                let new_ino = Self::alloc_ino(&mut header)?;
                let new_child = Self::default_inode_from_host(
                    &self.grant.owner,
                    new_ino,
                    dir.ino,
                    name,
                    child_path.clone(),
                    &host,
                );
                let mut modified = BTreeMap::new();
                let mut forgotten = Vec::new();
                if let Some(old_ino) = recorded_ino
                    && let Some(mut old) = self.meta.get_inode(old_ino).await?
                {
                    if old.meta.directory {
                        dir.nlink = dir.nlink.saturating_sub(1);
                    }
                    old.stale = true;
                    old.nlink = 0;
                    forgotten.push(old.ino);
                    self.collect_stale_descendants(&old, &mut modified, &mut forgotten)
                        .await?;
                    modified.insert(old.ino, old);
                }
                dir.entries.insert(name.to_string(), new_ino);
                if new_child.meta.directory {
                    dir.nlink += 1;
                }
                modified.insert(dir.ino, dir.clone());
                modified.insert(new_child.ino, new_child.clone());
                self.tree
                    .retain_host_entry(new_ino, &child_path, new_child.meta.directory)
                    .await?;
                self.meta
                    .commit(
                        MetaBatch {
                            header: Some(header),
                            put_inodes: modified.into_values().collect(),
                            ..MetaBatch::default()
                        },
                        false,
                    )
                    .await?;
                for stale_ino in forgotten {
                    self.tree.forget_host_entry(stale_ino).await?;
                }
                Ok(Some(new_child))
            }
        }
    }

    /// Synchronize all direct children of `dir` with the host directory listing.
    async fn sync_directory_children(&self, dir: &mut InodeRecord) -> Result<Vec<InodeRecord>> {
        let Backing::Path(dir_path) = dir.backing.clone() else {
            return Err(Errno::ENOENT);
        };
        let host_entries = self.tree.list_dir(&dir_path).await?;
        let mut seen = BTreeSet::new();
        for (name, _) in &host_entries {
            seen.insert(name.clone());
        }
        let existing_names: Vec<String> = dir.entries.keys().cloned().collect();
        for name in existing_names {
            seen.insert(name);
        }
        let mut children = Vec::new();
        for name in seen {
            if let Some(child) = self.resolve_child(dir, &name).await? {
                children.push(child);
            }
        }
        Ok(children)
    }

    fn require_searchable(cred: &Cred, dir: &InodeRecord) -> Result<()> {
        if !dir.meta.directory {
            return Err(Errno::ENOTDIR);
        }
        inode::require(&cred.identity, &dir.meta, EXEC)
    }

    fn touch(inode: &mut InodeRecord, now: (u64, u32), content: bool) {
        if content {
            inode.mtime = now;
        }
        inode.ctime = now;
    }

    fn touch_accessed(&self, inode: &mut InodeRecord) -> bool {
        let now = (self.clock)();
        let should_update = match crate::mount::active_mount_flags() {
            Some(flags) => {
                !flags.lazytime
                    && flags.should_update_atime(
                        inode.meta.directory,
                        inode.atime,
                        inode.mtime,
                        inode.ctime,
                        now,
                    )
            }
            None => {
                inode.atime <= inode.mtime
                    || inode.atime <= inode.ctime
                    || now.0.saturating_sub(inode.atime.0) >= 24 * 60 * 60
            }
        };
        if should_update {
            inode.atime = now;
            true
        } else {
            false
        }
    }

    fn require_writable_grant(&self) -> Result<()> {
        if self.grant.read_only {
            return Err(Errno::EROFS);
        }
        Ok(())
    }

    fn check_openable(
        &self,
        cred: &Cred,
        inode: &InodeRecord,
        options: &OpenOptions,
    ) -> Result<Access> {
        let access = options.access()?;
        if access == Access::Path {
            return Ok(access);
        }
        if (access.writes() || options.is_truncate()) && inode.meta.directory {
            return Err(Errno::EISDIR);
        }
        if access.writes() || options.is_truncate() {
            self.require_writable_grant()?;
        }
        let mut mask = access.mask();
        if options.is_truncate() {
            mask |= WRITE;
        }
        inode::may_open(&cred.identity, &inode.meta, mask)?;
        if access == Access::Exec && !inode.meta.directory && !self.grant.execute {
            return Err(Errno::EACCES);
        }
        Ok(access)
    }

    async fn prepare_open(
        &self,
        header: &mut StoreHeader,
        ino: u64,
    ) -> Result<(u64, Box<dyn LockGuard>)> {
        let id = Self::alloc_open_id(header)?;
        let guard = self.acquire_open_guard(ino, id).await?;
        Ok((id, guard))
    }

    fn commit_open(
        &self,
        id: u64,
        guard: Box<dyn LockGuard>,
        cred: &Cred,
        ino: u64,
        access: Access,
    ) -> OpenRef {
        self.local.borrow_mut().opens.insert(
            id,
            OpenEntry {
                ino,
                access,
                cred: cred.identity.clone(),
                _open_guard: guard,
            },
        );
        OpenRef {
            fs: self.id.clone(),
            id,
            node: NodeId {
                ino,
                generation: self.generation,
            },
            access,
        }
    }

    async fn finish_open_existing(
        &self,
        cred: &Cred,
        inode: InodeRecord,
        options: &OpenOptions,
        access: Access,
    ) -> Result<(Entry, OpenRef)> {
        let old_header = self.load_header().await?;
        let mut header = old_header.clone();
        let (open_id, open_guard) = self.prepare_open(&mut header, inode.ino).await?;
        let truncate_reg =
            access != Access::Path && options.is_truncate() && inode.file_type() == FileType::File;

        if !truncate_reg {
            if let Err(err) = self
                .meta
                .commit(
                    MetaBatch {
                        header: Some(header),
                        ..MetaBatch::default()
                    },
                    false,
                )
                .await
            {
                drop(open_guard);
                return Err(err);
            }
            let open = self.commit_open(open_id, open_guard, cred, inode.ino, access);
            return Ok((self.make_entry(&inode), open));
        }

        let old_inode = inode.clone();
        let (expected_fp, expected_ino) = self.dir_expectation(&inode);
        let trunc_backup = if inode.size > 0 && inode.size <= TRUNCATE_ROLLBACK_MAX {
            Some(
                self.fail_if_stale(
                    &inode,
                    self.tree
                        .read_file(
                            &inode.backing,
                            0,
                            inode.size as usize,
                            expected_fp,
                            expected_ino,
                        )
                        .await,
                )
                .await?,
            )
        } else {
            None
        };

        let mut post_trunc = inode.clone();
        post_trunc.size = 0;
        post_trunc.meta.size = 0;
        inode::remove_privs(&cred.identity, &mut post_trunc.meta);
        Self::touch(&mut post_trunc, (self.clock)(), true);

        let pt = PendingTruncate {
            ino: inode.ino,
            backing: inode.backing.clone(),
            target_mode: post_trunc.meta.mode,
        };
        header.pending_truncate = Some(pt.clone());

        // Persist `pending_truncate` + `open_id` BEFORE touching host bytes (without shrinking
        // `inode.size` prematurely): commit errors never truncate any file size, and crashes
        // before Commit 1 reconcile host & metadata under `recover_pending`.
        if let Err(err) = self
            .meta
            .commit(
                MetaBatch {
                    header: Some(header.clone()),
                    ..MetaBatch::default()
                },
                true,
            )
            .await
        {
            drop(open_guard);
            return Err(err);
        }

        let fp = match self
            .fail_if_stale(
                &old_inode,
                self.tree
                    .set_file_len(&inode.backing, 0, expected_fp, expected_ino)
                    .await,
            )
            .await
        {
            Ok(fp) => fp,
            Err(err) => {
                let put_inodes = if err == Errno::ESTALE && self.kind == HostKind::Directory {
                    let mut stale = old_inode;
                    stale.stale = true;
                    vec![stale]
                } else {
                    Vec::new()
                };
                let _ = self
                    .meta
                    .commit(
                        MetaBatch {
                            header: Some(old_header),
                            put_inodes,
                            ..MetaBatch::default()
                        },
                        true,
                    )
                    .await;
                drop(open_guard);
                return Err(err);
            }
        };

        header.pending_truncate = None;
        if self.kind == HostKind::Directory {
            post_trunc.fingerprint = Some(fp);
        }
        if let Err(err) = self
            .meta
            .commit(
                MetaBatch {
                    header: Some(header),
                    put_inodes: vec![post_trunc],
                    ..MetaBatch::default()
                },
                true,
            )
            .await
        {
            let mut rollback_header = old_header;
            let mut rollback_inode = old_inode;
            let dir_fp = (self.kind == HostKind::Directory).then_some(fp);
            let dir_ino = (self.kind == HostKind::Directory).then_some(rollback_inode.ino);
            let put_inodes = match trunc_backup {
                Some(ref old_bytes) => {
                    match self
                        .tree
                        .write_file(
                            &rollback_inode.backing,
                            0,
                            old_bytes,
                            false,
                            dir_fp,
                            dir_ino,
                        )
                        .await
                    {
                        Ok((_, restored_fp)) => {
                            if self.kind == HostKind::Directory {
                                rollback_inode.fingerprint = Some(restored_fp);
                            }
                            vec![rollback_inode]
                        }
                        Err(_) => Vec::new(),
                    }
                }
                None if rollback_inode.size == 0 => {
                    if self.kind == HostKind::Directory {
                        rollback_inode.fingerprint = Some(fp);
                    }
                    vec![rollback_inode]
                }
                None => {
                    // >16 MiB file was already truncated on disk: keep `pending_truncate` armed so
                    // the next namespace operation reconciles metadata to size 0 cleanly.
                    rollback_header.pending_truncate = Some(pt);
                    Vec::new()
                }
            };
            let _ = self
                .meta
                .commit(
                    MetaBatch {
                        header: Some(rollback_header),
                        put_inodes,
                        ..MetaBatch::default()
                    },
                    true,
                )
                .await;
            drop(open_guard);
            return Err(err);
        }

        let open = self.commit_open(open_id, open_guard, cred, inode.ino, access);
        Ok((self.make_entry(&inode), open))
    }

    pub(super) fn get_open_info(&self, open: &OpenRef) -> Result<(u64, Access, Identity)> {
        if open.fs != self.id || open.node.generation != self.generation {
            return Err(Errno::EBADF);
        }
        let local = self.local.borrow();
        let entry = local
            .opens
            .get(&open.id)
            .filter(|e| e.ino == open.node.ino)
            .ok_or(Errno::EBADF)?;
        Ok((entry.ino, entry.access, entry.cred.clone()))
    }

    pub(super) async fn do_lookup(&self, cred: &Cred, dir: &Handle, name: &str) -> Result<Entry> {
        self.ensure_version().await?;
        let _ns = self.ns_lock(LockKind::Exclusive).await?;
        let mut dir_rec = self.check_live_inode(dir).await?;
        check_component(name)?;
        Self::require_searchable(cred, &dir_rec)?;
        let child = self
            .resolve_child(&mut dir_rec, name)
            .await?
            .ok_or(Errno::ENOENT)?;
        Ok(self.make_entry(&child))
    }

    pub(super) async fn do_walk(
        &self,
        cred: &Cred,
        dir: &Handle,
        names: &[String],
    ) -> Result<Walked> {
        self.ensure_version().await?;
        let _ns = self.ns_lock(LockKind::Exclusive).await?;
        let mut current = self.check_live_inode(dir).await?;
        for name in names {
            check_component(name)?;
        }
        let mut entries = Vec::new();
        for (index, name) in names.iter().enumerate() {
            if index > 0 {
                let stop = match current.file_type() {
                    FileType::Dir => None,
                    FileType::Symlink => Some(Stop::Symlink(index - 1)),
                    _ => Some(Stop::NotDirectory(index - 1)),
                };
                if stop.is_some() {
                    return Ok(Walked { entries, stop });
                }
            }
            Self::require_searchable(cred, &current)?;
            match self.resolve_child(&mut current, name).await? {
                Some(child) => {
                    entries.push(self.make_entry(&child));
                    current = child;
                }
                None => {
                    return Ok(Walked {
                        entries,
                        stop: Some(Stop::Missing(index)),
                    });
                }
            }
        }
        Ok(Walked {
            entries,
            stop: None,
        })
    }

    pub(super) async fn do_parent(&self, dir: &Handle) -> Result<Option<(Entry, String)>> {
        self.ensure_version().await?;
        let _ns = self.ns_lock(self.read_ns_kind()).await?;
        let inode = self.check_live_inode(dir).await?;
        if !inode.meta.directory {
            return Err(Errno::ENOTDIR);
        }
        if inode.ino == ROOT_INO {
            return Ok(None);
        }
        if inode.removed() {
            return Err(Errno::ENOENT);
        }
        let parent = self
            .validate_inode_by_id(inode.parent)
            .await
            .map_err(|_| Errno::ENOENT)?;
        if parent.removed() {
            return Err(Errno::ENOENT);
        }
        Ok(Some((self.make_entry(&parent), inode.name.clone())))
    }

    pub(super) async fn do_metadata(&self, handle: &Handle) -> Result<Metadata> {
        self.ensure_version().await?;
        let _ns = self.ns_lock(self.read_ns_kind()).await?;
        let inode = self.check_live_inode(handle).await?;
        Ok(Self::metadata_of(&inode))
    }

    pub(super) async fn do_open_metadata(&self, open: &OpenRef) -> Result<Metadata> {
        self.ensure_version().await?;
        let (ino, _, _) = self.get_open_info(open)?;
        let _ns = self.ns_lock(self.read_ns_kind()).await?;
        let inode = self.validate_inode_by_id(ino).await?;
        Ok(Self::metadata_of(&inode))
    }

    pub(super) async fn do_setattr(
        &self,
        cred: &Cred,
        handle: &Handle,
        attr: &SetAttr,
    ) -> Result<Metadata> {
        self.ensure_version().await?;
        let _ns = self.ns_lock(LockKind::Exclusive).await?;
        let mut inode = self.check_live_inode(handle).await?;
        if *attr == SetAttr::default() {
            return Ok(Self::metadata_of(&inode));
        }
        self.require_writable_grant()?;
        let who = &cred.identity;
        let mut meta = inode.meta.clone();
        if let Some(mode) = attr.mode {
            inode::chmod(who, &mut meta, mode)?;
        }
        inode::chown(who, &mut meta, attr.uid, attr.gid)?;
        inode::may_set_times(who, &inode.meta, attr.atime, attr.mtime)?;
        if let Some(size) = attr.size {
            match inode.file_type() {
                FileType::Dir => return Err(Errno::EISDIR),
                FileType::File => {}
                _ => return Err(Errno::EINVAL),
            }
            inode::require(who, &inode.meta, WRITE)?;
            if size > FILE_MAX {
                return Err(Errno::EFBIG);
            }
        }
        let now = (self.clock)();
        let (expected_fp, expected_ino) = self.dir_expectation(&inode);
        inode.meta = meta;
        if let Some(size) = attr.size {
            let fp = self
                .fail_if_stale(
                    &inode,
                    self.tree
                        .set_file_len(&inode.backing, size, expected_fp, expected_ino)
                        .await,
                )
                .await?;
            inode.size = size;
            inode.meta.size = size;
            if self.kind == HostKind::Directory {
                inode.fingerprint = Some(fp);
            }
            inode::remove_privs(who, &mut inode.meta);
            Self::touch(&mut inode, now, true);
        }
        if let Some(atime) = inode::time(attr.atime, now) {
            inode.atime = atime;
        }
        if let Some(mtime) = inode::time(attr.mtime, now) {
            inode.mtime = mtime;
        }
        inode.ctime = now;
        let out = Self::metadata_of(&inode);
        self.meta
            .commit(
                MetaBatch {
                    put_inodes: vec![inode],
                    ..MetaBatch::default()
                },
                false,
            )
            .await?;
        Ok(out)
    }

    pub(super) async fn do_read_dir(&self, cred: &Cred, dir: &Handle) -> Result<Vec<DirEntry>> {
        self.ensure_version().await?;
        let _ns = self.ns_lock(LockKind::Exclusive).await?;
        let mut inode = self.check_live_inode(dir).await?;
        if !inode.meta.directory {
            return Err(Errno::ENOTDIR);
        }
        inode::require(&cred.identity, &inode.meta, READ)?;
        if inode.removed() {
            return Err(Errno::ENOENT);
        }
        let mut children = self.sync_directory_children(&mut inode).await?;
        children.sort_by(|a, b| {
            let a_name = inode
                .entries
                .iter()
                .find_map(|(k, v)| (*v == a.ino).then_some(k));
            let b_name = inode
                .entries
                .iter()
                .find_map(|(k, v)| (*v == b.ino).then_some(k));
            a_name.cmp(&b_name)
        });
        let by_ino: std::collections::HashMap<u64, &InodeRecord> =
            children.iter().map(|c| (c.ino, c)).collect();
        let entries = inode
            .entries
            .iter()
            .filter_map(|(name, child_ino)| {
                by_ino.get(child_ino).map(|child| DirEntry {
                    name: name.clone(),
                    node: NodeId {
                        ino: *child_ino,
                        generation: self.generation,
                    },
                    file_type: child.file_type(),
                })
            })
            .collect();
        if self.touch_accessed(&mut inode) {
            self.meta
                .commit(
                    MetaBatch {
                        put_inodes: vec![inode],
                        ..MetaBatch::default()
                    },
                    false,
                )
                .await?;
        }
        Ok(entries)
    }

    pub(super) async fn do_read_link(&self, link: &Handle) -> Result<String> {
        self.ensure_version().await?;
        let _ns = self.ns_lock(LockKind::Exclusive).await?;
        let mut inode = self.check_live_inode(link).await?;
        let target = inode.meta.link.clone().ok_or(Errno::EINVAL)?;
        if self.touch_accessed(&mut inode) {
            self.meta
                .commit(
                    MetaBatch {
                        put_inodes: vec![inode],
                        ..MetaBatch::default()
                    },
                    false,
                )
                .await?;
        }
        Ok(target)
    }

    pub(super) async fn do_create(
        &self,
        cred: &Cred,
        dir: &Handle,
        name: &str,
        mode: u16,
        options: &OpenOptions,
    ) -> Result<(Entry, OpenRef)> {
        self.ensure_version().await?;
        let access = options.access()?;
        if matches!(access, Access::Exec | Access::Path) {
            return Err(Errno::EINVAL);
        }
        let _ns = self.ns_lock(LockKind::Exclusive).await?;
        let mut dir_rec = self.check_live_inode(dir).await?;
        check_component(name)?;
        Self::require_searchable(cred, &dir_rec)?;

        if let Some(existing) = self.resolve_child(&mut dir_rec, name).await? {
            if options.is_create_new() {
                return Err(Errno::EEXIST);
            }
            if existing.meta.directory {
                return Err(Errno::EISDIR);
            }
            let access = self.check_openable(cred, &existing, options)?;
            return self
                .finish_open_existing(cred, existing, options, access)
                .await;
        }

        self.require_writable_grant()?;
        inode::may_create(&cred.identity, &dir_rec.meta, dir_rec.removed())?;
        let Backing::Path(dir_path) = dir_rec.backing.clone() else {
            return Err(Errno::ENOENT);
        };
        let mut header = self.load_header().await?;
        let ino = Self::alloc_ino(&mut header)?;
        let (open_id, open_guard) = self.prepare_open(&mut header, ino).await?;
        let child_path = join_rel(&dir_path, name);
        let host = match self.tree.create_file(&child_path, true, true).await {
            Ok(host) => host,
            Err(err) => {
                if err != Errno::EEXIST {
                    let _ = self.tree.remove_file(&child_path).await;
                }
                drop(open_guard);
                return Err(err);
            }
        };

        let mut meta = created(&cred.identity, &dir_rec.meta, mode, false, cred.umask);
        meta.ino = ino;
        let now = (self.clock)();
        let mut parents = BTreeSet::new();
        parents.insert((dir_rec.ino, name.to_string()));
        let child = InodeRecord {
            ino,
            meta,
            nlink: 1,
            size: 0,
            entries: BTreeMap::new(),
            parent: dir_rec.ino,
            name: String::new(),
            parents,
            xattrs: BTreeMap::new(),
            atime: now,
            mtime: now,
            ctime: now,
            backing: Backing::Path(child_path.clone()),
            fingerprint: Some(host.fingerprint),
            stale: false,
        };
        dir_rec.entries.insert(name.to_string(), ino);
        Self::touch(&mut dir_rec, now, true);

        let entry = self.make_entry(&child);
        if self.kind == HostKind::Directory
            && let Err(err) = self.tree.retain_host_entry(ino, &child_path, false).await
        {
            let _ = self.tree.remove_file(&child_path).await;
            drop(open_guard);
            return Err(err);
        }
        if let Err(err) = self
            .meta
            .commit(
                MetaBatch {
                    header: Some(header),
                    put_inodes: vec![dir_rec, child],
                    ..MetaBatch::default()
                },
                false,
            )
            .await
        {
            if self.kind == HostKind::Directory {
                let _ = self.tree.forget_host_entry(ino).await;
            }
            let _ = self.tree.remove_file(&child_path).await;
            drop(open_guard);
            return Err(err);
        }
        let open = self.commit_open(open_id, open_guard, cred, ino, access);
        Ok((entry, open))
    }

    pub(super) async fn do_mkdir(
        &self,
        cred: &Cred,
        dir: &Handle,
        name: &str,
        mode: u16,
    ) -> Result<Entry> {
        self.ensure_version().await?;
        let _ns = self.ns_lock(LockKind::Exclusive).await?;
        let mut dir_rec = self.check_live_inode(dir).await?;
        check_component(name)?;
        Self::require_searchable(cred, &dir_rec)?;
        if self.resolve_child(&mut dir_rec, name).await?.is_some() {
            return Err(Errno::EEXIST);
        }
        self.require_writable_grant()?;
        inode::may_create(&cred.identity, &dir_rec.meta, dir_rec.removed())?;
        let Backing::Path(dir_path) = dir_rec.backing.clone() else {
            return Err(Errno::ENOENT);
        };
        let mut header = self.load_header().await?;
        let ino = Self::alloc_ino(&mut header)?;
        let child_path = join_rel(&dir_path, name);
        let host = match self.tree.create_dir(&child_path).await {
            Ok(host) => host,
            Err(err) => {
                if err != Errno::EEXIST {
                    let _ = self.tree.remove_dir(&child_path).await;
                }
                return Err(err);
            }
        };

        let mut meta = created(&cred.identity, &dir_rec.meta, mode, true, cred.umask);
        meta.ino = ino;
        let now = (self.clock)();
        let child = InodeRecord {
            ino,
            meta,
            nlink: 2,
            size: 0,
            entries: BTreeMap::new(),
            parent: dir_rec.ino,
            name: name.to_string(),
            parents: BTreeSet::new(),
            xattrs: BTreeMap::new(),
            atime: now,
            mtime: now,
            ctime: now,
            backing: Backing::Path(child_path.clone()),
            fingerprint: Some(host.fingerprint),
            stale: false,
        };
        dir_rec.entries.insert(name.to_string(), ino);
        dir_rec.nlink += 1;
        Self::touch(&mut dir_rec, now, true);
        let entry = self.make_entry(&child);
        if self.kind == HostKind::Directory
            && let Err(err) = self.tree.retain_host_entry(ino, &child_path, true).await
        {
            let _ = self.tree.remove_dir(&child_path).await;
            return Err(err);
        }
        if let Err(err) = self
            .meta
            .commit(
                MetaBatch {
                    header: Some(header),
                    put_inodes: vec![dir_rec, child],
                    ..MetaBatch::default()
                },
                false,
            )
            .await
        {
            if self.kind == HostKind::Directory {
                let _ = self.tree.forget_host_entry(ino).await;
            }
            let _ = self.tree.remove_dir(&child_path).await;
            return Err(err);
        }
        Ok(entry)
    }

    pub(super) async fn do_mknod(
        &self,
        cred: &Cred,
        dir: &Handle,
        name: &str,
        mode: u16,
        rdev: &str,
    ) -> Result<Entry> {
        self.ensure_version().await?;
        if self.kind == HostKind::Directory || cred.identity.id != 0 {
            return Err(Errno::EPERM);
        }
        let _ns = self.ns_lock(LockKind::Exclusive).await?;
        let mut dir_rec = self.check_live_inode(dir).await?;
        check_component(name)?;
        Self::require_searchable(cred, &dir_rec)?;
        if self.resolve_child(&mut dir_rec, name).await?.is_some() {
            return Err(Errno::EEXIST);
        }
        self.require_writable_grant()?;
        inode::may_create(&cred.identity, &dir_rec.meta, dir_rec.removed())?;
        let mut header = self.load_header().await?;
        let ino = Self::alloc_ino(&mut header)?;
        let mut meta = created(&cred.identity, &dir_rec.meta, mode, false, cred.umask);
        meta.ino = ino;
        meta.rdev = Some(rdev.to_string());
        let now = (self.clock)();
        let mut parents = BTreeSet::new();
        parents.insert((dir_rec.ino, name.to_string()));
        let child = InodeRecord {
            ino,
            meta,
            nlink: 1,
            size: 0,
            entries: BTreeMap::new(),
            parent: dir_rec.ino,
            name: String::new(),
            parents,
            xattrs: BTreeMap::new(),
            atime: now,
            mtime: now,
            ctime: now,
            backing: Backing::MetaOnly,
            fingerprint: None,
            stale: false,
        };
        dir_rec.entries.insert(name.to_string(), ino);
        Self::touch(&mut dir_rec, now, true);
        let entry = self.make_entry(&child);
        self.meta
            .commit(
                MetaBatch {
                    header: Some(header),
                    put_inodes: vec![dir_rec, child],
                    ..MetaBatch::default()
                },
                false,
            )
            .await?;
        Ok(entry)
    }

    pub(super) async fn do_symlink(
        &self,
        cred: &Cred,
        dir: &Handle,
        name: &str,
        target: &str,
    ) -> Result<Entry> {
        self.ensure_version().await?;
        if self.kind == HostKind::Directory {
            return Err(Errno::EPERM);
        }
        inode::check_link_target(target)?;
        let _ns = self.ns_lock(LockKind::Exclusive).await?;
        let mut dir_rec = self.check_live_inode(dir).await?;
        check_component(name)?;
        Self::require_searchable(cred, &dir_rec)?;
        if self.resolve_child(&mut dir_rec, name).await?.is_some() {
            return Err(Errno::EEXIST);
        }
        self.require_writable_grant()?;
        inode::may_create(&cred.identity, &dir_rec.meta, dir_rec.removed())?;

        let mut header = self.load_header().await?;
        let ino = Self::alloc_ino(&mut header)?;
        let mut meta = inode::new_symlink(&cred.identity, &dir_rec.meta, target);
        meta.ino = ino;
        let now = (self.clock)();
        let mut parents = BTreeSet::new();
        parents.insert((dir_rec.ino, name.to_string()));
        let child = InodeRecord {
            ino,
            meta,
            nlink: 1,
            size: target.len() as u64,
            entries: BTreeMap::new(),
            parent: dir_rec.ino,
            name: String::new(),
            parents,
            xattrs: BTreeMap::new(),
            atime: now,
            mtime: now,
            ctime: now,
            backing: Backing::MetaOnly,
            fingerprint: None,
            stale: false,
        };
        dir_rec.entries.insert(name.to_string(), ino);
        Self::touch(&mut dir_rec, now, true);
        let entry = self.make_entry(&child);
        self.meta
            .commit(
                MetaBatch {
                    header: Some(header),
                    put_inodes: vec![dir_rec, child],
                    ..MetaBatch::default()
                },
                false,
            )
            .await?;
        Ok(entry)
    }

    pub(super) async fn do_link(
        &self,
        cred: &Cred,
        target: &Handle,
        dir: &Handle,
        name: &str,
    ) -> Result<Entry> {
        self.ensure_version().await?;
        if self.kind == HostKind::Directory {
            return Err(Errno::EPERM);
        }
        let _ns = self.ns_lock(LockKind::Exclusive).await?;
        let mut target_rec = self.check_live_inode(target).await?;
        let mut dir_rec = self.check_live_inode(dir).await?;
        check_component(name)?;
        Self::require_searchable(cred, &dir_rec)?;
        if self.resolve_child(&mut dir_rec, name).await?.is_some() {
            return Err(Errno::EEXIST);
        }
        self.require_writable_grant()?;
        inode::may_link(&cred.identity, &target_rec.meta)?;
        inode::may_create(&cred.identity, &dir_rec.meta, dir_rec.removed())?;
        if target_rec.nlink == 0 {
            return Err(Errno::ENOENT);
        }
        let now = (self.clock)();
        dir_rec.entries.insert(name.to_string(), target_rec.ino);
        Self::touch(&mut dir_rec, now, true);
        target_rec.nlink += 1;
        target_rec.parents.insert((dir_rec.ino, name.to_string()));
        Self::touch(&mut target_rec, now, false);
        let entry = self.make_entry(&target_rec);
        let put_inodes = if dir_rec.ino == target_rec.ino {
            vec![target_rec]
        } else {
            vec![dir_rec, target_rec]
        };
        self.meta
            .commit(
                MetaBatch {
                    put_inodes,
                    ..MetaBatch::default()
                },
                false,
            )
            .await?;
        Ok(entry)
    }

    async fn evacuate_or_remove_unlinked_link(
        &self,
        victim: &mut InodeRecord,
        unlinked_path: &str,
        extra_modified: &mut BTreeMap<u64, InodeRecord>,
    ) -> Result<(bool, Option<UndoTargetMove>, Option<u64>)> {
        if victim.meta.directory {
            self.tree.remove_dir(unlinked_path).await?;
            victim.nlink = 0;
            if self.kind == HostKind::Directory {
                victim.stale = true;
                self.tree.forget_host_entry(victim.ino).await?;
                return Ok((false, None, None));
            }
            victim.backing = Backing::MetaOnly;
            let keep = match self.has_external_opens(victim.ino).await {
                Ok(keep) => keep,
                Err(err) => {
                    let _ = self.tree.create_dir(unlinked_path).await;
                    return Err(err);
                }
            };
            return Ok((!keep, None, None));
        }

        victim.nlink = victim.nlink.saturating_sub(1);
        if self.kind == HostKind::Directory {
            self.tree.remove_file(unlinked_path).await?;
            victim.stale = true;
            victim.nlink = 0;
            self.tree.forget_host_entry(victim.ino).await?;
            return Ok((false, None, None));
        }

        // OPFS regular file / symlink / device.
        match victim.backing.clone() {
            Backing::MetaOnly => {
                if victim.nlink == 0 {
                    let keep = self.has_external_opens(victim.ino).await?;
                    return Ok((!keep, None, None));
                }
                Ok((false, None, None))
            }
            Backing::Orphan(orphan_ino) => {
                if victim.nlink == 0 {
                    let keep = self.has_external_opens(victim.ino).await?;
                    return Ok((!keep, None, (!keep).then_some(orphan_ino)));
                }
                Ok((false, None, None))
            }
            Backing::Path(bp) => {
                if victim.nlink > 0 {
                    let mut undo = None;
                    if bp == unlinked_path {
                        // Move backing OPFS file to another surviving link of this inode.
                        let (other_dir_ino, other_name) =
                            victim.parents.iter().next().cloned().ok_or(Errno::EIO)?;
                        let other_dir = if let Some(d) = extra_modified.get(&other_dir_ino) {
                            d.clone()
                        } else {
                            self.meta
                                .get_inode(other_dir_ino)
                                .await?
                                .ok_or(Errno::EIO)?
                        };
                        let Backing::Path(other_dir_path) = other_dir.backing else {
                            return Err(Errno::EIO);
                        };
                        let other_path = join_rel(&other_dir_path, &other_name);
                        self.tree.move_entry(&bp, &other_path, false).await?;
                        victim.backing = Backing::Path(other_path.clone());
                        undo = Some(UndoTargetMove::ToPath {
                            from: other_path,
                            to: bp,
                        });
                    }
                    Ok((false, undo, None))
                } else {
                    // Stage single-link regular unlink into `/os-orphans` first so commit
                    // failures can restore `unlinked_path` cleanly instead of losing data.
                    self.tree.move_to_orphan(&bp, victim.ino).await?;
                    let undo = UndoTargetMove::ToOrphan {
                        ino: victim.ino,
                        to: bp.clone(),
                    };
                    match self.has_external_opens(victim.ino).await {
                        Ok(true) => {
                            victim.backing = Backing::Orphan(victim.ino);
                            Ok((false, Some(undo), None))
                        }
                        Ok(false) => Ok((true, Some(undo), Some(victim.ino))),
                        Err(err) => {
                            let _ = self.tree.restore_orphan(victim.ino, &bp).await;
                            Err(err)
                        }
                    }
                }
            }
        }
    }

    pub(super) async fn do_remove(
        &self,
        cred: &Cred,
        dir: &Handle,
        name: &str,
        directory: bool,
        expected: Option<NodeId>,
    ) -> Result<()> {
        self.ensure_version().await?;
        let _ns = self.ns_lock(LockKind::Exclusive).await?;
        let mut dir_rec = self.check_live_inode(dir).await?;
        check_component(name)?;
        Self::require_searchable(cred, &dir_rec)?;
        let mut victim = self
            .resolve_child(&mut dir_rec, name)
            .await?
            .ok_or(Errno::ENOENT)?;
        if expected.is_some_and(|node| self.make_handle(victim.ino).node != node) {
            return Err(Errno::ESTALE);
        }
        self.require_writable_grant()?;
        inode::may_delete(&cred.identity, &dir_rec.meta, &victim.meta)?;
        match (directory, victim.meta.directory) {
            (false, true) => return Err(Errno::EISDIR),
            (true, false) => return Err(Errno::ENOTDIR),
            (true, true) => {
                let children = self.sync_directory_children(&mut victim).await?;
                if !children.is_empty() {
                    return Err(Errno::ENOTEMPTY);
                }
            }
            _ => {}
        }

        let Backing::Path(dir_path) = dir_rec.backing.clone() else {
            return Err(Errno::ENOENT);
        };
        let victim_path = join_rel(&dir_path, name);
        let now = (self.clock)();
        dir_rec.entries.remove(name);
        if directory {
            dir_rec.nlink = dir_rec.nlink.saturating_sub(1);
        }
        Self::touch(&mut dir_rec, now, true);
        victim.parents.remove(&(dir_rec.ino, name.to_string()));
        victim.ctime = now;

        let mut modified = BTreeMap::from([(dir_rec.ino, dir_rec)]);
        let (delete_victim, undo_evac, cleanup_orphan_ino) = self
            .evacuate_or_remove_unlinked_link(&mut victim, &victim_path, &mut modified)
            .await?;

        let mut batch = MetaBatch::default();
        if delete_victim {
            batch.delete_inodes.push(victim.ino);
            batch.delete_locks.push(victim.ino);
        } else {
            modified.insert(victim.ino, victim);
        }
        batch.put_inodes = modified.into_values().collect();
        if let Err(err) = self.meta.commit(batch, self.kind == HostKind::Opfs).await {
            let _ = self
                .rollback_rename_host(
                    false,
                    &victim_path,
                    &victim_path,
                    directory,
                    undo_evac,
                    directory && self.kind == HostKind::Opfs,
                )
                .await;
            return Err(err);
        }
        if let Some(orphan_ino) = cleanup_orphan_ino {
            let _ = self.tree.remove_orphan(orphan_ino).await;
        }
        Ok(())
    }

    async fn is_ancestor(&self, ancestor_ino: u64, mut ino: u64) -> Result<bool> {
        loop {
            if ino == ancestor_ino {
                return Ok(true);
            }
            if ino == ROOT_INO {
                return Ok(false);
            }
            match self.meta.get_inode(ino).await? {
                Some(rec) if !rec.removed() => ino = rec.parent,
                _ => return Ok(false),
            }
        }
    }
}

enum UndoTargetMove {
    ToPath { from: String, to: String },
    ToOrphan { ino: u64, to: String },
}

impl<T: HostTree, M: MetaStore, L: ProfileLocks> HostFs<T, M, L> {
    async fn clear_pending_rename(&self) {
        if let Ok(mut header) = self.load_header().await
            && header.pending_rename.take().is_some()
        {
            let _ = self
                .meta
                .commit(
                    MetaBatch {
                        header: Some(header),
                        ..MetaBatch::default()
                    },
                    false,
                )
                .await;
        }
    }

    async fn rollback_rename_host(
        &self,
        move_back: bool,
        from_path: &str,
        to_path: &str,
        is_dir: bool,
        undo_target: Option<UndoTargetMove>,
        recreate_empty_dir: bool,
    ) -> Result<()> {
        if move_back {
            self.tree.move_entry(to_path, from_path, is_dir).await?;
        }
        match undo_target {
            Some(UndoTargetMove::ToPath { from, to }) => {
                self.tree.move_entry(&from, &to, false).await?;
            }
            Some(UndoTargetMove::ToOrphan { ino, to }) => {
                self.tree.restore_orphan(ino, &to).await?;
            }
            None => {}
        }
        if recreate_empty_dir && self.tree.stat_path(to_path).await?.is_none() {
            self.tree.create_dir(to_path).await?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn do_rename(
        &self,
        cred: &Cred,
        from_dir: &Handle,
        from: &str,
        to_dir: &Handle,
        to: &str,
        flags: RenameFlags,
    ) -> Result<()> {
        self.ensure_version().await?;
        let _ns = self.ns_lock(LockKind::Exclusive).await?;
        let who = &cred.identity;
        let mut from_parent = self.check_live_inode(from_dir).await?;
        let mut to_parent = if from_dir.node.ino == to_dir.node.ino {
            let _ = self.check_handle_identity(to_dir)?;
            from_parent.clone()
        } else {
            self.check_live_inode(to_dir).await?
        };

        check_component(from)?;
        check_component(to)?;
        Self::require_searchable(cred, &from_parent)?;
        Self::require_searchable(cred, &to_parent)?;

        let mut source = self
            .resolve_child(&mut from_parent, from)
            .await?
            .ok_or(Errno::ENOENT)?;
        if from_parent.ino == to_parent.ino {
            to_parent = from_parent.clone();
        }
        let existing = self.resolve_child(&mut to_parent, to).await?;
        if from_parent.ino == to_parent.ino {
            from_parent = to_parent.clone();
        }

        self.require_writable_grant()?;
        if existing.is_some() && flags.contains(RenameFlags::NOREPLACE) {
            return Err(Errno::EEXIST);
        }
        inode::may_delete(who, &from_parent.meta, &source.meta)?;
        if let Some(ref target) = existing {
            inode::may_delete(who, &to_parent.meta, &target.meta)?;
        }
        if existing.as_ref().map(|e| e.ino) == Some(source.ino) {
            return Ok(());
        }

        let moving_dir = source.meta.directory;
        if moving_dir && self.is_ancestor(source.ino, to_parent.ino).await? {
            return Err(Errno::EINVAL);
        }
        if let Some(ref target) = existing {
            match (moving_dir, target.meta.directory) {
                (true, false) => return Err(Errno::ENOTDIR),
                (false, true) => return Err(Errno::EISDIR),
                (true, true) => {
                    let mut target_check = target.clone();
                    if !self
                        .sync_directory_children(&mut target_check)
                        .await?
                        .is_empty()
                    {
                        return Err(Errno::ENOTEMPTY);
                    }
                }
                _ => {}
            }
        } else {
            inode::may_create(who, &to_parent.meta, to_parent.removed())?;
        }
        if moving_dir && from_parent.ino != to_parent.ino {
            inode::require(who, &source.meta, WRITE)?;
        }

        let Backing::Path(from_dir_path) = from_parent.backing.clone() else {
            return Err(Errno::ENOENT);
        };
        let Backing::Path(to_dir_path) = to_parent.backing.clone() else {
            return Err(Errno::ENOENT);
        };
        let from_path = join_rel(&from_dir_path, from);
        let to_path = join_rel(&to_dir_path, to);

        let now = (self.clock)();
        let mut modified = BTreeMap::new();
        let mut delete_inodes = Vec::new();
        let mut delete_locks = Vec::new();

        // Update directory maps in memory first so any hard-link evacuation sees surviving links.
        from_parent.entries.remove(from);
        if moving_dir {
            from_parent.nlink = from_parent.nlink.saturating_sub(1);
        }
        Self::touch(&mut from_parent, now, true);

        if from_parent.ino == to_parent.ino {
            to_parent = from_parent.clone();
        }
        if existing.is_some() && moving_dir {
            to_parent.nlink = to_parent.nlink.saturating_sub(1);
        }
        to_parent.entries.insert(to.to_string(), source.ino);
        if moving_dir {
            to_parent.nlink += 1;
        }
        Self::touch(&mut to_parent, now, true);
        if from_parent.ino == to_parent.ino {
            modified.insert(to_parent.ino, to_parent.clone());
        } else {
            modified.insert(from_parent.ino, from_parent.clone());
            modified.insert(to_parent.ino, to_parent.clone());
        }

        let source_has_path =
            moving_dir || matches!(&source.backing, Backing::Path(bp) if bp == &from_path);
        let removed_empty_dir = existing
            .as_ref()
            .is_some_and(|target| target.meta.directory);

        // Pre-compute OPFS staging plan and persist durable `PendingRename` intent BEFORE any host
        // move or orphan evacuation runs, so crash/reload or commit failure never loses user data.
        let mut staged_header: Option<StoreHeader> = None;
        let mut planned_other_path: Option<String> = None;
        let mut planned_orphan_ino: Option<u64> = None;
        if self.kind == HostKind::Opfs && (source_has_path || existing.is_some()) {
            if let Some(ref target) = existing
                && !target.meta.directory
                && matches!(&target.backing, Backing::Path(bp) if bp == &to_path)
            {
                let mut remaining = target.parents.clone();
                remaining.remove(&(to_parent.ino, to.to_string()));
                if target.nlink > 1 {
                    let (other_dir_ino, other_name) =
                        remaining.iter().next().cloned().ok_or(Errno::EIO)?;
                    let other_dir = if let Some(d) = modified.get(&other_dir_ino) {
                        d.clone()
                    } else {
                        self.meta
                            .get_inode(other_dir_ino)
                            .await?
                            .ok_or(Errno::EIO)?
                    };
                    let Backing::Path(other_dir_path) = other_dir.backing else {
                        return Err(Errno::EIO);
                    };
                    planned_other_path = Some(join_rel(&other_dir_path, &other_name));
                } else {
                    // Stage single-link regular destinations (both open and closed) to orphan
                    // storage before moving/replacing, so commit failures/crashes never lose bytes.
                    planned_orphan_ino = Some(target.ino);
                }
            }
            let mut header = self.load_header().await?;
            header.pending_rename = Some(PendingRename {
                from_path: from_path.clone(),
                to_path: to_path.clone(),
                is_dir: moving_dir,
                source_has_path,
                staged_target_ino: planned_orphan_ino,
                staged_other_path: planned_other_path.clone(),
                removed_empty_dir,
            });
            self.meta
                .commit(
                    MetaBatch {
                        header: Some(header.clone()),
                        ..MetaBatch::default()
                    },
                    true,
                )
                .await?;
            staged_header = Some(header);
        }

        let mut undo_target = None;
        let mut forgotten_targets = Vec::new();
        let mut cleanup_orphans_after_commit = Vec::new();

        if let Some(mut target) = existing {
            target.parents.remove(&(to_parent.ino, to.to_string()));
            target.ctime = now;
            if !target.meta.directory && self.kind == HostKind::Opfs {
                target.nlink = target.nlink.saturating_sub(1);
                if let Backing::Path(bp) = target.backing.clone()
                    && bp == to_path
                {
                    if let Some(other_path) = planned_other_path {
                        if let Err(err) = self.tree.move_entry(&bp, &other_path, false).await {
                            self.clear_pending_rename().await;
                            return Err(err);
                        }
                        target.backing = Backing::Path(other_path.clone());
                        undo_target = Some(UndoTargetMove::ToPath {
                            from: other_path,
                            to: to_path.clone(),
                        });
                        modified.insert(target.ino, target);
                    } else if let Some(orphan_ino) = planned_orphan_ino {
                        if let Err(err) = self.tree.move_to_orphan(&bp, orphan_ino).await {
                            self.clear_pending_rename().await;
                            return Err(err);
                        }
                        target.backing = Backing::Orphan(orphan_ino);
                        undo_target = Some(UndoTargetMove::ToOrphan {
                            ino: orphan_ino,
                            to: to_path.clone(),
                        });
                        if target.nlink == 0 {
                            match self.has_external_opens(target.ino).await {
                                Ok(true) => {
                                    modified.insert(target.ino, target);
                                }
                                Ok(false) => {
                                    delete_inodes.push(target.ino);
                                    delete_locks.push(target.ino);
                                    cleanup_orphans_after_commit.push(orphan_ino);
                                }
                                Err(err) => {
                                    self.tree.restore_orphan(orphan_ino, &to_path).await?;
                                    self.clear_pending_rename().await;
                                    return Err(err);
                                }
                            }
                        } else {
                            modified.insert(target.ino, target);
                        }
                    }
                } else if target.nlink == 0 {
                    match self.has_external_opens(target.ino).await {
                        Ok(true) => {
                            modified.insert(target.ino, target);
                        }
                        Ok(false) => {
                            if let Backing::Orphan(orphan_ino) = target.backing {
                                cleanup_orphans_after_commit.push(orphan_ino);
                            }
                            delete_inodes.push(target.ino);
                            delete_locks.push(target.ino);
                        }
                        Err(err) => {
                            self.clear_pending_rename().await;
                            return Err(err);
                        }
                    }
                } else {
                    modified.insert(target.ino, target);
                }
            } else if source_has_path {
                target.nlink = 0;
                if self.kind == HostKind::Directory {
                    target.stale = true;
                    forgotten_targets.push(target.ino);
                    modified.insert(target.ino, target);
                } else {
                    // Empty destination directory replaced on OPFS by `move_entry`.
                    target.backing = Backing::MetaOnly;
                    match self.has_external_opens(target.ino).await {
                        Ok(true) => {
                            modified.insert(target.ino, target);
                        }
                        Ok(false) => {
                            delete_inodes.push(target.ino);
                            delete_locks.push(target.ino);
                        }
                        Err(err) => {
                            self.clear_pending_rename().await;
                            return Err(err);
                        }
                    }
                }
            } else {
                // `Directory` or non-backing `Opfs` replace over a non-path target.
                let (delete_target, evac_undo, evac_orphan) = match self
                    .evacuate_or_remove_unlinked_link(&mut target, &to_path, &mut modified)
                    .await
                {
                    Ok(res) => res,
                    Err(err) => {
                        self.clear_pending_rename().await;
                        return Err(err);
                    }
                };
                if undo_target.is_none() {
                    undo_target = evac_undo;
                }
                if let Some(orphan_ino) = evac_orphan {
                    cleanup_orphans_after_commit.push(orphan_ino);
                }
                if delete_target {
                    delete_inodes.push(target.ino);
                    delete_locks.push(target.ino);
                } else {
                    modified.insert(target.ino, target);
                }
            }
        }

        // Now move source on host if its backing lives at `from_path`.
        let moved_fps: Vec<(String, Fingerprint)> = if source_has_path {
            match self.tree.move_entry(&from_path, &to_path, moving_dir).await {
                Ok(fps) => {
                    if !moving_dir {
                        source.backing = Backing::Path(to_path.clone());
                    }
                    fps
                }
                Err(err) => {
                    self.rollback_rename_host(
                        false,
                        &from_path,
                        &to_path,
                        moving_dir,
                        undo_target,
                        false,
                    )
                    .await?;
                    self.clear_pending_rename().await;
                    return Err(err);
                }
            }
        } else {
            Vec::new()
        };

        let mut moved_retains: Vec<(u64, String, bool)> = Vec::new();
        if moving_dir {
            source.parent = to_parent.ino;
            source.name = to.to_string();
            source.backing = Backing::Path(to_path.clone());
            let fp_map: std::collections::HashMap<String, Fingerprint> =
                moved_fps.into_iter().collect();
            if self.kind == HostKind::Directory {
                if let Some(fp) = fp_map.get(&to_path) {
                    source.fingerprint = Some(*fp);
                }
                moved_retains.push((source.ino, to_path.clone(), true));
            }
            let prefix = format!("{from_path}/");
            let all_inodes = match self.meta.list_all_inodes().await {
                Ok(list) => list,
                Err(err) => {
                    self.rollback_rename_host(
                        source_has_path,
                        &from_path,
                        &to_path,
                        moving_dir,
                        undo_target,
                        source_has_path && removed_empty_dir,
                    )
                    .await?;
                    self.clear_pending_rename().await;
                    return Err(err);
                }
            };
            for mut rec in all_inodes {
                if rec.ino == source.ino || modified.contains_key(&rec.ino) {
                    continue;
                }
                if let Backing::Path(ref bp) = rec.backing
                    && bp.starts_with(&prefix)
                {
                    let new_bp = format!("{to_path}/{}", &bp[prefix.len()..]);
                    if self.kind == HostKind::Directory {
                        if let Some(fp) = fp_map.get(&new_bp) {
                            rec.fingerprint = Some(*fp);
                        }
                        moved_retains.push((rec.ino, new_bp.clone(), rec.meta.directory));
                    }
                    rec.backing = Backing::Path(new_bp);
                    modified.insert(rec.ino, rec);
                }
            }
        } else {
            source.parents.remove(&(from_parent.ino, from.to_string()));
            source.parents.insert((to_parent.ino, to.to_string()));
            if self.kind == HostKind::Directory && source_has_path {
                if let Some((_, fp)) = moved_fps.iter().find(|(p, _)| p == &to_path) {
                    source.fingerprint = Some(*fp);
                }
                moved_retains.push((source.ino, to_path.clone(), false));
            }
        }
        Self::touch(&mut source, now, false);
        modified.insert(source.ino, source);

        let strict_rename = staged_header.is_some();
        if let Some(ref mut h) = staged_header {
            h.pending_rename = None;
        }
        if let Err(err) = self
            .meta
            .commit(
                MetaBatch {
                    header: staged_header,
                    put_inodes: modified.into_values().collect(),
                    delete_inodes,
                    delete_locks,
                    ..MetaBatch::default()
                },
                strict_rename,
            )
            .await
        {
            self.rollback_rename_host(
                source_has_path,
                &from_path,
                &to_path,
                moving_dir,
                undo_target,
                source_has_path && removed_empty_dir,
            )
            .await?;
            self.clear_pending_rename().await;
            return Err(err);
        }
        for orphan_ino in cleanup_orphans_after_commit {
            let _ = self.tree.remove_orphan(orphan_ino).await;
        }
        if self.kind == HostKind::Directory {
            for ino in forgotten_targets {
                self.tree.forget_host_entry(ino).await?;
            }
            for (ino, path, is_dir) in moved_retains {
                self.tree.retain_host_entry(ino, &path, is_dir).await?;
            }
        }
        Ok(())
    }

    pub(super) async fn do_getxattr(
        &self,
        cred: &Cred,
        handle: &Handle,
        name: &str,
    ) -> Result<Vec<u8>> {
        self.ensure_version().await?;
        let space = xattr::space(name)?;
        let _ns = self.ns_lock(self.read_ns_kind()).await?;
        let inode = self.check_live_inode(handle).await?;
        xattr::readable(&cred.identity, &inode.meta, space)?;
        match space {
            Space::Access | Space::Default => {
                let entries = xattr::acl(&inode.meta, space)?;
                Ok(serde_json::to_vec(&entries).unwrap_or_default())
            }
            Space::User | Space::Trusted => inode.xattrs.get(name).cloned().ok_or(Errno::ENODATA),
        }
    }

    pub(super) async fn do_setxattr(
        &self,
        cred: &Cred,
        handle: &Handle,
        name: &str,
        value: &[u8],
        flags: XattrFlags,
    ) -> Result<()> {
        self.ensure_version().await?;
        let space = xattr::space(name)?;
        let _ns = self.ns_lock(LockKind::Exclusive).await?;
        let mut inode = self.check_live_inode(handle).await?;
        self.require_writable_grant()?;
        xattr::settable(&cred.identity, &inode.meta, space)?;
        match space {
            Space::Access | Space::Default => {
                xattr::check_flags(flags.bits(), xattr::has_acl(&inode.meta, space))?;
                let entries: Entries = serde_json::from_slice(value).map_err(|_| Errno::EINVAL)?;
                xattr::set_acl(&cred.identity, &mut inode.meta, space, entries)?;
            }
            Space::User | Space::Trusted => {
                xattr::check_flags(flags.bits(), inode.xattrs.contains_key(name))?;
                xattr::store(&mut inode.xattrs, name, value)?;
            }
        }
        Self::touch(&mut inode, (self.clock)(), false);
        self.meta
            .commit(
                MetaBatch {
                    put_inodes: vec![inode],
                    ..MetaBatch::default()
                },
                false,
            )
            .await
    }

    pub(super) async fn do_listxattr(&self, cred: &Cred, handle: &Handle) -> Result<Vec<String>> {
        self.ensure_version().await?;
        let _ns = self.ns_lock(self.read_ns_kind()).await?;
        let inode = self.check_live_inode(handle).await?;
        Ok(xattr::listed(
            &cred.identity,
            &inode.meta,
            inode.xattrs.keys(),
        ))
    }

    pub(super) async fn do_removexattr(
        &self,
        cred: &Cred,
        handle: &Handle,
        name: &str,
    ) -> Result<()> {
        self.ensure_version().await?;
        let space = xattr::space(name)?;
        let _ns = self.ns_lock(LockKind::Exclusive).await?;
        let mut inode = self.check_live_inode(handle).await?;
        self.require_writable_grant()?;
        xattr::settable(&cred.identity, &inode.meta, space)?;
        match space {
            Space::Access | Space::Default => xattr::remove_acl(&mut inode.meta, space)?,
            Space::User | Space::Trusted => {
                inode.xattrs.remove(name).ok_or(Errno::ENODATA)?;
            }
        }
        Self::touch(&mut inode, (self.clock)(), false);
        self.meta
            .commit(
                MetaBatch {
                    put_inodes: vec![inode],
                    ..MetaBatch::default()
                },
                false,
            )
            .await
    }

    pub(super) async fn do_statfs(&self) -> Result<StatFs> {
        self.ensure_version().await?;
        let _ns = self.ns_lock(LockKind::Shared).await?;
        let header = self.load_header().await?;
        let inodes = self.meta.list_all_inodes().await?;
        let used_blocks: u64 = inodes.iter().map(|i| i.size.div_ceil(PAGE_BYTES)).sum();
        Ok(StatFs {
            block_size: PAGE_BYTES,
            blocks: CAPACITY_BLOCKS,
            blocks_free: CAPACITY_BLOCKS.saturating_sub(used_blocks),
            files: inodes.len() as u64,
            files_free: abi::fs::JS_SAFE.saturating_sub(header.next_ino),
            name_max: abi::NAME_MAX as u64,
        })
    }

    pub(super) async fn do_open(
        &self,
        cred: &Cred,
        handle: &Handle,
        options: &OpenOptions,
    ) -> Result<OpenRef> {
        self.ensure_version().await?;
        let _ns = self.ns_lock(LockKind::Exclusive).await?;
        let inode = self.check_live_inode(handle).await?;
        let access = self.check_openable(cred, &inode, options)?;
        let (_, open) = self
            .finish_open_existing(cred, inode, options, access)
            .await?;
        Ok(open)
    }

    fn require_regular_file(inode: &InodeRecord) -> Result<()> {
        match inode.file_type() {
            FileType::File => Ok(()),
            FileType::Dir => Err(Errno::EISDIR),
            _ => Err(Errno::ENXIO),
        }
    }

    pub(super) async fn do_read_at(
        &self,
        open: &OpenRef,
        buf: &mut [u8],
        offset: u64,
    ) -> Result<usize> {
        self.ensure_version().await?;
        let (ino, access, _) = self.get_open_info(open)?;
        if !access.reads() {
            return Err(Errno::EBADF);
        }
        let ns_kind = if self.kind == HostKind::Directory || !self.grant.read_only {
            LockKind::Exclusive
        } else {
            LockKind::Shared
        };
        let _ns = self.ns_lock(ns_kind).await?;
        let mut inode = self.validate_inode_by_id(ino).await?;
        Self::require_regular_file(&inode)?;
        if offset > FILE_MAX || buf.len() as u64 > FILE_MAX - offset {
            return Err(Errno::EINVAL);
        }
        let max_len = buf.len().min(RW_MAX);
        let data = if offset >= inode.size || max_len == 0 {
            Vec::new()
        } else {
            let want =
                usize::try_from(inode.size - offset).map_or(max_len, |left| left.min(max_len));
            let (expected_fp, expected_ino) = self.dir_expectation(&inode);
            self.fail_if_stale(
                &inode,
                self.tree
                    .read_file(&inode.backing, offset, want, expected_fp, expected_ino)
                    .await,
            )
            .await?
        };
        let n = data.len().min(max_len);
        buf[..n].copy_from_slice(&data[..n]);
        if self.touch_accessed(&mut inode) && !self.grant.read_only {
            let _ = self
                .meta
                .commit(
                    MetaBatch {
                        put_inodes: vec![inode],
                        ..MetaBatch::default()
                    },
                    false,
                )
                .await;
        }
        Ok(n)
    }

    pub(super) async fn do_write_at(
        &self,
        open: &OpenRef,
        buf: &[u8],
        at: WriteAt,
    ) -> Result<Written> {
        self.ensure_version().await?;
        let (ino, access, writer) = self.get_open_info(open)?;
        if !access.writes() {
            return Err(Errno::EBADF);
        }
        let _ns = self.ns_lock(LockKind::Exclusive).await?;
        let mut inode = self.validate_inode_by_id(ino).await?;
        Self::require_regular_file(&inode)?;
        self.require_writable_grant()?;

        let (offset, append) = match at {
            WriteAt::Offset(off) => (off, false),
            WriteAt::End => (inode.size, true),
        };
        if buf.is_empty() {
            return Ok(Written { offset, len: 0 });
        }
        if offset >= FILE_MAX {
            return Err(Errno::EFBIG);
        }
        let room = usize::try_from(FILE_MAX - offset).unwrap_or(usize::MAX);
        let len = buf.len().min(room).min(RW_MAX);
        let (expected_fp, expected_ino) = self.dir_expectation(&inode);
        let (written, fp) = self
            .fail_if_stale(
                &inode,
                self.tree
                    .write_file(
                        &inode.backing,
                        offset,
                        &buf[..len],
                        append,
                        expected_fp,
                        expected_ino,
                    )
                    .await,
            )
            .await?;
        let new_end = written.offset.saturating_add(written.len as u64);
        inode.size = inode.size.max(new_end).max(fp.size);
        inode.meta.size = inode.size;
        if self.kind == HostKind::Directory {
            inode.fingerprint = Some(fp);
        }
        inode::remove_privs(&writer, &mut inode.meta);
        Self::touch(&mut inode, (self.clock)(), true);
        self.meta
            .commit(
                MetaBatch {
                    put_inodes: vec![inode],
                    ..MetaBatch::default()
                },
                false,
            )
            .await?;
        Ok(written)
    }

    pub(super) async fn do_set_len(&self, open: &OpenRef, size: u64) -> Result<()> {
        self.ensure_version().await?;
        let (ino, access, writer) = self.get_open_info(open)?;
        if access == Access::Path {
            return Err(Errno::EBADF);
        }
        let _ns = self.ns_lock(LockKind::Exclusive).await?;
        let mut inode = self.validate_inode_by_id(ino).await?;
        if !access.writes() || inode.file_type() != FileType::File {
            return Err(Errno::EINVAL);
        }
        if size > FILE_MAX {
            return Err(Errno::EFBIG);
        }
        self.require_writable_grant()?;
        let (expected_fp, expected_ino) = self.dir_expectation(&inode);
        let fp = self
            .fail_if_stale(
                &inode,
                self.tree
                    .set_file_len(&inode.backing, size, expected_fp, expected_ino)
                    .await,
            )
            .await?;
        inode.size = size;
        inode.meta.size = size;
        if self.kind == HostKind::Directory {
            inode.fingerprint = Some(fp);
        }
        inode::remove_privs(&writer, &mut inode.meta);
        Self::touch(&mut inode, (self.clock)(), true);
        self.meta
            .commit(
                MetaBatch {
                    put_inodes: vec![inode],
                    ..MetaBatch::default()
                },
                false,
            )
            .await
    }

    pub(super) async fn do_sync(&self, open: &OpenRef, data_only: bool) -> Result<()> {
        self.ensure_version().await?;
        let (ino, access, _) = self.get_open_info(open)?;
        if access == Access::Path {
            return Err(Errno::EBADF);
        }
        let _ns = self.ns_lock(LockKind::Exclusive).await?;
        let mut inode = self.validate_inode_by_id(ino).await?;
        match inode.file_type() {
            FileType::File => {
                let (expected_fp, expected_ino) = self.dir_expectation(&inode);
                let fp = self
                    .fail_if_stale(
                        &inode,
                        self.tree
                            .flush_file(&inode.backing, data_only, expected_fp, expected_ino)
                            .await,
                    )
                    .await?;
                if self.kind == HostKind::Directory && inode.fingerprint != Some(fp) {
                    inode.fingerprint = Some(fp);
                    self.meta
                        .commit(
                            MetaBatch {
                                put_inodes: vec![inode],
                                ..MetaBatch::default()
                            },
                            true,
                        )
                        .await?;
                    return Ok(());
                }
            }
            FileType::Dir => {}
            _ => return Err(Errno::EINVAL),
        }
        self.meta.sync_strict().await
    }

    pub(super) async fn do_sync_handle(&self, handle: &Handle) -> Result<()> {
        self.ensure_version().await?;
        let _ns = self.ns_lock(LockKind::Exclusive).await?;
        let mut inode = self.check_live_inode(handle).await?;
        if inode.file_type() == FileType::File {
            let (expected_fp, expected_ino) = self.dir_expectation(&inode);
            let fp = self
                .fail_if_stale(
                    &inode,
                    self.tree
                        .flush_file(&inode.backing, false, expected_fp, expected_ino)
                        .await,
                )
                .await?;
            if self.kind == HostKind::Directory && inode.fingerprint != Some(fp) {
                inode.fingerprint = Some(fp);
                self.meta
                    .commit(
                        MetaBatch {
                            put_inodes: vec![inode],
                            ..MetaBatch::default()
                        },
                        true,
                    )
                    .await?;
                return Ok(());
            }
        }
        self.meta.sync_strict().await
    }

    pub(super) async fn do_release(&self, open: &OpenRef) -> Result<()> {
        let (ino, _, _) = self.get_open_info(open)?;
        // First release any advisory locks held by this open description.
        let lock_res = self.release_open_locks(ino, open.id).await;

        let _ns = match self.ns_lock(LockKind::Exclusive).await {
            Ok(ns) => ns,
            Err(err) => {
                // Still retire the local descriptor & Web Lock guard even if coordinator failed.
                self.local.borrow_mut().opens.remove(&open.id);
                return Err(err);
            }
        };
        // Remove local OpenEntry (dropping its `os-fs-open:<uuid>:<ino>:<open_id>` Web Lock guard).
        self.local.borrow_mut().opens.remove(&open.id);

        if self.kind == HostKind::Opfs
            && let Some(inode) = self.meta.get_inode(ino).await?
            && inode.nlink == 0
            && !self.has_external_opens(ino).await?
        {
            if let Backing::Orphan(orphan_ino) = inode.backing {
                self.tree.remove_orphan(orphan_ino).await?;
            }
            self.meta
                .commit(
                    MetaBatch {
                        delete_inodes: vec![ino],
                        delete_locks: vec![ino],
                        ..MetaBatch::default()
                    },
                    false,
                )
                .await?;
        }
        lock_res
    }
}

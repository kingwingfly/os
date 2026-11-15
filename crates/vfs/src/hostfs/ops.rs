use super::{
    Backing, Fingerprint, HostEntry, HostFs, HostGrant, HostKind, HostTree, InodeRecord, LockGuard,
    MetaBatch, MetaStore, OpenEntry, ProfileLocks, ROOT_INO, STORE_FORMAT_VERSION, StoreHeader,
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

    pub(super) async fn ns_lock(&self, kind: LockKind) -> Result<Option<Box<dyn LockGuard>>> {
        let name = format!("os-fs-ns:{}", self.uuid);
        match self.locks.acquire(&name, kind).await {
            Ok(guard) => Ok(Some(guard)),
            Err(Errno::ENOLCK) => Ok(None),
            Err(err) => Err(err),
        }
    }

    async fn acquire_open_guard(&self, ino: u64, open_id: u64) -> Result<Box<dyn LockGuard>> {
        struct NoopGuard;
        impl LockGuard for NoopGuard {}

        let name = format!("os-fs-open:{}:{ino}:{open_id}", self.uuid);
        match self.locks.acquire(&name, LockKind::Exclusive).await {
            Ok(guard) => Ok(guard),
            Err(Errno::ENOLCK) => Ok(Box::new(NoopGuard)),
            Err(err) => Err(err),
        }
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
        match self.locks.held_locks().await {
            Ok(held) => Ok(held.iter().any(|name| name.starts_with(&prefix))),
            Err(Errno::ENOLCK) => Ok(false),
            Err(err) => Err(err),
        }
    }

    pub(super) async fn sweep_orphans(&self) -> Result<()> {
        let _ns = self.ns_lock(LockKind::Exclusive).await?;
        let held = match self.locks.held_locks().await {
            Ok(set) => set,
            Err(Errno::ENOLCK) => return Ok(()),
            Err(err) => return Err(err),
        };
        let orphans = self.tree.list_orphans().await?;
        let mut delete_inodes = Vec::new();
        let mut delete_locks = Vec::new();
        for ino in orphans {
            let prefix = format!("os-fs-open:{}:{ino}:", self.uuid);
            if !held.iter().any(|name| name.starts_with(&prefix)) {
                self.tree.remove_orphan(ino).await?;
                delete_inodes.push(ino);
                delete_locks.push(ino);
            }
        }
        for inode in self.meta.list_all_inodes().await? {
            if inode.ino != ROOT_INO && inode.nlink == 0 {
                let prefix = format!("os-fs-open:{}:{}:", self.uuid, inode.ino);
                if !held.iter().any(|name| name.starts_with(&prefix)) {
                    if let Backing::Orphan(ino) = inode.backing {
                        let _ = self.tree.remove_orphan(ino).await;
                    }
                    delete_inodes.push(inode.ino);
                    delete_locks.push(inode.ino);
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
                            && (host.file_type == FileType::Dir
                                || inode.fingerprint == Some(host.fingerprint)) => {}
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

    async fn mark_stale(&self, inode: &InodeRecord) -> Result<()> {
        let mut stale_rec = inode.clone();
        stale_rec.stale = true;
        stale_rec.nlink = 0;
        let mut put_inodes = vec![stale_rec];
        if inode.meta.directory && inode.ino != ROOT_INO && inode.parent != 0 {
            if let Some(mut p) = self.meta.get_inode(inode.parent).await?
                && p.entries.get(&inode.name) == Some(&inode.ino)
            {
                p.entries.remove(&inode.name);
                p.nlink = p.nlink.saturating_sub(1);
                put_inodes.push(p);
            }
        } else {
            for (p_ino, p_name) in &inode.parents {
                if let Some(mut p) = self.meta.get_inode(*p_ino).await?
                    && p.entries.get(p_name) == Some(&inode.ino)
                {
                    p.entries.remove(p_name);
                    put_inodes.push(p);
                }
            }
        }
        self.meta
            .commit(
                MetaBatch {
                    put_inodes,
                    ..MetaBatch::default()
                },
                false,
            )
            .await
    }

    fn default_inode_from_host(
        grant: &HostGrant,
        ino: u64,
        parent: u64,
        name: &str,
        path: String,
        host: &HostEntry,
    ) -> InodeRecord {
        let is_dir = host.file_type == FileType::Dir;
        let mut meta = if is_dir {
            Node::directory(grant.owner.id, grant.owner.group, 0o700)
        } else {
            let mode = 0o400
                | if grant.read_only { 0 } else { 0o200 }
                | if grant.execute && host.executable {
                    0o100
                } else {
                    0
                };
            Node::file(
                grant.owner.id,
                grant.owner.group,
                mode,
                String::new(),
                host.size,
            )
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
            fingerprint: (!is_dir).then_some(host.fingerprint),
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
                    &self.grant,
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
                        let mut put_inodes = vec![dir.clone()];
                        if let Some(mut old) = self.meta.get_inode(old_ino).await? {
                            if old.meta.directory {
                                dir.nlink = dir.nlink.saturating_sub(1);
                                put_inodes[0] = dir.clone();
                            }
                            old.stale = true;
                            old.nlink = 0;
                            put_inodes.push(old);
                        }
                        self.meta
                            .commit(
                                MetaBatch {
                                    put_inodes,
                                    ..MetaBatch::default()
                                },
                                false,
                            )
                            .await?;
                    }
                    return Ok(None);
                };

                if let Some(ino) = recorded_ino
                    && let Some(child) = self.meta.get_inode(ino).await?
                    && !child.stale
                    && child.file_type() == host.file_type
                    && (host.file_type == FileType::Dir
                        || child.fingerprint == Some(host.fingerprint))
                {
                    return Ok(Some(child));
                }

                // Either unrecorded or modified/replaced outside the OS: mark any old inode stale
                // and mint a new inode with private defaults.
                let mut header = self.load_header().await?;
                let new_ino = Self::alloc_ino(&mut header)?;
                let new_child = Self::default_inode_from_host(
                    &self.grant,
                    new_ino,
                    dir.ino,
                    name,
                    child_path,
                    &host,
                );
                let mut put_inodes = Vec::new();
                if let Some(old_ino) = recorded_ino
                    && let Some(mut old) = self.meta.get_inode(old_ino).await?
                {
                    if old.meta.directory {
                        dir.nlink = dir.nlink.saturating_sub(1);
                    }
                    old.stale = true;
                    old.nlink = 0;
                    put_inodes.push(old);
                }
                dir.entries.insert(name.to_string(), new_ino);
                if new_child.meta.directory {
                    dir.nlink += 1;
                }
                put_inodes.push(dir.clone());
                put_inodes.push(new_child.clone());
                self.meta
                    .commit(
                        MetaBatch {
                            header: Some(header),
                            put_inodes,
                            ..MetaBatch::default()
                        },
                        false,
                    )
                    .await?;
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
        if inode.atime <= inode.mtime
            || inode.atime <= inode.ctime
            || now.0.saturating_sub(inode.atime.0) >= 24 * 60 * 60
        {
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

    async fn register_open(
        &self,
        header: &mut StoreHeader,
        cred: &Cred,
        ino: u64,
        access: Access,
    ) -> Result<OpenRef> {
        let id = Self::alloc_open_id(header)?;
        let guard = self.acquire_open_guard(ino, id).await?;
        self.local.borrow_mut().opens.insert(
            id,
            OpenEntry {
                ino,
                access,
                cred: cred.identity.clone(),
                _open_guard: guard,
            },
        );
        Ok(OpenRef {
            fs: self.id.clone(),
            id,
            node: NodeId {
                ino,
                generation: self.generation,
            },
            access,
        })
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
        let _ns = self.ns_lock(LockKind::Shared).await?;
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
        let _ns = self.ns_lock(LockKind::Shared).await?;
        let inode = self.check_live_inode(handle).await?;
        Ok(Self::metadata_of(&inode))
    }

    pub(super) async fn do_open_metadata(&self, open: &OpenRef) -> Result<Metadata> {
        self.ensure_version().await?;
        let (ino, _, _) = self.get_open_info(open)?;
        let _ns = self.ns_lock(LockKind::Shared).await?;
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
        inode.meta = meta;
        if let Some(size) = attr.size {
            let fp = self.tree.set_file_len(&inode.backing, size).await?;
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

        if let Some(mut existing) = self.resolve_child(&mut dir_rec, name).await? {
            if options.is_create_new() {
                return Err(Errno::EEXIST);
            }
            if existing.meta.directory {
                return Err(Errno::EISDIR);
            }
            self.check_openable(cred, &existing, options)?;
            let mut header = self.load_header().await?;
            let mut put_inodes = Vec::new();
            if options.is_truncate() && existing.file_type() == FileType::File {
                let fp = self.tree.set_file_len(&existing.backing, 0).await?;
                existing.size = 0;
                existing.meta.size = 0;
                if self.kind == HostKind::Directory {
                    existing.fingerprint = Some(fp);
                }
                inode::remove_privs(&cred.identity, &mut existing.meta);
                Self::touch(&mut existing, (self.clock)(), true);
                put_inodes.push(existing.clone());
            }
            let open = self
                .register_open(&mut header, cred, existing.ino, access)
                .await?;
            self.meta
                .commit(
                    MetaBatch {
                        header: Some(header),
                        put_inodes,
                        ..MetaBatch::default()
                    },
                    false,
                )
                .await?;
            return Ok((self.make_entry(&existing), open));
        }

        self.require_writable_grant()?;
        inode::may_create(&cred.identity, &dir_rec.meta, dir_rec.removed())?;
        let Backing::Path(dir_path) = dir_rec.backing.clone() else {
            return Err(Errno::ENOENT);
        };
        let child_path = join_rel(&dir_path, name);
        let host = self.tree.create_file(&child_path, true, true).await?;

        let mut header = self.load_header().await?;
        let ino = Self::alloc_ino(&mut header)?;
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
            backing: Backing::Path(child_path),
            fingerprint: Some(host.fingerprint),
            stale: false,
        };
        dir_rec.entries.insert(name.to_string(), ino);
        Self::touch(&mut dir_rec, now, true);

        let open = self.register_open(&mut header, cred, ino, access).await?;
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
        let child_path = join_rel(&dir_path, name);
        self.tree.create_dir(&child_path).await?;

        let mut header = self.load_header().await?;
        let ino = Self::alloc_ino(&mut header)?;
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
            backing: Backing::Path(child_path),
            fingerprint: None,
            stale: false,
        };
        dir_rec.entries.insert(name.to_string(), ino);
        dir_rec.nlink += 1;
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
    ) -> Result<bool> {
        if victim.meta.directory {
            self.tree.remove_dir(unlinked_path).await?;
            victim.nlink = 0;
            if self.kind == HostKind::Directory {
                victim.stale = true;
                return Ok(false);
            }
            victim.backing = Backing::MetaOnly;
            let keep = self.has_external_opens(victim.ino).await?;
            return Ok(!keep);
        }

        victim.nlink = victim.nlink.saturating_sub(1);
        if self.kind == HostKind::Directory {
            self.tree.remove_file(unlinked_path).await?;
            victim.stale = true;
            victim.nlink = 0;
            return Ok(false);
        }

        // OPFS regular file / symlink / device.
        match victim.backing.clone() {
            Backing::MetaOnly | Backing::Orphan(_) => {
                if victim.nlink == 0 {
                    let keep = self.has_external_opens(victim.ino).await?;
                    return Ok(!keep);
                }
                Ok(false)
            }
            Backing::Path(bp) => {
                if victim.nlink > 0 {
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
                        victim.backing = Backing::Path(other_path);
                    }
                    Ok(false)
                } else if self.has_external_opens(victim.ino).await? {
                    self.tree.move_to_orphan(&bp, victim.ino).await?;
                    victim.backing = Backing::Orphan(victim.ino);
                    Ok(false)
                } else {
                    self.tree.remove_file(&bp).await?;
                    Ok(true)
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
        let delete_victim = self
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
        self.meta.commit(batch, false).await
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

        if existing.is_some() && flags.contains(RenameFlags::NOREPLACE) {
            return Err(Errno::EEXIST);
        }
        if existing.as_ref().map(|e| e.ino) == Some(source.ino) {
            return Ok(());
        }

        let moving_dir = source.meta.directory;
        if moving_dir && self.is_ancestor(source.ino, to_parent.ino).await? {
            return Err(Errno::EINVAL);
        }
        self.require_writable_grant()?;
        inode::may_delete(who, &from_parent.meta, &source.meta)?;
        if let Some(ref target) = existing {
            inode::may_delete(who, &to_parent.meta, &target.meta)?;
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

        // First clean up / evacuate overwritten target if present.
        if let Some(mut target) = existing {
            target.parents.remove(&(to_parent.ino, to.to_string()));
            target.ctime = now;
            let delete_target = self
                .evacuate_or_remove_unlinked_link(&mut target, &to_path, &mut modified)
                .await?;
            if delete_target {
                delete_inodes.push(target.ino);
                delete_locks.push(target.ino);
            } else {
                modified.insert(target.ino, target);
            }
        }

        // Now move source on host if its backing lives at `from_path`.
        let moved_fps: Vec<(String, Fingerprint)> = if moving_dir {
            self.tree.move_entry(&from_path, &to_path, true).await?
        } else {
            match &source.backing {
                Backing::Path(bp) if bp == &from_path => {
                    let fps = self.tree.move_entry(&from_path, &to_path, false).await?;
                    source.backing = Backing::Path(to_path.clone());
                    fps
                }
                _ => Vec::new(),
            }
        };

        if moving_dir {
            source.parent = to_parent.ino;
            source.name = to.to_string();
            source.backing = Backing::Path(to_path.clone());
            let fp_map: std::collections::HashMap<String, Fingerprint> =
                moved_fps.into_iter().collect();
            let prefix = format!("{from_path}/");
            for mut rec in self.meta.list_all_inodes().await? {
                if rec.ino == source.ino || modified.contains_key(&rec.ino) {
                    continue;
                }
                if let Backing::Path(ref bp) = rec.backing
                    && bp.starts_with(&prefix)
                {
                    let new_bp = format!("{to_path}/{}", &bp[prefix.len()..]);
                    if self.kind == HostKind::Directory
                        && let Some(fp) = fp_map.get(&new_bp)
                    {
                        rec.fingerprint = Some(*fp);
                    }
                    rec.backing = Backing::Path(new_bp);
                    modified.insert(rec.ino, rec);
                }
            }
        } else {
            source.parents.remove(&(from_parent.ino, from.to_string()));
            source.parents.insert((to_parent.ino, to.to_string()));
            if self.kind == HostKind::Directory
                && let Some((_, fp)) = moved_fps.iter().find(|(p, _)| p == &to_path)
            {
                source.fingerprint = Some(*fp);
            }
        }
        Self::touch(&mut source, now, false);
        modified.insert(source.ino, source);

        self.meta
            .commit(
                MetaBatch {
                    put_inodes: modified.into_values().collect(),
                    delete_inodes,
                    delete_locks,
                    ..MetaBatch::default()
                },
                false,
            )
            .await
    }

    pub(super) async fn do_getxattr(
        &self,
        cred: &Cred,
        handle: &Handle,
        name: &str,
    ) -> Result<Vec<u8>> {
        self.ensure_version().await?;
        let space = xattr::space(name)?;
        let _ns = self.ns_lock(LockKind::Shared).await?;
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
        let _ns = self.ns_lock(LockKind::Shared).await?;
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
        let mut inode = self.check_live_inode(handle).await?;
        let access = self.check_openable(cred, &inode, options)?;
        let mut header = self.load_header().await?;
        let mut put_inodes = Vec::new();
        if access != Access::Path && options.is_truncate() && inode.file_type() == FileType::File {
            let fp = self.tree.set_file_len(&inode.backing, 0).await?;
            inode.size = 0;
            inode.meta.size = 0;
            if self.kind == HostKind::Directory {
                inode.fingerprint = Some(fp);
            }
            inode::remove_privs(&cred.identity, &mut inode.meta);
            Self::touch(&mut inode, (self.clock)(), true);
            put_inodes.push(inode.clone());
        }
        let open = self
            .register_open(&mut header, cred, inode.ino, access)
            .await?;
        self.meta
            .commit(
                MetaBatch {
                    header: Some(header),
                    put_inodes,
                    ..MetaBatch::default()
                },
                false,
            )
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
        let _ns = self.ns_lock(LockKind::Shared).await?;
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
            self.tree.read_file(&inode.backing, offset, want).await?
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
        let (written, fp) = self
            .tree
            .write_file(&inode.backing, offset, &buf[..len], append)
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
        let fp = self.tree.set_file_len(&inode.backing, size).await?;
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
                let fp = self.tree.flush_file(&inode.backing, data_only).await?;
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

    pub(super) async fn do_release(&self, open: &OpenRef) -> Result<()> {
        let (ino, _, _) = self.get_open_info(open)?;
        // First release any advisory locks held by this open description.
        let _ = self.release_open_locks(ino, open.id).await;

        let _ns = self.ns_lock(LockKind::Exclusive).await?;
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
        Ok(())
    }
}

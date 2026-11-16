//! Headless in-memory [`HostTree`], [`MetaStore`], and [`ProfileLocks`] simulator for
//! deterministic multi-tab, crash-recovery, external-edit, and advisory-lock testing without DOM
//! types (contract §2.2, §2.11).

use super::{
    Backing, Clock, Fingerprint, HostEntry, HostFs, HostGrant, HostTree, InodeRecord, LockGuard,
    MetaBatch, MetaStore, ProfileLocks, StoreHeader,
};
use crate::locks::Locks;
use crate::{BoxFuture, FileType, LockKind, Result, Timespec, Written};
use abi::Errno;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::future::poll_fn;
use std::rc::Rc;
use std::task::{Poll, Waker};

const WASM_MAGIC: [u8; 8] = [0x00, b'a', b's', b'm', 0x01, 0x00, 0x00, 0x00];

#[derive(Clone, Debug)]
struct SimFile {
    bytes: Vec<u8>,
    mtime_ns: u64,
    entry_id: u64,
}

impl SimFile {
    fn fingerprint(&self) -> Fingerprint {
        Fingerprint {
            size: self.bytes.len() as u64,
            mtime_ns: self.mtime_ns,
        }
    }

    fn host_entry(&self) -> HostEntry {
        let sec = self.mtime_ns / 1_000_000_000;
        let nsec = (self.mtime_ns % 1_000_000_000) as u32;
        HostEntry {
            file_type: FileType::File,
            size: self.bytes.len() as u64,
            mtime: Timespec { sec, nsec },
            fingerprint: self.fingerprint(),
            executable: self.bytes.len() >= 8 && self.bytes[..8] == WASM_MAGIC,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct SimDir {
    mtime_ns: u64,
    entry_id: u64,
}

struct TreeInner {
    dirs: BTreeMap<String, SimDir>,
    files: BTreeMap<String, SimFile>,
    orphans: BTreeMap<u64, SimFile>,
    retained_entries: BTreeMap<u64, u64>,
    next_tick_ns: u64,
    next_entry_id: u64,
    pending_external_replace: Option<(String, Vec<u8>)>,
    copy_dir_move: bool,
    quota_exceeded: bool,
    flush_error: bool,
    permission_revoked: bool,
    restore_orphan_error: Option<Errno>,
    file_flushes: usize,
    tree_ops: usize,
}

impl TreeInner {
    fn tick(&mut self) -> u64 {
        let ts = self.next_tick_ns;
        self.next_tick_ns += 1_000_000;
        ts
    }

    fn mint_entry_id(&mut self) -> u64 {
        let id = self.next_entry_id;
        self.next_entry_id += 1;
        id
    }

    fn apply_pending_replace(&mut self) {
        if let Some((path, bytes)) = self.pending_external_replace.take() {
            let mtime_ns = self.tick();
            let entry_id = self.mint_entry_id();
            self.files.insert(
                path,
                SimFile {
                    bytes,
                    mtime_ns,
                    entry_id,
                },
            );
        }
    }

    fn check_file_io(
        file: &SimFile,
        expected_fp: Option<Fingerprint>,
        expected_ino: Option<u64>,
        retained: &BTreeMap<u64, u64>,
    ) -> Result<()> {
        if let Some(fp) = expected_fp
            && file.fingerprint() != fp
        {
            return Err(Errno::ESTALE);
        }
        if let Some(ino) = expected_ino
            && retained.get(&ino) != Some(&file.entry_id)
        {
            return Err(Errno::ESTALE);
        }
        Ok(())
    }

    fn check_perm(&self) -> Result<()> {
        if self.permission_revoked {
            return Err(Errno::EACCES);
        }
        Ok(())
    }

    fn check_quota(&self) -> Result<()> {
        if self.quota_exceeded {
            return Err(Errno::EDQUOT);
        }
        Ok(())
    }

    fn parent_path(path: &str) -> &str {
        path.rsplit_once('/').map_or("", |(p, _)| p)
    }

    fn require_parent_dir(&self, path: &str) -> Result<()> {
        let p = Self::parent_path(path);
        if self.files.contains_key(p) {
            return Err(Errno::ENOTDIR);
        }
        if !self.dirs.contains_key(p) {
            return Err(Errno::ENOENT);
        }
        Ok(())
    }

    fn dir_entry(dir: SimDir) -> HostEntry {
        let sec = dir.mtime_ns / 1_000_000_000;
        let nsec = (dir.mtime_ns % 1_000_000_000) as u32;
        HostEntry {
            file_type: FileType::Dir,
            size: 0,
            mtime: Timespec { sec, nsec },
            fingerprint: Fingerprint {
                size: 0,
                mtime_ns: dir.mtime_ns,
            },
            executable: false,
        }
    }
}

struct MetaInner {
    version: Option<u32>,
    header: Option<StoreHeader>,
    inodes: BTreeMap<u64, InodeRecord>,
    locks: BTreeMap<u64, Locks>,
    next_uuid: u64,
    strict_commits: usize,
    strict_syncs: usize,
    commit_calls: usize,
    commit_error: Option<Errno>,
    fail_commit_on_call: Option<(usize, Errno)>,
}

#[derive(Clone, Debug)]
struct HeldWebLock {
    holder_id: u64,
    tab_id: u64,
    kind: LockKind,
}

struct LockBusInner {
    held: BTreeMap<String, Vec<HeldWebLock>>,
    waiters: Vec<Waker>,
    change_epoch: u64,
    notify_epoch: u64,
    next_holder_id: u64,
    next_ticket_id: u64,
}

impl LockBusInner {
    fn wake_all(&mut self) {
        self.change_epoch = self.change_epoch.wrapping_add(1);
        for waker in self.waiters.drain(..) {
            waker.wake();
        }
    }

    fn can_grant(&self, name: &str, kind: LockKind) -> bool {
        let Some(existing) = self.held.get(name) else {
            return true;
        };
        if existing.is_empty() {
            return true;
        }
        matches!(kind, LockKind::Shared)
            && existing.iter().all(|h| matches!(h.kind, LockKind::Shared))
    }
}

/// Shared simulated browser profile backing one OPFS workspace or one host directory handle across
/// multiple tabs.
#[derive(Clone)]
pub struct SimProfile {
    tree: Rc<RefCell<TreeInner>>,
    meta: Rc<RefCell<MetaInner>>,
    bus: Rc<RefCell<LockBusInner>>,
    clock_ns: Rc<RefCell<u64>>,
}

impl Default for SimProfile {
    fn default() -> Self {
        Self::new()
    }
}

impl SimProfile {
    pub fn new() -> Self {
        let mut dirs = BTreeMap::new();
        dirs.insert(
            String::new(),
            SimDir {
                mtime_ns: 1_700_000_000_000_000_000,
                entry_id: 1,
            },
        );
        Self {
            tree: Rc::new(RefCell::new(TreeInner {
                dirs,
                files: BTreeMap::new(),
                orphans: BTreeMap::new(),
                retained_entries: BTreeMap::new(),
                next_tick_ns: 1_700_000_000_001_000_000,
                next_entry_id: 2,
                pending_external_replace: None,
                copy_dir_move: false,
                quota_exceeded: false,
                flush_error: false,
                permission_revoked: false,
                restore_orphan_error: None,
                file_flushes: 0,
                tree_ops: 0,
            })),
            meta: Rc::new(RefCell::new(MetaInner {
                version: None,
                header: None,
                inodes: BTreeMap::new(),
                locks: BTreeMap::new(),
                next_uuid: 1,
                strict_commits: 0,
                strict_syncs: 0,
                commit_calls: 0,
                commit_error: None,
                fail_commit_on_call: None,
            })),
            bus: Rc::new(RefCell::new(LockBusInner {
                held: BTreeMap::new(),
                waiters: Vec::new(),
                change_epoch: 0,
                notify_epoch: 0,
                next_holder_id: 1,
                next_ticket_id: 1,
            })),
            clock_ns: Rc::new(RefCell::new(1_700_000_000_000_000_000)),
        }
    }

    pub fn clock(&self) -> Clock {
        let clock_ns = Rc::clone(&self.clock_ns);
        Box::new(move || {
            let mut ns = clock_ns.borrow_mut();
            let cur = *ns;
            *ns += 1_000_000;
            (cur / 1_000_000_000, (cur % 1_000_000_000) as u32)
        })
    }

    pub async fn mount_opfs(
        &self,
        tab_id: u64,
        grant: HostGrant,
        generation: u64,
    ) -> Result<HostFs<SimTree, SimMeta, SimLocks>> {
        HostFs::opfs(
            grant,
            generation,
            self.tree_handle(),
            self.meta_handle(),
            self.locks_handle(tab_id),
            self.clock(),
        )
        .await
    }

    pub async fn mount_directory(
        &self,
        tab_id: u64,
        grant: HostGrant,
        generation: u64,
    ) -> Result<HostFs<SimTree, SimMeta, SimLocks>> {
        HostFs::directory(
            grant,
            generation,
            self.tree_handle(),
            self.meta_handle(),
            self.locks_handle(tab_id),
            self.clock(),
        )
        .await
    }

    pub fn tree_handle(&self) -> SimTree {
        SimTree(Rc::clone(&self.tree))
    }

    pub fn meta_handle(&self) -> SimMeta {
        SimMeta(Rc::clone(&self.meta))
    }

    pub fn locks_handle(&self, tab_id: u64) -> SimLocks {
        SimLocks {
            bus: Rc::clone(&self.bus),
            tab_id,
            unavailable: Rc::new(RefCell::new(false)),
            fifo: Rc::new(RefCell::new(VecDeque::new())),
        }
    }

    /// Simulate an abrupt tab crash: release every Web Lock held by `tab_id` WITHOUT running
    /// `HostFs::release`, leaving any unlinked orphans or IndexedDB lock rows behind for peer
    /// pruning and startup sweep.
    pub fn crash_tab(&self, tab_id: u64) {
        let mut bus = self.bus.borrow_mut();
        for holders in bus.held.values_mut() {
            holders.retain(|h| h.tab_id != tab_id);
        }
        bus.held.retain(|_, v| !v.is_empty());
        bus.wake_all();
    }

    pub fn external_write(&self, path: &str, bytes: &[u8]) {
        let mut t = self.tree.borrow_mut();
        let mtime_ns = t.tick();
        let entry_id = t.mint_entry_id();
        t.files.insert(
            path.to_string(),
            SimFile {
                bytes: bytes.to_vec(),
                mtime_ns,
                entry_id,
            },
        );
    }

    pub fn external_mkdir(&self, path: &str) {
        let mut t = self.tree.borrow_mut();
        let mtime_ns = t.tick();
        let entry_id = t.mint_entry_id();
        t.dirs
            .insert(path.to_string(), SimDir { mtime_ns, entry_id });
    }

    pub fn external_remove(&self, path: &str) {
        let mut t = self.tree.borrow_mut();
        t.files.remove(path);
        t.dirs.remove(path);
    }

    pub fn external_rename(&self, from: &str, to: &str) {
        let mut t = self.tree.borrow_mut();
        let mtime_ns = t.tick();
        if let Some(mut f) = t.files.remove(from) {
            f.mtime_ns = mtime_ns;
            t.files.insert(to.to_string(), f);
        } else if let Some(mut d) = t.dirs.remove(from) {
            d.mtime_ns = mtime_ns;
            t.dirs.insert(to.to_string(), d);
        }
    }

    pub fn schedule_external_replace(&self, path: &str, bytes: &[u8]) {
        self.tree.borrow_mut().pending_external_replace = Some((path.to_string(), bytes.to_vec()));
    }

    pub fn external_read(&self, path: &str) -> Option<Vec<u8>> {
        self.tree.borrow().files.get(path).map(|f| f.bytes.clone())
    }

    pub fn host_paths(&self) -> Vec<String> {
        let t = self.tree.borrow();
        let mut out: Vec<String> = t
            .dirs
            .keys()
            .filter(|p| !p.is_empty())
            .cloned()
            .chain(t.files.keys().cloned())
            .collect();
        out.sort();
        out
    }

    pub fn orphan_ids(&self) -> Vec<u64> {
        self.tree.borrow().orphans.keys().copied().collect()
    }

    pub fn set_copy_dir_move(&self, copy_dir_move: bool) {
        self.tree.borrow_mut().copy_dir_move = copy_dir_move;
    }

    pub fn set_quota_exceeded(&self, exceeded: bool) {
        self.tree.borrow_mut().quota_exceeded = exceeded;
    }

    pub fn set_flush_error(&self, err: bool) {
        self.tree.borrow_mut().flush_error = err;
    }

    pub fn lock_notifications(&self) -> u64 {
        self.bus.borrow().notify_epoch
    }

    pub fn set_permission_revoked(&self, revoked: bool) {
        self.tree.borrow_mut().permission_revoked = revoked;
    }

    pub fn set_commit_error(&self, err: Option<Errno>) {
        self.meta.borrow_mut().commit_error = err;
    }

    pub fn set_fail_commit_after(&self, successes: Option<usize>, err: Errno) {
        let mut m = self.meta.borrow_mut();
        m.fail_commit_on_call = successes.map(|s| (m.commit_calls + s + 1, err));
    }

    pub fn set_restore_orphan_error(&self, err: Option<Errno>) {
        self.tree.borrow_mut().restore_orphan_error = err;
    }

    pub fn put_external_orphan(&self, ino: u64, bytes: &[u8]) {
        let mut t = self.tree.borrow_mut();
        let mtime_ns = t.tick();
        let entry_id = t.mint_entry_id();
        t.orphans.insert(
            ino,
            SimFile {
                bytes: bytes.to_vec(),
                mtime_ns,
                entry_id,
            },
        );
    }

    pub fn held_lock_count(&self, prefix: &str) -> usize {
        self.bus
            .borrow()
            .held
            .iter()
            .filter(|(k, v)| k.starts_with(prefix) && !v.is_empty())
            .count()
    }

    pub fn raw_header(&self) -> Option<StoreHeader> {
        self.meta.borrow().header.clone()
    }

    pub fn flushes(&self) -> (usize, usize, usize) {
        let t = self.tree.borrow();
        let m = self.meta.borrow();
        (t.file_flushes, m.strict_commits, m.strict_syncs)
    }

    pub fn tree_ops(&self) -> usize {
        self.tree.borrow().tree_ops
    }

    pub fn set_raw_version(&self, version: Option<u32>) {
        let mut m = self.meta.borrow_mut();
        m.version = version;
        if let Some(ref mut h) = m.header
            && let Some(v) = version
        {
            h.format_version = v;
        }
    }

    pub fn raw_version(&self) -> Option<u32> {
        self.meta.borrow().version
    }

    pub fn raw_inode(&self, ino: u64) -> Option<InodeRecord> {
        self.meta.borrow().inodes.get(&ino).cloned()
    }

    pub fn put_raw_inode(&self, rec: InodeRecord) {
        self.meta.borrow_mut().inodes.insert(rec.ino, rec);
    }

    pub fn set_raw_header(&self, header: StoreHeader) {
        self.meta.borrow_mut().header = Some(header);
    }
}

#[derive(Clone)]
pub struct SimTree(Rc<RefCell<TreeInner>>);

impl HostTree for SimTree {
    fn stat_path<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Option<HostEntry>> {
        Box::pin(async move {
            let mut t = self.0.borrow_mut();
            t.tree_ops += 1;
            t.check_perm()?;
            if let Some(&dir) = t.dirs.get(path) {
                return Ok(Some(TreeInner::dir_entry(dir)));
            }
            if let Some(file) = t.files.get(path) {
                return Ok(Some(file.host_entry()));
            }
            Ok(None)
        })
    }

    fn list_dir<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Vec<(String, HostEntry)>> {
        Box::pin(async move {
            let mut t = self.0.borrow_mut();
            t.tree_ops += 1;
            t.check_perm()?;
            if !t.dirs.contains_key(path) {
                return Err(Errno::ENOENT);
            }
            let prefix = if path.is_empty() {
                String::new()
            } else {
                format!("{path}/")
            };
            let mut entries = Vec::new();
            for (dpath, &dir) in &t.dirs {
                if dpath.is_empty() {
                    continue;
                }
                if let Some(rest) = dpath.strip_prefix(&prefix)
                    && !rest.is_empty()
                    && !rest.contains('/')
                {
                    entries.push((rest.to_string(), TreeInner::dir_entry(dir)));
                }
            }
            for (fpath, file) in &t.files {
                if let Some(rest) = fpath.strip_prefix(&prefix)
                    && !rest.is_empty()
                    && !rest.contains('/')
                {
                    entries.push((rest.to_string(), file.host_entry()));
                }
            }
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Ok(entries)
        })
    }

    fn create_file<'a>(
        &'a self,
        path: &'a str,
        create_new: bool,
        truncate: bool,
    ) -> BoxFuture<'a, HostEntry> {
        Box::pin(async move {
            let mut t = self.0.borrow_mut();
            t.tree_ops += 1;
            t.check_perm()?;
            t.check_quota()?;
            t.require_parent_dir(path)?;
            if t.dirs.contains_key(path) {
                return Err(Errno::EISDIR);
            }
            if t.files.contains_key(path) && create_new {
                return Err(Errno::EEXIST);
            }
            let mtime_ns = t.tick();
            if let Some(entry) = t.files.get_mut(path) {
                if truncate {
                    entry.bytes.clear();
                    entry.mtime_ns = mtime_ns;
                }
                return Ok(entry.host_entry());
            }
            let entry_id = t.mint_entry_id();
            let entry = SimFile {
                bytes: Vec::new(),
                mtime_ns,
                entry_id,
            };
            let host = entry.host_entry();
            t.files.insert(path.to_string(), entry);
            Ok(host)
        })
    }

    fn create_dir<'a>(&'a self, path: &'a str) -> BoxFuture<'a, HostEntry> {
        Box::pin(async move {
            let mut t = self.0.borrow_mut();
            t.tree_ops += 1;
            t.check_perm()?;
            t.check_quota()?;
            t.require_parent_dir(path)?;
            if t.dirs.contains_key(path) || t.files.contains_key(path) {
                return Err(Errno::EEXIST);
            }
            let mtime_ns = t.tick();
            let entry_id = t.mint_entry_id();
            let dir = SimDir { mtime_ns, entry_id };
            t.dirs.insert(path.to_string(), dir);
            Ok(TreeInner::dir_entry(dir))
        })
    }

    fn read_file<'a>(
        &'a self,
        backing: &'a Backing,
        offset: u64,
        len: usize,
        expected_fp: Option<Fingerprint>,
        expected_ino: Option<u64>,
    ) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let mut t = self.0.borrow_mut();
            t.tree_ops += 1;
            t.check_perm()?;
            t.apply_pending_replace();
            let file = match backing {
                Backing::Path(p) => t.files.get(p).ok_or(Errno::ESTALE)?,
                Backing::Orphan(ino) => t.orphans.get(ino).ok_or(Errno::ESTALE)?,
                Backing::MetaOnly => return Err(Errno::EINVAL),
            };
            if matches!(backing, Backing::Path(_)) {
                TreeInner::check_file_io(file, expected_fp, expected_ino, &t.retained_entries)?;
            }
            let start = usize::try_from(offset).unwrap_or(usize::MAX);
            if start >= file.bytes.len() || len == 0 {
                return Ok(Vec::new());
            }
            let end = start.saturating_add(len).min(file.bytes.len());
            Ok(file.bytes[start..end].to_vec())
        })
    }

    fn write_file<'a>(
        &'a self,
        backing: &'a Backing,
        offset: u64,
        data: &'a [u8],
        append: bool,
        expected_fp: Option<Fingerprint>,
        expected_ino: Option<u64>,
    ) -> BoxFuture<'a, (Written, Fingerprint)> {
        Box::pin(async move {
            let mut t = self.0.borrow_mut();
            t.tree_ops += 1;
            t.check_perm()?;
            t.check_quota()?;
            t.apply_pending_replace();
            let check_path = matches!(backing, Backing::Path(_));
            if check_path {
                let retained = t.retained_entries.clone();
                let file = match backing {
                    Backing::Path(p) => t.files.get(p).ok_or(Errno::ESTALE)?,
                    _ => unreachable!(),
                };
                TreeInner::check_file_io(file, expected_fp, expected_ino, &retained)?;
            }
            let mtime_ns = t.tick();
            let file = match backing {
                Backing::Path(p) => t.files.get_mut(p).ok_or(Errno::ESTALE)?,
                Backing::Orphan(ino) => t.orphans.get_mut(ino).ok_or(Errno::ESTALE)?,
                Backing::MetaOnly => return Err(Errno::EINVAL),
            };
            let pos = if append {
                file.bytes.len() as u64
            } else {
                offset
            };
            let start = usize::try_from(pos).map_err(|_| Errno::EFBIG)?;
            let end = start.checked_add(data.len()).ok_or(Errno::EFBIG)?;
            if end > file.bytes.len() {
                file.bytes.resize(end, 0);
            }
            file.bytes[start..end].copy_from_slice(data);
            file.mtime_ns = mtime_ns;
            Ok((
                Written {
                    offset: pos,
                    len: data.len(),
                },
                file.fingerprint(),
            ))
        })
    }

    fn set_file_len<'a>(
        &'a self,
        backing: &'a Backing,
        size: u64,
        expected_fp: Option<Fingerprint>,
        expected_ino: Option<u64>,
    ) -> BoxFuture<'a, Fingerprint> {
        Box::pin(async move {
            let mut t = self.0.borrow_mut();
            t.tree_ops += 1;
            t.check_perm()?;
            t.check_quota()?;
            t.apply_pending_replace();
            if matches!(backing, Backing::Path(_)) {
                let retained = t.retained_entries.clone();
                let file = match backing {
                    Backing::Path(p) => t.files.get(p).ok_or(Errno::ESTALE)?,
                    _ => unreachable!(),
                };
                TreeInner::check_file_io(file, expected_fp, expected_ino, &retained)?;
            }
            let mtime_ns = t.tick();
            let new_len = usize::try_from(size).map_err(|_| Errno::EFBIG)?;
            let file = match backing {
                Backing::Path(p) => t.files.get_mut(p).ok_or(Errno::ESTALE)?,
                Backing::Orphan(ino) => t.orphans.get_mut(ino).ok_or(Errno::ESTALE)?,
                Backing::MetaOnly => return Err(Errno::EINVAL),
            };
            file.bytes.resize(new_len, 0);
            file.mtime_ns = mtime_ns;
            Ok(file.fingerprint())
        })
    }

    fn flush_file<'a>(
        &'a self,
        backing: &'a Backing,
        _data_only: bool,
        expected_fp: Option<Fingerprint>,
        expected_ino: Option<u64>,
    ) -> BoxFuture<'a, Fingerprint> {
        Box::pin(async move {
            let mut t = self.0.borrow_mut();
            t.tree_ops += 1;
            t.check_perm()?;
            t.apply_pending_replace();
            if t.flush_error {
                return Err(Errno::EIO);
            }
            let file = match backing {
                Backing::Path(p) => t.files.get(p).ok_or(Errno::ESTALE)?,
                Backing::Orphan(ino) => t.orphans.get(ino).ok_or(Errno::ESTALE)?,
                Backing::MetaOnly => return Err(Errno::EINVAL),
            };
            if matches!(backing, Backing::Path(_)) {
                TreeInner::check_file_io(file, expected_fp, expected_ino, &t.retained_entries)?;
            }
            let fp = file.fingerprint();
            t.file_flushes += 1;
            Ok(fp)
        })
    }

    fn retain_host_entry<'a>(&'a self, ino: u64, path: &'a str, is_dir: bool) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let mut t = self.0.borrow_mut();
            t.check_perm()?;
            let entry_id = if is_dir {
                t.dirs.get(path).map(|d| d.entry_id)
            } else {
                t.files.get(path).map(|f| f.entry_id)
            }
            .ok_or(Errno::ESTALE)?;
            t.retained_entries.insert(ino, entry_id);
            Ok(())
        })
    }

    fn verify_host_entry<'a>(
        &'a self,
        ino: u64,
        path: &'a str,
        is_dir: bool,
    ) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            let t = self.0.borrow();
            t.check_perm()?;
            let current_id = if is_dir {
                t.dirs.get(path).map(|d| d.entry_id)
            } else {
                t.files.get(path).map(|f| f.entry_id)
            };
            Ok(current_id.is_some() && t.retained_entries.get(&ino) == current_id.as_ref())
        })
    }

    fn forget_host_entry<'a>(&'a self, ino: u64) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.0.borrow_mut().retained_entries.remove(&ino);
            Ok(())
        })
    }

    fn remove_file<'a>(&'a self, path: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let mut t = self.0.borrow_mut();
            t.tree_ops += 1;
            t.check_perm()?;
            t.files.remove(path).ok_or(Errno::ENOENT)?;
            Ok(())
        })
    }

    fn remove_dir<'a>(&'a self, path: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let mut t = self.0.borrow_mut();
            t.tree_ops += 1;
            t.check_perm()?;
            if path.is_empty() {
                return Err(Errno::EBUSY);
            }
            let prefix = format!("{path}/");
            if t.dirs.keys().any(|k| k.starts_with(&prefix))
                || t.files.keys().any(|k| k.starts_with(&prefix))
            {
                return Err(Errno::ENOTEMPTY);
            }
            t.dirs.remove(path).ok_or(Errno::ENOENT)?;
            Ok(())
        })
    }

    fn move_entry<'a>(
        &'a self,
        from: &'a str,
        to: &'a str,
        is_dir: bool,
    ) -> BoxFuture<'a, Vec<(String, Fingerprint)>> {
        Box::pin(async move {
            let mut t = self.0.borrow_mut();
            t.tree_ops += 1;
            t.check_perm()?;
            t.check_quota()?;
            t.require_parent_dir(to)?;
            if !is_dir {
                let mut f = t.files.remove(from).ok_or(Errno::ENOENT)?;
                if t.copy_dir_move {
                    f.mtime_ns = t.tick();
                    f.entry_id = t.mint_entry_id();
                }
                let fp = f.fingerprint();
                t.files.insert(to.to_string(), f);
                return Ok(vec![(to.to_string(), fp)]);
            }
            let mut dir = t.dirs.remove(from).ok_or(Errno::ENOENT)?;
            if t.copy_dir_move {
                dir.mtime_ns = t.tick();
                dir.entry_id = t.mint_entry_id();
            }
            let mut moved_fps = vec![(to.to_string(), TreeInner::dir_entry(dir).fingerprint)];
            t.dirs.insert(to.to_string(), dir);
            let prefix = format!("{from}/");
            let subdirs: Vec<(String, SimDir)> = t
                .dirs
                .iter()
                .filter(|(k, _)| k.starts_with(&prefix))
                .map(|(k, &v)| (k.clone(), v))
                .collect();
            for (old_k, mut v) in subdirs {
                t.dirs.remove(&old_k);
                if t.copy_dir_move {
                    v.mtime_ns = t.tick();
                    v.entry_id = t.mint_entry_id();
                }
                let new_k = format!("{to}/{}", &old_k[prefix.len()..]);
                moved_fps.push((new_k.clone(), TreeInner::dir_entry(v).fingerprint));
                t.dirs.insert(new_k, v);
            }
            let subfiles: Vec<String> = t
                .files
                .keys()
                .filter(|k| k.starts_with(&prefix))
                .cloned()
                .collect();
            let copy_mode = t.copy_dir_move;
            for old_k in subfiles {
                if let Some(mut f) = t.files.remove(&old_k) {
                    if copy_mode {
                        f.mtime_ns = t.tick();
                        f.entry_id = t.mint_entry_id();
                    }
                    let new_k = format!("{to}/{}", &old_k[prefix.len()..]);
                    let fp = f.fingerprint();
                    t.files.insert(new_k.clone(), f);
                    moved_fps.push((new_k, fp));
                }
            }
            Ok(moved_fps)
        })
    }

    fn move_to_orphan<'a>(&'a self, path: &'a str, ino: u64) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let mut t = self.0.borrow_mut();
            t.tree_ops += 1;
            t.check_perm()?;
            let f = t.files.remove(path).ok_or(Errno::ENOENT)?;
            t.orphans.insert(ino, f);
            Ok(())
        })
    }

    fn restore_orphan<'a>(&'a self, ino: u64, to: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let mut t = self.0.borrow_mut();
            t.tree_ops += 1;
            if let Some(err) = t.restore_orphan_error {
                return Err(err);
            }
            t.check_perm()?;
            t.require_parent_dir(to)?;
            let f = t.orphans.remove(&ino).ok_or(Errno::ENOENT)?;
            t.files.insert(to.to_string(), f);
            Ok(())
        })
    }

    fn remove_orphan(&self, ino: u64) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let mut t = self.0.borrow_mut();
            t.tree_ops += 1;
            t.orphans.remove(&ino);
            Ok(())
        })
    }

    fn list_orphans(&self) -> BoxFuture<'_, Vec<u64>> {
        Box::pin(async move {
            let mut t = self.0.borrow_mut();
            t.tree_ops += 1;
            Ok(t.orphans.keys().copied().collect())
        })
    }
}

#[derive(Clone)]
pub struct SimMeta(Rc<RefCell<MetaInner>>);

impl MetaStore for SimMeta {
    fn read_version(&self) -> BoxFuture<'_, Option<u32>> {
        Box::pin(async move { Ok(self.0.borrow().version) })
    }

    fn read_header(&self) -> BoxFuture<'_, Option<StoreHeader>> {
        Box::pin(async move { Ok(self.0.borrow().header.clone()) })
    }

    fn reset_to_current(&self, header: StoreHeader, root: InodeRecord) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let mut m = self.0.borrow_mut();
            m.version = Some(header.format_version);
            m.header = Some(header);
            m.inodes.clear();
            m.locks.clear();
            m.inodes.insert(root.ino, root);
            m.strict_commits += 1;
            Ok(())
        })
    }

    fn mint_uuid(&self) -> BoxFuture<'_, String> {
        Box::pin(async move {
            let mut m = self.0.borrow_mut();
            let id = m.next_uuid;
            m.next_uuid += 1;
            Ok(format!("00000000-0000-4000-8000-{id:012x}"))
        })
    }

    fn get_inode(&self, ino: u64) -> BoxFuture<'_, Option<InodeRecord>> {
        Box::pin(async move { Ok(self.0.borrow().inodes.get(&ino).cloned()) })
    }

    fn find_by_backing<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Option<InodeRecord>> {
        Box::pin(async move {
            let m = self.0.borrow();
            Ok(m.inodes
                .values()
                .find(|rec| !rec.stale && rec.backing == Backing::Path(path.to_string()))
                .cloned())
        })
    }

    fn list_all_inodes(&self) -> BoxFuture<'_, Vec<InodeRecord>> {
        Box::pin(async move { Ok(self.0.borrow().inodes.values().cloned().collect()) })
    }

    fn get_locks(&self, ino: u64) -> BoxFuture<'_, Locks> {
        Box::pin(async move { Ok(self.0.borrow().locks.get(&ino).cloned().unwrap_or_default()) })
    }

    fn list_all_locks(&self) -> BoxFuture<'_, Vec<(u64, Locks)>> {
        Box::pin(async move {
            Ok(self
                .0
                .borrow()
                .locks
                .iter()
                .map(|(&k, v)| (k, v.clone()))
                .collect())
        })
    }

    fn commit(&self, batch: MetaBatch, strict: bool) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let mut m = self.0.borrow_mut();
            m.commit_calls += 1;
            if let Some((fail_at, err)) = m.fail_commit_on_call
                && m.commit_calls == fail_at
            {
                m.fail_commit_on_call = None;
                return Err(err);
            }
            if let Some(err) = m.commit_error {
                return Err(err);
            }
            if let Some(h) = batch.header {
                m.version = Some(h.format_version);
                m.header = Some(h);
            }
            for ino in batch.delete_inodes {
                m.inodes.remove(&ino);
            }
            for rec in batch.put_inodes {
                m.inodes.insert(rec.ino, rec);
            }
            for ino in batch.delete_locks {
                m.locks.remove(&ino);
            }
            for (ino, table) in batch.put_locks {
                m.locks.insert(ino, table);
            }
            if strict {
                m.strict_commits += 1;
            }
            Ok(())
        })
    }

    fn sync_strict(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.0.borrow_mut().strict_syncs += 1;
            Ok(())
        })
    }
}

struct SimGuard {
    bus: Rc<RefCell<LockBusInner>>,
    name: String,
    holder_id: u64,
}

impl LockGuard for SimGuard {}

impl Drop for SimGuard {
    fn drop(&mut self) {
        let mut bus = self.bus.borrow_mut();
        if let Some(list) = bus.held.get_mut(&self.name) {
            list.retain(|h| h.holder_id != self.holder_id);
            if list.is_empty() {
                bus.held.remove(&self.name);
            }
        }
        bus.wake_all();
    }
}

#[derive(Clone)]
pub struct SimLocks {
    bus: Rc<RefCell<LockBusInner>>,
    tab_id: u64,
    unavailable: Rc<RefCell<bool>>,
    fifo: Rc<RefCell<VecDeque<u64>>>,
}

impl SimLocks {
    pub fn set_unavailable(&self, unavailable: bool) {
        *self.unavailable.borrow_mut() = unavailable;
    }
}

impl ProfileLocks for SimLocks {
    fn acquire<'a>(&'a self, name: &'a str, kind: LockKind) -> BoxFuture<'a, Box<dyn LockGuard>> {
        let name_owned = name.to_string();
        Box::pin(async move {
            poll_fn(|cx| {
                if *self.unavailable.borrow() {
                    return Poll::Ready(Err(Errno::ENOLCK));
                }
                let mut bus = self.bus.borrow_mut();
                if bus.can_grant(&name_owned, kind) {
                    let holder_id = bus.next_holder_id;
                    bus.next_holder_id += 1;
                    bus.held
                        .entry(name_owned.clone())
                        .or_default()
                        .push(HeldWebLock {
                            holder_id,
                            tab_id: self.tab_id,
                            kind,
                        });
                    let guard: Box<dyn LockGuard> = Box::new(SimGuard {
                        bus: Rc::clone(&self.bus),
                        name: name_owned.clone(),
                        holder_id,
                    });
                    Poll::Ready(Ok(guard))
                } else {
                    bus.waiters.push(cx.waker().clone());
                    Poll::Pending
                }
            })
            .await
        })
    }

    fn try_acquire<'a>(
        &'a self,
        name: &'a str,
        kind: LockKind,
    ) -> BoxFuture<'a, Option<Box<dyn LockGuard>>> {
        let name_owned = name.to_string();
        Box::pin(async move {
            if *self.unavailable.borrow() {
                return Err(Errno::ENOLCK);
            }
            let mut bus = self.bus.borrow_mut();
            if bus.can_grant(&name_owned, kind) {
                let holder_id = bus.next_holder_id;
                bus.next_holder_id += 1;
                bus.held
                    .entry(name_owned.clone())
                    .or_default()
                    .push(HeldWebLock {
                        holder_id,
                        tab_id: self.tab_id,
                        kind,
                    });
                let guard: Box<dyn LockGuard> = Box::new(SimGuard {
                    bus: Rc::clone(&self.bus),
                    name: name_owned,
                    holder_id,
                });
                Ok(Some(guard))
            } else {
                Ok(None)
            }
        })
    }

    fn held_locks(&self) -> BoxFuture<'_, HashSet<String>> {
        Box::pin(async move {
            if *self.unavailable.borrow() {
                return Err(Errno::ENOLCK);
            }
            let bus = self.bus.borrow();
            Ok(bus
                .held
                .iter()
                .filter(|(_, list)| !list.is_empty())
                .map(|(k, _)| k.clone())
                .collect())
        })
    }

    fn notify_locks(&self) {
        let mut bus = self.bus.borrow_mut();
        bus.notify_epoch = bus.notify_epoch.wrapping_add(1);
        bus.wake_all();
    }

    fn wait_for_change<'a>(&'a self, blocking_locks: &'a [String]) -> BoxFuture<'a, ()> {
        let blockers: Vec<String> = blocking_locks.to_vec();
        Box::pin(async move {
            let start_epoch = self.bus.borrow().notify_epoch;
            let _ = self.fifo.borrow();
            poll_fn(|cx| {
                if *self.unavailable.borrow() {
                    return Poll::Ready(Err(Errno::ENOLCK));
                }
                let mut bus = self.bus.borrow_mut();
                if bus.notify_epoch != start_epoch
                    || blockers
                        .iter()
                        .any(|b| !bus.held.get(b).is_some_and(|v| !v.is_empty()))
                {
                    Poll::Ready(Ok(()))
                } else {
                    bus.waiters.push(cx.waker().clone());
                    Poll::Pending
                }
            })
            .await
        })
    }

    fn new_ticket(&self) -> String {
        let mut bus = self.bus.borrow_mut();
        let id = bus.next_ticket_id;
        bus.next_ticket_id += 1;
        format!("sim-ticket-{id}")
    }
}

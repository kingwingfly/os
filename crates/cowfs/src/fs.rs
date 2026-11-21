//! Complete POSIX [`vfs::Filesystem`] driver (`CowFs`) layered over `os-cowtree` single-map
//! Merkle CoW B+trees and pluggable [`HeadStore`] / [`PackStore`] backends (`contract.md` §2.5,
//! §2.15, §3, §5; #77).

use crate::inode::{DirIndexValue, DirItemValue, ExtentDataValue, InodeItem};
use crate::orphan;
use abi::Errno;
use abi::contract::FsCapabilities;
use abi::fs::{
    Access, Conflict, DirEntry, DirPage, Entry, FILE_MAX, FileType, FsId, Handle, LockFamily,
    LockKind, LockRange, Metadata, NodeId, OpenOptions, OpenRef, RenameFlags, SetAttr, StatFs,
    Stop, Timespec, Walked, WriteAt, Written, XattrFlags, check_component,
};
use abi::volume::CowfsInfoResp;
use cowtree::{
    Arena, ArenaConfig, ArenaStats, BLOCK_SIZE, COWFS_FORMAT_VERSION, CommitRequest, CowTree,
    Digest, ForkRequest, HeadStore, INLINE_MAX_BYTES, KIND_DIR_INDEX, KIND_DIR_ITEM,
    KIND_EXTENT_DATA, KIND_INODE_ITEM, KIND_INODE_REF, KIND_XATTR_ITEM, Node, PackBuilder,
    PackMeta, PackStore, ROOT_FEATURE_ACCOUNTING, RoPinGuard, RootObject, SnapshotRecord, TreeKey,
    TreeOverlay, VolumeHead, VolumeId, WriterLease, WriterMode, digest_to_hex, sha256,
    verify_block_digest,
};
use os_core::acl::Entries;
use os_core::inode;
use os_core::permissions::{EXEC, Identity, Node as PermNode, READ, WRITE, created};
use os_core::xattr::{self, Space};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};
use vfs::{BoxFuture, Cred, DIR_PAGE_MAX, Filesystem, Result, profiles};

/// Root directory inode number inside every `os-cowfs` subvolume.
pub const ROOT_INO: u64 = 1;
/// Default primary subvolume name (`contract.md` §2.15).
pub const DEFAULT_SUBVOL: &str = "@";
/// Maximum dirty transaction-group commit deadline while dirty (`contract.md` §2.15: 5 seconds).
pub const DIRTY_COMMIT_DEADLINE_SECS: u64 = 5;
/// Max single read/write byte count (Linux `MAX_RW_COUNT`).
const RW_MAX: usize = 0x7fff_f000;

/// Monotonic global open-ref counter so an `OpenRef` from an earlier mount can never collide with
/// a fresh mount (`EBADF`).
static NEXT_OPEN_ID: AtomicU64 = AtomicU64::new(1);

/// Clock returning `(sec, nsec)` since Unix epoch.
pub type CowFsClock = Rc<dyn Fn() -> Timespec>;

pub fn zero_clock() -> CowFsClock {
    Rc::new(|| Timespec { sec: 0, nsec: 0 })
}

/// Mount mode for opening an `os-cowfs` volume.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CowFsOpenMode {
    ReadWrite(WriterMode),
    ReadOnly,
    Snapshot(String),
}

/// Configuration for opening a [`CowFs`] instance.
#[derive(Clone)]
pub struct CowFsConfig {
    pub subvol: String,
    pub capabilities: FsCapabilities,
    pub arena: ArenaConfig,
    pub clock: CowFsClock,
    /// Optional logical capacity ceiling (bytes) reported in `statfs` and enforced on write.
    pub capacity_bytes: Option<u64>,
}

impl CowFsConfig {
    pub fn local_native(clock: CowFsClock) -> Self {
        Self {
            subvol: DEFAULT_SUBVOL.to_string(),
            capabilities: profiles::COWFS_LOCAL_NATIVE,
            arena: ArenaConfig::platform_default(),
            clock,
            capacity_bytes: None,
        }
    }

    pub fn local_browser(clock: CowFsClock) -> Self {
        Self {
            subvol: DEFAULT_SUBVOL.to_string(),
            capabilities: profiles::COWFS_LOCAL_BROWSER,
            arena: ArenaConfig::fixed_32mib(),
            clock,
            capacity_bytes: None,
        }
    }

    pub fn with_arena(mut self, arena: ArenaConfig) -> Self {
        self.arena = arena;
        self
    }

    pub fn with_subvol(mut self, subvol: impl Into<String>) -> Self {
        self.subvol = subvol.into();
        self
    }

    pub fn with_capacity(mut self, bytes: u64) -> Self {
        self.capacity_bytes = Some(bytes);
        self
    }
}

struct OpenRecord {
    ino: u64,
    generation: u64,
    access: Access,
    cred: Identity,
}

#[derive(Clone, Copy)]
struct Lock {
    owner: u64,
    family: LockFamily,
    kind: LockKind,
    range: LockRange,
}

impl Lock {
    fn conflicts(self, other: Lock) -> bool {
        self.owner != other.owner
            && self.family == other.family
            && self.range.overlaps(other.range)
            && (self.kind == LockKind::Exclusive || other.kind == LockKind::Exclusive)
    }
}

struct Waiter {
    ino: u64,
    lock: Lock,
    waker: Waker,
}

fn carve(locks: &mut Vec<Lock>, owner: u64, family: LockFamily, range: LockRange) {
    let mut pieces = Vec::new();
    locks.retain(|lock| {
        let cut = lock.owner == owner && lock.family == family && lock.range.overlaps(range);
        if cut {
            pieces.extend(
                lock.range
                    .minus(range)
                    .into_iter()
                    .flatten()
                    .map(|rest| Lock {
                        range: rest,
                        ..*lock
                    }),
            );
        }
        !cut
    });
    locks.extend(pieces);
}

#[derive(Default)]
struct AsyncMutex {
    held: Cell<bool>,
    next_id: Cell<u64>,
    waiters: RefCell<BTreeMap<u64, Waker>>,
}

struct AsyncMutexGuard<'a>(&'a AsyncMutex);
struct AsyncMutexWait<'a> {
    lock: &'a AsyncMutex,
    id: u64,
}

impl Drop for AsyncMutexWait<'_> {
    fn drop(&mut self) {
        self.lock.waiters.borrow_mut().remove(&self.id);
    }
}

impl Drop for AsyncMutexGuard<'_> {
    fn drop(&mut self) {
        self.0.held.set(false);
        for waker in self.0.waiters.take().into_values() {
            waker.wake();
        }
    }
}

impl AsyncMutex {
    async fn lock(&self) -> AsyncMutexGuard<'_> {
        let id = self.next_id.get();
        self.next_id.set(id.wrapping_add(1));
        let _wait = AsyncMutexWait { lock: self, id };
        poll_fn(|cx| {
            if self.held.replace(true) {
                self.waiters.borrow_mut().insert(id, cx.waker().clone());
                Poll::Pending
            } else {
                Poll::Ready(AsyncMutexGuard(self))
            }
        })
        .await
    }
}

struct PendingCommit {
    commit_req: CommitRequest,
    next_root_obj: RootObject,
    new_subvol_root: Digest,
}

struct CommittingGroup {
    first_dirty_at: Option<Timespec>,
    overlay: TreeOverlay,
    dirty_blocks: HashMap<Digest, (Rc<Vec<u8>>, usize)>,
    dirty_block_bytes: usize,
    /// Retained across an ambiguous `EIO` from `commit_head` so retry replays the exact same
    /// `op_id` + payload and resolves its receipt instead of self-fencing (`ESTALE`).
    pending: Option<PendingCommit>,
}

struct CowFsState {
    head: VolumeHead,
    root_obj: RootObject,
    subvol_root: Digest,
    lease: Option<WriterLease>,
    ro_pin: Option<Box<dyn RoPinGuard>>,
    forked_from: Option<VolumeId>,
    fenced: bool,
    closed: bool,
    /// True once an explicit user mutation (not an internal `relatime` update) has been staged.
    user_modified: bool,
    /// Timestamp when the live overlay first became dirty (drives the 5s dirty commit deadline).
    first_dirty_at: Option<Timespec>,
    overlay: TreeOverlay,
    /// Uncommitted data blocks keyed by SHA-256 digest: `(bytes, refcount)`.
    dirty_blocks: HashMap<Digest, (Rc<Vec<u8>>, usize)>,
    dirty_block_bytes: usize,
    /// Frozen transaction group currently committing to storage (or awaiting EIO reconciliation).
    committing: Option<CommittingGroup>,
    /// Open-file reference tracking (per-mount instance).
    opens: HashMap<u64, OpenRecord>,
    open_counts: HashMap<u64, u32>,
    locks: HashMap<u64, Vec<Lock>>,
    waiters: HashMap<u64, Waiter>,
    next_waiter: u64,
    /// Persisted allocated out-of-line extent bytes (for `statfs` & optional capacity checks).
    allocated_bytes: u64,
    inode_count: u64,
}

impl CowFsState {
    fn mark_dirty(&mut self, now: Timespec) {
        if self.first_dirty_at.is_none() {
            self.first_dirty_at = Some(now);
        }
    }

    fn stage_dirty_block(&mut self, digest: Digest, bytes: Rc<Vec<u8>>) {
        if let Some((_, count)) = self.dirty_blocks.get_mut(&digest) {
            *count += 1;
        } else {
            let sz = bytes.len();
            self.dirty_blocks.insert(digest, (bytes, 1));
            self.dirty_block_bytes += sz;
        }
    }

    fn unstage_dirty_block(&mut self, digest: &Digest) {
        let remove = if let Some((_, count)) = self.dirty_blocks.get_mut(digest) {
            *count = count.saturating_sub(1);
            *count == 0
        } else {
            false
        };
        if remove && let Some((bytes, _)) = self.dirty_blocks.remove(digest) {
            self.dirty_block_bytes = self.dirty_block_bytes.saturating_sub(bytes.len());
        }
    }

    fn total_dirty_bytes(&self) -> usize {
        let committing_bytes = self
            .committing
            .as_ref()
            .map_or(0, |c| c.overlay.dirty_bytes() + c.dirty_block_bytes);
        self.overlay.dirty_bytes() + self.dirty_block_bytes + committing_bytes
    }

    fn is_live_dirty(&self) -> bool {
        !self.overlay.is_empty() || !self.dirty_blocks.is_empty()
    }

    fn is_dirty(&self) -> bool {
        self.is_live_dirty() || self.committing.is_some()
    }

    fn combined_read_overlay(&self) -> TreeOverlay {
        match &self.committing {
            Some(c) => c.overlay.merged_with(&self.overlay),
            None => self.overlay.clone(),
        }
    }

    fn dirty_block_bytes(&self, digest: &Digest) -> Option<Rc<Vec<u8>>> {
        if let Some((bytes, _)) = self.dirty_blocks.get(digest) {
            return Some(Rc::clone(bytes));
        }
        if let Some(c) = &self.committing
            && let Some((bytes, _)) = c.dirty_blocks.get(digest)
        {
            return Some(Rc::clone(bytes));
        }
        None
    }

    fn rollback_committing(&mut self) {
        let Some(c) = self.committing.take() else {
            return;
        };
        self.overlay.merge_under(c.overlay);
        for (digest, (bytes, count)) in c.dirty_blocks {
            if let Some((_, live_cnt)) = self.dirty_blocks.get_mut(&digest) {
                *live_cnt = live_cnt.saturating_add(count);
            } else {
                let sz = bytes.len();
                self.dirty_blocks.insert(digest, (bytes, count));
                self.dirty_block_bytes = self.dirty_block_bytes.saturating_add(sz);
            }
        }
        if let Some(prev) = c.first_dirty_at {
            self.first_dirty_at = Some(match self.first_dirty_at {
                Some(cur) if (cur.sec, cur.nsec) < (prev.sec, prev.nsec) => cur,
                _ => prev,
            });
        }
    }

    fn deadlocks(&self, ino: u64, wanted: Lock) -> bool {
        let mut pending = vec![(ino, wanted)];
        let mut visited = HashSet::new();
        while let Some((ino, wanted_lock)) = pending.pop() {
            for held in self.locks.get(&ino).into_iter().flatten() {
                if !held.conflicts(wanted_lock) {
                    continue;
                }
                if held.owner == wanted.owner {
                    return true;
                }
                if visited.insert(held.owner) {
                    pending.extend(self.waiters.values().filter_map(|waiter| {
                        (waiter.lock.owner == held.owner && waiter.lock.family == wanted.family)
                            .then_some((waiter.ino, waiter.lock))
                    }));
                }
            }
        }
        false
    }
}

struct CommitRollbackGuard<'a, H: HeadStore + 'static, P: PackStore + 'static> {
    fs: &'a CowFs<H, P>,
    armed: bool,
}

impl<H: HeadStore + 'static, P: PackStore + 'static> Drop for CommitRollbackGuard<'_, H, P> {
    fn drop(&mut self) {
        if self.armed {
            {
                let mut st = self.fs.state.borrow_mut();
                st.rollback_committing();
            }
            self.fs.sync_arena_dirty();
        }
    }
}

/// MIT pure-Rust POSIX Copy-on-Write filesystem driver (`FsType::Cowfs`).
pub struct CowFs<H: HeadStore + 'static, P: PackStore + 'static> {
    fs_id: FsId,
    volume_id: VolumeId,
    subvol: String,
    read_only: bool,
    /// Set when mounted via `CowFsOpenMode::Snapshot(name)`; pins the mount immutably to that snapshot.
    pinned_snapshot: Option<String>,
    capabilities: FsCapabilities,
    capacity_bytes: Option<u64>,
    root_generation: u64,
    clock: CowFsClock,
    head_store: Rc<H>,
    pack_store: Rc<P>,
    arena: RefCell<Arena>,
    state: RefCell<CowFsState>,
    /// Serializes mutating read-modify-stage windows (lock hierarchy: ALWAYS `op_lock` -> `commit_lock`).
    op_lock: AsyncMutex,
    commit_lock: AsyncMutex,
}

/// Serialized `(digest, bytes)` node list created when formatting or reformatting a volume.
pub type InitialVolumeNodes = Vec<(Digest, Vec<u8>)>;

struct EncodedAcls {
    access: Option<Vec<u8>>,
    default: Option<Vec<u8>>,
}

impl<H: HeadStore + 'static, P: PackStore + 'static> CowFs<H, P> {
    /// Build initial empty-volume metadata nodes (`RootObject` + root directory leaf) for
    /// `format_volume` and `mkfs --force` reformatting.
    pub fn build_initial_volume_nodes(
        volume: VolumeId,
        root_uid: u32,
        root_gid: u32,
        root_mode: u16,
        now: Timespec,
    ) -> Result<(VolumeHead, InitialVolumeNodes)> {
        let root_inode = InodeItem {
            file_type: FileType::Dir,
            mode: root_mode & 0o7777,
            nlink: 2,
            uid: root_uid,
            gid: root_gid,
            size: 0,
            generation: 1,
            atime: now,
            mtime: now,
            ctime: now,
            rdev: None,
            symlink_target: None,
            next_dir_index: 1,
            acl_present: false,
            default_acl_present: false,
        };
        let leaf = Node::Leaf {
            entries: vec![cowtree::LeafEntry {
                key: TreeKey::inode_item(ROOT_INO),
                value: root_inode.encode(),
            }],
        };
        let (leaf_digest, leaf_bytes) = leaf.encode()?;

        let mut subvols = BTreeMap::new();
        subvols.insert(DEFAULT_SUBVOL.to_string(), leaf_digest);
        let root_obj = RootObject {
            format_version: COWFS_FORMAT_VERSION,
            features: ROOT_FEATURE_ACCOUNTING,
            volume_uuid: volume.0.clone(),
            subvols,
            next_ino: ROOT_INO + 1,
            generation: 1,
            parent_root: None,
            allocated_bytes: 0,
            inode_count: 1,
        };
        let (root_digest, root_bytes) = root_obj.encode()?;

        let head = VolumeHead {
            format_version: COWFS_FORMAT_VERSION,
            volume,
            incarnation: 1,
            fence: 1,
            epoch: 0,
            root: root_digest,
            parent_volume: None,
            ephemeral_if_unmodified: false,
            modified: false,
            updated_at: now,
        };
        Ok((
            head,
            vec![(leaf_digest, leaf_bytes), (root_digest, root_bytes)],
        ))
    }

    /// Initialize a brand-new `os-cowfs` volume (`mkfs.cowfs`) with root directory inode `1`.
    pub async fn format_volume(
        head_store: &H,
        _pack_store: &P,
        volume: VolumeId,
        root_uid: u32,
        root_gid: u32,
        root_mode: u16,
        now: Timespec,
    ) -> Result<VolumeHead> {
        if let Some(v) = head_store.format_version().await?
            && v != COWFS_FORMAT_VERSION
        {
            return Err(Errno::EPROTONOSUPPORT);
        }
        let (head, nodes) =
            Self::build_initial_volume_nodes(volume, root_uid, root_gid, root_mode, now)?;
        head_store.create_volume(&head, &nodes).await
    }

    async fn release_open_handles(
        head_store: &H,
        lease: Option<WriterLease>,
        ro_pin: Option<Box<dyn RoPinGuard>>,
    ) {
        if let Some(pin) = ro_pin {
            let _ = head_store.unpin_ro_root(pin).await;
        }
        if let Some(l) = lease {
            let _ = head_store.release_writer(l).await;
        }
    }

    async fn scan_subvol_accounting(
        tree: &CowTree<'_, H>,
        subvol_root: &Digest,
    ) -> Result<(u64, u64)> {
        let mut allocated_bytes = 0u64;
        let mut inode_count = 0u64;
        let mut start = TreeKey::new(0, 0, Vec::new());
        let end = TreeKey::new(u64::MAX, u8::MAX, Vec::new());
        loop {
            let batch = tree.scan_range(subvol_root, &start, &end, 512).await?;
            if batch.is_empty() {
                break;
            }
            let last = batch.last().unwrap().0.clone();
            let full = batch.len() == 512;
            for (k, raw) in batch {
                if k.kind == KIND_INODE_ITEM {
                    inode_count = inode_count.saturating_add(1);
                } else if k.kind == KIND_EXTENT_DATA
                    && let Ok(ExtentDataValue::Extent { len, .. }) = ExtentDataValue::decode(&raw)
                {
                    allocated_bytes = allocated_bytes.saturating_add(u64::from(len));
                }
            }
            if !full {
                break;
            }
            let mut next_tail = last.tail;
            next_tail.push(0);
            start = TreeKey::new(last.ino, last.kind, next_tail);
        }
        Ok((allocated_bytes, inode_count.max(1)))
    }

    /// Open a `cowfs` volume in read-write, read-only, or pinned-snapshot mode.
    pub async fn open(
        head_store: Rc<H>,
        pack_store: Rc<P>,
        volume: VolumeId,
        mode: CowFsOpenMode,
        config: CowFsConfig,
    ) -> Result<Self> {
        if let Some(v) = head_store.format_version().await?
            && v != COWFS_FORMAT_VERSION
        {
            return Err(Errno::EPROTONOSUPPORT);
        }

        let (
            head,
            root_digest,
            lease,
            ro_pin,
            forked_from,
            read_only,
            pinned_snapshot,
            capabilities,
            fs_id,
        ) = match mode {
            CowFsOpenMode::ReadWrite(writer_mode) => {
                let lease = head_store.acquire_writer(&volume, writer_mode).await?;
                if lease.head.format_version != COWFS_FORMAT_VERSION {
                    let _ = head_store.release_writer(lease).await;
                    return Err(Errno::EPROTONOSUPPORT);
                }
                let head = lease.head.clone();
                let root_digest = head.root;
                let forked_from = lease.forked_from.clone();
                let fs_id = FsId(format!("cowfs:{}", head.volume.0));
                (
                    head,
                    root_digest,
                    Some(lease),
                    None,
                    forked_from,
                    false,
                    None,
                    config.capabilities,
                    fs_id,
                )
            }
            CowFsOpenMode::ReadOnly => {
                let (head, pin) = head_store.pin_ro_root(&volume, None).await?;
                if head.format_version != COWFS_FORMAT_VERSION {
                    let _ = head_store.unpin_ro_root(pin).await;
                    return Err(Errno::EPROTONOSUPPORT);
                }
                let root_digest = head.root;
                let fs_id = FsId(format!(
                    "cowfs:{}@{}",
                    head.volume.0,
                    digest_to_hex(&root_digest)
                ));
                let mut caps = profiles::COWFS_SNAPSHOT;
                caps.durability = config.capabilities.durability;
                (
                    head,
                    root_digest,
                    None,
                    Some(pin),
                    None,
                    true,
                    None,
                    caps,
                    fs_id,
                )
            }
            CowFsOpenMode::Snapshot(snap_name) => {
                let (head, pin) = head_store.pin_ro_root(&volume, Some(&snap_name)).await?;
                if head.format_version != COWFS_FORMAT_VERSION {
                    let _ = head_store.unpin_ro_root(pin).await;
                    return Err(Errno::EPROTONOSUPPORT);
                }
                let root_digest = head.root;
                let fs_id = FsId(format!(
                    "cowfs:{}@{}",
                    volume.0,
                    digest_to_hex(&root_digest)
                ));
                let mut caps = profiles::COWFS_SNAPSHOT;
                caps.durability = config.capabilities.durability;
                (
                    head,
                    root_digest,
                    None,
                    Some(pin),
                    None,
                    true,
                    Some(snap_name),
                    caps,
                    fs_id,
                )
            }
        };

        let raw_root = match head_store.get_node(&root_digest).await {
            Ok(bytes) => bytes,
            Err(e) => {
                Self::release_open_handles(&*head_store, lease, ro_pin).await;
                return Err(e);
            }
        };
        let root_obj = match RootObject::decode_verified(&root_digest, &raw_root) {
            Ok(r) => r,
            Err(e) => {
                Self::release_open_handles(&*head_store, lease, ro_pin).await;
                return Err(e);
            }
        };
        let Some(&subvol_root) = root_obj.subvols.get(&config.subvol) else {
            Self::release_open_handles(&*head_store, lease, ro_pin).await;
            return Err(Errno::ENOENT);
        };

        let arena = RefCell::new(Arena::new(config.arena));
        let tree = CowTree::new(&*head_store, &arena);
        let root_raw = match tree.get(&subvol_root, &TreeKey::inode_item(ROOT_INO)).await {
            Ok(Some(b)) => b,
            Ok(None) => {
                Self::release_open_handles(&*head_store, lease, ro_pin).await;
                return Err(Errno::EIO);
            }
            Err(e) => {
                Self::release_open_handles(&*head_store, lease, ro_pin).await;
                return Err(e);
            }
        };
        let root_inode = match InodeItem::decode(&root_raw) {
            Ok(i) => i,
            Err(e) => {
                Self::release_open_handles(&*head_store, lease, ro_pin).await;
                return Err(e);
            }
        };

        let (allocated_bytes, inode_count) = if (root_obj.features & ROOT_FEATURE_ACCOUNTING) != 0 {
            (root_obj.allocated_bytes, root_obj.inode_count.max(1))
        } else {
            match Self::scan_subvol_accounting(&tree, &subvol_root).await {
                Ok(pair) => pair,
                Err(e) => {
                    Self::release_open_handles(&*head_store, lease, ro_pin).await;
                    return Err(e);
                }
            }
        };

        let actual_volume = head.volume.clone();
        let initial_modified = head.modified;
        let fs = Self {
            fs_id,
            volume_id: actual_volume,
            subvol: config.subvol,
            read_only,
            pinned_snapshot,
            capabilities,
            capacity_bytes: config.capacity_bytes,
            root_generation: root_inode.generation,
            clock: config.clock,
            head_store,
            pack_store,
            arena,
            state: RefCell::new(CowFsState {
                head,
                root_obj,
                subvol_root,
                lease,
                ro_pin,
                forked_from,
                fenced: false,
                closed: false,
                user_modified: initial_modified,
                first_dirty_at: None,
                overlay: TreeOverlay::new(),
                dirty_blocks: HashMap::new(),
                dirty_block_bytes: 0,
                committing: None,
                opens: HashMap::new(),
                open_counts: HashMap::new(),
                locks: HashMap::new(),
                waiters: HashMap::new(),
                next_waiter: 1,
                allocated_bytes,
                inode_count,
            }),
            op_lock: AsyncMutex::default(),
            commit_lock: AsyncMutex::default(),
        };

        // On RW mount, reap any persisted `ORPHAN_ITEM`s left behind by an earlier crash while
        // unlinked files were still open (contract §2.15, §3).
        if !read_only {
            let reap_res = async {
                let reaped = fs.reap_orphans_on_mount().await?;
                if reaped > 0 {
                    fs.commit_tx_group().await?;
                }
                Ok::<(), Errno>(())
            }
            .await;
            if let Err(e) = reap_res {
                let (lease, ro_pin) = {
                    let mut st = fs.state.borrow_mut();
                    st.closed = true;
                    (st.lease.take(), st.ro_pin.take())
                };
                Self::release_open_handles(&*fs.head_store, lease, ro_pin).await;
                return Err(e);
            }
        }
        Ok(fs)
    }

    pub fn volume_id(&self) -> &VolumeId {
        &self.volume_id
    }

    pub fn forked_from(&self) -> Option<VolumeId> {
        self.state.borrow().forked_from.clone()
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    pub fn is_closed(&self) -> bool {
        self.state.borrow().closed
    }

    /// Returns `true` when this RW mount has dirty uncommitted mutations whose 5-second commit
    /// deadline (`DIRTY_COMMIT_DEADLINE_SECS`) has elapsed (or an ambiguous `EIO` commit awaits
    /// idempotent retry).
    pub fn dirty_deadline_elapsed(&self) -> bool {
        if self.read_only {
            return false;
        }
        let st = self.state.borrow();
        if st.closed || st.fenced || st.lease.is_none() || !st.is_dirty() {
            return false;
        }
        let ephemeral_atime_only =
            st.head.ephemeral_if_unmodified && !st.head.modified && !st.user_modified;
        if ephemeral_atime_only {
            return false;
        }
        if st.committing.as_ref().is_some_and(|c| c.pending.is_some()) {
            return true;
        }
        let Some(since) = st.first_dirty_at else {
            return false;
        };
        let now = (self.clock)();
        let elapsed_ns = (i128::from(now.sec) - i128::from(since.sec)) * 1_000_000_000
            + (i128::from(now.nsec) - i128::from(since.nsec));
        elapsed_ns >= i128::from(DIRTY_COMMIT_DEADLINE_SECS) * 1_000_000_000
    }

    /// Milliseconds remaining until the 5-second dirty commit deadline fires, or `None` if clean /
    /// read-only / closed / unmodified ephemeral fork.
    pub fn ms_until_dirty_deadline(&self) -> Option<u64> {
        if self.read_only {
            return None;
        }
        let st = self.state.borrow();
        if st.closed || st.fenced || st.lease.is_none() || !st.is_dirty() {
            return None;
        }
        let ephemeral_atime_only =
            st.head.ephemeral_if_unmodified && !st.head.modified && !st.user_modified;
        if ephemeral_atime_only {
            return None;
        }
        if st.committing.as_ref().is_some_and(|c| c.pending.is_some()) {
            return Some(500);
        }
        let since = st.first_dirty_at?;
        let now = (self.clock)();
        let deadline_ns = i128::from(DIRTY_COMMIT_DEADLINE_SECS) * 1_000_000_000;
        let elapsed_ns = (i128::from(now.sec) - i128::from(since.sec)) * 1_000_000_000
            + (i128::from(now.nsec) - i128::from(since.nsec));
        if elapsed_ns <= 0 {
            return Some(DIRTY_COMMIT_DEADLINE_SECS * 1000);
        }
        if elapsed_ns >= deadline_ns {
            return Some(0);
        }
        let remaining_ns = deadline_ns - elapsed_ns;
        Some(((remaining_ns + 999_999) / 1_000_000) as u64)
    }

    /// Commit dirty state if the 5-second dirty commit deadline has elapsed.
    pub async fn flush_if_dirty_deadline_elapsed(&self) -> Result<bool> {
        if !self.dirty_deadline_elapsed() {
            return Ok(false);
        }
        self.commit_tx_group().await?;
        Ok(true)
    }

    pub fn head_store_rc(&self) -> Rc<H> {
        Rc::clone(&self.head_store)
    }

    pub fn pack_store_rc(&self) -> Rc<P> {
        Rc::clone(&self.pack_store)
    }

    pub fn clock_rc(&self) -> CowFsClock {
        Rc::clone(&self.clock)
    }

    pub fn current_head(&self) -> VolumeHead {
        self.state.borrow().head.clone()
    }

    pub fn arena_stats(&self) -> ArenaStats {
        self.arena.borrow().stats()
    }

    /// Clear clean caches (tree LRU + clean data cache) — useful for cold-read benchmarks/tests.
    pub fn drop_clean_caches(&self) {
        self.arena.borrow_mut().clear_clean_caches();
    }

    pub fn volume_info(&self) -> CowfsInfoResp {
        let st = self.state.borrow();
        CowfsInfoResp {
            format_version: st.head.format_version,
            volume: st.head.volume.0.clone(),
            root: digest_to_hex(&st.head.root),
            incarnation: st.head.incarnation,
            fence: st.head.fence,
            epoch: st.head.epoch,
            writer_model: self.capabilities.writer_model,
            durability: self.capabilities.durability,
            read_only: self.read_only,
            parent_volume: st.head.parent_volume.as_ref().map(|v| v.0.clone()),
        }
    }

    /// Refresh an RO view to the volume's latest committed head (`-o remount,refresh`).
    /// Named snapshot mounts are pinned immutably and reject refresh (`EINVAL`).
    pub async fn refresh_ro(&self) -> Result<VolumeHead> {
        if !self.read_only || self.pinned_snapshot.is_some() {
            return Err(Errno::EINVAL);
        }
        if self.state.borrow().closed {
            return Err(Errno::EBADF);
        }
        let (latest, new_pin) = self.head_store.pin_ro_root(&self.volume_id, None).await?;
        if latest.format_version != COWFS_FORMAT_VERSION {
            let _ = self.head_store.unpin_ro_root(new_pin).await;
            return Err(Errno::EPROTONOSUPPORT);
        }
        let raw_root = match self.head_store.get_node(&latest.root).await {
            Ok(b) => b,
            Err(e) => {
                let _ = self.head_store.unpin_ro_root(new_pin).await;
                return Err(e);
            }
        };
        let root_obj = match RootObject::decode_verified(&latest.root, &raw_root) {
            Ok(r) => r,
            Err(e) => {
                let _ = self.head_store.unpin_ro_root(new_pin).await;
                return Err(e);
            }
        };
        let Some(&subvol_root) = root_obj.subvols.get(&self.subvol) else {
            let _ = self.head_store.unpin_ro_root(new_pin).await;
            return Err(Errno::ENOENT);
        };
        let swap_res = {
            let mut st = self.state.borrow_mut();
            if st.closed {
                Err(new_pin)
            } else {
                if (root_obj.features & ROOT_FEATURE_ACCOUNTING) != 0 {
                    st.allocated_bytes = root_obj.allocated_bytes;
                    st.inode_count = root_obj.inode_count.max(1);
                }
                st.head = latest.clone();
                st.root_obj = root_obj;
                st.subvol_root = subvol_root;
                Ok(st.ro_pin.replace(new_pin))
            }
        };
        let old_pin = match swap_res {
            Ok(old) => old,
            Err(pin) => {
                let _ = self.head_store.unpin_ro_root(pin).await;
                return Err(Errno::EBADF);
            }
        };
        if let Some(old) = old_pin {
            let _ = self.head_store.unpin_ro_root(old).await;
        }
        Ok(latest)
    }

    /// Create an O(1) named snapshot (`name -> root_digest`), committing any dirty state first.
    pub async fn create_snapshot(&self, name: &str) -> Result<SnapshotRecord> {
        let _op = self.op_lock.lock().await;
        self.check_rw()?;
        self.commit_tx_group_with_lock_mode(true).await?;
        let _gc_guard = self.head_store.acquire_gc_lock(false).await?;
        let head = self.state.borrow().head.clone();
        let now = (self.clock)();
        self.head_store
            .create_snapshot(&self.volume_id, name, &head, now)
            .await
    }

    /// Create an O(1) persistent fork volume seeded from `snapshot` (or current committed head).
    /// Zero data bytes are copied.
    pub async fn fork_volume(
        &self,
        snapshot: Option<&str>,
        new_volume: VolumeId,
        ephemeral_if_unmodified: bool,
    ) -> Result<VolumeHead> {
        let _op = self.op_lock.lock().await;
        if self.state.borrow().closed {
            return Err(Errno::EBADF);
        }
        if !self.read_only && snapshot.is_none() {
            self.commit_tx_group_with_lock_mode(true).await?;
        }
        // Hold shared GC lock across root selection + fork publication so GC cannot sweep the
        // selected root concurrently.
        let _gc_guard = self.head_store.acquire_gc_lock(false).await?;
        let source_root = match snapshot {
            Some(snap_name) => {
                self.head_store
                    .get_snapshot(&self.volume_id, snap_name)
                    .await?
                    .root
            }
            None => self.state.borrow().head.root,
        };
        let req = ForkRequest {
            source_volume: self.volume_id.clone(),
            source_snapshot: snapshot
                .map(str::to_owned)
                .or_else(|| self.pinned_snapshot.clone()),
            source_root,
            new_volume,
            ephemeral_if_unmodified,
            created_at: (self.clock)(),
        };
        self.head_store.fork_volume(&req).await
    }

    /// Commit any dirty transaction group, release the writer lease or RO pin, and auto-prune an
    /// unmodified ephemeral tab fork ONLY when this mount is its live, unfenced RW lease holder.
    pub async fn close_clean(&self) -> Result<()> {
        let _op = self.op_lock.lock().await;
        if self.state.borrow().closed {
            return Ok(());
        }
        let (should_commit, can_prune) = {
            let st = self.state.borrow();
            let can_prune = !self.read_only
                && !st.fenced
                && st.lease.is_some()
                && st.head.ephemeral_if_unmodified
                && !st.head.modified
                && !st.user_modified;
            let should_commit =
                !self.read_only && !st.fenced && st.lease.is_some() && !can_prune && st.is_dirty();
            (should_commit, can_prune)
        };
        if should_commit {
            self.commit_tx_group_with_lock_mode(true).await?;
        }
        let _commit = self.commit_lock.lock().await;
        let (lease, ro_pin, final_prune) = {
            let mut st = self.state.borrow_mut();
            if st.closed {
                return Ok(());
            }
            let prune = can_prune
                && !self.read_only
                && !st.fenced
                && st.lease.is_some()
                && st.head.ephemeral_if_unmodified
                && !st.head.modified
                && !st.user_modified;
            st.closed = true;
            st.first_dirty_at = None;
            (st.lease.take(), st.ro_pin.take(), prune)
        };
        if let Some(pin) = ro_pin {
            let _ = self.head_store.unpin_ro_root(pin).await;
        }
        if let Some(l) = lease {
            if final_prune {
                let _ = self.head_store.delete_volume_with_lease(l, true).await;
            } else {
                self.head_store.release_writer(l).await?;
            }
        }
        Ok(())
    }

    /// Commit the current dirty transaction group atomically (`PackStore::write_pack` ->
    /// CoW B+tree node generation -> `HeadStore::commit_head` CAS).
    pub async fn commit_tx_group(&self) -> Result<VolumeHead> {
        if self.read_only {
            let st = self.state.borrow();
            if st.closed {
                return Err(Errno::EBADF);
            }
            return Ok(st.head.clone());
        }
        self.commit_tx_group_with_lock_mode(false).await
    }

    fn retire_committing_success(
        &self,
        committed_head: VolumeHead,
        next_root_obj: RootObject,
        new_subvol_root: Digest,
    ) {
        let mut st = self.state.borrow_mut();
        st.head = committed_head.clone();
        st.subvol_root = new_subvol_root;
        st.root_obj.format_version = next_root_obj.format_version;
        st.root_obj.features = next_root_obj.features;
        st.root_obj.subvols = next_root_obj.subvols;
        st.root_obj.parent_root = next_root_obj.parent_root;
        st.root_obj.generation = next_root_obj.generation;
        // Preserve any concurrent `alloc_ino()` / live mutations staged while committing!
        st.root_obj.next_ino = st.root_obj.next_ino.max(next_root_obj.next_ino);
        st.root_obj.allocated_bytes = st.allocated_bytes;
        st.root_obj.inode_count = st.inode_count;
        if let Some(lease) = st.lease.as_mut() {
            lease.epoch = committed_head.epoch;
            lease.head = committed_head;
        }
        let finished = st.committing.take();
        let remaining_dirty = st.total_dirty_bytes();
        let mut arena = self.arena.borrow_mut();
        arena.set_dirty_bytes(remaining_dirty);
        if let Some(c) = finished {
            for (d, (bytes, _)) in c.dirty_blocks {
                arena.put_data(d, bytes);
            }
        }
    }

    async fn build_commit_request(
        &self,
        head_snap: &VolumeHead,
        subvol_root: &Digest,
        mut next_root_obj: RootObject,
        dirty_blocks_snap: &[(Digest, Rc<Vec<u8>>)],
        sorted_ops: &[(TreeKey, Option<Vec<u8>>)],
    ) -> Result<PendingCommit> {
        // 1. Pack & flush any new dirty data blocks (skipping intra-store dedupe hits).
        let mut builder = PackBuilder::new();
        for (digest, bytes) in dirty_blocks_snap {
            if self.head_store.lookup_block(digest).await?.is_none() {
                builder.push(*digest, bytes)?;
            }
        }
        let built_packs = builder.finish()?;
        let now = (self.clock)();
        let mut put_packs: Vec<PackMeta> = Vec::with_capacity(built_packs.len());
        let mut put_blocks = Vec::new();
        for built in &built_packs {
            let mut meta = self
                .pack_store
                .write_pack(&built.pack_id, &built.bytes)
                .await?;
            meta.created_at = now;
            put_packs.push(meta);
            put_blocks.extend(built.locations.iter().cloned());
        }

        // 2. Apply sorted mutations to CoW B+tree (leaves -> parents -> new subvol root).
        let tree = CowTree::new(&*self.head_store, &self.arena);
        let (new_subvol_root, mut put_nodes) = tree.apply_batch(subvol_root, sorted_ops).await?;

        next_root_obj
            .subvols
            .insert(self.subvol.clone(), new_subvol_root);
        next_root_obj.parent_root = Some(head_snap.root);
        let (new_root_digest, root_bytes) = next_root_obj.encode()?;
        put_nodes.push((new_root_digest, root_bytes));

        // 3. Derive a globally collision-free idempotency key from
        // `(volume, incarnation, fence, epoch, new_root_digest)`.
        let mut op_seed = Vec::with_capacity(16 + self.volume_id.0.len() + 64);
        op_seed.extend_from_slice(b"os-cowfs-op-v1\0");
        op_seed.extend_from_slice(&(self.volume_id.0.len() as u32).to_be_bytes());
        op_seed.extend_from_slice(self.volume_id.0.as_bytes());
        op_seed.extend_from_slice(&head_snap.incarnation.to_be_bytes());
        op_seed.extend_from_slice(&head_snap.fence.to_be_bytes());
        op_seed.extend_from_slice(&head_snap.epoch.to_be_bytes());
        op_seed.extend_from_slice(&new_root_digest);
        let op_hash = sha256(&op_seed);
        let mut op_id = [0u8; 16];
        op_id.copy_from_slice(&op_hash[..16]);

        let commit_req = CommitRequest {
            op_id,
            volume: self.volume_id.clone(),
            expected_incarnation: head_snap.incarnation,
            expected_fence: head_snap.fence,
            expected_epoch: head_snap.epoch,
            new_root: new_root_digest,
            put_nodes,
            put_packs,
            put_blocks,
            committed_at: now,
        };
        Ok(PendingCommit {
            commit_req,
            next_root_obj,
            new_subvol_root,
        })
    }

    async fn commit_tx_group_with_lock_mode(&self, op_lock_held: bool) -> Result<VolumeHead> {
        loop {
            // Strict lock hierarchy: ALWAYS `op_lock` -> `commit_lock`.
            let mut op_guard = if op_lock_held {
                None
            } else {
                Some(self.op_lock.lock().await)
            };
            let commit_guard = self.commit_lock.lock().await;

            {
                let st = self.state.borrow();
                if st.closed {
                    return Err(Errno::EBADF);
                }
                if st.fenced || st.lease.is_none() {
                    return Err(Errno::ESTALE);
                }
            }

            // Phase A: If a previous `commit_head` returned an ambiguous error (e.g., `EIO`),
            // replay its exact `CommitRequest` (`op_id`) to reconcile via receipt before freezing
            // any new live mutations.
            let pending_replay = {
                let st = self.state.borrow();
                st.committing.as_ref().and_then(|c| {
                    c.pending.as_ref().map(|p| {
                        (
                            p.commit_req.clone(),
                            p.next_root_obj.clone(),
                            p.new_subvol_root,
                        )
                    })
                })
            };
            if let Some((commit_req, next_root_obj, new_subvol_root)) = pending_replay {
                drop(op_guard.take());
                let _gc_guard = self.head_store.acquire_gc_lock(false).await?;
                match self.head_store.commit_head(&commit_req).await {
                    Ok(committed_head) => {
                        self.retire_committing_success(
                            committed_head.clone(),
                            next_root_obj,
                            new_subvol_root,
                        );
                        let still_dirty = {
                            let st = self.state.borrow();
                            let ephemeral_atime_only = st.head.ephemeral_if_unmodified
                                && !st.head.modified
                                && !st.user_modified;
                            st.is_live_dirty() && !ephemeral_atime_only
                        };
                        if !still_dirty {
                            return Ok(committed_head);
                        }
                        // Loop to re-acquire `op_lock` -> `commit_lock` cleanly and flush live state.
                        drop(commit_guard);
                        continue;
                    }
                    Err(Errno::ESTALE) => {
                        {
                            let mut st = self.state.borrow_mut();
                            st.fenced = true;
                            st.rollback_committing();
                        }
                        self.sync_arena_dirty();
                        return Err(Errno::ESTALE);
                    }
                    Err(e @ (Errno::ENOSPC | Errno::EDQUOT)) => {
                        self.state.borrow_mut().rollback_committing();
                        self.sync_arena_dirty();
                        return Err(e);
                    }
                    Err(e) => {
                        // Still ambiguous — keep `st.committing.pending` intact for retry.
                        return Err(e);
                    }
                }
            }

            // Phase B: Freeze the live dirty transaction group into `st.committing` while holding
            // `op_lock`, then release `op_lock` BEFORE async storage I/O so concurrent VFS
            // mutations stage safely into fresh `st.overlay` / `st.dirty_blocks`.
            let (skip_commit, head_snap, subvol_root, root_obj_snap, dirty_blocks_snap, sorted_ops) = {
                let mut st = self.state.borrow_mut();
                let ephemeral_atime_only =
                    st.head.ephemeral_if_unmodified && !st.head.modified && !st.user_modified;
                if !st.is_live_dirty() || ephemeral_atime_only {
                    (
                        true,
                        st.head.clone(),
                        st.subvol_root,
                        st.root_obj.clone(),
                        Vec::new(),
                        Vec::new(),
                    )
                } else {
                    let head_snap = st.head.clone();
                    let subvol_root = st.subvol_root;
                    let mut root_obj_snap = st.root_obj.clone();
                    root_obj_snap.features |= ROOT_FEATURE_ACCOUNTING;
                    root_obj_snap.allocated_bytes = st.allocated_bytes;
                    root_obj_snap.inode_count = st.inode_count;
                    let first_dirty_at = st.first_dirty_at.take();
                    let live_overlay = std::mem::take(&mut st.overlay);
                    let live_blocks = std::mem::take(&mut st.dirty_blocks);
                    let live_block_bytes = std::mem::take(&mut st.dirty_block_bytes);

                    let blocks_vec: Vec<(Digest, Rc<Vec<u8>>)> = live_blocks
                        .iter()
                        .map(|(d, (b, _))| (*d, Rc::clone(b)))
                        .collect();
                    let sorted_ops = live_overlay.clone_sorted_ops();
                    st.committing = Some(CommittingGroup {
                        first_dirty_at,
                        overlay: live_overlay,
                        dirty_blocks: live_blocks,
                        dirty_block_bytes: live_block_bytes,
                        pending: None,
                    });
                    (
                        false,
                        head_snap,
                        subvol_root,
                        root_obj_snap,
                        blocks_vec,
                        sorted_ops,
                    )
                }
            };

            drop(op_guard.take());

            if skip_commit {
                // Even when clean, verify our writer fence hasn't been stolen (`ESTALE`).
                let latest = self.head_store.read_head(&self.volume_id).await?;
                if latest.incarnation != head_snap.incarnation || latest.fence != head_snap.fence {
                    self.state.borrow_mut().fenced = true;
                    return Err(Errno::ESTALE);
                }
                return Ok(head_snap);
            }

            let mut rollback = CommitRollbackGuard {
                fs: self,
                armed: true,
            };

            // Acquire shared GC lock across pack write + head CAS so GC never sweeps in-flight packs.
            let _gc_guard = self.head_store.acquire_gc_lock(false).await?;
            let pending = self
                .build_commit_request(
                    &head_snap,
                    &subvol_root,
                    root_obj_snap,
                    &dirty_blocks_snap,
                    &sorted_ops,
                )
                .await?;

            match self.head_store.commit_head(&pending.commit_req).await {
                Ok(committed_head) => {
                    rollback.armed = false;
                    self.retire_committing_success(
                        committed_head.clone(),
                        pending.next_root_obj,
                        pending.new_subvol_root,
                    );
                    return Ok(committed_head);
                }
                Err(Errno::ESTALE) => {
                    self.state.borrow_mut().fenced = true;
                    return Err(Errno::ESTALE);
                }
                Err(e @ (Errno::ENOSPC | Errno::EDQUOT)) => {
                    return Err(e);
                }
                Err(e) => {
                    // Ambiguous failure (e.g. `EIO`): the commit may have applied on storage.
                    // Retain `pending` inside `st.committing` so retry replays the exact `op_id`.
                    rollback.armed = false;
                    if let Some(c) = self.state.borrow_mut().committing.as_mut() {
                        c.pending = Some(pending);
                    }
                    return Err(e);
                }
            }
        }
    }

    fn sync_arena_dirty(&self) {
        let bytes = self.state.borrow().total_dirty_bytes();
        self.arena.borrow_mut().set_dirty_bytes(bytes);
    }

    /// Flush when arena dirty budget is approached OR when the 5-second dirty commit deadline has
    /// elapsed. Caller MUST already hold `op_lock`.
    async fn maybe_backpressure_flush(&self, incoming_bytes: usize) -> Result<()> {
        if self.read_only {
            return Ok(());
        }
        let bp = self.arena.borrow().needs_backpressure_flush(incoming_bytes);
        if bp || self.dirty_deadline_elapsed() {
            self.commit_tx_group_with_lock_mode(true).await?;
            if bp {
                self.arena.borrow_mut().record_backpressure_flush();
            }
        }
        Ok(())
    }

    async fn reap_orphans_on_mount(&self) -> Result<usize> {
        let subvol_root = self.state.borrow().subvol_root;
        let tree = CowTree::new(&*self.head_store, &self.arena);
        let mut overlay = TreeOverlay::new();
        let (reaped, freed_bytes) =
            orphan::reap_all_orphans(&tree, &subvol_root, &mut overlay).await?;
        if reaped > 0 {
            let now = (self.clock)();
            let mut st = self.state.borrow_mut();
            st.user_modified = true;
            st.mark_dirty(now);
            for (k, v) in overlay.take_sorted_ops() {
                match v {
                    Some(val) => st.overlay.put(k, val),
                    None => st.overlay.delete(k),
                }
            }
            st.allocated_bytes = st.allocated_bytes.saturating_sub(freed_bytes);
            st.inode_count = st.inode_count.saturating_sub(reaped as u64).max(1);
            let dirty = st.total_dirty_bytes();
            self.arena.borrow_mut().set_dirty_bytes(dirty);
        }
        Ok(reaped)
    }

    // -------------------------------------------------------------------------
    // Tree & inode helpers (never hold RefCell borrows across `.await`)
    // -------------------------------------------------------------------------

    async fn tree_get(&self, key: &TreeKey) -> Result<Option<Vec<u8>>> {
        let base_root = {
            let st = self.state.borrow();
            if let Some(opt) = st.overlay.get(key) {
                return Ok(opt.map(|v| v.to_vec()));
            }
            if let Some(c) = &st.committing
                && let Some(opt) = c.overlay.get(key)
            {
                return Ok(opt.map(|v| v.to_vec()));
            }
            st.subvol_root
        };
        let tree = CowTree::new(&*self.head_store, &self.arena);
        tree.get(&base_root, key).await
    }

    async fn tree_scan(
        &self,
        start: &TreeKey,
        end: &TreeKey,
        limit: usize,
    ) -> Result<Vec<(TreeKey, Vec<u8>)>> {
        let (base_root, overlay_clone) = {
            let st = self.state.borrow();
            (st.subvol_root, st.combined_read_overlay())
        };
        let tree = CowTree::new(&*self.head_store, &self.arena);
        tree.scan_range_with_overlay(&base_root, &overlay_clone, start, end, limit)
            .await
    }

    async fn tree_find_le(
        &self,
        min_key: &TreeKey,
        max_key: &TreeKey,
    ) -> Result<Option<(TreeKey, Vec<u8>)>> {
        let (base_root, overlay_clone) = {
            let st = self.state.borrow();
            (st.subvol_root, st.combined_read_overlay())
        };
        let tree = CowTree::new(&*self.head_store, &self.arena);
        tree.find_le_with_overlay(&base_root, &overlay_clone, min_key, max_key)
            .await
    }

    async fn load_inode(&self, ino: u64) -> Result<Option<InodeItem>> {
        let Some(raw) = self.tree_get(&TreeKey::inode_item(ino)).await? else {
            return Ok(None);
        };
        InodeItem::decode(&raw).map(Some)
    }

    async fn load_perm_node(&self, ino: u64, item: &InodeItem) -> Result<PermNode> {
        let acl_entries = if item.acl_present {
            match self
                .tree_get(&TreeKey::xattr_item(ino, abi::ACL_ACCESS))
                .await?
            {
                Some(raw) => Some(serde_json::from_slice::<Entries>(&raw).map_err(|_| Errno::EIO)?),
                None => None,
            }
        } else {
            None
        };
        let default_acl = if item.default_acl_present {
            match self
                .tree_get(&TreeKey::xattr_item(ino, abi::ACL_DEFAULT))
                .await?
            {
                Some(raw) => Some(serde_json::from_slice::<Entries>(&raw).map_err(|_| Errno::EIO)?),
                None => None,
            }
        } else {
            None
        };
        Ok(item.to_perm_node(ino, acl_entries, default_acl))
    }

    /// Serialize & validate POSIX ACLs against `xattr::VALUE_MAX` BEFORE mutating overlay state.
    fn encode_perm_acls(node: &PermNode) -> Result<EncodedAcls> {
        let access = if node.acl.is_some() {
            let raw = serde_json::to_vec(&node.entries()).map_err(|_| Errno::EIO)?;
            if raw.len() > xattr::VALUE_MAX {
                return Err(Errno::E2BIG);
            }
            Some(raw)
        } else {
            None
        };
        let default = if let Some(ref def) = node.default_acl {
            let raw = serde_json::to_vec(def).map_err(|_| Errno::EIO)?;
            if raw.len() > xattr::VALUE_MAX {
                return Err(Errno::E2BIG);
            }
            Some(raw)
        } else {
            None
        };
        Ok(EncodedAcls { access, default })
    }

    fn stage_encoded_acls(&self, ino: u64, acls: EncodedAcls) {
        let now = (self.clock)();
        {
            let mut st = self.state.borrow_mut();
            st.user_modified = true;
            st.mark_dirty(now);
            match acls.access {
                Some(raw) => st
                    .overlay
                    .put(TreeKey::xattr_item(ino, abi::ACL_ACCESS), raw),
                None => st.overlay.delete(TreeKey::xattr_item(ino, abi::ACL_ACCESS)),
            }
            match acls.default {
                Some(raw) => st
                    .overlay
                    .put(TreeKey::xattr_item(ino, abi::ACL_DEFAULT), raw),
                None => st
                    .overlay
                    .delete(TreeKey::xattr_item(ino, abi::ACL_DEFAULT)),
            }
        }
        self.sync_arena_dirty();
    }

    fn stage_inode(&self, ino: u64, item: &InodeItem) {
        let now = (self.clock)();
        {
            let mut st = self.state.borrow_mut();
            st.user_modified = true;
            st.mark_dirty(now);
            st.overlay.put(TreeKey::inode_item(ino), item.encode());
        }
        self.sync_arena_dirty();
    }

    fn stage_inode_atime(&self, ino: u64, item: &InodeItem) {
        let now = (self.clock)();
        {
            let mut st = self.state.borrow_mut();
            let ephemeral_unmodified =
                st.head.ephemeral_if_unmodified && !st.head.modified && !st.user_modified;
            if !ephemeral_unmodified {
                st.mark_dirty(now);
            }
            st.overlay.put(TreeKey::inode_item(ino), item.encode());
        }
        self.sync_arena_dirty();
    }

    fn handle_for(&self, ino: u64, generation: u64) -> Handle {
        Handle {
            fs: self.fs_id.clone(),
            node: NodeId { ino, generation },
            proof: String::new(),
        }
    }

    fn entry_for(&self, ino: u64, item: &InodeItem) -> Entry {
        Entry {
            handle: self.handle_for(ino, item.generation),
            metadata: item.to_metadata(),
        }
    }

    async fn check_handle(&self, handle: &Handle) -> Result<(u64, InodeItem)> {
        if self.state.borrow().closed {
            return Err(Errno::EBADF);
        }
        if handle.fs != self.fs_id || !handle.proof.is_empty() {
            return Err(Errno::EACCES);
        }
        let Some(item) = self.load_inode(handle.node.ino).await? else {
            return Err(Errno::ESTALE);
        };
        if item.generation != handle.node.generation {
            return Err(Errno::ESTALE);
        }
        Ok((handle.node.ino, item))
    }

    fn open_record_clone(&self, open: &OpenRef) -> Result<(u64, u64, Access, Identity)> {
        if open.fs != self.fs_id {
            return Err(Errno::EBADF);
        }
        let st = self.state.borrow();
        if st.closed {
            return Err(Errno::EBADF);
        }
        let rec = st.opens.get(&open.id).ok_or(Errno::EBADF)?;
        if rec.ino != open.node.ino || rec.generation != open.node.generation {
            return Err(Errno::EBADF);
        }
        Ok((rec.ino, rec.generation, rec.access, rec.cred.clone()))
    }

    fn new_open(&self, cred: &Cred, ino: u64, generation: u64, access: Access) -> OpenRef {
        let id = NEXT_OPEN_ID.fetch_add(1, Ordering::Relaxed);
        let mut st = self.state.borrow_mut();
        st.opens.insert(
            id,
            OpenRecord {
                ino,
                generation,
                access,
                cred: cred.identity.clone(),
            },
        );
        *st.open_counts.entry(ino).or_insert(0) += 1;
        OpenRef {
            fs: self.fs_id.clone(),
            id,
            node: NodeId { ino, generation },
            access,
        }
    }

    fn check_rw(&self) -> Result<()> {
        if self.read_only {
            return Err(Errno::EROFS);
        }
        let st = self.state.borrow();
        if st.closed {
            return Err(Errno::EBADF);
        }
        if st.fenced || st.lease.is_none() {
            return Err(Errno::ESTALE);
        }
        Ok(())
    }

    fn should_update_atime(item: &InodeItem, is_dir: bool, now: Timespec) -> bool {
        let atime = (item.atime.sec, item.atime.nsec);
        let mtime = (item.mtime.sec, item.mtime.nsec);
        let ctime = (item.ctime.sec, item.ctime.nsec);
        let now_t = (now.sec, now.nsec);
        match vfs::mount::active_mount_flags() {
            Some(flags) => flags.should_update_atime(is_dir, atime, mtime, ctime, now_t),
            None => {
                atime <= mtime
                    || atime <= ctime
                    || now.sec.saturating_sub(item.atime.sec) >= 24 * 60 * 60
            }
        }
    }

    async fn update_atime_if_needed(
        &self,
        ino: u64,
        expected_gen: u64,
        item: &InodeItem,
        is_dir: bool,
    ) {
        if self.read_only {
            return;
        }
        let now = (self.clock)();
        if !Self::should_update_atime(item, is_dir, now) {
            return;
        }
        let _op = self.op_lock.lock().await;
        {
            let st = self.state.borrow();
            if st.closed || st.fenced || st.lease.is_none() {
                return;
            }
        }
        if let Ok(Some(mut cur)) = self.load_inode(ino).await
            && cur.generation == expected_gen
            && cur.nlink > 0
        {
            let now = (self.clock)();
            if Self::should_update_atime(&cur, is_dir, now) {
                cur.atime = now;
                self.stage_inode_atime(ino, &cur);
            }
        }
    }

    async fn searchable(
        &self,
        cred: &Cred,
        dir_ino: u64,
        dir_item: &InodeItem,
    ) -> Result<PermNode> {
        if dir_item.file_type != FileType::Dir {
            return Err(Errno::ENOTDIR);
        }
        let perm = self.load_perm_node(dir_ino, dir_item).await?;
        inode::require(&cred.identity, &perm, EXEC)?;
        Ok(perm)
    }

    async fn lookup_dir_item(&self, dir_ino: u64, name: &str) -> Result<Option<DirItemValue>> {
        let Some(raw) = self.tree_get(&TreeKey::dir_item(dir_ino, name)).await? else {
            return Ok(None);
        };
        DirItemValue::decode(&raw).map(Some)
    }

    async fn dir_is_empty(&self, dir_ino: u64) -> Result<bool> {
        let items = self
            .tree_scan(
                &TreeKey::kind_start(dir_ino, KIND_DIR_ITEM),
                &TreeKey::kind_end(dir_ino, KIND_DIR_ITEM),
                1,
            )
            .await?;
        Ok(items.is_empty())
    }

    async fn is_ancestor(&self, ancestor: u64, mut ino: u64) -> Result<bool> {
        loop {
            if ino == ancestor {
                return Ok(true);
            }
            if ino == ROOT_INO {
                return Ok(false);
            }
            let refs = self
                .tree_scan(
                    &TreeKey::kind_start(ino, KIND_INODE_REF),
                    &TreeKey::kind_end(ino, KIND_INODE_REF),
                    1,
                )
                .await?;
            let Some((key, _)) = refs.first() else {
                return Ok(false);
            };
            let Some((parent, _)) = key.tail_inode_ref() else {
                return Ok(false);
            };
            if parent == ino {
                return Ok(false);
            }
            ino = parent;
        }
    }

    fn alloc_ino(&self) -> (u64, u64) {
        let mut st = self.state.borrow_mut();
        let ino = st.root_obj.next_ino;
        st.root_obj.next_ino += 1;
        let generation = st.root_obj.generation;
        st.inode_count = st.inode_count.saturating_add(1);
        (ino, generation)
    }

    /// Reclaim all items belonging to an unlinked inode when its open count reaches zero.
    /// Caller MUST hold `op_lock`. Never takes `st.overlay` across `.await`.
    async fn reclaim_if_dead_locked(&self, ino: u64, item: &InodeItem) -> Result<()> {
        if item.nlink != 0 {
            return Ok(());
        }
        let opens = self
            .state
            .borrow()
            .open_counts
            .get(&ino)
            .copied()
            .unwrap_or(0);
        if opens == 0 {
            let (base_root, read_overlay) = {
                let st = self.state.borrow();
                (st.subvol_root, st.combined_read_overlay())
            };
            let tree = CowTree::new(&*self.head_store, &self.arena);
            let plan =
                orphan::collect_inode_reclaim_plan(&tree, &base_root, &read_overlay, ino).await?;
            let now = (self.clock)();
            {
                let mut st = self.state.borrow_mut();
                if st.open_counts.get(&ino).copied().unwrap_or(0) > 0 {
                    st.user_modified = true;
                    st.mark_dirty(now);
                    orphan::stage_orphan(&mut st.overlay, ino);
                } else {
                    st.user_modified = true;
                    st.mark_dirty(now);
                    for k in plan.delete_keys {
                        st.overlay.delete(k);
                    }
                    orphan::clear_orphan(&mut st.overlay, ino);
                    for d in &plan.dropped_digests {
                        st.unstage_dirty_block(d);
                    }
                    st.locks.remove(&ino);
                    st.allocated_bytes = st.allocated_bytes.saturating_sub(plan.freed_extent_bytes);
                    st.inode_count = st.inode_count.saturating_sub(1).max(1);
                }
            }
            self.sync_arena_dirty();
        } else {
            // Still open after last link gone -> persist ORPHAN_ITEM for crash recovery!
            let now = (self.clock)();
            {
                let mut st = self.state.borrow_mut();
                st.user_modified = true;
                st.mark_dirty(now);
                orphan::stage_orphan(&mut st.overlay, ino);
            }
            self.sync_arena_dirty();
        }
        Ok(())
    }

    async fn read_verified_block(&self, digest: &Digest) -> Result<Rc<Vec<u8>>> {
        // 1. Check live & committing dirty uncommitted blocks.
        if let Some(bytes) = self.state.borrow().dirty_block_bytes(digest) {
            return Ok(bytes);
        }
        // 2. Check clean data LRU cache in Arena.
        if let Some(hit) = self.arena.borrow_mut().get_data(digest) {
            return Ok(hit);
        }
        // 3. Fetch from PackStore and SHA-256 verify BEFORE caching or returning bytes!
        let loc = self
            .head_store
            .lookup_block(digest)
            .await?
            .ok_or(Errno::EIO)?;
        let bytes = self
            .pack_store
            .read_pack_range(&loc.pack_id, loc.offset, loc.len)
            .await?;
        verify_block_digest(digest, &bytes)?;
        let rc = Rc::new(bytes);
        self.arena.borrow_mut().put_data(*digest, Rc::clone(&rc));
        Ok(rc)
    }

    /// Read up to `buf.len()` bytes of `ino` starting at `offset` (clamped by `inode.size`).
    async fn read_file_bytes(
        &self,
        ino: u64,
        file_size: u64,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize> {
        if offset >= file_size || buf.is_empty() {
            return Ok(0);
        }
        let target_len =
            usize::try_from(file_size - offset).map_or(buf.len(), |left| left.min(buf.len()));
        let mut done = 0usize;
        let min_k = TreeKey::kind_start(ino, KIND_EXTENT_DATA);

        while done < target_len {
            let at = offset + done as u64;
            let max_k = TreeKey::extent_data(ino, at);
            if let Some((ext_key, ext_raw)) = self.tree_find_le(&min_k, &max_k).await?
                && let Some(ext_start) = ext_key.tail_u64()
            {
                match ExtentDataValue::decode(&ext_raw)? {
                    ExtentDataValue::Inline(data) => {
                        let ext_end = ext_start.saturating_add(data.len() as u64);
                        if at < ext_end {
                            let within = (at - ext_start) as usize;
                            let avail = data.len() - within;
                            let take = avail.min(target_len - done);
                            buf[done..done + take].copy_from_slice(&data[within..within + take]);
                            done += take;
                            continue;
                        }
                    }
                    ExtentDataValue::Extent {
                        len: ext_len,
                        digest,
                        block_offset,
                    } => {
                        let ext_end = ext_start.saturating_add(u64::from(ext_len));
                        if at < ext_end {
                            let block = self.read_verified_block(&digest).await?;
                            let rel = (at - ext_start) as usize;
                            let start_in_blk =
                                (block_offset as usize).checked_add(rel).ok_or(Errno::EIO)?;
                            let avail_in_ext = (ext_len as usize) - rel;
                            let take = avail_in_ext.min(target_len - done);
                            let end_in_blk = start_in_blk.checked_add(take).ok_or(Errno::EIO)?;
                            if end_in_blk > block.len() {
                                return Err(Errno::EIO);
                            }
                            buf[done..done + take]
                                .copy_from_slice(&block[start_in_blk..end_in_blk]);
                            done += take;
                            continue;
                        }
                    }
                }
            }

            // `at` lies in a sparse hole. Find the next extent strictly after `at` (if any) to
            // know how many zeros to emit in one step.
            let next_start = TreeKey::extent_data(ino, at.saturating_add(1));
            let next_end = TreeKey::kind_end(ino, KIND_EXTENT_DATA);
            let next_ext = self.tree_scan(&next_start, &next_end, 1).await?;
            let hole_end = next_ext
                .first()
                .and_then(|(k, _)| k.tail_u64())
                .unwrap_or(file_size)
                .min(file_size);
            let hole_len = usize::try_from(hole_end.saturating_sub(at))
                .unwrap_or(usize::MAX)
                .min(target_len - done)
                .max(1);
            buf[done..done + hole_len].fill(0);
            done += hole_len;
        }
        Ok(target_len)
    }

    /// Shrink file extents past `new_size`, performing all async reads and verification BEFORE
    /// mutating the live overlay so an I/O error leaves the file completely unchanged.
    /// Caller MUST hold `op_lock`.
    async fn resize_file_extents(
        &self,
        ino: u64,
        old_size: u64,
        new_size: u64,
        now: Timespec,
    ) -> Result<()> {
        if new_size >= old_size {
            return Ok(());
        }

        // 1. Collect all extents starting at >= new_size without mutating `st.overlay` yet.
        let mut delete_extents: Vec<(TreeKey, Option<Digest>, u64)> = Vec::new();
        let mut start = TreeKey::extent_data(ino, new_size);
        let end = TreeKey::kind_end(ino, KIND_EXTENT_DATA);
        let (base_root, read_overlay) = {
            let st = self.state.borrow();
            (st.subvol_root, st.combined_read_overlay())
        };
        let tree = CowTree::new(&*self.head_store, &self.arena);
        loop {
            let batch = tree
                .scan_range_with_overlay(&base_root, &read_overlay, &start, &end, 256)
                .await?;
            if batch.is_empty() {
                break;
            }
            let last = batch.last().unwrap().0.clone();
            let full = batch.len() == 256;
            for (k, raw) in batch {
                let (dig, len) = match ExtentDataValue::decode(&raw)? {
                    ExtentDataValue::Extent { len, digest, .. } => (Some(digest), u64::from(len)),
                    ExtentDataValue::Inline(_) => (None, 0),
                };
                delete_extents.push((k, dig, len));
            }
            if !full {
                break;
            }
            let mut tail = last.tail;
            tail.push(0);
            start = TreeKey::new(last.ino, last.kind, tail);
        }

        // 2. Inspect any extent starting strictly before `new_size` that straddles `new_size`,
        // reading its verified backing block BEFORE staging any mutation.
        struct TailBlockPlan {
            key: TreeKey,
            digest: Digest,
            block: Rc<Vec<u8>>,
            encoded: Vec<u8>,
        }

        enum StraddlePlan {
            None,
            InlineReplace {
                key: TreeKey,
                encoded: Vec<u8>,
            },
            ExtentSplit {
                old_key: TreeKey,
                old_digest: Digest,
                old_len: u32,
                old_bytes: Rc<Vec<u8>>,
                prefix: Option<(TreeKey, Vec<u8>, u32)>,
                tail: Option<TailBlockPlan>,
            },
        }

        let mut straddle = StraddlePlan::None;
        if new_size > 0 {
            let min_k = TreeKey::kind_start(ino, KIND_EXTENT_DATA);
            let max_k = TreeKey::extent_data(ino, new_size - 1);
            if let Some((ext_key, ext_raw)) = tree
                .find_le_with_overlay(&base_root, &read_overlay, &min_k, &max_k)
                .await?
                && let Some(ext_start) = ext_key.tail_u64()
            {
                match ExtentDataValue::decode(&ext_raw)? {
                    ExtentDataValue::Inline(mut data) => {
                        // Compare in `u64` BEFORE narrowing to `usize` so >= 4 GiB truncates on
                        // 32-bit `wasm32` never wrap `(new_size - ext_start) as usize` to 0!
                        let keep_u64 = new_size - ext_start;
                        if keep_u64 < data.len() as u64 {
                            data.truncate(keep_u64 as usize);
                            let encoded = ExtentDataValue::Inline(data).encode()?;
                            straddle = StraddlePlan::InlineReplace {
                                key: ext_key,
                                encoded,
                            };
                        }
                    }
                    ExtentDataValue::Extent {
                        len: ext_len,
                        digest,
                        block_offset,
                    } => {
                        let ext_end = ext_start.saturating_add(u64::from(ext_len));
                        if new_size < ext_end {
                            let blk_size = u64::from(BLOCK_SIZE);
                            let tail_blk_start = (new_size / blk_size) * blk_size;
                            let block_bytes = self.read_verified_block(&digest).await?;

                            let prefix = if tail_blk_start > ext_start {
                                let prefix_len = (tail_blk_start - ext_start) as u32;
                                let prefix_val = ExtentDataValue::Extent {
                                    len: prefix_len,
                                    digest,
                                    block_offset,
                                }
                                .encode()?;
                                Some((TreeKey::extent_data(ino, ext_start), prefix_val, prefix_len))
                            } else {
                                None
                            };

                            let keep_in_blk = (new_size - tail_blk_start) as usize;
                            let tail = if keep_in_blk > 0 {
                                let mut new_blk = vec![0u8; BLOCK_SIZE as usize];
                                let src_off =
                                    (block_offset as usize) + (tail_blk_start - ext_start) as usize;
                                let avail = block_bytes.len().saturating_sub(src_off);
                                let copy_len = keep_in_blk.min(avail);
                                new_blk[..copy_len]
                                    .copy_from_slice(&block_bytes[src_off..src_off + copy_len]);
                                let new_dig = sha256(&new_blk);
                                let val = ExtentDataValue::Extent {
                                    len: BLOCK_SIZE,
                                    digest: new_dig,
                                    block_offset: 0,
                                }
                                .encode()?;
                                Some(TailBlockPlan {
                                    key: TreeKey::extent_data(ino, tail_blk_start),
                                    digest: new_dig,
                                    block: Rc::new(new_blk),
                                    encoded: val,
                                })
                            } else {
                                None
                            };

                            straddle = StraddlePlan::ExtentSplit {
                                old_key: ext_key,
                                old_digest: digest,
                                old_len: ext_len,
                                old_bytes: block_bytes,
                                prefix,
                                tail,
                            };
                        }
                    }
                }
            }
        }

        // 3. Apply the verified resize plan atomically in one synchronous borrow.
        {
            let mut st = self.state.borrow_mut();
            if !delete_extents.is_empty() || !matches!(straddle, StraddlePlan::None) {
                st.user_modified = true;
                st.mark_dirty(now);
            }
            for (k, dig, len) in delete_extents {
                if let Some(d) = dig {
                    st.unstage_dirty_block(&d);
                }
                st.allocated_bytes = st.allocated_bytes.saturating_sub(len);
                st.overlay.delete(k);
            }
            match straddle {
                StraddlePlan::None => {}
                StraddlePlan::InlineReplace { key, encoded } => {
                    st.overlay.put(key, encoded);
                }
                StraddlePlan::ExtentSplit {
                    old_key,
                    old_digest,
                    old_len,
                    old_bytes,
                    prefix,
                    tail,
                } => {
                    let was_dirty = st.dirty_block_bytes(&old_digest).is_some();
                    st.unstage_dirty_block(&old_digest);
                    st.overlay.delete(old_key);
                    st.allocated_bytes = st.allocated_bytes.saturating_sub(u64::from(old_len));
                    if let Some((pre_key, pre_val, pre_len)) = prefix {
                        if was_dirty {
                            st.stage_dirty_block(old_digest, Rc::clone(&old_bytes));
                        }
                        st.overlay.put(pre_key, pre_val);
                        st.allocated_bytes = st.allocated_bytes.saturating_add(u64::from(pre_len));
                    }
                    if let Some(TailBlockPlan {
                        key: tail_key,
                        digest: tail_dig,
                        block: tail_blk,
                        encoded: tail_val,
                    }) = tail
                    {
                        st.stage_dirty_block(tail_dig, tail_blk);
                        st.overlay.put(tail_key, tail_val);
                        st.allocated_bytes =
                            st.allocated_bytes.saturating_add(u64::from(BLOCK_SIZE));
                    }
                }
            }
        }
        self.sync_arena_dirty();
        Ok(())
    }

    /// Resize regular file `ino` to `new_size`, freeing extents past `new_size`, zeroing any
    /// partial tail block, stripping setuid/setgid privileges, and staging the updated inode.
    /// Caller MUST hold `op_lock`.
    async fn resize_file(
        &self,
        ino: u64,
        inode_item: &mut InodeItem,
        new_size: u64,
        by: &Identity,
        now: Timespec,
    ) -> Result<()> {
        let mut perm = self.load_perm_node(ino, inode_item).await?;
        self.resize_file_extents(ino, inode_item.size, new_size, now)
            .await?;
        inode::remove_privs(by, &mut perm);
        inode_item.apply_perm_node(&perm);
        inode_item.size = new_size;
        inode_item.mtime = now;
        inode_item.ctime = now;
        self.stage_inode(ino, inode_item);
        Ok(())
    }

    /// Promote an inline extent at offset 0 (if present) into a 64 KiB block so larger/offset
    /// writes operate uniformly on 64 KiB aligned blocks. Caller MUST hold `op_lock`.
    async fn promote_inline_if_present(&self, ino: u64, now: Timespec) -> Result<()> {
        let key0 = TreeKey::extent_data(ino, 0);
        let Some(raw) = self.tree_get(&key0).await? else {
            return Ok(());
        };
        let ExtentDataValue::Inline(inline_bytes) = ExtentDataValue::decode(&raw)? else {
            return Ok(());
        };
        if let Some(cap) = self.capacity_bytes
            && self
                .state
                .borrow()
                .allocated_bytes
                .saturating_add(u64::from(BLOCK_SIZE))
                > cap
        {
            return Err(Errno::ENOSPC);
        }
        self.maybe_backpressure_flush(BLOCK_SIZE as usize).await?;
        let mut blk = vec![0u8; BLOCK_SIZE as usize];
        blk[..inline_bytes.len()].copy_from_slice(&inline_bytes);
        let digest = sha256(&blk);
        let enc = ExtentDataValue::Extent {
            len: BLOCK_SIZE,
            digest,
            block_offset: 0,
        }
        .encode()?;
        {
            let mut st = self.state.borrow_mut();
            st.user_modified = true;
            st.mark_dirty(now);
            st.allocated_bytes = st.allocated_bytes.saturating_add(u64::from(BLOCK_SIZE));
            st.stage_dirty_block(digest, Rc::new(blk));
            st.overlay.put(key0, enc);
        }
        self.sync_arena_dirty();
        Ok(())
    }

    /// Write `data` to regular file `ino` starting at `offset`, using `<= 2 KiB` inline storage
    /// for tiny files and `64 KiB` CoW aligned blocks with `Arena` dirty backpressure for larger
    /// or sparse files. Caller MUST hold `op_lock`.
    async fn write_file_bytes(
        &self,
        ino: u64,
        inode_item: &mut InodeItem,
        offset: u64,
        data: &[u8],
        stripped_mode: u16,
        now: Timespec,
    ) -> Result<usize> {
        let end = offset.saturating_add(data.len() as u64);

        // Fast path: keep tiny files (`<= 2 KiB`) inline inside the B+tree leaf!
        if inode_item.size <= INLINE_MAX_BYTES as u64 && end <= INLINE_MAX_BYTES as u64 {
            let key0 = TreeKey::extent_data(ino, 0);
            let existing = self.tree_get(&key0).await?;
            let can_inline = match existing.as_deref() {
                None => true,
                Some(raw) => matches!(ExtentDataValue::decode(raw)?, ExtentDataValue::Inline(_)),
            };
            if can_inline {
                let mut buf = match existing.as_deref() {
                    Some(raw) => match ExtentDataValue::decode(raw)? {
                        ExtentDataValue::Inline(v) => v,
                        _ => unreachable!(),
                    },
                    None => Vec::new(),
                };
                if buf.len() < end as usize {
                    buf.resize(end as usize, 0);
                }
                buf[offset as usize..end as usize].copy_from_slice(data);
                let enc = ExtentDataValue::Inline(buf).encode()?;
                self.maybe_backpressure_flush(enc.len() + 64).await?;
                {
                    let mut st = self.state.borrow_mut();
                    st.user_modified = true;
                    st.mark_dirty(now);
                    st.overlay.put(key0, enc);
                }
                inode_item.size = inode_item.size.max(end);
                self.sync_arena_dirty();
                return Ok(data.len());
            }
        }

        // Promote any existing inline data into block 0 before 64 KiB block writes.
        self.promote_inline_if_present(ino, now).await?;

        let blk_size = u64::from(BLOCK_SIZE);
        let mut done = 0usize;

        while done < data.len() {
            let at = offset + done as u64;
            let blk_start = (at / blk_size) * blk_size;
            let within = (at % blk_size) as usize;
            let chunk = (BLOCK_SIZE as usize - within).min(data.len() - done);

            // Check optional logical capacity ceiling before allocating a brand-new block.
            let existing_cover = self
                .tree_find_le(
                    &TreeKey::kind_start(ino, KIND_EXTENT_DATA),
                    &TreeKey::extent_data(ino, blk_start),
                )
                .await?;
            let covering = match existing_cover {
                Some((k, raw)) => {
                    let ext_start = k.tail_u64().ok_or(Errno::EIO)?;
                    match ExtentDataValue::decode(&raw)? {
                        ExtentDataValue::Extent {
                            len,
                            digest,
                            block_offset,
                        } if blk_start < ext_start.saturating_add(u64::from(len)) => {
                            Some((k, ext_start, len, digest, block_offset))
                        }
                        _ => None,
                    }
                }
                None => None,
            };

            if covering.is_none()
                && let Some(cap) = self.capacity_bytes
            {
                let cur = self.state.borrow().allocated_bytes;
                if cur.saturating_add(blk_size) > cap {
                    if done > 0 {
                        return Ok(done);
                    }
                    return Err(Errno::ENOSPC);
                }
            }

            // Enforce Arena 8 MiB dirty slab backpressure (or 5s dirty deadline) BEFORE allocating
            // another dirty block. When `done > 0`, strip S_ISUID/S_ISGID and stage the consistent
            // intermediate inode BEFORE committing so a crash never leaves setuid on modified data.
            let bp = self
                .arena
                .borrow()
                .needs_backpressure_flush(BLOCK_SIZE as usize + 256);
            if bp || self.dirty_deadline_elapsed() {
                if done > 0 {
                    inode_item.mode = stripped_mode;
                    inode_item.mtime = now;
                    inode_item.ctime = now;
                    self.stage_inode(ino, inode_item);
                }
                if let Err(e) = self.commit_tx_group_with_lock_mode(true).await {
                    if done > 0 && matches!(e, Errno::ENOSPC | Errno::EDQUOT) {
                        return Ok(done);
                    }
                    return Err(e);
                }
                if bp {
                    self.arena.borrow_mut().record_backpressure_flush();
                }
            }

            // Build the new 64 KiB block content (copy-on-write).
            let mut blk = vec![0u8; BLOCK_SIZE as usize];
            if let Some((old_key, ext_start, ext_len, old_digest, old_blk_off)) = covering {
                let need_read = chunk < BLOCK_SIZE as usize || ext_len > BLOCK_SIZE;
                let old_bytes = if need_read {
                    Some(self.read_verified_block(&old_digest).await?)
                } else {
                    None
                };
                if chunk < BLOCK_SIZE as usize
                    && let Some(ref bytes) = old_bytes
                {
                    let src_off = (old_blk_off as usize) + (blk_start - ext_start) as usize;
                    let avail = bytes.len().saturating_sub(src_off);
                    let copy_len = (BLOCK_SIZE as usize).min(avail);
                    blk[..copy_len].copy_from_slice(&bytes[src_off..src_off + copy_len]);
                }

                // Remove old extent and split untouched prefix/suffix if it spanned > 64 KiB.
                let ext_end = ext_start.saturating_add(u64::from(ext_len));
                let blk_end = blk_start.saturating_add(blk_size);
                {
                    let mut st = self.state.borrow_mut();
                    let was_dirty = st.dirty_block_bytes(&old_digest).is_some();
                    st.unstage_dirty_block(&old_digest);
                    st.overlay.delete(old_key);
                    let mut retained_len = blk_size;

                    if blk_start > ext_start {
                        let pre_len = (blk_start - ext_start) as u32;
                        retained_len = retained_len.saturating_add(u64::from(pre_len));
                        let pre_enc = ExtentDataValue::Extent {
                            len: pre_len,
                            digest: old_digest,
                            block_offset: old_blk_off,
                        }
                        .encode()?;
                        if was_dirty && let Some(ref bytes) = old_bytes {
                            st.stage_dirty_block(old_digest, Rc::clone(bytes));
                        }
                        st.overlay
                            .put(TreeKey::extent_data(ino, ext_start), pre_enc);
                    }
                    if ext_end > blk_end {
                        let suf_len = (ext_end - blk_end) as u32;
                        retained_len = retained_len.saturating_add(u64::from(suf_len));
                        let suf_off = old_blk_off + (blk_end - ext_start) as u32;
                        let suf_enc = ExtentDataValue::Extent {
                            len: suf_len,
                            digest: old_digest,
                            block_offset: suf_off,
                        }
                        .encode()?;
                        if was_dirty && let Some(ref bytes) = old_bytes {
                            st.stage_dirty_block(old_digest, Rc::clone(bytes));
                        }
                        st.overlay.put(TreeKey::extent_data(ino, blk_end), suf_enc);
                    }
                    st.allocated_bytes = st
                        .allocated_bytes
                        .saturating_sub(u64::from(ext_len))
                        .saturating_add(retained_len);
                }
            } else {
                let mut st = self.state.borrow_mut();
                st.allocated_bytes = st.allocated_bytes.saturating_add(blk_size);
            }

            blk[within..within + chunk].copy_from_slice(&data[done..done + chunk]);
            let new_digest = sha256(&blk);
            let enc = ExtentDataValue::Extent {
                len: BLOCK_SIZE,
                digest: new_digest,
                block_offset: 0,
            }
            .encode()?;
            {
                let mut st = self.state.borrow_mut();
                st.user_modified = true;
                st.mark_dirty(now);
                st.stage_dirty_block(new_digest, Rc::new(blk));
                st.overlay.put(TreeKey::extent_data(ino, blk_start), enc);
            }
            done += chunk;
            inode_item.size = inode_item.size.max(offset + done as u64);
            self.sync_arena_dirty();
        }
        Ok(done)
    }

    // -------------------------------------------------------------------------
    // Lock helpers (identical semantics to MemFs, plus RO ENOLCK for exclusive locks)
    // -------------------------------------------------------------------------

    fn lockable(
        &self,
        open: &OpenRef,
        family: LockFamily,
        kind: Option<LockKind>,
        range: LockRange,
    ) -> Result<u64> {
        let (ino, _gen, access, _) = self.open_record_clone(open)?;
        let allowed = match (family, kind) {
            _ if access == Access::Path => false,
            (LockFamily::Flock, _) | (LockFamily::Posix, None) => true,
            (LockFamily::Posix, Some(LockKind::Shared)) => access.reads(),
            (LockFamily::Posix, Some(LockKind::Exclusive)) => access.writes(),
        };
        if !allowed {
            return Err(Errno::EBADF);
        }
        if family == LockFamily::Flock && range != LockRange::WHOLE {
            return Err(Errno::EINVAL);
        }
        // Contract §3: on RO / snapshot mounts, shared locks are instance-local; exclusive locks
        // return `ENOLCK` (no cross-instance lock keeper).
        if self.read_only && kind == Some(LockKind::Exclusive) {
            return Err(Errno::ENOLCK);
        }
        Ok(ino)
    }

    fn conflict(
        st: &CowFsState,
        ino: u64,
        owner: u64,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> Option<Conflict> {
        st.locks.get(&ino)?.iter().find_map(|lock| {
            (lock.owner != owner
                && lock.family == family
                && lock.range.overlaps(range)
                && (kind == LockKind::Exclusive || lock.kind == LockKind::Exclusive))
                .then_some(Conflict {
                    kind: lock.kind,
                    range: lock.range,
                    owner: lock.owner,
                })
        })
    }

    fn wake_lock_waiters(&self, ino: u64) {
        let wakers: Vec<Waker> = self
            .state
            .borrow()
            .waiters
            .values()
            .filter(|w| w.ino == ino)
            .map(|w| w.waker.clone())
            .collect();
        for w in wakers {
            w.wake();
        }
    }

    fn acquire_lock(
        &self,
        open: &OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
        waker: Option<&Waker>,
    ) -> Result<Option<u64>> {
        let ino = self.lockable(open, family, Some(kind), range)?;
        let owner = open.id;

        // flock conversion drops the old lock before waiting, matching Linux.
        let need_wake = {
            let mut st = self.state.borrow_mut();
            if family == LockFamily::Flock
                && let Some(locks) = st.locks.get_mut(&ino)
                && locks
                    .iter()
                    .any(|l| l.owner == owner && l.family == family && l.kind != kind)
            {
                carve(locks, owner, family, range);
                true
            } else {
                false
            }
        };
        if need_wake {
            self.wake_lock_waiters(ino);
            self.lockable(open, family, Some(kind), range)?;
        }

        let wanted = Lock {
            owner,
            family,
            kind,
            range,
        };
        let mut st = self.state.borrow_mut();
        if Self::conflict(&st, ino, owner, family, kind, range).is_some() {
            let Some(waker) = waker else {
                return Err(Errno::EAGAIN);
            };
            if family == LockFamily::Posix && st.deadlocks(ino, wanted) {
                return Err(Errno::EDEADLK);
            }
            let id = st.next_waiter;
            st.next_waiter += 1;
            st.waiters.insert(
                id,
                Waiter {
                    ino,
                    lock: wanted,
                    waker: waker.clone(),
                },
            );
            return Ok(Some(id));
        }

        let locks = st.locks.entry(ino).or_default();
        carve(locks, owner, family, range);
        let mut merged = range;
        locks.retain(|l| {
            let joins =
                l.owner == owner && l.family == family && l.kind == kind && l.range.touches(merged);
            if joins {
                merged = merged.union(l.range);
            }
            !joins
        });
        locks.push(Lock {
            owner,
            family,
            kind,
            range: merged,
        });
        drop(st);
        self.wake_lock_waiters(ino);
        Ok(None)
    }

    async fn add_node_in_dir(
        &self,
        dir_ino: u64,
        dir_item: &mut InodeItem,
        name: &str,
        node: PermNode,
    ) -> Result<(u64, InodeItem)> {
        let acls = Self::encode_perm_acls(&node)?;
        self.maybe_backpressure_flush(1024).await?;
        let (ino, generation) = self.alloc_ino();
        let now = (self.clock)();
        let file_type = if node.directory {
            FileType::Dir
        } else if node.link.is_some() {
            FileType::Symlink
        } else if node.rdev.is_some() {
            FileType::CharDevice
        } else {
            FileType::File
        };
        let nlink = if file_type == FileType::Dir { 2 } else { 1 };
        let item = InodeItem {
            file_type,
            mode: node.mode & 0o7777,
            nlink,
            uid: node.owner,
            gid: node.group,
            size: 0,
            generation,
            atime: now,
            mtime: now,
            ctime: now,
            rdev: node.rdev.clone(),
            symlink_target: node.link.clone(),
            next_dir_index: 1,
            acl_present: node.acl.is_some(),
            default_acl_present: node.default_acl.is_some(),
        };

        let dir_index = dir_item.next_dir_index;
        dir_item.next_dir_index = dir_item.next_dir_index.saturating_add(1);
        if file_type == FileType::Dir {
            dir_item.nlink = dir_item.nlink.saturating_add(1);
        }
        dir_item.mtime = now;
        dir_item.ctime = now;

        let di = DirItemValue {
            child_ino: ino,
            child_gen: generation,
            file_type,
            dir_index,
        };
        let didx = DirIndexValue {
            child_ino: ino,
            child_gen: generation,
            file_type,
            name: name.to_string(),
        };

        {
            let mut st = self.state.borrow_mut();
            st.user_modified = true;
            st.mark_dirty(now);
            st.overlay.put(TreeKey::inode_item(ino), item.encode());
            st.overlay
                .put(TreeKey::inode_ref(ino, dir_ino, name), Vec::new());
            st.overlay
                .put(TreeKey::dir_item(dir_ino, name), di.encode());
            st.overlay
                .put(TreeKey::dir_index(dir_ino, dir_index), didx.encode());
            st.overlay
                .put(TreeKey::inode_item(dir_ino), dir_item.encode());
        }
        if acls.access.is_some() || acls.default.is_some() {
            self.stage_encoded_acls(ino, acls);
        } else {
            self.sync_arena_dirty();
        }
        Ok((ino, item))
    }

    async fn load_user_trusted_xattrs(&self, ino: u64) -> Result<BTreeMap<String, Vec<u8>>> {
        let mut out = BTreeMap::new();
        let mut start = TreeKey::kind_start(ino, KIND_XATTR_ITEM);
        let end = TreeKey::kind_end(ino, KIND_XATTR_ITEM);
        loop {
            let batch = self.tree_scan(&start, &end, 128).await?;
            if batch.is_empty() {
                break;
            }
            let last = batch.last().unwrap().0.clone();
            let full = batch.len() == 128;
            for (k, v) in batch {
                let name = String::from_utf8(k.tail).map_err(|_| Errno::EIO)?;
                if name != abi::ACL_ACCESS && name != abi::ACL_DEFAULT {
                    out.insert(name, v);
                }
            }
            if !full {
                break;
            }
            let mut tail = last.tail;
            tail.push(0);
            start = TreeKey::new(last.ino, last.kind, tail);
        }
        Ok(out)
    }

    async fn openable(
        &self,
        cred: &Cred,
        ino: u64,
        item: &InodeItem,
        options: &OpenOptions,
    ) -> Result<Access> {
        let access = options.access()?;
        if access == Access::Path {
            return Ok(access);
        }
        if access.writes() || options.is_truncate() {
            self.check_rw()?;
        }
        let mut mask = access.mask();
        if options.is_truncate() {
            mask |= WRITE;
        }
        let perm = self.load_perm_node(ino, item).await?;
        inode::may_open(&cred.identity, &perm, mask)?;
        Ok(access)
    }
}

struct CowLockWait<'a, H: HeadStore + 'static, P: PackStore + 'static> {
    fs: &'a CowFs<H, P>,
    open: &'a OpenRef,
    family: LockFamily,
    kind: LockKind,
    range: LockRange,
    waiting: Option<u64>,
}

impl<H: HeadStore + 'static, P: PackStore + 'static> Future for CowLockWait<'_, H, P> {
    type Output = Result<()>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        if let Some(id) = self.waiting.take() {
            self.fs.state.borrow_mut().waiters.remove(&id);
        }
        let (family, kind, range) = (self.family, self.kind, self.range);
        match self
            .fs
            .acquire_lock(self.open, family, kind, range, Some(cx.waker()))
        {
            Ok(Some(id)) => {
                self.waiting = Some(id);
                Poll::Pending
            }
            Ok(None) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

impl<H: HeadStore + 'static, P: PackStore + 'static> Drop for CowLockWait<'_, H, P> {
    fn drop(&mut self) {
        if let Some(id) = self.waiting {
            self.fs.state.borrow_mut().waiters.remove(&id);
        }
    }
}

impl<H: HeadStore + 'static, P: PackStore + 'static> Filesystem for CowFs<H, P> {
    fn id(&self) -> &FsId {
        &self.fs_id
    }

    fn capabilities(&self) -> FsCapabilities {
        self.capabilities
    }

    fn root(&self) -> Handle {
        self.handle_for(ROOT_INO, self.root_generation)
    }

    fn lookup<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            let (dir_ino, dir_item) = self.check_handle(dir).await?;
            check_component(name)?;
            self.searchable(cred, dir_ino, &dir_item).await?;
            let di = self
                .lookup_dir_item(dir_ino, name)
                .await?
                .ok_or(Errno::ENOENT)?;
            let child = self.load_inode(di.child_ino).await?.ok_or(Errno::ESTALE)?;
            Ok(self.entry_for(di.child_ino, &child))
        })
    }

    fn walk<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        names: &'a [String],
    ) -> BoxFuture<'a, Walked> {
        Box::pin(async move {
            let (mut cur_ino, mut cur_item) = self.check_handle(dir).await?;
            for name in names {
                check_component(name)?;
            }
            let mut entries = Vec::new();
            for (index, name) in names.iter().enumerate() {
                if index > 0 {
                    let stop = match cur_item.file_type {
                        FileType::Dir => None,
                        FileType::Symlink => Some(Stop::Symlink(index - 1)),
                        _ => Some(Stop::NotDirectory(index - 1)),
                    };
                    if stop.is_some() {
                        return Ok(Walked { entries, stop });
                    }
                }
                self.searchable(cred, cur_ino, &cur_item).await?;
                match self.lookup_dir_item(cur_ino, name).await? {
                    Some(di) => {
                        let child = self.load_inode(di.child_ino).await?.ok_or(Errno::ESTALE)?;
                        entries.push(self.entry_for(di.child_ino, &child));
                        cur_ino = di.child_ino;
                        cur_item = child;
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
        })
    }

    fn parent<'a>(
        &'a self,
        _cred: &'a Cred,
        dir: &'a Handle,
    ) -> BoxFuture<'a, Option<(Entry, String)>> {
        Box::pin(async move {
            let (dir_ino, dir_item) = self.check_handle(dir).await?;
            if dir_item.file_type != FileType::Dir {
                return Err(Errno::ENOTDIR);
            }
            if dir_ino == ROOT_INO {
                return Ok(None);
            }
            if dir_item.nlink == 0 {
                return Err(Errno::ENOENT);
            }
            let refs = self
                .tree_scan(
                    &TreeKey::kind_start(dir_ino, KIND_INODE_REF),
                    &TreeKey::kind_end(dir_ino, KIND_INODE_REF),
                    1,
                )
                .await?;
            let Some((key, _)) = refs.first() else {
                return Err(Errno::ENOENT);
            };
            let Some((parent_ino, name)) = key.tail_inode_ref() else {
                return Err(Errno::EIO);
            };
            let Some(parent_item) = self.load_inode(parent_ino).await? else {
                return Err(Errno::ENOENT);
            };
            Ok(Some((
                self.entry_for(parent_ino, &parent_item),
                name.to_string(),
            )))
        })
    }

    fn metadata<'a>(&'a self, _cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Metadata> {
        Box::pin(async move {
            let (_, item) = self.check_handle(handle).await?;
            Ok(item.to_metadata())
        })
    }

    fn setattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        attr: &'a SetAttr,
    ) -> BoxFuture<'a, Metadata> {
        Box::pin(async move {
            let _op = self.op_lock.lock().await;
            self.check_rw()?;
            let (ino, mut item) = self.check_handle(handle).await?;
            if *attr == SetAttr::default() {
                return Ok(item.to_metadata());
            }
            let who = &cred.identity;
            let orig_perm = self.load_perm_node(ino, &item).await?;
            let mut perm = orig_perm.clone();
            if let Some(mode) = attr.mode {
                inode::chmod(who, &mut perm, mode)?;
            }
            inode::chown(who, &mut perm, attr.uid, attr.gid)?;
            inode::may_set_times(who, &orig_perm, attr.atime, attr.mtime)?;
            if let Some(size) = attr.size {
                match item.file_type {
                    FileType::Dir => return Err(Errno::EISDIR),
                    FileType::File => {}
                    _ => return Err(Errno::EINVAL),
                }
                inode::require(who, &orig_perm, WRITE)?;
                if size > FILE_MAX {
                    return Err(Errno::EFBIG);
                }
                inode::remove_privs(who, &mut perm);
            }
            // Validate & encode ACLs BEFORE mutating overlay or resizing extents.
            let acls = Self::encode_perm_acls(&perm)?;
            let now = (self.clock)();
            if let Some(size) = attr.size {
                self.resize_file_extents(ino, item.size, size, now).await?;
                item.size = size;
                item.mtime = now;
            }
            item.apply_perm_node(&perm);
            self.stage_encoded_acls(ino, acls);
            if let Some((sec, nsec)) = inode::time(attr.atime, (now.sec, now.nsec)) {
                item.atime = Timespec { sec, nsec };
            }
            if let Some((sec, nsec)) = inode::time(attr.mtime, (now.sec, now.nsec)) {
                item.mtime = Timespec { sec, nsec };
            }
            item.ctime = now;
            self.stage_inode(ino, &item);
            Ok(item.to_metadata())
        })
    }

    fn read_dir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle) -> BoxFuture<'a, Vec<DirEntry>> {
        Box::pin(async move {
            let (dir_ino, dir_item) = self.check_handle(dir).await?;
            if dir_item.file_type != FileType::Dir {
                return Err(Errno::ENOTDIR);
            }
            let perm = self.load_perm_node(dir_ino, &dir_item).await?;
            inode::require(&cred.identity, &perm, READ)?;
            if dir_item.nlink == 0 {
                return Err(Errno::ENOENT);
            }
            let mut out = Vec::new();
            let mut start = TreeKey::kind_start(dir_ino, KIND_DIR_ITEM);
            let end = TreeKey::kind_end(dir_ino, KIND_DIR_ITEM);
            loop {
                let batch = self.tree_scan(&start, &end, 512).await?;
                if batch.is_empty() {
                    break;
                }
                let last = batch.last().unwrap().0.clone();
                let full = batch.len() == 512;
                for (k, v) in batch {
                    let di = DirItemValue::decode(&v)?;
                    let name = String::from_utf8(k.tail).map_err(|_| Errno::EIO)?;
                    out.push(DirEntry {
                        name,
                        node: NodeId {
                            ino: di.child_ino,
                            generation: di.child_gen,
                        },
                        file_type: di.file_type,
                    });
                }
                if !full {
                    break;
                }
                let mut tail = last.tail;
                tail.push(0);
                start = TreeKey::new(last.ino, last.kind, tail);
            }
            self.update_atime_if_needed(dir_ino, dir_item.generation, &dir_item, true)
                .await;
            Ok(out)
        })
    }

    /// Native O(log N + page) paged enumeration directly over `0x21` `DIR_INDEX` keys!
    /// Never loads the full directory into memory — enumerates 100k+ entries cleanly inside the
    /// `32 MiB` wasm32 slab arena.
    fn read_dir_page<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        cookie: u64,
        max_entries: usize,
    ) -> BoxFuture<'a, DirPage> {
        Box::pin(async move {
            let (dir_ino, dir_item) = self.check_handle(dir).await?;
            if dir_item.file_type != FileType::Dir {
                return Err(Errno::ENOTDIR);
            }
            let perm = self.load_perm_node(dir_ino, &dir_item).await?;
            inode::require(&cred.identity, &perm, READ)?;
            if dir_item.nlink == 0 {
                return Err(Errno::ENOENT);
            }

            let start = TreeKey::dir_index(dir_ino, cookie);
            let end = TreeKey::kind_end(dir_ino, KIND_DIR_INDEX);

            if max_entries == 0 {
                let peek = self.tree_scan(&start, &end, 1).await?;
                let next_cookie = peek.first().and_then(|(k, _)| k.tail_u64());
                self.update_atime_if_needed(dir_ino, dir_item.generation, &dir_item, true)
                    .await;
                return Ok(DirPage {
                    entries: Vec::new(),
                    next_cookie,
                });
            }

            let limit = max_entries.min(DIR_PAGE_MAX);
            let batch = self.tree_scan(&start, &end, limit + 1).await?;
            let has_more = batch.len() > limit;
            let next_cookie = if has_more {
                batch[limit].0.tail_u64()
            } else {
                None
            };
            let mut entries = Vec::with_capacity(batch.len().min(limit));
            for (_, raw) in batch.into_iter().take(limit) {
                let dv = DirIndexValue::decode(&raw)?;
                entries.push(DirEntry {
                    name: dv.name,
                    node: NodeId {
                        ino: dv.child_ino,
                        generation: dv.child_gen,
                    },
                    file_type: dv.file_type,
                });
            }
            self.update_atime_if_needed(dir_ino, dir_item.generation, &dir_item, true)
                .await;
            Ok(DirPage {
                entries,
                next_cookie,
            })
        })
    }

    fn read_link<'a>(&'a self, _cred: &'a Cred, link: &'a Handle) -> BoxFuture<'a, String> {
        Box::pin(async move {
            let (ino, item) = self.check_handle(link).await?;
            let target = item.symlink_target.clone().ok_or(Errno::EINVAL)?;
            self.update_atime_if_needed(ino, item.generation, &item, false)
                .await;
            Ok(target)
        })
    }

    fn create<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        options: &'a OpenOptions,
    ) -> BoxFuture<'a, (Entry, OpenRef)> {
        Box::pin(async move {
            let _op = self.op_lock.lock().await;
            self.check_rw()?;
            let access = options.access()?;
            if matches!(access, Access::Exec | Access::Path) {
                return Err(Errno::EINVAL);
            }
            let (dir_ino, mut dir_item) = self.check_handle(dir).await?;
            check_component(name)?;
            let parent_perm = self.searchable(cred, dir_ino, &dir_item).await?;
            if let Some(di) = self.lookup_dir_item(dir_ino, name).await? {
                if options.is_create_new() {
                    return Err(Errno::EEXIST);
                }
                let mut existing = self.load_inode(di.child_ino).await?.ok_or(Errno::ESTALE)?;
                if existing.file_type == FileType::Dir {
                    return Err(Errno::EISDIR);
                }
                self.openable(cred, di.child_ino, &existing, options)
                    .await?;
                if options.is_truncate() && existing.file_type == FileType::File {
                    let now = (self.clock)();
                    self.resize_file(di.child_ino, &mut existing, 0, &cred.identity, now)
                        .await?;
                }
                let open = self.new_open(cred, di.child_ino, existing.generation, access);
                return Ok((self.entry_for(di.child_ino, &existing), open));
            }

            inode::may_create(&cred.identity, &parent_perm, dir_item.nlink == 0)?;
            let node = created(&cred.identity, &parent_perm, mode, false, cred.umask);
            let (ino, item) = self
                .add_node_in_dir(dir_ino, &mut dir_item, name, node)
                .await?;
            let open = self.new_open(cred, ino, item.generation, access);
            Ok((self.entry_for(ino, &item), open))
        })
    }

    fn mkdir<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            let _op = self.op_lock.lock().await;
            self.check_rw()?;
            let (dir_ino, mut dir_item) = self.check_handle(dir).await?;
            check_component(name)?;
            let parent_perm = self.searchable(cred, dir_ino, &dir_item).await?;
            if self.lookup_dir_item(dir_ino, name).await?.is_some() {
                return Err(Errno::EEXIST);
            }
            inode::may_create(&cred.identity, &parent_perm, dir_item.nlink == 0)?;
            let node = created(&cred.identity, &parent_perm, mode, true, cred.umask);
            let (ino, item) = self
                .add_node_in_dir(dir_ino, &mut dir_item, name, node)
                .await?;
            Ok(self.entry_for(ino, &item))
        })
    }

    fn mknod<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        rdev: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            let _op = self.op_lock.lock().await;
            self.check_rw()?;
            if cred.identity.id != 0 {
                return Err(Errno::EPERM);
            }
            let (dir_ino, mut dir_item) = self.check_handle(dir).await?;
            check_component(name)?;
            let parent_perm = self.searchable(cred, dir_ino, &dir_item).await?;
            if self.lookup_dir_item(dir_ino, name).await?.is_some() {
                return Err(Errno::EEXIST);
            }
            inode::may_create(&cred.identity, &parent_perm, dir_item.nlink == 0)?;
            let mut node = created(&cred.identity, &parent_perm, mode, false, cred.umask);
            node.rdev = Some(rdev.to_string());
            let (ino, item) = self
                .add_node_in_dir(dir_ino, &mut dir_item, name, node)
                .await?;
            Ok(self.entry_for(ino, &item))
        })
    }

    fn symlink<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        target: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            let _op = self.op_lock.lock().await;
            self.check_rw()?;
            inode::check_link_target(target)?;
            let (dir_ino, mut dir_item) = self.check_handle(dir).await?;
            check_component(name)?;
            let parent_perm = self.searchable(cred, dir_ino, &dir_item).await?;
            if self.lookup_dir_item(dir_ino, name).await?.is_some() {
                return Err(Errno::EEXIST);
            }
            inode::may_create(&cred.identity, &parent_perm, dir_item.nlink == 0)?;
            let node = inode::new_symlink(&cred.identity, &parent_perm, target);
            let (ino, item) = self
                .add_node_in_dir(dir_ino, &mut dir_item, name, node)
                .await?;
            Ok(self.entry_for(ino, &item))
        })
    }

    fn link<'a>(
        &'a self,
        cred: &'a Cred,
        target: &'a Handle,
        dir: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            let _op = self.op_lock.lock().await;
            self.check_rw()?;
            let (target_ino, mut target_item) = self.check_handle(target).await?;
            let (dir_ino, mut dir_item) = self.check_handle(dir).await?;
            check_component(name)?;
            let parent_perm = self.searchable(cred, dir_ino, &dir_item).await?;
            if self.lookup_dir_item(dir_ino, name).await?.is_some() {
                return Err(Errno::EEXIST);
            }
            let target_perm = self.load_perm_node(target_ino, &target_item).await?;
            inode::may_link(&cred.identity, &target_perm)?;
            inode::may_create(&cred.identity, &parent_perm, dir_item.nlink == 0)?;
            if target_item.nlink == 0 {
                return Err(Errno::ENOENT);
            }
            self.maybe_backpressure_flush(512).await?;
            let now = (self.clock)();
            let dir_index = dir_item.next_dir_index;
            dir_item.next_dir_index = dir_item.next_dir_index.saturating_add(1);
            dir_item.mtime = now;
            dir_item.ctime = now;
            target_item.nlink = target_item.nlink.saturating_add(1);
            target_item.ctime = now;

            let di = DirItemValue {
                child_ino: target_ino,
                child_gen: target_item.generation,
                file_type: target_item.file_type,
                dir_index,
            };
            let didx = DirIndexValue {
                child_ino: target_ino,
                child_gen: target_item.generation,
                file_type: target_item.file_type,
                name: name.to_string(),
            };
            {
                let mut st = self.state.borrow_mut();
                st.user_modified = true;
                st.mark_dirty(now);
                st.overlay
                    .put(TreeKey::dir_item(dir_ino, name), di.encode());
                st.overlay
                    .put(TreeKey::dir_index(dir_ino, dir_index), didx.encode());
                st.overlay
                    .put(TreeKey::inode_ref(target_ino, dir_ino, name), Vec::new());
                st.overlay
                    .put(TreeKey::inode_item(dir_ino), dir_item.encode());
                st.overlay
                    .put(TreeKey::inode_item(target_ino), target_item.encode());
            }
            self.sync_arena_dirty();
            Ok(self.entry_for(target_ino, &target_item))
        })
    }

    fn unlink<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move { self.do_remove(cred, dir, name, false, None).await })
    }

    fn unlink_if<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        node: NodeId,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move { self.do_remove(cred, dir, name, false, Some(node)).await })
    }

    fn rmdir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move { self.do_remove(cred, dir, name, true, None).await })
    }

    fn rename<'a>(
        &'a self,
        cred: &'a Cred,
        from_dir: &'a Handle,
        from: &'a str,
        to_dir: &'a Handle,
        to: &'a str,
        flags: RenameFlags,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let _op = self.op_lock.lock().await;
            self.check_rw()?;
            let who = &cred.identity;
            let (from_dir_ino, mut from_dir_item) = self.check_handle(from_dir).await?;
            let (to_dir_ino, mut to_dir_item) = self.check_handle(to_dir).await?;
            check_component(from)?;
            check_component(to)?;
            let from_perm = self.searchable(cred, from_dir_ino, &from_dir_item).await?;
            let to_perm = self.searchable(cred, to_dir_ino, &to_dir_item).await?;

            let src_di = self
                .lookup_dir_item(from_dir_ino, from)
                .await?
                .ok_or(Errno::ENOENT)?;
            let dst_di = self.lookup_dir_item(to_dir_ino, to).await?;
            if dst_di.is_some() && flags.contains(RenameFlags::NOREPLACE) {
                return Err(Errno::EEXIST);
            }
            if dst_di.is_some_and(|d| d.child_ino == src_di.child_ino) {
                return Ok(());
            }

            let mut src_item = self
                .load_inode(src_di.child_ino)
                .await?
                .ok_or(Errno::ESTALE)?;
            let moving_dir = src_item.file_type == FileType::Dir;
            if moving_dir && self.is_ancestor(src_di.child_ino, to_dir_ino).await? {
                return Err(Errno::EINVAL);
            }
            let src_perm = self.load_perm_node(src_di.child_ino, &src_item).await?;
            inode::may_delete(who, &from_perm, &src_perm)?;

            let mut target_opt = None;
            match dst_di {
                Some(tdi) => {
                    let target_item = self.load_inode(tdi.child_ino).await?.ok_or(Errno::ESTALE)?;
                    let target_perm = self.load_perm_node(tdi.child_ino, &target_item).await?;
                    inode::may_delete(who, &to_perm, &target_perm)?;
                    match (moving_dir, target_item.file_type == FileType::Dir) {
                        (true, false) => return Err(Errno::ENOTDIR),
                        (false, true) => return Err(Errno::EISDIR),
                        _ => {}
                    }
                    if target_item.file_type == FileType::Dir
                        && !self.dir_is_empty(tdi.child_ino).await?
                    {
                        return Err(Errno::ENOTEMPTY);
                    }
                    target_opt = Some((tdi, target_item));
                }
                None => {
                    inode::may_create(who, &to_perm, to_dir_item.nlink == 0)?;
                }
            }
            if moving_dir && from_dir_ino != to_dir_ino {
                inode::require(who, &src_perm, WRITE)?;
            }

            self.maybe_backpressure_flush(1024).await?;
            let now = (self.clock)();

            // Handle replaced target (if any).
            if let Some((tdi, mut target_item)) = target_opt {
                {
                    let mut st = self.state.borrow_mut();
                    st.user_modified = true;
                    st.mark_dirty(now);
                    st.overlay.delete(TreeKey::dir_item(to_dir_ino, to));
                    st.overlay
                        .delete(TreeKey::dir_index(to_dir_ino, tdi.dir_index));
                    st.overlay
                        .delete(TreeKey::inode_ref(tdi.child_ino, to_dir_ino, to));
                }
                if moving_dir {
                    to_dir_item.nlink = to_dir_item.nlink.saturating_sub(1);
                    target_item.nlink = 0;
                } else {
                    target_item.nlink = target_item.nlink.saturating_sub(1);
                }
                target_item.ctime = now;
                self.stage_inode(tdi.child_ino, &target_item);
                self.reclaim_if_dead_locked(tdi.child_ino, &target_item)
                    .await?;
            }

            // Reload `from_dir_item` / `to_dir_item` cleanly if they are the same directory.
            let same_dir = from_dir_ino == to_dir_ino;
            if same_dir {
                from_dir_item.nlink = to_dir_item.nlink;
            }
            let new_dir_index = if same_dir {
                let idx = from_dir_item.next_dir_index;
                from_dir_item.next_dir_index = idx.saturating_add(1);
                idx
            } else {
                let idx = to_dir_item.next_dir_index;
                to_dir_item.next_dir_index = idx.saturating_add(1);
                idx
            };

            if moving_dir && !same_dir {
                from_dir_item.nlink = from_dir_item.nlink.saturating_sub(1);
                to_dir_item.nlink = to_dir_item.nlink.saturating_add(1);
            }
            from_dir_item.mtime = now;
            from_dir_item.ctime = now;
            to_dir_item.mtime = now;
            to_dir_item.ctime = now;
            src_item.ctime = now;

            let new_di = DirItemValue {
                child_ino: src_di.child_ino,
                child_gen: src_item.generation,
                file_type: src_item.file_type,
                dir_index: new_dir_index,
            };
            let new_didx = DirIndexValue {
                child_ino: src_di.child_ino,
                child_gen: src_item.generation,
                file_type: src_item.file_type,
                name: to.to_string(),
            };
            {
                let mut st = self.state.borrow_mut();
                st.user_modified = true;
                st.mark_dirty(now);
                st.overlay.delete(TreeKey::dir_item(from_dir_ino, from));
                st.overlay
                    .delete(TreeKey::dir_index(from_dir_ino, src_di.dir_index));
                st.overlay
                    .delete(TreeKey::inode_ref(src_di.child_ino, from_dir_ino, from));

                st.overlay
                    .put(TreeKey::dir_item(to_dir_ino, to), new_di.encode());
                st.overlay.put(
                    TreeKey::dir_index(to_dir_ino, new_dir_index),
                    new_didx.encode(),
                );
                st.overlay.put(
                    TreeKey::inode_ref(src_di.child_ino, to_dir_ino, to),
                    Vec::new(),
                );

                st.overlay
                    .put(TreeKey::inode_item(from_dir_ino), from_dir_item.encode());
                if !same_dir {
                    st.overlay
                        .put(TreeKey::inode_item(to_dir_ino), to_dir_item.encode());
                }
                st.overlay
                    .put(TreeKey::inode_item(src_di.child_ino), src_item.encode());
            }
            self.sync_arena_dirty();
            Ok(())
        })
    }

    fn getxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let space = xattr::space(name)?;
            let (ino, item) = self.check_handle(handle).await?;
            let perm = self.load_perm_node(ino, &item).await?;
            xattr::readable(&cred.identity, &perm, space)?;
            match space {
                Space::Access | Space::Default => {
                    let entries = xattr::acl(&perm, space)?;
                    Ok(serde_json::to_vec(&entries).unwrap_or_default())
                }
                Space::User | Space::Trusted => self
                    .tree_get(&TreeKey::xattr_item(ino, name))
                    .await?
                    .ok_or(Errno::ENODATA),
            }
        })
    }

    fn setxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
        value: &'a [u8],
        flags: XattrFlags,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let _op = self.op_lock.lock().await;
            self.check_rw()?;
            let space = xattr::space(name)?;
            let (ino, mut item) = self.check_handle(handle).await?;
            let mut perm = self.load_perm_node(ino, &item).await?;
            xattr::settable(&cred.identity, &perm, space)?;
            match space {
                Space::Access | Space::Default => {
                    xattr::check_flags(flags.bits(), xattr::has_acl(&perm, space))?;
                    if value.len() > xattr::VALUE_MAX * 4 {
                        return Err(Errno::E2BIG);
                    }
                    let entries: Entries =
                        serde_json::from_slice(value).map_err(|_| Errno::EINVAL)?;
                    xattr::set_acl(&cred.identity, &mut perm, space, entries)?;
                    // Enforce `xattr::VALUE_MAX` BEFORE mutating `item` or `st.overlay`!
                    let acls = Self::encode_perm_acls(&perm)?;
                    let est = acls.access.as_ref().map_or(0, Vec::len)
                        + acls.default.as_ref().map_or(0, Vec::len)
                        + 128;
                    self.maybe_backpressure_flush(est).await?;
                    item.apply_perm_node(&perm);
                    self.stage_encoded_acls(ino, acls);
                }
                Space::User | Space::Trusted => {
                    let mut attrs = self.load_user_trusted_xattrs(ino).await?;
                    xattr::check_flags(flags.bits(), attrs.contains_key(name))?;
                    xattr::store(&mut attrs, name, value)?;
                    self.maybe_backpressure_flush(name.len() + value.len() + 64)
                        .await?;
                    let now = (self.clock)();
                    {
                        let mut st = self.state.borrow_mut();
                        st.user_modified = true;
                        st.mark_dirty(now);
                        st.overlay
                            .put(TreeKey::xattr_item(ino, name), value.to_vec());
                    }
                }
            }
            item.ctime = (self.clock)();
            self.stage_inode(ino, &item);
            Ok(())
        })
    }

    fn listxattr<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Vec<String>> {
        Box::pin(async move {
            let (ino, item) = self.check_handle(handle).await?;
            let perm = self.load_perm_node(ino, &item).await?;
            let attrs = self.load_user_trusted_xattrs(ino).await?;
            Ok(xattr::listed(&cred.identity, &perm, attrs.keys()))
        })
    }

    fn removexattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let _op = self.op_lock.lock().await;
            self.check_rw()?;
            let space = xattr::space(name)?;
            let (ino, mut item) = self.check_handle(handle).await?;
            let mut perm = self.load_perm_node(ino, &item).await?;
            xattr::settable(&cred.identity, &perm, space)?;
            match space {
                Space::Access | Space::Default => {
                    xattr::remove_acl(&mut perm, space)?;
                    let acls = Self::encode_perm_acls(&perm)?;
                    item.apply_perm_node(&perm);
                    self.stage_encoded_acls(ino, acls);
                }
                Space::User | Space::Trusted => {
                    if self
                        .tree_get(&TreeKey::xattr_item(ino, name))
                        .await?
                        .is_none()
                    {
                        return Err(Errno::ENODATA);
                    }
                    let now = (self.clock)();
                    {
                        let mut st = self.state.borrow_mut();
                        st.user_modified = true;
                        st.mark_dirty(now);
                        st.overlay.delete(TreeKey::xattr_item(ino, name));
                    }
                }
            }
            item.ctime = (self.clock)();
            self.stage_inode(ino, &item);
            Ok(())
        })
    }

    fn statfs<'a>(&'a self, _cred: &'a Cred) -> BoxFuture<'a, StatFs> {
        Box::pin(async move {
            let st = self.state.borrow();
            if st.closed {
                return Err(Errno::EBADF);
            }
            let blk_size = u64::from(BLOCK_SIZE);
            let total_bytes = self.capacity_bytes.unwrap_or(1024 * 1024 * 1024);
            let blocks = total_bytes.div_ceil(blk_size);
            let used_blocks = st.allocated_bytes.div_ceil(blk_size);
            Ok(StatFs {
                block_size: blk_size,
                blocks,
                blocks_free: blocks.saturating_sub(used_blocks),
                files: st.inode_count,
                files_free: u64::MAX.saturating_sub(st.root_obj.next_ino),
                name_max: abi::NAME_MAX as u64,
            })
        })
    }

    fn open<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        options: &'a OpenOptions,
    ) -> BoxFuture<'a, OpenRef> {
        Box::pin(async move {
            let _op = if options.is_truncate() {
                Some(self.op_lock.lock().await)
            } else {
                None
            };
            let (ino, mut item) = self.check_handle(handle).await?;
            let access = self.openable(cred, ino, &item, options).await?;
            if access != Access::Path && options.is_truncate() && item.file_type == FileType::File {
                let now = (self.clock)();
                self.resize_file(ino, &mut item, 0, &cred.identity, now)
                    .await?;
            }
            Ok(self.new_open(cred, ino, item.generation, access))
        })
    }

    fn open_metadata<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, Metadata> {
        Box::pin(async move {
            let (ino, generation, _, _) = self.open_record_clone(open)?;
            let item = self.load_inode(ino).await?.ok_or(Errno::ESTALE)?;
            if item.generation != generation {
                return Err(Errno::ESTALE);
            }
            Ok(item.to_metadata())
        })
    }

    fn read_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a mut [u8],
        offset: u64,
    ) -> BoxFuture<'a, usize> {
        Box::pin(async move {
            let (ino, generation, access, _) = self.open_record_clone(open)?;
            if !access.reads() {
                return Err(Errno::EBADF);
            }
            let item = self.load_inode(ino).await?.ok_or(Errno::ESTALE)?;
            if item.generation != generation {
                return Err(Errno::ESTALE);
            }
            match item.file_type {
                FileType::File => {}
                FileType::Dir => return Err(Errno::EISDIR),
                _ => return Err(Errno::ENXIO),
            }
            if offset > FILE_MAX || buf.len() as u64 > FILE_MAX - offset {
                return Err(Errno::EINVAL);
            }
            let len = buf.len().min(RW_MAX);
            let n = self
                .read_file_bytes(ino, item.size, offset, &mut buf[..len])
                .await?;
            self.update_atime_if_needed(ino, generation, &item, false)
                .await;
            Ok(n)
        })
    }

    fn write_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a [u8],
        at: WriteAt,
    ) -> BoxFuture<'a, Written> {
        Box::pin(async move {
            let _op = self.op_lock.lock().await;
            self.check_rw()?;
            let (ino, generation, access, writer) = self.open_record_clone(open)?;
            if !access.writes() {
                return Err(Errno::EBADF);
            }
            let mut item = self.load_inode(ino).await?.ok_or(Errno::ESTALE)?;
            if item.generation != generation {
                return Err(Errno::ESTALE);
            }
            match item.file_type {
                FileType::File => {}
                FileType::Dir => return Err(Errno::EISDIR),
                _ => return Err(Errno::ENXIO),
            }
            let offset = match at {
                WriteAt::Offset(off) => off,
                WriteAt::End => item.size,
            };
            if buf.is_empty() {
                return Ok(Written { offset, len: 0 });
            }
            if offset >= FILE_MAX {
                return Err(Errno::EFBIG);
            }
            let room = usize::try_from(FILE_MAX - offset).unwrap_or(usize::MAX);
            let len = buf.len().min(room).min(RW_MAX);

            // Compute privilege-stripped mode BEFORE `write_file_bytes` so any intermediate
            // backpressure commit strips `S_ISUID`/`S_ISGID` before persisting modified blocks.
            let mut perm = self.load_perm_node(ino, &item).await?;
            inode::remove_privs(&writer, &mut perm);
            let mut stripped_item = item.clone();
            stripped_item.apply_perm_node(&perm);
            let stripped_mode = stripped_item.mode;
            let now = (self.clock)();

            let written = self
                .write_file_bytes(ino, &mut item, offset, &buf[..len], stripped_mode, now)
                .await?;
            if written > 0 {
                item.mode = stripped_mode;
                let finish_now = (self.clock)();
                item.mtime = finish_now;
                item.ctime = finish_now;
                self.stage_inode(ino, &item);
            }
            Ok(Written {
                offset,
                len: written,
            })
        })
    }

    fn set_len<'a>(&'a self, open: &'a OpenRef, size: u64) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let _op = self.op_lock.lock().await;
            let (ino, generation, access, writer) = self.open_record_clone(open)?;
            if access == Access::Path {
                return Err(Errno::EBADF);
            }
            self.check_rw()?;
            let mut item = self.load_inode(ino).await?.ok_or(Errno::ESTALE)?;
            if item.generation != generation {
                return Err(Errno::ESTALE);
            }
            if !access.writes() || item.file_type != FileType::File {
                return Err(Errno::EINVAL);
            }
            if size > FILE_MAX {
                return Err(Errno::EFBIG);
            }
            let now = (self.clock)();
            self.resize_file(ino, &mut item, size, &writer, now).await
        })
    }

    fn sync_all<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let (_, _, access, _) = self.open_record_clone(open)?;
            if access == Access::Path {
                return Err(Errno::EBADF);
            }
            if self.read_only {
                return Ok(());
            }
            self.commit_tx_group().await.map(|_| ())
        })
    }

    fn sync_fs<'a>(&'a self, _cred: &'a Cred) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if self.read_only {
                if self.state.borrow().closed {
                    return Err(Errno::EBADF);
                }
                return Ok(());
            }
            self.commit_tx_group().await.map(|_| ())
        })
    }

    /// Intra-volume O(extents) extent clone (`FICLONE`, contract §5, Blueprint §3.2): copies
    /// `EXTENT_DATA` B+tree references with ZERO data bytes written to `PackStore`.
    /// Read-verifies all `src` and `dst` extents BEFORE mutating `dst`, using a single overlay
    /// snapshot (no O(N²) overlay cloning) and arena backpressure for very large files.
    fn reflink<'a>(
        &'a self,
        _cred: &'a Cred,
        src_open: &'a OpenRef,
        dst_open: &'a OpenRef,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if src_open.fs != self.fs_id || dst_open.fs != self.fs_id {
                return Err(Errno::EXDEV);
            }
            let _op = self.op_lock.lock().await;
            self.check_rw()?;
            let (src_ino, src_gen, src_acc, _) = self.open_record_clone(src_open)?;
            let (dst_ino, dst_gen, dst_acc, writer) = self.open_record_clone(dst_open)?;
            if !src_acc.reads() || !dst_acc.writes() {
                return Err(Errno::EBADF);
            }
            let src_item = self.load_inode(src_ino).await?.ok_or(Errno::ESTALE)?;
            let mut dst_item = self.load_inode(dst_ino).await?.ok_or(Errno::ESTALE)?;
            if src_item.generation != src_gen || dst_item.generation != dst_gen {
                return Err(Errno::ESTALE);
            }
            if src_item.file_type == FileType::Dir || dst_item.file_type == FileType::Dir {
                return Err(Errno::EISDIR);
            }
            if src_item.file_type != FileType::File || dst_item.file_type != FileType::File {
                return Err(Errno::EINVAL);
            }
            if src_ino == dst_ino {
                return Ok(());
            }

            let mut dst_perm = self.load_perm_node(dst_ino, &dst_item).await?;
            inode::remove_privs(&writer, &mut dst_perm);

            // Take ONE read-only `(base_root, read_overlay)` snapshot for the verification pass.
            let (base_root, read_overlay) = {
                let st = self.state.borrow();
                (st.subvol_root, st.combined_read_overlay())
            };
            let tree = CowTree::new(&*self.head_store, &self.arena);

            let mut streaming = false;
            let mut src_extent_bytes = 0u64;
            let mut dst_extent_bytes = 0u64;
            let mut estimated_overlay_bytes = 0usize;
            let mut src_entries: Vec<(TreeKey, Vec<u8>, Option<Digest>)> = Vec::new();
            let mut dst_deletes: Vec<(TreeKey, Option<Digest>)> = Vec::new();

            // 1. Read-only verification pass over ALL `src` extents BEFORE touching `dst`.
            let mut s_start = TreeKey::kind_start(src_ino, KIND_EXTENT_DATA);
            let s_end = TreeKey::kind_end(src_ino, KIND_EXTENT_DATA);
            loop {
                let batch = tree
                    .scan_range_with_overlay(&base_root, &read_overlay, &s_start, &s_end, 256)
                    .await?;
                if batch.is_empty() {
                    break;
                }
                let last = batch.last().unwrap().0.clone();
                let full = batch.len() == 256;
                for (k, raw) in batch {
                    let dig = match ExtentDataValue::decode(&raw)? {
                        ExtentDataValue::Extent { len, digest, .. } => {
                            src_extent_bytes = src_extent_bytes.saturating_add(u64::from(len));
                            Some(digest)
                        }
                        ExtentDataValue::Inline(_) => None,
                    };
                    estimated_overlay_bytes =
                        estimated_overlay_bytes.saturating_add(k.tail.len() + 11 + raw.len() + 32);
                    if !streaming {
                        if self
                            .arena
                            .borrow()
                            .needs_backpressure_flush(estimated_overlay_bytes.saturating_mul(2))
                        {
                            streaming = true;
                            src_entries.clear();
                        } else {
                            src_entries.push((k, raw, dig));
                        }
                    }
                }
                if !full {
                    break;
                }
                let mut tail = last.tail;
                tail.push(0);
                s_start = TreeKey::new(last.ino, last.kind, tail);
            }

            // 2. Read-only verification pass over ALL `dst` extents BEFORE touching `dst`.
            let mut d_start = TreeKey::kind_start(dst_ino, KIND_EXTENT_DATA);
            let d_end = TreeKey::kind_end(dst_ino, KIND_EXTENT_DATA);
            loop {
                let batch = tree
                    .scan_range_with_overlay(&base_root, &read_overlay, &d_start, &d_end, 256)
                    .await?;
                if batch.is_empty() {
                    break;
                }
                let last = batch.last().unwrap().0.clone();
                let full = batch.len() == 256;
                for (k, raw) in batch {
                    let dig = match ExtentDataValue::decode(&raw)? {
                        ExtentDataValue::Extent { len, digest, .. } => {
                            dst_extent_bytes = dst_extent_bytes.saturating_add(u64::from(len));
                            Some(digest)
                        }
                        ExtentDataValue::Inline(_) => None,
                    };
                    estimated_overlay_bytes =
                        estimated_overlay_bytes.saturating_add(k.tail.len() + 11 + 32);
                    if !streaming {
                        if self
                            .arena
                            .borrow()
                            .needs_backpressure_flush(estimated_overlay_bytes.saturating_mul(2))
                        {
                            streaming = true;
                            src_entries.clear();
                            dst_deletes.clear();
                        } else {
                            dst_deletes.push((k, dig));
                        }
                    }
                }
                if !full {
                    break;
                }
                let mut tail = last.tail;
                tail.push(0);
                d_start = TreeKey::new(last.ino, last.kind, tail);
            }
            drop(read_overlay);

            if let Some(cap) = self.capacity_bytes {
                let cur = self.state.borrow().allocated_bytes;
                let projected = cur
                    .saturating_sub(dst_extent_bytes)
                    .saturating_add(src_extent_bytes);
                if projected > cap {
                    return Err(Errno::ENOSPC);
                }
            }

            let now = (self.clock)();
            if !streaming {
                // Fast atomic path: flush pre-existing dirty state if needed, then apply all
                // `dst` deletes + `src` clones + `dst_item` in one synchronous block.
                self.maybe_backpressure_flush(estimated_overlay_bytes.saturating_add(512))
                    .await?;
                dst_item.apply_perm_node(&dst_perm);
                dst_item.size = src_item.size;
                dst_item.mtime = now;
                dst_item.ctime = now;
                {
                    let mut st = self.state.borrow_mut();
                    st.user_modified = true;
                    st.mark_dirty(now);
                    for (k, dig) in dst_deletes {
                        if let Some(d) = dig {
                            st.unstage_dirty_block(&d);
                        }
                        st.overlay.delete(k);
                    }
                    for (k, raw, dig) in src_entries {
                        if let Some(d) = dig
                            && let Some(bytes) = st.dirty_block_bytes(&d)
                        {
                            st.stage_dirty_block(d, bytes);
                        }
                        let dst_key = TreeKey::new(dst_ino, KIND_EXTENT_DATA, k.tail);
                        st.overlay.put(dst_key, raw);
                    }
                    st.allocated_bytes = st
                        .allocated_bytes
                        .saturating_sub(dst_extent_bytes)
                        .saturating_add(src_extent_bytes);
                    st.overlay
                        .put(TreeKey::inode_item(dst_ino), dst_item.encode());
                }
                self.sync_arena_dirty();
                return Ok(());
            }

            // Streaming path for huge files whose extent metadata exceeds half the dirty slab
            // budget: commit any pre-existing dirty state so both `src` and `dst` live cleanly
            // in `st.subvol_root` (zero overlay cloning!), then stream deletes & clones with
            // arena backpressure flushes.
            self.commit_tx_group_with_lock_mode(true).await?;

            // Delete existing `dst` extents in bounded batches directly from committed root.
            let mut cur_root = self.state.borrow().subvol_root;
            let mut d_start = TreeKey::kind_start(dst_ino, KIND_EXTENT_DATA);
            loop {
                let batch = tree.scan_range(&cur_root, &d_start, &d_end, 256).await?;
                if batch.is_empty() {
                    break;
                }
                let last = batch.last().unwrap().0.clone();
                let full = batch.len() == 256;
                let batch_bytes: usize = batch.iter().map(|(k, _)| k.tail.len() + 11 + 32).sum();
                self.maybe_backpressure_flush(batch_bytes).await?;
                {
                    let mut st = self.state.borrow_mut();
                    st.user_modified = true;
                    st.mark_dirty(now);
                    for (k, raw) in batch {
                        if let Ok(ExtentDataValue::Extent { len, digest, .. }) =
                            ExtentDataValue::decode(&raw)
                        {
                            st.unstage_dirty_block(&digest);
                            st.allocated_bytes = st.allocated_bytes.saturating_sub(u64::from(len));
                        }
                        st.overlay.delete(k);
                    }
                }
                self.sync_arena_dirty();
                if !full {
                    break;
                }
                let mut tail = last.tail;
                tail.push(0);
                d_start = TreeKey::new(last.ino, last.kind, tail);
                cur_root = self.state.borrow().subvol_root;
            }

            // Clone `src` extents in bounded batches directly from `st.subvol_root` (`src_ino` is
            // untouched, so every committed `cur_root` contains identical `src` extents).
            cur_root = self.state.borrow().subvol_root;
            let mut s_start = TreeKey::kind_start(src_ino, KIND_EXTENT_DATA);
            loop {
                let batch = tree.scan_range(&cur_root, &s_start, &s_end, 256).await?;
                if batch.is_empty() {
                    break;
                }
                let last = batch.last().unwrap().0.clone();
                let full = batch.len() == 256;
                let batch_bytes: usize = batch
                    .iter()
                    .map(|(k, v)| k.tail.len() + 11 + v.len() + 32)
                    .sum();
                self.maybe_backpressure_flush(batch_bytes).await?;
                {
                    let mut st = self.state.borrow_mut();
                    st.user_modified = true;
                    st.mark_dirty(now);
                    for (k, raw) in batch {
                        if let Ok(ExtentDataValue::Extent { len, .. }) =
                            ExtentDataValue::decode(&raw)
                        {
                            st.allocated_bytes = st.allocated_bytes.saturating_add(u64::from(len));
                        }
                        let dst_key = TreeKey::new(dst_ino, KIND_EXTENT_DATA, k.tail);
                        st.overlay.put(dst_key, raw);
                    }
                }
                self.sync_arena_dirty();
                if !full {
                    break;
                }
                let mut tail = last.tail;
                tail.push(0);
                s_start = TreeKey::new(last.ino, last.kind, tail);
                cur_root = self.state.borrow().subvol_root;
            }

            dst_item.apply_perm_node(&dst_perm);
            dst_item.size = src_item.size;
            let finish_now = (self.clock)();
            dst_item.mtime = finish_now;
            dst_item.ctime = finish_now;
            self.stage_inode(dst_ino, &dst_item);
            Ok(())
        })
    }

    fn lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        Box::pin(CowLockWait {
            fs: self,
            open,
            family,
            kind,
            range,
            waiting: None,
        })
    }

    fn try_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.acquire_lock(open, family, kind, range, None)
                .map(|_| ())
        })
    }

    fn unlock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let ino = self.lockable(open, family, None, range)?;
            {
                let mut st = self.state.borrow_mut();
                if let Some(locks) = st.locks.get_mut(&ino) {
                    carve(locks, open.id, family, range);
                }
            }
            self.wake_lock_waiters(ino);
            Ok(())
        })
    }

    fn test_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, Option<Conflict>> {
        Box::pin(async move {
            let ino = self.lockable(open, LockFamily::Posix, None, range)?;
            let st = self.state.borrow();
            Ok(Self::conflict(
                &st,
                ino,
                open.id,
                LockFamily::Posix,
                kind,
                range,
            ))
        })
    }

    fn release<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let _op = if !self.read_only {
                Some(self.op_lock.lock().await)
            } else {
                None
            };
            if open.fs != self.fs_id {
                return Err(Errno::EBADF);
            }
            let (ino, should_reclaim) = {
                let mut st = self.state.borrow_mut();
                let rec = st.opens.get(&open.id).ok_or(Errno::EBADF)?;
                if rec.ino != open.node.ino || rec.generation != open.node.generation {
                    return Err(Errno::EBADF);
                }
                let ino = rec.ino;
                st.opens.remove(&open.id);
                if let Some(locks) = st.locks.get_mut(&ino) {
                    locks.retain(|l| l.owner != open.id);
                }
                let mut remaining = 0u32;
                if let Some(cnt) = st.open_counts.get_mut(&ino) {
                    *cnt = cnt.saturating_sub(1);
                    remaining = *cnt;
                    if *cnt == 0 {
                        st.open_counts.remove(&ino);
                    }
                }
                let can_reclaim = !self.read_only
                    && !st.closed
                    && !st.fenced
                    && st.lease.is_some()
                    && remaining == 0;
                (ino, can_reclaim)
            };
            if should_reclaim && let Some(item) = self.load_inode(ino).await? {
                self.reclaim_if_dead_locked(ino, &item).await?;
            }
            self.wake_lock_waiters(ino);
            Ok(())
        })
    }
}

impl<H: HeadStore + 'static, P: PackStore + 'static> CowFs<H, P> {
    async fn do_remove(
        &self,
        cred: &Cred,
        dir: &Handle,
        name: &str,
        directory: bool,
        expected: Option<NodeId>,
    ) -> Result<()> {
        let _op = self.op_lock.lock().await;
        self.check_rw()?;
        let (dir_ino, mut dir_item) = self.check_handle(dir).await?;
        check_component(name)?;
        let dir_perm = self.searchable(cred, dir_ino, &dir_item).await?;
        let di = self
            .lookup_dir_item(dir_ino, name)
            .await?
            .ok_or(Errno::ENOENT)?;
        if expected.is_some_and(|node| node.ino != di.child_ino || node.generation != di.child_gen)
        {
            return Err(Errno::ESTALE);
        }
        let mut victim = self.load_inode(di.child_ino).await?.ok_or(Errno::ESTALE)?;
        let victim_perm = self.load_perm_node(di.child_ino, &victim).await?;
        inode::may_delete(&cred.identity, &dir_perm, &victim_perm)?;

        match (directory, victim.file_type == FileType::Dir) {
            (false, true) => return Err(Errno::EISDIR),
            (true, false) => return Err(Errno::ENOTDIR),
            (true, true) if !self.dir_is_empty(di.child_ino).await? => {
                return Err(Errno::ENOTEMPTY);
            }
            _ => {}
        }

        self.maybe_backpressure_flush(512).await?;
        let now = (self.clock)();
        if directory {
            dir_item.nlink = dir_item.nlink.saturating_sub(1);
            victim.nlink = 0;
        } else {
            victim.nlink = victim.nlink.saturating_sub(1);
        }
        dir_item.mtime = now;
        dir_item.ctime = now;
        victim.ctime = now;

        {
            let mut st = self.state.borrow_mut();
            st.user_modified = true;
            st.mark_dirty(now);
            st.overlay.delete(TreeKey::dir_item(dir_ino, name));
            st.overlay.delete(TreeKey::dir_index(dir_ino, di.dir_index));
            st.overlay
                .delete(TreeKey::inode_ref(di.child_ino, dir_ino, name));
            st.overlay
                .put(TreeKey::inode_item(dir_ino), dir_item.encode());
            st.overlay
                .put(TreeKey::inode_item(di.child_ino), victim.encode());
        }
        self.sync_arena_dirty();
        self.reclaim_if_dead_locked(di.child_ino, &victim).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_volume;
    use cowtree::memory::{MemoryHeadStore, MemoryPackStore};

    fn block_on<F: Future>(fut: F) -> F::Output {
        vfs::now_or_never(fut).expect("memory cowfs future ready")
    }

    #[test]
    fn uncommitted_multiblock_extent_split_preserves_dirty_block_on_write_and_truncate() {
        let hs = Rc::new(MemoryHeadStore::new());
        let ps = Rc::new(MemoryPackStore::new());
        let vol = VolumeId("vol-multiblk-split".into());
        let now = Timespec { sec: 1000, nsec: 0 };
        block_on(CowFs::format_volume(
            &*hs,
            &*ps,
            vol.clone(),
            0,
            0,
            0o755,
            now,
        ))
        .unwrap();
        let fs = block_on(CowFs::open(
            hs.clone(),
            ps.clone(),
            vol.clone(),
            CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
            CowFsConfig::local_browser(Rc::new(move || now)),
        ))
        .unwrap();
        let admin = Cred::root();
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true);

        // (a) Stage a single 192 KiB (3 * 64 KiB) uncommitted multi-block extent with refcount 1,
        // then overwrite its middle 64 KiB block -> splits into prefix [0, 64K), new [64K, 128K),
        // and suffix [128K, 192K). Both prefix and suffix must keep the dirty block staged!
        let (e_write, o_write) =
            block_on(fs.create(&admin, &fs.root(), "split_write.bin", 0o644, &opts)).unwrap();
        let ino_w = e_write.handle.node.ino;
        let mut multi_w = vec![0u8; 3 * BLOCK_SIZE as usize];
        multi_w[0..BLOCK_SIZE as usize].fill(0x11);
        multi_w[BLOCK_SIZE as usize..2 * BLOCK_SIZE as usize].fill(0x22);
        multi_w[2 * BLOCK_SIZE as usize..3 * BLOCK_SIZE as usize].fill(0x33);
        let dig_w = sha256(&multi_w);
        let ext_w = ExtentDataValue::Extent {
            len: 3 * BLOCK_SIZE,
            digest: dig_w,
            block_offset: 0,
        }
        .encode()
        .unwrap();
        {
            let mut item = block_on(fs.load_inode(ino_w)).unwrap().unwrap();
            item.size = (3 * BLOCK_SIZE) as u64;
            let mut st = fs.state.borrow_mut();
            st.stage_dirty_block(dig_w, Rc::new(multi_w));
            st.overlay.put(TreeKey::extent_data(ino_w, 0), ext_w);
            st.overlay.put(TreeKey::inode_item(ino_w), item.encode());
            st.user_modified = true;
        }
        // Overwrite 4 bytes inside the middle 64 KiB block [64K, 128K).
        block_on(fs.write_at(
            &o_write,
            b"MID!",
            WriteAt::Offset(u64::from(BLOCK_SIZE) + 8),
        ))
        .unwrap();

        // (b) Stage a single 192 KiB uncommitted multi-block extent with refcount 1, then truncate
        // to `128 KiB + 17` -> splits into untouched prefix [0, 128K) + zero-padded tail [128K, 192K).
        let (e_trunc, o_trunc) =
            block_on(fs.create(&admin, &fs.root(), "split_trunc.bin", 0o644, &opts)).unwrap();
        let ino_t = e_trunc.handle.node.ino;
        let mut multi_t = vec![0u8; 3 * BLOCK_SIZE as usize];
        multi_t[0..BLOCK_SIZE as usize].fill(0x44);
        multi_t[BLOCK_SIZE as usize..2 * BLOCK_SIZE as usize].fill(0x55);
        multi_t[2 * BLOCK_SIZE as usize..3 * BLOCK_SIZE as usize].fill(0x66);
        let dig_t = sha256(&multi_t);
        let ext_t = ExtentDataValue::Extent {
            len: 3 * BLOCK_SIZE,
            digest: dig_t,
            block_offset: 0,
        }
        .encode()
        .unwrap();
        {
            let mut item = block_on(fs.load_inode(ino_t)).unwrap().unwrap();
            item.size = (3 * BLOCK_SIZE) as u64;
            let mut st = fs.state.borrow_mut();
            st.stage_dirty_block(dig_t, Rc::new(multi_t));
            st.overlay.put(TreeKey::extent_data(ino_t, 0), ext_t);
            st.overlay.put(TreeKey::inode_item(ino_t), item.encode());
            st.user_modified = true;
        }
        let trunc_len = 2 * u64::from(BLOCK_SIZE) + 17;
        block_on(fs.set_len(&o_trunc, trunc_len)).unwrap();

        // Commit, drop caches, and verify BOTH split files read back intact from PackStore!
        block_on(fs.commit_tx_group()).unwrap();
        block_on(fs.release(&o_write)).unwrap();
        block_on(fs.release(&o_trunc)).unwrap();
        block_on(fs.close_clean()).unwrap();

        let report = block_on(verify_volume(&*hs, &*ps, &vol)).unwrap();
        assert!(report.ok, "fsck errors: {:?}", report.errors);

        let ro = block_on(CowFs::open(
            hs.clone(),
            ps.clone(),
            vol,
            CowFsOpenMode::ReadOnly,
            CowFsConfig::local_browser(Rc::new(move || now)),
        ))
        .unwrap();
        let mut ro_opt = OpenOptions::new();
        ro_opt.read(true);

        let w_ent = block_on(ro.lookup(&admin, &ro.root(), "split_write.bin")).unwrap();
        let w_fd = block_on(ro.open(&admin, &w_ent.handle, &ro_opt)).unwrap();
        let mut buf = vec![0u8; 3 * BLOCK_SIZE as usize];
        let mut off = 0;
        while off < buf.len() {
            let n = block_on(ro.read_at(&w_fd, &mut buf[off..], off as u64)).unwrap();
            assert!(n > 0);
            off += n;
        }
        assert!(buf[0..BLOCK_SIZE as usize].iter().all(|&b| b == 0x11));
        assert_eq!(
            &buf[BLOCK_SIZE as usize + 8..BLOCK_SIZE as usize + 12],
            b"MID!"
        );
        assert_eq!(buf[BLOCK_SIZE as usize], 0x22);
        assert!(buf[2 * BLOCK_SIZE as usize..].iter().all(|&b| b == 0x33));
        block_on(ro.release(&w_fd)).unwrap();

        let t_ent = block_on(ro.lookup(&admin, &ro.root(), "split_trunc.bin")).unwrap();
        assert_eq!(t_ent.metadata.size, trunc_len);
        let t_fd = block_on(ro.open(&admin, &t_ent.handle, &ro_opt)).unwrap();
        let mut tbuf = vec![0u8; trunc_len as usize];
        let mut toff = 0;
        while toff < tbuf.len() {
            let n = block_on(ro.read_at(&t_fd, &mut tbuf[toff..], toff as u64)).unwrap();
            assert!(n > 0);
            toff += n;
        }
        assert!(tbuf[0..BLOCK_SIZE as usize].iter().all(|&b| b == 0x44));
        assert!(
            tbuf[BLOCK_SIZE as usize..2 * BLOCK_SIZE as usize]
                .iter()
                .all(|&b| b == 0x55)
        );
        assert!(tbuf[2 * BLOCK_SIZE as usize..].iter().all(|&b| b == 0x66));
        block_on(ro.release(&t_fd)).unwrap();
    }
}

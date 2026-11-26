//! Raw LBA block-addressable Copy-on-Write volume (`ROOT_FEATURE_RAW_BLOCK`, Phase 9.5 #85).
//!
//! Stores deterministic `RawVolumeMeta` at `TreeKey::raw_block_meta()` (`0x60`) and block-aligned
//! non-overlapping `ExtentDataValue::Extent` entries at `TreeKey::raw_lba_extent(byte_offset)`
//! (`0x30`), reusing the existing Merkle CoW B+tree, `PackStore`, GC, `cowfs send/recv`,
//! `StorageVolume` DO, and OCI snapshot infrastructure without format forks.

use crate::fs::{AsyncMutex, CowFsClock, DEFAULT_SUBVOL};
use abi::Errno;
use abi::contract::{Durability, WriterModel};
use abi::fs::Timespec;
use abi::volume::{
    BlkInfoResp, BlkLeaseResp, CowfsForkReq, CowfsForkResp, CowfsFsckReq, CowfsFsckResp,
    CowfsGcReq, CowfsGcResp, CowfsInfoResp, CowfsSnapDeleteReq, CowfsSnapEntry, CowfsSnapListResp,
    CowfsSnapshotReq, CowfsSnapshotResp,
};
use cowtree::store::CommitOutcome;
use cowtree::{
    Arena, ArenaConfig, COWFS_FORMAT_VERSION, CommitRequest, CowTree, Digest, EXTENT_MAX_BYTES,
    ExtentDataValue, ForkRequest, HeadStore, KIND_EXTENT_DATA, LeafEntry, Node, PackBuilder,
    PackMeta, PackStore, RAW_BLOCK_INO, ROOT_FEATURE_ACCOUNTING, ROOT_FEATURE_RAW_BLOCK,
    RawVolumeMeta, RoPinGuard, RootObject, SnapshotRecord, TreeKey, TreeOverlay, VolumeHead,
    VolumeId, WriterLease, WriterMode, digest_to_hex, sha256, verify_block_digest,
};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;
use vfs::vblk::VolumeDevice;
use vfs::{BoxFuture, Result};

/// Open mode for [`RawBlockVolume::open`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RawBlockOpenMode {
    ReadWrite(WriterMode),
    ReadOnly,
    Snapshot(String),
}

/// Optional external fencing hook (for example CSI `ClusterState` publish-lease verification).
pub type FenceValidator = Rc<dyn Fn() -> Result<()>>;

/// Configuration for opening a [`RawBlockVolume`].
#[derive(Clone)]
pub struct RawBlockConfig {
    pub arena: ArenaConfig,
    pub clock: CowFsClock,
    pub writer_model: WriterModel,
    pub durability: Durability,
    pub fence_validator: Option<FenceValidator>,
}

impl RawBlockConfig {
    pub fn local_native(clock: CowFsClock) -> Self {
        Self {
            arena: ArenaConfig::platform_default(),
            clock,
            writer_model: WriterModel::Local,
            durability: Durability::TreeCommit,
            fence_validator: None,
        }
    }

    pub fn remote_fenced(clock: CowFsClock) -> Self {
        Self {
            arena: ArenaConfig::platform_default(),
            clock,
            writer_model: WriterModel::Fenced,
            durability: Durability::FencedCommit,
            fence_validator: None,
        }
    }

    pub fn with_arena(mut self, arena: ArenaConfig) -> Self {
        self.arena = arena;
        self
    }

    pub fn with_writer_model(mut self, model: WriterModel) -> Self {
        self.writer_model = model;
        self
    }

    pub fn with_durability(mut self, durability: Durability) -> Self {
        self.durability = durability;
        self
    }

    pub fn with_fence_validator(mut self, validator: FenceValidator) -> Self {
        self.fence_validator = Some(validator);
        self
    }
}

/// Metadata snapshot returned by [`RawBlockVolume::info`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawBlockInfo {
    pub volume: String,
    pub size_bytes: u64,
    pub block_size: u32,
    pub flags: u32,
    pub read_only: bool,
    pub incarnation: u64,
    pub fence: u64,
    pub epoch: u64,
    pub root: Digest,
    pub fenced: bool,
    pub dirty: bool,
    pub allocated_bytes: u64,
}

/// Live lease/fencing state returned by [`RawBlockVolume::fencing_state`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawBlockFencingState {
    pub held: bool,
    pub fenced: bool,
    pub expired: bool,
    pub lease_expires_at: Option<u64>,
    pub incarnation: u64,
    pub fence: u64,
    pub epoch: u64,
    pub read_only: bool,
}

struct RawBlockState {
    head: VolumeHead,
    root_obj: RootObject,
    meta: RawVolumeMeta,
    lease: Option<WriterLease>,
    ro_pin: Option<Box<dyn RoPinGuard>>,
    fenced: bool,
    closed: bool,
    overlay: TreeOverlay,
    /// Uncommitted data blocks keyed by SHA-256 digest: `(bytes, refcount)`.
    dirty_blocks: HashMap<Digest, (Rc<Vec<u8>>, usize)>,
    dirty_block_bytes: usize,
    allocated_bytes: u64,
}

impl RawBlockState {
    fn subvol_root(&self) -> Result<Digest> {
        self.root_obj
            .subvols
            .get(DEFAULT_SUBVOL)
            .copied()
            .ok_or(Errno::EIO)
    }

    fn is_dirty(&self) -> bool {
        !self.overlay.is_empty() || !self.dirty_blocks.is_empty()
    }

    fn total_dirty_bytes(&self) -> usize {
        self.overlay.dirty_bytes() + self.dirty_block_bytes
    }

    fn stage_dirty_block(&mut self, digest: Digest, bytes: Rc<Vec<u8>>) {
        if let Some((_, count)) = self.dirty_blocks.get_mut(&digest) {
            *count = count.saturating_add(1);
        } else {
            let sz = bytes.len();
            self.dirty_blocks.insert(digest, (bytes, 1));
            self.dirty_block_bytes = self.dirty_block_bytes.saturating_add(sz);
        }
    }

    fn retain_dirty_block(&mut self, digest: &Digest) {
        if let Some((_, count)) = self.dirty_blocks.get_mut(digest) {
            *count = count.saturating_add(1);
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
}

/// Fenced raw LBA block volume over `os-cowtree` (`HeadStore` + `PackStore`).
pub struct RawBlockVolume<H: HeadStore + 'static, P: PackStore + 'static> {
    volume_id: VolumeId,
    read_only: bool,
    pinned_snapshot: Option<String>,
    writer_model: WriterModel,
    durability: Durability,
    clock: CowFsClock,
    fence_validator: Option<FenceValidator>,
    head_store: Rc<H>,
    pack_store: Rc<P>,
    arena: RefCell<Arena>,
    state: RefCell<RawBlockState>,
    op_lock: AsyncMutex,
    commit_lock: AsyncMutex,
    commit_seq: Cell<u64>,
}

/// Initial formatted raw block volume head plus its root & metadata tree nodes.
pub type RawBlockInitNodes = (VolumeHead, Vec<(Digest, Vec<u8>)>);

impl<H: HeadStore + 'static, P: PackStore + 'static> RawBlockVolume<H, P> {
    /// Build initial metadata nodes (`RootObject` with `ROOT_FEATURE_RAW_BLOCK` + `RawVolumeMeta` leaf).
    pub fn build_initial_nodes(
        volume: VolumeId,
        size_bytes: u64,
        block_size: u32,
        flags: u32,
        now: Timespec,
    ) -> Result<RawBlockInitNodes> {
        let meta = RawVolumeMeta::new(block_size, size_bytes, flags, now)?;
        let leaf = Node::Leaf {
            entries: vec![LeafEntry {
                key: TreeKey::raw_block_meta(),
                value: meta.encode()?,
            }],
        };
        let (leaf_digest, leaf_bytes) = leaf.encode()?;

        let mut subvols = BTreeMap::new();
        subvols.insert(DEFAULT_SUBVOL.to_string(), leaf_digest);
        let root_obj = RootObject {
            format_version: COWFS_FORMAT_VERSION,
            features: ROOT_FEATURE_ACCOUNTING | ROOT_FEATURE_RAW_BLOCK,
            volume_uuid: volume.0.clone(),
            subvols,
            next_ino: RAW_BLOCK_INO + 1,
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

    /// Format a brand-new sparse raw LBA block volume (`ROOT_FEATURE_RAW_BLOCK`).
    pub async fn format(
        head_store: &H,
        _pack_store: &P,
        volume: VolumeId,
        size_bytes: u64,
        block_size: u32,
        flags: u32,
        now: Timespec,
    ) -> Result<VolumeHead> {
        if let Some(v) = head_store.format_version().await?
            && v != COWFS_FORMAT_VERSION
        {
            return Err(Errno::EPROTONOSUPPORT);
        }
        let (head, nodes) = Self::build_initial_nodes(volume, size_bytes, block_size, flags, now)?;
        head_store.create_volume(&head, &nodes).await
    }

    async fn release_handles(
        head_store: &H,
        lease: Option<WriterLease>,
        ro_pin: Option<Box<dyn RoPinGuard>>,
    ) {
        if let Some(pin) = ro_pin {
            let _ = head_store.unpin_ro_root(pin).await;
        }
        if let Some(l) = lease {
            if l.head.ephemeral_if_unmodified && !l.head.modified {
                let _ = head_store.delete_volume_with_lease(l, true).await;
            } else {
                let _ = head_store.release_writer(l).await;
            }
        }
    }

    /// Open an existing `ROOT_FEATURE_RAW_BLOCK` volume in RW, RO, or named-snapshot mode.
    /// Rejects non-raw (`CowFs`) volumes with `Errno::EOPNOTSUPP`.
    pub async fn open(
        head_store: Rc<H>,
        pack_store: Rc<P>,
        volume: VolumeId,
        mode: RawBlockOpenMode,
        config: RawBlockConfig,
    ) -> Result<Self> {
        if let Some(v) = head_store.format_version().await?
            && v != COWFS_FORMAT_VERSION
        {
            return Err(Errno::EPROTONOSUPPORT);
        }

        let (head, lease, ro_pin, read_only, pinned_snapshot) = match mode {
            RawBlockOpenMode::ReadWrite(writer_mode) => {
                if let Some(ref validator) = config.fence_validator
                    && validator().is_err()
                {
                    return Err(Errno::ESTALE);
                }
                let lease = head_store.acquire_writer(&volume, writer_mode).await?;
                if lease.head.format_version != COWFS_FORMAT_VERSION {
                    Self::release_handles(&*head_store, Some(lease), None).await;
                    return Err(Errno::EPROTONOSUPPORT);
                }
                let head = lease.head.clone();
                (head, Some(lease), None, false, None)
            }
            RawBlockOpenMode::ReadOnly => {
                let (head, pin) = head_store.pin_ro_root(&volume, None).await?;
                if head.format_version != COWFS_FORMAT_VERSION {
                    Self::release_handles(&*head_store, None, Some(pin)).await;
                    return Err(Errno::EPROTONOSUPPORT);
                }
                (head, None, Some(pin), true, None)
            }
            RawBlockOpenMode::Snapshot(name) => {
                let (head, pin) = head_store.pin_ro_root(&volume, Some(&name)).await?;
                if head.format_version != COWFS_FORMAT_VERSION {
                    Self::release_handles(&*head_store, None, Some(pin)).await;
                    return Err(Errno::EPROTONOSUPPORT);
                }
                (head, None, Some(pin), true, Some(name))
            }
        };

        let raw_root = match head_store.get_node(&head.root).await {
            Ok(b) => b,
            Err(e) => {
                Self::release_handles(&*head_store, lease, ro_pin).await;
                return Err(e);
            }
        };
        let root_obj = match RootObject::decode_verified(&head.root, &raw_root) {
            Ok(r) => r,
            Err(e) => {
                Self::release_handles(&*head_store, lease, ro_pin).await;
                return Err(e);
            }
        };
        if (root_obj.features & ROOT_FEATURE_RAW_BLOCK) == 0 {
            Self::release_handles(&*head_store, lease, ro_pin).await;
            return Err(Errno::EOPNOTSUPP);
        }
        let Some(&subvol_root) = root_obj.subvols.get(DEFAULT_SUBVOL) else {
            Self::release_handles(&*head_store, lease, ro_pin).await;
            return Err(Errno::EIO);
        };

        let arena = RefCell::new(Arena::new(config.arena));
        let tree = CowTree::new(&*head_store, &arena);
        let meta_bytes = match tree.get(&subvol_root, &TreeKey::raw_block_meta()).await {
            Ok(Some(b)) => b,
            Ok(None) => {
                Self::release_handles(&*head_store, lease, ro_pin).await;
                return Err(Errno::EIO);
            }
            Err(e) => {
                Self::release_handles(&*head_store, lease, ro_pin).await;
                return Err(e);
            }
        };
        let meta = match RawVolumeMeta::decode(&meta_bytes) {
            Ok(m) => m,
            Err(e) => {
                Self::release_handles(&*head_store, lease, ro_pin).await;
                return Err(e);
            }
        };

        let allocated_bytes = root_obj.allocated_bytes;
        let actual_volume = head.volume.clone();
        Ok(Self {
            volume_id: actual_volume,
            read_only,
            pinned_snapshot,
            writer_model: config.writer_model,
            durability: config.durability,
            clock: config.clock,
            fence_validator: config.fence_validator,
            head_store,
            pack_store,
            arena,
            state: RefCell::new(RawBlockState {
                head,
                root_obj,
                meta,
                lease,
                ro_pin,
                fenced: false,
                closed: false,
                overlay: TreeOverlay::new(),
                dirty_blocks: HashMap::new(),
                dirty_block_bytes: 0,
                allocated_bytes,
            }),
            op_lock: AsyncMutex::default(),
            commit_lock: AsyncMutex::default(),
            commit_seq: Cell::new(0),
        })
    }

    pub fn volume_id(&self) -> &VolumeId {
        &self.volume_id
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only
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

    /// Permanently fence this handle (fail closed on all subsequent writes, trims, and flushes).
    pub fn mark_fenced(&self) {
        self.state.borrow_mut().fenced = true;
    }

    pub fn info(&self) -> RawBlockInfo {
        let st = self.state.borrow();
        RawBlockInfo {
            volume: st.head.volume.0.clone(),
            size_bytes: st.meta.size_bytes,
            block_size: st.meta.block_size,
            flags: st.meta.flags,
            read_only: self.read_only,
            incarnation: st.head.incarnation,
            fence: st.head.fence,
            epoch: st.head.epoch,
            root: st.head.root,
            fenced: st.fenced,
            dirty: st.is_dirty(),
            allocated_bytes: st.allocated_bytes,
        }
    }

    pub fn fencing_state(&self) -> RawBlockFencingState {
        let st = self.state.borrow();
        let now = (self.clock)();
        let deadline_expired = st
            .lease
            .as_ref()
            .and_then(|l| l.expires_at)
            .is_some_and(|exp| exp <= now)
            || self.head_store.writer_expired()
            || self.head_store.check_writer_deadline().is_err();
        let validator_failed = self.fence_validator.as_ref().is_some_and(|v| v().is_err());
        let fenced = st.fenced || (!self.read_only && (deadline_expired || validator_failed));
        RawBlockFencingState {
            held: !self.read_only && !st.closed && st.lease.is_some() && !fenced,
            fenced,
            expired: !self.read_only && deadline_expired,
            lease_expires_at: st.lease.as_ref().and_then(|l| l.expires_at).map(|t| t.sec),
            incarnation: st.head.incarnation,
            fence: st.head.fence,
            epoch: st.head.epoch,
            read_only: self.read_only,
        }
    }

    fn check_open(&self) -> Result<()> {
        if self.state.borrow().closed {
            return Err(Errno::EBADF);
        }
        Ok(())
    }

    fn check_rw_and_fence(&self) -> Result<()> {
        {
            let st = self.state.borrow();
            if st.closed {
                return Err(Errno::EBADF);
            }
            if self.read_only {
                return Err(Errno::EROFS);
            }
            if st.fenced {
                return Err(Errno::ESTALE);
            }
            if st.lease.is_none() {
                return Err(Errno::ESTALE);
            }
            let now = (self.clock)();
            if st
                .lease
                .as_ref()
                .and_then(|l| l.expires_at)
                .is_some_and(|exp| exp <= now)
            {
                drop(st);
                self.state.borrow_mut().fenced = true;
                return Err(Errno::ESTALE);
            }
        }
        if self.head_store.writer_expired() || self.head_store.check_writer_deadline().is_err() {
            self.state.borrow_mut().fenced = true;
            return Err(Errno::ESTALE);
        }
        if let Some(ref validator) = self.fence_validator
            && validator().is_err()
        {
            self.state.borrow_mut().fenced = true;
            return Err(Errno::ESTALE);
        }
        Ok(())
    }

    async fn read_backing_block(&self, digest: &Digest) -> Result<Rc<Vec<u8>>> {
        if let Some((bytes, _)) = self.state.borrow().dirty_blocks.get(digest) {
            return Ok(Rc::clone(bytes));
        }
        if let Some(hit) = self.arena.borrow_mut().get_data(digest) {
            return Ok(hit);
        }
        let loc = self
            .head_store
            .lookup_block(digest)
            .await?
            .ok_or(Errno::EIO)?;
        loc.validate_v1()?;
        let raw = self
            .pack_store
            .read_pack_range(&loc.pack_id, loc.offset, loc.len)
            .await?;
        if raw.len() != loc.len as usize {
            return Err(Errno::EIO);
        }
        verify_block_digest(digest, &raw)?;
        let rc = Rc::new(raw);
        self.arena.borrow_mut().put_data(*digest, Rc::clone(&rc));
        Ok(rc)
    }

    async fn read_range_unlocked(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let (size_bytes, subvol_root, overlay) = {
            let st = self.state.borrow();
            if st.closed {
                return Err(Errno::EBADF);
            }
            (st.meta.size_bytes, st.subvol_root()?, st.overlay.clone())
        };
        if buf.is_empty() || offset >= size_bytes {
            return Ok(0);
        }
        let max_len = usize::try_from(size_bytes - offset).unwrap_or(usize::MAX);
        let to_read = buf.len().min(max_len);
        let out = &mut buf[..to_read];
        out.fill(0);

        let end = offset + to_read as u64;
        let tree = CowTree::new(&*self.head_store, &self.arena);
        let min_key = TreeKey::kind_start(RAW_BLOCK_INO, KIND_EXTENT_DATA);
        let mut extents: Vec<(u64, ExtentDataValue)> = Vec::new();

        if let Some((k, v)) = tree
            .find_le_with_overlay(
                &subvol_root,
                &overlay,
                &min_key,
                &TreeKey::raw_lba_extent(offset),
            )
            .await?
            && let Some(ext_off) = k.tail_u64()
        {
            let ext = ExtentDataValue::decode(&v)?;
            if ext_off.saturating_add(ext.byte_len()) > offset {
                extents.push((ext_off, ext));
            }
        }

        let mut scan_start = TreeKey::raw_lba_extent(offset.saturating_add(1));
        let scan_end = TreeKey::raw_lba_extent(end);
        if offset < end {
            loop {
                let batch = tree
                    .scan_range_with_overlay(&subvol_root, &overlay, &scan_start, &scan_end, 128)
                    .await?;
                if batch.is_empty() {
                    break;
                }
                let full = batch.len() == 128;
                let mut last_off = 0u64;
                for (k, v) in batch {
                    if let Some(ext_off) = k.tail_u64() {
                        last_off = ext_off;
                        let ext = ExtentDataValue::decode(&v)?;
                        extents.push((ext_off, ext));
                    }
                }
                if !full || last_off == u64::MAX {
                    break;
                }
                scan_start = TreeKey::raw_lba_extent(last_off.saturating_add(1));
            }
        }

        for (ext_start, ext) in extents {
            let ExtentDataValue::Extent {
                len,
                digest,
                block_offset,
            } = ext
            else {
                return Err(Errno::EIO);
            };
            let ext_end = ext_start.checked_add(u64::from(len)).ok_or(Errno::EIO)?;
            let ov_start = offset.max(ext_start);
            let ov_end = end.min(ext_end);
            if ov_start >= ov_end {
                continue;
            }
            let block_bytes = self.read_backing_block(&digest).await?;
            let src_start = usize::try_from(u64::from(block_offset) + (ov_start - ext_start))
                .map_err(|_| Errno::EIO)?;
            let copy_len = usize::try_from(ov_end - ov_start).map_err(|_| Errno::EIO)?;
            let src_end = src_start.checked_add(copy_len).ok_or(Errno::EIO)?;
            if src_end > block_bytes.len() {
                return Err(Errno::EIO);
            }
            let dst_start = usize::try_from(ov_start - offset).map_err(|_| Errno::EIO)?;
            out[dst_start..dst_start + copy_len].copy_from_slice(&block_bytes[src_start..src_end]);
        }

        Ok(to_read)
    }

    /// Read raw bytes at arbitrary byte `offset` (handles unaligned/partial reads; sparse regions
    /// return zeroes).
    pub async fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.check_open()?;
        let _op = self.op_lock.lock().await;
        self.read_range_unlocked(offset, buf).await
    }

    /// Zero-copy split / clear all extents overlapping aligned `[start, end)`.
    /// Surviving prefix/suffix slices reuse the original block `digest` with adjusted `block_offset`.
    async fn punch_aligned_range_locked(&self, start: u64, end: u64) -> Result<()> {
        if start >= end {
            return Ok(());
        }
        let (subvol_root, overlay_snapshot) = {
            let st = self.state.borrow();
            (st.subvol_root()?, st.overlay.clone())
        };
        let tree = CowTree::new(&*self.head_store, &self.arena);
        let min_key = TreeKey::kind_start(RAW_BLOCK_INO, KIND_EXTENT_DATA);
        let mut overlapping: Vec<(u64, u32, Digest, u32)> = Vec::new();

        if let Some((k, v)) = tree
            .find_le_with_overlay(
                &subvol_root,
                &overlay_snapshot,
                &min_key,
                &TreeKey::raw_lba_extent(start),
            )
            .await?
            && let Some(ext_off) = k.tail_u64()
        {
            let ExtentDataValue::Extent {
                len,
                digest,
                block_offset,
            } = ExtentDataValue::decode(&v)?
            else {
                return Err(Errno::EIO);
            };
            if ext_off.saturating_add(u64::from(len)) > start {
                overlapping.push((ext_off, len, digest, block_offset));
            }
        }

        let mut scan_start = TreeKey::raw_lba_extent(start.saturating_add(1));
        let scan_end = TreeKey::raw_lba_extent(end);
        loop {
            let batch = tree
                .scan_range_with_overlay(
                    &subvol_root,
                    &overlay_snapshot,
                    &scan_start,
                    &scan_end,
                    128,
                )
                .await?;
            if batch.is_empty() {
                break;
            }
            let full = batch.len() == 128;
            let mut last_off = 0u64;
            for (k, v) in batch {
                if let Some(ext_off) = k.tail_u64() {
                    last_off = ext_off;
                    let ExtentDataValue::Extent {
                        len,
                        digest,
                        block_offset,
                    } = ExtentDataValue::decode(&v)?
                    else {
                        return Err(Errno::EIO);
                    };
                    overlapping.push((ext_off, len, digest, block_offset));
                }
            }
            if !full || last_off == u64::MAX {
                break;
            }
            scan_start = TreeKey::raw_lba_extent(last_off.saturating_add(1));
        }

        if overlapping.is_empty() {
            return Ok(());
        }

        let mut st = self.state.borrow_mut();
        for (ext_start, len, digest, block_offset) in overlapping {
            let ext_end = ext_start.checked_add(u64::from(len)).ok_or(Errno::EIO)?;
            let keep_left = ext_start < start;
            let keep_right = ext_end > end;

            // Retain dirty block refcounts for surviving slices BEFORE unstaging the old extent.
            if keep_left {
                st.retain_dirty_block(&digest);
            }
            if keep_right {
                st.retain_dirty_block(&digest);
            }

            st.overlay.delete(TreeKey::raw_lba_extent(ext_start));
            st.allocated_bytes = st.allocated_bytes.saturating_sub(u64::from(len));
            st.unstage_dirty_block(&digest);

            if keep_left {
                let left_len = u32::try_from(start - ext_start).map_err(|_| Errno::EIO)?;
                let val = ExtentDataValue::Extent {
                    len: left_len,
                    digest,
                    block_offset,
                }
                .encode()?;
                st.overlay.put(TreeKey::raw_lba_extent(ext_start), val);
                st.allocated_bytes = st.allocated_bytes.saturating_add(u64::from(left_len));
            }
            if keep_right {
                let right_len = u32::try_from(ext_end - end).map_err(|_| Errno::EIO)?;
                let shift = u32::try_from(end - ext_start).map_err(|_| Errno::EIO)?;
                let right_block_offset = block_offset.checked_add(shift).ok_or(Errno::EIO)?;
                let val = ExtentDataValue::Extent {
                    len: right_len,
                    digest,
                    block_offset: right_block_offset,
                }
                .encode()?;
                st.overlay.put(TreeKey::raw_lba_extent(end), val);
                st.allocated_bytes = st.allocated_bytes.saturating_add(u64::from(right_len));
            }
        }
        Ok(())
    }

    async fn stage_aligned_slice_locked(&self, aligned_offset: u64, data: &[u8]) -> Result<()> {
        debug_assert!(!data.is_empty());
        let mut cursor = 0usize;
        let max_chunk = EXTENT_MAX_BYTES as usize;
        while cursor < data.len() {
            let take = (data.len() - cursor).min(max_chunk);
            let chunk = &data[cursor..cursor + take];
            let chunk_off = aligned_offset + cursor as u64;
            let chunk_end = chunk_off + take as u64;
            self.punch_aligned_range_locked(chunk_off, chunk_end)
                .await?;
            // Sparse elision: all-zero chunks remain unmapped holes (read back as zeroes).
            if chunk.iter().any(|&b| b != 0) {
                let digest = sha256(chunk);
                let val = ExtentDataValue::Extent {
                    len: u32::try_from(take).map_err(|_| Errno::EFBIG)?,
                    digest,
                    block_offset: 0,
                }
                .encode()?;
                let mut st = self.state.borrow_mut();
                st.stage_dirty_block(digest, Rc::new(chunk.to_vec()));
                st.overlay.put(TreeKey::raw_lba_extent(chunk_off), val);
                st.allocated_bytes = st.allocated_bytes.saturating_add(take as u64);
            }
            cursor += take;
        }
        Ok(())
    }

    fn touch_modified_meta(&self) -> Result<()> {
        let now = (self.clock)();
        let mut st = self.state.borrow_mut();
        st.meta.modified_at = now;
        let encoded = st.meta.encode()?;
        st.overlay.put(TreeKey::raw_block_meta(), encoded);
        let dirty = st.total_dirty_bytes();
        drop(st);
        self.arena.borrow_mut().set_dirty_bytes(dirty);
        Ok(())
    }

    /// Write raw bytes at arbitrary byte `offset` (performs boundary-sector RMW only for unaligned
    /// head/tail sectors; interior aligned sectors write directly in `<= 1 MiB` extents).
    pub async fn write_at(&self, offset: u64, data: &[u8]) -> Result<usize> {
        let _op = self.op_lock.lock().await;
        self.check_rw_and_fence()?;
        if data.is_empty() {
            return Ok(0);
        }
        let (size_bytes, block_size) = {
            let st = self.state.borrow();
            (st.meta.size_bytes, st.meta.block_size)
        };
        let end = offset.checked_add(data.len() as u64).ok_or(Errno::ENOSPC)?;
        if end > size_bytes {
            return Err(Errno::ENOSPC);
        }

        // Trigger backpressure flush before staging if dirty slab budget would be exceeded.
        if self
            .arena
            .borrow()
            .needs_backpressure_flush(data.len().saturating_add(block_size as usize * 2))
        {
            self.arena.borrow_mut().record_backpressure_flush();
            self.flush_locked().await?;
        }

        let bs = u64::from(block_size);
        let bs_usize = block_size as usize;
        let aligned_start = (offset / bs) * bs;
        let aligned_end = end.div_ceil(bs) * bs;

        if aligned_start + bs == aligned_end && (offset != aligned_start || end != aligned_end) {
            // Single-sector partial write: RMW 1 sector.
            let mut sector = vec![0u8; bs_usize];
            self.read_range_unlocked(aligned_start, &mut sector).await?;
            let in_sec = (offset - aligned_start) as usize;
            sector[in_sec..in_sec + data.len()].copy_from_slice(data);
            self.stage_aligned_slice_locked(aligned_start, &sector)
                .await?;
        } else {
            let mut src_pos = 0usize;
            let mut cur_off = offset;

            // Unaligned head sector RMW.
            if !cur_off.is_multiple_of(bs) {
                let sec_base = (cur_off / bs) * bs;
                let in_sec = (cur_off - sec_base) as usize;
                let take = (bs_usize - in_sec).min(data.len());
                let mut sector = vec![0u8; bs_usize];
                self.read_range_unlocked(sec_base, &mut sector).await?;
                sector[in_sec..in_sec + take].copy_from_slice(&data[..take]);
                self.stage_aligned_slice_locked(sec_base, &sector).await?;
                src_pos += take;
                cur_off += take as u64;
            }

            // Full aligned interior sectors (zero RMW!).
            let remaining = data.len() - src_pos;
            let aligned_len = (remaining / bs_usize) * bs_usize;
            if aligned_len > 0 {
                self.stage_aligned_slice_locked(cur_off, &data[src_pos..src_pos + aligned_len])
                    .await?;
                src_pos += aligned_len;
                cur_off += aligned_len as u64;
            }

            // Unaligned tail sector RMW.
            if src_pos < data.len() {
                let tail_len = data.len() - src_pos;
                let mut sector = vec![0u8; bs_usize];
                self.read_range_unlocked(cur_off, &mut sector).await?;
                sector[..tail_len].copy_from_slice(&data[src_pos..]);
                self.stage_aligned_slice_locked(cur_off, &sector).await?;
            }
        }

        self.touch_modified_meta()?;
        Ok(data.len())
    }

    /// Discard (TRIM / UNMAP) byte range `[offset, offset + len)`, punching holes for all fully
    /// covered aligned sectors using zero-copy extent splitting.
    pub async fn trim(&self, offset: u64, len: u64) -> Result<()> {
        let _op = self.op_lock.lock().await;
        self.check_rw_and_fence()?;
        if len == 0 {
            return Ok(());
        }
        let (size_bytes, block_size) = {
            let st = self.state.borrow();
            (st.meta.size_bytes, st.meta.block_size)
        };
        let end = offset.checked_add(len).ok_or(Errno::EINVAL)?;
        if end > size_bytes {
            return Err(Errno::EINVAL);
        }
        let bs = u64::from(block_size);
        let punch_start = offset.div_ceil(bs).saturating_mul(bs);
        let punch_end = (end / bs).saturating_mul(bs);
        if punch_start < punch_end {
            self.punch_aligned_range_locked(punch_start, punch_end)
                .await?;
            self.touch_modified_meta()?;
        }
        Ok(())
    }

    /// Write deterministic zeroes across `[offset, offset + len)`: RMW-zeroes unaligned boundary
    /// sectors and zero-copy punches sparse holes for all interior aligned sectors.
    pub async fn write_zeroes(&self, offset: u64, len: u64) -> Result<()> {
        let _op = self.op_lock.lock().await;
        self.check_rw_and_fence()?;
        if len == 0 {
            return Ok(());
        }
        let (size_bytes, block_size) = {
            let st = self.state.borrow();
            (st.meta.size_bytes, st.meta.block_size)
        };
        let end = offset.checked_add(len).ok_or(Errno::ENOSPC)?;
        if end > size_bytes {
            return Err(Errno::ENOSPC);
        }
        let bs = u64::from(block_size);
        let bs_usize = block_size as usize;
        let aligned_start = (offset / bs) * bs;
        let aligned_end = end.div_ceil(bs) * bs;

        if aligned_start + bs == aligned_end && (offset != aligned_start || end != aligned_end) {
            let mut sector = vec![0u8; bs_usize];
            self.read_range_unlocked(aligned_start, &mut sector).await?;
            let in_sec = (offset - aligned_start) as usize;
            let zlen = len as usize;
            sector[in_sec..in_sec + zlen].fill(0);
            self.stage_aligned_slice_locked(aligned_start, &sector)
                .await?;
        } else {
            let mut cur = offset;
            if !cur.is_multiple_of(bs) {
                let sec_base = (cur / bs) * bs;
                let in_sec = (cur - sec_base) as usize;
                let mut sector = vec![0u8; bs_usize];
                self.read_range_unlocked(sec_base, &mut sector).await?;
                sector[in_sec..].fill(0);
                self.stage_aligned_slice_locked(sec_base, &sector).await?;
                cur = sec_base + bs;
            }
            let punch_end = (end / bs) * bs;
            if cur < punch_end {
                self.punch_aligned_range_locked(cur, punch_end).await?;
                cur = punch_end;
            }
            if cur < end {
                let tail_len = (end - cur) as usize;
                let mut sector = vec![0u8; bs_usize];
                self.read_range_unlocked(cur, &mut sector).await?;
                sector[..tail_len].fill(0);
                self.stage_aligned_slice_locked(cur, &sector).await?;
            }
        }

        self.touch_modified_meta()?;
        Ok(())
    }

    async fn flush_locked(&self) -> Result<VolumeHead> {
        let _commit = self.commit_lock.lock().await;
        self.check_rw_and_fence()?;

        let (head_snap, lease_triple, is_dirty) = {
            let st = self.state.borrow();
            let lease = st.lease.as_ref().ok_or(Errno::ESTALE)?;
            (
                st.head.clone(),
                (lease.incarnation, lease.fence, lease.epoch),
                st.is_dirty(),
            )
        };

        if !is_dirty {
            // Even when clean, enforce fencing CAS against the backing store so a superseded
            // writer cannot silently report success on FLUSH.
            let stored = self.head_store.read_head(&self.volume_id).await?;
            if (stored.incarnation, stored.fence, stored.epoch) != lease_triple {
                self.state.borrow_mut().fenced = true;
                return Err(Errno::ESTALE);
            }
            return Ok(head_snap);
        }

        let _gc_guard = self.head_store.acquire_gc_lock(false).await?;
        let now = (self.clock)();

        // Snapshot dirty blocks and overlay ops without discarding them until commit succeeds.
        let (subvol_root, ops, dirty_blocks, mut next_root_obj) = {
            let st = self.state.borrow();
            let mut ro = st.root_obj.clone();
            ro.features |= ROOT_FEATURE_ACCOUNTING | ROOT_FEATURE_RAW_BLOCK;
            ro.allocated_bytes = st.allocated_bytes;
            ro.inode_count = 1;
            let blocks: Vec<(Digest, Rc<Vec<u8>>)> = st
                .dirty_blocks
                .iter()
                .map(|(d, (b, _))| (*d, Rc::clone(b)))
                .collect();
            (st.subvol_root()?, st.overlay.clone_sorted_ops(), blocks, ro)
        };

        // Pack any dirty blocks not already present in the content-addressed block index.
        let mut pack_builder = PackBuilder::new();
        for (digest, bytes) in &dirty_blocks {
            if self.head_store.lookup_block(digest).await?.is_none() {
                pack_builder.push(*digest, bytes)?;
            }
        }
        let built_packs = pack_builder.finish()?;
        let mut put_packs: Vec<PackMeta> = Vec::with_capacity(built_packs.len());
        let mut put_blocks = Vec::new();
        for built in built_packs {
            let mut meta = self
                .pack_store
                .write_pack(&built.pack_id, &built.bytes)
                .await?;
            meta.created_at = now;
            put_packs.push(meta);
            put_blocks.extend(built.locations);
        }

        // Apply B+tree batch via CoW.
        let tree = CowTree::new(&*self.head_store, &self.arena);
        let (new_subvol_root, mut put_nodes) = tree.apply_batch(&subvol_root, &ops).await?;
        next_root_obj
            .subvols
            .insert(DEFAULT_SUBVOL.to_string(), new_subvol_root);
        next_root_obj.parent_root = Some(head_snap.root);
        let (new_root_digest, new_root_bytes) = next_root_obj.encode()?;
        put_nodes.push((new_root_digest, new_root_bytes));

        let seq = self.commit_seq.get().wrapping_add(1);
        self.commit_seq.set(seq);
        let mut op_seed = Vec::with_capacity(64);
        op_seed.extend_from_slice(&lease_triple.0.to_be_bytes());
        op_seed.extend_from_slice(&lease_triple.1.to_be_bytes());
        op_seed.extend_from_slice(&lease_triple.2.to_be_bytes());
        op_seed.extend_from_slice(&seq.to_be_bytes());
        op_seed.extend_from_slice(&new_root_digest);
        let op_hash = sha256(&op_seed);
        let mut op_id = [0u8; 16];
        op_id.copy_from_slice(&op_hash[..16]);

        let mut commit_req = CommitRequest {
            op_id,
            volume: self.volume_id.clone(),
            expected_incarnation: lease_triple.0,
            expected_fence: lease_triple.1,
            expected_epoch: lease_triple.2,
            new_root: new_root_digest,
            put_nodes,
            put_packs,
            put_blocks,
            committed_at: now,
        };
        self.head_store.prepare_publication(&mut commit_req).await?;
        let outcome = self.head_store.publish_commit(&commit_req, false).await;
        match outcome {
            CommitOutcome::Committed(new_head) => {
                let mut st = self.state.borrow_mut();
                st.head = new_head.clone();
                st.root_obj = next_root_obj;
                if let Some(lease) = st.lease.as_mut() {
                    lease.epoch = new_head.epoch;
                    lease.head = new_head.clone();
                }
                // Move committed dirty blocks into clean data cache.
                let mut arena = self.arena.borrow_mut();
                for (d, (bytes, _)) in st.dirty_blocks.drain() {
                    arena.put_data(d, bytes);
                }
                st.dirty_block_bytes = 0;
                st.overlay.clear();
                arena.set_dirty_bytes(0);
                Ok(new_head)
            }
            CommitOutcome::Aborted(Errno::ESTALE) => {
                self.state.borrow_mut().fenced = true;
                Err(Errno::ESTALE)
            }
            CommitOutcome::Aborted(e) => Err(e),
            CommitOutcome::Uncertain => Err(Errno::EIO),
        }
    }

    /// Flush dirty extents & metadata to durable `PackStore` + atomic fenced `HeadStore::commit_head`.
    pub async fn flush(&self) -> Result<VolumeHead> {
        let _op = self.op_lock.lock().await;
        self.flush_locked().await
    }

    /// Create an O(1) named snapshot of the raw volume (requires an unfenced RW handle; flushes
    /// dirty extents first).
    pub async fn create_snapshot(&self, name: &str) -> Result<SnapshotRecord> {
        if name.is_empty() || name.contains(['/', '\0']) {
            return Err(Errno::EINVAL);
        }
        let _op = self.op_lock.lock().await;
        self.check_rw_and_fence()?;
        let head = self.flush_locked().await?;
        let _gc = self.head_store.acquire_gc_lock(false).await?;
        let now = (self.clock)();
        self.head_store
            .create_snapshot(&self.volume_id, name, &head, now)
            .await
    }

    /// Create an O(1) persistent raw block volume fork from a named snapshot or current head.
    pub async fn fork_volume(
        &self,
        snapshot: Option<&str>,
        new_vol: VolumeId,
    ) -> Result<VolumeHead> {
        if new_vol.0.is_empty() || new_vol.0.contains(['/', '\0']) {
            return Err(Errno::EINVAL);
        }
        let _op = self.op_lock.lock().await;
        self.check_open()?;
        if !self.read_only && snapshot.is_none() {
            self.flush_locked().await?;
        }
        let _gc = self.head_store.acquire_gc_lock(false).await?;
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
            source_snapshot: snapshot.map(str::to_owned),
            source_root,
            new_volume: new_vol,
            ephemeral_if_unmodified: false,
            created_at: (self.clock)(),
        };
        self.head_store.fork_volume(&req).await
    }

    /// Flush dirty writes (propagating `ESTALE` if fenced!) and release writer lease / RO pin cleanly.
    pub async fn close_clean(&self) -> Result<()> {
        let _op = self.op_lock.lock().await;
        if self.state.borrow().closed {
            return Ok(());
        }
        let flush_res = if !self.read_only && self.state.borrow().is_dirty() {
            self.flush_locked().await.map(|_| ())
        } else {
            Ok(())
        };
        let (lease, ro_pin) = {
            let mut st = self.state.borrow_mut();
            st.closed = true;
            (st.lease.take(), st.ro_pin.take())
        };
        Self::release_handles(&*self.head_store, lease, ro_pin).await;
        flush_res
    }
}

/// `/dev/vdN` [`VolumeDevice`] wrapper exposing raw byte I/O (`pread`/`pwrite`/`fsync`/`trim`)
/// and volume management ioctls (`BLK_INFO`, `BLK_LEASE`, `COWFS_IOC_*`) over a [`RawBlockVolume`].
pub struct RawBlockVolumeDevice<H: HeadStore + 'static, P: PackStore + 'static> {
    volume: Rc<RawBlockVolume<H, P>>,
}

impl<H: HeadStore + 'static, P: PackStore + 'static> RawBlockVolumeDevice<H, P> {
    pub fn new(volume: Rc<RawBlockVolume<H, P>>) -> Self {
        Self { volume }
    }

    pub fn raw_volume(&self) -> &Rc<RawBlockVolume<H, P>> {
        &self.volume
    }
}

impl<H: HeadStore + 'static, P: PackStore + 'static> VolumeDevice for RawBlockVolumeDevice<H, P> {
    fn volume_id(&self) -> &str {
        &self.volume.volume_id().0
    }

    fn is_read_only(&self) -> bool {
        self.volume.is_read_only()
    }

    fn is_raw_block(&self) -> bool {
        true
    }

    fn read_raw<'a>(&'a self, buf: &'a mut [u8], offset: u64) -> BoxFuture<'a, usize> {
        Box::pin(async move { self.volume.read_at(offset, buf).await })
    }

    fn write_raw<'a>(&'a self, buf: &'a [u8], offset: u64) -> BoxFuture<'a, usize> {
        Box::pin(async move { self.volume.write_at(offset, buf).await })
    }

    fn sync_raw(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move { self.volume.flush().await.map(|_| ()) })
    }

    fn trim_raw(&self, offset: u64, len: u64) -> BoxFuture<'_, ()> {
        Box::pin(async move { self.volume.trim(offset, len).await })
    }

    fn blk_info<'a>(&'a self, dev_name: &'a str) -> BoxFuture<'a, BlkInfoResp> {
        Box::pin(async move {
            let info = self.volume.info();
            Ok(BlkInfoResp {
                device: format!("/dev/{dev_name}"),
                volume: info.volume,
                size: info.size_bytes,
                sector: info.block_size,
                writer_model: self.volume.writer_model,
                durability: self.volume.durability,
                read_only: info.read_only,
                formatted: true,
            })
        })
    }

    fn blk_lease(&self) -> BoxFuture<'_, BlkLeaseResp> {
        Box::pin(async move {
            let st = self.volume.fencing_state();
            Ok(BlkLeaseResp {
                volume: self.volume.volume_id().0.clone(),
                held: st.held,
                fenced: st.fenced,
                expired: st.expired,
                lease_expires_at: st.lease_expires_at,
                incarnation: st.incarnation,
                fence: st.fence,
                epoch: st.epoch,
                read_only: st.read_only,
            })
        })
    }

    fn cowfs_info(&self) -> BoxFuture<'_, CowfsInfoResp> {
        Box::pin(async move {
            let info = self.volume.info();
            let head = self.volume.state.borrow().head.clone();
            Ok(CowfsInfoResp {
                snapshot: self.volume.pinned_snapshot.clone(),
                format_version: head.format_version,
                volume: info.volume,
                root: digest_to_hex(&info.root),
                incarnation: info.incarnation,
                fence: info.fence,
                epoch: info.epoch,
                writer_model: self.volume.writer_model,
                durability: self.volume.durability,
                read_only: info.read_only,
                parent_volume: head.parent_volume.map(|v| v.0),
            })
        })
    }

    fn cowfs_fsck<'a>(&'a self, req: &'a CowfsFsckReq) -> BoxFuture<'a, CowfsFsckResp> {
        Box::pin(async move {
            let target = req
                .volume
                .as_ref()
                .map(|v| VolumeId(v.clone()))
                .unwrap_or_else(|| self.volume.volume_id().clone());
            let (head, report) = crate::fsck::verify_view(
                &*self.volume.head_store,
                &*self.volume.pack_store,
                &target,
                req.snapshot.as_deref(),
                None,
            )
            .await?;
            Ok(CowfsFsckResp {
                ok: report.ok,
                volume: head.volume.0,
                format_version: head.format_version,
                epoch: head.epoch,
                root: digest_to_hex(&head.root),
                subvols_checked: report.subvols_checked,
                nodes_verified: report.nodes_verified,
                extents_verified: report.extents_verified,
                packs_verified: report.packs_verified,
                orphan_inodes: report.orphan_inodes,
                errors: report.errors,
            })
        })
    }

    fn cowfs_snapshot<'a>(&'a self, req: &'a CowfsSnapshotReq) -> BoxFuture<'a, CowfsSnapshotResp> {
        Box::pin(async move {
            let snap = self.volume.create_snapshot(&req.name).await?;
            Ok(CowfsSnapshotResp {
                volume: snap.volume.0,
                name: snap.name,
                root: digest_to_hex(&snap.root),
                epoch: snap.epoch,
            })
        })
    }

    fn cowfs_fork<'a>(&'a self, req: &'a CowfsForkReq) -> BoxFuture<'a, CowfsForkResp> {
        Box::pin(async move {
            let forked = self
                .volume
                .fork_volume(req.snapshot.as_deref(), VolumeId(req.new_volume.clone()))
                .await?;
            Ok(CowfsForkResp {
                volume: forked.volume.0,
                parent_volume: forked
                    .parent_volume
                    .map(|v| v.0)
                    .unwrap_or_else(|| self.volume.volume_id().0.clone()),
                root: digest_to_hex(&forked.root),
                epoch: forked.epoch,
            })
        })
    }

    fn mkfs(&self, _force: bool) -> BoxFuture<'_, CowfsInfoResp> {
        Box::pin(async { Err(Errno::EBUSY) })
    }

    fn cowfs_snap_list(&self) -> BoxFuture<'_, CowfsSnapListResp> {
        Box::pin(async move {
            let snaps = self
                .volume
                .head_store
                .list_snapshots(self.volume.volume_id())
                .await?;
            Ok(CowfsSnapListResp {
                volume: self.volume.volume_id().0.clone(),
                snapshots: snaps
                    .into_iter()
                    .map(|s| CowfsSnapEntry {
                        name: s.name,
                        root: digest_to_hex(&s.root),
                        epoch: s.epoch,
                        created_ms: s
                            .created_at
                            .sec
                            .saturating_mul(1000)
                            .saturating_add(u64::from(s.created_at.nsec) / 1_000_000),
                    })
                    .collect(),
            })
        })
    }

    fn cowfs_snap_delete<'a>(&'a self, req: &'a CowfsSnapDeleteReq) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let _op = self.volume.op_lock.lock().await;
            self.volume.check_rw_and_fence()?;
            if req.name.is_empty() || req.name.contains(['/', '\0']) {
                return Err(Errno::EINVAL);
            }
            let head = self.volume.state.borrow().head.clone();
            let res = self
                .volume
                .head_store
                .delete_snapshot_checked(&head, &req.name)
                .await;
            if res == Err(Errno::ESTALE) {
                self.volume.state.borrow_mut().fenced = true;
            }
            res
        })
    }

    fn cowfs_gc<'a>(&'a self, req: &'a CowfsGcReq) -> BoxFuture<'a, CowfsGcResp> {
        Box::pin(async move {
            if self.volume.is_read_only() {
                return Err(Errno::EROFS);
            }
            let now = (self.volume.clock)();
            let report = match req.grace_window_secs {
                Some(g) => {
                    crate::gc::collect_garbage_with_grace(
                        &*self.volume.head_store,
                        &*self.volume.pack_store,
                        now,
                        g,
                    )
                    .await?
                }
                None => {
                    crate::gc::collect_garbage(
                        &*self.volume.head_store,
                        &*self.volume.pack_store,
                        now,
                    )
                    .await?
                }
            };
            Ok(CowfsGcResp {
                live_roots: report.live_roots,
                live_nodes: report.live_nodes,
                live_blocks: report.live_blocks,
                live_packs: report.live_packs,
                swept_packs: report.swept_packs.into_iter().map(|p| p.0).collect(),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::{CowFs, CowFsConfig, CowFsOpenMode};
    use crate::ioctl::CowFsVolumeDevice;
    use cowtree::memory::{MemoryHeadStore, MemoryPackStore};
    use std::cell::Cell;
    use vfs::devfs::{DefaultDeviceBackend, DevTmpFs};
    use vfs::memfs::MemFs;
    use vfs::vblk::{VblkDeviceBackend, VblkRegistry};
    use vfs::{
        Cred, DefaultFilesystemFactory, Filesystem, FsId, FsType, MountBacking, MountFlags,
        StartAnchor, Vfs, now_or_never,
    };

    fn run<F: std::future::Future>(f: F) -> F::Output {
        now_or_never(f).expect("sync memory store future")
    }

    fn test_clock() -> CowFsClock {
        Rc::new(|| Timespec {
            sec: 1_700_000_000,
            nsec: 0,
        })
    }

    #[test]
    fn raw_volume_feature_isolation_partial_rmw_and_zero_copy_split() {
        let hs = Rc::new(MemoryHeadStore::new());
        let ps = Rc::new(MemoryPackStore::new());
        let clock = test_clock();
        let now = (clock)();

        let raw_id = VolumeId("raw-vol-1".into());
        let posix_id = VolumeId("posix-vol-1".into());

        // Format both a raw block volume and a POSIX CowFs volume.
        run(RawBlockVolume::format(
            &*hs,
            &*ps,
            raw_id.clone(),
            64 * 1024,
            4096,
            0,
            now,
        ))
        .unwrap();
        run(CowFs::format_volume(
            &*hs,
            &*ps,
            posix_id.clone(),
            0,
            0,
            0o755,
            now,
        ))
        .unwrap();

        // Feature isolation: CowFs rejects RAW_BLOCK (EINVAL); RawBlockVolume rejects POSIX (EOPNOTSUPP).
        assert_eq!(
            run(CowFs::open(
                Rc::clone(&hs),
                Rc::clone(&ps),
                raw_id.clone(),
                CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
                CowFsConfig::local_native(Rc::clone(&clock)),
            ))
            .err(),
            Some(Errno::EINVAL)
        );
        assert_eq!(
            run(RawBlockVolume::open(
                Rc::clone(&hs),
                Rc::clone(&ps),
                posix_id.clone(),
                RawBlockOpenMode::ReadWrite(WriterMode::Exclusive),
                RawBlockConfig::local_native(Rc::clone(&clock)),
            ))
            .err(),
            Some(Errno::EOPNOTSUPP)
        );

        let vol = run(RawBlockVolume::open(
            Rc::clone(&hs),
            Rc::clone(&ps),
            raw_id.clone(),
            RawBlockOpenMode::ReadWrite(WriterMode::Exclusive),
            RawBlockConfig::local_native(Rc::clone(&clock)),
        ))
        .unwrap();

        // Sparse reads return zeroes.
        let mut buf = vec![0xaa; 8192];
        assert_eq!(run(vol.read_at(0, &mut buf)).unwrap(), 8192);
        assert!(buf.iter().all(|&b| b == 0));

        // Write a contiguous 4-sector (16 KiB) extent at offset 0.
        let mut initial = vec![0u8; 16 * 1024];
        for (i, b) in initial.iter_mut().enumerate() {
            *b = ((i / 4096) as u8 + 1) * 0x11;
        }
        assert_eq!(run(vol.write_at(0, &initial)).unwrap(), 16 * 1024);
        run(vol.flush()).unwrap();

        // Inspect original extent digest before interior trim/overwrite.
        let head1 = run(hs.read_head(&raw_id)).unwrap();
        let root1 =
            RootObject::decode_verified(&head1.root, &run(hs.get_node(&head1.root)).unwrap())
                .unwrap();
        let arena = RefCell::new(Arena::new(ArenaConfig::platform_default()));
        let tree = CowTree::new(&*hs, &arena);
        let raw_ext0 = run(tree.get(&root1.subvols[DEFAULT_SUBVOL], &TreeKey::raw_lba_extent(0)))
            .unwrap()
            .unwrap();
        let orig_digest = match ExtentDataValue::decode(&raw_ext0).unwrap() {
            ExtentDataValue::Extent {
                len: 16384,
                digest,
                block_offset: 0,
            } => digest,
            other => panic!("unexpected extent: {other:?}"),
        };

        // Trim middle sector [4096..8192): must split into [0..4096) and [8192..16384) reusing orig_digest!
        run(vol.trim(4096, 4096)).unwrap();
        run(vol.flush()).unwrap();

        let head2 = run(hs.read_head(&raw_id)).unwrap();
        let root2 =
            RootObject::decode_verified(&head2.root, &run(hs.get_node(&head2.root)).unwrap())
                .unwrap();
        let left = ExtentDataValue::decode(
            &run(tree.get(&root2.subvols[DEFAULT_SUBVOL], &TreeKey::raw_lba_extent(0)))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let right = ExtentDataValue::decode(
            &run(tree.get(
                &root2.subvols[DEFAULT_SUBVOL],
                &TreeKey::raw_lba_extent(8192),
            ))
            .unwrap()
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            left,
            ExtentDataValue::Extent {
                len: 4096,
                digest: orig_digest,
                block_offset: 0
            }
        );
        assert_eq!(
            right,
            ExtentDataValue::Extent {
                len: 8192,
                digest: orig_digest,
                block_offset: 8192
            }
        );

        // Partial unaligned write across sector boundary [4090..4110).
        let patch = b"0123456789abcdefghij";
        assert_eq!(run(vol.write_at(4090, patch)).unwrap(), 20);
        let mut readback = vec![0u8; 32];
        assert_eq!(run(vol.read_at(4086, &mut readback)).unwrap(), 32);
        assert_eq!(&readback[..4], &[0x11; 4]);
        assert_eq!(&readback[4..24], patch);
        assert_eq!(&readback[24..32], &[0u8; 8]);

        // Unaligned write_zeroes across [4094..4106).
        run(vol.write_zeroes(4094, 12)).unwrap();
        let mut after_zero = vec![0u8; 20];
        assert_eq!(run(vol.read_at(4090, &mut after_zero)).unwrap(), 20);
        assert_eq!(&after_zero[..4], b"0123");
        assert_eq!(&after_zero[4..16], &[0u8; 12]);
        assert_eq!(&after_zero[16..20], b"ghij");

        // Snapshot, fork, fsck, and GC all work cleanly!
        let snap = run(vol.create_snapshot("s1")).unwrap();
        assert_eq!(snap.name, "s1");
        let report = run(crate::fsck::verify_volume(&*hs, &*ps, &raw_id)).unwrap();
        assert!(report.ok, "fsck errors: {:?}", report.errors);
        assert!(report.extents_verified >= 2);

        let fork_id = VolumeId("raw-vol-fork".into());
        run(vol.fork_volume(Some("s1"), fork_id.clone())).unwrap();
        let fork_vol = run(RawBlockVolume::open(
            Rc::clone(&hs),
            Rc::clone(&ps),
            fork_id.clone(),
            RawBlockOpenMode::ReadOnly,
            RawBlockConfig::local_native(Rc::clone(&clock)),
        ))
        .unwrap();
        let mut fork_check = vec![0u8; 20];
        assert_eq!(run(fork_vol.read_at(4090, &mut fork_check)).unwrap(), 20);
        assert_eq!(fork_check, after_zero);
        assert_eq!(run(fork_vol.write_at(0, b"nope")), Err(Errno::EROFS));

        let gc = run(crate::gc::collect_garbage(&*hs, &*ps, now)).unwrap();
        assert!(gc.live_blocks >= 1);

        run(fork_vol.close_clean()).unwrap();
        run(vol.close_clean()).unwrap();
    }

    #[test]
    fn raw_volume_sticky_fencing_and_vblk_dev_vdn_raw_io() {
        let hs = Rc::new(MemoryHeadStore::new());
        let ps = Rc::new(MemoryPackStore::new());
        let clock = test_clock();
        let now = (clock)();

        let raw_id = VolumeId("raw-dev-1".into());
        let obj_id = VolumeId("obj-dev-1".into());
        run(RawBlockVolume::format(
            &*hs,
            &*ps,
            raw_id.clone(),
            32 * 1024,
            4096,
            0,
            now,
        ))
        .unwrap();
        run(CowFs::format_volume(
            &*hs,
            &*ps,
            obj_id.clone(),
            0,
            0,
            0o755,
            now,
        ))
        .unwrap();

        let fenced_flag = Rc::new(Cell::new(false));
        let f_clone = Rc::clone(&fenced_flag);
        let raw_vol = Rc::new(
            run(RawBlockVolume::open(
                Rc::clone(&hs),
                Rc::clone(&ps),
                raw_id.clone(),
                RawBlockOpenMode::ReadWrite(WriterMode::Exclusive),
                RawBlockConfig::remote_fenced(Rc::clone(&clock)).with_fence_validator(Rc::new(
                    move || {
                        if f_clone.get() {
                            Err(Errno::ESTALE)
                        } else {
                            Ok(())
                        }
                    },
                )),
            ))
            .unwrap(),
        );
        let obj_fs = Rc::new(
            run(CowFs::open(
                Rc::clone(&hs),
                Rc::clone(&ps),
                obj_id.clone(),
                CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
                CowFsConfig::local_native(Rc::clone(&clock)),
            ))
            .unwrap(),
        );

        let vblk = Rc::new(VblkRegistry::new());
        vblk.attach_named(
            "vd0",
            Rc::new(CowFsVolumeDevice::from_mounted(Rc::clone(&obj_fs))),
        )
        .unwrap();
        vblk.attach_named(
            "vd1",
            Rc::new(RawBlockVolumeDevice::new(Rc::clone(&raw_vol))),
        )
        .unwrap();

        let dev_fs = Rc::new(DevTmpFs::new(
            FsId("devtmpfs".into()),
            1,
            Box::new(|| (1_700_000_000, 0)),
            VblkDeviceBackend::with_registry(DefaultDeviceBackend, Rc::clone(&vblk)),
        ));
        vblk.register_node(&dev_fs, "vd0", 0o600).unwrap();
        vblk.register_node(&dev_fs, "vd1", 0o600).unwrap();

        let root_fs = Rc::new(MemFs::new(
            FsId("root".into()),
            1,
            0,
            0,
            0o755,
            Box::new(|| (1_700_000_000, 0)),
        ));
        let factory = Rc::new(DefaultFilesystemFactory::new(Rc::new(|| {
            (1_700_000_000, 0)
        })));
        let vfs = run(Vfs::boot(
            "raw-vblk-test",
            Rc::new(MountBacking::new(root_fs, FsType::TmpFs)),
            "tmpfs",
            factory,
        ))
        .unwrap();
        run(vfs.mkdirat(1, StartAnchor::Root, "/dev", 0o755)).unwrap();
        run(vfs.mount_on_namespace(
            &vfs.system_namespace(),
            &Cred::root(),
            Rc::new(MountBacking::new(
                Rc::clone(&dev_fs) as Rc<dyn Filesystem>,
                FsType::DevTmpFs,
            )),
            None,
            "devtmpfs",
            "/dev",
            MountFlags::default(),
            0,
            None,
        ))
        .unwrap();

        // Object-native /dev/vd0 still refuses raw read/write with EOPNOTSUPP!
        let fd0 = run(vfs.openat(1, StartAnchor::Root, "/dev/vd0", abi::O_RDWR, 0)).unwrap();
        let mut scratch = [0u8; 16];
        assert_eq!(
            run(vfs.pread(1, fd0, &mut scratch, 0)),
            Err(Errno::EOPNOTSUPP)
        );
        assert_eq!(run(vfs.pwrite(1, fd0, b"abc", 0)), Err(Errno::EOPNOTSUPP));
        run(vfs.close(1, fd0)).unwrap();

        // Raw block /dev/vd1 supports pread/pwrite/fsync!
        let fd1 = run(vfs.openat(1, StartAnchor::Root, "/dev/vd1", abi::O_RDWR, 0)).unwrap();
        assert_eq!(
            run(vfs.pwrite(1, fd1, b"hello raw vblk!", 512)).unwrap(),
            15
        );
        run(vfs.fsync(1, fd1)).unwrap();
        assert_eq!(run(vfs.pread(1, fd1, &mut scratch, 512)).unwrap(), 16);
        assert_eq!(&scratch[..15], b"hello raw vblk!");
        assert_eq!(scratch[15], 0);

        // Append write rejected with EINVAL.
        let fd1_app = run(vfs.openat(
            1,
            StartAnchor::Root,
            "/dev/vd1",
            abi::O_WRONLY | abi::O_APPEND,
            0,
        ))
        .unwrap();
        assert_eq!(run(vfs.write(1, fd1_app, b"x")), Err(Errno::EINVAL));
        run(vfs.close(1, fd1_app)).unwrap();

        // Trip external fence validator -> sticky ESTALE even if flag resets back to false!
        fenced_flag.set(true);
        assert_eq!(run(vfs.pwrite(1, fd1, b"stale", 0)), Err(Errno::ESTALE));
        fenced_flag.set(false);
        assert_eq!(
            run(vfs.pwrite(1, fd1, b"still-stale", 0)),
            Err(Errno::ESTALE)
        );
        assert_eq!(run(vfs.fsync(1, fd1)), Err(Errno::ESTALE));
        assert!(raw_vol.fencing_state().fenced);
        run(vfs.close(1, fd1)).unwrap();

        // RO raw block device rejects O_RDWR open with EROFS!
        let ro_raw = Rc::new(
            run(RawBlockVolume::open(
                Rc::clone(&hs),
                Rc::clone(&ps),
                raw_id.clone(),
                RawBlockOpenMode::ReadOnly,
                RawBlockConfig::local_native(Rc::clone(&clock)),
            ))
            .unwrap(),
        );
        vblk.attach_named(
            "vd2",
            Rc::new(RawBlockVolumeDevice::new(Rc::clone(&ro_raw))),
        )
        .unwrap();
        vblk.register_node(&dev_fs, "vd2", 0o600).unwrap();
        assert_eq!(
            run(vfs.openat(1, StartAnchor::Root, "/dev/vd2", abi::O_RDWR, 0)),
            Err(Errno::EROFS)
        );
        let fd2 = run(vfs.openat(1, StartAnchor::Root, "/dev/vd2", abi::O_RDONLY, 0)).unwrap();
        let mut ro_buf = [0u8; 15];
        assert_eq!(run(vfs.pread(1, fd2, &mut ro_buf, 512)).unwrap(), 15);
        assert_eq!(&ro_buf, b"hello raw vblk!");
        run(vfs.close(1, fd2)).unwrap();

        run(ro_raw.close_clean()).unwrap();
        run(raw_vol.close_clean()).unwrap();
        run(obj_fs.close_clean()).unwrap();
    }

    #[test]
    fn raw_volume_close_clean_propagates_estale_and_snapshot_fencing() {
        let hs = Rc::new(MemoryHeadStore::new());
        let ps = Rc::new(MemoryPackStore::new());
        let clock = test_clock();
        let now = (clock)();
        let vid = VolumeId("raw-fence-close".into());
        run(RawBlockVolume::format(
            &*hs,
            &*ps,
            vid.clone(),
            32 * 1024,
            4096,
            0,
            now,
        ))
        .unwrap();

        // RO volume cannot create snapshots.
        let ro = run(RawBlockVolume::open(
            Rc::clone(&hs),
            Rc::clone(&ps),
            vid.clone(),
            RawBlockOpenMode::ReadOnly,
            RawBlockConfig::local_native(Rc::clone(&clock)),
        ))
        .unwrap();
        assert_eq!(run(ro.create_snapshot("ro-snap")).err(), Some(Errno::EROFS));
        run(ro.close_clean()).unwrap();

        // RW volume creates a snapshot while unfenced, then writes dirty data and gets fenced.
        let fenced_flag = Rc::new(Cell::new(false));
        let f_clone = Rc::clone(&fenced_flag);
        let rw = Rc::new(
            run(RawBlockVolume::open(
                Rc::clone(&hs),
                Rc::clone(&ps),
                vid.clone(),
                RawBlockOpenMode::ReadWrite(WriterMode::Exclusive),
                RawBlockConfig::remote_fenced(Rc::clone(&clock)).with_fence_validator(Rc::new(
                    move || {
                        if f_clone.get() {
                            Err(Errno::ESTALE)
                        } else {
                            Ok(())
                        }
                    },
                )),
            ))
            .unwrap(),
        );
        run(rw.create_snapshot("s0")).unwrap();
        run(rw.write_at(0, b"dirty-unflushed-block")).unwrap();

        // Trip external fence while buffer is dirty.
        fenced_flag.set(true);
        assert_eq!(run(rw.create_snapshot("s1")).err(), Some(Errno::ESTALE));

        // cowfs_snap_delete via VolumeDevice must also fail closed with ESTALE when fenced.
        let dev = RawBlockVolumeDevice::new(Rc::clone(&rw));
        assert_eq!(
            run(dev.cowfs_snap_delete(&abi::volume::CowfsSnapDeleteReq { name: "s0".into() }))
                .err(),
            Some(Errno::ESTALE)
        );

        // close_clean MUST propagate ESTALE when dirty & fenced (even though fenced is already true).
        assert_eq!(run(rw.close_clean()), Err(Errno::ESTALE));
    }
}

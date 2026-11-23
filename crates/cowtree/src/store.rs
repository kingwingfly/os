//! Pluggable `HeadStore` and `PackStore` traits and wire-portable metadata types shared by
//! browser OPFS+IDB, native SQLite+packs, test-only `MemoryHeadStore`, and future remote R2+DO
//! (#80) / OCI (#81) backends.

use abi::fs::Timespec;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use vfs::BoxFuture;

/// Lowercase 32-byte SHA-256 content address for CoW B+tree nodes and 64 KiB data blocks/extents.
pub type Digest = [u8; 32];

/// Stable volume UUID (`os-vol:<uuid>`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct VolumeId(pub String);

/// Content-addressed immutable pack identifier (64-char lowercase SHA-256 hex of pack bytes).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PackId(pub String);

/// Committed volume head. Uses `(incarnation, fence, epoch)` for both local Web Lock/flock
/// fencing (`fence = local_fence`) and remote R2+DO triple-fencing (#80) with zero conversion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeHead {
    pub format_version: u32,
    pub volume: VolumeId,
    /// Rotated on restore/re-seed; never decremented.
    pub incarnation: u64,
    /// Monotonic writer grant counter (`local_fence` locally; DO grant fence remotely).
    pub fence: u64,
    /// Monotonic commit counter; CAS requires `epoch == expected_epoch` -> `epoch + 1`.
    pub epoch: u64,
    /// SHA-256 root digest of the single-map CoW B+tree (`[0; 32]` forbidden after mkfs).
    pub root: Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_volume: Option<VolumeId>,
    /// True for concurrent-tab auto-forks: pruned on clean shutdown if `modified == false`.
    #[serde(default)]
    pub ephemeral_if_unmodified: bool,
    #[serde(default)]
    pub modified: bool,
    pub updated_at: Timespec,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WriterMode {
    /// Fail with `Errno::EBUSY` if another writer holds `os-vol:<uuid>` / `flock`.
    Exclusive,
    /// If held by another tab/host, atomically fork the last committed head (`O(1)`).
    ForkOnBusy,
    /// Increment `fence` to take over writer rights, fencing the prior holder with `ESTALE`.
    ForceTakeover,
}

/// RAII guard holding the profile Web Lock (`os-vol:<uuid>`) or native exclusive `flock`.
pub trait WriterLockGuard {
    /// Optional backend-specific lease identifier (used by the JS Web Lock adapter for atomic
    /// lease-validated delete/reformat).
    fn lease_id(&self) -> Option<&str> {
        None
    }
}

/// RAII guard for GC coordination: commits take shared (`exclusive = false`),
/// sweep takes exclusive (`exclusive = true`).
pub trait GcLockGuard {}

/// RAII guard keeping an open read-only or snapshot mount's root digest pinned against GC.
pub trait RoPinGuard {}

pub struct WriterLease {
    pub volume: VolumeId,
    pub incarnation: u64,
    pub fence: u64,
    pub epoch: u64,
    pub head: VolumeHead,
    /// `Some(source)` if `WriterMode::ForkOnBusy` created an O(1) persistent fork for this caller.
    pub forked_from: Option<VolumeId>,
    /// `None` for local Web Lock / flock; `Some(deadline)` for 60s remote DO leases (#80).
    pub expires_at: Option<Timespec>,
    pub guard: Box<dyn WriterLockGuard>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockLoc {
    pub pack_id: PackId,
    pub offset: u32,
    /// Stored byte length in the pack.
    pub len: u32,
    /// Uncompressed logical byte length (`<= 1 MiB`).
    pub raw_len: u32,
    /// Bit 0 = zstd/lz4 reserved (0 = raw in v1).
    pub flags: u16,
}

impl BlockLoc {
    pub fn validate_v1(&self) -> vfs::Result<()> {
        if self.flags != 0
            || self.len == 0
            || self.raw_len != self.len
            || self.len > crate::EXTENT_MAX_BYTES
            || u64::from(self.offset) + u64::from(self.len) > crate::PACK_MAX_BYTES as u64
        {
            return Err(abi::Errno::EIO);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackMeta {
    pub pack_id: PackId,
    pub size: u32,
    pub entry_count: u32,
    pub created_at: Timespec,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackIndexEntry {
    pub digest: Digest,
    pub offset: u32,
    pub len: u32,
    pub raw_len: u32,
    pub flags: u16,
}

/// Self-describing trailer at the end of every immutable `<= 8 MiB` pack file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackTrailer {
    pub magic: [u8; 4],
    pub version: u16,
    pub entries: Vec<PackIndexEntry>,
    pub trailer_sha256: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitRequest {
    /// Idempotency key (`receipts[op_id]` prevents duplicate apply on retry).
    pub op_id: [u8; 16],
    pub volume: VolumeId,
    pub expected_incarnation: u64,
    pub expected_fence: u64,
    pub expected_epoch: u64,
    pub new_root: Digest,
    /// New immutable `<= 16 KiB` CoW B+tree nodes written in the same atomic transaction.
    pub put_nodes: Vec<(Digest, Vec<u8>)>,
    /// Pack metadata for packs already flushed + closed in `PackStore`.
    pub put_packs: Vec<PackMeta>,
    /// Block digest -> `BlockLoc` index entries for blocks in `put_packs`.
    pub put_blocks: Vec<(Digest, BlockLoc)>,
    pub committed_at: Timespec,
}

/// Atomic ingestion commit for `cowfs receive`: writes verified delta nodes/packs/blocks and
/// either updates an existing leased volume head (`expected_lease = Some((inc, fence, epoch))`)
/// or creates a brand-new volume head (`expected_lease = None`), optionally recording a named
/// snapshot in the exact same transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiveCommitRequest {
    pub op_id: [u8; 16],
    pub volume: VolumeId,
    /// `Some((incarnation, fence, epoch))` when updating an existing leased volume;
    /// `None` when atomically creating a brand-new volume head.
    pub expected_lease: Option<(u64, u64, u64)>,
    pub new_root: Digest,
    pub put_nodes: Vec<(Digest, Vec<u8>)>,
    pub put_packs: Vec<PackMeta>,
    pub put_blocks: Vec<(Digest, BlockLoc)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_name: Option<String>,
    pub committed_at: Timespec,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRecord {
    pub volume: VolumeId,
    pub name: String,
    pub root: Digest,
    pub epoch: u64,
    pub created_at: Timespec,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkRequest {
    pub source_volume: VolumeId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_snapshot: Option<String>,
    pub source_root: Digest,
    pub new_volume: VolumeId,
    pub ephemeral_if_unmodified: bool,
    pub created_at: Timespec,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcRoot {
    pub volume: VolumeId,
    pub root: Digest,
    pub pinned_until: Option<Timespec>,
}

/// Durable metadata, CoW B+tree node, pack index, snapshot, and fenced head CAS store.
/// Browser impl: IndexedDB (`{durability: "strict"}`) + Web Locks (`os-vol:<uuid>`).
/// Native impl: SQLite (`WAL`, `synchronous=FULL`) + `flock`.
/// Test-only impl: `MemoryHeadStore` (never shipped as a `#56` fallback).
pub trait HeadStore {
    /// Inspect stored schema version before parsing any records.
    /// Caller MUST refuse any `Some(v)` where `v != COWFS_FORMAT_VERSION` with `EPROTONOSUPPORT`
    /// without resetting or mutating user data (contract §2.12).
    fn format_version(&self) -> BoxFuture<'_, Option<u32>>;

    fn create_volume<'a>(
        &'a self,
        head: &'a VolumeHead,
        initial_nodes: &'a [(Digest, Vec<u8>)],
    ) -> BoxFuture<'a, VolumeHead>;

    /// Configured GC grace window in seconds (default 600s).
    fn grace_window_secs(&self) -> u64;

    /// Read last committed head for RO mount or fork source (takes NO exclusive writer lock).
    fn read_head<'a>(&'a self, volume: &'a VolumeId) -> BoxFuture<'a, VolumeHead>;

    /// Enumerate all committed volume heads currently present in this store, sorted by `VolumeId`.
    fn list_volumes(&self) -> BoxFuture<'_, Vec<VolumeHead>> {
        Box::pin(async move {
            let roots = self.list_all_roots().await?;
            let mut seen = HashSet::new();
            let mut heads = Vec::new();
            for r in roots {
                if seen.insert(r.volume.clone())
                    && let Ok(head) = self.read_head(&r.volume).await
                {
                    heads.push(head);
                }
            }
            heads.sort_by(|a, b| a.volume.cmp(&b.volume));
            Ok(heads)
        })
    }

    /// Atomically ingest verified nodes/packs/blocks from `cowfs receive` and commit the target
    /// volume head (creating the volume when `expected_lease` is `None`, or CAS-updating an
    /// existing leased volume when `Some`), optionally recording `snapshot_name` in the same
    /// transaction.
    fn commit_received_root<'a>(
        &'a self,
        _req: &'a ReceiveCommitRequest,
    ) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async { Err(abi::Errno::EOPNOTSUPP) })
    }

    /// Store a bounded batch of immutable content under a shared GC guard. Only
    /// commit_received_root publishes ownership; exclusive GC reclaims unused content.
    fn stage_objects<'a>(
        &'a self,
        _nodes: &'a [(Digest, Vec<u8>)],
        _packs: &'a [PackMeta],
        _blocks: &'a [(Digest, BlockLoc)],
        _now: Timespec,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async { Err(abi::Errno::EOPNOTSUPP) })
    }

    fn check_no_readers<'a>(&'a self, _volume: &'a VolumeId) -> BoxFuture<'a, ()> {
        Box::pin(async { Err(abi::Errno::EOPNOTSUPP) })
    }

    fn delete_snapshot_checked<'a>(
        &'a self,
        _head: &'a VolumeHead,
        _name: &'a str,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async { Err(abi::Errno::EOPNOTSUPP) })
    }

    /// Atomically select `volume`'s committed head (or named `snapshot`), verify its root node
    /// exists, and register an active GC reader pin keeping that root reachable until unpinned
    /// or dropped.
    fn pin_ro_root<'a>(
        &'a self,
        volume: &'a VolumeId,
        snapshot: Option<&'a str>,
    ) -> BoxFuture<'a, (VolumeHead, Box<dyn RoPinGuard>)>;

    /// Release an active RO/snapshot root pin cleanly (also released automatically on drop).
    fn unpin_ro_root<'a>(&'a self, pin: Box<dyn RoPinGuard>) -> BoxFuture<'a, ()>;

    /// Acquire writer exclusion (`os-vol:<uuid>` / `flock`) and validate/bump fence per `mode`.
    fn acquire_writer<'a>(
        &'a self,
        volume: &'a VolumeId,
        mode: WriterMode,
    ) -> BoxFuture<'a, WriterLease>;

    fn renew_writer<'a>(&'a self, lease: &'a mut WriterLease) -> BoxFuture<'a, ()>;
    fn release_writer<'a>(&'a self, lease: WriterLease) -> BoxFuture<'a, ()>;

    /// Fetch a `<= 16 KiB` CoW B+tree node; caller verifies `sha256(bytes) == digest` (`EIO` on mismatch).
    fn get_node<'a>(&'a self, digest: &'a Digest) -> BoxFuture<'a, Vec<u8>>;

    /// Look up where a content-addressed data block/extent resides in `PackStore`.
    fn lookup_block<'a>(&'a self, digest: &'a Digest) -> BoxFuture<'a, Option<BlockLoc>>;

    /// Single atomic strict transaction:
    /// 1. Check `receipts[op_id]` (return recorded head if already applied).
    /// 2. Check `(incarnation, fence, epoch)` match -> `Err(Errno::ESTALE)` on mismatch.
    /// 3. Insert `put_nodes`, `put_packs`, `put_blocks`.
    /// 4. Advance `heads[volume] = { epoch + 1, root: new_root, modified: true, .. }`.
    ///
    /// Returns `Err(Errno::ENOSPC)` on quota exhaustion leaving committed head untouched.
    fn commit_head<'a>(&'a self, req: &'a CommitRequest) -> BoxFuture<'a, VolumeHead>;

    /// O(1) named snapshot (`name -> root_digest`), zero data bytes copied.
    fn create_snapshot<'a>(
        &'a self,
        volume: &'a VolumeId,
        name: &'a str,
        head: &'a VolumeHead,
        now: Timespec,
    ) -> BoxFuture<'a, SnapshotRecord>;

    fn get_snapshot<'a>(
        &'a self,
        volume: &'a VolumeId,
        name: &'a str,
    ) -> BoxFuture<'a, SnapshotRecord>;

    fn list_snapshots<'a>(&'a self, volume: &'a VolumeId) -> BoxFuture<'a, Vec<SnapshotRecord>>;

    fn delete_snapshot<'a>(&'a self, volume: &'a VolumeId, name: &'a str) -> BoxFuture<'a, ()>;

    /// O(1) persistent volume fork seeded at `source_root` (zero data bytes copied).
    fn fork_volume<'a>(&'a self, req: &'a ForkRequest) -> BoxFuture<'a, VolumeHead>;

    /// Delete a volume head, along with its snapshots and receipts, refusing if leased (`EBUSY`).
    fn delete_volume<'a>(&'a self, volume: &'a VolumeId) -> BoxFuture<'a, ()>;

    /// Atomically delete `lease.volume` (plus its snapshots and receipts) while holding `lease`,
    /// verifying stored `(incarnation, fence, epoch)` (`ESTALE` on mismatch). When
    /// `only_if_unmodified_ephemeral` is true, deletes ONLY if the stored head still has
    /// `ephemeral_if_unmodified && !modified` (returning `Ok(false)` without deleting otherwise).
    /// Always releases `lease` before returning.
    fn delete_volume_with_lease<'a>(
        &'a self,
        lease: WriterLease,
        only_if_unmodified_ephemeral: bool,
    ) -> BoxFuture<'a, bool>;

    /// Atomically replace an existing volume's head with a newly formatted head while holding its
    /// exclusive writer `lease`: verifies `(incarnation, fence, epoch)` (`ESTALE` on mismatch),
    /// deletes all prior snapshots and receipts for `lease.volume`, inserts `initial_nodes`, and
    /// bumps `incarnation = cur.incarnation + 1` (`fence = 1, epoch = 0`). Releases `lease`.
    fn reformat_volume_with_lease<'a>(
        &'a self,
        lease: WriterLease,
        new_head: &'a VolumeHead,
        initial_nodes: &'a [(Digest, Vec<u8>)],
    ) -> BoxFuture<'a, VolumeHead>;

    /// Reachability GC lock: `exclusive == false` for commits/forks/pins (waits while GC runs),
    /// `exclusive == true` for sweep (non-blocking `EBUSY` if writers are active).
    fn acquire_gc_lock(&self, exclusive: bool) -> BoxFuture<'_, Box<dyn GcLockGuard>>;

    /// Enumerate all reachable roots (live heads, snapshots, active RO pins, and grace pins).
    fn list_all_roots(&self) -> BoxFuture<'_, Vec<GcRoot>>;

    /// Enumerate all pack IDs currently referenced by `packs` or `blocks` metadata tables.
    fn list_indexed_packs(&self) -> BoxFuture<'_, HashSet<PackId>>;

    /// Prune abandoned unmodified ephemeral fork heads (`ephemeral_if_unmodified && !modified`)
    /// whose writer lock is not held and whose timestamp is older than `grace_window_secs` before
    /// `now`. Called by GC under the exclusive GC lock before marking.
    fn prune_abandoned_ephemeral_forks(
        &self,
        now: Timespec,
        grace_window_secs: u64,
    ) -> BoxFuture<'_, usize>;

    /// Remove expired grace pins (`pinned_until <= now`), unreachable nodes/packs whose
    /// `created_at` is at least `grace_window_secs` older than `now`, and aged receipts.
    /// Returns unreachable `PackId`s that the caller may now unlink from `PackStore`.
    fn sweep_metadata<'a>(
        &'a self,
        keep_nodes: &'a HashSet<Digest>,
        keep_packs: &'a HashSet<PackId>,
        now: Timespec,
        grace_window_secs: u64,
    ) -> BoxFuture<'a, Vec<PackId>>;
}

/// Immutable `<= 8 MiB` data pack store.
/// Browser impl: OPFS dedicated-Worker `FileSystemSyncAccessHandle` (`write` + `flush` + `close`)
/// for writes, and lock-free `getFile().slice(offset, offset + len)` for concurrent cross-tab reads.
/// Native impl: temp-file write + `sync_all()` + atomic rename + directory fsync; `pread` for reads.
pub trait PackStore {
    /// Persist an immutable pack (`bytes.len() <= PACK_MAX_BYTES`); never mutates an existing pack.
    /// Maps browser `QuotaExceededError` / host `ENOSPC` to `Errno::ENOSPC`.
    fn write_pack<'a>(&'a self, pack_id: &'a PackId, bytes: &'a [u8]) -> BoxFuture<'a, PackMeta>;

    /// Lock-free slice read; `CowFs` verifies `sha256` against the B+tree extent digest before
    /// exposing bytes (`Errno::EIO` on mismatch).
    fn read_pack_range<'a>(
        &'a self,
        pack_id: &'a PackId,
        offset: u32,
        len: u32,
    ) -> BoxFuture<'a, Vec<u8>>;

    /// Read and verify the pack's self-describing trailer index (for `cowfsck` / `send` / recovery).
    fn read_pack_trailer<'a>(&'a self, pack_id: &'a PackId) -> BoxFuture<'a, PackTrailer>;

    fn stat_pack<'a>(&'a self, pack_id: &'a PackId) -> BoxFuture<'a, Option<u64>>;
    fn list_packs(&self) -> BoxFuture<'_, Vec<PackId>>;
    fn delete_pack<'a>(&'a self, pack_id: &'a PackId) -> BoxFuture<'a, ()>;
}

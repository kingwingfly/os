//! Pluggable `HeadStore` and `PackStore` traits and wire-portable metadata types shared by
//! browser OPFS+IDB, native SQLite+packs, test-only `MemoryHeadStore`, and future remote R2+DO
//! (#80) / OCI (#81) backends.

use abi::fs::Timespec;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, rc::Rc};
use vfs::BoxFuture;

pub use abi::remote_volume::{
    BlockLoc, CommitRequest, Digest, ForkRequest, PackId, PackIndexEntry, PackMeta, PackTrailer,
    SnapshotRecord, VolumeHead, VolumeId, WriterMode,
};

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
pub trait RoPinGuard {
    fn retry_guard(&self) -> Option<Box<dyn RoPinGuard>> {
        None
    }
    fn pin_id(&self) -> Option<&str> {
        None
    }
    fn volume(&self) -> Option<&VolumeId> {
        None
    }
}

#[derive(Clone)]
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
    pub guard: Rc<dyn WriterLockGuard>,
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
pub struct GcRoot {
    pub volume: VolumeId,
    pub root: Digest,
    pub pinned_until: Option<Timespec>,
}

pub enum CommitOutcome {
    Committed(VolumeHead),
    Uncertain,
    Aborted(abi::Errno),
}
impl CommitOutcome {
    pub fn into_result(self) -> vfs::Result<VolumeHead> {
        match self {
            Self::Committed(head) => Ok(head),
            Self::Uncertain => Err(abi::Errno::EIO),
            Self::Aborted(e) => Err(e),
        }
    }
}

pub type Publication<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = CommitOutcome> + 'a>>;
pub type ScopedStores<H> = (Rc<H>, Rc<dyn PackStore>);
pub type PinnedView = (VolumeHead, Option<Box<dyn RoPinGuard>>);

/// Durable metadata, CoW B+tree node, pack index, snapshot, and fenced head CAS store.
/// Browser impl: IndexedDB (`{durability: "strict"}`) + Web Locks (`os-vol:<uuid>`).
/// Native impl: SQLite (`WAL`, `synchronous=FULL`) + `flock`.
/// Test-only impl: `MemoryHeadStore` (never shipped as a `#56` fallback).
pub trait HeadStore {
    fn scoped_stores(&self, _volume: &VolumeId) -> Option<ScopedStores<Self>>
    where
        Self: Sized,
    {
        None
    }

    /// Local stores stage an absent volume under the shared GC lock. A remote store needs
    /// a destination-specific reservation before it can accept staged packs.
    fn reserve_receive<'a>(&'a self, _volume: &'a VolumeId) -> BoxFuture<'a, Option<WriterLease>> {
        Box::pin(async { Ok(None) })
    }

    /// Select a traversal root under the caller's shared GC guard. Remote stores atomically
    /// select and pin it and return a renewable guard in place of local lock coverage.
    fn pin_view<'a>(
        &'a self,
        volume: &'a VolumeId,
        snapshot: Option<&'a str>,
        exact: Option<&'a VolumeHead>,
    ) -> BoxFuture<'a, PinnedView> {
        Box::pin(async move {
            let head = if let Some(name) = snapshot {
                let snap = self.get_snapshot(volume, name).await?;
                let mut head = self.read_head(volume).await?;
                head.root = snap.root;
                head.epoch = snap.epoch;
                head
            } else if let Some(h) = exact {
                h.clone()
            } else {
                self.read_head(volume).await?
            };
            Ok((head, None))
        })
    }
    fn repin_root<'a>(&'a self, _head: &'a VolumeHead) -> BoxFuture<'a, Box<dyn RoPinGuard>> {
        Box::pin(async { Err(abi::Errno::EOPNOTSUPP) })
    }
    fn writer_expired(&self) -> bool {
        false
    }

    fn pin_status(&self, _id: &str) -> (bool, Option<u64>) {
        (true, None)
    }

    fn prepare_publication<'a>(&'a self, _r: &'a mut CommitRequest) -> BoxFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn publish_commit<'a>(&'a self, r: &'a CommitRequest, _retry: bool) -> Publication<'a> {
        Box::pin(async move {
            match self.commit_head(r).await {
                Ok(h) => CommitOutcome::Committed(h),
                Err(abi::Errno::EIO | abi::Errno::ENOTCONN) => CommitOutcome::Uncertain,
                Err(e) => CommitOutcome::Aborted(e),
            }
        })
    }

    fn filesystem_identity(&self, volume: &VolumeId) -> String {
        format!("cowfs:{}", volume.0)
    }

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

    fn renew_ro_pin<'a>(&'a self, _volume: &'a VolumeId, _pin_id: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn run_server_gc(&self) -> BoxFuture<'_, Option<abi::volume::CowfsGcResp>> {
        Box::pin(async { Ok(None) })
    }
    /// Check the local deadline without performing I/O (remote writers only).
    fn check_writer_deadline(&self) -> vfs::Result<()> {
        Ok(())
    }

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

impl PackStore for Rc<dyn PackStore> {
    fn write_pack<'a>(&'a self, id: &'a PackId, bytes: &'a [u8]) -> BoxFuture<'a, PackMeta> {
        (**self).write_pack(id, bytes)
    }
    fn read_pack_range<'a>(
        &'a self,
        id: &'a PackId,
        offset: u32,
        len: u32,
    ) -> BoxFuture<'a, Vec<u8>> {
        (**self).read_pack_range(id, offset, len)
    }
    fn read_pack_trailer<'a>(&'a self, id: &'a PackId) -> BoxFuture<'a, PackTrailer> {
        (**self).read_pack_trailer(id)
    }
    fn stat_pack<'a>(&'a self, id: &'a PackId) -> BoxFuture<'a, Option<u64>> {
        (**self).stat_pack(id)
    }
    fn list_packs(&self) -> BoxFuture<'_, Vec<PackId>> {
        (**self).list_packs()
    }
    fn delete_pack<'a>(&'a self, id: &'a PackId) -> BoxFuture<'a, ()> {
        (**self).delete_pack(id)
    }
}

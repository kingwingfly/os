//! Merkle Delta Stream v1 (`OSCOWS1\0`) streaming `send` / `receive` engine for `os-cowfs`
//! (`docs/architecture/contract.md` §2.15, §2.16; #79 `L2.5c`).
//!
//! - `send_snapshot`: streams canonical post-order `OSCOWS1\0` records (or `.cowpack` archives
//!   when `archive == true`), skipping unchanged Merkle subtrees (`subtrees_skipped += 1`)
//!   without descending into identical child nodes when `--parent` is supplied.
//! - `receive_snapshot`: verifies every node/block SHA-256 and running stream SHA-256 while
//!   flushing `<= 8 MiB` packs incrementally, verifies the entire resulting Merkle tree via
//!   `fsck::verify_root_reachable` BEFORE committing, and updates the destination volume head
//!   (and optional named snapshot) in one atomic transaction — leaving zero head/snapshot
//!   mutation on truncation, bit-flip (`EIO`), or missing parent (`ENOENT`).

use crate::archive_pack;
use crate::inode::ExtentDataValue;
use abi::Errno;
use abi::fs::Timespec;
use abi::volume::{CowfsReceiveResp, CowfsSendResp};
use cowtree::pack::verify_block_digest;
use cowtree::stream::{
    STREAM_CHUNK_BYTES, StreamDecoder, StreamEncoder, StreamEvent, StreamHeader,
};
use cowtree::{
    BlockLoc, COWFS_FORMAT_VERSION, CommitRequest, Digest, ForkRequest, GcLockGuard, GcRoot,
    HeadStore, KIND_EXTENT_DATA, Node, PackBuilder, PackId, PackMeta, PackStore,
    ReceiveCommitRequest, RoPinGuard, RootObject, SnapshotRecord, VolumeHead, VolumeId,
    WriterLease, WriterMode, digest_to_hex, sha256,
};
use std::collections::{HashMap, HashSet};
use vfs::{BoxFuture, FileRef, Result};

/// Streaming byte sink used by `send_snapshot` and `export_archive_pack`.
pub trait StreamSink {
    fn write_chunk<'a>(&'a mut self, data: &'a [u8]) -> BoxFuture<'a, usize>;
}

/// Streaming byte source used by `receive_snapshot`.
pub trait StreamSource {
    fn read_chunk<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, usize>;
}

/// [`StreamSink`] writing sequentially to an open kernel [`vfs::FileRef`].
pub struct FileRefSink(pub FileRef);

impl StreamSink for FileRefSink {
    fn write_chunk<'a>(&'a mut self, data: &'a [u8]) -> BoxFuture<'a, usize> {
        Box::pin(async move { self.0.write(data).await })
    }
}

/// [`StreamSource`] reading sequentially from an open kernel [`vfs::FileRef`].
pub struct FileRefSource(pub FileRef);

impl StreamSource for FileRefSource {
    fn read_chunk<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, usize> {
        Box::pin(async move { self.0.read(buf).await })
    }
}

/// In-memory [`StreamSink`] accumulating bytes into a `Vec<u8>`.
#[derive(Default)]
pub struct VecSink(pub Vec<u8>);

impl StreamSink for VecSink {
    fn write_chunk<'a>(&'a mut self, data: &'a [u8]) -> BoxFuture<'a, usize> {
        Box::pin(async move {
            self.0.extend_from_slice(data);
            Ok(data.len())
        })
    }
}

/// In-memory [`StreamSource`] yielding bounded slices from `&[u8]`.
pub struct SliceSource<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> SliceSource<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
}

impl StreamSource for SliceSource<'_> {
    fn read_chunk<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, usize> {
        Box::pin(async move {
            let rem = self.bytes.len().saturating_sub(self.pos);
            if rem == 0 || buf.is_empty() {
                return Ok(0);
            }
            let n = rem.min(buf.len());
            buf[..n].copy_from_slice(&self.bytes[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        })
    }
}

/// Write `data` to `sink` in chunks of at most `STREAM_CHUNK_BYTES` (`64 KiB`).
pub async fn write_all_chunked<S: StreamSink>(sink: &mut S, mut data: &[u8]) -> Result<u64> {
    let mut written = 0u64;
    while !data.is_empty() {
        let take = data.len().min(STREAM_CHUNK_BYTES);
        let n = sink.write_chunk(&data[..take]).await?;
        if n == 0 {
            return Err(Errno::EIO);
        }
        written = written.saturating_add(n as u64);
        data = &data[n..];
    }
    Ok(written)
}

async fn collect_parent_digests<H: HeadStore>(
    head_store: &H,
    parent_root: Digest,
) -> Result<(HashSet<Digest>, HashSet<Digest>)> {
    let mut parent_nodes: HashSet<Digest> = HashSet::new();
    let mut parent_blocks: HashSet<Digest> = HashSet::new();

    let raw_root = head_store.get_node(&parent_root).await?;
    let root_obj = RootObject::decode_verified(&parent_root, &raw_root)?;
    parent_nodes.insert(parent_root);

    for sv_root in root_obj.subvols.values() {
        let mut stack = vec![*sv_root];
        while let Some(digest) = stack.pop() {
            if !parent_nodes.insert(digest) {
                continue;
            }
            let raw = head_store.get_node(&digest).await?;
            let node = Node::decode_verified(&digest, &raw)?;
            match node {
                Node::Internal { entries, .. } => {
                    for entry in entries {
                        if !parent_nodes.contains(&entry.child) {
                            stack.push(entry.child);
                        }
                    }
                }
                Node::Leaf { entries } => {
                    for entry in entries {
                        if entry.key.kind != KIND_EXTENT_DATA {
                            continue;
                        }
                        if let ExtentDataValue::Extent { digest: bdig, .. } =
                            ExtentDataValue::decode(&entry.value)?
                        {
                            parent_blocks.insert(bdig);
                        }
                    }
                }
            }
        }
    }

    Ok((parent_nodes, parent_blocks))
}

/// Emit a full or incremental `OSCOWS1\0` Merkle delta stream — or a self-verifying `.cowpack`
/// (`OSCOWA1\0`) archive when `archive == true` — for `snapshot` (or current head when `snapshot`
/// is `""` or `"@"`).
///
/// When `pinned_head` is `Some`, sending `""` / `"@"` exports that exact pinned root (used for
/// read-only/snapshot mounts).
#[allow(clippy::too_many_arguments)]
pub async fn send_snapshot<H: HeadStore, P: PackStore, S: StreamSink>(
    head_store: &H,
    pack_store: &P,
    volume: &VolumeId,
    pinned_head: Option<&VolumeHead>,
    snapshot: &str,
    parent: Option<&str>,
    archive: bool,
    sink: &mut S,
) -> Result<CowfsSendResp> {
    if let Some(ver) = head_store.format_version().await?
        && ver != COWFS_FORMAT_VERSION
    {
        return Err(Errno::EPROTONOSUPPORT);
    }

    let _gc_guard = head_store.acquire_gc_lock(false).await?;

    let snapshot_label = if snapshot.is_empty() { "@" } else { snapshot };
    let target_root = if snapshot.is_empty() || snapshot == "@" {
        match pinned_head {
            Some(h) => h.root,
            None => head_store.read_head(volume).await?.root,
        }
    } else {
        head_store.get_snapshot(volume, snapshot).await?.root
    };

    if archive {
        if parent.is_some() {
            return Err(Errno::EINVAL);
        }
        return archive_pack::export_archive_pack(
            head_store,
            pack_store,
            volume,
            snapshot_label,
            target_root,
            sink,
        )
        .await;
    }

    let parent_root = match parent {
        Some(p_name) => {
            if p_name.is_empty() || p_name == "@" {
                Some(match pinned_head {
                    Some(h) => h.root,
                    None => head_store.read_head(volume).await?.root,
                })
            } else {
                Some(head_store.get_snapshot(volume, p_name).await?.root)
            }
        }
        None => None,
    };

    let (parent_nodes, parent_blocks) = match parent_root {
        Some(pr) => collect_parent_digests(head_store, pr).await?,
        None => (HashSet::new(), HashSet::new()),
    };

    let header = match parent_root {
        Some(pr) => StreamHeader::incremental(volume.0.clone(), pr, target_root),
        None => StreamHeader::full(volume.0.clone(), target_root),
    };
    let mut encoder = StreamEncoder::new();
    let hdr_bytes = encoder.encode_header(&header)?;
    write_all_chunked(sink, &hdr_bytes).await?;

    let mut emitted_nodes: HashSet<Digest> = HashSet::new();
    let mut emitted_blocks: HashSet<Digest> = HashSet::new();
    let mut subtrees_skipped = 0u64;

    if parent_nodes.contains(&target_root) {
        subtrees_skipped = subtrees_skipped.saturating_add(1);
    } else {
        let raw_root = head_store.get_node(&target_root).await?;
        let root_obj = RootObject::decode_verified(&target_root, &raw_root)?;

        enum WalkFrame {
            Enter(Digest),
            EmitInternal(Digest, Vec<u8>),
        }

        // Canonical subvol order (`BTreeMap`) -> post-order traversal (blocks -> leaves -> internals -> root).
        for sv_root in root_obj.subvols.values() {
            if parent_nodes.contains(sv_root) {
                subtrees_skipped = subtrees_skipped.saturating_add(1);
                continue;
            }
            let mut stack = vec![WalkFrame::Enter(*sv_root)];
            while let Some(frame) = stack.pop() {
                match frame {
                    WalkFrame::Enter(digest) => {
                        if emitted_nodes.contains(&digest) {
                            continue;
                        }
                        if parent_nodes.contains(&digest) {
                            // Unchanged Merkle subtree — skip without descending or fetching!
                            subtrees_skipped = subtrees_skipped.saturating_add(1);
                            continue;
                        }
                        let raw = head_store.get_node(&digest).await?;
                        let node = Node::decode_verified(&digest, &raw)?;
                        match node {
                            Node::Internal { entries, .. } => {
                                stack.push(WalkFrame::EmitInternal(digest, raw));
                                for entry in entries.into_iter().rev() {
                                    if emitted_nodes.contains(&entry.child) {
                                        continue;
                                    }
                                    if parent_nodes.contains(&entry.child) {
                                        subtrees_skipped = subtrees_skipped.saturating_add(1);
                                        continue;
                                    }
                                    stack.push(WalkFrame::Enter(entry.child));
                                }
                            }
                            Node::Leaf { entries } => {
                                // Emit referenced blocks BEFORE the leaf node (post-order).
                                for entry in entries {
                                    if entry.key.kind != KIND_EXTENT_DATA {
                                        continue;
                                    }
                                    if let ExtentDataValue::Extent { digest: bdig, .. } =
                                        ExtentDataValue::decode(&entry.value)?
                                    {
                                        if parent_blocks.contains(&bdig)
                                            || !emitted_blocks.insert(bdig)
                                        {
                                            continue;
                                        }
                                        let loc = head_store
                                            .lookup_block(&bdig)
                                            .await?
                                            .ok_or(Errno::EIO)?;
                                        let block_bytes = pack_store
                                            .read_pack_range(&loc.pack_id, loc.offset, loc.len)
                                            .await?;
                                        verify_block_digest(&bdig, &block_bytes)?;
                                        let frame_bytes =
                                            encoder.encode_block(&bdig, &block_bytes)?;
                                        write_all_chunked(sink, &frame_bytes).await?;
                                    }
                                }
                                if emitted_nodes.insert(digest) {
                                    let frame_bytes = encoder.encode_node(&digest, &raw)?;
                                    write_all_chunked(sink, &frame_bytes).await?;
                                }
                            }
                        }
                    }
                    WalkFrame::EmitInternal(digest, raw) => {
                        if emitted_nodes.insert(digest) {
                            let frame_bytes = encoder.encode_node(&digest, &raw)?;
                            write_all_chunked(sink, &frame_bytes).await?;
                        }
                    }
                }
            }
        }

        if emitted_nodes.insert(target_root) {
            let frame_bytes = encoder.encode_node(&target_root, &raw_root)?;
            write_all_chunked(sink, &frame_bytes).await?;
        }
    }

    let end_bytes = encoder.encode_end()?;
    write_all_chunked(sink, &end_bytes).await?;

    Ok(CowfsSendResp {
        volume: volume.0.clone(),
        snapshot: snapshot_label.to_string(),
        root: digest_to_hex(&target_root),
        parent_root: parent_root.map(|d| digest_to_hex(&d)),
        bytes_written: encoder.bytes_written(),
        nodes_sent: encoder.node_count(),
        blocks_sent: encoder.block_count(),
        subtrees_skipped,
    })
}

/// Destination lease mode for [`receive_snapshot`].
pub enum ReceiveTarget<'a> {
    /// Target volume is currently mounted RW and caller holds `op_lock` + `commit_lock`.
    MountedLease {
        volume: &'a VolumeId,
        lease_incarnation: u64,
        lease_fence: u64,
        lease_epoch: u64,
    },
    /// Target volume is unmounted (exists -> acquires `WriterMode::Exclusive`, missing -> creates).
    UnmountedVolume(&'a VolumeId),
}

impl<'a> ReceiveTarget<'a> {
    fn volume(&self) -> &'a VolumeId {
        match self {
            ReceiveTarget::MountedLease { volume, .. } => volume,
            ReceiveTarget::UnmountedVolume(v) => v,
        }
    }
}

/// Overlay `HeadStore` exposing staged received nodes & block locations on top of the destination
/// `HeadStore` so `fsck::verify_root_reachable` can fully verify the received root BEFORE commit.
struct StagedOverlayHeadStore<'a, H: HeadStore> {
    base: &'a H,
    staged_nodes: &'a HashMap<Digest, Vec<u8>>,
    staged_blocks: &'a HashMap<Digest, BlockLoc>,
}

impl<H: HeadStore> HeadStore for StagedOverlayHeadStore<'_, H> {
    fn format_version(&self) -> BoxFuture<'_, Option<u32>> {
        self.base.format_version()
    }

    fn create_volume<'a>(
        &'a self,
        _head: &'a VolumeHead,
        _initial_nodes: &'a [(Digest, Vec<u8>)],
    ) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn grace_window_secs(&self) -> u64 {
        self.base.grace_window_secs()
    }

    fn read_head<'a>(&'a self, volume: &'a VolumeId) -> BoxFuture<'a, VolumeHead> {
        self.base.read_head(volume)
    }

    fn pin_ro_root<'a>(
        &'a self,
        _volume: &'a VolumeId,
        _snapshot: Option<&'a str>,
    ) -> BoxFuture<'a, (VolumeHead, Box<dyn RoPinGuard>)> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn unpin_ro_root<'a>(&'a self, _pin: Box<dyn RoPinGuard>) -> BoxFuture<'a, ()> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn acquire_writer<'a>(
        &'a self,
        _volume: &'a VolumeId,
        _mode: WriterMode,
    ) -> BoxFuture<'a, WriterLease> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn renew_writer<'a>(&'a self, _lease: &'a mut WriterLease) -> BoxFuture<'a, ()> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn release_writer<'a>(&'a self, _lease: WriterLease) -> BoxFuture<'a, ()> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn get_node<'a>(&'a self, digest: &'a Digest) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move {
            if let Some(bytes) = self.staged_nodes.get(digest) {
                return Ok(bytes.clone());
            }
            self.base.get_node(digest).await
        })
    }

    fn lookup_block<'a>(&'a self, digest: &'a Digest) -> BoxFuture<'a, Option<BlockLoc>> {
        Box::pin(async move {
            if let Some(loc) = self.staged_blocks.get(digest) {
                return Ok(Some(loc.clone()));
            }
            self.base.lookup_block(digest).await
        })
    }

    fn commit_head<'a>(&'a self, _req: &'a CommitRequest) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn create_snapshot<'a>(
        &'a self,
        _volume: &'a VolumeId,
        _name: &'a str,
        _head: &'a VolumeHead,
        _now: Timespec,
    ) -> BoxFuture<'a, SnapshotRecord> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn get_snapshot<'a>(
        &'a self,
        volume: &'a VolumeId,
        name: &'a str,
    ) -> BoxFuture<'a, SnapshotRecord> {
        self.base.get_snapshot(volume, name)
    }

    fn list_snapshots<'a>(&'a self, volume: &'a VolumeId) -> BoxFuture<'a, Vec<SnapshotRecord>> {
        self.base.list_snapshots(volume)
    }

    fn delete_snapshot<'a>(&'a self, _volume: &'a VolumeId, _name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn fork_volume<'a>(&'a self, _req: &'a ForkRequest) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn delete_volume<'a>(&'a self, _volume: &'a VolumeId) -> BoxFuture<'a, ()> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn delete_volume_with_lease<'a>(
        &'a self,
        _lease: WriterLease,
        _only_if_unmodified_ephemeral: bool,
    ) -> BoxFuture<'a, bool> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn reformat_volume_with_lease<'a>(
        &'a self,
        _lease: WriterLease,
        _new_head: &'a VolumeHead,
        _initial_nodes: &'a [(Digest, Vec<u8>)],
    ) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn acquire_gc_lock(&self, _exclusive: bool) -> BoxFuture<'_, Box<dyn GcLockGuard>> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn list_all_roots(&self) -> BoxFuture<'_, Vec<GcRoot>> {
        self.base.list_all_roots()
    }

    fn list_indexed_packs(&self) -> BoxFuture<'_, HashSet<PackId>> {
        self.base.list_indexed_packs()
    }

    fn prune_abandoned_ephemeral_forks(
        &self,
        _now: Timespec,
        _grace_window_secs: u64,
    ) -> BoxFuture<'_, usize> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn sweep_metadata<'a>(
        &'a self,
        _keep_nodes: &'a HashSet<Digest>,
        _keep_packs: &'a HashSet<PackId>,
        _now: Timespec,
        _grace_window_secs: u64,
    ) -> BoxFuture<'a, Vec<PackId>> {
        Box::pin(async { Err(Errno::EROFS) })
    }
}

/// Ingest, verify, and atomically commit an `OSCOWS1\0` Merkle delta stream into `target`.
///
/// Guarantees:
/// - Streams input in `<= 64 KiB` chunks and flushes data packs in `<= 8 MiB` increments.
/// - Rejects missing incremental parent roots in the destination volume with `Errno::ENOENT`
///   without mutating any destination metadata.
/// - Verifies every node/block SHA-256, running stream SHA-256, strict EOF, and full
///   `fsck::verify_root_reachable` BEFORE committing (`Errno::EIO` on any corruption/truncation,
///   with zero head/snapshot mutation).
pub async fn receive_snapshot<H: HeadStore, P: PackStore, S: StreamSource>(
    head_store: &H,
    pack_store: &P,
    target: ReceiveTarget<'_>,
    snapshot_name: Option<&str>,
    now: Timespec,
    source: &mut S,
) -> Result<(VolumeHead, CowfsReceiveResp)> {
    if let Some(snap) = snapshot_name
        && (snap.is_empty() || snap.contains(['/', '\0']))
    {
        return Err(Errno::EINVAL);
    }
    if let Some(ver) = head_store.format_version().await?
        && ver != COWFS_FORMAT_VERSION
    {
        return Err(Errno::EPROTONOSUPPORT);
    }

    let volume = target.volume().clone();
    let _gc_guard = head_store.acquire_gc_lock(false).await?;

    let mut acquired_lease: Option<WriterLease> = None;
    let expected_lease = match target {
        ReceiveTarget::MountedLease {
            lease_incarnation,
            lease_fence,
            lease_epoch,
            ..
        } => Some((lease_incarnation, lease_fence, lease_epoch)),
        ReceiveTarget::UnmountedVolume(_) => match head_store.read_head(&volume).await {
            Ok(_) => {
                let lease = head_store
                    .acquire_writer(&volume, WriterMode::Exclusive)
                    .await?;
                let triple = (lease.incarnation, lease.fence, lease.epoch);
                acquired_lease = Some(lease);
                Some(triple)
            }
            Err(Errno::ENOENT) => None,
            Err(e) => return Err(e),
        },
    };

    let mut newly_written_packs: Vec<PackId> = Vec::new();

    let res: Result<(VolumeHead, CowfsReceiveResp)> = async {
        // Pre-check snapshot name collision before doing heavy stream I/O.
        if let Some(snap) = snapshot_name
            && expected_lease.is_some()
            && head_store.get_snapshot(&volume, snap).await.is_ok()
        {
            return Err(Errno::EEXIST);
        }

        let mut decoder = StreamDecoder::new();
        let mut chunk_buf = vec![0u8; STREAM_CHUNK_BYTES];
        let mut header: Option<StreamHeader> = None;
        let mut staged_nodes: HashMap<Digest, Vec<u8>> = HashMap::new();
        let mut put_nodes: Vec<(Digest, Vec<u8>)> = Vec::new();
        let mut staged_blocks: HashMap<Digest, BlockLoc> = HashMap::new();
        let mut put_packs: Vec<PackMeta> = Vec::new();
        let mut put_blocks: Vec<(Digest, BlockLoc)> = Vec::new();
        let mut pack_builder = PackBuilder::new();
        let mut nodes_received = 0u64;
        let mut blocks_received = 0u64;

        loop {
            let n = source.read_chunk(&mut chunk_buf).await?;
            if n == 0 {
                break;
            }
            decoder.feed(&chunk_buf[..n])?;
            while let Some(ev) = decoder.next_event() {
                match ev {
                    StreamEvent::Header(hdr) => {
                        if let Some(parent_root) = hdr.parent_root {
                            // Verify the incremental parent root is actually owned by the
                            // destination volume (current head or one of its snapshots), NOT
                            // merely present in a shared store from another volume!
                            if expected_lease.is_none() {
                                return Err(Errno::ENOENT);
                            }
                            let dest_head = head_store.read_head(&volume).await?;
                            let mut has_parent = dest_head.root == parent_root;
                            if !has_parent {
                                let snaps = head_store.list_snapshots(&volume).await?;
                                has_parent = snaps.iter().any(|s| s.root == parent_root);
                            }
                            if !has_parent {
                                return Err(Errno::ENOENT);
                            }
                            // Also confirm the parent root node itself is readable.
                            head_store.get_node(&parent_root).await?;
                        }
                        header = Some(hdr);
                    }
                    StreamEvent::Block { digest, bytes } => {
                        blocks_received = blocks_received.saturating_add(1);
                        if !staged_blocks.contains_key(&digest)
                            && head_store.lookup_block(&digest).await?.is_none()
                        {
                            pack_builder.push(digest, &bytes)?;
                            for built in pack_builder.drain_finished() {
                                let existed = pack_store.stat_pack(&built.pack_id).await?.is_some();
                                let mut meta =
                                    pack_store.write_pack(&built.pack_id, &built.bytes).await?;
                                if !existed {
                                    newly_written_packs.push(built.pack_id.clone());
                                }
                                meta.created_at = now;
                                for (bdig, loc) in &built.locations {
                                    staged_blocks.insert(*bdig, loc.clone());
                                }
                                put_packs.push(meta);
                                put_blocks.extend(built.locations);
                            }
                        }
                    }
                    StreamEvent::Node { digest, bytes } => {
                        nodes_received = nodes_received.saturating_add(1);
                        let target_root = header.as_ref().ok_or(Errno::EIO)?.target_root;
                        if digest == target_root {
                            let _ = RootObject::decode_verified(&digest, &bytes)?;
                        } else {
                            let _ = Node::decode_verified(&digest, &bytes)?;
                        }
                        if let std::collections::hash_map::Entry::Vacant(e) =
                            staged_nodes.entry(digest)
                        {
                            e.insert(bytes.clone());
                            put_nodes.push((digest, bytes));
                        }
                    }
                    StreamEvent::End { .. } => {}
                }
            }
        }

        decoder.finish()?;
        let hdr = header.ok_or(Errno::EIO)?;

        for built in pack_builder.finish()? {
            let existed = pack_store.stat_pack(&built.pack_id).await?.is_some();
            let mut meta = pack_store.write_pack(&built.pack_id, &built.bytes).await?;
            if !existed {
                newly_written_packs.push(built.pack_id.clone());
            }
            meta.created_at = now;
            for (bdig, loc) in &built.locations {
                staged_blocks.insert(*bdig, loc.clone());
            }
            put_packs.push(meta);
            put_blocks.extend(built.locations);
        }

        // Verify complete reachability, SHA-256 integrity, and filesystem invariants of
        // `hdr.target_root` against `(base + staged)` BEFORE publishing any head or snapshot!
        let overlay = StagedOverlayHeadStore {
            base: head_store,
            staged_nodes: &staged_nodes,
            staged_blocks: &staged_blocks,
        };
        let verify_epoch = expected_lease.map_or(0, |(_, _, ep)| ep.saturating_add(1));
        let report = crate::fsck::verify_root_reachable(
            &overlay,
            pack_store,
            &volume.0,
            verify_epoch,
            hdr.target_root,
        )
        .await?;
        if !report.ok {
            return Err(Errno::EIO);
        }

        // Derive a deterministic idempotency key for `commit_received_root`.
        let mut op_seed = Vec::with_capacity(64 + volume.0.len());
        op_seed.extend_from_slice(b"os-cowfs-recv-v1\0");
        op_seed.extend_from_slice(&(volume.0.len() as u32).to_be_bytes());
        op_seed.extend_from_slice(volume.0.as_bytes());
        if let Some((inc, fence, ep)) = expected_lease {
            op_seed.push(1);
            op_seed.extend_from_slice(&inc.to_be_bytes());
            op_seed.extend_from_slice(&fence.to_be_bytes());
            op_seed.extend_from_slice(&ep.to_be_bytes());
        } else {
            op_seed.push(0);
        }
        op_seed.extend_from_slice(&hdr.target_root);
        if let Some(snap) = snapshot_name {
            op_seed.extend_from_slice(&(snap.len() as u32).to_be_bytes());
            op_seed.extend_from_slice(snap.as_bytes());
        }
        let op_hash = sha256(&op_seed);
        let mut op_id = [0u8; 16];
        op_id.copy_from_slice(&op_hash[..16]);

        let commit_req = ReceiveCommitRequest {
            op_id,
            volume: volume.clone(),
            expected_lease,
            new_root: hdr.target_root,
            put_nodes,
            put_packs,
            put_blocks,
            snapshot_name: snapshot_name.map(str::to_owned),
            committed_at: now,
        };
        let committed = head_store.commit_received_root(&commit_req).await?;
        let resp = CowfsReceiveResp {
            volume: committed.volume.0.clone(),
            root: digest_to_hex(&committed.root),
            epoch: committed.epoch,
            snapshot: snapshot_name.map(str::to_owned),
            nodes_received,
            blocks_received,
            bytes_read: decoder.bytes_read(),
        };
        Ok((committed, resp))
    }
    .await;

    if res.is_err() {
        // Best-effort cleanup of newly created unindexed packs so failed receives don't waste space.
        for pid in newly_written_packs {
            let _ = pack_store.delete_pack(&pid).await;
        }
    }
    if let Some(lease) = acquired_lease {
        let _ = head_store.release_writer(lease).await;
    }

    res
}

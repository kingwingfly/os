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
use cowtree::{Arena, ArenaConfig, CowTree, TreeKey, TreeOverlay};
use cowtree::{
    COWFS_FORMAT_VERSION, Digest, GcLockGuard, HeadStore, KIND_EXTENT_DATA, Node, PackBuilder,
    PackStore, ReceiveCommitRequest, RootObject, VolumeHead, VolumeId, WriterLease, WriterMode,
    digest_to_hex, sha256,
};
use std::cell::RefCell;
use std::collections::HashSet;
use vfs::{BoxFuture, FileRef, Result};

pub use vfs::vblk::{StreamSink, StreamSource};

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
pub async fn write_all_chunked<S: StreamSink + ?Sized>(
    sink: &mut S,
    mut data: &[u8],
) -> Result<u64> {
    let mut written = 0u64;
    while !data.is_empty() {
        let take = data.len().min(STREAM_CHUNK_BYTES);
        let n = sink.write_chunk(&data[..take]).await?;
        if n == 0 || n > take {
            return Err(Errno::EIO);
        }
        written = written.saturating_add(n as u64);
        data = &data[n..];
    }
    Ok(written)
}

// Remember recent publications. Re-emitting an older dependency is valid post-order.
fn remember(seen: &mut HashSet<Digest>, digest: Digest) -> bool {
    if seen.len() == 16_384 {
        seen.clear();
    }
    seen.insert(digest)
}

// Provenance belongs to this receive, even when the destination already has the bytes.
// Spill scratch B+tree pages under the shared GC lock. They never become volume roots.
const NODE_OBJECT: u8 = 1;
const BLOCK_OBJECT: u8 = 2;
const IN_PARENT: u8 = 1;
const FRAMED: u8 = 2;
const REFERENCED: u8 = 4;

struct ReceiveLedger<'a, H> {
    store: &'a H,
    now: Timespec,
    arena: RefCell<Arena>,
    root: Option<Digest>,
    overlay: TreeOverlay,
    unused: usize,
}

impl<'a, H: HeadStore> ReceiveLedger<'a, H> {
    fn new(store: &'a H, now: Timespec) -> Self {
        Self {
            store,
            now,
            arena: RefCell::new(Arena::new(ArenaConfig {
                tree_lru_bytes: 256 * 1024,
                clean_data_bytes: 0,
                dirty_bytes: 0,
            })),
            root: None,
            overlay: TreeOverlay::new(),
            unused: 0,
        }
    }

    async fn mark(&mut self, kind: u8, digest: &Digest, flag: u8) -> Result<bool> {
        let key = TreeKey::new(0, kind, digest.to_vec());
        let tree = CowTree::new(self.store, &self.arena);
        let old = match self.overlay.get(&key) {
            Some(Some(value)) => value[0],
            _ => match self.root {
                Some(root) => tree.get(&root, &key).await?.map_or(0, |v| v[0]),
                None => 0,
            },
        };
        if flag == REFERENCED && old & FRAMED == 0 {
            return if old & IN_PARENT != 0 {
                Ok(false)
            } else {
                Err(Errno::EIO)
            };
        }
        if flag & old != 0 {
            return Ok(false);
        }
        if flag == FRAMED {
            self.unused += 1;
        }
        if flag == REFERENCED {
            self.unused -= 1;
        }
        self.overlay.put(key, vec![old | flag]);
        if self.overlay.len() >= 2048 {
            let mut root = match self.root {
                Some(root) => root,
                None => {
                    let node = Node::empty_leaf().encode()?;
                    let root = node.0;
                    self.store
                        .stage_objects(&[node], &[], &[], self.now)
                        .await?;
                    root
                }
            };
            for chunk in self.overlay.take_sorted_ops().chunks(64) {
                let (next, nodes) = tree.apply_batch(&root, chunk).await?;
                self.store.stage_objects(&nodes, &[], &[], self.now).await?;
                root = next;
            }
            self.root = Some(root);
        }
        Ok(true)
    }

    async fn index_parent(&mut self, digest: Digest) -> Result<()> {
        let root = RootObject::decode_verified(&digest, &self.store.get_node(&digest).await?)?;
        self.mark(NODE_OBJECT, &digest, IN_PARENT).await?;
        let mut stack: Vec<_> = root.subvols.into_values().collect();
        while let Some(digest) = stack.pop() {
            if !self.mark(NODE_OBJECT, &digest, IN_PARENT).await? {
                continue;
            }
            let node = Node::decode_verified(&digest, &self.store.get_node(&digest).await?)?;
            match node {
                Node::Internal { entries, .. } => {
                    stack.extend(entries.into_iter().map(|e| e.child))
                }
                Node::Leaf { entries } => {
                    for entry in entries {
                        if entry.key.kind == KIND_EXTENT_DATA
                            && let ExtentDataValue::Extent { digest, .. } =
                                ExtentDataValue::decode(&entry.value)?
                        {
                            self.mark(BLOCK_OBJECT, &digest, IN_PARENT).await?;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// Find the deepest parent subtree covering the target child's entire key interval.
async fn corresponding_parent<H: HeadStore>(
    tree: &CowTree<'_, H>,
    mut digest: Digest,
    target: Digest,
    level: u8,
    lower: &TreeKey,
    upper: Option<&TreeKey>,
) -> Result<Digest> {
    while digest != target {
        let node = tree.load_node(&digest).await?;
        let Node::Internal {
            level: old_level,
            entries,
        } = &*node
        else {
            break;
        };
        if *old_level <= level {
            break;
        }
        let Some(i) = entries.partition_point(|e| &e.key <= lower).checked_sub(1) else {
            break;
        };
        let child = entries[i].child;
        if child != target
            && entries
                .get(i + 1)
                .is_some_and(|next| upper.is_none_or(|hi| hi > &next.key))
        {
            break;
        }
        digest = child;
    }
    Ok(digest)
}

/// Emit a full or incremental `OSCOWS1\0` Merkle delta stream — or a self-verifying `.cowpack`
/// (`OSCOWA1\0`) archive when `archive == true` — for `snapshot` (or current head when `snapshot`
/// is `""` or `"@"`).
///
/// When `pinned_head` is `Some`, sending `""` / `"@"` exports that exact pinned root (used for
/// read-only/snapshot mounts).
#[allow(clippy::too_many_arguments)]
pub async fn send_snapshot<H: HeadStore, P: PackStore, S: StreamSink + ?Sized>(
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
    if archive && parent.is_some() {
        return Err(Errno::EINVAL);
    }
    let view = |name: &str| {
        if name.is_empty() || name == "@" {
            None
        } else {
            Some(name.to_owned())
        }
    };
    let target = view(snapshot);
    let (head, target_pin) = head_store
        .pin_view(
            volume,
            target.as_deref(),
            pinned_head.filter(|_| target.is_none()),
        )
        .await?;
    let target_root = head.root;
    let (parent_root, parent_pin) = if let Some(name) = parent {
        let name = view(name);
        let (h, pin) = head_store
            .pin_view(
                volume,
                name.as_deref(),
                pinned_head.filter(|_| name.is_none()),
            )
            .await?;
        (Some(h.root), pin)
    } else {
        (None, None)
    };
    let result = send_pinned(
        head_store,
        pack_store,
        volume,
        snapshot_label,
        target_root,
        parent_root,
        archive,
        sink,
    )
    .await;
    for pin in [parent_pin, target_pin].into_iter().flatten() {
        head_store.unpin_ro_root(pin).await?;
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn send_pinned<H: HeadStore, P: PackStore, S: StreamSink + ?Sized>(
    head_store: &H,
    pack_store: &P,
    volume: &VolumeId,
    snapshot_label: &str,
    target_root: Digest,
    parent_root: Option<Digest>,
    archive: bool,
    sink: &mut S,
) -> Result<CowfsSendResp> {
    if archive {
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

    if parent_root == Some(target_root) {
        subtrees_skipped = subtrees_skipped.saturating_add(1);
    } else {
        let raw_root = head_store.get_node(&target_root).await?;
        let root_obj = RootObject::decode_verified(&target_root, &raw_root)?;

        let parent = if let Some(digest) = parent_root {
            Some(RootObject::decode_verified(
                &digest,
                &head_store.get_node(&digest).await?,
            )?)
        } else {
            None
        };
        let arena = RefCell::new(Arena::new(ArenaConfig {
            tree_lru_bytes: 256 * 1024,
            clean_data_bytes: 0,
            dirty_bytes: 0,
        }));
        let old_tree = CowTree::new(head_store, &arena);
        enum WalkFrame {
            Enter(Digest, Option<Digest>, Option<TreeKey>),
            EmitInternal(Digest, Vec<u8>),
        }

        // Canonical subvol order (`BTreeMap`) -> post-order traversal (blocks -> leaves -> internals -> root).
        for (name, sv_root) in &root_obj.subvols {
            let old = parent
                .as_ref()
                .and_then(|root| root.subvols.get(name))
                .copied();
            let mut stack = vec![WalkFrame::Enter(*sv_root, old, None)];
            while let Some(frame) = stack.pop() {
                match frame {
                    WalkFrame::Enter(digest, old, upper) => {
                        if emitted_nodes.contains(&digest) {
                            continue;
                        }
                        if old == Some(digest) {
                            subtrees_skipped += 1;
                            continue;
                        }
                        let raw = head_store.get_node(&digest).await?;
                        let node = Node::decode_verified(&digest, &raw)?;
                        match node {
                            Node::Internal { entries, level } => {
                                stack.push(WalkFrame::EmitInternal(digest, raw));
                                let mut hi = upper;
                                for entry in entries.into_iter().rev() {
                                    let corresponding = match old {
                                        Some(d) => Some(
                                            corresponding_parent(
                                                &old_tree,
                                                d,
                                                entry.child,
                                                level - 1,
                                                &entry.key,
                                                hi.as_ref(),
                                            )
                                            .await?,
                                        ),
                                        None => None,
                                    };
                                    stack.push(WalkFrame::Enter(entry.child, corresponding, hi));
                                    hi = Some(entry.key);
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
                                        let unchanged = if let Some(parent) = old {
                                            old_tree.get(&parent, &entry.key).await?.as_ref()
                                                == Some(&entry.value)
                                        } else {
                                            false
                                        };
                                        if unchanged || !remember(&mut emitted_blocks, bdig) {
                                            continue;
                                        }
                                        let loc = head_store
                                            .lookup_block(&bdig)
                                            .await?
                                            .ok_or(Errno::EIO)?;
                                        loc.validate_v1()?;
                                        let block_bytes = pack_store
                                            .read_pack_range(&loc.pack_id, loc.offset, loc.len)
                                            .await?;
                                        verify_block_digest(&bdig, &block_bytes)?;
                                        let frame_bytes =
                                            encoder.encode_block(&bdig, &block_bytes)?;
                                        write_all_chunked(sink, &frame_bytes).await?;
                                    }
                                }
                                if remember(&mut emitted_nodes, digest) {
                                    let frame_bytes = encoder.encode_node(&digest, &raw)?;
                                    write_all_chunked(sink, &frame_bytes).await?;
                                }
                            }
                        }
                    }
                    WalkFrame::EmitInternal(digest, raw) => {
                        if remember(&mut emitted_nodes, digest) {
                            let frame_bytes = encoder.encode_node(&digest, &raw)?;
                            write_all_chunked(sink, &frame_bytes).await?;
                        }
                    }
                }
            }
        }

        if remember(&mut emitted_nodes, target_root) {
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

pub(crate) struct PreparedReceive {
    pub request: ReceiveCommitRequest,
    response: CowfsReceiveResp,
    _gc: Box<dyn GcLockGuard>,
}

impl PreparedReceive {
    pub async fn publish<H: HeadStore>(self, store: &H) -> Result<(VolumeHead, CowfsReceiveResp)> {
        let head = store.commit_received_root(&self.request).await?;
        let mut response = self.response;
        response.epoch = head.epoch;
        Ok((head, response))
    }
}

pub(crate) async fn stage_pack<H: HeadStore, P: PackStore>(
    store: &H,
    packs: &P,
    built: cowtree::pack::BuiltPack,
    now: Timespec,
) -> Result<()> {
    let mut meta = packs.write_pack(&built.pack_id, &built.bytes).await?;
    meta.created_at = now;
    store
        .stage_objects(&[], &[meta], &built.locations, now)
        .await
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
pub async fn receive_snapshot<H: HeadStore, P: PackStore, S: StreamSource + ?Sized>(
    head_store: &H,
    pack_store: &P,
    target: ReceiveTarget<'_>,
    snapshot_name: Option<&str>,
    now: Timespec,
    source: &mut S,
) -> Result<(VolumeHead, CowfsReceiveResp)> {
    let volume = target.volume().clone();
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
            Err(Errno::ENOENT) => {
                acquired_lease = head_store.reserve_receive(&volume).await?;
                acquired_lease
                    .as_ref()
                    .map(|l| (l.incarnation, l.fence, l.epoch))
            }
            Err(e) => return Err(e),
        },
    };

    let result = async {
        prepare_receive(
            head_store,
            pack_store,
            &volume,
            expected_lease,
            snapshot_name,
            now,
            source,
        )
        .await?
        .publish(head_store)
        .await
    }
    .await;
    if let Some(lease) = acquired_lease {
        head_store.release_writer(lease).await?;
    }
    result
}

pub(crate) async fn prepare_receive<H: HeadStore, P: PackStore, S: StreamSource + ?Sized>(
    head_store: &H,
    pack_store: &P,
    volume: &VolumeId,
    expected_lease: Option<(u64, u64, u64)>,
    snapshot_name: Option<&str>,
    now: Timespec,
    source: &mut S,
) -> Result<PreparedReceive> {
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

    let gc = head_store.acquire_gc_lock(false).await?;
    // Pre-check snapshot name collision before doing heavy stream I/O.
    if let Some(snap) = snapshot_name
        && expected_lease.is_some()
        && head_store.get_snapshot(volume, snap).await.is_ok()
    {
        return Err(Errno::EEXIST);
    }

    let mut decoder = StreamDecoder::new();
    let mut chunk_buf = vec![0u8; STREAM_CHUNK_BYTES];
    let mut header: Option<StreamHeader> = None;
    let mut ledger = ReceiveLedger::new(head_store, now);
    let mut batch = Vec::new();
    let mut batch_bytes = 0;
    let mut pack_builder = PackBuilder::streaming();
    let mut nodes_received = 0u64;
    let mut blocks_received = 0u64;

    loop {
        let n = source.read_chunk(&mut chunk_buf).await?;
        if n == 0 {
            break;
        }
        decoder.feed(chunk_buf.get(..n).ok_or(Errno::EIO)?)?;
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
                        let dest_head = head_store.read_head(volume).await?;
                        let mut has_parent = dest_head.root == parent_root;
                        if !has_parent {
                            let snaps = head_store.list_snapshots(volume).await?;
                            has_parent = snaps.iter().any(|s| s.root == parent_root);
                        }
                        if !has_parent {
                            return Err(Errno::ENOENT);
                        }
                        // Also confirm the parent root node itself is readable.
                        ledger.index_parent(parent_root).await?;
                    }
                    header = Some(hdr);
                }
                StreamEvent::Block { digest, bytes } => {
                    blocks_received = blocks_received.saturating_add(1);
                    if ledger.mark(BLOCK_OBJECT, &digest, FRAMED).await? {
                        if head_store.lookup_block(&digest).await?.is_some() {
                            continue;
                        }
                        pack_builder.push(digest, &bytes)?;
                        for built in pack_builder.drain_finished() {
                            stage_pack(head_store, pack_store, built, now).await?;
                        }
                    }
                }
                StreamEvent::Node { digest, bytes } => {
                    nodes_received += 1;
                    let target = header.as_ref().ok_or(Errno::EIO)?.target_root;
                    if digest == target {
                        let root = RootObject::decode_verified(&digest, &bytes)?;
                        for dependency in root.subvols.values() {
                            ledger.mark(NODE_OBJECT, dependency, REFERENCED).await?;
                        }
                    } else {
                        match Node::decode_verified(&digest, &bytes)? {
                            Node::Internal { entries, .. } => {
                                for entry in entries {
                                    ledger.mark(NODE_OBJECT, &entry.child, REFERENCED).await?;
                                }
                            }
                            Node::Leaf { entries } => {
                                for entry in entries {
                                    if entry.key.kind == KIND_EXTENT_DATA
                                        && let ExtentDataValue::Extent { digest, .. } =
                                            ExtentDataValue::decode(&entry.value)?
                                    {
                                        ledger.mark(BLOCK_OBJECT, &digest, REFERENCED).await?;
                                    }
                                }
                            }
                        }
                    }
                    ledger.mark(NODE_OBJECT, &digest, FRAMED).await?;
                    batch_bytes += bytes.len();
                    batch.push((digest, bytes));
                    if batch_bytes >= 256 * 1024 {
                        head_store.stage_objects(&batch, &[], &[], now).await?;
                        batch.clear();
                        batch_bytes = 0;
                    }
                }
                StreamEvent::End { .. } => {}
            }
        }
    }

    decoder.finish()?;
    let hdr = header.ok_or(Errno::EIO)?;

    ledger
        .mark(NODE_OBJECT, &hdr.target_root, REFERENCED)
        .await?;
    if ledger.unused != 0 {
        return Err(Errno::EIO);
    }
    drop(ledger);
    if !batch.is_empty() {
        head_store.stage_objects(&batch, &[], &[], now).await?;
    }
    drop(batch);
    for built in pack_builder.finish()? {
        stage_pack(head_store, pack_store, built, now).await?;
    }
    let verify_epoch = expected_lease.map_or(0, |(_, _, ep)| ep.saturating_add(1));
    let report = crate::fsck::verify_root_reachable(
        head_store,
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
        put_nodes: vec![],
        put_packs: vec![],
        put_blocks: vec![],
        snapshot_name: snapshot_name.map(str::to_owned),
        committed_at: now,
    };
    let resp = CowfsReceiveResp {
        volume: volume.0.clone(),
        root: digest_to_hex(&hdr.target_root),
        epoch: verify_epoch,
        snapshot: snapshot_name.map(str::to_owned),
        nodes_received,
        blocks_received,
        bytes_read: decoder.bytes_read(),
    };
    Ok(PreparedReceive {
        request: commit_req,
        response: resp,
        _gc: gc,
    })
}

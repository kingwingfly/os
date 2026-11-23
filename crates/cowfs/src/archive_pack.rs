//! Self-verifying read-only `.cowpack` (`OSCOWA1\0`) archive [`HeadStore`], [`PackStore`],
//! streaming exporter, and zero-copy random-access readers (`docs/architecture/contract.md` §2.15,
//! §2.16; #79 `L2.5c`).

use crate::fs::{CowFs, CowFsConfig, CowFsOpenMode};
use crate::inode::ExtentDataValue;
use crate::send_recv::{StreamSink, write_all_chunked};
use abi::Errno;
use abi::fs::Timespec;
use abi::volume::CowfsSendResp;
use cowtree::archive::{
    ArchiveFooter, ArchiveReader, ArchiveWriter, PagedArchiveIndex, open_archive_index,
};
use cowtree::pack::{
    PACK_FOOTER_BYTES, decode_pack_footer, decode_pack_trailer_bytes, verify_block_digest,
};
use cowtree::{
    BlockLoc, COWFS_FORMAT_VERSION, CommitRequest, Digest, ForkRequest, GcLockGuard, GcRoot,
    HeadStore, KIND_EXTENT_DATA, Node, PACK_MAX_BYTES, PackBuilder, PackId, PackMeta, PackStore,
    PackTrailer, ReceiveCommitRequest, RoPinGuard, RootObject, SnapshotRecord, VolumeHead,
    VolumeId, WriterLease, WriterMode, digest_to_hex, sha256,
};
use std::collections::HashSet;
use std::rc::Rc;
use vfs::{BoxFuture, FileRef, Result};

/// Zero-copy [`ArchiveReader`] backed by a pinned [`vfs::FileRef`] using `pread` (`read_at`).
pub struct FileRefArchiveReader(pub FileRef);

impl ArchiveReader for FileRefArchiveReader {
    fn size(&self) -> BoxFuture<'_, u64> {
        Box::pin(async move { Ok(self.0.metadata().await?.size) })
    }

    fn read_at<'a>(&'a self, offset: u64, len: usize) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move {
            if len == 0 {
                return Ok(Vec::new());
            }
            let mut buf = vec![0u8; len];
            let mut done = 0usize;
            while done < len {
                let n = self
                    .0
                    .read_at(&mut buf[done..], offset.saturating_add(done as u64))
                    .await?;
                if n == 0 {
                    buf.truncate(done);
                    break;
                }
                done += n;
            }
            Ok(buf)
        })
    }
}

/// In-memory [`ArchiveReader`] backed by an `Rc<Vec<u8>>` slice (for tests and buffers).
#[derive(Clone)]
pub struct SliceArchiveReader(pub Rc<Vec<u8>>);

impl ArchiveReader for SliceArchiveReader {
    fn size(&self) -> BoxFuture<'_, u64> {
        Box::pin(async move { Ok(self.0.len() as u64) })
    }

    fn read_at<'a>(&'a self, offset: u64, len: usize) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let start = usize::try_from(offset).map_err(|_| Errno::EIO)?;
            let end = start.checked_add(len).ok_or(Errno::EIO)?;
            if end > self.0.len() {
                return Err(Errno::EIO);
            }
            Ok(self.0[start..end].to_vec())
        })
    }
}

struct ArchiveRoPin;
impl RoPinGuard for ArchiveRoPin {}

struct ArchiveGcGuard;
impl GcLockGuard for ArchiveGcGuard {}

/// Read-only [`PackStore`] reading pack ranges and trailers directly from a `.cowpack` archive
/// via zero-copy [`ArchiveReader::read_at`]. Every write/delete returns `Errno::EROFS`.
pub struct ArchivePackStore<R: ArchiveReader + 'static> {
    reader: Rc<R>,
    index: Rc<PagedArchiveIndex>,
}

impl<R: ArchiveReader + 'static> PackStore for ArchivePackStore<R> {
    fn write_pack<'a>(&'a self, _pack_id: &'a PackId, _bytes: &'a [u8]) -> BoxFuture<'a, PackMeta> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn read_pack_range<'a>(
        &'a self,
        pack_id: &'a PackId,
        offset: u32,
        len: u32,
    ) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let entry = self
                .index
                .find_pack(&*self.reader, &cowtree::digest_from_hex(&pack_id.0)?)
                .await?
                .ok_or(Errno::ENOENT)?;
            let end = offset.checked_add(len).ok_or(Errno::EIO)?;
            if end > entry.len {
                return Err(Errno::EIO);
            }
            let file_off = entry
                .offset
                .checked_add(u64::from(offset))
                .ok_or(Errno::EIO)?;
            self.reader.read_at(file_off, len as usize).await
        })
    }

    fn read_pack_trailer<'a>(&'a self, pack_id: &'a PackId) -> BoxFuture<'a, PackTrailer> {
        Box::pin(async move {
            let entry = self
                .index
                .find_pack(&*self.reader, &cowtree::digest_from_hex(&pack_id.0)?)
                .await?
                .ok_or(Errno::ENOENT)?;
            let pack_len = entry.len as usize;
            if !(PACK_FOOTER_BYTES..=PACK_MAX_BYTES).contains(&pack_len) {
                return Err(Errno::EIO);
            }
            let footer_off = entry
                .offset
                .checked_add((pack_len - PACK_FOOTER_BYTES) as u64)
                .ok_or(Errno::EIO)?;
            let footer = self.reader.read_at(footer_off, PACK_FOOTER_BYTES).await?;
            let (trailer_len, trailer_sha) = decode_pack_footer(&footer)?;
            let trailer_start_in_pack = entry
                .len
                .checked_sub(PACK_FOOTER_BYTES as u32 + trailer_len)
                .ok_or(Errno::EIO)?;
            let trailer_off = entry
                .offset
                .checked_add(u64::from(trailer_start_in_pack))
                .ok_or(Errno::EIO)?;
            let trailer_bytes = self
                .reader
                .read_at(trailer_off, trailer_len as usize)
                .await?;
            decode_pack_trailer_bytes(&trailer_bytes, trailer_sha, trailer_start_in_pack)
        })
    }

    fn stat_pack<'a>(&'a self, pack_id: &'a PackId) -> BoxFuture<'a, Option<u64>> {
        Box::pin(async move {
            Ok(self
                .index
                .find_pack(&*self.reader, &cowtree::digest_from_hex(&pack_id.0)?)
                .await?
                .map(|e| u64::from(e.len)))
        })
    }

    fn list_packs(&self) -> BoxFuture<'_, Vec<PackId>> {
        Box::pin(async move {
            let mut ids = Vec::new();
            for i in 0..self.index.packs.len() {
                ids.push(PackId(digest_to_hex(
                    &self.index.pack_at(&*self.reader, i).await?.digest,
                )));
            }
            Ok(ids)
        })
    }

    fn delete_pack<'a>(&'a self, _pack_id: &'a PackId) -> BoxFuture<'a, ()> {
        Box::pin(async { Err(Errno::EROFS) })
    }
}

/// Read-only [`HeadStore`] backed by a verified `.cowpack` (`OSCOWA1\0`) archive.
/// Verifies every node SHA-256 on read (`Errno::EIO` on bit-flip); every mutating operation
/// returns `Errno::EROFS`.
pub struct ArchiveHeadStore<R: ArchiveReader + 'static> {
    reader: Rc<R>,
    footer: ArchiveFooter,
    index: Rc<PagedArchiveIndex>,
    volume: VolumeId,
}

impl<R: ArchiveReader + 'static> ArchiveHeadStore<R> {
    /// Open and verify header, 96-byte footer, sorted binary index (`index_sha256`), and root
    /// object of a `.cowpack` archive without copying the backing file into RAM.
    pub async fn open(reader: Rc<R>, volume_name: String) -> Result<(Self, ArchivePackStore<R>)> {
        let (footer, index) = open_archive_index(&*reader).await?;
        let index = Rc::new(index);

        let head_store = Self {
            reader: Rc::clone(&reader),
            footer,
            index: Rc::clone(&index),
            volume: VolumeId(volume_name),
        };
        let pack_store = ArchivePackStore { reader, index };

        // Verify the RootObject immediately so incompatible versions (`EPROTONOSUPPORT`) or
        // corrupt roots (`EIO`) fail fast on open/mount.
        let root_raw = head_store.get_node(&head_store.footer.root_digest).await?;
        let _root = RootObject::decode_verified(&head_store.footer.root_digest, &root_raw)?;

        Ok((head_store, pack_store))
    }

    pub fn footer(&self) -> &ArchiveFooter {
        &self.footer
    }

    pub fn index(&self) -> &PagedArchiveIndex {
        &self.index
    }

    pub fn reader(&self) -> &Rc<R> {
        &self.reader
    }

    pub fn volume(&self) -> &VolumeId {
        &self.volume
    }

    pub fn synthetic_head(&self) -> VolumeHead {
        VolumeHead {
            format_version: COWFS_FORMAT_VERSION,
            volume: self.volume.clone(),
            incarnation: 1,
            fence: 1,
            epoch: 0,
            root: self.footer.root_digest,
            parent_volume: None,
            ephemeral_if_unmodified: false,
            modified: false,
            updated_at: Timespec { sec: 0, nsec: 0 },
        }
    }
}

impl<R: ArchiveReader + 'static> HeadStore for ArchiveHeadStore<R> {
    fn format_version(&self) -> BoxFuture<'_, Option<u32>> {
        Box::pin(async { Ok(Some(COWFS_FORMAT_VERSION)) })
    }

    fn create_volume<'a>(
        &'a self,
        _head: &'a VolumeHead,
        _initial_nodes: &'a [(Digest, Vec<u8>)],
    ) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn grace_window_secs(&self) -> u64 {
        0
    }

    fn read_head<'a>(&'a self, volume: &'a VolumeId) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            if volume == &self.volume {
                Ok(self.synthetic_head())
            } else {
                Err(Errno::ENOENT)
            }
        })
    }

    fn list_volumes(&self) -> BoxFuture<'_, Vec<VolumeHead>> {
        Box::pin(async move { Ok(vec![self.synthetic_head()]) })
    }

    fn commit_received_root<'a>(
        &'a self,
        _req: &'a ReceiveCommitRequest,
    ) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn pin_ro_root<'a>(
        &'a self,
        volume: &'a VolumeId,
        snapshot: Option<&'a str>,
    ) -> BoxFuture<'a, (VolumeHead, Box<dyn RoPinGuard>)> {
        Box::pin(async move {
            if volume != &self.volume || snapshot.is_some() {
                return Err(Errno::ENOENT);
            }
            Ok((
                self.synthetic_head(),
                Box::new(ArchiveRoPin) as Box<dyn RoPinGuard>,
            ))
        })
    }

    fn unpin_ro_root<'a>(&'a self, _pin: Box<dyn RoPinGuard>) -> BoxFuture<'a, ()> {
        Box::pin(async { Ok(()) })
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
            let entry = self
                .index
                .find_node(&*self.reader, digest)
                .await?
                .ok_or(Errno::ENOENT)?;
            if self.reader.read_at(entry.offset - 4, 4).await? != entry.len.to_be_bytes() {
                return Err(Errno::EIO);
            }
            let bytes = self
                .reader
                .read_at(entry.offset, entry.len as usize)
                .await?;
            if sha256(&bytes) != *digest {
                return Err(Errno::EIO);
            }
            Ok(bytes)
        })
    }

    fn lookup_block<'a>(&'a self, digest: &'a Digest) -> BoxFuture<'a, Option<BlockLoc>> {
        Box::pin(async move {
            let Some(b) = self.index.find_block(&*self.reader, digest).await? else {
                return Ok(None);
            };
            let pack = self
                .index
                .pack_at(&*self.reader, b.pack_idx as usize)
                .await?;
            let pack_id = PackId(digest_to_hex(&pack.digest));
            Ok(Some(BlockLoc {
                pack_id,
                offset: b.pack_off,
                len: b.block_len,
                raw_len: b.block_len,
                flags: 0,
            }))
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
        _volume: &'a VolumeId,
        _name: &'a str,
    ) -> BoxFuture<'a, SnapshotRecord> {
        Box::pin(async { Err(Errno::ENOENT) })
    }

    fn list_snapshots<'a>(&'a self, volume: &'a VolumeId) -> BoxFuture<'a, Vec<SnapshotRecord>> {
        Box::pin(async move {
            if volume == &self.volume {
                Ok(Vec::new())
            } else {
                Err(Errno::ENOENT)
            }
        })
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

    fn acquire_gc_lock(&self, exclusive: bool) -> BoxFuture<'_, Box<dyn GcLockGuard>> {
        Box::pin(async move {
            if exclusive {
                Err(Errno::EROFS)
            } else {
                Ok(Box::new(ArchiveGcGuard) as Box<dyn GcLockGuard>)
            }
        })
    }

    fn list_all_roots(&self) -> BoxFuture<'_, Vec<GcRoot>> {
        Box::pin(async move {
            Ok(vec![GcRoot {
                volume: self.volume.clone(),
                root: self.footer.root_digest,
                pinned_until: None,
            }])
        })
    }

    fn list_indexed_packs(&self) -> BoxFuture<'_, HashSet<PackId>> {
        Box::pin(async move {
            let mut ids = HashSet::new();
            for i in 0..self.index.packs.len() {
                ids.insert(PackId(digest_to_hex(
                    &self.index.pack_at(&*self.reader, i).await?.digest,
                )));
            }
            Ok(ids)
        })
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

/// Mount a `.cowpack` (`OSCOWA1\0`) archive as a zero-copy read-only [`CowFs`] filesystem.
pub async fn open_archive_cowfs<R: ArchiveReader + 'static>(
    reader: Rc<R>,
    volume_name: String,
    config: CowFsConfig,
) -> Result<CowFs<ArchiveHeadStore<R>, ArchivePackStore<R>>> {
    let (hs, ps) = ArchiveHeadStore::open(reader, volume_name.clone()).await?;
    CowFs::open(
        Rc::new(hs),
        Rc::new(ps),
        VolumeId(volume_name),
        CowFsOpenMode::ReadOnly,
        config,
    )
    .await
}

/// Stream a complete, self-verifying read-only `.cowpack` (`OSCOWA1\0`) archive for `root_digest`
/// into `sink`, bounding peak RAM via `<= 8 MiB` `PackBuilder` flushes and `<= 64 KiB` write chunks.
pub async fn export_archive_pack<H: HeadStore, P: PackStore, S: StreamSink + ?Sized>(
    head_store: &H,
    pack_store: &P,
    volume: &VolumeId,
    snapshot_label: &str,
    root_digest: Digest,
    sink: &mut S,
) -> Result<CowfsSendResp> {
    let raw_root = head_store.get_node(&root_digest).await?;
    let root_obj = RootObject::decode_verified(&root_digest, &raw_root)?;

    let mut writer = ArchiveWriter::new();
    let mut bytes_written = write_all_chunked(sink, &writer.header_bytes()).await?;
    let mut blocks_sent = 0u64;
    let mut nodes_sent = 0u64;

    // Pass 1: Walk reachable leaves in canonical subvol order and stream verified data blocks
    // through `PackBuilder`, flushing each sealed `<= 8 MiB` pack immediately to `sink`.
    let mut pack_builder = PackBuilder::streaming();
    let mut visited_nodes: HashSet<Digest> = HashSet::new();

    for sv_root in root_obj.subvols.values() {
        let mut stack = vec![*sv_root];
        while let Some(digest) = stack.pop() {
            if visited_nodes.len() == 4096 {
                visited_nodes.clear();
            }
            if !visited_nodes.insert(digest) {
                continue;
            }
            let raw = head_store.get_node(&digest).await?;
            let node = Node::decode_verified(&digest, &raw)?;
            match node {
                Node::Internal { entries, .. } => {
                    for entry in entries.into_iter().rev() {
                        if !visited_nodes.contains(&entry.child) {
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
                            && !writer.has_block(&bdig)
                            && !pack_builder.contains(&bdig)
                        {
                            let loc = head_store.lookup_block(&bdig).await?.ok_or(Errno::EIO)?;
                            loc.validate_v1()?;
                            let block_bytes = pack_store
                                .read_pack_range(&loc.pack_id, loc.offset, loc.len)
                                .await?;
                            verify_block_digest(&bdig, &block_bytes)?;
                            pack_builder.push(bdig, &block_bytes)?;
                            blocks_sent = blocks_sent.saturating_add(1);
                            for built in pack_builder.drain_finished() {
                                if writer.record_pack(&built)? {
                                    bytes_written = bytes_written.saturating_add(
                                        write_all_chunked(sink, &built.bytes).await?,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    for built in pack_builder.finish()? {
        if writer.record_pack(&built)? {
            bytes_written =
                bytes_written.saturating_add(write_all_chunked(sink, &built.bytes).await?);
        }
    }

    // Pass 2: Stream all reachable CoW B+tree nodes in canonical post-order, followed by `RootObject`.
    drop(visited_nodes);
    enum WalkFrame {
        Enter(Digest),
        Emit(Digest, Vec<u8>),
    }
    for sv_root in root_obj.subvols.values() {
        let mut stack = vec![WalkFrame::Enter(*sv_root)];
        while let Some(frame) = stack.pop() {
            match frame {
                WalkFrame::Enter(digest) => {
                    if writer.has_node(&digest) {
                        continue;
                    }
                    let raw = head_store.get_node(&digest).await?;
                    let node = Node::decode_verified(&digest, &raw)?;
                    match node {
                        Node::Internal { entries, .. } => {
                            stack.push(WalkFrame::Emit(digest, raw));
                            for entry in entries.into_iter().rev() {
                                if !writer.has_node(&entry.child) {
                                    stack.push(WalkFrame::Enter(entry.child));
                                }
                            }
                        }
                        Node::Leaf { .. } => {
                            if let Some(len_be) = writer.record_node(digest, &raw)? {
                                bytes_written = bytes_written
                                    .saturating_add(write_all_chunked(sink, &len_be).await?);
                                bytes_written = bytes_written
                                    .saturating_add(write_all_chunked(sink, &raw).await?);
                                nodes_sent = nodes_sent.saturating_add(1);
                            }
                        }
                    }
                }
                WalkFrame::Emit(digest, raw) => {
                    if let Some(len_be) = writer.record_node(digest, &raw)? {
                        bytes_written =
                            bytes_written.saturating_add(write_all_chunked(sink, &len_be).await?);
                        bytes_written =
                            bytes_written.saturating_add(write_all_chunked(sink, &raw).await?);
                        nodes_sent = nodes_sent.saturating_add(1);
                    }
                }
            }
        }
    }

    if let Some(len_be) = writer.record_node(root_digest, &raw_root)? {
        bytes_written = bytes_written.saturating_add(write_all_chunked(sink, &len_be).await?);
        bytes_written = bytes_written.saturating_add(write_all_chunked(sink, &raw_root).await?);
        nodes_sent = nodes_sent.saturating_add(1);
    }

    // Pass 3: Sorted binary index + 96-byte `OSCOWA1F` footer.
    for chunk in writer.finish_chunks(root_digest)? {
        bytes_written += write_all_chunked(sink, &chunk).await?;
    }

    Ok(CowfsSendResp {
        volume: volume.0.clone(),
        snapshot: snapshot_label.to_string(),
        root: digest_to_hex(&root_digest),
        parent_root: None,
        bytes_written,
        nodes_sent,
        blocks_sent,
        subtrees_skipped: 0,
    })
}

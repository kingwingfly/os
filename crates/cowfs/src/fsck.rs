//! Offline/read-only volume integrity checker (`os_cowfs::fsck::verify_volume`, Blueprint §1.2,
//! §3.2, `contract.md` §2.15).
//!
//! Verifies:
//! 1. `HeadStore::format_version()` matches `COWFS_FORMAT_VERSION` (refusing incompatible formats
//!    with `EPROTONOSUPPORT` without mutating any volume data).
//! 2. `RootObject` SHA-256, magic `"OSCOWFS1"`, and format version.
//! 3. Every reachable CoW B+tree node's SHA-256, `<= 16 KiB` size bound, strictly sorted keys,
//!    and internal separator key bounds.
//! 4. Filesystem invariants: root inode `1` is a directory; every `DIR_ITEM` matches a
//!    `DIR_INDEX` and targets an existing `INODE_ITEM`.
//! 5. Every out-of-line `EXTENT_DATA` block exists in `HeadStore::lookup_block`, reads cleanly
//!    from `PackStore::read_pack_range`, and matches its exact SHA-256 digest.
//! 6. Every referenced pack's self-describing `COWP` trailer passes SHA-256 verification.

use crate::archive_pack::ArchiveHeadStore;
use crate::fs::ROOT_INO;
use crate::inode::{DirIndexValue, DirItemValue, ExtentDataValue, InodeItem};
use abi::Errno;
use abi::fs::FileType;
use abi::volume::CowfsFsckResp;
use cowtree::archive::ArchiveReader;
use cowtree::stream::STREAM_CHUNK_BYTES;
use cowtree::{
    COWFS_FORMAT_VERSION, Digest, HeadStore, KIND_DIR_INDEX, KIND_DIR_ITEM, KIND_EXTENT_DATA,
    KIND_INODE_ITEM, KIND_ORPHAN_ITEM, Node, PackId, PackStore, RootObject, TreeKey, digest_to_hex,
    verify_block_digest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use vfs::Result;

/// Detailed integrity report returned by [`verify_volume`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsckReport {
    pub ok: bool,
    pub volume: String,
    pub epoch: u64,
    pub subvols_checked: usize,
    pub nodes_verified: usize,
    pub extents_verified: usize,
    pub packs_verified: usize,
    pub orphan_inodes: usize,
    pub errors: Vec<String>,
}

/// Verify an exact `root_digest` and every reachable subvolume, CoW B+tree node, extent block,
/// and pack trailer against `head_store` + `pack_store` without mutating any data.
///
/// Used by [`verify_head_pinned`], [`verify_snapshot`], [`verify_archive_file`], and pre-commit
/// validation inside `cowfs receive`.
pub async fn verify_root_reachable<H: HeadStore, P: PackStore>(
    head_store: &H,
    pack_store: &P,
    volume_label: &str,
    epoch: u64,
    root_digest: Digest,
) -> Result<FsckReport> {
    if let Some(ver) = head_store.format_version().await?
        && ver != COWFS_FORMAT_VERSION
    {
        return Err(Errno::EPROTONOSUPPORT);
    }

    let mut report = FsckReport {
        ok: true,
        volume: volume_label.to_string(),
        epoch,
        ..FsckReport::default()
    };

    let raw_root = match head_store.get_node(&root_digest).await {
        Ok(b) => b,
        Err(e) => {
            report.errors.push(format!("missing root node: {e:?}"));
            report.ok = false;
            return Ok(report);
        }
    };
    let root_obj = match RootObject::decode_verified(&root_digest, &raw_root) {
        Ok(r) => {
            report.nodes_verified += 1;
            r
        }
        Err(Errno::EPROTONOSUPPORT) => return Err(Errno::EPROTONOSUPPORT),
        Err(e) => {
            report
                .errors
                .push(format!("corrupt root object {root_digest:?}: {e:?}"));
            report.ok = false;
            return Ok(report);
        }
    };

    let mut verified_nodes: HashSet<Digest> = HashSet::new();
    let mut verified_blocks: HashMap<Digest, Option<u32>> = HashMap::new();
    let mut verified_packs: HashSet<PackId> = HashSet::new();

    if !root_obj.subvols.contains_key(crate::DEFAULT_SUBVOL) {
        report.errors.push(format!(
            "root object missing required default subvolume '{}'",
            crate::DEFAULT_SUBVOL
        ));
    }

    for (subvol_name, subvol_root) in &root_obj.subvols {
        report.subvols_checked += 1;
        verify_subvol(
            head_store,
            pack_store,
            subvol_name,
            *subvol_root,
            root_obj.next_ino,
            &mut verified_nodes,
            &mut verified_blocks,
            &mut verified_packs,
            &mut report,
        )
        .await
        .or_else(|err| {
            if !matches!(err, Errno::EIO | Errno::ENOENT) {
                return Err(err);
            }
            report.errors.push(format!(
                "subvol {subvol_name}: invalid tree or inode relationship ({err:?})"
            ));
            Ok(())
        })?;
        if report.errors.len() >= 32 {
            break;
        }
    }

    report.ok = report.errors.is_empty();
    Ok(report)
}

/// Verify an exact pinned `cowfs` [`cowtree::VolumeHead`] end-to-end without mutating any data.
///
/// Caller MUST already protect `head` from concurrent garbage collection (e.g., by holding the
/// shared GC lock `head_store.acquire_gc_lock(false)` or an active RO/writer pin). For callers
/// without an outer GC lock, use [`verify_head`] or [`verify_volume`].
///
/// Returns `Err(Errno::EPROTONOSUPPORT)` on incompatible format version. Structural and checksum
/// corruptions are recorded in `report.errors` (`report.ok == false`).
pub async fn verify_head_pinned<H: HeadStore, P: PackStore>(
    head_store: &H,
    pack_store: &P,
    head: &cowtree::VolumeHead,
) -> Result<FsckReport> {
    if head.format_version != COWFS_FORMAT_VERSION {
        return Err(Errno::EPROTONOSUPPORT);
    }
    verify_root_reachable(
        head_store,
        pack_store,
        &head.volume.0,
        head.epoch,
        head.root,
    )
    .await
}

/// Verify a named snapshot inside `volume` end-to-end while holding the shared GC lock.
pub async fn verify_snapshot<H: HeadStore, P: PackStore>(
    head_store: &H,
    pack_store: &P,
    volume: &cowtree::VolumeId,
    snapshot: &str,
) -> Result<(Digest, FsckReport)> {
    if snapshot.is_empty() || snapshot.contains(['/', '\0']) {
        return Err(Errno::EINVAL);
    }
    let (head, report) = verify_view(head_store, pack_store, volume, Some(snapshot), None).await?;
    Ok((head.root, report))
}

/// Verify a self-contained read-only `.cowpack` (`OSCOWA1\0`) archive file end-to-end via
/// zero-copy `ArchiveReader::read_at` calls without loading the whole file into memory.
///
/// Returns `Err(Errno::EPROTONOSUPPORT)` on incompatible archive/root format version.
/// Any header, footer, index, pack, node, or block corruption returns `Ok(resp)` with
/// `resp.ok == false` and descriptive `resp.errors` (causing `cowfsck --archive` to exit `4`).
pub async fn verify_archive_file<R: ArchiveReader + 'static>(
    reader: Rc<R>,
    label: &str,
) -> Result<CowfsFsckResp> {
    // Distinguish errors raised by the backing provider (including EIO) from
    // EIO produced by format and digest checks above that provider.
    let observed = Rc::new(ObservedReader {
        reader,
        error: Default::default(),
    });
    let result = verify_archive_contents(observed.clone(), label).await;
    match observed.error.get() {
        Some(err) => Err(err),
        None => result,
    }
}

struct ObservedReader<R> {
    reader: Rc<R>,
    error: std::cell::Cell<Option<Errno>>,
}

impl<R: ArchiveReader> ArchiveReader for ObservedReader<R> {
    fn size(&self) -> vfs::BoxFuture<'_, u64> {
        Box::pin(async move {
            self.reader
                .size()
                .await
                .inspect_err(|err| self.error.set(Some(*err)))
        })
    }
    fn read_at(&self, off: u64, len: usize) -> vfs::BoxFuture<'_, Vec<u8>> {
        Box::pin(async move {
            self.reader
                .read_at(off, len)
                .await
                .inspect_err(|err| self.error.set(Some(*err)))
        })
    }
}

async fn verify_archive_contents<R: ArchiveReader + 'static>(
    reader: Rc<R>,
    label: &str,
) -> Result<CowfsFsckResp> {
    let (hs, ps) = match ArchiveHeadStore::open(reader, label.to_string()).await {
        Ok(pair) => pair,
        Err(Errno::EPROTONOSUPPORT) => return Err(Errno::EPROTONOSUPPORT),
        Err(e) => {
            return Ok(CowfsFsckResp {
                ok: false,
                volume: label.to_string(),
                format_version: COWFS_FORMAT_VERSION,
                epoch: 0,
                root: String::new(),
                subvols_checked: 0,
                nodes_verified: 0,
                extents_verified: 0,
                packs_verified: 0,
                orphan_inodes: 0,
                errors: vec![format!(
                    "archive header/footer/index verification failed: {e:?}"
                )],
            });
        }
    };

    let root_digest = hs.footer().root_digest;
    let mut report = verify_root_reachable(&hs, &ps, label, 0, root_digest).await?;

    // Stream-verify every indexed pack's full SHA-256 in bounded `64 KiB` chunks so any bit-flip
    // anywhere inside a pack (even in padding or unreferenced regions) is detected.
    for idx in 0..hs.index().packs.len() {
        let pack_entry = hs.index().pack_at(&**hs.reader(), idx).await?;
        if report.errors.len() >= 32 {
            break;
        }
        let mut hasher = Sha256::new();
        let mut rem = pack_entry.len as usize;
        let mut off = pack_entry.offset;
        let mut io_failed = false;
        while rem > 0 {
            let take = rem.min(STREAM_CHUNK_BYTES);
            match hs.reader().read_at(off, take).await {
                Ok(chunk) if chunk.len() == take => {
                    hasher.update(&chunk);
                    off = off.saturating_add(take as u64);
                    rem -= take;
                }
                Ok(_) => {
                    report
                        .errors
                        .push(format!("archive pack #{idx}: short read"));
                    io_failed = true;
                    break;
                }
                Err(e) => {
                    report
                        .errors
                        .push(format!("archive pack #{idx}: read failed: {e:?}"));
                    io_failed = true;
                    break;
                }
            }
        }
        if !io_failed {
            let actual = hasher.finalize();
            if actual.as_slice() != pack_entry.digest {
                report.errors.push(format!(
                    "archive pack #{idx} ({}): SHA-256 mismatch",
                    digest_to_hex(&pack_entry.digest)
                ));
            }
        }
    }

    for idx in 0..hs.index().nodes.len() {
        if report.errors.len() >= 32 {
            break;
        }
        let node = hs.index().node_at(&**hs.reader(), idx).await?;
        if hs.get_node(&node.digest).await.is_err() {
            report.errors.push(format!(
                "archive node #{idx}: invalid length prefix or digest"
            ));
        }
    }
    report.packs_verified = report.packs_verified.max(hs.index().packs.len());
    report.ok = report.errors.is_empty();

    Ok(CowfsFsckResp {
        ok: report.ok,
        volume: label.to_string(),
        format_version: COWFS_FORMAT_VERSION,
        epoch: 0,
        root: digest_to_hex(&root_digest),
        subvols_checked: report.subvols_checked,
        nodes_verified: report.nodes_verified,
        extents_verified: report.extents_verified,
        packs_verified: report.packs_verified,
        orphan_inodes: report.orphan_inodes,
        errors: report.errors,
    })
}

/// Verify an exact [`cowtree::VolumeHead`] end-to-end while holding the shared GC lock so
/// concurrent garbage collection cannot sweep objects belonging to `head` during the scan.
pub async fn verify_head<H: HeadStore, P: PackStore>(
    head_store: &H,
    pack_store: &P,
    head: &cowtree::VolumeHead,
) -> Result<FsckReport> {
    verify_view(head_store, pack_store, &head.volume, None, Some(head))
        .await
        .map(|(_, report)| report)
}

/// Verify a `cowfs` volume end-to-end without mutating any data.
///
/// Acquires the shared GC lock BEFORE reading the volume head so concurrent GC cannot sweep
/// objects reachable from the head being scanned.
///
/// Returns `Err(Errno::EPROTONOSUPPORT)` on incompatible format version and `Err(Errno::ENOENT)`
/// if `volume` does not exist. Structural and checksum corruptions are recorded in `report.errors`
/// (`report.ok == false`).
pub async fn verify_volume<H: HeadStore, P: PackStore>(
    head_store: &H,
    pack_store: &P,
    volume: &cowtree::VolumeId,
) -> Result<FsckReport> {
    verify_view(head_store, pack_store, volume, None, None)
        .await
        .map(|(_, report)| report)
}

pub(crate) async fn verify_view<H: HeadStore, P: PackStore>(
    head_store: &H,
    pack_store: &P,
    volume: &cowtree::VolumeId,
    snapshot: Option<&str>,
    exact: Option<&cowtree::VolumeHead>,
) -> Result<(cowtree::VolumeHead, FsckReport)> {
    let _gc_guard = head_store.acquire_gc_lock(false).await?;
    if head_store
        .format_version()
        .await?
        .is_some_and(|v| v != COWFS_FORMAT_VERSION)
    {
        return Err(Errno::EPROTONOSUPPORT);
    }
    let (head, pin) = head_store.pin_view(volume, snapshot, exact).await?;
    let result = verify_head_pinned(head_store, pack_store, &head).await;
    if let Some(pin) = pin {
        head_store.unpin_ro_root(pin).await?;
    }
    Ok((head, result?))
}

/// Same as [`verify_volume`], returning `Err(Errno::EIO)` if any integrity error was detected.
pub async fn verify_volume_strict<H: HeadStore, P: PackStore>(
    head_store: &H,
    pack_store: &P,
    volume: &cowtree::VolumeId,
) -> Result<FsckReport> {
    let report = verify_volume(head_store, pack_store, volume).await?;
    if !report.ok {
        return Err(Errno::EIO);
    }
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
async fn verify_subvol<H: HeadStore, P: PackStore>(
    head_store: &H,
    pack_store: &P,
    subvol_name: &str,
    root_digest: Digest,
    next_ino: u64,
    verified_nodes: &mut HashSet<Digest>,
    verified_blocks: &mut HashMap<Digest, Option<u32>>,
    verified_packs: &mut HashSet<PackId>,
    report: &mut FsckReport,
) -> Result<()> {
    // An exact first-key match inside disjoint sibling intervals proves unique ownership.
    // A repeated child cannot satisfy both intervals, and each edge must decrease the level.
    type WalkFrame = (Digest, Option<u8>, Option<TreeKey>, Option<TreeKey>);
    // Stack of (digest, expected_level, lower_bound_inclusive, upper_bound_exclusive).
    let mut stack: Vec<WalkFrame> = vec![(root_digest, None, None, None)];

    while let Some((digest, expected_level, lo, hi)) = stack.pop() {
        let raw = head_store.get_node(&digest).await?;
        let node = Node::decode_verified(&digest, &raw)?;
        if expected_level.is_some_and(|level| level != node.level()) {
            return Err(Errno::EIO);
        }
        let (first, last) = match &node {
            Node::Internal { entries, .. } => (
                entries.first().map(|e| &e.key),
                entries.last().map(|e| &e.key),
            ),
            Node::Leaf { entries } => (
                entries.first().map(|e| &e.key),
                entries.last().map(|e| &e.key),
            ),
        };
        if lo.as_ref().is_some_and(|bound| Some(bound) != first)
            || hi
                .as_ref()
                .is_some_and(|bound| last.is_none_or(|key| key >= bound))
        {
            return Err(Errno::EIO);
        }
        if verified_nodes.len() == 8192 {
            verified_nodes.clear();
        }
        if verified_nodes.insert(digest) {
            report.nodes_verified += 1;
        }
        if let Node::Internal { level, entries } = node {
            if entries.is_empty() || level == 0 {
                return Err(Errno::EIO);
            }
            for (i, entry) in entries.iter().enumerate() {
                let upper = entries
                    .get(i + 1)
                    .map(|e| e.key.clone())
                    .or_else(|| hi.clone());
                stack.push((entry.child, Some(level - 1), Some(entry.key.clone()), upper));
            }
        }
    }
    // Only perform indexed lookups after every separator and child edge is validated.
    let arena = std::cell::RefCell::new(cowtree::Arena::new(cowtree::ArenaConfig {
        tree_lru_bytes: 512 * 1024,
        clean_data_bytes: 0,
        dirty_bytes: 0,
    }));
    let tree = cowtree::CowTree::new(head_store, &arena);
    let inode = async |ino| {
        let bytes = tree
            .get(&root_digest, &TreeKey::inode_item(ino))
            .await?
            .ok_or(Errno::EIO)?;
        InodeItem::decode(&bytes)
    };
    if inode(ROOT_INO).await?.file_type != FileType::Dir {
        return Err(Errno::EIO);
    }
    let mut start = TreeKey::ino_start(0);
    let end = TreeKey::new(u64::MAX, u8::MAX, vec![]);
    loop {
        let page = tree.scan_range(&root_digest, &start, &end, 64).await?;
        let Some((last, _)) = page.last() else { break };
        start = last.clone();
        start.tail.push(0);
        for (key, value) in page {
            match key.kind {
                KIND_INODE_ITEM => {
                    InodeItem::decode(&value)?;
                    if !key.tail.is_empty() || key.ino >= next_ino {
                        return Err(Errno::EIO);
                    }
                }
                KIND_DIR_ITEM => {
                    let item = DirItemValue::decode(&value)?;
                    let index = tree
                        .get(&root_digest, &TreeKey::dir_index(key.ino, item.dir_index))
                        .await?
                        .ok_or(Errno::EIO)?;
                    let idx = DirIndexValue::decode(&index)?;
                    let child = inode(item.child_ino).await?;
                    if idx.name.as_bytes() != key.tail
                        || idx.child_ino != item.child_ino
                        || idx.child_gen != item.child_gen
                        || idx.file_type != item.file_type
                        || child.nlink == 0
                        || child.generation != item.child_gen
                        || child.file_type != item.file_type
                    {
                        return Err(Errno::EIO);
                    }
                }
                KIND_DIR_INDEX => {
                    let idx = DirIndexValue::decode(&value)?;
                    let item = tree
                        .get(&root_digest, &TreeKey::dir_item(key.ino, &idx.name))
                        .await?
                        .ok_or(Errno::EIO)?;
                    if Some(DirItemValue::decode(&item)?.dir_index) != key.tail_u64() {
                        return Err(Errno::EIO);
                    }
                }
                KIND_ORPHAN_ITEM => {
                    let ino = key.tail_u64().ok_or(Errno::EIO)?;
                    if key.ino != 0
                        || ino == ROOT_INO
                        || !value.is_empty()
                        || inode(ino).await?.nlink != 0
                        || !tree
                            .scan_range(
                                &root_digest,
                                &TreeKey::kind_start(ino, cowtree::KIND_INODE_REF),
                                &TreeKey::kind_end(ino, cowtree::KIND_INODE_REF),
                                1,
                            )
                            .await?
                            .is_empty()
                    {
                        return Err(Errno::EIO);
                    }
                    report.orphan_inodes += 1;
                }
                KIND_EXTENT_DATA => {
                    if let ExtentDataValue::Extent {
                        len,
                        digest,
                        block_offset,
                    } = ExtentDataValue::decode(&value)?
                    {
                        let backing_len = if let Some(&cached) = verified_blocks.get(&digest) {
                            cached
                        } else {
                            let size = verify_extent_block(
                                head_store,
                                pack_store,
                                subvol_name,
                                &digest,
                                verified_packs,
                                report,
                            )
                            .await;
                            if verified_blocks.len() == 8192 {
                                verified_blocks.clear();
                            }
                            verified_blocks.insert(digest, size);
                            size
                        };
                        if let Some(size) = backing_len
                            && block_offset.checked_add(len).is_none_or(|end| end > size)
                        {
                            report.errors.push(format!("subvol {subvol_name}: extent slice exceeds backing block length {size}"));
                        }
                    }
                    report.extents_verified += 1;
                }
                _ => {}
            }
            if report.errors.len() >= 32 {
                return Ok(());
            }
        }
    }
    Ok(())
}

async fn verify_extent_block<H: HeadStore, P: PackStore>(
    head_store: &H,
    pack_store: &P,
    subvol_name: &str,
    block_digest: &Digest,
    verified_packs: &mut HashSet<PackId>,
    report: &mut FsckReport,
) -> Option<u32> {
    let loc = match head_store.lookup_block(block_digest).await {
        Ok(Some(loc)) => loc,
        Ok(None) => {
            report
                .errors
                .push(format!("subvol {subvol_name}: unindexed block digest"));
            return None;
        }
        Err(e) => {
            report
                .errors
                .push(format!("subvol {subvol_name}: block lookup failed: {e:?}"));
            return None;
        }
    };
    if loc.validate_v1().is_err() {
        report.errors.push(format!(
            "subvol {subvol_name}: invalid v1 block index entry in pack {}",
            loc.pack_id.0
        ));
        return None;
    }
    if verified_packs.len() == 8192 {
        verified_packs.clear();
    }
    if verified_packs.insert(loc.pack_id.clone()) {
        report.packs_verified += 1;
        if let Err(e) = pack_store.read_pack_trailer(&loc.pack_id).await {
            report.errors.push(format!(
                "subvol {subvol_name}: pack {} trailer verification failed: {e:?}",
                loc.pack_id.0
            ));
        }
    }
    match pack_store
        .read_pack_range(&loc.pack_id, loc.offset, loc.len)
        .await
    {
        Ok(bytes) => {
            if bytes.len() != loc.len as usize {
                report.errors.push(format!(
                    "subvol {subvol_name}: short pack read in pack {}",
                    loc.pack_id.0
                ));
                return None;
            }
            if let Err(e) = verify_block_digest(block_digest, &bytes) {
                report.errors.push(format!(
                    "subvol {subvol_name}: block digest mismatch in pack {}: {e:?}",
                    loc.pack_id.0
                ));
                return None;
            }
            Some(loc.len)
        }
        Err(e) => {
            report.errors.push(format!(
                "subvol {subvol_name}: pack read failed for {}: {e:?}",
                loc.pack_id.0
            ));
            None
        }
    }
}

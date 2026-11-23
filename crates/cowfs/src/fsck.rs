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

    for (subvol_name, subvol_root) in &root_obj.subvols {
        report.subvols_checked += 1;
        verify_subvol(
            head_store,
            pack_store,
            subvol_name,
            *subvol_root,
            &mut verified_nodes,
            &mut verified_blocks,
            &mut verified_packs,
            &mut report,
        )
        .await;
    }

    report.packs_verified = verified_packs.len();
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
    let _gc_guard = head_store.acquire_gc_lock(false).await?;
    if let Some(ver) = head_store.format_version().await?
        && ver != COWFS_FORMAT_VERSION
    {
        return Err(Errno::EPROTONOSUPPORT);
    }
    let snap = head_store.get_snapshot(volume, snapshot).await?;
    let report =
        verify_root_reachable(head_store, pack_store, &volume.0, snap.epoch, snap.root).await?;
    Ok((snap.root, report))
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
    for (idx, pack_entry) in hs.index().packs.iter().enumerate() {
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
    let _gc_guard = head_store.acquire_gc_lock(false).await?;
    verify_head_pinned(head_store, pack_store, head).await
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
    let _gc_guard = head_store.acquire_gc_lock(false).await?;
    if let Some(ver) = head_store.format_version().await?
        && ver != COWFS_FORMAT_VERSION
    {
        return Err(Errno::EPROTONOSUPPORT);
    }
    let head = head_store.read_head(volume).await?;
    verify_head_pinned(head_store, pack_store, &head).await
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
    verified_nodes: &mut HashSet<Digest>,
    verified_blocks: &mut HashMap<Digest, Option<u32>>,
    verified_packs: &mut HashSet<PackId>,
    report: &mut FsckReport,
) {
    let mut inodes: HashMap<u64, InodeItem> = HashMap::new();
    let mut dir_items: Vec<(u64, String, DirItemValue)> = Vec::new();
    let mut dir_indices: HashMap<(u64, u64), DirIndexValue> = HashMap::new();

    type WalkFrame = (Digest, Option<u8>, Option<TreeKey>, Option<TreeKey>);
    // Stack of (digest, expected_level, lower_bound_inclusive, upper_bound_exclusive).
    let mut stack: Vec<WalkFrame> = vec![(root_digest, None, None, None)];

    while let Some((digest, expected_level, lo, hi)) = stack.pop() {
        let raw = match head_store.get_node(&digest).await {
            Ok(b) => b,
            Err(e) => {
                report
                    .errors
                    .push(format!("subvol {subvol_name}: missing node: {e:?}"));
                continue;
            }
        };
        let node = match Node::decode_verified(&digest, &raw) {
            Ok(n) => n,
            Err(e) => {
                report.errors.push(format!(
                    "subvol {subvol_name}: node SHA-256/decode failed: {e:?}"
                ));
                continue;
            }
        };
        if let Some(exp) = expected_level
            && node.level() != exp
        {
            report.errors.push(format!(
                "subvol {subvol_name}: B+tree level mismatch: expected {exp}, got {}",
                node.level()
            ));
        }
        if verified_nodes.insert(digest) {
            report.nodes_verified += 1;
        }
        match node {
            Node::Internal { level, entries } => {
                if entries.len() < 2 {
                    report.errors.push(format!(
                        "subvol {subvol_name}: uncollapsed single-child internal node at level {level}"
                    ));
                }
                let child_expected_level = level.checked_sub(1);
                for (idx, entry) in entries.iter().enumerate() {
                    if let Some(ref l) = lo
                        && entry.key < *l
                    {
                        report
                            .errors
                            .push(format!("subvol {subvol_name}: key below separator bound"));
                    }
                    if let Some(ref h) = hi
                        && entry.key >= *h
                    {
                        report
                            .errors
                            .push(format!("subvol {subvol_name}: key above upper bound"));
                    }
                    let child_lo = Some(entry.key.clone());
                    let child_hi = entries
                        .get(idx + 1)
                        .map(|next| next.key.clone())
                        .or_else(|| hi.clone());
                    stack.push((entry.child, child_expected_level, child_lo, child_hi));
                }
            }
            Node::Leaf { entries } => {
                for entry in entries {
                    if let Some(ref l) = lo
                        && entry.key < *l
                    {
                        report
                            .errors
                            .push(format!("subvol {subvol_name}: leaf key below lower bound"));
                    }
                    if let Some(ref h) = hi
                        && entry.key >= *h
                    {
                        report
                            .errors
                            .push(format!("subvol {subvol_name}: leaf key above upper bound"));
                    }
                    match entry.key.kind {
                        KIND_INODE_ITEM => match InodeItem::decode(&entry.value) {
                            Ok(item) => {
                                inodes.insert(entry.key.ino, item);
                            }
                            Err(e) => report.errors.push(format!(
                                "subvol {subvol_name}: corrupt inode {}: {e:?}",
                                entry.key.ino
                            )),
                        },
                        KIND_DIR_ITEM => match DirItemValue::decode(&entry.value) {
                            Ok(di) => {
                                let name = String::from_utf8_lossy(&entry.key.tail).into_owned();
                                dir_items.push((entry.key.ino, name, di));
                            }
                            Err(e) => report
                                .errors
                                .push(format!("subvol {subvol_name}: corrupt dir item: {e:?}")),
                        },
                        KIND_DIR_INDEX => {
                            match (entry.key.tail_u64(), DirIndexValue::decode(&entry.value)) {
                                (Some(didx), Ok(dv)) => {
                                    dir_indices.insert((entry.key.ino, didx), dv);
                                }
                                _ => report
                                    .errors
                                    .push(format!("subvol {subvol_name}: corrupt dir index")),
                            }
                        }
                        KIND_ORPHAN_ITEM => {
                            report.orphan_inodes += 1;
                        }
                        KIND_EXTENT_DATA => match ExtentDataValue::decode(&entry.value) {
                            Ok(ExtentDataValue::Inline(_)) => {
                                report.extents_verified += 1;
                            }
                            Ok(ExtentDataValue::Extent {
                                len,
                                digest: bdig,
                                block_offset,
                            }) => {
                                let backing_len = if let Some(&cached) = verified_blocks.get(&bdig)
                                {
                                    cached
                                } else {
                                    let len_opt = verify_extent_block(
                                        head_store,
                                        pack_store,
                                        subvol_name,
                                        &bdig,
                                        verified_packs,
                                        report,
                                    )
                                    .await;
                                    verified_blocks.insert(bdig, len_opt);
                                    len_opt
                                };
                                if let Some(backing_len) = backing_len {
                                    match block_offset.checked_add(len) {
                                        Some(end) if end <= backing_len => {}
                                        _ => report.errors.push(format!(
                                            "subvol {subvol_name}: extent slice [{block_offset}..+{len}] exceeds backing block length {backing_len}"
                                        )),
                                    }
                                }
                                report.extents_verified += 1;
                            }
                            Err(e) => report
                                .errors
                                .push(format!("subvol {subvol_name}: corrupt extent: {e:?}")),
                        },
                        _ => {}
                    }
                }
            }
        }
    }

    // Structural filesystem checks.
    match inodes.get(&ROOT_INO) {
        Some(root) if root.file_type == FileType::Dir => {}
        _ => report.errors.push(format!(
            "subvol {subvol_name}: missing or non-dir root inode"
        )),
    }
    for (dir_ino, name, di) in &dir_items {
        if !inodes.contains_key(&di.child_ino) {
            report.errors.push(format!(
                "subvol {subvol_name}: dir {dir_ino} entry {name:?} targets missing inode {}",
                di.child_ino
            ));
        }
        match dir_indices.get(&(*dir_ino, di.dir_index)) {
            Some(idx_val) if idx_val.child_ino == di.child_ino && idx_val.name == *name => {}
            _ => report.errors.push(format!(
                "subvol {subvol_name}: dir {dir_ino} entry {name:?} missing matching DIR_INDEX {}",
                di.dir_index
            )),
        }
    }
    if dir_items.len() != dir_indices.len() {
        report.errors.push(format!(
            "subvol {subvol_name}: DIR_ITEM count ({}) != DIR_INDEX count ({})",
            dir_items.len(),
            dir_indices.len()
        ));
    }
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
    if loc.flags != 0 || loc.raw_len != loc.len || loc.len > cowtree::EXTENT_MAX_BYTES {
        report.errors.push(format!(
            "subvol {subvol_name}: invalid v1 block index entry in pack {}",
            loc.pack_id.0
        ));
        return None;
    }
    if verified_packs.insert(loc.pack_id.clone())
        && let Err(e) = pack_store.read_pack_trailer(&loc.pack_id).await
    {
        report.errors.push(format!(
            "subvol {subvol_name}: pack {} trailer verification failed: {e:?}",
            loc.pack_id.0
        ));
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

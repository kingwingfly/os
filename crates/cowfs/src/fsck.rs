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

use crate::fs::ROOT_INO;
use crate::inode::{DirIndexValue, DirItemValue, ExtentDataValue, InodeItem};
use abi::Errno;
use abi::fs::FileType;
use cowtree::{
    COWFS_FORMAT_VERSION, Digest, HeadStore, KIND_DIR_INDEX, KIND_DIR_ITEM, KIND_EXTENT_DATA,
    KIND_INODE_ITEM, KIND_ORPHAN_ITEM, Node, PackId, PackStore, RootObject, TreeKey,
    verify_block_digest,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
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

/// Verify a `cowfs` volume end-to-end without mutating any data.
///
/// Returns `Err(Errno::EPROTONOSUPPORT)` on incompatible format version and `Err(Errno::ENOENT)`
/// if `volume` does not exist. Structural and checksum corruptions are recorded in `report.errors`
/// (`report.ok == false`).
pub async fn verify_volume<H: HeadStore, P: PackStore>(
    head_store: &H,
    pack_store: &P,
    volume: &cowtree::VolumeId,
) -> Result<FsckReport> {
    if let Some(ver) = head_store.format_version().await?
        && ver != COWFS_FORMAT_VERSION
    {
        return Err(Errno::EPROTONOSUPPORT);
    }
    let head = head_store.read_head(volume).await?;
    if head.format_version != COWFS_FORMAT_VERSION {
        return Err(Errno::EPROTONOSUPPORT);
    }

    let mut report = FsckReport {
        ok: true,
        volume: volume.0.clone(),
        epoch: head.epoch,
        ..FsckReport::default()
    };

    let raw_root = match head_store.get_node(&head.root).await {
        Ok(b) => b,
        Err(e) => {
            report.errors.push(format!("missing root node: {e:?}"));
            report.ok = false;
            return Ok(report);
        }
    };
    let root_obj = match RootObject::decode_verified(&head.root, &raw_root) {
        Ok(r) => {
            report.nodes_verified += 1;
            r
        }
        Err(Errno::EPROTONOSUPPORT) => return Err(Errno::EPROTONOSUPPORT),
        Err(e) => {
            report
                .errors
                .push(format!("corrupt root object {:?}: {e:?}", head.root));
            report.ok = false;
            return Ok(report);
        }
    };

    let mut verified_nodes: HashSet<Digest> = HashSet::new();
    let mut verified_blocks: HashSet<Digest> = HashSet::new();
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
    verified_blocks: &mut HashSet<Digest>,
    verified_packs: &mut HashSet<PackId>,
    report: &mut FsckReport,
) {
    let mut inodes: HashMap<u64, InodeItem> = HashMap::new();
    let mut dir_items: Vec<(u64, String, DirItemValue)> = Vec::new();
    let mut dir_indices: HashMap<(u64, u64), DirIndexValue> = HashMap::new();

    // Stack of (digest, lower_bound_inclusive, upper_bound_exclusive).
    let mut stack: Vec<(Digest, Option<TreeKey>, Option<TreeKey>)> =
        vec![(root_digest, None, None)];

    while let Some((digest, lo, hi)) = stack.pop() {
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
        if verified_nodes.insert(digest) {
            report.nodes_verified += 1;
        }
        match node {
            Node::Internal { entries, .. } => {
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
                    stack.push((entry.child, child_lo, child_hi));
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
                            Ok(ExtentDataValue::Extent { digest: bdig, .. }) => {
                                if verified_blocks.insert(bdig) {
                                    verify_extent_block(
                                        head_store,
                                        pack_store,
                                        subvol_name,
                                        &bdig,
                                        verified_packs,
                                        report,
                                    )
                                    .await;
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
) {
    let loc = match head_store.lookup_block(block_digest).await {
        Ok(Some(loc)) => loc,
        Ok(None) => {
            report
                .errors
                .push(format!("subvol {subvol_name}: unindexed block digest"));
            return;
        }
        Err(e) => {
            report
                .errors
                .push(format!("subvol {subvol_name}: block lookup failed: {e:?}"));
            return;
        }
    };
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
            if let Err(e) = verify_block_digest(block_digest, &bytes) {
                report.errors.push(format!(
                    "subvol {subvol_name}: block digest mismatch in pack {}: {e:?}",
                    loc.pack_id.0
                ));
            }
        }
        Err(e) => report.errors.push(format!(
            "subvol {subvol_name}: pack read failed for {}: {e:?}",
            loc.pack_id.0
        )),
    }
}

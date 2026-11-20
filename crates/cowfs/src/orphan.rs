//! Persistent `ORPHAN_ITEM` (`(0, 0x50, ino_be)`) handling for open-unlinked files and
//! directories (`contract.md` §2.15, §3).
//!
//! When an inode loses its last directory name (`nlink == 0`) while open references remain,
//! `CowFs` inserts an `ORPHAN_ITEM` into the single-map CoW B+tree. If the instance releases the
//! last open reference cleanly, the inode and its `ORPHAN_ITEM` are reclaimed immediately. If the
//! instance crashes after committing while the file is still open, the next `rw` mount scans
//! `ORPHAN_ITEM`s and reaps all unreachable open-unlinked inodes cleanly.

use cowtree::{CowTree, Digest, HeadStore, KIND_ORPHAN_ITEM, TreeKey, TreeOverlay};
use vfs::Result;

/// Mark `ino` as an open-unlinked orphan in `overlay`.
pub fn stage_orphan(overlay: &mut TreeOverlay, ino: u64) {
    overlay.put(TreeKey::orphan_item(ino), Vec::new());
}

/// Remove `ORPHAN_ITEM` for `ino` once reclaimed.
pub fn clear_orphan(overlay: &mut TreeOverlay, ino: u64) {
    overlay.delete(TreeKey::orphan_item(ino));
}

/// Stage full reclamation of all B+tree items belonging to `ino` (`INODE_ITEM`, `INODE_REF`,
/// `DIR_ITEM`, `DIR_INDEX`, `EXTENT_DATA`, `XATTR_ITEM`, and `ORPHAN_ITEM`).
pub async fn reclaim_inode_items<H: HeadStore>(
    tree: &CowTree<'_, H>,
    base_root: &Digest,
    overlay: &mut TreeOverlay,
    ino: u64,
) -> Result<()> {
    let mut start = TreeKey::ino_start(ino);
    let end = TreeKey::ino_end(ino);
    loop {
        let batch = tree
            .scan_range_with_overlay(base_root, overlay, &start, &end, 512)
            .await?;
        if batch.is_empty() {
            break;
        }
        let last_key = batch.last().unwrap().0.clone();
        let full = batch.len() == 512;
        for (k, _) in batch {
            overlay.delete(k);
        }
        if !full {
            break;
        }
        let mut next_tail = last_key.tail;
        next_tail.push(0);
        start = TreeKey::new(last_key.ino, last_key.kind, next_tail);
    }
    clear_orphan(overlay, ino);
    Ok(())
}

/// Scan all `ORPHAN_ITEM` entries recorded in `base_root` and stage their complete reclamation.
/// Returns the number of reaped orphan inodes.
pub async fn reap_all_orphans<H: HeadStore>(
    tree: &CowTree<'_, H>,
    base_root: &Digest,
    overlay: &mut TreeOverlay,
) -> Result<usize> {
    let mut orphan_inos = Vec::new();
    let mut start = TreeKey::kind_start(0, KIND_ORPHAN_ITEM);
    let end = TreeKey::kind_end(0, KIND_ORPHAN_ITEM);
    loop {
        let batch = tree.scan_range(base_root, &start, &end, 256).await?;
        if batch.is_empty() {
            break;
        }
        let last_key = batch.last().unwrap().0.clone();
        let full = batch.len() == 256;
        for (k, _) in batch {
            if let Some(ino) = k.tail_u64() {
                orphan_inos.push(ino);
            }
        }
        if !full {
            break;
        }
        let mut next_tail = last_key.tail;
        next_tail.push(0);
        start = TreeKey::new(last_key.ino, last_key.kind, next_tail);
    }

    for &ino in &orphan_inos {
        reclaim_inode_items(tree, base_root, overlay, ino).await?;
    }
    Ok(orphan_inos.len())
}

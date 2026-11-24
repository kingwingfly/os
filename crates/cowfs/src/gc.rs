//! Reachability garbage collector for `os-cowfs` (`contract.md` §2.15, Blueprint §3.2).
//!
//! Takes the exclusive GC lock (`acquire_gc_lock(true)` — serialized against writers' shared GC
//! locks), marks all CoW B+tree nodes and content-addressed data packs reachable from every live
//! volume head, named snapshot, and active grace-window pin, sweeps expired metadata rows via
//! `HeadStore::sweep_metadata`, and unlinks unreachable packs (including orphan packs left by
//! crashes between `PackStore::write_pack` and `HeadStore::commit_head`) from `PackStore`.

use crate::inode::ExtentDataValue;
use abi::Errno;
use abi::fs::Timespec;
use cowtree::{Digest, HeadStore, KIND_EXTENT_DATA, Node, PackId, PackStore, RootObject};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use vfs::Result;

/// Summary returned by [`collect_garbage`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcReport {
    pub live_roots: usize,
    pub live_nodes: usize,
    pub live_blocks: usize,
    pub live_packs: usize,
    pub swept_packs: Vec<PackId>,
}

/// Run one full mark-and-sweep garbage-collection pass at wall-clock timestamp `now`, honoring the
/// store's configured `grace_window_secs`.
pub async fn collect_garbage<H: HeadStore, P: PackStore>(
    head_store: &H,
    pack_store: &P,
    now: Timespec,
) -> Result<GcReport> {
    let grace_window_secs = head_store.grace_window_secs();
    collect_garbage_with_grace(head_store, pack_store, now, grace_window_secs).await
}

/// Run one full mark-and-sweep garbage-collection pass with an explicit `now` timestamp and
/// `grace_window_secs` duration:
/// - `grace_pins` expire when `pinned_until <= now`
/// - unreachable `nodes` / `packs` / abandoned unmodified ephemeral forks sweep when
///   `created_at + grace_window_secs <= now`.
pub async fn collect_garbage_with_grace<H: HeadStore, P: PackStore>(
    head_store: &H,
    pack_store: &P,
    now: Timespec,
    grace_window_secs: u64,
) -> Result<GcReport> {
    if let Some(report) = head_store.run_server_gc().await? {
        return Ok(GcReport {
            live_roots: report.live_roots,
            live_nodes: report.live_nodes,
            live_blocks: report.live_blocks,
            live_packs: report.live_packs,
            swept_packs: report.swept_packs.into_iter().map(PackId).collect(),
        });
    }
    let _gc_guard = head_store.acquire_gc_lock(true).await?;

    // Reap abandoned unmodified ephemeral forks older than grace whose writer lock is not held.
    let _ = head_store
        .prune_abandoned_ephemeral_forks(now, grace_window_secs)
        .await?;

    let all_roots = head_store.list_all_roots().await?;

    let mut keep_nodes: HashSet<Digest> = HashSet::new();
    let mut keep_blocks: HashSet<Digest> = HashSet::new();
    let mut keep_packs: HashSet<PackId> = HashSet::new();
    let mut live_roots = 0usize;

    for gc_root in &all_roots {
        // Expire grace pins when `pinned_until <= now`; live heads/snapshots/RO pins have `None`.
        if let Some(until) = gc_root.pinned_until
            && until <= now
        {
            continue;
        }
        live_roots += 1;
        if !keep_nodes.insert(gc_root.root) {
            continue;
        }
        let raw_root = head_store.get_node(&gc_root.root).await?;
        let root_obj = RootObject::decode_verified(&gc_root.root, &raw_root)?;
        for subvol_root in root_obj.subvols.values() {
            mark_tree(
                head_store,
                *subvol_root,
                &mut keep_nodes,
                &mut keep_blocks,
                &mut keep_packs,
            )
            .await?;
        }
    }

    let mut swept_set: HashSet<PackId> = head_store
        .sweep_metadata(&keep_nodes, &keep_packs, now, grace_window_secs)
        .await?
        .into_iter()
        .collect();

    // Unlink any genuine unindexed crash-orphan packs in `PackStore` (packs written just before
    // a crash prior to `commit_head`). Confirm orphan status authoritatively against `HeadStore`'s
    // `packs` and `blocks` indexes instead of guessing from pack trailer reads, so transient I/O
    // errors or grace-protected packs can never be deleted while still indexed.
    let indexed_packs = head_store.list_indexed_packs().await?;
    let all_packs = pack_store.list_packs().await?;
    for pack_id in all_packs {
        if keep_packs.contains(&pack_id)
            || swept_set.contains(&pack_id)
            || indexed_packs.contains(&pack_id)
        {
            continue;
        }
        swept_set.insert(pack_id);
    }

    let mut swept_packs: Vec<PackId> = swept_set.into_iter().collect();
    swept_packs.sort();
    for pack_id in &swept_packs {
        pack_store.delete_pack(pack_id).await?;
    }

    Ok(GcReport {
        live_roots,
        live_nodes: keep_nodes.len(),
        live_blocks: keep_blocks.len(),
        live_packs: keep_packs.len(),
        swept_packs,
    })
}

async fn mark_tree<H: HeadStore>(
    head_store: &H,
    tree_root: Digest,
    keep_nodes: &mut HashSet<Digest>,
    keep_blocks: &mut HashSet<Digest>,
    keep_packs: &mut HashSet<PackId>,
) -> Result<()> {
    let mut stack = vec![tree_root];
    while let Some(digest) = stack.pop() {
        if !keep_nodes.insert(digest) {
            continue;
        }
        let raw = head_store.get_node(&digest).await?;
        let node = Node::decode_verified(&digest, &raw)?;
        match node {
            Node::Internal { entries, .. } => {
                for entry in entries {
                    if !keep_nodes.contains(&entry.child) {
                        stack.push(entry.child);
                    }
                }
            }
            Node::Leaf { entries } => {
                for entry in entries {
                    if entry.key.kind == KIND_EXTENT_DATA {
                        match ExtentDataValue::decode(&entry.value)? {
                            ExtentDataValue::Inline(_) => {}
                            ExtentDataValue::Extent { digest: bdig, .. } => {
                                if keep_blocks.insert(bdig) {
                                    // Abort destructive sweep if any live extent references a
                                    // block digest missing from the HeadStore block index.
                                    let loc =
                                        head_store.lookup_block(&bdig).await?.ok_or(Errno::EIO)?;
                                    keep_packs.insert(loc.pack_id);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

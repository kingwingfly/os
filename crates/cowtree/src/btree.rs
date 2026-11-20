//! Single-map Merkle Copy-on-Write B+tree operations:
//! - SHA-256 verified node reads backed by [`Arena`] LRU (`<= 8 MiB` on wasm32)
//! - O(log N) point lookup (`get`)
//! - O(log N) floor lookup (`find_le`) for extent queries on huge sparse files
//! - O(log N + page) cursor scan (`scan_range`) for 100k+ entry directories
//! - CoW batch commit (`apply_batch`) touching ONLY modified paths and guaranteeing `<= 16 KiB` nodes
//! - Staged read-your-writes overlay (`TreeOverlay`) merging uncommitted puts/deletes with committed tree.

use crate::NODE_MAX_BYTES;
use crate::arena::Arena;
use crate::key::TreeKey;
use crate::node::{InternalEntry, LeafEntry, NODE_HEADER_BYTES, Node};
use crate::store::{Digest, HeadStore};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ops::Bound;
use std::rc::Rc;
use vfs::Result;

/// Target fill size when splitting oversized nodes so resulting siblings stay well below 16 KiB.
const SPLIT_TARGET_BYTES: usize = (NODE_MAX_BYTES - NODE_HEADER_BYTES) * 3 / 4;

/// In-memory staged mutations for the active transaction group.
/// `Some(bytes)` = upsert, `None` = tombstone delete.
#[derive(Clone, Debug, Default)]
pub struct TreeOverlay {
    ops: BTreeMap<TreeKey, Option<Vec<u8>>>,
    bytes: usize,
}

impl TreeOverlay {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    pub fn len(&self) -> usize {
        self.ops.len()
    }

    pub fn dirty_bytes(&self) -> usize {
        self.bytes
    }

    pub fn put(&mut self, key: TreeKey, value: Vec<u8>) {
        let added = key.heap_bytes() + value.len();
        if let Some(old) = self.ops.insert(key.clone(), Some(value)) {
            let removed = key.heap_bytes() + old.as_ref().map_or(0, Vec::len);
            self.bytes = self.bytes.saturating_sub(removed);
        }
        self.bytes += added;
    }

    pub fn delete(&mut self, key: TreeKey) {
        let added = key.heap_bytes();
        if let Some(old) = self.ops.insert(key.clone(), None) {
            let removed = key.heap_bytes() + old.as_ref().map_or(0, Vec::len);
            self.bytes = self.bytes.saturating_sub(removed);
        }
        self.bytes += added;
    }

    pub fn get(&self, key: &TreeKey) -> Option<Option<&[u8]>> {
        self.ops.get(key).map(|v| v.as_deref())
    }

    pub fn clear(&mut self) {
        self.ops.clear();
        self.bytes = 0;
    }

    pub fn take_sorted_ops(&mut self) -> Vec<(TreeKey, Option<Vec<u8>>)> {
        self.bytes = 0;
        std::mem::take(&mut self.ops).into_iter().collect()
    }

    pub fn clone_sorted_ops(&self) -> Vec<(TreeKey, Option<Vec<u8>>)> {
        self.ops
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

/// Stateless CoW B+tree engine borrowing a [`HeadStore`] and [`Arena`].
pub struct CowTree<'a, H: HeadStore> {
    store: &'a H,
    arena: &'a RefCell<Arena>,
}

impl<'a, H: HeadStore> CowTree<'a, H> {
    pub fn new(store: &'a H, arena: &'a RefCell<Arena>) -> Self {
        Self { store, arena }
    }

    /// Load a node by digest from LRU cache or [`HeadStore`], verifying SHA-256 before decode.
    pub async fn load_node(&self, digest: &Digest) -> Result<Rc<Node>> {
        if let Some(hit) = self.arena.borrow_mut().get_node(digest) {
            return Ok(hit);
        }
        let raw = self.store.get_node(digest).await?;
        let raw_len = raw.len();
        let node = Rc::new(Node::decode_verified(digest, &raw)?);
        self.arena
            .borrow_mut()
            .put_node(*digest, raw_len, Rc::clone(&node));
        Ok(node)
    }

    /// Point lookup in the committed tree at `root`.
    pub async fn get(&self, root: &Digest, key: &TreeKey) -> Result<Option<Vec<u8>>> {
        let mut cur = *root;
        loop {
            let node = self.load_node(&cur).await?;
            match &*node {
                Node::Leaf { entries } => {
                    return Ok(entries
                        .binary_search_by(|e| e.key.cmp(key))
                        .ok()
                        .map(|idx| entries[idx].value.clone()));
                }
                Node::Internal { entries, .. } => {
                    let idx = match entries.binary_search_by(|e| e.key.cmp(key)) {
                        Ok(i) => i,
                        Err(0) => return Ok(None),
                        Err(i) => i - 1,
                    };
                    cur = entries[idx].child;
                }
            }
        }
    }

    /// Point lookup combining `overlay` (uncommitted writes/tombstones) over committed `root`.
    pub async fn get_with_overlay(
        &self,
        root: &Digest,
        overlay: &TreeOverlay,
        key: &TreeKey,
    ) -> Result<Option<Vec<u8>>> {
        if let Some(staged) = overlay.get(key) {
            return Ok(staged.map(|v| v.to_vec()));
        }
        self.get(root, key).await
    }

    /// Find the largest entry `(k, v)` with `min_key <= k <= max_key` in O(log N).
    pub async fn find_le(
        &self,
        root: &Digest,
        min_key: &TreeKey,
        max_key: &TreeKey,
    ) -> Result<Option<(TreeKey, Vec<u8>)>> {
        if min_key > max_key {
            return Ok(None);
        }
        let mut cur = *root;
        loop {
            let node = self.load_node(&cur).await?;
            match &*node {
                Node::Leaf { entries } => {
                    let pos = match entries.binary_search_by(|e| e.key.cmp(max_key)) {
                        Ok(i) => i,
                        Err(0) => return Ok(None),
                        Err(i) => i - 1,
                    };
                    let entry = &entries[pos];
                    if &entry.key >= min_key {
                        return Ok(Some((entry.key.clone(), entry.value.clone())));
                    }
                    return Ok(None);
                }
                Node::Internal { entries, .. } => {
                    let pos = match entries.binary_search_by(|e| e.key.cmp(max_key)) {
                        Ok(i) => i,
                        Err(0) => return Ok(None),
                        Err(i) => i - 1,
                    };
                    cur = entries[pos].child;
                }
            }
        }
    }

    /// Floor lookup `min_key <= k <= max_key` respecting uncommitted puts and deletes in `overlay`.
    pub async fn find_le_with_overlay(
        &self,
        root: &Digest,
        overlay: &TreeOverlay,
        min_key: &TreeKey,
        max_key: &TreeKey,
    ) -> Result<Option<(TreeKey, Vec<u8>)>> {
        if min_key > max_key {
            return Ok(None);
        }
        // Best live staged entry in [min_key, max_key].
        let staged_live = overlay
            .ops
            .range((Bound::Included(min_key), Bound::Included(max_key)))
            .rev()
            .find_map(|(k, v)| v.as_ref().map(|bytes| (k.clone(), bytes.clone())));

        // Search committed tree backwards past any tombstones until we find a live key > staged_live.
        let mut cursor_max = max_key.clone();
        let lower_bound = staged_live.as_ref().map(|(k, _)| k).unwrap_or(min_key);
        loop {
            let Some((ck, cv)) = self.find_le(root, lower_bound, &cursor_max).await? else {
                return Ok(staged_live);
            };
            if let Some((sk, _)) = &staged_live
                && ck <= *sk
            {
                return Ok(staged_live);
            }
            match overlay.get(&ck) {
                None => return Ok(Some((ck, cv))),
                Some(Some(val)) => return Ok(Some((ck, val.to_vec()))),
                Some(None) => {
                    // Tombstoned in overlay; step strictly below `ck`.
                    let Some(prev) = predecessor_key(&ck) else {
                        return Ok(staged_live);
                    };
                    if prev < *lower_bound {
                        return Ok(staged_live);
                    }
                    cursor_max = prev;
                }
            }
        }
    }

    /// Scan up to `limit` items in `[start_key, end_key_excl)` directly from the committed tree,
    /// touching only `O(log N + limit)` leaf nodes.
    pub async fn scan_range(
        &self,
        root: &Digest,
        start_key: &TreeKey,
        end_key_excl: &TreeKey,
        limit: usize,
    ) -> Result<Vec<(TreeKey, Vec<u8>)>> {
        if limit == 0 || start_key >= end_key_excl {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(limit.min(1024));
        let mut stack: Vec<(Rc<Node>, usize)> = Vec::new();
        let mut cur = *root;

        // Descend to the leaf that may contain `start_key`.
        let mut leaf = loop {
            let node = self.load_node(&cur).await?;
            match &*node {
                Node::Leaf { .. } => break node,
                Node::Internal { entries, .. } => {
                    let idx = match entries.binary_search_by(|e| e.key.cmp(start_key)) {
                        Ok(i) => i,
                        Err(0) => 0,
                        Err(i) => i - 1,
                    };
                    cur = entries[idx].child;
                    stack.push((node, idx));
                }
            }
        };

        let mut first_leaf = true;
        loop {
            if let Node::Leaf { entries } = &*leaf {
                let start_idx = if first_leaf {
                    first_leaf = false;
                    match entries.binary_search_by(|e| e.key.cmp(start_key)) {
                        Ok(i) | Err(i) => i,
                    }
                } else {
                    0
                };
                for entry in &entries[start_idx..] {
                    if entry.key >= *end_key_excl {
                        return Ok(out);
                    }
                    out.push((entry.key.clone(), entry.value.clone()));
                    if out.len() >= limit {
                        return Ok(out);
                    }
                }
            }

            // Advance to next sibling leaf via parent stack.
            let mut next_child = None;
            while let Some((parent, idx)) = stack.pop() {
                if let Node::Internal { entries, .. } = &*parent
                    && idx + 1 < entries.len()
                {
                    if entries[idx + 1].key >= *end_key_excl {
                        return Ok(out);
                    }
                    let child = entries[idx + 1].child;
                    stack.push((parent, idx + 1));
                    next_child = Some(child);
                    break;
                }
            }
            let Some(mut down) = next_child else {
                return Ok(out);
            };
            leaf = loop {
                let node = self.load_node(&down).await?;
                match &*node {
                    Node::Leaf { .. } => break node,
                    Node::Internal { entries, .. } => {
                        down = entries[0].child;
                        stack.push((node, 0));
                    }
                }
            };
        }
    }

    /// Scan up to `limit` items in `[start_key, end_key_excl)` merging uncommitted `overlay`
    /// changes over the committed B+tree in O(log N + limit) node loads.
    pub async fn scan_range_with_overlay(
        &self,
        root: &Digest,
        overlay: &TreeOverlay,
        start_key: &TreeKey,
        end_key_excl: &TreeKey,
        limit: usize,
    ) -> Result<Vec<(TreeKey, Vec<u8>)>> {
        if limit == 0 || start_key >= end_key_excl {
            return Ok(Vec::new());
        }
        if overlay.is_empty() {
            return self.scan_range(root, start_key, end_key_excl, limit).await;
        }

        let staged: Vec<(TreeKey, Option<Vec<u8>>)> = overlay
            .ops
            .range((Bound::Included(start_key), Bound::Excluded(end_key_excl)))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let mut s_idx = 0usize;
        let mut out = Vec::with_capacity(limit.min(1024));
        let mut base_start = start_key.clone();

        while out.len() < limit {
            let need = limit - out.len();
            // Fetch a bounded batch from committed tree (extra margin for tombstones).
            let fetch = need.saturating_add(16).min(1024);
            let base_batch = if base_start < *end_key_excl {
                self.scan_range(root, &base_start, end_key_excl, fetch)
                    .await?
            } else {
                Vec::new()
            };
            let base_exhausted = base_batch.len() < fetch;
            let mut b_idx = 0usize;

            while out.len() < limit {
                match (base_batch.get(b_idx), staged.get(s_idx)) {
                    (None, None) => return Ok(out),
                    (None, Some((sk, sv))) => {
                        if !base_exhausted {
                            // Need more base items before emitting staged items past last base key.
                            break;
                        }
                        if let Some(val) = sv {
                            out.push((sk.clone(), val.clone()));
                        }
                        s_idx += 1;
                    }
                    (Some((bk, bv)), None) => {
                        out.push((bk.clone(), bv.clone()));
                        b_idx += 1;
                    }
                    (Some((bk, bv)), Some((sk, sv))) => match bk.cmp(sk) {
                        std::cmp::Ordering::Less => {
                            out.push((bk.clone(), bv.clone()));
                            b_idx += 1;
                        }
                        std::cmp::Ordering::Greater => {
                            if let Some(val) = sv {
                                out.push((sk.clone(), val.clone()));
                            }
                            s_idx += 1;
                        }
                        std::cmp::Ordering::Equal => {
                            if let Some(val) = sv {
                                out.push((sk.clone(), val.clone()));
                            }
                            b_idx += 1;
                            s_idx += 1;
                        }
                    },
                }
            }

            if out.len() >= limit || base_exhausted {
                // Drain remaining staged entries if base is exhausted.
                while out.len() < limit && s_idx < staged.len() {
                    if let Some(val) = &staged[s_idx].1 {
                        out.push((staged[s_idx].0.clone(), val.clone()));
                    }
                    s_idx += 1;
                }
                break;
            }
            if let Some((last_bk, _)) = base_batch.last() {
                base_start = successor_key(last_bk);
            } else {
                break;
            }
        }
        Ok(out)
    }

    /// Apply a sorted deduplicated batch of mutations onto `root` via Copy-on-Write, returning
    /// `(new_root_digest, new_nodes_to_persist)`. Unmodified subtrees are never fetched or copied.
    pub async fn apply_batch(
        &self,
        root: &Digest,
        ops: &[(TreeKey, Option<Vec<u8>>)],
    ) -> Result<(Digest, Vec<(Digest, Vec<u8>)>)> {
        if ops.is_empty() {
            return Ok((*root, Vec::new()));
        }
        let mut new_nodes = Vec::new();
        let root_node = self.load_node(root).await?;
        let root_level = root_node.level();
        let mut children = self.apply_node(root, ops, &mut new_nodes).await?;

        if children.is_empty() {
            let empty = Node::empty_leaf();
            let (d, bytes) = empty.encode()?;
            new_nodes.push((d, bytes));
            return Ok((d, new_nodes));
        }

        if children.len() == 1 {
            // Collapse redundant root internal node with 1 child if we shrank it.
            return Ok((children[0].1, new_nodes));
        }

        // Grow tree height upward until a single root node holds all children.
        let mut level = root_level.saturating_add(1);
        loop {
            let entries: Vec<InternalEntry> = children
                .into_iter()
                .map(|(key, child)| InternalEntry { key, child })
                .collect();
            let packed = pack_internal_nodes(level, entries, &mut new_nodes)?;
            if packed.len() == 1 {
                return Ok((packed[0].1, new_nodes));
            }
            children = packed;
            level = level.saturating_add(1);
        }
    }

    fn apply_node<'b>(
        &'b self,
        digest: &'b Digest,
        ops: &'b [(TreeKey, Option<Vec<u8>>)],
        new_nodes: &'b mut Vec<(Digest, Vec<u8>)>,
    ) -> vfs::BoxFuture<'b, Vec<(TreeKey, Digest)>> {
        Box::pin(async move {
            let node = self.load_node(digest).await?;
            match &*node {
                Node::Leaf { entries } => {
                    let merged = merge_leaf_entries(entries, ops);
                    if merged.is_empty() {
                        return Ok(Vec::new());
                    }
                    pack_leaf_nodes(merged, new_nodes)
                }
                Node::Internal { level, entries } => {
                    let mut next_children: Vec<InternalEntry> = Vec::with_capacity(entries.len());
                    let mut op_idx = 0usize;
                    let n = entries.len();
                    for i in 0..n {
                        let start = op_idx;
                        if i + 1 < n {
                            let sep = &entries[i + 1].key;
                            while op_idx < ops.len() && ops[op_idx].0 < *sep {
                                op_idx += 1;
                            }
                        } else {
                            op_idx = ops.len();
                        }
                        if start == op_idx {
                            next_children.push(entries[i].clone());
                        } else {
                            let sub = self
                                .apply_node(&entries[i].child, &ops[start..op_idx], new_nodes)
                                .await?;
                            for (min_key, child_digest) in sub {
                                next_children.push(InternalEntry {
                                    key: min_key,
                                    child: child_digest,
                                });
                            }
                        }
                    }
                    if next_children.is_empty() {
                        return Ok(Vec::new());
                    }
                    if next_children.len() == 1 && *level >= 1 {
                        // Allow caller (or root) to collapse single-child internal chains cleanly.
                        let only = next_children.pop().unwrap();
                        return Ok(vec![(only.key, only.child)]);
                    }
                    pack_internal_nodes(*level, next_children, new_nodes)
                }
            }
        })
    }
}

fn merge_leaf_entries(
    existing: &[LeafEntry],
    ops: &[(TreeKey, Option<Vec<u8>>)],
) -> Vec<LeafEntry> {
    let mut out = Vec::with_capacity(existing.len() + ops.len());
    let (mut i, mut j) = (0usize, 0usize);
    while i < existing.len() || j < ops.len() {
        match (existing.get(i), ops.get(j)) {
            (Some(e), None) => {
                out.push(e.clone());
                i += 1;
            }
            (None, Some((k, v))) => {
                if let Some(bytes) = v {
                    out.push(LeafEntry {
                        key: k.clone(),
                        value: bytes.clone(),
                    });
                }
                j += 1;
            }
            (Some(e), Some((k, v))) => match e.key.cmp(k) {
                std::cmp::Ordering::Less => {
                    out.push(e.clone());
                    i += 1;
                }
                std::cmp::Ordering::Greater => {
                    if let Some(bytes) = v {
                        out.push(LeafEntry {
                            key: k.clone(),
                            value: bytes.clone(),
                        });
                    }
                    j += 1;
                }
                std::cmp::Ordering::Equal => {
                    if let Some(bytes) = v {
                        out.push(LeafEntry {
                            key: k.clone(),
                            value: bytes.clone(),
                        });
                    }
                    i += 1;
                    j += 1;
                }
            },
            (None, None) => break,
        }
    }
    out
}

fn pack_leaf_nodes(
    entries: Vec<LeafEntry>,
    new_nodes: &mut Vec<(Digest, Vec<u8>)>,
) -> Result<Vec<(TreeKey, Digest)>> {
    let total_size = NODE_HEADER_BYTES
        + entries
            .iter()
            .map(|e| Node::leaf_entry_encoded_size(&e.key, e.value.len()))
            .sum::<usize>();
    if total_size <= NODE_MAX_BYTES {
        let first_key = entries[0].key.clone();
        let node = Node::Leaf { entries };
        let (digest, bytes) = node.encode()?;
        new_nodes.push((digest, bytes));
        return Ok(vec![(first_key, digest)]);
    }

    let mut out = Vec::new();
    let mut chunk: Vec<LeafEntry> = Vec::new();
    let mut chunk_bytes = NODE_HEADER_BYTES;
    for entry in entries {
        let sz = Node::leaf_entry_encoded_size(&entry.key, entry.value.len());
        if !chunk.is_empty()
            && (chunk_bytes + sz > NODE_MAX_BYTES
                || (chunk_bytes >= SPLIT_TARGET_BYTES && chunk_bytes + sz > SPLIT_TARGET_BYTES))
        {
            let first_key = chunk[0].key.clone();
            let node = Node::Leaf {
                entries: std::mem::take(&mut chunk),
            };
            let (digest, bytes) = node.encode()?;
            new_nodes.push((digest, bytes));
            out.push((first_key, digest));
            chunk_bytes = NODE_HEADER_BYTES;
        }
        chunk_bytes += sz;
        chunk.push(entry);
    }
    if !chunk.is_empty() {
        let first_key = chunk[0].key.clone();
        let node = Node::Leaf { entries: chunk };
        let (digest, bytes) = node.encode()?;
        new_nodes.push((digest, bytes));
        out.push((first_key, digest));
    }
    Ok(out)
}

fn pack_internal_nodes(
    level: u8,
    entries: Vec<InternalEntry>,
    new_nodes: &mut Vec<(Digest, Vec<u8>)>,
) -> Result<Vec<(TreeKey, Digest)>> {
    let total_size = NODE_HEADER_BYTES
        + entries
            .iter()
            .map(|e| Node::internal_entry_encoded_size(&e.key))
            .sum::<usize>();
    if total_size <= NODE_MAX_BYTES {
        let first_key = entries[0].key.clone();
        let node = Node::Internal { level, entries };
        let (digest, bytes) = node.encode()?;
        new_nodes.push((digest, bytes));
        return Ok(vec![(first_key, digest)]);
    }

    let mut out = Vec::new();
    let mut chunk: Vec<InternalEntry> = Vec::new();
    let mut chunk_bytes = NODE_HEADER_BYTES;
    for entry in entries {
        let sz = Node::internal_entry_encoded_size(&entry.key);
        if !chunk.is_empty()
            && (chunk_bytes + sz > NODE_MAX_BYTES
                || (chunk_bytes >= SPLIT_TARGET_BYTES && chunk_bytes + sz > SPLIT_TARGET_BYTES))
        {
            let first_key = chunk[0].key.clone();
            let node = Node::Internal {
                level,
                entries: std::mem::take(&mut chunk),
            };
            let (digest, bytes) = node.encode()?;
            new_nodes.push((digest, bytes));
            out.push((first_key, digest));
            chunk_bytes = NODE_HEADER_BYTES;
        }
        chunk_bytes += sz;
        chunk.push(entry);
    }
    if !chunk.is_empty() {
        let first_key = chunk[0].key.clone();
        let node = Node::Internal {
            level,
            entries: chunk,
        };
        let (digest, bytes) = node.encode()?;
        new_nodes.push((digest, bytes));
        out.push((first_key, digest));
    }
    Ok(out)
}

/// Smallest key strictly greater than `key`.
fn successor_key(key: &TreeKey) -> TreeKey {
    let mut tail = key.tail.clone();
    tail.push(0);
    TreeKey {
        ino: key.ino,
        kind: key.kind,
        tail,
    }
}

/// Immediate predecessor key (best-effort for tombstone stepping on fixed-width or arbitrary tails).
fn predecessor_key(key: &TreeKey) -> Option<TreeKey> {
    if !key.tail.is_empty() {
        let mut tail = key.tail.clone();
        if let Some(last) = tail.last_mut() {
            if *last > 0 {
                *last -= 1;
                // Extend with max bytes? No — for fixed-width u64 tails (EXTENT_DATA), decrementing
                // big-endian integer is exact! Handle big-endian decrement when len == 8.
                if key.tail.len() == 8 {
                    let v = u64::from_be_bytes(key.tail.as_slice().try_into().unwrap());
                    if v > 0 {
                        return Some(TreeKey {
                            ino: key.ino,
                            kind: key.kind,
                            tail: (v - 1).to_be_bytes().to_vec(),
                        });
                    }
                }
                return Some(TreeKey {
                    ino: key.ino,
                    kind: key.kind,
                    tail,
                });
            }
            if key.tail.len() == 8 {
                let v = u64::from_be_bytes(key.tail.as_slice().try_into().unwrap());
                if v > 0 {
                    return Some(TreeKey {
                        ino: key.ino,
                        kind: key.kind,
                        tail: (v - 1).to_be_bytes().to_vec(),
                    });
                }
            }
            tail.pop();
            return Some(TreeKey {
                ino: key.ino,
                kind: key.kind,
                tail,
            });
        }
    }
    if key.kind > 0 {
        return Some(TreeKey {
            ino: key.ino,
            kind: key.kind - 1,
            tail: vec![0xff; 16],
        });
    }
    if key.ino > 0 {
        return Some(TreeKey {
            ino: key.ino - 1,
            kind: u8::MAX,
            tail: vec![0xff; 16],
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arena::ArenaConfig;
    use crate::memory::MemoryHeadStore;
    use crate::store::{CommitRequest, VolumeHead, VolumeId, WriterMode};
    use abi::fs::Timespec;
    use vfs::now_or_never;

    #[test]
    fn btree_handles_large_batch_splits_scans_and_deletes() {
        let store = MemoryHeadStore::new();
        let arena = RefCell::new(Arena::new(ArenaConfig::fixed_32mib()));
        let (empty_digest, empty_bytes) = Node::empty_leaf().encode().unwrap();
        let vol = VolumeId("vol-btree".into());
        let head = VolumeHead {
            format_version: crate::COWFS_FORMAT_VERSION,
            volume: vol.clone(),
            incarnation: 1,
            fence: 1,
            epoch: 0,
            root: empty_digest,
            parent_volume: None,
            ephemeral_if_unmodified: false,
            modified: false,
            updated_at: Timespec { sec: 1, nsec: 0 },
        };
        now_or_never(store.create_volume(&head, &[(empty_digest, empty_bytes)]))
            .unwrap()
            .unwrap();
        let lease = now_or_never(store.acquire_writer(&vol, WriterMode::Exclusive))
            .unwrap()
            .unwrap();

        let tree = CowTree::new(&store, &arena);
        let mut ops = Vec::new();
        for i in 1u64..=3000 {
            ops.push((
                TreeKey::dir_index(1, i),
                Some(format!("entry-{i:06}").into_bytes()),
            ));
        }
        let (new_root, put_nodes) = now_or_never(tree.apply_batch(&empty_digest, &ops))
            .unwrap()
            .unwrap();
        for (_, bytes) in &put_nodes {
            assert!(bytes.len() <= NODE_MAX_BYTES);
        }
        let commit = CommitRequest {
            op_id: [1; 16],
            volume: vol.clone(),
            expected_incarnation: lease.incarnation,
            expected_fence: lease.fence,
            expected_epoch: lease.epoch,
            new_root,
            put_nodes,
            put_packs: vec![],
            put_blocks: vec![],
            committed_at: Timespec { sec: 2, nsec: 0 },
        };
        now_or_never(store.commit_head(&commit)).unwrap().unwrap();

        // Point lookup & paged scan across multi-level tree.
        assert_eq!(
            now_or_never(tree.get(&new_root, &TreeKey::dir_index(1, 2500)))
                .unwrap()
                .unwrap(),
            Some(b"entry-002500".to_vec())
        );
        let page = now_or_never(tree.scan_range(
            &new_root,
            &TreeKey::dir_index(1, 1001),
            &TreeKey::kind_end(1, crate::KIND_DIR_INDEX),
            50,
        ))
        .unwrap()
        .unwrap();
        assert_eq!(page.len(), 50);
        assert_eq!(page[0].0, TreeKey::dir_index(1, 1001));
        assert_eq!(page[49].0, TreeKey::dir_index(1, 1050));

        // Floor lookup.
        let le = now_or_never(tree.find_le(
            &new_root,
            &TreeKey::dir_index(1, 0),
            &TreeKey::dir_index(1, 2999),
        ))
        .unwrap()
        .unwrap()
        .unwrap();
        assert_eq!(le.0, TreeKey::dir_index(1, 2999));

        now_or_never(store.release_writer(lease)).unwrap().unwrap();
    }
}

//! Fixed `32 MiB` wasm32 slab arena (R7, #77):
//! - `8 MiB` CoW B+tree node LRU cache (`tree_lru`)
//! - `16 MiB` clean verified data block LRU cache (`clean_data`)
//! - `8 MiB` dirty/in-flight mutation + dirty-block budget (`dirty`), NEVER evicted before commit
//!   (writer backpressure triggers a transaction-group flush instead).

use crate::node::Node;
use crate::store::Digest;
use crate::{ARENA_CLEAN_DATA_BYTES, ARENA_DIRTY_BYTES, ARENA_TREE_LRU_BYTES};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;

/// Configurable per-pool byte caps for [`Arena`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArenaConfig {
    pub tree_lru_bytes: usize,
    pub clean_data_bytes: usize,
    pub dirty_bytes: usize,
}

impl ArenaConfig {
    /// Contract §2.15 fixed `32 MiB` wasm32 slab arena (`8 MiB` + `16 MiB` + `8 MiB`).
    pub const fn fixed_32mib() -> Self {
        Self {
            tree_lru_bytes: ARENA_TREE_LRU_BYTES,
            clean_data_bytes: ARENA_CLEAN_DATA_BYTES,
            dirty_bytes: ARENA_DIRTY_BYTES,
        }
    }

    /// Native default cache budget (`256 MiB` total: `64 MiB` tree + `160 MiB` clean + `32 MiB`
    /// dirty; contract §2.15).
    pub const fn native_default() -> Self {
        Self {
            tree_lru_bytes: 64 * 1024 * 1024,
            clean_data_bytes: 160 * 1024 * 1024,
            dirty_bytes: 32 * 1024 * 1024,
        }
    }

    pub const fn platform_default() -> Self {
        #[cfg(target_arch = "wasm32")]
        {
            Self::fixed_32mib()
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            Self::native_default()
        }
    }

    pub const fn total_limit(&self) -> usize {
        self.tree_lru_bytes + self.clean_data_bytes + self.dirty_bytes
    }
}

impl Default for ArenaConfig {
    fn default() -> Self {
        Self::platform_default()
    }
}

/// Live and peak memory accounting exposed for diagnostics and bounded-memory gates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArenaStats {
    pub tree_lru_bytes: usize,
    pub peak_tree_lru_bytes: usize,
    pub clean_data_bytes: usize,
    pub peak_clean_data_bytes: usize,
    pub dirty_bytes: usize,
    pub peak_dirty_bytes: usize,
    pub peak_total_bytes: usize,
    pub tree_hits: u64,
    pub tree_misses: u64,
    pub data_hits: u64,
    pub data_misses: u64,
    pub evictions: u64,
    pub backpressure_flushes: u64,
}

struct LruPool<V> {
    limit: usize,
    bytes: usize,
    peak_bytes: usize,
    tick: u64,
    entries: HashMap<Digest, (u64, usize, Rc<V>)>,
    order: BTreeMap<u64, Digest>,
    hits: u64,
    misses: u64,
    evictions: u64,
}

impl<V> LruPool<V> {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            bytes: 0,
            peak_bytes: 0,
            tick: 0,
            entries: HashMap::new(),
            order: BTreeMap::new(),
            hits: 0,
            misses: 0,
            evictions: 0,
        }
    }

    fn next_tick(&mut self) -> u64 {
        self.tick = self.tick.wrapping_add(1);
        self.tick
    }

    fn get(&mut self, digest: &Digest) -> Option<Rc<V>> {
        let Some((old_tick, size, val)) = self.entries.get(digest).cloned() else {
            self.misses += 1;
            return None;
        };
        self.hits += 1;
        self.order.remove(&old_tick);
        let new_tick = self.next_tick();
        self.order.insert(new_tick, *digest);
        self.entries
            .insert(*digest, (new_tick, size, Rc::clone(&val)));
        Some(val)
    }

    fn insert(&mut self, digest: Digest, size: usize, value: Rc<V>) {
        if size > self.limit {
            return;
        }
        if let Some((old_tick, old_size, _)) = self.entries.remove(&digest) {
            self.order.remove(&old_tick);
            self.bytes = self.bytes.saturating_sub(old_size);
        }
        while self.bytes.saturating_add(size) > self.limit {
            let Some((_, oldest)) = self.order.pop_first() else {
                break;
            };
            if let Some((_, evicted_size, _)) = self.entries.remove(&oldest) {
                self.bytes = self.bytes.saturating_sub(evicted_size);
                self.evictions += 1;
            }
        }
        let tick = self.next_tick();
        self.order.insert(tick, digest);
        self.entries.insert(digest, (tick, size, value));
        self.bytes += size;
        if self.bytes > self.peak_bytes {
            self.peak_bytes = self.bytes;
        }
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
        self.bytes = 0;
    }
}

/// Bounded three-pool storage cache arena (`tree_lru` + `clean_data` + `dirty` accounting).
pub struct Arena {
    config: ArenaConfig,
    tree_lru: LruPool<Node>,
    clean_data: LruPool<Vec<u8>>,
    dirty_bytes: usize,
    peak_dirty_bytes: usize,
    peak_total_bytes: usize,
    backpressure_flushes: u64,
}

impl Arena {
    pub fn new(config: ArenaConfig) -> Self {
        Self {
            config,
            tree_lru: LruPool::new(config.tree_lru_bytes),
            clean_data: LruPool::new(config.clean_data_bytes),
            dirty_bytes: 0,
            peak_dirty_bytes: 0,
            peak_total_bytes: 0,
            backpressure_flushes: 0,
        }
    }

    pub fn config(&self) -> ArenaConfig {
        self.config
    }

    fn update_total_peak(&mut self) {
        let total = self.tree_lru.bytes + self.clean_data.bytes + self.dirty_bytes;
        if total > self.peak_total_bytes {
            self.peak_total_bytes = total;
        }
    }

    pub fn get_node(&mut self, digest: &Digest) -> Option<Rc<Node>> {
        self.tree_lru.get(digest)
    }

    pub fn put_node(&mut self, digest: Digest, encoded_bytes: usize, node: Rc<Node>) {
        // Charge actual retained heap footprint (struct + Vec capacities + per-entry allocations +
        // LRU table overhead) so the decoded tree cache never exceeds the 8 MiB budget.
        let retained = node
            .heap_bytes()
            .max(encoded_bytes)
            .saturating_add(128)
            .max(1);
        self.tree_lru.insert(digest, retained, node);
        self.update_total_peak();
    }

    pub fn get_data(&mut self, digest: &Digest) -> Option<Rc<Vec<u8>>> {
        self.clean_data.get(digest)
    }

    pub fn put_data(&mut self, digest: Digest, data: Rc<Vec<u8>>) {
        let size = data.capacity().max(data.len()).max(1);
        self.clean_data.insert(digest, size, data);
        self.update_total_peak();
    }

    /// Returns `true` when accepting `additional_bytes` of dirty mutations or dirty data blocks
    /// would exceed the dirty slab budget and requires a transaction-group flush first.
    pub fn needs_backpressure_flush(&self, additional_bytes: usize) -> bool {
        self.dirty_bytes > 0
            && self.dirty_bytes.saturating_add(additional_bytes) > self.config.dirty_bytes
    }

    /// Update current dirty slab byte usage (dirty mutations + dirty data blocks).
    pub fn set_dirty_bytes(&mut self, bytes: usize) {
        self.dirty_bytes = bytes;
        if self.dirty_bytes > self.peak_dirty_bytes {
            self.peak_dirty_bytes = self.dirty_bytes;
        }
        self.update_total_peak();
    }

    pub fn record_backpressure_flush(&mut self) {
        self.backpressure_flushes += 1;
    }

    pub fn clear_clean_caches(&mut self) {
        self.tree_lru.clear();
        self.clean_data.clear();
    }

    pub fn stats(&self) -> ArenaStats {
        ArenaStats {
            tree_lru_bytes: self.tree_lru.bytes,
            peak_tree_lru_bytes: self.tree_lru.peak_bytes,
            clean_data_bytes: self.clean_data.bytes,
            peak_clean_data_bytes: self.clean_data.peak_bytes,
            dirty_bytes: self.dirty_bytes,
            peak_dirty_bytes: self.peak_dirty_bytes,
            peak_total_bytes: self.peak_total_bytes,
            tree_hits: self.tree_lru.hits,
            tree_misses: self.tree_lru.misses,
            data_hits: self.clean_data.hits,
            data_misses: self.clean_data.misses,
            evictions: self.tree_lru.evictions + self.clean_data.evictions,
            backpressure_flushes: self.backpressure_flushes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256;

    #[test]
    fn arena_evicts_clean_pools_within_strict_32mib_bounds() {
        let mut arena = Arena::new(ArenaConfig::fixed_32mib());
        for i in 0u32..400 {
            let mut block = vec![0u8; 64 * 1024];
            block[0..4].copy_from_slice(&i.to_le_bytes());
            let d = sha256(&block);
            arena.put_data(d, Rc::new(block));
        }
        let st = arena.stats();
        assert!(st.clean_data_bytes <= ARENA_CLEAN_DATA_BYTES);
        assert!(st.peak_clean_data_bytes <= ARENA_CLEAN_DATA_BYTES);
        assert!(st.evictions > 0);
        assert!(st.peak_total_bytes <= ArenaConfig::fixed_32mib().total_limit());
    }
}

//! Portable `ClusterState` store abstraction, SQLite Schema v1 DDL, shared authorization rules,
//! atomic fencing builders, and reference in-memory implementation (`Phase 9.1a #83`).
//!
//! Semantics are explicitly an **etcd-subset** (linearizable revisioned KV, atomic conditional
//! transactions, persistent prefix watches, lease expiration, and MVCC compaction); no etcd or
//! Kubernetes wire protocol compatibility is claimed.
pub mod authz;
pub mod fencing;
pub mod memory;
pub mod schema;

use abi::auth_v2::RemoteScope;
use abi::cluster_state::{ClusterCall, ClusterError, ClusterReply, RangeEnd, WatchEvent};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;

#[cfg(not(target_arch = "wasm32"))]
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
#[cfg(target_arch = "wasm32")]
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// Verified caller authorization grant passed to `ClusterStore` backends.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterGrant {
    pub tenant: String,
    pub owner: String,
    pub admin: bool,
    pub scope: RemoteScope,
}

/// Stateful watch cursor used by `ClusterStore::poll_watch`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchCursor {
    pub key: String,
    pub range_end: RangeEnd,
    /// Next inclusive revision to scan (`0` starts live at `current_revision + 1`).
    pub next_revision: u64,
    /// Last delivered event sequence number within `next_revision` (for exact pagination).
    #[serde(default)]
    pub last_seq: u64,
    #[serde(default)]
    pub prev_kv: bool,
}

impl WatchCursor {
    pub fn new(
        key: impl Into<String>,
        range_end: RangeEnd,
        from_revision: u64,
        prev_kv: bool,
    ) -> Self {
        Self {
            key: key.into(),
            range_end,
            next_revision: from_revision,
            last_seq: 0,
            prev_kv,
        }
    }
}

/// Batch of watch events returned by `ClusterStore::poll_watch`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchBatch {
    pub revision: u64,
    pub compacted_floor: u64,
    pub events: Vec<WatchEvent>,
    pub more: bool,
}

/// Portable backend trait for `ClusterState` (implemented by `MemoryClusterStore` for tests
/// and backed by the `ClusterState` SQLite Durable Object in `crates/worker`).
pub trait ClusterStore {
    fn rpc<'a>(
        &'a self,
        grant: &'a ClusterGrant,
        call: ClusterCall,
        now_secs: u64,
    ) -> BoxFuture<'a, Result<ClusterReply, ClusterError>>;

    fn poll_watch<'a>(
        &'a self,
        grant: &'a ClusterGrant,
        cursor: &'a mut WatchCursor,
        limit: u32,
        now_secs: u64,
    ) -> BoxFuture<'a, Result<WatchBatch, ClusterError>>;
}

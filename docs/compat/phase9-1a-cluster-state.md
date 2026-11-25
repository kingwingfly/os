# Phase 9.1a: `ClusterState` Service (`Boundary::ClusterState` v1, #83)

Issue `#83` implements `Boundary::ClusterState` v1 (`abi::cluster_state::CLUSTER_STATE_PROTOCOL = 1`): a linearizable, revisioned metadata, watch, lease, and fenced-attempt store backed by a SQLite Durable Object (`ClusterState`) behind a portable pure-Rust `ClusterStore` trait (`crates/cluster-state`).

## Honest Compatibility Scope

- **etcd-subset semantics only.** `ClusterState` exposes an explicit, documented subset of etcd-style MVCC semantics: monotonic cluster revisions, historical `Range(key, end, rev)`, atomic conditional `Txn(compare[], success[], failure[])`, persistent prefix `Watch(from_revision)` with `Pull` pagination, alarm-driven `Lease{Grant, KeepAlive, Revoke, TimeToLive}`, and `Compact(rev)` returning structured `compacted { floor }` errors for relist recovery.
- **No etcd or Kubernetes wire compatibility is claimed.** Endpoints speak versioned strict-JSON (`#[serde(deny_unknown_fields)]`) over `POST /api/cluster/rpc`, `POST /api/cluster/watch-ticket`, and `GET /api/cluster/watch` (Hibernatable WebSockets), not etcd v3 gRPC/protobuf or Kubernetes apiserver REST/Watch wire formats.
- **Portable trait boundary.** `os_cluster_state::ClusterStore`, `authz`, `fencing`, and `schema` contain zero DOM, `web-sys`, or `worker` types. `MemoryClusterStore` serves as the pure-Rust reference implementation for host conformance tests (`crates/cluster-state/tests/conformance.rs`).
- **Frozen syscall ABI & zero external crates.** `abi::Call` remains frozen at 74 variants (`node scripts/conformance/check-abi.mjs`) and zero new external Cargo dependencies are added (`os-cluster-state` depends solely on `os-abi`, `serde`, and `serde_json`).

## Key Space & Typed Records (Contract §2.13, §2.16)

Every key is strictly scoped under `/t/<tenant>/<rel>` (`tenant = u<u32>`, segments `[A-Za-z0-9._:@-]`, no empty/`. `/`..` segments, max `512` bytes). All range operations (`Prefix`, `Key(end)`, `OpenEnded`) are clamped inside `/t/<tenant>/`.

| Key pattern | Record type | Lease-bound | Semantics |
| --- | --- | --- | --- |
| `/t/<tenant>/node-meta/<node_id>` | `NodeMetaRecord` | No | Durable node identity, host kind (`browser`, `os-native`, `container`), labels, and capabilities; survives restarts and lease expiry. |
| `/t/<tenant>/nodes/<node_id>` | `NodeRecord` | Yes | Ephemeral node liveness (`node_generation`, `instance_id`, `lease_id`, `status`, `heartbeat_at`); deleted atomically on lease expiry/revoke. |
| `/t/<tenant>/workloads/<workload_id>` | `WorkloadRecord` | No | Admitted workload desired state, `current_attempt`, and scoped immutable image/input references (never bulk payload bytes or credentials). |
| `/t/<tenant>/workloads/<workload_id>/canceled` | JSON marker | No | Cancellation fence written atomically when no final result exists. |
| `/t/<tenant>/attempts/<workload_id>/<attempt_gen>` | `AttemptRecord` | No | Fenced execution attempt bound to `(node_id, node_generation, node_lease_id)`. |
| `/t/<tenant>/results/<workload_id>` | `ResultRecord` | No | At-most-once terminal result carrying scoped immutable `output_ref` only. |
| `/t/<tenant>/outbox/<outbox_id>` | `OutboxRecord` | No | Notice-only dispatch record (`attempt_ready`, `workload_canceled`, `result_published`; Contract §2.13). |

## Authentication, Monotonic Scoping, and Live Revocation

- **ServiceAuth v2 only.** Every call to `/api/cluster/rpc`, `/api/cluster/watch-ticket`, and direct-header `/api/cluster/watch` verifies `X-Process-Token` + `X-OS-Instance` via `OsAuthority` (`/internal/service-auth/verify-cluster`) and live instance ownership via `Machine` (`checked_io` 0 bytes). Bare cookies, guests, container job tokens, locked accounts, expired sessions, and expired instances fail closed with `403 EACCES`. Browser requests carrying `Origin` or `Cookie` additionally enforce strict same-origin checks.
- **Monotonic `RemoteScope` attenuation.** `RemoteScope` adds `cluster_read`, `cluster_write`, `cluster_watch`, `cluster_lease`, `cluster_compact`, `cluster_prefixes`, and `cluster_node_id`. `RemoteScope::attenuate` intersects prefixes via `cluster_prefix_covers`, narrows `cluster_node_id`, collapses all cluster permissions on empty/conflicting intersections, and drops `cluster_compact` whenever any prefix or node restriction is present.
- **Pre-compare `Txn` authorization.** Every `compare`, `success`, and `failure` operation is authorized before evaluating any compare predicate so untaken branches cannot leak or bypass policy.
- **Batched live WebSocket revocation.** `ClusterState` persists `watch_events` inside the SQLite mutation transaction before waking subscribers, serializes fan-out and `Pull` under `notify_gate`, and batch-revalidates active WebSocket sessions against `OsAuthority` (`/internal/service-auth/verify-cluster-batch`) and `Machine` before delivering any event. Revoked, locked, or expired watchers receive an `EACCES` error frame and are closed immediately with their SQLite session/subscription rows removed.

## Bounds, Quotas, and Schema Version Guard

- Key `<= 512 B`, value `<= 256 KiB`, RPC body `<= 1 MiB`, WebSocket frame `<= 64 KiB`, `Txn` compares `<= 64`, `Txn` ops/branch `<= 64`, `Txn` write bytes `<= 512 KiB`, `Range` limit default `256` / max `1024`, watches/socket `<= 16`, active watch sockets `<= 256`, catch-up batch `<= 128`, lease TTL `5..=3600 s`, keys/lease `<= 256`, leases/tenant `<= 1024`, live keys/tenant `<= 16,384`, live bytes/tenant `<= 64 MiB`, prefix grants `<= 32`.
- All `u64` columns in SQLite Schema v1 (`CLUSTER_SCHEMA_VERSION = 1`) are read with `CAST(col AS TEXT)` + `db::exact_u64` to avoid JS float53 truncation.
- Opening a `ClusterState` DO whose `schema_meta.version != 1` fails closed with `503 EPROTONOSUPPORT` without silently migrating or resetting cluster state (Contract §2.12).

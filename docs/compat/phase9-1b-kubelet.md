# Phase 9.1b Compatibility & Architecture Notes (`#84`: Userspace `kubelet` Role, Sandbox Instances & Own-Device Task SDK)

## Overview

Phase 9.1b (`#84`) delivers the userspace worker-node `kubelet` role, isolated per-attempt Wasm/WASIX sandbox instances across both `os-native` and browser hosts, and the versioned Rust-first `os-task-sdk` (`crates/task-sdk`) over `ClusterState` v1 (`#83`), OCI `cowfs` snapshots (`#81`), and `ServiceAuth v2` (`#54`).

## Key Boundaries & Security Invariants

1. **Worker Node Authentication (`ServiceAuth v2` Additive Variants)**
   - `Request::MintBootstrapToken` (`30..=900 s` TTL) stores single-use `osbt_<64hex>` bootstrap tokens in `OsAuthority` under `ns = "bootstrap"`. Because every existing resource verifier (`verify-cluster`, `verify-cluster-batch`, `verify-registry`, `verify-registry-bearer`, `verify-volume`) accepts only live `session.*` and `node.*` credentials (`cred_ns_alive`), bootstrap tokens are **never** accepted directly on `/api/cluster/*`, `/v2/*`, `/api/volumes/*`, or `/api/fs` (`403 EACCES`).
   - `Request::ExchangeBootstrapToken` (cookie-less) atomically consumes the bootstrap token via `DELETE ... RETURNING` in `OsAuthority`, verifies `!user.locked`, mints an isolated `ns = "node.<enrollment_id>"` credential (`RemoteScope::node_ceiling(node_id)` monotonically intersected with the minted scope, renewable up to 30 days), and immediately binds the host-fenced `Machine` DO (`id_from_name(&ns)`).
   - `Request::RevokeNode` revokes all matching `node.*` credentials in `OsAuthority`, fans out `/internal/node-revoke` to each `Machine` DO, and triggers `/internal/revalidate-watches` on `ClusterState` so live WebSocket watches disconnect immediately and subsequent RPCs fail closed (`403`).
   - Cookie-less `X-OS-Node-Enrollment` routing on `/api/service-auth` authenticates strictly via `(ns, instance_id, host_proof_hash)` and forbids `AttachInstance`/`MintServiceCred` on `node.*`. CSRF is enforced whenever `Origin` or `Cookie` is present.

2. **Fenced Execution, Failover & Artifact Staging**
   - `KubeletEngine` (`crates/task-sdk/src/agent.rs`) and `web/kernel/kubelet-agent.js` register each node with a strictly monotonic `node_generation` persisted via `node-meta/<node_id>` (`os.node/last_generation`) and a leased `nodes/<node_id>` key.
   - Dual keepalive: `ClusterState` `LeaseKeepAlive` every `max(1, ttl/3) s` with client-monotonic self-fencing (`compute_self_fence_deadline_ms`), plus `ServiceAuth v2` `RenewInstance` every `30 s`.
   - Pending claims use `build_claim_attempt_txn`; dead-node failover uses `build_reclaim_attempt_txn` (atomically guarding `nodes/<prev_node> Lease != prev_attempt.node_lease_id` so a live node's attempt can never be stolen).
   - Every attempt derives an attenuated per-attempt storage token (`registry_pull`, `registry_push`, `volumes`, `volumes_ro` ONLY; zero `cluster_*` or `cloud_fs` scope), revoked unconditionally in cleanup.
   - Staged `/output` `cowfs` snapshots carry `org.os.kubelet.attempt: "<wid>:<attempt_gen>:<node_gen>"` in `OciPushOptions::extra_annotations` so each attempt's staged manifest digest is unique while `COWP` packs remain content-addressed and deduplicated. On 5-way fenced publish success, the staging manifest is promoted to `result-<wid>` and `staging-*` deleted; on rejection (`ESTALE`/`ECANCELED`/`EEXIST`), both the `staging-*` tag and the attempt-unique manifest digest are deleted without endangering the winner's `COWP` packs.

3. **Isolated Per-Attempt Sandbox Instances (`os-native` & Browser)**
   - **Dedicated kernel & namespaces**: each attempt runs in its own isolated `LocalProcessTable` (PID 1 only, cgroup `memory.max` + `pids.max` enforced on `/`), isolated `Vfs` + `MountNamespace`, O(1)-forked `cowfs` rootfs (supporting both `COWFS_SNAPSHOT_ARTIFACT_TYPE` and standard OCI tar with `StrictConfined` + `SetuidPolicy::Reject`), minimal `/dev` (`null`, `zero`, `full`, `random`, `urandom` ONLY), isolated `/proc` (PID 1 only), fresh `tmpfs` `/tmp`, strictly read-only `/input` (lazy range-verified OCI snapshot and/or `extra_inputs` mounted at `/input/<name>`), and writable `cowfs` `/output`.
   - **Preemption**: `os-native` runs with Wasmtime `epoch_interruption(true)` + 20 ms `EpochTickerGuard` + `cancel_flag`; browser/Node `kubelet-agent.js` runs zero-token `sandbox-worker.js` over a `SharedArrayBuffer` doorbell into `SandboxKernel` (`crates/client-kernel/src/sandbox.rs`) and calls `worker.terminate()` immediately on cancel, timeout, or self-fence.
   - **No Linux ELF pod delegation**: both `os-native` and browser `SandboxKernel` explicitly reject `\x7fELF` and non-`\0asm` binaries with `Errno::ENOEXEC` (`exit_code = 126`).

4. **Opt-In Userspace `kubelet.service` & Zero Boot Network**
   - `kubelet.service` (`/usr/bin/kubelet`) ships `enabled: false`, `FailurePolicy::Optional`, `Readiness::NotifySocket`, and zero cloud scope. At default boot, neither `/usr/bin/kubelet` nor `kubelet-agent.js` loads, `/run/kubelet/host.sock` is unbound, and zero `/api/cluster/*` or `/api/service-auth` requests are issued.
   - `service enable kubelet` / `service disable kubelet` persist unit enablement atomically in `/etc/services/.enabled.json` (and `~/.config/os/units/.enabled.json` for per-user managers).
   - `/run/kubelet/host.sock` (`0600`, `SO_PEERCRED.uid == 0`, verified `/usr/bin/kubelet` service image in browser) speaks versioned `abi::kubelet_ctl` v1.

## Known Limitations & Non-Goals

- **No Kubernetes API / CRI / etcd wire compatibility**: `kubelet` uses `os-cluster-state` (`ClusterState` v1) and `os-task-sdk` (`os.task/*` labels) directly.
- **No Linux ELF execution**: ELF binaries return `ENOEXEC` on all hosts.
- **No automatic placement controller or Cloudflare Queues dispatch yet**: tasks are claimed directly by eligible nodes watching `/t/<tenant>/workloads/`; centralized scheduling & Queues dispatch belong to Phase 9.2.
- **Frozen invariants preserved**: `abi::Call` remains at 74 variants (`check-abi.mjs`), zero new external Cargo crates were added, and zero Durable Object schemas were bumped (`OsAuthority = "10"`, `Machine = 3`, `StorageVolume = 2`, `ClusterState = 1`).

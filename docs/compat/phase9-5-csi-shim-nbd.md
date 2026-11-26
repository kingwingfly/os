# Phase 9.5 Compatibility & Architecture Notes (`#85`: CSI Driver, `containerd-shim-os-v1`, Raw LBA Volumes & NBD Export)

## Overview

Phase 9.5 (`#85`) brings full Kubernetes & containerd ecosystem interoperability to `os-cowfs` and `os-native` without introducing any new external Cargo dependencies or altering any frozen kernel/DO ABIs:

- **Raw LBA CoW block volumes (`os-cowtree`, `os-cowfs`)**: Block-addressable CoW volumes stored directly in the existing `cowfs` Merkle B+tree and `COWP` pack store (`ROOT_FEATURE_RAW_BLOCK`, `KIND_RAW_BLOCK_META = 0x60`, `KIND_EXTENT_DATA = 0x30`), giving O(1) snapshots, O(1) forks, SHA-256 integrity verification (`fsck`), GC, `cowfs send/recv`, and `StorageVolume` DO compatibility out of the box.
- **Raw `/dev/vdN` device I/O (`os-vfs`, `os-native`)**: `pread`/`pwrite`/`fsync`/`trim` on raw block `/dev/vdN` devices while preserving `EOPNOTSUPP` on object-native `cowfs` block devices (`/dev/vd0` rootfs) and enforcing `EROFS` on read-only devices.
- **Standard NBD Fixed Newstyle export (`crates/os-nbd`)**: Bounded pure-Rust NBD server & client over `0600` Unix sockets supporting `NBD_OPT_{LIST,INFO,GO,ABORT,EXPORT_NAME}`, `NBD_CMD_{READ,WRITE,DISC,FLUSH,TRIM,WRITE_ZEROES}`, `NBD_CMD_FLAG_FUA`, and single-writer fenced commits.
- **Linux CSI v1.9 Controller & Node plugins (`crates/os-csi`)**: Zero-dependency Protobuf v3 + bounded gRPC-over-HTTP/2 cleartext (h2c) `AF_UNIX` server/client (`csi.v1.{Identity,Controller,Node}`), atomic fenced publish leases in `ClusterState`, pure-Rust `/dev/fuse` ABI v7.31 daemon (`fusermount3` + `SCM_RIGHTS`) with `HostSubvol` fallback, and per-volume `0600` `os-nbd` block exports.
- **Containerd runwasi-compatible shim (`crates/containerd-shim-os`, binary `containerd-shim-os-v1`)**: Speaks containerd TTRPC v1 (`containerd.task.v2.Task` and `containerd.task.v3.Task`) over `0600` Unix sockets, runs isolated per-container `os-native` kernels with CSI `cowfs` + raw `/dev/vdN` mounts, and enforces Wasmtime 51 epoch preemption.

## Conformance Matrix (`P95-01..P95-08`)

| ID | Capability | Key Invariants & Guarantees | Verification |
|---|---|---|---|
| **P95-01** | Raw LBA CoW Volumes (`os-cowtree`, `os-cowfs`) | `ROOT_FEATURE_RAW_BLOCK = 1 << 1`, `RawVolumeMeta` (`512..=65536` power-of-2 sector size, `<= 16 TiB`), zero-copy extent splitting on partial overwrite/trim, sticky `fenced: bool` on `ESTALE`, `fsck` verifies bounds & SHA-256 digests, `CowFs::open` rejects raw volumes (`EINVAL`) and `RawBlockVolume::open` rejects FS volumes (`EOPNOTSUPP`). | `os-cowtree` & `os-cowfs` unit tests (`raw_lba::tests::*`) |
| **P95-02** | `/dev/vdN` Raw Block Device I/O (`os-vfs`, `os-native`) | `VolumeDevice::{read_raw,write_raw,sync_raw,trim_raw}` + `DeviceBackend::sync_device` wired through `GuiDeviceBackend` -> `LoopDeviceBackend` -> `VblkDeviceBackend`; write-open of RO raw `/dev/vdN` fails with `EROFS`; `WriteAt::End` fails with `EINVAL`; object-native `cowfs` `/dev/vd0` continues to return `EOPNOTSUPP`. | `os-cowfs` & `containerd-shim-os` E2E (`/dev/vd0` read/write/sync) |
| **P95-03** | NBD Fixed Newstyle Export (`os-nbd`) | `NBDMAGIC`/`IHAVEOPT`, `NBD_FLAG_FIXED_NEWSTYLE \| NBD_FLAG_NO_ZEROES`, `MAX_NBD_IO_BYTES = 4 MiB`, `MAX_OPTION_LEN = 4 KiB`, `MAX_HANDSHAKE_OPTIONS = 64`, `0600` Unix socket bind (rejecting symlink parents & `..`), clean unlink on drop, `FUA`/`FLUSH` fenced CAS rejecting stale writers (`NBD_EPERM`/`NBD_EIO`). | `crates/os-nbd/tests/nbd_e2e.rs` |
| **P95-04** | CSI v1.9 gRPC-h2c Controller (`os-csi`) | Zero-dep Protobuf v3 + RFC 7541 HPACK (static + dynamic + Huffman) gRPC-h2c over `0600` `AF_UNIX`; idempotent `CreateVolume` (FS + Block), O(1) `CreateSnapshot`/`DeleteSnapshot` & restore/clone, `DeleteVolume` refuses published volumes, `ListVolumes`/`ListSnapshots`/`ValidateVolumeCapabilities`. | `crates/os-csi/tests/csi_e2e.rs` & unit tests |
| **P95-05** | `ClusterState` Fenced CSI Publish Leases (`os-csi`) | Atomic `ClusterState` `Txn` under `/t/<tenant>/csi/...` with strictly monotonic `fence_epoch`; explicitly refuses `MULTI_NODE_MULTI_WRITER` (`INVALID_ARGUMENT`); allows concurrent `MULTI_NODE_READER_ONLY`; stale node writes/flushes fail closed with `ESTALE` after failover or lease expiry. | `crates/os-csi/tests/csi_e2e.rs` |
| **P95-06** | CSI Node Staging: Pure-Rust `/dev/fuse` v7.31 & `HostSubvol` (`os-csi`) | Path traversal & symlink rejection on staging/target paths; pure-Rust Linux `/dev/fuse` ABI v7.31 daemon (`fusermount3` + `SCM_RIGHTS`) + `HostSubvol` fallback backed by a live fenced `CowFs` actor; published descriptors persisted strictly in `$NODE_STATE/published/<hash>.json` (never inside user volumes); per-volume `0600` `os-nbd` sockets for block volumes. | `os-csi` FUSE `socketpair` unit tests & `csi_e2e.rs` |
| **P95-07** | `containerd-shim-os-v1` TTRPC v2/v3 & OCI Lifecycle | Standard shim v2 CLI (`start` printing `unix://<path>`, `delete`, `-version`, `-info`), TTRPC v1 (`containerd.task.v2.Task` & `v3.Task`, `4 MiB` frame cap, `0600` socket), CRI PodSandbox + Wasm/WASIX container lifecycle (`Create`/`Start`/`State`/`Exec`/`Kill`/`Wait`/`Pids`/`Connect`/`Delete`/`Shutdown`), host FIFO stdio, safe `O_NOFOLLOW` rootfs import rejecting setuid/setgid & host devices, `< 200 ms` Wasmtime epoch preemption on `Kill(SIGKILL)`. | `crates/containerd-shim-os/tests/shim_e2e.rs` |
| **P95-08** | Cross-Component Storage & Fencing E2E | Single end-to-end flow connecting CSI gRPC-h2c + `os-nbd` + `containerd-shim-os-v1` + `os-native`: WASI container reads/writes both CSI `cowfs` `/data` and CSI raw `/dev/vd0`, persists across container exit and CSI/NBD verification, rejects `\x7fELF` with `ENOEXEC`, preempts tight Wasm loop `< 200 ms`, and fails closed with `ESTALE` on `Delete` when fenced by a competing native writer. | `crates/containerd-shim-os/tests/shim_e2e.rs` |

## Containerd & CSI Configuration

### Containerd CRI Runtime Configuration (`/etc/containerd/config.toml`)

```toml
version = 2

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.os-wasm]
  runtime_type = "io.containerd.os.v1"
```

Place `containerd-shim-os-v1` on `$PATH` (for example `/usr/local/bin/containerd-shim-os-v1`) and create a matching Kubernetes `RuntimeClass`:

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: os-wasm
handler: os-wasm
```

### CSI Plugin Deployment (`os-csi`)

- **Combined Controller + Node plugin (default standalone binary with in-process `MemoryClusterStore`)**:
  `os-csi --mode all --endpoint unix:///run/os-csi/csi.sock --node-id <node> --state /var/lib/os-csi --tenant u0 --stage-mode auto`
  - Volume storage lives under `<state>/store` and node metadata (`published/`, `fences/`, `locks/`, `nbd/`) lives under `<state>/node`.
  - Split `--mode controller` and `--mode node` modes are supported in the library router (`OsCsiController` / `OsCsiNode`) when wired to a shared external `ClusterStore` implementation; the standalone `os-csi` binary uses an in-process `MemoryClusterStore` so running both roles together requires `--mode all`.
  - `os-csi` exposes driver name **`cowfs.csi.os.dev`** over `0600` Unix sockets (bound atomically via a private `0700` staging directory) speaking standard gRPC over HTTP/2 cleartext (h2c).
  - **FUSE3 vs `HostSubvol` staging**: `--stage-mode auto` mounts a pure-Rust `/dev/fuse` v7.31 daemon (`fusermount3` + `SCM_RIGHTS`) on `staging_target_path` when `/dev/fuse` and `fusermount3` are available (and performs an `MS_BIND` bind-mount onto `target_path` in `NodePublishVolume` when `target_path != staging_target_path`, requiring `CAP_SYS_ADMIN` / mount namespace privileges), falling back cleanly to `HostSubvol` (`StageMode::HostSubvol`) with a live fenced `CowFs` actor and `0600` handoff socket when unprivileged.
  - **Single-writer CSI-to-Shim coordination**: Pass `-csi-state /var/lib/os-csi/node` (or env `OS_CSI_NODE_STATE`) to `containerd-shim-os-v1` (trusted config takes precedence over OCI annotations). CSI block volumes route container `/dev/vdN` I/O through `OsCsiNode`'s live fenced `0600` `os-nbd` socket, while CSI `cowfs` volumes coordinate single-writer ownership via `flock` + `ACQUIRE`/`RELEASE` handoff and live `$NODE_STATE/fences/*.json` checks (never blindly using `ForceTakeover` to self-fence or steal another running container's lease).

## Explicit Non-Goals & Preserved Invariants

1. **Zero Linux ELF delegation**: `containerd-shim-os-v1` and `os-native::oci_runtime` execute WebAssembly (`\0asm`) and WASIX images only. Any `\x7fELF` or non-`\0asm` executable is explicitly rejected with `ENOEXEC` (`InvalidArgument` over TTRPC) — never delegated to `runc` or host `execve`.
2. **Strict single-writer fencing (no `MULTI_NODE_MULTI_WRITER`)**: `os-csi` enforces single-writer leases in `ClusterState` with monotonic `fence_epoch` and refuses `MULTI_NODE_MULTI_WRITER` (`INVALID_ARGUMENT`). Concurrent read-only mounts (`MULTI_NODE_READER_ONLY`) are supported.
3. **Frozen ABIs & zero external Cargo bloat**: `abi::Call` remains frozen at **74 variants** (`node scripts/conformance/check-abi.mjs`), zero Durable Object schemas or browser files were modified, and **zero** new external Cargo crates were added to `Cargo.lock`.

# Phase 10b (`#87`): `/dev/net/tun` L3 Interface, Tenant L3 Overlay, and `os-cni`

Phase 10b (`#87`) delivers a portable L3 virtual network interface (`/dev/net/tun`), a tenant-isolated L3 overlay transport (`OverlayRelay` Durable Object + `NativeOverlaySwitch` + browser WebSocket/WebTransport/WebRTC unordered DataChannel dataplane), and a CNI Spec v1.0.0 plugin (`crates/os-cni`) while keeping `abi::Call` frozen at **74 variants**, adding **zero new external Cargo crates**, and preserving the **zero-network default boot** invariant.

---

## Architecture Summary

### 1. Frozen ABI & Capability Scope (`crates/abi/src/overlay.rs`, `crates/abi/src/auth_v2.rs`)
- **`abi::Call` remains frozen at 74 variants.** All TUN control operations ride on the existing `abi::Call::Ioctl { fd, request, arg }` with Linux-standard request numbers (`TUNSETIFF = 0x4004_54ca`, `TUNGETIFF = 0x8004_54d2`, `TUNGETFEATURES = 0x8004_54cf`) plus OS-specific read/configure ioctls (`TUN_IOC_INFO = 0x5457_0301`, `TUN_IOC_STATS = 0x5457_0302`, `TUN_IOC_SET_MTU = 0x5457_0303`).
- **`RemoteScope.overlay: Option<OverlayScope>` is default-deny (`None`)** in `RemoteScope::default()`, `RemoteScope::cloud_only()`, and `RemoteScope::full()`. `RemoteScope::is_empty()` checks `!self.has_overlay()`.
- **`RemoteScope::node_ceiling(node_id)`** permits `"overlay/*"` cluster prefixes and `OverlayScope::node_ceiling()`, monotonically attenuated via `OverlayScope::attenuate` (intersecting `networks`, `allowed_peer_cidrs`, `cni_ipam`, and clamping `max_interfaces`, `max_mtu`, and `max_bytes_per_sec` to server ceilings).
- **Process credential preservation**: `LocalProcessTable::set_cred_inner` / `reexec` preserves valid `overlay`-only `allowed_remote_scope` just like `net`-only scopes.
- **Deterministic disjoint tenant subnets**:
  - IPv4 supernet: `10.64.0.0/10` (`4,194,304` addresses -> `16,384` disjoint `/24` tenant subnets derived via `SHA-256("os-overlay-v1-v4:" || tenant)`).
  - IPv6 supernet: `fd50:6f73::/32` (RFC 4193 ULA -> disjoint `/64` tenant subnets derived via `SHA-256("os-overlay-v1-v6:" || tenant)`).

### 2. `/dev/net/tun` Clone Device (`crates/vfs/src/tundev.rs`)
- Registered locally inside `DevTmpFs` at `/dev/net/tun` (`0o600`, root-owned, char device `"net:tun"`, **zero network calls at boot**).
- **Per-open-file-description clone semantics**: each `open("/dev/net/tun", O_RDWR)` creates an independent unbound `TunSlot` keyed by `OpenRef.id`; `dup`/`fork`/`SCM_RIGHTS` share the same interface; last close tears down the interface, frees the name, and releases the remote/switch port.
- **Access control**: non-root -> `EACCES`; root without `"tun"` grant (when policy requires explicit grants) -> `EPERM`; `O_PATH` permitted for `fstat` inspection only (cannot attach or read/write).
- **`TUNSETIFF`**: strictly requires `flags == (IFF_TUN | IFF_NO_PI)` (`0x1001`); rejects `IFF_TAP`, missing `IFF_NO_PI`, invalid names, and re-attach with `EINVAL`, and duplicate live names with `EBUSY`. Accepts both structured JSON (`TunSetIffReq`) and raw 40-byte Linux `struct ifreq`. Auto-allocates `tun0..tun15` when `name` is `""` or `"tun%d"`.
- **Single-packet datagram I/O**:
  - Both WASI hosts (`crates/os-native/src/wasi_host.rs` and `web/wasi/process.js`) gather all `iovec` buffers into one L3 packet on `fd_write` and scatter one L3 packet across `iovec` buffers on `fd_read`.
  - `fd_seek`, `fd_tell`, `fd_pread`, and `fd_pwrite` return `WASI_ESPIPE` (`70`).
  - Zero-length `fd_read` returns `0` without consuming a queued packet; small read buffers copy `buf.len()` bytes and discard the remainder of that single packet (`rx_truncated_reads++`).
  - `fd_write` larger than the interface MTU returns `EMSGSIZE` (`tx_dropped_malformed++`).
  - Bounded `1 MiB` (`1_048_576` B) RX queue (drop-tail, `rx_dropped_queue_full++`) and TX queue (`EAGAIN` when full).
  - Blocking reads/writes wait via `WakeBus` (`os-native`) / `Atomics.wait(sockNotify)` (browser) with `EINTR` on signals when `!O_NONBLOCK`; `poll_oneoff` supports `FD_READ`, `FD_WRITE`, and peer/transport hangup (`FD_READWRITE_HANGUP`).

### 3. Triple Defense-in-Depth L3 Firewall (`OverlayFirewall`)
Enforced identically at three independent layers: (1) `os-vfs` `TunRegistry`, (2) `os-native` `NativeOverlaySwitch`, and (3) Cloudflare Worker `OverlayRelay` Durable Object:
- **Header & bogon validation**: strict IPv4 (`ver == 4`, `ihl >= 20`, `ihl <= len`, `total_len == len`, `ttl > 0`, rejects `0.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16`, `224.0.0.0/4`, `240.0.0.0/4`, subnet network `.0`, directed broadcast `.255`) and IPv6 (`ver == 6`, `len >= 40`, `40 + payload_len == len`, `hop_limit > 0`, rejects `::`, `::1`, `fe80::/10`, `ff00::/8`, `::ffff:0:0/96`, `64:ff9b::/96`, subnet router-anycast).
- **TX anti-spoofing**: requires `pkt.src == leased_ip`; forged source IPs are dropped immediately (`tx_dropped_spoofed_src++`) and never forwarded.
- **TX cross-tenant & CIDR filtering**: rejects self-loop (`tx_dropped_self_loop++`) and requires `dst` inside `tenant_cidr` and `allowed_peer_cidrs`. Destinations targeting another tenant's CIDR within the overlay supernet (`10.64.0.0/10` / `fd50:6f73::/32`) or another tenant's active port are dropped (`tx_dropped_cross_tenant++`).
- **RX defense-in-depth**: validates `dst == local.leased_ip`, `src ∈ local.tenant_cidr`, `src != local.leased_ip`, and `len <= local.mtu` before enqueueing into any TUN RX queue (`rx_dropped_policy++`).

### 4. Worker Gateway & `OverlayRelay` Durable Object (`crates/worker/src/overlay_{gateway,do}.rs`)
- Mounted BEFORE `with_guest_cookie` at `POST /api/overlay/{attach,renew,detach}` and `GET /api/overlay/connect`.
- **Strict auth separation**: `session.*` credentials require a matching `os_session` cookie plus same-origin CSRF validation; `node.*` credentials reject any cookie. Guests, job tokens, bootstrap tokens, and credentials lacking `RemoteScope.overlay` fail closed (`403 EACCES`).
- **Lease-backed IPAM in `ClusterState` DO**: allocates tenant-scoped IPv4/IPv6 addresses with `ClusterState` leases (Worker gateway uses a fixed `60 s` default TTL `OVERLAY_DEFAULT_LEASE_TTL_SECS`; `os-cni` validates `5..=3600 s`) under `/t/<tenant>/overlay/{config,ipam,endpoints,node-endpoints}/...` via atomic `Txn` compare-and-swap (`Version == 0`).
- **Single-use 30-second upgrade tickets**: bound to `(tenant, network, endpoint_id, ns, cred_hash, instance_id)` and consumed atomically on `GET /api/overlay/connect` (`101 Switching Protocols`).
- **`OverlayRelay` SQLite DO** (`OVERLAY_RELAY` binding, `v8-overlay-relay` migration): sharded strictly per `overlay:{cluster}:{tenant}:{network}` using Hibernatable WebSockets (`< 512 B` attachment), `[0x01][raw L3 packet]` binary forwarding, `#[serde(deny_unknown_fields)]` JSON control & strictly intra-tenant WebRTC `Signal` frames (`<= 16 KiB`), batched `Machine` `io.max` accounting (`32 KiB` / `250 ms` + teardown flush), live credential revocation checks (`1008`), and alarm-driven cleanup.

### 5. Native Overlay, Browser Transport & `os-cni` Plugin
- **`os-native` (`crates/os-native/src/overlay.rs`)**: `NativeOverlaySwitch` switches L3 packets directly across local pods/containers within the same tenant/network with zero host root required, optionally uplinks to a remote `OverlayRelay` over binary WebSockets (`--overlay-url` opt-in, default off), and optionally bridges to host Linux `/dev/net/tun` when `CAP_NET_ADMIN` is present. `containerd-shim-os-v1` loads `$CNI_STATE/attachments/<container_id>.json` with `O_NOFOLLOW` symlink/traversal guards.
- **Browser (`crates/client-kernel/src/tun_bridge.rs`, `web/kernel/overlay-transport.js`)**: completely dormant at boot. On explicit `TUNSETIFF`, attaches via `/api/overlay/attach` + `OverlayRelay` WS, supports opportunistic WebTransport datagrams and window-brokered WebRTC unordered unreliable DataChannels (`label: "os-overlay-l3"`, `{ ordered: false, maxRetransmits: 0 }`) with automatic fallback to `OverlayRelay` WS.
- **`os-cni` (`crates/os-cni`)**: standalone CNI Spec v1.0.0 binary (`VERSION`, `ADD`, `CHECK`, `DEL`) with `O_NOFOLLOW` path guards, `ClusterState` lease-backed IPAM, `LinuxTunNetnsDriver` + `UserspaceNetnsDriver`, and strictly idempotent `DEL` (including after host loss / wiped local state / expired lease) guarded by CAS (`CompareTarget::ModRevision(kv.mod_revision)`) so a delayed `DEL` never frees another container's reallocated IP.
- **`/usr/bin/tunctl` (`crates/utilities/src/tunctl.rs`, `crates/posix/src/tun.rs`)**: WASI guest CLI supporting `info`, `probe`, `echo`, `spoof`, `send`, and `hold` over `/dev/net/tun`.

---

## Conformance Matrix (`OV-01..OV-10`)

| Case | Test Suite | Verified Behavior |
| --- | --- | --- |
| **OV-01** | `crates/abi/src/overlay.rs` | `OverlayScope::attenuate` monotonicity, `RemoteScope` default-deny, strict IPv4/IPv6 parser, bogon/broadcast/multicast/IMDS/loopback rejection, `OverlayFirewall` anti-spoofing & cross-tenant denial. |
| **OV-02** | `crates/vfs/src/tundev.rs` | `/dev/net/tun` clone isolation, `0o600` non-root `EACCES` / ungranted root `EPERM` / `O_PATH` inspection, `TUNSETIFF` flags/name validation, single-packet read/write/truncation/MTU `EMSGSIZE`, exact `1 MiB` RX drop-tail + TX `EAGAIN`, `poll` readability/writability/hangup, last-close cleanup. |
| **OV-03** | `crates/os-cni/tests/cni_conformance.rs` | CNI Spec v1.0.0 `VERSION`/`ADD`/`CHECK`/`DEL` (binary + library), invalid version/env error codes, `ClusterState` lease IPAM, `CHECK` drift failure, idempotent double-`DEL`, idempotent `DEL` after wiped local state + lease expiry, CAS protection against freeing reallocated IPs. |
| **OV-04** | `crates/os-native/tests/overlay_tun.rs` | Pod-to-pod L3 ICMP Echo + UDP-in-IPv4 roundtrip between isolated `OciContainerHandle` Wasmtime pods wired via `NativeCniAttachment::load_nofollow` and `NativeOverlaySwitch` (`TUNSETIFF`, `fd_seek -> ESPIPE`, `poll_oneoff`, `fd_read`/`fd_write`). |
| **OV-05** | `crates/os-native/tests/overlay_tun.rs` | Spoofed source-IP drop, cross-tenant denial (`u1000` -> `u1001`), `> mtu` -> `WASI_EMSGSIZE`, `1 MiB` RX queue flood drop-tail without OOM, and `SIGKILL` clean TUN + switch port teardown. |
| **OV-06** | `crates/os-native/tests/overlay_tun.rs` | Default `os-native` boot makes zero network requests (`NativeOverlayConfig::default()`); unprivileged container without CNI attachment receives `WASI_ENOENT` for `/dev/net/tun`. |
| **OV-07** | `tests/overlay-e2e.mjs` | Live Miniflare (`OsAuthority`, `Machine`, `ClusterState`, `OverlayRelay` DO): `session.*` vs `node.*` cookie checks, CSRF & guest/no-scope `403 EACCES`, single-use ticket replay denial, real L3 roundtrip across `OverlayRelay` DO, hostile WS spoofed-src & cross-tenant drop counters, live revocation (`1008`), and real `os-cni` CLI `VERSION`/`ADD`/`CHECK`/`DEL` + host-loss CAS guard against live `ClusterState` DO. |
| **OV-08** | `tests/overlay-tun.spec.js` | Chromium Playwright E2E: zero boot `/api/overlay/*` / `/api/cluster/*` / `/api/service-auth` calls, authorized browser `/usr/bin/tunctl` ↔ peer L3 IPv4 roundtrip via `OverlayRelay`, spoofed source-IP drop, cross-tenant denial against a live Tenant B peer, and clean lease release on close. |
| **OV-09** | `tests/overlay-tun.spec.js` | Browser WebRTC unordered DataChannel (`label: "os-overlay-l3"`, `ordered: false`, `maxRetransmits: 0`) signaling & fallback to `OverlayRelay` WS, plus cross-tenant signaling rejection (`EACCES`). |
| **OV-10** | CI Gates | `node scripts/conformance/check-abi.mjs` (74 `Call` variants frozen), zero new external Cargo crates in `Cargo.lock`, 3-target `cargo clippy --locked --offline -- -D warnings`, and Phase 9/10a regression suites (`cluster-state.mjs`, `netd-gateway.mjs`, `netd_gateway.rs`) green. |

---

## Explicit Scope & Non-Goals

- **L3 point-to-point TUN only (`IFF_TUN | IFF_NO_PI`)**: Ethernet TAP (`IFF_TAP`), ARP, L2 broadcast/multicast, and raw host-LAN bridging are explicitly rejected (`EINVAL`).
- **No in-kernel TCP/IP stack**: `/dev/net/tun` delivers raw L3 IPv4/IPv6 packets directly to userspace processes (such as `tunctl` or a userspace stack); standard outbound TCP streams remain served by Phase 10a `netd` (`/run/netd.sock`).
- **Zero-network default boot**: `/dev/net/tun` is registered locally in `DevTmpFs` with zero network traffic; overlay attach, IPAM, and WebSocket/WebTransport/WebRTC connections remain strictly dormant until explicitly triggered by `TUNSETIFF` with a granted `RemoteScope.overlay` (or explicit `--overlay-url` / CNI attachment on `os-native`).
- **No transparent internet NAT**: Traffic is confined strictly to the tenant's overlay CIDR and explicitly granted `allowed_peer_cidrs`; packets outside the tenant CIDR or targeting another tenant are dropped by `OverlayFirewall`.

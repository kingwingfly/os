# Phase 10a (`#86`): `netd` Outbound Stream Socket Gateway

Phase 10a implements **`Boundary::Network` v1 (outbound TCP/TLS stream gateway)** across the browser host, Cloudflare Worker edge gateway, and `os-native` Wasmtime host without altering `abi::Call` (frozen at 74 variants) and without adding any external Cargo dependencies.

## Architecture Overview

```text
Guest WASI / WASIX process (`netctl`, `os_posix::net`, or standard `wasix_32v1` + `wasi_snapshot_preview1` sockets)
  │ AF_UNIX SOCK_STREAM `/run/netd.sock` (`abi::net_ctl` v1: Hello -> Connect/Resolve/Status)
  ▼
`/usr/bin/netd` (`netd.service`, ordinary WASI service supervised by PID 1; boots with zero network calls)
  │ AF_UNIX SOCK_STREAM `/run/net/host.sock` + `SCM_RIGHTS = [client_sock_fd]` (verifies host uid == 0)
  ▼
Host Bridge (verifies peer is verified `/usr/bin/netd` + inspects `SO_PEERCRED` on `client_sock_fd`)
  ├── Browser (`crates/client-kernel/src/netd_bridge.rs` + `web/kernel/netd-host.js`):
  │     mints `ServiceAuth v2` (`NetEgress`) token -> `POST /api/net/ticket` -> WebSocket `GET /api/net/connect?ticket=...`
  │     -> Cloudflare Worker (`crates/worker/src/net_gateway.rs`, `cloudflare:sockets` `worker_sys::connect`)
  │     -> `Machine` DO (`MACHINE_SCHEMA_VERSION = 4`: `net_tickets`, `net_streams`, `io_buckets`)
  └── Native (`crates/os-native/src/netd.rs`):
        enforces `NativeNetdConfig` (`--net-policy`, `--net-allow-loopback-test`) + SSRF-checked DNS -> `tokio::net::TcpStream`
        (`TlsMode::On` / `StartTls` return `EOPNOTSUPP`; TLS is never faked)
```

## Protocol & Framing (`crates/abi/src/net_ctl.rs`)

- **Boundary version**: `NETD_VERSION = abi::contract::NETWORK_VERSION` (`1`).
- **Control framing** (both `/run/netd.sock` and `/run/net/host.sock`): `[u32_be len][JSON]` with `1 <= len <= 16 KiB` and `#[serde(deny_unknown_fields)]`.
- **Data-plane framing**:
  - Unix socket (`StreamMode::Framed` & `/run/net/host.sock`): `[u8 tag][u32_be len][payload]`.
  - WebSocket (`/api/net/connect` binary frames after initial JSON `opened` message): `[u8 tag][payload]`.
  - Tags: `0x01 DATA` (`<= 16 KiB`), `0x02 CREDIT` (`u32_be` bytes), `0x03 HALF_CLOSE`, `0x04 CANCEL`, `0x05 CLOSED` (JSON `StreamClosed`).
- **Flow control & backpressure**: Fixed `64 KiB` initial window (`NET_INITIAL_WINDOW_BYTES`) and `16 KiB` chunks (`NET_DATA_CHUNK_MAX`). `netd` only sends `CREDIT` upstream after the downstream `client_sock` accepts bytes; both gateways pause reading from the upstream TCP socket whenever `client_rx_credit == 0`.
- **Half-close & cancellation**: `SHUT_WR` maps to `0x03 HALF_CLOSE` and closes the upstream write half while continuing to drain peer reads. Client close/`SIGKILL` emits `0x04 CANCEL` (including mid-connect), cancelling upstream dials and releasing concurrency quota slots immediately.

## Policy, SSRF Protection & Two-Key Loopback Testing

- **Default-deny everywhere**: `RemoteScope::default()`, `cloud_only()`, `node_ceiling()`, and `full()` all set `net: None`. `NativeNetdConfig::default()` sets `policy: None`. `NetScope { rules: [] }` denies all egress (`EACCES`).
- **Monotonic attenuation**: `NetScope::attenuate` computes exact pairwise intersection of `EgressRule`s (`HostMatch::{Exact, Suffix, Cidr, AnyPublic}`, `PortRange`, `TlsPolicy::{PlainOnly, TlsOnly, Any}`) and field-wise `.min()` of `NetQuota` clamped to server ceilings (`32` concurrent streams, `256 MiB`/stream, `30 s` connect timeout, `300 s` idle timeout, `1800 s` max lifetime).
- **SSRF / Private-IP / Bogon / Obfuscation filter**:
  - Blocks all RFC 1918, loopback, link-local / cloud IMDS (`169.254.0.0/16`), CGNAT (`100.64.0.0/10`), multicast, documentation, benchmarking, reserved IPv4 ranges; IPv6 loopback, ULA (`fc00::/7`), link-local (`fe80::/10`), IPv4-mapped (`::ffff:0:0/96`), NAT64, Teredo, 6to4, multicast, and reserved ranges.
  - Blocks internal/local hostnames (`localhost`, single-label hostnames, `metadata.goog`, `*.localhost`, `*.local`, `*.internal`, `*.home.arpa`, `*.arpa`, `*.lan`, `*.home`, `*.corp`, `*.intranet`, etc.) and obfuscated IP spellings (`2130706433`, `0177.0.0.1`, `127.1`, `0x7f000001`, zone IDs `%`).
  - Re-verifies every resolved IP (native) and post-connect `SocketInfo.remoteAddress` (Worker) against DNS rebinding, redacting resolved private IPs from error messages. Note: when dialing a DNS hostname on Cloudflare Workers, `workerd` may echo the hostname rather than the resolved IP in `SocketInfo.remoteAddress`; hostname DNS-rebinding defense then relies on Cloudflare edge egress policy in addition to pre-dial SSRF hostname and scope validation.
- **Two-key test-only loopback allowlist**: Empty in production (`LoopbackTestAllowlist::new()`). Local/CI tests must enable **both** the host allowlist (`--net-allow-loopback-test` / Worker env `NET_TEST_LOOPBACK_ADDRS`) for an exact `127.0.0.1:<port>` or `[::1]:<port>` **and** an explicit `HostMatch::Exact` rule in the caller's `NetScope`. `AnyPublic` never matches loopback, `Cidr ∩ Exact` never elevates to a private/loopback `Exact` grant, and DNS hostnames can never rebind to an allowlisted loopback address.

## Honest Scope & Non-Goals

- Outbound TCP/TLS streams only (`AF_INET`/`AF_INET6` `SOCK_STREAM`).
- `SOCK_DGRAM` (UDP), `SOCK_RAW`, `IPPROTO_UDP`, `IPPROTO_ICMP` return `EPROTONOSUPPORT`.
- Inbound `bind`/`listen`/`accept` on inet sockets return `EOPNOTSUPP`.
- `TlsMode::StartTls` returns `EOPNOTSUPP` on both the Worker gateway and `os-native` (`TlsMode::On` is supported by the Cloudflare Worker gateway via `cloudflare:sockets` `secureTransport: "on"`).
- Native host returns `EOPNOTSUPP` for gateway-terminated `TlsMode::On`/`StartTls` (plain `TlsMode::Off` TCP streams work directly; guests may terminate TLS end-to-end).
- Browser host `HostNetReq::Resolve` (`netctl resolve` and DNS `sock_addr_resolve` for hostnames) returns `EOPNOTSUPP` because the browser/Worker gateway resolves hostnames inside `Connect` rather than exposing raw DNS queries (IP literals still work in `sock_addr_resolve`; `os-native` implements SSRF-checked `Resolve`).
- Raw L3 packets, `/dev/net/tun`, and cross-node pod networking belong strictly to Phase 10b (`#87`).

## Conformance & Test Matrix (`NT-01..NT-10`)

- `crates/abi/src/net_ctl.rs` & `auth_v2.rs`: `NT-01`, `NT-02`, `NT-05` (policy attenuation, SSRF/obfuscation/two-key loopback, wire codecs, WASIX `AddrPort`).
- `crates/services/src/netd.rs`: `netd` state machine, credit-windowed backpressure, mid-connect cancel, host-loss teardown.
- `crates/os-native/tests/netd_gateway.rs`: `NT-03..NT-09` (echo + half-close, 2 MiB slow-consumer backpressure, cancellation, SSRF/policy denial, UDP/raw `EPROTONOSUPPORT`, concurrency & byte quotas, forged `netd` peer rejection, host-loss teardown).
- `tests/netd-gateway.mjs`: Miniflare + `cloudflare:sockets` Worker gateway E2E (single-use ticket replay denial, CSRF/origin checks, live revocation, SSRF refusal, echo/half-close/backpressure/quota).
- `tests/netd-service.spec.js`: Chromium boot verification (`netd.service` active with zero boot network calls + `netctl` default-deny check).

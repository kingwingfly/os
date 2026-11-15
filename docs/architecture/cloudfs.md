# Cloud filesystem v2

L1a part 2 of [#48](https://github.com/kingwingfly/os/issues/48) implements contract §2.3 at the authority and in the portable `os_vfs::cloud::CloudFs` driver. The browser syscall path still uses the existing path protocol. Client integration and its host HTTP transport are subsequent work; there is no compatibility window once repository callers move.

## Calls and identity

`abi::fs` owns the shared handle, metadata, open-option and lock values. `os-vfs` reexports them. `abi::remote_fs` defines the version-2 JSON envelope and calls. `POST /api/fs` accepts `version`, `credential`, `session` and `call`. A wrong version returns `EPROTONOSUPPORT`; no uid, PID, instance ID or caller-supplied pathname is accepted as authority. Control bodies are limited to 4 MiB. The outer Worker requires an `Origin` header matching the service origin for POST requests.

`connect` requires a valid, cloud-enabled process credential in the request's authenticated namespace. The service returns its filesystem ID, signed root handle, capability profile and a fresh session ID/resume secret. Separate connections get separate handle proofs even if they share an account or cookie. Subsequent calls authenticate the secret and a credential in the recorded issuer namespace; cookies are unnecessary for resuming. This uses the current credential issuer until the instance bootstrap work replaces it.

A handle's HMAC covers filesystem, session and inode identity. It grants no permission and keeps no reference. Inode numbers use SQLite AUTOINCREMENT, never recycle, and have generation 1. Missing objects are `ESTALE`; altered or foreign-session handles are `EACCES`. Lookup uses the inode's recorded name and the indexed child name, checking search permission. Walk checks all components before resolving any and stops at missing names, links or non-directories. It never interprets `..` or crosses a mount.

Open descriptions record their service session, inode, access and opening credential. Each request authenticates a presenting credential; open operations also verify that the opening credential remains valid. Chmod does not remove an existing grant. Revocation ends its references and locks and leaves an `EACCES` tombstone until session cleanup. Path-only opens retain removed directories without granting byte access.

## Lifetime and cancellation

The lease is 120 seconds. Hosts call `renew` at least every minute, including while operations are pending. Renewing with the existing secret resumes all opens and locks; no in-memory authority state is needed. Explicit disconnect or expiry releases references, locks and active read manifests. Credential revocation is independent of browser logout.

Open/create calls carry unique tickets. Successful replies are retained for idempotent delivery. `cancel_open` records cancellation even when it arrives before the original request, and releases a delivered-but-abandoned result. Lock tickets similarly identify persistent waits; the driver acknowledges each grant to retire its wait record; cancellation also removes a grant whose reply the client abandoned. POSIX wait cycles are checked across inodes; flock and POSIX locks never conflict. Granted locks belong to open descriptions and disappear on release.

The portable driver starts operations only when polled. Its cancellation guards retain cleanup across a dropped future or disconnected transport. Hosts must drain that queue alongside `FileRef`'s release queue. `renew` and ordinary driver calls drain it first. For each byte operation, `Transport::caller` snapshots the current kernel task's credential and PID before any await; neither the connection nor the open description supplies a cached calling PID. Session expiry is the final cleanup when the host disappears. Session secrets and request/lock tickets belong in private kernel state.

## Bytes and commits

`POST /api/fs/data` carries the serialized `DataRequest` in `X-OS-Filesystem`. Reads return raw bytes; writes send raw bytes and return `Written { offset, len }`. Individual data calls are limited to 8 MiB; the portable driver may return a short read/write at that boundary. Offsets and sizes obey the signed 64-bit limit, including EOF validation. SQLite bindings and reads preserve integers beyond JavaScript's safe-number range.

The gateway authorizes through the binding, applies process I/O accounting, and streams immutable data to or from R2 outside authority WASM. Each data request includes the calling `pid`, which the process registry validates against the presenting credential and its issuer namespace, including for empty transfers. Forked processes share a credential but retain their own I/O budgets; only job credentials may omit the PID. A write commits only after R2 acknowledges the complete object and the authority revalidates the session, opener and presenting credential. The transaction splices its extent into the inode's current manifest. Append chooses the current EOF in that same transaction, so concurrent appends cannot overwrite each other. A lost write response is uncertain; transports must not silently replay writes.

Truncation clips extents without copying data; later growth reads as zero. Reads pin their immutable manifest until stream completion/cancellation, with the service lease covering host loss. If I/O accounting denies a prepared request, the gateway releases its read pin or upload reservation before returning the denial. Existing chunk files can become extent manifests without moving their bytes, and source files stay pinned while their extents are referenced. Ordinary files cloned from build/image assets retain immutable asset references through reads and partial writes, with asset integrity checks preserved. The existing inline `pread` reader and file/job gateways understand these content representations, including sparse holes. Removing the final name or open reference permits collection; retained readers, jobs and shared extents delay it. Ordinary-file collection never deletes release assets.

Completed writes already reached the R2 plus SQLite service commit point. `sync_all`/`sync_data` validate the open and acknowledge that point. This does not claim host `fsync` behavior or finish the broader #50 consistency gates.

## State and validation

Schema 8 adds durable service sessions, open descriptions, cancellation receipts, lock queues, immutable extents and temporary read/upload references. The table definitions replace schema 7 directly; older state is refused. Image and browser release checks require the same schema. No deployment or data migration is part of this change.

`crates/vfs/tests/cloud.rs` exercises cancellation and durable lock state without host dependencies. `tests/cloudfs.spec.js` exercises the real Worker/SQLite/R2 path: forged/foreign/stale handles, permission and open-grant rules, cancellation races, sparse bytes and large offsets, atomic append, locks, revocation and actual lease expiry. Full client/host adapter conformance and latency measurements remain #48 work.

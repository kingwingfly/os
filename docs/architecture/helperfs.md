# HelperFs & `os-local-helper` Architecture

`HelperFs` (`crates/vfs/src/helperfs.rs`) and `os-local-helper` (`crates/local-helper`) mount a host Linux directory into the portable OS VFS while preserving Linux filesystem semantics and keeping the helper's state completely out of the user's folder.

## 1. Protocol & Boundary Negotiation (`abi::local_helper`)

- **Boundary:** `Boundary::LocalHelper`, version `1` (`abi::local_helper::VERSION`).
- **Handshake:** Every client session begins with `Request::Hello(Hello { boundary: Boundary::LocalHelper, versions: [1] })`, returning `HelloReply { boundary, version, write, execute, handshake }`. Legacy envelopes, missing/mismatched `handshake` tokens, or mismatched boundary/version requests fail immediately with `Errno::EPROTONOSUPPORT` (no legacy protocol fallbacks or migrations, per `docs/architecture/contract.md` §2.12).
- **Session lifecycle:**
  1. `Attach { version, client_id, handshake, cred, grant }` verifies the single-use `handshake` token, clamps requested `{ write, execute }` against the helper's startup `--write` / `--execute` flags, initializes the persistent root inode if absent, and returns `AttachReply { version, session, fs, root, capabilities, grant, lease_seconds }`.
  2. `Call { version, session, cred, call }` executes one handle-addressed VFS operation with the calling `WireCred { id, group, groups, umask }`. `Open` and `Create` carry client-generated idempotency `ticket`s paired with `Call::CancelOpen { ticket }` so dropped or transport-uncertain open requests cannot leak host descriptors.
  3. `Renew { version, session }` refreshes the 60-second lease (`LEASE_SECONDS = 60`, renewed every `RENEW_MILLIS = 20_000`; transient `ENOTCONN`/`ETIMEDOUT` errors retry across the lease window before disconnecting). Expired sessions release all open descriptors and host locks cleanly.
  4. `Detach { version, session }` tears down the session immediately on unmount.

## 2. HTTP Origin, Concurrency & Token Security

`os-local-helper` binds strictly to `127.0.0.1:<port>` (default ephemeral `--port 0`) and mints a fresh 256-bit random Bearer token per process startup:

- Requires an exact match on the `Origin` header (`--origin <ORIGIN>`), answering `403` (`EACCES`) otherwise, and emits `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods: POST, OPTIONS`, `Access-Control-Allow-Headers: Content-Type, Authorization`, `Access-Control-Allow-Private-Network: true`, and `Vary: Origin`.
- Verifies `Authorization: Bearer <token>` using constant-time byte comparison (`401` / `EACCES` on mismatch).
- Caps control payloads at `CONTROL_MAX` (4 MiB -> `413` / `E2BIG`) and data chunks at `DATA_MAX` (1 MiB).
- **Bounded HTTP body readers & decoupled engine:** The `os-local-helper-engine` thread owns the state store, open descriptors, and 1-second lease/ticket sweeps independently of HTTP/1.1 TCP loopback sockets, while request reading runs in a bounded worker pool (`32` concurrent workers, kernel `SO_RCVTIMEO` enforced against a `10`s read deadline -> `408`/`ETIMEDOUT`, overflow -> `503`/`EBUSY`) so stalled HTTP clients cannot starve active sessions or prevent lease expiration.

## 3. Persistent Folder UUID, JS-Safe Inodes & Metadata Store

- **State directory:** Stored outside the mounted folder (`$XDG_STATE_HOME/os-local-helper` or `~/.local/state/os-local-helper`, overridable via `--state-dir`). Startup resolves directory descriptors without following symlinks (`O_NOFOLLOW`), inspects `/proc/self/mountinfo` backing filesystem paths and device/inode identities before creating `folders`, and refuses any `--state-dir` (or its `folders` descendant) equal to or overlapping `--root` directly or via bind mounts. Sidecar files are never written into the user's folder.
- **Exclusive per-root lock & format versioning (§2.12):** Each root's state file is guarded by an exclusive non-blocking `flock(2)` on `<root_hash>.lock` (`EBUSY` if another helper already owns that root's store). `PersistedState.format_version = 2` is written atomically via descriptor-confined `openat`/`fsync(file)`/`renameat`/`fsync(dir)`. Older state versions reset metadata once without touching host files; newer versions fail helper startup with `Errno::EPROTONOSUPPORT`.
- **Stable filesystem & inode identity:**
  - Mints one persistent UUIDv4 per canonical root folder (`FsId("helperfs:<uuid>")`), whose 53-bit `dev()` and minted `ino` values stay `<= abi::fs::JS_SAFE` (`2^53 - 1`, never wrapping, returning `ENOSPC` if exhausted; `ROOT_INO` is reserved exclusively for the root folder).
  - Keys each discovered host inode by `(subfs_relpath, subvol, subfs_fsuuid, host_ino, host_gen, host_kind)`:
    - `subfs_relpath`: folder-relative path of the topmost directory crossing a mount/subvolume boundary (`statx` `mnt_id` or `stx_subvol`, or directory `st_dev` change across submounts/btrfs subvolumes without splitting overlayfs file devices from their parent directory).
    - `subvol` / `subfs_fsuuid`: persistent Btrfs subvolume ID (`statx` `STATX_SUBVOL`) and superblock UUID (`FS_IOC_GETFSUUID`) so replaced snapshots or swapped submounts at the same path invalidate stale handles and grants while surviving `st_dev` renumbering across reboot/replug.
    - `host_gen`: `statx` `stx_btime` if available, falling back to `FS_IOC_GETVERSION`; refuses (`EOPNOTSUPP`) filesystems lacking any incarnation proof rather than inheriting stale grants.
  - Handles returned to clients carry HMAC-SHA256 proofs bound to `(fs_id, node.ino, node.generation)`.
- **External replacement & inode reuse protection:** If a host object disappears or its `(subfs_relpath, subvol, subfs_fsuuid, st_ino, host_gen, host_kind)` changes outside OS, held handles fail with `ESTALE`, stale OS grants/ACLs/xattrs are wiped, the generation bumps, and re-discovery resets metadata to private defaults (attaching account `uid`/`gid`, mode `0600` for files / `0700` for dirs, no ACL).

## 4. Permissions, Creation & Host Grant Ceilings

- Stores virtual OS ownership (`uid`/`gid`), full 12-bit mode (`setuid`, `setgid`, `sticky`, rwx), extended POSIX ACLs (`system.posix_acl_access`), default ACLs (`system.posix_acl_default`), and `user.*`/`trusted.*` xattrs using `os_core::{acl, inode, xattr}` rules.
- Creation (`create`, `mkdir`, `mknod`, `symlink`) applies creator `cred` (`uid`, primary/supplementary `groups`, explicit per-call `umask`), `setgid` directory group inheritance (`os_core::inode::setgid`), and default ACL inheritance.
- Enforces startup and session ceilings:
  - Missing `write` -> `Errno::EROFS` on all mutating calls and write/truncate/create opens.
  - Missing `execute` -> `Errno::EACCES` on non-directory `Access::Exec` opens (`dir` traversal and regular-file reads remain allowed).

## 5. Linux Confinement, Open Descriptors & Real Host Locks

- **Path confinement:** Uses root-anchored `openat2(2)` (`self.root_fd` with `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS`) to enforce kernel confinement atomically on opens and regular-file creation, `O_NONBLOCK` identity verification prior to any truncation, live `/proc/self/fd` relative-path recovery when held directories are renamed internally, and just-in-time `openat2` + `/proc/self/fd` containment checks (plus best-effort rollback for newly created entries if an external race moves a parent out of root) on `mkdirat`/`mkfifoat`/`symlinkat`/`linkat`/`unlinkat`/`renameat2`.
- **Unlink/rename survival & durability:** Open handles retain real host `OwnedFd` descriptors inside the active session (`open_metadata` queries live `statx(fd)` so unlinked files report `nlink == 0`, reads/writes keep working until last `Release`, and `sync_all`/`sync_data` invoke real `fsync(2)`/`fdatasync(2)`). Only confirmed last-link removals (`nlink == 0`) or garbage-collected orphaned records tomb/evict metadata while multi-link hard links keep metadata alive.
- **Atomic flags:** `O_EXCL` create, `O_APPEND` (`pwritev2(..., RWF_APPEND)` with descriptor offset), and `renameat2(..., RENAME_NOREPLACE)` rejecting unknown flags with `EINVAL`.
- **Real host locks:** Supports both `flock(2)` and Linux Open File Description (`F_OFD_SETLK`/`F_OFD_GETLK`) byte-range locks directly on each unique open host `OwnedFd` so host processes and other attachments observe the same locks.
  - Blocking `lock` registers a queued ticket, polls non-blocking host lock acquisition on the engine thread without blocking HTTP sockets, detects `LockFamily::Posix` cycles with `Errno::EDEADLK`, tracks exact per-ticket displaced segments, and rolls back displaced locks cleanly via `CancelLock` if a waiting future is dropped.
  - `HelperFs` distinguishes confirmed server rejections from uncertain transport failures (`ENOTCONN`/`ETIMEDOUT`): lost provider reachability surfaces `Errno::ENOTCONN` (`Errno::ENOLCK` on lock calls/overload; ordinary `try_lock` contention preserves `Errno::EAGAIN`; `Errno::ENODEV` on confirmed detached sessions), mutating/write operations whose acknowledgement was lost (`write_at`, `set_len`, `sync_all`, `sync_data`, `setattr`, `mkdir`, `mknod`, `symlink`, `link`, `unlink`, `rmdir`, `rename`, `setxattr`, `removexattr`) surface `Errno::EIO`, and `CancelOpen`/`CancelLock`/`Release` remain queued across transient `ENOTCONN`/`ETIMEDOUT`/`EIO`/`ENOLCK`/`EAGAIN`/`EBUSY` failures until `Renew` or the next operation drains them.

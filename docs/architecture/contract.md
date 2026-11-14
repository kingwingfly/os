# Architecture contract

This is the decision record for the [#44](https://github.com/kingwingfly/os/issues/44) refactor, written in L0b ([#47](https://github.com/kingwingfly/os/issues/47)). It settles what the later steps (#48–#65) build. It changes no behaviour; the only code it adds is unused version and capability types in `crates/abi/src/contract.rs`.

**Status.** Each decision is marked:

- **Decided**: the owner has stated it.
- **Proposed**: a default from reviewing the code, awaiting the owner's approval in this document's pull request. Once the pull request merges, every decision here is authoritative, and the later sub-issues are edited to agree.

"Today" statements describe `dev` at `48d9c15` and cite the code. Measured differences from Linux come from the L0a baseline ([`docs/compat/matrix.md`](../compat/matrix.md)).

## Contents

1. [Definitions and evidence](#1-definitions-and-evidence)
2. [Decisions](#2-decisions)
3. [Filesystem capability profiles](#3-filesystem-capability-profiles)
4. [Mounts and namespaces](#4-mounts-and-namespaces)
5. [New calls: flags and errors](#5-new-calls-flags-and-errors)
6. [Versioned boundaries](#6-versioned-boundaries)
7. [Replacement table](#7-replacement-table)

## 1. Definitions and evidence

| Term | Meaning |
| --- | --- |
| **Instance** | One running OS: one kernel, one boot, its own PID 1, PID space, `/proc`, `/run`, `/tmp`, mount namespaces and service lifecycle. It begins at boot and ends at shutdown or when its host goes away. Its identifier is random per boot. |
| **Execution host** | What runs an instance: today one browser tab's dedicated kernel Worker; later a native host. One host runs one instance. |
| **Account** | A user known to the identity service: uid, groups, home, password. Shared by every instance where it signs in. |
| **Login session** | One account's session inside one instance: a session leader process, its PTY or seat, and the credential it was granted. A login in another tab is another session in another instance. |
| **Seat** | Where a login session's input and output are: a terminal (PTY) or a graphical display with its input devices, in one instance. |
| **Mount namespace** | A process's set of mounts. Processes share or copy it; it never spans instances. |
| **App window** | A surface a process shows through the compositor. It belongs to one process in one instance; it is not a session or an instance. |

**Evidence a remote service accepts.** A remote service acts only on a credential it issued, or that its configured issuer issued, for the operation and resource requested. None of the identifiers above is a credential: an instance id, boot id, host id, PID, session number, seat, window, pathname, mount name or image digest grants nothing on its own. Local uid 0 is not remote root.

## 2. Decisions

### 2.1 What an instance is (Proposed)

**Today.**
- **One process space per browser login.** All tabs of one browser login share one PID space: the `Machine` Durable Object chosen by the session or guest key (`crates/worker/src/lib.rs`, `/api/sys` with `X-Registry` → `db::Db::namespace`). Its process table is in `crates/worker/src/procs.rs`.
- **One kernel Worker per tab.** Each tab runs its own dedicated kernel Worker (`web/kernel/protocol.js` `kernelPort()`, `web/kernel/client.js`), which owns that tab's process Workers and shared-memory pipes.
- **The init lease spans tabs.** One tab at a time holds the `Machine`'s init lease (`web/kernel/init.js`).
- **Cross-tab `ps` and `kill` work** today, because the process table is on the server.

**Decision.**
- **One tab, one instance.** An instance is one execution host: one tab's dedicated kernel Worker, with its own boot id, PID 1, PIDs, `/proc`, `/run` and `/tmp`.
- **A second tab is a second instance.** It shares the account and the remote filesystems, but not processes. Cross-tab `ps` and `kill` end: a tab's processes are invisible to other tabs.
- **No attaching yet.** Attaching a page to another instance (a remote terminal or display) is a later feature. `contract.rs` reserves the identity fields (`InstanceIdentity`) and nothing else.
- **Lifetime.** Closing or reloading a tab ends its instance, as host loss ends a machine's processes.

**Implemented by** #54 (process table and `/proc` in the instance), #56 (boot, PID 1), #57 (sessions).

### 2.2 Where kernel code lives (Proposed)

**Today.**
- **Server-side Rust:** path lookup and permission rules are Rust (`crates/kernel`, `crates/core`), executed by the server.
- **Client-side JavaScript:** the client's mount routing, descriptors and metadata overlay (`web/kernel/workspace.js`, `mount-policy.js`, `local-mounts.js`).
- **Client kernel crate:** `crates/client-kernel` (973 lines) holds processes and tokens only.

**Decision.**
- **Portable Rust crates.** Kernel semantics live in Rust crates with no DOM, `web-sys` or `wasm-bindgen` types, so a native host and a headless test host can run them. That covers VFS objects, the mount table, path walk, process filesystem context, procfs, local sockets and the process table.
- **Thin glue.** `crates/client-kernel` remains the thin `wasm-bindgen` glue.
- **JavaScript is host adapters only:** browser file and directory handles, OPFS, the helper connection, transports (MessagePort, WebRTC, relay), Worker spawning, and the page protocol. Adapters perform I/O and report results; they make no permission or path decisions.

**Implemented by** #48 (VFS crate and drivers), #51 (mount table and walk), #54 (process table), #55 (sockets).

### 2.3 The remote filesystem protocol (Proposed)

**Today.**
- **Paths, resolved by the server.** Every file call in `abi::Call` takes an absolute path string, and the server resolves it: `crates/kernel/src/namei.rs` over the path-keyed `Store` (`crates/core/src/permissions.rs:272`), on the table `nodes(path PRIMARY KEY, parent, ino)` (`crates/worker/src/db.rs`).
- **Why that blocks the target.** A client that owns mounts, `chroot` and cwd cannot work this way: the server would interpret `..` and symlinks against its own tree, not the client's mount table and process root. The baseline shows the effect: `mount-parent`, `link-dotdot` and `cwd-rename` differ from Linux (#48, #51).

**Decision.**
- **Version 2 is addressed by handles.** A handle is opaque, server-issued, and names (filesystem id, inode, generation). The calls are:
  - `lookup(dir, name)`;
  - `walk(dir, names)`, which resolves several components in one round trip and stops at the first symlink, missing name or non-directory, returning how far it got;
  - `getattr`, `setattr`, `readdir`, `open`, `create`, `mkdir`, `mknod`, `symlink`, `readlink`, `link(handle, dir, name)`, `unlink(dir, name)`, `rmdir(dir, name)`, `rename(dir, name, dir, name, flags)`, `getxattr`/`setxattr`/`listxattr`/`removexattr`, `statfs`, and `fsync`.
- **Who resolves what.** The client resolves `..`, symlinks and mount crossings against its own mount table and process root. The server never sees a client path.
- **Authorization.** The server authorizes every call with the caller's credential:
  - `lookup` and `walk` check search permission on each directory they pass.
  - An operation on a handle checks permission on that object, as Linux checks an open file or cwd and not its ancestors' later changes.
  - A handle is bound to the credential it was issued to, so a forged handle, or one from another credential, fails with `EACCES`.
  - A handle whose inode is gone, or whose generation has changed, fails with `ESTALE`.
  - Revoking a credential invalidates every handle bound to it.
- **Path calls go away.** Version 1 path calls are removed once nothing in the repository uses them. No compatibility window is kept (§2.12).
- **Server storage.** Looking a child up by (directory inode, name) uses the existing `nodes_ino` index; the table may be re-keyed if useful, without migration.

**Implemented by** #48 (calls and the cloud driver), #51 (client-side walk; path calls removed).

### 2.4 Who is trusted for what (Proposed)

**Today.** AGENT.md says user space is never trusted and every check is in the kernel; that was written when the kernel was the server.
- **Exec.** The authority checks the image (execute, not read), snapshots the caller's credential, and records it under the hash of the process's token (`crates/worker/src/creds.rs`).
- **Fork and revocation.** Forks carry the same token. The registry revokes it once no process holds it.
- **setuid.** setuid and setgid bits are descriptive and do not elevate (`crates/kernel/src/lib.rs:424`).
- **Limits.** cgroup limits (`pids.max`, `memory.max`, `io.max`) live in the `Machine`'s tables (`crates/worker/src/procs.rs`).

**Decision.**
- **Local policy, local enforcement.** Local policy protects one user's processes and local resources from another user's, inside one instance. Its enforcer is the client kernel, which the user's browser runs, so it is not a security boundary against that user. It is documented as such.
- **Remote services check everything themselves.** Each remote service checks its own resources against a credential it issued. Nothing local is taken on trust: a modified kernel gains no remote right.
- **No request needed** for `fork`, `exit`, `wait`, `kill` within the instance, signals, pipes, process groups, sessions, local sockets, local mounts of local filesystems, and tmpfs.
- **A request to the service is needed for:**
  - an identity change: `login`, `su`, `sudo`, `passwd`, `newgrp`, and exec of a setuid image if that is ever allowed to elevate (it is not today, and this contract keeps that);
  - the first use of a remote resource in a credential's lifetime (a filesystem mount, a device, a task);
  - every remote operation thereafter, each authorized as in §2.3.
- **Fork.** A forked child gets its parent's credential with no request: the child's remote calls carry the same remote credential, as forks carry the same token today.
- **Exec.** A plain exec keeps the credential and its remote rights. Exec does not need the service unless the image is remote, in which case the remote filesystem checks execute permission as for any read.
- **Revocation.**
  - The identity service revokes a credential when the account signs out, a password changes, the account is locked, or `sudo` expires.
  - Every remote call made with it then fails with `EACCES`. The instance learns of the revocation through its event line (the existing session WebSocket) and marks the credential dead.
  - Local processes keep running under their local uid, as on Linux after an account change, but have no remote access until a new login.
- **Accounting.**
  - Remote accounting stays remote: storage quota, containers, relay bandwidth, tasks and rate limits.
  - Local `pids.max`, `memory.max` and the local process count become local policy, enforced by the kernel and documented as bypassable by a modified client.
  - #44's "without losing denial or resource-accounting guarantees" therefore holds for every remote resource, and holds locally only against other users' processes, not against the browser's owner.

**Implemented by** #54 (local process authority and remote admission), #57 (login and sessions), #59 (exports).

### 2.5 Filesystem identity and metadata, per driver (Proposed)

| Driver | Filesystem identity | Inode identity | Where OS metadata lives |
| --- | --- | --- | --- |
| Cloud tree (`OsAuthority`) | the authority's filesystem id | its inode ids, with a generation added | the authority's tables, as today |
| Browser storage (`os-workspace` in OPFS) | a UUID minted at first use | ids minted by the metadata store | a metadata store beside the tree in OPFS (not inside it), keyed by the UUID |
| Host folder (browser directory handle) | a UUID minted at first attach, kept with the handle in IndexedDB and matched with `isSameEntry` | ids minted by the metadata store, keyed by path within the folder | OPFS, keyed by the UUID |
| Host folder (Linux helper) | the helper's `st_dev` | `st_ino` (already reported as `dev:ino`, `crates/local-helper/src/linux.rs:150`) | the helper's own state directory, keyed by `st_dev:st_ino` |
| Shared mount (export) | the publisher's | the publisher's | the publisher's, passed through |

**Consequences.**
- **Host folders are profile-local.** A directory-handle folder's identity and metadata are stable only within one browser profile.
- **Outside renames lose metadata.** A rename made outside the OS loses that file's metadata, which reverts to the folder defaults.
- **No sidecar files.** Nothing is written into the user's folder.
- **Never wider than the host.** Metadata never grants more than the host grant: the browser permission, or the helper's `--write`/`--execute` ceiling.

**Implemented by** #48 (identity), #49 (metadata stores).

### 2.6 Filesystem capability profiles (Proposed)

Every later gate is read against the table in [§3](#3-filesystem-capability-profiles). A capability a driver lacks returns the errno the table names, never success.

### 2.7 Mounts and namespaces (Proposed)

- **Private propagation only.** `MS_SHARED`, `MS_SLAVE` and `MS_UNBINDABLE` are rejected with `EINVAL`. A new namespace copies the mounts of the one it comes from.
- **Supported:** bind mounts (with `MS_REC`), `MS_RDONLY`, `MS_NOEXEC`, `MS_NOSUID`, `MS_NODEV`, `MS_REMOUNT` of those flags, `MS_MOVE` (for the root switch), unmount and lazy detach.
- **Who may mount.**
  - Instance root may mount anything.
  - An ordinary user may mount a filesystem it has a grant for (host folder, browser storage, an export it was admitted to) on a directory it owns. That covers what the Mounts app does today. `nosuid` and `nodev` are forced on such mounts, as for FUSE user mounts.
  - Bind mounts, remounts of mounts you did not make, and `MS_MOVE` need instance root.
- **Errors** for busy unmount, lazy detach, export revocation and provider loss are in [§4](#4-mounts-and-namespaces).

**Implemented by** #51 (mount table and calls), #52 (namespaces and authorization), #58 (tools and the Mounts app).

### 2.8 Local IPC (Proposed)

**Today.** The only IPC is the pipe. A service's readiness is a line on an inherited pipe (`crates/services/src/notify.rs`), and nothing lets one process serve another.

**Decision.**
- **Unix-domain sockets.** `AF_UNIX` `SOCK_STREAM` sockets bound to paths in the instance's VFS, normally under `/run`.
- **Peer credentials.** `SO_PEERCRED` is taken from the kernel's process table, never from the peer.
- **Descriptor passing.** `SCM_RIGHTS` passes descriptors, with their open descriptions and rights.
- **Unsupported for now:** `SOCK_SEQPACKET` and abstract names are not required; the step adds them only if a user needs them.
- **Not network sockets.** Network sockets remain the README's Phase 10 virtual network interface.

**Implemented by** #55.

### 2.9 GUI surfaces (Proposed)

**Today.**
- **A DOM desktop.** The desktop is a compositor in the page that places DOM windows (`crates/frontend/src/desktop.rs`).
- **Browser-rendered content.** Preview and Editor rely on the browser for PDF, video, input methods and accessibility.
- **The constraint.** A process in a Worker cannot touch the DOM.

**Decision.** There are two surface kinds under one protocol:
- **Document surface:** a sandboxed frame owned by one process and drawn by the browser. The process sends its content and receives events; the compositor places, sizes and stacks the frame and routes input focus to it.
- **Pixel surface:** an `OffscreenCanvas` the process draws through wasi-gfx.

The protocol contains no DOM types. `/dev/display` and `/dev/input` expose them to the compositor. Details belong to #60.

**Implemented by** #60, #61.

### 2.10 Versioning (Proposed)

**Today.**
- **Capabilities without versions.** `abi::Features` (`crates/abi/src/lib.rs:259`) discovers capabilities, but no protocol carries a version.
- **Existing version numbers:** the page–kernel envelope (`web/kernel/protocol.js` `VERSION = 1`), the client kernel (`crates/client-kernel` `VERSION = "1"`) and the accelerator ioctl (`crates/abi/src/accelerator.rs` `VERSION = 1`) carry their own, and nothing negotiates them.

**Decision.**
- **Named boundaries with versions.** Each boundary in [§6](#6-versioned-boundaries) has a version.
- **Negotiation at connect.** Each side states the versions it speaks, and the highest common one is used.
- **No common version.** With none in common, the connection is refused with `EPROTONOSUPPORT`, and a browser page reloads to get matching code.
- **One version per side.** Because nothing older is kept (§2.12), each side speaks exactly one version during #44; the negotiation exists to detect a stale page or host after a deployment, not to serve old clients.

`contract.rs` defines the boundaries, their versions and the negotiation rule.

### 2.11 "Native" in the L5 and L6 gates (Proposed)

#44 requires browser and native presentation to pass the same scenarios. But the native agent is a Phase 9.1 deliverable, and Phase 9 waits for #44.

**Decision.**
- **The gate:** the contracts contain no DOM types, and a headless test host that implements the host adapter passes the same protocol suite as the browser host.
- **Later:** real native presentation follows Phase 9.1.

### 2.12 Data preservation (Decided, owner, 2026-11-14)

**None.** When #44 is done, the owner removes the deployment and all its data and redeploys.

- **May change without migration:** the state schema, the authority's tables, Durable Object classes, storage layout and protocols. Each incompatible change bumps the schema version, so stale state is refused, never misread.
- **Removed as soon as replaced:** an old path goes when its replacement works in the repository. Its authorization rules and denial tests carry over.
- **Per-mount permissions are not carried over.** A filesystem's first attachment after L1 starts private to the attaching account and never widens access.
- **Still required:** the new system's own release generations, upgrades and rollback (L3).

### 2.13 Dispatch (Proposed)

The contract records only the boundary between task state and delivery:
- **Task state stays with the task service:** admission, durable state, leases, cancellation and results.
- **A dispatcher only delivers notices** of the form "task T, attempt A, is ready". It holds no task state and no bulk data, and it may deliver twice. A consumer claims the attempt from the task service, which fences duplicates.

The full Queues contract stays in README "Cloudflare Queues and background dispatch" and is implemented in Phase 9.2-Q.

### 2.14 When Phase 9 may start (Proposed)

#44 says after L6. Phase 9 (shared compute) needs identity, namespaces, init and the task contract, but not the GUI work.

**Proposed:** Phase 9 may start after #59 (L4b). The owner may keep #44's rule.

## 3. Filesystem capability profiles

Target profiles (Proposed). "Emulated" means the OS provides the behaviour in its own metadata within one instance; another instance, or a change made outside the OS, can observe the difference. A "no" returns the errno shown. The last column cites the L0a baseline rows that differ today.

| Capability | Cloud tree | Browser storage (OPFS) | Host folder (directory handle) | Host folder (helper) | Shared mount (export) |
| --- | --- | --- | --- | --- | --- |
| Filesystem identity | global | profile-local | profile-local | host-local (`st_dev`) | the publisher's |
| Open file survives unlink | yes | emulated: name removed, content deleted at last close | no: later access `ESTALE` | yes (the helper holds the host descriptor) | the publisher's |
| Open file survives rename | yes | yes | yes when renamed through the OS; `ESTALE` after an outside rename | yes | the publisher's |
| Hard links | yes | emulated in the metadata store | no: `EPERM` | yes | the publisher's |
| Symbolic links | yes | emulated in the metadata store | no: `EPERM` | yes, confined beneath the folder | the publisher's |
| Atomic `O_EXCL` create | yes | yes within the instance (instance lock) | yes within the instance (instance lock) | yes | the publisher's; a lost acknowledgement is an uncertain write |
| Atomic rename, `RENAME_NOREPLACE` | yes | yes within the instance | not atomic: declared; `RENAME_NOREPLACE` checked under the instance lock | yes (`renameat2`) | the publisher's |
| Durability point (`fsync` returns after) | the authority's transaction and chunk commit | closing the writable stream, or the sync handle's `flush()` | closing the writable stream | the helper's `fsync(2)` | the publisher's acknowledgement |
| Locking (`flock`, `fcntl`) | within the instance only | within the instance only | within the instance only | within the instance only | within the instance only |

Baseline rows: `open-rename`, `open-unlink`, `hard-link`, `symlink` → #48; `exclusive`, `noreplace`, `flush` → #50.

- **Locking across instances** is not provided by any driver; a lock is visible only within its instance.
- **Unsupported locks.** A lock request a driver cannot honour fails with `ENOLCK` (added to `abi::Errno` by #50).
- **Provider loss** (the folder's permission withdrawn, the helper gone, the publisher offline) fails operations with `ENOTCONN` (added by #51), as on Linux when a FUSE daemon dies.

## 4. Mounts and namespaces

Proposed results, following Linux where it has an answer:

| Situation | Result |
| --- | --- |
| `umount` of a mount with open files, a cwd, a process root or child mounts in it | `EBUSY` |
| `umount2(MNT_DETACH)` (lazy detach) | Succeeds at once. The mount leaves the namespace; open files, cwds and process roots in it keep working until released; then the filesystem is released. |
| `umount2(MNT_FORCE)` | `EINVAL` (not supported) |
| The publisher revokes an export, or the receiver's access is withdrawn | The mount stays attached. Every operation through it, including on open descriptors, fails with `EACCES`, until it is unmounted. |
| Provider loss | The mount stays attached. Operations fail with `ENOTCONN`. A write whose acknowledgement was lost fails with `EIO` and is reported as an uncertain write. |
| `MS_SHARED`, `MS_SLAVE`, `MS_UNBINDABLE` | `EINVAL` |
| `MS_PRIVATE` | Accepted; already the case |

## 5. New calls: flags and errors

These are the calls #51–#56 add. Errors follow Linux; the "OS rule" column says where this OS differs or decides.

### `mount(source, target, fstype, flags, data)`

| Item | Value |
| --- | --- |
| Flags | `MS_RDONLY`, `MS_NOSUID`, `MS_NODEV`, `MS_NOEXEC`, `MS_REMOUNT`, `MS_BIND`, `MS_REC`, `MS_MOVE`, `MS_PRIVATE`; any other flag → `EINVAL` |
| Filesystem types | `cloud`, `opfs`, `hostfs`, `helperfs`, `sharefs`, `tmpfs`, `proc`; unknown → `ENODEV` |
| `EPERM` | the caller may not mount here (§2.7) |
| `EACCES` | a path component cannot be searched, or the provider refused the grant |
| `ENOENT`, `ENOTDIR`, `ELOOP`, `ENAMETOOLONG` | path errors, as for any lookup |
| `EBUSY` | `MS_MOVE` or remount of a mount that cannot change now |
| `EINVAL` | unsupported flags or propagation; `MS_MOVE` or `MS_REMOUNT` of something that is not a mount point |
| `ENOTCONN` | the provider cannot be reached (added by #51) |

### `umount2(target, flags)`

| Item | Value |
| --- | --- |
| Flags | `MNT_DETACH`, `UMOUNT_NOFOLLOW`; `MNT_FORCE` and `MNT_EXPIRE` → `EINVAL` |
| `EBUSY` | in use, without `MNT_DETACH` |
| `EINVAL` | not a mount point, or an unsupported flag |
| `EPERM` | the caller did not make this mount and is not instance root |
| `ENOENT`, `ENOTDIR`, `ELOOP`, `ENAMETOOLONG` | path errors |

### `chroot(path)`

| Item | Value |
| --- | --- |
| Effect | changes only the calling process's root; not its cwd, descriptors or namespace |
| `EPERM` | the caller is not instance root (the reference is `CAP_SYS_CHROOT`) |
| `EACCES` | search permission denied on a component |
| `ENOENT`, `ENOTDIR`, `ELOOP`, `ENAMETOOLONG`, `EIO` | as Linux |

### `chdir(path)`, `fchdir(fd)`

| Item | Value |
| --- | --- |
| Effect | the cwd is held as a handle, not a string; it follows its directory through renames |
| `EACCES` | search permission denied |
| `EBADF` | `fchdir` of a descriptor that is not open |
| `ENOENT`, `ENOTDIR`, `ELOOP`, `ENAMETOOLONG` | as Linux |

### `fsync(fd)`, `fdatasync(fd)`

| Item | Value |
| --- | --- |
| Effect | returns only after the driver's durability point (§3); today both return 0 without doing anything (`web/wasi/process.js:873-874`) |
| `EBADF` | not open |
| `EINVAL` | the descriptor cannot be synced: a pipe, socket or terminal |
| `EIO` | the provider failed to make the data durable, or the acknowledgement was lost (uncertain write) |
| `ENOSPC`, `EDQUOT`, `EROFS` | as Linux; `EDQUOT` is added to `abi::Errno` by #50 |

### `unshare(flags)`, `setns(fd, nstype)`

| Item | Value |
| --- | --- |
| Namespaces | `CLONE_NEWNS` only; any other flag → `EINVAL` |
| `EPERM` | the caller is not instance root (there are no user namespaces) |
| `setns` | the descriptor is a `/proc/<pid>/ns/mnt` of the same instance; any other → `EINVAL`; another user's process → `EPERM` |

### Root switch (`switch_root`)

| Item | Value |
| --- | --- |
| Form | Linux's sequence: `chdir(new)`, `mount(new, "/", MS_MOVE)`, `chroot(".")`, then `execve` of the main init; not a separate syscall |
| Who | PID 1 of the instance, in the initial namespace, before any login session exists |
| `EPERM` | any other caller |
| `EINVAL` | the new root is not a mount point |
| `EBUSY` | the old root is still in use when the early filesystem is released |

## 6. Versioned boundaries

| Boundary | Between | Version this contract defines | Today |
| --- | --- | --- | --- |
| Syscall | applications and the kernel: `abi::Call`, WASI/WASIX imports | 1 | `abi::Call` over `/api/sys`, unversioned |
| Host adapter | the portable kernel and its host: page protocol, Worker spawning, file handles | 1 | `web/kernel/protocol.js` `VERSION = 1` |
| Remote filesystem | filesystem clients and filesystem services | 2 (handles, §2.3) | 1 (paths), unversioned |
| Identity | instances and the identity service: login, credentials, revocation | 1 | cookie and token routes, unversioned |
| Device and task | typed devices and remote tasks | 1 | `accelerator::VERSION = 1` |
| GUI | clients, the compositor, `/dev/display`, `/dev/input` | 1 (reserved, #60) | none |

**Negotiation (Proposed).**
- **Hello.** The first message on each connection is a hello naming the boundary and the versions offered.
- **Choice.** The receiver picks the highest version both offer.
- **Refusal.** With none in common, it refuses with `EPROTONOSUPPORT` and the client reloads.

`contract::negotiate` implements the choice.

## 7. Replacement table

What each component does today, where each responsibility goes, and which step moves it. As §2.12 decides, the old path is removed when its replacement works, with no compatibility window and no rollback to an older deployment.

| Component today | Responsibility | Goes to | Step |
| --- | --- | --- | --- |
| `Machine` Durable Object (`crates/worker/src/machine.rs`, `procs.rs`) | PIDs, process table, fork/exec admission, signals, cgroups | the instance kernel (§2.1, §2.4) | #54 |
| | remote admission and accounting (containers, tasks, relay) | stays remote, behind a versioned admission call | #54 |
| | login and init coordination, init lease | instance PID 1 and the service manager | #56, #57 |
| `OsAuthority` (`crates/worker/src/lib.rs`, `db.rs`) | path resolution across the shared tree | the client's walk over handles (§2.3) | #48, #51 |
| | authorization of files, devices, credentials | stays: the remote filesystem and identity services | — |
| | `/proc` and other instance-local trees | the instance (procfs, tmpfs) | #54 |
| `Workspace` (`web/kernel/workspace.js`) | prefix routing of `/mnt/local`, `/mnt/shared`, `/opt/private`; lexical `..`; per-path inode numbers | the mount table and component walk | #51 |
| `PermissionMount` (`web/kernel/mount-policy.js`) | in-memory permission overlay for providers | filesystem-owned metadata stores (§2.5) | #49 |
| Init lease (`web/kernel/init.js`, `login-boot.js`) | which tab runs init; page-driven startup | each instance's own PID 1 and service manager | #56, #57 |
| In-page shell (`crates/frontend/src/shell.rs` and `shell/`) | the interactive shell | a shell executable on a PTY, started by the terminal | #62 |
| `desktop.rs` (`crates/frontend/src/desktop.rs`) | window management in the page | the compositor and desktop-shell processes | #61 |
| Built-in apps (Files, Mounts, Editor, Preview) | page components | ordinary GUI processes | #63, #64 |
| In-kernel export dispatcher (`web/kernel/mount-sharing.js`) | serving exports | an ordinary export service | #59 |

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
| **Browser profile** | One browser's same-origin storage (OPFS, IndexedDB, Web Locks) and cookies. Every tab of a profile is a separate instance, but they share this storage. |
| **Account** | A user known to the identity service: uid, groups, home, password. Shared by every instance where it signs in. |
| **Credential** | What the identity service issues for an account (or a `sudo` elevation): the only thing a remote service acts on. An instance holds the credentials of its login sessions and running processes. |
| **Login session** | One account's session inside one instance: a session leader process, its PTY or seat, and the credential it was granted. A login in another tab is another session in another instance. |
| **Seat** | Where a login session's input and output are: a terminal (PTY) or a graphical display with its input devices, in one instance. |
| **Mount namespace** | A process's set of mounts. Processes share or copy it; it never spans instances. |
| **App window** | A surface a process shows through the compositor. It belongs to one process in one instance; it is not a session or an instance. |

**Evidence a remote service accepts.** A remote service acts only on a credential it issued, or that its configured issuer issued, for the operation and resource requested. None of the other terms is a credential: an instance id, boot id, host id, PID, session number, seat, window, pathname, mount name or image digest grants nothing on its own. A filesystem handle (§2.3) only names an object; the credential presented with it is what is checked. Local uid 0 is not remote root.

## 2. Decisions

### 2.1 What an instance is (Proposed)

**Today.**
- **One process space per browser login.** All tabs of one browser login share one PID space: the `Machine` Durable Object chosen by the session or guest key (`crates/worker/src/lib.rs`, `/api/sys` with `X-Registry` → `db::Db::namespace`). Its process table is in `crates/worker/src/procs.rs`.
- **One kernel Worker per tab.** Each tab runs its own dedicated kernel Worker (`web/kernel/protocol.js` `kernelPort()`, `web/kernel/client.js`), which owns that tab's process Workers and shared-memory pipes.
- **The init lease spans tabs.** One tab at a time holds the `Machine`'s init lease (`web/kernel/init.js`).
- **Cross-tab `ps` and `kill` work** today, because the process table is on the server.

**Decision.**
- **One tab, one instance.** An instance is one execution host: one tab's dedicated kernel Worker, with its own boot id, PID 1, PIDs, `/proc`, `/run` and `/tmp`.
- **A second tab is a second instance.** It shares the account, the remote filesystems and the browser profile's storage (§2.5), but not processes. Cross-tab `ps` and `kill` end: a tab's processes are invisible to other tabs.
- **No attaching yet.** Attaching a page to another instance (a remote terminal or display) is a later feature. `contract.rs` reserves the identity fields (`InstanceIdentity`) and nothing else.
- **Lifetime.** Closing or reloading a tab ends its instance, as host loss ends a machine's processes.

**Implemented by** #54 (process table and `/proc` in the instance), #56 (boot, PID 1), #57 (sessions).

### 2.2 Where kernel code lives (Proposed)

**Today.**
- **Server-side Rust:** path lookup and permission rules are Rust (`crates/kernel`, `crates/core`), executed by the server.
- **Client-side JavaScript:** the client's mount routing, descriptors and metadata overlay (`web/kernel/workspace.js`, `mount-policy.js`, `local-mounts.js`).
- **Client kernel crate:** `crates/client-kernel` holds processes and tokens. It also exports the Rust permission policy that `PermissionMount` calls for every decision (`vfs_policy`, over `kernel::mount_policy`) and private-extension validation (`private_extension`).

**Decision.**
- **Portable Rust crates.** Kernel semantics live in Rust crates with no DOM, `web-sys` or `wasm-bindgen` types, so a native host and a headless test host can run them. That covers VFS objects, the mount table, path walk, process filesystem context, procfs, local sockets and the process table.
- **Thin glue.** `crates/client-kernel` remains the thin `wasm-bindgen` glue.
- **JavaScript is host adapters only:** browser file and directory handles, OPFS, IndexedDB, Web Locks, the helper connection, transports (MessagePort, WebRTC, relay), Worker spawning, and the page protocol. Adapters perform I/O and report results; they make no permission or path decisions.

**Implemented by** #48 (VFS crate and drivers), #51 (mount table and walk), #54 (process table), #55 (sockets).

### 2.3 The remote filesystem protocol (Proposed)

**Today.**
- **Paths, resolved by the server.** Every file call in `abi::Call` takes an absolute path string, and the server resolves it: `crates/kernel/src/namei.rs` over the path-keyed `Store` (`crates/core/src/permissions.rs`, `trait Store`), on the table `nodes(path PRIMARY KEY, parent, ino)` (`crates/worker/src/db.rs`).
- **Open files tracked on the server.** The authority records open files in its `fds` table, and reads and writes go through them.
- **Why that blocks the target.** A client that owns mounts, `chroot` and cwd cannot work this way: the server would interpret `..` and symlinks against its own tree, not the client's mount table and process root. The baseline shows the effect: `mount-parent`, `link-dotdot` and `cwd-rename` differ from Linux (#48, #51).

**Decision.**
- **Handles.** Version 2 addresses objects by handle: an opaque, server-issued value naming (filesystem id, inode, generation).
  - A handle is bound to the **instance** that obtained it, not to one credential. Any credential that instance holds may present it, as on Linux, where a cwd or an open file passes across `su`, `sudo`, `newgrp` and `SCM_RIGHTS`.
  - A handle from another instance, or a forged one, fails with `EACCES`.
  - A handle whose inode is gone, or whose generation has changed, fails with `ESTALE`.
- **One credential per request.** Every request names the credential acting, and the server checks that credential, as Linux checks the current process's credentials.
- **Name operations:**
  - `lookup(dir, name)`;
  - `walk(dir, names)`: resolves several components within this one filesystem in one round trip. Each name is a single component and never `.` or `..` (`EINVAL` otherwise). It stops at the first symlink, missing name or non-directory, and returns how far it got. The client never passes a name beyond its own next mount point: it splits a path at its mount points and resolves `..`, symlinks and mount crossings itself, against its mount table and process root, so `..` can never escape a `chroot` through the server;
  - `parent(dir)`: the directory's parent and its name there, within this filesystem (at the filesystem's root it says so). The client resolves `..` with it inside a filesystem, and with its own mount table at mount roots and process roots. `getcwd` is built from it, so a cwd renamed by another instance still resolves `..` and reports its current path;
  - `create(dir, name, mode, flags, access)`: creates and opens in one call, returning the new handle and an open reference with the requested access, whatever the new file's mode, as Linux gives the creator. With `O_EXCL` it fails with `EEXIST` if the name exists, so no other instance can slip in between;
  - `mkdir`, `mknod`, `symlink`, `readlink`, `link(handle, dir, name)`, `unlink(dir, name)`, `rmdir(dir, name)`, `rename(dir, name, dir, name, flags)`.
- **Attributes:** `getattr`, `setattr` (mode, owner, times, size), `readdir`, `getxattr`/`setxattr`/`listxattr`/`removexattr`, `statfs`.
- **Open files:**
  - `open(handle, access)` returns an **open reference**. The server records it, as the `fds` table does today.
  - `access` is read, write, read-write, append, or **exec**. Exec is checked against execute permission, not read, and its bytes serve only the loader, so execute-only images keep running (`crates/kernel/src/lib.rs`, the X rule).
  - `read(open, offset, length)`, `write(open, offset, data)`, `truncate(open, size)`, `fsync(open, datasync)` and `release(open)` act on it.
  - `lock(open, kind, range, wait)`, `unlock(open, range)` and `getlk(open, range)` take advisory locks. The cloud authority keeps them per inode, owned by open references and released with them, so every instance sees them (§3).
  - An open reference records the credential that opened it, as Linux records an open file's credential. It works only while that credential is valid: revoking the credential ends its open references, and later operations on them fail with `EACCES`.
  - **Execute-only is local policy.** Exec access sends the bytes to the client's loader, so a client that may execute a file can read it. The server still refuses exec access without execute permission, but it promises no confidentiality of executable bytes.
- **When permission is checked, as on Linux:**
  - `lookup` and `walk` check search permission on each directory they pass.
  - `open` checks the requested access once.
  - `read`, `write` and `truncate` through an open reference check only the access granted at open (and that its credential is still valid). A file created read-only can still be written and truncated through the descriptor that created it, as `tar` relies on.
  - Every other operation (`setattr`, `link`, `unlink`, xattrs) checks the presenting credential when it is made.
- **Content lifetime.** An unlinked file's content lives until its last open reference is released. Open references belong to the instance's **session** with the service: a lease renewed while the instance is connected, and a resume secret the service issues at connect.
  - A reconnect within the lease (proposed: two minutes) that presents the secret keeps every open reference and lock, so a network drop or a deployment loses nothing.
  - When the lease expires because the host vanished, the service releases them, so content is neither leaked nor collected under a reader.
  - AGENT.md's garbage-collection rule ("respect open references") applies to these references.
- **Path calls go away.** Version 1 path calls are removed once nothing in the repository uses them. No compatibility window is kept (§2.12).
- **Server storage.** Looking a child up by (directory inode, name) uses the existing `nodes_ino` index; the table may be re-keyed if useful, without migration.

**Implemented by** #48 (calls and the cloud driver), #50 (`fsync`), #51 (client-side walk; path calls removed).

### 2.4 Who is trusted for what (Proposed)

**Today.** README says "User space is never trusted" (README "Current executable and API inventory"), and every check is in the server; that was written when the kernel was the server.
- **Exec.** The authority checks the image (execute, not read), snapshots the caller's credential, and records it under the hash of the process's token (`crates/worker/src/creds.rs`).
- **Fork and revocation.** Forks carry the same token. The registry revokes it once no process holds it.
- **sudo.** `sudo` lasts five minutes (`sudo_until`, `crates/worker/src/api.rs`). Its expiry only stops new elevations; a process already executed under it keeps its snapshot.
- **setuid.** setuid and setgid bits are descriptive and do not elevate (`crates/kernel/src/lib.rs`).
- **Limits.** cgroup limits (`pids.max`, `memory.max`, `io.max`) live in the `Machine`'s tables (`crates/worker/src/procs.rs`). `io.max` limits admitted filesystem byte transfers.

**Decision.**
- **Local policy, local enforcement.** Local policy protects one user's processes and local resources from another user's, inside one instance. Its enforcer is the client kernel, which the user's browser runs, so it is not a security boundary against that user. It is documented as such.
- **Remote services check everything themselves.** Each remote service checks its own resources against a credential it issued. Nothing local is taken on trust: a modified kernel gains no remote right beyond what its credentials allow. It does receive the bytes of what it may execute (§2.3).
- **No request needed** for `fork`, `exit`, `wait`, `kill` within the instance, signals, pipes, process groups, sessions, local sockets, local mounts of local filesystems, and tmpfs.
- **A request to the service is needed for:**
  - an identity change: `login`, `su`, `sudo`, `passwd`, `newgrp`, and exec of a setuid image if that is ever allowed to elevate (it is not today, and this contract keeps that);
  - dropping privileges: root's `setuid`, `setgid` or `setgroups` to a lower identity asks the service for that identity's credential (root may act as any account, as `su` does). The process's remote credential is replaced, never kept, so a daemon that drops privileges has only the lower identity's remote rights;
  - the first use of a remote resource in a credential's lifetime (a filesystem connection, a device, a task);
  - every remote operation thereafter, each authorized as in §2.3.
- **Fork and exec.** A forked child keeps its parent's credential with no request. A plain exec keeps the credential and its remote rights.
- **Credential lifetime.** A credential held by running processes stays valid until the last of them exits, as today's exec snapshot does.
  - `sudo` expiry and signing out stop new uses (a new elevation, a new login) but do not cut off running processes.
  - Locking or deleting the account, changing its password, or an administrator's explicit revocation revokes its credentials at once. Every remote call made with them then fails with `EACCES`, and the instance learns of it through its event line (the existing session WebSocket).
  - Local processes keep running under their local uid, as on Linux after an account change, without remote access until a new login.
- **Accounting.**
  - Remote accounting stays remote: storage quota, filesystem byte transfers (today's `io.max`), containers, relay bandwidth, tasks and rate limits. The filesystem service enforces the transfer limit per credential, whatever the client claims.
  - Local `pids.max`, `memory.max` and the local process count become local policy, enforced by the kernel and documented as bypassable by a modified client.
  - #44's "without losing denial or resource-accounting guarantees" therefore holds for every remote resource, and holds locally only against other users' processes, not against the browser's owner.

**Implemented by** #54 (local process authority and remote admission), #57 (login and sessions), #59 (exports).

### 2.5 Filesystem identity and metadata, per driver (Proposed)

| Driver | Filesystem identity | Inode identity | Where OS metadata lives |
| --- | --- | --- | --- |
| Cloud tree (`OsAuthority`) | the authority's filesystem id | its inode ids, with a generation added | the authority's tables, as today |
| Browser storage (`os-workspace` in OPFS) | a UUID minted once per profile | ids minted by the metadata store | a metadata store beside the tree, in the profile's IndexedDB |
| Host folder (browser directory handle) | a UUID minted at first attach, kept with the handle in IndexedDB and matched with `isSameEntry` | ids minted by the metadata store, keyed by path plus a fingerprint (size and modification time at the OS's last write) | the profile's IndexedDB, keyed by the UUID |
| Host folder (Linux helper) | a UUID the helper mints for its root folder and keeps in its own state | (device, `st_ino`, birth time `stx_btime` or generation `FS_IOC_GETVERSION`). The device is the helper's stable name for each filesystem under the folder: the folder-relative path of that filesystem's topmost directory, which the helper records. It distinguishes mounts, btrfs subvolumes and snapshots under the folder, and survives `st_dev` renumbering after a reboot or re-plug. | the helper's own state directory, keyed by the folder UUID and inode identity |
| Shared mount (export) | the publisher's | the publisher's | the publisher's, passed through |

**Shared by every tab of a profile.** OPFS and IndexedDB belong to the browser profile, and every tab of it is a separate instance (§2.1). So for browser storage and directory-handle folders, the metadata store, open references and whole-file locks are profile-wide:
- **Metadata** is written in IndexedDB transactions.
- **Open references** are registered under Web Locks, which every same-origin tab shares. Unlink-at-last-close counts every tab's opens, and a tab's references go when it closes. A tab that crashes releases its Web Locks too, so each tab sweeps, as it starts, unlinked entries whose references are no longer held.
- **Minting** a folder's UUID happens under a Web Lock, so two tabs attaching one folder agree on one identity.

**Never wider than the host.**
- **Bounded by the host grant.** Metadata never grants more than the host grant: the browser permission, or the helper's `--write`/`--execute` ceiling.
- **Changes outside the OS reset metadata.** A file whose identity no longer matches its metadata loses it and gets the folder's private defaults (owner the attaching account, no ACL): a helper inode reused after a deletion, or a directory-handle file renamed, replaced or changed outside the OS.
  - On the helper this is exact, so a file never inherits a previous file's grants.
  - On a directory-handle folder it is a declared limit. The API exposes nothing stronger than path, size and modification time, so a file replaced outside the OS with the same size and modification time (`cp -p`, `rsync -a`) keeps the previous file's metadata. The folder's owner made both files; no other account can cause it.
- **No sidecar files.** Nothing is written into the user's folder.
- **Profile-local.** A directory-handle folder's identity and metadata are stable only within one browser profile.

**Implemented by** #48 (identity), #49 (metadata stores).

### 2.6 Filesystem capability profiles (Proposed)

Every later gate is read against the table in [§3](#3-filesystem-capability-profiles). A capability a driver lacks either refuses the operation with the errno the table names, or lets it succeed and fails later access with the named errno, as the table says. It never fakes success.

### 2.7 Mounts and namespaces (Proposed)

- **Private propagation only.** `MS_SHARED`, `MS_SLAVE` and `MS_UNBINDABLE` are rejected with `EINVAL`. A new namespace copies the mounts of the one it comes from.
- **Supported:** bind mounts (with `MS_REC`), `MS_RDONLY`, `MS_NOEXEC`, `MS_NOSUID`, `MS_NODEV`, `MS_SYNCHRONOUS`, `MS_DIRSYNC`, `MS_NOSYMFOLLOW`, the atime flags, `MS_REMOUNT` of those flags, `MS_MOVE` (for the root switch), unmount, lazy detach and root's forced unmount. `MS_SILENT`, `MS_POSIXACL`, `MS_I_VERSION` and the `MS_MGC_VAL` magic are accepted and ignored, as Linux does.
- **Filesystem types** include `image`, for read-only system and extension images. That keeps private extensions (Phase 8.2, mounted at `/opt/private/NAME` today) as ordinary mounts. Early init builds `/dev` from `devtmpfs` and `devpts`. There is no `sysfs` (`ENODEV`).
- **Who may mount.**
  - Instance root may mount anything.
  - An ordinary user may mount a filesystem it has a grant for (host folder, browser storage, an export it was admitted to, its private extension image) on a directory it owns.
  - The mount service creates the user's mount-point directories under `/mnt/local`, `/mnt/shared` and `/opt/private`, owned by that user, in the instance's tmpfs. So the Mounts app's `/mnt/local/NAME`, `/mnt/shared/NAME` and `/opt/private/NAME` keep working.
  - `nosuid` and `nodev` are forced on user mounts, and an ordinary user's remount cannot clear them (`EPERM`).
  - A user mount is usable only by its user, not even by instance root, as FUSE does without `allow_other`. That keeps root's services and tools out of user-controlled trees with hostile symlinks or stalled providers. Sharing with other users goes through exports (#59).
  - Bind mounts, remounts of mounts you did not make, and `MS_MOVE` need instance root.
- **Errors** for busy unmount, lazy detach, export revocation and provider loss are in [§4](#4-mounts-and-namespaces).

**Implemented by** #51 (mount table and calls), #52 (namespaces and authorization), #58 (tools and the Mounts app).

### 2.8 Local IPC (Proposed)

**Today.** The only IPC is the pipe. A service's readiness is a line on an inherited pipe (`crates/services/src/notify.rs`), and nothing lets one process serve another.

**Decision.**
- **Unix-domain sockets.** `AF_UNIX` `SOCK_STREAM` sockets bound to paths in the instance's VFS, normally under `/run`.
- **Peer credentials.** `SO_PEERCRED` is taken from the kernel's process table, never from the peer.
- **Descriptor passing.** `SCM_RIGHTS` passes descriptors, with their open descriptions and rights, including remote open references (§2.3) between users of the same instance.
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
- **Capabilities without versions.** `abi::Features` (`crates/abi/src/lib.rs`) discovers capabilities, but most protocols carry no version.
- **Versions that exist, and nothing negotiates them:**
  - the page–kernel envelope (`web/kernel/protocol.js` `VERSION = 1`);
  - the client kernel (`crates/client-kernel` `VERSION = "1"`);
  - the local helper (`protocol: 1`, checked in `web/kernel/native-mount.js`);
  - images and release manifests (`os_image::PROTOCOL = 1`, `crates/image`);
  - the accelerator ioctl (`crates/abi/src/accelerator.rs` `VERSION = 1`).

**Decision.**
- **Named boundaries with versions.** Each boundary in [§6](#6-versioned-boundaries) has a version.
- **Negotiation at connect.** Each side states the versions it speaks, and the highest common one is used. With none in common, the connection is refused with `EPROTONOSUPPORT`.
- **Recovering in a page.** A page never reloads by itself, since a reload ends the instance and its processes.
  - It reports the mismatch, keeps local processes running, and fails only the calls that cross the mismatched boundary.
  - It offers a reload at the default release, or, at a pinned release URL (where a reload stays pinned, README "Immutable releases and extensions"), the switch to the default release.
  - Nothing is recorded between page loads, so each deployment's mismatch is reported afresh.
- **One version per side.** Because nothing older is kept (§2.12), each side speaks one version during #44. The exception is the step that replaces a protocol: version 1 and version 2 file calls coexist between #48 and #51. The negotiation exists to detect a stale page or host after a deployment, not to serve old clients.

`contract.rs` defines the boundaries, their versions and the negotiation rule.

### 2.11 "Native" in the L5 and L6 gates (Proposed)

#44 requires browser and native presentation to pass the same scenarios. But the native agent is a Phase 9.1 deliverable, and Phase 9 waits for #44.

**Decision.**
- **The gate:** the contracts contain no DOM types, and a headless test host that implements the host adapter passes the same protocol suite as the browser host.
- **Later:** real native presentation follows Phase 9.1.

### 2.12 Data preservation (Decided, owner, 2026-11-14)

**None.** When #44 is done, the owner removes the deployment and all its data and redeploys.

- **Server state may change without migration:** the state schema, the authority's tables, Durable Object classes, storage layout and protocols. Each incompatible change bumps the schema version, so stale state is refused, never misread.
- **Durable Object migration entries stay valid.** Cloudflare requires wrangler's `[[migrations]]` entries for Durable Object class changes, in deployment and in local development. Changes add entries as Cloudflare requires; the redeploy may start a fresh history.
- **Browser-side state survives the redeploy**, so it is versioned too.
  - Every store the client writes carries a format version: OPFS and IndexedDB metadata stores, the directory-handle registry, saved preferences.
  - Formats only move forward. Code meeting an older store resets it once, never reading it: its metadata goes back to private defaults. Code meeting a newer store (an older pinned release in another tab) leaves it alone and reports the filesystem unavailable (`EPROTONOSUPPORT`), so tabs on different releases never reset each other's metadata.
  - File contents (in `os-workspace` and in users' folders) are never deleted by a reset.
  - Cookies from before the redeploy fail authentication, and the user signs in again.
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

Target profiles (Proposed).
- **"Emulated"** means the OS provides the behaviour in its own metadata, coordinated across the tabs of the browser profile (§2.5). A change made outside the OS can still show the difference.
- **"Refused"** means the operation fails with the errno shown.
- **"Stale"** means the operation succeeds, but later access through a file already open fails with the errno shown.

| Capability | Cloud tree | Browser storage (OPFS) | Host folder (directory handle) | Host folder (helper) | Shared mount (export) |
| --- | --- | --- | --- | --- | --- |
| Filesystem identity | global | profile-local | profile-local | host-local (folder UUID) | the publisher's |
| Open file survives unlink | yes | emulated: name removed, content deleted when the last tab releases it (or when a later tab finds its holder gone) | stale: `ESTALE` | yes (the helper holds the host descriptor) | the publisher's |
| Open file survives rename | yes | yes | yes when renamed through the OS; stale (`ESTALE`) after an outside rename | yes | the publisher's |
| Hard links | yes | emulated in the metadata store | refused: `EPERM` | yes | the publisher's |
| Symbolic links | yes | emulated in the metadata store | refused: `EPERM` | yes, confined beneath the folder | the publisher's |
| Atomic `O_EXCL` create | yes | emulated (profile lock) | emulated (profile lock) | yes | the publisher's; a lost acknowledgement is an uncertain write |
| Atomic rename | yes | emulated (profile lock) | no: declared non-atomic | yes (`renameat2`) | the publisher's |
| `RENAME_NOREPLACE` | yes | emulated (profile lock) | emulated: checked under the profile lock | yes (`renameat2`) | the publisher's |
| Durability point (`fsync` returns after) | the authority's transaction and chunk commit | closing the writable stream, or the sync handle's `flush()` | closing the writable stream | the helper's `fsync(2)` | the publisher's acknowledgement |
| Locks (`flock`, `fcntl` byte ranges) | kept by the authority, seen by every instance | across the profile's tabs: Web Locks, with byte ranges in the metadata store | across the profile's tabs, as browser storage | the host's own locks, held by the helper, seen by every host program | the publisher's |

Baseline rows: `open-rename`, `open-unlink`, `hard-link`, `symlink` → #48; `exclusive`, `noreplace`, `flush` → #50.

- **No lock is faked.** A lock is granted only where every client of that filesystem can see it. A driver that cannot reach its lock keeper fails the request with `ENOLCK` (added to `abi::Errno` by #50), never with success.
- **Provider loss** (the folder's permission withdrawn, the helper gone, the publisher offline) fails operations with `ENOTCONN` (added by #51), as on Linux when a FUSE daemon dies.

## 4. Mounts and namespaces

Proposed results, following Linux where it has an answer:

| Situation | Result |
| --- | --- |
| `umount` of a mount with open files, a cwd, a process root or child mounts in it | `EBUSY` |
| `umount2(MNT_DETACH)` (lazy detach) | Succeeds at once. The mount leaves the namespace; open files, cwds and process roots in it keep working until released; then the filesystem is released. |
| `umount2(MNT_FORCE)` | Instance root: the provider's outstanding requests fail with `EIO`, then the unmount proceeds as without it (`EBUSY` if still busy). Anyone else: `EPERM`. |
| `umount2(MNT_EXPIRE)` | `EINVAL` (not supported) |
| The publisher revokes an export, or the receiver's access is withdrawn | The mount stays attached. Every operation through it, including on open descriptors, fails with `EACCES`, until it is unmounted. |
| Provider loss | The mount stays attached. Operations fail with `ENOTCONN`. A write whose acknowledgement was lost fails with `EIO` and is reported as an uncertain write. |
| `MS_SHARED`, `MS_SLAVE`, `MS_UNBINDABLE` | `EINVAL` |
| `MS_PRIVATE` | Accepted; already the case |
| Another user, or instance root, enters a user mount | `EACCES` (only its user may use it, §2.7) |
| An ordinary user's remount without `nosuid` or `nodev` | `EPERM` |

## 5. New calls: flags and errors

These are the calls #51–#56 add. Errors follow Linux; where this OS differs or decides, the table says so.

### `mount(source, target, fstype, flags, data)`

| Item | Value |
| --- | --- |
| Flags | `MS_RDONLY`, `MS_NOSUID`, `MS_NODEV`, `MS_NOEXEC`, `MS_SYNCHRONOUS`, `MS_DIRSYNC`, `MS_NOSYMFOLLOW`, `MS_NOATIME`, `MS_NODIRATIME`, `MS_RELATIME`, `MS_STRICTATIME`, `MS_LAZYTIME`, `MS_REMOUNT`, `MS_BIND`, `MS_REC`, `MS_MOVE`, `MS_PRIVATE`. `MS_SILENT`, `MS_POSIXACL`, `MS_I_VERSION` and the `MS_MGC_VAL` magic (`0xC0ED` in the top 16 bits) are accepted and ignored. Any other flag → `EINVAL`. |
| Filesystem types | `cloud`, `opfs`, `hostfs`, `helperfs`, `sharefs`, `image`, `tmpfs`, `proc`, `devtmpfs`, `devpts`; unknown (including `sysfs`) → `ENODEV` |
| `EPERM` | the caller may not mount here (§2.7), or an ordinary user's remount would clear `nosuid`/`nodev` |
| `EACCES` | a path component cannot be searched, or the provider refused the grant |
| `ENOENT`, `ENOTDIR`, `ELOOP`, `ENAMETOOLONG` | path errors, as for any lookup |
| `EBUSY` | `MS_MOVE` or remount of a mount that cannot change now |
| `EINVAL` | unsupported flags or propagation; `MS_MOVE` or `MS_REMOUNT` of something that is not a mount point |
| `ENOTCONN` | the provider cannot be reached (added by #51) |

### `umount2(target, flags)`

| Item | Value |
| --- | --- |
| Flags | `MNT_DETACH`, `UMOUNT_NOFOLLOW`, `MNT_FORCE` (instance root, §4); `MNT_EXPIRE` → `EINVAL` |
| `EBUSY` | in use, without `MNT_DETACH` |
| `EINVAL` | not a mount point, or an unsupported flag |
| `EPERM` | the caller did not make this mount and is not instance root, or `MNT_FORCE` without instance root |
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
| Effect | the cwd is held as a handle, not a string; it follows its directory through renames and across credential changes |
| `EACCES` | search permission denied |
| `EBADF` | `fchdir` of a descriptor that is not open |
| `ENOENT`, `ENOTDIR`, `ELOOP`, `ENAMETOOLONG` | as Linux |

### `fsync(fd)`, `fdatasync(fd)`

| Item | Value |
| --- | --- |
| Effect | returns only after the driver's durability point (§3); today both return 0 without doing anything (`web/wasi/process.js`, `fd_sync` and `fd_datasync`) |
| `EBADF` | not open |
| `EINVAL` | the descriptor cannot be synced: a pipe, socket or terminal |
| `EIO` | the provider failed to make the data durable, or the acknowledgement was lost (uncertain write) |
| `ENOSPC`, `EDQUOT`, `EROFS` | as Linux; `EDQUOT` is added to `abi::Errno` by #50 |

### `unshare(flags)`, `setns(fd, nstype)`

| Item | Value |
| --- | --- |
| `unshare` flags | `CLONE_NEWNS`, `CLONE_FS`, `CLONE_FILES`, or `0` (no change), as Linux; any other flag → `EINVAL` |
| `EPERM` | `CLONE_NEWNS` or `setns` without instance root (there are no user namespaces); `CLONE_FS` and `CLONE_FILES` need no privilege |
| `setns` | the descriptor is a `/proc/<pid>/ns/mnt` of the same instance; any other → `EINVAL` |

### Root switch (`switch_root`)

The root switch is not a separate call, and needs no special permission rule: it is a sequence of the calls above, which require instance root. The main init's early stage (#56) runs it as PID 1, following Linux's `switch_root`:

1. Open the initial root as a descriptor, so it can still be reached after the switch.
2. Move `/proc`, `/dev` and `/run` onto the new root: `mount("/proc", "/sysroot/proc", MS_MOVE)` and the same for the others.
3. `chdir("/sysroot")`, `mount(".", "/", MS_MOVE)`, `chroot(".")`.
4. Delete the initial filesystem's contents through the descriptor from step 1, without crossing into other mounts, then close it.
5. `execve` the main init, keeping PID 1.

Errors are those of the calls: `EPERM` without instance root, `EINVAL` when the new root is not a mount point, `EBUSY` when a mount cannot move now.

## 6. Versioned boundaries

| Boundary | Between | Version this contract defines | Today |
| --- | --- | --- | --- |
| Syscall | applications and the kernel: `abi::Call`, WASI/WASIX imports | 1 | `abi::Call` over `/api/sys`, unversioned |
| Host adapter | the portable kernel and its host: page protocol, Worker spawning, file handles | 1 | `web/kernel/protocol.js` `VERSION = 1` |
| Remote filesystem | filesystem clients and filesystem services | 2 (handles, §2.3) | 1 (paths), unversioned |
| Local helper | the helper driver and `os-local-helper` | 1 | `protocol: 1`, checked by `web/kernel/native-mount.js` |
| Identity | instances and the identity service: login, credentials, revocation | 1 | cookie and token routes, unversioned |
| Device and task | typed devices and remote tasks | 1 | the accelerator ioctl format is versioned separately (`accelerator::VERSION = 1`) |
| Release | images and release manifests | 1 | `os_image::PROTOCOL = 1` |
| GUI | clients, the compositor, `/dev/display`, `/dev/input` | 1 (reserved, #60) | none |

**Negotiation (Proposed).**
- **Hello.** The first message on each connection is a hello naming the boundary and the versions offered.
- **Choice.** The receiver picks the highest version both offer.
- **Refusal.** With none in common, it refuses with `EPROTONOSUPPORT`; a page recovers as §2.10 says.

`contract::negotiate` implements the choice.

## 7. Replacement table

What each component does today, where each responsibility goes, and which step moves it. As §2.12 decides, the old path is removed when its replacement works, with no compatibility window and no rollback to an older deployment.

| Component today | Responsibility | Goes to | Step |
| --- | --- | --- | --- |
| `Machine` Durable Object (`crates/worker/src/machine.rs`, `procs.rs`) | PIDs, process table, fork/exec admission, signals | the instance kernel (§2.1, §2.4) | #54 |
| | `pids.max`, `memory.max` | instance-local policy (§2.4) | #54 |
| | `io.max` (filesystem byte transfers), container, relay and task admission and accounting | stays remote, enforced per credential by the services | #54 |
| | login and init coordination, init lease | instance PID 1 and the service manager | #56, #57 |
| `OsAuthority` (`crates/worker/src/lib.rs`, `db.rs`) | path resolution across the shared tree | the client's walk over handles (§2.3) | #48, #51 |
| | authorization of files, devices, credentials; open-file tracking | stays: the remote filesystem and identity services | — |
| | `/proc` and other instance-local trees | the instance (procfs, tmpfs) | #54 |
| `Workspace` (`web/kernel/workspace.js`) | prefix routing of `/mnt/local`, `/mnt/shared`, `/opt/private`; lexical `..`; per-path inode numbers | the mount table and component walk | #51 |
| | private extensions at `/opt/private/NAME` (Phase 8.2) | user mounts of type `image` (§2.7) | #51, #58 |
| `PermissionMount` (`web/kernel/mount-policy.js`) | in-memory permission overlay for providers | filesystem-owned metadata stores (§2.5) | #49 |
| Init lease (`web/kernel/init.js`, `login-boot.js`) | which tab runs init; page-driven startup | each instance's own PID 1 and service manager | #56, #57 |
| In-page shell (`crates/frontend/src/shell.rs` and `shell/`) | the interactive shell | a shell executable on a PTY, started by the terminal | #62 |
| `desktop.rs` (`crates/frontend/src/desktop.rs`) | window management in the page | the compositor and desktop-shell processes | #61 |
| Built-in apps (Files, Mounts, Editor, Preview) | page components | ordinary GUI processes | #63, #64 |
| In-kernel export dispatcher (`web/kernel/mount-sharing.js`) | serving exports | an ordinary export service | #59 |

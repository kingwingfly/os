# Architecture contract (v2)

This is the decision record for the [#44](https://github.com/kingwingfly/os/issues/44) refactor, originally written in L0b ([#47](https://github.com/kingwingfly/os/issues/47), [PR #69](https://github.com/kingwingfly/os/pull/69)) and amended to **Contract v2** in L0c ([#76](https://github.com/kingwingfly/os/issues/76)) following the post-L2 architecture roundtable and owner design alignment ([#75](https://github.com/kingwingfly/os/issues/75)). It settles what L1–L6 (#48–#65), Wave L2.5 (#77–#81), and Phases 9–10 (#82–#87) build. L0c changes no runtime behaviour; the only code it updates is contract versions, `FsType`, capability/durability/writer-model types, ioctl constants, and `ENOTBLK` in `crates/abi` (with compile-preserving updates in workspace crates).

**Status: authoritative.** The owner approved Contract v1 on 2026-11-14 ([PR #69](https://github.com/kingwingfly/os/pull/69); §2.12 stated directly by the owner) and finalized every Contract v2 design branch on [#75](https://github.com/kingwingfly/os/issues/75) ahead of L0c (#76). Where any sub-issue (#48–#65, #77–#87) differs from this document, this document wins.

"Today" statements describe `dev` at `339a76d9` (after Wave 1 L1 [PR #73](https://github.com/kingwingfly/os/pull/73) and Wave 2 L2 [PR #74](https://github.com/kingwingfly/os/pull/74)) and cite the code. Measured differences from Linux come from the L0a baseline ([`docs/compat/matrix.md`](../compat/matrix.md)).

## Contents

1. [Definitions and evidence](#1-definitions-and-evidence)
2. [Decisions](#2-decisions)
   - [2.15 Storage substrate (`os-cowfs` v1) and two-stage offline boot](#215-storage-substrate-os-cowfs-v1-and-two-stage-offline-boot-decided)
   - [2.16 Virtual hardware, portable Wasm/WASIX container runtime, and cluster boundaries](#216-virtual-hardware-portable-wasmwasix-container-runtime-and-cluster-boundaries-decided-phase-910-reserved)
3. [Filesystem capability profiles](#3-filesystem-capability-profiles)
4. [Mounts and namespaces](#4-mounts-and-namespaces)
5. [New calls: flags and errors](#5-new-calls-flags-and-errors)
6. [Versioned boundaries](#6-versioned-boundaries)
7. [Replacement table](#7-replacement-table)

## 1. Definitions and evidence

| Term | Meaning |
| --- | --- |
| **Instance** | One running OS: one kernel, one boot, its own PID 1, PID space, `/proc`, `/run`, `/tmp`, mount namespaces, local root volume, and service lifecycle. It begins at boot and ends at shutdown or when its execution host goes away. Its boot/instance identifier is created locally and randomly per boot with zero remote requests. |
| **Execution host** | What runs an instance: a browser tab's dedicated kernel Worker (`browser`), a native Wasmtime host process (`os-native`), or `os-native` packaged in a Linux OCI container (`container`). One execution host runs one instance; a physical machine may run several execution hosts, each with its own instance. |
| **Browser profile** | One browser's same-origin storage (OPFS, IndexedDB, Cache Storage, Web Locks) and cookies. Every tab of a profile is a separate instance, sharing profile-local storage and volume locks. |
| **Boot profile** | Persisted local boot configuration (`{release_generation, root: volume:<uuid> \| snapshot:<digest> \| ephemeral, options}` in browser profile IndexedDB or native `$STATE/boot.json`) selecting the signed offline release generation and root volume/mode without any network request. |
| **Account** | A **100% local OS user** stored in the instance's root volume (`/etc/passwd`, `/etc/group`, `/etc/shadow`): numeric uid, primary and supplementary groups, home directory, shell, and local password hash. Local OS accounts are completely decoupled from remote cloud accounts and carry no cross-instance UID mapping. |
| **Cloud service credential** | An explicit userspace token or grant acquired from a remote cloud or cluster service (analogous to `docker login`, `gcloud auth login`, or `kubeconfig`), stored per local user and presented only to remote services (remote volumes, OCI registry, optional `/mnt/cloud`, remote devices, or `ClusterState`). Completely decoupled from `/etc/passwd`: local accounts imply no remote credential, and remote credentials never rewrite local UIDs. |
| **Login session** | One local account's session inside one instance: a session leader process, its PTY or seat, its mount namespace, and any explicit cloud service credentials that user has loaded. A login in another tab is another session in another instance. |
| **Seat** | Where a login session's input and output are: a local terminal (PTY), a graphical display with its input devices, or (reserved for Phase 9, #82) an authenticated remote seat/PTY attached to a hosted `os-native` instance. |
| **Mount namespace** | A process's set of mounts. Processes share or copy it; it never spans instances. |
| **App window** | A surface a process shows through the compositor. It belongs to one process in one instance; it is not a session or an instance. |
| **Volume** | A mutable `os-cowfs` CoW filesystem head pointing to a content-addressed Merkle B+tree root digest, stored locally (browser IndexedDB + OPFS or native SQLite + packs) or remotely (R2 + Storage Durable Object, #80, or another `HeadStore`/`PackStore` backend). |
| **Snapshot** | A named, pinned, immutable root digest of a volume's tree. Taking a snapshot is O(1) and copies zero data bytes. |
| **Fork** | A new volume (with a fresh volume UUID and `FsId`) whose initial head is an existing volume's last committed head or a snapshot's root digest. O(1) within a store; lazy-fetched across stores. |
| **Node** | An instance enrolled into an optional cluster via its opt-in userspace `kubelet` service (#84), holding a revocable node credential bound to a monotonic `node_generation` lease. |
| **Sandbox instance** | An isolated child OS instance (dedicated child kernel, PID 1, PID space, and O(1) forked `cowfs` rootfs with zero inherited host or account descriptors) spawned by `kubelet` (#84) to run one Wasm/WASIX OCI container pod. |

**Evidence a remote service accepts.** A remote service acts **only** on an explicit cloud service credential (or revocable node credential) that it issued and verifies for the operation and resource requested. None of the other terms is a credential: an instance id, boot id, host id, PID, session number, seat, window, pathname, mount name, image digest, volume UUID, root digest, snapshot name, lease, fence, epoch, node id, or local uid grants nothing on its own. A filesystem handle (§2.3) only names an object; the cloud service credential presented with it is what is checked. **Local `uid 0` genuinely owns its instance and its local root volume, and never confers remote administrator authority.**

## 2. Decisions

### 2.1 What an instance is (Decided, amended in L0c)

**Today (`dev` `339a76d9`).**
- **Client VFS, cloud root.** `os_vfs::Vfs` owns the client mount table and per-session mount namespaces, but `construct_vfs` still mounts `RootCloudDriver` (`FsType::Cloud`) at `/` alongside read-only `ImageFs` at `/usr` (`crates/client-kernel/src/vfs_engine.rs`).
- **One process space per browser login.** All tabs of one browser login still share one PID space in the `Machine` Durable Object (`crates/worker/src/procs.rs`) and one init lease (`web/kernel/init.js`), so cross-tab `ps` and `kill` remain active until #54 and #56.
- **One kernel Worker per tab.** Each tab runs its own dedicated kernel Worker (`web/kernel/protocol.js` `kernelPort()`, `web/kernel/client.js`), which owns that tab's process Workers and shared-memory pipes.

**Decision.**
- **One execution host, one instance.** An instance is one execution host (one browser tab's dedicated kernel Worker, one `os-native` process, or one container), with its own locally generated random boot id, PID 1, PIDs, `/proc`, `/run`, `/tmp`, and mount namespaces.
- **Zero-network standalone boot.** An installed release boots offline to a usable local console with **zero outbound network requests** (§2.15). No bootstrap credential exists or is needed. Registration with a remote service happens only on explicit post-boot remote attachment (remote volume, optional `/mnt/cloud`, remote device, or opt-in `kubelet` enrollment), binding the boot id solely for attachment and fencing.
- **Zero-friction first boot & Cloud/Cluster Sign-In.** Default first boot auto-enters a default local user (`uid 1000` in group `wheel` with passwordless `sudo`, or local `root` via boot config) with no login wall. The top-bar account button becomes a **Cloud / Cluster Sign-In panel** (analogous to `docker login` / `gcloud auth`) that acquires and stores explicit cloud service credentials for optional remote services; it is never required to boot or use the OS locally.
- **Clean 3-way separation of root, optional `CloudFs`, and shared hosted machine:**
  1. **Default boot (local `cowfs` root):** `/` is a locally owned MIT pure-Rust `os-cowfs` root volume chosen by the persisted boot profile (or an explicitly chosen snapshot or ephemeral root). `#56` strictly waits for `#77` (`L2.5a`) and `#78` (`L2.5b`) with no volatile-root merge flag (`MemoryHeadStore` is test-only).
  2. **Optional `CloudFs`:** `FsType::Cloud` is retained feature-frozen as an optional remote filesystem driver (`mount -t cloud /mnt/cloud`, or explicit `chroot` / opt-in NFS-root) authenticated with an explicit cloud service credential; it is **not** deleted in `#65`.
  3. **"One shared machine":** Multiple clients intentionally sharing one live OS (shared files, PIDs, services, and devices) is solved in Phase 9 via authenticated **remote seat/PTY attach** to a hosted `os-native`/Container instance (`#82`), rather than conflating shared storage with a shared kernel. `contract.rs` reserves `InstanceIdentity` for this.
- **Concurrent browser tabs.** A second tab is a second instance: cross-tab `ps` and `kill` end, and a tab's processes are invisible to other tabs. When a second tab opens while the default boot profile's volume Web Lock (`os-vol:<uuid>`) is held by Tab 1, Tab 2 automatically boots an **O(1) persistent fork** of Tab 1's last committed head (recorded in `/run/os/root` and announced on console). On clean shutdown, an unmodified fork (zero commits beyond its base) is auto-pruned; a modified fork is kept and offered in the boot chooser so no data is silently lost. Explicit `excl` mode returns `EBUSY` into the Stage 1 recovery chooser.
- **Lifetime.** Closing or reloading a tab (or stopping an `os-native`/container host) ends its instance, releasing its volume locks and ephemeral state as host loss ends a machine's processes.

**Implemented by** #54 (process table and `/proc` in the instance), #77 (`L2.5a` local `os-cowfs`), #78 (`L2.5b` offline Release v2), #56 (Stage 1 → Stage 2 `switch_root` boot, PID 1), #57 (service manager, local accounts, Cloud/Cluster Sign-In), #82 (Phase 9.0 `os-native` and remote seat/PTY attach).

### 2.2 Where kernel code lives (Decided)

**Today.**
- **Portable Rust VFS & policy crates:** `crates/vfs` (`os-vfs`), `crates/core`, and `crates/kernel` hold the portable VFS, mount table, component walk, namespace, `FsContext`, and permission rules.
- **Client kernel crate:** `crates/client-kernel` holds the `wasm-bindgen` glue, browser VFS engine, process host coordination, and private-extension validation.
- **JavaScript host adapters:** `web/kernel/` provides browser storage, IndexedDB, OPFS, Web Locks, helper transport, Worker spawning, and page protocol glue.

**Decision.**
- **Portable Rust crates.** Kernel semantics live in Rust crates with no DOM, `web-sys` or `wasm-bindgen` types, so `os-native` and a headless test host run the exact same code. That covers VFS objects, `os-cowtree`/`os-cowfs`, the mount table, path walk, process filesystem context, procfs, local sockets, and the process table.
- **Thin glue.** `crates/client-kernel` remains the thin `wasm-bindgen` glue.
- **JavaScript is host adapters only:** browser file and directory handles, OPFS, IndexedDB, Cache Storage, Web Locks, the helper connection, transports (MessagePort, WebRTC, WebTransport, relay), Worker spawning, and the page protocol. Adapters perform I/O and report results; they make no permission or path decisions.

**Implemented by** #48, #51 (done), #77 (`os-cowtree`/`os-cowfs`), #54 (process table), #55 (sockets).

### 2.3 The remote filesystem protocol (Decided, amended in L0c)

**Today (`dev` `339a76d9`).**
- L1 (#48–#50) and L2 (#51–#53) implemented `/api/fs` v2 handles and `/api/fs/data` streaming on `OsAuthority` (`crates/worker/src/cloudfs.rs`, `cloud_data.rs`), client-side `os-vfs` component walk (`crates/vfs/src/walk.rs`), and refused v1 path calls on `/api/sys` for ordinary non-job process tokens.
- `RootCloudDriver` still backs `/` until #56 switches `/` to local `cowfs`.

**Decision.**
- **Scope.** Remote filesystem handle protocol v2 serves the **optional, feature-frozen `cloud` (`FsType::Cloud`) shared tree** (normally mounted at `/mnt/cloud`, or explicitly used for a `chroot` / opt-in NFS-root) and **`sharefs` exports**. It is removed from default `/` boot in #56 and retained (not deleted in #65) for workloads that need server-enforced per-file ACLs, retained opens, cross-client locks, and atomic append across instances. Every request is authenticated with an explicit **cloud service credential** (§2.4), never local `/etc/passwd` UIDs.
- **Volumes use the Volume protocol (§2.15).** Local and remote `os-cowfs` volumes use the pluggable `HeadStore`/`PackStore` object-graph model (§2.15) with single fenced RW writer + unlimited concurrent RO pinned readers + O(1) forks.
- **Distinct multi-writer (`RWX`) cloud filesystem tier.** Any future scalable multi-writer (`RWX`) transactional cloud filesystem is explicitly a **separate filesystem driver/tier**, NOT `cowfs v2`.
- **Handles.** Version 2 addresses objects by handle: an opaque, server-issued value naming `(filesystem id, inode, generation)`.
  - A handle is bound to the **instance** that obtained it, not to one credential. Any valid cloud service credential that instance holds may present it, as on Linux where a cwd or an open file passes across credential transitions and `SCM_RIGHTS`.
  - A handle from another instance, or a forged one, fails with `EACCES`.
  - A handle whose inode is gone, or whose generation has changed, fails with `ESTALE`.
- **One credential per request.** Every request names the explicit cloud service credential acting, and the server checks that credential.
- **Name operations:**
  - `lookup(dir, name)`;
  - `walk(dir, names)`: resolves several components within this one filesystem in one round trip. Each name is a single component and never `.` or `..` (`EINVAL` otherwise). It stops at the first symlink, missing name or non-directory, and returns how far it got. The client never passes a name beyond its own next mount point: it splits a path at its mount points and resolves `..`, symlinks and mount crossings itself, against its mount table and process root, so `..` can never escape a `chroot` through the server;
  - `parent(dir)`: the directory's parent and its name there, within this filesystem (at the filesystem's root it says so). The client resolves `..` with it inside a filesystem, and with its own mount table at mount roots and process roots. `getcwd` is built from it, so a cwd renamed by another instance still resolves `..` and reports its current path;
  - `create(dir, name, mode, options)`: creates and opens in one call, returning the new handle and an open reference with the requested access, whatever the new file's mode, as Linux gives the creator. `options` carry the access, `O_EXCL` and `O_TRUNC`. With `O_EXCL` it fails with `EEXIST` if the name exists, so no other instance can slip in between. Without it, an existing file is opened, and with `O_TRUNC` emptied, in the same call;
  - `mkdir`, `mknod`, `symlink`, `readlink`, `link(handle, dir, name)`, `unlink(dir, name)`, `rmdir(dir, name)`, `rename(dir, name, dir, name, flags)`.
- **Attributes:** `getattr`, `setattr` (mode, owner, times, size), `readdir`, `getxattr`/`setxattr`/`listxattr`/`removexattr`, `statfs`.
- **Open files:**
  - `open(handle, options)` returns an **open reference**. The server records it, as the `fds` table does today. The options carry the access and `O_TRUNC`; truncation asks for write permission even with read-only access and empties the regular file in the same call.
  - `access` is read, write, read-write, **exec**, or **path**. Exec is checked against execute permission, not read, and its bytes serve only the loader, so execute-only images keep running (`crates/kernel/src/lib.rs`, the X rule). Path (`O_PATH`) asks no permission of the object and grants no access to it.
  - **An open reference keeps its object alive; a handle does not.** A process holds a path open reference for its working directory and its root, and the mount table one for each mount point. So a working directory removed by someone else stays usable as on Linux: `stat(".")` works, and `getcwd`, `readdir` and new names give `ENOENT`.
  - `open_metadata(open)` (fstat, also used by `SEEK_END`), `read(open, offset, length)`, `write(open, offset, data)`, `truncate(open, size)`, `fsync(open, datasync)` and `release(open)` act on it. Descriptor metadata authenticates the current caller and validates the retained open, including for path-only references.
  - **Append is a write position, not an access.** A write names an offset or the end of the file. The driver places a write at the end atomically, at the end as it is when the write lands, and returns where it went, so appends from several processes or instances never overwrite each other. `O_APPEND` set or cleared with `fcntl(F_SETFL)` applies from the next write.
  - `lock(open, family, kind, range)` waits until the lock is granted (`F_SETLKW`, `flock` without `LOCK_NB`). The waiter is queued by the lock keeper, giving up the wait cancels it, and an `fcntl` wait that would deadlock fails with `EDEADLK` (`flock` does not detect deadlock, as on Linux). `try_lock` with the same arguments fails at once with `EAGAIN` (`F_SETLK`, `LOCK_NB`). `unlock(open, family, range)` and `test_lock(open, kind, range)` (`F_GETLK`) complete the set.
  - Locks come in two families that never conflict with each other, as on Linux: `flock` locks cover the whole file and need any access but path; `fcntl` byte-range locks need read access to be shared and write access to be exclusive (`EBADF` otherwise). The cloud authority keeps both per inode, owned by open references and released with them, so every instance sees them (§3).
  - An open reference records the opening grant, as Linux records an open file's credential. Ordinary exec retains that grant under the process's active cloud service credential, and forked holders retain theirs independently. Revoking the last retaining credential ends the open reference; later operations on it fail with `EACCES`. Every request also authenticates the current acting credential.
  - **Execute-only is local policy.** Exec access sends the bytes to the client's loader, so a client that may execute a file can read it. The server still refuses exec access without execute permission, but it promises no confidentiality of executable bytes.
- **When permission is checked, as on Linux:**
  - `lookup` and `walk` check search permission on each directory they pass.
  - `open` checks the requested access once.
  - `read`, `write` and `truncate` through an open reference check only the access granted at open (and that its credential is still valid). A file created read-only can still be written and truncated through the descriptor that created it, as `tar` relies on.
  - Every other operation (`setattr`, `link`, `unlink`, xattrs) checks the presenting credential when it is made.
- **Content lifetime.** An unlinked file's content lives until its last open reference is released. Open references belong to the instance's **session** with the service: a lease renewed while the instance is connected, and a resume secret the service issues at connect.
  - A reconnect within the lease (two minutes) that presents the secret keeps every open reference and lock, so a network drop or a deployment loses nothing.
  - When the lease expires because the host vanished, the service releases them, so content is neither leaked nor collected under a reader.
  - AGENT.md's garbage-collection rule ("respect open references") applies to these references.
- **Path calls go away.** Version 1 path calls are removed once nothing in the repository uses them. No compatibility window is kept (§2.12).

**Implemented by** #48, #50, #51 (done); demoted out of `/` by #56 and mounted optionally at `/mnt/cloud` in #57.

### 2.4 Who is trusted for what (Decided, amended in L0c)

**Today (`dev` `339a76d9`).**
- Local mount permissions execute in `os-vfs`, while process registration, login, `sudo`, and account management still route through `Machine` and `OsAuthority` (`crates/worker/src/creds.rs`, `api.rs`, `procs.rs`) until #54 and #57.
- `setuid` and `setgid` bits are descriptive and do not elevate (`crates/kernel/src/lib.rs`).

**Decision.**
- **100% local OS accounts.** Each instance's root volume owns its own `/etc/passwd`, `/etc/group`, and `/etc/shadow`. `login`, `su`, `sudo`, `passwd`, `useradd`, `usermod`, `userdel`, `groupadd`, `groupmod`, `groupdel`, and `newgrp` are **100% local OS operations** requiring **zero remote RPCs**. There is **no** OS-level cloud account federation, **no** `/etc/os/principals` mapping table, **no** external-subject UID mapping, and **no** NFSv4 idmapping.
- **Local policy, local enforcement.** Local `uid 0` genuinely owns its instance and its local root volume (`/`). Local policy isolates one local user's processes and local resources from another local user's inside one instance. Because the client kernel runs on the host owner's browser or machine, local policy is not a security boundary against the host owner and is documented as such.
- **Explicit cloud service credentials.** Remote services (remote `cowfs` volumes, OCI registry, optional `/mnt/cloud`, `/dev/accel`, `/dev/archive`, `/dev/media`, `/dev/snd`, `ClusterState`, `netd`) authorize **solely** on explicit userspace cloud service credentials (or revocable node credentials) acquired through the Cloud/Cluster Sign-In panel or CLI tools (`Boundary::ServiceAuth` v2) and stored per local user (analogous to `docker login`, `gcloud auth`, or `kubeconfig`). Nothing local is taken on trust: a modified kernel gains no remote right beyond what its valid service credentials allow, and local `uid 0` never synthesizes remote root. (An executable read over a remote filesystem still sends bytes to the client's loader, §2.3.)
- **No remote request needed** for boot, `fork`, `exit`, `wait`, `kill` within the instance, signals, pipes, process groups, sessions, local sockets, local `login`/`su`/`sudo`/`passwd`/`newgrp`/`useradd`, local `cowfs` volumes/snapshots/forks/`mkfs`, local mounts of local filesystems, local devices, and `tmpfs`.
- **A remote request is needed only to:**
  - acquire, renew, scope/attenuate, or revoke an explicit cloud service credential (`Boundary::ServiceAuth` v2) or enroll an opt-in `kubelet` node (#84);
  - attach or open a remote resource on first use (remote volume lease, `/mnt/cloud` session, OCI registry pull/push, remote device attachment, `ClusterState` watch/lease, remote task);
  - execute every remote operation thereafter, each checked against the presented service credential.
- **Credential flow:**

| Local event | Local effect | Cloud service credential of the resulting process |
| --- | --- | --- |
| Default first boot | Auto-enters default local user (`uid 1000` in `wheel` with passwordless `sudo`, or local `root` via boot config) | None (zero remote requests at boot) |
| Local `login`, `su`, `passwd`, `useradd`, `newgrp` | Local check/update against `/etc/{passwd,group,shadow}` | None unless that local user has explicitly signed in to a cloud service |
| Cloud / Cluster Sign-In (top-bar panel or CLI) | None (never changes local `uid`, `gid`, or `/etc/passwd`) | Acquires explicit scoped cloud service credential(s) stored for that local user |
| Local `sudo` / `su` to `root` (elevation) | Local policy (`wheel` in local `/etc/group`; `setuid`/`setgid` file bits remain non-elevating) | **Never escalates remote authority.** Retains at most the invoker's existing cloud service credential (or none); local `uid 0` never synthesizes remote root |
| Privilege drop (`setuid`, `setgid`, `setgroups`, `su <user>` from `root`) | Switches to lower local `uid`/`gid` | **Clears inherited ambient remote credentials** before the process resumes, unless an explicitly scoped credential is passed (e.g., via unit config or explicit file/fd handoff) |
| Remote admin / elevated cloud action | None (local `uid 0` is irrelevant) | Requires an explicit cloud service credential authorized for that remote role by the remote service |
| Cloud service credential revoked or remote account locked | Local processes keep running under their local `uid` unaffected | Every remote call fails at once with `EACCES` (notified over the service event line when connected) |

- **Fork and exec.** A forked child or plain `exec` within the same local identity keeps its process's explicit cloud service credential handles with no network request; privilege drops clear ambient remote credentials as above.
- **Credential lifetime.** A valid cloud service credential held by running processes remains usable until it expires or is revoked by the remote service. Local cloud sign-out removes stored credentials for new processes without terminating running local processes; server-side revocation invalidates active credentials immediately (`EACCES`), while local processes continue unaffected.
- **Whole-volume disclosure rule.** A remote `cowfs` volume grant discloses the entire volume's objects and bytes, including files whose local mode is `0600`. Where per-file server-enforced ACLs between different cloud users are required, use optional `/mnt/cloud` (`FsType::Cloud`) or `sharefs` exports.
- **Accounting.**
  - Remote accounting stays remote: storage quota, filesystem byte transfers (today's `io.max`), containers/accelerators, relay bandwidth, tasks, and rate limits. Each remote service enforces its limits per cloud service credential, whatever the client claims.
  - Local `pids.max`, `memory.max`, and the local process count are instance-local policy, enforced by the kernel and documented as bypassable by the host owner.
  - #44's "without losing denial or resource-accounting guarantees" therefore holds for every remote resource, and holds locally against other local users' processes, not against the host owner.

**Implemented by** #54 (local process authority and remote admission), #57 (local accounts, sessions, and Cloud/Cluster Sign-In), #59 (exports).

### 2.5 Filesystem identity and metadata, per driver (Decided, amended in L0c)

| Driver | Filesystem identity | Inode identity | Where OS metadata lives |
| --- | --- | --- | --- |
| Local CoW volume (`cowfs`) | Volume UUID (`profile-local` in browser, `host-local` on native). A fork gets a new UUID. | `(subvol, ino, generation)` stored in the Merkle B+tree. Forks preserve inos under their new volume UUID, as btrfs snapshots do. | Inside the `cowfs` B+tree (`mode`, `uid`, `gid`, times, POSIX ACLs, xattrs, symlinks, hard links, orphan list) |
| Remote CoW volume (`cowfs`, #80) | Volume UUID (`global`) | `(subvol, ino, generation)` in the tree | Inside the `cowfs` B+tree |
| Snapshot / RO pinned view (`cowfs`) | `(volume UUID, root digest)` (`global` / content-addressed) | Same `(subvol, ino, generation)` as source, read-only | Inside the immutable `cowfs` B+tree |
| Cloud tree (`OsAuthority`, optional `/mnt/cloud`) | the authority's filesystem id (`global`) | its inode ids, with a generation | the authority's tables |
| Browser storage (`os-workspace` in OPFS) | a UUID minted once per profile | ids minted by the metadata store | a metadata store beside the tree, in the profile's IndexedDB |
| Host folder (browser directory handle) | a UUID minted at first attach, kept with the handle in IndexedDB and matched with `isSameEntry` | ids minted by the metadata store, keyed by path plus a fingerprint (size and modification time at the OS's last write) | the profile's IndexedDB, keyed by the UUID |
| Host folder (Linux helper) | a UUID the helper mints for its root folder and keeps in its own state | `(device, st_ino, birth time stx_btime or generation FS_IOC_GETVERSION)`. The device is the helper's stable name for each filesystem under the folder: the folder-relative path of that filesystem's topmost directory, which the helper records. It distinguishes mounts, btrfs subvolumes and snapshots under the folder, and survives `st_dev` renumbering after a reboot or re-plug. | the helper's own state directory, keyed by the folder UUID and inode identity |
| Shared mount (export) | the publisher's | the publisher's | the publisher's, passed through |

**Shared by every tab of a profile.** OPFS and IndexedDB belong to the browser profile, and every tab of it is a separate instance (§2.1):
- **For `cowfs` local volumes (§2.15):** immutable data packs are written once to OPFS (`FileSystemSyncAccessHandle` `flush()` + `close()`) and never mutated in place—so concurrent cross-tab fork reads use `getFile().slice()` without exclusive handle contention—while tree nodes, pack indexes, and volume heads commit in one `{durability: "strict"}` IndexedDB transaction gated by Web Lock `os-vol:<uuid>` and `local_fence`.
- **For `os-workspace` and directory-handle folders:** the metadata store, open references and whole-file locks are profile-wide:
  - **Metadata** is written in IndexedDB transactions.
  - **Open references** are registered under Web Locks, which every same-origin tab shares. Unlink-at-last-close counts every tab's opens, and a tab's references go when it closes. A tab that crashes releases its Web Locks too, so each tab sweeps, as it starts, unlinked entries whose references are no longer held.
  - **Minting** a folder's UUID happens under a Web Lock, so two tabs attaching one folder agree on one identity.

**Never wider than the host (host folders and browser storage).**
- **Bounded by the host grant.** Metadata never grants more than the host grant: the browser permission, or the helper's `--write`/`--execute` ceiling.
- **Changes outside the OS reset metadata.** A file whose identity no longer matches its metadata loses it and gets the folder's private defaults (owner the attaching account, no ACL): a helper inode reused after a deletion, or a directory-handle file renamed, replaced or changed outside the OS.
  - On the helper this is exact, so a file never inherits a previous file's grants.
  - On a directory-handle folder it is a declared limit. The API exposes nothing stronger than path, size and modification time, so a file replaced outside the OS with the same size and modification time (`cp -p`, `rsync -a`) keeps the previous file's metadata. The folder's owner made both files; no other account can cause it.
- **No sidecar files.** Nothing is written into the user's folder.
- **Profile-local.** A directory-handle folder's identity and metadata are stable only within one browser profile.

**Implemented by** #48, #49 (done), #77 (`L2.5a` local `cowfs`), #80 (`L2.5d` remote `cowfs`).

### 2.6 Filesystem capability profiles (Decided)

Every later gate is read against the table in [§3](#3-filesystem-capability-profiles). A capability a driver lacks either refuses the operation with the errno the table names, or lets it succeed and fails later access with the named errno, as the table says. It never fakes success.

### 2.7 Mounts and namespaces (Decided, amended in L0c)

- **Private propagation only.** `MS_SHARED`, `MS_SLAVE` and `MS_UNBINDABLE` are rejected with `EINVAL`. A new namespace copies the mounts of the one it comes from.
- **Supported:** bind mounts (with `MS_REC`), `MS_RDONLY`, `MS_NOEXEC`, `MS_NOSUID`, `MS_NODEV`, `MS_SYNCHRONOUS`, `MS_DIRSYNC`, `MS_NOSYMFOLLOW`, the atime flags, `MS_REMOUNT` of those flags, `MS_MOVE` (for the root switch), unmount, lazy detach and root's forced unmount. `MS_SILENT`, `MS_POSIXACL`, `MS_I_VERSION` and the `MS_MGC_VAL` magic are accepted and ignored, as Linux does.
- **Filesystem types** (11 canonical types): `cloud`, **`cowfs`**, `opfs`, `hostfs`, `helperfs`, `sharefs`, `image`, `tmpfs`, `proc`, `devtmpfs`, `devpts`.
  - `cowfs` is the MIT pure-Rust Merkle CoW B+tree filesystem for default `/` root volumes and local/remote data/snapshot mounts (§2.15).
  - `cloud` is an optional, explicitly attached **system** mount (normally `/mnt/cloud`, or explicit `chroot` / opt-in NFS-root). Because every request carries the caller's explicit cloud service credential (§2.3, §2.4), one system attachment serves local users who hold a valid cloud service credential without applying the single-owner user-mount ceiling, while callers without a valid credential fail with `EACCES`/`ENOTCONN`.
  - `image` serves read-only signed system compositions (`/usr`) and private extensions (`/opt/private/NAME`).
  - Early init builds `/dev` from `devtmpfs` and `devpts`. There is no `sysfs` (`ENODEV`), and any unknown filesystem type returns `ENODEV`.
- **Two-stage boot mount layouts.** Boot transitions from Stage 1 (`initramfs`) to Stage 2 (`switch_root` into local `cowfs` `/sysroot`) as specified in §2.15 and §5.
- **`mkfs` vs directory trees (`ENOTBLK`).** `mkfs.cowfs` applies only to an exclusively held, unmounted volume or block device (`/dev/vdN` or volume target). It refuses mounted or leased targets (`EBUSY`), existing formatted volumes without `-f` (`EEXIST`), and directory, host-folder, browser-storage, or export tree sources (**`ENOTBLK`**). Mounting a tree never formats it.
- **Who may mount.**
  - Instance root may mount anything (including `cowfs`, `cloud`, `tmpfs`, `proc`, `devtmpfs`, `devpts`).
  - An ordinary user may mount a filesystem it has an explicit grant for (`opfs`, `hostfs`, `helperfs`, `sharefs`, private `image`) on a directory it owns; requests to mount `cowfs` volumes/snapshots from unprivileged UI/CLI go through the `#58` mount service.
  - The mount service creates the user's mount-point directories under `/mnt/local`, `/mnt/shared` and `/opt/private`, owned by that user, in the instance's tmpfs. So the Mounts app's `/mnt/local/NAME`, `/mnt/shared/NAME` and `/opt/private/NAME` keep working.
  - `nosuid` and `nodev` are forced on user mounts, and an ordinary user's remount cannot clear them (`EPERM`).
  - A user mount is usable only by its user, not even by instance root, as FUSE does without `allow_other`. That keeps root's services and tools out of user-controlled trees with hostile symlinks or stalled providers. Sharing with other users goes through exports (#59).
  - Bind mounts, remounts of mounts you did not make, and `MS_MOVE` need instance root.
- **Errors** for busy unmount, lazy detach, export revocation, provider loss, writer contention, and fencing are in [§4](#4-mounts-and-namespaces).

**Implemented by** #51, #52 (done), #77 (`L2.5a`), #56 (`switch_root`), #58 (mount service, tools, and Mounts app).

### 2.8 Local IPC (Decided)

**Today.** The only IPC is the pipe. A service's readiness is a line on an inherited pipe (`crates/services/src/notify.rs`), and nothing lets one process serve another.

**Decision.**
- **Unix-domain sockets.** `AF_UNIX` `SOCK_STREAM` sockets bound to paths in the instance's VFS, normally under `/run`.
- **Peer credentials.** `SO_PEERCRED` is taken from the kernel's process table, never from the peer.
- **Descriptor passing.** `SCM_RIGHTS` passes descriptors, with their open descriptions and rights, including remote open references (§2.3) between users of the same instance.
- **Unsupported for now:** `SOCK_SEQPACKET` and abstract names are not required; the step adds them only if a user needs them.
- **Not network sockets.** Network sockets remain staged in Phase 10 (§2.16: `#86` `netd` outbound stream gateway over `AF_UNIX`, then `#87` `/dev/net/tun` L3 overlay). Userspace `kubelet` (#84) and device-attachment units (#57) also consume `AF_UNIX` + `SCM_RIGHTS`.

**Implemented by** #55.

### 2.9 GUI surfaces (Decided)

**GUI v1 is active on seat 0 (`L5a` #60 & `L5b` #61).** On `/`, the default graphical session activates `graphical.target` to run supervised `compositor.service` (system PID 1, `devices = ["display", "input"]`, `RestartPolicy::Never`) and `desktop-shell.service` (per-user `init --user`, `mount_namespace = "session"`, `RestartPolicy::OnFailure`), plus on-demand root `greeter.service` (no device grants). Terminal-only sessions (`/shell.html`, `/console.html`, `multi-user.target`) start neither `compositor` nor `desktop-shell`. Open `/gui-session.html` to run the standalone reference document and pixel clients. Each client owns a PID and an AF_UNIX connection to `/run/gui/seat0.sock`. `crates/frontend/src/desktop.rs` is slimmed to a thin `COMPAT-BRIDGE (#61)` forwarding compat app window events to `compositor` and projecting `DisplayCmd`s until built-in apps migrate in `#63`–`#65`.

The compositor opens `/dev/display` for writing and `/dev/input` for reading. Both character devices are local, root-owned and mode `0600`. An ordinary open returns `EACCES`. Root also needs explicit `grant.devices` for each device or receives `EPERM`, and `reexec` strips `display`/`input` grants from any image other than verified `/usr/bin/compositor`. A second open of a claimed device, or an attempt to split the seat across processes, returns `EBUSY`. `O_PATH` permits inspection. Last display close or compositor death resets the seat (`SeatReset`), releases bindings, retires the old surface IDs, and ends only the graphical session while `init`, `mountd`, `exportd`, and non-graphical processes continue running. Suspend cancels gestures and preserves mapped surfaces.

Each endpoint negotiates once with `Hello { versions, required }`. A negotiation refusal sends an error and closes the endpoint. GUI v1 uses a four-byte little-endian length and a bounded UTF-8 JSON payload. Version and capability refusals are `EPROTONOSUPPORT` and `EOPNOTSUPP`. The server reads `SO_PEERCRED` at accept, calls `ioctl(display_fd, gui_ioctl::PEER_ROLES, socket_fd)` (`0x4755_000c`) so the kernel grants per-image role capabilities (`desktop-shell.service` -> `Panel`/`Background`/`Launcher`; `greeter.service` -> `Lock`/`Greeter`; `gui_compat_proxy` -> `Window` compat apps only; ordinary or manually launched processes -> `Window` non-host only), binds each surface to that socket endpoint, and routes replies, descriptors and rendering resources to its owner. A cross-owner request returns `EACCES`. Unauthorized role, shell RPC, or `SurfaceKind::Host` requests return `EPERM`. `desktop-shell` persists per-display window layout atomically to `~/.config/os/desktop-layout.json` (`version = 1`, resetting older schemas and refusing to overwrite newer schemas per §2.12, converting legacy `localStorage['os-desktop']` once). Socket and device traffic use the existing syscall ABI.

**1. Move and resize.** A trusted pointer press on the titlebar or one of eight resize edges sends one `PointerDown`. For an active seat and eligible window the compositor replies with a single-use `DragLease` in `BeginInteractiveOp`. It identifies the surface, initiating pointer, original rectangle, operation, work area, size limits, eligible snap zones and expiry. An edge resize keeps the opposite edge fixed. The browser captures the pointer, applies geometry on local animation frames, and previews top maximize or left/right tiling. Progress travels at most once per 100 ms and renews the 30-second lease. Release commits once. Escape, pointer cancellation, a modal, suspend, expiry or owner exit cancels the operation. The compositor validates the lease, clamps the final rectangle, configures the owning client, and retires the lease. Revocation restores the last committed geometry.

**2. Window decorations.** Both surface kinds receive the same compositor-specified titlebar, focus ring, minimize, maximize/restore and close controls. The eight handles follow the resizable flag. Clients may request a title, size limits or a window state. Titles discard control characters and allow at most 128 characters. Close sends `CloseRequested`. Shell and security roles are chromeless.

**3. Document isolation.** A client supplies a bundle path plus the expected SHA-256, optionally passing a read-only file via `SCM_RIGHTS`. Path sources open with `O_RDONLY | O_NOFOLLOW` inside the system GUI tree. The compositor requires a regular readable file, enforces the 2 MiB limit and hashes its exact bytes independently. A digest mismatch returns `EIO`. The display command carries verified HTML, CSS, JS and the content, script and style digests.

The browser rechecks the script and style and builds an offline `srcdoc` under `sandbox="allow-scripts"` with a unique opaque origin. CSP pins the bootstrap, application script and style. It sets `default-src`, `connect-src`, `form-action`, `base-uri`, `object-src` and `frame-src` to `'none'`. Browser clipboard and sensor permissions are denied. The frame cannot access the parent DOM, its cookies, storage, service workers or authenticated API. The parent verifies the frame window, opaque origin and 128-bit boot nonce before transferring separate control and application ports. Trusted input waits for the parent to confirm DOM focus. The kernel routes application text to the compositor-bound owner, with a 4096-byte UTF-8 limit per message. Reload or navigation revokes both channels. Native paste and drop data pass through compositor policy.

**4. Transfers and notifications.** Clipboard writes require focus and a pointer/key activation within five seconds. The 1 MiB limit applies to plain text, sanitized HTML or PNG. A successful write updates the seat clipboard. The host attempts to mirror it to the system clipboard and reports mirror failures in the session status. Reads consume one explicit paste gesture. Trusted native paste supplies external plain text when available. The compositor returns `EACCES`, `ENODATA`, `E2BIG` or `EOPNOTSUPP` as appropriate. Drag start requires an active press on the focused source and accepts at most 64 items. Hover exposes only MIME types and coordinates. Drop transfers the payload to the target. A picker consumes an activating gesture from the focused surface, binds to its owner PID, socket endpoint and login generation through descriptor delivery, and returns only the selected read-only descriptor via `SCM_RIGHTS`. Cancel returns `ECANCELED`. Notifications carry the compositor-stamped owner, plain-text title up to 128 bytes and body up to 512 bytes. A per-client burst of three replenishes by one every five seconds, with at most 32 active. Excess returns `EAGAIN`. Lock and Greeter suppress notifications and dismiss visible ones.

**5. Focus, accessibility and IME.** Window regions and iframes expose their titles. Pixel canvases expose an image label, role description, focus target and a polite live announcement supplied by the client. A client that negotiates `pixel-input` receives surface-local pointer coordinates and focused key events. Minimized windows are hidden and inert. A security modal uses a modal dialog and makes the desktop inert. Clicking within an opaque document activates its surface through the sealed bootstrap. It captures Alt+backquote, Alt+Shift+backquote, Ctrl+Alt+arrow and Alt+F4 only for trusted non-composing key events with keyCode other than 229. This preserves native CJK composition. Closing or minimizing the focused window restores focus in stacking order.

**6. Pixel device loss.** Only the owning process Worker receives the transferred OffscreenCanvas and its generation. The renderer prefers WebGPU. On GPU loss, context loss or the simulation ioctl, the compositor reports `DeviceLost`, advances the generation and issues `RecreatePixelCanvas`. The browser replaces the DOM canvas and transfers a fresh one to the owner. The Worker acquires a 2D context on that canvas, reports `SurfaceReady(Software2d)`, and the sample redraws. Stale generations and reports from other owners are refused.

**7. Portable host contract.** The records in `abi::gui`, VFS device registry and `CompositorCore` use Rust types independent of a window system. The browser `HostPresentationAdapter` and the Rust `HeadlessHostAdapter` consume the same display commands. G-01 through G-10 exercise device access, negotiation, ownership, roles, content verification, input leases, accessibility, device recovery, mediated transfers and seat lifecycle. [Conformance matrix](../compat/matrix.md#gui-protocol-v1)

#### Pointer-to-frame measurements

The headless benchmark runs 120 pointer moves on each path with a simulated 60 Hz input clock. Times below are elapsed milliseconds from dispatch to the in-process adapter's geometry update. The message rate counts actual serialized seat inputs and emitted display commands across the two simulated seconds. The headless run has no OS Workers.

| Headless mode | p50 ms | p95 ms | p99 ms | Max ms | Frames over 16.7 ms | Seat messages | Messages/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| local-lease | 0.000214 | 0.016871 | 0.017703 | 0.022692 | 0 | 27 | 13.5 |
| roundtrip | 0.031076 | 0.036160 | 0.039425 | 0.040724 | 0 | 247 | 123.5 |

A second headless run used the packaged kernel, compositor and clients in Node Workers. The test schedules 120 moves at 60 Hz on an independent clock and matches compositor frames to individual dispatches. The local path updates immediately. The roundtrip path waits for the compositor's frame command. Counts include both directions at the host/kernel boundary and the compositor Worker's posted requests, including its polling traffic. Shared-memory replies use no posted message.

| Packaged Worker mode | p50 ms | p95 ms | p99 ms | Max ms | Frames over 16.7 ms | Missing frames | Worker messages/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| local-lease | 0.007 | 0.010 | 0.016 | 0.016 | 0 | 0 | 713.5 |
| roundtrip | 2.678 | 4.679 | 7.621 | 8.398 | 0 | 0 | 976.9 |

A Playwright run on `/gui-session.html` dispatched 120 Chromium pointer moves per mode at an independent 60 Hz cadence. Each latency runs from the pointer event timestamp to the CSS geometry update in the `requestAnimationFrame` callback. Browser rasterization and compositor presentation occur after that measurement.

| Chromium browser mode | p50 ms | p95 ms | p99 ms | Max ms | Frames over 16.7 ms | Missing frames | Gesture msgs | Worker messages/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| local-lease | 13.12 | 14.37 | 14.48 | 14.48 | 0 | 0 | 20 | 671.7 |
| roundtrip | 23.87 | 24.36 | 24.38 | 24.40 | 119 | 0 | 241 | 907.8 |

Reproduce the Rust measurements with `cargo test -p os-services headless_drag_latency_120_steps -- --nocapture`, the packaged Worker measurements with `node --test --test-isolation=none --test-reporter=tap tests/gui-protocol.test.mjs`, and the browser measurements with `npx playwright test tests/gui-drag-latency.spec.js --project=chromium`. The production URL uses local leases (`0/120` late frames vs `119/120` late frames on `?drag=roundtrip`, with 12x fewer gesture IPC messages). Worker counts include page/kernel messages in both directions and compositor requests answered through shared memory.

### 2.10 Versioning (Decided, amended in L0c)

**Today (`dev` `339a76d9`).**
- `RemoteFilesystem` v2 (`/api/fs` v2) and `LocalHelper` v1 (`Hello` negotiation in `crates/local-helper` and `crates/vfs/src/helperfs.rs`) are live.
- Existing v1 protocols not yet moved to Contract v2:
  - the page–kernel envelope (`web/kernel/protocol.js` `VERSION = 1`, `crates/client-kernel` `VERSION = "1"`);
  - cookie/token auth routes (unversioned v1);
  - images and release manifests (`os_image::PROTOCOL = 1`, `crates/image`);
  - the accelerator ioctl (`crates/abi/src/accelerator.rs` `VERSION = 1`).

**Decision.**
- **Named boundaries with versions.** Each boundary in [§6](#6-versioned-boundaries) has a version. Stored on-disk/IndexedDB formats (`COWFS_FORMAT_VERSION = 1`, browser metadata `STORE_FORMAT_VERSION`, helper `STATE_FORMAT_VERSION`) are versioned alongside wire boundaries.
- **Negotiation at connect.** Each side states the versions it speaks (`Hello`), and the highest common one is used. With none in common, the connection is refused with `EPROTONOSUPPORT`.
- **Recovering in a page.** A page never reloads by itself, since a reload ends the instance and its processes.
  - It reports the mismatch, keeps local processes running, and fails only the calls that cross the mismatched boundary.
  - It offers a reload at the default release, or, at a pinned release URL (where a reload stays pinned, README "Immutable releases and extensions"), the switch to the default release.
  - Nothing is recorded between page loads, so each deployment's mismatch is reported afresh.
- **One version per side.** Because nothing older is kept (§2.12), each side speaks one version during #44. A version bump in `contract.rs` defines the target contract ahead of its implementing PR (for example, `HostAdapter` v2 and `Release` v2 defined in L0c #76 and adopted in L2.5a/L2.5b #77/#78, or `ServiceAuth` v2 adopted in #54/#57). Negotiation detects a stale page or host after a deployment rather than serving old clients indefinitely.

`contract.rs` defines the boundaries, their versions and the negotiation rule.

### 2.11 "Native" in the L5 and L6 gates (Decided)

#44 requires browser and native presentation to pass the same scenarios. The native host (`os-native`) is a Phase 9.0 deliverable (#82), and Phase 9 waits for #59 (§2.14).

**Decision.**
- **The gate:** the contracts contain no DOM types, and a headless test host that implements the host adapter passes the same protocol suite as the browser host.
- **Later:** real native execution (`os-native` on Wasmtime + standalone OCI container image) follows in Phase 9.0 (#82).

### 2.12 Data preservation (Decided, owner, 2026-11-14; amended in L0c)

**None for pre-#44 deployments.** When #44 is done, the owner removes the deployment and all its data and redeploys.

- **Server state may change without migration:** the state schema, the authority's tables, Durable Object classes, storage layout and protocols. Each incompatible change bumps the schema version, so stale state is refused, never misread.
- **No SQL migrations.** A schema change edits the `CREATE TABLE` statements directly. Guarded `ALTER`s and backfills are not written, and existing ones may be removed when their code is touched. Local test state is recreated, not upgraded.
- **No previous versions or legacy configuration.** Nothing needs to read data, cookies, protocols or programs from before the refactor. `wrangler.legacy.toml`, the old Durable Object export and R2 marker, legacy cookie and preference names, and the old `terminal` WASM import namespace may be removed.
- **Durable Object migration entries stay valid.** Cloudflare requires wrangler's `[[migrations]]` entries for Durable Object class changes, in deployment and in local development. Changes add entries as Cloudflare requires; the redeploy may start a fresh history.
- **Browser-side metadata overlays and preferences survive the redeploy**, so they are versioned too.
  - Every derived store the client writes carries a format version: OPFS/hostfs IndexedDB metadata caches, the directory-handle registry, saved preferences.
  - Formats only move forward. Code meeting an older derived metadata store resets it once, never reading it: its metadata goes back to private defaults. Code meeting a newer store (an older pinned release in another tab) leaves it alone and reports the filesystem unavailable (`EPROTONOSUPPORT`), so tabs on different releases never reset each other's metadata.
  - File contents (in `os-workspace` and in users' folders) are never deleted by a reset.
  - Cookies from before the redeploy fail authentication, and the user signs in again if using remote services.
- **A `cowfs` user volume is never silently reset.** Unlike derived metadata overlays, a `cowfs` volume **is** the user's files and `/etc` state. Opening a `cowfs` store with an incompatible `COWFS_FORMAT_VERSION` (older or newer) MUST fail with `EPROTONOSUPPORT` and enter Stage 1 recovery, offering export with a compatible tool or explicit user-confirmed re-provisioning—never a silent wipe or automatic `mkfs`.
- **Installed offline boot generations (#78).** The release installer pins the complete verified Release v2 boot set locally before marking a generation active, retaining the previous known-good generation until the new one boots cleanly.
- **Removed as soon as replaced:** an old path goes when its replacement works in the repository. Its authorization rules and denial tests carry over.
- **Per-mount permissions are not carried over.** A host/OPFS filesystem's first attachment after L1 starts private to the attaching account and never widens access.
- **Still required:** the new system's own release generations, upgrades and rollback (L2.5b / L3).

### 2.13 Dispatch (Decided)

The contract records only the boundary between task state and delivery:
- **Task state stays with the task service (`ClusterState` outbox, #83):** admission, durable state, leases, cancellation and results.
- **A dispatcher only delivers notices** of the form "task T, attempt A, is ready". It holds no task state and no bulk data, and it may deliver twice. A consumer claims the attempt from the task service, which fences duplicates.

The full Queues contract stays in README "Cloudflare Queues and background dispatch" and is implemented in Phase 9.2-Q.

### 2.14 When Phase 9 may start and track dependencies (Decided, amended in L0c)

- **Narrow `#44` critical path.** Only #76 (`L0c`), #77 (`L2.5a` local `os-cowfs`), and #78 (`L2.5b` offline Release v2 + bounded image paging) enter `#44`, running **in parallel with #54 → #55** to converge at #56. `#56` strictly waits for #77 + #78 with no volatile-root merge flag.
- **Off-`#44` storage & registry track.** Storage tools (#79 `L2.5c`), fenced remote R2 + Durable Object volumes (#80 `L2.5d`), and the OCI Distribution v1.1 registry (#81 `L2.5e`) live outside `#44`'s closure gates.
- **Phase 9 start gate and parallel post-L4 tracks.** Phase 9 may start after **#59 (`L4b`)**. After #59, the Storage/Registry/Cluster track (#79–#84, plus #85 CSI/CRI/raw-LBA and #86–#87 networking) and the GUI Process Migration track (#60–#65) advance **in parallel**:
  - Phase 9.0 (#82 `os-native`, standalone OCI container image, remote seat/PTY attach) depends on #59, #77, #78.
  - Phase 9.1a (#83 `ClusterState` DO store) depends on #59.
  - Phase 9.1b (#84 userspace `kubelet` + sandbox instances + task SDK) depends on #57, #82, #83, #80, #81.
  - Phase 9.5 (#85 CSI + `containerd-shim-os-v1` `runwasi` shim + raw LBA/NBD) depends on #82, #80, #81.
  - Phase 10a (#86 `netd` stream gateway) depends on #55, #57; Phase 10b (#87 `/dev/net/tun` + tenant overlay + `os-cni`) depends on #86, #83.
- **`#44` closure.** `#44` itself closes only after all L0–L6 gates pass (#65).

### 2.15 Storage substrate (`os-cowfs` v1) and two-stage offline boot (Decided)

#### MIT pure-Rust single-map Merkle CoW filesystem (`os-cowfs` v1)

`os-cowfs` (`crates/cowtree` + `crates/cowfs`, MIT-licensed pure Rust; rejecting GPLv2 Btrfs / CDDL OpenZFS ports and double-CoW LBA allocators) is a single-map Merkle copy-on-write B+tree filesystem implementing `os_vfs::Filesystem` (`FsType::Cowfs`):

| Parameter | v1 specification |
| --- | --- |
| **Object addressing** | `sha256(plaintext object bytes)`. Every tree node and data extent is independently verifiable on range read. |
| **B+tree nodes** | Copy-on-write B+tree with **16 KiB** max nodes. Keys: `(subvol u64, ino u64, kind u8, offset u64)` with item kinds `INODE`, `DIRENT` (name hash + collision chain), `DIRIDX` (stable `readdir` cookie), `EXTENT`, `XATTR` (including POSIX ACLs), and `ORPHAN` (unlinked-but-open inodes reaped on next rw mount after crash). |
| **Data extents** | Fixed **64 KiB** aligned logical blocks; one `EXTENT` item covers `1–16` contiguous blocks (**<= 1 MiB** read unit). Inline file data `<= 2 KiB` lives in the leaf. Sparse holes read as zero. No content-defined chunking in v1. |
| **Root object** | `{magic: "OSCOWFS1", format: 1, features, volume_uuid, subvols: {name -> tree_root}, next_ino, generation, parent_root?}`. |
| **Immutable packs** | Objects are stored in immutable **<= 8 MiB** pack files carrying a trailer index `digest -> (offset, len)`. Packs are never mutated in place after commit. |
| **Transaction groups & commit** | Dirty state batches into a transaction group, committed on `fsync`/`fdatasync`/`syncfs`, every 5 s while dirty, or when dirty reaches 8 MiB (whole-volume commit in v1). Commit writes leaves → parents → root object, then one atomic head CAS. |
| **Garbage collection** | Reachability mark from all heads, snapshots, fork bases, active RO pins, orphan inodes, staged transactions, and a 10-minute grace window; writers hold a shared commit lock while GC takes an exclusive sweep lock for final deletion (remote GC serializes final deletion inside the Storage DO against new pins/publications). |
| **Dedupe scope** | Strictly within one store (one browser profile, one native `$STATE`, or one tenant prefix `t/<tenant>/packs/<digest>` in R2). Never across tenants. Public images use a public namespace. |
| **v1 non-goals** | Compression, encryption, RAID, qgroups, online fsck repair, content-defined chunking, and multi-writer (`RWX`). |

#### Pluggable `HeadStore` / `PackStore` traits and one object graph across three head stores

Persistence is isolated behind portable `HeadStore` and `PackStore` traits (`MemoryHeadStore` is strictly a fast test backend, never shipped as a `#56` fallback) so local browser/native backends, R2 + Storage DO (#80), and future NVMe page servers or CSI backends plug in cleanly without changing `os-cowfs`:

| Backend | Pack / object store | Head store & crash-safe commit | Writer exclusion |
| --- | --- | --- | --- |
| **Browser (`#77` L2.5a)** | IndexedDB `nodes` (tree nodes `<= 16 KiB` by digest) + OPFS immutable `packs/<uuid>.pack` written once in the dedicated kernel Worker via `FileSystemSyncAccessHandle` (`flush()` + `close()`). Concurrent cross-tab fork reads use `getFile().slice()` without exclusive lock contention. | One `{durability: "strict"}` IndexedDB `readwrite` transaction inserting nodes + pack index rows and CASing `heads[volume] = {epoch + 1, root, local_fence}` after checking `local_fence`. | Profile Web Lock `os-vol:<uuid>` held by the kernel Worker for the mount's lifetime. Forced UI takeover bumps `local_fence`, causing any paused/bfcached tab's next CAS to fail `ESTALE`. |
| **Native (`#77` L2.5a / `#82`)** | Immutable `$STATE/store/packs/*.pack` (`fsync(2)` before commit). | SQLite (`WAL`, `synchronous=FULL`) committing nodes, pack index, and head CAS in one transaction. | Exclusive `flock` on `$STATE/store/vol-<uuid>.lock`. |
| **Remote (`#80` L2.5d)** | R2 `t/<tenant>/packs/<digest>` via authorized streaming pack gateway (uploads only changed `64 KiB` delta blocks + B+tree path in immutable `<= 8 MiB` packs—never full-file copies). | SQLite in the tenant’s `StorageVolume` Durable Object: head, staging pins, RO pins, and idempotent `receipts[op_id]`. | Triple-fenced single RW writer lease (below). |
| **OCI v1.1 Registry (`#81` L2.5e)** | The exact same R2 immutable pack store. | OCI Distribution v1.1 manifests, tags, and `referrers` in the Storage DO. | Immutable (none). |

Because local volumes, remote volumes, and OCI v1.1 `cowfs` snapshot artifacts (`application/vnd.os.cowfs.snapshot.v1`, sharded via OCI index for large volumes so `oras cp -r` copies full graphs) share one immutable pack graph, `mkfs.cowfs`, O(1) `snapshot`, O(1) `fork`, `FICLONE`, `cowfs send`/`receive`, `push`/`pull`, and remote attach perform **zero byte-format conversion**. Standard runnable OCI images import tar layers once into a sealed `cowfs` root (handling whiteouts, opaque dirs, hard links, confined symlinks, and `os_image` non-elevating setuid policy) and export standard tar layers with accurate DiffIDs.

#### Triple-fenced single-writer remote volumes & distinct multi-writer FS tier

Issue #80 (L2.5d) implements `Boundary::Volume` v1. For each control and pack request, the edge verifies the caller's ServiceAuth credential with `OsAuthority` and the instance lease with `Machine`. The grant determines the tenant and permitted volume IDs. An unrestricted administrator can explicitly select another tenant. A read-only grant permits pinned reads. The gateway charges pack bytes to the caller's Machine I/O budget.

`POST /api/volumes/rpc` carries versioned metadata. `PUT /api/volumes/packs/<sha256>` streams up to 8 MiB to R2 and verifies the pack digest, canonical footer, trailer and indexed block digests. Sealing rechecks the grant and writer lease. `HEAD` returns the sealed length. A volume-ID-scoped `GET` requires an explicit byte range contained entirely in authorized block payloads. Storage schema 1 keeps verified nodes and block locations in SQLite. On cold start the DO compares its incarnation, sequence and nonce with `t/<tenant>/meta/checkpoint.json`. Divergence rotates every volume incarnation, clears writers and staging, and preserves snapshots and RO pins before serving requests.

RO pins expire after 120 seconds and renew every 40 seconds. Writer renewal also extends the writer’s live pack reservations and staged nodes for 300 seconds. GC retains volume heads, snapshots, live pins and superseded roots within the 600-second grace period. A fenced mount pins its last acknowledged root and renews that pin while it holds the dirty overlay. Recovery can then fork that root after the grace period. If a partition lasts until an unpinned base has been collected, recovery returns `ESTALE` and the mount retains its dirty data. The alarm reserves up to 100 deletion candidates per batch, deletes the objects in R2, then removes their SQLite rows. Staging can rescue a queued object. A deletion already in flight returns `EAGAIN`.

- **Strictly single fenced RW writer + unlimited RO pinned readers + O(1) forks.**
  - `attach_rw(volume, service_cred) -> {incarnation, fence = ++fence, epoch, root, ttl = 60 s}` (`EBUSY` while an unexpired lease exists unless takeover is authorized).
  - `renew(volume, incarnation, fence)` every `20 s` against the DO clock (`ESTALE` if `incarnation` or `fence` is stale); the client self-fences uploads after `t_renew_sent + TTL - 10 s`.
  - `incarnation` rotates on every Storage DO point-in-time restore so a restored database can never revive old fences.
  - `commit(volume, incarnation, fence, parent_epoch, root, packs[], op_id)` executes one synchronous DO SQLite transaction checking: valid grant, `incarnation == cur` (`ESTALE`), `fence == cur` and lease unexpired (`ESTALE`, defeating stale-writer races even when `epoch` has not advanced), `parent_epoch == head.epoch` (`EAGAIN`), and sealed pack reachability (`EIO`). It advances `head = {epoch + 1, root}`, promotes staging pins, and records `receipts[op_id]` (replaying the same `op_id` with identical payload returns the receipt; reusing `op_id` with a different payload returns `EINVAL`).
  - `status(volume, op_id) -> pending | committed(receipt) | aborted` resolves uncertain `EIO` after a lost commit reply.
  - Read-only attachments auto-pin a committed root safely alongside an active writer (`-o remount,refresh` advances to the newest head). A partitioned writer keeps its dirty group locally and may fork it under an explicit grant.
- **No multi-writer (`RWX`) mode in `os-cowfs`.** Multi-writer shared files use optional `/mnt/cloud` (`FsType::Cloud`, server ACLs + locks) or `sharefs` exports. Any future scalable multi-writer (`RWX`) transactional cloud filesystem is explicitly a **separate filesystem driver/tier**, NOT `cowfs v2`.

The volume RPC negotiates `Boundary::Volume` before reading the CowFs format. After logical collection, `VOLUME_GC_RETAIN_SECS` sets the physical pack retention window for point-in-time recovery (default 600 seconds). Restore checks every sealed pack's size and ETag against R2 and removes missing or corrupt locations from the block index. A volume whose head, snapshot, or live read pin has lost data returns `EIO`. Healthy volumes can upload verified replacements.

**Remote volume conformance (L2.5d, #80)**

| Cases | Exercised boundary | Expected observation |
| --- | --- | --- |
| RV-01, RV-02 | Two writers with one head | Exclusive attach returns `EBUSY`, fork-on-busy shares the committed root, administrator takeover evicts the old fence with `ESTALE`, and a valid writer with a stale parent gets `EAGAIN`. |
| RV-03, RV-04 | Upload seal and commit acknowledgement | Expiry during upload leaves a collectible orphan. The client stops uploading at 50 seconds. A lost acknowledgement resolves to the receipt, and conflicting operation-ID reuse returns `EINVAL`. |
| RV-05, RV-06 | GC and SQLite restore | Concurrent readers retain the old pack until the last pin expires. Staging survives collection. An interrupted checkpoint publication retries with existing leases intact. Restore rotates writer incarnations, reads retained packs, and quarantines a volume with a missing snapshot pack. |
| RV-07, RV-08 | R2 data and credentials | A 128-byte edit to a 2 MiB file uploads one pack below 128 KiB. A cold reader verifies all 2 MiB. Live authorization, tenant isolation, quota, pack integrity, schema and wire-version checks return typed errors. |
| RV-09, RV-10 | Portable filesystem client and local boot | The remote transport runs the existing POSIX suite plus reflink, snapshots, fork, fsck and refreshed reads. The local backend retains offline boot and the syscall audit covers 74 calls. |

The Worker acceptance cases live in `tests/remote-volume.mjs`. The portable client cases live in `crates/cowfs/tests/remote_cowfs.rs` and `crates/cowfs/tests/conformance.rs`.

#### Fixed `32 MiB` `wasm32` storage arena & bounded paging (`#77`, `#78`)

- **Fixed slab arena.** At first `cowfs` mount on `wasm32`, the kernel allocates one fixed **32 MiB** slab (`8 MiB` tree node LRU, `16 MiB` clean data cache, `8 MiB` dirty/in-flight with writer backpressure; dirty data is never evicted before commit) so `wasm32` linear memory does not grow unboundedly. Native hosts default to a configurable `256 MiB` RAM cache.
- **Bounded range-verified fetches.** At most `4` concurrent fetches of `<= 1 MiB` each, coalesced by digest, read via streaming length enforcement and SHA-256 verified per chunk/pack before exposing bytes (replacing `imageBlobRead`'s whole-blob `arrayBuffer()` in `#78`).
- **Paged directory reads.** `os-vfs` adds cursor-based `Filesystem::read_dir_page(dir, cookie, max) -> (Vec<DirEntry>, next_cookie)` with a default adapter over `read_dir` (`#77`).
- **Browser quota.** Call `navigator.storage.persist()` at first provisioning and check `estimate()` before each transaction group; quota exhaustion returns `ENOSPC` leaving the last committed head intact. Evict only clean refetchable cache packs, never local-only volume data or the pinned offline boot set.

#### Two-stage zero-network standalone boot (`Stage 0` → `Stage 1` → `Stage 2`)

1. **Stage 0 (Host loader):** Reads the persisted local boot profile, verifies the pinned signed **Release v2** offline boot set (Ed25519 via `os_image`; browser installer pins the complete boot set into OPFS/Cache Storage before activating a generation and keeps the previous generation until the new one boots cleanly), and starts the kernel with locally pinned initramfs + early image. Zero outbound network calls, zero cookies, zero OPFS writer locks.
2. **Stage 1 (`initramfs`, early `/init` as PID 1, local `uid 0`):**
   - `/` (`tmpfs` populated from initramfs: `/init`, `mount`, `switch_root`, `cowfsck`, recovery `sh`),
   - `/usr` (`image`, `ro,nodev` — early tools only; detached before root switch),
   - `/proc` (`proc`, local process table from `#54`),
   - `/dev` and `/dev/pts` (`devtmpfs`, `devpts`, local devices only: `null`, `zero`, `random`, `tty`/`pty`, `console`),
   - `/run` (`tmpfs`, per boot).
   - The console is usable offline in Stage 1.
3. **Stage 2 (`/sysroot` assembly & `switch_root`, `#56`):**
   - Early `/init` resolves the boot profile root:
     - `volume:<uuid>`: tries the volume lock (`os-vol:<uuid>` with `ifAvailable`, or native exclusive `flock`). If held by another tab on the default profile, creates and boots an **O(1) persistent fork** of the last committed head, recording `/run/os/root` and notifying the console (auto-pruned on clean unmodified shutdown; kept in the boot chooser if modified). If `excl` is set, `EBUSY` enters the Stage 1 recovery chooser.
     - **First boot** (no volume yet): provisions (`mkfs.cowfs` + verified `/etc`, `/var`, `/root` template defaults, including default local user `uid 1000` in `wheel` with passwordless `sudo`). Stage 1 **never** auto-formats an existing volume.
     - `snapshot:<digest>` (read-only root with tmpfs overlays unless writable volumes are named) or `ephemeral` (tmpfs-backed fork of template).
   - Mounts `cowfs` at `/sysroot` (`subvol=@`, plus `@home` at `/sysroot/home` if present), mounts the verified Release v2 system composition at `/sysroot/usr` (`image`, `ro`), mounts a fresh `tmpfs` (`01777`) at `/sysroot/tmp`, detaches Stage-1-only mounts (`umount2("/usr", MNT_DETACH)` — never moving Stage-1 `/usr` or `/tmp`), performs §5 `switch_root`, and `execve`s `/usr/bin/init` preserving PID 1 and start time.
4. **Post-switch remote units (`#57`):** Optional units (`cloud.mount` → `/mnt/cloud`, `devattach@*`, remote volume mounts, `kubelet.service`) start only after `switch_root` using explicit cloud service credentials; unavailability yields `ENOTCONN` on those resources without impairing offline local boot.

### 2.16 Virtual hardware, portable Wasm/WASIX container runtime, and cluster boundaries (Decided; Phase 9–10 reserved)

#### Typed virtual hardware contracts

Every device node is created in `devtmpfs` by the host adapter or a credentialed post-boot attachment service (never bound from a cloud file tree, and with no `sysfs`). Each device speaks a versioned `ioctl` protocol (`deny_unknown_fields`, bounded payloads, `INFO` capability query, `EOPNOTSUPP` for unsupported operations, `ENODEV` for unknown classes). Remote devices appear only after explicit attachment with a scoped cloud service credential.

| Device / interface | Contract & authorization | Phase |
| --- | --- | --- |
| `/dev/vdN` | Managed `cowfs` volume device (`BLK_INFO`, `BLK_LEASE`, `COWFS_IOC_*`, `mount`, `mkfs.cowfs`; `rw` open requires the volume lease; `O_EXCL` honored). Raw `read`/`write` on object-native volumes returns `EOPNOTSUPP` (`cowfs send` exports streams). Phase 9.5 (#85) adds an `LBA -> extent` schema on `os-cowtree` for raw block `/dev/vdN`, CSI block mode, and NBD export. | `#77` local, `#80` remote, `#85` raw LBA/NBD |
| `/dev/display`, `/dev/input` | GUI v1 seat 0. Root-owned exclusive device opens require the corresponding service device grants. The compositor binds surface endpoints through authenticated AF_UNIX peers (§2.9). | L5a (#60) |
| `/dev/loopN` | `LOOP_SET_FD` (instance root + read/write grant on file), `LOOP_CLR_FD` (`EBUSY` while mounted), `LOOP_GET_STATUS64` for mounting verified snapshot pack archives read-only or exposing granted regular image files without copying. Foreign fstypes (`ext4`, `vfat`) return `ENODEV`. | `#79` (`L2.5c`) |
| `/dev/accel/accelN` (plus `/dev/archive`, `/dev/media`) | Typed compute/archive/media accelerators: `INFO` advertises explicit classes (`container-cpu`, `inference`, `gpu-compute`) and GPU never silently downgrades to CPU; snapshot-digest inputs allow near-data R2 streaming; closing the last owning descriptor cancels attached work; explicit authorized detach follows deadline/recovery policy. | Re-homed `#54`/`#57`; v2 ABI Phase 9.2/9.3 |
| `/dev/snd/*`, `/dev/present/*` | Credentialed post-boot device attachments (`devattach@snd`, etc.), keeping direct Realtime SFU / WebRTC streaming and short-lived signaling grants. | Re-homed `#54`/`#57` |
| `netd` outbound stream gateway | WASIX outbound stream sockets routed over `AF_UNIX` (#55) to userspace `netd`, bridged to an authenticated gateway (Cloudflare Workers outbound `connect()` or native adapter) with destination/egress policy, per-credential quotas, cancellation, and host-loss teardown. No raw LAN access and no silent UDP claims. | Phase 10a (`#86`) |
| `/dev/net/tun` | Clone device: `TUNSETIFF` (`IFF_TUN \| IFF_NO_PI`) creates `tunN` interfaces carrying one L3 IP packet per read/write (`1 MiB` bounded queue, negotiated MTU, `poll`), bridged over WebTransport/WebRTC (browser) or host TUN + `os-cni` (`ADD`/`CHECK`/`DEL`) with control-plane IPAM, source-IP binding, and cross-tenant firewalling. | Phase 10b (`#87`) |

#### Portable Wasm/WASIX container runtime & multi-runtime symmetry

- **Same kernel, same release, same storage across hosts.** The OS kernel itself serves as a portable **Wasm/WASIX container runtime** ("compile once, run anywhere") across:
  - Browser Workers (`browser`),
  - `os-native` Wasmtime hosts (`#82`, Phase 9.0),
  - standalone Linux OCI images packaging `os-native` (`docker run` / `podman run` over a named `$STATE` volume, `#82`), and
  - `containerd-shim-os-v1` (`runwasi`-based CRI shim) + Linux CSI Controller/Node plugins (`#85`, Phase 9.5).
  All runtimes execute the exact same portable Rust kernel crates, signed Release v2 artifacts, and `os-cowfs` / OCI v1.1 pack format; only **Host Adapter v2** differs.
- **Linux ELF pod delegation is explicitly deferred / out of scope.** Our cluster does **not** delegate Linux ELF pods to host Podman or Cloudflare Containers due to cross-runtime filesystem and ABI sharing complexity. Wasm/WASIX hosts reject ELF binaries with `ENOEXEC`.
- **Remote seat / PTY attach (`#82`).** Authenticated remote console/PTY (and later display) attachment onto a running `os-native`/Container instance provides the "one shared hosted machine" workflow cleanly without overloading `CloudFs`.

#### `ClusterState` store, placement controller, and `kubelet` sandbox instances (`#83`, `#84`)

- **`ClusterState` Durable Object (`#83`, Phase 9.1a):** One SQLite-backed Durable Object per cluster exposing linearizable revisioned `Range(key, end, rev)`, conditional `Txn(compare[], success[], failure[])`, hibernatable WebSocket `Watch(prefix, from_rev)` (persisting events inside the mutation transaction before notifying), `Lease{Grant, KeepAlive, Revoke}` via DO alarms, and `Compact(rev)` (`compacted{floor}` relist semantics). Documented honestly as **etcd-subset semantics** behind a portable `ClusterStore` trait; **no etcd or Kubernetes wire compatibility is claimed**. Placement (`9.2`) and Cloudflare Queues dispatch (`9.2-Q`, §2.13) layer as controllers over `ClusterState`.
- **Userspace `kubelet` (`#84`, Phase 9.1b):** Opt-in `#57` system unit (`service enable kubelet`) enrolling a browser, `os-native`, or container node via bootstrap token → revocable node credential + `node_generation` lease. Schedules and runs Wasm/WASIX OCI container pods (including map-reduce / parallel shards) inside isolated **sandbox instances** (dedicated child kernel, PID 1, PID space, O(1) forked `cowfs` rootfs, zero inherited host or account descriptors). Outputs stage as immutable snapshots under storage staging pins and publish atomically via `ClusterState.Txn` fenced by `(node_generation, attempt_generation)` + cancellation state (stale or late commits fail `ESTALE`).

## 3. Filesystem capability profiles

Target profiles.
- **"Emulated"** means the OS provides the behaviour in its own metadata, coordinated across the tabs of the browser profile (§2.5). A change made outside the OS can still show the difference.
- **"Refused"** means the operation fails with the errno shown.
- **"Stale"** means the operation succeeds, but later access through a file already open fails with the errno shown.

| Capability | Local CoW volume (`cowfs`) | Remote CoW volume (`cowfs`, writer) | Snapshot / RO pinned view (`cowfs`) | Cloud tree (`cloud`, optional) | Browser storage (OPFS) | Host folder (directory handle) | Host folder (helper) | Shared mount (export) | Memory (`tmpfs`) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Filesystem identity | profile-local (browser) / host-local (native) | global | global (`(volume, root)`) | global | profile-local | profile-local | host-local (folder UUID) | the publisher's | instance-local |
| Writer model | `local` (single local exclusive writer) | `fenced` (single remotely fenced RW writer) | `immutable` (pinned RO view) | `multi-writer` (authority) | `multi-writer` (profile locks) | `multi-writer` (profile + host) | `multi-writer` (host kernel) | `publisher` | `local` (instance) |
| Open file survives unlink | yes (`ORPHAN` list, reaped at next rw mount after crash) | yes (`ORPHAN` list) | refused: `EROFS` | yes | emulated: name removed, content deleted when the last tab releases it (or on crash sweep) | stale: `ESTALE` | yes (the helper holds the host descriptor) | the publisher's | yes |
| Open file survives rename | yes | yes | refused: `EROFS` | yes | yes | yes when renamed through the OS; stale (`ESTALE`) after an outside rename | yes | the publisher's | yes |
| Hard links | yes | yes | read yes; create `EROFS` | yes | emulated in the metadata store | refused: `EPERM` | yes | the publisher's | yes |
| Symbolic links | yes | yes | read yes; create `EROFS` | yes | emulated in the metadata store | refused: `EPERM` | yes, confined beneath the folder | the publisher's | yes |
| Atomic `O_EXCL` create | yes (single writer instance) | yes | refused: `EROFS` | yes | emulated (profile lock) | emulated (profile lock) | yes | the publisher's; lost ack is an uncertain write | yes |
| Atomic rename | yes | yes | refused: `EROFS` | yes | emulated (profile lock) | no: declared non-atomic | yes (`renameat2`) | the publisher's | yes |
| `RENAME_NOREPLACE` | yes | yes | refused: `EROFS` | yes | emulated (profile lock) | emulated: checked under the profile lock | yes (`renameat2`) | the publisher's | yes |
| Snapshots / forks | yes: O(1) | yes: O(1) (one DO txn) | fork: O(1); snapshot write `EROFS` | refused: `EOPNOTSUPP` | refused: `EOPNOTSUPP` | refused: `EOPNOTSUPP` | refused: `EOPNOTSUPP` | the publisher's | refused: `EOPNOTSUPP` |
| `FICLONE` reflink | yes within one volume; across volumes `EXDEV` | yes within one volume; across volumes `EXDEV` | refused: `EROFS` as destination | yes | refused: `EOPNOTSUPP` | refused: `EOPNOTSUPP` | refused: `EOPNOTSUPP` | the publisher's | refused: `EOPNOTSUPP` |
| Durability point (`fsync` / `syncfs` returns after) | `tree-commit`: browser OPFS pack `flush()`+`close()` + `{durability:"strict"}` IDB head txn; native `fsync(pack)` + SQLite WAL `synchronous=FULL` head txn | `fenced-commit`: R2 pack PUT acks + triple-fenced Storage DO head txn | `tree-commit` / `fenced-commit` (already sealed; `fsync` returns 0) | `service-commit`: the authority's transaction and chunk commit | `writable-close`: closing the writable stream, or the sync handle's `flush()` | `writable-close`: closing the writable stream | `host-fsync`: the helper's `fsync(2)` | `publisher-ack`: the publisher's acknowledgement | `volatile`: content goes with the instance, `fsync` returns at once |
| Locks (`flock`, `fcntl` byte ranges) | kept by the writer instance (the only instance that can mount it rw) | kept by the writer instance | shared locks instance-local; exclusive locks `ENOLCK` (no cross-instance keeper) | kept by the authority, seen by every instance | across the profile's tabs: Web Locks, with byte ranges in the metadata store | across the profile's tabs, as browser storage | the host's own locks, held by the helper, seen by every host program | the publisher's | kept by the instance, seen by its processes |
| Fenced writer / takeover | forced UI takeover bumps `local_fence` → stale tab fails `ESTALE` | lost `fence` or `incarnation` → writes and `fsync` fail `ESTALE`; dirty state may be forked | — | — | — | — | — | — | — |
| Provider loss | — | `ENOTCONN`; lost commit reply gives uncertain `EIO` until `status(op_id)` resolves it | pinned cached objects stay readable; uncached objects fail `ENOTCONN` | `ENOTCONN`; lost write ack gives uncertain `EIO` | — | `ENOTCONN` (permission withdrawn) | `ENOTCONN` (helper gone) | `ENOTCONN` (publisher offline) | — |

Baseline rows: `open-rename`, `open-unlink`, `hard-link`, `symlink` → #48; `exclusive`, `noreplace`, `flush` → #50; `cowfs` differential conformance and crash-injection gates → #77.

- **No lock is faked.** A lock is granted only where every client of that filesystem can see it. A driver that cannot reach its lock keeper fails the request with `ENOLCK` (added to `abi::Errno` by #50), never with success.
- **Provider loss** (folder permission withdrawn, helper gone, publisher offline, or remote storage unreachable) fails operations with `ENOTCONN` (added by #51), as on Linux when a FUSE daemon dies.
- **Non-volume `mkfs` refusal** fails with `ENOTBLK` (added to `abi::Errno` by L0c #76).
- **Browser durability note.** IndexedDB `{durability: "strict"}` varies across browser engines (notably Safari's weaker durability and eviction behavior); `Durability::TreeCommit` advertises the OS barrier honestly, calls `navigator.storage.persist()`, and records per-engine evidence in `docs/compat`.

## 4. Mounts and namespaces

Results, following Linux where it has an answer:

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
| Second `rw` mount on a held local `cowfs` volume (explicit `excl`) or remote `cowfs` volume | `EBUSY` (default browser boot profile instead boots an O(1) persistent fork, §2.1, §2.15) |
| Stale `cowfs` writer after forced local takeover (`local_fence`) or remote lease/`fence`/`incarnation` loss | Writes and `fsync`/`syncfs` fail with `ESTALE`; dirty state may be forked under an explicit grant |
| Remote `cowfs` commit whose `parent_epoch` does not match under a valid fence | `EAGAIN` |
| Opening a `cowfs` store with an incompatible `COWFS_FORMAT_VERSION` | `EPROTONOSUPPORT` into Stage 1 recovery; user volume data is never silently reset (§2.12) |
| `mkfs.cowfs` on a directory, host folder, browser-storage tree, or export | `ENOTBLK` (`EBUSY` if mounted/leased; `EEXIST` if already formatted without `-f`) |

## 5. New calls: flags and errors

These are the calls #51–#56 and Wave L2.5 (#77–#81) add. Errors follow Linux; where this OS differs or decides, the table says so.

### `mount(source, target, fstype, flags, data)`

| Item | Value |
| --- | --- |
| Flags | `MS_RDONLY`, `MS_NOSUID`, `MS_NODEV`, `MS_NOEXEC`, `MS_SYNCHRONOUS`, `MS_DIRSYNC`, `MS_NOSYMFOLLOW`, `MS_NOATIME`, `MS_NODIRATIME`, `MS_RELATIME`, `MS_STRICTATIME`, `MS_LAZYTIME`, `MS_REMOUNT`, `MS_BIND`, `MS_REC`, `MS_MOVE`, `MS_PRIVATE`. `MS_SILENT`, `MS_POSIXACL`, `MS_I_VERSION` and the `MS_MGC_VAL` magic (`0xC0ED` in the top 16 bits) are accepted and ignored. Any other flag → `EINVAL`. |
| Filesystem types | `cloud`, `cowfs`, `opfs`, `hostfs`, `helperfs`, `sharefs`, `image`, `tmpfs`, `proc`, `devtmpfs`, `devpts`; unknown (including `sysfs`) → `ENODEV` |
| `cowfs` sources & options | Sources include `volume:<uuid>`, `/dev/vdN`, `snapshot:<volume>@<name>`, `remote:volume:<uuid>`, `remote:snapshot:<volume>@<name>` and `oci:<repo>@sha256:<digest>`. A managed volume or snapshot accepts `-o remote`. An administrator can request writer `takeover`. Other options include `subvol=<name>`, `ro`, `excl`, `refresh` (remount of an RO view to advance its pinned head). |
| `EPERM` | the caller may not mount here (§2.7), or an ordinary user's remount would clear `nosuid`/`nodev` |
| `EACCES` | a path component cannot be searched, or the provider refused the grant / cloud service credential |
| `ENOENT`, `ENOTDIR`, `ELOOP`, `ENAMETOOLONG` | path errors, as for any lookup |
| `EBUSY` | `MS_MOVE` or remount of a mount that cannot change now, or writer contention on an `excl` / remote `cowfs` volume |
| `EINVAL` | unsupported flags or propagation; `MS_MOVE` or `MS_REMOUNT` of something that is not a mount point; invalid mount options |
| `ESTALE` | fenced writer or stale `incarnation` / `local_fence` |
| `EPROTONOSUPPORT` | incompatible `cowfs` format version or boundary version mismatch |
| `ENOTCONN` | the provider cannot be reached |

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

### `fsync(fd)`, `fdatasync(fd)`, `syncfs(fd)`

| Item | Value |
| --- | --- |
| Effect | returns only after the driver's durability point (§3). On `cowfs` v1, `fsync`/`fdatasync` and `syncfs` commit the current transaction group to the head store. |
| `EBADF` | not open |
| `EINVAL` | the descriptor cannot be synced: a pipe, socket or terminal |
| `ESTALE` | `cowfs` writer lost its `local_fence`, remote `fence`, or `incarnation` |
| `EIO` | the provider failed to make the data durable, or the acknowledgement was lost (uncertain write; resolved via `status(op_id)` on remote `cowfs`) |
| `ENOSPC`, `EDQUOT`, `EROFS` | as Linux (`EDQUOT` added by #50) |

### `cowfs`, reflink, and volume-device `ioctl`s

| Request | Target & effect |
| --- | --- |
| `FICLONE`, `FICLONERANGE` | Intra-volume O(extents) extent clone on `cowfs` (and whole-file `FICLONE` on `cloud`). Cross-volume clone fails with `EXDEV`; read-only destination fails with `EROFS`. |
| `COWFS_IOC_SNAPSHOT` | On a mounted `cowfs` directory fd (`{name, ro}`): commits the transaction group and records O(1) `name -> root_digest` in the head store. |
| `COWFS_IOC_FORK` | On a `cowfs` directory or `/dev/vdN` fd (`{snapshot, new_volume}`): creates an O(1) new volume UUID seeded at `snapshot`. |
| `COWFS_IOC_INFO` | On a `cowfs` directory or `/dev/vdN` fd: returns volume UUID, root digest, epoch, writer model, and durability metadata. |
| `BLK_INFO`, `BLK_LEASE` | On `/dev/vdN`: queries managed volume metadata (`uuid`, `size`, `sector`, `writer_model`, `durability`) and lease status. |
| `LOOP_SET_FD`, `LOOP_CLR_FD`, `LOOP_GET_STATUS64` | On `/dev/loopN` (#79): attaches/detaches an explicitly granted regular snapshot pack archive or image file (`EBUSY` on clear while mounted). |
| Errors | `EBUSY`, `ESTALE`, `EAGAIN`, `EROFS`, `ENOTCONN`, `EIO` (digest/integrity failure or uncertain ack), `ENOSPC`, `EDQUOT`, `EXDEV`, `ENOTBLK` (`mkfs` on non-volume/directory source), `EOPNOTSUPP`, `EPERM`, `EINVAL`. |

### `unshare(flags)`, `setns(fd, nstype)`

| Item | Value |
| --- | --- |
| `unshare` flags | `CLONE_NEWNS`, `CLONE_FS`, `CLONE_FILES`, or `0` (no change), as Linux; any other flag → `EINVAL` |
| `EPERM` | `CLONE_NEWNS` or `setns` without instance root (there are no user namespaces); `CLONE_FS` and `CLONE_FILES` need no privilege |
| `setns` | the descriptor is a `/proc/<pid>/ns/mnt` of the same instance; any other → `EINVAL` |

### Root switch (`switch_root`)

The root switch is not a separate syscall and needs no special permission rule: it is a sequence of the calls above, run as PID 1 (local `uid 0`) by early `/init` (#56), following Linux's `switch_root` and §2.15:

1. Resolve and mount the persisted boot profile's local `cowfs` root volume at `/sysroot` (`subvol=@`, plus `@home` at `/sysroot/home` if present).
2. Mount the signed Release v2 system composition at `/sysroot/usr` (`image`, `ro`) and a fresh `tmpfs` (`01777`) at `/sysroot/tmp`.
3. Pre-flight: resolve `/sysroot/usr/bin/init` and its interpreter inside `/sysroot`, verify that every move target is a directory without following symlinks, and keep the verified rescue executable open.
4. Detach Stage-1-only mounts: `umount2("/usr", MNT_DETACH)` (never moving Stage-1 `/usr` or `/tmp` into `/sysroot`).
5. Open the initial root (`/`) as a descriptor so it can still be reached after the switch.
6. Move `/proc`, `/dev` (carrying `/dev/pts`), and `/run` onto the new root: `mount("/proc", "/sysroot/proc", MS_MOVE)` and the same for `/dev` and `/run`.
7. `chdir("/sysroot")`, `mount(".", "/", MS_MOVE)`, `chroot(".")`, `chdir("/")`.
8. Delete the initial `tmpfs` contents through the descriptor from step 5 without crossing into other mounts, then close it.
9. `execve("/usr/bin/init")`, preserving PID 1 and its start time.

Errors are those of the calls (`EPERM` without instance root, `EINVAL` when `/sysroot` is not a mount point, `EBUSY` when a mount cannot move or an `excl` volume is held, `EPROTONOSUPPORT` on incompatible `cowfs` format). Failure before step 7 undoes completed moves and enters the Stage 1 recovery console; a corrupt root enters `cowfsck` and snapshot rollback without ever auto-formatting; signature verification failure falls back to the previous trusted installed generation.

## 6. Versioned boundaries

| Boundary | Wire name | Between | Version this contract defines | Today (`dev` `339a76d9`) |
| --- | --- | --- | --- | --- |
| Syscall | `syscall` | applications and the kernel: `abi::Call`, WASI/WASIX imports | 1 | 1 (`abi::Call` over `/api/sys` + WASI/WASIX host imports) |
| Host adapter | `host-adapter` | the portable kernel and its host (`browser`, `os-native`, `container`): host/page protocol, Worker/process spawning, offline install, `cowfs` store, volume locks | 2 (`#77`, `#78`, `#82`) | 1 (`web/kernel/protocol.js` `VERSION = 1`, `crates/client-kernel` `VERSION = "1"`) |
| Remote filesystem | `remote-filesystem` | filesystem clients and optional `cloud` (`/mnt/cloud`) or `sharefs` services | 2 (handles, §2.3) | 2 (`/api/fs` v2 handles; v1 path calls refused for ordinary processes) |
| Local helper | `local-helper` | the helper driver and `os-local-helper` | 1 | 1 (`Hello` negotiated, `crates/local-helper` + `web/kernel/native-mount.js`) |
| Service auth *(formerly Identity)* | `service-auth` | userspace cloud/cluster clients and remote auth services: acquiring, renewing, scoping, and revoking explicit cloud service credentials (decoupled from local `/etc/passwd`) | 2 (`#54`, `#57`) | 1 (cookie and token routes, unversioned) |
| Device and task | `device-task` | typed devices and remote tasks | 1 | 1 (accelerator ioctl versioned separately, `accelerator::VERSION = 1`) |
| Release | `release` | signed offline boot sets, images, and release manifests | 2 (`#78`) | 1 (`os_image::PROTOCOL = 1`) |
| GUI | `gui` | clients, compositor, seat devices and host presentation | 1 | **Active v1**. AF_UNIX negotiation, `PEER_ROLES` separation, supervised `compositor`/`desktop-shell`/`greeter`, browser and headless adapters (§2.9, #60, #61). |
| Volume | `volume` | remote `os-cowfs` head, lease, triple-fenced commit (`incarnation`, `fence`, `epoch`), RO pins, and R2 pack gateway | 1 (`#80`) | 1 (`abi::remote_volume::REMOTE_VOLUME_PROTOCOL`, `StorageVolume`) |
| Registry | `registry` | OCI Distribution v1.1 subset and `cowfs` snapshot artifact v1 over the shared pack store | 1 (`#81`) | none |
| Cluster state | `cluster-state` | `ClusterState` Durable Object revisioned KV/Watch/Lease/Compact store | 1 (reserved, Phase 9 `#83`) | none |
| Network | `network` | `netd` outbound stream socket gateway (`#86`) and `/dev/net/tun` L3 tenant overlay (`#87`) | 1 (reserved, Phase 10) | none |

**Stored format version.** `os-cowfs` v1 carries `COWFS_FORMAT_VERSION = 1` (root magic `"OSCOWFS1"`) in local and remote heads/packs. Incompatible versions fail with `EPROTONOSUPPORT` into recovery without resetting user data (§2.12, §2.15).

**Negotiation.**
- **Hello.** The first message on each connection is a hello naming the boundary and the versions offered.
- **Choice.** The receiver picks the highest version both offer.
- **Refusal.** With none in common, it refuses with `EPROTONOSUPPORT`; a page recovers as §2.10 says.

`contract::negotiate` implements the choice.

## 7. Replacement table

What each component does today, where each responsibility goes, and which step moves it. As §2.12 decides, the old path is removed when its replacement works, with no compatibility window and no rollback to an older deployment.

| Component today | Responsibility | Goes to | Step |
| --- | --- | --- | --- |
| `RootCloudDriver`, `seed_from_authority`, `SEED_DIRS`/`SEED_SYMLINKS` (`crates/client-kernel/src/vfs_engine.rs`, `crates/worker/src/cloudfs.rs`) | mounting the shared cloud tree as `/` | local `os-cowfs` root volume (§2.1, §2.15) | #77 (`L2.5a`), #56 |
| `OsAuthority` shared tree (`crates/worker/src/cloudfs.rs`, `crates/vfs/src/cloud.rs`) | path resolution across the shared tree | client-side walk over v2 handles (§2.3) | #48, #51 *(done)* |
| | optional shared remote filesystem with per-file server ACLs and cross-client locks | **retained feature-frozen** as optional `FsType::Cloud` (`/mnt/cloud` or explicit `chroot`/NFS-root), authenticated by cloud service credential; **not** deleted in #65 | #56, #57 |
| | cloud-tree device directory binds (`/dev/present`, `/dev/snd`) | credentialed post-boot device attachments (§2.16) | #54, #57 |
| | `/proc` and other instance-local trees | the instance (`procfs`, `tmpfs`) | #54 |
| `Machine` Durable Object (`crates/worker/src/machine.rs`, `procs.rs`) | PIDs, process table, fork/exec admission, signals | the instance kernel (§2.1, §2.4) | #54 |
| | `pids.max`, `memory.max` | instance-local policy (§2.4) | #54 |
| | boot-time instance registration | local random boot id created offline; registered remotely only at first remote attachment | #54 |
| | `io.max` (filesystem byte transfers), container, relay, and task admission and accounting | stays remote, enforced per explicit cloud service credential | #54 |
| | OS account login (`login`/`su`/`sudo`/`passwd`), login/init coordination, init lease | 100% local `/etc/{passwd,group,shadow}` + instance PID 1 service manager + optional Cloud/Cluster Sign-In (`ServiceAuth` v2) | #56, #57 |
| | "one shared machine" across multiple tabs/clients | Phase 9 authenticated remote seat/PTY attach to a hosted `os-native`/Container instance (§2.1, §2.16) | #82 |
| `imageBlobRead` whole-blob `arrayBuffer()` (`web/kernel/client.js`) | reading release/image blobs into memory | bounded streaming range-verified chunk paging + pinned offline Release v2 boot set (§2.15) | #78 (`L2.5b`) |
| `Workspace` (`web/kernel/workspace.js`) | prefix routing of `/mnt/local`, `/mnt/shared`, `/opt/private`; lexical `..`; per-path inode numbers | the mount table and component walk (`os-vfs`) | #51 *(done)* |
| | private extensions at `/opt/private/NAME` (Phase 8.2) | user mounts of type `image` (§2.7) | #51 *(done)*, #58 |
| `PermissionMount` (`web/kernel/mount-policy.js`) | in-memory permission overlay for providers | filesystem-owned metadata stores (§2.5) | #49 *(done)* |
| Init lease (`web/kernel/init.js`, `login-boot.js`) | which tab runs init; page-driven startup | each instance's own PID 1 and service manager | #56, #57 |
| In-page shell (`crates/frontend/src/shell.rs` and `shell/`) | the interactive shell | a shell executable on a PTY, started by the terminal | #62 |
| `desktop.rs` (`crates/frontend/src/desktop.rs`) | window management in the page | the compositor and desktop-shell processes | #61 *(done — slimmed to `COMPAT-BRIDGE (#61)` pending #65)* |
| Built-in apps (Files, Mounts, Editor, Preview) | page components | ordinary GUI processes | #63, #64 |
| In-kernel export dispatcher (`web/kernel/mount-sharing.js`) | serving exports | an ordinary export service | #59 |

# L0a reference harness

This directory records measurements for [#46](https://github.com/kingwingfly/os/issues/46), step 1 of [#44](https://github.com/kingwingfly/os/issues/44). It does not select the architecture contract or change runtime behavior. Follow-up decisions belong to #47 and implementation belongs to the linked sub-issues.

The matrix contains 27 cases across five OS profiles. Filesystem rows compare normalized Linux and OS traces. Startup, GUI process visibility and browser-tab visibility are explicitly observational where this headless native fixture has no portable counterpart; their changes are checked, but they are not claimed to be compatibility differences that can automatically go stale. Every reviewed row names its follow-up issue; no permanent provider limitation is selected.

## Reproduce

From a fresh checkout on x86_64 Linux, install the repository's Rust targets and build tools as described in the main README, plus `unshare`, a Docker-compatible container engine, and Chromium's Playwright dependencies. Subordinate UID/GID mappings and `newuidmap`/`newgidmap` allow the Linux two-account case. The mount namespace uses `unshare -Urm`; `--map-auto` adds the mapped fixture IDs used by ACLs and the two creators.

```sh
npm ci
npm run setup
npx playwright install chromium
cargo xtask conformance --target linux
cargo xtask conformance --target os
cargo xtask conformance --check
```

The OS runner first rebuilds the current web assets with `cargo xtask build --web-only`, then builds the conformance WASI executable, Linux helper, and Worker. A stale or absent `dist/` cannot be used for a successful run. It selects an unused loopback port, sets `OS_TEST_URL`, creates a fresh Wrangler configuration, credentials and `--persist-to` state under `/tmp`, and uses fresh Playwright contexts. When using Podman, the runner owns a separate API service/socket with a separate image store under `/tmp/os-conformance-images-UID` (override with `OS_CONFORMANCE_PODMAN_DIR`). Only this image cache persists between runs. The temporary configuration uses the repository's real compiler container and relay; the unused archive container is omitted. No compiler transport interception is used. `OS_TEST_URL` from the calling shell is not used to connect to an existing instance. No seeding, existing credentials, demo directories or `.worktrees/` are used. The conformance executable is attached as a private executable file with explicit cloud delegation, then launched through the normal OS loader and process engine on every filesystem. It is not installed in the system image.


On this validation host, the default Podman store had inherited restrictive ACLs and rootless build networking could not resolve the package registry. The recorded run used the dedicated store and a prebuilt compiler made from the unchanged repository Dockerfile:

```sh
export OS_CONFORMANCE_PODMAN_DIR=/tmp/os-l0a-podman
mkdir -p "$OS_CONFORMANCE_PODMAN_DIR/storage" "$OS_CONFORMANCE_PODMAN_DIR/run"
umask 022
podman --root "$OS_CONFORMANCE_PODMAN_DIR/storage" \
  --runroot "$OS_CONFORMANCE_PODMAN_DIR/run" --storage-driver overlay \
  --cgroup-manager=cgroupfs build --network host --layers \
  -f containers/compiler/Dockerfile -t localhost/os-conformance-compiler:baseline .
export OS_CONFORMANCE_COMPILER_IMAGE=localhost/os-conformance-compiler:baseline
```

The optional prebuilt-image path verifies the compiler sources, lockfile and Binaryen bytes against this checkout before starting Wrangler. It still uses the actual ModuleCompiler service, container transport, authorization and R2 transform cache. It does not redirect compilation requests to a standalone server. The image identity and verified hashes are in `evidence.json`. The default remains building the repository Dockerfile directly.

Successful runs remove their disposable state. A failed run prints its retained state/log directory for investigation. Only processes started by the runner are stopped. A container's first build can require several minutes and network access.

`--check` validates the registry/table and reruns both targets in a new temporary output directory, requiring byte-identical `baseline.json` for the same available capability profile. Host PID 1 names and `/proc/1/exe` read errors live in `linux-evidence.json`, outside comparison signatures. When mount namespaces or subordinate mappings are unavailable, the runner produces explicit skips; those are a different capability profile, not a matching reproduction of the complete Linux reference. `--check --recorded` only checks saved artifacts and does not test the current runtime.

Use `--out /tmp/my-compat` on both target commands to write another result set without changing the committed results. `--report` regenerates the Markdown table after reviewing the difference registry. Do not automatically approve new observations: each entry needs an owning #44 sub-issue (or an explicit permanent provider limitation) and a reason.

## Evidence and comparison

- `baseline.json` contains the normalized JSON lines from the program and script observations, grouped by target/filesystem. The program emits every attempted step with a call and either `ok`, an errno name, or an explicit skip. IDs are equality observations, owners/groups are compared with the calling account and parent directory, and paths in cwd results use `$ROOT`. There are no raw PIDs, timestamps, randomized source paths or credentials in this file.
- `matrix.md` is generated from those observations, including successful steps, failures and skips. A skip is incomparable, never a passing result. A missing profile/case or duplicate step fails validation.
- `expected-differences.toml` explicitly lists each differing case/filesystem and a signature of both traces. An unlisted difference, a changed trace, or a listed difference that disappears fails the check. `[[observation]]` entries separately track facts without a comparable Linux fixture: they fail on changed evidence or reclassification, but do not claim automatic convergence. Later steps must review changed evidence and delete compatibility entries as their differences disappear. Allowed follow-up issue IDs are data in `follow-up-issues.json`; add newly created #44 sub-issues there rather than editing validator code.
- `evidence.json` and `linux-evidence.json` record the checkout `HEAD` and dirty flag captured before the run, without requiring any remote-tracking ref. They also record browser/host details and source-fragment presence used to attribute startup and flush behavior. The unrelated `.worktrees/` directory is excluded from the dirty flag. Host startup details retain the actual read error code. Essential `baseline.json` is saved before the auxiliary timing/evidence files. Source inspection is labeled separately from executable observations; a changed source fragment is recorded rather than blocking measurement.
- `latency.json` and `linux-latency.json` keep noisy measurements separate from deterministic behavior. Cold means the first invocation of that operation in the fresh profile/filesystem; warm means its immediate repeat. These measurements do not evict host, provider or browser caches. Both probe binaries use release builds. File operations include executable launch and return. Shell timing ends at the first interactive shell prompt; `ls -l /usr/bin` measures the shared system tree from each filesystem cwd. The stat target is eight components below the test root; reads/writes transfer 1 MiB.

The same Rust source uses native libc/filesystem calls on Linux and WASI preview 1 plus the existing `os-posix` adapter on OS. WASIX `chdir`/`getcwd` imports observe the runtime cwd rather than maintaining a test-side cwd. ACL adapters encode the same entries in Linux's binary xattr format and the existing OS JSON xattr format. Path identity reads the ABI `Stat` result, and missing `dev`/`ino` is explicit. This ABI has no `Fstat` call and its raw descriptors differ from libc descriptors: retained-fd identity therefore uses the Preview 1 inode only when nonzero, and marks device identity unavailable because `writeFilestat` fabricates dev=1. Missing values never compare equal. No unsupported syscall is emulated. All ABI errno names are normalized; Preview 1 has no ENODATA number (the runtime aliases it to ENOENT), so ENODATA is preserved only where the named ABI exposes it. Unknown errors do not use Rust `ErrorKind` debug strings.

## Profiles and limits

The five OS profiles are an authenticated account's cloud home, OPFS browser storage, a real host-backed `FileSystemDirectoryHandle` acquired with Chromium CDP drag selection, a real Linux `os-local-helper` process, and a shared mount forced through the relay (`p2p: false`, with transport inspection). The host directory is not replaced by OPFS or a mock. The directory profile uses full Chromium with a fresh persistent profile's file-system read/write guard set to allow, then explicitly selects only the disposable fixture via CDP. Other accounts use separate incognito profiles. These are real host-backed handles and bytes; this is not manual native-picker coverage. Chromium's [permission-context implementation](https://chromium.googlesource.com/chromium/src/+/main/chrome/browser/file_system_access/chrome_file_system_access_permission_context.cc) documents the allow guard used for this fixture.

Linux uses actual bind mounts of one source and a separate tmpfs for cross-mount operations. The namespace ends with the process. When namespaces or subordinate mappings are unavailable, the runner records why those cases could not run. The no-namespace fallback skips absolute cross-mount symlinks as well as other mount-dependent cases; its temporary target exists, so an incomplete fixture cannot turn ENOENT into a false pass. Two mapped Linux users and two authenticated OS accounts create files under a setgid directory with a default ACL and umask 027. For private providers, the second account accesses the same tree through the existing authenticated export path, since private workspaces are account-scoped. This extra transport is part of the recorded current behavior.

Cloud alias/remount/unmount operations have no corresponding attachment API today and are explicitly unavailable. `chroot`, `mount`, and `umount` are absent from the OS syscall ABI; the runner records that fact instead of pretending the GUI mount method implements them. Provider unmount lifetime is tested separately by pausing a live executable on stdin, detaching its mount, then resuming its retained descriptor or cwd operations.

The native host is headless: it has no corresponding four GUI applications or browser OS tabs. Those Linux process-profile rows explicitly state that limitation. OS script observations open the actual built-in applications, inspect processes and PID 1, and test cross-tab visibility with a live process. The fixture waits for its completed `cat /proc/1/cmdline` process to be reaped before taking the idle Files snapshot. Startup ownership attribution also names the inspected source. These process facts are `[[observation]]` records, not permanent Linux differences; no Linux GUI behavior is fabricated to make the comparison pass. This is an L0 baseline, not a GUI protocol gate or a claim of full POSIX compatibility.

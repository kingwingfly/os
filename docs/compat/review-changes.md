# PR #66 review measurement changes

Compared with reviewed commit `c71443c`. **No result rows changed: 0 of 120 filesystem rows and 0 of three process observations. The entire raw `baseline.json` is byte-identical to that commit.** Outcomes, normalized signatures and classifications are unchanged: **15 same, 105 differences/skips and three process observations**. The regenerated matrix and existing difference registry are unchanged. No OS runtime semantics or architecture decisions were changed.

| Changed result rows | Count |
| --- | --- |
| Filesystem rows | 0 of 120 |
| Process observations | 0 of 3 |

Full recordings were required this round because the Linux remount guard and the OS tab-process identity check change measurement logic. The Linux probe now records and stops on failed detach before attempting another bind mount; failed re-attachment also stops before dependent observations. Fault injection covers remount detach, remount attach and held attach, preserving error rows and panic diagnostics. Successful remount observations are unchanged. Tab visibility now compares PID, executable path and argv together, with one shared sleep predicate and process-list helper; the measured visibility result remains unchanged.

## Cleanup and small review fixes

Process cleanup checks the owned process group's existence independently of its leader. A reaped leader does not cancel escalation or finish cleanup while descendants remain; the first ESRCH ends signalling for that group. Regressions cover a resistant TCP listener whose leader exits both before and during cleanup and require group disappearance and a closed port. Development forwards SIGINT/SIGTERM to Wrangler and closes Podman only after Wrangler exits. Both signal tests delay Wrangler cleanup, make an engine request through the still-live proxy, then assert Podman shuts down last.

Service readiness diagnostics are preserved together with a subsequent cleanup error. Missing Miniflare image declarations produce a real lookup failure before environment mutation, while explicit image configuration bypasses discovery. Provenance exclusions are root-anchored even for subdirectory queries. Compiler-image references cannot begin with options. The isolated server bootstrap uses the runner's `process.execPath`. Redundant held-probe cancellation assignment is removed without claiming to resolve the broader deadline/lifetime finding below.

Linux and all five OS cold/warm latency records and provenance were regenerated. Both committed evidence files identify clean source `23cc5f89f38ab74426c4f3fafa296bccc25e9452` with `dirty:false`. Timings are noisy evidence, not claimed runtime speedups. The full recordings rebuilt web assets, the WASI probe, release helper and Worker and verified the existing compiler image against the checkout.

## Deferred items

Ten of the fifteen comments on `c71443c` are fixed. The other five are all tracked in [#67](https://github.com/kingwingfly/os/issues/67), linked to #46, with original review links, reasons and acceptance tests:

- Docker/podman-docker endpoint discovery across CLI versions.
- Held-probe phase deadlines and awaiting cancelled-process termination.
- Transient Podman runroot lifecycle with persistent image-store compatibility.
- Development shared-service publication/reuse policy and concurrent ownership.
- Using the real ABI package/workspace manifest in the mutation gate.

The current full measurements do not claim coverage of those deferred failure/portability scenarios. Commands and prerequisites are in [README](README.md); the PR records this revision's exact checks, results and exclusions.

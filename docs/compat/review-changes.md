# PR #66 review measurement changes

Compared with reviewed commit `7ddf26a`. **No normalized compatibility or process row changed its result, signature or classification.** The matrix still contains **120 filesystem rows (15 same and 105 differences/skips), plus three process observations**. No difference-registry entries or signatures were added, removed or changed. No OS runtime semantics or architecture decisions were changed.

| Changed result rows | Count |
| --- | --- |
| Filesystem rows | 0 of 120 |
| Process observations | 0 of 3 |

The raw cloud trace now emits the alias, mount-parent, remount and held-unmount skips from the Rust `basic-cloud` mode, at the probe's capability boundaries. Previously the runner executed and discarded alias/mount-parent observations, then appended replacement skips. The unsupported operations are no longer attempted, and the skip rows occur earlier in the raw JSON array. Every row retains the same outcome and normalized comparison signature. Native and all four other filesystem raw traces are unchanged.

The native two-account fixture now enters its mounted tree before dropping privileges and uses relative paths. Private TMPDIR ancestors no longer cause unrelated EACCES results. The regression gate requires successful create/stat/setgid inheritance for both creators under a private ancestor and identical observations under an ordinary temporary directory. The previously committed full reference used a searchable path, so its two-account outcomes do not change.

## Runner corrections and evidence

Playwright SIGINT/SIGTERM handling is disabled in the shared launch options so the runner's cleanup scope can finish. Real SIGINT and SIGTERM tests during OS measurement verified exit 130/143, the retained-state notice, closed server ports, stopped owned processes/Podman sockets and removed labeled containers. Reaped child PIDs are never used for later process-group signals.

Development uses a connect-only liveness check before borrowing a shared Podman socket. A stale socket gets a replacement on a private session path; the shared name is never unlinked. Potentially failing image discovery precedes environment mutation. The image cache defaults to a per-user directory and requires current-UID ownership, mode 0700 and a real directory rather than a symlink before images are loaded. The documented dedicated validation cache meets these checks. Container-list errors preserve their status/body, non-array responses are rejected, and only DELETE tolerates 404.

The browser gate and runner now share the exact CDP selection, permission request, profile setup and DISPLAY-free launch path. The account fixture checks distinct primary gids and overlaps independent creator account boots. Server/inspector ports are reserved together. Deployment reuses the command-availability helper, and xtask help lists the recorded and report modes.

All Linux and OS cold/warm latency samples and provenance are regenerated separately from deterministic comparison outcomes. These noisy timings are not claimed as runtime speedups. The full recordings rebuild web assets, the WASI probe, release helper and Worker, and verify the real cached compiler image against the checkout. Commands, prerequisites and measurement limits are in [README](README.md); the PR records every check completed and the checks not run for this revision.

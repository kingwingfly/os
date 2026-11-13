# PR #66 review changes

This report covers the review of `dcc9daa`: **10 of 12 comments are fixed; two are added to [#67](https://github.com/kingwingfly/os/issues/67)**, the follow-up linked to #46.

## Development bootstrap and cleanup

The dev-owned Podman service starts in its own process group. SIGINT/SIGTERM delivered to the dev foreground group therefore leave the engine available while Wrangler drains. Tests send signals both to the dev PID and to the entire group; a delayed Wrangler fixture still completes an HTTP cleanup request through Podman before the service stops.

Dev installs its signal handlers before bootstrap. Interrupting a pending startup aborts and cleans the acquired service; failure to spawn npx also closes it. Regression tests verify service death and removal of its private socket directory for both interrupts and the spawn-error path.

Missing Miniflare source or egress-image declarations now skip only the optional override for dev. The service, Docker shim and proxy remain usable. Discovery happens before service creation, and conformance opts into strict discovery. Tests cover both a missing source file and a source without the declaration: strict mode fails before spawning anything, while optional mode successfully serves an engine request without the override.

Bootstrap awaits the proxy's listening event, so bind errors reject and clean up instead of escaping as uncaught exceptions. A bind-failure regression verifies the service stops and the environment remains unchanged.

## Other small corrections

- Signalled server death ends the OS startup poll immediately.
- Both latency runners validate prepare results and preserve the setup phase and errno instead of failing at the next operation.
- An explicitly empty Podman cache path is rejected before resolving or creating directories.
- Artifact writers, readers/checks and provenance exclusions share one generated filename registry; a regression verifies the complete emitted file set.
- The proxy's explicit `destroyAllSockets` operation closes upgraded streams without overriding Node's ordinary `closeAllConnections` method; an actual upgraded-socket test covers it.
- The unused single-port helper and OS skip import are removed.

## Measurement status

No new Linux or OS measurements were recorded this round. Successful probe sequences, observation fields, artifact filenames and timed operations are unchanged; the corrections concern bootstrap, failure handling and bookkeeping. The six generated files and the difference registry are unchanged from `dcc9daa`. The existing 123-row record still passes `--check --recorded`: 15 same, 105 differences/skips and three process observations.

The last full recordings and independent byte-for-byte reproduction remain those documented by `dcc9daa`. Both evidence files still identify measured source `23cc5f89f38ab74426c4f3fafa296bccc25e9452` with `dirty:false`; they have not been relabeled as measurements of this revision. No new result changes or timing comparisons are claimed.

## Deferred items

The two new deferrals in #67 concern preserving process-group ownership after the leader/group exits, and bounded escalation with survivor reporting/retryable cleanup errors. The five earlier CLI, held-probe, runroot, shared-service and ABI-manifest items remain there. This round does not claim those seven findings fixed. The PR records the exact checks run, their results and what was not run.

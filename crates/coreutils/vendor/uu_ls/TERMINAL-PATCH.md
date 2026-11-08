# uutils ls platform patch

Vendored from crates.io `uu_ls` 0.12.0, upstream commit
`dc1efd89948a9ca4c78c3a4b9a6ac891019a8c69`, directory `src/uu/ls`.
The original MIT license is retained in LICENSE. Cargo selects this copy through
`crates/coreutils/Cargo.toml` for ls, dir and vdir.

WASI preview 1 lacks uid, gid, Unix modes and ACL metadata. Upstream's non-Unix
fallback prints placeholder owners and synthesized permissions. The platform patch
uses `terminal-worker-posix` to read stat/lstat through the existing OS ABI, with
the executable's credentials. It caches the result per PathData, reports failures
instead of inventing ownership, and supplies ownership, link counts, permission
bits, ACL markers and executable suffixes to upstream formatting.

The CLI, traversal, sorting, quoting, help and output layout remain uutils'. The
browser shell neither interprets ls arguments nor post-processes its output.
Files has its own structured listing through filesystem calls.

Modified upstream files: Cargo.toml, src/ls.rs, src/display.rs. Keep platform-only
changes isolated when updating uutils. The registry copy is not modified.
`tests/executable-resolution.spec.js` covers shell parity, metadata, permissions,
symlinks, help and failures in Chromium and Firefox. `crates/posix` tests malformed
and denied replies. Broader WASI compatibility remains tracked in issue #40.

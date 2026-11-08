# uutils mkdir WASI platform patch

Vendored from crates.io `uu_mkdir` 0.12.0, upstream commit
`dc1efd89948a9ca4c78c3a4b9a6ac891019a8c69`, directory `src/uu/mkdir`. The original MIT license is
retained in LICENSE. Cargo selects this copy through `crates/coreutils/Cargo.toml`.

WASI preview 1 has no mkdir mode or umask. Use the shared POSIX compatibility
adapter for mode-aware directory creation and the process-local umask primitive.
Keep upstream argument parsing, diagnostics, parent traversal and its shaped-mask
algorithm: parents ignore `-m` and retain owner write/search; explicitly requested
leaf permissions are applied atomically at creation, with normal default-ACL and
setgid inheritance. No browser command fallback or command-specific syscall.
Explicit set-ID bits, which mkdir(2) ignores, are applied afterwards through
chmod(2), retaining inherited setgid as GNU mkdir does.

Modified upstream files: `src/mkdir.rs`, `Cargo.toml` (WASI adapter dependency).

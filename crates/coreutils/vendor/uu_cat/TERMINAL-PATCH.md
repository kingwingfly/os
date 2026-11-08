# uutils cat WASI platform patch

Vendored from crates.io `uu_cat` 0.12.0, upstream commit
`dc1efd89948a9ca4c78c3a4b9a6ac891019a8c69`, directory `src/uu/cat`.
The original MIT license is retained in LICENSE. Cargo selects this copy through
`crates/coreutils/Cargo.toml`.

Upstream gates character/block device recognition on `cfg(unix)`. WASI exposes
these file types too, but Rust's WASI `FileTypeExt` is unstable. Use wasi-libc's
ordinary `stat` for file types stable Rust cannot classify, so cat opens and reads
devices through the same file descriptors as other inputs. This also covers local
PTY devices without a remote metadata request.
Use WASI preview 1's ELOOP value (32) for the existing symlink-loop diagnostic,
instead of Linux's 40. CLI options, stream processing and formatting are unchanged.
No command-specific runtime syscall, frontend fallback or registry edit is added.

Modified upstream files: `src/cat.rs` and `Cargo.toml` (WASI libc dependency). `tests/live.spec.js` exercises character
device reads and permissions; `tests/links.spec.js` covers symlink-loop errors;
the normal pipeline/PTY tests continue to exercise this same executable.

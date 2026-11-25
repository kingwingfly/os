# L6a: Native Terminal Emulator (`/usr/bin/terminal`) and Interactive Shell (`/usr/bin/osh`)

Issue `#62` replaces the retired in-page Leptos shell (`crates/frontend/src/shell.rs`, `shell/commands.rs`, `shell/jobs.rs`) with two ordinary unprivileged WASI processes that communicate strictly over standard POSIX PTYs and GUI v1 `AF_UNIX` sockets:

- **`/usr/bin/terminal`** (`crates/services/src/terminal.rs`, `crates/services/src/bin/terminal.rs`): Ordinary GUI v1 client connecting to `/run/gui/seat0.sock` (`Hello { versions: [1], required: ["document", "clipboard"] }`), presenting a `SurfaceRole::Window` + `SurfaceKind::Document` surface with `app_id: "terminal"` using the sealed bundle `/usr/share/gui/terminal/terminal.json`.
- **`/usr/bin/osh`** (`crates/services/src/osh.rs`, `crates/services/src/bin/osh.rs`): Ordinary interactive & script shell spawned on the slave side of each tab's `/dev/ptmx` -> `/dev/pts/<N>` pair with `setsid: true` and `ctty_fd: Some(0)`.
- **Desktop-action CLI utilities** (`crates/utilities/src/desktop_actions.rs`): `/usr/bin/{open,vim,man,present,stream,upload}` applets speaking newline-delimited JSON over `/run/user/<uid>/desktop-actions.sock` (`0600`, `SO_PEERCRED`-verified `uid == session_uid`), with stdout fallback for `man` when non-TTY or socket unavailable and `SIGINT` cancellation for interactive waits (`vim`, `upload`, `stream`).

## Privilege & Isolation Invariants

1. **Zero `gui_*` Wasm imports or exports**: Neither `/usr/bin/terminal` nor `/usr/bin/osh` imports or exports any `gui_*` host function (verified automatically in `tests/gui-protocol.test.mjs`).
2. **Unprivileged `SurfaceKind::Document` only**: `"terminal"` is removed from the `compositor.rs` `SurfaceKind::Host` compat allowlist and `compat-bridge.js` `APPS`. Any peer — including the compat proxy — requesting `SurfaceKind::Host { component: "terminal" }` receives `EPERM`.
3. **Frozen syscall ABI**: Zero changes to `crates/abi/src/lib.rs` (74 variants verified by `node scripts/conformance/check-abi.mjs`). `setsid` and `ctty_fd` are optional fields on the existing `os.posix_spawn` JSON payload.
4. **POSIX `sh` preserved**: `/bin/sh` and `/usr/bin/sh` remain `dash`, `/etc/passwd` is unchanged, and `/shell.html` continues to boot directly without the compositor or desktop shell.

## Session, PTY, and Hangup Semantics

1. For each tab, `/usr/bin/terminal` opens `/dev/ptmx` (`O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC`), queries `/dev/pts/<N>` via `TIOCGPTN`, unlocks with `TIOCSPTLCK(0)`, sets initial window dimensions with `TIOCSWINSZ`, opens `/dev/pts/<N>`, and spawns `/usr/bin/osh` with `dup2(slave -> 0, 1, 2)`, `setsid: true`, `ctty_fd: Some(0)`, `TERM=xterm-256color`, `COLORTERM=truecolor`, and `SHELL=/usr/bin/osh`. The parent immediately closes its slave descriptor.
2. In `web/wasi/exec.mjs`, `spawn` invokes `setsid` right after `fork` and `TIOCSCTTY` on `cttyFd` after descriptor inheritance so `/usr/bin/osh` launches as the controlling session leader of `/dev/pts/<N>`.
3. When a tab closes, `/usr/bin/terminal` drops its PTY master descriptor. `hangupTerminal` delivers `SIGHUP` + `SIGCONT` to both the foreground process group and the controlling session leader (`osh`). `osh`'s `SIGHUP` handler forwards `SIGHUP` + `SIGCONT` to every tracked running/stopped job process group before exiting.
4. When a tab's shell exits voluntarily (`exit` or `Ctrl+D`), the emulator detects PTY hangup/child reap, keeps the emulator window and sibling tabs alive, renders `[Process exited with status N]`, and offers a **Restart** control.
5. An optional per-user control socket `/run/user/<uid>/terminal.sock` (`0600`, `SO_PEERCRED.uid == getuid()`) lets Files executable launches (`*.wasm`) open a new tab inside an already-running Terminal window without disturbing unfinished input in existing tabs.

## Sealed Document Wire Protocol (`<= 4096` UTF-8 bytes/frame)

- **Document -> `/usr/bin/terminal`** (`DocInMsg`):
  - `{"t":"ready","cols":N,"rows":M}` / `{"t":"resize","cols":N,"rows":M}`
  - `{"t":"in","d":"..."}` (chunked `<= 1024` chars)
  - `{"t":"new_tab"}`, `{"t":"select_tab","id":N}`, `{"t":"close_tab","id":N}`, `{"t":"restart_tab","id":N}`
  - `{"t":"copy","text":"..."}`, `{"t":"paste"}`
- **`/usr/bin/terminal` -> Document**:
  - `{"t":"tabs","active":N,"tabs":[{"id":N,"title":"...","exited":null|code}]}`
  - `{"t":"frame","tab":N,"cols":C,"rows":R,"total":T,"cursor":{...},"alt":bool,"app_cursor":bool,"bracketed_paste":bool,"exited":null|code,"state":"idle"|"busy"|"exited","cwd":"...","full":bool,"lines":[[idx,runs],...]}`
  - `{"t":"focus"}`
  - Any payload exceeding the 4096-byte `MAX_DOCUMENT_MESSAGE` limit is transparently split at UTF-8 codepoint boundaries into `{"t":"chunk","id":seq,"i":idx,"n":count,"d":"..."}` frames and reassembled inside `web/gui/terminal/terminal.js`.
- **Shell integration (`OSC 7` & `OSC 133`)**:
  - `/usr/bin/osh` emits `OSC 7;file://os<cwd>\x07` on prompts and `cd`, plus `OSC 133;A`/`B`/`C`/`D;<code>` prompt/execution markers. `/usr/bin/terminal`'s `OscTracker` updates tab/window titles (`ClientReq::SetTitle`), exposes `data-state` (`idle`/`busy`/`exited`) and `data-cwd` on `#viewport`, and coalesces active-tab frames at ~16 ms intervals.

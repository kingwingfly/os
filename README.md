# OS

A browser OS with WASI/WASIX processes, a filesystem, accounts, Unix-style permissions, a terminal, and desktop applications. A dedicated client kernel runs in each tab; a Rust Worker and Durable Objects authorize shared resources. R2 stores files, and containers provide archive/media accelerators. Rust and Leptos implement the desktop. Configuration uses `wrangler.toml`.

For maintainers and incoming agents, start with [AGENT.md](AGENT.md).

## Project naming and existing installations

The project is **OS**, hosted at [kingwingfly/os](https://github.com/kingwingfly/os). Packages use `os` and `os-*`; browser APIs use `window.os`; program extensions use the `os` WASM import namespace. The desktop's Terminal remains a terminal emulator, with ordinary terminal/PTY names.

`wrangler.toml` describes a new `os` installation with `os-files` storage and `OsAuthority`. For an existing installation, use `wrangler.legacy.toml` with the same persisted state, secrets and resources: `npm run dev -- --config wrangler.legacy.toml` or `npm run deploy -- --config wrangler.legacy.toml`. It keeps the original service, R2 bucket and Durable Object identities while running the OS code. Changing those names alone does not move stored data; a cross-Worker move needs a separate [Durable Object migration](https://developers.cloudflare.com/durable-objects/reference/durable-objects-migrations/).

The remaining legacy product identifiers are compatibility boundaries: the old Durable Object export, R2 ownership marker and frontend content ID, migration of session/guest cookies and saved browser preferences, and acceptance of the old `terminal` WASM import namespace for existing uploaded programs. New cookies use `os_session`/`os_guest`; a successful login/logout overrides migration, and old cookies are expired so logout cannot restore an earlier login. New preferences take precedence when both names exist.

## Local development

Prerequisites: Node.js, Rust with the `wasm32-unknown-unknown` and `wasm32-wasip1` targets (the second for uutils' coreutils, in /usr/bin), `worker-build 0.8.5`, `wasm-bindgen-cli 0.2.129`, and clang with its WebAssembly target plus `llvm-ar`, which compile the tree-sitter grammars of the code previews. The wasm-bindgen CLI must match the Rust dependency version in `Cargo.lock`. Archive jobs (`zip`, `unzip`, `tar`) run in a container, which needs Docker or Podman; see [Archives](#archives).

```bash
rustup target add wasm32-unknown-unknown wasm32-wasip1
cargo install worker-build --version 0.8.5 --locked
cargo install wasm-bindgen-cli --version 0.2.129 --locked
npm ci
npm run setup
npm run build:web
npm run dev
```

In another terminal:

```bash
npm run seed
```

Open **http://127.0.0.1:8787**. `npm run dev` and direct `wrangler dev` both use port 8787, the one configured in `wrangler.toml`. Local development requires no Cloudflare login or account access.

`setup` creates `.dev.vars` and `.local-password` only when credentials do not exist. Both are gitignored. `ADMIN_PASSWORD` bootstraps root only during the first database initialization; later changes use `passwd`. Changing `.dev.vars` does not reset an existing root password. `SESSION_SECRET` is a password-hash pepper: preserve it when restoring data.

`npm run dev` runs `scripts/dev.mjs`, which starts `wrangler dev` with its arguments. Where Docker is missing and Podman present, it starts Podman's API service for the session and points wrangler at it, through `scripts/podman-docker.sh` (a shim for the Docker flags Podman's builder lacks) and `scripts/podman-proxy.mjs` (which removes the memory swappiness workerd asks for in every container; crun refuses it on cgroup v2 wherever cgroups apply, as in a systemd user session: `cannot set memory swappiness with cgroupv2`), with cgroups managed by Podman itself when there is no systemd user session. Rootless Podman needs subordinate ID ranges for your user in `/etc/subuid` and `/etc/subgid` (for example `sudo usermod --add-subuids 165536-231071 --add-subgids 165536-231071 $USER`, then `podman system migrate`). The first start builds the job container's image, pulling `rust:1-alpine`; later starts reuse it. With Podman, start through `npm run dev`, not `npx wrangler dev`: wrangler alone, even with `WRANGLER_DOCKER_BIN=podman`, passes `podman build` flags it rejects (`unknown flag: --provenance`) and finds no Docker socket. To pass wrangler options, add them after `--`, as in `npm run dev -- --persist-to /tmp/state`.

`npm run deploy` deploys: it runs the full build (`scripts/build.mjs`, the page in `dist/`), then `wrangler deploy`, which builds the Worker and the job container's image, through `scripts/podman-docker.sh` where Docker is missing and Podman present. `wrangler deploy` alone builds only the Worker, as `[build]` in `wrangler.toml` is what `wrangler dev` reruns on every Worker or core change, and uploads `dist/` as it is, stale or not. Options after `--` go to wrangler, as in `npm run deploy -- --dry-run`. The secrets come first, once: `npx wrangler secret put` for `ADMIN_PASSWORD`, `SESSION_SECRET`, and, for live sound, `REALTIME_APP_ID` and `REALTIME_APP_TOKEN`.

Rebuild frontend changes with `npm run build:web` (currently `npm run build` builds the same frontend). Wrangler watches Worker/core Rust sources. If newly generated lazy chunks return 404, restart your local Wrangler process after the build. Avoid concurrent Worker builds into the same `crates/worker/build` directory.

`seed` is local-only, defaults to port 8787, and preserves existing files. It installs `welcome.md`, `readme.txt`, `demo.slides.md`, and a generated `media/signal.wav`. Use `OS_PORT` to select another local instance. After changing root's password, supply the current password through `OS_PASSWORD` rather than changing the bootstrap secret.

## Accounts and permissions

Anonymous visitors are the `guest` account (uid 65534, group `guest`), which cannot sign in, as `nobody` cannot on Linux. The server checks permissions on every request, as Linux does: an owner by the owner bits, a named user by its ACL entry, members of the owning or a named group by those entries (any may allow), everyone else by the other bits. Classes do not combine: an owner uses owner bits even if other bits are more permissive. Root (uid 0) retains full control.

| Operation | Required permissions |
| --- | --- |
| Read, download, HEAD, Range | File r; every ancestor directory x |
| List a directory | Directory r+x; ancestors x |
| Enter a directory | Directory and ancestors x; without r its listing is unavailable |
| Create a file/directory | Parent w+x |
| Delete a file | Parent w+x, independent of the file write bit |
| Recursively delete a directory | Parent w+x and every emptied directory r+w+x; validate the whole tree first |
| Overwrite a file | File w; ancestors x |
| Remove or rename in a sticky directory (`+t`) | Also be the entry's owner, the directory's owner, or root |
| chmod, setfacl | Owner or root |
| chown, chgrp | Root can change owner/group; ordinary owners can select only a group they belong to |
| Hard link (`ln`) | Directory w+x; without root, own the file or may read and write it (protected_hardlinks) |
| Follow a symbolic link in a sticky directory others may write | Own the link, or the directory's owner does (protected_symlinks) |
| `user.*` attributes (setfattr) | File w; on a sticky directory, its owner |

Every request is checked when it is made, reads by path included: a `chmod`, `chown`, `setfacl`, removal or sign-out refuses the next one at once. What reads a file in many ranges reads it by a token instead: `open` of a whole file for reading gives one, the player plays from `GET /api/file?token=` (and /usr/bin's programs read large files so), and the Worker takes the kernel's word for a minute, so that a video's ranges do not each ask it. The kernel asks again then whether the descriptor is still open, still its session's, and its account may still read the file: a change of permission, a `close` or signing out stops such a read within a minute. A token is its session's; any other's request with it is refused.

Defaults are files 644, directories 755, and user homes 700. Public files inside private homes also need traversable ancestors; for example, home 711 and file 644 allow reading a known path without listing the home. Use 755 to permit listing.

The executable bit is stored and displayed, but files and commands never execute on the host. The umask is 022 and cannot be changed. Omitted chmod classes apply to all three classes.

- **Links.** Paths name inodes. A hard link (`ln`) is another name for an inode: content, owner, mode, ACLs and attributes are shared, and the inode goes with its last name; directories cannot be hard-linked. A symbolic link (`ln -s`) holds a target path, relative to its directory or absolute, which may not exist; its mode is always 777. Every path is resolved as the kernel resolves one: each link on the way is followed with the caller's search permission checked at every directory, at most 40 links per path. Commands follow a link at the end of a path except those that act on names (`rm`, `mv`, `ln`, `readlink`, `mkdir`, `chown -h`, `ls -l`/`-d`). `..` is resolved in the path as typed, as the shell's `cd` does, so `cd link` then `cd ..` comes back.
- **Special bits.** setgid on a directory gives what is made in it the directory's group, and the bit to new directories; sticky (`+t`) lets only an entry's owner, the directory's owner or root remove or rename it. setuid is kept and shown. Without root, setgid needs the file's group to be one of the caller's. Changing a file's owner clears setuid, and setgid if the group may execute it.
- **ACLs.** `setfacl` adds named user and group entries; the mode's group bits are then the mask, which bounds them, so `chmod` changes the mask. A directory's default ACL is what is made in it gets, in place of the umask. `ls -l` marks an ACL with `+`; `getfacl` shows `#effective` rights.
- **Extended attributes.** `setfattr`/`getfattr` keep `user.*` attributes (read to get, write to set) and root's `trusted.*`, up to 4 KB per inode.

### Identity changes and sudo

- `su [-] [USER]` switches this browser session (default root). Ordinary users supply the target password; root can switch to an enabled account without it. `-` enters the target home.
- `login [USER]` opens a username/password dialog and enters the account home.
- `sudo COMMAND` elevates only that command and leaves the current identity unchanged. Ordinary accounts must belong to **wheel**. guest cannot sudo. Verify the caller's own password; authorization lasts five minutes, and membership is rechecked for each request. `sudo -k` revokes it.
- `sudo -u USER` intentionally switches the browser account and enters its home. This is this terminal's simplified behavior, not Linux run-as syntax; no trailing command is accepted.
- `exit` and `logout` revoke the session and return directly to guest at `/`; there is no account stack.
- Permission failures never implicitly sign in as root. Browser interactions such as open, vim, and upload use the current identity.

Root and system groups are protected from deletion; root's identity fields are fixed.

### Example workflow

```text
su root
groupadd research
useradd -m -d /home/alice -G research alice
passwd alice
mkdir /shared
chown root:research /shared
chmod 770 /shared
usermod -aG wheel alice
su - alice
touch notes.md
vim notes.md
sudo chmod o+r /shared/result.md
sudo -k
exit
```

Create `/shared/result.md` before the example chmod. All passwords are entered in dialogs, not in command history.

### Command reference

Browser commands generate help and manual pages from their clap definitions (`crates/core/src/cli`). External programs own their options and help: use `ls --help` or `help ls`; `ls -h` means human-readable sizes. A wrong argument gets one line saying what was wrong, such as `rm: missing PATH...; rm -h shows how to use it`. Help runs before authentication or side effects, including `sudo chmod -h`. `--` terminates help/option interpretation where supported, as in `rm -- -h`.

| Command | Implemented syntax |
| --- | --- |
| Files | `ls [-l] [-a] [-d] [-t\|-S] [-r] [PATH]`, `stat [-L] [-c FORMAT\|--printf FORMAT] FILE...`, `df [-h] [FILE...]`, `cd [PATH/~]`, `pwd`, `open FILE`, `upload [DIR]` |
| Create/remove | `mkdir [-p] PATH...`, `rmdir [-p] DIR...`, `touch [-c] [-a] [-m] [-h] [-d DATE\|-t STAMP\|-r FILE] [--] FILE...`, `rm [-r] [-f] [--] PATH...` |
| Links | `ln [-s] [-f] [-n] [-L\|-P] [-v] TARGET... [LINK]`, `readlink [-f\|-e\|-m] [-n] FILE...`, `realpath [-e\|-m] FILE...` |
| Move/copy | `mv [-f\|-n\|-i] [-v] SOURCE... DEST`, `cp [-r] [-f\|-n\|-i] [-v] SOURCE... DEST` |
| Find | `fd [-H] [-t f\|d\|x] [-e EXT] [-d N] [-g\|-F] [-i\|-s] [-p] [-a] [-0] [PATTERN] [PATH...] [-x\|-X COMMAND...]` |
| Text | `echo`, `cat`, `head`, `tail`, `grep`, `wc`, `sort`, `uniq`, `xargs`, joined by `\|` |
| Permissions | `chmod [-R] MODE PATH...`, `chown [-R] [-h] USER[:GROUP] PATH...`, `chgrp [-R] [-h] GROUP PATH...`, `getfacl`, `setfacl`, `getfattr`, `setfattr` |
| Accounts | `useradd [-m\|-M] [-d HOME] [-g GROUP] [-G G1,G2] USER`; signed out, `useradd [-m\|-M] [--short-password] NAME` |
| Update account | `usermod [-a] [-G G1,G2] [-g GROUP] [-d HOME [-m]] [-l NEW] [-L\|-U] USER` |
| Remove account | `userdel [-r] USER`; an account in group guest, itself |
| Groups | `groupadd GROUP`, `groupmod -n NEW OLD`, `groupdel GROUP` |
| Password | `passwd [--force] [USER]` |
| Identity | `whoami`, `id [-u|-g|-G] [-n] [-r] [USER]`, `groups [USER]`, root-only `users` |
| Interface | `help`, `man [COMMAND]`, `clear`, `vim FILE` |
| /usr/bin (uutils) | `cut`, `tr`, `seq`, `printf`, `date`, `tee`, `truncate`, `split`, `od`, `base64`, `sha256sum`…, and `/usr/bin/NAME`, `coreutils NAME`, `syscall CALLS` |

Signed out, `useradd NAME` makes an account of one's own: the dialog asks for its password (12 characters unless `--short-password`), and the browser is signed in. The account has a private primary group and is in group `guest`; its home is `/guest/NAME`, mode 700, which `-m` makes (and `-M`, the default, does not), as useradd does. Other options need sudo. `/guest` is `root:guest` 1777, shared and sticky like `/tmp`. Registration is rate-limited per address, and guests may make at most 1,000 accounts. `guest` itself cannot have a password, be changed, or be deleted.

An account in group `guest` deletes itself: signed in as NAME, `userdel NAME` (with `-r`, its home too, if it is a directory of its own) asks for its password in the dialog, ends its sessions and returns the browser to guest. Root deletes any account; other accounts need it. As Linux userdel does, the account's group of the same name goes with it unless another account is in it, and `-r` keeps a home that is not the account's. A home not made yet is its account's to make: no one else may take its path, as anyone could in `/guest`.

An account sends at most three live sounds at once; starting one is rate-limited, as each makes a Realtime session.

As root, `useradd -m` creates the home; `-d` selects its absolute path. Without `-g`, a same-name primary group is created. New accounts need `passwd USER` before login. Names start with a lowercase letter and contain up to 32 lowercase letters, digits, underscores, or hyphens.

`usermod -G` replaces supplementary memberships; `-aG` appends. `-d PATH -m` atomically moves the home mapping while preserving content keys and permissions, without copying large files. The target must not exist or overlap another home. Without `-m`, only the account home field changes. `-g` changes the primary group, not existing file groups. `-L` locks and revokes sessions; `-U` does not restore those sessions.

`passwd` defaults to at least 12 characters and at most 512 bytes. `--force` explicitly permits short, nonempty passwords without bypassing identity or authorization checks. Ordinary users must supply their current password and can change only their own; root or sudo can reset others. Password changes revoke old sessions; self-service changes issue a replacement session to the current browser. Plaintext `useradd/usermod -p` arguments are not accepted.

Passwords use random salts, PBKDF2-SHA256 (100,000 iterations), and a server-side pepper. Sessions use random opaque tokens and HttpOnly/SameSite=Strict cookies, with Secure on HTTPS and an eight-hour lifetime. Authentication endpoints are rate-limited.

`touch` creates empty files with mode 644 (or what a default ACL gives), including extensionless names; of one that exists, it sets the times (`stat` shows them, in UTC, to the nanosecond), leaving content and mode intact. `-d DATE`, `-t STAMP` and `-r FILE` set another time than now, `-a` and `-m` only one of the two, `-h` a link itself; `-c` skips missing files. Now is the owner's or a writer's to set, another time the owner's, as on Linux. Reading does not change a file's access time: the store is mounted `noatime`. As GNU touch, each operand succeeds or fails on its own. `sudo touch` creates files as root for that command only.

`mkdir`, `rm`, `chmod`, and `chown` accept several paths. As on Linux, each path succeeds or fails on its own: failures are reported, and the others are still done; `rm -r` removes what it may of a tree and says what it may not, leaving the directories that hold it. As GNU's tools, they print nothing on success but with `-v`, and say why they failed as GNU's do (`rm: cannot remove 'x': Permission denied`). `rm` refuses `.` and `..`, and `-r` of `/`. There is no trash.

`mv` and `cp` follow Linux defaults: an existing file at the destination is replaced. `-n` never replaces one; `-i` asks for each. A directory is never replaced. `mv` moves names, so the inode keeps its owner, mode, ACLs and other names, and moving is instant whatever the size; it needs w+x on both parents, and a directory that changes parent needs w itself. A directory that is, or holds, an account's home cannot be moved, as a mount point in use cannot (use `usermod -d HOME -m`).

`cp` follows GNU cp. New nodes belong to the caller, with the source mode less the umask, or what the destination's default ACL gives. An existing file is written in place, keeping its owner, mode and other names (which need w on it). With `-f`, a file that cannot be written is removed and copied anew. `-p` keeps the mode, ACLs, times, and, as far as the caller may, the owner and group. Without `-r`, a link named is followed. With `-r`, links are copied as links, unless `-L` follows them all or `-H` those named. `-d` copies a file's several names as one file; `-a` is `-dpR` plus extended attributes. Copying a file onto another of its names is refused ("the same file"), as is writing through a dangling link. Copies share the source's immutable content, so they are instant too; editing either later keeps the other unchanged. A file still uploading cannot be copied yet.

`fd` follows sharkdp/fd: a regular expression (smart case) matched against names, or against whole paths with `-p`; `-g` for globs and `-F` for fixed strings; dot-names skipped unless `-H`. It searches only what the caller may list, reporting directories it could not read. `-x COMMAND` runs once per result and `-X COMMAND` once with all of them; `{}`, `{/}`, `{//}`, `{.}`, and `{/.}` are placeholders.

### Pipes

`A | B` passes what A writes to B. Commands that read input are the text filters `cat`, `head`, `tail`, `grep` (Rust regular expressions, as with `grep -E`), `wc`, `sort`, and `uniq`, plus `xargs`, which runs a command with the items it reads (`-0`, `-d`, `-n`, `-I`, `-r`, `-t`, and `-o` for terminal input). Consecutive external stages run concurrently through shared pipes when the browser is isolated. Stages involving shell builtins or browser UI actions pass buffered text. A trailing `&` starts an external pipeline as a background job; other shell operators (`&&`, `||`, `;`, `<`, `>`) are refused rather than taken literally; quote them to use them as text. Unquoted wildcards expand as in bash before a stage runs: `*`, `?` and `[...]` (`[a-z]`, `[!x]`) match names in each part of a path (`rm -rf *`, `cat docs/*.md`, `echo */`), sorted by byte order as `ls` sorts here (bash's order under `LC_ALL=C`: `B.md` before `a.md`), listed with the caller's permissions. Names starting with a dot match only a pattern starting with one; quoted or escaped wildcards are literal; a pattern that matches nothing stays as typed. Brace expansion (`{a,b}`) and `**` are not supported; `fd` fills that role. Quoting follows bash: single quotes keep everything as it is; within double quotes a backslash escapes only `$`, `` ` ``, `"`, `\` and a newline, and is kept before anything else (`grep "\d+"` searches for `\d+`); outside quotes it escapes any character.

```text
fd -e md | xargs wc -l
fd -0 -t f . reports | xargs -0 chmod 640
fd -e log -X rm
ls | grep -i draft | sort
```

## Editing and terminal interaction

`vim FILE` opens a floating CodeMirror editor with ordinary editing shortcuts, not Vim modes. Markdown, Rust, Python, JS/TS, JSON, HTML/CSS, C/C++, TOML, YAML, and shell have syntax highlighting. Use `touch README` before editing a new extensionless file.

- Ctrl/Cmd+S saves, Ctrl/Cmd+F finds, and Esc requests closing.
- Unsaved drafts require explicit discard and can be downloaded.
- UTF-8 text only, up to 2 MB. Files without write access are read-only.
- Saves use ETag conditions or create-only conditions. Concurrent edits/deletions reject overwrites and preserve the local draft.

The shell prompt follows the output in the scrollback. Programs run on a PTY when the browser is cross-origin isolated, with typing echoed at the program's cursor beside its prompt. `tty` names its slave as `/dev/pts/N`; `stty -a` shows its modes and size, and `stty sane` restores canonical input and echo. Terminal modes persist within a terminal tab. The PTY edits canonical input and delivers it when Enter is pressed; Ctrl+D sends a partial line or an empty read, Ctrl+C interrupts the foreground job, and Ctrl+Z stops it for `fg` or `bg`. Raw programs receive keys immediately, including arrows, Escape, and control bytes. With `-isig`, Ctrl+C and Ctrl+Z are bytes rather than signals. No-echo input stays invisible.

PTY input echo, stdout and stderr share a DOM cell grid, so prompts and replies stay together without added error prefixes. The grid supports cursor movement, erase/insert/delete, scroll regions, saved cursors, alternate screens, SGR colours/styles and safe OSC 8 links. A full-screen application's alternate buffer hides the transcript until it exits or is stopped; `fg` restores it. Resizing the terminal updates its rows and columns. The grid supports Unicode cell widths and combining marks, application cursor keys, bracketed paste and cursor-position replies. It is bounded to 500 columns, 200 rows and 2,000 scrollback lines; it is not a complete xterm implementation. Images, mouse reporting and signal-handler callbacks remain future work. Programs still have the existing output limit.

The client's terminal ioctls use `os.sys`: `TCGETS`, `TCSETS/W/F`, `TIOCG/SWINSZ`, `TIOCG/SPGRP` and `TIOCGPTN`. They act only on the calling process's terminal descriptors; a pipe returns `ENOTTY`. A run's pipeline and fork children form its process group; `fg` selects that group, and `TIOCSPGRP` can select only the caller's existing pipeline group. Arbitrary sessions and process-group creation are not implemented. Supported termios modes include canonical/raw input, echo, signal characters, CR/LF translation, output newline processing and `VMIN`/`VTIME`. Unsupported modes are refused. WASIX `tty_get`/`tty_set` also work with their [standard 24-byte tty record](https://github.com/wasix-org/wasix-libc/blob/main/libc-bottom-half/headers/public/wasi/api_wasix.h). That ABI exposes echo, line buffering and size, but no `ISIG` or process-group setter; the existing WASIX libc keeps its process-group bookkeeping internally. Signals retain their default actions here, so Ctrl+C can end an interactive shell that expects a signal handler. Without shared memory, sequential execution remains available but PTY ioctls report `ENOTTY`.

The main font is 20px. A file name keeps to one line; one too long slides back and forth to show the rest, when pointed at or focused, or always on touch screens. Terminal scrollbars are hidden while scrolling remains available. Files uses icons for media and file types; external programs control their own terminal text and ANSI colors.

Tab completes the token at the cursor, preserving surrounding arguments and existing quoting. A sole match completes immediately; multiple matches extend their common prefix and open a pager, navigated with Tab, Shift+Tab or up/down. Prefix matches take precedence over substring and subsequence matches. Directories end in `/`, ordinary paths stay unquoted, and spaces or shell characters are escaped. In command position, completion offers commands, directories and local programs; a local executable is spelled `./program.wasm`, with no inserted `open` or `cd`. A directory entered alone changes the working directory, while an existing command name keeps precedence. Completion also understands the last pipeline stage and commands run by `xargs`, `sudo` or `fd -x`. External commands without a browser definition default to path operands, so `ls `, `ls -l ` and `/usr/bin/ls ` offer files and directories after Tab. Right arrow accepts a selected match; Esc restores the input from before completion. Ctrl+C clears the current input and completion, and stops the command running in that tab at its next step: the request in flight finishes, nothing more runs, and an upload the tab runs is cancelled. A command that asks a question (`mv -i`) takes the next line as its answer.

The terminal has tabs, each with its own working directory, history, and running command, so several things can run at once: Alt+T opens one, Alt+W closes it, Alt+1–9 switch, and they survive a reload of the page. All tabs share one account, as they share one session cookie: `su`, `login`, and `exit` change it for every tab. Typing on the idle desktop, outside another window, focuses the terminal while dialogs, selections, shortcuts, and IME keep their behavior. Closing authentication or editor dialogs restores actual text-entry focus.

## The desktop

The page is a desktop: a bar with the account, the area its windows are laid out in, and a dock. Terminal, Files, Preview and Editor are windows. A compositor in the page's wasm (`crates/frontend/src/desktop.rs`) lays them out as elements of the page, by their place, size and stacking; nothing is drawn on a canvas.

- A window's bar moves it, and its edges and corners resize it, down to 280 × 180. A press anywhere in it brings it up, with the keyboard.
- Let go at the top of the desktop, a window fills it; at the left or right edge, it fills that half. Dragged away, it is free again at its own size; freed by its button or a double click on its bar, it goes back where it was.
- The buttons in its bar minimize it, fill the desktop with it, and close it.
- The dock shows each app, marking those open and the one with the keyboard. A click opens an app, brings it up, or minimizes it if it is the one up. Preview and Editor are there while open.
- The launcher (⋮⋮) opens Terminal, Files, the manual, and upload.
- Ctrl+Alt+← and → put the window up in a half, Ctrl+Alt+↑ fills the desktop with it, and Ctrl+Alt+↓ frees it, or minimizes it if it is free. Alt+` goes to the next window.

The Files keep a directory of their own, apart from the terminal's, which `cd` does not move: its location, at the top, takes a path typed (`~` for the account's home); a click goes into a directory, `../` out of it, and opens a document in the preview. Clicking a `.wasm` file or another executable runs it in the terminal, using the normal execution-permission checks. An occupied terminal or unfinished command is preserved by opening a new terminal tab. Explicit `open FILE` still requests a preview. Navigation errors and upload progress stay in the Files. Their upload button, the launcher's, and files dropped on them upload into their directory; files dropped elsewhere, into the terminal's, as `upload` does there. Each browser tab keeps where its Files are. Returning to a visited directory restores its horizontal and vertical scroll position for the current page session; new directories start at the top. Live refreshes and upload updates preserve the current position.

Each browser keeps its layout (localStorage `os-desktop`). Nothing is modal but signing in: the preview and the editor are windows among the others, and what is typed goes to the window that has the keyboard.

## Phones and touch screens

Below 650 px wide the desktop shows one window at a time, filling the visible screen. The dock goes from one to another, and minimizing or closing the one shown shows the next. app.js follows the screen as the on-screen keyboard opens (`visualViewport`; `interactive-widget=resizes-content` on Chromium), and the terminal keeps its command line at its foot. While the keyboard is open, the bar and the dock make room. The wallpaper and the button that fills a window are hidden; the account button stays on one line; `ls -l` keeps an entry a line and scrolls sideways. Touch screens get the keys their keyboards lack, Tab, ↑, ↓, ^D and ^C, under the command line; a tap on the transcript goes to the command line; nothing autocapitalizes or corrects commands.

## Uploads and previews

Uploads use current account permissions. Publicly writable directories accept guest writes. The UI does not overwrite existing names; `open` with `O_TRUNC` replaces a file one may write, only if it is still the version given, if one is. Files may be up to 1 GB. Identity changes close open previews.

Files are written through file descriptors (system calls `open`, `pwrite`, `close`, `fchmod`, and `discard`, which lets go of an unfinished file with its descriptor; large chunks stream on the Worker), as uploads, the editor's saves, recordings and copies all are. A descriptor belongs to its session: a signed-in account's, or, signed out, the browser's own (a `os_guest` cookie, given at once), so every page of a browser may use it, as threads share a process's. A process's descriptors are its own, in a table of its line's (the process, its forks, and the images they replace their own with), apart from the page's: signing the page in or out does not close them, and they close as the line ends. `fchmod` changes the inode a descriptor opened, whichever of its names it has now. The browser uploads in chunks of 8 MiB, three at a time, each with its SHA-256, which R2 checks. A file is hashed first; opening it again with the same SHA-256 and size, by the same account, goes on with the chunks the kernel already has, on the same device or another. One descriptor writes a file at a time: every batch a session sends keeps its descriptors, a page holding one says so every 8 seconds, and another session that opens the same file is told it is being uploaded from another tab or device (EBUSY), until the first page closes it, as it does when it goes, or its session has not been heard from for 20 seconds; the old descriptor then writes no more (EBADF). The same browser may always go on with its own unfinished file. `close` completes the file once every chunk is there; with one missing, the descriptor goes all the same (EIO) and the file waits, unfinished, for a day. Ctrl+C discards the descriptor: a file the upload was making goes, one it was replacing keeps its old content. Content is written whole: an existing file is replaced (`O_TRUNC`, an editor's save giving the version it read, ESTALE if it changed). A writer that gives no size writes its chunks in order and the file grows as it writes, readable meanwhile, truncated as it opens and whole when it closes (a program's output); a recording is that, appended to (`O_APPEND`). `cp` clones content (`ioctl(FICLONE)`): nothing is copied, whatever the size; a binary of `/usr` is shared so too, while what the kernel makes as it is read (`/etc/passwd`, `/proc`, a device's state) cannot be cloned (EOPNOTSUPP), and `cp` reads it and writes what it read, as `cp --reflink=auto` does. A descriptor reads and writes, to its end, with the credentials it was opened with (root, if opened as root or under sudo), the Worker's streams included, as a Linux file keeps its opener's. A session's descriptor numbers are given once each, from 3 on: its pages share them, and one may still use a number another closed. `jobs` lists the browser's descriptors that write files (`/proc/self/fd`; not a process's standard input, nor a device), and `jobs cancel fdN` closes one.

A file is listed as soon as its upload starts, with its progress (the bytes that have arrived, counted as the uploading tab counts them), and can be read while it arrives: a download, or a video, follows the upload, waiting for each chunk not sent yet (for up to 60 seconds without progress). An overwritten file shows its old content until the new upload completes.

Every page keeps a WebSocket to the authority (`GET /api/events`, accepted only from this site's origin, hibernating while idle). A page watches the directories it lists (`inotify_add_watch`), and after each change the authority tells the pages of each session watching a changed directory, while its account may list it, before it answers the request that changed it; the tabs showing one list it again: files created, moved, removed or uploaded on one device appear on the others as it happens. The page answers what only looks (`stat`, `lstat`, `getdents`, `access`, `readlink`) from a cache while the directory it is in is watched, as an NFS client answers from its attribute cache: listing a directory again asks the kernel nothing. What the kernel says changed, anything the page changes itself, a new account and a line that dropped clear it, and nothing is trusted past 15 seconds. A line that drops opens again and lists what was missed. Pages also say over it which slide, or presented PDF page, they show, which the authority keeps as where the account last showed it and passes to the account's pages signed in elsewhere and to the followers of its presentations; they ask where a deck was last shown, and which devices of /dev they follow (Presentations, below). A page whose session ends elsewhere (signed out, a password changed, the account locked or removed, or the session expired) is told at once, and its tabs say so and show guest; windows of one browser, which share its session, follow each other's `su`, `login` and `exit`.

| API | Purpose |
| --- | --- |
| `GET /api/events` | The page's line (a WebSocket): what changed, what devices it follows do, and the drivers' news to it |
| `POST /api/sys` `{calls, umask, sudo}` | System calls (owner's design, 2026-10-29: the page is user space): a batch of calls, each run on its own, in order, each answered with its value or its errno (`crates/abi`). The terminal's file programs (rm, chmod, setfacl...) are made of these, in the page (`crates/userland`) |
| `PUT /api/pwrite?fd=&index=` with optional `X-Chunk-SHA256` | pwrite(2): one chunk of the file a descriptor writes, streamed to R2; writing it again is harmless, other content is refused |
| `GET /api/file?path=/dev/present/NAME` | Read a device (as `cat` does): its driver's state, as JSON. Presenting, following, asking to speak and live sound are system calls on devices: `mknod`, `open`, and their drivers' `ioctl`s (`crates/worker/src/dev`) |

These are the whole API: the rest is system calls (`crates/abi`), the page being user space. Signing in and out, sudo's timestamp and passwords are calls too (`login`, `logout`, `sudo`, `passwd`), which give the session its cookie; so are accounts (`useradd`, `usermod`, `userdel`, `groupadd`, `groupmod`, `groupdel`: root's, or a signed-out useradd NAME's and an account's own userdel, with its password), whose policy is the kernel's, as setuid programs' is on Linux; `whoami`, `id`, `groups` and `users` read `/etc/passwd` and `/etc/group`, which the kernel writes as they are read.

Text, code, diffs and Markdown can be searched in the viewer: the search button or Ctrl/Cmd+F opens a panel that takes a regular expression (Rust syntax, as `grep` takes) or plain text, with a match-case toggle; Enter and Shift+Enter (or F3) step through the matches, which are highlighted without changing the preview, and Esc closes the panel.

Previews render in Rust, as the terminal does; PDF pages, Mermaid diagrams, and code highlighting run in web workers (`crates/preview`), each loaded the first time a preview needs it.

- PDF: one document that scrolls, every page in its place from the start; hayro draws the pages near the view, one at a time, and those far from it are released, so long documents stay light. The toolbar shows the page in view, goes up or down a page, and zooms (50–300%). Its screen button presents the PDF, a deck exported from Beamer, PowerPoint or Keynote, say: one page at a time, filling the view, drawn as wide as it shows (up to 3840 pixels), the next and previous pages drawn ahead. The arrow keys, Space, Page Up and Down, N and P, Home and End, and a swipe turn it, and F shows it full screen, as with slides; other windows and devices presenting it follow, as slides do. Encrypted PDFs do not open; download them.
- Markdown: GitHub's flavour with tables, task lists, footnotes, `$…$` / `$$…$$` maths as MathML, highlighted code blocks, and Mermaid diagrams drawn as images. Raw HTML is sanitized (ammonia, as DOMPurify did): no scripts, event handlers, styles, forms, or frames. The view switches to slides with the button in its corner.
- Code: tree-sitter highlighting in 39 languages, chosen by extension or file name (`Makefile`, `Dockerfile`, ...), for text up to 1 MB; JSON is pretty-printed.
- Tables: CSV and TSV, the first 1,000 rows. Cards: vCard contacts and iCalendar events. Diffs and patches are colored. ZIP and tar archives (gzipped too, up to 50 MB) list their files, in a worker of their own, as a gzipped tar is decompressed whole to list it: one that expands to more than 1 GB, as much as the terminal extracts, is not listed. A worker whose code cannot load says so, and the next preview starts it again.
- Images: PNG, JPEG, WebP, GIF, AVIF, BMP, ICO, and SVG; an SVG shows as an image from a `data:` URL, where its scripts do not run. `/api/file` serves SVG as `image/svg+xml`, so Markdown can show it with `![](logo.svg)`; opened by itself, it is sandboxed and downloads (`Content-Disposition: attachment`). Video/audio use native browser players; supported codecs depend on the browser.

Any file uploads. Those the previews know show, by their content or extension; others offer the download, and are served as bytes (`application/octet-stream`), as text when they are text or have no extension (`README`). R2 reads support HEAD, ETag, and single HTTP byte ranges, with authorization before conditional or range responses.

MP4 / MOV / M4V / M4A uploads inspect top-level boxes to check that moov precedes mdat, including 64-bit box sizes. A file that is not faststart still uploads, with a warning: players must fetch its end before they start, so it plays only once that has downloaded, and not at all while it is still uploading. `faststart FILE` then makes it stream where it is, on the server (see [Archives](#archives)); before uploading, the same can be done without re-encoding by:

```text
ffmpeg -i input.mp4 -c copy -movflags +faststart output.mp4
```

This is a UI-side structural faststart check, not a codec validator or proof of a particular encoder option; a file whose boxes cannot be read is warned about, not refused. Direct API uploads do not perform this check. WebM does not use it.

### Archives

`zip`, `unzip`, `tar` and `faststart` run as installed WASI programs, with the option subsets documented in `man`. They submit archive/media work through accelerator devices; containers transfer bulk file bytes through the storage gateway:

```text
zip -r notes.zip notes          unzip -d restored notes.zip     unzip -l notes.zip
tar -czf notes.tgz notes        tar -xvf notes.tgz -C restored  tar -tf notes.tgz | wc -l
```

- A job reads the files as they were when it started, which stay until it ends, whatever happens to their paths. It acts as the account that started it (root under `sudo`), and every file it writes passes the usual permission checks.
- Extraction writes members one by one, straight into the destination, as on Linux. Stopping early (Ctrl+C, or `jobs cancel ID`) leaves what was extracted, never a half-written file; `unzip -n` continues. `unzip` asks before replacing a file (`-o` replaces, `-n` never does); `tar -x` replaces, unless `-k` or `--skip-old-files`.
- Members whose names contain `..`, devices, and duplicate names are skipped with a warning; a leading `/` is removed. Archives may hold up to 10,000 members expanding to 1 GB.
- Links: `tar -c` stores symbolic links as links and a file's later names as hard links (`-h` stores what they lead to); `zip -r` follows links unless `-y`. Extraction makes them: hard links in archive order, symbolic links after everything else, as GNU tar's delayed links, so no member is written through a link from the same archive.
- A file that exists, when replaced, is removed and made anew, as GNU tar and Info-ZIP do: it is the extractor's, and its other names keep the old file. Extracted files and directories get, from `unzip`, the archived permission bits; from `tar`, those bits less the umask, or exactly (setuid, setgid and sticky too) for root. `000` counts as a mode; a member with none (zips made elsewhere) gets 644, or 755 for a directory. Directories that were there already get the archived mode too. A new file has its mode from its first byte, so nobody reads it while it is written who could not once it is there.
- A member named on the command line that is not in the archive is a failure (`caution: filename not matched`, `Not found in archive`), as is an empty zip; an empty tar extracts nothing, without complaint. A job that has nothing to write ends at once.
- A job tells its account nothing of what lies where that account may not look: before asking whether to replace a file, or saying one exists, it checks that the account may search every directory above it.
- `faststart FILE` moves an MP4, M4V, MOV or M4A file's index (`moov`) before its media, as `ffmpeg -c copy -movflags +faststart` and qt-faststart do: the boxes are reordered and the chunk offsets (`stco`, `co64`, upgraded to `co64` past 4 GB) follow, nothing re-encoded. The file is written in place, keeping its owner, mode, ACLs and other names; a file already faststart is left alone, a fragmented one or one that is not MP4 is refused.
- A new archive appears at once and can be read while it is written. `zip` does not update an existing archive; `tar -c` replaces one.
- The CLI owns terminal input/output and its device handle. Exiting it, Ctrl+C or closing the tab cancels attached work; explicit device detach/attach supports durable work. `ps` lists remote tasks from `/proc`, `kill ID` cancels one, and `jobs` lists them alongside unfinished uploads (`jobs cancel ID` stops either). `Wait` reports lifecycle/status; typed device completions carry output and questions.

Each job (zip, unzip, tar, faststart) has a `JobRunner` Durable Object and a container (`crates/jobs`, built by `containers/jobs/Dockerfile` into a 2 MB image) that reads and writes the archives, or the video, on its disk. The runner streams the job's files from R2 into the container and its output back, a chunk per request, and keeps its plan in its own storage, so that a restart of it or of the container resumes the job: extraction continues with the member it was writing, and a new archive goes on with the chunks still to write (its bytes are deterministic: fixed dates, owners, and deflate settings). Deploying requires Cloudflare Containers, on the Workers Paid plan.

**Remote task credentials.** Submission snapshots who started it (root under sudo) into credentials of its own, whose token only its runner holds, and the runner makes the job's file calls through the system calls with it (`lstat`, `mkdir`, `open`, `pwrite`, `close`, `link`, `symlink`, `rename`, `chmod`), checked as any process's are. The device driver also restricts the task to pinned inputs and scoped output grants. Within those grants it retains its starting permission snapshot: locking or deleting the account afterwards no longer fails it, as a running process keeps its credentials on Linux. Its descriptors are its own: `/proc/PID/fd` shows the archive it reads, and the file it writes while it writes it; they close as it ends.

### Presentations

`open demo.slides.md` shows the slides. A standalone `---` starts the next slide and `--` one below it; separators inside fenced code are preserved. A `Note:` line starts the slide's speaker notes, which show in the speaker view only.

````markdown
# Title

First slide.

---

## Next slide

- First point
- Second point

Note:
What to say here, in Markdown too.
````

The keys are reveal.js's. The arrow keys move between slides, left/right and up/down; Space, N and Page Down go to the next slide in order, those below others included, and Shift+Space, P and Page Up back (a presenter's remote sends Page Up and Down); Home and End go to the first and last. On a touch screen, a swipe left or right does the same. F toggles fullscreen, O (or the grid button) shows an overview of every slide, and G (or a click on the slide number) asks for a slide by its number, `3` or `3.2`. A click on an image in a slide shows it large. Escape closes the overview or an enlarged image before the viewer. Slides near the one shown are drawn ahead and kept, so the next slide shows at once, its images loaded and its code highlighted.

S opens the speaker view in a window of its own (pop-ups must be allowed), to keep on the laptop while the slides show on the projector: the slide, the next one, the slide's notes, which A− and A+ resize, the time since it opened (a click restarts it) and the time of day. The screen button in the slides' bar shows the speaker view in the window itself, as on a phone kept as a remote, where the notes go under the slide.

Every window and device that shows a deck shows the same slide: the other windows of this browser, and the pages of the same account signed in elsewhere, which the authority tells. Turn the slides on a phone, and the laptop on the projector follows. A page of the account opens a deck where the account showed it last, on any device, so a phone picked up in the middle of a talk turns on from the slide shown. Signed out, a page is guest's, which anyone signed out shares, so it follows only the windows of its own browser.

#### Presenting to others: /dev/present

`present talk.slides.md` shows the deck (or Markdown as slides, or a PDF presented a page at a time) and makes `/dev/present/talk`, a character device of the `present` driver (`ls -l` shows `crw-r--r--`), owned by the presenter, with the file's mode and ACL; `-n NAME` names it otherwise. Its mode and ACL say who may do what, as for any file, and its owner changes them with `chmod` and `setfacl`: whoever may read it follows it with `open /dev/present/talk`, guests too, each seeing the slide shown as it turns, and `cat /dev/present/talk` tells what it shows; whoever may write it turns it too: `setfacl -m u:ann:rw /dev/present/talk` makes ann a co-host, whose turns are the presentation's. A listener who turns elsewhere pauses following, and the button in the bar ("Follow NAME") brings them back to where the presenter is. The presenter's own windows and devices turn it, as remotes; root, who may write any device, turns only what it presents or is let turn. It lasts until `present --stop talk`, `rm /dev/present/talk` (its account's, or root's, to remove), or 12 hours after its last turn; deleting the account ends it. Guests cannot present, as guest is everyone signed out.

The bar of the slides, or of a PDF, has the same at hand, signed in: **Present** (the screen with waves) makes `/dev/present/NAME` of the file shown, or stops it; **Go live** (the microphone) sends the microphone as `stream` does, **Live** only or **Live + record**, recorded beside the file as `NAME-YYYYMMDD-HHMM.weba`, and shows how long it has gone, a click stopping it. A listener's bar has **Ask to speak** (the raised hand) instead. The presenter's bar then shows a hand with how many ask: **Allow** lets one speak, as Linux would let them: an account gets an ACL entry that lets it write the presentation (`u:NAME:rw`); a guest, as everyone signed out is one account, gets a descriptor that writes it, passed to their browser's session alone, as Linux passes an open file. Through it their microphone goes live as a voice of the presentation, `/dev/snd/NAME-SPEAKER`, the presenter's, with the presentation's mode, which everyone following hears, and the presenter's page that allowed it; **End** removes the voice, and with it the leave to speak, as does the listener's own button. At most two speak at once.

So for a talk whose files are `g:guest:r` (`setfacl -R -m g:guest:rX DIR`, so that its images may be read too): the laptop runs `present talk.slides.md` and presses S for the speaker view; the phone, signed in to the same account, opens the deck and turns it; the audience opens `/dev/present/talk` on their phones, signed in or not.

#### Live sound: stream and /dev/snd

`stream`, signed in, sends the microphone live as `/dev/snd/USER`, the account's name, kept nowhere (below); `-n talk` names it `/dev/snd/talk`. `stream talk.weba` also records it, into a new file, Opus in WebM, which every browser records (Chrome, Firefox, Safari 18.4+; none on Linux records AAC). The file is there at once, marked as recording, and grows a chunk (256 KiB, about half a minute) at a time; it may be read meanwhile. Ctrl+C in its tab, or `rm /dev/snd/NAME` from anywhere (its account or root), stops it, and the file is complete. A chunk that cannot be sent is sent again for as long as the network is down, while the recording goes on. `jobs` lists a recording, and `jobs cancel fdN` stops it from another tab of the browser, keeping what arrived. A recording ends at 240 MB, about eight hours: what one read of a file, an R2 request a chunk, can take. A page that goes away mid-recording leaves what arrived: ten minutes later the authority completes the file with it.

Signed in, the sound is also live, as `/dev/snd/NAME`, a character device of the `snd` driver, the speaker's, made with the umask, through Cloudflare Realtime (WebRTC): whoever may read the device hears it with `open /dev/snd/NAME`, in a small player that goes on playing whatever the viewer shows, with Mute and ×; a browser that wants a tap to play shows Listen. Whoever follows a presentation of the same account hears its sound with the slides: the one of the presentation's name, if there is one, or else the account's latest; one that starts later starts for them too, unless they stopped it with ×. A sound whose connection fails, as on a network that changed, is heard again. Listeners in the same room as the speaker should use earphones, or the microphone hears them. `-m ENTRIES` gives the recording and `/dev/snd/NAME` ACL entries as `setfacl -m` takes them, as they are made: `stream -n talk -m o::-,g:lab:r` is heard by group lab only. A live sound lasts while the descriptor that sends it is open and kept: its page closing it, or going away (two minutes later), ends it.

Live sound needs the site's Cloudflare Realtime app: create an SFU app in the dashboard (Realtime), then give the Worker its App ID and secret, in `.dev.vars` locally (`REALTIME_APP_ID=…`, `REALTIME_APP_TOKEN=…`) and as secrets when deployed (`npx wrangler secret put REALTIME_APP_ID`, `npx wrangler secret put REALTIME_APP_TOKEN`). Pages never see the secret: the authority asks Realtime for them, once it has decided that they may. Without the app, `stream` records only, and says so.

The preview toolbar provides fullscreen and close; a button clicked there or in the slides' bar leaves the focus where it was, so Space goes on turning slides rather than pressing it again. Slides have themes of their own, Light (the default), Dark, Sepia and Night, chosen in their bar and kept for every deck in this browser. Fullscreen, the bars float over the content and hide until the pointer moves. A title too long for the bar loses its start, so the file name stays in view. Escape closes the preview or the editor while it has the keyboard, or a dialog, and nothing else: the page takes the key, which Safari would otherwise also take to leave a full-screen window; a preview in element fullscreen leaves fullscreen first. Text slides are laid out at 1280 × 720 and scale to the space they have, in the dialog or fullscreen. A slide containing only one image fills the available viewer area with its aspect ratio preserved; it has no Markdown padding or 460px image limit. Relative Markdown links/images resolve within the virtual R2 filesystem, and linked files open in the viewer, with a Back button (←) to the file the link was in. Each preview opens where it was left: the slide, the PDF page and zoom, how far text was scrolled and media played, kept in this browser for the last 200 files. External links open separately. Text previews are limited to 2 MB; larger files can be downloaded.

### Optional games and custom branding

The default build includes no game. A separate content project can supply a build-time JSON configuration:

```json
{
  "branding": {
    "name": "MY TERMINAL",
    "subtitle": " / ARCHIVE",
    "heading": "Welcome back.",
    "description": "An archive with account-based access."
  },
  "assets": "dist/content",
  "games": { "example": "game/index.html" }
}
```

```bash
node scripts/build.mjs --content /path/to/content.json --out-dir /path/to/site
```

Assets are resolved relative to the configuration and copied to `content/` under the output directory. Output cannot be inside the source assets. Entries must be existing relative HTML files inside assets; no remote URLs, traversal, or symlinks.

Upload a `.game` manifest and open it:

```json
{"engine":"bevy","entry":"example","title":"Example game"}
```

The manifest can select only a build-time registered entry. Its read permissions protect the manifest, not the publicly served static game runtime. Game HTML/WASM is trusted site-maintainer code running in a same-origin iframe. The close protocol is `parent.postMessage('close-game', location.origin)`. An optional `window.signal.dispose()` may return a promise for releasing audio/resources; the terminal awaits it before removing the iframe.

## Architecture: user space and system calls

Programs run as separate WASI/WASIX processes under the dedicated client kernel. The browser terminal is a shell and UI; the Worker and Durable Objects authorize filesystem, identity and shared resources. Coreutils supplies standard utilities; `crates/utilities` packages OS-native filesystem, permission, account, process, grep, fd and xargs tools as runnable WASI programs. Both shells use the same images and process-authenticated calls. Filesystem commands and fd/xargs have no browser CLI routing. `zip`, `unzip`, `tar` and `faststart` are installed WASI clients too; they use typed accelerator devices and the generic remote-task lifecycle. User space is never trusted. Calls go in batches (`POST /api/sys`), each run on its own, in its own transaction, answered with its value or its errno (glibc's words, `crates/abi`). A call may name the descriptor an earlier call of the batch opened (`{"ref": i}`, as NFSv4's COMPOUND passes a filehandle on), so opening, writing and closing a small file is one request; a call naming one that failed fails as it did. Bytes travel as base64: up to 256 KiB a call in the batch (`pread`, `pwrite`), more on the Worker (`GET /api/file`, `PUT /api/pwrite`).

The ABI currently multiplexes several contracts. The O3 inventory now contains 59 `abi::Call` variants. The command-shaped `Spawn` call has been removed; no command-specific replacement syscall was added.

| Contract | Current calls | Direction |
| --- | --- | --- |
| Filesystem primitives | `Stat`, `Lstat`, `Getdents`, `Access`, `Readlink`, `Mkdir`, `Mknod`, `Rmdir`, `Unlink`, `Rename`, `Link`, `Symlink`, `Chmod`, `Chown`, `Utimens`, `Statfs`, `Getxattr`, `Setxattr`, `Listxattr`, `Removexattr` | Keep shared resource semantics; language/platform adapters translate them. |
| Descriptors and watches | `Open`, `Close`, `Discard`, `Fchmod`, `Pread`, `Pwrite`, `InotifyAddWatch`, `InotifyRmWatch` | Keep. `Discard` aborts an unfinished remote write; removing it requires an equivalent transactional close/abort contract. |
| File and device control | `Ioctl` | Keep typed request dispatch and descriptor rights; FICLONE and present/sound requests already use it. |
| Process primitives | `Getcreds`, `Getpid`, `Execve`, `Fork`, `Exit`, `Kill`, `Wait` | Keep process credentials/lifecycle. Numeric PIDs use the Machine registry; opaque remote task IDs use the executor lifecycle, without archive output or questions. |
| Host/registry control | `ProcInit`, `ProcTty`, `Pids`, `Seats`, `Gone`, `ProcPoll`, `ProcKeep` | Treat as authenticated host protocol, not new application syscalls. Preserve token proofs, namespace ownership, leases and cleanup. |
| Resource policy | `CgroupCreate`, `CgroupRemove`, `CgroupSet`, `CgroupAttach`, `CgroupStat`, `CgroupList` | Control-plane operations today; eventual cgroup filesystem projection must preserve authority and enforcement gates. |
| Identity service | `Login`, `Logout`, `Sudo`, `Passwd`, `Useradd`, `Usermod`, `Userdel`, `Groupadd`, `Groupmod`, `Groupdel` | Protected account/session policy, not hardware devices. CLI parsing belongs in programs; these policies cannot simply be replaced by edits to generated `/etc` files or fabricated setuid images. |

`Wait` reports lifecycle and exit status only. Device completions carry output, progress and conflicts; executable clients write stdout/stderr and read questions from their own stdin. There is no archive-stdin pseudo descriptor or browser archive-command dispatch.

### Drivers and the accelerator contract

A driver translates generic resource operations into a backend's protocol. Today `web/kernel/pty.js` implements local terminal behavior, while `crates/worker/src/dev/{present,snd,realtime}.rs` implement permission-checked media device control with browser endpoint adapters. The container is the remote execution backend; the Worker gateway routes authorized I/O; the driver owns submission, completion, cancellation and resource lifetime.

`crates/abi/src/accelerator.rs` defines the implemented version 1 protocol. `/dev/archive` accepts create/extract/list operations; `/dev/media` accepts MP4 index relocation. The installed clients parse arguments and open directory handles (`O_PATH | O_DIRECTORY`), then submit explicit options and names relative to those handles. Unknown versions and fields, escaped names and foreign descriptors fail. Directory O_PATH handles grant no read or write access: later operations perform their normal permission checks.

The driver snapshots readable inputs and derives inode-bound destination grants. `crates/worker/src/executor.rs` owns task authorization, cancellation and final cleanup; the registered container backend runs the selected archive/media operation. It accepts neither arbitrary shell commands nor CLI argv. Arbitrary remote images and distributed scheduling remain later capabilities; the current backend is a registered accelerator service. Containers stream bulk bytes through authorized R2 gateways. Each member still passes filesystem permission checks; a symlink or replaced destination cannot enlarge a grant. Runner credentials cannot use identity/registry policy or read arbitrary filesystem paths.

Submission uses a credential-lineage retry ID. Repeating an identical request returns the same task, including after completion; changing its parameters fails. At most 16 active tasks belong to a controlling account, with EAGAIN backpressure. Requests and completion pages are at most 256 KiB; pages contain at most 128 events. Output has a 4 MiB durable spool, and an over-budget producer fails explicitly with E2BIG. Conflict answers name the exact revision and paths. Completed output/resources expire after a week; small retry tombstones prevent an expired write from running again.

Execution credentials and control ownership are separate: sudo snapshots root credentials but retains the initiating account as controller. An attached task is cancelled when its last device handle closes, including client death or terminal closure. The explicit detach/attach protocol supports durable work and owner-authorized recovery; ordinary archive CLI invocations remain attached. Cancellation/failure discards unfinished writers before revocation, preserving the old content of overwritten files. Waiting executors check revocation every five seconds so abandoned containers are released. Deterministic archive rebuilding and chunk checks preserve existing restart recovery.

Raw ABI descriptors participate in the runtime's shared descriptor accounting, including fork, exec and forced child termination. Loader failures after reexec report through the process's inherited stderr, and close-on-exec writers flush with the replacement credential.


`/proc` is the kernel's, as Linux's procfs: `/proc/PID/status` and `/proc/PID/cmdline` for the account's processes (others' are not shown, as with `hidepid`), `/proc/self/fd/N` for the session's descriptors and `/proc/self/fdinfo/N` for what each says of itself. `/proc/self/fd/N` is a magic link: a path through it names what the descriptor has open, so a directory's descriptor names what is in it, as `openat` would. `ps`, `kill` and `jobs` read it.

A session is a browser: a signed-in one's, or, signed out, the browser's own (the `os_guest` cookie). Descriptors are a session's, shared by its tabs as threads share a process's; a presenter lets a guest speak by passing one to that guest's session. The places where an account last showed a deck (`present` on the events socket) are the one extension with no Linux counterpart.

### /usr: the build's, read-only

`/usr` is the system's own, as an image-based system mounts its `/usr` read-only: what the build put there (the Worker's assets), not R2's. The tree is Arch's: `/bin` and `/sbin` are links to `usr/bin`, `/lib` and `/lib64` to `usr/lib`, `/usr/sbin` to `bin` and `/usr/lib64` to `lib`; `/usr` holds `bin`, `include`, `lib`, `libexec`, `local`, `share` and `src`; `/sys`, sysfs's place, is empty. Changing any of them, or what is below them, fails with EROFS, and archive jobs refuse to write there too. The rest of `/` is the store's, made at first start as Arch has it: `/boot`, `/mnt`, `/opt`, `/run`, `/srv` and `/var` (755), `/tmp` (1777, shared and sticky), `/root` (750), with `/dev`, `/etc`, `/home`, `/proc` and this system's `/guest`. `/usr/bin` holds what a name runs:

- `coreutils` and `utilities` are regular executable WASI images, mode 755. Their applets are symlinks to the relevant image. `ls`, `echo`, `cat`, `head`, `tail`, `wc`, `sort`, `uniq`, `mkdir`, `rmdir`, `ln`, `readlink`, `realpath` and `touch` use coreutils in the browser shell and dash.
- `utilities` supplies `stat`, `df`, `chmod`, `chown`, `chgrp`, ACL/xattr tools, `ps`, `kill`, identity/account tools and streaming `grep`. Their options remain the documented subset; packaging does not claim full GNU compatibility. Numeric `kill` runs as a program; `%job` remains shell job control.
- Browser actions such as `open`, password/session dialogs and upload have no fake `/usr/bin` image or misleading setuid bit. Guest account registration/deletion dialogs remain browser policy flows; root's installed account tools are ordinary processes.
- `cp`, `mv`, `rm`, `fd` and `xargs` are installed OS-native WASI programs in `utilities`. Bare names, explicit paths, multicall invocation and dash share one implementation. The duplicate coreutils cp/mv/rm applets and browser CLI routes are removed. Existing copy/rename/removal code preserves ACLs, ownership, hard links, reflinks and write-abort behavior; these programs retain their documented option subsets. Native `rm -i` confirms removals (and directory descent with `-r`), and the last `-i`/`-f` option takes precedence.
- The catalog contains 108 applets: 69 unchanged uutils 0.12.0 applets, five platform-patched uutils applets (`ls`, `dir`, `vdir`, `cat`, `mkdir`), and 34 OS-native applets (31 in `utilities`, plus `tty`, `stty`, `syscall` in `coreutils`). The two multicall image names are additional entry points. This is an execution-consistency boundary, not a claim of complete GNU/fd option compatibility. “Unchanged” describes source provenance, not complete runtime compatibility. Known gap: upstream `dd` is not usable on this WASI preview 1 runtime yet (file-copy mode attempts a host thread; stdio modes report unsupported operations). Use `cp` for filesystem copies or `cat | tee` for streamed copying; dd needs a platform port or compatible execution engine.
- `zip`, `unzip`, `tar` and `faststart` are OS-native executable accelerator clients in `utilities`, with the same PATH, pipeline, stdio and signal behavior from either shell.
- The pinned uutils `mkdir` WASI port uses shared POSIX mode-aware creation and process-local umask. Parent directories retain owner write/search, leaf modes respect `-m`, and default ACLs and setgid inherit normally. Explicit set-ID bits use chmod after creation, as GNU mkdir does. Fork and exec preserve umask. WASI timestamp calls honor no-follow, so `touch -h` changes the symlink itself.

uutils' run as processes of their own in the page's WASI engine (`web/wasi/`). The browser's WebAssembly engine is only a CPU; the engine is what a process imports. Each process is a Worker of its own that instantiates the binary, compiled once, with WASI preview 1 implemented over the system calls, each blocking as a process blocks in a call (the image suspended on the request where the browser has JSPI, the Worker waiting on a synchronous request where it has not; see Processes), plus `os.sys` and its reply import, which carry a batch of the kernel's calls as it is, for what WASI has no words for (modes, owners, ACLs, devices, accounts): the `syscall` program makes them. The scalar `os.umask` import manages the process-local creation mask, carried in OS batches. Omitting that field keeps the launch snapshot for process callers (including archive jobs), or uses 022 for browser sessions. Identity and resource access still come from authenticated credentials. The engine keeps the descriptors (a file read ahead, one written in order, an existing one changed in place by rewriting it whole), the terminal and pipes as its standard streams, the working directory (`PWD`, which the binary enters as it starts) and the time; Ctrl+C ends the process at its next call, as it exits (outright, its Worker terminated, if it makes none for a second), and terminal output waits for the renderer through a bounded channel (two 4 KiB chunks per process). A writer checks signals while waiting, so continuous output such as `yes` remains interruptible. Captured output and the non-isolated fallback retain their 10 MB limit. Shared pipes and isolated terminal streams have no cumulative byte cap; readers provide backpressure and EOF.

`os.posix_spawn` and `os.waitpid`, exposed by `crates/posix::process`, provide generic child creation/wait for WASI preview 1 programs. They reuse authorized fork/exec and child reaping, inherit cwd/environment/umask/credentials and descriptors, close close-on-exec descriptors, and keep children in the job's signal group. No command name is interpreted by this adapter, and no ABI `Call` variant was added. `fd -x` executes sequentially with inherited stdin; `-X` passes all results once. `xargs` reads a bounded stream and starts batches before EOF, supplies empty child stdin by default, and uses `-o` for terminal input. It preserves failure classes (123 ordinary child failure, 124 exit 255, 125 signal, 126 execution denial, 127 missing program). Child creation requires shared memory; without cross-origin isolation it fails with ENOSYS instead of switching to a browser command path.

A pipeline's processes run at once, each one's output the next one's input through a pipe: 64 KiB of memory the page and its processes share (`web/wasi/pipe.js`), where a reader waits while it is empty and a writer while it is full. A write to a pipe whose reader has gone ends its process, as SIGPIPE does (status 141), so `yes | head -n 3` ends at once: the coreutils `head` process closes its input once it has its lines. What the last writes, standard error and terminal input echo share the program's screen as they arrive. The first reads the terminal unless given its input; typing appears at its cursor and stays out of shell history. In canonical mode, Ctrl+D ends a read (after what is typed, if anything is), and Ctrl+C kills the pipeline. Sharing memory needs a page isolated from other sites (`web/_headers`: `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Embedder-Policy: credentialless`, which lets other sites' images load without cookies); where a browser does not isolate it (Safari has no `credentialless`), the processes run one after another, each given what the one before wrote, and nothing reads the terminal. A pipeline joining the terminal's own programs passes text between stages as before. Remaining browser programs run in the page itself; Files and upload progress retain their structured views. External commands, including ls, write terminal text.

**Job control.** The pipeline's processes are a process group, and the terminal keeps jobs as a shell does.
- **Background:** a line ending in `&` runs as a job in the background and says `[N] PID`. What it writes still shows, its end says how it ended (`Done`, `Exit N`, `Terminated`…), and it reads nothing of the terminal. Only programs of `/usr/bin`, or uploaded ones, run so.
- **Ctrl+Z:** it stops the pipeline in the foreground, which becomes a job, `Stopped`.
- **Commands:**
  - `jobs` lists the jobs first.
  - `fg [%N]` continues one in the foreground, the terminal's input its own again.
  - `bg [%N]` continues one in the background.
  - `kill [-s SIGNAL | -SIGNAL] PID|%N` sends a signal, and `kill -l` names them.
- **Signals:** a signal reaches the process wherever it runs, from any tab or device of the browser. The kernel records it (`ps` shows a stopped process as `T`) and tells the browser's pages on their events line; the tab that hosts the process acts on it.
- **What signals do:** TERM, INT, HUP, QUIT, PIPE and KILL end a process. STOP and TSTP stop it at its next system call (a sleep wakes to stop, and a blocked read heeds a stop within a fifth of a second), and CONT continues it. A loop that makes no system call can only be ended. Stopping needs memory the page shares with its processes, so it needs an isolated page.

An explicit path (`/usr/bin/NAME`, `/bin/NAME`, `/sbin/NAME`, `/usr/sbin/NAME` or `./NAME`) executes its image through the kernel, including execution permission checks and loader errors; a directory entered alone retains implicit `cd`. External bare names search `PATH` (default `/usr/bin`), including programs installed by the user. `export PATH=/my/bin:/usr/bin` changes this shell’s environment; explicit paths bypass the search. Both launch paths retain access-denied errors while trying later PATH candidates, and an empty PATH entry searches cwd. `coreutils NAME` and `utilities NAME` run their multicall binaries. Shell builtins and browser UI actions retain their shell/UI roles; external utilities have no browser CLI fallback. Command-name completion also enumerates executable PATH entries, including relative directories and symlinks, using current-user access checks. `ls` writes ordinary terminal text and supports its upstream options; Files provides structured, clickable listings. External help is produced by the executable, and a missing or unsupported image cannot fall back to page code. A foreground command hides the shell prompt until it returns or stops; no working/input badge or busy tab marker appears. Program output and PTY echo alone occupy the active terminal, and shell errors have no decorative `!` prefix.

### The client kernel

Each tab runs a dedicated client-kernel Worker that owns its process Workers, tokens, SAB
pipes and terminal input buffers. The page sends commands and input, and renders output.
SharedWorker is optional infrastructure and owns no process state. The kernel is Rust (`crates/client-kernel`), built to wasm and imported by
`web/kernel/client.js`; the page talks to it through the versioned envelope in
`web/kernel/protocol.js`. Two tabs of one browser are one namespace and see each other's
processes.

**Each browser is a machine of its own.** The process table is not the filesystem's: each
browser's namespace has a Durable Object of its own (`Machine`, `crates/worker/src/machine.rs`,
with the registry in `procs.rs`). Token-authorized process bookkeeping stays on that machine.
Tokenless registry operations ask the authority for the current account once per
batch. For `execve`, the authority (`creds.rs`) checks the path, execute bit and caller,
records the process credentials by its token's hash, and answers how to read the image. A pipeline's stages are one `execve` request. The rest of a process's life
happens in the client kernel, as in a Linux kernel:
- **fork** takes a pid the machine lent ahead of time (`Pids`), at once; the child keeps its
  parent's credentials and token, and so its descriptors.
- **exit** makes a zombie until the parent waits; its children become init's, and a zombie
  orphan is reaped by init at once.
- **wait** answers from the kernel's own table, once the machine knows, so that `/proc` no
  longer names what was reaped.
- **Batches:** the machine hears of forks, exits and waits together, with the kernel's next
  request or a moment after, marked `X-Registry` so the Worker sends them straight to it.
- **Revocation:** a batch that ended processes revokes their tokens at the authority once,
  which closes what they opened, as Linux does at exit. A revocation that fails waits for the
  machine's alarm; the calls that ended the processes stand.
- **Room:** a namespace has room for `PROC_MAX` processes: those running, the pids lent to its
  kernels and not taken yet, and those execs were given and have not started yet.

**Who may make which call** is one table (`crates/kernel/src/registry.rs`, unit-tested).
`X-Registry` selects the machine's route; it grants no kernel privileges. Tokenless requests
act as the account verified by the authority, and process requests act as their token's
snapshot. `ProcInit` boot ids are per account and reset only that account's old processes and
lent pids. `Seats` lists the account's seats and lends (all for root); `Gone` applies the same
owner/root checks as kill to every affected row before committing. A public Web Lock is only
a liveness hint. After logout, a guest cannot clean up an earlier account's abandoned seat;
that requires the owner or root. Explicit host exits and waits still work using process tokens.

PID reservations belong to their account and, for process requests, their token. The client
keeps separate pools per process lineage, so forks still work after login/logout without
consuming another account's reservations. Unused token-bound reservations are released when
no live process holds that token. Forks and exits prove the process token; host waits carry
the zombie's token too, usable only for reaping. A tokenless registry wait needs the owning
account or root and an init child. Cgroups are their maker's: an account makes them under
`/user`, writes and removes its own, and moves its own processes into them.

`kill`, `poll` and the `Cgroup*` calls are the machine's too; a page's batch that carries one is
forwarded there by the authority, with the caller it found. In the client kernel, a process is
its host's (the tab that executed it): only that tab forks it, replaces its image, ends it,
waits for its children, or signals as it; a process's own `proc_signal` is allowed or refused by
its own credentials, not by whoever the page is signed in as now. `/proc` lists the machine's
processes. Coreutils runs through this path: the page asks the client kernel to run the pipeline,
and the kernel starts process Workers whose batches carry each process's pid and token.

**Any wasm can fork** (Phase 3). A program built for WASIX runs in the terminal's own process
Workers (`web/wasi/process.js`), with WASIX's process calls over the client kernel:
- **fork:** the loader gives an image that imports `proc_fork`, `stack_checkpoint` or
  `stack_restore` Binaryen's Asyncify through the existing `/api/file` byte route. A separate
  compiler container transforms once per immutable content and compiler version; R2 holds
  the result for at most seven days; deleting the original content also schedules its compiled
  versions for deletion. Access to the original image is authorized before every cache hit. The browser
  downloads no Binaryen bundle. Scratch occupies a separate wasm memory, preserving fixed
  and exhausted guest memory limits. Initialization runs on exec; a fork resumes its snapshot.
  A fork unwinds the image, and the dedicated kernel starts the child in a Worker of its own with a copy of the memory, the mutable globals and
  what its tables hold (the transform exports them, with a table of every function); both rewind
  (`web/wasi/fork.js`). The pid is the client kernel's, lent ahead.
- **execve:** `proc_exec` replaces the process's image in place: its pid, credentials and open
  descriptors stay, as Linux's do. Only the process can ask, by its token; the authority keeps the
  credentials it had and hands the descriptors on (`credentials.owner`).
- **wait:** `proc_join` waits for a child, or any, with its exit status or signal (wait4); an
  orphan is init's, and its kernel reaps it as it ends.
- **Open files a fork shares:** each open file is one, as Linux's struct file is. A table every
  process of a line shares counts each process's descriptors of it and keeps its offset, which a
  read or a write holds a lock of from choosing it to moving it; only the last close closes it,
  and a file being written keeps its bytes in memory they share (`web/wasi/shared.js`). A pipe
  counts its holders, so its end of file comes when every writer has closed, a killed one too.
  Both have a place for every process a namespace may have, freed as a holder closes its last
  descriptor; a fork that would leave one uncounted fails with EAGAIN.
- **Signals that end a process** are heeded at its next call: it exits by the signal, closing
  what it has open, so what it wrote is kept, as a killed process's writes are on Linux. One that
  makes no call for a second is ended outright; its host then lets go of what it held and closes
  the files it held last, as the process would have.
- **Blocking calls on JSPI** (change request 4): where the browser has JavaScript Promise
  Integration (Chrome 137+, Firefox), a call that asks the kernel (a file's, a directory's,
  `os.sys`, an execve's search of PATH) suspends the image on a fetch, and the Worker is
  free while it is answered; elsewhere, and for an untransformed image with a start function
  (which runs as it is instantiated, where nothing can be suspended), it is a synchronous XHR.
  Transformed fork images run initialization explicitly and can suspend it. What waits on
  shared memory still blocks the Worker either way: a pipe's read or write, a sleep, a stop, a
  wait for a child, an execve's answer from its host. Asyncify stays only for fork, setjmp and
  longjmp, as a JSPI suspension cannot be copied into a child.
- **Also:** `fd_pipe`, `fd_dup`, `fd_dup2` and WASIX's `fd_renumber` (dup2), `getcwd`, `chdir`,
  `proc_parent`, `proc_signal`, and setjmp and longjmp by asyncify. A forked child is in its
  parent's job: Ctrl+C and Ctrl+Z reach it. Signal handlers are not called; each signal does what
  it does by default.

A signed-out browser is now `guest-<uuid>:guest`, with a uid of its own from the anonymous range
(1,000,000–1,999,999) and no home; `HOME` stays the shared `/guest` (1777 sticky), and
`/etc/passwd` names it. A real `useradd` still makes a real account and home. Cgroups are a
cgroup-v2-like hierarchy per namespace (`/init`, `/user`, `/system`, `/cluster`), with
`cpu.max`, `memory.max`, `pids.max`, `io.max`, `cgroup.freeze` and device rules; enforcement is
Phase 6.

**Uploaded wasm is the ELF counterpart** (Phase 2): any path with the execute bit runs by its
name as typed — `./prog`, `dir/prog` — which `execve` resolves physically against the working
directory. The kernel checks the X rule (root needs an x bit too; setuid never elevates) and
opens the image as a descriptor of the process's own; the loader reads it by an exec token,
revalidated with X, not R, so an x-only file runs while a path read stays denied. The loader
compiles once per content id (an LRU, refreshed on a hit), and admits only WASI preview 1,
`os.sys`, WASIX and `env.memory` imports — as functions, with the
imported memory's own limits and shared flag — plus a `_start` and a memory; anything else is
`Exec format error`, as Linux says. Refusals keep the kernel's own errno and words. The process
runs with the credentials snapshotted at exec; its `/api/sys` batches carry `pid` and `proc` in
the body, its byte requests `X-Process-Token`, and it cannot sign the browser in or out. `.wasm`
files serve as `application/wasm`, and so does an exec image whatever its name.

Phase 0 measured the limits: SharedWorkers are not cross-origin isolated in Chromium or
Firefox, so they cannot use `SharedArrayBuffer`; File System Access and WebGPU are
Chromium-only. The Rust WASIX runtime runs and forks a prebuilt `dash` in Node and in a
cross-origin-isolated module Worker; asyncify-at-load transforms an uninstrumented WAT module
with binaryen in both. Details are in `AGENT.md` and issue #20.

**Where the kernel runs, and what a gone tab leaves.**
- **One kernel per tab:** every tab uses a dedicated Worker on the same Machine namespace. `OS_NO_SHARED_WORKER=1` deletes SharedWorker in every test context, including contexts created by tests.
- **Tab locks:** each tab holds the Web Lock `tw-tab-<tab>` while it lives, taken before it asks anything. Each process records its tab as its seat (`execve`'s `seat`).
- **Reaping:** a process whose seat's lock is free was left by a tab that closed, crashed or reloaded while it ran. The kernel requests cleanup at boot, periodically and on EAGAIN by checking held locks. The machine permits cleanup only for the current account's processes or root.
- **No reaping by boot:** dedicated kernels send no reset boot id. A new tab cannot reap another live tab's processes. Without Web Locks, the server lease supplies cleanup.
- **Kernel locks:** each kernel holds `tw-kernel-<id>` while it runs, and its lent pids are its own; a kernel that finds another's lock free gives what that one was lent back to the namespace.
- **`/proc`:** it shows the caller's namespace, as a Linux PID namespace does: every process of it for root, an account's own otherwise, and init, root's, for everyone.

Process hosts reconcile registry state every five seconds and after events reconnect, using
`ProcKeep` proofs for only the processes they own. This remains valid across login/logout.
A host lease lasts 30 minutes; a Machine alarm kills and reaps abandoned processes. Process
credentials expire after an hour and renew in batches every ten minutes; revoked or expired
tokens cannot be revived. Job credentials expire after at most a week. Authority alarms close
descriptors when credentials expire. Inactive guests are pruned after 30 days only if they own
no inodes, live credentials or job records. Pruned guest UIDs are never assigned to another
browser, since another owner's named ACL may still refer to them.

`placement.rs` defines local browser and container placement labels. Process/exec results and
credential snapshots carry cluster, executor and cgroup metadata; those labels grant no
permission. Descriptors remain tied to the credential lineage that opened them. `ProcInit`
returns feature flags, lease duration and Machine counters; the authority also counts syscall
and inline byte requests. `abi::Completion` reserves the request/index/result representation
for future asynchronous queues. Cluster execution and completion queues remain disabled;
cgroup enforcement and real init remain later phases.

## Roadmap

[Issue #40](https://github.com/kingwingfly/os/issues/40) amends [#20](https://github.com/kingwingfly/os/issues/20): executable convergence, the typed device/executor boundary and the full readiness gate are complete locally. The owner explicitly required this gate before Phase 6 on 2026-11-08. Phase 6 remains pending for init, sessions/process groups, cgroup enforcement and a reproducible installed shell. `/usr/bin/sh` is not installed; dash remains the approved test/uploaded fixture. Exhaustive GNU options, arbitrary remote images and distributed scheduling are not part of this overhaul gate.

WASI preview 1 does not carry Unix owners, mode bits or ACLs. `crates/posix` supplies that metadata over the existing process-authenticated OS interface. The pinned uutils `ls` platform patch consumes it, preserving uutils parsing and formatting for every shell. No new syscall or browser command handler is involved; see `crates/coreutils/vendor/uu_ls/OS-PATCH.md`. The small `uu_cat` platform patch uses wasi-libc stat to recognize character/block devices (including local PTYs), and WASI ELOOP for symlink-loop diagnostics; its provenance and scope are in `crates/coreutils/vendor/uu_cat/OS-PATCH.md`.

The next steps agreed in issue #20, and the ideas recorded for later.

- **WASIX beyond processes:** threads (`thread_spawn`, futexes that wait), signal handlers (`callback_signal`) and sockets answer ENOSYS or do nothing yet. PTYs and WASIX tty modes are implemented in Phase 5. The approved `dash` fixture starts at `/` regardless of the supplied working directory; probes also observed empty redirected/piped output from its builtin `printf`. Tests explicitly change directory and use installed `/usr/bin/printf`; the cause of the builtin behavior has not been established. `/dev/null` is not implemented, so dash's automatic stdin redirection for background commands fails. These are recorded compatibility gaps, not claims of full Linux behavior.
- **Compile pipeline:** `ModuleCompiler` owns the server transform/cache, separately from the filesystem authority. Its container parses modules without executing them, with input/output limits and a timeout. Bump `compiler::VERSION` when changing the transform or Binaryen version.
- **GUI programs:** the WASI graphics proposal (`wasi:webgpu`, `wasi:surface`, `wasi:frame-buffer`), implemented in each process's Worker on WebGPU and a canvas handed over from the compositor's window. `/dev/display` is the permission gate. Web content runs in sandboxed frames, since a browser cannot run as a wasm process.
- **Mounts and clusters:** a directory of the user's device mounted live, shared across devices and sessions peer to peer, or through a Cloudflare relay. Map/reduce across opted-in clients and Containers (the h264 to av1 example). Bytes go through a relay Durable Object per mount or cluster, never through the authority.
- **io_uring-style queues:** a batch is already a submission queue of calls. A completion ring in shared memory, with calls completing out of order, would let a program keep many calls in flight without waiting on each, as `ls` over uutils makes tens of calls.
- **JIT and AOT:** the module cache keyed by content is where compiled and transformed code (asyncify, fuel for CPU limits, ahead-of-time builds) can be kept and reused.
- **eBPF-style hooks:** small verified programs the kernel runs at syscall boundaries, for tracing, accounting and policy (cgroups, seccomp-like filters), without trusting user space.

## Storage and project boundaries

| Path | Responsibility |
| --- | --- |
| `crates/abi` / `os-abi` | The system calls: what each takes and gives back, and errno with glibc's words |
| `crates/kernel` / `os-kernel` | The file system's system calls, every check Linux's (namei, generic_permission with ACLs, sticky directories, protected links, xattrs), over a `Store`, tested in memory |
| `crates/userland` / `os-userland` | The programs of user space, each over `Sys` and nothing else, with GNU's messages and dates |
| `crates/utilities` / `os-utilities` | Installed WASI multicall tools for filesystem/permission/metadata operations, processes/accounts, grep, fd and xargs |
| `crates/posix` / `os-posix` | Shared process-authenticated OS-call, metadata, spawn and wait adapters for WASI programs |
| `crates/coreutils` / `os-coreutils` | /usr/bin's uutils binary: uutils' coreutils for `wasm32-wasip1`, a workspace of its own, and `syscall` over `os.sys` |
| `web/wasi/` | The WASI engine: `exec.mjs` runs a pipeline of processes, `process.js` is a process (a Worker), `pipe.js` a pipe between them |
| `web/_headers` | The page's isolation from other sites, which lets it share memory with its processes |
| `crates/core` / `os-core` | Shared command definitions and completion/manual metadata (`cli/`, with clap); paths, shell parsing, grep patterns, fd matching, completion, ACLs, HTTP Range |
| `crates/frontend` / `os-ui` | Leptos CSR terminal: tabs (`lib.rs`), the shell and its pipelines (`shell.rs`), the commands that run in the page (`shell/commands.rs`), upload hashing (`uploads.rs`), file previews (`preview.rs`, `viewer.rs`), man's pages for app.js (`manual.rs`) |
| `crates/preview` / `os-preview` | Preview web workers: PDF pages (hayro), Mermaid diagrams (merman), highlighted code (arborium, four language groups) |
| `crates/worker` / `os` | The kernel's host: the Worker streams file bytes (`files.rs`); the `OsAuthority` Durable Object serves the system calls (`sys.rs`), descriptors (`fds.rs`), /proc (`procfs.rs`), /usr (`usr.rs`), devices (`dev/`), archive jobs (`jobs.rs`), exec credentials (`creds.rs`) and accounts (`commands/accounts.rs`, api.rs), in SQLite tables (`db.rs`); each browser's `Machine` Durable Object keeps its processes and cgroups (`machine.rs`, `procs.rs`) |
| `web/app.js` | Browser bridge, authentication dialogs, the preview dialog's shell and games, focus handling |
| `web/upload.mjs` | Chunked, resumable uploads |
| `web/record.mjs`, `web/sound.mjs` | Recording the microphone into a growing file; live sound through Realtime |
| `crates/worker/src/dev` | /dev's drivers: archive/media acceleration (`accelerator.rs`), presentations (`present.rs`) and live sound (`snd.rs`, `realtime.rs`) |
| `crates/jobs` / `os-jobs` | The job container's HTTP server: zip and tar, read and written deterministically, and MP4 faststart |
| `containers/jobs/Dockerfile` | Its image: a static binary, built from the workspace |
| `crates/worker/src/runner.rs`, `jobs.rs` | Jobs: the `JobRunner` Durable Object, and the authority's side of them |
| `web/editor.mjs` | Lazy-loaded CodeMirror editor |
| `web/faststart.mjs` | MP4 structural inspection |
| `scripts/` | Local setup, frontend build, sample seeding |
| `wrangler.toml` | Worker, assets, FILES R2, AUTHORITY, MACHINE, JOBS and COMPILER (the last two with containers), and rate-limit bindings (sign-ins; listening to live sound) |
| `seed/` | English sample content |

R2 stores bytes, as immutable chunk objects (`chunks/<file>/<index>-<random>`: each write has its own key, and the first one committed for an index is kept). `OsAuthority`, one Durable Object, keeps everything else in SQLite tables of its own storage (`crates/worker/src/db.rs`): accounts, groups, sessions, one row per path (`nodes`), and each file's content (`files`) with its committed chunks (`chunks`). A file has a fixed chunk size, so chunk *i* starts at *i* × the chunk size.

Every decision is one synchronous SQLite transaction (`transactionSync`, bound by hand since workers-rs 0.8.7 has no binding): the permission checks and the writes they allow happen together or not at all, and nothing awaits inside a transaction. File bytes never pass through the authority. The Worker asks it whether a request may read or write, streams to or from R2 itself, then asks it to record what it wrote, which it checks again. So requests do not wait on each other's transfers: one upload does not hold up anyone's listing or download.

Nodes refer to files by id, and copies share files. A file nobody refers to any more goes to a garbage table in the same transaction, and an alarm deletes its R2 objects, in batches; the same alarm expires idle uploads. Home moves, `mv`, and `cp` change metadata only. Write through the application API; direct bucket writes add nothing to the tables. Keep the bucket private.

The R2 initialization marker (`system/os-authority-v2`) makes a missing authority fail closed instead of starting over with an empty filesystem. Back up R2, the Durable Object's storage, and credentials together; for local development, the whole `.wrangler/state` directory and `.dev.vars`. Changing the pepper breaks existing password verification. Nothing is deployed yet, so there is no migration from earlier storage formats.

This architecture targets personal or small-team use: one authority orders all decisions, which are short.

This is an independent workspace. Worker name: `os`; bucket: `os-files`; bindings: `FILES`, `ASSETS`, `AUTHORITY`, `MACHINE`, `JOBS`, and `COMPILER`. Content projects can reuse the build output with their own assets, configuration, data, and credentials. Copy the Durable Object declarations and migrations from `wrangler.toml`: `OsAuthority` (`v1-users-permissions`), `JobRunner` (`v2-job-runner`), `Machine` (`v3-machine`), and `ModuleCompiler` (`v4-module-compiler`), including both container images. Never connect an empty unrelated authority to an initialized bucket.

## Validation

The OS rename validation on 2026-11-08 completed **338/339 integration cases in the full run** (30.2 minutes). One live-audio WebRTC connection failed to establish; the complete nine-case sound suite then passed without code changes. All **339 distinct cases have passing latest results**, plus all six separate Chromium/Firefox fullscreen checks, 103 Rust tests and 22 Node tests. This is a full run plus an affected-suite rerun, not a single clean full run. Renamed builds, Clippy and manifest checks pass. Migration checks cover saved preferences, session tabs/history/Files paths, old cookies, both WASM import namespaces and legacy frontend content IDs; the existing local server retains its data. Evidence: `/tmp/os-rename-{full-gate,sound-rerun,fullscreen-final,smoke-final,manual-smoke,legacy-clone}.log`.

Before the rename, the 2026-11-08 #40 O5 gate passed **329/329 Chromium/Firefox browser/API/container cases in one clean full run** (29.7 minutes), plus all six separate Chromium/Firefox fullscreen checks. All **103 Rust tests and 20 Node tests** pass, as do native all-target, wasm UI/Worker/client-kernel and WASI utilities/coreutils Clippy, formatting, release web/Worker builds and executable-manifest size checks. Validation used fresh seeded state, the approved dash fixture, `OS_NO_SHARED_WORKER=1` and real compiler/archive containers, without a compiler transport override. The overhaul's implementation gate is complete locally; the documented `dd`, `/dev/null`, shell/session and remote-image limits remain explicit follow-up work.

Evidence: `/tmp/tw-o3-full-gate.log`, `/tmp/tw-o3-fullscreen.log`, `/tmp/tw-o3-{rust,node-final,native-clippy,wasm-clippy-final,utilities-clippy,coreutils-clippy,web-cleanup,worker-gate}.log`. The earlier 304-case utility gate is superseded by this clean full run.

```bash
# Set WASIX_DASH to the approved WASIX dash fixture for the shell/fork checks.
npm test
cargo test -p os-posix -p os-utilities
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p os -p os-ui -p os-client-kernel --target wasm32-unknown-unknown --release -- -D warnings
cargo clippy -p os-utilities --target wasm32-wasip1 --release -- -D warnings
cargo clippy --manifest-path crates/coreutils/Cargo.toml --target wasm32-wasip1 --release -- -D warnings
npm run build
npx playwright install chromium firefox
# With a fresh local instance running and English samples seeded:
OS_NO_SHARED_WORKER=1 npm run test:e2e
OS_NO_SHARED_WORKER=1 npx playwright test --config playwright.fullscreen.config.js --project chromium --project firefox
```

Use an isolated data directory for integration tests if your everyday root password has changed. Do not reset everyday credentials to satisfy tests:

```bash
# Start from this repository; choose an unused local port and fresh temporary state.
node scripts/dev.mjs --ip 127.0.0.1 --port 8790 --persist-to /tmp/os-test-state
# In another terminal:
OS_PORT=8790 npm run seed
OS_TEST_URL=http://127.0.0.1:8790 npm run test:e2e
# The same complete suite with SharedWorker unavailable:
OS_NO_SHARED_WORKER=1 OS_TEST_URL=http://127.0.0.1:8790 npm run test:e2e
```

Integration tests use the bootstrap password in `.dev.vars`; fresh test state makes that predictable. Tests create disposable accounts/files. The editor-focus regression mocks storage and does not require credentials.

The complete gate requires working container networking for archives and server-side fork
compilation. Set `WASIX_DASH` to the approved dash fixture to include its optional tests.
`TW_TEST_COMPILER_URL=http://127.0.0.1:PORT` is only a component-test aid: it routes authorized
image bytes to a standalone compiler and does not validate Wrangler's container transport or
the R2 cache. Leave it unset for the full gate.

Fullscreen checks can run in Chromium and Firefox:

```bash
npx playwright install chromium firefox
npx playwright test --config playwright.fullscreen.config.js --project chromium --project firefox
```

WebKit requires its browser/system dependencies and is not equivalent to physical Safari. Unit tests cover parsing, completion, permissions, moves, removal, ranges, and MP4 boxes. Browser/API tests cover identity, sudo, password changes, ACL enforcement, uploads, editing, focus recovery, media, presentations, and fullscreen.

Remote deployment (`npm run deploy`) requires the owner's account access, bucket, and secrets; tests never deploy.

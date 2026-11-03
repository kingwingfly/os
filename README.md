# Terminal Worker

A browser-based file terminal backed by Cloudflare R2, with accounts, groups, Unix-style permissions, media previews, presentations, and optional games. Rust and Leptos implement the terminal; a Rust Worker and Durable Object implement the filesystem and authorization. Configuration uses `wrangler.toml`.

For maintainers and incoming agents, start with [AGENT.md](AGENT.md).

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

`seed` is local-only, defaults to port 8787, and preserves existing files. It installs `welcome.md`, `readme.txt`, `demo.slides.md`, and a generated `media/signal.wav`. Use `TERMINAL_PORT` to select another local instance. After changing root's password, supply the current password through `TERMINAL_PASSWORD` rather than changing the bootstrap secret.

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

Every command supports `-h` and `--help`, generated, as is its page in `man COMMAND`, from the command's definition (`crates/core/src/cli`), which also parses its arguments. A wrong argument gets one line saying what was wrong, such as `rm: missing PATH...; rm -h shows how to use it`. Help runs before authentication or side effects, including `sudo chmod -h`. `--` terminates help/option interpretation where supported, as in `rm -- -h`.

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
| Identity | `whoami`, `id [USER]`, `groups [USER]`, root-only `users` |
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

`A | B` passes what A writes to B. Commands that read input are the text filters `cat`, `head`, `tail`, `grep` (Rust regular expressions, as with `grep -E`), `wc`, `sort`, and `uniq`, plus `xargs`, which runs a command with the items it reads (`-0`, `-d`, `-n`, `-I`, `-r`, `-t`, as in GNU xargs). Stages run one after another in the browser, as programs of user space, each command's system calls in batches. Other shell operators (`&&`, `||`, `;`, `<`, `>`, `&`) are refused rather than taken literally; quote them to use them as text. Unquoted wildcards expand as in bash before a stage runs: `*`, `?` and `[...]` (`[a-z]`, `[!x]`) match names in each part of a path (`rm -rf *`, `cat docs/*.md`, `echo */`), sorted by byte order as `ls` sorts here (bash's order under `LC_ALL=C`: `B.md` before `a.md`), listed with the caller's permissions. Names starting with a dot match only a pattern starting with one; quoted or escaped wildcards are literal; a pattern that matches nothing stays as typed. Brace expansion (`{a,b}`) and `**` are not supported; `fd` fills that role. Quoting follows bash: single quotes keep everything as it is; within double quotes a backslash escapes only `$`, `` ` ``, `"`, `\` and a newline, and is kept before anything else (`grep "\d+"` searches for `\d+`); outside quotes it escapes any character.

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

What programs write for a terminal shows as they mean it, as an xterm shows it: SGR's colours (the 16, whose shades suit the theme, 256, and 24-bit) and styles (bold, dim, italic, underline, inverse, strike), and OSC 8's links (`http` and `https` ones open in a new tab). What moves a cursor or clears a screen has no place in a transcript and is dropped. A program of /usr/bin knows it writes to a terminal, unless piped (`coreutils ls --color=auto`).

The main font is 20px. A file name keeps to one line; one too long slides back and forth to show the rest, when pointed at or focused, or always on touch screens. Terminal scrollbars are hidden while scrolling remains available. Icons distinguish media and file types; ls highlights directories and executable markers with a restrained palette.

Tab lists fuzzy completions, including Unicode and quoted paths, within the last stage of a pipeline and for the command `xargs`, `sudo`, or `fd -x` runs; a sole match completes at once. Of several, the first Tab only lists them, so that more may be typed to narrow them down; Tab and Shift+Tab then cycle through them. Empty input browses current files. Right arrow accepts; Esc cancels; up/down navigate history or completion choices. Ctrl+C clears the current input and completion, and stops the command running in that tab at its next step: the request in flight finishes, nothing more runs, and an upload the tab runs is cancelled. A command that asks a question (`mv -i`) takes the next line as its answer.

The terminal has tabs, each with its own working directory, history, and running command, so several things can run at once: Alt+T opens one, Alt+W closes it, Alt+1–9 switch, and they survive a reload of the page. All tabs share one account, as they share one session cookie: `su`, `login`, and `exit` change it for every tab. Typing on the idle desktop, outside another window, focuses the terminal while dialogs, selections, shortcuts, and IME keep their behavior. Closing authentication or editor dialogs restores actual text-entry focus.

## The desktop

The page is a desktop: a bar with the account, the area its windows are laid out in, and a dock. Terminal, Files, Preview and Editor are windows. A compositor in the page's wasm (`crates/frontend/src/desktop.rs`) lays them out as elements of the page, by their place, size and stacking; nothing is drawn on a canvas.

- A window's bar moves it, and its edges and corners resize it, down to 280 × 180. A press anywhere in it brings it up, with the keyboard.
- Let go at the top of the desktop, a window fills it; at the left or right edge, it fills that half. Dragged away, it is free again at its own size; freed by its button or a double click on its bar, it goes back where it was.
- The buttons in its bar minimize it, fill the desktop with it, and close it.
- The dock shows each app, marking those open and the one with the keyboard. A click opens an app, brings it up, or minimizes it if it is the one up. Preview and Editor are there while open.
- The launcher (⋮⋮) opens Terminal, Files, the manual, and upload.
- Ctrl+Alt+← and → put the window up in a half, Ctrl+Alt+↑ fills the desktop with it, and Ctrl+Alt+↓ frees it, or minimizes it if it is free. Alt+` goes to the next window.

The Files keep a directory of their own, apart from the terminal's, which `cd` does not move: its location, at the top, takes a path typed (`~` for the account's home); a click goes into a directory, `../` out of it, and opens a file in the preview. Nothing done in the Files is a command of the terminal, nor shows in it: what they cannot do, and an upload's progress, show in them. Their upload button, the launcher's, and files dropped on them upload into their directory; files dropped elsewhere, into the terminal's, as `upload` does there. Each browser tab keeps where its Files are.

Each browser keeps its layout (localStorage `terminal-desktop`). Nothing is modal but signing in: the preview and the editor are windows among the others, and what is typed goes to the window that has the keyboard.

## Phones and touch screens

Below 650 px wide the desktop shows one window at a time, filling the visible screen. The dock goes from one to another, and minimizing or closing the one shown shows the next. app.js follows the screen as the on-screen keyboard opens (`visualViewport`; `interactive-widget=resizes-content` on Chromium), and the terminal keeps its command line at its foot. While the keyboard is open, the bar and the dock make room. The wallpaper and the button that fills a window are hidden; the account button stays on one line; `ls -l` keeps an entry a line and scrolls sideways. Touch screens get the keys their keyboards lack, Tab, ↑, ↓, ^D and ^C, under the command line; a tap on the transcript goes to the command line; nothing autocapitalizes or corrects commands.

## Uploads and previews

Uploads use current account permissions. Publicly writable directories accept guest writes. The UI does not overwrite existing names; `open` with `O_TRUNC` replaces a file one may write, only if it is still the version given, if one is. Files may be up to 1 GB. Identity changes close open previews.

Files are written through file descriptors (system calls `open`, `pwrite`, `close`; large chunks stream on the Worker), as uploads, the editor's saves, recordings and copies all are. A descriptor belongs to its session: a signed-in account's, or, signed out, the browser's own (a `terminal_guest` cookie, given at once), so every page of a browser may use it, as threads share a process's. The browser uploads in chunks of 8 MiB, three at a time, each with its SHA-256, which R2 checks. A file is hashed first; opening it again with the same SHA-256 and size, by the same account, goes on with the chunks the kernel already has, on the same device or another. One descriptor writes a file at a time: every batch a session sends keeps its descriptors, a page holding one says so every 8 seconds, and another session that opens the same file is told it is being uploaded from another tab or device (EBUSY), until the first page closes it, as it does when it goes, or its session has not been heard from for 20 seconds; the old descriptor then writes no more (EBADF). The same browser may always go on with its own unfinished file. `close` completes the file once every chunk is there; with one missing, the descriptor goes all the same (EIO) and the file waits, unfinished, for a day. Ctrl+C closes the descriptor and removes a file the upload was making. Content is written whole: an existing file is replaced (`O_TRUNC`, an editor's save giving the version it read, ESTALE if it changed). A writer that gives no size writes its chunks in order and the file grows as it writes, readable meanwhile, truncated as it opens and whole when it closes (a program's output); a recording is that, appended to (`O_APPEND`). `cp` clones content (`ioctl(FICLONE)`): nothing is copied, whatever the size; a binary of `/usr` is shared so too, while what the kernel makes as it is read (`/etc/passwd`, `/proc`, a device's state) cannot be cloned (EOPNOTSUPP), and `cp` reads it and writes what it read, as `cp --reflink=auto` does. A descriptor opened as root, or under sudo, reads and writes as root to its end, the Worker's streams included, as a descriptor keeps the access it was opened with. A session's descriptor numbers are given once each, from 3 on: its pages share them, and one may still use a number another closed. `jobs` lists the browser's descriptors that write files (`/proc/self/fd`; not a process's standard input, nor a device), and `jobs cancel fdN` closes one.

A file is listed as soon as its upload starts, with its progress (the bytes that have arrived, counted as the uploading tab counts them), and can be read while it arrives: a download, or a video, follows the upload, waiting for each chunk not sent yet (for up to 60 seconds without progress). An overwritten file shows its old content until the new upload completes.

Every page keeps a WebSocket to the authority (`GET /api/events`, accepted only from this site's origin, hibernating while idle). A page watches the directories it lists (`inotify_add_watch`), and after each change the authority tells the pages of each session watching a changed directory, while its account may list it, before it answers the request that changed it; the tabs showing one list it again: files created, moved, removed or uploaded on one device appear on the others as it happens. The page answers what only looks (`stat`, `lstat`, `getdents`, `access`, `readlink`) from a cache while the directory it is in is watched, as an NFS client answers from its attribute cache: listing a directory again asks the kernel nothing. What the kernel says changed, anything the page changes itself, a new account and a line that dropped clear it, and nothing is trusted past 15 seconds. A line that drops opens again and lists what was missed. Pages also say over it which slide, or presented PDF page, they show, which the authority keeps as where the account last showed it and passes to the account's pages signed in elsewhere and to the followers of its presentations; they ask where a deck was last shown, and which devices of /dev they follow (Presentations, below). A page whose session ends elsewhere (signed out, a password changed, the account locked or removed, or the session expired) is told at once, and its tabs say so and show guest; windows of one browser, which share its session, follow each other's `su`, `login` and `exit`.

| API | Purpose |
| --- | --- |
| `GET /api/events` | The page's line (a WebSocket): what changed, what devices it follows do, and the drivers' news to it |
| `POST /api/sys` `{calls, umask, sudo}` | System calls (owner's design, 2026-10-29: the page is user space): a batch of calls, each run on its own, in order, each answered with its value or its errno (`crates/abi`). The terminal's file programs (ls, rm, chmod, setfacl...) are made of these, in the page (`crates/userland`) |
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

`zip`, `unzip`, and `tar` behave as their Linux namesakes do, for the options in `man`, and run on the server as jobs, so the archive's bytes never pass through the browser; so does `faststart`:

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
- Jobs are processes (system calls `spawn`, `kill` and `wait`; `spawn` gives a descriptor of the process's standard input, which unzip's answers are written to): they go on when their tab or the page closes; `ps` lists them from `/proc`, `kill PID` stops one, and `jobs` lists them with the browser's unfinished uploads (`jobs cancel ID` stops either).

Each job (zip, unzip, tar, faststart) has a `JobRunner` Durable Object and a container (`crates/jobs`, built by `containers/jobs/Dockerfile` into a 2 MB image) that reads and writes the archives, or the video, on its disk. The runner streams the job's files from R2 into the container and its output back, a chunk per request, and keeps its plan in its own storage, so that a restart of it or of the container resumes the job: extraction continues with the next member, and a new archive is rebuilt and checked, chunk by chunk, against what was stored before (its bytes are deterministic: fixed dates, owners, and deflate settings). Deploying requires Cloudflare Containers, on the Workers Paid plan.

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

So for a talk whose files are `u:guest:r` (`setfacl -R -m u:guest:rX DIR`, so that its images may be read too): the laptop runs `present talk.slides.md` and presses S for the speaker view; the phone, signed in to the same account, opens the deck and turns it; the audience opens `/dev/present/talk` on their phones, signed in or not.

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

The page is user space and the API is the system calls (owner's design, 2026-10-29), as on Linux. The terminal's programs (`ls`, `rm`, `cp`, `chmod`, `useradd`, `ps`…) run in the browser (`crates/userland`), parse their options, print coreutils' messages, and do everything through system calls; whether anything may be done is the kernel's to say, call by call: the Worker and its Durable Object (`crates/kernel`, `crates/worker`). User space is never trusted. Calls go in batches (`POST /api/sys`), each run on its own, in its own transaction, answered with its value or its errno (glibc's words, `crates/abi`). A call may name the descriptor an earlier call of the batch opened (`{"ref": i}`, as NFSv4's COMPOUND passes a filehandle on), so opening, writing and closing a small file is one request; a call naming one that failed fails as it did. Bytes travel as base64: up to 256 KiB a call in the batch (`pread`, `pwrite`), more on the Worker (`GET /api/file`, `PUT /api/pwrite`).

| Group | Calls |
| --- | --- |
| Credentials | `getcreds`; `login`, `logout`, `sudo` (its five-minute timestamp), `passwd` |
| Accounts | `useradd`, `usermod`, `userdel`, `groupadd`, `groupmod`, `groupdel` (root's; a signed-out `useradd` NAME, and an account's own `userdel`, with a password); `/etc/passwd` and `/etc/group` are generated as they are read |
| Names | `stat`, `lstat`, `getdents` (each entry with its `lstat`, from a `cookie`, `count` at a time), `access`, `readlink`, `mkdir`, `mknod`, `rmdir`, `unlink`, `rename` (`noreplace`), `link`, `symlink`, `chmod`, `chown`, `utimensat` (each time now, unchanged or given, in nanoseconds), `getxattr`, `setxattr`, `listxattr`, `removexattr` (ACLs are `system.posix_acl_access` and `system.posix_acl_default`), `statfs` |
| Watches | `inotify_add_watch` (a directory the caller may list; at most 128 a session), `inotify_rm_watch`; what changes in one is told on the session's lines of the events socket, as `IN_MODIFY` of its watch |
| Descriptors | `open` (`O_RDONLY`, `O_WRONLY`, `O_CREAT`, `O_EXCL`, `O_TRUNC`, `O_APPEND`, `O_DIRECTORY`; a size, or none to write in order; a SHA-256 to go on with an unfinished file; a version to replace only what was read; a whole file read gives a token, its bytes' by `GET /api/file?token=`), `pread`, `pwrite`, `close`, `ioctl` (`FICLONE`). Every batch keeps its session's descriptors |
| Devices | `mknod` with a driver (`present`, `snd`), and the drivers' requests as `ioctl`s: `PRESENT_SHOW`, `PRESENT_ASK`, `PRESENT_ANSWER`, `PRESENT_SPEAK`, `SND_PUBLISH`, `SND_LISTEN`, `SND_ANSWER`; reading one gives its state |
| Processes | `spawn` (zip, unzip, tar, faststart; with a descriptor of its standard input), `kill`, `wait` |

`/proc` is the kernel's, as Linux's procfs: `/proc/PID/status` and `/proc/PID/cmdline` for the account's processes (others' are not shown, as with `hidepid`), `/proc/self/fd/N` for the session's descriptors and `/proc/self/fdinfo/N` for what each says of itself. `/proc/self/fd/N` is a magic link: a path through it names what the descriptor has open, so a directory's descriptor names what is in it, as `openat` would. `ps`, `kill` and `jobs` read it.

A session is a browser: a signed-in one's, or, signed out, the browser's own (the `terminal_guest` cookie). Descriptors are a session's, shared by its tabs as threads share a process's; a presenter lets a guest speak by passing one to that guest's session. The places where an account last showed a deck (`present` on the events socket) are the one extension with no Linux counterpart.

### /usr: the build's, read-only

`/usr` is the system's own, as an image-based system mounts its `/usr` read-only: what the build put there (the Worker's assets), not R2's. The tree is Arch's: `/bin` and `/sbin` are links to `usr/bin`, `/lib` and `/lib64` to `usr/lib`, `/usr/sbin` to `bin` and `/usr/lib64` to `lib`; `/usr` holds `bin`, `include`, `lib`, `libexec`, `local`, `share` and `src`; `/sys`, sysfs's place, is empty. Changing any of them, or what is below them, fails with EROFS, and archive jobs refuse to write there too. The rest of `/` is the store's, made at first start as Arch has it: `/boot`, `/mnt`, `/opt`, `/run`, `/srv` and `/var` (755), `/tmp` (1777, shared and sticky), `/root` (750), with `/dev`, `/etc`, `/home`, `/proc` and this system's `/guest`. `/usr/bin` holds what a name runs:

- The terminal's own programs (`ls`, `chmod`, `cp`, `passwd`…), built into the page's binary (`/pkg/frontend_bg.wasm`), each a file of it, root's, 755. Those that act beyond the caller's own rights by a policy of their own are setuid root, `-rwsr-xr-x`, as `passwd`, `su` and `sudo` are on Linux, and `useradd` and `userdel`, with which a guest makes an account of its own and an account deletes itself. The bit says, rather than grants: the page cannot be trusted with a setuid program, so the kernel's calls hold each one's policy. Root's tools (`usermod`, `groupadd`…) are 755 and need root, as on Linux. The shell's builtins (`cd`, `exit`, `logout`, `jobs`, `help`) are no files.
- uutils' coreutils, built for `wasm32-wasip1` (`crates/coreutils`, one binary as busybox is), and a link to it of each of its utilities the terminal has no program of its own for (`cut`, `tr`, `seq`, `printf`, `date`, `tee`, `truncate`, `sha256sum`…).

uutils' run as processes of their own in the page's WASI engine (`web/wasi/`). The browser's WebAssembly engine is only a CPU; the engine is what a process imports. Each process is a Worker of its own that instantiates the binary, compiled once, with WASI preview 1 implemented over the system calls, synchronously (the Worker waits on each request, as a process blocks in a call), plus one import of its own, `terminal.sys`, which carries a batch of the kernel's calls as it is, for what WASI has no words for (modes, owners, ACLs, devices, accounts): the `syscall` program makes them. The engine keeps the descriptors (a file read ahead, one written in order, an existing one changed in place by rewriting it whole), the terminal and pipes as its standard streams, the working directory (`PWD`, which the binary enters as it starts) and the time; Ctrl+C terminates the Worker, and output over 10 MB stops it.

A pipeline's processes run at once, each one's output the next one's input through a pipe: 64 KiB of memory the page and its processes share (`web/wasi/pipe.js`), where a reader waits while it is empty and a writer while it is full. A write to a pipe whose reader has gone ends its process, as SIGPIPE does (status 141), so `yes | head -n 3` ends at once: the terminal's `head` closes its input once it has its lines, as GNU head does. What the last writes shows in the transcript as it is written, and so do errors, a line at a time. The first reads the terminal, unless given its input: the command line then says `Input ↵`, a line typed goes to it (echoed, and kept out of the history), Ctrl+D ends a read (after what is typed, if anything is), and Ctrl+C kills the pipeline. Sharing memory needs a page isolated from other sites (`web/_headers`: `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Embedder-Policy: credentialless`, which lets other sites' images load without cookies); where a browser does not isolate it (Safari has no `credentialless`), the processes run one after another, each given what the one before wrote, and nothing reads the terminal. A pipeline joining the terminal's own programs passes text between stages as before. The terminal's own programs run in the page itself, which draws what they give (`ls`'s listing, its icons, colours and uploads' progress) rather than text.

A name runs the terminal's program, or uutils' where it has none; `/usr/bin/NAME`, and `/bin/NAME`, `/sbin/NAME` and `/usr/sbin/NAME` through the links, run what NAME does, and `coreutils NAME` uutils' NAME whatever the terminal has. `help` lists uutils'; `NAME --help` tells how to use one.

## Storage and project boundaries

| Path | Responsibility |
| --- | --- |
| `crates/abi` / `terminal-worker-abi` | The system calls: what each takes and gives back, and errno with glibc's words |
| `crates/kernel` / `terminal-worker-kernel` | The file system's system calls, every check Linux's (namei, generic_permission with ACLs, sticky directories, protected links, xattrs), over a `Store`, tested in memory |
| `crates/userland` / `terminal-worker-userland` | The programs of user space, each over `Sys` and nothing else, with GNU's messages and dates |
| `crates/coreutils` / `terminal-worker-coreutils` | /usr/bin's uutils binary: uutils' coreutils for `wasm32-wasip1`, a workspace of its own, and `syscall` over `terminal.sys` |
| `web/wasi/` | The WASI engine: `exec.mjs` runs a pipeline of processes, `process.js` is a process (a Worker), `pipe.js` a pipe between them |
| `web/_headers` | The page's isolation from other sites, which lets it share memory with its processes |
| `crates/core` / `terminal-worker-core` | Every command's definition, parser, help and manual page (`cli/`, with clap); paths, pipelines, text filters, fd matching, completion, ACLs, HTTP Range |
| `crates/frontend` / `terminal-worker-ui` | Leptos CSR terminal: tabs (`lib.rs`), the shell and its pipelines (`shell.rs`), the commands that run in the page (`shell/commands.rs`), upload hashing (`uploads.rs`), file previews (`preview.rs`, `viewer.rs`), man's pages for app.js (`manual.rs`) |
| `crates/preview` / `terminal-worker-preview` | Preview web workers: PDF pages (hayro), Mermaid diagrams (merman), highlighted code (arborium, four language groups) |
| `crates/worker` / `terminal-worker` | The kernel's host: the Worker streams file bytes (`files.rs`); the `TerminalAuthority` Durable Object serves the system calls (`sys.rs`), descriptors (`fds.rs`), /proc (`procfs.rs`), /usr (`usr.rs`), devices (`dev/`), processes (`jobs.rs`) and accounts (`commands/accounts.rs`, api.rs), in SQLite tables (`db.rs`) |
| `web/app.js` | Browser bridge, authentication dialogs, the preview dialog's shell and games, focus handling |
| `web/upload.mjs` | Chunked, resumable uploads |
| `web/record.mjs`, `web/sound.mjs` | Recording the microphone into a growing file; live sound through Realtime |
| `crates/worker/src/dev` | /dev's drivers: presentations (`present.rs`) and live sound (`snd.rs`, `realtime.rs`) |
| `crates/jobs` / `terminal-worker-jobs` | The job container's HTTP server: zip and tar, read and written deterministically, and MP4 faststart |
| `containers/jobs/Dockerfile` | Its image: a static binary, built from the workspace |
| `crates/worker/src/runner.rs`, `jobs.rs` | Jobs: the `JobRunner` Durable Object, and the authority's side of them |
| `web/editor.mjs` | Lazy-loaded CodeMirror editor |
| `web/faststart.mjs` | MP4 structural inspection |
| `scripts/` | Local setup, frontend build, sample seeding |
| `wrangler.toml` | Worker, assets, FILES R2, AUTHORITY, JOBS (with its container), and rate-limit bindings (sign-ins; listening to live sound) |
| `seed/` | English sample content |

R2 stores bytes, as immutable chunk objects (`chunks/<file>/<index>-<random>`: each write has its own key, and the first one committed for an index is kept). `TerminalAuthority`, one Durable Object, keeps everything else in SQLite tables of its own storage (`crates/worker/src/db.rs`): accounts, groups, sessions, one row per path (`nodes`), and each file's content (`files`) with its committed chunks (`chunks`). A file has a fixed chunk size, so chunk *i* starts at *i* × the chunk size.

Every decision is one synchronous SQLite transaction (`transactionSync`, bound by hand since workers-rs 0.8.7 has no binding): the permission checks and the writes they allow happen together or not at all, and nothing awaits inside a transaction. File bytes never pass through the authority. The Worker asks it whether a request may read or write, streams to or from R2 itself, then asks it to record what it wrote, which it checks again. So requests do not wait on each other's transfers: one upload does not hold up anyone's listing or download.

Nodes refer to files by id, and copies share files. A file nobody refers to any more goes to a garbage table in the same transaction, and an alarm deletes its R2 objects, in batches; the same alarm expires idle uploads. Home moves, `mv`, and `cp` change metadata only. Write through the application API; direct bucket writes add nothing to the tables. Keep the bucket private.

The R2 initialization marker (`system/terminal-authority-v2`) makes a missing authority fail closed instead of starting over with an empty filesystem. Back up R2, the Durable Object's storage, and credentials together; for local development, the whole `.wrangler/state` directory and `.dev.vars`. Changing the pepper breaks existing password verification. Nothing is deployed yet, so there is no migration from earlier storage formats.

This architecture targets personal or small-team use: one authority orders all decisions, which are short.

This is an independent workspace. Worker name: `terminal-worker`; bucket: `terminal-worker-files`; bindings: `FILES`, `ASSETS`, `AUTHORITY`, and `JOBS`. Content projects can reuse the build output with their own assets, configuration, data, and credentials. They must also declare the `TerminalAuthority` class with its SQLite migration `v1-users-permissions`, and for archives the `JobRunner` class (`v2-job-runner`) with its container. Never connect an empty unrelated authority to an initialized bucket.

## Validation

```bash
npm test
cargo fmt --all --check
cargo check --workspace --target wasm32-unknown-unknown
npx playwright install chromium
# With a local instance running and English samples seeded:
npm run test:e2e
```

Use an isolated data directory for integration tests if your everyday root password has changed. Do not reset everyday credentials to satisfy tests:

```bash
# Start from this repository; choose an unused local port and fresh temporary state.
npx wrangler dev --ip 127.0.0.1 --port 8790 --persist-to /tmp/terminal-worker-test-state
# In another terminal:
TERMINAL_PORT=8790 npm run seed
TERMINAL_TEST_URL=http://127.0.0.1:8790 npm run test:e2e
```

Integration tests use the bootstrap password in `.dev.vars`; fresh test state makes that predictable. Tests create disposable accounts/files. The editor-focus regression mocks storage and does not require credentials.

Fullscreen checks can run in Chromium and Firefox:

```bash
npx playwright install chromium firefox
npx playwright test --config playwright.fullscreen.config.js --project chromium --project firefox
```

WebKit requires its browser/system dependencies and is not equivalent to physical Safari. Unit tests cover parsing, completion, permissions, moves, removal, ranges, and MP4 boxes. Browser/API tests cover identity, sudo, password changes, ACL enforcement, uploads, editing, focus recovery, media, presentations, and fullscreen.

Remote deployment (`npm run deploy`) requires the owner's account access, bucket, and secrets; tests never deploy.

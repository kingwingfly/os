## Permissions

Each file and directory has an owner, a group and a mode: owner, group and other permissions select the applicable class, with named ACL entries and their mask where present. Creation applies the requested mode and umask or directory default ACL; the default umask is 022 and private homes are 700. Mounted sources may impose additional access limits.

- **Special bits**: setgid on a directory passes its group to what is made in it; sticky (`+t`, as `/tmp`'s 1777) lets only an entry's owner, the directory's owner or root remove or rename it. Uploaded setuid/setgid bits do not elevate executable privileges.
- **ACLs**: `setfacl` grants named users and groups more than the classes allow, bounded by the mask (the group bits once there is an ACL); a directory's default ACL is what is made in it gets. `ls -l` marks an ACL with `+`.
- **Links**: a hard link is another name for the same file; a symbolic link holds a path, followed by most commands and removed by `rm` as itself. Following a link another account made in a sticky directory others may write is refused (protected_symlinks); hard-linking another's file needs read and write on it (protected_hardlinks).
- **Extended attributes**: `user.*` attributes go with a file, for anyone who may read or write it.

## Accounts and Cloud Sign-In

OS accounts are 100% local to this instance's `os-cowfs` root volume (`/etc/passwd`, `/etc/group`, `/etc/shadow`). By default a fresh instance signs in locally as `user` (uid 1000, in group `wheel`) with zero network requests. Local `root` (uid 0) owns only this instance and never synthesizes remote administrator privileges.

Optional remote services (`/mnt/cloud`, remote devices `/dev/{archive,media,present,snd}`, and relay shares) require explicit **Cloud Sign-In** from the top bar, which mints scoped `ServiceAuth v2` credentials without changing your local OS account.

## Shell and Pipes

The native Terminal application (`/usr/bin/terminal`) runs `/usr/bin/osh` on a UNIX 98 PTY (`/dev/ptmx` → `/dev/pts/N`); `/bin/sh` provides POSIX `dash`. `COMMAND | COMMAND` passes what one command writes to the next, as in `fd -e md | xargs wc -l` or `ls | grep -i report | sort`. Full POSIX shell operators (`&&`, `||`, `;`, `>`, `>>`, `<`, `2>&1`, subshells, functions, variables and background jobs `&`) are supported directly.

## Wildcards

Unquoted `*`, `?` and `[...]` expand to the matching paths, sorted by byte order (`LC_ALL=C`): `rm -rf *`, `cat docs/*.md`, `echo */`. Names starting with a dot match only a pattern that starts with one. Quote or escape a wildcard to keep it literal; within double quotes a backslash escapes only `$`, `` ` ``, `"`, `\` and a newline. A pattern that matches nothing stays as typed.

## Tabs and Applications

Terminal, Files, Mounts, Editor and Preview run as ordinary unprivileged GUI processes under the supervised userspace `compositor` and `desktop-shell`. Each terminal tab owns its own PTY, working directory, history and jobs. Alt+T opens a tab, Alt+W closes it, and Alt+1–9 switch. Running processes retain their captured credentials across account switches.

## Keys

Tab completes commands and paths; ↑ / ↓ browse history; Ctrl+C interrupts the foreground process group (or cancels an active upload); Ctrl+Z stops it for `fg` or `bg`. On touch screens, Tab, ↑, ↓, ^D and ^C have dedicated buttons. Files has Refresh/F5 for sources without change notifications.

## Permissions

Each file and directory has an owner, a group and a mode: owner, group and other permissions select the applicable class, with named ACL entries and their mask where present. Creation applies the requested mode and umask or directory default ACL; the default umask is 022 and private homes are 700. Mounted sources may impose additional access limits.

- **Special bits**: setgid on a directory passes its group to what is made in it; sticky (`+t`, as `/guest`'s 1777) lets only an entry's owner, the directory's owner or root remove or rename it. Uploaded setuid/setgid bits do not elevate executable privileges.
- **ACLs**: `setfacl` grants named users and groups more than the classes allow, bounded by the mask (the group bits once there is an ACL); a directory's default ACL is what is made in it gets. `ls -l` marks an ACL with `+`.
- **Links**: a hard link is another name for the same file; a symbolic link holds a path, followed by most commands and removed by `rm` as itself. Following a link another account made in a sticky directory others may write is refused (protected_symlinks); hard-linking another's file needs read and write on it (protected_hardlinks).
- **Extended attributes**: `user.*` attributes go with a file, for anyone who may read or write it.

## Guests

Signed out, you have an individual **guest-<id>** identity in group guest and own the files you create. `useradd -m NAME` registers an account with a password and a private home at `/guest/NAME`. `/guest` is shared and sticky: only an entry's owner, the directory owner or root can remove it. Share through group bits or a named ACL such as `setfacl -m u:NAME:r FILE`; directories also need traversal (`x`) permission.

## Pipes

`COMMAND | COMMAND` passes what one command writes to the next, as in `fd -e md | xargs wc -l` or `ls | grep -i report | sort`. The desktop's browser shell supports pipelines and external background jobs with `&`; it rejects other operators such as `&&`, `;`, `>` and `<`. Use the installed `sh` for POSIX shell syntax, or quote operators to pass them as text.

## Wildcards

Unquoted `*`, `?` and `[...]` expand to the matching paths, sorted by byte order as `ls` sorts them (bash under LC_ALL=C): `rm -rf *`, `cat docs/*.md`, `echo */`. Names starting with a dot match only a pattern that starts with one. Quote or escape a wildcard to keep it literal; within double quotes a backslash escapes only `$`, `` ` ``, `"`, `\` and a newline, as in bash. A pattern that matches nothing stays as typed.

## Tabs

Each terminal tab has its own working directory, history and jobs. Alt+T opens a tab, Alt+W closes it, Alt+1–9 switch. Browser account changes apply to the page session; running processes retain their captured credentials. Logging out and explicitly shutting down a session are separate operations.

## Keys

Tab lists matching completions below the active input; a single candidate completes immediately. Tab / Shift+Tab cycle candidates; ↑ / ↓ browse history; → accepts and Esc cancels a completion. Ctrl+C interrupts the foreground job when terminal signal handling is enabled, clears idle input, or cancels an active upload. On touch screens, Tab, ↑, ↓ and ^C have dedicated buttons. Files has Refresh/F5 for sources without change notifications.

//! The rules Linux applies to one inode when its attributes change or it gains a name: who may
//! chmod(2), chown(2), utimensat(2) and link(2) it, and what else changes with them. The
//! server's kernel and the VFS drivers (`os-vfs`) both apply these, so their answers agree.

use crate::permissions::{EXEC, Identity, Node, READ, SETGID, SETUID, WRITE};
use abi::{Errno, Time};

/// Whether `cred` may `mask` (READ, WRITE, EXEC) the node, as Linux's generic_permission
/// decides: its mode and ACL say ([`Identity::allows`]); root may anything, but execute only
/// what someone may.
pub fn permission(cred: &Identity, node: &Node, mask: u16) -> bool {
    if cred.id == 0 {
        return mask & EXEC == 0 || node.directory || node.mode & 0o111 != 0;
    }
    cred.allows(node, mask)
}

/// chmod(2): its owner's or root's (EPERM). Without root, setgid needs the node's group to be
/// one of the caller's: it is cleared otherwise, on any kind of node, without an error, as
/// Linux's setattr_copy does.
pub fn chmod(cred: &Identity, node: &mut Node, mode: u16) -> Result<(), Errno> {
    if cred.id != 0 && cred.id != node.owner {
        return Err(Errno::EPERM);
    }
    node.mode = mode & 0o7777;
    if cred.id != 0 && !cred.groups.contains(&node.group) {
        node.mode &= !SETGID;
    }
    Ok(())
}

/// chown(2): root's. Its owner may name itself as the owner, and as the group one of its own or
/// the group it has, as Linux's chown_ok and chgrp_ok allow; anything else is EPERM, even
/// naming the owner it already has. Changing who owns a regular file, or its group, clears its
/// setuid bit, and its setgid bit if its group may execute it.
pub fn chown(
    cred: &Identity,
    node: &mut Node,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<(), Errno> {
    if cred.id != 0
        && (cred.id != node.owner
            || uid.is_some_and(|id| id != node.owner)
            || gid.is_some_and(|g| g != node.group && !cred.groups.contains(&g)))
    {
        return Err(Errno::EPERM);
    }
    if let Some(id) = uid {
        node.owner = id;
    }
    if let Some(id) = gid {
        node.group = id;
    }
    if node.is_file() && (uid.is_some() || gid.is_some()) {
        node.mode &= !SETUID;
        if node.mode & 0o010 != 0 {
            node.mode &= !SETGID;
        }
    }
    Ok(())
}

/// utimensat(2): whether `cred` may set these times. Both omitted, nothing is asked. Set to
/// now, they need the owner, root, or write permission (EACCES); a time given needs the owner
/// or root (EPERM), as Linux's setattr asks.
pub fn may_set_times(cred: &Identity, node: &Node, atime: Time, mtime: Time) -> Result<(), Errno> {
    if atime == Time::Omit && mtime == Time::Omit {
        return Ok(());
    }
    let owner = cred.id == 0 || cred.id == node.owner;
    let given = |time| matches!(time, Time::At { .. });
    if (given(atime) || given(mtime)) && !owner {
        return Err(Errno::EPERM);
    }
    if !owner && !permission(cred, node, WRITE) {
        return Err(Errno::EACCES);
    }
    Ok(())
}

/// The time a [`Time`] sets, in seconds and nanoseconds: `now`, none, or the one given, its
/// nanoseconds at most 999,999,999.
pub fn time(time: Time, now: (u64, u32)) -> Option<(u64, u32)> {
    match time {
        Time::Now => Some(now),
        Time::Omit => None,
        Time::At { sec, nsec } => Some((sec, nsec.min(999_999_999))),
    }
}

/// link(2): another name for the node, never a directory (EPERM). Without owning it, as
/// Linux's protected_hardlinks has it, only a regular file one may read and write, and neither
/// setuid nor setgid and group-executable (EPERM).
pub fn may_link(cred: &Identity, node: &Node) -> Result<(), Errno> {
    if node.directory {
        return Err(Errno::EPERM);
    }
    if cred.id != 0 && cred.id != node.owner {
        let safe = node.is_file()
            && node.mode & SETUID == 0
            && !(node.mode & SETGID != 0 && node.mode & 0o010 != 0)
            && permission(cred, node, READ | WRITE);
        if !safe {
            return Err(Errno::EPERM);
        }
    }
    Ok(())
}

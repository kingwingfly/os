//! Extended attributes, as Linux keeps them: `user.*` on regular files and directories, for
//! whoever may read (to get) or write (to set) them; `trusted.*`, root's alone, which others do
//! not see; and a node's ACLs, `system.posix_acl_access` and `system.posix_acl_default`, which
//! anyone who may look it up reads and its owner or root sets, so that getfacl and setfacl are
//! programs of user space, as on Linux. An ACL's value is its entries, as JSON.
use crate::{Fs, existing, permission};
use abi::{ACL_ACCESS, ACL_DEFAULT, Errno, Error, XATTR_CREATE, XATTR_REPLACE};
use terminal_worker_core::acl::Entries;
use terminal_worker_core::permissions::*;
use terminal_worker_core::xattr::{NAME_MAX, TOTAL_MAX, VALUE_MAX};

type Result<T> = std::result::Result<T, Error>;

enum Space {
    User,
    Trusted,
    Access,
    Default,
}

fn space(name: &str) -> Result<Space> {
    if name.len() > NAME_MAX {
        return Err(Errno::ERANGE.into());
    }
    match name {
        ACL_ACCESS => return Ok(Space::Access),
        ACL_DEFAULT => return Ok(Space::Default),
        _ => {}
    }
    match name.split_once('.') {
        Some(("user", rest)) if !rest.is_empty() => Ok(Space::User),
        Some(("trusted", rest)) if !rest.is_empty() => Ok(Space::Trusted),
        _ => Err(Errno::EOPNOTSUPP.into()),
    }
}

/// Whether `cred` may change the attributes `space` of `node`: user ones on regular files and
/// directories it may write (a sticky directory's, its owner only, as Linux has it), trusted
/// ones as root, ACLs as its owner or root.
fn settable(cred: &Identity, node: &Node, space: &Space) -> Result<()> {
    match space {
        Space::User => {
            if !node.directory && !node.is_file() {
                return Err(Errno::EPERM.into());
            }
            let sticky = node.directory && node.mode & STICKY != 0;
            if sticky && cred.id != 0 && cred.id != node.owner {
                return Err(Errno::EPERM.into());
            }
            if permission(cred, node, WRITE) {
                Ok(())
            } else {
                Err(Errno::EACCES.into())
            }
        }
        Space::Trusted if cred.id == 0 => Ok(()),
        Space::Trusted => Err(Errno::EPERM.into()),
        Space::Access | Space::Default if cred.id == 0 || cred.id == node.owner => Ok(()),
        Space::Access | Space::Default => Err(Errno::EPERM.into()),
    }
}

pub fn get(fs: &impl Fs, cred: &Identity, path: &str, name: &str, follow: bool) -> Result<Vec<u8>> {
    let space = space(name)?;
    let (_, node) = existing(fs, cred, path, follow)?;
    match space {
        Space::Access => {
            let acl = node.acl.as_ref().ok_or(Errno::ENODATA)?;
            Ok(json(&Entries::access(node.mode, Some(acl))))
        }
        Space::Default => node
            .default_acl
            .as_ref()
            .map(json)
            .ok_or_else(|| Errno::ENODATA.into()),
        Space::Trusted if cred.id != 0 => Err(Errno::ENODATA.into()),
        Space::User if !permission(cred, &node, READ) => Err(Errno::EACCES.into()),
        _ => fs
            .xattrs(node.ino)
            .remove(name)
            .ok_or_else(|| Errno::ENODATA.into()),
    }
}

fn json(entries: &Entries) -> Vec<u8> {
    serde_json::to_vec(entries).unwrap_or_default()
}

pub fn set(
    fs: &mut impl Fs,
    cred: &Identity,
    path: &str,
    name: &str,
    value: &[u8],
    flags: u8,
    follow: bool,
) -> Result<()> {
    let space = space(name)?;
    let (real, mut node) = existing(fs, cred, path, follow)?;
    settable(cred, &node, &space)?;
    let has = match space {
        Space::Access => node.acl.is_some(),
        Space::Default => node.default_acl.is_some(),
        _ => fs.xattrs(node.ino).contains_key(name),
    };
    if flags & XATTR_CREATE != 0 && has {
        return Err(Errno::EEXIST.into());
    }
    if flags & XATTR_REPLACE != 0 && !has {
        return Err(Errno::ENODATA.into());
    }
    match space {
        Space::Access | Space::Default => {
            let entries: Entries = serde_json::from_slice(value).map_err(|_| Errno::EINVAL)?;
            if !valid(&entries) {
                return Err(Errno::EINVAL.into());
            }
            if matches!(space, Space::Access) {
                node.set_entries(&entries);
            } else if node.directory {
                node.default_acl = Some(entries);
            } else {
                return Err(Errno::EACCES.into());
            }
            fs.set_node(&real, &node);
        }
        Space::User | Space::Trusted => {
            if value.len() > VALUE_MAX {
                return Err(Errno::E2BIG.into());
            }
            let mut attrs = fs.xattrs(node.ino);
            attrs.insert(name.to_string(), value.to_vec());
            let total: usize = attrs.iter().map(|(k, v)| k.len() + v.len()).sum();
            if total > TOTAL_MAX {
                return Err(Errno::ENOSPC.into());
            }
            fs.set_xattrs(node.ino, &attrs);
        }
    }
    Ok(())
}

/// An ACL's entries, as Linux accepts them: bits within rwx, and a mask once it names anyone.
fn valid(entries: &Entries) -> bool {
    let bits = [entries.user, entries.group, entries.other]
        .into_iter()
        .chain(entries.mask)
        .chain(entries.users.values().copied())
        .chain(entries.groups.values().copied());
    let named = !entries.users.is_empty() || !entries.groups.is_empty();
    bits.into_iter().all(|bits| bits <= 7) && (!named || entries.mask.is_some())
}

pub fn list(fs: &impl Fs, cred: &Identity, path: &str, follow: bool) -> Result<Vec<String>> {
    let (_, node) = existing(fs, cred, path, follow)?;
    let mut names: Vec<String> = fs
        .xattrs(node.ino)
        .into_keys()
        .filter(|name| cred.id == 0 || !name.starts_with("trusted."))
        .collect();
    if node.acl.is_some() {
        names.push(ACL_ACCESS.into());
    }
    if node.default_acl.is_some() {
        names.push(ACL_DEFAULT.into());
    }
    names.sort();
    Ok(names)
}

pub fn remove(
    fs: &mut impl Fs,
    cred: &Identity,
    path: &str,
    name: &str,
    follow: bool,
) -> Result<()> {
    let space = space(name)?;
    let (real, mut node) = existing(fs, cred, path, follow)?;
    settable(cred, &node, &space)?;
    match space {
        Space::Access => {
            if node.acl.is_none() {
                return Err(Errno::ENODATA.into());
            }
            let mut entries = node.entries();
            entries.users.clear();
            entries.groups.clear();
            entries.mask = None;
            node.set_entries(&entries);
            fs.set_node(&real, &node);
        }
        Space::Default => {
            if node.default_acl.take().is_none() {
                return Err(Errno::ENODATA.into());
            }
            fs.set_node(&real, &node);
        }
        Space::User | Space::Trusted => {
            let mut attrs = fs.xattrs(node.ino);
            if attrs.remove(name).is_none() {
                return Err(Errno::ENODATA.into());
            }
            fs.set_xattrs(node.ino, &attrs);
        }
    }
    Ok(())
}

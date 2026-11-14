//! Extended attributes, as Linux keeps them: `user.*` on regular files and directories, for
//! whoever may read (to get) or write (to set) them; `trusted.*`, root's alone, which others do
//! not see; and a node's ACLs, `system.posix_acl_access` and `system.posix_acl_default`, which
//! anyone who may look it up reads and its owner or root sets, so that getfacl and setfacl are
//! programs of user space, as on Linux. An ACL's value is its entries, as JSON. Who may do what
//! is `os_core::xattr`'s, which the VFS drivers share.
use crate::{Fs, existing};
use abi::Error;
use os_core::acl::Entries;
use os_core::permissions::*;
use os_core::xattr::{self, Space};

type Result<T> = std::result::Result<T, Error>;

pub fn get(fs: &impl Fs, cred: &Identity, path: &str, name: &str, follow: bool) -> Result<Vec<u8>> {
    let space = xattr::space(name)?;
    let (_, node) = existing(fs, cred, path, follow)?;
    xattr::readable(cred, &node, space)?;
    match space {
        Space::Access | Space::Default => Ok(json(&xattr::acl(&node, space)?)),
        Space::User | Space::Trusted => fs
            .xattrs(node.ino)
            .remove(name)
            .ok_or_else(|| abi::Errno::ENODATA.into()),
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
    let space = xattr::space(name)?;
    let (real, mut node) = existing(fs, cred, path, follow)?;
    xattr::settable(cred, &node, space)?;
    match space {
        Space::Access | Space::Default => {
            xattr::check_flags(flags, xattr::has_acl(&node, space))?;
            let entries: Entries = serde_json::from_slice(value).map_err(|_| abi::Errno::EINVAL)?;
            xattr::set_acl(&mut node, space, entries)?;
            fs.set_node(&real, &node);
        }
        Space::User | Space::Trusted => {
            let mut attrs = fs.xattrs(node.ino);
            xattr::check_flags(flags, attrs.contains_key(name))?;
            xattr::store(&mut attrs, name, value)?;
            fs.set_xattrs(node.ino, &attrs);
        }
    }
    Ok(())
}

pub fn list(fs: &impl Fs, cred: &Identity, path: &str, follow: bool) -> Result<Vec<String>> {
    let (_, node) = existing(fs, cred, path, follow)?;
    Ok(xattr::listed(cred, &node, fs.xattrs(node.ino).keys()))
}

pub fn remove(
    fs: &mut impl Fs,
    cred: &Identity,
    path: &str,
    name: &str,
    follow: bool,
) -> Result<()> {
    let space = xattr::space(name)?;
    let (real, mut node) = existing(fs, cred, path, follow)?;
    xattr::settable(cred, &node, space)?;
    match space {
        Space::Access | Space::Default => {
            xattr::remove_acl(&mut node, space)?;
            fs.set_node(&real, &node);
        }
        Space::User | Space::Trusted => {
            let mut attrs = fs.xattrs(node.ino);
            if attrs.remove(name).is_none() {
                return Err(abi::Errno::ENODATA.into());
            }
            fs.set_xattrs(node.ino, &attrs);
        }
    }
    Ok(())
}

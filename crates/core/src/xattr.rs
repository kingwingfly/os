//! Extended attributes, as setfattr and getfattr show and change them: `user.*` for anyone who
//! may read (to get) or write (to set) a file or directory, `trusted.*` for root only. Values are
//! bytes, written as text, `0x` and hexadecimal digits, or `0s` and base64.

use crate::acl::Entries;
use crate::inode::permission;
use crate::permissions::{Identity, Node, READ, STICKY, WRITE};
use abi::{ACL_ACCESS, ACL_DEFAULT, Errno, XATTR_CREATE, XATTR_REPLACE};
use std::collections::BTreeMap;

/// The longest name, ...
pub const NAME_MAX: usize = 255;
/// ... the longest value, and the most one node holds, names and values together, as an ext4
/// block does.
pub const VALUE_MAX: usize = 4096;
pub const TOTAL_MAX: usize = 4096;

/// The namespace of an attribute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Namespace {
    User,
    Trusted,
}

/// The namespace of the attribute `name`, which must have one this filesystem keeps.
pub fn namespace(name: &str) -> Result<Namespace, String> {
    if name.len() > NAME_MAX {
        return Err(format!("{name}: Numerical result out of range"));
    }
    let (space, rest) = name.split_once('.').unwrap_or((name, ""));
    if rest.is_empty() {
        return Err(format!("{name}: Operation not supported"));
    }
    match space {
        "user" => Ok(Namespace::User),
        "trusted" => Ok(Namespace::Trusted),
        _ => Err(format!("{name}: Operation not supported")),
    }
}

/// Where an attribute is kept, as the server's kernel and the VFS drivers decide who may get
/// and set it: `user.*` and `trusted.*` among a node's attributes, and its ACLs,
/// `system.posix_acl_access` and `system.posix_acl_default`, in its mode and ACL fields. An
/// ACL's value is its entries, as JSON, so that getfacl and setfacl are programs of user space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Space {
    User,
    Trusted,
    Access,
    Default,
}

/// The space of the attribute `name`: ERANGE for a name past [`NAME_MAX`], EOPNOTSUPP for one
/// in no space kept.
pub fn space(name: &str) -> Result<Space, Errno> {
    if name.len() > NAME_MAX {
        return Err(Errno::ERANGE);
    }
    match name {
        ACL_ACCESS => return Ok(Space::Access),
        ACL_DEFAULT => return Ok(Space::Default),
        _ => {}
    }
    match name.split_once('.') {
        Some(("user", rest)) if !rest.is_empty() => Ok(Space::User),
        Some(("trusted", rest)) if !rest.is_empty() => Ok(Space::Trusted),
        _ => Err(Errno::EOPNOTSUPP),
    }
}

/// Whether `cred` may change the attributes `space` of `node`: user ones on regular files and
/// directories it may write (EPERM on anything else, EACCES without write permission; a sticky
/// directory's, its owner and root only, as Linux has it), trusted ones as root, ACLs as its
/// owner or root (EPERM).
pub fn settable(cred: &Identity, node: &Node, space: Space) -> Result<(), Errno> {
    match space {
        Space::User => {
            if !node.directory && !node.is_file() {
                return Err(Errno::EPERM);
            }
            let sticky = node.directory && node.mode & STICKY != 0;
            if sticky && cred.id != 0 && cred.id != node.owner {
                return Err(Errno::EPERM);
            }
            if permission(cred, node, WRITE) {
                Ok(())
            } else {
                Err(Errno::EACCES)
            }
        }
        Space::Trusted if cred.id == 0 => Ok(()),
        Space::Trusted => Err(Errno::EPERM),
        Space::Access | Space::Default if cred.id == 0 || cred.id == node.owner => Ok(()),
        Space::Access | Space::Default => Err(Errno::EPERM),
    }
}

/// Whether `cred` may read the attributes `space` of `node`: user ones need read permission
/// (EACCES); trusted ones are root's, and others see none (ENODATA); ACLs anyone may read.
pub fn readable(cred: &Identity, node: &Node, space: Space) -> Result<(), Errno> {
    match space {
        Space::Trusted if cred.id != 0 => Err(Errno::ENODATA),
        Space::User if !permission(cred, node, READ) => Err(Errno::EACCES),
        _ => Ok(()),
    }
}

/// setxattr(2)'s flags, given whether the attribute exists: with XATTR_CREATE it must not
/// (EEXIST), with XATTR_REPLACE it must (ENODATA).
pub fn check_flags(flags: u8, exists: bool) -> Result<(), Errno> {
    if flags & XATTR_CREATE != 0 && exists {
        return Err(Errno::EEXIST);
    }
    if flags & XATTR_REPLACE != 0 && !exists {
        return Err(Errno::ENODATA);
    }
    Ok(())
}

/// Whether `node` has the ACL `space`.
pub fn has_acl(node: &Node, space: Space) -> bool {
    match space {
        Space::Access => node.acl.is_some(),
        Space::Default => node.default_acl.is_some(),
        Space::User | Space::Trusted => false,
    }
}

/// The ACL `space` of `node`, as getxattr gives it: ENODATA without one.
pub fn acl(node: &Node, space: Space) -> Result<Entries, Errno> {
    match space {
        Space::Access => node
            .acl
            .as_ref()
            .map(|acl| Entries::access(node.mode, Some(acl)))
            .ok_or(Errno::ENODATA),
        Space::Default => node.default_acl.clone().ok_or(Errno::ENODATA),
        Space::User | Space::Trusted => Err(Errno::EINVAL),
    }
}

/// Take `entries` as the ACL `space` of `node`: EINVAL for entries Linux refuses, EACCES for a
/// default ACL on anything but a directory. An access ACL sets the mode's permission bits.
pub fn set_acl(node: &mut Node, space: Space, entries: Entries) -> Result<(), Errno> {
    if !valid_acl(&entries) {
        return Err(Errno::EINVAL);
    }
    match space {
        Space::Access => node.set_entries(&entries),
        Space::Default if node.directory => node.default_acl = Some(entries),
        Space::Default => return Err(Errno::EACCES),
        Space::User | Space::Trusted => return Err(Errno::EINVAL),
    }
    Ok(())
}

/// Remove the ACL `space` of `node` (ENODATA without one): an access ACL's named entries and
/// mask go, and the mode stays.
pub fn remove_acl(node: &mut Node, space: Space) -> Result<(), Errno> {
    match space {
        Space::Access => {
            if node.acl.is_none() {
                return Err(Errno::ENODATA);
            }
            let mut entries = node.entries();
            entries.users.clear();
            entries.groups.clear();
            entries.mask = None;
            node.set_entries(&entries);
        }
        Space::Default => {
            node.default_acl.take().ok_or(Errno::ENODATA)?;
        }
        Space::User | Space::Trusted => return Err(Errno::EINVAL),
    }
    Ok(())
}

/// An ACL's entries, as Linux accepts them: bits within rwx, and a mask once it names anyone.
pub fn valid_acl(entries: &Entries) -> bool {
    let bits = [entries.user, entries.group, entries.other]
        .into_iter()
        .chain(entries.mask)
        .chain(entries.users.values().copied())
        .chain(entries.groups.values().copied());
    let named = !entries.users.is_empty() || !entries.groups.is_empty();
    bits.into_iter().all(|bits| bits <= 7) && (!named || entries.mask.is_some())
}

/// Set the user or trusted attribute `name` to `value` among a node's `attrs`: E2BIG for a
/// value past [`VALUE_MAX`], ENOSPC once its names and values together pass [`TOTAL_MAX`], as
/// an ext4 block fills. Nothing changes on an error.
pub fn store(attrs: &mut BTreeMap<String, Vec<u8>>, name: &str, value: &[u8]) -> Result<(), Errno> {
    if value.len() > VALUE_MAX {
        return Err(Errno::E2BIG);
    }
    let others: usize = attrs
        .iter()
        .filter(|(key, _)| key.as_str() != name)
        .map(|(key, value)| key.len() + value.len())
        .sum();
    if others + name.len() + value.len() > TOTAL_MAX {
        return Err(Errno::ENOSPC);
    }
    attrs.insert(name.to_string(), value.to_vec());
    Ok(())
}

/// The names listxattr gives `cred` for `node`, whose user and trusted attributes are named
/// `names`: trusted ones to root only, and the ACLs it has, sorted.
pub fn listed<'a>(
    cred: &Identity,
    node: &Node,
    names: impl IntoIterator<Item = &'a String>,
) -> Vec<String> {
    let mut listed: Vec<String> = names
        .into_iter()
        .filter(|name| cred.id == 0 || !name.starts_with("trusted."))
        .cloned()
        .collect();
    if node.acl.is_some() {
        listed.push(ACL_ACCESS.into());
    }
    if node.default_acl.is_some() {
        listed.push(ACL_DEFAULT.into());
    }
    listed.sort();
    listed
}

/// The bytes `text` stands for, as setfattr -v reads it: `0x...` hexadecimal, `0s...` base64,
/// or text, quoted or not, with `\` escapes in quotes.
pub fn decode(text: &str) -> Result<Vec<u8>, String> {
    let invalid = || format!("Invalid value: {text}");
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        // Byte slicing below needs ASCII: `0xaé` would split a character and panic.
        if !hex.is_ascii() || hex.len() % 2 != 0 {
            return Err(invalid());
        }
        return (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| invalid()))
            .collect();
    }
    if let Some(encoded) = text.strip_prefix("0s").or_else(|| text.strip_prefix("0S")) {
        return base64(encoded).ok_or_else(invalid);
    }
    let Some(quoted) = text.strip_prefix('"').and_then(|t| t.strip_suffix('"')) else {
        return Ok(text.as_bytes().to_vec());
    };
    let mut out = Vec::new();
    let mut bytes = quoted.bytes().peekable();
    while let Some(b) = bytes.next() {
        if b != b'\\' {
            out.push(b);
            continue;
        }
        // \\, \", \n and octal \ooo.
        match bytes.next().ok_or_else(invalid)? {
            b'n' => out.push(b'\n'),
            b't' => out.push(b'\t'),
            d @ b'0'..=b'7' => {
                let mut value = u32::from(d - b'0');
                for _ in 0..2 {
                    match bytes.peek() {
                        Some(d @ b'0'..=b'7') => {
                            value = value * 8 + u32::from(d - b'0');
                            bytes.next();
                        }
                        _ => break,
                    }
                }
                out.push(u8::try_from(value).map_err(|_| invalid())?);
            }
            other => out.push(other),
        }
    }
    Ok(out)
}

/// How getfattr writes `value`: `"text"`, with octal escapes for what is not printable,
/// `0x...` or `0s...`, as `encoding` says (`text`, `hex` or `base64`).
pub fn encode(value: &[u8], encoding: &str) -> String {
    match encoding {
        "hex" => format!(
            "0x{}",
            value.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ),
        "base64" => format!("0s{}", to_base64(value)),
        _ => {
            let mut out = String::from("\"");
            for &b in value {
                match b {
                    b'"' | b'\\' => {
                        out.push('\\');
                        out.push(b as char);
                    }
                    0x20..=0x7e => out.push(b as char),
                    _ => out.push_str(&format!("\\{b:03o}")),
                }
            }
            out.push('"');
            out
        }
    }
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn to_base64(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn base64(text: &str) -> Option<Vec<u8>> {
    let text = text.trim_end_matches('=');
    let mut out = Vec::new();
    let mut n = 0u32;
    let mut bits = 0;
    for c in text.bytes() {
        n = n << 6 | ALPHABET.iter().position(|a| *a == c)? as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((n >> bits & 0xff) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_read_and_write_as_the_attr_tools_do() {
        assert_eq!(decode("hello").unwrap(), b"hello");
        assert_eq!(decode("\"a\\\"b\\012\"").unwrap(), b"a\"b\n");
        assert_eq!(decode("0x00ff").unwrap(), [0, 255]);
        assert_eq!(decode("0saGk=").unwrap(), b"hi");
        assert!(decode("0x0").is_err());
        assert!(decode("0xaé").is_err());
        assert_eq!(encode(b"say \"hi\"\n", "text"), "\"say \\\"hi\\\"\\012\"");
        assert_eq!(encode(&[0, 255], "hex"), "0x00ff");
        assert_eq!(encode(b"hi", "base64"), "0saGk=");
        assert_eq!(
            decode(&encode(b"any\x01bytes", "base64")).unwrap(),
            b"any\x01bytes"
        );
    }

    #[test]
    fn only_user_and_trusted_attributes_are_kept() {
        assert_eq!(namespace("user.comment"), Ok(Namespace::User));
        assert_eq!(namespace("trusted.tag"), Ok(Namespace::Trusted));
        for name in [
            "security.selinux",
            "system.posix_acl_access",
            "user.",
            "comment",
        ] {
            assert!(namespace(name).is_err(), "{name}");
        }
    }
}

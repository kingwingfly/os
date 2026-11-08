//! Privileged account policy and shared account validation. CLI parsing is user space.
pub(crate) mod accounts;

use crate::db::Db;

use os_core::{permissions::*, resolve};
use std::collections::BTreeSet;

fn group(c: &Db, name: &str) -> std::result::Result<u32, String> {
    c.group(name)
        .or_else(|| name.parse().ok().filter(|id| c.group_name(*id).is_some()))
        .ok_or_else(|| format!("Group does not exist: {name}"))
}
/// The group named `name`, as groupmod and groupdel take one: by its name only, as on Linux, so
/// that what they refuse to change by name, they refuse by number too.
fn named_group(c: &Db, name: &str) -> std::result::Result<u32, String> {
    c.group(name)
        .ok_or_else(|| format!("Group does not exist: {name}"))
}
fn groups(c: &Db, value: &str) -> std::result::Result<BTreeSet<u32>, String> {
    if value.is_empty() {
        return Ok(BTreeSet::new());
    }
    value.split(',').map(|n| group(c, n)).collect()
}
fn absolute_home(path: &str) -> std::result::Result<String, String> {
    if !path.starts_with('/') {
        return Err("Home must be an absolute path".into());
    }
    let path = resolve("/", path)?;
    if path == "/" {
        return Err("Home cannot be the root directory".into());
    }
    Ok(path)
}
fn protect_home(c: &Db, path: &str, except: u32) -> std::result::Result<(), String> {
    for (_, u) in c.users() {
        // The homes of the accounts guests make are in guest's.
        let a_guests = u.id == GUEST && path.starts_with(&format!("{}/", u.home));
        if u.id != except
            && !a_guests
            && (u.home == path
                || u.home.starts_with(&format!("{path}/"))
                || path.starts_with(&format!("{}/", u.home)))
        {
            return Err("Home must not overlap another account's home directory".into());
        }
    }
    Ok(())
}

pub fn is_permission_error(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("current account is not in the wheel group")
        || message.contains("sudo requires reauthentication")
        || message.contains("permission denied")
        || message.contains("only root")
        || message.contains("only the owner")
        || message.contains("root permission required")
        || message.contains("cannot traverse")
        || message.contains("operation not permitted")
}

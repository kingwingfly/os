//! What the account calls (`accounts`) and processes (jobs.rs) share: a command line as a
//! process is spawned with it (`Command`), the paths it names, and the groups and homes it
//! names. The server runs no commands (owner's design, 2026-10-29): they are user space's.

pub(crate) mod accounts;

use crate::db::Db;
use serde::Deserialize;

use std::collections::BTreeSet;
use terminal_worker_core::{permissions::*, resolve};

#[derive(Deserialize)]
pub struct Command {
    pub args: Vec<String>,
    #[serde(default = "root_path")]
    pub cwd: String,
    #[serde(default)]
    pub sudo: bool,
    /// The home `~` stands for: the signed-in account's, under sudo too, as a shell expands `~`
    /// before sudo runs; if not set, the acting account's.
    #[serde(skip)]
    pub home: Option<String>,
}
fn root_path() -> String {
    "/".into()
}
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

/// `value`, a path typed in `command`, from its working directory, `~` its home, physically: a
/// link on the way, and at its end, followed, as most commands take a path (stat(2)).
pub fn command_path(
    c: &Db,
    who: &Identity,
    command: &Command,
    value: &str,
) -> Result<String, String> {
    c.physical(who, &typed_path(c, who, command, value)?, true)
}
/// The same, but a link at the end is itself, as rm, mv and ln take names (lstat(2)).
pub fn entry_path(
    c: &Db,
    who: &Identity,
    command: &Command,
    value: &str,
) -> Result<String, String> {
    c.physical(who, &typed_path(c, who, command, value)?, false)
}
/// `value` as typed, from the working directory: links not followed.
fn typed_path(c: &Db, who: &Identity, command: &Command, value: &str) -> Result<String, String> {
    let cwd = resolve("/", &command.cwd)?;
    let home = command
        .home
        .clone()
        .or_else(|| c.user_by_id(who.id).map(|(_, user)| user.home))
        .unwrap_or_else(|| "/".into());
    let value = if value == "~" {
        home
    } else if let Some(rest) = value.strip_prefix("~/") {
        format!("{home}/{rest}")
    } else {
        value.into()
    };
    resolve(&cwd, &value)
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

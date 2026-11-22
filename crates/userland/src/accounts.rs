//! Programs on accounts: whoami, id, groups and users, of /etc/passwd and /etc/group, as libc
//! reads them; and useradd, usermod, userdel, groupadd, groupmod and groupdel, which ask the
//! kernel (their policy is its, as setuid programs' is on Linux). A signed-out useradd NAME,
//! and an account's userdel of itself, take a password, in the terminal's dialog (web/app.js).
use crate::files::parsed;
use crate::io::Io;
use crate::sys::{Sys, call};
use abi::{Call, Creds};
use os_core::cli::{accounts as args, parse};
use serde_json::Value;

/// An account as /etc/passwd lists it: its name, uid, login group and home.
struct Account {
    name: String,
    uid: u32,
    gid: u32,
    home: String,
}

async fn accounts(sys: &impl Sys) -> Vec<Account> {
    String::from_utf8(sys.read("/etc/passwd").await.unwrap_or_default())
        .unwrap_or_default()
        .lines()
        .filter_map(parse_passwd_line)
        .map(|rec| Account {
            name: rec.name,
            uid: rec.uid,
            gid: rec.gid,
            home: rec.home,
        })
        .collect()
}

/// Each group of /etc/group: its name, gid and members.
async fn groups(sys: &impl Sys) -> Vec<(String, u32, Vec<String>)> {
    String::from_utf8(sys.read("/etc/group").await.unwrap_or_default())
        .unwrap_or_default()
        .lines()
        .filter_map(parse_group_line)
        .map(|rec| (rec.name, rec.gid, rec.members))
        .collect()
}

/// Who `user` names, or the process: its uid and name, login group, and every group it is in
/// (as their ids, in order).
async fn who(
    sys: &impl Sys,
    io: &mut Io<'_>,
    program: &str,
    user: &Option<String>,
) -> Option<(u32, String, u32, Vec<u32>)> {
    let creds: Creds = match call(sys, Call::Getcreds).await {
        Ok(creds) => creds,
        Err(error) => {
            io.fail(format!("{program}: {error}"));
            return None;
        }
    };
    let Some(name) = user else {
        let mut ids = creds.groups.clone();
        ids.sort_unstable();
        return Some((creds.uid, creds.user, creds.gid, ids));
    };
    let Some(account) = accounts(sys).await.into_iter().find(|a| &a.name == name) else {
        io.fail(format!("{program}: '{name}': no such user"));
        return None;
    };
    let mut ids: Vec<u32> = groups(sys)
        .await
        .into_iter()
        .filter(|(_, _, members)| members.contains(name))
        .map(|(_, gid, _)| gid)
        .chain([account.gid])
        .collect();
    ids.sort_unstable();
    ids.dedup();
    Some((account.uid, account.name, account.gid, ids))
}

pub async fn whoami(sys: &impl Sys, io: &mut Io<'_>) -> i32 {
    let _ = parsed!(io, args::Whoami);
    match call::<Creds>(sys, Call::Getcreds).await {
        Ok(creds) => {
            io.say(creds.user);
            0
        }
        Err(error) => {
            io.fail(format!("whoami: {error}"));
            1
        }
    }
}

pub async fn id(sys: &impl Sys, io: &mut Io<'_>) -> i32 {
    let id = parsed!(io, args::Id);
    if (id.names || id.real) && !(id.user_only || id.group_only || id.groups_only) {
        io.fail("id: cannot print only names or real IDs in default format");
        return 1;
    }
    let Some((uid, name, gid, ids)) = who(sys, io, "id", &id.user).await else {
        return 1;
    };
    let table = groups(sys).await;
    let named = |gid: u32| {
        table
            .iter()
            .find(|(_, id, _)| *id == gid)
            .map_or_else(|| gid.to_string(), |(name, _, _)| name.clone())
    };
    if id.user_only {
        io.say(if id.names { name } else { uid.to_string() });
        return 0;
    }
    if id.group_only {
        io.say(if id.names {
            named(gid)
        } else {
            gid.to_string()
        });
        return 0;
    }
    if id.groups_only {
        io.say(
            ids.iter()
                .map(|gid| {
                    if id.names {
                        named(*gid)
                    } else {
                        gid.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(" "),
        );
        return 0;
    }
    let list: Vec<String> = ids.iter().map(|g| format!("{g}({})", named(*g))).collect();
    io.say(format!(
        "uid={uid}({name}) gid={gid}({}) groups={}",
        named(gid),
        list.join(",")
    ));
    0
}

pub async fn groups_program(sys: &impl Sys, io: &mut Io<'_>) -> i32 {
    let groups_args = parsed!(io, args::Groups);
    let Some((_, _, _, ids)) = who(sys, io, "groups", &groups_args.user).await else {
        return 1;
    };
    let table = groups(sys).await;
    let names: Vec<String> = ids
        .iter()
        .map(|gid| {
            table
                .iter()
                .find(|(_, id, _)| id == gid)
                .map_or_else(|| gid.to_string(), |(name, _, _)| name.clone())
        })
        .collect();
    io.say(names.join(" "));
    0
}

pub async fn users(sys: &impl Sys, io: &mut Io<'_>) -> i32 {
    let _ = parsed!(io, args::Users);
    match call::<Creds>(sys, Call::Getcreds).await {
        Ok(creds) if creds.uid == 0 => {}
        Ok(_) => {
            io.fail("users: Only root can list accounts");
            return 1;
        }
        Err(error) => {
            io.fail(format!("users: {error}"));
            return 1;
        }
    }
    for account in accounts(sys).await {
        io.say(format!(
            "{}\tuid={}\t{}",
            account.name, account.uid, account.home
        ));
    }
    0
}

/// Ask the kernel to change accounts as `call` says, and say what it did, or why not.
async fn change(sys: &impl Sys, io: &mut Io<'_>, call_made: Call) -> i32 {
    match call::<Value>(sys, call_made).await {
        Ok(done) => {
            if let Some(message) = done["message"].as_str().filter(|m| !m.is_empty()) {
                io.say(message);
            }
            0
        }
        Err(error) => {
            io.fail(error.to_string());
            1
        }
    }
}

pub async fn useradd(sys: &impl Sys, io: &mut Io<'_>) -> i32 {
    let useradd = parsed!(io, args::Useradd);
    let made = Call::Useradd {
        name: useradd.name,
        create_home: useradd.create_home,
        home: useradd.home,
        group: useradd.group,
        groups: useradd.groups,
        password: None,
        short_password: useradd.short_password,
    };
    change(sys, io, made).await
}

pub async fn usermod(sys: &impl Sys, io: &mut Io<'_>) -> i32 {
    let usermod = parsed!(io, args::Usermod);
    let made = Call::Usermod {
        name: usermod.user,
        append: usermod.append,
        groups: usermod.groups,
        group: usermod.group,
        home: usermod.home,
        move_home: usermod.move_home,
        rename: usermod.rename,
        lock: usermod.lock,
        unlock: usermod.unlock,
    };
    change(sys, io, made).await
}

pub async fn userdel(sys: &impl Sys, io: &mut Io<'_>) -> i32 {
    let userdel = parsed!(io, args::Userdel);
    let made = Call::Userdel {
        name: userdel.user,
        remove: userdel.remove,
        password: None,
    };
    change(sys, io, made).await
}

pub async fn groupadd(sys: &impl Sys, io: &mut Io<'_>) -> i32 {
    let groupadd = parsed!(io, args::Groupadd);
    change(
        sys,
        io,
        Call::Groupadd {
            name: groupadd.group,
        },
    )
    .await
}

pub async fn groupmod(sys: &impl Sys, io: &mut Io<'_>) -> i32 {
    let groupmod = parsed!(io, args::Groupmod);
    let made = Call::Groupmod {
        name: groupmod.old,
        new_name: groupmod.new,
    };
    change(sys, io, made).await
}

pub async fn groupdel(sys: &impl Sys, io: &mut Io<'_>) -> i32 {
    let groupdel = parsed!(io, args::Groupdel);
    change(
        sys,
        io,
        Call::Groupdel {
            name: groupdel.group,
        },
    )
    .await
}

/// Parsed record from local `/etc/passwd`.
#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalPasswdRecord {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
    pub home: String,
    pub shell: String,
}

/// Parsed record from local `/etc/group`.
#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalGroupRecord {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

/// Reject colon, newline, carriage-return, and NUL characters in `/etc/{passwd,group,shadow}` fields.
#[allow(dead_code)]
pub fn valid_local_etc_field(value: &str) -> bool {
    !value
        .bytes()
        .any(|b| matches!(b, b':' | b'\n' | b'\r' | b'\0'))
}

/// Parse one non-comment line from `/etc/passwd`.
pub fn parse_passwd_line(line: &str) -> Option<LocalPasswdRecord> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let fields: Vec<&str> = trimmed.split(':').collect();
    if fields.len() != 7 || fields[0].is_empty() {
        return None;
    }
    Some(LocalPasswdRecord {
        name: fields[0].to_owned(),
        uid: fields[2].parse().ok()?,
        gid: fields[3].parse().ok()?,
        gecos: fields[4].to_owned(),
        home: fields[5].to_owned(),
        shell: fields[6].to_owned(),
    })
}

/// Format a `/etc/passwd` line after validating every field against delimiter injection.
#[allow(dead_code)]
pub fn format_passwd_line(record: &LocalPasswdRecord) -> Result<String, &'static str> {
    if record.name.is_empty()
        || !valid_local_etc_field(&record.name)
        || !valid_local_etc_field(&record.gecos)
        || !valid_local_etc_field(&record.home)
        || !valid_local_etc_field(&record.shell)
    {
        return Err("invalid /etc/passwd field");
    }
    Ok(format!(
        "{}:x:{}:{}:{}:{}:{}",
        record.name, record.uid, record.gid, record.gecos, record.home, record.shell
    ))
}

/// Parse one non-comment line from `/etc/group`.
pub fn parse_group_line(line: &str) -> Option<LocalGroupRecord> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let fields: Vec<&str> = trimmed.split(':').collect();
    if fields.len() != 4 || fields[0].is_empty() {
        return None;
    }
    let members = fields[3]
        .split(',')
        .filter(|m| !m.is_empty())
        .map(str::to_owned)
        .collect();
    Some(LocalGroupRecord {
        name: fields[0].to_owned(),
        gid: fields[2].parse().ok()?,
        members,
    })
}

/// Format a `/etc/group` line after validating every field against delimiter injection.
#[allow(dead_code)]
pub fn format_group_line(record: &LocalGroupRecord) -> Result<String, &'static str> {
    if record.name.is_empty()
        || !valid_local_etc_field(&record.name)
        || record
            .members
            .iter()
            .any(|m| m.is_empty() || !valid_local_etc_field(m) || m.contains(','))
    {
        return Err("invalid /etc/group field");
    }
    Ok(format!(
        "{}:x:{}:{}",
        record.name,
        record.gid,
        record.members.join(",")
    ))
}

#[cfg(test)]
mod local_etc_tests {
    use super::*;

    #[test]
    fn local_passwd_and_group_helpers_round_trip_and_reject_delimiters() {
        let p = parse_passwd_line("user:x:1000:1000:Local User:/home/user:/bin/sh").unwrap();
        assert_eq!(p.uid, 1000);
        assert_eq!(
            format_passwd_line(&p).unwrap(),
            "user:x:1000:1000:Local User:/home/user:/bin/sh"
        );
        let bad_p = LocalPasswdRecord {
            gecos: "evil:0:0".into(),
            ..p
        };
        assert!(format_passwd_line(&bad_p).is_err());

        let g = parse_group_line("wheel:x:10:user,alice").unwrap();
        assert_eq!(g.members, vec!["user", "alice"]);
        assert_eq!(format_group_line(&g).unwrap(), "wheel:x:10:user,alice");
        let bad_g = LocalGroupRecord {
            members: vec!["bad,name".into()],
            ..g
        };
        assert!(format_group_line(&bad_g).is_err());
    }
}

//! Programs on accounts: whoami, id, groups and users, of /etc/passwd and /etc/group, as libc
//! reads them; and useradd, usermod, userdel, groupadd, groupmod and groupdel, which ask the
//! kernel (their policy is its, as setuid programs' is on Linux). A signed-out useradd NAME,
//! and an account's userdel of itself, take a password, in the terminal's dialog (web/app.js).
use crate::files::parsed;
use crate::io::Io;
use crate::sys::{Sys, call};
use abi::{Call, Creds};
use serde_json::Value;
use terminal_worker_core::cli::{accounts as args, parse};

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
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            Some(Account {
                name: fields.first()?.to_string(),
                uid: fields.get(2)?.parse().ok()?,
                gid: fields.get(3)?.parse().ok()?,
                home: fields.get(5)?.to_string(),
            })
        })
        .collect()
}

/// Each group of /etc/group: its name, gid and members.
async fn groups(sys: &impl Sys) -> Vec<(String, u32, Vec<String>)> {
    String::from_utf8(sys.read("/etc/group").await.unwrap_or_default())
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            let members = fields
                .get(3)
                .map(|list| {
                    list.split(',')
                        .filter(|m| !m.is_empty())
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            Some((
                fields.first()?.to_string(),
                fields.get(2)?.parse().ok()?,
                members,
            ))
        })
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

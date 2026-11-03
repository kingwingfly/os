//! The account system calls (owner's design, 2026-10-29): useradd, usermod, userdel, groupadd,
//! groupmod and groupdel, root's, as setuid programs' policy is the kernel's here; user space
//! parses their options (crates/userland). A signed-out useradd NAME, and an account of group
//! guest's userdel of itself, are the kernel's too (api.rs register, unregister), which the
//! terminal's dialog asks for.

use crate::db::Db;
use terminal_worker_core::cli::accounts as args;
use terminal_worker_core::parent;
use terminal_worker_core::permissions::Id as Next;
use terminal_worker_core::permissions::*;

use super::{absolute_home, group, groups, named_group, protect_home};

/// The groups that cannot be renamed or deleted.
const SYSTEM_GROUPS: [&str; 3] = ["root", "wheel", "guest"];

/// Refuse anyone but root.
fn root(who: &Identity) -> Result<(), String> {
    if who.id != 0 {
        return Err("Root permission required; use sudo".into());
    }
    Ok(())
}

/// The useradd system call, as useradd's options say.
pub fn useradd(db: &mut Db, who: &Identity, useradd: args::Useradd) -> Result<String, String> {
    if who.id == GUEST {
        return Err(
            "useradd: signed out, useradd NAME makes an account of your own; options need root"
                .into(),
        );
    }
    root(who)?;
    let name = useradd.name.as_str();
    if !valid_name(name) || db.user(name).is_some() {
        return Err(
            "Username is invalid or already exists (start with a lowercase letter; up to 32 lowercase letters, digits, underscores, or hyphens)".into(),
        );
    }
    let home = absolute_home(useradd.home.as_deref().unwrap_or(&format!("/home/{name}")))?;
    protect_home(db, &home, u32::MAX)?;
    let extra = groups(db, useradd.groups.as_deref().unwrap_or(""))?;
    let gid = match &useradd.group {
        Some(g) => group(db, g)?,
        None => {
            if db.group(name).is_some() {
                return Err("Group already exists; use -g to choose the primary group".into());
            }
            let gid = db.next_id(Next::Group);
            db.set_group(name, gid);
            gid
        }
    };
    let uid = db.next_id(Next::User);
    if useradd.create_home {
        if db.node(&home).is_some() {
            return Err("Home already exists; existing content cannot be taken over".into());
        }
        db.mkdir(&Identity::root(), parent(&home), true)?;
        db.set_node(&home, &Node::directory(uid, gid, 0o700));
    }
    db.set_user(
        name,
        &User {
            id: uid,
            group: gid,
            groups: extra,
            home,
            locked: true,
            salt: String::new(),
            hash: String::new(),
        },
    );
    Ok(format!(
        "Created user {name}; use passwd {name} to set a password before signing in"
    ))
}

/// The usermod system call, as usermod's options say.
pub fn usermod(db: &mut Db, who: &Identity, usermod: args::Usermod) -> Result<String, String> {
    root(who)?;
    let name = usermod.user.as_str();
    if name == "guest" {
        return Err("The guest account cannot be changed".into());
    }
    let mut user = db.user(name).ok_or("User does not exist")?;
    if user.id == 0 {
        return Err("The root identity is fixed; use passwd root to change its password".into());
    }
    let changes = usermod.groups.is_some()
        || usermod.group.is_some()
        || usermod.home.is_some()
        || usermod.rename.is_some()
        || usermod.lock
        || usermod.unlock;
    if !changes {
        return Err("usermod requires an update option; use passwd to change a password".into());
    }
    if let Some(g) = &usermod.group {
        user.group = group(db, g)?;
    }
    if let Some(g) = &usermod.groups {
        let new = groups(db, g)?;
        if usermod.append {
            user.groups.extend(new);
        } else {
            user.groups = new;
        }
    }
    if let Some(home) = &usermod.home {
        let home = absolute_home(home)?;
        protect_home(db, &home, user.id)?;
        if usermod.move_home {
            db.move_home(&user.home, &home)?;
        }
        user.home = home;
    }
    if usermod.lock {
        user.locked = true;
    }
    if usermod.unlock {
        if user.hash.is_empty() {
            return Err("Set a password with passwd first".into());
        }
        user.locked = false;
    }
    let new = usermod.rename.as_deref().unwrap_or(name);
    if new != name && (!valid_name(new) || db.user(new).is_some()) {
        return Err("New username is invalid or already exists".into());
    }
    if user.locked {
        db.delete_sessions(user.id);
    }
    db.delete_user(name);
    db.set_user(new, &user);
    Ok(format!("Updated user {new}"))
}

/// The userdel system call, as userdel's options say.
pub fn userdel(db: &mut Db, who: &Identity, userdel: args::Userdel) -> Result<String, String> {
    root(who)?;
    let kept = delete_account(db, &userdel.user, userdel.remove)?;
    Ok(match kept {
        Some(why) => format!("Deleted user {}; {why}", userdel.user),
        None => format!("Deleted user {}", userdel.user),
    })
}

/// Delete the account `name`, and with `remove` its home, if it is a directory of its own, as
/// userdel -r does; its group of the same name goes too, unless another account is in it, as
/// userdel does (USERGROUPS_ENAB). Its sessions end, its devices end (their followers hear so),
/// and where it showed decks is forgotten, as a new account may take its uid. Its files keep its
/// uid. root and guest are never deleted. Says why a home was kept, if it was.
pub fn delete_account(
    db: &mut crate::db::Db,
    name: &str,
    remove: bool,
) -> Result<Option<String>, String> {
    let user = db.user(name).ok_or("User does not exist")?;
    if user.id == 0 || user.id == GUEST {
        return Err(format!("Cannot delete {name}"));
    }
    let mut kept = None;
    if remove && let Some(home) = db.node(&user.home) {
        if home.directory && home.owner == user.id {
            protect_home(db, &user.home, user.id)?;
            db.remove(&Identity::root(), &user.home, true)?;
        } else {
            kept = Some(format!("{} is not {name}'s, not removed", user.home));
        }
    }
    db.delete_user(name);
    if let Some(gid) = db.group(name).filter(|gid| *gid == user.group)
        && !SYSTEM_GROUPS.contains(&name)
        && !db
            .users()
            .iter()
            .any(|(_, other)| other.group == gid || other.groups.contains(&gid))
    {
        db.delete_group(name);
    }
    db.delete_sessions(user.id);
    for device in db.devices_of(user.id) {
        crate::dev::hangup(db, &device, true);
    }
    db.delete_places(user.id);
    Ok(kept)
}

/// The groupadd system call, as groupadd's options say.
pub fn groupadd(db: &mut Db, who: &Identity, groupadd: args::Groupadd) -> Result<String, String> {
    root(who)?;
    let name = groupadd.group.as_str();
    if !valid_name(name) || db.group(name).is_some() {
        return Err("Group name is invalid or already exists".into());
    }
    let gid = db.next_id(Next::Group);
    db.set_group(name, gid);
    Ok(format!("Created group {name}"))
}

/// The groupmod system call, as groupmod's options say.
pub fn groupmod(db: &mut Db, who: &Identity, groupmod: args::Groupmod) -> Result<String, String> {
    root(who)?;
    let (name, new) = (groupmod.old.as_str(), groupmod.new.as_str());
    if SYSTEM_GROUPS.contains(&name) {
        return Err("Cannot rename a system group".into());
    }
    let gid = named_group(db, name)?;
    if !valid_name(new) || db.group(new).is_some() {
        return Err("Group name is invalid or already exists".into());
    }
    db.delete_group(name);
    db.set_group(new, gid);
    Ok(format!("Group {name} renamed to {new}"))
}

/// The groupdel system call, as groupdel's options say.
pub fn groupdel(db: &mut Db, who: &Identity, groupdel: args::Groupdel) -> Result<String, String> {
    root(who)?;
    let name = groupdel.group.as_str();
    if SYSTEM_GROUPS.contains(&name) {
        return Err("Cannot delete a system group".into());
    }
    let gid = named_group(db, name)?;
    if db.users().iter().any(|(_, u)| u.group == gid) {
        return Err("This group is still an account's primary group".into());
    }
    db.delete_group(name);
    for (n, mut u) in db.users() {
        if u.groups.remove(&gid) {
            db.set_user(&n, &u);
        }
    }
    Ok(format!("Deleted group {name}"))
}

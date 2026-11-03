//! Programs on permissions: chmod, chown, chgrp, getfacl, setfacl, getfattr and setfattr. ACLs
//! are extended attributes, as on Linux (`system.posix_acl_*`): these read them, change them
//! as setfacl does, and write them back; the kernel says whether they may.
use crate::files::parsed;
use crate::io::{Io, joined, quote};
use crate::names::Names;
use crate::sys::{Sys, calls, lstat, stat};
use crate::walk;
use abi::{ACL_ACCESS, ACL_DEFAULT, Call, Errno, Error, Stat};
use serde_json::Value;
use terminal_worker_core::acl::{self, Entries, Spec};
use terminal_worker_core::cli::{parse, permissions as args};
use terminal_worker_core::permissions::change_mode;
use terminal_worker_core::xattr;

/// What a program acts on: a name as it shows it, its absolute path, and its stat.
struct Target {
    shown: String,
    abs: String,
    stat: Stat,
}

/// `typed`, and with `recursive` each node below it, links left out unless `links`: what a
/// program acts on. The operand is followed if `follow`. Directories below that cannot be
/// read are reported by the program `program`.
async fn targets(
    sys: &impl Sys,
    io: &mut Io<'_>,
    program: &str,
    typed: &str,
    follow: bool,
    recursive: bool,
    links: bool,
) -> Result<Vec<Target>, Error> {
    let abs = io.path(typed);
    let node = if follow {
        stat(sys, &abs).await?
    } else {
        lstat(sys, &abs).await?
    };
    let directory = node.is_dir();
    let mut out = vec![Target {
        shown: typed.to_string(),
        abs: abs.clone(),
        stat: node,
    }];
    if recursive && directory {
        let tree = walk::below(sys, &abs, None, io.cancelled).await;
        for (rel, _, error) in tree.unread {
            io.fail(format!(
                "{program}: cannot read directory {}: {error}",
                quote(&joined(typed, &rel))
            ));
        }
        out.extend(tree.found.into_iter().filter_map(|found| {
            let stat = found.stat?;
            (links || !stat.is_link()).then(|| Target {
                shown: joined(typed, &found.rel),
                abs: found.abs,
                stat,
            })
        }));
    }
    Ok(out)
}

pub async fn chmod(sys: &impl Sys, io: &mut Io<'_>) -> i32 {
    let chmod = parsed!(io, args::Chmod);
    let mut status = 0;
    for typed in &chmod.paths {
        let found = match targets(sys, io, "chmod", typed, true, chmod.recursive, false).await {
            Ok(found) => found,
            Err(error) => {
                io.fail(format!("chmod: cannot access {}: {error}", quote(typed)));
                status = 1;
                continue;
            }
        };
        let mut changes = Vec::new();
        for target in found {
            match change_mode(target.stat.perm(), &chmod.mode, target.stat.is_dir()) {
                Ok(mode) => changes.push((target, mode)),
                Err(_) => {
                    io.fail(format!("chmod: invalid mode: {}", quote(&chmod.mode)));
                    return 1;
                }
            }
        }
        let done = calls::<Value>(
            sys,
            changes
                .iter()
                .map(|(target, mode)| Call::Chmod {
                    path: target.abs.clone(),
                    mode: *mode,
                })
                .collect(),
        )
        .await;
        for ((target, _), result) in changes.iter().zip(done) {
            if let Err(error) = result {
                io.fail(format!(
                    "chmod: changing permissions of {}: {error}",
                    quote(&target.shown)
                ));
                status = 1;
            }
        }
    }
    status
}

/// chown OWNER[:GROUP], and chgrp GROUP (`group_only`).
pub async fn chown(sys: &impl Sys, io: &mut Io<'_>, group_only: bool) -> i32 {
    let names = Names::read(sys).await;
    let program = if group_only { "chgrp" } else { "chown" };
    let (spec, paths, recursive, no_dereference) = if group_only {
        let chgrp = parsed!(io, args::Chgrp);
        (
            format!(":{}", chgrp.group),
            chgrp.paths,
            chgrp.recursive,
            chgrp.no_dereference,
        )
    } else {
        let chown = parsed!(io, args::Chown);
        (
            chown.owner,
            chown.paths,
            chown.recursive,
            chown.no_dereference,
        )
    };
    let (user, group) = match spec.split_once(':') {
        Some((user, group)) => (user, Some(group)),
        None => (spec.as_str(), None),
    };
    let uid = match user {
        "" => None,
        user => match names.uid(user) {
            Some(uid) => Some(uid),
            None => {
                io.fail(format!("{program}: invalid user: {}", quote(&spec)));
                return 1;
            }
        },
    };
    // USER: also gives USER's login group.
    let gid = match group {
        Some("") => uid.and_then(|uid| names.login_group(uid)),
        Some(group) => match names.gid(group) {
            Some(gid) => Some(gid),
            None => {
                io.fail(format!("{program}: invalid group: {}", quote(group)));
                return 1;
            }
        },
        None => None,
    };
    let mut status = 0;
    for typed in &paths {
        let found = match targets(sys, io, program, typed, !no_dereference, recursive, true).await {
            Ok(found) => found,
            Err(error) => {
                io.fail(format!(
                    "{program}: cannot access {}: {error}",
                    quote(typed)
                ));
                status = 1;
                continue;
            }
        };
        // What -R finds is changed as itself; the operand as -h says.
        let done = calls::<Value>(
            sys,
            found
                .iter()
                .enumerate()
                .map(|(index, target)| Call::Chown {
                    path: target.abs.clone(),
                    uid,
                    gid,
                    nofollow: no_dereference || index > 0,
                })
                .collect(),
        )
        .await;
        for (target, result) in found.iter().zip(done) {
            if let Err(error) = result {
                let what = if group_only { "group" } else { "ownership" };
                io.fail(format!(
                    "{program}: changing {what} of {}: {error}",
                    quote(&target.shown)
                ));
                status = 1;
            }
        }
    }
    status
}

/// A node's ACLs, as its extended attributes say: its access ACL, its mode's if it has none
/// beyond it; and a directory's default ACL, if it has one.
async fn acls(sys: &impl Sys, found: &[Target]) -> Vec<(Entries, Option<Entries>)> {
    let read = calls::<abi::Bytes>(
        sys,
        found
            .iter()
            .flat_map(|target| {
                [
                    Call::Getxattr {
                        path: target.abs.clone(),
                        name: ACL_ACCESS.into(),
                        nofollow: false,
                    },
                    Call::Getxattr {
                        path: target.abs.clone(),
                        name: ACL_DEFAULT.into(),
                        nofollow: false,
                    },
                ]
            })
            .collect(),
    )
    .await;
    let mut read = read.into_iter();
    found
        .iter()
        .map(|target| {
            let parse = |value: Option<Result<abi::Bytes, Error>>| {
                value
                    .and_then(Result::ok)
                    .and_then(|bytes| serde_json::from_slice::<Entries>(&bytes).ok())
            };
            let access =
                parse(read.next()).unwrap_or_else(|| Entries::access(target.stat.perm(), None));
            (access, parse(read.next()))
        })
        .collect()
}

pub async fn getfacl(sys: &impl Sys, io: &mut Io<'_>) -> i32 {
    let getfacl = parsed!(io, args::Getfacl);
    let names = Names::read(sys).await;
    let user = |id: u32| {
        if getfacl.numeric {
            id.to_string()
        } else {
            names.user(id)
        }
    };
    let group = |id: u32| {
        if getfacl.numeric {
            id.to_string()
        } else {
            names.group(id)
        }
    };
    let mut status = 0;
    let mut blocks = Vec::new();
    for typed in &getfacl.files {
        let found = match targets(
            sys,
            io,
            "getfacl",
            typed,
            !getfacl.physical,
            getfacl.recursive,
            false,
        )
        .await
        {
            Ok(found) => found,
            Err(error) => {
                io.fail(format!("getfacl: {typed}: {error}"));
                status = 1;
                continue;
            }
        };
        for (target, (access, default)) in found.iter().zip(acls(sys, &found).await) {
            let mut lines = Vec::new();
            if !getfacl.omit_header {
                let shown = crate::files::shown_path(&target.abs);
                let shown = if getfacl.absolute {
                    shown
                } else {
                    shown.trim_start_matches('/').to_string()
                };
                lines.push(format!(
                    "# file: {}",
                    if shown.is_empty() { "/" } else { &shown }
                ));
                lines.push(format!("# owner: {}", user(target.stat.uid)));
                lines.push(format!("# group: {}", group(target.stat.gid)));
                let special = target.stat.perm() & 0o7000;
                if special != 0 {
                    let flag = |bit: u16, c| if special & bit != 0 { c } else { '-' };
                    lines.push(format!(
                        "# flags: {}{}{}",
                        flag(0o4000, 's'),
                        flag(0o2000, 's'),
                        flag(0o1000, 't')
                    ));
                }
            }
            if !getfacl.default {
                lines.extend(acl::lines(&access, false, &user, &group));
            }
            if let (false, Some(default)) = (getfacl.access, &default) {
                lines.extend(acl::lines(default, true, &user, &group));
            }
            blocks.push(lines.join("\n") + "\n");
        }
    }
    io.out = blocks.join("\n");
    status
}

/// The entries of `specs` for the default ACL, if `default`, or for the access ACL.
fn sided(specs: &[Spec], default: bool) -> Vec<&Spec> {
    specs.iter().filter(|s| s.default == default).collect()
}

pub async fn setfacl(sys: &impl Sys, io: &mut Io<'_>) -> i32 {
    let setfacl = parsed!(io, args::Setfacl);
    if setfacl.modify_file.is_some() || setfacl.remove_file.is_some() {
        io.fail("setfacl: -M and -X read files of entries, which this terminal does not; give them with -m and -x");
        return 1;
    }
    let names = Names::read(sys).await;
    let parse_specs = |text: &Option<String>, perms| -> Result<Vec<Spec>, String> {
        let Some(text) = text else {
            return Ok(Vec::new());
        };
        let user = |name: &str| names.uid(name);
        let group = |name: &str| names.gid(name);
        let mut specs =
            acl::parse_specs(text, perms, &user, &group).map_err(|e| format!("setfacl: {e}"))?;
        // -d makes every entry a default one.
        if setfacl.default {
            for spec in &mut specs {
                spec.default = true;
            }
        }
        Ok(specs)
    };
    let parsed = (|| {
        Ok::<_, String>((
            parse_specs(&setfacl.modify, true)?,
            parse_specs(&setfacl.remove, false)?,
            parse_specs(&setfacl.set, true)?,
        ))
    })();
    let (modify, remove, set) = match parsed {
        Ok(specs) => specs,
        Err(error) => {
            io.fail(error);
            return 1;
        }
    };
    let touches = |default| {
        !sided(&set, default).is_empty()
            || !sided(&modify, default).is_empty()
            || !sided(&remove, default).is_empty()
    };
    let defaults = touches(true);
    let mut status = 0;
    for typed in &setfacl.files {
        let found = match targets(sys, io, "setfacl", typed, true, setfacl.recursive, false).await {
            Ok(found) => found,
            Err(error) => {
                io.fail(format!("setfacl: {typed}: {error}"));
                status = 1;
                continue;
            }
        };
        let current = acls(sys, &found).await;
        let mut writes = Vec::new();
        let mut shown = Vec::new();
        for (index, (target, (mut access, default))) in found.iter().zip(current).enumerate() {
            let directory = target.stat.is_dir();
            let executable = directory || target.stat.perm() & 0o111 != 0;
            // A default ACL is a directory's; -R passes over files for one.
            if defaults && !directory {
                if setfacl.recursive && index > 0 {
                    continue;
                }
                io.fail(format!(
                    "setfacl: {}: Only directories can have default ACLs",
                    target.shown
                ));
                status = 1;
                continue;
            }
            let mut default = default;
            if setfacl.remove_all {
                access.users.clear();
                access.groups.clear();
                access.mask = None;
                default = None;
            }
            if setfacl.remove_default {
                default = None;
            }
            // A default ACL begins as the access ACL's base entries.
            let had_default = default.is_some();
            let mut new_default = default.clone().unwrap_or_else(|| Entries {
                user: access.user,
                group: access.group,
                other: access.other,
                ..Entries::default()
            });
            let mut failed = None;
            for (entries, side) in [(&mut access, false), (&mut new_default, true)] {
                let replacing = sided(&set, side);
                if !replacing.is_empty() {
                    match acl::set(&replacing, executable) {
                        Ok(made) => *entries = made,
                        Err(error) => failed = Some(error),
                    }
                }
                acl::modify(entries, &sided(&modify, side), executable, setfacl.no_mask);
                let removing = sided(&remove, side);
                if !removing.is_empty()
                    && let Err(error) = acl::remove(entries, &removing, setfacl.no_mask)
                {
                    failed = Some(error);
                }
            }
            if let Some(error) = failed {
                io.fail(format!("setfacl: {}: {error}", target.shown));
                status = 1;
                continue;
            }
            let bytes = |entries: &Entries| serde_json::to_vec(entries).unwrap_or_default();
            writes.push(Call::Setxattr {
                path: target.abs.clone(),
                name: ACL_ACCESS.into(),
                value: bytes(&access).into(),
                flags: 0,
                nofollow: false,
            });
            shown.push(target.shown.clone());
            if directory && (had_default || defaults) && !setfacl.remove_default {
                writes.push(Call::Setxattr {
                    path: target.abs.clone(),
                    name: ACL_DEFAULT.into(),
                    value: bytes(&new_default).into(),
                    flags: 0,
                    nofollow: false,
                });
                shown.push(target.shown.clone());
            } else if had_default && (setfacl.remove_default || setfacl.remove_all) {
                writes.push(Call::Removexattr {
                    path: target.abs.clone(),
                    name: ACL_DEFAULT.into(),
                    nofollow: false,
                });
                shown.push(target.shown.clone());
            }
        }
        let mut reported = std::collections::BTreeSet::new();
        for (shown, result) in shown.iter().zip(calls::<Value>(sys, writes).await) {
            if let Err(error) = result
                && reported.insert(shown.clone())
            {
                io.fail(format!("setfacl: {shown}: {error}"));
                status = 1;
            }
        }
    }
    status
}

pub async fn getfattr(sys: &impl Sys, io: &mut Io<'_>) -> i32 {
    let getfattr = parsed!(io, args::Getfattr);
    // -m - and -m . match everything; the default, user. only.
    let matcher = match getfattr.pattern.as_deref().unwrap_or("^user\\.") {
        "-" | "." | "" => None,
        pattern => match regex::Regex::new(pattern) {
            Ok(matcher) => Some(matcher),
            Err(error) => {
                io.fail(format!("getfattr: bad pattern: {error}"));
                return 1;
            }
        },
    };
    let encoding = getfattr.encoding.clone().unwrap_or_else(|| "text".into());
    let mut status = 0;
    let mut blocks = Vec::new();
    for typed in &getfattr.files {
        let found = match targets(
            sys,
            io,
            "getfattr",
            typed,
            !getfattr.no_dereference,
            getfattr.recursive,
            true,
        )
        .await
        {
            Ok(found) => found,
            Err(error) => {
                io.fail(format!("getfattr: {typed}: {error}"));
                status = 1;
                continue;
            }
        };
        for target in found {
            let nofollow = getfattr.no_dereference || target.abs != io.path(typed);
            let names: Vec<String> = match &getfattr.name {
                Some(name) => vec![name.clone()],
                None => match crate::sys::call(
                    sys,
                    Call::Listxattr {
                        path: target.abs.clone(),
                        nofollow,
                    },
                )
                .await
                {
                    Ok(names) => names,
                    Err(error) => {
                        io.fail(format!("getfattr: {}: {error}", target.shown));
                        status = 1;
                        continue;
                    }
                },
            };
            let names: Vec<String> = names
                .into_iter()
                .filter(|name| xattr::namespace(name).is_ok())
                .filter(|name| {
                    getfattr.name.is_some() || matcher.as_ref().is_none_or(|m| m.is_match(name))
                })
                .collect();
            let values = calls::<abi::Bytes>(
                sys,
                names
                    .iter()
                    .map(|name| Call::Getxattr {
                        path: target.abs.clone(),
                        name: name.clone(),
                        nofollow,
                    })
                    .collect(),
            )
            .await;
            let mut lines = Vec::new();
            for (name, value) in names.iter().zip(values) {
                match value {
                    Ok(value) if getfattr.dump || getfattr.name.is_some() => {
                        lines.push(format!("{name}={}", xattr::encode(&value, &encoding)))
                    }
                    Ok(_) => lines.push(name.clone()),
                    Err(error) if error.errno == Errno::ENODATA => {
                        io.fail(format!("{}: {name}: No such attribute", target.shown));
                        status = 1;
                    }
                    Err(error) => {
                        io.fail(format!("getfattr: {}: {error}", target.shown));
                        status = 1;
                    }
                }
            }
            if lines.is_empty() {
                continue;
            }
            let shown = crate::files::shown_path(&target.abs);
            let file = if getfattr.absolute {
                shown
            } else {
                shown.trim_start_matches('/').to_string()
            };
            blocks.push(format!("# file: {file}\n{}\n", lines.join("\n")));
        }
    }
    io.out = blocks.join("\n");
    status
}

pub async fn setfattr(sys: &impl Sys, io: &mut Io<'_>) -> i32 {
    let setfattr = parsed!(io, args::Setfattr);
    let (name, value) = match (&setfattr.name, &setfattr.remove) {
        (Some(name), _) => match xattr::decode(setfattr.value.as_deref().unwrap_or("")) {
            Ok(value) => (name.clone(), Some(value)),
            Err(error) => {
                io.fail(format!("setfattr: {error}"));
                return 1;
            }
        },
        (None, Some(name)) => (name.clone(), None),
        (None, None) => {
            io.fail("setfattr: -n or -x is required");
            return 1;
        }
    };
    let calls_made: Vec<Call> = setfattr
        .files
        .iter()
        .map(|typed| {
            let path = io.path(typed);
            match &value {
                Some(value) => Call::Setxattr {
                    path,
                    name: name.clone(),
                    value: value.clone().into(),
                    flags: 0,
                    nofollow: setfattr.no_dereference,
                },
                None => Call::Removexattr {
                    path,
                    name: name.clone(),
                    nofollow: setfattr.no_dereference,
                },
            }
        })
        .collect();
    let mut status = 0;
    for (typed, result) in setfattr
        .files
        .iter()
        .zip(calls::<Value>(sys, calls_made).await)
    {
        if let Err(error) = result {
            let why = match error.errno {
                Errno::ENODATA => "No such attribute".to_string(),
                _ => error.to_string(),
            };
            io.fail(format!("setfattr: {typed}: {why}"));
            status = 1;
        }
    }
    status
}

//! Path resolution, as Linux's path_lookupat does it: part by part from the root, each
//! directory searched (x) before a name is looked up in it, `..` physical (the directory a
//! link led to has its own), links on the way followed, and the last one too if asked.
use crate::{Fs, permission};
use abi::{Errno, Error, MAXSYMLINKS, NAME_MAX, PATH_MAX};
use std::collections::VecDeque;
use terminal_worker_core::permissions::*;

/// What a path names: the physical path of its last part, every link on the way followed, and
/// the last one too if asked; and the node there, if there is one.
#[derive(Clone, Debug)]
pub struct Name {
    pub path: String,
    pub node: Option<Node>,
}

fn join(parts: &[String]) -> String {
    if parts.is_empty() {
        "/".into()
    } else {
        format!("/{}", parts.join("/"))
    }
}

/// Resolve the absolute `path` for `cred`. Each directory on the way must be there (ENOENT),
/// be one (ENOTDIR), and be searchable (EACCES); more than `MAXSYMLINKS` links fail with
/// ELOOP. A link followed in a sticky directory others may write must be the follower's, or
/// the directory owner's (protected_symlinks). A path ending in `/` names a directory, through
/// a link too.
pub fn namei(fs: &impl Fs, cred: &Identity, path: &str, follow: bool) -> Result<Name, Error> {
    if path.is_empty() {
        return Err(Errno::ENOENT.into());
    }
    if path.len() > PATH_MAX {
        return Err(Errno::ENAMETOOLONG.into());
    }
    if !path.starts_with('/') {
        return Err(Error::because(Errno::EINVAL, "a path must be absolute"));
    }
    let directory = path.len() > 1 && path.ends_with('/');
    let follow = follow || directory;
    let mut todo: VecDeque<String> = path
        .split('/')
        .filter(|part| !part.is_empty())
        .map(String::from)
        .collect();
    let mut at: Vec<String> = Vec::new();
    let mut links = 0;
    let mut found = fs.node("/");
    while let Some(part) = todo.pop_front() {
        if part.len() > NAME_MAX {
            return Err(Errno::ENAMETOOLONG.into());
        }
        let dir = fs.node(&join(&at)).ok_or(Errno::ENOENT)?;
        if !dir.directory {
            return Err(Errno::ENOTDIR.into());
        }
        if !permission(cred, &dir, EXEC) {
            return Err(Errno::EACCES.into());
        }
        match part.as_str() {
            "." => {
                found = Some(dir);
                continue;
            }
            ".." => {
                at.pop();
                found = fs.node(&join(&at));
                continue;
            }
            _ => {}
        }
        at.push(part);
        let child = join(&at);
        let last = todo.is_empty();
        match fs.node(&child) {
            None if last => {
                return Ok(Name {
                    path: child,
                    node: None,
                });
            }
            None => return Err(Errno::ENOENT.into()),
            Some(link) if link.is_link() && (!last || follow) => {
                links += 1;
                if links > MAXSYMLINKS {
                    return Err(Errno::ELOOP.into());
                }
                if dir.mode & STICKY != 0
                    && dir.mode & 0o002 != 0
                    && cred.id != 0
                    && cred.id != link.owner
                    && dir.owner != link.owner
                {
                    return Err(Errno::EACCES.into());
                }
                at.pop();
                let target = link.link.unwrap_or_default();
                if target.is_empty() {
                    return Err(Errno::ENOENT.into());
                }
                if target.starts_with('/') {
                    at.clear();
                }
                for part in target.split('/').filter(|part| !part.is_empty()).rev() {
                    todo.push_front(part.to_string());
                }
                found = fs.node(&join(&at));
            }
            node => found = node,
        }
    }
    let node = found;
    if directory && node.as_ref().is_some_and(|node| !node.directory) {
        return Err(Errno::ENOTDIR.into());
    }
    Ok(Name {
        path: join(&at),
        node,
    })
}

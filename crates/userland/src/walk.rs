//! Walking a tree, as fts(3) does for rm -r, chmod -R and fd: breadth-first, a level at a time,
//! one batch of getdents a level, so that a big tree takes a few requests, not one an entry.
//! Links are not followed. A directory that cannot be read is reported, and not entered.
use crate::io::joined;
use crate::sys::{Sys, calls};
use abi::{Call, Dirent, Error, Stat};

/// An entry found below a root: its path below it (`a/b`), its absolute path, its lstat (none
/// if its directory may be read but not searched), and how deep it is (1: in the root).
#[derive(Clone, Debug)]
pub struct Found {
    pub rel: String,
    pub abs: String,
    pub stat: Option<Stat>,
    pub depth: usize,
}

/// What a walk found, and the directories it could not read: their path below the root, their
/// absolute path, and why.
#[derive(Debug, Default)]
pub struct Walk {
    pub found: Vec<Found>,
    pub unread: Vec<(String, String, Error)>,
}

/// Walk below the directory `root` (absolute): its entries, theirs, and so on, `max_depth`
/// levels at most. `cancelled` stops it between levels.
pub async fn below(
    sys: &impl Sys,
    root: &str,
    max_depth: Option<usize>,
    cancelled: &dyn Fn() -> bool,
) -> Walk {
    let mut walk = Walk::default();
    let mut level = vec![(String::new(), root.to_string())];
    let mut depth = 1;
    while !level.is_empty() && max_depth.is_none_or(|max| depth <= max) && !cancelled() {
        let listed = calls::<Vec<Dirent>>(
            sys,
            level
                .iter()
                .map(|(_, abs)| Call::Getdents {
                    path: abs.clone(),
                    cookie: 0,
                    count: None,
                })
                .collect(),
        )
        .await;
        let mut next = Vec::new();
        for ((rel, abs), result) in level.into_iter().zip(listed) {
            let entries = match result {
                Ok(entries) => entries,
                Err(error) => {
                    walk.unread.push((rel, abs, error));
                    continue;
                }
            };
            for entry in entries {
                let found = Found {
                    rel: if rel.is_empty() {
                        entry.name.clone()
                    } else {
                        format!("{rel}/{}", entry.name)
                    },
                    abs: joined(&abs, &entry.name),
                    stat: entry.stat,
                    depth,
                };
                if found.stat.as_ref().is_some_and(Stat::is_dir) {
                    next.push((found.rel.clone(), found.abs.clone()));
                }
                walk.found.push(found);
            }
        }
        level = next;
        depth += 1;
    }
    walk
}

//! cp, as GNU's, over the system calls. Content is shared, not copied: each file is cloned
//! (ioctl FICLONE, as cp --reflink=always does), so a copy of any size takes a few calls. A tree
//! goes a level at a time, each level's calls in a few batches. Whether anything may be read or
//! made is the kernel's to say, call by call.
use crate::files::{Existing, canonical, parsed, yes};
use crate::io::{Io, basename, joined, quote};
use crate::sys::{Sys, calls, lstat, stat};
use crate::walk;
use abi::{
    ACL_ACCESS, ACL_DEFAULT, Call, Errno, Error, FICLONE, FdRef, INLINE_MAX, O_CREAT, O_EXCL,
    O_RDONLY, O_TRUNC, O_WRONLY, Opened, Stat,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use terminal_worker_core::cli::{files as args, parse};

/// What cp's options ask of each copy.
struct Options {
    recursive: bool,
    /// Links below copied as links, and a file's names kept together (-d, -a).
    links: bool,
    /// Mode, ACLs, owner and group (-p, -a); and other extended attributes (-a).
    preserve: bool,
    xattrs: bool,
    /// Links below followed (-L).
    follow_below: bool,
    interactive: bool,
    no_clobber: bool,
    force: bool,
    verbose: bool,
}

/// Something to copy, as absolute paths and as shown, and how deep below the operand it is.
#[derive(Clone)]
struct Item {
    from: String,
    shown_from: String,
    stat: Stat,
    to: String,
    shown_to: String,
    depth: usize,
}

/// What is done with an item, once what is at its destination is known.
enum Step {
    Skip,
    Mkdir,
    /// Into a directory that is there.
    Merge,
    Symlink {
        replace: bool,
    },
    /// Another name for the copy of a file met before (-d, -a).
    Link {
        first: String,
        replace: bool,
    },
    File {
        replace: bool,
    },
}

struct Copier {
    options: Options,
    /// The copy made of each file with several names, by its inode (-d, -a).
    seen: BTreeMap<u64, (String, String)>,
    /// Directories made, or merged into, to finish once what they hold is copied: their mode
    /// may forbid writing in them.
    dirs: Vec<(Item, bool)>,
    /// Directories that could not be made: nothing goes below them.
    failed: BTreeSet<String>,
    status: i32,
}

pub async fn cp(sys: &impl Sys, io: &mut Io<'_>) -> i32 {
    let cp = parsed!(io, args::Cp);
    let options = Options {
        recursive: cp.archive || cp.recursive,
        links: cp.archive || cp.links,
        preserve: cp.archive || cp.preserve,
        xattrs: cp.archive,
        follow_below: cp.dereference,
        interactive: cp.interactive,
        no_clobber: cp.no_clobber,
        force: cp.force,
        verbose: cp.verbose,
    };
    // A link named is followed without -r, and with -L or -H; otherwise copied as one (-P, also
    // in -d and -a).
    let follow_named = cp.dereference
        || cp.command_line
        || !cp.no_dereference && !options.recursive && !options.links;
    let dest = io.path(&cp.dest);
    let into = match stat(sys, &dest).await {
        Ok(found) => found.is_dir(),
        Err(error) if error.errno == Errno::ENOENT => false,
        Err(error) => {
            io.fail(format!("cp: failed to access {}: {error}", quote(&cp.dest)));
            return 1;
        }
    };
    if cp.sources.len() > 1 && !into {
        io.fail(format!("cp: target {} is not a directory", quote(&cp.dest)));
        return 1;
    }
    let mut copier = Copier {
        options,
        seen: BTreeMap::new(),
        dirs: Vec::new(),
        failed: BTreeSet::new(),
        status: 0,
    };
    for typed in &cp.sources {
        if (io.cancelled)() {
            return 130;
        }
        let from = io.path(typed);
        let found = if follow_named {
            stat(sys, &from).await
        } else {
            lstat(sys, &from).await
        };
        let found = match found {
            Ok(found) => found,
            Err(error) => {
                io.fail(format!("cp: cannot stat {}: {error}", quote(typed)));
                copier.status = 1;
                continue;
            }
        };
        let (to, shown_to) = if into {
            let name = basename(typed);
            (joined(&dest, name), joined(&cp.dest, name))
        } else {
            (dest.clone(), cp.dest.clone())
        };
        if found.is_dir() {
            if !copier.options.recursive {
                io.fail(format!(
                    "cp: -r not specified; omitting directory {}",
                    quote(typed)
                ));
                copier.status = 1;
                continue;
            }
            if let (Ok(above), Ok(below)) = (
                canonical(sys, &from, Existing::All).await,
                canonical(sys, &to, Existing::Above).await,
            ) && (below == above || below.starts_with(&format!("{above}/")))
            {
                io.fail(format!(
                    "cp: cannot copy a directory, {}, into itself, {}",
                    quote(typed),
                    quote(&shown_to)
                ));
                copier.status = 1;
                continue;
            }
        }
        let root = Item {
            from,
            shown_from: typed.clone(),
            stat: found,
            to,
            shown_to,
            depth: 0,
        };
        let Some(items) = copier.gather(sys, io, root).await else {
            copier.status = 1;
            continue;
        };
        copier.copy(sys, io, items).await;
    }
    copier.finish_dirs(sys, io).await;
    copier.status
}

/// A call's value, as `T`.
fn value<T: serde::de::DeserializeOwned>(result: Result<Value, Error>) -> Result<T, Error> {
    result.and_then(|value| {
        serde_json::from_value(value).map_err(|e| Error::because(Errno::EIO, e.to_string()))
    })
}

impl Copier {
    /// What copying `root` copies, parents before what they hold: links below followed with
    /// -L. None, said why, if a file in it is still uploading: it is copied once whole, and
    /// nothing of it before.
    async fn gather(&mut self, sys: &impl Sys, io: &mut Io<'_>, root: Item) -> Option<Vec<Item>> {
        let mut items = vec![root];
        let mut todo = if items[0].stat.is_dir() {
            vec![0]
        } else {
            vec![]
        };
        let mut walked = BTreeSet::new();
        while let Some(at) = todo.pop() {
            let top = items[at].clone();
            if !walked.insert(top.stat.ino) {
                io.fail(format!(
                    "cp: {}: directory causes a cycle",
                    quote(&top.shown_from)
                ));
                self.status = 1;
                continue;
            }
            let walk = walk::below(sys, &top.from, None, io.cancelled).await;
            for (rel, _, error) in &walk.unread {
                let shown = if rel.is_empty() {
                    top.shown_from.clone()
                } else {
                    joined(&top.shown_from, rel)
                };
                io.fail(format!(
                    "cp: cannot open directory {}: {error}",
                    quote(&shown)
                ));
                self.status = 1;
            }
            for found in walk.found {
                let shown_from = joined(&top.shown_from, &found.rel);
                let Some(mut stat_found) = found.stat else {
                    io.fail(format!(
                        "cp: cannot stat {}: {}",
                        quote(&shown_from),
                        Errno::EACCES.text()
                    ));
                    self.status = 1;
                    continue;
                };
                if stat_found.is_link() && self.options.follow_below {
                    match stat(sys, &found.abs).await {
                        Ok(followed) => stat_found = followed,
                        Err(error) => {
                            io.fail(format!("cp: cannot stat {}: {error}", quote(&shown_from)));
                            self.status = 1;
                            continue;
                        }
                    }
                    if stat_found.is_dir() {
                        todo.push(items.len());
                    }
                }
                items.push(Item {
                    to: joined(&top.to, &found.rel),
                    shown_to: joined(&top.shown_to, &found.rel),
                    from: found.abs,
                    shown_from,
                    stat: stat_found,
                    depth: top.depth + found.depth,
                });
            }
        }
        if let Some(item) = items
            .iter()
            .find(|item| item.stat.is_file() && item.stat.writing.is_some())
        {
            io.fail(format!(
                "cp: cannot copy {}: still uploading; copy it once it completes",
                quote(&item.shown_from)
            ));
            return None;
        }
        items.sort_by_key(|item| item.depth);
        Some(items)
    }

    /// Copy `items`, a level at a time.
    async fn copy(&mut self, sys: &impl Sys, io: &mut Io<'_>, items: Vec<Item>) {
        let mut start = 0;
        while start < items.len() {
            if (io.cancelled)() {
                self.status = 130;
                return;
            }
            let depth = items[start].depth;
            let end = items[start..]
                .iter()
                .position(|item| item.depth != depth)
                .map_or(items.len(), |n| start + n);
            let level: Vec<Item> = items[start..end]
                .iter()
                .filter(|item| {
                    !self
                        .failed
                        .iter()
                        .any(|dir| item.to.starts_with(&format!("{dir}/")))
                })
                .cloned()
                .collect();
            self.level(sys, io, level).await;
            start = end;
        }
    }

    /// What is done with each item of a level, given what is at its destination.
    async fn steps(&mut self, sys: &impl Sys, io: &mut Io<'_>, level: &[Item]) -> Vec<Step> {
        let there = calls::<Stat>(
            sys,
            level
                .iter()
                .map(|item| Call::Lstat {
                    path: item.to.clone(),
                })
                .collect(),
        )
        .await;
        let mut steps = Vec::with_capacity(level.len());
        for (item, there) in level.iter().zip(there) {
            let source = &item.stat;
            let existing = match there {
                Ok(existing) => Some(existing),
                Err(error) if error.errno == Errno::ENOENT => None,
                Err(error) => {
                    self.cannot_create(io, item, &error);
                    steps.push(Step::Skip);
                    continue;
                }
            };
            let first = (self.options.links && source.is_file() && source.nlink > 1)
                .then(|| self.seen.get(&source.ino).map(|(to, _)| to.clone()))
                .flatten();
            if self.options.links && source.is_file() && source.nlink > 1 && first.is_none() {
                self.seen
                    .insert(source.ino, (item.to.clone(), item.shown_to.clone()));
            }
            let Some(existing) = existing else {
                steps.push(match first {
                    Some(first) => Step::Link {
                        first,
                        replace: false,
                    },
                    None if source.is_dir() => Step::Mkdir,
                    None if source.is_link() => Step::Symlink { replace: false },
                    None => Step::File { replace: false },
                });
                continue;
            };
            let failure = if existing.ino == source.ino && !source.is_dir() {
                Some(format!(
                    "cp: {} and {} are the same file",
                    quote(&item.shown_from),
                    quote(&item.shown_to)
                ))
            } else if source.is_dir() && !existing.is_dir() {
                Some(format!(
                    "cp: cannot overwrite non-directory {} with directory {}",
                    quote(&item.shown_to),
                    quote(&item.shown_from)
                ))
            } else if !source.is_dir() && existing.is_dir() {
                Some(format!(
                    "cp: cannot overwrite directory {} with non-directory",
                    quote(&item.shown_to)
                ))
            } else {
                None
            };
            if let Some(failure) = failure {
                io.fail(failure);
                self.status = 1;
                steps.push(Step::Skip);
                continue;
            }
            if source.is_dir() {
                steps.push(Step::Merge);
                continue;
            }
            if self.options.no_clobber
                || self.options.interactive
                    && !yes(io, format!("cp: overwrite {}?", quote(&item.shown_to))).await
            {
                steps.push(Step::Skip);
                continue;
            }
            if let Some(first) = first {
                steps.push(Step::Link {
                    first,
                    replace: true,
                });
            } else if source.is_link() {
                steps.push(Step::Symlink { replace: true });
            } else {
                // A file is written through a link to one, as open(2) writes; not one leading
                // nowhere.
                if existing.is_link() && stat(sys, &item.to).await.is_err() {
                    io.fail(format!(
                        "cp: not writing through dangling symlink {}",
                        quote(&item.shown_to)
                    ));
                    self.status = 1;
                    steps.push(Step::Skip);
                    continue;
                }
                steps.push(Step::File { replace: true });
            }
        }
        steps
    }

    /// Copy `item` by reading it whole and writing it to its copy, made empty already: for what
    /// has no content to share, which is small (the kernel's making).
    async fn write_read(&self, sys: &impl Sys, item: &Item) -> Result<(), Error> {
        let bytes = sys.read(&item.from).await?;
        if bytes.len() as u64 > INLINE_MAX {
            return Err(Errno::EFBIG.into());
        }
        let first = FdRef::Ref { call: 0 };
        let mut writing = vec![Call::Open {
            path: item.to.clone(),
            flags: O_WRONLY | O_TRUNC,
            mode: 0,
            size: None,
            sha256: None,
            version: None,
        }];
        if !bytes.is_empty() {
            writing.push(Call::Pwrite {
                fd: first,
                index: 0,
                data: bytes.into(),
            });
        }
        writing.push(Call::Close { fd: first });
        for result in calls::<Value>(sys, writing).await {
            result?;
        }
        Ok(())
    }

    fn cannot_create(&mut self, io: &mut Io<'_>, item: &Item, error: &Error) {
        let what = if item.stat.is_dir() {
            "directory"
        } else if item.stat.is_link() {
            "symbolic link"
        } else {
            "regular file"
        };
        io.fail(format!(
            "cp: cannot create {what} {}: {error}",
            quote(&item.shown_to)
        ));
        if item.stat.is_dir() {
            self.failed.insert(item.to.clone());
        }
        self.status = 1;
    }

    async fn level(&mut self, sys: &impl Sys, io: &mut Io<'_>, level: Vec<Item>) {
        let steps = self.steps(sys, io, &level).await;
        // Names made, and descriptors opened: a call or two an item, in one batch.
        let mut made: Vec<Call> = Vec::new();
        let mut spans = Vec::with_capacity(level.len());
        for (item, step) in level.iter().zip(&steps) {
            let begin = made.len();
            let replace = matches!(
                step,
                Step::Symlink { replace: true } | Step::Link { replace: true, .. }
            );
            if replace {
                made.push(Call::Unlink {
                    path: item.to.clone(),
                });
            }
            match step {
                Step::Mkdir => made.push(Call::Mkdir {
                    path: item.to.clone(),
                    // Writable and searchable until what it holds is in (finish_dirs).
                    mode: item.stat.perm() & 0o777 | 0o700,
                }),
                Step::Symlink { .. } => made.push(Call::Symlink {
                    target: item.stat.link.clone().unwrap_or_default(),
                    path: item.to.clone(),
                }),
                Step::File { replace } => {
                    made.push(Call::Open {
                        path: item.from.clone(),
                        flags: O_RDONLY,
                        mode: 0,
                        size: None,
                        sha256: None,
                        version: None,
                    });
                    made.push(open_writing(item, *replace));
                }
                _ => {}
            }
            spans.push((begin, made.len()));
        }
        let results = calls::<Value>(sys, made).await;
        // What was copied, said in order once the level is done (-v).
        let mut copied = vec![false; level.len()];
        // Each file's descriptors, to clone, and those to close.
        let mut fds: Vec<Option<(u32, u32, bool)>> = vec![None; level.len()];
        let mut closing: Vec<Call> = Vec::new();
        let mut again: Vec<usize> = Vec::new();
        for (index, (item, step)) in level.iter().zip(&steps).enumerate() {
            let (begin, end) = spans[index];
            let mut results = results[begin..end].iter().cloned();
            let replace = matches!(
                step,
                Step::Symlink { replace: true } | Step::Link { replace: true, .. }
            );
            if replace && let Some(Err(error)) = results.next() {
                io.fail(format!(
                    "cp: cannot remove {}: {error}",
                    quote(&item.shown_to)
                ));
                self.status = 1;
                continue;
            }
            match step {
                Step::Mkdir => match results.next().unwrap_or(Err(Errno::EIO.into())) {
                    Ok(_) => {
                        copied[index] = true;
                        self.dirs.push((item.clone(), true));
                    }
                    Err(error) => self.cannot_create(io, item, &error),
                },
                Step::Merge => {
                    copied[index] = true;
                    self.dirs.push((item.clone(), false));
                }
                Step::Symlink { .. } => match results.next().unwrap_or(Err(Errno::EIO.into())) {
                    Ok(_) => copied[index] = true,
                    Err(error) => self.cannot_create(io, item, &error),
                },
                Step::File { replace } => {
                    let reading = value::<Opened>(results.next().unwrap_or(Err(Errno::EIO.into())));
                    let writing = value::<Opened>(results.next().unwrap_or(Err(Errno::EIO.into())));
                    match (reading, writing) {
                        (Ok(reading), Ok(writing)) => {
                            fds[index] = Some((reading.fd, writing.fd, writing.created));
                        }
                        (Err(error), writing) => {
                            io.fail(format!(
                                "cp: cannot open {} for reading: {error}",
                                quote(&item.shown_from)
                            ));
                            self.status = 1;
                            if let Ok(writing) = writing {
                                closing.push(Call::Close {
                                    fd: writing.fd.into(),
                                });
                                if writing.created {
                                    closing.push(Call::Unlink {
                                        path: item.to.clone(),
                                    });
                                }
                            }
                        }
                        (Ok(reading), Err(error)) => {
                            closing.push(Call::Close {
                                fd: reading.fd.into(),
                            });
                            // -f: a file that cannot be written is removed, and made anew.
                            if *replace
                                && self.options.force
                                && matches!(error.errno, Errno::EACCES | Errno::EPERM)
                            {
                                again.push(index);
                            } else {
                                self.cannot_create(io, item, &error);
                            }
                        }
                    }
                }
                Step::Skip | Step::Link { .. } => {}
            }
        }
        if !closing.is_empty() {
            calls::<Value>(sys, std::mem::take(&mut closing)).await;
        }
        if !again.is_empty() {
            let mut made = Vec::new();
            for &index in &again {
                made.push(Call::Unlink {
                    path: level[index].to.clone(),
                });
                made.push(Call::Open {
                    path: level[index].from.clone(),
                    flags: O_RDONLY,
                    mode: 0,
                    size: None,
                    sha256: None,
                    version: None,
                });
                made.push(open_writing(&level[index], false));
            }
            let mut results = calls::<Value>(sys, made).await.into_iter();
            for &index in &again {
                let item = &level[index];
                let removed = results.next().unwrap_or(Err(Errno::EIO.into()));
                let reading = value::<Opened>(results.next().unwrap_or(Err(Errno::EIO.into())));
                let writing = value::<Opened>(results.next().unwrap_or(Err(Errno::EIO.into())));
                match (removed, reading, writing) {
                    (_, Ok(reading), Ok(writing)) => {
                        fds[index] = Some((reading.fd, writing.fd, writing.created));
                    }
                    (Err(error), reading, _) => {
                        io.fail(format!(
                            "cp: cannot remove {}: {error}",
                            quote(&item.shown_to)
                        ));
                        self.status = 1;
                        closing.extend(reading.ok().map(|r| Call::Close { fd: r.fd.into() }));
                    }
                    (_, reading, writing) => {
                        let error = writing
                            .as_ref()
                            .err()
                            .or(reading.as_ref().err())
                            .cloned()
                            .unwrap_or_else(|| Errno::EIO.into());
                        self.cannot_create(io, item, &error);
                        closing.extend(reading.ok().map(|r| Call::Close { fd: r.fd.into() }));
                        closing.extend(writing.ok().map(|w| Call::Close { fd: w.fd.into() }));
                    }
                }
            }
            if !closing.is_empty() {
                calls::<Value>(sys, std::mem::take(&mut closing)).await;
            }
        }
        // Each file takes its source's content, and is closed, complete.
        let cloned: Vec<usize> = (0..level.len()).filter(|i| fds[*i].is_some()).collect();
        let mut clones = Vec::new();
        for &index in &cloned {
            let (reading, writing, _) = fds[index].expect("opened");
            clones.extend([
                Call::Ioctl {
                    fd: writing.into(),
                    request: FICLONE,
                    arg: reading.into(),
                },
                Call::Close { fd: writing.into() },
                Call::Close { fd: reading.into() },
            ]);
        }
        let mut results = calls::<Value>(sys, clones).await.into_iter();
        let mut cleanup = Vec::new();
        // What has no content to share (the kernel makes it as it is read: /etc/passwd, /proc,
        // a device's state) is read, and written, as cp --reflink=auto does.
        let mut read = Vec::new();
        for &index in &cloned {
            let item = &level[index];
            let (_, _, created) = fds[index].expect("opened");
            let clone = results.next().unwrap_or(Err(Errno::EIO.into()));
            let closed = results.next().unwrap_or(Err(Errno::EIO.into()));
            results.next();
            match (clone, closed) {
                (Ok(_), Ok(_)) => copied[index] = true,
                (Err(error), Ok(_)) if error.errno == Errno::EOPNOTSUPP => read.push(index),
                (Err(error), _) => {
                    io.fail(format!(
                        "cp: failed to clone {} from {}: {error}",
                        quote(&item.shown_to),
                        quote(&item.shown_from)
                    ));
                    self.status = 1;
                    if created {
                        cleanup.push(Call::Unlink {
                            path: item.to.clone(),
                        });
                    }
                }
                (Ok(_), Err(error)) => {
                    io.fail(format!(
                        "cp: failed to close {}: {error}",
                        quote(&item.shown_to)
                    ));
                    self.status = 1;
                }
            }
        }
        for index in read {
            let item = &level[index];
            match self.write_read(sys, item).await {
                Ok(()) => copied[index] = true,
                Err(error) => {
                    io.fail(format!(
                        "cp: cannot copy {} to {}: {error}",
                        quote(&item.shown_from),
                        quote(&item.shown_to)
                    ));
                    self.status = 1;
                }
            }
        }
        // Other names of files copied, once those are whole.
        for (item, step) in level.iter().zip(&steps) {
            if let Step::Link { first, .. } = step {
                cleanup.push(Call::Link {
                    from: first.clone(),
                    to: item.to.clone(),
                    follow: false,
                });
            }
        }
        let links: Vec<usize> = (0..level.len())
            .filter(|i| matches!(steps[*i], Step::Link { .. }))
            .collect();
        let results = calls::<Value>(sys, cleanup).await;
        for (&index, result) in links
            .iter()
            .zip(results.iter().rev().take(links.len()).rev())
        {
            let item = &level[index];
            match result {
                Ok(_) => copied[index] = true,
                Err(error) => {
                    let first = self
                        .seen
                        .get(&item.stat.ino)
                        .map(|(_, shown)| shown.clone())
                        .unwrap_or_default();
                    io.fail(format!(
                        "cp: cannot create hard link {} to {}: {error}",
                        quote(&item.shown_to),
                        quote(&first)
                    ));
                    self.status = 1;
                }
            }
        }
        if self.options.verbose {
            for (item, _) in level.iter().zip(&copied).filter(|(_, copied)| **copied) {
                io.say(format!(
                    "{} -> {}",
                    quote(&item.shown_from),
                    quote(&item.shown_to)
                ));
            }
        }
        if self.options.preserve {
            let kept: Vec<Item> = level
                .iter()
                .zip(&steps)
                .zip(0..)
                .filter(|((item, step), index)| {
                    !item.stat.is_dir()
                        && !item.stat.is_link()
                        && matches!(step, Step::File { .. })
                        && fds[*index].is_some()
                })
                .map(|((item, _), _)| item.clone())
                .collect();
            self.keep(sys, &kept).await;
        }
    }

    /// Give `items` their sources' owner and group, as far as the copier may, then their mode,
    /// without setuid or setgid if they could not keep both, their ACLs (with -a, their other
    /// extended attributes too), and their times. What cannot be kept is left, as GNU's cp -p
    /// leaves it.
    async fn keep(&mut self, sys: &impl Sys, items: &[Item]) {
        if items.is_empty() {
            return;
        }
        let mut owners = Vec::new();
        for item in items {
            owners.push(Call::Chown {
                path: item.to.clone(),
                uid: Some(item.stat.uid),
                gid: Some(item.stat.gid),
                nofollow: true,
            });
            owners.push(Call::Chown {
                path: item.to.clone(),
                uid: None,
                gid: Some(item.stat.gid),
                nofollow: true,
            });
        }
        let owned = calls::<Value>(sys, owners).await;
        let mut later = Vec::new();
        for (index, item) in items.iter().enumerate() {
            let mut mode = item.stat.perm();
            if owned[index * 2].is_err() {
                mode &= !0o6000;
            }
            later.push(Call::Chmod {
                path: item.to.clone(),
                mode,
            });
        }
        // The ACLs, and with -a every other attribute, as the sources have them.
        let names = calls::<Vec<String>>(
            sys,
            items
                .iter()
                .map(|item| Call::Listxattr {
                    path: item.from.clone(),
                    nofollow: true,
                })
                .collect(),
        )
        .await;
        let mut wanted = Vec::new();
        for (item, names) in items.iter().zip(names) {
            for name in names.unwrap_or_default() {
                let acl = name == ACL_ACCESS || name == ACL_DEFAULT && item.stat.is_dir();
                if acl || self.options.xattrs && !name.starts_with("system.") {
                    wanted.push((item, name));
                }
            }
        }
        let values = calls::<abi::Bytes>(
            sys,
            wanted
                .iter()
                .map(|(item, name)| Call::Getxattr {
                    path: item.from.clone(),
                    name: name.clone(),
                    nofollow: true,
                })
                .collect(),
        )
        .await;
        for ((item, name), value) in wanted.into_iter().zip(values) {
            if let Ok(value) = value {
                later.push(Call::Setxattr {
                    path: item.to.clone(),
                    name,
                    value,
                    flags: 0,
                    nofollow: true,
                });
            }
        }
        // And their times, last, as nothing after it changes them.
        for item in items {
            later.push(Call::Utimens {
                path: item.to.clone(),
                atime: abi::Time::At {
                    sec: item.stat.atime,
                    nsec: item.stat.atime_nsec,
                },
                mtime: abi::Time::At {
                    sec: item.stat.mtime,
                    nsec: item.stat.mtime_nsec,
                },
                nofollow: true,
            });
        }
        calls::<Value>(sys, later).await;
    }

    /// Directories made or merged into, deepest first: those made take the mode they should
    /// have, without the writing their copying needed; with -p, they keep their sources'.
    async fn finish_dirs(&mut self, sys: &impl Sys, _io: &mut Io<'_>) {
        let mut dirs = std::mem::take(&mut self.dirs);
        dirs.sort_by_key(|(item, _)| std::cmp::Reverse(item.to.matches('/').count()));
        if self.options.preserve {
            let items: Vec<Item> = dirs.into_iter().map(|(item, _)| item).collect();
            self.keep(sys, &items).await;
            return;
        }
        let narrowed: Vec<&Item> = dirs
            .iter()
            .filter(|(item, made)| *made && item.stat.perm() & 0o700 != 0o700)
            .map(|(item, _)| item)
            .collect();
        if narrowed.is_empty() {
            return;
        }
        let now = calls::<Stat>(
            sys,
            narrowed
                .iter()
                .map(|item| Call::Lstat {
                    path: item.to.clone(),
                })
                .collect(),
        )
        .await;
        let mut modes = Vec::new();
        for (item, now) in narrowed.iter().zip(now) {
            if let Ok(now) = now {
                // What mkdir gave, less the umask, without what the source does not have.
                modes.push(Call::Chmod {
                    path: item.to.clone(),
                    mode: now.perm() & (item.stat.perm() | !0o777),
                });
            }
        }
        calls::<Value>(sys, modes).await;
    }
}

/// open(2) of where `item` goes, for writing: a new file, or the one there replaced, written
/// through a link to it. The mode is the source's, less the umask, as the kernel takes it.
fn open_writing(item: &Item, replace: bool) -> Call {
    Call::Open {
        path: item.to.clone(),
        flags: O_WRONLY | if replace { O_TRUNC } else { O_CREAT | O_EXCL },
        mode: item.stat.perm() & 0o777,
        size: Some(item.stat.size),
        sha256: None,
        version: None,
    }
}

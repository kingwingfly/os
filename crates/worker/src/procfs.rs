//! /proc (owner's design, 2026-10-29: the page is user space, its requests system calls): what
//! the kernel tells of processes and descriptors, as files it writes as they are read, as Linux's
//! procfs does. Each session sees its own descriptors (/proc/self/fd, /proc/self/fdinfo), and an
//! account its own processes (/proc/PID), as procfs mounted with hidepid=invisible shows them;
//! a job's descriptors are /proc/PID/fd.
//!
//! /proc/self/fd/N is a magic link: a path through it names what the descriptor has open, as
//! openat(2) names it from a directory's descriptor.
use crate::db::{Db, Fd};
use crate::procs::Row;
use abi::{Dirent, Errno, Error, Stat};
use serde_json::{Value, json};
use terminal_worker_core::permissions::{Identity, Store};

type Result<T> = std::result::Result<T, Error>;

/// Whether `path` is in /proc.
pub fn is(path: &str) -> bool {
    path == "/proc" || path.starts_with("/proc/")
}

/// Whether `path` tells of processes: /proc and /proc/PID, not /proc/self's descriptors.
pub fn of_processes(path: &str) -> bool {
    let path = path.trim_end_matches('/');
    path == "/proc" || (is(path) && !path.starts_with("/proc/self"))
}

/// What a descriptor has open, where it is now: a file being written is where it shows.
pub fn opened(db: &Db, found: &Fd) -> String {
    if let Some(device) = &found.device {
        return device.clone();
    }
    match found.file.as_deref().and_then(|file| db.file(file)) {
        Some(file) if found.writes() => db.showing(&file.id).pop().unwrap_or(file.target),
        _ => found.path.clone(),
    }
}

/// `path` with a magic link /proc/self/fd/N in it followed: the last part only if `follow`, as
/// lstat and readlink look at the link itself.
pub fn follow(db: &Db, sid: Option<&str>, path: &str, follow: bool) -> Result<String> {
    let Some(rest) = path.strip_prefix("/proc/self/fd/") else {
        return Ok(path.to_string());
    };
    let (number, after) = rest
        .split_once('/')
        .map_or((rest, None), |(n, a)| (n, Some(a)));
    if after.is_none() && !follow {
        return Ok(path.to_string());
    }
    let fd: u32 = number.parse().map_err(|_| Errno::ENOENT)?;
    let found = sid.and_then(|sid| db.fd(sid, fd)).ok_or(Errno::ENOENT)?;
    let target = opened(db, &found);
    Ok(match after {
        Some(after) if !after.is_empty() => format!("{}/{after}", target.trim_end_matches('/')),
        _ => target,
    })
}

/// What a path in /proc is.
enum Entry {
    Dir(u32),
    File(String, u32),
    Link(String, u32),
}

/// What /proc lists as a process: one of the client kernel's processes (procs.rs), or a job
/// whose work is done apart.
enum Proc {
    Job(crate::db::Job),
    Process(Row),
}
impl Proc {
    fn id(&self) -> String {
        match self {
            Self::Job(job) => job.id.clone(),
            Self::Process(row) => row.pid.to_string(),
        }
    }
    fn owner(&self) -> u32 {
        match self {
            Self::Job(job) => job.owner,
            Self::Process(row) => row.uid,
        }
    }
}

/// The account's jobs and the browser's processes `procs` (its machine's), by PID, as /proc
/// lists them: a PID names a process of one namespace (each browser's), as a Linux PID
/// namespace sees its own; root sees every process of it, an account its own, and init.
fn processes(db: &Db, who: &Identity, procs: &[Row]) -> Vec<Proc> {
    let jobs = db.jobs_of(who.id, 20).into_iter().map(Proc::Job);
    let rows = procs
        .iter()
        .filter(|row| who.id == 0 || row.uid == who.id || row.pid == crate::procs::INIT)
        .cloned()
        .map(Proc::Process);
    jobs.chain(rows).collect()
}

/// /proc/PID/status: as Linux's, its name, state and who it runs as; and, for a job, how far
/// it is.
fn status(db: &Db, process: &Proc) -> String {
    match process {
        Proc::Job(job) => {
            let progress: Value = serde_json::from_str(&job.progress).unwrap_or_default();
            format!(
                "Name:\t{}\nState:\t{}\nUid:\t{}\nProgress:\t{}/{}\nStarted:\t{}\n",
                job.kind,
                job.state,
                db.username(job.actor),
                progress["done"].as_u64().unwrap_or(0),
                progress["total"].as_u64().unwrap_or(0),
                job.created
            )
        }
        Proc::Process(row) => {
            let name = row.path.rsplit('/').next().unwrap_or(&row.path);
            let state = match row.state.as_str() {
                "zombie" => "Z (zombie)",
                "stopped" => "T (stopped)",
                "sleeping" => "S (sleeping)",
                _ => "R (running)",
            };
            format!(
                "Name:\t{name}\nState:\t{state}\nPid:\t{}\nPPid:\t{}\nUid:\t{}\t{}\t{}\t{}\nGid:\t{}\t{}\t{}\t{}\nCgroup:\t{}\n",
                row.pid,
                row.ppid,
                row.uid,
                row.uid,
                row.uid,
                row.uid,
                row.gid,
                row.gid,
                row.gid,
                row.gid,
                row.cgroup
            )
        }
    }
}

/// /proc/PID/cmdline: its program and what it works on, each ended by a NUL.
fn cmdline(process: &Proc) -> String {
    match process {
        Proc::Job(job) => {
            let command = crate::jobs::Spec::of(job)
                .map(|spec| json!(spec.command))
                .unwrap_or_default();
            let on = command["archive"]
                .as_str()
                .or(command["file"].as_str())
                .unwrap_or_default();
            [job.kind.as_str(), on]
                .iter()
                .filter(|part| !part.is_empty())
                .map(|part| format!("{part}\0"))
                .collect()
        }
        Proc::Process(row) => {
            let argv: Vec<String> = serde_json::from_str(&row.argv).unwrap_or_default();
            argv.iter().map(|arg| format!("{arg}\0")).collect()
        }
    }
}

/// /proc/self/fdinfo/N: as Linux's, where it is and how it was opened (its flags in octal); and
/// what it writes: the file's size, what has arrived, and whether it made it.
fn fdinfo(db: &Db, found: &Fd) -> String {
    let file = found.file.as_deref().and_then(|file| db.file(file));
    format!(
        "pos:\t0\nflags:\t0{:o}\nsize:\t{}\nreceived:\t{}\ncreated:\t{}\n",
        found.flags,
        file.as_ref().map_or(0, |file| file.size),
        file.as_ref().map_or(0, |file| db.received(file)),
        u8::from(found.created)
    )
}

fn lookup(db: &Db, sid: Option<&str>, procs: &[Row], who: &Identity, path: &str) -> Result<Entry> {
    let parts: Vec<&str> = path
        .trim_start_matches("/proc")
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    let fd = |number: &str| {
        let fd: u32 = number.parse().map_err(|_| Errno::ENOENT)?;
        sid.and_then(|sid| db.fd(sid, fd))
            .ok_or_else(|| Error::from(Errno::ENOENT))
    };
    let job = |pid: &str| {
        processes(db, who, procs)
            .into_iter()
            .find(|process| process.id() == pid)
            .ok_or_else(|| Error::from(Errno::ENOENT))
    };
    Ok(match parts.as_slice() {
        [] => Entry::Dir(0),
        ["self"] | ["self", "fd" | "fdinfo"] => Entry::Dir(who.id),
        ["self", "fd", number] => Entry::Link(opened(db, &fd(number)?), who.id),
        ["self", "fdinfo", number] => Entry::File(fdinfo(db, &fd(number)?), who.id),
        [pid] => Entry::Dir(job(pid)?.owner()),
        [pid, "status"] => {
            let process = job(pid)?;
            Entry::File(status(db, &process), process.owner())
        }
        [pid, "cmdline"] => {
            let process = job(pid)?;
            Entry::File(cmdline(&process), process.owner())
        }
        // A job's descriptors, its own (creds.rs `job_owner`): what it has open, as its runner
        // works (the archive it reads, the file it writes).
        [pid, "fd"] => match job(pid)? {
            process @ Proc::Job(_) => Entry::Dir(process.owner()),
            Proc::Process(row) => Entry::Dir(row.uid),
        },
        [pid, "fd", number] => match job(pid)? {
            process @ Proc::Job(_) => {
                let fd: u32 = number.parse().map_err(|_| Errno::ENOENT)?;
                let found = db
                    .fd(&crate::creds::job_owner(pid), fd)
                    .ok_or(Errno::ENOENT)?;
                Entry::Link(opened(db, &found), process.owner())
            }
            Proc::Process(row) => {
                let fd: u32 = number.parse().map_err(|_| Errno::ENOENT)?;
                let fds: Vec<u32> = serde_json::from_str(&row.tty_fds).unwrap_or_default();
                let tty = row.tty.filter(|_| fds.contains(&fd)).ok_or(Errno::ENOENT)?;
                Entry::Link(format!("/dev/pts/{tty}"), row.uid)
            }
        },
        _ => return Err(Errno::ENOENT.into()),
    })
}

/// What stat tells of /proc's `entry`, at `path`: a number of its own, as procfs's inodes are;
/// its files' size 0, as theirs are, read to their end whatever it says.
fn stat_of(db: &Db, path: &str, entry: &Entry) -> Stat {
    let ino = (1 << 48)
        | path.bytes().fold(0xcbf29ce484222325u64, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
        }) >> 16;
    let (mode, owner, link) = match entry {
        Entry::Dir(owner) => (abi::S_IFDIR | 0o555, *owner, None),
        Entry::File(_, owner) => (abi::S_IFREG | 0o444, *owner, None),
        Entry::Link(target, owner) => (abi::S_IFLNK | 0o700, *owner, Some(target.clone())),
    };
    let group = db.user_by_id(owner).map_or(0, |(_, user)| user.group);
    let now = crate::auth::now();
    Stat {
        ino,
        mode,
        nlink: 1,
        uid: owner,
        gid: group,
        user: db.username(owner),
        group: db.groupname(group),
        size: link.as_ref().map_or(0, |target| target.len() as u64),
        mtime: now,
        ctime: now,
        atime: now,
        link,
        ..Stat::default()
    }
}

/// The entries of the /proc directory `path`.
fn entries(
    db: &Db,
    sid: Option<&str>,
    procs: &[Row],
    who: &Identity,
    path: &str,
) -> Result<Vec<Dirent>> {
    let Entry::Dir(_) = lookup(db, sid, procs, who, path)? else {
        return Err(Errno::ENOTDIR.into());
    };
    let names: Vec<String> = match path.trim_end_matches('/') {
        "/proc" => std::iter::once("self".to_string())
            .chain(
                processes(db, who, procs)
                    .into_iter()
                    .map(|process| process.id()),
            )
            .collect(),
        "/proc/self" => vec!["fd".into(), "fdinfo".into()],
        "/proc/self/fd" | "/proc/self/fdinfo" => sid
            .map(|sid| db.fds_of(sid))
            .unwrap_or_default()
            .into_iter()
            .map(|found| found.fd.to_string())
            .collect(),
        other => match other
            .strip_prefix("/proc/")
            .and_then(|rest| rest.strip_suffix("/fd"))
        {
            Some(pid) if pid.parse::<u32>().is_ok() => {
                let row = procs
                    .iter()
                    .find(|row| row.pid.to_string() == pid)
                    .ok_or(Errno::ENOENT)?;
                serde_json::from_str::<Vec<u32>>(&row.tty_fds)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|fd| fd.to_string())
                    .collect()
            }
            Some(pid) => db
                .fds_of(&crate::creds::job_owner(pid))
                .into_iter()
                .map(|found| found.fd.to_string())
                .collect(),
            None => vec!["cmdline".into(), "fd".into(), "status".into()],
        },
    };
    Ok(names
        .into_iter()
        .filter_map(|name| {
            let at = format!("{}/{name}", path.trim_end_matches('/'));
            let entry = lookup(db, sid, procs, who, &at).ok()?;
            Some(Dirent {
                stat: Some(stat_of(db, &at, &entry)),
                name,
            })
        })
        .collect())
}

/// The content of the /proc file `path`, as it is now.
pub fn read(
    db: &Db,
    sid: Option<&str>,
    procs: &[Row],
    who: &Identity,
    path: &str,
) -> Result<String> {
    match lookup(db, sid, procs, who, path)? {
        Entry::File(text, _) => Ok(text),
        Entry::Dir(_) => Err(Errno::EISDIR.into()),
        Entry::Link(..) => Err(Errno::EINVAL.into()),
    }
}

/// A call on a path in /proc, once its magic links are followed: its result. What would change
/// /proc may not.
pub fn call(
    db: &mut Db,
    sid: Option<&str>,
    procs: &[Row],
    who: &Identity,
    call: abi::Call,
) -> Result<Value> {
    use abi::Call;
    match call {
        Call::Stat { path } | Call::Lstat { path } => {
            let entry = lookup(db, sid, procs, who, &path)?;
            Ok(json!(stat_of(db, &path, &entry)))
        }
        Call::Getdents {
            path,
            cookie,
            count,
        } => Ok(json!(
            entries(db, sid, procs, who, &path)?
                .into_iter()
                .skip(cookie as usize)
                .take(count.unwrap_or(u64::MAX) as usize)
                .collect::<Vec<_>>()
        )),
        Call::Access { path, mode } => {
            lookup(db, sid, procs, who, &path)?;
            if mode & abi::W_OK != 0 {
                Err(Errno::EACCES.into())
            } else {
                Ok(Value::Null)
            }
        }
        Call::Readlink { path } => match lookup(db, sid, procs, who, &path)? {
            Entry::Link(target, _) => Ok(json!(target)),
            _ => Err(Errno::EINVAL.into()),
        },
        Call::Getxattr { path, .. } => {
            lookup(db, sid, procs, who, &path)?;
            Err(Errno::ENODATA.into())
        }
        Call::Listxattr { path, .. } => {
            lookup(db, sid, procs, who, &path)?;
            Ok(json!([]))
        }
        Call::Statfs { path } => {
            lookup(db, sid, procs, who, &path)?;
            Ok(json!(abi::StatFs {
                namelen: abi::NAME_MAX as u64,
                ..abi::StatFs::default()
            }))
        }
        Call::Open { path, flags, .. } => {
            let entry = lookup(db, sid, procs, who, &path)?;
            if flags & abi::O_ACCMODE != abi::O_RDONLY {
                return Err(Errno::EACCES.into());
            }
            if flags & abi::O_DIRECTORY != 0 && !matches!(entry, Entry::Dir(_)) {
                return Err(Errno::ENOTDIR.into());
            }
            let sid = sid.ok_or(Errno::EBADF)?;
            let now = crate::auth::now();
            let fd = db.add_fd(sid, None, &path, flags, false, now);
            Ok(json!(abi::Opened {
                fd,
                ..abi::Opened::default()
            }))
        }
        // What would make, change or remove something in /proc.
        _ => Err(Errno::EACCES.into()),
    }
}

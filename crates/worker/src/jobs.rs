//! Jobs, as the authority sees them: zip, unzip, tar and faststart start one, whose work a
//! JobRunner Durable Object does with a container, asking the authority, as the job's account,
//! for each file it reads or writes.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use terminal_worker_core::archive::{self, ENTRIES_MAX, Job as Command};
use terminal_worker_core::permissions::*;
use terminal_worker_core::{MAX_FILE, kind};

use crate::commands::{self, command_path};
use crate::db::{Db, Job};

/// An archive a job reads.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Source {
    pub path: String,
    pub file: String,
    pub size: u64,
}
/// A member of an archive a job writes, as the files were when it started.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Input {
    pub name: String,
    /// Its content; none for a directory.
    pub file: Option<String>,
    pub size: u64,
    pub mode: u32,
    pub owner: String,
    pub group: String,
    pub uid: u64,
    pub gid: u64,
    /// Whether to store it as it is, as for content already compressed.
    pub store: bool,
    /// A symbolic link's target, stored as a link.
    #[serde(default)]
    pub symlink: Option<String>,
    /// The earlier member it is another name of, in a tar.
    #[serde(default)]
    pub hardlink: Option<String>,
}
/// What a job does.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Spec {
    pub command: Command,
    pub source: Option<Source>,
    /// Where extracted members go.
    pub directory: Option<String>,
    /// The archive written, and whether it replaces a file.
    pub output: Option<String>,
    #[serde(default)]
    pub replace: bool,
    #[serde(default)]
    pub inputs: Vec<Input>,
    /// The date every member written gets, so that rebuilding gives the same archive.
    pub mtime: u64,
    /// unzip's answers, path by path, to whether to replace an existing file.
    #[serde(default)]
    pub decisions: Option<BTreeMap<String, bool>>,
}
impl Spec {
    pub fn of(job: &Job) -> Result<Spec, String> {
        serde_json::from_str(&job.spec).map_err(|e| e.to_string())
    }
}

/// The identity a job acts as: root if started with sudo, a guest if started by one, otherwise
/// its account as it is now.
pub fn actor(db: &Db, job: &Job) -> Result<Identity, String> {
    if job.actor == 0 {
        return Ok(Identity::root());
    }
    if job.actor == GUEST {
        return Ok(Identity::guest());
    }
    match db.user_by_id(job.actor) {
        Some((_, user)) if !user.locked => Ok(Identity::of(&user)),
        _ => Err("The account that started this job is locked or deleted".into()),
    }
}

/// A complete file at `path` that `who` may read: an archive to extract or list.
fn source(db: &Db, who: &Identity, cmd: &str, path: &str) -> Result<Source, String> {
    let node = db
        .access(who, path, READ)
        .map_err(|e| format!("{cmd}: {e}"))?;
    let file = node
        .file
        .and_then(|id| db.file(&id))
        .ok_or_else(|| format!("{cmd}: {path}: This is a directory, not an archive"))?;
    if !file.complete() {
        return Err(format!(
            "{cmd}: {path} is still uploading; try again once it completes"
        ));
    }
    Ok(Source {
        path: path.into(),
        file: file.id,
        size: file.size,
    })
}

/// The members of an archive made of `paths`, as they are now; warnings for what is left out.
/// Relative paths are found in `directory` if given, as tar -C works in it, and stored as typed.
/// With `links`, as tar does, a symbolic link is stored as one, and the second name of a file
/// as another name for the first; otherwise, as zip does, links are followed.
#[allow(clippy::too_many_arguments)]
fn inputs(
    db: &Db,
    who: &Identity,
    command: &commands::Command,
    cmd: &str,
    paths: &[String],
    recursive: bool,
    links: bool,
    output: &str,
    directory: Option<&str>,
) -> Result<(Vec<Input>, Vec<String>), String> {
    let within;
    let command = match directory {
        Some(typed) => {
            let dir = command_path(db, who, command, typed).map_err(|e| format!("{cmd}: {e}"))?;
            let node = db
                .access(who, &dir, EXEC)
                .map_err(|e| format!("{cmd}: {typed}: {e}"))?;
            if !node.directory {
                return Err(format!("{cmd}: {typed}: Cannot open: Not a directory"));
            }
            within = commands::Command {
                args: Vec::new(),
                cwd: dir,
                sudo: command.sudo,
                home: command.home.clone(),
            };
            &within
        }
        None => command,
    };
    let mut members = Vec::new();
    let mut warnings = Vec::new();
    let mut names = BTreeSet::new();
    // The first member each inode was stored as, for its other names.
    let mut first: BTreeMap<u64, String> = BTreeMap::new();
    for typed in paths {
        let found = if links {
            commands::entry_path(db, who, command, typed)
        } else {
            command_path(db, who, command, typed)
        };
        let (path, node) = match found.and_then(|p| db.access(who, &p, 0).map(|n| (p, n))) {
            Ok(found) => found,
            Err(e) => {
                warnings.push(format!("{cmd}: {typed}: {e}"));
                continue;
            }
        };
        // Stored as typed, or, for an absolute or home path, without its leading slash.
        let base = if typed.starts_with('/') || typed.starts_with('~') {
            archive::stored_name(&path)
        } else {
            archive::stored_name(typed)
        };
        // Depth first, parents before what they hold, each directory's in order of name.
        // Each with the directories above it, so that a link to one of them does not loop.
        let mut stack = vec![(path, node, base, Vec::<String>::new())];
        while let Some((path, mut node, name, above)) = stack.pop() {
            let mut path = path;
            if node.is_link() && !links {
                // A link that loops, or may not be followed, is left out, as zip warns and goes on.
                let real = match db.physical(who, &path, true) {
                    Ok(real) => real,
                    Err(e) => {
                        warnings.push(format!("{cmd}: {name}: {e}; left out"));
                        continue;
                    }
                };
                match db.node(&real).filter(|_| db.traverse(who, &real).is_ok()) {
                    Some(target) => {
                        path = real;
                        node = target;
                    }
                    None => {
                        warnings.push(format!("{cmd}: {name}: the link leads nowhere; left out"));
                        continue;
                    }
                }
            }
            // A directory named `.` (or `/`, or `..`) is stored as nothing itself, and what it
            // holds by its own names.
            let unnamed = name.is_empty();
            if unnamed && !node.directory || !unnamed && !names.insert(name.clone()) {
                continue;
            }
            let mut input = Input {
                store: matches!(kind(&name), "image" | "video" | "audio" | "pdf" | "archive"),
                name: name.clone(),
                file: None,
                size: 0,
                mode: u32::from(node.mode),
                owner: db.username(node.owner),
                group: db.groupname(node.group),
                uid: u64::from(node.owner),
                gid: u64::from(node.group),
                symlink: None,
                hardlink: None,
            };
            if let Some(target) = &node.link {
                input.symlink = Some(target.clone());
                members.push(input);
                continue;
            }
            if !node.directory {
                if path == output {
                    warnings.push(format!("{cmd}: {name} is the archive itself; left out"));
                    continue;
                }
                if !who.allows(&node, READ) {
                    warnings.push(format!("{cmd}: {path}: Permission denied; left out"));
                    continue;
                }
                if let Some(file) = node.file.as_deref().and_then(|id| db.file(id))
                    && !file.complete()
                {
                    warnings.push(format!("{cmd}: {name} is still uploading; left out"));
                    continue;
                }
                match first.get(&node.ino) {
                    // Only tar has hard links: zip -y keeps symbolic links, and stores another
                    // name of a file as a file (a zip entry without content is a directory).
                    Some(earlier) if links && cmd == "tar" => {
                        input.hardlink = Some(earlier.clone())
                    }
                    _ => {
                        if node.links > 1 {
                            first.insert(node.ino, name.clone());
                        }
                        input.file = node.file.clone();
                        input.size = node.size;
                    }
                }
                members.push(input);
                continue;
            }
            if !unnamed {
                members.push(input);
            }
            // Without -r, a directory named is a member, and what it holds is not.
            if !recursive {
                continue;
            }
            if !who.allows(&node, READ | EXEC) {
                warnings.push(format!("{cmd}: {name}: could not be read; left out"));
                continue;
            }
            if above.contains(&path) {
                warnings.push(format!(
                    "{cmd}: {name}: a directory it is in again; left out"
                ));
                continue;
            }
            let mut inside = above;
            inside.push(path.clone());
            for (child, n) in db.children(&path).into_iter().rev() {
                let leaf = child.rsplit('/').next().unwrap_or_default();
                let named = if unnamed {
                    leaf.to_string()
                } else {
                    format!("{name}/{leaf}")
                };
                stack.push((child.clone(), n, named, inside.clone()));
            }
            if members.len() > ENTRIES_MAX {
                return Err(format!(
                    "{cmd}: more than {ENTRIES_MAX} members; archive less at once"
                ));
            }
        }
    }
    let total: u64 = members.iter().map(|m| m.size).sum();
    if total > MAX_FILE {
        return Err(format!(
            "{cmd}: the files come to more than {} MB, the most an archive may hold",
            MAX_FILE / 1_000_000
        ));
    }
    if members.is_empty() {
        return Err(format!("{cmd}: nothing to do"));
    }
    Ok((members, warnings))
}

/// Start the archive job `command` asks for, as `who`; it is the reply's `job`.
/// Refuse to write `path`, as `who` resolves it (its directory, if it is not there yet), if it is
/// the image's (/usr), read-only, as the kernel's calls refuse with EROFS (sys.rs).
fn read_only(db: &Db, who: &Identity, cmd: &str, path: &str) -> Result<(), String> {
    let real = kernel::namei(db, who, path, true)
        .map(|name| name.path)
        .or_else(|_| {
            let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
            let parent = if parent.is_empty() { "/" } else { parent };
            kernel::namei(db, who, parent, true)
                .map(|dir| format!("{}/{name}", dir.path.trim_end_matches('/')))
        })
        .unwrap_or_else(|_| path.to_string());
    if crate::usr::is(&real) {
        return Err(format!("{cmd}: {path}: Read-only file system"));
    }
    Ok(())
}

pub fn start(
    db: &mut Db,
    who: &Identity,
    owner: u32,
    command: &commands::Command,
) -> Result<Value, String> {
    let (cmd, args) = command.args.split_first().ok_or("Missing command")?;
    let parsed = match cmd.as_str() {
        "zip" => archive::zip_args(args)?,
        "unzip" => archive::unzip_args(args)?,
        "faststart" => archive::faststart_args(args)?,
        _ => archive::tar_args(args)?,
    };
    let path = |db: &Db, value: &str| command_path(db, who, command, value);
    let now = crate::auth::now();
    let mut spec = Spec {
        command: parsed.clone(),
        source: None,
        directory: None,
        output: None,
        replace: false,
        inputs: Vec::new(),
        mtime: now,
        decisions: None,
    };
    let mut warnings = Vec::new();
    match &parsed {
        Command::Create {
            format,
            archive: name,
            paths,
            recursive,
            directory,
            links,
            ..
        } => {
            let output = path(db, name)?;
            // Only where `who` may look is it told what is there.
            db.traverse(who, &output)
                .map_err(|e| format!("{cmd}: {e}"))?;
            read_only(db, who, cmd, &output)?;
            match db.node(&output) {
                Some(node) if node.directory => {
                    return Err(format!("{cmd}: {output} is a directory"));
                }
                Some(_) if *format == archive::Format::Zip => {
                    return Err(format!(
                        "zip: {output} exists; this terminal does not update archives, so remove it or choose another name"
                    ));
                }
                Some(_) => {
                    db.access(who, &output, WRITE)
                        .map_err(|e| format!("{cmd}: {e}"))?;
                    spec.replace = true;
                }
                None => db
                    .writable_parent(who, &output)
                    .map_err(|e| format!("{cmd}: {e}"))?,
            }
            let (members, notes) = inputs(
                db,
                who,
                command,
                cmd,
                paths,
                *recursive,
                *links,
                &output,
                directory.as_deref(),
            )?;
            spec.inputs = members;
            spec.output = Some(output);
            warnings = notes;
        }
        Command::Extract {
            zip,
            archive: name,
            directory,
            ..
        } => {
            spec.source = Some(source(db, who, cmd, &path(db, name)?)?);
            let dest = path(db, directory.as_deref().unwrap_or("."))?;
            // Only where `who` may look is it told what is there; unzip -d creates what is
            // missing on the way.
            if let Err(e) = db.traverse(who, &dest)
                && commands::is_permission_error(&e)
            {
                return Err(format!("{cmd}: {e}"));
            }
            read_only(db, who, cmd, &dest)?;
            match db.node(&dest) {
                Some(node) if node.directory => {
                    db.access(who, &dest, WRITE | EXEC)
                        .map_err(|e| format!("{cmd}: {e}"))?;
                }
                Some(_) => return Err(format!("{cmd}: {dest} is not a directory")),
                // unzip -d creates its directory; tar -C needs one.
                None if *zip => db
                    .mkdir(who, &dest, true)
                    .map_err(|e| format!("{cmd}: {e}"))?,
                None => {
                    return Err(format!(
                        "tar: {dest}: Cannot open: No such file or directory"
                    ));
                }
            }
            spec.directory = Some(dest);
        }
        Command::List { archive: name, .. } => {
            spec.source = Some(source(db, who, cmd, &path(db, name)?)?);
        }
        // The file is read as it is now, and written over in place, as a new archive is: it
        // keeps its owner, mode, ACLs and other names, and shows its old content until done.
        Command::Faststart { file } => {
            let target = path(db, file)?;
            read_only(db, who, cmd, &target)?;
            let found = source(db, who, cmd, &target)?;
            let node = db
                .access(who, &target, READ | WRITE)
                .map_err(|e| format!("{cmd}: {e}"))?;
            spec.inputs = vec![Input {
                name: target.rsplit('/').next().unwrap_or_default().to_string(),
                file: Some(found.file),
                size: found.size,
                mode: u32::from(node.mode),
                owner: db.username(node.owner),
                group: db.groupname(node.group),
                uid: u64::from(node.owner),
                gid: u64::from(node.group),
                store: true,
                symlink: None,
                hardlink: None,
            }];
            spec.output = Some(target);
            spec.replace = true;
        }
    }
    let spec_value = serde_json::to_value(&spec).map_err(|e| e.to_string())?;
    let id = db.create_job(owner, who.id, cmd, &spec_value, now);
    if let Some(source) = &spec.source {
        db.pin(&id, &source.file);
    }
    for input in &spec.inputs {
        if let Some(file) = &input.file {
            db.pin(&id, file);
        }
    }
    db.add_lines(
        &id,
        &warnings.into_iter().map(|w| (true, w)).collect::<Vec<_>>(),
    );
    // A job left waiting for a runner is cancelled after a week.
    db.set_expiry("job", &id, now + WAITING);
    Ok(json!({"job": id, "kind": cmd}))
}

/// The most lines one view of a job carries.
const LINES_MAX: u32 = 500;
/// How long a job may wait to run, or be done, before it is cancelled ...
pub const WAITING: u64 = 7 * 24 * 60 * 60;
/// ... and for an answer to its question: then nobody is there to give one, as a process whose
/// terminal closed is hung up.
pub const UNANSWERED: u64 = 60 * 60;

/// What a job's owner sees of it: its state, progress, question and new lines, a page of them,
/// and whether more follow, which a job that has ended may still have.
pub fn view(db: &Db, job: &Job, since: u64) -> Value {
    let mut lines = db.lines(&job.id, since, LINES_MAX + 1);
    let more = lines.len() > LINES_MAX as usize;
    lines.truncate(LINES_MAX as usize);
    let lines: Vec<Value> = lines
        .into_iter()
        .map(|(seq, err, text)| json!([seq, err, text]))
        .collect();
    json!({
        "id": job.id, "kind": job.kind, "state": job.state, "created": job.created,
        "progress": serde_json::from_str::<Value>(&job.progress).unwrap_or_default(),
        "question": job.question.as_deref().and_then(|q| serde_json::from_str::<Value>(q).ok()),
        "lines": lines, "more": more,
    })
}

/// End a job: let go of the files it read, and keep what it says.
pub fn finish(db: &mut Db, job: &str, state: &str) {
    db.set_job(job, crate::db::JobColumn::State, Some(state));
    db.set_job(job, crate::db::JobColumn::Question, None);
    db.unpin(job);
    db.clear_expiry("job", job);
}

/// The process calls (owner's design, 2026-10-29): a job is a process of the account signed in
/// (`owner`), run as `process` (root under sudo).
pub fn call(
    db: &mut Db,
    owner: u32,
    home: &str,
    sid: Option<&str>,
    process: &kernel::Process,
    call: abi::Call,
) -> std::result::Result<Value, abi::Error> {
    use crate::db::JobColumn;
    use abi::{Call, Errno, Error};
    let refused = |why: String| {
        let errno = if commands::is_permission_error(&why) {
            Errno::EACCES
        } else {
            Errno::EINVAL
        };
        Error::because(errno, why)
    };
    // Its owner's, or root's, to see and signal.
    let theirs = |db: &Db, pid: &str| -> std::result::Result<Job, Error> {
        let job = db.job(pid).ok_or(Errno::ESRCH)?;
        if job.owner != owner && process.cred.id != 0 {
            return Err(Errno::EPERM.into());
        }
        Ok(job)
    };
    match call {
        Call::Spawn { argv, cwd } => {
            if !matches!(
                argv.first().map(String::as_str),
                Some("zip" | "unzip" | "tar" | "faststart")
            ) {
                return Err(Errno::ENOENT.into());
            }
            let command = commands::Command {
                args: argv,
                cwd,
                sudo: process.cred.id == 0,
                home: Some(home.to_string()),
            };
            let started = start(db, &process.cred, owner, &command).map_err(refused)?;
            let pid = started["job"].as_str().unwrap_or_default().to_string();
            // Its standard input, a descriptor of the session that writes it, as a pipe.
            let sid = sid.ok_or(Errno::EBADF)?;
            let now = crate::auth::now();
            let stdin = db.add_fd(sid, None, &stdin_of(&pid), abi::O_WRONLY, false, now);
            db.set_expiry("fd", &crate::db::fd_key(sid, stdin), now + crate::fds::IDLE);
            Ok(json!({ "pid": pid, "kind": started["kind"], "stdin": stdin }))
        }
        Call::Kill { pid } => {
            let job = theirs(db, &pid)?;
            if !job.finished() {
                db.set_job(&pid, JobColumn::State, Some("cancelling"));
            }
            Ok(json!({ "pid": pid, "state": db.job(&pid).map(|job| job.state) }))
        }
        Call::Wait { pid, since } => {
            let job = theirs(db, &pid)?;
            Ok(view(db, &job, since))
        }
        _ => Err(Errno::ENOSYS.into()),
    }
}

/// Where a process's standard input is, as its descriptor names it.
pub fn stdin_of(pid: &str) -> String {
    format!("/proc/{pid}/fd/0")
}

/// The process whose standard input `path` is, if it is one's.
pub fn stdin_pid(path: &str) -> Option<&str> {
    path.strip_prefix("/proc/")?.strip_suffix("/fd/0")
}

/// Write `data` to the standard input of the process `pid`, the account `owner`'s (or anyone's
/// as root): unzip's answers to its question, `{"decisions": {PATH: true|false}}`.
pub fn answer(
    db: &mut Db,
    owner: u32,
    process: &kernel::Process,
    pid: &str,
    data: &[u8],
) -> std::result::Result<Value, abi::Error> {
    use crate::db::JobColumn;
    use abi::{Errno, Error};
    let job = db.job(pid).ok_or(Errno::EPIPE)?;
    if job.owner != owner && process.cred.id != 0 {
        return Err(Errno::EPERM.into());
    }
    if job.state != "question" {
        return Err(Error::because(
            Errno::EAGAIN,
            "the process is not waiting for an answer",
        ));
    }
    let data: Value = serde_json::from_slice(data).unwrap_or_default();
    let mut spec = Spec::of(&job).map_err(|why| Error::because(Errno::EIO, why))?;
    spec.decisions = serde_json::from_value(data["decisions"].clone()).ok();
    if spec.decisions.is_none() {
        return Err(Error::because(
            Errno::EINVAL,
            "answer with {\"decisions\": {PATH: true|false}}",
        ));
    }
    db.set_job(pid, JobColumn::Spec, Some(&json!(spec).to_string()));
    db.set_job(pid, JobColumn::Question, None);
    db.set_job(pid, JobColumn::State, Some("queued"));
    db.set_expiry("job", pid, crate::auth::now() + WAITING);
    Ok(json!({ "pid": pid, "state": "queued" }))
}

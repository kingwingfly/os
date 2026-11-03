//! The kernel's file system (owner's design, 2026-10-29: the page is user space, its requests
//! are system calls): what each call on names does, and who may, as Linux's VFS decides. One
//! function a call, each changing one name or one inode, or failing with an errno and changing
//! nothing; what walks a tree (rm -r, cp -r, chmod -R) is user space's, as on Linux.
//!
//! It keeps nothing itself: a store (`Fs`) holds the names, inodes and accounts. The Worker's
//! is SQLite in its Durable Object; tests use `MemStore`.
mod namei;
mod xattr;

use abi::{
    Call, Dirent, Errno, Error, O_ACCMODE, O_CREAT, O_DIRECTORY, O_EXCL, O_RDONLY, Stat, Time,
};
use serde_json::{Value, json};
use terminal_worker_core::parent;
use terminal_worker_core::permissions::*;

pub use namei::namei;

/// What a store keeps beyond names and inodes: the time, an inode's times, empty content for a
/// new file, and what has arrived of content still being written.
pub trait Fs: Store {
    /// Seconds since 1970, and nanoseconds past them.
    fn now(&self) -> (u64, u32);
    /// The inode `ino`'s times.
    fn times(&self, ino: u64) -> Times;
    /// Set its access and modification times, those given, as utimensat(2) does; its change
    /// time is now.
    fn set_times(&mut self, ino: u64, atime: Option<(u64, u32)>, mtime: Option<(u64, u32)>);
    /// New content, empty and whole, for a file `owner` makes at `path`: its id.
    fn empty(&mut self, owner: u32, path: &str) -> String;
    /// What has arrived of the content `file`, if it is still being written, and whether it is
    /// a recording.
    fn writing(&self, file: &str) -> Option<(u64, bool)>;
    /// What unlinking the device at `path` does, as its driver has it (rm of a presentation
    /// stops it); None for a name like any other.
    fn unlink_device(&mut self, _cred: &Identity, _path: &str) -> Option<Result<()>> {
        None
    }
}

/// The store in memory, for tests and tools: no clock, no times, every file whole but those
/// marked `incomplete`, of which nothing has arrived.
impl Fs for MemStore {
    fn now(&self) -> (u64, u32) {
        (0, 0)
    }
    fn times(&self, _ino: u64) -> Times {
        Times::default()
    }
    fn set_times(&mut self, _ino: u64, _atime: Option<(u64, u32)>, _mtime: Option<(u64, u32)>) {}
    fn empty(&mut self, _owner: u32, path: &str) -> String {
        format!("empty:{path}")
    }
    fn writing(&self, file: &str) -> Option<(u64, bool)> {
        self.incomplete.contains(file).then_some((0, false))
    }
}

/// An inode's times, each seconds since 1970 and nanoseconds past them: when it was last read
/// (as far as anything says), when its content changed, and when anything of it did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Times {
    pub atime: (u64, u32),
    pub mtime: (u64, u32),
    pub ctime: (u64, u32),
}

/// What a call runs as: an account (root under sudo), and the process's umask.
#[derive(Clone, Debug)]
pub struct Process {
    pub cred: Identity,
    pub umask: u16,
}

type Result<T> = std::result::Result<T, Error>;

/// Run the call `call` for `process`: its value, or its error. Getcreds is the host's, which
/// knows the session.
pub fn call(fs: &mut impl Fs, process: &Process, call: Call) -> Result<Value> {
    let cred = &process.cred;
    match call {
        // The session's, and descriptors' content, are the host's.
        Call::Getcreds
        | Call::Open { .. }
        | Call::Close { .. }
        | Call::Pread { .. }
        | Call::Pwrite { .. }
        | Call::Statfs { .. }
        | Call::InotifyAddWatch { .. }
        | Call::InotifyRmWatch { .. }
        | Call::Ioctl { .. }
        | Call::Spawn { .. }
        | Call::Kill { .. }
        | Call::Wait { .. }
        | Call::Login { .. }
        | Call::Logout
        | Call::Sudo { .. }
        | Call::Passwd { .. }
        | Call::Useradd { .. }
        | Call::Usermod { .. }
        | Call::Userdel { .. }
        | Call::Groupadd { .. }
        | Call::Groupmod { .. }
        | Call::Groupdel { .. } => Err(Errno::ENOSYS.into()),
        Call::Stat { path } => stat(fs, cred, &path, true).map(|stat| json!(stat)),
        Call::Lstat { path } => stat(fs, cred, &path, false).map(|stat| json!(stat)),
        Call::Getdents {
            path,
            cookie,
            count,
        } => getdents(fs, cred, &path).map(|entries| {
            let entries = entries.into_iter().skip(cookie as usize);
            json!(
                entries
                    .take(count.unwrap_or(u64::MAX) as usize)
                    .collect::<Vec<_>>()
            )
        }),
        Call::Access { path, mode } => access(fs, cred, &path, mode).map(|()| Value::Null),
        Call::Readlink { path } => readlink(fs, cred, &path).map(Value::String),
        Call::Mkdir { path, mode } => mkdir(fs, process, &path, mode).map(|()| Value::Null),
        // A device is its driver's to make (the host's).
        Call::Mknod { rdev: Some(_), .. } => Err(Errno::ENOSYS.into()),
        Call::Mknod { path, mode, .. } => mknod(fs, process, &path, mode).map(|()| Value::Null),
        Call::Rmdir { path } => rmdir(fs, cred, &path).map(|()| Value::Null),
        Call::Unlink { path } => unlink(fs, cred, &path).map(|()| Value::Null),
        Call::Rename {
            from,
            to,
            noreplace,
        } => rename(fs, cred, &from, &to, noreplace).map(|()| Value::Null),
        Call::Link { from, to, follow } => link(fs, cred, &from, &to, follow).map(|()| Value::Null),
        Call::Symlink { target, path } => symlink(fs, cred, &target, &path).map(|()| Value::Null),
        Call::Chmod { path, mode } => chmod(fs, cred, &path, mode).map(|()| Value::Null),
        Call::Chown {
            path,
            uid,
            gid,
            nofollow,
        } => chown(fs, cred, &path, uid, gid, !nofollow).map(|()| Value::Null),
        Call::Utimens {
            path,
            atime,
            mtime,
            nofollow,
        } => utimens(fs, cred, &path, atime, mtime, !nofollow).map(|()| Value::Null),
        Call::Getxattr {
            path,
            name,
            nofollow,
        } => xattr::get(fs, cred, &path, &name, !nofollow).map(|value| json!(abi::Bytes(value))),
        Call::Setxattr {
            path,
            name,
            value,
            flags,
            nofollow,
        } => xattr::set(fs, cred, &path, &name, &value, flags, !nofollow).map(|()| Value::Null),
        Call::Listxattr { path, nofollow } => {
            xattr::list(fs, cred, &path, !nofollow).map(|names| json!(names))
        }
        Call::Removexattr {
            path,
            name,
            nofollow,
        } => xattr::remove(fs, cred, &path, &name, !nofollow).map(|()| Value::Null),
    }
}

/// Whether `cred` may `mask` (READ, WRITE, EXEC) the node, as Linux's generic_permission
/// decides: its mode and ACL say (`Identity::allows`); root may anything, but execute only
/// what someone may.
pub fn permission(cred: &Identity, node: &Node, mask: u16) -> bool {
    if cred.id == 0 {
        return mask & EXEC == 0 || node.directory || node.mode & 0o111 != 0;
    }
    cred.allows(node, mask)
}
fn require(cred: &Identity, node: &Node, mask: u16) -> Result<()> {
    if permission(cred, node, mask) {
        Ok(())
    } else {
        Err(Errno::EACCES.into())
    }
}

/// What stat(2) tells of `node`, named `path`.
pub fn stat_of(fs: &impl Fs, node: &Node) -> Stat {
    let kind = if node.directory {
        abi::S_IFDIR
    } else if node.is_link() {
        abi::S_IFLNK
    } else if node.is_device() {
        abi::S_IFCHR
    } else {
        abi::S_IFREG
    };
    let times = fs.times(node.ino);
    let writing =
        node.file
            .as_deref()
            .and_then(|file| fs.writing(file))
            .map(|(received, recording)| abi::Writing {
                received,
                recording,
            });
    Stat {
        ino: node.ino,
        mode: kind | u32::from(node.mode & 0o7777),
        nlink: node.links,
        uid: node.owner,
        gid: node.group,
        user: fs.username(node.owner),
        group: fs.groupname(node.group),
        size: node.size,
        mtime: times.mtime.0,
        mtime_nsec: times.mtime.1,
        ctime: times.ctime.0,
        ctime_nsec: times.ctime.1,
        atime: times.atime.0,
        atime_nsec: times.atime.1,
        link: node.link.clone(),
        rdev: node.rdev.clone(),
        acl: node.acl.is_some(),
        writing,
    }
}

/// The node at `path`, which must be there.
fn existing(fs: &impl Fs, cred: &Identity, path: &str, follow: bool) -> Result<(String, Node)> {
    let name = namei(fs, cred, path, follow)?;
    let node = name.node.ok_or(Errno::ENOENT)?;
    Ok((name.path, node))
}

pub fn stat(fs: &impl Fs, cred: &Identity, path: &str, follow: bool) -> Result<Stat> {
    let (_, node) = existing(fs, cred, path, follow)?;
    Ok(stat_of(fs, &node))
}

/// The entries of the directory `path`, which `cred` may read, each with its lstat if `cred`
/// may search it too.
pub fn getdents(fs: &impl Fs, cred: &Identity, path: &str) -> Result<Vec<Dirent>> {
    let (real, dir) = existing(fs, cred, path, true)?;
    if !dir.directory {
        return Err(Errno::ENOTDIR.into());
    }
    require(cred, &dir, READ)?;
    let searchable = permission(cred, &dir, EXEC);
    Ok(fs
        .children(&real)
        .into_iter()
        .map(|(child, node)| Dirent {
            name: child.rsplit('/').next().unwrap_or_default().to_string(),
            stat: searchable.then(|| stat_of(fs, &node)),
        })
        .collect())
}

pub fn access(fs: &impl Fs, cred: &Identity, path: &str, mode: u16) -> Result<()> {
    let (_, node) = existing(fs, cred, path, true)?;
    require(cred, &node, mode & 7)
}

pub fn readlink(fs: &impl Fs, cred: &Identity, path: &str) -> Result<String> {
    let (_, node) = existing(fs, cred, path, false)?;
    node.link.ok_or_else(|| Errno::EINVAL.into())
}

/// The last part of `path` as written: `.` and `..` name no new entry.
fn last(path: &str) -> &str {
    path.trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or_default()
}

/// Whether the last part of `path` is `.` or `..`, once the directory it is in is found to be
/// there, as Linux resolves that directory before it looks at the last part.
fn dots(fs: &impl Fs, cred: &Identity, path: &str) -> Result<bool> {
    if !matches!(last(path), "." | "..") {
        return Ok(false);
    }
    let above = match path.trim_end_matches('/').rsplit_once('/') {
        Some(("", _)) | None => "/",
        Some((above, _)) => above,
    };
    match namei(fs, cred, above, true)?.node {
        Some(node) if node.directory => Ok(true),
        Some(_) => Err(Errno::ENOTDIR.into()),
        None => Err(Errno::ENOENT.into()),
    }
}

/// Where a new name `path` goes: the directory, which `cred` may write and search, and the
/// name, which must be free. A home not made yet is its account's to make, or root's: no one
/// else takes its name, as anyone could in /guest, which everyone may write in.
fn creating(fs: &impl Fs, cred: &Identity, path: &str) -> Result<(String, Node)> {
    if last(path).is_empty() || dots(fs, cred, path)? {
        return Err(Errno::EEXIST.into());
    }
    let name = namei(fs, cred, path, false)?;
    if name.node.is_some() {
        return Err(Errno::EEXIST.into());
    }
    let dir = writable_dir(fs, cred, &name.path)?;
    Ok((name.path, dir))
}
/// The directory a new name `real` goes in, which `cred` may write and search, unless the name
/// is a home not made yet, and not `cred`'s.
fn writable_dir(fs: &impl Fs, cred: &Identity, real: &str) -> Result<Node> {
    let dir = fs.node(parent(real)).ok_or(Errno::ENOENT)?;
    require(cred, &dir, WRITE | EXEC)?;
    if cred.id != 0 && fs.home_of(real).is_some_and(|owner| owner != cred.id) {
        return Err(Error::because(
            Errno::EACCES,
            format!("{real} is another account's home"),
        ));
    }
    Ok(dir)
}

/// What open(2) found at a path: the node a descriptor reads or writes, or the regular file
/// `O_CREAT` makes, which the host makes once it has content for it.
#[derive(Clone, Debug)]
pub enum Opening {
    Existing { path: String, node: Node },
    New { path: String, node: Node },
}
/// open(2)'s checks: a link at the end is followed, and one leading nowhere makes what it
/// names, except with `O_CREAT | O_EXCL`, which fails on anything there; a directory is opened
/// only to read (EISDIR otherwise), and `O_DIRECTORY` opens nothing else (ENOTDIR); what is
/// there must be readable, or writable, as `flags` ask. What it makes has `mode` less the
/// umask, as mknod does.
pub fn open(fs: &impl Fs, process: &Process, path: &str, flags: u32, mode: u16) -> Result<Opening> {
    let cred = &process.cred;
    let write = flags & O_ACCMODE != O_RDONLY;
    let exclusive = flags & O_CREAT != 0 && flags & O_EXCL != 0;
    let name = namei(fs, cred, path, !exclusive)?;
    match name.node {
        Some(_) if exclusive => Err(Errno::EEXIST.into()),
        Some(node) if flags & O_DIRECTORY != 0 && !node.directory => Err(Errno::ENOTDIR.into()),
        Some(node) if node.directory && write => Err(Errno::EISDIR.into()),
        None if flags & O_DIRECTORY != 0 => Err(Errno::ENOENT.into()),
        Some(node) => {
            require(cred, &node, if write { WRITE } else { READ })?;
            Ok(Opening::Existing {
                path: name.path,
                node,
            })
        }
        None if flags & O_CREAT == 0 => Err(Errno::ENOENT.into()),
        None if path.ends_with('/') => Err(Errno::EISDIR.into()),
        None => {
            let dir = writable_dir(fs, cred, &name.path)?;
            let node = created(cred, &dir, mode & 0o777, false, process.umask);
            Ok(Opening::New {
                path: name.path,
                node,
            })
        }
    }
}

pub fn mkdir(fs: &mut impl Fs, process: &Process, path: &str, mode: u16) -> Result<()> {
    let (real, dir) = creating(fs, &process.cred, path)?;
    let mut node = created(&process.cred, &dir, mode, true, process.umask);
    // mkdir(2) keeps the sticky bit asked for.
    node.mode |= mode & !process.umask & 0o1000;
    fs.set_node(&real, &node);
    Ok(())
}

/// A regular file, empty, as mknod(2) with S_IFREG, or open(2) with O_CREAT, makes one.
pub fn mknod(fs: &mut impl Fs, process: &Process, path: &str, mode: u16) -> Result<()> {
    let (real, dir) = creating(fs, &process.cred, path)?;
    let mut node = created(&process.cred, &dir, mode, false, process.umask);
    node.file = Some(fs.empty(process.cred.id, &real));
    fs.set_node(&real, &node);
    Ok(())
}

/// Whether `cred` may take the name `path`, of `node`, out of its directory, which it may
/// write: in a sticky one, only its owner, the directory's owner and root may.
fn unlinkable(fs: &impl Fs, cred: &Identity, path: &str, node: &Node) -> Result<()> {
    let dir = fs.node(parent(path)).ok_or(Errno::ENOENT)?;
    require(cred, &dir, WRITE | EXEC)?;
    if dir.mode & STICKY != 0 && cred.id != 0 && cred.id != node.owner && cred.id != dir.owner {
        return Err(Errno::EPERM.into());
    }
    Ok(())
}

pub fn rmdir(fs: &mut impl Fs, cred: &Identity, path: &str) -> Result<()> {
    if last(path).is_empty() {
        return Err(Errno::EBUSY.into());
    }
    if dots(fs, cred, path)? {
        let errno = if last(path) == "." {
            Errno::EINVAL
        } else {
            Errno::ENOTEMPTY
        };
        return Err(errno.into());
    }
    // As Linux's may_delete has it: whether the name may go, before what it names.
    let (real, node) = existing(fs, cred, path, false)?;
    unlinkable(fs, cred, &real, &node)?;
    if !node.directory {
        return Err(Errno::ENOTDIR.into());
    }
    if !fs.children(&real).is_empty() {
        return Err(Errno::ENOTEMPTY.into());
    }
    fs.delete_node(&real);
    Ok(())
}

pub fn unlink(fs: &mut impl Fs, cred: &Identity, path: &str) -> Result<()> {
    if last(path).is_empty() || dots(fs, cred, path)? {
        return Err(Errno::EISDIR.into());
    }
    let (real, node) = existing(fs, cred, path, false)?;
    if let Some(done) = fs.unlink_device(cred, &real) {
        return done;
    }
    unlinkable(fs, cred, &real, &node)?;
    if node.directory {
        return Err(Errno::EISDIR.into());
    }
    fs.delete_node(&real);
    Ok(())
}

/// rename(2): both directories need w+x, and a directory moving to another needs w itself (its
/// `..` changes); in a sticky directory, only the owner of what is moved or replaced, the
/// directory's, or root may. What is at `to` is replaced: a file by a file, an empty directory
/// by a directory; with `noreplace`, nothing is.
pub fn rename(
    fs: &mut impl Fs,
    cred: &Identity,
    from: &str,
    to: &str,
    noreplace: bool,
) -> Result<()> {
    if last(from).is_empty() || last(to).is_empty() || dots(fs, cred, from)? || dots(fs, cred, to)?
    {
        return Err(Errno::EBUSY.into());
    }
    let (source, node) = existing(fs, cred, from, false)?;
    // A device's name is its driver's, which knows it by it.
    if node.is_device() {
        return Err(Error::because(
            Errno::EPERM,
            "a device stays where its driver made it",
        ));
    }
    let target = namei(fs, cred, to, false)?;
    let dir = fs.node(parent(&target.path)).ok_or(Errno::ENOENT)?;
    require(cred, &dir, WRITE | EXEC)?;
    unlinkable(fs, cred, &source, &node)?;
    if target.path == source {
        return Ok(());
    }
    if target.path.starts_with(&format!("{source}/")) {
        return Err(Errno::EINVAL.into());
    }
    if node.directory && parent(&source) != parent(&target.path) {
        require(cred, &node, WRITE)?;
    }
    // A directory an account's home is, or is in, stays, as a mount point in use does.
    if node.directory {
        let below = format!("{source}/");
        if let Some((name, _)) = fs
            .users()
            .into_iter()
            .find(|(_, user)| user.home == source || user.home.starts_with(&below))
        {
            return Err(Error::because(
                Errno::EBUSY,
                format!(
                    "{source} holds the home of {name}; move homes with usermod -d HOME -m {name}"
                ),
            ));
        }
    }
    if let Some(existing) = &target.node {
        if existing.ino == node.ino {
            return Ok(());
        }
        if noreplace {
            return Err(Errno::EEXIST.into());
        }
        match (node.directory, existing.directory) {
            (true, false) => return Err(Errno::ENOTDIR.into()),
            (false, true) => return Err(Errno::EISDIR.into()),
            (true, true) if !fs.children(&target.path).is_empty() => {
                return Err(Errno::ENOTEMPTY.into());
            }
            _ => {}
        }
        unlinkable(fs, cred, &target.path, existing)?;
    } else if cred.id != 0
        && fs
            .home_of(&target.path)
            .is_some_and(|owner| owner != cred.id)
    {
        return Err(Error::because(
            Errno::EACCES,
            format!("{} is another account's home", target.path),
        ));
    }
    if target.node.is_some() {
        fs.delete_node(&target.path);
    }
    // The new names first, so that nothing is ever without one.
    let moved = fs.subtree(&source);
    for (path, node) in &moved {
        fs.set_node(&format!("{}{}", target.path, &path[source.len()..]), node);
    }
    for (path, _) in moved.iter().rev() {
        fs.delete_node(path);
    }
    Ok(())
}

/// link(2): another name for what `from` names (a link as itself, unless `follow`), not a
/// directory. Without owning it, as Linux's protected_hardlinks has it, only a regular file one
/// may read and write, and not setuid, nor setgid and group-executable.
pub fn link(fs: &mut impl Fs, cred: &Identity, from: &str, to: &str, follow: bool) -> Result<()> {
    let (_, node) = existing(fs, cred, from, follow)?;
    if node.directory || node.is_device() {
        return Err(Errno::EPERM.into());
    }
    if node.file.as_deref().is_some_and(|id| fs.uploading(id)) {
        return Err(Error::because(
            Errno::EBUSY,
            format!("{from} is still uploading; link it once it completes"),
        ));
    }
    let (real, _) = creating(fs, cred, to)?;
    if cred.id != 0 && cred.id != node.owner {
        let safe = node.is_file()
            && node.mode & SETUID == 0
            && !(node.mode & SETGID != 0 && node.mode & 0o010 != 0)
            && permission(cred, &node, READ | WRITE);
        if !safe {
            return Err(Errno::EPERM.into());
        }
    }
    fs.set_node(&real, &node);
    Ok(())
}

/// symlink(2): a link at `path` to `target`, which need not exist.
pub fn symlink(fs: &mut impl Fs, cred: &Identity, target: &str, path: &str) -> Result<()> {
    if target.is_empty() {
        return Err(Errno::ENOENT.into());
    }
    if target.len() > abi::PATH_MAX {
        return Err(Errno::ENAMETOOLONG.into());
    }
    if target.contains('\0') {
        return Err(Errno::EINVAL.into());
    }
    let (real, dir) = creating(fs, cred, path)?;
    let group = if dir.mode & SETGID != 0 {
        dir.group
    } else {
        cred.group
    };
    fs.set_node(&real, &Node::symlink(cred.id, group, target));
    Ok(())
}

/// chmod(2): its owner's or root's. Without root, setgid needs the node's group to be one of
/// the caller's: it is cleared otherwise, without an error, as Linux does.
pub fn chmod(fs: &mut impl Fs, cred: &Identity, path: &str, mode: u16) -> Result<()> {
    let (real, mut node) = existing(fs, cred, path, true)?;
    if cred.id != 0 && cred.id != node.owner {
        return Err(Errno::EPERM.into());
    }
    node.mode = mode & 0o7777;
    if cred.id != 0 && !cred.groups.contains(&node.group) {
        node.mode &= !SETGID;
    }
    fs.set_node(&real, &node);
    Ok(())
}

/// chown(2), lchown(2) without `follow`: root's; an owner may change the group to one of its
/// own. Changing who owns a regular file clears its setuid bit, and its setgid bit if its
/// group may execute it.
pub fn chown(
    fs: &mut impl Fs,
    cred: &Identity,
    path: &str,
    uid: Option<u32>,
    gid: Option<u32>,
    follow: bool,
) -> Result<()> {
    let (real, mut node) = existing(fs, cred, path, follow)?;
    if cred.id != 0
        && (cred.id != node.owner
            || uid.is_some_and(|id| id != node.owner)
            || gid.is_some_and(|g| !cred.groups.contains(&g)))
    {
        return Err(Errno::EPERM.into());
    }
    if let Some(id) = uid {
        node.owner = id;
    }
    if let Some(id) = gid {
        node.group = id;
    }
    if node.is_file() && (uid.is_some() || gid.is_some()) {
        node.mode &= !SETUID;
        if node.mode & 0o010 != 0 {
            node.mode &= !SETGID;
        }
    }
    fs.set_node(&real, &node);
    Ok(())
}

/// utimensat(2): times set to now need the owner, root, or whoever may write it; a time given,
/// the owner or root, as Linux's setattr asks.
pub fn utimens(
    fs: &mut impl Fs,
    cred: &Identity,
    path: &str,
    atime: Time,
    mtime: Time,
    follow: bool,
) -> Result<()> {
    let (_, node) = existing(fs, cred, path, follow)?;
    if atime == Time::Omit && mtime == Time::Omit {
        return Ok(());
    }
    let owner = cred.id == 0 || cred.id == node.owner;
    let given = |time| matches!(time, Time::At { .. });
    if (given(atime) || given(mtime)) && !owner {
        return Err(Errno::EPERM.into());
    }
    if !owner && !permission(cred, &node, WRITE) {
        return Err(Errno::EACCES.into());
    }
    let now = fs.now();
    let at = |time| match time {
        Time::Now => Some(now),
        Time::Omit => None,
        Time::At { sec, nsec } => Some((sec, nsec.min(999_999_999))),
    };
    fs.set_times(node.ino, at(atime), at(mtime));
    Ok(())
}

#[cfg(test)]
mod tests;

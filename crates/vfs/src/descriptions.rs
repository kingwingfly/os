//! Open file descriptions a kernel keeps for its processes, over one driver (#48), until the
//! mount table and per-process descriptor tables move into the portable kernel (#51, #54).
//!
//! A process host (the browser's process Workers) numbers its descriptors itself; the kernel
//! keeps the descriptions they refer to, by [`Id`], with the processes that hold each. A process
//! holds a description once however many of its descriptors refer to it; a fork's child holds
//! what its parent held; exec keeps what the process held. When the last holder lets go, or
//! exits, the description closes and the driver's open reference is released.
//!
//! [`Descriptions::open`] resolves an absolute path within the driver itself, as the client's
//! walk does (contract §2.3): one [`Filesystem::walk`] per run of names, `..` against the
//! directories it came through, symbolic links read and followed here (at most
//! [`abi::MAXSYMLINKS`]). A path that leaves the driver (another mount, a tree the driver does
//! not serve) is not resolved here at all: the caller's `inside` says which paths are the
//! driver's, and anything else answers `None`, for the caller's other paths to serve.
use crate::{
    Cred, Entry, Filesystem, Handle, Metadata, OpenOptions, ReleaseQueue, Result, Stop,
    check_component, file::FileRef,
};
use abi::Errno;
use os_core::inode::may_follow_link as allowed_link;
use os_core::permissions::Node;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;

/// A description's number, unique for the life of the kernel.
pub type Id = u64;

/// What a path names, as [`Descriptions::resolve`] finds it.
#[derive(Debug)]
pub enum Resolved {
    /// An existing object, named `name` in `parent`.
    Found {
        parent: Handle,
        name: String,
        entry: Entry,
    },
    /// Nothing, yet: `name` would be made in `parent`.
    Missing { parent: Handle, name: String },
    /// A directory reached by `..` or `.` (or the root itself), with no last name.
    Directory(Handle),
}

/// A description just opened: its number, and what it refers to.
pub struct Opened {
    pub id: Id,
    pub file: FileRef,
    pub entry: Entry,
}

struct Held {
    file: FileRef,
    holders: BTreeMap<u32, usize>,
}

pub struct Descriptions {
    fs: Rc<dyn Filesystem>,
    releases: ReleaseQueue,
    next: Rc<Cell<Id>>,
    files: RefCell<BTreeMap<Id, Held>>,
}

/// The names of `path`, with empty ones (`//`) dropped.
fn names(path: &str) -> impl DoubleEndedIterator<Item = String> + '_ {
    path.split('/')
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

struct Frame {
    handle: Handle,
    path: String,
    metadata: Option<Metadata>,
    searchable: bool,
}

async fn ensure_searchable(fs: &Rc<dyn Filesystem>, cred: &Cred, frame: &mut Frame) -> Result<()> {
    if !frame.searchable {
        // Probe with a valid component name so drivers with ACLs or server-side identity
        // evaluate search permission (`EXEC`) on `frame.handle` using their real authority.
        fs.walk(cred, &frame.handle, &["_".to_string()]).await?;
        frame.searchable = true;
    }
    Ok(())
}

async fn ensure_metadata<'a>(
    fs: &Rc<dyn Filesystem>,
    cred: &Cred,
    frame: &'a mut Frame,
) -> Result<&'a Metadata> {
    if frame.metadata.is_none() {
        frame.metadata = Some(fs.metadata(cred, &frame.handle).await?);
    }
    Ok(frame.metadata.as_ref().expect("populated metadata"))
}

pub fn may_follow_link(cred: &Cred, dir: &Metadata, link: &Metadata) -> bool {
    let dir_node = Node::directory(dir.uid, dir.gid, dir.mode);
    let link_node = Node::symlink(link.uid, link.gid, "");
    allowed_link(&cred.identity, &dir_node, &link_node)
}

impl Descriptions {
    pub fn new(fs: Rc<dyn Filesystem>) -> Self {
        Self::with_id_source(fs, Rc::new(Cell::new(1)))
    }
    /// Construct a table sharing a monotonic ID counter so IDs never alias across reconnects.
    pub fn with_id_source(fs: Rc<dyn Filesystem>, next: Rc<Cell<Id>>) -> Self {
        Self {
            fs,
            releases: ReleaseQueue::new(),
            next,
            files: RefCell::new(BTreeMap::new()),
        }
    }
    pub fn fs(&self) -> &Rc<dyn Filesystem> {
        &self.fs
    }
    /// How many descriptions are open.
    pub fn len(&self) -> usize {
        self.files.borrow().len()
    }
    pub fn is_empty(&self) -> bool {
        self.files.borrow().is_empty()
    }

    /// Resolve the absolute `path` from the driver's root, following a last symbolic link only
    /// if `follow`. `None` if the path leaves the paths `inside` accepts (each prefix of it as
    /// resolved, an absolute path, is asked).
    pub async fn resolve(
        &self,
        cred: &Cred,
        path: &str,
        follow: bool,
        inside: &dyn Fn(&str) -> bool,
    ) -> Result<Option<Resolved>> {
        if !path.starts_with('/') {
            return Err(Errno::EINVAL);
        }
        if path.len() > abi::PATH_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        // Each directory came through, with its path; the root's is "".
        let mut stack = vec![Frame {
            handle: self.fs.root(),
            path: String::new(),
            metadata: None,
            searchable: false,
        }];
        let mut queue: VecDeque<String> = names(path).collect();
        // A trailing slash asks for a directory: the last name is followed, as Linux does.
        let mut directory = path.ends_with('/') && queue.back().is_some();
        let mut links = 0;
        'walk: loop {
            match queue.front().map(String::as_str) {
                None => return Ok(Some(Resolved::Directory(stack.pop().expect("root").handle))),
                Some(".") => {
                    ensure_searchable(&self.fs, cred, stack.last_mut().expect("root")).await?;
                    queue.pop_front();
                    continue;
                }
                Some("..") => {
                    ensure_searchable(&self.fs, cred, stack.last_mut().expect("root")).await?;
                    queue.pop_front();
                    if stack.len() > 1 {
                        stack.pop();
                    }
                    continue;
                }
                Some(_) => {}
            }
            // The run of plain names from here, as far as the driver serves them.
            let base = stack.last().expect("root").path.clone();
            let mut run = Vec::new();
            let mut at = base;
            while let Some(name) = queue.front() {
                if name == "." || name == ".." {
                    break;
                }
                check_component(name)?;
                let next = format!("{at}/{name}");
                if !inside(&next) {
                    if run.is_empty() {
                        return Ok(None);
                    }
                    break;
                }
                at = next;
                run.push(queue.pop_front().expect("front"));
            }
            let dir = stack.last().expect("root").handle.clone();
            let walked = self.fs.walk(cred, &dir, &run).await?;
            // Stepping into `run[0]` succeeded, so `dir` passed search permission.
            stack.last_mut().expect("root").searchable = true;
            for (index, entry) in walked.entries.into_iter().enumerate() {
                let name = &run[index];
                let last = index + 1 == run.len() && queue.is_empty();
                if entry.metadata.is_symlink() && (!last || follow || directory) {
                    let parent_meta =
                        ensure_metadata(&self.fs, cred, stack.last_mut().expect("root")).await?;
                    if !may_follow_link(cred, parent_meta, &entry.metadata) {
                        return Err(Errno::EACCES);
                    }
                    links += 1;
                    if links > abi::MAXSYMLINKS {
                        return Err(Errno::ELOOP);
                    }
                    let target = self.fs.read_link(cred, &entry.handle).await?;
                    if target.is_empty() {
                        return Err(Errno::ENOENT);
                    }
                    for rest in run[index + 1..].iter().rev() {
                        queue.push_front(rest.clone());
                    }
                    for name in names(&target).rev() {
                        queue.push_front(name);
                    }
                    if target.starts_with('/') {
                        stack.truncate(1);
                    }
                    if target.ends_with('/') && last {
                        directory = true;
                    }
                    continue 'walk;
                }
                if last {
                    if directory && !entry.metadata.is_dir() {
                        return Err(Errno::ENOTDIR);
                    }
                    let parent = stack.pop().expect("root").handle;
                    return Ok(Some(Resolved::Found {
                        parent,
                        name: name.clone(),
                        entry,
                    }));
                }
                if !entry.metadata.is_dir() {
                    return Err(Errno::ENOTDIR);
                }
                let path = format!("{}/{name}", stack.last().expect("root").path);
                stack.push(Frame {
                    handle: entry.handle,
                    path,
                    metadata: Some(entry.metadata),
                    searchable: index + 1 < run.len(),
                });
            }
            match walked.stop {
                Some(Stop::Missing(index)) if index + 1 == run.len() && queue.is_empty() => {
                    let parent = stack.pop().expect("root").handle;
                    return Ok(Some(Resolved::Missing {
                        parent,
                        name: run[index].clone(),
                    }));
                }
                Some(Stop::Missing(_)) => return Err(Errno::ENOENT),
                Some(Stop::NotDirectory(_)) => return Err(Errno::ENOTDIR),
                // Every symbolic link the walk stopped at was among its entries, above.
                Some(Stop::Symlink(_)) => return Err(Errno::EIO),
                // Resolved the whole run; a name the driver does not serve, next, answers None
                // at the top of the loop.
                None => {}
            }
        }
    }

    /// open(2) of a regular file at `path` by `pid`, as `options` say (`O_CREAT` with `mode`,
    /// `O_EXCL`, `O_TRUNC`, the access, `O_APPEND`). `None` for anything this table does not
    /// keep: a path outside the driver, a directory, a device. With `O_EXCL` a last symbolic
    /// link is not followed (EEXIST), as on Linux; without it, a dangling one is created at
    /// its target.
    pub async fn open(
        &self,
        pid: u32,
        cred: &Cred,
        path: &str,
        options: &OpenOptions,
        mode: u16,
        inside: &dyn Fn(&str) -> bool,
    ) -> Result<Option<Opened>> {
        self.open_with(pid, cred, path, options, mode, false, false, inside)
            .await
    }

    /// Like [`Descriptions::open`], additionally enforcing `O_NOFOLLOW` and `O_DIRECTORY`.
    #[allow(clippy::too_many_arguments)]
    pub async fn open_with(
        &self,
        pid: u32,
        cred: &Cred,
        path: &str,
        options: &OpenOptions,
        mode: u16,
        nofollow: bool,
        directory: bool,
        inside: &dyn Fn(&str) -> bool,
    ) -> Result<Option<Opened>> {
        let access = options.access()?;
        let is_path = access == abi::fs::Access::Path;
        let dir_disallowed =
            !is_path && (options.is_truncate() || access.writes() || options.is_create());
        let follow = !options.is_create_new() && !nofollow;
        let resolved = self.resolve(cred, path, follow, inside).await?;
        let (handle, open, entry) = match resolved {
            None => return Ok(None),
            Some(Resolved::Directory(_)) => {
                if dir_disallowed {
                    return Err(Errno::EISDIR);
                }
                return Ok(None);
            }
            Some(Resolved::Found { entry, .. }) => {
                if options.is_create_new() {
                    return Err(Errno::EEXIST);
                }
                if nofollow && !is_path && entry.metadata.is_symlink() {
                    return Err(Errno::ELOOP);
                }
                if entry.metadata.is_dir() {
                    if dir_disallowed {
                        return Err(Errno::EISDIR);
                    }
                    return Ok(None);
                }
                if directory {
                    return Err(Errno::ENOTDIR);
                }
                if !entry.metadata.is_file() {
                    return Ok(None);
                }
                let open = self.fs.open(cred, &entry.handle, options).await?;
                (entry.handle.clone(), open, entry)
            }
            Some(Resolved::Missing { parent, name }) => {
                if directory {
                    return Err(if options.is_create() {
                        Errno::EINVAL
                    } else {
                        Errno::ENOENT
                    });
                }
                if !options.is_create() {
                    return Err(Errno::ENOENT);
                }
                if path.ends_with('/') {
                    return Err(Errno::EISDIR);
                }
                let (entry, open) = self.fs.create(cred, &parent, &name, mode, options).await?;
                (entry.handle.clone(), open, entry)
            }
        };
        let file = FileRef::new(
            self.fs.clone(),
            open,
            handle,
            cred.clone(),
            options,
            &self.releases,
        );
        let id = self.next.get();
        self.next.set(id + 1);
        self.files.borrow_mut().insert(
            id,
            Held {
                file: file.clone(),
                holders: BTreeMap::from([(pid, 1)]),
            },
        );
        Ok(Some(Opened { id, file, entry }))
    }

    /// The description `id`, which `pid` must hold (EBADF otherwise).
    pub fn get(&self, pid: u32, id: Id) -> Result<FileRef> {
        let files = self.files.borrow();
        let held = files.get(&id).ok_or(Errno::EBADF)?;
        if !held.holders.contains_key(&pid) {
            return Err(Errno::EBADF);
        }
        Ok(held.file.clone())
    }

    /// fork(2): `child` holds the descriptions `ids` its parent `pid` holds, before it runs.
    /// Nothing changes unless the parent holds every one.
    pub fn inherit(&self, pid: u32, child: u32, ids: &[Id]) -> Result<()> {
        let mut files = self.files.borrow_mut();
        if ids.iter().any(|id| {
            files
                .get(id)
                .is_none_or(|held| !held.holders.contains_key(&pid))
        }) {
            return Err(Errno::EBADF);
        }
        for id in ids {
            let held = files.get_mut(id).expect("checked");
            *held.holders.entry(child).or_default() += 1;
        }
        Ok(())
    }

    /// close(2) of the last of `pid`'s descriptors of `id`: if no process holds it any more,
    /// the description closes, and the driver's release is close's answer.
    pub async fn close(&self, pid: u32, id: Id) -> Result<()> {
        let last = {
            let mut files = self.files.borrow_mut();
            let held = files.get_mut(&id).ok_or(Errno::EBADF)?;
            let count = held.holders.get_mut(&pid).ok_or(Errno::EBADF)?;
            *count -= 1;
            if *count == 0 {
                held.holders.remove(&pid);
            }
            if held.holders.is_empty() {
                files.remove(&id).map(|held| held.file)
            } else {
                None
            }
        };
        match last {
            Some(file) => file.close().await,
            None => Ok(()),
        }
    }

    /// exit(2), or a process ended outright: what `pid` held, it lets go; the descriptions no
    /// process holds any more close, their errors unreported (their releases stay queued for
    /// [`Descriptions::flush`] if they fail).
    pub async fn exit(&self, pid: u32) {
        let closing: Vec<FileRef> = {
            let mut files = self.files.borrow_mut();
            let ids: Vec<Id> = files
                .iter_mut()
                .filter_map(|(id, held)| {
                    held.holders.remove(&pid)?;
                    held.holders.is_empty().then_some(*id)
                })
                .collect();
            ids.into_iter()
                .filter_map(|id| files.remove(&id).map(|held| held.file))
                .collect()
        };
        for file in closing {
            if file.close().await.is_err() {
                // A failed release is retried by the driver's own cleanup queue.
            }
        }
    }

    /// The releases owed by descriptions whose last reference was dropped while a call was
    /// still in progress.
    pub async fn flush(&self) -> Result<()> {
        self.releases.flush().await
    }
}

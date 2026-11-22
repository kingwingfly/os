//! An in-memory filesystem with Linux semantics: the reference the other drivers are tested
//! against (contract §3, every capability "yes"), and the instance's tmpfs (#51). Who may do
//! what is `os_core`'s, which the server's kernel applies too, so their answers agree:
//! `permissions` (owner/group/other, ACLs, setgid inheritance, umask and default ACLs),
//! `inode` (may_open, may_create, may_delete, the sticky rule, chmod, chown, utimensat,
//! protected hard links, symbolic link targets) and `xattr`.
//!
//! Inode numbers are never used again, so a handle's generation only has to say which filesystem
//! instance issued it. A file's content lives until its last name and its last open reference
//! are gone. Files are sparse, as on tmpfs: content is kept in pages, holes read as zeros, and
//! only the pages written count against the filesystem's capacity (`ENOSPC` past it).
//! Reads of files, directories and symlink targets use relatime: atime changes when it is no
//! newer than mtime or ctime, or its seconds field is at least 24 hours old. File reads at EOF
//! and zero-length reads count too, as on Linux tmpfs. Mount-specific atime flags belong to
//! the later mount layer; this driver currently uses the default policy.
//!
//! Devices are names here, not drivers: the client sends a device's I/O to its driver, and the
//! I/O calls of this filesystem refuse device open references (ENXIO).

use crate::{
    Access, BoxFuture, Conflict, Cred, DirEntry, Entry, FILE_MAX, FileType, Filesystem, FsId,
    Handle, LockFamily, LockKind, LockRange, Metadata, NodeId, OpenOptions, OpenRef, RenameFlags,
    Result, SetAttr, StatFs, Stop, Timespec, Walked, WriteAt, Written, XattrFlags, check_component,
    profiles,
};
use abi::Errno;
use abi::contract::FsCapabilities;
use os_core::acl::Entries;
use os_core::inode;
use os_core::permissions::{EXEC, Identity, Node, READ, WRITE, created};
use os_core::xattr::{self, Space};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

const ROOT: u64 = 1;
/// The unit content is kept and counted in.
const PAGE: usize = 4096;
const PAGE_BYTES: u64 = PAGE as u64;
/// The most one read or write moves, as Linux's `MAX_RW_COUNT`: a longer one is short.
const RW_MAX: usize = 0x7fff_f000;
/// The content a filesystem holds unless [`MemFs::with_capacity`] says otherwise, as tmpfs's
/// `size=`: 256 MiB.
pub const DEFAULT_CAPACITY: u64 = 256 << 20;

/// Seconds and nanoseconds since 1970. The kernel passes the host's clock; tests count.
pub type Clock = Box<dyn Fn() -> (u64, u32)>;

struct Inode {
    meta: Node,
    is_socket: bool,
    nlink: u32,
    /// A regular file's size, and the pages of its content written, by index: the rest reads as
    /// zeros, and every byte past the size is zero.
    size: u64,
    pages: BTreeMap<u64, Box<[u8; PAGE]>>,
    entries: BTreeMap<String, u64>,
    /// A directory's parent (the root's is itself) and its name there, which a directory has
    /// only one of.
    parent: u64,
    name: String,
    xattrs: BTreeMap<String, Vec<u8>>,
    atime: (u64, u32),
    mtime: (u64, u32),
    ctime: (u64, u32),
    opens: u32,
}
impl Inode {
    fn new(meta: Node, nlink: u32, parent: u64, name: &str, now: (u64, u32)) -> Self {
        Self {
            meta,
            is_socket: false,
            nlink,
            size: 0,
            pages: BTreeMap::new(),
            entries: BTreeMap::new(),
            parent,
            name: name.to_string(),
            xattrs: BTreeMap::new(),
            atime: now,
            mtime: now,
            ctime: now,
            opens: 0,
        }
    }
    fn file_type(&self) -> FileType {
        if self.meta.directory {
            FileType::Dir
        } else if self.meta.link.is_some() {
            FileType::Symlink
        } else if self.is_socket {
            FileType::Socket
        } else if self.meta.rdev.is_some() {
            FileType::CharDevice
        } else {
            FileType::File
        }
    }
    /// A directory removed while something still holds it.
    fn removed(&self) -> bool {
        self.nlink == 0
    }
    /// Read into `buf` from `offset`, holes as zeros; how much was read.
    fn read(&self, offset: u64, buf: &mut [u8]) -> usize {
        if offset >= self.size {
            return 0;
        }
        let len = usize::try_from(self.size - offset).map_or(buf.len(), |left| left.min(buf.len()));
        let mut done = 0;
        while done < len {
            let at = offset + done as u64;
            let within = (at % PAGE_BYTES) as usize;
            let n = (PAGE - within).min(len - done);
            match self.pages.get(&(at / PAGE_BYTES)) {
                Some(page) => buf[done..done + n].copy_from_slice(&page[within..within + n]),
                None => buf[done..done + n].fill(0),
            }
            done += n;
        }
        len
    }
    /// How many of `len` bytes at `offset` fit with `free` pages to add: all of them, or those
    /// before the first page that does not fit.
    fn fitting(&self, offset: u64, len: usize, mut free: u64) -> (usize, u64) {
        let end = offset + len as u64;
        let mut index = offset / PAGE_BYTES;
        let mut fits = offset;
        let mut added = 0;
        while fits < end {
            if !self.pages.contains_key(&index) {
                if free == 0 {
                    break;
                }
                free -= 1;
                added += 1;
            }
            index += 1;
            fits = (index * PAGE_BYTES).min(end);
        }
        ((fits - offset) as usize, added)
    }
    fn write(&mut self, offset: u64, data: &[u8]) {
        let mut done = 0;
        while done < data.len() {
            let at = offset + done as u64;
            let within = (at % PAGE_BYTES) as usize;
            let n = (PAGE - within).min(data.len() - done);
            let page = self
                .pages
                .entry(at / PAGE_BYTES)
                .or_insert_with(|| Box::new([0; PAGE]));
            page[within..within + n].copy_from_slice(&data[done..done + n]);
            done += n;
        }
        self.size = self.size.max(offset + data.len() as u64);
    }
    /// Make the file `size` bytes long, and say how many pages that freed. Growing allocates
    /// nothing: the new bytes are a hole.
    fn resize(&mut self, size: u64) -> u64 {
        let mut freed = 0;
        if size < self.size {
            freed = self.pages.split_off(&size.div_ceil(PAGE_BYTES)).len() as u64;
            let within = (size % PAGE_BYTES) as usize;
            if within != 0
                && let Some(page) = self.pages.get_mut(&(size / PAGE_BYTES))
            {
                page[within..].fill(0);
            }
        }
        self.size = size;
        freed
    }
}

struct OpenRecord {
    ino: u64,
    access: Access,
    /// The opener's identity, as Linux keeps `f_cred`.
    cred: Identity,
}

#[derive(Clone, Copy)]
struct Lock {
    owner: u64,
    family: LockFamily,
    kind: LockKind,
    range: LockRange,
}

struct Waiter {
    ino: u64,
    lock: Lock,
    waker: Waker,
}

impl Lock {
    fn conflicts(self, other: Lock) -> bool {
        self.owner != other.owner
            && self.family == other.family
            && self.range.overlaps(other.range)
            && (self.kind == LockKind::Exclusive || other.kind == LockKind::Exclusive)
    }
}

/// Take `range` out of `owner`'s locks of `family`, keeping what lies outside it, as fcntl(2)
/// splits a lock that a new lock or an unlock covers part of.
fn carve(locks: &mut Vec<Lock>, owner: u64, family: LockFamily, range: LockRange) {
    let mut pieces = Vec::new();
    locks.retain(|lock| {
        let cut = lock.owner == owner && lock.family == family && lock.range.overlaps(range);
        if cut {
            pieces.extend(
                lock.range
                    .minus(range)
                    .into_iter()
                    .flatten()
                    .map(|rest| Lock {
                        range: rest,
                        ..*lock
                    }),
            );
        }
        !cut
    });
    locks.extend(pieces);
}

struct State {
    inodes: HashMap<u64, Inode>,
    next_ino: u64,
    next_open: u64,
    opens: HashMap<u64, OpenRecord>,
    locks: HashMap<u64, Vec<Lock>>,
    /// Each pending call has its own registration, even through the same open reference.
    waiters: HashMap<u64, Waiter>,
    next_waiter: u64,
    /// Pages of content held, against the capacity.
    pages: u64,
}
impl State {
    /// Follow every current conflict, rather than cached edges to one of several holders.
    /// A cancelled wait or a lock that has already been released cannot form a false cycle.
    fn deadlocks(&self, ino: u64, wanted: Lock) -> bool {
        let mut pending = vec![(ino, wanted)];
        let mut visited = HashSet::new();
        while let Some((ino, wanted_lock)) = pending.pop() {
            for held in self.locks.get(&ino).into_iter().flatten() {
                if !held.conflicts(wanted_lock) {
                    continue;
                }
                if held.owner == wanted.owner {
                    return true;
                }
                if visited.insert(held.owner) {
                    pending.extend(self.waiters.values().filter_map(|waiter| {
                        (waiter.lock.owner == held.owner && waiter.lock.family == wanted.family)
                            .then_some((waiter.ino, waiter.lock))
                    }));
                }
            }
        }
        false
    }
}

pub struct MemFs {
    id: FsId,
    generation: u64,
    clock: Clock,
    /// The most pages of content it holds.
    capacity: u64,
    state: RefCell<State>,
}

impl MemFs {
    /// A filesystem whose root directory is owned by `owner`:`group` with `mode`, holding up to
    /// [`DEFAULT_CAPACITY`] of content.
    pub fn new(id: FsId, generation: u64, owner: u32, group: u32, mode: u16, clock: Clock) -> Self {
        let now = clock();
        let mut root = Node::directory(owner, group, mode);
        root.ino = ROOT;
        Self {
            id,
            generation,
            clock,
            capacity: DEFAULT_CAPACITY.div_ceil(PAGE_BYTES),
            state: RefCell::new(State {
                inodes: HashMap::from([(ROOT, Inode::new(root, 2, ROOT, "", now))]),
                next_ino: ROOT + 1,
                next_open: 1,
                opens: HashMap::new(),
                locks: HashMap::new(),
                waiters: HashMap::new(),
                next_waiter: 1,
                pages: 0,
            }),
        }
    }
    /// The same, holding up to `bytes` of content, in whole pages.
    pub fn with_capacity(mut self, bytes: u64) -> Self {
        self.capacity = bytes.div_ceil(PAGE_BYTES);
        self
    }
    /// The number of objects it holds, for tests: content released with its last name and open.
    pub fn inode_count(&self) -> usize {
        self.state.borrow().inodes.len()
    }

    fn handle(&self, ino: u64) -> Handle {
        Handle {
            fs: self.id.clone(),
            node: NodeId {
                ino,
                generation: self.generation,
            },
            proof: String::new(),
        }
    }
    /// The inode a handle names: `EACCES` for a handle this filesystem did not issue, `ESTALE`
    /// for one whose object is gone.
    fn check(&self, state: &State, handle: &Handle) -> Result<u64> {
        if handle.fs != self.id || !handle.proof.is_empty() {
            return Err(Errno::EACCES);
        }
        if handle.node.generation != self.generation || !state.inodes.contains_key(&handle.node.ino)
        {
            return Err(Errno::ESTALE);
        }
        Ok(handle.node.ino)
    }
    fn metadata_of(inode: &Inode) -> Metadata {
        Metadata {
            file_type: inode.file_type(),
            mode: inode.meta.mode & 0o7777,
            nlink: inode.nlink,
            uid: inode.meta.owner,
            gid: inode.meta.group,
            size: match inode.file_type() {
                FileType::Symlink => inode.meta.link.as_ref().map_or(0, |l| l.len() as u64),
                FileType::Dir => PAGE_BYTES,
                _ => inode.size,
            },
            mtime: Timespec::from(inode.mtime),
            ctime: Timespec::from(inode.ctime),
            atime: Timespec::from(inode.atime),
            rdev: inode.meta.rdev.clone(),
            acl: inode.meta.acl.is_some(),
        }
    }
    fn entry(&self, state: &State, ino: u64) -> Entry {
        Entry {
            handle: self.handle(ino),
            metadata: Self::metadata_of(&state.inodes[&ino]),
        }
    }
    /// A directory `cred` may search: ENOTDIR, EACCES otherwise.
    fn searchable(state: &State, cred: &Cred, ino: u64) -> Result<()> {
        let dir = &state.inodes[&ino];
        if !dir.meta.directory {
            return Err(Errno::ENOTDIR);
        }
        inode::require(&cred.identity, &dir.meta, EXEC)
    }
    /// What `name` names in the directory `dir`, which `cred` may search.
    fn child(state: &State, cred: &Cred, dir: u64, name: &str) -> Result<Option<u64>> {
        check_component(name)?;
        Self::searchable(state, cred, dir)?;
        Ok(state.inodes[&dir].entries.get(name).copied())
    }
    /// A new name in `dir`, as filename_create and may_create check it: free (EEXIST), then
    /// the directory not removed (ENOENT) and writable (EACCES).
    fn creatable(state: &State, cred: &Cred, dir: u64, name: &str) -> Result<()> {
        if Self::child(state, cred, dir, name)?.is_some() {
            return Err(Errno::EEXIST);
        }
        let dir = &state.inodes[&dir];
        inode::may_create(&cred.identity, &dir.meta, dir.removed())
    }
    fn touch(inode: &mut Inode, now: (u64, u32), content: bool) {
        if content {
            inode.mtime = now;
        }
        inode.ctime = now;
    }
    fn add(&self, state: &mut State, dir: u64, name: &str, meta: Node) -> u64 {
        let ino = state.next_ino;
        state.next_ino += 1;
        let directory = meta.directory;
        let mut meta = meta;
        meta.ino = ino;
        let nlink = if directory { 2 } else { 1 };
        let now = (self.clock)();
        state
            .inodes
            .insert(ino, Inode::new(meta, nlink, dir, name, now));
        let parent = state.inodes.get_mut(&dir).expect("parent directory");
        parent.entries.insert(name.to_string(), ino);
        if directory {
            parent.nlink += 1;
        }
        Self::touch(parent, now, true);
        ino
    }
    /// Free an object with no name and no open reference left, and its content.
    fn reclaim(state: &mut State, ino: u64) {
        if state
            .inodes
            .get(&ino)
            .is_some_and(|i| i.nlink == 0 && i.opens == 0)
        {
            if let Some(inode) = state.inodes.remove(&ino) {
                state.pages -= inode.pages.len() as u64;
            }
            state.locks.remove(&ino);
        }
    }
    /// Drop one name of `ino`; directories lose both their names (the entry and `.`).
    fn unname(state: &mut State, ino: u64, now: (u64, u32)) {
        let inode = state.inodes.get_mut(&ino).expect("named inode");
        if inode.meta.directory {
            inode.nlink = 0;
        } else {
            inode.nlink -= 1;
        }
        inode.ctime = now;
        Self::reclaim(state, ino);
    }
    /// Whether `ancestor` is `ino` or above it. Only live directories are asked about, whose
    /// parents are live too; a missing one ends the walk all the same.
    fn is_ancestor(state: &State, ancestor: u64, mut ino: u64) -> bool {
        loop {
            if ino == ancestor {
                return true;
            }
            match state.inodes.get(&ino) {
                Some(inode) if ino != ROOT => ino = inode.parent,
                _ => return false,
            }
        }
    }
    /// The record of an open reference this filesystem gave, for the object it names (EBADF
    /// otherwise, a reference from an earlier instance with the same id included).
    fn open_record<'s>(&self, state: &'s State, open: &OpenRef) -> Result<&'s OpenRecord> {
        if open.fs != self.id || open.node.generation != self.generation {
            return Err(Errno::EBADF);
        }
        state
            .opens
            .get(&open.id)
            .filter(|record| record.ino == open.node.ino)
            .ok_or(Errno::EBADF)
    }
    fn new_open(&self, state: &mut State, cred: &Cred, ino: u64, access: Access) -> OpenRef {
        let id = state.next_open;
        state.next_open += 1;
        state.opens.insert(
            id,
            OpenRecord {
                ino,
                access,
                cred: cred.identity.clone(),
            },
        );
        state.inodes.get_mut(&ino).expect("opened inode").opens += 1;
        OpenRef {
            fs: self.id.clone(),
            id,
            node: NodeId {
                ino,
                generation: self.generation,
            },
            access,
        }
    }
    /// Check `options` on an existing object, as may_open does: `truncate` asks write
    /// permission too, even with read-only access, as on Linux.
    fn openable(cred: &Cred, inode: &Inode, options: &OpenOptions) -> Result<Access> {
        let access = options.access()?;
        if access == Access::Path {
            return Ok(access);
        }
        if inode.file_type() == FileType::Socket {
            return Err(Errno::ENXIO);
        }
        let mut mask = access.mask();
        if options.is_truncate() {
            mask |= WRITE;
        }
        inode::may_open(&cred.identity, &inode.meta, mask)?;
        Ok(access)
    }
    /// open's truncation: a regular file's content goes; anything else stays as it is.
    fn truncate_on_open(&self, state: &mut State, ino: u64, options: &OpenOptions, cred: &Cred) {
        if options.is_truncate() && state.inodes[&ino].file_type() == FileType::File {
            let now = (self.clock)();
            Self::resize(state, ino, 0, &cred.identity, now);
        }
    }
    /// Resize a file's content, freeing the pages past its new end; the resizer loses the
    /// file's privileges, as on a write.
    fn resize(state: &mut State, ino: u64, size: u64, by: &Identity, now: (u64, u32)) {
        let inode = state.inodes.get_mut(&ino).expect("checked inode");
        let freed = inode.resize(size);
        inode::remove_privs(by, &mut inode.meta);
        Self::touch(inode, now, true);
        state.pages -= freed;
    }

    fn do_lookup(&self, cred: &Cred, dir: &Handle, name: &str) -> Result<Entry> {
        let state = self.state.borrow();
        let dir = self.check(&state, dir)?;
        let ino = Self::child(&state, cred, dir, name)?.ok_or(Errno::ENOENT)?;
        Ok(self.entry(&state, ino))
    }
    fn do_walk(&self, cred: &Cred, dir: &Handle, names: &[String]) -> Result<Walked> {
        let state = self.state.borrow();
        let mut current = self.check(&state, dir)?;
        for name in names {
            check_component(name)?;
        }
        let mut entries = Vec::new();
        for (index, name) in names.iter().enumerate() {
            if index > 0 {
                let stop = match state.inodes[&current].file_type() {
                    FileType::Dir => None,
                    FileType::Symlink => Some(Stop::Symlink(index - 1)),
                    _ => Some(Stop::NotDirectory(index - 1)),
                };
                if stop.is_some() {
                    return Ok(Walked { entries, stop });
                }
            }
            match Self::child(&state, cred, current, name)? {
                Some(ino) => {
                    current = ino;
                    entries.push(self.entry(&state, current));
                }
                None => {
                    return Ok(Walked {
                        entries,
                        stop: Some(Stop::Missing(index)),
                    });
                }
            }
        }
        Ok(Walked {
            entries,
            stop: None,
        })
    }
    fn do_parent(&self, dir: &Handle) -> Result<Option<(Entry, String)>> {
        let state = self.state.borrow();
        let dir = self.check(&state, dir)?;
        let inode = &state.inodes[&dir];
        if !inode.meta.directory {
            return Err(Errno::ENOTDIR);
        }
        if dir == ROOT {
            return Ok(None);
        }
        // A removed directory has no parent left to name, as getcwd(2) says: ENOENT.
        if inode.removed() || !state.inodes.contains_key(&inode.parent) {
            return Err(Errno::ENOENT);
        }
        Ok(Some((self.entry(&state, inode.parent), inode.name.clone())))
    }
    fn do_setattr(&self, cred: &Cred, handle: &Handle, attr: &SetAttr) -> Result<Metadata> {
        let mut state = self.state.borrow_mut();
        let ino = self.check(&state, handle)?;
        let who = &cred.identity;
        let inode = &state.inodes[&ino];
        if *attr == SetAttr::default() {
            return Ok(Self::metadata_of(inode));
        }
        // Every change is checked before any is made.
        let mut meta = inode.meta.clone();
        if let Some(mode) = attr.mode {
            inode::chmod(who, &mut meta, mode)?;
        }
        inode::chown(who, &mut meta, attr.uid, attr.gid)?;
        inode::may_set_times(who, &inode.meta, attr.atime, attr.mtime)?;
        if let Some(size) = attr.size {
            match inode.file_type() {
                FileType::Dir => return Err(Errno::EISDIR),
                FileType::File => {}
                _ => return Err(Errno::EINVAL),
            }
            inode::require(who, &inode.meta, WRITE)?;
            if size > FILE_MAX {
                return Err(Errno::EFBIG);
            }
        }
        let now = (self.clock)();
        state.inodes.get_mut(&ino).expect("checked inode").meta = meta;
        if let Some(size) = attr.size {
            Self::resize(&mut state, ino, size, who, now);
        }
        let inode = state.inodes.get_mut(&ino).expect("checked inode");
        if let Some(atime) = inode::time(attr.atime, now) {
            inode.atime = atime;
        }
        if let Some(mtime) = inode::time(attr.mtime, now) {
            inode.mtime = mtime;
        }
        inode.ctime = now;
        Ok(Self::metadata_of(inode))
    }
    fn do_read_dir(&self, cred: &Cred, dir: &Handle) -> Result<Vec<DirEntry>> {
        let mut state = self.state.borrow_mut();
        let ino = self.check(&state, dir)?;
        let inode = &state.inodes[&ino];
        if !inode.meta.directory {
            return Err(Errno::ENOTDIR);
        }
        inode::require(&cred.identity, &inode.meta, READ)?;
        if inode.removed() {
            return Err(Errno::ENOENT);
        }
        let entries = inode
            .entries
            .iter()
            .map(|(name, ino)| DirEntry {
                name: name.clone(),
                node: NodeId {
                    ino: *ino,
                    generation: self.generation,
                },
                file_type: state.inodes[ino].file_type(),
            })
            .collect();
        self.accessed(state.inodes.get_mut(&ino).expect("checked directory"), true);
        Ok(entries)
    }
    /// Make a node named `name` in `dir`, after the checks every creation shares.
    fn make(
        &self,
        cred: &Cred,
        dir: &Handle,
        name: &str,
        meta: impl FnOnce(&Node) -> Node,
    ) -> Result<Entry> {
        let mut state = self.state.borrow_mut();
        let dir = self.check(&state, dir)?;
        Self::creatable(&state, cred, dir, name)?;
        let meta = meta(&state.inodes[&dir].meta);
        let ino = self.add(&mut state, dir, name, meta);
        Ok(self.entry(&state, ino))
    }
    fn do_create(
        &self,
        cred: &Cred,
        dir: &Handle,
        name: &str,
        mode: u16,
        options: &OpenOptions,
    ) -> Result<(Entry, OpenRef)> {
        let access = options.access()?;
        if matches!(access, Access::Exec | Access::Path) {
            return Err(Errno::EINVAL);
        }
        let mut state = self.state.borrow_mut();
        let dir_ino = self.check(&state, dir)?;
        if let Some(ino) = Self::child(&state, cred, dir_ino, name)? {
            if options.is_create_new() {
                return Err(Errno::EEXIST);
            }
            // open(O_CREAT) never opens a directory, whatever the access.
            if state.inodes[&ino].meta.directory {
                return Err(Errno::EISDIR);
            }
            Self::openable(cred, &state.inodes[&ino], options)?;
            self.truncate_on_open(&mut state, ino, options, cred);
            let open = self.new_open(&mut state, cred, ino, access);
            return Ok((self.entry(&state, ino), open));
        }
        let parent = &state.inodes[&dir_ino];
        inode::may_create(&cred.identity, &parent.meta, parent.removed())?;
        let meta = created(&cred.identity, &parent.meta, mode, false, cred.umask);
        let ino = self.add(&mut state, dir_ino, name, meta);
        // The creator gets the access it asked for, whatever the new file's mode, as on Linux.
        let open = self.new_open(&mut state, cred, ino, access);
        Ok((self.entry(&state, ino), open))
    }
    fn do_link(&self, cred: &Cred, target: &Handle, dir: &Handle, name: &str) -> Result<Entry> {
        let mut state = self.state.borrow_mut();
        let target = self.check(&state, target)?;
        let dir = self.check(&state, dir)?;
        if Self::child(&state, cred, dir, name)?.is_some() {
            return Err(Errno::EEXIST);
        }
        inode::may_link(&cred.identity, &state.inodes[&target].meta)?;
        let parent = &state.inodes[&dir];
        inode::may_create(&cred.identity, &parent.meta, parent.removed())?;
        // An unlinked file, though still open, takes no name again.
        if state.inodes[&target].nlink == 0 {
            return Err(Errno::ENOENT);
        }
        let now = (self.clock)();
        let parent = state.inodes.get_mut(&dir).expect("checked directory");
        parent.entries.insert(name.to_string(), target);
        Self::touch(parent, now, true);
        let inode = state.inodes.get_mut(&target).expect("checked target");
        inode.nlink += 1;
        Self::touch(inode, now, false);
        Ok(self.entry(&state, target))
    }
    fn do_remove(
        &self,
        cred: &Cred,
        dir: &Handle,
        name: &str,
        directory: bool,
        expected: Option<NodeId>,
    ) -> Result<()> {
        let mut state = self.state.borrow_mut();
        let dir = self.check(&state, dir)?;
        let victim = Self::child(&state, cred, dir, name)?.ok_or(Errno::ENOENT)?;
        if expected.is_some_and(|node| self.handle(victim).node != node) {
            return Err(Errno::ESTALE);
        }
        let inode = &state.inodes[&victim];
        // As may_delete: whether the name may go, then what it names.
        inode::may_delete(&cred.identity, &state.inodes[&dir].meta, &inode.meta)?;
        match (directory, inode.meta.directory) {
            (false, true) => return Err(Errno::EISDIR),
            (true, false) => return Err(Errno::ENOTDIR),
            (true, true) if !inode.entries.is_empty() => return Err(Errno::ENOTEMPTY),
            _ => {}
        }
        let now = (self.clock)();
        let parent = state.inodes.get_mut(&dir).expect("checked directory");
        parent.entries.remove(name);
        if directory {
            parent.nlink -= 1;
        }
        Self::touch(parent, now, true);
        Self::unname(&mut state, victim, now);
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    fn do_rename(
        &self,
        cred: &Cred,
        from_dir: &Handle,
        from: &str,
        to_dir: &Handle,
        to: &str,
        flags: RenameFlags,
    ) -> Result<()> {
        let who = &cred.identity;
        let mut state = self.state.borrow_mut();
        let from_dir = self.check(&state, from_dir)?;
        let to_dir = self.check(&state, to_dir)?;
        let source = Self::child(&state, cred, from_dir, from)?.ok_or(Errno::ENOENT)?;
        let existing = Self::child(&state, cred, to_dir, to)?;
        if existing.is_some() && flags.contains(RenameFlags::NOREPLACE) {
            return Err(Errno::EEXIST);
        }
        if existing == Some(source) {
            return Ok(());
        }
        let moving_dir = state.inodes[&source].meta.directory;
        if moving_dir && Self::is_ancestor(&state, source, to_dir) {
            return Err(Errno::EINVAL);
        }
        inode::may_delete(
            who,
            &state.inodes[&from_dir].meta,
            &state.inodes[&source].meta,
        )?;
        match existing {
            Some(target) => {
                let target_inode = &state.inodes[&target];
                inode::may_delete(who, &state.inodes[&to_dir].meta, &target_inode.meta)?;
                match (moving_dir, target_inode.meta.directory) {
                    (true, false) => return Err(Errno::ENOTDIR),
                    (false, true) => return Err(Errno::EISDIR),
                    _ => {}
                }
            }
            None => {
                let parent = &state.inodes[&to_dir];
                inode::may_create(who, &parent.meta, parent.removed())?;
            }
        }
        // Moving a directory to another parent rewrites its `..`, which needs write permission.
        if moving_dir && from_dir != to_dir {
            inode::require(who, &state.inodes[&source].meta, WRITE)?;
        }
        if let Some(target) = existing
            && !state.inodes[&target].entries.is_empty()
        {
            return Err(Errno::ENOTEMPTY);
        }
        let now = (self.clock)();
        if let Some(target) = existing {
            let parent = state.inodes.get_mut(&to_dir).expect("checked");
            parent.entries.remove(to);
            if moving_dir {
                parent.nlink -= 1;
            }
            Self::unname(&mut state, target, now);
        }
        let parent = state.inodes.get_mut(&from_dir).expect("checked");
        parent.entries.remove(from);
        if moving_dir {
            parent.nlink -= 1;
        }
        Self::touch(parent, now, true);
        let parent = state.inodes.get_mut(&to_dir).expect("checked");
        parent.entries.insert(to.to_string(), source);
        if moving_dir {
            parent.nlink += 1;
        }
        Self::touch(parent, now, true);
        let inode = state.inodes.get_mut(&source).expect("checked");
        if moving_dir {
            inode.parent = to_dir;
            inode.name = to.to_string();
        }
        Self::touch(inode, now, false);
        Ok(())
    }
    fn do_getxattr(&self, cred: &Cred, handle: &Handle, name: &str) -> Result<Vec<u8>> {
        let space = xattr::space(name)?;
        let state = self.state.borrow();
        let inode = &state.inodes[&self.check(&state, handle)?];
        xattr::readable(&cred.identity, &inode.meta, space)?;
        match space {
            Space::Access | Space::Default => {
                let entries = xattr::acl(&inode.meta, space)?;
                Ok(serde_json::to_vec(&entries).unwrap_or_default())
            }
            Space::User | Space::Trusted => inode.xattrs.get(name).cloned().ok_or(Errno::ENODATA),
        }
    }
    fn do_setxattr(
        &self,
        cred: &Cred,
        handle: &Handle,
        name: &str,
        value: &[u8],
        flags: XattrFlags,
    ) -> Result<()> {
        let space = xattr::space(name)?;
        let mut state = self.state.borrow_mut();
        let ino = self.check(&state, handle)?;
        let inode = state.inodes.get_mut(&ino).expect("checked inode");
        xattr::settable(&cred.identity, &inode.meta, space)?;
        match space {
            Space::Access | Space::Default => {
                xattr::check_flags(flags.bits(), xattr::has_acl(&inode.meta, space))?;
                let entries: Entries = serde_json::from_slice(value).map_err(|_| Errno::EINVAL)?;
                xattr::set_acl(&cred.identity, &mut inode.meta, space, entries)?;
            }
            Space::User | Space::Trusted => {
                xattr::check_flags(flags.bits(), inode.xattrs.contains_key(name))?;
                xattr::store(&mut inode.xattrs, name, value)?;
            }
        }
        Self::touch(inode, (self.clock)(), false);
        Ok(())
    }
    fn do_removexattr(&self, cred: &Cred, handle: &Handle, name: &str) -> Result<()> {
        let space = xattr::space(name)?;
        let mut state = self.state.borrow_mut();
        let ino = self.check(&state, handle)?;
        let inode = state.inodes.get_mut(&ino).expect("checked inode");
        xattr::settable(&cred.identity, &inode.meta, space)?;
        match space {
            Space::Access | Space::Default => xattr::remove_acl(&mut inode.meta, space)?,
            Space::User | Space::Trusted => {
                inode.xattrs.remove(name).ok_or(Errno::ENODATA)?;
            }
        }
        Self::touch(inode, (self.clock)(), false);
        Ok(())
    }
    fn do_open(&self, cred: &Cred, handle: &Handle, options: &OpenOptions) -> Result<OpenRef> {
        let mut state = self.state.borrow_mut();
        let ino = self.check(&state, handle)?;
        let access = Self::openable(cred, &state.inodes[&ino], options)?;
        if access != Access::Path {
            self.truncate_on_open(&mut state, ino, options, cred);
        }
        Ok(self.new_open(&mut state, cred, ino, access))
    }
    /// The inode an open reference reads or writes: a regular file (EISDIR for a directory,
    /// ENXIO for a device, whose I/O is its driver's).
    fn content(inode: &Inode) -> Result<()> {
        match inode.file_type() {
            FileType::File => Ok(()),
            FileType::Dir => Err(Errno::EISDIR),
            _ => Err(Errno::ENXIO),
        }
    }
    /// Access-time update respecting active mount flags (`MS_NOATIME`, `MS_NODIRATIME`,
    /// `MS_STRICTATIME`, `MS_RDONLY`), defaulting to Linux's relatime policy when unmounted.
    fn accessed(&self, inode: &mut Inode, is_dir: bool) {
        let now = (self.clock)();
        let update = match crate::mount::active_mount_flags() {
            Some(flags) => {
                flags.should_update_atime(is_dir, inode.atime, inode.mtime, inode.ctime, now)
            }
            None => {
                inode.atime <= inode.mtime
                    || inode.atime <= inode.ctime
                    || now.0.saturating_sub(inode.atime.0) >= 24 * 60 * 60
            }
        };
        if update {
            inode.atime = now;
        }
    }
    fn do_read_at(&self, open: &OpenRef, buf: &mut [u8], offset: u64) -> Result<usize> {
        let mut state = self.state.borrow_mut();
        let record = self.open_record(&state, open)?;
        if !record.access.reads() {
            return Err(Errno::EBADF);
        }
        let ino = record.ino;
        let inode = state.inodes.get_mut(&ino).expect("open inode");
        Self::content(inode)?;
        if offset > FILE_MAX || buf.len() as u64 > FILE_MAX - offset {
            return Err(Errno::EINVAL);
        }
        let len = buf.len().min(RW_MAX);
        let read = inode.read(offset, &mut buf[..len]);
        self.accessed(inode, false);
        Ok(read)
    }
    fn do_write_at(&self, open: &OpenRef, buf: &[u8], at: WriteAt) -> Result<Written> {
        let mut state = self.state.borrow_mut();
        let record = self.open_record(&state, open)?;
        if !record.access.writes() {
            return Err(Errno::EBADF);
        }
        let (ino, writer) = (record.ino, record.cred.clone());
        let inode = &state.inodes[&ino];
        Self::content(inode)?;
        // The end is read here, with the write, so appends never overwrite each other.
        let offset = match at {
            WriteAt::Offset(offset) => offset,
            WriteAt::End => inode.size,
        };
        // Nothing to write changes nothing: not the size, the times nor the mode.
        if buf.is_empty() {
            return Ok(Written { offset, len: 0 });
        }
        // As Linux: nothing goes at or past the largest offset (EFBIG); before it, what fits,
        // and what fits in the capacity: a short write, ENOSPC only if nothing fits.
        if offset >= FILE_MAX {
            return Err(Errno::EFBIG);
        }
        let room = usize::try_from(FILE_MAX - offset).unwrap_or(usize::MAX);
        let len = buf.len().min(room).min(RW_MAX);
        let (len, added) = inode.fitting(offset, len, self.capacity - state.pages);
        if len == 0 {
            return Err(Errno::ENOSPC);
        }
        state.pages += added;
        let now = (self.clock)();
        let inode = state.inodes.get_mut(&ino).expect("open inode");
        inode.write(offset, &buf[..len]);
        inode::remove_privs(&writer, &mut inode.meta);
        Self::touch(inode, now, true);
        Ok(Written { offset, len })
    }
    fn do_set_len(&self, open: &OpenRef, size: u64) -> Result<()> {
        let mut state = self.state.borrow_mut();
        let record = self.open_record(&state, open)?;
        if record.access == Access::Path {
            return Err(Errno::EBADF);
        }
        if !record.access.writes() || state.inodes[&record.ino].file_type() != FileType::File {
            return Err(Errno::EINVAL);
        }
        if size > FILE_MAX {
            return Err(Errno::EFBIG);
        }
        let (ino, by) = (record.ino, record.cred.clone());
        let now = (self.clock)();
        Self::resize(&mut state, ino, size, &by, now);
        Ok(())
    }
    fn do_sync(&self, open: &OpenRef) -> Result<()> {
        let state = self.state.borrow();
        if self.open_record(&state, open)?.access == Access::Path {
            return Err(Errno::EBADF);
        }
        // Nothing here is durable (`Durability::Volatile`): there is nothing to wait for.
        Ok(())
    }
    /// The first lock of `family` another owner holds that a `kind` lock on `range` would
    /// conflict with.
    fn conflict(
        state: &State,
        ino: u64,
        owner: u64,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> Option<Conflict> {
        state.locks.get(&ino)?.iter().find_map(|lock| {
            (lock.owner != owner
                && lock.family == family
                && lock.range.overlaps(range)
                && (kind == LockKind::Exclusive || lock.kind == LockKind::Exclusive))
                .then_some(Conflict {
                    kind: lock.kind,
                    range: lock.range,
                    owner: lock.owner,
                })
        })
    }
    /// The inode an open reference may take a lock of `family` and `kind` on: flock needs any
    /// access but a path-only one, fcntl read access to share and write access to exclude
    /// (EBADF); flock covers the whole file (EINVAL).
    fn lockable(
        &self,
        state: &State,
        open: &OpenRef,
        family: LockFamily,
        kind: Option<LockKind>,
        range: LockRange,
    ) -> Result<u64> {
        let record = self.open_record(state, open)?;
        let allowed = match (family, kind) {
            _ if record.access == Access::Path => false,
            (LockFamily::Flock, _) | (LockFamily::Posix, None) => true,
            (LockFamily::Posix, Some(LockKind::Shared)) => record.access.reads(),
            (LockFamily::Posix, Some(LockKind::Exclusive)) => record.access.writes(),
        };
        if !allowed {
            return Err(Errno::EBADF);
        }
        if family == LockFamily::Flock && range != LockRange::WHOLE {
            return Err(Errno::EINVAL);
        }
        Ok(record.ino)
    }
    /// Wake outside the state borrow: a waker may immediately schedule another operation.
    fn wake(&self, ino: u64) {
        let wakers: Vec<_> = self
            .state
            .borrow()
            .waiters
            .values()
            .filter(|waiter| waiter.ino == ino)
            .map(|waiter| waiter.waker.clone())
            .collect();
        for waker in wakers {
            waker.wake();
        }
    }
    /// Take a lock, or say why not: EAGAIN without `waker`; with one, return the registration
    /// of the pending call, unless waiting would deadlock (EDEADLK).
    fn acquire(
        &self,
        open: &OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
        waker: Option<&Waker>,
    ) -> Result<Option<u64>> {
        let mut state = self.state.borrow_mut();
        let ino = self.lockable(&state, open, family, Some(kind), range)?;
        let owner = open.id;
        // flock conversions first give up the old lock, even if the new one cannot be
        // granted. Keeping it during an upgrade could leave two shared owners stuck forever.
        if family == LockFamily::Flock
            && let Some(locks) = state.locks.get_mut(&ino)
            && locks
                .iter()
                .any(|lock| lock.owner == owner && lock.family == family && lock.kind != kind)
        {
            carve(locks, owner, family, range);
            drop(state);
            self.wake(ino);
            state = self.state.borrow_mut();
            self.lockable(&state, open, family, Some(kind), range)?;
        }
        let wanted = Lock {
            owner,
            family,
            kind,
            range,
        };
        if Self::conflict(&state, ino, owner, family, kind, range).is_some() {
            let Some(waker) = waker else {
                return Err(Errno::EAGAIN);
            };
            if family == LockFamily::Posix && state.deadlocks(ino, wanted) {
                return Err(Errno::EDEADLK);
            }
            let id = state.next_waiter;
            state.next_waiter += 1;
            state.waiters.insert(
                id,
                Waiter {
                    ino,
                    lock: wanted,
                    waker: waker.clone(),
                },
            );
            return Ok(Some(id));
        }
        let locks = state.locks.entry(ino).or_default();
        // The new lock replaces this owner's within its range, whatever their kind; what lies
        // outside stays, and locks of the same kind it meets join it, as Linux merges them.
        carve(locks, owner, family, range);
        let mut merged = range;
        locks.retain(|lock| {
            let joins = lock.owner == owner
                && lock.family == family
                && lock.kind == kind
                && lock.range.touches(merged);
            if joins {
                merged = merged.union(lock.range);
            }
            !joins
        });
        locks.push(Lock {
            owner,
            family,
            kind,
            range: merged,
        });
        // A downgrade may let a waiter in.
        drop(state);
        self.wake(ino);
        Ok(None)
    }
    fn do_unlock(&self, open: &OpenRef, family: LockFamily, range: LockRange) -> Result<()> {
        let mut state = self.state.borrow_mut();
        let ino = self.lockable(&state, open, family, None, range)?;
        if let Some(locks) = state.locks.get_mut(&ino) {
            carve(locks, open.id, family, range);
        }
        drop(state);
        self.wake(ino);
        Ok(())
    }
    fn do_test_lock(
        &self,
        open: &OpenRef,
        kind: LockKind,
        range: LockRange,
    ) -> Result<Option<Conflict>> {
        let state = self.state.borrow();
        // F_GETLK tests conflicts without acquiring a lock, so it does not require the access
        // that F_SETLK of this kind would need. O_PATH remains invalid.
        let ino = self.lockable(&state, open, LockFamily::Posix, None, range)?;
        Ok(Self::conflict(
            &state,
            ino,
            open.id,
            LockFamily::Posix,
            kind,
            range,
        ))
    }
    fn do_release(&self, open: &OpenRef) -> Result<()> {
        let mut state = self.state.borrow_mut();
        let ino = self.open_record(&state, open)?.ino;
        state.opens.remove(&open.id);
        if let Some(locks) = state.locks.get_mut(&ino) {
            locks.retain(|lock| lock.owner != open.id);
        }
        if let Some(inode) = state.inodes.get_mut(&ino) {
            inode.opens -= 1;
        }
        Self::reclaim(&mut state, ino);
        drop(state);
        self.wake(ino);
        Ok(())
    }
}

/// A lock waited for: ready once granted, or refused. Dropped before then, it gives up the
/// wait, as a signal interrupts F_SETLKW.
struct LockWait<'a> {
    fs: &'a MemFs,
    open: &'a OpenRef,
    family: LockFamily,
    kind: LockKind,
    range: LockRange,
    waiting: Option<u64>,
}
impl Future for LockWait<'_> {
    type Output = Result<()>;
    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<()>> {
        if let Some(id) = self.waiting.take() {
            self.fs.state.borrow_mut().waiters.remove(&id);
        }
        let (family, kind, range) = (self.family, self.kind, self.range);
        let result = self
            .fs
            .acquire(self.open, family, kind, range, Some(context.waker()));
        match result {
            Ok(Some(id)) => {
                self.waiting = Some(id);
                Poll::Pending
            }
            Ok(None) => Poll::Ready(Ok(())),
            Err(errno) => Poll::Ready(Err(errno)),
        }
    }
}
impl Drop for LockWait<'_> {
    fn drop(&mut self) {
        if let Some(id) = self.waiting {
            self.fs.state.borrow_mut().waiters.remove(&id);
        }
    }
}

macro_rules! ready {
    ($body:expr) => {
        // Execute only when polled. In particular, an abandoned open/create must never
        // allocate an open reference whose result nobody receives and releases.
        Box::pin(async move { $body })
    };
}

impl Filesystem for MemFs {
    fn id(&self) -> &FsId {
        &self.id
    }
    fn capabilities(&self) -> FsCapabilities {
        profiles::MEMORY
    }
    fn root(&self) -> Handle {
        self.handle(ROOT)
    }
    fn lookup<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Entry> {
        ready!(self.do_lookup(cred, dir, name))
    }
    fn walk<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        names: &'a [String],
    ) -> BoxFuture<'a, Walked> {
        ready!(self.do_walk(cred, dir, names))
    }
    fn parent<'a>(
        &'a self,
        _cred: &'a Cred,
        dir: &'a Handle,
    ) -> BoxFuture<'a, Option<(Entry, String)>> {
        ready!(self.do_parent(dir))
    }
    fn metadata<'a>(&'a self, _cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Metadata> {
        ready!({
            let state = self.state.borrow();
            self.check(&state, handle)
                .map(|ino| Self::metadata_of(&state.inodes[&ino]))
        })
    }
    fn open_metadata<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, Metadata> {
        ready!({
            let state = self.state.borrow();
            self.open_record(&state, open)
                .map(|record| Self::metadata_of(&state.inodes[&record.ino]))
        })
    }
    fn setattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        attr: &'a SetAttr,
    ) -> BoxFuture<'a, Metadata> {
        ready!(self.do_setattr(cred, handle, attr))
    }
    fn read_dir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle) -> BoxFuture<'a, Vec<DirEntry>> {
        ready!(self.do_read_dir(cred, dir))
    }
    fn read_link<'a>(&'a self, _cred: &'a Cred, link: &'a Handle) -> BoxFuture<'a, String> {
        ready!({
            let mut state = self.state.borrow_mut();
            let ino = self.check(&state, link)?;
            let inode = state.inodes.get_mut(&ino).expect("checked inode");
            let target = inode.meta.link.clone().ok_or(Errno::EINVAL)?;
            self.accessed(inode, false);
            Ok(target)
        })
    }
    fn create<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        options: &'a OpenOptions,
    ) -> BoxFuture<'a, (Entry, OpenRef)> {
        ready!(self.do_create(cred, dir, name, mode, options))
    }
    fn mkdir<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
    ) -> BoxFuture<'a, Entry> {
        // `created` keeps the sticky bit asked for, as mkdir(2) does.
        ready!(self.make(cred, dir, name, |parent| created(
            &cred.identity,
            parent,
            mode,
            true,
            cred.umask
        )))
    }
    fn mknod<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        rdev: &'a str,
    ) -> BoxFuture<'a, Entry> {
        if !rdev.is_empty() && cred.identity.id != 0 {
            return ready!(Err(Errno::EPERM));
        }
        ready!(self.make(cred, dir, name, |parent| {
            let mut node = created(&cred.identity, parent, mode, false, cred.umask);
            if !rdev.is_empty() {
                node.rdev = Some(rdev.to_string());
            }
            node
        }))
    }
    fn mksock<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
    ) -> BoxFuture<'a, Entry> {
        ready!({
            let mut state = self.state.borrow_mut();
            let dir_ino = self.check(&state, dir)?;
            Self::creatable(&state, cred, dir_ino, name)?;
            let meta = created(
                &cred.identity,
                &state.inodes[&dir_ino].meta,
                mode,
                false,
                cred.umask,
            );
            let ino = self.add(&mut state, dir_ino, name, meta);
            state.inodes.get_mut(&ino).expect("socket inode").is_socket = true;
            Ok(self.entry(&state, ino))
        })
    }
    fn symlink<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        target: &'a str,
    ) -> BoxFuture<'a, Entry> {
        if let Err(errno) = inode::check_link_target(target) {
            return ready!(Err(errno));
        }
        ready!(self.make(cred, dir, name, |parent| inode::new_symlink(
            &cred.identity,
            parent,
            target
        )))
    }
    fn link<'a>(
        &'a self,
        cred: &'a Cred,
        target: &'a Handle,
        dir: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Entry> {
        ready!(self.do_link(cred, target, dir, name))
    }
    fn unlink<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        ready!(self.do_remove(cred, dir, name, false, None))
    }
    fn unlink_if<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        node: NodeId,
    ) -> BoxFuture<'a, ()> {
        ready!(self.do_remove(cred, dir, name, false, Some(node)))
    }
    fn rmdir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        ready!(self.do_remove(cred, dir, name, true, None))
    }
    fn rename<'a>(
        &'a self,
        cred: &'a Cred,
        from_dir: &'a Handle,
        from: &'a str,
        to_dir: &'a Handle,
        to: &'a str,
        flags: RenameFlags,
    ) -> BoxFuture<'a, ()> {
        ready!(self.do_rename(cred, from_dir, from, to_dir, to, flags))
    }
    fn getxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Vec<u8>> {
        ready!(self.do_getxattr(cred, handle, name))
    }
    fn setxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
        value: &'a [u8],
        flags: XattrFlags,
    ) -> BoxFuture<'a, ()> {
        ready!(self.do_setxattr(cred, handle, name, value, flags))
    }
    fn listxattr<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Vec<String>> {
        ready!({
            let state = self.state.borrow();
            self.check(&state, handle).map(|ino| {
                let inode = &state.inodes[&ino];
                xattr::listed(&cred.identity, &inode.meta, inode.xattrs.keys())
            })
        })
    }
    fn removexattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, ()> {
        ready!(self.do_removexattr(cred, handle, name))
    }
    fn statfs<'a>(&'a self, _cred: &'a Cred) -> BoxFuture<'a, StatFs> {
        ready!({
            let state = self.state.borrow();
            Ok(StatFs {
                block_size: PAGE_BYTES,
                blocks: self.capacity,
                blocks_free: self.capacity.saturating_sub(state.pages),
                files: state.inodes.len() as u64,
                files_free: u64::MAX - state.next_ino,
                name_max: abi::NAME_MAX as u64,
            })
        })
    }
    fn open<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        options: &'a OpenOptions,
    ) -> BoxFuture<'a, OpenRef> {
        ready!(self.do_open(cred, handle, options))
    }
    fn read_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a mut [u8],
        offset: u64,
    ) -> BoxFuture<'a, usize> {
        ready!(self.do_read_at(open, buf, offset))
    }
    fn write_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a [u8],
        at: WriteAt,
    ) -> BoxFuture<'a, Written> {
        ready!(self.do_write_at(open, buf, at))
    }
    fn set_len<'a>(&'a self, open: &'a OpenRef, size: u64) -> BoxFuture<'a, ()> {
        ready!(self.do_set_len(open, size))
    }
    fn sync_all<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        ready!(self.do_sync(open))
    }
    fn lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        Box::pin(LockWait {
            fs: self,
            open,
            family,
            kind,
            range,
            waiting: None,
        })
    }
    fn try_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        ready!(self.acquire(open, family, kind, range, None).map(|_| ()))
    }
    fn unlock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        ready!(self.do_unlock(open, family, range))
    }
    fn test_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, Option<Conflict>> {
        ready!(self.do_test_lock(open, kind, range))
    }
    fn release<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        ready!(self.do_release(open))
    }
}

/// Parsed `tmpfs` mount options (`-o mode=...,uid=...,gid=...,size=...`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TmpfsOptions {
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
}

impl TmpfsOptions {
    /// Parse comma-separated `tmpfs` mount options (`mode=`, `uid=`, `gid=`, `size=`).
    /// Defaults match Linux `tmpfs`: `mode=01777`, caller `uid`/`gid`, [`DEFAULT_CAPACITY`].
    /// Unknown or malformed options fail with `Errno::EINVAL`.
    pub fn parse(cred: &Cred, data: Option<&str>) -> Result<Self> {
        let mut opts = Self {
            mode: 0o1777,
            uid: cred.identity.id,
            gid: cred.identity.group,
            size: DEFAULT_CAPACITY,
        };
        let Some(raw) = data else {
            return Ok(opts);
        };
        for item in raw.split(',').filter(|s| !s.is_empty()) {
            let Some((key, val)) = item.split_once('=') else {
                return Err(Errno::EINVAL);
            };
            if val.is_empty() {
                return Err(Errno::EINVAL);
            }
            match key {
                "mode" => {
                    let mode = u16::from_str_radix(val, 8).map_err(|_| Errno::EINVAL)?;
                    if mode > 0o7777 {
                        return Err(Errno::EINVAL);
                    }
                    opts.mode = mode;
                }
                "uid" => {
                    opts.uid = val.parse::<u32>().map_err(|_| Errno::EINVAL)?;
                }
                "gid" => {
                    opts.gid = val.parse::<u32>().map_err(|_| Errno::EINVAL)?;
                }
                "size" => {
                    opts.size = parse_tmpfs_size(val)?;
                }
                _ => return Err(Errno::EINVAL),
            }
        }
        Ok(opts)
    }
}

fn parse_tmpfs_size(val: &str) -> Result<u64> {
    let bytes = val.as_bytes();
    let (digits, mult) = match bytes.last().copied() {
        Some(b'k' | b'K') => (&val[..val.len() - 1], 1024u64),
        Some(b'm' | b'M') => (&val[..val.len() - 1], 1024u64 * 1024),
        Some(b'g' | b'G') => (&val[..val.len() - 1], 1024u64 * 1024 * 1024),
        _ => (val, 1u64),
    };
    if digits.is_empty() {
        return Err(Errno::EINVAL);
    }
    let base = digits.parse::<u64>().map_err(|_| Errno::EINVAL)?;
    let total = base.checked_mul(mult).ok_or(Errno::EINVAL)?;
    if total > FILE_MAX {
        return Err(Errno::EINVAL);
    }
    Ok(total)
}

impl MemFs {
    /// Instantiate a `tmpfs` [`MemFs`] from `mount(2)` `data` options.
    pub fn from_mount_options(
        id: FsId,
        generation: u64,
        cred: &Cred,
        data: Option<&str>,
        clock: Clock,
    ) -> Result<Self> {
        let opts = TmpfsOptions::parse(cred, data)?;
        Ok(
            Self::new(id, generation, opts.uid, opts.gid, opts.mode, clock)
                .with_capacity(opts.size),
        )
    }
}

//! An in-memory filesystem with Linux semantics: the reference the other drivers are tested
//! against (contract §3, every capability "yes"), and the instance's tmpfs (#51). Who may do
//! what is `os_core`'s, which the server's kernel applies too, so their answers agree:
//! `permissions` (owner/group/other, ACLs, sticky directories, setgid inheritance, umask and
//! default ACLs), `inode` (chmod, chown, utimensat, protected hard links) and `xattr`.
//!
//! Inode numbers are never used again, so a handle's generation only has to say which filesystem
//! instance issued it. A file's content lives until its last name and its last open reference
//! are gone. Files are sparse, as on tmpfs: content is kept in pages, holes read as zeros, and
//! only the pages written count against the filesystem's capacity (`ENOSPC` past it).

use crate::{
    Access, Attr, BoxFuture, Conflict, Cred, DirEntry, Entry, FILE_MAX, FileKind, Filesystem, FsId,
    Handle, LockKind, LockRange, NodeId, OpenRef, RENAME_NOREPLACE, Result, SetAttr, StatFs, Stop,
    Walked, WriteAt, Written, check_component, profiles,
};
use abi::Errno;
use abi::contract::FsCapabilities;
use os_core::acl::Entries;
use os_core::inode;
use os_core::permissions::{EXEC, Node, READ, SETGID, SETUID, STICKY, WRITE, created};
use os_core::xattr::{self, Space};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};

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
    nlink: u32,
    /// A regular file's size, and the pages of its content written, by index: the rest reads as
    /// zeros, and every byte past the size is zero.
    size: u64,
    pages: BTreeMap<u64, Box<[u8; PAGE]>>,
    entries: BTreeMap<String, u64>,
    /// A directory's parent (the root's is itself).
    parent: u64,
    xattrs: BTreeMap<String, Vec<u8>>,
    atime: (u64, u32),
    mtime: (u64, u32),
    ctime: (u64, u32),
    opens: u32,
}
impl Inode {
    fn new(meta: Node, nlink: u32, parent: u64, now: (u64, u32)) -> Self {
        Self {
            meta,
            nlink,
            size: 0,
            pages: BTreeMap::new(),
            entries: BTreeMap::new(),
            parent,
            xattrs: BTreeMap::new(),
            atime: now,
            mtime: now,
            ctime: now,
            opens: 0,
        }
    }
    fn kind(&self) -> FileKind {
        if self.meta.directory {
            FileKind::Directory
        } else if self.meta.link.is_some() {
            FileKind::Symlink
        } else if self.meta.rdev.is_some() {
            FileKind::Device
        } else {
            FileKind::File
        }
    }
    /// Up to `len` bytes from `offset`, holes as zeros.
    fn read(&self, offset: u64, len: usize) -> Vec<u8> {
        if offset >= self.size {
            return Vec::new();
        }
        let len = usize::try_from(self.size - offset).map_or(len, |left| left.min(len));
        let mut out = vec![0; len];
        let mut done = 0;
        while done < len {
            let at = offset + done as u64;
            let within = (at % PAGE_BYTES) as usize;
            let n = (PAGE - within).min(len - done);
            if let Some(page) = self.pages.get(&(at / PAGE_BYTES)) {
                out[done..done + n].copy_from_slice(&page[within..within + n]);
            }
            done += n;
        }
        out
    }
    /// How many pages writing `len` bytes at `offset` would add.
    fn missing(&self, offset: u64, len: usize) -> u64 {
        if len == 0 {
            return 0;
        }
        let first = offset / PAGE_BYTES;
        let last = (offset + len as u64 - 1) / PAGE_BYTES;
        (first..=last)
            .filter(|index| !self.pages.contains_key(index))
            .count() as u64
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
    /// A write or truncate by anyone but root clears setuid, and setgid if the group may
    /// execute, as Linux's file_remove_privs.
    fn written_by(&mut self, uid: u32) {
        if uid != 0 {
            self.meta.mode &= !SETUID;
            if self.meta.mode & 0o010 != 0 {
                self.meta.mode &= !SETGID;
            }
        }
    }
}

struct OpenRecord {
    ino: u64,
    access: Access,
    uid: u32,
}

#[derive(Clone, Copy)]
struct Lock {
    owner: u64,
    kind: LockKind,
    range: LockRange,
}

/// Take `range` out of `owner`'s locks, keeping what lies outside it, as fcntl(2) splits a
/// lock that a new lock or an unlock covers part of.
fn carve(locks: &mut Vec<Lock>, owner: u64, range: LockRange) {
    let mut kept = Vec::with_capacity(locks.len() + 1);
    for lock in locks.drain(..) {
        if lock.owner != owner || !lock.range.overlaps(range) {
            kept.push(lock);
            continue;
        }
        if lock.range.start < range.start {
            kept.push(Lock {
                range: LockRange::between(lock.range.start, range.start),
                ..lock
            });
        }
        if range.end() < lock.range.end() {
            kept.push(Lock {
                range: LockRange::between(range.end(), lock.range.end()),
                ..lock
            });
        }
    }
    *locks = kept;
}

struct State {
    inodes: HashMap<u64, Inode>,
    next_ino: u64,
    next_open: u64,
    opens: HashMap<u64, OpenRecord>,
    locks: HashMap<u64, Vec<Lock>>,
    /// Pages of content held, against the capacity.
    pages: u64,
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
    /// A filesystem whose root directory is owned by `owner`:`group` with `perm`, holding up to
    /// [`DEFAULT_CAPACITY`] of content.
    pub fn new(id: FsId, generation: u64, owner: u32, group: u32, perm: u16, clock: Clock) -> Self {
        let now = clock();
        let mut root = Node::directory(owner, group, perm);
        root.ino = ROOT;
        Self {
            id,
            generation,
            clock,
            capacity: DEFAULT_CAPACITY.div_ceil(PAGE_BYTES),
            state: RefCell::new(State {
                inodes: HashMap::from([(ROOT, Inode::new(root, 2, ROOT, now))]),
                next_ino: ROOT + 1,
                next_open: 1,
                opens: HashMap::new(),
                locks: HashMap::new(),
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
    fn attr(inode: &Inode) -> Attr {
        Attr {
            kind: inode.kind(),
            perm: inode.meta.mode & 0o7777,
            nlink: inode.nlink,
            uid: inode.meta.owner,
            gid: inode.meta.group,
            size: match inode.kind() {
                FileKind::Symlink => inode.meta.link.as_ref().map_or(0, |l| l.len() as u64),
                FileKind::Directory => PAGE_BYTES,
                _ => inode.size,
            },
            mtime: inode.mtime,
            ctime: inode.ctime,
            atime: inode.atime,
            rdev: inode.meta.rdev.clone(),
            acl: inode.meta.acl.is_some(),
        }
    }
    fn entry(&self, state: &State, ino: u64) -> Entry {
        Entry {
            handle: self.handle(ino),
            attr: Self::attr(&state.inodes[&ino]),
        }
    }
    fn may(cred: &Cred, inode: &Inode, bits: u16) -> bool {
        inode::permission(&cred.identity, &inode.meta, bits)
    }
    /// A directory `cred` may search: ENOTDIR, EACCES otherwise.
    fn searchable(state: &State, cred: &Cred, ino: u64) -> Result<()> {
        let dir = &state.inodes[&ino];
        if !dir.meta.directory {
            return Err(Errno::ENOTDIR);
        }
        if !Self::may(cred, dir, EXEC) {
            return Err(Errno::EACCES);
        }
        Ok(())
    }
    /// A directory still named: one removed, though open, takes no new names (ENOENT), as
    /// Linux's IS_DEADDIR.
    fn alive(state: &State, ino: u64) -> Result<()> {
        if state.inodes[&ino].nlink == 0 {
            return Err(Errno::ENOENT);
        }
        Ok(())
    }
    /// A directory `cred` may add names to or remove names from.
    fn writable_dir(state: &State, cred: &Cred, ino: u64) -> Result<()> {
        Self::searchable(state, cred, ino)?;
        Self::alive(state, ino)?;
        if !Self::may(cred, &state.inodes[&ino], WRITE) {
            return Err(Errno::EACCES);
        }
        Ok(())
    }
    /// The sticky rule: in a `+t` directory only the entry's owner, the directory's or root may
    /// remove or rename it.
    fn sticky_allows(cred: &Cred, dir: &Inode, victim: &Inode) -> bool {
        dir.meta.mode & STICKY == 0
            || cred.identity.id == 0
            || cred.identity.id == dir.meta.owner
            || cred.identity.id == victim.meta.owner
    }
    fn touch(&self, inode: &mut Inode, content: bool) {
        let now = (self.clock)();
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
        let inode = Inode::new(meta, nlink, dir, (self.clock)());
        state.inodes.insert(ino, inode);
        let parent = state.inodes.get_mut(&dir).expect("parent directory");
        parent.entries.insert(name.to_string(), ino);
        if directory {
            parent.nlink += 1;
        }
        self.touch(parent, true);
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
    fn unname(state: &mut State, ino: u64) {
        let inode = state.inodes.get_mut(&ino).expect("named inode");
        if inode.meta.directory {
            inode.nlink = 0;
        } else {
            inode.nlink -= 1;
        }
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
    fn open_record<'s>(&self, state: &'s State, open: &OpenRef) -> Result<&'s OpenRecord> {
        if open.fs != self.id {
            return Err(Errno::EBADF);
        }
        state.opens.get(&open.id).ok_or(Errno::EBADF)
    }
    fn new_open(&self, state: &mut State, cred: &Cred, ino: u64, access: Access) -> OpenRef {
        let id = state.next_open;
        state.next_open += 1;
        state.opens.insert(
            id,
            OpenRecord {
                ino,
                access,
                uid: cred.identity.id,
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
    /// Check `access` on an existing object, as open(2) does. Only regular files run, and
    /// root needs an execute bit to run one, as `inode::permission` has it.
    fn openable(cred: &Cred, inode: &Inode, access: Access) -> Result<()> {
        match inode.kind() {
            FileKind::Directory if access != Access::Read => {
                return Err(if access == Access::Exec {
                    Errno::EACCES
                } else {
                    Errno::EISDIR
                });
            }
            FileKind::Symlink => return Err(Errno::ELOOP),
            FileKind::Device if access == Access::Exec => return Err(Errno::EACCES),
            _ => {}
        }
        if !Self::may(cred, inode, access.bits()) {
            return Err(Errno::EACCES);
        }
        Ok(())
    }
    /// Resize a file's content, freeing the pages past its new end.
    fn resize(&self, state: &mut State, ino: u64, size: u64, uid: u32) {
        let now = (self.clock)();
        let inode = state.inodes.get_mut(&ino).expect("checked inode");
        let freed = inode.resize(size);
        inode.written_by(uid);
        inode.mtime = now;
        inode.ctime = now;
        state.pages -= freed;
    }

    fn do_lookup(&self, cred: &Cred, dir: &Handle, name: &str) -> Result<Entry> {
        let state = self.state.borrow();
        let dir = self.check(&state, dir)?;
        check_component(name)?;
        Self::searchable(&state, cred, dir)?;
        let ino = *state.inodes[&dir].entries.get(name).ok_or(Errno::ENOENT)?;
        Ok(self.entry(&state, ino))
    }
    fn do_walk(&self, cred: &Cred, dir: &Handle, names: &[String]) -> Result<Walked> {
        let state = self.state.borrow();
        let mut current = self.check(&state, dir)?;
        let mut entries = Vec::new();
        for (index, name) in names.iter().enumerate() {
            check_component(name)?;
            if index > 0 {
                match state.inodes[&current].kind() {
                    FileKind::Symlink => {
                        return Ok(Walked {
                            entries,
                            stop: Some(Stop::Symlink(index - 1)),
                        });
                    }
                    FileKind::Directory => {}
                    _ => {
                        return Ok(Walked {
                            entries,
                            stop: Some(Stop::NotDirectory(index - 1)),
                        });
                    }
                }
            }
            Self::searchable(&state, cred, current)?;
            match state.inodes[&current].entries.get(name.as_str()) {
                Some(ino) => {
                    current = *ino;
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
    fn do_parent(&self, cred: &Cred, dir: &Handle) -> Result<Option<(Entry, String)>> {
        let state = self.state.borrow();
        let dir = self.check(&state, dir)?;
        Self::searchable(&state, cred, dir)?;
        if dir == ROOT {
            return Ok(None);
        }
        // A removed directory has no parent left to name, as getcwd(2) says: ENOENT.
        Self::alive(&state, dir)?;
        let parent = state.inodes[&dir].parent;
        let name = state
            .inodes
            .get(&parent)
            .and_then(|parent| {
                parent
                    .entries
                    .iter()
                    .find(|(_, ino)| **ino == dir)
                    .map(|(name, _)| name.clone())
            })
            .ok_or(Errno::ENOENT)?;
        Ok(Some((self.entry(&state, parent), name)))
    }
    fn do_setattr(&self, cred: &Cred, handle: &Handle, set: &SetAttr) -> Result<Attr> {
        let mut state = self.state.borrow_mut();
        let ino = self.check(&state, handle)?;
        let who = &cred.identity;
        let inode = &state.inodes[&ino];
        if *set == SetAttr::default() {
            return Ok(Self::attr(inode));
        }
        // Every change is checked before any is made.
        let mut meta = inode.meta.clone();
        if let Some(perm) = set.perm {
            inode::chmod(who, &mut meta, perm)?;
        }
        if set.uid.is_some() || set.gid.is_some() {
            inode::chown(who, &mut meta, set.uid, set.gid)?;
        }
        inode::may_set_times(who, &inode.meta, set.atime, set.mtime)?;
        if let Some(size) = set.size {
            match inode.kind() {
                FileKind::Directory => return Err(Errno::EISDIR),
                FileKind::File => {}
                _ => return Err(Errno::EINVAL),
            }
            if !Self::may(cred, inode, WRITE) {
                return Err(Errno::EACCES);
            }
            if size > FILE_MAX {
                return Err(Errno::EFBIG);
            }
        }
        let now = (self.clock)();
        state.inodes.get_mut(&ino).expect("checked inode").meta = meta;
        if let Some(size) = set.size {
            self.resize(&mut state, ino, size, who.id);
        }
        let inode = state.inodes.get_mut(&ino).expect("checked inode");
        if let Some(atime) = inode::time(set.atime, now) {
            inode.atime = atime;
        }
        if let Some(mtime) = inode::time(set.mtime, now) {
            inode.mtime = mtime;
        }
        inode.ctime = now;
        Ok(Self::attr(inode))
    }
    fn do_readdir(&self, cred: &Cred, dir: &Handle) -> Result<Vec<DirEntry>> {
        let state = self.state.borrow();
        let ino = self.check(&state, dir)?;
        let inode = &state.inodes[&ino];
        if !inode.meta.directory {
            return Err(Errno::ENOTDIR);
        }
        if !Self::may(cred, inode, READ) {
            return Err(Errno::EACCES);
        }
        Ok(inode
            .entries
            .iter()
            .map(|(name, ino)| DirEntry {
                name: name.clone(),
                node: NodeId {
                    ino: *ino,
                    generation: self.generation,
                },
                kind: state.inodes[ino].kind(),
            })
            .collect())
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
        check_component(name)?;
        Self::writable_dir(&state, cred, dir)?;
        if state.inodes[&dir].entries.contains_key(name) {
            return Err(Errno::EEXIST);
        }
        let meta = meta(&state.inodes[&dir].meta);
        let ino = self.add(&mut state, dir, name, meta);
        Ok(self.entry(&state, ino))
    }
    fn do_create(
        &self,
        cred: &Cred,
        dir: &Handle,
        name: &str,
        perm: u16,
        exclusive: bool,
        access: Access,
    ) -> Result<(Entry, OpenRef)> {
        if access == Access::Exec {
            return Err(Errno::EINVAL);
        }
        let mut state = self.state.borrow_mut();
        let dir_ino = self.check(&state, dir)?;
        check_component(name)?;
        Self::searchable(&state, cred, dir_ino)?;
        if let Some(ino) = state.inodes[&dir_ino].entries.get(name).copied() {
            if exclusive {
                return Err(Errno::EEXIST);
            }
            // open(O_CREAT) never opens a directory, whatever the access.
            if state.inodes[&ino].meta.directory {
                return Err(Errno::EISDIR);
            }
            Self::openable(cred, &state.inodes[&ino], access)?;
            let open = self.new_open(&mut state, cred, ino, access);
            return Ok((self.entry(&state, ino), open));
        }
        Self::alive(&state, dir_ino)?;
        if !Self::may(cred, &state.inodes[&dir_ino], WRITE) {
            return Err(Errno::EACCES);
        }
        let meta = created(
            &cred.identity,
            &state.inodes[&dir_ino].meta,
            perm,
            false,
            cred.umask,
        );
        let ino = self.add(&mut state, dir_ino, name, meta);
        // The creator gets the access it asked for, whatever the new file's mode, as on Linux.
        let open = self.new_open(&mut state, cred, ino, access);
        Ok((self.entry(&state, ino), open))
    }
    fn do_link(&self, cred: &Cred, target: &Handle, dir: &Handle, name: &str) -> Result<Entry> {
        let mut state = self.state.borrow_mut();
        let target = self.check(&state, target)?;
        let dir = self.check(&state, dir)?;
        check_component(name)?;
        inode::may_link(&cred.identity, &state.inodes[&target].meta)?;
        Self::writable_dir(&state, cred, dir)?;
        if state.inodes[&dir].entries.contains_key(name) {
            return Err(Errno::EEXIST);
        }
        // An unlinked file, though still open, takes no name again.
        if state.inodes[&target].nlink == 0 {
            return Err(Errno::ENOENT);
        }
        let parent = state.inodes.get_mut(&dir).expect("checked directory");
        parent.entries.insert(name.to_string(), target);
        self.touch(parent, true);
        let inode = state.inodes.get_mut(&target).expect("checked target");
        inode.nlink += 1;
        self.touch(inode, false);
        Ok(self.entry(&state, target))
    }
    fn do_remove(&self, cred: &Cred, dir: &Handle, name: &str, directory: bool) -> Result<()> {
        let mut state = self.state.borrow_mut();
        let dir = self.check(&state, dir)?;
        check_component(name)?;
        Self::writable_dir(&state, cred, dir)?;
        let victim = *state.inodes[&dir].entries.get(name).ok_or(Errno::ENOENT)?;
        let inode = &state.inodes[&victim];
        match (directory, inode.meta.directory) {
            (false, true) => return Err(Errno::EISDIR),
            (true, false) => return Err(Errno::ENOTDIR),
            (true, true) if !inode.entries.is_empty() => return Err(Errno::ENOTEMPTY),
            _ => {}
        }
        if !Self::sticky_allows(cred, &state.inodes[&dir], inode) {
            return Err(Errno::EPERM);
        }
        let parent = state.inodes.get_mut(&dir).expect("checked directory");
        parent.entries.remove(name);
        if directory {
            parent.nlink -= 1;
        }
        self.touch(parent, true);
        if let Some(inode) = state.inodes.get_mut(&victim) {
            self.touch(inode, false);
        }
        Self::unname(&mut state, victim);
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
        flags: u32,
    ) -> Result<()> {
        if flags & !RENAME_NOREPLACE != 0 {
            return Err(Errno::EINVAL);
        }
        let mut state = self.state.borrow_mut();
        let from_dir = self.check(&state, from_dir)?;
        let to_dir = self.check(&state, to_dir)?;
        check_component(from)?;
        check_component(to)?;
        Self::writable_dir(&state, cred, from_dir)?;
        Self::writable_dir(&state, cred, to_dir)?;
        let source = *state.inodes[&from_dir]
            .entries
            .get(from)
            .ok_or(Errno::ENOENT)?;
        let moving_dir = state.inodes[&source].meta.directory;
        if !Self::sticky_allows(cred, &state.inodes[&from_dir], &state.inodes[&source]) {
            return Err(Errno::EPERM);
        }
        if moving_dir && Self::is_ancestor(&state, source, to_dir) {
            return Err(Errno::EINVAL);
        }
        // Moving a directory to another parent rewrites its `..`, which needs write permission.
        if moving_dir && from_dir != to_dir && !Self::may(cred, &state.inodes[&source], WRITE) {
            return Err(Errno::EACCES);
        }
        let existing = state.inodes[&to_dir].entries.get(to).copied();
        if let Some(target) = existing {
            if flags & RENAME_NOREPLACE != 0 {
                return Err(Errno::EEXIST);
            }
            if target == source {
                return Ok(());
            }
            let target_inode = &state.inodes[&target];
            match (moving_dir, target_inode.meta.directory) {
                (true, false) => return Err(Errno::ENOTDIR),
                (false, true) => return Err(Errno::EISDIR),
                (true, true) if !target_inode.entries.is_empty() => return Err(Errno::ENOTEMPTY),
                _ => {}
            }
            if !Self::sticky_allows(cred, &state.inodes[&to_dir], target_inode) {
                return Err(Errno::EPERM);
            }
        }
        if let Some(target) = existing {
            state
                .inodes
                .get_mut(&to_dir)
                .expect("checked")
                .entries
                .remove(to);
            if moving_dir {
                state.inodes.get_mut(&to_dir).expect("checked").nlink -= 1;
            }
            Self::unname(&mut state, target);
        }
        let parent = state.inodes.get_mut(&from_dir).expect("checked");
        parent.entries.remove(from);
        if moving_dir {
            parent.nlink -= 1;
        }
        self.touch(parent, true);
        let parent = state.inodes.get_mut(&to_dir).expect("checked");
        parent.entries.insert(to.to_string(), source);
        if moving_dir {
            parent.nlink += 1;
        }
        self.touch(parent, true);
        let inode = state.inodes.get_mut(&source).expect("checked");
        if moving_dir {
            inode.parent = to_dir;
        }
        self.touch(inode, false);
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
        flags: u8,
    ) -> Result<()> {
        let space = xattr::space(name)?;
        let mut state = self.state.borrow_mut();
        let ino = self.check(&state, handle)?;
        let inode = state.inodes.get_mut(&ino).expect("checked inode");
        xattr::settable(&cred.identity, &inode.meta, space)?;
        match space {
            Space::Access | Space::Default => {
                xattr::check_flags(flags, xattr::has_acl(&inode.meta, space))?;
                let entries: Entries = serde_json::from_slice(value).map_err(|_| Errno::EINVAL)?;
                xattr::set_acl(&mut inode.meta, space, entries)?;
            }
            Space::User | Space::Trusted => {
                xattr::check_flags(flags, inode.xattrs.contains_key(name))?;
                xattr::store(&mut inode.xattrs, name, value)?;
            }
        }
        self.touch(inode, false);
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
        self.touch(inode, false);
        Ok(())
    }
    fn do_open(
        &self,
        cred: &Cred,
        handle: &Handle,
        access: Access,
        truncate: bool,
    ) -> Result<OpenRef> {
        let mut state = self.state.borrow_mut();
        let ino = self.check(&state, handle)?;
        Self::openable(cred, &state.inodes[&ino], access)?;
        if truncate {
            if !access.writes() {
                return Err(Errno::EINVAL);
            }
            if state.inodes[&ino].kind() == FileKind::File {
                self.resize(&mut state, ino, 0, cred.identity.id);
            }
        }
        Ok(self.new_open(&mut state, cred, ino, access))
    }
    fn do_read(&self, open: &OpenRef, offset: u64, len: usize) -> Result<Vec<u8>> {
        let state = self.state.borrow();
        let record = self.open_record(&state, open)?;
        if !record.access.reads() {
            return Err(Errno::EBADF);
        }
        let inode = &state.inodes[&record.ino];
        if inode.meta.directory {
            return Err(Errno::EISDIR);
        }
        Ok(inode.read(offset, len.min(RW_MAX)))
    }
    fn do_write(&self, open: &OpenRef, at: WriteAt, data: &[u8]) -> Result<Written> {
        let mut state = self.state.borrow_mut();
        let record = self.open_record(&state, open)?;
        if !record.access.writes() {
            return Err(Errno::EBADF);
        }
        let (ino, uid) = (record.ino, record.uid);
        let inode = &state.inodes[&ino];
        // The end is read here, with the write, so appends never overwrite each other.
        let offset = match at {
            WriteAt::Offset(offset) => offset,
            WriteAt::End => inode.size,
        };
        // Nothing to write changes nothing: not the size, the times nor the mode.
        if data.is_empty() {
            return Ok(Written { offset, len: 0 });
        }
        // As Linux: nothing goes at or past the largest offset (EFBIG); before it, what fits.
        if offset >= FILE_MAX {
            return Err(Errno::EFBIG);
        }
        let fits = usize::try_from(FILE_MAX - offset).unwrap_or(usize::MAX);
        let data = &data[..data.len().min(fits).min(RW_MAX)];
        let needed = inode.missing(offset, data.len());
        if state.pages + needed > self.capacity {
            return Err(Errno::ENOSPC);
        }
        state.pages += needed;
        let now = (self.clock)();
        let inode = state.inodes.get_mut(&ino).expect("open inode");
        inode.write(offset, data);
        inode.written_by(uid);
        inode.mtime = now;
        inode.ctime = now;
        Ok(Written {
            offset,
            len: data.len(),
        })
    }
    fn do_truncate(&self, open: &OpenRef, size: u64) -> Result<()> {
        let mut state = self.state.borrow_mut();
        let record = self.open_record(&state, open)?;
        if !record.access.writes() {
            return Err(Errno::EINVAL);
        }
        if size > FILE_MAX {
            return Err(Errno::EFBIG);
        }
        let (ino, uid) = (record.ino, record.uid);
        self.resize(&mut state, ino, size, uid);
        Ok(())
    }
    fn conflict(
        state: &State,
        ino: u64,
        owner: u64,
        kind: LockKind,
        range: LockRange,
    ) -> Option<Conflict> {
        state.locks.get(&ino)?.iter().find_map(|lock| {
            (lock.owner != owner
                && lock.range.overlaps(range)
                && (kind == LockKind::Exclusive || lock.kind == LockKind::Exclusive))
                .then_some(Conflict {
                    kind: lock.kind,
                    range: lock.range,
                    owner: lock.owner,
                })
        })
    }
    fn do_lock(&self, open: &OpenRef, kind: LockKind, range: LockRange) -> Result<()> {
        let mut state = self.state.borrow_mut();
        let ino = self.open_record(&state, open)?.ino;
        if Self::conflict(&state, ino, open.id, kind, range).is_some() {
            return Err(Errno::EAGAIN);
        }
        let locks = state.locks.entry(ino).or_default();
        // The new lock replaces this owner's within its range, whatever their kind; what lies
        // outside stays, and locks of the same kind it meets join it, as Linux merges them.
        carve(locks, open.id, range);
        let mut merged = range;
        locks.retain(|lock| {
            let joins = lock.owner == open.id && lock.kind == kind && lock.range.touches(merged);
            if joins {
                merged = LockRange::between(
                    merged.start.min(lock.range.start),
                    merged.end().max(lock.range.end()),
                );
            }
            !joins
        });
        locks.push(Lock {
            owner: open.id,
            kind,
            range: merged,
        });
        Ok(())
    }
    fn do_unlock(&self, open: &OpenRef, range: LockRange) -> Result<()> {
        let mut state = self.state.borrow_mut();
        let ino = self.open_record(&state, open)?.ino;
        if let Some(locks) = state.locks.get_mut(&ino) {
            carve(locks, open.id, range);
        }
        Ok(())
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
        Ok(())
    }
}

macro_rules! ready {
    ($body:expr) => {
        Box::pin(std::future::ready($body))
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
        cred: &'a Cred,
        dir: &'a Handle,
    ) -> BoxFuture<'a, Option<(Entry, String)>> {
        ready!(self.do_parent(cred, dir))
    }
    fn getattr<'a>(&'a self, _cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Attr> {
        let state = self.state.borrow();
        ready!(
            self.check(&state, handle)
                .map(|ino| Self::attr(&state.inodes[&ino]))
        )
    }
    fn setattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        set: &'a SetAttr,
    ) -> BoxFuture<'a, Attr> {
        ready!(self.do_setattr(cred, handle, set))
    }
    fn readdir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle) -> BoxFuture<'a, Vec<DirEntry>> {
        ready!(self.do_readdir(cred, dir))
    }
    fn readlink<'a>(&'a self, _cred: &'a Cred, link: &'a Handle) -> BoxFuture<'a, String> {
        let state = self.state.borrow();
        ready!(
            self.check(&state, link).and_then(|ino| state.inodes[&ino]
                .meta
                .link
                .clone()
                .ok_or(Errno::EINVAL))
        )
    }
    fn create<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        perm: u16,
        exclusive: bool,
        access: Access,
    ) -> BoxFuture<'a, (Entry, OpenRef)> {
        ready!(self.do_create(cred, dir, name, perm, exclusive, access))
    }
    fn mkdir<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        perm: u16,
    ) -> BoxFuture<'a, Entry> {
        // `created` keeps the sticky bit asked for, as mkdir(2) does.
        ready!(self.make(cred, dir, name, |parent| created(
            &cred.identity,
            parent,
            perm,
            true,
            cred.umask
        )))
    }
    fn mknod<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        perm: u16,
        rdev: &'a str,
    ) -> BoxFuture<'a, Entry> {
        if cred.identity.id != 0 {
            return ready!(Err(Errno::EPERM));
        }
        ready!(self.make(cred, dir, name, |parent| {
            let mut node = created(&cred.identity, parent, perm, false, cred.umask);
            node.rdev = Some(rdev.to_string());
            node
        }))
    }
    fn symlink<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        target: &'a str,
    ) -> BoxFuture<'a, Entry> {
        if target.is_empty() || target.len() > os_core::permissions::LINK_TARGET_MAX {
            return ready!(Err(if target.is_empty() {
                Errno::ENOENT
            } else {
                Errno::ENAMETOOLONG
            }));
        }
        ready!(self.make(cred, dir, name, |parent| {
            let mut node = created(&cred.identity, parent, 0o777, false, 0);
            node.mode = 0o777;
            node.acl = None;
            node.link = Some(target.to_string());
            node
        }))
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
        ready!(self.do_remove(cred, dir, name, false))
    }
    fn rmdir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        ready!(self.do_remove(cred, dir, name, true))
    }
    fn rename<'a>(
        &'a self,
        cred: &'a Cred,
        from_dir: &'a Handle,
        from: &'a str,
        to_dir: &'a Handle,
        to: &'a str,
        flags: u32,
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
        flags: u8,
    ) -> BoxFuture<'a, ()> {
        ready!(self.do_setxattr(cred, handle, name, value, flags))
    }
    fn listxattr<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Vec<String>> {
        let state = self.state.borrow();
        ready!(self.check(&state, handle).map(|ino| {
            let inode = &state.inodes[&ino];
            xattr::listed(&cred.identity, &inode.meta, inode.xattrs.keys())
        }))
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
        let state = self.state.borrow();
        ready!(Ok(StatFs {
            block_size: PAGE_BYTES,
            blocks: self.capacity,
            blocks_free: self.capacity.saturating_sub(state.pages),
            files: state.inodes.len() as u64,
            files_free: u64::MAX - state.next_ino,
            name_max: abi::NAME_MAX as u64,
        }))
    }
    fn open<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        access: Access,
        truncate: bool,
    ) -> BoxFuture<'a, OpenRef> {
        ready!(self.do_open(cred, handle, access, truncate))
    }
    fn read<'a>(&'a self, open: &'a OpenRef, offset: u64, len: usize) -> BoxFuture<'a, Vec<u8>> {
        ready!(self.do_read(open, offset, len))
    }
    fn write<'a>(
        &'a self,
        open: &'a OpenRef,
        at: WriteAt,
        data: &'a [u8],
    ) -> BoxFuture<'a, Written> {
        ready!(self.do_write(open, at, data))
    }
    fn truncate<'a>(&'a self, open: &'a OpenRef, size: u64) -> BoxFuture<'a, ()> {
        ready!(self.do_truncate(open, size))
    }
    fn fsync<'a>(&'a self, open: &'a OpenRef, _datasync: bool) -> BoxFuture<'a, ()> {
        // Nothing here is durable (`Durability::Volatile`): there is nothing to wait for.
        let state = self.state.borrow();
        ready!(self.open_record(&state, open).map(|_| ()))
    }
    fn lock<'a>(
        &'a self,
        open: &'a OpenRef,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        ready!(self.do_lock(open, kind, range))
    }
    fn unlock<'a>(&'a self, open: &'a OpenRef, range: LockRange) -> BoxFuture<'a, ()> {
        ready!(self.do_unlock(open, range))
    }
    fn getlk<'a>(
        &'a self,
        open: &'a OpenRef,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, Option<Conflict>> {
        let state = self.state.borrow();
        ready!(
            self.open_record(&state, open)
                .map(|record| Self::conflict(&state, record.ino, open.id, kind, range))
        )
    }
    fn release<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        ready!(self.do_release(open))
    }
}

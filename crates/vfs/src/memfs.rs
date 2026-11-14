//! An in-memory filesystem with Linux semantics: the reference the other drivers are tested
//! against (contract §3, every capability "yes"), and the instance's tmpfs (#51). Permissions
//! are `os_core::permissions`' (owner/group/other, ACLs, sticky directories, protected hard
//! links, setgid inheritance, umask and default ACLs), so they match the server's.
//!
//! Inode numbers are never used again, so a handle's generation only has to say which filesystem
//! instance issued it. A file's content lives until its last name and its last open reference
//! are gone.

use crate::{
    Access, Attr, BoxFuture, Conflict, Cred, DirEntry, Entry, FileKind, Filesystem, FsId, Handle,
    LockKind, LockRange, NodeId, OpenRef, RENAME_NOREPLACE, Result, SetAttr, StatFs, Stop, Walked,
    profiles, valid_component,
};
use abi::Errno;
use abi::contract::FsCapabilities;
use os_core::permissions::{EXEC, Node, READ, SETGID, SETUID, STICKY, WRITE, created};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};

const ROOT: u64 = 1;
/// Extended attribute values, as the server allows (4 KiB per value).
const XATTR_MAX: usize = 4096;

/// Seconds and nanoseconds since 1970. The kernel passes the host's clock; tests count.
pub type Clock = Box<dyn Fn() -> (u64, u32)>;

struct Inode {
    meta: Node,
    nlink: u32,
    data: Vec<u8>,
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
}

struct OpenRecord {
    ino: u64,
    access: Access,
    uid: u32,
}

struct Lock {
    owner: u64,
    kind: LockKind,
    range: LockRange,
}

struct State {
    inodes: HashMap<u64, Inode>,
    next_ino: u64,
    next_open: u64,
    opens: HashMap<u64, OpenRecord>,
    locks: HashMap<u64, Vec<Lock>>,
}

pub struct MemFs {
    id: FsId,
    generation: u64,
    clock: Clock,
    state: RefCell<State>,
}

impl MemFs {
    /// A filesystem whose root directory is owned by `owner`:`group` with `perm`.
    pub fn new(id: FsId, generation: u64, owner: u32, group: u32, perm: u16, clock: Clock) -> Self {
        let now = clock();
        let mut root = Node::directory(owner, group, perm);
        root.ino = ROOT;
        let inode = Inode {
            meta: root,
            nlink: 2,
            data: Vec::new(),
            entries: BTreeMap::new(),
            parent: ROOT,
            xattrs: BTreeMap::new(),
            atime: now,
            mtime: now,
            ctime: now,
            opens: 0,
        };
        Self {
            id,
            generation,
            clock,
            state: RefCell::new(State {
                inodes: HashMap::from([(ROOT, inode)]),
                next_ino: ROOT + 1,
                next_open: 1,
                opens: HashMap::new(),
                locks: HashMap::new(),
            }),
        }
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
                FileKind::Directory => 4096,
                _ => inode.data.len() as u64,
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
        cred.identity.allows(&inode.meta, bits)
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
    /// A directory `cred` may add names to or remove names from.
    fn writable_dir(state: &State, cred: &Cred, ino: u64) -> Result<()> {
        Self::searchable(state, cred, ino)?;
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
    fn name(name: &str) -> Result<()> {
        if valid_component(name) {
            Ok(())
        } else {
            Err(Errno::EINVAL)
        }
    }
    fn touch(&self, inode: &mut Inode, content: bool) {
        let now = (self.clock)();
        if content {
            inode.mtime = now;
        }
        inode.ctime = now;
    }
    fn add(&self, state: &mut State, dir: u64, name: &str, meta: Node, data: Vec<u8>) -> u64 {
        let ino = state.next_ino;
        state.next_ino += 1;
        let now = (self.clock)();
        let directory = meta.directory;
        let mut meta = meta;
        meta.ino = ino;
        state.inodes.insert(
            ino,
            Inode {
                meta,
                nlink: if directory { 2 } else { 1 },
                data,
                entries: BTreeMap::new(),
                parent: dir,
                xattrs: BTreeMap::new(),
                atime: now,
                mtime: now,
                ctime: now,
                opens: 0,
            },
        );
        let parent = state.inodes.get_mut(&dir).expect("parent directory");
        parent.entries.insert(name.to_string(), ino);
        if directory {
            parent.nlink += 1;
        }
        self.touch(parent, true);
        ino
    }
    /// Free an object with no name and no open reference left.
    fn reclaim(state: &mut State, ino: u64) {
        if state
            .inodes
            .get(&ino)
            .is_some_and(|i| i.nlink == 0 && i.opens == 0)
        {
            state.inodes.remove(&ino);
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
    fn is_ancestor(state: &State, ancestor: u64, mut ino: u64) -> bool {
        loop {
            if ino == ancestor {
                return true;
            }
            if ino == ROOT {
                return false;
            }
            ino = state.inodes[&ino].parent;
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
    /// Check `access` on an existing object, as open(2) does.
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
            // Even root needs one execute bit, and only regular files run.
            FileKind::File | FileKind::Device
                if access == Access::Exec
                    && (inode.kind() != FileKind::File || inode.meta.mode & 0o111 == 0) =>
            {
                return Err(Errno::EACCES);
            }
            _ => {}
        }
        if !Self::may(cred, inode, access.bits()) {
            return Err(Errno::EACCES);
        }
        Ok(())
    }

    fn do_lookup(&self, cred: &Cred, dir: &Handle, name: &str) -> Result<Entry> {
        let state = self.state.borrow();
        let dir = self.check(&state, dir)?;
        Self::name(name)?;
        Self::searchable(&state, cred, dir)?;
        let ino = *state.inodes[&dir].entries.get(name).ok_or(Errno::ENOENT)?;
        Ok(self.entry(&state, ino))
    }
    fn do_walk(&self, cred: &Cred, dir: &Handle, names: &[String]) -> Result<Walked> {
        let state = self.state.borrow();
        let mut current = self.check(&state, dir)?;
        let mut entries = Vec::new();
        for (index, name) in names.iter().enumerate() {
            Self::name(name)?;
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
        let parent = state.inodes[&dir].parent;
        let name = state.inodes[&parent]
            .entries
            .iter()
            .find(|(_, ino)| **ino == dir)
            .map(|(name, _)| name.clone())
            .ok_or(Errno::ESTALE)?;
        Ok(Some((self.entry(&state, parent), name)))
    }
    fn do_setattr(&self, cred: &Cred, handle: &Handle, set: &SetAttr) -> Result<Attr> {
        let mut state = self.state.borrow_mut();
        let ino = self.check(&state, handle)?;
        let who = &cred.identity;
        let inode = &state.inodes[&ino];
        let owner = who.id == 0 || who.id == inode.meta.owner;
        if (set.perm.is_some() || set.atime.is_some() || set.mtime.is_some()) && !owner {
            return Err(Errno::EPERM);
        }
        if set
            .uid
            .is_some_and(|uid| uid != inode.meta.owner && who.id != 0)
        {
            return Err(Errno::EPERM);
        }
        if set.gid.is_some_and(|gid| {
            gid != inode.meta.group && who.id != 0 && !(owner && who.groups.contains(&gid))
        }) {
            return Err(Errno::EPERM);
        }
        if set.size.is_some() {
            if inode.meta.directory {
                return Err(Errno::EISDIR);
            }
            if !Self::may(cred, inode, WRITE) {
                return Err(Errno::EACCES);
            }
        }
        let now = (self.clock)();
        let inode = state.inodes.get_mut(&ino).expect("checked inode");
        if let Some(perm) = set.perm {
            let mut perm = perm & 0o7777;
            // Without root, setgid needs the file's group to be one of the caller's.
            if who.id != 0 && !inode.meta.directory && !who.groups.contains(&inode.meta.group) {
                perm &= !SETGID;
            }
            inode.meta.mode = perm;
        }
        let changing_owner = set.uid.is_some_and(|u| u != inode.meta.owner)
            || set.gid.is_some_and(|g| g != inode.meta.group);
        if let Some(uid) = set.uid {
            inode.meta.owner = uid;
        }
        if let Some(gid) = set.gid {
            inode.meta.group = gid;
        }
        if changing_owner && inode.kind() == FileKind::File {
            inode.meta.mode &= !SETUID;
            if inode.meta.mode & 0o010 != 0 {
                inode.meta.mode &= !SETGID;
            }
        }
        if let Some(size) = set.size {
            inode.data.resize(size as usize, 0);
            inode.mtime = now;
        }
        if let Some(atime) = set.atime {
            inode.atime = atime;
        }
        if let Some(mtime) = set.mtime {
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
        Self::name(name)?;
        Self::writable_dir(&state, cred, dir)?;
        if state.inodes[&dir].entries.contains_key(name) {
            return Err(Errno::EEXIST);
        }
        let meta = meta(&state.inodes[&dir].meta);
        let ino = self.add(&mut state, dir, name, meta, Vec::new());
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
        Self::name(name)?;
        Self::searchable(&state, cred, dir_ino)?;
        if let Some(ino) = state.inodes[&dir_ino].entries.get(name).copied() {
            if exclusive {
                return Err(Errno::EEXIST);
            }
            Self::openable(cred, &state.inodes[&ino], access)?;
            let open = self.new_open(&mut state, cred, ino, access);
            return Ok((self.entry(&state, ino), open));
        }
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
        let ino = self.add(&mut state, dir_ino, name, meta, Vec::new());
        // The creator gets the access it asked for, whatever the new file's mode, as on Linux.
        let open = self.new_open(&mut state, cred, ino, access);
        Ok((self.entry(&state, ino), open))
    }
    fn do_link(&self, cred: &Cred, target: &Handle, dir: &Handle, name: &str) -> Result<Entry> {
        let mut state = self.state.borrow_mut();
        let target = self.check(&state, target)?;
        let dir = self.check(&state, dir)?;
        Self::name(name)?;
        let inode = &state.inodes[&target];
        if inode.meta.directory {
            return Err(Errno::EPERM);
        }
        // protected_hardlinks: without root, own the file or be able to read and write it.
        if cred.identity.id != 0
            && cred.identity.id != inode.meta.owner
            && !Self::may(cred, inode, READ | WRITE)
        {
            return Err(Errno::EPERM);
        }
        Self::writable_dir(&state, cred, dir)?;
        if state.inodes[&dir].entries.contains_key(name) {
            return Err(Errno::EEXIST);
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
        Self::name(name)?;
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
        Self::name(from)?;
        Self::name(to)?;
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
    /// The permission an extended attribute's namespace needs: `user.*` read or write,
    /// `trusted.*` root; others are not supported.
    fn xattr_allowed(cred: &Cred, inode: &Inode, name: &str, write: bool) -> Result<()> {
        if name.starts_with("trusted.") {
            return if cred.identity.id == 0 {
                Ok(())
            } else {
                Err(Errno::EPERM)
            };
        }
        if !name.starts_with("user.") || name.len() == 5 {
            return Err(Errno::EOPNOTSUPP);
        }
        if !Self::may(cred, inode, if write { WRITE } else { READ }) {
            return Err(Errno::EACCES);
        }
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
            let now = (self.clock)();
            let inode = state.inodes.get_mut(&ino).expect("checked");
            inode.data.clear();
            inode.mtime = now;
            inode.ctime = now;
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
        let start = (offset as usize).min(inode.data.len());
        let end = start.saturating_add(len).min(inode.data.len());
        Ok(inode.data[start..end].to_vec())
    }
    fn do_write(&self, open: &OpenRef, offset: u64, data: &[u8]) -> Result<usize> {
        let mut state = self.state.borrow_mut();
        let record = self.open_record(&state, open)?;
        if !record.access.writes() {
            return Err(Errno::EBADF);
        }
        let (ino, uid) = (record.ino, record.uid);
        let now = (self.clock)();
        let inode = state.inodes.get_mut(&ino).expect("open inode");
        let start = offset as usize;
        let end = start.checked_add(data.len()).ok_or(Errno::EFBIG)?;
        if inode.data.len() < end {
            inode.data.resize(end, 0);
        }
        inode.data[start..end].copy_from_slice(data);
        inode.mtime = now;
        inode.ctime = now;
        // A write by anyone but root clears setuid, and setgid if the group may execute.
        if uid != 0 {
            inode.meta.mode &= !SETUID;
            if inode.meta.mode & 0o010 != 0 {
                inode.meta.mode &= !SETGID;
            }
        }
        Ok(data.len())
    }
    fn do_truncate(&self, open: &OpenRef, size: u64) -> Result<()> {
        let mut state = self.state.borrow_mut();
        let record = self.open_record(&state, open)?;
        if !record.access.writes() {
            return Err(Errno::EINVAL);
        }
        let ino = record.ino;
        let now = (self.clock)();
        let inode = state.inodes.get_mut(&ino).expect("open inode");
        inode.data.resize(size as usize, 0);
        inode.mtime = now;
        inode.ctime = now;
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
        locks.retain(|lock| lock.owner != open.id || !lock.range.overlaps(range));
        locks.push(Lock {
            owner: open.id,
            kind,
            range,
        });
        Ok(())
    }
    fn do_unlock(&self, open: &OpenRef, range: LockRange) -> Result<()> {
        let mut state = self.state.borrow_mut();
        let ino = self.open_record(&state, open)?.ino;
        if let Some(locks) = state.locks.get_mut(&ino) {
            locks.retain(|lock| lock.owner != open.id || !lock.range.overlaps(range));
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
        let state = self.state.borrow();
        ready!(self.check(&state, handle).and_then(|ino| {
            let inode = &state.inodes[&ino];
            Self::xattr_allowed(cred, inode, name, false)?;
            inode.xattrs.get(name).cloned().ok_or(Errno::ENODATA)
        }))
    }
    fn setxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
        value: &'a [u8],
    ) -> BoxFuture<'a, ()> {
        let mut state = self.state.borrow_mut();
        ready!(self.check(&state, handle).and_then(|ino| {
            Self::xattr_allowed(cred, &state.inodes[&ino], name, true)?;
            if value.len() > XATTR_MAX {
                return Err(Errno::ERANGE);
            }
            let inode = state.inodes.get_mut(&ino).expect("checked");
            inode.xattrs.insert(name.to_string(), value.to_vec());
            self.touch(inode, false);
            Ok(())
        }))
    }
    fn listxattr<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Vec<String>> {
        let state = self.state.borrow();
        ready!(self.check(&state, handle).map(|ino| {
            state.inodes[&ino]
                .xattrs
                .keys()
                .filter(|name| name.starts_with("user.") || cred.identity.id == 0)
                .cloned()
                .collect()
        }))
    }
    fn removexattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, ()> {
        let mut state = self.state.borrow_mut();
        ready!(self.check(&state, handle).and_then(|ino| {
            Self::xattr_allowed(cred, &state.inodes[&ino], name, true)?;
            let inode = state.inodes.get_mut(&ino).expect("checked");
            inode.xattrs.remove(name).ok_or(Errno::ENODATA)?;
            self.touch(inode, false);
            Ok(())
        }))
    }
    fn statfs<'a>(&'a self, _cred: &'a Cred) -> BoxFuture<'a, StatFs> {
        let state = self.state.borrow();
        let used: usize = state.inodes.values().map(|inode| inode.data.len()).sum();
        ready!(Ok(StatFs {
            block_size: 4096,
            blocks: (used as u64).div_ceil(4096),
            blocks_free: 0,
            files: state.inodes.len() as u64,
            files_free: u64::MAX - state.next_ino,
            name_max: 255,
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
    fn write<'a>(&'a self, open: &'a OpenRef, offset: u64, data: &'a [u8]) -> BoxFuture<'a, usize> {
        ready!(self.do_write(open, offset, data))
    }
    fn truncate<'a>(&'a self, open: &'a OpenRef, size: u64) -> BoxFuture<'a, ()> {
        ready!(self.do_truncate(open, size))
    }
    fn fsync<'a>(&'a self, open: &'a OpenRef, _datasync: bool) -> BoxFuture<'a, ()> {
        // Memory is this filesystem's durability point: there is nothing further to wait for.
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

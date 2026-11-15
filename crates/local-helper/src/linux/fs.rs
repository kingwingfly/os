//! Filesystem engine for `os-local-helper`: sessions, ceiling grants, durable metadata store,
//! confined `openat2` handle resolution, `renameat2(RENAME_NOREPLACE)`, `fsync`/`fdatasync`, and
//! real host locking.

use super::locks::LockManager;
use super::store::{HostInodeKey, ROOT_INO, StateStore, StoredNode};
use super::sys::{self, HostKind, HostStat};
use abi::Errno;
use abi::contract::{Boundary, FsCapabilities, Hello, negotiate};
use abi::fs::{
    Access, DirEntry, Entry, FILE_MAX, FileType, FsId, Handle, Metadata, NodeId, OpenOptions,
    OpenRef, RenameFlags, SetAttr, Stop, Walked, WriteAt, Written, XattrFlags, check_component,
};
use abi::local_helper::{
    AttachReply, Call, DATA_MAX, HelloReply, LEASE_SECONDS, ReadReply, RenewReply, Request,
    VERSION, WireCred,
};
use os_core::acl::Entries;
use os_core::inode;
use os_core::permissions::{EXEC, Identity, Node, READ, WRITE, created};
use os_core::xattr::{self, Space};
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const OPEN_TICKET_CAP: usize = 4096;
const HANDSHAKE_CAP: usize = 256;

#[derive(Clone)]
enum OpenTicketState {
    Cancelled,
    Created { entry: Entry, open: OpenRef },
    Opened { open: OpenRef },
}

struct OpenHandle {
    id: u64,
    node_id: NodeId,
    subfs_relpath: String,
    host_key: HostInodeKey,
    access: Access,
    kind: HostKind,
    fd: OwnedFd,
}

struct Session {
    last_seen: Instant,
    owner: (u32, u32),
    grant: abi::local_helper::HelperGrant,
    opens: HashMap<u64, OpenHandle>,
    open_tickets: HashMap<String, OpenTicketState>,
    open_ticket_order: VecDeque<String>,
}

struct ResolvedHandle {
    ino: u64,
    relpath: String,
    unlinked: bool,
    fd: OwnedFd,
    stat: HostStat,
    key: HostInodeKey,
}

pub struct HelperEngine {
    canonical_root: PathBuf,
    root_fd: OwnedFd,
    store: StateStore,
    locks: LockManager,
    handshakes: HashMap<String, Instant>,
    sessions: HashMap<String, Session>,
    next_open_id: u64,
    ceiling: abi::local_helper::HelperGrant,
}

impl HelperEngine {
    pub fn open(
        canonical_root: &Path,
        state_dir: &Path,
        root_fd: OwnedFd,
        write: bool,
        execute: bool,
    ) -> Result<Self, Errno> {
        sys::verify_fd_inside_root(canonical_root, root_fd.as_fd())?;
        let root_stx = sys::statx_fd(root_fd.as_fd())?;
        if root_stx.kind != HostKind::Dir {
            return Err(Errno::ENOTDIR);
        }
        let root_key = HostInodeKey::from_root(root_fd.as_fd(), &root_stx)?;
        let store = StateStore::open(canonical_root, state_dir, root_key)?;
        Ok(Self {
            canonical_root: canonical_root.to_path_buf(),
            root_fd,
            store,
            locks: LockManager::new(),
            handshakes: HashMap::new(),
            sessions: HashMap::new(),
            next_open_id: 1,
            ceiling: abi::local_helper::HelperGrant { write, execute },
        })
    }

    pub fn fs_id(&self) -> &FsId {
        self.store.fs_id()
    }

    pub fn capabilities() -> FsCapabilities {
        os_vfs::profiles::HELPER
    }

    #[cfg(test)]
    pub fn state_file_path(&self) -> &Path {
        self.store.state_file_path()
    }

    #[cfg(test)]
    pub fn force_session_idle(&mut self, session: &str, elapsed: Duration) {
        if let Some(s) = self.sessions.get_mut(session) {
            s.last_seen = Instant::now() - elapsed;
        }
    }

    /// Expire inactive sessions so crashed/detached tabs cannot leave descriptors or host locks
    /// orphaned.
    pub fn sweep_expired(&mut self) {
        let now = Instant::now();
        let ttl = Duration::from_secs(LEASE_SECONDS);
        self.handshakes
            .retain(|_, issued| now.saturating_duration_since(*issued) < ttl);
        let expired: Vec<String> = self
            .sessions
            .iter()
            .filter(|&(_, s)| now.saturating_duration_since(s.last_seen) >= ttl)
            .map(|(id, _)| id.clone())
            .collect();
        for session_id in expired {
            let _ = self.close_session(&session_id);
        }
    }

    pub fn handle_request(&mut self, request: Request) -> Result<Value, Errno> {
        self.sweep_expired();
        match request {
            Request::Hello(hello) => self.handle_hello(hello),
            Request::Attach {
                version,
                client_id,
                cred,
                grant,
                handshake,
            } => self.handle_attach(version, &client_id, &cred, grant, &handshake),
            Request::Renew { version, session } => self.handle_renew(version, &session),
            Request::Detach { version, session } => {
                if version != VERSION {
                    return Err(Errno::EPROTONOSUPPORT);
                }
                self.close_session(&session)?;
                Ok(json!({}))
            }
            Request::Call {
                version,
                session,
                cred,
                call,
            } => self.handle_call(version, &session, &cred, call),
        }
    }

    fn handle_hello(&mut self, client: Hello) -> Result<Value, Errno> {
        let ours = Hello {
            boundary: Boundary::LocalHelper,
            versions: vec![VERSION],
        };
        let Some(version) = negotiate(&ours, &client) else {
            return Err(Errno::EPROTONOSUPPORT);
        };
        let now = Instant::now();
        let ttl = Duration::from_secs(LEASE_SECONDS);
        self.handshakes
            .retain(|_, issued| now.saturating_duration_since(*issued) < ttl);
        while self.handshakes.len() >= HANDSHAKE_CAP {
            if let Some(oldest) = self
                .handshakes
                .iter()
                .min_by_key(|(_, ts)| **ts)
                .map(|(k, _)| k.clone())
            {
                self.handshakes.remove(&oldest);
            } else {
                break;
            }
        }
        let handshake = sys::hex_encode(&sys::random_bytes::<32>()?);
        self.handshakes.insert(handshake.clone(), now);
        let reply = HelloReply {
            boundary: Boundary::LocalHelper,
            version,
            write: self.ceiling.write,
            execute: self.ceiling.execute,
            handshake,
        };
        serde_json::to_value(reply).map_err(|_| Errno::EIO)
    }

    fn handle_attach(
        &mut self,
        version: u32,
        client_id: &str,
        cred: &WireCred,
        requested: abi::local_helper::HelperGrant,
        handshake: &str,
    ) -> Result<Value, Errno> {
        if version != VERSION {
            return Err(Errno::EPROTONOSUPPORT);
        }
        let now = Instant::now();
        let ttl = Duration::from_secs(LEASE_SECONDS);
        let Some(issued) = (!handshake.is_empty())
            .then(|| self.handshakes.remove(handshake))
            .flatten()
        else {
            return Err(Errno::EPROTONOSUPPORT);
        };
        if now.saturating_duration_since(issued) >= ttl {
            return Err(Errno::EPROTONOSUPPORT);
        }
        if client_id.is_empty() || client_id.len() > 128 {
            return Err(Errno::EINVAL);
        }
        sys::verify_fd_inside_root(&self.canonical_root, self.root_fd.as_fd())?;
        let root_stx = sys::statx_fd(self.root_fd.as_fd())?;
        let root_key = HostInodeKey::from_root(self.root_fd.as_fd(), &root_stx)?;
        let root_handle = self
            .store
            .ensure_root_node(&root_key, cred.id, cred.group)?;

        let session_id = sys::hex_encode(&sys::random_bytes::<32>()?);
        let grant = abi::local_helper::HelperGrant {
            write: self.ceiling.write && requested.write,
            execute: self.ceiling.execute && requested.execute,
        };
        self.sessions.insert(
            session_id.clone(),
            Session {
                last_seen: Instant::now(),
                owner: (cred.id, cred.group),
                grant,
                opens: HashMap::new(),
                open_tickets: HashMap::new(),
                open_ticket_order: VecDeque::new(),
            },
        );
        let reply = AttachReply {
            version: VERSION,
            session: session_id,
            fs: self.store.fs_id().clone(),
            root: root_handle,
            capabilities: Self::capabilities(),
            grant,
            lease_seconds: LEASE_SECONDS,
        };
        serde_json::to_value(reply).map_err(|_| Errno::EIO)
    }

    fn handle_renew(&mut self, version: u32, session_id: &str) -> Result<Value, Errno> {
        if version != VERSION {
            return Err(Errno::EPROTONOSUPPORT);
        }
        let Some(session) = self.sessions.get_mut(session_id) else {
            return Err(Errno::ENODEV);
        };
        session.last_seen = Instant::now();
        serde_json::to_value(RenewReply {
            lease_seconds: LEASE_SECONDS,
        })
        .map_err(|_| Errno::EIO)
    }

    fn close_session(&mut self, session_id: &str) -> Result<(), Errno> {
        let Some(mut session) = self.sessions.remove(session_id) else {
            return Err(Errno::ENODEV);
        };
        let opens: Vec<OpenHandle> = session.opens.drain().map(|(_, o)| o).collect();
        for open in opens {
            let ino = open.node_id.ino;
            self.locks.release_open(open.id);
            drop(open.fd);
            let still_open = self.is_ino_open(ino);
            let _ = self.store.gc_unlinked(ino, still_open);
        }
        Ok(())
    }

    fn is_ino_open(&self, ino: u64) -> bool {
        self.sessions
            .values()
            .any(|s| s.opens.values().any(|o| o.node_id.ino == ino))
    }

    fn session_context(
        &mut self,
        session_id: &str,
    ) -> Result<(abi::local_helper::HelperGrant, (u32, u32)), Errno> {
        let Some(s) = self.sessions.get_mut(session_id) else {
            return Err(Errno::ENODEV);
        };
        s.last_seen = Instant::now();
        Ok((s.grant, s.owner))
    }

    fn handle_call(
        &mut self,
        version: u32,
        session_id: &str,
        cred: &WireCred,
        call: Call,
    ) -> Result<Value, Errno> {
        if version != VERSION {
            return Err(Errno::EPROTONOSUPPORT);
        }
        let (grant, owner) = self.session_context(session_id)?;
        let identity = to_identity(cred);

        match call {
            Call::Lookup { dir, name } => {
                let entry = self.do_lookup(owner, &identity, &dir, &name)?;
                serde_json::to_value(entry).map_err(|_| Errno::EIO)
            }
            Call::Walk { dir, names } => {
                let walked = self.do_walk(owner, &identity, &dir, &names)?;
                serde_json::to_value(walked).map_err(|_| Errno::EIO)
            }
            Call::Parent { dir } => {
                let res = self.do_parent(owner, &dir)?;
                serde_json::to_value(res).map_err(|_| Errno::EIO)
            }
            Call::Metadata { handle } => {
                let meta = self.do_metadata(&handle)?;
                serde_json::to_value(meta).map_err(|_| Errno::EIO)
            }
            Call::OpenMetadata { open } => {
                let meta = self.do_open_metadata(session_id, &open)?;
                serde_json::to_value(meta).map_err(|_| Errno::EIO)
            }
            Call::Setattr { handle, attr } => {
                let meta = self.do_setattr(&identity, grant, &handle, &attr)?;
                serde_json::to_value(meta).map_err(|_| Errno::EIO)
            }
            Call::ReadDir { dir } => {
                let entries = self.do_read_dir(owner, &identity, &dir)?;
                serde_json::to_value(entries).map_err(|_| Errno::EIO)
            }
            Call::ReadLink { link } => {
                let target = self.do_read_link(&link)?;
                serde_json::to_value(target).map_err(|_| Errno::EIO)
            }
            Call::Create {
                dir,
                name,
                mode,
                options,
                ticket,
            } => {
                let res = self.do_create(
                    session_id, owner, cred.umask, &identity, grant, &dir, &name, mode, &options,
                    &ticket,
                )?;
                serde_json::to_value(res).map_err(|_| Errno::EIO)
            }
            Call::Mkdir { dir, name, mode } => {
                let entry = self.do_mkdir(cred, &identity, grant, &dir, &name, mode)?;
                serde_json::to_value(entry).map_err(|_| Errno::EIO)
            }
            Call::Mknod {
                dir,
                name,
                mode,
                rdev,
            } => {
                let entry = self.do_mknod(cred, &identity, grant, &dir, &name, mode, &rdev)?;
                serde_json::to_value(entry).map_err(|_| Errno::EIO)
            }
            Call::Symlink { dir, name, target } => {
                let entry = self.do_symlink(&identity, grant, &dir, &name, &target)?;
                serde_json::to_value(entry).map_err(|_| Errno::EIO)
            }
            Call::Link { target, dir, name } => {
                let entry = self.do_link(&identity, grant, &target, &dir, &name)?;
                serde_json::to_value(entry).map_err(|_| Errno::EIO)
            }
            Call::Unlink { dir, name } => {
                self.do_remove(owner, &identity, grant, &dir, &name, false)?;
                Ok(json!({}))
            }
            Call::Rmdir { dir, name } => {
                self.do_remove(owner, &identity, grant, &dir, &name, true)?;
                Ok(json!({}))
            }
            Call::Rename {
                from_dir,
                from,
                to_dir,
                to,
                flags,
            } => {
                self.do_rename(
                    owner, &identity, grant, &from_dir, &from, &to_dir, &to, flags,
                )?;
                Ok(json!({}))
            }
            Call::Getxattr { handle, name } => {
                let bytes = self.do_getxattr(&identity, &handle, &name)?;
                serde_json::to_value(abi::Bytes(bytes)).map_err(|_| Errno::EIO)
            }
            Call::Setxattr {
                handle,
                name,
                value,
                flags,
            } => {
                self.do_setxattr(&identity, grant, &handle, &name, &value, flags)?;
                Ok(json!({}))
            }
            Call::Listxattr { handle } => {
                let names = self.do_listxattr(&identity, &handle)?;
                serde_json::to_value(names).map_err(|_| Errno::EIO)
            }
            Call::Removexattr { handle, name } => {
                self.do_removexattr(&identity, grant, &handle, &name)?;
                Ok(json!({}))
            }
            Call::Statfs => {
                let st = sys::fstatvfs_fd(self.root_fd.as_fd())?;
                serde_json::to_value(st).map_err(|_| Errno::EIO)
            }
            Call::Open {
                handle,
                options,
                ticket,
            } => {
                let open =
                    self.do_open(session_id, &identity, grant, &handle, &options, &ticket)?;
                serde_json::to_value(open).map_err(|_| Errno::EIO)
            }
            Call::ReadAt {
                open,
                offset,
                count,
            } => {
                let data = self.do_read_at(session_id, &open, offset, count)?;
                serde_json::to_value(ReadReply {
                    data: abi::Bytes(data),
                })
                .map_err(|_| Errno::EIO)
            }
            Call::WriteAt { open, data, at } => {
                let written = self.do_write_at(session_id, &identity, grant, &open, &data, at)?;
                serde_json::to_value(written).map_err(|_| Errno::EIO)
            }
            Call::SetLen { open, size } => {
                self.do_set_len(session_id, &identity, grant, &open, size)?;
                Ok(json!({}))
            }
            Call::Sync { open, data_only } => {
                self.do_sync(session_id, &open, data_only)?;
                Ok(json!({}))
            }
            Call::Lock {
                open,
                family,
                kind,
                range,
                ticket,
            } => {
                let handle = lookup_open(&self.sessions, self.store.fs_id(), session_id, &open)?;
                let spec = super::locks::LockSpec {
                    family,
                    kind,
                    range,
                };
                let outcome = self.locks.lock(
                    handle.node_id.ino,
                    handle.id,
                    handle.access,
                    handle.fd.as_fd(),
                    spec,
                    &ticket,
                )?;
                serde_json::to_value(outcome).map_err(|_| Errno::EIO)
            }
            Call::TryLock {
                open,
                family,
                kind,
                range,
            } => {
                let handle = lookup_open(&self.sessions, self.store.fs_id(), session_id, &open)?;
                let spec = super::locks::LockSpec {
                    family,
                    kind,
                    range,
                };
                self.locks.try_lock(
                    handle.node_id.ino,
                    handle.id,
                    handle.access,
                    handle.fd.as_fd(),
                    spec,
                )?;
                Ok(json!({}))
            }
            Call::Unlock {
                open,
                family,
                range,
            } => {
                let handle = lookup_open(&self.sessions, self.store.fs_id(), session_id, &open)?;
                self.locks.unlock(
                    handle.node_id.ino,
                    handle.id,
                    handle.access,
                    handle.fd.as_fd(),
                    family,
                    range,
                )?;
                Ok(json!({}))
            }
            Call::TestLock { open, kind, range } => {
                let handle = lookup_open(&self.sessions, self.store.fs_id(), session_id, &open)?;
                let conflict = self.locks.test_lock(
                    handle.node_id.ino,
                    handle.id,
                    handle.access,
                    handle.fd.as_fd(),
                    kind,
                    range,
                )?;
                serde_json::to_value(conflict).map_err(|_| Errno::EIO)
            }
            Call::CancelLock { open, ticket } => {
                let fd_and_id = self
                    .sessions
                    .get(session_id)
                    .and_then(|s| s.opens.get(&open.id))
                    .filter(|o| o.node_id == open.node && open.fs == *self.store.fs_id())
                    .map(|o| o.id);
                if let Some(open_id) = fd_and_id {
                    let fd = &self.sessions[session_id].opens[&open_id].fd;
                    self.locks.cancel_lock(open_id, Some(fd.as_fd()), &ticket)?;
                }
                Ok(json!({}))
            }
            Call::CancelOpen { ticket } => {
                self.do_cancel_open(session_id, &ticket)?;
                Ok(json!({}))
            }
            Call::Release { open } => {
                self.do_release(session_id, &open)?;
                Ok(json!({}))
            }
        }
    }

    fn resolve_handle(&mut self, handle: &Handle) -> Result<ResolvedHandle, Errno> {
        let ino = self.store.verify_handle(handle)?;
        let (host_key, hints) = {
            let rec = self.store.get(ino).ok_or(Errno::ESTALE)?;
            (rec.host.clone(), rec.path_hints.clone())
        };

        if ino == ROOT_INO {
            let stx = sys::statx_fd(self.root_fd.as_fd())?;
            let live_key = HostInodeKey::from_root(self.root_fd.as_fd(), &stx)?;
            if live_key != host_key {
                return Err(Errno::ESTALE);
            }
            let fd = sys::open_beneath(self.root_fd.as_fd(), ".", libc::O_PATH, 0)?;
            return Ok(ResolvedHandle {
                ino,
                relpath: String::new(),
                unlinked: false,
                fd,
                stat: stx,
                key: live_key,
            });
        }

        let mut hints_dirty = false;
        for hint in hints {
            match self.walk_relpath(&hint) {
                Ok((fd, stx, live_key)) if live_key == host_key => {
                    self.store.promote_hint(ino, &hint);
                    if hints_dirty {
                        let _ = self.store.flush();
                    }
                    let unlinked = stx.nlink == 0;
                    return Ok(ResolvedHandle {
                        ino,
                        relpath: hint,
                        unlinked,
                        fd,
                        stat: stx,
                        key: live_key,
                    });
                }
                Ok(_) | Err(Errno::ENOENT | Errno::ENOTDIR) => {
                    if self.store.drop_dead_hint(ino, &hint) {
                        hints_dirty = true;
                    }
                }
                Err(e) => {
                    if hints_dirty {
                        let _ = self.store.flush();
                    }
                    return Err(e);
                }
            }
        }
        if hints_dirty {
            let _ = self.store.flush();
        }
        if let Some((dup_fd, is_opath)) = self.clone_open_fd(ino)? {
            let stx = sys::statx_fd(dup_fd.as_fd())?;
            let live_gen = sys::capture_gen_from_fd(dup_fd.as_fd(), &stx)?;
            let fsuuid_ok = if !is_opath && host_key.subfs_fsuuid.is_some() {
                sys::capture_fsuuid_from_fd(dup_fd.as_fd()) == host_key.subfs_fsuuid
            } else {
                true
            };
            if stx.ino == host_key.host_ino
                && stx.kind == host_key.kind
                && stx.subvol == host_key.subvol
                && live_gen == host_key.host_gen
                && fsuuid_ok
            {
                if stx.kind == HostKind::Dir {
                    if stx.nlink == 0 {
                        let _ = self.store.mark_unlinked(ino);
                        let _ = self.store.flush();
                        return Err(Errno::ENOENT);
                    }
                    let live_rel =
                        sys::fd_relpath_inside_root(&self.canonical_root, dup_fd.as_fd())?;
                    if live_rel.is_empty() {
                        return Err(Errno::ESTALE);
                    }
                    let (walked_fd, walked_stx, walked_key) = self.walk_relpath(&live_rel)?;
                    if walked_key != host_key || walked_stx.kind != HostKind::Dir {
                        return Err(Errno::ESTALE);
                    }
                    self.store.add_path_hint(ino, &live_rel)?;
                    return Ok(ResolvedHandle {
                        ino,
                        relpath: live_rel,
                        unlinked: false,
                        fd: walked_fd,
                        stat: walked_stx,
                        key: walked_key,
                    });
                }
                if stx.nlink == 0 {
                    if self.store.mark_unlinked(ino) {
                        let _ = self.store.flush();
                    }
                    return Ok(ResolvedHandle {
                        ino,
                        relpath: String::new(),
                        unlinked: true,
                        fd: dup_fd,
                        stat: stx,
                        key: host_key,
                    });
                }
                match sys::fd_relpath_inside_root(&self.canonical_root, dup_fd.as_fd()) {
                    Ok(live_rel) if !live_rel.is_empty() => {
                        if let Ok((walked_fd, walked_stx, walked_key)) =
                            self.walk_relpath(&live_rel)
                            && walked_key == host_key
                        {
                            self.store.add_path_hint(ino, &live_rel)?;
                            return Ok(ResolvedHandle {
                                ino,
                                relpath: live_rel,
                                unlinked: false,
                                fd: walked_fd,
                                stat: walked_stx,
                                key: walked_key,
                            });
                        }
                        return Err(Errno::ESTALE);
                    }
                    Ok(_) => return Err(Errno::ESTALE),
                    Err(Errno::ENOENT) => {
                        // Positive link count indicates another surviving hard link elsewhere in
                        // the host tree, so never mark the inode unlinked or lose its metadata on close.
                        return Ok(ResolvedHandle {
                            ino,
                            relpath: String::new(),
                            unlinked: false,
                            fd: dup_fd,
                            stat: stx,
                            key: host_key,
                        });
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        Err(Errno::ESTALE)
    }

    fn clone_open_fd(&self, ino: u64) -> Result<Option<(OwnedFd, bool)>, Errno> {
        let mut fallback: Option<&OwnedFd> = None;
        for s in self.sessions.values() {
            for o in s.opens.values() {
                if o.node_id.ino == ino {
                    if o.access != Access::Path {
                        return o
                            .fd
                            .try_clone()
                            .map(|fd| Some((fd, false)))
                            .map_err(|e| sys::io_to_errno(&e));
                    }
                    if fallback.is_none() {
                        fallback = Some(&o.fd);
                    }
                }
            }
        }
        match fallback {
            Some(fd) => fd
                .try_clone()
                .map(|fd| Some((fd, true)))
                .map_err(|e| sys::io_to_errno(&e)),
            None => Ok(None),
        }
    }

    fn open_ino_set(&self) -> BTreeSet<u64> {
        let mut set = BTreeSet::new();
        for s in self.sessions.values() {
            for o in s.opens.values() {
                set.insert(o.node_id.ino);
            }
        }
        set
    }

    fn verify_dir_confined(&self, dir_res: &ResolvedHandle) -> Result<(), Errno> {
        if dir_res.stat.kind != HostKind::Dir {
            return Err(Errno::ENOTDIR);
        }
        if dir_res.unlinked || dir_res.stat.nlink == 0 {
            return Err(Errno::ENOENT);
        }
        sys::verify_fd_inside_root(&self.canonical_root, self.root_fd.as_fd())?;
        sys::verify_fd_inside_root(&self.canonical_root, dir_res.fd.as_fd())
    }

    /// Re-resolve and open a fresh, root-anchored directory descriptor immediately prior to a
    /// directory mutation so external moves cannot silently redirect a cached descriptor.
    fn reopen_confined_dir(&self, dir_res: &ResolvedHandle) -> Result<(String, OwnedFd), Errno> {
        self.verify_dir_confined(dir_res)?;
        let live_rel = if dir_res.ino == ROOT_INO {
            String::new()
        } else {
            sys::fd_relpath_inside_root(&self.canonical_root, dir_res.fd.as_fd())?
        };
        if dir_res.ino != ROOT_INO && live_rel.is_empty() {
            return Err(Errno::ESTALE);
        }
        let (fresh_fd, fresh_stx, fresh_key) = self.walk_relpath(&live_rel)?;
        if fresh_stx.kind != HostKind::Dir
            || fresh_stx.ino != dir_res.stat.ino
            || fresh_stx.dev != dir_res.stat.dev
            || fresh_stx.mnt_id != dir_res.stat.mnt_id
            || fresh_stx.subvol != dir_res.stat.subvol
            || fresh_key.host_gen != dir_res.key.host_gen
            || fresh_key.subfs_fsuuid != dir_res.key.subfs_fsuuid
        {
            return Err(Errno::ESTALE);
        }
        Ok((live_rel, fresh_fd))
    }

    fn walk_relpath(&self, rel: &str) -> Result<(OwnedFd, HostStat, HostInodeKey), Errno> {
        sys::verify_fd_inside_root(&self.canonical_root, self.root_fd.as_fd())?;
        let root_stx = sys::statx_fd(self.root_fd.as_fd())?;
        let mut cur_fd = sys::open_beneath(self.root_fd.as_fd(), ".", libc::O_PATH, 0)?;
        if rel.is_empty() {
            let key = HostInodeKey::from_root(self.root_fd.as_fd(), &root_stx)?;
            return Ok((cur_fd, root_stx, key));
        }
        let mut cur_subfs = String::new();
        let mut cur_subfs_fsuuid = sys::capture_dir_fsuuid(self.root_fd.as_fd(), "");
        let mut cur_stx = root_stx;
        let mut cur_rel = String::new();

        for comp in rel.split('/') {
            check_component(comp)?;
            if !cur_rel.is_empty() {
                cur_rel.push('/');
            }
            cur_rel.push_str(comp);
            let next_fd = sys::open_beneath(
                self.root_fd.as_fd(),
                &cur_rel,
                libc::O_PATH | libc::O_NOFOLLOW,
                0,
            )?;
            let next_stx = sys::statx_fd(next_fd.as_fd())?;
            if sys::boundary_crossed(&cur_stx, &next_stx) {
                cur_subfs = cur_rel.clone();
                cur_subfs_fsuuid = if next_stx.kind == HostKind::Dir {
                    sys::capture_dir_fsuuid(self.root_fd.as_fd(), &cur_subfs)
                } else {
                    None
                };
            }
            cur_fd = next_fd;
            cur_stx = next_stx;
        }
        if cur_stx.kind == HostKind::Dir {
            sys::verify_fd_inside_root(&self.canonical_root, cur_fd.as_fd())?;
        }
        let host_gen = sys::capture_gen_from_fd(cur_fd.as_fd(), &cur_stx)?;
        let key = HostInodeKey {
            subfs_relpath: cur_subfs,
            subvol: cur_stx.subvol,
            subfs_fsuuid: cur_subfs_fsuuid,
            host_ino: cur_stx.ino,
            host_gen,
            kind: cur_stx.kind,
        };
        Ok((cur_fd, cur_stx, key))
    }

    fn inspect_child(
        &self,
        parent: &ResolvedHandle,
        name: &str,
    ) -> Result<(String, OwnedFd, HostStat, HostInodeKey), Errno> {
        self.verify_dir_confined(parent)?;
        let rel = join_rel(&parent.relpath, name);
        let fd = sys::open_beneath(
            self.root_fd.as_fd(),
            &rel,
            libc::O_PATH | libc::O_NOFOLLOW,
            0,
        )?;
        let stx = sys::statx_fd(fd.as_fd())?;
        if stx.kind == HostKind::Dir {
            sys::verify_fd_inside_root(&self.canonical_root, fd.as_fd())?;
        }
        let parent_stx = sys::statx_fd(parent.fd.as_fd())?;
        let (subfs_relpath, subfs_fsuuid) = if sys::boundary_crossed(&parent_stx, &stx) {
            let uuid = if stx.kind == HostKind::Dir {
                sys::capture_dir_fsuuid(self.root_fd.as_fd(), &rel)
            } else {
                None
            };
            (rel.clone(), uuid)
        } else {
            (parent.key.subfs_relpath.clone(), parent.key.subfs_fsuuid)
        };
        let host_gen = sys::capture_gen_from_fd(fd.as_fd(), &stx)?;
        let key = HostInodeKey {
            subfs_relpath,
            subvol: stx.subvol,
            subfs_fsuuid,
            host_ino: stx.ino,
            host_gen,
            kind: stx.kind,
        };
        Ok((rel, fd, stx, key))
    }

    fn is_wasm_binary(&self, rel: &str) -> bool {
        const WASM_MAGIC: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        let Ok(rfd) = sys::open_beneath(
            self.root_fd.as_fd(),
            rel,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0,
        ) else {
            return false;
        };
        let Ok(stx) = sys::statx_fd(rfd.as_fd()) else {
            return false;
        };
        if stx.kind != HostKind::File {
            return false;
        }
        let mut file = std::fs::File::from(rfd);
        let mut magic = [0u8; 8];
        std::io::Read::read_exact(&mut file, &mut magic).is_ok() && magic == WASM_MAGIC
    }

    fn discover_child(
        &mut self,
        parent: &ResolvedHandle,
        name: &str,
        owner: (u32, u32),
    ) -> Result<(u64, String, OwnedFd, HostStat, HostInodeKey, bool), Errno> {
        let (rel, fd, stx, key) = self.inspect_child(parent, name)?;
        let default_file_mode = if stx.kind == HostKind::File
            && stx.size >= 8
            && !self.store.has_host_key(&key)
            && self.is_wasm_binary(&rel)
        {
            0o700
        } else {
            0o600
        };
        let open_inos = self.open_ino_set();
        let (ino, dirty) = self.store.discover_or_reset_with_mode(
            &rel,
            key.clone(),
            owner.0,
            owner.1,
            default_file_mode,
            &|id| open_inos.contains(&id),
        )?;
        Ok((ino, rel, fd, stx, key, dirty))
    }

    fn entry_for(&self, ino: u64, stx: &HostStat) -> Entry {
        let rec = self.store.get(ino).expect("stored inode");
        Entry {
            handle: self.store.sign_handle(NodeId {
                ino,
                generation: rec.generation,
            }),
            metadata: metadata_of(rec, stx),
        }
    }

    fn do_lookup(
        &mut self,
        owner: (u32, u32),
        identity: &Identity,
        dir: &Handle,
        name: &str,
    ) -> Result<Entry, Errno> {
        check_component(name)?;
        let dir_res = self.resolve_handle(dir)?;
        let dir_node = &self.store.get(dir_res.ino).ok_or(Errno::ESTALE)?.node;
        require_live_dir(&dir_res, dir_node)?;
        inode::require(identity, dir_node, EXEC)?;
        let (ino, _rel, _fd, stx, _key, dirty) = self.discover_child(&dir_res, name, owner)?;
        if dirty {
            self.store.flush()?;
        }
        Ok(self.entry_for(ino, &stx))
    }

    fn do_walk(
        &mut self,
        owner: (u32, u32),
        identity: &Identity,
        dir: &Handle,
        names: &[String],
    ) -> Result<Walked, Errno> {
        for name in names {
            check_component(name)?;
        }
        let mut cur = self.resolve_handle(dir)?;
        let mut entries = Vec::with_capacity(names.len());
        let mut dirty = false;

        for (index, name) in names.iter().enumerate() {
            if index > 0 {
                let stop = match cur.stat.kind {
                    HostKind::Dir if cur.unlinked || cur.stat.nlink == 0 => {
                        if dirty {
                            self.store.flush()?;
                        }
                        return Ok(Walked {
                            entries,
                            stop: Some(Stop::Missing(index)),
                        });
                    }
                    HostKind::Dir => None,
                    HostKind::Symlink => Some(Stop::Symlink(index - 1)),
                    _ => Some(Stop::NotDirectory(index - 1)),
                };
                if stop.is_some() {
                    if dirty {
                        self.store.flush()?;
                    }
                    return Ok(Walked { entries, stop });
                }
            } else {
                let dir_node = &self.store.get(cur.ino).ok_or(Errno::ESTALE)?.node;
                require_live_dir(&cur, dir_node)?;
            }
            {
                let cur_node = &self.store.get(cur.ino).ok_or(Errno::ESTALE)?.node;
                inode::require(identity, cur_node, EXEC)?;
            }
            match self.discover_child(&cur, name, owner) {
                Ok((ino, rel, fd, stx, key, d)) => {
                    dirty |= d;
                    entries.push(self.entry_for(ino, &stx));
                    cur = ResolvedHandle {
                        ino,
                        relpath: rel,
                        unlinked: stx.nlink == 0,
                        fd,
                        stat: stx,
                        key,
                    };
                }
                Err(Errno::ENOENT) => {
                    if dirty {
                        self.store.flush()?;
                    }
                    return Ok(Walked {
                        entries,
                        stop: Some(Stop::Missing(index)),
                    });
                }
                Err(e) => return Err(e),
            }
        }
        if dirty {
            self.store.flush()?;
        }
        Ok(Walked {
            entries,
            stop: None,
        })
    }

    fn do_parent(
        &mut self,
        owner: (u32, u32),
        dir: &Handle,
    ) -> Result<Option<(Entry, String)>, Errno> {
        let dir_res = self.resolve_handle(dir)?;
        let dir_node = &self.store.get(dir_res.ino).ok_or(Errno::ESTALE)?.node;
        require_live_dir(&dir_res, dir_node)?;
        if dir_res.ino == ROOT_INO {
            return Ok(None);
        }
        let (parent_rel, my_name) = match dir_res.relpath.rsplit_once('/') {
            Some((p, n)) => (p, n.to_owned()),
            None => ("", dir_res.relpath.clone()),
        };
        let (parent_fd, parent_stx, parent_key) = self.walk_relpath(parent_rel)?;
        let open_inos = self.open_ino_set();
        let (parent_ino, dirty) =
            self.store
                .discover_or_reset(parent_rel, parent_key, owner.0, owner.1, &|id| {
                    open_inos.contains(&id)
                })?;
        if dirty {
            self.store.flush()?;
        }
        let _ = parent_fd;
        Ok(Some((self.entry_for(parent_ino, &parent_stx), my_name)))
    }

    fn do_metadata(&mut self, handle: &Handle) -> Result<Metadata, Errno> {
        let res = self.resolve_handle(handle)?;
        let rec = self.store.get(res.ino).ok_or(Errno::ESTALE)?;
        Ok(metadata_of(rec, &res.stat))
    }

    fn do_open_metadata(&self, session_id: &str, open: &OpenRef) -> Result<Metadata, Errno> {
        let handle = self.check_open(session_id, open)?;
        let stx = sys::statx_fd(handle.fd.as_fd())?;
        let rec = self.store.get(handle.node_id.ino).ok_or(Errno::ESTALE)?;
        Ok(metadata_of(rec, &stx))
    }

    fn do_setattr(
        &mut self,
        identity: &Identity,
        grant: abi::local_helper::HelperGrant,
        handle: &Handle,
        attr: &SetAttr,
    ) -> Result<Metadata, Errno> {
        let res = self.resolve_handle(handle)?;
        if !grant.write {
            return Err(Errno::EROFS);
        }
        let mut meta = self.store.get(res.ino).ok_or(Errno::ESTALE)?.node.clone();
        if *attr == SetAttr::default() {
            let rec = self.store.get(res.ino).ok_or(Errno::ESTALE)?;
            return Ok(metadata_of(rec, &res.stat));
        }

        if let Some(mode) = attr.mode {
            inode::chmod(identity, &mut meta, mode)?;
        }
        inode::chown(identity, &mut meta, attr.uid, attr.gid)?;
        inode::may_set_times(
            identity,
            &self.store.get(res.ino).ok_or(Errno::ESTALE)?.node,
            attr.atime,
            attr.mtime,
        )?;
        if let Some(size) = attr.size {
            match res.stat.kind {
                HostKind::Dir => return Err(Errno::EISDIR),
                HostKind::File => {}
                _ => return Err(Errno::EINVAL),
            }
            inode::require(
                identity,
                &self.store.get(res.ino).ok_or(Errno::ESTALE)?.node,
                WRITE,
            )?;
            if size > FILE_MAX {
                return Err(Errno::EFBIG);
            }
        }

        if let Some(size) = attr.size {
            let wfd = if !res.relpath.is_empty() {
                sys::verify_fd_inside_root(&self.canonical_root, self.root_fd.as_fd())?;
                sys::open_beneath(
                    self.root_fd.as_fd(),
                    &res.relpath,
                    libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                    0,
                )?
            } else {
                sys::open_proc_fd(res.fd.as_fd(), libc::O_WRONLY | libc::O_NONBLOCK)?
            };
            let w_stx = sys::statx_fd(wfd.as_fd())?;
            if w_stx.kind != HostKind::File {
                return Err(Errno::ESTALE);
            }
            let w_gen = sys::capture_gen_from_fd(wfd.as_fd(), &w_stx)?;
            if w_stx.ino != res.stat.ino
                || w_stx.dev != res.stat.dev
                || w_stx.mnt_id != res.stat.mnt_id
                || w_stx.subvol != res.stat.subvol
                || w_gen != res.key.host_gen
            {
                return Err(Errno::ESTALE);
            }
            sys::clear_nonblock(wfd.as_fd())?;
            sys::ftruncate_fd(wfd.as_fd(), size)?;
            inode::remove_privs(identity, &mut meta);
        }

        if attr.atime != abi::Time::Omit || attr.mtime != abi::Time::Omit {
            sys::utimensat_exact_fd(res.fd.as_fd(), attr.atime, attr.mtime)?;
        }

        let new_stx = sys::statx_fd(res.fd.as_fd())?;
        {
            let rec = self.store.get_mut(res.ino).ok_or(Errno::ESTALE)?;
            rec.node = meta;
            rec.meta_ctime = Some(sys::now_timespec());
        }
        self.store.flush()?;
        Ok(metadata_of(
            self.store.get(res.ino).ok_or(Errno::ESTALE)?,
            &new_stx,
        ))
    }

    fn do_read_dir(
        &mut self,
        owner: (u32, u32),
        identity: &Identity,
        dir: &Handle,
    ) -> Result<Vec<DirEntry>, Errno> {
        let dir_res = self.resolve_handle(dir)?;
        let dir_node = &self.store.get(dir_res.ino).ok_or(Errno::ESTALE)?.node;
        require_live_dir(&dir_res, dir_node)?;
        inode::require(identity, dir_node, READ)?;
        let names = sys::readdir_fd(dir_res.fd.as_fd())?;
        let mut out = Vec::with_capacity(names.len());
        let mut dirty = false;
        for name in names {
            let (ino, _rel, _fd, stx, _key, d) = self.discover_child(&dir_res, &name, owner)?;
            dirty |= d;
            let rec = self.store.get(ino).ok_or(Errno::ESTALE)?;
            out.push(DirEntry {
                name,
                node: NodeId {
                    ino,
                    generation: rec.generation,
                },
                file_type: file_type_of(rec, &stx),
            });
        }
        if dirty {
            self.store.flush()?;
        }
        Ok(out)
    }

    fn do_read_link(&mut self, link: &Handle) -> Result<String, Errno> {
        let res = self.resolve_handle(link)?;
        if res.stat.kind != HostKind::Symlink {
            return Err(Errno::EINVAL);
        }
        sys::readlink_fd(res.fd.as_fd())
    }

    #[allow(clippy::too_many_arguments)]
    fn do_create(
        &mut self,
        session_id: &str,
        owner: (u32, u32),
        umask: u16,
        identity: &Identity,
        grant: abi::local_helper::HelperGrant,
        dir: &Handle,
        name: &str,
        mode: u16,
        options: &OpenOptions,
        ticket: &str,
    ) -> Result<(Entry, OpenRef), Errno> {
        if !grant.write {
            return Err(Errno::EROFS);
        }
        check_component(name)?;
        if ticket.is_empty() || ticket.len() > 128 {
            return Err(Errno::EINVAL);
        }
        let access = options.access()?;
        if matches!(access, Access::Exec | Access::Path) {
            return Err(Errno::EINVAL);
        }
        if let Some(prev) = self
            .sessions
            .get(session_id)
            .ok_or(Errno::ENODEV)?
            .open_tickets
            .get(ticket)
        {
            return match prev {
                OpenTicketState::Cancelled => Err(Errno::ECANCELED),
                OpenTicketState::Created { entry, open } => Ok((entry.clone(), open.clone())),
                OpenTicketState::Opened { .. } => Err(Errno::EINVAL),
            };
        }

        let dir_res = self.resolve_handle(dir)?;
        let dir_node = self
            .store
            .get(dir_res.ino)
            .ok_or(Errno::ESTALE)?
            .node
            .clone();
        require_live_dir(&dir_res, &dir_node)?;
        self.verify_dir_confined(&dir_res)?;
        inode::require(identity, &dir_node, EXEC)?;

        for attempt in 0..8 {
            // Check whether an entry already exists first to apply POSIX permissions & O_EXCL checks.
            match self.discover_child(&dir_res, name, owner) {
                Ok((
                    existing_ino,
                    existing_rel,
                    _existing_fd,
                    existing_stx,
                    existing_key,
                    dirty,
                )) => {
                    if dirty {
                        self.store.flush()?;
                    }
                    if options.is_create_new() {
                        return Err(Errno::EEXIST);
                    }
                    let existing_meta = self
                        .store
                        .get(existing_ino)
                        .ok_or(Errno::ESTALE)?
                        .node
                        .clone();
                    if existing_meta.directory || existing_stx.kind == HostKind::Dir {
                        return Err(Errno::EISDIR);
                    }
                    if existing_stx.kind == HostKind::Symlink {
                        return Err(Errno::ELOOP);
                    }
                    if existing_stx.kind != HostKind::File || existing_meta.rdev.is_some() {
                        return Err(Errno::ENXIO);
                    }
                    let mut mask = access.mask();
                    if options.is_truncate() {
                        mask |= WRITE;
                    }
                    inode::may_open(identity, &existing_meta, mask)?;
                    self.verify_dir_confined(&dir_res)?;
                    let fd = match self.open_existing_host_file(
                        &existing_rel,
                        access,
                        options.is_truncate(),
                        &existing_stx,
                        &existing_key,
                    ) {
                        Ok(fd) => fd,
                        Err(Errno::ENOENT) if !options.is_create_new() && attempt < 7 => continue,
                        Err(e) => return Err(e),
                    };
                    if options.is_truncate() {
                        if let Some(rec) = self.store.get_mut(existing_ino) {
                            inode::remove_privs(identity, &mut rec.node);
                            rec.meta_ctime = Some(sys::now_timespec());
                        }
                        self.store.flush()?;
                    }
                    let live_stx = sys::statx_fd(fd.as_fd())?;
                    let entry = self.entry_for(existing_ino, &live_stx);
                    let open = self.register_open(
                        session_id,
                        entry.handle.node,
                        existing_key,
                        access,
                        HostKind::File,
                        fd,
                    )?;
                    self.record_open_ticket(
                        session_id,
                        ticket,
                        OpenTicketState::Created {
                            entry: entry.clone(),
                            open: open.clone(),
                        },
                    );
                    return Ok((entry, open));
                }
                Err(Errno::ENOENT) => {}
                Err(e) => return Err(e),
            }

            inode::may_create(identity, &dir_node, dir_res.unlinked)?;
            let node = created(identity, &dir_node, mode, false, umask);
            let host_flags = open_access_flags(access)?
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK;
            let (live_dir_rel, _fresh_dir_fd) = self.reopen_confined_dir(&dir_res)?;
            let rel = join_rel(&live_dir_rel, name);
            let fd = match sys::open_beneath(self.root_fd.as_fd(), &rel, host_flags, 0o600) {
                Ok(fd) => fd,
                Err(Errno::EEXIST) if !options.is_create_new() && attempt < 7 => continue,
                Err(e) => return Err(e),
            };
            sys::clear_nonblock(fd.as_fd())?;
            let stx = sys::statx_fd(fd.as_fd())?;
            let (subfs_relpath, subfs_fsuuid) = if sys::boundary_crossed(&dir_res.stat, &stx) {
                (rel.clone(), sys::capture_fsuuid_from_fd(fd.as_fd()))
            } else {
                (dir_res.key.subfs_relpath.clone(), dir_res.key.subfs_fsuuid)
            };
            let host_gen = sys::capture_gen_from_fd(fd.as_fd(), &stx)?;
            let key = HostInodeKey {
                subfs_relpath,
                subvol: stx.subvol,
                subfs_fsuuid,
                host_ino: stx.ino,
                host_gen,
                kind: stx.kind,
            };
            let open_inos = self.open_ino_set();
            let ino = self
                .store
                .insert_created(&rel, key.clone(), node, &|id| open_inos.contains(&id))?;
            let entry = self.entry_for(ino, &stx);
            let open =
                self.register_open(session_id, entry.handle.node, key, access, stx.kind, fd)?;
            self.record_open_ticket(
                session_id,
                ticket,
                OpenTicketState::Created {
                    entry: entry.clone(),
                    open: open.clone(),
                },
            );
            return Ok((entry, open));
        }

        Err(Errno::EEXIST)
    }

    fn finish_created_child(
        &mut self,
        fresh_dir_fd: BorrowedFd<'_>,
        name: &str,
        is_dir: bool,
        node: Node,
    ) -> Result<Entry, Errno> {
        let post_dir_rel = match sys::fd_relpath_inside_root(&self.canonical_root, fresh_dir_fd) {
            Ok(rel) => rel,
            Err(e) => {
                let _ = sys::unlinkat_fd(fresh_dir_fd, name, is_dir);
                return Err(e);
            }
        };
        let rel = join_rel(&post_dir_rel, name);
        let (_fd, stx, key) = self.walk_relpath(&rel)?;
        let open_inos = self.open_ino_set();
        let ino = self
            .store
            .insert_created(&rel, key, node, &|id| open_inos.contains(&id))?;
        Ok(self.entry_for(ino, &stx))
    }

    fn do_mkdir(
        &mut self,
        cred: &WireCred,
        identity: &Identity,
        grant: abi::local_helper::HelperGrant,
        dir: &Handle,
        name: &str,
        mode: u16,
    ) -> Result<Entry, Errno> {
        if !grant.write {
            return Err(Errno::EROFS);
        }
        check_component(name)?;
        let dir_res = self.resolve_handle(dir)?;
        let dir_node = self
            .store
            .get(dir_res.ino)
            .ok_or(Errno::ESTALE)?
            .node
            .clone();
        require_live_dir(&dir_res, &dir_node)?;
        inode::may_create(identity, &dir_node, dir_res.unlinked)?;
        let node = created(identity, &dir_node, mode, true, cred.umask);
        let (live_rel, fresh_dir_fd) = self.reopen_confined_dir(&dir_res)?;
        let rel = join_rel(&live_rel, name);
        if entry_exists(self.root_fd.as_fd(), &rel)? {
            return Err(Errno::EEXIST);
        }
        sys::mkdirat_fd(fresh_dir_fd.as_fd(), name, 0o700)?;
        self.finish_created_child(fresh_dir_fd.as_fd(), name, true, node)
    }

    #[allow(clippy::too_many_arguments)]
    fn do_mknod(
        &mut self,
        cred: &WireCred,
        identity: &Identity,
        grant: abi::local_helper::HelperGrant,
        dir: &Handle,
        name: &str,
        mode: u16,
        rdev: &str,
    ) -> Result<Entry, Errno> {
        if !grant.write {
            return Err(Errno::EROFS);
        }
        check_component(name)?;
        if identity.id != 0 {
            return Err(Errno::EPERM);
        }
        let dir_res = self.resolve_handle(dir)?;
        let dir_node = self
            .store
            .get(dir_res.ino)
            .ok_or(Errno::ESTALE)?
            .node
            .clone();
        require_live_dir(&dir_res, &dir_node)?;
        inode::may_create(identity, &dir_node, dir_res.unlinked)?;
        let mut node = created(identity, &dir_node, mode, false, cred.umask);
        node.rdev = (!rdev.is_empty()).then(|| rdev.to_owned());
        let (live_rel, fresh_dir_fd) = self.reopen_confined_dir(&dir_res)?;
        let rel = join_rel(&live_rel, name);
        if entry_exists(self.root_fd.as_fd(), &rel)? {
            return Err(Errno::EEXIST);
        }
        if rdev == "fifo" {
            sys::mkfifoat_fd(fresh_dir_fd.as_fd(), name, 0o600)?;
        } else {
            // Host unprivileged helpers cannot mknod device nodes; back with a 0-byte regular
            // host inode while preserving OS device metadata.
            let fd = sys::open_beneath(
                self.root_fd.as_fd(),
                &rel,
                libc::O_CREAT | libc::O_EXCL | libc::O_RDWR | libc::O_NOFOLLOW,
                0o600,
            )?;
            drop(fd);
        }
        self.finish_created_child(fresh_dir_fd.as_fd(), name, false, node)
    }

    fn do_symlink(
        &mut self,
        identity: &Identity,
        grant: abi::local_helper::HelperGrant,
        dir: &Handle,
        name: &str,
        target: &str,
    ) -> Result<Entry, Errno> {
        if !grant.write {
            return Err(Errno::EROFS);
        }
        check_component(name)?;
        inode::check_link_target(target)?;
        let dir_res = self.resolve_handle(dir)?;
        let dir_node = self
            .store
            .get(dir_res.ino)
            .ok_or(Errno::ESTALE)?
            .node
            .clone();
        require_live_dir(&dir_res, &dir_node)?;
        inode::may_create(identity, &dir_node, dir_res.unlinked)?;
        let node = inode::new_symlink(identity, &dir_node, target);
        let (live_rel, fresh_dir_fd) = self.reopen_confined_dir(&dir_res)?;
        let rel = join_rel(&live_rel, name);
        if entry_exists(self.root_fd.as_fd(), &rel)? {
            return Err(Errno::EEXIST);
        }
        sys::symlinkat_fd(target, fresh_dir_fd.as_fd(), name)?;
        self.finish_created_child(fresh_dir_fd.as_fd(), name, false, node)
    }

    fn do_link(
        &mut self,
        identity: &Identity,
        grant: abi::local_helper::HelperGrant,
        target: &Handle,
        dir: &Handle,
        name: &str,
    ) -> Result<Entry, Errno> {
        if !grant.write {
            return Err(Errno::EROFS);
        }
        check_component(name)?;
        let target_res = self.resolve_handle(target)?;
        let dir_res = self.resolve_handle(dir)?;
        let dir_node = self
            .store
            .get(dir_res.ino)
            .ok_or(Errno::ESTALE)?
            .node
            .clone();
        require_live_dir(&dir_res, &dir_node)?;
        let target_node = self
            .store
            .get(target_res.ino)
            .ok_or(Errno::ESTALE)?
            .node
            .clone();
        inode::may_link(identity, &target_node)?;
        inode::may_create(identity, &dir_node, dir_res.unlinked)?;

        if target_res.ino == ROOT_INO {
            return Err(Errno::EPERM);
        }
        if target_res.unlinked || target_res.stat.nlink == 0 {
            return Err(Errno::ENOENT);
        }
        let live_target_rel =
            sys::fd_relpath_inside_root(&self.canonical_root, target_res.fd.as_fd())?;
        if live_target_rel.is_empty() {
            return Err(Errno::ENOENT);
        }
        let (old_parent_fd, old_name) = self.open_parent_of(&live_target_rel)?;
        sys::verify_fd_inside_root(&self.canonical_root, old_parent_fd.as_fd())?;
        let (live_dir_rel, fresh_dir_fd) = self.reopen_confined_dir(&dir_res)?;
        let rel = join_rel(&live_dir_rel, name);
        if entry_exists(self.root_fd.as_fd(), &rel)? {
            return Err(Errno::EEXIST);
        }
        sys::linkat_fd(old_parent_fd.as_fd(), &old_name, fresh_dir_fd.as_fd(), name)?;
        let post_dir_rel =
            match sys::fd_relpath_inside_root(&self.canonical_root, fresh_dir_fd.as_fd()) {
                Ok(r) => r,
                Err(e) => {
                    let _ = sys::unlinkat_fd(fresh_dir_fd.as_fd(), name, false);
                    return Err(e);
                }
            };
        let new_rel = join_rel(&post_dir_rel, name);
        let (_fd, new_stx, new_key) = self.walk_relpath(&new_rel)?;
        if new_key != target_res.key {
            let _ = sys::unlinkat_fd(fresh_dir_fd.as_fd(), name, false);
            return Err(Errno::ESTALE);
        }
        self.store.add_path_hint(target_res.ino, &new_rel)?;
        Ok(self.entry_for(target_res.ino, &new_stx))
    }

    #[allow(clippy::too_many_arguments)]
    fn do_remove(
        &mut self,
        owner: (u32, u32),
        identity: &Identity,
        grant: abi::local_helper::HelperGrant,
        dir: &Handle,
        name: &str,
        directory: bool,
    ) -> Result<(), Errno> {
        if !grant.write {
            return Err(Errno::EROFS);
        }
        check_component(name)?;
        let dir_res = self.resolve_handle(dir)?;
        let dir_node = self
            .store
            .get(dir_res.ino)
            .ok_or(Errno::ESTALE)?
            .node
            .clone();
        require_live_dir(&dir_res, &dir_node)?;
        self.verify_dir_confined(&dir_res)?;
        let (victim_ino, _victim_rel, victim_fd, victim_stx, _vkey, dirty) =
            self.discover_child(&dir_res, name, owner)?;
        if dirty {
            self.store.flush()?;
        }
        let victim_node = &self.store.get(victim_ino).ok_or(Errno::ESTALE)?.node;
        inode::may_delete(identity, &dir_node, victim_node)?;
        match (directory, victim_stx.kind == HostKind::Dir) {
            (false, true) => return Err(Errno::EISDIR),
            (true, false) => return Err(Errno::ENOTDIR),
            _ => {}
        }
        let (live_dir_rel, fresh_dir_fd) = self.reopen_confined_dir(&dir_res)?;
        let victim_rel = join_rel(&live_dir_rel, name);
        sys::unlinkat_fd(fresh_dir_fd.as_fd(), name, directory)?;
        let post_nlink = sys::statx_fd(victim_fd.as_fd())
            .map(|s| s.nlink)
            .unwrap_or(0);
        let confirmed_last_link = directory || post_nlink == 0;
        let open_inos = self.open_ino_set();
        self.store
            .remove_hint(&victim_rel, confirmed_last_link, &|id| {
                open_inos.contains(&id)
            })
    }

    #[allow(clippy::too_many_arguments)]
    fn do_rename(
        &mut self,
        owner: (u32, u32),
        identity: &Identity,
        grant: abi::local_helper::HelperGrant,
        from_dir: &Handle,
        from: &str,
        to_dir: &Handle,
        to: &str,
        flags: RenameFlags,
    ) -> Result<(), Errno> {
        if !grant.write {
            return Err(Errno::EROFS);
        }
        if flags.bits() & !RenameFlags::NOREPLACE.bits() != 0 {
            return Err(Errno::EINVAL);
        }
        check_component(from)?;
        check_component(to)?;
        let from_res = self.resolve_handle(from_dir)?;
        let to_res = self.resolve_handle(to_dir)?;
        let from_node = self
            .store
            .get(from_res.ino)
            .ok_or(Errno::ESTALE)?
            .node
            .clone();
        let to_node = self
            .store
            .get(to_res.ino)
            .ok_or(Errno::ESTALE)?
            .node
            .clone();
        require_live_dir(&from_res, &from_node)?;
        require_live_dir(&to_res, &to_node)?;
        self.verify_dir_confined(&from_res)?;
        self.verify_dir_confined(&to_res)?;
        let (src_ino, src_rel, _sfd, src_stx, _skey, mut dirty) =
            self.discover_child(&from_res, from, owner)?;
        let existing = match self.discover_child(&to_res, to, owner) {
            Ok((ino, _rel, fd, stx, _key, d)) => {
                dirty |= d;
                Some((ino, stx, fd))
            }
            Err(Errno::ENOENT) => None,
            Err(e) => return Err(e),
        };
        if dirty {
            self.store.flush()?;
        }

        let noreplace = flags.contains(RenameFlags::NOREPLACE);
        if existing.is_some() && noreplace {
            return Err(Errno::EEXIST);
        }
        if existing.as_ref().is_some_and(|(ino, _, _)| *ino == src_ino) {
            return Ok(());
        }
        let moving_dir = src_stx.kind == HostKind::Dir;
        if moving_dir
            && (to_res.relpath == src_rel || to_res.relpath.starts_with(&format!("{src_rel}/")))
        {
            return Err(Errno::EINVAL);
        }
        let src_node = self.store.get(src_ino).ok_or(Errno::ESTALE)?.node.clone();
        inode::may_delete(identity, &from_node, &src_node)?;
        if let Some((target_ino, ref target_stx, _)) = existing {
            let target_node = self
                .store
                .get(target_ino)
                .ok_or(Errno::ESTALE)?
                .node
                .clone();
            inode::may_delete(identity, &to_node, &target_node)?;
            match (moving_dir, target_stx.kind == HostKind::Dir) {
                (true, false) => return Err(Errno::ENOTDIR),
                (false, true) => return Err(Errno::EISDIR),
                _ => {}
            }
        } else if from_res.ino != to_res.ino {
            inode::may_create(identity, &to_node, to_res.unlinked)?;
        }
        if moving_dir && from_res.ino != to_res.ino {
            inode::require(identity, &src_node, WRITE)?;
        }

        let (live_from_rel, fresh_from_fd) = self.reopen_confined_dir(&from_res)?;
        let (live_to_rel, fresh_to_fd) = self.reopen_confined_dir(&to_res)?;
        let src_live_rel = join_rel(&live_from_rel, from);
        let to_live_rel = join_rel(&live_to_rel, to);
        if moving_dir
            && (live_to_rel == src_live_rel || live_to_rel.starts_with(&format!("{src_live_rel}/")))
        {
            return Err(Errno::EINVAL);
        }
        sys::renameat2_fd(
            fresh_from_fd.as_fd(),
            from,
            fresh_to_fd.as_fd(),
            to,
            noreplace,
        )?;
        let target_confirmed_last_link = match existing {
            Some((_, target_stx, target_fd)) => {
                target_stx.kind == HostKind::Dir
                    || sys::statx_fd(target_fd.as_fd())
                        .map(|s| s.nlink)
                        .unwrap_or(0)
                        == 0
            }
            None => false,
        };
        let open_inos = self.open_ino_set();
        self.store.apply_rename(
            &src_live_rel,
            &to_live_rel,
            moving_dir,
            target_confirmed_last_link,
            &|id| open_inos.contains(&id),
        )
    }

    fn do_getxattr(
        &mut self,
        identity: &Identity,
        handle: &Handle,
        name: &str,
    ) -> Result<Vec<u8>, Errno> {
        let space = xattr::space(name)?;
        let res = self.resolve_handle(handle)?;
        let rec = self.store.get(res.ino).ok_or(Errno::ESTALE)?;
        xattr::readable(identity, &rec.node, space)?;
        match space {
            Space::Access | Space::Default => {
                let entries = xattr::acl(&rec.node, space)?;
                Ok(serde_json::to_vec(&entries).unwrap_or_default())
            }
            Space::User | Space::Trusted => rec.xattrs.get(name).cloned().ok_or(Errno::ENODATA),
        }
    }

    fn do_setxattr(
        &mut self,
        identity: &Identity,
        grant: abi::local_helper::HelperGrant,
        handle: &Handle,
        name: &str,
        value: &[u8],
        flags: XattrFlags,
    ) -> Result<(), Errno> {
        let space = xattr::space(name)?;
        let res = self.resolve_handle(handle)?;
        if !grant.write {
            return Err(Errno::EROFS);
        }
        {
            let rec = self.store.get_mut(res.ino).ok_or(Errno::ESTALE)?;
            xattr::settable(identity, &rec.node, space)?;
            match space {
                Space::Access | Space::Default => {
                    xattr::check_flags(flags.bits(), xattr::has_acl(&rec.node, space))?;
                    let entries: Entries =
                        serde_json::from_slice(value).map_err(|_| Errno::EINVAL)?;
                    xattr::set_acl(identity, &mut rec.node, space, entries)?;
                }
                Space::User | Space::Trusted => {
                    xattr::check_flags(flags.bits(), rec.xattrs.contains_key(name))?;
                    xattr::store(&mut rec.xattrs, name, value)?;
                }
            }
            rec.meta_ctime = Some(sys::now_timespec());
        }
        self.store.flush()
    }

    fn do_listxattr(&mut self, identity: &Identity, handle: &Handle) -> Result<Vec<String>, Errno> {
        let res = self.resolve_handle(handle)?;
        let rec = self.store.get(res.ino).ok_or(Errno::ESTALE)?;
        Ok(xattr::listed(identity, &rec.node, rec.xattrs.keys()))
    }

    fn do_removexattr(
        &mut self,
        identity: &Identity,
        grant: abi::local_helper::HelperGrant,
        handle: &Handle,
        name: &str,
    ) -> Result<(), Errno> {
        let space = xattr::space(name)?;
        let res = self.resolve_handle(handle)?;
        if !grant.write {
            return Err(Errno::EROFS);
        }
        {
            let rec = self.store.get_mut(res.ino).ok_or(Errno::ESTALE)?;
            xattr::settable(identity, &rec.node, space)?;
            match space {
                Space::Access | Space::Default => xattr::remove_acl(&mut rec.node, space)?,
                Space::User | Space::Trusted => {
                    rec.xattrs.remove(name).ok_or(Errno::ENODATA)?;
                }
            }
            rec.meta_ctime = Some(sys::now_timespec());
        }
        self.store.flush()
    }

    fn do_open(
        &mut self,
        session_id: &str,
        identity: &Identity,
        grant: abi::local_helper::HelperGrant,
        handle: &Handle,
        options: &OpenOptions,
        ticket: &str,
    ) -> Result<OpenRef, Errno> {
        if ticket.is_empty() || ticket.len() > 128 {
            return Err(Errno::EINVAL);
        }
        let access = options.access()?;
        if !grant.write && (access.writes() || options.is_truncate() || options.is_create()) {
            return Err(Errno::EROFS);
        }
        if let Some(prev) = self
            .sessions
            .get(session_id)
            .ok_or(Errno::ENODEV)?
            .open_tickets
            .get(ticket)
        {
            return match prev {
                OpenTicketState::Cancelled => Err(Errno::ECANCELED),
                OpenTicketState::Opened { open } => Ok(open.clone()),
                OpenTicketState::Created { .. } => Err(Errno::EINVAL),
            };
        }

        let res = self.resolve_handle(handle)?;
        let node = self.store.get(res.ino).ok_or(Errno::ESTALE)?.node.clone();

        if access == Access::Exec && res.stat.kind != HostKind::Dir && !grant.execute {
            return Err(Errno::EACCES);
        }

        if access != Access::Path {
            if res.stat.kind == HostKind::Symlink {
                return Err(Errno::ELOOP);
            }
            if res.stat.kind != HostKind::Dir && res.stat.kind != HostKind::File {
                return Err(Errno::ENXIO);
            }
            if node.rdev.is_some() {
                return Err(Errno::ENXIO);
            }
            let mut mask = access.mask();
            if options.is_truncate() {
                mask |= WRITE;
            }
            inode::may_open(identity, &node, mask)?;
        }

        let fd = if access == Access::Path {
            res.fd
        } else if res.stat.kind == HostKind::Dir {
            if access.writes() || options.is_truncate() {
                return Err(Errno::EISDIR);
            }
            sys::upgrade_dir_fd(res.fd.as_fd())?
        } else {
            let fd = if !res.relpath.is_empty() {
                self.open_existing_host_file(
                    &res.relpath,
                    access,
                    options.is_truncate(),
                    &res.stat,
                    &res.key,
                )?
            } else {
                let fd = sys::open_proc_fd(
                    res.fd.as_fd(),
                    open_access_flags(access)? | libc::O_NONBLOCK,
                )?;
                let stx = sys::statx_fd(fd.as_fd())?;
                if stx.kind != HostKind::File {
                    return Err(Errno::ESTALE);
                }
                let live_gen = sys::capture_gen_from_fd(fd.as_fd(), &stx)?;
                if stx.ino != res.stat.ino
                    || stx.dev != res.stat.dev
                    || stx.mnt_id != res.stat.mnt_id
                    || stx.subvol != res.stat.subvol
                    || live_gen != res.key.host_gen
                {
                    return Err(Errno::ESTALE);
                }
                sys::clear_nonblock(fd.as_fd())?;
                if options.is_truncate() {
                    if access.writes() {
                        sys::ftruncate_fd(fd.as_fd(), 0)?;
                    } else {
                        let wfd =
                            sys::open_proc_fd(res.fd.as_fd(), libc::O_WRONLY | libc::O_NONBLOCK)?;
                        sys::clear_nonblock(wfd.as_fd())?;
                        sys::ftruncate_fd(wfd.as_fd(), 0)?;
                    }
                }
                fd
            };
            if options.is_truncate() {
                if let Some(rec) = self.store.get_mut(res.ino) {
                    inode::remove_privs(identity, &mut rec.node);
                    rec.meta_ctime = Some(sys::now_timespec());
                }
                self.store.flush()?;
            }
            fd
        };

        let generation = self.store.get(res.ino).ok_or(Errno::ESTALE)?.generation;
        let open = self.register_open(
            session_id,
            NodeId {
                ino: res.ino,
                generation,
            },
            res.key,
            access,
            res.stat.kind,
            fd,
        )?;
        self.record_open_ticket(
            session_id,
            ticket,
            OpenTicketState::Opened { open: open.clone() },
        );
        Ok(open)
    }

    fn open_existing_host_file(
        &self,
        rel: &str,
        access: Access,
        truncate: bool,
        expected: &HostStat,
        expected_key: &HostInodeKey,
    ) -> Result<OwnedFd, Errno> {
        sys::verify_fd_inside_root(&self.canonical_root, self.root_fd.as_fd())?;
        let flags = open_access_flags(access)? | libc::O_NOFOLLOW | libc::O_NONBLOCK;
        let fd = match sys::open_beneath(self.root_fd.as_fd(), rel, flags, 0) {
            Ok(fd) => fd,
            Err(Errno::ENXIO) => {
                // Nonblocking O_WRONLY on a replacement FIFO returns ENXIO; report ESTALE if the
                // entry is no longer the expected inode.
                if let Ok(probe) = sys::open_beneath(
                    self.root_fd.as_fd(),
                    rel,
                    libc::O_PATH | libc::O_NOFOLLOW,
                    0,
                ) && let Ok(pstx) = sys::statx_fd(probe.as_fd())
                    && (pstx.ino != expected.ino
                        || pstx.dev != expected.dev
                        || pstx.mnt_id != expected.mnt_id
                        || pstx.kind != HostKind::File)
                {
                    return Err(Errno::ESTALE);
                }
                return Err(Errno::ENXIO);
            }
            Err(e) => return Err(e),
        };
        let stx = sys::statx_fd(fd.as_fd())?;
        if stx.kind != HostKind::File {
            return Err(Errno::ESTALE);
        }
        let live_gen = sys::capture_gen_from_fd(fd.as_fd(), &stx)?;
        if stx.ino != expected.ino
            || stx.dev != expected.dev
            || stx.mnt_id != expected.mnt_id
            || stx.subvol != expected.subvol
            || live_gen != expected_key.host_gen
        {
            return Err(Errno::ESTALE);
        }
        sys::clear_nonblock(fd.as_fd())?;
        if truncate {
            if access.writes() {
                sys::ftruncate_fd(fd.as_fd(), 0)?;
            } else {
                let wfd = sys::open_beneath(
                    self.root_fd.as_fd(),
                    rel,
                    libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
                    0,
                )?;
                let wstx = sys::statx_fd(wfd.as_fd())?;
                if wstx.kind != HostKind::File {
                    return Err(Errno::ESTALE);
                }
                let wgen = sys::capture_gen_from_fd(wfd.as_fd(), &wstx)?;
                if wstx.ino != expected.ino
                    || wstx.dev != expected.dev
                    || wstx.mnt_id != expected.mnt_id
                    || wstx.subvol != expected.subvol
                    || wgen != expected_key.host_gen
                {
                    return Err(Errno::ESTALE);
                }
                sys::clear_nonblock(wfd.as_fd())?;
                sys::ftruncate_fd(wfd.as_fd(), 0)?;
            }
        }
        Ok(fd)
    }

    fn record_open_ticket(&mut self, session_id: &str, ticket: &str, state: OpenTicketState) {
        let Some(session) = self.sessions.get_mut(session_id) else {
            return;
        };
        if !session.open_tickets.contains_key(ticket) {
            session.open_ticket_order.push_back(ticket.to_owned());
        }
        session.open_tickets.insert(ticket.to_owned(), state);
        while session.open_ticket_order.len() > OPEN_TICKET_CAP {
            let Some(oldest) = session.open_ticket_order.pop_front() else {
                break;
            };
            session.open_tickets.remove(&oldest);
        }
    }

    fn do_cancel_open(&mut self, session_id: &str, ticket: &str) -> Result<(), Errno> {
        if ticket.is_empty() || ticket.len() > 128 {
            return Err(Errno::EINVAL);
        }
        let existing_open =
            {
                let Some(session) = self.sessions.get_mut(session_id) else {
                    return Err(Errno::ENODEV);
                };
                let prev = session
                    .open_tickets
                    .insert(ticket.to_owned(), OpenTicketState::Cancelled);
                if prev.is_none() {
                    session.open_ticket_order.push_back(ticket.to_owned());
                    while session.open_ticket_order.len() > OPEN_TICKET_CAP {
                        if let Some(oldest) = session.open_ticket_order.pop_front() {
                            session.open_tickets.remove(&oldest);
                        }
                    }
                }
                match prev {
                    Some(
                        OpenTicketState::Created { open, .. } | OpenTicketState::Opened { open },
                    ) if session.opens.contains_key(&open.id) => Some(open),
                    _ => None,
                }
            };
        if let Some(open) = existing_open {
            let _ = self.do_release(session_id, &open);
        }
        Ok(())
    }

    fn register_open(
        &mut self,
        session_id: &str,
        node: NodeId,
        host_key: HostInodeKey,
        access: Access,
        kind: HostKind,
        fd: OwnedFd,
    ) -> Result<OpenRef, Errno> {
        let id = self.next_open_id;
        self.next_open_id += 1;
        let subfs_relpath = host_key.subfs_relpath.clone();
        let Some(session) = self.sessions.get_mut(session_id) else {
            return Err(Errno::ENODEV);
        };
        session.opens.insert(
            id,
            OpenHandle {
                id,
                node_id: node,
                subfs_relpath,
                host_key,
                access,
                kind,
                fd,
            },
        );
        Ok(OpenRef {
            fs: self.store.fs_id().clone(),
            id,
            node,
            access,
        })
    }

    fn check_open(&self, session_id: &str, open: &OpenRef) -> Result<&OpenHandle, Errno> {
        lookup_open(&self.sessions, self.store.fs_id(), session_id, open)
    }

    fn do_read_at(
        &self,
        session_id: &str,
        open: &OpenRef,
        offset: u64,
        count: u64,
    ) -> Result<Vec<u8>, Errno> {
        let handle = self.check_open(session_id, open)?;
        if !handle.access.reads() {
            return Err(Errno::EBADF);
        }
        match handle.kind {
            HostKind::File => {}
            HostKind::Dir => return Err(Errno::EISDIR),
            _ => return Err(Errno::ENXIO),
        }
        let len = count.min(DATA_MAX) as usize;
        if len == 0 {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; len];
        let n = sys::pread_fd(handle.fd.as_fd(), &mut buf, offset)?;
        buf.truncate(n);
        Ok(buf)
    }

    fn do_write_at(
        &mut self,
        session_id: &str,
        identity: &Identity,
        grant: abi::local_helper::HelperGrant,
        open: &OpenRef,
        data: &[u8],
        at: WriteAt,
    ) -> Result<Written, Errno> {
        if !grant.write {
            return Err(Errno::EROFS);
        }
        let (ino, access, kind, raw_ok) = {
            let handle = self.check_open(session_id, open)?;
            if !handle.access.writes() {
                return Err(Errno::EBADF);
            }
            match handle.kind {
                HostKind::File => {}
                HostKind::Dir => return Err(Errno::EISDIR),
                _ => return Err(Errno::ENXIO),
            }
            if data.len() as u64 > DATA_MAX {
                return Err(Errno::EINVAL);
            }
            (handle.node_id.ino, handle.access, handle.kind, true)
        };
        let _ = (access, kind, raw_ok);

        let (offset, written) = {
            let fd = self.sessions[session_id].opens[&open.id].fd.as_fd();
            match at {
                WriteAt::Offset(off) => {
                    let n = sys::pwrite_fd(fd, data, off)?;
                    (off, n)
                }
                WriteAt::End => sys::pwrite_append_fd(fd, data)?,
            }
        };

        if let Some(rec) = self.store.get_mut(ino) {
            let prev_mode = rec.node.mode;
            inode::remove_privs(identity, &mut rec.node);
            if rec.node.mode != prev_mode {
                rec.meta_ctime = Some(sys::now_timespec());
                self.store.flush()?;
            }
        }
        Ok(Written {
            offset,
            len: written,
        })
    }

    fn do_set_len(
        &mut self,
        session_id: &str,
        identity: &Identity,
        grant: abi::local_helper::HelperGrant,
        open: &OpenRef,
        size: u64,
    ) -> Result<(), Errno> {
        if !grant.write {
            return Err(Errno::EROFS);
        }
        let ino = {
            let handle = self.check_open(session_id, open)?;
            if handle.access == Access::Path {
                return Err(Errno::EBADF);
            }
            if !handle.access.writes() || handle.kind != HostKind::File {
                return Err(Errno::EINVAL);
            }
            if size > FILE_MAX {
                return Err(Errno::EFBIG);
            }
            sys::ftruncate_fd(handle.fd.as_fd(), size)?;
            handle.node_id.ino
        };
        if let Some(rec) = self.store.get_mut(ino) {
            let prev_mode = rec.node.mode;
            inode::remove_privs(identity, &mut rec.node);
            if rec.node.mode != prev_mode {
                rec.meta_ctime = Some(sys::now_timespec());
                self.store.flush()?;
            }
        }
        Ok(())
    }

    fn do_sync(&self, session_id: &str, open: &OpenRef, data_only: bool) -> Result<(), Errno> {
        let handle = self.check_open(session_id, open)?;
        if handle.access == Access::Path {
            return Err(Errno::EBADF);
        }
        sys::sync_fd(handle.fd.as_fd(), data_only)
    }

    fn do_release(&mut self, session_id: &str, open: &OpenRef) -> Result<(), Errno> {
        if open.fs != *self.store.fs_id() {
            return Err(Errno::EBADF);
        }
        let session = self.sessions.get_mut(session_id).ok_or(Errno::ENODEV)?;
        let Some(handle) = session.opens.remove(&open.id) else {
            return Err(Errno::EBADF);
        };
        if handle.node_id != open.node {
            session.opens.insert(open.id, handle);
            return Err(Errno::EBADF);
        }
        let ino = handle.node_id.ino;
        self.locks.release_open(handle.id);
        drop(handle.fd);
        let still_open = self.is_ino_open(ino);
        self.store.gc_unlinked(ino, still_open)?;
        Ok(())
    }

    fn open_parent_of(&self, relpath: &str) -> Result<(OwnedFd, String), Errno> {
        let (parent_rel, name) = match relpath.rsplit_once('/') {
            Some((p, n)) => (p, n.to_owned()),
            None => ("", relpath.to_owned()),
        };
        check_component(&name)?;
        let (parent_fd, _stx, _key) = self.walk_relpath(parent_rel)?;
        Ok((parent_fd, name))
    }
}

fn require_live_dir(res: &ResolvedHandle, node: &Node) -> Result<(), Errno> {
    if res.stat.kind != HostKind::Dir || !node.directory {
        return Err(Errno::ENOTDIR);
    }
    if res.unlinked || res.stat.nlink == 0 {
        return Err(Errno::ENOENT);
    }
    Ok(())
}

fn join_rel(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_owned()
    } else {
        format!("{parent}/{name}")
    }
}

fn to_identity(cred: &WireCred) -> Identity {
    let mut groups: BTreeSet<u32> = cred.groups.iter().copied().collect();
    groups.insert(cred.group);
    Identity {
        id: cred.id,
        group: cred.group,
        groups,
    }
}

fn file_type_of(rec: &StoredNode, stx: &HostStat) -> FileType {
    if rec.node.rdev.is_some() {
        return FileType::CharDevice;
    }
    match stx.kind {
        HostKind::Dir => FileType::Dir,
        HostKind::File => FileType::File,
        HostKind::Symlink => FileType::Symlink,
        HostKind::Other => FileType::CharDevice,
    }
}

fn lookup_open<'a>(
    sessions: &'a HashMap<String, Session>,
    fs_id: &FsId,
    session_id: &str,
    open: &OpenRef,
) -> Result<&'a OpenHandle, Errno> {
    if open.fs != *fs_id {
        return Err(Errno::EBADF);
    }
    let session = sessions.get(session_id).ok_or(Errno::ENODEV)?;
    let handle = session.opens.get(&open.id).ok_or(Errno::EBADF)?;
    if handle.node_id != open.node {
        return Err(Errno::EBADF);
    }
    let _ = (&handle.subfs_relpath, &handle.host_key);
    Ok(handle)
}

fn metadata_of(rec: &StoredNode, stx: &HostStat) -> Metadata {
    let (atime, mtime, _host_ctime) = stx.times();
    let ctime_raw = match rec.meta_ctime {
        Some(mc) if mc > stx.ctime => mc,
        _ => stx.ctime,
    };
    Metadata {
        file_type: file_type_of(rec, stx),
        mode: rec.node.mode & 0o7777,
        nlink: stx.nlink,
        uid: rec.node.owner,
        gid: rec.node.group,
        size: stx.size,
        atime,
        mtime,
        ctime: sys::to_timespec(ctime_raw),
        rdev: rec.node.rdev.clone(),
        acl: rec.node.acl.is_some(),
    }
}

fn open_access_flags(access: Access) -> Result<libc::c_int, Errno> {
    match access {
        Access::Read | Access::Exec => Ok(libc::O_RDONLY),
        Access::Write => Ok(libc::O_WRONLY),
        Access::ReadWrite => Ok(libc::O_RDWR),
        Access::Path => Ok(libc::O_PATH),
    }
}

fn entry_exists(dir_fd: BorrowedFd<'_>, name: &str) -> Result<bool, Errno> {
    match sys::open_beneath(dir_fd, name, libc::O_PATH | libc::O_NOFOLLOW, 0) {
        Ok(_) => Ok(true),
        Err(Errno::ENOENT) => Ok(false),
        Err(e) => Err(e),
    }
}

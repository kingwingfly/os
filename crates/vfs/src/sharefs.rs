//! Shared-mount (`sharefs`) client driver (`docs/architecture/contract.md` §2.5, §3, §4, §5).
//! Preserves the publisher's [`FsId`], [`NodeId`], and [`profiles::EXPORT`] capabilities, while
//! mapping export revocation to `ProviderState::revoke()` (`EACCES`) and peer disconnect to
//! `ProviderState::lose()` (`ENOTCONN`, or `EIO` + uncertain write on in-flight mutations).

use crate::mount::{FsType, MountBacking, ProviderState};
use crate::{
    Access, BoxFuture, Conflict, Cred, DirEntry, Entry, FileType, Filesystem, FsId, Handle,
    LockFamily, LockKind, LockRange, Metadata, OpenOptions, OpenRef, RenameFlags, Result, SetAttr,
    StatFs, Stop, Walked, WriteAt, Written, XattrFlags, check_component, profiles,
};
use abi::Errno;
use abi::contract::FsCapabilities;
use std::cell::Cell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareError {
    /// Confirmed filesystem `Errno` returned by the publisher.
    Remote(Errno),
    /// Export explicitly revoked or receiver access withdrawn (`EACCES`).
    Revoked,
    /// Peer MessagePort / WebRTC / relay connection dropped (`ENOTCONN` / uncertain `EIO`).
    Disconnected,
}

pub type ShareFuture<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, ShareError>> + 'a>>;

pub trait ShareTransport {
    fn id(&self) -> &FsId;
    fn root(&self) -> Handle;

    fn lookup<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
    ) -> ShareFuture<'a, Entry>;

    fn walk<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        names: &'a [String],
    ) -> ShareFuture<'a, Walked> {
        Box::pin(async move {
            for name in names {
                check_component(name).map_err(ShareError::Remote)?;
            }
            let mut cur = dir.clone();
            let mut cur_kind: Option<FileType> = None;
            let mut entries = Vec::new();
            for (idx, name) in names.iter().enumerate() {
                if let Some(ft) = cur_kind {
                    let stop = match ft {
                        FileType::Dir => None,
                        FileType::Symlink => Some(Stop::Symlink(idx - 1)),
                        _ => Some(Stop::NotDirectory(idx - 1)),
                    };
                    if stop.is_some() {
                        return Ok(Walked { entries, stop });
                    }
                }
                match self.lookup(cred, &cur, name).await {
                    Ok(entry) => {
                        cur = entry.handle.clone();
                        cur_kind = Some(entry.metadata.file_type);
                        entries.push(entry);
                    }
                    Err(ShareError::Remote(Errno::ENOENT)) => {
                        return Ok(Walked {
                            entries,
                            stop: Some(Stop::Missing(idx)),
                        });
                    }
                    Err(e) => return Err(e),
                }
            }
            Ok(Walked {
                entries,
                stop: None,
            })
        })
    }

    fn parent<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
    ) -> ShareFuture<'a, Option<(Entry, String)>>;

    fn metadata<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> ShareFuture<'a, Metadata>;
    fn open_metadata<'a>(&'a self, open: &'a OpenRef) -> ShareFuture<'a, Metadata>;
    fn setattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        attr: &'a SetAttr,
    ) -> ShareFuture<'a, Metadata>;
    fn read_dir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle) -> ShareFuture<'a, Vec<DirEntry>>;
    fn read_link<'a>(&'a self, cred: &'a Cred, link: &'a Handle) -> ShareFuture<'a, String>;
    fn create<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        options: &'a OpenOptions,
    ) -> ShareFuture<'a, (Entry, OpenRef)>;
    fn mkdir<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
    ) -> ShareFuture<'a, Entry>;
    fn mknod<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        rdev: &'a str,
    ) -> ShareFuture<'a, Entry>;
    fn symlink<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        target: &'a str,
    ) -> ShareFuture<'a, Entry>;
    fn link<'a>(
        &'a self,
        cred: &'a Cred,
        target: &'a Handle,
        dir: &'a Handle,
        name: &'a str,
    ) -> ShareFuture<'a, Entry>;
    fn unlink<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> ShareFuture<'a, ()>;
    fn rmdir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> ShareFuture<'a, ()>;
    #[allow(clippy::too_many_arguments)]
    fn rename<'a>(
        &'a self,
        cred: &'a Cred,
        from_dir: &'a Handle,
        from: &'a str,
        to_dir: &'a Handle,
        to: &'a str,
        flags: RenameFlags,
    ) -> ShareFuture<'a, ()>;
    fn getxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> ShareFuture<'a, Vec<u8>>;
    fn setxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
        value: &'a [u8],
        flags: XattrFlags,
    ) -> ShareFuture<'a, ()>;
    fn listxattr<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> ShareFuture<'a, Vec<String>>;
    fn removexattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> ShareFuture<'a, ()>;
    fn statfs<'a>(&'a self, cred: &'a Cred) -> ShareFuture<'a, StatFs>;
    fn open<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        options: &'a OpenOptions,
    ) -> ShareFuture<'a, OpenRef>;
    fn read_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a mut [u8],
        offset: u64,
    ) -> ShareFuture<'a, usize>;
    fn write_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a [u8],
        at: WriteAt,
    ) -> ShareFuture<'a, Written>;
    fn set_len<'a>(&'a self, open: &'a OpenRef, size: u64) -> ShareFuture<'a, ()>;
    fn sync_all<'a>(&'a self, open: &'a OpenRef) -> ShareFuture<'a, ()>;
    fn sync_data<'a>(&'a self, open: &'a OpenRef) -> ShareFuture<'a, ()> {
        self.sync_all(open)
    }
    fn lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> ShareFuture<'a, ()>;
    fn try_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> ShareFuture<'a, ()>;
    fn unlock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        range: LockRange,
    ) -> ShareFuture<'a, ()>;
    fn test_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        kind: LockKind,
        range: LockRange,
    ) -> ShareFuture<'a, Option<Conflict>>;
    fn release<'a>(&'a self, open: &'a OpenRef) -> ShareFuture<'a, ()>;
}

pub struct ShareFs<T> {
    transport: T,
    provider: Rc<ProviderState>,
    grant_rdonly: bool,
    grant_noexec: bool,
}

impl<T: ShareTransport> ShareFs<T> {
    pub fn new(
        transport: T,
        provider: Rc<ProviderState>,
        grant_rdonly: bool,
        grant_noexec: bool,
    ) -> Self {
        Self {
            transport,
            provider,
            grant_rdonly,
            grant_noexec,
        }
    }

    pub fn provider(&self) -> &Rc<ProviderState> {
        &self.provider
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn into_backing(self) -> (Rc<MountBacking>, Handle)
    where
        T: 'static,
    {
        let root = self.transport.root();
        let provider = Rc::clone(&self.provider);
        let rdonly = self.grant_rdonly;
        let noexec = self.grant_noexec;
        let fs: Rc<dyn Filesystem> = Rc::new(self);
        let backing = MountBacking::new(fs, FsType::ShareFs)
            .with_provider(provider)
            .with_ceilings(rdonly, noexec);
        (Rc::new(backing), root)
    }

    fn map_err(&self, err: ShareError, is_mutating: bool) -> Errno {
        match err {
            ShareError::Remote(errno) => errno,
            ShareError::Revoked => {
                self.provider.revoke();
                Errno::EACCES
            }
            ShareError::Disconnected => {
                if self.provider.health() == crate::mount::ProviderHealth::Revoked {
                    return Errno::EACCES;
                }
                let in_guard = self.provider.is_in_guarded_poll();
                self.provider.lose();
                if is_mutating {
                    if !in_guard {
                        self.provider.record_uncertain_write();
                    }
                    Errno::EIO
                } else {
                    Errno::ENOTCONN
                }
            }
        }
    }

    async fn call<R, F>(&self, is_mutating: bool, check_rofs: bool, fut: F) -> Result<R>
    where
        F: Future<Output = std::result::Result<R, ShareError>>,
    {
        self.provider.check_health()?;
        if check_rofs && self.grant_rdonly {
            return Err(Errno::EROFS);
        }
        fut.await.map_err(|e| self.map_err(e, is_mutating))
    }
}

impl<T: ShareTransport> Filesystem for ShareFs<T> {
    fn id(&self) -> &FsId {
        self.transport.id()
    }

    fn capabilities(&self) -> FsCapabilities {
        profiles::EXPORT
    }

    fn root(&self) -> Handle {
        self.transport.root()
    }

    fn lookup<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(self.call(false, false, self.transport.lookup(cred, dir, name)))
    }

    fn walk<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        names: &'a [String],
    ) -> BoxFuture<'a, Walked> {
        Box::pin(self.call(false, false, self.transport.walk(cred, dir, names)))
    }

    fn parent<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
    ) -> BoxFuture<'a, Option<(Entry, String)>> {
        Box::pin(self.call(false, false, self.transport.parent(cred, dir)))
    }

    fn metadata<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Metadata> {
        Box::pin(self.call(false, false, self.transport.metadata(cred, handle)))
    }

    fn setattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        attr: &'a SetAttr,
    ) -> BoxFuture<'a, Metadata> {
        Box::pin(self.call(true, true, self.transport.setattr(cred, handle, attr)))
    }

    fn read_dir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle) -> BoxFuture<'a, Vec<DirEntry>> {
        Box::pin(self.call(false, false, self.transport.read_dir(cred, dir)))
    }

    fn read_link<'a>(&'a self, cred: &'a Cred, link: &'a Handle) -> BoxFuture<'a, String> {
        Box::pin(self.call(false, false, self.transport.read_link(cred, link)))
    }

    fn create<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        options: &'a OpenOptions,
    ) -> BoxFuture<'a, (Entry, OpenRef)> {
        Box::pin(self.call(
            true,
            true,
            self.transport.create(cred, dir, name, mode, options),
        ))
    }

    fn mkdir<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(self.call(true, true, self.transport.mkdir(cred, dir, name, mode)))
    }

    fn mknod<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        rdev: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(self.call(
            true,
            true,
            self.transport.mknod(cred, dir, name, mode, rdev),
        ))
    }

    fn symlink<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        target: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(self.call(true, true, self.transport.symlink(cred, dir, name, target)))
    }

    fn link<'a>(
        &'a self,
        cred: &'a Cred,
        target: &'a Handle,
        dir: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(self.call(true, true, self.transport.link(cred, target, dir, name)))
    }

    fn unlink<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(self.call(true, true, self.transport.unlink(cred, dir, name)))
    }

    fn rmdir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(self.call(true, true, self.transport.rmdir(cred, dir, name)))
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
        Box::pin(
            self.call(
                true,
                true,
                self.transport
                    .rename(cred, from_dir, from, to_dir, to, flags),
            ),
        )
    }

    fn getxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(self.call(false, false, self.transport.getxattr(cred, handle, name)))
    }

    fn setxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
        value: &'a [u8],
        flags: XattrFlags,
    ) -> BoxFuture<'a, ()> {
        Box::pin(self.call(
            true,
            true,
            self.transport.setxattr(cred, handle, name, value, flags),
        ))
    }

    fn listxattr<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Vec<String>> {
        Box::pin(self.call(false, false, self.transport.listxattr(cred, handle)))
    }

    fn removexattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, ()> {
        Box::pin(self.call(true, true, self.transport.removexattr(cred, handle, name)))
    }

    fn statfs<'a>(&'a self, cred: &'a Cred) -> BoxFuture<'a, StatFs> {
        Box::pin(self.call(false, false, self.transport.statfs(cred)))
    }

    fn open<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        options: &'a OpenOptions,
    ) -> BoxFuture<'a, OpenRef> {
        Box::pin(async move {
            self.provider.check_health()?;
            let access = options.access()?;
            if self.grant_noexec && access == Access::Exec {
                return Err(Errno::EACCES);
            }
            let wants_write = access.writes() || options.is_truncate();
            if self.grant_rdonly && wants_write {
                return Err(Errno::EROFS);
            }
            self.transport
                .open(cred, handle, options)
                .await
                .map_err(|e| self.map_err(e, options.is_truncate()))
        })
    }

    fn open_metadata<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, Metadata> {
        Box::pin(self.call(false, false, self.transport.open_metadata(open)))
    }

    fn read_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a mut [u8],
        offset: u64,
    ) -> BoxFuture<'a, usize> {
        Box::pin(self.call(false, false, self.transport.read_at(open, buf, offset)))
    }

    fn write_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a [u8],
        at: WriteAt,
    ) -> BoxFuture<'a, Written> {
        Box::pin(self.call(
            !buf.is_empty(),
            true,
            self.transport.write_at(open, buf, at),
        ))
    }

    fn set_len<'a>(&'a self, open: &'a OpenRef, size: u64) -> BoxFuture<'a, ()> {
        Box::pin(self.call(true, true, self.transport.set_len(open, size)))
    }

    fn sync_all<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        if open.access == Access::Path {
            return Box::pin(async { Err(Errno::EBADF) });
        }
        Box::pin(self.call(false, false, self.transport.sync_all(open)))
    }

    fn sync_data<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        if open.access == Access::Path {
            return Box::pin(async { Err(Errno::EBADF) });
        }
        Box::pin(self.call(false, false, self.transport.sync_data(open)))
    }

    fn lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        Box::pin(self.call(false, false, self.transport.lock(open, family, kind, range)))
    }

    fn try_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        Box::pin(self.call(
            false,
            false,
            self.transport.try_lock(open, family, kind, range),
        ))
    }

    fn unlock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        Box::pin(self.call(false, false, self.transport.unlock(open, family, range)))
    }

    fn test_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, Option<Conflict>> {
        Box::pin(self.call(false, false, self.transport.test_lock(open, kind, range)))
    }

    fn release<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        Box::pin(self.call(false, false, self.transport.release(open)))
    }
}

/// In-process [`ShareTransport`] forwarding to an underlying [`Filesystem`], with live revocation
/// and disconnect simulation hooks for same-instance exports and integration tests.
pub struct LoopbackShareTransport {
    fs: Rc<dyn Filesystem>,
    root: Handle,
    fault: Rc<Cell<Option<ShareError>>>,
}

impl LoopbackShareTransport {
    pub fn new(fs: Rc<dyn Filesystem>) -> Self {
        let root = fs.root();
        Self {
            fs,
            root,
            fault: Rc::new(Cell::new(None)),
        }
    }

    pub fn with_subroot(fs: Rc<dyn Filesystem>, root: Handle) -> Self {
        Self {
            fs,
            root,
            fault: Rc::new(Cell::new(None)),
        }
    }

    pub fn fault_handle(&self) -> Rc<Cell<Option<ShareError>>> {
        Rc::clone(&self.fault)
    }

    fn gate(&self) -> std::result::Result<(), ShareError> {
        match self.fault.get() {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }
}

macro_rules! loopback_op {
    ($self:ident, $fut:expr) => {{
        Box::pin(async move {
            $self.gate()?;
            let res = $fut.await;
            $self.gate()?;
            res.map_err(ShareError::Remote)
        })
    }};
}

impl ShareTransport for LoopbackShareTransport {
    fn id(&self) -> &FsId {
        self.fs.id()
    }
    fn root(&self) -> Handle {
        self.root.clone()
    }
    fn lookup<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
    ) -> ShareFuture<'a, Entry> {
        loopback_op!(self, self.fs.lookup(cred, dir, name))
    }
    fn walk<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        names: &'a [String],
    ) -> ShareFuture<'a, Walked> {
        loopback_op!(self, self.fs.walk(cred, dir, names))
    }
    fn parent<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
    ) -> ShareFuture<'a, Option<(Entry, String)>> {
        loopback_op!(self, self.fs.parent(cred, dir))
    }
    fn metadata<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> ShareFuture<'a, Metadata> {
        loopback_op!(self, self.fs.metadata(cred, handle))
    }
    fn open_metadata<'a>(&'a self, open: &'a OpenRef) -> ShareFuture<'a, Metadata> {
        loopback_op!(self, self.fs.open_metadata(open))
    }
    fn setattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        attr: &'a SetAttr,
    ) -> ShareFuture<'a, Metadata> {
        loopback_op!(self, self.fs.setattr(cred, handle, attr))
    }
    fn read_dir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle) -> ShareFuture<'a, Vec<DirEntry>> {
        loopback_op!(self, self.fs.read_dir(cred, dir))
    }
    fn read_link<'a>(&'a self, cred: &'a Cred, link: &'a Handle) -> ShareFuture<'a, String> {
        loopback_op!(self, self.fs.read_link(cred, link))
    }
    fn create<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        options: &'a OpenOptions,
    ) -> ShareFuture<'a, (Entry, OpenRef)> {
        loopback_op!(self, self.fs.create(cred, dir, name, mode, options))
    }
    fn mkdir<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
    ) -> ShareFuture<'a, Entry> {
        loopback_op!(self, self.fs.mkdir(cred, dir, name, mode))
    }
    fn mknod<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        rdev: &'a str,
    ) -> ShareFuture<'a, Entry> {
        loopback_op!(self, self.fs.mknod(cred, dir, name, mode, rdev))
    }
    fn symlink<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        target: &'a str,
    ) -> ShareFuture<'a, Entry> {
        loopback_op!(self, self.fs.symlink(cred, dir, name, target))
    }
    fn link<'a>(
        &'a self,
        cred: &'a Cred,
        target: &'a Handle,
        dir: &'a Handle,
        name: &'a str,
    ) -> ShareFuture<'a, Entry> {
        loopback_op!(self, self.fs.link(cred, target, dir, name))
    }
    fn unlink<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> ShareFuture<'a, ()> {
        loopback_op!(self, self.fs.unlink(cred, dir, name))
    }
    fn rmdir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> ShareFuture<'a, ()> {
        loopback_op!(self, self.fs.rmdir(cred, dir, name))
    }
    fn rename<'a>(
        &'a self,
        cred: &'a Cred,
        from_dir: &'a Handle,
        from: &'a str,
        to_dir: &'a Handle,
        to: &'a str,
        flags: RenameFlags,
    ) -> ShareFuture<'a, ()> {
        loopback_op!(
            self,
            self.fs.rename(cred, from_dir, from, to_dir, to, flags)
        )
    }
    fn getxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> ShareFuture<'a, Vec<u8>> {
        loopback_op!(self, self.fs.getxattr(cred, handle, name))
    }
    fn setxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
        value: &'a [u8],
        flags: XattrFlags,
    ) -> ShareFuture<'a, ()> {
        loopback_op!(self, self.fs.setxattr(cred, handle, name, value, flags))
    }
    fn listxattr<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> ShareFuture<'a, Vec<String>> {
        loopback_op!(self, self.fs.listxattr(cred, handle))
    }
    fn removexattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> ShareFuture<'a, ()> {
        loopback_op!(self, self.fs.removexattr(cred, handle, name))
    }
    fn statfs<'a>(&'a self, cred: &'a Cred) -> ShareFuture<'a, StatFs> {
        loopback_op!(self, self.fs.statfs(cred))
    }
    fn open<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        options: &'a OpenOptions,
    ) -> ShareFuture<'a, OpenRef> {
        loopback_op!(self, self.fs.open(cred, handle, options))
    }
    fn read_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a mut [u8],
        offset: u64,
    ) -> ShareFuture<'a, usize> {
        loopback_op!(self, self.fs.read_at(open, buf, offset))
    }
    fn write_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a [u8],
        at: WriteAt,
    ) -> ShareFuture<'a, Written> {
        loopback_op!(self, self.fs.write_at(open, buf, at))
    }
    fn set_len<'a>(&'a self, open: &'a OpenRef, size: u64) -> ShareFuture<'a, ()> {
        loopback_op!(self, self.fs.set_len(open, size))
    }
    fn sync_all<'a>(&'a self, open: &'a OpenRef) -> ShareFuture<'a, ()> {
        loopback_op!(self, self.fs.sync_all(open))
    }
    fn sync_data<'a>(&'a self, open: &'a OpenRef) -> ShareFuture<'a, ()> {
        loopback_op!(self, self.fs.sync_data(open))
    }
    fn lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> ShareFuture<'a, ()> {
        loopback_op!(self, self.fs.lock(open, family, kind, range))
    }
    fn try_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> ShareFuture<'a, ()> {
        loopback_op!(self, self.fs.try_lock(open, family, kind, range))
    }
    fn unlock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        range: LockRange,
    ) -> ShareFuture<'a, ()> {
        loopback_op!(self, self.fs.unlock(open, family, range))
    }
    fn test_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        kind: LockKind,
        range: LockRange,
    ) -> ShareFuture<'a, Option<Conflict>> {
        loopback_op!(self, self.fs.test_lock(open, kind, range))
    }
    fn release<'a>(&'a self, open: &'a OpenRef) -> ShareFuture<'a, ()> {
        loopback_op!(self, self.fs.release(open))
    }
}

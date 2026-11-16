//! Open file descriptions (#48 scope 3, #51/#52 mount & namespace integration).
//! A [`File`] is Linux's `struct file`: its position and status flags are shared by every
//! descriptor that refers to it, in this process (`dup`) and in its children (`fork`).
//!
//! When opened through [`crate::Vfs`], a [`File`] carries `mount: Some(MountPin)`, enforcing
//! user-mount `owner_uid` ceilings (`EACCES` even for `uid 0`), `MS_RDONLY` (`EROFS`),
//! `MS_SYNCHRONOUS` durability, export revocation (`EACCES`), provider loss (`ENOTCONN` / `EIO`
//! uncertain writes), and `MNT_FORCE` (`EIO`).

use crate::mount::{MountPin, ProviderHealth};
use crate::namespace::MountNamespace;
use crate::{
    Access, Conflict, Cred, Filesystem, Handle, LockFamily, LockKind, LockRange, Metadata,
    OpenOptions, OpenRef, Result, SeekFrom, Timespec, WriteAt,
};
use abi::Errno;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::rc::Rc;
use std::task::{Poll, Waker};

/// The driver releases owed by descriptions whose last reference was dropped rather than
/// closed. The kernel runs [`ReleaseQueue::flush`] when it next can, as Linux's
/// `task_work_run` and `delayed_fput` run the last `fput`.
#[derive(Clone, Default)]
pub struct ReleaseQueue(Rc<RefCell<Vec<Release>>>);

type Release = (Rc<dyn Filesystem>, OpenRef);

/// A release removed from the queue but not yet answered. Cancellation puts it back.
struct PendingRelease<'a> {
    queue: &'a ReleaseQueue,
    item: Option<Release>,
}
impl Drop for PendingRelease<'_> {
    fn drop(&mut self) {
        if let Some((fs, open)) = self.item.take() {
            self.queue.push(fs, open);
        }
    }
}

impl ReleaseQueue {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.0.borrow().len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.borrow().is_empty()
    }
    fn push(&self, fs: Rc<dyn Filesystem>, open: OpenRef) {
        self.0.borrow_mut().push((fs, open));
    }
    /// Release every open reference queued, and say how the first that failed did. Every
    /// release is tried, whatever an earlier one says.
    pub async fn flush(&self) -> Result<()> {
        let mut result = Ok(());
        loop {
            let next = self.0.borrow_mut().pop();
            let Some(item) = next else {
                return result;
            };
            let mut pending = PendingRelease {
                queue: self,
                item: Some(item),
            };
            let (fs, open) = pending.item.as_ref().expect("pending release");
            let released = fs.release(open).await;
            pending.item.take();
            if result.is_ok() {
                result = released;
            }
        }
    }
}

/// Linux's `f_pos_lock`: one read, write or seek at a time moves a description's position, so
/// calls through `dup`ed and inherited descriptors never use the same bytes twice.
#[derive(Default)]
struct PosLock {
    held: Cell<bool>,
    next_waiter: Cell<u64>,
    waiters: RefCell<BTreeMap<u64, Waker>>,
}
struct PosGuard<'a>(&'a PosLock);
struct PosWait<'a> {
    lock: &'a PosLock,
    id: u64,
}
impl Drop for PosWait<'_> {
    fn drop(&mut self) {
        self.lock.waiters.borrow_mut().remove(&self.id);
    }
}
impl PosLock {
    async fn lock(&self) -> PosGuard<'_> {
        let id = self.next_waiter.get();
        self.next_waiter.set(id + 1);
        let _wait = PosWait { lock: self, id };
        poll_fn(|context| {
            if self.held.replace(true) {
                self.waiters
                    .borrow_mut()
                    .insert(id, context.waker().clone());
                Poll::Pending
            } else {
                Poll::Ready(PosGuard(self))
            }
        })
        .await
    }
}
impl Drop for PosGuard<'_> {
    fn drop(&mut self) {
        self.0.held.set(false);
        for waker in self.0.waiters.take().into_values() {
            waker.wake();
        }
    }
}

/// Kernel namespace payload carried by a `/proc/<pid>/ns/mnt` file description (`setns(2)`).
#[derive(Clone)]
pub struct MountNsFile {
    pub instance_id: String,
    pub ns: Rc<RefCell<MountNamespace>>,
}

enum FilePayload {
    Driver,
    MountNs(MountNsFile),
    VirtualBytes {
        bytes: Rc<Vec<u8>>,
        metadata: Metadata,
    },
}

/// An open file description.
pub struct File {
    fs: Rc<dyn Filesystem>,
    open: OpenRef,
    handle: Handle,
    /// The opener's credential, as Linux keeps `f_cred`; never current-call authentication.
    cred: Cred,
    mount: Option<MountPin>,
    payload: FilePayload,
    writable_tracked: Cell<bool>,
    pos: Cell<u64>,
    pos_lock: PosLock,
    append: Cell<bool>,
    /// The counted references ([`FileRef`]) to it.
    refs: Cell<usize>,
    releases: ReleaseQueue,
}

impl Drop for File {
    fn drop(&mut self) {
        self.release_writable_tracking();
    }
}

impl File {
    pub fn fs(&self) -> &Rc<dyn Filesystem> {
        &self.fs
    }
    /// The driver's open reference.
    pub fn open_ref(&self) -> &OpenRef {
        &self.open
    }
    pub fn handle(&self) -> &Handle {
        &self.handle
    }
    pub fn cred(&self) -> &Cred {
        &self.cred
    }
    pub fn access(&self) -> Access {
        self.open.access
    }
    pub fn mount_pin(&self) -> Option<&MountPin> {
        self.mount.as_ref()
    }
    pub fn mount_ns(&self) -> Option<&MountNsFile> {
        match &self.payload {
            FilePayload::MountNs(ns) => Some(ns),
            _ => None,
        }
    }
    pub fn is_virtual(&self) -> bool {
        !matches!(self.payload, FilePayload::Driver)
    }
    /// The position reads and writes move, as `Seek::stream_position` reads it.
    pub fn position(&self) -> u64 {
        self.pos.get()
    }
    pub fn is_append(&self) -> bool {
        self.append.get()
    }
    /// fcntl(F_SETFL) of O_APPEND: shared by every descriptor of the description.
    pub fn set_append(&self, append: bool) {
        self.append.set(append);
    }

    fn release_writable_tracking(&self) {
        if self.writable_tracked.replace(false)
            && let Some(pin) = &self.mount
        {
            pin.slot().dec_writable_opens();
        }
    }

    async fn guard<T, F>(
        &self,
        cred: &Cred,
        is_mutating: bool,
        check_rofs: bool,
        fut: F,
    ) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        if let Some(pin) = &self.mount {
            pin.guard_op(cred, is_mutating, check_rofs, fut).await
        } else {
            fut.await
        }
    }
}

/// One counted reference to a [`File`]. See the module's documentation.
pub struct FileRef {
    file: Rc<File>,
    /// Whether dropping it gives its reference back: [`FileRef::close`] gives it back itself.
    counted: bool,
}

impl std::ops::Deref for FileRef {
    type Target = File;
    fn deref(&self) -> &File {
        &self.file
    }
}

impl Clone for FileRef {
    fn clone(&self) -> Self {
        self.file.refs.set(self.file.refs.get() + 1);
        Self {
            file: self.file.clone(),
            counted: true,
        }
    }
}

impl Drop for FileRef {
    fn drop(&mut self) {
        if self.counted && self.put() {
            self.file.release_writable_tracking();
            if matches!(self.file.payload, FilePayload::Driver) {
                self.file
                    .releases
                    .push(self.file.fs.clone(), self.file.open.clone());
            }
        }
    }
}

impl FileRef {
    /// A new description of the open reference `open`, which the driver gave for `handle` and
    /// `cred`, with the status `options` give (`O_APPEND`); its last reference, dropped, is
    /// released through `releases`.
    pub fn new(
        fs: Rc<dyn Filesystem>,
        open: OpenRef,
        handle: Handle,
        cred: Cred,
        options: &OpenOptions,
        releases: &ReleaseQueue,
    ) -> Self {
        Self {
            file: Rc::new(File {
                fs,
                open,
                handle,
                cred,
                mount: None,
                payload: FilePayload::Driver,
                writable_tracked: Cell::new(false),
                pos: Cell::new(0),
                pos_lock: PosLock::default(),
                append: Cell::new(options.is_append()),
                refs: Cell::new(1),
                releases: releases.clone(),
            }),
            counted: true,
        }
    }

    /// A mount-pinned description opened through [`crate::Vfs`]. Tracks `MountPin` busy count
    /// and writable-open count (`remount,ro -> EBUSY`).
    pub fn new_mounted(
        pin: MountPin,
        open: OpenRef,
        handle: Handle,
        cred: Cred,
        options: &OpenOptions,
        releases: &ReleaseQueue,
    ) -> Self {
        let fs = Rc::clone(pin.fs());
        let writable = open.access.writes();
        if writable {
            pin.slot().inc_writable_opens();
        }
        Self {
            file: Rc::new(File {
                fs,
                open,
                handle,
                cred,
                mount: Some(pin),
                payload: FilePayload::Driver,
                writable_tracked: Cell::new(writable),
                pos: Cell::new(0),
                pos_lock: PosLock::default(),
                append: Cell::new(options.is_append()),
                refs: Cell::new(1),
                releases: releases.clone(),
            }),
            counted: true,
        }
    }

    /// A kernel namespace description opened from `/proc/<pid>/ns/mnt` for `setns(2)`.
    pub fn new_mount_ns(
        proc_fs: Rc<dyn Filesystem>,
        pin: Option<MountPin>,
        instance_id: String,
        ns: Rc<RefCell<MountNamespace>>,
        access: Access,
        cred: Cred,
        releases: &ReleaseQueue,
    ) -> Self {
        let ino = ns.borrow().id().0;
        let node = crate::NodeId { ino, generation: 1 };
        let fs_id = proc_fs.id().clone();
        let handle = Handle {
            fs: fs_id.clone(),
            node,
            proof: String::new(),
        };
        let open = OpenRef {
            fs: fs_id,
            id: 0,
            node,
            access,
        };
        Self {
            file: Rc::new(File {
                fs: proc_fs,
                open,
                handle,
                cred,
                mount: pin,
                payload: FilePayload::MountNs(MountNsFile { instance_id, ns }),
                writable_tracked: Cell::new(false),
                pos: Cell::new(0),
                pos_lock: PosLock::default(),
                append: Cell::new(false),
                refs: Cell::new(1),
                releases: releases.clone(),
            }),
            counted: true,
        }
    }

    /// A synthesized read-only virtual file (e.g. `/proc/<pid>/mountinfo`, `/proc/<pid>/mounts`,
    /// `/proc/<pid>/fdinfo/<n>`) whose snapshot bytes are captured at open time.
    #[allow(clippy::too_many_arguments)]
    pub fn new_virtual_bytes(
        fs: Rc<dyn Filesystem>,
        pin: Option<MountPin>,
        handle: Handle,
        access: Access,
        cred: Cred,
        bytes: Vec<u8>,
        mut metadata: Metadata,
        releases: &ReleaseQueue,
    ) -> Self {
        metadata.size = bytes.len() as u64;
        let open = OpenRef {
            fs: fs.id().clone(),
            id: 0,
            node: handle.node,
            access,
        };
        Self {
            file: Rc::new(File {
                fs,
                open,
                handle,
                cred,
                mount: pin,
                payload: FilePayload::VirtualBytes {
                    bytes: Rc::new(bytes),
                    metadata,
                },
                writable_tracked: Cell::new(false),
                pos: Cell::new(0),
                pos_lock: PosLock::default(),
                append: Cell::new(false),
                refs: Cell::new(1),
                releases: releases.clone(),
            }),
            counted: true,
        }
    }

    /// Whether two references are to the same description.
    pub fn ptr_eq(&self, other: &FileRef) -> bool {
        Rc::ptr_eq(&self.file, &other.file)
    }

    /// Give this reference back; whether it was the last.
    fn put(&self) -> bool {
        let refs = self.file.refs.get() - 1;
        self.file.refs.set(refs);
        refs == 0
    }

    /// close(2): give this reference back now. If it was the last, the driver's open reference
    /// is released before this returns, and its error, if any, is close's (except on revoked or
    /// lost mounts where local descriptor cleanup succeeds per contract §4).
    pub async fn close(mut self) -> Result<()> {
        let result = if self.file.refs.get() == 1 {
            self.file.release_writable_tracking();
            match &self.file.payload {
                FilePayload::Driver => {
                    let released = self.file.fs.release(&self.file.open).await;
                    if self
                        .file
                        .mount
                        .as_ref()
                        .is_some_and(|p| p.health() != ProviderHealth::Connected)
                    {
                        Ok(())
                    } else {
                        released
                    }
                }
                FilePayload::MountNs(_) | FilePayload::VirtualBytes { .. } => Ok(()),
            }
        } else {
            Ok(())
        };
        self.counted = false;
        self.put();
        result
    }

    /// stat through the description (fstat).
    pub async fn metadata(&self) -> Result<Metadata> {
        self.metadata_as(&self.cred).await
    }

    pub async fn metadata_as(&self, cred: &Cred) -> Result<Metadata> {
        let _call = self.clone();
        match &self.payload {
            FilePayload::Driver => {
                self.guard(cred, false, false, self.fs.open_metadata(&self.open))
                    .await
            }
            FilePayload::MountNs(_) => {
                if let Some(pin) = &self.mount {
                    pin.guard_enter(cred)?;
                }
                Ok(Metadata {
                    file_type: crate::FileType::File,
                    mode: 0o444,
                    nlink: 1,
                    uid: 0,
                    gid: 0,
                    size: 0,
                    atime: Timespec::default(),
                    mtime: Timespec::default(),
                    ctime: Timespec::default(),
                    rdev: None,
                    acl: false,
                })
            }
            FilePayload::VirtualBytes { metadata, .. } => {
                if let Some(pin) = &self.mount {
                    pin.guard_enter(cred)?;
                }
                Ok(metadata.clone())
            }
        }
    }

    /// lseek(2), as `Seek::seek`: EINVAL for a position before 0.
    pub async fn seek(&self, from: SeekFrom) -> Result<u64> {
        self.seek_as(&self.cred, from).await
    }

    pub async fn seek_as(&self, cred: &Cred, from: SeekFrom) -> Result<u64> {
        if self.access() == Access::Path {
            return Err(Errno::EBADF);
        }
        if matches!(self.payload, FilePayload::MountNs(_)) {
            return Err(Errno::EINVAL);
        }
        let _call = self.clone();
        let _pos = self.pos_lock.lock().await;
        let (base, offset) = match from {
            SeekFrom::Start(at) => {
                if let Some(pin) = &self.mount {
                    pin.guard_enter(cred)?;
                }
                (at, 0)
            }
            SeekFrom::Current(offset) => {
                if let Some(pin) = &self.mount {
                    pin.guard_enter(cred)?;
                }
                (self.pos.get(), offset)
            }
            SeekFrom::End(offset) => {
                let size = match &self.payload {
                    FilePayload::Driver => {
                        self.guard(cred, false, false, self.fs.open_metadata(&self.open))
                            .await?
                            .size
                    }
                    FilePayload::VirtualBytes { bytes, .. } => {
                        if let Some(pin) = &self.mount {
                            pin.guard_enter(cred)?;
                        }
                        bytes.len() as u64
                    }
                    FilePayload::MountNs(_) => unreachable!(),
                };
                (size, offset)
            }
        };
        let at = base.checked_add_signed(offset).ok_or(Errno::EINVAL)?;
        if at > crate::FILE_MAX {
            return Err(Errno::EINVAL);
        }
        self.pos.set(at);
        Ok(at)
    }

    /// read(2): into `buf` from the shared position, which moves past what was read.
    pub async fn read(&self, buf: &mut [u8]) -> Result<usize> {
        self.read_as(&self.cred, buf).await
    }

    pub async fn read_as(&self, cred: &Cred, buf: &mut [u8]) -> Result<usize> {
        if !self.access().reads() {
            return Err(Errno::EBADF);
        }
        if matches!(self.payload, FilePayload::MountNs(_)) {
            return Err(Errno::EINVAL);
        }
        let _call = self.clone();
        let _pos = self.pos_lock.lock().await;
        let at = self.pos.get();
        let read = match &self.payload {
            FilePayload::Driver => {
                self.guard(cred, false, false, self.fs.read_at(&self.open, buf, at))
                    .await?
            }
            FilePayload::VirtualBytes { bytes, .. } => {
                if let Some(pin) = &self.mount {
                    pin.guard_enter(cred)?;
                }
                read_slice(bytes, at, buf)?
            }
            FilePayload::MountNs(_) => unreachable!(),
        };
        self.pos.set(at + read as u64);
        Ok(read)
    }

    /// write(2): at the shared position, or, with O_APPEND, at the end as the driver finds it
    /// when the write lands.
    pub async fn write(&self, buf: &[u8]) -> Result<usize> {
        self.write_as(&self.cred, buf).await
    }

    pub async fn write_as(&self, cred: &Cred, buf: &[u8]) -> Result<usize> {
        if matches!(self.payload, FilePayload::MountNs(_)) {
            return Err(if self.access().writes() {
                Errno::EINVAL
            } else {
                Errno::EBADF
            });
        }
        if !self.access().writes() || matches!(self.payload, FilePayload::VirtualBytes { .. }) {
            return Err(Errno::EBADF);
        }
        let _call = self.clone();
        let _pos = self.pos_lock.lock().await;
        let at = if self.is_append() {
            WriteAt::End
        } else {
            WriteAt::Offset(self.pos.get())
        };
        let written = self
            .guard(cred, true, true, self.fs.write_at(&self.open, buf, at))
            .await?;
        if written.len > 0 {
            self.pos.set(written.offset + written.len as u64);
            if let Some(pin) = &self.mount
                && pin.effective_flags().synchronous
            {
                pin.guard_op(cred, true, false, self.fs.sync_all(&self.open))
                    .await?;
                pin.backing().record_sync();
            }
        }
        Ok(written.len)
    }

    /// pread(2), as `FileExt::read_at`: the position does not move.
    pub async fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize> {
        self.read_at_as(&self.cred, buf, offset).await
    }

    pub async fn read_at_as(&self, cred: &Cred, buf: &mut [u8], offset: u64) -> Result<usize> {
        if !self.access().reads() {
            return Err(Errno::EBADF);
        }
        let _call = self.clone();
        match &self.payload {
            FilePayload::Driver => {
                self.guard(cred, false, false, self.fs.read_at(&self.open, buf, offset))
                    .await
            }
            FilePayload::VirtualBytes { bytes, .. } => {
                if let Some(pin) = &self.mount {
                    pin.guard_enter(cred)?;
                }
                read_slice(bytes, offset, buf)
            }
            FilePayload::MountNs(_) => Err(Errno::EINVAL),
        }
    }

    /// pwrite(2), as `FileExt::write_at`: the position does not move.
    pub async fn write_at(&self, buf: &[u8], offset: u64) -> Result<usize> {
        self.write_at_as(&self.cred, buf, offset).await
    }

    pub async fn write_at_as(&self, cred: &Cred, buf: &[u8], offset: u64) -> Result<usize> {
        if matches!(self.payload, FilePayload::MountNs(_)) {
            return Err(if self.access().writes() {
                Errno::EINVAL
            } else {
                Errno::EBADF
            });
        }
        if !self.access().writes() || matches!(self.payload, FilePayload::VirtualBytes { .. }) {
            return Err(Errno::EBADF);
        }
        let _call = self.clone();
        let at = if self.is_append() {
            WriteAt::End
        } else {
            WriteAt::Offset(offset)
        };
        let written = self
            .guard(cred, true, true, self.fs.write_at(&self.open, buf, at))
            .await?;
        if written.len > 0
            && let Some(pin) = &self.mount
            && pin.effective_flags().synchronous
        {
            pin.guard_op(cred, true, false, self.fs.sync_all(&self.open))
                .await?;
            pin.backing().record_sync();
        }
        Ok(written.len)
    }

    /// ftruncate(2), as `File::set_len`.
    pub async fn set_len(&self, size: u64) -> Result<()> {
        self.set_len_as(&self.cred, size).await
    }

    pub async fn set_len_as(&self, cred: &Cred, size: u64) -> Result<()> {
        if !matches!(self.payload, FilePayload::Driver) {
            return Err(Errno::EINVAL);
        }
        let _call = self.clone();
        self.guard(cred, true, true, self.fs.set_len(&self.open, size))
            .await?;
        if let Some(pin) = &self.mount
            && pin.effective_flags().synchronous
        {
            pin.guard_op(cred, true, false, self.fs.sync_all(&self.open))
                .await?;
            pin.backing().record_sync();
        }
        Ok(())
    }

    /// fsync(2), as `File::sync_all`.
    pub async fn sync_all(&self) -> Result<()> {
        self.sync_all_as(&self.cred).await
    }

    pub async fn sync_all_as(&self, cred: &Cred) -> Result<()> {
        let _call = self.clone();
        match &self.payload {
            FilePayload::Driver => {
                self.guard(cred, true, false, self.fs.sync_all(&self.open))
                    .await
            }
            FilePayload::VirtualBytes { .. } => {
                if self.access() == Access::Path {
                    return Err(Errno::EBADF);
                }
                if let Some(pin) = &self.mount {
                    pin.guard_enter(cred)?;
                }
                Ok(())
            }
            FilePayload::MountNs(_) => Err(Errno::EINVAL),
        }
    }

    /// fdatasync(2), as `File::sync_data`.
    pub async fn sync_data(&self) -> Result<()> {
        self.sync_data_as(&self.cred).await
    }

    pub async fn sync_data_as(&self, cred: &Cred) -> Result<()> {
        let _call = self.clone();
        match &self.payload {
            FilePayload::Driver => {
                self.guard(cred, true, false, self.fs.sync_data(&self.open))
                    .await
            }
            FilePayload::VirtualBytes { .. } => {
                if self.access() == Access::Path {
                    return Err(Errno::EBADF);
                }
                if let Some(pin) = &self.mount {
                    pin.guard_enter(cred)?;
                }
                Ok(())
            }
            FilePayload::MountNs(_) => Err(Errno::EINVAL),
        }
    }

    /// flock(2) or F_SETLKW: wait until the lock is granted, as `File::lock`.
    pub async fn lock(&self, family: LockFamily, kind: LockKind, range: LockRange) -> Result<()> {
        self.lock_as(&self.cred, family, kind, range).await
    }

    pub async fn lock_as(
        &self,
        cred: &Cred,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> Result<()> {
        if !matches!(self.payload, FilePayload::Driver) {
            return Err(Errno::EINVAL);
        }
        let _call = self.clone();
        self.guard(
            cred,
            false,
            false,
            self.fs.lock(&self.open, family, kind, range),
        )
        .await
    }

    /// flock(2) with LOCK_NB, or F_SETLK: EAGAIN on a conflict, as `File::try_lock`.
    pub async fn try_lock(
        &self,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> Result<()> {
        self.try_lock_as(&self.cred, family, kind, range).await
    }

    pub async fn try_lock_as(
        &self,
        cred: &Cred,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> Result<()> {
        if !matches!(self.payload, FilePayload::Driver) {
            return Err(Errno::EINVAL);
        }
        let _call = self.clone();
        self.guard(
            cred,
            false,
            false,
            self.fs.try_lock(&self.open, family, kind, range),
        )
        .await
    }

    pub async fn unlock(&self, family: LockFamily, range: LockRange) -> Result<()> {
        self.unlock_as(&self.cred, family, range).await
    }

    pub async fn unlock_as(&self, cred: &Cred, family: LockFamily, range: LockRange) -> Result<()> {
        if !matches!(self.payload, FilePayload::Driver) {
            return Err(Errno::EINVAL);
        }
        let _call = self.clone();
        self.guard(
            cred,
            false,
            false,
            self.fs.unlock(&self.open, family, range),
        )
        .await
    }

    /// F_GETLK.
    pub async fn test_lock(&self, kind: LockKind, range: LockRange) -> Result<Option<Conflict>> {
        self.test_lock_as(&self.cred, kind, range).await
    }

    pub async fn test_lock_as(
        &self,
        cred: &Cred,
        kind: LockKind,
        range: LockRange,
    ) -> Result<Option<Conflict>> {
        if !matches!(self.payload, FilePayload::Driver) {
            return Err(Errno::EINVAL);
        }
        let _call = self.clone();
        self.guard(
            cred,
            false,
            false,
            self.fs.test_lock(&self.open, kind, range),
        )
        .await
    }
}

fn read_slice(bytes: &[u8], offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset > crate::FILE_MAX {
        return Err(Errno::EINVAL);
    }
    if buf.len() as u64 > crate::FILE_MAX - offset {
        return Err(Errno::EINVAL);
    }
    if offset >= bytes.len() as u64 {
        return Ok(0);
    }
    let start = offset as usize;
    let len = (bytes.len() - start).min(buf.len());
    buf[..len].copy_from_slice(&bytes[start..start + len]);
    Ok(len)
}

//! Open file descriptions (#48 scope 3). A [`File`] is Linux's `struct file`: its position and
//! status flags are shared by every descriptor that refers to it, in this process (`dup`) and in
//! its children (`fork`).
//!
//! A [`FileRef`] is one counted reference to a description, as Linux counts `f_count`: each
//! descriptor holds one, so does whatever keeps a description beyond a call (a descriptor in
//! transit, the loader), and so does each call in progress through it. References are owned
//! values: cloning one takes a reference (`get_file`), and dropping one gives it back (`fput`),
//! on every path, a cancelled call and a failed `insert` included. When the last goes, the
//! driver's open reference is released: at once by [`FileRef::close`], which reports how that
//! went, or, for a reference merely dropped, by the [`ReleaseQueue`], which the kernel drains as
//! Linux runs its delayed `fput`.

use crate::{
    Access, Conflict, Cred, Filesystem, Handle, LockFamily, LockKind, LockRange, Metadata,
    OpenOptions, OpenRef, Result, SeekFrom, WriteAt,
};
use abi::Errno;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::future::poll_fn;
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

/// An open file description.
pub struct File {
    fs: Rc<dyn Filesystem>,
    open: OpenRef,
    handle: Handle,
    /// The opener's credential, as Linux keeps `f_cred`; never current-call authentication.
    cred: Cred,
    pos: Cell<u64>,
    pos_lock: PosLock,
    append: Cell<bool>,
    /// The counted references ([`FileRef`]) to it.
    refs: Cell<usize>,
    releases: ReleaseQueue,
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
            self.file
                .releases
                .push(self.file.fs.clone(), self.file.open.clone());
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
                pos: Cell::new(0),
                pos_lock: PosLock::default(),
                append: Cell::new(options.is_append()),
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
    /// is released before this returns, and its error, if any, is close's.
    pub async fn close(mut self) -> Result<()> {
        // Keep the reference until release answers, so cancellation goes through Drop and
        // queues the outstanding release instead of losing the driver's open reference.
        let result = if self.file.refs.get() == 1 {
            self.file.fs.release(&self.file.open).await
        } else {
            Ok(())
        };
        self.counted = false;
        self.put();
        result
    }

    /// stat through the description (fstat).
    pub async fn metadata(&self) -> Result<Metadata> {
        let _call = self.clone();
        self.fs.open_metadata(&self.open).await
    }
    /// lseek(2), as `Seek::seek`: EINVAL for a position before 0.
    pub async fn seek(&self, from: SeekFrom) -> Result<u64> {
        if self.access() == Access::Path {
            return Err(Errno::EBADF);
        }
        let _call = self.clone();
        let _pos = self.pos_lock.lock().await;
        let (base, offset) = match from {
            SeekFrom::Start(at) => (at, 0),
            SeekFrom::Current(offset) => (self.pos.get(), offset),
            SeekFrom::End(offset) => (self.fs.open_metadata(&self.open).await?.size, offset),
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
        if !self.access().reads() {
            return Err(Errno::EBADF);
        }
        let _call = self.clone();
        let _pos = self.pos_lock.lock().await;
        let at = self.pos.get();
        let read = self.fs.read_at(&self.open, buf, at).await?;
        self.pos.set(at + read as u64);
        Ok(read)
    }
    /// write(2): at the shared position, or, with O_APPEND, at the end as the driver finds it
    /// when the write lands, so concurrent appends never overwrite each other. The position
    /// moves past what was written, and stays where it was if nothing was.
    pub async fn write(&self, buf: &[u8]) -> Result<usize> {
        if !self.access().writes() {
            return Err(Errno::EBADF);
        }
        let _call = self.clone();
        let _pos = self.pos_lock.lock().await;
        let at = if self.is_append() {
            WriteAt::End
        } else {
            WriteAt::Offset(self.pos.get())
        };
        let written = self.fs.write_at(&self.open, buf, at).await?;
        if written.len > 0 {
            self.pos.set(written.offset + written.len as u64);
        }
        Ok(written.len)
    }
    /// pread(2), as `FileExt::read_at`: the position does not move.
    pub async fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize> {
        if !self.access().reads() {
            return Err(Errno::EBADF);
        }
        let _call = self.clone();
        self.fs.read_at(&self.open, buf, offset).await
    }
    /// pwrite(2), as `FileExt::write_at`: the position does not move. With O_APPEND the data
    /// goes at the end whatever `offset` says, as on Linux (pwrite(2), BUGS).
    pub async fn write_at(&self, buf: &[u8], offset: u64) -> Result<usize> {
        if !self.access().writes() {
            return Err(Errno::EBADF);
        }
        let _call = self.clone();
        let at = if self.is_append() {
            WriteAt::End
        } else {
            WriteAt::Offset(offset)
        };
        Ok(self.fs.write_at(&self.open, buf, at).await?.len)
    }
    /// ftruncate(2), as `File::set_len`.
    pub async fn set_len(&self, size: u64) -> Result<()> {
        let _call = self.clone();
        self.fs.set_len(&self.open, size).await
    }
    /// fsync(2), as `File::sync_all`.
    pub async fn sync_all(&self) -> Result<()> {
        let _call = self.clone();
        self.fs.sync_all(&self.open).await
    }
    /// fdatasync(2), as `File::sync_data`.
    pub async fn sync_data(&self) -> Result<()> {
        let _call = self.clone();
        self.fs.sync_data(&self.open).await
    }
    /// flock(2) or F_SETLKW: wait until the lock is granted, as `File::lock`.
    pub async fn lock(&self, family: LockFamily, kind: LockKind, range: LockRange) -> Result<()> {
        let _call = self.clone();
        self.fs.lock(&self.open, family, kind, range).await
    }
    /// flock(2) with LOCK_NB, or F_SETLK: EAGAIN on a conflict, as `File::try_lock`.
    pub async fn try_lock(
        &self,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> Result<()> {
        let _call = self.clone();
        self.fs.try_lock(&self.open, family, kind, range).await
    }
    pub async fn unlock(&self, family: LockFamily, range: LockRange) -> Result<()> {
        let _call = self.clone();
        self.fs.unlock(&self.open, family, range).await
    }
    /// F_GETLK.
    pub async fn test_lock(&self, kind: LockKind, range: LockRange) -> Result<Option<Conflict>> {
        let _call = self.clone();
        self.fs.test_lock(&self.open, kind, range).await
    }
}

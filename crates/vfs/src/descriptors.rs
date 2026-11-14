//! Open file descriptions and one process's descriptor table, whatever the driver behind them
//! (#48 scope 3). An [`OpenFile`] is Linux's `struct file`: its offset and status flags are
//! shared by every descriptor that refers to it, in this process (`dup`) and in its children
//! (`fork`).
//!
//! References to a description are counted explicitly, as Linux counts `f_count`, never by
//! `Rc` clones: each descriptor holds one, so does each holder that took one with
//! [`OpenFile::hold`] (a descriptor in transit, the loader), and so does each call in progress
//! through it, so a close while a read waits on a remote driver leaves the read to finish. The
//! driver's open reference is released when the last reference goes; calls through a
//! description after that fail with `EBADF`.

use crate::{Attr, BoxFuture, Cred, Filesystem, Handle, OpenRef, Result, WriteAt, Written};
use abi::Errno;
use std::cell::Cell;
use std::rc::Rc;

/// The most descriptors one process may hold (RLIMIT_NOFILE).
pub const FD_MAX: usize = 1024;

/// An open file description.
pub struct OpenFile {
    pub fs: Rc<dyn Filesystem>,
    pub open: OpenRef,
    pub handle: Handle,
    /// The opener's credential, as Linux keeps `f_cred`: fstat uses it.
    pub cred: Cred,
    offset: Cell<u64>,
    append: Cell<bool>,
    /// Descriptors, holders and calls in progress referring to it; 0 once released.
    refs: Cell<usize>,
}

impl OpenFile {
    /// A description with one reference, the caller's: [`DescriptorTable::insert`] takes it
    /// over, or [`OpenFile::put`] gives it up.
    pub fn new(
        fs: Rc<dyn Filesystem>,
        open: OpenRef,
        handle: Handle,
        cred: Cred,
        flags: u32,
    ) -> Rc<Self> {
        Rc::new(Self {
            fs,
            open,
            handle,
            cred,
            offset: Cell::new(0),
            append: Cell::new(flags & abi::O_APPEND != 0),
            refs: Cell::new(1),
        })
    }
    pub fn offset(&self) -> u64 {
        self.offset.get()
    }
    pub fn append(&self) -> bool {
        self.append.get()
    }
    /// fcntl(F_SETFL) of O_APPEND: shared by every descriptor of the description.
    pub fn set_append(&self, append: bool) {
        self.append.set(append);
    }
    /// Whether the driver's open reference has been released.
    pub fn released(&self) -> bool {
        self.refs.get() == 0
    }
    /// Take another reference, as Linux's `get_file`: `EBADF` once released. Give it up with
    /// [`OpenFile::put`].
    pub fn hold(&self) -> Result<()> {
        match self.refs.get() {
            0 => Err(Errno::EBADF),
            refs => {
                self.refs.set(refs + 1);
                Ok(())
            }
        }
    }
    /// Give up a reference, as Linux's `fput`: the last releases the driver's open reference,
    /// and says how that went.
    pub async fn put(&self) -> Result<()> {
        match self.refs.get() {
            0 => Err(Errno::EBADF),
            1 => {
                self.refs.set(0);
                self.fs.release(&self.open).await
            }
            refs => {
                self.refs.set(refs - 1);
                Ok(())
            }
        }
    }
    /// Make a driver call holding a reference, so that a close meanwhile leaves the release
    /// to the call's end. The release's result is not the call's, as Linux's last `fput`
    /// after a read reports nothing.
    async fn during<'s, T>(&'s self, call: impl FnOnce(&'s Self) -> BoxFuture<'s, T>) -> Result<T> {
        self.hold()?;
        let result = call(self).await;
        let _ = self.put().await;
        result
    }
    pub async fn stat(&self) -> Result<Attr> {
        if self.released() {
            return Err(Errno::EBADF);
        }
        self.fs.getattr(&self.cred, &self.handle).await
    }
    /// lseek(2): `whence` 0 (SEEK_SET), 1 (SEEK_CUR) or 2 (SEEK_END).
    pub async fn seek(&self, offset: i64, whence: u32) -> Result<u64> {
        let base = match whence {
            0 => 0,
            1 => self.offset.get() as i64,
            2 => self.stat().await?.size as i64,
            _ => return Err(Errno::EINVAL),
        };
        let at = base
            .checked_add(offset)
            .filter(|at| *at >= 0)
            .ok_or(Errno::EINVAL)? as u64;
        self.offset.set(at);
        Ok(at)
    }
    /// read(2): from the shared offset, which moves past what was read.
    pub async fn read(&self, len: usize) -> Result<Vec<u8>> {
        if !self.open.access.reads() {
            return Err(Errno::EBADF);
        }
        let at = self.offset.get();
        let data = self
            .during(|file| file.fs.read(&file.open, at, len))
            .await?;
        self.offset.set(at + data.len() as u64);
        Ok(data)
    }
    /// write(2): at the shared offset, or, with O_APPEND, at the end as the driver finds it
    /// when the write lands (atomically: concurrent appends never overwrite each other). The
    /// offset moves past what was written.
    pub async fn write(&self, data: &[u8]) -> Result<usize> {
        if !self.open.access.writes() {
            return Err(Errno::EBADF);
        }
        let at = if self.append.get() {
            WriteAt::End
        } else {
            WriteAt::Offset(self.offset.get())
        };
        let written = self.write_at(at, data).await?;
        self.offset.set(written.offset + written.len as u64);
        Ok(written.len)
    }
    /// pread(2): the offset does not move.
    pub async fn pread(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        if !self.open.access.reads() {
            return Err(Errno::EBADF);
        }
        self.during(|file| file.fs.read(&file.open, offset, len))
            .await
    }
    /// pwrite(2): the offset does not move. With O_APPEND the data goes at the end whatever
    /// `offset` says, as on Linux (pwrite(2), BUGS).
    pub async fn pwrite(&self, offset: u64, data: &[u8]) -> Result<usize> {
        if !self.open.access.writes() {
            return Err(Errno::EBADF);
        }
        let at = if self.append.get() {
            WriteAt::End
        } else {
            WriteAt::Offset(offset)
        };
        Ok(self.write_at(at, data).await?.len)
    }
    async fn write_at(&self, at: WriteAt, data: &[u8]) -> Result<Written> {
        self.during(|file| file.fs.write(&file.open, at, data))
            .await
    }
}

#[derive(Clone)]
struct Slot {
    file: Rc<OpenFile>,
    cloexec: bool,
}

/// One process's descriptors. Each holds a reference to its description. Cloning the table is
/// `fork`: the child's descriptors refer to the same descriptions, each with its own
/// reference. A process empties its table with [`DescriptorTable::close_all`] when it exits.
#[derive(Default)]
pub struct DescriptorTable {
    slots: Vec<Option<Slot>>,
}

impl Clone for DescriptorTable {
    fn clone(&self) -> Self {
        for slot in self.slots.iter().flatten() {
            // A description in a table is never released: its descriptor holds it.
            slot.file.refs.set(slot.file.refs.get() + 1);
        }
        Self {
            slots: self.slots.clone(),
        }
    }
}

impl DescriptorTable {
    pub fn new() -> Self {
        Self::default()
    }
    fn lowest_free(&self, min: usize) -> Result<usize> {
        (min..FD_MAX)
            .find(|fd| self.slots.get(*fd).is_none_or(Option::is_none))
            .ok_or(Errno::EMFILE)
    }
    fn place(&mut self, fd: usize, slot: Slot) -> Option<Rc<OpenFile>> {
        if self.slots.len() <= fd {
            self.slots.resize(fd + 1, None);
        }
        self.slots[fd].replace(slot).map(|old| old.file)
    }
    fn take(&mut self, fd: u32) -> Result<Rc<OpenFile>> {
        self.slots
            .get_mut(fd as usize)
            .and_then(Option::take)
            .map(|slot| slot.file)
            .ok_or(Errno::EBADF)
    }
    /// A new descriptor for `file`, the lowest free number: it takes over the caller's
    /// reference (as from [`OpenFile::new`]), which stays the caller's if this fails
    /// (`EMFILE`, or `EBADF` for a released description).
    pub fn insert(&mut self, file: Rc<OpenFile>, cloexec: bool) -> Result<u32> {
        if file.released() {
            return Err(Errno::EBADF);
        }
        let fd = self.lowest_free(0)?;
        self.place(fd, Slot { file, cloexec });
        Ok(fd as u32)
    }
    /// The description `fd` refers to. Calls through it hold their own reference while they
    /// run; anything kept longer takes one with [`OpenFile::hold`].
    pub fn get(&self, fd: u32) -> Result<Rc<OpenFile>> {
        self.slots
            .get(fd as usize)
            .and_then(Option::as_ref)
            .map(|slot| slot.file.clone())
            .ok_or(Errno::EBADF)
    }
    pub fn cloexec(&self, fd: u32) -> Result<bool> {
        self.slots
            .get(fd as usize)
            .and_then(Option::as_ref)
            .map(|slot| slot.cloexec)
            .ok_or(Errno::EBADF)
    }
    pub fn set_cloexec(&mut self, fd: u32, cloexec: bool) -> Result<()> {
        let slot = self
            .slots
            .get_mut(fd as usize)
            .and_then(Option::as_mut)
            .ok_or(Errno::EBADF)?;
        slot.cloexec = cloexec;
        Ok(())
    }
    /// F_DUPFD: the lowest free descriptor at least `min`, for the same description.
    pub fn dup(&mut self, fd: u32, min: u32, cloexec: bool) -> Result<u32> {
        let file = self.get(fd)?;
        if min as usize >= FD_MAX {
            return Err(Errno::EINVAL);
        }
        let new = self.lowest_free(min as usize)?;
        file.hold()?;
        self.place(new, Slot { file, cloexec });
        Ok(new as u32)
    }
    /// dup2(2): `new` refers to `old`'s description. What `new` referred to before is closed,
    /// its errors unreported, as Linux's dup2 does.
    pub async fn dup2(&mut self, old: u32, new: u32) -> Result<u32> {
        let file = self.get(old)?;
        if new as usize >= FD_MAX {
            return Err(Errno::EBADF);
        }
        if old == new {
            return Ok(new);
        }
        file.hold()?;
        let replaced = self.place(
            new as usize,
            Slot {
                file,
                cloexec: false,
            },
        );
        if let Some(replaced) = replaced {
            let _ = replaced.put().await;
        }
        Ok(new)
    }
    /// The descriptors open, in order.
    pub fn fds(&self) -> impl Iterator<Item = u32> + '_ {
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, slot)| slot.is_some())
            .map(|(fd, _)| fd as u32)
    }
    /// close(2): the last reference to its description releases the driver's open reference,
    /// and its error, if any, is close's.
    pub async fn close(&mut self, fd: u32) -> Result<()> {
        self.take(fd)?.put().await
    }
    /// execve(2): the close-on-exec descriptors are closed, their errors unreported.
    pub async fn exec(&mut self) {
        let doomed: Vec<u32> = self
            .slots
            .iter()
            .enumerate()
            .filter(|(_, slot)| slot.as_ref().is_some_and(|slot| slot.cloexec))
            .map(|(fd, _)| fd as u32)
            .collect();
        for fd in doomed {
            let _ = self.close(fd).await;
        }
    }
    /// exit(2): every descriptor is closed, their errors unreported.
    pub async fn close_all(&mut self) {
        let open: Vec<u32> = self.fds().collect();
        for fd in open {
            let _ = self.close(fd).await;
        }
    }
}

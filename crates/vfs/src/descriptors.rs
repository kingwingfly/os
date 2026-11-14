//! Open file descriptions and one process's descriptor table, whatever the driver behind them
//! (#48 scope 3). An [`OpenFile`] is Linux's `struct file`: its offset and status flags are
//! shared by every descriptor that refers to it, in this process (`dup`) and in its children
//! (`fork`). The driver's open reference is released when the last descriptor closes.

use crate::{Attr, Cred, Filesystem, Handle, OpenRef, Result};
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
    /// The opener's credential, as Linux keeps `f_cred`: fstat and the offset of `O_APPEND`
    /// writes use it.
    pub cred: Cred,
    offset: Cell<u64>,
    append: Cell<bool>,
}

impl OpenFile {
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
    pub async fn stat(&self) -> Result<Attr> {
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
        let data = self.fs.read(&self.open, at, len).await?;
        self.offset.set(at + data.len() as u64);
        Ok(data)
    }
    /// write(2): at the shared offset, or at the end with O_APPEND; the offset moves past it.
    pub async fn write(&self, data: &[u8]) -> Result<usize> {
        if !self.open.access.writes() {
            return Err(Errno::EBADF);
        }
        let at = if self.append.get() {
            self.stat().await?.size
        } else {
            self.offset.get()
        };
        let written = self.fs.write(&self.open, at, data).await?;
        self.offset.set(at + written as u64);
        Ok(written)
    }
    /// pread(2): the offset does not move.
    pub async fn pread(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        if !self.open.access.reads() {
            return Err(Errno::EBADF);
        }
        self.fs.read(&self.open, offset, len).await
    }
    /// pwrite(2): the offset does not move.
    pub async fn pwrite(&self, offset: u64, data: &[u8]) -> Result<usize> {
        if !self.open.access.writes() {
            return Err(Errno::EBADF);
        }
        self.fs.write(&self.open, offset, data).await
    }
}

#[derive(Clone)]
struct Slot {
    file: Rc<OpenFile>,
    cloexec: bool,
}

/// One process's descriptors. Cloning it is `fork`: the child's descriptors refer to the same
/// descriptions.
#[derive(Clone, Default)]
pub struct DescriptorTable {
    slots: Vec<Option<Slot>>,
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
    /// A new descriptor for `file`: the lowest free number.
    pub fn insert(&mut self, file: Rc<OpenFile>, cloexec: bool) -> Result<u32> {
        let fd = self.lowest_free(0)?;
        self.place(fd, Slot { file, cloexec });
        Ok(fd as u32)
    }
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
        self.place(new, Slot { file, cloexec });
        Ok(new as u32)
    }
    /// dup2(2): `new` refers to `old`'s description. What `new` referred to before is returned,
    /// to be released with [`release_if_last`].
    pub fn dup2(&mut self, old: u32, new: u32) -> Result<Option<Rc<OpenFile>>> {
        let file = self.get(old)?;
        if new as usize >= FD_MAX {
            return Err(Errno::EBADF);
        }
        if old == new {
            return Ok(None);
        }
        Ok(self.place(
            new as usize,
            Slot {
                file,
                cloexec: false,
            },
        ))
    }
    /// Remove a descriptor; release its description with [`release_if_last`].
    pub fn remove(&mut self, fd: u32) -> Result<Rc<OpenFile>> {
        self.slots
            .get_mut(fd as usize)
            .and_then(Option::take)
            .map(|slot| slot.file)
            .ok_or(Errno::EBADF)
    }
    /// The descriptors open, in order.
    pub fn fds(&self) -> impl Iterator<Item = u32> + '_ {
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, slot)| slot.is_some())
            .map(|(fd, _)| fd as u32)
    }
    /// execve(2): close-on-exec descriptors go. Release what is returned.
    pub fn exec(&mut self) -> Vec<Rc<OpenFile>> {
        self.slots
            .iter_mut()
            .filter(|slot| slot.as_ref().is_some_and(|slot| slot.cloexec))
            .filter_map(|slot| slot.take().map(|slot| slot.file))
            .collect()
    }
    /// close(2).
    pub async fn close(&mut self, fd: u32) -> Result<()> {
        let file = self.remove(fd)?;
        release_if_last(file).await
    }
}

/// Release the driver's open reference if `file` was the last reference to its description.
pub async fn release_if_last(file: Rc<OpenFile>) -> Result<()> {
    if Rc::strong_count(&file) == 1 {
        file.fs.release(&file.open).await
    } else {
        Ok(())
    }
}

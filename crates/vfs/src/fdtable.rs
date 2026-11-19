//! One process's file descriptors, as Linux's `struct files_struct` and its `fdtable`: each
//! descriptor holds a [`FileRef`], and so a counted reference to its description. Cloning the
//! table is `fork`; dropping it gives every reference back.

use crate::{FileRef, Result};
use abi::Errno;

/// A file descriptor's number.
pub type Fd = u32;

/// The most descriptors one process may hold (RLIMIT_NOFILE).
pub const FD_MAX: usize = 1024;

#[derive(Clone)]
struct Slot {
    file: FileRef,
    cloexec: bool,
}

/// One process's descriptors.
#[derive(Clone, Default)]
pub struct FdTable {
    slots: Vec<Option<Slot>>,
}

impl FdTable {
    pub fn new() -> Self {
        Self::default()
    }
    fn lowest_free(&self, min: usize) -> Result<usize> {
        (min..FD_MAX)
            .find(|fd| self.slots.get(*fd).is_none_or(Option::is_none))
            .ok_or(Errno::EMFILE)
    }
    fn slot(&self, fd: Fd) -> Result<&Slot> {
        self.slots
            .get(fd as usize)
            .and_then(Option::as_ref)
            .ok_or(Errno::EBADF)
    }
    fn place(&mut self, fd: usize, slot: Slot) -> Option<FileRef> {
        if self.slots.len() <= fd {
            self.slots.resize(fd + 1, None);
        }
        self.slots[fd].replace(slot).map(|old| old.file)
    }
    /// alloc_fd and fd_install: a new descriptor for `file`, the lowest free number, holding
    /// the reference given. On EMFILE the reference is dropped, and so given back.
    pub fn insert(&mut self, file: FileRef, cloexec: bool) -> Result<Fd> {
        let fd = self.lowest_free(0)?;
        self.place(fd, Slot { file, cloexec });
        Ok(fd as Fd)
    }
    /// fget: a reference to the description `fd` refers to, which keeps it open as long as it
    /// is kept.
    pub fn get(&self, fd: Fd) -> Result<FileRef> {
        Ok(self.slot(fd)?.file.clone())
    }
    /// F_GETFD's FD_CLOEXEC.
    pub fn get_cloexec(&self, fd: Fd) -> Result<bool> {
        Ok(self.slot(fd)?.cloexec)
    }
    /// F_SETFD's FD_CLOEXEC.
    pub fn set_cloexec(&mut self, fd: Fd, cloexec: bool) -> Result<()> {
        let slot = self
            .slots
            .get_mut(fd as usize)
            .and_then(Option::as_mut)
            .ok_or(Errno::EBADF)?;
        slot.cloexec = cloexec;
        Ok(())
    }
    /// F_DUPFD and F_DUPFD_CLOEXEC: the lowest free descriptor at least `min`, for the same
    /// description.
    pub fn dup(&mut self, fd: Fd, min: Fd, cloexec: bool) -> Result<Fd> {
        let file = self.get(fd)?;
        if min as usize >= FD_MAX {
            return Err(Errno::EINVAL);
        }
        let new = self.lowest_free(min as usize)?;
        self.place(new, Slot { file, cloexec });
        Ok(new as Fd)
    }
    /// dup2(2): `new` refers to `old`'s description; nothing happens if they are the same
    /// descriptor. What `new` referred to before is closed, its errors unreported, as Linux's
    /// dup2 does.
    pub async fn dup2(&mut self, old: Fd, new: Fd) -> Result<Fd> {
        self.slot(old)?;
        if old == new {
            return Ok(new);
        }
        self.dup3(old, new, false).await
    }
    /// dup3(2): as dup2, with FD_CLOEXEC as `cloexec` says; EINVAL for the same descriptor.
    pub async fn dup3(&mut self, old: Fd, new: Fd, cloexec: bool) -> Result<Fd> {
        if old == new {
            return Err(Errno::EINVAL);
        }
        let file = self.get(old)?;
        if new as usize >= FD_MAX {
            return Err(Errno::EBADF);
        }
        if let Some(replaced) = self.place(new as usize, Slot { file, cloexec }) {
            let _ = replaced.close().await;
        }
        Ok(new)
    }
    /// The descriptors open, in order.
    pub fn fds(&self) -> impl Iterator<Item = Fd> + '_ {
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, slot)| slot.is_some())
            .map(|(fd, _)| fd as Fd)
    }
    /// Synchronously remove `fd` from the table and return its [`FileRef`] so callers sharing
    /// [`crate::SharedFdTable`] via `CLONE_FILES` never hold a `RefMut` across `close().await`.
    pub fn take(&mut self, fd: Fd) -> Result<FileRef> {
        let slot = self
            .slots
            .get_mut(fd as usize)
            .and_then(Option::take)
            .ok_or(Errno::EBADF)?;
        Ok(slot.file)
    }
    /// Synchronously perform the table mutation of `dup2`/`dup3`, returning any displaced
    /// [`FileRef`] to close outside a `RefCell` borrow.
    pub fn replace_dup(
        &mut self,
        old: Fd,
        new: Fd,
        cloexec: bool,
        is_dup3: bool,
    ) -> Result<Option<FileRef>> {
        self.slot(old)?;
        if old == new {
            return if is_dup3 {
                Err(Errno::EINVAL)
            } else {
                Ok(None)
            };
        }
        if new as usize >= FD_MAX {
            return Err(Errno::EBADF);
        }
        let file = self.get(old)?;
        Ok(self.place(new as usize, Slot { file, cloexec }))
    }
    /// Synchronously remove all `FD_CLOEXEC` descriptors for `execve(2)`.
    pub fn take_cloexec(&mut self) -> Vec<FileRef> {
        let mut out = Vec::new();
        for slot in &mut self.slots {
            if slot.as_ref().is_some_and(|s| s.cloexec)
                && let Some(taken) = slot.take()
            {
                out.push(taken.file);
            }
        }
        out
    }
    /// Synchronously remove all open descriptors for `exit(2)`.
    pub fn take_all(&mut self) -> Vec<FileRef> {
        self.slots
            .iter_mut()
            .filter_map(|s| s.take().map(|slot| slot.file))
            .collect()
    }
    /// close(2): if this was the last reference to its description, the driver's open
    /// reference is released before this returns, and its error, if any, is close's.
    pub async fn close(&mut self, fd: Fd) -> Result<()> {
        let file = self.take(fd)?;
        file.close().await
    }
    /// execve(2)'s do_close_on_exec: the close-on-exec descriptors are closed, their errors
    /// unreported.
    pub async fn close_on_exec(&mut self) {
        let doomed: Vec<Fd> = self
            .slots
            .iter()
            .enumerate()
            .filter(|(_, slot)| slot.as_ref().is_some_and(|slot| slot.cloexec))
            .map(|(fd, _)| fd as Fd)
            .collect();
        for fd in doomed {
            let _ = self.close(fd).await;
        }
    }
    /// exit(2): every descriptor is closed, their errors unreported. Dropping the table gives
    /// the references back too, through the release queue.
    pub async fn close_all(&mut self) {
        let open: Vec<Fd> = self.fds().collect();
        for fd in open {
            let _ = self.close(fd).await;
        }
    }
}

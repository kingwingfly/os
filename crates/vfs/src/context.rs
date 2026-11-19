//! Process filesystem context (`FsContext` / `SharedFsContext`) and descriptor-table sharing
//! (`SharedFdTable`) for `CLONE_FS`, `CLONE_FILES`, `fork`, `exec`, and `unshare`.

use crate::mount::{MountId, MountPin};
use crate::{FdTable, FileRef, Handle, NodeId};
use std::cell::{Ref, RefCell, RefMut};
use std::collections::HashMap;
use std::rc::Rc;

/// A pinned directory location in a mount namespace (Linux `struct path`: `{ mnt, dentry }`),
/// accompanied by a path-only [`FileRef`] keeping the directory alive across `rmdir`.
#[derive(Clone)]
pub struct PathAnchor {
    pub pin: MountPin,
    pub handle: Handle,
    /// `Access::Path` `FileRef` keeping the anchored directory alive even if removed (contract §2.3).
    pub open: FileRef,
}

impl std::fmt::Debug for PathAnchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PathAnchor")
            .field("mount_id", &self.pin.id())
            .field("node", &self.handle.node)
            .finish()
    }
}

impl PathAnchor {
    pub fn same_location(&self, pin: &MountPin, node: NodeId) -> bool {
        self.pin.id() == pin.id() && self.handle.node == node
    }

    pub fn same_anchor(&self, other: &Self) -> bool {
        self.pin.id() == other.pin.id() && self.handle.node == other.handle.node
    }

    pub fn remap_pin(&mut self, map: &HashMap<MountId, MountPin>) {
        if let Some(new_pin) = map.get(&self.pin.id()) {
            self.pin = new_pin.clone();
        }
    }
}

#[derive(Clone, Debug)]
pub struct FsContext {
    pub root: PathAnchor,
    pub cwd: PathAnchor,
    pub umask: u16,
}

/// Process handle to [`FsContext`]: shared via `Rc` under `CLONE_FS`; deep-cloned on ordinary `fork`.
#[derive(Clone, Debug)]
pub struct SharedFsContext(Rc<RefCell<FsContext>>);

impl SharedFsContext {
    pub fn new(root: PathAnchor, cwd: PathAnchor, umask: u16) -> Self {
        Self(Rc::new(RefCell::new(FsContext { root, cwd, umask })))
    }

    pub fn from_context(ctx: FsContext) -> Self {
        Self(Rc::new(RefCell::new(ctx)))
    }

    pub fn borrow(&self) -> Ref<'_, FsContext> {
        self.0.borrow()
    }

    pub fn borrow_mut(&self) -> RefMut<'_, FsContext> {
        self.0.borrow_mut()
    }

    pub fn is_shared(&self) -> bool {
        Rc::strong_count(&self.0) > 1
    }

    pub fn ptr_eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }

    /// `fork()`: `share == false` deep-clones `FsContext` (cloning `PathAnchor`s increments
    /// `MountPin` & `FileRef`); `share == true` (`CLONE_FS`) shares the `Rc`.
    pub fn fork_clone(&self, share: bool) -> Self {
        if share {
            Self(Rc::clone(&self.0))
        } else {
            Self(Rc::new(RefCell::new(self.0.borrow().clone())))
        }
    }

    /// `unshare(CLONE_FS)`: if shared with other tasks, replace `self.0` with an independent copy.
    pub fn unshare(&mut self) {
        if self.is_shared() {
            let copy = self.0.borrow().clone();
            self.0 = Rc::new(RefCell::new(copy));
        }
    }
}

/// Process handle to [`FdTable`]: shared via `Rc` under `CLONE_FILES`; deep-cloned on ordinary `fork`.
#[derive(Clone, Default)]
pub struct SharedFdTable(Rc<RefCell<FdTable>>);

impl SharedFdTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_table(table: FdTable) -> Self {
        Self(Rc::new(RefCell::new(table)))
    }

    pub fn borrow(&self) -> Ref<'_, FdTable> {
        self.0.borrow()
    }

    pub fn borrow_mut(&self) -> RefMut<'_, FdTable> {
        self.0.borrow_mut()
    }

    pub fn is_shared(&self) -> bool {
        Rc::strong_count(&self.0) > 1
    }

    pub fn ptr_eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }

    pub fn fork_clone(&self, share: bool) -> Self {
        if share {
            Self(Rc::clone(&self.0))
        } else {
            Self(Rc::new(RefCell::new(self.0.borrow().clone())))
        }
    }

    /// `unshare(CLONE_FILES)`: if shared with other tasks, replace `self.0` with an independent copy.
    pub fn unshare(&mut self) {
        if self.is_shared() {
            let copy = self.0.borrow().clone();
            self.0 = Rc::new(RefCell::new(copy));
        }
    }

    pub async fn close(&self, fd: crate::Fd) -> crate::Result<()> {
        let file = self.0.borrow_mut().take(fd)?;
        file.close().await
    }

    pub async fn dup2(&self, old: crate::Fd, new: crate::Fd) -> crate::Result<crate::Fd> {
        let replaced = self.0.borrow_mut().replace_dup(old, new, false, false)?;
        if let Some(old_file) = replaced {
            let _ = old_file.close().await;
        }
        Ok(new)
    }

    pub async fn close_on_exec(&self) {
        let doomed = self.0.borrow_mut().take_cloexec();
        for file in doomed {
            let _ = file.close().await;
        }
    }

    pub async fn close_all(&self) {
        let all = self.0.borrow_mut().take_all();
        for file in all {
            let _ = file.close().await;
        }
    }
}

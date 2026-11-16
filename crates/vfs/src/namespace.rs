//! Mount namespace topology, mount stacking, private cloning, and `/proc/<pid>/{mountinfo,mounts}`
//! formatting (`docs/architecture/contract.md` §2.7, §4, §5).

use crate::context::PathAnchor;
use crate::mount::{
    FsType, MountAttachment, MountEntry, MountFlags, MountId, MountSlot, NamespaceId,
};
use crate::{Cred, Handle, NodeId, Result};
use abi::Errno;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;

pub struct MountNamespace {
    id: NamespaceId,
    root_mount: MountId,
    mounts: BTreeMap<MountId, MountEntry>,
    /// Stacked child mounts keyed by `(parent_mount_id, mountpoint_node_id)`.
    /// Ordered oldest -> newest; `.last()` is the currently visible top mount.
    children: HashMap<(MountId, NodeId), Vec<MountId>>,
    /// Per-parent-mount reference counts of active mountpoint component names (`mp_name`),
    /// enabling safe 1-RTT `Filesystem::walk` batching when names cannot cross a mountpoint.
    mp_names_by_parent: HashMap<MountId, HashMap<String, usize>>,
    generation: u64,
}

impl MountNamespace {
    pub fn new(id: NamespaceId, mut root_entry: MountEntry) -> Self {
        let root_mount = root_entry.slot.id;
        root_entry.parent = None;
        let mut mounts = BTreeMap::new();
        mounts.insert(root_mount, root_entry);
        Self {
            id,
            root_mount,
            mounts,
            children: HashMap::new(),
            mp_names_by_parent: HashMap::new(),
            generation: 1,
        }
    }

    pub fn id(&self) -> NamespaceId {
        self.id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn bump_generation(&mut self) {
        self.generation = self.generation.wrapping_add(1);
    }

    pub fn root_mount_id(&self) -> MountId {
        self.root_mount
    }

    pub fn root_entry(&self) -> &MountEntry {
        &self.mounts[&self.root_mount]
    }

    pub fn root_anchor(&self) -> PathAnchor {
        let root = self.root_entry();
        PathAnchor {
            pin: root.slot.pin(),
            handle: root.root.clone(),
            open: root.root_open.clone(),
        }
    }

    pub fn len(&self) -> usize {
        self.mounts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.mounts.is_empty()
    }

    pub fn contains_mount(&self, id: MountId) -> bool {
        self.mounts.contains_key(&id)
    }

    pub fn entry(&self, id: MountId) -> Option<&MountEntry> {
        self.mounts.get(&id)
    }

    pub fn mount_root_node(&self, id: MountId) -> Option<NodeId> {
        self.mounts.get(&id).map(|e| e.root.node)
    }

    pub fn mounts(&self) -> &BTreeMap<MountId, MountEntry> {
        &self.mounts
    }

    /// Follow stacked mounts at `(mount_id, node)` to the topmost visible mount, if any.
    pub fn top_mount_at(
        &self,
        mut mount_id: MountId,
        mut node: NodeId,
    ) -> Option<(Rc<MountSlot>, Handle)> {
        let mut crossed = None;
        while let Some(&child_id) = self
            .children
            .get(&(mount_id, node))
            .and_then(|stack| stack.last())
        {
            let child = self.mounts.get(&child_id)?;
            mount_id = child_id;
            node = child.root.node;
            crossed = Some((Rc::clone(&child.slot), child.root.clone()));
        }
        crossed
    }

    /// True if `name` is the component name of any active mountpoint on `parent_mount`.
    pub fn may_be_mountpoint_name(&self, parent_mount: MountId, name: &str) -> bool {
        self.mp_names_by_parent
            .get(&parent_mount)
            .is_some_and(|names| names.get(name).copied().unwrap_or(0) > 0)
    }

    /// True if `(parent_mount, child_node)` currently has at least one child mount attached.
    pub fn is_mountpoint(&self, parent_mount: MountId, child_node: NodeId) -> bool {
        self.children
            .get(&(parent_mount, child_node))
            .is_some_and(|stack| !stack.is_empty())
    }

    /// True if `(dir_node, name)` on `parent_mount` is an active mountpoint (`EBUSY` on
    /// `unlink`/`rmdir`/`rename`).
    pub fn has_mountpoint_at_name(
        &self,
        parent_mount: MountId,
        dir_node: NodeId,
        name: &str,
    ) -> bool {
        if !self.may_be_mountpoint_name(parent_mount, name) {
            return false;
        }
        self.mounts.values().any(|entry| {
            entry.parent.as_ref().is_some_and(|att| {
                att.parent_pin.id() == parent_mount
                    && att.mp_parent_node == Some(dir_node)
                    && att.mp_name.as_deref() == Some(name)
            })
        })
    }

    fn register_attachment_indices(&mut self, child_id: MountId, att: &MountAttachment) {
        let parent_id = att.parent_pin.id();
        self.children
            .entry((parent_id, att.mountpoint.node))
            .or_default()
            .push(child_id);
        if let Some(name) = &att.mp_name {
            *self
                .mp_names_by_parent
                .entry(parent_id)
                .or_default()
                .entry(name.clone())
                .or_insert(0) += 1;
        }
    }

    fn unregister_attachment_indices(&mut self, child_id: MountId, att: &MountAttachment) {
        let parent_id = att.parent_pin.id();
        let key = (parent_id, att.mountpoint.node);
        if let Some(stack) = self.children.get_mut(&key) {
            stack.retain(|&id| id != child_id);
            if stack.is_empty() {
                self.children.remove(&key);
            }
        }
        if let Some(name) = &att.mp_name
            && let Some(names) = self.mp_names_by_parent.get_mut(&parent_id)
        {
            if let Some(count) = names.get_mut(name) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    names.remove(name);
                }
            }
            if names.is_empty() {
                self.mp_names_by_parent.remove(&parent_id);
            }
        }
    }

    pub fn attach(&mut self, entry: MountEntry) -> MountId {
        let id = entry.slot.id;
        if let Some(att) = &entry.parent {
            self.register_attachment_indices(id, att);
        }
        self.mounts.insert(id, entry);
        self.bump_generation();
        id
    }

    /// True if `ancestor` equals `candidate` or is a mount-tree ancestor of `candidate`.
    pub fn is_mount_ancestor(&self, ancestor: MountId, mut candidate: MountId) -> bool {
        loop {
            if candidate == ancestor {
                return true;
            }
            let Some(parent_id) = self
                .mounts
                .get(&candidate)
                .and_then(|e| e.parent.as_ref())
                .map(|att| att.parent_pin.id())
            else {
                return false;
            };
            candidate = parent_id;
        }
    }

    /// Direct child mount IDs attached anywhere on `parent_mount` (in stack order per mountpoint).
    pub fn direct_children_of(&self, parent_mount: MountId) -> Vec<MountId> {
        let mut out = Vec::new();
        for ((p_id, _), stack) in &self.children {
            if *p_id == parent_mount {
                out.extend(stack.iter().copied());
            }
        }
        out.sort_by_key(|id| id.0);
        out
    }

    /// Collect `root_id` and all descendant submounts in post-order (children before parents).
    pub fn collect_subtree_postorder(&self, root_id: MountId) -> Vec<MountId> {
        fn visit(ns: &MountNamespace, id: MountId, out: &mut Vec<MountId>) {
            for ((p_id, _), stack) in &ns.children {
                if *p_id == id {
                    for &child_id in stack.iter().rev() {
                        visit(ns, child_id, out);
                    }
                }
            }
            out.push(id);
        }
        let mut out = Vec::new();
        if self.mounts.contains_key(&root_id) {
            visit(self, root_id, &mut out);
        }
        out
    }

    /// Ordinary `umount2(target, 0)`: fails with `EBUSY` if `mount_id` is the namespace root or
    /// has any active `MountPin` (open files, `cwd`, `root`, or child mounts).
    pub fn unmount_ordinary(&mut self, mount_id: MountId) -> Result<MountEntry> {
        if mount_id == self.root_mount {
            return Err(Errno::EBUSY);
        }
        let Some(entry) = self.mounts.get(&mount_id) else {
            return Err(Errno::EINVAL);
        };
        if entry.slot.is_busy() {
            return Err(Errno::EBUSY);
        }
        let mut entry = self.mounts.remove(&mount_id).expect("checked mount");
        if let Some(att) = entry.parent.take() {
            self.unregister_attachment_indices(mount_id, &att);
        }
        self.bump_generation();
        Ok(entry)
    }

    /// Lazy `umount2(target, MNT_DETACH)`: detaches `mount_id` and any descendant mounts from
    /// this namespace immediately while keeping existing `MountPin`s functional until dropped.
    pub fn detach_subtree(&mut self, mount_id: MountId) -> Result<Vec<MountEntry>> {
        if mount_id == self.root_mount {
            return Err(Errno::EBUSY);
        }
        if !self.mounts.contains_key(&mount_id) {
            return Err(Errno::EINVAL);
        }
        let postorder = self.collect_subtree_postorder(mount_id);
        let mut removed = Vec::with_capacity(postorder.len());
        for id in postorder {
            if let Some(mut entry) = self.mounts.remove(&id) {
                entry.slot.detached.set(true);
                if let Some(att) = entry.parent.take() {
                    self.unregister_attachment_indices(id, &att);
                }
                removed.push(entry);
            }
        }
        self.bump_generation();
        Ok(removed)
    }

    /// Re-parent `mount_id` onto `new_att` (`MS_MOVE` to a non-root target).
    pub fn move_mount(&mut self, mount_id: MountId, new_att: MountAttachment) -> Result<()> {
        if mount_id == self.root_mount {
            return Err(Errno::EINVAL);
        }
        if self.is_mount_ancestor(mount_id, new_att.parent_pin.id()) {
            return Err(Errno::EINVAL);
        }
        let old_att = self
            .mounts
            .get_mut(&mount_id)
            .ok_or(Errno::EINVAL)?
            .parent
            .take();
        if let Some(att) = old_att {
            self.unregister_attachment_indices(mount_id, &att);
        }
        self.register_attachment_indices(mount_id, &new_att);
        self.mounts
            .get_mut(&mount_id)
            .expect("checked mount")
            .parent = Some(new_att);
        self.bump_generation();
        Ok(())
    }

    /// `switch_root` move (`mount(src, "/", MS_MOVE)`): promotes `mount_id` to `self.root_mount`
    /// and detaches the old root hierarchy's un-moved mounts.
    pub fn switch_root_move(&mut self, mount_id: MountId) -> Result<Vec<MountEntry>> {
        if mount_id == self.root_mount || !self.mounts.contains_key(&mount_id) {
            return Err(Errno::EINVAL);
        }
        let old_att = self
            .mounts
            .get_mut(&mount_id)
            .expect("checked mount")
            .parent
            .take();
        if let Some(att) = old_att {
            self.unregister_attachment_indices(mount_id, &att);
        }
        self.root_mount = mount_id;

        // Every mount still in `self.mounts` that does NOT descend from the new `root_mount`
        // belonged to the superseded initial root and is detached in post-order.
        let keep: std::collections::HashSet<MountId> = self
            .collect_subtree_postorder(mount_id)
            .into_iter()
            .collect();
        let doomed_roots: Vec<MountId> = self
            .mounts
            .iter()
            .filter_map(|(&id, e)| {
                (!keep.contains(&id)
                    && e.parent
                        .as_ref()
                        .is_none_or(|att| keep.contains(&att.parent_pin.id())))
                .then_some(id)
            })
            .collect();
        let mut detached = Vec::new();
        for root in doomed_roots {
            for id in self.collect_subtree_postorder(root) {
                if !keep.contains(&id)
                    && let Some(mut entry) = self.mounts.remove(&id)
                {
                    entry.slot.detached.set(true);
                    if let Some(att) = entry.parent.take() {
                        self.unregister_attachment_indices(id, &att);
                    }
                    detached.push(entry);
                }
            }
        }
        self.bump_generation();
        Ok(detached)
    }

    /// Clone this namespace with private propagation (`CLONE_NEWNS` / login session derivation),
    /// minting fresh `MountId`s that share `Rc<MountBacking>` with the source entries.
    pub fn clone_private(
        &self,
        new_ns_id: NamespaceId,
        mut mint_mount_id: impl FnMut() -> MountId,
    ) -> (Self, HashMap<MountId, Rc<MountSlot>>) {
        let mut old_to_new: HashMap<MountId, Rc<MountSlot>> =
            HashMap::with_capacity(self.mounts.len());
        for (&old_id, entry) in &self.mounts {
            let new_id = mint_mount_id();
            let slot = MountSlot::new(
                new_id,
                new_ns_id,
                entry.root.node,
                Rc::clone(&entry.slot.backing),
                entry.slot.flags(),
                entry.slot.locked_flags(),
                entry.slot.owner_uid,
            );
            old_to_new.insert(old_id, slot);
        }

        let new_root = old_to_new[&self.root_mount].id;
        let mut new_mounts = BTreeMap::new();
        for (&old_id, entry) in &self.mounts {
            let slot = Rc::clone(&old_to_new[&old_id]);
            let parent = entry.parent.as_ref().map(|att| {
                let parent_slot = &old_to_new[&att.parent_pin.id()];
                MountAttachment {
                    parent_pin: parent_slot.pin(),
                    mountpoint: att.mountpoint.clone(),
                    mountpoint_open: att.mountpoint_open.clone(),
                    mp_parent_node: att.mp_parent_node,
                    mp_name: att.mp_name.clone(),
                }
            });
            new_mounts.insert(
                slot.id,
                MountEntry {
                    slot,
                    parent,
                    root: entry.root.clone(),
                    root_open: entry.root_open.clone(),
                    root_in_fs: entry.root_in_fs.clone(),
                    source: entry.source.clone(),
                },
            );
        }

        let mut new_children = HashMap::with_capacity(self.children.len());
        for (&(old_parent, node), stack) in &self.children {
            let new_parent = old_to_new[&old_parent].id;
            let mapped: Vec<MountId> = stack.iter().map(|old_c| old_to_new[old_c].id).collect();
            new_children.insert((new_parent, node), mapped);
        }

        let mut new_mp_names = HashMap::with_capacity(self.mp_names_by_parent.len());
        for (&old_parent, names) in &self.mp_names_by_parent {
            new_mp_names.insert(old_to_new[&old_parent].id, names.clone());
        }

        let ns = Self {
            id: new_ns_id,
            root_mount: new_root,
            mounts: new_mounts,
            children: new_children,
            mp_names_by_parent: new_mp_names,
            generation: 1,
        };
        (ns, old_to_new)
    }
}

/// Escape `' '`, `'\t'`, `'\n'`, and `'\\'` as octal sequences per `proc_pid_mountinfo(5)`.
pub fn escape_mountinfo(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            ' ' => out.push_str("\\040"),
            '\t' => out.push_str("\\011"),
            '\n' => out.push_str("\\012"),
            '\\' => out.push_str("\\134"),
            _ => out.push(ch),
        }
    }
    out
}

#[derive(Clone)]
struct MountSnapshot {
    id: MountId,
    parent: Option<(MountId, Handle)>,
    slot: Rc<MountSlot>,
    root: Handle,
    root_in_fs: String,
    source: String,
    flags: MountFlags,
    fstype: FsType,
    dev: u64,
    ceiling_rdonly: bool,
    owner_uid: Option<u32>,
}

fn snapshot_namespace(
    ns_rc: &Rc<RefCell<MountNamespace>>,
    reader_root: &PathAnchor,
    reader_is_at_own_ns_root: bool,
) -> Option<(MountId, NodeId, BTreeMap<MountId, MountSnapshot>)> {
    let ns = ns_rc.borrow();
    let (filter_mount, filter_node) = if ns.contains_mount(reader_root.pin.id()) {
        (reader_root.pin.id(), reader_root.handle.node)
    } else if reader_is_at_own_ns_root {
        let root = ns.root_entry();
        (ns.root_mount, root.root.node)
    } else {
        // Chrooted reader inspecting a foreign namespace whose mounts are outside its root.
        return None;
    };
    let mut snaps = BTreeMap::new();
    for (&id, entry) in &ns.mounts {
        snaps.insert(
            id,
            MountSnapshot {
                id,
                parent: entry
                    .parent
                    .as_ref()
                    .map(|att| (att.parent_pin.id(), att.mountpoint.clone())),
                slot: Rc::clone(&entry.slot),
                root: entry.root.clone(),
                root_in_fs: entry.root_in_fs.clone(),
                source: entry.source.clone(),
                flags: entry.slot.effective_flags(),
                fstype: entry.slot.backing.fstype,
                dev: entry.slot.backing.fs.id().dev(),
                ceiling_rdonly: entry.slot.backing.ceiling_rdonly,
                owner_uid: entry.slot.owner_uid,
            },
        );
    }
    Some((filter_mount, filter_node, snaps))
}

async fn resolve_mountpoint_path(
    cred: &Cred,
    snaps: &BTreeMap<MountId, MountSnapshot>,
    mount_id: MountId,
    filter_mount: MountId,
    filter_node: NodeId,
) -> Option<String> {
    let start = snaps.get(&mount_id)?;
    let mut cur_mount = mount_id;
    let mut cur_handle = start.root.clone();
    let mut segments: Vec<String> = Vec::new();

    loop {
        if cur_mount == filter_mount && cur_handle.node == filter_node {
            return if segments.is_empty() {
                Some("/".to_string())
            } else {
                segments.reverse();
                Some(format!("/{}", segments.join("/")))
            };
        }

        let cur_snap = snaps.get(&cur_mount)?;
        if cur_handle.node == cur_snap.root.node {
            let (parent_id, mp_handle) = cur_snap.parent.as_ref()?;
            cur_mount = *parent_id;
            cur_handle = mp_handle.clone();
            continue;
        }

        let fs = Rc::clone(&cur_snap.slot.backing.fs);
        match fs.parent(cred, &cur_handle).await {
            Ok(Some((parent_entry, name))) => {
                segments.push(name);
                cur_handle = parent_entry.handle;
            }
            _ => return None,
        }
    }
}

/// Format `/proc/<pid>/mountinfo` (10-field Linux format, filtered relative to `reader_root`).
pub async fn format_mountinfo(
    cred: &Cred,
    target_ns: &Rc<RefCell<MountNamespace>>,
    reader_root: &PathAnchor,
    reader_is_at_own_ns_root: bool,
) -> String {
    let Some((filter_mount, filter_node, snaps)) =
        snapshot_namespace(target_ns, reader_root, reader_is_at_own_ns_root)
    else {
        return String::new();
    };
    let mut out = String::new();
    for (&id, snap) in &snaps {
        let Some(mp_path) =
            resolve_mountpoint_path(cred, &snaps, id, filter_mount, filter_node).await
        else {
            continue;
        };
        let parent_id = snap.parent.as_ref().map_or(snap.id.0, |(p, _)| p.0);
        let minor = (snap.dev % 1_000_000) + 1;
        let root_str = escape_mountinfo(if snap.root_in_fs.is_empty() {
            "/"
        } else {
            &snap.root_in_fs
        });
        let mp_str = escape_mountinfo(&mp_path);
        let mount_opts = snap.flags.format_mount_opts();
        let fstype = snap.fstype.as_str();
        let source = escape_mountinfo(if snap.source.is_empty() {
            "none"
        } else {
            &snap.source
        });
        let mut super_opts = if snap.ceiling_rdonly {
            "ro".to_string()
        } else {
            "rw".to_string()
        };
        if let Some(uid) = snap.owner_uid {
            super_opts.push_str(&format!(",user_id={uid}"));
        }
        out.push_str(&format!(
            "{} {} 0:{} {} {} {} - {} {} {}\n",
            snap.id.0, parent_id, minor, root_str, mp_str, mount_opts, fstype, source, super_opts
        ));
    }
    out
}

/// Format `/proc/<pid>/mounts` (6-field `mtab` format, filtered relative to `reader_root`).
pub async fn format_mounts(
    cred: &Cred,
    target_ns: &Rc<RefCell<MountNamespace>>,
    reader_root: &PathAnchor,
    reader_is_at_own_ns_root: bool,
) -> String {
    let Some((filter_mount, filter_node, snaps)) =
        snapshot_namespace(target_ns, reader_root, reader_is_at_own_ns_root)
    else {
        return String::new();
    };
    let mut out = String::new();
    for (&id, snap) in &snaps {
        let Some(mp_path) =
            resolve_mountpoint_path(cred, &snaps, id, filter_mount, filter_node).await
        else {
            continue;
        };
        let source = escape_mountinfo(if snap.source.is_empty() {
            "none"
        } else {
            &snap.source
        });
        let mp_str = escape_mountinfo(&mp_path);
        let fstype = snap.fstype.as_str();
        let opts = snap.flags.format_mount_opts();
        out.push_str(&format!("{source} {mp_str} {fstype} {opts} 0 0\n"));
    }
    out
}

//! Durable state directory persistence, folder UUID, handle HMAC, and inode identity map.

use super::sys::{self, HostGen, HostKind, HostStat};
use abi::Errno;
use abi::fs::{FsId, Handle, JS_SAFE, NodeId};
use os_core::permissions::Node;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Component, Path, PathBuf};

/// On-disk state schema version (contract §2.12). Older versions reset metadata once without
/// touching host files; newer versions are refused with `EPROTONOSUPPORT`.
pub const STATE_FORMAT_VERSION: u32 = 2;
pub const ROOT_INO: u64 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct HostInodeKey {
    pub subfs_relpath: String,
    pub subvol: Option<u64>,
    pub subfs_fsuuid: Option<[u8; 16]>,
    pub host_ino: u64,
    pub host_gen: HostGen,
    pub kind: HostKind,
}

impl HostInodeKey {
    pub fn from_root(dir_fd: BorrowedFd<'_>, stx: &HostStat) -> Result<Self, Errno> {
        Ok(Self {
            subfs_relpath: String::new(),
            subvol: stx.subvol,
            subfs_fsuuid: sys::capture_dir_fsuuid(dir_fd, ""),
            host_ino: stx.ino,
            host_gen: sys::capture_gen(dir_fd, None, stx)?,
            kind: stx.kind,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredNode {
    pub minted_ino: u64,
    pub generation: u64,
    pub host: HostInodeKey,
    pub path_hints: Vec<String>,
    pub node: Node,
    pub xattrs: BTreeMap<String, Vec<u8>>,
    /// Highest ctime observed from OS-side metadata updates `(sec, nsec)`, merged with host ctime.
    pub meta_ctime: Option<(i64, u32)>,
    #[serde(default)]
    pub unlinked: bool,
}

#[derive(Deserialize)]
struct PersistedHeader {
    format_version: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedState {
    format_version: u32,
    folder_uuid: String,
    handle_key: String,
    root_identity: Option<HostInodeKey>,
    next_ino: u64,
    nodes: BTreeMap<u64, StoredNode>,
}

/// Resolve the default helper state directory (`$XDG_STATE_HOME/os-local-helper` or
/// `~/.local/state/os-local-helper`).
pub fn default_state_dir() -> Result<PathBuf, String> {
    if let Ok(xdg) = std::env::var("XDG_STATE_HOME")
        && !xdg.is_empty()
    {
        return Ok(PathBuf::from(xdg).join("os-local-helper"));
    }
    let home = std::env::var("HOME")
        .ok()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| "HOME or XDG_STATE_HOME must be set (or pass --state-dir)".to_owned())?;
    Ok(PathBuf::from(home).join(".local/state/os-local-helper"))
}

/// Resolve `path` to its deepest canonical ancestor plus remaining normalized components, even
/// before leaf directories exist, so symlinked paths inside `--root` cannot slip past confinement.
pub fn resolve_nonexistent_safe(path: &Path) -> Result<PathBuf, String> {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("failed to read current directory: {e}"))?
            .join(path)
    };
    let mut normalized = Vec::new();
    for comp in abs.components() {
        match comp {
            Component::RootDir => {}
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part.to_os_string()),
            Component::Prefix(_) => return Err("unsupported path prefix".to_owned()),
        }
    }
    let mut probe = PathBuf::from("/");
    for part in &normalized {
        probe.push(part);
    }
    let mut tail = Vec::new();
    let mut cursor = probe.as_path();
    loop {
        match fs::canonicalize(cursor) {
            Ok(mut resolved) => {
                for part in tail.into_iter().rev() {
                    resolved.push(part);
                }
                return Ok(resolved);
            }
            Err(_) => {
                let Some(name) = cursor.file_name() else {
                    return Ok(probe);
                };
                tail.push(name.to_os_string());
                cursor = cursor.parent().unwrap_or(Path::new("/"));
            }
        }
    }
}

/// Refuse putting the helper's state directory at or inside `--root`.
pub fn validate_state_dir_outside_root(
    canonical_root: &Path,
    state_dir: &Path,
) -> Result<PathBuf, String> {
    let resolved_state = resolve_nonexistent_safe(state_dir)?;
    if resolved_state == canonical_root || resolved_state.starts_with(canonical_root) {
        return Err(format!(
            "state directory '{}' must not live inside mounted root '{}'",
            resolved_state.display(),
            canonical_root.display()
        ));
    }
    if let Ok(raw) = fs::read_to_string("/proc/self/mountinfo") {
        let mounts = sys::parse_mountinfo(&raw);
        let folders_dir = resolved_state.join("folders");
        if sys::check_mountinfo_overlap(
            &mounts,
            canonical_root,
            None,
            &resolved_state,
            None,
            &folders_dir,
            None,
        )
        .is_err()
        {
            return Err(format!(
                "state directory '{}' overlaps mounted root '{}' via mount/bind alias",
                resolved_state.display(),
                canonical_root.display()
            ));
        }
    }
    Ok(resolved_state)
}

pub struct StateStore {
    state_name: String,
    #[cfg(test)]
    state_file: PathBuf,
    folders_fd: OwnedFd,
    _lock_fd: OwnedFd,
    fs_id: FsId,
    hmac_key: [u8; 32],
    state: PersistedState,
    by_host: HashMap<HostInodeKey, u64>,
}

fn open_dir_chain_nofollow(path: &Path) -> Result<OwnedFd, Errno> {
    let mut cur = sys::openat_nofollow(
        unsafe { BorrowedFd::borrow_raw(libc::AT_FDCWD) },
        "/",
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )?;
    for comp in path.components() {
        match comp {
            Component::RootDir => {}
            Component::Normal(part) => {
                let name = part.to_str().ok_or(Errno::EINVAL)?;
                match sys::openat_nofollow(cur.as_fd(), name, libc::O_RDONLY | libc::O_DIRECTORY, 0)
                {
                    Ok(next) => cur = next,
                    Err(Errno::ENOENT) => {
                        match sys::mkdirat_dir(cur.as_fd(), name, 0o700) {
                            Ok(()) | Err(Errno::EEXIST) => {}
                            Err(e) => return Err(e),
                        }
                        cur = sys::openat_nofollow(
                            cur.as_fd(),
                            name,
                            libc::O_RDONLY | libc::O_DIRECTORY,
                            0,
                        )?;
                    }
                    Err(e) => return Err(e),
                }
            }
            _ => return Err(Errno::EINVAL),
        }
    }
    Ok(cur)
}

impl StateStore {
    pub fn open(
        canonical_root: &Path,
        state_dir: &Path,
        root_key: HostInodeKey,
    ) -> Result<Self, Errno> {
        let resolved_state = validate_state_dir_outside_root(canonical_root, state_dir)
            .map_err(|_| Errno::EINVAL)?;
        let folders_dir = resolved_state.join("folders");

        let root_file = File::open(canonical_root).map_err(|e| sys::io_to_errno(&e))?;
        let root_stx = sys::statx_fd(root_file.as_fd())?;

        let state_fd = open_dir_chain_nofollow(&resolved_state)?;
        let state_stx = sys::statx_fd(state_fd.as_fd())?;
        if state_stx.ino == root_stx.ino && state_stx.dev == root_stx.dev {
            return Err(Errno::EINVAL);
        }
        sys::verify_state_dirs_outside_root(
            canonical_root,
            root_file.as_fd(),
            &resolved_state,
            state_fd.as_fd(),
            &folders_dir,
            None,
        )?;
        let folders_fd = open_dir_chain_nofollow(&folders_dir)?;
        let folders_stx = sys::statx_fd(folders_fd.as_fd())?;
        if folders_stx.ino == root_stx.ino && folders_stx.dev == root_stx.dev {
            return Err(Errno::EINVAL);
        }
        sys::verify_state_dirs_outside_root(
            canonical_root,
            root_file.as_fd(),
            &resolved_state,
            state_fd.as_fd(),
            &folders_dir,
            Some(folders_fd.as_fd()),
        )?;

        let _ = sys::fchmod_fd(state_fd.as_fd(), 0o700);
        let _ = sys::fchmod_fd(folders_fd.as_fd(), 0o700);
        drop(state_fd);

        let root_hash = sys::hex_encode(&Sha256::digest(
            canonical_root.as_os_str().as_encoded_bytes(),
        ));
        let lock_name = format!("{root_hash}.lock");
        let lock_fd = sys::openat_nofollow(
            folders_fd.as_fd(),
            &lock_name,
            libc::O_CREAT | libc::O_RDWR,
            0o600,
        )?;
        sys::flock_fd(lock_fd.as_fd(), libc::LOCK_EX | libc::LOCK_NB)
            .map_err(|e| if e == Errno::EAGAIN { Errno::EBUSY } else { e })?;

        let state_name = format!("{root_hash}.json");
        #[cfg(test)]
        let state_file = folders_dir.join(&state_name);

        let (mut state, mut need_flush) =
            match sys::openat_nofollow(folders_fd.as_fd(), &state_name, libc::O_RDONLY, 0) {
                Ok(fd) => {
                    let mut bytes = Vec::new();
                    File::from(fd)
                        .read_to_end(&mut bytes)
                        .map_err(|e| sys::io_to_errno(&e))?;
                    let header: PersistedHeader =
                        serde_json::from_slice(&bytes).map_err(|_| Errno::EIO)?;
                    if header.format_version > STATE_FORMAT_VERSION {
                        return Err(Errno::EPROTONOSUPPORT);
                    }
                    if header.format_version < STATE_FORMAT_VERSION {
                        // Older state version: reset metadata once without touching host files.
                        (Self::mint_fresh_state(root_key)?, true)
                    } else {
                        let loaded: PersistedState =
                            serde_json::from_slice(&bytes).map_err(|_| Errno::EIO)?;
                        if loaded.root_identity.as_ref() != Some(&root_key)
                            || decode_key_32(&loaded.handle_key).is_none()
                        {
                            // Host root directory itself changed identity; never inherit stale grants.
                            (Self::mint_fresh_state(root_key)?, true)
                        } else {
                            (loaded, false)
                        }
                    }
                }
                Err(Errno::ENOENT) => (Self::mint_fresh_state(root_key)?, true),
                Err(e) => return Err(e),
            };

        // Sweep crash-persisted unlinked nodes on startup when no descriptors remain open.
        let before_sweep = state.nodes.len();
        state
            .nodes
            .retain(|&ino, rec| ino == ROOT_INO || !rec.unlinked);
        if state.nodes.len() != before_sweep {
            need_flush = true;
        }

        let hmac_key = decode_key_32(&state.handle_key).ok_or(Errno::EIO)?;
        let fs_id = FsId(format!("helperfs:{}", state.folder_uuid));
        let mut by_host = HashMap::with_capacity(state.nodes.len());
        for (ino, record) in &state.nodes {
            by_host.insert(record.host.clone(), *ino);
        }

        let store = Self {
            state_name,
            #[cfg(test)]
            state_file,
            folders_fd,
            _lock_fd: lock_fd,
            fs_id,
            hmac_key,
            state,
            by_host,
        };
        if need_flush {
            store.flush()?;
        }
        Ok(store)
    }

    fn mint_fresh_state(root_key: HostInodeKey) -> Result<PersistedState, Errno> {
        let folder_uuid = sys::new_uuid_v4()?;
        let handle_key = sys::hex_encode(&sys::random_bytes::<32>()?);
        Ok(PersistedState {
            format_version: STATE_FORMAT_VERSION,
            folder_uuid,
            handle_key,
            root_identity: Some(root_key),
            next_ino: ROOT_INO + 1,
            nodes: BTreeMap::new(),
        })
    }

    pub fn fs_id(&self) -> &FsId {
        &self.fs_id
    }

    #[cfg(test)]
    pub fn state_file_path(&self) -> &Path {
        &self.state_file
    }

    pub fn ensure_root_node(
        &mut self,
        root_key: &HostInodeKey,
        uid: u32,
        gid: u32,
    ) -> Result<Handle, Errno> {
        if !self.state.nodes.contains_key(&ROOT_INO) {
            let record = StoredNode {
                minted_ino: ROOT_INO,
                generation: 1,
                host: root_key.clone(),
                path_hints: vec![String::new()],
                node: Node::directory(uid, gid, 0o700),
                xattrs: BTreeMap::new(),
                meta_ctime: None,
                unlinked: false,
            };
            self.by_host.insert(root_key.clone(), ROOT_INO);
            self.state.nodes.insert(ROOT_INO, record);
            self.flush()?;
        }
        Ok(self.sign_handle(NodeId {
            ino: ROOT_INO,
            generation: self.state.nodes[&ROOT_INO].generation,
        }))
    }

    pub fn sign_handle(&self, node: NodeId) -> Handle {
        Handle {
            fs: self.fs_id.clone(),
            node,
            proof: self.hmac_proof(node),
        }
    }

    pub fn verify_handle(&self, handle: &Handle) -> Result<u64, Errno> {
        if handle.fs != self.fs_id {
            return Err(Errno::EACCES);
        }
        let expected = self.hmac_proof(handle.node);
        if !sys::constant_time_eq(handle.proof.as_bytes(), expected.as_bytes()) {
            return Err(Errno::EACCES);
        }
        let Some(record) = self.state.nodes.get(&handle.node.ino) else {
            return Err(Errno::ESTALE);
        };
        if record.generation != handle.node.generation {
            return Err(Errno::ESTALE);
        }
        Ok(handle.node.ino)
    }

    fn hmac_proof(&self, node: NodeId) -> String {
        let mut msg = Vec::with_capacity(self.fs_id.0.len() + 48);
        msg.extend_from_slice(b"os-local-helper:handle:v1\0");
        msg.extend_from_slice(self.fs_id.0.as_bytes());
        msg.push(0);
        msg.extend_from_slice(&node.ino.to_le_bytes());
        msg.extend_from_slice(&node.generation.to_le_bytes());
        sys::hex_encode(&hmac_sha256(&self.hmac_key, &msg))
    }

    pub fn get(&self, ino: u64) -> Option<&StoredNode> {
        self.state.nodes.get(&ino)
    }

    pub fn get_mut(&mut self, ino: u64) -> Option<&mut StoredNode> {
        self.state.nodes.get_mut(&ino)
    }

    #[cfg(test)]
    pub fn next_ino_mut(&mut self) -> &mut u64 {
        &mut self.state.next_ino
    }

    fn mint_ino(&mut self) -> Result<u64, Errno> {
        let mut candidate = self.state.next_ino.max(ROOT_INO + 1);
        while candidate <= JS_SAFE {
            if !self.state.nodes.contains_key(&candidate) {
                self.state.next_ino = candidate + 1;
                return Ok(candidate);
            }
            candidate += 1;
        }
        Err(Errno::ENOSPC)
    }

    /// Look up an existing host inode or mint a private-default record when newly discovered or
    /// replaced outside OS. Returns `(minted_ino, dirty)`.
    pub fn has_host_key(&self, key: &HostInodeKey) -> bool {
        self.by_host.contains_key(key)
    }

    pub fn discover_or_reset<F>(
        &mut self,
        relpath: &str,
        key: HostInodeKey,
        default_uid: u32,
        default_gid: u32,
        is_open: &F,
    ) -> Result<(u64, bool), Errno>
    where
        F: Fn(u64) -> bool,
    {
        self.discover_or_reset_with_mode(relpath, key, default_uid, default_gid, 0o600, is_open)
    }

    pub fn discover_or_reset_with_mode<F>(
        &mut self,
        relpath: &str,
        key: HostInodeKey,
        default_uid: u32,
        default_gid: u32,
        default_file_mode: u16,
        is_open: &F,
    ) -> Result<(u64, bool), Errno>
    where
        F: Fn(u64) -> bool,
    {
        if relpath.is_empty() {
            if self.state.root_identity.as_ref() == Some(&key)
                && self.state.nodes.contains_key(&ROOT_INO)
            {
                return Ok((ROOT_INO, false));
            }
            return Err(Errno::ESTALE);
        }
        if let Some(&existing_ino) = self.by_host.get(&key) {
            let mut dirty = self.detach_hint_except(relpath, Some(existing_ino), false, is_open);
            let record = self
                .state
                .nodes
                .get_mut(&existing_ino)
                .expect("by_host index matches nodes map");
            if record.unlinked {
                record.unlinked = false;
                dirty = true;
            }
            if !record.path_hints.iter().any(|p| p == relpath) {
                record.path_hints.push(relpath.to_owned());
                dirty = true;
            }
            return Ok((existing_ino, dirty));
        }

        // Not matched by identity: purge stale hint pointing here without deleting old inode's
        // surviving identity record (it may have been moved externally or have another link).
        self.detach_hint_except(relpath, None, false, is_open);
        let minted_ino = self.mint_ino()?;
        let mut node = match key.kind {
            HostKind::Dir => Node::directory(default_uid, default_gid, 0o700),
            HostKind::File => Node::file(
                default_uid,
                default_gid,
                default_file_mode,
                String::new(),
                0,
            ),
            HostKind::Symlink => Node::symlink(default_uid, default_gid, ""),
            HostKind::Other => Node::device(default_uid, default_gid, 0o600, ""),
        };
        node.ino = minted_ino;
        let record = StoredNode {
            minted_ino,
            generation: 1,
            host: key.clone(),
            path_hints: if relpath.is_empty() {
                vec![String::new()]
            } else {
                vec![relpath.to_owned()]
            },
            node,
            xattrs: BTreeMap::new(),
            meta_ctime: None,
            unlinked: false,
        };
        self.by_host.insert(key, minted_ino);
        self.state.nodes.insert(minted_ino, record);
        Ok((minted_ino, true))
    }

    /// Insert a brand-new node just created by OS (`create`, `mkdir`, `mknod`, `symlink`), cleaning
    /// up any stale record previously occupying `relpath` or `key`.
    pub fn insert_created<F>(
        &mut self,
        relpath: &str,
        key: HostInodeKey,
        mut node: Node,
        is_open: &F,
    ) -> Result<u64, Errno>
    where
        F: Fn(u64) -> bool,
    {
        self.detach_hint_except(relpath, None, false, is_open);
        if let Some(stale_ino) = self.by_host.remove(&key) {
            if is_open(stale_ino) {
                if let Some(rec) = self.state.nodes.get_mut(&stale_ino) {
                    rec.unlinked = true;
                    rec.path_hints.clear();
                }
            } else {
                self.state.nodes.remove(&stale_ino);
            }
        }
        let minted_ino = self.mint_ino()?;
        node.ino = minted_ino;
        let record = StoredNode {
            minted_ino,
            generation: 1,
            host: key.clone(),
            path_hints: vec![relpath.to_owned()],
            node,
            xattrs: BTreeMap::new(),
            meta_ctime: Some(sys::now_timespec()),
            unlinked: false,
        };
        self.by_host.insert(key, minted_ino);
        self.state.nodes.insert(minted_ino, record);
        self.flush()?;
        Ok(minted_ino)
    }

    pub fn add_path_hint(&mut self, ino: u64, relpath: &str) -> Result<(), Errno> {
        if let Some(rec) = self.state.nodes.get_mut(&ino) {
            rec.unlinked = false;
            if !rec.path_hints.iter().any(|p| p == relpath) {
                rec.path_hints.push(relpath.to_owned());
            }
            rec.meta_ctime = Some(sys::now_timespec());
        }
        self.flush()
    }

    pub fn remove_hint<F>(
        &mut self,
        relpath: &str,
        confirmed_last_link: bool,
        is_open: &F,
    ) -> Result<(), Errno>
    where
        F: Fn(u64) -> bool,
    {
        let _ = self.detach_hint_except(relpath, None, confirmed_last_link, is_open);
        self.flush()
    }

    pub fn mark_unlinked(&mut self, ino: u64) -> bool {
        if let Some(rec) = self.state.nodes.get_mut(&ino)
            && !rec.unlinked
        {
            rec.unlinked = true;
            rec.path_hints.clear();
            return true;
        }
        false
    }

    pub fn promote_hint(&mut self, ino: u64, relpath: &str) {
        if let Some(rec) = self.state.nodes.get_mut(&ino)
            && let Some(pos) = rec.path_hints.iter().position(|p| p == relpath)
            && pos != 0
        {
            let item = rec.path_hints.remove(pos);
            rec.path_hints.insert(0, item);
        }
    }

    /// Drop a path hint that returned `ENOENT`/`ENOTDIR` without mistaking missing hints for
    /// inode death (an undiscovered hard link or external rename may keep the inode alive).
    pub fn drop_dead_hint(&mut self, ino: u64, relpath: &str) -> bool {
        let Some(rec) = self.state.nodes.get_mut(&ino) else {
            return false;
        };
        let before = rec.path_hints.len();
        rec.path_hints.retain(|p| p != relpath);
        rec.path_hints.len() != before
    }

    pub fn gc_unlinked(&mut self, ino: u64, still_open: bool) -> Result<(), Errno> {
        if still_open {
            return Ok(());
        }
        let should_remove = self
            .state
            .nodes
            .get(&ino)
            .is_some_and(|rec| rec.unlinked && rec.path_hints.is_empty());
        if should_remove {
            if let Some(removed) = self.state.nodes.remove(&ino) {
                self.by_host.remove(&removed.host);
            }
            self.flush()?;
        }
        Ok(())
    }

    pub fn apply_rename<F>(
        &mut self,
        from_rel: &str,
        to_rel: &str,
        is_dir: bool,
        target_confirmed_last_link: bool,
        is_open: &F,
    ) -> Result<(), Errno>
    where
        F: Fn(u64) -> bool,
    {
        if from_rel == to_rel {
            return Ok(());
        }
        // Any existing destination path hints are replaced (including subtree hints if overwriting
        // an empty directory).
        self.detach_hint_except(to_rel, None, target_confirmed_last_link, is_open);

        let from_prefix = format!("{from_rel}/");
        let to_prefix = format!("{to_rel}/");
        let mut rekey = Vec::new();
        for (&ino, rec) in &mut self.state.nodes {
            for hint in &mut rec.path_hints {
                if hint == from_rel {
                    *hint = to_rel.to_owned();
                } else if is_dir && hint.starts_with(&from_prefix) {
                    *hint = format!("{to_prefix}{}", &hint[from_prefix.len()..]);
                }
            }
            if is_dir
                && (rec.host.subfs_relpath == from_rel
                    || rec.host.subfs_relpath.starts_with(&from_prefix))
            {
                let old_key = rec.host.clone();
                if rec.host.subfs_relpath == from_rel {
                    rec.host.subfs_relpath = to_rel.to_owned();
                } else {
                    rec.host.subfs_relpath = format!(
                        "{to_prefix}{}",
                        &rec.host.subfs_relpath[from_prefix.len()..]
                    );
                }
                rekey.push((ino, old_key, rec.host.clone()));
            }
        }
        for (ino, old_key, new_key) in rekey {
            self.by_host.remove(&old_key);
            self.by_host.insert(new_key, ino);
        }
        self.flush()
    }

    fn detach_hint_except<F>(
        &mut self,
        relpath: &str,
        keep_ino: Option<u64>,
        confirmed_last_link: bool,
        is_open: &F,
    ) -> bool
    where
        F: Fn(u64) -> bool,
    {
        if relpath.is_empty() {
            return false;
        }
        let mut to_prune = Vec::new();
        let mut changed = false;
        for (&ino, rec) in &mut self.state.nodes {
            if Some(ino) == keep_ino {
                continue;
            }
            let prev = rec.path_hints.len();
            rec.path_hints.retain(|p| p != relpath);
            if rec.path_hints.len() != prev {
                changed = true;
                if rec.path_hints.is_empty() && confirmed_last_link {
                    if is_open(ino) {
                        rec.unlinked = true;
                    } else {
                        to_prune.push(ino);
                    }
                }
            }
        }
        for ino in to_prune {
            if let Some(removed) = self.state.nodes.remove(&ino) {
                self.by_host.remove(&removed.host);
            }
        }
        changed
    }

    pub fn flush(&self) -> Result<(), Errno> {
        let payload = serde_json::to_vec(&self.state).map_err(|_| Errno::EIO)?;
        let tmp_name = format!(
            ".{}.tmp.{}",
            self.state_name,
            sys::hex_encode(&sys::random_bytes::<8>()?)
        );
        {
            let tmp_fd = sys::openat_nofollow(
                self.folders_fd.as_fd(),
                &tmp_name,
                libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY,
                0o600,
            )?;
            let mut file = File::from(tmp_fd);
            file.write_all(&payload).map_err(|e| sys::io_to_errno(&e))?;
            file.sync_all().map_err(|e| sys::io_to_errno(&e))?;
        }
        sys::renameat_same_dir(self.folders_fd.as_fd(), &tmp_name, &self.state_name)?;
        sys::sync_fd(self.folders_fd.as_fd(), false)?;
        Ok(())
    }
}

fn decode_key_32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let s = std::str::from_utf8(chunk).ok()?;
        out[i] = u8::from_str_radix(s, 16).ok()?;
    }
    Some(out)
}

fn hmac_sha256(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for (i, &b) in key.iter().enumerate() {
        ipad[i] ^= b;
        opad[i] ^= b;
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    outer.finalize().into()
}

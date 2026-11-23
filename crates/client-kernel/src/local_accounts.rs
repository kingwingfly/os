//! Instance-local OS accounts bridge (`#57` L3d, Contract v2 §2.1, §2.4, §2.15).
//!
//! Routes all local OS account syscalls (`Getcreds`, `Login`, `Logout`, `Sudo`, `Passwd`,
//! `Useradd`, `Usermod`, `Userdel`, `Groupadd`, `Groupmod`, `Groupdel`) exclusively through
//! [`kernel::accounts::LocalAccountStore`] against local `/etc/{passwd,group,shadow,sudoers}`
//! on local `/` (`os-cowfs` or Stage 1 `tmpfs`) with **ZERO** network RPCs, **ZERO** `issuer`,
//! and **ZERO** `(issuer, subject)` UID federation.
//!
//! Also enforces strict local vs remote authority separation:
//! - Local `uid 0` / `sudo` / `su root` NEVER synthesizes a remote root token (retains at most
//!   the invoker's existing non-root `remote` cred or `None`).
//! - Privilege drops (`su <non-root>`, `login <other>`, `newgrp`, `ServiceGrant.user`) clear
//!   ambient `remote` credentials and immediately revoke dropped `ServiceAuth v2` tokens.

use crate::vfs_engine::SCOPED_PAGE_PID_BASE;
use crate::{INIT, Kernel, LocalAccount, now_secs, random_hex, revoke_remote_tokens_state};
use abi::{Call, Creds, Errno, Error};
use kernel::accounts::{
    AccountFs, DEFAULT_GROUP, DEFAULT_PASSWD, DEFAULT_SHADOW, DEFAULT_SUDOERS, GROUP_MODE,
    GroupEntry, LocalAccountStore, PASSWD_MODE, PasswdEntry, SHADOW_MODE, SUDOERS_MODE, SudoCheck,
    UseraddReq, UsermodReq, parse_group, parse_passwd,
};
use os_core::permissions::Identity;
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashMap, HashSet};
use vfs::memfs::MemFs;
use vfs::{Cred, Filesystem, OpenOptions, RenameFlags, SetAttr, StartAnchor, Vfs, WriteAt};

const PASSWD_PATH: &str = "/etc/passwd";
const GROUP_PATH: &str = "/etc/group";
const SHADOW_PATH: &str = "/etc/shadow";
const SUDOERS_PATH: &str = "/etc/sudoers";

const SUDO_TTL_SECS: u64 = 300;
/// Hard ceiling for reading local `/etc/{passwd,group,shadow,sudoers}` files without truncation.
/// Files exceeding this size fail closed with `Errno::EFBIG` instead of silently truncating.
pub(crate) const MAX_ACCOUNT_FILE_BYTES: usize = 16 * 1024 * 1024;

fn random_salt() -> [u8; 16] {
    let hex = random_hex(16);
    let mut out = [0u8; 16];
    let bytes = hex.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_nibble(bytes.get(i * 2).copied().unwrap_or(b'0'));
        let lo = hex_nibble(bytes.get(i * 2 + 1).copied().unwrap_or(b'0'));
        *slot = (hi << 4) | lo;
    }
    out
}

fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

/// Recorded mutation emitted by `LocalAccountStore` while operating on the sync snapshot.
enum FsMutation {
    WriteFile {
        path: String,
        data: Vec<u8>,
        mode: u16,
        uid: u32,
        gid: u32,
    },
    Rename {
        from: String,
        to: String,
    },
    RemoveFile {
        path: String,
    },
    MkdirP {
        path: String,
        mode: u16,
        uid: u32,
        gid: u32,
    },
    RemoveDirAll {
        path: String,
        expected_dev: u64,
        expected_uid: u32,
        expected_ino: u64,
    },
}

fn parent_dir(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() || trimmed == "/" {
        return "/";
    }
    match trimmed.rfind('/') {
        Some(0) | None => "/",
        Some(idx) => &trimmed[..idx],
    }
}

fn etc_file_mode(path: &str) -> u16 {
    match path {
        PASSWD_PATH => PASSWD_MODE,
        GROUP_PATH => GROUP_MODE,
        SHADOW_PATH => SHADOW_MODE,
        SUDOERS_PATH => SUDOERS_MODE,
        _ => 0o644,
    }
}

async fn stat_with_parent_dev(
    vfs: &Vfs,
    path: &str,
    existing: &mut HashSet<String>,
    stats: &mut HashMap<String, abi::Stat>,
    parent_devs: &mut HashMap<String, u64>,
) -> Result<(), Error> {
    if path.is_empty() || stats.contains_key(path) {
        return Ok(());
    }
    match vfs.statat(INIT, StartAnchor::Root, path, false).await {
        Ok(st) => {
            existing.insert(path.to_string());
            stats.insert(path.to_string(), st);
            let parent = parent_dir(path);
            let parent_st = vfs
                .statat(INIT, StartAnchor::Root, parent, true)
                .await
                .map_err(Error::from)?;
            parent_devs.insert(path.to_string(), parent_st.dev);
            Ok(())
        }
        Err(Errno::ENOENT | Errno::ENOTDIR) => Ok(()),
        Err(e) => Err(Error::from(e)),
    }
}

/// Sync [`AccountFs`] snapshot bridged cleanly to async [`os_vfs::Vfs`] as PID 1 (`Cred::root()`).
pub(crate) struct VfsSnapshotAccountFs {
    files: HashMap<String, Vec<u8>>,
    initial_files: HashMap<String, Vec<u8>>,
    existing: HashSet<String>,
    stats: HashMap<String, abi::Stat>,
    parent_devs: HashMap<String, u64>,
    ops: Vec<FsMutation>,
}

impl VfsSnapshotAccountFs {
    pub(crate) async fn load(vfs: &Vfs, extra_paths: &[&str]) -> Result<Self, Error> {
        let mut files = HashMap::new();
        let mut initial_files = HashMap::new();
        let mut existing = HashSet::new();
        let mut stats = HashMap::new();
        let mut parent_devs = HashMap::new();

        for &path in &[PASSWD_PATH, GROUP_PATH, SHADOW_PATH, SUDOERS_PATH] {
            match read_vfs_file_as_root(vfs, path).await {
                Ok(bytes) => {
                    existing.insert(path.to_string());
                    initial_files.insert(path.to_string(), bytes.clone());
                    files.insert(path.to_string(), bytes);
                }
                Err(Errno::ENOENT) => {}
                Err(e) => return Err(Error::from(e)),
            }
        }
        for &path in &["/etc", "/home", "/home/user", "/root"] {
            stat_with_parent_dev(vfs, path, &mut existing, &mut stats, &mut parent_devs).await?;
        }
        for &path in extra_paths {
            stat_with_parent_dev(vfs, path, &mut existing, &mut stats, &mut parent_devs).await?;
        }
        // Preload lstat + parent `st_dev` for existing home directories referenced in
        // `/etc/passwd` so `userdel -r` and `usermod -m` validate ownership, file type (refusing
        // symlinks), and mount boundaries BEFORE mutating `/etc/{passwd,group,shadow}`.
        if let Some(raw_pw) = files.get(PASSWD_PATH)
            && let Ok(text) = std::str::from_utf8(raw_pw)
            && let Ok(records) = parse_passwd(text)
        {
            for rec in records {
                stat_with_parent_dev(vfs, &rec.home, &mut existing, &mut stats, &mut parent_devs)
                    .await?;
            }
        }
        Ok(Self {
            files,
            initial_files,
            existing,
            stats,
            parent_devs,
            ops: Vec::new(),
        })
    }

    pub(crate) async fn flush(self, vfs: &Vfs) -> Result<(), Error> {
        enum AppliedRename {
            ReplacedFile {
                target: String,
                prev_bytes: Option<Vec<u8>>,
                mode: u16,
                uid: u32,
                gid: u32,
            },
            MovedPath {
                from: String,
                to: String,
            },
        }

        let mut writes = Vec::new();
        let mut renames = Vec::new();
        let mut post_ops = Vec::new();
        for op in self.ops {
            match op {
                FsMutation::WriteFile { .. } => writes.push(op),
                FsMutation::Rename { .. } => renames.push(op),
                other => post_ops.push(other),
            }
        }

        // Phase 1: Stage ALL `WriteFile` operations (`*.tmp.*`) first. If ANY write fails, clean
        // up every already-staged temp file and return `Err` without touching live `/etc/*`!
        let mut staged_files: Vec<String> = Vec::with_capacity(writes.len());
        let mut staged_meta: HashMap<String, (u16, u32, u32)> = HashMap::new();
        for op in writes {
            if let FsMutation::WriteFile {
                path,
                data,
                mode,
                uid,
                gid,
            } = op
            {
                if let Err(err) = write_vfs_file_as_root(vfs, &path, &data, mode, uid, gid).await {
                    let _ = vfs.unlinkat(INIT, StartAnchor::Root, &path, false).await;
                    for staged in staged_files {
                        let _ = vfs.unlinkat(INIT, StartAnchor::Root, &staged, false).await;
                    }
                    return Err(err);
                }
                staged_meta.insert(path.clone(), (mode, uid, gid));
                staged_files.push(path);
            }
        }

        // Phase 2: Apply ALL `Rename` operations while tracking applied changes. If ANY rename
        // fails mid-batch, roll back already-renamed files from `self.initial_files` (and undo
        // moved paths) and remove all remaining staged temp files before returning `Err`!
        let mut remaining_staged: HashSet<String> = staged_files.into_iter().collect();
        let mut applied_renames: Vec<AppliedRename> = Vec::with_capacity(renames.len());
        for op in renames {
            if let FsMutation::Rename { from, to } = op {
                let is_staged = remaining_staged.contains(&from);
                if let Err(e) = vfs
                    .renameat(
                        INIT,
                        StartAnchor::Root,
                        &from,
                        StartAnchor::Root,
                        &to,
                        RenameFlags::empty(),
                    )
                    .await
                {
                    for applied in applied_renames.into_iter().rev() {
                        match applied {
                            AppliedRename::ReplacedFile {
                                target,
                                prev_bytes: Some(bytes),
                                mode,
                                uid,
                                gid,
                            } => {
                                let rb_tmp = format!("{target}.rollback.{}", random_hex(8));
                                let restored =
                                    write_vfs_file_as_root(vfs, &rb_tmp, &bytes, mode, uid, gid)
                                        .await
                                        .is_ok()
                                        && vfs
                                            .renameat(
                                                INIT,
                                                StartAnchor::Root,
                                                &rb_tmp,
                                                StartAnchor::Root,
                                                &target,
                                                RenameFlags::empty(),
                                            )
                                            .await
                                            .is_ok();
                                if !restored {
                                    let _ =
                                        vfs.unlinkat(INIT, StartAnchor::Root, &rb_tmp, false).await;
                                    let _ = write_vfs_file_as_root(
                                        vfs, &target, &bytes, mode, uid, gid,
                                    )
                                    .await;
                                }
                            }
                            AppliedRename::ReplacedFile {
                                target,
                                prev_bytes: None,
                                ..
                            } => {
                                let _ = vfs.unlinkat(INIT, StartAnchor::Root, &target, false).await;
                            }
                            AppliedRename::MovedPath {
                                from: orig_from,
                                to: orig_to,
                            } => {
                                let _ = vfs
                                    .renameat(
                                        INIT,
                                        StartAnchor::Root,
                                        &orig_to,
                                        StartAnchor::Root,
                                        &orig_from,
                                        RenameFlags::empty(),
                                    )
                                    .await;
                            }
                        }
                    }
                    for staged in remaining_staged {
                        let _ = vfs.unlinkat(INIT, StartAnchor::Root, &staged, false).await;
                    }
                    return Err(Error::from(e));
                }
                if is_staged {
                    remaining_staged.remove(&from);
                    let (mode, uid, gid) = staged_meta
                        .get(&from)
                        .copied()
                        .unwrap_or_else(|| (etc_file_mode(&to), 0, 0));
                    applied_renames.push(AppliedRename::ReplacedFile {
                        prev_bytes: self.initial_files.get(&to).cloned(),
                        target: to,
                        mode,
                        uid,
                        gid,
                    });
                } else {
                    applied_renames.push(AppliedRename::MovedPath { from, to });
                }
            }
        }

        // Phase 3: Apply post-rename mutations (`RemoveFile`, `MkdirP`, pinned `RemoveDirAll`).
        for op in post_ops {
            match op {
                FsMutation::RemoveFile { path } => {
                    match vfs.unlinkat(INIT, StartAnchor::Root, &path, false).await {
                        Ok(()) | Err(Errno::ENOENT) => {}
                        Err(e) => return Err(Error::from(e)),
                    }
                }
                FsMutation::MkdirP {
                    path,
                    mode,
                    uid,
                    gid,
                } => {
                    ensure_parent_dirs_as_root(vfs, &path).await?;
                    match vfs.mkdirat(INIT, StartAnchor::Root, &path, mode).await {
                        Ok(_) | Err(Errno::EEXIST) => {}
                        Err(e) => return Err(Error::from(e)),
                    }
                    vfs.setattrat(
                        INIT,
                        StartAnchor::Root,
                        &path,
                        &SetAttr {
                            mode: Some(mode),
                            uid: Some(uid),
                            gid: Some(gid),
                            ..SetAttr::default()
                        },
                        false,
                    )
                    .await
                    .map_err(Error::from)?;
                }
                FsMutation::RemoveDirAll {
                    path,
                    expected_dev,
                    expected_uid,
                    expected_ino,
                } => {
                    // Re-verify the pinned lstat identity + parent mount boundary right before
                    // unlinking to close any TOCTOU window.
                    let st = match vfs.statat(INIT, StartAnchor::Root, &path, false).await {
                        Ok(st) => st,
                        Err(Errno::ENOENT) => continue,
                        Err(e) => return Err(Error::from(e)),
                    };
                    if st.kind() != abi::S_IFDIR {
                        return Err(Error::because(
                            Errno::ENOTDIR,
                            format!("refusing to remove non-directory home '{path}'"),
                        ));
                    }
                    if st.uid != expected_uid {
                        return Err(Error::because(
                            Errno::EPERM,
                            format!(
                                "refusing to remove home '{path}' owned by uid {} (expected {expected_uid})",
                                st.uid
                            ),
                        ));
                    }
                    let parent_st = vfs
                        .statat(INIT, StartAnchor::Root, parent_dir(&path), true)
                        .await
                        .map_err(Error::from)?;
                    if st.dev != expected_dev || st.dev != parent_st.dev {
                        return Err(Error::because(
                            Errno::EXDEV,
                            format!("refusing to remove mountpoint home '{path}'"),
                        ));
                    }
                    if st.ino != expected_ino {
                        return Err(Error::because(
                            Errno::ESTALE,
                            format!("home directory '{path}' changed before removal"),
                        ));
                    }
                    remove_tree_as_root(vfs, &path, expected_dev).await?;
                }
                FsMutation::WriteFile { .. } | FsMutation::Rename { .. } => {}
            }
        }
        Ok(())
    }
}

impl AccountFs for VfsSnapshotAccountFs {
    fn read_file(&self, path: &str) -> Result<Vec<u8>, Error> {
        self.files
            .get(path)
            .cloned()
            .ok_or_else(|| Error::from(Errno::ENOENT))
    }

    fn write_file(
        &mut self,
        path: &str,
        data: &[u8],
        mode: u16,
        uid: u32,
        gid: u32,
    ) -> Result<(), Error> {
        self.files.insert(path.to_string(), data.to_vec());
        self.existing.insert(path.to_string());
        self.ops.push(FsMutation::WriteFile {
            path: path.to_string(),
            data: data.to_vec(),
            mode,
            uid,
            gid,
        });
        Ok(())
    }

    fn rename(&mut self, from: &str, to: &str) -> Result<(), Error> {
        if let Some(bytes) = self.files.remove(from) {
            self.files.insert(to.to_string(), bytes);
        }
        self.existing.remove(from);
        self.existing.insert(to.to_string());
        self.ops.push(FsMutation::Rename {
            from: from.to_string(),
            to: to.to_string(),
        });
        Ok(())
    }

    fn remove_file(&mut self, path: &str) -> Result<(), Error> {
        self.files.remove(path);
        self.existing.remove(path);
        self.ops.push(FsMutation::RemoveFile {
            path: path.to_string(),
        });
        Ok(())
    }

    fn exists(&self, path: &str) -> bool {
        self.existing.contains(path) || self.files.contains_key(path)
    }

    fn mkdir_p(&mut self, path: &str, mode: u16, uid: u32, gid: u32) -> Result<(), Error> {
        self.existing.insert(path.to_string());
        self.ops.push(FsMutation::MkdirP {
            path: path.to_string(),
            mode,
            uid,
            gid,
        });
        Ok(())
    }

    fn remove_dir_all(&mut self, path: &str) -> Result<(), Error> {
        let st = self.stats.get(path).cloned().ok_or_else(|| {
            Error::because(
                Errno::ENOENT,
                format!("unpinned home directory '{path}' cannot be removed"),
            )
        })?;
        self.files.remove(path);
        self.existing.remove(path);
        self.ops.push(FsMutation::RemoveDirAll {
            path: path.to_string(),
            expected_dev: st.dev,
            expected_uid: st.uid,
            expected_ino: st.ino,
        });
        Ok(())
    }

    fn validate_removable_home(&self, path: &str, expected_uid: u32) -> Result<(), Error> {
        let Some(st) = self.stats.get(path) else {
            if self.existing.contains(path) {
                return Err(Error::from(Errno::EIO));
            }
            return Ok(());
        };
        if st.kind() != abi::S_IFDIR {
            return Err(Error::because(
                Errno::ENOTDIR,
                format!("refusing to remove non-directory home '{path}'"),
            ));
        }
        if st.uid != expected_uid {
            return Err(Error::because(
                Errno::EPERM,
                format!(
                    "refusing to remove home '{path}' owned by uid {} (expected {expected_uid})",
                    st.uid
                ),
            ));
        }
        let parent_dev = self
            .parent_devs
            .get(path)
            .copied()
            .ok_or_else(|| Error::from(Errno::EIO))?;
        if st.dev != parent_dev {
            return Err(Error::because(
                Errno::EXDEV,
                format!("refusing to remove mountpoint home '{path}'"),
            ));
        }
        Ok(())
    }
}

async fn read_vfs_file_as_root(vfs: &Vfs, path: &str) -> vfs::Result<Vec<u8>> {
    read_vfs_file_as_root_with_limit(vfs, path, MAX_ACCOUNT_FILE_BYTES).await
}

async fn read_vfs_file_as_root_with_limit(
    vfs: &Vfs,
    path: &str,
    max_bytes: usize,
) -> vfs::Result<Vec<u8>> {
    let (file, entry) = vfs
        .open_file(INIT, StartAnchor::Root, path, abi::O_RDONLY, 0)
        .await?;
    if entry.metadata.size > max_bytes as u64 {
        let _ = file.close().await;
        return Err(Errno::EFBIG);
    }
    let initial_cap = usize::try_from(entry.metadata.size)
        .unwrap_or(0)
        .min(64 * 1024);
    let mut out = Vec::with_capacity(initial_cap);
    let mut chunk = vec![0u8; 64 * 1024];
    let mut off = 0u64;
    loop {
        match file.read_at(&mut chunk, off).await {
            Ok(0) => break,
            Ok(n) => {
                if out.len().saturating_add(n) > max_bytes {
                    let _ = file.close().await;
                    return Err(Errno::EFBIG);
                }
                out.extend_from_slice(&chunk[..n]);
                off = off.saturating_add(n as u64);
            }
            Err(e) => {
                let _ = file.close().await;
                return Err(e);
            }
        }
    }
    let _ = file.close().await;
    Ok(out)
}

async fn ensure_parent_dirs_as_root(vfs: &Vfs, path: &str) -> Result<(), Error> {
    let mut cur = String::new();
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if parts.len() <= 1 {
        return Ok(());
    }
    for part in &parts[..parts.len() - 1] {
        cur.push('/');
        cur.push_str(part);
        match vfs.mkdirat(INIT, StartAnchor::Root, &cur, 0o755).await {
            Ok(_) | Err(Errno::EEXIST) => {}
            Err(e) => return Err(Error::from(e)),
        }
    }
    Ok(())
}

async fn write_vfs_file_as_root(
    vfs: &Vfs,
    path: &str,
    data: &[u8],
    mode: u16,
    uid: u32,
    gid: u32,
) -> Result<(), Error> {
    ensure_parent_dirs_as_root(vfs, path).await?;
    let (file, _) = vfs
        .open_file(
            INIT,
            StartAnchor::Root,
            path,
            abi::O_WRONLY | abi::O_CREAT | abi::O_TRUNC,
            mode,
        )
        .await
        .map_err(Error::from)?;
    let mut off = 0usize;
    while off < data.len() {
        let end = (off + 256 * 1024).min(data.len());
        match file.write_at(&data[off..end], off as u64).await {
            Ok(w) if w > 0 => off += w,
            Ok(_) => {
                let _ = file.close().await;
                return Err(Error::from(Errno::EIO));
            }
            Err(e) => {
                let _ = file.close().await;
                return Err(Error::from(e));
            }
        }
    }
    file.close().await.map_err(Error::from)?;
    vfs.setattrat(
        INIT,
        StartAnchor::Root,
        path,
        &SetAttr {
            mode: Some(mode),
            uid: Some(uid),
            gid: Some(gid),
            ..SetAttr::default()
        },
        false,
    )
    .await
    .map_err(Error::from)?;
    Ok(())
}

fn remove_tree_as_root<'a>(
    vfs: &'a Vfs,
    path: &'a str,
    expected_dev: u64,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Error>> + 'a>> {
    Box::pin(async move {
        let st = match vfs.statat(INIT, StartAnchor::Root, path, false).await {
            Ok(st) => st,
            Err(Errno::ENOENT) => return Ok(()),
            Err(e) => return Err(Error::from(e)),
        };
        if st.dev != expected_dev {
            return Err(Error::because(
                Errno::EXDEV,
                format!("refusing to cross mount boundary at '{path}'"),
            ));
        }
        if st.kind() == abi::S_IFDIR {
            let mut names = Vec::new();
            let mut cookie = 0u64;
            loop {
                let page = vfs
                    .read_dir_page(INIT, StartAnchor::Root, path, cookie, 256)
                    .await
                    .map_err(Error::from)?;
                for e in page.entries {
                    if e.name != "." && e.name != ".." {
                        names.push(e.name);
                    }
                }
                match page.next_cookie {
                    Some(next) if next != cookie => cookie = next,
                    _ => break,
                }
            }
            for name in names {
                let child = if path == "/" {
                    format!("/{name}")
                } else {
                    format!("{path}/{name}")
                };
                remove_tree_as_root(vfs, &child, expected_dev).await?;
            }
            match vfs.unlinkat(INIT, StartAnchor::Root, path, true).await {
                Ok(()) | Err(Errno::ENOENT) => {}
                Err(e) => return Err(Error::from(e)),
            }
        } else {
            match vfs.unlinkat(INIT, StartAnchor::Root, path, false).await {
                Ok(()) | Err(Errno::ENOENT) => {}
                Err(e) => return Err(Error::from(e)),
            }
        }
        Ok(())
    })
}

/// Seed the initial Stage 1 local `MemFs` root (before `switch_root` onto persistent `os-cowfs`)
/// with FHS mountpoints, symlinks, and default local `/etc/{passwd,group,shadow,sudoers}`.
pub(crate) async fn seed_local_stage1_memfs(mem: &MemFs) -> vfs::Result<()> {
    let mut root_cred = Cred::root();
    root_cred.umask = 0;
    let root = mem.root();

    let dirs: &[(&str, u32, u32, u16)] = &[
        ("/boot", 0, 0, 0o755),
        ("/dev", 0, 0, 0o755),
        ("/dev/pts", 0, 0, 0o755),
        ("/etc", 0, 0, 0o755),
        ("/home", 0, 0, 0o755),
        ("/home/user", 1000, 1000, 0o750),
        ("/mnt", 0, 0, 0o755),
        ("/mnt/cloud", 0, 0, 0o755),
        ("/mnt/local", 0, 0, 0o755),
        ("/mnt/shared", 0, 0, 0o755),
        ("/opt", 0, 0, 0o755),
        ("/opt/private", 0, 0, 0o755),
        ("/proc", 0, 0, 0o555),
        ("/root", 0, 0, 0o700),
        ("/run", 0, 0, 0o755),
        ("/run/os", 0, 0, 0o755),
        ("/srv", 0, 0, 0o755),
        ("/sys", 0, 0, 0o555),
        ("/sysroot", 0, 0, 0o755),
        ("/tmp", 0, 0, 0o1777),
        ("/usr", 0, 0, 0o755),
        ("/var", 0, 0, 0o755),
        ("/var/cache", 0, 0, 0o755),
        ("/var/lib", 0, 0, 0o755),
        ("/var/log", 0, 0, 0o755),
        ("/var/tmp", 0, 0, 0o1777),
    ];
    for &(path, uid, gid, mode) in dirs {
        let mut cur = root.clone();
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        for (i, part) in parts.iter().enumerate() {
            let is_last = i + 1 == parts.len();
            match mem.lookup(&root_cred, &cur, part).await {
                Ok(entry) => cur = entry.handle,
                Err(Errno::ENOENT) => {
                    let m = if is_last { mode } else { 0o755 };
                    let created = mem.mkdir(&root_cred, &cur, part, m).await?;
                    if is_last && (uid != 0 || gid != 0 || (mode & 0o7000) != 0) {
                        let _ = mem
                            .setattr(
                                &root_cred,
                                &created.handle,
                                &SetAttr {
                                    mode: Some(mode),
                                    uid: Some(uid),
                                    gid: Some(gid),
                                    ..SetAttr::default()
                                },
                            )
                            .await;
                    }
                    cur = created.handle;
                }
                Err(e) => return Err(e),
            }
        }
    }

    for &(link_name, target) in &[
        ("bin", "usr/bin"),
        ("sbin", "usr/bin"),
        ("lib", "usr/lib"),
        ("lib64", "usr/lib"),
    ] {
        if mem.lookup(&root_cred, &root, link_name).await.is_err() {
            let _ = mem.symlink(&root_cred, &root, link_name, target).await;
        }
    }

    let etc = mem.lookup(&root_cred, &root, "etc").await?.handle;
    let defaults: &[(&str, u16, &[u8])] = &[
        ("passwd", 0o644, DEFAULT_PASSWD.as_bytes()),
        ("group", 0o644, DEFAULT_GROUP.as_bytes()),
        ("shadow", 0o600, DEFAULT_SHADOW.as_bytes()),
        ("sudoers", 0o440, DEFAULT_SUDOERS.as_bytes()),
        ("hostname", 0o644, b"os\n"),
        (
            "os-release",
            0o644,
            b"NAME=\"OS\"\nID=os\nVERSION_ID=\"2\"\nPRETTY_NAME=\"OS Release v2\"\n",
        ),
    ];
    for &(name, mode, bytes) in defaults {
        match mem.lookup(&root_cred, &etc, name).await {
            Ok(_) => {}
            Err(Errno::ENOENT) => {
                let mut opts = OpenOptions::new();
                opts.write(true).create(true).truncate(true);
                let (_, open) = mem.create(&root_cred, &etc, name, mode, &opts).await?;
                let _ = mem.write_at(&open, bytes, WriteAt::Offset(0)).await?;
                let _ = mem.release(&open).await;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Seed a freshly provisioned `CowFs` root volume on first boot with Contract v2 defaults.
pub(crate) async fn seed_fresh_cowfs_root<F: Filesystem>(fs: &F) -> vfs::Result<()> {
    let mut root_cred = Cred::root();
    root_cred.umask = 0;
    let root = fs.root();

    let dirs: &[(&str, u32, u32, u16)] = &[
        ("/boot", 0, 0, 0o755),
        ("/dev", 0, 0, 0o755),
        ("/dev/pts", 0, 0, 0o755),
        ("/etc", 0, 0, 0o755),
        ("/home", 0, 0, 0o755),
        ("/home/user", 1000, 1000, 0o750),
        ("/mnt", 0, 0, 0o755),
        ("/mnt/cloud", 0, 0, 0o755),
        ("/mnt/local", 0, 0, 0o755),
        ("/mnt/shared", 0, 0, 0o755),
        ("/opt", 0, 0, 0o755),
        ("/opt/private", 0, 0, 0o755),
        ("/proc", 0, 0, 0o555),
        ("/root", 0, 0, 0o700),
        ("/run", 0, 0, 0o755),
        ("/srv", 0, 0, 0o755),
        ("/sys", 0, 0, 0o555),
        ("/tmp", 0, 0, 0o1777),
        ("/usr", 0, 0, 0o755),
        ("/var", 0, 0, 0o755),
        ("/var/cache", 0, 0, 0o755),
        ("/var/lib", 0, 0, 0o755),
        ("/var/log", 0, 0, 0o755),
        ("/var/tmp", 0, 0, 0o1777),
    ];
    for &(path, uid, gid, mode) in dirs {
        let mut cur = root.clone();
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        for (i, part) in parts.iter().enumerate() {
            let is_last = i + 1 == parts.len();
            match fs.lookup(&root_cred, &cur, part).await {
                Ok(entry) => cur = entry.handle,
                Err(Errno::ENOENT) => {
                    let m = if is_last { mode } else { 0o755 };
                    let created = fs.mkdir(&root_cred, &cur, part, m).await?;
                    if is_last && (uid != 0 || gid != 0 || (mode & 0o7000) != 0) {
                        let _ = fs
                            .setattr(
                                &root_cred,
                                &created.handle,
                                &SetAttr {
                                    mode: Some(mode),
                                    uid: Some(uid),
                                    gid: Some(gid),
                                    ..SetAttr::default()
                                },
                            )
                            .await;
                    }
                    cur = created.handle;
                }
                Err(e) => return Err(e),
            }
        }
    }
    for &(link_name, target) in &[
        ("bin", "usr/bin"),
        ("sbin", "usr/bin"),
        ("lib", "usr/lib"),
        ("lib64", "usr/lib"),
    ] {
        if fs.lookup(&root_cred, &root, link_name).await.is_err() {
            let _ = fs.symlink(&root_cred, &root, link_name, target).await;
        }
    }
    let etc = fs.lookup(&root_cred, &root, "etc").await?.handle;
    let defaults: &[(&str, u16, &[u8])] = &[
        ("passwd", 0o644, DEFAULT_PASSWD.as_bytes()),
        ("group", 0o644, DEFAULT_GROUP.as_bytes()),
        ("shadow", 0o600, DEFAULT_SHADOW.as_bytes()),
        ("sudoers", 0o440, DEFAULT_SUDOERS.as_bytes()),
        ("hostname", 0o644, b"os\n"),
        (
            "os-release",
            0o644,
            b"NAME=\"OS\"\nID=os\nVERSION_ID=\"2\"\nPRETTY_NAME=\"OS Release v2\"\n",
        ),
    ];
    for &(name, mode, bytes) in defaults {
        match fs.lookup(&root_cred, &etc, name).await {
            Ok(_) => {}
            Err(Errno::ENOENT) => {
                let mut opts = OpenOptions::new();
                opts.write(true).create(true).truncate(true);
                let (_, open) = fs.create(&root_cred, &etc, name, mode, &opts).await?;
                let _ = fs.write_at(&open, bytes, WriteAt::Offset(0)).await?;
                let _ = fs.release(&open).await;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn identity_for_passwd(
    rec: &PasswdEntry,
    groups: &[GroupEntry],
) -> (Identity, Vec<u32>, Vec<String>) {
    let mut gids: BTreeSet<u32> = BTreeSet::new();
    gids.insert(rec.gid);
    for g in groups {
        if g.gid == rec.gid || g.members.iter().any(|m| m == &rec.name) {
            gids.insert(g.gid);
        }
    }
    let gid_vec: Vec<u32> = gids.iter().copied().collect();
    let group_names: Vec<String> = gid_vec
        .iter()
        .map(|&gid| {
            groups
                .iter()
                .find(|g| g.gid == gid)
                .map(|g| g.name.clone())
                .unwrap_or_else(|| gid.to_string())
        })
        .collect();
    (
        Identity {
            id: rec.uid,
            group: rec.gid,
            groups: gids,
        },
        gid_vec,
        group_names,
    )
}

fn build_creds_from_records(
    uid: u32,
    gid: u32,
    groups_vec: &[u32],
    passwd: &[PasswdEntry],
    groups: &[GroupEntry],
    can_sudo: bool,
    sudo_active: bool,
) -> Creds {
    let rec = passwd.iter().find(|u| u.uid == uid);
    let user = rec.map(|u| u.name.clone()).unwrap_or_else(|| {
        if uid == 0 {
            "root".into()
        } else {
            uid.to_string()
        }
    });
    let group = groups
        .iter()
        .find(|g| g.gid == gid)
        .map(|g| g.name.clone())
        .unwrap_or_else(|| {
            if gid == 0 {
                "root".into()
            } else {
                gid.to_string()
            }
        });
    let group_names: Vec<String> = groups_vec
        .iter()
        .map(|&g| {
            groups
                .iter()
                .find(|gr| gr.gid == g)
                .map(|gr| gr.name.clone())
                .unwrap_or_else(|| g.to_string())
        })
        .collect();
    let home = rec
        .map(|u| u.home.clone())
        .unwrap_or_else(|| if uid == 0 { "/root".into() } else { "/".into() });
    Creds {
        uid,
        gid,
        groups: groups_vec.to_vec(),
        user,
        group,
        group_names,
        home,
        signed_in: true,
        can_sudo,
        sudo_active,
    }
}

/// Narrow host interface used by the local OS account engine, implemented by [`Kernel`] in
/// production and by a pure-Rust harness in native unit tests (zero `js_sys` dependencies).
trait LocalAccountHost {
    fn state(&self) -> &std::rc::Rc<std::cell::RefCell<crate::State>>;
    fn account_lock(&self) -> &std::rc::Rc<crate::AccountAsyncLock>;
    fn default_user(&self) -> String;
    fn apply_account_update_host(&self, account: LocalAccount);
    fn proc_set_creds_host(
        &self,
        pid: u32,
        uid: u32,
        gid: u32,
        groups: Vec<u32>,
        token: Option<String>,
        cloud_access: bool,
    );
    fn commit_root_cowfs_host<'a>(
        &'a self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Error>> + 'a>>;
    fn refresh_caches_host<'a>(
        &'a self,
        vfs: &'a Vfs,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>>;
}

impl LocalAccountHost for Kernel {
    fn state(&self) -> &std::rc::Rc<std::cell::RefCell<crate::State>> {
        &self.state
    }
    fn account_lock(&self) -> &std::rc::Rc<crate::AccountAsyncLock> {
        &self.account_lock
    }
    fn default_user(&self) -> String {
        self.vfs_rt.borrow().boot_profile.default_user.clone()
    }
    fn apply_account_update_host(&self, account: LocalAccount) {
        self.apply_account_update(account);
    }
    fn proc_set_creds_host(
        &self,
        pid: u32,
        uid: u32,
        gid: u32,
        groups: Vec<u32>,
        token: Option<String>,
        cloud_access: bool,
    ) {
        let _ = self.proc_set_creds(pid, uid, gid, groups, token, cloud_access);
    }
    fn commit_root_cowfs_host<'a>(
        &'a self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Error>> + 'a>> {
        Box::pin(self.commit_root_cowfs_if_mounted())
    }
    fn refresh_caches_host<'a>(
        &'a self,
        vfs: &'a Vfs,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>> {
        Box::pin(self.refresh_local_account_caches(vfs))
    }
}

fn page_sudo_sid_for_state(state: &std::rc::Rc<std::cell::RefCell<crate::State>>) -> u32 {
    let seq = state.borrow().session_seq;
    0x8000_0000 | ((seq as u32) & 0x7fff_ffff).max(1)
}

async fn resolve_local_user_account_vfs(vfs: &Vfs, user_spec: &str) -> Result<LocalAccount, Errno> {
    if user_spec.is_empty() {
        return Err(Errno::ENOENT);
    }
    let raw_pw = read_vfs_file_as_root(vfs, PASSWD_PATH).await?;
    let raw_gr = read_vfs_file_as_root(vfs, GROUP_PATH).await?;
    let passwd = parse_passwd(std::str::from_utf8(&raw_pw).map_err(|_| Errno::EINVAL)?)
        .map_err(|e| e.errno)?;
    let groups = parse_group(std::str::from_utf8(&raw_gr).map_err(|_| Errno::EINVAL)?)
        .map_err(|e| e.errno)?;
    let rec = if let Ok(num_uid) = user_spec.parse::<u32>() {
        passwd.iter().find(|u| u.uid == num_uid)
    } else {
        passwd.iter().find(|u| u.name == user_spec)
    }
    .ok_or(Errno::ENOENT)?;
    let (_, gid_vec, _) = identity_for_passwd(rec, &groups);
    let group = groups
        .iter()
        .find(|g| g.gid == rec.gid)
        .map(|g| g.name.clone())
        .unwrap_or_else(|| rec.gid.to_string());
    Ok(LocalAccount {
        uid: rec.uid,
        gid: rec.gid,
        groups: gid_vec,
        user: rec.name.clone(),
        group,
        home: rec.home.clone(),
        shell: rec.shell.clone(),
        signed_in: true,
    })
}

async fn check_local_sudo_for_sid_on<H: LocalAccountHost>(
    host: &H,
    vfs: &Vfs,
    uid: u32,
    sid: u32,
) -> Result<(bool, bool), Errno> {
    if uid == 0 {
        return Ok((true, true));
    }
    let now = now_secs();
    let snap = VfsSnapshotAccountFs::load(vfs, &[])
        .await
        .map_err(|e| e.errno)?;
    let store = LocalAccountStore::new();
    let raw_pw = snap.read_file(PASSWD_PATH).map_err(|e| e.errno)?;
    let raw_gr = snap.read_file(GROUP_PATH).map_err(|e| e.errno)?;
    let passwd = parse_passwd(std::str::from_utf8(&raw_pw).map_err(|_| Errno::EINVAL)?)
        .map_err(|e| e.errno)?;
    let groups = parse_group(std::str::from_utf8(&raw_gr).map_err(|_| Errno::EINVAL)?)
        .map_err(|e| e.errno)?;
    let Some(rec) = passwd.iter().find(|u| u.uid == uid) else {
        return Ok((false, false));
    };
    let (_, gvec, _) = identity_for_passwd(rec, &groups);
    let check = {
        let st = host.state().borrow();
        store
            .check_sudo_with_timestamps(&snap, uid, &gvec, sid, now, &st.sudo_timestamps)
            .map_err(|e| e.errno)?
    };
    let can_sudo = !matches!(check, SudoCheck::Denied);
    let sudo_active = matches!(check, SudoCheck::AllowedNoPassword);
    Ok((can_sudo, sudo_active))
}

async fn eval_local_account_call_on<H: LocalAccountHost>(
    host: &H,
    vfs: &Vfs,
    pid: u32,
    page_sid: Option<&str>,
    page_sudo: bool,
    call: Call,
) -> Result<Value, Error> {
    let is_page = page_sid.is_some() || pid >= SCOPED_PAGE_PID_BASE;
    let is_mutating = matches!(
        call,
        Call::Passwd { .. }
            | Call::Useradd { .. }
            | Call::Usermod { .. }
            | Call::Userdel { .. }
            | Call::Groupadd { .. }
            | Call::Groupmod { .. }
            | Call::Groupdel { .. }
    );
    // Serialize the entire read -> validate -> flush -> commit cycle for concurrent account
    // mutations BEFORE loading `/etc/*` so two concurrent `useradd` calls never race on UIDs
    // or overwrite each other's updates.
    let _account_guard = if is_mutating {
        Some(host.account_lock().acquire().await)
    } else {
        None
    };

    let (caller_identity, caller_sid) = if is_page {
        let mut id = host.state().borrow().account.identity();
        if page_sudo {
            id = Identity::root();
        }
        (id, page_sudo_sid_for_state(host.state()))
    } else {
        host.state()
            .borrow()
            .table
            .proc(pid)
            .map(|p| (p.cred.identity.clone(), p.sid))
            .ok_or_else(|| Error::from(Errno::ESRCH))?
    };
    let now = now_secs();

    // Collect any extra paths whose existence `LocalAccountStore` needs to know.
    let mut extra_paths: Vec<String> = Vec::new();
    match &call {
        Call::Useradd { name, home, .. } => {
            extra_paths.push(home.clone().unwrap_or_else(|| format!("/home/{name}")));
        }
        Call::Usermod { home: Some(h), .. } => extra_paths.push(h.clone()),
        _ => {}
    }
    let extra_refs: Vec<&str> = extra_paths.iter().map(String::as_str).collect();
    let mut snap = VfsSnapshotAccountFs::load(vfs, &extra_refs).await?;
    // Fail closed if `/etc/passwd` is absent on a live volume: NEVER re-seed defaults over
    // existing `/etc/{group,shadow,sudoers}`! Seeding belongs strictly to fresh volume
    // provisioning (`seed_fresh_cowfs_root` / `seed_local_stage1_memfs`).
    if !snap.exists(PASSWD_PATH) {
        return Err(Error::because(
            Errno::ENOENT,
            "/etc/passwd is missing on live root volume",
        ));
    }
    let mut store = LocalAccountStore::new();

    match call {
        Call::Getcreds => {
            let raw_pw = snap.read_file(PASSWD_PATH)?;
            let raw_gr = snap.read_file(GROUP_PATH)?;
            let passwd = parse_passwd(
                std::str::from_utf8(&raw_pw).map_err(|_| Error::from(Errno::EINVAL))?,
            )?;
            let groups =
                parse_group(std::str::from_utf8(&raw_gr).map_err(|_| Error::from(Errno::EINVAL))?)?;
            let gvec: Vec<u32> = caller_identity.groups.iter().copied().collect();
            let check = {
                let st = host.state().borrow();
                store.check_sudo_with_timestamps(
                    &snap,
                    caller_identity.id,
                    &gvec,
                    caller_sid,
                    now,
                    &st.sudo_timestamps,
                )?
            };
            let can_sudo = !matches!(check, SudoCheck::Denied);
            let sudo_active =
                caller_identity.id == 0 || matches!(check, SudoCheck::AllowedNoPassword);
            let creds = build_creds_from_records(
                caller_identity.id,
                caller_identity.group,
                &gvec,
                &passwd,
                &groups,
                can_sudo,
                sudo_active,
            );
            Ok(json!(creds))
        }
        Call::Sudo { password, revoke } => {
            if revoke {
                host.state()
                    .borrow_mut()
                    .sudo_timestamps
                    .remove(&(caller_identity.id, caller_sid));
                return Ok(json!({ "sudo_active": false }));
            }
            let gvec: Vec<u32> = caller_identity.groups.iter().copied().collect();
            let check = {
                let st = host.state().borrow();
                store.check_sudo_with_timestamps(
                    &snap,
                    caller_identity.id,
                    &gvec,
                    caller_sid,
                    now,
                    &st.sudo_timestamps,
                )?
            };
            match check {
                SudoCheck::Denied => {
                    return Err(Error::because(
                        Errno::EPERM,
                        "current user is not in the sudoers file",
                    ));
                }
                SudoCheck::AllowedNoPassword => {}
                SudoCheck::RequiresPassword => {
                    let raw_pw = snap.read_file(PASSWD_PATH)?;
                    let passwd = parse_passwd(
                        std::str::from_utf8(&raw_pw).map_err(|_| Error::from(Errno::EINVAL))?,
                    )?;
                    let user_rec = passwd
                        .iter()
                        .find(|u| u.uid == caller_identity.id)
                        .ok_or_else(|| Error::from(Errno::ENOENT))?;
                    store.authenticate(&snap, &user_rec.name, &password)?;
                }
            }
            host.state().borrow_mut().sudo_timestamps.insert(
                (caller_identity.id, caller_sid),
                now.saturating_add(SUDO_TTL_SECS),
            );

            // When invoked from a real process (e.g. `sudo` applet), elevate ONLY that
            // process's local identity to uid 0 while strictly preserving at most its existing
            // non-root remote cred (NEVER synthesizing remote root!).
            if !is_page {
                let existing_remote = {
                    let mut st = host.state().borrow_mut();
                    let proc = st
                        .table
                        .proc(pid)
                        .ok_or_else(|| Error::from(Errno::ESRCH))?;
                    let owner_host = proc.owner_host.clone();
                    let rem = proc.cred.remote.clone();
                    let _ = st.table.set_authenticated_cred(
                        &owner_host,
                        pid,
                        Identity::root(),
                        rem.clone(),
                    )?;
                    rem
                };
                let token = existing_remote.as_ref().map(|r| r.token.clone());
                let cloud_access = host
                    .state()
                    .borrow()
                    .table
                    .proc(pid)
                    .is_some_and(|p| p.cred.cloud_access);
                host.proc_set_creds_host(pid, 0, 0, vec![0], token, cloud_access);
            }
            Ok(json!({ "sudo_active": true }))
        }
        Call::Login {
            username,
            password,
            force,
        } => {
            // `force: true` skips password verification ONLY when the caller is already root
            // (`uid 0`) — e.g. `login -f`, root `su`, or elevated `sudo -u`.
            // When `force: false`, password & lock verification are ALWAYS enforced, even when
            // launched by UID 0 (ordinary root-launched `login`).
            if force && caller_identity.id != 0 {
                return Err(Error::because(
                    Errno::EPERM,
                    "only root may perform passwordless forced login",
                ));
            }
            let raw_pw = snap.read_file(PASSWD_PATH)?;
            let raw_gr = snap.read_file(GROUP_PATH)?;
            let passwd = parse_passwd(
                std::str::from_utf8(&raw_pw).map_err(|_| Error::from(Errno::EINVAL))?,
            )?;
            let groups =
                parse_group(std::str::from_utf8(&raw_gr).map_err(|_| Error::from(Errno::EINVAL))?)?;
            if !force {
                store.authenticate(&snap, &username, &password)?;
            }
            let target_rec = passwd
                .iter()
                .find(|u| u.name == username)
                .ok_or_else(|| Error::because(Errno::EACCES, "invalid username or password"))?;

            let (target_id, gid_vec, _) = identity_for_passwd(target_rec, &groups);
            let target_group = groups
                .iter()
                .find(|g| g.gid == target_rec.gid)
                .map(|g| g.name.clone())
                .unwrap_or_else(|| target_rec.gid.to_string());

            if is_page {
                let acc = LocalAccount {
                    uid: target_rec.uid,
                    gid: target_rec.gid,
                    groups: gid_vec.clone(),
                    user: target_rec.name.clone(),
                    group: target_group,
                    home: target_rec.home.clone(),
                    shell: target_rec.shell.clone(),
                    signed_in: true,
                };
                host.apply_account_update_host(acc);
            } else {
                // Process credential switch (`su` / `login` / `sudo -u`):
                // - Local escalation to uid 0 (`su root`): retain at most invoker's existing
                //   non-root remote cred (NEVER synthesize remote root!).
                // - Privilege drop (`root -> non-root`) or user switch (`uid_a -> uid_b`):
                //   clear ambient remote cred and immediately revoke dropped `ServiceAuth v2` tokens!
                let is_local_root_switch = caller_identity.id != 0 && target_id.id == 0;
                let (revoked, next_token, next_cloud) = {
                    let mut st = host.state().borrow_mut();
                    let proc = st
                        .table
                        .proc(pid)
                        .ok_or_else(|| Error::from(Errno::ESRCH))?;
                    let owner_host = proc.owner_host.clone();
                    let next_remote = if is_local_root_switch {
                        proc.cred.remote.clone()
                    } else {
                        None
                    };
                    let revoked = st.table.set_authenticated_cred(
                        &owner_host,
                        pid,
                        target_id.clone(),
                        next_remote.clone(),
                    )?;
                    let next_cloud = st.table.proc(pid).is_some_and(|p| p.cred.cloud_access);
                    (revoked, next_remote.map(|r| r.token), next_cloud)
                };
                revoke_remote_tokens_state(host.state(), revoked).await;
                host.proc_set_creds_host(
                    pid,
                    target_id.id,
                    target_id.group,
                    gid_vec.clone(),
                    next_token,
                    next_cloud,
                );
            }
            let post_sid = if is_page {
                page_sudo_sid_for_state(host.state())
            } else {
                caller_sid
            };
            let check = {
                let st = host.state().borrow();
                store.check_sudo_with_timestamps(
                    &snap,
                    target_id.id,
                    &gid_vec,
                    post_sid,
                    now,
                    &st.sudo_timestamps,
                )?
            };
            let can_sudo = !matches!(check, SudoCheck::Denied);
            let sudo_active = target_id.id == 0 || matches!(check, SudoCheck::AllowedNoPassword);
            let creds = build_creds_from_records(
                target_id.id,
                target_id.group,
                &gid_vec,
                &passwd,
                &groups,
                can_sudo,
                sudo_active,
            );
            Ok(json!(creds))
        }
        Call::Logout => {
            if !is_page {
                return Err(Error::because(
                    Errno::EPERM,
                    "a process cannot change the page's local session",
                ));
            }
            let default_user = host.default_user();
            // Propagate missing/renamed default user or parse errors cleanly — NEVER fall back
            // to a hardcoded UID 1000 `wheel` account!
            let next = resolve_local_user_account_vfs(vfs, &default_user)
                .await
                .map_err(Error::from)?;
            let (prev_uid, prev_epoch, prev_page_sid) = {
                let st = host.state().borrow();
                (
                    st.account.uid,
                    st.account_epoch,
                    page_sudo_sid_for_state(host.state()),
                )
            };
            host.state()
                .borrow_mut()
                .sudo_timestamps
                .retain(|&(u, s), _| u != prev_uid && s != prev_page_sid);
            host.apply_account_update_host(next.clone());
            // Guarantee that logout ALWAYS advances `account_epoch` and `session_seq` (even
            // when logging out from the configured default user back to itself) so prior
            // `CloudSession` bindings and page sudo sessions are invalidated immediately.
            {
                let mut st = host.state().borrow_mut();
                if st.account_epoch == prev_epoch {
                    st.account_epoch = st.account_epoch.saturating_add(1);
                    st.session_seq = st.session_seq.saturating_add(1);
                    let sid = format!("{}:s{}", st.instance_id, st.session_seq);
                    let uid = st.account.uid;
                    let profile = st.login_profiles.get(&uid).cloned();
                    let mut session = kernel::login::Session::new(sid, uid, now + 86_400, now);
                    if let Some(p) = profile {
                        session.startup = Some(kernel::startup::Startup::new(p));
                    }
                    st.login_session = session;
                }
            }
            Ok(json!({
                "username": next.user,
                "home": next.home,
                "uid": next.uid,
                "gid": next.gid,
            }))
        }
        Call::Passwd {
            username,
            password,
            current_password,
            force,
        } => {
            let raw_pw = snap.read_file(PASSWD_PATH)?;
            let passwd = parse_passwd(
                std::str::from_utf8(&raw_pw).map_err(|_| Error::from(Errno::EINVAL))?,
            )?;
            let (target, target_uid) = match username {
                Some(name) if !name.is_empty() => {
                    let uid = passwd
                        .iter()
                        .find(|u| u.name == name)
                        .map(|u| u.uid)
                        .ok_or_else(|| {
                            Error::because(Errno::ENOENT, format!("no such user: {name}"))
                        })?;
                    (name, uid)
                }
                _ => {
                    let rec = passwd
                        .iter()
                        .find(|u| u.uid == caller_identity.id)
                        .ok_or_else(|| Error::from(Errno::ENOENT))?;
                    (rec.name.clone(), rec.uid)
                }
            };
            store.passwd(
                &mut snap,
                &caller_identity,
                Some(&target),
                current_password.as_deref(),
                &password,
                force,
                random_salt(),
            )?;
            snap.flush(vfs).await?;
            host.state()
                .borrow_mut()
                .sudo_timestamps
                .retain(|&(u, _), _| u != target_uid);
            host.commit_root_cowfs_host().await?;
            Ok(json!({ "output": format!("Password updated for {target}") }))
        }
        Call::Useradd {
            name,
            create_home,
            home,
            group,
            groups,
            password,
            short_password,
        } => {
            let extra_groups: Vec<String> = groups
                .as_deref()
                .map(|s| {
                    s.split(',')
                        .map(str::trim)
                        .filter(|g| !g.is_empty())
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            let rec = store.useradd(
                &mut snap,
                &caller_identity,
                UseraddReq {
                    name: name.clone(),
                    uid: None,
                    group,
                    groups: extra_groups,
                    gecos: None,
                    home,
                    shell: None,
                    create_home,
                    password,
                    short_password,
                },
                random_salt(),
            )?;
            snap.flush(vfs).await?;
            host.commit_root_cowfs_host().await?;
            host.refresh_caches_host(vfs).await;
            Ok(json!({
                "message": format!("created user {} (uid {})", rec.name, rec.uid),
                "uid": rec.uid,
                "gid": rec.gid,
                "home": rec.home,
            }))
        }
        Call::Usermod {
            name,
            append,
            groups,
            group,
            home,
            move_home,
            rename,
            lock,
            unlock,
        } => {
            let parsed_groups: Option<Vec<String>> = groups.as_deref().map(|s| {
                s.split(',')
                    .map(str::trim)
                    .filter(|g| !g.is_empty())
                    .map(str::to_owned)
                    .collect()
            });
            let updated = store.usermod(
                &mut snap,
                &caller_identity,
                UsermodReq {
                    name: name.clone(),
                    rename,
                    group,
                    groups: parsed_groups,
                    append,
                    gecos: None,
                    home,
                    move_home,
                    shell: None,
                    lock,
                    unlock,
                },
            )?;
            snap.flush(vfs).await?;
            if lock {
                host.state()
                    .borrow_mut()
                    .sudo_timestamps
                    .retain(|&(u, _), _| u != updated.uid);
            }
            host.commit_root_cowfs_host().await?;
            host.refresh_caches_host(vfs).await;
            Ok(json!({ "message": format!("updated user {name}") }))
        }
        Call::Userdel { name, remove, .. } => {
            let deleted_uid = store.resolve_user(&snap, &name).ok().map(|id| id.id);
            store.userdel(&mut snap, &caller_identity, &name, remove)?;
            snap.flush(vfs).await?;
            if let Some(uid) = deleted_uid {
                host.state()
                    .borrow_mut()
                    .sudo_timestamps
                    .retain(|&(u, _), _| u != uid);
            }
            host.commit_root_cowfs_host().await?;
            host.refresh_caches_host(vfs).await;
            Ok(json!({ "message": format!("deleted user {name}") }))
        }
        Call::Groupadd { name } => {
            let rec = store.groupadd(&mut snap, &caller_identity, &name)?;
            snap.flush(vfs).await?;
            host.commit_root_cowfs_host().await?;
            host.refresh_caches_host(vfs).await;
            Ok(json!({ "message": format!("created group {} (gid {})", rec.name, rec.gid) }))
        }
        Call::Groupmod { name, new_name } => {
            store.groupmod(&mut snap, &caller_identity, &name, &new_name)?;
            snap.flush(vfs).await?;
            host.commit_root_cowfs_host().await?;
            host.refresh_caches_host(vfs).await;
            Ok(json!({ "message": format!("renamed group {name} to {new_name}") }))
        }
        Call::Groupdel { name } => {
            store.groupdel(&mut snap, &caller_identity, &name)?;
            snap.flush(vfs).await?;
            host.commit_root_cowfs_host().await?;
            host.refresh_caches_host(vfs).await;
            Ok(json!({ "message": format!("deleted group {name}") }))
        }
        _ => Err(Error::from(Errno::ENOSYS)),
    }
}

impl Kernel {
    /// Commit the mounted root `CowFs` transaction group if active, propagating any durability
    /// failure instead of acknowledging an uncommitted account mutation.
    pub(crate) async fn commit_root_cowfs_if_mounted(&self) -> Result<(), Error> {
        let cowfs = self.vfs_rt.borrow().root_cowfs.clone();
        if let Some(fs) = cowfs {
            fs.commit_tx_group().await.map_err(Error::from)?;
        }
        Ok(())
    }

    /// Stable non-zero session key for the active page login session, derived from
    /// `state.session_seq` (which increments on every login/logout/account switch) with the high
    /// bit set so page login sessions NEVER collide with real process `proc.sid` values.
    pub(crate) fn page_sudo_sid(&self) -> u32 {
        page_sudo_sid_for_state(&self.state)
    }

    /// Refresh cached `uid_names` and `gid_names` strictly from local `/etc/passwd` + `/etc/group`.
    pub(crate) async fn refresh_local_account_caches(&self, vfs: &Vfs) {
        let mut uids =
            HashMap::from([(0u32, "root".to_string()), (65534u32, "nobody".to_string())]);
        let mut gids = HashMap::from([
            (0u32, "root".to_string()),
            (10u32, "wheel".to_string()),
            (65534u32, "nogroup".to_string()),
        ]);
        if let Ok(raw) = read_vfs_file_as_root(vfs, PASSWD_PATH).await
            && let Ok(text) = std::str::from_utf8(&raw)
            && let Ok(records) = parse_passwd(text)
        {
            for r in records {
                uids.insert(r.uid, r.name);
            }
        }
        if let Ok(raw) = read_vfs_file_as_root(vfs, GROUP_PATH).await
            && let Ok(text) = std::str::from_utf8(&raw)
            && let Ok(records) = parse_group(text)
        {
            for r in records {
                gids.insert(r.gid, r.name);
            }
        }
        let mut rt = self.vfs_rt.borrow_mut();
        rt.uid_names = uids;
        rt.gid_names = gids;
    }

    /// Look up a local user by username or numeric UID string from local `/etc/passwd` + `/etc/group`.
    /// Never synthesizes a fallback UID 1000 identity when the user is absent or files fail to parse.
    pub(crate) async fn resolve_local_user_account(
        &self,
        vfs: &Vfs,
        user_spec: &str,
    ) -> Result<LocalAccount, Errno> {
        resolve_local_user_account_vfs(vfs, user_spec).await
    }

    /// Authoritative local `(uid, sid)` sudoers + timestamp evaluator returning
    /// `(can_sudo, sudo_active)`. Shared by `Getcreds`, `Call::Sudo`, and page sudo authorization.
    /// ZERO network RPCs!
    pub(crate) async fn check_local_sudo_for_sid(
        &self,
        vfs: &Vfs,
        uid: u32,
        sid: u32,
    ) -> Result<(bool, bool), Errno> {
        check_local_sudo_for_sid_on(self, vfs, uid, sid).await
    }

    /// Check whether local `uid` is authorized for page-scoped local `sudo` (via local
    /// `/etc/sudoers` `NOPASSWD` or an active `(uid, page_sudo_sid)` timestamp). ZERO network RPCs!
    pub(crate) async fn check_local_sudo_authorized(
        &self,
        vfs: &Vfs,
        uid: u32,
    ) -> Result<bool, Errno> {
        let sid = self.page_sudo_sid();
        let (_, sudo_active) = self.check_local_sudo_for_sid(vfs, uid, sid).await?;
        Ok(sudo_active)
    }

    /// Check if `uid` is a member of `target_gid` (or is `uid 0`) in local `/etc/{passwd,group}`.
    pub(crate) async fn verify_local_group_membership(
        &self,
        vfs: &Vfs,
        uid: u32,
        target_gid: u32,
    ) -> Result<bool, Errno> {
        if uid == 0 {
            return Ok(true);
        }
        let raw_pw = read_vfs_file_as_root(vfs, PASSWD_PATH).await?;
        let raw_gr = read_vfs_file_as_root(vfs, GROUP_PATH).await?;
        let passwd = parse_passwd(std::str::from_utf8(&raw_pw).map_err(|_| Errno::EINVAL)?)
            .map_err(|e| e.errno)?;
        let groups = parse_group(std::str::from_utf8(&raw_gr).map_err(|_| Errno::EINVAL)?)
            .map_err(|e| e.errno)?;
        let Some(rec) = passwd.iter().find(|u| u.uid == uid) else {
            return Ok(false);
        };
        if rec.gid == target_gid {
            return Ok(true);
        }
        Ok(groups
            .iter()
            .find(|g| g.gid == target_gid)
            .is_some_and(|g| g.members.iter().any(|m| m == &rec.name)))
    }

    /// Evaluate any of the 11 local OS account calls (`Getcreds`, `Login`, `Logout`, `Sudo`,
    /// `Passwd`, `Useradd`, `Usermod`, `Userdel`, `Groupadd`, `Groupmod`, `Groupdel`) 100% locally
    /// on local `/` (`os-cowfs` / Stage 1 `tmpfs`) with ZERO network RPCs!
    pub(crate) async fn eval_local_account_call(
        &self,
        vfs: &Vfs,
        pid: u32,
        page_sid: Option<&str>,
        page_sudo: bool,
        call: Call,
    ) -> Result<Value, Error> {
        eval_local_account_call_on(self, vfs, pid, page_sid, page_sudo, call).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloudfs::{CloudMountDriver, Connector};
    use crate::{AccountAsyncLock, CloudSession, State};
    use abi::auth_v2::RemoteScope;
    use abi::contract::{FsCapabilities, InstanceIdentity};
    use cowfs::{CowFs, CowFsConfig, CowFsOpenMode};
    use cowtree::pack::decode_pack_trailer;
    use cowtree::{
        BlockLoc, COWFS_FORMAT_VERSION, CommitRequest, Digest, ForkRequest, GcLockGuard, GcRoot,
        HeadStore, PackId, PackMeta, PackStore, PackTrailer, RoPinGuard, SnapshotRecord,
        VolumeHead, VolumeId, WriterLease, WriterLockGuard, WriterMode,
    };
    use futures_util::future::join;
    use kernel::init::Init;
    use kernel::login::Session as LoginSession;
    use kernel::proc_table::{LocalCred, LocalProcessTable, SpawnSpec};
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::future::Future;
    use std::pin::Pin;
    use std::rc::Rc;
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use vfs::{
        BoxFuture, Conflict, DefaultFilesystemFactory, DirEntry, Entry, FsId, FsType, Handle,
        LockFamily, LockKind, LockRange, Metadata, MountBacking, MountFlags, OpenRef, StatFs,
        Timespec, Walked, Written, XattrFlags,
    };

    fn test_clock() -> (u64, u32) {
        (1_700_000_000, 0)
    }

    fn new_memfs(id: &str) -> MemFs {
        MemFs::new(FsId(id.to_string()), 1, 0, 0, 0o755, Box::new(test_clock))
    }

    fn block_on<F: Future>(fut: F) -> F::Output {
        unsafe fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VTABLE)
        }
        unsafe fn wake(_: *const ()) {}
        unsafe fn wake_by_ref(_: *const ()) {}
        unsafe fn drop(_: *const ()) {}
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
        let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
        let mut cx = Context::from_waker(&waker);
        let mut fut = std::pin::pin!(fut);
        loop {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    /// Yield once to the executor so concurrent futures genuinely interleave across `.await` points.
    struct YieldOnce(bool);
    impl Future for YieldOnce {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.0 {
                Poll::Ready(())
            } else {
                self.0 = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    /// Fault-injecting `Filesystem` wrapper around `MemFs` for testing real-VFS error propagation,
    /// mid-batch staging/rename rollback, and concurrent mutation serialization.
    struct FaultyFs {
        inner: MemFs,
        fail_open_name: RefCell<Option<(String, Errno)>>,
        fail_create_after: Cell<Option<usize>>,
        create_count: Cell<usize>,
        fail_rename_after: Cell<Option<usize>>,
        rename_count: Cell<usize>,
        yield_on_open: Cell<bool>,
    }

    impl FaultyFs {
        fn new() -> Self {
            Self {
                inner: new_memfs("faulty-root"),
                fail_open_name: RefCell::new(None),
                fail_create_after: Cell::new(None),
                create_count: Cell::new(0),
                fail_rename_after: Cell::new(None),
                rename_count: Cell::new(0),
                yield_on_open: Cell::new(false),
            }
        }
    }

    impl Filesystem for FaultyFs {
        fn id(&self) -> &FsId {
            self.inner.id()
        }
        fn capabilities(&self) -> FsCapabilities {
            self.inner.capabilities()
        }
        fn root(&self) -> Handle {
            self.inner.root()
        }
        fn lookup<'a>(
            &'a self,
            cred: &'a Cred,
            dir: &'a Handle,
            name: &'a str,
        ) -> BoxFuture<'a, Entry> {
            Box::pin(async move {
                if self.yield_on_open.get() {
                    YieldOnce(false).await;
                }
                if let Some((ref target, err)) = *self.fail_open_name.borrow()
                    && name == target
                {
                    return Err(err);
                }
                self.inner.lookup(cred, dir, name).await
            })
        }
        fn walk<'a>(
            &'a self,
            cred: &'a Cred,
            dir: &'a Handle,
            names: &'a [String],
        ) -> BoxFuture<'a, Walked> {
            Box::pin(async move {
                if self.yield_on_open.get() {
                    YieldOnce(false).await;
                }
                if let Some((ref target, err)) = *self.fail_open_name.borrow()
                    && names.iter().any(|n| n == target)
                {
                    return Err(err);
                }
                self.inner.walk(cred, dir, names).await
            })
        }
        fn parent<'a>(
            &'a self,
            cred: &'a Cred,
            dir: &'a Handle,
        ) -> BoxFuture<'a, Option<(Entry, String)>> {
            self.inner.parent(cred, dir)
        }
        fn metadata<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Metadata> {
            self.inner.metadata(cred, handle)
        }
        fn setattr<'a>(
            &'a self,
            cred: &'a Cred,
            handle: &'a Handle,
            attr: &'a SetAttr,
        ) -> BoxFuture<'a, Metadata> {
            self.inner.setattr(cred, handle, attr)
        }
        fn read_dir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle) -> BoxFuture<'a, Vec<DirEntry>> {
            self.inner.read_dir(cred, dir)
        }
        fn read_link<'a>(&'a self, cred: &'a Cred, link: &'a Handle) -> BoxFuture<'a, String> {
            self.inner.read_link(cred, link)
        }
        fn create<'a>(
            &'a self,
            cred: &'a Cred,
            dir: &'a Handle,
            name: &'a str,
            mode: u16,
            options: &'a OpenOptions,
        ) -> BoxFuture<'a, (Entry, OpenRef)> {
            Box::pin(async move {
                if let Some(limit) = self.fail_create_after.get() {
                    let cur = self.create_count.get();
                    self.create_count.set(cur + 1);
                    if cur >= limit {
                        return Err(Errno::EIO);
                    }
                }
                self.inner.create(cred, dir, name, mode, options).await
            })
        }
        fn mkdir<'a>(
            &'a self,
            cred: &'a Cred,
            dir: &'a Handle,
            name: &'a str,
            mode: u16,
        ) -> BoxFuture<'a, Entry> {
            self.inner.mkdir(cred, dir, name, mode)
        }
        fn mknod<'a>(
            &'a self,
            cred: &'a Cred,
            dir: &'a Handle,
            name: &'a str,
            mode: u16,
            rdev: &'a str,
        ) -> BoxFuture<'a, Entry> {
            self.inner.mknod(cred, dir, name, mode, rdev)
        }
        fn symlink<'a>(
            &'a self,
            cred: &'a Cred,
            dir: &'a Handle,
            name: &'a str,
            target: &'a str,
        ) -> BoxFuture<'a, Entry> {
            self.inner.symlink(cred, dir, name, target)
        }
        fn link<'a>(
            &'a self,
            cred: &'a Cred,
            target: &'a Handle,
            dir: &'a Handle,
            name: &'a str,
        ) -> BoxFuture<'a, Entry> {
            self.inner.link(cred, target, dir, name)
        }
        fn unlink<'a>(
            &'a self,
            cred: &'a Cred,
            dir: &'a Handle,
            name: &'a str,
        ) -> BoxFuture<'a, ()> {
            self.inner.unlink(cred, dir, name)
        }
        fn rmdir<'a>(
            &'a self,
            cred: &'a Cred,
            dir: &'a Handle,
            name: &'a str,
        ) -> BoxFuture<'a, ()> {
            self.inner.rmdir(cred, dir, name)
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
            Box::pin(async move {
                if let Some(limit) = self.fail_rename_after.get()
                    && !from.contains(".rollback.")
                {
                    let cur = self.rename_count.get();
                    self.rename_count.set(cur + 1);
                    if cur >= limit {
                        return Err(Errno::EIO);
                    }
                }
                self.inner
                    .rename(cred, from_dir, from, to_dir, to, flags)
                    .await
            })
        }
        fn getxattr<'a>(
            &'a self,
            cred: &'a Cred,
            handle: &'a Handle,
            name: &'a str,
        ) -> BoxFuture<'a, Vec<u8>> {
            self.inner.getxattr(cred, handle, name)
        }
        fn setxattr<'a>(
            &'a self,
            cred: &'a Cred,
            handle: &'a Handle,
            name: &'a str,
            value: &'a [u8],
            flags: XattrFlags,
        ) -> BoxFuture<'a, ()> {
            self.inner.setxattr(cred, handle, name, value, flags)
        }
        fn listxattr<'a>(
            &'a self,
            cred: &'a Cred,
            handle: &'a Handle,
        ) -> BoxFuture<'a, Vec<String>> {
            self.inner.listxattr(cred, handle)
        }
        fn removexattr<'a>(
            &'a self,
            cred: &'a Cred,
            handle: &'a Handle,
            name: &'a str,
        ) -> BoxFuture<'a, ()> {
            self.inner.removexattr(cred, handle, name)
        }
        fn statfs<'a>(&'a self, cred: &'a Cred) -> BoxFuture<'a, StatFs> {
            self.inner.statfs(cred)
        }
        fn open<'a>(
            &'a self,
            cred: &'a Cred,
            handle: &'a Handle,
            options: &'a OpenOptions,
        ) -> BoxFuture<'a, OpenRef> {
            self.inner.open(cred, handle, options)
        }
        fn open_metadata<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, Metadata> {
            self.inner.open_metadata(open)
        }
        fn read_at<'a>(
            &'a self,
            open: &'a OpenRef,
            buf: &'a mut [u8],
            offset: u64,
        ) -> BoxFuture<'a, usize> {
            self.inner.read_at(open, buf, offset)
        }
        fn write_at<'a>(
            &'a self,
            open: &'a OpenRef,
            buf: &'a [u8],
            at: WriteAt,
        ) -> BoxFuture<'a, Written> {
            self.inner.write_at(open, buf, at)
        }
        fn set_len<'a>(&'a self, open: &'a OpenRef, size: u64) -> BoxFuture<'a, ()> {
            self.inner.set_len(open, size)
        }
        fn sync_all<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
            self.inner.sync_all(open)
        }
        fn sync_data<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
            self.inner.sync_data(open)
        }
        fn lock<'a>(
            &'a self,
            open: &'a OpenRef,
            family: LockFamily,
            kind: LockKind,
            range: LockRange,
        ) -> BoxFuture<'a, ()> {
            self.inner.lock(open, family, kind, range)
        }
        fn try_lock<'a>(
            &'a self,
            open: &'a OpenRef,
            family: LockFamily,
            kind: LockKind,
            range: LockRange,
        ) -> BoxFuture<'a, ()> {
            self.inner.try_lock(open, family, kind, range)
        }
        fn unlock<'a>(
            &'a self,
            open: &'a OpenRef,
            family: LockFamily,
            range: LockRange,
        ) -> BoxFuture<'a, ()> {
            self.inner.unlock(open, family, range)
        }
        fn test_lock<'a>(
            &'a self,
            open: &'a OpenRef,
            kind: LockKind,
            range: LockRange,
        ) -> BoxFuture<'a, Option<Conflict>> {
            self.inner.test_lock(open, kind, range)
        }
        fn release<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
            self.inner.release(open)
        }
    }

    async fn seeded_faulty_vfs() -> (Rc<FaultyFs>, Vfs) {
        let fs = Rc::new(FaultyFs::new());
        seed_local_stage1_memfs(&fs.inner)
            .await
            .expect("seed stage1 memfs");
        let backing = Rc::new(MountBacking::new(
            fs.clone() as Rc<dyn Filesystem>,
            FsType::TmpFs,
        ));
        let factory = Rc::new(DefaultFilesystemFactory::new(Rc::new(test_clock)));
        let vfs = Vfs::boot("test-inst", backing, "tmpfs", factory)
            .await
            .expect("boot test vfs");
        (fs, vfs)
    }

    struct TestAccountHost {
        state: Rc<RefCell<State>>,
        account_lock: Rc<AccountAsyncLock>,
        cloud_mount: Rc<CloudMountDriver>,
        root_cowfs: Option<Rc<CowFs<FailingCommitHeadStore, TestCowPackStore>>>,
    }

    impl TestAccountHost {
        fn new(id: &str) -> Self {
            let now = now_secs();
            let mut table = LocalProcessTable::new(
                InstanceIdentity {
                    instance: id.into(),
                    host: "browser".into(),
                },
                now,
            );
            let _ = table.boot_init("boot", now);
            let account = LocalAccount::default();
            let state = Rc::new(RefCell::new(State {
                instance_id: id.into(),
                host_proof: "proof".into(),
                boot: "boot-1".into(),
                namespace: id.into(),
                table,
                account: account.clone(),
                account_epoch: 1,
                proc_account_epoch: HashMap::new(),
                cloud_session: None,
                sudo_timestamps: BTreeMap::new(),
                remote_attached: false,
                host_epoch: 0,
                pending_revocations: Vec::new(),
                volume_tokens: Default::default(),
                pending_detach: false,
                attached_devices: BTreeMap::new(),
                init_state: Init::new("boot-1".into(), now),
                login_session: LoginSession::new(
                    format!("{id}:s1"),
                    account.uid,
                    now + 86_400,
                    now,
                ),
                login_profiles: BTreeMap::new(),
                seat_policies: BTreeMap::new(),
                boot_seq: 1,
                session_seq: 1,
            }));
            let cloud_mount = Rc::new(CloudMountDriver::new(
                Rc::clone(&state),
                Rc::default(),
                Connector::default(),
                Rc::new(Cell::new(None)),
                Rc::new(Cell::new(false)),
            ));
            Self {
                state,
                account_lock: AccountAsyncLock::new(),
                cloud_mount,
                root_cowfs: None,
            }
        }

        async fn eval_local_account_call(
            &self,
            vfs: &Vfs,
            pid: u32,
            page_sid: Option<&str>,
            page_sudo: bool,
            call: Call,
        ) -> Result<Value, Error> {
            eval_local_account_call_on(self, vfs, pid, page_sid, page_sudo, call).await
        }

        async fn check_local_sudo_for_sid(
            &self,
            vfs: &Vfs,
            uid: u32,
            sid: u32,
        ) -> Result<(bool, bool), Errno> {
            check_local_sudo_for_sid_on(self, vfs, uid, sid).await
        }

        async fn check_local_sudo_authorized(&self, vfs: &Vfs, uid: u32) -> Result<bool, Errno> {
            let sid = page_sudo_sid_for_state(&self.state);
            let (_, sudo_active) = check_local_sudo_for_sid_on(self, vfs, uid, sid).await?;
            Ok(sudo_active)
        }

        async fn resolve_local_user_account(
            &self,
            vfs: &Vfs,
            user_spec: &str,
        ) -> Result<LocalAccount, Errno> {
            resolve_local_user_account_vfs(vfs, user_spec).await
        }
    }

    impl LocalAccountHost for TestAccountHost {
        fn state(&self) -> &Rc<RefCell<State>> {
            &self.state
        }
        fn account_lock(&self) -> &Rc<AccountAsyncLock> {
            &self.account_lock
        }
        fn default_user(&self) -> String {
            "user".into()
        }
        fn apply_account_update_host(&self, account: LocalAccount) {
            self.state.borrow_mut().sync_account(account);
        }
        fn proc_set_creds_host(
            &self,
            _pid: u32,
            _uid: u32,
            _gid: u32,
            _groups: Vec<u32>,
            _token: Option<String>,
            _cloud_access: bool,
        ) {
        }
        fn commit_root_cowfs_host<'a>(
            &'a self,
        ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + 'a>> {
            Box::pin(async move {
                if let Some(fs) = &self.root_cowfs {
                    fs.commit_tx_group().await.map_err(Error::from)?;
                }
                Ok(())
            })
        }
        fn refresh_caches_host<'a>(
            &'a self,
            _vfs: &'a Vfs,
        ) -> Pin<Box<dyn Future<Output = ()> + 'a>> {
            Box::pin(async {})
        }
    }

    fn spawn_proc(host: &TestAccountHost, id: Identity, sid: u32) -> u32 {
        let mut st = host.state.borrow_mut();
        let mut spec = SpawnSpec::new("/bin/sh", LocalCred::local_only(id, 0o022), "browser");
        spec.sid = Some(sid);
        st.table.spawn(spec, now_secs()).expect("spawn proc").pid
    }

    #[test]
    fn finding_3_login_force_requires_root_and_non_force_always_authenticates_even_as_root() {
        block_on(async {
            let (_fs, vfs) = seeded_faulty_vfs().await;
            let kernel = TestAccountHost::new("inst-f3");
            let root_pid = spawn_proc(&kernel, Identity::root(), 10);
            let user_id = kernel.state.borrow().account.identity();
            let user_pid = spawn_proc(&kernel, user_id, 20);

            // Create `alice` with password and `lockedbob` (locked `!`).
            kernel
                .eval_local_account_call(
                    &vfs,
                    root_pid,
                    None,
                    false,
                    Call::Useradd {
                        name: "alice".into(),
                        create_home: true,
                        home: None,
                        group: None,
                        groups: None,
                        password: Some("alice-secret-password".into()),
                        short_password: false,
                    },
                )
                .await
                .unwrap();
            kernel
                .eval_local_account_call(
                    &vfs,
                    root_pid,
                    None,
                    false,
                    Call::Useradd {
                        name: "lockedbob".into(),
                        create_home: false,
                        home: None,
                        group: None,
                        groups: None,
                        password: None,
                        short_password: false,
                    },
                )
                .await
                .unwrap();

            // Non-root with `force: true` MUST fail closed with EPERM!
            let err = kernel
                .eval_local_account_call(
                    &vfs,
                    user_pid,
                    None,
                    false,
                    Call::Login {
                        username: "root".into(),
                        password: String::new(),
                        force: true,
                    },
                )
                .await
                .unwrap_err();
            assert_eq!(err.errno, Errno::EPERM);

            // Root with `force: false` + WRONG password MUST fail with EACCES!
            let err = kernel
                .eval_local_account_call(
                    &vfs,
                    root_pid,
                    None,
                    false,
                    Call::Login {
                        username: "alice".into(),
                        password: "wrong-password".into(),
                        force: false,
                    },
                )
                .await
                .unwrap_err();
            assert_eq!(err.errno, Errno::EACCES);

            // Root with `force: false` on a LOCKED account (`lockedbob` / `root`) MUST fail with EACCES!
            for locked in ["lockedbob", "root"] {
                let err = kernel
                    .eval_local_account_call(
                        &vfs,
                        root_pid,
                        None,
                        false,
                        Call::Login {
                            username: locked.into(),
                            password: "anything".into(),
                            force: false,
                        },
                    )
                    .await
                    .unwrap_err();
                assert_eq!(
                    err.errno,
                    Errno::EACCES,
                    "locked account {locked} admitted!"
                );
            }

            // Root with `force: false` + CORRECT password succeeds!
            let ok_pid = spawn_proc(&kernel, Identity::root(), 30);
            let res = kernel
                .eval_local_account_call(
                    &vfs,
                    ok_pid,
                    None,
                    false,
                    Call::Login {
                        username: "alice".into(),
                        password: "alice-secret-password".into(),
                        force: false,
                    },
                )
                .await
                .unwrap();
            assert_eq!(res["user"], "alice");

            // Root with `force: true` (e.g. `login -f` / root `su`) skips password even for locked account.
            let force_pid = spawn_proc(&kernel, Identity::root(), 40);
            let res = kernel
                .eval_local_account_call(
                    &vfs,
                    force_pid,
                    None,
                    false,
                    Call::Login {
                        username: "lockedbob".into(),
                        password: String::new(),
                        force: true,
                    },
                )
                .await
                .unwrap();
            assert_eq!(res["user"], "lockedbob");
        });
    }

    #[test]
    fn finding_4_transient_read_error_and_missing_passwd_never_reseed_or_overwrite_etc() {
        block_on(async {
            let (fs, vfs) = seeded_faulty_vfs().await;
            let kernel = TestAccountHost::new("inst-f4");
            let root_pid = spawn_proc(&kernel, Identity::root(), 10);

            // Customize `/etc/group` and `/etc/sudoers` so any overwrite is immediately detected.
            let custom_group = b"root:x:0:\nwheel:x:10:user\nuser:x:1000:\ncustomgrp:x:2222:user\n";
            let custom_sudoers = b"root ALL=(ALL:ALL) ALL\n%customgrp ALL=(ALL:ALL) ALL\n";
            write_vfs_file_as_root(&vfs, GROUP_PATH, custom_group, GROUP_MODE, 0, 0)
                .await
                .unwrap();
            write_vfs_file_as_root(&vfs, SUDOERS_PATH, custom_sudoers, SUDOERS_MODE, 0, 0)
                .await
                .unwrap();

            // 1. Transient EIO reading `/etc/passwd` MUST propagate as EIO, leaving `/etc/*` intact.
            *fs.fail_open_name.borrow_mut() = Some(("passwd".into(), Errno::EIO));
            let err = kernel
                .eval_local_account_call(
                    &vfs,
                    root_pid,
                    None,
                    false,
                    Call::Groupadd { name: "ops".into() },
                )
                .await
                .unwrap_err();
            assert_eq!(err.errno, Errno::EIO);
            *fs.fail_open_name.borrow_mut() = None;
            assert_eq!(
                read_vfs_file_as_root(&vfs, GROUP_PATH).await.unwrap(),
                custom_group
            );
            assert_eq!(
                read_vfs_file_as_root(&vfs, SUDOERS_PATH).await.unwrap(),
                custom_sudoers
            );

            // 2. Missing `/etc/passwd` on a live volume MUST fail closed with ENOENT without seeding!
            vfs.unlinkat(INIT, StartAnchor::Root, PASSWD_PATH, false)
                .await
                .unwrap();
            let err = kernel
                .eval_local_account_call(
                    &vfs,
                    root_pid,
                    None,
                    false,
                    Call::Groupadd { name: "ops".into() },
                )
                .await
                .unwrap_err();
            assert_eq!(err.errno, Errno::ENOENT);
            assert_eq!(
                read_vfs_file_as_root(&vfs, PASSWD_PATH).await.unwrap_err(),
                Errno::ENOENT
            );
            assert_eq!(
                read_vfs_file_as_root(&vfs, GROUP_PATH).await.unwrap(),
                custom_group
            );
            assert_eq!(
                read_vfs_file_as_root(&vfs, SUDOERS_PATH).await.unwrap(),
                custom_sudoers
            );
        });
    }

    #[test]
    fn finding_5_userdel_validates_symlink_owner_mountpoint_and_respects_submount_boundaries() {
        block_on(async {
            let (_fs, vfs) = seeded_faulty_vfs().await;
            let kernel = TestAccountHost::new("inst-f5");
            let root_pid = spawn_proc(&kernel, Identity::root(), 10);

            // 1. Symlink home (`/home/symuser -> /etc`) rejected with ENOTDIR BEFORE editing `/etc/passwd`.
            vfs.symlinkat(INIT, "/etc", StartAnchor::Root, "/home/symuser")
                .await
                .unwrap();
            kernel
                .eval_local_account_call(
                    &vfs,
                    root_pid,
                    None,
                    false,
                    Call::Useradd {
                        name: "symuser".into(),
                        create_home: false,
                        home: Some("/home/symuser".into()),
                        group: None,
                        groups: None,
                        password: None,
                        short_password: false,
                    },
                )
                .await
                .unwrap();
            let pw_before = read_vfs_file_as_root(&vfs, PASSWD_PATH).await.unwrap();
            let err = kernel
                .eval_local_account_call(
                    &vfs,
                    root_pid,
                    None,
                    false,
                    Call::Userdel {
                        name: "symuser".into(),
                        remove: true,
                        password: None,
                    },
                )
                .await
                .unwrap_err();
            assert_eq!(err.errno, Errno::ENOTDIR);
            assert_eq!(
                read_vfs_file_as_root(&vfs, PASSWD_PATH).await.unwrap(),
                pw_before
            );
            assert!(
                vfs.statat(INIT, StartAnchor::Root, "/etc/passwd", false)
                    .await
                    .is_ok()
            );

            // 2. Wrong-owner home (`/home/foreign` owned by uid 1000) rejected with EPERM.
            vfs.mkdirat(INIT, StartAnchor::Root, "/home/foreign", 0o750)
                .await
                .unwrap();
            vfs.setattrat(
                INIT,
                StartAnchor::Root,
                "/home/foreign",
                &SetAttr {
                    uid: Some(1000),
                    gid: Some(1000),
                    ..SetAttr::default()
                },
                false,
            )
            .await
            .unwrap();
            kernel
                .eval_local_account_call(
                    &vfs,
                    root_pid,
                    None,
                    false,
                    Call::Useradd {
                        name: "foreignuser".into(),
                        create_home: false,
                        home: Some("/home/foreign".into()),
                        group: None,
                        groups: None,
                        password: None,
                        short_password: false,
                    },
                )
                .await
                .unwrap();
            let pw_before = read_vfs_file_as_root(&vfs, PASSWD_PATH).await.unwrap();
            let err = kernel
                .eval_local_account_call(
                    &vfs,
                    root_pid,
                    None,
                    false,
                    Call::Userdel {
                        name: "foreignuser".into(),
                        remove: true,
                        password: None,
                    },
                )
                .await
                .unwrap_err();
            assert_eq!(err.errno, Errno::EPERM);
            assert_eq!(
                read_vfs_file_as_root(&vfs, PASSWD_PATH).await.unwrap(),
                pw_before
            );

            // 3. Mountpoint home (`/home/mntuser` mounted with a distinct filesystem -> different st.dev).
            let mnt_res = kernel
                .eval_local_account_call(
                    &vfs,
                    root_pid,
                    None,
                    false,
                    Call::Useradd {
                        name: "mntuser".into(),
                        create_home: true,
                        home: Some("/home/mntuser".into()),
                        group: None,
                        groups: None,
                        password: None,
                        short_password: false,
                    },
                )
                .await
                .unwrap();
            let mnt_uid = mnt_res["uid"].as_u64().unwrap() as u32;
            let mounted_fs = Rc::new(new_memfs("mounted-home"));
            // Even if the mounted root is owned by `mnt_uid`, st.dev != parent_dev MUST fail with EXDEV!
            let _ = mounted_fs
                .setattr(
                    &Cred::root(),
                    &mounted_fs.root(),
                    &SetAttr {
                        uid: Some(mnt_uid),
                        gid: Some(mnt_uid),
                        ..SetAttr::default()
                    },
                )
                .await;
            vfs.mount_on_namespace(
                &vfs.system_namespace(),
                &Cred::root(),
                Rc::new(MountBacking::new(
                    mounted_fs as Rc<dyn Filesystem>,
                    FsType::TmpFs,
                )),
                None,
                "tmpfs",
                "/home/mntuser",
                MountFlags::from_accepted(0),
                0,
                None,
            )
            .await
            .unwrap();
            write_vfs_file_as_root(
                &vfs,
                "/home/mntuser/keep.txt",
                b"precious",
                0o644,
                mnt_uid,
                mnt_uid,
            )
            .await
            .unwrap();
            let pw_before = read_vfs_file_as_root(&vfs, PASSWD_PATH).await.unwrap();
            let err = kernel
                .eval_local_account_call(
                    &vfs,
                    root_pid,
                    None,
                    false,
                    Call::Userdel {
                        name: "mntuser".into(),
                        remove: true,
                        password: None,
                    },
                )
                .await
                .unwrap_err();
            assert_eq!(err.errno, Errno::EXDEV);
            assert_eq!(
                read_vfs_file_as_root(&vfs, PASSWD_PATH).await.unwrap(),
                pw_before
            );
            assert_eq!(
                read_vfs_file_as_root(&vfs, "/home/mntuser/keep.txt")
                    .await
                    .unwrap(),
                b"precious"
            );

            // 4. Nested submount inside a user's home: `remove_tree_as_root` MUST NOT cross st_dev!
            let sub_res = kernel
                .eval_local_account_call(
                    &vfs,
                    root_pid,
                    None,
                    false,
                    Call::Useradd {
                        name: "subuser".into(),
                        create_home: true,
                        home: Some("/home/subuser".into()),
                        group: None,
                        groups: None,
                        password: None,
                        short_password: false,
                    },
                )
                .await
                .unwrap();
            let sub_uid = sub_res["uid"].as_u64().unwrap() as u32;
            vfs.mkdirat(INIT, StartAnchor::Root, "/home/subuser/submnt", 0o755)
                .await
                .unwrap();
            let sub_fs = Rc::new(new_memfs("nested-submount"));
            vfs.mount_on_namespace(
                &vfs.system_namespace(),
                &Cred::root(),
                Rc::new(MountBacking::new(
                    sub_fs as Rc<dyn Filesystem>,
                    FsType::TmpFs,
                )),
                None,
                "tmpfs",
                "/home/subuser/submnt",
                MountFlags::from_accepted(0),
                0,
                None,
            )
            .await
            .unwrap();
            write_vfs_file_as_root(
                &vfs,
                "/home/subuser/submnt/preserved.txt",
                b"never-delete",
                0o644,
                sub_uid,
                sub_uid,
            )
            .await
            .unwrap();
            let home_st = vfs
                .statat(INIT, StartAnchor::Root, "/home/subuser", false)
                .await
                .unwrap();
            let err = remove_tree_as_root(&vfs, "/home/subuser", home_st.dev)
                .await
                .unwrap_err();
            assert_eq!(err.errno, Errno::EXDEV);
            assert_eq!(
                read_vfs_file_as_root(&vfs, "/home/subuser/submnt/preserved.txt")
                    .await
                    .unwrap(),
                b"never-delete"
            );

            // 5. Legitimate owned home directory removes cleanly.
            kernel
                .eval_local_account_call(
                    &vfs,
                    root_pid,
                    None,
                    false,
                    Call::Useradd {
                        name: "cleanuser".into(),
                        create_home: true,
                        home: None,
                        group: None,
                        groups: None,
                        password: None,
                        short_password: false,
                    },
                )
                .await
                .unwrap();
            write_vfs_file_as_root(&vfs, "/home/cleanuser/file.txt", b"ok", 0o600, 0, 0)
                .await
                .unwrap();
            kernel
                .eval_local_account_call(
                    &vfs,
                    root_pid,
                    None,
                    false,
                    Call::Userdel {
                        name: "cleanuser".into(),
                        remove: true,
                        password: None,
                    },
                )
                .await
                .unwrap();
            assert_eq!(
                vfs.statat(INIT, StartAnchor::Root, "/home/cleanuser", false)
                    .await
                    .unwrap_err(),
                Errno::ENOENT
            );
        });
    }

    #[test]
    fn finding_6_flush_stages_writes_rolls_back_mid_batch_rename_and_serializes_concurrent_useradd()
    {
        block_on(async {
            let (fs, vfs) = seeded_faulty_vfs().await;
            let kernel = TestAccountHost::new("inst-f6");
            let root_pid = spawn_proc(&kernel, Identity::root(), 10);

            let orig_passwd = read_vfs_file_as_root(&vfs, PASSWD_PATH).await.unwrap();
            let orig_group = read_vfs_file_as_root(&vfs, GROUP_PATH).await.unwrap();
            let orig_shadow = read_vfs_file_as_root(&vfs, SHADOW_PATH).await.unwrap();

            // 1. Fail 2nd staged WriteFile -> cleans up 1st temp file, leaves live /etc/* untouched!
            fs.create_count.set(0);
            fs.fail_create_after.set(Some(1));
            let err = kernel
                .eval_local_account_call(
                    &vfs,
                    root_pid,
                    None,
                    false,
                    Call::Useradd {
                        name: "writefail".into(),
                        create_home: false,
                        home: None,
                        group: None,
                        groups: None,
                        password: None,
                        short_password: false,
                    },
                )
                .await
                .unwrap_err();
            assert_eq!(err.errno, Errno::EIO);
            fs.fail_create_after.set(None);
            assert_eq!(
                read_vfs_file_as_root(&vfs, PASSWD_PATH).await.unwrap(),
                orig_passwd
            );
            assert_eq!(
                read_vfs_file_as_root(&vfs, GROUP_PATH).await.unwrap(),
                orig_group
            );
            assert_eq!(
                read_vfs_file_as_root(&vfs, SHADOW_PATH).await.unwrap(),
                orig_shadow
            );
            let etc_entries = vfs
                .read_dir_page(INIT, StartAnchor::Root, "/etc", 0, 256)
                .await
                .unwrap();
            assert!(
                !etc_entries.entries.iter().any(|e| e.name.contains(".tmp.")),
                "leaked staged temp file after write failure: {:?}",
                etc_entries.entries
            );

            // 2. Fail 2nd Rename mid-batch -> rolls back 1st renamed file & cleans remaining temps!
            fs.rename_count.set(0);
            fs.fail_rename_after.set(Some(1));
            let err = kernel
                .eval_local_account_call(
                    &vfs,
                    root_pid,
                    None,
                    false,
                    Call::Useradd {
                        name: "renamefail".into(),
                        create_home: false,
                        home: None,
                        group: None,
                        groups: None,
                        password: None,
                        short_password: false,
                    },
                )
                .await
                .unwrap_err();
            assert_eq!(err.errno, Errno::EIO);
            fs.fail_rename_after.set(None);
            assert_eq!(
                read_vfs_file_as_root(&vfs, PASSWD_PATH).await.unwrap(),
                orig_passwd
            );
            assert_eq!(
                read_vfs_file_as_root(&vfs, GROUP_PATH).await.unwrap(),
                orig_group
            );
            assert_eq!(
                read_vfs_file_as_root(&vfs, SHADOW_PATH).await.unwrap(),
                orig_shadow
            );
            let etc_entries = vfs
                .read_dir_page(INIT, StartAnchor::Root, "/etc", 0, 256)
                .await
                .unwrap();
            assert!(
                !etc_entries
                    .entries
                    .iter()
                    .any(|e| e.name.contains(".tmp.") || e.name.contains(".rollback.")),
                "leaked temp/rollback file after rename failure: {:?}",
                etc_entries.entries
            );

            // 3. Concurrent `useradd` calls serialize via `account_lock` even when VFS yields!
            fs.yield_on_open.set(true);
            let f1 = kernel.eval_local_account_call(
                &vfs,
                root_pid,
                None,
                false,
                Call::Useradd {
                    name: "conc1".into(),
                    create_home: false,
                    home: None,
                    group: None,
                    groups: None,
                    password: None,
                    short_password: false,
                },
            );
            let f2 = kernel.eval_local_account_call(
                &vfs,
                root_pid,
                None,
                false,
                Call::Useradd {
                    name: "conc2".into(),
                    create_home: false,
                    home: None,
                    group: None,
                    groups: None,
                    password: None,
                    short_password: false,
                },
            );
            let (r1, r2) = join(f1, f2).await;
            fs.yield_on_open.set(false);
            let u1 = r1.unwrap();
            let u2 = r2.unwrap();
            assert_ne!(
                u1["uid"], u2["uid"],
                "concurrent useradd allocated duplicate UID!"
            );
            let final_pw =
                String::from_utf8(read_vfs_file_as_root(&vfs, PASSWD_PATH).await.unwrap()).unwrap();
            let records = parse_passwd(&final_pw).unwrap();
            assert!(records.iter().any(|u| u.name == "conc1"));
            assert!(records.iter().any(|u| u.name == "conc2"));
        });
    }

    // Thin `MemoryHeadStore` wrapper that can inject `ENOSPC` on `commit_head` to verify #6.
    struct DummyWriterGuard;
    impl WriterLockGuard for DummyWriterGuard {}
    struct DummyGcGuard;
    impl GcLockGuard for DummyGcGuard {}
    struct DummyRoPinGuard;
    impl RoPinGuard for DummyRoPinGuard {}

    #[derive(Default)]
    struct FailingCowHeadState {
        format_version: Option<u32>,
        heads: HashMap<VolumeId, VolumeHead>,
        nodes: HashMap<Digest, Vec<u8>>,
        packs: HashMap<PackId, PackMeta>,
        blocks: HashMap<Digest, BlockLoc>,
    }

    struct FailingCommitHeadStore {
        state: RefCell<FailingCowHeadState>,
        fail_commits: Cell<bool>,
    }

    impl FailingCommitHeadStore {
        fn new() -> Self {
            Self {
                state: RefCell::new(FailingCowHeadState::default()),
                fail_commits: Cell::new(false),
            }
        }
    }

    impl HeadStore for FailingCommitHeadStore {
        fn format_version(&self) -> BoxFuture<'_, Option<u32>> {
            Box::pin(async move { Ok(self.state.borrow().format_version) })
        }
        fn grace_window_secs(&self) -> u64 {
            600
        }
        fn create_volume<'a>(
            &'a self,
            head: &'a VolumeHead,
            initial_nodes: &'a [(Digest, Vec<u8>)],
        ) -> BoxFuture<'a, VolumeHead> {
            Box::pin(async move {
                let mut st = self.state.borrow_mut();
                st.format_version = Some(COWFS_FORMAT_VERSION);
                for (d, b) in initial_nodes {
                    st.nodes.insert(*d, b.clone());
                }
                st.heads.insert(head.volume.clone(), head.clone());
                Ok(head.clone())
            })
        }
        fn read_head<'a>(&'a self, volume: &'a VolumeId) -> BoxFuture<'a, VolumeHead> {
            Box::pin(async move {
                self.state
                    .borrow()
                    .heads
                    .get(volume)
                    .cloned()
                    .ok_or(Errno::ENOENT)
            })
        }
        fn pin_ro_root<'a>(
            &'a self,
            volume: &'a VolumeId,
            _snapshot: Option<&'a str>,
        ) -> BoxFuture<'a, (VolumeHead, Box<dyn RoPinGuard>)> {
            Box::pin(async move {
                let head = self
                    .state
                    .borrow()
                    .heads
                    .get(volume)
                    .cloned()
                    .ok_or(Errno::ENOENT)?;
                Ok((head, Box::new(DummyRoPinGuard) as Box<dyn RoPinGuard>))
            })
        }
        fn unpin_ro_root<'a>(&'a self, _pin: Box<dyn RoPinGuard>) -> BoxFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }
        fn acquire_writer<'a>(
            &'a self,
            volume: &'a VolumeId,
            _mode: WriterMode,
        ) -> BoxFuture<'a, WriterLease> {
            Box::pin(async move {
                let mut st = self.state.borrow_mut();
                let head = st.heads.get_mut(volume).ok_or(Errno::ENOENT)?;
                head.fence += 1;
                let updated = head.clone();
                Ok(WriterLease {
                    volume: volume.clone(),
                    incarnation: updated.incarnation,
                    fence: updated.fence,
                    epoch: updated.epoch,
                    head: updated,
                    forked_from: None,
                    expires_at: None,
                    guard: Box::new(DummyWriterGuard),
                })
            })
        }
        fn renew_writer<'a>(&'a self, _lease: &'a mut WriterLease) -> BoxFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }
        fn release_writer<'a>(&'a self, _lease: WriterLease) -> BoxFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }
        fn get_node<'a>(&'a self, digest: &'a Digest) -> BoxFuture<'a, Vec<u8>> {
            Box::pin(async move {
                self.state
                    .borrow()
                    .nodes
                    .get(digest)
                    .cloned()
                    .ok_or(Errno::ENOENT)
            })
        }
        fn lookup_block<'a>(&'a self, digest: &'a Digest) -> BoxFuture<'a, Option<BlockLoc>> {
            Box::pin(async move { Ok(self.state.borrow().blocks.get(digest).cloned()) })
        }
        fn commit_head<'a>(&'a self, req: &'a CommitRequest) -> BoxFuture<'a, VolumeHead> {
            Box::pin(async move {
                if self.fail_commits.get() {
                    return Err(Errno::ENOSPC);
                }
                let mut st = self.state.borrow_mut();
                let cur = st.heads.get(&req.volume).cloned().ok_or(Errno::ENOENT)?;
                for (d, b) in &req.put_nodes {
                    st.nodes.insert(*d, b.clone());
                }
                for pm in &req.put_packs {
                    st.packs.insert(pm.pack_id.clone(), pm.clone());
                }
                for (d, loc) in &req.put_blocks {
                    st.blocks.insert(*d, loc.clone());
                }
                let next = VolumeHead {
                    epoch: cur.epoch + 1,
                    root: req.new_root,
                    modified: true,
                    ephemeral_if_unmodified: false,
                    updated_at: req.committed_at,
                    ..cur
                };
                st.heads.insert(req.volume.clone(), next.clone());
                Ok(next)
            })
        }
        fn create_snapshot<'a>(
            &'a self,
            _volume: &'a VolumeId,
            _name: &'a str,
            _head: &'a VolumeHead,
            _now: Timespec,
        ) -> BoxFuture<'a, SnapshotRecord> {
            Box::pin(async { Err(Errno::ENOSYS) })
        }
        fn get_snapshot<'a>(
            &'a self,
            _volume: &'a VolumeId,
            _name: &'a str,
        ) -> BoxFuture<'a, SnapshotRecord> {
            Box::pin(async { Err(Errno::ENOENT) })
        }
        fn list_snapshots<'a>(
            &'a self,
            _volume: &'a VolumeId,
        ) -> BoxFuture<'a, Vec<SnapshotRecord>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn delete_snapshot<'a>(
            &'a self,
            _volume: &'a VolumeId,
            _name: &'a str,
        ) -> BoxFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }
        fn fork_volume<'a>(&'a self, _req: &'a ForkRequest) -> BoxFuture<'a, VolumeHead> {
            Box::pin(async { Err(Errno::ENOSYS) })
        }
        fn delete_volume<'a>(&'a self, _volume: &'a VolumeId) -> BoxFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }
        fn delete_volume_with_lease<'a>(
            &'a self,
            _lease: WriterLease,
            _only_if_unmodified_ephemeral: bool,
        ) -> BoxFuture<'a, bool> {
            Box::pin(async { Ok(false) })
        }
        fn reformat_volume_with_lease<'a>(
            &'a self,
            _lease: WriterLease,
            _new_head: &'a VolumeHead,
            _initial_nodes: &'a [(Digest, Vec<u8>)],
        ) -> BoxFuture<'a, VolumeHead> {
            Box::pin(async { Err(Errno::ENOSYS) })
        }
        fn acquire_gc_lock(&self, _exclusive: bool) -> BoxFuture<'_, Box<dyn GcLockGuard>> {
            Box::pin(async { Ok(Box::new(DummyGcGuard) as Box<dyn GcLockGuard>) })
        }
        fn list_all_roots(&self) -> BoxFuture<'_, Vec<GcRoot>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn list_indexed_packs(&self) -> BoxFuture<'_, HashSet<PackId>> {
            Box::pin(async move { Ok(self.state.borrow().packs.keys().cloned().collect()) })
        }
        fn prune_abandoned_ephemeral_forks(
            &self,
            _now: Timespec,
            _grace_window_secs: u64,
        ) -> BoxFuture<'_, usize> {
            Box::pin(async { Ok(0) })
        }
        fn sweep_metadata<'a>(
            &'a self,
            _keep_nodes: &'a HashSet<Digest>,
            _keep_packs: &'a HashSet<PackId>,
            _now: Timespec,
            _grace_window_secs: u64,
        ) -> BoxFuture<'a, Vec<PackId>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    #[derive(Default)]
    struct TestCowPackStore {
        packs: RefCell<HashMap<PackId, Vec<u8>>>,
    }

    impl PackStore for TestCowPackStore {
        fn write_pack<'a>(
            &'a self,
            pack_id: &'a PackId,
            bytes: &'a [u8],
        ) -> BoxFuture<'a, PackMeta> {
            Box::pin(async move {
                let trailer = decode_pack_trailer(bytes)?;
                self.packs
                    .borrow_mut()
                    .insert(pack_id.clone(), bytes.to_vec());
                Ok(PackMeta {
                    pack_id: pack_id.clone(),
                    size: bytes.len() as u32,
                    entry_count: trailer.entries.len() as u32,
                    created_at: Timespec { sec: 0, nsec: 0 },
                })
            })
        }
        fn read_pack_range<'a>(
            &'a self,
            pack_id: &'a PackId,
            offset: u32,
            len: u32,
        ) -> BoxFuture<'a, Vec<u8>> {
            Box::pin(async move {
                let map = self.packs.borrow();
                let bytes = map.get(pack_id).ok_or(Errno::ENOENT)?;
                let start = offset as usize;
                let end = start.checked_add(len as usize).ok_or(Errno::EINVAL)?;
                Ok(bytes.get(start..end).ok_or(Errno::EIO)?.to_vec())
            })
        }
        fn read_pack_trailer<'a>(&'a self, pack_id: &'a PackId) -> BoxFuture<'a, PackTrailer> {
            Box::pin(async move {
                let map = self.packs.borrow();
                let bytes = map.get(pack_id).ok_or(Errno::ENOENT)?;
                decode_pack_trailer(bytes)
            })
        }
        fn stat_pack<'a>(&'a self, pack_id: &'a PackId) -> BoxFuture<'a, Option<u64>> {
            Box::pin(async move { Ok(self.packs.borrow().get(pack_id).map(|b| b.len() as u64)) })
        }
        fn list_packs(&self) -> BoxFuture<'_, Vec<PackId>> {
            Box::pin(async move { Ok(self.packs.borrow().keys().cloned().collect()) })
        }
        fn delete_pack<'a>(&'a self, pack_id: &'a PackId) -> BoxFuture<'a, ()> {
            Box::pin(async move {
                self.packs.borrow_mut().remove(pack_id);
                Ok(())
            })
        }
    }

    #[test]
    fn finding_6_cowfs_commit_failures_propagate_on_all_mutating_account_calls() {
        block_on(async {
            let hs = Rc::new(FailingCommitHeadStore::new());
            let ps = Rc::new(TestCowPackStore::default());
            let vol = VolumeId("vol-commit-test".into());
            let now = Timespec {
                sec: 1_700_000_000,
                nsec: 0,
            };
            CowFs::format_volume(&*hs, &*ps, vol.clone(), 0, 0, 0o755, now)
                .await
                .expect("format cowfs");
            let cowfs = Rc::new(
                CowFs::open(
                    hs.clone(),
                    ps.clone(),
                    vol,
                    CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
                    CowFsConfig::local_browser(Rc::new(move || now)),
                )
                .await
                .expect("open cowfs"),
            );
            seed_fresh_cowfs_root(&*cowfs).await.unwrap();
            cowfs.commit_tx_group().await.unwrap();

            let backing = Rc::new(MountBacking::new(
                cowfs.clone() as Rc<dyn Filesystem>,
                FsType::Cowfs,
            ));
            let factory = Rc::new(DefaultFilesystemFactory::new(Rc::new(test_clock)));
            let vfs = Vfs::boot("test-cow", backing, "cowfs", factory)
                .await
                .expect("boot cowfs vfs");

            let mut kernel = TestAccountHost::new("inst-cow");
            kernel.root_cowfs = Some(cowfs.clone());
            assert!(kernel.commit_root_cowfs_host().await.is_ok());
            hs.fail_commits.set(true);
            let root_pid = spawn_proc(&kernel, Identity::root(), 10);

            // Real `CowFs::commit_tx_group()` fails with `Errno::ENOSPC` on EVERY ONE of the 7
            // mutating account calls — verify none silently succeed!

            assert_eq!(
                kernel
                    .eval_local_account_call(
                        &vfs,
                        root_pid,
                        None,
                        false,
                        Call::Passwd {
                            username: Some("user".into()),
                            password: "strong-password-commit".into(),
                            current_password: None,
                            force: false,
                        },
                    )
                    .await
                    .unwrap_err()
                    .errno,
                Errno::ENOSPC
            );
            assert_eq!(
                kernel
                    .eval_local_account_call(
                        &vfs,
                        root_pid,
                        None,
                        false,
                        Call::Useradd {
                            name: "cuser".into(),
                            create_home: false,
                            home: None,
                            group: None,
                            groups: None,
                            password: None,
                            short_password: false,
                        },
                    )
                    .await
                    .unwrap_err()
                    .errno,
                Errno::ENOSPC
            );
            assert_eq!(
                kernel
                    .eval_local_account_call(
                        &vfs,
                        root_pid,
                        None,
                        false,
                        Call::Usermod {
                            name: "cuser".into(),
                            append: false,
                            groups: None,
                            group: None,
                            home: None,
                            move_home: false,
                            rename: None,
                            lock: true,
                            unlock: false,
                        },
                    )
                    .await
                    .unwrap_err()
                    .errno,
                Errno::ENOSPC
            );
            assert_eq!(
                kernel
                    .eval_local_account_call(
                        &vfs,
                        root_pid,
                        None,
                        false,
                        Call::Userdel {
                            name: "cuser".into(),
                            remove: false,
                            password: None,
                        },
                    )
                    .await
                    .unwrap_err()
                    .errno,
                Errno::ENOSPC
            );
            assert_eq!(
                kernel
                    .eval_local_account_call(
                        &vfs,
                        root_pid,
                        None,
                        false,
                        Call::Groupadd { name: "cg1".into() },
                    )
                    .await
                    .unwrap_err()
                    .errno,
                Errno::ENOSPC
            );
            assert_eq!(
                kernel
                    .eval_local_account_call(
                        &vfs,
                        root_pid,
                        None,
                        false,
                        Call::Groupmod {
                            name: "cg1".into(),
                            new_name: "cg2".into(),
                        },
                    )
                    .await
                    .unwrap_err()
                    .errno,
                Errno::ENOSPC
            );
            assert_eq!(
                kernel
                    .eval_local_account_call(
                        &vfs,
                        root_pid,
                        None,
                        false,
                        Call::Groupdel { name: "cg2".into() },
                    )
                    .await
                    .unwrap_err()
                    .errno,
                Errno::ENOSPC
            );
            // Also verify real `CowFs::commit_tx_group()` returns `Errno::ENOSPC`.
            assert_eq!(cowfs.commit_tx_group().await.unwrap_err(), Errno::ENOSPC);
        });
    }

    #[test]
    fn finding_22_sudo_timestamps_isolate_sessions_and_invalidate_on_passwd_lock_del_logout() {
        block_on(async {
            let (_fs, vfs) = seeded_faulty_vfs().await;
            let kernel = TestAccountHost::new("inst-f22");
            let root_pid = spawn_proc(&kernel, Identity::root(), 1);

            // Switch sudoers to password-required `%wheel` + named non-wheel NOPASSWD user `bob`.
            kernel
                .eval_local_account_call(
                    &vfs,
                    root_pid,
                    None,
                    false,
                    Call::Useradd {
                        name: "bob".into(),
                        create_home: false,
                        home: None,
                        group: None,
                        groups: None,
                        password: None,
                        short_password: false,
                    },
                )
                .await
                .unwrap();
            let bob_acc = kernel
                .resolve_local_user_account(&vfs, "bob")
                .await
                .unwrap();
            write_vfs_file_as_root(
                &vfs,
                SUDOERS_PATH,
                b"root ALL=(ALL:ALL) ALL\n%wheel ALL=(ALL:ALL) ALL\nbob ALL=(ALL:ALL) NOPASSWD: ALL\n",
                SUDOERS_MODE,
                0,
                0,
            )
            .await
            .unwrap();
            // Set password for `user`.
            kernel
                .eval_local_account_call(
                    &vfs,
                    root_pid,
                    None,
                    false,
                    Call::Passwd {
                        username: Some("user".into()),
                        password: "user-strong-password-1".into(),
                        current_password: None,
                        force: false,
                    },
                )
                .await
                .unwrap();

            // Named non-wheel user `bob` gets `(can_sudo=true, sudo_active=true)` via `check_local_sudo_for_sid`!
            assert_eq!(
                kernel
                    .check_local_sudo_for_sid(&vfs, bob_acc.uid, 55)
                    .await
                    .unwrap(),
                (true, true)
            );

            // Spawn two processes for `user` (uid 1000) in DIFFERENT sessions (`sid=10`, `sid=20`).
            let user_id = kernel.state.borrow().account.identity();
            let p10 = spawn_proc(&kernel, user_id.clone(), 10);
            let p20 = spawn_proc(&kernel, user_id.clone(), 20);

            // Before sudo: neither session nor page is sudo_active.
            assert_eq!(
                kernel
                    .check_local_sudo_for_sid(&vfs, 1000, 10)
                    .await
                    .unwrap(),
                (true, false)
            );
            assert_eq!(
                kernel
                    .check_local_sudo_for_sid(&vfs, 1000, 20)
                    .await
                    .unwrap(),
                (true, false)
            );
            assert!(
                !kernel
                    .check_local_sudo_authorized(&vfs, 1000)
                    .await
                    .unwrap()
            );

            // Authenticate sudo in session 10.
            kernel
                .eval_local_account_call(
                    &vfs,
                    p10,
                    None,
                    false,
                    Call::Sudo {
                        password: "user-strong-password-1".into(),
                        revoke: false,
                    },
                )
                .await
                .unwrap();
            assert_eq!(
                kernel
                    .check_local_sudo_for_sid(&vfs, 1000, 10)
                    .await
                    .unwrap(),
                (true, true)
            );
            // Session 20 AND page session MUST remain unauthorized!
            assert_eq!(
                kernel
                    .check_local_sudo_for_sid(&vfs, 1000, 20)
                    .await
                    .unwrap(),
                (true, false)
            );
            assert!(
                !kernel
                    .check_local_sudo_authorized(&vfs, 1000)
                    .await
                    .unwrap()
            );
            let c20 = kernel
                .eval_local_account_call(&vfs, p20, None, false, Call::Getcreds)
                .await
                .unwrap();
            assert_eq!(c20["can_sudo"], true);
            assert_eq!(c20["sudo_active"], false);

            // Authenticate page-scoped sudo -> page authorized, session 20 still NOT authorized!
            kernel
                .eval_local_account_call(
                    &vfs,
                    SCOPED_PAGE_PID_BASE + 1,
                    Some("page-1"),
                    false,
                    Call::Sudo {
                        password: "user-strong-password-1".into(),
                        revoke: false,
                    },
                )
                .await
                .unwrap();
            assert!(
                kernel
                    .check_local_sudo_authorized(&vfs, 1000)
                    .await
                    .unwrap()
            );
            assert_eq!(
                kernel
                    .check_local_sudo_for_sid(&vfs, 1000, 20)
                    .await
                    .unwrap(),
                (true, false)
            );

            // 1. `Call::Passwd` invalidates ALL sudo timestamps for uid 1000 across ALL sessions!
            kernel
                .eval_local_account_call(
                    &vfs,
                    root_pid,
                    None,
                    false,
                    Call::Passwd {
                        username: Some("user".into()),
                        password: "user-strong-password-2".into(),
                        current_password: None,
                        force: false,
                    },
                )
                .await
                .unwrap();
            assert_eq!(
                kernel
                    .check_local_sudo_for_sid(&vfs, 1000, 10)
                    .await
                    .unwrap(),
                (true, false)
            );
            assert!(
                !kernel
                    .check_local_sudo_authorized(&vfs, 1000)
                    .await
                    .unwrap()
            );

            // 2. `Call::Usermod { lock: true }` invalidates ALL sudo timestamps for uid 1000!
            let p10b = spawn_proc(&kernel, user_id.clone(), 10);
            kernel
                .eval_local_account_call(
                    &vfs,
                    p10b,
                    None,
                    false,
                    Call::Sudo {
                        password: "user-strong-password-2".into(),
                        revoke: false,
                    },
                )
                .await
                .unwrap();
            assert_eq!(
                kernel
                    .check_local_sudo_for_sid(&vfs, 1000, 10)
                    .await
                    .unwrap(),
                (true, true)
            );
            kernel
                .eval_local_account_call(
                    &vfs,
                    root_pid,
                    None,
                    false,
                    Call::Usermod {
                        name: "user".into(),
                        append: false,
                        groups: None,
                        group: None,
                        home: None,
                        move_home: false,
                        rename: None,
                        lock: true,
                        unlock: false,
                    },
                )
                .await
                .unwrap();
            assert_eq!(
                kernel
                    .check_local_sudo_for_sid(&vfs, 1000, 10)
                    .await
                    .unwrap(),
                (true, false)
            );

            // Unlock `user`, re-authenticate page sudo, then `Call::Logout` invalidates timestamps AND
            // advances `account_epoch` (invalidating active `CloudSession` for Finding #1 too!).
            kernel
                .eval_local_account_call(
                    &vfs,
                    root_pid,
                    None,
                    false,
                    Call::Usermod {
                        name: "user".into(),
                        append: false,
                        groups: None,
                        group: None,
                        home: None,
                        move_home: false,
                        rename: None,
                        lock: false,
                        unlock: true,
                    },
                )
                .await
                .unwrap();
            let epoch_before = kernel.state.borrow().account_epoch;
            kernel.state.borrow_mut().cloud_session = Some(CloudSession {
                cloud_user: "cloud-u".into(),
                cloud_uid: 3000,
                cloud_gid: 3000,
                cloud_groups: vec![3000],
                local_uid: 1000,
                login_generation: epoch_before,
                scope: RemoteScope::full(),
                page_token: "tok-before-logout".into(),
                signed_in_at: 1,
                revoked: false,
            });
            kernel
                .eval_local_account_call(
                    &vfs,
                    SCOPED_PAGE_PID_BASE + 2,
                    Some("page-2"),
                    false,
                    Call::Sudo {
                        password: "user-strong-password-2".into(),
                        revoke: false,
                    },
                )
                .await
                .unwrap();
            assert!(
                kernel
                    .check_local_sudo_authorized(&vfs, 1000)
                    .await
                    .unwrap()
            );
            kernel
                .eval_local_account_call(
                    &vfs,
                    SCOPED_PAGE_PID_BASE + 3,
                    Some("page-3"),
                    false,
                    Call::Logout,
                )
                .await
                .unwrap();
            assert!(
                !kernel
                    .check_local_sudo_authorized(&vfs, 1000)
                    .await
                    .unwrap()
            );
            assert!(kernel.state.borrow().account_epoch > epoch_before);
            // Finding #1: stale CloudSession from before logout is now rejected on `/mnt/cloud`!
            let cloud_mount = kernel.cloud_mount.clone();
            assert_eq!(
                cloud_mount
                    .metadata(&Cred::root(), &cloud_mount.root())
                    .await
                    .unwrap_err(),
                Errno::EACCES
            );

            // 3. `Call::Userdel` invalidates deleted user's sudo timestamps!
            kernel
                .eval_local_account_call(
                    &vfs,
                    root_pid,
                    None,
                    false,
                    Call::Useradd {
                        name: "tempwheel".into(),
                        create_home: false,
                        home: None,
                        group: None,
                        groups: Some("wheel".into()),
                        password: Some("tempwheel-strong-pass".into()),
                        short_password: false,
                    },
                )
                .await
                .unwrap();
            let tw_acc = kernel
                .resolve_local_user_account(&vfs, "tempwheel")
                .await
                .unwrap();
            let tw_pid = spawn_proc(&kernel, tw_acc.identity(), 77);
            kernel
                .eval_local_account_call(
                    &vfs,
                    tw_pid,
                    None,
                    false,
                    Call::Sudo {
                        password: "tempwheel-strong-pass".into(),
                        revoke: false,
                    },
                )
                .await
                .unwrap();
            assert!(
                kernel
                    .state
                    .borrow()
                    .sudo_timestamps
                    .contains_key(&(tw_acc.uid, 77))
            );
            kernel
                .eval_local_account_call(
                    &vfs,
                    root_pid,
                    None,
                    false,
                    Call::Userdel {
                        name: "tempwheel".into(),
                        remove: false,
                        password: None,
                    },
                )
                .await
                .unwrap();
            assert!(
                !kernel
                    .state
                    .borrow()
                    .sudo_timestamps
                    .keys()
                    .any(|&(u, _)| u == tw_acc.uid)
            );
        });
    }

    #[test]
    fn finding_24_logout_and_resolve_never_fallback_to_hardcoded_uid_1000_wheel() {
        block_on(async {
            let (_fs, vfs) = seeded_faulty_vfs().await;
            let kernel = TestAccountHost::new("inst-f24");
            let root_pid = spawn_proc(&kernel, Identity::root(), 1);

            // Delete default `user` and create non-wheel `replacement` which takes UID 1000.
            kernel
                .eval_local_account_call(
                    &vfs,
                    root_pid,
                    None,
                    false,
                    Call::Userdel {
                        name: "user".into(),
                        remove: false,
                        password: None,
                    },
                )
                .await
                .unwrap();
            let rep = kernel
                .eval_local_account_call(
                    &vfs,
                    root_pid,
                    None,
                    false,
                    Call::Useradd {
                        name: "replacement".into(),
                        create_home: false,
                        home: None,
                        group: None,
                        groups: None,
                        password: None,
                        short_password: false,
                    },
                )
                .await
                .unwrap();
            assert_eq!(rep["uid"], 1000);

            // `resolve_local_user_account("user")` and `Call::Logout` MUST return ENOENT!
            assert_eq!(
                kernel
                    .resolve_local_user_account(&vfs, "user")
                    .await
                    .unwrap_err(),
                Errno::ENOENT
            );
            let err = kernel
                .eval_local_account_call(
                    &vfs,
                    SCOPED_PAGE_PID_BASE + 1,
                    Some("page-1"),
                    false,
                    Call::Logout,
                )
                .await
                .unwrap_err();
            assert_eq!(err.errno, Errno::ENOENT);

            // Corrupt `/etc/passwd` -> MUST return EINVAL cleanly.
            write_vfs_file_as_root(&vfs, PASSWD_PATH, b"not:enough:fields\n", PASSWD_MODE, 0, 0)
                .await
                .unwrap();
            assert_eq!(
                kernel
                    .resolve_local_user_account(&vfs, "replacement")
                    .await
                    .unwrap_err(),
                Errno::EINVAL
            );
        });
    }

    #[test]
    fn finding_31_read_vfs_file_reads_past_4mib_and_fails_closed_with_efbig_over_cap() {
        block_on(async {
            let (_fs, vfs) = seeded_faulty_vfs().await;

            // 1. A 5 MiB file (larger than the old 4 MiB silent truncation limit) is read completely!
            let five_mib = vec![b'A'; 5 * 1024 * 1024 + 123];
            write_vfs_file_as_root(&vfs, "/etc/bigtest", &five_mib, 0o644, 0, 0)
                .await
                .unwrap();
            let read_back = read_vfs_file_as_root(&vfs, "/etc/bigtest").await.unwrap();
            assert_eq!(read_back.len(), five_mib.len());
            assert_eq!(read_back, five_mib);

            // 2. Exceeding the limit fails closed with EFBIG instead of truncating!
            assert_eq!(
                read_vfs_file_as_root_with_limit(&vfs, "/etc/bigtest", 4 * 1024 * 1024)
                    .await
                    .unwrap_err(),
                Errno::EFBIG
            );

            // 3. Oversized `/etc/passwd` (> MAX_ACCOUNT_FILE_BYTES) causes VfsSnapshotAccountFs::load
            //    to fail closed with EFBIG instead of truncating records!
            let oversize = vec![b'#'; MAX_ACCOUNT_FILE_BYTES + 1];
            write_vfs_file_as_root(&vfs, PASSWD_PATH, &oversize, PASSWD_MODE, 0, 0)
                .await
                .unwrap();
            let err = match VfsSnapshotAccountFs::load(&vfs, &[]).await {
                Ok(_) => panic!("expected EFBIG for oversize /etc/passwd"),
                Err(e) => e,
            };
            assert_eq!(err.errno, Errno::EFBIG);
        });
    }
}

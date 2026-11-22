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
    AccountFs, DEFAULT_GROUP, DEFAULT_PASSWD, DEFAULT_SHADOW, DEFAULT_SUDOERS, GroupEntry,
    LocalAccountStore, PasswdEntry, SudoCheck, UseraddReq, UsermodReq, parse_group, parse_passwd,
    seed_default_etc,
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
    },
}

/// Sync [`AccountFs`] snapshot bridged cleanly to async [`os_vfs::Vfs`] as PID 1 (`Cred::root()`).
pub(crate) struct VfsSnapshotAccountFs {
    files: HashMap<String, Vec<u8>>,
    existing: HashSet<String>,
    ops: Vec<FsMutation>,
}

impl VfsSnapshotAccountFs {
    pub(crate) async fn load(vfs: &Vfs, extra_paths: &[&str]) -> Self {
        let mut files = HashMap::new();
        let mut existing = HashSet::new();
        for &path in &[PASSWD_PATH, GROUP_PATH, SHADOW_PATH, SUDOERS_PATH] {
            if let Ok(bytes) = read_vfs_file_as_root(vfs, path).await {
                existing.insert(path.to_string());
                files.insert(path.to_string(), bytes);
            }
        }
        for &path in &["/etc", "/home", "/home/user", "/root"] {
            if vfs
                .statat(INIT, StartAnchor::Root, path, false)
                .await
                .is_ok()
            {
                existing.insert(path.to_string());
            }
        }
        for &path in extra_paths {
            if !path.is_empty()
                && vfs
                    .statat(INIT, StartAnchor::Root, path, false)
                    .await
                    .is_ok()
            {
                existing.insert(path.to_string());
            }
        }
        // Preload existing home directories referenced in `/etc/passwd` so `userdel -r` and
        // `usermod -m` observe their real presence on the underlying VFS.
        if let Some(raw_pw) = files.get(PASSWD_PATH)
            && let Ok(text) = std::str::from_utf8(raw_pw)
            && let Ok(records) = parse_passwd(text)
        {
            for rec in records {
                if !rec.home.is_empty()
                    && !existing.contains(&rec.home)
                    && vfs
                        .statat(INIT, StartAnchor::Root, &rec.home, false)
                        .await
                        .is_ok()
                {
                    existing.insert(rec.home);
                }
            }
        }
        Self {
            files,
            existing,
            ops: Vec::new(),
        }
    }

    pub(crate) async fn flush(self, vfs: &Vfs) -> Result<(), Error> {
        for op in self.ops {
            match op {
                FsMutation::WriteFile {
                    path,
                    data,
                    mode,
                    uid,
                    gid,
                } => {
                    write_vfs_file_as_root(vfs, &path, &data, mode, uid, gid).await?;
                }
                FsMutation::Rename { from, to } => {
                    vfs.renameat(
                        INIT,
                        StartAnchor::Root,
                        &from,
                        StartAnchor::Root,
                        &to,
                        RenameFlags::empty(),
                    )
                    .await
                    .map_err(Error::from)?;
                }
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
                    let _ = vfs
                        .setattrat(
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
                        .await;
                }
                FsMutation::RemoveDirAll { path } => {
                    remove_tree_as_root(vfs, &path).await?;
                }
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
        self.files.remove(path);
        self.existing.remove(path);
        self.ops.push(FsMutation::RemoveDirAll {
            path: path.to_string(),
        });
        Ok(())
    }
}

async fn read_vfs_file_as_root(vfs: &Vfs, path: &str) -> vfs::Result<Vec<u8>> {
    let (file, entry) = vfs
        .open_file(INIT, StartAnchor::Root, path, abi::O_RDONLY, 0)
        .await?;
    let cap = usize::try_from(entry.metadata.size.min(4 * 1024 * 1024)).unwrap_or(0);
    let mut out = vec![0u8; cap];
    let mut off = 0usize;
    while off < out.len() {
        match file.read_at(&mut out[off..], off as u64).await {
            Ok(0) => break,
            Ok(n) => off += n,
            Err(e) => {
                let _ = file.close().await;
                return Err(e);
            }
        }
    }
    out.truncate(off);
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
    let _ = file.close().await;
    let _ = vfs
        .setattrat(
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
        .await;
    Ok(())
}

fn remove_tree_as_root<'a>(
    vfs: &'a Vfs,
    path: &'a str,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Error>> + 'a>> {
    Box::pin(async move {
        let st = match vfs.statat(INIT, StartAnchor::Root, path, false).await {
            Ok(st) => st,
            Err(Errno::ENOENT) => return Ok(()),
            Err(e) => return Err(Error::from(e)),
        };
        if st.kind() == abi::S_IFDIR {
            let mut names = Vec::new();
            let mut cookie = 0u64;
            loop {
                let Ok(page) = vfs
                    .read_dir_page(INIT, StartAnchor::Root, path, cookie, 256)
                    .await
                else {
                    break;
                };
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
                remove_tree_as_root(vfs, &child).await?;
            }
            let _ = vfs.unlinkat(INIT, StartAnchor::Root, path, true).await;
        } else {
            let _ = vfs.unlinkat(INIT, StartAnchor::Root, path, false).await;
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
        if mem.lookup(&root_cred, &etc, name).await.is_err() {
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            let (_, open) = mem.create(&root_cred, &etc, name, mode, &opts).await?;
            let _ = mem.write_at(&open, bytes, WriteAt::Offset(0)).await?;
            let _ = mem.release(&open).await;
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
        if fs.lookup(&root_cred, &etc, name).await.is_err() {
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            let (_, open) = fs.create(&root_cred, &etc, name, mode, &opts).await?;
            let _ = fs.write_at(&open, bytes, WriteAt::Offset(0)).await?;
            let _ = fs.release(&open).await;
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
    let home = rec.map(|u| u.home.clone()).unwrap_or_else(|| {
        if uid == 0 {
            "/root".into()
        } else {
            "/home/user".into()
        }
    });
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

impl Kernel {
    /// Commit the mounted root `CowFs` transaction group if active.
    pub(crate) async fn commit_root_cowfs_if_mounted(&self) {
        let cowfs = self.vfs_rt.borrow().root_cowfs.clone();
        if let Some(fs) = cowfs {
            let _ = fs.commit_tx_group().await;
        }
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
    pub(crate) async fn resolve_local_user_account(
        &self,
        vfs: &Vfs,
        user_spec: &str,
    ) -> Result<LocalAccount, Errno> {
        let raw_pw = read_vfs_file_as_root(vfs, PASSWD_PATH).await?;
        let raw_gr = read_vfs_file_as_root(vfs, GROUP_PATH).await?;
        let passwd = parse_passwd(std::str::from_utf8(&raw_pw).map_err(|_| Errno::EIO)?)
            .map_err(|_| Errno::EIO)?;
        let groups = parse_group(std::str::from_utf8(&raw_gr).map_err(|_| Errno::EIO)?)
            .map_err(|_| Errno::EIO)?;
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
            .unwrap_or_else(|| rec.name.clone());
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

    /// Check whether local `uid` is authorized for local `sudo` (via local `/etc/sudoers`
    /// `NOPASSWD` or an active local sudo timestamp). ZERO network RPCs!
    pub(crate) async fn check_local_sudo_authorized(
        &self,
        vfs: &Vfs,
        uid: u32,
    ) -> Result<bool, Errno> {
        if uid == 0 {
            return Ok(true);
        }
        let now = now_secs();
        let snap = VfsSnapshotAccountFs::load(vfs, &[]).await;
        let store = LocalAccountStore::new();
        let raw_pw = snap.read_file(PASSWD_PATH).map_err(|e| e.errno)?;
        let raw_gr = snap.read_file(GROUP_PATH).map_err(|e| e.errno)?;
        let passwd = parse_passwd(std::str::from_utf8(&raw_pw).map_err(|_| Errno::EIO)?)
            .map_err(|_| Errno::EIO)?;
        let groups = parse_group(std::str::from_utf8(&raw_gr).map_err(|_| Errno::EIO)?)
            .map_err(|_| Errno::EIO)?;
        let Some(rec) = passwd.iter().find(|u| u.uid == uid) else {
            return Ok(false);
        };
        let (_, gvec, _) = identity_for_passwd(rec, &groups);
        match store
            .check_sudo(&snap, uid, &gvec, 0, now)
            .map_err(|e| e.errno)?
        {
            SudoCheck::Denied => Ok(false),
            SudoCheck::AllowedNoPassword => Ok(true),
            SudoCheck::RequiresPassword => {
                let cached_until = self
                    .state
                    .borrow()
                    .sudo_timestamps
                    .get(&uid)
                    .copied()
                    .unwrap_or(0);
                Ok(now <= cached_until)
            }
        }
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
        let passwd = parse_passwd(std::str::from_utf8(&raw_pw).map_err(|_| Errno::EIO)?)
            .map_err(|_| Errno::EIO)?;
        let groups = parse_group(std::str::from_utf8(&raw_gr).map_err(|_| Errno::EIO)?)
            .map_err(|_| Errno::EIO)?;
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
        let is_page = page_sid.is_some() || pid >= SCOPED_PAGE_PID_BASE;
        let caller_identity = if is_page {
            let mut id = self.state.borrow().account.identity();
            if page_sudo {
                id = Identity::root();
            }
            id
        } else {
            self.state
                .borrow()
                .table
                .proc(pid)
                .map(|p| p.cred.identity.clone())
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
        let mut snap = VfsSnapshotAccountFs::load(vfs, &extra_refs).await;
        if !snap.exists(PASSWD_PATH) {
            seed_default_etc(&mut snap)?;
        }
        let mut store = LocalAccountStore::new();

        match call {
            Call::Getcreds => {
                let raw_pw = snap.read_file(PASSWD_PATH)?;
                let raw_gr = snap.read_file(GROUP_PATH)?;
                let passwd = parse_passwd(
                    std::str::from_utf8(&raw_pw).map_err(|_| Error::from(Errno::EIO))?,
                )?;
                let groups = parse_group(
                    std::str::from_utf8(&raw_gr).map_err(|_| Error::from(Errno::EIO))?,
                )?;
                let gvec: Vec<u32> = caller_identity.groups.iter().copied().collect();
                let check = store.check_sudo(&snap, caller_identity.id, &gvec, 0, now)?;
                let can_sudo = !matches!(check, SudoCheck::Denied);
                let sudo_active = caller_identity.id == 0
                    || matches!(check, SudoCheck::AllowedNoPassword)
                    || (can_sudo
                        && self
                            .state
                            .borrow()
                            .sudo_timestamps
                            .get(&caller_identity.id)
                            .is_some_and(|&until| now <= until));
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
                    self.state
                        .borrow_mut()
                        .sudo_timestamps
                        .remove(&caller_identity.id);
                    return Ok(json!({ "sudo_active": false }));
                }
                let gvec: Vec<u32> = caller_identity.groups.iter().copied().collect();
                let check = store.check_sudo(&snap, caller_identity.id, &gvec, 0, now)?;
                match check {
                    SudoCheck::Denied => {
                        return Err(Error::because(
                            Errno::EPERM,
                            "current user is not in the sudoers file",
                        ));
                    }
                    SudoCheck::AllowedNoPassword => {}
                    SudoCheck::RequiresPassword => {
                        let cached = self
                            .state
                            .borrow()
                            .sudo_timestamps
                            .get(&caller_identity.id)
                            .is_some_and(|&until| now <= until);
                        if !cached {
                            let raw_pw = snap.read_file(PASSWD_PATH)?;
                            let passwd = parse_passwd(
                                std::str::from_utf8(&raw_pw)
                                    .map_err(|_| Error::from(Errno::EIO))?,
                            )?;
                            let user_rec = passwd
                                .iter()
                                .find(|u| u.uid == caller_identity.id)
                                .ok_or_else(|| Error::from(Errno::ENOENT))?;
                            store.authenticate(&snap, &user_rec.name, &password)?;
                        }
                    }
                }
                self.state
                    .borrow_mut()
                    .sudo_timestamps
                    .insert(caller_identity.id, now.saturating_add(SUDO_TTL_SECS));

                // When invoked from a real process (e.g. `sudo` applet), elevate ONLY that
                // process's local identity to uid 0 while strictly preserving at most its existing
                // non-root remote cred (NEVER synthesizing remote root!).
                if !is_page {
                    let existing_remote = {
                        let mut st = self.state.borrow_mut();
                        let proc = st
                            .table
                            .proc(pid)
                            .ok_or_else(|| Error::from(Errno::ESRCH))?;
                        let host = proc.owner_host.clone();
                        let rem = proc.cred.remote.clone();
                        let _ = st.table.set_authenticated_cred(
                            &host,
                            pid,
                            Identity::root(),
                            rem.clone(),
                        )?;
                        rem
                    };
                    let token = existing_remote.as_ref().map(|r| r.token.clone());
                    let cloud_access = self
                        .state
                        .borrow()
                        .table
                        .proc(pid)
                        .is_some_and(|p| p.cred.cloud_access);
                    let _ = self.proc_set_creds(pid, 0, 0, vec![0], token, cloud_access);
                }
                Ok(json!({ "sudo_active": true }))
            }
            Call::Login { username, password } => {
                let raw_pw = snap.read_file(PASSWD_PATH)?;
                let raw_gr = snap.read_file(GROUP_PATH)?;
                let passwd = parse_passwd(
                    std::str::from_utf8(&raw_pw).map_err(|_| Error::from(Errno::EIO))?,
                )?;
                let groups = parse_group(
                    std::str::from_utf8(&raw_gr).map_err(|_| Error::from(Errno::EIO))?,
                )?;
                let target_rec = passwd
                    .iter()
                    .find(|u| u.name == username)
                    .ok_or_else(|| Error::because(Errno::EACCES, "invalid username or password"))?;

                // Root (uid 0) may switch to any local user without password (e.g. `su alice`,
                // `sudo -u alice`, `login -f alice`); non-root must authenticate against /etc/shadow.
                if caller_identity.id != 0 {
                    store.authenticate(&snap, &username, &password)?;
                }

                let (target_id, gid_vec, _) = identity_for_passwd(target_rec, &groups);
                let target_group = groups
                    .iter()
                    .find(|g| g.gid == target_rec.gid)
                    .map(|g| g.name.clone())
                    .unwrap_or_else(|| target_rec.name.clone());

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
                    self.apply_account_update(acc);
                } else {
                    // Process credential switch (`su` / `login` / `sudo -u`):
                    // - Local escalation to uid 0 (`su root`): retain at most invoker's existing
                    //   non-root remote cred (NEVER synthesize remote root!).
                    // - Privilege drop (`root -> non-root`) or user switch (`uid_a -> uid_b`):
                    //   clear ambient remote cred and immediately revoke dropped `ServiceAuth v2` tokens!
                    let is_local_root_switch = caller_identity.id != 0 && target_id.id == 0;
                    let (revoked, next_token, next_cloud) = {
                        let mut st = self.state.borrow_mut();
                        let proc = st
                            .table
                            .proc(pid)
                            .ok_or_else(|| Error::from(Errno::ESRCH))?;
                        let host = proc.owner_host.clone();
                        let next_remote = if is_local_root_switch {
                            proc.cred.remote.clone()
                        } else {
                            None
                        };
                        let revoked = st.table.set_authenticated_cred(
                            &host,
                            pid,
                            target_id.clone(),
                            next_remote.clone(),
                        )?;
                        let next_cloud = st.table.proc(pid).is_some_and(|p| p.cred.cloud_access);
                        (revoked, next_remote.map(|r| r.token), next_cloud)
                    };
                    revoke_remote_tokens_state(&self.state, revoked).await;
                    let _ = self.proc_set_creds(
                        pid,
                        target_id.id,
                        target_id.group,
                        gid_vec.clone(),
                        next_token,
                        next_cloud,
                    );
                }
                let check = store.check_sudo(&snap, target_id.id, &gid_vec, 0, now)?;
                let can_sudo = !matches!(check, SudoCheck::Denied);
                let sudo_active =
                    target_id.id == 0 || matches!(check, SudoCheck::AllowedNoPassword);
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
                let default_user = self.vfs_rt.borrow().boot_profile.default_user.clone();
                let next = self
                    .resolve_local_user_account(vfs, &default_user)
                    .await
                    .unwrap_or_else(|_| LocalAccount::default());
                self.state.borrow_mut().sudo_timestamps.clear();
                self.apply_account_update(next.clone());
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
                let target = match username {
                    Some(name) if !name.is_empty() => name,
                    _ => {
                        let raw_pw = snap.read_file(PASSWD_PATH)?;
                        let passwd = parse_passwd(
                            std::str::from_utf8(&raw_pw).map_err(|_| Error::from(Errno::EIO))?,
                        )?;
                        passwd
                            .iter()
                            .find(|u| u.uid == caller_identity.id)
                            .map(|u| u.name.clone())
                            .ok_or_else(|| Error::from(Errno::ENOENT))?
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
                self.commit_root_cowfs_if_mounted().await;
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
                self.commit_root_cowfs_if_mounted().await;
                self.refresh_local_account_caches(vfs).await;
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
                store.usermod(
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
                self.commit_root_cowfs_if_mounted().await;
                self.refresh_local_account_caches(vfs).await;
                Ok(json!({ "message": format!("updated user {name}") }))
            }
            Call::Userdel { name, remove, .. } => {
                store.userdel(&mut snap, &caller_identity, &name, remove)?;
                snap.flush(vfs).await?;
                self.commit_root_cowfs_if_mounted().await;
                self.refresh_local_account_caches(vfs).await;
                Ok(json!({ "message": format!("deleted user {name}") }))
            }
            Call::Groupadd { name } => {
                let rec = store.groupadd(&mut snap, &caller_identity, &name)?;
                snap.flush(vfs).await?;
                self.commit_root_cowfs_if_mounted().await;
                self.refresh_local_account_caches(vfs).await;
                Ok(json!({ "message": format!("created group {} (gid {})", rec.name, rec.gid) }))
            }
            Call::Groupmod { name, new_name } => {
                store.groupmod(&mut snap, &caller_identity, &name, &new_name)?;
                snap.flush(vfs).await?;
                self.commit_root_cowfs_if_mounted().await;
                self.refresh_local_account_caches(vfs).await;
                Ok(json!({ "message": format!("renamed group {name} to {new_name}") }))
            }
            Call::Groupdel { name } => {
                store.groupdel(&mut snap, &caller_identity, &name)?;
                snap.flush(vfs).await?;
                self.commit_root_cowfs_if_mounted().await;
                self.refresh_local_account_caches(vfs).await;
                Ok(json!({ "message": format!("deleted group {name}") }))
            }
            _ => Err(Error::from(Errno::ENOSYS)),
        }
    }
}

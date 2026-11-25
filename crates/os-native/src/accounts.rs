//! Local `/etc/{passwd,group,shadow,sudoers}` account bridge over `os_vfs::Vfs` and
//! `os_kernel::accounts::LocalAccountStore` (100% offline, atomic temp-file + rename).

use crate::dev_backend::fill_os_random;
use abi::{Errno, Error};
use os_kernel::accounts::{
    AccountFs, GROUP_MODE, GROUP_PATH, PASSWD_MODE, PASSWD_PATH, SHADOW_MODE, SHADOW_PATH,
    SUDOERS_MODE, SUDOERS_PATH, parse_passwd,
};
use std::collections::{HashMap, HashSet};
use vfs::{SetAttr, StartAnchor, Vfs};

const MAX_ACCOUNT_FILE_BYTES: usize = 16 * 1024 * 1024;
const INIT_PID: u32 = 1;

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
    },
}

pub fn random_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    let _ = fill_os_random(&mut salt);
    salt
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

fn etc_mode(path: &str) -> u16 {
    match path {
        PASSWD_PATH => PASSWD_MODE,
        GROUP_PATH => GROUP_MODE,
        SHADOW_PATH => SHADOW_MODE,
        SUDOERS_PATH => SUDOERS_MODE,
        _ => 0o644,
    }
}

pub async fn read_vfs_file_as_root(vfs: &Vfs, path: &str) -> Result<Vec<u8>, Errno> {
    let fd = vfs
        .openat(INIT_PID, StartAnchor::Root, path, abi::O_RDONLY, 0)
        .await?;
    let mut out = Vec::new();
    let mut off = 0u64;
    let mut buf = vec![0u8; 65_536];
    loop {
        match vfs.pread(INIT_PID, fd, &mut buf, off).await {
            Ok(0) => break,
            Ok(n) => {
                if out.len().saturating_add(n) > MAX_ACCOUNT_FILE_BYTES {
                    let _ = vfs.close(INIT_PID, fd).await;
                    return Err(Errno::EFBIG);
                }
                out.extend_from_slice(&buf[..n]);
                off += n as u64;
            }
            Err(e) => {
                let _ = vfs.close(INIT_PID, fd).await;
                return Err(e);
            }
        }
    }
    vfs.close(INIT_PID, fd).await?;
    Ok(out)
}

async fn write_vfs_file_as_root(
    vfs: &Vfs,
    path: &str,
    data: &[u8],
    mode: u16,
    uid: u32,
    gid: u32,
) -> Result<(), Error> {
    let fd = vfs
        .openat(
            INIT_PID,
            StartAnchor::Root,
            path,
            abi::O_CREAT | abi::O_WRONLY | abi::O_TRUNC,
            mode,
        )
        .await
        .map_err(Error::from)?;
    let mut off = 0u64;
    while (off as usize) < data.len() {
        let n = match vfs.pwrite(INIT_PID, fd, &data[off as usize..], off).await {
            Ok(n) => n,
            Err(e) => {
                let _ = vfs.close(INIT_PID, fd).await;
                return Err(Error::from(e));
            }
        };
        if n == 0 {
            let _ = vfs.close(INIT_PID, fd).await;
            return Err(Error::new(Errno::EIO));
        }
        off += n as u64;
    }
    let _ = vfs.fsync(INIT_PID, fd).await;
    vfs.close(INIT_PID, fd).await.map_err(Error::from)?;
    vfs.setattrat(
        INIT_PID,
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

async fn mkdir_p_as_root(
    vfs: &Vfs,
    path: &str,
    mode: u16,
    uid: u32,
    gid: u32,
) -> Result<(), Error> {
    let mut cur = String::new();
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    for (idx, part) in parts.iter().enumerate() {
        cur.push('/');
        cur.push_str(part);
        let is_last = idx + 1 == parts.len();
        match vfs
            .mkdirat(
                INIT_PID,
                StartAnchor::Root,
                &cur,
                if is_last { mode } else { 0o755 },
            )
            .await
        {
            Ok(_) => {
                if is_last {
                    let _ = vfs
                        .setattrat(
                            INIT_PID,
                            StartAnchor::Root,
                            &cur,
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
            }
            Err(Errno::EEXIST) => {}
            Err(e) => return Err(Error::from(e)),
        }
    }
    Ok(())
}

fn remove_dir_all_as_root<'a>(
    vfs: &'a Vfs,
    path: &'a str,
    expected_dev: u64,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Error>> + 'a>> {
    Box::pin(async move {
        let st = match vfs.statat(INIT_PID, StartAnchor::Root, path, false).await {
            Ok(s) => s,
            Err(Errno::ENOENT) => return Ok(()),
            Err(e) => return Err(Error::from(e)),
        };
        if st.dev != expected_dev {
            return Err(Error::new(Errno::EXDEV));
        }
        if st.is_dir() {
            let entries = vfs
                .readdir(INIT_PID, StartAnchor::Root, path)
                .await
                .map_err(Error::from)?;
            for entry in entries {
                if entry.name == "." || entry.name == ".." {
                    continue;
                }
                let child = format!("{}/{}", path.trim_end_matches('/'), entry.name);
                remove_dir_all_as_root(vfs, &child, expected_dev).await?;
            }
            vfs.unlinkat(INIT_PID, StartAnchor::Root, path, true)
                .await
                .map_err(Error::from)?;
        } else {
            vfs.unlinkat(INIT_PID, StartAnchor::Root, path, false)
                .await
                .map_err(Error::from)?;
        }
        Ok(())
    })
}

/// Sync `AccountFs` snapshot over async `os_vfs::Vfs`.
pub struct VfsAccountFs {
    files: HashMap<String, Vec<u8>>,
    initial: HashMap<String, Vec<u8>>,
    existing: HashSet<String>,
    stats: HashMap<String, abi::Stat>,
    parent_devs: HashMap<String, u64>,
    ops: Vec<FsMutation>,
}

impl VfsAccountFs {
    pub async fn load(vfs: &Vfs, extra_paths: &[&str]) -> Result<Self, Error> {
        let mut files = HashMap::new();
        let mut initial = HashMap::new();
        let mut existing = HashSet::new();
        let mut stats = HashMap::new();
        let mut parent_devs = HashMap::new();

        for &path in &[PASSWD_PATH, GROUP_PATH, SHADOW_PATH, SUDOERS_PATH] {
            match read_vfs_file_as_root(vfs, path).await {
                Ok(bytes) => {
                    existing.insert(path.to_string());
                    initial.insert(path.to_string(), bytes.clone());
                    files.insert(path.to_string(), bytes);
                }
                Err(Errno::ENOENT) => {}
                Err(e) => return Err(Error::from(e)),
            }
        }

        let mut to_stat: Vec<String> = vec![
            "/etc".into(),
            "/home".into(),
            "/home/user".into(),
            "/root".into(),
        ];
        for &p in extra_paths {
            if !p.is_empty() {
                to_stat.push(p.to_string());
            }
        }
        if let Some(raw_pw) = files.get(PASSWD_PATH)
            && let Ok(text) = std::str::from_utf8(raw_pw)
            && let Ok(recs) = parse_passwd(text)
        {
            for r in recs {
                if !r.home.is_empty() {
                    to_stat.push(r.home);
                }
            }
        }

        for p in to_stat {
            if stats.contains_key(&p) {
                continue;
            }
            if let Ok(st) = vfs.statat(INIT_PID, StartAnchor::Root, &p, false).await {
                existing.insert(p.clone());
                stats.insert(p.clone(), st);
                if let Ok(pst) = vfs
                    .statat(INIT_PID, StartAnchor::Root, parent_dir(&p), true)
                    .await
                {
                    parent_devs.insert(p, pst.dev);
                }
            }
        }

        Ok(Self {
            files,
            initial,
            existing,
            stats,
            parent_devs,
            ops: Vec::new(),
        })
    }

    pub async fn flush(self, vfs: &Vfs) -> Result<(), Error> {
        let mut writes = Vec::new();
        let mut renames = Vec::new();
        let mut post = Vec::new();
        for op in self.ops {
            match op {
                FsMutation::WriteFile { .. } => writes.push(op),
                FsMutation::Rename { .. } => renames.push(op),
                other => post.push(other),
            }
        }

        let mut staged: Vec<String> = Vec::new();
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
                    let _ = vfs
                        .unlinkat(INIT_PID, StartAnchor::Root, &path, false)
                        .await;
                    for s in staged {
                        let _ = vfs.unlinkat(INIT_PID, StartAnchor::Root, &s, false).await;
                    }
                    return Err(err);
                }
                staged.push(path);
            }
        }

        let mut remaining_staged: HashSet<String> = staged.into_iter().collect();
        let mut renamed_targets: Vec<String> = Vec::new();
        for op in renames {
            if let FsMutation::Rename { from, to } = op {
                if let Err(err) = vfs
                    .renameat(
                        INIT_PID,
                        StartAnchor::Root,
                        &from,
                        StartAnchor::Root,
                        &to,
                        vfs::RenameFlags::empty(),
                    )
                    .await
                {
                    // Best-effort rollback of already-replaced /etc/* files.
                    for prev in renamed_targets.into_iter().rev() {
                        if let Some(orig) = self.initial.get(&prev) {
                            let _ = write_vfs_file_as_root(vfs, &prev, orig, etc_mode(&prev), 0, 0)
                                .await;
                        }
                    }
                    for s in remaining_staged {
                        let _ = vfs.unlinkat(INIT_PID, StartAnchor::Root, &s, false).await;
                    }
                    return Err(Error::from(err));
                }
                remaining_staged.remove(&from);
                renamed_targets.push(to);
            }
        }

        for op in post {
            match op {
                FsMutation::RemoveFile { path } => {
                    let _ = vfs
                        .unlinkat(INIT_PID, StartAnchor::Root, &path, false)
                        .await;
                }
                FsMutation::MkdirP {
                    path,
                    mode,
                    uid,
                    gid,
                } => {
                    mkdir_p_as_root(vfs, &path, mode, uid, gid).await?;
                }
                FsMutation::RemoveDirAll { path, expected_dev } => {
                    remove_dir_all_as_root(vfs, &path, expected_dev).await?;
                }
                FsMutation::WriteFile { .. } | FsMutation::Rename { .. } => {}
            }
        }
        Ok(())
    }
}

impl AccountFs for VfsAccountFs {
    fn read_file(&self, path: &str) -> Result<Vec<u8>, Error> {
        self.files
            .get(path)
            .cloned()
            .ok_or_else(|| Error::new(Errno::ENOENT))
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
        if let Some(data) = self.files.remove(from) {
            self.files.insert(to.to_string(), data);
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
        self.existing.contains(path)
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
        let dev = self
            .stats
            .get(path)
            .map(|s| s.dev)
            .ok_or_else(|| Error::new(Errno::ENOENT))?;
        self.existing.remove(path);
        self.ops.push(FsMutation::RemoveDirAll {
            path: path.to_string(),
            expected_dev: dev,
        });
        Ok(())
    }

    fn validate_removable_home(&self, path: &str, expected_uid: u32) -> Result<(), Error> {
        let Some(st) = self.stats.get(path) else {
            return Ok(());
        };
        if !st.is_dir() {
            return Err(Error::because(
                Errno::ENOTDIR,
                format!("home path {path} is not a directory"),
            ));
        }
        if st.uid != expected_uid {
            return Err(Error::because(
                Errno::EPERM,
                format!("home path {path} not owned by uid {expected_uid}"),
            ));
        }
        if let Some(&pdev) = self.parent_devs.get(path)
            && st.dev != pdev
        {
            return Err(Error::because(
                Errno::EXDEV,
                format!("refusing to remove mounted home {path}"),
            ));
        }
        Ok(())
    }
}

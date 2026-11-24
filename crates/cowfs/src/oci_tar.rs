//! Standard runnable OCI Image tar/tar+gzip layer importer and reproducible exporter
//! (`docs/architecture/contract.md` §2.15; #81).
//!
//! - **Importer (`import_oci_tar_layers`):** Bounded streaming `flate2::read::MultiGzDecoder` +
//!   `tar::Archive` with strict `BudgetReader` (defeating gzip bombs & entry floods), uncompressed
//!   `DiffID` verification, OCI `.wh.<name>` and `.wh..wh..opq` whiteouts (both tar orderings!),
//!   regular-file hard links, `SymlinkPolicy::StrictConfined` + post-import multi-hop symlink chain
//!   verifier (`MAXSYMLINKS = 40`), `os_image` non-elevating `SetuidPolicy::Reject` default, and
//!   rejection of device/FIFO nodes (`EPERM`).
//! - **Exporter (`export_cowfs_oci_tar_layer`):** Canonical lexicographic tree walk emitting
//!   deterministic POSIX tar / tar+gzip layers while simultaneously hashing uncompressed `DiffID`
//!   and compressed blob digest, plus OCI Image Config & Manifest builders and direct push.

use crate::fs::{CowFs, CowFsConfig, CowFsOpenMode};
use crate::oci_client::{OciClient, OciTransport};
use abi::Errno;
use abi::fs::{FileType, Handle, OpenOptions, SetAttr, Timespec, WriteAt, check_component};
use abi::registry::{
    CowfsOciPushResp, OCI_IMAGE_CONFIG_MEDIA_TYPE, OCI_IMAGE_MANIFEST_MEDIA_TYPE,
    OCI_LAYER_TAR_GZIP_MEDIA_TYPE, OCI_LAYER_TAR_MEDIA_TYPE, OciDescriptor, OciImageConfig,
    OciImageManifest, OciRootFs, OciRuntimeConfig, parse_sha256_digest,
};
use cowtree::{HeadStore, PackStore, VolumeId, WriterMode, digest_to_hex};
use flate2::read::MultiGzDecoder;
use flate2::{Compression, GzBuilder};
use sha2::{Digest as _, Sha256};
use std::cell::Cell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{self, Cursor, Read, Write};
use std::rc::Rc;
use vfs::{Cred, Filesystem, Result};

/// Symlink confinement policy for OCI tar layer import.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymlinkPolicy {
    /// Reject absolute symlink targets (`/etc/shadow`), backslashes, `//` host/UNC prefixes,
    /// scheme/drive colons, and any relative `..` escape above the image root.
    StrictConfined,
    /// Permit clean root-confined absolute symlinks without `..`, `//`, or `\`, still rejecting
    /// escapes, host prefixes, and multi-hop escapes/loops.
    RootedAbsolute,
}

/// Setuid/setgid policy for OCI tar layer import (matches `os_image::Image::validate_shallow`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetuidPolicy {
    /// Reject any tar entry with `S_ISUID | S_ISGID` (`mode & 0o6000 != 0`) with `Errno::EPERM`.
    Reject,
    /// Strip `S_ISUID | S_ISGID` down to `mode & 0o1777`.
    Strip,
}

/// Bounded streaming safety limits for [`import_oci_tar_layers`].
#[derive(Clone, Debug)]
pub struct OciTarImportOptions {
    pub max_layer_uncompressed_bytes: u64,
    pub max_total_uncompressed_bytes: u64,
    pub max_entries: usize,
    pub max_file_bytes: u64,
    pub max_path_bytes: usize,
    pub max_component_bytes: usize,
    pub symlink_policy: SymlinkPolicy,
    pub setuid_policy: SetuidPolicy,
}

impl Default for OciTarImportOptions {
    fn default() -> Self {
        Self {
            max_layer_uncompressed_bytes: 256 * 1024 * 1024,
            max_total_uncompressed_bytes: 512 * 1024 * 1024,
            max_entries: 65_536,
            max_file_bytes: 128 * 1024 * 1024,
            max_path_bytes: abi::PATH_MAX,
            max_component_bytes: abi::NAME_MAX,
            symlink_policy: SymlinkPolicy::StrictConfined,
            setuid_policy: SetuidPolicy::Reject,
        }
    }
}

/// Input specification for one OCI tar / tar+gzip layer.
#[derive(Clone, Copy, Debug)]
pub struct OciTarLayerInput<'a> {
    pub bytes: &'a [u8],
    pub expected_diff_id: Option<&'a str>,
}

/// Summary returned by [`import_oci_tar_layers`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OciImportReport {
    pub volume: String,
    pub root: String,
    pub epoch: u64,
    pub snapshot: Option<String>,
    pub diff_ids: Vec<String>,
    pub entries_imported: u64,
    pub uncompressed_bytes: u64,
}

/// Options for [`export_cowfs_oci_tar_layer`].
#[derive(Clone, Copy, Debug)]
pub struct OciTarExportOptions {
    pub compress: bool,
    pub reproducible: bool,
    pub max_file_bytes: u64,
}

impl Default for OciTarExportOptions {
    fn default() -> Self {
        Self {
            compress: true,
            reproducible: true,
            max_file_bytes: 128 * 1024 * 1024,
        }
    }
}

/// Result of [`export_cowfs_oci_tar_layer`].
#[derive(Clone, Debug)]
pub struct OciExportedLayer {
    pub bytes: Vec<u8>,
    pub media_type: String,
    pub diff_id: String,
    pub blob_digest: String,
    pub blob_size: u64,
    pub uncompressed_size: u64,
    pub entries_exported: u64,
}

/// Strict decompressed byte-budgeting reader that simultaneously hashes uncompressed bytes for
/// OCI `DiffID` verification and immediately aborts gzip bombs with `budget_exceeded`.
struct BudgetReader<R: Read> {
    inner: R,
    layer_read: u64,
    layer_limit: u64,
    total_remaining: u64,
    hasher: Sha256,
    exceeded: Rc<Cell<bool>>,
}

impl<R: Read> BudgetReader<R> {
    fn new(inner: R, layer_limit: u64, total_remaining: u64, exceeded: Rc<Cell<bool>>) -> Self {
        Self {
            inner,
            layer_read: 0,
            layer_limit,
            total_remaining,
            hasher: Sha256::new(),
            exceeded,
        }
    }

    fn drain_and_finish(mut self) -> Result<(String, u64)> {
        let mut scratch = vec![0u8; 16 * 1024];
        loop {
            match self.read(&mut scratch) {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) if self.exceeded.get() => return Err(Errno::EFBIG),
                Err(_) => return Err(Errno::EIO),
            }
        }
        let digest: [u8; 32] = self.hasher.finalize().into();
        Ok((
            format!("sha256:{}", digest_to_hex(&digest)),
            self.layer_read,
        ))
    }
}

impl<R: Read> Read for BudgetReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let max_allowed = self
            .layer_limit
            .saturating_sub(self.layer_read)
            .min(self.total_remaining);
        // Probe up to max_allowed + 1 so exceeding the budget by even 1 byte trips EFBIG!
        let probe_cap = max_allowed.saturating_add(1).min(buf.len() as u64) as usize;
        if probe_cap == 0 {
            self.exceeded.set(true);
            return Err(io::Error::other("budget_exceeded"));
        }
        let n = self.inner.read(&mut buf[..probe_cap])?;
        if n == 0 {
            return Ok(0);
        }
        let n64 = n as u64;
        if n64 > max_allowed {
            self.exceeded.set(true);
            return Err(io::Error::other("budget_exceeded"));
        }
        self.layer_read += n64;
        self.total_remaining -= n64;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

fn is_gzip(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b
}

/// Normalize a tar entry path into validated relative path components (empty vec means root `.`).
fn normalize_tar_path(
    raw: &[u8],
    max_path_bytes: usize,
    max_component_bytes: usize,
) -> Result<Vec<String>> {
    if raw.is_empty() || raw.len() > max_path_bytes || raw.contains(&0) {
        return Err(Errno::EINVAL);
    }
    let s = std::str::from_utf8(raw).map_err(|_| Errno::EINVAL)?;
    if s.contains('\\') || s.starts_with("//") {
        return Err(Errno::EACCES);
    }
    let trimmed = s.trim_end_matches('/');
    let mut comps = Vec::new();
    for part in trimmed.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return Err(Errno::EACCES);
        }
        if part.len() > max_component_bytes {
            return Err(Errno::ENAMETOOLONG);
        }
        check_component(part)?;
        comps.push(part.to_string());
    }
    Ok(comps)
}

/// Validate a symlink target at extraction time against `policy` and `parent_depth`.
fn validate_symlink_target(
    target: &str,
    parent_depth: usize,
    policy: SymlinkPolicy,
    max_path_bytes: usize,
) -> Result<()> {
    if target.is_empty() || target.len() > max_path_bytes || target.contains('\0') {
        return Err(Errno::EINVAL);
    }
    if target.contains('\\') || target.starts_with("//") || target.contains("//") {
        return Err(Errno::EACCES);
    }
    // Reject drive/scheme prefixes like `C:...` or `http:...` in the first segment.
    let first_seg = target.split('/').next().unwrap_or("");
    if first_seg.contains(':') {
        return Err(Errno::EACCES);
    }
    if let Some(stripped) = target.strip_prefix('/') {
        match policy {
            SymlinkPolicy::StrictConfined => return Err(Errno::EACCES),
            SymlinkPolicy::RootedAbsolute => {
                // Absolute path within root must not contain `..` components.
                for comp in stripped.split('/') {
                    if comp == ".." {
                        return Err(Errno::EACCES);
                    }
                }
                return Ok(());
            }
        }
    }
    let mut depth = parent_depth as isize;
    for comp in target.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                depth -= 1;
                if depth < 0 {
                    return Err(Errno::EACCES);
                }
            }
            _ => depth += 1,
        }
    }
    Ok(())
}

fn root_cred_zero_umask() -> Cred {
    let mut cred = Cred::root();
    cred.umask = 0;
    cred
}

fn rm_rf<'a, H: HeadStore + 'static, P: PackStore + 'static>(
    fs: &'a CowFs<H, P>,
    cred: &'a Cred,
    parent: Handle,
    name: String,
) -> vfs::BoxFuture<'a, ()> {
    Box::pin(async move {
        let entry = match fs.lookup(cred, &parent, &name).await {
            Ok(e) => e,
            Err(Errno::ENOENT) => return Ok(()),
            Err(e) => return Err(e),
        };
        if entry.metadata.file_type == FileType::Dir {
            let children = fs.read_dir(cred, &entry.handle).await?;
            for child in children {
                if child.name == "." || child.name == ".." {
                    continue;
                }
                rm_rf(fs, cred, entry.handle.clone(), child.name).await?;
            }
            fs.rmdir(cred, &parent, &name).await
        } else {
            fs.unlink(cred, &parent, &name).await
        }
    })
}

async fn ensure_parent_dir<H: HeadStore + 'static, P: PackStore + 'static>(
    fs: &CowFs<H, P>,
    cred: &Cred,
    comps: &[String],
    created_in_layer: &mut HashSet<String>,
) -> Result<Handle> {
    let mut cur = fs.root();
    let mut path_acc = String::new();
    for comp in comps {
        path_acc.push('/');
        path_acc.push_str(comp);
        match fs.lookup(cred, &cur, comp).await {
            Ok(entry) => {
                if entry.metadata.file_type == FileType::Symlink {
                    // Never traverse a symlink parent during tar extraction!
                    return Err(Errno::EACCES);
                }
                if entry.metadata.file_type != FileType::Dir {
                    return Err(Errno::ENOTDIR);
                }
                cur = entry.handle;
            }
            Err(Errno::ENOENT) => {
                let created = fs.mkdir(cred, &cur, comp, 0o755).await?;
                created_in_layer.insert(path_acc.clone());
                cur = created.handle;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(cur)
}

async fn lookup_exact_no_follow<H: HeadStore + 'static, P: PackStore + 'static>(
    fs: &CowFs<H, P>,
    cred: &Cred,
    comps: &[String],
) -> Result<abi::fs::Entry> {
    let mut cur = fs.root();
    let mut last_entry = None;
    for (idx, comp) in comps.iter().enumerate() {
        let entry = fs.lookup(cred, &cur, comp).await?;
        if idx + 1 < comps.len() && entry.metadata.file_type != FileType::Dir {
            return Err(if entry.metadata.file_type == FileType::Symlink {
                Errno::EACCES
            } else {
                Errno::ENOTDIR
            });
        }
        cur = entry.handle.clone();
        last_entry = Some(entry);
    }
    last_entry.ok_or(Errno::ENOENT)
}

fn verify_symlinks_in_tree<'a, H: HeadStore + 'static, P: PackStore + 'static>(
    fs: &'a CowFs<H, P>,
    cred: &'a Cred,
    dir: Handle,
    dir_comps: Vec<String>,
    policy: SymlinkPolicy,
    max_path_bytes: usize,
) -> vfs::BoxFuture<'a, ()> {
    Box::pin(async move {
        let entries = fs.read_dir(cred, &dir).await?;
        for de in entries {
            if de.name == "." || de.name == ".." {
                continue;
            }
            let entry = fs.lookup(cred, &dir, &de.name).await?;
            let mut child_comps = dir_comps.clone();
            child_comps.push(de.name);
            match entry.metadata.file_type {
                FileType::Dir => {
                    verify_symlinks_in_tree(
                        fs,
                        cred,
                        entry.handle,
                        child_comps,
                        policy,
                        max_path_bytes,
                    )
                    .await?;
                }
                FileType::Symlink => {
                    let target = fs.read_link(cred, &entry.handle).await?;
                    verify_multihop_symlink(fs, cred, &dir_comps, &target, policy, max_path_bytes)
                        .await?;
                }
                _ => {}
            }
        }
        Ok(())
    })
}

async fn verify_multihop_symlink<H: HeadStore + 'static, P: PackStore + 'static>(
    fs: &CowFs<H, P>,
    cred: &Cred,
    start_dir: &[String],
    initial_target: &str,
    policy: SymlinkPolicy,
    max_path_bytes: usize,
) -> Result<()> {
    validate_symlink_target(initial_target, start_dir.len(), policy, max_path_bytes)?;
    let mut stack: Vec<String> = if initial_target.starts_with('/') {
        Vec::new()
    } else {
        start_dir.to_vec()
    };
    let mut queue: std::collections::VecDeque<String> = initial_target
        .trim_start_matches('/')
        .split('/')
        .filter(|c| !c.is_empty())
        .map(str::to_owned)
        .collect();
    let mut hops = 0usize;

    while let Some(comp) = queue.pop_front() {
        match comp.as_str() {
            "." => continue,
            ".." => {
                if stack.pop().is_none() {
                    return Err(Errno::EACCES);
                }
                continue;
            }
            _ => {
                stack.push(comp);
            }
        }
        if let Ok(entry) = lookup_exact_no_follow(fs, cred, &stack).await
            && entry.metadata.file_type == FileType::Symlink
        {
            hops += 1;
            if hops > abi::MAXSYMLINKS {
                return Err(Errno::ELOOP);
            }
            let next_target = fs.read_link(cred, &entry.handle).await?;
            // Pop the symlink's own filename to resolve relative to its containing directory.
            stack.pop();
            validate_symlink_target(&next_target, stack.len(), policy, max_path_bytes)?;
            if next_target.starts_with('/') {
                stack.clear();
            }
            let next_parts: Vec<String> = next_target
                .trim_start_matches('/')
                .split('/')
                .filter(|c| !c.is_empty())
                .map(str::to_owned)
                .collect();
            for p in next_parts.into_iter().rev() {
                queue.push_front(p);
            }
        }
    }
    Ok(())
}

/// Apply one or more ordered OCI tar / tar+gzip layers into an open mutable [`CowFs`], verifying
/// DiffIDs, whiteouts, hard links, symlink confinement (including multi-hop resolution), and
/// `os_image` setuid policy, then commits the transaction group and verifies the volume strictly.
pub async fn import_oci_tar_layers_into_cowfs<H: HeadStore + 'static, P: PackStore + 'static>(
    fs: &CowFs<H, P>,
    layers: &[OciTarLayerInput<'_>],
    opts: &OciTarImportOptions,
    snapshot_name: Option<&str>,
) -> Result<OciImportReport> {
    if fs.is_read_only() {
        return Err(Errno::EROFS);
    }
    let cred = root_cred_zero_umask();
    let mut total_uncompressed = 0u64;
    let mut total_entries = 0usize;
    let mut diff_ids = Vec::with_capacity(layers.len());

    for layer in layers {
        let exceeded = Rc::new(Cell::new(false));
        let remaining_total = opts
            .max_total_uncompressed_bytes
            .saturating_sub(total_uncompressed);
        let reader: Box<dyn Read + '_> = if is_gzip(layer.bytes) {
            Box::new(MultiGzDecoder::new(Cursor::new(layer.bytes)))
        } else {
            Box::new(Cursor::new(layer.bytes))
        };
        let budget = BudgetReader::new(
            reader,
            opts.max_layer_uncompressed_bytes,
            remaining_total,
            Rc::clone(&exceeded),
        );
        let mut archive = tar::Archive::new(budget);
        let mut created_in_layer: HashSet<String> = HashSet::new();

        {
            let entries_iter = archive.entries().map_err(|_| {
                if exceeded.get() {
                    Errno::EFBIG
                } else {
                    Errno::EIO
                }
            })?;
            for entry_res in entries_iter {
                let mut entry = entry_res.map_err(|_| {
                    if exceeded.get() {
                        Errno::EFBIG
                    } else {
                        Errno::EIO
                    }
                })?;
                total_entries += 1;
                if total_entries > opts.max_entries {
                    return Err(Errno::EFBIG);
                }

                let etype = entry.header().entry_type();
                if matches!(
                    etype,
                    tar::EntryType::Char | tar::EntryType::Block | tar::EntryType::Fifo
                ) {
                    return Err(Errno::EPERM);
                }
                if matches!(
                    etype,
                    tar::EntryType::GNULongName
                        | tar::EntryType::GNULongLink
                        | tar::EntryType::XHeader
                        | tar::EntryType::XGlobalHeader
                ) {
                    continue;
                }

                let raw_path = entry.path_bytes();
                let comps =
                    normalize_tar_path(&raw_path, opts.max_path_bytes, opts.max_component_bytes)?;
                if comps.is_empty() {
                    continue;
                }
                let (parent_comps, name) = (&comps[..comps.len() - 1], &comps[comps.len() - 1]);
                let parent_handle =
                    ensure_parent_dir(fs, &cred, parent_comps, &mut created_in_layer).await?;
                let canon_path = format!("/{}", comps.join("/"));

                // Handle OCI whiteouts BEFORE mode/type processing.
                if name == ".wh..wh..opq" {
                    let parent_prefix = if parent_comps.is_empty() {
                        String::new()
                    } else {
                        format!("/{}", parent_comps.join("/"))
                    };
                    let existing = fs.read_dir(&cred, &parent_handle).await?;
                    for child in existing {
                        if child.name == "." || child.name == ".." {
                            continue;
                        }
                        let child_path = format!("{parent_prefix}/{}", child.name);
                        if !created_in_layer.contains(&child_path) {
                            rm_rf(fs, &cred, parent_handle.clone(), child.name).await?;
                        }
                    }
                    continue;
                }
                if let Some(victim) = name.strip_prefix(".wh.") {
                    if victim.is_empty()
                        || victim == "."
                        || victim == ".."
                        || victim.starts_with(".wh.")
                    {
                        return Err(Errno::EINVAL);
                    }
                    check_component(victim)?;
                    rm_rf(fs, &cred, parent_handle, victim.to_string()).await?;
                    continue;
                }

                let raw_mode = entry.header().mode().map_err(|_| Errno::EIO)? & 0o7777;
                if raw_mode & 0o6000 != 0 {
                    match opts.setuid_policy {
                        SetuidPolicy::Reject => return Err(Errno::EPERM),
                        SetuidPolicy::Strip => {}
                    }
                }
                let mode = (raw_mode & 0o1777) as u16;
                let uid = entry.header().uid().unwrap_or(0).min(u64::from(u32::MAX)) as u32;
                let gid = entry.header().gid().unwrap_or(0).min(u64::from(u32::MAX)) as u32;
                let mtime_sec = entry.header().mtime().unwrap_or(0);
                let ts = Timespec {
                    sec: mtime_sec,
                    nsec: 0,
                };

                match etype {
                    tar::EntryType::Directory => {
                        let dir_handle = match fs.lookup(&cred, &parent_handle, name).await {
                            Ok(existing) if existing.metadata.file_type == FileType::Dir => {
                                existing.handle
                            }
                            Ok(_) => {
                                rm_rf(fs, &cred, parent_handle.clone(), name.clone()).await?;
                                fs.mkdir(&cred, &parent_handle, name, mode).await?.handle
                            }
                            Err(Errno::ENOENT) => {
                                fs.mkdir(&cred, &parent_handle, name, mode).await?.handle
                            }
                            Err(e) => return Err(e),
                        };
                        fs.setattr(
                            &cred,
                            &dir_handle,
                            &SetAttr {
                                mode: Some(mode),
                                uid: Some(uid),
                                gid: Some(gid),
                                mtime: abi::Time::At {
                                    sec: ts.sec,
                                    nsec: ts.nsec,
                                },
                                ..Default::default()
                            },
                        )
                        .await?;
                        created_in_layer.insert(canon_path);
                    }
                    tar::EntryType::Regular | tar::EntryType::Continuous => {
                        let size = entry.header().size().map_err(|_| Errno::EIO)?;
                        if size > opts.max_file_bytes {
                            return Err(Errno::EFBIG);
                        }
                        if fs.lookup(&cred, &parent_handle, name).await.is_ok() {
                            rm_rf(fs, &cred, parent_handle.clone(), name.clone()).await?;
                        }
                        let mut create_opts = OpenOptions::new();
                        create_opts.read(true).write(true).create_new(true);
                        let (created, open_ref) = fs
                            .create(&cred, &parent_handle, name, 0o600, &create_opts)
                            .await?;
                        let mut offset = 0u64;
                        let mut buf = vec![0u8; 64 * 1024];
                        let write_res: Result<()> = async {
                            loop {
                                let n = entry.read(&mut buf).map_err(|_| {
                                    if exceeded.get() {
                                        Errno::EFBIG
                                    } else {
                                        Errno::EIO
                                    }
                                })?;
                                if n == 0 {
                                    break;
                                }
                                let next_off = offset.checked_add(n as u64).ok_or(Errno::EFBIG)?;
                                if next_off > opts.max_file_bytes {
                                    return Err(Errno::EFBIG);
                                }
                                fs.write_at(&open_ref, &buf[..n], WriteAt::Offset(offset))
                                    .await?;
                                offset = next_off;
                            }
                            Ok(())
                        }
                        .await;
                        let rel_res = fs.release(&open_ref).await;
                        write_res?;
                        rel_res?;
                        fs.setattr(
                            &cred,
                            &created.handle,
                            &SetAttr {
                                mode: Some(mode),
                                uid: Some(uid),
                                gid: Some(gid),
                                mtime: abi::Time::At {
                                    sec: ts.sec,
                                    nsec: ts.nsec,
                                },
                                ..Default::default()
                            },
                        )
                        .await?;
                        created_in_layer.insert(canon_path);
                    }
                    tar::EntryType::Link => {
                        let raw_link = entry.link_name_bytes().ok_or(Errno::EINVAL)?;
                        let target_comps = normalize_tar_path(
                            &raw_link,
                            opts.max_path_bytes,
                            opts.max_component_bytes,
                        )?;
                        if target_comps.is_empty() {
                            return Err(Errno::EPERM);
                        }
                        let target_entry = lookup_exact_no_follow(fs, &cred, &target_comps).await?;
                        if target_entry.metadata.file_type != FileType::File {
                            return Err(Errno::EPERM);
                        }
                        if fs.lookup(&cred, &parent_handle, name).await.is_ok() {
                            rm_rf(fs, &cred, parent_handle.clone(), name.clone()).await?;
                        }
                        fs.link(&cred, &target_entry.handle, &parent_handle, name)
                            .await?;
                        created_in_layer.insert(canon_path);
                    }
                    tar::EntryType::Symlink => {
                        let raw_link = entry.link_name_bytes().ok_or(Errno::EINVAL)?;
                        let target_str =
                            std::str::from_utf8(&raw_link).map_err(|_| Errno::EINVAL)?;
                        validate_symlink_target(
                            target_str,
                            parent_comps.len(),
                            opts.symlink_policy,
                            opts.max_path_bytes,
                        )?;
                        if fs.lookup(&cred, &parent_handle, name).await.is_ok() {
                            rm_rf(fs, &cred, parent_handle.clone(), name.clone()).await?;
                        }
                        let sym = fs.symlink(&cred, &parent_handle, name, target_str).await?;
                        fs.setattr(
                            &cred,
                            &sym.handle,
                            &SetAttr {
                                uid: Some(uid),
                                gid: Some(gid),
                                mtime: abi::Time::At {
                                    sec: ts.sec,
                                    nsec: ts.nsec,
                                },
                                ..Default::default()
                            },
                        )
                        .await?;
                        created_in_layer.insert(canon_path);
                    }
                    _ => return Err(Errno::EPERM),
                }
            }
        }

        let budget = archive.into_inner();
        let (actual_diff_id, layer_bytes) = budget.drain_and_finish()?;
        if let Some(expected) = layer.expected_diff_id
            && actual_diff_id != expected
        {
            return Err(Errno::EIO);
        }
        total_uncompressed = total_uncompressed.saturating_add(layer_bytes);
        diff_ids.push(actual_diff_id);
    }

    // Post-import multi-hop symlink chain verifier (`MAXSYMLINKS = 40`).
    verify_symlinks_in_tree(
        fs,
        &cred,
        fs.root(),
        Vec::new(),
        opts.symlink_policy,
        opts.max_path_bytes,
    )
    .await?;

    let head = fs.commit_tx_group().await?;
    let snap_out = if let Some(sname) = snapshot_name {
        fs.create_snapshot(sname).await?;
        Some(sname.to_string())
    } else {
        None
    };

    let hs = fs.head_store_rc();
    let ps = fs.pack_store_rc();
    let report = crate::fsck::verify_volume_strict(&*hs, &*ps, fs.volume_id()).await?;
    if !report.ok {
        return Err(Errno::EIO);
    }

    Ok(OciImportReport {
        volume: head.volume.0,
        root: digest_to_hex(&head.root),
        epoch: head.epoch,
        snapshot: snap_out,
        diff_ids,
        entries_imported: total_entries as u64,
        uncompressed_bytes: total_uncompressed,
    })
}

/// Format (if needed) or open `volume`, import all ordered OCI tar layers into it, and close cleanly.
#[allow(clippy::too_many_arguments)]
pub async fn import_oci_tar_layers<H: HeadStore + 'static, P: PackStore + 'static>(
    head_store: Rc<H>,
    pack_store: Rc<P>,
    volume: VolumeId,
    layers: &[OciTarLayerInput<'_>],
    opts: &OciTarImportOptions,
    snapshot_name: Option<&str>,
    config: CowFsConfig,
) -> Result<OciImportReport> {
    if head_store.read_head(&volume).await.is_err() {
        let now = (config.clock)();
        CowFs::format_volume(&*head_store, &*pack_store, volume.clone(), 0, 0, 0o755, now).await?;
    }
    let fs = CowFs::open(
        head_store,
        pack_store,
        volume,
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        config,
    )
    .await?;
    let res = import_oci_tar_layers_into_cowfs(&fs, layers, opts, snapshot_name).await;
    let close_res = fs.close_clean().await;
    let report = res?;
    close_res?;
    Ok(report)
}

struct HashingWriter<W: Write> {
    inner: W,
    hasher: Sha256,
    written: u64,
}

impl<W: Write> HashingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            written: 0,
        }
    }

    fn finish(self) -> (W, String, u64) {
        let digest: [u8; 32] = self.hasher.finalize().into();
        (
            self.inner,
            format!("sha256:{}", digest_to_hex(&digest)),
            self.written,
        )
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.written = self.written.saturating_add(n as u64);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

enum ExportNode {
    Dir {
        path: String,
        mode: u16,
        uid: u32,
        gid: u32,
        mtime: u64,
    },
    File {
        path: String,
        ino: u64,
        mode: u16,
        uid: u32,
        gid: u32,
        mtime: u64,
        size: u64,
        handle: Handle,
    },
    Symlink {
        path: String,
        uid: u32,
        gid: u32,
        mtime: u64,
        target: String,
    },
}

fn collect_canonical_tree<'a, H: HeadStore + 'static, P: PackStore + 'static>(
    fs: &'a CowFs<H, P>,
    cred: &'a Cred,
    dir: Handle,
    prefix: String,
    out: &'a mut Vec<ExportNode>,
) -> vfs::BoxFuture<'a, ()> {
    Box::pin(async move {
        let mut entries = fs.read_dir(cred, &dir).await?;
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        for de in entries {
            if de.name == "." || de.name == ".." {
                continue;
            }
            let entry = fs.lookup(cred, &dir, &de.name).await?;
            let rel_path = if prefix.is_empty() {
                de.name.clone()
            } else {
                format!("{prefix}/{}", de.name)
            };
            let m = &entry.metadata;
            match m.file_type {
                FileType::Dir => {
                    out.push(ExportNode::Dir {
                        path: rel_path.clone(),
                        mode: m.mode & 0o1777,
                        uid: m.uid,
                        gid: m.gid,
                        mtime: m.mtime.sec,
                    });
                    collect_canonical_tree(fs, cred, entry.handle, rel_path, out).await?;
                }
                FileType::File => {
                    out.push(ExportNode::File {
                        path: rel_path,
                        ino: entry.handle.node.ino,
                        mode: m.mode & 0o1777,
                        uid: m.uid,
                        gid: m.gid,
                        mtime: m.mtime.sec,
                        size: m.size,
                        handle: entry.handle,
                    });
                }
                FileType::Symlink => {
                    let target = fs.read_link(cred, &entry.handle).await?;
                    out.push(ExportNode::Symlink {
                        path: rel_path,
                        uid: m.uid,
                        gid: m.gid,
                        mtime: m.mtime.sec,
                        target,
                    });
                }
                _ => {}
            }
        }
        Ok(())
    })
}

async fn write_tar_entries<H: HeadStore + 'static, P: PackStore + 'static, W: Write>(
    fs: &CowFs<H, P>,
    cred: &Cred,
    nodes: Vec<ExportNode>,
    opts: &OciTarExportOptions,
    writer: W,
) -> Result<(W, u64)> {
    let mut builder = tar::Builder::new(writer);
    let mut seen_inodes: HashMap<u64, String> = HashMap::new();
    let mut exported = 0u64;

    for node in nodes {
        match node {
            ExportNode::Dir {
                path,
                mode,
                uid,
                gid,
                mtime,
            } => {
                let mut hdr = tar::Header::new_gnu();
                hdr.set_entry_type(tar::EntryType::Directory);
                hdr.set_size(0);
                hdr.set_mode(u32::from(mode & 0o1777));
                hdr.set_uid(u64::from(uid));
                hdr.set_gid(u64::from(gid));
                hdr.set_mtime(if opts.reproducible { 0 } else { mtime });
                hdr.set_cksum();
                builder
                    .append_data(&mut hdr, &path, io::empty())
                    .map_err(|_| Errno::EIO)?;
                exported += 1;
            }
            ExportNode::File {
                path,
                ino,
                mode,
                uid,
                gid,
                mtime,
                size,
                handle,
            } => {
                if let Some(first_path) = seen_inodes.get(&ino) {
                    let mut hdr = tar::Header::new_gnu();
                    hdr.set_entry_type(tar::EntryType::Link);
                    hdr.set_size(0);
                    hdr.set_mode(u32::from(mode & 0o1777));
                    hdr.set_uid(u64::from(uid));
                    hdr.set_gid(u64::from(gid));
                    hdr.set_mtime(if opts.reproducible { 0 } else { mtime });
                    hdr.set_cksum();
                    builder
                        .append_link(&mut hdr, &path, first_path)
                        .map_err(|_| Errno::EIO)?;
                    exported += 1;
                    continue;
                }
                if size > opts.max_file_bytes {
                    return Err(Errno::EFBIG);
                }
                let mut read_opts = OpenOptions::new();
                read_opts.read(true);
                let open_ref = fs.open(cred, &handle, &read_opts).await?;
                let mut file_bytes = Vec::with_capacity(size.min(1024 * 1024) as usize);
                let mut offset = 0u64;
                let mut chunk = vec![0u8; 64 * 1024];
                let read_res: Result<()> = async {
                    while offset < size {
                        let want = (size - offset).min(chunk.len() as u64) as usize;
                        let n = fs.read_at(&open_ref, &mut chunk[..want], offset).await?;
                        if n == 0 {
                            break;
                        }
                        file_bytes.extend_from_slice(&chunk[..n]);
                        offset += n as u64;
                    }
                    Ok(())
                }
                .await;
                let rel_res = fs.release(&open_ref).await;
                read_res?;
                rel_res?;
                if file_bytes.len() as u64 != size {
                    return Err(Errno::EIO);
                }
                let mut hdr = tar::Header::new_gnu();
                hdr.set_entry_type(tar::EntryType::Regular);
                hdr.set_size(size);
                hdr.set_mode(u32::from(mode & 0o1777));
                hdr.set_uid(u64::from(uid));
                hdr.set_gid(u64::from(gid));
                hdr.set_mtime(if opts.reproducible { 0 } else { mtime });
                hdr.set_cksum();
                builder
                    .append_data(&mut hdr, &path, Cursor::new(&file_bytes))
                    .map_err(|_| Errno::EIO)?;
                seen_inodes.insert(ino, path);
                exported += 1;
            }
            ExportNode::Symlink {
                path,
                uid,
                gid,
                mtime,
                target,
            } => {
                let mut hdr = tar::Header::new_gnu();
                hdr.set_entry_type(tar::EntryType::Symlink);
                hdr.set_size(0);
                hdr.set_mode(0o777);
                hdr.set_uid(u64::from(uid));
                hdr.set_gid(u64::from(gid));
                hdr.set_mtime(if opts.reproducible { 0 } else { mtime });
                hdr.set_cksum();
                builder
                    .append_link(&mut hdr, &path, &target)
                    .map_err(|_| Errno::EIO)?;
                exported += 1;
            }
        }
    }

    let inner = builder.into_inner().map_err(|_| Errno::EIO)?;
    Ok((inner, exported))
}

/// Export a pinned [`CowFs`] tree as a reproducible OCI tar or tar+gzip layer, simultaneously
/// computing the exact uncompressed `DiffID` and compressed blob SHA-256 digest.
pub async fn export_cowfs_oci_tar_layer<H: HeadStore + 'static, P: PackStore + 'static>(
    fs: &CowFs<H, P>,
    opts: &OciTarExportOptions,
) -> Result<OciExportedLayer> {
    let cred = root_cred_zero_umask();
    let mut nodes = Vec::new();
    collect_canonical_tree(fs, &cred, fs.root(), String::new(), &mut nodes).await?;

    if opts.compress {
        let compressed_writer = HashingWriter::new(Vec::<u8>::new());
        let gz_writer = GzBuilder::new()
            .mtime(0)
            .operating_system(3)
            .write(compressed_writer, Compression::default());
        let tar_hashing = HashingWriter::new(gz_writer);
        let (tar_hashing, entries_exported) =
            write_tar_entries(fs, &cred, nodes, opts, tar_hashing).await?;
        let (gz_writer, diff_id, uncompressed_size) = tar_hashing.finish();
        let compressed_writer = gz_writer.finish().map_err(|_| Errno::EIO)?;
        let (bytes, blob_digest, blob_size) = compressed_writer.finish();
        Ok(OciExportedLayer {
            bytes,
            media_type: OCI_LAYER_TAR_GZIP_MEDIA_TYPE.into(),
            diff_id,
            blob_digest,
            blob_size,
            uncompressed_size,
            entries_exported,
        })
    } else {
        let raw_writer = HashingWriter::new(Vec::<u8>::new());
        let (raw_writer, entries_exported) =
            write_tar_entries(fs, &cred, nodes, opts, raw_writer).await?;
        let (bytes, digest, size) = raw_writer.finish();
        Ok(OciExportedLayer {
            bytes,
            media_type: OCI_LAYER_TAR_MEDIA_TYPE.into(),
            diff_id: digest.clone(),
            blob_digest: digest,
            blob_size: size,
            uncompressed_size: size,
            entries_exported,
        })
    }
}

/// Build a canonical OCI Image Config (`application/vnd.oci.image.config.v1+json`) from layer
/// uncompressed `diff_ids`.
pub fn build_oci_image_config(
    diff_ids: Vec<String>,
    architecture: &str,
    os: &str,
    runtime_config: Option<OciRuntimeConfig>,
) -> Result<(OciImageConfig, Vec<u8>, OciDescriptor)> {
    for d in &diff_ids {
        if parse_sha256_digest(d).is_none() {
            return Err(Errno::EINVAL);
        }
    }
    let cfg = OciImageConfig {
        created: Some("1970-01-01T00:00:00Z".into()),
        architecture: architecture.into(),
        os: os.into(),
        config: runtime_config,
        rootfs: OciRootFs {
            kind: "layers".into(),
            diff_ids,
        },
    };
    let bytes = serde_json::to_vec(&cfg).map_err(|_| Errno::EIO)?;
    let digest = format!("sha256:{}", digest_to_hex(&cowtree::sha256(&bytes)));
    let desc = OciDescriptor {
        media_type: OCI_IMAGE_CONFIG_MEDIA_TYPE.into(),
        digest,
        size: bytes.len() as u64,
        urls: None,
        annotations: None,
        artifact_type: None,
        platform: None,
        data: None,
    };
    Ok((cfg, bytes, desc))
}

/// Build a canonical OCI Image Manifest (`application/vnd.oci.image.manifest.v1+json`).
pub fn build_oci_image_manifest(
    config: OciDescriptor,
    layers: Vec<OciDescriptor>,
    annotations: Option<BTreeMap<String, String>>,
) -> Result<(OciImageManifest, Vec<u8>, String)> {
    let manifest = OciImageManifest {
        schema_version: 2,
        media_type: Some(OCI_IMAGE_MANIFEST_MEDIA_TYPE.into()),
        artifact_type: None,
        config,
        layers,
        subject: None,
        annotations,
    };
    let bytes = serde_json::to_vec(&manifest).map_err(|_| Errno::EIO)?;
    let digest = format!("sha256:{}", digest_to_hex(&cowtree::sha256(&bytes)));
    Ok((manifest, bytes, digest))
}

/// Export a pinned `cowfs` root as a standard runnable OCI tar+gzip image and push its config,
/// layer, and manifest directly to an OCI Distribution v1.1 registry (pullable by `podman pull`).
#[allow(clippy::too_many_arguments)]
pub async fn export_and_push_oci_image<
    H: HeadStore + 'static,
    P: PackStore + 'static,
    T: OciTransport,
>(
    fs: &CowFs<H, P>,
    client: &OciClient<T>,
    repo: &str,
    reference: &str,
    export_opts: &OciTarExportOptions,
    architecture: &str,
    os: &str,
    runtime_config: Option<OciRuntimeConfig>,
) -> Result<CowfsOciPushResp> {
    let layer = export_cowfs_oci_tar_layer(fs, export_opts).await?;
    let (_cfg, cfg_bytes, cfg_desc) = build_oci_image_config(
        vec![layer.diff_id.clone()],
        architecture,
        os,
        runtime_config,
    )?;
    let layer_desc = OciDescriptor {
        media_type: layer.media_type.clone(),
        digest: layer.blob_digest.clone(),
        size: layer.blob_size,
        urls: None,
        annotations: None,
        artifact_type: None,
        platform: None,
        data: None,
    };
    let (_manifest, manifest_bytes, _mdig) =
        build_oci_image_manifest(cfg_desc.clone(), vec![layer_desc], None)?;

    let mut bytes_pushed = 0u64;
    if client.head_blob(repo, &cfg_desc.digest).await?.is_none() {
        client
            .put_blob_monolithic(repo, &cfg_desc.digest, &cfg_bytes)
            .await?;
        bytes_pushed += cfg_bytes.len() as u64;
    }
    if client.head_blob(repo, &layer.blob_digest).await?.is_none() {
        client
            .put_blob_monolithic(repo, &layer.blob_digest, &layer.bytes)
            .await?;
        bytes_pushed += layer.blob_size;
    }
    let (manifest_digest, _) = client
        .put_manifest(
            repo,
            reference,
            OCI_IMAGE_MANIFEST_MEDIA_TYPE,
            &manifest_bytes,
        )
        .await?;
    Ok(CowfsOciPushResp {
        repo: repo.into(),
        reference: reference.into(),
        manifest_digest,
        media_type: OCI_IMAGE_MANIFEST_MEDIA_TYPE.into(),
        shards: 1,
        packs_pushed: 1,
        bytes_pushed,
    })
}

//! Pure-Rust Linux `/dev/fuse` ABI v7.31 daemon (`fusermount3` + `SCM_RIGHTS` fd handoff) backed
//! directly by a live fenced `os_cowfs::CowFs` (`Phase 9.5 #85`).

use abi::Errno;
use abi::fs::{
    DirEntry, FileType, Handle, Metadata, OpenOptions, OpenRef, RenameFlags, SetAttr, WriteAt,
};
use cowtree::{HeadStore, PackStore};
use os_cowfs::CowFs;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::process::Command;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, oneshot};
use vfs::{Cred, Filesystem};

pub const FUSE_KERNEL_VERSION: u32 = 7;
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 31;
pub const FUSE_ROOT_ID: u64 = 1;
pub const FUSE_MAX_WRITE: u32 = 128 * 1024;
pub const FUSE_MAX_FRAME_BYTES: usize = FUSE_MAX_WRITE as usize + 4096;

// Linux FUSE opcodes
pub const FUSE_LOOKUP: u32 = 1;
pub const FUSE_FORGET: u32 = 2;
pub const FUSE_GETATTR: u32 = 3;
pub const FUSE_SETATTR: u32 = 4;
pub const FUSE_READLINK: u32 = 5;
pub const FUSE_SYMLINK: u32 = 6;
pub const FUSE_MKDIR: u32 = 9;
pub const FUSE_UNLINK: u32 = 10;
pub const FUSE_RMDIR: u32 = 11;
pub const FUSE_RENAME: u32 = 12;
pub const FUSE_OPEN: u32 = 14;
pub const FUSE_READ: u32 = 15;
pub const FUSE_WRITE: u32 = 16;
pub const FUSE_STATFS: u32 = 17;
pub const FUSE_RELEASE: u32 = 18;
pub const FUSE_FSYNC: u32 = 20;
pub const FUSE_FLUSH: u32 = 25;
pub const FUSE_INIT: u32 = 26;
pub const FUSE_OPENDIR: u32 = 27;
pub const FUSE_READDIR: u32 = 28;
pub const FUSE_RELEASEDIR: u32 = 29;
pub const FUSE_FSYNCDIR: u32 = 30;
pub const FUSE_CREATE: u32 = 35;
pub const FUSE_DESTROY: u32 = 38;
pub const FUSE_BATCH_FORGET: u32 = 42;
pub const FUSE_RENAME2: u32 = 45;

// Linux renameat2(2) flags
const LINUX_RENAME_NOREPLACE: u32 = 1 << 0;

// FUSE_SETATTR valid bits
const FATTR_MODE: u32 = 1 << 0;
const FATTR_UID: u32 = 1 << 1;
const FATTR_GID: u32 = 1 << 2;
const FATTR_SIZE: u32 = 1 << 3;
const FATTR_ATIME: u32 = 1 << 4;
const FATTR_MTIME: u32 = 1 << 5;
const FATTR_ATIME_NOW: u32 = 1 << 7;
const FATTR_MTIME_NOW: u32 = 1 << 8;

const FUSE_IN_HEADER_BYTES: usize = 40;
const FUSE_OUT_HEADER_BYTES: usize = 16;

fn abi_errno_to_linux(err: Errno) -> i32 {
    match err {
        Errno::EPERM => libc::EPERM,
        Errno::ENOENT => libc::ENOENT,
        Errno::EIO => libc::EIO,
        Errno::EBADF => libc::EBADF,
        Errno::EAGAIN => libc::EAGAIN,
        Errno::EACCES => libc::EACCES,
        Errno::EBUSY => libc::EBUSY,
        Errno::EEXIST => libc::EEXIST,
        Errno::EXDEV => libc::EXDEV,
        Errno::ENODEV => libc::ENODEV,
        Errno::ENOTDIR => libc::ENOTDIR,
        Errno::EISDIR => libc::EISDIR,
        Errno::EINVAL => libc::EINVAL,
        Errno::EFBIG => libc::EFBIG,
        Errno::ENOSPC => libc::ENOSPC,
        Errno::EROFS => libc::EROFS,
        Errno::ENOTEMPTY => libc::ENOTEMPTY,
        Errno::ELOOP => libc::ELOOP,
        Errno::ENAMETOOLONG => libc::ENAMETOOLONG,
        Errno::ENOSYS => libc::ENOSYS,
        Errno::EOPNOTSUPP => libc::EOPNOTSUPP,
        Errno::ESTALE => libc::ESTALE,
        _ => libc::EIO,
    }
}

fn read_u32_le(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u64_le(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off + 8)?;
    Some(u64::from_le_bytes(s.try_into().ok()?))
}

fn read_cstr(b: &[u8]) -> Option<(&str, &[u8])> {
    let nul = b.iter().position(|&c| c == 0)?;
    let s = std::str::from_utf8(&b[..nul]).ok()?;
    Some((s, &b[nul + 1..]))
}

fn encode_out_frame(unique: u64, error: i32, body: &[u8]) -> Vec<u8> {
    let total = (FUSE_OUT_HEADER_BYTES + body.len()) as u32;
    let mut out = Vec::with_capacity(total as usize);
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(&error.to_le_bytes());
    out.extend_from_slice(&unique.to_le_bytes());
    out.extend_from_slice(body);
    out
}

fn encode_fuse_attr(ino: u64, meta: &Metadata) -> [u8; 88] {
    let mut b = [0u8; 88];
    let mode = meta.file_type.mode_bits() | u32::from(meta.mode & 0o7777);
    let blocks = meta.size.div_ceil(512);
    b[0..8].copy_from_slice(&ino.to_le_bytes());
    b[8..16].copy_from_slice(&meta.size.to_le_bytes());
    b[16..24].copy_from_slice(&blocks.to_le_bytes());
    b[24..32].copy_from_slice(&meta.atime.sec.to_le_bytes());
    b[32..40].copy_from_slice(&meta.mtime.sec.to_le_bytes());
    b[40..48].copy_from_slice(&meta.ctime.sec.to_le_bytes());
    b[48..52].copy_from_slice(&meta.atime.nsec.to_le_bytes());
    b[52..56].copy_from_slice(&meta.mtime.nsec.to_le_bytes());
    b[56..60].copy_from_slice(&meta.ctime.nsec.to_le_bytes());
    b[60..64].copy_from_slice(&mode.to_le_bytes());
    b[64..68].copy_from_slice(&meta.nlink.to_le_bytes());
    b[68..72].copy_from_slice(&meta.uid.to_le_bytes());
    b[72..76].copy_from_slice(&meta.gid.to_le_bytes());
    b[76..80].copy_from_slice(&0u32.to_le_bytes()); // rdev
    b[80..84].copy_from_slice(&4096u32.to_le_bytes()); // blksize
    b[84..88].copy_from_slice(&0u32.to_le_bytes()); // padding
    b
}

fn encode_entry_out(nodeid: u64, generation: u64, meta: &Metadata) -> [u8; 128] {
    let mut b = [0u8; 128];
    b[0..8].copy_from_slice(&nodeid.to_le_bytes());
    b[8..16].copy_from_slice(&generation.to_le_bytes());
    b[16..24].copy_from_slice(&1u64.to_le_bytes()); // entry_valid = 1s
    b[24..32].copy_from_slice(&1u64.to_le_bytes()); // attr_valid = 1s
    b[32..36].copy_from_slice(&0u32.to_le_bytes());
    b[36..40].copy_from_slice(&0u32.to_le_bytes());
    b[40..128].copy_from_slice(&encode_fuse_attr(nodeid, meta));
    b
}

fn encode_attr_out(nodeid: u64, meta: &Metadata) -> [u8; 104] {
    let mut b = [0u8; 104];
    b[0..8].copy_from_slice(&1u64.to_le_bytes()); // attr_valid
    b[8..12].copy_from_slice(&0u32.to_le_bytes());
    b[12..16].copy_from_slice(&0u32.to_le_bytes());
    b[16..104].copy_from_slice(&encode_fuse_attr(nodeid, meta));
    b
}

fn encode_open_out(fh: u64) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0..8].copy_from_slice(&fh.to_le_bytes());
    b
}

fn encode_init_out() -> [u8; 64] {
    let mut b = [0u8; 64];
    b[0..4].copy_from_slice(&FUSE_KERNEL_VERSION.to_le_bytes());
    b[4..8].copy_from_slice(&FUSE_KERNEL_MINOR_VERSION.to_le_bytes());
    b[8..12].copy_from_slice(&(128u32 * 1024).to_le_bytes()); // max_readahead
    b[12..16].copy_from_slice(&0u32.to_le_bytes()); // flags
    b[16..18].copy_from_slice(&16u16.to_le_bytes()); // max_background
    b[18..20].copy_from_slice(&12u16.to_le_bytes()); // congestion_threshold
    b[20..24].copy_from_slice(&FUSE_MAX_WRITE.to_le_bytes()); // max_write
    b[24..28].copy_from_slice(&1u32.to_le_bytes()); // time_gran
    b[28..30].copy_from_slice(&32u16.to_le_bytes()); // max_pages
    b
}

fn dtype_from_filetype(ft: FileType) -> u32 {
    match ft {
        FileType::File => libc::DT_REG as u32,
        FileType::Dir => libc::DT_DIR as u32,
        FileType::Symlink => libc::DT_LNK as u32,
        FileType::CharDevice => libc::DT_CHR as u32,
        FileType::Socket => libc::DT_SOCK as u32,
    }
}

fn cred_from_header(uid: u32, gid: u32) -> Cred {
    let mut cred = Cred::new(os_core::permissions::Identity {
        id: uid,
        group: gid,
        groups: std::collections::BTreeSet::from([gid]),
    });
    cred.umask = 0;
    cred
}

fn open_options_from_posix_flags(flags: u32) -> OpenOptions {
    let mut opts = OpenOptions::new();
    let acc = (flags as i32) & libc::O_ACCMODE;
    let writable = matches!(acc, libc::O_WRONLY | libc::O_RDWR);
    match acc {
        libc::O_RDONLY => {
            opts.read(true);
        }
        libc::O_WRONLY => {
            opts.write(true);
        }
        libc::O_RDWR => {
            opts.read(true).write(true);
        }
        _ => {
            opts.read(true);
        }
    }
    // Only set `append` when write access was requested (so `O_RDONLY | O_APPEND` does not
    // implicitly promote to write access via `OpenOptions::append`).
    if writable && ((flags as i32) & libc::O_APPEND != 0) {
        opts.append(true);
    }
    if (flags as i32) & libc::O_TRUNC != 0 {
        opts.truncate(true);
    }
    if (flags as i32) & libc::O_CREAT != 0 {
        if (flags as i32) & libc::O_EXCL != 0 {
            opts.create_new(true);
        } else {
            opts.create(true);
        }
    }
    opts
}

struct NodeSlot {
    handle: Handle,
    nlookup: u64,
}

/// Live Linux `/dev/fuse` ABI v7.31 session backed directly by a fenced [`CowFs`].
/// Supports single-writer handoff (`ACQUIRE`/`RELEASE`) to `containerd-shim-os-v1`, returning
/// `-EBUSY` to host FUSE requests while handed off.
pub struct FuseCowFsSession<H: HeadStore + 'static, P: PackStore + 'static> {
    fs: Option<Rc<CowFs<H, P>>>,
    readonly: bool,
    fence_flag: Arc<AtomicBool>,
    on_fenced: Option<Arc<dyn Fn() + Send + Sync>>,
    nodes: HashMap<u64, NodeSlot>,
    open_files: HashMap<u64, OpenRef>,
    open_dirs: HashMap<u64, Vec<DirEntry>>,
    next_fh: u64,
}

impl<H: HeadStore + 'static, P: PackStore + 'static> FuseCowFsSession<H, P> {
    pub fn new(fs: Rc<CowFs<H, P>>, fence_flag: Arc<AtomicBool>) -> Self {
        let readonly = fs.is_read_only();
        let mut nodes = HashMap::new();
        nodes.insert(
            FUSE_ROOT_ID,
            NodeSlot {
                handle: fs.root(),
                nlookup: 1,
            },
        );
        Self {
            fs: Some(fs),
            readonly,
            fence_flag,
            on_fenced: None,
            nodes,
            open_files: HashMap::new(),
            open_dirs: HashMap::new(),
            next_fh: 1,
        }
    }

    pub fn with_on_fenced(mut self, cb: Arc<dyn Fn() + Send + Sync>) -> Self {
        self.on_fenced = Some(cb);
        self
    }

    pub fn is_fenced(&self) -> bool {
        self.fence_flag.load(Ordering::SeqCst)
    }

    fn trip_fence(&self) {
        self.fence_flag.store(true, Ordering::SeqCst);
        if let Some(ref cb) = self.on_fenced {
            cb();
        }
    }

    fn check_write_fence(&self) -> Result<(), Errno> {
        if self.readonly {
            return Err(Errno::EROFS);
        }
        if self.fence_flag.load(Ordering::SeqCst) {
            return Err(Errno::ESTALE);
        }
        Ok(())
    }

    fn map_err(&self, err: Errno) -> i32 {
        if err == Errno::ESTALE {
            self.trip_fence();
        }
        -abi_errno_to_linux(err)
    }

    /// Flush & release exclusive `CowFs` ownership so `containerd-shim-os-v1` can attach
    /// `WriterMode::Exclusive` without self-fencing. While handed off, host FUSE requests
    /// receive `-EBUSY`.
    pub async fn handoff_acquire(&mut self) -> Result<(), Errno> {
        if self.readonly {
            return Err(Errno::EROFS);
        }
        if self.fence_flag.load(Ordering::SeqCst) {
            return Err(Errno::ESTALE);
        }
        let Some(fs) = self.fs.as_ref() else {
            return Err(Errno::EBUSY);
        };
        let r1 = fs.renew_lease().await;
        let r2 = if r1.is_ok() {
            fs.commit_tx_group().await.map(|_| ())
        } else {
            r1
        };
        if r2 == Err(Errno::ESTALE) {
            self.trip_fence();
            if let Some(fs) = self.fs.take() {
                for (_, open_ref) in self.open_files.drain() {
                    let _ = fs.release(&open_ref).await;
                }
                self.open_dirs.clear();
                let _ = fs.close_clean().await;
            }
            return Err(Errno::ESTALE);
        }
        // Preserve active `CowFs` on transient errors so the FUSE session is never wedged.
        r2?;
        if let Some(fs) = self.fs.take() {
            for (_, open_ref) in self.open_files.drain() {
                let _ = fs.release(&open_ref).await;
            }
            self.open_dirs.clear();
            let _ = fs.close_clean().await;
        }
        Ok(())
    }

    /// Re-attach a freshly opened `CowFs` after `containerd-shim-os-v1` signals `RELEASE`.
    pub fn handoff_release_reopen(&mut self, fs: Rc<CowFs<H, P>>) {
        self.nodes.insert(
            FUSE_ROOT_ID,
            NodeSlot {
                handle: fs.root(),
                nlookup: 1,
            },
        );
        self.fs = Some(fs);
    }

    /// Flush and cleanly close the underlying `CowFs`, propagating `ESTALE` if fenced.
    pub async fn close_clean(&mut self) -> Result<(), Errno> {
        if let Some(fs) = self.fs.take() {
            for (_, open_ref) in self.open_files.drain() {
                let _ = fs.release(&open_ref).await;
            }
            self.open_dirs.clear();
            if !self.readonly && !self.fence_flag.load(Ordering::SeqCst) {
                let r = fs.commit_tx_group().await.map(|_| ());
                let c = fs.close_clean().await;
                if r == Err(Errno::ESTALE) || c == Err(Errno::ESTALE) {
                    self.trip_fence();
                    return Err(Errno::ESTALE);
                }
                r?;
                c?;
                Ok(())
            } else {
                let _ = fs.close_clean().await;
                if self.fence_flag.load(Ordering::SeqCst) {
                    Err(Errno::ESTALE)
                } else {
                    Ok(())
                }
            }
        } else if self.fence_flag.load(Ordering::SeqCst) {
            Err(Errno::ESTALE)
        } else {
            Ok(())
        }
    }

    fn handle_for_node(&self, nodeid: u64) -> Result<Handle, Errno> {
        self.nodes
            .get(&nodeid)
            .map(|s| s.handle.clone())
            .ok_or(Errno::ENOENT)
    }

    fn register_node(&mut self, handle: Handle) -> u64 {
        let nodeid = handle.node.ino;
        if let Some(slot) = self.nodes.get_mut(&nodeid) {
            slot.handle = handle;
            slot.nlookup = slot.nlookup.saturating_add(1);
        } else {
            self.nodes.insert(nodeid, NodeSlot { handle, nlookup: 1 });
        }
        nodeid
    }

    fn alloc_fh(&mut self) -> u64 {
        let fh = self.next_fh;
        self.next_fh = self.next_fh.wrapping_add(1).max(1);
        fh
    }

    /// Process a single raw `/dev/fuse` request frame and return the raw reply frame (`None` for
    /// one-way notifications like `FUSE_FORGET`).
    pub async fn handle_request(&mut self, req: &[u8]) -> Option<Vec<u8>> {
        if req.len() < FUSE_IN_HEADER_BYTES {
            return None;
        }
        let in_len = read_u32_le(req, 0)? as usize;
        if in_len < FUSE_IN_HEADER_BYTES || in_len > req.len() {
            return None;
        }
        let opcode = read_u32_le(req, 4)?;
        let unique = read_u64_le(req, 8)?;
        let nodeid = read_u64_le(req, 16)?;
        let uid = read_u32_le(req, 24)?;
        let gid = read_u32_le(req, 28)?;
        let body = &req[FUSE_IN_HEADER_BYTES..in_len];
        let cred = cred_from_header(uid, gid);

        match opcode {
            FUSE_INIT => return Some(encode_out_frame(unique, 0, &encode_init_out())),
            FUSE_DESTROY => return Some(encode_out_frame(unique, 0, &[])),
            FUSE_FORGET => {
                if let Some(nlookup) = read_u64_le(body, 0)
                    && nodeid != FUSE_ROOT_ID
                    && let Some(slot) = self.nodes.get_mut(&nodeid)
                {
                    slot.nlookup = slot.nlookup.saturating_sub(nlookup);
                    if slot.nlookup == 0 {
                        self.nodes.remove(&nodeid);
                    }
                }
                return None;
            }
            FUSE_BATCH_FORGET => {
                if let Some(count) = read_u32_le(body, 0) {
                    let max_items = body.len().saturating_sub(8) / 16;
                    let n = (count as usize).min(max_items);
                    for i in 0..n {
                        let base = 8 + i * 16;
                        if let (Some(ino), Some(nlookup)) =
                            (read_u64_le(body, base), read_u64_le(body, base + 8))
                            && ino != FUSE_ROOT_ID
                            && let Some(slot) = self.nodes.get_mut(&ino)
                        {
                            slot.nlookup = slot.nlookup.saturating_sub(nlookup);
                            if slot.nlookup == 0 {
                                self.nodes.remove(&ino);
                            }
                        }
                    }
                }
                return None;
            }
            _ => {}
        }

        let Some(fs) = self.fs.as_ref().map(Rc::clone) else {
            return Some(encode_out_frame(unique, -libc::EBUSY, &[]));
        };

        match opcode {
            FUSE_LOOKUP => {
                let Some((name, _)) = read_cstr(body) else {
                    return Some(encode_out_frame(unique, -libc::EINVAL, &[]));
                };
                let dir_h = match self.handle_for_node(nodeid) {
                    Ok(h) => h,
                    Err(e) => return Some(encode_out_frame(unique, self.map_err(e), &[])),
                };
                match fs.lookup(&cred, &dir_h, name).await {
                    Ok(ent) => {
                        let generation = ent.handle.node.generation;
                        let nid = self.register_node(ent.handle);
                        Some(encode_out_frame(
                            unique,
                            0,
                            &encode_entry_out(nid, generation, &ent.metadata),
                        ))
                    }
                    Err(e) => Some(encode_out_frame(unique, self.map_err(e), &[])),
                }
            }
            FUSE_GETATTR => {
                let h = match self.handle_for_node(nodeid) {
                    Ok(h) => h,
                    Err(e) => return Some(encode_out_frame(unique, self.map_err(e), &[])),
                };
                match fs.metadata(&cred, &h).await {
                    Ok(meta) => Some(encode_out_frame(unique, 0, &encode_attr_out(nodeid, &meta))),
                    Err(e) => Some(encode_out_frame(unique, self.map_err(e), &[])),
                }
            }
            FUSE_SETATTR => {
                if let Err(e) = self.check_write_fence() {
                    return Some(encode_out_frame(unique, self.map_err(e), &[]));
                }
                if body.len() < 88 {
                    return Some(encode_out_frame(unique, -libc::EINVAL, &[]));
                }
                let valid = read_u32_le(body, 0).unwrap_or(0);
                let size = read_u64_le(body, 16).unwrap_or(0);
                let atime_s = read_u64_le(body, 32).unwrap_or(0);
                let mtime_s = read_u64_le(body, 40).unwrap_or(0);
                let atime_ns = read_u32_le(body, 56).unwrap_or(0);
                let mtime_ns = read_u32_le(body, 60).unwrap_or(0);
                let mode = read_u32_le(body, 68).unwrap_or(0);
                let set_uid = read_u32_le(body, 76).unwrap_or(0);
                let set_gid = read_u32_le(body, 80).unwrap_or(0);
                let h = match self.handle_for_node(nodeid) {
                    Ok(h) => h,
                    Err(e) => return Some(encode_out_frame(unique, self.map_err(e), &[])),
                };
                let attr = SetAttr {
                    mode: (valid & FATTR_MODE != 0).then_some((mode & 0o7777) as u16),
                    uid: (valid & FATTR_UID != 0).then_some(set_uid),
                    gid: (valid & FATTR_GID != 0).then_some(set_gid),
                    size: (valid & FATTR_SIZE != 0).then_some(size),
                    atime: if valid & FATTR_ATIME_NOW != 0 {
                        abi::Time::Now
                    } else if valid & FATTR_ATIME != 0 {
                        abi::Time::At {
                            sec: atime_s,
                            nsec: atime_ns,
                        }
                    } else {
                        abi::Time::Omit
                    },
                    mtime: if valid & FATTR_MTIME_NOW != 0 {
                        abi::Time::Now
                    } else if valid & FATTR_MTIME != 0 {
                        abi::Time::At {
                            sec: mtime_s,
                            nsec: mtime_ns,
                        }
                    } else {
                        abi::Time::Omit
                    },
                };
                match fs.setattr(&cred, &h, &attr).await {
                    Ok(meta) => Some(encode_out_frame(unique, 0, &encode_attr_out(nodeid, &meta))),
                    Err(e) => Some(encode_out_frame(unique, self.map_err(e), &[])),
                }
            }
            FUSE_READLINK => {
                let h = match self.handle_for_node(nodeid) {
                    Ok(h) => h,
                    Err(e) => return Some(encode_out_frame(unique, self.map_err(e), &[])),
                };
                match fs.read_link(&cred, &h).await {
                    Ok(target) => Some(encode_out_frame(unique, 0, target.as_bytes())),
                    Err(e) => Some(encode_out_frame(unique, self.map_err(e), &[])),
                }
            }
            FUSE_SYMLINK => {
                if let Err(e) = self.check_write_fence() {
                    return Some(encode_out_frame(unique, self.map_err(e), &[]));
                }
                let Some((name, rest)) = read_cstr(body) else {
                    return Some(encode_out_frame(unique, -libc::EINVAL, &[]));
                };
                let Some((target, _)) = read_cstr(rest) else {
                    return Some(encode_out_frame(unique, -libc::EINVAL, &[]));
                };
                let dir_h = match self.handle_for_node(nodeid) {
                    Ok(h) => h,
                    Err(e) => return Some(encode_out_frame(unique, self.map_err(e), &[])),
                };
                match fs.symlink(&cred, &dir_h, name, target).await {
                    Ok(ent) => {
                        let generation = ent.handle.node.generation;
                        let nid = self.register_node(ent.handle);
                        Some(encode_out_frame(
                            unique,
                            0,
                            &encode_entry_out(nid, generation, &ent.metadata),
                        ))
                    }
                    Err(e) => Some(encode_out_frame(unique, self.map_err(e), &[])),
                }
            }
            FUSE_MKDIR => {
                if let Err(e) = self.check_write_fence() {
                    return Some(encode_out_frame(unique, self.map_err(e), &[]));
                }
                if body.len() < 8 {
                    return Some(encode_out_frame(unique, -libc::EINVAL, &[]));
                }
                let mode = (read_u32_le(body, 0).unwrap_or(0o755) & 0o7777) as u16;
                let Some((name, _)) = read_cstr(&body[8..]) else {
                    return Some(encode_out_frame(unique, -libc::EINVAL, &[]));
                };
                let dir_h = match self.handle_for_node(nodeid) {
                    Ok(h) => h,
                    Err(e) => return Some(encode_out_frame(unique, self.map_err(e), &[])),
                };
                match fs.mkdir(&cred, &dir_h, name, mode).await {
                    Ok(ent) => {
                        let generation = ent.handle.node.generation;
                        let nid = self.register_node(ent.handle);
                        Some(encode_out_frame(
                            unique,
                            0,
                            &encode_entry_out(nid, generation, &ent.metadata),
                        ))
                    }
                    Err(e) => Some(encode_out_frame(unique, self.map_err(e), &[])),
                }
            }
            FUSE_UNLINK => {
                if let Err(e) = self.check_write_fence() {
                    return Some(encode_out_frame(unique, self.map_err(e), &[]));
                }
                let Some((name, _)) = read_cstr(body) else {
                    return Some(encode_out_frame(unique, -libc::EINVAL, &[]));
                };
                let dir_h = match self.handle_for_node(nodeid) {
                    Ok(h) => h,
                    Err(e) => return Some(encode_out_frame(unique, self.map_err(e), &[])),
                };
                match fs.unlink(&cred, &dir_h, name).await {
                    Ok(()) => Some(encode_out_frame(unique, 0, &[])),
                    Err(e) => Some(encode_out_frame(unique, self.map_err(e), &[])),
                }
            }
            FUSE_RMDIR => {
                if let Err(e) = self.check_write_fence() {
                    return Some(encode_out_frame(unique, self.map_err(e), &[]));
                }
                let Some((name, _)) = read_cstr(body) else {
                    return Some(encode_out_frame(unique, -libc::EINVAL, &[]));
                };
                let dir_h = match self.handle_for_node(nodeid) {
                    Ok(h) => h,
                    Err(e) => return Some(encode_out_frame(unique, self.map_err(e), &[])),
                };
                match fs.rmdir(&cred, &dir_h, name).await {
                    Ok(()) => Some(encode_out_frame(unique, 0, &[])),
                    Err(e) => Some(encode_out_frame(unique, self.map_err(e), &[])),
                }
            }
            FUSE_RENAME | FUSE_RENAME2 => {
                if let Err(e) = self.check_write_fence() {
                    return Some(encode_out_frame(unique, self.map_err(e), &[]));
                }
                let hdr_len = if opcode == FUSE_RENAME2 { 16 } else { 8 };
                if body.len() < hdr_len {
                    return Some(encode_out_frame(unique, -libc::EINVAL, &[]));
                }
                let newdir = read_u64_le(body, 0).unwrap_or(0);
                let rename_flags = if opcode == FUSE_RENAME2 {
                    let raw_flags = read_u32_le(body, 8).unwrap_or(0);
                    if (raw_flags & !LINUX_RENAME_NOREPLACE) != 0 {
                        return Some(encode_out_frame(unique, -libc::EINVAL, &[]));
                    }
                    if (raw_flags & LINUX_RENAME_NOREPLACE) != 0 {
                        RenameFlags::NOREPLACE
                    } else {
                        RenameFlags::empty()
                    }
                } else {
                    RenameFlags::empty()
                };
                let Some((old_name, rest)) = read_cstr(&body[hdr_len..]) else {
                    return Some(encode_out_frame(unique, -libc::EINVAL, &[]));
                };
                let Some((new_name, _)) = read_cstr(rest) else {
                    return Some(encode_out_frame(unique, -libc::EINVAL, &[]));
                };
                let from_h = match self.handle_for_node(nodeid) {
                    Ok(h) => h,
                    Err(e) => return Some(encode_out_frame(unique, self.map_err(e), &[])),
                };
                let to_h = match self.handle_for_node(newdir) {
                    Ok(h) => h,
                    Err(e) => return Some(encode_out_frame(unique, self.map_err(e), &[])),
                };
                match fs
                    .rename(&cred, &from_h, old_name, &to_h, new_name, rename_flags)
                    .await
                {
                    Ok(()) => Some(encode_out_frame(unique, 0, &[])),
                    Err(e) => Some(encode_out_frame(unique, self.map_err(e), &[])),
                }
            }
            FUSE_CREATE => {
                if let Err(e) = self.check_write_fence() {
                    return Some(encode_out_frame(unique, self.map_err(e), &[]));
                }
                if body.len() < 16 {
                    return Some(encode_out_frame(unique, -libc::EINVAL, &[]));
                }
                let flags = read_u32_le(body, 0).unwrap_or(0);
                let mode = (read_u32_le(body, 4).unwrap_or(0o644) & 0o7777) as u16;
                let Some((name, _)) = read_cstr(&body[16..]) else {
                    return Some(encode_out_frame(unique, -libc::EINVAL, &[]));
                };
                let dir_h = match self.handle_for_node(nodeid) {
                    Ok(h) => h,
                    Err(e) => return Some(encode_out_frame(unique, self.map_err(e), &[])),
                };
                let mut opts = open_options_from_posix_flags(flags);
                opts.write(true).create(true);
                match fs.create(&cred, &dir_h, name, mode, &opts).await {
                    Ok((ent, open_ref)) => {
                        let generation = ent.handle.node.generation;
                        let nid = self.register_node(ent.handle);
                        let fh = self.alloc_fh();
                        self.open_files.insert(fh, open_ref);
                        let mut payload = Vec::with_capacity(144);
                        payload.extend_from_slice(&encode_entry_out(
                            nid,
                            generation,
                            &ent.metadata,
                        ));
                        payload.extend_from_slice(&encode_open_out(fh));
                        Some(encode_out_frame(unique, 0, &payload))
                    }
                    Err(e) => Some(encode_out_frame(unique, self.map_err(e), &[])),
                }
            }
            FUSE_OPEN => {
                if body.len() < 8 {
                    return Some(encode_out_frame(unique, -libc::EINVAL, &[]));
                }
                let flags = read_u32_le(body, 0).unwrap_or(0);
                let opts = open_options_from_posix_flags(flags);
                let wants_write = matches!(
                    (flags as i32) & libc::O_ACCMODE,
                    libc::O_WRONLY | libc::O_RDWR
                ) || ((flags as i32) & libc::O_TRUNC != 0);
                if wants_write && let Err(e) = self.check_write_fence() {
                    return Some(encode_out_frame(unique, self.map_err(e), &[]));
                }
                let h = match self.handle_for_node(nodeid) {
                    Ok(h) => h,
                    Err(e) => return Some(encode_out_frame(unique, self.map_err(e), &[])),
                };
                match fs.open(&cred, &h, &opts).await {
                    Ok(open_ref) => {
                        let fh = self.alloc_fh();
                        self.open_files.insert(fh, open_ref);
                        Some(encode_out_frame(unique, 0, &encode_open_out(fh)))
                    }
                    Err(e) => Some(encode_out_frame(unique, self.map_err(e), &[])),
                }
            }
            FUSE_READ => {
                if body.len() < 24 {
                    return Some(encode_out_frame(unique, -libc::EINVAL, &[]));
                }
                let fh = read_u64_le(body, 0).unwrap_or(0);
                let offset = read_u64_le(body, 8).unwrap_or(0);
                let size = read_u32_le(body, 16).unwrap_or(0).min(FUSE_MAX_WRITE) as usize;
                let Some(open_ref) = self.open_files.get(&fh).cloned() else {
                    return Some(encode_out_frame(unique, -libc::EBADF, &[]));
                };
                let mut buf = vec![0u8; size];
                match fs.read_at(&open_ref, &mut buf, offset).await {
                    Ok(n) => {
                        buf.truncate(n);
                        Some(encode_out_frame(unique, 0, &buf))
                    }
                    Err(e) => Some(encode_out_frame(unique, self.map_err(e), &[])),
                }
            }
            FUSE_WRITE => {
                if let Err(e) = self.check_write_fence() {
                    return Some(encode_out_frame(unique, self.map_err(e), &[]));
                }
                if body.len() < 40 {
                    return Some(encode_out_frame(unique, -libc::EINVAL, &[]));
                }
                let fh = read_u64_le(body, 0).unwrap_or(0);
                let offset = read_u64_le(body, 8).unwrap_or(0);
                let size = read_u32_le(body, 16).unwrap_or(0) as usize;
                let Some(data) = body.get(40..40 + size) else {
                    return Some(encode_out_frame(unique, -libc::EINVAL, &[]));
                };
                let Some(open_ref) = self.open_files.get(&fh).cloned() else {
                    return Some(encode_out_frame(unique, -libc::EBADF, &[]));
                };
                match fs.write_at(&open_ref, data, WriteAt::Offset(offset)).await {
                    Ok(w) => {
                        let mut out = [0u8; 8];
                        out[0..4].copy_from_slice(&(w.len as u32).to_le_bytes());
                        Some(encode_out_frame(unique, 0, &out))
                    }
                    Err(e) => Some(encode_out_frame(unique, self.map_err(e), &[])),
                }
            }
            FUSE_FSYNC | FUSE_FLUSH | FUSE_FSYNCDIR => {
                if self.readonly {
                    return Some(encode_out_frame(unique, 0, &[]));
                }
                if let Err(e) = self.check_write_fence() {
                    return Some(encode_out_frame(unique, self.map_err(e), &[]));
                }
                match fs.commit_tx_group().await {
                    Ok(_) => Some(encode_out_frame(unique, 0, &[])),
                    Err(e) => Some(encode_out_frame(unique, self.map_err(e), &[])),
                }
            }
            FUSE_RELEASE => {
                if let Some(fh) = read_u64_le(body, 0)
                    && let Some(open_ref) = self.open_files.remove(&fh)
                {
                    let _ = fs.release(&open_ref).await;
                }
                Some(encode_out_frame(unique, 0, &[]))
            }
            FUSE_OPENDIR => {
                let h = match self.handle_for_node(nodeid) {
                    Ok(h) => h,
                    Err(e) => return Some(encode_out_frame(unique, self.map_err(e), &[])),
                };
                match fs.read_dir(&cred, &h).await {
                    Ok(entries) => {
                        let fh = self.alloc_fh();
                        self.open_dirs.insert(fh, entries);
                        Some(encode_out_frame(unique, 0, &encode_open_out(fh)))
                    }
                    Err(e) => Some(encode_out_frame(unique, self.map_err(e), &[])),
                }
            }
            FUSE_READDIR => {
                if body.len() < 24 {
                    return Some(encode_out_frame(unique, -libc::EINVAL, &[]));
                }
                let fh = read_u64_le(body, 0).unwrap_or(0);
                let offset = read_u64_le(body, 8).unwrap_or(0) as usize;
                let max_size = read_u32_le(body, 16).unwrap_or(0).min(FUSE_MAX_WRITE) as usize;
                let Some(entries) = self.open_dirs.get(&fh) else {
                    return Some(encode_out_frame(unique, -libc::EBADF, &[]));
                };
                let mut buf = Vec::new();
                for (idx, ent) in entries.iter().enumerate().skip(offset) {
                    let nb = ent.name.as_bytes();
                    let rec_len = (24 + nb.len() + 7) & !7;
                    if buf.len() + rec_len > max_size {
                        break;
                    }
                    buf.extend_from_slice(&ent.node.ino.to_le_bytes());
                    buf.extend_from_slice(&((idx + 1) as u64).to_le_bytes());
                    buf.extend_from_slice(&(nb.len() as u32).to_le_bytes());
                    buf.extend_from_slice(&dtype_from_filetype(ent.file_type).to_le_bytes());
                    buf.extend_from_slice(nb);
                    while !buf.len().is_multiple_of(8) {
                        buf.push(0);
                    }
                }
                Some(encode_out_frame(unique, 0, &buf))
            }
            FUSE_RELEASEDIR => {
                if let Some(fh) = read_u64_le(body, 0) {
                    self.open_dirs.remove(&fh);
                }
                Some(encode_out_frame(unique, 0, &[]))
            }
            FUSE_STATFS => match fs.statfs(&cred).await {
                Ok(st) => {
                    let mut out = [0u8; 80];
                    out[0..8].copy_from_slice(&st.blocks.to_le_bytes());
                    out[8..16].copy_from_slice(&st.blocks_free.to_le_bytes());
                    out[16..24].copy_from_slice(&st.blocks_free.to_le_bytes());
                    out[24..32].copy_from_slice(&st.files.to_le_bytes());
                    out[32..40].copy_from_slice(&st.files_free.to_le_bytes());
                    out[40..44].copy_from_slice(&st.block_size.to_le_bytes());
                    out[44..48].copy_from_slice(&st.name_max.to_le_bytes());
                    out[48..52].copy_from_slice(&st.block_size.to_le_bytes());
                    Some(encode_out_frame(unique, 0, &out))
                }
                Err(e) => Some(encode_out_frame(unique, self.map_err(e), &[])),
            },
            _ => Some(encode_out_frame(unique, -libc::ENOSYS, &[])),
        }
    }
}

/// Control commands accepted by [`serve_fuse_fd_with_control`] for shim handoff & clean shutdown.
pub enum FuseControlCmd {
    HandoffAcquire {
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    HandoffRelease {
        reply: oneshot::Sender<Result<(), Errno>>,
    },
    Shutdown {
        reply: oneshot::Sender<Result<(), Errno>>,
    },
}

/// Serve a raw `/dev/fuse` fd asynchronously alongside a control channel (`ACQUIRE`/`RELEASE`/
/// `Shutdown`) using non-blocking `AsyncFd`, enabling single-writer handoff under `StageMode::Fuse`.
pub async fn serve_fuse_fd_with_control<H, P, F, Fut>(
    fd: OwnedFd,
    mut session: FuseCowFsSession<H, P>,
    stop: Arc<AtomicBool>,
    mut ctrl_rx: mpsc::UnboundedReceiver<FuseControlCmd>,
    reopen: F,
) -> io::Result<()>
where
    H: HeadStore + 'static,
    P: PackStore + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = Result<Rc<CowFs<H, P>>, Errno>>,
{
    let raw = fd.as_raw_fd();
    let fl = unsafe { libc::fcntl(raw, libc::F_GETFL) };
    if fl >= 0 {
        let _ = unsafe { libc::fcntl(raw, libc::F_SETFL, fl | libc::O_NONBLOCK) };
    }
    // SAFETY: `fd` is an exclusively owned valid `/dev/fuse` `OwnedFd` whose lifetime is owned
    // by `AsyncFd` until dropped after deregistration.
    let async_fd = unsafe { AsyncFd::register(fd) }?;
    let mut buf = vec![0u8; FUSE_MAX_FRAME_BYTES];

    while !stop.load(Ordering::SeqCst) {
        tokio::select! {
            cmd = ctrl_rx.recv() => {
                match cmd {
                    Some(FuseControlCmd::HandoffAcquire { reply }) => {
                        let _ = reply.send(session.handoff_acquire().await);
                    }
                    Some(FuseControlCmd::HandoffRelease { reply }) => {
                        if session.fs.is_none() && !session.is_fenced() {
                            match reopen().await {
                                Ok(fs) => session.handoff_release_reopen(fs),
                                Err(Errno::ESTALE) => session.trip_fence(),
                                Err(_) => {}
                            }
                        }
                        let _ = reply.send(Ok(()));
                    }
                    Some(FuseControlCmd::Shutdown { reply }) => {
                        let res = session.close_clean().await;
                        let _ = reply.send(res);
                        return Ok(());
                    }
                    None => break,
                }
            }
            ready = async_fd.readable() => {
                let mut guard = ready?;
                let n = unsafe { libc::read(raw, buf.as_mut_ptr().cast(), buf.len()) };
                if n < 0 {
                    let err = io::Error::last_os_error();
                    match err.raw_os_error() {
                        Some(libc::EAGAIN) => {
                            guard.clear_ready();
                            continue;
                        }
                        Some(libc::EINTR) => continue,
                        Some(libc::ENODEV) => break,
                        _ => return Err(err),
                    }
                }
                if n == 0 {
                    break;
                }
                if let Some(reply) = session.handle_request(&buf[..n as usize]).await {
                    let wn = unsafe { libc::write(raw, reply.as_ptr().cast(), reply.len()) };
                    if wn < 0 {
                        let err = io::Error::last_os_error();
                        if err.raw_os_error() == Some(libc::ENOENT) {
                            continue;
                        }
                        if err.raw_os_error() == Some(libc::ENODEV) {
                            break;
                        }
                    }
                }
            }
        }
    }
    let _ = session.close_clean().await;
    Ok(())
}

/// Serve a raw `/dev/fuse` (or `SOCK_SEQPACKET` test `socketpair`) fd until EOF or `stop` is set.
pub async fn serve_fuse_fd<H: HeadStore + 'static, P: PackStore + 'static>(
    fd: OwnedFd,
    mut session: FuseCowFsSession<H, P>,
    stop: Arc<AtomicBool>,
) -> io::Result<()> {
    let raw = fd.as_raw_fd();
    let mut buf = vec![0u8; FUSE_MAX_FRAME_BYTES];
    while !stop.load(Ordering::SeqCst) {
        let n = unsafe { libc::read(raw, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR | libc::EAGAIN) => continue,
                Some(libc::ENODEV) => break, // unmounted
                _ => return Err(err),
            }
        }
        if n == 0 {
            break;
        }
        if let Some(reply) = session.handle_request(&buf[..n as usize]).await {
            let wn = unsafe { libc::write(raw, reply.as_ptr().cast(), reply.len()) };
            if wn < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ENOENT) {
                    // Interrupted request on kernel side; ignore per FUSE ABI.
                    continue;
                }
                if err.raw_os_error() == Some(libc::ENODEV) {
                    break;
                }
                return Err(err);
            }
        }
    }
    Ok(())
}

/// Mount `mountpoint` using `fusermount3` and receive the `/dev/fuse` fd via `SCM_RIGHTS`.
pub fn mount_via_fusermount3(
    mountpoint: &Path,
    fsname: &str,
    read_only: bool,
) -> io::Result<OwnedFd> {
    if fsname.is_empty()
        || fsname.len() > 128
        || !fsname
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b',' && b != b'=')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid FUSE fsname option",
        ));
    }
    let mut fds = [-1 as libc::c_int; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let parent_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let child_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    // Ensure parent end is CLOEXEC so fusermount3 only inherits `_FUSE_COMMFD`.
    let _ = unsafe { libc::fcntl(parent_fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };

    let mut opts = format!("fsname={fsname},subtype=cowfs,default_permissions");
    if read_only {
        opts.push_str(",ro");
    }
    let status = Command::new("fusermount3")
        .arg("-o")
        .arg(&opts)
        .arg("--")
        .arg(mountpoint)
        .env("_FUSE_COMMFD", child_fd.as_raw_fd().to_string())
        .status()?;
    drop(child_fd);
    if !status.success() {
        return Err(io::Error::other(format!(
            "fusermount3 exited with status {status}"
        )));
    }
    recv_scm_rights_fd(parent_fd.as_raw_fd())
}

/// Unmount a FUSE3 mountpoint via `fusermount3 -u`.
pub fn unmount_via_fusermount3(mountpoint: &Path) -> io::Result<()> {
    let status = Command::new("fusermount3")
        .arg("-u")
        .arg("--")
        .arg(mountpoint)
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "fusermount3 -u failed with status {status}"
        )));
    }
    Ok(())
}

fn recv_scm_rights_fd(sock: libc::c_int) -> io::Result<OwnedFd> {
    let mut data_buf = [0u8; 8];
    let mut iov = libc::iovec {
        iov_base: data_buf.as_mut_ptr().cast(),
        iov_len: data_buf.len(),
    };
    let cmsg_space =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast();
    msg.msg_controllen = cmsg_buf.len();

    let n = unsafe { libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing SCM_RIGHTS control message from fusermount3",
        ));
    }
    let min_cmsg_len =
        unsafe { libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) } as usize;
    let (level, typ, len) = unsafe {
        (
            (*cmsg).cmsg_level,
            (*cmsg).cmsg_type,
            (*cmsg).cmsg_len as usize,
        )
    };
    if level != libc::SOL_SOCKET || typ != libc::SCM_RIGHTS || len < min_cmsg_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected or truncated ancillary message",
        ));
    }
    let mut received_fd: libc::c_int = -1;
    unsafe {
        std::ptr::copy_nonoverlapping(
            libc::CMSG_DATA(cmsg),
            (&mut received_fd as *mut libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>(),
        );
    }
    if received_fd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "negative fd received from fusermount3",
        ));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(received_fd) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::fs::Timespec;
    use cowtree::memory::{MemoryHeadStore, MemoryPackStore};
    use cowtree::{VolumeId, WriterMode};
    use os_cowfs::{CowFsConfig, CowFsOpenMode};

    fn make_req(opcode: u32, unique: u64, nodeid: u64, body: &[u8]) -> Vec<u8> {
        let len = (FUSE_IN_HEADER_BYTES + body.len()) as u32;
        let mut out = Vec::with_capacity(len as usize);
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&opcode.to_le_bytes());
        out.extend_from_slice(&unique.to_le_bytes());
        out.extend_from_slice(&nodeid.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // uid
        out.extend_from_slice(&0u32.to_le_bytes()); // gid
        out.extend_from_slice(&1u32.to_le_bytes()); // pid
        out.extend_from_slice(&0u32.to_le_bytes()); // padding
        out.extend_from_slice(body);
        out
    }

    fn parse_reply(rep: &[u8]) -> (u64, i32, &[u8]) {
        let len = read_u32_le(rep, 0).unwrap() as usize;
        assert_eq!(len, rep.len());
        let err = read_u32_le(rep, 4).unwrap() as i32;
        let uniq = read_u64_le(rep, 8).unwrap();
        (uniq, err, &rep[16..])
    }

    #[test]
    fn fuse_v731_socketpair_full_posix_ops_and_fenced_estale() {
        let mut sv = [-1 as libc::c_int; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, sv.as_mut_ptr()) },
            0
        );
        let server_fd = unsafe { OwnedFd::from_raw_fd(sv[0]) };
        let client_fd = unsafe { OwnedFd::from_raw_fd(sv[1]) };

        let fence_flag = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::new(AtomicBool::new(false));

        let srv_fence = Arc::clone(&fence_flag);
        let srv_stop = Arc::clone(&stop_flag);
        let server_thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let local = tokio::task::LocalSet::new();
            local.block_on(&rt, async move {
                let hs = Rc::new(MemoryHeadStore::new());
                let ps = Rc::new(MemoryPackStore::new());
                let clock: os_cowfs::CowFsClock = Rc::new(|| Timespec {
                    sec: 1_700_000_000,
                    nsec: 0,
                });
                let vid = VolumeId("fuse-test-vol".into());
                CowFs::format_volume(&*hs, &*ps, vid.clone(), 0, 0, 0o755, (clock)())
                    .await
                    .unwrap();
                let fs = Rc::new(
                    CowFs::open(
                        Rc::clone(&hs),
                        Rc::clone(&ps),
                        vid,
                        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
                        CowFsConfig::local_native(clock),
                    )
                    .await
                    .unwrap(),
                );
                let sess = FuseCowFsSession::new(Rc::clone(&fs), srv_fence);
                let _ = serve_fuse_fd(server_fd, sess, srv_stop).await;
                let _ = fs.close_clean().await;
            });
        });

        let call = |req: Vec<u8>| -> Vec<u8> {
            let wn = unsafe { libc::write(client_fd.as_raw_fd(), req.as_ptr().cast(), req.len()) };
            assert_eq!(wn as usize, req.len());
            let mut resp = vec![0u8; 64 * 1024];
            let rn =
                unsafe { libc::read(client_fd.as_raw_fd(), resp.as_mut_ptr().cast(), resp.len()) };
            assert!(rn >= 16);
            resp.truncate(rn as usize);
            resp
        };

        // 1. FUSE_INIT
        let init_body = [7u32, 31, 65536, 0]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect::<Vec<_>>();
        let rep = call(make_req(FUSE_INIT, 1, 0, &init_body));
        let (u, err, body) = parse_reply(&rep);
        assert_eq!((u, err), (1, 0));
        assert_eq!(read_u32_le(body, 0), Some(7));
        assert_eq!(read_u32_le(body, 4), Some(31));

        // 2. GETATTR root
        let rep = call(make_req(FUSE_GETATTR, 2, FUSE_ROOT_ID, &[0u8; 16]));
        let (_, err, body) = parse_reply(&rep);
        assert_eq!(err, 0);
        assert_eq!(read_u64_le(body, 16), Some(FUSE_ROOT_ID));

        // 3. MKDIR "sub"
        let mut mk_body = Vec::new();
        mk_body.extend_from_slice(&0o755u32.to_le_bytes());
        mk_body.extend_from_slice(&0u32.to_le_bytes());
        mk_body.extend_from_slice(b"sub\0");
        let rep = call(make_req(FUSE_MKDIR, 3, FUSE_ROOT_ID, &mk_body));
        let (_, err, body) = parse_reply(&rep);
        assert_eq!(err, 0);
        let sub_ino = read_u64_le(body, 0).unwrap();

        // 4. LOOKUP "sub"
        let rep = call(make_req(FUSE_LOOKUP, 4, FUSE_ROOT_ID, b"sub\0"));
        let (_, err, body) = parse_reply(&rep);
        assert_eq!(err, 0);
        assert_eq!(read_u64_le(body, 0), Some(sub_ino));

        // 5. CREATE "sub/hello.txt"
        let mut cr_body = Vec::new();
        cr_body.extend_from_slice(&(libc::O_RDWR as u32).to_le_bytes());
        cr_body.extend_from_slice(&0o644u32.to_le_bytes());
        cr_body.extend_from_slice(&0u32.to_le_bytes());
        cr_body.extend_from_slice(&0u32.to_le_bytes());
        cr_body.extend_from_slice(b"hello.txt\0");
        let rep = call(make_req(FUSE_CREATE, 5, sub_ino, &cr_body));
        let (_, err, body) = parse_reply(&rep);
        assert_eq!(err, 0);
        let file_ino = read_u64_le(body, 0).unwrap();
        let fh = read_u64_le(body, 128).unwrap();

        // 6. WRITE + FSYNC + READ
        let payload = b"hello fuse3 cowfs!";
        let mut wr_body = vec![0u8; 40];
        wr_body[0..8].copy_from_slice(&fh.to_le_bytes());
        wr_body[8..16].copy_from_slice(&0u64.to_le_bytes());
        wr_body[16..20].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        wr_body.extend_from_slice(payload);
        let rep = call(make_req(FUSE_WRITE, 6, file_ino, &wr_body));
        let (_, err, body) = parse_reply(&rep);
        assert_eq!(err, 0);
        assert_eq!(read_u32_le(body, 0), Some(payload.len() as u32));

        let rep = call(make_req(FUSE_FSYNC, 7, file_ino, &[0u8; 16]));
        assert_eq!(parse_reply(&rep).1, 0);

        let mut rd_body = vec![0u8; 40];
        rd_body[0..8].copy_from_slice(&fh.to_le_bytes());
        rd_body[8..16].copy_from_slice(&0u64.to_le_bytes());
        rd_body[16..20].copy_from_slice(&64u32.to_le_bytes());
        let rep = call(make_req(FUSE_READ, 8, file_ino, &rd_body));
        let (_, err, body) = parse_reply(&rep);
        assert_eq!(err, 0);
        assert_eq!(body, payload);

        // 7. OPENDIR + READDIR + RELEASEDIR on sub
        let rep = call(make_req(FUSE_OPENDIR, 9, sub_ino, &[0u8; 8]));
        let (_, err, body) = parse_reply(&rep);
        assert_eq!(err, 0);
        let dir_fh = read_u64_le(body, 0).unwrap();
        let mut rddir = vec![0u8; 40];
        rddir[0..8].copy_from_slice(&dir_fh.to_le_bytes());
        rddir[8..16].copy_from_slice(&0u64.to_le_bytes());
        rddir[16..20].copy_from_slice(&4096u32.to_le_bytes());
        let rep = call(make_req(FUSE_READDIR, 10, sub_ino, &rddir));
        let (_, err, body) = parse_reply(&rep);
        assert_eq!(err, 0);
        assert!(body.windows(9).any(|w| w == b"hello.txt"));

        // 8. RENAME "hello.txt" -> "renamed.txt"
        let mut ren_body = Vec::new();
        ren_body.extend_from_slice(&sub_ino.to_le_bytes());
        ren_body.extend_from_slice(b"hello.txt\0renamed.txt\0");
        let rep = call(make_req(FUSE_RENAME, 11, sub_ino, &ren_body));
        assert_eq!(parse_reply(&rep).1, 0);

        // 8b. P1-4 & Nit-5 regressions:
        //     - O_CREAT | O_EXCL on existing file returns -EEXIST
        let mut excl_body = Vec::new();
        excl_body.extend_from_slice(
            &((libc::O_RDWR | libc::O_CREAT | libc::O_EXCL) as u32).to_le_bytes(),
        );
        excl_body.extend_from_slice(&0o644u32.to_le_bytes());
        excl_body.extend_from_slice(&0u32.to_le_bytes());
        excl_body.extend_from_slice(&0u32.to_le_bytes());
        excl_body.extend_from_slice(b"renamed.txt\0");
        let rep = call(make_req(FUSE_CREATE, 110, sub_ino, &excl_body));
        assert_eq!(parse_reply(&rep).1, -libc::EEXIST);

        //     - O_RDONLY | O_APPEND open succeeds
        let mut ro_app_body = Vec::new();
        ro_app_body.extend_from_slice(&((libc::O_RDONLY | libc::O_APPEND) as u32).to_le_bytes());
        ro_app_body.extend_from_slice(&0u32.to_le_bytes());
        let rep = call(make_req(FUSE_OPEN, 111, file_ino, &ro_app_body));
        assert_eq!(parse_reply(&rep).1, 0);

        //     - Create second file "other.txt", then FUSE_RENAME2 with RENAME_NOREPLACE -> -EEXIST,
        //       and FUSE_RENAME2 with unsupported flag -> -EINVAL
        let mut cr2_body = Vec::new();
        cr2_body.extend_from_slice(&(libc::O_RDWR as u32).to_le_bytes());
        cr2_body.extend_from_slice(&0o644u32.to_le_bytes());
        cr2_body.extend_from_slice(&0u32.to_le_bytes());
        cr2_body.extend_from_slice(&0u32.to_le_bytes());
        cr2_body.extend_from_slice(b"other.txt\0");
        let rep = call(make_req(FUSE_CREATE, 112, sub_ino, &cr2_body));
        assert_eq!(parse_reply(&rep).1, 0);

        let mut ren2_noreplace = Vec::new();
        ren2_noreplace.extend_from_slice(&sub_ino.to_le_bytes());
        ren2_noreplace.extend_from_slice(&LINUX_RENAME_NOREPLACE.to_le_bytes());
        ren2_noreplace.extend_from_slice(&0u32.to_le_bytes());
        ren2_noreplace.extend_from_slice(b"other.txt\0renamed.txt\0");
        let rep = call(make_req(FUSE_RENAME2, 113, sub_ino, &ren2_noreplace));
        assert_eq!(parse_reply(&rep).1, -libc::EEXIST);

        let mut ren2_bad_flags = Vec::new();
        ren2_bad_flags.extend_from_slice(&sub_ino.to_le_bytes());
        ren2_bad_flags.extend_from_slice(&0x8000u32.to_le_bytes());
        ren2_bad_flags.extend_from_slice(&0u32.to_le_bytes());
        ren2_bad_flags.extend_from_slice(b"other.txt\0renamed2.txt\0");
        let rep = call(make_req(FUSE_RENAME2, 114, sub_ino, &ren2_bad_flags));
        assert_eq!(parse_reply(&rep).1, -libc::EINVAL);

        //     - FUSE_SETATTR with FATTR_ATIME_NOW | FATTR_MTIME_NOW succeeds
        let mut sattr = vec![0u8; 88];
        let valid_mask = FATTR_ATIME | FATTR_MTIME | FATTR_ATIME_NOW | FATTR_MTIME_NOW;
        sattr[0..4].copy_from_slice(&valid_mask.to_le_bytes());
        let rep = call(make_req(FUSE_SETATTR, 115, file_ino, &sattr));
        assert_eq!(parse_reply(&rep).1, 0);

        //     - FUSE_BATCH_FORGET is a one-way notification (no reply sent on the socket)
        let bf_req = make_req(FUSE_BATCH_FORGET, 116, FUSE_ROOT_ID, &[0u8; 8]);
        let wn =
            unsafe { libc::write(client_fd.as_raw_fd(), bf_req.as_ptr().cast(), bf_req.len()) };
        assert_eq!(wn as usize, bf_req.len());
        // Next GETATTR must immediately get its own unique=117 reply (proving no stray reply from BATCH_FORGET).
        let rep = call(make_req(FUSE_GETATTR, 117, file_ino, &[0u8; 16]));
        assert_eq!(parse_reply(&rep).0, 117);
        assert_eq!(parse_reply(&rep).1, 0);

        // 9. Trip fence -> WRITE, FSYNC, OPEN(O_TRUNC), UNLINK MUST return -ESTALE!
        fence_flag.store(true, Ordering::SeqCst);
        let rep = call(make_req(FUSE_WRITE, 12, file_ino, &wr_body));
        assert_eq!(parse_reply(&rep).1, -libc::ESTALE);
        let rep = call(make_req(FUSE_FSYNC, 13, file_ino, &[0u8; 16]));
        assert_eq!(parse_reply(&rep).1, -libc::ESTALE);
        let mut trunc_open = Vec::new();
        trunc_open.extend_from_slice(&((libc::O_RDONLY | libc::O_TRUNC) as u32).to_le_bytes());
        trunc_open.extend_from_slice(&0u32.to_le_bytes());
        let rep = call(make_req(FUSE_OPEN, 130, file_ino, &trunc_open));
        assert_eq!(parse_reply(&rep).1, -libc::ESTALE);
        let rep = call(make_req(FUSE_UNLINK, 14, sub_ino, b"renamed.txt\0"));
        assert_eq!(parse_reply(&rep).1, -libc::ESTALE);

        // Clear fence to test UNLINK succeeds when unfenced.
        fence_flag.store(false, Ordering::SeqCst);
        let rep = call(make_req(FUSE_UNLINK, 15, sub_ino, b"renamed.txt\0"));
        assert_eq!(parse_reply(&rep).1, 0);
        let rep = call(make_req(FUSE_UNLINK, 16, sub_ino, b"other.txt\0"));
        assert_eq!(parse_reply(&rep).1, 0);

        stop_flag.store(true, Ordering::SeqCst);
        drop(client_fd);
        server_thread.join().unwrap();
    }

    #[test]
    fn fuse_v731_handoff_acquire_returns_ebusy_and_release_reopens() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async {
            let hs = Rc::new(MemoryHeadStore::new());
            let ps = Rc::new(MemoryPackStore::new());
            let clock: os_cowfs::CowFsClock = Rc::new(|| Timespec {
                sec: 1_700_000_000,
                nsec: 0,
            });
            let vid = VolumeId("fuse-handoff-vol".into());
            CowFs::format_volume(&*hs, &*ps, vid.clone(), 0, 0, 0o755, (clock)())
                .await
                .unwrap();
            let fs1 = Rc::new(
                CowFs::open(
                    Rc::clone(&hs),
                    Rc::clone(&ps),
                    vid.clone(),
                    CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
                    CowFsConfig::local_native(Rc::clone(&clock)),
                )
                .await
                .unwrap(),
            );
            let fence_flag = Arc::new(AtomicBool::new(false));
            let mut sess = FuseCowFsSession::new(fs1, fence_flag);

            // Before handoff, GETATTR on root succeeds.
            let rep = sess
                .handle_request(&make_req(FUSE_GETATTR, 1, FUSE_ROOT_ID, &[0u8; 16]))
                .await
                .unwrap();
            assert_eq!(parse_reply(&rep).1, 0);

            // Acquire handoff -> host FUSE requests return -EBUSY, and another Exclusive opener succeeds!
            sess.handoff_acquire().await.unwrap();
            let rep = sess
                .handle_request(&make_req(FUSE_GETATTR, 2, FUSE_ROOT_ID, &[0u8; 16]))
                .await
                .unwrap();
            assert_eq!(parse_reply(&rep).1, -libc::EBUSY);

            let shim_fs = CowFs::open(
                Rc::clone(&hs),
                Rc::clone(&ps),
                vid.clone(),
                CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
                CowFsConfig::local_native(Rc::clone(&clock)),
            )
            .await
            .expect("shim Exclusive open must succeed after FUSE handoff_acquire");
            shim_fs.close_clean().await.unwrap();

            // Release handoff -> reopen Exclusive and verify host FUSE GETATTR works again.
            let fs2 = Rc::new(
                CowFs::open(
                    Rc::clone(&hs),
                    Rc::clone(&ps),
                    vid,
                    CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
                    CowFsConfig::local_native(clock),
                )
                .await
                .unwrap(),
            );
            sess.handoff_release_reopen(fs2);
            let rep = sess
                .handle_request(&make_req(FUSE_GETATTR, 3, FUSE_ROOT_ID, &[0u8; 16]))
                .await
                .unwrap();
            assert_eq!(parse_reply(&rep).1, 0);
            sess.close_clean().await.unwrap();
        });
    }
}

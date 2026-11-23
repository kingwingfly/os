//! Compact binary encoding for `os-cowfs` single-map B+tree items:
//! - `0x01` `INODE_ITEM`
//! - `0x10` `INODE_REF`
//! - `0x20` `DIR_ITEM`
//! - `0x21` `DIR_INDEX`
//! - `0x30` `EXTENT_DATA` (Inline `<= 2 KiB` or Extent `<= 1 MiB` aligned on `64 KiB` blocks)
//! - `0x40` `XATTR_ITEM`

use abi::Errno;
use abi::fs::{FileType, Metadata, Timespec};
use cowtree::{BLOCK_SIZE, Digest, EXTENT_MAX_BYTES, INLINE_MAX_BYTES};
use os_core::acl::Entries;
use os_core::permissions::Node as PermNode;
use vfs::Result;

const INODE_VERSION: u8 = 1;
const EXTENT_TAG_INLINE: u8 = 0;
const EXTENT_TAG_OUTLINE: u8 = 1;

/// `0x01` `INODE_ITEM` value stored at `(ino, 0x01, [])`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InodeItem {
    pub file_type: FileType,
    pub mode: u16,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub generation: u64,
    pub atime: Timespec,
    pub mtime: Timespec,
    pub ctime: Timespec,
    pub rdev: Option<String>,
    pub symlink_target: Option<String>,
    pub next_dir_index: u64,
    pub acl_present: bool,
    pub default_acl_present: bool,
}

impl InodeItem {
    pub fn to_metadata(&self) -> Metadata {
        Metadata {
            file_type: self.file_type,
            mode: self.mode & 0o7777,
            nlink: self.nlink,
            uid: self.uid,
            gid: self.gid,
            size: match self.file_type {
                FileType::Symlink => self.symlink_target.as_ref().map_or(0, |s| s.len() as u64),
                FileType::Dir => u64::from(BLOCK_SIZE),
                _ => self.size,
            },
            atime: self.atime,
            mtime: self.mtime,
            ctime: self.ctime,
            rdev: self.rdev.clone(),
            acl: self.acl_present,
        }
    }

    pub fn to_perm_node(
        &self,
        ino: u64,
        acl_entries: Option<Entries>,
        default_acl: Option<Entries>,
    ) -> PermNode {
        let mut node = PermNode {
            ino,
            directory: self.file_type == FileType::Dir,
            owner: self.uid,
            group: self.gid,
            mode: self.mode & 0o7777,
            links: self.nlink,
            size: self.size,
            file: None,
            rdev: self.rdev.clone(),
            link: self.symlink_target.clone(),
            acl: None,
            default_acl,
        };
        if let Some(entries) = acl_entries {
            let (acl_mode, ext) = entries.split();
            node.mode = (node.mode & !0o777) | acl_mode;
            node.acl = ext;
        }
        node
    }

    pub fn apply_perm_node(&mut self, node: &PermNode) {
        self.uid = node.owner;
        self.gid = node.group;
        self.mode = node.mode & 0o7777;
        self.rdev = node.rdev.clone();
        self.symlink_target = node.link.clone();
        self.acl_present = node.acl.is_some();
        self.default_acl_present = node.default_acl.is_some();
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96);
        out.push(INODE_VERSION);
        out.push(encode_file_type(self.file_type));
        out.extend_from_slice(&(self.mode & 0o7777).to_be_bytes());
        out.extend_from_slice(&self.nlink.to_be_bytes());
        out.extend_from_slice(&self.uid.to_be_bytes());
        out.extend_from_slice(&self.gid.to_be_bytes());
        out.extend_from_slice(&self.size.to_be_bytes());
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.atime.sec.to_be_bytes());
        out.extend_from_slice(&self.atime.nsec.to_be_bytes());
        out.extend_from_slice(&self.mtime.sec.to_be_bytes());
        out.extend_from_slice(&self.mtime.nsec.to_be_bytes());
        out.extend_from_slice(&self.ctime.sec.to_be_bytes());
        out.extend_from_slice(&self.ctime.nsec.to_be_bytes());
        out.extend_from_slice(&self.next_dir_index.to_be_bytes());
        let flags = (u8::from(self.acl_present)) | (u8::from(self.default_acl_present) << 1);
        out.push(flags);
        write_opt_str(&mut out, self.rdev.as_deref());
        write_opt_str(&mut out, self.symlink_target.as_deref());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut c = 0usize;
        let ver = read_u8(bytes, &mut c)?;
        if ver != INODE_VERSION {
            return Err(Errno::EIO);
        }
        let file_type = decode_file_type(read_u8(bytes, &mut c)?)?;
        let mode = read_u16(bytes, &mut c)?;
        let nlink = read_u32(bytes, &mut c)?;
        let uid = read_u32(bytes, &mut c)?;
        let gid = read_u32(bytes, &mut c)?;
        let size = read_u64(bytes, &mut c)?;
        let generation = read_u64(bytes, &mut c)?;
        let atime = Timespec {
            sec: read_u64(bytes, &mut c)?,
            nsec: read_u32(bytes, &mut c)?,
        };
        let mtime = Timespec {
            sec: read_u64(bytes, &mut c)?,
            nsec: read_u32(bytes, &mut c)?,
        };
        let ctime = Timespec {
            sec: read_u64(bytes, &mut c)?,
            nsec: read_u32(bytes, &mut c)?,
        };
        let next_dir_index = read_u64(bytes, &mut c)?;
        let flags = read_u8(bytes, &mut c)?;
        let acl_present = (flags & 1) != 0;
        let default_acl_present = (flags & 2) != 0;
        let rdev = read_opt_str(bytes, &mut c)?;
        let symlink_target = read_opt_str(bytes, &mut c)?;
        if c != bytes.len() {
            return Err(Errno::EIO);
        }
        Ok(Self {
            file_type,
            mode,
            nlink,
            uid,
            gid,
            size,
            generation,
            atime,
            mtime,
            ctime,
            rdev,
            symlink_target,
            next_dir_index,
            acl_present,
            default_acl_present,
        })
    }
}

/// `0x20` `DIR_ITEM` value stored at `(dir_ino, 0x20, name_bytes)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirItemValue {
    pub child_ino: u64,
    pub child_gen: u64,
    pub file_type: FileType,
    pub dir_index: u64,
}

impl DirItemValue {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(25);
        out.extend_from_slice(&self.child_ino.to_be_bytes());
        out.extend_from_slice(&self.child_gen.to_be_bytes());
        out.push(encode_file_type(self.file_type));
        out.extend_from_slice(&self.dir_index.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 25 {
            return Err(Errno::EIO);
        }
        let mut c = 0;
        let child_ino = read_u64(bytes, &mut c)?;
        let child_gen = read_u64(bytes, &mut c)?;
        let file_type = decode_file_type(read_u8(bytes, &mut c)?)?;
        let dir_index = read_u64(bytes, &mut c)?;
        Ok(Self {
            child_ino,
            child_gen,
            file_type,
            dir_index,
        })
    }
}

/// `0x21` `DIR_INDEX` value stored at `(dir_ino, 0x21, dir_index_be)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirIndexValue {
    pub child_ino: u64,
    pub child_gen: u64,
    pub file_type: FileType,
    pub name: String,
}

impl DirIndexValue {
    pub fn encode(&self) -> Vec<u8> {
        let nb = self.name.as_bytes();
        let mut out = Vec::with_capacity(19 + nb.len());
        out.extend_from_slice(&self.child_ino.to_be_bytes());
        out.extend_from_slice(&self.child_gen.to_be_bytes());
        out.push(encode_file_type(self.file_type));
        out.extend_from_slice(&(nb.len() as u16).to_be_bytes());
        out.extend_from_slice(nb);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut c = 0;
        let child_ino = read_u64(bytes, &mut c)?;
        let child_gen = read_u64(bytes, &mut c)?;
        let file_type = decode_file_type(read_u8(bytes, &mut c)?)?;
        let nlen = read_u16(bytes, &mut c)? as usize;
        let name = std::str::from_utf8(read_slice(bytes, &mut c, nlen)?)
            .map_err(|_| Errno::EIO)?
            .to_string();
        if c != bytes.len() {
            return Err(Errno::EIO);
        }
        Ok(Self {
            child_ino,
            child_gen,
            file_type,
            name,
        })
    }
}

/// `0x30` `EXTENT_DATA` value stored at `(ino, 0x30, file_offset_be)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExtentDataValue {
    /// Inline regular-file content (`<= 2 KiB`) residing directly in the B+tree leaf at offset 0.
    Inline(Vec<u8>),
    /// Content-addressed out-of-line data extent (`64 KiB` aligned, `len <= 1 MiB`) in `PackStore`.
    Extent {
        len: u32,
        digest: Digest,
        block_offset: u32,
    },
}

impl ExtentDataValue {
    pub fn byte_len(&self) -> u64 {
        match self {
            Self::Inline(v) => v.len() as u64,
            Self::Extent { len, .. } => u64::from(*len),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        match self {
            ExtentDataValue::Inline(data) => {
                if data.len() > INLINE_MAX_BYTES {
                    return Err(Errno::EIO);
                }
                let mut out = Vec::with_capacity(3 + data.len());
                out.push(EXTENT_TAG_INLINE);
                out.extend_from_slice(&(data.len() as u16).to_be_bytes());
                out.extend_from_slice(data);
                Ok(out)
            }
            ExtentDataValue::Extent {
                len,
                digest,
                block_offset,
            } => {
                if *len == 0 || *len > EXTENT_MAX_BYTES {
                    return Err(Errno::EIO);
                }
                let mut out = Vec::with_capacity(41);
                out.push(EXTENT_TAG_OUTLINE);
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(digest);
                out.extend_from_slice(&block_offset.to_be_bytes());
                Ok(out)
            }
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut c = 0;
        let tag = read_u8(bytes, &mut c)?;
        match tag {
            EXTENT_TAG_INLINE => {
                let len = read_u16(bytes, &mut c)? as usize;
                if len > INLINE_MAX_BYTES {
                    return Err(Errno::EIO);
                }
                let data = read_slice(bytes, &mut c, len)?.to_vec();
                if c != bytes.len() {
                    return Err(Errno::EIO);
                }
                Ok(ExtentDataValue::Inline(data))
            }
            EXTENT_TAG_OUTLINE => {
                let len = read_u32(bytes, &mut c)?;
                let mut digest = [0u8; 32];
                digest.copy_from_slice(read_slice(bytes, &mut c, 32)?);
                let block_offset = read_u32(bytes, &mut c)?;
                if c != bytes.len() || len == 0 || len > EXTENT_MAX_BYTES {
                    return Err(Errno::EIO);
                }
                Ok(ExtentDataValue::Extent {
                    len,
                    digest,
                    block_offset,
                })
            }
            _ => Err(Errno::EIO),
        }
    }
}

fn encode_file_type(ft: FileType) -> u8 {
    match ft {
        FileType::File => 1,
        FileType::Dir => 2,
        FileType::Symlink => 3,
        FileType::CharDevice => 4,
        FileType::Socket => 5,
    }
}

fn decode_file_type(tag: u8) -> Result<FileType> {
    match tag {
        1 => Ok(FileType::File),
        2 => Ok(FileType::Dir),
        3 => Ok(FileType::Symlink),
        4 => Ok(FileType::CharDevice),
        5 => Ok(FileType::Socket),
        _ => Err(Errno::EIO),
    }
}

fn write_opt_str(out: &mut Vec<u8>, s: Option<&str>) {
    match s {
        None => out.push(0),
        Some(text) => {
            out.push(1);
            let bytes = text.as_bytes();
            out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            out.extend_from_slice(bytes);
        }
    }
}

fn read_opt_str(bytes: &[u8], c: &mut usize) -> Result<Option<String>> {
    match read_u8(bytes, c)? {
        0 => Ok(None),
        1 => {
            let len = read_u16(bytes, c)? as usize;
            let text = std::str::from_utf8(read_slice(bytes, c, len)?)
                .map_err(|_| Errno::EIO)?
                .to_string();
            Ok(Some(text))
        }
        _ => Err(Errno::EIO),
    }
}

fn read_slice<'a>(bytes: &'a [u8], c: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = c.checked_add(len).ok_or(Errno::EIO)?;
    if end > bytes.len() {
        return Err(Errno::EIO);
    }
    let s = &bytes[*c..end];
    *c = end;
    Ok(s)
}

fn read_u8(bytes: &[u8], c: &mut usize) -> Result<u8> {
    Ok(read_slice(bytes, c, 1)?[0])
}

fn read_u16(bytes: &[u8], c: &mut usize) -> Result<u16> {
    let s = read_slice(bytes, c, 2)?;
    Ok(u16::from_be_bytes([s[0], s[1]]))
}

fn read_u32(bytes: &[u8], c: &mut usize) -> Result<u32> {
    let s = read_slice(bytes, c, 4)?;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u64(bytes: &[u8], c: &mut usize) -> Result<u64> {
    let s = read_slice(bytes, c, 8)?;
    Ok(u64::from_be_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_inode_tag5_roundtrips_under_inode_version_1() {
        let item = InodeItem {
            file_type: FileType::Socket,
            mode: 0o660,
            nlink: 1,
            uid: 1000,
            gid: 1000,
            size: 0,
            generation: 7,
            atime: Timespec { sec: 10, nsec: 1 },
            mtime: Timespec { sec: 20, nsec: 2 },
            ctime: Timespec { sec: 30, nsec: 3 },
            rdev: None,
            symlink_target: None,
            next_dir_index: 1,
            acl_present: false,
            default_acl_present: false,
        };
        let encoded = item.encode();
        assert_eq!(encoded[0], INODE_VERSION);
        assert_eq!(encoded[1], 5);
        let decoded = InodeItem::decode(&encoded).unwrap();
        assert_eq!(decoded, item);
        assert_eq!(decoded.to_metadata().st_mode(), abi::S_IFSOCK | 0o660);

        let di = DirItemValue {
            child_ino: 42,
            child_gen: 7,
            file_type: FileType::Socket,
            dir_index: 3,
        };
        assert_eq!(DirItemValue::decode(&di.encode()).unwrap(), di);

        let didx = DirIndexValue {
            child_ino: 42,
            child_gen: 7,
            file_type: FileType::Socket,
            name: "control.sock".into(),
        };
        assert_eq!(DirIndexValue::decode(&didx.encode()).unwrap(), didx);
    }

    #[test]
    fn cowfs_mksock_persists_tag5_and_open_returns_enxio() {
        use crate::{CowFs, CowFsConfig, CowFsOpenMode};
        use cowtree::memory::{MemoryHeadStore, MemoryPackStore};
        use cowtree::{VolumeId, WriterMode};
        use std::rc::Rc;
        use vfs::{Cred, Filesystem, OpenOptions, now_or_never};

        let hs = Rc::new(MemoryHeadStore::new());
        let ps = Rc::new(MemoryPackStore::new());
        let now = Timespec {
            sec: 1_700_000_000,
            nsec: 0,
        };
        let vol = VolumeId("cowfs-sock-test".into());
        now_or_never(CowFs::format_volume(
            &*hs,
            &*ps,
            vol.clone(),
            0,
            0,
            0o755,
            now,
        ))
        .unwrap()
        .unwrap();
        let fs = now_or_never(CowFs::open(
            hs.clone(),
            ps.clone(),
            vol.clone(),
            CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
            CowFsConfig::local_browser(Rc::new(move || now)),
        ))
        .unwrap()
        .unwrap();
        let admin = Cred::root();
        let entry = now_or_never(fs.mksock(&admin, &fs.root(), "daemon.sock", 0o660))
            .unwrap()
            .unwrap();
        assert_eq!(entry.metadata.file_type, FileType::Socket);
        assert_eq!(
            entry.metadata.st_mode(),
            abi::S_IFSOCK | (0o660 & !admin.umask as u32)
        );

        // open(2) on a socket inode returns ENXIO; O_PATH succeeds.
        let mut ro = OpenOptions::new();
        ro.read(true);
        assert_eq!(
            now_or_never(fs.open(&admin, &entry.handle, &ro)).unwrap(),
            Err(Errno::ENXIO)
        );
        let mut path_opts = OpenOptions::new();
        path_opts.path(true);
        let oref = now_or_never(fs.open(&admin, &entry.handle, &path_opts))
            .unwrap()
            .unwrap();
        now_or_never(fs.release(&oref)).unwrap().unwrap();

        // Commit & reopen -> tag 5 persists intact!
        now_or_never(fs.commit_tx_group()).unwrap().unwrap();
        now_or_never(fs.close_clean()).unwrap().unwrap();

        let reopened = now_or_never(CowFs::open(
            hs,
            ps,
            vol,
            CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
            CowFsConfig::local_browser(Rc::new(move || now)),
        ))
        .unwrap()
        .unwrap();
        let found = now_or_never(reopened.lookup(&admin, &reopened.root(), "daemon.sock"))
            .unwrap()
            .unwrap();
        assert_eq!(found.metadata.file_type, FileType::Socket);
        assert_eq!(
            now_or_never(reopened.open(&admin, &found.handle, &ro)).unwrap(),
            Err(Errno::ENXIO)
        );
        now_or_never(reopened.unlink(&admin, &reopened.root(), "daemon.sock"))
            .unwrap()
            .unwrap();
    }
}

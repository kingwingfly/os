//! Converting driver metadata to stat(2) values (contract §2.5): `st_dev` from the filesystem's
//! id, `st_ino` from the node, and the live `nlink` (0 for an unlinked file still open). Every
//! driver's glue reports stat through [`stat`], so the identity rules are the same everywhere.
use crate::{FsId, Metadata, NodeId};

/// `abi::Stat` of an object of the filesystem `fs`. Owner and group names are left empty: a
/// driver knows ids, and the account database names them.
pub fn stat(fs: &FsId, node: NodeId, metadata: &Metadata) -> abi::Stat {
    abi::Stat {
        dev: fs.dev(),
        ino: node.ino,
        mode: metadata.st_mode(),
        nlink: metadata.nlink,
        uid: metadata.uid,
        gid: metadata.gid,
        user: String::new(),
        group: String::new(),
        size: metadata.size,
        mtime: metadata.mtime.sec,
        mtime_nsec: metadata.mtime.nsec,
        ctime: metadata.ctime.sec,
        ctime_nsec: metadata.ctime.nsec,
        atime: metadata.atime.sec,
        atime_nsec: metadata.atime.nsec,
        link: None,
        rdev: metadata.rdev.clone(),
        acl: metadata.acl,
        writing: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FileType, Timespec};

    #[test]
    fn identity_comes_from_the_filesystem_and_node_and_links_stay_live() {
        let metadata = Metadata {
            file_type: FileType::File,
            mode: 0o640,
            nlink: 0,
            uid: 7,
            gid: 8,
            size: 5,
            atime: Timespec { sec: 1, nsec: 2 },
            mtime: Timespec { sec: 3, nsec: 4 },
            ctime: Timespec { sec: 5, nsec: 6 },
            rdev: None,
            acl: true,
        };
        let fs = FsId("cloud".into());
        let node = NodeId {
            ino: 42,
            generation: 1,
        };
        let stat = stat(&fs, node, &metadata);
        assert_eq!((stat.dev, stat.ino, stat.nlink), (fs.dev(), 42, 0));
        assert_eq!(stat.mode, abi::S_IFREG | 0o640);
        assert!(stat.dev != 0 && stat.dev <= abi::fs::JS_SAFE);
        assert_eq!((stat.mtime, stat.mtime_nsec, stat.atime), (3, 4, 1));
        assert!(stat.acl);
    }
}

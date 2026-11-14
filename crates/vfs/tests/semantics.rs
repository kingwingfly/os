//! The VFS object model against Linux semantics, through the reference driver (memfs).

use abi::contract::Durability;
use abi::{ACL_ACCESS, ACL_DEFAULT, Errno, XATTR_CREATE, XATTR_REPLACE};
use os_vfs::memfs::MemFs;
use os_vfs::{
    Access, Cred, DescriptorTable, FILE_MAX, Filesystem, FsId, Handle, Identity, LockKind,
    LockRange, OpenFile, RENAME_NOREPLACE, SetAttr, Stop, Time, WriteAt, Written, ready,
};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::rc::Rc;

fn memfs() -> MemFs {
    let tick = Cell::new(0u64);
    MemFs::new(
        FsId("mem-test".into()),
        7,
        0,
        0,
        0o1777,
        Box::new(move || {
            tick.set(tick.get() + 1);
            (tick.get(), 0)
        }),
    )
}
fn fs() -> Rc<MemFs> {
    Rc::new(memfs())
}
fn user(id: u32) -> Cred {
    Cred::new(Identity {
        id,
        group: id,
        groups: BTreeSet::from([id]),
    })
}
fn names(path: &str) -> Vec<String> {
    path.split('/').map(String::from).collect()
}
fn new_file(fs: &MemFs, cred: &Cred, dir: &Handle, name: &str, perm: u16, data: &[u8]) -> Handle {
    let (entry, open) = ready(fs.create(cred, dir, name, perm, true, Access::Write)).unwrap();
    ready(fs.write(&open, WriteAt::Offset(0), data)).unwrap();
    ready(fs.release(&open)).unwrap();
    entry.handle
}
fn chmod(fs: &MemFs, cred: &Cred, handle: &Handle, perm: u16) -> Result<u16, Errno> {
    let set = SetAttr {
        perm: Some(perm),
        ..SetAttr::default()
    };
    ready(fs.setattr(cred, handle, &set)).map(|attr| attr.perm)
}
fn chown(
    fs: &MemFs,
    cred: &Cred,
    handle: &Handle,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<(), Errno> {
    let set = SetAttr {
        uid,
        gid,
        ..SetAttr::default()
    };
    ready(fs.setattr(cred, handle, &set)).map(|_| ())
}
/// Pages of content the filesystem holds.
fn used(fs: &MemFs) -> u64 {
    let statfs = ready(fs.statfs(&Cred::root())).unwrap();
    statfs.blocks - statfs.blocks_free
}

#[test]
fn lookup_walk_and_parent_resolve_within_the_filesystem() {
    let fs = fs();
    let root = fs.root();
    let alice = user(1000);
    let a = ready(fs.mkdir(&alice, &root, "a", 0o755)).unwrap().handle;
    let b = ready(fs.mkdir(&alice, &a, "b", 0o755)).unwrap().handle;
    let file = new_file(&fs, &alice, &b, "f", 0o644, b"hello");
    ready(fs.symlink(&alice, &a, "link", "b")).unwrap();

    let walked = ready(fs.walk(&alice, &root, &names("a/b/f"))).unwrap();
    assert_eq!(walked.stop, None);
    assert_eq!(walked.entries.last().unwrap().handle, file);
    // Stops: at a missing name, at a symlink with names after it, at a file with names after it.
    assert_eq!(
        ready(fs.walk(&alice, &root, &names("a/nope/f")))
            .unwrap()
            .stop,
        Some(Stop::Missing(1))
    );
    assert_eq!(
        ready(fs.walk(&alice, &root, &names("a/link/f")))
            .unwrap()
            .stop,
        Some(Stop::Symlink(1))
    );
    assert_eq!(
        ready(fs.walk(&alice, &root, &names("a/b/f/x")))
            .unwrap()
            .stop,
        Some(Stop::NotDirectory(2))
    );
    // A link at the end is returned as it is: the client decides whether to follow it.
    let end = ready(fs.walk(&alice, &root, &names("a/link"))).unwrap();
    assert_eq!((end.stop, end.entries.len()), (None, 2));
    for bad in [".", "..", "x/y", ""] {
        assert_eq!(
            ready(fs.lookup(&alice, &root, bad)).unwrap_err(),
            Errno::EINVAL
        );
        assert_eq!(
            ready(fs.walk(&alice, &root, &[bad.to_string()])).unwrap_err(),
            Errno::EINVAL
        );
    }
    let (parent, name) = ready(fs.parent(&alice, &b)).unwrap().unwrap();
    assert_eq!((parent.handle, name.as_str()), (a.clone(), "b"));
    assert!(ready(fs.parent(&alice, &root)).unwrap().is_none());
    // The parent follows a rename made elsewhere: `..` and getcwd stay right.
    ready(fs.rename(&alice, &a, "b", &root, "moved", 0)).unwrap();
    let (parent, name) = ready(fs.parent(&alice, &b)).unwrap().unwrap();
    assert_eq!((parent.handle, name.as_str()), (root, "moved"));
}

#[test]
fn permissions_follow_linux() {
    let fs = fs();
    let root = fs.root();
    let (alice, bob) = (user(1000), user(1001));
    let private = ready(fs.mkdir(&alice, &root, "private", 0o700))
        .unwrap()
        .handle;
    new_file(&fs, &alice, &private, "secret", 0o600, b"s");
    assert_eq!(
        ready(fs.lookup(&bob, &private, "secret")).unwrap_err(),
        Errno::EACCES
    );
    assert_eq!(
        ready(fs.readdir(&bob, &private)).unwrap_err(),
        Errno::EACCES
    );
    assert_eq!(
        ready(fs.create(&bob, &private, "x", 0o644, true, Access::Write)).unwrap_err(),
        Errno::EACCES
    );
    // The sticky root: bob cannot remove alice's file, nor rename it away.
    let shared = new_file(&fs, &alice, &root, "shared", 0o666, b"x");
    // The umask (022) applied at creation; make it writable to all explicitly.
    ready(fs.setattr(
        &alice,
        &shared,
        &SetAttr {
            perm: Some(0o666),
            ..SetAttr::default()
        },
    ))
    .unwrap();
    assert_eq!(
        ready(fs.unlink(&bob, &root, "shared")).unwrap_err(),
        Errno::EPERM
    );
    assert_eq!(
        ready(fs.rename(&bob, &root, "shared", &root, "mine", 0)).unwrap_err(),
        Errno::EPERM
    );
    // Writable to all, so bob may write it; only its owner may chmod it; only root chown.
    let open = ready(fs.open(&bob, &shared, Access::Write, false)).unwrap();
    ready(fs.release(&open)).unwrap();
    let chmod = SetAttr {
        perm: Some(0o600),
        ..SetAttr::default()
    };
    assert_eq!(
        ready(fs.setattr(&bob, &shared, &chmod)).unwrap_err(),
        Errno::EPERM
    );
    ready(fs.setattr(&alice, &shared, &chmod)).unwrap();
    let chown = SetAttr {
        uid: Some(1001),
        ..SetAttr::default()
    };
    assert_eq!(
        ready(fs.setattr(&alice, &shared, &chown)).unwrap_err(),
        Errno::EPERM
    );
    assert_eq!(
        ready(fs.setattr(&Cred::root(), &shared, &chown))
            .unwrap()
            .uid,
        1001
    );
    // protected_hardlinks: bob may not link a file he cannot read and write.
    let other = new_file(&fs, &alice, &root, "other", 0o600, b"o");
    assert_eq!(
        ready(fs.link(&bob, &other, &root, "stolen")).unwrap_err(),
        Errno::EPERM
    );
    // mknod needs root.
    assert_eq!(
        ready(fs.mknod(&alice, &root, "dev", 0o600, "null")).unwrap_err(),
        Errno::EPERM
    );
}

#[test]
fn the_creator_keeps_the_access_it_asked_for() {
    // tar: open(O_CREAT|O_WRONLY|O_EXCL, 0444), then write and ftruncate through that descriptor.
    let fs = fs();
    let root = fs.root();
    let alice = user(1000);
    let (entry, open) = ready(fs.create(&alice, &root, "ro", 0o444, true, Access::Write)).unwrap();
    assert_eq!(entry.attr.perm, 0o444 & !0o022);
    assert_eq!(
        ready(fs.write(&open, WriteAt::Offset(0), b"data"))
            .unwrap()
            .len,
        4
    );
    ready(fs.truncate(&open, 2)).unwrap();
    assert_eq!(ready(fs.getattr(&alice, &entry.handle)).unwrap().size, 2);
    // A second open for writing is refused: the mode applies to everyone else.
    assert_eq!(
        ready(fs.open(&alice, &entry.handle, Access::Write, false)).unwrap_err(),
        Errno::EACCES
    );
    // O_EXCL is atomic: the name is taken.
    assert_eq!(
        ready(fs.create(&alice, &root, "ro", 0o644, true, Access::Write)).unwrap_err(),
        Errno::EEXIST
    );
    // A read-only open reference cannot write or truncate.
    let reader = ready(fs.create(&alice, &root, "r", 0o644, true, Access::Read))
        .unwrap()
        .1;
    assert_eq!(
        ready(fs.write(&reader, WriteAt::Offset(0), b"x")).unwrap_err(),
        Errno::EBADF
    );
    assert_eq!(ready(fs.truncate(&reader, 0)).unwrap_err(), Errno::EINVAL);
}

#[test]
fn open_files_survive_unlink_and_rename_until_released() {
    let fs = fs();
    let root = fs.root();
    let alice = user(1000);
    let file = new_file(&fs, &alice, &root, "f", 0o644, b"content");
    let open = ready(fs.open(&alice, &file, Access::Read, false)).unwrap();
    ready(fs.rename(&alice, &root, "f", &root, "g", 0)).unwrap();
    assert_eq!(ready(fs.read(&open, 0, 64)).unwrap(), b"content");
    let objects = fs.inode_count();
    ready(fs.unlink(&alice, &root, "g")).unwrap();
    // Unlinked but open: still readable, nlink 0, and its content is kept.
    assert_eq!(ready(fs.read(&open, 0, 64)).unwrap(), b"content");
    assert_eq!(ready(fs.getattr(&alice, &file)).unwrap().nlink, 0);
    assert_eq!(fs.inode_count(), objects);
    ready(fs.release(&open)).unwrap();
    // Released: the content is gone and the handle is stale.
    assert_eq!(fs.inode_count(), objects - 1);
    assert_eq!(ready(fs.getattr(&alice, &file)).unwrap_err(), Errno::ESTALE);
    assert_eq!(ready(fs.read(&open, 0, 1)).unwrap_err(), Errno::EBADF);
}

#[test]
fn rename_and_remove_follow_linux() {
    let fs = fs();
    let root = fs.root();
    let alice = user(1000);
    let d = ready(fs.mkdir(&alice, &root, "d", 0o755)).unwrap().handle;
    let sub = ready(fs.mkdir(&alice, &d, "sub", 0o755)).unwrap().handle;
    new_file(&fs, &alice, &sub, "x", 0o644, b"");
    new_file(&fs, &alice, &root, "a", 0o644, b"a");
    new_file(&fs, &alice, &root, "b", 0o644, b"b");
    assert_eq!(
        ready(fs.rename(&alice, &root, "a", &root, "b", RENAME_NOREPLACE)).unwrap_err(),
        Errno::EEXIST
    );
    assert_eq!(
        ready(fs.rename(&alice, &root, "d", &sub, "loop", 0)).unwrap_err(),
        Errno::EINVAL
    );
    assert_eq!(
        ready(fs.rename(&alice, &root, "a", &root, "d", 0)).unwrap_err(),
        Errno::EISDIR
    );
    assert_eq!(
        ready(fs.rmdir(&alice, &root, "d")).unwrap_err(),
        Errno::ENOTEMPTY
    );
    assert_eq!(
        ready(fs.unlink(&alice, &root, "d")).unwrap_err(),
        Errno::EISDIR
    );
    assert_eq!(
        ready(fs.rmdir(&alice, &root, "a")).unwrap_err(),
        Errno::ENOTDIR
    );
    // Replacing rename: b now has a's content, and the old b is gone.
    ready(fs.rename(&alice, &root, "a", &root, "b", 0)).unwrap();
    let b = ready(fs.lookup(&alice, &root, "b")).unwrap();
    let open = ready(fs.open(&alice, &b.handle, Access::Read, false)).unwrap();
    assert_eq!(ready(fs.read(&open, 0, 8)).unwrap(), b"a");
    // Directory link counts follow moves.
    let other = ready(fs.mkdir(&alice, &root, "other", 0o755))
        .unwrap()
        .handle;
    ready(fs.rename(&alice, &d, "sub", &other, "sub", 0)).unwrap();
    assert_eq!(ready(fs.getattr(&alice, &d)).unwrap().nlink, 2);
    assert_eq!(ready(fs.getattr(&alice, &other)).unwrap().nlink, 3);
}

#[test]
fn hard_links_share_one_object() {
    let fs = fs();
    let root = fs.root();
    let alice = user(1000);
    let file = new_file(&fs, &alice, &root, "one", 0o644, b"shared");
    let second = ready(fs.link(&alice, &file, &root, "two")).unwrap();
    assert_eq!(second.handle, file);
    assert_eq!(second.attr.nlink, 2);
    ready(fs.unlink(&alice, &root, "one")).unwrap();
    let left = ready(fs.lookup(&alice, &root, "two")).unwrap();
    assert_eq!((left.handle, left.attr.nlink), (file, 1));
    let dir = ready(fs.mkdir(&alice, &root, "dir", 0o755)).unwrap().handle;
    assert_eq!(
        ready(fs.link(&alice, &dir, &root, "dirlink")).unwrap_err(),
        Errno::EPERM
    );
}

#[test]
fn exec_access_is_checked_against_execute_permission() {
    let fs = fs();
    let root = fs.root();
    let (alice, bob) = (user(1000), user(1001));
    let tool = new_file(&fs, &alice, &root, "tool", 0o711, b"\0asm");
    // Execute-only: bob may run it, not read it.
    ready(fs.open(&bob, &tool, Access::Exec, false)).unwrap();
    assert_eq!(
        ready(fs.open(&bob, &tool, Access::Read, false)).unwrap_err(),
        Errno::EACCES
    );
    // Root still needs an execute bit; directories do not run.
    let data = new_file(&fs, &alice, &root, "data", 0o644, b"x");
    assert_eq!(
        ready(fs.open(&Cred::root(), &data, Access::Exec, false)).unwrap_err(),
        Errno::EACCES
    );
    let dir = ready(fs.mkdir(&alice, &root, "d", 0o755)).unwrap().handle;
    assert_eq!(
        ready(fs.open(&alice, &dir, Access::Exec, false)).unwrap_err(),
        Errno::EACCES
    );
    assert_eq!(
        ready(fs.open(&alice, &dir, Access::Write, false)).unwrap_err(),
        Errno::EISDIR
    );
}

#[test]
fn forged_foreign_and_stale_handles_are_refused() {
    let fs = fs();
    let root = fs.root();
    let alice = user(1000);
    let file = new_file(&fs, &alice, &root, "f", 0o644, b"x");
    let mut forged = file.clone();
    forged.proof = "made-up".into();
    assert_eq!(
        ready(fs.getattr(&alice, &forged)).unwrap_err(),
        Errno::EACCES
    );
    let mut foreign = file.clone();
    foreign.fs = FsId("another".into());
    assert_eq!(
        ready(fs.getattr(&alice, &foreign)).unwrap_err(),
        Errno::EACCES
    );
    let mut old = file.clone();
    old.node.generation += 1;
    assert_eq!(ready(fs.getattr(&alice, &old)).unwrap_err(), Errno::ESTALE);
    ready(fs.unlink(&alice, &root, "f")).unwrap();
    assert_eq!(ready(fs.getattr(&alice, &file)).unwrap_err(), Errno::ESTALE);
}

#[test]
fn locks_conflict_between_open_references_and_go_with_them() {
    let fs = fs();
    let root = fs.root();
    let alice = user(1000);
    let file = new_file(&fs, &alice, &root, "db", 0o666, b"");
    let one = ready(fs.open(&alice, &file, Access::ReadWrite, false)).unwrap();
    let two = ready(fs.open(&alice, &file, Access::ReadWrite, false)).unwrap();
    let range = LockRange { start: 0, len: 10 };
    ready(fs.lock(&one, LockKind::Exclusive, range)).unwrap();
    assert_eq!(
        ready(fs.lock(&two, LockKind::Shared, LockRange { start: 5, len: 1 })).unwrap_err(),
        Errno::EAGAIN
    );
    ready(fs.lock(&two, LockKind::Exclusive, LockRange { start: 10, len: 5 })).unwrap();
    let conflict = ready(fs.getlk(&two, LockKind::Shared, LockRange::WHOLE))
        .unwrap()
        .unwrap();
    assert_eq!(
        (conflict.kind, conflict.owner),
        (LockKind::Exclusive, one.id)
    );
    ready(fs.release(&one)).unwrap();
    assert_eq!(
        ready(fs.getlk(&two, LockKind::Exclusive, range)).unwrap(),
        None
    );
}

#[test]
fn xattrs_follow_their_namespaces() {
    let fs = fs();
    let root = fs.root();
    let (alice, bob) = (user(1000), user(1001));
    let file = new_file(&fs, &alice, &root, "f", 0o644, b"");
    ready(fs.setxattr(&alice, &file, "user.tag", b"v", 0)).unwrap();
    assert_eq!(ready(fs.getxattr(&bob, &file, "user.tag")).unwrap(), b"v");
    assert_eq!(
        ready(fs.setxattr(&bob, &file, "user.tag", b"w", 0)).unwrap_err(),
        Errno::EACCES
    );
    assert_eq!(
        ready(fs.setxattr(&alice, &file, "trusted.x", b"t", 0)).unwrap_err(),
        Errno::EPERM
    );
    assert_eq!(
        ready(fs.setxattr(&alice, &file, "security.x", b"t", 0)).unwrap_err(),
        Errno::EOPNOTSUPP
    );
    assert_eq!(
        ready(fs.getxattr(&alice, &file, "user.none")).unwrap_err(),
        Errno::ENODATA
    );
    assert_eq!(
        ready(fs.listxattr(&alice, &file)).unwrap(),
        vec!["user.tag".to_string()]
    );
}

fn open_file(
    fs: &Rc<MemFs>,
    cred: &Cred,
    handle: &Handle,
    access: Access,
    flags: u32,
) -> Rc<OpenFile> {
    let open = ready(fs.open(cred, handle, access, false)).unwrap();
    OpenFile::new(fs.clone(), open, handle.clone(), cred.clone(), flags)
}

#[test]
fn descriptors_share_descriptions_across_dup_and_fork() {
    let fs = fs();
    let root = fs.root();
    let alice = user(1000);
    let file = new_file(&fs, &alice, &root, "f", 0o644, b"0123456789");
    let mut table = DescriptorTable::new();
    let fd = table
        .insert(open_file(&fs, &alice, &file, Access::ReadWrite, 0), false)
        .unwrap();
    assert_eq!(fd, 0);
    let dup = table.dup(fd, 0, false).unwrap();
    assert_eq!(dup, 1);
    assert_eq!(ready(table.get(fd).unwrap().read(3)).unwrap(), b"012");
    // The offset is the description's: dup and a forked child see it move.
    assert_eq!(ready(table.get(dup).unwrap().read(2)).unwrap(), b"34");
    let child = table.clone();
    assert_eq!(ready(child.get(fd).unwrap().read(1)).unwrap(), b"5");
    assert_eq!(table.get(fd).unwrap().offset(), 6);
    assert_eq!(ready(table.get(fd).unwrap().pread(0, 2)).unwrap(), b"01");
    assert_eq!(table.get(fd).unwrap().offset(), 6);
    assert_eq!(table.get(9).err(), Some(Errno::EBADF));
    // The lowest free descriptor is used again.
    ready(table.close(fd)).unwrap();
    assert_eq!(table.dup(dup, 0, false).unwrap(), 0);
}

#[test]
fn the_last_close_releases_the_open_reference() {
    let fs = fs();
    let root = fs.root();
    let alice = user(1000);
    let file = new_file(&fs, &alice, &root, "temp", 0o644, b"t");
    let mut parent = DescriptorTable::new();
    let fd = parent
        .insert(open_file(&fs, &alice, &file, Access::Read, 0), false)
        .unwrap();
    let mut child = parent.clone();
    ready(fs.unlink(&alice, &root, "temp")).unwrap();
    let objects = fs.inode_count();
    ready(parent.close(fd)).unwrap();
    // The child still holds the description: the unlinked content stays.
    assert_eq!(fs.inode_count(), objects);
    assert_eq!(ready(child.get(fd).unwrap().read(1)).unwrap(), b"t");
    ready(child.close(fd)).unwrap();
    assert_eq!(fs.inode_count(), objects - 1);
}

#[test]
fn exec_closes_close_on_exec_descriptors_and_append_writes_at_the_end() {
    let fs = fs();
    let root = fs.root();
    let alice = user(1000);
    let file = new_file(&fs, &alice, &root, "log", 0o644, b"start");
    let mut table = DescriptorTable::new();
    let keep = table
        .insert(
            open_file(&fs, &alice, &file, Access::Write, abi::O_APPEND),
            false,
        )
        .unwrap();
    let gone = table
        .insert(open_file(&fs, &alice, &file, Access::Read, 0), true)
        .unwrap();
    ready(table.exec());
    assert_eq!(table.fds().collect::<Vec<_>>(), vec![keep]);
    assert_eq!(table.get(gone).err(), Some(Errno::EBADF));
    assert_eq!(ready(table.get(keep).unwrap().write(b"+end")).unwrap(), 4);
    let reader = open_file(&fs, &alice, &file, Access::Read, 0);
    assert_eq!(ready(reader.read(64)).unwrap(), b"start+end");
    // A write-only description cannot read.
    assert_eq!(
        ready(table.get(keep).unwrap().read(1)).unwrap_err(),
        Errno::EBADF
    );
}

#[test]
fn st_dev_is_stable_per_filesystem() {
    let one = FsId("cloud:authority".into());
    assert_eq!(one.dev(), FsId("cloud:authority".into()).dev());
    assert_ne!(one.dev(), FsId("opfs:1234".into()).dev());
    assert_ne!(FsId(String::new()).dev(), 0);
}

#[test]
fn a_removed_directory_takes_no_names_and_has_no_parent() {
    let fs = fs();
    let root = fs.root();
    let alice = user(1000);
    let a = ready(fs.mkdir(&alice, &root, "a", 0o755)).unwrap().handle;
    let b = ready(fs.mkdir(&alice, &a, "b", 0o755)).unwrap().handle;
    let file = new_file(&fs, &alice, &root, "f", 0o644, b"f");
    let held = ready(fs.open(&alice, &b, Access::Read, false)).unwrap();
    let objects = fs.inode_count();
    ready(fs.rmdir(&alice, &a, "b")).unwrap();
    ready(fs.rmdir(&alice, &root, "a")).unwrap();
    // b is open and its parent gone: `..` and getcwd say ENOENT, without a panic.
    assert_eq!(ready(fs.parent(&alice, &b)).unwrap_err(), Errno::ENOENT);
    // No name goes into it, as Linux's IS_DEADDIR has it.
    assert_eq!(
        ready(fs.mkdir(&alice, &b, "x", 0o755)).unwrap_err(),
        Errno::ENOENT
    );
    assert_eq!(
        ready(fs.create(&alice, &b, "x", 0o644, true, Access::Write)).unwrap_err(),
        Errno::ENOENT
    );
    assert_eq!(
        ready(fs.symlink(&alice, &b, "x", "t")).unwrap_err(),
        Errno::ENOENT
    );
    assert_eq!(
        ready(fs.mknod(&Cred::root(), &b, "x", 0o600, "null")).unwrap_err(),
        Errno::ENOENT
    );
    assert_eq!(
        ready(fs.link(&alice, &file, &b, "x")).unwrap_err(),
        Errno::ENOENT
    );
    assert_eq!(
        ready(fs.rename(&alice, &root, "f", &b, "x", 0)).unwrap_err(),
        Errno::ENOENT
    );
    // Moving a directory into it neither panics nor succeeds.
    ready(fs.mkdir(&alice, &root, "d", 0o755)).unwrap();
    assert_eq!(
        ready(fs.rename(&alice, &root, "d", &b, "d", 0)).unwrap_err(),
        Errno::ENOENT
    );
    // Released, it goes: a and b are gone, d was made.
    ready(fs.release(&held)).unwrap();
    assert_eq!(fs.inode_count(), objects - 2 + 1);
    // An unlinked file, though still open, takes no name again.
    let open = ready(fs.open(&alice, &file, Access::Read, false)).unwrap();
    ready(fs.unlink(&alice, &root, "f")).unwrap();
    assert_eq!(
        ready(fs.link(&alice, &file, &root, "again")).unwrap_err(),
        Errno::ENOENT
    );
    ready(fs.release(&open)).unwrap();
    assert_eq!(ready(fs.getattr(&alice, &file)).unwrap_err(), Errno::ESTALE);
}

#[test]
fn offsets_are_64_bit_files_are_sparse_and_content_is_bounded() {
    let fs = memfs().with_capacity(64 * 1024);
    let root = fs.root();
    let alice = user(1000);
    let (entry, open) =
        ready(fs.create(&alice, &root, "f", 0o644, true, Access::ReadWrite)).unwrap();
    ready(fs.write(&open, WriteAt::Offset(0), b"hello")).unwrap();
    // Past 4 GiB: a hole between, not the start of the file, and only two pages held.
    let far = (1u64 << 32) + 10;
    assert_eq!(
        ready(fs.write(&open, WriteAt::Offset(far), b"tail")).unwrap(),
        Written {
            offset: far,
            len: 4
        }
    );
    assert_eq!(
        ready(fs.getattr(&alice, &entry.handle)).unwrap().size,
        far + 4
    );
    assert_eq!(ready(fs.read(&open, 1 << 32, 5)).unwrap(), vec![0; 5]);
    assert_eq!(ready(fs.read(&open, far, 64)).unwrap(), b"tail");
    assert_eq!(ready(fs.read(&open, 0, 5)).unwrap(), b"hello");
    assert_eq!(used(&fs), 2);
    // Truncating up allocates nothing; truncating down frees what it cuts, and what lay past
    // the end reads as zeros once the file grows again.
    ready(fs.truncate(&open, 1 << 40)).unwrap();
    assert_eq!(used(&fs), 2);
    ready(fs.truncate(&open, 2)).unwrap();
    assert_eq!(used(&fs), 1);
    ready(fs.truncate(&open, 6)).unwrap();
    assert_eq!(ready(fs.read(&open, 0, 64)).unwrap(), b"he\0\0\0\0");
    // At or past the largest offset: EFBIG. A write up to it is cut to fit.
    assert_eq!(
        ready(fs.write(&open, WriteAt::Offset(FILE_MAX), b"x")).unwrap_err(),
        Errno::EFBIG
    );
    assert_eq!(
        ready(fs.truncate(&open, FILE_MAX + 1)).unwrap_err(),
        Errno::EFBIG
    );
    assert_eq!(
        ready(fs.write(&open, WriteAt::Offset(FILE_MAX - 2), b"abcd")).unwrap(),
        Written {
            offset: FILE_MAX - 2,
            len: 2
        }
    );
    ready(fs.truncate(&open, 6)).unwrap();
    // Past the capacity: ENOSPC, and nothing is written.
    let big = vec![1u8; 64 * 1024];
    assert_eq!(
        ready(fs.write(&open, WriteAt::Offset(1 << 20), &big)).unwrap_err(),
        Errno::ENOSPC
    );
    assert_eq!(ready(fs.getattr(&alice, &entry.handle)).unwrap().size, 6);
    assert_eq!(used(&fs), 1);
    // A path truncate past the largest size fails too, and the content goes with the file.
    let too_big = SetAttr {
        size: Some(FILE_MAX + 1),
        ..SetAttr::default()
    };
    assert_eq!(
        ready(fs.setattr(&alice, &entry.handle, &too_big)).unwrap_err(),
        Errno::EFBIG
    );
    ready(fs.release(&open)).unwrap();
    ready(fs.unlink(&alice, &root, "f")).unwrap();
    assert_eq!(used(&fs), 0);
}

#[test]
fn locks_split_and_merge_as_fcntl_has_them() {
    let fs = fs();
    let root = fs.root();
    let alice = user(1000);
    let file = new_file(&fs, &alice, &root, "db", 0o666, b"");
    let one = ready(fs.open(&alice, &file, Access::ReadWrite, false)).unwrap();
    let two = ready(fs.open(&alice, &file, Access::ReadWrite, false)).unwrap();
    let range = |start, len| LockRange { start, len };
    ready(fs.lock(&one, LockKind::Exclusive, range(0, 100))).unwrap();
    // Unlocking the middle keeps both ends.
    ready(fs.unlock(&one, range(50, 10))).unwrap();
    for held in [range(0, 10), range(90, 10)] {
        assert_eq!(
            ready(fs.lock(&two, LockKind::Shared, held)).unwrap_err(),
            Errno::EAGAIN
        );
    }
    ready(fs.lock(&two, LockKind::Shared, range(50, 10))).unwrap();
    ready(fs.unlock(&two, range(50, 10))).unwrap();
    // Downgrading part keeps the rest exclusive.
    ready(fs.lock(&one, LockKind::Shared, range(0, 10))).unwrap();
    ready(fs.lock(&two, LockKind::Shared, range(0, 10))).unwrap();
    assert_eq!(
        ready(fs.lock(&two, LockKind::Shared, range(10, 10))).unwrap_err(),
        Errno::EAGAIN
    );
    // Locks of one kind that meet merge into one, as F_GETLK shows.
    ready(fs.lock(&one, LockKind::Exclusive, range(50, 10))).unwrap();
    let conflict = ready(fs.getlk(&two, LockKind::Shared, range(20, 1)))
        .unwrap()
        .unwrap();
    assert_eq!(conflict.range, range(10, 90));
    // A lock to the end of the file splits too.
    ready(fs.unlock(&one, LockRange::WHOLE)).unwrap();
    ready(fs.lock(&one, LockKind::Exclusive, range(100, 0))).unwrap();
    ready(fs.unlock(&one, range(200, 10))).unwrap();
    let conflict = |at| {
        ready(fs.getlk(&two, LockKind::Exclusive, range(at, 1)))
            .unwrap()
            .map(|conflict| conflict.range)
    };
    assert_eq!(conflict(150), Some(range(100, 100)));
    assert_eq!(conflict(205), None);
    assert_eq!(conflict(300), Some(range(210, 0)));
    ready(fs.lock(&two, LockKind::Exclusive, range(200, 10))).unwrap();
}

#[test]
fn appends_land_at_the_end_the_driver_sees() {
    let fs = fs();
    let root = fs.root();
    let alice = user(1000);
    let file = new_file(&fs, &alice, &root, "log", 0o644, b"start");
    // Two descriptions append in turn, neither knowing the size: neither overwrites the other.
    let one = open_file(&fs, &alice, &file, Access::Write, abi::O_APPEND);
    let two = open_file(&fs, &alice, &file, Access::Write, abi::O_APPEND);
    ready(one.write(b"+one")).unwrap();
    ready(two.write(b"+two")).unwrap();
    assert_eq!((one.offset(), two.offset()), (9, 13));
    // The driver places a write at the end it sees, and says where it went.
    let open = ready(fs.open(&alice, &file, Access::Write, false)).unwrap();
    assert_eq!(
        ready(fs.write(&open, WriteAt::End, b"!")).unwrap(),
        Written { offset: 13, len: 1 }
    );
    // pwrite with O_APPEND appends, as on Linux, and the offset stays.
    assert_eq!(ready(one.pwrite(0, b"?")).unwrap(), 1);
    assert_eq!(one.offset(), 9);
    // Cleared with fcntl, O_APPEND no longer applies: the next write goes at the offset.
    one.set_append(false);
    ready(one.write(b"X")).unwrap();
    let reader = open_file(&fs, &alice, &file, Access::Read, 0);
    assert_eq!(ready(reader.read(64)).unwrap(), b"start+oneXtwo!?");
}

#[test]
fn the_last_reference_releases_whatever_rc_clones_remain() {
    let fs = fs();
    let root = fs.root();
    let alice = user(1000);
    let mut table = DescriptorTable::new();
    let file = new_file(&fs, &alice, &root, "kept", 0o644, b"k");
    let fd = table
        .insert(open_file(&fs, &alice, &file, Access::Read, 0), false)
        .unwrap();
    ready(fs.unlink(&alice, &root, "kept")).unwrap();
    let objects = fs.inode_count();
    // A clone of the description kept past the close holds no reference.
    let kept = table.get(fd).unwrap();
    ready(table.close(fd)).unwrap();
    assert_eq!(fs.inode_count(), objects - 1);
    assert!(kept.released());
    assert_eq!(ready(kept.read(1)).unwrap_err(), Errno::EBADF);
    assert_eq!(table.insert(kept, false).unwrap_err(), Errno::EBADF);

    // A holder's reference does: a descriptor in transit outlives the close.
    let file = new_file(&fs, &alice, &root, "passed", 0o644, b"p");
    let fd = table
        .insert(open_file(&fs, &alice, &file, Access::Read, 0), false)
        .unwrap();
    let passed = table.get(fd).unwrap();
    passed.hold().unwrap();
    ready(fs.unlink(&alice, &root, "passed")).unwrap();
    let objects = fs.inode_count();
    ready(table.close(fd)).unwrap();
    assert_eq!(fs.inode_count(), objects);
    assert_eq!(ready(passed.read(1)).unwrap(), b"p");
    ready(passed.put()).unwrap();
    assert_eq!(fs.inode_count(), objects - 1);
    assert_eq!(ready(passed.put()).unwrap_err(), Errno::EBADF);

    // fork, exec, dup2 and exit each give up their references.
    let a = new_file(&fs, &alice, &root, "a", 0o644, b"a");
    let b = new_file(&fs, &alice, &root, "b", 0o644, b"b");
    let mut parent = DescriptorTable::new();
    let fa = parent
        .insert(open_file(&fs, &alice, &a, Access::Read, 0), false)
        .unwrap();
    let fb = parent
        .insert(open_file(&fs, &alice, &b, Access::Read, 0), true)
        .unwrap();
    let (da, db) = (parent.get(fa).unwrap(), parent.get(fb).unwrap());
    let mut child = parent.clone();
    ready(child.exec());
    assert_eq!(child.fds().collect::<Vec<_>>(), vec![fa]);
    assert!(!db.released());
    // dup2 over fb drops the parent's last reference to b's description.
    assert_eq!(ready(parent.dup2(fa, fb)).unwrap(), fb);
    assert!(db.released());
    ready(parent.close_all());
    assert!(!da.released());
    ready(child.close_all());
    assert!(da.released());
}

#[test]
fn protected_hard_links_follow_the_kernel() {
    let fs = fs();
    let root = fs.root();
    let (alice, bob) = (user(1000), user(1001));
    let admin = Cred::root();
    let special = |name, perm| {
        let file = new_file(&fs, &admin, &root, name, 0o644, b"x");
        assert_eq!(chmod(&fs, &admin, &file, perm).unwrap(), perm);
        file
    };
    // Someone else's setuid file, or setgid and group-executable one, even writable to all.
    for (name, perm) in [("suid", 0o4777), ("sgid", 0o2777)] {
        let file = special(name, perm);
        assert_eq!(
            ready(fs.link(&bob, &file, &root, "stolen")).unwrap_err(),
            Errno::EPERM
        );
    }
    // Setgid without group execute is no privilege: it may be linked.
    let marked = special("marked", 0o2767);
    ready(fs.link(&bob, &marked, &root, "marked2")).unwrap();
    // Nor a device someone else owns; root may link one.
    let device = ready(fs.mknod(&admin, &root, "null", 0o666, "null"))
        .unwrap()
        .handle;
    assert_eq!(
        ready(fs.link(&bob, &device, &root, "null2")).unwrap_err(),
        Errno::EPERM
    );
    ready(fs.link(&admin, &device, &root, "null2")).unwrap();
    // Its owner may link its own setuid file.
    let own = new_file(&fs, &alice, &root, "own", 0o755, b"x");
    chmod(&fs, &alice, &own, 0o4755).unwrap();
    ready(fs.link(&alice, &own, &root, "own2")).unwrap();
}

#[test]
fn xattrs_follow_the_kernel() {
    let fs = fs();
    let root = fs.root();
    let (alice, bob) = (user(1000), user(1001));
    let admin = Cred::root();
    let file = new_file(&fs, &alice, &root, "f", 0o644, b"");
    ready(fs.setxattr(&alice, &file, "user.tag", b"v", 0)).unwrap();
    // trusted.*: root's, and others see none.
    ready(fs.setxattr(&admin, &file, "trusted.t", b"t", 0)).unwrap();
    assert_eq!(
        ready(fs.getxattr(&alice, &file, "trusted.t")).unwrap_err(),
        Errno::ENODATA
    );
    assert_eq!(ready(fs.listxattr(&alice, &file)).unwrap(), ["user.tag"]);
    assert_eq!(
        ready(fs.listxattr(&admin, &file)).unwrap(),
        ["trusted.t", "user.tag"]
    );
    // XATTR_CREATE and XATTR_REPLACE.
    assert_eq!(
        ready(fs.setxattr(&alice, &file, "user.tag", b"w", XATTR_CREATE)).unwrap_err(),
        Errno::EEXIST
    );
    assert_eq!(
        ready(fs.setxattr(&alice, &file, "user.new", b"w", XATTR_REPLACE)).unwrap_err(),
        Errno::ENODATA
    );
    ready(fs.setxattr(&alice, &file, "user.tag", b"w", XATTR_REPLACE)).unwrap();
    // The limits: a name's, a value's, and one node's in all.
    let long = format!("user.{}", "x".repeat(251));
    assert_eq!(
        ready(fs.setxattr(&alice, &file, &long, b"v", 0)).unwrap_err(),
        Errno::ERANGE
    );
    assert_eq!(
        ready(fs.setxattr(&alice, &file, "user.big", &[0; 4097], 0)).unwrap_err(),
        Errno::E2BIG
    );
    ready(fs.setxattr(&alice, &file, "user.big", &[0; 4000], 0)).unwrap();
    assert_eq!(
        ready(fs.setxattr(&alice, &file, "user.more", &[0; 100], 0)).unwrap_err(),
        Errno::ENOSPC
    );
    // user.* only on regular files and directories, and a sticky directory's are its owner's.
    let link = ready(fs.symlink(&alice, &root, "l", "f")).unwrap().handle;
    assert_eq!(
        ready(fs.setxattr(&alice, &link, "user.x", b"v", 0)).unwrap_err(),
        Errno::EPERM
    );
    let sticky = ready(fs.mkdir(&alice, &root, "t", 0o1777)).unwrap().handle;
    chmod(&fs, &alice, &sticky, 0o1777).unwrap();
    assert_eq!(
        ready(fs.setxattr(&bob, &sticky, "user.x", b"v", 0)).unwrap_err(),
        Errno::EPERM
    );
    // ACLs, as getfacl and setfacl read and write them: the entries, as JSON.
    let entries = br#"{"user":6,"group":4,"other":4,"mask":6,"users":{"1001":6}}"#;
    assert_eq!(
        ready(fs.open(&bob, &file, Access::Write, false)).unwrap_err(),
        Errno::EACCES
    );
    assert_eq!(
        ready(fs.setxattr(&bob, &file, ACL_ACCESS, entries, 0)).unwrap_err(),
        Errno::EPERM
    );
    ready(fs.setxattr(&alice, &file, ACL_ACCESS, entries, 0)).unwrap();
    ready(fs.open(&bob, &file, Access::Write, false)).unwrap();
    assert!(ready(fs.getattr(&alice, &file)).unwrap().acl);
    let read: serde_json::Value =
        serde_json::from_slice(&ready(fs.getxattr(&bob, &file, ACL_ACCESS)).unwrap()).unwrap();
    assert_eq!(read["users"]["1001"], 6);
    assert!(
        ready(fs.listxattr(&alice, &file))
            .unwrap()
            .contains(&ACL_ACCESS.to_string())
    );
    // A default ACL is a directory's, and what is made in it takes it.
    let default = br#"{"user":7,"group":5,"other":0,"mask":7,"users":{"1001":7}}"#;
    assert_eq!(
        ready(fs.setxattr(&alice, &file, ACL_DEFAULT, default, 0)).unwrap_err(),
        Errno::EACCES
    );
    let shared = ready(fs.mkdir(&alice, &root, "shared", 0o755))
        .unwrap()
        .handle;
    ready(fs.setxattr(&alice, &shared, ACL_DEFAULT, default, 0)).unwrap();
    let made = new_file(&fs, &alice, &shared, "made", 0o666, b"");
    ready(fs.open(&bob, &made, Access::Write, false)).unwrap();
    // Removing an ACL leaves the mode.
    ready(fs.removexattr(&alice, &file, ACL_ACCESS)).unwrap();
    assert_eq!(
        ready(fs.removexattr(&alice, &file, ACL_ACCESS)).unwrap_err(),
        Errno::ENODATA
    );
    assert!(!ready(fs.getattr(&alice, &file)).unwrap().acl);
}

#[test]
fn modes_owners_and_times_change_as_the_kernel_has_them() {
    let fs = fs();
    let root = fs.root();
    let (alice, bob, carol) = (user(1000), user(1001), user(1002));
    let admin = Cred::root();
    // mkdir keeps the sticky bit asked for.
    let tmp = ready(fs.mkdir(&alice, &root, "tmp", 0o1777)).unwrap();
    assert_eq!(tmp.attr.perm, 0o1755);
    // chmod by an owner outside the group clears setgid, on a directory too.
    let dir = ready(fs.mkdir(&alice, &root, "g", 0o755)).unwrap().handle;
    chown(&fs, &admin, &dir, None, Some(50)).unwrap();
    assert_eq!(chmod(&fs, &alice, &dir, 0o2775).unwrap(), 0o775);
    // Only root names an owner, even the one it has; an owner names the group it has or one
    // of its own.
    let file = new_file(&fs, &alice, &root, "f", 0o644, b"");
    assert_eq!(
        chown(&fs, &bob, &file, Some(1000), None).unwrap_err(),
        Errno::EPERM
    );
    chown(&fs, &admin, &file, None, Some(50)).unwrap();
    chown(&fs, &alice, &file, None, Some(50)).unwrap();
    assert_eq!(
        chown(&fs, &alice, &file, None, Some(60)).unwrap_err(),
        Errno::EPERM
    );
    chown(&fs, &alice, &file, None, Some(1000)).unwrap();
    // Times set to now are anyone's who may write; a time given, the owner's or root's.
    let now = SetAttr {
        atime: Time::Now,
        mtime: Time::Now,
        ..SetAttr::default()
    };
    chmod(&fs, &alice, &file, 0o646).unwrap();
    ready(fs.setattr(&bob, &file, &now)).unwrap();
    chmod(&fs, &alice, &file, 0o644).unwrap();
    assert_eq!(
        ready(fs.setattr(&carol, &file, &now)).unwrap_err(),
        Errno::EACCES
    );
    let given = SetAttr {
        mtime: Time::At {
            sec: 5,
            nsec: 2_000_000_000,
        },
        ..SetAttr::default()
    };
    assert_eq!(
        ready(fs.setattr(&bob, &file, &given)).unwrap_err(),
        Errno::EPERM
    );
    let attr = ready(fs.setattr(&alice, &file, &given)).unwrap();
    assert_eq!(attr.mtime, (5, 999_999_999));
    // Leaving everything alone asks nothing and changes nothing.
    let before = ready(fs.getattr(&carol, &file)).unwrap();
    assert_eq!(
        ready(fs.setattr(&carol, &file, &SetAttr::default())).unwrap(),
        before
    );
    // A failed change changes nothing: chmod and chown together, one refused.
    let both = SetAttr {
        perm: Some(0o600),
        uid: Some(1001),
        ..SetAttr::default()
    };
    assert_eq!(
        ready(fs.setattr(&alice, &file, &both)).unwrap_err(),
        Errno::EPERM
    );
    assert_eq!(ready(fs.getattr(&alice, &file)).unwrap().perm, 0o644);
}

#[test]
fn writes_of_nothing_and_creates_of_directories_change_nothing() {
    let fs = fs();
    let root = fs.root();
    let alice = user(1000);
    let file = new_file(&fs, &alice, &root, "z", 0o644, b"abc");
    let open = ready(fs.open(&alice, &file, Access::Write, false)).unwrap();
    let before = ready(fs.getattr(&alice, &file)).unwrap();
    assert_eq!(
        ready(fs.write(&open, WriteAt::Offset(1000), b"")).unwrap(),
        Written {
            offset: 1000,
            len: 0
        }
    );
    assert_eq!(ready(fs.getattr(&alice, &file)).unwrap(), before);
    // open(O_CREAT) on a directory: EISDIR, whatever the access.
    ready(fs.mkdir(&alice, &root, "d", 0o755)).unwrap();
    for access in [Access::Read, Access::Write] {
        assert_eq!(
            ready(fs.create(&alice, &root, "d", 0o644, false, access)).unwrap_err(),
            Errno::EISDIR
        );
    }
}

#[test]
fn names_past_name_max_are_too_long() {
    let fs = fs();
    let root = fs.root();
    let alice = user(1000);
    let longest = "n".repeat(255);
    ready(fs.mkdir(&alice, &root, &longest, 0o755)).unwrap();
    let long = "n".repeat(256);
    assert_eq!(
        ready(fs.mkdir(&alice, &root, &long, 0o755)).unwrap_err(),
        Errno::ENAMETOOLONG
    );
    assert_eq!(
        ready(fs.lookup(&alice, &root, &long)).unwrap_err(),
        Errno::ENAMETOOLONG
    );
    assert_eq!(
        ready(fs.create(&alice, &root, &long, 0o644, true, Access::Write)).unwrap_err(),
        Errno::ENAMETOOLONG
    );
}

#[test]
fn memory_is_not_durable() {
    assert_eq!(fs().capabilities().durability, Durability::Volatile);
}

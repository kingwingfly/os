//! The VFS object model against Linux semantics, through the reference driver (memfs).

use abi::Errno;
use os_vfs::descriptors::release_if_last;
use os_vfs::memfs::MemFs;
use os_vfs::{
    Access, Cred, DescriptorTable, Filesystem, FsId, Handle, Identity, LockKind, LockRange,
    OpenFile, RENAME_NOREPLACE, SetAttr, Stop, ready,
};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::rc::Rc;

fn fs() -> Rc<MemFs> {
    let tick = Cell::new(0u64);
    Rc::new(MemFs::new(
        FsId("mem-test".into()),
        7,
        0,
        0,
        0o1777,
        Box::new(move || {
            tick.set(tick.get() + 1);
            (tick.get(), 0)
        }),
    ))
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
    ready(fs.write(&open, 0, data)).unwrap();
    ready(fs.release(&open)).unwrap();
    entry.handle
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
    assert_eq!(ready(fs.write(&open, 0, b"data")).unwrap(), 4);
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
    assert_eq!(ready(fs.write(&reader, 0, b"x")).unwrap_err(), Errno::EBADF);
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
    ready(fs.setxattr(&alice, &file, "user.tag", b"v")).unwrap();
    assert_eq!(ready(fs.getxattr(&bob, &file, "user.tag")).unwrap(), b"v");
    assert_eq!(
        ready(fs.setxattr(&bob, &file, "user.tag", b"w")).unwrap_err(),
        Errno::EACCES
    );
    assert_eq!(
        ready(fs.setxattr(&alice, &file, "trusted.x", b"t")).unwrap_err(),
        Errno::EPERM
    );
    assert_eq!(
        ready(fs.setxattr(&alice, &file, "security.x", b"t")).unwrap_err(),
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
    assert_eq!(table.insert(table.get(dup).unwrap(), false).unwrap(), 0);
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
    for file in table.exec() {
        ready(release_if_last(file)).unwrap();
    }
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

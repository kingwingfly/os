//! The kernel's description table over a driver (#48): path resolution within the driver,
//! descriptions shared across fork and released by their last holder, and live identity.
use abi::Errno;
use os_vfs::descriptions::{Descriptions, Resolved};
use os_vfs::memfs::MemFs;
use os_vfs::{Cred, Filesystem, FsId, OpenOptions, SeekFrom, now_or_never};
use std::cell::Cell;
use std::future::Future;
use std::rc::Rc;

fn run<F: Future>(future: F) -> F::Output {
    now_or_never(future).expect("memfs never waits")
}
fn table() -> (Rc<MemFs>, Descriptions) {
    let tick = Cell::new(0u64);
    let fs = Rc::new(MemFs::new(
        FsId("cloud-test".into()),
        1,
        0,
        0,
        0o1777,
        Box::new(move || {
            tick.set(tick.get() + 1);
            (tick.get(), 0)
        }),
    ));
    let table = Descriptions::new(fs.clone());
    (fs, table)
}
fn everywhere(_: &str) -> bool {
    true
}
fn create() -> OpenOptions {
    *OpenOptions::new().read(true).write(true).create(true)
}
fn read() -> OpenOptions {
    *OpenOptions::new().read(true)
}
fn mkdir(fs: &MemFs, path: &str) {
    let cred = Cred::root();
    let mut dir = fs.root();
    for name in path.split('/').filter(|n| !n.is_empty()) {
        dir = match run(fs.lookup(&cred, &dir, name)) {
            Ok(entry) => entry.handle,
            Err(_) => run(fs.mkdir(&cred, &dir, name, 0o755)).unwrap().handle,
        };
    }
}
fn symlink(fs: &MemFs, dir: &str, name: &str, target: &str) {
    let cred = Cred::root();
    let mut handle = fs.root();
    for part in dir.split('/').filter(|n| !n.is_empty()) {
        handle = run(fs.lookup(&cred, &handle, part)).unwrap().handle;
    }
    run(fs.symlink(&cred, &handle, name, target)).unwrap();
}

#[test]
fn paths_resolve_within_the_driver_with_dotdot_and_symlinks_followed_here() {
    let (fs, table) = table();
    let cred = Cred::root();
    mkdir(&fs, "/a/b/c");
    symlink(&fs, "/a", "up", "b/c/..");
    symlink(&fs, "/a", "abs", "/a/b");
    symlink(&fs, "/a", "loop", "loop");
    let opened = run(table.open(1, &cred, "/a/b/c/../f", &create(), 0o644, &everywhere))
        .unwrap()
        .unwrap();
    let ino = opened.entry.handle.node.ino;
    for path in [
        "/a/b/f",
        "/a/up/f",
        "/a/abs/f",
        "/a/./b//f",
        "/../a/b/c/../../b/f",
    ] {
        match run(table.resolve(&cred, path, true, &everywhere)).unwrap() {
            Some(Resolved::Found { entry, name, .. }) => {
                assert_eq!((entry.handle.node.ino, name.as_str()), (ino, "f"), "{path}");
            }
            other => panic!("{path}: {other:?}"),
        }
    }
    assert!(matches!(
        run(table.resolve(&cred, "/a/b/missing", true, &everywhere)).unwrap(),
        Some(Resolved::Missing { name, .. }) if name == "missing"
    ));
    assert!(matches!(
        run(table.resolve(&cred, "/a/b/..", true, &everywhere)).unwrap(),
        Some(Resolved::Directory(_))
    ));
    assert_eq!(
        run(table.resolve(&cred, "/a/loop/x", true, &everywhere)).unwrap_err(),
        Errno::ELOOP
    );
    assert_eq!(
        run(table.resolve(&cred, "/a/missing/x", true, &everywhere)).unwrap_err(),
        Errno::ENOENT
    );
    assert_eq!(
        run(table.resolve(&cred, "/a/b/f/x", true, &everywhere)).unwrap_err(),
        Errno::ENOTDIR
    );
    assert_eq!(
        run(table.resolve(&cred, "/a/b/f/", true, &everywhere)).unwrap_err(),
        Errno::ENOTDIR
    );
    assert_eq!(
        run(table.resolve(&cred, "relative", true, &everywhere)).unwrap_err(),
        Errno::EINVAL
    );
}

#[test]
fn paths_outside_the_driver_are_left_to_the_caller_even_through_symlinks() {
    let (fs, table) = table();
    let cred = Cred::root();
    mkdir(&fs, "/proc/1");
    mkdir(&fs, "/home");
    symlink(&fs, "/home", "self", "/proc/1");
    let inside = |path: &str| path != "/proc" && !path.starts_with("/proc/");
    for path in ["/proc/1/status", "/home/self/status", "/home/../proc"] {
        assert!(
            run(table.resolve(&cred, path, true, &inside))
                .unwrap()
                .is_none(),
            "{path}"
        );
        assert!(
            run(table.open(1, &cred, path, &read(), 0, &inside))
                .unwrap()
                .is_none()
        );
    }
    // Directories and devices are not this table's either.
    assert!(
        run(table.open(1, &cred, "/home", &read(), 0, &inside))
            .unwrap()
            .is_none()
    );
}

#[test]
fn creation_follows_dangling_links_but_exclusive_creation_never_does() {
    let (fs, table) = table();
    let cred = Cred::root();
    mkdir(&fs, "/d");
    symlink(&fs, "/d", "dangling", "target");
    let exclusive = *OpenOptions::new().write(true).create_new(true);
    assert_eq!(
        run(table.open(1, &cred, "/d/dangling", &exclusive, 0o600, &everywhere))
            .err()
            .unwrap(),
        Errno::EEXIST
    );
    let made = run(table.open(1, &cred, "/d/dangling", &create(), 0o600, &everywhere))
        .unwrap()
        .unwrap();
    assert_eq!(made.entry.metadata.mode, 0o600 & !0o022);
    assert!(matches!(
        run(table.resolve(&cred, "/d/target", false, &everywhere)).unwrap(),
        Some(Resolved::Found { entry, .. }) if entry.handle == made.entry.handle
    ));
    assert_eq!(
        run(table.open(1, &cred, "/d/new/", &create(), 0o600, &everywhere))
            .err()
            .unwrap(),
        Errno::EISDIR
    );
    assert_eq!(
        run(table.open(1, &cred, "/d/absent", &read(), 0, &everywhere))
            .err()
            .unwrap(),
        Errno::ENOENT
    );
}

#[test]
fn descriptions_are_shared_by_forks_and_released_by_the_last_holder() {
    let (fs, table) = table();
    let cred = Cred::root();
    mkdir(&fs, "/d");
    let opened = run(table.open(10, &cred, "/d/f", &create(), 0o644, &everywhere))
        .unwrap()
        .unwrap();
    let id = opened.id;
    drop(opened);
    let file = table.get(10, id).unwrap();
    assert_eq!(run(file.write(b"hello")).unwrap(), 5);
    drop(file);
    // Another process holds nothing until it inherits.
    assert_eq!(table.get(11, id).err().unwrap(), Errno::EBADF);
    assert_eq!(table.inherit(11, 12, &[id]).unwrap_err(), Errno::EBADF);
    table.inherit(10, 11, &[id]).unwrap();
    // The position is the description's, shared by parent and child.
    assert_eq!(
        run(table.get(11, id).unwrap().seek(SeekFrom::Current(0))).unwrap(),
        5
    );
    run(table.close(10, id)).unwrap();
    assert_eq!(run(table.close(10, id)).unwrap_err(), Errno::EBADF);
    // Unlinked while the child still holds it: content and identity stay, with no links.
    let dir = run(fs.lookup(&cred, &fs.root(), "d")).unwrap().handle;
    run(fs.unlink(&cred, &dir, "f")).unwrap();
    let file = table.get(11, id).unwrap();
    let metadata = run(file.metadata()).unwrap();
    assert_eq!((metadata.nlink, metadata.size), (0, 5));
    let stat = os_vfs::stat::stat(&file.handle().fs, file.handle().node, &metadata);
    assert_eq!(stat.dev, FsId("cloud-test".into()).dev());
    let mut buf = [0; 5];
    assert_eq!(run(file.read_at(&mut buf, 0)).unwrap(), 5);
    let handle = file.handle().clone();
    drop(file);
    run(table.exit(11));
    assert!(table.is_empty());
    // The last holder's exit released the open reference, and the unlinked inode went.
    assert_eq!(run(fs.metadata(&cred, &handle)).unwrap_err(), Errno::ESTALE);
}

#[test]
fn seek_end_and_append_use_the_driver_size() {
    let (fs, table) = table();
    let cred = Cred::root();
    mkdir(&fs, "/d");
    let id = run(table.open(1, &cred, "/d/f", &create(), 0o644, &everywhere))
        .unwrap()
        .unwrap()
        .id;
    let file = table.get(1, id).unwrap();
    run(file.write(b"abc")).unwrap();
    run(file.seek(SeekFrom::Start(0))).unwrap();
    assert_eq!(run(file.seek(SeekFrom::End(1))).unwrap(), 4);
    file.set_append(true);
    run(file.seek(SeekFrom::Start(0))).unwrap();
    run(file.write(b"de")).unwrap();
    assert_eq!(run(file.seek(SeekFrom::Current(0))).unwrap(), 5);
    let truncate = *OpenOptions::new().write(true).truncate(true);
    let again = run(table.open(1, &cred, "/d/f", &truncate, 0, &everywhere))
        .unwrap()
        .unwrap();
    assert_eq!(run(again.file.metadata()).unwrap().size, 0);
    drop((file, again));
    run(table.exit(1));
    assert!(table.is_empty());
}

#[test]
fn open_with_enforces_nofollow_and_directory_flags() {
    let (fs, table) = table();
    let cred = Cred::root();
    mkdir(&fs, "/d");
    run(table.open(1, &cred, "/d/target", &create(), 0o644, &everywhere))
        .unwrap()
        .unwrap();
    symlink(&fs, "/d", "link_file", "target");
    symlink(&fs, "/d", "link_dir", ".");

    // O_NOFOLLOW rejects symlinks with ELOOP, even if O_DIRECTORY is also set.
    for dir in [false, true] {
        assert_eq!(
            run(table.open_with(1, &cred, "/d/link_file", &read(), 0, true, dir, &everywhere))
                .err()
                .unwrap(),
            Errno::ELOOP
        );
        assert_eq!(
            run(table.open_with(1, &cred, "/d/link_dir", &read(), 0, true, dir, &everywhere))
                .err()
                .unwrap(),
            Errno::ELOOP
        );
    }

    // O_CREAT | O_EXCL returns EEXIST on a symlink even when O_NOFOLLOW is passed.
    let excl = *OpenOptions::new().write(true).create_new(true);
    assert_eq!(
        run(table.open_with(
            1,
            &cred,
            "/d/link_file",
            &excl,
            0o644,
            true,
            false,
            &everywhere
        ))
        .err()
        .unwrap(),
        Errno::EEXIST
    );

    // O_PATH with O_NOFOLLOW still resolves the symlink entry (fallback None since non-regular).
    let path_only = *OpenOptions::new().path(true);
    assert!(
        run(table.open_with(
            1,
            &cred,
            "/d/link_file",
            &path_only,
            0,
            true,
            false,
            &everywhere
        ))
        .unwrap()
        .is_none()
    );

    // O_DIRECTORY rejects non-directories with ENOTDIR, falls back to None on directories,
    // and returns ENOENT / EINVAL on missing targets.
    assert_eq!(
        run(table.open_with(1, &cred, "/d/target", &read(), 0, false, true, &everywhere))
            .err()
            .unwrap(),
        Errno::ENOTDIR
    );
    assert!(
        run(table.open_with(1, &cred, "/d", &read(), 0, false, true, &everywhere))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        run(table.open_with(1, &cred, "/d/absent", &read(), 0, false, true, &everywhere))
            .err()
            .unwrap(),
        Errno::ENOENT
    );
    assert_eq!(
        run(table.open_with(
            1,
            &cred,
            "/d/absent",
            &create(),
            0o644,
            false,
            true,
            &everywhere
        ))
        .err()
        .unwrap(),
        Errno::EINVAL
    );

    run(table.exit(1));
    assert!(table.is_empty());
}

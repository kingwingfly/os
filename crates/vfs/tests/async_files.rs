//! Exercise description lifetimes and shared positions while driver operations are pending.

use abi::Errno;
use abi::contract::FsCapabilities;
use os_vfs::memfs::MemFs;
use os_vfs::*;
use std::cell::{Cell, RefCell};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

#[derive(Default)]
struct Gate {
    blocked: Cell<bool>,
    waiters: RefCell<Vec<Waker>>,
}
impl Gate {
    async fn wait(&self) {
        poll_fn(|cx| {
            if self.blocked.get() {
                self.waiters.borrow_mut().push(cx.waker().clone());
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await
    }
    fn resume(&self) {
        self.blocked.set(false);
        for waker in self.waiters.take() {
            waker.wake();
        }
    }
}

struct DelayedFs {
    inner: MemFs,
    reads: Gate,
    releases: Gate,
    offsets: RefCell<Vec<u64>>,
}

macro_rules! delegate {
    ($(fn $name:ident($($arg:ident: $ty:ty),*) -> $ret:ty;)*) => {
        $(fn $name<'a>(&'a self, $($arg: $ty),*) -> BoxFuture<'a, $ret> {
            self.inner.$name($($arg),*)
        })*
    };
}

impl Filesystem for DelayedFs {
    fn id(&self) -> &FsId {
        self.inner.id()
    }
    fn root(&self) -> Handle {
        self.inner.root()
    }
    fn capabilities(&self) -> FsCapabilities {
        self.inner.capabilities()
    }
    delegate! {
        fn lookup(cred: &'a Cred, dir: &'a Handle, name: &'a str) -> Entry;
        fn walk(cred: &'a Cred, dir: &'a Handle, names: &'a [String]) -> Walked;
        fn parent(cred: &'a Cred, dir: &'a Handle) -> Option<(Entry, String)>;
        fn metadata(cred: &'a Cred, handle: &'a Handle) -> Metadata;
        fn open_metadata(open: &'a OpenRef) -> Metadata;
        fn setattr(cred: &'a Cred, handle: &'a Handle, attr: &'a SetAttr) -> Metadata;
        fn read_dir(cred: &'a Cred, dir: &'a Handle) -> Vec<DirEntry>;
        fn read_link(cred: &'a Cred, link: &'a Handle) -> String;
        fn create(cred: &'a Cred, dir: &'a Handle, name: &'a str, mode: u16, options: &'a OpenOptions) -> (Entry, OpenRef);
        fn mkdir(cred: &'a Cred, dir: &'a Handle, name: &'a str, mode: u16) -> Entry;
        fn mknod(cred: &'a Cred, dir: &'a Handle, name: &'a str, mode: u16, rdev: &'a str) -> Entry;
        fn symlink(cred: &'a Cred, dir: &'a Handle, name: &'a str, target: &'a str) -> Entry;
        fn link(cred: &'a Cred, target: &'a Handle, dir: &'a Handle, name: &'a str) -> Entry;
        fn unlink(cred: &'a Cred, dir: &'a Handle, name: &'a str) -> ();
        fn rmdir(cred: &'a Cred, dir: &'a Handle, name: &'a str) -> ();
        fn rename(cred: &'a Cred, from_dir: &'a Handle, from: &'a str, to_dir: &'a Handle, to: &'a str, flags: RenameFlags) -> ();
        fn getxattr(cred: &'a Cred, handle: &'a Handle, name: &'a str) -> Vec<u8>;
        fn setxattr(cred: &'a Cred, handle: &'a Handle, name: &'a str, value: &'a [u8], flags: XattrFlags) -> ();
        fn listxattr(cred: &'a Cred, handle: &'a Handle) -> Vec<String>;
        fn removexattr(cred: &'a Cred, handle: &'a Handle, name: &'a str) -> ();
        fn statfs(cred: &'a Cred) -> StatFs;
        fn open(cred: &'a Cred, handle: &'a Handle, options: &'a OpenOptions) -> OpenRef;
        fn write_at(open: &'a OpenRef, buf: &'a [u8], at: WriteAt) -> Written;
        fn set_len(open: &'a OpenRef, size: u64) -> ();
        fn sync_all(open: &'a OpenRef) -> ();
        fn lock(open: &'a OpenRef, family: LockFamily, kind: LockKind, range: LockRange) -> ();
        fn try_lock(open: &'a OpenRef, family: LockFamily, kind: LockKind, range: LockRange) -> ();
        fn unlock(open: &'a OpenRef, family: LockFamily, range: LockRange) -> ();
        fn test_lock(open: &'a OpenRef, kind: LockKind, range: LockRange) -> Option<Conflict>;
    }
    fn read_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a mut [u8],
        offset: u64,
    ) -> BoxFuture<'a, usize> {
        Box::pin(async move {
            self.offsets.borrow_mut().push(offset);
            self.reads.wait().await;
            self.inner.read_at(open, buf, offset).await
        })
    }
    fn release<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.releases.wait().await;
            self.inner.release(open).await
        })
    }
}

fn poll<F: Future + ?Sized>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}
fn run<F: Future>(future: F) -> F::Output {
    now_or_never(future).expect("call should complete")
}
fn fixture() -> (Rc<DelayedFs>, FileRef, ReleaseQueue) {
    let fs = Rc::new(DelayedFs {
        inner: MemFs::new(FsId("delayed".into()), 1, 0, 0, 0o755, Box::new(|| (1, 0))),
        reads: Gate::default(),
        releases: Gate::default(),
        offsets: RefCell::default(),
    });
    let cred = Cred::root();
    let options = *OpenOptions::new().read(true).write(true).create_new(true);
    let (entry, open) = run(fs.create(&cred, &fs.root(), "f", 0o600, &options)).unwrap();
    run(fs.write_at(&open, b"abcdef", WriteAt::Offset(0))).unwrap();
    let queue = ReleaseQueue::new();
    let file = FileRef::new(fs.clone(), open, entry.handle, cred, &options, &queue);
    (fs, file, queue)
}

#[test]
fn concurrent_reads_share_a_position_and_cancelled_reads_do_not_advance_it() {
    let (fs, file, _) = fixture();
    let other = file.clone();
    fs.reads.blocked.set(true);
    let (mut first_buf, mut second_buf, mut cancelled_buf) = ([0; 2], [0; 2], [0; 2]);
    let mut first = Box::pin(file.read(&mut first_buf));
    let mut cancelled = Box::pin(other.read(&mut cancelled_buf));
    let mut second = Box::pin(other.read(&mut second_buf));
    assert!(poll(first.as_mut()).is_pending());
    assert!(poll(cancelled.as_mut()).is_pending());
    assert!(poll(second.as_mut()).is_pending());
    assert_eq!(*fs.offsets.borrow(), [0]);
    drop(cancelled);
    fs.reads.resume();
    assert_eq!(poll(first.as_mut()), Poll::Ready(Ok(2)));
    assert_eq!(poll(second.as_mut()), Poll::Ready(Ok(2)));
    drop((first, second));
    assert_eq!(
        (&first_buf, &second_buf, file.position()),
        (b"ab", b"cd", 4)
    );
    assert_eq!(*fs.offsets.borrow(), [0, 2]);
    // Cancelling the operation holding the position lock also lets the next call proceed.
    fs.reads.blocked.set(true);
    let mut cancelled = Box::pin(file.read(&mut cancelled_buf));
    assert!(poll(cancelled.as_mut()).is_pending());
    drop(cancelled);
    fs.reads.resume();
    assert_eq!(run(other.read(&mut second_buf)), Ok(2));
    assert_eq!((&second_buf, file.position()), (b"ef", 6));
}

#[test]
fn cancelled_close_and_queue_flush_preserve_the_outstanding_release() {
    let (fs, file, queue) = fixture();
    let handle = file.handle().clone();
    run(fs.unlink(&Cred::root(), &fs.root(), "f")).unwrap();
    fs.releases.blocked.set(true);
    let mut close = Box::pin(file.close());
    assert!(poll(close.as_mut()).is_pending());
    drop(close);
    assert_eq!(queue.len(), 1);
    assert_eq!(fs.inner.inode_count(), 2);
    let mut flush = Box::pin(queue.flush());
    assert!(poll(flush.as_mut()).is_pending());
    drop(flush);
    assert_eq!(queue.len(), 1);
    fs.releases.resume();
    run(queue.flush()).unwrap();
    assert!(queue.is_empty());
    assert_eq!(fs.inner.inode_count(), 1);
    assert_eq!(run(fs.metadata(&Cred::root(), &handle)), Err(Errno::ESTALE));
}

#[test]
fn seeking_rejects_path_only_access_and_offsets_outside_off_t() {
    let (fs, file, queue) = fixture();
    assert_eq!(run(file.seek(SeekFrom::Start(FILE_MAX))), Ok(FILE_MAX));
    for from in [
        SeekFrom::Current(1),
        SeekFrom::Start(u64::MAX),
        SeekFrom::End(i64::MAX),
    ] {
        assert_eq!(run(file.seek(from)), Err(Errno::EINVAL));
        assert_eq!(file.position(), FILE_MAX);
    }
    let cred = Cred::root();
    let options = *OpenOptions::new().path(true);
    let open = run(fs.open(&cred, file.handle(), &options)).unwrap();
    let path = FileRef::new(
        fs.clone(),
        open,
        file.handle().clone(),
        cred,
        &options,
        &queue,
    );
    for from in [SeekFrom::Start(0), SeekFrom::Current(0), SeekFrom::End(0)] {
        assert_eq!(run(path.seek(from)), Err(Errno::EBADF));
    }
    assert_eq!(run(path.metadata()).unwrap().size, 6);
}

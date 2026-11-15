use abi::Errno;
use abi::remote_fs::{self as wire, Call, DataRequest};
use os_vfs::{
    cloud::{CloudFs, Transport},
    locks::{Held, Locks},
    *,
};
use serde_json::{Value, json};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};
#[derive(Clone, Default)]
struct Host {
    pending: Rc<Cell<bool>>,
    calls: Rc<RefCell<Vec<Call>>>,
    next: Rc<Cell<u64>>,
    actor: Rc<RefCell<(String, Option<u32>)>>,
    data: Rc<RefCell<Vec<DataRequest>>>,
    requests: Rc<RefCell<Vec<wire::Request>>>,
    failure: Rc<Cell<Option<Errno>>>,
    denied: Rc<RefCell<Vec<String>>>,
    granted: Rc<Cell<bool>>,
}
fn root() -> Handle {
    Handle {
        fs: FsId("remote".into()),
        node: NodeId {
            ino: 1,
            generation: 1,
        },
        proof: "proof".into(),
    }
}
fn open() -> OpenRef {
    OpenRef {
        fs: root().fs,
        id: 1,
        node: NodeId {
            ino: 2,
            generation: 1,
        },
        access: Access::ReadWrite,
    }
}
impl Transport for Host {
    fn caller(&self) -> Result<(String, Option<u32>)> {
        Ok(self.actor.borrow().clone())
    }
    fn request(&self, request: wire::Request) -> BoxFuture<'_, Value> {
        Box::pin(async move {
            self.calls.borrow_mut().push(request.call.clone());
            self.requests.borrow_mut().push(request.clone());
            std::future::poll_fn(|_| {
                if self.pending.get() {
                    std::task::Poll::Pending
                } else {
                    std::task::Poll::Ready(())
                }
            })
            .await;
            if let Some(error) = self.failure.get() {
                return Err(error);
            }
            if self.denied.borrow().contains(&request.credential) {
                return Err(Errno::EACCES);
            }
            Ok(match request.call {
                Call::Connect => json!(wire::Connected {
                    version: 2,
                    session: wire::Session {
                        id: "session".into(),
                        secret: "secret".into()
                    },
                    root: root(),
                    capabilities: profiles::CLOUD,
                    lease_seconds: 120
                }),
                Call::Open { .. } => json!(open()),
                Call::Metadata { .. } | Call::OpenMetadata { .. } => json!({
                    "file_type":"file", "mode":384, "nlink":0, "uid":0, "gid":0,
                    "size":20, "atime":{"sec":0,"nsec":0}, "mtime":{"sec":0,"nsec":0},
                    "ctime":{"sec":0,"nsec":0}, "rdev":null, "acl":false
                }),
                Call::Lock { .. } => json!(self.granted.get()),
                _ => Value::Null,
            })
        })
    }
    fn read(&self, request: DataRequest) -> BoxFuture<'_, Vec<u8>> {
        Box::pin(async move {
            self.data.borrow_mut().push(request);
            Ok(Vec::new())
        })
    }
    fn write<'a>(&'a self, request: DataRequest, bytes: &'a [u8]) -> BoxFuture<'a, Written> {
        Box::pin(async move {
            self.data.borrow_mut().push(request);
            Ok(Written {
                offset: 0,
                len: bytes.len(),
            })
        })
    }
    fn pause(&self) -> BoxFuture<'_, ()> {
        Box::pin(std::future::pending())
    }
    fn ticket(&self) -> String {
        let n = self.next.get() + 1;
        self.next.set(n);
        n.to_string()
    }
}
fn ready<T>(future: BoxFuture<'_, T>) -> Result<T> {
    now_or_never(future).expect("ready")
}
#[test]
fn creation_sends_the_current_umask_separately_from_the_requested_mode() {
    let host = Host::default();
    let fs = now_or_never(CloudFs::connect(host.clone(), "credential".into()))
        .unwrap()
        .unwrap();
    let mut cred = Cred::root();
    cred.token = Some("credential".into());
    let options = *OpenOptions::new().read(true).write(true).create(true);
    for mask in [0o077, 0o002, 0] {
        cred.umask = mask;
        host.pending.set(true);
        assert!(now_or_never(fs.mkdir(&cred, &root(), "dir", 0o777)).is_none());
        assert!(now_or_never(fs.mknod(&cred, &root(), "device", 0o666, "present")).is_none());
        assert!(now_or_never(fs.create(&cred, &root(), "file", 0o666, &options)).is_none());
        {
            let calls = host.calls.borrow();
            for call in &calls[calls.len() - 3..] {
                let value = serde_json::to_value(call).unwrap();
                let (kind, args) = value.as_object().unwrap().iter().next().unwrap();
                assert_eq!(args["umask"], json!(mask));
                // Applying umask on the client would prevent default ACL inheritance.
                assert_eq!(
                    args["mode"],
                    json!(if kind == "mkdir" { 0o777 } else { 0o666 })
                );
                let mut omitted = value.clone();
                omitted[kind].as_object_mut().unwrap().remove("umask");
                assert!(serde_json::from_value::<Call>(omitted).is_err());
            }
        }
        host.pending.set(false);
        assert_eq!(now_or_never(fs.drain()), Some(Ok(())));
    }
}
#[test]
fn abandoned_and_cancelled_remote_opens_keep_cleanup_until_delivered() {
    let host = Host::default();
    let fs = now_or_never(CloudFs::connect(host.clone(), "credential".into()))
        .unwrap()
        .unwrap();
    let mut cred = Cred::root();
    cred.token = Some("credential".into());
    let opts = *OpenOptions::new().read(true);
    drop(fs.open(&cred, &root(), &opts));
    assert_eq!(host.calls.borrow().len(), 1);
    host.pending.set(true);
    assert!(now_or_never(fs.open(&cred, &root(), &opts)).is_none());
    assert_eq!(fs.pending_cancellations(), 1);
    // Cancelling cleanup itself preserves it; a later reconnection drains it once.
    assert!(now_or_never(fs.drain()).is_none());
    assert_eq!(fs.pending_cancellations(), 1);
    host.pending.set(false);
    assert_eq!(now_or_never(fs.drain()), Some(Ok(())));
    assert_eq!(fs.pending_cancellations(), 0);
    assert!(matches!(host.calls.borrow().last(),Some(Call::CancelOpen{ticket}) if ticket=="1"));
}
#[test]
fn descriptor_metadata_and_seek_end_use_the_current_caller_after_exec() {
    use std::task::{Context, Poll, Waker};
    let host = Host::default();
    let fs = Rc::new(
        now_or_never(CloudFs::connect(host.clone(), "opener".into()))
            .unwrap()
            .unwrap(),
    );
    let mut cred = Cred::root();
    cred.token = Some("opener".into());
    let options = *OpenOptions::new().read(true).write(true);
    let opened = ready(fs.open(&cred, &root(), &options)).unwrap();
    let queue = ReleaseQueue::new();
    let file = FileRef::new(
        fs.clone(),
        opened.clone(),
        Handle {
            node: opened.node,
            ..root()
        },
        cred.clone(),
        &options,
        &queue,
    );
    host.denied
        .borrow_mut()
        .extend(["opener".into(), "revoked".into(), "cloud denied".into()]);
    *host.actor.borrow_mut() = ("replacement".into(), Some(42));
    assert_eq!(now_or_never(file.metadata()).unwrap().unwrap().size, 20);
    assert_eq!(now_or_never(file.seek(SeekFrom::End(-2))), Some(Ok(18)));
    // Ordinary handle calls still authenticate their explicit credential.
    assert_eq!(ready(fs.metadata(&cred, file.handle())), Err(Errno::EACCES));
    for token in ["revoked", "cloud denied"] {
        *host.actor.borrow_mut() = (token.into(), Some(42));
        assert_eq!(now_or_never(file.metadata()), Some(Err(Errno::EACCES)));
        assert_eq!(
            now_or_never(file.seek(SeekFrom::End(0))),
            Some(Err(Errno::EACCES))
        );
        assert_eq!(file.position(), 18);
    }
    // The driver keeps the actor it sampled before deferred cleanup or transport waits.
    for seek in [false, true] {
        *host.actor.borrow_mut() = ("replacement".into(), Some(42));
        cred.token = Some("replacement".into());
        host.pending.set(true);
        assert!(now_or_never(fs.open(&cred, &root(), &options)).is_none());
        let mut operation: BoxFuture<'_, u64> = if seek {
            Box::pin(file.seek(SeekFrom::End(0)))
        } else {
            Box::pin(async { file.metadata().await.map(|m| m.size) })
        };
        assert!(matches!(
            operation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ));
        *host.actor.borrow_mut() = ("revoked".into(), Some(43));
        host.pending.set(false);
        assert_eq!(ready(operation), Ok(20));
    }
    *host.actor.borrow_mut() = ("replacement".into(), Some(42));
    assert_eq!(now_or_never(file.close()), Some(Ok(())));
}
#[test]
fn cancelled_release_is_retried_and_invalid_read_offsets_never_cross_transport() {
    let host = Host::default();
    let fs = now_or_never(CloudFs::connect(host.clone(), "credential".into()))
        .unwrap()
        .unwrap();
    let mut cred = Cred::root();
    cred.token = Some("credential".into());
    let opened = ready(fs.open(&cred, &root(), OpenOptions::new().read(true).write(true))).unwrap();
    assert_eq!(
        ready(fs.read_at(&opened, &mut [], u64::MAX)),
        Err(Errno::EINVAL)
    );
    let mut forged = opened.clone();
    forged.node.ino += 1;
    assert_eq!(ready(fs.release(&forged)), Err(Errno::EACCES));
    assert_eq!(fs.pending_cancellations(), 0);
    host.pending.set(true);
    assert!(now_or_never(fs.release(&opened)).is_none());
    assert_eq!(fs.pending_cancellations(), 1);
    host.pending.set(false);
    assert_eq!(now_or_never(fs.drain()), Some(Ok(())));
    assert_eq!(ready(fs.sync_all(&opened)), Err(Errno::EBADF));
}
#[test]
fn data_calls_snapshot_the_current_process_before_waiting_for_cleanup() {
    use std::task::{Context, Poll, Waker};
    let host = Host::default();
    let fs = now_or_never(CloudFs::connect(host.clone(), "opener".into()))
        .unwrap()
        .unwrap();
    let mut cred = Cred::root();
    cred.token = Some("opener".into());
    let options = *OpenOptions::new().read(true).write(true);
    let opened = ready(fs.open(&cred, &root(), &options)).unwrap();
    host.pending.set(true);
    assert!(now_or_never(fs.open(&cred, &root(), &options)).is_none());
    *host.actor.borrow_mut() = ("child".into(), Some(42));
    let mut write = fs.write_at(&opened, b"data", WriteAt::End);
    assert!(matches!(
        write.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    *host.actor.borrow_mut() = ("another process".into(), Some(43));
    host.pending.set(false);
    assert_eq!(ready(write).unwrap().len, 4);
    assert_eq!(ready(fs.read_at(&opened, &mut [0], 0)), Ok(0));
    let sent = host.data.borrow();
    assert_eq!(
        (sent[0].credential.as_str(), sent[0].pid),
        ("child", Some(42))
    );
    assert_eq!(
        (sent[1].credential.as_str(), sent[1].pid),
        ("another process", Some(43))
    );
    assert_eq!(sent[0].open, sent[1].open);
}
#[test]
fn open_control_calls_authenticate_the_actor_separately_from_the_opener() {
    let host = Host::default();
    let fs = now_or_never(CloudFs::connect(host.clone(), "opener".into()))
        .unwrap()
        .unwrap();
    let mut cred = Cred::root();
    cred.token = Some("opener".into());
    let opened = ready(fs.open(&cred, &root(), OpenOptions::new().read(true).write(true))).unwrap();
    *host.denied.borrow_mut() = vec!["revoked".into(), "cloud denied".into()];
    host.granted.set(true);
    for token in ["revoked", "cloud denied", "allowed"] {
        *host.actor.borrow_mut() = (token.into(), Some(42));
        let expected = if token == "allowed" {
            Ok(())
        } else {
            Err(Errno::EACCES)
        };
        assert_eq!(ready(fs.set_len(&opened, 0)), expected);
        assert_eq!(ready(fs.sync_all(&opened)), expected);
        assert_eq!(ready(fs.sync_data(&opened)), expected);
        assert_eq!(
            ready(fs.try_lock(
                &opened,
                LockFamily::Posix,
                LockKind::Exclusive,
                LockRange::WHOLE
            )),
            expected
        );
        assert_eq!(
            ready(fs.lock(
                &opened,
                LockFamily::Posix,
                LockKind::Exclusive,
                LockRange::WHOLE
            )),
            expected
        );
        assert_eq!(
            ready(fs.unlock(&opened, LockFamily::Posix, LockRange::WHOLE)),
            expected
        );
        assert_eq!(
            ready(fs.test_lock(&opened, LockKind::Exclusive, LockRange::WHOLE)),
            expected.map(|()| None)
        );
    }
    // Cleanup remains possible after a calling task is gone; it cannot acquire a new grant.
    assert!(
        host.requests
            .borrow()
            .iter()
            .filter(|r| matches!(r.call, Call::CancelLock { .. }))
            .all(|r| r.credential == "opener")
    );
    let requests = host.requests.borrow();
    let acknowledged = requests
        .iter()
        .find(|r| matches!(r.call, Call::AckLock { .. }))
        .unwrap();
    assert_eq!(acknowledged.credential, "allowed");
}
#[test]
fn open_control_calls_snapshot_the_actor_before_draining_older_cleanup() {
    use std::task::{Context, Poll, Waker};
    for locking in [false, true] {
        let host = Host::default();
        let fs = now_or_never(CloudFs::connect(host.clone(), "opener".into()))
            .unwrap()
            .unwrap();
        let mut cred = Cred::root();
        cred.token = Some("opener".into());
        let options = *OpenOptions::new().read(true).write(true);
        let opened = ready(fs.open(&cred, &root(), &options)).unwrap();
        host.pending.set(true);
        assert!(now_or_never(fs.open(&cred, &root(), &options)).is_none());
        *host.actor.borrow_mut() = ("caller".into(), Some(42));
        let mut operation = if locking {
            fs.lock(
                &opened,
                LockFamily::Posix,
                LockKind::Exclusive,
                LockRange::WHOLE,
            )
        } else {
            fs.set_len(&opened, 0)
        };
        assert!(matches!(
            operation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ));
        *host.actor.borrow_mut() = ("different task".into(), Some(43));
        host.pending.set(false);
        host.granted.set(true);
        assert_eq!(ready(operation), Ok(()));
        for request in host.requests.borrow().iter().filter(|r| {
            matches!(
                r.call,
                Call::SetLen { .. } | Call::Lock { .. } | Call::AckLock { .. }
            )
        }) {
            assert_eq!(request.credential, "caller");
        }
    }
}
#[test]
fn failed_older_cleanup_cannot_lose_a_close_or_release_queue_entry() {
    for explicit_close in [false, true] {
        let host = Host::default();
        let fs = Rc::new(
            now_or_never(CloudFs::connect(host.clone(), "opener".into()))
                .unwrap()
                .unwrap(),
        );
        let mut cred = Cred::root();
        cred.token = Some("opener".into());
        let options = *OpenOptions::new().read(true).write(true);
        let opened = ready(fs.open(&cred, &root(), &options)).unwrap();
        let queue = ReleaseQueue::new();
        let file = FileRef::new(
            fs.clone(),
            opened.clone(),
            Handle {
                node: opened.node,
                ..root()
            },
            cred.clone(),
            &options,
            &queue,
        );
        host.pending.set(true);
        assert!(now_or_never(fs.open(&cred, &root(), &options)).is_none());
        host.pending.set(false);
        host.failure.set(Some(Errno::EIO));
        if explicit_close {
            assert_eq!(now_or_never(file.close()), Some(Err(Errno::EIO)));
        } else {
            drop(file);
            assert_eq!(now_or_never(queue.flush()), Some(Err(Errno::EIO)));
        }
        assert!(queue.is_empty());
        assert_eq!(fs.pending_cancellations(), 2);
        host.failure.set(None);
        assert_eq!(now_or_never(fs.drain()), Some(Ok(())));
        assert_eq!(fs.pending_cancellations(), 0);
        assert_eq!(
            host.calls
                .borrow()
                .iter()
                .filter(|c| matches!(c, Call::Release { .. }))
                .count(),
            1
        );
        assert_eq!(ready(fs.sync_all(&opened)), Err(Errno::EBADF));
    }
}
#[test]
fn exec_rotation_retries_deferred_cleanup_without_losing_unauthorized_work() {
    let host = Host::default();
    let fs = now_or_never(CloudFs::connect(host.clone(), "opener".into()))
        .unwrap()
        .unwrap();
    let mut cred = Cred::root();
    cred.token = Some("opener".into());
    let options = *OpenOptions::new().read(true).write(true);
    let opened = ready(fs.open(&cred, &root(), &options)).unwrap();
    host.pending.set(true);
    assert!(now_or_never(fs.open(&cred, &root(), &options)).is_none());
    host.pending.set(false);
    host.denied
        .borrow_mut()
        .extend(["opener".into(), "revoked actor".into()]);
    *host.actor.borrow_mut() = ("revoked actor".into(), Some(42));
    assert_eq!(ready(fs.release(&opened)), Err(Errno::EACCES));
    assert_eq!(fs.pending_cancellations(), 2);
    *host.actor.borrow_mut() = ("replacement".into(), Some(42));
    assert_eq!(now_or_never(fs.drain()), Some(Ok(())));
    assert_eq!(fs.pending_cancellations(), 0);
    for cleanup in ["cancel_open", "release"] {
        assert!(host.requests.borrow().iter().any(|r| {
            r.credential == "replacement"
                && serde_json::to_value(&r.call)
                    .unwrap()
                    .get(cleanup)
                    .is_some()
        }));
    }
    assert_eq!(ready(fs.sync_all(&opened)), Err(Errno::EBADF));
    // A direct close also retries when exec retired its original opening credential.
    cred.token = Some("replacement".into());
    let opened = ready(fs.open(&cred, &root(), &options)).unwrap();
    host.denied.borrow_mut().push("replacement".into());
    *host.actor.borrow_mut() = ("next exec".into(), Some(42));
    assert_eq!(ready(fs.release(&opened)), Ok(()));
    assert_eq!(fs.pending_cancellations(), 0);
}
#[test]
fn cancelling_a_release_while_draining_older_cleanup_keeps_both_obligations() {
    let host = Host::default();
    let fs = now_or_never(CloudFs::connect(host.clone(), "opener".into()))
        .unwrap()
        .unwrap();
    let mut cred = Cred::root();
    cred.token = Some("opener".into());
    let options = *OpenOptions::new().read(true).write(true);
    let opened = ready(fs.open(&cred, &root(), &options)).unwrap();
    host.pending.set(true);
    assert!(now_or_never(fs.open(&cred, &root(), &options)).is_none());
    assert!(now_or_never(fs.release(&opened)).is_none());
    assert_eq!(fs.pending_cancellations(), 2);
    host.pending.set(false);
    assert_eq!(now_or_never(fs.drain()), Some(Ok(())));
    assert_eq!(fs.pending_cancellations(), 0);
    assert_eq!(
        host.calls
            .borrow()
            .iter()
            .filter(|c| matches!(c, Call::Release { .. }))
            .count(),
        1
    );
}
fn held(owner: u64, start: u64, end: Option<u64>) -> Held {
    Held {
        owner,
        family: LockFamily::Posix,
        kind: LockKind::Exclusive,
        range: LockRange::new(start, end).unwrap(),
        ticket: None,
    }
}
#[test]
fn serialized_waits_wake_and_cancel_without_crossing_lock_families() {
    let mut locks = Locks::default();
    assert_eq!(locks.acquire(held(1, 0, None), None, &[]), Ok(true));
    assert_eq!(
        locks.acquire(held(2, 0, None), Some("wait"), &[]),
        Ok(false)
    );
    let mut restored: Locks = serde_json::from_value(json!(locks)).unwrap();
    restored.release(1);
    assert_eq!(
        restored.acquire(held(2, 0, None), Some("wait"), &[]),
        Ok(true)
    );
    restored.cancel(2, "wait");
    assert!(restored.held.is_empty());
    assert_eq!(
        restored.acquire(held(2, 0, None), Some("wait"), &[]),
        Err(Errno::ECANCELED)
    );
    restored.cancel(3, "before");
    assert_eq!(
        restored.acquire(held(3, 0, None), Some("before"), &[]),
        Err(Errno::ECANCELED)
    );
    let mut flock = held(4, 0, None);
    flock.family = LockFamily::Flock;
    restored.acquire(flock, None, &[]).unwrap();
    assert_eq!(restored.acquire(held(5, 0, None), None, &[]), Ok(true));
}
#[test]
fn posix_adjacent_ranges_merge_and_split_without_changing_kind_or_owner() {
    let mut locks = Locks::default();
    for n in (0..100).rev() {
        assert_eq!(
            locks.acquire(held(1, n * 10, Some((n + 1) * 10)), None, &[]),
            Ok(true)
        );
        assert_eq!(locks.held.len(), 1);
    }
    assert_eq!(
        locks.conflict(&held(2, 20, Some(21))).unwrap().range,
        LockRange::new(0, Some(1000)).unwrap()
    );
    locks.carve(1, LockFamily::Posix, LockRange::new(50, Some(60)).unwrap());
    let shared = Held {
        kind: LockKind::Shared,
        ..held(1, 0, Some(10))
    };
    locks.acquire(shared, None, &[]).unwrap();
    locks.acquire(held(1, 50, Some(60)), None, &[]).unwrap();
    assert_eq!(
        locks.conflict(&held(2, 20, Some(21))).unwrap().range,
        LockRange::new(10, Some(1000)).unwrap()
    );
    locks.acquire(held(1, 1000, None), None, &[]).unwrap();
    assert_eq!(
        locks.conflict(&held(2, 999, None)).unwrap().range,
        LockRange::from(10..)
    );
    locks.carve(1, LockFamily::Posix, LockRange::new(20, Some(30)).unwrap());
    assert!(locks.conflict(&held(2, 20, Some(30))).is_none());
    assert_eq!(
        locks.conflict(&held(2, 30, Some(31))).unwrap().range,
        LockRange::from(30..)
    );
}
#[test]
fn merged_lock_reports_preserve_each_tickets_surviving_ranges_after_serialization() {
    let mut locks = Locks::default();
    locks.acquire(held(1, 0, Some(10)), None, &[]).unwrap();
    locks
        .acquire(held(1, 20, Some(30)), Some("right"), &[])
        .unwrap();
    locks.acknowledge(1, "right");
    locks.acquire(held(2, 10, Some(20)), None, &[]).unwrap();
    assert_eq!(
        locks.acquire(held(1, 10, Some(20)), Some("middle"), &[]),
        Ok(false)
    );
    locks.release(2);
    assert_eq!(
        locks.conflict(&held(3, 25, Some(26))).unwrap().range,
        LockRange::new(0, Some(30)).unwrap()
    );
    locks.acknowledge(1, "middle");
    // A later request replaces only part of the cancelled request's contribution.
    locks.acquire(held(1, 15, Some(25)), None, &[]).unwrap();
    let mut restored: Locks = serde_json::from_value(json!(locks)).unwrap();
    restored.cancel(1, "middle");
    assert!(restored.conflict(&held(3, 10, Some(15))).is_none());
    assert_eq!(
        restored.conflict(&held(3, 15, Some(16))).unwrap().range,
        LockRange::new(15, Some(30)).unwrap()
    );
    restored.cancel(1, "right");
    assert!(restored.conflict(&held(3, 25, Some(30))).is_none());
    assert_eq!(
        restored.conflict(&held(3, 15, Some(16))).unwrap().range,
        LockRange::new(15, Some(25)).unwrap()
    );
    assert_eq!(
        restored.conflict(&held(3, 5, Some(6))).unwrap().range,
        LockRange::new(0, Some(10)).unwrap()
    );
}
#[test]
fn durable_posix_deadlock_detection_crosses_inodes_and_unlock_splits_ranges() {
    let mut a = Locks::default();
    let mut b = Locks::default();
    a.acquire(held(1, 0, None), None, &[]).unwrap();
    b.acquire(held(2, 0, None), None, &[]).unwrap();
    assert_eq!(
        a.acquire(held(2, 0, None), Some("two"), &[b.clone()]),
        Ok(false)
    );
    assert_eq!(
        b.acquire(held(1, 0, None), Some("one"), &[a.clone()]),
        Err(Errno::EDEADLK)
    );
    b.carve(2, LockFamily::Posix, LockRange::new(5, Some(10)).unwrap());
    assert_eq!(b.held.len(), 2);
    assert!(b.conflict(&held(3, 5, Some(10))).is_none());
    assert!(b.conflict(&held(3, 0, Some(1))).is_some());
}
#[test]
fn flock_conversion_wakes_waiters_even_when_the_conversion_would_block() {
    let mut locks = Locks::default();
    let mut a = held(1, 0, None);
    a.family = LockFamily::Flock;
    let b = Held {
        owner: 2,
        ..a.clone()
    };
    assert_eq!(locks.acquire(a.clone(), None, &[]), Ok(true));
    assert_eq!(locks.acquire(b.clone(), Some("wait"), &[]), Ok(false));
    // Reapplying the same flock keeps ownership; converting it releases ownership first.
    assert_eq!(locks.acquire(a.clone(), None, &[]), Ok(true));
    a.kind = LockKind::Shared;
    assert_eq!(locks.acquire(a, None, &[]), Err(Errno::EAGAIN));
    let mut restored: Locks = serde_json::from_value(json!(locks)).unwrap();
    assert_eq!(restored.acquire(b, Some("wait"), &[]), Ok(true));
    assert_eq!(restored.held.len(), 1);
    assert_eq!(restored.held[0].owner, 2);
}
#[test]
fn posix_owner_can_reapply_and_downgrade_without_bypassing_held_conflicts() {
    let mut locks = Locks::default();
    let mut a = held(1, 0, None);
    let b = held(2, 0, None);
    let c = Held {
        kind: LockKind::Shared,
        ..held(3, 0, None)
    };
    assert_eq!(locks.acquire(a.clone(), None, &[]), Ok(true));
    assert_eq!(locks.acquire(b.clone(), Some("writer"), &[]), Ok(false));
    assert_eq!(locks.acquire(a.clone(), None, &[]), Ok(true));
    a.kind = LockKind::Shared;
    assert_eq!(locks.acquire(a.clone(), Some("downgrade"), &[]), Ok(true));
    // New readers stay behind the writer, even though the held lock is now shared.
    assert_eq!(locks.acquire(c.clone(), Some("reader"), &[]), Ok(false));
    assert_eq!(locks.acquire(b.clone(), Some("writer"), &[]), Ok(false));
    locks.release(1);
    assert_eq!(locks.acquire(b, Some("writer"), &[]), Ok(true));
    assert_eq!(locks.acquire(c.clone(), Some("reader"), &[]), Ok(false));
    locks.release(2);
    assert_eq!(locks.acquire(c, Some("reader"), &[]), Ok(true));
    assert_eq!(locks.acquire(a.clone(), None, &[]), Ok(true));
    a.kind = LockKind::Exclusive;
    assert_eq!(locks.acquire(a, None, &[]), Err(Errno::EAGAIN));
}
#[test]
fn posix_downgrade_wakes_shared_waiters() {
    let mut locks = Locks::default();
    let mut a = held(1, 0, None);
    let b = Held {
        kind: LockKind::Shared,
        ..held(2, 0, None)
    };
    assert_eq!(locks.acquire(a.clone(), None, &[]), Ok(true));
    assert_eq!(locks.acquire(b.clone(), Some("reader"), &[]), Ok(false));
    a.kind = LockKind::Shared;
    assert_eq!(locks.acquire(a, None, &[]), Ok(true));
    assert_eq!(locks.acquire(b, Some("reader"), &[]), Ok(true));
}
#[test]
fn acknowledged_locks_do_not_accumulate_wait_records() {
    let mut state = Locks::default();
    for n in 0..5000 {
        let ticket = n.to_string();
        assert_eq!(
            state.acquire(held(1, 0, None), Some(&ticket), &[]),
            Ok(true)
        );
        state.acknowledge(1, &ticket);
        assert!(state.waits.is_empty());
        state.carve(1, LockFamily::Posix, LockRange::WHOLE);
    }
}
#[test]
fn dropping_a_pending_remote_lock_queues_cancellation() {
    let host = Host::default();
    let fs = now_or_never(CloudFs::connect(host.clone(), "credential".into()))
        .unwrap()
        .unwrap();
    let mut cred = Cred::root();
    cred.token = Some("credential".into());
    let open = ready(fs.open(&cred, &root(), OpenOptions::new().read(true).write(true))).unwrap();
    assert!(
        now_or_never(fs.lock(
            &open,
            LockFamily::Posix,
            LockKind::Exclusive,
            LockRange::WHOLE
        ))
        .is_none()
    );
    assert_eq!(fs.pending_cancellations(), 1);
    assert_eq!(now_or_never(fs.drain()), Some(Ok(())));
    assert!(matches!(host.calls.borrow().last(),Some(Call::CancelLock{ticket,..}) if ticket=="2"));
}

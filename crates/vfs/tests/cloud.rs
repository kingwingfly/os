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
            std::future::poll_fn(|_| {
                if self.pending.get() {
                    std::task::Poll::Pending
                } else {
                    std::task::Poll::Ready(())
                }
            })
            .await;
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
                Call::Lock { .. } => json!(false),
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

use abi::Errno;
use abi::contract::{Boundary, Hello};
use abi::fs::{
    Access, Conflict, Entry, FileType, FsId, Handle, LockFamily, LockKind, LockRange, Metadata,
    NodeId, OpenOptions, OpenRef, StatFs, WriteAt, Written,
};
use abi::local_helper::{
    AttachReply, CONTROL_MAX, Call, DATA_MAX, HelloReply, HelperGrant, LockOutcome, ReadReply,
    RenewReply, Request, VERSION,
};
use os_vfs::{
    BoxFuture, Cred, Filesystem, Identity,
    helperfs::{HelperFs, HelperHttpHost, HelperTransport, HttpHelperTransport, HttpReply},
    now_or_never, profiles,
};
use serde_json::{Value, json};
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;

fn fake_root() -> Handle {
    Handle {
        fs: FsId("helperfs:11111111-2222-4333-8444-555555555555".into()),
        node: NodeId {
            ino: 1,
            generation: 1,
        },
        proof: "root-proof".into(),
    }
}

fn fake_entry(ino: u64) -> Entry {
    Entry {
        handle: Handle {
            fs: fake_root().fs,
            node: NodeId { ino, generation: 1 },
            proof: format!("proof-{ino}"),
        },
        metadata: Metadata {
            file_type: FileType::File,
            mode: 0o644,
            nlink: 1,
            uid: 1000,
            gid: 1000,
            size: 0,
            atime: (1, 0).into(),
            mtime: (1, 0).into(),
            ctime: (1, 0).into(),
            rdev: None,
            acl: false,
        },
    }
}

fn fake_open(ino: u64, id: u64) -> OpenRef {
    OpenRef {
        fs: fake_root().fs,
        id,
        node: NodeId { ino, generation: 1 },
        access: Access::ReadWrite,
    }
}

#[derive(Clone, Default)]
struct MockTransport {
    requests: Rc<RefCell<Vec<Request>>>,
    replies: Rc<RefCell<VecDeque<Result<Value, Errno>>>>,
    disconnected: Rc<Cell<Option<Errno>>>,
    next_ticket: Rc<Cell<u64>>,
    paused: Rc<Cell<u64>>,
}

impl MockTransport {
    fn push_ok(&self, v: impl serde::Serialize) {
        self.replies
            .borrow_mut()
            .push_back(Ok(serde_json::to_value(v).unwrap()));
    }

    fn push_err(&self, e: Errno) {
        self.replies.borrow_mut().push_back(Err(e));
    }

    fn push_connect(&self, grant: HelperGrant) {
        self.push_ok(HelloReply {
            boundary: Boundary::LocalHelper,
            version: VERSION,
            write: grant.write,
            execute: grant.execute,
            handshake: "hs-1".into(),
        });
        self.push_ok(AttachReply {
            version: VERSION,
            session: "sess-1".into(),
            fs: fake_root().fs,
            root: fake_root(),
            capabilities: profiles::HELPER,
            grant,
            lease_seconds: 60,
        });
    }
}

impl HelperTransport for MockTransport {
    fn request(&self, request: Request) -> BoxFuture<'_, Value> {
        Box::pin(async move {
            self.requests.borrow_mut().push(request);
            if let Some(err) = self.disconnected.get() {
                return Err(err);
            }
            self.replies
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| Ok(json!({})))
        })
    }

    fn pause(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.paused.set(self.paused.get() + 1);
            std::future::pending::<os_vfs::Result<()>>().await
        })
    }

    fn ticket(&self) -> String {
        let id = self.next_ticket.get() + 1;
        self.next_ticket.set(id);
        format!("ticket-{id}")
    }
}

fn cred() -> Cred {
    Cred {
        identity: Identity {
            id: 1000,
            group: 1000,
            groups: [1000, 2000].into(),
        },
        umask: 0o027,
        token: None,
    }
}

#[test]
fn connect_hello_negotiation_and_protocol_mismatch() {
    let t = MockTransport::default();
    t.push_connect(HelperGrant {
        write: true,
        execute: false,
    });
    let fs = now_or_never(HelperFs::connect(
        t.clone(),
        "tab-1",
        &cred(),
        HelperGrant {
            write: true,
            execute: true,
        },
    ))
    .unwrap()
    .unwrap();

    assert_eq!(fs.id(), &fake_root().fs);
    assert_eq!(fs.capabilities(), profiles::HELPER);
    assert_eq!(fs.root(), fake_root());
    assert_eq!(
        fs.grant(),
        HelperGrant {
            write: true,
            execute: false
        }
    );

    let reqs = t.requests.borrow();
    assert_eq!(
        reqs[0],
        Request::Hello(Hello {
            boundary: Boundary::LocalHelper,
            versions: vec![VERSION],
        })
    );
    assert!(matches!(
        &reqs[1],
        Request::Attach {
            version: VERSION,
            client_id,
            ..
        } if client_id == "tab-1"
    ));

    // Legacy or wrong boundary reply fails with EPROTONOSUPPORT.
    let bad = MockTransport::default();
    bad.push_ok(HelloReply {
        boundary: Boundary::RemoteFilesystem,
        version: VERSION,
        write: true,
        execute: true,
        handshake: "hs-bad".into(),
    });
    let err = now_or_never(HelperFs::connect(
        bad,
        "tab-bad",
        &cred(),
        HelperGrant::default(),
    ))
    .unwrap()
    .err()
    .unwrap();
    assert_eq!(err, Errno::EPROTONOSUPPORT);
}

#[test]
fn cred_and_umask_forwarded_and_cross_fs_rejected() {
    let t = MockTransport::default();
    t.push_connect(HelperGrant {
        write: true,
        execute: true,
    });
    let fs = now_or_never(HelperFs::connect(
        t.clone(),
        "tab-1",
        &cred(),
        HelperGrant {
            write: true,
            execute: true,
        },
    ))
    .unwrap()
    .unwrap();

    let open = fake_open(2, 9);
    t.push_ok((fake_entry(2), open.clone()));
    let (_entry, got_open) = now_or_never(fs.create(
        &cred(),
        &fs.root(),
        "script.sh",
        0o755,
        OpenOptions::new().write(true).create(true).create_new(true),
    ))
    .unwrap()
    .unwrap();
    assert_eq!(got_open, open);

    let last = t.requests.borrow().last().unwrap().clone();
    match last {
        Request::Call { cred: wcred, .. } => {
            assert_eq!(wcred.id, 1000);
            assert_eq!(wcred.group, 1000);
            assert!(wcred.groups.contains(&2000));
            assert_eq!(wcred.umask, 0o027);
        }
        other => panic!("expected Call, got {other:?}"),
    }

    // Wrong FsId handle rejected locally without sending RPC.
    let foreign = Handle {
        fs: FsId("helperfs:other".into()),
        node: NodeId {
            ino: 1,
            generation: 1,
        },
        proof: "x".into(),
    };
    let reqs_before = t.requests.borrow().len();
    assert_eq!(
        now_or_never(fs.lookup(&cred(), &foreign, "a"))
            .unwrap()
            .unwrap_err(),
        Errno::EACCES
    );
    assert_eq!(t.requests.borrow().len(), reqs_before);
}

#[test]
fn large_read_and_write_chunked_at_data_max() {
    let t = MockTransport::default();
    t.push_connect(HelperGrant {
        write: true,
        execute: true,
    });
    let fs = now_or_never(HelperFs::connect(
        t.clone(),
        "tab-1",
        &cred(),
        HelperGrant {
            write: true,
            execute: true,
        },
    ))
    .unwrap()
    .unwrap();

    let open = fake_open(2, 11);
    t.push_ok(open.clone());
    now_or_never(fs.open(
        &cred(),
        &fake_entry(2).handle,
        OpenOptions::new().read(true).write(true),
    ))
    .unwrap()
    .unwrap();

    let big_write = vec![b'A'; DATA_MAX as usize + 512];
    t.push_ok(Written {
        offset: 0,
        len: DATA_MAX as usize,
    });
    let written = now_or_never(fs.write_at(&open, &big_write, WriteAt::Offset(0)))
        .unwrap()
        .unwrap();
    assert_eq!(written.len, DATA_MAX as usize);
    match t.requests.borrow().last().unwrap() {
        Request::Call {
            call: Call::WriteAt { data, .. },
            ..
        } => assert_eq!(data.0.len(), DATA_MAX as usize),
        other => panic!("unexpected req: {other:?}"),
    }

    let mut big_read = vec![0u8; DATA_MAX as usize + 512];
    t.push_ok(ReadReply {
        data: abi::Bytes(vec![b'Z'; DATA_MAX as usize]),
    });
    let read_n = now_or_never(fs.read_at(&open, &mut big_read, 0))
        .unwrap()
        .unwrap();
    assert_eq!(read_n, DATA_MAX as usize);
    assert!(big_read[..read_n].iter().all(|&b| b == b'Z'));
    match t.requests.borrow().last().unwrap() {
        Request::Call {
            call: Call::ReadAt { count, .. },
            ..
        } => assert_eq!(*count, DATA_MAX),
        other => panic!("unexpected req: {other:?}"),
    }

    // Offset past FILE_MAX fails locally with EINVAL.
    let mut small = [0u8; 4];
    assert_eq!(
        now_or_never(fs.read_at(&open, &mut small, os_vfs::FILE_MAX))
            .unwrap()
            .unwrap_err(),
        Errno::EINVAL
    );
}

#[test]
fn lock_drop_cancels_deferred_ticket_and_unreachable_maps_to_enolck() {
    let t = MockTransport::default();
    t.push_connect(HelperGrant {
        write: true,
        execute: true,
    });
    let fs = now_or_never(HelperFs::connect(
        t.clone(),
        "tab-1",
        &cred(),
        HelperGrant {
            write: true,
            execute: true,
        },
    ))
    .unwrap()
    .unwrap();

    let open = fake_open(2, 22);
    t.push_ok(open.clone());
    now_or_never(fs.open(
        &cred(),
        &fake_entry(2).handle,
        OpenOptions::new().read(true).write(true),
    ))
    .unwrap()
    .unwrap();

    // Lock returns Pending then future is dropped -> CancelLock must drain before next call!
    t.push_ok(LockOutcome::Pending);
    let range = LockRange::new(0, Some(8)).unwrap();
    assert!(now_or_never(fs.lock(&open, LockFamily::Posix, LockKind::Exclusive, range)).is_none());
    assert_eq!(t.paused.get(), 1);

    t.push_ok(json!({})); // CancelLock ack
    t.push_ok(StatFs::default());
    let _st = now_or_never(fs.statfs(&cred())).unwrap().unwrap();
    let reqs = t.requests.borrow();
    assert!(matches!(
        &reqs[reqs.len() - 2],
        Request::Call {
            call: Call::CancelLock { ticket, .. },
            ..
        } if ticket == "ticket-2"
    ));
    drop(reqs);

    // Deterministic first-poll refusal (EACCES) does NOT queue a spurious CancelLock!
    t.push_err(Errno::EACCES);
    assert_eq!(
        now_or_never(fs.lock(&open, LockFamily::Posix, LockKind::Exclusive, range))
            .unwrap()
            .unwrap_err(),
        Errno::EACCES
    );
    t.push_ok(StatFs::default());
    let reqs_before = t.requests.borrow().len();
    now_or_never(fs.statfs(&cred())).unwrap().unwrap();
    assert_eq!(t.requests.borrow().len(), reqs_before + 1);

    // Confirmed TryLock contention returns EAGAIN (never masked as ENOLCK!), while 503 overload
    // (EBUSY) and unreachable helper calls still map to ENOLCK!
    for family in [LockFamily::Flock, LockFamily::Posix] {
        t.push_err(Errno::EAGAIN);
        assert_eq!(
            now_or_never(fs.try_lock(&open, family, LockKind::Exclusive, LockRange::WHOLE))
                .unwrap()
                .unwrap_err(),
            Errno::EAGAIN
        );
        t.push_err(Errno::EBUSY);
        assert_eq!(
            now_or_never(fs.try_lock(&open, family, LockKind::Exclusive, LockRange::WHOLE))
                .unwrap()
                .unwrap_err(),
            Errno::ENOLCK
        );
    }

    // Unreachable helper during lock operations -> ENOLCK; non-lock -> ENODEV!
    t.disconnected.set(Some(Errno::ENODEV));
    assert_eq!(
        now_or_never(fs.try_lock(
            &open,
            LockFamily::Flock,
            LockKind::Exclusive,
            LockRange::WHOLE
        ))
        .unwrap()
        .unwrap_err(),
        Errno::ENOLCK
    );
    assert_eq!(
        now_or_never(fs.lock(
            &open,
            LockFamily::Flock,
            LockKind::Exclusive,
            LockRange::WHOLE
        ))
        .unwrap()
        .unwrap_err(),
        Errno::ENOLCK
    );
    assert_eq!(
        now_or_never(fs.unlock(&open, LockFamily::Flock, LockRange::WHOLE))
            .unwrap()
            .unwrap_err(),
        Errno::ENOLCK
    );
    assert_eq!(
        now_or_never(fs.test_lock(&open, LockKind::Exclusive, LockRange::WHOLE))
            .unwrap()
            .unwrap_err(),
        Errno::ENOLCK
    );
    assert_eq!(
        now_or_never(fs.lookup(&cred(), &fs.root(), "a"))
            .unwrap()
            .unwrap_err(),
        Errno::ENODEV
    );
    assert_eq!(
        now_or_never(fs.sync_all(&open)).unwrap().unwrap_err(),
        Errno::ENODEV
    );

    // Reconnect / reachable again -> renew & detach work cleanly.
    t.disconnected.set(None);
    t.push_ok(RenewReply { lease_seconds: 60 });
    assert_eq!(now_or_never(fs.renew()).unwrap().unwrap().lease_seconds, 60);
    t.push_ok(json!({}));
    now_or_never(fs.detach()).unwrap().unwrap();
}

#[test]
fn http_helper_transport_parses_refusals_and_enforces_control_max() {
    struct MockHttpHost {
        reply: RefCell<Result<HttpReply, Errno>>,
    }
    impl HelperHttpHost for MockHttpHost {
        fn post<'a>(&'a self, _body: Vec<u8>) -> BoxFuture<'a, HttpReply> {
            Box::pin(async move { self.reply.borrow().clone() })
        }
        fn sleep(&self, _millis: u32) -> BoxFuture<'_, ()> {
            Box::pin(async move { Ok(()) })
        }
        fn ticket(&self) -> String {
            "t".into()
        }
    }

    let host = HttpHelperTransport(MockHttpHost {
        reply: RefCell::new(Ok(HttpReply {
            status: 400,
            body: br#"{"errno":"EPROTONOSUPPORT","error":"old protocol"}"#.to_vec(),
        })),
    });
    let err = now_or_never(host.request(Request::Renew {
        version: 1,
        session: "s".into(),
    }))
    .unwrap()
    .unwrap_err();
    assert_eq!(err, Errno::EPROTONOSUPPORT);

    // Network loss preserves ENOTCONN/ETIMEDOUT uncertainty so HelperFs distinguishes transport
    // uncertainty from confirmed server disconnects (ENODEV). HTTP 503 overload maps to EBUSY.
    *host.host().reply.borrow_mut() = Ok(HttpReply {
        status: 503,
        body: br#"{"errno":"EAGAIN","error":"helper busy"}"#.to_vec(),
    });
    assert_eq!(
        now_or_never(host.request(Request::Renew {
            version: 1,
            session: "s".into(),
        }))
        .unwrap()
        .unwrap_err(),
        Errno::EBUSY
    );

    *host.host().reply.borrow_mut() = Err(Errno::ENOTCONN);
    let err2 = now_or_never(host.request(Request::Renew {
        version: 1,
        session: "s".into(),
    }))
    .unwrap()
    .unwrap_err();
    assert_eq!(err2, Errno::ENOTCONN);

    *host.host().reply.borrow_mut() = Err(Errno::ETIMEDOUT);
    let err_timeout = now_or_never(host.request(Request::Renew {
        version: 1,
        session: "s".into(),
    }))
    .unwrap()
    .unwrap_err();
    assert_eq!(err_timeout, Errno::ETIMEDOUT);

    // Oversized body fails locally with E2BIG before posting.
    let huge = "x".repeat(CONTROL_MAX + 1);
    let err3 = now_or_never(host.request(Request::Renew {
        version: 1,
        session: huge,
    }))
    .unwrap()
    .unwrap_err();
    assert_eq!(err3, Errno::E2BIG);

    assert_eq!(serde_json::to_string(&Call::Statfs).unwrap(), r#""statfs""#);
    assert_eq!(
        serde_json::to_string(&os_vfs::RenameFlags::empty()).unwrap(),
        r#""""#
    );

    let _ = None::<Conflict>;
}

#[test]
fn uncertain_open_mutations_return_eio_and_abandoned_open_create_queues_cancel_open() {
    let t = MockTransport::default();
    t.push_connect(HelperGrant {
        write: true,
        execute: true,
    });
    let fs = now_or_never(HelperFs::connect(
        t.clone(),
        "tab-1",
        &cred(),
        HelperGrant {
            write: true,
            execute: true,
        },
    ))
    .unwrap()
    .unwrap();

    // Deterministic refusal on open queues NO CancelOpen.
    t.push_err(Errno::EACCES);
    assert_eq!(
        now_or_never(fs.open(
            &cred(),
            &fake_entry(2).handle,
            OpenOptions::new().read(true)
        ))
        .unwrap()
        .unwrap_err(),
        Errno::EACCES
    );
    assert_eq!(fs.pending_cancellations(), 0);

    // Uncertain ENOTCONN on create & ETIMEDOUT on open fail with ENOTCONN while keeping CancelOpen queued.
    t.push_err(Errno::ENOTCONN);
    assert_eq!(
        now_or_never(fs.create(
            &cred(),
            &fake_root(),
            "new.txt",
            0o644,
            OpenOptions::new().write(true).create(true),
        ))
        .unwrap()
        .unwrap_err(),
        Errno::ENOTCONN
    );
    assert_eq!(fs.pending_cancellations(), 1);

    t.push_ok(json!({})); // drain CancelOpen ticket-2 at start of fs.open
    t.push_err(Errno::ETIMEDOUT);
    assert_eq!(
        now_or_never(fs.open(
            &cred(),
            &fake_entry(2).handle,
            OpenOptions::new().read(true)
        ))
        .unwrap()
        .unwrap_err(),
        Errno::ENOTCONN
    );
    assert_eq!(fs.pending_cancellations(), 1);

    t.push_ok(json!({})); // CancelOpen ticket-3
    t.push_ok(StatFs::default());
    now_or_never(fs.statfs(&cred())).unwrap().unwrap();
    assert_eq!(fs.pending_cancellations(), 0);
    let reqs = t.requests.borrow();
    assert!(matches!(
        &reqs[reqs.len() - 4],
        Request::Call {
            call: Call::CancelOpen { ticket },
            ..
        } if ticket == "ticket-2"
    ));
    assert!(matches!(
        &reqs[reqs.len() - 2],
        Request::Call {
            call: Call::CancelOpen { ticket },
            ..
        } if ticket == "ticket-3"
    ));
    drop(reqs);

    // Open a file, then hit ENOTCONN/ETIMEDOUT on mutating calls -> EIO (uncertain commit!),
    // while non-mutating calls -> ENOTCONN (provider unreachable).
    let open = fake_open(2, 22);
    t.push_ok(open.clone());
    now_or_never(fs.open(
        &cred(),
        &fake_entry(2).handle,
        OpenOptions::new().read(true).write(true),
    ))
    .unwrap()
    .unwrap();

    for transient in [Errno::ENOTCONN, Errno::ETIMEDOUT] {
        t.disconnected.set(Some(transient));
        assert_eq!(
            now_or_never(fs.write_at(&open, b"abc", os_vfs::WriteAt::Offset(0)))
                .unwrap()
                .unwrap_err(),
            Errno::EIO
        );
        assert_eq!(
            now_or_never(fs.set_len(&open, 1)).unwrap().unwrap_err(),
            Errno::EIO
        );
        assert_eq!(
            now_or_never(fs.sync_all(&open)).unwrap().unwrap_err(),
            Errno::EIO
        );
        assert_eq!(
            now_or_never(fs.sync_data(&open)).unwrap().unwrap_err(),
            Errno::EIO
        );
        assert_eq!(
            now_or_never(fs.setattr(
                &cred(),
                &fake_entry(2).handle,
                &os_vfs::SetAttr {
                    mode: Some(0o640),
                    ..Default::default()
                },
            ))
            .unwrap()
            .unwrap_err(),
            Errno::EIO
        );
        assert_eq!(
            now_or_never(fs.rename(
                &cred(),
                &fs.root(),
                "a",
                &fs.root(),
                "b",
                os_vfs::RenameFlags::empty(),
            ))
            .unwrap()
            .unwrap_err(),
            Errno::EIO
        );
        assert_eq!(
            now_or_never(fs.lookup(&cred(), &fs.root(), "a"))
                .unwrap()
                .unwrap_err(),
            Errno::ENOTCONN
        );
    }
    t.disconnected.set(None);
}

#[test]
fn enotconn_and_eagain_keep_pending_cleanup_queued_and_renew_drains_cleanup() {
    let t = MockTransport::default();
    t.push_connect(HelperGrant {
        write: true,
        execute: true,
    });
    let fs = now_or_never(HelperFs::connect(
        t.clone(),
        "tab-1",
        &cred(),
        HelperGrant {
            write: true,
            execute: true,
        },
    ))
    .unwrap()
    .unwrap();

    let open = fake_open(2, 22);
    t.push_ok(open.clone());
    now_or_never(fs.open(
        &cred(),
        &fake_entry(2).handle,
        OpenOptions::new().read(true).write(true),
    ))
    .unwrap()
    .unwrap();

    // First lock call returns uncertain ENOTCONN: CancelLock must stay queued for cancellation.
    t.push_err(Errno::ENOTCONN);
    assert_eq!(
        now_or_never(fs.lock(
            &open,
            LockFamily::Flock,
            LockKind::Exclusive,
            LockRange::WHOLE
        ))
        .unwrap()
        .unwrap_err(),
        Errno::ENOLCK
    );
    assert_eq!(fs.pending_cancellations(), 1);

    // Release while disconnected hits ENOTCONN when trying to drain CancelLock -> keeps BOTH queued!
    t.disconnected.set(Some(Errno::ENOTCONN));
    assert_eq!(
        now_or_never(fs.release(&open)).unwrap(),
        Err(Errno::ENOTCONN)
    );
    assert_eq!(fs.pending_cancellations(), 2);
    // Overload (503 / EAGAIN) while retrying WaitDrained MUST also preserve BOTH pending cleanups!
    t.disconnected.set(Some(Errno::EAGAIN));
    assert_eq!(
        now_or_never(fs.release(&open)).unwrap(),
        Err(Errno::ENOTCONN)
    );
    assert_eq!(fs.pending_cancellations(), 2);

    // Recover transport: renew() renews lease and drains CancelLock + Release!
    t.disconnected.set(None);
    t.push_ok(RenewReply { lease_seconds: 60 });
    t.push_ok(json!({})); // CancelLock ack
    t.push_ok(json!({})); // Release ack
    assert_eq!(now_or_never(fs.renew()).unwrap().unwrap().lease_seconds, 60);
    assert_eq!(fs.pending_cancellations(), 0);
    // Once drained, a subsequent release recognizes it was already closed (or drains cleanly once).
    assert_eq!(now_or_never(fs.release(&open)).unwrap(), Ok(()));
    assert_eq!(now_or_never(fs.release(&open)).unwrap(), Err(Errno::EBADF));

    let reqs = t.requests.borrow();
    assert!(matches!(&reqs[reqs.len() - 3], Request::Renew { .. }));
    assert!(matches!(
        &reqs[reqs.len() - 2],
        Request::Call {
            call: Call::CancelLock { .. },
            ..
        }
    ));
    assert!(matches!(
        &reqs[reqs.len() - 1],
        Request::Call {
            call: Call::Release { .. },
            ..
        }
    ));
}

//! The cloud driver's HTTP transport: envelopes, limits, errno replies, and no replays.
use abi::Errno;
use abi::remote_fs::{self as wire, Call, DataOperation, DataRequest, Session};
use os_vfs::cloud::Transport;
use os_vfs::cloud_http::{CONTROL_MAX, DATA_HEADER, Host, HttpTransport, Reply};
use os_vfs::{Access, BoxFuture, FsId, NodeId, OpenRef, Result, WriteAt, now_or_never};
use std::cell::RefCell;
use std::collections::VecDeque;

#[derive(Default)]
struct Fake {
    sent: RefCell<Vec<(String, Vec<(&'static str, String)>, Vec<u8>)>>,
    replies: RefCell<VecDeque<Result<Reply>>>,
}
impl Host for Fake {
    fn post<'a>(
        &'a self,
        path: &'a str,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
    ) -> BoxFuture<'a, Reply> {
        self.sent.borrow_mut().push((path.into(), headers, body));
        let reply = self.replies.borrow_mut().pop_front().expect("a reply");
        Box::pin(async move { reply })
    }
    fn sleep(&self, _millis: u32) -> BoxFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
    fn ticket(&self) -> String {
        "ticket".into()
    }
    fn caller(&self) -> Result<(String, Option<u32>)> {
        Ok(("token".into(), Some(7)))
    }
}
fn reply(status: u16, body: &str) -> Result<Reply> {
    Ok(Reply {
        status,
        body: body.as_bytes().to_vec(),
    })
}
fn request(call: Call) -> wire::Request {
    wire::Request {
        version: wire::VERSION,
        credential: "token".into(),
        session: None,
        call,
    }
}
fn data(operation: DataOperation) -> DataRequest {
    DataRequest {
        version: wire::VERSION,
        credential: "token".into(),
        pid: Some(7),
        session: Session {
            id: "s".into(),
            secret: "secret".into(),
        },
        open: OpenRef {
            fs: FsId("cloud".into()),
            id: 3,
            node: NodeId {
                ino: 4,
                generation: 1,
            },
            access: Access::ReadWrite,
        },
        operation,
    }
}
fn ready<T>(future: BoxFuture<'_, T>) -> Result<T> {
    now_or_never(future).expect("the fake answers at once")
}

#[test]
fn control_calls_post_the_envelope_and_translate_errno_replies() {
    let transport = HttpTransport(Fake::default());
    transport.0.replies.borrow_mut().extend([
        reply(200, "7"),
        reply(412, r#"{"error":"Stale file handle","errno":"ESTALE"}"#),
        reply(400, r#"{"errno":"ENOLCK"}"#),
        reply(502, "<html>bad gateway</html>"),
        Err(Errno::ENOTCONN),
    ]);
    assert_eq!(ready(transport.request(request(Call::Renew))).unwrap(), 7);
    for errno in [Errno::ESTALE, Errno::ENOLCK, Errno::EIO, Errno::EIO] {
        assert_eq!(
            ready(transport.request(request(Call::Statfs))).unwrap_err(),
            errno
        );
    }
    let sent = transport.0.sent.borrow();
    assert_eq!(sent[0].0, "/api/fs");
    let body: serde_json::Value = serde_json::from_slice(&sent[0].2).unwrap();
    assert_eq!(body["call"], "renew");
    assert_eq!(body["version"], wire::VERSION);
}

#[test]
fn oversized_control_bodies_never_leave_the_host() {
    let transport = HttpTransport(Fake::default());
    let call = Call::Setxattr {
        handle: os_vfs::Handle {
            fs: FsId("cloud".into()),
            node: NodeId {
                ino: 1,
                generation: 1,
            },
            proof: String::new(),
        },
        name: "user.big".into(),
        value: vec![0; CONTROL_MAX],
        flags: Default::default(),
    };
    assert_eq!(
        ready(transport.request(request(call))).unwrap_err(),
        Errno::E2BIG
    );
    assert!(transport.0.sent.borrow().is_empty());
}

#[test]
fn data_calls_carry_the_header_and_raw_bytes_and_lost_writes_are_not_replayed() {
    let transport = HttpTransport(Fake::default());
    transport.0.replies.borrow_mut().extend([
        reply(200, "abc"),
        reply(200, r#"{"offset":9,"len":2}"#),
        Err(Errno::EIO),
        reply(403, r#"{"errno":"EACCES"}"#),
    ]);
    let read = ready(transport.read(data(DataOperation::Read {
        offset: 0,
        length: 3,
    })))
    .unwrap();
    assert_eq!(read, b"abc");
    let write = data(DataOperation::Write {
        at: WriteAt::End,
        length: 2,
    });
    let written = ready(transport.write(write.clone(), b"xy")).unwrap();
    assert_eq!((written.offset, written.len), (9, 2));
    // The reply was lost: uncertain, reported once as EIO, and the write is not sent again.
    assert_eq!(
        ready(transport.write(write.clone(), b"xy")).unwrap_err(),
        Errno::EIO
    );
    assert_eq!(transport.0.sent.borrow().len(), 3);
    assert_eq!(
        ready(transport.read(data(DataOperation::Read {
            offset: 0,
            length: 1
        })))
        .unwrap_err(),
        Errno::EACCES
    );
    let sent = transport.0.sent.borrow();
    assert_eq!(sent[1].0, "/api/fs/data");
    assert_eq!(sent[1].1[0].0, DATA_HEADER);
    let header: serde_json::Value = serde_json::from_str(&sent[1].1[0].1).unwrap();
    assert_eq!((header["pid"].as_u64(), header["open"]["id"].as_u64()), (Some(7), Some(3)));
    assert_eq!(sent[1].2, b"xy");
    assert!(sent[0].2.is_empty());
}

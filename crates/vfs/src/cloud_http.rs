//! The cloud driver's HTTP transport (docs/architecture/cloudfs.md): `POST /api/fs` with a JSON
//! control envelope, and `POST /api/fs/data` with the `DataRequest` in `X-OS-Filesystem` and raw
//! bytes in the body. Portable: the host supplies one HTTP POST, a timer, fresh tickets and the
//! current kernel task, and nothing else. The host's POST is same-origin, so the browser adds the
//! `Origin` header the service requires; a native host adds it itself.
//!
//! - Control bodies above [`CONTROL_MAX`] fail here with `E2BIG`, before anything is sent.
//! - Data calls are at most [`wire::DATA_MAX`] bytes; [`CloudFs`](crate::cloud::CloudFs) makes the
//!   short read or write at that boundary.
//! - Nothing is retried. A request that got no reply fails with `EIO`, so the driver keeps its
//!   cleanup obligations (an `ENOTCONN` would be taken as the session being gone). A write whose
//!   reply was lost is an uncertain write: it fails with `EIO` and is never sent again.
use crate::cloud::Transport;
use crate::{BoxFuture, Result, Written};
use abi::Errno;
use abi::remote_fs::{self as wire, DataRequest};
use serde_json::Value;

/// The largest control body the service accepts.
pub const CONTROL_MAX: usize = 4 * 1024 * 1024;
/// How long a queued lock wait sleeps between polls of its durable wait record.
pub const LOCK_POLL_MILLIS: u32 = 200;
/// How often a host renews its session: at least every minute (the lease is
/// [`wire::LEASE_SECONDS`]), including while calls are pending.
pub const RENEW_MILLIS: u32 = 30_000;

pub const CONTROL_PATH: &str = "/api/fs";
pub const DATA_PATH: &str = "/api/fs/data";
pub const DATA_HEADER: &str = "X-OS-Filesystem";

/// An HTTP reply: its status and body.
pub struct Reply {
    pub status: u16,
    pub body: Vec<u8>,
}

/// What a host provides the transport.
pub trait Host {
    /// POST `body` to `path` on the service's origin with `headers` (plus `Content-Type`).
    /// `Err` only when no reply arrived; any HTTP status is a reply.
    fn post<'a>(
        &'a self,
        path: &'a str,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
    ) -> BoxFuture<'a, Reply>;
    fn sleep(&self, millis: u32) -> BoxFuture<'_, ()>;
    /// A value unique across reconnects and reloads (a random UUID).
    fn ticket(&self) -> String;
    /// The current kernel task's remote credential and PID, read now, before any await.
    fn caller(&self) -> Result<(String, Option<u32>)>;
}

/// [`Transport`] over a [`Host`]'s HTTP.
pub struct HttpTransport<H>(pub H);

/// The errno an error reply names; `EIO` for a reply that names none.
fn refusal(reply: &Reply) -> Errno {
    serde_json::from_slice::<Value>(&reply.body)
        .ok()
        .and_then(|body| serde_json::from_value(body["errno"].clone()).ok())
        .unwrap_or(Errno::EIO)
}

fn json(reply: Reply) -> Result<Value> {
    if reply.status != 200 {
        return Err(refusal(&reply));
    }
    serde_json::from_slice(&reply.body).map_err(|_| Errno::EIO)
}

impl<H: Host> HttpTransport<H> {
    pub fn host(&self) -> &H {
        &self.0
    }
    fn data<'a>(&'a self, request: &DataRequest, body: Vec<u8>) -> Result<BoxFuture<'a, Reply>> {
        let header = serde_json::to_string(request).map_err(|_| Errno::EIO)?;
        if header.len() > CONTROL_MAX {
            return Err(Errno::E2BIG);
        }
        Ok(self.0.post(DATA_PATH, vec![(DATA_HEADER, header)], body))
    }
}

impl<H: Host> Transport for HttpTransport<H> {
    fn caller(&self) -> Result<(String, Option<u32>)> {
        self.0.caller()
    }
    fn request(&self, request: wire::Request) -> BoxFuture<'_, Value> {
        Box::pin(async move {
            let body = serde_json::to_vec(&request).map_err(|_| Errno::EIO)?;
            if body.len() > CONTROL_MAX {
                return Err(Errno::E2BIG);
            }
            let reply = self.0.post(CONTROL_PATH, Vec::new(), body).await;
            json(reply.map_err(|_| Errno::EIO)?)
        })
    }
    fn read(&self, request: DataRequest) -> BoxFuture<'_, Vec<u8>> {
        Box::pin(async move {
            let reply = self.data(&request, Vec::new())?.await;
            let reply = reply.map_err(|_| Errno::EIO)?;
            if reply.status != 200 {
                return Err(refusal(&reply));
            }
            Ok(reply.body)
        })
    }
    fn write<'a>(&'a self, request: DataRequest, bytes: &'a [u8]) -> BoxFuture<'a, Written> {
        Box::pin(async move {
            if bytes.len() as u64 > wire::DATA_MAX {
                return Err(Errno::EINVAL);
            }
            // Sent once. A lost reply leaves the write uncertain (EIO), never repeated here.
            let reply = self.data(&request, bytes.to_vec())?.await;
            let value = json(reply.map_err(|_| Errno::EIO)?)?;
            serde_json::from_value(value).map_err(|_| Errno::EIO)
        })
    }
    fn pause(&self) -> BoxFuture<'_, ()> {
        self.0.sleep(LOCK_POLL_MILLIS)
    }
    fn ticket(&self) -> String {
        self.0.ticket()
    }
}

//! Portable cloud driver. A host supplies HTTP, a timer and fresh request tickets; no host
//! types enter the filesystem contract. Hosts renew the session at least every minute and
//! call `drain` during shutdown. Deferred cancellations remain queued across disconnects.
use crate::*;
use abi::remote_fs::{self as wire, Call, DataOperation, DataRequest};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
};

pub trait Transport {
    /// Snapshot the current call's credential and PID before any await. This is kernel
    /// task context, never the opener or connection's cached identity. Only jobs omit PID.
    fn caller(&self) -> Result<(String, Option<u32>)>;
    /// POST /api/fs; deserialize a successful JSON body and translate an error's errno.
    /// Never retry a mutating request automatically except an open with its same ticket.
    fn request(&self, request: wire::Request) -> BoxFuture<'_, Value>;
    /// POST /api/fs/data, the DataRequest JSON in X-OS-Filesystem and an empty body.
    fn read(&self, request: DataRequest) -> BoxFuture<'_, Vec<u8>>;
    /// Same endpoint/header, with raw bytes in the request body. Lost replies are uncertain
    /// writes; the transport must report the failure and must not silently repeat the write.
    fn write<'a>(&'a self, request: DataRequest, bytes: &'a [u8]) -> BoxFuture<'a, Written>;
    fn pause(&self) -> BoxFuture<'_, ()>;
    /// Unique across reconnects/reconstruction (for example a host-generated UUID).
    fn ticket(&self) -> String;
}
struct Pending {
    credential: String,
    call: Call,
}
pub struct CloudFs<T> {
    transport: T,
    connected: wire::Connected,
    opens: RefCell<HashMap<u64, (OpenRef, String)>>,
    pending: RefCell<VecDeque<Pending>>,
}
impl<T: Transport> CloudFs<T> {
    pub async fn connect(transport: T, credential: String) -> Result<Self> {
        let value = transport
            .request(wire::Request {
                version: wire::VERSION,
                credential: credential.clone(),
                session: None,
                call: Call::Connect,
            })
            .await?;
        let connected: wire::Connected = serde_json::from_value(value).map_err(|_| Errno::EIO)?;
        if connected.version != wire::VERSION {
            return Err(Errno::EPROTONOSUPPORT);
        }
        Ok(Self {
            transport,
            connected,
            opens: RefCell::new(HashMap::new()),
            pending: RefCell::new(VecDeque::new()),
        })
    }
    /// The resume secret is private transport state, never a pathname/uid/PID credential.
    pub fn session(&self) -> &wire::Session {
        &self.connected.session
    }
    pub async fn renew(&self, cred: &Cred) -> Result<()> {
        let _: u64 = self.call(cred, Call::Renew).await?;
        Ok(())
    }
    pub async fn disconnect(&self, cred: &Cred) -> Result<()> {
        self.call(cred, Call::Disconnect).await
    }
    pub fn pending_cancellations(&self) -> usize {
        self.pending.borrow().len()
    }
    pub async fn drain(&self) -> Result<()> {
        loop {
            let pending = self.pending.borrow_mut().pop_front();
            let Some(pending) = pending else {
                return Ok(());
            };
            let mut guard = Cancel {
                fs: self,
                pending: Some(pending),
            };
            let p = guard.pending.as_ref().expect("pending cancellation");
            match self.send(&p.credential, p.call.clone()).await {
                Ok(_) | Err(Errno::EACCES | Errno::ENOTCONN | Errno::EBADF) => {
                    if let Call::Release { open } = &p.call {
                        self.opens.borrow_mut().remove(&open.id);
                    }
                    guard.pending = None;
                }
                Err(e) => return Err(e),
            }
        }
    }
    async fn send(&self, credential: &str, call: Call) -> Result<Value> {
        self.transport
            .request(wire::Request {
                version: wire::VERSION,
                credential: credential.into(),
                session: Some(self.connected.session.clone()),
                call,
            })
            .await
    }
    async fn call<R: DeserializeOwned>(&self, cred: &Cred, call: Call) -> Result<R> {
        self.drain().await?;
        let value = self
            .send(cred.token.as_deref().ok_or(Errno::EACCES)?, call)
            .await?;
        serde_json::from_value(value).map_err(|_| Errno::EIO)
    }
    fn opener(&self, open: &OpenRef) -> Result<String> {
        if open.fs != self.connected.root.fs {
            return Err(Errno::EACCES);
        }
        let opens = self.opens.borrow();
        let (record, token) = opens.get(&open.id).ok_or(Errno::EBADF)?;
        if record != open {
            return Err(Errno::EACCES);
        }
        Ok(token.clone())
    }
    async fn opened<R: DeserializeOwned>(&self, open: &OpenRef, call: Call) -> Result<R> {
        self.opener(open)?;
        let (token, _) = self.transport.caller()?;
        self.drain().await?;
        serde_json::from_value(self.send(&token, call).await?).map_err(|_| Errno::EIO)
    }
    fn data(&self, open: &OpenRef, operation: DataOperation) -> Result<DataRequest> {
        self.opener(open)?;
        let (credential, pid) = self.transport.caller()?;
        Ok(DataRequest {
            version: wire::VERSION,
            credential,
            pid,
            session: self.connected.session.clone(),
            open: open.clone(),
            operation,
        })
    }
}
struct Cancel<'a, T: Transport> {
    fs: &'a CloudFs<T>,
    pending: Option<Pending>,
}
impl<T: Transport> Drop for Cancel<'_, T> {
    fn drop(&mut self) {
        if let Some(pending) = self.pending.take() {
            self.fs.pending.borrow_mut().push_front(pending);
        }
    }
}

impl<T: Transport> Filesystem for CloudFs<T> {
    fn id(&self) -> &FsId {
        &self.connected.root.fs
    }
    fn root(&self) -> Handle {
        self.connected.root.clone()
    }
    fn capabilities(&self) -> FsCapabilities {
        self.connected.capabilities
    }
    fn lookup<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            self.call(
                cred,
                Call::Lookup {
                    dir: dir.clone(),
                    name: name.into(),
                },
            )
            .await
        })
    }
    fn walk<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        names: &'a [String],
    ) -> BoxFuture<'a, Walked> {
        Box::pin(async move {
            self.call(
                cred,
                Call::Walk {
                    dir: dir.clone(),
                    names: names.into(),
                },
            )
            .await
        })
    }
    fn parent<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
    ) -> BoxFuture<'a, Option<(Entry, String)>> {
        Box::pin(async move { self.call(cred, Call::Parent { dir: dir.clone() }).await })
    }
    fn metadata<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Metadata> {
        Box::pin(async move {
            self.call(
                cred,
                Call::Metadata {
                    handle: handle.clone(),
                },
            )
            .await
        })
    }
    fn setattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        attr: &'a SetAttr,
    ) -> BoxFuture<'a, Metadata> {
        Box::pin(async move {
            self.call(
                cred,
                Call::Setattr {
                    handle: handle.clone(),
                    attr: attr.clone(),
                },
            )
            .await
        })
    }
    fn read_dir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle) -> BoxFuture<'a, Vec<DirEntry>> {
        Box::pin(async move { self.call(cred, Call::ReadDir { dir: dir.clone() }).await })
    }
    fn read_link<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, String> {
        Box::pin(async move {
            self.call(
                cred,
                Call::ReadLink {
                    handle: handle.clone(),
                },
            )
            .await
        })
    }
    fn mkdir<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            self.call(
                cred,
                Call::Mkdir {
                    dir: dir.clone(),
                    name: name.into(),
                    mode,
                    umask: cred.umask,
                },
            )
            .await
        })
    }
    fn mknod<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        rdev: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            self.call(
                cred,
                Call::Mknod {
                    dir: dir.clone(),
                    name: name.into(),
                    mode,
                    umask: cred.umask,
                    rdev: rdev.into(),
                },
            )
            .await
        })
    }
    fn symlink<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        target: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            self.call(
                cred,
                Call::Symlink {
                    dir: dir.clone(),
                    name: name.into(),
                    target: target.into(),
                },
            )
            .await
        })
    }
    fn link<'a>(
        &'a self,
        cred: &'a Cred,
        target: &'a Handle,
        dir: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            self.call(
                cred,
                Call::Link {
                    target: target.clone(),
                    dir: dir.clone(),
                    name: name.into(),
                },
            )
            .await
        })
    }
    fn unlink<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.call(
                cred,
                Call::Unlink {
                    dir: dir.clone(),
                    name: name.into(),
                },
            )
            .await
        })
    }
    fn rmdir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.call(
                cred,
                Call::Rmdir {
                    dir: dir.clone(),
                    name: name.into(),
                },
            )
            .await
        })
    }
    fn rename<'a>(
        &'a self,
        cred: &'a Cred,
        from_dir: &'a Handle,
        from: &'a str,
        to_dir: &'a Handle,
        to: &'a str,
        flags: RenameFlags,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.call(
                cred,
                Call::Rename {
                    from_dir: from_dir.clone(),
                    from: from.into(),
                    to_dir: to_dir.clone(),
                    to: to.into(),
                    flags,
                },
            )
            .await
        })
    }
    fn getxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move {
            self.call(
                cred,
                Call::Getxattr {
                    handle: handle.clone(),
                    name: name.into(),
                },
            )
            .await
        })
    }
    fn listxattr<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Vec<String>> {
        Box::pin(async move {
            self.call(
                cred,
                Call::Listxattr {
                    handle: handle.clone(),
                },
            )
            .await
        })
    }
    fn setxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
        value: &'a [u8],
        flags: XattrFlags,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.call(
                cred,
                Call::Setxattr {
                    handle: handle.clone(),
                    name: name.into(),
                    value: value.into(),
                    flags,
                },
            )
            .await
        })
    }
    fn removexattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.call(
                cred,
                Call::Removexattr {
                    handle: handle.clone(),
                    name: name.into(),
                },
            )
            .await
        })
    }
    fn statfs<'a>(&'a self, cred: &'a Cred) -> BoxFuture<'a, StatFs> {
        Box::pin(async move { self.call(cred, Call::Statfs).await })
    }
    fn open<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        options: &'a OpenOptions,
    ) -> BoxFuture<'a, OpenRef> {
        Box::pin(async move {
            let ticket = self.transport.ticket();
            let token = cred.token.clone().ok_or(Errno::EACCES)?;
            // Drain before arming this guard: its cancellation must never precede its request.
            self.drain().await?;
            let mut guard = Cancel {
                fs: self,
                pending: Some(Pending {
                    credential: token.clone(),
                    call: Call::CancelOpen {
                        ticket: ticket.clone(),
                    },
                }),
            };
            let open: OpenRef = serde_json::from_value(
                self.send(
                    &token,
                    Call::Open {
                        ticket,
                        handle: handle.clone(),
                        options: *options,
                    },
                )
                .await?,
            )
            .map_err(|_| Errno::EIO)?;
            self.opens
                .borrow_mut()
                .insert(open.id, (open.clone(), token));
            guard.pending = None;
            Ok(open)
        })
    }
    fn create<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        options: &'a OpenOptions,
    ) -> BoxFuture<'a, (Entry, OpenRef)> {
        Box::pin(async move {
            let ticket = self.transport.ticket();
            let token = cred.token.clone().ok_or(Errno::EACCES)?;
            let umask = cred.umask;
            self.drain().await?;
            let mut guard = Cancel {
                fs: self,
                pending: Some(Pending {
                    credential: token.clone(),
                    call: Call::CancelOpen {
                        ticket: ticket.clone(),
                    },
                }),
            };
            let (entry, open): (Entry, OpenRef) = serde_json::from_value(
                self.send(
                    &token,
                    Call::Create {
                        ticket,
                        dir: dir.clone(),
                        name: name.into(),
                        mode,
                        umask,
                        options: *options,
                    },
                )
                .await?,
            )
            .map_err(|_| Errno::EIO)?;
            self.opens
                .borrow_mut()
                .insert(open.id, (open.clone(), token));
            guard.pending = None;
            Ok((entry, open))
        })
    }
    fn read_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a mut [u8],
        offset: u64,
    ) -> BoxFuture<'a, usize> {
        Box::pin(async move {
            if offset > FILE_MAX || buf.len() as u64 > FILE_MAX - offset {
                return Err(Errno::EINVAL);
            }
            let length = (buf.len() as u64).min(wire::DATA_MAX);
            let request = self.data(open, DataOperation::Read { offset, length })?;
            self.drain().await?;
            let bytes = self.transport.read(request).await?;
            if bytes.len() > length as usize {
                return Err(Errno::EIO);
            }
            buf[..bytes.len()].copy_from_slice(&bytes);
            Ok(bytes.len())
        })
    }
    fn write_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a [u8],
        at: WriteAt,
    ) -> BoxFuture<'a, Written> {
        Box::pin(async move {
            let length = (buf.len() as u64).min(wire::DATA_MAX);
            let request = self.data(open, DataOperation::Write { at, length })?;
            self.drain().await?;
            self.transport.write(request, &buf[..length as usize]).await
        })
    }
    fn set_len<'a>(&'a self, open: &'a OpenRef, size: u64) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.opened(
                open,
                Call::SetLen {
                    open: open.clone(),
                    size,
                },
            )
            .await
        })
    }
    fn sync_all<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.opened(
                open,
                Call::Sync {
                    open: open.clone(),
                    data_only: false,
                },
            )
            .await
        })
    }
    fn sync_data<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.opened(
                open,
                Call::Sync {
                    open: open.clone(),
                    data_only: true,
                },
            )
            .await
        })
    }
    fn try_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.opened(
                open,
                Call::TryLock {
                    open: open.clone(),
                    family,
                    kind,
                    range,
                },
            )
            .await
        })
    }
    fn lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let opener = self.opener(open)?;
            let (token, _) = self.transport.caller()?;
            self.drain().await?;
            let ticket = self.transport.ticket();
            let mut guard = Cancel {
                fs: self,
                pending: Some(Pending {
                    // Cleanup belongs to the retained grant even if the actor goes away.
                    credential: opener,
                    call: Call::CancelLock {
                        open: open.clone(),
                        ticket: ticket.clone(),
                    },
                }),
            };
            loop {
                let granted: bool = serde_json::from_value(
                    self.send(
                        &token,
                        Call::Lock {
                            open: open.clone(),
                            family,
                            kind,
                            range,
                            ticket: ticket.clone(),
                        },
                    )
                    .await?,
                )
                .map_err(|_| Errno::EIO)?;
                if granted {
                    self.send(
                        &token,
                        Call::AckLock {
                            open: open.clone(),
                            ticket: ticket.clone(),
                        },
                    )
                    .await?;
                    guard.pending = None;
                    return Ok(());
                }
                self.transport.pause().await?;
            }
        })
    }
    fn unlock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.opened(
                open,
                Call::Unlock {
                    open: open.clone(),
                    family,
                    range,
                },
            )
            .await
        })
    }
    fn test_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, Option<Conflict>> {
        Box::pin(async move {
            self.opened(
                open,
                Call::TestLock {
                    open: open.clone(),
                    kind,
                    range,
                },
            )
            .await
        })
    }
    fn release<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let token = self.opener(open)?;
            let mut guard = Cancel {
                fs: self,
                pending: Some(Pending {
                    credential: token.clone(),
                    call: Call::Release { open: open.clone() },
                }),
            };
            // Retain this release before older cleanup can fail or be cancelled.
            self.drain().await?;
            self.send(&token, Call::Release { open: open.clone() })
                .await?;
            self.opens.borrow_mut().remove(&open.id);
            guard.pending = None;
            Ok(())
        })
    }
}

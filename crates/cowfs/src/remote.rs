//! Portable client for a single mounted remote volume. Deadlines use the client's monotonic
//! clock at request transmission. Server wall-clock timestamps are informational only.
use crate::fs::AsyncMutex;
use crate::*;
use abi::Errno;
use abi::fs::Timespec;
use abi::remote_volume::{self as wire, Fence, Operation as Op, Response as Reply};
use cowtree::pack::{PACK_FOOTER_BYTES, decode_pack_footer, decode_pack_trailer_bytes};
use cowtree::store::{CommitOutcome, PinnedView, ScopedStores};
use std::cell::{Cell, RefCell};
use std::{
    collections::{HashMap, HashSet},
    rc::Rc,
};
use vfs::{BoxFuture, Result};

pub struct RemoteHttpReply {
    pub status: u16,
    pub body: Vec<u8>,
    pub content_length: Option<u64>,
}
pub type Renewal = Rc<dyn Fn() -> BoxFuture<'static, ()>>;
pub trait RenewalGuard {}
impl RenewalGuard for () {}
pub trait RemoteVolumeTransport: 'static {
    /// Browser timers continue while the stream sink or source is suspended.
    fn keep_alive(&self, _secs: u64, _renew: Renewal) -> Result<Box<dyn RenewalGuard>> {
        Ok(Box::new(()))
    }
    fn cleanup(&self, cleanup: BoxFuture<'static, ()>) {
        let _ = vfs::now_or_never(cleanup);
    }

    fn monotonic_seconds(&self) -> u64;
    fn fetch<'a>(
        &'a self,
        method: &'a str,
        path: &'a str,
        headers: &'a [(String, String)],
        body: &'a [u8],
    ) -> BoxFuture<'a, RemoteHttpReply>;
}

pub struct RemoteVolumeStore<T> {
    transport: Rc<T>,
    /// A receive or recovery fork owns its writer timer directly for the duration of the operation.
    scoped_writer: Option<std::rc::Weak<Self>>,
    pins: Rc<RefCell<HashMap<String, (u64, u64)>>>,
    tenant: RefCell<String>,
    volume: RefCell<VolumeId>,
    writer: Cell<Option<(Fence, u64)>>,
    reads: [AsyncMutex; 4],
    next_read: Cell<usize>,
}

pub type RemoteHeadStore<T> = RemoteVolumeStore<T>;
pub type RemotePackStore<T> = RemoteVolumeStore<T>;
pub type RemoteVolumeBackend<T> = RemoteVolumeStore<T>;

struct Guard;
impl WriterLockGuard for Guard {}
struct ScopedWriterGuard {
    _renewal: Box<dyn RenewalGuard>,
}
impl WriterLockGuard for ScopedWriterGuard {}
impl GcLockGuard for Guard {}
#[derive(Clone)]
struct Pin {
    volume: VolumeId,
    id: String,
    _lifetime: Rc<PinLifetime>,
}
struct PinLifetime {
    _renewal: Option<Box<dyn RenewalGuard>>,
    cleanup: Option<Box<dyn FnOnce()>>,
}
impl Drop for PinLifetime {
    fn drop(&mut self) {
        if let Some(cleanup) = self.cleanup.take() {
            cleanup();
        }
    }
}
impl RoPinGuard for Pin {
    fn retry_guard(&self) -> Option<Box<dyn RoPinGuard>> {
        Some(Box::new(self.clone()))
    }
    fn pin_id(&self) -> Option<&str> {
        Some(&self.id)
    }
    fn volume(&self) -> Option<&VolumeId> {
        Some(&self.volume)
    }
}

fn success(reply: RemoteHttpReply) -> Result<RemoteHttpReply> {
    if (200..300).contains(&reply.status) {
        return Ok(reply);
    }
    Err(serde_json::from_slice::<wire::VolumeError>(&reply.body)
        .map(|e| e.errno)
        .unwrap_or(Errno::EIO))
}

impl<T: RemoteVolumeTransport> RemoteVolumeStore<T> {
    pub fn new(volume: VolumeId, transport: T) -> Self {
        Self::shared(volume, Rc::new(transport))
    }
    fn shared(volume: VolumeId, transport: Rc<T>) -> Self {
        Self {
            transport,
            scoped_writer: None,
            pins: Default::default(),
            tenant: Default::default(),
            volume: RefCell::new(volume),
            writer: Cell::new(None),
            reads: Default::default(),
            next_read: Cell::new(0),
        }
    }
    fn scoped(&self, volume: &VolumeId) -> Rc<Self> {
        Rc::new_cyclic(|weak| Self {
            scoped_writer: Some(weak.clone()),
            ..Self::shared(volume.clone(), self.transport.clone())
        })
    }
    fn volume(&self) -> VolumeId {
        self.volume.borrow().clone()
    }
    fn lease(&self) -> Result<Fence> {
        self.writer
            .get()
            .filter(|(_, deadline)| self.transport.monotonic_seconds() < *deadline)
            .map(|(f, _)| f)
            .ok_or(Errno::ESTALE)
    }
    fn renewed(&self, head: Fence, sent: u64) -> Result<()> {
        let deadline =
            sent.saturating_add(wire::WRITER_LEASE_TTL_SECS - wire::WRITER_SELF_FENCE_MARGIN_SECS);
        self.writer.set(Some((head, deadline)));
        self.lease().map(|_| ())
    }
    async fn publish(
        &self,
        r: &CommitRequest,
        receive: bool,
        snapshot: Option<&str>,
        retry: bool,
    ) -> CommitOutcome {
        use CommitOutcome::*;
        let status = Op::Status {
            op_id: r.op_id,
            lease: Some(Fence {
                incarnation: r.expected_incarnation,
                fence: r.expected_fence,
            }),
        };
        if retry {
            match self.rpc(&r.volume, status.clone()).await {
                Ok(Reply::Status(wire::Status::Committed(rec))) => {
                    return Self::receipt(r, snapshot, rec);
                }
                Ok(Reply::Status(wire::Status::Aborted { errno })) => return Aborted(errno),
                Ok(Reply::Status(wire::Status::Pending)) => {}
                _ => return Uncertain,
            }
        }
        if let Err(e) = self.lease() {
            // An unrecorded request may still arrive while the DO considers the fence live.
            return if retry { Uncertain } else { Aborted(e) };
        }
        let op = if receive {
            Op::Receive {
                request: r.clone(),
                snapshot: snapshot.map(str::to_owned),
            }
        } else {
            Op::Commit { request: r.clone() }
        };
        match self.rpc(&r.volume, op).await {
            Ok(Reply::Receipt(rec)) => Self::receipt(r, snapshot, rec),
            Err(e @ (Errno::EIO | Errno::ENOTCONN | Errno::ESTALE)) => {
                match self.rpc(&r.volume, status).await {
                    Ok(Reply::Status(wire::Status::Committed(rec))) => {
                        Self::receipt(r, snapshot, rec)
                    }
                    Ok(Reply::Status(wire::Status::Aborted { errno })) => Aborted(errno),
                    Ok(Reply::Status(wire::Status::Pending)) if e == Errno::ESTALE => Aborted(e),
                    _ => Uncertain,
                }
            }
            Err(e) => Aborted(e),
            _ => Uncertain,
        }
    }
    fn receipt(r: &CommitRequest, snapshot: Option<&str>, receipt: wire::Receipt) -> CommitOutcome {
        let payload = match snapshot {
            Some(name) => serde_json::to_vec(&(r, name)),
            None => serde_json::to_vec(r),
        };
        if receipt.op_id != r.op_id
            || receipt.head.volume != r.volume
            || !payload.is_ok_and(|p| sha256(&p) == receipt.payload_hash)
        {
            return CommitOutcome::Aborted(Errno::EINVAL);
        }
        CommitOutcome::Committed(receipt.head)
    }
    async fn rpc(&self, volume: &VolumeId, call: Op) -> Result<Reply> {
        let raw = serde_json::to_vec(&wire::Request {
            version: wire::REMOTE_VOLUME_PROTOCOL,
            volume: volume.clone(),
            call,
        })
        .map_err(|_| Errno::EINVAL)?;
        if raw.len() > wire::CONTROL_BODY_MAX {
            return Err(Errno::EFBIG);
        }
        let reply = success(
            self.transport
                .fetch("POST", "/api/volumes/rpc", &[], &raw)
                .await?,
        )?;
        serde_json::from_slice(&reply.body).map_err(|_| Errno::EIO)
    }
    async fn attach(&self, v: &VolumeId, op: Op) -> Result<WriterLease> {
        let sent = self.transport.monotonic_seconds();
        let Reply::Attached {
            head,
            forked_from,
            expires,
        } = self.rpc(v, op).await?
        else {
            return Err(Errno::EIO);
        };
        self.renewed((&head).into(), sent)?;
        self.volume.replace(head.volume.clone());
        let mut lease = WriterLease {
            volume: head.volume.clone(),
            incarnation: head.incarnation,
            fence: head.fence,
            epoch: head.epoch,
            head,
            forked_from,
            expires_at: Some(Timespec {
                sec: expires,
                nsec: 0,
            }),
            guard: Rc::new(Guard),
        };
        if let Some(scope) = self.scoped_writer.clone() {
            let current = lease.clone();
            let timer = self.transport.keep_alive(
                wire::WRITER_RENEW_INTERVAL_SECS,
                Rc::new(move || {
                    let scope = scope.upgrade();
                    let mut current = current.clone();
                    Box::pin(async move {
                        if let Some(store) = scope {
                            store.renew_writer(&mut current).await?;
                        }
                        Ok(())
                    })
                }),
            );
            match timer {
                Ok(timer) => lease.guard = Rc::new(ScopedWriterGuard { _renewal: timer }),
                Err(e) => {
                    let _ = self.release_writer(lease).await;
                    return Err(e);
                }
            }
        }
        Ok(lease)
    }
    async fn pin(
        &self,
        v: &VolumeId,
        snapshot: Option<&str>,
        root: Option<Digest>,
        traversal: bool,
    ) -> Result<(VolumeHead, Box<dyn RoPinGuard>)> {
        let sent = self.transport.monotonic_seconds();
        let Reply::Pinned {
            head,
            pin_id,
            expires,
        } = self
            .rpc(
                v,
                Op::PinRo {
                    snapshot: snapshot.map(str::to_owned),
                    root,
                },
            )
            .await?
        else {
            return Err(Errno::EIO);
        };
        self.pins
            .borrow_mut()
            .insert(pin_id.clone(), (sent + wire::RO_PIN_TTL_SECS, expires));
        let mut scope = Self::shared(v.clone(), self.transport.clone());
        scope.pins = self.pins.clone();
        let scope = Rc::new(scope);
        let release = scope.clone();
        let id = pin_id.clone();
        let mut lifetime = PinLifetime {
            cleanup: Some(Box::new(move || {
                if release.pins.borrow().contains_key(&id) {
                    let transport = release.transport.clone();
                    transport.cleanup(Box::pin(async move { release.unpin(&id).await }));
                }
            })),
            _renewal: None,
        };
        if traversal {
            let id = pin_id.clone();
            lifetime._renewal = Some(self.transport.keep_alive(
                wire::RO_PIN_TTL_SECS / 3,
                Rc::new(move || {
                    let scope = scope.clone();
                    let id = id.clone();
                    Box::pin(async move { scope.renew_ro_pin(&scope.volume(), &id).await })
                }),
            )?);
        }
        Ok((
            head,
            Box::new(Pin {
                volume: v.clone(),
                id: pin_id,
                _lifetime: Rc::new(lifetime),
            }),
        ))
    }
    async fn unpin(&self, id: &str) -> Result<()> {
        if !self.pins.borrow().contains_key(id) {
            return Ok(());
        }
        match self
            .rpc(&self.volume(), Op::UnpinRo { pin_id: id.into() })
            .await?
        {
            Reply::Done => {
                self.pins.borrow_mut().remove(id);
                Ok(())
            }
            _ => Err(Errno::EIO),
        }
    }
    async fn pack(
        &self,
        method: &str,
        id: &PackId,
        mut headers: Vec<(String, String)>,
        body: &[u8],
    ) -> Result<RemoteHttpReply> {
        digest_from_hex(&id.0)?;
        headers.push(("X-OS-Volume".into(), self.volume().0));
        success(
            self.transport
                .fetch(
                    method,
                    &format!("/api/volumes/packs/{}", id.0),
                    &headers,
                    body,
                )
                .await?,
        )
    }
}
impl<T: RemoteVolumeTransport> HeadStore for RemoteVolumeStore<T> {
    fn scoped_stores(&self, v: &VolumeId) -> Option<ScopedStores<Self>> {
        let scoped = self.scoped(v);
        Some((scoped.clone(), scoped))
    }
    fn reserve_receive<'a>(&'a self, v: &'a VolumeId) -> BoxFuture<'a, Option<WriterLease>> {
        Box::pin(async move { self.attach(v, Op::BeginReceive {}).await.map(Some) })
    }
    fn filesystem_identity(&self, v: &VolumeId) -> String {
        format!("cowfs:remote/{}/{}", self.tenant.borrow(), v.0)
    }
    fn format_version(&self) -> BoxFuture<'_, Option<u32>> {
        Box::pin(async move {
            let version = abi::contract::Boundary::Volume.version();
            match self
                .rpc(
                    &self.volume(),
                    Op::Hello {
                        versions: vec![version],
                    },
                )
                .await?
            {
                Reply::Version { version: v, .. } if v == version => {}
                _ => return Err(Errno::EPROTONOSUPPORT),
            }
            match self.rpc(&self.volume(), Op::FormatVersion {}).await? {
                Reply::Version { version, tenant } => Ok({
                    self.tenant.replace(tenant);
                    Some(version)
                }),
                _ => Err(Errno::EIO),
            }
        })
    }
    fn grace_window_secs(&self) -> u64 {
        wire::GC_GRACE_WINDOW_SECS
    }
    fn check_writer_deadline(&self) -> Result<()> {
        self.lease().map(|_| ())
    }
    fn create_volume<'a>(
        &'a self,
        head: &'a VolumeHead,
        nodes: &'a [(Digest, Vec<u8>)],
    ) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            match self
                .rpc(
                    &head.volume,
                    Op::CreateVolume {
                        head: head.clone(),
                        nodes: nodes.to_vec(),
                    },
                )
                .await?
            {
                Reply::Head(h) => Ok(h),
                _ => Err(Errno::EIO),
            }
        })
    }
    fn read_head<'a>(&'a self, v: &'a VolumeId) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            match self.rpc(v, Op::ReadHead {}).await? {
                Reply::Head(h) => Ok(h),
                _ => Err(Errno::EIO),
            }
        })
    }
    fn list_volumes(&self) -> BoxFuture<'_, Vec<VolumeHead>> {
        Box::pin(async move {
            match self.rpc(&self.volume(), Op::ListVolumes {}).await? {
                Reply::Heads(v) => Ok(v),
                _ => Err(Errno::EIO),
            }
        })
    }
    fn acquire_writer<'a>(
        &'a self,
        v: &'a VolumeId,
        mode: WriterMode,
    ) -> BoxFuture<'a, WriterLease> {
        Box::pin(async move { self.attach(v, Op::AttachRw { mode }).await })
    }
    fn renew_writer<'a>(&'a self, l: &'a mut WriterLease) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let lease = self.lease()?;
            if lease != Fence::from(&l.head) {
                return Err(Errno::ESTALE);
            }
            let sent = self.transport.monotonic_seconds();
            let expires = match self.rpc(&l.volume, Op::Renew { lease }).await {
                Ok(Reply::Renewed { expires }) => expires,
                Ok(_) => return Err(Errno::EIO),
                Err(Errno::ESTALE) => {
                    if self.writer.get().is_some_and(|(f, _)| f == lease) {
                        self.writer.set(None);
                    }
                    return Err(Errno::ESTALE);
                }
                Err(e) => return Err(e),
            };
            if !self.writer.get().is_some_and(|(f, _)| f == lease) {
                return Err(Errno::ESTALE);
            }
            self.renewed(lease, sent)?;
            l.expires_at = Some(Timespec {
                sec: expires,
                nsec: 0,
            });
            Ok(())
        })
    }
    fn release_writer<'a>(&'a self, l: WriterLease) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let lease = Fence::from(&l.head);
            let result = self.rpc(&l.volume, Op::DetachRw { lease }).await;
            if matches!(result, Ok(Reply::Done) | Err(Errno::ESTALE | Errno::ENOENT))
                && self.writer.get().is_some_and(|(f, _)| f == lease)
            {
                self.writer.set(None);
            }
            match result? {
                Reply::Done => Ok(()),
                _ => Err(Errno::EIO),
            }
        })
    }
    fn pin_ro_root<'a>(
        &'a self,
        v: &'a VolumeId,
        s: Option<&'a str>,
    ) -> BoxFuture<'a, (VolumeHead, Box<dyn RoPinGuard>)> {
        Box::pin(self.pin(v, s, None, false))
    }
    fn pin_view<'a>(
        &'a self,
        v: &'a VolumeId,
        name: Option<&'a str>,
        exact: Option<&'a VolumeHead>,
    ) -> BoxFuture<'a, PinnedView> {
        Box::pin(async move {
            let (head, pin) = self.pin(v, name, exact.map(|h| h.root), true).await?;
            Ok((exact.cloned().unwrap_or(head), Some(pin)))
        })
    }
    fn repin_root<'a>(&'a self, head: &'a VolumeHead) -> BoxFuture<'a, Box<dyn RoPinGuard>> {
        Box::pin(async move {
            self.pin(&head.volume, None, Some(head.root), false)
                .await
                .map(|(_, pin)| pin)
        })
    }
    fn writer_expired(&self) -> bool {
        self.writer.get().is_some_and(|(_, end)| {
            self.transport.monotonic_seconds()
                >= end.saturating_add(wire::WRITER_SELF_FENCE_MARGIN_SECS)
        })
    }
    fn pin_status(&self, id: &str) -> (bool, Option<u64>) {
        self.pins
            .borrow()
            .get(id)
            .map_or((false, None), |&(deadline, expires)| {
                (self.transport.monotonic_seconds() < deadline, Some(expires))
            })
    }
    fn renew_ro_pin<'a>(&'a self, v: &'a VolumeId, id: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let sent = self.transport.monotonic_seconds();
            match self.rpc(v, Op::RenewRo { pin_id: id.into() }).await? {
                Reply::Renewed { expires } => {
                    if let Some(d) = self.pins.borrow_mut().get_mut(id) {
                        *d = (sent + wire::RO_PIN_TTL_SECS, expires);
                    }
                    Ok(())
                }
                _ => Err(Errno::EIO),
            }
        })
    }
    fn unpin_ro_root<'a>(&'a self, p: Box<dyn RoPinGuard>) -> BoxFuture<'a, ()> {
        Box::pin(async move { self.unpin(p.pin_id().ok_or(Errno::EINVAL)?).await })
    }
    fn get_node<'a>(&'a self, d: &'a Digest) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let bytes = match self.rpc(&self.volume(), Op::GetNode { digest: *d }).await? {
                Reply::Node(b) => Ok(b),
                _ => Err(Errno::EIO),
            }?;
            if bytes.len() > NODE_MAX_BYTES || sha256(&bytes) != *d {
                return Err(Errno::EIO);
            }
            Ok(bytes)
        })
    }
    fn lookup_block<'a>(&'a self, d: &'a Digest) -> BoxFuture<'a, Option<BlockLoc>> {
        Box::pin(async move {
            let loc = match self
                .rpc(&self.volume(), Op::LookupBlock { digest: *d })
                .await?
            {
                Reply::Block(b) => Ok(b),
                _ => Err(Errno::EIO),
            }?;
            if let Some(l) = &loc {
                l.validate_v1()?;
            }
            Ok(loc)
        })
    }
    fn commit_head<'a>(&'a self, r: &'a CommitRequest) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            let mut req = r.clone();
            self.prepare_publication(&mut req).await?;
            self.publish(&req, false, None, false).await.into_result()
        })
    }
    fn publish_commit<'a>(
        &'a self,
        r: &'a CommitRequest,
        retry: bool,
    ) -> cowtree::store::Publication<'a> {
        Box::pin(self.publish(r, false, None, retry))
    }
    fn prepare_publication<'a>(&'a self, r: &'a mut CommitRequest) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            const LIMIT: usize = 2 * 1024 * 1024;
            // JSON byte arrays use at most four characters per byte plus the digest and delimiters.
            let mut start = 0;
            let mut size = 0;
            for (i, (_, bytes)) in r.put_nodes.iter().enumerate() {
                let bound = 150 + bytes.len() * 4;
                if size + bound > LIMIT {
                    self.stage_objects(&r.put_nodes[start..i], &[], &[], r.committed_at)
                        .await?;
                    start = i;
                    size = 0;
                }
                size += bound;
            }
            if start != 0 {
                self.stage_objects(&r.put_nodes[start..], &[], &[], r.committed_at)
                    .await?;
                r.put_nodes.clear();
            }
            Ok(())
        })
    }
    fn stage_objects<'a>(
        &'a self,
        nodes: &'a [(Digest, Vec<u8>)],
        packs: &'a [PackMeta],
        blocks: &'a [(Digest, BlockLoc)],
        _: Timespec,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let call = Op::StageObjects {
                lease: self.lease()?,
                nodes: nodes.to_vec(),
                packs: packs.to_vec(),
                blocks: blocks.to_vec(),
            };
            match self.rpc(&self.volume(), call).await? {
                Reply::Done => Ok(()),
                _ => Err(Errno::EIO),
            }
        })
    }
    fn commit_received_root<'a>(
        &'a self,
        r: &'a ReceiveCommitRequest,
    ) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            let destination;
            let mut reservation = None;
            let (store, expected) = match r.expected_lease {
                Some(fence) => (self, fence),
                None => {
                    destination = self.scoped(&r.volume);
                    let lease = destination.attach(&r.volume, Op::BeginReceive {}).await?;
                    let fence = (lease.incarnation, lease.fence, lease.epoch);
                    reservation = Some(lease);
                    (&*destination, fence)
                }
            };
            let (expected_incarnation, expected_fence, expected_epoch) = expected;
            let mut request = CommitRequest {
                op_id: r.op_id,
                volume: r.volume.clone(),
                expected_incarnation,
                expected_fence,
                expected_epoch,
                new_root: r.new_root,
                put_nodes: r.put_nodes.clone(),
                put_packs: r.put_packs.clone(),
                put_blocks: r.put_blocks.clone(),
                committed_at: r.committed_at,
            };
            let result = async {
                store.prepare_publication(&mut request).await?;
                store
                    .publish(&request, true, r.snapshot_name.as_deref(), false)
                    .await
                    .into_result()
            }
            .await;
            if let Some(lease) = reservation {
                store.release_writer(lease).await?;
            }
            result
        })
    }
    fn create_snapshot<'a>(
        &'a self,
        v: &'a VolumeId,
        name: &'a str,
        head: &'a VolumeHead,
        _: Timespec,
    ) -> BoxFuture<'a, SnapshotRecord> {
        Box::pin(async move {
            match self
                .rpc(
                    v,
                    Op::CreateSnapshot {
                        name: name.into(),
                        head: head.clone(),
                    },
                )
                .await?
            {
                Reply::Snapshot(s) => Ok(s),
                _ => Err(Errno::EIO),
            }
        })
    }
    fn get_snapshot<'a>(&'a self, v: &'a VolumeId, name: &'a str) -> BoxFuture<'a, SnapshotRecord> {
        Box::pin(async move {
            match self.rpc(v, Op::GetSnapshot { name: name.into() }).await? {
                Reply::Snapshot(s) => Ok(s),
                _ => Err(Errno::EIO),
            }
        })
    }
    fn list_snapshots<'a>(&'a self, v: &'a VolumeId) -> BoxFuture<'a, Vec<SnapshotRecord>> {
        Box::pin(async move {
            match self.rpc(v, Op::ListSnapshots {}).await? {
                Reply::Snapshots(s) => Ok(s),
                _ => Err(Errno::EIO),
            }
        })
    }
    fn delete_snapshot<'a>(&'a self, v: &'a VolumeId, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.delete_snapshot_checked(&self.read_head(v).await?, name)
                .await
        })
    }
    fn delete_snapshot_checked<'a>(
        &'a self,
        h: &'a VolumeHead,
        name: &'a str,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            match self
                .rpc(
                    &h.volume,
                    Op::DeleteSnapshot {
                        name: name.into(),
                        head: h.clone(),
                    },
                )
                .await?
            {
                Reply::Done => Ok(()),
                _ => Err(Errno::EIO),
            }
        })
    }
    fn fork_volume<'a>(&'a self, r: &'a ForkRequest) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            match self
                .rpc(&r.source_volume, Op::Fork { request: r.clone() })
                .await?
            {
                Reply::Head(h) => Ok(h),
                _ => Err(Errno::EIO),
            }
        })
    }
    fn check_no_readers<'a>(&'a self, v: &'a VolumeId) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            match self.rpc(v, Op::CheckNoReaders {}).await? {
                Reply::Done => Ok(()),
                _ => Err(Errno::EIO),
            }
        })
    }
    fn delete_volume<'a>(&'a self, v: &'a VolumeId) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            match self
                .rpc(
                    v,
                    Op::DeleteVolume {
                        expected: None,
                        only_unmodified: false,
                    },
                )
                .await?
            {
                Reply::Deleted(true) => Ok(()),
                _ => Err(Errno::EIO),
            }
        })
    }
    fn delete_volume_with_lease<'a>(
        &'a self,
        l: WriterLease,
        only_unmodified: bool,
    ) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            let r = match self
                .rpc(
                    &l.volume,
                    Op::DeleteVolume {
                        expected: Some(l.head.clone()),
                        only_unmodified,
                    },
                )
                .await
            {
                Ok(Reply::Deleted(v)) => Ok(v),
                Ok(_) => Err(Errno::EIO),
                Err(e) => Err(e),
            };
            let _ = self.release_writer(l).await;
            r
        })
    }
    fn reformat_volume_with_lease<'a>(
        &'a self,
        l: WriterLease,
        h: &'a VolumeHead,
        n: &'a [(Digest, Vec<u8>)],
    ) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            let r = match self
                .rpc(
                    &l.volume,
                    Op::ReformatVolume {
                        expected: l.head.clone(),
                        head: h.clone(),
                        nodes: n.to_vec(),
                    },
                )
                .await
            {
                Ok(Reply::Head(h)) => Ok(h),
                Ok(_) => Err(Errno::EIO),
                Err(e) => Err(e),
            };
            let _ = self.release_writer(l).await;
            r
        })
    }
    fn run_server_gc(&self) -> BoxFuture<'_, Option<abi::volume::CowfsGcResp>> {
        Box::pin(async move {
            match self.rpc(&self.volume(), Op::RunGc {}).await? {
                Reply::Gc(g) => Ok(Some(g)),
                _ => Err(Errno::EIO),
            }
        })
    }
    fn acquire_gc_lock(&self, _: bool) -> BoxFuture<'_, Box<dyn GcLockGuard>> {
        Box::pin(async { Ok(Box::new(Guard) as Box<dyn GcLockGuard>) })
    }
    fn list_all_roots(&self) -> BoxFuture<'_, Vec<GcRoot>> {
        Box::pin(async { Err(Errno::EOPNOTSUPP) })
    }
    fn list_indexed_packs(&self) -> BoxFuture<'_, HashSet<PackId>> {
        Box::pin(async move { Ok(self.list_packs().await?.into_iter().collect()) })
    }
    fn prune_abandoned_ephemeral_forks(&self, _: Timespec, _: u64) -> BoxFuture<'_, usize> {
        Box::pin(async { Err(Errno::EOPNOTSUPP) })
    }
    fn sweep_metadata<'a>(
        &'a self,
        _: &'a HashSet<Digest>,
        _: &'a HashSet<PackId>,
        _: Timespec,
        _: u64,
    ) -> BoxFuture<'a, Vec<PackId>> {
        Box::pin(async { Err(Errno::EOPNOTSUPP) })
    }
}

impl<T: RemoteVolumeTransport> PackStore for RemoteVolumeStore<T> {
    fn write_pack<'a>(&'a self, id: &'a PackId, bytes: &'a [u8]) -> BoxFuture<'a, PackMeta> {
        Box::pin(async move {
            let lease = self.lease()?;
            if bytes.len() > PACK_MAX_BYTES {
                return Err(Errno::EFBIG);
            }
            if digest_to_hex(&sha256(bytes)) != id.0 {
                return Err(Errno::EIO);
            }
            let headers = vec![
                ("X-OS-Incarnation".into(), lease.incarnation.to_string()),
                ("X-OS-Fence".into(), lease.fence.to_string()),
            ];
            let reply = self.pack("PUT", id, headers, bytes).await?;
            let meta: PackMeta = serde_json::from_slice(&reply.body).map_err(|_| Errno::EIO)?;
            if meta.pack_id != *id || meta.size as usize != bytes.len() {
                return Err(Errno::EIO);
            }
            Ok(meta)
        })
    }
    fn read_pack_range<'a>(
        &'a self,
        id: &'a PackId,
        offset: u32,
        len: u32,
    ) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let end = offset
                .checked_add(len)
                .filter(|n| *n as usize <= PACK_MAX_BYTES)
                .ok_or(Errno::EIO)?;
            let lane = self.next_read.get();
            self.next_read.set((lane + 1) % self.reads.len());
            let _slot = self.reads[lane].lock().await;
            let mut out = Vec::with_capacity(len as usize);
            let mut start = offset;
            while start < end {
                let next = (start + EXTENT_MAX_BYTES).min(end);
                let r = self
                    .pack(
                        "GET",
                        id,
                        vec![("Range".into(), format!("bytes={start}-{}", next - 1))],
                        &[],
                    )
                    .await?;
                if r.status != 206 || r.body.len() != (next - start) as usize {
                    return Err(Errno::EIO);
                }
                out.extend(r.body);
                start = next;
            }
            Ok(out)
        })
    }
    fn read_pack_trailer<'a>(&'a self, id: &'a PackId) -> BoxFuture<'a, PackTrailer> {
        Box::pin(async move {
            let size = self.stat_pack(id).await?.ok_or(Errno::ENOENT)?;
            let footer = u32::try_from(size)
                .ok()
                .and_then(|s| s.checked_sub(PACK_FOOTER_BYTES as u32))
                .ok_or(Errno::EIO)?;
            let (len, hash) = decode_pack_footer(
                &self
                    .read_pack_range(id, footer, PACK_FOOTER_BYTES as u32)
                    .await?,
            )?;
            let start = footer.checked_sub(len).ok_or(Errno::EIO)?;
            decode_pack_trailer_bytes(&self.read_pack_range(id, start, len).await?, hash, start)
        })
    }
    fn stat_pack<'a>(&'a self, id: &'a PackId) -> BoxFuture<'a, Option<u64>> {
        Box::pin(async move {
            match self.pack("HEAD", id, Vec::new(), &[]).await {
                Ok(r) => Ok(Some(
                    r.content_length
                        .filter(|n| *n <= PACK_MAX_BYTES as u64)
                        .ok_or(Errno::EIO)?,
                )),
                Err(Errno::ENOENT) => Ok(None),
                Err(e) => Err(e),
            }
        })
    }
    fn list_packs(&self) -> BoxFuture<'_, Vec<PackId>> {
        Box::pin(async move {
            match self.rpc(&self.volume(), Op::ListPacks {}).await? {
                Reply::Packs(p) => Ok(p),
                _ => Err(Errno::EIO),
            }
        })
    }
    fn delete_pack<'a>(&'a self, _: &'a PackId) -> BoxFuture<'a, ()> {
        Box::pin(async { Err(Errno::EOPNOTSUPP) })
    }
}

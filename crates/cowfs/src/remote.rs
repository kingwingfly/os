//! Portable client for a single mounted remote volume. Deadlines use the client's monotonic
//! clock at request transmission. Server wall-clock timestamps are informational only.
use crate::fs::AsyncMutex;
use crate::*;
use abi::Errno;
use abi::fs::Timespec;
use abi::remote_volume::{self as wire, Fence, Operation as Op, Response as Reply};
use cowtree::pack::{PACK_FOOTER_BYTES, decode_pack_footer, decode_pack_trailer_bytes};
use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use vfs::{BoxFuture, Result};

pub struct RemoteHttpReply {
    pub status: u16,
    pub body: Vec<u8>,
    pub content_length: Option<u64>,
}
pub trait RemoteVolumeTransport {
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
    transport: T,
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
impl GcLockGuard for Guard {}
struct Pin {
    volume: VolumeId,
    id: String,
}
impl RoPinGuard for Pin {
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
        Self {
            transport,
            tenant: Default::default(),
            volume: RefCell::new(volume),
            writer: Cell::new(None),
            reads: Default::default(),
            next_read: Cell::new(0),
        }
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
    async fn publish(&self, r: &CommitRequest, snapshot: Option<&str>) -> Result<VolumeHead> {
        let result = if self.lease().is_ok() {
            let call = match snapshot {
                Some(name) => Op::Receive {
                    request: r.clone(),
                    snapshot: Some(name.to_owned()),
                },
                None => Op::Commit { request: r.clone() },
            };
            self.rpc(&r.volume, call).await
        } else {
            Err(Errno::ESTALE)
        };
        let receipt = match result {
            Ok(Reply::Receipt(rec)) => rec,
            Err(error @ (Errno::EIO | Errno::ENOTCONN | Errno::ESTALE)) => {
                match self.rpc(&r.volume, Op::Status { op_id: r.op_id }).await? {
                    Reply::Status(wire::Status::Committed(rec)) => rec,
                    Reply::Status(wire::Status::Aborted { errno }) => return Err(errno),
                    _ => return Err(error),
                }
            }
            Err(error) => return Err(error),
            _ => return Err(Errno::EIO),
        };
        if receipt.op_id != r.op_id || receipt.head.volume != r.volume {
            return Err(Errno::EIO);
        }
        let payload = match snapshot {
            Some(name) => serde_json::to_vec(&(r, name)),
            None => serde_json::to_vec(r),
        }
        .map_err(|_| Errno::EIO)?;
        if receipt.payload_hash != sha256(&payload) {
            return Err(Errno::EINVAL);
        }
        Ok(receipt.head)
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
    fn filesystem_identity(&self, v: &VolumeId) -> String {
        format!("cowfs:remote/{}/{}", self.tenant.borrow(), v.0)
    }
    fn format_version(&self) -> BoxFuture<'_, Option<u32>> {
        Box::pin(async move {
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
        Box::pin(async move {
            let sent = self.transport.monotonic_seconds();
            let Reply::Attached {
                head,
                forked_from,
                expires,
            } = self.rpc(v, Op::AttachRw { mode }).await?
            else {
                return Err(Errno::EIO);
            };
            self.renewed((&head).into(), sent)?;
            self.volume.replace(head.volume.clone());
            Ok(WriterLease {
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
                guard: Box::new(Guard),
            })
        })
    }
    fn renew_writer<'a>(&'a self, l: &'a mut WriterLease) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let lease = self.lease()?;
            if lease != Fence::from(&l.head) {
                return Err(Errno::ESTALE);
            }
            let sent = self.transport.monotonic_seconds();
            let expires = match self.rpc(&l.volume, Op::Renew { lease }).await? {
                Reply::Renewed { expires } => Ok(expires),
                _ => Err(Errno::EIO),
            }?;
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
            if self.writer.get().is_some_and(|(f, _)| f == lease) {
                self.writer.set(None);
            }
            match self.rpc(&l.volume, Op::DetachRw { lease }).await? {
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
        Box::pin(async move {
            let (head, id) = match self
                .rpc(
                    v,
                    Op::PinRo {
                        snapshot: s.map(str::to_owned),
                    },
                )
                .await?
            {
                Reply::Pinned { head, pin_id } => Ok((head, pin_id)),
                _ => Err(Errno::EIO),
            }?;
            Ok((
                head,
                Box::new(Pin {
                    volume: v.clone(),
                    id,
                }) as Box<dyn RoPinGuard>,
            ))
        })
    }
    fn renew_ro_pin<'a>(&'a self, v: &'a VolumeId, id: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            match self.rpc(v, Op::RenewRo { pin_id: id.into() }).await? {
                Reply::Done => Ok(()),
                _ => Err(Errno::EIO),
            }
        })
    }
    fn unpin_ro_root<'a>(&'a self, p: Box<dyn RoPinGuard>) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let volume = p.volume().ok_or(Errno::EINVAL)?;
            let pin_id = p.pin_id().ok_or(Errno::EINVAL)?.to_owned();
            match self.rpc(volume, Op::UnpinRo { pin_id }).await? {
                Reply::Done => Ok(()),
                _ => Err(Errno::EIO),
            }
        })
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
        Box::pin(self.publish(r, None))
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
            let (expected_incarnation, expected_fence, expected_epoch) =
                r.expected_lease.ok_or(Errno::ENOENT)?;
            let request = CommitRequest {
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
            self.publish(&request, r.snapshot_name.as_deref()).await
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

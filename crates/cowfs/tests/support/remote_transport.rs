//! In-process HTTP peer for deterministic client tests. The Worker acceptance suite exercises
//! the production authority, SQL transactions, R2 checksums, and garbage collector.
use abi::{
    Errno,
    remote_volume::{self as w, Operation as Op, Response as Reply},
};
use cowtree::{
    memory::{MemoryHeadStore, MemoryPackStore},
    *,
};
use os_cowfs::remote::{Renewal, RenewalGuard};
use os_cowfs::{
    CowFs, CowFsConfig, CowFsOpenMode, RemoteHttpReply, RemoteVolumeStore, RemoteVolumeTransport,
};
use serde::Serialize;
use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    rc::Rc,
};
use vfs::{BoxFuture, Result, Timespec};

pub type Mount = CowFs<RemoteVolumeStore<Transport>, RemoteVolumeStore<Transport>>;
type Receipts = HashMap<(VolumeId, [u8; 16]), (Digest, w::Status)>;
struct ReaderPin {
    guard: Rc<dyn RoPinGuard>,
    head: VolumeHead,
    expires: u64,
}
#[derive(Default)]
pub struct Peer {
    pub heads: MemoryHeadStore,
    pub packs: MemoryPackStore,
    leases: RefCell<HashMap<VolumeId, WriterLease>>,
    pins: RefCell<HashMap<String, ReaderPin>>,
    timers: RefCell<HashMap<u64, (u64, Renewal)>>,
    next_timer: Cell<u64>,
    receipts: RefCell<Receipts>,
    next_pin: Cell<u64>,
    pub hold_nodes: Cell<bool>,
    reservations: RefCell<HashMap<VolumeId, w::Fence>>,
    deadlines: RefCell<HashMap<VolumeId, u64>>,
    pub status_offline: Cell<bool>,
    pub drop_before_publish: Cell<bool>,
    pub abort_io: Cell<bool>,
    pub hold_upload: Cell<bool>,
    pub signed_out: Cell<bool>,
    pub staged_bytes: Cell<usize>,
    pub stage_batches: Cell<usize>,
    pub lost: Cell<bool>,
    pub retry_epoch: Cell<bool>,
    pub queries: Cell<usize>,
    pub time: Cell<u64>,
    pub puts: Cell<usize>,
    pub last_range: Cell<u32>,
}
#[derive(Clone)]
pub struct Transport(Rc<Peer>);
fn response(status: u16, body: Vec<u8>) -> RemoteHttpReply {
    RemoteHttpReply {
        status,
        content_length: Some(body.len() as u64),
        body,
    }
}
fn encoded(value: &impl Serialize) -> Result<RemoteHttpReply> {
    Ok(response(200, serde_json::to_vec(value).unwrap()))
}
impl Transport {
    async fn publish(
        &self,
        r: CommitRequest,
        receive: bool,
        snapshot: Option<String>,
    ) -> Result<Reply> {
        let peer = &self.0;
        let h = &peer.heads;
        if peer.drop_before_publish.replace(false) {
            return Err(Errno::ENOTCONN);
        }
        let key = (r.volume.clone(), r.op_id);
        let hash = sha256(
            &match &snapshot {
                Some(name) => serde_json::to_vec(&(&r, name)),
                None => serde_json::to_vec(&r),
            }
            .unwrap(),
        );
        if let Some((saved, status)) = peer.receipts.borrow().get(&key) {
            if *saved != hash {
                return Err(Errno::EINVAL);
            }
            return match status {
                w::Status::Aborted { errno } => Err(*errno),
                w::Status::Committed(rec) => Ok(Reply::Receipt(rec.clone())),
                _ => Err(Errno::EIO),
            };
        }
        let result = if peer.abort_io.replace(false) {
            Err(Errno::EIO)
        } else if receive {
            let new = peer.reservations.borrow().contains_key(&r.volume);
            h.commit_received_root(&ReceiveCommitRequest {
                op_id: r.op_id,
                volume: r.volume.clone(),
                new_root: r.new_root,
                put_nodes: r.put_nodes,
                put_packs: r.put_packs,
                put_blocks: r.put_blocks,
                committed_at: r.committed_at,
                snapshot_name: snapshot,
                expected_lease: (!new).then_some((
                    r.expected_incarnation,
                    r.expected_fence,
                    r.expected_epoch,
                )),
            })
            .await
        } else {
            if peer.retry_epoch.replace(false) {
                let mut concurrent = r.clone();
                concurrent.op_id = [0xee; 16];
                concurrent.new_root = h.read_head(&r.volume).await?.root;
                h.commit_head(&concurrent).await?;
            }
            let current = h.read_head(&r.volume).await?;
            if (current.incarnation, current.fence) != (r.expected_incarnation, r.expected_fence)
                || peer.deadlines.borrow().get(&r.volume).copied().unwrap_or(0) <= peer.time.get()
            {
                Err(Errno::ESTALE)
            } else if current.epoch != r.expected_epoch {
                Err(Errno::EAGAIN)
            } else {
                h.commit_head(&r).await
            }
        };
        let status = match result {
            Ok(head) => w::Status::Committed(w::Receipt {
                op_id: r.op_id,
                payload_hash: hash,
                head,
            }),
            Err(errno) => w::Status::Aborted { errno },
        };
        peer.receipts
            .borrow_mut()
            .insert(key, (hash, status.clone()));
        if peer.lost.replace(false) {
            return Err(Errno::ENOTCONN);
        }
        match status {
            w::Status::Committed(rec) => Ok(Reply::Receipt(rec)),
            w::Status::Aborted { errno } => Err(errno),
            _ => unreachable!(),
        }
    }
    async fn check_fence(&self, volume: &VolumeId, lease: w::Fence) -> Result<()> {
        let reserved = self.0.reservations.borrow().get(volume).copied();
        let current = match reserved {
            Some(f) => f,
            None => w::Fence::from(&self.0.heads.read_head(volume).await?),
        };
        if current != lease
            || self.0.deadlines.borrow().get(volume).copied().unwrap_or(0) <= self.0.time.get()
        {
            return Err(Errno::ESTALE);
        }
        Ok(())
    }
    async fn rpc(&self, r: w::Request) -> Result<Reply> {
        let peer = &self.0;
        let h = &peer.heads;
        let v = &r.volume;
        let now = Timespec {
            sec: peer.time.get(),
            nsec: 0,
        };
        Ok(match r.call {
            Op::Hello { versions } if versions.contains(&w::REMOTE_VOLUME_PROTOCOL) => {
                Reply::Version {
                    version: w::REMOTE_VOLUME_PROTOCOL,
                    tenant: "u1000".into(),
                }
            }
            Op::BeginReceive {} => {
                if h.read_head(v).await.is_ok() || peer.reservations.borrow().contains_key(v) {
                    return Err(Errno::EBUSY);
                }
                let (head, _) = Mount::build_initial_volume_nodes(v.clone(), 0, 0, 0o755, now)?;
                peer.reservations
                    .borrow_mut()
                    .insert(v.clone(), w::Fence::from(&head));
                peer.deadlines.borrow_mut().insert(v.clone(), now.sec + 60);
                Reply::Attached {
                    head,
                    forked_from: None,
                    expires: now.sec + 60,
                }
            }
            Op::FormatVersion {} => Reply::Version {
                version: 1,
                tenant: "u1000".into(),
            },
            Op::CreateVolume { head, nodes } => Reply::Head(h.create_volume(&head, &nodes).await?),
            Op::ReadHead {} => Reply::Head(h.read_head(v).await?),
            Op::AttachRw { mode } => {
                let l = h.acquire_writer(v, mode).await?;
                let reply = Reply::Attached {
                    head: l.head.clone(),
                    forked_from: l.forked_from.clone(),
                    expires: now.sec + 60,
                };
                peer.deadlines
                    .borrow_mut()
                    .insert(l.volume.clone(), now.sec + 60);
                peer.leases.borrow_mut().insert(l.volume.clone(), l);
                reply
            }
            Op::Renew { lease } => {
                self.check_fence(v, lease).await?;
                peer.deadlines.borrow_mut().insert(v.clone(), now.sec + 60);
                Reply::Renewed {
                    expires: now.sec + 60,
                }
            }
            Op::DetachRw { lease } => {
                if peer.reservations.borrow_mut().remove(v).is_some() {
                    return Ok(Reply::Done);
                }
                if w::Fence::from(&h.read_head(v).await?) != lease {
                    return Err(Errno::ESTALE);
                }

                let l = peer.leases.borrow_mut().remove(v).ok_or(Errno::ESTALE)?;
                h.release_writer(l).await?;
                Reply::Done
            }
            Op::GetNode { digest } => {
                wait_while(&peer.hold_nodes).await;
                Reply::Node(h.get_node(&digest).await?)
            }
            Op::LookupBlock { digest } => Reply::Block(h.lookup_block(&digest).await?),
            Op::StageObjects {
                nodes,
                packs,
                blocks,
                lease,
            } => {
                self.check_fence(v, lease).await?;
                peer.stage_batches.set(peer.stage_batches.get() + 1);
                peer.staged_bytes
                    .set(peer.staged_bytes.get() + serde_json::to_vec(&nodes).unwrap().len());
                h.stage_objects(&nodes, &packs, &blocks, now).await?;
                Reply::Done
            }
            Op::Commit { request } => self.publish(request, false, None).await?,
            Op::Receive { request, snapshot } => self.publish(request, true, snapshot).await?,
            Op::Status { op_id, lease } => {
                peer.queries.set(peer.queries.get() + 1);
                if peer.status_offline.get() {
                    return Err(Errno::ENOTCONN);
                }
                let recorded = peer
                    .receipts
                    .borrow()
                    .get(&(v.clone(), op_id))
                    .map(|(_, s)| s.clone());
                let active = peer
                    .leases
                    .borrow()
                    .get(v)
                    .map(|l| w::Fence::from(&l.head))
                    .or_else(|| peer.reservations.borrow().get(v).copied());
                let expired = peer.deadlines.borrow().get(v).copied().unwrap_or(0) <= now.sec;
                Reply::Status(recorded.unwrap_or_else(|| {
                    if lease.is_some() && (lease != active || expired) {
                        w::Status::Aborted {
                            errno: Errno::ESTALE,
                        }
                    } else {
                        w::Status::Pending
                    }
                }))
            }
            Op::PinRo { snapshot, root } => {
                let existing = root.and_then(|root| {
                    peer.pins
                        .borrow()
                        .values()
                        .find(|p| p.head.volume == *v && p.head.root == root && p.expires > now.sec)
                        .map(|p| (p.head.clone(), p.guard.clone()))
                });
                let (head, pin) = match existing {
                    Some(pair) => pair,
                    None => {
                        let (head, pin) = h.pin_ro_root(v, snapshot.as_deref()).await?;
                        if root.is_some_and(|d| d != head.root) {
                            return Err(Errno::ESTALE);
                        }
                        (head, Rc::from(pin))
                    }
                };
                // Multiple pins at one head must remain independently detachable.
                let n = peer.next_pin.get();
                let id = format!("pin{n}");
                peer.next_pin.set(n + 1);
                peer.pins.borrow_mut().insert(
                    id.clone(),
                    ReaderPin {
                        guard: pin,
                        head: head.clone(),
                        expires: now.sec + w::RO_PIN_TTL_SECS,
                    },
                );
                Reply::Pinned {
                    head,
                    pin_id: id,
                    expires: now.sec + w::RO_PIN_TTL_SECS,
                }
            }
            Op::RenewRo { pin_id } => {
                let mut pins = peer.pins.borrow_mut();
                let pin = pins.get_mut(&pin_id).ok_or(Errno::ESTALE)?;
                pin.expires = now.sec + w::RO_PIN_TTL_SECS;
                Reply::Renewed {
                    expires: now.sec + w::RO_PIN_TTL_SECS,
                }
            }
            Op::UnpinRo { pin_id } => {
                peer.pins.borrow_mut().remove(&pin_id);
                Reply::Done
            }
            Op::CreateSnapshot { name, head } => {
                Reply::Snapshot(h.create_snapshot(v, &name, &head, now).await?)
            }
            Op::DeleteSnapshot { name, .. } => {
                h.delete_snapshot(v, &name).await?;
                Reply::Done
            }
            Op::GetSnapshot { name } => Reply::Snapshot(h.get_snapshot(v, &name).await?),
            Op::ListSnapshots {} => Reply::Snapshots(h.list_snapshots(v).await?),
            Op::Fork { request } => {
                if let Some(name) = &request.source_snapshot
                    && h.get_snapshot(v, name).await?.root != request.source_root
                {
                    return Err(Errno::ESTALE);
                }
                Reply::Head(h.fork_volume(&request).await?)
            }
            Op::ListPacks {} => Reply::Packs(peer.packs.list_packs().await?),
            Op::RunGc {} => {
                let r = os_cowfs::collect_garbage(h, &peer.packs, now).await?;
                Reply::Gc(abi::volume::CowfsGcResp {
                    live_roots: r.live_roots,
                    live_nodes: r.live_nodes,
                    live_blocks: r.live_blocks,
                    live_packs: r.live_packs,
                    swept_packs: r.swept_packs.into_iter().map(|p| p.0).collect(),
                })
            }
            _ => return Err(Errno::EOPNOTSUPP),
        })
    }
}
struct Timer {
    id: u64,
    peer: std::rc::Weak<Peer>,
}
impl RenewalGuard for Timer {}
impl Drop for Timer {
    fn drop(&mut self) {
        if let Some(peer) = self.peer.upgrade() {
            peer.timers.borrow_mut().remove(&self.id);
        }
    }
}
impl RemoteVolumeTransport for Transport {
    fn keep_alive(&self, period: u64, renew: Renewal) -> Result<Box<dyn RenewalGuard>> {
        let id = self.0.next_timer.get();
        self.0.next_timer.set(id + 1);
        self.0.timers.borrow_mut().insert(id, (period, renew));
        Ok(Box::new(Timer {
            id,
            peer: Rc::downgrade(&self.0),
        }))
    }
    fn monotonic_seconds(&self) -> u64 {
        self.0.time.get()
    }
    fn fetch<'a>(
        &'a self,
        method: &'a str,
        path: &'a str,
        headers: &'a [(String, String)],
        body: &'a [u8],
    ) -> BoxFuture<'a, RemoteHttpReply> {
        Box::pin(async move {
            if self.0.signed_out.get() {
                return Err(Errno::EACCES);
            }
            if path == "/api/volumes/rpc" {
                return encoded(&self.rpc(serde_json::from_slice(body).unwrap()).await?);
            }
            let id = PackId(path.strip_prefix("/api/volumes/packs/").unwrap().into());
            match method {
                "PUT" => {
                    wait_while(&self.0.hold_upload).await;
                    let header = |name| headers.iter().find(|(k, _)| k == name).unwrap().1.as_str();
                    self.check_fence(
                        &VolumeId(header("X-OS-Volume").into()),
                        w::Fence {
                            incarnation: header("X-OS-Incarnation").parse().unwrap(),
                            fence: header("X-OS-Fence").parse().unwrap(),
                        },
                    )
                    .await?;
                    self.0.puts.set(self.0.puts.get() + 1);
                    encoded(&self.0.packs.write_pack(&id, body).await?)
                }
                "HEAD" => Ok(RemoteHttpReply {
                    status: 200,
                    body: vec![],
                    content_length: self.0.packs.stat_pack(&id).await?,
                }),
                "GET" => {
                    let range = headers.iter().find(|(k, _)| k == "Range").unwrap();
                    let (a, b) =
                        os_core::byte_range(&range.1, self.0.packs.stat_pack(&id).await?.unwrap())
                            .unwrap();
                    let len = (b - a + 1) as u32;
                    assert!(len <= cowtree::EXTENT_MAX_BYTES);
                    self.0.last_range.set(len);
                    Ok(response(
                        206,
                        self.0.packs.read_pack_range(&id, a as u32, len).await?,
                    ))
                }
                _ => Err(Errno::EINVAL),
            }
        })
    }
}
async fn wait_while(held: &Cell<bool>) {
    std::future::poll_fn(|_| {
        if held.get() {
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(())
        }
    })
    .await;
}
impl Peer {
    pub async fn tick(&self, seconds: u64) {
        let now = self.time.get() + seconds;
        self.time.set(now);
        self.pins.borrow_mut().retain(|_, pin| pin.expires > now);
        let due: Vec<_> = self
            .timers
            .borrow()
            .values()
            .filter(|(period, _)| now.is_multiple_of(*period))
            .map(|(_, renew)| renew.clone())
            .collect();
        for renew in due {
            renew().await.unwrap();
        }
    }
    pub fn pin_count(&self) -> usize {
        self.pins.borrow().len()
    }

    pub async fn mount(self: &Rc<Self>, id: &str, mode: CowFsOpenMode, create: bool) -> Rc<Mount> {
        let v = VolumeId(id.to_string());
        let s = Rc::new(RemoteVolumeStore::new(v.clone(), Transport(self.clone())));
        let time = self.clone();
        let clock: os_cowfs::CowFsClock = Rc::new(move || Timespec {
            sec: time.time.get(),
            nsec: 0,
        });
        if create {
            CowFs::format_volume(&*s, &*s, v.clone(), 0, 0, 0o1777, clock())
                .await
                .unwrap();
        }
        Rc::new(
            CowFs::open(s.clone(), s, v, mode, CowFsConfig::remote(clock))
                .await
                .unwrap(),
        )
    }
}

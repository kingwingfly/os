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
#[derive(Default)]
pub struct Peer {
    pub heads: MemoryHeadStore,
    pub packs: MemoryPackStore,
    leases: RefCell<HashMap<VolumeId, WriterLease>>,
    pins: RefCell<HashMap<String, Box<dyn RoPinGuard>>>,
    receipts: RefCell<HashMap<[u8; 16], w::Receipt>>,
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
    async fn rpc(&self, r: w::Request) -> Result<Reply> {
        let peer = &self.0;
        let h = &peer.heads;
        let v = &r.volume;
        let now = Timespec {
            sec: peer.time.get(),
            nsec: 0,
        };
        Ok(match r.call {
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
                peer.leases.borrow_mut().insert(l.volume.clone(), l);
                reply
            }
            Op::Renew { lease } => {
                if w::Fence::from(&h.read_head(v).await?) != lease {
                    return Err(Errno::ESTALE);
                }
                Reply::Renewed {
                    expires: now.sec + 60,
                }
            }
            Op::DetachRw { .. } => {
                let l = peer.leases.borrow_mut().remove(v).ok_or(Errno::ESTALE)?;
                h.release_writer(l).await?;
                Reply::Done
            }
            Op::GetNode { digest } => Reply::Node(h.get_node(&digest).await?),
            Op::LookupBlock { digest } => Reply::Block(h.lookup_block(&digest).await?),
            Op::StageObjects {
                nodes,
                packs,
                blocks,
                ..
            } => {
                h.stage_objects(&nodes, &packs, &blocks, now).await?;
                Reply::Done
            }
            Op::Commit { request } => {
                if peer.retry_epoch.replace(false) {
                    return Err(Errno::EAGAIN);
                }
                let head = h.commit_head(&request).await?;
                let receipt = w::Receipt {
                    op_id: request.op_id,
                    payload_hash: sha256(&serde_json::to_vec(&request).unwrap()),
                    head,
                };
                peer.receipts
                    .borrow_mut()
                    .insert(request.op_id, receipt.clone());
                if peer.lost.replace(false) {
                    return Err(Errno::EIO);
                }
                Reply::Receipt(receipt)
            }
            Op::Status { op_id } => {
                peer.queries.set(peer.queries.get() + 1);
                Reply::Status(
                    peer.receipts
                        .borrow()
                        .get(&op_id)
                        .cloned()
                        .map_or(w::Status::Pending, w::Status::Committed),
                )
            }
            Op::PinRo { snapshot } => {
                let (head, pin) = h.pin_ro_root(v, snapshot.as_deref()).await?;
                // Multiple pins at one head must remain independently detachable.
                let id = (0..)
                    .map(|n| format!("pin{n}"))
                    .find(|id| !peer.pins.borrow().contains_key(id))
                    .unwrap();
                peer.pins.borrow_mut().insert(id.clone(), pin);
                Reply::Pinned { head, pin_id: id }
            }
            Op::RenewRo { pin_id } => {
                if !peer.pins.borrow().contains_key(&pin_id) {
                    return Err(Errno::ESTALE);
                }
                Reply::Done
            }
            Op::UnpinRo { pin_id } => {
                let pin = peer
                    .pins
                    .borrow_mut()
                    .remove(&pin_id)
                    .ok_or(Errno::ESTALE)?;
                h.unpin_ro_root(pin).await?;
                Reply::Done
            }
            Op::CreateSnapshot { name, head } => {
                Reply::Snapshot(h.create_snapshot(v, &name, &head, now).await?)
            }
            Op::GetSnapshot { name } => Reply::Snapshot(h.get_snapshot(v, &name).await?),
            Op::ListSnapshots {} => Reply::Snapshots(h.list_snapshots(v).await?),
            Op::Fork { request } => Reply::Head(h.fork_volume(&request).await?),
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
impl RemoteVolumeTransport for Transport {
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
            if path == "/api/volumes/rpc" {
                return encoded(&self.rpc(serde_json::from_slice(body).unwrap()).await?);
            }
            let id = PackId(path.strip_prefix("/api/volumes/packs/").unwrap().into());
            match method {
                "PUT" => {
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
impl Peer {
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

//! `wasm-bindgen` bridge for `AF_UNIX` sockets, `SCM_RIGHTS`, `SO_PEERCRED`, and the
//! instance-wide `SockArena` slot pool (`#55` L3b, `docs/architecture/contract.md` §2.8).
//!
//! All `#[wasm_bindgen]` socket exports live here so `crates/client-kernel/src/lib.rs` stays
//! minimal and disjoint across Wave 4 tracks.

use crate::Kernel;
use crate::vfs_engine::{json_to_js, map_errno, vfs_js_err};
use abi::socket::{PeerCred, validate_unix_path};
use abi::{Call, Errno, FdRef};
use serde::Deserialize;
use serde_json::{Value, json};
use std::rc::Rc;
use vfs::StartAnchor;
use vfs::unix_sock::{
    ArenaSlot, CleanupBatch, InFlightFd, PipeEnd, SockId, SockType, SocketInodeKey,
};
use wasm_bindgen::prelude::*;

/// Deferred JS-side socket cleanup buffered when a process is torn down via `kill(pid, 9)` /
/// `cgroup.kill` (`vfs_process_exit_cleanup` / `proc_exit`) before `exec.mjs` calls
/// `sock_release_process(pid)`. Drained and applied via `applySockCleanup` so peer SAB rings
/// never hang, freed arena slots are always fenced, and queued PTY/ArenaPipe handles never leak.
#[derive(Default)]
pub(crate) struct PendingSockCleanup {
    pub(crate) freed_slots: Vec<ArenaSlot>,
    pub(crate) peer_wr_closed: Vec<ArenaSlot>,
    pub(crate) peer_rd_closed: Vec<ArenaSlot>,
    pub(crate) dropped_ptys: Vec<Value>,
    pub(crate) dropped_pipes: Vec<Value>,
}

const B64_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = if chunk.len() > 1 {
            u32::from(chunk[1])
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            u32::from(chunk[2])
        } else {
            0
        };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64_TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            B64_TABLE[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_TABLE[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn b64_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn b64_decode(input: &str) -> Result<Vec<u8>, Errno> {
    let bytes = input.as_bytes();
    let (chunks, rem) = bytes.as_chunks::<4>();
    if !rem.is_empty() {
        return Err(Errno::EINVAL);
    }
    let mut out = Vec::with_capacity(chunks.len() * 3);
    for chunk in chunks {
        let a = b64_val(chunk[0]).ok_or(Errno::EINVAL)?;
        let b = b64_val(chunk[1]).ok_or(Errno::EINVAL)?;
        out.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            let c = b64_val(chunk[2]).ok_or(Errno::EINVAL)?;
            out.push((b << 4) | (c >> 2));
            if chunk[3] != b'=' {
                let d = b64_val(chunk[3]).ok_or(Errno::EINVAL)?;
                out.push((c << 6) | d);
            }
        } else if chunk[3] != b'=' {
            return Err(Errno::EINVAL);
        }
    }
    Ok(out)
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum SendFdSpec {
    Kfd {
        kfd: u32,
        #[serde(default, rename = "isDir")]
        is_dir: bool,
        #[serde(default, rename = "mountNs")]
        mount_ns: bool,
        #[serde(default)]
        device: Option<String>,
        #[serde(default = "default_true")]
        read: bool,
        #[serde(default)]
        writable: bool,
        #[serde(default)]
        append: bool,
        #[serde(default, rename = "pathOnly")]
        path_only: bool,
    },
    ServerDev {
        vfd: u32,
        #[serde(default)]
        device: String,
        #[serde(default = "default_true")]
        read: bool,
        #[serde(default)]
        writable: bool,
    },
    UnixSock {
        #[serde(rename = "sockId")]
        sock_id: SockId,
    },
    ArenaPipe {
        slot: u16,
        #[serde(rename = "gen")]
        generation: u32,
        end: String,
    },
    Pty {
        handle: u32,
        #[serde(default)]
        master: bool,
        #[serde(default)]
        number: u32,
        #[serde(default = "default_true")]
        read: bool,
        #[serde(default = "default_true")]
        writable: bool,
    },
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
struct SendMsgReq {
    #[serde(default)]
    data: String,
    #[serde(default)]
    fds: Vec<SendFdSpec>,
    #[serde(default)]
    addr: Option<String>,
    #[serde(default, rename = "sabSpan")]
    sab_span: Option<(u64, u64)>,
}

#[derive(Deserialize)]
struct RecvMsgReq {
    #[serde(rename = "bufLen")]
    buf_len: usize,
    #[serde(default, rename = "maxFds")]
    max_fds: usize,
    #[serde(default)]
    flags: u32,
    #[serde(default, rename = "sabRxTail")]
    sab_rx_tail: Option<u64>,
    #[serde(default, rename = "cmsgCloexec")]
    cmsg_cloexec: bool,
}

fn slot_json(slot: Option<ArenaSlot>) -> Value {
    match slot {
        Some(s) => json!({ "slot": s.slot, "gen": s.generation }),
        None => Value::Null,
    }
}

fn slots_json(slots: &[ArenaSlot]) -> Vec<Value> {
    slots
        .iter()
        .map(|s| json!({ "slot": s.slot, "gen": s.generation }))
        .collect()
}

fn cred_json(cred: PeerCred) -> Value {
    json!({ "pid": cred.pid, "uid": cred.uid, "gid": cred.gid })
}

impl Kernel {
    /// Read authentic `PeerCred` EXCLUSIVELY from `LocalProcessTable` (`U-08`).
    /// Guest Workers can NEVER supply or override `pid`, `uid`, or `gid`.
    pub(crate) fn kernel_peer_cred(&self, pid: u32) -> Result<PeerCred, Errno> {
        let state = self.state.borrow();
        let proc = state.table.proc(pid).ok_or(Errno::ESRCH)?;
        Ok(PeerCred {
            pid: proc.pid,
            uid: proc.cred.identity.id,
            gid: proc.cred.identity.group,
        })
    }

    /// Asynchronously release any non-JS-owned `InFlightFd`s (`VfsFile`, `AttenuatedServerFd`)
    /// discarded during `MSG_CTRUNC`, socket close, process exit, or `unix_gc()`, returning JS
    /// descriptors (`Pty`, `ArenaPipe`) for `exec.mjs` to release.
    pub(crate) async fn dispose_unix_sock_dropped_fds(
        &self,
        dropped: Vec<InFlightFd>,
    ) -> (Vec<Value>, Vec<Value>) {
        let mut dropped_ptys = Vec::new();
        let mut dropped_pipes = Vec::new();
        for fd in dropped {
            match fd {
                InFlightFd::VfsFile {
                    file, origin_pid, ..
                } => {
                    let _ = self.with_proc_scope(origin_pid, file.close()).await;
                }
                InFlightFd::AttenuatedServerFd {
                    sfd,
                    owner_pid,
                    owner_token,
                    ..
                } => {
                    if Rc::strong_count(&sfd) == 1 {
                        let _ = self
                            .forward_server_call_attenuated(
                                owner_pid,
                                &owner_token,
                                Call::Close {
                                    fd: FdRef::Fd(*sfd),
                                },
                            )
                            .await;
                    }
                }
                InFlightFd::Pty {
                    handle,
                    master,
                    number,
                    ..
                } => {
                    dropped_ptys.push(json!({
                        "handle": handle,
                        "master": master,
                        "number": number,
                    }));
                }
                InFlightFd::ArenaPipe {
                    slot,
                    generation,
                    end,
                } => {
                    dropped_pipes.push(json!({
                        "slot": slot,
                        "gen": generation,
                        "end": match end {
                            PipeEnd::Read => "r",
                            PipeEnd::Write => "w",
                        },
                    }));
                }
                InFlightFd::UnixSocket(_) => {}
            }
        }
        (dropped_ptys, dropped_pipes)
    }

    /// Dispose Rust-side dropped fds from `batch` and buffer JS-side SAB/PTY/ArenaPipe cleanup
    /// on `VfsRuntime` so `exec.mjs` can never lose wakeups or leak handles across `SIGKILL`.
    pub(crate) async fn record_unix_sock_cleanup(&self, batch: CleanupBatch) {
        if batch.dropped_fds.is_empty()
            && batch.freed_slots.is_empty()
            && batch.peer_wr_closed.is_empty()
            && batch.peer_rd_closed.is_empty()
        {
            return;
        }
        let (dropped_ptys, dropped_pipes) =
            self.dispose_unix_sock_dropped_fds(batch.dropped_fds).await;
        let mut rt = self.vfs_rt.borrow_mut();
        rt.pending_sock_cleanup
            .freed_slots
            .extend(batch.freed_slots);
        rt.pending_sock_cleanup
            .peer_wr_closed
            .extend(batch.peer_wr_closed);
        rt.pending_sock_cleanup
            .peer_rd_closed
            .extend(batch.peer_rd_closed);
        rt.pending_sock_cleanup.dropped_ptys.extend(dropped_ptys);
        rt.pending_sock_cleanup.dropped_pipes.extend(dropped_pipes);
    }

    pub(crate) fn take_pending_sock_cleanup_json(&self) -> Result<JsValue, JsValue> {
        let pending = std::mem::take(&mut self.vfs_rt.borrow_mut().pending_sock_cleanup);
        json_to_js(&json!({
            "freedSlots": slots_json(&pending.freed_slots),
            "peerWrClosed": slots_json(&pending.peer_wr_closed),
            "peerRdClosed": slots_json(&pending.peer_rd_closed),
            "droppedPtys": pending.dropped_ptys,
            "droppedPipes": pending.dropped_pipes,
        }))
    }

    async fn cleanup_batch_json(&self, batch: CleanupBatch) -> Result<JsValue, JsValue> {
        let (dropped_ptys, dropped_pipes) =
            self.dispose_unix_sock_dropped_fds(batch.dropped_fds).await;
        json_to_js(&json!({
            "freedSlots": slots_json(&batch.freed_slots),
            "peerWrClosed": slots_json(&batch.peer_wr_closed),
            "peerRdClosed": slots_json(&batch.peer_rd_closed),
            "droppedPtys": dropped_ptys,
            "droppedPipes": dropped_pipes,
        }))
    }
}

#[wasm_bindgen]
impl Kernel {
    /// Create an unbound `AF_UNIX` socket for `pid`.
    pub fn sock_create(&self, pid: u32, sock_type: u32) -> Result<JsValue, JsValue> {
        let st = SockType::from_raw(sock_type).map_err(map_errno)?;
        let cred = self.kernel_peer_cred(pid).map_err(map_errno)?;
        let sock_id = self
            .vfs_rt
            .borrow()
            .unix_sock
            .borrow_mut()
            .create(pid, st, cred)
            .map_err(map_errno)?;
        json_to_js(&json!({ "sockId": sock_id }))
    }

    /// Create a connected pair of `AF_UNIX` sockets (`socketpair(2)`).
    pub fn sock_socketpair(&self, pid: u32, sock_type: u32) -> Result<JsValue, JsValue> {
        let st = SockType::from_raw(sock_type).map_err(map_errno)?;
        let cred = self.kernel_peer_cred(pid).map_err(map_errno)?;
        let pair = self
            .vfs_rt
            .borrow()
            .unix_sock
            .borrow_mut()
            .socketpair(pid, st, cred)
            .map_err(map_errno)?;
        json_to_js(&json!({
            "sockA": pair.sock_a,
            "sockB": pair.sock_b,
            "slotAB": slot_json(pair.slot_ab),
            "slotBA": slot_json(pair.slot_ba),
        }))
    }

    /// Bind socket `sock_id` to pathname `path` in `pid`'s mount namespace and `chroot`.
    pub async fn sock_bind(
        &self,
        pid: u32,
        sock_id: u32,
        path: String,
    ) -> Result<JsValue, JsValue> {
        validate_unix_path(&path).map_err(map_errno)?;
        let (vfs, unix_sock) = {
            let rt = self.vfs_rt.borrow();
            (rt.vfs.clone(), Rc::clone(&rt.unix_sock))
        };
        // Verify socket exists and is owned by `pid` before creating filesystem inode.
        unix_sock
            .borrow()
            .describe(pid, sock_id)
            .map_err(map_errno)?;

        let entry = self
            .with_proc_scope_retry(pid, || {
                let vfs = vfs.clone();
                let path = path.clone();
                async move { vfs.mksockat(pid, StartAnchor::AtFdCwd, &path, 0o777).await }
            })
            .await
            .map_err(|e| {
                if e == Errno::EEXIST {
                    map_errno(Errno::EADDRINUSE)
                } else {
                    map_errno(e)
                }
            })?;

        let key = SocketInodeKey {
            fs_id: entry.handle.fs.clone(),
            node: entry.handle.node,
        };
        let bind_res = unix_sock.borrow_mut().bind(pid, sock_id, key, path.clone());
        if let Err(err) = bind_res {
            // Roll back the socket inode if binding failed (e.g. socket already bound).
            let _ = self
                .with_proc_scope(pid, vfs.unlinkat(pid, StartAnchor::AtFdCwd, &path, false))
                .await;
            return Err(map_errno(err));
        }
        json_to_js(&json!({
            "ino": entry.handle.node.ino,
            "path": path,
        }))
    }

    /// Mark bound socket `sock_id` as listening.
    pub fn sock_listen(&self, pid: u32, sock_id: u32, backlog: u32) -> Result<JsValue, JsValue> {
        self.vfs_rt
            .borrow()
            .unix_sock
            .borrow_mut()
            .listen(pid, sock_id, backlog)
            .map_err(map_errno)?;
        json_to_js(&json!({ "ok": true }))
    }

    /// Connect socket `sock_id` to `path`, checking DAC + POSIX ACL `W_OK` on the socket inode
    /// and stamping `SO_PEERCRED` strictly from `LocalProcessTable`.
    pub async fn sock_connect(
        &self,
        pid: u32,
        sock_id: u32,
        path: String,
    ) -> Result<JsValue, JsValue> {
        validate_unix_path(&path).map_err(map_errno)?;
        let cred = self.kernel_peer_cred(pid).map_err(map_errno)?;
        let (vfs, unix_sock) = {
            let rt = self.vfs_rt.borrow();
            (rt.vfs.clone(), Rc::clone(&rt.unix_sock))
        };
        let entry = self
            .with_proc_scope_retry(pid, || {
                let vfs = vfs.clone();
                let path = path.clone();
                async move {
                    vfs.resolve_socket_inode(pid, StartAnchor::AtFdCwd, &path)
                        .await
                }
            })
            .await
            .map_err(map_errno)?;
        let key = SocketInodeKey {
            fs_id: entry.handle.fs,
            node: entry.handle.node,
        };
        let res = unix_sock
            .borrow_mut()
            .connect(pid, sock_id, &key, path, cred)
            .map_err(map_errno)?;
        json_to_js(&json!({
            "peerId": res.peer_id,
            "listenerId": res.listener_id,
            "peerCred": cred_json(res.peer_cred),
            "txSlot": slot_json(res.tx_slot),
            "rxSlot": slot_json(res.rx_slot),
        }))
    }

    /// Non-blocking accept step; returns `{ wouldBlock: true }` when accept queue is empty.
    pub fn sock_accept(&self, pid: u32, sock_id: u32) -> Result<JsValue, JsValue> {
        let cred = self.kernel_peer_cred(pid).map_err(map_errno)?;
        let res = self
            .vfs_rt
            .borrow()
            .unix_sock
            .borrow_mut()
            .accept(pid, sock_id, cred);
        match res {
            Ok(acc) => json_to_js(&json!({
                "sockId": acc.sock_id,
                "peerCred": cred_json(acc.peer_cred),
                "txSlot": slot_json(acc.tx_slot),
                "rxSlot": slot_json(acc.rx_slot),
            })),
            Err(Errno::EAGAIN) => json_to_js(&json!({ "wouldBlock": true })),
            Err(e) => Err(map_errno(e)),
        }
    }

    /// Shut down reads, writes, or both on `sock_id`.
    pub fn sock_shutdown(&self, pid: u32, sock_id: u32, how: u32) -> Result<JsValue, JsValue> {
        let res = self
            .vfs_rt
            .borrow()
            .unix_sock
            .borrow_mut()
            .shutdown(pid, sock_id, how)
            .map_err(map_errno)?;
        json_to_js(&json!({
            "txSlot": slot_json(res.tx_slot),
            "rxSlot": slot_json(res.rx_slot),
            "shutRd": res.shut_rd,
            "shutWr": res.shut_wr,
        }))
    }

    /// Add `count` external holder references to `sock_id` for `pid` (`dup`/`fork`/`spawn`).
    pub fn sock_hold(&self, pid: u32, sock_id: u32, count: u32) -> Result<JsValue, JsValue> {
        self.vfs_rt
            .borrow()
            .unix_sock
            .borrow_mut()
            .hold(pid, sock_id, count as usize)
            .map_err(map_errno)?;
        json_to_js(&json!({ "ok": true }))
    }

    /// Close `count` external references to `sock_id` held by `pid`, running `unix_gc()` as needed.
    pub async fn sock_close(&self, pid: u32, sock_id: u32, count: u32) -> Result<JsValue, JsValue> {
        let unix_sock = Rc::clone(&self.vfs_rt.borrow().unix_sock);
        let batch = unix_sock
            .borrow_mut()
            .close(pid, sock_id, count as usize)
            .map_err(map_errno)?;
        self.cleanup_batch_json(batch).await
    }

    /// Release all sockets held by an exiting or crashed process `pid`, merging and draining any
    /// cleanup already buffered by `vfs_process_exit_cleanup` / `proc_exit` (e.g. `SIGKILL`).
    pub async fn sock_release_process(&self, pid: u32) -> Result<JsValue, JsValue> {
        let unix_sock = Rc::clone(&self.vfs_rt.borrow().unix_sock);
        let batch = unix_sock.borrow_mut().release_process(pid);
        self.record_unix_sock_cleanup(batch).await;
        self.take_pending_sock_cleanup_json()
    }

    /// Drain any JS-side socket cleanup buffered during `kill(pid, 9)` / `cgroup.kill` teardown.
    pub fn sock_drain_cleanup(&self) -> Result<JsValue, JsValue> {
        self.take_pending_sock_cleanup_json()
    }

    /// Send payload + optional `SCM_RIGHTS` fds + optional destination path (`sendmsg(2)`).
    pub async fn sock_sendmsg(
        &self,
        pid: u32,
        sock_id: u32,
        req_json: String,
    ) -> Result<JsValue, JsValue> {
        let req: SendMsgReq =
            serde_json::from_str(&req_json).map_err(|_| map_errno(Errno::EINVAL))?;
        let data = if req.data.is_empty() {
            Vec::new()
        } else {
            b64_decode(&req.data).map_err(map_errno)?
        };
        let cred = self.kernel_peer_cred(pid).map_err(map_errno)?;
        let sender_remote_token = self
            .state
            .borrow()
            .table
            .proc(pid)
            .and_then(|p| p.cred.remote.as_ref().map(|r| r.token.clone()));

        let (vfs, unix_sock) = {
            let rt = self.vfs_rt.borrow();
            (rt.vfs.clone(), Rc::clone(&rt.unix_sock))
        };

        // Resolve optional unconnected DGRAM destination via VFS (DAC+ACL W_OK checked!).
        let dest_key = if let Some(ref path) = req.addr {
            validate_unix_path(path).map_err(map_errno)?;
            let entry = self
                .with_proc_scope_retry(pid, || {
                    let vfs = vfs.clone();
                    let path = path.clone();
                    async move {
                        vfs.resolve_socket_inode(pid, StartAnchor::AtFdCwd, &path)
                            .await
                    }
                })
                .await
                .map_err(map_errno)?;
            Some(SocketInodeKey {
                fs_id: entry.handle.fs,
                node: entry.handle.node,
            })
        } else {
            None
        };

        // Atomically validate and resolve EVERY fd in `req.fds` BEFORE modifying any state!
        let mut inflight = Vec::with_capacity(req.fds.len());
        for spec in req.fds {
            match spec {
                SendFdSpec::Kfd {
                    kfd,
                    is_dir,
                    mount_ns,
                    device,
                    read,
                    writable,
                    append,
                    path_only,
                } => {
                    let file = vfs.get_file(pid, kfd).map_err(map_errno)?;
                    let (origin_pid, origin_token) = {
                        let rt = self.vfs_rt.borrow();
                        rt.proc_meta
                            .get(&pid)
                            .and_then(|m| m.attenuated_kfds.get(&kfd).cloned())
                            .unwrap_or_else(|| (pid, sender_remote_token.clone()))
                    };
                    inflight.push(InFlightFd::VfsFile {
                        file,
                        origin_pid,
                        origin_token,
                        is_dir,
                        mount_ns,
                        device,
                        read,
                        writable,
                        append,
                        path_only,
                    });
                }
                SendFdSpec::ServerDev {
                    vfd,
                    device,
                    read,
                    writable,
                } => {
                    let (sfd, att) = {
                        let rt = self.vfs_rt.borrow();
                        let entry = rt
                            .proc_meta
                            .get(&pid)
                            .and_then(|m| m.server_fds.get(&vfd))
                            .filter(|e| !e.closing)
                            .ok_or_else(|| map_errno(Errno::EBADF))?;
                        (Rc::clone(&entry.sfd), entry.attenuated_token.clone())
                    };
                    let (owner_pid, owner_token) = match att {
                        Some(pair) => pair,
                        None => (
                            pid,
                            sender_remote_token
                                .clone()
                                .ok_or_else(|| map_errno(Errno::EACCES))?,
                        ),
                    };
                    inflight.push(InFlightFd::AttenuatedServerFd {
                        sfd,
                        owner_pid,
                        owner_token,
                        device,
                        readable: read,
                        writable,
                    });
                }
                SendFdSpec::UnixSock { sock_id: pass_id } => {
                    unix_sock
                        .borrow()
                        .describe(pid, pass_id)
                        .map_err(map_errno)?;
                    inflight.push(InFlightFd::UnixSocket(pass_id));
                }
                SendFdSpec::ArenaPipe {
                    slot,
                    generation,
                    end,
                } => {
                    let pipe_end = match end.as_str() {
                        "r" => PipeEnd::Read,
                        "w" => PipeEnd::Write,
                        _ => return Err(map_errno(Errno::EINVAL)),
                    };
                    if !unix_sock
                        .borrow()
                        .is_arena_slot_live(ArenaSlot { slot, generation })
                    {
                        return Err(map_errno(Errno::EBADF));
                    }
                    inflight.push(InFlightFd::ArenaPipe {
                        slot,
                        generation,
                        end: pipe_end,
                    });
                }
                SendFdSpec::Pty {
                    handle,
                    master,
                    number,
                    read,
                    writable,
                } => {
                    inflight.push(InFlightFd::Pty {
                        handle,
                        master,
                        number,
                        readable: read,
                        writable,
                    });
                }
            }
        }

        let outcome = unix_sock
            .borrow_mut()
            .sendmsg(
                pid,
                sock_id,
                &data,
                inflight,
                dest_key.as_ref(),
                cred,
                req.sab_span,
            )
            .map_err(map_errno)?;

        json_to_js(&json!({
            "sent": outcome.sent,
            "targetId": outcome.target_id,
            "targetRxSlot": slot_json(outcome.target_rx_slot),
            "hasAncillary": outcome.has_ancillary,
            "headAncillaryOffset": outcome.head_ancillary_offset,
        }))
    }

    /// Receive payload + optional `SCM_RIGHTS` fds (`recvmsg(2)`).
    /// Returns `{ wouldBlock: true }` on `EAGAIN`.
    pub async fn sock_recvmsg(
        &self,
        pid: u32,
        sock_id: u32,
        req_json: String,
    ) -> Result<JsValue, JsValue> {
        let req: RecvMsgReq =
            serde_json::from_str(&req_json).map_err(|_| map_errno(Errno::EINVAL))?;
        let (vfs, unix_sock) = {
            let rt = self.vfs_rt.borrow();
            (rt.vfs.clone(), Rc::clone(&rt.unix_sock))
        };

        let outcome = match unix_sock.borrow_mut().recvmsg(
            pid,
            sock_id,
            req.buf_len,
            req.max_fds,
            req.flags,
            req.sab_rx_tail,
        ) {
            Ok(o) => o,
            Err(Errno::EAGAIN) => return json_to_js(&json!({ "wouldBlock": true })),
            Err(e) => return Err(map_errno(e)),
        };

        let (receiver_cloud_access, receiver_remote_token) = {
            let state = self.state.borrow();
            match state.table.proc(pid) {
                Some(p) => (
                    p.cred.cloud_access,
                    p.cred.remote.as_ref().map(|r| r.token.clone()),
                ),
                None => (false, None),
            }
        };

        let mut out_flags = outcome.out_flags;
        let mut installed_fds = Vec::with_capacity(outcome.fds.len());
        let mut extra_dropped = outcome.dropped_fds;
        let mut extra_freed = outcome.freed_slots;

        for fd in outcome.fds {
            match fd {
                InFlightFd::VfsFile {
                    file,
                    origin_pid,
                    origin_token,
                    is_dir,
                    mount_ns,
                    device,
                    read,
                    writable,
                    append,
                    path_only,
                } => {
                    let is_cloud_file = file
                        .mount_pin()
                        .is_some_and(|p| p.fstype() == vfs::FsType::Cloud);
                    match vfs.insert_file(pid, file.clone(), req.cmsg_cloexec) {
                        Ok(new_kfd) => {
                            let same_token =
                                receiver_cloud_access && receiver_remote_token == origin_token;
                            let needs_attenuation = is_cloud_file && !same_token;
                            if needs_attenuation {
                                let mut rt = self.vfs_rt.borrow_mut();
                                let meta = rt.proc_meta.entry(pid).or_insert_with(|| {
                                    crate::vfs_engine::ProcessVfsMeta::new(None, false)
                                });
                                meta.attenuated_kfds
                                    .insert(new_kfd, (origin_pid, origin_token.clone()));
                            }
                            let scope_pid = if needs_attenuation { origin_pid } else { pid };
                            let st_val = self
                                .with_proc_scope(scope_pid, vfs.fstat(pid, new_kfd))
                                .await
                                .ok()
                                .map(|st| json!(st))
                                .unwrap_or(Value::Null);
                            installed_fds.push(json!({
                                "kind": "kfd",
                                "kfd": new_kfd,
                                "isDir": is_dir,
                                "mountNs": mount_ns,
                                "device": device,
                                "read": read,
                                "writable": writable,
                                "append": append,
                                "pathOnly": path_only,
                                "stat": st_val,
                            }));
                        }
                        Err(_) => {
                            out_flags |= abi::socket::MSG_CTRUNC;
                            extra_dropped.push(InFlightFd::VfsFile {
                                file,
                                origin_pid,
                                origin_token,
                                is_dir,
                                mount_ns,
                                device,
                                read,
                                writable,
                                append,
                                path_only,
                            });
                        }
                    }
                }
                InFlightFd::AttenuatedServerFd {
                    sfd,
                    owner_pid,
                    owner_token,
                    device,
                    readable,
                    writable,
                } => {
                    let alloc = {
                        let mut rt = self.vfs_rt.borrow_mut();
                        let meta = rt
                            .proc_meta
                            .entry(pid)
                            .or_insert_with(|| crate::vfs_engine::ProcessVfsMeta::new(None, false));
                        meta.alloc_server_fd_with_attenuation(
                            Rc::clone(&sfd),
                            req.cmsg_cloexec,
                            Some((owner_pid, owner_token.clone())),
                        )
                    };
                    match alloc {
                        Ok(vfd) => {
                            installed_fds.push(json!({
                                "kind": "server_dev",
                                "kfd": vfd,
                                "device": device,
                                "read": readable,
                                "writable": writable,
                            }));
                        }
                        Err(_) => {
                            out_flags |= abi::socket::MSG_CTRUNC;
                            extra_dropped.push(InFlightFd::AttenuatedServerFd {
                                sfd,
                                owner_pid,
                                owner_token,
                                device,
                                readable,
                                writable,
                            });
                        }
                    }
                }
                InFlightFd::UnixSocket(recv_sock_id) => {
                    match unix_sock.borrow().describe(pid, recv_sock_id) {
                        Ok((st, tx, rx)) => {
                            installed_fds.push(json!({
                                "kind": "unix_sock",
                                "sockId": recv_sock_id,
                                "sockType": st.to_raw(),
                                "txSlot": slot_json(tx),
                                "rxSlot": slot_json(rx),
                            }));
                        }
                        Err(_) => {
                            out_flags |= abi::socket::MSG_CTRUNC;
                            if let Ok(b) = unix_sock.borrow_mut().close(pid, recv_sock_id, 1) {
                                extra_freed.extend(b.freed_slots);
                                extra_dropped.extend(b.dropped_fds);
                            }
                        }
                    }
                }
                InFlightFd::ArenaPipe {
                    slot,
                    generation,
                    end,
                } => {
                    installed_fds.push(json!({
                        "kind": "arena_pipe",
                        "slot": slot,
                        "gen": generation,
                        "end": match end {
                            PipeEnd::Read => "r",
                            PipeEnd::Write => "w",
                        },
                    }));
                }
                InFlightFd::Pty {
                    handle,
                    master,
                    number,
                    readable,
                    writable,
                } => {
                    installed_fds.push(json!({
                        "kind": "pty",
                        "handle": handle,
                        "master": master,
                        "number": number,
                        "read": readable,
                        "writable": writable,
                    }));
                }
            }
        }

        let (dropped_ptys, dropped_pipes) = self.dispose_unix_sock_dropped_fds(extra_dropped).await;

        // Re-read current ancillary queue head AFTER all awaits so JS updates the shared ring
        // atomically without ever clobbering a concurrent `sendmsg` mark (`U-05`).
        let (has_next_ancillary, next_ancillary_offset, rx_slot) = {
            let table = unix_sock.borrow();
            let head = table.head_ancillary_offset(sock_id);
            (head.is_some(), head.unwrap_or(0), table.rx_slot(sock_id))
        };

        json_to_js(&json!({
            "data": b64_encode(&outcome.data),
            "fds": installed_fds,
            "peerCred": cred_json(outcome.peer_cred),
            "senderPath": outcome.sender_path,
            "flags": out_flags,
            "maxStreamBytes": outcome.max_stream_bytes,
            "rxSlot": slot_json(rx_slot),
            "hasNextAncillary": has_next_ancillary,
            "nextAncillaryOffset": next_ancillary_offset,
            "freedSlots": slots_json(&extra_freed),
            "droppedPtys": dropped_ptys,
            "droppedPipes": dropped_pipes,
        }))
    }

    /// Query kernel-authenticated `SO_PEERCRED` for `sock_id`.
    pub fn sock_peercred(&self, pid: u32, sock_id: u32) -> Result<JsValue, JsValue> {
        let cred = self
            .vfs_rt
            .borrow()
            .unix_sock
            .borrow()
            .peer_cred(pid, sock_id)
            .map_err(map_errno)?;
        json_to_js(&cred_json(cred))
    }

    /// Query local bound socket pathname (`getsockname(2)`).
    pub fn sock_getsockname(&self, pid: u32, sock_id: u32) -> Result<String, JsValue> {
        self.vfs_rt
            .borrow()
            .unix_sock
            .borrow()
            .getsockname(pid, sock_id)
            .map_err(map_errno)
    }

    /// Query peer bound socket pathname (`getpeername(2)`).
    pub fn sock_getpeername(&self, pid: u32, sock_id: u32) -> Result<String, JsValue> {
        self.vfs_rt
            .borrow()
            .unix_sock
            .borrow()
            .getpeername(pid, sock_id)
            .map_err(map_errno)
    }

    /// Query integer socket option (`SOL_SOCKET`).
    pub fn sock_getsockopt(
        &self,
        pid: u32,
        sock_id: u32,
        level: u32,
        optname: u32,
    ) -> Result<i32, JsValue> {
        self.vfs_rt
            .borrow()
            .unix_sock
            .borrow_mut()
            .getsockopt(pid, sock_id, level, optname)
            .map_err(map_errno)
    }

    /// Set integer socket option (`SOL_SOCKET`).
    pub fn sock_setsockopt(
        &self,
        pid: u32,
        sock_id: u32,
        level: u32,
        optname: u32,
        val: i32,
    ) -> Result<(), JsValue> {
        self.vfs_rt
            .borrow()
            .unix_sock
            .borrow_mut()
            .setsockopt(pid, sock_id, level, optname, val)
            .map_err(map_errno)
    }

    /// Query `poll_oneoff` readiness for `sock_id`.
    pub fn sock_poll(&self, pid: u32, sock_id: u32, writing: bool) -> Result<JsValue, JsValue> {
        let status = self
            .vfs_rt
            .borrow()
            .unix_sock
            .borrow()
            .poll(pid, sock_id, writing)
            .map_err(map_errno)?;
        json_to_js(&json!({
            "ready": status.ready,
            "nbytes": status.nbytes,
            "hangup": status.hangup,
        }))
    }

    /// Allocate one slot in the shared `SockArena` for an arena-backed `fd_pipe`.
    pub fn sock_arena_alloc_pipe(&self) -> Result<JsValue, JsValue> {
        let slot = self
            .vfs_rt
            .borrow()
            .unix_sock
            .borrow_mut()
            .alloc_pipe_slot()
            .map_err(map_errno)?;
        json_to_js(&json!({ "slot": slot.slot, "gen": slot.generation }))
    }

    /// Free an arena-backed `fd_pipe` slot when both pipe ends have closed.
    pub fn sock_arena_free_pipe(&self, slot: u16, generation: u32) -> Result<JsValue, JsValue> {
        let freed = self
            .vfs_rt
            .borrow()
            .unix_sock
            .borrow_mut()
            .free_pipe_slot(ArenaSlot { slot, generation });
        match freed {
            Some(next) => {
                json_to_js(&json!({ "freed": true, "slot": next.slot, "gen": next.generation }))
            }
            None => json_to_js(&json!({ "freed": false })),
        }
    }

    /// Diagnostic counters for leak verification (`U-11`).
    pub fn sock_stats(&self) -> Result<JsValue, JsValue> {
        let s = self.vfs_rt.borrow().unix_sock.borrow().stats();
        json_to_js(&json!({
            "activeSockets": s.active_sockets,
            "boundInodes": s.bound_inodes,
            "inflightGlobal": s.inflight_global,
            "allocatedArenaSlots": s.allocated_arena_slots,
        }))
    }

    /// Helper to validate `Errno` error propagation from bridge tests.
    pub fn sock_error_check(&self, code: &str) -> Result<JsValue, JsValue> {
        match code {
            "EADDRINUSE" => Err(vfs_js_err(Errno::EADDRINUSE, "")),
            _ => json_to_js(&json!({ "ok": true })),
        }
    }
}

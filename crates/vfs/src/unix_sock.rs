//! Portable pure-Rust `AF_UNIX` local IPC state machine (`#55` L3b,
//! `docs/architecture/contract.md` §2.8).
//!
//! Zero DOM, zero `web-sys`, zero `wasm-bindgen`: testable natively under `cargo test -p os-vfs`
//! and used directly by `crates/client-kernel` (`unix_sock_bridge.rs`) and future `os-native`.
//!
//! Covers:
//! - `SOCK_STREAM`, `SOCK_DGRAM`, and `SOCK_SEQPACKET`
//! - Inode-keyed `(FsId, NodeId)` bindings so `unlink(2)` detaches paths while preserving active
//!   listeners/connections and allowing immediate re-`bind(2)` on the same path
//! - Kernel-stamped `SO_PEERCRED` (`PeerCred` populated exclusively from `LocalProcessTable`)
//! - `SCM_RIGHTS` fd passing (local files, `CloudFs` open refs, arena pipes, PTYs, Unix sockets,
//!   attenuated single-fd remote devices) with atomic validation, `SOCK_STREAM` byte-offset
//!   ancillary boundary splitting, `MSG_CTRUNC` on receiver `FD_MAX`, per-user/global in-flight
//!   quotas (`256` / `512`), and mark-and-sweep `unix_gc()` cycle reclamation
//! - `SockArena` 128-slot ring allocator with generation fencing on slot reuse

use abi::Errno;
use abi::fs::{FsId, NodeId};
use abi::socket::{
    MAX_INFLIGHT_FDS_GLOBAL, MAX_INFLIGHT_FDS_PER_USER, MSG_CTRUNC, MSG_PEEK, MSG_TRUNC, PeerCred,
    SCM_MAX_FD, SHUT_RD, SHUT_RDWR, SHUT_WR, SO_ACCEPTCONN, SO_ERROR, SO_PASSCRED, SO_TYPE,
    SOCK_DGRAM, SOCK_SEQPACKET, SOCK_STREAM, SOL_SOCKET, UNIX_DGRAM_MAX, UNIX_MAX_QUEUED_BYTES,
    UNIX_MAX_QUEUED_MSGS, UNIX_SOCK_MAX, UNIX_SOMAXCONN, validate_unix_path,
};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::rc::Rc;

use crate::{FileRef, Result};

/// Opaque kernel socket identifier within an OS instance.
pub type SockId = u32;
/// Slot index inside the instance-wide `8 MiB` `SockArena` SAB (`0..128`).
pub type ArenaSlotId = u16;

/// Number of 64 KiB slots in the instance-wide `SockArena` SAB (`128 * 64 KiB = 8 MiB`).
pub const ARENA_SLOTS: usize = 128;

/// Socket type supported on `AF_UNIX`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SockType {
    Stream,
    Dgram,
    Seqpacket,
}

impl SockType {
    pub fn from_raw(raw: u32) -> Result<Self> {
        match raw {
            SOCK_STREAM => Ok(Self::Stream),
            SOCK_DGRAM => Ok(Self::Dgram),
            SOCK_SEQPACKET => Ok(Self::Seqpacket),
            _ => Err(Errno::EPROTOTYPE),
        }
    }

    pub fn to_raw(self) -> u32 {
        match self {
            Self::Stream => SOCK_STREAM,
            Self::Dgram => SOCK_DGRAM,
            Self::Seqpacket => SOCK_SEQPACKET,
        }
    }
}

/// Direction of an arena-backed pipe end carried over `SCM_RIGHTS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PipeEnd {
    Read,
    Write,
}

/// Filesystem inode key identifying a bound Unix-domain socket regardless of mount path or chroot.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SocketInodeKey {
    pub fs_id: FsId,
    pub node: NodeId,
}

/// Allocated `SockArena` slot with generation counter fenced on slot reuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArenaSlot {
    pub slot: ArenaSlotId,
    pub generation: u32,
}

/// One open file description queued inside an `SCM_RIGHTS` ancillary control message.
pub enum InFlightFd {
    /// Local (`cowfs`/`tmpfs`/`hostfs`/`devfs`/`procfs`) OR remote `CloudFs` open description.
    /// `origin_pid` / `origin_token` record the sender's remote scope so an attenuated receiver
    /// may perform I/O on this exact open reference without gaining broader cloud scope.
    VfsFile {
        file: FileRef,
        origin_pid: u32,
        origin_token: Option<String>,
        is_dir: bool,
        mount_ns: bool,
        device: Option<String>,
        read: bool,
        writable: bool,
        append: bool,
        path_only: bool,
    },
    /// Another `AF_UNIX` socket (tracked by mark-and-sweep `unix_gc()` cycle collector!).
    UnixSocket(SockId),
    /// Arena-backed pipe end (zero-copy across unrelated Workers via shared `SockArena` SAB).
    ArenaPipe {
        slot: ArenaSlotId,
        generation: u32,
        end: PipeEnd,
    },
    /// Local PTY master/slave handle owned by `PtyDevices`.
    Pty {
        handle: u32,
        master: bool,
        number: u32,
        readable: bool,
        writable: bool,
    },
    /// Single-fd attenuated remote device transfer: grants ONLY `pread`/`pwrite`/`ioctl`/`close`
    /// on this exact `sfd` while the originating `ServiceAuth v2` token remains unrevoked;
    /// NEVER grants broader scope.
    AttenuatedServerFd {
        sfd: Rc<u32>,
        owner_pid: u32,
        owner_token: String,
        device: String,
        readable: bool,
        writable: bool,
    },
}

/// Ancillary `SCM_RIGHTS` attachment anchored to a byte span `[start_offset, end_offset)` in a
/// `SOCK_STREAM` byte stream so reads never coalesce bytes across `SCM_RIGHTS` boundaries.
pub struct AncillaryMark {
    pub start_offset: u64,
    pub end_offset: u64,
    pub fds: Vec<InFlightFd>,
    pub sender_cred: PeerCred,
    pub sender_uid: u32,
}

/// Discrete packet queued on `SOCK_DGRAM` or `SOCK_SEQPACKET`.
pub struct PacketMsg {
    pub data: Vec<u8>,
    pub fds: Vec<InFlightFd>,
    pub sender_cred: PeerCred,
    pub sender_uid: u32,
    pub sender_path: Option<String>,
}

/// Result of `connect()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectResult {
    pub peer_id: SockId,
    pub listener_id: Option<SockId>,
    pub peer_cred: PeerCred,
    pub tx_slot: Option<ArenaSlot>,
    pub rx_slot: Option<ArenaSlot>,
}

/// Result of `accept()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptResult {
    pub sock_id: SockId,
    pub peer_cred: PeerCred,
    pub tx_slot: Option<ArenaSlot>,
    pub rx_slot: Option<ArenaSlot>,
}

/// Result of `socketpair()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PairResult {
    pub sock_a: SockId,
    pub sock_b: SockId,
    pub slot_ab: Option<ArenaSlot>,
    pub slot_ba: Option<ArenaSlot>,
}

/// Result of `shutdown()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShutdownResult {
    pub tx_slot: Option<ArenaSlot>,
    pub rx_slot: Option<ArenaSlot>,
    pub shut_rd: bool,
    pub shut_wr: bool,
}

/// Readiness snapshot returned by `poll()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PollStatus {
    pub ready: bool,
    pub nbytes: usize,
    pub hangup: bool,
}

/// Outcome of `sendmsg()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendOutcome {
    pub sent: usize,
    pub target_id: SockId,
    pub target_rx_slot: Option<ArenaSlot>,
    pub has_ancillary: bool,
    pub head_ancillary_offset: u64,
}

/// Outcome of `recvmsg()`.
pub struct RecvOutcome {
    pub data: Vec<u8>,
    pub fds: Vec<InFlightFd>,
    pub dropped_fds: Vec<InFlightFd>,
    pub peer_cred: PeerCred,
    pub sender_path: Option<String>,
    pub out_flags: u32,
    /// For `SOCK_STREAM` SAB mode: maximum bytes JS may read from `rx_slot` for this call
    /// without crossing the next `SCM_RIGHTS` ancillary boundary (`None` = unbounded).
    pub max_stream_bytes: Option<usize>,
    pub has_next_ancillary: bool,
    pub next_ancillary_offset: u64,
    pub freed_slots: Vec<ArenaSlot>,
}

/// Cleanup items produced when sockets or cycles are reclaimed.
#[derive(Default)]
pub struct CleanupBatch {
    pub freed_slots: Vec<ArenaSlot>,
    pub dropped_fds: Vec<InFlightFd>,
    /// Peer `ArenaSlot`s that should be marked `WR_CLOSED` (we closed our tx end).
    pub peer_wr_closed: Vec<ArenaSlot>,
    /// Peer `ArenaSlot`s that should be marked `RD_CLOSED` (we closed our rx end).
    pub peer_rd_closed: Vec<ArenaSlot>,
}

/// Diagnostic counts for leak testing (`U-11`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SocketStats {
    pub active_sockets: usize,
    pub bound_inodes: usize,
    pub inflight_global: usize,
    pub allocated_arena_slots: usize,
}

#[derive(Clone, Copy, Debug)]
struct ArenaEntry {
    allocated: bool,
    generation: u32,
}

/// Fixed 128-slot `SockArena` allocator with generation fencing.
struct ArenaPool {
    slots: Vec<ArenaEntry>,
    allocated_count: usize,
    next_cursor: usize,
}

impl ArenaPool {
    fn new() -> Self {
        Self {
            slots: vec![
                ArenaEntry {
                    allocated: false,
                    generation: 1,
                };
                ARENA_SLOTS
            ],
            allocated_count: 0,
            next_cursor: 0,
        }
    }

    fn alloc(&mut self) -> Result<ArenaSlot> {
        if self.allocated_count >= ARENA_SLOTS {
            return Err(Errno::ENOBUFS);
        }
        for i in 0..ARENA_SLOTS {
            let idx = (self.next_cursor + i) % ARENA_SLOTS;
            if !self.slots[idx].allocated {
                self.slots[idx].allocated = true;
                self.slots[idx].generation = self.slots[idx].generation.wrapping_add(1).max(1);
                self.allocated_count += 1;
                self.next_cursor = (idx + 1) % ARENA_SLOTS;
                return Ok(ArenaSlot {
                    slot: idx as ArenaSlotId,
                    generation: self.slots[idx].generation,
                });
            }
        }
        Err(Errno::ENOBUFS)
    }

    fn free(&mut self, slot: ArenaSlot) -> Option<ArenaSlot> {
        let entry = self.slots.get_mut(slot.slot as usize)?;
        if !entry.allocated || entry.generation != slot.generation {
            return None;
        }
        entry.allocated = false;
        entry.generation = entry.generation.wrapping_add(1).max(1);
        self.allocated_count = self.allocated_count.saturating_sub(1);
        Some(ArenaSlot {
            slot: slot.slot,
            generation: entry.generation,
        })
    }

    fn is_live(&self, slot: ArenaSlot) -> bool {
        self.slots
            .get(slot.slot as usize)
            .is_some_and(|e| e.allocated && e.generation == slot.generation)
    }

    fn allocated_count(&self) -> usize {
        self.allocated_count
    }
}

enum SockState {
    Unbound,
    Bound,
    Listening {
        backlog: usize,
        pending: VecDeque<SockId>,
    },
    Connected {
        peer: Option<SockId>,
        peer_cred: PeerCred,
        peer_path: Option<String>,
        tx_slot: Option<ArenaSlot>,
        rx_slot: Option<ArenaSlot>,
        /// Pure-Rust stream buffer (used in native unit tests; SAB mode leaves this empty).
        stream_buf: VecDeque<u8>,
        /// Total stream bytes enqueued into this socket's recv queue (pure-Rust mode).
        stream_enqueued: u64,
        /// Total stream bytes read from this socket's recv queue (pure-Rust mode).
        stream_read: u64,
        /// Ancillary `SCM_RIGHTS` marks anchored to stream byte spans.
        ancillary: VecDeque<AncillaryMark>,
        /// Discrete packet queue for `SOCK_SEQPACKET`.
        packets: VecDeque<PacketMsg>,
        queued_packet_bytes: usize,
        shut_rd: bool,
        shut_wr: bool,
        peer_closed: bool,
    },
}

struct UnixSocket {
    id: SockId,
    sock_type: SockType,
    owner_cred: PeerCred,
    /// Per-PID external descriptor reference count (enables clean exit/crash reclamation).
    external_holders: HashMap<u32, usize>,
    /// Number of `InFlightFd::UnixSocket(self.id)` copies sitting inside socket queues.
    inflight_refs: usize,
    /// Bound inode key (present whenever registered in `UnixSocketTable::bindings`).
    bound_key: Option<SocketInodeKey>,
    bound_path: Option<String>,
    /// Default peer for `SOCK_DGRAM` after `connect()`.
    dgram_peer: Option<(SockId, String)>,
    /// Incoming datagram queue for `SOCK_DGRAM`.
    dgram_queue: VecDeque<PacketMsg>,
    dgram_queued_bytes: usize,
    dgram_shut_rd: bool,
    dgram_shut_wr: bool,
    /// `SO_PASSCRED` option flag.
    passcred: bool,
    /// Pending `SO_ERROR` value.
    so_error: i32,
    state: SockState,
}

impl UnixSocket {
    fn total_external_holders(&self) -> usize {
        self.external_holders.values().sum()
    }

    fn is_held_by(&self, pid: u32) -> bool {
        self.external_holders.get(&pid).copied().unwrap_or(0) > 0
    }
}

/// Kernel-owned instance-wide Unix-domain socket table.
pub struct UnixSocketTable {
    sockets: BTreeMap<SockId, UnixSocket>,
    bindings: HashMap<SocketInodeKey, SockId>,
    arena: ArenaPool,
    inflight_global: usize,
    inflight_by_uid: HashMap<u32, usize>,
    next_id: SockId,
}

impl Default for UnixSocketTable {
    fn default() -> Self {
        Self::new()
    }
}

impl UnixSocketTable {
    pub fn new() -> Self {
        Self {
            sockets: BTreeMap::new(),
            bindings: HashMap::new(),
            arena: ArenaPool::new(),
            inflight_global: 0,
            inflight_by_uid: HashMap::new(),
            next_id: 1,
        }
    }

    /// Snapshot table & arena counts (used by leak tests).
    pub fn stats(&self) -> SocketStats {
        SocketStats {
            active_sockets: self.sockets.len(),
            bound_inodes: self.bindings.len(),
            inflight_global: self.inflight_global,
            allocated_arena_slots: self.arena.allocated_count(),
        }
    }

    /// Allocate one `SockArena` slot for an arena-backed `fd_pipe` (shared pool with `AF_UNIX`).
    pub fn alloc_pipe_slot(&mut self) -> Result<ArenaSlot> {
        self.arena.alloc()
    }

    /// Free an arena-backed `fd_pipe` slot when both ends are closed.
    pub fn free_pipe_slot(&mut self, slot: ArenaSlot) -> Option<ArenaSlot> {
        self.arena.free(slot)
    }

    /// Verify a `SockArena` slot generation is currently allocated.
    pub fn is_arena_slot_live(&self, slot: ArenaSlot) -> bool {
        self.arena.is_live(slot)
    }

    fn alloc_sock_id(&mut self) -> Result<SockId> {
        if self.sockets.len() >= UNIX_SOCK_MAX {
            return Err(Errno::ENOBUFS);
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        Ok(id)
    }

    /// Create an unbound `AF_UNIX` socket held by `pid` with kernel-authenticated `cred`.
    pub fn create(&mut self, pid: u32, sock_type: SockType, cred: PeerCred) -> Result<SockId> {
        let id = self.alloc_sock_id()?;
        let mut holders = HashMap::new();
        holders.insert(pid, 1);
        self.sockets.insert(
            id,
            UnixSocket {
                id,
                sock_type,
                owner_cred: cred,
                external_holders: holders,
                inflight_refs: 0,
                bound_key: None,
                bound_path: None,
                dgram_peer: None,
                dgram_queue: VecDeque::new(),
                dgram_queued_bytes: 0,
                dgram_shut_rd: false,
                dgram_shut_wr: false,
                passcred: false,
                so_error: 0,
                state: SockState::Unbound,
            },
        );
        Ok(id)
    }

    /// Create a pre-connected pair of `AF_UNIX` sockets (`socketpair(2)`).
    pub fn socketpair(
        &mut self,
        pid: u32,
        sock_type: SockType,
        cred: PeerCred,
    ) -> Result<PairResult> {
        if self.sockets.len() + 2 > UNIX_SOCK_MAX {
            return Err(Errno::ENOBUFS);
        }
        let (slot_ab, slot_ba) = if sock_type == SockType::Stream {
            let ab = self.arena.alloc()?;
            let ba = match self.arena.alloc() {
                Ok(s) => s,
                Err(e) => {
                    self.arena.free(ab);
                    return Err(e);
                }
            };
            (Some(ab), Some(ba))
        } else {
            (None, None)
        };

        let id_a = self.alloc_sock_id()?;
        let id_b = self.alloc_sock_id()?;

        let make_sock =
            |id: SockId, peer: SockId, tx_slot: Option<ArenaSlot>, rx_slot: Option<ArenaSlot>| {
                let mut holders = HashMap::new();
                holders.insert(pid, 1);
                let (dgram_peer, state) = if sock_type == SockType::Dgram {
                    (Some((peer, String::new())), SockState::Unbound)
                } else {
                    (
                        None,
                        SockState::Connected {
                            peer: Some(peer),
                            peer_cred: cred,
                            peer_path: None,
                            tx_slot,
                            rx_slot,
                            stream_buf: VecDeque::new(),
                            stream_enqueued: 0,
                            stream_read: 0,
                            ancillary: VecDeque::new(),
                            packets: VecDeque::new(),
                            queued_packet_bytes: 0,
                            shut_rd: false,
                            shut_wr: false,
                            peer_closed: false,
                        },
                    )
                };
                UnixSocket {
                    id,
                    sock_type,
                    owner_cred: cred,
                    external_holders: holders,
                    inflight_refs: 0,
                    bound_key: None,
                    bound_path: None,
                    dgram_peer,
                    dgram_queue: VecDeque::new(),
                    dgram_queued_bytes: 0,
                    dgram_shut_rd: false,
                    dgram_shut_wr: false,
                    passcred: false,
                    so_error: 0,
                    state,
                }
            };

        self.sockets
            .insert(id_a, make_sock(id_a, id_b, slot_ab, slot_ba));
        self.sockets
            .insert(id_b, make_sock(id_b, id_a, slot_ba, slot_ab));

        Ok(PairResult {
            sock_a: id_a,
            sock_b: id_b,
            slot_ab,
            slot_ba,
        })
    }

    /// Increment external holder refcount (for `dup`, `dup2`, `fork`, `posix_spawn`).
    pub fn hold(&mut self, pid: u32, sock_id: SockId, count: usize) -> Result<()> {
        if count == 0 {
            return Ok(());
        }
        let sock = self.sockets.get_mut(&sock_id).ok_or(Errno::EBADF)?;
        *sock.external_holders.entry(pid).or_insert(0) += count;
        Ok(())
    }

    /// Return the start byte offset of the front pending `AncillaryMark` on `sock_id`, if any.
    pub fn head_ancillary_offset(&self, sock_id: SockId) -> Option<u64> {
        let sock = self.sockets.get(&sock_id)?;
        match &sock.state {
            SockState::Connected { ancillary, .. } => ancillary.front().map(|m| m.start_offset),
            _ => None,
        }
    }

    /// Return the `rx_slot` of a connected stream socket, if any.
    pub fn rx_slot(&self, sock_id: SockId) -> Option<ArenaSlot> {
        let sock = self.sockets.get(&sock_id)?;
        match &sock.state {
            SockState::Connected { rx_slot, .. } => *rx_slot,
            _ => None,
        }
    }

    /// Verify a socket is held by `pid` and return its type and `SockArena` slots (if connected).
    pub fn describe(
        &self,
        pid: u32,
        sock_id: SockId,
    ) -> Result<(SockType, Option<ArenaSlot>, Option<ArenaSlot>)> {
        let sock = self.sockets.get(&sock_id).ok_or(Errno::EBADF)?;
        if !sock.is_held_by(pid) {
            return Err(Errno::EBADF);
        }
        let (tx, rx) = match &sock.state {
            SockState::Connected {
                tx_slot, rx_slot, ..
            } => (*tx_slot, *rx_slot),
            _ => (None, None),
        };
        Ok((sock.sock_type, tx, rx))
    }

    /// Bind an unbound socket to a freshly created filesystem socket inode `(fs_id, node)`.
    pub fn bind(
        &mut self,
        pid: u32,
        sock_id: SockId,
        key: SocketInodeKey,
        path: String,
    ) -> Result<()> {
        validate_unix_path(&path)?;
        if self.bindings.contains_key(&key) {
            return Err(Errno::EADDRINUSE);
        }
        let sock = self.sockets.get_mut(&sock_id).ok_or(Errno::EBADF)?;
        if !sock.is_held_by(pid) {
            return Err(Errno::EBADF);
        }
        if sock.bound_key.is_some() || !matches!(sock.state, SockState::Unbound) {
            return Err(Errno::EINVAL);
        }
        sock.bound_key = Some(key.clone());
        sock.bound_path = Some(path);
        sock.state = SockState::Bound;
        self.bindings.insert(key, sock_id);
        Ok(())
    }

    /// Mark a bound `SOCK_STREAM` or `SOCK_SEQPACKET` socket as listening.
    pub fn listen(&mut self, pid: u32, sock_id: SockId, backlog: u32) -> Result<()> {
        let sock = self.sockets.get_mut(&sock_id).ok_or(Errno::EBADF)?;
        if !sock.is_held_by(pid) {
            return Err(Errno::EBADF);
        }
        if sock.sock_type == SockType::Dgram {
            return Err(Errno::EOPNOTSUPP);
        }
        let clamped = (backlog as usize).clamp(1, UNIX_SOMAXCONN);
        match &mut sock.state {
            SockState::Bound => {
                sock.state = SockState::Listening {
                    backlog: clamped,
                    pending: VecDeque::new(),
                };
                Ok(())
            }
            SockState::Listening {
                backlog: cur_backlog,
                ..
            } => {
                *cur_backlog = clamped;
                Ok(())
            }
            _ => Err(Errno::EINVAL),
        }
    }

    /// Connect `client_id` to the socket bound at `target_key`.
    ///
    /// Callers MUST resolve `target_key` through `Vfs::resolve_socket_inode` first so mount
    /// namespaces, `chroot`, `FileType::Socket`, and DAC+ACL `W_OK` permissions are enforced.
    /// `caller_cred` MUST come strictly from `LocalProcessTable`.
    pub fn connect(
        &mut self,
        pid: u32,
        client_id: SockId,
        target_key: &SocketInodeKey,
        target_path: String,
        caller_cred: PeerCred,
    ) -> Result<ConnectResult> {
        let (client_type, client_is_conn, client_is_listening, client_bound_path) = {
            let client = self.sockets.get(&client_id).ok_or(Errno::EBADF)?;
            if !client.is_held_by(pid) {
                return Err(Errno::EBADF);
            }
            (
                client.sock_type,
                matches!(client.state, SockState::Connected { .. }),
                matches!(client.state, SockState::Listening { .. }),
                client.bound_path.clone(),
            )
        };

        let target_id = *self.bindings.get(target_key).ok_or(Errno::ECONNREFUSED)?;
        let (target_type, target_cred, target_listening, target_full) = {
            let target = self.sockets.get(&target_id).ok_or(Errno::ECONNREFUSED)?;
            let (listening, full) = match &target.state {
                SockState::Listening {
                    backlog, pending, ..
                } => (true, pending.len() >= *backlog),
                _ => (false, false),
            };
            (target.sock_type, target.owner_cred, listening, full)
        };

        if client_type != target_type {
            return Err(Errno::EPROTOTYPE);
        }

        if client_type == SockType::Dgram {
            let client = self.sockets.get_mut(&client_id).ok_or(Errno::EBADF)?;
            client.dgram_peer = Some((target_id, target_path));
            return Ok(ConnectResult {
                peer_id: target_id,
                listener_id: None,
                peer_cred: target_cred,
                tx_slot: None,
                rx_slot: None,
            });
        }

        if client_is_conn {
            return Err(Errno::EISCONN);
        }
        if client_is_listening {
            return Err(Errno::EINVAL);
        }
        if !target_listening {
            return Err(Errno::ECONNREFUSED);
        }
        if target_full {
            return Err(Errno::EAGAIN);
        }
        if self.sockets.len() >= UNIX_SOCK_MAX {
            return Err(Errno::ENOBUFS);
        }

        let (slot_c2s, slot_s2c) = if client_type == SockType::Stream {
            let c2s = self.arena.alloc()?;
            let s2c = match self.arena.alloc() {
                Ok(s) => s,
                Err(e) => {
                    self.arena.free(c2s);
                    return Err(e);
                }
            };
            (Some(c2s), Some(s2c))
        } else {
            (None, None)
        };

        let server_id = self.alloc_sock_id()?;
        let server_sock = UnixSocket {
            id: server_id,
            sock_type: client_type,
            owner_cred: target_cred,
            external_holders: HashMap::new(),
            inflight_refs: 0,
            bound_key: None,
            bound_path: Some(target_path.clone()),
            dgram_peer: None,
            dgram_queue: VecDeque::new(),
            dgram_queued_bytes: 0,
            dgram_shut_rd: false,
            dgram_shut_wr: false,
            passcred: false,
            so_error: 0,
            state: SockState::Connected {
                peer: Some(client_id),
                peer_cred: caller_cred,
                peer_path: client_bound_path,
                tx_slot: slot_s2c,
                rx_slot: slot_c2s,
                stream_buf: VecDeque::new(),
                stream_enqueued: 0,
                stream_read: 0,
                ancillary: VecDeque::new(),
                packets: VecDeque::new(),
                queued_packet_bytes: 0,
                shut_rd: false,
                shut_wr: false,
                peer_closed: false,
            },
        };
        self.sockets.insert(server_id, server_sock);

        if let Some(client) = self.sockets.get_mut(&client_id) {
            client.owner_cred = caller_cred;
            client.state = SockState::Connected {
                peer: Some(server_id),
                peer_cred: target_cred,
                peer_path: Some(target_path),
                tx_slot: slot_c2s,
                rx_slot: slot_s2c,
                stream_buf: VecDeque::new(),
                stream_enqueued: 0,
                stream_read: 0,
                ancillary: VecDeque::new(),
                packets: VecDeque::new(),
                queued_packet_bytes: 0,
                shut_rd: false,
                shut_wr: false,
                peer_closed: false,
            };
        }

        if let Some(listener) = self.sockets.get_mut(&target_id)
            && let SockState::Listening { pending, .. } = &mut listener.state
        {
            pending.push_back(server_id);
        }

        Ok(ConnectResult {
            peer_id: server_id,
            listener_id: Some(target_id),
            peer_cred: target_cred,
            tx_slot: slot_c2s,
            rx_slot: slot_s2c,
        })
    }

    /// Pop the next pending connection from a listening socket (`accept(2)`).
    /// Returns `Err(Errno::EAGAIN)` when no connection is pending.
    pub fn accept(
        &mut self,
        pid: u32,
        listener_id: SockId,
        caller_cred: PeerCred,
    ) -> Result<AcceptResult> {
        let server_id = {
            let listener = self.sockets.get_mut(&listener_id).ok_or(Errno::EBADF)?;
            if !listener.is_held_by(pid) {
                return Err(Errno::EBADF);
            }
            match &mut listener.state {
                SockState::Listening { pending, .. } => pending.pop_front().ok_or(Errno::EAGAIN)?,
                _ => return Err(Errno::EINVAL),
            }
        };

        let server = self
            .sockets
            .get_mut(&server_id)
            .ok_or(Errno::ECONNABORTED)?;
        *server.external_holders.entry(pid).or_insert(0) += 1;
        server.owner_cred = caller_cred;
        let (peer_cred, tx_slot, rx_slot) = match &server.state {
            SockState::Connected {
                peer_cred,
                tx_slot,
                rx_slot,
                ..
            } => (*peer_cred, *tx_slot, *rx_slot),
            _ => return Err(Errno::ECONNABORTED),
        };

        Ok(AcceptResult {
            sock_id: server_id,
            peer_cred,
            tx_slot,
            rx_slot,
        })
    }

    /// Shut down reads, writes, or both on a socket (`shutdown(2)`).
    pub fn shutdown(&mut self, pid: u32, sock_id: SockId, how: u32) -> Result<ShutdownResult> {
        if how != SHUT_RD && how != SHUT_WR && how != SHUT_RDWR {
            return Err(Errno::EINVAL);
        }
        let shut_r = how == SHUT_RD || how == SHUT_RDWR;
        let shut_w = how == SHUT_WR || how == SHUT_RDWR;

        let (peer_id, tx_slot, rx_slot, out_rd, out_wr) = {
            let sock = self.sockets.get_mut(&sock_id).ok_or(Errno::EBADF)?;
            if !sock.is_held_by(pid) {
                return Err(Errno::EBADF);
            }
            if sock.sock_type == SockType::Dgram {
                if shut_r {
                    sock.dgram_shut_rd = true;
                }
                if shut_w {
                    sock.dgram_shut_wr = true;
                }
                return Ok(ShutdownResult {
                    tx_slot: None,
                    rx_slot: None,
                    shut_rd: sock.dgram_shut_rd,
                    shut_wr: sock.dgram_shut_wr,
                });
            }
            match &mut sock.state {
                SockState::Connected {
                    peer,
                    tx_slot,
                    rx_slot,
                    shut_rd,
                    shut_wr,
                    ..
                } => {
                    if shut_r {
                        *shut_rd = true;
                    }
                    if shut_w {
                        *shut_wr = true;
                    }
                    (*peer, *tx_slot, *rx_slot, *shut_rd, *shut_wr)
                }
                _ => return Err(Errno::ENOTCONN),
            }
        };

        if let Some(peer_id) = peer_id
            && let Some(peer) = self.sockets.get_mut(&peer_id)
            && let SockState::Connected {
                shut_rd: peer_rd,
                shut_wr: peer_wr,
                ..
            } = &mut peer.state
        {
            if shut_r {
                *peer_wr = true;
            }
            if shut_w {
                *peer_rd = true;
            }
        }

        Ok(ShutdownResult {
            tx_slot,
            rx_slot,
            shut_rd: out_rd,
            shut_wr: out_wr,
        })
    }

    /// Query kernel-authenticated `SO_PEERCRED` (`PeerCred`).
    pub fn peer_cred(&self, pid: u32, sock_id: SockId) -> Result<PeerCred> {
        let sock = self.sockets.get(&sock_id).ok_or(Errno::EBADF)?;
        if !sock.is_held_by(pid) {
            return Err(Errno::EBADF);
        }
        if sock.sock_type == SockType::Dgram {
            let (peer_id, _) = sock.dgram_peer.as_ref().ok_or(Errno::ENOTCONN)?;
            let peer = self.sockets.get(peer_id).ok_or(Errno::ENOTCONN)?;
            return Ok(peer.owner_cred);
        }
        match &sock.state {
            SockState::Connected { peer_cred, .. } => Ok(*peer_cred),
            _ => Err(Errno::ENOTCONN),
        }
    }

    /// Query local bound pathname (`getsockname(2)`). Returns empty string if unbound.
    pub fn getsockname(&self, pid: u32, sock_id: SockId) -> Result<String> {
        let sock = self.sockets.get(&sock_id).ok_or(Errno::EBADF)?;
        if !sock.is_held_by(pid) {
            return Err(Errno::EBADF);
        }
        Ok(sock.bound_path.clone().unwrap_or_default())
    }

    /// Query peer's bound pathname (`getpeername(2)`). Returns `ENOTCONN` if unconnected.
    pub fn getpeername(&self, pid: u32, sock_id: SockId) -> Result<String> {
        let sock = self.sockets.get(&sock_id).ok_or(Errno::EBADF)?;
        if !sock.is_held_by(pid) {
            return Err(Errno::EBADF);
        }
        if sock.sock_type == SockType::Dgram {
            let (_, path) = sock.dgram_peer.as_ref().ok_or(Errno::ENOTCONN)?;
            return Ok(path.clone());
        }
        match &sock.state {
            SockState::Connected { peer_path, .. } => Ok(peer_path.clone().unwrap_or_default()),
            _ => Err(Errno::ENOTCONN),
        }
    }

    /// `getsockopt(2)` for `SOL_SOCKET` integer options.
    pub fn getsockopt(
        &mut self,
        pid: u32,
        sock_id: SockId,
        level: u32,
        optname: u32,
    ) -> Result<i32> {
        if level != SOL_SOCKET {
            return Err(Errno::EOPNOTSUPP);
        }
        let sock = self.sockets.get_mut(&sock_id).ok_or(Errno::EBADF)?;
        if !sock.is_held_by(pid) {
            return Err(Errno::EBADF);
        }
        match optname {
            SO_TYPE => Ok(sock.sock_type.to_raw() as i32),
            SO_ERROR => {
                let err = sock.so_error;
                sock.so_error = 0;
                Ok(err)
            }
            SO_ACCEPTCONN => Ok(i32::from(matches!(sock.state, SockState::Listening { .. }))),
            SO_PASSCRED => Ok(i32::from(sock.passcred)),
            _ => Err(Errno::EOPNOTSUPP),
        }
    }

    /// `setsockopt(2)` for `SOL_SOCKET` integer options.
    pub fn setsockopt(
        &mut self,
        pid: u32,
        sock_id: SockId,
        level: u32,
        optname: u32,
        val: i32,
    ) -> Result<()> {
        if level != SOL_SOCKET {
            return Err(Errno::EOPNOTSUPP);
        }
        let sock = self.sockets.get_mut(&sock_id).ok_or(Errno::EBADF)?;
        if !sock.is_held_by(pid) {
            return Err(Errno::EBADF);
        }
        match optname {
            SO_PASSCRED => {
                sock.passcred = val != 0;
                Ok(())
            }
            _ => Err(Errno::EOPNOTSUPP),
        }
    }

    /// Check atomic `SCM_RIGHTS` fd limits BEFORE mutating any queue state.
    fn check_inflight_quota(&self, sender_uid: u32, count: usize) -> Result<()> {
        if count == 0 {
            return Ok(());
        }
        if count > SCM_MAX_FD {
            return Err(Errno::EINVAL);
        }
        if self.inflight_global.saturating_add(count) > MAX_INFLIGHT_FDS_GLOBAL {
            return Err(Errno::ETOOMANYREFS);
        }
        let user_cur = self.inflight_by_uid.get(&sender_uid).copied().unwrap_or(0);
        if user_cur.saturating_add(count) > MAX_INFLIGHT_FDS_PER_USER {
            return Err(Errno::ETOOMANYREFS);
        }
        Ok(())
    }

    fn account_inflight_enqueue(&mut self, sender_uid: u32, fds: &[InFlightFd]) {
        if fds.is_empty() {
            return;
        }
        self.inflight_global += fds.len();
        *self.inflight_by_uid.entry(sender_uid).or_insert(0) += fds.len();
        for fd in fds {
            if let InFlightFd::UnixSocket(id) = fd
                && let Some(s) = self.sockets.get_mut(id)
            {
                s.inflight_refs += 1;
            }
        }
    }

    fn account_inflight_dequeue(&mut self, sender_uid: u32, fds: &[InFlightFd]) {
        if fds.is_empty() {
            return;
        }
        self.inflight_global = self.inflight_global.saturating_sub(fds.len());
        if let Some(count) = self.inflight_by_uid.get_mut(&sender_uid) {
            *count = count.saturating_sub(fds.len());
            if *count == 0 {
                self.inflight_by_uid.remove(&sender_uid);
            }
        }
        for fd in fds {
            if let InFlightFd::UnixSocket(id) = fd
                && let Some(s) = self.sockets.get_mut(id)
            {
                s.inflight_refs = s.inflight_refs.saturating_sub(1);
            }
        }
    }

    /// Send data and/or `SCM_RIGHTS` descriptors on a socket (`sendmsg(2)`).
    ///
    /// - For `SOCK_STREAM` in pure-Rust mode: pass `sab_stream_span = None`; payload is buffered in
    ///   `peer.stream_buf` and ancillary marks anchor to `(stream_enqueued_before, stream_enqueued_after)`.
    /// - For `SOCK_STREAM` in browser `SockArena` SAB mode: pass `sab_stream_span = Some((start, end))`
    ///   after writing payload to the shared ring; only the ancillary mark is stored here.
    /// - For unconnected `SOCK_DGRAM`: pass `dest_key = Some(&inode_key)` resolved via
    ///   `Vfs::resolve_socket_inode` (DAC+ACL `W_OK` already checked).
    /// - `sender_cred` MUST come strictly from `LocalProcessTable`.
    #[allow(clippy::too_many_arguments)]
    pub fn sendmsg(
        &mut self,
        pid: u32,
        sock_id: SockId,
        data: &[u8],
        fds: Vec<InFlightFd>,
        dest_key: Option<&SocketInodeKey>,
        sender_cred: PeerCred,
        sab_stream_span: Option<(u64, u64)>,
    ) -> Result<SendOutcome> {
        let sender_uid = sender_cred.uid;
        self.check_inflight_quota(sender_uid, fds.len())?;

        // Validate any passed UnixSocket IDs exist before mutating state.
        for fd in &fds {
            if let InFlightFd::UnixSocket(id) = fd
                && !self.sockets.contains_key(id)
            {
                return Err(Errno::EBADF);
            }
        }

        let (sock_type, sender_path) = {
            let sock = self.sockets.get(&sock_id).ok_or(Errno::EBADF)?;
            if !sock.is_held_by(pid) {
                return Err(Errno::EBADF);
            }
            (sock.sock_type, sock.bound_path.clone())
        };

        match sock_type {
            SockType::Dgram => {
                if data.len() > UNIX_DGRAM_MAX {
                    return Err(Errno::EMSGSIZE);
                }
                let sock = self.sockets.get(&sock_id).ok_or(Errno::EBADF)?;
                if sock.dgram_shut_wr {
                    return Err(Errno::EPIPE);
                }
                let target_id = if let Some(key) = dest_key {
                    *self.bindings.get(key).ok_or(Errno::ECONNREFUSED)?
                } else {
                    sock.dgram_peer.as_ref().ok_or(Errno::ENOTCONN)?.0
                };
                let target = self.sockets.get(&target_id).ok_or(Errno::ECONNREFUSED)?;
                if target.sock_type != SockType::Dgram {
                    return Err(Errno::EPROTOTYPE);
                }
                if target.dgram_shut_rd {
                    return Err(Errno::EPIPE);
                }
                if target.dgram_queue.len() >= UNIX_MAX_QUEUED_MSGS
                    || target.dgram_queued_bytes.saturating_add(data.len()) > UNIX_MAX_QUEUED_BYTES
                {
                    return Err(Errno::EAGAIN);
                }
                self.account_inflight_enqueue(sender_uid, &fds);
                let target = self
                    .sockets
                    .get_mut(&target_id)
                    .ok_or(Errno::ECONNREFUSED)?;
                target.dgram_queued_bytes += data.len();
                target.dgram_queue.push_back(PacketMsg {
                    data: data.to_vec(),
                    fds,
                    sender_cred,
                    sender_uid,
                    sender_path,
                });
                Ok(SendOutcome {
                    sent: data.len(),
                    target_id,
                    target_rx_slot: None,
                    has_ancillary: false,
                    head_ancillary_offset: 0,
                })
            }
            SockType::Seqpacket => {
                if dest_key.is_some() {
                    return Err(Errno::EISCONN);
                }
                if data.len() > UNIX_DGRAM_MAX {
                    return Err(Errno::EMSGSIZE);
                }
                let peer_id = {
                    let sock = self.sockets.get(&sock_id).ok_or(Errno::EBADF)?;
                    match &sock.state {
                        SockState::Connected {
                            peer,
                            shut_wr,
                            peer_closed,
                            ..
                        } => {
                            if *shut_wr || *peer_closed {
                                return Err(Errno::EPIPE);
                            }
                            (*peer).ok_or(Errno::EPIPE)?
                        }
                        _ => return Err(Errno::ENOTCONN),
                    }
                };
                {
                    let peer = self.sockets.get(&peer_id).ok_or(Errno::EPIPE)?;
                    match &peer.state {
                        SockState::Connected {
                            packets,
                            queued_packet_bytes,
                            shut_rd,
                            ..
                        } => {
                            if *shut_rd {
                                return Err(Errno::EPIPE);
                            }
                            if packets.len() >= UNIX_MAX_QUEUED_MSGS
                                || queued_packet_bytes.saturating_add(data.len())
                                    > UNIX_MAX_QUEUED_BYTES
                            {
                                return Err(Errno::EAGAIN);
                            }
                        }
                        _ => return Err(Errno::EPIPE),
                    }
                }
                self.account_inflight_enqueue(sender_uid, &fds);
                let peer = self.sockets.get_mut(&peer_id).ok_or(Errno::EPIPE)?;
                if let SockState::Connected {
                    packets,
                    queued_packet_bytes,
                    ..
                } = &mut peer.state
                {
                    *queued_packet_bytes += data.len();
                    packets.push_back(PacketMsg {
                        data: data.to_vec(),
                        fds,
                        sender_cred,
                        sender_uid,
                        sender_path,
                    });
                }
                Ok(SendOutcome {
                    sent: data.len(),
                    target_id: peer_id,
                    target_rx_slot: None,
                    has_ancillary: false,
                    head_ancillary_offset: 0,
                })
            }
            SockType::Stream => {
                if dest_key.is_some() {
                    return Err(Errno::EISCONN);
                }
                let peer_id = {
                    let sock = self.sockets.get(&sock_id).ok_or(Errno::EBADF)?;
                    match &sock.state {
                        SockState::Connected {
                            peer,
                            shut_wr,
                            peer_closed,
                            ..
                        } => {
                            if *shut_wr || *peer_closed {
                                return Err(Errno::EPIPE);
                            }
                            (*peer).ok_or(Errno::EPIPE)?
                        }
                        _ => return Err(Errno::ENOTCONN),
                    }
                };

                // Check peer readiness & stream capacity.
                let (peer_rx_slot, write_len) = {
                    let peer = self.sockets.get(&peer_id).ok_or(Errno::EPIPE)?;
                    match &peer.state {
                        SockState::Connected {
                            rx_slot,
                            stream_buf,
                            ancillary,
                            shut_rd,
                            ..
                        } => {
                            if *shut_rd {
                                return Err(Errno::EPIPE);
                            }
                            if !fds.is_empty() && ancillary.len() >= UNIX_MAX_QUEUED_MSGS {
                                return Err(Errno::EAGAIN);
                            }
                            let len = if let Some((s, e)) = sab_stream_span {
                                (e.saturating_sub(s)) as usize
                            } else {
                                let room = UNIX_MAX_QUEUED_BYTES.saturating_sub(stream_buf.len());
                                if room == 0 && !data.is_empty() {
                                    return Err(Errno::EAGAIN);
                                }
                                data.len().min(room)
                            };
                            (*rx_slot, len)
                        }
                        _ => return Err(Errno::EPIPE),
                    }
                };

                self.account_inflight_enqueue(sender_uid, &fds);
                let peer = self.sockets.get_mut(&peer_id).ok_or(Errno::EPIPE)?;
                let (has_anc, head_off) = match &mut peer.state {
                    SockState::Connected {
                        stream_buf,
                        stream_enqueued,
                        ancillary,
                        ..
                    } => {
                        let (start_off, end_off) = if let Some((s, e)) = sab_stream_span {
                            (s, e)
                        } else {
                            let start = *stream_enqueued;
                            stream_buf.extend(&data[..write_len]);
                            *stream_enqueued = stream_enqueued.saturating_add(write_len as u64);
                            (start, *stream_enqueued)
                        };
                        if !fds.is_empty() {
                            ancillary.push_back(AncillaryMark {
                                start_offset: start_off,
                                end_offset: end_off,
                                fds,
                                sender_cred,
                                sender_uid,
                            });
                        }
                        match ancillary.front() {
                            Some(mark) => (true, mark.start_offset),
                            None => (false, 0),
                        }
                    }
                    _ => (false, 0),
                };

                Ok(SendOutcome {
                    sent: write_len,
                    target_id: peer_id,
                    target_rx_slot: peer_rx_slot,
                    has_ancillary: has_anc,
                    head_ancillary_offset: head_off,
                })
            }
        }
    }

    /// Receive data and/or `SCM_RIGHTS` descriptors (`recvmsg(2)`).
    ///
    /// - `max_fds`: receiver's maximum installable fds (min of `fds_cap` and remaining `FD_MAX`
    ///   headroom). Any excess fds from the delivered message are placed in `dropped_fds` and
    ///   `MSG_CTRUNC` is set in `out_flags` (with zero leaked refs!).
    /// - For `SOCK_STREAM` SAB mode: pass `sab_rx_tail = Some(tail_offset)`; `data` is returned
    ///   empty and `max_stream_bytes` tells JS the exact byte cap to read from `rx_slot` without
    ///   crossing an `SCM_RIGHTS` boundary.
    pub fn recvmsg(
        &mut self,
        pid: u32,
        sock_id: SockId,
        buf_len: usize,
        max_fds: usize,
        flags: u32,
        sab_rx_tail: Option<u64>,
    ) -> Result<RecvOutcome> {
        let peek = (flags & MSG_PEEK) != 0;
        let want_full_len = (flags & MSG_TRUNC) != 0;

        let sock_type = {
            let sock = self.sockets.get(&sock_id).ok_or(Errno::EBADF)?;
            if !sock.is_held_by(pid) {
                return Err(Errno::EBADF);
            }
            sock.sock_type
        };

        match sock_type {
            SockType::Dgram => {
                let (msg_opt, shut_rd) = {
                    let sock = self.sockets.get_mut(&sock_id).ok_or(Errno::EBADF)?;
                    if sock.dgram_queue.is_empty() {
                        (None, sock.dgram_shut_rd)
                    } else if peek {
                        let front = sock.dgram_queue.front().unwrap();
                        (
                            Some((
                                front.data.clone(),
                                Vec::new(),
                                front.sender_cred,
                                front.sender_uid,
                                front.sender_path.clone(),
                            )),
                            sock.dgram_shut_rd,
                        )
                    } else {
                        let m = sock.dgram_queue.pop_front().unwrap();
                        sock.dgram_queued_bytes =
                            sock.dgram_queued_bytes.saturating_sub(m.data.len());
                        (
                            Some((m.data, m.fds, m.sender_cred, m.sender_uid, m.sender_path)),
                            sock.dgram_shut_rd,
                        )
                    }
                };
                let Some((raw_data, mut raw_fds, sender_cred, sender_uid, sender_path)) = msg_opt
                else {
                    if shut_rd {
                        return Ok(RecvOutcome {
                            data: Vec::new(),
                            fds: Vec::new(),
                            dropped_fds: Vec::new(),
                            peer_cred: PeerCred::default(),
                            sender_path: None,
                            out_flags: 0,
                            max_stream_bytes: None,
                            has_next_ancillary: false,
                            next_ancillary_offset: 0,
                            freed_slots: Vec::new(),
                        });
                    }
                    return Err(Errno::EAGAIN);
                };
                self.finish_packet_recv(
                    pid,
                    raw_data,
                    &mut raw_fds,
                    sender_cred,
                    sender_uid,
                    sender_path,
                    buf_len,
                    max_fds,
                    peek,
                    want_full_len,
                )
            }
            SockType::Seqpacket => {
                let (msg_opt, eof) = {
                    let sock = self.sockets.get_mut(&sock_id).ok_or(Errno::EBADF)?;
                    match &mut sock.state {
                        SockState::Connected {
                            packets,
                            queued_packet_bytes,
                            shut_rd,
                            peer_closed,
                            ..
                        } => {
                            if packets.is_empty() {
                                (None, *shut_rd || *peer_closed)
                            } else if peek {
                                let front = packets.front().unwrap();
                                (
                                    Some((
                                        front.data.clone(),
                                        Vec::new(),
                                        front.sender_cred,
                                        front.sender_uid,
                                        front.sender_path.clone(),
                                    )),
                                    false,
                                )
                            } else {
                                let m = packets.pop_front().unwrap();
                                *queued_packet_bytes =
                                    queued_packet_bytes.saturating_sub(m.data.len());
                                (
                                    Some((
                                        m.data,
                                        m.fds,
                                        m.sender_cred,
                                        m.sender_uid,
                                        m.sender_path,
                                    )),
                                    false,
                                )
                            }
                        }
                        _ => return Err(Errno::ENOTCONN),
                    }
                };
                let Some((raw_data, mut raw_fds, sender_cred, sender_uid, sender_path)) = msg_opt
                else {
                    if eof {
                        return Ok(RecvOutcome {
                            data: Vec::new(),
                            fds: Vec::new(),
                            dropped_fds: Vec::new(),
                            peer_cred: PeerCred::default(),
                            sender_path: None,
                            out_flags: 0,
                            max_stream_bytes: None,
                            has_next_ancillary: false,
                            next_ancillary_offset: 0,
                            freed_slots: Vec::new(),
                        });
                    }
                    return Err(Errno::EAGAIN);
                };
                self.finish_packet_recv(
                    pid,
                    raw_data,
                    &mut raw_fds,
                    sender_cred,
                    sender_uid,
                    sender_path,
                    buf_len,
                    max_fds,
                    peek,
                    want_full_len,
                )
            }
            SockType::Stream => {
                self.recvmsg_stream(pid, sock_id, buf_len, max_fds, peek, sab_rx_tail)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_packet_recv(
        &mut self,
        pid: u32,
        raw_data: Vec<u8>,
        raw_fds: &mut Vec<InFlightFd>,
        sender_cred: PeerCred,
        sender_uid: u32,
        sender_path: Option<String>,
        buf_len: usize,
        max_fds: usize,
        peek: bool,
        _want_full_len: bool,
    ) -> Result<RecvOutcome> {
        let mut out_flags = 0u32;
        let data = if raw_data.len() > buf_len {
            out_flags |= MSG_TRUNC;
            raw_data[..buf_len].to_vec()
        } else {
            raw_data
        };
        let mut delivered = Vec::new();
        let mut dropped = Vec::new();
        let mut freed_slots = Vec::new();

        if !peek && !raw_fds.is_empty() {
            self.account_inflight_dequeue(sender_uid, raw_fds);
            let all = std::mem::take(raw_fds);
            if all.len() > max_fds {
                out_flags |= MSG_CTRUNC;
            }
            for (idx, fd) in all.into_iter().enumerate() {
                if idx < max_fds {
                    if let InFlightFd::UnixSocket(id) = fd
                        && let Some(s) = self.sockets.get_mut(&id)
                    {
                        *s.external_holders.entry(pid).or_insert(0) += 1;
                    }
                    delivered.push(fd);
                } else {
                    dropped.push(fd);
                }
            }
            if !dropped.is_empty() {
                let mut gc_batch = CleanupBatch::default();
                self.dispose_dropped_fds(&mut dropped, &mut gc_batch);
                freed_slots.extend(gc_batch.freed_slots);
                dropped.extend(gc_batch.dropped_fds);
            }
        }

        Ok(RecvOutcome {
            data,
            fds: delivered,
            dropped_fds: dropped,
            peer_cred: sender_cred,
            sender_path,
            out_flags,
            max_stream_bytes: None,
            has_next_ancillary: false,
            next_ancillary_offset: 0,
            freed_slots,
        })
    }

    fn recvmsg_stream(
        &mut self,
        pid: u32,
        sock_id: SockId,
        buf_len: usize,
        max_fds: usize,
        peek: bool,
        sab_rx_tail: Option<u64>,
    ) -> Result<RecvOutcome> {
        // Phase 1: inspect stream queue & ancillary marks.
        let mut delivered_mark: Option<AncillaryMark> = None;
        let data: Vec<u8>;
        let max_stream_bytes: Option<usize>;
        let peer_cred: PeerCred;
        let has_next_ancillary: bool;
        let next_ancillary_offset: u64;

        {
            let sock = self.sockets.get_mut(&sock_id).ok_or(Errno::EBADF)?;
            match &mut sock.state {
                SockState::Connected {
                    peer_cred: pcred,
                    stream_buf,
                    stream_read,
                    ancillary,
                    shut_rd,
                    peer_closed,
                    ..
                } => {
                    peer_cred = *pcred;
                    if let Some(rx_tail) = sab_rx_tail {
                        // Browser SockArena SAB mode: bytes live in the shared ring; we enforce
                        // exact ancillary byte-offset boundaries and pop marks at `rx_tail`.
                        data = Vec::new();
                        if let Some(front) = ancillary.front() {
                            if rx_tail < front.start_offset {
                                let until_mark = (front.start_offset - rx_tail) as usize;
                                max_stream_bytes = Some(buf_len.min(until_mark));
                                has_next_ancillary = true;
                                next_ancillary_offset = front.start_offset;
                            } else {
                                // `rx_tail` has reached `front.start_offset`: deliver this mark
                                // and clamp read length to NOT cross `front.end_offset` or the
                                // following mark's `start_offset`!
                                let end_bound = front.end_offset;
                                let next_start = ancillary.get(1).map(|m| m.start_offset);
                                let stop_at = match next_start {
                                    Some(ns) => end_bound.min(ns),
                                    None => end_bound,
                                };
                                let span = stop_at.saturating_sub(rx_tail) as usize;
                                max_stream_bytes = Some(buf_len.min(span));
                                if !peek {
                                    delivered_mark = ancillary.pop_front();
                                }
                                match ancillary.front() {
                                    Some(m) => {
                                        has_next_ancillary = true;
                                        next_ancillary_offset = m.start_offset;
                                    }
                                    None => {
                                        has_next_ancillary = false;
                                        next_ancillary_offset = 0;
                                    }
                                }
                            }
                        } else {
                            max_stream_bytes = Some(buf_len);
                            has_next_ancillary = false;
                            next_ancillary_offset = 0;
                        }
                    } else {
                        // Pure-Rust mode: read directly from `stream_buf`.
                        max_stream_bytes = None;
                        if stream_buf.is_empty() && ancillary.is_empty() {
                            if *shut_rd || *peer_closed {
                                return Ok(RecvOutcome {
                                    data: Vec::new(),
                                    fds: Vec::new(),
                                    dropped_fds: Vec::new(),
                                    peer_cred,
                                    sender_path: None,
                                    out_flags: 0,
                                    max_stream_bytes: None,
                                    has_next_ancillary: false,
                                    next_ancillary_offset: 0,
                                    freed_slots: Vec::new(),
                                });
                            }
                            return Err(Errno::EAGAIN);
                        }

                        let limit = if let Some(front) = ancillary.front() {
                            if *stream_read < front.start_offset {
                                // Stop BEFORE the ancillary boundary!
                                let until_mark = (front.start_offset - *stream_read) as usize;
                                buf_len.min(until_mark).min(stream_buf.len())
                            } else {
                                let end_bound = front.end_offset;
                                let next_start = ancillary.get(1).map(|m| m.start_offset);
                                let stop_at = match next_start {
                                    Some(ns) => end_bound.min(ns),
                                    None => end_bound,
                                };
                                let span = stop_at.saturating_sub(*stream_read) as usize;
                                if !peek {
                                    delivered_mark = ancillary.pop_front();
                                }
                                if span == 0 && next_start.is_none() {
                                    buf_len.min(stream_buf.len())
                                } else {
                                    buf_len.min(span).min(stream_buf.len())
                                }
                            }
                        } else {
                            buf_len.min(stream_buf.len())
                        };

                        if peek {
                            data = stream_buf.iter().take(limit).copied().collect();
                        } else {
                            data = stream_buf.drain(..limit).collect();
                            *stream_read = stream_read.saturating_add(data.len() as u64);
                        }
                        match ancillary.front() {
                            Some(m) => {
                                has_next_ancillary = true;
                                next_ancillary_offset = m.start_offset;
                            }
                            None => {
                                has_next_ancillary = false;
                                next_ancillary_offset = 0;
                            }
                        }
                    }
                }
                _ => return Err(Errno::ENOTCONN),
            }
        }

        // Phase 2: deliver/truncate any popped `AncillaryMark`.
        let mut out_flags = 0u32;
        let mut delivered = Vec::new();
        let mut dropped = Vec::new();
        let mut freed_slots = Vec::new();
        let mut out_cred = peer_cred;

        if let Some(mark) = delivered_mark {
            out_cred = mark.sender_cred;
            self.account_inflight_dequeue(mark.sender_uid, &mark.fds);
            if mark.fds.len() > max_fds {
                out_flags |= MSG_CTRUNC;
            }
            for (idx, fd) in mark.fds.into_iter().enumerate() {
                if idx < max_fds {
                    if let InFlightFd::UnixSocket(id) = fd
                        && let Some(s) = self.sockets.get_mut(&id)
                    {
                        *s.external_holders.entry(pid).or_insert(0) += 1;
                    }
                    delivered.push(fd);
                } else {
                    dropped.push(fd);
                }
            }
            if !dropped.is_empty() {
                let mut gc_batch = CleanupBatch::default();
                self.dispose_dropped_fds(&mut dropped, &mut gc_batch);
                freed_slots.extend(gc_batch.freed_slots);
                dropped.extend(gc_batch.dropped_fds);
            }
        }

        Ok(RecvOutcome {
            data,
            fds: delivered,
            dropped_fds: dropped,
            peer_cred: out_cred,
            sender_path: None,
            out_flags,
            max_stream_bytes,
            has_next_ancillary,
            next_ancillary_offset,
            freed_slots,
        })
    }

    /// Query `poll_oneoff` readiness for `sock_id`.
    pub fn poll(&self, pid: u32, sock_id: SockId, writing: bool) -> Result<PollStatus> {
        let sock = self.sockets.get(&sock_id).ok_or(Errno::EBADF)?;
        if !sock.is_held_by(pid) {
            return Err(Errno::EBADF);
        }
        match sock.sock_type {
            SockType::Dgram => {
                if !writing {
                    let nbytes = sock.dgram_queue.front().map_or(0, |m| m.data.len());
                    let has_msg = !sock.dgram_queue.is_empty();
                    let hangup = sock.dgram_shut_rd;
                    return Ok(PollStatus {
                        ready: has_msg || hangup,
                        nbytes,
                        hangup,
                    });
                }
                if sock.dgram_shut_wr {
                    return Ok(PollStatus {
                        ready: true,
                        nbytes: 0,
                        hangup: true,
                    });
                }
                if let Some((peer_id, _)) = &sock.dgram_peer {
                    let Some(peer) = self.sockets.get(peer_id) else {
                        return Ok(PollStatus {
                            ready: true,
                            nbytes: 0,
                            hangup: true,
                        });
                    };
                    if peer.dgram_shut_rd {
                        return Ok(PollStatus {
                            ready: true,
                            nbytes: 0,
                            hangup: true,
                        });
                    }
                    let room = UNIX_MAX_QUEUED_BYTES.saturating_sub(peer.dgram_queued_bytes);
                    let ready = peer.dgram_queue.len() < UNIX_MAX_QUEUED_MSGS && room > 0;
                    return Ok(PollStatus {
                        ready,
                        nbytes: room,
                        hangup: false,
                    });
                }
                Ok(PollStatus {
                    ready: true,
                    nbytes: UNIX_DGRAM_MAX,
                    hangup: false,
                })
            }
            SockType::Stream | SockType::Seqpacket => match &sock.state {
                SockState::Listening { pending, .. } => {
                    if writing {
                        return Ok(PollStatus {
                            ready: false,
                            nbytes: 0,
                            hangup: false,
                        });
                    }
                    Ok(PollStatus {
                        ready: !pending.is_empty(),
                        nbytes: pending.len(),
                        hangup: false,
                    })
                }
                SockState::Connected {
                    peer,
                    stream_buf,
                    ancillary,
                    packets,
                    shut_rd,
                    shut_wr,
                    peer_closed,
                    ..
                } => {
                    if !writing {
                        let (has_data, nbytes) = if sock.sock_type == SockType::Stream {
                            (
                                !stream_buf.is_empty() || !ancillary.is_empty(),
                                stream_buf.len(),
                            )
                        } else {
                            (
                                !packets.is_empty(),
                                packets.front().map_or(0, |m| m.data.len()),
                            )
                        };
                        let hangup = *shut_rd || *peer_closed;
                        Ok(PollStatus {
                            ready: has_data || hangup,
                            nbytes,
                            hangup,
                        })
                    } else {
                        if *shut_wr || *peer_closed {
                            return Ok(PollStatus {
                                ready: true,
                                nbytes: 0,
                                hangup: true,
                            });
                        }
                        let Some(peer_id) = peer else {
                            return Ok(PollStatus {
                                ready: true,
                                nbytes: 0,
                                hangup: true,
                            });
                        };
                        let Some(peer_sock) = self.sockets.get(peer_id) else {
                            return Ok(PollStatus {
                                ready: true,
                                nbytes: 0,
                                hangup: true,
                            });
                        };
                        match &peer_sock.state {
                            SockState::Connected {
                                stream_buf: pbuf,
                                packets: ppkts,
                                queued_packet_bytes: pbytes,
                                shut_rd: pshut_rd,
                                ..
                            } => {
                                if *pshut_rd {
                                    return Ok(PollStatus {
                                        ready: true,
                                        nbytes: 0,
                                        hangup: true,
                                    });
                                }
                                if sock.sock_type == SockType::Stream {
                                    let room = UNIX_MAX_QUEUED_BYTES.saturating_sub(pbuf.len());
                                    Ok(PollStatus {
                                        ready: room > 0,
                                        nbytes: room,
                                        hangup: false,
                                    })
                                } else {
                                    let room = UNIX_MAX_QUEUED_BYTES.saturating_sub(*pbytes);
                                    let ready = ppkts.len() < UNIX_MAX_QUEUED_MSGS && room > 0;
                                    Ok(PollStatus {
                                        ready,
                                        nbytes: room,
                                        hangup: false,
                                    })
                                }
                            }
                            _ => Ok(PollStatus {
                                ready: true,
                                nbytes: 0,
                                hangup: true,
                            }),
                        }
                    }
                }
                _ => Ok(PollStatus {
                    ready: false,
                    nbytes: 0,
                    hangup: true,
                }),
            },
        }
    }

    /// Close `count` external descriptor references held by `pid` on `sock_id`.
    /// Runs `unix_gc()` whenever any socket loses its last external holder while still in-flight.
    pub fn close(&mut self, pid: u32, sock_id: SockId, count: usize) -> Result<CleanupBatch> {
        let mut batch = CleanupBatch::default();
        let should_reap;
        let should_gc;
        {
            let sock = self.sockets.get_mut(&sock_id).ok_or(Errno::EBADF)?;
            let held = sock.external_holders.get_mut(&pid).ok_or(Errno::EBADF)?;
            if count >= *held {
                sock.external_holders.remove(&pid);
            } else {
                *held -= count;
            }
            let ext = sock.total_external_holders();
            should_reap = ext == 0 && sock.inflight_refs == 0;
            should_gc = ext == 0 && sock.inflight_refs > 0;
        }
        if should_reap {
            self.reap_socket_cascade(sock_id, &mut batch);
        }
        if should_gc {
            self.unix_gc(&mut batch);
        }
        Ok(batch)
    }

    /// Release ALL sockets held by an exiting or crashed process `pid`.
    pub fn release_process(&mut self, pid: u32) -> CleanupBatch {
        let mut batch = CleanupBatch::default();
        let held_ids: Vec<SockId> = self
            .sockets
            .iter()
            .filter(|(_, s)| s.is_held_by(pid))
            .map(|(&id, _)| id)
            .collect();
        let mut run_gc = false;
        let mut to_reap = Vec::new();
        for id in held_ids {
            if let Some(sock) = self.sockets.get_mut(&id) {
                sock.external_holders.remove(&pid);
                let ext = sock.total_external_holders();
                if ext == 0 {
                    if sock.inflight_refs == 0 {
                        to_reap.push(id);
                    } else {
                        run_gc = true;
                    }
                }
            }
        }
        for id in to_reap {
            self.reap_socket_cascade(id, &mut batch);
        }
        if run_gc {
            self.unix_gc(&mut batch);
        }
        batch
    }

    /// Dispose of truncated (`MSG_CTRUNC`) fds, returning non-socket fds in `dropped` and
    /// triggering `unix_gc()` / reaping for any `InFlightFd::UnixSocket` that became unreachable.
    fn dispose_dropped_fds(&mut self, dropped: &mut Vec<InFlightFd>, batch: &mut CleanupBatch) {
        let mut run_gc = false;
        let mut to_reap = Vec::new();
        let mut kept_non_sock = Vec::new();
        for fd in std::mem::take(dropped) {
            match fd {
                InFlightFd::UnixSocket(id) => {
                    if let Some(s) = self.sockets.get(&id)
                        && s.total_external_holders() == 0
                    {
                        if s.inflight_refs == 0 {
                            to_reap.push(id);
                        } else {
                            run_gc = true;
                        }
                    }
                }
                other => kept_non_sock.push(other),
            }
        }
        *dropped = kept_non_sock;
        for id in to_reap {
            self.reap_socket_cascade(id, batch);
        }
        if run_gc {
            self.unix_gc(batch);
        }
    }

    /// Reap one dead socket (`external_holders == 0 && inflight_refs == 0`) and cascade any
    /// newly orphaned sockets or cycles discovered while draining its queues.
    fn reap_socket_cascade(&mut self, start_id: SockId, batch: &mut CleanupBatch) {
        let mut work = VecDeque::new();
        work.push_back(start_id);
        let mut needs_gc = false;

        while let Some(id) = work.pop_front() {
            let Some(sock) = self.sockets.get(&id) else {
                continue;
            };
            if sock.total_external_holders() > 0 || sock.inflight_refs > 0 {
                continue;
            }
            let Some(dead) = self.sockets.remove(&id) else {
                continue;
            };
            self.finalize_removed_socket(dead, batch, &mut work, &mut needs_gc);
        }
        if needs_gc {
            self.unix_gc(batch);
        }
    }

    /// Mark-and-sweep cycle collector (`unix_gc()`):
    /// Finds all sockets reachable from external process holders (following listener accept queues
    /// and in-flight `SCM_RIGHTS` socket edges), then collects every unreachable socket cycle,
    /// draining all queued `InFlightFd`s, decrementing in-flight quotas, and freeing `SockArena` slots.
    pub fn unix_gc(&mut self, batch: &mut CleanupBatch) -> usize {
        let mut reachable: HashSet<SockId> = HashSet::new();
        let mut queue: VecDeque<SockId> = VecDeque::new();

        for (&id, sock) in &self.sockets {
            if sock.total_external_holders() > 0 && reachable.insert(id) {
                queue.push_back(id);
            }
        }

        while let Some(id) = queue.pop_front() {
            let Some(sock) = self.sockets.get(&id) else {
                continue;
            };
            for msg in &sock.dgram_queue {
                for fd in &msg.fds {
                    if let InFlightFd::UnixSocket(child) = fd
                        && self.sockets.contains_key(child)
                        && reachable.insert(*child)
                    {
                        queue.push_back(*child);
                    }
                }
            }
            match &sock.state {
                SockState::Listening { pending, .. } => {
                    for &child in pending {
                        if self.sockets.contains_key(&child) && reachable.insert(child) {
                            queue.push_back(child);
                        }
                    }
                }
                SockState::Connected {
                    ancillary, packets, ..
                } => {
                    for mark in ancillary {
                        for fd in &mark.fds {
                            if let InFlightFd::UnixSocket(child) = fd
                                && self.sockets.contains_key(child)
                                && reachable.insert(*child)
                            {
                                queue.push_back(*child);
                            }
                        }
                    }
                    for msg in packets {
                        for fd in &msg.fds {
                            if let InFlightFd::UnixSocket(child) = fd
                                && self.sockets.contains_key(child)
                                && reachable.insert(*child)
                            {
                                queue.push_back(*child);
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        let dead_ids: Vec<SockId> = self
            .sockets
            .keys()
            .copied()
            .filter(|id| !reachable.contains(id))
            .collect();

        if dead_ids.is_empty() {
            return 0;
        }

        let collected = dead_ids.len();
        let mut dead_sockets = Vec::with_capacity(collected);
        for id in dead_ids {
            if let Some(dead) = self.sockets.remove(&id) {
                dead_sockets.push(dead);
            }
        }

        let mut dummy_work = VecDeque::new();
        let mut dummy_gc = false;
        for dead in dead_sockets {
            self.finalize_removed_socket(dead, batch, &mut dummy_work, &mut dummy_gc);
        }
        collected
    }

    fn finalize_removed_socket(
        &mut self,
        mut dead: UnixSocket,
        batch: &mut CleanupBatch,
        work: &mut VecDeque<SockId>,
        needs_gc: &mut bool,
    ) {
        if let Some(key) = dead.bound_key.take()
            && self.bindings.get(&key) == Some(&dead.id)
        {
            self.bindings.remove(&key);
        }

        // Drain dgram queue.
        let dgrams: Vec<PacketMsg> = dead.dgram_queue.drain(..).collect();
        for msg in dgrams {
            self.drain_inflight_fds(msg.sender_uid, msg.fds, batch, work, needs_gc);
        }

        match dead.state {
            SockState::Listening { pending, .. } => {
                for pending_id in pending {
                    work.push_back(pending_id);
                }
            }
            SockState::Connected {
                peer,
                tx_slot,
                rx_slot,
                ancillary,
                packets,
                ..
            } => {
                for mark in ancillary {
                    self.drain_inflight_fds(mark.sender_uid, mark.fds, batch, work, needs_gc);
                }
                for msg in packets {
                    self.drain_inflight_fds(msg.sender_uid, msg.fds, batch, work, needs_gc);
                }
                // Notify surviving peer (if still alive in `self.sockets`), OR free shared
                // `SockArena` slots once BOTH ends of the channel are gone!
                let peer_alive = peer.is_some_and(|pid| self.sockets.contains_key(&pid));
                if let Some(peer_id) = peer
                    && let Some(peer_sock) = self.sockets.get_mut(&peer_id)
                    && let SockState::Connected {
                        peer: p_peer,
                        peer_closed,
                        shut_wr,
                        ..
                    } = &mut peer_sock.state
                {
                    *p_peer = None;
                    *peer_closed = true;
                    *shut_wr = true;
                }
                if peer_alive {
                    if let Some(tx) = tx_slot {
                        batch.peer_wr_closed.push(tx);
                    }
                    if let Some(rx) = rx_slot {
                        batch.peer_rd_closed.push(rx);
                    }
                } else {
                    if let Some(tx) = tx_slot
                        && let Some(freed) = self.arena.free(tx)
                    {
                        batch.freed_slots.push(freed);
                    }
                    if let Some(rx) = rx_slot
                        && let Some(freed) = self.arena.free(rx)
                    {
                        batch.freed_slots.push(freed);
                    }
                }
            }
            SockState::Unbound | SockState::Bound => {}
        }
    }

    fn drain_inflight_fds(
        &mut self,
        sender_uid: u32,
        fds: Vec<InFlightFd>,
        batch: &mut CleanupBatch,
        work: &mut VecDeque<SockId>,
        needs_gc: &mut bool,
    ) {
        if fds.is_empty() {
            return;
        }
        self.account_inflight_dequeue(sender_uid, &fds);
        for fd in fds {
            match fd {
                InFlightFd::UnixSocket(child_id) => {
                    if let Some(child) = self.sockets.get(&child_id)
                        && child.total_external_holders() == 0
                    {
                        if child.inflight_refs == 0 {
                            work.push_back(child_id);
                        } else {
                            *needs_gc = true;
                        }
                    }
                }
                other => batch.dropped_fds.push(other),
            }
        }
    }
}

//! Native host bridge for `/run/net/host.sock` (`#86` Phase 10a).
//!
//! Runs inside `os-native`'s `KernelActor`:
//! - Binds `/run/net/host.sock` (`0600`, uid 0) when verified `/usr/bin/netd` starts.
//! - Rejects any non-root or non-`netd` peer (`peer.uid == 0 && netd_pids.contains(&peer.pid)`).
//! - Extracts the originating guest `PeerCred` from the `SCM_RIGHTS`-transferred client socket
//!   via `UnixSocketTable::peer_cred` and immediately closes the host's duplicated ref.
//! - Intersects `NativeNetdConfig.policy` (default `None` -> default-deny!) with the client
//!   process's `cred.allowed_remote_scope.net` (if `allowed_remote_scope` is `Some`).
//! - Refuses `TlsMode::On` and `TlsMode::StartTls` with `EOPNOTSUPP` (never fakes TLS).
//! - Resolves DNS via `tokio::net::lookup_host` and checks EVERY returned `SocketAddr` through
//!   `NetScope::check_resolved_ip` BEFORE connecting `tokio::net::TcpStream::connect`.
//! - Runs full-duplex split `TcpStream` tasks with true credit-gated `tcp_read.read()` (pauses
//!   reading when `client_rx_credit == 0` -> zero OOM under slow-consumer backpressure),
//!   per-credential `max_concurrent_streams`, `max_bytes_per_stream`, `max_bytes_per_sec`,
//!   `connect_timeout_ms`, `idle_timeout_ms`, `max_stream_lifetime_ms`, `HALF_CLOSE` <-> `SHUT_WR`,
//!   and deterministic task abort on `CANCEL`, client exit, `netd` exit, or `KernelActor` drop.

use abi::Errno;
use abi::net_ctl::{
    DataFrame, HostNetReq, HostNetResp, LoopbackTestAllowlist, NET_CONTROL_MAX_BYTES,
    NET_DATA_CHUNK_MAX, NET_HOST_SOCK, NET_INITIAL_WINDOW_BYTES, NETD_VERSION, NetErrorKind,
    NetQuota, NetScope, ParsedHost, StreamClosed, TlsMode, decode_control_payload,
    encode_control_frame, encode_unix_data_frame, try_decode_unix_data_frame,
};
use abi::socket::PeerCred;
use os_kernel::proc_table::LocalProcessTable;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;
use vfs::unix_sock::{InFlightFd, SockId, SockType, SocketInodeKey, UnixSocketTable};
use vfs::{StartAnchor, Vfs};

const KERNEL_HOST_PID: u32 = 1;

/// Native outbound network policy configuration (default-deny when `policy` is `None`).
#[derive(Clone, Debug, Default)]
pub struct NativeNetdConfig {
    /// Host policy ceiling; `None` denies ALL outbound streams and DNS resolution.
    pub policy: Option<NetScope>,
    /// Two-key test-only loopback allowlist (empty by default; only exact `127.0.0.1:<port>` or `[::1]:<port>`).
    pub loopback_test_allowlist: LoopbackTestAllowlist,
}

struct PendingCtrl {
    netd_pid: u32,
    rx: Vec<u8>,
    client_sock: Option<SockId>,
    tx: VecDeque<u8>,
    close_after_tx: bool,
}

enum TcpCmd {
    Write(Vec<u8>),
    AddCredit(u32),
    HalfClose,
}

enum TcpEvent {
    Opened {
        stream_id: String,
        peer_addr: Option<String>,
        initial_window: u32,
        quota: NetQuota,
    },
    OpenError {
        errno: Errno,
        error: NetErrorKind,
        message: String,
    },
    Data(Vec<u8>),
    Credit(u32),
    HalfClose,
    Closed(StreamClosed),
}

struct ActiveNativeStream {
    netd_pid: u32,
    client_pid: u32,
    client_uid: u32,
    quota: NetQuota,
    bytes_sent: u64,
    opened: bool,
    host_rx: Vec<u8>,
    host_tx: VecDeque<u8>,
    cmd_tx: mpsc::UnboundedSender<TcpCmd>,
    evt_rx: mpsc::UnboundedReceiver<TcpEvent>,
    task: JoinHandle<()>,
    closing_after_tx: bool,
}

struct PendingResolve {
    netd_pid: u32,
    client_pid: u32,
    evt_rx: tokio::sync::oneshot::Receiver<HostNetResp>,
    task: JoinHandle<()>,
}

/// Kernel-side `/run/net/host.sock` server owned by `KernelActor`.
pub struct NetdHostServer {
    config: NativeNetdConfig,
    listener_id: Option<SockId>,
    notify: Arc<Notify>,
    pending_ctrl: HashMap<SockId, PendingCtrl>,
    active_streams: HashMap<SockId, ActiveNativeStream>,
    pending_resolves: HashMap<SockId, PendingResolve>,
    streams_by_uid: HashMap<u32, u32>,
    next_stream_seq: u64,
}

impl Default for NetdHostServer {
    fn default() -> Self {
        Self::new(NativeNetdConfig::default())
    }
}

impl Drop for NetdHostServer {
    fn drop(&mut self) {
        self.abort_all_tasks();
    }
}

impl NetdHostServer {
    pub fn new(config: NativeNetdConfig) -> Self {
        Self {
            config,
            listener_id: None,
            notify: Arc::new(Notify::new()),
            pending_ctrl: HashMap::new(),
            active_streams: HashMap::new(),
            pending_resolves: HashMap::new(),
            streams_by_uid: HashMap::new(),
            next_stream_seq: 1,
        }
    }

    pub fn notify_handle(&self) -> Arc<Notify> {
        Arc::clone(&self.notify)
    }

    pub fn active_stream_count(&self) -> u32 {
        self.active_streams.len() as u32
    }

    pub fn abort_all_tasks(&mut self) {
        for (_, st) in self.active_streams.drain() {
            st.task.abort();
        }
        for (_, r) in self.pending_resolves.drain() {
            r.task.abort();
        }
        self.streams_by_uid.clear();
    }

    /// Deterministically abort and clean up any streams/resolves tied to an exiting `netd` or client PID.
    pub fn on_process_exit(&mut self, pid: u32, socks: &mut UnixSocketTable) {
        let dead_streams: Vec<SockId> = self
            .active_streams
            .iter()
            .filter(|(_, s)| s.client_pid == pid || s.netd_pid == pid)
            .map(|(&id, _)| id)
            .collect();
        for sid in dead_streams {
            self.teardown_stream(sid, socks);
        }
        let dead_resolves: Vec<SockId> = self
            .pending_resolves
            .iter()
            .filter(|(_, r)| r.client_pid == pid || r.netd_pid == pid)
            .map(|(&id, _)| id)
            .collect();
        for sid in dead_resolves {
            if let Some(r) = self.pending_resolves.remove(&sid) {
                r.task.abort();
            }
            let _ = socks.close(KERNEL_HOST_PID, sid, 1);
        }
        let dead_ctrl: Vec<SockId> = self
            .pending_ctrl
            .iter()
            .filter(|(_, c)| c.netd_pid == pid)
            .map(|(&id, _)| id)
            .collect();
        for sid in dead_ctrl {
            if let Some(c) = self.pending_ctrl.remove(&sid)
                && let Some(cs) = c.client_sock
            {
                let _ = socks.close(KERNEL_HOST_PID, cs, 1);
            }
            let _ = socks.close(KERNEL_HOST_PID, sid, 1);
        }
    }

    /// Ensure `/run/net/host.sock` (`0600`, uid 0) is bound and listening on `/run`.
    pub async fn ensure_bound(&mut self, vfs: &Vfs, socks: &mut UnixSocketTable) {
        if let Some(id) = self.listener_id {
            if socks.describe(KERNEL_HOST_PID, id).is_ok() {
                return;
            }
            self.listener_id = None;
        }
        let _ = vfs
            .mkdirat(KERNEL_HOST_PID, StartAnchor::Root, "/run/net", 0o755)
            .await;
        let _ = vfs
            .unlinkat(KERNEL_HOST_PID, StartAnchor::Root, NET_HOST_SOCK, false)
            .await;
        let cred = PeerCred {
            pid: 1,
            uid: 0,
            gid: 0,
        };
        let Ok(sock_id) = socks.create(KERNEL_HOST_PID, SockType::Stream, cred) else {
            return;
        };
        let _ = socks.set_nonblock(KERNEL_HOST_PID, sock_id, true);
        if socks
            .begin_bind(KERNEL_HOST_PID, sock_id, NET_HOST_SOCK)
            .is_err()
        {
            let _ = socks.close(KERNEL_HOST_PID, sock_id, 1);
            return;
        }
        match vfs
            .mksockat_with_parent(KERNEL_HOST_PID, StartAnchor::Root, NET_HOST_SOCK, 0o600)
            .await
        {
            Ok((entry, _pin, _parent, _name)) => {
                let key = SocketInodeKey {
                    fs_id: entry.handle.fs.clone(),
                    node: entry.handle.node,
                };
                if socks
                    .finish_bind(KERNEL_HOST_PID, sock_id, key, NET_HOST_SOCK.to_string())
                    .is_ok()
                    && socks.listen(KERNEL_HOST_PID, sock_id, 32, cred).is_ok()
                {
                    let _ = vfs
                        .setattrat(
                            KERNEL_HOST_PID,
                            StartAnchor::Root,
                            NET_HOST_SOCK,
                            &vfs::SetAttr {
                                mode: Some(0o600),
                                uid: Some(0),
                                gid: Some(0),
                                ..vfs::SetAttr::default()
                            },
                            false,
                        )
                        .await;
                    self.listener_id = Some(sock_id);
                } else {
                    socks.abort_bind(sock_id);
                    let _ = socks.close(KERNEL_HOST_PID, sock_id, 1);
                }
            }
            Err(_) => {
                socks.abort_bind(sock_id);
                let _ = socks.close(KERNEL_HOST_PID, sock_id, 1);
            }
        }
    }

    fn teardown_stream(&mut self, sid: SockId, socks: &mut UnixSocketTable) {
        if let Some(st) = self.active_streams.remove(&sid) {
            st.task.abort();
            if let Some(cnt) = self.streams_by_uid.get_mut(&st.client_uid) {
                *cnt = cnt.saturating_sub(1);
                if *cnt == 0 {
                    self.streams_by_uid.remove(&st.client_uid);
                }
            }
        }
        let _ = socks.close(KERNEL_HOST_PID, sid, 1);
    }

    fn effective_scope(
        &self,
        procs: &Rc<RefCell<LocalProcessTable>>,
        client_peer: PeerCred,
    ) -> Result<NetScope, (Errno, NetErrorKind, String)> {
        let Some(host_policy) = self.config.policy.as_ref().filter(|p| !p.is_empty()) else {
            return Err((
                Errno::EACCES,
                NetErrorKind::PolicyDenied,
                "outbound networking disabled by host policy (default-deny)".into(),
            ));
        };
        let tbl = procs.borrow();
        let Some(proc) = tbl
            .proc(client_peer.pid)
            .filter(|p| p.state != abi::ProcState::Zombie)
        else {
            return Err((
                Errno::ESRCH,
                NetErrorKind::Canceled,
                "originating process is no longer live".into(),
            ));
        };
        if proc.cred.identity.id != client_peer.uid {
            return Err((
                Errno::EACCES,
                NetErrorKind::PolicyDenied,
                "client socket peer UID does not match live process identity".into(),
            ));
        }
        if let Some(ref cap) = proc.cred.allowed_remote_scope {
            let Some(ref proc_net) = cap.net else {
                return Err((
                    Errno::EACCES,
                    NetErrorKind::PolicyDenied,
                    "process capability grant prohibits outbound network access".into(),
                ));
            };
            host_policy.attenuate(proc_net).ok_or_else(|| {
                (
                    Errno::EACCES,
                    NetErrorKind::PolicyDenied,
                    "intersected host and process network policy permits no targets".into(),
                )
            })
        } else {
            Ok(host_policy.clone())
        }
    }

    /// Drive all pending connections, control requests, DNS resolves, and active streams.
    pub fn tick(
        &mut self,
        socks: &mut UnixSocketTable,
        procs: &Rc<RefCell<LocalProcessTable>>,
        netd_pids: &HashSet<u32>,
    ) -> bool {
        let mut did_work = false;
        let root_cred = PeerCred {
            pid: 1,
            uid: 0,
            gid: 0,
        };

        // 1. Accept new connections on `/run/net/host.sock` — strictly require `uid == 0 && netd_pids.contains(pid)`.
        if let Some(listener_id) = self.listener_id {
            while let Ok(accepted) = socks.accept(KERNEL_HOST_PID, listener_id, root_cred) {
                did_work = true;
                if accepted.peer_cred.uid != 0 || !netd_pids.contains(&accepted.peer_cred.pid) {
                    let err_frame = encode_control_frame(&HostNetResp::Error {
                        errno: Errno::EACCES,
                        error: NetErrorKind::PolicyDenied,
                        message: "untrusted netd host socket peer".into(),
                    })
                    .unwrap_or_default();
                    let _ = socks.sendmsg(
                        KERNEL_HOST_PID,
                        accepted.sock_id,
                        &err_frame,
                        Vec::new(),
                        None,
                        root_cred,
                        None,
                    );
                    let _ = socks.close(KERNEL_HOST_PID, accepted.sock_id, 1);
                    continue;
                }
                let _ = socks.set_nonblock(KERNEL_HOST_PID, accepted.sock_id, true);
                self.pending_ctrl.insert(
                    accepted.sock_id,
                    PendingCtrl {
                        netd_pid: accepted.peer_cred.pid,
                        rx: Vec::new(),
                        client_sock: None,
                        tx: VecDeque::new(),
                        close_after_tx: false,
                    },
                );
            }
        }

        // 2. Drive pending control handshakes.
        let ctrl_ids: Vec<SockId> = self.pending_ctrl.keys().copied().collect();
        for cid in ctrl_ids {
            // Drain any queued reply bytes first.
            let mut drop_ctrl = false;
            if let Some(ctrl) = self.pending_ctrl.get_mut(&cid)
                && !ctrl.tx.is_empty()
            {
                let sent_ok = flush_unix_tx(socks, cid, &mut ctrl.tx, root_cred);
                if !sent_ok {
                    drop_ctrl = true;
                } else {
                    did_work = true;
                    if ctrl.tx.is_empty() && ctrl.close_after_tx {
                        drop_ctrl = true;
                    }
                }
            }
            if drop_ctrl {
                if let Some(c) = self.pending_ctrl.remove(&cid)
                    && let Some(cs) = c.client_sock
                {
                    let _ = socks.close(KERNEL_HOST_PID, cs, 1);
                }
                let _ = socks.close(KERNEL_HOST_PID, cid, 1);
                continue;
            }
            if self.pending_ctrl.get(&cid).is_none_or(|c| c.close_after_tx) {
                continue;
            }

            let mut ready_req: Option<(u32, HostNetReq, Option<SockId>, Vec<u8>)> = None;
            let mut proto_err: Option<(Errno, NetErrorKind, String)> = None;
            let mut peer_closed = false;

            if let Some(ctrl) = self.pending_ctrl.get_mut(&cid) {
                match socks.recvmsg(KERNEL_HOST_PID, cid, 4096, 4, 0, None) {
                    Ok(recv) => {
                        did_work = true;
                        for in_fd in recv.fds {
                            if let InFlightFd::UnixSocket(cs) = in_fd {
                                if ctrl.client_sock.is_none() {
                                    ctrl.client_sock = Some(cs);
                                } else {
                                    let _ = socks.close(KERNEL_HOST_PID, cs, 1);
                                }
                            }
                        }
                        if recv.data.is_empty() {
                            peer_closed = true;
                        } else if ctrl.rx.len() + recv.data.len() > NET_CONTROL_MAX_BYTES + 4 {
                            proto_err = Some((
                                Errno::E2BIG,
                                NetErrorKind::ProtocolError,
                                "host control frame exceeds maximum length".into(),
                            ));
                        } else {
                            ctrl.rx.extend_from_slice(&recv.data);
                            if ctrl.rx.len() >= 4 {
                                let len = u32::from_be_bytes([
                                    ctrl.rx[0], ctrl.rx[1], ctrl.rx[2], ctrl.rx[3],
                                ]) as usize;
                                if len == 0 || len > NET_CONTROL_MAX_BYTES {
                                    proto_err = Some((
                                        Errno::EINVAL,
                                        NetErrorKind::ProtocolError,
                                        "invalid host control length".into(),
                                    ));
                                } else if ctrl.rx.len() >= 4 + len {
                                    let payload = ctrl.rx[4..4 + len].to_vec();
                                    let leftover = ctrl.rx[4 + len..].to_vec();
                                    match decode_control_payload::<HostNetReq>(&payload) {
                                        Ok(req) => {
                                            ready_req = Some((
                                                ctrl.netd_pid,
                                                req,
                                                ctrl.client_sock.take(),
                                                leftover,
                                            ));
                                        }
                                        Err(e) => {
                                            proto_err = Some((
                                                e.errno,
                                                NetErrorKind::ProtocolError,
                                                e.to_string(),
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(Errno::EAGAIN) => {}
                    Err(_) => peer_closed = true,
                }
            }

            if peer_closed {
                if let Some(c) = self.pending_ctrl.remove(&cid)
                    && let Some(cs) = c.client_sock
                {
                    let _ = socks.close(KERNEL_HOST_PID, cs, 1);
                }
                let _ = socks.close(KERNEL_HOST_PID, cid, 1);
                continue;
            }
            if let Some((errno, error, message)) = proto_err {
                if let Some(ctrl) = self.pending_ctrl.get_mut(&cid) {
                    if let Some(cs) = ctrl.client_sock.take() {
                        let _ = socks.close(KERNEL_HOST_PID, cs, 1);
                    }
                    if let Ok(frame) = encode_control_frame(&HostNetResp::Error {
                        errno,
                        error,
                        message,
                    }) {
                        ctrl.tx.extend(frame);
                    }
                    ctrl.close_after_tx = true;
                    let _ = flush_unix_tx(socks, cid, &mut ctrl.tx, root_cred);
                    if ctrl.tx.is_empty() {
                        self.pending_ctrl.remove(&cid);
                        let _ = socks.close(KERNEL_HOST_PID, cid, 1);
                    }
                }
                continue;
            }

            if let Some((netd_pid, req, client_sock_opt, leftover)) = ready_req {
                self.pending_ctrl.remove(&cid);
                // Extract `client_peer` and IMMEDIATELY close host's duplicated `client_sock` ref!
                let client_peer = client_sock_opt.and_then(|cs| {
                    let cred = socks.peer_cred(KERNEL_HOST_PID, cs).ok();
                    let _ = socks.close(KERNEL_HOST_PID, cs, 1);
                    cred
                });
                self.dispatch_host_req(
                    cid,
                    netd_pid,
                    req,
                    client_peer,
                    leftover,
                    socks,
                    procs,
                    root_cred,
                );
            }
        }

        // 3. Poll completed async DNS resolves.
        let res_ids: Vec<SockId> = self.pending_resolves.keys().copied().collect();
        for sid in res_ids {
            let done = match self.pending_resolves.get_mut(&sid) {
                Some(pr) => match pr.evt_rx.try_recv() {
                    Ok(resp) => Some(resp),
                    Err(tokio::sync::oneshot::error::TryRecvError::Empty) => None,
                    Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                        Some(HostNetResp::Error {
                            errno: Errno::EIO,
                            error: NetErrorKind::ConnectFailed,
                            message: "DNS resolver task aborted".into(),
                        })
                    }
                },
                None => None,
            };
            if let Some(resp) = done {
                did_work = true;
                self.pending_resolves.remove(&sid);
                self.send_ctrl_reply_and_close(sid, resp, socks, root_cred);
            }
        }

        // 4. Drive active streams (TCP events -> `host_tx` -> `netd`, `netd` -> `host_rx` -> TCP cmds).
        let stream_ids: Vec<SockId> = self.active_streams.keys().copied().collect();
        for sid in stream_ids {
            let mut should_teardown = false;
            if let Some(st) = self.active_streams.get_mut(&sid) {
                // 4a. Drain TCP events into `host_tx` (and detect task exit/panic via Disconnected).
                loop {
                    match st.evt_rx.try_recv() {
                        Ok(evt) => {
                            did_work = true;
                            match evt {
                                TcpEvent::Opened {
                                    stream_id,
                                    peer_addr,
                                    initial_window,
                                    quota,
                                } => {
                                    st.opened = true;
                                    if let Ok(frame) = encode_control_frame(&HostNetResp::Opened {
                                        stream_id,
                                        peer_addr,
                                        initial_window,
                                        quota,
                                    }) {
                                        st.host_tx.extend(frame);
                                    }
                                }
                                TcpEvent::OpenError {
                                    errno,
                                    error,
                                    message,
                                } => {
                                    if let Ok(frame) = encode_control_frame(&HostNetResp::Error {
                                        errno,
                                        error,
                                        message,
                                    }) {
                                        st.host_tx.extend(frame);
                                    }
                                    st.closing_after_tx = true;
                                }
                                TcpEvent::Data(bytes) => {
                                    if let Ok(frame) =
                                        encode_unix_data_frame(&DataFrame::Data(bytes))
                                    {
                                        st.host_tx.extend(frame);
                                    }
                                }
                                TcpEvent::Credit(n) => {
                                    if let Ok(frame) = encode_unix_data_frame(&DataFrame::Credit(n))
                                    {
                                        st.host_tx.extend(frame);
                                    }
                                }
                                TcpEvent::HalfClose => {
                                    if let Ok(frame) = encode_unix_data_frame(&DataFrame::HalfClose)
                                    {
                                        st.host_tx.extend(frame);
                                    }
                                }
                                TcpEvent::Closed(info) => {
                                    if let Ok(frame) =
                                        encode_unix_data_frame(&DataFrame::Closed(info))
                                    {
                                        st.host_tx.extend(frame);
                                    }
                                    st.closing_after_tx = true;
                                }
                            }
                        }
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            did_work = true;
                            st.closing_after_tx = true;
                            break;
                        }
                    }
                }

                // 4b. Flush `host_tx` to `netd`.
                if !st.host_tx.is_empty() {
                    if !flush_unix_tx(socks, sid, &mut st.host_tx, root_cred) {
                        should_teardown = true;
                    } else {
                        did_work = true;
                    }
                }
                if st.closing_after_tx && st.host_tx.is_empty() {
                    should_teardown = true;
                }

                // 4c. Read data/credit/cancel frames from `netd` -> forward to TCP task.
                if !should_teardown && !st.closing_after_tx {
                    loop {
                        match socks.recvmsg(
                            KERNEL_HOST_PID,
                            sid,
                            NET_DATA_CHUNK_MAX + 64,
                            0,
                            0,
                            None,
                        ) {
                            Ok(recv) => {
                                did_work = true;
                                if recv.data.is_empty() {
                                    should_teardown = true;
                                    break;
                                }
                                st.host_rx.extend_from_slice(&recv.data);
                                if st.host_rx.len() > (NET_INITIAL_WINDOW_BYTES as usize) * 2 + 4096
                                {
                                    should_teardown = true;
                                    break;
                                }
                            }
                            Err(Errno::EAGAIN) => break,
                            Err(_) => {
                                should_teardown = true;
                                break;
                            }
                        }
                    }
                    while !should_teardown {
                        match try_decode_unix_data_frame(&st.host_rx) {
                            Ok(Some((frame, used))) => {
                                st.host_rx.drain(..used);
                                match frame {
                                    DataFrame::Data(bytes) => {
                                        if !st.opened {
                                            should_teardown = true;
                                            break;
                                        }
                                        if bytes.is_empty() {
                                            continue;
                                        }
                                        let next = st.bytes_sent.saturating_add(bytes.len() as u64);
                                        if next > st.quota.max_bytes_per_stream {
                                            if let Ok(f) = encode_unix_data_frame(
                                                &DataFrame::Closed(StreamClosed {
                                                    errno: Some(Errno::EDQUOT),
                                                    error: Some(NetErrorKind::QuotaExceeded),
                                                    message: Some(
                                                        "stream exceeded max_bytes_per_stream"
                                                            .into(),
                                                    ),
                                                    bytes_sent: st.bytes_sent,
                                                    bytes_received: 0,
                                                }),
                                            ) {
                                                st.host_tx.extend(f);
                                                let _ = flush_unix_tx(
                                                    socks,
                                                    sid,
                                                    &mut st.host_tx,
                                                    root_cred,
                                                );
                                            }
                                            st.closing_after_tx = true;
                                            st.task.abort();
                                            if st.host_tx.is_empty() {
                                                should_teardown = true;
                                            }
                                            break;
                                        }
                                        st.bytes_sent = next;
                                        if st.cmd_tx.send(TcpCmd::Write(bytes)).is_err() {
                                            should_teardown = true;
                                            break;
                                        }
                                    }
                                    DataFrame::Credit(n) => {
                                        if st.cmd_tx.send(TcpCmd::AddCredit(n)).is_err() {
                                            should_teardown = true;
                                            break;
                                        }
                                    }
                                    DataFrame::HalfClose => {
                                        let _ = st.cmd_tx.send(TcpCmd::HalfClose);
                                    }
                                    DataFrame::Cancel => {
                                        should_teardown = true;
                                        break;
                                    }
                                    DataFrame::Closed(_) => {
                                        should_teardown = true;
                                        break;
                                    }
                                }
                            }
                            Ok(None) => break,
                            Err(_) => {
                                should_teardown = true;
                                break;
                            }
                        }
                    }
                }
            }
            if should_teardown {
                self.teardown_stream(sid, socks);
                did_work = true;
            }
        }

        did_work
    }

    fn send_ctrl_reply_and_close(
        &mut self,
        sid: SockId,
        resp: HostNetResp,
        socks: &mut UnixSocketTable,
        root_cred: PeerCred,
    ) {
        let mut tx = VecDeque::new();
        if let Ok(frame) = encode_control_frame(&resp) {
            tx.extend(frame);
        }
        let ok = flush_unix_tx(socks, sid, &mut tx, root_cred);
        if ok && !tx.is_empty() {
            self.pending_ctrl.insert(
                sid,
                PendingCtrl {
                    netd_pid: 0,
                    rx: Vec::new(),
                    client_sock: None,
                    tx,
                    close_after_tx: true,
                },
            );
        } else {
            let _ = socks.close(KERNEL_HOST_PID, sid, 1);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn dispatch_host_req(
        &mut self,
        sid: SockId,
        netd_pid: u32,
        req: HostNetReq,
        client_peer: Option<PeerCred>,
        leftover: Vec<u8>,
        socks: &mut UnixSocketTable,
        procs: &Rc<RefCell<LocalProcessTable>>,
        root_cred: PeerCred,
    ) {
        match req {
            HostNetReq::Hello { versions } => {
                let resp = if versions.contains(&NETD_VERSION) {
                    HostNetResp::Welcome {
                        version: NETD_VERSION,
                        host_kind: "os-native".into(),
                    }
                } else {
                    HostNetResp::Error {
                        errno: Errno::EPROTONOSUPPORT,
                        error: NetErrorKind::ProtocolError,
                        message: format!("netd v{NETD_VERSION} required"),
                    }
                };
                self.send_ctrl_reply_and_close(sid, resp, socks, root_cred);
            }
            HostNetReq::Status {} => {
                let resp = HostNetResp::Status {
                    version: NETD_VERSION,
                    host_kind: "os-native".into(),
                    active_streams: self.active_streams.len() as u32,
                    ready: true,
                };
                self.send_ctrl_reply_and_close(sid, resp, socks, root_cred);
            }
            HostNetReq::Resolve { host, port } => {
                let Some(client_peer) = client_peer else {
                    self.send_ctrl_reply_and_close(
                        sid,
                        HostNetResp::Error {
                            errno: Errno::EINVAL,
                            error: NetErrorKind::InvalidArgument,
                            message: "Resolve requires SCM_RIGHTS client socket".into(),
                        },
                        socks,
                        root_cred,
                    );
                    return;
                };
                let eff = match self.effective_scope(procs, client_peer) {
                    Ok(s) => s,
                    Err((errno, error, message)) => {
                        self.send_ctrl_reply_and_close(
                            sid,
                            HostNetResp::Error {
                                errno,
                                error,
                                message,
                            },
                            socks,
                            root_cred,
                        );
                        return;
                    }
                };
                let parsed =
                    match eff.check_resolve(&host, port, &self.config.loopback_test_allowlist) {
                        Ok(p) => p,
                        Err(f) => {
                            self.send_ctrl_reply_and_close(
                                sid,
                                HostNetResp::Error {
                                    errno: f.errno,
                                    error: f.kind,
                                    message: f.message,
                                },
                                socks,
                                root_cred,
                            );
                            return;
                        }
                    };
                let allowlist = self.config.loopback_test_allowlist.clone();
                let notify = Arc::clone(&self.notify);
                let (evt_tx, evt_rx) = tokio::sync::oneshot::channel();
                let task = tokio::task::spawn_local(async move {
                    let resp = run_ssrf_resolve(eff, allowlist, parsed, host, port).await;
                    let _ = evt_tx.send(resp);
                    notify.notify_one();
                });
                self.pending_resolves.insert(
                    sid,
                    PendingResolve {
                        netd_pid,
                        client_pid: client_peer.pid,
                        evt_rx,
                        task,
                    },
                );
            }
            HostNetReq::Open {
                host,
                port,
                tls,
                timeout_ms,
            } => {
                let Some(client_peer) = client_peer else {
                    self.send_ctrl_reply_and_close(
                        sid,
                        HostNetResp::Error {
                            errno: Errno::EINVAL,
                            error: NetErrorKind::InvalidArgument,
                            message: "Open requires SCM_RIGHTS client socket".into(),
                        },
                        socks,
                        root_cred,
                    );
                    return;
                };
                if tls != TlsMode::Off {
                    self.send_ctrl_reply_and_close(
                        sid,
                        HostNetResp::Error {
                            errno: Errno::EOPNOTSUPP,
                            error: NetErrorKind::Unsupported,
                            message: "os-native does not terminate gateway TLS (use TlsMode::Off)"
                                .into(),
                        },
                        socks,
                        root_cred,
                    );
                    return;
                }
                let eff = match self.effective_scope(procs, client_peer) {
                    Ok(s) => s,
                    Err((errno, error, message)) => {
                        self.send_ctrl_reply_and_close(
                            sid,
                            HostNetResp::Error {
                                errno,
                                error,
                                message,
                            },
                            socks,
                            root_cred,
                        );
                        return;
                    }
                };
                let parsed = match eff.check_egress(
                    &host,
                    port,
                    tls,
                    &self.config.loopback_test_allowlist,
                ) {
                    Ok(p) => p,
                    Err(f) => {
                        self.send_ctrl_reply_and_close(
                            sid,
                            HostNetResp::Error {
                                errno: f.errno,
                                error: f.kind,
                                message: f.message,
                            },
                            socks,
                            root_cred,
                        );
                        return;
                    }
                };
                let quota = match eff.quota.clamped() {
                    Ok(q) => q,
                    Err(e) => {
                        self.send_ctrl_reply_and_close(
                            sid,
                            HostNetResp::Error {
                                errno: e.errno,
                                error: NetErrorKind::PolicyDenied,
                                message: e.to_string(),
                            },
                            socks,
                            root_cred,
                        );
                        return;
                    }
                };
                let cur_count = self
                    .streams_by_uid
                    .get(&client_peer.uid)
                    .copied()
                    .unwrap_or(0);
                if cur_count >= quota.max_concurrent_streams {
                    self.send_ctrl_reply_and_close(
                        sid,
                        HostNetResp::Error {
                            errno: Errno::EDQUOT,
                            error: NetErrorKind::QuotaExceeded,
                            message: format!(
                                "concurrent stream limit ({}) exceeded",
                                quota.max_concurrent_streams
                            ),
                        },
                        socks,
                        root_cred,
                    );
                    return;
                }
                *self.streams_by_uid.entry(client_peer.uid).or_insert(0) += 1;

                let stream_id = format!("nat-{}", self.next_stream_seq);
                self.next_stream_seq += 1;
                let connect_timeout_ms = timeout_ms
                    .map(|t| t.clamp(1, quota.connect_timeout_ms))
                    .unwrap_or(quota.connect_timeout_ms);
                let allowlist = self.config.loopback_test_allowlist.clone();
                let notify = Arc::clone(&self.notify);
                let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
                let (evt_tx, evt_rx) = mpsc::unbounded_channel();
                let q_clone = quota.clone();
                let task = tokio::task::spawn_local(async move {
                    run_native_tcp_stream(
                        stream_id,
                        eff,
                        allowlist,
                        parsed,
                        host,
                        port,
                        tls,
                        connect_timeout_ms,
                        q_clone,
                        cmd_rx,
                        evt_tx,
                        notify,
                    )
                    .await;
                });

                self.active_streams.insert(
                    sid,
                    ActiveNativeStream {
                        netd_pid,
                        client_pid: client_peer.pid,
                        client_uid: client_peer.uid,
                        quota,
                        bytes_sent: 0,
                        opened: false,
                        host_rx: leftover,
                        host_tx: VecDeque::new(),
                        cmd_tx,
                        evt_rx,
                        task,
                        closing_after_tx: false,
                    },
                );
            }
        }
    }
}

fn flush_unix_tx(
    socks: &mut UnixSocketTable,
    sid: SockId,
    tx: &mut VecDeque<u8>,
    root_cred: PeerCred,
) -> bool {
    while !tx.is_empty() {
        let (front, _) = tx.as_slices();
        if front.is_empty() {
            tx.make_contiguous();
            continue;
        }
        let chunk_len = front.len().min(NET_DATA_CHUNK_MAX);
        match socks.sendmsg(
            KERNEL_HOST_PID,
            sid,
            &front[..chunk_len],
            Vec::new(),
            None,
            root_cred,
            None,
        ) {
            Ok(outcome) => {
                if outcome.sent == 0 {
                    return false;
                }
                tx.drain(..outcome.sent);
            }
            Err(Errno::EAGAIN) => break,
            Err(_) => return false,
        }
    }
    true
}

async fn run_ssrf_resolve(
    scope: NetScope,
    allowlist: LoopbackTestAllowlist,
    parsed: ParsedHost,
    host: String,
    port: u16,
) -> HostNetResp {
    let lookup_port = if port == 0 { 80 } else { port };
    if let ParsedHost::Ip(ip) = parsed {
        return HostNetResp::Resolved {
            addrs: vec![ip.to_string()],
        };
    }
    let resolved = match tokio::time::timeout(
        Duration::from_millis(5_000),
        tokio::net::lookup_host((host.as_str(), lookup_port)),
    )
    .await
    {
        Ok(Ok(iter)) => iter.collect::<Vec<SocketAddr>>(),
        Ok(Err(e)) => {
            return HostNetResp::Error {
                errno: Errno::ENOENT,
                error: NetErrorKind::ConnectFailed,
                message: format!("DNS lookup failed: {e}"),
            };
        }
        Err(_) => {
            return HostNetResp::Error {
                errno: Errno::ETIMEDOUT,
                error: NetErrorKind::Timeout,
                message: "DNS lookup timed out".into(),
            };
        }
    };
    if resolved.is_empty() {
        return HostNetResp::Error {
            errno: Errno::ENOENT,
            error: NetErrorKind::ConnectFailed,
            message: "DNS lookup returned no addresses".into(),
        };
    }
    let mut addrs = Vec::new();
    for sa in resolved {
        if let Err(f) =
            scope.check_resolved_ip(&parsed, sa.ip(), lookup_port, TlsMode::Off, &allowlist)
        {
            return HostNetResp::Error {
                errno: f.errno,
                error: f.kind,
                message: f.message,
            };
        }
        let s = sa.ip().to_string();
        if !addrs.contains(&s) {
            addrs.push(s);
        }
    }
    HostNetResp::Resolved { addrs }
}

fn map_connect_io_error(err: &std::io::Error) -> (Errno, NetErrorKind, String) {
    match err.kind() {
        std::io::ErrorKind::ConnectionRefused => (
            Errno::ECONNREFUSED,
            NetErrorKind::ConnectFailed,
            err.to_string(),
        ),
        std::io::ErrorKind::TimedOut => (Errno::ETIMEDOUT, NetErrorKind::Timeout, err.to_string()),
        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted => (
            Errno::ECONNRESET,
            NetErrorKind::StreamReset,
            err.to_string(),
        ),
        std::io::ErrorKind::AddrNotAvailable => (
            Errno::EADDRNOTAVAIL,
            NetErrorKind::ConnectFailed,
            err.to_string(),
        ),
        _ => (Errno::EIO, NetErrorKind::ConnectFailed, err.to_string()),
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_native_tcp_stream(
    stream_id: String,
    scope: NetScope,
    allowlist: LoopbackTestAllowlist,
    parsed: ParsedHost,
    host: String,
    port: u16,
    tls: TlsMode,
    connect_timeout_ms: u64,
    quota: NetQuota,
    mut cmd_rx: mpsc::UnboundedReceiver<TcpCmd>,
    evt_tx: mpsc::UnboundedSender<TcpEvent>,
    notify: Arc<Notify>,
) {
    let send_evt = |evt: TcpEvent| {
        let _ = evt_tx.send(evt);
        notify.notify_one();
    };

    // 1. Resolve target & SSRF-verify EVERY returned address BEFORE dialing!
    let connect_deadline = tokio::time::Instant::now() + Duration::from_millis(connect_timeout_ms);
    let addrs: Vec<SocketAddr> = match &parsed {
        ParsedHost::Ip(ip) => {
            if let Err(f) = scope.check_resolved_ip(&parsed, *ip, port, tls, &allowlist) {
                send_evt(TcpEvent::OpenError {
                    errno: f.errno,
                    error: f.kind,
                    message: f.message,
                });
                return;
            }
            vec![SocketAddr::new(*ip, port)]
        }
        ParsedHost::Domain(_) => {
            let lookup = tokio::time::timeout_at(
                connect_deadline,
                tokio::net::lookup_host((host.as_str(), port)),
            )
            .await;
            let iter = match lookup {
                Ok(Ok(it)) => it,
                Ok(Err(e)) => {
                    send_evt(TcpEvent::OpenError {
                        errno: Errno::ECONNREFUSED,
                        error: NetErrorKind::ConnectFailed,
                        message: format!("DNS lookup failed: {e}"),
                    });
                    return;
                }
                Err(_) => {
                    send_evt(TcpEvent::OpenError {
                        errno: Errno::ETIMEDOUT,
                        error: NetErrorKind::Timeout,
                        message: "DNS lookup timed out".into(),
                    });
                    return;
                }
            };
            let list: Vec<SocketAddr> = iter.collect();
            if list.is_empty() {
                send_evt(TcpEvent::OpenError {
                    errno: Errno::ECONNREFUSED,
                    error: NetErrorKind::ConnectFailed,
                    message: "DNS lookup returned no addresses".into(),
                });
                return;
            }
            for sa in &list {
                if let Err(f) = scope.check_resolved_ip(&parsed, sa.ip(), port, tls, &allowlist) {
                    send_evt(TcpEvent::OpenError {
                        errno: f.errno,
                        error: f.kind,
                        message: f.message,
                    });
                    return;
                }
            }
            list
        }
    };

    // 2. Dial validated addresses strictly within `connect_deadline`.
    let mut connected: Option<TcpStream> = None;
    let mut last_err: Option<(Errno, NetErrorKind, String)> = None;
    for sa in addrs {
        match tokio::time::timeout_at(connect_deadline, TcpStream::connect(sa)).await {
            Ok(Ok(stream)) => {
                // Re-check actual peer_addr post-connect as defense in depth!
                if let Ok(peer) = stream.peer_addr()
                    && let Err(f) =
                        scope.check_resolved_ip(&parsed, peer.ip(), peer.port(), tls, &allowlist)
                {
                    send_evt(TcpEvent::OpenError {
                        errno: f.errno,
                        error: f.kind,
                        message: f.message,
                    });
                    return;
                }
                let _ = stream.set_nodelay(true);
                connected = Some(stream);
                break;
            }
            Ok(Err(e)) => {
                last_err = Some(map_connect_io_error(&e));
            }
            Err(_) => {
                last_err = Some((
                    Errno::ETIMEDOUT,
                    NetErrorKind::Timeout,
                    "TCP connect timed out".into(),
                ));
                break;
            }
        }
    }
    let Some(stream) = connected else {
        let (errno, error, message) = last_err.unwrap_or((
            Errno::ECONNREFUSED,
            NetErrorKind::ConnectFailed,
            "TCP connect failed".into(),
        ));
        send_evt(TcpEvent::OpenError {
            errno,
            error,
            message,
        });
        return;
    };

    let peer_addr = stream.peer_addr().ok().map(|sa| sa.to_string());
    send_evt(TcpEvent::Opened {
        stream_id,
        peer_addr,
        initial_window: NET_INITIAL_WINDOW_BYTES,
        quota: quota.clone(),
    });

    // 3. Full-duplex credit-gated TCP pump with multiplexed non-blocking reads, writes, half-close,
    //    rate-pacing, idle timeout, lifetime cap, and combined TX+RX byte cap!
    let (mut tcp_read, mut tcp_write) = stream.into_split();
    let mut client_rx_credit: u32 = NET_INITIAL_WINDOW_BYTES;
    let mut bytes_sent: u64 = 0;
    let mut bytes_received: u64 = 0;
    let mut tcp_eof = false;
    let mut client_eof = false;
    let mut tx_queue: VecDeque<Vec<u8>> = VecDeque::new();
    let mut tx_front_pos: usize = 0;
    let mut pending_client_half_close = false;
    let mut shutdown_pending = false;
    let mut read_buf = vec![0u8; NET_DATA_CHUNK_MAX];

    let max_lifetime_at =
        tokio::time::Instant::now() + Duration::from_millis(quota.max_stream_lifetime_ms);
    let mut idle_deadline =
        tokio::time::Instant::now() + Duration::from_millis(quota.idle_timeout_ms);
    let mut rate_window_start = tokio::time::Instant::now();
    let mut rate_window_bytes: u64 = 0;
    let mut pace_until: Option<tokio::time::Instant> = None;

    let mut close_info = StreamClosed::default();

    loop {
        if tcp_eof && client_eof {
            close_info.bytes_sent = bytes_sent;
            close_info.bytes_received = bytes_received;
            break;
        }
        let now = tokio::time::Instant::now();
        if let Some(pu) = pace_until
            && now >= pu
        {
            pace_until = None;
            rate_window_start = now;
            rate_window_bytes = 0;
        }
        let throttled = pace_until.is_some();
        let next_deadline = max_lifetime_at.min(idle_deadline);
        let can_read_tcp = !tcp_eof && client_rx_credit > 0 && !throttled;
        let can_write_tcp = !tx_queue.is_empty() && !throttled;
        let read_cap = (client_rx_credit as usize).min(NET_DATA_CHUNK_MAX);
        let pace_wake = pace_until.unwrap_or(next_deadline);

        tokio::select! {
            _ = tokio::time::sleep_until(next_deadline) => {
                let now = tokio::time::Instant::now();
                let msg = if now >= max_lifetime_at {
                    "stream exceeded max_stream_lifetime_ms"
                } else {
                    "stream exceeded idle_timeout_ms"
                };
                close_info = StreamClosed {
                    errno: Some(Errno::ETIMEDOUT),
                    error: Some(NetErrorKind::Timeout),
                    message: Some(msg.into()),
                    bytes_sent,
                    bytes_received,
                };
                break;
            }
            _ = tokio::time::sleep_until(pace_wake), if throttled => {
                pace_until = None;
                rate_window_start = tokio::time::Instant::now();
                rate_window_bytes = 0;
            }
            res = tcp_read.read(&mut read_buf[..read_cap]), if can_read_tcp => {
                match res {
                    Ok(0) => {
                        tcp_eof = true;
                        send_evt(TcpEvent::HalfClose);
                    }
                    Ok(n) => {
                        let next_rx = bytes_received.saturating_add(n as u64);
                        if bytes_sent.saturating_add(next_rx) > quota.max_bytes_per_stream {
                            close_info = StreamClosed {
                                errno: Some(Errno::EDQUOT),
                                error: Some(NetErrorKind::QuotaExceeded),
                                message: Some("stream exceeded max_bytes_per_stream".into()),
                                bytes_sent,
                                bytes_received,
                            };
                            break;
                        }
                        bytes_received = next_rx;
                        client_rx_credit = client_rx_credit.saturating_sub(n as u32);
                        idle_deadline = tokio::time::Instant::now() + Duration::from_millis(quota.idle_timeout_ms);
                        send_evt(TcpEvent::Data(read_buf[..n].to_vec()));
                        pace_until = update_rate_pace(
                            &quota,
                            &mut rate_window_start,
                            &mut rate_window_bytes,
                            n as u64,
                        );
                    }
                    Err(e) => {
                        close_info = StreamClosed {
                            errno: Some(Errno::ECONNRESET),
                            error: Some(NetErrorKind::StreamReset),
                            message: Some(e.to_string()),
                            bytes_sent,
                            bytes_received,
                        };
                        break;
                    }
                }
            }
            res = async {
                if shutdown_pending {
                    tcp_write.shutdown().await.map(|()| None)
                } else {
                    let slice = &tx_queue.front().unwrap()[tx_front_pos..];
                    tcp_write.write(slice).await.map(Some)
                }
            }, if can_write_tcp || shutdown_pending => {
                match res {
                    Ok(None) => {
                        shutdown_pending = false;
                        client_eof = true;
                    }
                    Ok(Some(0)) => {
                        close_info = StreamClosed {
                            errno: Some(Errno::ECONNRESET),
                            error: Some(NetErrorKind::StreamReset),
                            message: Some("remote write closed".into()),
                            bytes_sent,
                            bytes_received,
                        };
                        break;
                    }
                    Ok(Some(n)) => {
                        let next_tx = bytes_sent.saturating_add(n as u64);
                        if next_tx.saturating_add(bytes_received) > quota.max_bytes_per_stream {
                            close_info = StreamClosed {
                                errno: Some(Errno::EDQUOT),
                                error: Some(NetErrorKind::QuotaExceeded),
                                message: Some("stream exceeded max_bytes_per_stream".into()),
                                bytes_sent,
                                bytes_received,
                            };
                            break;
                        }
                        bytes_sent = next_tx;
                        tx_front_pos += n;
                        if tx_queue.front().is_some_and(|f| tx_front_pos >= f.len()) {
                            tx_queue.pop_front();
                            tx_front_pos = 0;
                        }
                        idle_deadline = tokio::time::Instant::now() + Duration::from_millis(quota.idle_timeout_ms);
                        send_evt(TcpEvent::Credit(n as u32));
                        pace_until = update_rate_pace(
                            &quota,
                            &mut rate_window_start,
                            &mut rate_window_bytes,
                            n as u64,
                        );
                        if tx_queue.is_empty() && pending_client_half_close && !client_eof {
                            pending_client_half_close = false;
                            shutdown_pending = true;
                        }
                    }
                    Err(e) => {
                        if shutdown_pending {
                            shutdown_pending = false;
                            client_eof = true;
                        } else {
                            close_info = StreamClosed {
                                errno: Some(Errno::ECONNRESET),
                                error: Some(NetErrorKind::StreamReset),
                                message: Some(e.to_string()),
                                bytes_sent,
                                bytes_received,
                            };
                            break;
                        }
                    }
                }
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(TcpCmd::AddCredit(c)) => {
                        client_rx_credit = client_rx_credit
                            .saturating_add(c)
                            .min(NET_INITIAL_WINDOW_BYTES);
                    }
                    Some(TcpCmd::Write(bytes)) => {
                        if client_eof || pending_client_half_close || shutdown_pending || bytes.is_empty() {
                            continue;
                        }
                        let queued_bytes: u64 = tx_queue
                            .iter()
                            .enumerate()
                            .map(|(i, v)| {
                                if i == 0 {
                                    v.len().saturating_sub(tx_front_pos) as u64
                                } else {
                                    v.len() as u64
                                }
                            })
                            .sum();
                        let projected_total = bytes_sent
                            .saturating_add(queued_bytes)
                            .saturating_add(bytes.len() as u64)
                            .saturating_add(bytes_received);
                        if projected_total > quota.max_bytes_per_stream {
                            close_info = StreamClosed {
                                errno: Some(Errno::EDQUOT),
                                error: Some(NetErrorKind::QuotaExceeded),
                                message: Some("stream exceeded max_bytes_per_stream".into()),
                                bytes_sent,
                                bytes_received,
                            };
                            break;
                        }
                        tx_queue.push_back(bytes);
                    }
                    Some(TcpCmd::HalfClose) => {
                        if !client_eof && !pending_client_half_close && !shutdown_pending {
                            if tx_queue.is_empty() {
                                shutdown_pending = true;
                            } else {
                                pending_client_half_close = true;
                            }
                        }
                    }
                    None => {
                        // Host dropped stream (cancel / exit).
                        return;
                    }
                }
            }
        }
    }

    send_evt(TcpEvent::Closed(close_info));
}

fn update_rate_pace(
    quota: &NetQuota,
    window_start: &mut tokio::time::Instant,
    window_bytes: &mut u64,
    added: u64,
) -> Option<tokio::time::Instant> {
    let bps = quota.max_bytes_per_sec?;
    if bps == 0 {
        return None;
    }
    let now = tokio::time::Instant::now();
    let elapsed = now.saturating_duration_since(*window_start);
    if elapsed >= Duration::from_secs(1) {
        *window_start = now;
        *window_bytes = added;
        return None;
    }
    *window_bytes = window_bytes.saturating_add(added);
    if *window_bytes > bps {
        let target_ms = ((*window_bytes as u128) * 1000 / (bps as u128)) as u64;
        let elapsed_ms = elapsed.as_millis() as u64;
        if target_ms > elapsed_ms {
            return Some(now + Duration::from_millis((target_ms - elapsed_ms).min(1000)));
        }
        *window_start = now;
        *window_bytes = 0;
    }
    None
}

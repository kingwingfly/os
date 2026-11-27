//! Userspace `netd` session state machine, framing, and credit-windowed bidirectional pump
//! (`#86` Phase 10a).
//!
//! Pure-Rust logic decoupled from WASI socket syscalls via [`NetdIo`] and [`HostConnector`] so
//! every state transition, backpressure stall, credit replenishment, half-close, mid-connect
//! cancellation, and host-loss teardown is exhaustively unit-tested natively.

use abi::Errno;
use abi::net_ctl::{
    DataFrame, HostNetReq, HostNetResp, NET_CONTROL_MAX_BYTES, NET_DATA_CHUNK_MAX,
    NET_INITIAL_WINDOW_BYTES, NETD_VERSION, NetErrorKind, NetdReq, NetdResp, StreamClosed,
    StreamMode, decode_control_payload, encode_control_frame, encode_unix_data_frame,
    prevalidate_connect_target, try_decode_unix_data_frame,
};
use abi::socket::{MSG_DONTWAIT, MSG_NOSIGNAL, MSG_PEEK, PeerCred, SHUT_WR};
use std::collections::VecDeque;

/// Maximum concurrent client sessions served by `/usr/bin/netd`.
pub const MAX_CLIENTS: usize = 16;

/// Credit batching threshold for `Raw` mode (return credit to host once client consumes >= 8 KiB
/// or drains the buffer completely).
pub const RAW_CREDIT_THRESHOLD: u32 = (NET_DATA_CHUNK_MAX as u32) / 2;

/// Non-blocking stream socket abstraction for both client and host Unix stream connections.
pub trait NetdIo {
    fn raw_fd(&self) -> u32;
    fn recv(&self, buf: &mut [u8], flags: u32) -> Result<usize, Errno>;
    fn send(&self, data: &[u8], flags: u32) -> Result<usize, Errno>;
    fn send_with_fds(&self, data: &[u8], fds: &[u32], flags: u32) -> Result<usize, Errno>;
    fn shutdown(&self, how: u32) -> Result<(), Errno>;
}

/// Factory connecting to `/run/net/host.sock` (and checking `peer_cred().uid == 0`).
pub trait HostConnector<S: NetdIo> {
    fn connect_host(&mut self) -> Result<S, Errno>;
}

/// Readiness interests reported by a [`ClientSession`] to the `poll_oneoff` event loop.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionPollInterest {
    pub client_fd: u32,
    pub client_read: bool,
    pub client_write: bool,
    pub host_fd: Option<u32>,
    pub host_read: bool,
    pub host_write: bool,
}

enum Phase<S: NetdIo> {
    /// Waiting for `Hello` and subsequent `Status` / `Resolve` / `Connect` control frames.
    Control { negotiated: bool },
    /// Waiting for `HostNetResp::Resolved` from `/run/net/host.sock`.
    Resolving {
        host: S,
        host_rx: Vec<u8>,
        host_tx: Vec<u8>,
        host_tx_pos: usize,
        pending_rights: Option<u32>,
    },
    /// Waiting for `HostNetResp::Status` from `/run/net/host.sock`.
    QueryingStatus {
        host: S,
        host_rx: Vec<u8>,
        host_tx: Vec<u8>,
        host_tx_pos: usize,
    },
    /// Waiting for `HostNetResp::Opened` while monitoring `client` for disconnect/cancel.
    Opening {
        host: S,
        mode: StreamMode,
        host_rx: Vec<u8>,
        host_tx: Vec<u8>,
        host_tx_pos: usize,
        pending_rights: Option<u32>,
    },
    /// Active credit-windowed full-duplex stream between `client` and `host`.
    Streaming {
        host: S,
        mode: StreamMode,
        host_rx: Vec<u8>,
        host_tx: VecDeque<u8>,
        /// Maximum receive window negotiated with host (`<= NET_INITIAL_WINDOW_BYTES`).
        max_recv_window: u32,
        /// Bytes `netd` is still allowed to send to `host` in `DATA` frames.
        host_send_credit: u32,
        /// Bytes `host` is still allowed to send to `netd` before exceeding `max_recv_window`.
        host_recv_window: u32,
        /// Remaining unflushed control bytes (from `NetdResp::Connected`) at the front of `client_tx`.
        ctrl_tx_remaining: usize,
        /// Per-frame `(wire_bytes, payload_data_bytes)` queued in `client_tx` (Framed mode OOM guard).
        client_tx_segments: VecDeque<(usize, u32)>,
        /// Total un-flushed RX data payload bytes currently buffered inside `client_tx` (Framed mode).
        buffered_rx_bytes: u32,
        /// Pending client-to-host `Data` frames waiting for `host_send_credit` in `Framed` mode
        /// (separated from `client_rx` so `Credit`/`Cancel`/`HalfClose` are never HoL-blocked).
        pending_client_tx_data: VecDeque<Vec<u8>>,
        /// Total payload bytes queued inside `pending_client_tx_data`.
        pending_client_tx_bytes: usize,
        /// Deferred client `HalfClose` waiting for `pending_client_tx_data` to drain.
        pending_client_half_close: bool,
        /// Consumed bytes waiting to be credited back to `host` (Raw mode).
        pending_credit_to_host: u32,
        /// Client half-closed its write side (`EOF` or `HalfClose`).
        client_eof: bool,
        /// Host half-closed its write side (`HalfClose` or `Closed`).
        host_eof: bool,
        /// Whether `client.shutdown(SHUT_WR)` has already been issued in `Raw` mode.
        client_shut_wr: bool,
        /// Terminal `Closed` received from host.
        host_closed: Option<StreamClosed>,
        /// Client explicitly canceled or disconnected.
        closing_after_host_flush: bool,
    },
    /// Draining remaining `client_tx` (typically an error or status reply) before closing.
    DrainingClient,
}

/// One client session accepted on `/run/netd.sock`.
pub struct ClientSession<S: NetdIo> {
    pub peer: PeerCred,
    client: S,
    client_rx: Vec<u8>,
    client_tx: VecDeque<u8>,
    phase: Phase<S>,
}

impl<S: NetdIo> ClientSession<S> {
    pub fn new(client: S, peer: PeerCred) -> Self {
        Self {
            peer,
            client,
            client_rx: Vec::new(),
            client_tx: VecDeque::new(),
            phase: Phase::Control { negotiated: false },
        }
    }

    pub fn is_active_stream(&self) -> bool {
        matches!(self.phase, Phase::Opening { .. } | Phase::Streaming { .. })
    }

    /// Report which descriptors should be registered in `poll_oneoff` for this session.
    pub fn poll_interest(&self) -> SessionPollInterest {
        let client_fd = self.client.raw_fd();
        let client_write = !self.client_tx.is_empty();
        match &self.phase {
            Phase::Control { .. } => SessionPollInterest {
                client_fd,
                client_read: self.client_tx.is_empty(),
                client_write,
                host_fd: None,
                host_read: false,
                host_write: false,
            },
            Phase::Resolving {
                host,
                host_tx,
                host_tx_pos,
                ..
            }
            | Phase::QueryingStatus {
                host,
                host_tx,
                host_tx_pos,
                ..
            }
            | Phase::Opening {
                host,
                host_tx,
                host_tx_pos,
                ..
            } => SessionPollInterest {
                client_fd,
                client_read: true, // Detect client exit/disconnect immediately!
                client_write,
                host_fd: Some(host.raw_fd()),
                host_read: true,
                host_write: *host_tx_pos < host_tx.len(),
            },
            Phase::Streaming {
                host,
                mode,
                host_tx,
                host_send_credit,
                client_eof,
                host_closed,
                closing_after_host_flush,
                ..
            } => {
                let want_client_read = !*client_eof
                    && !*closing_after_host_flush
                    && match mode {
                        StreamMode::Raw => {
                            *host_send_credit > 0
                                && host_tx.len() < NET_INITIAL_WINDOW_BYTES as usize
                                && self.client_rx.is_empty()
                        }
                        StreamMode::Framed => {
                            host_tx.len() < NET_INITIAL_WINDOW_BYTES as usize
                                && self.client_rx.len() < NET_INITIAL_WINDOW_BYTES as usize
                        }
                    };
                let want_host_read = !*closing_after_host_flush && host_closed.is_none();
                SessionPollInterest {
                    client_fd,
                    client_read: want_client_read,
                    client_write,
                    host_fd: Some(host.raw_fd()),
                    host_read: want_host_read,
                    host_write: !host_tx.is_empty(),
                }
            }
            Phase::DrainingClient => SessionPollInterest {
                client_fd,
                client_read: false,
                client_write,
                host_fd: None,
                host_read: false,
                host_write: false,
            },
        }
    }

    fn enqueue_client_resp(&mut self, resp: &NetdResp) {
        if let Ok(frame) = encode_control_frame(resp) {
            self.client_tx.extend(frame);
        }
    }

    fn enqueue_client_error(
        &mut self,
        errno: Errno,
        error: NetErrorKind,
        message: impl Into<String>,
    ) {
        self.enqueue_client_resp(&NetdResp::Error {
            errno,
            error,
            message: message.into(),
        });
    }

    /// Flush queued bytes to `client`. Returns `Ok(bytes_sent)` or `Err(())` if peer broke/closed.
    fn flush_client_tx(&mut self) -> Result<usize, ()> {
        let mut total_sent = 0usize;
        while !self.client_tx.is_empty() {
            let (front, _) = self.client_tx.as_slices();
            if front.is_empty() {
                self.client_tx.make_contiguous();
                continue;
            }
            match self.client.send(front, MSG_DONTWAIT | MSG_NOSIGNAL) {
                Ok(0) => return Err(()),
                Ok(n) => {
                    self.client_tx.drain(..n);
                    total_sent += n;
                }
                Err(Errno::EAGAIN) => break,
                Err(Errno::EINTR) => continue,
                Err(_) => return Err(()),
            }
        }
        Ok(total_sent)
    }

    /// Account for `flushed` wire bytes written to `self.client`:
    /// - Deducts unflushed `NetdResp::Connected` control bytes first so they are never credited as data.
    /// - In `Raw` mode, credits flushed data bytes back to `host` (clamped to `max_recv_window`).
    /// - In `Framed` mode, drains `client_tx_segments` so `buffered_rx_bytes` reflects unflushed RX data.
    fn account_client_flushed(&mut self, mut flushed: usize) {
        if flushed == 0 {
            return;
        }
        let Phase::Streaming {
            mode,
            max_recv_window,
            ctrl_tx_remaining,
            client_tx_segments,
            buffered_rx_bytes,
            pending_credit_to_host,
            host_recv_window,
            host_tx,
            ..
        } = &mut self.phase
        else {
            return;
        };

        let ctrl_flushed = flushed.min(*ctrl_tx_remaining);
        *ctrl_tx_remaining -= ctrl_flushed;
        let data_flushed = flushed - ctrl_flushed;

        match *mode {
            StreamMode::Raw => {
                if data_flushed > 0 {
                    *pending_credit_to_host =
                        pending_credit_to_host.saturating_add(data_flushed as u32);
                    if (*pending_credit_to_host >= RAW_CREDIT_THRESHOLD
                        || self.client_tx.is_empty())
                        && *pending_credit_to_host > 0
                    {
                        let headroom = max_recv_window.saturating_sub(*host_recv_window);
                        let credit = (*pending_credit_to_host).min(headroom);
                        *pending_credit_to_host = 0;
                        if credit > 0 {
                            *host_recv_window = host_recv_window.saturating_add(credit);
                            if let Ok(encoded) = encode_unix_data_frame(&DataFrame::Credit(credit))
                            {
                                host_tx.extend(encoded);
                            }
                        }
                    }
                }
            }
            StreamMode::Framed => {
                while flushed > 0 {
                    let Some((seg_wire, seg_data)) = client_tx_segments.front_mut() else {
                        *buffered_rx_bytes = 0;
                        break;
                    };
                    if flushed >= *seg_wire {
                        flushed -= *seg_wire;
                        let data_done = *seg_data;
                        client_tx_segments.pop_front();
                        *buffered_rx_bytes = buffered_rx_bytes.saturating_sub(data_done);
                    } else {
                        *seg_wire -= flushed;
                        flushed = 0;
                    }
                }
            }
        }
    }

    /// Check if `client` disconnected while we are waiting on host (`Opening`/`Resolving`).
    fn client_disconnected(&self) -> bool {
        let mut probe = [0u8; 1];
        match self.client.recv(&mut probe, MSG_DONTWAIT | MSG_PEEK) {
            Ok(0) => true,
            Ok(_) | Err(Errno::EAGAIN | Errno::EINTR) => false,
            Err(_) => true,
        }
    }

    /// Drive this session forward. Returns `true` if the session remains live, `false` to drop it.
    pub fn step(&mut self, connector: &mut impl HostConnector<S>, active_streams: u32) -> bool {
        // Always drain any pending `client_tx` first.
        let flushed = match self.flush_client_tx() {
            Ok(n) => n,
            Err(()) => {
                // Client disappeared — notify host immediately if we have an open stream!
                if let Phase::Streaming { host, .. } | Phase::Opening { host, .. } = &self.phase
                    && let Ok(cancel) = encode_unix_data_frame(&DataFrame::Cancel)
                {
                    let _ = host.send(&cancel, MSG_DONTWAIT | MSG_NOSIGNAL);
                }
                return false;
            }
        };

        // Account for flushed bytes: exclude `NetdResp::Connected` control bytes from Raw credit,
        // and release flushed Framed RX segment payload accounting.
        if flushed > 0 {
            self.account_client_flushed(flushed);
        }

        match &mut self.phase {
            Phase::DrainingClient => !self.client_tx.is_empty(),
            Phase::Control { .. } => self.step_control(connector, active_streams),
            Phase::Resolving { .. } => self.step_resolving(),
            Phase::QueryingStatus { .. } => self.step_querying_status(active_streams),
            Phase::Opening { .. } => self.step_opening(),
            Phase::Streaming { .. } => self.step_streaming(),
        }
    }

    fn step_control(&mut self, connector: &mut impl HostConnector<S>, active_streams: u32) -> bool {
        if !self.client_tx.is_empty() {
            return true;
        }
        let mut buf = [0u8; 4096];
        loop {
            match self.client.recv(&mut buf, MSG_DONTWAIT) {
                Ok(0) => return false,
                Ok(n) => {
                    if self.client_rx.len() + n > NET_CONTROL_MAX_BYTES + 4 {
                        self.enqueue_client_error(
                            Errno::E2BIG,
                            NetErrorKind::ProtocolError,
                            "control frame exceeds maximum size",
                        );
                        self.phase = Phase::DrainingClient;
                        let _ = self.flush_client_tx();
                        return !self.client_tx.is_empty();
                    }
                    self.client_rx.extend_from_slice(&buf[..n]);
                }
                Err(Errno::EAGAIN) => break,
                Err(Errno::EINTR) => continue,
                Err(_) => return false,
            }
        }
        if self.client_rx.len() < 4 {
            return true;
        }
        let len = u32::from_be_bytes([
            self.client_rx[0],
            self.client_rx[1],
            self.client_rx[2],
            self.client_rx[3],
        ]) as usize;
        if len == 0 || len > NET_CONTROL_MAX_BYTES {
            self.enqueue_client_error(
                if len == 0 {
                    Errno::EINVAL
                } else {
                    Errno::E2BIG
                },
                NetErrorKind::ProtocolError,
                "invalid control frame length",
            );
            self.phase = Phase::DrainingClient;
            let _ = self.flush_client_tx();
            return !self.client_tx.is_empty();
        }
        if self.client_rx.len() < 4 + len {
            return true;
        }
        let payload = self.client_rx[4..4 + len].to_vec();
        self.client_rx.drain(..4 + len);
        let req = match decode_control_payload::<NetdReq>(&payload) {
            Ok(r) => r,
            Err(e) => {
                self.enqueue_client_error(e.errno, NetErrorKind::ProtocolError, e.to_string());
                self.phase = Phase::DrainingClient;
                let _ = self.flush_client_tx();
                return !self.client_tx.is_empty();
            }
        };

        let negotiated = match self.phase {
            Phase::Control { negotiated } => negotiated,
            _ => false,
        };

        match req {
            NetdReq::Hello { versions } => {
                if !versions.contains(&NETD_VERSION) {
                    self.enqueue_client_error(
                        Errno::EPROTONOSUPPORT,
                        NetErrorKind::ProtocolError,
                        format!("netd v{NETD_VERSION} required"),
                    );
                    self.phase = Phase::DrainingClient;
                } else {
                    self.phase = Phase::Control { negotiated: true };
                    self.enqueue_client_resp(&NetdResp::Welcome {
                        version: NETD_VERSION,
                        max_chunk: NET_DATA_CHUNK_MAX,
                        initial_window: NET_INITIAL_WINDOW_BYTES,
                    });
                }
                let _ = self.flush_client_tx();
                true
            }
            NetdReq::Status {} => {
                if !negotiated {
                    self.enqueue_client_error(
                        Errno::EPROTONOSUPPORT,
                        NetErrorKind::ProtocolError,
                        "Hello handshake required before Status",
                    );
                    self.phase = Phase::DrainingClient;
                    let _ = self.flush_client_tx();
                    return !self.client_tx.is_empty();
                }
                match connector.connect_host() {
                    Ok(host) => match encode_control_frame(&HostNetReq::Status {}) {
                        Ok(host_tx) => {
                            self.phase = Phase::QueryingStatus {
                                host,
                                host_rx: Vec::new(),
                                host_tx,
                                host_tx_pos: 0,
                            };
                            self.step_querying_status(active_streams)
                        }
                        Err(e) => {
                            self.enqueue_client_error(
                                e.errno,
                                NetErrorKind::ProtocolError,
                                e.to_string(),
                            );
                            self.phase = Phase::DrainingClient;
                            let _ = self.flush_client_tx();
                            !self.client_tx.is_empty()
                        }
                    },
                    Err(_) => {
                        self.enqueue_client_resp(&NetdResp::Status {
                            version: NETD_VERSION,
                            host_kind: "unavailable".into(),
                            active_streams,
                            ready: false,
                        });
                        let _ = self.flush_client_tx();
                        true
                    }
                }
            }
            NetdReq::Resolve { host, port } => {
                if !negotiated {
                    self.enqueue_client_error(
                        Errno::EPROTONOSUPPORT,
                        NetErrorKind::ProtocolError,
                        "Hello handshake required before Resolve",
                    );
                    self.phase = Phase::DrainingClient;
                    let _ = self.flush_client_tx();
                    return !self.client_tx.is_empty();
                }
                if let Err(fail) =
                    prevalidate_connect_target(&host, if port == 0 { 80 } else { port })
                {
                    self.enqueue_client_error(fail.errno, fail.kind, fail.message);
                    self.phase = Phase::DrainingClient;
                    let _ = self.flush_client_tx();
                    return !self.client_tx.is_empty();
                }
                match connector.connect_host() {
                    Ok(host_sock) => {
                        match encode_control_frame(&HostNetReq::Resolve { host, port }) {
                            Ok(host_tx) => {
                                self.phase = Phase::Resolving {
                                    host: host_sock,
                                    host_rx: Vec::new(),
                                    host_tx,
                                    host_tx_pos: 0,
                                    pending_rights: Some(self.client.raw_fd()),
                                };
                                self.step_resolving()
                            }
                            Err(e) => {
                                self.enqueue_client_error(
                                    e.errno,
                                    NetErrorKind::ProtocolError,
                                    e.to_string(),
                                );
                                self.phase = Phase::DrainingClient;
                                let _ = self.flush_client_tx();
                                !self.client_tx.is_empty()
                            }
                        }
                    }
                    Err(e) => {
                        let errno = if matches!(e, Errno::ENOENT | Errno::ECONNREFUSED) {
                            Errno::ENOTCONN
                        } else {
                            e
                        };
                        self.enqueue_client_error(
                            errno,
                            NetErrorKind::HostUnavailable,
                            "network host bridge unavailable",
                        );
                        self.phase = Phase::DrainingClient;
                        let _ = self.flush_client_tx();
                        !self.client_tx.is_empty()
                    }
                }
            }
            NetdReq::Connect {
                host,
                port,
                tls,
                mode,
                timeout_ms,
            } => {
                if !negotiated {
                    self.enqueue_client_error(
                        Errno::EPROTONOSUPPORT,
                        NetErrorKind::ProtocolError,
                        "Hello handshake required before Connect",
                    );
                    self.phase = Phase::DrainingClient;
                    let _ = self.flush_client_tx();
                    return !self.client_tx.is_empty();
                }
                if let Err(fail) = prevalidate_connect_target(&host, port) {
                    self.enqueue_client_error(fail.errno, fail.kind, fail.message);
                    self.phase = Phase::DrainingClient;
                    let _ = self.flush_client_tx();
                    return !self.client_tx.is_empty();
                }
                match connector.connect_host() {
                    Ok(host_sock) => {
                        match encode_control_frame(&HostNetReq::Open {
                            host,
                            port,
                            tls,
                            timeout_ms,
                        }) {
                            Ok(host_tx) => {
                                self.phase = Phase::Opening {
                                    host: host_sock,
                                    mode,
                                    host_rx: Vec::new(),
                                    host_tx,
                                    host_tx_pos: 0,
                                    pending_rights: Some(self.client.raw_fd()),
                                };
                                self.step_opening()
                            }
                            Err(e) => {
                                self.enqueue_client_error(
                                    e.errno,
                                    NetErrorKind::ProtocolError,
                                    e.to_string(),
                                );
                                self.phase = Phase::DrainingClient;
                                let _ = self.flush_client_tx();
                                !self.client_tx.is_empty()
                            }
                        }
                    }
                    Err(e) => {
                        let errno = if matches!(e, Errno::ENOENT | Errno::ECONNREFUSED) {
                            Errno::ENOTCONN
                        } else {
                            e
                        };
                        self.enqueue_client_error(
                            errno,
                            NetErrorKind::HostUnavailable,
                            "network host bridge unavailable",
                        );
                        self.phase = Phase::DrainingClient;
                        let _ = self.flush_client_tx();
                        !self.client_tx.is_empty()
                    }
                }
            }
        }
    }

    fn drive_host_control_rpc(
        host: &S,
        host_rx: &mut Vec<u8>,
        host_tx: &[u8],
        host_tx_pos: &mut usize,
        pending_rights: &mut Option<u32>,
    ) -> Result<Option<HostNetResp>, (Errno, NetErrorKind, String)> {
        while *host_tx_pos < host_tx.len() {
            let res = if let Some(fd) = *pending_rights {
                host.send_with_fds(&host_tx[*host_tx_pos..], &[fd], MSG_DONTWAIT | MSG_NOSIGNAL)
            } else {
                host.send(&host_tx[*host_tx_pos..], MSG_DONTWAIT | MSG_NOSIGNAL)
            };
            match res {
                Ok(0) => {
                    return Err((
                        Errno::ECONNRESET,
                        NetErrorKind::HostUnavailable,
                        "host bridge closed during control send".into(),
                    ));
                }
                Ok(n) => {
                    *pending_rights = None;
                    *host_tx_pos += n;
                }
                Err(Errno::EAGAIN) => break,
                Err(Errno::EINTR) => continue,
                Err(e) => {
                    return Err((
                        e,
                        NetErrorKind::HostUnavailable,
                        format!("host bridge send failed: {}", e.text()),
                    ));
                }
            }
        }
        if *host_tx_pos < host_tx.len() {
            return Ok(None);
        }
        let mut buf = [0u8; 4096];
        loop {
            match host.recv(&mut buf, MSG_DONTWAIT) {
                Ok(0) => {
                    return Err((
                        Errno::ECONNRESET,
                        NetErrorKind::HostUnavailable,
                        "host bridge closed before control reply".into(),
                    ));
                }
                Ok(n) => {
                    if host_rx.len() + n > NET_CONTROL_MAX_BYTES + 4 {
                        return Err((
                            Errno::E2BIG,
                            NetErrorKind::ProtocolError,
                            "host control reply exceeded maximum length".into(),
                        ));
                    }
                    host_rx.extend_from_slice(&buf[..n]);
                }
                Err(Errno::EAGAIN) => break,
                Err(Errno::EINTR) => continue,
                Err(e) => {
                    return Err((
                        e,
                        NetErrorKind::HostUnavailable,
                        format!("host bridge recv failed: {}", e.text()),
                    ));
                }
            }
            if host_rx.len() >= 4 {
                let len =
                    u32::from_be_bytes([host_rx[0], host_rx[1], host_rx[2], host_rx[3]]) as usize;
                if len == 0 || len > NET_CONTROL_MAX_BYTES {
                    return Err((
                        Errno::EIO,
                        NetErrorKind::ProtocolError,
                        "invalid host control reply frame length".into(),
                    ));
                }
                if host_rx.len() >= 4 + len {
                    break;
                }
            }
        }
        if host_rx.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([host_rx[0], host_rx[1], host_rx[2], host_rx[3]]) as usize;
        if host_rx.len() < 4 + len {
            return Ok(None);
        }
        let payload = host_rx[4..4 + len].to_vec();
        host_rx.drain(..4 + len);
        let resp = decode_control_payload::<HostNetResp>(&payload).map_err(|e| {
            (
                e.errno,
                NetErrorKind::ProtocolError,
                format!("invalid host reply JSON: {e}"),
            )
        })?;
        Ok(Some(resp))
    }

    fn step_querying_status(&mut self, active_streams: u32) -> bool {
        if self.client_disconnected() {
            return false;
        }
        let rpc_res = match &mut self.phase {
            Phase::QueryingStatus {
                host,
                host_rx,
                host_tx,
                host_tx_pos,
            } => {
                let mut no_fd = None;
                Self::drive_host_control_rpc(host, host_rx, host_tx, host_tx_pos, &mut no_fd)
            }
            _ => return false,
        };
        match rpc_res {
            Ok(None) => true,
            Ok(Some(HostNetResp::Status {
                version,
                host_kind,
                active_streams: host_active,
                ready,
            })) => {
                self.phase = Phase::Control { negotiated: true };
                self.enqueue_client_resp(&NetdResp::Status {
                    version,
                    host_kind,
                    active_streams: active_streams.max(host_active),
                    ready,
                });
                let _ = self.flush_client_tx();
                true
            }
            Ok(Some(HostNetResp::Error {
                errno,
                error,
                message,
            })) => {
                self.phase = Phase::Control { negotiated: true };
                self.enqueue_client_error(errno, error, message);
                let _ = self.flush_client_tx();
                true
            }
            Ok(Some(_)) | Err(_) => {
                self.phase = Phase::Control { negotiated: true };
                self.enqueue_client_resp(&NetdResp::Status {
                    version: NETD_VERSION,
                    host_kind: "unavailable".into(),
                    active_streams,
                    ready: false,
                });
                let _ = self.flush_client_tx();
                true
            }
        }
    }

    fn step_resolving(&mut self) -> bool {
        if self.client_disconnected() {
            return false;
        }
        let rpc_res = match &mut self.phase {
            Phase::Resolving {
                host,
                host_rx,
                host_tx,
                host_tx_pos,
                pending_rights,
            } => Self::drive_host_control_rpc(host, host_rx, host_tx, host_tx_pos, pending_rights),
            _ => return false,
        };
        match rpc_res {
            Ok(None) => true,
            Ok(Some(HostNetResp::Resolved { addrs })) => {
                self.phase = Phase::Control { negotiated: true };
                self.enqueue_client_resp(&NetdResp::Resolved { addrs });
                let _ = self.flush_client_tx();
                true
            }
            Ok(Some(HostNetResp::Error {
                errno,
                error,
                message,
            })) => {
                self.enqueue_client_error(errno, error, message);
                self.phase = Phase::DrainingClient;
                let _ = self.flush_client_tx();
                !self.client_tx.is_empty()
            }
            Ok(Some(_)) => {
                self.enqueue_client_error(
                    Errno::EIO,
                    NetErrorKind::ProtocolError,
                    "unexpected host reply to Resolve",
                );
                self.phase = Phase::DrainingClient;
                let _ = self.flush_client_tx();
                !self.client_tx.is_empty()
            }
            Err((errno, kind, msg)) => {
                self.enqueue_client_error(errno, kind, msg);
                self.phase = Phase::DrainingClient;
                let _ = self.flush_client_tx();
                !self.client_tx.is_empty()
            }
        }
    }

    fn step_opening(&mut self) -> bool {
        if self.client_disconnected() {
            if let Phase::Opening { host, .. } = &self.phase
                && let Ok(cancel) = encode_unix_data_frame(&DataFrame::Cancel)
            {
                let _ = host.send(&cancel, MSG_DONTWAIT | MSG_NOSIGNAL);
            }
            return false;
        }
        let rpc_res = match &mut self.phase {
            Phase::Opening {
                host,
                host_rx,
                host_tx,
                host_tx_pos,
                pending_rights,
                ..
            } => Self::drive_host_control_rpc(host, host_rx, host_tx, host_tx_pos, pending_rights),
            _ => return false,
        };
        match rpc_res {
            Ok(None) => true,
            Ok(Some(HostNetResp::Opened {
                stream_id,
                peer_addr,
                initial_window,
                quota,
            })) => {
                let old = std::mem::replace(&mut self.phase, Phase::DrainingClient);
                let Phase::Opening {
                    host,
                    mode,
                    host_rx,
                    ..
                } = old
                else {
                    return false;
                };
                let win = initial_window.clamp(NET_DATA_CHUNK_MAX as u32, NET_INITIAL_WINDOW_BYTES);
                self.enqueue_client_resp(&NetdResp::Connected {
                    stream_id,
                    peer_addr,
                    mode,
                    initial_window: win,
                    quota,
                });
                let ctrl_len = self.client_tx.len();
                let mut client_tx_segments = VecDeque::new();
                if mode == StreamMode::Framed && ctrl_len > 0 {
                    client_tx_segments.push_back((ctrl_len, 0));
                }
                self.phase = Phase::Streaming {
                    host,
                    mode,
                    host_rx,
                    host_tx: VecDeque::new(),
                    max_recv_window: win,
                    host_send_credit: win,
                    host_recv_window: win,
                    ctrl_tx_remaining: ctrl_len,
                    client_tx_segments,
                    buffered_rx_bytes: 0,
                    pending_client_tx_data: VecDeque::new(),
                    pending_client_tx_bytes: 0,
                    pending_client_half_close: false,
                    pending_credit_to_host: 0,
                    client_eof: false,
                    host_eof: false,
                    client_shut_wr: false,
                    host_closed: None,
                    closing_after_host_flush: false,
                };
                match self.flush_client_tx() {
                    Ok(flushed) => self.account_client_flushed(flushed),
                    Err(()) => {
                        if let Phase::Streaming { host, .. } = &self.phase
                            && let Ok(cancel) = encode_unix_data_frame(&DataFrame::Cancel)
                        {
                            let _ = host.send(&cancel, MSG_DONTWAIT | MSG_NOSIGNAL);
                        }
                        return false;
                    }
                }
                self.step_streaming()
            }
            Ok(Some(HostNetResp::Error {
                errno,
                error,
                message,
            })) => {
                self.enqueue_client_error(errno, error, message);
                self.phase = Phase::DrainingClient;
                let _ = self.flush_client_tx();
                !self.client_tx.is_empty()
            }
            Ok(Some(_)) => {
                self.enqueue_client_error(
                    Errno::EIO,
                    NetErrorKind::ProtocolError,
                    "unexpected host reply to Open",
                );
                self.phase = Phase::DrainingClient;
                let _ = self.flush_client_tx();
                !self.client_tx.is_empty()
            }
            Err((errno, kind, msg)) => {
                self.enqueue_client_error(errno, kind, msg);
                self.phase = Phase::DrainingClient;
                let _ = self.flush_client_tx();
                !self.client_tx.is_empty()
            }
        }
    }

    fn step_streaming(&mut self) -> bool {
        let mut host_broken = false;
        let mut client_broken = false;

        // 1. Flush `host_tx` to `host`.
        if let Phase::Streaming { host, host_tx, .. } = &mut self.phase {
            while !host_tx.is_empty() {
                let (front, _) = host_tx.as_slices();
                if front.is_empty() {
                    host_tx.make_contiguous();
                    continue;
                }
                match host.send(front, MSG_DONTWAIT | MSG_NOSIGNAL) {
                    Ok(0) => {
                        host_broken = true;
                        break;
                    }
                    Ok(n) => {
                        host_tx.drain(..n);
                    }
                    Err(Errno::EAGAIN) => break,
                    Err(Errno::EINTR) => continue,
                    Err(_) => {
                        host_broken = true;
                        break;
                    }
                }
            }
        }

        if let Phase::Streaming {
            closing_after_host_flush,
            host_tx,
            ..
        } = &self.phase
            && *closing_after_host_flush
            && (host_tx.is_empty() || host_broken)
        {
            return false;
        }

        // 2. Read from `host` and process data frames (`DATA`, `CREDIT`, `HALF_CLOSE`, `CLOSED`).
        if !host_broken
            && let Phase::Streaming {
                host,
                mode,
                host_rx,
                host_send_credit,
                host_recv_window,
                client_tx_segments,
                buffered_rx_bytes,
                host_eof,
                host_closed,
                ..
            } = &mut self.phase
            && host_closed.is_none()
        {
            let mut buf = [0u8; NET_DATA_CHUNK_MAX + 64];
            loop {
                match host.recv(&mut buf, MSG_DONTWAIT) {
                    Ok(0) => {
                        host_broken = true;
                        break;
                    }
                    Ok(n) => {
                        host_rx.extend_from_slice(&buf[..n]);
                        if host_rx.len() > (NET_INITIAL_WINDOW_BYTES as usize) * 2 + 4096 {
                            host_broken = true;
                            break;
                        }
                    }
                    Err(Errno::EAGAIN) => break,
                    Err(Errno::EINTR) => continue,
                    Err(_) => {
                        host_broken = true;
                        break;
                    }
                }
            }
            loop {
                match try_decode_unix_data_frame(host_rx) {
                    Ok(Some((frame, consumed))) => {
                        host_rx.drain(..consumed);
                        match frame {
                            DataFrame::Data(data) => {
                                let len = data.len() as u32;
                                if len > *host_recv_window {
                                    // Host violated flow-control window -> fail closed!
                                    host_broken = true;
                                    break;
                                }
                                *host_recv_window -= len;
                                match *mode {
                                    StreamMode::Raw => self.client_tx.extend(data),
                                    StreamMode::Framed => {
                                        if let Ok(enc) =
                                            encode_unix_data_frame(&DataFrame::Data(data))
                                        {
                                            client_tx_segments.push_back((enc.len(), len));
                                            *buffered_rx_bytes =
                                                buffered_rx_bytes.saturating_add(len);
                                            self.client_tx.extend(enc);
                                        }
                                    }
                                }
                            }
                            DataFrame::Credit(n) => {
                                *host_send_credit = host_send_credit
                                    .saturating_add(n)
                                    .min(NET_INITIAL_WINDOW_BYTES);
                                if *mode == StreamMode::Framed
                                    && let Ok(enc) = encode_unix_data_frame(&DataFrame::Credit(n))
                                {
                                    client_tx_segments.push_back((enc.len(), 0));
                                    self.client_tx.extend(enc);
                                }
                            }
                            DataFrame::HalfClose => {
                                *host_eof = true;
                                if *mode == StreamMode::Framed
                                    && let Ok(enc) = encode_unix_data_frame(&DataFrame::HalfClose)
                                {
                                    client_tx_segments.push_back((enc.len(), 0));
                                    self.client_tx.extend(enc);
                                }
                            }
                            DataFrame::Cancel => {
                                host_broken = true;
                                break;
                            }
                            DataFrame::Closed(info) => {
                                *host_eof = true;
                                if *mode == StreamMode::Framed
                                    && let Ok(enc) =
                                        encode_unix_data_frame(&DataFrame::Closed(info.clone()))
                                {
                                    client_tx_segments.push_back((enc.len(), 0));
                                    self.client_tx.extend(enc);
                                }
                                *host_closed = Some(info);
                                break;
                            }
                        }
                    }
                    Ok(None) => break,
                    Err(_) => {
                        host_broken = true;
                        break;
                    }
                }
            }
        }

        // 3. Flush `client_tx` again immediately after decoding host frames.
        let flushed = match self.flush_client_tx() {
            Ok(n) => n,
            Err(()) => {
                client_broken = true;
                0
            }
        };
        if flushed > 0 {
            self.account_client_flushed(flushed);
        }

        // 4. Read from `client` -> forward to `host_tx` (respecting `host_send_credit`!).
        if !client_broken
            && !host_broken
            && let Phase::Streaming {
                mode,
                host_tx,
                max_recv_window,
                host_send_credit,
                host_recv_window,
                buffered_rx_bytes,
                pending_client_tx_data,
                pending_client_tx_bytes,
                pending_client_half_close,
                client_eof,
                closing_after_host_flush,
                ..
            } = &mut self.phase
            && !*closing_after_host_flush
        {
            match *mode {
                StreamMode::Raw => {
                    // Drain any pipelined bytes already in `self.client_rx` before reading the socket!
                    while !self.client_rx.is_empty()
                        && *host_send_credit > 0
                        && host_tx.len() < NET_INITIAL_WINDOW_BYTES as usize
                    {
                        let take = self
                            .client_rx
                            .len()
                            .min(*host_send_credit as usize)
                            .min(NET_DATA_CHUNK_MAX);
                        let chunk: Vec<u8> = self.client_rx.drain(..take).collect();
                        *host_send_credit -= take as u32;
                        if let Ok(enc) = encode_unix_data_frame(&DataFrame::Data(chunk)) {
                            host_tx.extend(enc);
                        }
                    }
                    if !*client_eof && self.client_rx.is_empty() {
                        while *host_send_credit > 0
                            && host_tx.len() < NET_INITIAL_WINDOW_BYTES as usize
                        {
                            let want = (*host_send_credit as usize).min(NET_DATA_CHUNK_MAX);
                            let mut buf = vec![0u8; want];
                            match self.client.recv(&mut buf, MSG_DONTWAIT) {
                                Ok(0) => {
                                    *client_eof = true;
                                    if let Ok(enc) = encode_unix_data_frame(&DataFrame::HalfClose) {
                                        host_tx.extend(enc);
                                    }
                                    break;
                                }
                                Ok(n) => {
                                    buf.truncate(n);
                                    *host_send_credit -= n as u32;
                                    if let Ok(enc) = encode_unix_data_frame(&DataFrame::Data(buf)) {
                                        host_tx.extend(enc);
                                    }
                                }
                                Err(Errno::EAGAIN) => break,
                                Err(Errno::EINTR) => continue,
                                Err(_) => {
                                    client_broken = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                StreamMode::Framed => {
                    // 4a. Drain already-queued Framed data frames as `host_send_credit` allows.
                    while let Some(front) = pending_client_tx_data.front_mut() {
                        if *host_send_credit == 0
                            || host_tx.len() >= NET_INITIAL_WINDOW_BYTES as usize
                        {
                            break;
                        }
                        if front.len() as u32 <= *host_send_credit {
                            let chunk = pending_client_tx_data.pop_front().unwrap();
                            let len = chunk.len();
                            *pending_client_tx_bytes = pending_client_tx_bytes.saturating_sub(len);
                            *host_send_credit -= len as u32;
                            if let Ok(enc) = encode_unix_data_frame(&DataFrame::Data(chunk)) {
                                host_tx.extend(enc);
                            }
                        } else {
                            let take = (*host_send_credit as usize).min(NET_DATA_CHUNK_MAX);
                            let chunk: Vec<u8> = front.drain(..take).collect();
                            *pending_client_tx_bytes = pending_client_tx_bytes.saturating_sub(take);
                            *host_send_credit -= take as u32;
                            if let Ok(enc) = encode_unix_data_frame(&DataFrame::Data(chunk)) {
                                host_tx.extend(enc);
                            }
                        }
                    }
                    if *pending_client_half_close && pending_client_tx_data.is_empty() {
                        *pending_client_half_close = false;
                        if let Ok(enc) = encode_unix_data_frame(&DataFrame::HalfClose) {
                            host_tx.extend(enc);
                        }
                    }

                    // 4b. Read from `client` only while `client_rx` is below `NET_INITIAL_WINDOW_BYTES`.
                    if !*client_eof {
                        let mut buf = [0u8; NET_DATA_CHUNK_MAX + 64];
                        while host_tx.len() < NET_INITIAL_WINDOW_BYTES as usize
                            && self.client_rx.len() < NET_INITIAL_WINDOW_BYTES as usize
                        {
                            let want = ((NET_INITIAL_WINDOW_BYTES as usize) - self.client_rx.len())
                                .min(buf.len());
                            match self.client.recv(&mut buf[..want], MSG_DONTWAIT) {
                                Ok(0) => {
                                    *client_eof = true;
                                    *closing_after_host_flush = true;
                                    pending_client_tx_data.clear();
                                    *pending_client_tx_bytes = 0;
                                    *pending_client_half_close = false;
                                    if let Ok(enc) = encode_unix_data_frame(&DataFrame::Cancel) {
                                        host_tx.extend(enc);
                                    }
                                    break;
                                }
                                Ok(n) => {
                                    self.client_rx.extend_from_slice(&buf[..n]);
                                }
                                Err(Errno::EAGAIN) => break,
                                Err(Errno::EINTR) => continue,
                                Err(_) => {
                                    client_broken = true;
                                    break;
                                }
                            }
                        }
                    }

                    // 4c. Decode framed messages: queue `Data` separately (bounded by
                    // `NET_INITIAL_WINDOW_BYTES`) so `Credit`/`Cancel`/`HalfClose` are NEVER
                    // head-of-line blocked behind un-credited `Data`!
                    while !client_broken {
                        match try_decode_unix_data_frame(&self.client_rx) {
                            Ok(Some((frame, consumed))) => match frame {
                                DataFrame::Data(data) => {
                                    if data.len() > NET_DATA_CHUNK_MAX {
                                        client_broken = true;
                                        break;
                                    }
                                    if *client_eof {
                                        client_broken = true;
                                        break;
                                    }
                                    if pending_client_tx_data.is_empty()
                                        && (data.len() as u32) <= *host_send_credit
                                        && host_tx.len() < NET_INITIAL_WINDOW_BYTES as usize
                                    {
                                        self.client_rx.drain(..consumed);
                                        *host_send_credit -= data.len() as u32;
                                        if let Ok(enc) =
                                            encode_unix_data_frame(&DataFrame::Data(data))
                                        {
                                            host_tx.extend(enc);
                                        }
                                    } else if *pending_client_tx_bytes + data.len()
                                        <= NET_INITIAL_WINDOW_BYTES as usize
                                    {
                                        self.client_rx.drain(..consumed);
                                        *pending_client_tx_bytes += data.len();
                                        pending_client_tx_data.push_back(data);
                                    } else {
                                        // Both send credit and pending data queue are saturated;
                                        // keep frame in `client_rx` until host returns credit.
                                        break;
                                    }
                                }
                                DataFrame::Credit(n) => {
                                    self.client_rx.drain(..consumed);
                                    // Strictly clamp incoming `Credit` so total in-flight window
                                    // `host_recv_window + buffered_rx_bytes <= max_recv_window <= NET_INITIAL_WINDOW_BYTES`!
                                    let inflight =
                                        host_recv_window.saturating_add(*buffered_rx_bytes);
                                    let cap = (*max_recv_window).min(NET_INITIAL_WINDOW_BYTES);
                                    let headroom = cap.saturating_sub(inflight);
                                    let grant = n.min(headroom);
                                    if grant > 0 {
                                        *host_recv_window = host_recv_window.saturating_add(grant);
                                        if let Ok(enc) =
                                            encode_unix_data_frame(&DataFrame::Credit(grant))
                                        {
                                            host_tx.extend(enc);
                                        }
                                    }
                                }
                                DataFrame::HalfClose => {
                                    self.client_rx.drain(..consumed);
                                    *client_eof = true;
                                    if pending_client_tx_data.is_empty() {
                                        if let Ok(enc) =
                                            encode_unix_data_frame(&DataFrame::HalfClose)
                                        {
                                            host_tx.extend(enc);
                                        }
                                    } else {
                                        *pending_client_half_close = true;
                                    }
                                }
                                DataFrame::Cancel => {
                                    self.client_rx.drain(..consumed);
                                    pending_client_tx_data.clear();
                                    *pending_client_tx_bytes = 0;
                                    *pending_client_half_close = false;
                                    *client_eof = true;
                                    *closing_after_host_flush = true;
                                    if let Ok(enc) = encode_unix_data_frame(&DataFrame::Cancel) {
                                        host_tx.extend(enc);
                                    }
                                    break;
                                }
                                DataFrame::Closed(_) => {
                                    self.client_rx.drain(..consumed);
                                    client_broken = true;
                                    break;
                                }
                            },
                            Ok(None) => break,
                            Err(_) => {
                                client_broken = true;
                                break;
                            }
                        }
                    }
                }
            }
        }

        // 5. Flush any newly queued `host_tx` frames immediately!
        if client_broken
            && let Phase::Streaming { host, .. } = &self.phase
            && let Ok(cancel) = encode_unix_data_frame(&DataFrame::Cancel)
        {
            let _ = host.send(&cancel, MSG_DONTWAIT | MSG_NOSIGNAL);
            return false;
        }
        if !host_broken && let Phase::Streaming { host, host_tx, .. } = &mut self.phase {
            while !host_tx.is_empty() {
                let (front, _) = host_tx.as_slices();
                if front.is_empty() {
                    host_tx.make_contiguous();
                    continue;
                }
                match host.send(front, MSG_DONTWAIT | MSG_NOSIGNAL) {
                    Ok(0) => {
                        host_broken = true;
                        break;
                    }
                    Ok(n) => {
                        host_tx.drain(..n);
                    }
                    Err(Errno::EAGAIN) => break,
                    Err(Errno::EINTR) => continue,
                    Err(_) => {
                        host_broken = true;
                        break;
                    }
                }
            }
        }

        // 6. Handle half-close propagation, host closure, and host loss cleanly!
        if host_broken {
            if let Phase::Streaming {
                mode: StreamMode::Framed,
                host_closed: None,
                ..
            } = &self.phase
                && let Ok(enc) = encode_unix_data_frame(&DataFrame::Closed(StreamClosed {
                    errno: Some(Errno::ECONNRESET),
                    error: Some(NetErrorKind::StreamReset),
                    message: Some("host bridge disconnected".into()),
                    bytes_sent: 0,
                    bytes_received: 0,
                }))
            {
                self.client_tx.extend(enc);
                self.phase = Phase::DrainingClient;
                let _ = self.flush_client_tx();
                return !self.client_tx.is_empty();
            }
            // In Raw mode (or already closed): flush remaining buffered data if any, then drop!
            if !self.client_tx.is_empty() {
                self.phase = Phase::DrainingClient;
                let _ = self.flush_client_tx();
                return !self.client_tx.is_empty();
            }
            return false;
        }

        if let Phase::Streaming {
            mode,
            client_eof,
            host_eof,
            client_shut_wr,
            host_closed,
            host_tx,
            pending_client_tx_data,
            pending_client_half_close,
            closing_after_host_flush,
            ..
        } = &mut self.phase
        {
            if *closing_after_host_flush && host_tx.is_empty() {
                return false;
            }
            if *host_eof
                && self.client_tx.is_empty()
                && !*client_shut_wr
                && *mode == StreamMode::Raw
            {
                let _ = self.client.shutdown(SHUT_WR);
                *client_shut_wr = true;
            }
            if let Some(info) = host_closed {
                if info.errno.is_some() {
                    // Error closure (e.g. EDQUOT, ETIMEDOUT, EACCES): finish draining error frame/data then close.
                    if self.client_tx.is_empty() {
                        return false;
                    }
                    self.phase = Phase::DrainingClient;
                    return true;
                }
                if self.client_tx.is_empty() && host_tx.is_empty() {
                    return false;
                }
            }
            if *client_eof
                && *host_eof
                && self.client_tx.is_empty()
                && host_tx.is_empty()
                && pending_client_tx_data.is_empty()
                && !*pending_client_half_close
            {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::net_ctl::{NetQuota, TlsMode};
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Default)]
    struct PipeEnd {
        rx: VecDeque<u8>,
        rx_fds: Vec<u32>,
        tx_cap: usize,
        closed_rx: bool,
        closed_tx: bool,
        shut_wr_called: bool,
    }

    struct MockPair;

    struct MockSock {
        fd: u32,
        read_end: Rc<RefCell<PipeEnd>>,
        write_end: Rc<RefCell<PipeEnd>>,
    }

    impl MockPair {
        fn pair(fd_a: u32, fd_b: u32, cap: usize) -> (MockSock, MockSock) {
            Self::pair_asym(fd_a, fd_b, cap, cap)
        }

        fn pair_asym(
            fd_a: u32,
            fd_b: u32,
            cap_a_to_b: usize,
            cap_b_to_a: usize,
        ) -> (MockSock, MockSock) {
            let a_to_b = Rc::new(RefCell::new(PipeEnd {
                tx_cap: cap_a_to_b,
                ..Default::default()
            }));
            let b_to_a = Rc::new(RefCell::new(PipeEnd {
                tx_cap: cap_b_to_a,
                ..Default::default()
            }));
            (
                MockSock {
                    fd: fd_a,
                    read_end: b_to_a.clone(),
                    write_end: a_to_b.clone(),
                },
                MockSock {
                    fd: fd_b,
                    read_end: a_to_b,
                    write_end: b_to_a,
                },
            )
        }
    }

    impl MockSock {
        fn close_write(&self) {
            self.write_end.borrow_mut().closed_tx = true;
        }
        fn close_both(&self) {
            self.write_end.borrow_mut().closed_tx = true;
            self.read_end.borrow_mut().closed_rx = true;
        }
        fn shut_wr_called(&self) -> bool {
            self.write_end.borrow().shut_wr_called
        }
    }

    impl NetdIo for MockSock {
        fn raw_fd(&self) -> u32 {
            self.fd
        }
        fn recv(&self, buf: &mut [u8], flags: u32) -> Result<usize, Errno> {
            let mut end = self.read_end.borrow_mut();
            if end.rx.is_empty() {
                if end.closed_tx {
                    return Ok(0);
                }
                return Err(Errno::EAGAIN);
            }
            let n = buf.len().min(end.rx.len());
            if (flags & MSG_PEEK) != 0 {
                for (i, slot) in buf.iter_mut().take(n).enumerate() {
                    *slot = end.rx[i];
                }
                return Ok(n);
            }
            for slot in buf.iter_mut().take(n) {
                *slot = end.rx.pop_front().unwrap();
            }
            Ok(n)
        }
        fn send(&self, data: &[u8], _flags: u32) -> Result<usize, Errno> {
            self.send_with_fds(data, &[], 0)
        }
        fn send_with_fds(&self, data: &[u8], fds: &[u32], _flags: u32) -> Result<usize, Errno> {
            let mut end = self.write_end.borrow_mut();
            if end.closed_rx {
                return Err(Errno::EPIPE);
            }
            let space = end.tx_cap.saturating_sub(end.rx.len());
            if space == 0 {
                return Err(Errno::EAGAIN);
            }
            let n = data.len().min(space);
            end.rx.extend(&data[..n]);
            end.rx_fds.extend_from_slice(fds);
            Ok(n)
        }
        fn shutdown(&self, how: u32) -> Result<(), Errno> {
            if how == SHUT_WR {
                let mut end = self.write_end.borrow_mut();
                end.closed_tx = true;
                end.shut_wr_called = true;
            }
            Ok(())
        }
    }

    struct MockConnector {
        next: Option<Result<MockSock, Errno>>,
    }

    impl HostConnector<MockSock> for MockConnector {
        fn connect_host(&mut self) -> Result<MockSock, Errno> {
            self.next.take().unwrap_or(Err(Errno::ENOENT))
        }
    }

    fn read_resp(sock: &MockSock) -> NetdResp {
        let mut hdr = [0u8; 4];
        assert_eq!(sock.recv(&mut hdr, 0).unwrap(), 4);
        let len = u32::from_be_bytes(hdr) as usize;
        let mut body = vec![0u8; len];
        assert_eq!(sock.recv(&mut body, 0).unwrap(), len);
        decode_control_payload(&body).unwrap()
    }

    #[test]
    fn raw_stream_echo_half_close_and_credit_backpressure() {
        let (client_end, netd_client) = MockPair::pair(10, 11, 4096); // small 4 KiB client socket buffer!
        let (netd_host, host_end) = MockPair::pair(20, 21, 256 * 1024);
        let mut conn = MockConnector {
            next: Some(Ok(netd_host)),
        };
        let mut sess = ClientSession::new(
            netd_client,
            PeerCred {
                pid: 42,
                uid: 1000,
                gid: 1000,
            },
        );

        // 1. Hello / Welcome
        let hello = encode_control_frame(&NetdReq::Hello {
            versions: vec![NETD_VERSION],
        })
        .unwrap();
        client_end.send(&hello, 0).unwrap();
        assert!(sess.step(&mut conn, 0));
        assert!(matches!(
            read_resp(&client_end),
            NetdResp::Welcome {
                version: NETD_VERSION,
                ..
            }
        ));

        // 2. Connect (Raw mode) -> forwarded with SCM_RIGHTS = [11]
        let req = encode_control_frame(&NetdReq::Connect {
            host: "93.184.216.34".into(),
            port: 80,
            tls: TlsMode::Off,
            mode: StreamMode::Raw,
            timeout_ms: None,
        })
        .unwrap();
        client_end.send(&req, 0).unwrap();
        assert!(sess.step(&mut conn, 0));

        // Verify host received Open + SCM_RIGHTS = [netd_client fd = 11]
        assert_eq!(host_end.read_end.borrow().rx_fds, vec![11]);
        let mut hdr = [0u8; 4];
        assert_eq!(host_end.recv(&mut hdr, 0).unwrap(), 4);
        let len = u32::from_be_bytes(hdr) as usize;
        let mut body = vec![0u8; len];
        assert_eq!(host_end.recv(&mut body, 0).unwrap(), len);
        assert!(matches!(
            decode_control_payload::<HostNetReq>(&body).unwrap(),
            HostNetReq::Open { port: 80, .. }
        ));

        // Host replies Opened with 32 KiB window
        let opened = encode_control_frame(&HostNetResp::Opened {
            stream_id: "s-1".into(),
            peer_addr: Some("93.184.216.34:80".into()),
            initial_window: 32 * 1024,
            quota: NetQuota::default(),
        })
        .unwrap();
        host_end.send(&opened, 0).unwrap();
        assert!(sess.step(&mut conn, 1));
        assert!(matches!(
            read_resp(&client_end),
            NetdResp::Connected {
                mode: StreamMode::Raw,
                ..
            }
        ));

        // 3. Backpressure check: host sends 16 KiB while client socket only accepts 4 KiB.
        // netd MUST NOT send CREDIT for bytes still stuck in client_tx!
        let big_chunk = vec![0xab; 16 * 1024];
        host_end
            .send(
                &encode_unix_data_frame(&DataFrame::Data(big_chunk.clone())).unwrap(),
                0,
            )
            .unwrap();
        assert!(sess.step(&mut conn, 1));
        // Only 4 KiB fit into client_end's buffer (< 8 KiB threshold), so NO credit sent yet!
        assert_eq!(host_end.recv(&mut [0u8; 64], 0), Err(Errno::EAGAIN));

        // Drain all 16 KiB at the client in 4 KiB chunks.
        let mut got = Vec::new();
        while got.len() < big_chunk.len() {
            let mut tmp = [0u8; 4096];
            if let Ok(n) = client_end.recv(&mut tmp, 0) {
                got.extend_from_slice(&tmp[..n]);
            }
            assert!(sess.step(&mut conn, 1));
        }
        assert_eq!(got, big_chunk);

        // Now host MUST have received CREDIT summing to 16 KiB!
        let mut raw_host = Vec::new();
        let mut tmp = [0u8; 256];
        while let Ok(n) = host_end.recv(&mut tmp, 0) {
            raw_host.extend_from_slice(&tmp[..n]);
        }
        let mut credited = 0u32;
        while let Some((frame, used)) = try_decode_unix_data_frame(&raw_host).unwrap() {
            raw_host.drain(..used);
            if let DataFrame::Credit(c) = frame {
                credited += c;
            }
        }
        assert_eq!(credited, 16 * 1024);

        // 4. Client writes + half-closes -> host receives DATA + HALF_CLOSE; host replies HALF_CLOSE -> client gets SHUT_WR.
        client_end.send(b"ping", 0).unwrap();
        client_end.close_write();
        assert!(sess.step(&mut conn, 1));
        let mut host_in = Vec::new();
        while let Ok(n) = host_end.recv(&mut tmp, 0) {
            host_in.extend_from_slice(&tmp[..n]);
        }
        let (f1, u1) = try_decode_unix_data_frame(&host_in).unwrap().unwrap();
        host_in.drain(..u1);
        assert_eq!(f1, DataFrame::Data(b"ping".to_vec()));
        let (f2, _) = try_decode_unix_data_frame(&host_in).unwrap().unwrap();
        assert_eq!(f2, DataFrame::HalfClose);

        // Host replies HalfClose -> netd shuts down client write side and finishes cleanly!
        host_end
            .send(&encode_unix_data_frame(&DataFrame::HalfClose).unwrap(), 0)
            .unwrap();
        let alive = sess.step(&mut conn, 1);
        assert!(!alive);
        assert!(sess.client.shut_wr_called());
    }

    #[test]
    fn mid_connect_client_disconnect_cancels_host_and_host_loss_tears_down_client() {
        // Part A: Client drops mid-Opening -> netd sends Cancel to host and terminates immediately.
        let (client_end, netd_client) = MockPair::pair(10, 11, 65_536);
        let (netd_host, host_end) = MockPair::pair(20, 21, 65_536);
        let mut conn = MockConnector {
            next: Some(Ok(netd_host)),
        };
        let mut sess = ClientSession::new(
            netd_client,
            PeerCred {
                pid: 9,
                uid: 1000,
                gid: 1000,
            },
        );
        client_end
            .send(
                &encode_control_frame(&NetdReq::Hello {
                    versions: vec![NETD_VERSION],
                })
                .unwrap(),
                0,
            )
            .unwrap();
        assert!(sess.step(&mut conn, 0));
        let _ = read_resp(&client_end);
        client_end
            .send(
                &encode_control_frame(&NetdReq::Connect {
                    host: "93.184.216.34".into(),
                    port: 443,
                    tls: TlsMode::On,
                    mode: StreamMode::Framed,
                    timeout_ms: None,
                })
                .unwrap(),
                0,
            )
            .unwrap();
        assert!(sess.step(&mut conn, 0));
        // Drain Open request at host
        let mut drain = [0u8; 512];
        assert!(host_end.recv(&mut drain, 0).unwrap() > 0);
        // Now client dies (SIGKILL / close) before HostNetResp::Opened arrives!
        client_end.close_both();
        assert!(!sess.step(&mut conn, 1));
        let n = host_end.recv(&mut drain, 0).unwrap();
        let (frame, _) = try_decode_unix_data_frame(&drain[..n]).unwrap().unwrap();
        assert_eq!(frame, DataFrame::Cancel);

        // Part B: Abrupt host loss mid-Framed stream emits StreamReset Closed frame to client.
        let (client_end2, netd_client2) = MockPair::pair(30, 31, 65_536);
        let (netd_host2, host_end2) = MockPair::pair(40, 41, 65_536);
        let mut conn2 = MockConnector {
            next: Some(Ok(netd_host2)),
        };
        let mut sess2 = ClientSession::new(
            netd_client2,
            PeerCred {
                pid: 10,
                uid: 1000,
                gid: 1000,
            },
        );
        client_end2
            .send(
                &encode_control_frame(&NetdReq::Hello {
                    versions: vec![NETD_VERSION],
                })
                .unwrap(),
                0,
            )
            .unwrap();
        assert!(sess2.step(&mut conn2, 0));
        let _ = read_resp(&client_end2);
        client_end2
            .send(
                &encode_control_frame(&NetdReq::Connect {
                    host: "93.184.216.34".into(),
                    port: 443,
                    tls: TlsMode::Off,
                    mode: StreamMode::Framed,
                    timeout_ms: None,
                })
                .unwrap(),
                0,
            )
            .unwrap();
        assert!(sess2.step(&mut conn2, 0));
        host_end2
            .send(
                &encode_control_frame(&HostNetResp::Opened {
                    stream_id: "s-2".into(),
                    peer_addr: None,
                    initial_window: NET_INITIAL_WINDOW_BYTES,
                    quota: NetQuota::default(),
                })
                .unwrap(),
                0,
            )
            .unwrap();
        assert!(sess2.step(&mut conn2, 1));
        let _ = read_resp(&client_end2);
        // Host abruptly dies!
        host_end2.close_both();
        assert!(!sess2.step(&mut conn2, 1));
        let mut out = [0u8; 512];
        let n = client_end2.recv(&mut out, 0).unwrap();
        let (f, _) = try_decode_unix_data_frame(&out[..n]).unwrap().unwrap();
        assert!(matches!(
            f,
            DataFrame::Closed(StreamClosed {
                errno: Some(Errno::ECONNRESET),
                error: Some(NetErrorKind::StreamReset),
                ..
            })
        ));
    }

    #[test]
    fn fast_ssrf_prevalidation_blocks_private_ips_without_touching_host() {
        let (client_end, netd_client) = MockPair::pair(50, 51, 65_536);
        let mut conn = MockConnector { next: None };
        let mut sess = ClientSession::new(
            netd_client,
            PeerCred {
                pid: 12,
                uid: 1000,
                gid: 1000,
            },
        );
        client_end
            .send(
                &encode_control_frame(&NetdReq::Hello {
                    versions: vec![NETD_VERSION],
                })
                .unwrap(),
                0,
            )
            .unwrap();
        assert!(sess.step(&mut conn, 0));
        let _ = read_resp(&client_end);
        client_end
            .send(
                &encode_control_frame(&NetdReq::Connect {
                    host: "169.254.169.254".into(),
                    port: 80,
                    tls: TlsMode::Off,
                    mode: StreamMode::Raw,
                    timeout_ms: None,
                })
                .unwrap(),
                0,
            )
            .unwrap();
        let _ = sess.step(&mut conn, 0);
        assert!(matches!(
            read_resp(&client_end),
            NetdResp::Error {
                errno: Errno::EACCES,
                error: NetErrorKind::PrivateAddressDenied,
                ..
            }
        ));
    }

    #[test]
    fn credit_u32_max_clamped_and_framed_controls_not_hol_blocked() {
        let (client_end, netd_client) = MockPair::pair(60, 61, 256 * 1024);
        let (netd_host, host_end) = MockPair::pair(70, 71, 256 * 1024);
        let mut conn = MockConnector {
            next: Some(Ok(netd_host)),
        };
        let mut sess = ClientSession::new(
            netd_client,
            PeerCred {
                pid: 20,
                uid: 1000,
                gid: 1000,
            },
        );
        client_end
            .send(
                &encode_control_frame(&NetdReq::Hello {
                    versions: vec![NETD_VERSION],
                })
                .unwrap(),
                0,
            )
            .unwrap();
        assert!(sess.step(&mut conn, 0));
        let _ = read_resp(&client_end);
        client_end
            .send(
                &encode_control_frame(&NetdReq::Connect {
                    host: "93.184.216.34".into(),
                    port: 443,
                    tls: TlsMode::Off,
                    mode: StreamMode::Framed,
                    timeout_ms: None,
                })
                .unwrap(),
                0,
            )
            .unwrap();
        assert!(sess.step(&mut conn, 0));
        let mut drain = [0u8; 4096];
        assert!(host_end.recv(&mut drain, 0).unwrap() > 0);
        host_end
            .send(
                &encode_control_frame(&HostNetResp::Opened {
                    stream_id: "s-clamp".into(),
                    peer_addr: None,
                    initial_window: NET_INITIAL_WINDOW_BYTES,
                    quota: NetQuota::default(),
                })
                .unwrap(),
                0,
            )
            .unwrap();
        assert!(sess.step(&mut conn, 1));
        let _ = read_resp(&client_end);

        // 1. Send Credit(u32::MAX) when host_recv_window is already full -> MUST NOT forward credit!
        client_end
            .send(
                &encode_unix_data_frame(&DataFrame::Credit(u32::MAX)).unwrap(),
                0,
            )
            .unwrap();
        assert!(sess.step(&mut conn, 1));
        assert_eq!(host_end.recv(&mut drain, 0), Err(Errno::EAGAIN));

        // 2. Host sends 16 KiB, client reads it and sends Credit(u32::MAX) -> clamped to 16 KiB!
        host_end
            .send(
                &encode_unix_data_frame(&DataFrame::Data(vec![b'A'; 16 * 1024])).unwrap(),
                0,
            )
            .unwrap();
        assert!(sess.step(&mut conn, 1));
        let mut rx = vec![0u8; 20 * 1024];
        let n = client_end.recv(&mut rx, 0).unwrap();
        assert!(n > 16 * 1024);
        client_end
            .send(
                &encode_unix_data_frame(&DataFrame::Credit(u32::MAX)).unwrap(),
                0,
            )
            .unwrap();
        assert!(sess.step(&mut conn, 1));
        let hn = host_end.recv(&mut drain, 0).unwrap();
        let (frame, _) = try_decode_unix_data_frame(&drain[..hn]).unwrap().unwrap();
        assert_eq!(frame, DataFrame::Credit(16 * 1024));

        // 3. Exhaust host_send_credit (64 KiB) + queue 16 KiB un-credited Data + trailing Credit(8 KiB)
        //    after host delivers 8 KiB: Credit MUST NOT be HoL-blocked behind un-credited Data!
        for _ in 0..4 {
            let frame = encode_unix_data_frame(&DataFrame::Data(vec![b'B'; 16 * 1024])).unwrap();
            assert_eq!(client_end.send(&frame, 0).unwrap(), frame.len());
        }
        let mut drained_host = 0usize;
        let mut host_got = vec![0u8; 128 * 1024];
        for _ in 0..4 {
            assert!(sess.step(&mut conn, 1));
            while let Ok(n) = host_end.recv(&mut host_got, 0) {
                drained_host += n;
            }
            if drained_host >= 4 * (5 + 16 * 1024) {
                break;
            }
        }
        assert_eq!(drained_host, 4 * (5 + 16 * 1024));

        // Host sends 8 KiB so client has 8 KiB of legal credit headroom.
        host_end
            .send(
                &encode_unix_data_frame(&DataFrame::Data(vec![b'C'; 8 * 1024])).unwrap(),
                0,
            )
            .unwrap();
        assert!(sess.step(&mut conn, 1));
        let _ = client_end.recv(&mut rx, 0).unwrap();

        // Client sends 16 KiB Data (0 send credit!) followed immediately by Credit(8 KiB).
        let uncredited = encode_unix_data_frame(&DataFrame::Data(vec![b'D'; 16 * 1024])).unwrap();
        assert_eq!(client_end.send(&uncredited, 0).unwrap(), uncredited.len());
        let credit_frame = encode_unix_data_frame(&DataFrame::Credit(8 * 1024)).unwrap();
        assert_eq!(
            client_end.send(&credit_frame, 0).unwrap(),
            credit_frame.len()
        );
        assert!(sess.step(&mut conn, 1));
        let hn2 = host_end.recv(&mut drain, 0).unwrap();
        let (f2, _) = try_decode_unix_data_frame(&drain[..hn2]).unwrap().unwrap();
        assert_eq!(
            f2,
            DataFrame::Credit(8 * 1024),
            "Credit must not be HoL-blocked behind un-credited Data"
        );
    }

    #[test]
    fn partial_connected_flush_not_credited_and_pipelined_raw_bytes_forwarded() {
        // Asymmetric pair: 64 KiB client->netd, tiny 16-byte netd->client so NetdResp::Connected
        // flushes across multiple steps without falsely emitting Raw-mode Credit!
        let (client_end, netd_client) = MockPair::pair_asym(80, 81, 65_536, 16);
        let (netd_host, host_end) = MockPair::pair(90, 91, 65_536);
        let mut conn = MockConnector {
            next: Some(Ok(netd_host)),
        };
        let mut sess = ClientSession::new(
            netd_client,
            PeerCred {
                pid: 21,
                uid: 1000,
                gid: 1000,
            },
        );
        let hello = encode_control_frame(&NetdReq::Hello {
            versions: vec![NETD_VERSION],
        })
        .unwrap();
        assert_eq!(client_end.send(&hello, 0).unwrap(), hello.len());
        let mut welcome_buf = Vec::new();
        for _ in 0..32 {
            assert!(sess.step(&mut conn, 0));
            let mut tmp = [0u8; 64];
            if let Ok(n) = client_end.recv(&mut tmp, 0) {
                welcome_buf.extend_from_slice(&tmp[..n]);
            }
            if welcome_buf.len() >= 4 {
                let len = u32::from_be_bytes(welcome_buf[..4].try_into().unwrap()) as usize;
                if welcome_buf.len() >= 4 + len {
                    break;
                }
            }
        }
        // Pipeline Connect + raw payload in one write so "PIPELINED" sits in `client_rx` on Opening.
        let mut combined = encode_control_frame(&NetdReq::Connect {
            host: "93.184.216.34".into(),
            port: 80,
            tls: TlsMode::Off,
            mode: StreamMode::Raw,
            timeout_ms: None,
        })
        .unwrap();
        combined.extend_from_slice(b"PIPELINED");
        assert_eq!(client_end.send(&combined, 0).unwrap(), combined.len());
        assert!(sess.step(&mut conn, 0));
        let mut hbuf = [0u8; 4096];
        assert!(host_end.recv(&mut hbuf, 0).unwrap() > 0);
        // Host replies Opened; NetdResp::Connected flushes in 16-byte slices across multiple steps.
        let opened = encode_control_frame(&HostNetResp::Opened {
            stream_id: "s-pipe".into(),
            peer_addr: None,
            initial_window: NET_INITIAL_WINDOW_BYTES,
            quota: NetQuota::default(),
        })
        .unwrap();
        assert_eq!(host_end.send(&opened, 0).unwrap(), opened.len());
        let mut conn_buf = Vec::new();
        for _ in 0..64 {
            assert!(sess.step(&mut conn, 1));
            let mut tmp = [0u8; 64];
            if let Ok(n) = client_end.recv(&mut tmp, 0) {
                conn_buf.extend_from_slice(&tmp[..n]);
            }
            if conn_buf.len() >= 4 {
                let len = u32::from_be_bytes(conn_buf[..4].try_into().unwrap()) as usize;
                if conn_buf.len() >= 4 + len {
                    break;
                }
            }
        }
        // Host MUST have received ONLY the pipelined "PIPELINED" DataFrame (NO bogus Credit from Connected)!
        let hn = host_end.recv(&mut hbuf, 0).unwrap();
        let (f, used) = try_decode_unix_data_frame(&hbuf[..hn]).unwrap().unwrap();
        assert_eq!(f, DataFrame::Data(b"PIPELINED".to_vec()));
        assert_eq!(used, hn, "Connected control bytes must not emit Credit");
    }

    #[test]
    fn host_half_close_with_zero_send_credit_drains_pending_framed_tx_and_half_close() {
        let (client_end, netd_client) = MockPair::pair(100, 101, 256 * 1024);
        let (netd_host, host_end) = MockPair::pair(110, 111, 256 * 1024);
        let mut conn = MockConnector {
            next: Some(Ok(netd_host)),
        };
        let mut sess = ClientSession::new(
            netd_client,
            PeerCred {
                pid: 22,
                uid: 1000,
                gid: 1000,
            },
        );
        let hello = encode_control_frame(&NetdReq::Hello {
            versions: vec![NETD_VERSION],
        })
        .unwrap();
        assert_eq!(client_end.send(&hello, 0).unwrap(), hello.len());
        assert!(sess.step(&mut conn, 0));
        let _ = read_resp(&client_end);
        let connect = encode_control_frame(&NetdReq::Connect {
            host: "93.184.216.34".into(),
            port: 80,
            tls: TlsMode::Off,
            mode: StreamMode::Framed,
            timeout_ms: None,
        })
        .unwrap();
        assert_eq!(client_end.send(&connect, 0).unwrap(), connect.len());
        assert!(sess.step(&mut conn, 0));
        let mut hbuf = vec![0u8; 128 * 1024];
        assert!(host_end.recv(&mut hbuf, 0).unwrap() > 0);
        let opened = encode_control_frame(&HostNetResp::Opened {
            stream_id: "s-half".into(),
            peer_addr: None,
            initial_window: NET_INITIAL_WINDOW_BYTES,
            quota: NetQuota::default(),
        })
        .unwrap();
        assert_eq!(host_end.send(&opened, 0).unwrap(), opened.len());
        assert!(sess.step(&mut conn, 1));
        let _ = read_resp(&client_end);

        // 1. Exhaust host_send_credit (64 KiB).
        for _ in 0..4 {
            let f = encode_unix_data_frame(&DataFrame::Data(vec![b'X'; 16 * 1024])).unwrap();
            assert_eq!(client_end.send(&f, 0).unwrap(), f.len());
        }
        let mut drained = 0usize;
        for _ in 0..4 {
            assert!(sess.step(&mut conn, 1));
            while let Ok(n) = host_end.recv(&mut hbuf, 0) {
                drained += n;
            }
            if drained >= 4 * (5 + 16 * 1024) {
                break;
            }
        }
        assert_eq!(drained, 4 * (5 + 16 * 1024));

        // 2. Host sends HalfClose (host_eof = true), while host_send_credit == 0.
        let hc = encode_unix_data_frame(&DataFrame::HalfClose).unwrap();
        assert_eq!(host_end.send(&hc, 0).unwrap(), hc.len());
        assert!(sess.step(&mut conn, 1));
        let mut cbuf = [0u8; 512];
        let cn = client_end.recv(&mut cbuf, 0).unwrap();
        assert_eq!(
            try_decode_unix_data_frame(&cbuf[..cn]).unwrap().unwrap().0,
            DataFrame::HalfClose
        );

        // 3. Client queues a final Data("tail") + HalfClose while send_credit == 0.
        //    Session MUST stay alive until host sends Credit and both frames drain!
        let tail = encode_unix_data_frame(&DataFrame::Data(b"tail".to_vec())).unwrap();
        assert_eq!(client_end.send(&tail, 0).unwrap(), tail.len());
        assert_eq!(client_end.send(&hc, 0).unwrap(), hc.len());
        assert!(
            sess.step(&mut conn, 1),
            "session must NOT close while pending_client_tx_data / pending_client_half_close await credit"
        );
        assert_eq!(host_end.recv(&mut hbuf, 0), Err(Errno::EAGAIN));

        // 4. Host grants Credit(4) -> "tail" + HalfClose flush cleanly to host, then session closes!
        let cr = encode_unix_data_frame(&DataFrame::Credit(4)).unwrap();
        assert_eq!(host_end.send(&cr, 0).unwrap(), cr.len());
        assert!(!sess.step(&mut conn, 1));

        let hn = host_end.recv(&mut hbuf, 0).unwrap();
        let (f1, u1) = try_decode_unix_data_frame(&hbuf[..hn]).unwrap().unwrap();
        assert_eq!(f1, DataFrame::Data(b"tail".to_vec()));
        let (f2, u2) = try_decode_unix_data_frame(&hbuf[u1..hn]).unwrap().unwrap();
        assert_eq!(f2, DataFrame::HalfClose);
        assert_eq!(u1 + u2, hn);
    }
}

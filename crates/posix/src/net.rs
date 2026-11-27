//! Outbound stream networking client helpers for WASI/WASIX guests (Phase 10a, `#86`).
//!
//! Two layers are provided:
//! 1. [`NetStream`] — direct client for `/run/netd.sock` (`abi::net_ctl` v1 protocol),
//!    supporting raw byte streams (`StreamMode::Raw`), credit-framed streams (`StreamMode::Framed`),
//!    gateway-terminated TLS (`TlsMode::On` on Cloudflare Worker; `TlsMode::StartTls` returns
//!    `EOPNOTSUPP` on both hosts), DNS resolution (native), and status queries.
//! 2. [`WasixTcpStream`] — standard `wasix_32v1` + `wasi_snapshot_preview1` socket calls
//!    (`sock_open`, `sock_connect`, `sock_recv`, `sock_send`, `sock_shutdown`), which both the
//!    browser WASI engine and `os-native` route transparently over `/run/netd.sock`.

use crate::socket::{MSG_NOSIGNAL, SHUT_RD, SHUT_RDWR, SHUT_WR, UnixStream};
use abi::Errno;
use abi::net_ctl::{
    DataFrame, NET_CONTROL_MAX_BYTES, NET_DATA_CHUNK_MAX, NETD_SOCK, NETD_VERSION, NetErrorKind,
    NetFailure, NetQuota, NetdReq, NetdResp, StreamClosed, StreamMode, TlsMode,
    decode_control_payload, decode_data_frame_body, encode_control_frame, encode_unix_data_frame,
    read_control_frame,
};
use std::collections::VecDeque;
use std::net::SocketAddr;

/// Structured error returned by [`NetStream`] control-plane operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetError {
    pub errno: Errno,
    pub error: NetErrorKind,
    pub message: String,
}

impl NetError {
    pub fn from_errno(errno: Errno, message: impl Into<String>) -> Self {
        let f = NetFailure::from(errno);
        let msg = message.into();
        Self {
            errno,
            error: f.kind,
            message: if msg.is_empty() { f.message } else { msg },
        }
    }
}

impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.message.is_empty() {
            write!(f, "{:?}", self.errno)
        } else {
            write!(f, "{:?}: {}", self.errno, self.message)
        }
    }
}

impl std::error::Error for NetError {}

impl From<Errno> for NetError {
    fn from(errno: Errno) -> Self {
        Self::from_errno(errno, "")
    }
}

/// Snapshot returned by `netd` `Status`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetStatus {
    pub version: u32,
    pub host_kind: String,
    pub active_streams: u32,
    pub ready: bool,
}

/// Connected outbound TCP/TLS stream mediated by `/run/netd.sock`.
pub struct NetStream {
    sock: UnixStream,
    stream_id: String,
    peer_addr: Option<String>,
    initial_window: u32,
    quota: NetQuota,
    mode: StreamMode,
    rx_buf: VecDeque<u8>,
}

impl NetStream {
    /// Connect a raw byte stream via `/run/netd.sock`.
    pub fn connect_raw(
        host: &str,
        port: u16,
        tls: TlsMode,
        timeout_ms: Option<u64>,
    ) -> Result<Self, NetError> {
        Self::connect_via(NETD_SOCK, host, port, tls, StreamMode::Raw, timeout_ms)
    }

    /// Connect a framed (`0x01..0x05`) stream via `/run/netd.sock`.
    pub fn connect_framed(
        host: &str,
        port: u16,
        tls: TlsMode,
        timeout_ms: Option<u64>,
    ) -> Result<Self, NetError> {
        Self::connect_via(NETD_SOCK, host, port, tls, StreamMode::Framed, timeout_ms)
    }

    /// Connect via an explicit `netd` Unix socket path.
    pub fn connect_via(
        sock_path: &str,
        host: &str,
        port: u16,
        tls: TlsMode,
        mode: StreamMode,
        timeout_ms: Option<u64>,
    ) -> Result<Self, NetError> {
        let sock = UnixStream::connect(sock_path)
            .map_err(|e| NetError::from_errno(e, format!("connect {sock_path}")))?;
        handshake_hello(&sock)?;
        send_req(
            &sock,
            &NetdReq::Connect {
                host: host.to_string(),
                port,
                tls,
                mode,
                timeout_ms,
            },
        )?;
        match recv_resp(&sock)? {
            NetdResp::Connected {
                stream_id,
                peer_addr,
                initial_window,
                quota,
                ..
            } => Ok(Self {
                sock,
                stream_id,
                peer_addr,
                initial_window,
                quota,
                mode,
                rx_buf: VecDeque::new(),
            }),
            NetdResp::Error {
                errno,
                error,
                message,
            } => Err(NetError {
                errno,
                error,
                message,
            }),
            _ => Err(NetError::from_errno(
                Errno::EIO,
                "unexpected response from netd",
            )),
        }
    }

    /// Query `/run/netd.sock` status without dialing any remote network target.
    pub fn status() -> Result<NetStatus, NetError> {
        Self::status_via(NETD_SOCK)
    }

    /// Query `netd` status at an explicit socket path.
    pub fn status_via(sock_path: &str) -> Result<NetStatus, NetError> {
        let sock = UnixStream::connect(sock_path)
            .map_err(|e| NetError::from_errno(e, format!("connect {sock_path}")))?;
        handshake_hello(&sock)?;
        send_req(&sock, &NetdReq::Status {})?;
        match recv_resp(&sock)? {
            NetdResp::Status {
                version,
                host_kind,
                active_streams,
                ready,
            } => Ok(NetStatus {
                version,
                host_kind,
                active_streams,
                ready,
            }),
            NetdResp::Error {
                errno,
                error,
                message,
            } => Err(NetError {
                errno,
                error,
                message,
            }),
            _ => Err(NetError::from_errno(
                Errno::EIO,
                "unexpected status response from netd",
            )),
        }
    }

    /// Resolve a permitted hostname via `/run/netd.sock`.
    pub fn resolve(host: &str, port: u16) -> Result<Vec<String>, NetError> {
        Self::resolve_via(NETD_SOCK, host, port)
    }

    /// Resolve a permitted hostname via an explicit `netd` socket path.
    pub fn resolve_via(sock_path: &str, host: &str, port: u16) -> Result<Vec<String>, NetError> {
        let sock = UnixStream::connect(sock_path)
            .map_err(|e| NetError::from_errno(e, format!("connect {sock_path}")))?;
        handshake_hello(&sock)?;
        send_req(
            &sock,
            &NetdReq::Resolve {
                host: host.to_string(),
                port,
            },
        )?;
        match recv_resp(&sock)? {
            NetdResp::Resolved { addrs } => Ok(addrs),
            NetdResp::Error {
                errno,
                error,
                message,
            } => Err(NetError {
                errno,
                error,
                message,
            }),
            _ => Err(NetError::from_errno(
                Errno::EIO,
                "unexpected resolve response from netd",
            )),
        }
    }

    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }

    pub fn peer_addr(&self) -> Option<&str> {
        self.peer_addr.as_deref()
    }

    pub fn initial_window(&self) -> u32 {
        self.initial_window
    }

    pub fn quota(&self) -> &NetQuota {
        &self.quota
    }

    pub fn mode(&self) -> StreamMode {
        self.mode
    }

    pub fn as_raw_fd(&self) -> u32 {
        self.sock.as_raw_fd()
    }

    pub fn set_nonblocking(&self, nb: bool) -> Result<(), Errno> {
        self.sock.set_nonblocking(nb)
    }

    pub fn shutdown(&self, how: u32) -> Result<(), Errno> {
        self.sock.shutdown(how)
    }

    pub fn shutdown_write(&self) -> Result<(), Errno> {
        self.sock.shutdown(SHUT_WR)
    }

    /// Read raw bytes (`StreamMode::Raw`), draining any buffered bytes first.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, Errno> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.rx_buf.is_empty() {
            let take = buf.len().min(self.rx_buf.len());
            for slot in buf.iter_mut().take(take) {
                *slot = self.rx_buf.pop_front().unwrap();
            }
            return Ok(take);
        }
        self.sock.recv(buf, 0)
    }

    /// Write raw bytes (`StreamMode::Raw`), returning bytes accepted.
    pub fn write(&self, data: &[u8]) -> Result<usize, Errno> {
        self.sock.send(data, MSG_NOSIGNAL)
    }

    /// Write all raw bytes (`StreamMode::Raw`), looping across partial writes.
    pub fn write_all(&self, mut data: &[u8]) -> Result<(), Errno> {
        while !data.is_empty() {
            let n = self.sock.send(data, MSG_NOSIGNAL)?;
            if n == 0 {
                return Err(Errno::EPIPE);
            }
            data = &data[n..];
        }
        Ok(())
    }

    /// Send a single framed data-plane message (`StreamMode::Framed`).
    pub fn send_frame(&self, frame: &DataFrame) -> Result<(), Errno> {
        let encoded = encode_unix_data_frame(frame).map_err(|_| Errno::EINVAL)?;
        self.write_all(&encoded)
    }

    /// Send framed data payload, splitting into `NET_DATA_CHUNK_MAX` chunks.
    pub fn send_framed_data(&self, data: &[u8]) -> Result<(), Errno> {
        for chunk in data.chunks(NET_DATA_CHUNK_MAX) {
            self.send_frame(&DataFrame::Data(chunk.to_vec()))?;
        }
        Ok(())
    }

    /// Send framed half-close (`0x03 HALF_CLOSE`).
    pub fn send_framed_half_close(&self) -> Result<(), Errno> {
        self.send_frame(&DataFrame::HalfClose)
    }

    /// Send framed flow-control credit (`0x02 CREDIT`).
    pub fn send_framed_credit(&self, bytes: u32) -> Result<(), Errno> {
        if bytes == 0 {
            return Ok(());
        }
        self.send_frame(&DataFrame::Credit(bytes))
    }

    /// Send framed cancellation (`0x04 CANCEL`).
    pub fn send_framed_cancel(&self) -> Result<(), Errno> {
        self.send_frame(&DataFrame::Cancel)
    }

    /// Receive the next data-plane frame (`StreamMode::Framed`), returning `Ok(None)` on clean EOF.
    pub fn recv_frame(&mut self) -> Result<Option<DataFrame>, Errno> {
        loop {
            if self.rx_buf.len() >= 5 {
                let contig = self.rx_buf.make_contiguous();
                let tag = contig[0];
                let len = u32::from_be_bytes([contig[1], contig[2], contig[3], contig[4]]) as usize;
                if len > NET_DATA_CHUNK_MAX.max(NET_CONTROL_MAX_BYTES) {
                    return Err(Errno::EMSGSIZE);
                }
                if contig.len() >= 5 + len {
                    let frame =
                        decode_data_frame_body(tag, &contig[5..5 + len]).map_err(|e| e.errno)?;
                    self.rx_buf.drain(..5 + len);
                    return Ok(Some(frame));
                }
            }
            let mut tmp = [0u8; 4096];
            match self.sock.recv(&mut tmp, 0) {
                Ok(0) => {
                    if self.rx_buf.is_empty() {
                        return Ok(None);
                    }
                    return Ok(Some(DataFrame::Closed(StreamClosed {
                        errno: Some(Errno::ECONNRESET),
                        error: Some(NetErrorKind::StreamReset),
                        message: Some("truncated frame at EOF".into()),
                        ..StreamClosed::default()
                    })));
                }
                Ok(n) => self.rx_buf.extend(&tmp[..n]),
                Err(Errno::EINTR) => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// Return true if there are unread buffered bytes already pulled from the socket.
    pub fn has_buffered_rx(&self) -> bool {
        !self.rx_buf.is_empty()
    }
}

fn send_all_sock(sock: &UnixStream, mut bytes: &[u8]) -> Result<(), Errno> {
    while !bytes.is_empty() {
        match sock.send(bytes, MSG_NOSIGNAL) {
            Ok(0) => return Err(Errno::EPIPE),
            Ok(n) => bytes = &bytes[n..],
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn send_req(sock: &UnixStream, req: &NetdReq) -> Result<(), NetError> {
    let frame =
        encode_control_frame(req).map_err(|e| NetError::from_errno(e.errno, e.to_string()))?;
    send_all_sock(sock, &frame).map_err(|e| NetError::from_errno(e, "write netd request"))
}

fn recv_resp(sock: &UnixStream) -> Result<NetdResp, NetError> {
    let payload = read_control_frame(|buf| sock.recv(buf, 0))
        .map_err(|e| NetError::from_errno(e.errno, e.to_string()))?;
    decode_control_payload::<NetdResp>(&payload)
        .map_err(|e| NetError::from_errno(e.errno, e.to_string()))
}

fn handshake_hello(sock: &UnixStream) -> Result<(), NetError> {
    send_req(
        sock,
        &NetdReq::Hello {
            versions: vec![NETD_VERSION],
        },
    )?;
    match recv_resp(sock)? {
        NetdResp::Welcome { .. } => Ok(()),
        NetdResp::Error {
            errno,
            error,
            message,
        } => Err(NetError {
            errno,
            error,
            message,
        }),
        _ => Err(NetError::from_errno(
            Errno::EPROTONOSUPPORT,
            "unexpected netd hello reply",
        )),
    }
}

/// Outbound TCP stream opened via standard `wasix_32v1` + `wasi_snapshot_preview1` socket imports.
pub struct WasixTcpStream {
    fd: u32,
}

#[cfg(target_arch = "wasm32")]
mod wasix_raw {
    #[repr(C)]
    pub struct Iovec {
        pub buf: *mut u8,
        pub len: usize,
    }

    #[repr(C)]
    pub struct Ciovec {
        pub buf: *const u8,
        pub len: usize,
    }

    #[link(wasm_import_module = "wasix_32v1")]
    unsafe extern "C" {
        pub fn sock_open(af: u32, ty: u32, pt: u32, ro_fd: *mut u32) -> u32;
        pub fn sock_connect(fd: u32, addr_ptr: *const u8) -> u32;
    }

    #[link(wasm_import_module = "wasi_snapshot_preview1")]
    unsafe extern "C" {
        pub fn sock_recv(
            fd: u32,
            ri_data: *const Iovec,
            ri_data_len: usize,
            ri_flags: u16,
            ro_datalen: *mut usize,
            ro_flags: *mut u16,
        ) -> u32;
        pub fn sock_send(
            fd: u32,
            si_data: *const Ciovec,
            si_data_len: usize,
            si_flags: u16,
            ro_datalen: *mut usize,
        ) -> u32;
        pub fn sock_shutdown(fd: u32, how: u8) -> u32;
        pub fn fd_close(fd: u32) -> u32;
    }
}

#[cfg(target_arch = "wasm32")]
fn check_wasi_rc(rc: u32) -> Result<(), Errno> {
    if rc == 0 {
        Ok(())
    } else {
        Err(crate::wasi_libc::wasi_errno_to_abi(rc as i32).unwrap_or(Errno::EIO))
    }
}

impl WasixTcpStream {
    /// Open and connect an outbound TCP socket using WASIX `sock_open` + `sock_connect`.
    pub fn connect(addr: SocketAddr) -> Result<Self, Errno> {
        #[cfg(target_arch = "wasm32")]
        {
            let af = match addr {
                SocketAddr::V4(_) => abi::net_ctl::WASIX_AF_INET4 as u32,
                SocketAddr::V6(_) => abi::net_ctl::WASIX_AF_INET6 as u32,
            };
            let mut fd = 0u32;
            // SAFETY: stack pointer `fd` is valid for 4 bytes.
            check_wasi_rc(unsafe {
                wasix_raw::sock_open(
                    af,
                    abi::net_ctl::WASIX_SOCK_STREAM as u32,
                    abi::socket::IPPROTO_TCP,
                    &mut fd,
                )
            })?;
            let stream = Self { fd };
            let encoded = abi::net_ctl::encode_wasix_addr_port(addr);
            // SAFETY: `encoded` is a 20-byte WASIX AddrPort struct.
            check_wasi_rc(unsafe { wasix_raw::sock_connect(stream.fd, encoded.as_ptr()) })?;
            Ok(stream)
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = addr;
            Err(Errno::ENOSYS)
        }
    }

    pub fn recv(&self, buf: &mut [u8], ri_flags: u16) -> Result<usize, Errno> {
        #[cfg(target_arch = "wasm32")]
        {
            let iov = wasix_raw::Iovec {
                buf: buf.as_mut_ptr(),
                len: buf.len(),
            };
            let mut n = 0usize;
            let mut ro_flags = 0u16;
            // SAFETY: iov and out pointers are valid stack references.
            check_wasi_rc(unsafe {
                wasix_raw::sock_recv(self.fd, &iov, 1, ri_flags, &mut n, &mut ro_flags)
            })?;
            Ok(n)
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (buf, ri_flags);
            Err(Errno::ENOSYS)
        }
    }

    pub fn send(&self, data: &[u8], si_flags: u16) -> Result<usize, Errno> {
        #[cfg(target_arch = "wasm32")]
        {
            let iov = wasix_raw::Ciovec {
                buf: data.as_ptr(),
                len: data.len(),
            };
            let mut n = 0usize;
            // SAFETY: iov and out pointer are valid stack references.
            check_wasi_rc(unsafe { wasix_raw::sock_send(self.fd, &iov, 1, si_flags, &mut n) })?;
            Ok(n)
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (data, si_flags);
            Err(Errno::ENOSYS)
        }
    }

    pub fn shutdown(&self, how_posix: u32) -> Result<(), Errno> {
        let sdflags = match how_posix {
            SHUT_RD => abi::net_ctl::WASI_SD_RD,
            SHUT_WR => abi::net_ctl::WASI_SD_WR,
            SHUT_RDWR => abi::net_ctl::WASI_SD_RD | abi::net_ctl::WASI_SD_WR,
            _ => return Err(Errno::EINVAL),
        };
        #[cfg(target_arch = "wasm32")]
        {
            // SAFETY: scalar WASI sock_shutdown call.
            check_wasi_rc(unsafe { wasix_raw::sock_shutdown(self.fd, sdflags) })
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = sdflags;
            Err(Errno::ENOSYS)
        }
    }

    pub fn as_raw_fd(&self) -> u32 {
        self.fd
    }

    pub fn into_raw_fd(self) -> u32 {
        let fd = self.fd;
        core::mem::forget(self);
        fd
    }
}

impl Drop for WasixTcpStream {
    fn drop(&mut self) {
        #[cfg(target_arch = "wasm32")]
        {
            // SAFETY: closes owned guest socket descriptor.
            let _ = unsafe { wasix_raw::fd_close(self.fd) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn net_error_display_and_kind_mapping() {
        let e = NetError::from_errno(Errno::EACCES, "denied");
        assert_eq!(e.error, NetErrorKind::PolicyDenied);
        assert!(e.to_string().contains("denied"));
        assert_eq!(
            NetError::from(Errno::EDQUOT).error,
            NetErrorKind::QuotaExceeded
        );
        assert_eq!(
            NetError::from(Errno::EPROTONOSUPPORT).error,
            NetErrorKind::Unsupported
        );
    }

    #[test]
    fn non_wasm_wasix_tcp_returns_enosys() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        assert_eq!(WasixTcpStream::connect(addr).err(), Some(Errno::ENOSYS));
    }
}

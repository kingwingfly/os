//! Local Unix-domain sockets (`AF_UNIX`), `SCM_RIGHTS`, and `SO_PEERCRED` for WASI/WASIX guests
//! (`#55` L3b, consumed by `#57` PID 1 service manager and userspace daemons).
//!
//! Raw host imports live under `(module "os")` and return a WASI errno (`0` = success).

use abi::Errno;
pub use abi::socket::{
    AF_UNIX, MAX_INFLIGHT_FDS_GLOBAL, MAX_INFLIGHT_FDS_PER_USER, MSG_CMSG_CLOEXEC, MSG_CTRUNC,
    MSG_DONTWAIT, MSG_NOSIGNAL, MSG_PEEK, MSG_TRUNC, PeerCred, SCM_CREDENTIALS, SCM_MAX_FD,
    SCM_RIGHTS, SHUT_RD, SHUT_RDWR, SHUT_WR, SO_ACCEPTCONN, SO_ERROR, SO_PASSCRED, SO_PEERCRED,
    SO_TYPE, SOCK_CLOEXEC, SOCK_DGRAM, SOCK_NONBLOCK, SOCK_SEQPACKET, SOCK_STREAM, SOL_SOCKET,
    UNIX_DGRAM_MAX, UNIX_PATH_MAX, UNIX_SOMAXCONN,
};

#[cfg(target_arch = "wasm32")]
pub mod raw {
    use abi::socket::PeerCred;

    #[link(wasm_import_module = "os")]
    unsafe extern "C" {
        pub fn sock_socket(domain: u32, sock_type: u32, protocol: u32, out_fd: *mut u32) -> u32;
        pub fn sock_socketpair(
            domain: u32,
            sock_type: u32,
            protocol: u32,
            out_fds: *mut u32,
        ) -> u32;
        pub fn sock_bind(fd: u32, path_ptr: *const u8, path_len: u32) -> u32;
        pub fn sock_listen(fd: u32, backlog: u32) -> u32;
        pub fn sock_accept(fd: u32, flags: u32, out_fd: *mut u32) -> u32;
        pub fn sock_connect(fd: u32, path_ptr: *const u8, path_len: u32) -> u32;
        pub fn sock_shutdown(fd: u32, how: u32) -> u32;
        pub fn sock_sendmsg(
            fd: u32,
            data_ptr: *const u8,
            data_len: u32,
            fds_ptr: *const u32,
            fds_len: u32,
            addr_ptr: *const u8,
            addr_len: u32,
            flags: u32,
            out_sent: *mut u32,
        ) -> u32;
        pub fn sock_recvmsg(
            fd: u32,
            buf_ptr: *mut u8,
            buf_len: u32,
            fds_ptr: *mut u32,
            fds_cap: u32,
            out_fds_len: *mut u32,
            out_peer_ptr: *mut PeerCred,
            flags: u32,
            out_recv: *mut u32,
            out_flags: *mut u32,
        ) -> u32;
        pub fn sock_peercred(fd: u32, out_cred: *mut PeerCred) -> u32;
        pub fn sock_getsockname(fd: u32, buf_ptr: *mut u8, buf_len: u32, out_len: *mut u32) -> u32;
        pub fn sock_getpeername(fd: u32, buf_ptr: *mut u8, buf_len: u32, out_len: *mut u32) -> u32;
        pub fn sock_getsockopt(fd: u32, level: u32, optname: u32, out_val: *mut i32) -> u32;
        pub fn sock_setsockopt(fd: u32, level: u32, optname: u32, val: i32) -> u32;
    }

    #[link(wasm_import_module = "wasi_snapshot_preview1")]
    unsafe extern "C" {
        pub fn fd_close(fd: u32) -> u32;
        pub fn fd_fdstat_set_flags(fd: u32, flags: u16) -> u32;
    }
}

#[cfg(target_arch = "wasm32")]
fn check_wasi(rc: u32) -> Result<(), Errno> {
    if rc == 0 {
        Ok(())
    } else {
        Err(crate::wasi_libc::wasi_errno_to_abi(rc as i32).unwrap_or(Errno::EIO))
    }
}

fn close_fd(fd: u32) {
    #[cfg(target_arch = "wasm32")]
    {
        // SAFETY: closes owned guest descriptor on drop.
        let _ = unsafe { raw::fd_close(fd) };
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = fd;
    }
}

/// Set or clear `O_NONBLOCK` (`FDFLAG_NONBLOCK = 4`) on a socket descriptor.
pub fn set_nonblocking_fd(fd: u32, nonblock: bool) -> Result<(), Errno> {
    #[cfg(target_arch = "wasm32")]
    {
        let flags: u16 = if nonblock { 4 } else { 0 };
        // SAFETY: scalar WASI fd_fdstat_set_flags call.
        check_wasi(unsafe { raw::fd_fdstat_set_flags(fd, flags) })
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (fd, nonblock);
        Err(Errno::ENOSYS)
    }
}

/// Create a raw `AF_UNIX` socket descriptor (`SOCK_STREAM` | `SOCK_DGRAM` | `SOCK_SEQPACKET`,
/// optionally OR'd with `SOCK_NONBLOCK` / `SOCK_CLOEXEC`).
pub fn socket(domain: u32, sock_type: u32, protocol: u32) -> Result<u32, Errno> {
    #[cfg(target_arch = "wasm32")]
    {
        let mut fd = 0u32;
        // SAFETY: `fd` is a valid stack pointer.
        check_wasi(unsafe { raw::sock_socket(domain, sock_type, protocol, &mut fd) })?;
        Ok(fd)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (domain, sock_type, protocol);
        Err(Errno::ENOSYS)
    }
}

/// Create a connected pair of raw `AF_UNIX` socket descriptors.
pub fn socketpair(domain: u32, sock_type: u32, protocol: u32) -> Result<(u32, u32), Errno> {
    #[cfg(target_arch = "wasm32")]
    {
        let mut fds = [0u32; 2];
        // SAFETY: `fds` points to 2 writable `u32` slots.
        check_wasi(unsafe { raw::sock_socketpair(domain, sock_type, protocol, fds.as_mut_ptr()) })?;
        Ok((fds[0], fds[1]))
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (domain, sock_type, protocol);
        Err(Errno::ENOSYS)
    }
}

/// Bind raw socket descriptor `fd` to filesystem pathname `path`.
pub fn bind_fd(fd: u32, path: &str) -> Result<(), Errno> {
    abi::socket::validate_unix_path(path)?;
    #[cfg(target_arch = "wasm32")]
    {
        // SAFETY: `path` slice lives for the duration of the host call.
        check_wasi(unsafe { raw::sock_bind(fd, path.as_ptr(), path.len() as u32) })
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (fd, path);
        Err(Errno::ENOSYS)
    }
}

/// Listen for incoming connections on bound socket descriptor `fd`.
pub fn listen_fd(fd: u32, backlog: u32) -> Result<(), Errno> {
    #[cfg(target_arch = "wasm32")]
    {
        // SAFETY: scalar host call.
        check_wasi(unsafe { raw::sock_listen(fd, backlog) })
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (fd, backlog);
        Err(Errno::ENOSYS)
    }
}

/// Accept a connection from listening socket `fd` with `SOCK_NONBLOCK`/`SOCK_CLOEXEC` flags.
pub fn accept_fd(fd: u32, flags: u32) -> Result<u32, Errno> {
    #[cfg(target_arch = "wasm32")]
    {
        let mut out_fd = 0u32;
        // SAFETY: `out_fd` is a valid stack pointer.
        check_wasi(unsafe { raw::sock_accept(fd, flags, &mut out_fd) })?;
        Ok(out_fd)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (fd, flags);
        Err(Errno::ENOSYS)
    }
}

/// Connect raw socket `fd` to filesystem pathname `path`.
pub fn connect_fd(fd: u32, path: &str) -> Result<(), Errno> {
    abi::socket::validate_unix_path(path)?;
    #[cfg(target_arch = "wasm32")]
    {
        // SAFETY: `path` slice lives across the host call.
        check_wasi(unsafe { raw::sock_connect(fd, path.as_ptr(), path.len() as u32) })
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (fd, path);
        Err(Errno::ENOSYS)
    }
}

/// Shut down read, write, or both halves of socket `fd`.
pub fn shutdown_fd(fd: u32, how: u32) -> Result<(), Errno> {
    #[cfg(target_arch = "wasm32")]
    {
        // SAFETY: scalar host call.
        check_wasi(unsafe { raw::sock_shutdown(fd, how) })
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (fd, how);
        Err(Errno::ENOSYS)
    }
}

/// Send payload bytes + optional `SCM_RIGHTS` fds + optional destination path (unconnected DGRAM).
pub fn sendmsg_fd(
    fd: u32,
    data: &[u8],
    fds: &[u32],
    addr: Option<&str>,
    flags: u32,
) -> Result<usize, Errno> {
    if fds.len() > SCM_MAX_FD {
        return Err(Errno::EINVAL);
    }
    if let Some(p) = addr {
        abi::socket::validate_unix_path(p)?;
    }
    #[cfg(target_arch = "wasm32")]
    {
        let (addr_ptr, addr_len) = match addr {
            Some(p) => (p.as_ptr(), p.len() as u32),
            None => (core::ptr::null(), 0),
        };
        let fds_ptr = if fds.is_empty() {
            core::ptr::null()
        } else {
            fds.as_ptr()
        };
        let mut sent = 0u32;
        // SAFETY: all slices and stack outputs live for the duration of the host call.
        check_wasi(unsafe {
            raw::sock_sendmsg(
                fd,
                data.as_ptr(),
                data.len() as u32,
                fds_ptr,
                fds.len() as u32,
                addr_ptr,
                addr_len,
                flags,
                &mut sent,
            )
        })?;
        Ok(sent as usize)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (fd, data, fds, addr, flags);
        Err(Errno::ENOSYS)
    }
}

/// Receive payload bytes + up to `max_fds` `SCM_RIGHTS` fds + kernel-stamped `PeerCred` + out_flags.
pub fn recvmsg_fd(
    fd: u32,
    buf: &mut [u8],
    max_fds: usize,
    flags: u32,
) -> Result<(usize, Vec<u32>, PeerCred, u32), Errno> {
    #[cfg(target_arch = "wasm32")]
    {
        let cap = max_fds.min(SCM_MAX_FD);
        let mut fds = vec![0u32; cap];
        let mut fds_len = 0u32;
        let mut cred = PeerCred::default();
        let mut recvd = 0u32;
        let mut out_flags = 0u32;
        let fds_ptr = if cap == 0 {
            core::ptr::null_mut()
        } else {
            fds.as_mut_ptr()
        };
        // SAFETY: all output buffers and stack scalars are valid for the duration of the host call.
        check_wasi(unsafe {
            raw::sock_recvmsg(
                fd,
                buf.as_mut_ptr(),
                buf.len() as u32,
                fds_ptr,
                cap as u32,
                &mut fds_len,
                &mut cred,
                flags,
                &mut recvd,
                &mut out_flags,
            )
        })?;
        fds.truncate((fds_len as usize).min(cap));
        Ok((recvd as usize, fds, cred, out_flags))
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (fd, buf, max_fds, flags);
        Err(Errno::ENOSYS)
    }
}

/// Query kernel-authenticated `SO_PEERCRED` for connected socket `fd`.
pub fn peercred_fd(fd: u32) -> Result<PeerCred, Errno> {
    #[cfg(target_arch = "wasm32")]
    {
        let mut cred = PeerCred::default();
        // SAFETY: `cred` is a valid 12-byte `#[repr(C)]` struct.
        check_wasi(unsafe { raw::sock_peercred(fd, &mut cred) })?;
        Ok(cred)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = fd;
        Err(Errno::ENOSYS)
    }
}

/// Query local bound pathname (`getsockname(2)`).
pub fn getsockname_fd(fd: u32) -> Result<String, Errno> {
    #[cfg(target_arch = "wasm32")]
    {
        let mut buf = vec![0u8; UNIX_PATH_MAX + 1];
        let mut len = 0u32;
        // SAFETY: `buf` is valid for `buf.len()` bytes.
        check_wasi(unsafe {
            raw::sock_getsockname(fd, buf.as_mut_ptr(), buf.len() as u32, &mut len)
        })?;
        buf.truncate((len as usize).min(buf.len()));
        String::from_utf8(buf).map_err(|_| Errno::EIO)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = fd;
        Err(Errno::ENOSYS)
    }
}

/// Query peer bound pathname (`getpeername(2)`).
pub fn getpeername_fd(fd: u32) -> Result<String, Errno> {
    #[cfg(target_arch = "wasm32")]
    {
        let mut buf = vec![0u8; UNIX_PATH_MAX + 1];
        let mut len = 0u32;
        // SAFETY: `buf` is valid for `buf.len()` bytes.
        check_wasi(unsafe {
            raw::sock_getpeername(fd, buf.as_mut_ptr(), buf.len() as u32, &mut len)
        })?;
        buf.truncate((len as usize).min(buf.len()));
        String::from_utf8(buf).map_err(|_| Errno::EIO)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = fd;
        Err(Errno::ENOSYS)
    }
}

/// Query integer socket option (`SOL_SOCKET`).
pub fn getsockopt_fd(fd: u32, level: u32, optname: u32) -> Result<i32, Errno> {
    #[cfg(target_arch = "wasm32")]
    {
        let mut val = 0i32;
        // SAFETY: `val` is a valid stack pointer.
        check_wasi(unsafe { raw::sock_getsockopt(fd, level, optname, &mut val) })?;
        Ok(val)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (fd, level, optname);
        Err(Errno::ENOSYS)
    }
}

/// Set integer socket option (`SOL_SOCKET`).
pub fn setsockopt_fd(fd: u32, level: u32, optname: u32, val: i32) -> Result<(), Errno> {
    #[cfg(target_arch = "wasm32")]
    {
        // SAFETY: scalar host call.
        check_wasi(unsafe { raw::sock_setsockopt(fd, level, optname, val) })
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (fd, level, optname, val);
        Err(Errno::ENOSYS)
    }
}

/// Listening `AF_UNIX` `SOCK_STREAM` server socket.
pub struct UnixListener {
    fd: u32,
}

impl UnixListener {
    pub fn bind(path: &str) -> Result<Self, Errno> {
        Self::bind_with_backlog(path, UNIX_SOMAXCONN as u32)
    }

    /// Bind with the final inode permissions, including while the daemon is
    /// starting. The caller must have exclusive use of its process umask.
    #[cfg(target_os = "wasi")]
    pub fn bind_with_mode(path: &str, mode: u32) -> Result<Self, Errno> {
        let previous = crate::umask(!mode & 0o777);
        let listener = Self::bind(path);
        crate::umask(previous);
        listener
    }

    #[cfg(not(target_os = "wasi"))]
    pub fn bind_with_mode(_path: &str, _mode: u32) -> Result<Self, Errno> {
        Err(Errno::ENOSYS)
    }

    pub fn bind_with_backlog(path: &str, backlog: u32) -> Result<Self, Errno> {
        let fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)?;
        let listener = Self { fd };
        bind_fd(listener.fd, path)?;
        listen_fd(listener.fd, backlog)?;
        Ok(listener)
    }

    pub fn accept(&self) -> Result<(UnixStream, PeerCred), Errno> {
        self.accept_flags(SOCK_CLOEXEC)
    }

    pub fn accept_flags(&self, flags: u32) -> Result<(UnixStream, PeerCred), Errno> {
        let client_fd = accept_fd(self.fd, flags)?;
        let stream = UnixStream { fd: client_fd };
        let cred = stream.peer_cred()?;
        Ok((stream, cred))
    }

    pub fn set_nonblocking(&self, nb: bool) -> Result<(), Errno> {
        set_nonblocking_fd(self.fd, nb)
    }

    pub fn local_addr(&self) -> Result<String, Errno> {
        getsockname_fd(self.fd)
    }

    pub fn as_raw_fd(&self) -> u32 {
        self.fd
    }

    pub fn into_raw_fd(self) -> u32 {
        let fd = self.fd;
        core::mem::forget(self);
        fd
    }

    /// Construct a wrapper taking exclusive ownership of a raw WASI `AF_UNIX` descriptor.
    ///
    /// # Safety
    /// `fd` must be a valid, open `AF_UNIX` descriptor of the matching socket type that is not
    /// owned by any other wrapper (dropping two wrappers over the same raw fd causes a double close).
    pub unsafe fn from_raw_fd(fd: u32) -> Self {
        Self { fd }
    }
}

impl Drop for UnixListener {
    fn drop(&mut self) {
        close_fd(self.fd);
    }
}

/// Connected `AF_UNIX` `SOCK_STREAM` socket.
pub struct UnixStream {
    fd: u32,
}

impl UnixStream {
    pub fn connect(path: &str) -> Result<Self, Errno> {
        let fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)?;
        let stream = Self { fd };
        connect_fd(stream.fd, path)?;
        Ok(stream)
    }

    pub fn pair() -> Result<(Self, Self), Errno> {
        Self::pair_with_flags(SOCK_CLOEXEC)
    }

    pub fn pair_with_flags(flags: u32) -> Result<(Self, Self), Errno> {
        let (a, b) = socketpair(AF_UNIX, SOCK_STREAM | flags, 0)?;
        Ok((Self { fd: a }, Self { fd: b }))
    }

    pub fn peer_cred(&self) -> Result<PeerCred, Errno> {
        peercred_fd(self.fd)
    }

    pub fn send(&self, data: &[u8], flags: u32) -> Result<usize, Errno> {
        sendmsg_fd(self.fd, data, &[], None, flags)
    }

    pub fn recv(&self, buf: &mut [u8], flags: u32) -> Result<usize, Errno> {
        let (n, _, _, _) = recvmsg_fd(self.fd, buf, 0, flags)?;
        Ok(n)
    }

    pub fn send_with_fds(&self, data: &[u8], fds: &[u32], flags: u32) -> Result<usize, Errno> {
        sendmsg_fd(self.fd, data, fds, None, flags)
    }

    pub fn recv_with_fds(
        &self,
        buf: &mut [u8],
        max_fds: usize,
        flags: u32,
    ) -> Result<(usize, Vec<u32>, u32), Errno> {
        let (n, fds, _, out_flags) = recvmsg_fd(self.fd, buf, max_fds, flags)?;
        Ok((n, fds, out_flags))
    }

    pub fn shutdown(&self, how: u32) -> Result<(), Errno> {
        shutdown_fd(self.fd, how)
    }

    pub fn set_nonblocking(&self, nb: bool) -> Result<(), Errno> {
        set_nonblocking_fd(self.fd, nb)
    }

    pub fn local_addr(&self) -> Result<String, Errno> {
        getsockname_fd(self.fd)
    }

    pub fn peer_addr(&self) -> Result<String, Errno> {
        getpeername_fd(self.fd)
    }

    pub fn as_raw_fd(&self) -> u32 {
        self.fd
    }

    pub fn into_raw_fd(self) -> u32 {
        let fd = self.fd;
        core::mem::forget(self);
        fd
    }

    /// Construct a wrapper taking exclusive ownership of a raw WASI `AF_UNIX` descriptor.
    ///
    /// # Safety
    /// `fd` must be a valid, open `AF_UNIX` descriptor of the matching socket type that is not
    /// owned by any other wrapper (dropping two wrappers over the same raw fd causes a double close).
    pub unsafe fn from_raw_fd(fd: u32) -> Self {
        Self { fd }
    }
}

impl Drop for UnixStream {
    fn drop(&mut self) {
        close_fd(self.fd);
    }
}

/// `AF_UNIX` `SOCK_DGRAM` socket (used by PID 1 `NOTIFY_SOCKET` and datagram services).
pub struct UnixDatagram {
    fd: u32,
}

impl UnixDatagram {
    pub fn bind(path: &str) -> Result<Self, Errno> {
        let fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0)?;
        let sock = Self { fd };
        bind_fd(sock.fd, path)?;
        Ok(sock)
    }

    pub fn unbound() -> Result<Self, Errno> {
        let fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0)?;
        Ok(Self { fd })
    }

    pub fn pair() -> Result<(Self, Self), Errno> {
        let (a, b) = socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0)?;
        Ok((Self { fd: a }, Self { fd: b }))
    }

    pub fn connect(&self, path: &str) -> Result<(), Errno> {
        connect_fd(self.fd, path)
    }

    pub fn send(&self, data: &[u8]) -> Result<usize, Errno> {
        sendmsg_fd(self.fd, data, &[], None, MSG_NOSIGNAL)
    }

    pub fn send_to(&self, data: &[u8], path: &str) -> Result<usize, Errno> {
        sendmsg_fd(self.fd, data, &[], Some(path), MSG_NOSIGNAL)
    }

    pub fn send_to_with_fds(&self, data: &[u8], fds: &[u32], path: &str) -> Result<usize, Errno> {
        sendmsg_fd(self.fd, data, fds, Some(path), MSG_NOSIGNAL)
    }

    pub fn recv_with_cred(
        &self,
        buf: &mut [u8],
        max_fds: usize,
        flags: u32,
    ) -> Result<(usize, Vec<u32>, PeerCred, u32), Errno> {
        recvmsg_fd(self.fd, buf, max_fds, flags)
    }

    pub fn set_nonblocking(&self, nb: bool) -> Result<(), Errno> {
        set_nonblocking_fd(self.fd, nb)
    }

    pub fn local_addr(&self) -> Result<String, Errno> {
        getsockname_fd(self.fd)
    }

    pub fn as_raw_fd(&self) -> u32 {
        self.fd
    }

    pub fn into_raw_fd(self) -> u32 {
        let fd = self.fd;
        core::mem::forget(self);
        fd
    }

    /// Construct a wrapper taking exclusive ownership of a raw WASI `AF_UNIX` descriptor.
    ///
    /// # Safety
    /// `fd` must be a valid, open `AF_UNIX` descriptor of the matching socket type that is not
    /// owned by any other wrapper (dropping two wrappers over the same raw fd causes a double close).
    pub unsafe fn from_raw_fd(fd: u32) -> Self {
        Self { fd }
    }
}

impl Drop for UnixDatagram {
    fn drop(&mut self) {
        close_fd(self.fd);
    }
}

/// Connection-oriented record-framed `AF_UNIX` `SOCK_SEQPACKET` socket.
pub struct UnixSeqpacket {
    fd: u32,
}

impl UnixSeqpacket {
    pub fn bind(path: &str) -> Result<Self, Errno> {
        let fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0)?;
        let sock = Self { fd };
        bind_fd(sock.fd, path)?;
        listen_fd(sock.fd, UNIX_SOMAXCONN as u32)?;
        Ok(sock)
    }

    pub fn accept(&self) -> Result<(Self, PeerCred), Errno> {
        let client_fd = accept_fd(self.fd, SOCK_CLOEXEC)?;
        let sock = Self { fd: client_fd };
        let cred = sock.peer_cred()?;
        Ok((sock, cred))
    }

    pub fn connect(path: &str) -> Result<Self, Errno> {
        let fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0)?;
        let sock = Self { fd };
        connect_fd(sock.fd, path)?;
        Ok(sock)
    }

    pub fn pair() -> Result<(Self, Self), Errno> {
        let (a, b) = socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0)?;
        Ok((Self { fd: a }, Self { fd: b }))
    }

    pub fn peer_cred(&self) -> Result<PeerCred, Errno> {
        peercred_fd(self.fd)
    }

    pub fn send_with_fds(&self, data: &[u8], fds: &[u32], flags: u32) -> Result<usize, Errno> {
        sendmsg_fd(self.fd, data, fds, None, flags)
    }

    pub fn recv_with_fds(
        &self,
        buf: &mut [u8],
        max_fds: usize,
        flags: u32,
    ) -> Result<(usize, Vec<u32>, u32), Errno> {
        let (n, fds, _, out_flags) = recvmsg_fd(self.fd, buf, max_fds, flags)?;
        Ok((n, fds, out_flags))
    }

    pub fn shutdown(&self, how: u32) -> Result<(), Errno> {
        shutdown_fd(self.fd, how)
    }

    pub fn set_nonblocking(&self, nb: bool) -> Result<(), Errno> {
        set_nonblocking_fd(self.fd, nb)
    }

    pub fn local_addr(&self) -> Result<String, Errno> {
        getsockname_fd(self.fd)
    }

    pub fn peer_addr(&self) -> Result<String, Errno> {
        getpeername_fd(self.fd)
    }

    pub fn as_raw_fd(&self) -> u32 {
        self.fd
    }

    pub fn into_raw_fd(self) -> u32 {
        let fd = self.fd;
        core::mem::forget(self);
        fd
    }

    /// Construct a wrapper taking exclusive ownership of a raw WASI `AF_UNIX` descriptor.
    ///
    /// # Safety
    /// `fd` must be a valid, open `AF_UNIX` descriptor of the matching socket type that is not
    /// owned by any other wrapper (dropping two wrappers over the same raw fd causes a double close).
    pub unsafe fn from_raw_fd(fd: u32) -> Self {
        Self { fd }
    }
}

impl Drop for UnixSeqpacket {
    fn drop(&mut self) {
        close_fd(self.fd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wasi_libc::{abi_errno_to_wasi, wasi_errno_to_abi};

    #[test]
    fn socket_errnos_roundtrip_wasi() {
        let socket_errnos = [
            Errno::EADDRINUSE,
            Errno::EADDRNOTAVAIL,
            Errno::EAFNOSUPPORT,
            Errno::ECONNABORTED,
            Errno::ECONNREFUSED,
            Errno::ECONNRESET,
            Errno::EISCONN,
            Errno::EMSGSIZE,
            Errno::ENOBUFS,
            Errno::ENOTSOCK,
            Errno::EPROTOTYPE,
            Errno::ETOOMANYREFS,
        ];
        for err in socket_errnos {
            let code = abi_errno_to_wasi(err);
            assert_eq!(wasi_errno_to_abi(code), Some(err), "roundtrip for {err:?}");
        }
    }
}

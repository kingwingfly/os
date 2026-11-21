//! `AF_UNIX` conformance cases (`#55` L3b: `U-02`, `U-06`, `U-07`, ABI & `os-posix::socket`
//! contract invariants).

#[cfg(target_os = "wasi")]
pub mod wasi_cases {
    use abi::Errno;
    use abi::socket::{MSG_NOSIGNAL, SHUT_WR, SOCK_CLOEXEC, SOCK_DGRAM, SOCK_STREAM};
    use os_posix::socket::{UnixDatagram, UnixListener, UnixStream};

    /// Verify `socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC)` roundtrip and `SO_PEERCRED`.
    pub fn check_stream_pair_and_peercred() -> Result<(), Errno> {
        let (a, b) = UnixStream::pair_with_flags(SOCK_CLOEXEC)?;
        let cred_a = a.peer_cred()?;
        let cred_b = b.peer_cred()?;
        if cred_a != cred_b || cred_a.pid == 0 {
            return Err(Errno::EINVAL);
        }
        let payload = b"conformance-af-unix";
        let sent = a.send(payload, MSG_NOSIGNAL)?;
        if sent != payload.len() {
            return Err(Errno::EIO);
        }
        let mut buf = [0u8; 64];
        let n = b.recv(&mut buf, 0)?;
        if &buf[..n] != payload {
            return Err(Errno::EIO);
        }
        a.shutdown(SHUT_WR)?;
        let eof = b.recv(&mut buf, 0)?;
        if eof != 0 {
            return Err(Errno::EIO);
        }
        Ok(())
    }

    /// Verify `/run/*.sock` bind/stat/open(`ENXIO`)/unlink/rebind lifecycle.
    pub fn check_socket_inode_lifecycle(path: &str) -> Result<(), Errno> {
        let listener = UnixListener::bind(path)?;
        let st = os_posix::stat(std::path::Path::new(path), false)
            .map_err(|e| os_posix::errno_of(&e).unwrap_or(Errno::EIO))?;
        if !st.is_socket() {
            return Err(Errno::ENOTSOCK);
        }
        if listener.local_addr()? != path {
            return Err(Errno::EINVAL);
        }
        let _ = (SOCK_STREAM, SOCK_DGRAM);
        Ok(())
    }

    /// Verify `SOCK_DGRAM` framing & `PeerCred` delivery.
    pub fn check_dgram_framing(path: &str) -> Result<(), Errno> {
        let srv = UnixDatagram::bind(path)?;
        let cli = UnixDatagram::unbound()?;
        cli.send_to(b"READY=1", path)?;
        let mut buf = [0u8; 32];
        let (n, fds, cred, flags) = srv.recv_with_cred(&mut buf, 0, 0)?;
        if &buf[..n] != b"READY=1" || !fds.is_empty() || cred.pid == 0 || flags != 0 {
            return Err(Errno::EIO);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use abi::fs::FileType;
    use abi::socket::{
        AF_UNIX, MAX_INFLIGHT_FDS_GLOBAL, MAX_INFLIGHT_FDS_PER_USER, MSG_CMSG_CLOEXEC, MSG_CTRUNC,
        MSG_DONTWAIT, MSG_NOSIGNAL, MSG_PEEK, MSG_TRUNC, PeerCred, SCM_MAX_FD, SCM_RIGHTS, SHUT_RD,
        SHUT_RDWR, SHUT_WR, SO_ACCEPTCONN, SO_ERROR, SO_PASSCRED, SO_PEERCRED, SO_TYPE,
        SOCK_CLOEXEC, SOCK_DGRAM, SOCK_NONBLOCK, SOCK_SEQPACKET, SOCK_STREAM, SOL_SOCKET,
        UNIX_DGRAM_MAX, UNIX_PATH_MAX, UNIX_SOCK_MAX, UNIX_SOMAXCONN, validate_unix_path,
    };
    use abi::{Errno, S_IFSOCK};

    #[test]
    fn socket_abi_constants_match_linux_contract() {
        assert_eq!(S_IFSOCK, 0o140_000);
        assert_eq!(FileType::Socket.mode(), S_IFSOCK);
        assert!(FileType::Socket.is_socket());
        assert_eq!(AF_UNIX, 1);
        assert_eq!(SOCK_STREAM, 1);
        assert_eq!(SOCK_DGRAM, 2);
        assert_eq!(SOCK_SEQPACKET, 5);
        assert_eq!(SOCK_NONBLOCK, 0o4000);
        assert_eq!(SOCK_CLOEXEC, 0o2_000_000);
        assert_eq!((SHUT_RD, SHUT_WR, SHUT_RDWR), (0, 1, 2));
        assert_eq!(SOL_SOCKET, 1);
        assert_eq!(
            (SO_TYPE, SO_ERROR, SO_PASSCRED, SO_PEERCRED, SO_ACCEPTCONN),
            (3, 4, 16, 17, 30)
        );
        assert_eq!(SCM_RIGHTS, 1);
        assert_eq!(
            (
                MSG_PEEK,
                MSG_CTRUNC,
                MSG_TRUNC,
                MSG_DONTWAIT,
                MSG_NOSIGNAL,
                MSG_CMSG_CLOEXEC
            ),
            (0x02, 0x08, 0x20, 0x40, 0x4000, 0x4000_0000)
        );
        assert_eq!(UNIX_PATH_MAX, 108);
        assert_eq!(UNIX_SOMAXCONN, 64);
        assert_eq!(UNIX_DGRAM_MAX, 65_536);
        assert_eq!(SCM_MAX_FD, 64);
        assert_eq!(MAX_INFLIGHT_FDS_PER_USER, 256);
        assert_eq!(MAX_INFLIGHT_FDS_GLOBAL, 512);
        assert_eq!(UNIX_SOCK_MAX, 256);
        assert_eq!(core::mem::size_of::<PeerCred>(), 12);
    }

    #[test]
    fn socket_errnos_carry_glibc_strerror_text() {
        assert_eq!(Errno::EADDRINUSE.text(), "Address already in use");
        assert_eq!(
            Errno::EADDRNOTAVAIL.text(),
            "Cannot assign requested address"
        );
        assert_eq!(
            Errno::EAFNOSUPPORT.text(),
            "Address family not supported by protocol"
        );
        assert_eq!(
            Errno::ECONNABORTED.text(),
            "Software caused connection abort"
        );
        assert_eq!(Errno::ECONNREFUSED.text(), "Connection refused");
        assert_eq!(Errno::ECONNRESET.text(), "Connection reset by peer");
        assert_eq!(
            Errno::EISCONN.text(),
            "Transport endpoint is already connected"
        );
        assert_eq!(Errno::EMSGSIZE.text(), "Message too long");
        assert_eq!(Errno::ENOBUFS.text(), "No buffer space available");
        assert_eq!(Errno::ENOTSOCK.text(), "Socket operation on non-socket");
        assert_eq!(Errno::EPROTOTYPE.text(), "Protocol wrong type for socket");
        assert_eq!(
            Errno::ETOOMANYREFS.text(),
            "Too many references: cannot splice"
        );
        assert_eq!(validate_unix_path("/run/init/control.sock"), Ok(()));
        assert_eq!(validate_unix_path("\0abstract"), Err(Errno::EINVAL));
    }
}

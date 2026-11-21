//! Local Unix-domain socket (`AF_UNIX`) constants, limits, and wire types (`#55` L3b,
//! `docs/architecture/contract.md` §2.8).

use crate::Errno;
use serde::{Deserialize, Serialize};

/// Address family for local Unix-domain IPC sockets.
pub const AF_UNIX: u32 = 1;

/// Connection-oriented byte stream socket.
pub const SOCK_STREAM: u32 = 1;
/// Connectionless message-boundary datagram socket.
pub const SOCK_DGRAM: u32 = 2;
/// Connection-oriented message-boundary sequenced-packet socket.
pub const SOCK_SEQPACKET: u32 = 5;
/// Bitmask extracting the base socket type (`SOCK_STREAM` | `SOCK_DGRAM` | `SOCK_SEQPACKET`).
pub const SOCK_TYPE_MASK: u32 = 0xf;

/// Set `O_NONBLOCK` on newly created or accepted socket descriptors.
pub const SOCK_NONBLOCK: u32 = 0o4000;
/// Set `O_CLOEXEC` on newly created or accepted socket descriptors.
pub const SOCK_CLOEXEC: u32 = 0o2_000_000;

/// Disable further receives.
pub const SHUT_RD: u32 = 0;
/// Disable further sends.
pub const SHUT_WR: u32 = 1;
/// Disable further sends and receives.
pub const SHUT_RDWR: u32 = 2;

/// Socket-level option namespace (`SOL_SOCKET`).
pub const SOL_SOCKET: u32 = 1;
/// Query socket type (`SOCK_STREAM` / `SOCK_DGRAM` / `SOCK_SEQPACKET`).
pub const SO_TYPE: u32 = 3;
/// Query and clear pending socket error.
pub const SO_ERROR: u32 = 4;
/// Enable/disable receiving `SCM_CREDENTIALS` metadata.
pub const SO_PASSCRED: u32 = 16;
/// Query kernel-authenticated peer credentials (`PeerCred`).
pub const SO_PEERCRED: u32 = 17;
/// Query whether socket is listening (`1` or `0`).
pub const SO_ACCEPTCONN: u32 = 30;

/// Ancillary message type for file descriptor passing (`SCM_RIGHTS`).
pub const SCM_RIGHTS: u32 = 1;
/// Ancillary message type for peer credentials (`SCM_CREDENTIALS`).
pub const SCM_CREDENTIALS: u32 = 2;

/// Peek at incoming data without removing it from the queue.
pub const MSG_PEEK: u32 = 0x02;
/// Output flag: control data (ancillary fds) was truncated.
pub const MSG_CTRUNC: u32 = 0x08;
/// Output flag: packet data was truncated to fit receiver buffer; input flag returns full length.
pub const MSG_TRUNC: u32 = 0x20;
/// Per-call nonblocking send/recv.
pub const MSG_DONTWAIT: u32 = 0x40;
/// Suppress `SIGPIPE` when writing to a closed peer (still returns `EPIPE`).
pub const MSG_NOSIGNAL: u32 = 0x4000;
/// Apply `O_CLOEXEC` to all file descriptors received via `SCM_RIGHTS`.
pub const MSG_CMSG_CLOEXEC: u32 = 0x4000_0000;

/// Maximum Unix-domain socket pathname length (`sizeof(sockaddr_un.sun_path)`).
pub const UNIX_PATH_MAX: usize = 108;
/// Maximum listen backlog for `AF_UNIX` listeners.
pub const UNIX_SOMAXCONN: usize = 64;
/// Maximum payload bytes for a single `SOCK_DGRAM` or `SOCK_SEQPACKET` message.
pub const UNIX_DGRAM_MAX: usize = 65_536;
/// Maximum queued datagrams/packets per socket before backpressure (`EAGAIN`).
pub const UNIX_MAX_QUEUED_MSGS: usize = 64;
/// Maximum queued bytes per socket buffer before backpressure (`EAGAIN`).
pub const UNIX_MAX_QUEUED_BYTES: usize = 256 * 1024;
/// Maximum file descriptors transferred in a single `SCM_RIGHTS` message.
pub const SCM_MAX_FD: usize = 64;
/// Maximum simultaneous in-flight `SCM_RIGHTS` descriptors owned by one UID.
pub const MAX_INFLIGHT_FDS_PER_USER: usize = 256;
/// Maximum simultaneous in-flight `SCM_RIGHTS` descriptors across the whole OS instance.
pub const MAX_INFLIGHT_FDS_GLOBAL: usize = 512;
/// Maximum simultaneous live `AF_UNIX` sockets per OS instance.
pub const UNIX_SOCK_MAX: usize = 256;

/// `statfs` magic for `sockfs` (matches Linux `SOCKFS_MAGIC`).
pub const SOCKFS_MAGIC: u64 = 0x534f_434b;

/// Kernel-authenticated peer credentials (`SO_PEERCRED`, Linux `struct ucred`).
///
/// Populated exclusively by the kernel from `LocalProcessTable`; guest payloads
/// can never supply or override these fields.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerCred {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

const _: () = {
    assert!(core::mem::size_of::<PeerCred>() == 12);
    assert!(core::mem::align_of::<PeerCred>() == 4);
    assert!(core::mem::offset_of!(PeerCred, pid) == 0);
    assert!(core::mem::offset_of!(PeerCred, uid) == 4);
    assert!(core::mem::offset_of!(PeerCred, gid) == 8);
};

/// Validate a filesystem-bound `AF_UNIX` socket path.
///
/// Abstract socket names (leading NUL) are not supported (contract §2.8) and
/// return `EINVAL`; paths longer than `UNIX_PATH_MAX` return `ENAMETOOLONG`.
pub fn validate_unix_path(path: &str) -> Result<(), Errno> {
    if path.is_empty() {
        return Err(Errno::EINVAL);
    }
    if path.len() > UNIX_PATH_MAX {
        return Err(Errno::ENAMETOOLONG);
    }
    if path.as_bytes().contains(&0) {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_path_validation() {
        assert_eq!(validate_unix_path(""), Err(Errno::EINVAL));
        assert_eq!(validate_unix_path("\0abstract"), Err(Errno::EINVAL));
        assert_eq!(validate_unix_path("/run/a\0b"), Err(Errno::EINVAL));
        assert!(validate_unix_path("/run/init/control.sock").is_ok());
        assert!(validate_unix_path(&"a".repeat(UNIX_PATH_MAX)).is_ok());
        assert_eq!(
            validate_unix_path(&"a".repeat(UNIX_PATH_MAX + 1)),
            Err(Errno::ENAMETOOLONG)
        );
    }

    #[test]
    fn peercred_serde_roundtrip() {
        let cred = PeerCred {
            pid: 42,
            uid: 1000,
            gid: 1000,
        };
        let encoded = serde_json::to_string(&cred).unwrap();
        let decoded: PeerCred = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, cred);
    }
}

//! Pure-Rust integration and security refusal tests for Wave 4A Track 1 (`#55` L3b):
//! `AF_UNIX`, `SCM_RIGHTS`, `SO_PEERCRED`, `S_IFSOCK` on `tmpfs`/`MemFs` and `os-cowfs`,
//! DAC+ACL `W_OK`, ancillary boundary splitting, DoS quotas, `MSG_CTRUNC`, and `unix_gc()`.
//!
//! Covers rows `U-01`, `U-03`, `U-04`, `U-05`, `U-06`, `U-07`, `U-08`, `U-09`, `U-11`.

use abi::Errno;
use abi::fs::{FileType, FsId, OpenOptions};
use abi::socket::{
    MAX_INFLIGHT_FDS_GLOBAL, MAX_INFLIGHT_FDS_PER_USER, MSG_CTRUNC, MSG_PEEK, MSG_TRUNC, PeerCred,
    SCM_MAX_FD, SHUT_RD, SHUT_WR, SO_ACCEPTCONN, SO_PASSCRED, SO_TYPE, SOCK_DGRAM, SOCK_SEQPACKET,
    SOCK_STREAM, SOL_SOCKET, UNIX_DGRAM_MAX,
};
use os_core::acl::Entries;
use os_core::permissions::Identity;
use os_vfs as vfs;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use vfs::memfs::MemFs;
use vfs::unix_sock::{
    CleanupBatch, InFlightFd, PipeEnd, SockType, SocketInodeKey, UnixSocketTable,
};
use vfs::{
    Cred, DefaultFilesystemFactory, Filesystem, FsType, MountBacking, StartAnchor, Vfs,
    now_or_never,
};

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    now_or_never(f).expect("local in-memory VFS future must complete immediately")
}

fn user_identity(uid: u32, gid: u32) -> Identity {
    let mut groups = BTreeSet::new();
    groups.insert(gid);
    Identity {
        id: uid,
        group: gid,
        groups,
    }
}

fn setup_vfs() -> Vfs {
    let clock: Rc<dyn Fn() -> (u64, u32)> = Rc::new(|| (1_700_000_000, 0));
    let factory = Rc::new(DefaultFilesystemFactory::new(clock));
    let root = Rc::new(MemFs::new(
        FsId("root-tmpfs".into()),
        1,
        0,
        0,
        0o755,
        Box::new(|| (1_700_000_000, 0)),
    ));
    let backing = Rc::new(MountBacking::new(root as Rc<dyn Filesystem>, FsType::TmpFs));
    let vfs = block_on(Vfs::boot("test-inst", backing, "tmpfs", factory)).unwrap();
    block_on(vfs.mkdirat(1, StartAnchor::Root, "/run", 0o755)).unwrap();
    block_on(vfs.mkdirat(1, StartAnchor::Root, "/tmp", 0o1777)).unwrap();
    block_on(vfs.setattrat(
        1,
        StartAnchor::Root,
        "/tmp",
        &abi::fs::SetAttr {
            mode: Some(0o1777),
            ..Default::default()
        },
        true,
    ))
    .unwrap();
    block_on(vfs.mkdirat(1, StartAnchor::Root, "/ro", 0o555)).unwrap();
    vfs.spawn_process(
        10,
        1,
        Cred::new(user_identity(1000, 1000)),
        None,
        None,
        None,
    )
    .unwrap();
    vfs.spawn_process(
        20,
        1,
        Cred::new(user_identity(2000, 2000)),
        None,
        None,
        None,
    )
    .unwrap();
    vfs
}

fn inode_key(entry: &vfs::Entry) -> SocketInodeKey {
    SocketInodeKey {
        fs_id: entry.handle.fs.clone(),
        node: entry.handle.node,
    }
}

/// U-01 + U-07: `SOCK_STREAM` bind/listen/accept/connect, `getsockname`/`getpeername`,
/// `S_IFSOCK` stat, `open()` -> `ENXIO`, and `unlink()` while listener alive lets new `bind()`
/// succeed while old accepted connections keep communicating.
#[test]
fn u01_u07_stream_lifecycle_and_unlink_rebind() {
    let vfs = setup_vfs();
    let mut table = UnixSocketTable::new();
    let root_cred = PeerCred {
        pid: 1,
        uid: 0,
        gid: 0,
    };
    let cli_cred = PeerCred {
        pid: 10,
        uid: 1000,
        gid: 1000,
    };

    // Bind /run/test.sock (mode 0666 & !022 = 0644, then chmod 0666 so uid 1000 can connect).
    let srv_sock = table.create(1, SockType::Stream, root_cred).unwrap();
    let entry1 = block_on(vfs.mksockat(1, StartAnchor::Root, "/run/test.sock", 0o666)).unwrap();
    block_on(vfs.setattrat(
        1,
        StartAnchor::Root,
        "/run/test.sock",
        &abi::fs::SetAttr {
            mode: Some(0o666),
            ..Default::default()
        },
        true,
    ))
    .unwrap();
    assert_eq!(entry1.metadata.file_type, FileType::Socket);
    let st = block_on(vfs.statat(1, StartAnchor::Root, "/run/test.sock", true)).unwrap();
    assert!(st.is_socket());
    assert_eq!(st.mode & abi::S_IFMT, abi::S_IFSOCK);

    // open(2) on a socket inode MUST return ENXIO (both read and write, and O_CREAT without O_EXCL).
    assert_eq!(
        block_on(vfs.open_file(1, StartAnchor::Root, "/run/test.sock", abi::O_RDONLY, 0)).err(),
        Some(Errno::ENXIO)
    );
    assert_eq!(
        block_on(vfs.open_file(
            1,
            StartAnchor::Root,
            "/run/test.sock",
            abi::O_RDWR | abi::O_CREAT,
            0o666
        ))
        .err(),
        Some(Errno::ENXIO)
    );
    // O_PATH open on a socket inode succeeds as on Linux.
    let (path_ref, _) =
        block_on(vfs.open_file(1, StartAnchor::Root, "/run/test.sock", abi::O_PATH, 0)).unwrap();
    block_on(path_ref.close()).unwrap();

    // Binding again on existing path fails EEXIST in VFS (mapped to EADDRINUSE by bridge).
    assert_eq!(
        block_on(vfs.mksockat(1, StartAnchor::Root, "/run/test.sock", 0o666)).err(),
        Some(Errno::EEXIST)
    );

    table
        .bind(1, srv_sock, inode_key(&entry1), "/run/test.sock".into())
        .unwrap();
    table.listen(1, srv_sock, 16, root_cred).unwrap();
    assert_eq!(
        table.getsockopt(1, srv_sock, SOL_SOCKET, SO_ACCEPTCONN),
        Ok(1)
    );
    assert_eq!(
        table.getsockopt(1, srv_sock, SOL_SOCKET, SO_TYPE),
        Ok(SOCK_STREAM as i32)
    );
    assert_eq!(table.getsockname(1, srv_sock).unwrap(), "/run/test.sock");

    // Client connects and verifies SO_PEERCRED & getpeername.
    let cli_sock = table.create(10, SockType::Stream, cli_cred).unwrap();
    let target =
        block_on(vfs.resolve_socket_inode(10, StartAnchor::Root, "/run/test.sock")).unwrap();
    let conn = table
        .connect(
            10,
            cli_sock,
            &inode_key(&target),
            "/run/test.sock".into(),
            cli_cred,
        )
        .unwrap();
    assert_eq!(conn.peer_cred, root_cred);
    assert_eq!(table.getpeername(10, cli_sock).unwrap(), "/run/test.sock");

    let poll_lis = table.poll(1, srv_sock, false).unwrap();
    assert!(poll_lis.ready);
    assert_eq!(poll_lis.nbytes, 1);

    let accepted = table.accept(1, srv_sock, root_cred).unwrap();
    assert_eq!(accepted.peer_cred, cli_cred);
    assert_eq!(
        table.getsockname(1, accepted.sock_id).unwrap(),
        "/run/test.sock"
    );

    // Unlink /run/test.sock while listener & accepted pair are alive!
    block_on(vfs.unlinkat(1, StartAnchor::Root, "/run/test.sock", false)).unwrap();

    // New bind("/run/test.sock") succeeds immediately with a fresh inode!
    let srv_sock2 = table.create(1, SockType::Stream, root_cred).unwrap();
    let entry2 = block_on(vfs.mksockat(1, StartAnchor::Root, "/run/test.sock", 0o666)).unwrap();
    assert_ne!(entry1.handle.node.ino, entry2.handle.node.ino);
    table
        .bind(1, srv_sock2, inode_key(&entry2), "/run/test.sock".into())
        .unwrap();
    table.listen(1, srv_sock2, 8, root_cred).unwrap();

    // Old connection STILL exchanges data cleanly!
    table
        .sendmsg(
            10,
            cli_sock,
            b"hello-over-unlinked",
            Vec::new(),
            None,
            cli_cred,
            None,
        )
        .unwrap();
    let got = table.recvmsg(1, accepted.sock_id, 64, 0, 0, None).unwrap();
    assert_eq!(got.data, b"hello-over-unlinked");

    // Close everything -> verify zero leaked sockets, bindings, or arena slots!
    table.close(10, cli_sock, 1).unwrap();
    table.close(1, accepted.sock_id, 1).unwrap();
    table.close(1, srv_sock, 1).unwrap();
    table.close(1, srv_sock2, 1).unwrap();
    assert_eq!(
        table.stats(),
        vfs::unix_sock::SocketStats {
            active_sockets: 0,
            bound_inodes: 0,
            inflight_global: 0,
            allocated_arena_slots: 0,
        }
    );
}

/// U-03: `SOCK_DGRAM` multi-client unconnected `sendmsg` + `SO_PEERCRED` + `SOCK_SEQPACKET`
/// record framing, `MSG_TRUNC`, `MSG_PEEK`, and `EMSGSIZE`.
#[test]
fn u03_dgram_and_seqpacket_framing_and_limits() {
    let vfs = setup_vfs();
    let mut table = UnixSocketTable::new();
    let root_cred = PeerCred {
        pid: 1,
        uid: 0,
        gid: 0,
    };
    let c1_cred = PeerCred {
        pid: 10,
        uid: 1000,
        gid: 1000,
    };
    let c2_cred = PeerCred {
        pid: 20,
        uid: 2000,
        gid: 2000,
    };

    // SOCK_DGRAM server bound at /run/notify.sock
    let srv = table.create(1, SockType::Dgram, root_cred).unwrap();
    let entry = block_on(vfs.mksockat(1, StartAnchor::Root, "/run/notify.sock", 0o666)).unwrap();
    table
        .bind(1, srv, inode_key(&entry), "/run/notify.sock".into())
        .unwrap();
    // listen() on DGRAM returns EOPNOTSUPP.
    assert_eq!(table.listen(1, srv, 4, root_cred), Err(Errno::EOPNOTSUPP));
    assert_eq!(
        table.getsockopt(1, srv, SOL_SOCKET, SO_TYPE),
        Ok(SOCK_DGRAM as i32)
    );

    let c1 = table.create(10, SockType::Dgram, c1_cred).unwrap();
    let c2 = table.create(20, SockType::Dgram, c2_cred).unwrap();
    let dst = inode_key(&entry);

    // Oversized datagram (> 64 KiB) fails EMSGSIZE.
    let huge = vec![0xAA; UNIX_DGRAM_MAX + 1];
    assert_eq!(
        table.sendmsg(10, c1, &huge, Vec::new(), Some(&dst), c1_cred, None),
        Err(Errno::EMSGSIZE)
    );

    // Two independent unconnected clients send to /run/notify.sock.
    table
        .sendmsg(10, c1, b"READY=1", Vec::new(), Some(&dst), c1_cred, None)
        .unwrap();
    table
        .sendmsg(
            20,
            c2,
            b"STATUS=booting",
            Vec::new(),
            Some(&dst),
            c2_cred,
            None,
        )
        .unwrap();

    // MSG_PEEK sees first packet without dequeuing.
    let peeked = table.recvmsg(1, srv, 32, 0, MSG_PEEK, None).unwrap();
    assert_eq!(peeked.data, b"READY=1");
    assert_eq!(peeked.peer_cred, c1_cred);

    let m1 = table.recvmsg(1, srv, 32, 0, 0, None).unwrap();
    assert_eq!(m1.data, b"READY=1");
    assert_eq!(m1.peer_cred, c1_cred);
    assert_eq!(m1.out_flags, 0);

    // Smaller buffer truncates message and sets MSG_TRUNC, discarding remainder of packet.
    let m2 = table.recvmsg(1, srv, 6, 0, 0, None).unwrap();
    assert_eq!(m2.data, b"STATUS");
    assert_eq!(m2.peer_cred, c2_cred);
    assert_eq!(m2.out_flags & MSG_TRUNC, MSG_TRUNC);
    assert_eq!(
        table.recvmsg(1, srv, 32, 0, 0, None).err(),
        Some(Errno::EAGAIN)
    );

    // SOCK_SEQPACKET record boundaries!
    let pair = table.socketpair(10, SockType::Seqpacket, c1_cred).unwrap();
    assert_eq!(
        table.getsockopt(10, pair.sock_a, SOL_SOCKET, SO_TYPE),
        Ok(SOCK_SEQPACKET as i32)
    );
    assert_eq!(
        table.sendmsg(10, pair.sock_a, &huge, Vec::new(), None, c1_cred, None),
        Err(Errno::EMSGSIZE)
    );
    table
        .sendmsg(10, pair.sock_a, b"pkt-one", Vec::new(), None, c1_cred, None)
        .unwrap();
    table
        .sendmsg(
            10,
            pair.sock_a,
            b"pkt-two-longer",
            Vec::new(),
            None,
            c1_cred,
            None,
        )
        .unwrap();
    // Large recv buffer receives ONLY first packet (never coalesced!).
    let p1 = table.recvmsg(10, pair.sock_b, 1024, 0, 0, None).unwrap();
    assert_eq!(p1.data, b"pkt-one");
    assert_eq!(p1.out_flags, 0);
    // Small recv buffer truncates second packet with MSG_TRUNC.
    let p2 = table.recvmsg(10, pair.sock_b, 7, 0, 0, None).unwrap();
    assert_eq!(p2.data, b"pkt-two");
    assert_eq!(p2.out_flags & MSG_TRUNC, MSG_TRUNC);

    // Shutdown & EOF on SEQPACKET.
    table.shutdown(10, pair.sock_a, SHUT_WR).unwrap();
    let eof = table.recvmsg(10, pair.sock_b, 32, 0, 0, None).unwrap();
    assert!(eof.data.is_empty());
    assert_eq!(
        table.sendmsg(10, pair.sock_a, b"late", Vec::new(), None, c1_cred, None),
        Err(Errno::EPIPE)
    );
}

/// U-04 + U-05: `SCM_RIGHTS` passing a `VfsFile` (verifying shared seek offset across processes),
/// `ArenaPipe`, `Pty`, and `UnixSocket`, PLUS strict `SOCK_STREAM` ancillary boundary splitting
/// (`"AAA"+[fd1]` then `"BBB"+[fd2]` NEVER coalesced!).
#[test]
fn u04_u05_scm_rights_and_stream_ancillary_boundary_splitting() {
    let vfs = setup_vfs();
    let mut table = UnixSocketTable::new();
    let c1 = PeerCred {
        pid: 10,
        uid: 1000,
        gid: 1000,
    };
    let c2 = PeerCred {
        pid: 20,
        uid: 2000,
        gid: 2000,
    };

    // Create two regular files in /tmp.
    let fd1 = block_on(vfs.openat(
        10,
        StartAnchor::Root,
        "/tmp/f1.txt",
        abi::O_RDWR | abi::O_CREAT | abi::O_TRUNC,
        0o600,
    ))
    .unwrap();
    block_on(vfs.write(10, fd1, b"0123456789")).unwrap();
    block_on(vfs.lseek(10, fd1, vfs::SeekFrom::Start(4))).unwrap();

    let fd2 = block_on(vfs.openat(
        10,
        StartAnchor::Root,
        "/tmp/f2.txt",
        abi::O_RDWR | abi::O_CREAT | abi::O_TRUNC,
        0o600,
    ))
    .unwrap();
    block_on(vfs.write(10, fd2, b"second")).unwrap();
    block_on(vfs.lseek(10, fd2, vfs::SeekFrom::Start(0))).unwrap();

    // Connect pid 10 <-> pid 20 via /run/pass.sock.
    let lis = table.create(20, SockType::Stream, c2).unwrap();
    let ent = block_on(vfs.mksockat(20, StartAnchor::Root, "/tmp/pass.sock", 0o666)).unwrap();
    table
        .bind(20, lis, inode_key(&ent), "/tmp/pass.sock".into())
        .unwrap();
    table.listen(20, lis, 4, c2).unwrap();
    let cli = table.create(10, SockType::Stream, c1).unwrap();
    table
        .connect(10, cli, &inode_key(&ent), "/tmp/pass.sock".into(), c1)
        .unwrap();
    let srv = table.accept(20, lis, c2).unwrap().sock_id;

    let file1 = vfs.get_file(10, fd1).unwrap();
    let file2 = vfs.get_file(10, fd2).unwrap();
    let pipe_slot = table.alloc_pipe_slot().unwrap();

    // Sender sends "AAA" + [file1, pipe_end], then IMMEDIATELY "BBB" + [file2].
    table
        .sendmsg(
            10,
            cli,
            b"AAA",
            vec![
                InFlightFd::VfsFile {
                    file: file1,
                    origin_pid: 10,
                    origin_token: None,
                    is_dir: false,
                    mount_ns: false,
                    device: None,
                    read: true,
                    writable: true,
                    append: false,
                    path_only: false,
                },
                InFlightFd::ArenaPipe {
                    slot: pipe_slot.slot,
                    generation: pipe_slot.generation,
                    end: PipeEnd::Read,
                    path_only: false,
                },
            ],
            None,
            c1,
            None,
        )
        .unwrap();
    table
        .sendmsg(
            10,
            cli,
            b"BBB",
            vec![InFlightFd::VfsFile {
                file: file2,
                origin_pid: 10,
                origin_token: None,
                is_dir: false,
                mount_ns: false,
                device: None,
                read: true,
                writable: true,
                append: false,
                path_only: false,
            }],
            None,
            c1,
            None,
        )
        .unwrap();

    // U-05: Receiver calls recvmsg(buf[16]) -> MUST get ONLY "AAA" + [fd1, pipe] (never coalesced!).
    let r1 = table.recvmsg(20, srv, 16, 8, 0, None).unwrap();
    assert_eq!(r1.data, b"AAA");
    assert_eq!(r1.fds.len(), 2);
    assert_eq!(r1.out_flags, 0);

    // Install received file1 into pid 20 (mode 0600 owned by uid 1000!) -> pid 20 reads from shared offset 4!
    let mut r1_fds = r1.fds.into_iter();
    let recv_file1 = match r1_fds.next().unwrap() {
        InFlightFd::VfsFile { file, .. } => file,
        _ => panic!("expected VfsFile"),
    };
    let pid20_fd1 = vfs.insert_file(20, recv_file1, false).unwrap();
    let mut buf = [0u8; 3];
    let n = block_on(vfs.read(20, pid20_fd1, &mut buf)).unwrap();
    assert_eq!(&buf[..n], b"456");
    // Shared seek offset: pid 10 now reads from offset 7!
    let mut buf2 = [0u8; 3];
    let n2 = block_on(vfs.read(10, fd1, &mut buf2)).unwrap();
    assert_eq!(&buf2[..n2], b"789");

    // Second recvmsg(buf[16]) -> MUST get "BBB" + [fd2]!
    let r2 = table.recvmsg(20, srv, 16, 8, 0, None).unwrap();
    assert_eq!(r2.data, b"BBB");
    assert_eq!(r2.fds.len(), 1);
    let recv_file2 = match r2.fds.into_iter().next().unwrap() {
        InFlightFd::VfsFile { file, .. } => file,
        _ => panic!("expected VfsFile"),
    };
    let pid20_fd2 = vfs.insert_file(20, recv_file2, true).unwrap();
    let mut buf3 = [0u8; 16];
    let n3 = block_on(vfs.read(20, pid20_fd2, &mut buf3)).unwrap();
    assert_eq!(&buf3[..n3], b"second");

    // Also test prefix bytes BEFORE an ancillary mark ("XX" without fds, then "YY" + [fd]).
    table
        .sendmsg(10, cli, b"XX", Vec::new(), None, c1, None)
        .unwrap();
    table
        .sendmsg(
            10,
            cli,
            b"YY",
            vec![InFlightFd::Pty {
                handle: 7,
                master: false,
                number: 1,
                readable: true,
                writable: true,
            }],
            None,
            c1,
            None,
        )
        .unwrap();
    let r3 = table.recvmsg(20, srv, 16, 8, 0, None).unwrap();
    assert_eq!(r3.data, b"XX");
    assert!(r3.fds.is_empty());
    let r4 = table.recvmsg(20, srv, 16, 8, 0, None).unwrap();
    assert_eq!(r4.data, b"YY");
    assert_eq!(r4.fds.len(), 1);

    // Free pipe slot & close all sockets -> zero leaks.
    assert!(table.free_pipe_slot(pipe_slot).is_some());
    table.release_process(10);
    table.release_process(20);
    assert_eq!(table.stats().active_sockets, 0);
    assert_eq!(table.stats().inflight_global, 0);
    assert_eq!(table.stats().allocated_arena_slots, 0);
}

/// U-06: `poll_oneoff` readiness for listener, stream read/write, hangup on `SHUT_WR`/close,
/// and datagram queue.
#[test]
fn u06_poll_readiness_and_hangup() {
    let mut table = UnixSocketTable::new();
    let cred = PeerCred {
        pid: 10,
        uid: 1000,
        gid: 1000,
    };
    let pair = table.socketpair(10, SockType::Stream, cred).unwrap();

    // Initially unreadable, writable.
    let r = table.poll(10, pair.sock_b, false).unwrap();
    assert!(!r.ready && !r.hangup);
    let w = table.poll(10, pair.sock_a, true).unwrap();
    assert!(w.ready && !w.hangup);

    // Send bytes -> peer becomes readable.
    table
        .sendmsg(10, pair.sock_a, b"ping", Vec::new(), None, cred, None)
        .unwrap();
    let r = table.poll(10, pair.sock_b, false).unwrap();
    assert!(r.ready && r.nbytes == 4 && !r.hangup);

    // Peer shuts down write -> reader observes hangup after draining.
    table.shutdown(10, pair.sock_a, SHUT_WR).unwrap();
    let _ = table.recvmsg(10, pair.sock_b, 4, 0, 0, None).unwrap();
    let r_hup = table.poll(10, pair.sock_b, false).unwrap();
    assert!(r_hup.ready && r_hup.hangup);

    // Closing sock_b marks sock_a write-poll as hangup and sendmsg returns EPIPE.
    let cleanup = table.close(10, pair.sock_b, 1).unwrap();
    assert!(!cleanup.peer_rd_closed.is_empty());
    let w_hup = table.poll(10, pair.sock_a, true).unwrap();
    assert!(w_hup.ready && w_hup.hangup);
    assert_eq!(
        table.sendmsg(10, pair.sock_a, b"x", Vec::new(), None, cred, None),
        Err(Errno::EPIPE)
    );
}

/// U-08 + U-09: Socket inode DAC & POSIX ACL `W_OK` enforcement on `bind` & `connect`,
/// including read-only mount (`EROFS`), `0555` directory (`EACCES`), `0600 root:root` socket
/// refused for `uid 1000` (`EACCES`), and POSIX ACL `u:1000:rw` granting `connect()`.
#[test]
fn u08_u09_dac_and_posix_acl_enforcement() {
    let vfs = setup_vfs();

    // Read-only directory `/ro` (mode 0555): uid 1000 cannot bind -> EACCES.
    assert_eq!(
        block_on(vfs.mksockat(10, StartAnchor::Root, "/ro/s.sock", 0o666)).err(),
        Some(Errno::EACCES)
    );

    // Mount a read-only tmpfs at `/ro_mnt` -> even root gets EROFS on bind!
    block_on(vfs.mkdirat(1, StartAnchor::Root, "/ro_mnt", 0o755)).unwrap();
    block_on(vfs.mount(
        1,
        "tmpfs",
        "/ro_mnt",
        Some("tmpfs"),
        abi::contract::mount_flags::MS_RDONLY,
        None,
    ))
    .unwrap();
    assert_eq!(
        block_on(vfs.mksockat(1, StartAnchor::Root, "/ro_mnt/s.sock", 0o666)).err(),
        Some(Errno::EROFS)
    );

    // Root creates `/run/priv.sock` mode `0600`: uid 1000 MUST be refused with EACCES on connect!
    let _priv_sock = block_on(vfs.mksockat(1, StartAnchor::Root, "/run/priv.sock", 0o600)).unwrap();
    assert_eq!(
        block_on(vfs.resolve_socket_inode(10, StartAnchor::Root, "/run/priv.sock")).err(),
        Some(Errno::EACCES)
    );
    // Root itself is allowed.
    assert!(block_on(vfs.resolve_socket_inode(1, StartAnchor::Root, "/run/priv.sock")).is_ok());

    // Grant POSIX ACL `u:1000:rw` on `/run/priv.sock` -> uid 1000 is now allowed, uid 2000 still refused!
    let mut users = BTreeMap::new();
    users.insert(1000, 6);
    let acl = Entries {
        user: 6,
        group: 0,
        other: 0,
        mask: Some(6),
        users,
        groups: BTreeMap::new(),
    };
    let acl_json = serde_json::to_vec(&acl).unwrap();
    block_on(vfs.setxattrat(
        1,
        StartAnchor::Root,
        "/run/priv.sock",
        abi::ACL_ACCESS,
        &acl_json,
        abi::fs::XattrFlags::empty(),
        true,
    ))
    .unwrap();

    assert!(block_on(vfs.resolve_socket_inode(10, StartAnchor::Root, "/run/priv.sock")).is_ok());
    assert_eq!(
        block_on(vfs.resolve_socket_inode(20, StartAnchor::Root, "/run/priv.sock")).err(),
        Some(Errno::EACCES)
    );
    // access(W_OK) on ACL-bearing socket also succeeds for uid 1000 and fails EACCES for uid 2000!
    assert!(
        block_on(vfs.accessat(10, StartAnchor::Root, "/run/priv.sock", abi::W_OK, true)).is_ok()
    );
    assert_eq!(
        block_on(vfs.accessat(20, StartAnchor::Root, "/run/priv.sock", abi::W_OK, true)).err(),
        Some(Errno::EACCES)
    );

    // Non-socket file returns ECONNREFUSED on resolve_socket_inode.
    let regular = block_on(vfs.openat(
        1,
        StartAnchor::Root,
        "/run/regular",
        abi::O_RDWR | abi::O_CREAT,
        0o666,
    ))
    .unwrap();
    block_on(vfs.close(1, regular)).unwrap();
    assert_eq!(
        block_on(vfs.resolve_socket_inode(1, StartAnchor::Root, "/run/regular")).err(),
        Some(Errno::ECONNREFUSED)
    );
}

/// U-11: `SCM_RIGHTS` DoS limits (`> 64` -> `EINVAL`, per-user `256` & global `512` ->
/// `ETOOMANYREFS`), invalid fd atomicity (`EBADF` with zero partial transfer), `MSG_CTRUNC`
/// zero-leak, and mark-and-sweep `unix_gc()` reclaiming `sockA <-> sockB` cycles + `SockArena` slots!
#[test]
fn u11_dos_limits_ctrunc_and_cycle_gc_zero_leak() {
    let mut table = UnixSocketTable::new();
    let u1 = PeerCred {
        pid: 10,
        uid: 1000,
        gid: 1000,
    };
    let u2 = PeerCred {
        pid: 20,
        uid: 2000,
        gid: 2000,
    };
    let u3 = PeerCred {
        pid: 30,
        uid: 3000,
        gid: 3000,
    };

    let pair1 = table.socketpair(10, SockType::Stream, u1).unwrap();
    let dummy = table.create(10, SockType::Dgram, u1).unwrap();

    // 1. Sending > SCM_MAX_FD (64) fds fails EINVAL with zero partial transfer.
    let too_many: Vec<InFlightFd> = (0..=SCM_MAX_FD)
        .map(|_| InFlightFd::UnixSocket(dummy))
        .collect();
    assert_eq!(
        table.sendmsg(10, pair1.sock_a, b"x", too_many, None, u1, None),
        Err(Errno::EINVAL)
    );
    assert_eq!(table.stats().inflight_global, 0);

    // 2. Invalid UnixSocket ID inside fd list fails EBADF atomically (zero partial transfer).
    assert_eq!(
        table.sendmsg(
            10,
            pair1.sock_a,
            b"x",
            vec![
                InFlightFd::UnixSocket(dummy),
                InFlightFd::UnixSocket(999_999)
            ],
            None,
            u1,
            None
        ),
        Err(Errno::EBADF)
    );
    assert_eq!(table.stats().inflight_global, 0);

    // 3. Per-user quota (256): 4 batches of 64 succeed (256 total); 1 more fails ETOOMANYREFS!
    for _ in 0..(MAX_INFLIGHT_FDS_PER_USER / SCM_MAX_FD) {
        let batch: Vec<InFlightFd> = (0..SCM_MAX_FD)
            .map(|_| InFlightFd::UnixSocket(dummy))
            .collect();
        table
            .sendmsg(10, pair1.sock_a, b"b", batch, None, u1, None)
            .unwrap();
    }
    assert_eq!(table.stats().inflight_global, MAX_INFLIGHT_FDS_PER_USER);
    assert_eq!(
        table.sendmsg(
            10,
            pair1.sock_a,
            b"z",
            vec![InFlightFd::UnixSocket(dummy)],
            None,
            u1,
            None
        ),
        Err(Errno::ETOOMANYREFS)
    );

    // 4. Global quota (512): user 2 queues 256 more (global == 512); user 3 fails ETOOMANYREFS!
    let pair2 = table.socketpair(20, SockType::Stream, u2).unwrap();
    let dummy2 = table.create(20, SockType::Dgram, u2).unwrap();
    for _ in 0..(MAX_INFLIGHT_FDS_PER_USER / SCM_MAX_FD) {
        let batch: Vec<InFlightFd> = (0..SCM_MAX_FD)
            .map(|_| InFlightFd::UnixSocket(dummy2))
            .collect();
        table
            .sendmsg(20, pair2.sock_a, b"b", batch, None, u2, None)
            .unwrap();
    }
    assert_eq!(table.stats().inflight_global, MAX_INFLIGHT_FDS_GLOBAL);
    let pair3 = table.socketpair(30, SockType::Stream, u3).unwrap();
    let dummy3 = table.create(30, SockType::Dgram, u3).unwrap();
    assert_eq!(
        table.sendmsg(
            30,
            pair3.sock_a,
            b"z",
            vec![InFlightFd::UnixSocket(dummy3)],
            None,
            u3,
            None
        ),
        Err(Errno::ETOOMANYREFS)
    );

    // 5. MSG_CTRUNC: receiver accepts max_fds = 2 out of 64 -> MSG_CTRUNC set, 62 dropped cleanly!
    let trunc = table.recvmsg(10, pair1.sock_b, 8, 2, 0, None).unwrap();
    assert_eq!(trunc.out_flags & MSG_CTRUNC, MSG_CTRUNC);
    assert_eq!(trunc.fds.len(), 2);
    assert_eq!(table.stats().inflight_global, MAX_INFLIGHT_FDS_GLOBAL - 64);

    // Release all processes -> drains all remaining queues & sockets.
    table.release_process(10);
    table.release_process(20);
    table.release_process(30);
    assert_eq!(
        table.stats(),
        vfs::unix_sock::SocketStats {
            active_sockets: 0,
            bound_inodes: 0,
            inflight_global: 0,
            allocated_arena_slots: 0,
        }
    );

    // 6. Reference cycle GC:
    //    Send sockA over sockA (delivers sockA into sockB's recv queue: sockB -> sockA)
    //    and sockB over sockB (delivers sockB into sockA's recv queue: sockA -> sockB).
    let cyc = table.socketpair(10, SockType::Stream, u1).unwrap();
    assert_eq!(table.stats().active_sockets, 2);
    assert_eq!(table.stats().allocated_arena_slots, 2);

    table
        .sendmsg(
            10,
            cyc.sock_a,
            b"A",
            vec![InFlightFd::UnixSocket(cyc.sock_a)],
            None,
            u1,
            None,
        )
        .unwrap();
    table
        .sendmsg(
            10,
            cyc.sock_b,
            b"B",
            vec![InFlightFd::UnixSocket(cyc.sock_b)],
            None,
            u1,
            None,
        )
        .unwrap();
    assert_eq!(table.stats().inflight_global, 2);

    // Close sock_a first: sock_b is still externally held and its recv queue holds sock_a, so BOTH stay alive.
    table.close(10, cyc.sock_a, 1).unwrap();
    assert_eq!(table.stats().active_sockets, 2);

    // Close sock_b: external holders of BOTH are now 0 -> unix_gc() MUST collect the entire cycle
    // and reclaim BOTH sockets, BOTH inflight refs, and BOTH SockArena slots!
    let gc_cleanup = table.close(10, cyc.sock_b, 1).unwrap();
    assert_eq!(gc_cleanup.freed_slots.len(), 2);
    assert_eq!(
        table.stats(),
        vfs::unix_sock::SocketStats {
            active_sockets: 0,
            bound_inodes: 0,
            inflight_global: 0,
            allocated_arena_slots: 0,
        }
    );

    // 7. Also verify direct `unix_gc()` on a 3-way cycle carrying a non-socket fd (Pty) returns the dropped fd!
    let p1 = table.socketpair(10, SockType::Stream, u1).unwrap();
    let p2 = table.socketpair(10, SockType::Stream, u1).unwrap();
    table
        .sendmsg(
            10,
            p1.sock_a,
            b"1",
            vec![
                InFlightFd::UnixSocket(p2.sock_b),
                InFlightFd::Pty {
                    handle: 99,
                    master: true,
                    number: 1,
                    readable: true,
                    writable: true,
                },
            ],
            None,
            u1,
            None,
        )
        .unwrap();
    table
        .sendmsg(
            10,
            p2.sock_a,
            b"2",
            vec![InFlightFd::UnixSocket(p1.sock_b)],
            None,
            u1,
            None,
        )
        .unwrap();
    let rel = table.release_process(10);
    assert_eq!(rel.dropped_fds.len(), 1);
    assert!(matches!(
        rel.dropped_fds[0],
        InFlightFd::Pty { handle: 99, .. }
    ));
    let mut noop = CleanupBatch::default();
    assert_eq!(table.unix_gc(&mut noop), 0);
    assert_eq!(table.stats().active_sockets, 0);
    assert_eq!(table.stats().inflight_global, 0);
    assert_eq!(table.stats().allocated_arena_slots, 0);

    // Ensure SO_PASSCRED option works cleanly on a fresh socket.
    let s = table.create(10, SockType::Stream, u1).unwrap();
    assert_eq!(table.getsockopt(10, s, SOL_SOCKET, SO_PASSCRED), Ok(0));
    table.setsockopt(10, s, SOL_SOCKET, SO_PASSCRED, 1).unwrap();
    assert_eq!(table.getsockopt(10, s, SOL_SOCKET, SO_PASSCRED), Ok(1));
    table.close(10, s, 1).unwrap();
    assert_eq!(table.stats().active_sockets, 0);
}

/// U-07 (on `MemFs` direct driver): verify `FileType::Socket` `stat`/`chmod`/`chown`/`unlink`
/// and `open()` -> `ENXIO`.
#[test]
fn u07_memfs_socket_inode_ops() {
    let fs = MemFs::new(
        FsId("mem-sock".into()),
        1,
        0,
        0,
        0o755,
        Box::new(|| (1_700_000_000, 0)),
    );
    let root = fs.root();
    let u = Cred::new(user_identity(1000, 1000));
    // Create world-writable dir so uid 1000 can create socket inode in it.
    let dir = block_on(fs.mkdir(&Cred::root(), &root, "run", 0o777)).unwrap();
    block_on(fs.setattr(
        &Cred::root(),
        &dir.handle,
        &abi::fs::SetAttr {
            mode: Some(0o777),
            ..Default::default()
        },
    ))
    .unwrap();
    // Unprivileged user creates socket inode (unlike char-dev mknod which requires root!).
    let sock = block_on(fs.mksock(&u, &dir.handle, "app.sock", 0o640)).unwrap();
    assert_eq!(sock.metadata.file_type, FileType::Socket);
    assert_eq!(
        sock.metadata.st_mode(),
        abi::S_IFSOCK | (0o640 & !u.umask as u32)
    );

    // open() fails ENXIO.
    let mut ro = OpenOptions::new();
    ro.read(true);
    assert_eq!(block_on(fs.open(&u, &sock.handle, &ro)), Err(Errno::ENXIO));
    // O_PATH succeeds.
    let mut path_only = OpenOptions::new();
    path_only.path(true);
    let oref = block_on(fs.open(&u, &sock.handle, &path_only)).unwrap();
    block_on(fs.release(&oref)).unwrap();

    // chmod + unlink work normally.
    let attr = abi::fs::SetAttr {
        mode: Some(0o660),
        ..Default::default()
    };
    let updated = block_on(fs.setattr(&u, &sock.handle, &attr)).unwrap();
    assert_eq!(updated.mode, 0o660);
    block_on(fs.unlink(&u, &dir.handle, "app.sock")).unwrap();
}

/// Regression tests for Codex audit findings (High #8, #9, #13, #14, #16; Medium #2, #4, #5; Low #1).
#[test]
fn codex_high8_half_close_preserves_data_and_shut_rd_drains_rights() {
    let mut table = UnixSocketTable::new();
    let cred = PeerCred {
        pid: 10,
        uid: 1000,
        gid: 1000,
    };
    let pair = table.socketpair(10, SockType::Stream, cred).unwrap();

    // A writes "queued" and calls SHUT_WR; then B calls SHUT_WR: B MUST still read "queued" before EOF!
    table
        .sendmsg(10, pair.sock_a, b"queued", Vec::new(), None, cred, None)
        .unwrap();
    let sh_a = table.shutdown(10, pair.sock_a, SHUT_WR).unwrap();
    assert!(sh_a.close_tx_wr && !sh_a.close_rx_rd);
    let sh_b = table.shutdown(10, pair.sock_b, SHUT_WR).unwrap();
    assert!(sh_b.close_tx_wr && !sh_b.close_rx_rd);
    // Subsequent send on A or B fails EPIPE.
    assert_eq!(
        table.sendmsg(10, pair.sock_a, b"x", Vec::new(), None, cred, None),
        Err(Errno::EPIPE)
    );
    // B reads all queued bytes from A, then sees EOF.
    let got = table.recvmsg(10, pair.sock_b, 16, 0, 0, None).unwrap();
    assert_eq!(got.data, b"queued");
    let eof = table.recvmsg(10, pair.sock_b, 16, 0, 0, None).unwrap();
    assert!(eof.data.is_empty());
    table.close(10, pair.sock_a, 1).unwrap();
    table.close(10, pair.sock_b, 1).unwrap();

    // Explicit SHUT_RD immediately discards queued rights & frees quotas/orphan sockets!
    let p2 = table.socketpair(10, SockType::Stream, cred).unwrap();
    let orphan = table.create(10, SockType::Dgram, cred).unwrap();
    table
        .sendmsg(
            10,
            p2.sock_a,
            b"X",
            vec![InFlightFd::UnixSocket(orphan)],
            None,
            cred,
            None,
        )
        .unwrap();
    table.close(10, orphan, 1).unwrap();
    assert_eq!(table.stats().inflight_global, 1);
    assert_eq!(table.stats().active_sockets, 3);

    let sh_rd = table.shutdown(10, p2.sock_b, SHUT_RD).unwrap();
    assert!(sh_rd.close_rx_rd && !sh_rd.close_tx_wr);
    assert_eq!(table.stats().inflight_global, 0);
    assert_eq!(table.stats().active_sockets, 2);
    let eof2 = table.recvmsg(10, p2.sock_b, 16, 4, 0, None).unwrap();
    assert!(eof2.data.is_empty() && eof2.fds.is_empty());
    table.close(10, p2.sock_a, 1).unwrap();
    table.close(10, p2.sock_b, 1).unwrap();
    assert_eq!(table.stats().active_sockets, 0);
    assert_eq!(table.stats().allocated_arena_slots, 0);
}

#[test]
fn codex_high9_ctrunc_propagates_peer_close_notifications() {
    let mut table = UnixSocketTable::new();
    let cred = PeerCred {
        pid: 10,
        uid: 1000,
        gid: 1000,
    };
    let outer = table.socketpair(10, SockType::Stream, cred).unwrap();
    let inner = table.socketpair(10, SockType::Stream, cred).unwrap();

    // Pass inner.sock_a over outer.sock_a and drop our external ref so ONLY the in-flight queue holds it.
    table
        .sendmsg(
            10,
            outer.sock_a,
            b"Z",
            vec![InFlightFd::UnixSocket(inner.sock_a)],
            None,
            cred,
            None,
        )
        .unwrap();
    table.close(10, inner.sock_a, 1).unwrap();

    // Receiver accepts max_fds = 0 -> MSG_CTRUNC reclaims inner.sock_a -> MUST report peer_wr_closed & peer_rd_closed!
    let r = table.recvmsg(10, outer.sock_b, 16, 0, 0, None).unwrap();
    assert_eq!(r.out_flags & MSG_CTRUNC, MSG_CTRUNC);
    assert!(r.fds.is_empty());
    assert_eq!(r.peer_wr_closed, vec![inner.slot_ab.unwrap()]);
    assert_eq!(r.peer_rd_closed, vec![inner.slot_ba.unwrap()]);

    table.release_process(10);
    assert_eq!(table.stats().active_sockets, 0);
    assert_eq!(table.stats().allocated_arena_slots, 0);
}

#[test]
fn codex_high13_high14_low1_listener_cred_passcred_dgram_peer_and_bound_name() {
    let vfs = setup_vfs();
    let mut table = UnixSocketTable::new();
    let c10 = PeerCred {
        pid: 10,
        uid: 1000,
        gid: 1000,
    };
    let c20 = PeerCred {
        pid: 20,
        uid: 2000,
        gid: 2000,
    };
    let c30 = PeerCred {
        pid: 30,
        uid: 3000,
        gid: 3000,
    };

    // High #13 + Low #1: pid 10 creates & binds /tmp/orig.sock, pid 20 calls listen(),
    // then /tmp/orig.sock is renamed to /tmp/renamed.sock before pid 10 connects.
    let lis = table.create(10, SockType::Stream, c10).unwrap();
    let ent = block_on(vfs.mksockat(10, StartAnchor::Root, "/tmp/orig.sock", 0o666)).unwrap();
    table
        .bind(10, lis, inode_key(&ent), "/tmp/orig.sock".into())
        .unwrap();
    table.hold(20, lis, 1).unwrap();
    table.listen(20, lis, 4, c20).unwrap();
    block_on(vfs.renameat(
        1,
        StartAnchor::Root,
        "/tmp/orig.sock",
        StartAnchor::Root,
        "/tmp/renamed.sock",
        abi::fs::RenameFlags::empty(),
    ))
    .unwrap();

    let cli = table.create(10, SockType::Stream, c10).unwrap();
    // Enable SO_PASSCRED on client BEFORE connect() so ConnectResult reports client_passcred = true!
    table
        .setsockopt(10, cli, SOL_SOCKET, SO_PASSCRED, 1)
        .unwrap();
    let resolved =
        block_on(vfs.resolve_socket_inode(10, StartAnchor::Root, "/tmp/renamed.sock")).unwrap();
    let conn = table
        .connect(
            10,
            cli,
            &inode_key(&resolved),
            "/tmp/renamed.sock".into(),
            c10,
        )
        .unwrap();
    assert!(conn.client_passcred);
    // Client MUST see listener's credentials at listen() time (pid 20, NOT creator pid 10)!
    assert_eq!(conn.peer_cred, c20);
    // Low #1: getpeername & accepted getsockname MUST report bound name "/tmp/orig.sock", NOT "/tmp/renamed.sock"!
    assert_eq!(table.getpeername(10, cli).unwrap(), "/tmp/orig.sock");
    let acc = table.accept(20, lis, c20).unwrap();
    assert_eq!(
        table.getsockname(20, acc.sock_id).unwrap(),
        "/tmp/orig.sock"
    );
    // Pre-connect client SO_PASSCRED attributes writes from a forwarded server holder (pid 30) to pid 30!
    table.hold(30, acc.sock_id, 1).unwrap();
    table
        .sendmsg(30, acc.sock_id, b"srv30", Vec::new(), None, c30, None)
        .unwrap();
    let cli_got = table.recvmsg(10, cli, 16, 0, 0, None).unwrap();
    assert_eq!(cli_got.data, b"srv30");
    assert_eq!(cli_got.peer_cred, c30);

    // High #13: SO_PASSCRED on accepted socket attributes plain writes from another holder (pid 30) to pid 30!
    let opt = table
        .setsockopt(20, acc.sock_id, SOL_SOCKET, SO_PASSCRED, 1)
        .unwrap();
    assert_eq!(opt.passcred, Some(true));
    assert_eq!(opt.rx_slot, acc.rx_slot);
    table.hold(30, cli, 1).unwrap();
    table
        .sendmsg(30, cli, b"from30", Vec::new(), None, c30, None)
        .unwrap();
    let got = table.recvmsg(20, acc.sock_id, 16, 0, 0, None).unwrap();
    assert_eq!(got.data, b"from30");
    assert_eq!(got.peer_cred, c30);

    // High #14: Connected SOCK_DGRAM rejects third-party senders before charging quota!
    let d_a = table.create(10, SockType::Dgram, c10).unwrap();
    let ent_a = block_on(vfs.mksockat(10, StartAnchor::Root, "/tmp/da.sock", 0o666)).unwrap();
    table
        .bind(10, d_a, inode_key(&ent_a), "/tmp/da.sock".into())
        .unwrap();
    let d_b = table.create(20, SockType::Dgram, c20).unwrap();
    let ent_b = block_on(vfs.mksockat(20, StartAnchor::Root, "/tmp/db.sock", 0o666)).unwrap();
    table
        .bind(20, d_b, inode_key(&ent_b), "/tmp/db.sock".into())
        .unwrap();
    // B connects to A -> B now accepts datagrams ONLY from A!
    table
        .connect(20, d_b, &inode_key(&ent_a), "/tmp/da.sock".into(), c20)
        .unwrap();
    let d_c = table.create(30, SockType::Dgram, c30).unwrap();
    assert_eq!(
        table.sendmsg(
            30,
            d_c,
            b"spoof",
            vec![InFlightFd::UnixSocket(d_c)],
            Some(&inode_key(&ent_b)),
            c30,
            None
        ),
        Err(Errno::ECONNREFUSED)
    );
    assert_eq!(table.stats().inflight_global, 0);
    // A sending to B succeeds!
    table
        .sendmsg(
            10,
            d_a,
            b"legit",
            Vec::new(),
            Some(&inode_key(&ent_b)),
            c10,
            None,
        )
        .unwrap();
    let dg = table.recvmsg(20, d_b, 16, 0, 0, None).unwrap();
    assert_eq!(dg.data, b"legit");

    table.release_process(10);
    table.release_process(20);
    table.release_process(30);
    assert_eq!(table.stats().active_sockets, 0);
}

#[test]
fn codex_high16_med4_med5_bind_rollback_trunc_peek_and_zero_len_stream() {
    let vfs = setup_vfs();
    let mut table = UnixSocketTable::new();
    let cred = PeerCred {
        pid: 10,
        uid: 1000,
        gid: 1000,
    };

    // High #16: begin_bind rejects concurrent second bind; rollback_created_inode won't unlink a replacement!
    let s = table.create(10, SockType::Stream, cred).unwrap();
    table.begin_bind(10, s, "/tmp/race.sock").unwrap();
    assert_eq!(
        table.begin_bind(10, s, "/tmp/race2.sock"),
        Err(Errno::EINVAL)
    );
    let (created, parent_pin, parent_handle, name) =
        block_on(vfs.mksockat_with_parent(10, StartAnchor::Root, "/tmp/race.sock", 0o666)).unwrap();
    // Simulate another process renaming away and replacing `/tmp/race.sock` with a regular file!
    block_on(vfs.renameat(
        10,
        StartAnchor::Root,
        "/tmp/race.sock",
        StartAnchor::Root,
        "/tmp/moved.sock",
        abi::fs::RenameFlags::empty(),
    ))
    .unwrap();
    let repl = block_on(vfs.openat(
        10,
        StartAnchor::Root,
        "/tmp/race.sock",
        abi::O_RDWR | abi::O_CREAT,
        0o644,
    ))
    .unwrap();
    block_on(vfs.close(10, repl)).unwrap();
    table.abort_bind(s);
    // Rollback targeting `created.handle.node` MUST NOT delete the replacement regular file!
    let _ = block_on(vfs.rollback_created_inode(
        10,
        &parent_pin,
        &parent_handle,
        &name,
        created.handle.node,
    ));
    let st = block_on(vfs.statat(10, StartAnchor::Root, "/tmp/race.sock", true)).unwrap();
    assert!(
        !st.is_socket(),
        "replacement regular file must survive bind rollback"
    );
    table.close(10, s, 1).unwrap();

    // Medium #4: MSG_TRUNC orig_len + MSG_PEEK delivering fds without consuming message/quota!
    let dp = table.socketpair(10, SockType::Dgram, cred).unwrap();
    let pass_sock = table.create(10, SockType::Dgram, cred).unwrap();
    table
        .sendmsg(
            10,
            dp.sock_a,
            b"12345678",
            vec![InFlightFd::UnixSocket(pass_sock)],
            None,
            cred,
            None,
        )
        .unwrap();
    let peeked = table
        .recvmsg(10, dp.sock_b, 1, 1, MSG_PEEK | MSG_TRUNC, None)
        .unwrap();
    assert_eq!(peeked.data, b"1");
    assert_eq!(peeked.orig_len, 8);
    assert_eq!(peeked.out_flags & MSG_TRUNC, MSG_TRUNC);
    assert_eq!(peeked.fds.len(), 1);
    assert_eq!(table.stats().inflight_global, 1);
    // Close peeked duplicate ref, then consume the real message cleanly!
    table.close(10, pass_sock, 1).unwrap();
    let real = table.recvmsg(10, dp.sock_b, 16, 1, 0, None).unwrap();
    assert_eq!(real.data, b"12345678");
    assert_eq!(real.orig_len, 8);
    assert_eq!(real.fds.len(), 1);
    assert_eq!(table.stats().inflight_global, 0);

    // Medium #5: 0-byte SOCK_STREAM sendmsg with SCM_RIGHTS charges 0 quota and installs no mark;
    // 0-byte recvmsg with queued stream bytes returns 0 without consuming bytes or marks!
    let sp = table.socketpair(10, SockType::Stream, cred).unwrap();
    let zero_send = table
        .sendmsg(
            10,
            sp.sock_a,
            b"",
            vec![InFlightFd::UnixSocket(pass_sock)],
            None,
            cred,
            None,
        )
        .unwrap();
    assert_eq!(zero_send.sent, 0);
    assert!(!zero_send.has_ancillary);
    assert_eq!(table.stats().inflight_global, 0);

    table
        .sendmsg(
            10,
            sp.sock_a,
            b"AB",
            vec![InFlightFd::UnixSocket(pass_sock)],
            None,
            cred,
            None,
        )
        .unwrap();
    let zero_recv = table.recvmsg(10, sp.sock_b, 0, 1, 0, None).unwrap();
    assert!(zero_recv.data.is_empty() && zero_recv.fds.is_empty());
    assert_eq!(table.stats().inflight_global, 1);
    // Stream MSG_PEEK delivers fd without consuming bytes or mark!
    let sp_peek = table.recvmsg(10, sp.sock_b, 2, 1, MSG_PEEK, None).unwrap();
    assert_eq!(sp_peek.data, b"AB");
    assert_eq!(sp_peek.fds.len(), 1);
    assert_eq!(table.stats().inflight_global, 1);
    table.close(10, pass_sock, 1).unwrap();
    // Real receive still gets "AB" + [pass_sock].
    let sp_real = table.recvmsg(10, sp.sock_b, 2, 1, 0, None).unwrap();
    assert_eq!(sp_real.data, b"AB");
    assert_eq!(sp_real.fds.len(), 1);
    assert_eq!(table.stats().inflight_global, 0);

    table.release_process(10);
    assert_eq!(table.stats().active_sockets, 0);
    assert_eq!(table.stats().allocated_arena_slots, 0);
}

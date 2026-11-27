//! Phase 10a (`#86`) `os-native` Outbound Stream Gateway Integration Tests (`NT-02..NT-09`).
//!
//! Exercises `os_native::netd::NetdHostServer` wired directly to real `os_vfs::Vfs` (`MemFs`),
//! `vfs::unix_sock::UnixSocketTable`, `os_kernel::proc_table::LocalProcessTable`, and real
//! ephemeral `tokio::net::TcpListener` fixtures on `127.0.0.1:0` (authorized strictly via the
//! two-key `LoopbackTestAllowlist` + `HostMatch::Exact` gate), plus a real Wasmtime 51 guest
//! executing `wasix_32v1` + `wasi_snapshot_preview1` socket imports through `os_native::wasi_host`.

use abi::Errno;
use abi::contract::InstanceIdentity;
use abi::net_ctl::{
    DataFrame, EgressRule, HostMatch, HostNetReq, HostNetResp, LoopbackTestAllowlist,
    NET_DATA_CHUNK_MAX, NET_HOST_SOCK, NET_INITIAL_WINDOW_BYTES, NETD_SOCK, NETD_VERSION, NetQuota,
    NetScope, NetdReq, NetdResp, PortRange, StreamMode, TlsMode, TlsPolicy, decode_control_payload,
    encode_control_frame, encode_unix_data_frame, encode_wasix_addr_port,
    try_decode_unix_data_frame,
};
use abi::socket::{AF_UNIX, PeerCred, SHUT_WR, SOCK_STREAM};
use os_core::permissions::Identity;
use os_kernel::proc_table::{LocalCred, LocalProcessTable, ReexecSpec, SpawnSpec};
use os_native::kernel_rpc::{KernelClient, KernelCmd, SockRecvReply, WakeBus};
use os_native::netd::{NativeNetdConfig, NetdHostServer};
use os_native::proc_runner::{GuestMem, ProcessHost, StoreMemoryLimiter, WasmRuntime};
use os_native::pty::PtyTable;
use os_native::signals::{ProcessSignals, SignalControl};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use vfs::memfs::MemFs;
use vfs::unix_sock::{InFlightFd, SockId, SockType, SocketInodeKey, UnixSocketTable};
use vfs::{DefaultFilesystemFactory, Filesystem, FsId, FsType, MountBacking, StartAnchor, Vfs};

const NETD_PID: u32 = 2;
const CLIENT_PID: u32 = 3;
const FORGED_PID: u32 = 4;

struct Harness {
    vfs: Vfs,
    socks: UnixSocketTable,
    procs: Rc<RefCell<LocalProcessTable>>,
    netd_pids: HashSet<u32>,
    server: NetdHostServer,
}

impl Harness {
    async fn new(config: NativeNetdConfig) -> Self {
        let clock: Rc<dyn Fn() -> (u64, u32)> = Rc::new(|| (1_700_000_000, 0));
        let root_fs = Rc::new(MemFs::new(
            FsId("netd-test-root".into()),
            1,
            0,
            0,
            0o755,
            Box::new(|| (1_700_000_000, 0)),
        ));
        let factory = Rc::new(DefaultFilesystemFactory::new(Rc::clone(&clock)));
        let root_backing = Rc::new(MountBacking::new(
            root_fs as Rc<dyn Filesystem>,
            FsType::TmpFs,
        ));
        let vfs = Vfs::boot("inst-netd-test", root_backing, "tmpfs", factory)
            .await
            .expect("boot test Vfs");
        vfs.mkdirat(1, StartAnchor::Root, "/run", 0o755)
            .await
            .expect("mkdir /run");

        let procs = Rc::new(RefCell::new(LocalProcessTable::new(
            InstanceIdentity {
                instance: "inst-netd-test".into(),
                host: "native-test".into(),
            },
            1_700_000_000,
        )));
        {
            let mut tbl = procs.borrow_mut();
            tbl.boot_init("native-test", 1_700_000_000)
                .expect("boot_init");
            // PID 2 = verified netd (uid 0)
            let p2 = tbl
                .spawn(
                    SpawnSpec::new(
                        "/usr/bin/netd",
                        LocalCred::local_only(Identity::root(), 0o022),
                        "native-test",
                    ),
                    1_700_000_000,
                )
                .expect("spawn netd");
            assert_eq!(p2.pid, NETD_PID);
            // PID 3 = ordinary local user client (uid 1000)
            let p3 = tbl
                .spawn(
                    SpawnSpec::new(
                        "/usr/bin/netctl",
                        LocalCred::local_only(
                            Identity {
                                id: 1000,
                                group: 1000,
                                groups: BTreeSet::from([1000]),
                            },
                            0o022,
                        ),
                        "native-test",
                    ),
                    1_700_000_000,
                )
                .expect("spawn client");
            assert_eq!(p3.pid, CLIENT_PID);
            // PID 4 = forged root process (NOT in netd_pids!)
            let p4 = tbl
                .spawn(
                    SpawnSpec::new(
                        "/usr/bin/fake",
                        LocalCred::local_only(Identity::root(), 0o022),
                        "native-test",
                    ),
                    1_700_000_000,
                )
                .expect("spawn forged");
            assert_eq!(p4.pid, FORGED_PID);
        }

        let mut socks = UnixSocketTable::new();
        let mut server = NetdHostServer::new(config);
        server.ensure_bound(&vfs, &mut socks).await;

        let mut netd_pids = HashSet::new();
        netd_pids.insert(NETD_PID);

        Self {
            vfs,
            socks,
            procs,
            netd_pids,
            server,
        }
    }

    fn tick(&mut self) -> bool {
        self.server
            .tick(&mut self.socks, &self.procs, &self.netd_pids)
    }

    async fn pump_once(&mut self) {
        self.tick();
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
        self.tick();
    }

    async fn connect_host_as(&mut self, pid: u32, uid: u32) -> SockId {
        let cred = PeerCred { pid, uid, gid: uid };
        let sid = self
            .socks
            .create(pid, SockType::Stream, cred)
            .expect("create host client sock");
        self.socks
            .set_nonblock(pid, sid, true)
            .expect("set nonblock");
        let entry = self
            .vfs
            .resolve_socket_inode(1, StartAnchor::Root, NET_HOST_SOCK)
            .await
            .expect("resolve socket inode");
        let key = SocketInodeKey {
            fs_id: entry.handle.fs.clone(),
            node: entry.handle.node,
        };
        self.socks
            .connect(pid, sid, &key, NET_HOST_SOCK.to_string(), cred)
            .expect("connect host sock");
        self.tick();
        sid
    }

    fn make_client_sock_pair(&mut self) -> (SockId, SockId) {
        let client_cred = PeerCred {
            pid: CLIENT_PID,
            uid: 1000,
            gid: 1000,
        };
        let pair = self
            .socks
            .socketpair(CLIENT_PID, SockType::Stream, client_cred)
            .expect("client pair");
        (pair.sock_a, pair.sock_b)
    }

    fn send_ctrl(
        &mut self,
        pid: u32,
        uid: u32,
        sid: SockId,
        req: &HostNetReq,
        pass_fd: Option<SockId>,
    ) {
        let frame = encode_control_frame(req).expect("encode HostNetReq");
        let fds = match pass_fd {
            Some(cs) => {
                self.socks.hold(pid, cs, 1).expect("hold scm fd");
                vec![InFlightFd::UnixSocket(cs)]
            }
            None => Vec::new(),
        };
        let cred = PeerCred { pid, uid, gid: uid };
        let out = self
            .socks
            .sendmsg(pid, sid, &frame, fds, None, cred, None)
            .expect("send ctrl");
        assert_eq!(out.sent, frame.len());
    }

    async fn recv_ctrl_resp(&mut self, pid: u32, sid: SockId, rx_buf: &mut Vec<u8>) -> HostNetResp {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            self.tick();
            if rx_buf.len() >= 4 {
                let len = u32::from_be_bytes([rx_buf[0], rx_buf[1], rx_buf[2], rx_buf[3]]) as usize;
                if rx_buf.len() >= 4 + len {
                    let payload = rx_buf[4..4 + len].to_vec();
                    rx_buf.drain(..4 + len);
                    return decode_control_payload::<HostNetResp>(&payload)
                        .expect("decode HostNetResp");
                }
            }
            match self.socks.recvmsg(pid, sid, 8192, 0, 0, None) {
                Ok(r) if !r.data.is_empty() => rx_buf.extend_from_slice(&r.data),
                Ok(_) => panic!("EOF waiting for HostNetResp"),
                Err(Errno::EAGAIN) => {
                    assert!(
                        Instant::now() < deadline,
                        "timed out waiting for HostNetResp"
                    );
                    self.pump_once().await;
                }
                Err(e) => panic!("recv_ctrl_resp error: {e:?}"),
            }
        }
    }

    fn send_data_frame(&mut self, sid: SockId, frame: &DataFrame) {
        assert!(
            self.try_send_data_frame(sid, frame),
            "send_data_frame hit unexpected EPIPE"
        );
    }

    fn try_send_data_frame(&mut self, sid: SockId, frame: &DataFrame) -> bool {
        let bytes = encode_unix_data_frame(frame).expect("encode data frame");
        let cred = PeerCred {
            pid: NETD_PID,
            uid: 0,
            gid: 0,
        };
        let mut off = 0usize;
        while off < bytes.len() {
            match self
                .socks
                .sendmsg(NETD_PID, sid, &bytes[off..], Vec::new(), None, cred, None)
            {
                Ok(out) => off += out.sent,
                Err(Errno::EAGAIN) => {
                    self.tick();
                }
                Err(Errno::EPIPE) => return false,
                Err(e) => panic!("send_data_frame failed: {e:?}"),
            }
        }
        true
    }

    async fn recv_data_frame(&mut self, sid: SockId, rx_buf: &mut Vec<u8>) -> Option<DataFrame> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            self.tick();
            if let Ok(Some((frame, used))) = try_decode_unix_data_frame(rx_buf) {
                rx_buf.drain(..used);
                return Some(frame);
            }
            match self.socks.recvmsg(NETD_PID, sid, 32 * 1024, 0, 0, None) {
                Ok(r) if r.data.is_empty() => return None,
                Ok(r) => rx_buf.extend_from_slice(&r.data),
                Err(Errno::EAGAIN) => {
                    assert!(Instant::now() < deadline, "timed out waiting for DataFrame");
                    self.pump_once().await;
                }
                Err(e) => panic!("recv_data_frame error: {e:?}"),
            }
        }
    }

    async fn open_stream(
        &mut self,
        host: &str,
        port: u16,
        tls: TlsMode,
    ) -> (SockId, SockId, SockId, Vec<u8>, HostNetResp) {
        let host_sid = self.connect_host_as(NETD_PID, 0).await;
        let (client_end, netd_client_end) = self.make_client_sock_pair();
        self.send_ctrl(
            NETD_PID,
            0,
            host_sid,
            &HostNetReq::Open {
                host: host.to_string(),
                port,
                tls,
                timeout_ms: Some(3000),
            },
            Some(netd_client_end),
        );
        let mut rx = Vec::new();
        let resp = self.recv_ctrl_resp(NETD_PID, host_sid, &mut rx).await;
        (host_sid, client_end, netd_client_end, rx, resp)
    }
}

fn loopback_config(ports: &[u16], quota: NetQuota) -> NativeNetdConfig {
    let mut allowlist = LoopbackTestAllowlist::new();
    let mut port_ranges = Vec::new();
    for &p in ports {
        allowlist
            .insert(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), p))
            .expect("insert loopback");
        port_ranges.push(PortRange { start: p, end: p });
    }
    NativeNetdConfig {
        policy: Some(NetScope {
            rules: vec![EgressRule {
                host: HostMatch::Exact("127.0.0.1".into()),
                ports: port_ranges,
                tls: TlsPolicy::PlainOnly,
            }],
            quota,
        }),
        loopback_test_allowlist: allowlist,
    }
}

#[tokio::test]
async fn nt03_permitted_stream_echo_and_half_close() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = Vec::new();
                sock.read_to_end(&mut buf).await.unwrap();
                sock.write_all(&buf).await.unwrap();
                sock.shutdown().await.unwrap();
            });

            let mut h = Harness::new(loopback_config(&[port], NetQuota::default())).await;
            let (host_sid, _c1, _c2, mut rx, resp) =
                h.open_stream("127.0.0.1", port, TlsMode::Off).await;
            match resp {
                HostNetResp::Opened { initial_window, .. } => {
                    assert_eq!(initial_window, NET_INITIAL_WINDOW_BYTES);
                }
                other => panic!("expected Opened, got {other:?}"),
            }

            let payload = b"phase10a-native-echo-with-half-close!";
            h.send_data_frame(host_sid, &DataFrame::Data(payload[..15].to_vec()));
            h.send_data_frame(host_sid, &DataFrame::Data(payload[15..].to_vec()));
            h.send_data_frame(host_sid, &DataFrame::HalfClose);

            let mut echoed = Vec::new();
            let mut saw_half_close = false;
            while let Some(frame) = h.recv_data_frame(host_sid, &mut rx).await {
                match frame {
                    DataFrame::Data(chunk) => {
                        echoed.extend_from_slice(&chunk);
                        // Peer may have already delivered `HalfClose` + `Closed` and closed the
                        // Unix socket after flushing its final echo chunk; tolerate `EPIPE` on
                        // late best-effort `Credit`.
                        let _ =
                            h.try_send_data_frame(host_sid, &DataFrame::Credit(chunk.len() as u32));
                    }
                    DataFrame::Credit(_) => {}
                    DataFrame::HalfClose => saw_half_close = true,
                    DataFrame::Closed(cl) => {
                        assert_eq!(cl.errno, None);
                        break;
                    }
                    DataFrame::Cancel => panic!("unexpected cancel"),
                }
            }
            assert_eq!(echoed, payload);
            assert!(saw_half_close);
        })
        .await;
}

#[tokio::test]
async fn nt04_two_mib_slow_consumer_backpressure() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            const TOTAL: usize = 2 * 1024 * 1024;
            let expected: Vec<u8> = (0..TOTAL).map(|i| ((i * 29 + 7) & 0xff) as u8).collect();
            let expected_sha = Sha256::digest(&expected);

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let to_send = expected.clone();
            tokio::spawn(async move {
                let (mut sock, _) = listener.accept().await.unwrap();
                let _ = sock.write_all(&to_send).await;
                let _ = sock.shutdown().await;
            });

            let mut h = Harness::new(loopback_config(&[port], NetQuota::default())).await;
            let (host_sid, _c1, _c2, mut rx, resp) =
                h.open_stream("127.0.0.1", port, TlsMode::Off).await;
            assert!(matches!(resp, HostNetResp::Opened { .. }));

            // Read ONLY the initial 64 KiB window WITHOUT issuing CREDIT!
            let mut received = Vec::with_capacity(TOTAL);
            while received.len() < NET_INITIAL_WINDOW_BYTES as usize {
                let frame = h
                    .recv_data_frame(host_sid, &mut rx)
                    .await
                    .expect("expected DATA");
                if let DataFrame::Data(chunk) = frame {
                    assert!(chunk.len() <= NET_DATA_CHUNK_MAX);
                    received.extend_from_slice(&chunk);
                }
            }
            assert_eq!(
                received.len(),
                NET_INITIAL_WINDOW_BYTES as usize,
                "host must respect 64 KiB initial window"
            );

            // Pump for 120 ms with 0 credit and verify ZERO additional DATA arrives!
            for _ in 0..12 {
                tokio::time::sleep(Duration::from_millis(10)).await;
                h.tick();
                if let Ok(r) = h.socks.recvmsg(NETD_PID, host_sid, 8192, 0, 0, None) {
                    rx.extend_from_slice(&r.data);
                }
            }
            assert!(
                !matches!(
                    try_decode_unix_data_frame(&rx),
                    Ok(Some((DataFrame::Data(_), _)))
                ),
                "upstream TCP reader must pause when client_rx_credit == 0"
            );

            // Now trickle credit until all 2 MiB arrive losslessly!
            h.send_data_frame(host_sid, &DataFrame::Credit(NET_INITIAL_WINDOW_BYTES));
            while received.len() < TOTAL {
                match h.recv_data_frame(host_sid, &mut rx).await {
                    Some(DataFrame::Data(chunk)) => {
                        let len = chunk.len() as u32;
                        received.extend_from_slice(&chunk);
                        h.send_data_frame(host_sid, &DataFrame::Credit(len));
                    }
                    Some(DataFrame::HalfClose | DataFrame::Closed(_)) => break,
                    Some(_) => {}
                    None => break,
                }
            }
            assert_eq!(received.len(), TOTAL);
            assert_eq!(Sha256::digest(&received), expected_sha);
        })
        .await;
}

#[tokio::test]
async fn nt06_mid_connect_cancel_and_mid_transfer_kill_release_quota() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                while let Ok((mut sock, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let mut buf = [0u8; 256];
                        let _ = sock.read(&mut buf).await;
                    });
                }
            });

            let quota = NetQuota {
                max_concurrent_streams: 1,
                ..NetQuota::default()
            };
            let mut h = Harness::new(loopback_config(&[port], quota)).await;

            // Open stream 1, then send explicit CANCEL -> quota slot must be released!
            let (s1, _c1a, _c1b, _rx1, resp1) =
                h.open_stream("127.0.0.1", port, TlsMode::Off).await;
            assert!(matches!(resp1, HostNetResp::Opened { .. }));
            assert_eq!(h.server.active_stream_count(), 1);

            h.send_data_frame(s1, &DataFrame::Cancel);
            for _ in 0..10 {
                h.pump_once().await;
                if h.server.active_stream_count() == 0 {
                    break;
                }
            }
            assert_eq!(
                h.server.active_stream_count(),
                0,
                "CANCEL must release concurrency slot immediately"
            );

            // Open stream 2, then simulate client SIGKILL via `on_process_exit(CLIENT_PID)` -> slot freed!
            let (_s2, _c2a, _c2b, _rx2, resp2) =
                h.open_stream("127.0.0.1", port, TlsMode::Off).await;
            assert!(matches!(resp2, HostNetResp::Opened { .. }));
            assert_eq!(h.server.active_stream_count(), 1);

            h.server.on_process_exit(CLIENT_PID, &mut h.socks);
            assert_eq!(
                h.server.active_stream_count(),
                0,
                "client exit must abort stream and free quota slot"
            );
        })
        .await;
}

#[tokio::test]
async fn nt02_default_deny_policy_ssrf_and_tls_unsupported() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let allowed_srv = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let allowed_port = allowed_srv.local_addr().unwrap().port();
            let unlisted_srv = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let unlisted_port = unlisted_srv.local_addr().unwrap().port();

            // 1. Default-deny config (`policy: None`) denies everything.
            let mut h_deny = Harness::new(NativeNetdConfig::default()).await;
            let (_, _, _, _, resp) = h_deny
                .open_stream("127.0.0.1", allowed_port, TlsMode::Off)
                .await;
            assert!(matches!(
                resp,
                HostNetResp::Error {
                    errno: Errno::EACCES,
                    ..
                }
            ));

            // 2. Allowlisted config still rejects unlisted loopback, RFC1918, IMDS, mapped IPv6, localhost, and gateway TLS!
            let mut cfg = loopback_config(&[allowed_port], NetQuota::default());
            cfg.policy.as_mut().unwrap().rules.push(EgressRule {
                host: HostMatch::AnyPublic,
                ports: vec![PortRange {
                    start: 1,
                    end: 65535,
                }],
                tls: TlsPolicy::Any,
            });
            cfg.policy.as_mut().unwrap().rules[0].tls = TlsPolicy::Any;
            let mut h = Harness::new(cfg).await;

            for (host, port, expected_errno) in [
                ("127.0.0.1", unlisted_port, Errno::EACCES),
                ("10.0.0.1", 80, Errno::EACCES),
                ("169.254.169.254", 80, Errno::EACCES),
                ("::ffff:127.0.0.1", allowed_port, Errno::EACCES),
                ("localhost", allowed_port, Errno::EACCES),
                ("2130706433", 80, Errno::EINVAL),
            ] {
                let (_, _, _, _, resp) = h.open_stream(host, port, TlsMode::Off).await;
                assert!(
                    matches!(resp, HostNetResp::Error { errno, .. } if errno == expected_errno),
                    "expected {expected_errno:?} for {host}:{port}, got {resp:?}"
                );
            }

            // Native gateway NEVER fakes TLS -> returns EOPNOTSUPP!
            for tls in [TlsMode::On, TlsMode::StartTls] {
                let (_, _, _, _, resp) = h.open_stream("127.0.0.1", allowed_port, tls).await;
                assert!(
                    matches!(
                        resp,
                        HostNetResp::Error {
                            errno: Errno::EOPNOTSUPP,
                            ..
                        }
                    ),
                    "expected EOPNOTSUPP for {tls:?}, got {resp:?}"
                );
            }
        })
        .await;
}

#[tokio::test]
async fn nt08_concurrency_and_byte_quotas() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let blast = Arc::new(tokio::sync::Notify::new());
            let blast_srv = Arc::clone(&blast);
            tokio::spawn(async move {
                while let Ok((mut sock, _)) = listener.accept().await {
                    let b = Arc::clone(&blast_srv);
                    tokio::spawn(async move {
                        b.notified().await;
                        let _ = sock.write_all(&vec![b'X'; 64 * 1024]).await;
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    });
                }
            });

            let quota = NetQuota {
                max_concurrent_streams: 1,
                max_bytes_per_stream: 16 * 1024,
                ..NetQuota::default()
            };
            let mut h = Harness::new(loopback_config(&[port], quota)).await;

            // Stream 1 opens cleanly and stays idle while waiting for `blast`.
            let (s1, _, _, mut rx1, resp1) = h.open_stream("127.0.0.1", port, TlsMode::Off).await;
            assert!(matches!(resp1, HostNetResp::Opened { .. }));

            // Stream 2 exceeds `max_concurrent_streams` -> EDQUOT!
            let (_, _, _, _, resp2) = h.open_stream("127.0.0.1", port, TlsMode::Off).await;
            assert!(
                matches!(
                    resp2,
                    HostNetResp::Error {
                        errno: Errno::EDQUOT,
                        ..
                    }
                ),
                "expected EDQUOT for 2nd concurrent stream, got {resp2:?}"
            );

            // Trigger 64 KiB blast on Stream 1 -> exceeds `max_bytes_per_stream` (16 KiB) -> EDQUOT!
            blast.notify_waiters();
            let mut saw_edquot = false;
            while let Some(frame) = h.recv_data_frame(s1, &mut rx1).await {
                if let DataFrame::Closed(cl) = frame {
                    assert_eq!(cl.errno, Some(Errno::EDQUOT));
                    saw_edquot = true;
                    break;
                }
            }
            assert!(
                saw_edquot,
                "expected EDQUOT when max_bytes_per_stream exceeded"
            );

            // Once Stream 1 tears down, the concurrency slot is released and Stream 3 opens cleanly.
            let deadline = Instant::now() + Duration::from_secs(2);
            while h.server.active_stream_count() > 0 && Instant::now() < deadline {
                h.pump_once().await;
            }
            assert_eq!(h.server.active_stream_count(), 0);
            let (_, _, _, _, resp3) = h.open_stream("127.0.0.1", port, TlsMode::Off).await;
            assert!(
                matches!(resp3, HostNetResp::Opened { .. }),
                "expected Opened after slot released, got {resp3:?}"
            );
        })
        .await;
}

#[tokio::test]
async fn nt09_forged_netd_peer_rejected_and_host_loss_teardown() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                if let Ok((sock, _)) = listener.accept().await {
                    drop(sock);
                }
            });

            let mut h = Harness::new(loopback_config(&[port], NetQuota::default())).await;

            // 1. Forged root process (PID 4 not in `netd_pids`) connects to `/run/net/host.sock` -> EACCES!
            let forged_sid = h.connect_host_as(FORGED_PID, 0).await;
            let mut frx = Vec::new();
            let err = h.recv_ctrl_resp(FORGED_PID, forged_sid, &mut frx).await;
            assert!(
                matches!(
                    err,
                    HostNetResp::Error {
                        errno: Errno::EACCES,
                        ..
                    }
                ),
                "forged netd peer must fail with EACCES, got {err:?}"
            );

            // 2. Abrupt server disconnect tears down cleanly without hanging!
            let (s1, _, _, mut rx1, resp1) = h.open_stream("127.0.0.1", port, TlsMode::Off).await;
            assert!(matches!(resp1, HostNetResp::Opened { .. }));
            let mut saw_end = false;
            for _ in 0..8 {
                match h.recv_data_frame(s1, &mut rx1).await {
                    Some(DataFrame::HalfClose) => {
                        h.send_data_frame(s1, &DataFrame::HalfClose);
                    }
                    Some(DataFrame::Closed(_)) | None => {
                        saw_end = true;
                        break;
                    }
                    Some(_) => {}
                }
            }
            assert!(saw_end, "abrupt disconnect must terminate stream cleanly");

            // 3. `netd` exit cleans up all state cleanly.
            let s_hello = h.connect_host_as(NETD_PID, 0).await;
            h.send_ctrl(
                NETD_PID,
                0,
                s_hello,
                &HostNetReq::Hello {
                    versions: vec![NETD_VERSION],
                },
                None,
            );
            let mut hrx = Vec::new();
            let welcome = h.recv_ctrl_resp(NETD_PID, s_hello, &mut hrx).await;
            assert!(matches!(welcome, HostNetResp::Welcome { version: 1, .. }));
            h.server.on_process_exit(NETD_PID, &mut h.socks);
            assert_eq!(h.server.active_stream_count(), 0);
        })
        .await;
}

// ---- Minimal Wasm module exercising WASIX UDP/raw/bind/listen/accept/send_to/recv_from refusal ----

fn enc_uleb(mut v: u32, out: &mut Vec<u8>) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

fn enc_sleb(mut v: i32, out: &mut Vec<u8>) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        let done = (v == 0 && (b & 0x40) == 0) || (v == -1 && (b & 0x40) != 0);
        if !done {
            b |= 0x80;
        }
        out.push(b);
        if done {
            break;
        }
    }
}

fn push_sec(out: &mut Vec<u8>, id: u8, body: &[u8]) {
    out.push(id);
    enc_uleb(body.len() as u32, out);
    out.extend_from_slice(body);
}

fn enc_str(s: &str, out: &mut Vec<u8>) {
    enc_uleb(s.len() as u32, out);
    out.extend_from_slice(s.as_bytes());
}

fn wasm_wasix_socket_policy_probe() -> Vec<u8> {
    let mut wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    push_sec(
        &mut wasm,
        1,
        &[
            7, 0x60, 1, 0x7f, 0, 0x60, 4, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f, 0x60, 2, 0x7f, 0x7f, 1,
            0x7f, 0x60, 3, 0x7f, 0x7f, 0x7f, 1, 0x7f, 0x60, 6, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
            1, 0x7f, 0x60, 7, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f, 0x60, 0, 0,
        ],
    );
    let imports = [
        ("wasi_snapshot_preview1", "proc_exit", 0u8),
        ("wasix_32v1", "sock_open", 1),
        ("wasix_32v1", "sock_bind", 2),
        ("wasix_32v1", "sock_listen", 2),
        ("wasi_snapshot_preview1", "sock_accept", 3),
        ("wasix_32v1", "sock_send_to", 4),
        ("wasix_32v1", "sock_recv_from", 5),
    ];
    let mut imp = vec![imports.len() as u8];
    for (m, n, ty) in imports {
        enc_str(m, &mut imp);
        enc_str(n, &mut imp);
        imp.push(0x00);
        imp.push(ty);
    }
    push_sec(&mut wasm, 2, &imp);
    push_sec(&mut wasm, 3, &[1, 6]);
    push_sec(&mut wasm, 5, &[1, 0x00, 1]);
    let mut exp = vec![2];
    enc_str("memory", &mut exp);
    exp.extend_from_slice(&[0x02, 0]);
    enc_str("_start", &mut exp);
    exp.extend_from_slice(&[0x00, 7]);
    push_sec(&mut wasm, 7, &exp);

    let mut body = vec![1, 1, 0x7f];
    let i32c = |v: i32, b: &mut Vec<u8>| {
        b.push(0x41);
        enc_sleb(v, b);
    };
    let assert_eq_or_exit = |expected: i32, code: i32, b: &mut Vec<u8>| {
        i32c(expected, b);
        b.push(0x47);
        b.push(0x04);
        b.push(0x40);
        i32c(code, b);
        b.push(0x10);
        b.push(0);
        b.push(0x0b);
    };

    // 1. DGRAM -> 66 (EPROTONOSUPPORT)
    i32c(1, &mut body);
    i32c(1, &mut body);
    i32c(0, &mut body);
    i32c(0x100, &mut body);
    body.extend_from_slice(&[0x10, 1]);
    assert_eq_or_exit(66, 1, &mut body);
    // 2. RAW -> 66
    i32c(1, &mut body);
    i32c(3, &mut body);
    i32c(0, &mut body);
    i32c(0x100, &mut body);
    body.extend_from_slice(&[0x10, 1]);
    assert_eq_or_exit(66, 2, &mut body);
    // 3. STREAM + UDP(17) -> 66
    i32c(1, &mut body);
    i32c(2, &mut body);
    i32c(17, &mut body);
    i32c(0x100, &mut body);
    body.extend_from_slice(&[0x10, 1]);
    assert_eq_or_exit(66, 3, &mut body);
    // 4. STREAM + TCP(6) -> 0
    i32c(1, &mut body);
    i32c(2, &mut body);
    i32c(6, &mut body);
    i32c(0x100, &mut body);
    body.extend_from_slice(&[0x10, 1]);
    assert_eq_or_exit(0, 4, &mut body);
    // local.0 = i32.load(0x100)
    i32c(0x100, &mut body);
    body.extend_from_slice(&[0x28, 0x02, 0x00, 0x21, 0x00]);
    // 5. sock_bind -> 58 (EOPNOTSUPP)
    body.extend_from_slice(&[0x20, 0x00]);
    i32c(0x200, &mut body);
    body.extend_from_slice(&[0x10, 2]);
    assert_eq_or_exit(58, 5, &mut body);
    // 6. sock_listen -> 58
    body.extend_from_slice(&[0x20, 0x00]);
    i32c(8, &mut body);
    body.extend_from_slice(&[0x10, 3]);
    assert_eq_or_exit(58, 6, &mut body);
    // 7. sock_accept -> 58
    body.extend_from_slice(&[0x20, 0x00]);
    i32c(0, &mut body);
    i32c(0x104, &mut body);
    body.extend_from_slice(&[0x10, 4]);
    assert_eq_or_exit(58, 7, &mut body);
    // 8. sock_send_to -> 66
    body.extend_from_slice(&[0x20, 0x00]);
    for _ in 0..5 {
        i32c(0, &mut body);
    }
    body.extend_from_slice(&[0x10, 5]);
    assert_eq_or_exit(66, 8, &mut body);
    // 9. sock_recv_from -> 66
    body.extend_from_slice(&[0x20, 0x00]);
    for _ in 0..6 {
        i32c(0, &mut body);
    }
    body.extend_from_slice(&[0x10, 6]);
    assert_eq_or_exit(66, 9, &mut body);

    i32c(0, &mut body);
    body.extend_from_slice(&[0x10, 0, 0x0b]);

    let mut code = vec![1];
    enc_uleb(body.len() as u32, &mut code);
    code.extend_from_slice(&body);
    push_sec(&mut wasm, 10, &code);
    wasm
}

#[test]
fn nt07_wasix_udp_raw_and_inbound_refusal() {
    let runtime = WasmRuntime::new().expect("wasmtime runtime");
    let mut linker = wasmtime::Linker::new(&runtime.engine);
    linker.allow_shadowing(true);
    os_native::wasi_host::register_all(&mut linker).expect("register_all");

    let (tx, _rx) = mpsc::unbounded_channel::<KernelCmd>();
    let kernel = KernelClient {
        tx,
        wake: WakeBus::new(),
        ptys: PtyTable::new(Arc::new(|_, _| {}), Arc::new(|_, _, _| {})),
    };
    let host = ProcessHost {
        pid: 10,
        argv: vec!["probe".into()],
        env: vec![],
        umask: 0o022,
        fds: BTreeMap::new(),
        signals: ProcessSignals::new(SignalControl::new(), None, false),
        sys_reply: Vec::new(),
        main_mem: None,
        asyncify: Default::default(),
        snapshots: Default::default(),
        next_snapshot_id: 1,
        kernel,
        runtime: Arc::clone(&runtime),
        limiter: StoreMemoryLimiter {
            limit_bytes: None,
            linear_bytes: 0,
            grow_reserved: 0,
        },
        boot_instant: Instant::now(),
        in_signal_dispatch: false,
        sig_callback_fn: None,
        instance_exports: None,
        cancel_flag: None,
    };

    let wasm = wasm_wasix_socket_policy_probe();
    let module = wasmtime::Module::new(&runtime.engine, &wasm).expect("compile probe wasm");
    let mut store = wasmtime::Store::new(&runtime.engine, host);
    store.set_epoch_deadline(u64::MAX / 2);
    let instance = linker
        .instantiate(&mut store, &module)
        .expect("instantiate probe wasm");
    let mem = instance
        .get_memory(&mut store, "memory")
        .expect("probe memory");
    store.data_mut().main_mem = Some(GuestMem::Regular(mem));
    let start = instance
        .get_typed_func::<(), ()>(&mut store, "_start")
        .expect("_start");
    let err = start
        .call(&mut store, ())
        .expect_err("probe exits via proc_exit");
    let cf = err
        .downcast_ref::<os_native::proc_runner::GuestControlFlow>()
        .unwrap_or_else(|| panic!("expected GuestControlFlow, got: {err:?}"));
    match cf {
        os_native::proc_runner::GuestControlFlow::Exit { code, signal } => {
            assert_eq!(*signal, None);
            assert_eq!(
                *code, 0,
                "WASIX socket refusal probe failed at check {code}"
            );
        }
        other => panic!("unexpected GuestControlFlow: {other:?}"),
    }
    assert_eq!(AF_UNIX, 1);
    assert_eq!(SOCK_STREAM, 1);
}

#[tokio::test]
async fn p02_native_credit_u32_max_and_combined_tx_rx_byte_cap() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            // Part A: `Credit(u32::MAX)` must be clamped to `NET_INITIAL_WINDOW_BYTES` (64 KiB).
            let bulk_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let bulk_port = bulk_listener.local_addr().unwrap().port();
            let start_blast = Arc::new(tokio::sync::Notify::new());
            let blast_srv = Arc::clone(&start_blast);
            tokio::spawn(async move {
                if let Ok((mut sock, _)) = bulk_listener.accept().await {
                    blast_srv.notified().await;
                    let _ = sock.write_all(&vec![b'Z'; 512 * 1024]).await;
                    let _ = sock.shutdown().await;
                }
            });

            // Part B: Combined TX + RX byte cap (`12 KiB` TX + `12 KiB` RX > `20 KiB` cap -> EDQUOT).
            let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let echo_port = echo_listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                if let Ok((mut sock, _)) = echo_listener.accept().await {
                    let mut buf = vec![0u8; 16 * 1024];
                    if let Ok(n) = sock.read(&mut buf).await {
                        let _ = sock.write_all(&buf[..n]).await;
                    }
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            });

            let mut h = Harness::new(loopback_config(
                &[bulk_port, echo_port],
                NetQuota::default(),
            ))
            .await;
            let (s1, _, _, mut rx1, resp1) =
                h.open_stream("127.0.0.1", bulk_port, TlsMode::Off).await;
            assert!(matches!(resp1, HostNetResp::Opened { .. }));

            // Attempt to inflate window with Credit(u32::MAX) BEFORE server sends 512 KiB.
            h.send_data_frame(s1, &DataFrame::Credit(u32::MAX));
            h.pump_once().await;
            start_blast.notify_waiters();
            let mut got = 0usize;
            while got < NET_INITIAL_WINDOW_BYTES as usize {
                match h.recv_data_frame(s1, &mut rx1).await.expect("frame") {
                    DataFrame::Data(chunk) => got += chunk.len(),
                    other => panic!("unexpected frame: {other:?}"),
                }
            }
            assert_eq!(got, NET_INITIAL_WINDOW_BYTES as usize);
            // Must stall at 64 KiB (no extra Data frames delivered without further Credit!).
            for _ in 0..8 {
                tokio::time::sleep(Duration::from_millis(15)).await;
                h.tick();
                match h.socks.recvmsg(NETD_PID, s1, 32 * 1024, 0, 0, None) {
                    Ok(r) => rx1.extend_from_slice(&r.data),
                    Err(Errno::EAGAIN) => {}
                    Err(e) => panic!("unexpected recv err: {e:?}"),
                }
                assert!(
                    try_decode_unix_data_frame(&rx1).unwrap().is_none(),
                    "Credit(u32::MAX) must remain clamped to NET_INITIAL_WINDOW_BYTES"
                );
            }
            h.send_data_frame(s1, &DataFrame::Cancel);
            h.pump_once().await;

            // Part B: Combined TX + RX limit (`max_bytes_per_stream = 20 KiB`, 12 KiB TX + 12 KiB RX).
            let quota2 = NetQuota {
                max_bytes_per_stream: 20 * 1024,
                ..NetQuota::default()
            };
            let mut h2 = Harness::new(loopback_config(&[echo_port], quota2)).await;
            let (s2, _, _, mut rx2, resp2) =
                h2.open_stream("127.0.0.1", echo_port, TlsMode::Off).await;
            assert!(matches!(resp2, HostNetResp::Opened { .. }));
            h2.send_data_frame(s2, &DataFrame::Data(vec![b'Q'; 12 * 1024]));
            let mut saw_edquot = false;
            while let Some(frame) = h2.recv_data_frame(s2, &mut rx2).await {
                if let DataFrame::Closed(cl) = frame {
                    assert_eq!(cl.errno, Some(Errno::EDQUOT));
                    saw_edquot = true;
                    break;
                }
            }
            assert!(
                saw_edquot,
                "combined TX + RX must trip max_bytes_per_stream EDQUOT"
            );
        })
        .await;
}

/// Build a Wasm guest that executes the full WASIX outbound TCP lifecycle:
/// `sock_open(INET4, STREAM, TCP)` -> `sock_connect(127.0.0.1:port)` ->
/// `sock_send(payload)` -> `sock_shutdown(SHUT_WR)` -> `sock_recv(MSG_WAITALL)` -> `proc_exit(0)`.
fn wasm_wasix_tcp_echo_guest() -> Vec<u8> {
    let mut wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    // Types:
    // 0: (i32) -> ()                      proc_exit
    // 1: (i32, i32, i32, i32) -> (i32)    sock_open
    // 2: (i32, i32) -> (i32)              sock_connect, sock_shutdown
    // 3: (i32, i32, i32, i32, i32) -> (i32)         sock_send
    // 4: (i32, i32, i32, i32, i32, i32) -> (i32)    sock_recv
    // 5: () -> ()                         _start
    push_sec(
        &mut wasm,
        1,
        &[
            6, 0x60, 1, 0x7f, 0, 0x60, 4, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f, 0x60, 2, 0x7f, 0x7f, 1,
            0x7f, 0x60, 5, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f, 0x60, 6, 0x7f, 0x7f, 0x7f, 0x7f,
            0x7f, 0x7f, 1, 0x7f, 0x60, 0, 0,
        ],
    );
    let imports = [
        ("wasi_snapshot_preview1", "proc_exit", 0u8),
        ("wasix_32v1", "sock_open", 1),
        ("wasix_32v1", "sock_connect", 2),
        ("wasi_snapshot_preview1", "sock_send", 3),
        ("wasi_snapshot_preview1", "sock_shutdown", 2),
        ("wasi_snapshot_preview1", "sock_recv", 4),
    ];
    let mut imp = vec![imports.len() as u8];
    for (m, n, ty) in imports {
        enc_str(m, &mut imp);
        enc_str(n, &mut imp);
        imp.push(0x00);
        imp.push(ty);
    }
    push_sec(&mut wasm, 2, &imp);
    push_sec(&mut wasm, 3, &[1, 5]);
    push_sec(&mut wasm, 5, &[1, 0x00, 1]);
    let mut exp = vec![2];
    enc_str("memory", &mut exp);
    exp.extend_from_slice(&[0x02, 0]);
    enc_str("_start", &mut exp);
    exp.extend_from_slice(&[0x00, 6]);
    push_sec(&mut wasm, 7, &exp);

    let mut body = vec![1, 1, 0x7f]; // local 0: fd (i32)
    let i32c = |v: i32, b: &mut Vec<u8>| {
        b.push(0x41);
        enc_sleb(v, b);
    };
    let assert_zero = |code: i32, b: &mut Vec<u8>| {
        b.push(0x04); // if (err != 0)
        b.push(0x40);
        i32c(code, b);
        b.push(0x10);
        b.push(0); // proc_exit(code)
        b.push(0x0b);
    };

    // 1. sock_open(INET4=1, STREAM=2, TCP=6, ro_fd=0x100)
    i32c(1, &mut body);
    i32c(2, &mut body);
    i32c(6, &mut body);
    i32c(0x100, &mut body);
    body.extend_from_slice(&[0x10, 1]);
    assert_zero(1, &mut body);
    // local.0 = i32.load(0x100)
    i32c(0x100, &mut body);
    body.extend_from_slice(&[0x28, 0x02, 0x00, 0x21, 0x00]);

    // 2. sock_connect(fd, addr_ptr=0x200)
    body.extend_from_slice(&[0x20, 0x00]);
    i32c(0x200, &mut body);
    body.extend_from_slice(&[0x10, 2]);
    assert_zero(2, &mut body);

    // 3. sock_send(fd, iovs=0x240, iovs_len=1, flags=0, ro_len=0x104)
    body.extend_from_slice(&[0x20, 0x00]);
    i32c(0x240, &mut body);
    i32c(1, &mut body);
    i32c(0, &mut body);
    i32c(0x104, &mut body);
    body.extend_from_slice(&[0x10, 3]);
    assert_zero(3, &mut body);

    // 4. sock_shutdown(fd, SD_WR=2)
    body.extend_from_slice(&[0x20, 0x00]);
    i32c(2, &mut body);
    body.extend_from_slice(&[0x10, 4]);
    assert_zero(4, &mut body);

    // 5. sock_recv(fd, iovs=0x250, iovs_len=1, flags=WAITALL(2), ro_len=0x108, ro_flags=0x10c)
    body.extend_from_slice(&[0x20, 0x00]);
    i32c(0x250, &mut body);
    i32c(1, &mut body);
    i32c(2, &mut body);
    i32c(0x108, &mut body);
    i32c(0x10c, &mut body);
    body.extend_from_slice(&[0x10, 5]);
    assert_zero(5, &mut body);

    // proc_exit(0)
    i32c(0, &mut body);
    body.extend_from_slice(&[0x10, 0, 0x0b]);

    let mut code = vec![1];
    enc_uleb(body.len() as u32, &mut code);
    code.extend_from_slice(&body);
    push_sec(&mut wasm, 10, &code);
    wasm
}

#[tokio::test]
async fn nt07_wasix_tcp_outbound_echo_end_to_end() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                if let Ok((mut sock, _)) = listener.accept().await {
                    let mut buf = Vec::new();
                    let _ = sock.read_to_end(&mut buf).await;
                    let _ = sock.write_all(&buf).await;
                    let _ = sock.shutdown().await;
                }
            });

            let mut h = Harness::new(loopback_config(&[port], NetQuota::default())).await;
            // Bind `/run/netd.sock` inside VFS + UnixSocketTable for the in-process netd relay.
            let netd_cred = PeerCred {
                pid: NETD_PID,
                uid: 0,
                gid: 0,
            };
            let netd_listener = h
                .socks
                .create(NETD_PID, SockType::Stream, netd_cred)
                .expect("netd listener");
            let entry = h
                .vfs
                .mksockat(1, StartAnchor::Root, NETD_SOCK, 0o666)
                .await
                .expect("mksock /run/netd.sock");
            h.socks
                .bind(
                    NETD_PID,
                    netd_listener,
                    SocketInodeKey {
                        fs_id: entry.handle.fs.clone(),
                        node: entry.handle.node,
                    },
                    NETD_SOCK.into(),
                )
                .expect("bind /run/netd.sock");
            h.socks
                .listen(NETD_PID, netd_listener, 16, netd_cred)
                .expect("listen /run/netd.sock");

            let (tx, mut rx) = mpsc::unbounded_channel::<KernelCmd>();
            let wake = WakeBus::new();
            let kernel = KernelClient {
                tx,
                wake: wake.clone(),
                ptys: PtyTable::new(Arc::new(|_, _| {}), Arc::new(|_, _, _| {})),
            };
            let payload = b"wasix-tcp-e2e-echo-ok!";
            let target_sa = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
            let encoded_addr = encode_wasix_addr_port(target_sa);

            // Run the Wasmtime guest on a worker thread so blocking `KernelClient::call_sync`
            // exchanges commands cleanly with our LocalSet kernel + netd + NetdHostServer loop.
            let guest_handle = std::thread::spawn(move || -> Vec<u8> {
                let runtime = WasmRuntime::new().expect("wasmtime runtime");
                let mut linker = wasmtime::Linker::new(&runtime.engine);
                linker.allow_shadowing(true);
                os_native::wasi_host::register_all(&mut linker).expect("register_all");
                let host = ProcessHost {
                    pid: CLIENT_PID,
                    argv: vec!["wasix-echo".into()],
                    env: vec![],
                    umask: 0o022,
                    fds: BTreeMap::new(),
                    signals: ProcessSignals::new(SignalControl::new(), None, false),
                    sys_reply: Vec::new(),
                    main_mem: None,
                    asyncify: Default::default(),
                    snapshots: Default::default(),
                    next_snapshot_id: 1,
                    kernel,
                    runtime: Arc::clone(&runtime),
                    limiter: StoreMemoryLimiter {
                        limit_bytes: None,
                        linear_bytes: 0,
                        grow_reserved: 0,
                    },
                    boot_instant: Instant::now(),
                    in_signal_dispatch: false,
                    sig_callback_fn: None,
                    instance_exports: None,
                    cancel_flag: None,
                };
                let wasm = wasm_wasix_tcp_echo_guest();
                let module =
                    wasmtime::Module::new(&runtime.engine, &wasm).expect("compile echo guest");
                let mut store = wasmtime::Store::new(&runtime.engine, host);
                store.set_epoch_deadline(u64::MAX / 2);
                let instance = linker
                    .instantiate(&mut store, &module)
                    .expect("instantiate echo guest");
                let mem = instance
                    .get_memory(&mut store, "memory")
                    .expect("guest memory");
                // Populate linear memory: 0x200 = AddrPort, 0x240 = tx iov -> 0x280, 0x250 = rx iov -> 0x300
                let data = mem.data_mut(&mut store);
                data[0x200..0x200 + encoded_addr.len()].copy_from_slice(&encoded_addr);
                data[0x280..0x280 + payload.len()].copy_from_slice(payload);
                data[0x240..0x244].copy_from_slice(&(0x280u32).to_le_bytes());
                data[0x244..0x248].copy_from_slice(&(payload.len() as u32).to_le_bytes());
                data[0x250..0x254].copy_from_slice(&(0x300u32).to_le_bytes());
                data[0x254..0x258].copy_from_slice(&(64u32).to_le_bytes());

                store.data_mut().main_mem = Some(GuestMem::Regular(mem));
                let start = instance
                    .get_typed_func::<(), ()>(&mut store, "_start")
                    .expect("_start");
                let err = start
                    .call(&mut store, ())
                    .expect_err("guest calls proc_exit");
                let cf = err
                    .downcast_ref::<os_native::proc_runner::GuestControlFlow>()
                    .unwrap_or_else(|| panic!("expected GuestControlFlow, got {err:?}"));
                match cf {
                    os_native::proc_runner::GuestControlFlow::Exit { code, signal } => {
                        assert_eq!(*signal, None);
                        assert_eq!(*code, 0, "WASIX echo guest failed at step {code}");
                    }
                    other => panic!("unexpected GuestControlFlow: {other:?}"),
                }
                let data = mem.data(&store);
                let nread = u32::from_le_bytes(data[0x108..0x10c].try_into().unwrap()) as usize;
                data[0x300..0x300 + nread].to_vec()
            });

            // Drive KernelCmds + minimal `/run/netd.sock` -> `/run/net/host.sock` Raw relay until guest finishes!
            struct NetdSession {
                client_sid: SockId,
                host_sid: Option<SockId>,
                client_rx: Vec<u8>,
                host_rx: Vec<u8>,
                streaming: bool,
                client_eof: bool,
            }
            let mut session: Option<NetdSession> = None;
            let client_cred = PeerCred {
                pid: CLIENT_PID,
                uid: 1000,
                gid: 1000,
            };
            let deadline = Instant::now() + Duration::from_secs(10);

            while !guest_handle.is_finished() {
                assert!(Instant::now() < deadline, "WASIX E2E echo timed out");
                while let Ok(cmd) = rx.try_recv() {
                    match cmd {
                        KernelCmd::SockCreate {
                            pid,
                            sock_type,
                            nonblock,
                            reply,
                        } => {
                            let st = match sock_type {
                                2 => SockType::Dgram,
                                5 => SockType::Seqpacket,
                                _ => SockType::Stream,
                            };
                            let res = h.socks.create(pid, st, client_cred).map(|id| {
                                let _ = h.socks.set_nonblock(pid, id, nonblock);
                                u64::from(id)
                            });
                            let _ = reply.send(res);
                        }
                        KernelCmd::SockConnect {
                            pid,
                            sock_id,
                            path,
                            reply,
                        } => {
                            let res = match h
                                .vfs
                                .resolve_socket_inode(1, StartAnchor::Root, &path)
                                .await
                            {
                                Ok(entry) => {
                                    let key = SocketInodeKey {
                                        fs_id: entry.handle.fs.clone(),
                                        node: entry.handle.node,
                                    };
                                    h.socks
                                        .connect(pid, sock_id as SockId, &key, path, client_cred)
                                        .map(|_| netd_cred)
                                }
                                Err(e) => Err(e),
                            };
                            let _ = reply.send(res);
                        }
                        KernelCmd::SockSendMsg {
                            pid,
                            sock_id,
                            data,
                            flags,
                            reply,
                            ..
                        } => {
                            let res = h
                                .socks
                                .sendmsg(
                                    pid,
                                    sock_id as SockId,
                                    &data,
                                    Vec::new(),
                                    None,
                                    client_cred,
                                    None,
                                )
                                .map(|o| o.sent);
                            let _ = flags;
                            let _ = reply.send(res);
                        }
                        KernelCmd::SockRecvMsg {
                            pid,
                            sock_id,
                            max_bytes,
                            flags,
                            reply,
                            ..
                        } => {
                            let res = h
                                .socks
                                .recvmsg(pid, sock_id as SockId, max_bytes, 0, flags, None)
                                .map(|r| SockRecvReply {
                                    reported_len: r.data.len(),
                                    data: r.data,
                                    fds: Vec::new(),
                                    peer_cred: r.peer_cred,
                                    out_flags: r.out_flags,
                                });
                            let _ = reply.send(res);
                        }
                        KernelCmd::SockShutdown {
                            pid,
                            sock_id,
                            how,
                            reply,
                        } => {
                            let _ = reply
                                .send(h.socks.shutdown(pid, sock_id as SockId, how).map(|_| ()));
                        }
                        KernelCmd::SockSetNonblock {
                            pid,
                            sock_id,
                            nonblock,
                            reply,
                        } => {
                            let _ = reply.send(
                                h.socks
                                    .set_nonblock(pid, sock_id as SockId, nonblock)
                                    .map(|_| ()),
                            );
                        }
                        KernelCmd::SockClose {
                            pid,
                            sock_id,
                            reply,
                        } => {
                            let _ = h.socks.close(pid, sock_id as SockId, 1);
                            let _ = reply.send(Ok(()));
                        }
                        _ => {}
                    }
                    wake.notify();
                }

                // Accept `/run/netd.sock` connection from guest `wasi_host`.
                if session.is_none()
                    && let Ok(acc) = h.socks.accept(NETD_PID, netd_listener, netd_cred)
                {
                    session = Some(NetdSession {
                        client_sid: acc.sock_id,
                        host_sid: None,
                        client_rx: Vec::new(),
                        host_rx: Vec::new(),
                        streaming: false,
                        client_eof: false,
                    });
                }

                // Pump in-process netd session <-> `NetdHostServer` on `/run/net/host.sock`.
                if let Some(s) = session.as_mut() {
                    if !s.streaming {
                        if let Ok(r) = h.socks.recvmsg(NETD_PID, s.client_sid, 4096, 0, 0, None)
                            && !r.data.is_empty()
                        {
                            s.client_rx.extend_from_slice(&r.data);
                        }
                        if s.host_sid.is_none() && s.client_rx.len() >= 4 {
                            let len =
                                u32::from_be_bytes(s.client_rx[..4].try_into().unwrap()) as usize;
                            if s.client_rx.len() >= 4 + len {
                                let req: NetdReq =
                                    decode_control_payload(&s.client_rx[4..4 + len]).unwrap();
                                s.client_rx.drain(..4 + len);
                                match req {
                                    NetdReq::Hello { .. } => {
                                        let frame = encode_control_frame(&NetdResp::Welcome {
                                            version: NETD_VERSION,
                                            max_chunk: NET_DATA_CHUNK_MAX,
                                            initial_window: NET_INITIAL_WINDOW_BYTES,
                                        })
                                        .unwrap();
                                        let _ = h.socks.sendmsg(
                                            NETD_PID,
                                            s.client_sid,
                                            &frame,
                                            Vec::new(),
                                            None,
                                            netd_cred,
                                            None,
                                        );
                                        wake.notify();
                                    }
                                    NetdReq::Connect {
                                        host, port, tls, ..
                                    } => {
                                        let hsid = h.connect_host_as(NETD_PID, 0).await;
                                        h.send_ctrl(
                                            NETD_PID,
                                            0,
                                            hsid,
                                            &HostNetReq::Open {
                                                host,
                                                port,
                                                tls,
                                                timeout_ms: Some(3000),
                                            },
                                            Some(s.client_sid),
                                        );
                                        s.host_sid = Some(hsid);
                                    }
                                    _ => {}
                                }
                            }
                        }
                        if let Some(hsid) = s.host_sid {
                            if let Ok(r) = h.socks.recvmsg(NETD_PID, hsid, 4096, 0, 0, None)
                                && !r.data.is_empty()
                            {
                                s.host_rx.extend_from_slice(&r.data);
                            }
                            if s.host_rx.len() >= 4 {
                                let len =
                                    u32::from_be_bytes(s.host_rx[..4].try_into().unwrap()) as usize;
                                if s.host_rx.len() >= 4 + len {
                                    let resp: HostNetResp =
                                        decode_control_payload(&s.host_rx[4..4 + len]).unwrap();
                                    s.host_rx.drain(..4 + len);
                                    if let HostNetResp::Opened {
                                        stream_id,
                                        peer_addr,
                                        initial_window,
                                        quota,
                                    } = resp
                                    {
                                        let frame = encode_control_frame(&NetdResp::Connected {
                                            stream_id,
                                            peer_addr,
                                            mode: StreamMode::Raw,
                                            initial_window,
                                            quota,
                                        })
                                        .unwrap();
                                        let _ = h.socks.sendmsg(
                                            NETD_PID,
                                            s.client_sid,
                                            &frame,
                                            Vec::new(),
                                            None,
                                            netd_cred,
                                            None,
                                        );
                                        s.streaming = true;
                                        wake.notify();
                                    }
                                }
                            }
                        }
                    } else if let Some(hsid) = s.host_sid {
                        // Raw relay: client -> host Data/HalfClose
                        if !s.client_eof {
                            match h.socks.recvmsg(NETD_PID, s.client_sid, 4096, 0, 0, None) {
                                Ok(r) if r.data.is_empty() => {
                                    s.client_eof = true;
                                    let enc =
                                        encode_unix_data_frame(&DataFrame::HalfClose).unwrap();
                                    let _ = h.socks.sendmsg(
                                        NETD_PID,
                                        hsid,
                                        &enc,
                                        Vec::new(),
                                        None,
                                        netd_cred,
                                        None,
                                    );
                                }
                                Ok(r) => {
                                    let enc =
                                        encode_unix_data_frame(&DataFrame::Data(r.data)).unwrap();
                                    let _ = h.socks.sendmsg(
                                        NETD_PID,
                                        hsid,
                                        &enc,
                                        Vec::new(),
                                        None,
                                        netd_cred,
                                        None,
                                    );
                                }
                                _ => {}
                            }
                        }
                        // Raw relay: host Data/HalfClose -> client
                        if let Ok(r) = h.socks.recvmsg(NETD_PID, hsid, 4096, 0, 0, None)
                            && !r.data.is_empty()
                        {
                            s.host_rx.extend_from_slice(&r.data);
                        }
                        while let Ok(Some((frame, used))) = try_decode_unix_data_frame(&s.host_rx) {
                            s.host_rx.drain(..used);
                            match frame {
                                DataFrame::Data(bytes) => {
                                    let _ = h.socks.sendmsg(
                                        NETD_PID,
                                        s.client_sid,
                                        &bytes,
                                        Vec::new(),
                                        None,
                                        netd_cred,
                                        None,
                                    );
                                    wake.notify();
                                }
                                DataFrame::HalfClose | DataFrame::Closed(_) => {
                                    let _ = h.socks.shutdown(NETD_PID, s.client_sid, SHUT_WR);
                                    wake.notify();
                                }
                                _ => {}
                            }
                        }
                    }
                }
                h.pump_once().await;
            }

            let echoed = guest_handle.join().expect("guest thread panicked");
            assert_eq!(echoed, payload);
        })
        .await;
}

#[tokio::test]
async fn p01_reexec_and_authenticated_login_preserve_native_net_policy() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                while let Ok((mut sock, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let _ = sock.shutdown().await;
                    });
                }
            });

            let mut h = Harness::new(loopback_config(&[port], NetQuota::default())).await;

            // 1. `os-native` reexec with `cloud_access: false` must NOT poison `allowed_remote_scope`!
            h.procs
                .borrow_mut()
                .reexec(
                    "native-test",
                    CLIENT_PID,
                    ReexecSpec {
                        path: "/usr/bin/netctl".into(),
                        argv: vec!["netctl".into()],
                        env: vec![],
                        cwd: None,
                        runtime: None,
                        cloud_access: false,
                        new_remote: None,
                    },
                    1_700_000_010,
                )
                .expect("reexec client");
            let (_, _, _, _, resp1) = h.open_stream("127.0.0.1", port, TlsMode::Off).await;
            assert!(
                matches!(resp1, HostNetResp::Opened { .. }),
                "expected Opened after os-native reexec(cloud_access: false), got {resp1:?}"
            );

            // 2. Authenticated login/sudo (`set_authenticated_cred`) must ALSO keep `--net-policy` working!
            let new_uid = 2000;
            h.procs
                .borrow_mut()
                .set_authenticated_cred(
                    "native-test",
                    CLIENT_PID,
                    Identity {
                        id: new_uid,
                        group: new_uid,
                        groups: BTreeSet::from([new_uid]),
                    },
                    None,
                )
                .expect("set_authenticated_cred");
            let host_sid = h.connect_host_as(NETD_PID, 0).await;
            let bob_cred = PeerCred {
                pid: CLIENT_PID,
                uid: new_uid,
                gid: new_uid,
            };
            let pair = h
                .socks
                .socketpair(CLIENT_PID, SockType::Stream, bob_cred)
                .expect("bob pair");
            h.send_ctrl(
                NETD_PID,
                0,
                host_sid,
                &HostNetReq::Open {
                    host: "127.0.0.1".into(),
                    port,
                    tls: TlsMode::Off,
                    timeout_ms: Some(3000),
                },
                Some(pair.sock_b),
            );
            let mut rx = Vec::new();
            let resp2 = h.recv_ctrl_resp(NETD_PID, host_sid, &mut rx).await;
            assert!(
                matches!(resp2, HostNetResp::Opened { .. }),
                "expected Opened after set_authenticated_cred, got {resp2:?}"
            );
        })
        .await;
}

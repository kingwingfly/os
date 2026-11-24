//! NAT-05: Authenticated `HostAdapter v2` remote seat/PTY tests (Unix `0600`, TCP, WebSocket,
//! protocol mismatch `EPROTONOSUPPORT`, auth rejection `EACCES`, 2-client shared PTY + resize,
//! detach/reattach scrollback replay, and immediate live token revocation without harming OS procs).

mod common;

use abi::contract::Boundary;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use common::{TempDir, boot_host};
use os_native::{
    ClientFrame, ControlReply, ControlRequest, SeatClient, SeatServerConfig, SeatServerHandle,
    ServerFrame, send_control_request,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::{Duration, Instant};

async fn read_until_contains(
    client: &mut SeatClient,
    needle: &str,
    timeout: Duration,
) -> Result<String, String> {
    let mut acc = String::new();
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let rem = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(rem, client.recv()).await {
            Ok(Ok(Some(ServerFrame::Output { data_b64, .. }))) => {
                if let Ok(bytes) = B64.decode(&data_b64) {
                    acc.push_str(&String::from_utf8_lossy(&bytes));
                    if acc.contains(needle) {
                        return Ok(acc);
                    }
                }
            }
            Ok(Ok(Some(ServerFrame::Error { errno, message, .. }))) => {
                return Err(format!("server error {errno}: {message} (seen={acc:?})"));
            }
            Ok(Ok(None)) => return Err(format!("eof before {needle:?} (seen={acc:?})")),
            Ok(Err(e)) => return Err(format!("recv error: {e} (seen={acc:?})")),
            Err(_) => break,
            Ok(Ok(Some(_))) => {}
        }
    }
    Err(format!("timed out waiting for {needle:?}; seen={acc:?}"))
}

#[test]
#[ignore = "requires signed Release v2 bundle; run with OS_NATIVE_TEST_BUNDLE=<dir> cargo test -p os-native -- --ignored --test-threads=1"]
fn nat05_remote_seat_handshake_auth_shared_pty_and_live_revocation() {
    let state = TempDir::new("nat05");
    let host = Arc::new(boot_host(state.path(), true));

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let mut cfg = SeatServerConfig::default_for(state.path().to_path_buf());
        cfg.tcp_listen = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
        let server = SeatServerHandle::start(Arc::clone(&host), cfg)
            .await
            .expect("start seat server");

        let tcp_addr = server.tcp_addr.expect("tcp bound");
        let tcp_target = format!("tcp://{tcp_addr}");
        let ws_target = format!("ws://{tcp_addr}/seat");
        let unix_target = format!(
            "unix://{}",
            server.unix_seat_path.as_ref().unwrap().display()
        );

        // Verify socket permissions are strictly 0600.
        let ctl_mode = std::fs::metadata(&server.ctl_sock_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(ctl_mode, 0o600, "host-ctl.sock must be 0600");
        let seat_mode = std::fs::metadata(server.unix_seat_path.as_ref().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(seat_mode, 0o600, "seat.sock must be 0600");

        // 1. Handshake version mismatch (HostAdapter v1) -> EPROTONOSUPPORT.
        {
            let mut c = SeatClient::connect(&tcp_target).await.unwrap();
            c.send(&ClientFrame::Hello {
                boundary: Boundary::HostAdapter,
                versions: vec![1],
            })
            .await
            .unwrap();
            match c.recv().await.unwrap() {
                Some(ServerFrame::Error { errno, .. }) => assert_eq!(errno, "EPROTONOSUPPORT"),
                other => panic!("expected EPROTONOSUPPORT, got {other:?}"),
            }
        }

        // 2. Wrong boundary (Syscall v2) -> EPROTONOSUPPORT (tested over WebSocket!).
        {
            let mut c = SeatClient::connect(&ws_target).await.unwrap();
            c.send(&ClientFrame::Hello {
                boundary: Boundary::Syscall,
                versions: vec![2],
            })
            .await
            .unwrap();
            match c.recv().await.unwrap() {
                Some(ServerFrame::Error { errno, .. }) => assert_eq!(errno, "EPROTONOSUPPORT"),
                other => panic!("expected EPROTONOSUPPORT on ws, got {other:?}"),
            }
        }

        // 3. Unauthenticated attach & bad token -> EACCES.
        {
            let mut c = SeatClient::connect(&unix_target).await.unwrap();
            c.send(&ClientFrame::Hello {
                boundary: Boundary::HostAdapter,
                versions: vec![2],
            })
            .await
            .unwrap();
            assert!(matches!(
                c.recv().await.unwrap(),
                Some(ServerFrame::HelloOk { .. })
            ));
            c.send(&ClientFrame::Attach {
                seat: Some(0),
                spawn_if_missing: false,
                cols: None,
                rows: None,
            })
            .await
            .unwrap();
            match c.recv().await.unwrap() {
                Some(ServerFrame::Error { errno, .. }) => assert_eq!(errno, "EACCES"),
                other => panic!("expected EACCES on unauthed attach, got {other:?}"),
            }
        }
        {
            let mut c = SeatClient::connect(&tcp_target).await.unwrap();
            let err = c
                .handshake_and_auth(
                    "osnt_0000000000000000000000000000000000000000000000000000000000000000",
                )
                .await
                .unwrap_err();
            assert!(err.contains("EACCES"), "expected EACCES, got {err}");
        }

        // 4. Create 3 tokens via `$STATE/host-ctl.sock`: tokA (WS), tokB (TCP), tokExpired (ttl=0).
        let (tok_a_id, tok_a_secret) = match send_control_request(
            state.path(),
            ControlRequest::CreateToken {
                uid: 0,
                label: "client-a".into(),
                allowed_seats: vec![0],
                can_exec: true,
                ttl_secs: Some(3600),
            },
        )
        .await
        .unwrap()
        {
            ControlReply::TokenCreated { record, token } => (record.id, token),
            other => panic!("unexpected reply: {other:?}"),
        };
        let (_tok_b_id, tok_b_secret) = match send_control_request(
            state.path(),
            ControlRequest::CreateToken {
                uid: 0,
                label: "client-b".into(),
                allowed_seats: vec![0],
                can_exec: true,
                ttl_secs: Some(3600),
            },
        )
        .await
        .unwrap()
        {
            ControlReply::TokenCreated { record, token } => (record.id, token),
            other => panic!("unexpected reply: {other:?}"),
        };
        let (_tok_exp_id, tok_exp_secret) = match send_control_request(
            state.path(),
            ControlRequest::CreateToken {
                uid: 0,
                label: "expired".into(),
                allowed_seats: vec![0],
                can_exec: false,
                ttl_secs: Some(0),
            },
        )
        .await
        .unwrap()
        {
            ControlReply::TokenCreated { record, token } => (record.id, token),
            other => panic!("unexpected reply: {other:?}"),
        };

        // Token file must be 0600 and MUST NOT contain plaintext secret!
        let tok_file_path = state.path().join("seat-tokens.json");
        let tok_file_mode = std::fs::metadata(&tok_file_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(tok_file_mode, 0o600, "seat-tokens.json must be 0600");
        let tok_file_raw = std::fs::read_to_string(&tok_file_path).unwrap();
        assert!(
            !tok_file_raw.contains(&tok_a_secret),
            "plaintext secret must never be persisted"
        );

        // Expired token must fail EACCES.
        {
            let mut c = SeatClient::connect(&tcp_target).await.unwrap();
            let err = c.handshake_and_auth(&tok_exp_secret).await.unwrap_err();
            assert!(
                err.contains("EACCES"),
                "expired token should fail EACCES: {err}"
            );
        }

        // 5. Two clients (Client A over WebSocket, Client B over TCP) attach concurrently to PTY 0.
        let mut client_a = SeatClient::connect(&ws_target).await.unwrap();
        client_a.handshake_and_auth(&tok_a_secret).await.unwrap();
        client_a
            .send(&ClientFrame::Attach {
                seat: Some(0),
                spawn_if_missing: false,
                cols: Some(100),
                rows: Some(30),
            })
            .await
            .unwrap();
        assert!(matches!(
            client_a.recv().await.unwrap(),
            Some(ServerFrame::Attached {
                seat: 0,
                cols: 100,
                rows: 30,
                ..
            })
        ));

        let mut client_b = SeatClient::connect(&tcp_target).await.unwrap();
        client_b.handshake_and_auth(&tok_b_secret).await.unwrap();
        client_b
            .send(&ClientFrame::Attach {
                seat: Some(0),
                spawn_if_missing: false,
                cols: None,
                rows: None,
            })
            .await
            .unwrap();
        assert!(matches!(
            client_b.recv().await.unwrap(),
            Some(ServerFrame::Attached { seat: 0, .. })
        ));

        // Client A sends a shell command -> BOTH Client A and Client B receive the output!
        client_a
            .send_input(b"echo SHARED_SEAT_MARKER_42\n")
            .await
            .unwrap();
        let out_a = read_until_contains(
            &mut client_a,
            "SHARED_SEAT_MARKER_42",
            Duration::from_secs(10),
        )
        .await
        .expect("client A output");
        let out_b = read_until_contains(
            &mut client_b,
            "SHARED_SEAT_MARKER_42",
            Duration::from_secs(10),
        )
        .await
        .expect("client B output");
        assert!(out_a.contains("SHARED_SEAT_MARKER_42"));
        assert!(out_b.contains("SHARED_SEAT_MARKER_42"));

        // Resize from Client A updates live PTY winsize!
        client_a.send_resize(132, 43).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let ws = host.console_pty.winsize();
        assert_eq!((ws.columns, ws.rows), (132, 43));

        // 6. Detach & reattach replays scrollback and keeps shell alive!
        client_a.send(&ClientFrame::Detach).await.unwrap();
        // Drain any stray output until Detached.
        loop {
            match tokio::time::timeout(Duration::from_secs(5), client_a.recv())
                .await
                .unwrap()
                .unwrap()
            {
                Some(ServerFrame::Detached { seat: 0 }) => break,
                Some(ServerFrame::Output { .. }) => continue,
                other => panic!("expected Detached, got {other:?}"),
            }
        }
        drop(client_a);

        // Reconnect Client A over Unix socket and check scrollback contains marker!
        let mut client_a2 = SeatClient::connect(&unix_target).await.unwrap();
        client_a2.handshake_and_auth(&tok_a_secret).await.unwrap();
        client_a2
            .send(&ClientFrame::Attach {
                seat: Some(0),
                spawn_if_missing: false,
                cols: None,
                rows: None,
            })
            .await
            .unwrap();
        match client_a2.recv().await.unwrap() {
            Some(ServerFrame::Attached {
                seat: 0,
                scrollback_b64,
                ..
            }) => {
                let sb =
                    String::from_utf8_lossy(&B64.decode(&scrollback_b64).unwrap()).into_owned();
                assert!(
                    sb.contains("SHARED_SEAT_MARKER_42"),
                    "scrollback missing marker: {sb:?}"
                );
            }
            other => panic!("expected Attached with scrollback, got {other:?}"),
        }

        // 7. Live token revocation via `$STATE/host-ctl.sock` immediately severs Client A2
        //    with EACCES while leaving Client B and the running shell process untouched!
        match send_control_request(
            state.path(),
            ControlRequest::RevokeToken {
                id_or_prefix: tok_a_id.clone(),
            },
        )
        .await
        .unwrap()
        {
            ControlReply::Revoked {
                token_ids,
                disconnected_clients,
            } => {
                assert_eq!(token_ids, vec![tok_a_id]);
                assert_eq!(disconnected_clients, 1);
            }
            other => panic!("unexpected revoke reply: {other:?}"),
        }

        // Client A2 MUST immediately receive EACCES and close!
        match tokio::time::timeout(Duration::from_secs(5), client_a2.recv())
            .await
            .unwrap()
            .unwrap()
        {
            Some(ServerFrame::Error { errno, message, .. }) => {
                assert_eq!(errno, "EACCES");
                assert!(message.contains("revoked"), "unexpected msg: {message}");
            }
            other => panic!("expected EACCES revoke error on active client, got {other:?}"),
        }

        // Reconnecting with revoked token MUST fail with EACCES.
        {
            let mut c = SeatClient::connect(&ws_target).await.unwrap();
            let err = c.handshake_and_auth(&tok_a_secret).await.unwrap_err();
            assert!(
                err.contains("EACCES"),
                "revoked token must be rejected: {err}"
            );
        }

        // Client B (different token) is still connected and PTY 0 shell is still alive!
        client_b
            .send_input(b"echo SHELL_SURVIVED_REVOKE_99\n")
            .await
            .unwrap();
        let out_b2 = read_until_contains(
            &mut client_b,
            "SHELL_SURVIVED_REVOKE_99",
            Duration::from_secs(10),
        )
        .await
        .expect("client B still alive after tokA revoke");
        assert!(out_b2.contains("SHELL_SURVIVED_REVOKE_99"));

        // Non-interactive `Exec` over authenticated seat works too.
        let mut exec_c = SeatClient::connect(&tcp_target).await.unwrap();
        exec_c.handshake_and_auth(&tok_b_secret).await.unwrap();
        exec_c
            .send(&ClientFrame::Exec {
                argv: vec!["/bin/sh".into(), "-c".into(), "echo EXEC_OK_77".into()],
                env: Vec::new(),
                cwd: Some("/".into()),
                stdin_b64: None,
                timeout_ms: Some(10_000),
            })
            .await
            .unwrap();
        match exec_c.recv().await.unwrap() {
            Some(ServerFrame::ExecResult {
                exit_code: 0,
                stdout_b64,
                ..
            }) => {
                let s = String::from_utf8(B64.decode(&stdout_b64).unwrap()).unwrap();
                assert_eq!(s.trim(), "EXEC_OK_77");
            }
            other => panic!("expected ExecResult exit 0, got {other:?}"),
        }

        server.stop();
    });

    assert!(host.shutdown_blocking().expect("clean shutdown"));
}

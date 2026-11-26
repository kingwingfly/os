//! Opt-in userspace `kubelet` service daemon (`/usr/bin/kubelet`, Phase 9.1b #84).
//!
//! Runs under PID 1 (`kubelet.service`, `enabled: false` by default). Speaks the strictly typed
//! `abi::kubelet_ctl` protocol over `/run/kubelet/host.sock` (`0600`, `SO_PEERCRED.uid == 0`),
//! reads optional `/etc/kubelet/config.json` & `/etc/kubelet/bootstrap-token`, notifies readiness
//! over `NOTIFY_SOCKET`, and cleanly drains/stops the host kubelet agent on `SIGTERM`/`SIGINT`.
//!
//! WASM32-WASIP1 SAFETY:
//! - NEVER calls `std::process::id()`.
//! - Sets `SA_RESTART` (`0x1000_0000`) on caught signals (`SIGTERM`, `SIGINT`, `SIGHUP`).

#[cfg(target_os = "wasi")]
mod runtime {
    use abi::Errno;
    use abi::kubelet_ctl::{
        KUBELET_CTL_VERSION, KUBELET_HOST_SOCK, KubeletHostReply, KubeletHostRequest,
        KubeletStatus, MAX_FRAME_BYTES, decode_payload, encode_frame,
    };
    use abi::socket::MSG_NOSIGNAL;
    use os_posix::socket::{UnixDatagram, UnixStream};
    use serde::Deserialize;
    use std::collections::BTreeMap;
    use std::fs;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    const SA_RESTART: u32 = 0x1000_0000;
    const CONFIG_PATH: &str = "/etc/kubelet/config.json";
    const BOOTSTRAP_PATH: &str = "/etc/kubelet/bootstrap-token";

    static STOP: AtomicU32 = AtomicU32::new(0);

    #[unsafe(no_mangle)]
    pub extern "C" fn __os_kubelet_signal(signal: u32) {
        if matches!(signal, 1 | 2 | 15) {
            let _ = STOP.compare_exchange(0, signal, Ordering::SeqCst, Ordering::SeqCst);
        }
    }

    #[link(wasm_import_module = "wasix_32v1")]
    unsafe extern "C" {
        fn callback_signal(name: *const u8, len: usize);
    }

    #[link(wasm_import_module = "os")]
    unsafe extern "C" {
        fn sigaction(signal: u32, kind: u32, mask: u32, flags: u32) -> i32;
    }

    #[derive(Clone, Debug, Default, Deserialize)]
    struct KubeletFileConfig {
        #[serde(default)]
        control_plane_url: Option<String>,
        #[serde(default)]
        cluster: Option<String>,
        #[serde(default)]
        node_id: Option<String>,
        #[serde(default)]
        lease_ttl_secs: Option<u64>,
        #[serde(default)]
        labels: BTreeMap<String, String>,
        #[serde(default)]
        bootstrap_token: Option<String>,
    }

    fn install_signals() -> Result<(), String> {
        let name = b"__os_kubelet_signal";
        // SAFETY: valid exported callback symbol and scalar signal numbers with SA_RESTART.
        unsafe {
            callback_signal(name.as_ptr(), name.len());
            let _ = sigaction(13, 1, 0, 0); // SIGPIPE -> SIG_IGN
            for sig in [1, 2, 15] {
                if sigaction(sig, 2, 0, SA_RESTART) < 0 {
                    return Err(format!("sigaction({sig}) failed"));
                }
            }
        }
        Ok(())
    }

    fn notify_systemd(payload: &str) {
        let Ok(sock_path) = std::env::var("NOTIFY_SOCKET") else {
            return;
        };
        if sock_path.is_empty() {
            return;
        }
        if let Ok(sock) = UnixDatagram::unbound() {
            let _ = sock.send_to(payload.as_bytes(), &sock_path);
        }
    }

    fn host_rpc(req: &KubeletHostRequest) -> Result<KubeletHostReply, String> {
        let stream = UnixStream::connect(KUBELET_HOST_SOCK)
            .map_err(|e| format!("connect {KUBELET_HOST_SOCK}: {}", e.text()))?;
        let peer = stream
            .peer_cred()
            .map_err(|e| format!("peer_cred: {}", e.text()))?;
        if peer.uid != 0 {
            return Err("kubelet host socket peer is not uid 0".into());
        }
        let frame = encode_frame(req).map_err(|e| e.to_string())?;
        let mut sent = 0usize;
        while sent < frame.len() {
            match stream.send(&frame[sent..], MSG_NOSIGNAL) {
                Ok(0) => return Err("host socket closed during send".into()),
                Ok(n) => sent += n,
                Err(Errno::EINTR) => continue,
                Err(Errno::EAGAIN) => std::thread::sleep(Duration::from_millis(5)),
                Err(e) => return Err(format!("send: {}", e.text())),
            }
        }
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        let mut expected_total: Option<usize> = None;
        for _ in 0..4000 {
            match stream.recv(&mut buf, 0) {
                Ok(0) => break,
                Ok(n) => {
                    raw.extend_from_slice(&buf[..n]);
                    if raw.len() > MAX_FRAME_BYTES + 4 {
                        return Err("host reply exceeds max frame size".into());
                    }
                    if expected_total.is_none() && raw.len() >= 4 {
                        let len = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
                        if len == 0 || len > MAX_FRAME_BYTES {
                            return Err("invalid kubelet host reply frame size".into());
                        }
                        expected_total = 4usize.checked_add(len);
                    }
                    if let Some(tot) = expected_total
                        && raw.len() >= tot
                    {
                        break;
                    }
                }
                Err(Errno::EINTR) => continue,
                Err(Errno::EAGAIN) => std::thread::sleep(Duration::from_millis(5)),
                Err(e) => return Err(format!("recv: {}", e.text())),
            }
        }
        if raw.len() < 4 {
            return Err("truncated kubelet host reply".into());
        }
        let len = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
        if raw.len() < 4 + len {
            return Err("incomplete kubelet host reply".into());
        }
        decode_payload::<KubeletHostReply>(&raw[4..4 + len])
            .map_err(|e| format!("decode reply: {e}"))
    }

    fn load_config() -> KubeletFileConfig {
        fs::read(CONFIG_PATH)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn read_bootstrap_token(cfg: &KubeletFileConfig) -> Option<(String, bool)> {
        if let Ok(raw) = fs::read_to_string(BOOTSTRAP_PATH) {
            let trimmed = raw.trim().to_string();
            if !trimmed.is_empty() {
                return Some((trimmed, true));
            }
        }
        if let Some(ref t) = cfg.bootstrap_token {
            let trimmed = t.trim().to_string();
            if !trimmed.is_empty() {
                return Some((trimmed, false));
            }
        }
        None
    }

    fn wait_for_host_socket() -> Result<(), String> {
        for _ in 0..100 {
            if STOP.load(Ordering::SeqCst) != 0 {
                return Ok(());
            }
            if let Ok(KubeletHostReply::Welcome { .. }) = host_rpc(&KubeletHostRequest::Hello {
                versions: vec![KUBELET_CTL_VERSION],
            }) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        Err(format!("timed out waiting for {KUBELET_HOST_SOCK}"))
    }

    fn try_enroll_and_start(cfg: &KubeletFileConfig) -> Result<KubeletStatus, String> {
        let mut status = match host_rpc(&KubeletHostRequest::Status {})? {
            KubeletHostReply::Status { status } => status,
            KubeletHostReply::Error { message, .. } => return Err(message),
            other => return Err(format!("unexpected status reply: {other:?}")),
        };
        if !status.enrolled
            && let Some((token, from_file)) = read_bootstrap_token(cfg)
        {
            match host_rpc(&KubeletHostRequest::Enroll {
                bootstrap_token: token,
                node_id: cfg.node_id.clone(),
                cluster: cfg.cluster.clone(),
                control_plane_url: cfg.control_plane_url.clone(),
                labels: cfg.labels.clone(),
            })? {
                KubeletHostReply::Enrolled {
                    node_id,
                    cluster,
                    tenant,
                    enrollment_id,
                    instance_id,
                } => {
                    status.enrolled = true;
                    status.state = "enrolled".into();
                    status.node_id = Some(node_id);
                    status.cluster = Some(cluster);
                    status.tenant = Some(tenant);
                    status.enrollment_id = Some(enrollment_id);
                    status.instance_id = Some(instance_id);
                    if from_file {
                        let _ = fs::remove_file(BOOTSTRAP_PATH);
                    }
                }
                KubeletHostReply::Error { message, .. } => return Err(message),
                other => return Err(format!("unexpected enroll reply: {other:?}")),
            }
        }
        if status.enrolled && !status.running {
            match host_rpc(&KubeletHostRequest::Start {
                control_plane_url: cfg.control_plane_url.clone(),
                cluster: cfg.cluster.clone(),
                node_id: cfg.node_id.clone(),
                labels: cfg.labels.clone(),
                lease_ttl_secs: cfg.lease_ttl_secs,
            })? {
                KubeletHostReply::Started { status: st } => status = st,
                KubeletHostReply::Error { message, .. } => return Err(message),
                other => return Err(format!("unexpected start reply: {other:?}")),
            }
        }
        Ok(status)
    }

    pub fn run() -> Result<(), String> {
        os_posix::init_preopens().map_err(|e| e.to_string())?;
        install_signals()?;
        wait_for_host_socket()?;

        let cfg = load_config();
        let initial_status = match try_enroll_and_start(&cfg) {
            Ok(st) => st,
            Err(err) => {
                eprintln!("kubelet: initial sync warning: {err}");
                KubeletStatus {
                    state: "stopped".into(),
                    enrolled: false,
                    running: false,
                    last_error: Some(err),
                    ..KubeletStatus::default()
                }
            }
        };

        let status_line = if initial_status.running {
            format!(
                "READY=1\nSTATUS=kubelet active (node={})\n",
                initial_status.node_id.as_deref().unwrap_or("unknown")
            )
        } else {
            "READY=1\nSTATUS=kubelet ready (awaiting enrollment)\n".to_string()
        };
        notify_systemd(&status_line);

        let mut last_running = initial_status.running;
        while STOP.load(Ordering::SeqCst) == 0 {
            std::thread::sleep(Duration::from_millis(250));
            if STOP.load(Ordering::SeqCst) != 0 {
                break;
            }
            if !last_running {
                let fresh_cfg = load_config();
                if let Ok(st) = try_enroll_and_start(&fresh_cfg)
                    && st.running
                {
                    last_running = true;
                    notify_systemd(&format!(
                        "STATUS=kubelet active (node={})\n",
                        st.node_id.as_deref().unwrap_or("unknown")
                    ));
                }
            }
        }

        // Graceful drain & stop on SIGTERM/SIGINT.
        let _ = host_rpc(&KubeletHostRequest::Drain {});
        let _ = host_rpc(&KubeletHostRequest::Stop {});
        Ok(())
    }
}

fn main() {
    #[cfg(target_os = "wasi")]
    let result = runtime::run();
    #[cfg(not(target_os = "wasi"))]
    let result: Result<(), String> = Err("kubelet service requires the OS WASI runtime".into());
    if let Err(err) = result {
        eprintln!("kubelet: {err}");
        std::process::exit(1);
    }
}

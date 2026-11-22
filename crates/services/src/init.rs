//! PID 1 System Service Manager (`/usr/bin/init`) and Per-User Service Manager
//! (`/usr/bin/init --user [uid]`, `#57` `L3d`, Contract v2 §2.8, §2.15).
//!
//! - System PID 1 mode:
//!   - Loads built-in units from `/usr/lib/os/units/*.json` (fallback `default_system_units()`)
//!     plus overrides in `/etc/services/*.json`, instantiates `user-session@<default_uid>.service`
//!     and `devattach@{archive,media,present,snd}.service`.
//!   - Binds `/run/init/notify.sock` (`SOCK_DGRAM`, mode `0666`, strictly `SO_PEERCRED`-checked
//!     `cred.pid == unit.pid`) and `/run/init/control.sock` (`SOCK_STREAM`, mode `0666`, mutating
//!     operations strictly require kernel `SO_PEERCRED` `cred.uid == 0`).
//!   - Activates `multi-user.target` offline (optional `cloud.mount` / `cloud-online.target` never
//!     block boot), writes `/run/os/boot-healthy` on `MarkBootHealthy`, reaps all children via
//!     `waitpid2(-1, WNOHANG)`, and executes ordered reverse shutdown + unmount + `/run/os/shutdown`
//!     on `Poweroff`/`Reboot`/`SIGTERM`.
//! - Per-user mode (`--user [uid]`):
//!   - Runs strictly attenuated under `ServiceManager::new_user(uid, graph)` (non-root only),
//!     binds `/run/user/<uid>/notify.sock` & `/run/user/<uid>/manager.sock` (`0600`), verifies
//!     `SO_PEERCRED.uid == uid`, rejects `grant.user` elevation and `Poweroff`/`Reboot` with
//!     `EPERM`, and notifies PID 1 readiness over `NOTIFY_SOCKET`.
#[allow(dead_code)]
mod notify;

#[cfg(target_os = "wasi")]
mod runtime {
    use crate::notify::{Notification, notify_socket_ready};
    use abi::{Call, Creds, Errno};
    use os_posix::process::{
        Child, ServiceBindMount, ServiceGrant, SpawnOptions, Stdin, spawn_configured,
    };
    use os_posix::socket::{
        MSG_DONTWAIT, MSG_NOSIGNAL, SOCK_CLOEXEC, SOCK_NONBLOCK, UnixDatagram, UnixListener,
        UnixStream,
    };
    use os_services::control::{
        ControlResponse, MAX_CONTROL_FRAME_BYTES, MAX_NOTIFY_DATAGRAM_BYTES, PeerCred,
        SYSTEM_CONTROL_SOCKET, SYSTEM_NOTIFY_SOCKET, decode_request_frame, encode_response_frame,
        user_manager_socket,
    };
    use os_services::graph::{CLOUD_DEVICE_INSTANCES, UnitGraph, default_system_units};
    use os_services::manager::{ManagerAction, ServiceManager, ShutdownMode};
    use os_services::unit::UnitSpec;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    static REAP: AtomicBool = AtomicBool::new(true);
    static STOP: AtomicU32 = AtomicU32::new(0);

    #[unsafe(no_mangle)]
    pub extern "C" fn __os_init_signal(signal: u32) {
        if signal == 17 {
            REAP.store(true, Ordering::SeqCst);
        }
        if matches!(signal, 1 | 2 | 15) {
            let _ = STOP.compare_exchange(0, signal, Ordering::SeqCst, Ordering::SeqCst);
        }
    }

    #[link(wasm_import_module = "wasix_32v1")]
    unsafe extern "C" {
        fn callback_signal(name: *const u8, len: usize);
        fn proc_id(pid: *mut u32) -> u32;
    }

    #[link(wasm_import_module = "os")]
    unsafe extern "C" {
        fn sigaction(signal: u32, kind: u32, mask: u32, flags: u32) -> i32;
        fn waitpid2(pid: i32, status: *mut u32, options: u32) -> i32;
    }

    struct LiveUnit {
        child: Child,
        ready_pipe: Option<Notification>,
    }

    fn install_signals() -> Result<(), String> {
        let name = b"__os_init_signal";
        // SAFETY: valid static callback name and scalar signal dispositions.
        unsafe {
            callback_signal(name.as_ptr(), name.len());
            let _ = sigaction(13, 1, 0, 0); // SIGPIPE -> SIG_IGN
            for sig in [1, 2, 15, 17] {
                if sigaction(sig, 2, 0, 0x1000_0000) < 0 {
                    return Err(format!("cannot install signal handler for {sig}"));
                }
            }
        }
        Ok(())
    }

    fn ensure_dir_mode(path: &str, mode: u16) {
        let _ = fs::create_dir_all(path);
        let _ = os_posix::batch(&[Call::Chmod {
            path: path.to_owned(),
            mode,
        }]);
    }

    fn chmod_path(path: &str, mode: u16) {
        let _ = os_posix::batch(&[Call::Chmod {
            path: path.to_owned(),
            mode,
        }]);
    }

    fn current_creds() -> Result<Creds, String> {
        let mut reply = os_posix::batch(&[Call::Getcreds]).map_err(|e| e.to_string())?;
        let val = reply
            .results
            .remove(0)
            .into_result()
            .map_err(|e| e.to_string())?;
        serde_json::from_value(val).map_err(|e| format!("invalid getcreds reply: {e}"))
    }

    fn resolve_default_uid() -> u32 {
        let wanted_user = fs::read_to_string("/run/os/boot-profile.json")
            .ok()
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
            .and_then(|v| v["default_user"].as_str().map(str::to_owned))
            .unwrap_or_else(|| "user".to_owned());
        if wanted_user == "root" {
            return 0;
        }
        if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
            for line in passwd.lines() {
                let fields: Vec<&str> = line.split(':').collect();
                if fields.len() >= 3
                    && fields[0] == wanted_user
                    && let Ok(uid) = fields[2].parse::<u32>()
                {
                    return uid;
                }
            }
        }
        1000
    }

    fn load_units_from_dir(dir: &str, out: &mut BTreeMap<String, UnitSpec>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        let mut paths: Vec<_> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "json"))
            .collect();
        paths.sort();
        for path in paths {
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            if let Ok(spec) = UnitSpec::parse_json(&bytes) {
                out.insert(spec.name.clone(), spec);
            }
        }
    }

    fn load_system_graph(default_uid: u32) -> Result<UnitGraph, String> {
        let mut by_name = BTreeMap::new();
        for spec in default_system_units() {
            by_name.insert(spec.name.clone(), spec);
        }
        load_units_from_dir("/usr/lib/os/units", &mut by_name);
        load_units_from_dir("/etc/services", &mut by_name);

        let user_session =
            (default_uid != 0).then(|| format!("user-session@{default_uid}.service"));
        if let Some(ref us) = user_session
            && let Some(cloud_mount) = by_name.get_mut("cloud.mount")
            && !cloud_mount.after.contains(us)
        {
            cloud_mount.after.push(us.clone());
        }

        let mut graph =
            UnitGraph::build(by_name.into_values().collect()).map_err(|e| e.to_string())?;
        if let Some(ref us) = user_session {
            let _ = graph.instantiate_template(us);
        }
        for dev in CLOUD_DEVICE_INSTANCES {
            let _ = graph.instantiate_template(&format!("devattach@{dev}.service"));
        }
        Ok(graph)
    }

    fn load_user_graph(home: &str) -> Result<UnitGraph, String> {
        let mut by_name = BTreeMap::new();
        if !home.is_empty() {
            load_units_from_dir(&format!("{home}/.config/os/units"), &mut by_name);
        }
        UnitGraph::build(by_name.into_values().collect()).map_err(|e| e.to_string())
    }

    fn read_control_frame(stream: &UnixStream) -> Result<Vec<u8>, Errno> {
        let mut data = Vec::new();
        let mut buf = [0u8; 4096];
        for _ in 0..200 {
            match stream.recv(&mut buf, MSG_DONTWAIT) {
                Ok(0) => break,
                Ok(n) => {
                    data.extend_from_slice(&buf[..n]);
                    if data.len() > MAX_CONTROL_FRAME_BYTES {
                        return Err(Errno::E2BIG);
                    }
                    if data.ends_with(b"\n") {
                        break;
                    }
                }
                Err(Errno::EAGAIN) => {
                    if !data.is_empty() && data.ends_with(b"\n") {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(Errno::EINTR) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(data)
    }

    fn write_control_frame(stream: &UnixStream, frame: &[u8]) {
        let mut written = 0;
        while written < frame.len() {
            match stream.send(&frame[written..], MSG_NOSIGNAL) {
                Ok(0) => break,
                Ok(n) => written += n,
                Err(Errno::EINTR) => continue,
                Err(Errno::EAGAIN) => std::thread::sleep(Duration::from_millis(2)),
                Err(_) => break,
            }
        }
    }

    fn run_devattach(device: &str) -> Result<(), String> {
        os_posix::init_preopens().map_err(|e| e.to_string())?;
        install_signals()?;
        let dev_path = format!("/dev/{device}");
        if !Path::new(&dev_path).exists() {
            return Err(format!("remote device {dev_path} is not attached"));
        }
        let _ = notify_socket_ready(Some(&format!("attached {dev_path}")));
        while STOP.load(Ordering::SeqCst) == 0 {
            std::thread::sleep(Duration::from_millis(100));
        }
        Ok(())
    }

    fn execute_actions(
        actions: Vec<ManagerAction>,
        manager: &mut ServiceManager,
        live: &mut BTreeMap<String, LiveUnit>,
        is_system: bool,
        now_ms: u64,
    ) -> bool {
        let mut should_exit = false;
        for action in actions {
            match action {
                ManagerAction::SpawnService {
                    unit,
                    spec,
                    use_ready_fd,
                    notify_socket,
                } => {
                    let Some(mut argv) = spec.exec_start.clone() else {
                        let _ = manager.on_spawn_failed(&unit, "missing exec_start", now_ms);
                        continue;
                    };
                    // Built-in handler for optional `devattach@<name>.service` when no external
                    // `/usr/bin/devattach` binary is packaged.
                    if argv.first().map(String::as_str) == Some("/usr/bin/devattach")
                        && !Path::new("/usr/bin/devattach").exists()
                        && let Some(dev) = argv.get(1).cloned()
                    {
                        argv = vec!["/usr/bin/init".into(), "--devattach".into(), dev];
                    }
                    let mut env_map: BTreeMap<String, String> = BTreeMap::new();
                    env_map.insert("PATH".into(), "/usr/bin:/bin:/sbin".into());
                    for (k, v) in &spec.environment {
                        env_map.insert(k.clone(), v.clone());
                    }
                    let mut ready_pipe = None;
                    if use_ready_fd {
                        match Notification::open() {
                            Ok(pipe) => {
                                env_map.insert("OS_READY_FD".into(), pipe.fd());
                                ready_pipe = Some(pipe);
                            }
                            Err(err) => {
                                let _ = manager.on_spawn_failed(
                                    &unit,
                                    &format!("ready pipe: {err}"),
                                    now_ms,
                                );
                                continue;
                            }
                        }
                    }
                    if let Some(ref sock) = notify_socket {
                        env_map.insert("NOTIFY_SOCKET".into(), sock.clone());
                    }
                    let env: Vec<String> = env_map
                        .into_iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect();
                    let binds: Vec<ServiceBindMount<'_>> = spec
                        .grant
                        .bind_mounts
                        .iter()
                        .map(|b| ServiceBindMount {
                            source: b.source.as_str(),
                            target: b.target.as_str(),
                            read_only: b.read_only,
                        })
                        .collect();
                    let needs_grant = spec.grant.user.is_some()
                        || !binds.is_empty()
                        || spec.grant.mount_namespace.as_str() != "system";
                    let service_grant = needs_grant.then(|| ServiceGrant {
                        mount_namespace: spec.grant.mount_namespace.as_str(),
                        bind_mounts: &binds,
                        user: spec.grant.user.as_deref(),
                        group: spec.grant.group.as_deref(),
                        devices: &[],
                        cloud_scope: None,
                    });
                    let cwd = spec.cwd.as_deref().unwrap_or("/");
                    let opts = SpawnOptions {
                        cgroup: None,
                        dup2: &[],
                        service_grant,
                    };
                    match spawn_configured(&argv, Stdin::Null, cwd, &env, Some(0), &opts) {
                        Ok(child) => {
                            if let Some(ref mut pipe) = ready_pipe {
                                pipe.spawned();
                            }
                            let pid = child.id();
                            if manager.on_spawned(&unit, pid, now_ms).is_ok() {
                                live.insert(unit, LiveUnit { child, ready_pipe });
                            }
                        }
                        Err(err) => {
                            let _ = manager.on_spawn_failed(&unit, &err.to_string(), now_ms);
                        }
                    }
                }
                ManagerAction::MountFs { unit, spec } => {
                    let _ = fs::create_dir_all(&spec.target);
                    let res = os_posix::mount(
                        Some(std::path::Path::new(&spec.source)),
                        std::path::Path::new(&spec.target),
                        Some(&spec.fstype),
                        spec.flags,
                        spec.options.as_deref(),
                    )
                    .map_err(|e| e.to_string());
                    let _ = manager.on_mount_result(&unit, res, now_ms);
                }
                ManagerAction::UmountFs { target, .. } => {
                    let _ = os_posix::umount2(
                        std::path::Path::new(&target),
                        abi::umount_flags::MNT_DETACH,
                    );
                }
                ManagerAction::SignalUnit { pid, signal, .. } => {
                    let _ = os_posix::batch(&[Call::Kill {
                        pid: pid.to_string(),
                        signal: Some(signal),
                    }]);
                }
                ManagerAction::MarkBootHealthy => {
                    if is_system {
                        ensure_dir_mode("/run/os", 0o755);
                        let _ = fs::write("/run/os/boot-healthy", "{\"healthy\":true}\n");
                    }
                }
                ManagerAction::CloseCleanRoot { reboot } => {
                    if is_system {
                        for target in ["/mnt/cloud", "/tmp", "/usr"] {
                            let _ = os_posix::umount2(
                                std::path::Path::new(target),
                                abi::umount_flags::MNT_DETACH,
                            );
                        }
                        ensure_dir_mode("/run/os", 0o755);
                        let mode = if reboot { "reboot" } else { "poweroff" };
                        let _ = fs::write(
                            "/run/os/shutdown",
                            format!("{{\"mode\":\"{mode}\",\"clean\":true}}\n"),
                        );
                    }
                    should_exit = true;
                }
                ManagerAction::Log { .. } => {}
            }
        }
        should_exit
    }

    fn run_manager_loop(
        mut manager: ServiceManager,
        control_sock: UnixListener,
        notify_sock: UnixDatagram,
        is_system: bool,
    ) -> Result<(), String> {
        let mut live: BTreeMap<String, LiveUnit> = BTreeMap::new();
        let clock = Instant::now();
        let now_ms = || clock.elapsed().as_millis().min(u64::MAX as u128) as u64;
        let mut notify_buf = vec![0u8; MAX_NOTIFY_DATAGRAM_BYTES];
        let mut reap_followup_at: Option<u64> = None;

        loop {
            let now = now_ms();

            // 1. Handle termination signals -> clean ordered reverse shutdown.
            let stop_sig = STOP.load(Ordering::SeqCst);
            if stop_sig != 0 && manager.shutdown_mode() == ShutdownMode::None {
                let (_, actions) = manager.handle_control(
                    PeerCred {
                        pid: 1,
                        uid: manager.manager_uid(),
                        gid: manager.manager_uid(),
                    },
                    os_services::control::ControlRequest::Poweroff,
                    now,
                );
                if execute_actions(actions, &mut manager, &mut live, is_system, now) {
                    return Ok(());
                }
            }

            // 2. Reap direct and adopted exited children on `SIGCHLD` (plus a single delayed
            //    follow-up pass for un-waited host-spawned children once their host-wait grace
            //    window expires), or check our own explicitly managed unit PIDs without stealing
            //    unrelated host-spawned children.
            let got_sigchld = REAP.swap(false, Ordering::SeqCst);
            let due_followup = reap_followup_at.is_some_and(|at| now >= at);
            if got_sigchld {
                reap_followup_at = Some(now.saturating_add(550));
            } else if due_followup {
                reap_followup_at = None;
            }
            if got_sigchld || due_followup {
                loop {
                    let mut status = 0u32;
                    // SAFETY: status points to a live u32; -1/WNOHANG select ended children.
                    let pid = unsafe { waitpid2(-1, &mut status, 1) };
                    match pid {
                        1.. => {
                            let reaped_pid = pid as u32;
                            let exit_code = if status & 0x7f == 0 {
                                ((status >> 8) & 0xff) as i32
                            } else {
                                128 + (status & 0x7f) as i32
                            };
                            live.retain(|_, u| u.child.id() != reaped_pid);
                            let actions = manager.on_exited(reaped_pid, exit_code, now_ms());
                            if execute_actions(
                                actions,
                                &mut manager,
                                &mut live,
                                is_system,
                                now_ms(),
                            ) {
                                return Ok(());
                            }
                        }
                        0 | -12 => break, // No ended child or ECHILD
                        -27 => continue,  // EINTR
                        _ => break,
                    }
                }
            } else if !live.is_empty() {
                let managed_pids: Vec<u32> = live.values().map(|u| u.child.id()).collect();
                for target_pid in managed_pids {
                    let mut status = 0u32;
                    // SAFETY: status points to a live u32; specific managed PID + WNOHANG.
                    let pid = unsafe { waitpid2(target_pid as i32, &mut status, 1) };
                    if pid > 0 {
                        let reaped_pid = pid as u32;
                        let exit_code = if status & 0x7f == 0 {
                            ((status >> 8) & 0xff) as i32
                        } else {
                            128 + (status & 0x7f) as i32
                        };
                        live.retain(|_, u| u.child.id() != reaped_pid);
                        let actions = manager.on_exited(reaped_pid, exit_code, now_ms());
                        if execute_actions(actions, &mut manager, &mut live, is_system, now_ms()) {
                            return Ok(());
                        }
                    }
                }
            }

            // 3. Drain non-blocking `NOTIFY_SOCKET` datagrams authenticated via kernel `SO_PEERCRED`.
            loop {
                match notify_sock.recv_with_cred(&mut notify_buf, 0, MSG_DONTWAIT) {
                    Ok((n, _, raw_cred, _)) if n > 0 => {
                        let cred = PeerCred {
                            pid: raw_cred.pid,
                            uid: raw_cred.uid,
                            gid: raw_cred.gid,
                        };
                        let _ = manager.on_notify(cred, &notify_buf[..n], now_ms());
                    }
                    Ok(_) => break,
                    Err(Errno::EAGAIN) => break,
                    Err(Errno::EINTR) => continue,
                    Err(_) => break,
                }
            }

            // 4. Poll `OS_READY_FD` readiness pipes.
            let mut ready_events: Vec<(String, u32)> = Vec::new();
            let mut failed_pipes: Vec<String> = Vec::new();
            for (name, unit) in &mut live {
                if let Some(ref mut pipe) = unit.ready_pipe {
                    match pipe.check() {
                        Ok(true) => {
                            ready_events.push((name.clone(), unit.child.id()));
                            unit.ready_pipe = None;
                        }
                        Ok(false) => {}
                        Err(_) => {
                            failed_pipes.push(name.clone());
                            unit.ready_pipe = None;
                        }
                    }
                }
            }
            for (name, pid) in ready_events {
                let _ = manager.on_ready_fd(&name, pid, now_ms());
            }
            for _ in failed_pipes {
                // Readiness timeout or child exit handles failure cleanly.
            }

            // 5. Accept & process framed JSON control connections with kernel `SO_PEERCRED`.
            loop {
                match control_sock.accept_flags(SOCK_CLOEXEC | SOCK_NONBLOCK) {
                    Ok((stream, raw_cred)) => {
                        let cred = PeerCred {
                            pid: raw_cred.pid,
                            uid: raw_cred.uid,
                            gid: raw_cred.gid,
                        };
                        let (resp, actions) = match read_control_frame(&stream)
                            .and_then(|raw| decode_request_frame(&raw).map_err(|e| e.errno))
                        {
                            Ok(req) => manager.handle_control(cred, req, now_ms()),
                            Err(errno) => (
                                ControlResponse::Error {
                                    errno,
                                    message: format!("invalid control request ({})", errno.text()),
                                },
                                Vec::new(),
                            ),
                        };
                        if let Ok(encoded) = encode_response_frame(&resp) {
                            write_control_frame(&stream, &encoded);
                        }
                        if execute_actions(actions, &mut manager, &mut live, is_system, now_ms()) {
                            return Ok(());
                        }
                    }
                    Err(Errno::EAGAIN) => break,
                    Err(Errno::EINTR) => continue,
                    Err(_) => break,
                }
            }

            // 6. Advance DAG state machine (starts, stops, backoffs, timeouts, shutdown barrier).
            let actions = manager.tick(now_ms());
            if execute_actions(actions, &mut manager, &mut live, is_system, now_ms()) {
                return Ok(());
            }
            if manager.is_shutdown_complete() {
                return Ok(());
            }

            std::thread::sleep(Duration::from_millis(25));
        }
    }

    pub fn run() -> Result<(), String> {
        let args: Vec<String> = std::env::args().collect();
        if args.get(1).map(String::as_str) == Some("--devattach") {
            let dev = args
                .get(2)
                .ok_or_else(|| "missing device name for --devattach".to_owned())?;
            return run_devattach(dev);
        }

        os_posix::init_preopens().map_err(|e| e.to_string())?;
        install_signals()?;

        if args.get(1).map(String::as_str) == Some("--user") {
            let creds = current_creds()?;
            if creds.uid == 0 {
                return Err("per-user service manager refuses uid 0".into());
            }
            if let Some(arg_uid) = args.get(2)
                && arg_uid.parse::<u32>().ok() != Some(creds.uid)
            {
                return Err(format!(
                    "requested user uid '{arg_uid}' does not match process uid {}",
                    creds.uid
                ));
            }
            ensure_dir_mode("/run/user", 0o755);
            let user_dir = format!("/run/user/{}", creds.uid);
            ensure_dir_mode(&user_dir, 0o700);
            let notify_path = format!("{user_dir}/notify.sock");
            let control_path = user_manager_socket(creds.uid);
            let _ = fs::remove_file(&notify_path);
            let _ = fs::remove_file(&control_path);

            let notify_sock = UnixDatagram::bind(&notify_path)
                .map_err(|e| format!("bind {notify_path}: {}", e.text()))?;
            let _ = notify_sock.set_nonblocking(true);
            chmod_path(&notify_path, 0o600);

            let control_sock = UnixListener::bind(&control_path)
                .map_err(|e| format!("bind {control_path}: {}", e.text()))?;
            let _ = control_sock.set_nonblocking(true);
            chmod_path(&control_path, 0o600);

            let graph = load_user_graph(&creds.home)?;
            let manager = ServiceManager::new_user(creds.uid, graph).map_err(|e| e.to_string())?;
            let _ = notify_socket_ready(Some(&format!("user manager ready (uid {})", creds.uid)));
            return run_manager_loop(manager, control_sock, notify_sock, false);
        }

        // System PID 1 mode.
        let mut pid = 0u32;
        // SAFETY: `pid` points to a valid u32.
        unsafe {
            if proc_id(&mut pid) != 0 || pid != 1 {
                return Err("requires PID 1 boot capability".into());
            }
        }
        ensure_dir_mode("/run", 0o755);
        ensure_dir_mode("/run/init", 0o755);
        ensure_dir_mode("/run/os", 0o755);
        ensure_dir_mode("/run/user", 0o755);
        let _ = fs::remove_file(SYSTEM_NOTIFY_SOCKET);
        let _ = fs::remove_file(SYSTEM_CONTROL_SOCKET);

        let notify_sock = UnixDatagram::bind(SYSTEM_NOTIFY_SOCKET)
            .map_err(|e| format!("bind {SYSTEM_NOTIFY_SOCKET}: {}", e.text()))?;
        let _ = notify_sock.set_nonblocking(true);
        chmod_path(SYSTEM_NOTIFY_SOCKET, 0o666);

        let control_sock = UnixListener::bind(SYSTEM_CONTROL_SOCKET)
            .map_err(|e| format!("bind {SYSTEM_CONTROL_SOCKET}: {}", e.text()))?;
        let _ = control_sock.set_nonblocking(true);
        chmod_path(SYSTEM_CONTROL_SOCKET, 0o666);

        let default_uid = resolve_default_uid();
        let graph = load_system_graph(default_uid)?;
        let mut manager = ServiceManager::new_system(graph).map_err(|e| e.to_string())?;
        manager
            .boot_target("multi-user.target")
            .map_err(|e| e.to_string())?;
        run_manager_loop(manager, control_sock, notify_sock, true)
    }
}

fn main() {
    #[cfg(target_os = "wasi")]
    let result = runtime::run();
    #[cfg(not(target_os = "wasi"))]
    let result: Result<(), String> = Err("requires the OS WASI runtime".into());
    if let Err(error) = result {
        eprintln!("init: {error}");
        std::process::exit(1);
    }
}

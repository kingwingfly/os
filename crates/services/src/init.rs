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

#[cfg_attr(not(target_os = "wasi"), allow(dead_code))]
mod helpers {
    use abi::Errno;
    use os_services::graph::{CLOUD_DEVICE_INSTANCES, UnitGraph};
    use os_services::unit::{ResourceLimits, UnitSpec};
    use std::collections::BTreeMap;
    use std::io;

    /// Path where Stage 1 `switch_root` retains a verified rescue binary across the pivot.
    /// Stage 2 PID 1 unlinks it cleanly on startup once PID 1 is alive.
    pub const RETAINED_RESCUE_PATH: &str = "/run/os/.rescue";

    /// Targets unmounted by PID 1 during `CloseCleanRoot`.
    pub const SHUTDOWN_UNMOUNT_TARGETS: &[&str] = &["/mnt/cloud", "/tmp", "/usr"];

    /// Build the system unit graph from default + on-disk specs, ensuring that when
    /// `default_uid != 0`, `user-session@<default_uid>.service` is instantiated and ordered/required
    /// BEFORE `multi-user.target` so `MarkBootHealthy` cannot fire until the user session is ready.
    pub fn build_system_graph(
        default_uid: u32,
        mut by_name: BTreeMap<String, UnitSpec>,
    ) -> Result<UnitGraph, String> {
        let user_session =
            (default_uid != 0).then(|| format!("user-session@{default_uid}.service"));
        if let Some(ref us) = user_session {
            if let Some(tmpl) = by_name.get_mut("user-session@.service") {
                // Defensively strip legacy `multi-user.target` ordering from older unit files.
                tmpl.after.retain(|dep| dep != "multi-user.target");
            }
            if !by_name.contains_key(us)
                && let Some(tmpl) = by_name.get("user-session@.service").cloned()
            {
                let concrete = tmpl.instantiate(&default_uid.to_string())?;
                by_name.insert(concrete.name.clone(), concrete);
            }
            if let Some(multi_user) = by_name.get_mut("multi-user.target") {
                if !multi_user.after.contains(us) {
                    multi_user.after.push(us.clone());
                }
                if !multi_user.requires.contains(us) {
                    multi_user.requires.push(us.clone());
                }
            }
            if let Some(cloud_mount) = by_name.get_mut("cloud.mount")
                && !cloud_mount.after.contains(us)
            {
                cloud_mount.after.push(us.clone());
            }
        }

        let mut graph =
            UnitGraph::build(by_name.into_values().collect()).map_err(|e| e.to_string())?;
        for dev in CLOUD_DEVICE_INSTANCES {
            let _ = graph.instantiate_template(&format!("devattach@{dev}.service"));
        }
        Ok(graph)
    }

    /// Unmount every target in `targets`, ignoring `ENOENT`/`EINVAL` (not mounted) and recording
    /// every real unmount error (`EBUSY`, `EIO`, `EPERM`, etc.).
    pub fn unmount_shutdown_targets<F>(targets: &[&str], mut umount_fn: F) -> Vec<String>
    where
        F: FnMut(&str) -> io::Result<()>,
    {
        let mut errors = Vec::new();
        for &target in targets {
            if let Err(err) = umount_fn(target) {
                if matches!(
                    os_posix::errno_of(&err),
                    Some(Errno::ENOENT | Errno::EINVAL)
                ) {
                    continue;
                }
                errors.push(format!("{target}: {err}"));
            }
        }
        errors
    }

    /// Format `/run/os/shutdown` JSON payload: `"clean":true` ONLY when `errors` is empty.
    pub fn format_shutdown_record(mode: &str, errors: &[String]) -> String {
        let mut value = if errors.is_empty() {
            serde_json::json!({
                "mode": mode,
                "clean": true,
            })
            .to_string()
        } else {
            serde_json::json!({
                "mode": mode,
                "clean": false,
                "errors": errors,
            })
            .to_string()
        };
        value.push('\n');
        value
    }

    /// Resolve `(uid, gid)` for a unit's `grant.user` (numeric UID or username) from `/etc/passwd`.
    pub fn lookup_passwd_uid_gid(passwd_text: &str, user_spec: &str) -> Result<(u32, u32), String> {
        let numeric = user_spec.parse::<u32>().ok();
        for line in passwd_text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = trimmed.split(':').collect();
            if fields.len() < 4 {
                continue;
            }
            let Ok(uid) = fields[2].parse::<u32>() else {
                continue;
            };
            let Ok(gid) = fields[3].parse::<u32>() else {
                continue;
            };
            let matched = match numeric {
                Some(wanted_uid) => uid == wanted_uid,
                None => fields[0] == user_spec,
            };
            if matched {
                return Ok((uid, gid));
            }
        }
        Err(format!("user '{user_spec}' not found in /etc/passwd"))
    }

    /// Minimal filesystem status needed to verify `/run/user/<uid>` ownership and mode.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct DirStat {
        pub is_dir: bool,
        pub uid: u32,
        pub gid: u32,
        pub mode: u32,
    }

    pub trait UserRuntimeDirOps {
        fn create_dir_all(&mut self, path: &str) -> Result<(), String>;
        fn chmod(&mut self, path: &str, mode: u16) -> Result<(), String>;
        fn chown(&mut self, path: &str, uid: u32, gid: u32) -> Result<(), String>;
        fn lstat(&self, path: &str) -> Result<DirStat, String>;
    }

    /// PID 1 preparation of `/run/user` (`0755`) and `/run/user/<uid>` (`uid:gid`, `0700`) with
    /// explicit post-creation `lstat` verification before spawning `user-session@<uid>.service`.
    pub fn prepare_user_runtime_dir(
        ops: &mut impl UserRuntimeDirOps,
        uid: u32,
        gid: u32,
    ) -> Result<String, String> {
        ops.create_dir_all("/run/user")
            .map_err(|e| format!("create /run/user: {e}"))?;
        ops.chmod("/run/user", 0o755)
            .map_err(|e| format!("chmod /run/user: {e}"))?;
        let user_dir = format!("/run/user/{uid}");
        ops.create_dir_all(&user_dir)
            .map_err(|e| format!("create {user_dir}: {e}"))?;
        let pre = ops
            .lstat(&user_dir)
            .map_err(|e| format!("stat {user_dir}: {e}"))?;
        if !pre.is_dir {
            return Err(format!("{user_dir} is not a directory"));
        }
        ops.chown(&user_dir, uid, gid)
            .map_err(|e| format!("chown {user_dir} to {uid}:{gid}: {e}"))?;
        ops.chmod(&user_dir, 0o700)
            .map_err(|e| format!("chmod {user_dir} 0700: {e}"))?;
        let st = ops
            .lstat(&user_dir)
            .map_err(|e| format!("verify stat {user_dir}: {e}"))?;
        if !st.is_dir || st.uid != uid || st.gid != gid || (st.mode & 0o7777) != 0o700 {
            return Err(format!(
                "verification failed for {user_dir}: is_dir={} uid={} gid={} mode=0o{:o} (expected dir {uid}:{gid} 0o700)",
                st.is_dir,
                st.uid,
                st.gid,
                st.mode & 0o7777
            ));
        }
        Ok(user_dir)
    }

    /// Per-user manager (`--user`) validation/setup of `/run/user/<uid>`: propagates errors
    /// instead of silently ignoring directory creation or permission failures.
    pub fn ensure_user_mode_runtime_dir(
        ops: &mut impl UserRuntimeDirOps,
        uid: u32,
    ) -> Result<String, String> {
        let user_dir = format!("/run/user/{uid}");
        ops.create_dir_all(&user_dir)
            .map_err(|e| format!("create {user_dir}: {e}"))?;
        ops.chmod(&user_dir, 0o700)
            .map_err(|e| format!("chmod {user_dir} 0700: {e}"))?;
        let st = ops
            .lstat(&user_dir)
            .map_err(|e| format!("stat {user_dir}: {e}"))?;
        if !st.is_dir || st.uid != uid || (st.mode & 0o7777) != 0o700 {
            return Err(format!(
                "invalid runtime dir {user_dir}: is_dir={} uid={} mode=0o{:o}",
                st.is_dir,
                st.uid,
                st.mode & 0o7777
            ));
        }
        Ok(user_dir)
    }

    /// Sanitize a unit name into a valid cgroup v2 path segment (`[a-zA-Z0-9._-]`, <= 64 chars).
    pub fn sanitize_cgroup_unit_name(unit: &str) -> String {
        let mut out: String = unit
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                    c
                } else {
                    '_'
                }
            })
            .take(64)
            .collect();
        if out.is_empty() || out == "." || out == ".." {
            out = "unit".into();
        }
        out
    }

    /// Compute `(parent_cgroup, unit_cgroup)` for system PID 1 (`/services/<unit>`) or per-user
    /// managers (`/user/services-<uid>/<unit>`).
    pub fn service_cgroup_paths(is_system: bool, manager_uid: u32, unit: &str) -> (String, String) {
        let seg = sanitize_cgroup_unit_name(unit);
        if is_system {
            ("/services".into(), format!("/services/{seg}"))
        } else {
            let parent = format!("/user/services-{manager_uid}");
            let child = format!("{parent}/{seg}");
            (parent, child)
        }
    }

    /// Translate declared `ResourceLimits` into ordered `(key, value)` cgroup v2 control writes.
    pub fn resource_limit_controls(limits: &ResourceLimits) -> Vec<(&'static str, String)> {
        let mut controls = Vec::new();
        if let Some(ref cpu_max) = limits.cpu_max {
            controls.push(("cpu.max", cpu_max.clone()));
        }
        if let Some(memory_max) = limits.memory_max {
            controls.push(("memory.max", memory_max.to_string()));
        }
        if let Some(pids_max) = limits.pids_max {
            controls.push(("pids.max", pids_max.to_string()));
        }
        if limits.io_read_bps.is_some() || limits.io_write_bps.is_some() {
            let rate = |v: Option<u64>| v.map_or_else(|| "max".to_string(), |n| n.to_string());
            controls.push((
                "io.max",
                format!(
                    "rbps={} wbps={}",
                    rate(limits.io_read_bps),
                    rate(limits.io_write_bps)
                ),
            ));
        }
        controls
    }

    pub trait CgroupOps {
        fn create(&mut self, path: &str, process_lifetime: bool) -> Result<(), abi::Error>;
        fn set(&mut self, path: &str, key: &str, value: &str) -> Result<(), abi::Error>;
        fn remove(&mut self, path: &str) -> Result<(), abi::Error>;
    }

    /// Create and configure the cgroup for a service with declared `ResourceLimits`.
    /// Fails closed (cleaning up a freshly created cgroup) if creation or any limit write fails.
    pub fn setup_service_cgroup(
        ops: &mut impl CgroupOps,
        is_system: bool,
        manager_uid: u32,
        unit: &str,
        limits: &ResourceLimits,
    ) -> Result<String, String> {
        let (parent, cg_path) = service_cgroup_paths(is_system, manager_uid, unit);
        if let Err(err) = ops.create(&parent, false)
            && err.errno != Errno::EEXIST
        {
            return Err(format!("cgroup create {parent}: {err}"));
        }
        let created_fresh = match ops.create(&cg_path, !is_system) {
            Ok(()) => true,
            Err(err) if err.errno == Errno::EEXIST => false,
            Err(err) => return Err(format!("cgroup create {cg_path}: {err}")),
        };
        for (key, value) in resource_limit_controls(limits) {
            if let Err(err) = ops.set(&cg_path, key, &value) {
                if created_fresh {
                    let _ = ops.remove(&cg_path);
                }
                return Err(format!("cgroup set {cg_path} {key}={value}: {err}"));
            }
        }
        Ok(cg_path)
    }
}

#[cfg(target_os = "wasi")]
mod runtime {
    use crate::helpers::{
        CgroupOps, DirStat, RETAINED_RESCUE_PATH, SHUTDOWN_UNMOUNT_TARGETS, UserRuntimeDirOps,
        build_system_graph, ensure_user_mode_runtime_dir, format_shutdown_record,
        lookup_passwd_uid_gid, prepare_user_runtime_dir, setup_service_cgroup,
        unmount_shutdown_targets,
    };
    use crate::notify::{Notification, notify_socket_ready};
    use abi::{Call, CgroupLifetime, Creds, Errno};
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
    use os_services::graph::{UnitGraph, default_system_units};
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
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| !n.starts_with('.'))
                    && p.extension().is_some_and(|ext| ext == "json")
            })
            .collect();
        paths.sort();
        for path in paths {
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            if let Ok(spec) = UnitSpec::parse_json(&bytes) {
                if spec.grant.export_impersonate {
                    eprintln!(
                        "init: {}: EPERM: export impersonation requires the built-in exportd unit",
                        path.display()
                    );
                    continue;
                }
                out.insert(spec.name.clone(), spec);
            }
        }
    }

    fn apply_enabled_overrides(path: &str, by_name: &mut BTreeMap<String, UnitSpec>) {
        let Ok(raw) = fs::read(path) else {
            return;
        };
        let Ok(map) = serde_json::from_slice::<BTreeMap<String, bool>>(&raw) else {
            return;
        };
        for (unit, enabled) in map {
            if let Some(spec) = by_name.get_mut(&unit) {
                spec.enabled = enabled;
            }
        }
    }

    fn save_enabled_override(path: &str, unit: &str, enabled: bool) {
        if let Some(parent) = Path::new(path).parent() {
            let _ = fs::create_dir_all(parent);
        }
        let mut map = fs::read(path)
            .ok()
            .and_then(|raw| serde_json::from_slice::<BTreeMap<String, bool>>(&raw).ok())
            .unwrap_or_default();
        map.insert(unit.to_owned(), enabled);
        if let Ok(bytes) = serde_json::to_vec_pretty(&map) {
            let tmp = format!("{path}.tmp");
            if fs::write(&tmp, &bytes).is_ok() {
                let _ = fs::rename(&tmp, path);
            }
        }
    }

    struct OsRuntimeOps;

    impl UserRuntimeDirOps for OsRuntimeOps {
        fn create_dir_all(&mut self, path: &str) -> Result<(), String> {
            fs::create_dir_all(path).map_err(|e| e.to_string())
        }

        fn chmod(&mut self, path: &str, mode: u16) -> Result<(), String> {
            let mut reply = os_posix::batch(&[Call::Chmod {
                path: path.to_owned(),
                mode,
            }])
            .map_err(|e| e.to_string())?;
            reply
                .results
                .remove(0)
                .into_result()
                .map(|_| ())
                .map_err(|e| e.to_string())
        }

        fn chown(&mut self, path: &str, uid: u32, gid: u32) -> Result<(), String> {
            let mut reply = os_posix::batch(&[Call::Chown {
                path: path.to_owned(),
                uid: Some(uid),
                gid: Some(gid),
                nofollow: true,
            }])
            .map_err(|e| e.to_string())?;
            reply
                .results
                .remove(0)
                .into_result()
                .map(|_| ())
                .map_err(|e| e.to_string())
        }

        fn lstat(&self, path: &str) -> Result<DirStat, String> {
            let st = os_posix::stat(Path::new(path), false).map_err(|e| e.to_string())?;
            Ok(DirStat {
                is_dir: st.is_dir(),
                uid: st.uid,
                gid: st.gid,
                mode: st.mode,
            })
        }
    }

    impl CgroupOps for OsRuntimeOps {
        fn create(&mut self, path: &str, process_lifetime: bool) -> Result<(), abi::Error> {
            let mut reply = os_posix::batch(&[Call::CgroupCreate {
                path: path.to_owned(),
                controllers: None,
                lifetime: process_lifetime.then_some(CgroupLifetime::Process),
            }])
            .map_err(|e| abi::Error::because(Errno::EIO, e.to_string()))?;
            reply.results.remove(0).into_result().map(|_| ())
        }

        fn set(&mut self, path: &str, key: &str, value: &str) -> Result<(), abi::Error> {
            let mut reply = os_posix::batch(&[Call::CgroupSet {
                path: path.to_owned(),
                key: key.to_owned(),
                value: value.to_owned(),
            }])
            .map_err(|e| abi::Error::because(Errno::EIO, e.to_string()))?;
            reply.results.remove(0).into_result().map(|_| ())
        }

        fn remove(&mut self, path: &str) -> Result<(), abi::Error> {
            let mut reply = os_posix::batch(&[Call::CgroupRemove {
                path: path.to_owned(),
            }])
            .map_err(|e| abi::Error::because(Errno::EIO, e.to_string()))?;
            reply.results.remove(0).into_result().map(|_| ())
        }
    }

    fn load_system_graph(default_uid: u32) -> Result<UnitGraph, String> {
        let mut by_name = BTreeMap::new();
        for spec in default_system_units() {
            by_name.insert(spec.name.clone(), spec);
        }
        load_units_from_dir("/usr/lib/os/units", &mut by_name);
        load_units_from_dir("/etc/services", &mut by_name);
        apply_enabled_overrides("/etc/services/.enabled.json", &mut by_name);
        build_system_graph(default_uid, by_name)
    }

    fn load_user_graph(home: &str) -> Result<UnitGraph, String> {
        let mut by_name = os_services::graph::default_user_units()
            .into_iter()
            .map(|unit| (unit.name.clone(), unit))
            .collect();
        if !home.is_empty() {
            load_units_from_dir(&format!("{home}/.config/os/units"), &mut by_name);
            apply_enabled_overrides(
                &format!("{home}/.config/os/units/.enabled.json"),
                &mut by_name,
            );
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
        user_home: Option<&str>,
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
                    // Finding #17: Before PID 1 spawns `user-session@<uid>.service`, create and
                    // verify the UID-owned `0700` `/run/user/<uid>` directory so the per-user
                    // manager can bind its sockets cleanly after dropping privileges.
                    if is_system
                        && unit.starts_with("user-session@")
                        && let Some(ref user_spec) = spec.grant.user
                    {
                        let prep = fs::read_to_string("/etc/passwd")
                            .map_err(|e| format!("read /etc/passwd: {e}"))
                            .and_then(|passwd| lookup_passwd_uid_gid(&passwd, user_spec))
                            .and_then(|(uid, gid)| {
                                let mut ops = OsRuntimeOps;
                                prepare_user_runtime_dir(&mut ops, uid, gid)
                            });
                        if let Err(err) = prep {
                            eprintln!("init: {unit}: prepare user runtime dir: {err}");
                            let _ = manager.on_spawn_failed(
                                &unit,
                                &format!("prepare user runtime dir: {err}"),
                                now_ms,
                            );
                            continue;
                        }
                    }

                    // Finding #19: Enforce declared cgroup v2 resource limits; fail spawn closed
                    // instead of silently dropping limits if cgroup setup fails.
                    let cgroup_path = if let Some(ref limits) = spec.grant.limits
                        && !limits.is_empty()
                    {
                        let mut ops = OsRuntimeOps;
                        match setup_service_cgroup(
                            &mut ops,
                            is_system,
                            manager.manager_uid(),
                            &unit,
                            limits,
                        ) {
                            Ok(path) => Some(path),
                            Err(err) => {
                                let _ = manager.on_spawn_failed(&unit, &err, now_ms);
                                continue;
                            }
                        }
                    } else {
                        None
                    };

                    let mut env_map: BTreeMap<String, String> = BTreeMap::new();
                    env_map.insert("PATH".into(), "/usr/bin:/bin:/sbin".into());
                    if let Some(home) = user_home
                        && !home.is_empty()
                    {
                        env_map.insert("HOME".into(), home.into());
                    }
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
                    let dev_refs: Vec<&str> =
                        spec.grant.devices.iter().map(String::as_str).collect();
                    let cloud_scope =
                        (!spec.grant.cloud_scope.is_empty()).then_some(&spec.grant.cloud_scope);
                    let needs_grant = matches!(
                        spec.name.as_str(),
                        "mountd.service"
                            | "compositor.service"
                            | "desktop-shell.service"
                            | "greeter.service"
                            | "kubelet.service"
                    ) || spec.grant.export_impersonate
                        || spec.grant.user.is_some()
                        || spec.grant.group.is_some()
                        || !binds.is_empty()
                        || spec.grant.mount_namespace.as_str() != "system"
                        || !dev_refs.is_empty()
                        || cloud_scope.is_some();
                    let service_grant = needs_grant.then(|| ServiceGrant {
                        export_impersonate: spec.grant.export_impersonate,
                        mount_namespace: spec.grant.mount_namespace.as_str(),
                        bind_mounts: &binds,
                        user: spec.grant.user.as_deref(),
                        group: spec.grant.group.as_deref(),
                        devices: &dev_refs,
                        cloud_scope,
                    });
                    let cwd = spec.cwd.as_deref().unwrap_or("/");
                    let opts = SpawnOptions {
                        cgroup: cgroup_path.as_deref(),
                        dup2: &[],
                        service_grant,
                        ..SpawnOptions::default()
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
                            eprintln!("init: {unit}: spawn failed: {err}");
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
                        let errors = unmount_shutdown_targets(SHUTDOWN_UNMOUNT_TARGETS, |target| {
                            os_posix::umount2(
                                std::path::Path::new(target),
                                abi::umount_flags::MNT_DETACH,
                            )
                        });
                        ensure_dir_mode("/run/os", 0o755);
                        let mode = if reboot { "reboot" } else { "poweroff" };
                        let record = format_shutdown_record(mode, &errors);
                        let _ = fs::write("/run/os/shutdown", record);
                    }
                    should_exit = true;
                }
                ManagerAction::Log { unit, message } => {
                    eprintln!("init: {unit}: {message}");
                }
            }
        }
        should_exit
    }

    fn run_manager_loop(
        mut manager: ServiceManager,
        control_sock: UnixListener,
        notify_sock: UnixDatagram,
        is_system: bool,
        user_home: Option<&str>,
    ) -> Result<(), String> {
        let mut live: BTreeMap<String, LiveUnit> = BTreeMap::new();
        let clock = Instant::now();
        let now_ms = || clock.elapsed().as_millis().min(u64::MAX as u128) as u64;
        let mut notify_buf = vec![0u8; MAX_NOTIFY_DATAGRAM_BYTES];
        let mut reap_followup_at: Option<u64> = None;

        loop {
            let now = now_ms();

            // 1. Handle termination signals -> private manager-local ordered reverse shutdown
            //    (Finding #28: works for both PID 1 and per-user managers without routing through
            //    root-only external control-socket `Poweroff`).
            let stop_sig = STOP.load(Ordering::SeqCst);
            if stop_sig != 0 && manager.shutdown_mode() == ShutdownMode::None {
                let actions = manager.begin_local_shutdown(now);
                if execute_actions(actions, &mut manager, &mut live, is_system, user_home, now) {
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
                                user_home,
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
                        if execute_actions(
                            actions,
                            &mut manager,
                            &mut live,
                            is_system,
                            user_home,
                            now_ms(),
                        ) {
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
                        let parsed_req = read_control_frame(&stream)
                            .and_then(|raw| decode_request_frame(&raw).map_err(|e| e.errno));
                        let persist_toggle = match &parsed_req {
                            Ok(os_services::control::ControlRequest::Enable { unit }) => {
                                Some((unit.clone(), true))
                            }
                            Ok(os_services::control::ControlRequest::Disable { unit }) => {
                                Some((unit.clone(), false))
                            }
                            _ => None,
                        };
                        let (resp, actions) = match parsed_req {
                            Ok(req) => manager.handle_control(cred, req, now_ms()),
                            Err(errno) => (
                                ControlResponse::Error {
                                    errno,
                                    message: format!("invalid control request ({})", errno.text()),
                                },
                                Vec::new(),
                            ),
                        };
                        if matches!(resp, ControlResponse::Ok { .. })
                            && let Some((unit_name, enabled)) = persist_toggle
                        {
                            if is_system {
                                save_enabled_override(
                                    "/etc/services/.enabled.json",
                                    &unit_name,
                                    enabled,
                                );
                            } else if let Some(home) = user_home
                                && !home.is_empty()
                            {
                                save_enabled_override(
                                    &format!("{home}/.config/os/units/.enabled.json"),
                                    &unit_name,
                                    enabled,
                                );
                            }
                        }
                        if let Ok(encoded) = encode_response_frame(&resp) {
                            write_control_frame(&stream, &encoded);
                        }
                        if execute_actions(
                            actions,
                            &mut manager,
                            &mut live,
                            is_system,
                            user_home,
                            now_ms(),
                        ) {
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
            if execute_actions(
                actions,
                &mut manager,
                &mut live,
                is_system,
                user_home,
                now_ms(),
            ) {
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
            let mut dir_ops = OsRuntimeOps;
            let user_dir = ensure_user_mode_runtime_dir(&mut dir_ops, creds.uid)?;
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
            let mut manager =
                ServiceManager::new_user(creds.uid, graph).map_err(|e| e.to_string())?;
            manager
                .boot_target("mountd.service")
                .map_err(|e| e.to_string())?;
            manager
                .boot_target("exportd.service")
                .map_err(|e| e.to_string())?;
            let _ = notify_socket_ready(Some(&format!("user manager ready (uid {})", creds.uid)));
            return run_manager_loop(manager, control_sock, notify_sock, false, Some(&creds.home));
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
        let mut dirs = OsRuntimeOps;
        let passwd = fs::read_to_string("/etc/passwd").map_err(|e| e.to_string())?;
        // An existing writable root may predate the dedicated locked service account.
        let (uid, gid) = if passwd.lines().any(|row| row.starts_with("exportd:")) {
            lookup_passwd_uid_gid(&passwd, "exportd")?
        } else {
            let result = os_posix::batch(&[Call::Useradd {
                name: "exportd".into(),
                create_home: false,
                home: Some("/nonexistent".into()),
                group: None,
                groups: None,
                password: None,
                short_password: false,
            }])
            .map_err(|e| e.to_string())?;
            result
                .results
                .into_iter()
                .next()
                .ok_or("missing useradd result")?
                .into_result()
                .map_err(|e| e.to_string())?;
            lookup_passwd_uid_gid(
                &fs::read_to_string("/etc/passwd").map_err(|e| e.to_string())?,
                "exportd",
            )?
        };
        if uid == 0 {
            return Err("exportd requires a non-root account".into());
        }
        for (path, mode) in [
            ("/run/mount", 0o755),
            ("/run/kubelet", 0o755),
            ("/run/export", 0o755),
            ("/run/export/share", 0o1777),
        ] {
            dirs.create_dir_all(path)?;
            if path != "/run/mount" && path != "/run/kubelet" {
                dirs.chown(path, uid, gid)?;
            }
            dirs.chmod(path, mode)?;
        }
        // Finding #9: Stage 2 PID 1 is alive; unlink retained Stage 1 rescue binary cleanly.
        let _ = fs::remove_file(RETAINED_RESCUE_PATH);
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
        run_manager_loop(manager, control_sock, notify_sock, true, None)
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

#[cfg(test)]
mod tests {
    use super::helpers::*;
    use abi::Errno;
    use os_services::graph::default_system_units;
    use os_services::unit::ResourceLimits;
    use std::collections::BTreeMap;
    use std::io;

    fn os_err(errno: Errno) -> io::Error {
        io::Error::other(os_posix::OsCallError(abi::Error::new(errno)))
    }

    #[test]
    fn build_system_graph_requires_user_session_before_multi_user_even_with_legacy_unit() {
        let mut by_name = BTreeMap::new();
        for mut spec in default_system_units() {
            if spec.name == "user-session@.service" {
                spec.after.push("multi-user.target".into());
            }
            by_name.insert(spec.name.clone(), spec);
        }
        let graph = build_system_graph(1000, by_name).unwrap();
        let order = graph.start_order();
        let pos = |n: &str| order.iter().position(|u| u == n).unwrap();
        assert!(pos("local-fs.target") < pos("user-session@1000.service"));
        assert!(pos("user-session@1000.service") < pos("multi-user.target"));
        let multi = graph.unit("multi-user.target").unwrap();
        assert!(multi.requires.contains(&"user-session@1000.service".into()));
        assert!(multi.after.contains(&"user-session@1000.service".into()));
    }

    #[test]
    fn shutdown_unmount_checks_ignore_enoent_einval_and_report_real_failures() {
        // Optional `/mnt/cloud` unmounted (`EINVAL`), `/tmp` & `/usr` unmount cleanly -> clean:true.
        let errs = unmount_shutdown_targets(SHUTDOWN_UNMOUNT_TARGETS, |target| match target {
            "/mnt/cloud" => Err(os_err(Errno::EINVAL)),
            "/tmp" | "/usr" => Ok(()),
            _ => Err(os_err(Errno::ENOENT)),
        });
        assert!(errs.is_empty());
        let ok_rec: serde_json::Value =
            serde_json::from_str(&format_shutdown_record("poweroff", &errs)).unwrap();
        assert_eq!(ok_rec["mode"], "poweroff");
        assert_eq!(ok_rec["clean"], true);
        assert!(ok_rec.get("errors").is_none());

        // Real failure (`EBUSY` on `/usr`, `EIO` on `/mnt/cloud`) -> clean:false + errors list!
        let errs = unmount_shutdown_targets(SHUTDOWN_UNMOUNT_TARGETS, |target| match target {
            "/mnt/cloud" => Err(os_err(Errno::EIO)),
            "/tmp" => Ok(()),
            "/usr" => Err(os_err(Errno::EBUSY)),
            _ => Ok(()),
        });
        assert_eq!(errs.len(), 2);
        let bad_rec: serde_json::Value =
            serde_json::from_str(&format_shutdown_record("reboot", &errs)).unwrap();
        assert_eq!(bad_rec["mode"], "reboot");
        assert_eq!(bad_rec["clean"], false);
        let list = bad_rec["errors"].as_array().unwrap();
        assert_eq!(list.len(), 2);
        assert!(list[0].as_str().unwrap().contains("/mnt/cloud"));
        assert!(list[1].as_str().unwrap().contains("/usr"));
    }

    struct MockDirOps {
        dirs: BTreeMap<String, DirStat>,
        fail_create: Option<String>,
        fail_chmod: Option<String>,
        override_post_stat: Option<DirStat>,
    }

    impl MockDirOps {
        fn new() -> Self {
            Self {
                dirs: BTreeMap::new(),
                fail_create: None,
                fail_chmod: None,
                override_post_stat: None,
            }
        }
    }

    impl UserRuntimeDirOps for MockDirOps {
        fn create_dir_all(&mut self, path: &str) -> Result<(), String> {
            if self.fail_create.as_deref() == Some(path) {
                return Err("EACCES".into());
            }
            self.dirs.entry(path.to_owned()).or_insert(DirStat {
                is_dir: true,
                uid: 0,
                gid: 0,
                mode: 0o755,
            });
            Ok(())
        }
        fn chmod(&mut self, path: &str, mode: u16) -> Result<(), String> {
            if self.fail_chmod.as_deref() == Some(path) {
                return Err("EPERM".into());
            }
            let entry = self.dirs.get_mut(path).ok_or_else(|| "ENOENT".to_owned())?;
            entry.mode = u32::from(mode);
            Ok(())
        }
        fn chown(&mut self, path: &str, uid: u32, gid: u32) -> Result<(), String> {
            let entry = self.dirs.get_mut(path).ok_or_else(|| "ENOENT".to_owned())?;
            entry.uid = uid;
            entry.gid = gid;
            Ok(())
        }
        fn lstat(&self, path: &str) -> Result<DirStat, String> {
            if path == "/run/user/1000"
                && let Some(over) = self.override_post_stat
            {
                return Ok(over);
            }
            self.dirs
                .get(path)
                .copied()
                .ok_or_else(|| "ENOENT".to_owned())
        }
    }

    #[test]
    fn user_runtime_dir_preparation_and_user_mode_checks_fail_closed() {
        let passwd = "root:x:0:0:root:/root:/bin/sh\nuser:x:1000:1005:User:/home/user:/bin/sh\n";
        assert_eq!(lookup_passwd_uid_gid(passwd, "1000").unwrap(), (1000, 1005));
        assert_eq!(lookup_passwd_uid_gid(passwd, "user").unwrap(), (1000, 1005));
        assert!(lookup_passwd_uid_gid(passwd, "ghost").is_err());

        // PID 1 creates `/run/user` (0755) and `/run/user/1000` (1000:1005 0700) and verifies stat.
        let mut ops = MockDirOps::new();
        let dir = prepare_user_runtime_dir(&mut ops, 1000, 1005).unwrap();
        assert_eq!(dir, "/run/user/1000");
        assert_eq!(
            ops.dirs["/run/user/1000"],
            DirStat {
                is_dir: true,
                uid: 1000,
                gid: 1005,
                mode: 0o700,
            }
        );

        // Verification fails closed if stat reports wrong owner/mode or non-directory!
        let mut bad_ops = MockDirOps::new();
        bad_ops.override_post_stat = Some(DirStat {
            is_dir: true,
            uid: 0,
            gid: 0,
            mode: 0o755,
        });
        assert!(prepare_user_runtime_dir(&mut bad_ops, 1000, 1005).is_err());

        // `--user` mode propagates `create_dir_all` and `chmod` errors instead of ignoring them!
        let mut unpriv_create_fail = MockDirOps::new();
        unpriv_create_fail.fail_create = Some("/run/user/1000".into());
        assert!(ensure_user_mode_runtime_dir(&mut unpriv_create_fail, 1000).is_err());

        let mut unpriv_chmod_fail = MockDirOps::new();
        unpriv_chmod_fail.dirs.insert(
            "/run/user/1000".into(),
            DirStat {
                is_dir: true,
                uid: 1000,
                gid: 1000,
                mode: 0o700,
            },
        );
        unpriv_chmod_fail.fail_chmod = Some("/run/user/1000".into());
        assert!(ensure_user_mode_runtime_dir(&mut unpriv_chmod_fail, 1000).is_err());
    }

    struct MockCgroupOps {
        calls: Vec<String>,
        fail_set_key: Option<String>,
    }

    impl CgroupOps for MockCgroupOps {
        fn create(&mut self, path: &str, process_lifetime: bool) -> Result<(), abi::Error> {
            self.calls
                .push(format!("create:{path}:proc={process_lifetime}"));
            Ok(())
        }
        fn set(&mut self, path: &str, key: &str, value: &str) -> Result<(), abi::Error> {
            self.calls.push(format!("set:{path}:{key}={value}"));
            if self.fail_set_key.as_deref() == Some(key) {
                return Err(abi::Error::new(Errno::EOPNOTSUPP));
            }
            Ok(())
        }
        fn remove(&mut self, path: &str) -> Result<(), abi::Error> {
            self.calls.push(format!("remove:{path}"));
            Ok(())
        }
    }

    #[test]
    fn service_cgroup_setup_sanitizes_name_applies_limits_and_fails_closed_on_error() {
        assert_eq!(
            sanitize_cgroup_unit_name("user-session@1000.service"),
            "user-session_1000.service"
        );
        let limits = ResourceLimits {
            cpu_max: Some("max 100000".into()),
            memory_max: Some(64 * 1024 * 1024),
            pids_max: Some(16),
            io_read_bps: Some(1_048_576),
            io_write_bps: None,
        };
        let mut ops = MockCgroupOps {
            calls: Vec::new(),
            fail_set_key: None,
        };
        let cg = setup_service_cgroup(&mut ops, true, 0, "worker@1.service", &limits).unwrap();
        assert_eq!(cg, "/services/worker_1.service");
        assert_eq!(
            ops.calls,
            vec![
                "create:/services:proc=false",
                "create:/services/worker_1.service:proc=false",
                "set:/services/worker_1.service:cpu.max=max 100000",
                "set:/services/worker_1.service:memory.max=67108864",
                "set:/services/worker_1.service:pids.max=16",
                "set:/services/worker_1.service:io.max=rbps=1048576 wbps=max",
            ]
        );

        // If setting any limit fails (e.g. unsupported `cpu.max` quota), fail closed & remove cgroup!
        let mut fail_ops = MockCgroupOps {
            calls: Vec::new(),
            fail_set_key: Some("cpu.max".into()),
        };
        let err =
            setup_service_cgroup(&mut fail_ops, true, 0, "strict.service", &limits).unwrap_err();
        assert!(err.contains("cpu.max"));
        assert!(
            fail_ops
                .calls
                .contains(&"remove:/services/strict.service".to_string())
        );
    }
}

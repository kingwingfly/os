//! Native OS host boot orchestrator (Stage 0 -> Stage 1 `early_init` -> Stage 2 `init`),
//! console PTY 0 shell management, non-interactive `exec`, and clean `SIGTERM` shutdown.

use crate::dev_backend::new_uuid_v4;
use crate::kernel_actor::{KernelActor, NativeBootProfile, NativeRootSpec, NativeWriterMode};
use crate::kernel_rpc::{
    GuestFdEntry, GuestFdKind, HostInspect, KernelClient, KernelCmd, SpawnProcessReq, WakeBus,
};
use crate::netd::NativeNetdConfig;
use crate::pipes::PipeHandle;
use crate::proc_runner::{WasmRuntime, spawn_and_launch, spawn_process_thread};
use crate::pty::{PtyInstance, PtyMasterHandle, PtySlaveHandle, PtyTable};
use crate::release::VerifiedReleaseBundle;
use abi::Errno;
use os_image::Trust;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Configuration for booting a headless `os-native` OS instance.
#[derive(Clone, Debug)]
pub struct NativeBootConfig {
    pub bundle_dir: PathBuf,
    pub state_dir: PathBuf,
    pub trust_path: Option<PathBuf>,
    pub allow_unsigned_dev: bool,
    pub root: NativeRootSpec,
    pub default_user: String,
    pub recovery: bool,
    pub boot_timeout: Duration,
    pub spawn_console_shell: bool,
    pub netd: NativeNetdConfig,
}

impl NativeBootConfig {
    pub fn new(bundle_dir: PathBuf, state_dir: PathBuf) -> Self {
        Self {
            bundle_dir,
            state_dir,
            trust_path: None,
            allow_unsigned_dev: false,
            root: NativeRootSpec::CowFs {
                volume_uuid: None,
                writer_mode: NativeWriterMode::ForkOnBusy,
            },
            default_user: "user".to_string(),
            recovery: false,
            boot_timeout: Duration::from_secs(30),
            spawn_console_shell: true,
            netd: NativeNetdConfig::default(),
        }
    }
}

/// Captured result of running a non-interactive guest command via `NativeOsHost::exec_command`.
#[derive(Clone, Debug)]
pub struct ExecOutput {
    pub exit_code: i32,
    pub signal: Option<u8>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Live headless `os-native` OS instance owning the Kernel Actor OS thread, Wasmtime runtime,
/// and console PTY 0.
pub struct NativeOsHost {
    pub instance_id: String,
    pub release_id: String,
    pub state_dir: PathBuf,
    pub kernel: KernelClient,
    pub runtime: Arc<WasmRuntime>,
    pub console_pty: Arc<PtyInstance>,
    pub console_shell_pid: Option<u32>,
    _console_master: PtyMasterHandle,
    seat_masters: std::sync::Mutex<Vec<PtyMasterHandle>>,
    actor_thread: Option<std::thread::JoinHandle<()>>,
    shut_down: AtomicBool,
}

impl NativeOsHost {
    /// Boot an `os-native` instance completely offline:
    /// 1. Stage 0: load & Ed25519-verify Release v2 bundle from `cfg.bundle_dir`.
    /// 2. Stage 1: bootstrap `initramfs` VFS, `/dev`, `/proc`, `/run`, `NativeSqliteHeadStore`,
    ///    `NativePackStore`, and spawn PID 1 (`/init` -> `early_init.wasm`).
    /// 3. Stage 2: wait for `switch_root` -> `/usr/bin/init` -> `/run/os/boot-healthy`.
    /// 4. Optionally launch the console shell on PTY 0 (`/dev/pts/0`).
    pub fn boot(cfg: NativeBootConfig) -> Result<Self, String> {
        let trust_override: Option<Trust> = if let Some(ref p) = cfg.trust_path {
            let bytes =
                std::fs::read(p).map_err(|e| format!("read trust bundle {}: {e}", p.display()))?;
            let parsed: Trust = os_image::parse(&bytes)
                .map_err(|e| format!("parse trust bundle {}: {e}", p.display()))?;
            if parsed.keys.is_empty() {
                return Err("trust bundle contains no keys".into());
            }
            Some(parsed)
        } else {
            None
        };

        let release = VerifiedReleaseBundle::load(
            &cfg.bundle_dir,
            trust_override.as_ref(),
            cfg.allow_unsigned_dev,
        )?;
        let release_id = release.release_id.clone();
        let instance_id = new_uuid_v4();

        let runtime = WasmRuntime::shared()?;
        let wake = WakeBus::new();
        let (tx, rx) = mpsc::unbounded_channel::<KernelCmd>();

        // PTY signal & hangup hooks forward Ctrl-C / Ctrl-\ / Ctrl-Z / SIGWINCH / SIGHUP to Kernel Actor.
        let hook_tx = tx.clone();
        let hangup_tx = tx.clone();
        let ptys = PtyTable::new(
            Arc::new(move |pgrp, signal| {
                let _ = hook_tx.send(KernelCmd::KillPgrp { pgrp, signal });
            }),
            Arc::new(move |number, pgrp, sid| {
                let _ = hangup_tx.send(KernelCmd::PtyHangup { number, pgrp, sid });
            }),
        );
        let console_master = ptys.allocate_owned(0, 0, false);
        let console_pty = Arc::clone(&console_master.pty);

        let boot_profile = NativeBootProfile {
            version: 1,
            root: cfg.root.clone(),
            default_user: cfg.default_user.clone(),
            generation: None,
            recovery: cfg.recovery,
        };

        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let actor_instance_id = instance_id.clone();
        let actor_state_dir = cfg.state_dir.clone();
        let actor_wake = Arc::clone(&wake);
        let actor_ptys = Arc::clone(&ptys);
        let actor_netd = cfg.netd.clone();

        let actor_thread = std::thread::Builder::new()
            .name("os-kernel-actor".to_string())
            .stack_size(8 * 1024 * 1024)
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = ready_tx.send(Err(format!("tokio runtime: {e}")));
                        return;
                    }
                };
                let local = tokio::task::LocalSet::new();
                local.block_on(&rt, async move {
                    match KernelActor::boot_stage1(
                        actor_instance_id,
                        actor_state_dir,
                        release,
                        boot_profile,
                        actor_wake,
                        actor_ptys,
                        actor_netd,
                    )
                    .await
                    {
                        Ok((actor, pid1_ctrl, pid1_img)) => {
                            let _ = ready_tx.send(Ok((pid1_ctrl, pid1_img)));
                            actor.run_loop(rx).await;
                        }
                        Err(e) => {
                            let _ = ready_tx.send(Err(e));
                        }
                    }
                });
            })
            .map_err(|e| format!("spawn kernel actor thread: {e}"))?;

        let (pid1_ctrl, pid1_img) = ready_rx
            .recv()
            .map_err(|_| "kernel actor terminated during Stage 1 bootstrap".to_string())??;

        let kernel = KernelClient {
            tx,
            wake: Arc::clone(&wake),
            ptys: Arc::clone(&ptys),
        };

        // Launch PID 1 (`early_init.wasm` -> `switch_root` -> `/usr/bin/init`).
        let mut pid1_fds = BTreeMap::new();
        pid1_fds.insert(
            0,
            GuestFdEntry {
                kind: GuestFdKind::NullIn,
                cloexec: false,
            },
        );
        pid1_fds.insert(
            1,
            GuestFdEntry {
                kind: GuestFdKind::HostLog { fd: 1 },
                cloexec: false,
            },
        );
        pid1_fds.insert(
            2,
            GuestFdEntry {
                kind: GuestFdKind::HostLog { fd: 2 },
                cloexec: false,
            },
        );
        spawn_process_thread(
            1,
            pid1_ctrl,
            pid1_fds,
            pid1_img,
            0o022,
            None,
            kernel.clone(),
            Arc::clone(&runtime),
        );

        let mut host = Self {
            instance_id,
            release_id,
            state_dir: cfg.state_dir.clone(),
            kernel,
            runtime,
            console_pty,
            console_shell_pid: None,
            _console_master: console_master,
            seat_masters: std::sync::Mutex::new(Vec::new()),
            actor_thread: Some(actor_thread),
            shut_down: AtomicBool::new(false),
        };

        // Wait for Stage 2 `/run/os/boot-healthy` (unless recovery mode was explicitly requested).
        if !cfg.recovery {
            let deadline = Instant::now() + cfg.boot_timeout;
            loop {
                let info = host.inspect_blocking();
                if info.boot_healthy {
                    break;
                }
                if !info.pids.contains(&1) {
                    let _ = host.shutdown_blocking();
                    return Err(format!(
                        "PID 1 exited before /run/os/boot-healthy (stage={}, pids={:?})",
                        info.stage, info.pids
                    ));
                }
                if Instant::now() >= deadline {
                    let _ = host.shutdown_blocking();
                    return Err(format!(
                        "timed out waiting for /run/os/boot-healthy (stage={}, pids={:?})",
                        info.stage, info.pids
                    ));
                }
                let seq = host.kernel.wake.current();
                host.kernel.wake.wait_since(seq, Duration::from_millis(50));
            }
        }

        if !cfg.recovery {
            let (uid, gid) = host
                .resolve_user_uid_gid(&cfg.default_user)
                .unwrap_or((0, 0));
            host.console_pty.set_owner(uid, gid);
            host.kernel.call_sync(|reply| KernelCmd::RegisterPty {
                number: host.console_pty.number,
                uid,
                gid,
                mode: 0o620,
                reply,
            });
            if cfg.spawn_console_shell {
                match host.spawn_shell_on_pty(&host.console_pty, uid, None) {
                    Ok(pid) => host.console_shell_pid = Some(pid),
                    Err(e) => {
                        eprintln!(
                            "os-native: warning: failed to spawn console shell on PTY 0: {e:?}"
                        );
                    }
                }
            }
        }

        Ok(host)
    }

    fn resolve_user_uid_gid(&self, username: &str) -> Option<(u32, u32)> {
        if username == "root" {
            return Some((0, 0));
        }
        if let Ok(uid) = username.parse::<u32>() {
            return Some((uid, uid));
        }
        // Look up `/etc/passwd` inside the booted OS.
        let open = self
            .kernel
            .call_sync(|reply| KernelCmd::OpenAt {
                pid: 1,
                anchor: crate::kernel_rpc::KAnchor::Root,
                path: "/etc/passwd".to_string(),
                flags: abi::O_RDONLY,
                mode: 0,
                cloexec: true,
                reply,
            })
            .ok()?;
        let data = self
            .kernel
            .call_sync(|reply| KernelCmd::ReadKfd {
                pid: 1,
                kfd: open.kfd,
                offset: Some(0),
                len: 64 * 1024,
                reply,
            })
            .ok()?;
        let _ = self.kernel.call_sync(|reply| KernelCmd::CloseKfd {
            pid: 1,
            kfd: open.kfd,
            reply,
        });
        let text = std::str::from_utf8(&data).ok()?;
        for line in text.lines() {
            let mut parts = line.split(':');
            if parts.next() == Some(username) {
                let _pw = parts.next();
                if let (Some(uid_str), Some(gid_str)) = (parts.next(), parts.next())
                    && let (Ok(u), Ok(g)) = (uid_str.parse::<u32>(), gid_str.parse::<u32>())
                {
                    return Some((u, g));
                }
            }
        }
        None
    }

    /// Blocking inspection snapshot of the live OS instance.
    pub fn inspect_blocking(&self) -> HostInspect {
        self.kernel.call_sync(|reply| KernelCmd::Inspect { reply })
    }

    /// Async inspection snapshot of the live OS instance.
    pub async fn inspect(&self) -> HostInspect {
        self.kernel
            .call_async(|reply| KernelCmd::Inspect { reply })
            .await
    }

    /// Flush all dirty `CowFs` mounts immediately (durable `fsync` + SQLite WAL commit).
    pub fn commit_cowfs_blocking(&self) -> Result<(), Errno> {
        self.kernel
            .call_sync(|reply| KernelCmd::CommitCowfsNow { reply })
    }

    /// Spawn an interactive shell (or custom command) attached to `pty` as session leader.
    pub fn spawn_shell_on_pty(
        &self,
        pty: &Arc<PtyInstance>,
        uid: u32,
        argv_override: Option<Vec<String>>,
    ) -> Result<u32, Errno> {
        let home = if uid == 0 {
            "/root".to_string()
        } else {
            "/home/user".to_string()
        };
        let user_label = if uid == 0 { "root" } else { "user" };
        let cwd = self
            .kernel
            .call_sync(|reply| KernelCmd::StatAt {
                pid: 1,
                anchor: crate::kernel_rpc::KAnchor::Root,
                path: home.clone(),
                follow: true,
                reply,
            })
            .map(|_| home.clone())
            .unwrap_or_else(|_| "/".to_string());

        let argv = argv_override.unwrap_or_else(|| vec!["/bin/sh".to_string()]);
        let env = vec![
            "PATH=/usr/local/bin:/usr/bin:/bin:/sbin".to_string(),
            format!("HOME={home}"),
            format!("USER={user_label}"),
            format!("LOGNAME={user_label}"),
            "TERM=xterm-256color".to_string(),
            "SHELL=/bin/sh".to_string(),
            format!("PS1={user_label}@os-native:\\w\\$ "),
        ];

        let mut fds = BTreeMap::new();
        for fd_num in 0u32..=2 {
            fds.insert(
                fd_num,
                GuestFdEntry {
                    kind: GuestFdKind::PtySlave {
                        pty: PtySlaveHandle::new(Arc::clone(pty)),
                        readable: fd_num == 0,
                        writable: fd_num != 0,
                        nonblock: false,
                    },
                    cloexec: false,
                },
            );
        }

        let pid = spawn_and_launch(
            &self.kernel,
            &self.runtime,
            SpawnProcessReq {
                parent_pid: 1,
                argv,
                env,
                cwd,
                pgroup: None,
                cgroup: None,
                service_grant: None,
                umask: 0o022,
                fds,
                dup_kfds: Vec::new(),
                close_kfds: Vec::new(),
                clear_cloexec_kfds: Vec::new(),
                signals: None,
                ctty: Some(pty.number),
                setsid: true,
                host_owned: true,
                host_uid: Some(uid),
            },
        )?;
        pty.set_session(pid, pid);
        Ok(pid)
    }

    /// Allocate a host-owned seat PTY (optionally at a specific seat number), register `/dev/pts/<N>`,
    /// and spawn an interactive shell on it safely from Tokio async code (`spawn_blocking`).
    pub async fn allocate_and_spawn_seat_shell(
        self: &Arc<Self>,
        specific_seat: Option<u32>,
        uid: u32,
    ) -> Result<Arc<PtyInstance>, Errno> {
        let host = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let master = match specific_seat {
                Some(num) => host.kernel.ptys.allocate_specific(num, uid, uid, false)?,
                None => host.kernel.ptys.allocate_owned(uid, uid, false),
            };
            let num = master.number;
            let pty = Arc::clone(&master.pty);
            host.kernel.call_sync(|reply| KernelCmd::RegisterPty {
                number: num,
                uid,
                gid: uid,
                mode: 0o620,
                reply,
            });
            match host.spawn_shell_on_pty(&pty, uid, None) {
                Ok(_pid) => {
                    host.seat_masters.lock().unwrap().push(master);
                    Ok(pty)
                }
                Err(e) => {
                    drop(master);
                    host.kernel.ptys.remove(num);
                    Err(e)
                }
            }
        })
        .await
        .map_err(|_| Errno::EIO)?
    }

    /// Run a non-interactive guest command capturing stdout, stderr, and exit status.
    pub fn exec_command_blocking(
        &self,
        uid: u32,
        argv: Vec<String>,
        extra_env: Vec<String>,
        cwd: Option<String>,
        stdin_bytes: &[u8],
        timeout: Duration,
    ) -> Result<ExecOutput, Errno> {
        if argv.is_empty() {
            return Err(Errno::EINVAL);
        }
        let (stdin_r, stdin_w) = PipeHandle::pair();
        let (stdout_r, stdout_w) = PipeHandle::pair();
        let (stderr_r, stderr_w) = PipeHandle::pair();

        // Feed stdin in a small helper thread if non-empty so >64KiB inputs never deadlock.
        let stdin_owned = stdin_bytes.to_vec();
        let stdin_writer = std::thread::spawn(move || {
            let mut off = 0usize;
            while off < stdin_owned.len() {
                match stdin_w.buf.write(&stdin_owned[off..], false, || Ok(())) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => off += n,
                }
            }
            drop(stdin_w);
        });

        let mut env = vec![
            "PATH=/usr/local/bin:/usr/bin:/bin:/sbin".to_string(),
            format!("HOME={}", if uid == 0 { "/root" } else { "/home/user" }),
            format!("USER={}", if uid == 0 { "root" } else { "user" }),
            "TERM=dumb".to_string(),
        ];
        env.extend(extra_env);

        let mut fds = BTreeMap::new();
        fds.insert(
            0,
            GuestFdEntry {
                kind: GuestFdKind::Pipe {
                    handle: stdin_r,
                    nonblock: false,
                },
                cloexec: false,
            },
        );
        fds.insert(
            1,
            GuestFdEntry {
                kind: GuestFdKind::Pipe {
                    handle: stdout_w,
                    nonblock: false,
                },
                cloexec: false,
            },
        );
        fds.insert(
            2,
            GuestFdEntry {
                kind: GuestFdKind::Pipe {
                    handle: stderr_w,
                    nonblock: false,
                },
                cloexec: false,
            },
        );

        let pid = spawn_and_launch(
            &self.kernel,
            &self.runtime,
            SpawnProcessReq {
                parent_pid: 1,
                argv,
                env,
                cwd: cwd.unwrap_or_else(|| "/".to_string()),
                pgroup: None,
                cgroup: None,
                service_grant: None,
                umask: 0o022,
                fds,
                dup_kfds: Vec::new(),
                close_kfds: Vec::new(),
                clear_cloexec_kfds: Vec::new(),
                signals: None,
                ctty: None,
                setsid: false,
                host_owned: true,
                host_uid: Some(uid),
            },
        )?;

        let stdout_thread = std::thread::spawn(move || {
            let mut out = Vec::new();
            let mut buf = [0u8; 8192];
            loop {
                match stdout_r.buf.read(&mut buf, false, || Ok(())) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => out.extend_from_slice(&buf[..n]),
                }
            }
            out
        });
        let stderr_thread = std::thread::spawn(move || {
            let mut out = Vec::new();
            let mut buf = [0u8; 8192];
            loop {
                match stderr_r.buf.read(&mut buf, false, || Ok(())) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => out.extend_from_slice(&buf[..n]),
                }
            }
            out
        });

        let deadline = Instant::now() + timeout;
        let mut timed_out = false;
        let wait_res = loop {
            let seq = self.kernel.wake.current();
            let res = self.kernel.call_sync(|reply| KernelCmd::Waitpid {
                pid: 0,
                target: pid as i32,
                options: 1, // WNOHANG
                host_reap: true,
                reply,
            })?;
            if !res.nothing {
                break res;
            }
            if Instant::now() >= deadline {
                timed_out = true;
                let _ = self.kernel.call_sync(|reply| KernelCmd::Kill {
                    pid: 1,
                    target: pid.to_string(),
                    signal: 9,
                    reply,
                });
                // Give killed thread a moment to exit and be reaped.
                self.kernel.wake.wait_since(seq, Duration::from_millis(200));
                let res2 = self.kernel.call_sync(|reply| KernelCmd::Waitpid {
                    pid: 0,
                    target: pid as i32,
                    options: 1,
                    host_reap: true,
                    reply,
                })?;
                break res2;
            }
            self.kernel.wake.wait_since(seq, Duration::from_millis(25));
        };

        let _ = stdin_writer.join();
        let stdout = stdout_thread.join().unwrap_or_default();
        let stderr = stderr_thread.join().unwrap_or_default();

        if timed_out {
            return Err(Errno::ETIMEDOUT);
        }

        let (exit_code, signal) = if let Some(sig) = wait_res.signal {
            (128 + i32::from(sig), Some(sig))
        } else {
            ((wait_res.status >> 8) & 0xff, None)
        };
        Ok(ExecOutput {
            exit_code,
            signal,
            stdout,
            stderr,
        })
    }

    /// Async wrapper around `exec_command_blocking` for Tokio handlers.
    pub async fn exec_command(
        self: &Arc<Self>,
        uid: u32,
        argv: Vec<String>,
        extra_env: Vec<String>,
        cwd: Option<String>,
        stdin_bytes: Vec<u8>,
        timeout: Duration,
    ) -> Result<ExecOutput, Errno> {
        let host = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            host.exec_command_blocking(uid, argv, extra_env, cwd, &stdin_bytes, timeout)
        })
        .await
        .map_err(|_| Errno::EIO)?
    }

    /// Cleanly shut down the OS instance: send `SIGTERM` to PID 1, allow services to flush,
    /// and cleanly commit/close every mounted `CowFs` volume (`close_clean`).
    pub fn shutdown_blocking(&self) -> Result<bool, String> {
        if self.shut_down.swap(true, Ordering::SeqCst) {
            return Ok(true);
        }
        // Ask PID 1 (`init`) to run clean shutdown sequence if still running.
        let _ = self.kernel.call_sync(|reply| KernelCmd::Kill {
            pid: 1,
            target: "1".to_string(),
            signal: 15, // SIGTERM
            reply,
        });
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            let info = self.inspect_blocking();
            if !info.pids.contains(&1) {
                break;
            }
            let seq = self.kernel.wake.current();
            self.kernel.wake.wait_since(seq, Duration::from_millis(50));
        }
        // Flush and cleanly close all CowFs stores and terminate the Kernel Actor.
        self.kernel.call_sync(|reply| KernelCmd::Shutdown { reply })
    }

    /// Async clean shutdown wrapper.
    pub async fn shutdown(self: &Arc<Self>) -> Result<bool, String> {
        let host = Arc::clone(self);
        tokio::task::spawn_blocking(move || host.shutdown_blocking())
            .await
            .map_err(|e| format!("shutdown join: {e}"))?
    }
}

impl Drop for NativeOsHost {
    fn drop(&mut self) {
        let _ = self.shutdown_blocking();
        if let Some(handle) = self.actor_thread.take() {
            let _ = handle.join();
        }
    }
}

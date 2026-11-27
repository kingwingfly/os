//! `/usr/bin/osh`: ordinary WASI interactive shell process (Contract v2 §2.12).
//!
//! Runs over standard stdin/stdout/stderr (a PTY slave in the desktop Terminal emulator or
//! pipes/scripts in non-interactive mode) with zero `gui_*` Wasm imports or exports.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[cfg(target_os = "wasi")]
use std::os::wasi::io::{AsRawFd, FromRawFd};

use os_core::cli;
#[cfg(target_os = "wasi")]
use os_posix::process::open_raw;
use os_posix::process::{
    SpawnOptions, Stdin, WCONTINUED, WNOHANG, WUNTRACED, getpgid, getuid, ioctl, kill,
    spawn_configured, tcsetpgrp, waitpid2,
};
use os_services::osh::{
    Connector, EditorAction, History, JobState, JobTable, KeyDecoder, LineEditor, Pipeline, Redir,
    Stage, complete_input, expand_word_glob, format_prompt, fs_read_dir_names, fs_read_entries,
    osc7, osc133_cmd_done, osc133_cmd_exec, osc133_cmd_start, osc133_prompt_start,
    parse_line_with_subst, valid_var_name,
};
use serde_json::{Value, json};

const IOCTL_TCGETS: u32 = 0x5401;
const IOCTL_TCSETS: u32 = 0x5402;
const IOCTL_TIOCGWINSZ: u32 = 0x5413;

const TERMIOS_IFLAG_ICRNL: u64 = 0x0100;
const TERMIOS_IFLAG_IXON: u64 = 0x0400;
const TERMIOS_LFLAG_ISIG: u64 = 0x0001;
const TERMIOS_LFLAG_ICANON: u64 = 0x0002;
const TERMIOS_LFLAG_ECHO: u64 = 0x0008;

const O_RDONLY: u32 = 0;
const O_WRONLY: u32 = 1;
const O_CREAT: u32 = 0x40;
const O_TRUNC: u32 = 0x200;
const O_APPEND: u32 = 0x400;
const O_CLOEXEC: u32 = 0x80000;

static GOT_HUP: AtomicBool = AtomicBool::new(false);
static GOT_CHLD: AtomicBool = AtomicBool::new(false);
static GOT_INT: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "wasi")]
#[unsafe(no_mangle)]
pub extern "C" fn __osh_signal(signal: u32) {
    match signal {
        1 => GOT_HUP.store(true, Ordering::SeqCst),
        2 => GOT_INT.store(true, Ordering::SeqCst),
        17 => GOT_CHLD.store(true, Ordering::SeqCst),
        _ => {}
    }
}

fn get_pid(fallback: u32) -> u32 {
    #[cfg(target_os = "wasi")]
    {
        #[link(wasm_import_module = "wasix_32v1")]
        unsafe extern "C" {
            fn proc_id(pid: *mut u32) -> u32;
        }
        let mut pid = 0u32;
        // SAFETY: scalar output pointer lives across the host call.
        if unsafe { proc_id(&mut pid) } == 0 && pid != 0 {
            return pid;
        }
        fallback
    }
    #[cfg(not(target_os = "wasi"))]
    {
        let _ = fallback;
        std::process::id()
    }
}

fn install_signals(interactive: bool) {
    #[cfg(target_os = "wasi")]
    {
        #[link(wasm_import_module = "wasix_32v1")]
        unsafe extern "C" {
            fn callback_signal(name: *const u8, len: usize);
        }
        #[link(wasm_import_module = "os")]
        unsafe extern "C" {
            fn sigaction(signal: u32, kind: u32, mask: u32, flags: u32) -> i32;
        }
        let name = b"__osh_signal";
        // SAFETY: valid static callback symbol name and scalar signal numbers.
        // Set SA_RESTART (0x10000000) on all caught signals so `std::thread::sleep` on
        // wasm32-wasip1 never panics on EINTR; wait loops check GOT_HUP/GOT_INT explicitly.
        unsafe {
            callback_signal(name.as_ptr(), name.len());
            // Catch (no-op, SA_RESTART) instead of SIG_IGN so children reset to SIG_DFL on exec.
            let _ = sigaction(13, 2, 0, 0x10000000); // SIGPIPE -> caught no-op
            let _ = sigaction(1, 2, 0, 0x10000000); // SIGHUP -> catch (SA_RESTART)
            let _ = sigaction(17, 2, 0, 0x10000000); // SIGCHLD -> catch (SA_RESTART)
            if interactive {
                let _ = sigaction(2, 2, 0, 0x10000000); // SIGINT -> catch (SA_RESTART)
                let _ = sigaction(3, 2, 0, 0x10000000); // SIGQUIT -> caught no-op (SIG_DFL in child)
                let _ = sigaction(20, 2, 0, 0x10000000); // SIGTSTP -> caught no-op (SIG_DFL in child)
                let _ = sigaction(21, 1, 0, 0); // SIGTTIN -> SIG_IGN (reset around child spawn)
                let _ = sigaction(22, 1, 0, 0); // SIGTTOU -> SIG_IGN (reset around child spawn)
            }
        }
    }
    #[cfg(not(target_os = "wasi"))]
    {
        let _ = interactive;
    }
}

fn set_tty_job_signals_ignored(ignored: bool) {
    #[cfg(target_os = "wasi")]
    {
        #[link(wasm_import_module = "os")]
        unsafe extern "C" {
            fn sigaction(signal: u32, kind: u32, mask: u32, flags: u32) -> i32;
        }
        let kind = if ignored { 1 } else { 0 };
        // SAFETY: scalar signal numbers and disposition kinds.
        unsafe {
            let _ = sigaction(21, kind, 0, 0); // SIGTTIN
            let _ = sigaction(22, kind, 0, 0); // SIGTTOU
        }
    }
    #[cfg(not(target_os = "wasi"))]
    {
        let _ = ignored;
    }
}

struct ChildSignalGuard(bool);

impl ChildSignalGuard {
    fn new(interactive: bool) -> Self {
        if interactive {
            set_tty_job_signals_ignored(false);
        }
        Self(interactive)
    }
}

impl Drop for ChildSignalGuard {
    fn drop(&mut self) {
        if self.0 {
            set_tty_job_signals_ignored(true);
        }
    }
}

fn poll_fd_readable(fd: u32, timeout_ms: u64) -> io::Result<bool> {
    #[cfg(target_os = "wasi")]
    {
        #[link(wasm_import_module = "wasi_snapshot_preview1")]
        unsafe extern "C" {
            fn poll_oneoff(
                input: *const u8,
                output: *mut u8,
                count: usize,
                events: *mut usize,
            ) -> u32;
        }
        #[repr(C, align(8))]
        struct Buf<const N: usize>([u8; N]);
        let mut input = Buf([0u8; 96]);
        // Subscription 0: fd_read on `fd`.
        input.0[8] = 1;
        input.0[16..20].copy_from_slice(&fd.to_le_bytes());
        // Subscription 1: monotonic clock timeout.
        input.0[48..56].copy_from_slice(&1u64.to_le_bytes());
        input.0[56] = 0; // clock
        input.0[64..68].copy_from_slice(&1u32.to_le_bytes()); // monotonic
        input.0[72..80].copy_from_slice(&(timeout_ms * 1_000_000).to_le_bytes());
        let mut output = Buf([0u8; 64]);
        let mut events = 0usize;
        // SAFETY: aligned buffers for exactly 2 subscriptions/events.
        let rc = unsafe { poll_oneoff(input.0.as_ptr(), output.0.as_mut_ptr(), 2, &mut events) };
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        for ev in output.0.as_chunks::<32>().0.iter().take(events) {
            if ev[10] == 1 {
                return Ok(true);
            }
        }
        Ok(false)
    }
    #[cfg(not(target_os = "wasi"))]
    {
        let _ = fd;
        std::thread::sleep(Duration::from_millis(timeout_ms.min(20)));
        Ok(true)
    }
}

fn poll_stdin_readable(timeout_ms: u64) -> io::Result<bool> {
    poll_fd_readable(0, timeout_ms)
}

fn lookup_passwd_by_uid(uid: u32) -> Option<(String, String)> {
    let text = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in text.lines() {
        let fields: Vec<&str> = line.trim().split(':').collect();
        if fields.len() == 7 && fields[2].parse::<u32>().ok() == Some(uid) {
            return Some((fields[0].to_owned(), fields[5].to_owned()));
        }
    }
    None
}

struct Shell {
    interactive: bool,
    uid: u32,
    pid: u32,
    shell_pgid: u32,
    env: BTreeMap<String, String>,
    locals: BTreeMap<String, String>,
    cwd: String,
    old_pwd: Option<String>,
    last_status: i32,
    orig_termios: Option<Value>,
    saved_termios: Option<Value>,
    job_termios: BTreeMap<u32, Value>,
    jobs: JobTable,
    history: History,
    history_path: Option<PathBuf>,
    exit_requested: Option<i32>,
    cmd_exec_emitted: bool,
}

impl Shell {
    fn new(interactive: bool, orig_termios: Option<Value>) -> Self {
        let uid = getuid();
        let mut env: BTreeMap<String, String> = std::env::vars().collect();
        if !env.contains_key("PATH") {
            env.insert("PATH".into(), "/usr/bin:/bin".into());
        }
        if let Some((user, home)) = lookup_passwd_by_uid(uid) {
            let user_is_fallback = env
                .get("USER")
                .is_none_or(|u| u.is_empty() || (u == "guest" && user != "guest"));
            if user_is_fallback {
                env.insert("USER".into(), user.clone());
                env.insert("LOGNAME".into(), user);
            }
            let home_is_fallback = env
                .get("HOME")
                .is_none_or(|h| h.is_empty() || (h == "/" && home != "/" && !home.is_empty()));
            if home_is_fallback && !home.is_empty() {
                env.insert("HOME".into(), home);
            }
        } else {
            env.entry("USER".into()).or_insert_with(|| {
                if uid == 0 {
                    "root".into()
                } else {
                    "guest".into()
                }
            });
            env.entry("HOME".into()).or_insert_with(|| "/".into());
        }
        env.entry("SHELL".into())
            .or_insert_with(|| "/usr/bin/osh".into());

        let cwd = os_posix::getcwd()
            .ok()
            .and_then(|p| p.to_str().map(str::to_owned))
            .or_else(|| env.get("PWD").cloned())
            .unwrap_or_else(|| "/".into());
        env.insert("PWD".into(), cwd.clone());

        let shell_pgid = getpgid(0).unwrap_or(1);
        let pid = get_pid(shell_pgid);
        let history_path = env
            .get("HOME")
            .filter(|h| !h.is_empty() && *h != "/")
            .map(|h| PathBuf::from(h).join(".osh_history"));
        let mut history = History::new(500);
        if interactive && let Some(ref p) = history_path {
            history.load_file(p);
        }

        let saved_termios = orig_termios.clone();
        Self {
            interactive,
            uid,
            pid,
            shell_pgid,
            env,
            locals: BTreeMap::new(),
            cwd,
            old_pwd: None,
            last_status: 0,
            orig_termios,
            saved_termios,
            job_termios: BTreeMap::new(),
            jobs: JobTable::new(),
            history,
            history_path,
            exit_requested: None,
            cmd_exec_emitted: false,
        }
    }

    fn emit_cmd_exec_once(&mut self) {
        if self.interactive && !self.cmd_exec_emitted {
            self.cmd_exec_emitted = true;
            let _ = io::stdout().write_all(osc133_cmd_exec().as_bytes());
            let _ = io::stdout().flush();
        }
    }

    fn var(&self, name: &str) -> Option<String> {
        self.locals
            .get(name)
            .or_else(|| self.env.get(name))
            .cloned()
    }

    fn home(&self) -> String {
        self.var("HOME").unwrap_or_else(|| "/".into())
    }

    fn user(&self) -> String {
        self.var("USER").unwrap_or_else(|| "guest".into())
    }

    fn path_env(&self) -> String {
        self.var("PATH").unwrap_or_else(|| "/usr/bin:/bin".into())
    }

    fn env_vec(&self, extra: &[(String, String)]) -> Vec<String> {
        let mut map = self.env.clone();
        for (k, v) in extra {
            map.insert(k.clone(), v.clone());
        }
        map.into_iter().map(|(k, v)| format!("{k}={v}")).collect()
    }

    fn set_raw_mode(&self) {
        let Some(orig) = &self.orig_termios else {
            return;
        };
        let mut raw = orig.clone();
        if let Some(obj) = raw.as_object_mut() {
            let lflag = obj.get("lflag").and_then(Value::as_u64).unwrap_or(0);
            let iflag = obj.get("iflag").and_then(Value::as_u64).unwrap_or(0);
            obj.insert(
                "lflag".into(),
                Value::from(
                    lflag & !(TERMIOS_LFLAG_ICANON | TERMIOS_LFLAG_ECHO | TERMIOS_LFLAG_ISIG),
                ),
            );
            obj.insert(
                "iflag".into(),
                Value::from(iflag & !(TERMIOS_IFLAG_ICRNL | TERMIOS_IFLAG_IXON)),
            );
        }
        let _ = ioctl(0, IOCTL_TCSETS, raw);
    }

    fn restore_termios(&self) {
        if let Some(orig) = &self.orig_termios {
            let _ = ioctl(0, IOCTL_TCSETS, orig.clone());
        }
    }

    fn restore_saved_termios(&self) {
        if let Some(saved) = self.saved_termios.as_ref().or(self.orig_termios.as_ref()) {
            let _ = ioctl(0, IOCTL_TCSETS, saved.clone());
        }
    }

    fn tty_cols(&self) -> usize {
        if let Ok(val) = ioctl(0, IOCTL_TIOCGWINSZ, Value::Null)
            && let Some(cols) = val.get("columns").and_then(Value::as_u64)
            && cols >= 20
        {
            return cols as usize;
        }
        80
    }

    fn hangup_all_jobs(&mut self) {
        for pgid in self.jobs.active_pgids() {
            let _ = kill(-(pgid as i32), 1); // SIGHUP
            let _ = kill(-(pgid as i32), 18); // SIGCONT
        }
    }

    fn handle_hup_if_pending(&mut self) -> bool {
        if !GOT_HUP.swap(false, Ordering::SeqCst) {
            return false;
        }
        self.hangup_all_jobs();
        self.restore_termios();
        self.exit_requested = Some(129);
        true
    }

    fn eval_cmd_subst(&self, cmd: &str) -> Result<String, String> {
        #[cfg(target_os = "wasi")]
        {
            let (mut reader, writer) = os_posix::pipe::pipe().map_err(|e| format!("pipe: {e}"))?;
            let _ = os_posix::pipe::close_on_exec(&reader);
            let _ = os_posix::pipe::close_on_exec(&writer);
            let dup2 = [(writer.as_raw_fd() as u32, 1)];
            let opts = SpawnOptions {
                dup2: &dup2,
                ..SpawnOptions::default()
            };
            let env = self.env_vec(&[]);
            let argv = vec!["/usr/bin/osh".to_owned(), "-c".to_owned(), cmd.to_owned()];
            let child = {
                let _sig_guard = ChildSignalGuard::new(self.interactive);
                spawn_configured(&argv, Stdin::Null, &self.cwd, &env, None, &opts)
            }
            .map_err(|e| format!("command substitution: {e}"))?;
            drop(writer);

            const MAX_SUBST_BYTES: usize = 1024 * 1024;
            let mut out = Vec::new();
            let mut buf = [0u8; 4096];
            let cpid = child.id() as i32;
            let rfd = reader.as_raw_fd() as u32;
            let mut cancelled = false;
            loop {
                if GOT_HUP.load(Ordering::SeqCst) || GOT_INT.load(Ordering::SeqCst) {
                    cancelled = true;
                    break;
                }
                match poll_fd_readable(rfd, 25) {
                    Ok(false) => continue,
                    Ok(true) => {}
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let remaining = MAX_SUBST_BYTES.saturating_sub(out.len());
                        let take = n.min(remaining);
                        if take > 0 {
                            out.extend_from_slice(&buf[..take]);
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
            drop(reader);

            if cancelled {
                let _ = kill(cpid, 9);
            }
            for _ in 0..250 {
                match waitpid2(cpid, WNOHANG) {
                    Ok(Some(_)) | Err(_) => break,
                    Ok(None) => {
                        if !cancelled
                            && (GOT_HUP.load(Ordering::SeqCst) || GOT_INT.load(Ordering::SeqCst))
                        {
                            cancelled = true;
                            let _ = kill(cpid, 9);
                        }
                        std::thread::sleep(Duration::from_millis(4));
                    }
                }
            }
            let text = String::from_utf8_lossy(&out);
            Ok(text.trim_end_matches('\n').to_owned())
        }
        #[cfg(not(target_os = "wasi"))]
        {
            let _ = cmd;
            Err("command substitution requires WASI".into())
        }
    }

    fn reap_background(&mut self) {
        GOT_CHLD.swap(false, Ordering::SeqCst);
        while let Ok(Some((pid, status))) = waitpid2(-1, WNOHANG | WUNTRACED | WCONTINUED) {
            if status.exited() || status.signaled() {
                self.jobs
                    .on_wait(pid, Some(status.shell_status()), None, false);
            } else if let Some(sig) = status.stop_signal() {
                self.jobs.on_wait(pid, None, Some(sig), false);
            } else if status.continued() {
                self.jobs.on_wait(pid, None, None, true);
            }
        }
    }

    fn run_line(&mut self, line: &str) {
        let items = {
            let env_ref = &self.env;
            let loc_ref = &self.locals;
            let lookup = |k: &str| loc_ref.get(k).or_else(|| env_ref.get(k)).cloned();
            let mut subst = |cmd: &str| self.eval_cmd_subst(cmd);
            parse_line_with_subst(line, &lookup, &mut subst, self.last_status, self.pid)
        };
        let items = match items {
            Ok(items) => items,
            Err(err) => {
                eprintln!("osh: {err}");
                self.last_status = 2;
                return;
            }
        };

        for item in items {
            if self.exit_requested.is_some() || self.handle_hup_if_pending() {
                break;
            }
            let should_run = match item.connector {
                Connector::Seq => true,
                Connector::And => self.last_status == 0,
                Connector::Or => self.last_status != 0,
            };
            if !should_run {
                continue;
            }
            self.run_pipeline(item.pipeline);
        }
    }

    fn expand_stage(&self, stage: &Stage) -> (Vec<(String, String)>, Vec<String>, Vec<Redir>) {
        let mut argv = Vec::new();
        for w in &stage.words {
            argv.extend(expand_word_glob(w, &fs_read_dir_names));
        }
        (stage.assignments.clone(), argv, stage.redirs.clone())
    }

    fn find_on_path(&self, name: &str) -> bool {
        if name.contains('/') {
            return Path::new(name).is_file();
        }
        for dir in self.path_env().split(':').filter(|d| !d.is_empty()) {
            let candidate = Path::new(dir).join(name);
            if candidate.is_file() {
                return true;
            }
        }
        false
    }

    fn run_pipeline(&mut self, pipeline: Pipeline) {
        if pipeline.stages.is_empty() {
            return;
        }
        // Single-stage foreground commands may be pure assignments or shell builtins.
        if pipeline.stages.len() == 1 && !pipeline.background {
            let (assignments, argv, redirs) = self.expand_stage(&pipeline.stages[0]);
            if argv.is_empty() {
                for (k, v) in assignments {
                    if let Some(slot) = self.env.get_mut(&k) {
                        *slot = v;
                    } else {
                        self.locals.insert(k, v);
                    }
                }
                self.last_status = 0;
                return;
            }
            if let Some(status) = self.try_builtin(&argv, &redirs) {
                self.emit_cmd_exec_once();
                self.last_status = status;
                return;
            }
            // Implicit `cd` when bare token is an existing directory and not on $PATH.
            if argv.len() == 1 && redirs.is_empty() && !self.find_on_path(&argv[0]) {
                let p = Path::new(&argv[0]);
                if p.is_dir() {
                    self.last_status = self.builtin_cd(Some(&argv[0]));
                    return;
                }
            }
        }

        self.spawn_pipeline(pipeline);
    }

    fn try_builtin(&mut self, argv: &[String], redirs: &[Redir]) -> Option<i32> {
        let name = argv[0].as_str();
        let args = &argv[1..];
        let mut out_buf = String::new();
        let status = match name {
            ":" => 0,
            "cd" => {
                if args.len() > 1 {
                    eprintln!("cd: too many arguments");
                    1
                } else {
                    self.builtin_cd(args.first().map(String::as_str))
                }
            }
            "pwd" => {
                out_buf.push_str(&self.cwd);
                out_buf.push('\n');
                0
            }
            "clear" => {
                out_buf.push_str("\x1b[3J\x1b[H\x1b[2J");
                0
            }
            "export" => self.builtin_export(args, &mut out_buf),
            "unset" => self.builtin_unset(args),
            "jobs" => match self.jobs.format_list(args.first().map(String::as_str)) {
                Ok(text) => {
                    out_buf.push_str(&text);
                    0
                }
                Err(err) => {
                    eprintln!("jobs: {err}");
                    1
                }
            },
            "fg" => self.builtin_fg(args.first().map(String::as_str)),
            "bg" => self.builtin_bg(args.first().map(String::as_str)),
            "kill" => {
                if args.iter().any(|a| a.starts_with('%')) {
                    self.builtin_kill_job(args)
                } else {
                    return None; // Delegate PID kills to `/usr/bin/kill`.
                }
            }
            "help" => self.builtin_help(args, &mut out_buf),
            "history" => {
                for (i, entry) in self.history.entries().iter().enumerate() {
                    out_buf.push_str(&format!("{:>4}  {entry}\n", i + 1));
                }
                0
            }
            "umask" => self.builtin_umask(args, &mut out_buf),
            "exit" | "logout" => {
                let code = match args.first() {
                    None => self.last_status,
                    Some(s) => match s.parse::<i32>() {
                        Ok(n) => n & 0xff,
                        Err(_) => {
                            eprintln!("{name}: {s}: numeric argument required");
                            2
                        }
                    },
                };
                self.exit_requested = Some(code);
                code
            }
            "exec" => {
                if args.is_empty() {
                    0
                } else {
                    self.restore_termios();
                    let _sig_guard = ChildSignalGuard::new(self.interactive);
                    let env = self.env_vec(&[]);
                    let err = if args[0].contains('/') {
                        os_posix::process::execve(&args[0], args, &env)
                    } else {
                        os_posix::process::execvp(&args[0], args)
                    };
                    eprintln!("osh: exec: {}: {err}", args[0]);
                    126
                }
            }
            _ => return None,
        };

        if !out_buf.is_empty()
            && let Err(err) = write_builtin_output(&out_buf, redirs)
        {
            eprintln!("osh: {err}");
            return Some(1);
        }
        Some(status)
    }

    fn builtin_cd(&mut self, target: Option<&str>) -> i32 {
        let dest = match target {
            None | Some("~") => self.home(),
            Some("-") => match &self.old_pwd {
                Some(prev) => {
                    println!("{prev}");
                    prev.clone()
                }
                None => {
                    eprintln!("cd: OLDPWD not set");
                    return 1;
                }
            },
            Some(path) => path.to_owned(),
        };
        if let Err(err) = os_posix::chdir(Path::new(&dest)) {
            eprintln!("cd: {dest}: {err}");
            return 1;
        }
        let new_cwd = os_posix::getcwd()
            .ok()
            .and_then(|p| p.to_str().map(str::to_owned))
            .unwrap_or_else(|| dest.clone());
        self.old_pwd = Some(self.cwd.clone());
        self.cwd = new_cwd.clone();
        self.env.insert("PWD".into(), new_cwd.clone());
        if let Some(old) = &self.old_pwd {
            self.env.insert("OLDPWD".into(), old.clone());
        }
        if self.interactive {
            let _ = io::stdout().write_all(osc7(&new_cwd).as_bytes());
            let _ = io::stdout().flush();
        }
        0
    }

    fn builtin_export(&mut self, args: &[String], out: &mut String) -> i32 {
        if args.is_empty() || (args.len() == 1 && args[0] == "-p") {
            for (k, v) in &self.env {
                out.push_str(&format!("{k}={}\n", os_core::completion::escape_path(v)));
            }
            return 0;
        }
        for arg in args {
            if let Some((k, v)) = arg.split_once('=') {
                if !valid_var_name(k) {
                    eprintln!("export: `{arg}': not a valid identifier");
                    return 1;
                }
                self.locals.remove(k);
                self.env.insert(k.to_owned(), v.to_owned());
            } else {
                if !valid_var_name(arg) {
                    eprintln!("export: `{arg}': not a valid identifier");
                    return 1;
                }
                let val = self
                    .locals
                    .remove(arg)
                    .or_else(|| self.env.get(arg).cloned())
                    .unwrap_or_default();
                self.env.insert(arg.clone(), val);
            }
        }
        0
    }

    fn builtin_unset(&mut self, args: &[String]) -> i32 {
        for name in args {
            if !valid_var_name(name) {
                eprintln!("unset: `{name}': not a valid identifier");
                return 1;
            }
            self.env.remove(name);
            self.locals.remove(name);
        }
        0
    }

    fn builtin_help(&self, args: &[String], out: &mut String) -> i32 {
        match args.first() {
            None => {
                out.push_str(&cli::commands());
                out.push('\n');
                0
            }
            Some(cmd) => match cli::help(cmd) {
                Some(text) => {
                    out.push_str(&text);
                    out.push('\n');
                    0
                }
                None => {
                    eprintln!("Unknown command: {cmd}. Enter help for commands.");
                    1
                }
            },
        }
    }

    fn builtin_umask(&self, args: &[String], out: &mut String) -> i32 {
        #[cfg(target_os = "wasi")]
        {
            if args.is_empty() {
                let cur = os_posix::umask(0);
                let _ = os_posix::umask(cur);
                out.push_str(&format!("{cur:04o}\n"));
                return 0;
            }
            let Ok(val) = u32::from_str_radix(&args[0], 8) else {
                eprintln!("umask: invalid octal mask: {}", args[0]);
                return 1;
            };
            let _ = os_posix::umask(val & 0o777);
            0
        }
        #[cfg(not(target_os = "wasi"))]
        {
            let _ = (args, out);
            0
        }
    }

    fn builtin_fg(&mut self, spec: Option<&str>) -> i32 {
        let id = match self.jobs.resolve(spec) {
            Ok(id) => id,
            Err(err) => {
                eprintln!("fg: {err}");
                return 1;
            }
        };
        let Some(job) = self.jobs.remove(id) else {
            return 1;
        };
        println!("{}", job.command);
        let _ = io::stdout().flush();
        if let Some(saved) = self.job_termios.remove(&id) {
            let _ = ioctl(0, IOCTL_TCSETS, saved);
        } else {
            self.restore_saved_termios();
        }
        let _ = tcsetpgrp(0, job.pgid);
        let _ = kill(-(job.pgid as i32), 18); // SIGCONT
        self.emit_cmd_exec_once();
        let pids: Vec<u32> = job.alive.into_iter().collect();
        self.wait_foreground(job.pgid, pids, job.command)
    }

    fn builtin_bg(&mut self, spec: Option<&str>) -> i32 {
        let id = match self.jobs.resolve(spec) {
            Ok(id) => id,
            Err(err) => {
                eprintln!("bg: {err}");
                return 1;
            }
        };
        let (pgid, cmd) = {
            let Some(job) = self.jobs.get_mut(id) else {
                return 1;
            };
            job.state = JobState::Running;
            job.notified = true;
            (job.pgid, job.command.clone())
        };
        self.jobs.touch(id);
        let _ = kill(-(pgid as i32), 18); // SIGCONT
        println!("[{id}]+ {cmd} &");
        0
    }

    fn builtin_kill_job(&mut self, args: &[String]) -> i32 {
        let mut sig: u8 = 15; // SIGTERM
        let mut targets = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            if let Some(rest) = a.strip_prefix("-s") {
                let s = if rest.is_empty() {
                    i += 1;
                    args.get(i).map(String::as_str).unwrap_or("")
                } else {
                    rest
                };
                if let Some(n) = parse_signal(s) {
                    sig = n;
                } else {
                    eprintln!("kill: unknown signal: {s}");
                    return 1;
                }
            } else if let Some(rest) = a.strip_prefix('-')
                && targets.is_empty()
                && !rest.is_empty()
            {
                if let Some(n) = parse_signal(rest) {
                    sig = n;
                } else {
                    eprintln!("kill: unknown signal: {rest}");
                    return 1;
                }
            } else {
                targets.push(a.as_str());
            }
            i += 1;
        }
        let mut rc = 0;
        for t in targets {
            if t.starts_with('%') {
                match self.jobs.resolve(Some(t)) {
                    Ok(id) => {
                        if let Some(job) = self.jobs.get(id) {
                            let pgid = job.pgid;
                            let was_stopped = matches!(job.state, JobState::Stopped(_));
                            if let Err(err) = kill(-(pgid as i32), sig) {
                                eprintln!("kill: {t}: {err}");
                                rc = 1;
                            } else if was_stopped && matches!(sig, 1 | 15) {
                                let _ = kill(-(pgid as i32), 18); // SIGCONT so stopped job acts on HUP/TERM
                            }
                        }
                    }
                    Err(err) => {
                        eprintln!("kill: {err}");
                        rc = 1;
                    }
                }
            } else if let Ok(pid) = t.parse::<i32>() {
                if let Err(err) = kill(pid, sig) {
                    eprintln!("kill: {t}: {err}");
                    rc = 1;
                }
            } else {
                eprintln!("kill: invalid target: {t}");
                rc = 1;
            }
        }
        rc
    }

    fn spawn_pipeline(&mut self, pipeline: Pipeline) {
        let n = pipeline.stages.len();
        let mut pipes: Vec<(File, File)> = Vec::with_capacity(n.saturating_sub(1));
        for _ in 0..n.saturating_sub(1) {
            match os_posix::pipe::pipe() {
                Ok((r, w)) => {
                    let _ = os_posix::pipe::close_on_exec(&r);
                    let _ = os_posix::pipe::close_on_exec(&w);
                    pipes.push((r, w));
                }
                Err(err) => {
                    eprintln!("osh: pipe: {err}");
                    self.last_status = 1;
                    return;
                }
            }
        }

        let mut pgid: Option<u32> = None;
        let mut pids = Vec::with_capacity(n);
        let mut spawn_err = false;

        for (idx, stage) in pipeline.stages.iter().enumerate() {
            let _ = idx;
            let (assignments, argv, redirs) = self.expand_stage(stage);
            if argv.is_empty() {
                continue;
            }

            let mut dup2_actions: Vec<(u32, u32)> = Vec::new();
            let mut opened_files: Vec<File> = Vec::new();

            #[cfg(target_os = "wasi")]
            {
                if idx > 0 {
                    dup2_actions.push((pipes[idx - 1].0.as_raw_fd() as u32, 0));
                }
                if idx + 1 < n {
                    dup2_actions.push((pipes[idx].1.as_raw_fd() as u32, 1));
                }
            }

            let mut redir_failed = false;
            for r in &redirs {
                match open_redir(r) {
                    Ok(RedirAction::Dup(src, dst)) => dup2_actions.push((src, dst)),
                    Ok(RedirAction::File(file, dst)) => {
                        #[cfg(target_os = "wasi")]
                        dup2_actions.push((file.as_raw_fd() as u32, dst));
                        #[cfg(not(target_os = "wasi"))]
                        let _ = dst;
                        opened_files.push(file);
                    }
                    Err(err) => {
                        eprintln!("osh: {err}");
                        redir_failed = true;
                        break;
                    }
                }
            }
            if redir_failed {
                spawn_err = true;
                self.last_status = 1;
                break;
            }

            let env = self.env_vec(&assignments);
            let target_pg = if self.interactive {
                Some(pgid.unwrap_or(0))
            } else {
                None
            };
            let opts = SpawnOptions {
                dup2: &dup2_actions,
                ..SpawnOptions::default()
            };
            let spawn_res = {
                let _sig_guard = ChildSignalGuard::new(self.interactive);
                spawn_configured(&argv, Stdin::Inherit, &self.cwd, &env, target_pg, &opts)
            };
            match spawn_res {
                Ok(child) => {
                    let cpid = child.id();
                    if pgid.is_none() {
                        pgid = Some(cpid);
                    }
                    pids.push(cpid);
                }
                Err(err) => {
                    eprintln!("osh: {}: {err}", argv[0]);
                    spawn_err = true;
                    self.last_status = 127;
                    break;
                }
            }
            drop(opened_files);
        }

        // Parent closes all pipe ends immediately so EOF propagates cleanly.
        drop(pipes);

        if pids.is_empty() {
            if !spawn_err {
                self.last_status = 0;
            }
            return;
        }

        let job_pgid = pgid.unwrap_or(pids[0]);
        if pipeline.background {
            self.emit_cmd_exec_once();
            let id = self
                .jobs
                .insert(job_pgid, pids, pipeline.raw, JobState::Running);
            println!("[{id}] {job_pgid}");
            let _ = io::stdout().flush();
            self.last_status = 0;
        } else {
            if self.interactive {
                let _ = tcsetpgrp(0, job_pgid);
            }
            self.emit_cmd_exec_once();
            let status = self.wait_foreground(job_pgid, pids, pipeline.raw);
            self.last_status = status;
        }
    }

    fn wait_foreground(&mut self, pgid: u32, pids: Vec<u32>, command: String) -> i32 {
        let mut alive: std::collections::BTreeSet<u32> = pids.iter().copied().collect();
        let last_pid = *pids.last().unwrap_or(&pgid);
        let mut final_status = 0i32;
        let mut last_signaled = false;
        let mut stopped_sig: Option<u32> = None;

        while !alive.is_empty() {
            if self.handle_hup_if_pending() {
                let _ = kill(-(pgid as i32), 1);
                let _ = kill(-(pgid as i32), 18);
                break;
            }
            let mut progressed = false;
            loop {
                match waitpid2(-1, WNOHANG | WUNTRACED | WCONTINUED) {
                    Ok(Some((pid, status))) => {
                        progressed = true;
                        if alive.contains(&pid) {
                            if status.exited() || status.signaled() {
                                alive.remove(&pid);
                                if pid == last_pid || alive.is_empty() {
                                    final_status = status.shell_status();
                                    last_signaled = status.signaled();
                                }
                            } else if let Some(sig) = status.stop_signal() {
                                stopped_sig = Some(sig);
                                break;
                            }
                        } else if status.exited() || status.signaled() {
                            self.jobs
                                .on_wait(pid, Some(status.shell_status()), None, false);
                        } else if let Some(sig) = status.stop_signal() {
                            self.jobs.on_wait(pid, None, Some(sig), false);
                        } else if status.continued() {
                            self.jobs.on_wait(pid, None, None, true);
                        }
                    }
                    Ok(None) => break,
                    Err(_) => {
                        alive.clear();
                        break;
                    }
                }
            }
            if stopped_sig.is_some() || alive.is_empty() {
                break;
            }
            if !progressed {
                std::thread::sleep(Duration::from_millis(8));
            }
        }

        if self.interactive {
            let _ = tcsetpgrp(0, self.shell_pgid);
        }

        if let Some(sig) = stopped_sig {
            let job_t = if self.interactive {
                ioctl(0, IOCTL_TCGETS, Value::Null).ok()
            } else {
                None
            };
            let remaining: Vec<u32> = alive.into_iter().collect();
            let id = self
                .jobs
                .insert(pgid, remaining, command.clone(), JobState::Stopped(sig));
            if let Some(t) = job_t {
                self.job_termios.insert(id, t);
            }
            if self.interactive {
                self.saved_termios = self.orig_termios.clone();
                self.restore_termios();
            }
            if let Some(j) = self.jobs.get_mut(id) {
                j.notified = true;
            }
            println!("\r\n[{id}]+  Stopped   {command}");
            let _ = io::stdout().flush();
            return 128 + sig as i32;
        }
        if self.interactive {
            if last_signaled {
                self.saved_termios = self.orig_termios.clone();
                self.restore_termios();
            } else if let Ok(cur) = ioctl(0, IOCTL_TCGETS, Value::Null) {
                self.saved_termios = Some(cur);
            }
        }
        final_status
    }

    fn interactive_loop(&mut self) -> i32 {
        let mut editor = LineEditor::new();
        let mut decoder = KeyDecoder::default();
        let mut stdout = io::stdout();

        // Emit initial OSC 7 for the starting directory.
        let _ = stdout.write_all(osc7(&self.cwd).as_bytes());
        let _ = stdout.flush();

        loop {
            if self.exit_requested.is_some() || self.handle_hup_if_pending() {
                break;
            }
            self.reap_background();
            for note in self.jobs.drain_notifications() {
                let _ = writeln!(stdout, "{note}");
            }

            let prompt = format_prompt(&self.user(), &self.cwd, &self.home(), self.uid);
            self.set_raw_mode();
            let _ = write!(
                stdout,
                "{}{}{}{}",
                osc7(&self.cwd),
                osc133_prompt_start(),
                prompt,
                osc133_cmd_start()
            );
            let _ = stdout.flush();

            editor.reset_for_prompt(&prompt, self.tty_cols());
            let submitted = loop {
                if self.handle_hup_if_pending() {
                    break None;
                }
                if GOT_INT.swap(false, Ordering::SeqCst) {
                    let rendered = editor.render_final(&prompt, &editor.buffer.clone(), "^C\r\n");
                    editor.clear_line();
                    let _ = stdout.write_all(rendered.as_bytes());
                    let _ = stdout.flush();
                    self.last_status = 130;
                    break Some(String::new());
                }
                if GOT_CHLD.load(Ordering::SeqCst) {
                    self.reap_background();
                }

                match poll_stdin_readable(50) {
                    Ok(false) => continue,
                    Ok(true) => {}
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => {
                        self.hangup_all_jobs();
                        self.exit_requested = Some(129);
                        break None;
                    }
                }

                let mut buf = [0u8; 256];
                let n = match io::stdin().read(&mut buf) {
                    Ok(0) => {
                        self.hangup_all_jobs();
                        self.exit_requested = Some(if GOT_HUP.load(Ordering::SeqCst) {
                            129
                        } else {
                            0
                        });
                        break None;
                    }
                    Ok(n) => n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => {
                        self.hangup_all_jobs();
                        self.exit_requested = Some(129);
                        break None;
                    }
                };

                let path_env = self.path_env();
                let home = self.home();
                let mut done: Option<Option<String>> = None;
                let mut needs_redraw = false;

                for key in decoder.push(&buf[..n]) {
                    let prev_buf = if matches!(key, os_services::osh::KeyEvent::CtrlC) {
                        Some(editor.buffer.clone())
                    } else {
                        None
                    };
                    let action = editor.handle_key(key, &mut self.history, &|input, cur| {
                        complete_input(input, cur, &path_env, &home, &fs_read_entries)
                    });
                    match action {
                        EditorAction::None => {}
                        EditorAction::Redraw => needs_redraw = true,
                        EditorAction::Cancel => {
                            let line = prev_buf.unwrap_or_default();
                            let rendered = editor.render_final(&prompt, &line, "^C\r\n");
                            let _ = stdout.write_all(rendered.as_bytes());
                            let _ = stdout.flush();
                            self.last_status = 130;
                            done = Some(Some(String::new()));
                            break;
                        }
                        EditorAction::Eof => {
                            let _ = write!(stdout, "\r\n");
                            let _ = stdout.flush();
                            self.exit_requested = Some(0);
                            done = Some(None);
                            break;
                        }
                        EditorAction::Clear => {
                            let _ = write!(stdout, "\x1b[H\x1b[2J");
                            editor.reset_render_row();
                            needs_redraw = true;
                        }
                        EditorAction::Submit(line) => {
                            let rendered = editor.render_final(&prompt, &line, "\r\n");
                            let _ = stdout.write_all(rendered.as_bytes());
                            let _ = stdout.flush();
                            done = Some(Some(line));
                            break;
                        }
                    }
                }
                if let Some(result) = done {
                    break result;
                }
                if needs_redraw {
                    let rendered = editor.render(&prompt, self.tty_cols());
                    let _ = stdout.write_all(rendered.as_bytes());
                    let _ = stdout.flush();
                }
            };

            let Some(line) = submitted else {
                break;
            };
            if line.trim().is_empty() {
                continue;
            }

            self.history.record(&line, self.history_path.as_deref());
            self.restore_saved_termios();
            self.cmd_exec_emitted = false;
            self.run_line(&line);
            self.emit_cmd_exec_once();
            let _ = stdout.write_all(osc133_cmd_done(self.last_status).as_bytes());
            let _ = stdout.flush();
        }

        self.restore_termios();
        self.exit_requested.unwrap_or(self.last_status)
    }
}

enum RedirAction {
    Dup(u32, u32),
    #[allow(dead_code)]
    File(File, u32),
}

fn open_redir(redir: &Redir) -> io::Result<RedirAction> {
    match redir {
        Redir::StderrToStdout => Ok(RedirAction::Dup(1, 2)),
        Redir::StdoutToStderr => Ok(RedirAction::Dup(2, 1)),
        Redir::Stdin(w) => open_redir_file(&w.text, O_RDONLY | O_CLOEXEC, 0),
        Redir::StdoutTrunc(w) => {
            open_redir_file(&w.text, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 1)
        }
        Redir::StdoutAppend(w) => {
            open_redir_file(&w.text, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 1)
        }
        Redir::StderrTrunc(w) => {
            open_redir_file(&w.text, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 2)
        }
        Redir::StderrAppend(w) => {
            open_redir_file(&w.text, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 2)
        }
    }
}

fn open_redir_file(path: &str, flags: u32, dst_fd: u32) -> io::Result<RedirAction> {
    #[cfg(target_os = "wasi")]
    {
        let fd = open_raw(path, flags, 0o666)?;
        // SAFETY: `open_raw` returns a freshly opened owned guest descriptor.
        let file = unsafe { File::from_raw_fd(fd as i32) };
        Ok(RedirAction::File(file, dst_fd))
    }
    #[cfg(not(target_os = "wasi"))]
    {
        let _ = (path, flags, dst_fd);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "redirection requires WASI",
        ))
    }
}

fn write_builtin_output(text: &str, redirs: &[Redir]) -> io::Result<()> {
    let mut target: Option<(String, bool)> = None;
    for r in redirs {
        match r {
            Redir::StdoutTrunc(w) => target = Some((w.text.clone(), false)),
            Redir::StdoutAppend(w) => target = Some((w.text.clone(), true)),
            _ => {}
        }
    }
    if let Some((path, append)) = target {
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).write(true);
        if append {
            opts.append(true);
        } else {
            opts.truncate(true);
        }
        let mut file = opts.open(path)?;
        file.write_all(text.as_bytes())?;
        file.flush()
    } else {
        let mut out = io::stdout();
        out.write_all(text.as_bytes())?;
        out.flush()
    }
}

fn parse_signal(name: &str) -> Option<u8> {
    abi::signal_named(name)
}

fn main() {
    if let Err(err) = os_posix::init_preopens() {
        eprintln!("osh: {err}");
        std::process::exit(1);
    }

    let args: Vec<String> = std::env::args().skip(1).collect();

    // Support `-c <command>` non-interactive execution.
    if args.first().map(String::as_str) == Some("-c") {
        let Some(cmd) = args.get(1) else {
            eprintln!("osh: -c: option requires an argument");
            std::process::exit(2);
        };
        install_signals(false);
        let mut shell = Shell::new(false, None);
        shell.run_line(cmd);
        std::process::exit(shell.exit_requested.unwrap_or(shell.last_status));
    }

    // Support `--help` / `-h`.
    if matches!(args.first().map(String::as_str), Some("--help" | "-h")) {
        println!("Usage: osh [-c COMMAND | SCRIPT]");
        return;
    }

    // Support executing a script file.
    if let Some(script_path) = args.first().filter(|a| !a.starts_with('-')) {
        install_signals(false);
        let content = match std::fs::read_to_string(script_path) {
            Ok(c) => c,
            Err(err) => {
                eprintln!("osh: {script_path}: {err}");
                std::process::exit(127);
            }
        };
        let mut shell = Shell::new(false, None);
        for line in content.lines() {
            shell.run_line(line);
            if shell.exit_requested.is_some() {
                break;
            }
        }
        std::process::exit(shell.exit_requested.unwrap_or(shell.last_status));
    }

    // Detect interactive TTY via TCGETS on fd 0.
    let orig_termios = ioctl(0, IOCTL_TCGETS, json!(null)).ok();
    let interactive = orig_termios.is_some();
    install_signals(interactive);

    let mut shell = Shell::new(interactive, orig_termios);
    if interactive {
        let _ = tcsetpgrp(0, shell.shell_pgid);
        let code = shell.interactive_loop();
        std::process::exit(code);
    } else {
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            match line {
                Ok(text) => shell.run_line(&text),
                Err(_) => break,
            }
            if shell.exit_requested.is_some() {
                break;
            }
        }
        std::process::exit(shell.exit_requested.unwrap_or(shell.last_status));
    }
}

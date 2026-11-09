//! One terminal tab: shell grammar, builtins, browser actions and the terminal display.
//! External commands execute installed WASI images with normal process credentials and stdio.

mod commands;
mod jobs;

use std::cell::RefCell;
use std::rc::Rc;

use abi::Call;
use futures::channel::oneshot;
use futures::future::{Either, LocalBoxFuture, select};
use futures::{FutureExt, StreamExt};
use leptos::prelude::*;
use os_core::ansi::screen::Screen;
use os_core::bin as cli_bin;
use os_core::completion::{self, Candidate, Query};
use os_core::glob::{self, Part};
use os_core::shell::{self as grammar, Word};
use os_core::{cli, resolve, split_command};
use serde_json::Value;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::{JsFuture, spawn_local};

use crate::{
    account_command, cancel_choosing, cancel_uploads, choose_files, completion_cursor,
    completion_focus, listing, set_directory, stop_recording, sudo,
};

/// The most transcript lines kept, ...
const KEPT: usize = 100;
/// ... the most lines one output shows, ...
const SHOWN: usize = 2000;
/// ... the most bytes passed from one stage to the next, and read from one file.
const PIPED_MAX: usize = 10_000_000;
/// How many filesystem lookups one wildcard pattern makes, and paths it expands to, at most.
const GLOB_LOOKUPS: usize = 1000;
const GLOB_PATHS: usize = 10_000;
/// How many of a wildcard's lookups run at once.
const GLOB_CONCURRENCY: usize = 8;

#[derive(Clone)]
pub enum LogLine {
    Screen(RwSignal<Screen>, RwSignal<bool>),
    Text(String),
    /// Text that changes as a command goes on, such as an upload's progress.
    Live(RwSignal<String>),
    Command {
        user: String,
        cwd: String,
        command: String,
    },
}

/// What a command wrote and whether it failed.
#[derive(Default)]
pub struct Output {
    pub stdout: String,
    pub failed: bool,
}
impl Output {
    fn text(stdout: impl Into<String>) -> Self {
        Self {
            stdout: stdout.into(),
            ..Default::default()
        }
    }
}

#[derive(Clone)]
pub struct CompletionSession {
    pub original: String,
    pub cwd: String,
    pub candidates: Vec<Candidate>,
    pub baseline: String,
    pub cursor: usize,
    pub original_cursor: usize,
    /// The candidate selected in the pager, after the common prefix was inserted.
    pub selected: Option<usize>,
}

/// Who is signed in, which every tab shares, since it is one session.
#[derive(Clone, Copy)]
pub struct Account {
    pub writable: RwSignal<bool>,
    pub username: RwSignal<String>,
    pub home: RwSignal<String>,
}

/// The programs web/app.js asks for a password for first, in a dialog: a guest's own useradd,
/// an account's own userdel.
const DIALOGS: &[&str] = &["useradd", "userdel"];

#[derive(Clone, Copy)]
pub struct Shell {
    pub id: u64,
    pub account: Account,
    pub cwd: RwSignal<String>,
    environment: StoredValue<std::collections::BTreeMap<String, String>>,
    pub lines: RwSignal<Vec<LogLine>>,
    pub input: RwSignal<String>,
    pub busy: RwSignal<bool>,
    pub history: RwSignal<Vec<String>>,
    pub history_index: RwSignal<usize>,
    pub completion: RwSignal<Option<CompletionSession>>,
    pub completing: RwSignal<bool>,
    pub completion_status: RwSignal<String>,
    pub completion_epoch: RwSignal<u64>,
    pub completion_offset: RwSignal<i64>,
    /// Whether Ctrl+C asked the running line to stop, ...
    cancelled: RwSignal<bool>,
    /// ... which, for an upload, cancels it, ...
    uploading: RwSignal<bool>,
    /// ... for a recording (`stream`), stops it, ...
    recording: RwSignal<bool>,
    /// ... and, waiting for files to upload, gives it none.
    choosing: RwSignal<bool>,
    /// The files the next upload sends: chosen as the command started, or dropped.
    chosen: StoredValue<Option<js_sys::Promise>, LocalStorage>,
    /// Whether the tab was closed: its processes stop and attached device work is cancelled.
    detached: RwSignal<bool>,
    /// The terminal's input, while the running line's first process may read it
    /// (web/wasi/exec.mjs): the lines typed go to it, and Ctrl+D ends a read ...
    terminal: StoredValue<Option<JsValue>, LocalStorage>,
    /// ... which it waits on now.
    pub reading: RwSignal<bool>,
    pub tty_echo: RwSignal<bool>,
    pub terminal_active: RwSignal<bool>,
    terminal_modes: RwSignal<(bool, bool)>,
    /// The terminal's jobs: pipelines run with `&`, or stopped with Ctrl+Z (shell/jobs.rs) ...
    jobs: StoredValue<Vec<jobs::Job>, LocalStorage>,
    /// ... and the run in the foreground, which Ctrl+Z stops.
    foreground: StoredValue<Option<jobs::Foreground>, LocalStorage>,
    /// The line running now, which names the job it may become.
    line: StoredValue<String>,
}

/// What a pipeline of processes showed in the transcript as they wrote: the line of the last's
/// output, how many lines it shows (up to [`SHOWN`]) and how many more there were; and the
/// part of an error line written so far.
/// A pipeline of processes started (`Shell::launch`): what to await, the handlers that must
/// outlive it, and what it shares with the job it may become.
struct Launched {
    exec: JsFuture,
    handlers: Box<dyn std::any::Any>,
    run: jobs::Run,
    shown: Rc<RefCell<Shown>>,
    names: Vec<String>,
    execed: bool,
}

#[derive(Default)]
struct Shown {
    grid: Screen,
    screen: Option<RwSignal<Screen>>,
    live: Option<RwSignal<bool>>,
    line: Option<RwSignal<String>>,
    lines: usize,
    hidden: usize,
    partial: String,
}
impl Shown {
    /// What of `text`, written to standard output, shows: up to [`SHOWN`] lines in all.
    fn output(&mut self, text: &str) -> Option<String> {
        if self.lines >= SHOWN {
            self.hidden += text.matches('\n').count();
            return None;
        }
        for (at, _) in text.match_indices('\n') {
            self.lines += 1;
            if self.lines >= SHOWN {
                self.hidden += text[at + 1..].matches('\n').count();
                return Some(text[..=at].to_string());
            }
        }
        Some(text.to_string())
    }
    /// The lines `text`, written to standard error, completes, after what was written before.
    fn error(&mut self, text: &str) -> Vec<String> {
        self.partial.push_str(text);
        let mut lines = Vec::new();
        while let Some(at) = self.partial.find('\n') {
            lines.push(self.partial[..at].to_string());
            self.partial.drain(..=at);
        }
        lines
    }
}

/// What an output says of the `count` lines past [`SHOWN`] that it does not show.
fn more_lines(count: usize) -> String {
    format!("… {count} more lines; pipe the output into head, tail or grep to see them")
}

/// Wait `ms` milliseconds.
async fn sleep(ms: i32) {
    let promise = js_sys::Promise::new(&mut |resolve, _| {
        if let Some(window) = web_sys::window() {
            let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms);
        }
    });
    let _ = JsFuture::from(promise).await;
}
/// The path `typed` names from the directory `cwd`: `~` and `~/` from the account's `home`, as
/// a shell expands them. The shell and the Files' location go by it alike.
pub(crate) fn located(cwd: &str, home: &str, typed: &str) -> Result<String, String> {
    let expanded = if typed == "~" {
        home.to_string()
    } else if let Some(rest) = typed.strip_prefix("~/") {
        format!("{home}/{rest}")
    } else {
        typed.into()
    };
    resolve(cwd, &expanded)
}
/// Call `object`'s method `name` with `argument`, as JavaScript would.
fn call(object: &JsValue, name: &str, argument: &JsValue) {
    if let Some(method) = js_sys::Reflect::get(object, &JsValue::from_str(name))
        .ok()
        .and_then(|method| method.dyn_into::<js_sys::Function>().ok())
    {
        let _ = method.call1(object, argument);
    }
}
/// The external process a stage runs. A slash always names an executable, including /usr/bin
/// paths; the kernel resolves it and checks execution permission. External names resolve through PATH.
/// [`Shell::invoke`] runs a single one so, and a pipeline at once with the processes beside it.
fn process(shell: &Shell, args: &[String]) -> Option<(Option<String>, Vec<String>)> {
    let name = args.first()?;
    if name.contains('/') {
        let home = shell.account.home.get_untracked();
        let path = if let Some(rest) = name.strip_prefix("~/") {
            format!("{}/{}", home.trim_end_matches('/'), rest)
        } else {
            name.clone()
        };
        return Some((Some(path), args.to_vec()));
    }
    // Job specifications and browser identity dialogs are shell/UI state, not external argv.
    if (name == "kill" && args.iter().skip(1).any(|arg| arg.starts_with('%')))
        || DIALOGS.contains(&name.as_str())
    {
        return None;
    }
    if commands::find(name).is_some() {
        return None;
    }
    if cli_bin::image(name).is_none() && cli::definition(name).is_some() {
        return None;
    }
    // execvp searches PATH, including commands installed by the user. The engine tries each
    // candidate through ordinary exec authorization; the shell has no applet dispatch table.
    Some((Some(name.clone()), args.to_vec()))
}

pub(crate) fn js_message(error: JsValue) -> String {
    js_sys::Reflect::get(&error, &JsValue::from_str("message"))
        .ok()
        .and_then(|v| v.as_string())
        .or_else(|| error.as_string())
        .unwrap_or_else(|| "Operation failed".into())
}
/// `args`, a command line clap accepts, as web/app.js reads it for the commands it runs itself,
/// with their dialogs: as clap read them, options before operands and -- gone (sudo -ubob is
/// sudo -u bob, vim -- f is vim f). Other commands go as typed, for the server to read.
fn spelled(args: &[String]) -> Result<Vec<String>, String> {
    use cli::{accounts, files, terminal};
    let Some((name, rest)) = args.split_first() else {
        return Ok(Vec::new());
    };
    let mut out = vec![name.clone()];
    let mut option = |on: bool, option: &str, value: Option<String>| {
        if on || value.is_some() {
            out.push(option.into());
        }
        out.extend(value);
    };
    match name.as_str() {
        "sudo" => {
            let sudo = cli::parse::<accounts::Sudo>(rest)?;
            option(false, "-u", sudo.user);
            option(sudo.forget, "-k", None);
            out.extend(spelled(&sudo.command)?);
        }
        "su" => out.extend(cli::parse::<accounts::Su>(rest)?.operands),
        "login" => out.extend(cli::parse::<accounts::Login>(rest)?.user),
        "passwd" => {
            let passwd = cli::parse::<accounts::Passwd>(rest)?;
            option(passwd.force, "--force", None);
            out.extend(passwd.user);
        }
        // Signed out, app.js makes the account; signed in, the server, which reads it again.
        "useradd" => {
            let useradd = cli::parse::<accounts::Useradd>(rest)?;
            option(useradd.short_password, "--short-password", None);
            option(useradd.create_home, "-m", None);
            option(useradd.no_create_home, "-M", None);
            option(false, "-d", useradd.home);
            option(false, "-g", useradd.group);
            option(false, "-G", useradd.groups);
            if useradd.name.starts_with('-') {
                out.push("--".into());
            }
            out.push(useradd.name);
        }
        "vim" => out.push(cli::parse::<files::Vim>(rest)?.file),
        "man" => out.extend(cli::parse::<terminal::Man>(rest)?.command),
        _ => out.extend(rest.iter().cloned()),
    }
    Ok(out)
}
/// `name` in the directory `typed`, as typed: `""` stands for the working directory.
fn joined(typed: &str, name: &str) -> String {
    match typed {
        "" => name.to_string(),
        t if t.ends_with('/') => format!("{t}{name}"),
        t => format!("{t}/{name}"),
    }
}

impl Shell {
    pub fn new(id: u64, account: Account, cwd: String, history: Vec<String>) -> Self {
        let index = history.len();
        Self {
            id,
            account,
            cwd: RwSignal::new(cwd),
            environment: StoredValue::new(std::collections::BTreeMap::new()),
            lines: RwSignal::new(Vec::new()),
            input: RwSignal::new(String::new()),
            busy: RwSignal::new(false),
            history: RwSignal::new(history),
            history_index: RwSignal::new(index),
            completion: RwSignal::new(None),
            completing: RwSignal::new(false),
            completion_status: RwSignal::new(String::new()),
            completion_epoch: RwSignal::new(0),
            completion_offset: RwSignal::new(0),
            cancelled: RwSignal::new(false),
            uploading: RwSignal::new(false),
            recording: RwSignal::new(false),
            choosing: RwSignal::new(false),
            chosen: StoredValue::new_local(None),
            detached: RwSignal::new(false),
            terminal: StoredValue::new_local(None),
            reading: RwSignal::new(false),
            tty_echo: RwSignal::new(true),
            terminal_active: RwSignal::new(false),
            terminal_modes: RwSignal::new((false, false)),
            jobs: StoredValue::new_local(Vec::new()),
            foreground: StoredValue::new_local(None),
            line: StoredValue::new(String::new()),
        }
    }
    fn push(self, line: LogLine) {
        self.lines.update(|l| {
            l.push(line);
            if l.len() > KEPT {
                l.remove(0);
            }
        });
    }
    pub fn log(self, value: impl Into<String>) {
        let value: String = value.into();
        let count = value.lines().count();
        let value = if count > SHOWN {
            let mut kept: String = value.lines().take(SHOWN).collect::<Vec<_>>().join("\n");
            kept.push('\n');
            kept.push_str(&more_lines(count - SHOWN));
            kept
        } else {
            value
        };
        self.push(LogLine::Text(value));
    }
    fn error(self, message: impl AsRef<str>) {
        self.log(message.as_ref());
    }
    /// Learn the account again, which a command may have changed, and let the Files list their
    /// directory again, which it may have changed too.
    /// What a command changed shows: the account, as the kernel says it now, and the Files.
    pub async fn refresh(self) -> Result<(), String> {
        self.refresh_account().await;
        if let Some(files) = crate::files::files() {
            files.refresh();
        }
        Ok(())
    }
    /// The account, as the kernel says it now (getcreds): every tab's, as the browser session
    /// is.
    pub async fn refresh_account(self) {
        if let Ok(creds) =
            userland::sys::call::<abi::Creds>(&crate::sys::HttpSys::default(), abi::Call::Getcreds)
                .await
        {
            self.account.writable.set(creds.signed_in);
            self.account.username.set(creds.user);
            self.account.home.set(creds.home);
        }
    }
    pub fn path(self, value: &str) -> Result<String, String> {
        located(
            &self.cwd.get_untracked(),
            &self.account.home.get_untracked(),
            value,
        )
    }
    fn cancelled(self) -> bool {
        self.cancelled.get_untracked()
    }

    /// Ask the server, through web/app.js, which handles sudo and the commands that need
    /// dialogs.
    async fn call(self, args: &[String]) -> Result<Value, String> {
        // What clap would refuse goes no further, whether app.js or the server runs it.
        cli::check(args)?;
        let args = &spelled(args)?;
        let value = JsFuture::from(account_command(
            serde_wasm_bindgen::to_value(args).map_err(|e| e.to_string())?,
            &self.cwd.get_untracked(),
        ))
        .await
        .map_err(js_message)?;
        serde_wasm_bindgen::from_value(value).map_err(|e| e.to_string())
    }
    /// What a server command's reply wrote.
    fn output(self, value: &Value) -> Output {
        let mut out = Output::default();
        if let Some(home) = value["home"].as_str() {
            self.cwd.set(home.into());
            set_directory(home);
        }
        if let Some(errors) = value["errors"].as_array() {
            for error in errors {
                self.error(error.as_str().unwrap_or_default());
            }
            out.failed = true;
        }
        if let Some(text) = value["output"].as_str() {
            out.stdout = text.into();
            if !text.is_empty() && !text.ends_with(['\n', '\0']) {
                out.stdout.push('\n');
            }
        }
        out
    }
    async fn manage(self, args: &[String], piped: bool) -> Result<Output, String> {
        let sudo = args.first().is_some_and(|a| a == "sudo");
        let argv = &args[usize::from(sudo)..];
        let value = self.call(args).await?;
        // Not one of web/app.js's dialogs: a program of user space.
        if value["program"] == true {
            return self
                .bin((Some(argv[0].clone()), argv.to_vec()), None, piped, sudo)
                .await;
        }
        let out = self.output(&value);
        self.refresh().await?;
        Ok(out)
    }
    /// The jobs of this account, and the files this browser is writing (its descriptors, as
    /// /proc/self/fd lists them), or, given `jobs cancel ID`, cancel that one: a job, or a
    /// descriptor (`fdN`), closed, which completes a recording with what arrived and leaves an
    /// upload, removed if it was making the file.
    async fn jobs(self, cancel: Option<&str>) -> Result<Output, String> {
        use abi::O_APPEND;
        use userland::procs::{Descriptor, descriptors, processes};
        let sys = crate::sys::HttpSys::default();
        // The archive processes (zip, unzip, tar, faststart), by their long ids: the numbered
        // processes of the browser's namespace are ps's to list, and the terminal's jobs its own.
        let jobs: Vec<_> = processes(&sys)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|process| !process.pid.bytes().all(|b| b.is_ascii_digit()))
            .collect();
        // Uploads and recordings: descriptors writing files, not a process's standard input
        // (/proc/PID/fd/0) nor a device.
        let fds: Vec<Descriptor> = descriptors(&sys)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|fd| {
                fd.flags & 3 != 0 && !fd.path.starts_with("/proc/") && !fd.path.starts_with("/dev/")
            })
            .collect();
        let recording = |fd: &Descriptor| fd.flags & O_APPEND != 0;
        match cancel {
            None => {
                // The terminal's own jobs first, as a shell lists them.
                let mut text: String = self
                    .job_lines()
                    .into_iter()
                    .map(|line| line + "\n")
                    .collect();
                for job in &jobs {
                    text.push_str(&format!(
                        "{}  {:<10} {}  {}/{}\n",
                        job.pid.get(..8).unwrap_or(&job.pid),
                        job.state,
                        job.command(),
                        job.done,
                        job.total,
                    ));
                }
                for fd in &fds {
                    let id = format!("fd{}", fd.fd);
                    // A recording has as many bytes as have arrived, and grows.
                    if recording(fd) {
                        text.push_str(&format!(
                            "{id:<8}  recording  {}  {}\n",
                            fd.path,
                            crate::viewer::size(fd.size)
                        ));
                        continue;
                    }
                    text.push_str(&format!(
                        "{id:<8}  uploading  {}  {}%\n",
                        fd.path,
                        fd.received * 100 / fd.size.max(1),
                    ));
                }
                if text.is_empty() {
                    text = "No jobs or unfinished uploads\n".into();
                }
                Ok(Output::text(text))
            }
            Some(wanted) => {
                if let Some(job) = jobs.iter().find(|job| job.pid.starts_with(wanted)) {
                    userland::sys::call::<Value>(
                        &sys,
                        Call::Kill {
                            pid: job.pid.clone(),
                            signal: None,
                        },
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                    Ok(Output::text(format!(
                        "Cancelling job {}\n",
                        job.pid.get(..8).unwrap_or(&job.pid)
                    )))
                } else if let Some(fd) = fds.iter().find(|fd| format!("fd{}", fd.fd) == wanted) {
                    let mut calls = vec![Call::Close { fd: fd.fd.into() }];
                    if fd.created && !recording(fd) {
                        calls.push(Call::Unlink {
                            path: fd.path.clone(),
                        });
                    }
                    userland::sys::calls::<Value>(&sys, calls).await;
                    self.refresh().await?;
                    // A recording stops, keeping what arrived; an upload is cancelled.
                    Ok(Output::text(if recording(fd) {
                        format!(
                            "Stopped the recording of {}; what arrived is kept\n",
                            fd.path
                        )
                    } else {
                        format!("Cancelled the upload of {}\n", fd.path)
                    }))
                } else {
                    Err(format!("jobs: no job or upload {wanted}"))
                }
            }
        }
    }
    /// Run coreutils' utility `args[0]` (a name the terminal has no program of its own for, or
    /// `coreutils NAME`), as a process of its own: what it writes goes on, its errors to the
    /// transcript. Ctrl+C kills it.
    pub async fn bin(
        self,
        stage: (Option<String>, Vec<String>),
        stdin: Option<String>,
        piped: bool,
        sudo: bool,
    ) -> Result<Output, String> {
        self.processes(
            vec![stage],
            stdin.clone(),
            stdin.is_none(),
            piped,
            sudo,
            None,
        )
        .await
    }
    /// Run `stages`, each a utility of coreutils and its arguments, or an image by its path, as
    /// a pipeline of processes (web/wasi/exec.mjs), given `stdin`, or reading the terminal if
    /// `terminal` says so: the lines typed then go to the first, and Ctrl+D ends its reads. What
    /// the last writes goes on if `piped`, of which its reader takes `enough` lines, if it says;
    /// to the transcript otherwise, as it writes it. What any writes to standard error goes to
    /// the transcript, a line at a time. Ctrl+C kills them; Ctrl+Z stops them, and they are a
    /// job of the terminal's from then on (shell/jobs.rs).
    pub async fn processes(
        self,
        stages: Vec<(Option<String>, Vec<String>)>,
        stdin: Option<String>,
        terminal: bool,
        piped: bool,
        sudo: bool,
        enough: Option<usize>,
    ) -> Result<Output, String> {
        let launched = self.launch(stages, stdin, terminal, piped, sudo, enough);
        let Launched {
            exec,
            handlers,
            run,
            shown,
            names,
            execed,
        } = launched;
        let (stopping, stopped) = oneshot::channel();
        self.foreground.set_value(Some(jobs::Foreground {
            group: run.group.borrow().clone(),
            stopped: stopping,
        }));
        let exited = match select(exec, stopped).await {
            Either::Left((exited, _)) => exited,
            Either::Right((Err(_), exec)) => exec.await,
            // Ctrl+Z: a job, stopped, which goes on, and ends, apart from this line.
            Either::Right((Ok(()), exec)) => {
                run.foreground.set(false);
                call(&run.group.borrow(), "foreground", &JsValue::FALSE);
                run.live.set(false);
                let reading = self.reading.get_untracked();
                self.attach_terminal(None);
                self.reading.set(false);
                let command = self.line.get_value();
                let number = self.add_job(command.clone(), &run, jobs::State::Stopped, reading);
                self.log(format!("[{number}]+  {:<24}{command}", "Stopped"));
                spawn_local(async move {
                    let exited = exec.await;
                    drop(handlers);
                    let status = self
                        .ended_run(exited, shown, names, execed)
                        .await
                        .map_or(1, |(status, _)| status);
                    self.job_ended(number, status);
                });
                return Ok(Output {
                    failed: true,
                    ..Default::default()
                });
            }
        };
        self.foreground.set_value(None);
        self.attach_terminal(None);
        self.reading.set(false);
        drop(handlers);
        let (status, stdout) = self.ended_run(exited, shown, names, execed).await?;
        Ok(Output {
            stdout,
            failed: status != 0,
        })
    }
    /// Run `line`, ended with `&`, as a job in the background: a pipeline of /usr/bin's programs,
    /// or uploaded ones, which reads nothing of the terminal's and whose output still shows; the
    /// line says `[N] PID`, and the job's end says how it ended.
    async fn start_job(self, line: String) {
        let stages = match grammar::words(&line) {
            Ok(stages) => stages,
            Err(error) => return self.error(error),
        };
        let mut run = Vec::new();
        for words in stages {
            let args = match self.expand(words).await {
                Ok(args) => args,
                Err(error) => return self.error(error),
            };
            match process(&self, &args) {
                Some(stage) => run.push(stage),
                None => {
                    let name = args.first().cloned().unwrap_or_default();
                    return self.error(format!(
                        "{name}: & runs programs of /usr/bin, or uploaded ones, in the background; {name} is the terminal's own"
                    ));
                }
            }
        }
        let Launched {
            exec,
            handlers,
            run,
            shown,
            names,
            execed,
        } = self.launch(run, Some(String::new()), false, false, false, None);
        run.foreground.set(false);
        call(&run.group.borrow(), "foreground", &JsValue::FALSE);
        run.live.set(false);
        let number = self.add_job(line, &run, jobs::State::Running, false);
        let said = RwSignal::new(format!("[{number}]"));
        self.push(LogLine::Live(said));
        spawn_local(async move {
            // `[N] PID`, the last's, once its processes have pids.
            let mut exec = exec;
            let exited = loop {
                let pids = jobs::pids(&run.group.borrow());
                if let Some(pid) = pids.last() {
                    said.set(format!("[{number}] {pid}"));
                    break exec.await;
                }
                match select(exec, Box::pin(sleep(30))).await {
                    Either::Left((exited, _)) => break exited,
                    Either::Right((_, rest)) => exec = rest,
                }
            };
            drop(handlers);
            let status = self
                .ended_run(exited, shown, names, execed)
                .await
                .map_or(1, |(status, _)| status);
            self.job_ended(number, status);
        });
    }
    /// Start the pipeline `stages` (as [`Shell::processes`] says): what to await, the handlers
    /// that must outlive it, and what it shares with the job it may become.
    fn launch(
        self,
        stages: Vec<(Option<String>, Vec<String>)>,
        stdin: Option<String>,
        terminal: bool,
        piped: bool,
        sudo: bool,
        enough: Option<usize>,
    ) -> Launched {
        let set = |options: &js_sys::Object, key: &str, value: JsValue| {
            let _ = js_sys::Reflect::set(options, &JsValue::from_str(key), &value);
        };
        let options = js_sys::Object::new();
        set(&options, "terminalId", self.id.to_string().into());
        set(&options, "cwd", self.cwd.get_untracked().into());
        set(&options, "home", self.account.home.get_untracked().into());
        let environment = js_sys::Object::new();
        for (name, value) in self.environment.get_value() {
            set(&environment, &name, value.into());
        }
        set(&options, "environment", environment.into());
        set(
            &options,
            "user",
            self.account.username.get_untracked().into(),
        );
        // None is the terminal's input; nothing to read is an empty one.
        let stdin = match stdin {
            Some(text) => JsValue::from(text),
            None if terminal => JsValue::NULL,
            None => JsValue::from(""),
        };
        set(&options, "stdin", stdin);
        set(&options, "sudo", sudo.into());
        set(&options, "tty", (!piped).into());
        if let Some(enough) = enough {
            set(&options, "enough", (enough as f64).into());
        }
        // A run may become a job: it shares its group, the terminal's input, and whether it is
        // in the foreground, with the job. Ctrl+C ends it only in the foreground.
        let run = jobs::Run::new();
        let cancelled = Closure::<dyn Fn() -> bool>::new({
            let foreground = run.foreground.clone();
            move || foreground.get() && self.cancelled()
        });
        set(&options, "cancelled", cancelled.as_ref().clone());
        let on_job = Closure::<dyn Fn(JsValue)>::new({
            let group = run.group.clone();
            move |given: JsValue| *group.borrow_mut() = given
        });
        set(&options, "onJob", on_job.as_ref().clone());
        // Stopped, or going on, as its processes say: a kill from elsewhere stops a run in the
        // foreground as Ctrl+Z does, and a job's state shows.
        let on_state = Closure::<dyn Fn(String)>::new({
            let run = run.clone();
            move |state: String| {
                let state = if state == "stopped" {
                    jobs::State::Stopped
                } else {
                    jobs::State::Running
                };
                run.live
                    .set(state == jobs::State::Running && run.foreground.get());
                match run.number.get() {
                    Some(number) => self.job_state(number, state),
                    None if state == jobs::State::Stopped && run.foreground.get() => {
                        self.stopped_elsewhere()
                    }
                    None => {}
                }
            }
        });
        set(&options, "onState", on_state.as_ref().clone());
        // What they write to the terminal shows as they write it: the last's output, a line of
        // the transcript that grows, a new one after anything else shows; errors a line at a time.
        let shown = Rc::new(RefCell::new(Shown::default()));
        let output = Closure::<dyn Fn(u32, String)>::new({
            let shown = shown.clone();
            let run = run.clone();
            move |fd: u32, text: String| {
                let reply = shown.borrow_mut().grid.feed(&text);
                if !reply.is_empty()
                    && let Some(input) = run.input.borrow().clone()
                {
                    call(&input, "reply", &reply.into());
                }
                let modes = shown.borrow();
                if run.foreground.get() {
                    self.terminal_modes
                        .set((modes.grid.application_cursor, modes.grid.bracketed_paste));
                }
                drop(modes);
                if shown.borrow().grid.addressed {
                    let mut shown = shown.borrow_mut();
                    let screen = match shown.screen {
                        Some(screen) => {
                            if run.foreground.get() {
                                self.lines.update(|lines| {
                                    if !matches!(lines.last(), Some(LogLine::Screen(last, _)) if *last == screen) {
                                        lines.retain(|line| !matches!(line, LogLine::Screen(old, _) if *old == screen));
                                        lines.push(LogLine::Screen(screen, run.live));
                                    }
                                });
                            }
                            screen
                        }
                        None => {
                            let screen = RwSignal::new(shown.grid.clone());
                            let live = run.live;
                            shown.partial.clear();
                            // A partial line becomes the same program's cursor grid.
                            if let Some(line) = shown.line {
                                self.lines.update(|lines| lines.retain(|entry| !matches!(entry, LogLine::Live(old) if *old == line)));
                            }
                            self.push(LogLine::Screen(screen, live));
                            shown.screen = Some(screen);
                            shown.live = Some(live);
                            screen
                        }
                    };
                    screen.set(shown.grid.clone());
                    return;
                }
                let text = text.replace('\r', "");
                if fd == 2 {
                    let lines = shown.borrow_mut().error(&text);
                    for line in lines {
                        self.error(line);
                    }
                    return;
                }
                // NULs end lines, as the transcript shows any stage's output.
                let Some(text) = shown.borrow_mut().output(&text.replace('\0', "\n")) else {
                    return;
                };
                let current = shown.borrow().line;
                let live = self.lines.with_untracked(
                    |lines| matches!(lines.last(), Some(LogLine::Live(line)) if Some(*line) == current),
                );
                let line = match current {
                    Some(line) if live => line,
                    _ => {
                        let line = RwSignal::new(String::new());
                        self.push(LogLine::Live(line));
                        shown.borrow_mut().line = Some(line);
                        line
                    }
                };
                line.update(|line| line.push_str(&text));
            }
        });
        set(&options, "onOutput", output.as_ref().clone());
        // The terminal's input is the job's to keep; only the run in the foreground has it.
        let tty = Closure::<dyn Fn(JsValue)>::new({
            let run = run.clone();
            let shown = shown.clone();
            move |input: JsValue| {
                let input = (!input.is_null() && !input.is_undefined()).then_some(input);
                *run.input.borrow_mut() = input.clone();
                if input.is_some() {
                    let mut shown = shown.borrow_mut();
                    shown.grid.addressed = true;
                    if shown.screen.is_none() && run.foreground.get() {
                        let screen = RwSignal::new(shown.grid.clone());
                        shown.screen = Some(screen);
                        shown.live = Some(run.live);
                        self.push(LogLine::Screen(screen, run.live));
                    }
                }
                if run.foreground.get() {
                    if input.is_none() {
                        self.reading.set(false);
                    }
                    self.attach_terminal(input);
                }
            }
        });
        set(&options, "onTty", tty.as_ref().clone());
        let mode = Closure::<dyn Fn(JsValue)>::new({
            let foreground = run.foreground.clone();
            move |value: JsValue| {
                if foreground.get() {
                    self.tty_echo.set(
                        js_sys::Reflect::get(&value, &"echo".into())
                            .ok()
                            .and_then(|v| v.as_bool())
                            .unwrap_or(true),
                    );
                }
            }
        });
        set(&options, "onMode", mode.as_ref().clone());
        let size = Closure::<dyn Fn(JsValue)>::new({
            let shown = shown.clone();
            move |value: JsValue| {
                let number = |name: &str| {
                    js_sys::Reflect::get(&value, &name.into())
                        .ok()
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0) as usize
                };
                let mut shown = shown.borrow_mut();
                shown.grid.resize(number("columns"), number("rows"));
                if let Some(screen) = shown.screen {
                    screen.set(shown.grid.clone());
                }
            }
        });
        set(&options, "onSize", size.as_ref().clone());
        let reading = Closure::<dyn Fn()>::new({
            let shown = shown.clone();
            let foreground = run.foreground.clone();
            move || {
                // A prompt written to standard error, its line not ended, shows as it waits.
                let prompt = std::mem::take(&mut shown.borrow_mut().partial);
                if !prompt.is_empty() {
                    self.error(prompt);
                }
                if foreground.get() {
                    self.reading.set(true);
                }
            }
        });
        set(&options, "onReading", reading.as_ref().clone());
        let names: Vec<String> = stages.iter().map(|(_, args)| args[0].clone()).collect();
        // An uploaded program's writes are its own: refresh after one ran, as after coreutils'.
        let execed = stages.iter().any(|(path, _)| path.is_some());
        let argvs = js_sys::Array::new();
        for (path, args) in stages {
            let stage = js_sys::Object::new();
            if let Some(path) = path {
                set(&stage, "path", path.into());
            }
            set(
                &stage,
                "argv",
                args.into_iter()
                    .map(JsValue::from)
                    .collect::<js_sys::Array>()
                    .into(),
            );
            argvs.push(&stage);
        }
        let exec = JsFuture::from(crate::exec(&argvs, &options.into()));
        Launched {
            exec,
            handlers: Box::new((
                cancelled, on_job, on_state, output, tty, reading, mode, size,
            )),
            run,
            shown,
            names,
            execed,
        }
    }
    /// What a run of processes left, once it ended: the last's status and what it wrote if not
    /// to the terminal; what is left of an error line, and how much output was not shown, said.
    async fn ended_run(
        self,
        exited: Result<JsValue, JsValue>,
        shown: Rc<RefCell<Shown>>,
        names: Vec<String>,
        execed: bool,
    ) -> Result<(i32, String), String> {
        if let Some(live) = shown.borrow().live {
            live.set(false);
        }
        if shown.borrow().grid.runs(false).is_empty()
            && let Some(screen) = shown.borrow().screen
        {
            self.lines.update(|lines| {
                lines.retain(|entry| !matches!(entry, LogLine::Screen(old, _) if *old == screen))
            });
        }
        let exited = exited.map_err(js_message)?;
        let Shown {
            line,
            hidden,
            partial,
            ..
        } = shown.take();
        if !partial.is_empty() {
            self.error(partial);
        }
        if hidden > 0
            && let Some(line) = line
        {
            line.update(|line| {
                line.truncate(line.trim_end_matches('\n').len());
                line.push('\n');
                line.push_str(&more_lines(hidden));
            });
        }
        let field = |key: &str| js_sys::Reflect::get(&exited, &JsValue::from_str(key)).ok();
        let status = field("status").and_then(|v| v.as_f64()).unwrap_or(1.0) as i32;
        let stdout = field("stdout")
            .and_then(|v| v.as_string())
            .unwrap_or_default();
        let name = names.last().cloned().unwrap_or_default();
        if field("truncated").and_then(|v| v.as_bool()) == Some(true) {
            let name = field("truncatedBy")
                .and_then(|value| serde_wasm_bindgen::from_value::<Vec<String>>(value).ok())
                .filter(|names| !names.is_empty())
                .map(|names| names.join(", "))
                .unwrap_or(name);
            self.error(format!(
                "{name}: output larger than 10 MB was cut short, and {name} stopped"
            ));
        }
        if execed || names.iter().any(|name| cli_bin::writes(name)) {
            self.refresh().await?;
        }
        Ok((status, stdout))
    }
    pub(super) fn attach_terminal(self, input: Option<JsValue>) {
        self.terminal_active.set(input.is_some());
        self.input.set(String::new());
        self.tty_echo.set(
            input
                .as_ref()
                .and_then(|input| js_sys::Reflect::get(input, &"echo".into()).ok())
                .and_then(|v| v.as_bool())
                .unwrap_or(true),
        );
        self.terminal.set_value(input);
    }
    /// The DOM input captures typing and IME; the PTY edits and echoes canonical input.
    pub fn typed(self, text: String) {
        if let Some(input) = self.terminal.get_value() {
            call(&input, "write", &text.into());
            self.input.set(String::new());
        } else {
            self.reset_completion();
            self.input.set(text);
        }
    }
    pub fn paste(self, text: String) -> bool {
        let Some(input) = self.terminal.get_value() else {
            return false;
        };
        let text = if self.terminal_modes.get_untracked().1 {
            format!("\x1b[200~{text}\x1b[201~")
        } else {
            text
        };
        call(&input, "write", &text.into());
        true
    }
    pub fn terminal_key(self, event: &web_sys::KeyboardEvent) -> bool {
        let Some(input) = self.terminal.get_value() else {
            return false;
        };
        let Some(text) = crate::terminal::key(event, self.terminal_modes.get_untracked().0) else {
            return false;
        };
        call(&input, "write", &text.into());
        true
    }
    /// Send control bytes through termios, including canonical EOF and raw Ctrl+D.
    pub fn send_terminal(self, text: &str) -> bool {
        let Some(input) = self.terminal.get_value() else {
            return false;
        };
        call(&input, "write", &text.into());
        true
    }
    pub fn end_of_input(self) -> bool {
        self.send_terminal("\x04")
    }
    /// Whether the account may act as root now: sudo's password, asked for if it has not been
    /// lately.
    pub async fn authenticated(self) -> Result<bool, String> {
        let allowed = JsFuture::from(sudo()).await.map_err(js_message)?;
        Ok(allowed.as_bool() == Some(true))
    }
    /// Run one command, with what the previous stage wrote, if any. `piped`: whether its output
    /// goes on to another stage, rather than to the transcript.
    pub fn invoke(
        self,
        args: Vec<String>,
        stdin: Option<String>,
        piped: bool,
    ) -> LocalBoxFuture<'static, Result<Output, String>> {
        async move {
            let Some(name) = args.first().cloned() else {
                return Ok(Output::default());
            };
            // External programs own their arguments, help and errors. Paths must reach exec
            // before any frontend command interpretation, including a nested xargs/fd stage.
            if let Some(stage) = process(&self, &args) {
                return self.bin(stage, stdin, piped, false).await;
            }
            let mut args = args;
            // Help is the tab's, made from the command's definition: nothing is asked of the
            // server. Under sudo, it is the command sudo runs that is asked about.
            if cli::wants_help(&args) {
                let asked = match args.get(1) {
                    Some(command) if name == "sudo" && !command.starts_with('-') => command,
                    _ => &name,
                };
                if let Some(help) = cli::help(asked) {
                    return Ok(Output::text(help + "\n"));
                }
            }
            // kill %N: the job's processes, signalled here at once, and named by their pids to
            // the program, which tells the kernel.
            if name == "kill" && args.iter().skip(1).any(|arg| arg.starts_with('%')) {
                match self.kill_jobs(args)? {
                    Some(rest) => args = rest,
                    None => return Ok(Output::default()),
                }
                if let Some(stage) = process(&self, &args) {
                    return self.bin(stage, stdin, piped, false).await;
                }
            }
            // A guest's own useradd and an account's own userdel take a password, in web/app.js's
            // dialog, which hands back what is not that to run here.
            match commands::find(&name) {
                Some(command) => command.run(self, args, stdin, piped).await,
                // What the server runs, or web/app.js with its dialogs.
                None if cli::definition(&name).is_some() => self.manage(&args, piped).await,
                None => Err(format!("Unknown command: {name}. Enter help for commands.")),
            }
        }
        .boxed_local()
    }

    /// The line `line`, entered on the command line: the input of the process reading the
    /// terminal, if one may, echoed as a terminal's line discipline echoes it; else the pipeline
    /// to run. Buttons run theirs with [`Shell::run`], which gives a process nothing.
    pub fn enter(self, line: String) {
        let Some(input) = self.terminal.get_value() else {
            return self.run(line);
        };
        self.input.set(String::new());
        self.reading.set(false);
        call(&input, "write", &format!("{line}\r").into());
    }

    /// Run the pipeline `command`, typed into this tab.
    pub fn run(self, command: String) {
        if self.busy.get_untracked() || command.trim().is_empty() {
            return;
        }
        if let Ok(words) = split_command(&command)
            && words
                .iter()
                .any(|a| a.starts_with("-p") || a.starts_with("--password"))
            && words.iter().any(|a| a == "usermod" || a == "useradd")
        {
            self.input.set(String::new());
            self.log("Passwords cannot be command arguments; use passwd [USER] and enter the password in the dialog.");
            return;
        }
        // Phones open a file chooser only while the tap or key that asked is fresh, before any
        // request is awaited: an upload line chooses its files now.
        if split_command(&command).is_ok_and(|words| words.first().is_some_and(|w| w == "upload"))
            && self.chosen.with_value(Option::is_none)
        {
            self.chosen.set_value(Some(choose_files()));
        }
        self.reset_completion();
        self.input.set(String::new());
        self.push(LogLine::Command {
            user: self.account.username.get_untracked(),
            cwd: self.cwd.get_untracked(),
            command: command.clone(),
        });
        self.history.update(|h| h.push(command.clone()));
        self.history_index
            .set(self.history.with_untracked(Vec::len));
        // `&` at its end: a job in the background, and the line is the shell's again at once.
        if let Some(line) = grammar::background(&command) {
            spawn_local(self.start_job(line.to_string()));
            return;
        }
        self.line.set_value(command.clone());
        self.busy.set(true);
        self.cancelled.set(false);
        spawn_local(async move {
            match grammar::words(&command) {
                Ok(stages) => self.pipeline(stages).await,
                Err(e) => self.error(e),
            }
            self.busy.set(false);
            self.cancelled.set(false);
            crate::persist();
            crate::focus_input();
        });
    }
    /// The previous command in the history, or with `up` false the next, into the command line.
    pub fn recall(self, up: bool) {
        self.reset_completion();
        let len = self.history.with_untracked(Vec::len);
        let index = self.history_index.get_untracked();
        let index = if up {
            index.saturating_sub(1)
        } else {
            (index + 1).min(len)
        };
        self.history_index.set(index);
        self.input.set(
            self.history
                .with_untracked(|h| h.get(index).cloned().unwrap_or_default()),
        );
    }
    /// Upload `files`, dropped on the page, as the upload command does, into this tab's directory.
    pub fn upload_dropped(self, files: JsValue) {
        if self.busy.get_untracked() {
            self.error("A command is running in this tab; drop the files again when it ends");
            return;
        }
        self.chosen
            .set_value(Some(js_sys::Promise::resolve(&files)));
        self.run("upload".into());
    }
    async fn pipeline(self, mut stages: Vec<Vec<Word>>) {
        let last = stages.len().saturating_sub(1);
        let mut stdin = None;
        // A stage expanded ahead, as a run of processes was looked for its end.
        let mut ahead = None;
        let mut index = 0;
        while index <= last && !stages.is_empty() {
            // Wildcards expand as the stage starts, as a shell expands them.
            let mut args = match ahead.take() {
                Some(args) => args,
                None => self.expand(std::mem::take(&mut stages[index])).await,
            };
            if self.cancelled() {
                break;
            }
            // Fish-style implicit cd: a single directory operand is enough. Existing command
            // names keep precedence; a trailing slash explicitly names a directory.
            if last == 0
                && let Ok(words) = &args
                && words.len() == 1
            {
                let name = &words[0];
                let known = cli::definition(name).is_some()
                    || cli_bin::program(name).is_some()
                    || name == "coreutils";
                if !known
                    && let Ok(path) = self.path(name)
                    && crate::stat(&path).await.is_ok_and(|stat| stat.is_dir())
                {
                    args = Ok(vec!["cd".into(), "--".into(), name.clone()]);
                }
            }
            let first = index == 0;
            // A run of processes runs at once, each reading the one before through a pipe; the
            // first of a line reads the terminal.
            let mut run = Vec::new();
            if let Ok(args) = &args
                && let Some(stage) = process(&self, args)
            {
                run.push(stage);
                while index < last {
                    let next = self.expand(std::mem::take(&mut stages[index + 1])).await;
                    match next.as_ref().ok().and_then(|args| process(&self, args)) {
                        Some(stage) => {
                            run.push(stage);
                            index += 1;
                        }
                        None => {
                            ahead = Some(next);
                            break;
                        }
                    }
                }
            }
            let piped = index < last;
            let result = match args {
                Ok(_) if !run.is_empty() => {
                    self.processes(run, stdin.take(), first, piped, false, None)
                        .await
                }
                Ok(args) => self.invoke(args, stdin.take(), piped).await,
                Err(e) => Err(e),
            };
            index += 1;
            match result {
                Ok(out) if piped => {
                    let mut text = out.stdout;
                    if text.len() > PIPED_MAX {
                        self.error("Output larger than 10 MB was cut short for the next command");
                        let mut end = PIPED_MAX;
                        while !text.is_char_boundary(end) {
                            end -= 1;
                        }
                        text.truncate(end);
                    }
                    stdin = Some(text);
                }
                Ok(out) => {
                    let text = out.stdout.replace('\0', "\n");
                    let text = text.trim_end_matches('\n');
                    if !text.is_empty() {
                        self.log(text);
                    }
                }
                Err(e) => {
                    self.error(e);
                    // Like a shell, the next stage still runs, reading nothing.
                    stdin = Some(String::new());
                }
            }
        }
    }
    /// The arguments `words` stand for: each word's wildcards expanded to the paths they match,
    /// sorted, or the word as it is if they match none, as a shell leaves it.
    async fn expand(self, words: Vec<Word>) -> Result<Vec<String>, String> {
        let mut args = Vec::new();
        for word in words {
            let Some(pattern) = word.pattern else {
                args.push(word.text);
                continue;
            };
            let mut paths = self.glob(&pattern).await?;
            if paths.is_empty() {
                args.push(word.text);
            } else {
                paths.sort();
                args.append(&mut paths);
            }
            if args.len() > GLOB_PATHS {
                return Err(format!("{}: Argument list too long", args[0]));
            }
        }
        Ok(args)
    }
    /// The paths `pattern` matches, as typed: relative ones stay relative. A directory that
    /// cannot be listed matches nothing; a pattern ending in `/` matches directories. The
    /// lookups for one part of the pattern run a few at a time.
    async fn glob(self, pattern: &str) -> Result<Vec<String>, String> {
        let parts = glob::parts(pattern);
        // Brackets that close no set: a name, which the word stands for as it is.
        if !parts.iter().any(|part| matches!(part, Part::Pattern(_))) {
            return Ok(Vec::new());
        }
        let directories = pattern.ends_with('/');
        let mut found = vec![if pattern.starts_with('/') { "/" } else { "" }.to_string()];
        let mut lookups = 0;
        // Before the first pattern, names need no looking up; after it, they must exist.
        let mut looked_up = false;
        for (index, part) in parts.iter().enumerate() {
            let last = index + 1 == parts.len();
            let navigation =
                matches!(part, Part::Name(name) if matches!(name.as_str(), "." | ".."));
            // Except `..`, which leaves a directory: it needs search permission there, even
            // before the first pattern, since resolving it removes that directory from the path.
            if let Part::Name(name) = part
                && !looked_up
                && name != ".."
            {
                found = found.iter().map(|typed| joined(typed, name)).collect();
                continue;
            }
            lookups += found.len() * if navigation && looked_up { 2 } else { 1 };
            if lookups > GLOB_LOOKUPS {
                return Err(format!("{pattern}: the pattern searches too many paths"));
            }
            let lookup = move |typed: String| async move {
                if self.cancelled() {
                    return Vec::new();
                }
                // A path this terminal cannot name (a backslash, too deep) matches nothing.
                let Ok(directory) = self.path(if typed.is_empty() { "." } else { &typed }) else {
                    return Vec::new();
                };
                match part {
                    Part::Name(name) => {
                        // Literal names need search permission, not a listing. Dot components
                        // are not listing entries; check traversal before resolving them away.
                        if navigation && crate::enterable(&directory).await.is_err() {
                            return Vec::new();
                        }
                        let target = joined(&typed, name);
                        if !looked_up {
                            return vec![target];
                        }
                        let Ok(path) = self.path(&target) else {
                            return Vec::new();
                        };
                        match crate::stat(&path).await {
                            Ok(node) if node.is_dir() || last && !directories => vec![target],
                            _ => Vec::new(),
                        }
                    }
                    Part::Pattern(pattern) => match listing(&directory).await {
                        Ok(entries) => entries
                            .into_iter()
                            .filter(|entry| {
                                glob::matches(pattern, &entry.name)
                                    && (entry.directory || last && !directories)
                            })
                            .map(|entry| joined(&typed, &entry.name))
                            .collect(),
                        Err(_) => Vec::new(),
                    },
                }
            };
            found = futures::stream::iter(found)
                .map(lookup)
                .buffered(GLOB_CONCURRENCY)
                .collect::<Vec<_>>()
                .await
                .into_iter()
                .flatten()
                .collect();
            looked_up |= matches!(part, Part::Pattern(_));
            if self.cancelled() {
                return Ok(Vec::new());
            }
            if found.is_empty() {
                break;
            }
        }
        if directories {
            for path in &mut found {
                path.push('/');
            }
        }
        Ok(found)
    }
    /// The tab is closing: stop its browser work at the next step, but leave its server jobs
    /// running.
    pub fn detach(self) {
        self.detached.set(true);
        self.cancelled.set(true);
        if self.choosing.get_untracked() {
            cancel_choosing();
        }
    }
    /// Ctrl+C: clear the line, and stop what this tab is running at its next step.
    pub fn interrupt(self) {
        self.reset_completion();
        self.input.set(String::new());
        self.history_index
            .set(self.history.with_untracked(Vec::len));
        if self.busy.get_untracked() && !self.cancelled.get_untracked() {
            self.cancelled.set(true);
            if self.uploading.get_untracked() {
                cancel_uploads();
            }
            if self.recording.get_untracked() {
                stop_recording();
            }
            if self.choosing.get_untracked() {
                cancel_choosing();
            }
            // A command waiting for an answer gets none.
            self.log("^C");
        }
    }

    pub fn reset_completion(self) {
        self.completion_epoch.update(|epoch| *epoch += 1);
        self.completion.set(None);
        self.completing.set(false);
        self.completion_status.set(String::new());
    }
    pub fn select_completion(self, index: usize) {
        if let Some(mut session) = self.completion.get_untracked() {
            let index = index % session.candidates.len();
            session.selected = Some(index);
            let candidate = &session.candidates[index];
            let value = candidate.value.clone();
            let cursor = value[..candidate.cursor].encode_utf16().count() as u32;
            self.input.set(value.clone());
            self.completion.set(Some(session));
            completion_focus(&value, cursor);
        }
    }
    pub fn accept_completion(self) {
        let cursor = self.completion.with_untracked(|s| {
            s.as_ref().map(|s| {
                s.selected
                    .map_or(s.cursor, |index| s.candidates[index].cursor)
            })
        });
        let value = self.input.get_untracked();
        self.reset_completion();
        if let Some(cursor) = cursor {
            completion_focus(&value, value[..cursor].encode_utf16().count() as u32);
        }
    }
    pub fn cancel_completion(self) {
        if let Some(session) = self.completion.get_untracked() {
            self.input.set(session.original.clone());
            completion_focus(
                &session.original,
                session.original[..session.original_cursor]
                    .encode_utf16()
                    .count() as u32,
            );
        }
        self.reset_completion();
    }
    fn finish_completion(
        self,
        original: String,
        cwd: String,
        mut candidates: Vec<Candidate>,
        cursor: usize,
    ) {
        self.completing.set(false);
        if candidates.is_empty() {
            self.completion_status.set("No matches".into());
            return;
        }
        self.completion_status.set(String::new());
        let (start, end) = completion::token_span(&original, cursor);
        let suffix = &original[end..];
        let mut baseline = completion::common_prefix(&original[..cursor], &candidates);
        let baseline_cursor = baseline.len();
        // Preserve the closing quote when completing inside an existing quoted token.
        if end > cursor
            && let Some(q @ ('\'' | '"')) = original[start..].chars().next()
            && original[..end].ends_with(q)
            && !baseline.ends_with(q)
        {
            baseline.push(q);
        }
        baseline.push_str(suffix);
        for candidate in &mut candidates {
            if candidate.value.ends_with(' ') && suffix.starts_with(char::is_whitespace) {
                candidate.value.pop();
                candidate.cursor = candidate.value.len();
            }
            candidate.value.push_str(suffix);
        }
        if candidates.len() == 1 {
            let candidate = &candidates[0];
            self.input.set(candidate.value.clone());
            self.completion.set(None);
            completion_focus(
                &candidate.value,
                candidate.value[..candidate.cursor].encode_utf16().count() as u32,
            );
            return;
        }
        let len = candidates.len() as i64;
        let selected = match self.completion_offset.get_untracked() {
            0 => None,
            ahead if ahead > 0 => Some((ahead - 1).rem_euclid(len) as usize),
            back => Some(back.rem_euclid(len) as usize),
        };
        self.input.set(baseline.clone());
        self.completion.set(Some(CompletionSession {
            original,
            cwd,
            candidates,
            baseline: baseline.clone(),
            cursor: baseline_cursor,
            original_cursor: cursor,
            selected: None,
        }));
        match selected {
            Some(index) => self.select_completion(index),
            None => completion_focus(
                &baseline,
                baseline[..baseline_cursor].encode_utf16().count() as u32,
            ),
        }
    }
    pub fn complete(self, backwards: bool) {
        if self.busy.get_untracked() {
            return;
        }
        let step = if backwards { -1 } else { 1 };
        if self.completing.get_untracked() {
            // Multiple Tabs during a slow R2 listing still advance the eventual selection.
            self.completion_offset.update(|index| *index += step);
            return;
        }
        let input = self.input.get_untracked();
        let cwd = self.cwd.get_untracked();
        let utf16_cursor = completion_cursor() as usize;
        let mut utf16 = 0;
        let cursor = input
            .char_indices()
            .find_map(|(at, c)| {
                if utf16 >= utf16_cursor {
                    Some(at)
                } else {
                    utf16 += c.len_utf16();
                    None
                }
            })
            .unwrap_or(input.len());
        if let Some(session) = self.completion.get_untracked()
            && session.cwd == cwd
            && session
                .selected
                .map_or(&session.baseline, |index| &session.candidates[index].value)
                == &input
            && session
                .selected
                .map_or(session.cursor, |index| session.candidates[index].cursor)
                == cursor
        {
            // From the list alone, Tab picks the first, Shift+Tab the last.
            let len = session.candidates.len() as i64;
            let index = match session.selected {
                Some(index) => (index as i64 + step).rem_euclid(len),
                None if backwards => len - 1,
                None => 0,
            };
            self.select_completion(index as usize);
            return;
        }
        self.reset_completion();
        self.completion_offset.set(0);
        let epoch = self.completion_epoch.get_untracked();
        match completion::query(&input[..cursor]) {
            Query::Commands(candidates) => self.finish_completion(input, cwd, candidates, cursor),
            Query::None => self
                .completion_status
                .set("No path completion is available here".into()),
            Query::Paths(mut query) => {
                let directory = match self.path(&query.prefix) {
                    Ok(path) => path,
                    Err(error) => {
                        self.completion_status.set(error);
                        return;
                    }
                };
                self.completing.set(true);
                self.completion_status.set("Loading completions...".into());
                spawn_local(async move {
                    let result = listing(&directory).await;
                    if query.command_position && query.prefix.is_empty() {
                        // Completion uses the same PATH as execution, including relative and
                        // empty entries. Access checks follow links and use the current user.
                        let path = self
                            .environment
                            .get_value()
                            .get("PATH")
                            .cloned()
                            .unwrap_or_else(|| "/usr/bin".into());
                        query.commands.retain(|candidate| {
                            commands::find(&candidate.label).is_some()
                                || cli_bin::image(&candidate.label).is_none()
                        });
                        let mut seen = std::collections::BTreeSet::new();
                        for directory in path.split(':') {
                            let Ok(directory) =
                                self.path(if directory.is_empty() { "." } else { directory })
                            else {
                                continue;
                            };
                            if !seen.insert(directory.clone()) {
                                continue;
                            }
                            let Ok(entries) = listing(&directory).await else {
                                continue;
                            };
                            let matching: Vec<_> = entries
                                .into_iter()
                                .filter(|entry| {
                                    !entry.directory
                                        && entry.mode & 0o111 != 0
                                        && completion::fuzzy_score(&query.needle, &entry.name)
                                            .is_some()
                                })
                                .collect();
                            let checks = userland::sys::calls::<Value>(
                                &crate::sys::HttpSys::default(),
                                matching
                                    .iter()
                                    .map(|entry| Call::Access {
                                        path: entry.path.clone(),
                                        mode: abi::X_OK,
                                    })
                                    .collect(),
                            )
                            .await;
                            for (entry, access) in matching.into_iter().zip(checks) {
                                if access.is_err()
                                    || query
                                        .commands
                                        .iter()
                                        .any(|candidate| candidate.label == entry.name)
                                {
                                    continue;
                                }
                                let value = format!(
                                    "{}{} ",
                                    query.before,
                                    completion::escape_path(&entry.name)
                                );
                                query.commands.push(Candidate {
                                    label: entry.name,
                                    cursor: value.len(),
                                    value,
                                    kind: "command".into(),
                                    descend: true,
                                });
                            }
                        }
                    }
                    // Never let a late request overwrite new typing, history, or a new cwd.
                    if self.completion_epoch.get_untracked() != epoch
                        || self.input.get_untracked() != input
                        || self.cwd.get_untracked() != cwd
                        || completion_cursor() as usize != utf16_cursor
                    {
                        if self.completion_epoch.get_untracked() == epoch {
                            self.completing.set(false);
                            self.completion_status.set(String::new());
                        }
                        return;
                    }
                    match result {
                        Ok(entries) => self.finish_completion(
                            input,
                            cwd,
                            completion::path_candidates(&query, &entries),
                            cursor,
                        ),
                        Err(_) if !query.commands.is_empty() => self.finish_completion(
                            input,
                            cwd,
                            completion::path_candidates(&query, &[]),
                            cursor,
                        ),
                        Err(error) => {
                            self.completing.set(false);
                            self.completion_status.set(error);
                        }
                    }
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::spelled;

    #[test]
    fn app_js_reads_its_commands_as_clap_read_them() {
        let line = |text: &str| text.split(' ').map(String::from).collect::<Vec<_>>();
        let spell = |text: &str| spelled(&line(text)).unwrap().join(" ");
        assert_eq!(spell("sudo -ubob"), "sudo -u bob");
        assert_eq!(spell("sudo -k"), "sudo -k");
        assert_eq!(spell("vim -- -notes.md"), "vim -notes.md");
        assert_eq!(spell("useradd -- ann"), "useradd ann");
        assert_eq!(
            spell("sudo useradd -m -G team,web -- -odd"),
            "sudo useradd -m -G team,web -- -odd"
        );
        assert_eq!(spell("passwd bob --force"), "passwd --force bob");
        assert_eq!(spell("su - bob"), "su - bob");
        assert_eq!(spell("sudo passwd -- bob"), "sudo passwd bob");
        // The server's commands go as typed.
        assert_eq!(spell("sudo rm -rf -- -h"), "sudo rm -rf -- -h");
    }
}

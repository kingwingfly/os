//! One terminal tab: its directory, transcript, history and completion, and the commands it
//! runs. A line is a pipeline: each stage's output is the next one's input. The programs of
//! user space (crates/userland: ls, rm, chmod...) run here, over system calls; so do text
//! filters, xargs and fd -x, and browser interactions such as open and upload. The server
//! still runs what has not moved yet (cp, accounts, archives).

mod commands;

use std::cell::RefCell;
use std::rc::Rc;

use abi::Call;
use futures::channel::oneshot;
use futures::future::LocalBoxFuture;
use futures::{FutureExt, StreamExt};
use leptos::prelude::*;
use serde_json::{Value, json};
use terminal_worker_core::bin as cli_bin;
use terminal_worker_core::completion::{self, Candidate, Query};
use terminal_worker_core::glob::{self, Part};
use terminal_worker_core::shell::{self as grammar, Delimiter, Word};
use terminal_worker_core::{Entry, cli, find, resolve, split_command, text};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::{JsFuture, spawn_local};

use crate::{
    account_command, cancel_choosing, cancel_uploads, choose_files, completion_focus, endpoint,
    focus_input, listing, set_directory, stop_recording, sudo,
};

/// What a program of user space left: its exit status, its output and errors, its listing,
/// and what fd found.
struct Exited {
    status: i32,
    out: String,
    err: Vec<String>,
    view: Option<userland::View>,
    found: Vec<String>,
}

/// The most transcript lines kept, ...
const KEPT: usize = 100;
/// ... the most lines one output shows, ...
const SHOWN: usize = 2000;
/// ... the most bytes passed from one stage to the next, and read from one file.
const PIPED_MAX: usize = 10_000_000;
/// How many paths xargs passes to one command, at most.
const XARGS_MAX: usize = 1000;
/// How many filesystem lookups one wildcard pattern makes, and paths it expands to, at most.
const GLOB_LOOKUPS: usize = 1000;
const GLOB_PATHS: usize = 10_000;
/// How many of a wildcard's lookups run at once.
const GLOB_CONCURRENCY: usize = 8;

#[derive(Clone)]
pub enum LogLine {
    Text(String),
    /// Text that changes as a command goes on, such as an upload's progress.
    Live(RwSignal<String>),
    Command {
        user: String,
        cwd: String,
        command: String,
    },
    Listing {
        entries: Vec<Entry>,
        long: bool,
    },
}

/// What a command wrote: its text, or a view of it, which shows only at the end of a pipeline.
#[derive(Default)]
pub struct Output {
    pub stdout: String,
    pub view: Option<LogLine>,
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
    /// The candidate in the line, if one is: the first Tab only lists them, so that more may be
    /// typed to narrow them down (owner's request, 2026-10-28), unless there is only one.
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
    /// Whether the tab was closed: its browser work stops, but not its server jobs.
    detached: RwSignal<bool>,
    /// The answer a running command waits for, if any.
    prompt: StoredValue<Option<oneshot::Sender<String>>>,
    pub asking: RwSignal<bool>,
    /// The terminal's input, while the running line's first process may read it
    /// (web/wasi/exec.mjs): the lines typed go to it, and Ctrl+D ends a read ...
    terminal: StoredValue<Option<JsValue>, LocalStorage>,
    /// ... which it waits on now.
    pub reading: RwSignal<bool>,
}

/// What a pipeline of processes showed in the transcript as they wrote: the line of the last's
/// output, how many lines it shows (up to [`SHOWN`]) and how many more there were; and the
/// part of an error line written so far.
#[derive(Default)]
struct Shown {
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
/// Call `object`'s method `name` with `argument`, as JavaScript would.
fn call(object: &JsValue, name: &str, argument: &JsValue) {
    if let Some(method) = js_sys::Reflect::get(object, &JsValue::from_str(name))
        .ok()
        .and_then(|method| method.dyn_into::<js_sys::Function>().ok())
    {
        let _ = method.call1(object, argument);
    }
}
/// The process the stage `args` runs, if it is one: a utility of /usr/bin's coreutils the
/// terminal has no program of its own for (by name, by its path, or as `coreutils NAME`), with
/// the arguments it is given. [`Shell::invoke`] runs it so, and a pipeline at once with the
/// processes beside it.
fn process(args: &[String]) -> Option<Vec<String>> {
    let mut args = args.to_vec();
    if let Some(named) = cli_bin::named(args.first()?) {
        args[0] = named.to_string();
    }
    let name = args[0].clone();
    if cli::wants_help(&args) && cli::help(&name).is_some() {
        return None;
    }
    if name == "coreutils" {
        args.remove(0);
        cli_bin::program(args.first()?)?;
        return Some(args);
    }
    let own = commands::find(&name).is_some()
        || cli::definition(&name).is_some()
        || userland::PROGRAMS.contains(&name.as_str());
    (cli_bin::program(&name).is_some() && !own).then_some(args)
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
/// A listing as text, as ls writes into a pipe: one name a line.
fn listing_text(entries: &[Entry], long: bool) -> String {
    entries
        .iter()
        .map(|e| {
            if long {
                format!(
                    "{} {:>2} {} {} {:>8} {} {}{}\n",
                    e.mode_line(),
                    e.links,
                    e.owner,
                    e.group,
                    e.size,
                    crate::listed(e.mtime),
                    e.name,
                    e.link
                        .as_ref()
                        .map(|t| format!(" -> {t}"))
                        .unwrap_or_default()
                )
            } else {
                format!("{}\n", e.name)
            }
        })
        .collect()
}
/// `name` in the directory `typed`, as typed: `""` stands for the working directory.
fn joined(typed: &str, name: &str) -> String {
    match typed {
        "" => name.to_string(),
        t if t.ends_with('/') => format!("{t}{name}"),
        t => format!("{t}/{name}"),
    }
}
/// `-d`'s delimiter: one character, or an escape such as `\n`.
fn parse_delimiter(value: &str) -> Result<char, String> {
    match value {
        "\\n" => Ok('\n'),
        "\\t" => Ok('\t'),
        "\\0" => Ok('\0'),
        _ => {
            let mut chars = value.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) => Ok(c),
                _ => Err(format!(
                    "xargs: invalid delimiter {value}; use one character"
                )),
            }
        }
    }
}

impl Shell {
    pub fn new(id: u64, account: Account, cwd: String, history: Vec<String>) -> Self {
        let index = history.len();
        Self {
            id,
            account,
            cwd: RwSignal::new(cwd),
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
            prompt: StoredValue::new(None),
            asking: RwSignal::new(false),
            terminal: StoredValue::new_local(None),
            reading: RwSignal::new(false),
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
        self.log(format!("! {}", message.as_ref()));
    }
    /// Learn the account again, which a command may have changed, and let the Files list their
    /// directory again, which it may have changed too.
    pub async fn refresh(self) -> Result<(), String> {
        if let Ok(creds) =
            userland::sys::call::<abi::Creds>(&crate::sys::HttpSys::default(), abi::Call::Getcreds)
                .await
        {
            self.account.writable.set(creds.signed_in);
            self.account.username.set(creds.user);
            self.account.home.set(creds.home);
        }
        if let Some(files) = crate::files::files() {
            files.refresh();
        }
        Ok(())
    }
    pub fn path(self, value: &str) -> Result<String, String> {
        let expanded = if value == "~" {
            self.account.home.get_untracked()
        } else if let Some(rest) = value.strip_prefix("~/") {
            format!("{}/{rest}", self.account.home.get_untracked())
        } else {
            value.into()
        };
        resolve(&self.cwd.get_untracked(), &expanded)
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
    fn output(self, value: &Value, piped: bool) -> Result<Output, String> {
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
        if let Some(entries) = value.get("entries") {
            let entries: Vec<Entry> =
                serde_json::from_value(entries.clone()).map_err(|e| e.to_string())?;
            let long = value["long"] == true;
            if piped {
                out.stdout = listing_text(&entries, long);
            } else {
                out.view = Some(LogLine::Listing { entries, long });
            }
        } else if let Some(text) = value["output"].as_str() {
            out.stdout = text.into();
            if !text.is_empty() && !text.ends_with(['\n', '\0']) {
                out.stdout.push('\n');
            }
        }
        Ok(out)
    }
    async fn manage(self, args: &[String], piped: bool) -> Result<Output, String> {
        let sudo = args.first().is_some_and(|a| a == "sudo");
        let argv = &args[usize::from(sudo)..];
        // zip, unzip, tar and faststart are processes (spawn), done apart; the tab follows one.
        if matches!(
            argv.first().map(String::as_str),
            Some("zip" | "unzip" | "tar" | "faststart")
        ) {
            cli::check(argv)?;
            if sudo
                && JsFuture::from(crate::sudo())
                    .await
                    .map_err(js_message)?
                    .as_bool()
                    != Some(true)
            {
                return Err("sudo canceled".into());
            }
            let sys = crate::sys::HttpSys {
                sudo,
                ..Default::default()
            };
            let spawn = abi::Call::Spawn {
                argv: argv.to_vec(),
                cwd: self.cwd.get_untracked(),
            };
            let spawned: Value = userland::sys::call(&sys, spawn)
                .await
                .map_err(|error| error.to_string())?;
            let pid = spawned["pid"].as_str().unwrap_or_default().to_string();
            let stdin = spawned["stdin"].as_u64().unwrap_or(u64::from(u32::MAX)) as u32;
            let followed = self.follow(&pid, stdin, piped).await;
            // Its standard input is let go of as it ends, or as this tab stops following it.
            userland::sys::calls::<Value>(&sys, vec![Call::Close { fd: stdin.into() }]).await;
            return followed;
        }
        let value = self.call(args).await?;
        // Not one of web/app.js's dialogs: a program of user space.
        if value["program"] == true {
            return self.program(argv.to_vec(), None, piped, sudo).await;
        }
        let out = self.output(&value, piped)?;
        self.refresh().await?;
        Ok(out)
    }
    /// Follow the process `id` to its end: write its lines as they come, answer its question in
    /// this tab (its stdin), and signal it on Ctrl+C.
    async fn follow(self, id: &str, stdin: u32, piped: bool) -> Result<Output, String> {
        let sys = crate::sys::HttpSys::default();
        let mut out = Output::default();
        let mut since = 0;
        let mut cancelling = false;
        loop {
            // A closed tab stops following; the process goes on, and jobs lists it.
            if self.detached.get_untracked() {
                return Ok(out);
            }
            if self.cancelled() && !cancelling {
                cancelling = true;
                userland::sys::call::<Value>(&sys, Call::Kill { pid: id.into() })
                    .await
                    .map_err(|error| error.to_string())?;
            }
            let view: Value = userland::sys::call(
                &sys,
                Call::Wait {
                    pid: id.into(),
                    since,
                },
            )
            .await
            .map_err(|error| error.to_string())?;
            for line in view["lines"].as_array().into_iter().flatten() {
                since = line[0].as_u64().unwrap_or(since);
                let text = line[2].as_str().unwrap_or_default();
                if line[1] == true {
                    self.error(text);
                } else if piped {
                    out.stdout.push_str(text);
                    out.stdout.push('\n');
                } else {
                    self.log(text);
                }
            }
            // A page at a time: what a process wrote before it ended is all read before it is
            // taken to have ended.
            if view["more"] == true {
                continue;
            }
            match view["state"].as_str().unwrap_or_default() {
                "done" => {
                    out.failed |= view["progress"]["errors"].as_u64().is_some_and(|e| e > 0);
                    break;
                }
                "failed" | "cancelled" => {
                    out.failed = true;
                    break;
                }
                "question" if !cancelling => {
                    let decisions = self.decide(&view["question"]).await;
                    if self.cancelled() {
                        continue;
                    }
                    // Its answer goes to its standard input.
                    let answer = Call::Pwrite {
                        fd: stdin.into(),
                        index: 0,
                        data: json!({ "decisions": decisions })
                            .to_string()
                            .into_bytes()
                            .into(),
                    };
                    userland::sys::call::<Value>(&sys, answer)
                        .await
                        .map_err(|error| error.to_string())?;
                    continue;
                }
                _ => {}
            }
            sleep(600).await;
        }
        self.refresh().await?;
        Ok(out)
    }
    /// unzip's question about files that exist: replace each, or not, as Info-ZIP asks.
    async fn decide(self, question: &Value) -> serde_json::Map<String, Value> {
        let mut decisions = serde_json::Map::new();
        let mut all = None;
        for path in question["replace"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            let replace = match all {
                Some(answer) => answer,
                None => {
                    let answer = self
                        .ask(format!("replace {path}? [y]es, [n]o, [A]ll, [N]one"))
                        .await;
                    match answer.trim() {
                        "A" | "All" => {
                            all = Some(true);
                            true
                        }
                        "N" | "None" => {
                            all = Some(false);
                            false
                        }
                        a => a.to_lowercase().starts_with('y'),
                    }
                }
            };
            if self.cancelled() {
                break;
            }
            decisions.insert(path.into(), json!(replace));
        }
        decisions
    }
    /// The jobs of this account, and the files this browser is writing (its descriptors, as
    /// /proc/self/fd lists them), or, given `jobs cancel ID`, cancel that one: a job, or a
    /// descriptor (`fdN`), closed, which completes a recording with what arrived and leaves an
    /// upload, removed if it was making the file.
    async fn jobs(self, cancel: Option<&str>) -> Result<Output, String> {
        use abi::O_APPEND;
        use userland::procs::{Descriptor, descriptors, processes};
        let sys = crate::sys::HttpSys::default();
        let jobs = processes(&sys).await.unwrap_or_default();
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
                let mut text = String::new();
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
    /// Run each of `commands` as xargs or fd -x would, one by one. Their output joins in order;
    /// a failure does not stop the next.
    async fn run_all(self, commands: Vec<Vec<String>>, trace: bool) -> Output {
        let mut out = Output::default();
        for command in commands {
            if self.cancelled() {
                break;
            }
            if trace {
                self.log(format!("+ {}", command.join(" ")));
            }
            match self.invoke(command, None, true).await {
                Ok(o) => {
                    out.stdout.push_str(&o.stdout);
                    out.failed |= o.failed;
                }
                Err(e) => {
                    self.error(e);
                    out.failed = true;
                }
            }
        }
        out
    }

    /// Read `value`, a path, as text for a filter.
    async fn read_text(self, value: &str) -> Result<String, String> {
        let path = self.path(value)?;
        let response = gloo_net::http::Request::get(&endpoint("file", &path))
            .header("Accept-Encoding", "identity")
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !response.ok() {
            let value: Value = response.json().await.unwrap_or_default();
            return Err(value["error"]
                .as_str()
                .unwrap_or("cannot read the file")
                .into());
        }
        if response
            .headers()
            .get("Content-Length")
            .and_then(|l| l.parse::<usize>().ok())
            .is_some_and(|l| l > PIPED_MAX)
        {
            return Err("larger than 10 MB".into());
        }
        let bytes = response.binary().await.map_err(|e| e.to_string())?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
    async fn filter(self, args: &[String], stdin: Option<String>) -> Result<Output, String> {
        let command = args[0].as_str();
        let filter = text::parse(command, &args[1..])?;
        let mut out = Output::default();
        let mut inputs = Vec::new();
        if filter.files.is_empty() {
            let Some(stdin) = stdin else {
                return Err(format!(
                    "{command}: name a FILE, or pipe text into it, as in ls | {command}"
                ));
            };
            inputs.push(("-".to_string(), stdin));
            let (stdout, status) = text::apply(&filter, &inputs);
            return Ok(Output {
                stdout,
                failed: status != 0,
                ..Default::default()
            });
        }
        for file in &filter.files {
            if file == "-" {
                inputs.push((file.clone(), stdin.clone().unwrap_or_default()));
                continue;
            }
            match self.read_text(file).await {
                Ok(text) => inputs.push((file.clone(), text)),
                Err(e) => {
                    self.error(format!("{command}: {file}: {e}"));
                    out.failed = true;
                }
            }
        }
        let (stdout, status) = text::apply(&filter, &inputs);
        out.stdout = stdout;
        out.failed |= status != 0;
        Ok(out)
    }
    async fn xargs(self, args: &[String], stdin: Option<String>) -> Result<Output, String> {
        let xargs = cli::parse::<cli::text::Xargs>(&args[1..])?;
        let mut delimiter = match (&xargs.delimiter, xargs.null) {
            (Some(d), _) => Delimiter::Char(parse_delimiter(d)?),
            (None, true) => Delimiter::Char('\0'),
            (None, false) => Delimiter::Blank,
        };
        let most = xargs.max_args.map_or(XARGS_MAX, |n| n as usize);
        let replace = xargs.replace;
        if replace.is_some() {
            delimiter = Delimiter::Line;
        }
        let (skip_empty, trace) = (xargs.no_run_if_empty, xargs.verbose);
        let command: Vec<String> = if xargs.command.is_empty() {
            vec!["echo".into()]
        } else {
            xargs.command
        };
        let items = grammar::xargs_items(&stdin.unwrap_or_default(), delimiter)?;
        if items.is_empty() && (skip_empty || replace.is_some()) {
            return Ok(Output::default());
        }
        let commands: Vec<Vec<String>> = match &replace {
            Some(r) => items
                .iter()
                .map(|item| {
                    command
                        .iter()
                        .map(|a| a.replace(r.as_str(), item))
                        .collect()
                })
                .collect(),
            None if items.is_empty() => vec![command],
            None => items
                .chunks(most)
                .map(|chunk| {
                    command
                        .iter()
                        .cloned()
                        .chain(chunk.iter().cloned())
                        .collect()
                })
                .collect(),
        };
        let mut out = self.run_all(commands, trace).await;
        out.failed |= self.cancelled();
        Ok(out)
    }
    /// fd with -x or -X: fd searches, and this runs the command on what it found.
    async fn fd_exec(self, args: &[String]) -> Result<Output, String> {
        let search = find::parse(&args[1..])?;
        let Some((all, template)) = search.exec else {
            return self.program(args.to_vec(), None, true, false).await;
        };
        let (found, results) = self.find(args).await;
        if results.is_empty() {
            return Ok(Output {
                failed: found.failed,
                ..Default::default()
            });
        }
        let commands = if all {
            vec![grammar::exec_all(&template, &results)]
        } else {
            results
                .iter()
                .map(|path| grammar::exec_one(&template, path))
                .collect()
        };
        let mut out = self.run_all(commands, false).await;
        out.failed |= found.failed;
        Ok(out)
    }
    /// The answer to `question`, which the next Enter in this tab gives.
    async fn ask(self, question: String) -> String {
        let (sender, answer) = oneshot::channel();
        self.prompt.set_value(Some(sender));
        self.asking.set(true);
        self.log(question);
        focus_input();
        let answer = answer.await.unwrap_or_default();
        self.asking.set(false);
        answer
    }
    /// Run the program of user space `args[0]`, under sudo if `sudo`, with `stdin`: what it
    /// left. Its questions (mv -i) go to this tab's next line, and Ctrl+C stops it between
    /// steps.
    async fn exec(self, args: Vec<String>, stdin: Option<String>, sudo: bool) -> Exited {
        let cancelled = move || self.cancelled();
        let ask = move |question: String| {
            Box::pin(async move { Some(self.ask(question).await) })
                as std::pin::Pin<Box<dyn std::future::Future<Output = Option<String>>>>
        };
        let mut io = userland::Io {
            args,
            cwd: self.cwd.get_untracked(),
            home: self.account.home.get_untracked(),
            now: (js_sys::Date::now() / 1000.0) as u64,
            stdin,
            out: String::new(),
            err: Vec::new(),
            view: None,
            found: Vec::new(),
            cancelled: &cancelled,
            ask: &ask,
        };
        let sys = crate::sys::HttpSys {
            sudo,
            ..Default::default()
        };
        let status = userland::run(&sys, &mut io).await.unwrap_or(127);
        Exited {
            status,
            out: io.out,
            err: io.err,
            view: io.view,
            found: io.found,
        }
    }
    /// Run coreutils' utility `args[0]` (a name the terminal has no program of its own for, or
    /// `coreutils NAME`), as a process of its own: what it writes goes on, its errors to the
    /// transcript. Ctrl+C kills it.
    pub async fn bin(
        self,
        args: Vec<String>,
        stdin: Option<String>,
        piped: bool,
        sudo: bool,
    ) -> Result<Output, String> {
        self.processes(vec![args], stdin, false, piped, sudo, None)
            .await
    }
    /// Run `stages`, each a utility of coreutils and its arguments, as a pipeline of processes
    /// (web/wasi/exec.mjs), given `stdin`, or reading the terminal if `terminal` says so: the
    /// lines typed then go to the first, and Ctrl+D ends its reads. What the last writes goes on
    /// if `piped`, of which its reader takes `enough` lines, if it says; to the transcript
    /// otherwise, as it writes it. What any writes to standard error goes to the transcript, a
    /// line at a time. Ctrl+C kills them.
    pub async fn processes(
        self,
        mut stages: Vec<Vec<String>>,
        stdin: Option<String>,
        terminal: bool,
        piped: bool,
        sudo: bool,
        enough: Option<usize>,
    ) -> Result<Output, String> {
        for args in &mut stages {
            args[0] = cli_bin::program(&args[0]).unwrap_or_default().to_string();
        }
        let set = |options: &js_sys::Object, key: &str, value: JsValue| {
            let _ = js_sys::Reflect::set(options, &JsValue::from_str(key), &value);
        };
        let options = js_sys::Object::new();
        set(&options, "cwd", self.cwd.get_untracked().into());
        set(&options, "home", self.account.home.get_untracked().into());
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
        let cancelled = Closure::<dyn Fn() -> bool>::new(move || self.cancelled());
        set(&options, "cancelled", cancelled.as_ref().clone());
        // What they write to the terminal shows as they write it: the last's output, a line of
        // the transcript that grows, a new one after anything else shows; errors a line at a time.
        let shown = Rc::new(RefCell::new(Shown::default()));
        let output = Closure::<dyn Fn(u32, String)>::new({
            let shown = shown.clone();
            move |fd: u32, text: String| {
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
        let tty = Closure::<dyn Fn(JsValue)>::new(move |input: JsValue| {
            let input = (!input.is_null() && !input.is_undefined()).then_some(input);
            if input.is_none() {
                self.reading.set(false);
            }
            self.terminal.set_value(input);
        });
        set(&options, "onTty", tty.as_ref().clone());
        let reading = Closure::<dyn Fn()>::new({
            let shown = shown.clone();
            move || {
                // A prompt written to standard error, its line not ended, shows as it waits.
                let prompt = std::mem::take(&mut shown.borrow_mut().partial);
                if !prompt.is_empty() {
                    self.error(prompt);
                }
                self.reading.set(true);
            }
        });
        set(&options, "onReading", reading.as_ref().clone());
        let names: Vec<String> = stages.iter().map(|args| args[0].clone()).collect();
        let argvs = js_sys::Array::new();
        for args in stages {
            argvs.push(
                &args
                    .into_iter()
                    .map(JsValue::from)
                    .collect::<js_sys::Array>(),
            );
        }
        let exited = JsFuture::from(crate::exec(&argvs, &options.into())).await;
        self.terminal.set_value(None);
        self.reading.set(false);
        drop((cancelled, output, tty, reading));
        let exited = exited.map_err(js_message)?;
        // What is left of an error line, and how much output was not shown.
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
            self.error(format!(
                "{name}: output larger than 10 MB was cut short, and {name} stopped"
            ));
        }
        if names.iter().any(|name| cli_bin::writes(name)) {
            self.refresh().await?;
        }
        Ok(Output {
            stdout,
            failed: status != 0,
            ..Default::default()
        })
    }
    /// End of input, Ctrl+D, for the process reading the terminal, if one may: what is typed goes
    /// as it is, without a newline, or, if nothing is, its read ends with nothing.
    pub fn end_of_input(self) -> bool {
        let Some(input) = self.terminal.get_value() else {
            return false;
        };
        let typed = self.input.get_untracked();
        self.input.set(String::new());
        self.reading.set(false);
        if typed.is_empty() {
            call(&input, "eof", &JsValue::UNDEFINED);
        } else {
            self.log(typed.clone());
            call(&input, "write", &typed.into());
        }
        true
    }
    /// Run the program of user space `args[0]` as a stage: its errors go to the transcript, and
    /// its listing as a view of its own unless piped.
    pub async fn program(
        self,
        args: Vec<String>,
        stdin: Option<String>,
        piped: bool,
        sudo: bool,
    ) -> Result<Output, String> {
        let changes = !matches!(
            args[0].as_str(),
            "ls" | "stat" | "readlink" | "realpath" | "getfacl" | "getfattr" | "fd"
        );
        let io = self.exec(args, stdin, sudo).await;
        let status = io.status;
        for line in io.err {
            self.error(line);
        }
        let mut out = Output {
            stdout: io.out,
            failed: status != 0,
            ..Default::default()
        };
        if let Some(userland::View::Listing { entries, long }) = io.view {
            if piped {
                out.stdout = listing_text(&entries, long);
            } else if entries.is_empty() {
                out.stdout = "(empty directory)\n".into();
            } else {
                out.view = Some(LogLine::Listing { entries, long });
            }
        }
        if changes {
            self.refresh().await?;
        }
        Ok(out)
    }
    /// sudo PROGRAM ...: a program of user space, run as root once the account has authenticated
    /// (sudo's password, asked for if it has not lately).
    pub async fn sudo_program(
        self,
        args: Vec<String>,
        stdin: Option<String>,
        piped: bool,
    ) -> Result<Output, String> {
        if !self.authenticated().await? {
            return Err("sudo canceled".into());
        }
        self.program(args, stdin, piped, true).await
    }
    /// Whether the account may act as root now: sudo's password, asked for if it has not been
    /// lately.
    pub async fn authenticated(self) -> Result<bool, String> {
        let allowed = JsFuture::from(sudo()).await.map_err(js_message)?;
        Ok(allowed.as_bool() == Some(true))
    }
    /// What fd finds, as `args` say: whether it failed, and its results, by path.
    async fn find(self, args: &[String]) -> (Output, Vec<String>) {
        let io = self.exec(args.to_vec(), None, false).await;
        let status = io.status;
        for line in io.err {
            self.error(line);
        }
        let out = Output {
            failed: status != 0,
            ..Default::default()
        };
        (out, io.found)
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
            let Some(mut name) = args.first().cloned() else {
                return Ok(Output::default());
            };
            let mut args = args;
            // A path to /usr/bin runs what its name does, as PATH would have found it.
            if let Some(named) = cli_bin::named(&name) {
                if cli::definition(named).is_none() && cli_bin::program(named).is_none() {
                    return Err(format!("{name}: No such file or directory"));
                }
                name = named.to_string();
                args[0] = name.clone();
            }
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
            // A guest's own useradd and an account's own userdel take a password, in web/app.js's
            // dialog, which hands back what is not that to run here.
            if userland::PROGRAMS.contains(&name.as_str())
                && commands::find(&name).is_none()
                && !DIALOGS.contains(&name.as_str())
            {
                return self.program(args, stdin, piped, false).await;
            }
            // A name the terminal has nothing of its own for runs coreutils', as PATH finds it,
            // and `coreutils NAME` uutils' NAME.
            if let Some(argv) = process(&args) {
                return self.bin(argv, stdin, piped, false).await;
            }
            if name == "coreutils" {
                return match args.get(1) {
                    None => Ok(Output::text(format!(
                        "coreutils (uutils): {}\n",
                        cli_bin::PROGRAMS.join(" ")
                    ))),
                    Some(utility) => Err(format!("coreutils: {utility}: no such utility")),
                };
            }
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
        self.log(line.clone());
        self.reading.set(false);
        call(&input, "write", &format!("{line}\n").into());
    }

    /// Run the pipeline `command`, typed into this tab.
    pub fn run(self, command: String) {
        if self.asking.get_untracked() {
            // The line answers the question a command is waiting on.
            self.input.set(String::new());
            self.log(command.clone());
            if let Some(sender) = self.prompt.try_update_value(Option::take).flatten() {
                let _ = sender.send(command);
            }
            return;
        }
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
            let args = match ahead.take() {
                Some(args) => args,
                None => self.expand(std::mem::take(&mut stages[index])).await,
            };
            if self.cancelled() {
                break;
            }
            let first = index == 0;
            // A run of processes runs at once, each reading the one before through a pipe; the
            // first of a line reads the terminal.
            let mut run = Vec::new();
            if let Ok(args) = &args
                && let Some(argv) = process(args)
            {
                run.push(argv);
                while index < last {
                    let next = self.expand(std::mem::take(&mut stages[index + 1])).await;
                    match next.as_ref().ok().and_then(|args| process(args)) {
                        Some(argv) => {
                            run.push(argv);
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
                    // head reads only the lines it shows: then it closes the pipe.
                    let enough = match &ahead {
                        Some(Ok(next))
                            if next.first().is_some_and(|name| {
                                cli_bin::named(name).unwrap_or(name) == "head"
                            }) =>
                        {
                            text::parse("head", &next[1..])
                                .ok()
                                .and_then(|filter| filter.reads())
                        }
                        _ => None,
                    };
                    self.processes(run, stdin.take(), first, piped, false, enough)
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
                    if let Some(view) = out.view {
                        self.push(view);
                    } else {
                        let text = out.stdout.replace('\0', "\n");
                        let text = text.trim_end_matches('\n');
                        if !text.is_empty() {
                            self.log(text);
                        }
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
        self.prompt.set_value(None);
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
            self.prompt.set_value(None);
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
            let value = session.candidates[index].value.clone();
            self.input.set(value.clone());
            self.completion.set(Some(session));
            completion_focus(&value, false);
        }
    }
    pub fn accept_completion(self) {
        let inside_quote = self.completion.with_untracked(|s| {
            s.as_ref()
                .and_then(|s| s.selected.map(|index| &s.candidates[index]))
                .is_some_and(|c| c.descend && c.kind != "command")
        });
        let value = self.input.get_untracked();
        self.reset_completion();
        completion_focus(&value, inside_quote);
    }
    pub fn cancel_completion(self) {
        if let Some(session) = self.completion.get_untracked() {
            self.input.set(session.original);
        }
        self.reset_completion();
    }
    fn finish_completion(self, original: String, cwd: String, candidates: Vec<Candidate>) {
        self.completing.set(false);
        if candidates.is_empty() {
            self.completion_status.set("No matches".into());
            return;
        }
        self.completion_status.set(String::new());
        // One completes at once; of several, the Tabs pressed while they were listed pick one.
        let len = candidates.len() as i64;
        let selected = match self.completion_offset.get_untracked() {
            _ if len == 1 => Some(0),
            0 => None,
            ahead if ahead > 0 => Some((ahead - 1).rem_euclid(len) as usize),
            back => Some(back.rem_euclid(len) as usize),
        };
        let shown = original.clone();
        self.completion.set(Some(CompletionSession {
            original,
            cwd,
            candidates,
            selected: None,
        }));
        match selected {
            Some(index) => self.select_completion(index),
            None => completion_focus(&shown, false),
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
        if let Some(session) = self.completion.get_untracked()
            && session.cwd == cwd
            && session.selected.map_or(&session.original, |index| &session.candidates[index].value)
                == &input
            // A sole command/directory can continue into its arguments/children.
            && (session.candidates.len() != 1 || !session.candidates[0].descend)
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
        match completion::query(&input) {
            Query::Commands(candidates) => self.finish_completion(input, cwd, candidates),
            Query::None => self
                .completion_status
                .set("No path completion is available here".into()),
            Query::Paths(query) => {
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
                    // Never let a late request overwrite new typing, history, or a new cwd.
                    if self.completion_epoch.get_untracked() != epoch
                        || self.input.get_untracked() != input
                        || self.cwd.get_untracked() != cwd
                    {
                        return;
                    }
                    match result {
                        Ok(entries) => self.finish_completion(
                            input,
                            cwd,
                            completion::path_candidates(&query, &entries),
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

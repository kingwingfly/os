//! The commands a tab runs, each a [`TerminalCommand`] registered by name in [`COMMANDS`]: those
//! the page does itself (cd, open, upload, the text filters, xargs, fd -x...), and those it
//! decides how to hand on (ls and mkdir with options, cp and mv -i, sudo). Every other command
//! [`terminal_worker_core::cli`] defines goes to the server through web/app.js's
//! accountCommand, which shows the dialogs some need. Their arguments, and their help, are their
//! definitions there.

use futures::FutureExt;
use futures::future::LocalBoxFuture;
use leptos::prelude::*;
use terminal_worker_core::cli::{self, files, terminal, text as filters};
use terminal_worker_core::text;
use wasm_bindgen::{JsCast, closure::Closure};
use wasm_bindgen_futures::JsFuture;

use super::{LogLine, Output, Shell, js_message};
use crate::{choose_files, enterable, open_file, record_sound, set_directory, stat, upload_files};

/// A command the tab runs.
pub trait TerminalCommand: Sync {
    /// Its name, as [`terminal_worker_core::cli`] defines it.
    fn name(&self) -> &'static str;
    /// Run `args`, its whole line, in `shell`, with what the stage before wrote, if any; `piped`
    /// if what it writes goes on to another stage.
    fn run(
        &self,
        shell: Shell,
        args: Vec<String>,
        stdin: Option<String>,
        piped: bool,
    ) -> LocalBoxFuture<'static, Result<Output, String>>;
}

/// Every command the tab runs itself, or hands on as it decides.
pub static COMMANDS: &[&dyn TerminalCommand] = &[
    &Echo,
    &Filter("cat"),
    &Filter("head"),
    &Filter("tail"),
    &Filter("grep"),
    &Filter("wc"),
    &Filter("sort"),
    &Filter("uniq"),
    &Xargs,
    &Fd,
    &Jobs,
    &Asking("sudo"),
    &Cd,
    &Pwd,
    &Clear,
    &Open,
    &Present,
    &Stream,
    &Upload,
    &Help,
];

/// The command named `name`, if the tab runs it.
pub fn find(name: &str) -> Option<&'static dyn TerminalCommand> {
    COMMANDS.iter().copied().find(|c| c.name() == name)
}

/// `args` without the command's name.
fn rest(args: &[String]) -> &[String] {
    args.get(1..).unwrap_or_default()
}

struct Echo;
impl TerminalCommand for Echo {
    fn name(&self) -> &'static str {
        "echo"
    }
    fn run(
        &self,
        _: Shell,
        args: Vec<String>,
        _: Option<String>,
        _: bool,
    ) -> LocalBoxFuture<'static, Result<Output, String>> {
        async move {
            let typed = rest(&args);
            let echo = cli::parse::<filters::Echo>(typed)?;
            // echo has no --: one before its words is a word, as GNU echo writes it.
            let start = typed.len() - echo.words.len();
            let start = if start > 0 && typed[start - 1] == "--" {
                start - 1
            } else {
                start
            };
            Ok(Output::text(format!(
                "{}{}",
                typed[start..].join(" "),
                if echo.no_newline { "" } else { "\n" }
            )))
        }
        .boxed_local()
    }
}

/// A text filter: cat, head, tail, grep, wc, sort or uniq.
struct Filter(&'static str);
impl TerminalCommand for Filter {
    fn name(&self) -> &'static str {
        self.0
    }
    fn run(
        &self,
        shell: Shell,
        args: Vec<String>,
        stdin: Option<String>,
        _: bool,
    ) -> LocalBoxFuture<'static, Result<Output, String>> {
        debug_assert!(text::FILTERS.contains(&self.0));
        async move { shell.filter(&args, stdin).await }.boxed_local()
    }
}

struct Xargs;
impl TerminalCommand for Xargs {
    fn name(&self) -> &'static str {
        "xargs"
    }
    fn run(
        &self,
        shell: Shell,
        args: Vec<String>,
        stdin: Option<String>,
        _: bool,
    ) -> LocalBoxFuture<'static, Result<Output, String>> {
        async move { shell.xargs(&args, stdin).await }.boxed_local()
    }
}

/// fd: with -x or -X, the server searches and the tab runs the command; otherwise the server.
struct Fd;
impl TerminalCommand for Fd {
    fn name(&self) -> &'static str {
        "fd"
    }
    fn run(
        &self,
        shell: Shell,
        args: Vec<String>,
        _: Option<String>,
        piped: bool,
    ) -> LocalBoxFuture<'static, Result<Output, String>> {
        async move {
            let find = terminal_worker_core::find::parse(rest(&args))?;
            if find.exec.is_some() {
                shell.fd_exec(&args).await
            } else {
                shell.program(args, None, piped, false).await
            }
        }
        .boxed_local()
    }
}

struct Jobs;
impl TerminalCommand for Jobs {
    fn name(&self) -> &'static str {
        "jobs"
    }
    fn run(
        &self,
        shell: Shell,
        args: Vec<String>,
        _: Option<String>,
        _: bool,
    ) -> LocalBoxFuture<'static, Result<Output, String>> {
        async move {
            let jobs = cli::parse::<cli::archives::Jobs>(rest(&args))?;
            shell.jobs(jobs.id.as_deref()).await
        }
        .boxed_local()
    }
}

/// sudo: of a program of user space, it runs as root; of one of the server's, the server runs
/// it as root.
struct Asking(&'static str);
impl TerminalCommand for Asking {
    fn name(&self) -> &'static str {
        self.0
    }
    fn run(
        &self,
        shell: Shell,
        args: Vec<String>,
        stdin: Option<String>,
        piped: bool,
    ) -> LocalBoxFuture<'static, Result<Output, String>> {
        async move {
            let program = args.get(1).filter(|_| args[0] == "sudo");
            if program.is_some_and(|name| userland::PROGRAMS.contains(&name.as_str())) {
                return shell.sudo_program(args[1..].to_vec(), stdin, piped).await;
            }
            // /bin's, as root: its system calls go under sudo.
            if let Some(name) = program
                && terminal_worker_core::bin::program(name).is_some()
                && cli::definition(name).is_none()
            {
                if !shell.authenticated().await? {
                    return Err("sudo canceled".into());
                }
                return shell.bin(args[1..].to_vec(), stdin, piped, true).await;
            }
            shell.manage(&args, piped).await
        }
        .boxed_local()
    }
}

struct Cd;
impl TerminalCommand for Cd {
    fn name(&self) -> &'static str {
        "cd"
    }
    fn run(
        &self,
        shell: Shell,
        args: Vec<String>,
        _: Option<String>,
        _: bool,
    ) -> LocalBoxFuture<'static, Result<Output, String>> {
        async move {
            let cd = cli::parse::<files::Cd>(rest(&args))?;
            let path = match &cd.dir {
                Some(dir) => shell.path(dir)?,
                None => shell.account.home.get_untracked(),
            };
            let typed = cd.dir.as_deref().unwrap_or("~");
            enterable(&path)
                .await
                .map_err(|error| format!("cd: {typed}: {error}"))?;
            shell.cwd.set(path.clone());
            set_directory(&path);
            Ok(Output::default())
        }
        .boxed_local()
    }
}

struct Pwd;
impl TerminalCommand for Pwd {
    fn name(&self) -> &'static str {
        "pwd"
    }
    fn run(
        &self,
        shell: Shell,
        args: Vec<String>,
        _: Option<String>,
        _: bool,
    ) -> LocalBoxFuture<'static, Result<Output, String>> {
        async move {
            cli::parse::<files::Pwd>(rest(&args))?;
            Ok(Output::text(format!("{}\n", shell.cwd.get_untracked())))
        }
        .boxed_local()
    }
}

struct Clear;
impl TerminalCommand for Clear {
    fn name(&self) -> &'static str {
        "clear"
    }
    fn run(
        &self,
        shell: Shell,
        args: Vec<String>,
        _: Option<String>,
        _: bool,
    ) -> LocalBoxFuture<'static, Result<Output, String>> {
        async move {
            cli::parse::<terminal::Clear>(rest(&args))?;
            shell.lines.set(Vec::new());
            Ok(Output::default())
        }
        .boxed_local()
    }
}

struct Open;
impl TerminalCommand for Open {
    fn name(&self) -> &'static str {
        "open"
    }
    fn run(
        &self,
        shell: Shell,
        args: Vec<String>,
        _: Option<String>,
        _: bool,
    ) -> LocalBoxFuture<'static, Result<Output, String>> {
        async move {
            let open = cli::parse::<files::Open>(rest(&args))?;
            let path = shell.path(&open.file)?;
            let node = stat(&path)
                .await
                .map_err(|error| format!("open: {}: {error}", open.file))?;
            if node.is_dir() {
                return Err("This is a directory; use cd".into());
            }
            JsFuture::from(open_file(&path, terminal_worker_core::kind(&path)))
                .await
                .map_err(js_message)?;
            Ok(Output::default())
        }
        .boxed_local()
    }
}

struct Present;
impl TerminalCommand for Present {
    fn name(&self) -> &'static str {
        "present"
    }
    fn run(
        &self,
        shell: Shell,
        args: Vec<String>,
        _: Option<String>,
        _: bool,
    ) -> LocalBoxFuture<'static, Result<Output, String>> {
        async move {
            let present = cli::parse::<files::Present>(rest(&args))?;
            let failed = |error: wasm_bindgen::JsValue| format!("present: {}", js_message(error));
            if let Some(name) = present.stop {
                let stopped = JsFuture::from(crate::stop_presenting(&name))
                    .await
                    .map_err(failed)?;
                let device = js_sys::Reflect::get(&stopped, &"device".into())
                    .ok()
                    .and_then(|device| device.as_string())
                    .unwrap_or(name);
                return Ok(Output::text(format!("Stopped {device}\n")));
            }
            let path = shell.path(present.file.as_deref().unwrap_or_default())?;
            let started = JsFuture::from(crate::present_file(&path, present.name.clone()))
                .await
                .map_err(failed)?;
            let started: serde_json::Value =
                serde_wasm_bindgen::from_value(started).unwrap_or_default();
            let device = started["device"].as_str().unwrap_or_default().to_string();
            // Shown presented, a PDF a page at a time and Markdown as slides, from where the
            // account showed it last.
            let kind = terminal_worker_core::kind(&path);
            let place = &started["place"];
            let kept = match (kind, place.is_array()) {
                ("pdf", true) => serde_json::json!({ "present": true, "page": place[0] }),
                ("pdf", false) => serde_json::json!({ "present": true }),
                (_, true) => serde_json::json!({ "slides": true, "slide": place }),
                (_, false) => serde_json::json!({ "slides": true }),
            };
            crate::viewer::set_place(&path, kept);
            JsFuture::from(open_file(&path, kind))
                .await
                .map_err(js_message)?;
            let name = device.rsplit('/').next().unwrap_or_default();
            Ok(Output::text(format!(
                "Presenting {path} as {device}: whoever may read it follows it with open {device}; present --stop {name} ends it\n"
            )))
        }
        .boxed_local()
    }
}

struct Stream;
impl TerminalCommand for Stream {
    fn name(&self) -> &'static str {
        "stream"
    }
    fn run(
        &self,
        shell: Shell,
        args: Vec<String>,
        _: Option<String>,
        _: bool,
    ) -> LocalBoxFuture<'static, Result<Output, String>> {
        async move {
            let stream = cli::parse::<files::Stream>(rest(&args))?;
            // Recorded into FILE, or live only.
            let path = match &stream.file {
                Some(file) => {
                    let path = shell.path(file)?;
                    let lower = path.to_lowercase();
                    if !lower.ends_with(".weba") && !lower.ends_with(".webm") {
                        return Err(format!(
                            "stream: {file}: browsers record Opus in WebM; name the recording NAME.weba"
                        ));
                    }
                    Some(path)
                }
                None => None,
            };
            // Entries for who may hear, given as one list, as setfacl -m takes them.
            let acl = (!stream.modify.is_empty()).then(|| stream.modify.join(","));
            // A line that follows the sound; Ctrl+C in this tab stops it, as it cancels an
            // upload.
            let line = RwSignal::new(String::from("● starting the microphone"));
            shell.push(LogLine::Live(line));
            let progress = Closure::<dyn Fn(String)>::new(move |text: String| line.set(text));
            shell.recording.set(true);
            let result = JsFuture::from(record_sound(
                path.clone(),
                stream.name,
                acl,
                progress.as_ref().unchecked_ref(),
            ))
            .await;
            shell.recording.set(false);
            drop(progress);
            let saved = result
                .map_err(js_message)
                .inspect_err(|e| line.set(format!("✕ {e}")))?;
            let get = |name: &str| js_sys::Reflect::get(&saved, &name.into()).unwrap_or_default();
            let seconds = get("seconds").as_f64().unwrap_or_default() as u64;
            let size = get("size").as_f64().unwrap_or_default() as u64;
            let note = get("note").as_string().unwrap_or_default();
            let clock = format!("{:02}:{:02}", seconds / 60, seconds % 60);
            line.set(match &path {
                Some(path) => format!("✓ {path} · {clock} · {}{note}", crate::viewer::size(size)),
                None => format!(
                    "✓ {} · {clock}{note}",
                    get("device").as_string().unwrap_or_default()
                ),
            });
            shell.refresh().await?;
            Ok(Output::default())
        }
        .boxed_local()
    }
}

struct Upload;
impl TerminalCommand for Upload {
    fn name(&self) -> &'static str {
        "upload"
    }
    fn run(
        &self,
        shell: Shell,
        args: Vec<String>,
        _: Option<String>,
        _: bool,
    ) -> LocalBoxFuture<'static, Result<Output, String>> {
        async move {
            // The files were chosen as the line started, while the tap that asked was fresh.
            let chosen = shell.chosen.try_update_value(Option::take).flatten();
            let upload = cli::parse::<files::Upload>(rest(&args))?;
            let path = shell.path(upload.dir.as_deref().unwrap_or("."))?;
            shell.choosing.set(true);
            let files = JsFuture::from(chosen.unwrap_or_else(choose_files)).await;
            shell.choosing.set(false);
            let files = files.map_err(js_message)?;
            if js_sys::Array::from(&files).length() == 0 {
                return Ok(Output::default());
            }
            // A line that follows the upload, here rather than over the page.
            let line = RwSignal::new(String::from("↑ starting"));
            shell.push(LogLine::Live(line));
            let progress = Closure::<dyn Fn(String)>::new(move |text: String| line.set(text));
            shell.uploading.set(true);
            let result = JsFuture::from(upload_files(
                &files,
                &path,
                progress.as_ref().unchecked_ref(),
            ))
            .await;
            shell.uploading.set(false);
            drop(progress);
            let results: Vec<String> = result
                .map_err(js_message)
                .inspect_err(|e| line.set(format!("✕ {e}")))?
                .dyn_into::<js_sys::Array>()
                .map(|a| a.iter().filter_map(|r| r.as_string()).collect())
                .unwrap_or_default();
            let failed = results.iter().any(|r| r.starts_with('✕'));
            line.set(results.join("\n"));
            shell.refresh().await?;
            Ok(Output {
                failed,
                ..Output::default()
            })
        }
        .boxed_local()
    }
}

/// help: every command by section, or one's help, as -h shows it.
struct Help;
impl TerminalCommand for Help {
    fn name(&self) -> &'static str {
        "help"
    }
    fn run(
        &self,
        _: Shell,
        args: Vec<String>,
        _: Option<String>,
        _: bool,
    ) -> LocalBoxFuture<'static, Result<Output, String>> {
        async move {
            let help = cli::parse::<terminal::Help>(rest(&args))?;
            let text = match &help.command {
                Some(name) => cli::help(name)
                    .ok_or_else(|| format!("Unknown command: {name}. Enter help for commands."))?,
                None => cli::commands(),
            };
            Ok(Output::text(text + "\n"))
        }
        .boxed_local()
    }
}

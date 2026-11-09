//! Job control (Phase 3, owner's plan in issue #20): the terminal's jobs, pipelines of /usr/bin
//! run in the background with `&` or stopped with Ctrl+Z, which `fg`, `bg` and `kill %N` take, as
//! a shell's are. A job is a process group (web/wasi/exec.mjs `onJob`): signalled as one,
//! stopped at its processes' next system calls, continued, ended. A stopped or background job
//! goes on apart from the line that started it; what it writes still shows, and its end is said
//! as bash says it.
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use abi::{Call, SIGCONT, SIGTSTP};
use futures::channel::oneshot;
use futures::future::{Either, select};
use leptos::prelude::*;
use serde_json::Value;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::spawn_local;

use super::{Output, Shell, call};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum State {
    Running,
    Stopped,
}

/// A job: its number (%N), its line, its process group, and what it was running with.
pub(super) struct Job {
    pub number: u32,
    pub command: String,
    /// Its process group: `signal(n)`, `pids`, `stoppable`.
    pub group: JsValue,
    /// The terminal's input, if its first process reads it, given back to it in the foreground.
    pub input: Rc<RefCell<Option<JsValue>>>,
    /// Whether it is the tab's foreground run: Ctrl+C ends it, and it has the terminal's input.
    pub foreground: Rc<Cell<bool>>,
    pub live: RwSignal<bool>,
    pub state: State,
    /// Whether its first process was waiting on the terminal as it stopped, as it still is.
    pub reading: bool,
    /// Who waits for its end (fg), for its status.
    pub waiting: Vec<oneshot::Sender<i32>>,
}

/// The run in the foreground, which Ctrl+Z stops: its group, and how to say it stopped.
pub(super) struct Foreground {
    pub group: JsValue,
    pub stopped: oneshot::Sender<()>,
}

/// What a run in the foreground shares with the job it may become.
#[derive(Clone)]
pub(super) struct Run {
    pub group: Rc<RefCell<JsValue>>,
    pub input: Rc<RefCell<Option<JsValue>>>,
    pub foreground: Rc<Cell<bool>>,
    pub live: RwSignal<bool>,
    /// Its job's number, once it is one.
    pub number: Rc<Cell<Option<u32>>>,
}
impl Run {
    pub fn new() -> Self {
        Self {
            group: Rc::new(RefCell::new(JsValue::UNDEFINED)),
            input: Rc::new(RefCell::new(None)),
            foreground: Rc::new(Cell::new(true)),
            live: RwSignal::new(true),
            number: Rc::new(Cell::new(None)),
        }
    }
}

/// A group's pids.
pub(super) fn pids(group: &JsValue) -> Vec<u32> {
    js_sys::Reflect::get(group, &JsValue::from_str("pids"))
        .ok()
        .and_then(|pids| pids.dyn_into::<js_sys::Array>().ok())
        .map(|pids| {
            pids.iter()
                .filter_map(|pid| pid.as_f64())
                .map(|pid| pid as u32)
                .collect()
        })
        .unwrap_or_default()
}
/// Whether a group can be stopped: its processes share memory with the page.
fn stoppable(group: &JsValue) -> bool {
    js_sys::Reflect::get(group, &JsValue::from_str("stoppable"))
        .ok()
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
}
/// Send `signal` to the group `group`: here, at once, and to the kernel's record of each of its
/// processes, which `ps` shows and which tells the tab hosting them (this one) on its line.
pub(super) fn signal(group: &JsValue, number: u8) {
    call(group, "signal", &JsValue::from(number));
    let pids = pids(group);
    spawn_local(async move {
        let sys = crate::sys::HttpSys::default();
        for pid in pids {
            let sent = Call::Kill {
                pid: pid.to_string(),
                signal: Some(number),
            };
            let _ = userland::sys::call::<Value>(&sys, sent).await;
        }
    });
}

/// How a job ended, as bash says it: Done, Exit N, or the signal that ended it.
fn ended(status: i32) -> String {
    match status {
        0 => "Done".into(),
        status if status > 128 => match u8::try_from(status - 128).unwrap_or(0) {
            1 => "Hangup".into(),
            2 => "Interrupt".into(),
            3 => "Quit".into(),
            9 => "Killed".into(),
            13 => "Broken pipe".into(),
            15 => "Terminated".into(),
            signal => format!("Signal {signal}"),
        },
        status => format!("Exit {status}"),
    }
}

impl Shell {
    /// The jobs' lines, as `jobs` lists them: `[N]+  Running   command &`, the latest marked +,
    /// the one before -.
    pub(super) fn job_lines(self) -> Vec<String> {
        self.jobs.with_value(|jobs| {
            let latest: Vec<u32> = {
                let mut numbers: Vec<u32> = jobs.iter().map(|job| job.number).collect();
                numbers.sort_unstable();
                numbers.into_iter().rev().take(2).collect()
            };
            jobs.iter()
                .map(|job| {
                    let mark = match latest.iter().position(|n| *n == job.number) {
                        Some(0) => '+',
                        Some(1) => '-',
                        _ => ' ',
                    };
                    let (state, and) = match job.state {
                        State::Running => ("Running", " &"),
                        State::Stopped => ("Stopped", ""),
                    };
                    format!("[{}]{mark}  {state:<24}{}{and}", job.number, job.command)
                })
                .collect()
        })
    }
    /// The job `spec` names: %N or N, %+ or %% or none for the latest, %- for the one before.
    fn job(self, spec: Option<&str>, command: &str) -> Result<u32, String> {
        let mut numbers: Vec<u32> = self
            .jobs
            .with_value(|jobs| jobs.iter().map(|job| job.number).collect());
        numbers.sort_unstable();
        let found = match spec.map(|spec| spec.strip_prefix('%').unwrap_or(spec)) {
            None | Some("+") | Some("%") | Some("") => numbers.last().copied(),
            Some("-") => numbers.iter().rev().nth(1).copied(),
            Some(number) => number.parse().ok().filter(|n| numbers.contains(n)),
        };
        found.ok_or_else(|| match spec {
            Some(spec) => format!("{command}: {spec}: no such job"),
            None => format!("{command}: current: no such job"),
        })
    }
    /// The pids of the job `spec` names, and its group: what `kill %N` signals.
    pub(super) fn job_pids(self, spec: &str) -> Result<(Vec<u32>, JsValue), String> {
        let number = self.job(Some(spec), "kill")?;
        Ok(self.jobs.with_value(|jobs| {
            jobs.iter()
                .find(|job| job.number == number)
                .map(|job| (pids(&job.group), job.group.clone()))
                .unwrap_or_default()
        }))
    }
    /// Make the run `run`, its line `command`, a job, in `state`: its number.
    pub(super) fn add_job(self, command: String, run: &Run, state: State, reading: bool) -> u32 {
        let number = self
            .jobs
            .with_value(|jobs| jobs.iter().map(|job| job.number).max().unwrap_or(0) + 1);
        run.number.set(Some(number));
        self.jobs.update_value(|jobs| {
            jobs.push(Job {
                number,
                command,
                group: run.group.borrow().clone(),
                input: run.input.clone(),
                foreground: run.foreground.clone(),
                live: run.live,
                state,
                reading,
                waiting: Vec::new(),
            })
        });
        number
    }
    /// The job `number` ended with `status`: it goes, whoever waits for it hears, and, unless it
    /// was in the foreground, the transcript says how.
    pub(super) fn job_ended(self, number: u32, status: i32) {
        let Some(job) = self.jobs.try_update_value(|jobs| {
            let at = jobs.iter().position(|job| job.number == number)?;
            Some(jobs.remove(at))
        }) else {
            return;
        };
        let Some(job) = job else { return };
        if !job.foreground.get() {
            self.log(format!("[{number}]+  {:<24}{}", ended(status), job.command));
        }
        for waiting in job.waiting {
            let _ = waiting.send(status);
        }
    }
    /// The job `number` stopped or went on, as its processes said (a kill from elsewhere): one in
    /// the background that stops says so, as bash does; going on, it says nothing.
    pub(super) fn job_state(self, number: u32, state: State) {
        let stopped = self.jobs.try_update_value(|jobs| {
            let job = jobs.iter_mut().find(|job| job.number == number)?;
            let stopped = job.state != state && state == State::Stopped && !job.foreground.get();
            job.state = state;
            stopped.then(|| job.command.clone())
        });
        if let Some(Some(command)) = stopped {
            self.log(format!("[{number}]+  {:<24}{command}", "Stopped"));
        }
    }

    /// `kill`'s arguments without its jobs (%N), which are signalled here, as `kill` says
    /// (-s SIGNAL, -SIGNAL, or TERM): at once, and in the kernel's record of their processes.
    /// None if nothing is left for the program to signal.
    pub(super) fn kill_jobs(self, args: Vec<String>) -> Result<Option<Vec<String>>, String> {
        let mut signal = abi::SIGTERM;
        if let Some(name) = args
            .get(1)
            .and_then(|first| first.strip_prefix('-'))
            .filter(|name| !name.starts_with('-'))
            && let Some(named) = abi::signal_named(name)
        {
            signal = named;
        }
        if let Some(at) = args.iter().position(|arg| arg == "-s" || arg == "--signal")
            && let Some(name) = args.get(at + 1)
        {
            signal = abi::signal_named(name)
                .ok_or_else(|| format!("kill: {name}: invalid signal specification"))?;
        }
        let mut out = Vec::with_capacity(args.len());
        let mut left = false;
        for (at, arg) in args.into_iter().enumerate() {
            if arg.starts_with('%') {
                let (_, group) = self.job_pids(&arg)?;
                self::signal(&group, signal);
                continue;
            }
            // What is left to signal: a word that is no option, nor the signal -s names.
            let named =
                at >= 2 && matches!(out.last().map(String::as_str), Some("-s" | "--signal"));
            left |= at >= 1 && !arg.starts_with('-') && !named;
            out.push(arg);
        }
        Ok(left.then_some(out))
    }
    /// Ctrl+Z: stop the run in the foreground, which becomes a job; whether there was one.
    pub fn suspend(self) -> bool {
        let Some(foreground) = self.foreground.try_update_value(Option::take).flatten() else {
            return false;
        };
        if !stoppable(&foreground.group) {
            self.foreground.set_value(Some(foreground));
            self.log("Ctrl+Z stops a program only where the page is isolated from other sites; Ctrl+C ends it");
            return true;
        }
        signal(&foreground.group, SIGTSTP);
        let _ = foreground.stopped.send(());
        true
    }
    /// The run in the foreground stopped by itself (a kill from elsewhere): it becomes a job, as
    /// with Ctrl+Z.
    pub(super) fn stopped_elsewhere(self) {
        if let Some(Some(foreground)) = self.foreground.try_update_value(Option::take) {
            let _ = foreground.stopped.send(());
        }
    }

    /// fg: the job `spec` names, continued in the foreground, until it ends or stops again.
    pub(super) async fn fg(self, spec: Option<&str>) -> Result<Output, String> {
        let number = self.job(spec, "fg")?;
        let (done, ended) = oneshot::channel();
        let Some((group, input, foreground, state, command, reading, live)) = self
            .jobs
            .try_update_value(|jobs| {
                let job = jobs.iter_mut().find(|job| job.number == number)?;
                job.waiting.push(done);
                let state = job.state;
                job.state = State::Running;
                Some((
                    job.group.clone(),
                    job.input.clone(),
                    job.foreground.clone(),
                    state,
                    job.command.clone(),
                    job.reading,
                    job.live,
                ))
            })
            .flatten()
        else {
            return Err(format!("fg: %{number}: no such job"));
        };
        self.log(command.clone());
        foreground.set(true);
        call(&group, "foreground", &JsValue::TRUE);
        live.set(true);
        self.attach_terminal(input.borrow().clone());
        self.reading.set(reading);
        let (stopping, stopped) = oneshot::channel();
        self.foreground.set_value(Some(Foreground {
            group: group.clone(),
            stopped: stopping,
        }));
        if state == State::Stopped {
            signal(&group, SIGCONT);
        }
        let outcome = select(ended, stopped).await;
        let was_reading = self.reading.get_untracked();
        self.foreground.set_value(None);
        self.attach_terminal(None);
        self.reading.set(false);
        match outcome {
            Either::Left((status, _)) => Ok(Output {
                failed: status.unwrap_or(1) != 0,
                ..Default::default()
            }),
            // Stopped again: a job in the background, stopped, as it was.
            Either::Right(_) => {
                foreground.set(false);
                call(&group, "foreground", &JsValue::FALSE);
                live.set(false);
                let reading = was_reading;
                self.jobs.update_value(|jobs| {
                    if let Some(job) = jobs.iter_mut().find(|job| job.number == number) {
                        job.state = State::Stopped;
                        job.reading = reading;
                    }
                });
                self.log(format!("[{number}]+  {:<24}{command}", "Stopped"));
                Ok(Output {
                    failed: true,
                    ..Default::default()
                })
            }
        }
    }
    /// bg: the stopped job `spec` names, continued in the background.
    pub(super) fn bg(self, spec: Option<&str>) -> Result<Output, String> {
        let number = self.job(spec, "bg")?;
        let continued = self
            .jobs
            .try_update_value(|jobs| {
                let job = jobs.iter_mut().find(|job| job.number == number)?;
                let was = job.state;
                job.state = State::Running;
                Some((job.group.clone(), job.command.clone(), was))
            })
            .flatten();
        let Some((group, command, was)) = continued else {
            return Err(format!("bg: %{number}: no such job"));
        };
        if was == State::Running {
            return Err(format!("bg: job {number} already in background"));
        }
        signal(&group, SIGCONT);
        Ok(Output::text(format!("[{number}]+ {command} &\n")))
    }
}

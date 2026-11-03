//! Programs on processes: ps and kill, as procps' are, over /proc and the process calls. A PID
//! is a long word; the first eight of it name it, as ps shows it, and fewer do as long as one
//! matches.
use crate::files::parsed;
use crate::io::Io;
use crate::sys::{Sys, call, calls, getdents};
use abi::{Call, Data, Errno, Error};
use serde_json::Value;
use terminal_worker_core::cli::{archives as args, parse};

/// A process, as /proc/PID says: its PID, its state and progress, and its command line.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Process {
    pub pid: String,
    pub name: String,
    pub state: String,
    /// What it has done of what it does.
    pub done: u64,
    pub total: u64,
    pub cmdline: Vec<String>,
}
impl Process {
    /// What it runs, as ps shows it: its program and what it works on.
    pub fn command(&self) -> String {
        self.cmdline.join(" ")
    }
}

/// The account's processes, the latest first, as /proc lists them: each one's status and
/// command line, read in one batch.
pub async fn processes(sys: &impl Sys) -> Result<Vec<Process>, Error> {
    let pids: Vec<String> = getdents(sys, "/proc")
        .await?
        .into_iter()
        .map(|entry| entry.name)
        .filter(|name| name != "self")
        .collect();
    let read = |path: String| Call::Pread {
        fd: None,
        path: Some(path),
        offset: 0,
        count: abi::INLINE_MAX,
    };
    let mut files = calls::<Data>(
        sys,
        pids.iter()
            .flat_map(|pid| {
                [
                    read(format!("/proc/{pid}/status")),
                    read(format!("/proc/{pid}/cmdline")),
                ]
            })
            .collect(),
    )
    .await
    .into_iter();
    let mut found = Vec::new();
    for pid in pids {
        let (Some(Ok(status)), Some(Ok(cmdline))) = (files.next(), files.next()) else {
            continue;
        };
        let mut process = Process {
            pid,
            cmdline: String::from_utf8_lossy(&cmdline.data)
                .split('\0')
                .filter(|part| !part.is_empty())
                .map(String::from)
                .collect(),
            ..Process::default()
        };
        for line in String::from_utf8_lossy(&status.data).lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            match key {
                "Name" => process.name = value.into(),
                "State" => process.state = value.into(),
                "Progress" => {
                    let (done, total) = value.split_once('/').unwrap_or((value, "0"));
                    process.done = done.parse().unwrap_or(0);
                    process.total = total.parse().unwrap_or(0);
                }
                _ => {}
            }
        }
        found.push(process);
    }
    Ok(found)
}

/// A descriptor of this session, as /proc/self/fd and /proc/self/fdinfo say: its number, the
/// file, how it was opened, and what has arrived of a file it writes.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Descriptor {
    pub fd: u32,
    pub path: String,
    pub flags: u32,
    pub size: u64,
    pub received: u64,
    pub created: bool,
}

/// The session's descriptors, read in two batches: the links, and what each says of itself.
pub async fn descriptors(sys: &impl Sys) -> Result<Vec<Descriptor>, Error> {
    let entries = getdents(sys, "/proc/self/fd").await?;
    let infos = calls::<Data>(
        sys,
        entries
            .iter()
            .map(|entry| Call::Pread {
                fd: None,
                path: Some(format!("/proc/self/fdinfo/{}", entry.name)),
                offset: 0,
                count: abi::INLINE_MAX,
            })
            .collect(),
    )
    .await;
    let mut found = Vec::new();
    for (entry, info) in entries.into_iter().zip(infos) {
        let (Ok(fd), Ok(info)) = (entry.name.parse(), info) else {
            continue;
        };
        let mut descriptor = Descriptor {
            fd,
            path: entry.stat.and_then(|stat| stat.link).unwrap_or_default(),
            ..Descriptor::default()
        };
        for line in String::from_utf8_lossy(&info.data).lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            match key {
                "flags" => descriptor.flags = u32::from_str_radix(value, 8).unwrap_or(0),
                "size" => descriptor.size = value.parse().unwrap_or(0),
                "received" => descriptor.received = value.parse().unwrap_or(0),
                "created" => descriptor.created = value == "1",
                _ => {}
            }
        }
        found.push(descriptor);
    }
    Ok(found)
}

fn short(pid: &str) -> &str {
    pid.get(..8).unwrap_or(pid)
}

pub async fn ps(sys: &impl Sys, io: &mut Io<'_>) -> i32 {
    let _ = parsed!(io, args::Ps);
    let processes = match processes(sys).await {
        Ok(processes) => processes,
        Err(error) => {
            io.fail(format!("ps: {error}"));
            return 1;
        }
    };
    io.say(format!("{:<8}  {:<10}  COMMAND", "PID", "STAT"));
    for process in &processes {
        io.say(format!(
            "{:<8}  {:<10}  {}",
            short(&process.pid),
            process.state,
            process.command()
        ));
    }
    0
}

pub async fn kill(sys: &impl Sys, io: &mut Io<'_>) -> i32 {
    let kill = parsed!(io, args::Kill);
    let processes = processes(sys).await.unwrap_or_default();
    let mut status = 0;
    for given in &kill.pids {
        let matching: Vec<&str> = processes
            .iter()
            .map(|process| process.pid.as_str())
            .filter(|pid| pid.starts_with(given.as_str()))
            .collect();
        let pid = match matching.as_slice() {
            [pid] => pid.to_string(),
            // Not one of the account's: the kernel says whose, if anyone's.
            [] => given.clone(),
            _ => {
                io.fail(format!("kill: ({given}) - ambiguous: name more of it"));
                status = 1;
                continue;
            }
        };
        if let Err(error) = call::<Value>(sys, Call::Kill { pid }).await {
            let error = if error.errno == Errno::ESRCH {
                "No such process".to_string()
            } else {
                error.to_string()
            };
            io.fail(format!("kill: ({given}) - {error}"));
            status = 1;
        }
    }
    status
}

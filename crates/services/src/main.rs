//! The executable supervisor is ordinary user space, with the caller's process snapshot.
mod journal;
mod notify;

use journal::{Journals, Output};

use notify::Notification;
use os_core::cli::{self, terminal::Supervise};
use os_posix::process::{Child, SpawnOptions, Stdin, reap, spawn_configured};
use os_services::{Action, Manifest, Readiness, State, Supervisor};
use std::{
    collections::BTreeMap,
    io::{self, Read},
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
    time::{Duration, Instant},
};

static STOP: AtomicU32 = AtomicU32::new(0);
static REAP: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "wasi")]
#[unsafe(no_mangle)]
pub extern "C" fn __os_service_signal(signal: u32) {
    // Signal callbacks only set a flag; all I/O and process calls happen in the main loop.
    if signal == 17 {
        REAP.store(true, Ordering::SeqCst);
    }
    if [1, 2, 15].contains(&signal) {
        let _ = STOP.compare_exchange(0, signal, Ordering::SeqCst, Ordering::SeqCst);
    }
}
fn signals() -> io::Result<()> {
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
        let name = b"__os_service_signal";
        // SAFETY: the host copies this valid callback name; dispositions use scalar values.
        unsafe {
            callback_signal(name.as_ptr(), name.len());
            for signal in [1, 2, 15, 17] {
                // Let the short WASI sleep finish after setting STOP. Preview-1 libc
                // cannot provide nanosleep's remaining-time result on interruption.
                let result = sigaction(signal, 2, 0, 0x10000000); // SA_RESTART
                if result < 0 {
                    return Err(io::Error::from_raw_os_error(-result));
                }
            }
        }
        Ok(())
    }
    #[cfg(not(target_os = "wasi"))]
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "service execution requires the OS WASI runtime",
    ))
}
fn call(call: abi::Call) -> io::Result<serde_json::Value> {
    os_posix::batch(&[call])?
        .results
        .remove(0)
        .into_result()
        .map_err(|e| io::Error::other(e.to_string()))
}
fn group_stat(path: &str) -> io::Result<serde_json::Value> {
    call(abi::Call::CgroupStat { path: path.into() })
}
fn signal_group(path: &str, signal: u32) -> io::Result<()> {
    if signal == 9 {
        call(abi::Call::CgroupSet {
            path: path.into(),
            key: "cgroup.kill".into(),
            value: "1".into(),
        })?;
    } else {
        let group = group_stat(path)?;
        let calls = group["subtree.procs"]
            .as_array()
            .ok_or_else(|| io::Error::other("invalid cgroup reply"))?
            .iter()
            .filter_map(|pid| pid.as_u64())
            .map(|pid| abi::Call::Kill {
                pid: pid.to_string(),
                signal: Some(signal as u8),
            })
            .collect::<Vec<_>>();
        // Keep batches below the API limit even when a service has many descendants.
        for calls in calls.chunks(32) {
            for result in os_posix::batch(calls)?.results {
                if let Err(error) = result.into_result()
                    && error.errno != abi::Errno::ESRCH
                {
                    return Err(io::Error::other(error.to_string()));
                }
            }
        }
    }
    Ok(())
}
fn remove_group(path: &str) -> io::Result<()> {
    let mut paths = vec![path.to_owned()];
    let mut index = 0;
    while index < paths.len() {
        let value = group_stat(&paths[index])?;
        if let Some(children) = value["children"].as_array() {
            paths.extend(children.iter().filter_map(|p| p.as_str()).map(String::from));
        }
        index += 1;
        if paths.len() > 1024 {
            return Err(io::Error::other("too many cgroup descendants"));
        }
    }
    for path in paths.into_iter().rev() {
        call(abi::Call::CgroupRemove { path })?;
    }
    Ok(())
}
struct Running {
    child: Child,
    group: String,
    attempt: u32,
    success: Option<bool>,
    notification: Option<Notification>,
    output: Output,
}
struct Children(BTreeMap<usize, Running>);
impl Drop for Children {
    fn drop(&mut self) {
        for running in self.0.values() {
            let _ = signal_group(&running.group, 9);
        }
    }
}

fn check_readiness(
    i: usize,
    running: &mut Running,
    supervisor: &mut Supervisor,
    journal: &mut Journals,
    now: u64,
) {
    if STOP.load(Ordering::SeqCst) != 0 || supervisor.services[i].state != State::Starting {
        running.notification.take();
        return;
    }
    let Some(notification) = &mut running.notification else {
        return;
    };
    match notification.check() {
        Ok(false) => return,
        Ok(true) => {
            if supervisor.ready(i, running.child.id(), now) {
                eprintln!("supervise: {}: Ready", supervisor.manifest.units[i].name);
                journal.event(i, running.attempt, now, "Ready");
            }
        }
        Err(error) if error.kind() == io::ErrorKind::Interrupted => return,
        Err(error) => {
            eprintln!(
                "supervise: {}: readiness failed: {error}",
                supervisor.manifest.units[i].name
            );
            journal.event(
                i,
                running.attempt,
                now,
                &format!("readiness failed: {error}"),
            );
            supervisor.readiness_failed(i, running.child.id());
        }
    }
    running.notification.take();
}

fn run() -> Result<i32, String> {
    let args: Vec<String> = std::env::args().collect();
    if cli::wants_help(&args) {
        println!("{}", cli::help("supervise").unwrap());
        return Ok(0);
    }
    let options = cli::parse::<Supervise>(&args[1..])?;
    os_posix::init_preopens().map_err(|e| e.to_string())?;
    if let Ok(pwd) = std::env::var("PWD") {
        std::env::set_current_dir(pwd).map_err(|e| e.to_string())?;
    }
    let mut bytes = Vec::new();
    std::fs::File::open(&options.file)
        .and_then(|f| f.take(65537).read_to_end(&mut bytes))
        .map_err(|e| e.to_string())?;
    let manifest = Manifest::parse(&bytes)?;
    if options.check {
        return Ok(0);
    }
    signals().map_err(|e| e.to_string())?;
    call(abi::Call::Prctl {
        option: 36,
        value: 1,
    })
    .map_err(|e| e.to_string())?;
    let pid = call(abi::Call::Getpid).map_err(|e| e.to_string())?["pid"]
        .as_u64()
        .ok_or("missing supervisor pid")?;
    let mut journals = Journals::open(
        manifest.units.iter().map(|u| u.name.clone()).collect(),
        options.journal.as_deref(),
    )
    .map_err(|e| e.to_string())?;
    let mut supervisor = Supervisor::new(manifest);
    let mut children = Children(BTreeMap::new());
    let clock = Instant::now();
    let now = || clock.elapsed().as_millis().min(u64::MAX as u128) as u64;
    loop {
        for (&i, running) in &mut children.0 {
            running
                .output
                .drain(&mut journals, i, running.attempt, now())
                .map_err(|e| e.to_string())?;
            check_readiness(i, running, &mut supervisor, &mut journals, now());
        }
        // Drain all direct and adopted descendants on each coalesced SIGCHLD.
        if REAP.swap(false, Ordering::SeqCst) {
            loop {
                let ended = match reap() {
                    Ok(value) => value,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                        REAP.store(true, Ordering::SeqCst);
                        break;
                    }
                    Err(error) => return Err(error.to_string()),
                };
                let Some((pid, status)) = ended else {
                    break;
                };
                if let Some((&i, running)) =
                    children.0.iter_mut().find(|(_, r)| r.child.id() == pid)
                {
                    check_readiness(i, running, &mut supervisor, &mut journals, now());
                    signal_group(&running.group, 9).map_err(|e| e.to_string())?;
                    let message = format!(
                        "exited {}",
                        status
                            .code()
                            .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
                    );
                    eprintln!(
                        "supervise: {}: {message}",
                        supervisor.manifest.units[i].name
                    );
                    journals.event(i, running.attempt, now(), &message);
                    running.success = Some(status.success());
                }
            }
        }
        let mut exits = Vec::new();
        for (&i, running) in &mut children.0 {
            if let Some(success) = running.success {
                // No retry or dependent success until descendants and captured output drain.
                running
                    .output
                    .drain(&mut journals, i, running.attempt, now())
                    .map_err(|e| e.to_string())?;
                if running.output.ended()
                    && group_stat(&running.group).map_err(|e| e.to_string())?["subtree.procs"]
                        .as_array()
                        .is_some_and(Vec::is_empty)
                {
                    remove_group(&running.group).map_err(|e| e.to_string())?;
                    exits.push((i, success));
                }
            }
        }
        for (i, success) in exits {
            children.0.remove(&i);
            supervisor.exited(i, success, now());
        }
        let before: Vec<_> = supervisor.services.iter().map(|s| s.state).collect();
        for action in supervisor.tick(now(), STOP.load(Ordering::SeqCst) != 0) {
            match action {
                Action::Start(i) => {
                    if STOP.load(Ordering::SeqCst) != 0 {
                        continue;
                    }
                    supervisor.launching(i, now());
                    let unit = &supervisor.manifest.units[i];
                    let mut notification = if unit.readiness == Readiness::Notify {
                        match Notification::open() {
                            Ok(notification) => Some(notification),
                            Err(error) => {
                                eprintln!(
                                    "supervise: {}: readiness pipe failed: {error}",
                                    unit.name
                                );
                                supervisor.exited(i, false, now());
                                continue;
                            }
                        }
                    } else {
                        None
                    };
                    // Do not inherit ambient environment secrets into every service. These
                    // defaults and the explicit unit environment form its complete vector.
                    let mut env = BTreeMap::from([
                        ("PATH".into(), "/usr/bin".into()),
                        ("LANG".into(), "C.UTF-8".into()),
                        ("PWD".into(), unit.cwd.clone()),
                    ]);
                    env.extend(unit.environment.clone());
                    env.insert("PWD".into(), unit.cwd.clone());
                    if let Some(notification) = &notification {
                        env.insert("OS_READY_FD".into(), notification.fd());
                    }
                    let env = env
                        .into_iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect::<Vec<_>>();
                    let attempt = supervisor.services[i].restarts + 1;
                    let group = format!("/user/supervise-{pid}-{i}-{attempt}");
                    let mut output = Output::open().map_err(|e| e.to_string())?;
                    call(abi::Call::CgroupCreate {
                        path: group.clone(),
                        controllers: None,
                        lifetime: Some(abi::CgroupLifetime::Process),
                    })
                    .map_err(|e| e.to_string())?;
                    let actions = output.actions();
                    let result = (|| {
                        if let Some(limits) = &unit.limits {
                            let stat = group_stat(&group)?;
                            let mut controls = Vec::new();
                            for (key, value) in [
                                ("pids.max", limits.pids.map(u64::from)),
                                ("memory.max", limits.memory),
                            ] {
                                let Some(value) = value else {
                                    continue;
                                };
                                controls.push((key, value.to_string()));
                            }
                            if limits.read_bps.is_some() || limits.write_bps.is_some() {
                                let rate = |n: Option<u64>| {
                                    n.map_or_else(|| "max".to_string(), |n| n.to_string())
                                };
                                controls.push((
                                    "io.max",
                                    format!(
                                        "rbps={} wbps={}",
                                        rate(limits.read_bps),
                                        rate(limits.write_bps)
                                    ),
                                ));
                            }
                            for (key, value) in controls {
                                if !stat["resource.enforced"]
                                    .as_array()
                                    .is_some_and(|v| v.iter().any(|s| s == key))
                                {
                                    return Err(io::Error::new(
                                        io::ErrorKind::Unsupported,
                                        format!("host does not enforce {key}"),
                                    ));
                                }
                                call(abi::Call::CgroupSet {
                                    path: group.clone(),
                                    key: key.into(),
                                    value,
                                })?;
                            }
                        }
                        spawn_configured(
                            &unit.argv,
                            Stdin::Null,
                            &unit.cwd,
                            &env,
                            Some(0),
                            &SpawnOptions {
                                cgroup: Some(&group),
                                dup2: &actions,
                            },
                        )
                    })();
                    output.spawned();
                    if let Some(notification) = &mut notification {
                        notification.spawned();
                    }
                    match result {
                        Ok(child) => {
                            eprintln!("supervise: {}: started pid {}", unit.name, child.id());
                            journals.event(
                                i,
                                attempt,
                                now(),
                                &format!("started pid {}", child.id()),
                            );
                            supervisor.started(i, child.id(), now());
                            children.0.insert(
                                i,
                                Running {
                                    child,
                                    notification,
                                    group,
                                    attempt,
                                    success: None,
                                    output,
                                },
                            );
                        }
                        Err(error) => {
                            eprintln!("supervise: {}: start failed: {error}", unit.name);
                            journals.event(i, attempt, now(), &format!("start failed: {error}"));
                            remove_group(&group).map_err(|e| e.to_string())?;
                            supervisor.exited(i, false, now());
                        }
                    }
                }
                Action::StartupTimeout(i) => {
                    journals.event(
                        i,
                        supervisor.services[i].restarts + 1,
                        now(),
                        "startup deadline exceeded",
                    );
                    eprintln!(
                        "supervise: {}: startup deadline exceeded",
                        supervisor.manifest.units[i].name
                    );
                }
                Action::Signal { index, pid, signal } => {
                    eprintln!(
                        "supervise: {}: signal {signal}",
                        supervisor.manifest.units[index].name
                    );
                    let _ = pid;
                    if let Some(running) = children.0.get(&index) {
                        journals.event(index, running.attempt, now(), &format!("signal {signal}"));
                        signal_group(&running.group, signal).map_err(|e| e.to_string())?;
                    }
                }
            }
        }
        for (i, prior) in before.into_iter().enumerate() {
            if prior != supervisor.services[i].state {
                journals.event(
                    i,
                    supervisor.services[i].restarts + 1,
                    now(),
                    &format!("{:?}", supervisor.services[i].state),
                );
                eprintln!(
                    "supervise: {}: {:?}",
                    supervisor.manifest.units[i].name, supervisor.services[i].state
                );
            }
        }
        journals
            .flush(now(), supervisor.done())
            .map_err(|e| e.to_string())?;
        if supervisor.done() {
            let signal = STOP.load(Ordering::SeqCst);
            return Ok(if signal != 0 {
                128 + signal as i32
            } else {
                i32::from(supervisor.failed())
            });
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}
fn main() {
    let code = run().unwrap_or_else(|e| {
        eprintln!("supervise: {}", e.strip_prefix("supervise: ").unwrap_or(&e));
        1
    });
    std::process::exit(code);
}

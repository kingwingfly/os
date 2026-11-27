//! Installed WASI programs for operations not supplied by the coreutils WASI build.
//! The shell and dash execute these same bytes, with normal process credentials and stdio.
use os_core::{bin, cli, text};
use os_userland::{Io, Sys};
use std::io::{self, BufRead, Write};
mod accelerator;
mod chroot;
mod cowfs;
mod cowfsck;
mod exportctl;
mod findmnt;
mod imagectl;
mod losetup;
mod mkfs_cowfs;
mod mount;
mod mountctl;
mod netctl;
mod providerctl;
mod switch_root;
mod xargs;

struct Os;
impl Sys for Os {
    async fn batch(&self, calls: Vec<abi::Call>) -> Vec<Result<serde_json::Value, abi::Error>> {
        match os_posix::batch(&calls) {
            Ok(reply) => reply
                .results
                .into_iter()
                .map(abi::Return::into_result)
                .collect(),
            Err(error) => {
                vec![Err(abi::Error::because(abi::Errno::EIO, error.to_string())); calls.len()]
            }
        }
    }
    async fn read(&self, path: &str) -> Result<Vec<u8>, abi::Error> {
        std::fs::read(path).map_err(|error| {
            let errno = os_posix::errno_of(&error).unwrap_or(match error.kind() {
                io::ErrorKind::NotFound => abi::Errno::ENOENT,
                io::ErrorKind::PermissionDenied => abi::Errno::EACCES,
                io::ErrorKind::IsADirectory => abi::Errno::EISDIR,
                _ => abi::Errno::EIO,
            });
            abi::Error::because(errno, error.to_string())
        })
    }
    async fn write(&self, path: &str, bytes: &[u8]) -> Result<(), abi::Error> {
        // Descriptor writes use the runtime's chunked byte transport, independent of
        // the inline syscall limit. Explicit close observes the final commit error.
        let write = || -> io::Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(path)?;
            let result = file.write_all(bytes);
            #[cfg(target_os = "wasi")]
            {
                use std::os::wasi::io::IntoRawFd;
                #[link(wasm_import_module = "wasi_snapshot_preview1")]
                unsafe extern "C" {
                    fn fd_close(fd: u32) -> u32;
                }
                // SAFETY: ownership transfers from File to this one close operation.
                let errno = unsafe { fd_close(file.into_raw_fd() as u32) };
                result?;
                if errno != 0 {
                    return Err(io::Error::from_raw_os_error(errno as i32));
                }
                Ok(())
            }
            #[cfg(not(target_os = "wasi"))]
            {
                result
            }
        };
        write().map_err(|e| {
            let errno = os_posix::errno_of(&e).unwrap_or(match e.kind() {
                io::ErrorKind::PermissionDenied => abi::Errno::EACCES,
                io::ErrorKind::NotFound => abi::Errno::ENOENT,
                _ => abi::Errno::EIO,
            });
            abi::Error::because(errno, e.to_string())
        })
    }
}

fn main() {
    if let Err(error) = os_posix::init_preopens() {
        eprintln!("utilities: {error}");
        std::process::exit(1);
    }
    let mut args: Vec<String> = std::env::args().collect();
    let name = args
        .first()
        .and_then(|s| std::path::Path::new(s).file_name())
        .and_then(|s| s.to_str())
        .unwrap_or("utilities")
        .to_owned();
    if name == "utilities" {
        if args.len() == 1 {
            println!(
                "Usage: utilities PROGRAM [ARGUMENT]...\n\n{}",
                bin::UTILITIES.join(" ")
            );
            return;
        }
        args.remove(0);
    } else {
        args[0] = name;
    }
    if !bin::UTILITIES.contains(&args[0].as_str()) {
        eprintln!("utilities: {}: no such program", args[0]);
        std::process::exit(127);
    }
    if args[0] == "exportctl" {
        std::process::exit(exportctl::run(&args[1..]));
    }
    if args[0] == "netctl" {
        std::process::exit(netctl::run(&args[1..]));
    }
    if args[0] == "chroot" {
        std::process::exit(chroot::run(&args[1..]));
    }
    if args[0] == "switch_root" {
        std::process::exit(switch_root::run(&args[1..]));
    }
    if args[0] == "cowfsck" {
        std::process::exit(cowfsck::run(&args[1..]));
    }
    if args[0] == "mkfs.cowfs" {
        std::process::exit(mkfs_cowfs::run(&args[1..]));
    }
    if args[0] == "cowfs" {
        std::process::exit(cowfs::run(&args[1..]));
    }
    if args[0] == "losetup" {
        std::process::exit(losetup::run(&args[1..]));
    }
    if args[0] == "su" {
        std::process::exit(os_utilities::su::run(&args[1..]));
    }
    if args[0] == "sudo" {
        std::process::exit(os_utilities::sudo::run(&args[1..]));
    }
    if args[0] == "passwd" {
        std::process::exit(os_utilities::passwd::run(&args[1..]));
    }
    if args[0] == "login" {
        std::process::exit(os_utilities::login::run(&args[1..]));
    }
    if args[0] == "newgrp" {
        std::process::exit(os_utilities::newgrp::run(&args[1..]));
    }
    if args[0] == "service" {
        std::process::exit(os_utilities::service::run(&args[1..]));
    }
    if matches!(
        args[0].as_str(),
        "open" | "vim" | "man" | "present" | "stream" | "upload"
    ) {
        std::process::exit(os_utilities::desktop_actions::run(&args[0], &args[1..]));
    }
    if cli::wants_help(&args)
        && let Some(help) = cli::help(&args[0])
    {
        println!("{help}");
        return;
    }
    if args[0] == "mountctl" {
        std::process::exit(mountctl::run(&args[1..]));
    }
    if args[0] == "mount" {
        std::process::exit(mount::run_mount(&args[1..]));
    }
    if args[0] == "umount" {
        std::process::exit(mount::run_umount(&args[1..]));
    }
    if args[0] == "findmnt" {
        std::process::exit(findmnt::run(&args[1..]));
    }
    if matches!(args[0].as_str(), "zip" | "unzip" | "tar" | "faststart") {
        let status = accelerator::run(&args[0], &args[1..]).unwrap_or_else(|error| {
            let prefix = format!("{}: ", args[0]);
            eprintln!(
                "{}{}",
                prefix,
                error.strip_prefix(&prefix).unwrap_or(&error)
            );
            1
        });
        std::process::exit(status);
    }
    if args[0] == "imagectl" {
        if let Err(error) = imagectl::run(&args[1..]) {
            eprintln!("imagectl: {error}");
            std::process::exit(1);
        }
        return;
    }
    if args[0] == "providerctl" {
        if let Err(error) = providerctl::run(&args[1..]) {
            eprintln!("providerctl: {error}");
            std::process::exit(1);
        }
        return;
    }
    if args[0] == "grep" {
        let status = match grep(&args[1..]) {
            Ok(status) => status,
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => 141,
            Err(error) => {
                let message = error.to_string();
                eprintln!(
                    "grep: {}",
                    message.strip_prefix("grep: ").unwrap_or(&message)
                );
                2
            }
        };
        std::process::exit(status);
    }
    if args[0] == "xargs" {
        let status = xargs::run(&args[1..]).unwrap_or_else(|error| {
            eprintln!("xargs: {error}");
            1
        });
        std::process::exit(status);
    }
    let fd_exec = (args[0] == "fd")
        .then(|| {
            os_core::find::parse(&args[1..])
                .ok()
                .and_then(|find| find.exec)
        })
        .flatten();
    let ask =
        |question: String| -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<String>>>> {
            Box::pin(async move {
                eprint!("{question}");
                io::stderr().flush().ok()?;
                let mut line = String::new();
                (io::stdin().read_line(&mut line).ok()? != 0).then_some(line)
            })
        };
    let mut state = Io {
        args,
        cwd: std::env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default(),
        home: std::env::var("HOME").unwrap_or_else(|_| "/".into()),
        now: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        stdin: None,
        out: String::new(),
        err: Vec::new(),
        found: Vec::new(),
        cancelled: &|| false,
        ask: &ask,
    };
    let mut status = futures::executor::block_on(os_userland::run(&Os, &mut state)).unwrap_or(127);
    if let Some((all, template)) = fd_exec {
        use os_core::shell::{exec_all, exec_one};
        use os_posix::process::{Stdin, spawn};
        let commands = if state.found.is_empty() {
            Vec::new()
        } else if all {
            vec![exec_all(&template, &state.found)]
        } else {
            state
                .found
                .iter()
                .map(|path| exec_one(&template, path))
                .collect()
        };
        for command in commands {
            match spawn(&command, Stdin::Inherit).and_then(|child| child.wait()) {
                Ok(exit) => {
                    if !exit.success() {
                        status = 1;
                    }
                }
                Err(error) => {
                    eprintln!("fd: {}: {error}", command[0]);
                    status = 1;
                }
            }
        }
    } else if let Err(error) = io::stdout().write_all(state.out.as_bytes()) {
        status = if error.kind() == io::ErrorKind::BrokenPipe {
            141
        } else {
            1
        };
    }
    for error in state.err {
        eprintln!("{error}");
    }
    std::process::exit(status);
}

/// Stream matching lines so an interactive pipe can produce output before EOF.
fn grep(args: &[String]) -> io::Result<i32> {
    let text::Grep {
        pattern,
        invert,
        number,
        count,
        files,
    } = text::grep(args).map_err(io::Error::other)?;
    let files = if files.is_empty() {
        vec!["-".into()]
    } else {
        files
    };
    let several = files.len() > 1;
    let mut matched = false;
    let mut failed = false;
    let stdout = io::stdout();
    let mut output = stdout.lock();
    for file in files {
        let input: Box<dyn BufRead> = if file == "-" {
            Box::new(io::BufReader::new(io::stdin()))
        } else {
            match std::fs::File::open(&file) {
                Ok(file) => Box::new(io::BufReader::new(file)),
                Err(error) => {
                    eprintln!("grep: {file}: {error}");
                    failed = true;
                    continue;
                }
            }
        };
        let prefix = if several {
            format!("{file}:")
        } else {
            String::new()
        };
        let mut found = 0;
        for (index, line) in input.split(b'\n').enumerate() {
            let line = line?;
            let line = String::from_utf8_lossy(&line);
            if pattern.is_match(&line) == invert {
                continue;
            }
            found += 1;
            if !count {
                write!(output, "{prefix}")?;
                if number {
                    write!(output, "{}:", index + 1)?;
                }
                writeln!(output, "{line}")?;
                output.flush()?;
            }
        }
        matched |= found > 0;
        if count {
            writeln!(output, "{prefix}{found}")?;
        }
    }
    Ok(if failed { 2 } else { i32::from(!matched) })
}

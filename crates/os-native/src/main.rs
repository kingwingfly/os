//! CLI entrypoint for `os-native`: `run`, `attach`, `exec`, `token`, and `inspect`.

use os_native::attach_cli::{run_attach_cli, run_exec_cli, send_control_request};
use os_native::{
    ControlReply, ControlRequest, NativeBootConfig, NativeOsHost, NativeRootSpec, NativeWriterMode,
    SeatServerConfig, SeatServerHandle,
};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

fn usage() -> &'static str {
    "os-native — Standalone headless native OS host (Contract v2 / HostAdapter v2)\n\n\
     USAGE:\n\
       os-native run --bundle <DIR> --state <DIR> [OPTIONS]\n\
       os-native attach --target <unix://...|tcp://...|ws://...> (--token <TOK> | --token-file <FILE>) [--seat <N>] [--spawn]\n\
       os-native exec --target <...> (--token <TOK> | --token-file <FILE>) [--cwd <DIR>] -- <CMD> [ARGS...]\n\
       os-native token create --state <DIR> [--uid <N>] [--label <STR>] [--seats <0,1>] [--no-exec] [--ttl <SECS>] [--json]\n\
       os-native token list --state <DIR> [--json]\n\
       os-native token revoke --state <DIR> <ID_OR_PREFIX> [--json]\n\
       os-native inspect --state <DIR> [--json]\n"
}

fn next_arg(args: &[String], idx: &mut usize, flag: &str) -> Result<String, String> {
    *idx += 1;
    args.get(*idx)
        .cloned()
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn read_token_arg(token: Option<String>, token_file: Option<PathBuf>) -> Result<String, String> {
    if let Some(t) = token {
        return Ok(t.trim().to_string());
    }
    if let Some(p) = token_file {
        let s = std::fs::read_to_string(&p)
            .map_err(|e| format!("read token file {}: {e}", p.display()))?;
        return Ok(s.trim().to_string());
    }
    if let Ok(env_t) = std::env::var("OS_NATIVE_TOKEN")
        && !env_t.trim().is_empty()
    {
        return Ok(env_t.trim().to_string());
    }
    Err("authentication token required (--token, --token-file, or OS_NATIVE_TOKEN)".into())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help" | "help") {
        print!("{}", usage());
        return;
    }

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("os-native: failed to build tokio runtime: {e}");
            std::process::exit(1);
        }
    };

    let code = rt.block_on(async_main(args));
    std::process::exit(code);
}

async fn async_main(args: Vec<String>) -> i32 {
    let cmd = args[0].as_str();
    let rest = &args[1..];
    let res = match cmd {
        "run" => cmd_run(rest).await,
        "attach" => cmd_attach(rest).await,
        "exec" => cmd_exec(rest).await,
        "token" => cmd_token(rest).await,
        "inspect" => cmd_inspect(rest).await,
        other => Err(format!("unknown subcommand '{other}'\n\n{}", usage())),
    };
    match res {
        Ok(code) => code,
        Err(e) => {
            eprintln!("os-native: {e}");
            1
        }
    }
}

async fn cmd_run(args: &[String]) -> Result<i32, String> {
    let mut bundle_dir: Option<PathBuf> = None;
    let mut state_dir: Option<PathBuf> = None;
    let mut trust_path: Option<PathBuf> = None;
    let mut allow_unsigned_dev = false;
    let mut listen: Option<SocketAddr> = None;
    let mut unix_seat: Option<PathBuf> = None;
    let mut no_unix_seat = false;
    let mut default_user = "user".to_string();
    let mut ephemeral = false;
    let mut volume_uuid: Option<String> = None;
    let mut writer_mode = NativeWriterMode::ForkOnBusy;
    let mut recovery = false;
    let mut spawn_console_shell = true;
    let mut boot_timeout_secs = 30u64;
    let mut bootstrap_token_file: Option<PathBuf> =
        std::env::var_os("OS_NATIVE_BOOTSTRAP_TOKEN_FILE").map(PathBuf::from);
    let mut ready_file: Option<PathBuf> = None;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--bundle" => bundle_dir = Some(PathBuf::from(next_arg(args, &mut i, "--bundle")?)),
            "--state" => state_dir = Some(PathBuf::from(next_arg(args, &mut i, "--state")?)),
            "--trust" => trust_path = Some(PathBuf::from(next_arg(args, &mut i, "--trust")?)),
            "--allow-unsigned-dev" => allow_unsigned_dev = true,
            "--listen" => {
                let s = next_arg(args, &mut i, "--listen")?;
                listen = Some(
                    s.parse::<SocketAddr>()
                        .map_err(|e| format!("invalid --listen '{s}': {e}"))?,
                );
            }
            "--unix" => unix_seat = Some(PathBuf::from(next_arg(args, &mut i, "--unix")?)),
            "--no-unix" => no_unix_seat = true,
            "--user" => default_user = next_arg(args, &mut i, "--user")?,
            "--root" => {
                let v = next_arg(args, &mut i, "--root")?;
                match v.as_str() {
                    "cowfs" => ephemeral = false,
                    "ephemeral" => ephemeral = true,
                    _ => return Err(format!("invalid --root '{v}' (expected cowfs|ephemeral)")),
                }
            }
            "--volume" => volume_uuid = Some(next_arg(args, &mut i, "--volume")?),
            "--writer-mode" => {
                let v = next_arg(args, &mut i, "--writer-mode")?;
                writer_mode = match v.as_str() {
                    "fork-on-busy" | "fork_on_busy" => NativeWriterMode::ForkOnBusy,
                    "exclusive" => NativeWriterMode::Exclusive,
                    _ => {
                        return Err(format!(
                            "invalid --writer-mode '{v}' (expected fork-on-busy|exclusive)"
                        ));
                    }
                };
            }
            "--recovery" => recovery = true,
            "--no-console-shell" => spawn_console_shell = false,
            "--boot-timeout" => {
                let v = next_arg(args, &mut i, "--boot-timeout")?;
                boot_timeout_secs = v
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --boot-timeout '{v}'"))?;
            }
            "--bootstrap-token-file" => {
                bootstrap_token_file = Some(PathBuf::from(next_arg(
                    args,
                    &mut i,
                    "--bootstrap-token-file",
                )?));
            }
            "--ready-file" => {
                ready_file = Some(PathBuf::from(next_arg(args, &mut i, "--ready-file")?));
            }
            other => return Err(format!("unknown flag for run: {other}")),
        }
        i += 1;
    }

    let bundle_dir = bundle_dir.ok_or("missing required --bundle <DIR>")?;
    let state_dir = state_dir.ok_or("missing required --state <DIR>")?;

    let mut boot_cfg = NativeBootConfig::new(bundle_dir, state_dir.clone());
    boot_cfg.trust_path = trust_path;
    boot_cfg.allow_unsigned_dev = allow_unsigned_dev;
    boot_cfg.default_user = default_user;
    boot_cfg.recovery = recovery;
    boot_cfg.spawn_console_shell = spawn_console_shell;
    boot_cfg.boot_timeout = Duration::from_secs(boot_timeout_secs);
    boot_cfg.root = if ephemeral {
        NativeRootSpec::Ephemeral
    } else {
        NativeRootSpec::CowFs {
            volume_uuid,
            writer_mode,
        }
    };

    let host = tokio::task::spawn_blocking(move || NativeOsHost::boot(boot_cfg))
        .await
        .map_err(|e| format!("boot join error: {e}"))??;
    let host = Arc::new(host);

    let seat_cfg = SeatServerConfig {
        state_dir: state_dir.clone(),
        unix_seat_path: if no_unix_seat {
            None
        } else {
            Some(unix_seat.unwrap_or_else(|| state_dir.join("seat.sock")))
        },
        tcp_listen: listen,
    };
    let server = SeatServerHandle::start(Arc::clone(&host), seat_cfg).await?;

    if let Some(ref tok_path) = bootstrap_token_file {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let (_rec, secret) =
            server
                .tokens
                .create_token(0, "bootstrap".to_string(), Vec::new(), true, None)?;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(tok_path)
            .map_err(|e| format!("create {}: {e}", tok_path.display()))?;
        f.write_all(format!("{secret}\n").as_bytes())
            .map_err(|e| format!("write {}: {e}", tok_path.display()))?;
        let _ = std::fs::set_permissions(tok_path, std::fs::Permissions::from_mode(0o600));
    }

    let info = host.inspect().await;
    if let Some(ref rf) = ready_file {
        let _ = std::fs::write(rf, serde_json::to_vec_pretty(&info).unwrap_or_default());
    }
    eprintln!(
        "os-native: ready instance={} release={} root={:?} boot_healthy={} ctl={} tcp={:?}",
        info.instance_id,
        info.release_id,
        info.root_volume,
        info.boot_healthy,
        server.ctl_sock_path.display(),
        server.tcp_addr
    );

    // Wait for SIGINT or SIGTERM and perform a clean OS shutdown + CowFs flush.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| format!("signal handler: {e}"))?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
    }

    eprintln!("os-native: shutting down cleanly...");
    server.stop();
    match host.shutdown().await {
        Ok(clean) => {
            eprintln!("os-native: shutdown complete (clean={clean})");
            Ok(0)
        }
        Err(e) => Err(format!("clean shutdown failed: {e}")),
    }
}

async fn cmd_attach(args: &[String]) -> Result<i32, String> {
    let mut target: Option<String> = None;
    let mut token: Option<String> = None;
    let mut token_file: Option<PathBuf> = None;
    let mut seat: Option<u32> = None;
    let mut spawn = false;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--target" => target = Some(next_arg(args, &mut i, "--target")?),
            "--token" => token = Some(next_arg(args, &mut i, "--token")?),
            "--token-file" => {
                token_file = Some(PathBuf::from(next_arg(args, &mut i, "--token-file")?));
            }
            "--seat" => {
                let s = next_arg(args, &mut i, "--seat")?;
                seat = Some(
                    s.parse::<u32>()
                        .map_err(|_| format!("invalid --seat '{s}'"))?,
                );
            }
            "--spawn" => spawn = true,
            other => return Err(format!("unknown flag for attach: {other}")),
        }
        i += 1;
    }

    let target = target.ok_or("missing required --target <unix://...|tcp://...|ws://...>")?;
    let token = read_token_arg(token, token_file)?;
    run_attach_cli(&target, &token, seat, spawn).await
}

async fn cmd_exec(args: &[String]) -> Result<i32, String> {
    let mut target: Option<String> = None;
    let mut token: Option<String> = None;
    let mut token_file: Option<PathBuf> = None;
    let mut cwd: Option<String> = None;
    let mut timeout_ms: Option<u64> = None;
    let mut argv: Vec<String> = Vec::new();

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--" => {
                argv.extend_from_slice(&args[i + 1..]);
                break;
            }
            "--target" => target = Some(next_arg(args, &mut i, "--target")?),
            "--token" => token = Some(next_arg(args, &mut i, "--token")?),
            "--token-file" => {
                token_file = Some(PathBuf::from(next_arg(args, &mut i, "--token-file")?));
            }
            "--cwd" => cwd = Some(next_arg(args, &mut i, "--cwd")?),
            "--timeout-ms" => {
                let v = next_arg(args, &mut i, "--timeout-ms")?;
                timeout_ms = Some(
                    v.parse::<u64>()
                        .map_err(|_| format!("invalid --timeout-ms '{v}'"))?,
                );
            }
            other if !other.starts_with('-') => {
                argv.extend_from_slice(&args[i..]);
                break;
            }
            other => return Err(format!("unknown flag for exec: {other}")),
        }
        i += 1;
    }

    let target = target.ok_or("missing required --target")?;
    let token = read_token_arg(token, token_file)?;
    if argv.is_empty() {
        return Err("missing command after --".into());
    }
    run_exec_cli(&target, &token, argv, cwd, timeout_ms).await
}

async fn cmd_token(args: &[String]) -> Result<i32, String> {
    let sub = args
        .first()
        .map(String::as_str)
        .ok_or("expected subcommand: token create | list | revoke")?;
    let rest = &args[1..];
    match sub {
        "create" => {
            let mut state_dir: Option<PathBuf> = None;
            let mut uid = 1000u32;
            let mut label = "remote".to_string();
            let mut allowed_seats = Vec::new();
            let mut can_exec = true;
            let mut ttl_secs: Option<u64> = None;
            let mut as_json = false;

            let mut i = 0usize;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--state" => {
                        state_dir = Some(PathBuf::from(next_arg(rest, &mut i, "--state")?));
                    }
                    "--uid" => {
                        let v = next_arg(rest, &mut i, "--uid")?;
                        uid = v
                            .parse::<u32>()
                            .map_err(|_| format!("invalid --uid '{v}'"))?;
                    }
                    "--label" => label = next_arg(rest, &mut i, "--label")?,
                    "--seats" => {
                        let v = next_arg(rest, &mut i, "--seats")?;
                        for part in v.split(',').filter(|s| !s.is_empty()) {
                            allowed_seats.push(
                                part.parse::<u32>()
                                    .map_err(|_| format!("invalid seat number '{part}'"))?,
                            );
                        }
                    }
                    "--no-exec" => can_exec = false,
                    "--ttl" => {
                        let v = next_arg(rest, &mut i, "--ttl")?;
                        ttl_secs = Some(
                            v.parse::<u64>()
                                .map_err(|_| format!("invalid --ttl '{v}'"))?,
                        );
                    }
                    "--json" => as_json = true,
                    other => return Err(format!("unknown flag for token create: {other}")),
                }
                i += 1;
            }
            let state_dir = state_dir.ok_or("missing required --state <DIR>")?;
            let reply = send_control_request(
                &state_dir,
                ControlRequest::CreateToken {
                    uid,
                    label,
                    allowed_seats,
                    can_exec,
                    ttl_secs,
                },
            )
            .await?;
            match reply {
                ControlReply::TokenCreated { record, token } => {
                    if as_json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "id": record.id,
                                "token": token,
                                "uid": record.uid,
                                "allowed_seats": record.allowed_seats,
                                "can_exec": record.can_exec,
                                "expires_at": record.expires_at,
                            }))
                            .unwrap()
                        );
                    } else {
                        println!("id={}\ntoken={}", record.id, token);
                    }
                    Ok(0)
                }
                ControlReply::Error { message } => Err(message),
                other => Err(format!("unexpected control reply: {other:?}")),
            }
        }
        "list" => {
            let mut state_dir: Option<PathBuf> = None;
            let mut as_json = false;
            let mut i = 0usize;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--state" => {
                        state_dir = Some(PathBuf::from(next_arg(rest, &mut i, "--state")?));
                    }
                    "--json" => as_json = true,
                    other => return Err(format!("unknown flag for token list: {other}")),
                }
                i += 1;
            }
            let state_dir = state_dir.ok_or("missing required --state <DIR>")?;
            let reply = send_control_request(&state_dir, ControlRequest::ListTokens).await?;
            match reply {
                ControlReply::Tokens { tokens } => {
                    if as_json {
                        println!("{}", serde_json::to_string_pretty(&tokens).unwrap());
                    } else {
                        for t in tokens {
                            println!(
                                "{} uid={} label={} seats={:?} exec={} revoked={} expires_at={:?}",
                                t.id,
                                t.uid,
                                t.label,
                                t.allowed_seats,
                                t.can_exec,
                                t.revoked,
                                t.expires_at
                            );
                        }
                    }
                    Ok(0)
                }
                ControlReply::Error { message } => Err(message),
                other => Err(format!("unexpected control reply: {other:?}")),
            }
        }
        "revoke" => {
            let mut state_dir: Option<PathBuf> = None;
            let mut id: Option<String> = None;
            let mut as_json = false;
            let mut i = 0usize;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--state" => {
                        state_dir = Some(PathBuf::from(next_arg(rest, &mut i, "--state")?));
                    }
                    "--json" => as_json = true,
                    other if !other.starts_with('-') && id.is_none() => {
                        id = Some(other.to_string())
                    }
                    other => return Err(format!("unknown arg for token revoke: {other}")),
                }
                i += 1;
            }
            let state_dir = state_dir.ok_or("missing required --state <DIR>")?;
            let id_or_prefix = id.ok_or("missing token id/prefix")?;
            let reply =
                send_control_request(&state_dir, ControlRequest::RevokeToken { id_or_prefix })
                    .await?;
            match reply {
                ControlReply::Revoked {
                    token_ids,
                    disconnected_clients,
                } => {
                    if as_json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "token_ids": token_ids,
                                "disconnected_clients": disconnected_clients,
                            }))
                            .unwrap()
                        );
                    } else {
                        println!(
                            "revoked={:?} disconnected_clients={}",
                            token_ids, disconnected_clients
                        );
                    }
                    Ok(0)
                }
                ControlReply::Error { message } => Err(message),
                other => Err(format!("unexpected control reply: {other:?}")),
            }
        }
        other => Err(format!("unknown token subcommand '{other}'")),
    }
}

async fn cmd_inspect(args: &[String]) -> Result<i32, String> {
    let mut state_dir: Option<PathBuf> = None;
    let mut as_json = false;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--state" => state_dir = Some(PathBuf::from(next_arg(args, &mut i, "--state")?)),
            "--json" => as_json = true,
            other => return Err(format!("unknown flag for inspect: {other}")),
        }
        i += 1;
    }
    let state_dir = state_dir.ok_or("missing required --state <DIR>")?;
    let reply = send_control_request(&state_dir, ControlRequest::Inspect).await?;
    match reply {
        ControlReply::Inspect(info) => {
            if as_json {
                println!("{}", serde_json::to_string_pretty(&info).unwrap());
            } else {
                println!(
                    "instance={} release={} stage={} boot_healthy={} root={:?} epoch={} pids={:?} ptys={:?}",
                    info.instance_id,
                    info.release_id,
                    info.stage,
                    info.boot_healthy,
                    info.root_volume,
                    info.root_epoch,
                    info.pids,
                    info.pty_numbers
                );
            }
            Ok(0)
        }
        ControlReply::Error { message } => Err(message),
        other => Err(format!("unexpected control reply: {other:?}")),
    }
}

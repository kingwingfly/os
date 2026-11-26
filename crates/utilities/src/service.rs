//! `service` CLI applet for PID 1 (`/run/init/control.sock`) and per-user
//! (`/run/user/<uid>/manager.sock`) Service Manager v2 (`#57` `L3d`, Contract v2 §2.8, §2.15).
//!
//! Speaks the framed newline-delimited JSON control protocol defined in
//! `crates/services/src/control.rs`. Wave 4B plugs Track 1's `os_posix::socket::UnixStream`
//! directly into `OsServiceTransport`.

use abi::{Call, Creds, Errno};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const SYSTEM_CONTROL_SOCKET: &str = "/run/init/control.sock";

pub const USAGE: &str = "\
Usage: service [--user] [--socket PATH] [--json] COMMAND [UNIT]

Inspect and control PID 1 or per-user Service Manager v2 units.
Commands:
  list | ls            list all loaded units and their states
  status [UNIT]        show detailed status for UNIT (or all units)
  start UNIT           activate UNIT and its dependencies
  stop UNIT            stop UNIT and dependent required units
  restart UNIT         restart UNIT
  enable UNIT          mark UNIT enabled for target activation
  disable UNIT         mark UNIT disabled
  poweroff             ordered reverse shutdown, unmount, and clean root close (root)
  reboot               ordered reverse shutdown, unmount, and reboot (root)

Options:
  --user               connect to /run/user/<uid>/manager.sock
  --socket PATH        connect to an explicit AF_UNIX control socket path
  --json               print raw JSON reply from the service manager
  -h, --help           display this help and exit";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceCommand {
    List,
    Status { unit: Option<String> },
    Start { unit: String },
    Stop { unit: String },
    Restart { unit: String },
    Enable { unit: String },
    Disable { unit: String },
    Poweroff,
    Reboot,
}

impl ServiceCommand {
    /// Encode as the exact JSON control frame expected by `os_services::control::ControlRequest`.
    pub fn to_request_json(&self) -> Value {
        match self {
            Self::List => json!({ "op": "list" }),
            Self::Status { unit: None } => json!({ "op": "status" }),
            Self::Status { unit: Some(u) } => json!({ "op": "status", "unit": u }),
            Self::Start { unit } => json!({ "op": "start", "unit": unit }),
            Self::Stop { unit } => json!({ "op": "stop", "unit": unit }),
            Self::Restart { unit } => json!({ "op": "restart", "unit": unit }),
            Self::Enable { unit } => json!({ "op": "enable", "unit": unit }),
            Self::Disable { unit } => json!({ "op": "disable", "unit": unit }),
            Self::Poweroff => json!({ "op": "poweroff" }),
            Self::Reboot => json!({ "op": "reboot" }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceAction {
    Help(String),
    Run(ServiceOptions),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceOptions {
    pub user_manager: bool,
    pub socket: Option<String>,
    pub json: bool,
    pub command: ServiceCommand,
}

pub fn parse_args(args: &[String]) -> Result<ServiceAction, (String, i32)> {
    let mut user_manager = false;
    let mut socket: Option<String> = None;
    let mut json_out = false;
    let mut rest: Vec<String> = Vec::new();
    let mut i = 0;

    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "-h" | "--help" => return Ok(ServiceAction::Help(USAGE.to_owned())),
            "--user" => {
                user_manager = true;
                i += 1;
            }
            "--json" => {
                json_out = true;
                i += 1;
            }
            "--socket" => {
                let Some(path) = args.get(i + 1) else {
                    return Err(("service: --socket requires a PATH argument".into(), 2));
                };
                socket = Some(path.clone());
                i += 2;
            }
            "--" => {
                rest.extend(args[i + 1..].iter().cloned());
                break;
            }
            other if other.starts_with('-') => {
                return Err((format!("service: unsupported option '{other}'"), 2));
            }
            _ => {
                rest.extend(args[i..].iter().cloned());
                break;
            }
        }
    }

    let Some(cmd) = rest.first().map(String::as_str) else {
        return Err((
            "service: missing command (use service -h for usage)".into(),
            2,
        ));
    };

    let normalize_unit = |raw: &str| -> String {
        if raw.contains('.') {
            raw.to_owned()
        } else {
            format!("{raw}.service")
        }
    };
    let require_unit = |verb: &str| -> Result<String, (String, i32)> {
        if rest.len() != 2 {
            return Err((format!("service: '{verb}' requires exactly one UNIT"), 2));
        }
        Ok(normalize_unit(&rest[1]))
    };
    let require_no_args = |verb: &str| -> Result<(), (String, i32)> {
        if rest.len() != 1 {
            return Err((format!("service: '{verb}' takes no operands"), 2));
        }
        Ok(())
    };

    let command = match cmd {
        "list" | "ls" => {
            require_no_args(cmd)?;
            ServiceCommand::List
        }
        "status" => {
            if rest.len() > 2 {
                return Err(("service: 'status' accepts at most one UNIT".into(), 2));
            }
            ServiceCommand::Status {
                unit: rest.get(1).map(|u| normalize_unit(u)),
            }
        }
        "start" => ServiceCommand::Start {
            unit: require_unit("start")?,
        },
        "stop" => ServiceCommand::Stop {
            unit: require_unit("stop")?,
        },
        "restart" => ServiceCommand::Restart {
            unit: require_unit("restart")?,
        },
        "enable" => ServiceCommand::Enable {
            unit: require_unit("enable")?,
        },
        "disable" => ServiceCommand::Disable {
            unit: require_unit("disable")?,
        },
        "poweroff" => {
            require_no_args("poweroff")?;
            ServiceCommand::Poweroff
        }
        "reboot" => {
            require_no_args("reboot")?;
            ServiceCommand::Reboot
        }
        other => {
            return Err((
                format!("service: unknown command '{other}' (use service -h for usage)"),
                2,
            ));
        }
    };

    Ok(ServiceAction::Run(ServiceOptions {
        user_manager,
        socket,
        json: json_out,
        command,
    }))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitView {
    pub name: String,
    pub kind: String,
    pub state: String,
    pub enabled: bool,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub attempts: u32,
    #[serde(default)]
    pub status_text: Option<String>,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Reply {
    Ok {
        #[serde(default)]
        message: Option<String>,
    },
    Units {
        units: Vec<UnitView>,
    },
    Unit {
        unit: UnitView,
    },
    Error {
        errno: Errno,
        message: String,
    },
}

pub trait ServiceTransport {
    fn current_uid(&mut self) -> Result<u32, abi::Error>;
    fn send_control(
        &mut self,
        socket_path: &str,
        request_frame: &[u8],
    ) -> Result<Vec<u8>, abi::Error>;
}

struct OsServiceTransport;

impl ServiceTransport for OsServiceTransport {
    fn current_uid(&mut self) -> Result<u32, abi::Error> {
        let mut reply = os_posix::batch(&[Call::Getcreds])
            .map_err(|e| abi::Error::because(Errno::EIO, e.to_string()))?;
        let val = reply.results.remove(0).into_result()?;
        let creds: Creds = serde_json::from_value(val)
            .map_err(|e| abi::Error::because(Errno::EIO, format!("invalid creds reply: {e}")))?;
        Ok(creds.uid)
    }

    fn send_control(
        &mut self,
        socket_path: &str,
        request_frame: &[u8],
    ) -> Result<Vec<u8>, abi::Error> {
        use os_posix::socket::{MSG_NOSIGNAL, SHUT_WR, UnixStream};

        let stream = UnixStream::connect(socket_path).map_err(|errno| {
            abi::Error::because(
                errno,
                format!("cannot connect to service manager socket '{socket_path}'"),
            )
        })?;
        let mut written = 0usize;
        while written < request_frame.len() {
            match stream.send(&request_frame[written..], MSG_NOSIGNAL) {
                Ok(0) => {
                    return Err(abi::Error::because(
                        Errno::EPIPE,
                        "control socket closed during send",
                    ));
                }
                Ok(n) => written += n,
                Err(Errno::EINTR) => continue,
                Err(errno) => {
                    return Err(abi::Error::because(errno, "control socket send failed"));
                }
            }
        }
        let _ = stream.shutdown(SHUT_WR);

        let mut response = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match stream.recv(&mut buf, 0) {
                Ok(0) => break,
                Ok(n) => {
                    response.extend_from_slice(&buf[..n]);
                    if response.len() > 65_536 {
                        return Err(abi::Error::because(
                            Errno::E2BIG,
                            "service manager reply exceeded 64 KiB",
                        ));
                    }
                    if response.ends_with(b"\n") {
                        break;
                    }
                }
                Err(Errno::EINTR) => continue,
                Err(Errno::EAGAIN) => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(errno) => {
                    return Err(abi::Error::because(errno, "control socket receive failed"));
                }
            }
        }
        if response.is_empty() {
            return Err(abi::Error::because(
                Errno::ECONNRESET,
                "service manager closed control socket without reply",
            ));
        }
        Ok(response)
    }
}

fn format_units_table(units: &[UnitView]) -> String {
    let mut lines = vec![format!(
        "{:<30} {:<9} {:<10} {:<8} {:<6} {}",
        "UNIT", "KIND", "STATE", "ENABLED", "PID", "STATUS"
    )];
    for u in units {
        let enabled = if u.enabled { "enabled" } else { "disabled" };
        let pid = u.pid.map_or_else(|| "-".to_owned(), |p| p.to_string());
        let detail = u
            .last_error
            .as_deref()
            .or(u.status_text.as_deref())
            .unwrap_or("");
        lines.push(format!(
            "{:<30} {:<9} {:<10} {:<8} {:<6} {}",
            u.name, u.kind, u.state, enabled, pid, detail
        ));
    }
    lines.join("\n")
}

fn format_single_unit(u: &UnitView) -> String {
    let mut out = format!(
        "Unit:    {}\nKind:    {}\nState:   {}\nEnabled: {}\n",
        u.name,
        u.kind,
        u.state,
        if u.enabled { "yes" } else { "no" }
    );
    if let Some(pid) = u.pid {
        out.push_str(&format!("PID:     {pid}\n"));
    }
    if u.attempts > 0 {
        out.push_str(&format!("Retries: {}\n", u.attempts));
    }
    if let Some(text) = &u.status_text {
        out.push_str(&format!("Status:  {text}\n"));
    }
    if let Some(err) = &u.last_error {
        out.push_str(&format!("Error:   {err}\n"));
    }
    out.trim_end_matches('\n').to_owned()
}

pub fn run_with(
    args: &[String],
    transport: &mut impl ServiceTransport,
) -> (Option<String>, Option<String>, i32) {
    let opts = match parse_args(args) {
        Ok(ServiceAction::Help(help)) => return (Some(help), None, 0),
        Ok(ServiceAction::Run(opts)) => opts,
        Err((msg, code)) => return (None, Some(msg), code),
    };

    let socket_path = match (opts.socket, opts.user_manager) {
        (Some(explicit), _) => explicit,
        (None, true) => match transport.current_uid() {
            Ok(uid) => format!("/run/user/{uid}/manager.sock"),
            Err(err) => return (None, Some(format!("service: {err}")), 1),
        },
        (None, false) => SYSTEM_CONTROL_SOCKET.to_owned(),
    };

    let mut frame = match serde_json::to_vec(&opts.command.to_request_json()) {
        Ok(v) => v,
        Err(err) => return (None, Some(format!("service: encode error: {err}")), 1),
    };
    frame.push(b'\n');

    let raw_reply = match transport.send_control(&socket_path, &frame) {
        Ok(bytes) => bytes,
        Err(err) => return (None, Some(format!("service: {err}")), 1),
    };
    let trimmed = raw_reply.strip_suffix(b"\n").unwrap_or(&raw_reply);
    let reply: Reply = match serde_json::from_slice(trimmed) {
        Ok(r) => r,
        Err(err) => {
            return (
                None,
                Some(format!("service: invalid manager reply: {err}")),
                1,
            );
        }
    };

    if opts.json {
        let code = i32::from(matches!(reply, Reply::Error { .. }));
        let pretty = serde_json::to_string_pretty(&reply).unwrap_or_default();
        return (Some(pretty), None, code);
    }

    match reply {
        Reply::Ok { message } => (message, None, 0),
        Reply::Units { units } => (Some(format_units_table(&units)), None, 0),
        Reply::Unit { unit } => (Some(format_single_unit(&unit)), None, 0),
        Reply::Error { errno, message } => (
            None,
            Some(format!("service: {message} ({})", errno.text())),
            1,
        ),
    }
}

pub fn run(args: &[String]) -> i32 {
    let mut transport = OsServiceTransport;
    let (out, err, code) = run_with(args, &mut transport);
    if let Some(msg) = out {
        println!("{msg}");
    }
    if let Some(msg) = err {
        eprintln!("{msg}");
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockTransport {
        uid: u32,
        last_socket: Option<String>,
        last_request: Option<Value>,
        reply: Reply,
    }

    impl ServiceTransport for MockTransport {
        fn current_uid(&mut self) -> Result<u32, abi::Error> {
            Ok(self.uid)
        }

        fn send_control(
            &mut self,
            socket_path: &str,
            request_frame: &[u8],
        ) -> Result<Vec<u8>, abi::Error> {
            self.last_socket = Some(socket_path.to_owned());
            self.last_request = Some(serde_json::from_slice(request_frame).unwrap());
            let mut out = serde_json::to_vec(&self.reply).unwrap();
            out.push(b'\n');
            Ok(out)
        }
    }

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|v| (*v).to_owned()).collect()
    }

    #[test]
    fn service_cli_targets_system_or_user_socket_and_formats_replies() {
        let mut mock = MockTransport {
            uid: 1000,
            last_socket: None,
            last_request: None,
            reply: Reply::Units {
                units: vec![UnitView {
                    name: "multi-user.target".into(),
                    kind: "target".into(),
                    state: "active".into(),
                    enabled: true,
                    pid: None,
                    attempts: 0,
                    status_text: None,
                    last_error: None,
                }],
            },
        };
        let (out, err, code) = run_with(&s(&["list"]), &mut mock);
        assert_eq!((err, code), (None, 0));
        assert_eq!(mock.last_socket.as_deref(), Some(SYSTEM_CONTROL_SOCKET));
        assert_eq!(mock.last_request, Some(json!({ "op": "list" })));
        assert!(out.unwrap().contains("multi-user.target"));

        mock.reply = Reply::Ok {
            message: Some("starting my.service".into()),
        };
        let (_, err, code) = run_with(&s(&["--user", "start", "my.service"]), &mut mock);
        assert_eq!((err, code), (None, 0));
        assert_eq!(
            mock.last_socket.as_deref(),
            Some("/run/user/1000/manager.sock")
        );
        assert_eq!(
            mock.last_request,
            Some(json!({ "op": "start", "unit": "my.service" }))
        );

        // Error response returns non-zero exit code.
        mock.reply = Reply::Error {
            errno: Errno::EPERM,
            message: "root required".into(),
        };
        let (_, err, code) = run_with(&s(&["poweroff"]), &mut mock);
        assert_eq!(code, 1);
        assert!(err.unwrap().contains("root required"));
    }

    #[test]
    fn service_cli_rejects_invalid_invocations() {
        let mut mock = MockTransport {
            uid: 0,
            last_socket: None,
            last_request: None,
            reply: Reply::Ok { message: None },
        };
        assert_eq!(run_with(&s(&[]), &mut mock).2, 2);
        assert_eq!(run_with(&s(&["start"]), &mut mock).2, 2);
        assert_eq!(run_with(&s(&["poweroff", "extra"]), &mut mock).2, 2);
        assert_eq!(run_with(&s(&["bogus"]), &mut mock).2, 2);
    }
}

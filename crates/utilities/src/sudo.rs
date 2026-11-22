//! Local `sudo` applet: `sudo [-k|-K|-v|-n|-l] [-u USER] [--] [COMMAND [ARG]...]` (`#57` `L3d`).
//!
//! Operates 100% locally against `/etc/sudoers` and `/etc/shadow` via `abi::Call::Sudo`.
//! Local `sudo` elevates only local OS authority (`uid 0`) and NEVER synthesizes remote cloud root.

use abi::{Call, Creds, Errno};
use std::io;

pub const USAGE: &str = "\
Usage: sudo [-n] [-u USER] [--] COMMAND [ARG]...
       sudo -k | -K | -v | -l

Run a command as local root (or USER) per /etc/sudoers.
  -k, -K             revoke the cached local sudo timestamp
  -v                 validate/refresh the cached sudo timestamp
  -n                 non-interactive; fail if a password is required
  -l                 display local sudo privileges for the current user
  -u USER            target local user (default: root)
  -h, --help         display this help and exit";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SudoAction {
    Help(String),
    Revoke,
    List,
    Validate {
        non_interactive: bool,
    },
    Exec {
        user: Option<String>,
        non_interactive: bool,
        command: Vec<String>,
    },
}

pub fn parse_args(args: &[String]) -> Result<SudoAction, (String, i32)> {
    let mut revoke = false;
    let mut validate = false;
    let mut list = false;
    let mut non_interactive = false;
    let mut user: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "-h" | "--help" => return Ok(SudoAction::Help(USAGE.to_owned())),
            "--" => {
                i += 1;
                break;
            }
            "-k" | "-K" | "--reset-timestamp" | "--remove-timestamp" => {
                revoke = true;
                i += 1;
            }
            "-v" | "--validate" => {
                validate = true;
                i += 1;
            }
            "-n" | "--non-interactive" => {
                non_interactive = true;
                i += 1;
            }
            "-l" | "--list" => {
                list = true;
                i += 1;
            }
            "-u" | "--user" => {
                let Some(val) = args.get(i + 1) else {
                    return Err(("sudo: option requires an argument -- 'u'".into(), 1));
                };
                user = Some(val.clone());
                i += 2;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                return Err((format!("sudo: unsupported option '{other}'"), 1));
            }
            _ => break,
        }
    }

    let command = args[i..].to_vec();
    if revoke {
        if !command.is_empty() || validate || list {
            return Err((
                "sudo: -k cannot be combined with a command or -v/-l".into(),
                1,
            ));
        }
        return Ok(SudoAction::Revoke);
    }
    if list {
        return Ok(SudoAction::List);
    }
    if validate {
        if !command.is_empty() {
            return Err(("sudo: -v cannot be combined with a command".into(), 1));
        }
        return Ok(SudoAction::Validate { non_interactive });
    }
    if command.is_empty() {
        return Err(("sudo: missing command (use sudo -h for usage)".into(), 1));
    }

    Ok(SudoAction::Exec {
        user,
        non_interactive,
        command,
    })
}

pub trait SudoBackend {
    fn getcreds(&mut self) -> Result<Creds, abi::Error>;
    fn prompt_password(&mut self, prompt: &str) -> Result<String, String>;
    fn sudo_call(&mut self, password: &str, revoke: bool) -> Result<(), abi::Error>;
    fn login_as(&mut self, user: &str) -> Result<(), abi::Error>;
    fn execvp(&mut self, prog: &str, argv: &[String]) -> Result<(), io::Error>;
}

struct OsSudoBackend;

impl SudoBackend for OsSudoBackend {
    fn getcreds(&mut self) -> Result<Creds, abi::Error> {
        let mut reply = os_posix::batch(&[Call::Getcreds])
            .map_err(|e| abi::Error::because(Errno::EIO, e.to_string()))?;
        let val = reply.results.remove(0).into_result()?;
        serde_json::from_value(val)
            .map_err(|e| abi::Error::because(Errno::EIO, format!("invalid creds reply: {e}")))
    }

    fn prompt_password(&mut self, prompt: &str) -> Result<String, String> {
        crate::prompt_password(prompt)
    }

    fn sudo_call(&mut self, password: &str, revoke: bool) -> Result<(), abi::Error> {
        let mut reply = os_posix::batch(&[Call::Sudo {
            password: password.to_owned(),
            revoke,
        }])
        .map_err(|e| abi::Error::because(Errno::EIO, e.to_string()))?;
        reply.results.remove(0).into_result().map(|_| ())
    }

    fn login_as(&mut self, user: &str) -> Result<(), abi::Error> {
        let mut reply = os_posix::batch(&[Call::Login {
            username: user.to_owned(),
            password: String::new(),
            force: true,
        }])
        .map_err(|e| abi::Error::because(Errno::EIO, e.to_string()))?;
        reply.results.remove(0).into_result().map(|_| ())
    }

    fn execvp(&mut self, prog: &str, argv: &[String]) -> Result<(), io::Error> {
        Err(os_posix::execvp(prog, argv))
    }
}

fn ensure_authenticated(
    backend: &mut impl SudoBackend,
    creds: &Creds,
    non_interactive: bool,
) -> Result<(), String> {
    if creds.uid == 0 {
        return Ok(());
    }
    if !creds.can_sudo {
        return Err(format!(
            "sudo: {} is not in the sudoers file (wheel)",
            creds.user
        ));
    }
    if creds.sudo_active {
        return backend
            .sudo_call("", false)
            .map_err(|e| format!("sudo: {e}"));
    }
    if non_interactive {
        return Err("sudo: a password is required".into());
    }
    let prompt = format!("[sudo] password for {}: ", creds.user);
    let pw = backend
        .prompt_password(&prompt)
        .map_err(|e| format!("sudo: {e}"))?;
    backend
        .sudo_call(&pw, false)
        .map_err(|e| format!("sudo: {e}"))
}

pub fn run_with(
    args: &[String],
    backend: &mut impl SudoBackend,
) -> (Option<String>, Option<String>, i32) {
    let action = match parse_args(args) {
        Ok(a) => a,
        Err((msg, code)) => return (None, Some(msg), code),
    };

    match action {
        SudoAction::Help(help) => (Some(help), None, 0),
        SudoAction::Revoke => match backend.sudo_call("", true) {
            Ok(()) => (None, None, 0),
            Err(err) => (None, Some(format!("sudo: {err}")), 1),
        },
        SudoAction::List => match backend.getcreds() {
            Ok(creds) if creds.uid == 0 || creds.can_sudo => {
                let mode = if creds.sudo_active {
                    "(ALL:ALL) NOPASSWD: ALL"
                } else {
                    "(ALL:ALL) ALL"
                };
                (
                    Some(format!(
                        "User {} may run the following local commands:\n    {mode}",
                        creds.user
                    )),
                    None,
                    0,
                )
            }
            Ok(creds) => (
                None,
                Some(format!("Sorry, user {} may not run sudo.", creds.user)),
                1,
            ),
            Err(err) => (None, Some(format!("sudo: {err}")), 1),
        },
        SudoAction::Validate { non_interactive } => {
            let creds = match backend.getcreds() {
                Ok(c) => c,
                Err(err) => return (None, Some(format!("sudo: {err}")), 1),
            };
            match ensure_authenticated(backend, &creds, non_interactive) {
                Ok(()) => (None, None, 0),
                Err(msg) => (None, Some(msg), 1),
            }
        }
        SudoAction::Exec {
            user,
            non_interactive,
            command,
        } => {
            let creds = match backend.getcreds() {
                Ok(c) => c,
                Err(err) => return (None, Some(format!("sudo: {err}")), 1),
            };
            if let Err(msg) = ensure_authenticated(backend, &creds, non_interactive) {
                return (None, Some(msg), 1);
            }
            if let Some(target_user) = user
                && let Err(err) = backend.login_as(&target_user)
            {
                return (None, Some(format!("sudo: {err}")), 1);
            }
            if command.is_empty() {
                return (None, None, 0);
            }
            match backend.execvp(&command[0], &command) {
                Ok(()) => (None, None, 0),
                Err(err) => {
                    let code = if os_posix::errno_of(&err) == Some(Errno::ENOENT)
                        || err.kind() == io::ErrorKind::NotFound
                    {
                        127
                    } else {
                        126
                    };
                    (None, Some(format!("sudo: {}: {err}", command[0])), code)
                }
            }
        }
    }
}

pub fn run(args: &[String]) -> i32 {
    let mut backend = OsSudoBackend;
    let (out, err, code) = run_with(args, &mut backend);
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

    struct MockSudo {
        creds: Creds,
        password: Option<String>,
        steps: Vec<String>,
    }

    impl SudoBackend for MockSudo {
        fn getcreds(&mut self) -> Result<Creds, abi::Error> {
            Ok(self.creds.clone())
        }

        fn prompt_password(&mut self, prompt: &str) -> Result<String, String> {
            self.steps.push(format!("prompt:{prompt}"));
            self.password.clone().ok_or_else(|| "eof".to_owned())
        }

        fn sudo_call(&mut self, password: &str, revoke: bool) -> Result<(), abi::Error> {
            self.steps.push(format!("sudo:{revoke}:{password}"));
            Ok(())
        }

        fn login_as(&mut self, user: &str) -> Result<(), abi::Error> {
            self.steps.push(format!("login:{user}"));
            Ok(())
        }

        fn execvp(&mut self, prog: &str, argv: &[String]) -> Result<(), io::Error> {
            self.steps.push(format!("exec:{prog}:{}", argv.join(" ")));
            Ok(())
        }
    }

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|v| (*v).to_owned()).collect()
    }

    #[test]
    fn sudo_nopasswd_exec_and_password_prompt_and_revoke() {
        let mut nopw = MockSudo {
            creds: Creds {
                uid: 1000,
                user: "user".into(),
                can_sudo: true,
                sudo_active: true,
                ..Creds::default()
            },
            password: None,
            steps: Vec::new(),
        };
        let (_, err, code) = run_with(&s(&["id", "-u"]), &mut nopw);
        assert_eq!((err, code), (None, 0));
        assert_eq!(nopw.steps, vec!["sudo:false:", "exec:id:id -u"]);

        // Non-interactive fails when password required.
        let mut need_pw = MockSudo {
            creds: Creds {
                uid: 1000,
                user: "user".into(),
                can_sudo: true,
                sudo_active: false,
                ..Creds::default()
            },
            password: Some("my-secret".into()),
            steps: Vec::new(),
        };
        assert_eq!(run_with(&s(&["-n", "id"]), &mut need_pw).2, 1);

        // Interactive prompts and executes.
        let (_, err, code) = run_with(&s(&["--", "ls", "-la"]), &mut need_pw);
        assert_eq!((err, code), (None, 0));
        assert_eq!(
            need_pw.steps,
            vec![
                "prompt:[sudo] password for user: ",
                "sudo:false:my-secret",
                "exec:ls:ls -la",
            ]
        );

        // Revoke (`sudo -k`).
        need_pw.steps.clear();
        assert_eq!(run_with(&s(&["-k"]), &mut need_pw).2, 0);
        assert_eq!(need_pw.steps, vec!["sudo:true:"]);
    }

    #[test]
    fn sudo_denies_non_wheel_user() {
        let mut denied = MockSudo {
            creds: Creds {
                uid: 1001,
                user: "guestuser".into(),
                can_sudo: false,
                sudo_active: false,
                ..Creds::default()
            },
            password: None,
            steps: Vec::new(),
        };
        let (_, err, code) = run_with(&s(&["id"]), &mut denied);
        assert_eq!(code, 1);
        assert!(err.unwrap().contains("not in the sudoers"));

        // `sudo -u USER` without a command is rejected before invoking any backend operation.
        let mut no_cmd = MockSudo {
            creds: Creds {
                uid: 1000,
                user: "user".into(),
                can_sudo: true,
                sudo_active: true,
                ..Creds::default()
            },
            password: None,
            steps: Vec::new(),
        };
        let (_, err, code) = run_with(&s(&["-u", "alice"]), &mut no_cmd);
        assert_eq!(code, 1);
        assert!(err.unwrap().contains("missing command"));
        assert!(no_cmd.steps.is_empty());
    }

    #[test]
    fn sudo_target_user_switches_only_after_authentication() {
        let mut wheel = MockSudo {
            creds: Creds {
                uid: 1000,
                user: "user".into(),
                can_sudo: true,
                sudo_active: true,
                ..Creds::default()
            },
            password: None,
            steps: Vec::new(),
        };
        let (_, err, code) = run_with(&s(&["-u", "alice", "id"]), &mut wheel);
        assert_eq!((err, code), (None, 0));
        assert_eq!(
            wheel.steps,
            vec!["sudo:false:", "login:alice", "exec:id:id"]
        );

        let mut root = MockSudo {
            creds: Creds {
                uid: 0,
                user: "root".into(),
                ..Creds::default()
            },
            password: None,
            steps: Vec::new(),
        };
        let (_, err, code) = run_with(&s(&["-u", "alice", "whoami"]), &mut root);
        assert_eq!((err, code), (None, 0));
        assert_eq!(root.steps, vec!["login:alice", "exec:whoami:whoami"]);

        // Failed auth must NEVER call `login_as`.
        let mut denied = MockSudo {
            creds: Creds {
                uid: 1001,
                user: "bob".into(),
                can_sudo: false,
                sudo_active: false,
                ..Creds::default()
            },
            password: None,
            steps: Vec::new(),
        };
        assert_eq!(run_with(&s(&["-u", "alice", "id"]), &mut denied).2, 1);
        assert!(denied.steps.is_empty());
    }
}

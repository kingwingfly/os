//! Local `login` applet: `login [-f] [-p] [USER]` (`#57` `L3d`).
//!
//! Authenticates strictly against local `/etc/passwd` + `/etc/shadow` via `abi::Call::Login`
//! with zero network RPCs, then chdirs into the user's home and execs their login shell.

use crate::{LocalPasswdRecord, parse_passwd_line};
use abi::{Call, Creds, Errno};
use std::io::{self, Write};
use std::path::Path;

pub const USAGE: &str = "\
Usage: login [-f] [-p] [USER]

Begin a local OS session as USER on this terminal.
  -f                 skip password prompt when already running as root
  -p                 preserve environment
  -h, --help         display this help and exit";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoginAction {
    Help(String),
    Run(LoginOptions),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoginOptions {
    pub user: Option<String>,
    pub force_no_auth: bool,
    pub preserve_env: bool,
}

pub fn parse_args(args: &[String]) -> Result<LoginAction, (String, i32)> {
    let mut force_no_auth = false;
    let mut preserve_env = false;
    let mut user: Option<String> = None;

    for arg in args {
        match arg.as_str() {
            "-h" | "--help" => return Ok(LoginAction::Help(USAGE.to_owned())),
            "-f" => force_no_auth = true,
            "-p" => preserve_env = true,
            other if other.starts_with('-') => {
                return Err((format!("login: unsupported option '{other}'"), 2));
            }
            operand => {
                if user.is_some() {
                    return Err((format!("login: unexpected extra operand '{operand}'"), 2));
                }
                user = Some(operand.to_owned());
            }
        }
    }

    Ok(LoginAction::Run(LoginOptions {
        user,
        force_no_auth,
        preserve_env,
    }))
}

pub trait LoginBackend {
    fn getcreds(&mut self) -> Result<Creds, abi::Error>;
    fn read_passwd(&mut self) -> Result<String, abi::Error>;
    fn prompt(&mut self, prompt: &str) -> Result<String, String>;
    fn login(&mut self, username: &str, password: &str) -> Result<(), abi::Error>;
    fn chdir(&mut self, path: &str) -> io::Result<()>;
    fn execvp(&mut self, prog: &str, argv: &[String]) -> Result<(), io::Error>;
}

struct OsLoginBackend;

impl LoginBackend for OsLoginBackend {
    fn getcreds(&mut self) -> Result<Creds, abi::Error> {
        let mut reply = os_posix::batch(&[Call::Getcreds])
            .map_err(|e| abi::Error::because(Errno::EIO, e.to_string()))?;
        let val = reply.results.remove(0).into_result()?;
        serde_json::from_value(val)
            .map_err(|e| abi::Error::because(Errno::EIO, format!("invalid creds reply: {e}")))
    }

    fn read_passwd(&mut self) -> Result<String, abi::Error> {
        std::fs::read_to_string("/etc/passwd")
            .map_err(|e| abi::Error::because(Errno::EIO, e.to_string()))
    }

    fn prompt(&mut self, prompt: &str) -> Result<String, String> {
        eprint!("{prompt}");
        let _ = io::stderr().flush();
        let mut line = String::new();
        let n = io::stdin()
            .read_line(&mut line)
            .map_err(|e| format!("read failed: {e}"))?;
        if n == 0 {
            return Err("aborted (EOF)".into());
        }
        while line.ends_with('\n') || line.ends_with('\r') {
            line.pop();
        }
        Ok(line)
    }

    fn login(&mut self, username: &str, password: &str) -> Result<(), abi::Error> {
        let mut reply = os_posix::batch(&[Call::Login {
            username: username.to_owned(),
            password: password.to_owned(),
        }])
        .map_err(|e| abi::Error::because(Errno::EIO, e.to_string()))?;
        reply.results.remove(0).into_result().map(|_| ())
    }

    fn chdir(&mut self, path: &str) -> io::Result<()> {
        os_posix::chdir(Path::new(path))
    }

    fn execvp(&mut self, prog: &str, argv: &[String]) -> Result<(), io::Error> {
        Err(os_posix::execvp(prog, argv))
    }
}

fn find_user(passwd: &str, name: &str) -> Option<LocalPasswdRecord> {
    passwd
        .lines()
        .filter_map(parse_passwd_line)
        .find(|u| u.name == name)
}

pub fn run_with(
    args: &[String],
    backend: &mut impl LoginBackend,
) -> (Option<String>, Option<String>, i32) {
    let opts = match parse_args(args) {
        Ok(LoginAction::Help(help)) => return (Some(help), None, 0),
        Ok(LoginAction::Run(opts)) => opts,
        Err((msg, code)) => return (None, Some(msg), code),
    };

    let creds = match backend.getcreds() {
        Ok(c) => c,
        Err(err) => return (None, Some(format!("login: {err}")), 1),
    };

    if opts.force_no_auth && creds.uid != 0 {
        return (
            None,
            Some("login: -f is only permitted when running as root".into()),
            1,
        );
    }

    let username = match opts.user {
        Some(u) if !u.is_empty() => u,
        _ => match backend.prompt("login: ") {
            Ok(u) if !u.trim().is_empty() => u.trim().to_owned(),
            Ok(_) => return (None, Some("login: empty username".into()), 1),
            Err(err) => return (None, Some(format!("login: {err}")), 1),
        },
    };

    let password = if opts.force_no_auth && creds.uid == 0 {
        String::new()
    } else {
        match backend.prompt("Password: ") {
            Ok(pw) => pw,
            Err(err) => return (None, Some(format!("login: {err}")), 1),
        }
    };

    if let Err(err) = backend.login(&username, &password) {
        return (None, Some(format!("login: {err}")), 1);
    }

    let passwd = backend.read_passwd().unwrap_or_default();
    let (home, shell) = find_user(&passwd, &username)
        .map(|u| (u.home, u.shell))
        .unwrap_or_else(|| ("/".into(), "/bin/sh".into()));

    let _ = backend.chdir(&home);
    let shell = if shell.is_empty() {
        "/bin/sh".to_owned()
    } else {
        shell
    };
    let argv = vec![shell.clone(), "-l".to_owned()];
    match backend.execvp(&shell, &argv) {
        Ok(()) => (None, None, 0),
        Err(err) => (
            None,
            Some(format!("login: failed to execute '{shell}': {err}")),
            126,
        ),
    }
}

pub fn run(args: &[String]) -> i32 {
    let mut backend = OsLoginBackend;
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
    use std::collections::VecDeque;

    struct MockLogin {
        uid: u32,
        passwd: String,
        answers: VecDeque<String>,
        steps: Vec<String>,
    }

    impl LoginBackend for MockLogin {
        fn getcreds(&mut self) -> Result<Creds, abi::Error> {
            Ok(Creds {
                uid: self.uid,
                ..Creds::default()
            })
        }

        fn read_passwd(&mut self) -> Result<String, abi::Error> {
            Ok(self.passwd.clone())
        }

        fn prompt(&mut self, prompt: &str) -> Result<String, String> {
            self.steps.push(format!("prompt:{prompt}"));
            self.answers.pop_front().ok_or_else(|| "eof".to_owned())
        }

        fn login(&mut self, username: &str, password: &str) -> Result<(), abi::Error> {
            self.steps.push(format!("login:{username}:{password}"));
            Ok(())
        }

        fn chdir(&mut self, path: &str) -> io::Result<()> {
            self.steps.push(format!("chdir:{path}"));
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
    fn login_authenticates_prompts_and_refuses_non_root_force() {
        let mut non_root = MockLogin {
            uid: 1000,
            passwd: "user:x:1000:1000:Local User:/home/user:/bin/sh\n".into(),
            answers: VecDeque::from(["user".into(), "pw".into()]),
            steps: Vec::new(),
        };
        assert_eq!(run_with(&s(&["-f", "root"]), &mut non_root).2, 1);

        let (_, err, code) = run_with(&s(&[]), &mut non_root);
        assert_eq!((err, code), (None, 0));
        assert_eq!(
            non_root.steps,
            vec![
                "prompt:login: ",
                "prompt:Password: ",
                "login:user:pw",
                "chdir:/home/user",
                "exec:/bin/sh:/bin/sh -l",
            ]
        );
    }
}

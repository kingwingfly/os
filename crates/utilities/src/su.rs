//! Local `su` applet: `su [- | -l | --login] [-c COMMAND] [-s SHELL] [USER]` (`#57` `L3d`).
//!
//! Authenticates 100% locally against `/etc/passwd` + `/etc/shadow` via `abi::Call::Login`.
//! Privilege drops from `root` to a non-root user clear inherited ambient cloud credentials
//! in the kernel (`Contract v2 §2.4`).

use crate::{LocalPasswdRecord, parse_passwd_line};
use abi::{Call, Creds, Errno};
use std::io;
use std::path::Path;

pub const USAGE: &str = "\
Usage: su [- | -l | --login] [-c COMMAND] [-s SHELL] [USER]

Switch to local OS account USER (default: root).
  -, -l, --login     start a login shell and enter USER's home directory
  -c, --command CMD  pass a single command to the shell with -c
  -s, --shell SHELL  run SHELL instead of the user's /etc/passwd shell
  -h, --help         display this help and exit";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SuAction {
    Help(String),
    Switch(SuOptions),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuOptions {
    pub user: String,
    pub login: bool,
    pub command: Option<String>,
    pub shell: Option<String>,
}

pub fn parse_args(args: &[String]) -> Result<SuAction, (String, i32)> {
    let mut login = false;
    let mut command: Option<String> = None;
    let mut shell: Option<String> = None;
    let mut user: Option<String> = None;
    let mut i = 0;
    let mut positional_only = false;

    while i < args.len() {
        let arg = &args[i];
        if !positional_only {
            match arg.as_str() {
                "-h" | "--help" => return Ok(SuAction::Help(USAGE.to_owned())),
                "--" => {
                    positional_only = true;
                    i += 1;
                    continue;
                }
                "-" | "-l" | "--login" => {
                    login = true;
                    i += 1;
                    continue;
                }
                "-c" | "--command" => {
                    let Some(val) = args.get(i + 1) else {
                        return Err(("su: option requires an argument -- 'c'".into(), 2));
                    };
                    command = Some(val.clone());
                    i += 2;
                    continue;
                }
                "-s" | "--shell" => {
                    let Some(val) = args.get(i + 1) else {
                        return Err(("su: option requires an argument -- 's'".into(), 2));
                    };
                    shell = Some(val.clone());
                    i += 2;
                    continue;
                }
                other if other.starts_with('-') && other.len() > 1 => {
                    return Err((format!("su: unsupported option '{other}'"), 2));
                }
                _ => {}
            }
        }
        if user.is_none() {
            user = Some(arg.clone());
            i += 1;
        } else {
            return Err((format!("su: unexpected extra operand '{arg}'"), 2));
        }
    }

    Ok(SuAction::Switch(SuOptions {
        user: user.unwrap_or_else(|| "root".to_owned()),
        login,
        command,
        shell,
    }))
}

pub trait SuBackend {
    fn getcreds(&mut self) -> Result<Creds, abi::Error>;
    fn read_passwd(&mut self) -> Result<String, abi::Error>;
    fn prompt_password(&mut self, prompt: &str) -> Result<String, String>;
    fn login(&mut self, username: &str, password: &str, force: bool) -> Result<(), abi::Error>;
    fn chdir(&mut self, path: &str) -> io::Result<()>;
    fn execvp(&mut self, prog: &str, argv: &[String]) -> Result<(), io::Error>;
}

struct OsSuBackend;

impl SuBackend for OsSuBackend {
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

    fn prompt_password(&mut self, prompt: &str) -> Result<String, String> {
        crate::prompt_password(prompt)
    }

    fn login(&mut self, username: &str, password: &str, force: bool) -> Result<(), abi::Error> {
        let mut reply = os_posix::batch(&[Call::Login {
            username: username.to_owned(),
            password: password.to_owned(),
            force,
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

fn find_passwd_user(passwd: &str, name: &str) -> Option<LocalPasswdRecord> {
    passwd
        .lines()
        .filter_map(parse_passwd_line)
        .find(|u| u.name == name)
}

pub fn run_with(
    args: &[String],
    backend: &mut impl SuBackend,
) -> (Option<String>, Option<String>, i32) {
    let opts = match parse_args(args) {
        Ok(SuAction::Help(help)) => return (Some(help), None, 0),
        Ok(SuAction::Switch(opts)) => opts,
        Err((msg, code)) => return (None, Some(msg), code),
    };

    let creds = match backend.getcreds() {
        Ok(c) => c,
        Err(err) => return (None, Some(format!("su: {err}")), 1),
    };

    let passwd_text = match backend.read_passwd() {
        Ok(text) => text,
        Err(err) => return (None, Some(format!("su: cannot read /etc/passwd: {err}")), 1),
    };

    let Some(target) = find_passwd_user(&passwd_text, &opts.user) else {
        return (
            None,
            Some(format!("su: user '{}' does not exist", opts.user)),
            1,
        );
    };

    let force = creds.uid == 0;
    let password = if force {
        String::new()
    } else {
        match backend.prompt_password("Password: ") {
            Ok(pw) => pw,
            Err(err) => return (None, Some(format!("su: {err}")), 1),
        }
    };

    if let Err(err) = backend.login(&target.name, &password, force) {
        return (None, Some(format!("su: {err}")), 1);
    }

    if opts.login
        && let Err(err) = backend.chdir(&target.home)
    {
        return (
            None,
            Some(format!(
                "su: warning: cannot change directory to '{}': {err}",
                target.home
            )),
            1,
        );
    }

    let shell = opts
        .shell
        .filter(|s| !s.is_empty())
        .or_else(|| (!target.shell.is_empty()).then_some(target.shell))
        .unwrap_or_else(|| "/bin/sh".to_owned());

    let mut argv = vec![shell.clone()];
    if opts.login && opts.command.is_none() {
        argv.push("-l".into());
    }
    if let Some(cmd) = opts.command {
        argv.push("-c".into());
        argv.push(cmd);
    }

    match backend.execvp(&shell, &argv) {
        Ok(()) => (None, None, 0),
        Err(err) => {
            let code = if os_posix::errno_of(&err) == Some(Errno::ENOENT)
                || err.kind() == io::ErrorKind::NotFound
            {
                127
            } else {
                126
            };
            (
                None,
                Some(format!("su: failed to execute '{shell}': {err}")),
                code,
            )
        }
    }
}

pub fn run(args: &[String]) -> i32 {
    let mut backend = OsSuBackend;
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

    struct MockSu {
        uid: u32,
        passwd: String,
        prompted_password: Option<String>,
        login_err: Option<Errno>,
        steps: Vec<String>,
    }

    impl SuBackend for MockSu {
        fn getcreds(&mut self) -> Result<Creds, abi::Error> {
            Ok(Creds {
                uid: self.uid,
                user: if self.uid == 0 {
                    "root".into()
                } else {
                    "user".into()
                },
                ..Creds::default()
            })
        }

        fn read_passwd(&mut self) -> Result<String, abi::Error> {
            Ok(self.passwd.clone())
        }

        fn prompt_password(&mut self, prompt: &str) -> Result<String, String> {
            self.steps.push(format!("prompt:{prompt}"));
            self.prompted_password
                .clone()
                .ok_or_else(|| "eof".to_owned())
        }

        fn login(&mut self, username: &str, password: &str, force: bool) -> Result<(), abi::Error> {
            self.steps
                .push(format!("login:{username}:{password}:force={force}"));
            if let Some(errno) = self.login_err {
                return Err(errno.into());
            }
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
    fn su_root_switches_without_prompt_and_non_root_prompts() {
        let passwd =
            "root:x:0:0:root:/root:/bin/sh\nalice:x:1001:1001:Alice:/home/alice:/bin/dash\n"
                .to_owned();

        let mut root_mock = MockSu {
            uid: 0,
            passwd: passwd.clone(),
            prompted_password: None,
            login_err: None,
            steps: Vec::new(),
        };
        let (_, err, code) = run_with(&s(&["-", "alice"]), &mut root_mock);
        assert_eq!((err, code), (None, 0));
        assert_eq!(
            root_mock.steps,
            vec![
                "login:alice::force=true",
                "chdir:/home/alice",
                "exec:/bin/dash:/bin/dash -l",
            ]
        );

        let mut user_mock = MockSu {
            uid: 1000,
            passwd,
            prompted_password: Some("secret123".into()),
            login_err: None,
            steps: Vec::new(),
        };
        let (_, err, code) = run_with(&s(&["-c", "id", "alice"]), &mut user_mock);
        assert_eq!((err, code), (None, 0));
        assert_eq!(
            user_mock.steps,
            vec![
                "prompt:Password: ",
                "login:alice:secret123:force=false",
                "exec:/bin/dash:/bin/dash -c id",
            ]
        );
    }

    #[test]
    fn su_rejects_unknown_user_and_bad_flags() {
        let mut mock = MockSu {
            uid: 0,
            passwd: "root:x:0:0:root:/root:/bin/sh\n".into(),
            prompted_password: None,
            login_err: None,
            steps: Vec::new(),
        };
        assert_eq!(run_with(&s(&["ghost"]), &mut mock).2, 1);
        assert_eq!(run_with(&s(&["--bogus"]), &mut mock).2, 2);
        assert_eq!(run_with(&s(&["-c"]), &mut mock).2, 2);
    }
}

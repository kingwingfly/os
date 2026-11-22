//! Local `passwd` applet: `passwd [-l|-u|-S|--force] [USER]` (`#57` `L3d`).
//!
//! Updates local `/etc/shadow` PBKDF2-HMAC-SHA256 hashes via `abi::Call::Passwd` / `Usermod`.

use abi::{Call, Creds, Errno};

pub const USAGE: &str = "\
Usage: passwd [-l | -u | -S] [--force] [USER]

Update a local account's password in /etc/shadow.
  -l, --lock         lock the named account (root only)
  -u, --unlock       unlock the named account (root only)
  -S, --status       report local account lock status
      --force        allow a password shorter than 12 characters
  -h, --help         display this help and exit";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PasswdAction {
    Help(String),
    Lock(String),
    Unlock(String),
    Status(Option<String>),
    Change { user: Option<String>, force: bool },
}

pub fn parse_args(args: &[String]) -> Result<PasswdAction, (String, i32)> {
    let mut lock = false;
    let mut unlock = false;
    let mut status = false;
    let mut force = false;
    let mut user: Option<String> = None;

    for arg in args {
        match arg.as_str() {
            "-h" | "--help" => return Ok(PasswdAction::Help(USAGE.to_owned())),
            "-l" | "--lock" => lock = true,
            "-u" | "--unlock" => unlock = true,
            "-S" | "--status" => status = true,
            "--force" => force = true,
            other if other.starts_with('-') => {
                return Err((format!("passwd: unsupported option '{other}'"), 2));
            }
            operand => {
                if user.is_some() {
                    return Err((format!("passwd: unexpected extra operand '{operand}'"), 2));
                }
                user = Some(operand.to_owned());
            }
        }
    }

    let mode_count = usize::from(lock) + usize::from(unlock) + usize::from(status);
    if mode_count > 1 {
        return Err(("passwd: -l, -u, and -S are mutually exclusive".into(), 2));
    }

    if lock {
        let Some(target) = user else {
            return Err(("passwd: --lock requires a USER operand".into(), 2));
        };
        return Ok(PasswdAction::Lock(target));
    }
    if unlock {
        let Some(target) = user else {
            return Err(("passwd: --unlock requires a USER operand".into(), 2));
        };
        return Ok(PasswdAction::Unlock(target));
    }
    if status {
        return Ok(PasswdAction::Status(user));
    }
    Ok(PasswdAction::Change { user, force })
}

pub trait PasswdBackend {
    fn getcreds(&mut self) -> Result<Creds, abi::Error>;
    fn prompt(&mut self, prompt: &str) -> Result<String, String>;
    fn set_password(
        &mut self,
        username: Option<String>,
        current_password: Option<String>,
        new_password: String,
        force: bool,
    ) -> Result<(), abi::Error>;
    fn set_lock(&mut self, username: &str, lock: bool) -> Result<(), abi::Error>;
}

struct OsPasswdBackend;

impl PasswdBackend for OsPasswdBackend {
    fn getcreds(&mut self) -> Result<Creds, abi::Error> {
        let mut reply = os_posix::batch(&[Call::Getcreds])
            .map_err(|e| abi::Error::because(Errno::EIO, e.to_string()))?;
        let val = reply.results.remove(0).into_result()?;
        serde_json::from_value(val)
            .map_err(|e| abi::Error::because(Errno::EIO, format!("invalid creds reply: {e}")))
    }

    fn prompt(&mut self, prompt: &str) -> Result<String, String> {
        crate::prompt_password(prompt)
    }

    fn set_password(
        &mut self,
        username: Option<String>,
        current_password: Option<String>,
        new_password: String,
        force: bool,
    ) -> Result<(), abi::Error> {
        let mut reply = os_posix::batch(&[Call::Passwd {
            username,
            password: new_password,
            current_password,
            force,
        }])
        .map_err(|e| abi::Error::because(Errno::EIO, e.to_string()))?;
        reply.results.remove(0).into_result().map(|_| ())
    }

    fn set_lock(&mut self, username: &str, lock: bool) -> Result<(), abi::Error> {
        let mut reply = os_posix::batch(&[Call::Usermod {
            name: username.to_owned(),
            append: false,
            groups: None,
            group: None,
            home: None,
            move_home: false,
            rename: None,
            lock,
            unlock: !lock,
        }])
        .map_err(|e| abi::Error::because(Errno::EIO, e.to_string()))?;
        reply.results.remove(0).into_result().map(|_| ())
    }
}

pub fn run_with(
    args: &[String],
    backend: &mut impl PasswdBackend,
) -> (Option<String>, Option<String>, i32) {
    let action = match parse_args(args) {
        Ok(a) => a,
        Err((msg, code)) => return (None, Some(msg), code),
    };

    match action {
        PasswdAction::Help(help) => (Some(help), None, 0),
        PasswdAction::Lock(target) => match backend.set_lock(&target, true) {
            Ok(()) => (Some(format!("passwd: locked '{target}'")), None, 0),
            Err(err) => (None, Some(format!("passwd: {err}")), 1),
        },
        PasswdAction::Unlock(target) => match backend.set_lock(&target, false) {
            Ok(()) => (Some(format!("passwd: unlocked '{target}'")), None, 0),
            Err(err) => (None, Some(format!("passwd: {err}")), 1),
        },
        PasswdAction::Status(target) => match backend.getcreds() {
            Ok(creds) => {
                let name = target.unwrap_or(creds.user);
                (Some(format!("{name} (local /etc/shadow)")), None, 0)
            }
            Err(err) => (None, Some(format!("passwd: {err}")), 1),
        },
        PasswdAction::Change { user, force } => {
            let creds = match backend.getcreds() {
                Ok(c) => c,
                Err(err) => return (None, Some(format!("passwd: {err}")), 1),
            };
            let target_is_other = user.as_deref().is_some_and(|u| u != creds.user);
            if target_is_other && creds.uid != 0 {
                return (
                    None,
                    Some("passwd: only root may change another user's password".into()),
                    1,
                );
            }
            let current = if creds.uid == 0 {
                None
            } else {
                match backend.prompt("Current password: ") {
                    Ok(pw) => Some(pw),
                    Err(err) => return (None, Some(format!("passwd: {err}")), 1),
                }
            };
            let new_pw = match backend.prompt("New password: ") {
                Ok(pw) if !pw.is_empty() => pw,
                Ok(_) => return (None, Some("passwd: password cannot be empty".into()), 1),
                Err(err) => return (None, Some(format!("passwd: {err}")), 1),
            };
            let confirm = match backend.prompt("Retype new password: ") {
                Ok(pw) => pw,
                Err(err) => return (None, Some(format!("passwd: {err}")), 1),
            };
            if new_pw != confirm {
                return (
                    None,
                    Some("passwd: passwords do not match; unchanged".into()),
                    1,
                );
            }
            match backend.set_password(user, current, new_pw, force) {
                Ok(()) => (
                    Some("passwd: password updated successfully".into()),
                    None,
                    0,
                ),
                Err(err) => (None, Some(format!("passwd: {err}")), 1),
            }
        }
    }
}

pub fn run(args: &[String]) -> i32 {
    let mut backend = OsPasswdBackend;
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

    struct MockPasswd {
        uid: u32,
        user: String,
        answers: VecDeque<String>,
        calls: Vec<String>,
    }

    impl PasswdBackend for MockPasswd {
        fn getcreds(&mut self) -> Result<Creds, abi::Error> {
            Ok(Creds {
                uid: self.uid,
                user: self.user.clone(),
                ..Creds::default()
            })
        }

        fn prompt(&mut self, prompt: &str) -> Result<String, String> {
            self.calls.push(format!("prompt:{prompt}"));
            self.answers.pop_front().ok_or_else(|| "eof".to_owned())
        }

        fn set_password(
            &mut self,
            username: Option<String>,
            current_password: Option<String>,
            new_password: String,
            force: bool,
        ) -> Result<(), abi::Error> {
            self.calls.push(format!(
                "passwd:{username:?}:{current_password:?}:{new_password}:{force}"
            ));
            Ok(())
        }

        fn set_lock(&mut self, username: &str, lock: bool) -> Result<(), abi::Error> {
            self.calls.push(format!("lock:{username}:{lock}"));
            Ok(())
        }
    }

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|v| (*v).to_owned()).collect()
    }

    #[test]
    fn passwd_confirms_matching_passwords_and_checks_permissions() {
        let mut user_mock = MockPasswd {
            uid: 1000,
            user: "user".into(),
            answers: VecDeque::from([
                "old-pass-1234".into(),
                "new-strong-password".into(),
                "mismatch".into(),
            ]),
            calls: Vec::new(),
        };
        let (_, err, code) = run_with(&s(&[]), &mut user_mock);
        assert_eq!(code, 1);
        assert!(err.unwrap().contains("do not match"));

        // Non-root cannot change another account.
        assert_eq!(run_with(&s(&["alice"]), &mut user_mock).2, 1);

        // Root resets alice without current password prompt.
        let mut root_mock = MockPasswd {
            uid: 0,
            user: "root".into(),
            answers: VecDeque::from(["short".into(), "short".into()]),
            calls: Vec::new(),
        };
        let (out, err, code) = run_with(&s(&["--force", "alice"]), &mut root_mock);
        assert_eq!((err, code), (None, 0));
        assert!(out.unwrap().contains("updated"));
        assert_eq!(
            root_mock.calls,
            vec![
                "prompt:New password: ",
                "prompt:Retype new password: ",
                "passwd:Some(\"alice\"):None:short:true",
            ]
        );
    }
}

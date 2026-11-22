//! Local `newgrp` applet: `newgrp [-] [GROUP]` (`#57` `L3d`).
//!
//! Switches the process's primary group to `GROUP` (or back to the user's `/etc/passwd` login
//! group when omitted) after verifying membership in local `/etc/group` (root may enter any group).

use crate::{LocalGroupRecord, parse_group_line, parse_passwd_line};
use abi::{Call, Creds, Errno};
use std::io;

pub const USAGE: &str = "\
Usage: newgrp [-] [GROUP]

Start a shell with primary group set to local GROUP (default: user's login group).
  -                  reinitialize as a login shell
  -h, --help         display this help and exit";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NewgrpAction {
    Help(String),
    Switch { login: bool, group: Option<String> },
}

pub fn parse_args(args: &[String]) -> Result<NewgrpAction, (String, i32)> {
    let mut login = false;
    let mut group: Option<String> = None;

    for arg in args {
        match arg.as_str() {
            "-h" | "--help" => return Ok(NewgrpAction::Help(USAGE.to_owned())),
            "-" | "-l" => login = true,
            other if other.starts_with('-') => {
                return Err((format!("newgrp: unsupported option '{other}'"), 2));
            }
            operand => {
                if group.is_some() {
                    return Err((format!("newgrp: unexpected extra operand '{operand}'"), 2));
                }
                group = Some(operand.to_owned());
            }
        }
    }

    Ok(NewgrpAction::Switch { login, group })
}

pub trait NewgrpBackend {
    fn getcreds(&mut self) -> Result<Creds, abi::Error>;
    fn read_passwd(&mut self) -> Result<String, abi::Error>;
    fn read_group(&mut self) -> Result<String, abi::Error>;
    fn set_primary_gid(&mut self, gid: u32) -> Result<(), abi::Error>;
    fn execvp(&mut self, prog: &str, argv: &[String]) -> Result<(), io::Error>;
}

struct OsNewgrpBackend;

impl NewgrpBackend for OsNewgrpBackend {
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

    fn read_group(&mut self) -> Result<String, abi::Error> {
        std::fs::read_to_string("/etc/group")
            .map_err(|e| abi::Error::because(Errno::EIO, e.to_string()))
    }

    fn set_primary_gid(&mut self, gid: u32) -> Result<(), abi::Error> {
        let mut reply = os_posix::batch(&[Call::Prctl {
            option: 1001,
            value: gid,
        }])
        .map_err(|e| abi::Error::because(Errno::EIO, e.to_string()))?;
        reply.results.remove(0).into_result().map(|_| ())
    }

    fn execvp(&mut self, prog: &str, argv: &[String]) -> Result<(), io::Error> {
        Err(os_posix::execvp(prog, argv))
    }
}

fn find_group(group_text: &str, name: &str) -> Option<LocalGroupRecord> {
    group_text
        .lines()
        .filter_map(parse_group_line)
        .find(|g| g.name == name)
}

pub fn run_with(
    args: &[String],
    backend: &mut impl NewgrpBackend,
) -> (Option<String>, Option<String>, i32) {
    let (login, requested_group) = match parse_args(args) {
        Ok(NewgrpAction::Help(help)) => return (Some(help), None, 0),
        Ok(NewgrpAction::Switch { login, group }) => (login, group),
        Err((msg, code)) => return (None, Some(msg), code),
    };

    let creds = match backend.getcreds() {
        Ok(c) => c,
        Err(err) => return (None, Some(format!("newgrp: {err}")), 1),
    };
    let passwd_text = match backend.read_passwd() {
        Ok(t) => t,
        Err(err) => return (None, Some(format!("newgrp: {err}")), 1),
    };
    let group_text = match backend.read_group() {
        Ok(t) => t,
        Err(err) => return (None, Some(format!("newgrp: {err}")), 1),
    };

    let user_record = passwd_text
        .lines()
        .filter_map(parse_passwd_line)
        .find(|u| u.uid == creds.uid);

    let target_gid = if let Some(group_name) = requested_group {
        let Some(group) = find_group(&group_text, &group_name) else {
            return (
                None,
                Some(format!("newgrp: group '{group_name}' does not exist")),
                1,
            );
        };
        let is_member = creds.uid == 0
            || creds.gid == group.gid
            || creds.groups.contains(&group.gid)
            || user_record
                .as_ref()
                .is_some_and(|u| u.gid == group.gid || group.members.contains(&u.name))
            || group.members.contains(&creds.user);
        if !is_member {
            return (
                None,
                Some(format!(
                    "newgrp: permission denied for group '{group_name}'"
                )),
                1,
            );
        }
        group.gid
    } else {
        user_record.as_ref().map_or(creds.gid, |u| u.gid)
    };

    if let Err(err) = backend.set_primary_gid(target_gid) {
        return (None, Some(format!("newgrp: {err}")), 1);
    }

    let shell = user_record
        .map(|u| u.shell)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/bin/sh".to_owned());
    let mut argv = vec![shell.clone()];
    if login {
        argv.push("-l".into());
    }
    match backend.execvp(&shell, &argv) {
        Ok(()) => (None, None, 0),
        Err(err) => (
            None,
            Some(format!("newgrp: failed to execute '{shell}': {err}")),
            126,
        ),
    }
}

pub fn run(args: &[String]) -> i32 {
    let mut backend = OsNewgrpBackend;
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

    struct MockNewgrp {
        creds: Creds,
        passwd: String,
        group: String,
        steps: Vec<String>,
    }

    impl NewgrpBackend for MockNewgrp {
        fn getcreds(&mut self) -> Result<Creds, abi::Error> {
            Ok(self.creds.clone())
        }

        fn read_passwd(&mut self) -> Result<String, abi::Error> {
            Ok(self.passwd.clone())
        }

        fn read_group(&mut self) -> Result<String, abi::Error> {
            Ok(self.group.clone())
        }

        fn set_primary_gid(&mut self, gid: u32) -> Result<(), abi::Error> {
            self.steps.push(format!("setgid:{gid}"));
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
    fn newgrp_enforces_local_group_membership_and_defaults_to_login_gid() {
        let mut mock = MockNewgrp {
            creds: Creds {
                uid: 1000,
                gid: 1000,
                groups: vec![1000, 10],
                user: "user".into(),
                ..Creds::default()
            },
            passwd: "user:x:1000:1000:Local User:/home/user:/bin/sh\n".into(),
            group: "root:x:0:\nwheel:x:10:user\nuser:x:1000:\nsecret:x:2000:root\n".into(),
            steps: Vec::new(),
        };

        // Allowed: `wheel` member.
        let (_, err, code) = run_with(&s(&["-", "wheel"]), &mut mock);
        assert_eq!((err, code), (None, 0));
        assert_eq!(mock.steps, vec!["setgid:10", "exec:/bin/sh:/bin/sh -l"]);

        // Denied: not a member of `secret`.
        mock.steps.clear();
        let (_, err, code) = run_with(&s(&["secret"]), &mut mock);
        assert_eq!(code, 1);
        assert!(err.unwrap().contains("permission denied"));
        assert!(mock.steps.is_empty());

        // Missing group fails cleanly.
        assert_eq!(run_with(&s(&["nosuchgroup"]), &mut mock).2, 1);
    }
}

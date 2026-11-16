//! `chroot` utility: `chroot NEWROOT [COMMAND [ARG]...]`.
use os_core::cli;
use std::io;
use std::path::Path;

pub(crate) trait ChrootBackend {
    fn shell_env(&self) -> Option<String>;
    fn chroot(&mut self, newroot: &str) -> io::Result<()>;
    fn chdir_root(&mut self) -> io::Result<()>;
    fn execvp(&mut self, prog: &str, argv: &[String]) -> Result<(), io::Error>;
}

struct OsChrootBackend;

impl ChrootBackend for OsChrootBackend {
    fn shell_env(&self) -> Option<String> {
        std::env::var("SHELL").ok().filter(|s| !s.is_empty())
    }

    fn chroot(&mut self, newroot: &str) -> io::Result<()> {
        os_posix::chroot(Path::new(newroot))
    }

    fn chdir_root(&mut self) -> io::Result<()> {
        os_posix::chdir(Path::new("/"))
    }

    fn execvp(&mut self, prog: &str, argv: &[String]) -> Result<(), io::Error> {
        Err(os_posix::execvp(prog, argv))
    }
}

pub(crate) enum ChrootAction {
    Help(String),
    Run {
        newroot: String,
        command: Vec<String>,
    },
}

pub(crate) fn parse_chroot_args(args: &[String]) -> Result<ChrootAction, (String, i32)> {
    let mut idx = 0;
    if let Some(arg) = args.first() {
        if arg == "--" {
            idx = 1;
        } else if arg == "-h" || arg == "--help" {
            let help = cli::help("chroot")
                .unwrap_or_else(|| "Usage: chroot NEWROOT [COMMAND [ARG]...]\n".to_string());
            return Ok(ChrootAction::Help(help));
        } else if arg.starts_with('-') && arg.len() > 1 {
            return Err((format!("chroot: unsupported option '{arg}'"), 125));
        }
    }

    if idx >= args.len() {
        return Err((
            "chroot: missing operand NEWROOT; chroot -h shows how to use it".to_string(),
            125,
        ));
    }

    let newroot = args[idx].clone();
    let command = args[idx + 1..].to_vec();
    Ok(ChrootAction::Run { newroot, command })
}

pub(crate) fn run_with(
    args: &[String],
    backend: &mut impl ChrootBackend,
) -> (Option<String>, Option<String>, i32) {
    let (newroot, command) = match parse_chroot_args(args) {
        Ok(ChrootAction::Help(help)) => return (Some(help), None, 0),
        Ok(ChrootAction::Run { newroot, command }) => (newroot, command),
        Err((msg, code)) => return (None, Some(msg), code),
    };

    if let Err(err) = backend.chroot(&newroot) {
        return (
            None,
            Some(format!(
                "chroot: cannot change root directory to '{newroot}': {err}"
            )),
            125,
        );
    }

    if let Err(err) = backend.chdir_root() {
        return (
            None,
            Some(format!("chroot: cannot chdir to '/': {err}")),
            125,
        );
    }

    let (prog, argv) = if command.is_empty() {
        let shell = backend.shell_env().unwrap_or_else(|| "/bin/sh".to_string());
        let argv = vec![shell.clone(), "-i".to_string()];
        (shell, argv)
    } else {
        (command[0].clone(), command)
    };

    match backend.execvp(&prog, &argv) {
        Ok(()) => (None, None, 0),
        Err(err) => {
            let code = if os_posix::errno_of(&err) == Some(abi::Errno::ENOENT)
                || err.kind() == io::ErrorKind::NotFound
            {
                127
            } else {
                126
            };
            (
                None,
                Some(format!("chroot: failed to run command '{prog}': {err}")),
                code,
            )
        }
    }
}

pub fn run(args: &[String]) -> i32 {
    let mut backend = OsChrootBackend;
    let (out, err, code) = run_with(args, &mut backend);
    if let Some(help) = out {
        println!("{help}");
    }
    if let Some(msg) = err {
        eprintln!("{msg}");
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MockChroot {
        shell: Option<String>,
        steps: Vec<String>,
        chroot_err: Option<io::ErrorKind>,
        chdir_err: Option<io::ErrorKind>,
        exec_err: Option<io::ErrorKind>,
    }

    impl ChrootBackend for MockChroot {
        fn shell_env(&self) -> Option<String> {
            self.shell.clone()
        }

        fn chroot(&mut self, newroot: &str) -> io::Result<()> {
            self.steps.push(format!("chroot:{newroot}"));
            if let Some(kind) = self.chroot_err {
                return Err(io::Error::new(kind, "chroot failed"));
            }
            Ok(())
        }

        fn chdir_root(&mut self) -> io::Result<()> {
            self.steps.push("chdir:/".into());
            if let Some(kind) = self.chdir_err {
                return Err(io::Error::new(kind, "chdir failed"));
            }
            Ok(())
        }

        fn execvp(&mut self, prog: &str, argv: &[String]) -> Result<(), io::Error> {
            self.steps.push(format!("exec:{prog}:{}", argv.join(" ")));
            if let Some(kind) = self.exec_err {
                return Err(io::Error::new(kind, "exec failed"));
            }
            Ok(())
        }
    }

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|v| (*v).to_string()).collect()
    }

    #[test]
    fn chroot_executes_sequence_and_preserves_trailing_command_flags() {
        let mut mock = MockChroot::default();
        let (out, err, code) = run_with(&s(&["/jail", "/bin/ls", "--help", "-la"]), &mut mock);
        assert_eq!((out, err, code), (None, None, 0));
        assert_eq!(
            mock.steps,
            vec!["chroot:/jail", "chdir:/", "exec:/bin/ls:/bin/ls --help -la",]
        );

        let mut default_shell = MockChroot {
            shell: Some("/bin/dash".into()),
            ..Default::default()
        };
        let (_, _, code2) = run_with(&s(&["--", "/jail"]), &mut default_shell);
        assert_eq!(code2, 0);
        assert_eq!(
            default_shell.steps,
            vec!["chroot:/jail", "chdir:/", "exec:/bin/dash:/bin/dash -i"]
        );
    }

    #[test]
    fn chroot_returns_gnu_exit_codes_125_126_127_and_rejects_leading_options() {
        for bad in [
            &["--userspec=0:0", "/jail"][..],
            &["--groups=wheel", "/jail"][..],
            &["--skip-chdir", "/jail"][..],
            &[][..],
        ] {
            let mut mock = MockChroot::default();
            let (_, err, code) = run_with(&s(bad), &mut mock);
            assert_eq!(code, 125, "bad={bad:?}");
            assert!(err.is_some());
            assert!(mock.steps.is_empty());
        }

        let mut fail_chroot = MockChroot {
            chroot_err: Some(io::ErrorKind::PermissionDenied),
            ..Default::default()
        };
        assert_eq!(run_with(&s(&["/jail"]), &mut fail_chroot).2, 125);

        let mut fail_not_found = MockChroot {
            exec_err: Some(io::ErrorKind::NotFound),
            ..Default::default()
        };
        assert_eq!(
            run_with(&s(&["/jail", "/bin/missing"]), &mut fail_not_found).2,
            127
        );

        let mut fail_perm = MockChroot {
            exec_err: Some(io::ErrorKind::PermissionDenied),
            ..Default::default()
        };
        assert_eq!(
            run_with(&s(&["/jail", "/bin/noexec"]), &mut fail_perm).2,
            126
        );
    }
}

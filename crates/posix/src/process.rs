//! Process creation and image replacement for WASI/WASIX programs over the OS host adapter.
use std::io;

#[derive(Clone, Copy)]
pub enum Stdin {
    Inherit,
    Null,
    Tty,
}

pub struct Child(u32);

/// POSIX wait status: ordinary exit codes and terminating signals stay distinct.
pub struct ExitStatus(u32);
impl ExitStatus {
    pub fn code(&self) -> Option<i32> {
        (self.0 & 0x7f == 0).then_some(((self.0 >> 8) & 0xff) as i32)
    }
    pub fn signal(&self) -> Option<i32> {
        (self.0 & 0x7f != 0).then_some((self.0 & 0x7f) as i32)
    }
    pub fn success(&self) -> bool {
        self.code() == Some(0)
    }
}

/// Spawn through PATH, inheriting credentials, umask, cwd, root, mount namespace and descriptors.
/// The stdin action is applied only in the child. Close-on-exec descriptors are excluded.
pub fn spawn(argv: &[String], stdin: Stdin) -> io::Result<Child> {
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    spawn_with(
        argv,
        stdin,
        &cwd,
        &std::env::vars()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>(),
        None,
    )
}

/// Explicit spawn attributes; pgroup=0 creates a group before the child executes guest code.
/// Identity always comes from the parent process, never these attributes.
pub fn spawn_with(
    argv: &[String],
    stdin: Stdin,
    cwd: &str,
    env: &[String],
    pgroup: Option<u32>,
) -> io::Result<Child> {
    spawn_configured(argv, stdin, cwd, env, pgroup, &SpawnOptions::default())
}

/// Additional generic child attributes, applied before guest instructions.
#[derive(Default)]
pub struct SpawnOptions<'a> {
    pub cgroup: Option<&'a str>,
    pub dup2: &'a [(u32, u32)],
}

pub fn spawn_configured(
    argv: &[String],
    stdin: Stdin,
    cwd: &str,
    env: &[String],
    pgroup: Option<u32>,
    options: &SpawnOptions<'_>,
) -> io::Result<Child> {
    if argv.is_empty() || argv[0].is_empty() || argv.iter().any(|arg| arg.contains('\0')) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid argument vector",
        ));
    }
    let request = serde_json::to_vec(&serde_json::json!({
        "argv": argv,
        "cwd": cwd,
        "env": env,
        "pgroup": pgroup,
        "cgroup": options.cgroup,
        "dup2": options.dup2,
        "stdin": match stdin { Stdin::Inherit => "inherit", Stdin::Null => "null", Stdin::Tty => "tty" },
    }))?;
    #[cfg(target_os = "wasi")]
    {
        let mut pid = 0;
        // SAFETY: the input buffer and scalar output live throughout this blocking call.
        let errno = unsafe { host_spawn(request.as_ptr(), request.len(), &mut pid) };
        if errno != 0 {
            return Err(io::Error::from_raw_os_error(errno as i32));
        }
        Ok(Child(pid))
    }
    #[cfg(not(target_os = "wasi"))]
    {
        let _ = request;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "requires the WASI process adapter",
        ))
    }
}

/// Replace the current process image in place, searching `PATH` when `file` contains no `'/'`.
///
/// Preserves PID, process group, controlling TTY, open non-`FD_CLOEXEC` descriptors, mount
/// namespace, `FsContext.root` (`chroot`), and `FsContext.cwd`. Never returns on success;
/// returns the failure `io::Error` if the image could not be resolved or executed.
pub fn execvp(file: &str, argv: &[String]) -> io::Error {
    let env: Vec<String> = std::env::vars()
        .map(|(name, value)| format!("{name}={value}"))
        .collect();
    exec_impl(file, argv, &env, !file.contains('/'))
}

/// Replace the current process image in place without searching `PATH`.
pub fn execve(file: &str, argv: &[String], env: &[String]) -> io::Error {
    exec_impl(file, argv, env, false)
}

fn exec_impl(file: &str, argv: &[String], env: &[String], search: bool) -> io::Error {
    if file.is_empty() {
        return crate::os_error(abi::Error::new(abi::Errno::ENOENT));
    }
    if file.contains('\0')
        || argv.is_empty()
        || argv.iter().any(|arg| arg.contains('\0'))
        || env.iter().any(|entry| entry.contains('\0'))
    {
        return crate::os_error(abi::Error::new(abi::Errno::EINVAL));
    }
    let request = match serde_json::to_vec(&serde_json::json!({
        "file": file,
        "argv": argv,
        "env": env,
        "search": search,
    })) {
        Ok(bytes) => bytes,
        Err(err) => return err.into(),
    };
    #[cfg(target_arch = "wasm32")]
    {
        // SAFETY: `request` lives across the host call; on success the host unwinds the image.
        let rc = unsafe { crate::wasi_libc::host::host_execve(request.as_ptr(), request.len()) };
        if rc < 0 {
            crate::host_errno_error(-rc)
        } else {
            crate::os_error(abi::Error::new(abi::Errno::ENOEXEC))
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = request;
        io::Error::new(
            io::ErrorKind::Unsupported,
            "requires the WASI process adapter",
        )
    }
}

/// Wait for any adopted or direct child without blocking. SIGCHLD tells the caller when
/// to drain; ECHILD is returned as None, like an empty nonblocking observation.
pub fn reap() -> io::Result<Option<(u32, ExitStatus)>> {
    #[cfg(target_os = "wasi")]
    {
        let mut status = 0;
        // SAFETY: the output scalar is valid throughout this host call.
        let result = unsafe { host_waitpid2(-1, &mut status, 1) };
        if result == -12 {
            return Ok(None);
        } // WASI ECHILD
        if result < 0 {
            return Err(io::Error::from_raw_os_error(-result));
        }
        Ok((result != 0).then_some((result as u32, ExitStatus(status))))
    }
    #[cfg(not(target_os = "wasi"))]
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "requires the WASI process adapter",
    ))
}

impl Child {
    pub fn id(&self) -> u32 {
        self.0
    }

    /// Nonblocking wait. A returned status reaps the child; do not wait on it again.
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        #[cfg(target_os = "wasi")]
        {
            let mut status = 0;
            // SAFETY: the host writes one scalar to this valid pointer.
            let result = unsafe { host_waitpid2(self.0 as i32, &mut status, 1) };
            if result < 0 {
                return Err(io::Error::from_raw_os_error(-result));
            }
            Ok((result != 0).then_some(ExitStatus(status)))
        }
        #[cfg(not(target_os = "wasi"))]
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "requires the WASI process adapter",
        ))
    }

    /// Wait for and reap this child. Its output uses the inherited descriptors directly.
    pub fn wait(self) -> io::Result<ExitStatus> {
        #[cfg(target_os = "wasi")]
        {
            let mut status = 0;
            // SAFETY: the host writes one scalar into this valid output pointer.
            let errno = unsafe { host_waitpid(self.0, &mut status) };
            if errno != 0 {
                return Err(io::Error::from_raw_os_error(errno as i32));
            }
            Ok(ExitStatus(status))
        }
        #[cfg(not(target_os = "wasi"))]
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "requires the WASI process adapter",
        ))
    }
}

#[cfg(target_os = "wasi")]
#[link(wasm_import_module = "os")]
unsafe extern "C" {
    #[link_name = "posix_spawn"]
    fn host_spawn(request: *const u8, len: usize, pid: *mut u32) -> u32;
    #[link_name = "waitpid"]
    fn host_waitpid(pid: u32, status: *mut u32) -> u32;
    #[link_name = "waitpid2"]
    fn host_waitpid2(pid: i32, status: *mut u32, options: u32) -> i32;
}

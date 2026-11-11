//! Process creation for WASI preview 1 programs, over the runtime's generic host adapter.
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

/// Spawn through PATH, inheriting credentials, umask, cwd, environment and descriptors.
/// The stdin action is applied only in the child. Close-on-exec descriptors are excluded.
pub fn spawn(argv: &[String], stdin: Stdin) -> io::Result<Child> {
    spawn_with(
        argv,
        stdin,
        &std::env::current_dir()?.to_string_lossy(),
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

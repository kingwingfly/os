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

/// Explicit bind-mount specification forwarded in a service's spawn grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceBindMount<'a> {
    pub source: &'a str,
    pub target: &'a str,
    pub read_only: bool,
}

/// Mount-namespace, user/group, device, cloud-scope, and bind-mount grant applied before a
/// supervised unit executes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceGrant<'a> {
    pub export_impersonate: bool,
    pub mount_namespace: &'a str,
    pub bind_mounts: &'a [ServiceBindMount<'a>],
    pub user: Option<&'a str>,
    pub group: Option<&'a str>,
    pub devices: &'a [&'a str],
    pub cloud_scope: Option<&'a abi::auth_v2::RemoteScope>,
}

/// Additional generic child attributes, applied before guest instructions.
#[derive(Default)]
pub struct SpawnOptions<'a> {
    pub cgroup: Option<&'a str>,
    pub dup2: &'a [(u32, u32)],
    pub service_grant: Option<ServiceGrant<'a>>,
    /// Create a new session (`setsid(2)`) in the child before executing guest code.
    /// Mutually exclusive with `pgroup`.
    pub setsid: bool,
    /// Acquire this child descriptor (after `dup2`) as the child's controlling terminal
    /// (`TIOCSCTTY`) before executing guest code.
    pub ctty_fd: Option<u32>,
}

pub(crate) fn encode_spawn_request(
    argv: &[String],
    stdin: Stdin,
    cwd: &str,
    env: &[String],
    pgroup: Option<u32>,
    options: &SpawnOptions<'_>,
) -> io::Result<Vec<u8>> {
    if argv.is_empty() || argv[0].is_empty() || argv.iter().any(|arg| arg.contains('\0')) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid argument vector",
        ));
    }
    if options.setsid && pgroup.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "setsid cannot be combined with pgroup",
        ));
    }
    if cwd.contains('\0')
        || env.iter().any(|entry| entry.contains('\0'))
        || options.cgroup.is_some_and(|cg| cg.contains('\0'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "spawn attribute contains NUL byte",
        ));
    }
    if let Some(grant) = options.service_grant
        && (grant.mount_namespace.contains('\0')
            || grant.user.is_some_and(|u| u.contains('\0'))
            || grant.group.is_some_and(|g| g.contains('\0'))
            || grant.devices.iter().any(|d| d.contains('\0'))
            || grant
                .bind_mounts
                .iter()
                .any(|b| b.source.contains('\0') || b.target.contains('\0')))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "service grant contains NUL byte",
        ));
    }
    let mut payload = serde_json::json!({
        "argv": argv,
        "cwd": cwd,
        "env": env,
        "pgroup": pgroup,
        "cgroup": options.cgroup,
        "dup2": options.dup2,
        "stdin": match stdin { Stdin::Inherit => "inherit", Stdin::Null => "null", Stdin::Tty => "tty" },
    });
    if options.setsid {
        payload["setsid"] = true.into();
    }
    if let Some(fd) = options.ctty_fd {
        payload["cttyFd"] = serde_json::json!(fd);
    }
    if let Some(grant) = options.service_grant {
        let bind_mounts: Vec<serde_json::Value> = grant
            .bind_mounts
            .iter()
            .map(|b| {
                serde_json::json!({
                    "source": b.source,
                    "target": b.target,
                    "readOnly": b.read_only,
                })
            })
            .collect();
        let mut grant_json = serde_json::json!({
            "mountNamespace": grant.mount_namespace,
            "bindMounts": bind_mounts,
        });
        if grant.export_impersonate {
            grant_json["exportImpersonate"] = true.into();
        }
        if let Some(user) = grant.user {
            grant_json["user"] = serde_json::json!(user);
        }
        if let Some(group) = grant.group {
            grant_json["group"] = serde_json::json!(group);
        }
        if !grant.devices.is_empty() {
            grant_json["devices"] = serde_json::json!(grant.devices);
        }
        if let Some(scope) = grant.cloud_scope {
            grant_json["cloudScope"] = serde_json::to_value(scope).map_err(io::Error::other)?;
        }
        payload["serviceGrant"] = grant_json;
    }
    serde_json::to_vec(&payload).map_err(Into::into)
}

pub fn spawn_configured(
    argv: &[String],
    stdin: Stdin,
    cwd: &str,
    env: &[String],
    pgroup: Option<u32>,
    options: &SpawnOptions<'_>,
) -> io::Result<Child> {
    let request = encode_spawn_request(argv, stdin, cwd, env, pgroup, options)?;
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

/// Wait flags for [`waitpid2`].
pub const WNOHANG: u32 = 1;
pub const WUNTRACED: u32 = 2;
pub const WCONTINUED: u32 = 8;

/// Full POSIX wait status supporting exited, signaled, stopped, and continued states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitStatus(pub u32);

impl WaitStatus {
    pub fn exited(&self) -> bool {
        (self.0 & 0x7f) == 0
    }
    pub fn code(&self) -> Option<i32> {
        self.exited().then_some(((self.0 >> 8) & 0xff) as i32)
    }
    pub fn stopped(&self) -> bool {
        (self.0 & 0xff) == 0x7f
    }
    pub fn stop_signal(&self) -> Option<u32> {
        self.stopped().then_some((self.0 >> 8) & 0xff)
    }
    pub fn continued(&self) -> bool {
        self.0 == 0xffff
    }
    pub fn signaled(&self) -> bool {
        let low = self.0 & 0x7f;
        low != 0 && low != 0x7f
    }
    pub fn signal(&self) -> Option<u32> {
        self.signaled().then_some(self.0 & 0x7f)
    }
    /// POSIX shell exit status convention (`code`, or `128 + signal`).
    pub fn shell_status(&self) -> i32 {
        if let Some(code) = self.code() {
            code
        } else if let Some(sig) = self.signal() {
            128 + sig as i32
        } else {
            0
        }
    }
}

/// Wait for children matching `pid` (`-1` any, `> 0` specific pid, `0` own pgrp, `< -1` pgrp `-pid`)
/// with `WNOHANG` / `WUNTRACED` / `WCONTINUED`. Returns `Ok(None)` when `WNOHANG` sees no event.
pub fn waitpid2(pid: i32, options: u32) -> io::Result<Option<(u32, WaitStatus)>> {
    #[cfg(target_os = "wasi")]
    {
        let mut status = 0u32;
        // SAFETY: `status` is a valid stack output scalar.
        let result = unsafe { host_waitpid2(pid, &mut status, options) };
        if result < 0 {
            return Err(crate::host_errno_error(-result));
        }
        Ok((result != 0).then_some((result as u32, WaitStatus(status))))
    }
    #[cfg(not(target_os = "wasi"))]
    {
        let _ = (pid, options);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "requires the WASI process adapter",
        ))
    }
}

/// Open a path using Linux `O_*` flags directly via `(module "os") open` (supports `/dev/ptmx`,
/// `/dev/pts/<N>`, `O_NOCTTY`, `O_NONBLOCK`, `O_CLOEXEC`).
pub fn open_raw(path: &str, flags: u32, mode: u32) -> io::Result<u32> {
    if path.is_empty() || path.contains('\0') {
        return Err(crate::os_error(abi::Error::new(abi::Errno::EINVAL)));
    }
    #[cfg(target_os = "wasi")]
    {
        // SAFETY: `path` slice lives across this synchronous host call.
        let rc = unsafe { host_open(path.as_ptr(), path.len(), flags, mode) };
        if rc < 0 {
            Err(crate::host_errno_error(-rc))
        } else {
            Ok(rc as u32)
        }
    }
    #[cfg(not(target_os = "wasi"))]
    {
        let _ = (flags, mode);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "requires the WASI process adapter",
        ))
    }
}

/// Effective/real UID of the calling process.
pub fn getuid() -> u32 {
    #[cfg(target_os = "wasi")]
    {
        // SAFETY: scalar host import.
        unsafe { host_getuid() }
    }
    #[cfg(not(target_os = "wasi"))]
    {
        0
    }
}

/// Effective/real GID of the calling process.
pub fn getgid() -> u32 {
    #[cfg(target_os = "wasi")]
    {
        // SAFETY: scalar host import.
        unsafe { host_getgid() }
    }
    #[cfg(not(target_os = "wasi"))]
    {
        0
    }
}

/// Query process group id of `pid` (`0` = caller).
pub fn getpgid(pid: u32) -> io::Result<u32> {
    #[cfg(target_os = "wasi")]
    {
        // SAFETY: scalar host import.
        let rc = unsafe { host_getpgid(pid) };
        if rc < 0 {
            Err(crate::host_errno_error(-rc))
        } else {
            Ok(rc as u32)
        }
    }
    #[cfg(not(target_os = "wasi"))]
    {
        let _ = pid;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "requires the WASI process adapter",
        ))
    }
}

/// Set process group id of `pid` (`0` = caller) to `pgid` (`0` = `pid`).
pub fn setpgid(pid: u32, pgid: u32) -> io::Result<()> {
    #[cfg(target_os = "wasi")]
    {
        // SAFETY: scalar host import.
        let rc = unsafe { host_setpgid(pid, pgid) };
        if rc < 0 {
            Err(crate::host_errno_error(-rc))
        } else {
            Ok(())
        }
    }
    #[cfg(not(target_os = "wasi"))]
    {
        let _ = (pid, pgid);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "requires the WASI process adapter",
        ))
    }
}

/// Create a new session and return its session id.
pub fn setsid() -> io::Result<u32> {
    #[cfg(target_os = "wasi")]
    {
        // SAFETY: scalar host import.
        let rc = unsafe { host_setsid() };
        if rc < 0 {
            Err(crate::host_errno_error(-rc))
        } else {
            Ok(rc as u32)
        }
    }
    #[cfg(not(target_os = "wasi"))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "requires the WASI process adapter",
        ))
    }
}

/// Return foreground process group id of controlling terminal `fd`.
pub fn tcgetpgrp(fd: u32) -> io::Result<u32> {
    #[cfg(target_os = "wasi")]
    {
        // SAFETY: scalar host import.
        let rc = unsafe { host_tcgetpgrp(fd) };
        if rc < 0 {
            Err(crate::host_errno_error(-rc))
        } else {
            Ok(rc as u32)
        }
    }
    #[cfg(not(target_os = "wasi"))]
    {
        let _ = fd;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "requires the WASI process adapter",
        ))
    }
}

/// Set foreground process group id of controlling terminal `fd` to `pgid`.
pub fn tcsetpgrp(fd: u32, pgid: u32) -> io::Result<()> {
    #[cfg(target_os = "wasi")]
    {
        // SAFETY: scalar host import.
        let rc = unsafe { host_tcsetpgrp(fd, pgid) };
        if rc < 0 {
            Err(crate::host_errno_error(-rc))
        } else {
            Ok(())
        }
    }
    #[cfg(not(target_os = "wasi"))]
    {
        let _ = (fd, pgid);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "requires the WASI process adapter",
        ))
    }
}

/// Perform a single `Call::Ioctl` against descriptor `fd`.
pub fn ioctl(fd: u32, request: u32, arg: serde_json::Value) -> io::Result<serde_json::Value> {
    let mut reply = crate::batch(&[abi::Call::Ioctl {
        fd: fd.into(),
        request,
        arg,
    }])?;
    reply
        .results
        .remove(0)
        .into_result()
        .map_err(crate::os_error)
}

/// Send signal `signal` to process `pid` (`> 0`) or process group `-pid` (`< 0`).
pub fn kill(pid: i32, signal: u8) -> io::Result<()> {
    let mut reply = crate::batch(&[abi::Call::Kill {
        pid: pid.to_string(),
        signal: Some(signal),
    }])?;
    reply
        .results
        .remove(0)
        .into_result()
        .map(|_| ())
        .map_err(crate::os_error)
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
    #[link_name = "open"]
    fn host_open(path: *const u8, len: usize, flags: u32, mode: u32) -> i32;
    #[link_name = "getuid"]
    fn host_getuid() -> u32;
    #[link_name = "getgid"]
    fn host_getgid() -> u32;
    #[link_name = "getpgid"]
    fn host_getpgid(pid: u32) -> i32;
    #[link_name = "setpgid"]
    fn host_setpgid(pid: u32, pgid: u32) -> i32;
    #[link_name = "setsid"]
    fn host_setsid() -> i32;
    #[link_name = "tcgetpgrp"]
    fn host_tcgetpgrp(fd: u32) -> i32;
    #[link_name = "tcsetpgrp"]
    fn host_tcsetpgrp(fd: u32, pgid: u32) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_spawn_options_omit_service_grant() {
        let argv = vec!["/usr/bin/true".to_string()];
        let env = vec!["PATH=/usr/bin".to_string()];
        let raw = encode_spawn_request(
            &argv,
            Stdin::Null,
            "/",
            &env,
            Some(0),
            &SpawnOptions::default(),
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(parsed["argv"], serde_json::json!(["/usr/bin/true"]));
        assert_eq!(parsed["stdin"], "null");
        assert!(parsed.get("serviceGrant").is_none());
        assert!(parsed.get("setsid").is_none());
        assert!(parsed.get("cttyFd").is_none());
    }

    #[test]
    fn spawn_options_serializes_setsid_and_ctty_fd() {
        let argv = vec!["/usr/bin/osh".to_string()];
        let env = vec!["TERM=xterm-256color".to_string()];
        let opts = SpawnOptions {
            dup2: &[(7, 0), (7, 1), (7, 2)],
            setsid: true,
            ctty_fd: Some(0),
            ..SpawnOptions::default()
        };
        let raw = encode_spawn_request(&argv, Stdin::Inherit, "/", &env, None, &opts).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(parsed["setsid"], true);
        assert_eq!(parsed["cttyFd"], 0);
        assert!(parsed["pgroup"].is_null());

        let err =
            encode_spawn_request(&argv, Stdin::Inherit, "/", &env, Some(0), &opts).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn spawn_options_serializes_service_grant_contract() {
        let argv = vec!["/usr/bin/worker".to_string()];
        let env = vec!["LANG=C.UTF-8".to_string()];
        let binds = [
            ServiceBindMount {
                source: "/srv/data",
                target: "/var/lib/app",
                read_only: true,
            },
            ServiceBindMount {
                source: "/tmp/work",
                target: "/work",
                read_only: false,
            },
        ];
        let opts = SpawnOptions {
            cgroup: Some("/user/supervise-1-0-1"),
            dup2: &[(4, 1), (5, 2)],
            service_grant: Some(ServiceGrant {
                export_impersonate: false,
                mount_namespace: "isolated",
                bind_mounts: &binds,
                user: None,
                group: None,
                devices: &[],
                cloud_scope: None,
            }),
            ..SpawnOptions::default()
        };
        let raw = encode_spawn_request(&argv, Stdin::Null, "/work", &env, Some(0), &opts).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(
            parsed["serviceGrant"],
            serde_json::json!({
                "mountNamespace": "isolated",
                "bindMounts": [
                    { "source": "/srv/data", "target": "/var/lib/app", "readOnly": true },
                    { "source": "/tmp/work", "target": "/work", "readOnly": false }
                ]
            })
        );
        assert_eq!(parsed["cgroup"], "/user/supervise-1-0-1");
        assert_eq!(parsed["dup2"], serde_json::json!([[4, 1], [5, 2]]));
    }

    #[test]
    fn spawn_request_rejects_nul_bytes_in_service_grant() {
        let argv = vec!["/usr/bin/true".to_string()];
        let bad_binds = [ServiceBindMount {
            source: "/srv/\0bad",
            target: "/mnt",
            read_only: true,
        }];
        let err = encode_spawn_request(
            &argv,
            Stdin::Null,
            "/",
            &[],
            None,
            &SpawnOptions {
                cgroup: None,
                dup2: &[],
                service_grant: Some(ServiceGrant {
                    export_impersonate: false,
                    mount_namespace: "isolated",
                    bind_mounts: &bad_binds,
                    user: None,
                    group: None,
                    devices: &[],
                    cloud_scope: None,
                }),
                ..SpawnOptions::default()
            },
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}

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
                mount_namespace: "isolated",
                bind_mounts: &binds,
                user: None,
                group: None,
                devices: &[],
                cloud_scope: None,
            }),
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
                    mount_namespace: "isolated",
                    bind_mounts: &bad_binds,
                    user: None,
                    group: None,
                    devices: &[],
                    cloud_scope: None,
                }),
            },
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}

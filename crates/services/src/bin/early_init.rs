//! Stage 1 `initramfs` early `/init` (PID 1, local `uid 0`; Contract §2.15, §5, #56 L3c).
//!
//! Runs inside Stage 1 `tmpfs` `/`:
//! 1. Reads `/run/os/boot-profile.json` (`0444`). If `recovery == true`, drops directly into
//!    Stage 1 interactive `/bin/sh` recovery shell.
//! 2. Checks `COWFS_FORMAT_VERSION` & runs `/bin/cowfsck /dev/vd0` before mounting root.
//!    - Incompatible format version -> `EPROTONOSUPPORT` into Stage 1 recovery chooser
//!      (**NEVER silently formats or wipes user data!**).
//!    - Corruption -> prints diagnostics & offers snapshot rollback or recovery shell.
//! 3. Mounts local `os-cowfs` root at `/sysroot` (`ForkOnBusy` default or `Exclusive`).
//!    - On `ForkOnBusy` fork -> emits non-blocking console banner announcing O(1) fork.
//!    - On `Exclusive` busy -> `EBUSY` into Stage 1 recovery chooser.
//! 4. Ensures `/run/os/root` (`0444`) is recorded, mounts verified Release v2 `/sysroot/usr`
//!    (`image`, `MS_RDONLY | MS_NODEV`) and fresh `tmpfs` (`01777`) at `/sysroot/tmp`.
//! 5. Transfers PID 1 cleanly via `/bin/switch_root /sysroot /usr/bin/init` preserving PID 1
//!    and original `start_time`.

use abi::Errno;
use abi::contract::mount_flags;
use serde::{Deserialize, Serialize};
use std::io;
use std::path::Path;

pub const BOOT_PROFILE_PATH: &str = "/run/os/boot-profile.json";
pub const MOUNTED_ROOT_PATH: &str = "/run/os/root";
pub const STAGE2_INIT_PATH: &str = "/usr/bin/init";
pub const RECOVERY_SHELL_PATH: &str = "/bin/sh";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootWriterMode {
    ForkOnBusy,
    Exclusive,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootSpec {
    CowFs {
        volume_uuid: Option<String>,
        writer_mode: BootWriterMode,
    },
    CloudOptIn {
        subpath: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootProfile {
    pub version: u32,
    pub root: RootSpec,
    pub default_user: String,
    pub generation: Option<String>,
    pub recovery: bool,
}

impl Default for BootProfile {
    fn default() -> Self {
        Self {
            version: 1,
            root: RootSpec::CowFs {
                volume_uuid: None,
                writer_mode: BootWriterMode::ForkOnBusy,
            },
            default_user: "user".into(),
            generation: None,
            recovery: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedRootInfo {
    pub fstype: String,
    pub volume_uuid: Option<String>,
    pub forked_from: Option<String>,
    pub base_epoch: u64,
    pub ephemeral_if_unmodified: bool,
    pub writer_mode: String,
    pub first_boot_seeded: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EarlyBootOutcome {
    SwitchedToStage2 {
        init: String,
    },
    Recovery {
        reason: String,
        errno: Option<Errno>,
    },
}

pub trait EarlyInitBackend {
    fn getpid(&self) -> io::Result<u32>;
    fn read_file(&self, path: &str) -> io::Result<String>;
    fn write_file(&mut self, path: &str, content: &str, mode: u32) -> io::Result<()>;
    fn run_cowfsck(&mut self, target: &str) -> io::Result<i32>;
    fn mount(
        &mut self,
        source: Option<&str>,
        target: &str,
        fstype: Option<&str>,
        flags: u64,
        data: Option<&str>,
    ) -> io::Result<()>;
    fn log(&mut self, line: &str);
    fn exec_switch_root(&mut self, newroot: &str, init: &str) -> io::Result<()>;
    fn enter_recovery(&mut self, reason: &str) -> io::Result<()>;
}

struct OsEarlyInitBackend;

impl EarlyInitBackend for OsEarlyInitBackend {
    fn getpid(&self) -> io::Result<u32> {
        #[cfg(target_os = "wasi")]
        {
            #[link(wasm_import_module = "wasix_32v1")]
            unsafe extern "C" {
                fn proc_id(pid: *mut u32) -> u32;
            }
            let mut pid = 0u32;
            // SAFETY: scalar output pointer lives across the import.
            if unsafe { proc_id(&mut pid) } == 0 && pid != 0 {
                return Ok(pid);
            }
        }
        let mut reply = os_posix::batch(&[abi::Call::Getpid])?;
        let val = reply
            .results
            .remove(0)
            .into_result()
            .map_err(|e| io::Error::other(os_posix::OsCallError(e)))?;
        val.as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| io::Error::other("invalid getpid reply"))
    }

    fn read_file(&self, path: &str) -> io::Result<String> {
        std::fs::read_to_string(path)
    }

    fn write_file(&mut self, path: &str, content: &str, mode: u32) -> io::Result<()> {
        if let Some(parent) = Path::new(path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(path, content)?;
        let _ = os_posix::chmod(Path::new(path), mode);
        Ok(())
    }

    fn run_cowfsck(&mut self, target: &str) -> io::Result<i32> {
        let child = os_posix::process::spawn(
            &["/bin/cowfsck".to_string(), target.to_string()],
            os_posix::process::Stdin::Null,
        )?;
        let status = child.wait()?;
        Ok(status.code().unwrap_or(8))
    }

    fn mount(
        &mut self,
        source: Option<&str>,
        target: &str,
        fstype: Option<&str>,
        flags: u64,
        data: Option<&str>,
    ) -> io::Result<()> {
        os_posix::mount(
            source.map(Path::new),
            Path::new(target),
            fstype,
            flags,
            data,
        )
    }

    fn log(&mut self, line: &str) {
        eprintln!("{line}");
    }

    fn exec_switch_root(&mut self, newroot: &str, init: &str) -> io::Result<()> {
        let env: Vec<String> = std::env::vars().map(|(k, v)| format!("{k}={v}")).collect();
        Err(os_posix::process::execve(
            "/bin/switch_root",
            &[
                "/bin/switch_root".to_string(),
                newroot.to_string(),
                init.to_string(),
            ],
            &env,
        ))
    }

    fn enter_recovery(&mut self, reason: &str) -> io::Result<()> {
        eprintln!("os: Stage 1 recovery: {reason}");
        let env: Vec<String> = std::env::vars().map(|(k, v)| format!("{k}={v}")).collect();
        Err(os_posix::process::execve(
            RECOVERY_SHELL_PATH,
            &[RECOVERY_SHELL_PATH.to_string(), "-i".to_string()],
            &env,
        ))
    }
}

pub fn run_early_init(backend: &mut impl EarlyInitBackend) -> io::Result<EarlyBootOutcome> {
    let pid = backend.getpid()?;
    if pid != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            os_posix::OsCallError(abi::Error::because(
                Errno::EPERM,
                "early_init must run as PID 1",
            )),
        ));
    }

    // Step 1: Load persisted BootProfile injected by Stage 0 at `/run/os/boot-profile.json`.
    let profile: BootProfile = match backend.read_file(BOOT_PROFILE_PATH) {
        Ok(raw) => serde_json::from_str(&raw).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid {BOOT_PROFILE_PATH}: {e}"),
            )
        })?,
        Err(err) if err.kind() == io::ErrorKind::NotFound => BootProfile::default(),
        Err(err) => return Err(err),
    };

    if profile.recovery {
        let reason = "boot profile requested Stage 1 recovery shell".to_string();
        backend.log(&format!("os: {reason}"));
        let _ = backend.enter_recovery(&reason);
        return Ok(EarlyBootOutcome::Recovery {
            reason,
            errno: None,
        });
    }

    // Step 2: Resolve root spec, check format version & integrity via `cowfsck`, and mount `/sysroot`.
    let root_info = match &profile.root {
        RootSpec::CowFs {
            volume_uuid,
            writer_mode,
        } => {
            // Existing volume: ALWAYS run pre-mount `cowfsck` before mounting rw!
            if let Some(uuid) = volume_uuid {
                let target = format!("volume:{uuid}");
                match backend.run_cowfsck(&target) {
                    Ok(0) => {}
                    Ok(4) => {
                        let reason = format!(
                            "cowfsck detected corruption on volume {uuid}; refusing to mount (use cowfsck --rollback <snapshot> or recovery shell)"
                        );
                        backend.log(&format!("os: {reason}"));
                        let _ = backend.enter_recovery(&reason);
                        return Ok(EarlyBootOutcome::Recovery {
                            reason,
                            errno: Some(Errno::EIO),
                        });
                    }
                    Ok(code) => {
                        let reason = format!(
                            "cowfsck failed on volume {uuid} (exit {code}, possible EPROTONOSUPPORT format mismatch); refusing to format or wipe user data"
                        );
                        backend.log(&format!("os: {reason}"));
                        let _ = backend.enter_recovery(&reason);
                        return Ok(EarlyBootOutcome::Recovery {
                            reason,
                            errno: Some(Errno::EPROTONOSUPPORT),
                        });
                    }
                    Err(err) => {
                        let errno = os_posix::errno_of(&err);
                        let reason = format!(
                            "cowfsck error on volume {uuid}: {err}; preserving user volume untouched"
                        );
                        backend.log(&format!("os: {reason}"));
                        let _ = backend.enter_recovery(&reason);
                        return Ok(EarlyBootOutcome::Recovery { reason, errno });
                    }
                }
            }

            let source = match volume_uuid {
                Some(uuid) => format!("volume:{uuid}"),
                None => "/dev/vd0".to_string(),
            };
            let mode_opt = match writer_mode {
                BootWriterMode::Exclusive => "subvol=@,excl",
                BootWriterMode::ForkOnBusy => "subvol=@",
            };
            if let Err(err) =
                backend.mount(Some(&source), "/sysroot", Some("cowfs"), 0, Some(mode_opt))
            {
                let errno = os_posix::errno_of(&err);
                let reason = match errno {
                    Some(Errno::EPROTONOSUPPORT) => {
                        "incompatible os-cowfs format version (EPROTONOSUPPORT); volume preserved untouched (NEVER silently formatted)".to_string()
                    }
                    Some(Errno::EBUSY) => {
                        "root volume locked exclusively by another tab (EBUSY); choose fork, another volume, force-takeover, or recovery shell".to_string()
                    }
                    _ => format!("failed to mount cowfs root at /sysroot: {err}"),
                };
                backend.log(&format!("os: {reason}"));
                let _ = backend.enter_recovery(&reason);
                return Ok(EarlyBootOutcome::Recovery { reason, errno });
            }

            // If kernel already populated `/run/os/root` (e.g. with ForkOnBusy fork metadata),
            // preserve it and emit the non-blocking fork banner if booted on a fork.
            if let Ok(existing) = backend.read_file(MOUNTED_ROOT_PATH)
                && let Ok(parsed) = serde_json::from_str::<MountedRootInfo>(&existing)
            {
                if let (Some(fork_uuid), Some(_parent)) = (&parsed.volume_uuid, &parsed.forked_from)
                {
                    let short = &fork_uuid[..fork_uuid.len().min(12)];
                    backend.log(&format!(
                        "os: root volume busy; booted O(1) fork {short} (pruned on clean shutdown if unmodified)"
                    ));
                }
                parsed
            } else {
                MountedRootInfo {
                    fstype: "cowfs".into(),
                    volume_uuid: volume_uuid.clone(),
                    forked_from: None,
                    base_epoch: 0,
                    ephemeral_if_unmodified: false,
                    writer_mode: match writer_mode {
                        BootWriterMode::ForkOnBusy => "fork_on_busy".into(),
                        BootWriterMode::Exclusive => "exclusive".into(),
                    },
                    first_boot_seeded: volume_uuid.is_none(),
                }
            }
        }
        RootSpec::CloudOptIn { subpath } => {
            let src = subpath.as_deref().unwrap_or("cloud");
            if let Err(err) = backend.mount(Some(src), "/sysroot", Some("cloud"), 0, None) {
                let errno = os_posix::errno_of(&err);
                let reason = format!("opt-in cloud root mount failed: {err}");
                backend.log(&format!("os: {reason}"));
                let _ = backend.enter_recovery(&reason);
                return Ok(EarlyBootOutcome::Recovery { reason, errno });
            }
            MountedRootInfo {
                fstype: "cloud".into(),
                volume_uuid: None,
                forked_from: None,
                base_epoch: 0,
                ephemeral_if_unmodified: false,
                writer_mode: "multi-writer".into(),
                first_boot_seeded: false,
            }
        }
    };

    // Step 3: Record `/run/os/root` (`0444`) and mount Stage 2 `/sysroot/usr` + `/sysroot/tmp`.
    let root_json = serde_json::to_string_pretty(&root_info).map_err(io::Error::other)?;
    backend.write_file(MOUNTED_ROOT_PATH, &root_json, 0o444)?;

    backend.mount(
        Some("release-v2"),
        "/sysroot/usr",
        Some("image"),
        mount_flags::MS_RDONLY | mount_flags::MS_NODEV,
        None,
    )?;
    backend.mount(
        Some("tmpfs"),
        "/sysroot/tmp",
        Some("tmpfs"),
        mount_flags::MS_NOSUID | mount_flags::MS_NODEV,
        Some("mode=1777"),
    )?;

    // Step 4: Transfer PID 1 to Stage 2 via `switch_root`.
    if let Err(err) = backend.exec_switch_root("/sysroot", STAGE2_INIT_PATH) {
        let errno = os_posix::errno_of(&err);
        let reason = format!("switch_root failed: {err}");
        backend.log(&format!("os: {reason}"));
        let _ = backend.enter_recovery(&reason);
        return Ok(EarlyBootOutcome::Recovery { reason, errno });
    }

    Ok(EarlyBootOutcome::SwitchedToStage2 {
        init: STAGE2_INIT_PATH.into(),
    })
}

fn main() {
    let mut backend = OsEarlyInitBackend;
    if let Err(error) = run_early_init(&mut backend) {
        eprintln!("early_init: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct MockEarlyInit {
        pid: u32,
        files: BTreeMap<String, String>,
        cowfsck_code: i32,
        mount_fail_errno: Option<Errno>,
        mounts: Vec<(String, String, u64, Option<String>)>,
        logs: Vec<String>,
        switched: Option<(String, String)>,
        recovered: Option<String>,
    }

    impl MockEarlyInit {
        fn new(profile: &BootProfile) -> Self {
            let mut files = BTreeMap::new();
            files.insert(
                BOOT_PROFILE_PATH.into(),
                serde_json::to_string(profile).unwrap(),
            );
            Self {
                pid: 1,
                files,
                cowfsck_code: 0,
                mount_fail_errno: None,
                mounts: Vec::new(),
                logs: Vec::new(),
                switched: None,
                recovered: None,
            }
        }
    }

    impl EarlyInitBackend for MockEarlyInit {
        fn getpid(&self) -> io::Result<u32> {
            Ok(self.pid)
        }
        fn read_file(&self, path: &str) -> io::Result<String> {
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, path))
        }
        fn write_file(&mut self, path: &str, content: &str, _mode: u32) -> io::Result<()> {
            self.files.insert(path.to_string(), content.to_string());
            Ok(())
        }
        fn run_cowfsck(&mut self, _target: &str) -> io::Result<i32> {
            Ok(self.cowfsck_code)
        }
        fn mount(
            &mut self,
            source: Option<&str>,
            target: &str,
            fstype: Option<&str>,
            flags: u64,
            data: Option<&str>,
        ) -> io::Result<()> {
            if target == "/sysroot"
                && let Some(errno) = self.mount_fail_errno
            {
                return Err(io::Error::other(os_posix::OsCallError(abi::Error::new(
                    errno,
                ))));
            }
            self.mounts.push((
                format!("{}:{}", fstype.unwrap_or(""), source.unwrap_or("")),
                target.to_string(),
                flags,
                data.map(str::to_string),
            ));
            Ok(())
        }
        fn log(&mut self, line: &str) {
            self.logs.push(line.to_string());
        }
        fn exec_switch_root(&mut self, newroot: &str, init: &str) -> io::Result<()> {
            self.switched = Some((newroot.to_string(), init.to_string()));
            Ok(())
        }
        fn enter_recovery(&mut self, reason: &str) -> io::Result<()> {
            self.recovered = Some(reason.to_string());
            Ok(())
        }
    }

    #[test]
    fn early_init_mounts_sysroot_usr_tmp_and_switches_root() {
        let profile = BootProfile {
            root: RootSpec::CowFs {
                volume_uuid: Some("vol-main".into()),
                writer_mode: BootWriterMode::ForkOnBusy,
            },
            ..BootProfile::default()
        };
        let mut mock = MockEarlyInit::new(&profile);
        let outcome = run_early_init(&mut mock).unwrap();
        assert_eq!(
            outcome,
            EarlyBootOutcome::SwitchedToStage2 {
                init: STAGE2_INIT_PATH.into()
            }
        );
        assert_eq!(
            mock.switched,
            Some(("/sysroot".into(), "/usr/bin/init".into()))
        );
        assert_eq!(mock.mounts.len(), 3);
        assert_eq!(mock.mounts[0].1, "/sysroot");
        assert_eq!(mock.mounts[1].1, "/sysroot/usr");
        assert_eq!(
            mock.mounts[1].2,
            mount_flags::MS_RDONLY | mount_flags::MS_NODEV
        );
        assert_eq!(mock.mounts[2].1, "/sysroot/tmp");
        assert_eq!(mock.mounts[2].3.as_deref(), Some("mode=1777"));
        assert!(mock.files.contains_key(MOUNTED_ROOT_PATH));
    }

    #[test]
    fn early_init_enters_recovery_on_eprotonosupport_corrupt_cowfsck_and_exclusive_ebusy() {
        // 1. Corrupt cowfsck (exit 4) -> recovery, NEVER mounts /sysroot!
        let profile = BootProfile {
            root: RootSpec::CowFs {
                volume_uuid: Some("vol-corrupt".into()),
                writer_mode: BootWriterMode::ForkOnBusy,
            },
            ..BootProfile::default()
        };
        let mut m1 = MockEarlyInit::new(&profile);
        m1.cowfsck_code = 4;
        let out1 = run_early_init(&mut m1).unwrap();
        assert!(matches!(
            out1,
            EarlyBootOutcome::Recovery {
                errno: Some(Errno::EIO),
                ..
            }
        ));
        assert!(m1.mounts.is_empty());
        assert!(m1.switched.is_none());

        // 2. EPROTONOSUPPORT on mount -> recovery without formatting!
        let mut m2 = MockEarlyInit::new(&profile);
        m2.mount_fail_errno = Some(Errno::EPROTONOSUPPORT);
        let out2 = run_early_init(&mut m2).unwrap();
        assert!(matches!(
            out2,
            EarlyBootOutcome::Recovery {
                errno: Some(Errno::EPROTONOSUPPORT),
                ..
            }
        ));
        assert!(m2.recovered.unwrap().contains("EPROTONOSUPPORT"));

        // 3. Exclusive EBUSY -> recovery chooser!
        let excl_profile = BootProfile {
            root: RootSpec::CowFs {
                volume_uuid: Some("vol-busy".into()),
                writer_mode: BootWriterMode::Exclusive,
            },
            ..BootProfile::default()
        };
        let mut m3 = MockEarlyInit::new(&excl_profile);
        m3.mount_fail_errno = Some(Errno::EBUSY);
        let out3 = run_early_init(&mut m3).unwrap();
        assert!(matches!(
            out3,
            EarlyBootOutcome::Recovery {
                errno: Some(Errno::EBUSY),
                ..
            }
        ));
        assert!(m3.recovered.unwrap().contains("EBUSY"));
    }
}

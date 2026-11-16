//! `mount` and `umount` utilities.
use crate::findmnt::parse_mountinfo;
use abi::{mount_flags, umount_flags};
use os_core::cli::{
    parse,
    system::{Mount, Umount},
};
use std::io::{self, Write};
use std::path::Path;

pub(crate) trait MountBackend {
    fn read_mountinfo(&self) -> io::Result<String>;
    fn mount(
        &mut self,
        source: Option<&str>,
        target: &str,
        fstype: Option<&str>,
        flags: u64,
        data: Option<&str>,
    ) -> io::Result<()>;
    fn umount2(&mut self, target: &str, flags: u32) -> io::Result<()>;
}

struct OsMountBackend;

impl MountBackend for OsMountBackend {
    fn read_mountinfo(&self) -> io::Result<String> {
        std::fs::read_to_string("/proc/self/mountinfo")
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

    fn umount2(&mut self, target: &str, flags: u32) -> io::Result<()> {
        os_posix::umount2(Path::new(target), flags)
    }
}

pub(crate) fn parse_mount_options(options: &[String]) -> (u64, String) {
    let mut flags: u64 = 0;
    let mut fs_data: Vec<String> = Vec::new();
    for group in options {
        for raw in group.split(',') {
            let token = raw.trim();
            if token.is_empty() {
                continue;
            }
            match token {
                "ro" | "rdonly" => flags |= mount_flags::MS_RDONLY,
                "rw" => flags &= !mount_flags::MS_RDONLY,
                "nosuid" => flags |= mount_flags::MS_NOSUID,
                "suid" => flags &= !mount_flags::MS_NOSUID,
                "nodev" => flags |= mount_flags::MS_NODEV,
                "dev" => flags &= !mount_flags::MS_NODEV,
                "noexec" => flags |= mount_flags::MS_NOEXEC,
                "exec" => flags &= !mount_flags::MS_NOEXEC,
                "nosymfollow" => flags |= mount_flags::MS_NOSYMFOLLOW,
                "symfollow" => flags &= !mount_flags::MS_NOSYMFOLLOW,
                "sync" => flags |= mount_flags::MS_SYNCHRONOUS,
                "async" => flags &= !mount_flags::MS_SYNCHRONOUS,
                "dirsync" => flags |= mount_flags::MS_DIRSYNC,
                "remount" => flags |= mount_flags::MS_REMOUNT,
                "bind" => flags |= mount_flags::MS_BIND,
                "rbind" => flags |= mount_flags::MS_BIND | mount_flags::MS_REC,
                "move" => flags |= mount_flags::MS_MOVE,
                "noatime" => flags |= mount_flags::MS_NOATIME,
                "atime" => flags &= !mount_flags::MS_NOATIME,
                "nodiratime" => flags |= mount_flags::MS_NODIRATIME,
                "diratime" => flags &= !mount_flags::MS_NODIRATIME,
                "relatime" => flags |= mount_flags::MS_RELATIME,
                "norelatime" => flags &= !mount_flags::MS_RELATIME,
                "strictatime" => flags |= mount_flags::MS_STRICTATIME,
                "nostrictatime" => flags &= !mount_flags::MS_STRICTATIME,
                "lazytime" => flags |= mount_flags::MS_LAZYTIME,
                "nolazytime" => flags &= !mount_flags::MS_LAZYTIME,
                "silent" => flags |= mount_flags::MS_SILENT,
                "loud" => flags &= !mount_flags::MS_SILENT,
                "private" => flags |= mount_flags::MS_PRIVATE,
                "rprivate" => flags |= mount_flags::MS_PRIVATE | mount_flags::MS_REC,
                "shared" => flags |= mount_flags::MS_SHARED,
                "rshared" => flags |= mount_flags::MS_SHARED | mount_flags::MS_REC,
                "slave" => flags |= mount_flags::MS_SLAVE,
                "rslave" => flags |= mount_flags::MS_SLAVE | mount_flags::MS_REC,
                "unbindable" => flags |= mount_flags::MS_UNBINDABLE,
                "runbindable" => flags |= mount_flags::MS_UNBINDABLE | mount_flags::MS_REC,
                "defaults" => {
                    flags &= !(mount_flags::MS_RDONLY
                        | mount_flags::MS_NOSUID
                        | mount_flags::MS_NODEV
                        | mount_flags::MS_NOEXEC
                        | mount_flags::MS_SYNCHRONOUS);
                }
                other => fs_data.push(other.to_string()),
            }
        }
    }
    (flags, fs_data.join(","))
}

fn check_unsupported_mount_flags(args: &[String]) -> Result<(), String> {
    for arg in args {
        if arg == "--" {
            break;
        }
        for bad in [
            "-a",
            "--all",
            "-L",
            "--label",
            "-U",
            "--uuid",
            "-N",
            "--namespace",
            "--fstab",
            "-T",
            "-f",
            "--fake",
        ] {
            if arg == bad
                || (bad.starts_with("--") && arg.starts_with(&format!("{bad}=")))
                || (bad.len() == 2
                    && arg.starts_with('-')
                    && !arg.starts_with("--")
                    && arg[1..].starts_with(&bad[1..]))
            {
                return Err(format!("mount: unsupported option '{arg}'"));
            }
        }
    }
    Ok(())
}

fn check_unsupported_umount_flags(args: &[String]) -> Result<(), String> {
    for arg in args {
        if arg == "--" {
            break;
        }
        for bad in [
            "-a",
            "--all",
            "-R",
            "--recursive",
            "-O",
            "--test-opts",
            "-t",
            "--types",
            "-N",
            "--namespace",
        ] {
            if arg == bad
                || (bad.starts_with("--") && arg.starts_with(&format!("{bad}=")))
                || (bad.len() == 2
                    && arg.starts_with('-')
                    && !arg.starts_with("--")
                    && arg[1..].starts_with(&bad[1..]))
            {
                return Err(format!("umount: unsupported option '{arg}'"));
            }
        }
    }
    Ok(())
}

fn matches_type_filter(fstype: &str, filter: &str) -> bool {
    filter
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .any(|item| item == fstype)
}

pub(crate) fn run_mount_with(
    args: &[String],
    backend: &mut impl MountBackend,
) -> (String, Vec<String>, i32) {
    if let Err(msg) = check_unsupported_mount_flags(args) {
        return (String::new(), vec![msg], 2);
    }
    let parsed = match parse::<Mount>(args) {
        Ok(m) => m,
        Err(msg) => return (String::new(), vec![msg], 2),
    };

    let (mut flags, data) = parse_mount_options(&parsed.options);
    if parsed.read_only {
        flags |= mount_flags::MS_RDONLY;
    }
    if parsed.read_write {
        flags &= !mount_flags::MS_RDONLY;
    }
    if parsed.bind {
        flags |= mount_flags::MS_BIND;
    }
    if parsed.rbind {
        flags |= mount_flags::MS_BIND | mount_flags::MS_REC;
    }
    if parsed.move_mount {
        flags |= mount_flags::MS_MOVE;
    }
    if parsed.make_private {
        flags |= mount_flags::MS_PRIVATE;
    }
    if parsed.make_shared {
        flags |= mount_flags::MS_SHARED;
    }
    if parsed.make_slave {
        flags |= mount_flags::MS_SLAVE;
    }
    if parsed.make_unbindable {
        flags |= mount_flags::MS_UNBINDABLE;
    }
    if parsed.make_rprivate {
        flags |= mount_flags::MS_PRIVATE | mount_flags::MS_REC;
    }
    if parsed.make_rshared {
        flags |= mount_flags::MS_SHARED | mount_flags::MS_REC;
    }
    if parsed.make_rslave {
        flags |= mount_flags::MS_SLAVE | mount_flags::MS_REC;
    }
    if parsed.make_runbindable {
        flags |= mount_flags::MS_UNBINDABLE | mount_flags::MS_REC;
    }

    let propagation_mask = mount_flags::MS_PRIVATE
        | mount_flags::MS_SHARED
        | mount_flags::MS_SLAVE
        | mount_flags::MS_UNBINDABLE;
    let has_action = flags != 0
        || !parsed.options.is_empty()
        || parsed.read_only
        || parsed.read_write
        || parsed.bind
        || parsed.rbind
        || parsed.move_mount;

    // Listing mode: `mount` or `mount -t <fstype>` with zero operands and no action flags.
    if parsed.operands.is_empty() && !has_action {
        let text = match backend.read_mountinfo() {
            Ok(t) => t,
            Err(err) => {
                return (
                    String::new(),
                    vec![format!("mount: cannot read /proc/self/mountinfo: {err}")],
                    1,
                );
            }
        };
        let mut out = String::new();
        for rec in parse_mountinfo(&text) {
            if let Some(filter) = parsed.types.as_deref()
                && !matches_type_filter(&rec.fstype, filter)
            {
                continue;
            }
            out.push_str(&format!(
                "{} on {} type {} ({})\n",
                rec.display_source(),
                rec.target,
                rec.fstype,
                rec.combined_options()
            ));
        }
        return (out, Vec::new(), 0);
    }

    let data_opt = (!data.is_empty()).then_some(data.as_str());
    let is_propagation_only = (flags & propagation_mask) != 0
        && (flags & (mount_flags::MS_BIND | mount_flags::MS_MOVE | mount_flags::MS_REMOUNT)) == 0
        && parsed.types.is_none();

    let (source, target, fstype): (Option<&str>, &str, Option<&str>) = if is_propagation_only {
        if parsed.operands.len() != 1 {
            return (
                String::new(),
                vec!["mount: propagation operations require a single TARGET".into()],
                2,
            );
        }
        (None, &parsed.operands[0], None)
    } else if (flags & (mount_flags::MS_BIND | mount_flags::MS_MOVE)) != 0
        && (flags & mount_flags::MS_REMOUNT) == 0
    {
        if parsed.operands.len() != 2 {
            return (
                String::new(),
                vec!["mount: bind and move operations require SOURCE and TARGET".into()],
                2,
            );
        }
        (Some(&parsed.operands[0]), &parsed.operands[1], None)
    } else if (flags & mount_flags::MS_REMOUNT) != 0 && parsed.operands.len() == 1 {
        (None, &parsed.operands[0], parsed.types.as_deref())
    } else {
        match parsed.operands.as_slice() {
            [src, tgt] => {
                let inferred = parsed.types.as_deref().or_else(|| {
                    matches!(src.as_str(), "tmpfs" | "proc" | "devpts" | "devtmpfs")
                        .then_some(src.as_str())
                });
                (Some(src.as_str()), tgt.as_str(), inferred)
            }
            [only] => {
                return (
                    String::new(),
                    vec![format!(
                        "mount: {only}: can't find in /etc/fstab (specify SOURCE and TARGET)"
                    )],
                    1,
                );
            }
            _ => {
                return (
                    String::new(),
                    vec![
                        "mount: missing mount source and target; mount -h shows how to use it"
                            .into(),
                    ],
                    2,
                );
            }
        }
    };

    if let Err(err) = backend.mount(source, target, fstype, flags, data_opt) {
        return (String::new(), vec![format!("mount: {target}: {err}")], 32);
    }
    (String::new(), Vec::new(), 0)
}

pub(crate) fn run_umount_with(
    args: &[String],
    backend: &mut impl MountBackend,
) -> (Vec<String>, i32) {
    if let Err(msg) = check_unsupported_umount_flags(args) {
        return (vec![msg], 2);
    }
    let parsed = match parse::<Umount>(args) {
        Ok(u) => u,
        Err(msg) => return (vec![msg], 2),
    };
    let mut flags: u32 = 0;
    if parsed.lazy {
        flags |= umount_flags::MNT_DETACH;
    }
    if parsed.force {
        flags |= umount_flags::MNT_FORCE;
    }
    if parsed.no_canonicalize {
        flags |= umount_flags::UMOUNT_NOFOLLOW;
    }
    let mut errs = Vec::new();
    let mut status = 0;
    for target in &parsed.targets {
        if let Err(err) = backend.umount2(target, flags) {
            errs.push(format!("umount: {target}: {err}"));
            status = 32;
        }
    }
    (errs, status)
}

pub fn run_mount(args: &[String]) -> i32 {
    let mut backend = OsMountBackend;
    let (out, errs, code) = run_mount_with(args, &mut backend);
    if !out.is_empty() && io::stdout().write_all(out.as_bytes()).is_err() {
        return 1;
    }
    for err in errs {
        eprintln!("{err}");
    }
    code
}

pub fn run_umount(args: &[String]) -> i32 {
    let mut backend = OsMountBackend;
    let (errs, code) = run_umount_with(args, &mut backend);
    for err in errs {
        eprintln!("{err}");
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct RecordedMount {
        source: Option<String>,
        target: String,
        fstype: Option<String>,
        flags: u64,
        data: Option<String>,
    }

    #[derive(Default)]
    struct MockMountBackend {
        mountinfo: String,
        mounts: Vec<RecordedMount>,
        umounts: Vec<(String, u32)>,
        fail_errno: Option<i32>,
    }

    impl MountBackend for MockMountBackend {
        fn read_mountinfo(&self) -> io::Result<String> {
            Ok(self.mountinfo.clone())
        }

        fn mount(
            &mut self,
            source: Option<&str>,
            target: &str,
            fstype: Option<&str>,
            flags: u64,
            data: Option<&str>,
        ) -> io::Result<()> {
            if let Some(code) = self.fail_errno {
                return Err(io::Error::from_raw_os_error(code));
            }
            self.mounts.push(RecordedMount {
                source: source.map(ToOwned::to_owned),
                target: target.to_string(),
                fstype: fstype.map(ToOwned::to_owned),
                flags,
                data: data.map(ToOwned::to_owned),
            });
            Ok(())
        }

        fn umount2(&mut self, target: &str, flags: u32) -> io::Result<()> {
            if let Some(code) = self.fail_errno {
                return Err(io::Error::from_raw_os_error(code));
            }
            self.umounts.push((target.to_string(), flags));
            Ok(())
        }
    }

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|v| (*v).to_string()).collect()
    }

    #[test]
    fn mount_option_parser_combines_vfs_flags_and_fs_data_in_order() {
        let (flags, data) = parse_mount_options(&s(&[
            "ro,nosuid,nodev,noexec,size=64m,rw,ro,mode=0755,nosymfollow",
        ]));
        assert_eq!(
            flags,
            mount_flags::MS_RDONLY
                | mount_flags::MS_NOSUID
                | mount_flags::MS_NODEV
                | mount_flags::MS_NOEXEC
                | mount_flags::MS_NOSYMFOLLOW
        );
        assert_eq!(data, "size=64m,mode=0755");
    }

    #[test]
    fn mount_dispatches_list_tmpfs_bind_remount_propagation_and_rejects_fstab_flags() {
        let mut backend = MockMountBackend {
            mountinfo: "1 1 0:1 / / rw - r2 r2 rw\n2 1 0:2 / /mnt rw - tmpfs scratch rw,size=4m\n"
                .into(),
            ..Default::default()
        };

        let (listed, errs, code) = run_mount_with(&s(&["-t", "tmpfs"]), &mut backend);
        assert_eq!(code, 0, "errs={errs:?}");
        assert_eq!(listed, "scratch on /mnt type tmpfs (rw,size=4m)\n");

        let (_, errs, code) = run_mount_with(
            &s(&["-t", "tmpfs", "-o", "noexec,size=16m", "scratch", "/mnt"]),
            &mut backend,
        );
        assert_eq!(code, 0, "errs={errs:?}");
        assert_eq!(
            backend.mounts.pop().unwrap(),
            RecordedMount {
                source: Some("scratch".into()),
                target: "/mnt".into(),
                fstype: Some("tmpfs".into()),
                flags: mount_flags::MS_NOEXEC,
                data: Some("size=16m".into()),
            }
        );

        let (_, _, code) = run_mount_with(&s(&["--rbind", "/src", "/dst"]), &mut backend);
        assert_eq!(code, 0);
        assert_eq!(
            backend.mounts.pop().unwrap(),
            RecordedMount {
                source: Some("/src".into()),
                target: "/dst".into(),
                fstype: None,
                flags: mount_flags::MS_BIND | mount_flags::MS_REC,
                data: None,
            }
        );

        let (_, _, code) = run_mount_with(&s(&["-o", "remount,ro", "/mnt"]), &mut backend);
        assert_eq!(code, 0);
        assert_eq!(
            backend.mounts.pop().unwrap(),
            RecordedMount {
                source: None,
                target: "/mnt".into(),
                fstype: None,
                flags: mount_flags::MS_REMOUNT | mount_flags::MS_RDONLY,
                data: None,
            }
        );

        let (_, _, code) = run_mount_with(&s(&["--make-shared", "/mnt"]), &mut backend);
        assert_eq!(code, 0);
        assert_eq!(
            backend.mounts.pop().unwrap(),
            RecordedMount {
                source: None,
                target: "/mnt".into(),
                fstype: None,
                flags: mount_flags::MS_SHARED,
                data: None,
            }
        );

        for unsupported in ["-a", "-L", "-U", "-N", "--fstab", "-f"] {
            let (_, errs, bad_code) = run_mount_with(&s(&[unsupported]), &mut backend);
            assert_eq!(bad_code, 2, "flag {unsupported}");
            assert!(errs[0].contains("unsupported option"), "errs={errs:?}");
        }
    }

    #[test]
    fn umount_supports_lazy_force_no_canonicalize_multiple_targets_and_rejects_unsupported() {
        let mut backend = MockMountBackend::default();
        let (errs, code) =
            run_umount_with(&s(&["-l", "-f", "-c", "/mnt/a", "/mnt/b"]), &mut backend);
        assert_eq!(code, 0, "errs={errs:?}");
        let expected_flags =
            umount_flags::MNT_DETACH | umount_flags::MNT_FORCE | umount_flags::UMOUNT_NOFOLLOW;
        assert_eq!(
            backend.umounts,
            vec![
                ("/mnt/a".into(), expected_flags),
                ("/mnt/b".into(), expected_flags),
            ]
        );

        for unsupported in ["-a", "-R", "-O", "-t", "-N"] {
            let (errs, bad_code) = run_umount_with(&s(&[unsupported, "/mnt"]), &mut backend);
            assert_eq!(bad_code, 2, "flag {unsupported}");
            assert!(errs[0].contains("unsupported option"), "errs={errs:?}");
        }
    }
}

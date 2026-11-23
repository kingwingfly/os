//! The programs of /usr/bin that the page runs as processes of their own, built for
//! wasm32-wasip1 (uutils' coreutils, crates/coreutils, one binary as busybox is), in its WASI
//! engine (web/wasi/). Explicit executable paths always run their image through execve. Bare
//! external names resolve through PATH (default /usr/bin). Shell builtins and browser actions
//! are separate from this installed catalog.
//! `coreutils NAME` invokes the multicall binary with NAME as its own argument.

/// The utilities coreutils has, as crates/coreutils builds them: uutils', and `syscall`, which
/// makes the kernel's own calls through the engine's `os.sys`.
pub const PROGRAMS: &[&str] = &[
    "arch",
    "base32",
    "base64",
    "basename",
    "basenc",
    "cat",
    "cksum",
    "b2sum",
    "md5sum",
    "nice",
    "sha1sum",
    "sha224sum",
    "sha256sum",
    "sha384sum",
    "sha512sum",
    "comm",
    "csplit",
    "cut",
    "date",
    "dd",
    "dir",
    "dircolors",
    "dirname",
    "echo",
    "expand",
    "expr",
    "factor",
    "false",
    "fmt",
    "fold",
    "head",
    "hostid",
    "join",
    "link",
    "ln",
    "ls",
    "mkdir",
    "mktemp",
    "nl",
    "numfmt",
    "od",
    "paste",
    "pathchk",
    "pr",
    "printenv",
    "printf",
    "ptx",
    "pwd",
    "readlink",
    "realpath",
    "rmdir",
    "seq",
    "shred",
    "shuf",
    "sleep",
    "sort",
    "split",
    "sum",
    "tail",
    "tee",
    "test",
    "touch",
    "tr",
    "true",
    "truncate",
    "tsort",
    "tty",
    "stty",
    "uname",
    "unexpand",
    "uniq",
    "unlink",
    "vdir",
    "wc",
    "yes",
    "nproc",
    "syscall",
];

/// Those that may change files, after which the shell looks at its directory again.
const WRITING: &[&str] = &[
    "cp",
    "mv",
    "rm",
    "rmdir",
    "mkdir",
    "touch",
    "ln",
    "link",
    "unlink",
    "truncate",
    "shred",
    "split",
    "csplit",
    "tee",
    "dd",
    "mktemp",
    "zip",
    "unzip",
    "tar",
    "faststart",
    "imagectl",
    "providerctl",
    "mount",
    "umount",
    "chroot",
    "switch_root",
    "mkfs.cowfs",
    "cowfs",
    "passwd",
    "useradd",
    "usermod",
    "userdel",
    "groupadd",
    "groupmod",
    "groupdel",
    "service",
];

/// The utility of coreutils named `name`.
pub fn program(name: &str) -> Option<&'static str> {
    PROGRAMS.iter().copied().find(|program| *program == name)
}

/// Whether the utility `name` may change files.
pub fn writes(name: &str) -> bool {
    WRITING.contains(&name)
}

/// Installed OS-native programs, compiled from shared user-space code.
pub const UTILITIES: &[&str] = &[
    "stat",
    "df",
    "chmod",
    "chown",
    "chgrp",
    "getfacl",
    "setfacl",
    "getfattr",
    "setfattr",
    "ps",
    "kill",
    "whoami",
    "id",
    "groups",
    "users",
    "useradd",
    "usermod",
    "userdel",
    "groupadd",
    "groupmod",
    "groupdel",
    "grep",
    "cp",
    "mv",
    "rm",
    "fd",
    "xargs",
    "zip",
    "unzip",
    "tar",
    "faststart",
    "imagectl",
    "providerctl",
    "exportctl",
    "mount",
    "umount",
    "findmnt",
    "mountctl",
    "chroot",
    "switch_root",
    "cowfsck",
    "mkfs.cowfs",
    "cowfs",
    "losetup",
    "su",
    "sudo",
    "passwd",
    "login",
    "newgrp",
    "service",
];

/// The installed multicall image that owns a program; UI actions have no executable image.
pub fn image(name: &str) -> Option<&'static str> {
    if name == "init" {
        Some("init")
    } else if name == "mountd" {
        Some("mountd")
    } else if name == "exportd" {
        Some("exportd")
    } else if name == "early_init" {
        Some("early_init")
    } else if name == "supervise" {
        Some("supervise")
    } else if name == "coreutils" || PROGRAMS.contains(&name) {
        Some("coreutils")
    } else if name == "utilities" || UTILITIES.contains(&name) {
        Some("utilities")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_list_is_the_binary_s() {
        let main = include_str!("../../coreutils/src/main.rs");
        let listed = main
            .split("pub const UTILITIES: &[&str] = &[")
            .nth(1)
            .and_then(|rest| rest.split("];").next())
            .unwrap();
        let built: Vec<&str> = listed
            .split(',')
            .map(|name| name.trim().trim_matches('"'))
            .filter(|name| !name.is_empty())
            .collect();
        assert_eq!(built, super::PROGRAMS);
        assert_eq!(super::program("cut"), Some("cut"));
        assert_eq!(super::program("zip"), None);
    }

    #[test]
    fn mount_and_chroot_utilities_are_registered_and_classified() {
        for util in ["mount", "umount", "findmnt", "chroot"] {
            assert!(super::UTILITIES.contains(&util), "missing {util}");
            assert_eq!(super::image(util), Some("utilities"));
        }
        assert!(super::writes("mount"));
        assert!(super::writes("umount"));
        assert!(super::writes("chroot"));
        assert!(!super::writes("findmnt"));
    }

    #[test]
    fn stage1_boot_utilities_are_registered() {
        for util in ["switch_root", "cowfsck", "mkfs.cowfs", "cowfs", "losetup"] {
            assert!(super::UTILITIES.contains(&util), "missing {util}");
            assert_eq!(super::image(util), Some("utilities"));
        }
        assert!(super::writes("switch_root"));
        assert!(super::writes("mkfs.cowfs"));
        assert!(super::writes("cowfs"));
        assert!(!super::writes("cowfsck"));
        assert!(!super::writes("losetup"));
        assert_eq!(super::image("early_init"), Some("early_init"));
    }

    #[test]
    fn local_account_and_service_utilities_are_registered() {
        for util in ["su", "sudo", "passwd", "login", "newgrp", "service"] {
            assert!(super::UTILITIES.contains(&util), "missing {util}");
            assert_eq!(super::image(util), Some("utilities"));
        }
        assert!(super::writes("passwd"));
        assert!(super::writes("service"));
        assert!(super::writes("useradd"));
        assert!(!super::writes("su"));
        assert!(!super::writes("sudo"));
    }
}

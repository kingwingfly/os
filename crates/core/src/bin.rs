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
];

/// The installed multicall image that owns a program; UI actions have no executable image.
pub fn image(name: &str) -> Option<&'static str> {
    if name == "coreutils" || PROGRAMS.contains(&name) {
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
}

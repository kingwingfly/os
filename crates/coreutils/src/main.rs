//! uutils' coreutils as one program, as busybox is one: what it is run as (its first argument, as
//! a link's name would be) is the utility it runs. It starts in the working directory the shell
//! gives it as `PWD`, as WASI's libc starts every program at `/`.
use std::ffi::OsString;
use std::path::Path;

/// The utilities, as uutils builds them for WebAssembly (its `feat_wasm`).
pub const UTILITIES: &[&str] = &[
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
    "cp",
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
    "mv",
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
    "rm",
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

fn main() {
    if let Some(pwd) = std::env::var_os("PWD") {
        let _ = std::env::set_current_dir(pwd);
    }
    let mut args: Vec<OsString> = std::env::args_os().collect();
    let mut name = args
        .first()
        .and_then(|first| Path::new(first).file_name())
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_string();
    // Run as `coreutils UTILITY ...`: the utility is the next argument.
    if name == "coreutils" {
        if args.len() < 2 {
            println!(
                "coreutils (uutils 0.12.0, multi-call binary)\n\nUsage: coreutils UTILITY [ARGUMENT]...\n\n{}",
                UTILITIES.join(" ")
            );
            std::process::exit(0);
        }
        args.remove(0);
        name = args[0].to_string_lossy().into_owned();
    }
    // Their messages are in Fluent's files, which each utility loads as it starts (uutils').
    let canonical = match name.as_str() {
        "syscall" => "",
        "dir" | "vdir" => "ls",
        other => other,
    };
    if UTILITIES.contains(&name.as_str())
        && !canonical.is_empty()
        && let Err(error) = uucore::locale::setup_localization(canonical)
    {
        eprintln!("{name}: {error}");
        std::process::exit(99);
    }
    let args = args.into_iter();
    let status = match name.as_str() {
        "syscall" => syscall(args),
        "arch" => uu_arch::uumain(args),
        "base32" => uu_base32::uumain(args),
        "base64" => uu_base64::uumain(args),
        "basename" => uu_basename::uumain(args),
        "basenc" => uu_basenc::uumain(args),
        "cat" => uu_cat::uumain(args),
        "cksum" => uu_cksum::uumain(args),
        "b2sum" => uu_b2sum::uumain(args),
        "md5sum" => uu_md5sum::uumain(args),
        "nice" => uu_nice::uumain(args),
        "sha1sum" => uu_sha1sum::uumain(args),
        "sha224sum" => uu_sha224sum::uumain(args),
        "sha256sum" => uu_sha256sum::uumain(args),
        "sha384sum" => uu_sha384sum::uumain(args),
        "sha512sum" => uu_sha512sum::uumain(args),
        "comm" => uu_comm::uumain(args),
        "cp" => uu_cp::uumain(args),
        "csplit" => uu_csplit::uumain(args),
        "cut" => uu_cut::uumain(args),
        "date" => uu_date::uumain(args),
        "dd" => uu_dd::uumain(args),
        "dir" => uu_dir::uumain(args),
        "dircolors" => uu_dircolors::uumain(args),
        "dirname" => uu_dirname::uumain(args),
        "echo" => uu_echo::uumain(args),
        "expand" => uu_expand::uumain(args),
        "expr" => uu_expr::uumain(args),
        "factor" => uu_factor::uumain(args),
        "false" => uu_false::uumain(args),
        "fmt" => uu_fmt::uumain(args),
        "fold" => uu_fold::uumain(args),
        "head" => uu_head::uumain(args),
        "hostid" => uu_hostid::uumain(args),
        "join" => uu_join::uumain(args),
        "link" => uu_link::uumain(args),
        "ln" => uu_ln::uumain(args),
        "ls" => uu_ls::uumain(args),
        "mkdir" => uu_mkdir::uumain(args),
        "mktemp" => uu_mktemp::uumain(args),
        "mv" => uu_mv::uumain(args),
        "nl" => uu_nl::uumain(args),
        "numfmt" => uu_numfmt::uumain(args),
        "od" => uu_od::uumain(args),
        "paste" => uu_paste::uumain(args),
        "pathchk" => uu_pathchk::uumain(args),
        "pr" => uu_pr::uumain(args),
        "printenv" => uu_printenv::uumain(args),
        "printf" => uu_printf::uumain(args),
        "ptx" => uu_ptx::uumain(args),
        "pwd" => uu_pwd::uumain(args),
        "readlink" => uu_readlink::uumain(args),
        "realpath" => uu_realpath::uumain(args),
        "rm" => uu_rm::uumain(args),
        "rmdir" => uu_rmdir::uumain(args),
        "seq" => uu_seq::uumain(args),
        "shred" => uu_shred::uumain(args),
        "shuf" => uu_shuf::uumain(args),
        "sleep" => uu_sleep::uumain(args),
        "sort" => uu_sort::uumain(args),
        "split" => uu_split::uumain(args),
        "sum" => uu_sum::uumain(args),
        "tail" => uu_tail::uumain(args),
        "tee" => uu_tee::uumain(args),
        "test" => uu_test::uumain(args),
        "touch" => uu_touch::uumain(args),
        "tr" => uu_tr::uumain(args),
        "true" => uu_true::uumain(args),
        "truncate" => uu_truncate::uumain(args),
        "tsort" => uu_tsort::uumain(args),
        "tty" => uu_tty::uumain(args),
        "uname" => uu_uname::uumain(args),
        "unexpand" => uu_unexpand::uumain(args),
        "uniq" => uu_uniq::uumain(args),
        "unlink" => uu_unlink::uumain(args),
        "vdir" => uu_vdir::uumain(args),
        "wc" => uu_wc::uumain(args),
        "yes" => uu_yes::uumain(args),
        "nproc" => uu_nproc::uumain(args),
        _ => {
            eprintln!("coreutils: {name}: no such utility");
            127
        }
    };
    std::process::exit(status);
}

// The kernel's own calls, which WASI has no words for, as this system's engine gives them: a
// batch (abi's `calls`, as JSON) sent as it is, and its reply copied where the program says.
#[cfg(target_os = "wasi")]
#[link(wasm_import_module = "terminal")]
unsafe extern "C" {
    fn sys(calls: *const u8, len: usize) -> usize;
    fn reply(to: *mut u8);
}

/// syscall CALLS: make the system calls CALLS, a JSON list of them, as one batch, through
/// `terminal.sys`, and write what each gave: `syscall '[{"stat":{"path":"/"}}]'`.
fn syscall(mut args: impl Iterator<Item = OsString>) -> i32 {
    let _ = args.next();
    let Some(calls) = args.next().and_then(|calls| calls.into_string().ok()) else {
        eprintln!("syscall: usage: syscall CALLS (a JSON list of system calls)");
        return 1;
    };
    #[cfg(target_os = "wasi")]
    {
        // SAFETY: the engine reads `calls` and writes `len` bytes into `out`, which has them.
        let len = unsafe { sys(calls.as_ptr(), calls.len()) };
        let mut out = vec![0u8; len];
        unsafe { reply(out.as_mut_ptr()) };
        println!("{}", String::from_utf8_lossy(&out));
        0
    }
    #[cfg(not(target_os = "wasi"))]
    {
        eprintln!("syscall: {calls}: only this system's engine makes system calls");
        1
    }
}

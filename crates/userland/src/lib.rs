//! User space (owner's design, 2026-10-29: the page is user space, its requests are system
//! calls): the terminal's programs, as coreutils are, each over the system calls (abi) and
//! nothing else. What they take, print and fail with is GNU's: `rm: cannot remove 'x':
//! Permission denied`, nothing printed on success but with -v. Whether something may be done
//! is never theirs to decide: the kernel says, call by call; they walk trees, a level a batch.
//!
//! The page runs them (crates/frontend), as the shell's commands; tests run them over the
//! kernel in memory.
mod accounts;
mod copy;
mod files;
mod find;
pub mod io;
mod names;
mod perms;
pub mod procs;
pub mod sys;
pub mod time;
pub mod walk;

pub use io::{Ask, Io, View};
pub use names::Names;
pub use sys::Sys;

/// The programs of user space.
pub const PROGRAMS: &[&str] = &[
    "ls", "stat", "mkdir", "rmdir", "rm", "mv", "cp", "ln", "readlink", "realpath", "touch", "df",
    "chmod", "chown", "chgrp", "getfacl", "setfacl", "getfattr", "setfattr", "fd", "ps", "kill",
    "whoami", "id", "groups", "users", "useradd", "usermod", "userdel", "groupadd", "groupmod",
    "groupdel",
];

/// Run the program `io.args[0]`, with what `io` gives it: its exit status, as a shell sees it;
/// None if user space has no such program.
pub async fn run(sys: &impl Sys, io: &mut Io<'_>) -> Option<i32> {
    let name = io.args.first()?.clone();
    let status = match name.as_str() {
        "ls" => files::ls(sys, io).await,
        "stat" => files::stat_program(sys, io).await,
        "mkdir" => files::mkdir(sys, io).await,
        "rmdir" => files::rmdir(sys, io).await,
        "rm" => files::rm(sys, io).await,
        "mv" => files::mv(sys, io).await,
        "cp" => copy::cp(sys, io).await,
        "ln" => files::ln(sys, io).await,
        "readlink" => files::readlink(sys, io, false).await,
        "realpath" => files::readlink(sys, io, true).await,
        "touch" => files::touch(sys, io).await,
        "df" => files::df(sys, io).await,
        "chmod" => perms::chmod(sys, io).await,
        "chown" => perms::chown(sys, io, false).await,
        "chgrp" => perms::chown(sys, io, true).await,
        "getfacl" => perms::getfacl(sys, io).await,
        "setfacl" => perms::setfacl(sys, io).await,
        "getfattr" => perms::getfattr(sys, io).await,
        "setfattr" => perms::setfattr(sys, io).await,
        "fd" => find::fd(sys, io).await,
        "ps" => procs::ps(sys, io).await,
        "kill" => procs::kill(sys, io).await,
        "whoami" => accounts::whoami(sys, io).await,
        "id" => accounts::id(sys, io).await,
        "groups" => accounts::groups_program(sys, io).await,
        "users" => accounts::users(sys, io).await,
        "useradd" => accounts::useradd(sys, io).await,
        "usermod" => accounts::usermod(sys, io).await,
        "userdel" => accounts::userdel(sys, io).await,
        "groupadd" => accounts::groupadd(sys, io).await,
        "groupmod" => accounts::groupmod(sys, io).await,
        "groupdel" => accounts::groupdel(sys, io).await,
        _ => return None,
    };
    Some(status)
}

pub use files::entries;

#[cfg(test)]
mod tests;

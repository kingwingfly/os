//! The terminal itself: help, man and clear.

use clap::Parser;

use super::{Manual, Section};

/// supervise foreground services from a versioned JSON unit file
///
/// Runs as the caller, with explicit argv and environment, dependency ordering, bounded
/// restarts and TERM/CONT shutdown followed by KILL after each stop timeout. Standard input
/// is /dev/null; bounded per-unit capture forwards stdout/stderr to this command.
/// Cgroup cleanup contains forked and detached descendants. Optional journals retain
/// bounded output and lifecycle history. Browser host lifetime applies.
#[derive(Parser, Debug)]
#[command(name = "supervise")]
pub struct Supervise {
    /// save bounded per-unit JSONL snapshots in a new private directory
    #[arg(long, value_name = "DIRECTORY", value_hint = clap::ValueHint::DirPath)]
    pub journal: Option<String>,
    /// validate the whole file without launching any service
    #[arg(long)]
    pub check: bool,
    #[arg(value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
    pub file: String,
}
impl Manual for Supervise {
    const SECTION: Section = Section::Terminal;
    const NEEDS: &'static str = "Read the unit file and execute its commands as the caller. Unit metadata grants no additional permissions.";
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        (
            "supervise --check services.json",
            "validate names, bounds and dependencies",
        ),
        (
            "supervise services.json",
            "run services until they exit or the supervisor receives TERM, INT or HUP",
        ),
    ];
    const SEE: &'static [&'static str] = &["ps", "kill"];
}

/// list the commands
///
/// Lists the commands by section, a line each, or shows COMMAND's help, as COMMAND -h does; man
/// COMMAND opens its manual page.
#[derive(Parser, Debug)]
#[command(name = "help")]
pub struct Help {
    #[arg(value_name = "COMMAND")]
    pub command: Option<String>,
}
impl Manual for Help {
    const SECTION: Section = Section::Terminal;
    const SEE: &'static [&'static str] = &["man"];
}

/// read the manual
///
/// Opens COMMAND's manual page, or, without one, the index and the overview of permissions,
/// links, pipes and keys. It describes what this terminal does, not a whole Linux system.
#[derive(Parser, Debug)]
#[command(name = "man")]
pub struct Man {
    #[arg(value_name = "COMMAND")]
    pub command: Option<String>,
}
impl Manual for Man {
    const SECTION: Section = Section::Terminal;
    const EXAMPLES: &'static [(&'static str, &'static str)] =
        &[("man ln", "one page"), ("man", "the index")];
    const SEE: &'static [&'static str] = &["help"];
}

/// clear the terminal
///
/// Clears this tab's output; nothing else changes.
#[derive(Parser, Debug)]
#[command(name = "clear")]
pub struct Clear {}
impl Manual for Clear {
    const SECTION: Section = Section::Terminal;
}

/// show or change terminal settings
///
/// Without settings, shows the terminal's modes and size. Supports sane, raw, cooked,
/// echo, icanon, isig, tostop, opost and onlcr (prefix a mode with - to disable it), size,
/// and min N, time N, rows N or cols N. Settings belong to this terminal tab.
#[derive(Parser, Debug)]
#[command(name = "stty")]
pub struct Stty {
    /// show all supported settings
    #[arg(short = 'a', long)]
    pub all: bool,
    #[arg(value_name = "SETTING", allow_hyphen_values = true)]
    pub settings: Vec<String>,
}
impl Manual for Stty {
    const SECTION: Section = Section::Terminal;
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("stty -a", "show modes"),
        ("stty sane", "restore canonical input and echo"),
    ];
    const SEE: &'static [&'static str] = &["tty"];
}

/// set environment variables for programs launched from this terminal
///
/// Each argument is NAME=VALUE. With no arguments, lists variables explicitly exported in
/// this tab. PATH controls executable lookup; existing processes retain their environment.
#[derive(Parser, Debug)]
#[command(name = "export")]
pub struct Export {
    #[arg(value_name = "NAME=VALUE")]
    pub assignments: Vec<String>,
}
impl Manual for Export {
    const SECTION: Section = Section::Terminal;
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[(
        "export PATH=/guest/bin:/usr/bin",
        "choose executable search directories",
    )];
}

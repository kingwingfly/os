//! The terminal itself: help, man and clear.

use clap::Parser;

use super::{Manual, Section};

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
/// echo, icanon, isig, opost and onlcr (prefix a mode with - to disable it), size,
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

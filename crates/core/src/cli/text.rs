//! Text: echo, the filters cat, head, tail, grep, wc, sort and uniq, and xargs.

use clap::{Parser, ValueHint};

use super::{Manual, Section};

/// write text
///
/// Writes TEXT, its words separated by spaces, and a newline unless -n. What follows the first
/// word is written as it is, options or not.
#[derive(Parser, Debug)]
#[command(name = "echo")]
pub struct Echo {
    /// no newline at the end
    #[arg(short = 'n')]
    pub no_newline: bool,
    #[arg(
        value_name = "TEXT",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    pub words: Vec<String>,
}
impl Manual for Echo {
    const SECTION: Section = Section::Text;
    const EXAMPLES: &'static [(&'static str, &'static str)] =
        &[("echo hello | wc -c", "count bytes")];
    const SEE: &'static [&'static str] = &["cat"];
}

/// write files one after another
///
/// Writes each FILE, or standard input; - stands for standard input. Files are read as UTF-8
/// text, up to 10 MB each; links are followed.
#[derive(Parser, Debug)]
#[command(name = "cat")]
pub struct Cat {
    #[arg(value_hint = ValueHint::AnyPath, value_name = "FILE")]
    pub files: Vec<String>,
}
impl Manual for Cat {
    const SECTION: Section = Section::Text;
    const NEEDS: &'static str = "r on each FILE.";
    const EXAMPLES: &'static [(&'static str, &'static str)] =
        &[("cat notes.md", "one file"), ("ls | cat", "standard input")];
    const SEE: &'static [&'static str] = &["head", "tail", "open"];
}

/// write the first lines
///
/// Writes the first N lines (10) of each FILE, or of standard input; -n -N all but the last N;
/// -N is -n N. With several files, each is headed by its name.
#[derive(Parser, Debug)]
#[command(name = "head")]
pub struct Head {
    /// the first N lines, or with -N all but the last N
    #[arg(
        short = 'n',
        long = "lines",
        value_name = "[-]N",
        allow_hyphen_values = true
    )]
    pub lines: Option<String>,
    #[arg(value_hint = ValueHint::AnyPath, value_name = "FILE")]
    pub files: Vec<String>,
}
impl Manual for Head {
    fn check(args: &[String]) -> Result<(), String> {
        crate::text::parse("head", args).map(drop)
    }
    const SECTION: Section = Section::Text;
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("head -n 3 notes.md", "three lines"),
        ("ls -l | head -5", "five entries"),
    ];
    const SEE: &'static [&'static str] = &["tail"];
}

/// write the last lines
///
/// Writes the last N lines (10) of each FILE, or of standard input; -n +N the lines from line N
/// on; -N is -n N.
#[derive(Parser, Debug)]
#[command(name = "tail")]
pub struct Tail {
    /// the last N lines, or with +N those from line N on
    #[arg(
        short = 'n',
        long = "lines",
        value_name = "[+]N",
        allow_hyphen_values = true
    )]
    pub lines: Option<String>,
    #[arg(value_hint = ValueHint::AnyPath, value_name = "FILE")]
    pub files: Vec<String>,
}
impl Manual for Tail {
    fn check(args: &[String]) -> Result<(), String> {
        crate::text::parse("tail", args).map(drop)
    }
    const SECTION: Section = Section::Text;
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("tail -n 20 server.log", "twenty lines"),
        ("tail -n +2 table.csv", "without the header"),
    ];
    const SEE: &'static [&'static str] = &["head"];
}

/// write the lines that match
///
/// Writes the lines of each FILE, or of standard input, that match PATTERN, a regular expression
/// (as grep -E reads it). With several files, lines are prefixed by their file's name. Fails when
/// nothing matches.
#[derive(Parser, Debug)]
#[command(
    name = "grep",
    override_usage = "grep [OPTIONS] PATTERN [FILE...]\n       grep [OPTIONS] -e PATTERN [FILE...]"
)]
pub struct Grep {
    /// ignore case
    #[arg(short = 'i', long = "ignore-case")]
    pub ignore_case: bool,
    /// lines that do not match
    #[arg(short = 'v', long = "invert-match")]
    pub invert: bool,
    /// number the lines
    #[arg(short = 'n', long = "line-number")]
    pub number: bool,
    /// count them instead
    #[arg(short = 'c', long = "count")]
    pub count: bool,
    /// PATTERN is a fixed string
    #[arg(short = 'F', long = "fixed-strings")]
    pub fixed: bool,
    /// PATTERN is an extended regular expression (always)
    #[arg(short = 'E', long = "extended-regexp")]
    pub extended: bool,
    /// a pattern, which may start with -; given again, lines matching any are selected
    #[arg(
        short = 'e',
        long = "regexp",
        value_name = "PATTERN",
        allow_hyphen_values = true
    )]
    pub patterns: Vec<String>,
    #[arg(value_hint = ValueHint::AnyPath, value_name = "PATTERN|FILE")]
    pub operands: Vec<String>,
}
impl Manual for Grep {
    const SECTION: Section = Section::Text;
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("grep -in todo notes.md", "numbered, any case"),
        ("ls | grep -v tmp", "all but tmp"),
        ("fd -e md -X grep -c TODO", "count per file"),
    ];
    const SEE: &'static [&'static str] = &["fd", "wc"];
}

/// count lines, words and bytes
///
/// Counts the lines, words and bytes of each FILE, or of standard input, with a total for
/// several.
#[derive(Parser, Debug)]
#[command(name = "wc")]
pub struct Wc {
    /// lines
    #[arg(short = 'l', long = "lines")]
    pub lines: bool,
    /// words
    #[arg(short = 'w', long = "words")]
    pub words: bool,
    /// bytes
    #[arg(short = 'c', long = "bytes")]
    pub bytes: bool,
    #[arg(value_hint = ValueHint::AnyPath, value_name = "FILE")]
    pub files: Vec<String>,
}
impl Manual for Wc {
    const SECTION: Section = Section::Text;
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("wc -l notes.md", "lines"),
        ("fd -e rs -X wc -l", "per file, and in all"),
    ];
    const SEE: &'static [&'static str] = &["grep"];
}

/// sort lines
///
/// Writes the lines of the FILEs, or of standard input, sorted.
#[derive(Parser, Debug)]
#[command(name = "sort")]
pub struct Sort {
    /// by leading number
    #[arg(short = 'n', long = "numeric-sort")]
    pub numeric: bool,
    /// reversed
    #[arg(short = 'r', long = "reverse")]
    pub reverse: bool,
    /// one of each equal line
    #[arg(short = 'u', long = "unique")]
    pub unique: bool,
    #[arg(value_hint = ValueHint::AnyPath, value_name = "FILE")]
    pub files: Vec<String>,
}
impl Manual for Sort {
    const SECTION: Section = Section::Text;
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("ls | sort -r", "reversed"),
        ("fd -e md -X wc -l | sort -n", "by size"),
    ];
    const SEE: &'static [&'static str] = &["uniq"];
}

/// drop repeated lines
///
/// Writes the lines of FILE, or of standard input, adjacent repeats once. Sort first to count
/// all repeats.
#[derive(Parser, Debug)]
#[command(name = "uniq")]
pub struct Uniq {
    /// prefix each with how many times it came
    #[arg(short = 'c', long = "count")]
    pub count: bool,
    #[arg(value_hint = ValueHint::AnyPath, value_name = "FILE")]
    pub file: Option<String>,
}
impl Manual for Uniq {
    const SECTION: Section = Section::Text;
    const EXAMPLES: &'static [(&'static str, &'static str)] =
        &[("sort names.txt | uniq -c", "count each name")];
    const SEE: &'static [&'static str] = &["sort"];
}

/// run a command on what it reads
///
/// Runs COMMAND (echo) with the items read from standard input added as arguments. Items are
/// separated by blanks and newlines, with quotes and backslashes as in GNU xargs.
///
/// Each run is a program of its own; a failed run does not stop the next. Ctrl+C stops between
/// runs.
#[derive(Parser, Debug)]
#[command(name = "xargs")]
pub struct Xargs {
    /// items end with NUL (fd -0)
    #[arg(short = '0', long = "null")]
    pub null: bool,
    /// items end with DELIM
    #[arg(
        short = 'd',
        long = "delimiter",
        value_name = "DELIM",
        allow_hyphen_values = true
    )]
    pub delimiter: Option<String>,
    /// at most N items a run
    #[arg(short = 'n', long = "max-args", value_name = "N", value_parser = positive)]
    pub max_args: Option<u64>,
    /// once per line, REPLACE in the arguments
    #[arg(short = 'I', value_name = "REPLACE")]
    pub replace: Option<String>,
    /// nothing to read, nothing run
    #[arg(short = 'r', long = "no-run-if-empty")]
    pub no_run_if_empty: bool,
    /// print each command first
    #[arg(short = 't', long = "verbose")]
    pub verbose: bool,
    #[arg(value_name = "COMMAND", trailing_var_arg = true)]
    pub command: Vec<String>,
}
impl Manual for Xargs {
    const SECTION: Section = Section::Text;
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("fd -e tmp | xargs rm", "remove them all"),
        ("fd -0 -t f | xargs -0 chmod 600", "names with spaces too"),
        ("ls | xargs -I {} cp {} /backup/{}", "one at a time"),
    ];
    const SEE: &'static [&'static str] = &["fd"];
}

/// A count of 1 or more.
fn positive(value: &str) -> Result<u64, String> {
    match value.parse() {
        Ok(0) | Err(_) => Err("a count of 1 or more is expected".into()),
        Ok(count) => Ok(count),
    }
}

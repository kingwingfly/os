//! What a program is given, and what it gives back: its arguments, its working directory, its
//! standard input, what it writes, its errors, and, for ls, a listing the terminal shows as a
//! view of its own.
use std::future::Future;
use std::pin::Pin;
use terminal_worker_core::Entry;

/// A question a program asks on the terminal (mv -i): the line answered, or none if cancelled.
pub type Ask<'a> = &'a dyn Fn(String) -> Pin<Box<dyn Future<Output = Option<String>>>>;

/// What the terminal shows of a program's output, rather than its text.
#[derive(Clone, Debug)]
pub enum View {
    /// A listing: the entries, long (-l) or not.
    Listing { entries: Vec<Entry>, long: bool },
}

pub struct Io<'a> {
    /// The program's name and its arguments.
    pub args: Vec<String>,
    /// The working directory, as the shell keeps it (logical: as typed through links).
    pub cwd: String,
    /// The account's home, which `~` names.
    pub home: String,
    /// The time it started, in seconds since 1970, which touch -d now and ls -l reckon from.
    pub now: u64,
    pub stdin: Option<String>,
    /// What it writes, ...
    pub out: String,
    /// ... and its error lines.
    pub err: Vec<String>,
    pub view: Option<View>,
    /// What fd found, by path, for -x and -X to run on.
    pub found: Vec<String>,
    /// Whether Ctrl+C asked it to stop: it does, between steps.
    pub cancelled: &'a dyn Fn() -> bool,
    pub ask: Ask<'a>,
}
impl Io<'_> {
    /// The arguments after the program's name.
    pub fn rest(&self) -> &[String] {
        self.args.get(1..).unwrap_or_default()
    }
    /// `operand` as an absolute path, from the working directory, `~` the home: as written
    /// otherwise, `..` and links left for the kernel to resolve, as Linux resolves them.
    pub fn path(&self, operand: &str) -> String {
        let operand = if operand == "~" {
            self.home.clone()
        } else if let Some(rest) = operand.strip_prefix("~/") {
            format!("{}/{rest}", self.home)
        } else {
            operand.to_string()
        };
        if operand.starts_with('/') {
            operand
        } else if self.cwd == "/" {
            format!("/{operand}")
        } else {
            format!("{}/{operand}", self.cwd)
        }
    }
    /// Write a line.
    pub fn say(&mut self, line: impl AsRef<str>) {
        self.out.push_str(line.as_ref());
        self.out.push('\n');
    }
    /// Report an error line, as a program writes to stderr.
    pub fn fail(&mut self, line: impl Into<String>) {
        self.err.push(line.into());
    }
}

/// `name` quoted as GNU's tools quote what they name in messages: in single quotes, or double
/// ones if it has a single quote.
pub fn quote(name: &str) -> String {
    if name.contains('\'') {
        format!("\"{name}\"")
    } else {
        format!("'{name}'")
    }
}

/// `name` in the directory `dir`, both as written.
pub fn joined(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// The last part of `path`, as basename(1) gives it.
pub fn basename(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/";
    }
    trimmed.rsplit('/').next().unwrap_or(trimmed)
}

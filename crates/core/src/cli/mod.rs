//! Every command's definition: what it takes, as clap parses it, and its manual. A command is a
//! clap `Parser` whose doc comments are its summary, description and options, and whose
//! [`Manual`] adds what it needs, examples and related commands. [`DEFINITIONS`] registers them
//! all; user space's programs (crates/userland) and the terminal run them, and `-h`, `man`
//! and `help` are made from these definitions alone, so that what a page says is what parsing
//! accepts.

pub mod accounts;
pub mod archives;
pub mod files;
pub mod permissions;
pub mod terminal;
pub mod text;

use std::marker::PhantomData;
use std::sync::OnceLock;

use clap::error::{ContextKind, ContextValue, ErrorKind};
use clap::{Arg, ArgAction, Command, Parser};

/// Where a command is listed in `help` and the manual's index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Section {
    Files,
    Text,
    Archives,
    Permissions,
    Accounts,
    Terminal,
}
impl Section {
    pub const ALL: [Section; 6] = [
        Section::Files,
        Section::Text,
        Section::Archives,
        Section::Permissions,
        Section::Accounts,
        Section::Terminal,
    ];
    pub fn title(self) -> &'static str {
        match self {
            Section::Files => "Files",
            Section::Text => "Text",
            Section::Archives => "Archives and video",
            Section::Permissions => "Permissions",
            Section::Accounts => "Accounts",
            Section::Terminal => "Terminal",
        }
    }
}

/// A command's manual, beyond what its clap definition says.
pub trait Manual: Parser {
    const SECTION: Section;
    /// The permissions it needs.
    const NEEDS: &'static str = "";
    /// Command lines, and what each does.
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[];
    /// Related commands.
    const SEE: &'static [&'static str] = &[];
    /// Whether the command accepts `args`, as it reads them: by clap, unless it reads some
    /// spellings first (tar czf, head -5).
    fn check(args: &[String]) -> Result<(), String> {
        parse::<Self>(args).map(drop)
    }
}

/// A command, as the manual and parsing see it, whatever its arguments' type.
pub trait Definition: Sync {
    /// Its clap command, as every command is configured: no help or version flag of clap's own,
    /// as -h is the terminal's (or an option of the command's), and no colour.
    fn command(&self) -> Command;
    fn section(&self) -> Section;
    fn needs(&self) -> &'static str;
    fn examples(&self) -> &'static [(&'static str, &'static str)];
    fn see(&self) -> &'static [&'static str];
    /// Whether it accepts `args`, its arguments after its name; if not, why, on one line.
    fn check(&self, args: &[String]) -> Result<(), String>;
}

/// The definition of the command `T` parses.
pub struct Def<T>(PhantomData<fn() -> T>);
impl<T> Def<T> {
    pub const NEW: Self = Self(PhantomData);
}
impl<T: Manual> Definition for Def<T> {
    fn command(&self) -> Command {
        configured(T::command())
    }
    fn section(&self) -> Section {
        T::SECTION
    }
    fn needs(&self) -> &'static str {
        T::NEEDS
    }
    fn examples(&self) -> &'static [(&'static str, &'static str)] {
        T::EXAMPLES
    }
    fn see(&self) -> &'static [&'static str] {
        T::SEE
    }
    fn check(&self, args: &[String]) -> Result<(), String> {
        T::check(args)
    }
}

/// An option given again overrides itself, as GNU's getopt allows (rm -rf -f, tar -f a -f b);
/// options that gather values (grep -e, fd -e) still gather them all.
fn configured(command: Command) -> Command {
    command
        .disable_help_flag(true)
        .disable_version_flag(true)
        .disable_help_subcommand(true)
        .args_override_self(true)
}

/// Every command: within its section, in the order help lists it; the sections in the order
/// completion prefers among equal matches (he is help before head).
pub static DEFINITIONS: &[&dyn Definition] = &[
    &Def::<terminal::Help>::NEW,
    &Def::<terminal::Man>::NEW,
    &Def::<terminal::Clear>::NEW,
    &Def::<files::Ls>::NEW,
    &Def::<files::Cd>::NEW,
    &Def::<files::Pwd>::NEW,
    &Def::<files::Open>::NEW,
    &Def::<files::Present>::NEW,
    &Def::<files::Stream>::NEW,
    &Def::<files::Vim>::NEW,
    &Def::<files::Mkdir>::NEW,
    &Def::<files::Touch>::NEW,
    &Def::<files::Rm>::NEW,
    &Def::<files::Mv>::NEW,
    &Def::<files::Cp>::NEW,
    &Def::<files::Ln>::NEW,
    &Def::<files::Readlink>::NEW,
    &Def::<files::Realpath>::NEW,
    &Def::<files::Stat>::NEW,
    &Def::<files::Df>::NEW,
    &Def::<files::Rmdir>::NEW,
    &Def::<files::Fd>::NEW,
    &Def::<files::Upload>::NEW,
    &Def::<accounts::Whoami>::NEW,
    &Def::<accounts::Id>::NEW,
    &Def::<accounts::Groups>::NEW,
    &Def::<accounts::Users>::NEW,
    &Def::<accounts::Login>::NEW,
    &Def::<accounts::Su>::NEW,
    &Def::<accounts::Sudo>::NEW,
    &Def::<accounts::Exit>::NEW,
    &Def::<accounts::Logout>::NEW,
    &Def::<accounts::Passwd>::NEW,
    &Def::<accounts::Useradd>::NEW,
    &Def::<accounts::Usermod>::NEW,
    &Def::<accounts::Userdel>::NEW,
    &Def::<accounts::Groupadd>::NEW,
    &Def::<accounts::Groupmod>::NEW,
    &Def::<accounts::Groupdel>::NEW,
    &Def::<permissions::Chmod>::NEW,
    &Def::<permissions::Chown>::NEW,
    &Def::<permissions::Chgrp>::NEW,
    &Def::<permissions::Getfacl>::NEW,
    &Def::<permissions::Setfacl>::NEW,
    &Def::<permissions::Getfattr>::NEW,
    &Def::<permissions::Setfattr>::NEW,
    &Def::<text::Echo>::NEW,
    &Def::<text::Cat>::NEW,
    &Def::<text::Head>::NEW,
    &Def::<text::Tail>::NEW,
    &Def::<text::Grep>::NEW,
    &Def::<text::Wc>::NEW,
    &Def::<text::Sort>::NEW,
    &Def::<text::Uniq>::NEW,
    &Def::<text::Xargs>::NEW,
    &Def::<archives::Zip>::NEW,
    &Def::<archives::Unzip>::NEW,
    &Def::<archives::Tar>::NEW,
    &Def::<archives::Faststart>::NEW,
    &Def::<archives::Jobs>::NEW,
    &Def::<archives::Ps>::NEW,
    &Def::<archives::Kill>::NEW,
];

/// Every command's name, in the order of [`DEFINITIONS`].
pub fn names() -> &'static [String] {
    static NAMES: OnceLock<Vec<String>> = OnceLock::new();
    NAMES.get_or_init(|| {
        DEFINITIONS
            .iter()
            .map(|d| d.command().get_name().to_string())
            .collect()
    })
}

/// The definition of the command `name`.
pub fn definition(name: &str) -> Option<&'static dyn Definition> {
    names()
        .iter()
        .position(|n| n == name)
        .map(|i| DEFINITIONS[i])
}

/// Whether `args`, a command line, is one its command accepts, and under sudo the command sudo
/// runs; if not, why, on one line. Names without a definition are left to what runs them.
pub fn check(args: &[String]) -> Result<(), String> {
    let Some((name, rest)) = args.split_first() else {
        return Ok(());
    };
    let Some(definition) = definition(name) else {
        return Ok(());
    };
    definition.check(rest)?;
    match rest.first() {
        Some(command) if name == "sudo" && !command.starts_with('-') => check(rest),
        _ => Ok(()),
    }
}

/// `args`, a command's arguments after its name, as `T` parses them; or clap's reason why not,
/// after the command's name, with a pointer to its help.
pub fn parse<T: Manual>(args: &[String]) -> Result<T, String> {
    let mut command = configured(T::command());
    let name = command.get_name().to_string();
    command
        .try_get_matches_from_mut(std::iter::once(name).chain(args.iter().cloned()))
        .and_then(|matches| T::from_arg_matches(&matches))
        .map_err(|e| tidied(&command, &e))
}

/// clap's error, on one line: what was wrong, without the usage it adds, and with operands named
/// as the help names them (PATH, not <PATH>).
fn tidied(command: &Command, error: &clap::Error) -> String {
    let name = command.get_name();
    let hidden = |option: &str| {
        let long = option
            .split(' ')
            .next()
            .unwrap_or_default()
            .trim_start_matches("--");
        command
            .get_arguments()
            .any(|arg| arg.is_hide_set() && arg.get_long() == Some(long))
    };
    let reason = match (error.kind(), error.get(ContextKind::InvalidArg)) {
        (ErrorKind::MissingRequiredArgument, Some(ContextValue::Strings(missing))) => {
            // A required group, as <--create|--extract|--list>, is one of its options shown.
            let missing = missing.iter().map(|arg| match arg.strip_prefix('<') {
                Some(group) if group.starts_with('-') => {
                    let options = group.strip_suffix('>').unwrap_or(group).split('|');
                    let shown: Vec<_> = options.filter(|option| !hidden(option)).collect();
                    format!("one of {}", shown.join(", "))
                }
                _ => arg.clone(),
            });
            format!("missing {}", missing.collect::<Vec<_>>().join(", "))
        }
        _ => {
            let rendered = error.render().to_string();
            let first = rendered.lines().next().unwrap_or_default();
            first.trim_start_matches("error: ").to_string()
        }
    };
    format!(
        "{name}: {}; {name} -h shows how to use it",
        unbracketed(&reason)
    )
}

/// `text` with clap's `<NAME>` written `NAME`, as in help.
fn unbracketed(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find('<') {
        let name = rest[start + 1..].split_once('>').map(|(name, _)| name);
        match name.filter(|name| {
            !name.is_empty() && name.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
        }) {
            Some(name) => {
                out.push_str(&rest[..start]);
                out.push_str(name);
                rest = &rest[start + name.len() + 2..];
            }
            None => {
                out.push_str(&rest[..=start]);
                rest = &rest[start + 1..];
            }
        }
    }
    out + rest
}

/// Whether `args`, a command line, asks for help: `--help` before `--`, or `-h`, unless the
/// command has an -h of its own (chown -h, tar -h...) and is given more than it. Under sudo, the
/// command sudo runs is asked.
pub fn wants_help(args: &[String]) -> bool {
    let args = match args {
        [sudo, command, ..] if sudo == "sudo" && !command.starts_with('-') => &args[1..],
        _ => args,
    };
    let Some(name) = args.first() else {
        return false;
    };
    // Whether each command has an -h of its own, and whether it runs with that alone, worked
    // out once: xargs and fd -x ask this of every command line they run. Alone, -h is help,
    // unless the command runs so (df -h).
    static OWN_H: OnceLock<Vec<(bool, bool)>> = OnceLock::new();
    let own_h = OWN_H.get_or_init(|| {
        DEFINITIONS
            .iter()
            .map(|d| {
                let command = d.command();
                let own = command
                    .get_arguments()
                    .any(|arg| arg.get_short() == Some('h'));
                let name = command.get_name().to_string();
                let alone = own && command.try_get_matches_from([name, "-h".into()]).is_ok();
                (own, alone)
            })
            .collect()
    });
    let (own_h, alone) = names()
        .iter()
        .position(|n| n == name)
        .map_or((false, false), |i| own_h[i]);
    args.iter()
        .skip(1)
        .take_while(|arg| arg.as_str() != "--")
        .any(|arg| arg == "--help" || arg == "-h" && (!own_h || args.len() == 2 && !alone))
}

/// How an option is written: `-r, -R, --recursive`, and its value, as in `-n N`.
fn option_text(arg: &Arg) -> String {
    let mut names = Vec::new();
    if let Some(short) = arg.get_short() {
        names.push(format!("-{short}"));
    }
    for short in arg.get_visible_short_aliases().unwrap_or_default() {
        names.push(format!("-{short}"));
    }
    if let Some(long) = arg.get_long() {
        names.push(format!("--{long}"));
    }
    for long in arg.get_visible_aliases().unwrap_or_default() {
        names.push(format!("--{long}"));
    }
    let mut text = names.join(", ");
    if !matches!(
        arg.get_action(),
        ArgAction::SetTrue | ArgAction::SetFalse | ArgAction::Count | ArgAction::Help
    ) {
        let value = arg
            .get_value_names()
            .map(|names| {
                names
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_else(|| arg.get_id().as_str().to_uppercase());
        text.push(' ');
        text.push_str(&value);
    }
    text
}

/// A command's options, as (how each is written, what it does).
fn options(command: &Command) -> Vec<(String, String)> {
    command
        .get_arguments()
        .filter(|arg| !arg.is_positional() && !arg.is_hide_set())
        .map(|arg| {
            (
                option_text(arg),
                arg.get_help().map(|h| h.to_string()).unwrap_or_default(),
            )
        })
        .collect()
}

/// Its usage lines, without clap's `Usage: `, operands written as in the rest of the help.
fn usage(command: &Command) -> Vec<String> {
    let rendered = command.clone().render_usage().to_string();
    rendered
        .trim_start_matches("Usage:")
        .lines()
        .map(|line| unbracketed(line.trim()))
        .filter(|line| !line.is_empty())
        .collect()
}

/// Its summary and the paragraphs of its description.
fn about(command: &Command) -> (String, Vec<String>) {
    let summary = command
        .get_about()
        .map(|a| a.to_string())
        .unwrap_or_default();
    let long = command
        .get_long_about()
        .map(|a| a.to_string())
        .unwrap_or_default();
    let paragraphs = long
        .split("\n\n")
        .skip(1)
        .map(|p| p.replace('\n', " ").trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();
    (summary, paragraphs)
}

/// `name`'s help, as text for the terminal: what -h shows.
pub fn help(name: &str) -> Option<String> {
    let definition = definition(name)?;
    let command = definition.command();
    let (summary, paragraphs) = about(&command);
    let mut out = vec![format!("{name} — {summary}"), String::new()];
    for (i, line) in usage(&command).iter().enumerate() {
        out.push(format!(
            "{}{line}",
            if i == 0 { "Usage: " } else { "       " }
        ));
    }
    for paragraph in paragraphs {
        out.push(String::new());
        out.push(paragraph);
    }
    let options = options(&command);
    if !options.is_empty() {
        let width = options
            .iter()
            .map(|(flag, _)| flag.chars().count())
            .max()
            .unwrap_or(0);
        out.push(String::new());
        out.push("Options:".into());
        for (flag, meaning) in options {
            out.push(format!("  {flag:width$}  {meaning}"));
        }
    }
    if !definition.needs().is_empty() {
        out.push(String::new());
        out.push(format!("Needs: {}", definition.needs()));
    }
    let examples = definition.examples();
    if !examples.is_empty() {
        let width = examples
            .iter()
            .map(|(c, _)| c.chars().count())
            .max()
            .unwrap_or(0);
        out.push(String::new());
        out.push("Examples:".into());
        for (line, what) in examples {
            out.push(format!("  {line:width$}   # {what}"));
        }
    }
    out.push(String::new());
    let see = definition.see();
    out.push(if see.is_empty() {
        format!("man {name} opens the manual page.")
    } else {
        format!(
            "See also: {}. man {name} opens the manual page.",
            see.join(", ")
        )
    });
    Some(out.join("\n"))
}

/// `name`'s manual page, as Markdown.
pub fn page(name: &str) -> Option<String> {
    let definition = definition(name)?;
    let command = definition.command();
    let (summary, paragraphs) = about(&command);
    let mut page = format!(
        "# {name} — {summary}\n\n```text\n{}\n```",
        usage(&command).join("\n")
    );
    for paragraph in paragraphs {
        page.push_str("\n\n");
        page.push_str(&paragraph);
    }
    let options = options(&command);
    if !options.is_empty() {
        page.push_str("\n\n## Options\n\n| Option | Meaning |\n| --- | --- |\n");
        page.push_str(
            &options
                .iter()
                .map(|(flag, meaning)| format!("| `{flag}` | {meaning} |"))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
    if !definition.needs().is_empty() {
        page.push_str(&format!("\n\n## Permissions\n\n{}", definition.needs()));
    }
    let examples = definition.examples();
    if !examples.is_empty() {
        let width = examples
            .iter()
            .map(|(c, _)| c.chars().count())
            .max()
            .unwrap_or(0);
        page.push_str("\n\n## Examples\n\n```text\n");
        page.push_str(
            &examples
                .iter()
                .map(|(line, what)| format!("{line:width$}   # {what}"))
                .collect::<Vec<_>>()
                .join("\n"),
        );
        page.push_str("\n```");
    }
    if !definition.see().is_empty() {
        page.push_str("\n\n## See also\n\n");
        page.push_str(
            &definition
                .see()
                .iter()
                .map(|n| format!("`{n}`"))
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    Some(page)
}

/// The commands of `section`, with their summaries.
fn listed(section: Section) -> Vec<(String, String)> {
    DEFINITIONS
        .iter()
        .filter(|d| d.section() == section)
        .map(|d| {
            let command = d.command();
            (command.get_name().to_string(), about(&command).0)
        })
        .collect()
}

/// The manual's index, as Markdown: every command by section, then how the terminal works.
pub fn index() -> String {
    let mut out = String::from(
        "# Terminal Worker Manual\n\n`man COMMAND` opens a page; `COMMAND -h` shows it in short in the terminal; `help` lists every command. All paths are in this terminal's own filesystem: nothing runs on a host.",
    );
    for section in Section::ALL {
        out.push_str(&format!(
            "\n\n## {}\n\n| Command | What it does |\n| --- | --- |\n",
            section.title()
        ));
        out.push_str(
            &listed(section)
                .iter()
                .map(|(name, summary)| format!("| `{name}` | {summary} |"))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
    out.push_str("\n\n");
    out.push_str(OVERVIEW);
    out
}

/// What help writes: every command, a line each, by section.
pub fn commands() -> String {
    let width = names().iter().map(|n| n.len()).max().unwrap_or(0);
    let mut out = Vec::new();
    for section in Section::ALL {
        out.push(section.title().to_string());
        for (name, summary) in listed(section) {
            out.push(format!("  {name:width$}  {summary}"));
        }
        out.push(String::new());
    }
    // /usr/bin's programs the shell has no command of its own for: uutils'.
    let names = names();
    let bin: Vec<&str> = crate::bin::PROGRAMS
        .iter()
        .copied()
        .filter(|program| !names.iter().any(|name| name == program))
        .collect();
    out.push("/usr/bin, from uutils' coreutils (processes of their own)".to_string());
    let mut line = String::new();
    for program in bin {
        if !line.is_empty() && line.len() + 1 + program.len() > 76 {
            out.push(format!("  {line}"));
            line.clear();
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(program);
    }
    out.push(format!("  {line}"));
    out.push(
        "  /bin/NAME runs /bin's NAME where the shell has its own; NAME --help says how.".into(),
    );
    out.push(String::new());
    out.extend(
        [
            "COMMAND -h shows how to use one; man COMMAND its manual page; man, the index.",
            "COMMAND | COMMAND pipes; *, ? and [...] expand to paths; quote to keep them.",
            "Tab completes · ↑↓ history · Ctrl+C stops · Alt+T / Alt+W / Alt+1–9 tabs.",
            "Signed out? useradd NAME makes an account of your own, at home in /guest.",
        ]
        .map(String::from),
    );
    out.join("\n")
}

/// How the terminal works, after the index.
const OVERVIEW: &str = include_str!("overview.md");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_command_has_a_page_and_help() {
        let mut seen = std::collections::BTreeSet::new();
        for name in names() {
            assert!(seen.insert(name), "{name} twice");
            let help = help(name).unwrap();
            assert!(help.contains("Usage: "), "{name}");
            assert!(help.contains(&format!("man {name}")), "{name}");
            assert!(
                page(name).unwrap().starts_with(&format!("# {name} — ")),
                "{name}"
            );
            // Its summary is a phrase, not a sentence.
            assert!(
                !about(&definition(name).unwrap().command()).0.is_empty(),
                "{name}"
            );
        }
        assert!(index().contains("## Permissions"));
        assert!(commands().contains("  setfacl"));
    }

    #[test]
    fn help_is_asked_as_each_command_takes_h() {
        let line = |text: &str| text.split(' ').map(String::from).collect::<Vec<_>>();
        assert!(wants_help(&line("cp -h")));
        assert!(wants_help(&line("cp --help a b")));
        assert!(!wants_help(&line("cp -- -h b")));
        assert!(wants_help(&line("chown -h")));
        assert!(!wants_help(&line("chown -h root link")));
        assert!(!wants_help(&line("sudo chown -h root link")));
        assert!(wants_help(&line("sudo cp -h")));
    }

    #[test]
    fn path_operands_say_so_for_completion() {
        // A path operand or option value without a hint is not completed (faststart's FILE
        // once was not).
        for definition in DEFINITIONS {
            let mut command = definition.command();
            command.build();
            for arg in command
                .get_arguments()
                .filter(|a| a.get_action().takes_values())
            {
                let named = arg.get_value_names().unwrap_or_default();
                let path = named.iter().any(|n| {
                    ["PATH", "FILE", "DIR", "SOURCE", "DEST", "TARGET", "ARCHIVE"]
                        .iter()
                        .any(|p| n.as_str().contains(p))
                });
                assert!(
                    !path || arg.get_value_hint() != clap::ValueHint::Unknown,
                    "{} {:?} needs a value_hint",
                    command.get_name(),
                    named
                );
            }
        }
    }

    #[test]
    fn command_lines_are_checked_as_their_commands_read_them() {
        let line = |text: &str| text.split(' ').map(String::from).collect::<Vec<_>>();
        assert_eq!(check(&line("tar czf notes.tgz notes")), Ok(()));
        assert_eq!(check(&line("head -5 notes.md")), Ok(()));
        assert_eq!(check(&line("sudo -u bob")), Ok(()));
        assert_eq!(check(&line("nothing-defined -x")), Ok(()));
        assert!(
            check(&line("passwd a b"))
                .unwrap_err()
                .starts_with("passwd: unexpected")
        );
        assert_eq!(
            check(&line("sudo rm")),
            Err("rm: missing PATH...; rm -h shows how to use it".into())
        );
    }

    #[test]
    fn options_given_again_are_taken_as_getopt_takes_them() {
        let line = |text: &str| text.split(' ').map(String::from).collect::<Vec<_>>();
        for text in ["rm -rf -f x", "ls -l -l", "cp -f -f -- a b", "echo -nn hi"] {
            assert_eq!(check(&line(text)), Ok(()), "{text}");
        }
        let tar = parse::<archives::Tar>(&line("-cf a.tar -f b.tar x")).unwrap();
        assert_eq!(tar.file.as_deref(), Some("b.tar"));
    }

    #[test]
    fn options_with_attached_values_are_not_taken_for_the_command() {
        let line = |text: &str| text.split(' ').map(String::from).collect::<Vec<_>>();
        let xargs = parse::<text::Xargs>(&line("-n1 -I{} cp {} -r b")).unwrap();
        assert_eq!(
            (xargs.max_args, xargs.replace.as_deref()),
            (Some(1), Some("{}"))
        );
        assert_eq!(xargs.command, line("cp {} -r b"));
        let sudo = parse::<accounts::Sudo>(&line("-ubob")).unwrap();
        assert_eq!((sudo.user.as_deref(), sudo.command.len()), (Some("bob"), 0));
        assert_eq!(
            parse::<accounts::Sudo>(&line("rm -- -h")).unwrap().command,
            line("rm -- -h")
        );
    }

    #[test]
    fn errors_say_what_was_wrong_on_one_line() {
        let error = parse::<files::Cp>(&["-x".into(), "a".into(), "b".into()]).unwrap_err();
        assert_eq!(
            error,
            "cp: unexpected argument '-x' found; cp -h shows how to use it"
        );
        let error = parse::<permissions::Chmod>(&[]).unwrap_err();
        assert_eq!(
            error,
            "chmod: missing MODE, PATH...; chmod -h shows how to use it"
        );
        let error = parse::<archives::Tar>(&["-f".into(), "x.tar".into()]).unwrap_err();
        assert!(
            error.starts_with("tar: missing one of --create, --extract, --list;"),
            "{error}"
        );
    }
}

//! Portable interactive shell core for `/usr/bin/osh`.
//!
//! Pure-Rust parser, variable/glob expander, raw-mode PTY line editor, history ring,
//! completion engine, job table, and OSC 7 / OSC 133 shell-integration formatter so all
//! non-syscall logic compiles and unit-tests on the host as well as `wasm32-wasip1`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use os_core::{
    Entry, cli,
    completion::{self, Candidate, Query},
    glob,
    shell::Word,
};

/// Builtin commands executed directly inside `/usr/bin/osh`.
pub const BUILTINS: &[&str] = &[
    "cd", "pwd", "export", "unset", "clear", "jobs", "fg", "bg", "kill", "help", "exit", "logout",
    "history", "umask", "exec", ":",
];

/// Control flow connector between two pipelines in a command list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Connector {
    Seq,
    And,
    Or,
}

/// File redirection attached to one pipeline stage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Redir {
    Stdin(Word),
    StdoutTrunc(Word),
    StdoutAppend(Word),
    StderrTrunc(Word),
    StderrAppend(Word),
    StderrToStdout,
    StdoutToStderr,
}

/// One simple command within a pipeline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stage {
    pub assignments: Vec<(String, String)>,
    pub words: Vec<Word>,
    pub redirs: Vec<Redir>,
}

/// One pipeline (`cmd1 | cmd2 [&]`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pipeline {
    pub stages: Vec<Stage>,
    pub background: bool,
    pub raw: String,
}

/// One pipeline plus the connector governing whether it runs after the prior pipeline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListItem {
    pub connector: Connector,
    pub pipeline: Pipeline,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Word(Word),
    Pipe,
    Amp,
    Semi,
    AndIf,
    OrIf,
    Lt,
    Gt,
    Dgt,
    ErrGt,
    ErrDgt,
    ErrToOut,
    OutToErr,
}

/// Check whether `name` is a valid POSIX shell variable identifier.
pub fn valid_var_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first == b'_' || first.is_ascii_alphabetic())
        && bytes.all(|b| b == b'_' || b.is_ascii_alphanumeric())
}

fn push_literal_glob(c: char, text: &mut String, pattern: &mut String) {
    text.push(c);
    if matches!(c, '*' | '?' | '[' | ']' | '\\' | '-' | '!' | '^') {
        pattern.push('\\');
    }
    pattern.push(c);
}

fn collect_cmd_subst(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
) -> Result<String, String> {
    let mut inner = String::new();
    let mut depth = 1usize;
    let mut quote: Option<char> = None;
    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            inner.push(c);
            if q == '"' && c == '\\' {
                if let Some(next) = chars.next() {
                    inner.push(next);
                }
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '\\' => {
                inner.push(c);
                if let Some(next) = chars.next() {
                    inner.push(next);
                }
            }
            '\'' | '"' => {
                quote = Some(c);
                inner.push(c);
            }
            '(' => {
                depth += 1;
                inner.push(c);
            }
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(inner);
                }
                inner.push(c);
            }
            _ => inner.push(c),
        }
    }
    Err("Unterminated $(...) command substitution".into())
}

fn expand_var(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    lookup: &dyn Fn(&str) -> Option<String>,
    cmd_subst: &mut dyn FnMut(&str) -> Result<String, String>,
    last_status: i32,
    pid: u32,
) -> Result<String, String> {
    match chars.peek().copied() {
        Some('(') => {
            chars.next();
            let inner = collect_cmd_subst(chars)?;
            cmd_subst(&inner)
        }
        Some('?') => {
            chars.next();
            Ok(last_status.to_string())
        }
        Some('$') => {
            chars.next();
            Ok(pid.to_string())
        }
        Some('{') => {
            chars.next();
            let mut inner = String::new();
            let mut closed = false;
            for c in chars.by_ref() {
                if c == '}' {
                    closed = true;
                    break;
                }
                inner.push(c);
            }
            if !closed {
                return Err("Unterminated ${...} expansion".into());
            }
            if inner == "?" {
                return Ok(last_status.to_string());
            }
            if inner == "$" {
                return Ok(pid.to_string());
            }
            if let Some((name, default)) = inner.split_once(":-") {
                if !valid_var_name(name) {
                    return Err(format!("Bad substitution: ${{{inner}}}"));
                }
                let val = lookup(name).unwrap_or_default();
                return Ok(if val.is_empty() {
                    default.to_owned()
                } else {
                    val
                });
            }
            if let Some((name, default)) = inner.split_once('-') {
                if !valid_var_name(name) {
                    return Err(format!("Bad substitution: ${{{inner}}}"));
                }
                return Ok(lookup(name).unwrap_or_else(|| default.to_owned()));
            }
            if !valid_var_name(&inner) {
                return Err(format!("Bad substitution: ${{{inner}}}"));
            }
            Ok(lookup(&inner).unwrap_or_default())
        }
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {
            let mut name = String::new();
            while let Some(&ch) = chars.peek() {
                if ch == '_' || ch.is_ascii_alphanumeric() {
                    name.push(ch);
                    chars.next();
                } else {
                    break;
                }
            }
            Ok(lookup(&name).unwrap_or_default())
        }
        _ => Ok("$".into()),
    }
}

fn tokenize(
    input: &str,
    lookup: &dyn Fn(&str) -> Option<String>,
    cmd_subst: &mut dyn FnMut(&str) -> Result<String, String>,
    last_status: i32,
    pid: u32,
) -> Result<Vec<(Token, usize)>, String> {
    let mut tokens = Vec::new();
    let mut word = String::new();
    let mut pattern = String::new();
    let mut wild = false;
    let mut quote: Option<char> = None;
    let mut active = false;
    let mut token_start = 0usize;
    let mut word_quoted_prefix = false;

    let flush_word = |word: &mut String,
                      pattern: &mut String,
                      wild: &mut bool,
                      active: &mut bool,
                      quoted_prefix: &mut bool,
                      start: usize,
                      tokens: &mut Vec<(Token, usize)>| {
        if !*active {
            return;
        }
        let mut text = std::mem::take(word);
        let mut pat = std::mem::take(pattern);
        let is_wild = std::mem::take(wild);
        // Leading unquoted `~` expands to $HOME (for `~` or `~/...`).
        if !*quoted_prefix && (text == "~" || text.starts_with("~/")) {
            let home = lookup("HOME").unwrap_or_else(|| "/".into());
            let home_trimmed = if home == "/" {
                String::new()
            } else {
                home.trim_end_matches('/').to_owned()
            };
            if text == "~" {
                text = if home.is_empty() { "/".into() } else { home };
                pat = escape_glob_literal(&text);
            } else {
                let suffix = &text[1..];
                text = format!("{home_trimmed}{suffix}");
                if let Some(pat_suffix) = pat.strip_prefix('~') {
                    pat = format!("{}{pat_suffix}", escape_glob_literal(&home_trimmed));
                }
            }
        }
        *active = false;
        *quoted_prefix = false;
        tokens.push((
            Token::Word(Word {
                text,
                pattern: is_wild.then_some(pat),
            }),
            start,
        ));
    };

    let bytes = input.as_bytes();
    let mut chars = input.chars().peekable();
    let mut pos = 0usize;

    while let Some(c) = chars.next() {
        let cur_pos = pos;
        pos += c.len_utf8();

        if let Some(q) = quote {
            if c == q {
                quote = None;
                continue;
            }
            if q == '"'
                && c == '\\'
                && let Some(&next) = chars.peek()
                && matches!(next, '"' | '\\' | '$' | '`' | '\n')
            {
                chars.next();
                pos += next.len_utf8();
                if next != '\n' {
                    push_literal_glob(next, &mut word, &mut pattern);
                }
                continue;
            }
            if q == '"' && c == '$' {
                let before_len = chars.clone().map(char::len_utf8).sum::<usize>();
                let val = expand_var(&mut chars, lookup, cmd_subst, last_status, pid)?;
                let after_len = chars.clone().map(char::len_utf8).sum::<usize>();
                pos += before_len - after_len;
                for ch in val.chars() {
                    push_literal_glob(ch, &mut word, &mut pattern);
                }
                continue;
            }
            push_literal_glob(c, &mut word, &mut pattern);
            continue;
        }

        // Unquoted state
        if c == '\\' {
            if !active {
                token_start = cur_pos;
                word_quoted_prefix = true;
            }
            active = true;
            if let Some(next) = chars.next() {
                pos += next.len_utf8();
                if next != '\n' {
                    push_literal_glob(next, &mut word, &mut pattern);
                }
            } else {
                return Err("Unterminated escape".into());
            }
            continue;
        }

        if c == '#' && !active {
            // Comment until end of line.
            for ch in chars.by_ref() {
                pos += ch.len_utf8();
                if ch == '\n' {
                    break;
                }
            }
            continue;
        }

        match c {
            '\'' | '"' => {
                if !active {
                    token_start = cur_pos;
                    word_quoted_prefix = true;
                }
                quote = Some(c);
                active = true;
            }
            c if c.is_whitespace() => {
                flush_word(
                    &mut word,
                    &mut pattern,
                    &mut wild,
                    &mut active,
                    &mut word_quoted_prefix,
                    token_start,
                    &mut tokens,
                );
                if c == '\n' {
                    tokens.push((Token::Semi, cur_pos));
                }
            }
            '|' => {
                flush_word(
                    &mut word,
                    &mut pattern,
                    &mut wild,
                    &mut active,
                    &mut word_quoted_prefix,
                    token_start,
                    &mut tokens,
                );
                if chars.peek() == Some(&'|') {
                    chars.next();
                    pos += 1;
                    tokens.push((Token::OrIf, cur_pos));
                } else {
                    tokens.push((Token::Pipe, cur_pos));
                }
            }
            '&' => {
                flush_word(
                    &mut word,
                    &mut pattern,
                    &mut wild,
                    &mut active,
                    &mut word_quoted_prefix,
                    token_start,
                    &mut tokens,
                );
                if chars.peek() == Some(&'&') {
                    chars.next();
                    pos += 1;
                    tokens.push((Token::AndIf, cur_pos));
                } else {
                    tokens.push((Token::Amp, cur_pos));
                }
            }
            ';' => {
                flush_word(
                    &mut word,
                    &mut pattern,
                    &mut wild,
                    &mut active,
                    &mut word_quoted_prefix,
                    token_start,
                    &mut tokens,
                );
                tokens.push((Token::Semi, cur_pos));
            }
            '<' => {
                flush_word(
                    &mut word,
                    &mut pattern,
                    &mut wild,
                    &mut active,
                    &mut word_quoted_prefix,
                    token_start,
                    &mut tokens,
                );
                tokens.push((Token::Lt, cur_pos));
            }
            '>' => {
                // Check if immediately preceded by standalone `2` or `1` as fd prefix.
                let fd_prefix = if active && !word_quoted_prefix && (word == "2" || word == "1") {
                    let fd = word.clone();
                    word.clear();
                    pattern.clear();
                    wild = false;
                    active = false;
                    Some(fd)
                } else {
                    flush_word(
                        &mut word,
                        &mut pattern,
                        &mut wild,
                        &mut active,
                        &mut word_quoted_prefix,
                        token_start,
                        &mut tokens,
                    );
                    None
                };
                if fd_prefix.as_deref() == Some("2") && bytes.get(pos..pos + 2) == Some(b"&1") {
                    chars.next();
                    chars.next();
                    pos += 2;
                    tokens.push((Token::ErrToOut, cur_pos));
                } else if fd_prefix.as_deref() == Some("1")
                    && bytes.get(pos..pos + 2) == Some(b"&2")
                {
                    chars.next();
                    chars.next();
                    pos += 2;
                    tokens.push((Token::OutToErr, cur_pos));
                } else if chars.peek() == Some(&'>') {
                    chars.next();
                    pos += 1;
                    if fd_prefix.as_deref() == Some("2") {
                        tokens.push((Token::ErrDgt, cur_pos));
                    } else {
                        tokens.push((Token::Dgt, cur_pos));
                    }
                } else if fd_prefix.as_deref() == Some("2") {
                    tokens.push((Token::ErrGt, cur_pos));
                } else {
                    tokens.push((Token::Gt, cur_pos));
                }
            }
            '$' => {
                if !active {
                    token_start = cur_pos;
                }
                active = true;
                let before_len = chars.clone().map(char::len_utf8).sum::<usize>();
                let val = expand_var(&mut chars, lookup, cmd_subst, last_status, pid)?;
                let after_len = chars.clone().map(char::len_utf8).sum::<usize>();
                pos += before_len - after_len;
                for ch in val.chars() {
                    word.push(ch);
                    pattern.push(ch);
                    wild |= matches!(ch, '*' | '?' | '[');
                }
            }
            c => {
                if !active {
                    token_start = cur_pos;
                }
                active = true;
                word.push(c);
                pattern.push(c);
                wild |= matches!(c, '*' | '?' | '[');
            }
        }
    }

    if quote.is_some() {
        return Err("Unterminated quote".into());
    }
    flush_word(
        &mut word,
        &mut pattern,
        &mut wild,
        &mut active,
        &mut word_quoted_prefix,
        token_start,
        &mut tokens,
    );
    Ok(tokens)
}

fn escape_glob_literal(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, '*' | '?' | '[' | ']' | '\\' | '-' | '!' | '^') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Parse a full command line into a list of pipelines with redirections, variable expansion,
/// quoting, and background markers.
pub fn parse_line(
    input: &str,
    lookup: &dyn Fn(&str) -> Option<String>,
    last_status: i32,
    pid: u32,
) -> Result<Vec<ListItem>, String> {
    let mut no_subst = |cmd: &str| Ok(format!("$({cmd})"));
    parse_line_with_subst(input, lookup, &mut no_subst, last_status, pid)
}

/// Parse a full command line with an active `$(...)` command-substitution evaluator.
pub fn parse_line_with_subst(
    input: &str,
    lookup: &dyn Fn(&str) -> Option<String>,
    cmd_subst: &mut dyn FnMut(&str) -> Result<String, String>,
    last_status: i32,
    pid: u32,
) -> Result<Vec<ListItem>, String> {
    let tokens = tokenize(input, lookup, cmd_subst, last_status, pid)?;
    let mut items = Vec::new();
    let mut i = 0usize;
    let mut connector = Connector::Seq;

    while i < tokens.len() {
        // Skip empty separators (e.g. blank lines / consecutive `;`).
        if matches!(tokens[i].0, Token::Semi) {
            i += 1;
            connector = Connector::Seq;
            continue;
        }
        if matches!(
            tokens[i].0,
            Token::AndIf | Token::OrIf | Token::Amp | Token::Pipe
        ) {
            return Err("syntax error near unexpected operator".into());
        }

        let pipe_start_byte = tokens[i].1;
        let mut stages = Vec::new();

        loop {
            let mut assignments = Vec::new();
            let mut words = Vec::new();
            let mut redirs = Vec::new();

            while i < tokens.len() {
                match &tokens[i].0 {
                    Token::Word(w) => {
                        if words.is_empty()
                            && w.pattern.is_none()
                            && let Some((name, val)) = w.text.split_once('=')
                            && valid_var_name(name)
                        {
                            assignments.push((name.to_owned(), val.to_owned()));
                        } else {
                            words.push(w.clone());
                        }
                        i += 1;
                    }
                    Token::Lt => {
                        i += 1;
                        let Some((Token::Word(target), _)) = tokens.get(i) else {
                            return Err("syntax error: expected filename after <".into());
                        };
                        redirs.push(Redir::Stdin(target.clone()));
                        i += 1;
                    }
                    Token::Gt => {
                        i += 1;
                        let Some((Token::Word(target), _)) = tokens.get(i) else {
                            return Err("syntax error: expected filename after >".into());
                        };
                        redirs.push(Redir::StdoutTrunc(target.clone()));
                        i += 1;
                    }
                    Token::Dgt => {
                        i += 1;
                        let Some((Token::Word(target), _)) = tokens.get(i) else {
                            return Err("syntax error: expected filename after >>".into());
                        };
                        redirs.push(Redir::StdoutAppend(target.clone()));
                        i += 1;
                    }
                    Token::ErrGt => {
                        i += 1;
                        let Some((Token::Word(target), _)) = tokens.get(i) else {
                            return Err("syntax error: expected filename after 2>".into());
                        };
                        redirs.push(Redir::StderrTrunc(target.clone()));
                        i += 1;
                    }
                    Token::ErrDgt => {
                        i += 1;
                        let Some((Token::Word(target), _)) = tokens.get(i) else {
                            return Err("syntax error: expected filename after 2>>".into());
                        };
                        redirs.push(Redir::StderrAppend(target.clone()));
                        i += 1;
                    }
                    Token::ErrToOut => {
                        redirs.push(Redir::StderrToStdout);
                        i += 1;
                    }
                    Token::OutToErr => {
                        redirs.push(Redir::StdoutToStderr);
                        i += 1;
                    }
                    _ => break,
                }
            }

            if words.is_empty() && assignments.is_empty() && redirs.is_empty() {
                return Err("Each side of | needs a command".into());
            }
            stages.push(Stage {
                assignments,
                words,
                redirs,
            });

            if matches!(tokens.get(i).map(|(t, _)| t), Some(Token::Pipe)) {
                i += 1;
                if i >= tokens.len() {
                    return Err("Each side of | needs a command".into());
                }
                continue;
            }
            break;
        }

        let (background, next_connector, pipe_end_byte) = match tokens.get(i) {
            Some((Token::Amp, pos)) => {
                i += 1;
                (true, Connector::Seq, *pos)
            }
            Some((Token::Semi, pos)) => {
                i += 1;
                (false, Connector::Seq, *pos)
            }
            Some((Token::AndIf, pos)) => {
                i += 1;
                if i >= tokens.len() {
                    return Err("syntax error: expected command after &&".into());
                }
                (false, Connector::And, *pos)
            }
            Some((Token::OrIf, pos)) => {
                i += 1;
                if i >= tokens.len() {
                    return Err("syntax error: expected command after ||".into());
                }
                (false, Connector::Or, *pos)
            }
            None => (false, Connector::Seq, input.len()),
            Some(_) => return Err("syntax error".into()),
        };

        let raw = input
            .get(pipe_start_byte..pipe_end_byte)
            .unwrap_or("")
            .trim()
            .to_owned();
        items.push(ListItem {
            connector,
            pipeline: Pipeline {
                stages,
                background,
                raw,
            },
        });
        connector = next_connector;
    }

    Ok(items)
}

/// Expand a word's glob pattern against the local filesystem using `os_core::glob::matches`.
/// If the word has no unquoted wildcard or matches nothing, returns `[word.text]`.
pub fn expand_word_glob(word: &Word, read_dir: &dyn Fn(&str) -> Vec<String>) -> Vec<String> {
    let Some(pattern) = &word.pattern else {
        return vec![word.text.clone()];
    };
    let (dir_prefix, file_pat) = match pattern.rfind('/') {
        Some(idx) => (&pattern[..=idx], &pattern[idx + 1..]),
        None => ("", pattern.as_str()),
    };
    // If directory component itself contains a glob, keep literal (single-segment glob expansion).
    if dir_prefix.contains('*') || dir_prefix.contains('?') || dir_prefix.contains('[') {
        return vec![word.text.clone()];
    }
    let dir_display = match word.text.rfind('/') {
        Some(idx) => &word.text[..=idx],
        None => "",
    };
    let lookup_dir = if dir_display.is_empty() {
        "."
    } else {
        dir_display
    };
    let allow_dot = file_pat.starts_with('.');
    let mut matched: Vec<String> = read_dir(lookup_dir)
        .into_iter()
        .filter(|name| {
            if name == "." || name == ".." {
                return false;
            }
            if name.starts_with('.') && !allow_dot {
                return false;
            }
            glob::matches(file_pat, name)
        })
        .map(|name| format!("{dir_display}{name}"))
        .collect();
    matched.sort();
    if matched.is_empty() {
        vec![word.text.clone()]
    } else {
        matched
    }
}

/// Read directory names from the local OS filesystem for glob expansion.
pub fn fs_read_dir_names(dir: &str) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .collect()
}

/// Read `os_core::Entry` metadata from the local filesystem for completion.
pub fn fs_read_entries(dir: &str) -> Vec<Entry> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in entries.flatten() {
        let Ok(name) = item.file_name().into_string() else {
            continue;
        };
        let path = item.path();
        let meta = std::fs::metadata(&path).ok();
        let lmeta = std::fs::symlink_metadata(&path).ok();
        let is_dir = meta.as_ref().is_some_and(|m| m.is_dir());
        let is_link = lmeta.as_ref().is_some_and(|m| m.file_type().is_symlink());
        let mode = if is_dir
            || name.ends_with(".wasm")
            || dir.starts_with("/usr/bin")
            || dir.starts_with("/bin")
        {
            0o755
        } else {
            0o644
        };
        out.push(Entry {
            name: name.clone(),
            path: path.to_string_lossy().into_owned(),
            directory: is_dir,
            size: meta.map_or(0, |m| m.len()),
            kind: if is_dir {
                "directory"
            } else {
                os_core::kind(&name)
            }
            .into(),
            mode,
            link: is_link.then(String::new),
            ..Default::default()
        });
    }
    out
}

/// Collect completion candidates for `input` at byte offset `cursor`, combining `os_core::completion`,
/// local VFS entries, `$PATH` executables, shell builtins, and CLI flags.
pub fn complete_input(
    input: &str,
    cursor: usize,
    path_env: &str,
    home: &str,
    read_entries: &dyn Fn(&str) -> Vec<Entry>,
) -> Vec<Candidate> {
    let cursor = cursor.min(input.len());
    let prefix_input = &input[..cursor];
    let (tok_start, _tok_end) = completion::token_span(prefix_input, prefix_input.len());
    let before = &prefix_input[..tok_start];
    let current_tok = &prefix_input[tok_start..];

    // Check option/flag completion when typing `-...` in argument position.
    if current_tok.starts_with('-') && !before.trim().is_empty() {
        let cmd_word = before
            .rsplit('|')
            .next()
            .unwrap_or("")
            .split_whitespace()
            .next()
            .unwrap_or("");
        if let Some(def) = cli::definition(cmd_word) {
            let mut cmd = def.command();
            cmd.build();
            let mut flags = Vec::new();
            for arg in cmd.get_arguments() {
                if arg.is_positional() || arg.is_hide_set() {
                    continue;
                }
                if let Some(short) = arg.get_short() {
                    let label = format!("-{short}");
                    if label.starts_with(current_tok) {
                        let value = format!("{before}{label} ");
                        let c = value.len();
                        flags.push(Candidate {
                            label,
                            value,
                            kind: "flag".into(),
                            descend: false,
                            cursor: c,
                        });
                    }
                }
                if let Some(long) = arg.get_long() {
                    let label = format!("--{long}");
                    if label.starts_with(current_tok) {
                        let value = format!("{before}{label} ");
                        let c = value.len();
                        flags.push(Candidate {
                            label,
                            value,
                            kind: "flag".into(),
                            descend: false,
                            cursor: c,
                        });
                    }
                }
            }
            if !flags.is_empty() {
                flags.sort_by(|a, b| a.label.cmp(&b.label));
                flags.dedup_by(|a, b| a.label == b.label);
                return flags;
            }
        }
    }

    let extra_commands = |needle: &str| -> Vec<Candidate> {
        let mut names = BTreeSet::new();
        for &b in BUILTINS {
            if b != ":" {
                names.insert(b.to_owned());
            }
        }
        for dir in path_env.split(':').filter(|d| !d.is_empty()) {
            for entry in read_entries(dir) {
                if !entry.directory && !entry.name.starts_with('.') {
                    names.insert(entry.name);
                }
            }
        }
        let mut out: Vec<_> = names
            .into_iter()
            .filter_map(|name| {
                let score = completion::fuzzy_score(needle, &name)?;
                let value = format!("{before}{name} ");
                let c = value.len();
                Some((
                    score,
                    Candidate {
                        label: name,
                        value,
                        kind: "command".into(),
                        descend: true,
                        cursor: c,
                    },
                ))
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.label.cmp(&b.1.label)));
        out.into_iter().map(|(_, c)| c).collect()
    };

    match completion::query(prefix_input) {
        Query::Commands(mut cmds) => {
            let mut seen: BTreeSet<String> = cmds.iter().map(|c| c.label.clone()).collect();
            for c in extra_commands(current_tok) {
                if seen.insert(c.label.clone()) {
                    cmds.push(c);
                }
            }
            cmds
        }
        Query::Paths(mut q) => {
            if q.command_position && q.prefix.is_empty() {
                let mut seen: BTreeSet<String> =
                    q.commands.iter().map(|c| c.label.clone()).collect();
                for c in extra_commands(&q.needle) {
                    if seen.insert(c.label.clone()) {
                        q.commands.push(c);
                    }
                }
            }
            let dir = if q.prefix.is_empty() {
                ".".to_owned()
            } else if q.prefix == "~/" {
                home.to_owned()
            } else if let Some(rest) = q.prefix.strip_prefix("~/") {
                format!("{}/{rest}", home.trim_end_matches('/'))
            } else {
                q.prefix.clone()
            };
            let entries = read_entries(&dir);
            completion::path_candidates(&q, &entries)
        }
        Query::None => Vec::new(),
    }
}

/// OSC 7 working-directory notification sequence.
pub fn osc7(cwd: &str) -> String {
    format!("\x1b]7;file://os{cwd}\x07")
}

/// OSC 133;A — prompt start marker.
pub fn osc133_prompt_start() -> &'static str {
    "\x1b]133;A\x07"
}

/// OSC 133;B — command input start marker.
pub fn osc133_cmd_start() -> &'static str {
    "\x1b]133;B\x07"
}

/// OSC 133;C — command execution start marker.
pub fn osc133_cmd_exec() -> &'static str {
    "\x1b]133;C\x07"
}

/// OSC 133;D — command finished with exit code marker.
pub fn osc133_cmd_done(code: i32) -> String {
    format!("\x1b]133;D;{code}\x07")
}

/// Format display cwd, abbreviating `$HOME` prefix as `~`.
pub fn display_cwd(cwd: &str, home: &str) -> String {
    if !home.is_empty() && home != "/" {
        let trimmed = home.trim_end_matches('/');
        if cwd == trimmed {
            return "~".into();
        }
        if let Some(rest) = cwd.strip_prefix(trimmed)
            && rest.starts_with('/')
        {
            return format!("~{rest}");
        }
    }
    cwd.to_owned()
}

/// Format interactive shell prompt text (without OSC wrappers).
pub fn format_prompt(user: &str, cwd: &str, home: &str, uid: u32) -> String {
    let shown = display_cwd(cwd, home);
    let sigil = if uid == 0 { '#' } else { '$' };
    format!("{user}@os:{shown}{sigil} ")
}

/// Decoded terminal keyboard event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyEvent {
    Char(char),
    Enter,
    Backspace,
    Delete,
    Tab,
    BackTab,
    Escape,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    CtrlA,
    CtrlB,
    CtrlC,
    CtrlD,
    CtrlE,
    CtrlF,
    CtrlK,
    CtrlL,
    CtrlN,
    CtrlP,
    CtrlU,
    CtrlW,
    Paste(String),
}

/// Incremental UTF-8 + ANSI CSI/SS3/bracketed-paste input decoder.
#[derive(Default)]
pub struct KeyDecoder {
    buf: Vec<u8>,
    in_paste: bool,
    paste_buf: Vec<u8>,
}

impl KeyDecoder {
    pub fn push(&mut self, bytes: &[u8]) -> Vec<KeyEvent> {
        self.buf.extend_from_slice(bytes);
        let mut events = Vec::new();
        while !self.buf.is_empty() {
            if self.in_paste {
                if let Some(pos) = find_subslice(&self.buf, b"\x1b[201~") {
                    self.paste_buf.extend_from_slice(&self.buf[..pos]);
                    self.buf.drain(..pos + 6);
                    self.in_paste = false;
                    let text = String::from_utf8_lossy(&self.paste_buf).into_owned();
                    self.paste_buf.clear();
                    events.push(KeyEvent::Paste(text));
                    continue;
                }
                // Keep last 5 bytes in case the terminator splits across reads.
                if self.buf.len() > 5 {
                    let keep = self.buf.len() - 5;
                    self.paste_buf.extend_from_slice(&self.buf[..keep]);
                    self.buf.drain(..keep);
                }
                break;
            }

            let b0 = self.buf[0];
            if b0 == 0x1b {
                if self.buf.len() == 1 {
                    // Bare Escape (wait only if caller feeds more in same chunk; here emit Escape).
                    self.buf.remove(0);
                    events.push(KeyEvent::Escape);
                    continue;
                }
                let b1 = self.buf[1];
                if b1 == b'[' {
                    // CSI sequence: find final byte in 0x40..=0x7e.
                    if let Some(end) = self.buf[2..]
                        .iter()
                        .position(|&b| (0x40..=0x7e).contains(&b))
                    {
                        let seq_len = end + 3;
                        let params = &self.buf[2..2 + end];
                        let final_b = self.buf[2 + end];
                        let event = match (params, final_b) {
                            (b"", b'A') => Some(KeyEvent::Up),
                            (b"", b'B') => Some(KeyEvent::Down),
                            (b"", b'C') => Some(KeyEvent::Right),
                            (b"", b'D') => Some(KeyEvent::Left),
                            (b"", b'H') | (b"1", b'~') | (b"7", b'~') => Some(KeyEvent::Home),
                            (b"", b'F') | (b"4", b'~') | (b"8", b'~') => Some(KeyEvent::End),
                            (b"3", b'~') => Some(KeyEvent::Delete),
                            (b"", b'Z') => Some(KeyEvent::BackTab),
                            (b"200", b'~') => {
                                self.buf.drain(..seq_len);
                                self.in_paste = true;
                                self.paste_buf.clear();
                                continue;
                            }
                            _ => None,
                        };
                        self.buf.drain(..seq_len);
                        if let Some(ev) = event {
                            events.push(ev);
                        }
                        continue;
                    }
                    // Incomplete CSI sequence — wait if short, else drop ESC.
                    if self.buf.len() < 16 {
                        break;
                    }
                    self.buf.remove(0);
                    events.push(KeyEvent::Escape);
                    continue;
                }
                if b1 == b'O' {
                    if self.buf.len() < 3 {
                        break;
                    }
                    let b2 = self.buf[2];
                    self.buf.drain(..3);
                    match b2 {
                        b'H' => events.push(KeyEvent::Home),
                        b'F' => events.push(KeyEvent::End),
                        b'A' => events.push(KeyEvent::Up),
                        b'B' => events.push(KeyEvent::Down),
                        b'C' => events.push(KeyEvent::Right),
                        b'D' => events.push(KeyEvent::Left),
                        _ => {}
                    }
                    continue;
                }
                self.buf.remove(0);
                events.push(KeyEvent::Escape);
                continue;
            }

            if b0 < 0x80 {
                self.buf.remove(0);
                match b0 {
                    b'\r' | b'\n' => events.push(KeyEvent::Enter),
                    0x7f | 0x08 => events.push(KeyEvent::Backspace),
                    0x09 => events.push(KeyEvent::Tab),
                    0x01 => events.push(KeyEvent::CtrlA),
                    0x02 => events.push(KeyEvent::CtrlB),
                    0x03 => events.push(KeyEvent::CtrlC),
                    0x04 => events.push(KeyEvent::CtrlD),
                    0x05 => events.push(KeyEvent::CtrlE),
                    0x06 => events.push(KeyEvent::CtrlF),
                    0x0b => events.push(KeyEvent::CtrlK),
                    0x0c => events.push(KeyEvent::CtrlL),
                    0x0e => events.push(KeyEvent::CtrlN),
                    0x10 => events.push(KeyEvent::CtrlP),
                    0x15 => events.push(KeyEvent::CtrlU),
                    0x17 => events.push(KeyEvent::CtrlW),
                    0x20..=0x7e => events.push(KeyEvent::Char(b0 as char)),
                    _ => {}
                }
                continue;
            }

            // Multi-byte UTF-8 sequence.
            let needed = if b0 & 0xe0 == 0xc0 {
                2
            } else if b0 & 0xf0 == 0xe0 {
                3
            } else if b0 & 0xf8 == 0xf0 {
                4
            } else {
                self.buf.remove(0);
                continue;
            };
            if self.buf.len() < needed {
                break;
            }
            if let Ok(s) = std::str::from_utf8(&self.buf[..needed])
                && let Some(ch) = s.chars().next()
            {
                events.push(KeyEvent::Char(ch));
            }
            self.buf.drain(..needed);
        }
        events
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Bounded command history with draft preservation.
#[derive(Clone, Debug, Default)]
pub struct History {
    entries: Vec<String>,
    max_entries: usize,
    browse_index: Option<usize>,
    draft: String,
}

impl History {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_entries: max_entries.max(1),
            browse_index: None,
            draft: String::new(),
        }
    }

    pub fn load_file(&mut self, path: &Path) {
        if let Ok(text) = std::fs::read_to_string(path) {
            for line in text.lines() {
                let trimmed = line.trim_end_matches('\r');
                if !trimmed.is_empty() {
                    self.push_loaded(trimmed.to_owned());
                }
            }
        }
    }

    fn push_loaded(&mut self, entry: String) {
        if self.entries.last().is_some_and(|last| last == &entry) {
            return;
        }
        if self.entries.len() >= self.max_entries {
            self.entries.remove(0);
        }
        self.entries.push(entry);
    }

    pub fn record(&mut self, line: &str, save_path: Option<&Path>) {
        let trimmed = line.trim();
        self.browse_index = None;
        self.draft.clear();
        if trimmed.is_empty() {
            return;
        }
        if self.entries.last().is_some_and(|last| last == trimmed) {
            return;
        }
        if self.entries.len() >= self.max_entries {
            self.entries.remove(0);
        }
        self.entries.push(trimmed.to_owned());
        if let Some(path) = save_path {
            let content = self.entries.join("\n") + "\n";
            let _ = std::fs::write(path, content);
        }
    }

    pub fn entries(&self) -> &[String] {
        &self.entries
    }

    pub fn reset_browse(&mut self) {
        self.browse_index = None;
    }

    pub fn up(&mut self, current: &str) -> Option<String> {
        if self.entries.is_empty() {
            return None;
        }
        let next = match self.browse_index {
            None => {
                self.draft = current.to_owned();
                self.entries.len() - 1
            }
            Some(0) => return None,
            Some(i) => i - 1,
        };
        self.browse_index = Some(next);
        Some(self.entries[next].clone())
    }

    pub fn down(&mut self) -> Option<String> {
        let idx = self.browse_index?;
        if idx + 1 >= self.entries.len() {
            self.browse_index = None;
            Some(std::mem::take(&mut self.draft))
        } else {
            self.browse_index = Some(idx + 1);
            Some(self.entries[idx + 1].clone())
        }
    }
}

/// Active inline completion menu state.
#[derive(Clone, Debug, Default)]
pub struct CompletionState {
    pub candidates: Vec<Candidate>,
    pub selected: Option<usize>,
    pub suffix_after_token: String,
}

impl CompletionState {
    pub fn clear(&mut self) {
        self.candidates.clear();
        self.selected = None;
        self.suffix_after_token.clear();
    }

    pub fn is_open(&self) -> bool {
        !self.candidates.is_empty()
    }
}

/// Outcome of handling one key event in [`LineEditor`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EditorAction {
    None,
    Redraw,
    Submit(String),
    Cancel,
    Eof,
    Clear,
}

/// Stateful UTF-8 single-line PTY editor with inline completion pager below the active line.
#[derive(Clone, Debug, Default)]
pub struct LineEditor {
    pub buffer: String,
    /// Byte offset in `buffer` (always on a UTF-8 char boundary).
    pub cursor: usize,
    pub completion: CompletionState,
}

impl LineEditor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear_line(&mut self) {
        self.buffer.clear();
        self.cursor = 0;
        self.completion.clear();
    }

    pub fn set_line(&mut self, text: String) {
        self.cursor = text.len();
        self.buffer = text;
        self.completion.clear();
    }

    fn prev_char_boundary(&self, pos: usize) -> usize {
        if pos == 0 {
            return 0;
        }
        let mut i = pos - 1;
        while i > 0 && !self.buffer.is_char_boundary(i) {
            i -= 1;
        }
        i
    }

    fn next_char_boundary(&self, pos: usize) -> usize {
        if pos >= self.buffer.len() {
            return self.buffer.len();
        }
        let mut i = pos + 1;
        while i < self.buffer.len() && !self.buffer.is_char_boundary(i) {
            i += 1;
        }
        i
    }

    pub fn handle_key(
        &mut self,
        key: KeyEvent,
        history: &mut History,
        complete: &dyn Fn(&str, usize) -> Vec<Candidate>,
    ) -> EditorAction {
        match key {
            KeyEvent::Enter => {
                let line = std::mem::take(&mut self.buffer);
                self.cursor = 0;
                self.completion.clear();
                history.reset_browse();
                EditorAction::Submit(line)
            }
            KeyEvent::CtrlC => {
                self.clear_line();
                history.reset_browse();
                EditorAction::Cancel
            }
            KeyEvent::CtrlD => {
                if self.buffer.is_empty() {
                    self.completion.clear();
                    EditorAction::Eof
                } else if self.cursor < self.buffer.len() {
                    let next = self.next_char_boundary(self.cursor);
                    self.buffer.drain(self.cursor..next);
                    self.completion.clear();
                    EditorAction::Redraw
                } else {
                    EditorAction::None
                }
            }
            KeyEvent::CtrlL => EditorAction::Clear,
            KeyEvent::Escape => {
                if self.completion.is_open() {
                    self.completion.clear();
                    EditorAction::Redraw
                } else {
                    EditorAction::None
                }
            }
            KeyEvent::Char(c) => {
                self.buffer.insert(self.cursor, c);
                self.cursor += c.len_utf8();
                self.completion.clear();
                history.reset_browse();
                EditorAction::Redraw
            }
            KeyEvent::Paste(text) => {
                let sanitized = text.replace('\r', "");
                self.buffer.insert_str(self.cursor, &sanitized);
                self.cursor += sanitized.len();
                self.completion.clear();
                history.reset_browse();
                EditorAction::Redraw
            }
            KeyEvent::Backspace => {
                if self.cursor > 0 {
                    let prev = self.prev_char_boundary(self.cursor);
                    self.buffer.drain(prev..self.cursor);
                    self.cursor = prev;
                    self.completion.clear();
                    history.reset_browse();
                    EditorAction::Redraw
                } else {
                    EditorAction::None
                }
            }
            KeyEvent::Delete => {
                if self.cursor < self.buffer.len() {
                    let next = self.next_char_boundary(self.cursor);
                    self.buffer.drain(self.cursor..next);
                    self.completion.clear();
                    history.reset_browse();
                    EditorAction::Redraw
                } else {
                    EditorAction::None
                }
            }
            KeyEvent::Left | KeyEvent::CtrlB => {
                if self.cursor > 0 {
                    self.cursor = self.prev_char_boundary(self.cursor);
                    EditorAction::Redraw
                } else {
                    EditorAction::None
                }
            }
            KeyEvent::Right | KeyEvent::CtrlF => {
                if self.cursor < self.buffer.len() {
                    self.cursor = self.next_char_boundary(self.cursor);
                    EditorAction::Redraw
                } else {
                    EditorAction::None
                }
            }
            KeyEvent::Home | KeyEvent::CtrlA => {
                if self.cursor != 0 {
                    self.cursor = 0;
                    EditorAction::Redraw
                } else {
                    EditorAction::None
                }
            }
            KeyEvent::End | KeyEvent::CtrlE => {
                if self.cursor != self.buffer.len() {
                    self.cursor = self.buffer.len();
                    EditorAction::Redraw
                } else {
                    EditorAction::None
                }
            }
            KeyEvent::CtrlU => {
                if self.cursor > 0 {
                    self.buffer.drain(..self.cursor);
                    self.cursor = 0;
                    self.completion.clear();
                    history.reset_browse();
                    EditorAction::Redraw
                } else {
                    EditorAction::None
                }
            }
            KeyEvent::CtrlK => {
                if self.cursor < self.buffer.len() {
                    self.buffer.truncate(self.cursor);
                    self.completion.clear();
                    history.reset_browse();
                    EditorAction::Redraw
                } else {
                    EditorAction::None
                }
            }
            KeyEvent::CtrlW => {
                if self.cursor == 0 {
                    return EditorAction::None;
                }
                let mut pos = self.cursor;
                while pos > 0 {
                    let prev = self.prev_char_boundary(pos);
                    if !self.buffer[prev..pos].chars().all(char::is_whitespace) {
                        break;
                    }
                    pos = prev;
                }
                while pos > 0 {
                    let prev = self.prev_char_boundary(pos);
                    if self.buffer[prev..pos].chars().all(char::is_whitespace) {
                        break;
                    }
                    pos = prev;
                }
                self.buffer.drain(pos..self.cursor);
                self.cursor = pos;
                self.completion.clear();
                history.reset_browse();
                EditorAction::Redraw
            }
            KeyEvent::Up | KeyEvent::CtrlP => {
                if let Some(prev) = history.up(&self.buffer) {
                    self.set_line(prev);
                    EditorAction::Redraw
                } else {
                    EditorAction::None
                }
            }
            KeyEvent::Down | KeyEvent::CtrlN => {
                if let Some(next) = history.down() {
                    self.set_line(next);
                    EditorAction::Redraw
                } else {
                    EditorAction::None
                }
            }
            KeyEvent::Tab => self.step_completion(false, complete),
            KeyEvent::BackTab => self.step_completion(true, complete),
        }
    }

    fn apply_candidate(&mut self, idx: usize) {
        let Some(cand) = self.completion.candidates.get(idx).cloned() else {
            return;
        };
        let suffix = self.completion.suffix_after_token.clone();
        self.buffer = format!("{}{}", cand.value, suffix);
        self.cursor = cand.cursor.min(self.buffer.len());
    }

    fn step_completion(
        &mut self,
        reverse: bool,
        complete: &dyn Fn(&str, usize) -> Vec<Candidate>,
    ) -> EditorAction {
        if self.completion.is_open() {
            let len = self.completion.candidates.len();
            let next = match (self.completion.selected, reverse) {
                (None, false) => 0,
                (None, true) => len - 1,
                (Some(i), false) => (i + 1) % len,
                (Some(i), true) => (i + len - 1) % len,
            };
            self.completion.selected = Some(next);
            self.apply_candidate(next);
            return EditorAction::Redraw;
        }

        let (_, tok_end) = completion::token_span(&self.buffer, self.cursor);
        let suffix = self.buffer[tok_end..].to_owned();
        let candidates = complete(&self.buffer, tok_end);
        if candidates.is_empty() {
            return EditorAction::None;
        }
        if candidates.len() == 1 {
            let cand = &candidates[0];
            self.buffer = format!("{}{}", cand.value, suffix);
            self.cursor = cand.cursor.min(self.buffer.len());
            self.completion.clear();
            return EditorAction::Redraw;
        }
        let current_prefix = &self.buffer[..tok_end];
        let shared = completion::common_prefix(current_prefix, &candidates);
        if shared.len() > current_prefix.len() {
            self.buffer = format!("{shared}{suffix}");
            self.cursor = shared.len();
            self.completion = CompletionState {
                candidates,
                selected: None,
                suffix_after_token: suffix,
            };
            return EditorAction::Redraw;
        }
        let chosen = if reverse { candidates.len() - 1 } else { 0 };
        self.completion = CompletionState {
            candidates,
            selected: Some(chosen),
            suffix_after_token: suffix,
        };
        self.apply_candidate(chosen);
        EditorAction::Redraw
    }

    /// Render the active prompt + edit buffer, plus inline completion candidates **below**
    /// the active line while keeping the cursor positioned right on the active edit line.
    pub fn render(&self, prompt: &str, cols: usize) -> String {
        let cols = cols.max(20);
        let mut out = String::new();
        // Return to column 1, print prompt + buffer, clear rest of screen below.
        out.push('\r');
        out.push_str(prompt);
        out.push_str(&self.buffer);
        out.push_str("\x1b[J");

        let prompt_chars = prompt.chars().count();
        let buf_before_cursor = self.buffer[..self.cursor].chars().count();
        let buf_total_chars = self.buffer.chars().count();
        let end_col = prompt_chars + buf_total_chars;
        let cursor_col = prompt_chars + buf_before_cursor;

        // Render completion pager strictly below the active line.
        let mut pager_lines = 0usize;
        if self.completion.is_open() {
            let max_items = 24usize;
            let items =
                &self.completion.candidates[..self.completion.candidates.len().min(max_items)];
            let col_w = items
                .iter()
                .map(|c| c.label.chars().count())
                .max()
                .unwrap_or(8)
                .clamp(8, 28)
                + 2;
            let per_row = (cols / col_w).max(1);
            for (row_idx, chunk) in items.chunks(per_row).take(6).enumerate() {
                out.push_str("\r\n");
                pager_lines += 1;
                for (i, cand) in chunk.iter().enumerate() {
                    let abs_idx = row_idx * per_row + i;
                    let selected = self.completion.selected == Some(abs_idx);
                    if selected {
                        out.push_str("\x1b[7m");
                    } else {
                        out.push_str("\x1b[2m");
                    }
                    out.push_str(&cand.label);
                    out.push_str("\x1b[0m");
                    let pad = col_w.saturating_sub(cand.label.chars().count());
                    for _ in 0..pad {
                        out.push(' ');
                    }
                }
            }
        }

        // Move cursor back up from pager (and/or wrapped lines) onto the cursor's exact position.
        let end_row = end_col / cols;
        let cursor_row = cursor_col / cols;
        let up = pager_lines + end_row.saturating_sub(cursor_row);
        if up > 0 {
            out.push_str(&format!("\x1b[{up}A"));
        }
        let target_col = (cursor_col % cols) + 1;
        out.push_str(&format!("\x1b[{target_col}G"));
        out
    }
}

/// Lifecycle state of one shell job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobState {
    Running,
    Stopped(u32),
    Done(i32),
}

/// Tracked pipeline job inside `/usr/bin/osh`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    pub id: u32,
    pub pgid: u32,
    pub pids: Vec<u32>,
    pub alive: BTreeSet<u32>,
    pub command: String,
    pub state: JobState,
    pub last_status: i32,
    pub notified: bool,
}

/// Shell job table for `jobs`, `fg`, `bg`, `kill %N`, and `SIGHUP` propagation.
#[derive(Clone, Debug, Default)]
pub struct JobTable {
    next_id: u32,
    jobs: BTreeMap<u32, Job>,
    order: Vec<u32>,
}

impl JobTable {
    pub fn new() -> Self {
        Self {
            next_id: 1,
            jobs: BTreeMap::new(),
            order: Vec::new(),
        }
    }

    pub fn insert(&mut self, pgid: u32, pids: Vec<u32>, command: String, state: JobState) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        let alive: BTreeSet<u32> = pids.iter().copied().collect();
        self.jobs.insert(
            id,
            Job {
                id,
                pgid,
                pids,
                alive,
                command,
                state,
                last_status: 0,
                notified: false,
            },
        );
        self.touch(id);
        id
    }

    pub fn touch(&mut self, id: u32) {
        self.order.retain(|&x| x != id);
        self.order.push(id);
    }

    pub fn get(&self, id: u32) -> Option<&Job> {
        self.jobs.get(&id)
    }

    pub fn get_mut(&mut self, id: u32) -> Option<&mut Job> {
        self.jobs.get_mut(&id)
    }

    pub fn remove(&mut self, id: u32) -> Option<Job> {
        self.order.retain(|&x| x != id);
        self.jobs.remove(&id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Job> {
        self.jobs.values()
    }

    /// Process groups of all active (running or stopped) jobs, used for `SIGHUP` forwarding.
    pub fn active_pgids(&self) -> Vec<u32> {
        self.jobs
            .values()
            .filter(|j| !matches!(j.state, JobState::Done(_)))
            .map(|j| j.pgid)
            .collect()
    }

    /// Resolve a job specification (`None`, `"%1"`, `"1"`, `"%+"`, `"%%"`, `"%-"`, `"%sleep"`).
    pub fn resolve(&self, spec: Option<&str>) -> Result<u32, String> {
        let current = self.order.last().copied();
        let previous = if self.order.len() >= 2 {
            Some(self.order[self.order.len() - 2])
        } else {
            current
        };
        let Some(raw) = spec else {
            return current.ok_or_else(|| "no current job".into());
        };
        let s = raw.strip_prefix('%').unwrap_or(raw);
        if s.is_empty() || s == "+" || s == "%" {
            return current.ok_or_else(|| format!("{raw}: no such job"));
        }
        if s == "-" {
            return previous.ok_or_else(|| format!("{raw}: no such job"));
        }
        if let Ok(num) = s.parse::<u32>() {
            return self
                .jobs
                .contains_key(&num)
                .then_some(num)
                .ok_or_else(|| format!("{raw}: no such job"));
        }
        let matches: Vec<u32> = self
            .jobs
            .values()
            .filter(|j| j.command.starts_with(s))
            .map(|j| j.id)
            .collect();
        match matches.as_slice() {
            [only] => Ok(*only),
            [] => Err(format!("{raw}: no such job")),
            _ => Err(format!("{raw}: ambiguous job spec")),
        }
    }

    /// Record a `waitpid2` status update for child `pid`.
    pub fn on_wait(
        &mut self,
        pid: u32,
        exited_status: Option<i32>,
        stopped_sig: Option<u32>,
        continued: bool,
    ) {
        let Some((&id, _)) = self.jobs.iter().find(|(_, j)| j.pids.contains(&pid)) else {
            return;
        };
        if let Some(job) = self.jobs.get_mut(&id) {
            if let Some(code) = exited_status {
                job.alive.remove(&pid);
                if job.pids.last() == Some(&pid) || job.alive.is_empty() {
                    job.last_status = code;
                }
                if job.alive.is_empty() {
                    job.state = JobState::Done(job.last_status);
                    job.notified = false;
                }
            } else if let Some(sig) = stopped_sig {
                job.state = JobState::Stopped(sig);
                job.notified = false;
            } else if continued {
                job.state = JobState::Running;
                job.notified = false;
            }
        }
    }

    /// Collect and prune finished job notifications to display before the next prompt.
    pub fn drain_notifications(&mut self) -> Vec<String> {
        let mut lines = Vec::new();
        let mut finished = Vec::new();
        for (&id, job) in &mut self.jobs {
            if !job.notified {
                match job.state {
                    JobState::Done(code) => {
                        let status = if code == 0 {
                            "Done".to_owned()
                        } else {
                            format!("Exit {code}")
                        };
                        lines.push(format!("[{id}]  {status:<12} {}", job.command));
                        finished.push(id);
                    }
                    JobState::Stopped(sig) => {
                        lines.push(format!("[{id}]+ Stopped({sig})  {}", job.command));
                        job.notified = true;
                    }
                    JobState::Running => {
                        job.notified = true;
                    }
                }
            }
        }
        for id in finished {
            self.remove(id);
        }
        lines
    }

    /// Format the `jobs` builtin listing.
    pub fn format_list(&self, filter: Option<&str>) -> Result<String, String> {
        let current = self.order.last().copied();
        let previous = if self.order.len() >= 2 {
            Some(self.order[self.order.len() - 2])
        } else {
            None
        };
        let ids: Vec<u32> = match filter {
            Some(spec) => vec![self.resolve(Some(spec))?],
            None => self.jobs.keys().copied().collect(),
        };
        let mut out = String::new();
        for id in ids {
            let job = &self.jobs[&id];
            let marker = if current == Some(id) {
                '+'
            } else if previous == Some(id) {
                '-'
            } else {
                ' '
            };
            let state = match job.state {
                JobState::Running => "Running".to_owned(),
                JobState::Stopped(_) => "Stopped".to_owned(),
                JobState::Done(0) => "Done".to_owned(),
                JobState::Done(code) => format!("Exit {code}"),
            };
            out.push_str(&format!("[{id}]{marker}  {state:<10} {}\n", job.command));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_lookup<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| vars.iter().find(|(n, _)| *n == k).map(|(_, v)| (*v).into())
    }

    #[test]
    fn parse_line_handles_quoting_vars_pipes_redirs_and_background() {
        let lookup = env_lookup(&[("HOME", "/home/alice"), ("GREETING", "hello world")]);
        let items = parse_line(
            "FOO=1 echo \"$GREETING\" '$GREETING' ~/notes.txt 2>&1 | wc -c > /tmp/out.txt &",
            &lookup,
            42,
            7,
        )
        .unwrap();
        assert_eq!(items.len(), 1);
        assert!(items[0].pipeline.background);
        assert_eq!(items[0].pipeline.stages.len(), 2);
        let s0 = &items[0].pipeline.stages[0];
        assert_eq!(s0.assignments, vec![("FOO".into(), "1".into())]);
        let texts: Vec<&str> = s0.words.iter().map(|w| w.text.as_str()).collect();
        assert_eq!(
            texts,
            ["echo", "hello world", "$GREETING", "/home/alice/notes.txt"]
        );
        assert_eq!(s0.redirs, vec![Redir::StderrToStdout]);
        let s1 = &items[0].pipeline.stages[1];
        assert_eq!(
            s1.words.iter().map(|w| w.text.as_str()).collect::<Vec<_>>(),
            ["wc", "-c"]
        );
        assert_eq!(
            s1.redirs,
            vec![Redir::StdoutTrunc(Word {
                text: "/tmp/out.txt".into(),
                pattern: None
            })]
        );
    }

    #[test]
    fn parse_line_handles_status_pid_connectors_and_append_redirs() {
        let lookup = env_lookup(&[("X", "val")]);
        let items = parse_line(
            "echo $? $$ ${X} >> a.log && cat < a.log || echo fail 2> err.log",
            &lookup,
            7,
            99,
        )
        .unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].connector, Connector::Seq);
        assert_eq!(items[1].connector, Connector::And);
        assert_eq!(items[2].connector, Connector::Or);
        let s0_texts: Vec<&str> = items[0].pipeline.stages[0]
            .words
            .iter()
            .map(|w| w.text.as_str())
            .collect();
        assert_eq!(s0_texts, ["echo", "7", "99", "val"]);
        assert!(matches!(
            items[0].pipeline.stages[0].redirs[0],
            Redir::StdoutAppend(_)
        ));
        assert!(matches!(
            items[1].pipeline.stages[0].redirs[0],
            Redir::Stdin(_)
        ));
        assert!(matches!(
            items[2].pipeline.stages[0].redirs[0],
            Redir::StderrTrunc(_)
        ));
    }

    #[test]
    fn expand_word_glob_sorts_and_respects_dotfiles_and_fallback() {
        let reader = |dir: &str| {
            assert_eq!(dir, "docs/");
            vec![
                ".secret.md".into(),
                "b.md".into(),
                "a.md".into(),
                "c.txt".into(),
            ]
        };
        let w = Word {
            text: "docs/*.md".into(),
            pattern: Some("docs/*.md".into()),
        };
        assert_eq!(
            expand_word_glob(&w, &reader),
            vec!["docs/a.md", "docs/b.md"]
        );
        let w_none = Word {
            text: "docs/*.rs".into(),
            pattern: Some("docs/*.rs".into()),
        };
        assert_eq!(expand_word_glob(&w_none, &reader), vec!["docs/*.rs"]);
    }

    #[test]
    fn key_decoder_handles_utf8_csi_arrows_shift_tab_and_bracketed_paste() {
        let mut dec = KeyDecoder::default();
        let events = dec.push(b"a\xc3\xa9\x1b[A\x1b[D\x1b[3~\x1b[Z\x1b[200~hi there\x1b[201~\r");
        assert_eq!(
            events,
            vec![
                KeyEvent::Char('a'),
                KeyEvent::Char('é'),
                KeyEvent::Up,
                KeyEvent::Left,
                KeyEvent::Delete,
                KeyEvent::BackTab,
                KeyEvent::Paste("hi there".into()),
                KeyEvent::Enter,
            ]
        );
    }

    #[test]
    fn line_editor_utf8_editing_history_draft_and_completion_pager() {
        let mut ed = LineEditor::new();
        let mut hist = History::new(16);
        hist.record("echo first", None);
        hist.record("ls /tmp", None);
        let no_comp = |_: &str, _: usize| Vec::new();

        for ch in "café".chars() {
            ed.handle_key(KeyEvent::Char(ch), &mut hist, &no_comp);
        }
        assert_eq!(ed.buffer, "café");
        ed.handle_key(KeyEvent::Left, &mut hist, &no_comp);
        ed.handle_key(KeyEvent::Char('!'), &mut hist, &no_comp);
        assert_eq!(ed.buffer, "caf!é");
        ed.handle_key(KeyEvent::CtrlA, &mut hist, &no_comp);
        assert_eq!(ed.cursor, 0);
        ed.handle_key(KeyEvent::CtrlE, &mut hist, &no_comp);
        assert_eq!(ed.cursor, ed.buffer.len());
        // History Up preserves in-progress draft, Down restores it.
        ed.handle_key(KeyEvent::Up, &mut hist, &no_comp);
        assert_eq!(ed.buffer, "ls /tmp");
        ed.handle_key(KeyEvent::Up, &mut hist, &no_comp);
        assert_eq!(ed.buffer, "echo first");
        ed.handle_key(KeyEvent::Down, &mut hist, &no_comp);
        assert_eq!(ed.buffer, "ls /tmp");
        ed.handle_key(KeyEvent::Down, &mut hist, &no_comp);
        assert_eq!(ed.buffer, "caf!é");

        // Completion pager stays below the active line and returns cursor up.
        ed.set_line("al".into());
        let comp = |_: &str, _: usize| {
            vec![
                Candidate {
                    label: "alpha.txt".into(),
                    value: "alpha.txt ".into(),
                    kind: "text".into(),
                    descend: false,
                    cursor: 10,
                },
                Candidate {
                    label: "alphabet.txt".into(),
                    value: "alphabet.txt ".into(),
                    kind: "text".into(),
                    descend: false,
                    cursor: 13,
                },
            ]
        };
        ed.handle_key(KeyEvent::Tab, &mut hist, &comp);
        assert_eq!(ed.buffer, "alpha");
        assert!(ed.completion.is_open());
        let rendered = ed.render("alice@os:~$ ", 80);
        assert!(rendered.contains("\r\n"));
        assert!(rendered.contains("\x1b[1A"));
        // Shift+Tab cycles backward, Escape dismisses pager.
        ed.handle_key(KeyEvent::BackTab, &mut hist, &comp);
        assert_eq!(ed.buffer, "alphabet.txt ");
        ed.handle_key(KeyEvent::Escape, &mut hist, &comp);
        assert!(!ed.completion.is_open());
    }

    #[test]
    fn job_table_tracks_resolution_notifications_and_active_pgids() {
        let mut jobs = JobTable::new();
        let j1 = jobs.insert(101, vec![101], "sleep 10 &".into(), JobState::Running);
        let j2 = jobs.insert(
            202,
            vec![202, 203],
            "cat | wc".into(),
            JobState::Stopped(20),
        );
        assert_eq!(jobs.resolve(None).unwrap(), j2);
        assert_eq!(jobs.resolve(Some("%+")).unwrap(), j2);
        assert_eq!(jobs.resolve(Some("%-")).unwrap(), j1);
        assert_eq!(jobs.resolve(Some("%sleep")).unwrap(), j1);
        assert_eq!(jobs.active_pgids(), vec![101, 202]);

        jobs.on_wait(101, Some(0), None, false);
        let notes = jobs.drain_notifications();
        assert!(
            notes
                .iter()
                .any(|n| n.contains("[1]") && n.contains("Done"))
        );
        assert_eq!(jobs.active_pgids(), vec![202]);
    }

    #[test]
    fn osc_and_prompt_formatting_abbreviate_home() {
        assert_eq!(
            osc7("/home/alice/docs"),
            "\x1b]7;file://os/home/alice/docs\x07"
        );
        assert_eq!(osc133_prompt_start(), "\x1b]133;A\x07");
        assert_eq!(osc133_cmd_done(0), "\x1b]133;D;0\x07");
        assert_eq!(
            format_prompt("alice", "/home/alice", "/home/alice", 1000),
            "alice@os:~$ "
        );
        assert_eq!(
            format_prompt("alice", "/home/alice/docs", "/home/alice", 1000),
            "alice@os:~/docs$ "
        );
        assert_eq!(format_prompt("root", "/etc", "/root", 0), "root@os:/etc# ");
    }

    #[test]
    fn parse_line_with_subst_expands_quoted_and_nested_command_substitutions() {
        let lookup = env_lookup(&[]);
        let mut subst = |cmd: &str| match cmd.trim() {
            "sudo id -u" => Ok("0".into()),
            "echo $(id -u)" => Ok("1000".into()),
            other => Ok(format!("[{other}]")),
        };
        let items = parse_line_with_subst(
            "echo \"SUDO_UID=$(sudo id -u)\" '$(sudo id -u)' $(echo $(id -u))",
            &lookup,
            &mut subst,
            0,
            42,
        )
        .unwrap();
        let texts: Vec<&str> = items[0].pipeline.stages[0]
            .words
            .iter()
            .map(|w| w.text.as_str())
            .collect();
        assert_eq!(texts, ["echo", "SUDO_UID=0", "$(sudo id -u)", "1000"]);
        assert!(parse_line_with_subst("echo $(unclosed", &lookup, &mut subst, 0, 42).is_err());
    }
}

//! Completion matching and tolerant parsing, independent of the browser.
use clap::{Arg, Command, ValueHint};

use crate::Entry;

#[derive(Clone, Debug)]
pub struct Candidate {
    pub label: String,
    pub value: String,
    pub kind: String,
    pub descend: bool,
}
#[derive(Clone, Debug)]
pub struct PathQuery {
    pub head: String,
    pub prefix: String,
    pub needle: String,
    pub directories_only: bool,
    pub auto_open: bool,
}

/// Exact, prefix, substring, then ordered subsequence. Case-insensitive Unicode;
/// tighter subsequences rank ahead of scattered matches. No typo correction.
pub fn fuzzy_score(needle: &str, name: &str) -> Option<(u8, usize, usize, usize)> {
    let needle = needle.to_lowercase();
    let name = name.to_lowercase();
    if needle.is_empty() {
        return Some((0, 0, 0, 0));
    }
    let n: Vec<_> = needle.chars().collect();
    let s: Vec<_> = name.chars().collect();
    if needle == name {
        return Some((0, 0, 0, s.len()));
    }
    if name.starts_with(&needle) {
        return Some((1, 0, 0, s.len()));
    }
    if let Some(start) = name.find(&needle) {
        return Some((2, 0, name[..start].chars().count(), s.len()));
    }
    let mut best = None;
    for start in 0..s.len() {
        if s[start] != n[0] {
            continue;
        }
        let mut pos = start + 1;
        let mut matched = true;
        for c in &n[1..] {
            while pos < s.len() && s[pos] != *c {
                pos += 1;
            }
            if pos == s.len() {
                matched = false;
                break;
            }
            pos += 1;
        }
        if matched {
            let score = (3, pos - start - n.len(), start, s.len());
            best = Some(best.map_or(score, |old| std::cmp::min(old, score)));
        }
    }
    best
}

/// Unlike the command parser, tolerate an unfinished quote/escape at the end. Each word comes
/// with how to type it again: quoted by [`quote_word`], or, if it has wildcards outside quotes,
/// as it was typed, so that they still expand and quoted ones stay literal.
fn partial_words(input: &str) -> (Vec<String>, Vec<String>) {
    let mut words = Vec::new();
    let mut typed = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escaped = false;
    let mut active = false;
    let mut wild = false;
    let mut start = 0;
    for (i, c) in input.char_indices() {
        if !active && !c.is_whitespace() {
            start = i;
        }
        if escaped {
            // A backslash and a newline join two lines.
            if c != '\n' {
                word.push(c);
            }
            escaped = false;
            active = true;
            continue;
        }
        if c == '\\' && crate::escapes(quote, input[i + 1..].chars().next()) {
            escaped = true;
            active = true;
            continue;
        }
        if let Some(q) = quote {
            if c == q {
                quote = None;
            } else {
                word.push(c);
            }
        } else if c == '\'' || c == '"' {
            quote = Some(c);
            active = true;
        } else if c.is_whitespace() {
            if active {
                typed.push(retyped(&word, std::mem::take(&mut wild), &input[start..i]));
                words.push(std::mem::take(&mut word));
                active = false;
            }
        } else {
            word.push(c);
            wild |= matches!(c, '*' | '?' | '[');
            active = true;
        }
    }
    // The empty final argument in `open ` is meaningful.
    typed.push(retyped(
        &word,
        wild,
        if active { &input[start..] } else { "" },
    ));
    words.push(word);
    (words, typed)
}
fn retyped(word: &str, wild: bool, raw: &str) -> String {
    if wild { raw.into() } else { quote_word(word) }
}
fn quote(path: &str) -> String {
    format!("\"{}\"", path.replace('\\', "\\\\").replace('"', "\\\""))
}

pub enum Query {
    Commands(Vec<Candidate>),
    Paths(PathQuery),
    None,
}
/// Whether the word being typed, the last of `words`, is a path, as the command's definition
/// says of the operand or option value it is: `Some(true)` a directory, `Some(false)` any path,
/// `None` not a path (an option, a mode, a user, a pattern...).
fn path_operand(words: &[String]) -> Option<bool> {
    let mut command = crate::cli::definition(&words[0])?.command();
    command.build();
    let hint = |arg: &Arg| match arg.get_value_hint() {
        ValueHint::DirPath => Some(true),
        ValueHint::AnyPath | ValueHint::FilePath => Some(false),
        _ => None,
    };
    let (last, before) = words[1..].split_last()?;
    let mut operands = 0;
    let mut ended = false;
    let mut value_of = None;
    for word in before {
        if value_of.take().is_some() {
            continue;
        }
        if !ended && word == "--" {
            ended = true;
        } else if let Some(option) = (!ended).then(|| option(&command, word)).flatten() {
            value_of = option;
        } else {
            operands += 1;
        }
    }
    if let Some(arg) = value_of {
        return hint(arg);
    }
    if !ended && (last == "--" || option(&command, last).is_some()) {
        return None;
    }
    // The operand at its place, or one before it that takes all that follow.
    let mut place = operands;
    for arg in command.get_positionals() {
        if place == 0 || arg.get_num_args().is_some_and(|n| n.max_values() > 1) {
            return hint(arg);
        }
        place -= 1;
    }
    None
}

/// Whether `word` is one of `command`'s options, and if so, the option whose value is the next
/// word, if it takes one that is not attached (`-f` in `-czf a.tgz`, `--file a.tgz`). A word
/// that is not an option is an operand, as a mode like -w is to chmod.
fn option<'a>(command: &'a Command, word: &str) -> Option<Option<&'a Arg>> {
    let takes = |arg: &Arg| arg.get_action().takes_values();
    if let Some(long) = word.strip_prefix("--") {
        let (name, attached) = long
            .split_once('=')
            .map_or((long, false), |(n, _)| (n, true));
        let arg = command.get_arguments().find(|a| {
            a.get_long() == Some(name) || a.get_all_aliases().is_some_and(|v| v.contains(&name))
        });
        return Some(arg.filter(|a| takes(a) && !attached));
    }
    let letters = word.strip_prefix('-').filter(|l| !l.is_empty())?;
    // Flags, then perhaps one option taking a value: the rest of the word, or the next.
    for (at, letter) in letters.char_indices() {
        let arg = command.get_arguments().find(|a| {
            a.get_short() == Some(letter)
                || a.get_all_short_aliases()
                    .is_some_and(|v| v.contains(&letter))
        })?;
        if takes(arg) {
            return Some((at + letter.len_utf8() == letters.len()).then_some(arg));
        }
    }
    Some(None)
}

/// `input` split before its last pipeline stage: what precedes it, with the `|`, and the stage.
fn last_stage(input: &str) -> (&str, &str) {
    let mut quote = None;
    let mut escaped = false;
    let mut split = 0;
    for (i, c) in input.char_indices() {
        if escaped {
            escaped = false;
        } else if c == '\\' && quote != Some('\'') {
            escaped = true;
        } else if let Some(q) = quote {
            if c == q {
                quote = None;
            }
        } else if c == '\'' || c == '"' {
            quote = Some(c);
        } else if c == '|' {
            split = i + 1;
        }
    }
    let stage = &input[split..];
    let start = split + (stage.len() - stage.trim_start().len());
    (&input[..start], &input[start..])
}

/// Where, in `words`, the command that this command runs starts: after xargs and its options,
/// after sudo, or after fd's -x or -X.
fn nested(words: &[String]) -> Option<usize> {
    let at = match words[0].as_str() {
        "xargs" => {
            let mut i = 1;
            while i < words.len() - 1 && words[i].starts_with('-') {
                i += if ["-d", "-n", "-I", "-L"].contains(&words[i].as_str()) {
                    2
                } else {
                    1
                };
            }
            i
        }
        "sudo" if words.len() > 1 && !["-u", "-k"].contains(&words[1].as_str()) => 1,
        "fd" => {
            words
                .iter()
                .position(|w| ["-x", "-X", "--exec", "--exec-batch"].contains(&w.as_str()))?
                + 1
        }
        _ => return None,
    };
    (at < words.len()).then_some(at)
}

pub fn query(input: &str) -> Query {
    let (before, stage) = last_stage(input);
    let (words, typed) = partial_words(stage);
    query_words(before.trim_end(), &words, &typed, before.is_empty())
}

/// Complete `words`, a command and its arguments, typed after `context` on the line, each of
/// them typed again as `typed` says. Only the line's first command, alone, may also complete as
/// a path to open or enter.
fn query_words(context: &str, words: &[String], typed: &[String], first: bool) -> Query {
    let after = |head: &str| match (context.is_empty(), head.is_empty()) {
        (true, _) => head.to_string(),
        (false, true) => context.to_string(),
        (false, false) => format!("{context} {head}"),
    };
    let command = words[0].as_str();
    let auto_open = words.len() == 1 && first;
    if words.len() == 1 && (!command.is_empty() || !first) {
        // Every command defined, as help lists them, and /bin's programs the shell has none
        // of its own for.
        let names = crate::cli::names();
        let mut commands: Vec<_> = names
            .iter()
            .map(String::as_str)
            .chain(
                crate::bin::PROGRAMS
                    .iter()
                    .copied()
                    .filter(|program| !names.iter().any(|name| name == program)),
            )
            .filter_map(|name| {
                fuzzy_score(command, name).map(|score| {
                    (
                        score,
                        Candidate {
                            label: (*name).into(),
                            value: format!("{} ", after(name)),
                            kind: "command".into(),
                            descend: true,
                        },
                    )
                })
            })
            .collect();
        commands.sort_by_key(|(score, _)| *score);
        if !commands.is_empty() {
            return Query::Commands(commands.into_iter().map(|(_, c)| c).collect());
        }
        if !first {
            return Query::None;
        }
    }
    if let Some(at) = nested(words) {
        let head = typed[..at].join(" ");
        return query_words(&after(&head), &words[at..], &typed[at..], false);
    }
    let (head, raw, directories_only) = if auto_open {
        (String::new(), command, false)
    } else if let Some(directories) = path_operand(words) {
        let last = words.last().map_or("", String::as_str);
        (typed[..words.len() - 1].join(" "), last, directories)
    } else {
        return Query::None;
    };
    let (prefix, needle) = raw
        .rfind('/')
        .map_or(("", raw), |i| (&raw[..=i], &raw[i + 1..]));
    Query::Paths(PathQuery {
        head: if auto_open { head } else { after(&head) },
        prefix: prefix.into(),
        needle: needle.into(),
        directories_only,
        auto_open,
    })
}
/// A word as typed again: options and plain words as they are, anything else quoted.
fn quote_word(word: &str) -> String {
    if word.starts_with('-')
        || (!word.is_empty()
            && word
                .chars()
                .all(|c| c.is_alphanumeric() || "._/{}:=,+@%~^-".contains(c)))
    {
        word.into()
    } else {
        quote(word)
    }
}

pub fn path_candidates(query: &PathQuery, entries: &[Entry]) -> Vec<Candidate> {
    let mut hits: Vec<_> = entries
        .iter()
        .filter_map(|entry| {
            if query.directories_only && !entry.directory {
                return None;
            }
            let score = fuzzy_score(&query.needle, &entry.name)?;
            let mut path = format!(
                "{}{}{}",
                query.prefix,
                entry.name,
                if entry.directory { "/" } else { "" }
            );
            // Quoting alone doesn't stop a command from reading a leading '-' as an option.
            if path.starts_with('-') {
                path.insert_str(0, "./");
            }
            let head = if query.auto_open {
                if entry.directory { "cd" } else { "open" }
            } else {
                &query.head
            };
            Some((
                score,
                !entry.directory,
                Candidate {
                    label: format!("{}{}", entry.name, if entry.directory { "/" } else { "" }),
                    value: format!("{head} {}", quote(&path)),
                    kind: entry.kind.clone(),
                    descend: entry.directory,
                },
            ))
        })
        .collect();
    hits.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then(a.1.cmp(&b.1))
            .then(a.2.label.cmp(&b.2.label))
    });
    hits.into_iter().map(|(_, _, c)| c).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::split_command;
    fn entry(name: &str, directory: bool) -> Entry {
        Entry {
            name: name.into(),
            path: format!("/{name}"),
            directory,
            size: 0,
            kind: if directory { "directory" } else { "text" }.into(),
            ..Default::default()
        }
    }
    #[test]
    fn touch_completion_preserves_prior_paths_and_flags() {
        let Query::Paths(q) = query("touch -c \"first file.txt\" -- -no") else {
            panic!()
        };
        let hits = path_candidates(&q, &[entry("-notes.txt", false)]);
        assert_eq!(
            split_command(&hits[0].value).unwrap(),
            ["touch", "-c", "first file.txt", "--", "./-notes.txt"]
        );
    }
    #[test]
    fn pipelines_complete_their_last_stage_and_the_commands_others_run() {
        let Query::Commands(c) = query("ls | gr") else {
            panic!()
        };
        assert_eq!(c[0].value, "ls | grep ");
        let Query::Commands(c) = query("ls -l |") else {
            panic!()
        };
        assert!(c.len() > 10);
        let Query::Commands(c) = query("fd -e md | xargs -0 w") else {
            panic!()
        };
        assert_eq!(c[0].value, "fd -e md | xargs -0 wc ");
        let Query::Paths(q) = query("fd -e md | xargs wc -l no") else {
            panic!()
        };
        assert_eq!(q.head, "fd -e md | xargs wc -l");
        assert!(!q.auto_open);
        let Query::Paths(q) = query("fd -e txt -x mv {} 'old notes/") else {
            panic!()
        };
        assert_eq!(q.head, "fd -e txt -x mv {}");
        assert_eq!(q.prefix, "old notes/");
        let Query::Paths(q) = query("cp -r 'a b' med") else {
            panic!()
        };
        let hits = path_candidates(&q, &[entry("media", true)]);
        assert_eq!(
            split_command(&hits[0].value).unwrap(),
            ["cp", "-r", "a b", "media/"]
        );
        assert!(matches!(query("grep -i"), Query::None));
        assert!(matches!(query("cat x | open"), Query::Commands(_)));
        let Query::Paths(q) = query("sudo rm -r med") else {
            panic!()
        };
        assert_eq!(q.head, "sudo rm -r");
    }
    #[test]
    fn ranking_and_unicode() {
        let rank = |name| fuzzy_score("spec", name).unwrap();
        assert!(rank("SPEC") < rank("Spectrum.txt"));
        assert!(rank("spectrum.txt") < rank("gamma-spec.txt"));
        assert!(rank("gamma-spec.txt") < rank("s_p_e_c.txt"));
        assert!(fuzzy_score("gmsp", "GammaSpectrum.txt").is_some());
        assert!(fuzzy_score("γα", "γάμμα-spectrum.md").is_some());
        assert!(fuzzy_score("αγ", "spéctrum.md").is_none());
        assert!(fuzzy_score("xyz", "hekou.md").is_none());
    }
    #[test]
    fn empty_input_browses_files_and_commands_keep_their_context() {
        let Query::Paths(q) = query("") else { panic!() };
        let hits = path_candidates(&q, &[entry("b.txt", false), entry("media", true)]);
        assert_eq!(hits[0].value, "cd \"media/\"");
        assert_eq!(hits[1].value, "open \"b.txt\"");
        let Query::Paths(q) = query("cd ") else {
            panic!()
        };
        assert_eq!(
            path_candidates(&q, &[entry("b.txt", false), entry("media", true)]).len(),
            1
        );
        let Query::Commands(c) = query("op") else {
            panic!()
        };
        assert_eq!(c[0].value, "open ");
    }
    #[test]
    fn operands_are_paths_where_the_definitions_say() {
        let path = |input: &str| match query(input) {
            Query::Paths(q) => Some((q.head, q.directories_only)),
            _ => None,
        };
        let head = |input: &str| path(input).map(|(head, _)| head);
        // Every command with a path operand completes it, faststart and ln included.
        assert_eq!(head("faststart hol"), Some("faststart".into()));
        assert_eq!(head("ln -s ../notes no"), Some("ln -s ../notes".into()));
        assert_eq!(
            head("setfacl -m u:bob:rw no"),
            Some("setfacl -m u:bob:rw".into())
        );
        // What an option takes next: a directory, an archive, or not a path.
        assert_eq!(path("unzip -d res"), Some(("unzip -d".into(), true)));
        assert_eq!(path("tar -czf no"), Some(("tar -czf".into(), false)));
        assert_eq!(path("tar -C res"), Some(("tar -C".into(), true)));
        assert_eq!(
            path("tar --directory=res -x -f no"),
            Some(("tar --directory=res -x -f".into(), false))
        );
        assert_eq!(path("setfacl -m u:b"), None);
        assert_eq!(
            path("useradd -m -d /ho"),
            Some(("useradd -m -d".into(), true))
        );
        // Operands that are not paths, and those after them that are.
        assert_eq!(path("chmod 6"), None);
        assert_eq!(head("chmod -w no"), Some("chmod -w".into()));
        assert_eq!(path("chown bob"), None);
        assert_eq!(path("fd notes do"), Some(("fd notes".into(), true)));
        assert_eq!(path("fd no"), None);
        assert_eq!(path("su bo"), None);
        assert_eq!(path("cd do"), Some(("cd".into(), true)));
        assert_eq!(path("open a b"), None);
        assert_eq!(path("rm -rf"), None);
    }

    #[test]
    fn quoted_nested_paths_and_rm_flags_survive_completion() {
        for input in [
            "rm -r -- 'media/spé",
            "rm -r -- media/spé",
            "rm -r -- \"media/spé",
        ] {
            let Query::Paths(q) = query(input) else {
                panic!()
            };
            assert_eq!(q.head, "rm -r --");
            assert_eq!(q.prefix, "media/");
            let hits = path_candidates(&q, &[entry("spéctrum \"calibration\".txt", false)]);
            assert_eq!(
                split_command(&hits[0].value).unwrap(),
                ["rm", "-r", "--", "media/spéctrum \"calibration\".txt"]
            );
        }
        // Earlier wildcards keep their meaning: unquoted ones still expand, quoted ones do not.
        for (input, head) in [
            ("rm -rf *.tmp d[1]'*' do", "rm -rf *.tmp d[1]'*'"),
            ("cp '*.md' \"a?\" do", "cp \"*.md\" \"a?\""),
            ("fd -e md -x cp {} *.bak do", "fd -e md -x cp {} *.bak"),
        ] {
            let Query::Paths(q) = query(input) else {
                panic!("{input}")
            };
            assert_eq!(q.head, head, "{input}");
        }
        let Query::Paths(q) = query("rm ") else {
            panic!()
        };
        assert_eq!(
            path_candidates(&q, &[entry("-notes.txt", false)])[0].value,
            "rm \"./-notes.txt\""
        );
    }
}

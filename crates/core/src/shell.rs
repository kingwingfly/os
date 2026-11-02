//! The shell's grammar beyond one command: pipelines, the items xargs reads, and the commands
//! fd -x and -X run. Nothing here runs anything.

/// A word of a command line: its text, and, if it has wildcards outside quotes, the pattern
/// it expands to the paths of, as [`crate::glob`] reads patterns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Word {
    pub text: String,
    pub pattern: Option<String>,
}

/// The line `line` without its last `&`, if that runs it in the background, as a shell's job:
/// an `&` at its end, outside quotes. `&&`, and an `&` alone, are not.
pub fn background(line: &str) -> Option<&str> {
    let stripped = line.trim_end().strip_suffix('&')?.trim_end();
    if stripped.is_empty() || stripped.ends_with('&') || words(line).is_ok() {
        return None;
    }
    words(stripped).is_ok().then_some(stripped)
}

/// The stages of the pipeline `input`, each its words with their patterns, quoted as
/// [`crate::split_command`] quotes them. An unquoted `|` separates stages; the shell's other
/// operators are refused rather than taken as words.
pub fn words(input: &str) -> Result<Vec<Vec<Word>>, String> {
    let mut stages = Vec::new();
    let mut words = Vec::new();
    let mut word = String::new();
    // The word as a pattern: its quoted or escaped wildcards escaped.
    let mut pattern = String::new();
    let mut wild = false;
    let mut quote = None;
    let mut escaped = false;
    let mut active = false;
    let end = |word: &mut String, pattern: &mut String, wild: &mut bool, words: &mut Vec<Word>| {
        let pattern = std::mem::take(pattern);
        words.push(Word {
            text: std::mem::take(word),
            pattern: std::mem::take(wild).then_some(pattern),
        });
    };
    let literal = |c: char, word: &mut String, pattern: &mut String| {
        word.push(c);
        if matches!(c, '*' | '?' | '[' | ']' | '\\' | '-' | '!' | '^') {
            pattern.push('\\');
        }
        pattern.push(c);
    };
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if escaped {
            // A backslash and a newline join two lines.
            if c != '\n' {
                literal(c, &mut word, &mut pattern);
                active = true;
            }
            escaped = false;
            continue;
        }
        if c == '\\' && crate::escapes(quote, chars.peek().copied()) {
            escaped = true;
            continue;
        }
        if let Some(q) = quote {
            if c == q {
                quote = None;
            } else {
                literal(c, &mut word, &mut pattern);
            }
            continue;
        }
        match c {
            '\'' | '"' => {
                quote = Some(c);
                active = true;
            }
            c if c.is_whitespace() => {
                if active {
                    end(&mut word, &mut pattern, &mut wild, &mut words);
                    active = false;
                }
            }
            '|' if chars.peek() == Some(&'|') => return Err(unsupported("||")),
            '|' => {
                if active {
                    end(&mut word, &mut pattern, &mut wild, &mut words);
                    active = false;
                }
                if words.is_empty() {
                    return Err(EMPTY_STAGE.into());
                }
                stages.push(std::mem::take(&mut words));
            }
            '&' if chars.peek() == Some(&'&') => return Err(unsupported("&&")),
            '&' | ';' | '<' | '>' => return Err(unsupported(&c.to_string())),
            c => {
                word.push(c);
                pattern.push(c);
                wild |= matches!(c, '*' | '?' | '[');
                active = true;
            }
        }
    }
    if quote.is_some() || escaped {
        return Err("Unterminated quote or escape".into());
    }
    if active {
        end(&mut word, &mut pattern, &mut wild, &mut words);
    }
    if words.is_empty() {
        return if stages.is_empty() {
            Ok(stages)
        } else {
            Err(EMPTY_STAGE.into())
        };
    }
    stages.push(words);
    Ok(stages)
}
const EMPTY_STAGE: &str = "Each side of | needs a command";
fn unsupported(operator: &str) -> String {
    format!(
        "{operator} is not supported: this terminal runs one command, or commands joined by |; quote it to use it as text"
    )
}

/// How xargs separates the items it reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delimiter {
    /// Blanks and newlines, with quotes and backslashes as GNU xargs reads them.
    Blank,
    /// Lines, without their leading blanks, as `xargs -I` reads them.
    Line,
    /// Exactly this character, as `-d` or `-0` select.
    Char(char),
}

/// The items xargs reads from `input`.
pub fn xargs_items(input: &str, delimiter: Delimiter) -> Result<Vec<String>, String> {
    match delimiter {
        Delimiter::Char(d) => {
            let mut items: Vec<String> = input.split(d).map(String::from).collect();
            // A final delimiter ends the last item; it does not start an empty one.
            if items.last().is_some_and(String::is_empty) {
                items.pop();
            }
            Ok(items)
        }
        Delimiter::Line => Ok(input
            .lines()
            .map(|line| line.trim_start())
            .filter(|line| !line.is_empty())
            .map(String::from)
            .collect()),
        Delimiter::Blank => {
            let mut items = Vec::new();
            let mut item = String::new();
            let mut active = false;
            let mut quote = None;
            let mut chars = input.chars();
            while let Some(c) = chars.next() {
                if let Some(q) = quote {
                    if c == q {
                        quote = None;
                    } else if c == '\n' {
                        return Err(format!(
                            "xargs: unmatched {} quote; use -0 or -d for names with quotes",
                            if q == '\'' { "single" } else { "double" }
                        ));
                    } else {
                        item.push(c);
                    }
                    continue;
                }
                match c {
                    '\'' | '"' => {
                        quote = Some(c);
                        active = true;
                    }
                    '\\' => {
                        if let Some(next) = chars.next() {
                            item.push(next);
                        }
                        active = true;
                    }
                    c if c.is_whitespace() => {
                        if active {
                            items.push(std::mem::take(&mut item));
                            active = false;
                        }
                    }
                    c => {
                        item.push(c);
                        active = true;
                    }
                }
            }
            if let Some(q) = quote {
                return Err(format!(
                    "xargs: unmatched {} quote; use -0 or -d for names with quotes",
                    if q == '\'' { "single" } else { "double" }
                ));
            }
            if active {
                items.push(item);
            }
            Ok(items)
        }
    }
}

/// `template` with each placeholder of fd's replaced, for `path`: `{}` the path, `{/}` its name,
/// `{//}` its parent, `{.}` the path without its extension, and `{/.}` the name without it.
fn expand(template: &str, path: &str) -> String {
    let name = path.rsplit('/').next().unwrap_or(path);
    let parent = match path.rfind('/') {
        Some(0) => "/",
        Some(i) => &path[..i],
        None => ".",
    };
    let stem = |s: &str| -> String {
        let base = s.rsplit('/').next().unwrap_or(s);
        match base.rfind('.') {
            Some(i) if i > 0 => s[..s.len() - (base.len() - i)].to_string(),
            _ => s.to_string(),
        }
    };
    let tokens = [
        ("{//}", parent.to_string()),
        ("{/.}", stem(name)),
        ("{/}", name.to_string()),
        ("{.}", stem(path)),
        ("{}", path.to_string()),
    ];
    // One pass over the template, so that braces in a path put in are never read as another
    // placeholder.
    let mut out = String::new();
    let mut rest = template;
    'next: while let Some(c) = rest.chars().next() {
        for (token, value) in &tokens {
            if let Some(after) = rest.strip_prefix(token) {
                out.push_str(value);
                rest = after;
                continue 'next;
            }
        }
        out.push(c);
        rest = &rest[c.len_utf8()..];
    }
    out
}
fn has_placeholder(arg: &str) -> bool {
    ["{}", "{/}", "{//}", "{.}", "{/.}"]
        .iter()
        .any(|p| arg.contains(p))
}

/// The command `fd -x` runs for one result: the template expanded for `path`, or with the path
/// added if the template has no placeholder.
pub fn exec_one(template: &[String], path: &str) -> Vec<String> {
    let mut command: Vec<String> = template.iter().map(|arg| expand(arg, path)).collect();
    if !template.iter().any(|arg| has_placeholder(arg)) {
        command.push(path.into());
    }
    command
}

/// The command `fd -X` runs once for all results: each argument with a placeholder becomes one
/// argument per path; without any placeholder, the paths are added at the end.
pub fn exec_all(template: &[String], paths: &[String]) -> Vec<String> {
    let mut command = Vec::new();
    for arg in template {
        if has_placeholder(arg) {
            command.extend(paths.iter().map(|path| expand(arg, path)));
        } else {
            command.push(arg.clone());
        }
    }
    if !template.iter().any(|arg| has_placeholder(arg)) {
        command.extend(paths.iter().cloned());
    }
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The words of each stage of `input`, as text.
    fn pipeline(input: &str) -> Result<Vec<Vec<String>>, String> {
        Ok(words(input)?
            .into_iter()
            .map(|stage| stage.into_iter().map(|word| word.text).collect())
            .collect())
    }

    #[test]
    fn an_ampersand_at_the_end_runs_a_line_in_the_background() {
        assert_eq!(background("coreutils sleep 3 &"), Some("coreutils sleep 3"));
        assert_eq!(background("seq 3 | tr 1 x&  "), Some("seq 3 | tr 1 x"));
        // Quoted or escaped, it is text; doubled, or alone, it is no job.
        assert_eq!(background("echo 'a &'"), None);
        assert_eq!(background("echo a\\&"), None);
        assert_eq!(background("a &&"), None);
        assert_eq!(background("&"), None);
        assert_eq!(background("ls"), None);
    }

    #[test]
    fn pipelines_split_on_unquoted_bars_only() {
        assert_eq!(
            pipeline("fd -e md | xargs wc -l").unwrap(),
            [vec!["fd", "-e", "md"], vec!["xargs", "wc", "-l"]]
        );
        assert_eq!(
            pipeline("grep 'a|b' \"x | y\" c\\|d").unwrap(),
            [vec!["grep", "a|b", "x | y", "c|d"]]
        );
        assert_eq!(pipeline("ls|wc").unwrap(), [vec!["ls"], vec!["wc"]]);
        assert!(pipeline("   ").unwrap().is_empty());
        for refused in [
            "ls || pwd",
            "ls && pwd",
            "ls; pwd",
            "ls > out",
            "cat < in",
            "ls &",
        ] {
            assert!(
                pipeline(refused).unwrap_err().contains("not supported"),
                "{refused}"
            );
        }
        for empty in ["| wc", "ls |", "ls | | wc"] {
            assert_eq!(pipeline(empty).unwrap_err(), EMPTY_STAGE, "{empty}");
        }
        assert!(pipeline("echo 'open").is_err());
    }

    #[test]
    fn unquoted_wildcards_make_patterns() {
        let stage = &words(r#"rm -rf * 'a*' "b?" c\* d[1]'*' plain"#).unwrap()[0];
        let patterns: Vec<_> = stage.iter().map(|w| w.pattern.as_deref()).collect();
        assert_eq!(
            patterns,
            [
                None,
                None,
                Some("*"),
                None,
                None,
                None,
                Some("d[1]\\*"),
                None
            ]
        );
        let texts: Vec<_> = stage.iter().map(|w| w.text.as_str()).collect();
        // A backslash kept in double quotes is a character of the name, as a quoted * is.
        let word = &words(r#"ls "x\*"*"#).unwrap()[0][1];
        assert_eq!(word.text, r"x\**");
        let pattern = word.pattern.as_deref().unwrap();
        assert!(crate::glob::matches(pattern, r"x\*.md"));
        assert!(!crate::glob::matches(pattern, "x*.md"));
        assert_eq!(
            texts,
            ["rm", "-rf", "*", "a*", "b?", "c*", "d[1]*", "plain"]
        );
    }

    #[test]
    fn quoted_bracket_characters_stay_literal_during_expansion() {
        for (input, matching, excluded) in [
            (r#"echo [a"-"c]"#, vec!["a", "-", "c"], vec!["b"]),
            (r#"echo ["!"a]"#, vec!["!", "a"], vec!["b"]),
            (r#"echo ["^"a]"#, vec!["^", "a"], vec!["b"]),
            (r#"echo [a-"c"]"#, vec!["a", "b", "c"], vec!["d"]),
            (r#"echo [\[-\]]"#, vec!["[", "]"], vec!["^", "a"]),
        ] {
            let stages = words(input).unwrap();
            let pattern = stages[0][1].pattern.as_deref().unwrap();
            for name in matching {
                assert!(crate::glob::matches(pattern, name), "{input}: {name}");
            }
            for name in excluded {
                assert!(!crate::glob::matches(pattern, name), "{input}: {name}");
            }
        }
    }

    #[test]
    fn xargs_reads_items_as_gnu_xargs_does() {
        assert_eq!(
            xargs_items("a b\n  'c d' \"e f\" g\\ h\n", Delimiter::Blank).unwrap(),
            ["a", "b", "c d", "e f", "g h"]
        );
        assert!(xargs_items("it's\n", Delimiter::Blank).is_err());
        assert_eq!(
            xargs_items("spéctrum one.txt\0b\0", Delimiter::Char('\0')).unwrap(),
            ["spéctrum one.txt", "b"]
        );
        assert_eq!(
            xargs_items("a\n\nb\n", Delimiter::Char('\n')).unwrap(),
            ["a", "", "b"]
        );
        assert_eq!(
            xargs_items("  one two\n\n three\n", Delimiter::Line).unwrap(),
            ["one two", "three"]
        );
    }

    #[test]
    fn fd_placeholders() {
        let template: Vec<String> = ["mv", "{}", "{//}/{/.}.bak"].map(String::from).to_vec();
        assert_eq!(
            exec_one(&template, "docs/notes.md"),
            ["mv", "docs/notes.md", "docs/notes.bak"]
        );
        assert_eq!(exec_one(&template, "a")[2], "./a.bak");
        // Braces in a name are part of it, not placeholders.
        assert_eq!(
            exec_one(&template, "d/a{}b.md"),
            ["mv", "d/a{}b.md", "d/a{}b.bak"]
        );
        assert_eq!(
            exec_one(&["chmod".into(), "600".into()], ".hidden"),
            ["chmod", "600", ".hidden"]
        );
        assert_eq!(
            exec_one(&["echo".into(), "{.}".into()], "/x.y/z"),
            ["echo", "/x.y/z"]
        );
        let paths = ["a.md".to_string(), "b/c.md".to_string()];
        assert_eq!(
            exec_all(&["wc".into(), "-l".into()], &paths),
            ["wc", "-l", "a.md", "b/c.md"]
        );
        assert_eq!(
            exec_all(&["zip".into(), "out.zip".into(), "{/}".into()], &paths),
            ["zip", "out.zip", "a.md", "c.md"]
        );
    }
}

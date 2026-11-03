//! The text filters pipelines join: cat, head, tail, grep, wc, sort and uniq. They read
//! standard input, or the files named, and write text, as their GNU namesakes do for the options
//! listed. Nothing here reads a file: the terminal reads them, and hands over their text.
use regex::{Regex, RegexBuilder};

/// The commands that are filters.
pub const FILTERS: [&str; 7] = ["cat", "head", "tail", "grep", "wc", "sort", "uniq"];

/// A filter, and the files it reads instead of standard input, if any; `-` is standard input.
#[derive(Debug)]
pub struct Filter {
    pub kind: Kind,
    pub files: Vec<String>,
}
#[derive(Debug)]
pub enum Kind {
    Cat,
    /// The first `lines` lines, or with `-n -N` all but the last `lines`.
    Head {
        lines: usize,
        all_but: bool,
    },
    /// The last `lines` lines, or with `-n +N` those from line `lines` on.
    Tail {
        lines: usize,
        from_start: bool,
    },
    Grep {
        pattern: Regex,
        invert: bool,
        number: bool,
        count: bool,
    },
    Wc {
        lines: bool,
        words: bool,
        bytes: bool,
    },
    Sort {
        reverse: bool,
        numeric: bool,
        unique: bool,
    },
    Uniq {
        count: bool,
    },
}

impl Filter {
    /// How many lines of standard input it reads, if it stops before its end: `head -n N`, as
    /// GNU head closes its input once it has its lines, and a process writing to it hears SIGPIPE.
    pub fn reads(&self) -> Option<usize> {
        match self.kind {
            Kind::Head {
                lines,
                all_but: false,
            } if self.files.is_empty() => Some(lines),
            _ => None,
        }
    }
}

fn count(command: &str, value: &str) -> Result<usize, String> {
    value
        .parse()
        .map_err(|_| format!("{command}: invalid number of lines: {value}"))
}
/// head's or tail's -n: how many lines (10), and its sign, which counts from the other end:
/// head -n -N, tail -n +N.
fn lines(command: &str, value: Option<&str>) -> Result<(usize, Option<char>), String> {
    let Some(value) = value else {
        return Ok((10, None));
    };
    match value.strip_prefix(['+', '-']) {
        Some(digits) => Ok((count(command, digits)?, value.chars().next())),
        None => Ok((count(command, value)?, None)),
    }
}

/// Parse the filter `command` with `args`, as its definition in [`crate::cli::text`] reads them.
pub fn parse(command: &str, args: &[String]) -> Result<Filter, String> {
    use crate::cli::{parse, text as cli};
    let (kind, files) = match command {
        "cat" => (Kind::Cat, parse::<cli::Cat>(args)?.files),
        "head" | "tail" => {
            // head -5 is head -n 5, as it always was.
            // A -N that is -n's value (head -n -5, head --lines -5) is the value.
            let mut spelled = Vec::new();
            let mut ended = false;
            for (i, arg) in args.iter().enumerate() {
                match arg.strip_prefix('-') {
                    Some(digits)
                        if !ended
                            && !digits.is_empty()
                            && digits.bytes().all(|b| b.is_ascii_digit())
                            && args
                                .get(i.wrapping_sub(1))
                                .is_none_or(|a| a != "-n" && a != "--lines") =>
                    {
                        spelled.extend(["-n".to_string(), digits.to_string()]);
                    }
                    _ => {
                        ended |= arg == "--";
                        spelled.push(arg.clone());
                    }
                }
            }
            if command == "head" {
                let head = parse::<cli::Head>(&spelled)?;
                let (lines, sign) = lines(command, head.lines.as_deref())?;
                let all_but = sign == Some('-');
                (Kind::Head { lines, all_but }, head.files)
            } else {
                let tail = parse::<cli::Tail>(&spelled)?;
                let (lines, sign) = lines(command, tail.lines.as_deref())?;
                let from_start = sign == Some('+');
                (Kind::Tail { lines, from_start }, tail.files)
            }
        }
        "grep" => {
            let grep = parse::<cli::Grep>(args)?;
            let mut operands = grep.operands;
            let patterns = if !grep.patterns.is_empty() {
                grep.patterns
            } else if operands.is_empty() {
                return Err("grep: no PATTERN given; grep -h shows how to use it".into());
            } else {
                vec![operands.remove(0)]
            };
            // Several -e: a line matching any of them, as GNU grep selects.
            let source = patterns
                .iter()
                .map(|pattern| {
                    if grep.fixed {
                        regex::escape(pattern)
                    } else {
                        format!("(?:{pattern})")
                    }
                })
                .collect::<Vec<_>>()
                .join("|");
            let pattern = RegexBuilder::new(&source)
                .case_insensitive(grep.ignore_case)
                .build()
                .map_err(|e| format!("grep: invalid pattern: {e}"))?;
            (
                Kind::Grep {
                    pattern,
                    invert: grep.invert,
                    number: grep.number,
                    count: grep.count,
                },
                operands,
            )
        }
        "wc" => {
            let wc = parse::<cli::Wc>(args)?;
            let any = wc.lines || wc.words || wc.bytes;
            (
                Kind::Wc {
                    lines: !any || wc.lines,
                    words: !any || wc.words,
                    bytes: !any || wc.bytes,
                },
                wc.files,
            )
        }
        "sort" => {
            let sort = parse::<cli::Sort>(args)?;
            (
                Kind::Sort {
                    reverse: sort.reverse,
                    numeric: sort.numeric,
                    unique: sort.unique,
                },
                sort.files,
            )
        }
        "uniq" => {
            let uniq = parse::<cli::Uniq>(args)?;
            (
                Kind::Uniq { count: uniq.count },
                uniq.file.into_iter().collect(),
            )
        }
        _ => return Err(format!("{command} is not a filter")),
    };
    Ok(Filter { kind, files })
}

fn joined<'a>(lines: impl IntoIterator<Item = &'a str>) -> String {
    let mut out = String::new();
    for line in lines {
        out.push_str(line);
        out.push('\n');
    }
    out
}
/// The leading number of a line, as sort -n reads it; lines without one sort first.
fn leading_number(line: &str) -> f64 {
    let line = line.trim_start();
    let end = line
        .char_indices()
        .find(|&(i, c)| !(c.is_ascii_digit() || c == '.' || (i == 0 && c == '-')))
        .map_or(line.len(), |(i, _)| i);
    line[..end].parse().unwrap_or(f64::NEG_INFINITY)
}

/// The output and exit status of `filter` on `inputs`: each file's name and text, in order, or
/// standard input alone, named `-`.
pub fn apply(filter: &Filter, inputs: &[(String, String)]) -> (String, i32) {
    let several = inputs.len() > 1;
    match &filter.kind {
        Kind::Cat => (inputs.iter().map(|(_, t)| t.as_str()).collect(), 0),
        Kind::Head { .. } | Kind::Tail { .. } => {
            let mut out = String::new();
            for (i, (name, text)) in inputs.iter().enumerate() {
                if several {
                    if i > 0 {
                        out.push('\n');
                    }
                    out.push_str(&format!("==> {name} <==\n"));
                }
                let lines: Vec<&str> = text.lines().collect();
                let chosen = match filter.kind {
                    Kind::Head { lines: n, all_but } if all_but => {
                        &lines[..lines.len().saturating_sub(n)]
                    }
                    Kind::Head { lines: n, .. } => &lines[..lines.len().min(n)],
                    // tail -n +0 is tail -n +1, the whole input.
                    Kind::Tail {
                        lines: n,
                        from_start,
                    } if from_start => &lines[n.saturating_sub(1).min(lines.len())..],
                    Kind::Tail { lines: n, .. } => &lines[lines.len().saturating_sub(n)..],
                    _ => unreachable!(),
                };
                out.push_str(&joined(chosen.iter().copied()));
            }
            (out, 0)
        }
        Kind::Grep {
            pattern,
            invert,
            number,
            count,
        } => {
            let mut out = String::new();
            let mut matched = false;
            for (name, text) in inputs {
                let prefix = if several {
                    format!("{name}:")
                } else {
                    String::new()
                };
                let mut found = 0;
                for (index, line) in text.lines().enumerate() {
                    if pattern.is_match(line) == *invert {
                        continue;
                    }
                    found += 1;
                    if !count {
                        out.push_str(&prefix);
                        if *number {
                            out.push_str(&format!("{}:", index + 1));
                        }
                        out.push_str(line);
                        out.push('\n');
                    }
                }
                if *count {
                    out.push_str(&format!("{prefix}{found}\n"));
                }
                matched |= found > 0;
            }
            (out, if matched { 0 } else { 1 })
        }
        Kind::Wc {
            lines,
            words,
            bytes,
        } => {
            let counts: Vec<(Vec<usize>, &str)> = inputs
                .iter()
                .map(|(name, text)| {
                    let mut c = Vec::new();
                    if *lines {
                        c.push(text.matches('\n').count());
                    }
                    if *words {
                        c.push(text.split_whitespace().count());
                    }
                    if *bytes {
                        c.push(text.len());
                    }
                    (c, name.as_str())
                })
                .collect();
            let mut rows = counts.clone();
            if several {
                let total = (0..counts[0].0.len())
                    .map(|i| counts.iter().map(|(c, _)| c[i]).sum())
                    .collect();
                rows.push((total, "total"));
            }
            let width = rows
                .iter()
                .flat_map(|(c, _)| c.iter().map(|n| n.to_string().len()))
                .max()
                .unwrap_or(1);
            let mut out = String::new();
            for (c, name) in rows {
                let numbers: Vec<String> = c.iter().map(|n| format!("{n:>width$}")).collect();
                out.push_str(&numbers.join(" "));
                if name != "-" {
                    out.push(' ');
                    out.push_str(name);
                }
                out.push('\n');
            }
            (out, 0)
        }
        Kind::Sort {
            reverse,
            numeric,
            unique,
        } => {
            let mut lines: Vec<&str> = inputs.iter().flat_map(|(_, t)| t.lines()).collect();
            if *numeric {
                lines.sort_by(|a, b| {
                    leading_number(a)
                        .total_cmp(&leading_number(b))
                        .then_with(|| a.cmp(b))
                });
            } else {
                lines.sort();
            }
            if *unique {
                lines.dedup_by(|a, b| {
                    if *numeric {
                        leading_number(a) == leading_number(b)
                    } else {
                        a == b
                    }
                });
            }
            if *reverse {
                lines.reverse();
            }
            (joined(lines), 0)
        }
        Kind::Uniq { count } => {
            let mut out = String::new();
            let mut lines = inputs.iter().flat_map(|(_, t)| t.lines()).peekable();
            while let Some(line) = lines.next() {
                let mut n = 1;
                while lines.peek() == Some(&line) {
                    lines.next();
                    n += 1;
                }
                if *count {
                    out.push_str(&format!("{n:>7} "));
                }
                out.push_str(line);
                out.push('\n');
            }
            (out, 0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(command: &str, args: &[&str], inputs: &[(&str, &str)]) -> (String, i32) {
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        let filter = parse(command, &args).unwrap();
        let inputs: Vec<(String, String)> = inputs
            .iter()
            .map(|(n, t)| (n.to_string(), t.to_string()))
            .collect();
        apply(&filter, &inputs)
    }
    const LINES: &str = "beta\nalpha\nGamma\nalpha\nspéctrum 10\nspéctrum 9\n";

    #[test]
    fn head_alone_says_how_much_of_its_input_it_reads() {
        let reads = |command: &str, args: &[&str]| {
            let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
            parse(command, &args).unwrap().reads()
        };
        assert_eq!(reads("head", &["-n", "3"]), Some(3));
        assert_eq!(reads("head", &["-5"]), Some(5));
        assert_eq!(reads("head", &[]), Some(10));
        // All but the last lines, files, or another filter: all of it.
        assert_eq!(reads("head", &["-n", "-3"]), None);
        assert_eq!(reads("head", &["file"]), None);
        assert_eq!(reads("tail", &["-n", "3"]), None);
    }

    #[test]
    fn head_tail_and_cat() {
        assert_eq!(
            run("head", &["-n", "2"], &[("-", LINES)]).0,
            "beta\nalpha\n"
        );
        assert_eq!(run("head", &["-2"], &[("-", LINES)]).0, "beta\nalpha\n");
        assert_eq!(run("tail", &["-n1"], &[("-", LINES)]).0, "spéctrum 9\n");
        // tail -n +N starts at line N; head -n -N leaves out the last N.
        assert_eq!(
            run("tail", &["-n", "+5"], &[("-", LINES)]).0,
            "spéctrum 10\nspéctrum 9\n"
        );
        assert_eq!(run("tail", &["-n+0"], &[("-", LINES)]).0, LINES);
        assert_eq!(run("tail", &["-n", "+9"], &[("-", LINES)]).0, "");
        assert_eq!(
            run("tail", &["-n", "-1"], &[("-", LINES)]).0,
            "spéctrum 9\n"
        );
        assert_eq!(
            run("head", &["-n", "-4"], &[("-", LINES)]).0,
            "beta\nalpha\n"
        );
        assert_eq!(run("head", &["-n", "-9"], &[("-", LINES)]).0, "");
        assert_eq!(run("head", &["-n", "+1"], &[("-", LINES)]).0, "beta\n");
        assert_eq!(
            run("head", &["--lines", "-4"], &[("-", LINES)]).0,
            "beta\nalpha\n"
        );
        assert!(parse("tail", &["-n".into(), "+x".into()]).is_err());
        assert_eq!(
            run("head", &["-n", "1"], &[("a", "1\n2\n"), ("b", "3")]).0,
            "==> a <==\n1\n\n==> b <==\n3\n"
        );
        assert_eq!(run("cat", &[], &[("a", "x"), ("b", "y\n")]).0, "xy\n");
        assert!(parse("head", &["-n".into(), "x".into()]).is_err());
        assert!(parse("cat", &["-z".into()]).is_err());
    }

    #[test]
    fn grep_selects_lines_and_reports_matches() {
        assert_eq!(
            run("grep", &["-in", "GAMMA|beta"], &[("-", LINES)]),
            ("1:beta\n3:Gamma\n".into(), 0)
        );
        assert_eq!(run("grep", &["-c", "alpha"], &[("-", LINES)]).0, "2\n");
        assert_eq!(run("grep", &["-v", "a"], &[("-", "a\nb\n")]).0, "b\n");
        assert_eq!(
            run("grep", &["-F", "a.b"], &[("-", "a.b\naxb\n")]).0,
            "a.b\n"
        );
        assert_eq!(
            run("grep", &["nothing"], &[("-", LINES)]),
            (String::new(), 1)
        );
        assert_eq!(
            run(
                "grep",
                &["-i", "SPÉCTRUM 9"],
                &[("x.txt", LINES), ("y.txt", "")]
            )
            .0,
            "x.txt:spéctrum 9\n"
        );
        // Several -e select a line matching any.
        assert_eq!(
            run("grep", &["-e", "beta", "-e", "Gamma"], &[("-", LINES)]).0,
            "beta\nGamma\n"
        );
        assert_eq!(
            run(
                "grep",
                &["-F", "-e", "a.b", "-e", "c|d"],
                &[("-", "a.b\naxb\nc|d\nc\n")]
            )
            .0,
            "a.b\nc|d\n"
        );
        assert!(parse("grep", &[]).is_err());
        assert!(parse("grep", &["(".into()]).is_err());
    }

    #[test]
    fn wc_sort_and_uniq() {
        assert_eq!(run("wc", &["-l"], &[("-", LINES)]).0, "6\n");
        assert_eq!(run("wc", &[], &[("-", "a b\nc\n")]).0, "2 3 6\n");
        assert_eq!(
            run("wc", &["-l"], &[("a", "1\n"), ("b", "1\n2\n")]).0,
            "1 a\n2 b\n3 total\n"
        );
        assert_eq!(
            run("sort", &["-u"], &[("-", LINES)]).0,
            "Gamma\nalpha\nbeta\nspéctrum 10\nspéctrum 9\n"
        );
        assert_eq!(
            run("sort", &["-n"], &[("-", "10 x\n9 y\n-1 z\nnone\n")]).0,
            "none\n-1 z\n9 y\n10 x\n"
        );
        assert_eq!(run("sort", &["-rn"], &[("-", "1\n3\n2\n")]).0, "3\n2\n1\n");
        assert_eq!(
            run("uniq", &["-c"], &[("-", "a\na\nb\na\n")]).0,
            "      2 a\n      1 b\n      1 a\n"
        );
    }
}

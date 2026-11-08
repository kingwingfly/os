//! Options and pattern compilation for the installed streaming grep program.
//! Other text filters are supplied by coreutils; their implementations do not live here.
use regex::{Regex, RegexBuilder};

pub struct Grep {
    pub pattern: Regex,
    pub invert: bool,
    pub number: bool,
    pub count: bool,
    pub files: Vec<String>,
}

pub fn grep(args: &[String]) -> Result<Grep, String> {
    let grep = crate::cli::parse::<crate::cli::text::Grep>(args)?;
    let mut files = grep.operands;
    let patterns = if !grep.patterns.is_empty() {
        grep.patterns
    } else if files.is_empty() {
        return Err("no PATTERN given; grep --help shows how to use it".into());
    } else {
        vec![files.remove(0)]
    };
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
        .map_err(|error| format!("invalid pattern: {error}"))?;
    Ok(Grep {
        pattern,
        invert: grep.invert,
        number: grep.number,
        count: grep.count,
        files,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn options(args: &[&str]) -> Result<Grep, String> {
        grep(&args.iter().map(|arg| (*arg).into()).collect::<Vec<_>>())
    }
    #[test]
    fn patterns_flags_and_operands() {
        let selected = options(&["-in", "GAMMA|beta", "a.txt", "-"]).unwrap();
        assert!(selected.number);
        assert!(selected.pattern.is_match("Gamma"));
        assert!(selected.pattern.is_match("BETA"));
        assert!(!selected.pattern.is_match("alpha"));
        assert_eq!(selected.files, ["a.txt", "-"]);
        let fixed = options(&["-F", "-e", "a.b", "-e", "c|d"]).unwrap();
        assert!(fixed.pattern.is_match("a.b"));
        assert!(fixed.pattern.is_match("c|d"));
        assert!(!fixed.pattern.is_match("axb"));
        let unicode = options(&["-i", "SPÉCTRUM"]).unwrap();
        assert!(unicode.pattern.is_match("spéctrum 9"));
    }
    #[test]
    fn missing_and_invalid_patterns_fail() {
        assert!(options(&[]).is_err());
        assert!(options(&["("]).is_err());
    }
}

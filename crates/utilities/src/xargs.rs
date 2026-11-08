//! Bounded, streaming argument construction. Children use the generic process adapter.
use os_core::cli::{self, text::Xargs};
use os_posix::process::{Stdin, spawn};
use std::io::{self, BufRead};

const LIMIT: usize = 128 * 1024;
#[derive(Clone, Copy)]
enum Delimiter {
    Blank,
    Byte(u8),
    Line,
}

struct Items<R> {
    input: R,
    delimiter: Delimiter,
}
impl<R: BufRead> Items<R> {
    fn next(&mut self) -> io::Result<Option<String>> {
        let mut item = Vec::new();
        let mut quote = None;
        let mut escape = false;
        let mut started = false;
        loop {
            let byte = self.input.fill_buf()?.first().copied();
            if byte.is_some() {
                self.input.consume(1);
            }
            let Some(byte) = byte else {
                if quote.is_some() || escape {
                    return Err(io::Error::other("unclosed quote or backslash"));
                }
                return if started {
                    Self::text(item).map(Some)
                } else {
                    Ok(None)
                };
            };
            match self.delimiter {
                Delimiter::Byte(end) => {
                    if byte == end {
                        return Self::text(item).map(Some);
                    }
                    started = true;
                    item.push(byte);
                }
                Delimiter::Line => {
                    if byte == b'\n' {
                        if started {
                            return Self::text(item).map(Some);
                        }
                        continue;
                    }
                    if !started && byte.is_ascii_whitespace() {
                        continue;
                    }
                    started = true;
                    item.push(byte);
                }
                Delimiter::Blank => {
                    if escape {
                        item.push(byte);
                        escape = false;
                    } else if let Some(end) = quote {
                        if byte == end {
                            quote = None;
                        } else if byte == b'\n' {
                            return Err(io::Error::other("unclosed quote"));
                        } else {
                            item.push(byte);
                        }
                    } else {
                        match byte {
                            b'\\' => escape = true,
                            b'\'' | b'"' => quote = Some(byte),
                            byte if byte.is_ascii_whitespace() => {
                                if started {
                                    return Self::text(item).map(Some);
                                }
                                continue;
                            }
                            _ => item.push(byte),
                        }
                    }
                    started = true;
                }
            }
            if item.len() >= LIMIT {
                return Err(io::Error::other("argument exceeds process limit"));
            }
        }
    }
    fn text(item: Vec<u8>) -> io::Result<String> {
        if item.contains(&0) {
            return Err(io::Error::other(
                "NUL in argument; use -0 for NUL-delimited input",
            ));
        }
        String::from_utf8(item).map_err(io::Error::other)
    }
}

fn delimiter(value: &str) -> io::Result<u8> {
    match value {
        "\\n" => Ok(b'\n'),
        "\\t" => Ok(b'\t'),
        "\\0" => Ok(0),
        "\\\\" => Ok(b'\\'),
        _ if value.len() == 1 => Ok(value.as_bytes()[0]),
        _ => Err(io::Error::other(
            "delimiter must be one byte or \\n, \\t, \\0, \\\\",
        )),
    }
}
fn size(args: &[String]) -> usize {
    args.iter().map(|arg| arg.len() + 1).sum()
}

/// Return both xargs' status and whether it must stop consuming input.
fn execute(command: &[String], tty: bool, trace: bool) -> (i32, bool) {
    if trace {
        eprintln!("{}", command.join(" "));
    }
    match spawn(command, if tty { Stdin::Tty } else { Stdin::Null }).and_then(|child| child.wait())
    {
        Ok(status) => match status.code() {
            Some(0) => (0, false),
            Some(255) => {
                eprintln!("xargs: {}: exited with status 255; stopping", command[0]);
                (124, true)
            }
            Some(_) => (123, false),
            None => {
                eprintln!(
                    "xargs: {}: terminated by signal {}",
                    command[0],
                    status.signal().unwrap_or(0)
                );
                (125, true)
            }
        },
        Err(error) => {
            eprintln!("xargs: {}: {error}", command[0]);
            (
                if error.kind() == io::ErrorKind::NotFound {
                    127
                } else {
                    126
                },
                true,
            )
        }
    }
}

pub fn run(args: &[String]) -> io::Result<i32> {
    let options = cli::parse::<Xargs>(args).map_err(io::Error::other)?;
    if options.replace.as_deref() == Some("") {
        return Err(io::Error::other("replacement cannot be empty"));
    }
    let mode = if let Some(value) = &options.delimiter {
        Delimiter::Byte(delimiter(value)?)
    } else if options.null {
        Delimiter::Byte(0)
    } else if options.replace.is_some() {
        Delimiter::Line
    } else {
        Delimiter::Blank
    };
    let command = if options.command.is_empty() {
        vec!["echo".into()]
    } else {
        options.command
    };
    let base = size(&command);
    if base > LIMIT {
        return Err(io::Error::other("command exceeds process limit"));
    }
    let mut input = Items {
        input: io::stdin().lock(),
        delimiter: mode,
    };
    let mut batch = command.clone();
    let mut bytes = base;
    let mut seen = false;
    let mut status = 0;
    while let Some(item) = input.next()? {
        seen = true;
        if let Some(replace) = &options.replace {
            let expanded: Vec<_> = command
                .iter()
                .map(|arg| arg.replace(replace, &item))
                .collect();
            if size(&expanded) > LIMIT {
                return Err(io::Error::other("expanded command exceeds process limit"));
            }
            let (code, stop) = execute(&expanded, options.open_tty, options.verbose);
            if stop {
                return Ok(code);
            }
            status = status.max(code);
            continue;
        }
        if base + item.len() + 1 > LIMIT {
            return Err(io::Error::other("argument exceeds process limit"));
        }
        if bytes + item.len() + 1 > LIMIT {
            let (code, stop) = execute(&batch, options.open_tty, options.verbose);
            if stop {
                return Ok(code);
            }
            status = status.max(code);
            batch.truncate(command.len());
            bytes = base;
        }
        bytes += item.len() + 1;
        batch.push(item);
        if (batch.len() - command.len()) as u64 >= options.max_args.unwrap_or(1000) {
            let (code, stop) = execute(&batch, options.open_tty, options.verbose);
            if stop {
                return Ok(code);
            }
            status = status.max(code);
            batch.truncate(command.len());
            bytes = base;
        }
    }
    if options.replace.is_none()
        && (batch.len() > command.len() || !seen && !options.no_run_if_empty)
    {
        let (code, _) = execute(&batch, options.open_tty, options.verbose);
        status = status.max(code);
    }
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn collect(input: &[u8], delimiter: Delimiter) -> io::Result<Vec<String>> {
        let mut items = Items {
            input: io::BufReader::with_capacity(1, input),
            delimiter,
        };
        let mut found = Vec::new();
        while let Some(item) = items.next()? {
            found.push(item);
        }
        Ok(found)
    }
    #[test]
    fn quotes_and_utf8_cross_read_boundaries() {
        assert_eq!(
            collect(
                "  'two words' \"\" escaped\\ space 中文\n".as_bytes(),
                Delimiter::Blank
            )
            .unwrap(),
            ["two words", "", "escaped space", "中文"]
        );
        assert!(collect(b"'unfinished", Delimiter::Blank).is_err());
        assert!(collect(b"trailing\\", Delimiter::Blank).is_err());
        assert!(collect(b"a\0b", Delimiter::Blank).is_err());
    }
    #[test]
    fn delimiters_preserve_empty_arguments_and_final_item() {
        assert_eq!(
            collect(b"a\0\0b", Delimiter::Byte(0)).unwrap(),
            ["a", "", "b"]
        );
        assert_eq!(collect(b"\0", Delimiter::Byte(0)).unwrap(), [""]);
        assert!(collect(b"", Delimiter::Byte(0)).unwrap().is_empty());
        assert_eq!(
            collect(b"\n  a b\n\n\tc d", Delimiter::Line).unwrap(),
            ["a b", "c d"]
        );
    }
    #[test]
    fn first_item_does_not_require_eof() {
        struct Source(bool);
        impl io::Read for Source {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                if self.0 {
                    return Err(io::Error::other("input is still running"));
                }
                self.0 = true;
                out[..2].copy_from_slice(b"x ");
                Ok(2)
            }
        }
        let mut items = Items {
            input: io::BufReader::new(Source(false)),
            delimiter: Delimiter::Blank,
        };
        assert_eq!(items.next().unwrap().as_deref(), Some("x"));
        assert!(items.next().is_err());
    }
}

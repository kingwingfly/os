//! What programs write to a terminal beyond text, as an xterm reads it: SGR's colours and styles
//! (`ESC [ … m`: the 16 colours, 256, and 24-bit ones, bold, dim, italic, underline, inverse,
//! strike), and OSC 8's hyperlinks (`ESC ] 8 ; ; URI ESC \`). What moves a cursor or clears a
//! screen has nothing to do in a transcript, and goes; so do other sequences.

/// A colour, as SGR names one: of the 256 (the first 16 the terminal's own), or red, green and
/// blue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Color {
    Indexed(u8),
    Rgb(u8, u8, u8),
}
impl Color {
    /// As CSS: one of the terminal's 16 by its custom property; the rest as they are.
    pub fn css(self) -> String {
        match self {
            Self::Indexed(n) if n < 16 => format!("var(--ansi-{n})"),
            Self::Indexed(n) if n < 232 => {
                let n = n - 16;
                let level = |v: u8| if v == 0 { 0 } else { 55 + v * 40 };
                format!(
                    "rgb({},{},{})",
                    level(n / 36),
                    level(n / 6 % 6),
                    level(n % 6)
                )
            }
            Self::Indexed(n) => {
                let grey = 8 + (n - 232) * 10;
                format!("rgb({grey},{grey},{grey})")
            }
            Self::Rgb(r, g, b) => format!("rgb({r},{g},{b})"),
        }
    }
}

/// How a run of text shows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Style {
    pub fg: Option<Color>,
    pub bg: Option<Color>,
    pub bold: bool,
    pub dim: bool,
    pub italic: bool,
    pub underline: bool,
    pub inverse: bool,
    pub strike: bool,
}
impl Style {
    /// As CSS declarations; nothing for the terminal's own look.
    pub fn css(&self) -> String {
        let (mut fg, mut bg) = (self.fg.map(Color::css), self.bg.map(Color::css));
        if self.inverse {
            (fg, bg) = (
                Some(bg.unwrap_or_else(|| "var(--ansi-bg)".into())),
                Some(fg.unwrap_or_else(|| "var(--ansi-fg)".into())),
            );
        }
        let mut out = String::new();
        if let Some(fg) = fg {
            out.push_str(&format!("color:{fg};"));
        }
        if let Some(bg) = bg {
            out.push_str(&format!("background:{bg};"));
        }
        if self.bold {
            out.push_str("font-weight:700;");
        }
        if self.dim {
            out.push_str("opacity:.65;");
        }
        if self.italic {
            out.push_str("font-style:italic;");
        }
        match (self.underline, self.strike) {
            (true, true) => out.push_str("text-decoration:underline line-through;"),
            (true, false) => out.push_str("text-decoration:underline;"),
            (false, true) => out.push_str("text-decoration:line-through;"),
            _ => {}
        }
        out
    }
    /// Take an SGR's parameters, as `;`-separated numbers (`:` too, for 38 and 48's colours).
    fn apply(&mut self, params: &str) {
        let numbers: Vec<u16> = params
            .split([';', ':'])
            .map(|n| n.parse().unwrap_or(0))
            .collect();
        let mut at = 0;
        while at < numbers.len() {
            let n = numbers[at];
            match n {
                0 => *self = Style::default(),
                1 => self.bold = true,
                2 => self.dim = true,
                3 => self.italic = true,
                4 => self.underline = true,
                7 => self.inverse = true,
                9 => self.strike = true,
                21 | 22 => (self.bold, self.dim) = (false, false),
                23 => self.italic = false,
                24 => self.underline = false,
                27 => self.inverse = false,
                29 => self.strike = false,
                30..=37 => self.fg = Some(Color::Indexed((n - 30) as u8)),
                39 => self.fg = None,
                40..=47 => self.bg = Some(Color::Indexed((n - 40) as u8)),
                49 => self.bg = None,
                90..=97 => self.fg = Some(Color::Indexed((n - 90 + 8) as u8)),
                100..=107 => self.bg = Some(Color::Indexed((n - 100 + 8) as u8)),
                38 | 48 => {
                    let color = match numbers.get(at + 1) {
                        Some(5) => {
                            at += 2;
                            numbers.get(at).map(|n| Color::Indexed(*n as u8))
                        }
                        Some(2) => {
                            at += 4;
                            match numbers.get(at - 2..=at) {
                                Some([r, g, b]) => Some(Color::Rgb(*r as u8, *g as u8, *b as u8)),
                                _ => None,
                            }
                        }
                        _ => None,
                    };
                    if n == 38 {
                        self.fg = color;
                    } else {
                        self.bg = color;
                    }
                }
                _ => {}
            }
            at += 1;
        }
    }
}

/// A run of text, how it shows, and the link it is, if OSC 8 made it one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    pub text: String,
    pub style: Style,
    pub link: Option<String>,
}

/// Whether `text` has anything for a terminal beyond text.
pub fn escaped(text: &str) -> bool {
    text.contains('\x1b')
}

/// `text` as runs, each of one style and link; what is not text gone.
pub fn parse(text: &str) -> Vec<Run> {
    let mut runs: Vec<Run> = Vec::new();
    let (mut style, mut link) = (Style::default(), None::<String>);
    let mut current = String::new();
    let flush = |runs: &mut Vec<Run>,
                 current: &mut String,
                 style: &Style,
                 link: &Option<String>| {
        if current.is_empty() {
            return;
        }
        match runs.last_mut() {
            Some(last) if last.style == *style && last.link == *link => last.text.push_str(current),
            _ => runs.push(Run {
                text: current.clone(),
                style: style.clone(),
                link: link.clone(),
            }),
        }
        current.clear();
    };
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            current.push(c);
            continue;
        }
        match chars.next() {
            // CSI: parameters, intermediates, then a final byte.
            Some('[') => {
                let mut params = String::new();
                let mut last = None;
                for c in chars.by_ref() {
                    if ('\x40'..='\x7e').contains(&c) {
                        last = Some(c);
                        break;
                    }
                    params.push(c);
                }
                if last == Some('m') {
                    flush(&mut runs, &mut current, &style, &link);
                    style.apply(if params.is_empty() { "0" } else { &params });
                }
            }
            // OSC: up to BEL or ST (ESC \).
            Some(']') => {
                let mut body = String::new();
                while let Some(c) = chars.next() {
                    if c == '\x07' {
                        break;
                    }
                    if c == '\x1b' {
                        if chars.peek() == Some(&'\\') {
                            chars.next();
                        }
                        break;
                    }
                    body.push(c);
                }
                if let Some(rest) = body.strip_prefix("8;") {
                    flush(&mut runs, &mut current, &style, &link);
                    let uri = rest.split_once(';').map_or("", |(_, uri)| uri);
                    link = (!uri.is_empty()).then(|| uri.to_string());
                }
            }
            // A charset's designation, and the like: one more byte.
            Some('(' | ')' | '*' | '+' | '#' | '%') => {
                chars.next();
            }
            _ => {}
        }
    }
    flush(&mut runs, &mut current, &style, &link);
    runs
}

/// `text` without what is not text.
pub fn strip(text: &str) -> String {
    parse(text).into_iter().map(|run| run.text).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colours_styles_and_links_read_as_an_xterm_reads_them() {
        let runs = parse("plain \x1b[1;31mbold red\x1b[0m \x1b[38;5;208mo\x1b[38;2;1;2;3mr\x1b[m.");
        let texts: Vec<&str> = runs.iter().map(|run| run.text.as_str()).collect();
        assert_eq!(texts, ["plain ", "bold red", " ", "o", "r", "."]);
        assert_eq!(runs[1].style.fg, Some(Color::Indexed(1)));
        assert!(runs[1].style.bold);
        assert_eq!(runs[2].style, Style::default());
        assert_eq!(runs[3].style.fg, Some(Color::Indexed(208)));
        assert_eq!(runs[4].style.fg, Some(Color::Rgb(1, 2, 3)));
        assert_eq!(runs[1].style.css(), "color:var(--ansi-1);font-weight:700;");
        assert_eq!(Color::Indexed(208).css(), "rgb(255,135,0)");
        assert_eq!(Color::Indexed(244).css(), "rgb(128,128,128)");
        // What moves the cursor goes; a link is text that leads somewhere.
        let linked = parse(
            "\x1b[2K\x1b]8;;https://example.com/\x1b\\site\x1b]8;;\x1b\\ \x1b[90mgrey\x1b[39m",
        );
        assert_eq!(linked[0].text, "site");
        assert_eq!(linked[0].link.as_deref(), Some("https://example.com/"));
        assert_eq!(linked[1].link, None);
        assert_eq!(linked[2].style.fg, Some(Color::Indexed(8)));
        assert_eq!(strip("\x1b[01;34mdir\x1b[0m/"), "dir/");
        let inverse = Style {
            inverse: true,
            ..Style::default()
        };
        assert_eq!(
            inverse.css(),
            "color:var(--ansi-bg);background:var(--ansi-fg);"
        );
        assert!(!escaped("plain"));
    }
}

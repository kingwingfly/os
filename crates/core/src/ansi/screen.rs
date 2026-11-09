//! Incremental terminal grid. Escape sequences can span writes; all rendering remains text.
use super::{Run, Style};
use unicode_width::UnicodeWidthChar;

#[derive(Clone, Default)]
struct Cell {
    text: String,
    style: Style,
    link: Option<String>,
    continuation: bool,
}
#[derive(Clone)]
struct Buffer {
    cells: Vec<Vec<Cell>>,
    row: usize,
    col: usize,
    saved: (usize, usize, Style),
}
impl Buffer {
    fn new(cols: usize, rows: usize) -> Self {
        Self {
            cells: vec![vec![Cell::default(); cols]; rows],
            row: 0,
            col: 0,
            saved: (0, 0, Style::default()),
        }
    }
}
#[derive(Clone, Default)]
enum Parse {
    #[default]
    Text,
    Escape,
    Csi(String),
    Osc(String, bool),
    Ignore(bool),
    Charset,
}

#[derive(Clone)]
pub struct Screen {
    cols: usize,
    rows: usize,
    buffer: Buffer,
    main: Option<Buffer>,
    history: Vec<Vec<Cell>>,
    style: Style,
    link: Option<String>,
    parse: Parse,
    top: usize,
    bottom: usize,
    wrap: bool,
    pub cursor: bool,
    pub application_cursor: bool,
    pub bracketed_paste: bool,
    /// A cursor operation was seen: use this grid instead of a plain transcript.
    pub addressed: bool,
}
impl Default for Screen {
    fn default() -> Self {
        Self::new(80, 24)
    }
}
impl Screen {
    pub fn new(cols: usize, rows: usize) -> Self {
        let cols = cols.clamp(2, 500);
        let rows = rows.clamp(2, 200);
        Self {
            cols,
            rows,
            buffer: Buffer::new(cols, rows),
            main: None,
            history: Vec::new(),
            style: Style::default(),
            link: None,
            parse: Parse::Text,
            top: 0,
            bottom: rows - 1,
            wrap: true,
            cursor: true,
            application_cursor: false,
            bracketed_paste: false,
            addressed: false,
        }
    }
    pub fn alternate(&self) -> bool {
        self.main.is_some()
    }
    /// Cursor coordinates in the rendered buffer, including normal-screen scrollback.
    pub fn cursor_position(&self) -> (usize, usize) {
        (
            if self.alternate() {
                0
            } else {
                self.history.len()
            } + self.buffer.row,
            self.buffer.col.min(self.cols - 1),
        )
    }
    pub fn resize(&mut self, cols: usize, rows: usize) {
        let cols = cols.clamp(2, 500);
        let rows = rows.clamp(2, 200);
        for buffer in std::iter::once(&mut self.buffer).chain(self.main.iter_mut()) {
            buffer
                .cells
                .resize_with(rows, || vec![Cell::default(); cols]);
            for line in &mut buffer.cells {
                line.resize(cols, Cell::default());
            }
            buffer.row = buffer.row.min(rows - 1);
            buffer.col = buffer.col.min(cols - 1);
        }
        self.cols = cols;
        self.rows = rows;
        self.top = 0;
        self.bottom = rows - 1;
    }
    fn blank(&self) -> Cell {
        Cell {
            style: self.style.clone(),
            ..Cell::default()
        }
    }
    fn scroll(&mut self, down: bool) {
        let blank = vec![self.blank(); self.cols];
        if down {
            self.buffer.cells.remove(self.bottom);
            self.buffer.cells.insert(self.top, blank);
        } else {
            let removed = self.buffer.cells.remove(self.top);
            self.buffer.cells.insert(self.bottom, blank);
            if self.top == 0 && self.bottom == self.rows - 1 && !self.alternate() {
                self.history.push(removed);
                if self.history.len() > 2000 {
                    self.history.remove(0);
                }
            }
        }
    }
    fn newline(&mut self) {
        if self.buffer.row == self.bottom {
            self.scroll(false);
        } else {
            self.buffer.row = (self.buffer.row + 1).min(self.rows - 1);
        }
    }
    fn put(&mut self, ch: char) {
        let width = ch.width().unwrap_or(0);
        if width == 0 {
            let mut col = self.buffer.col.saturating_sub(1).min(self.cols - 1);
            if self.buffer.cells[self.buffer.row][col].continuation {
                col = col.saturating_sub(1);
            }
            self.buffer.cells[self.buffer.row][col].text.push(ch);
            return;
        }
        if self.buffer.col >= self.cols || width == 2 && self.buffer.col == self.cols - 1 {
            if self.wrap {
                self.buffer.col = 0;
                self.newline();
            } else {
                self.buffer.col = self.cols - 1;
            }
        }
        let row = self.buffer.row;
        let col = self.buffer.col;
        // A carriage return or backspace followed by replacement text needs the grid,
        // while ordinary CRLF output can keep the shell's line-oriented transcript.
        self.addressed |= !self.buffer.cells[row][col].text.is_empty()
            || self.buffer.cells[row][col].continuation;
        if self.buffer.cells[row][col].continuation && col > 0 {
            self.buffer.cells[row][col - 1] = self.blank();
        }
        if col + 1 < self.cols && self.buffer.cells[row][col + 1].continuation {
            self.buffer.cells[row][col + 1] = self.blank();
        }
        self.buffer.cells[row][col] = Cell {
            text: ch.to_string(),
            style: self.style.clone(),
            link: self.link.clone(),
            continuation: false,
        };
        if width == 2 && col + 1 < self.cols {
            self.buffer.cells[row][col + 1] = Cell {
                continuation: true,
                ..self.blank()
            };
        }
        self.buffer.col = (col + width).min(self.cols);
    }
    /// Consume a write; replies (DSR/DA) go back to the PTY master as input.
    pub fn feed(&mut self, text: &str) -> String {
        let mut reply = String::new();
        for ch in text.chars() {
            match std::mem::take(&mut self.parse) {
                Parse::Text => match ch {
                    '\x1b' => self.parse = Parse::Escape,
                    '\r' => self.buffer.col = 0,
                    '\n' | '\x0b' | '\x0c' => self.newline(),
                    '\x08' => self.buffer.col = self.buffer.col.saturating_sub(1),
                    '\t' => self.buffer.col = ((self.buffer.col / 8 + 1) * 8).min(self.cols - 1),
                    ch if !ch.is_control() => self.put(ch),
                    _ => {}
                },
                Parse::Escape => match ch {
                    '[' => self.parse = Parse::Csi(String::new()),
                    ']' => self.parse = Parse::Osc(String::new(), false),
                    'P' | '^' | '_' => self.parse = Parse::Ignore(false),
                    '(' | ')' => self.parse = Parse::Charset,
                    '7' => self.save(),
                    '8' => self.restore(),
                    'D' => self.newline(),
                    'E' => {
                        self.buffer.col = 0;
                        self.newline();
                    }
                    'M' => {
                        if self.buffer.row == self.top {
                            self.scroll(true);
                        } else {
                            self.buffer.row = self.buffer.row.saturating_sub(1);
                        }
                    }
                    'c' => *self = Self::new(self.cols, self.rows),
                    _ => {}
                },
                Parse::Csi(mut seq) => {
                    if ('@'..='~').contains(&ch) {
                        self.csi(&seq, ch, &mut reply);
                    } else if ch == '\x1b' {
                        self.parse = Parse::Escape;
                    } else if seq.len() < 256 {
                        seq.push(ch);
                        self.parse = Parse::Csi(seq);
                    }
                }
                Parse::Osc(mut seq, escape) => {
                    if ch == '\x07' || escape && ch == '\\' {
                        if let Some(value) = seq
                            .strip_prefix("8;")
                            .and_then(|s| s.split_once(';'))
                            .map(|(_, uri)| uri)
                        {
                            self.link = (value.starts_with("https://")
                                || value.starts_with("http://"))
                            .then(|| value.to_string());
                        }
                    } else if ch == '\x1b' {
                        self.parse = Parse::Osc(seq, true);
                    } else if seq.len() < 4096 {
                        seq.push(ch);
                        self.parse = Parse::Osc(seq, false);
                    } else {
                        self.parse = Parse::Ignore(false);
                    }
                }
                Parse::Ignore(escape) => {
                    if !(escape && ch == '\\') && ch != '\x07' {
                        self.parse = Parse::Ignore(ch == '\x1b');
                    }
                }
                Parse::Charset => {}
            }
        }
        reply
    }
    fn save(&mut self) {
        self.buffer.saved = (self.buffer.row, self.buffer.col, self.style.clone());
    }
    fn restore(&mut self) {
        let (row, col, style) = self.buffer.saved.clone();
        self.buffer.row = row.min(self.rows - 1);
        self.buffer.col = col.min(self.cols - 1);
        self.style = style;
    }
    fn csi(&mut self, seq: &str, action: char, reply: &mut String) {
        if action == 'm' {
            self.style.apply(seq);
            return;
        }
        self.addressed = true;
        let private = seq.starts_with('?');
        let params: Vec<usize> = seq
            .trim_start_matches(['?', '>'])
            .split(';')
            .map(|n| n.parse().unwrap_or(0))
            .collect();
        let get = |index: usize, default: usize| {
            params
                .get(index)
                .copied()
                .filter(|n| *n > 0)
                .unwrap_or(default)
        };
        let n = get(0, 1);
        let row = self.buffer.row;
        let col = self.buffer.col.min(self.cols - 1);
        match action {
            'A' => self.buffer.row = row.saturating_sub(n),
            'B' | 'e' => self.buffer.row = row.saturating_add(n).min(self.rows - 1),
            'C' | 'a' => self.buffer.col = col.saturating_add(n).min(self.cols - 1),
            'D' => self.buffer.col = col.saturating_sub(n),
            'E' => {
                self.buffer.row = row.saturating_add(n).min(self.rows - 1);
                self.buffer.col = 0;
            }
            'F' => {
                self.buffer.row = row.saturating_sub(n);
                self.buffer.col = 0;
            }
            'G' | '`' => self.buffer.col = (n - 1).min(self.cols - 1),
            'd' => self.buffer.row = (n - 1).min(self.rows - 1),
            'H' | 'f' => {
                self.buffer.row = (n - 1).min(self.rows - 1);
                self.buffer.col = (get(1, 1) - 1).min(self.cols - 1);
            }
            's' => self.save(),
            'u' => self.restore(),
            'J' => {
                let mode = params[0];
                let blank = self.blank();
                for r in 0..self.rows {
                    for c in 0..self.cols {
                        if mode == 2
                            || mode == 3
                            || mode == 0 && (r, c) >= (row, col)
                            || mode == 1 && (r, c) <= (row, col)
                        {
                            self.buffer.cells[r][c] = blank.clone();
                        }
                    }
                }
                if mode == 3 {
                    self.history.clear();
                }
            }
            'K' => {
                let mode = params[0];
                let blank = self.blank();
                for c in 0..self.cols {
                    if mode == 2 || mode == 0 && c >= col || mode == 1 && c <= col {
                        self.buffer.cells[row][c] = blank.clone();
                    }
                }
            }
            '@' | 'P' | 'X' => {
                let n = n.min(self.cols - col);
                let blank = self.blank();
                let line = &mut self.buffer.cells[row];
                if action == '@' {
                    for _ in 0..n {
                        line.insert(col, blank.clone());
                        line.pop();
                    }
                } else if action == 'P' {
                    for _ in 0..n {
                        line.remove(col);
                        line.push(blank.clone());
                    }
                } else {
                    line[col..col + n].fill(blank);
                }
            }
            'L' | 'M' if (self.top..=self.bottom).contains(&row) => {
                let old = self.top;
                self.top = row;
                for _ in 0..n.min(self.bottom - row + 1) {
                    self.scroll(action == 'L');
                }
                self.top = old;
            }
            'S' | 'T' => {
                for _ in 0..n.min(self.rows) {
                    self.scroll(action == 'T');
                }
            }
            'r' if !private => {
                let top = n - 1;
                let bottom = get(1, self.rows) - 1;
                if top < bottom && bottom < self.rows {
                    self.top = top;
                    self.bottom = bottom;
                    self.buffer.row = 0;
                    self.buffer.col = 0;
                }
            }
            'h' | 'l' if private => {
                for mode in params {
                    let on = action == 'h';
                    match mode {
                        1 => self.application_cursor = on,
                        7 => self.wrap = on,
                        25 => self.cursor = on,
                        2004 => self.bracketed_paste = on,
                        47 | 1047 | 1049 => {
                            if on && self.main.is_none() {
                                self.save();
                                self.main = Some(std::mem::replace(
                                    &mut self.buffer,
                                    Buffer::new(self.cols, self.rows),
                                ));
                            } else if !on && let Some(main) = self.main.take() {
                                self.buffer = main;
                                self.restore();
                            }
                            self.top = 0;
                            self.bottom = self.rows - 1;
                        }
                        _ => {}
                    }
                }
            }
            'n' if params[0] == 5 => reply.push_str("\x1b[0n"),
            'n' if params[0] == 6 => reply.push_str(&format!("\x1b[{};{}R", row + 1, col + 1)),
            'c' => reply.push_str("\x1b[?1;2c"),
            _ => {}
        }
    }
    pub fn runs(&self, live: bool) -> Vec<Run> {
        let mut runs: Vec<Run> = Vec::new();
        let history = if self.alternate() {
            &[][..]
        } else {
            &self.history[..]
        };
        let end = if self.alternate() {
            self.rows
        } else {
            self.buffer
                .cells
                .iter()
                .rposition(|r| r.iter().any(|c| !c.text.is_empty()))
                .map_or(0, |n| n + 1)
                .max(if live { self.buffer.row + 1 } else { 0 })
        };
        let lines: Vec<_> = history
            .iter()
            .chain(self.buffer.cells[..end].iter())
            .collect();
        for (row, line) in lines.iter().enumerate() {
            let end = line
                .iter()
                .rposition(|c| !c.text.is_empty() || c.style.bg.is_some())
                .map_or(0, |n| n + 1)
                .max(
                    if live && self.cursor && row == history.len() + self.buffer.row {
                        (self.buffer.col + 1).min(self.cols)
                    } else {
                        0
                    },
                );
            for cell in line.iter().take(end) {
                if cell.continuation {
                    continue;
                }
                let style = cell.style.clone();
                let text = if cell.text.is_empty() {
                    " "
                } else {
                    &cell.text
                };
                if let Some(last) = runs
                    .last_mut()
                    .filter(|r| r.style == style && r.link == cell.link)
                {
                    last.text.push_str(text);
                } else {
                    runs.push(Run {
                        text: text.into(),
                        style,
                        link: cell.link.clone(),
                    });
                }
            }
            if row + 1 < lines.len() {
                runs.push(Run {
                    text: "\n".into(),
                    style: Style::default(),
                    link: None,
                });
            }
        }
        runs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn text(screen: &Screen) -> String {
        screen.runs(false).iter().map(|r| r.text.as_str()).collect()
    }
    #[test]
    fn incremental_cursor_erase_and_alternate() {
        let mut s = Screen::new(12, 4);
        s.feed("hello\r\nworld\x1b[");
        s.feed("1;2H!\x1b[K");
        assert_eq!(text(&s), "h!\nworld");
        s.feed("\x1b[?1049h\x1b[2;3Hscreen");
        assert!(s.alternate());
        assert!(text(&s).contains("  screen"));
        s.feed("\x1b[?1049l");
        assert_eq!(text(&s), "h!\nworld");
        assert_eq!(s.feed("\x1b[6n"), "\x1b[1;3R");
    }
    #[test]
    fn scrolling_unicode_styles_and_safe_links() {
        let mut s = Screen::new(8, 3);
        s.feed("1\r\n2\r\n3\r\n4");
        assert_eq!(text(&s), "1\n2\n3\n4");
        s.feed(
            "\x1b[3J\x1b[H\x1b[2J\x1b[31m界e\u{301}\x1b]8;;https://example.com\x1b\\x\x1b]8;;\x07",
        );
        assert_eq!(text(&s), "界e\u{301}x");
        assert_eq!(
            s.runs(false)[0].style.fg,
            Some(super::super::Color::Indexed(1))
        );
        assert_eq!(
            s.runs(false).last().unwrap().link.as_deref(),
            Some("https://example.com")
        );
        s.feed("\x1b]8;;javascript:alert(1)\x07z");
        assert_eq!(s.runs(false).last().unwrap().link, None);
        s.resize(2, 2);
        s.feed("\x1b[999999999999999999999999H!");
    }
    #[test]
    fn overwritten_progress_and_combining_wide_characters() {
        let mut s = Screen::new(12, 4);
        s.feed("progress\r");
        assert!(!s.addressed);
        s.feed("done");
        assert!(s.addressed);
        assert_eq!(text(&s), "doneress");
        s.feed("\x1b[2K\r界\u{301}");
        assert_eq!(text(&s), "界\u{301}");
    }
}

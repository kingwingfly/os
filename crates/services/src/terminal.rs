//! Portable Terminal emulator state machine for `/usr/bin/terminal`.
//!
//! Manages multiple PTY-backed tabs, `os_core::ansi::screen::Screen` grids, OSC 0/2/7
//! title/cwd extraction, dirty-row hashing/diffing, and UTF-8-safe `<= 4096`-byte
//! `DocumentReply` chunking so the core logic is fully unit-tested on host and WASI.

pub use crate::gui_doc::{MAX_CHUNK_WIRE_BYTES, chunk_document_message};
use os_core::ansi::screen::Screen;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Incremental scanner extracting OSC 0 (icon+title), OSC 2 (title), OSC 7 (cwd), and
/// OSC 133 (prompt/command lifecycle markers) from raw PTY output streams, even when
/// split arbitrarily across reads.
#[derive(Clone, Debug, Default)]
pub struct OscTracker {
    state: OscState,
    buf: String,
    pub title: Option<String>,
    pub cwd: Option<String>,
    pub prompt_idle: bool,
    pub prompt_seq: u64,
    pub last_exit_code: Option<i32>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum OscState {
    #[default]
    Ground,
    Esc,
    Body,
    BodyEsc,
}

impl OscTracker {
    /// Feed decoded UTF-8 text; returns `true` if `title` or `cwd` changed.
    pub fn feed(&mut self, text: &str) -> bool {
        let mut changed = false;
        for ch in text.chars() {
            match self.state {
                OscState::Ground => {
                    if ch == '\x1b' {
                        self.state = OscState::Esc;
                    }
                }
                OscState::Esc => {
                    if ch == ']' {
                        self.buf.clear();
                        self.state = OscState::Body;
                    } else if ch != '\x1b' {
                        self.state = OscState::Ground;
                    }
                }
                OscState::Body => {
                    if ch == '\x07' {
                        changed |= self.finish();
                        self.state = OscState::Ground;
                    } else if ch == '\x1b' {
                        self.state = OscState::BodyEsc;
                    } else if self.buf.len() < 4096 {
                        self.buf.push(ch);
                    } else {
                        self.buf.clear();
                        self.state = OscState::Ground;
                    }
                }
                OscState::BodyEsc => {
                    if ch == '\\' {
                        changed |= self.finish();
                        self.state = OscState::Ground;
                    } else if ch == ']' {
                        self.buf.clear();
                        self.state = OscState::Body;
                    } else {
                        self.buf.clear();
                        self.state = OscState::Ground;
                    }
                }
            }
        }
        changed
    }

    fn finish(&mut self) -> bool {
        let body = std::mem::take(&mut self.buf);
        let Some((code, rest)) = body.split_once(';') else {
            return false;
        };
        match code {
            "0" | "2" => {
                let clean = sanitize_title(rest);
                if self.title.as_deref() != Some(clean.as_str()) {
                    self.title = if clean.is_empty() { None } else { Some(clean) };
                    return true;
                }
                false
            }
            "7" => {
                let path = parse_osc7_path(rest);
                if let Some(p) = path
                    && self.cwd.as_deref() != Some(p.as_str())
                {
                    self.cwd = Some(p);
                    return true;
                }
                false
            }
            "133" => {
                let prev = self.prompt_idle;
                if rest == "B" || rest.starts_with("B;") {
                    self.prompt_idle = true;
                    self.prompt_seq = self.prompt_seq.wrapping_add(1);
                    return true;
                } else if rest == "C"
                    || rest.starts_with("C;")
                    || rest == "A"
                    || rest.starts_with("A;")
                {
                    self.prompt_idle = false;
                } else if let Some(code_str) = rest.strip_prefix("D;") {
                    if let Ok(code) = code_str.split(';').next().unwrap_or("").parse::<i32>() {
                        self.last_exit_code = Some(code);
                    }
                    self.prompt_idle = false;
                } else if rest == "D" {
                    self.prompt_idle = false;
                }
                self.prompt_idle != prev
            }
            _ => false,
        }
    }
}

fn sanitize_title(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_control())
        .take(128)
        .collect::<String>()
        .trim()
        .to_owned()
}

/// Extract the filesystem path from an `OSC 7` payload like `file://os/home/user`.
pub fn parse_osc7_path(raw: &str) -> Option<String> {
    let without_scheme = raw.strip_prefix("file://")?;
    let path_start = without_scheme.find('/')?;
    let raw_path = &without_scheme[path_start..];
    if raw_path.is_empty() || raw_path.contains('\0') {
        return None;
    }
    Some(percent_decode(raw_path))
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
        {
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Incremental UTF-8 decoder preserving incomplete trailing multi-byte sequences across reads.
#[derive(Clone, Debug, Default)]
pub struct Utf8Stream {
    pending: Vec<u8>,
}

impl Utf8Stream {
    pub fn push(&mut self, bytes: &[u8]) -> String {
        if bytes.is_empty() {
            return String::new();
        }
        self.pending.extend_from_slice(bytes);
        let mut out = String::new();
        loop {
            match std::str::from_utf8(&self.pending) {
                Ok(valid) => {
                    out.push_str(valid);
                    self.pending.clear();
                    break;
                }
                Err(err) => {
                    let valid_up_to = err.valid_up_to();
                    if valid_up_to > 0 {
                        // SAFETY: `valid_up_to` is guaranteed valid UTF-8 by `from_utf8`.
                        let prefix = std::str::from_utf8(&self.pending[..valid_up_to]).unwrap();
                        out.push_str(prefix);
                    }
                    if let Some(bad_len) = err.error_len() {
                        out.push('\u{FFFD}');
                        self.pending.drain(..valid_up_to + bad_len);
                    } else {
                        self.pending.drain(..valid_up_to);
                        break;
                    }
                }
            }
        }
        out
    }
}

/// Wire message sent by the sealed Document iframe to `/usr/bin/terminal`.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum DocInMsg {
    Ready { cols: u16, rows: u16 },
    In { d: String },
    Resize { cols: u16, rows: u16 },
    NewTab,
    SelectTab { id: u32 },
    CloseTab { id: u32 },
    RestartTab { id: u32 },
    Copy { text: String },
    CopyChunk { id: u32, i: u16, n: u16, d: String },
    Paste,
}

/// Bounded assembler for chunked clipboard-copy messages sent from the Document iframe.
#[derive(Clone, Debug, Default)]
pub struct CopyAssembler {
    id: u32,
    total: usize,
    parts: Vec<Option<String>>,
    received_bytes: usize,
}

impl CopyAssembler {
    pub fn push(&mut self, id: u32, idx: u16, total: u16, data: String) -> Option<String> {
        let total = usize::from(total);
        let idx = usize::from(idx);
        if total == 0 || total > 256 || idx >= total {
            return None;
        }
        if self.id != id || self.total != total {
            self.id = id;
            self.total = total;
            self.parts = vec![None; total];
            self.received_bytes = 0;
        }
        if self.parts[idx].is_some() {
            return None;
        }
        if self.received_bytes.saturating_add(data.len()) > abi::gui::MAX_CLIPBOARD {
            self.parts.clear();
            self.total = 0;
            self.received_bytes = 0;
            return None;
        }
        self.received_bytes += data.len();
        self.parts[idx] = Some(data);
        if self.parts.iter().all(Option::is_some) {
            let mut out = String::with_capacity(self.received_bytes);
            for s in self.parts.drain(..).flatten() {
                out.push_str(&s);
            }
            self.total = 0;
            self.received_bytes = 0;
            return Some(out);
        }
        None
    }
}

/// Wire message sent by a local control client to `/run/user/<uid>/terminal.sock`.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ControlReq {
    OpenTab {
        #[serde(default)]
        argv: Option<Vec<String>>,
        #[serde(default)]
        cwd: Option<String>,
    },
    Focus,
}

/// Compact representation of a styled run inside one rendered screen row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StyledRun {
    pub text: String,
    pub css: String,
    pub link: Option<String>,
}

/// Pure-Rust terminal tab state (PTY fd & child pid live alongside this in the WASI binary).
#[derive(Clone)]
pub struct TabModel {
    pub id: u32,
    pub cols: u16,
    pub rows: u16,
    pub screen: Screen,
    pub osc: OscTracker,
    pub utf8: Utf8Stream,
    pub exited_status: Option<i32>,
    pub dirty: bool,
    last_hashes: Vec<u64>,
    last_cursor: (usize, usize, bool),
    last_alt: bool,
}

impl TabModel {
    pub fn new(id: u32, cols: u16, rows: u16, initial_cwd: Option<String>) -> Self {
        let cols = cols.clamp(10, 500);
        let rows = rows.clamp(4, 200);
        let osc = OscTracker {
            cwd: initial_cwd,
            ..OscTracker::default()
        };
        Self {
            id,
            cols,
            rows,
            screen: Screen::new(cols as usize, rows as usize),
            osc,
            utf8: Utf8Stream::default(),
            exited_status: None,
            dirty: true,
            last_hashes: Vec::new(),
            last_cursor: (0, 0, true),
            last_alt: false,
        }
    }

    /// Feed raw bytes from the PTY master; returns any terminal response bytes (DSR/DA)
    /// that must be written back to the PTY master, plus whether tab title/cwd changed.
    pub fn feed_bytes(&mut self, bytes: &[u8]) -> (Vec<u8>, bool) {
        let text = self.utf8.push(bytes);
        if text.is_empty() {
            return (Vec::new(), false);
        }
        let meta_changed = self.osc.feed(&text);
        let reply = self.screen.feed(&text);
        self.dirty = true;
        (reply.into_bytes(), meta_changed)
    }

    pub fn resize(&mut self, cols: u16, rows: u16) {
        let cols = cols.clamp(10, 500);
        let rows = rows.clamp(4, 200);
        if self.cols == cols && self.rows == rows {
            return;
        }
        self.cols = cols;
        self.rows = rows;
        self.screen.resize(cols as usize, rows as usize);
        self.last_hashes.clear();
        self.dirty = true;
    }

    pub fn reset_for_restart(&mut self, initial_cwd: Option<String>) {
        self.screen = Screen::new(self.cols as usize, self.rows as usize);
        self.osc = OscTracker {
            cwd: initial_cwd,
            ..OscTracker::default()
        };
        self.utf8 = Utf8Stream::default();
        self.exited_status = None;
        self.last_hashes.clear();
        self.dirty = true;
    }

    pub fn display_title(&self, home: &str) -> String {
        if let Some(title) = &self.osc.title
            && !title.is_empty()
        {
            return title.clone();
        }
        if let Some(cwd) = &self.osc.cwd {
            return crate::osh::display_cwd(cwd, home);
        }
        format!("Tab {}", self.id)
    }

    pub fn window_title(&self, home: &str) -> String {
        let sub = self.display_title(home);
        if sub == "Terminal" || sub.is_empty() {
            "Terminal".into()
        } else {
            format!("Terminal — {sub}")
        }
    }

    /// Extract the rendered rows from `self.screen`.
    pub fn rendered_rows(&self) -> Vec<Vec<StyledRun>> {
        let live = self.exited_status.is_none();
        let runs = self.screen.runs(live);
        let mut rows: Vec<Vec<StyledRun>> = vec![Vec::new()];
        for run in runs {
            let css = run.style.css();
            let link = run.link;
            let mut parts = run.text.split('\n');
            if let Some(first) = parts.next()
                && !first.is_empty()
            {
                rows.last_mut().unwrap().push(StyledRun {
                    text: first.to_owned(),
                    css: css.clone(),
                    link: link.clone(),
                });
            }
            for part in parts {
                rows.push(Vec::new());
                if !part.is_empty() {
                    rows.last_mut().unwrap().push(StyledRun {
                        text: part.to_owned(),
                        css: css.clone(),
                        link: link.clone(),
                    });
                }
            }
        }
        rows
    }

    /// Build a full or incremental frame JSON payload. Returns `None` if nothing changed
    /// since the last emitted frame (when `force_full == false`).
    pub fn build_frame_json(&mut self, force_full: bool) -> Option<String> {
        let rows = self.rendered_rows();
        let (cur_row, cur_col) = self.screen.cursor_position();
        let cur_vis = self.screen.cursor && self.exited_status.is_none();
        let alt = self.screen.alternate();

        let hashes: Vec<u64> = rows.iter().map(|r| hash_row(r)).collect();
        let full = force_full
            || self.last_hashes.is_empty()
            || alt != self.last_alt
            || hashes.len() < self.last_hashes.len()
            || hashes.len().saturating_sub(self.last_hashes.len()) > 64;

        let mut changed_lines: Vec<Value> = Vec::new();
        if full {
            for (idx, row) in rows.iter().enumerate() {
                changed_lines.push(encode_line(idx, row));
            }
        } else {
            for (idx, row) in rows.iter().enumerate() {
                if self.last_hashes.get(idx).copied() != Some(hashes[idx]) {
                    changed_lines.push(encode_line(idx, row));
                }
            }
            if changed_lines.is_empty()
                && self.last_hashes.len() == hashes.len()
                && self.last_cursor == (cur_row, cur_col, cur_vis)
                && !self.dirty
            {
                return None;
            }
        }

        self.last_hashes = hashes;
        self.last_cursor = (cur_row, cur_col, cur_vis);
        self.last_alt = alt;
        self.dirty = false;

        let state = if self.exited_status.is_some() {
            "exited"
        } else if self.osc.prompt_idle {
            "idle"
        } else {
            "busy"
        };
        let payload = serde_json::json!({
            "t": "frame",
            "tab": self.id,
            "cols": self.cols,
            "rows": self.rows,
            "total": rows.len(),
            "cursor": { "row": cur_row, "col": cur_col, "visible": cur_vis },
            "alt": alt,
            "app_cursor": self.screen.application_cursor,
            "bracketed_paste": self.screen.bracketed_paste,
            "exited": self.exited_status,
            "state": state,
            "prompt_seq": self.osc.prompt_seq,
            "cwd": self.osc.cwd,
            "full": full,
            "lines": changed_lines,
        });
        Some(payload.to_string())
    }
}

fn hash_row(runs: &[StyledRun]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    let mix = |h: &mut u64, bytes: &[u8]| {
        for &b in bytes {
            *h ^= u64::from(b);
            *h = h.wrapping_mul(0x100000001b3);
        }
        *h ^= 0xff;
        *h = h.wrapping_mul(0x100000001b3);
    };
    for run in runs {
        mix(&mut h, run.text.as_bytes());
        mix(&mut h, run.css.as_bytes());
        if let Some(link) = &run.link {
            mix(&mut h, link.as_bytes());
        }
    }
    h
}

fn encode_line(idx: usize, runs: &[StyledRun]) -> Value {
    let encoded_runs: Vec<Value> = runs
        .iter()
        .map(|r| {
            if let Some(link) = &r.link {
                serde_json::json!([r.text, r.css, link])
            } else if !r.css.is_empty() {
                serde_json::json!([r.text, r.css])
            } else {
                serde_json::json!([r.text])
            }
        })
        .collect();
    serde_json::json!([idx, encoded_runs])
}

/// Summary of one tab sent in `{"t":"tabs", ...}` messages.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct TabSummary {
    pub id: u32,
    pub title: String,
    pub exited: Option<i32>,
}

/// Encode a `{"t":"tabs", ...}` payload.
pub fn encode_tabs_message(active: u32, tabs: &[TabSummary]) -> String {
    serde_json::json!({
        "t": "tabs",
        "active": active,
        "tabs": tabs,
    })
    .to_string()
}

/// Format pasted bytes for a PTY, wrapping in bracketed paste markers when active.
pub fn format_paste_bytes(data: &[u8], bracketed_paste: bool) -> Vec<u8> {
    if !bracketed_paste {
        return data.to_vec();
    }
    let mut out = Vec::with_capacity(data.len() + 12);
    out.extend_from_slice(b"\x1b[200~");
    out.extend_from_slice(data);
    out.extend_from_slice(b"\x1b[201~");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn osc_tracker_parses_split_osc0_osc2_and_osc7() {
        let mut osc = OscTracker::default();
        assert!(!osc.feed("\x1b]7;file://os/home/"));
        assert!(osc.feed("alice/my%20docs\x07"));
        assert_eq!(osc.cwd.as_deref(), Some("/home/alice/my docs"));
        assert!(osc.feed("\x1b]2;vim notes.md\x1b\\"));
        assert_eq!(osc.title.as_deref(), Some("vim notes.md"));
        assert!(osc.feed("\x1b]0;osh\x07"));
        assert_eq!(osc.title.as_deref(), Some("osh"));
        assert!(!osc.prompt_idle);
        assert!(osc.feed("\x1b]133;A\x07\x1b]133;B\x07"));
        assert!(osc.prompt_idle);
        assert!(osc.feed("\x1b]133;C\x07"));
        assert!(!osc.prompt_idle);
        osc.feed("\x1b]133;D;42\x07");
        assert_eq!(osc.last_exit_code, Some(42));
    }

    #[test]
    fn utf8_stream_reassembles_split_multibyte_sequences() {
        let mut s = Utf8Stream::default();
        let bytes = "héllo 界🚀".as_bytes();
        let mut joined = String::new();
        for chunk in bytes.chunks(1) {
            joined.push_str(&s.push(chunk));
        }
        assert_eq!(joined, "héllo 界🚀");
    }

    #[test]
    fn tab_model_diffs_dirty_rows_and_emits_terminal_replies() {
        let mut tab = TabModel::new(1, 40, 10, Some("/home/user".into()));
        let (reply, meta) = tab.feed_bytes(b"\x1b]7;file://os/tmp\x07hello\r\nworld\x1b[6n");
        assert!(meta);
        assert_eq!(reply, b"\x1b[2;6R");
        assert_eq!(tab.display_title("/home/user"), "/tmp");

        let first: Value = serde_json::from_str(&tab.build_frame_json(false).unwrap()).unwrap();
        assert_eq!(first["full"], true);
        assert_eq!(first["lines"].as_array().unwrap().len(), 2);

        // No-op when nothing changed.
        assert!(tab.build_frame_json(false).is_none());

        // Single-line edit emits incremental diff of just row 1.
        tab.feed_bytes(b"!");
        let diff: Value = serde_json::from_str(&tab.build_frame_json(false).unwrap()).unwrap();
        assert_eq!(diff["full"], false);
        let lines = diff["lines"].as_array().unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0][0], 1);
    }

    #[test]
    fn chunk_document_message_respects_4096_byte_limit_with_unicode_and_escapes() {
        // Worst-case mix of escaped quotes, backslashes, and multi-byte UTF-8 characters.
        let big = "\"\\界🚀\n".repeat(1500);
        let chunks = chunk_document_message(7, &big);
        assert!(chunks.len() > 2);
        let mut reassembled = String::new();
        for (idx, frame) in chunks.iter().enumerate() {
            assert!(
                frame.len() <= abi::gui::MAX_DOCUMENT_MESSAGE,
                "chunk {idx} exceeded 4096 bytes: {}",
                frame.len()
            );
            let parsed: Value = serde_json::from_str(frame).unwrap();
            assert_eq!(parsed["t"], "chunk");
            assert_eq!(parsed["id"], 7);
            assert_eq!(parsed["i"], idx);
            assert_eq!(parsed["n"], chunks.len());
            reassembled.push_str(parsed["d"].as_str().unwrap());
        }
        assert_eq!(reassembled, big);
    }

    #[test]
    fn paste_helper_wraps_only_when_bracketed_paste_active() {
        assert_eq!(format_paste_bytes(b"ls", false), b"ls");
        assert_eq!(format_paste_bytes(b"ls", true), b"\x1b[200~ls\x1b[201~");
    }

    #[test]
    fn copy_assembler_reassembles_and_enforces_clipboard_cap() {
        let mut asm = CopyAssembler::default();
        assert_eq!(asm.push(1, 0, 2, "hello ".into()), None);
        assert_eq!(
            asm.push(1, 1, 2, "world".into()).as_deref(),
            Some("hello world")
        );
        // Oversized payload resets without returning.
        let huge = "x".repeat(abi::gui::MAX_CLIPBOARD + 1);
        assert_eq!(asm.push(2, 0, 1, huge), None);
    }
}

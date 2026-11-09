//! What the viewer shows of a file. Its kind comes from its content first, then from its name;
//! for some kinds, Rust prepares what shows: Markdown as HTML, slides, tables, listings of
//! archives, and cards of contacts and events.
//!
//! Markdown's raw HTML is sanitized, as DOMPurify did before, and its relative links and images
//! resolve within the terminal's own filesystem, read with the viewer's permissions.

use std::borrow::Cow;
use std::collections::HashSet;

use ammonia::{UrlRelative, UrlRelativeEvaluate};
use os_preview::language::{self, Language};
use pulldown_cmark::{CodeBlockKind, Event, Options, Parser, Tag, TagEnd};
use pulldown_latex::{RenderConfig, Storage, config::DisplayMode};

/// The most bytes of text shown, ...
pub const TEXT_MAX: usize = 2_000_000;
/// ... and highlighted, which takes a while.
pub const HIGHLIGHT_MAX: usize = 1_000_000;
/// The most bytes of an archive listed, which takes the whole of it.
pub const ARCHIVE_MAX: usize = 50_000_000;
/// The most rows of a table shown.
pub const ROWS_MAX: usize = 1_000;

/// Office documents, which show no preview, not even as the archives some of them are.
const OFFICE: [&str; 13] = [
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "odg", "pages", "numbers",
    "key",
];

/// What a file shows as.
#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    /// An image, a video or audio, shown by the browser from a blob of this MIME type.
    Image(&'static str),
    Video(&'static str),
    Audio(&'static str),
    Pdf,
    /// Markdown, as HTML, with its source, which can also show as slides.
    Markdown {
        html: String,
        source: String,
    },
    /// Text, highlighted as the language of this name in
    /// [`LANGUAGES`](os_preview::language::LANGUAGES), if any, unless too long.
    Code {
        text: String,
        language: Option<&'static str>,
    },
    Table(Table),
    /// A ZIP or tar archive, gzipped or not, which its worker lists.
    Archive,
    /// Contacts or events.
    Cards(Vec<Card>),
    Diff(Vec<(DiffLine, String)>),
    None,
}

/// The rows of a table, the first one as its header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    pub rows: Vec<Vec<String>>,
    /// Whether there are more rows than [`ROWS_MAX`], which do not show.
    pub more: bool,
}

/// A file or directory in an archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub size: u64,
    pub directory: bool,
}

/// A contact or an event: its name, then its fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Card {
    pub title: String,
    pub fields: Vec<(&'static str, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffLine {
    /// `--- a/file` or `+++ b/file`, or what comes before the hunks.
    File,
    /// `@@ -1,2 +1,3 @@`.
    Hunk,
    Added,
    Removed,
    Context,
}

/// What `data`, the file at `path`, shows as.
pub fn kind(path: &str, data: &[u8]) -> Kind {
    let name = path.rsplit('/').next().unwrap_or(path);
    let lower = name.to_lowercase();
    let extension = lower
        .rsplit_once('.')
        .map_or("", |(_, extension)| extension);
    if OFFICE.contains(&extension) {
        return Kind::None;
    }
    if let Some(kind) = sniff(&lower, data) {
        return kind;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return Kind::None;
    };
    if text.len() > TEXT_MAX || text.contains('\0') {
        return Kind::None;
    }
    match extension {
        "md" | "markdown" | "mdown" | "mkd" => Kind::Markdown {
            html: markdown(text, path),
            source: text.to_string(),
        },
        "csv" => table(text, b','),
        "tsv" => table(text, b'\t'),
        "json" => {
            let pretty = serde_json::from_str::<serde_json::Value>(text)
                .and_then(|value| serde_json::to_string_pretty(&value));
            code(
                pretty.unwrap_or_else(|_| text.to_string()),
                language::named("json"),
            )
        }
        "diff" | "patch" => Kind::Diff(diff(text)),
        "vcf" | "vcard" => Kind::Cards(contacts(text)),
        "ics" | "ical" => Kind::Cards(events(text)),
        "svg" if text.contains("<svg") => Kind::Image("image/svg+xml"),
        _ => code(text.to_string(), language::of_file(name)),
    }
}

/// `text`, highlighted as `language`, unless it is too long for that.
fn code(text: String, language: Option<&'static Language>) -> Kind {
    let language = language
        .filter(|_| text.len() <= HIGHLIGHT_MAX)
        .map(|language| language.name);
    Kind::Code { text, language }
}

/// The MIME type of the image `data`, the file `name`, if the browser shows it: PNG, JPEG, GIF,
/// WebP, AVIF, BMP and ICO by their first bytes, and SVG by its name and tag. An SVG shows as an
/// image only, where its scripts do not run.
pub fn image_mime(name: &str, data: &[u8]) -> Option<&'static str> {
    match data {
        [0x89, b'P', b'N', b'G', ..] => Some("image/png"),
        [0xFF, 0xD8, 0xFF, ..] => Some("image/jpeg"),
        [b'G', b'I', b'F', b'8', ..] => Some("image/gif"),
        _ if data.starts_with(b"RIFF") && data.get(8..12) == Some(b"WEBP") => Some("image/webp"),
        [
            _,
            _,
            _,
            _,
            b'f',
            b't',
            b'y',
            b'p',
            b'a',
            b'v',
            b'i',
            b'f' | b's',
            ..,
        ] => Some("image/avif"),
        [b'B', b'M', ..] if data.len() > 26 => Some("image/bmp"),
        [0, 0, 1, 0, count, ..] if *count > 0 => Some("image/x-icon"),
        _ if name.to_lowercase().ends_with(".svg")
            && std::str::from_utf8(data).is_ok_and(|text| text.contains("<svg")) =>
        {
            Some("image/svg+xml")
        }
        _ => None,
    }
}

/// The kind of the file `name`, lowercase, by its first bytes, for the formats that have them.
fn sniff(name: &str, data: &[u8]) -> Option<Kind> {
    if data.starts_with(b"%PDF-") {
        return Some(Kind::Pdf);
    }
    if let Some(mime) = image_mime(name, data) {
        return Some(Kind::Image(mime));
    }
    let window = &data[..data.len().min(64)];
    let has = |needle: &[u8]| window.windows(needle.len()).any(|bytes| bytes == needle);
    Some(match data {
        // ISO base media: MP4, QuickTime, M4A; HEIF images no browser here shows.
        [_, _, _, _, b'f', b't', b'y', b'p', brand @ ..] => match brand.get(..4)? {
            b"qt  " => Kind::Video("video/quicktime"),
            b"M4A " | b"M4B " | b"M4P " => Kind::Audio("audio/mp4"),
            b"heic" | b"heix" | b"hevc" | b"mif1" | b"msf1" => Kind::None,
            _ => Kind::Video("video/mp4"),
        },
        [0x1A, 0x45, 0xDF, 0xA3, ..] if has(b"webm") => Kind::Video("video/webm"),
        [0x1A, 0x45, 0xDF, 0xA3, ..] => Kind::Video("video/x-matroska"),
        [b'O', b'g', b'g', b'S', ..] if has(b"theora") => Kind::Video("video/ogg"),
        [b'O', b'g', b'g', b'S', ..] => Kind::Audio("audio/ogg"),
        [b'f', b'L', b'a', b'C', ..] => Kind::Audio("audio/flac"),
        [
            b'R',
            b'I',
            b'F',
            b'F',
            _,
            _,
            _,
            _,
            b'W',
            b'A',
            b'V',
            b'E',
            ..,
        ] => Kind::Audio("audio/wav"),
        [b'I', b'D', b'3', ..] => Kind::Audio("audio/mpeg"),
        // ADTS AAC, then MPEG audio frames.
        [0xFF, second, ..] if second & 0xF6 == 0xF0 => Kind::Audio("audio/aac"),
        [0xFF, second, ..] if second & 0xE0 == 0xE0 && second & 0x06 != 0 => {
            Kind::Audio("audio/mpeg")
        }
        [b'P', b'K', 3, 4, ..] | [b'P', b'K', 5, 6, ..] | [0x1F, 0x8B, ..] => Kind::Archive,
        _ if data.get(257..262) == Some(b"ustar") => Kind::Archive,
        _ => return None,
    })
}

/// Markdown `source`, the file at `path`, as HTML: GitHub's flavour, with maths, as MathML.
/// Raw HTML is sanitized; links go to the web, to mail, within the document, or to files, as do
/// images, whose relative paths resolve from `path`'s directory. Code blocks are
/// `<pre><code data-lang="…">`, for the page to highlight, or to draw if Mermaid.
pub fn markdown(source: &str, path: &str) -> String {
    let options = Options::ENABLE_TABLES
        | Options::ENABLE_FOOTNOTES
        | Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_TASKLISTS
        | Options::ENABLE_MATH
        | Options::ENABLE_GFM;
    // Maths goes in after sanitizing, which would take MathML apart: each formula is a mark in
    // the text until then. A mark written in the source only shows the formula it names.
    let mut maths = Vec::new();
    let mut mark = |mathml: String| {
        maths.push(mathml);
        format!("{MATH_MARK}{}{MATH_MARK}", maths.len() - 1)
    };
    let events = Parser::new_ext(source, options).map(|event| match event {
        Event::Start(Tag::CodeBlock(kind)) => {
            let lang = match &kind {
                CodeBlockKind::Fenced(info) => info.split_whitespace().next().unwrap_or(""),
                CodeBlockKind::Indented => "",
            };
            Event::Html(format!("<pre><code data-lang=\"{}\">", escape(lang)).into())
        }
        Event::End(TagEnd::CodeBlock) => Event::Html("</code></pre>\n".into()),
        Event::InlineMath(tex) => Event::Text(mark(mathml(&tex, DisplayMode::Inline)).into()),
        Event::DisplayMath(tex) => Event::Text(mark(mathml(&tex, DisplayMode::Block)).into()),
        // Sanitizing would drop the checkboxes, which are inputs.
        Event::TaskListMarker(done) => Event::Text(if done { "☑ " } else { "☐ " }.into()),
        event => event,
    });
    let mut html = String::new();
    pulldown_cmark::html::push_html(&mut html, events);
    let directory = path
        .rsplit_once('/')
        .map_or("/", |(directory, _)| directory);
    let directory = if directory.is_empty() { "/" } else { directory };
    let clean = ammonia::Builder::default()
        .add_tag_attributes("code", &["data-lang"])
        .url_schemes(HashSet::from(["http", "https", "mailto"]))
        .url_relative(UrlRelative::Custom(Box::new(Within(directory.to_string()))))
        .link_rel(Some("noopener noreferrer"))
        .clean(&html)
        .to_string();
    let mut parts = clean.split(MATH_MARK);
    let mut html = parts.next().unwrap_or_default().to_string();
    while let Some(index) = parts.next() {
        match index
            .parse::<usize>()
            .ok()
            .and_then(|index| maths.get(index))
        {
            Some(mathml) => html.push_str(mathml),
            None => {
                html.push(MATH_MARK);
                html.push_str(index);
                html.push(MATH_MARK);
            }
        }
        html.push_str(parts.next().unwrap_or_default());
    }
    html
}

/// Relative URLs in Markdown, resolved from this directory, as files'; links within the
/// document stay as they are.
struct Within(String);

impl<'a> UrlRelativeEvaluate<'a> for Within {
    fn evaluate<'url>(&self, url: &'url str) -> Option<Cow<'url, str>> {
        if url.starts_with('#') {
            return Some(url.into());
        }
        if url.starts_with("//") {
            return None;
        }
        let relative = percent_decode(url.split(['?', '#']).next()?)?;
        let file = os_core::resolve(&self.0, &relative).ok()?;
        Some(file_url(&file).into())
    }
}

/// What marks a formula's place in Markdown until it goes in: a private-use character.
const MATH_MARK: char = '\u{F8FF}';

/// The URL the terminal serves the file at `path` from, with the viewer's permissions.
pub fn file_url(path: &str) -> String {
    let mut url = String::from("/api/file?path=");
    for byte in path.bytes() {
        match byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'!'
            | b'~'
            | b'*'
            | b'\''
            | b'('
            | b')' => url.push(byte as char),
            _ => url.push_str(&format!("%{byte:02X}")),
        }
    }
    url
}

/// The path of the file a [`file_url`] serves, if `url` is one.
pub fn file_path(url: &str) -> Option<String> {
    percent_decode(url.strip_prefix("/api/file?path=")?.split('&').next()?)
}

/// `text` with its `%XX` escapes decoded, if they are UTF-8.
fn percent_decode(text: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(text.len());
    let mut rest = text.as_bytes();
    while let Some((&byte, after)) = rest.split_first() {
        if byte == b'%' {
            let hex = std::str::from_utf8(after.get(..2)?).ok()?;
            bytes.push(u8::from_str_radix(hex, 16).ok()?);
            rest = &after[2..];
        } else {
            bytes.push(byte);
            rest = after;
        }
    }
    String::from_utf8(bytes).ok()
}

/// The TeX `tex` as MathML, or as written if it does not render.
fn mathml(tex: &str, display_mode: DisplayMode) -> String {
    let storage = Storage::new();
    let parser = pulldown_latex::Parser::new(tex, &storage);
    let config = RenderConfig {
        display_mode,
        ..RenderConfig::default()
    };
    let mut mathml = String::new();
    match pulldown_latex::push_mathml(&mut mathml, parser, config) {
        Ok(()) => mathml,
        Err(_) => escape(tex),
    }
}

/// `text` escaped for HTML, in elements and attributes.
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Whether a rendered slide is just one image, without a heading or caption: a whole page of a
/// presentation, which fills the viewer.
pub fn image_slide(html: &str) -> bool {
    let html = html.trim();
    let image = html
        .strip_prefix("<p>")
        .and_then(|p| p.strip_suffix("</p>"))
        .map(str::trim)
        .unwrap_or(html);
    image.starts_with("<img ") && image.find('>') == Some(image.len() - 1)
}

/// A slide: what it shows, and its speaker notes, which show in the speaker view; both HTML.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Slide {
    pub html: String,
    pub notes: String,
}

/// The slides of the reveal.js Markdown `source`, the file at `path`, in columns: a `---` line
/// starts the next column, and a `--` line the next slide in it, except in code blocks. A
/// slide's speaker notes are what follows its `Note:` line.
pub fn slides(source: &str, path: &str) -> Vec<Vec<Slide>> {
    split(source, "---")
        .iter()
        .map(|column| {
            split(column, "--")
                .iter()
                .map(|slide| {
                    let (shown, notes) = notes(slide);
                    Slide {
                        html: markdown(shown, path),
                        notes: markdown(notes, path),
                    }
                })
                .collect()
        })
        .collect()
}

/// The place of the slide `text` names, as reveal.js numbers slides: `3` is the third column,
/// `3.2` the second slide in it.
pub fn slide_number(text: &str) -> Option<(usize, usize)> {
    let (column, row) = text.trim().split_once('.').unwrap_or((text.trim(), "1"));
    let number = |text: &str| text.parse::<usize>().ok()?.checked_sub(1);
    Some((number(column)?, number(row)?))
}

/// `source` cut at each line that is `separator`, outside fenced code blocks.
fn split(source: &str, separator: &str) -> Vec<String> {
    let mut parts = vec![String::new()];
    let mut fence: Option<String> = None;
    for line in source.lines() {
        let indent = line.len() - line.trim_start_matches(' ').len();
        let marker: String = line
            .trim_start_matches(' ')
            .chars()
            .take_while(|c| *c == '`' || *c == '~')
            .collect();
        let opens = indent <= 3
            && marker.len() >= 3
            && marker
                .chars()
                .all(|c| c == marker.chars().next().unwrap_or('`'));
        if opens {
            fence = match fence {
                None => Some(marker),
                Some(open) if marker.starts_with(&open[..1]) && marker.len() >= open.len() => None,
                open => open,
            };
        }
        if fence.is_none() && line.trim_end() == separator {
            parts.push(String::new());
        } else {
            let part = parts.last_mut().expect("never empty");
            part.push_str(line);
            part.push('\n');
        }
    }
    parts
}

/// `slide` cut at its speaker notes, which start at a `Note:` (or `Notes:`) line: what shows,
/// and the notes, without that word.
fn notes(slide: &str) -> (&str, &str) {
    let mut start = 0;
    for line in slide.split_inclusive('\n') {
        let indent = line.len() - line.trim_start().len();
        for word in ["note:", "notes:"] {
            if line[indent..]
                .get(..word.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(word))
            {
                return (&slide[..start], &slide[start + indent + word.len()..]);
            }
        }
        start += line.len();
    }
    (slide, "")
}

/// The CSV `text`, separated by `delimiter`, as a table.
fn table(text: &str, delimiter: u8) -> Kind {
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(delimiter)
        .has_headers(false)
        .flexible(true)
        .from_reader(text.as_bytes());
    let mut rows = vec![];
    let mut more = false;
    for record in reader.records() {
        let Ok(record) = record else { break };
        if rows.len() == ROWS_MAX {
            more = true;
            break;
        }
        rows.push(record.iter().map(str::to_string).collect());
    }
    Kind::Table(Table { rows, more })
}

/// The lines of the unified diff `text`, each with its kind.
fn diff(text: &str) -> Vec<(DiffLine, String)> {
    let mut in_hunk = false;
    text.lines()
        .map(|line| {
            let kind = if line.starts_with("@@") {
                in_hunk = true;
                DiffLine::Hunk
            } else if line.starts_with("diff ") || line.starts_with("--- ") && !in_hunk {
                in_hunk = false;
                DiffLine::File
            } else if !in_hunk {
                DiffLine::File
            } else if line.starts_with('+') {
                DiffLine::Added
            } else if line.starts_with('-') {
                DiffLine::Removed
            } else {
                DiffLine::Context
            };
            (kind, line.to_string())
        })
        .collect()
}

/// The content lines of a vCard or iCalendar file: unfolded, each as its name, upper case, and
/// its value, unescaped.
fn content_lines(text: &str) -> Vec<(String, String)> {
    let mut lines: Vec<String> = vec![];
    for line in text.lines() {
        match (line.strip_prefix([' ', '\t']), lines.last_mut()) {
            (Some(rest), Some(last)) => last.push_str(rest),
            _ => lines.push(line.to_string()),
        }
    }
    lines
        .iter()
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            let name = name.split(';').next()?.trim().to_uppercase();
            let value = value
                .replace("\\n", "\n")
                .replace("\\N", "\n")
                .replace("\\,", ",")
                .replace("\\;", ";")
                .replace("\\\\", "\\");
            Some((name, value))
        })
        .collect()
}

/// The contacts of the vCard file `text`.
fn contacts(text: &str) -> Vec<Card> {
    let mut cards = vec![];
    let mut card: Option<Card> = None;
    for (name, value) in content_lines(text) {
        match (name.as_str(), &mut card) {
            ("BEGIN", None) if value.eq_ignore_ascii_case("VCARD") => {
                card = Some(Card {
                    title: String::new(),
                    fields: vec![],
                });
            }
            ("END", Some(_)) if value.eq_ignore_ascii_case("VCARD") => cards.extend(card.take()),
            ("FN", Some(card)) => card.title = value,
            // The structured name, if there is no formatted one: given then family name.
            ("N", Some(card)) if card.title.is_empty() => {
                let mut parts = value.split(';');
                let family = parts.next().unwrap_or_default();
                let given = parts.next().unwrap_or_default();
                card.title = format!("{given} {family}").trim().to_string();
            }
            (name, Some(card)) => {
                let label = match name {
                    "TEL" => "Phone",
                    "EMAIL" => "Email",
                    "ORG" => "Organization",
                    "TITLE" => "Title",
                    "ADR" => "Address",
                    "URL" => "Web",
                    "BDAY" => "Birthday",
                    "NOTE" => "Note",
                    _ => continue,
                };
                let value = match name {
                    "ADR" | "ORG" => joined(&value),
                    "BDAY" => date(&value),
                    _ => value,
                };
                card.fields.push((label, value));
            }
            _ => {}
        }
    }
    cards
}

/// The events of the iCalendar file `text`, without their alarms.
fn events(text: &str) -> Vec<Card> {
    let mut cards = vec![];
    let mut card: Option<Card> = None;
    let mut nested = 0;
    for (name, value) in content_lines(text) {
        match (name.as_str(), &mut card) {
            ("BEGIN", None) if value.eq_ignore_ascii_case("VEVENT") => {
                card = Some(Card {
                    title: String::new(),
                    fields: vec![],
                });
            }
            ("BEGIN", Some(_)) => nested += 1,
            ("END", Some(_)) if nested > 0 => nested -= 1,
            ("END", Some(_)) if value.eq_ignore_ascii_case("VEVENT") => cards.extend(card.take()),
            (_, Some(_)) if nested > 0 => {}
            ("SUMMARY", Some(card)) => card.title = value,
            (name, Some(card)) => {
                let label = match name {
                    "DTSTART" => "Starts",
                    "DTEND" => "Ends",
                    "LOCATION" => "Where",
                    "ORGANIZER" => "Organizer",
                    "ATTENDEE" => "Attendee",
                    "RRULE" => "Repeats",
                    "DESCRIPTION" => "Description",
                    _ => continue,
                };
                let value = match name {
                    "DTSTART" | "DTEND" => date(&value),
                    "ORGANIZER" | "ATTENDEE" => value
                        .trim_start_matches("mailto:")
                        .trim_start_matches("MAILTO:")
                        .to_string(),
                    _ => value,
                };
                card.fields.push((label, value));
            }
            _ => {}
        }
    }
    cards
}

/// A structured value's parts, such as an address's, joined by commas, the empty ones left out.
fn joined(value: &str) -> String {
    value
        .split(';')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

/// A date or date-time such as `20261025T090000Z` as `2026-10-25 09:00 UTC`; any other as is.
fn date(value: &str) -> String {
    let digits = |range: std::ops::Range<usize>| {
        value
            .get(range)
            .filter(|part| part.bytes().all(|b| b.is_ascii_digit()))
    };
    let (Some(year), Some(month), Some(day)) = (digits(0..4), digits(4..6), digits(6..8)) else {
        return value.to_string();
    };
    let date = format!("{year}-{month}-{day}");
    match (value.get(8..9), digits(9..11), digits(11..13)) {
        (Some("T"), Some(hour), Some(minute)) => {
            let zone = if value.ends_with('Z') { " UTC" } else { "" };
            format!("{date} {hour}:{minute}{zone}")
        }
        _ => date,
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn kinds_come_from_contents_first() {
        let kind_of = |name: &str, data: &[u8]| kind(&format!("/files/{name}"), data);
        assert_eq!(kind_of("x.bin", b"%PDF-1.7\n..."), Kind::Pdf);
        assert_eq!(
            kind_of("photo.txt", b"\x89PNG\r\n\x1a\n...."),
            Kind::Image("image/png")
        );
        assert_eq!(
            kind_of("a", b"\0\0\0\x1cftypavif\0\0\0\0"),
            Kind::Image("image/avif")
        );
        assert_eq!(
            kind_of("clip", b"\0\0\0\x14ftypqt  \0\0\0\0"),
            Kind::Video("video/quicktime")
        );
        assert_eq!(
            kind_of("voice", b"\0\0\0\x1cftypM4A \0\0\0\0"),
            Kind::Audio("audio/mp4")
        );
        assert_eq!(
            kind_of("photo.heic", b"\0\0\0\x18ftypheic\0\0\0\0"),
            Kind::None
        );
        assert_eq!(
            kind_of("a.opus", b"OggS\0\x02....OpusHead"),
            Kind::Audio("audio/ogg")
        );
        assert_eq!(kind_of("song", b"ID3\x04\0\0"), Kind::Audio("audio/mpeg"));
        assert_eq!(
            kind_of("logo.svg", b"<?xml version=\"1.0\"?><svg xmlns=\"\"></svg>"),
            Kind::Image("image/svg+xml")
        );
        // Office documents are archives, but show nothing.
        assert_eq!(kind_of("report.docx", b"PK\x03\x04...."), Kind::None);
        assert_eq!(kind_of("blob", &[0xC3, 0x28, 0x00]), Kind::None);
        // Text, highlighted as its name says, unless too long.
        assert_eq!(
            kind_of("main.rs", b"fn main() {}"),
            Kind::Code {
                text: "fn main() {}".into(),
                language: Some("rust")
            }
        );
        let long = vec![b'a'; HIGHLIGHT_MAX + 1];
        assert!(matches!(
            kind_of("a.rs", &long),
            Kind::Code { language: None, .. }
        ));
        assert_eq!(
            kind_of("a.json", br#"{"a":[1,2]}"#),
            Kind::Code {
                text: "{\n  \"a\": [\n    1,\n    2\n  ]\n}".into(),
                language: Some("json")
            }
        );
    }

    #[test]
    fn markdown_is_sanitized() {
        let html = markdown(
            "# Title\n\n<script>alert(1)</script>\n\n<!-- .slide: data-x -->\n\n\
             <img src=\"missing\" onerror=\"window.xss=true\">\n\n\
             <details><summary>More</summary>kept</details>\n\n\
             [web](https://example.com) [script](javascript:alert(1)) [notes](notes.md#part) \
             [up](../Über%20mich.md) [here](#title)\n\n\
             ![remote](https://example.com/pixel.png) ![local](img/a.png)\n\n\
             - [x] done\n\n```rust\nfn main() {}\n```\n\n$a^2$ and \u{F8FF}7\u{F8FF}\n",
            "/docs/readme.md",
        );
        assert!(html.contains("<h1>Title</h1>"), "{html}");
        assert!(
            !html.contains("<script") && !html.contains("alert(1)</"),
            "{html}"
        );
        assert!(
            !html.contains("onerror") && !html.contains("slide:"),
            "{html}"
        );
        assert!(
            html.contains(r#"<img src="/api/file?path=%2Fdocs%2Fmissing">"#),
            "{html}"
        );
        assert!(
            html.contains("<details><summary>More</summary>kept</details>"),
            "{html}"
        );
        assert!(
            html.contains(r#"<a href="https://example.com" rel="noopener noreferrer">web</a>"#),
            "{html}"
        );
        assert!(
            html.contains(r#"<a rel="noopener noreferrer">script</a>"#),
            "{html}"
        );
        assert!(
            html.contains(r#"href="/api/file?path=%2Fdocs%2Fnotes.md""#),
            "{html}"
        );
        assert!(
            html.contains(r#"href="/api/file?path=%2F%C3%9Cber%20mich.md""#),
            "{html}"
        );
        assert!(html.contains(r##"href="#title""##), "{html}");
        assert!(
            html.contains(r#"src="https://example.com/pixel.png""#),
            "{html}"
        );
        assert!(
            html.contains(r#"src="/api/file?path=%2Fdocs%2Fimg%2Fa.png""#),
            "{html}"
        );
        assert!(html.contains("☑ done"), "{html}");
        assert!(
            html.contains("<pre><code data-lang=\"rust\">fn main() {}\n</code></pre>"),
            "{html}"
        );
        assert!(html.contains("<math"), "{html}");
        // A formula's mark written in the source names none here, and shows as written.
        assert!(html.contains("\u{F8FF}7\u{F8FF}"), "{html}");
        // Maths keeps to itself too.
        assert!(!markdown(r"$\text{<script>}$", "/a.md").contains("<script"));
    }

    #[test]
    fn every_highlighted_language_can_be_uploaded() {
        // Dotfiles are no paths here, so only extensions and plain names count.
        for language in language::LANGUAGES {
            let extensions = language.extensions.iter().map(|e| format!("/a.{e}"));
            let files = language.files.iter().filter(|f| !f.starts_with('.'));
            for path in extensions.chain(files.map(|f| format!("/{f}"))) {
                assert_ne!(os_core::kind(&path), "unknown", "{path}");
            }
        }
    }

    #[test]
    fn file_urls_go_both_ways() {
        let url = file_url("/home/ana/Ünïcode notes (1).md");
        assert_eq!(
            url,
            "/api/file?path=%2Fhome%2Fana%2F%C3%9Cn%C3%AFcode%20notes%20(1).md"
        );
        assert_eq!(
            file_path(&url).as_deref(),
            Some("/home/ana/Ünïcode notes (1).md")
        );
        assert_eq!(file_path("https://example.com/"), None);
    }

    #[test]
    fn image_slides_are_one_image_alone() {
        let deck = slides(
            "![Wide](wide.svg)\n\nNote:\nNotes.\n\n---\n\nA caption ![x](a.png)\n\n---\n\n# Title\n\n![x](a.png)\n",
            "/deck.slides.md",
        );
        let alone: Vec<bool> = deck
            .iter()
            .map(|column| image_slide(&column[0].html))
            .collect();
        assert_eq!(alone, [true, false, false]);
        assert!(!image_slide(
            "<p><a href=\"/x\"><img src=\"a.png\"></a></p>"
        ));
    }

    #[test]
    fn slides_follow_reveal() {
        let deck = "# One\n\n---\n\n# Two\n\n--\n\n# Two, below\n\nNote: said, *not* shown\n\nAt length.\n\n---\n\n# Three\n\nnotes:\nLower case.\n";
        let deck = slides(deck, "/deck.slides.md");
        assert_eq!(deck.iter().map(Vec::len).collect::<Vec<_>>(), [1, 2, 1]);
        assert!(deck[1][1].html.contains("Two, below"));
        assert!(!deck[1][1].html.contains("said"));
        assert_eq!(
            deck[1][1].notes,
            "<p>said, <em>not</em> shown</p>\n<p>At length.</p>\n"
        );
        assert_eq!(deck[2][0].notes, "<p>Lower case.</p>\n");
        assert_eq!(deck[0][0].notes, "");
        // Separators in code blocks are code.
        let deck = slides(
            "# Code\n\n```yaml\n---\nkey: value\n```\n\n---\n\n# Next\n",
            "/d.md",
        );
        assert_eq!(deck.len(), 2);
        assert!(deck[0][0].html.contains("key: value"));
    }

    #[test]
    fn slides_are_numbered_from_one() {
        assert_eq!(slide_number("3"), Some((2, 0)));
        assert_eq!(slide_number(" 3.2 "), Some((2, 1)));
        for wrong in ["", "0", "3.0", "x", "3.", "-1", "3.2.1"] {
            assert_eq!(slide_number(wrong), None, "{wrong}");
        }
    }

    #[test]
    fn tables_cards_and_diffs() {
        let Kind::Table(table) = kind("/a.csv", b"name,age\n\"Doe, J\",30\n") else {
            panic!("a table");
        };
        assert_eq!(table.rows, [["name", "age"], ["Doe, J", "30"]]);
        assert!(!table.more);

        let vcard = "BEGIN:VCARD\r\nVERSION:4.0\r\nN:Doe;Jane;;;\r\nTEL;TYPE=cell:+1 555\r\n\
                     ADR:;;1 Main St;Springfield;;12345;\r\n  USA\r\nEND:VCARD\r\n";
        assert_eq!(
            contacts(vcard),
            [Card {
                title: "Jane Doe".into(),
                fields: vec![
                    ("Phone", "+1 555".into()),
                    ("Address", "1 Main St, Springfield, 12345, USA".into())
                ]
            }]
        );
        let ics = "BEGIN:VCALENDAR\nBEGIN:VEVENT\nSUMMARY:Lab meeting\nDTSTART:20261028T140000Z\n\
                   LOCATION:Room 2\\, east\nBEGIN:VALARM\nDESCRIPTION:reminder\nEND:VALARM\n\
                   END:VEVENT\nEND:VCALENDAR\n";
        assert_eq!(
            events(ics),
            [Card {
                title: "Lab meeting".into(),
                fields: vec![
                    ("Starts", "2026-10-28 14:00 UTC".into()),
                    ("Where", "Room 2, east".into())
                ]
            }]
        );

        let lines = diff("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+new\n same\n");
        let kinds: Vec<_> = lines.iter().map(|(kind, _)| *kind).collect();
        use DiffLine::*;
        assert_eq!(kinds, [File, File, File, Hunk, Removed, Added, Context]);
    }

    #[test]
    fn archives_are_known_by_their_first_bytes() {
        let mut tar = vec![0u8; 512];
        tar[257..262].copy_from_slice(b"ustar");
        for data in [&b"PK\x03\x04rest"[..], b"PK\x05\x06", b"\x1f\x8b\x08", &tar] {
            assert_eq!(kind("/a.bin", data), Kind::Archive);
        }
        assert_eq!(kind("/a.docx", b"PK\x03\x04"), Kind::None);
    }
}

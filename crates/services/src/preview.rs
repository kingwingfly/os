//! Portable Preview engine, hostile-document sanitizers, reading-place store,
//! `.game` manifest validator, and sealed Document UI wire messages (`#64` `L6c-2`).
//!
//! All parsing, sniffing, sanitization (`ammonia` + Mermaid SVG allowlist), slide
//! splitting, table/card/diff formatting, and versioned reading-place persistence
//! (§2.12) run natively in Rust without DOM dependencies so they are unit-tested
//! identically across Linux native and `wasm32-wasip1`.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use abi::gui::{ArchiveMember, PdfPageSize};
use ammonia::{UrlRelative, UrlRelativeEvaluate};
use os_preview::language::{self, Group, Language};
use pulldown_cmark::{CodeBlockKind, Event, Options, Parser, Tag, TagEnd};
use pulldown_latex::{RenderConfig, Storage, config::DisplayMode};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Maximum bytes of text shown directly in Preview.
pub const TEXT_MAX: usize = 2_000_000;
/// Maximum bytes of source text highlighted by Arborium.
pub const HIGHLIGHT_MAX: usize = 1_000_000;
/// Maximum bytes of an archive listed by `preview_archive`.
pub const ARCHIVE_MAX: usize = 50_000_000;
/// Maximum bytes of a PDF opened by `preview_pdf`.
pub const PDF_MAX: usize = 100_000_000;
/// Maximum rows of a CSV/TSV table shown.
pub const ROWS_MAX: usize = 1_000;
/// Maximum `.game` manifest bytes.
pub const GAME_MANIFEST_MAX: usize = 64 * 1024;
/// Maximum reading-place entries persisted in `~/.local/state/os/preview/places.json`.
pub const PLACES_MAX: usize = 200;
pub const PLACES_VERSION: u32 = 1;
pub const PLACES_REL_PATH: &str = ".local/state/os/preview/places.json";
pub const SYSTEM_OS_CONFIG_PATH: &str = "/usr/share/os/config.json";
pub const MAX_PREVIEW_ASSEMBLED_BYTES: usize = 2_600_000;
pub const MAX_PREVIEW_CHUNKS: usize = 1024;

/// Office documents show no preview (even though OOXML/ODF are ZIP archives).
const OFFICE: [&str; 13] = [
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "odg", "pages", "numbers",
    "key",
];

/// What marks a formula's place in Markdown until it is spliced in after sanitization.
const MATH_MARK: char = '\u{F8FF}';

/// Classified preview kind computed from file bytes first, then filename.
#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    Image(&'static str),
    Video(&'static str),
    Audio(&'static str),
    Pdf,
    Markdown {
        html: String,
        source: String,
    },
    Code {
        text: String,
        language: Option<&'static str>,
    },
    Table(Table),
    Archive,
    Cards(Vec<Card>),
    Diff(Vec<(DiffLine, String)>),
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Table {
    pub rows: Vec<Vec<String>>,
    pub more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Card {
    pub title: String,
    pub fields: Vec<(String, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffLine {
    File,
    Hunk,
    Added,
    Removed,
    Context,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Slide {
    pub html: String,
    pub notes: String,
    pub image_only: bool,
}

/// System config schema packaged at `/usr/share/os/config.json` (read-only `0444`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemOsConfig {
    #[serde(default = "default_one")]
    pub version: u32,
    #[serde(default)]
    pub games: BTreeMap<String, String>,
}

fn default_one() -> u32 {
    1
}

/// Parsed `.game` manifest from user files.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct GameManifest {
    #[serde(default)]
    pub engine: String,
    #[serde(default)]
    pub entry: String,
    #[serde(default)]
    pub title: Option<String>,
}

/// Validate a `.game` manifest against the read-only `/usr/share/os/config.json` catalog.
pub fn validate_game_manifest(
    raw_json: &str,
    config: &SystemOsConfig,
) -> Result<(String, String), String> {
    let manifest: GameManifest =
        serde_json::from_str(raw_json).map_err(|e| format!("Invalid game manifest: {e}"))?;
    if manifest.engine != "bevy" {
        return Err(
            "Game entry is not registered; add it to the site content configuration and rebuild"
                .into(),
        );
    }
    let key = manifest.entry.as_str();
    if key.is_empty()
        || key.len() > 128
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(
            "Game entry is not registered; add it to the site content configuration and rebuild"
                .into(),
        );
    }
    let Some(mapped) = config.games.get(key) else {
        return Err(
            "Game entry is not registered; add it to the site content configuration and rebuild"
                .into(),
        );
    };
    if !is_safe_game_url(mapped) {
        return Err(
            "Game entry is not registered; add it to the site content configuration and rebuild"
                .into(),
        );
    }
    let title = manifest
        .title
        .filter(|t| !t.trim().is_empty())
        .unwrap_or_else(|| key.to_owned());
    Ok((key.to_owned(), title))
}

pub fn is_safe_game_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("/content/") else {
        return false;
    };
    if !rest.ends_with(".html") || rest.contains("..") || rest.contains('\\') || rest.contains('\0')
    {
        return false;
    }
    rest.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
}

pub fn load_system_os_config() -> SystemOsConfig {
    let Ok(raw) = fs::read_to_string(SYSTEM_OS_CONFIG_PATH) else {
        return SystemOsConfig::default();
    };
    serde_json::from_str(&raw).unwrap_or_default()
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
            let pretty = serde_json::from_str::<Value>(text)
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

fn code(text: String, language: Option<&'static Language>) -> Kind {
    let language = language
        .filter(|_| text.len() <= HIGHLIGHT_MAX)
        .map(|language| language.name);
    Kind::Code { text, language }
}

pub fn group_name(group: Group) -> &'static str {
    match group {
        Group::Web => "web",
        Group::Systems => "systems",
        Group::Apps => "apps",
        Group::Scripts => "scripts",
    }
}

/// The MIME type of image bytes (magic first, then `.svg` tag check).
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

pub fn media_mime_from_name(path: &str) -> Option<(&'static str, &'static str)> {
    let lower = path.to_lowercase();
    let ext = lower.rsplit_once('.').map_or("", |(_, e)| e);
    match ext {
        "png" => Some(("image", "image/png")),
        "jpg" | "jpeg" => Some(("image", "image/jpeg")),
        "gif" => Some(("image", "image/gif")),
        "webp" => Some(("image", "image/webp")),
        "avif" => Some(("image", "image/avif")),
        "bmp" => Some(("image", "image/bmp")),
        "ico" => Some(("image", "image/x-icon")),
        "svg" => Some(("image", "image/svg+xml")),
        "mp4" | "m4v" => Some(("video", "video/mp4")),
        "webm" => Some(("video", "video/webm")),
        "mov" => Some(("video", "video/quicktime")),
        "ogv" => Some(("video", "video/ogg")),
        "mkv" => Some(("video", "video/x-matroska")),
        "mp3" => Some(("audio", "audio/mpeg")),
        "wav" => Some(("audio", "audio/wav")),
        "ogg" | "opus" => Some(("audio", "audio/ogg")),
        "m4a" => Some(("audio", "audio/mp4")),
        "flac" => Some(("audio", "audio/flac")),
        "weba" => Some(("audio", "audio/webm")),
        "aac" => Some(("audio", "audio/aac")),
        _ => None,
    }
}

pub fn sniff(name: &str, data: &[u8]) -> Option<Kind> {
    if data.starts_with(b"%PDF-") {
        return Some(Kind::Pdf);
    }
    if let Some(mime) = image_mime(name, data) {
        return Some(Kind::Image(mime));
    }
    let window = &data[..data.len().min(64)];
    let has = |needle: &[u8]| window.windows(needle.len()).any(|bytes| bytes == needle);
    Some(match data {
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
        [0xFF, second, ..] if second & 0xF6 == 0xF0 => Kind::Audio("audio/aac"),
        [0xFF, second, ..] if second & 0xE0 == 0xE0 && second & 0x06 != 0 => {
            Kind::Audio("audio/mpeg")
        }
        [b'P', b'K', 3, 4, ..] | [b'P', b'K', 5, 6, ..] | [0x1F, 0x8B, ..] => Kind::Archive,
        _ if data.get(257..262) == Some(b"ustar") => Kind::Archive,
        _ => return None,
    })
}

/// Sanitized GitHub-flavored Markdown with MathML and inert `data-local-src` images.
pub fn markdown(source: &str, path: &str) -> String {
    let options = Options::ENABLE_TABLES
        | Options::ENABLE_FOOTNOTES
        | Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_TASKLISTS
        | Options::ENABLE_MATH
        | Options::ENABLE_GFM;
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
        Event::TaskListMarker(done) => Event::Text(if done { "☑ " } else { "☐ " }.into()),
        event => event,
    });
    let mut html = String::new();
    pulldown_cmark::html::push_html(&mut html, events);
    let directory = path
        .rsplit_once('/')
        .map_or("/", |(directory, _)| directory);
    let directory = if directory.is_empty() { "/" } else { directory };
    let mut clean = ammonia::Builder::default()
        .add_tag_attributes("code", &["data-lang"])
        .url_schemes(HashSet::from(["http", "https", "mailto"]))
        .url_relative(UrlRelative::Custom(Box::new(Within(directory.to_string()))))
        .link_rel(Some("noopener noreferrer"))
        .clean(&html)
        .to_string();
    clean = clean.replace("src=\"/api/file?path=", "data-local-src=\"/api/file?path=");
    for prefix in ["https://", "http://", "//"] {
        clean = clean.replace(
            &format!("src=\"{prefix}"),
            &format!("crossorigin=\"anonymous\" referrerpolicy=\"no-referrer\" src=\"{prefix}"),
        );
    }
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

fn is_allowed_svg_tag(local_lower: &str) -> bool {
    matches!(
        local_lower,
        "svg"
            | "g"
            | "defs"
            | "style"
            | "title"
            | "desc"
            | "path"
            | "rect"
            | "circle"
            | "ellipse"
            | "line"
            | "polyline"
            | "polygon"
            | "text"
            | "tspan"
            | "textpath"
            | "marker"
            | "clippath"
            | "mask"
            | "pattern"
            | "symbol"
            | "use"
            | "switch"
            | "lineargradient"
            | "radialgradient"
            | "stop"
            | "filter"
            | "feblend"
            | "fecolormatrix"
            | "fecomponenttransfer"
            | "fecomposite"
            | "fedropshadow"
            | "feflood"
            | "fefunca"
            | "fefuncb"
            | "fefuncg"
            | "fefuncr"
            | "fegaussianblur"
            | "femerge"
            | "femergenode"
            | "femorphology"
            | "feoffset"
            | "a"
    )
}

fn is_xml_name_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn is_xml_name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':')
}

fn decode_xml_entities(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&'
            && let Some(rel_semi) = bytes[i + 1..].iter().position(|&b| b == b';')
            && rel_semi > 0
            && rel_semi <= 16
        {
            let entity = &input[i + 1..i + 1 + rel_semi];
            let decoded = match entity {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                "colon" => Some(':'),
                "tab" => Some('\t'),
                "newline" => Some('\n'),
                _ if entity.starts_with("#x") || entity.starts_with("#X") => {
                    u32::from_str_radix(&entity[2..], 16)
                        .ok()
                        .and_then(char::from_u32)
                }
                _ if entity.starts_with('#') => {
                    entity[1..].parse::<u32>().ok().and_then(char::from_u32)
                }
                _ => None,
            };
            if let Some(ch) = decoded {
                out.push(ch);
                i += rel_semi + 2;
                continue;
            }
        }
        let ch = input[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn xml_escape_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(ch),
        }
    }
    out
}

fn xml_escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(ch),
        }
    }
    out
}

fn strip_css_comments(css: &str) -> String {
    let mut out = String::with_capacity(css.len());
    let mut rest = css;
    while let Some(start) = rest.find("/*") {
        out.push_str(&rest[..start]);
        match rest[start + 2..].find("*/") {
            Some(end) => rest = &rest[start + 2 + end + 2..],
            None => return out,
        }
    }
    out.push_str(rest);
    out
}

fn all_css_urls_are_fragments(text: &str) -> bool {
    let lower = strip_css_comments(text).to_ascii_lowercase();
    let mut rest = lower.as_str();
    while let Some(pos) = rest.find("url") {
        rest = &rest[pos + 3..];
        let trimmed = rest.trim_start();
        let Some(after_paren) = trimmed.strip_prefix('(') else {
            continue;
        };
        let Some(close) = after_paren.find(')') else {
            return false;
        };
        let arg = after_paren[..close]
            .trim()
            .trim_matches(|c| c == '"' || c == '\'')
            .trim();
        if !arg.starts_with('#')
            || arg.len() < 2
            || arg.contains(':')
            || arg.chars().any(char::is_whitespace)
        {
            return false;
        }
        rest = &after_paren[close + 1..];
    }
    true
}

fn is_safe_svg_css(css: &str) -> bool {
    let no_comments = strip_css_comments(css);
    if no_comments.contains('\\') {
        return false;
    }
    let compact: String = no_comments
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .to_ascii_lowercase();
    for bad in [
        "javascript:",
        "vbscript:",
        "data:",
        "expression(",
        "@import",
        "behavior:",
        "-moz-binding",
    ] {
        if compact.contains(bad) {
            return false;
        }
    }
    all_css_urls_are_fragments(&no_comments) && all_css_urls_are_fragments(&compact)
}

fn is_safe_svg_attr(raw_name: &str, raw_val: &str) -> Option<String> {
    let lower = raw_name.to_ascii_lowercase();
    if lower.starts_with("on")
        || matches!(
            lower.as_str(),
            "src" | "srcdoc" | "formaction" | "action" | "ping" | "data"
        )
    {
        return None;
    }
    let decoded = decode_xml_entities(raw_val);
    let compact: String = decoded
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && !c.is_control())
        .collect();
    let compact_lower = compact.to_ascii_lowercase();
    if lower == "href" || lower.ends_with(":href") {
        if !compact.starts_with('#') || compact.len() < 2 || compact.contains(':') {
            return None;
        }
        return Some(compact);
    }
    if lower == "style" {
        if !is_safe_svg_css(&decoded) {
            return None;
        }
        return Some(decoded);
    }
    if compact_lower.contains("javascript:")
        || compact_lower.contains("vbscript:")
        || !all_css_urls_are_fragments(&decoded)
    {
        return None;
    }
    Some(decoded)
}

/// Sanitize a Mermaid SVG string produced by `preview_diagram` before rendering as `<img src="data:image/svg+xml,...">`.
/// Uses a strict XML-preserving element/attribute allowlist tokenizer (zero regexes), preserving
/// exact SVG XML casing (`viewBox`, `linearGradient`, `clipPath`, etc.) while dropping comments,
/// processing instructions, DOCTYPE/entities, disallowed element subtrees (`<script>`,
/// `<foreignObject>`, `<animate>`, `<set>`, `<iframe>`, `<object>`, `<embed>`, etc.), `on*`
/// event handlers, non-fragment `href`/`*:href` URLs, and unsafe CSS.
pub fn sanitize_svg(svg: &str) -> Result<String, String> {
    let bytes = svg.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    let mut out = String::with_capacity(len);
    let mut skip_stack: Vec<String> = Vec::new();
    let mut open_tags: Vec<(String, String)> = Vec::new(); // (local_lower, raw_name)
    let mut style_buf: Option<String> = None;
    let mut saw_svg = false;

    while i < len {
        if bytes[i] != b'<' {
            let start = i;
            while i < len && bytes[i] != b'<' {
                i += 1;
            }
            if skip_stack.is_empty() {
                let text = &svg[start..i];
                if let Some(buf) = style_buf.as_mut() {
                    buf.push_str(&decode_xml_entities(text));
                } else {
                    out.push_str(text);
                }
            }
            continue;
        }

        // XML comment: <!-- ... -->
        if svg[i..].starts_with("<!--") {
            match svg[i + 4..].find("-->") {
                Some(end) => i += 4 + end + 3,
                None => break,
            }
            continue;
        }
        // CDATA: <![CDATA[ ... ]]>
        if svg[i..].starts_with("<![CDATA[") {
            let content_start = i + 9;
            match svg[content_start..].find("]]>") {
                Some(end) => {
                    if skip_stack.is_empty() {
                        let body = &svg[content_start..content_start + end];
                        if let Some(buf) = style_buf.as_mut() {
                            buf.push_str(body);
                        } else {
                            out.push_str(&xml_escape_text(body));
                        }
                    }
                    i = content_start + end + 3;
                }
                None => break,
            }
            continue;
        }
        // Processing instruction: <? ... ?>
        if svg[i..].starts_with("<?") {
            match svg[i + 2..].find("?>") {
                Some(end) => i += 2 + end + 2,
                None => break,
            }
            continue;
        }
        // DOCTYPE / ENTITY / declaration: <! ... > (respecting internal [...] subset)
        if svg[i..].starts_with("<!") {
            i += 2;
            let mut bracket_depth = 0usize;
            while i < len {
                match bytes[i] {
                    b'[' => bracket_depth += 1,
                    b']' => bracket_depth = bracket_depth.saturating_sub(1),
                    b'>' if bracket_depth == 0 => {
                        i += 1;
                        break;
                    }
                    _ => {}
                }
                i += 1;
            }
            continue;
        }

        // Closing tag: </name>
        if svg[i..].starts_with("</") {
            let mut p = i + 2;
            while p < len && bytes[p].is_ascii_whitespace() {
                p += 1;
            }
            let name_start = p;
            while p < len && is_xml_name_char(bytes[p]) {
                p += 1;
            }
            let raw_name = &svg[name_start..p];
            let local_lower = raw_name
                .rsplit_once(':')
                .map_or(raw_name, |(_, l)| l)
                .to_ascii_lowercase();
            while p < len && bytes[p] != b'>' {
                p += 1;
            }
            i = if p < len { p + 1 } else { len };

            if !skip_stack.is_empty() {
                if let Some(pos) = skip_stack.iter().rposition(|t| t == &local_lower) {
                    skip_stack.truncate(pos);
                }
            } else if let Some(pos) = open_tags.iter().rposition(|(l, _)| l == &local_lower) {
                while open_tags.len() > pos {
                    let (closed_lower, orig) = open_tags.pop().unwrap();
                    if closed_lower == "style"
                        && let Some(buf) = style_buf.take()
                        && is_safe_svg_css(&buf)
                    {
                        out.push_str(&xml_escape_text(&buf));
                    }
                    out.push_str("</");
                    out.push_str(&orig);
                    out.push('>');
                }
            }
            continue;
        }

        // Opening or self-closing tag: <name ...>
        let mut p = i + 1;
        if p >= len || !is_xml_name_start(bytes[p]) {
            if skip_stack.is_empty() {
                if let Some(buf) = style_buf.as_mut() {
                    buf.push('<');
                } else {
                    out.push_str("&lt;");
                }
            }
            i += 1;
            continue;
        }
        let name_start = p;
        while p < len && is_xml_name_char(bytes[p]) {
            p += 1;
        }
        let raw_name = &svg[name_start..p];
        let local_lower = raw_name
            .rsplit_once(':')
            .map_or(raw_name, |(_, l)| l)
            .to_ascii_lowercase();

        // Parse attributes up to closing `>` (respecting quoted values).
        let mut attrs: Vec<(&str, String)> = Vec::new();
        let mut self_closing = false;
        while p < len {
            while p < len && bytes[p].is_ascii_whitespace() {
                p += 1;
            }
            if p >= len {
                break;
            }
            if bytes[p] == b'>' {
                p += 1;
                break;
            }
            if bytes[p] == b'/' {
                p += 1;
                while p < len && bytes[p].is_ascii_whitespace() {
                    p += 1;
                }
                if p < len && bytes[p] == b'>' {
                    self_closing = true;
                    p += 1;
                    break;
                }
                continue;
            }
            if !is_xml_name_start(bytes[p]) {
                p += 1;
                continue;
            }
            let a_start = p;
            while p < len && is_xml_name_char(bytes[p]) {
                p += 1;
            }
            let attr_name = &svg[a_start..p];
            while p < len && bytes[p].is_ascii_whitespace() {
                p += 1;
            }
            if p < len && bytes[p] == b'=' {
                p += 1;
                while p < len && bytes[p].is_ascii_whitespace() {
                    p += 1;
                }
                let raw_val = if p < len && (bytes[p] == b'"' || bytes[p] == b'\'') {
                    let quote = bytes[p];
                    p += 1;
                    let v_start = p;
                    while p < len && bytes[p] != quote {
                        p += 1;
                    }
                    let val = &svg[v_start..p];
                    if p < len {
                        p += 1;
                    }
                    val
                } else {
                    let v_start = p;
                    while p < len
                        && !bytes[p].is_ascii_whitespace()
                        && bytes[p] != b'>'
                        && !(bytes[p] == b'/' && p + 1 < len && bytes[p + 1] == b'>')
                    {
                        p += 1;
                    }
                    &svg[v_start..p]
                };
                if skip_stack.is_empty()
                    && style_buf.is_none()
                    && is_allowed_svg_tag(&local_lower)
                    && let Some(clean_val) = is_safe_svg_attr(attr_name, raw_val)
                {
                    attrs.push((attr_name, clean_val));
                }
            }
        }
        i = p;

        if !skip_stack.is_empty() {
            if !self_closing {
                skip_stack.push(local_lower);
            }
            continue;
        }
        if style_buf.is_some() || !is_allowed_svg_tag(&local_lower) {
            if !self_closing {
                skip_stack.push(local_lower);
            }
            continue;
        }
        if local_lower == "svg" {
            saw_svg = true;
        }
        out.push('<');
        out.push_str(raw_name);
        for (k, v) in attrs {
            out.push(' ');
            out.push_str(k);
            out.push_str("=\"");
            out.push_str(&xml_escape_attr(&v));
            out.push('"');
        }
        if self_closing {
            out.push_str("/>");
        } else {
            out.push('>');
            if local_lower == "style" {
                style_buf = Some(String::new());
            }
            open_tags.push((local_lower, raw_name.to_owned()));
        }
    }

    while let Some((closed_lower, orig)) = open_tags.pop() {
        if closed_lower == "style"
            && let Some(buf) = style_buf.take()
            && is_safe_svg_css(&buf)
        {
            out.push_str(&xml_escape_text(&buf));
        }
        out.push_str("</");
        out.push_str(&orig);
        out.push('>');
    }
    if !saw_svg {
        return Err("Invalid SVG diagram".into());
    }
    Ok(out)
}

/// Sanitize Arborium highlighted HTML (`<span class="hl-...">` or `<a-k>` etc. — strips any non-span/script tags).
pub fn sanitize_highlight_html(html: &str) -> String {
    ammonia::Builder::empty()
        .tags(HashSet::from(["span"]))
        .add_tag_attributes("span", &["class"])
        .clean(html)
        .to_string()
}

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

pub fn file_path(url: &str) -> Option<String> {
    percent_decode(url.strip_prefix("/api/file?path=")?.split('&').next()?)
}

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

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub fn image_slide(html: &str) -> bool {
    let html = html.trim();
    let image = html
        .strip_prefix("<p>")
        .and_then(|p| p.strip_suffix("</p>"))
        .map(str::trim)
        .unwrap_or(html);
    image.starts_with("<img ") && image.find('>') == Some(image.len() - 1)
}

pub fn slides(source: &str, path: &str) -> Vec<Vec<Slide>> {
    split(source, "---")
        .iter()
        .map(|column| {
            split(column, "--")
                .iter()
                .map(|slide| {
                    let (shown, slide_notes) = notes(slide);
                    let html = markdown(shown, path);
                    let image_only = image_slide(&html);
                    Slide {
                        html,
                        notes: markdown(slide_notes, path),
                        image_only,
                    }
                })
                .collect()
        })
        .collect()
}

pub fn slide_number(text: &str) -> Option<(usize, usize)> {
    let (column, row) = text.trim().split_once('.').unwrap_or((text.trim(), "1"));
    let number = |text: &str| text.parse::<usize>().ok()?.checked_sub(1);
    Some((number(column)?, number(row)?))
}

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
                card.fields.push((label.to_string(), value));
            }
            _ => {}
        }
    }
    cards
}

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
                card.fields.push((label.to_string(), value));
            }
            _ => {}
        }
    }
    cards
}

fn joined(value: &str) -> String {
    value
        .split(';')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

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

/// Default presentation name for a path (matching `web/dev.mjs` `defaultName`).
pub fn default_present_name(path: &str) -> String {
    let file = path.rsplit('/').next().unwrap_or(path);
    let lower = file.to_lowercase();
    let stem = if lower.ends_with(".slides.md") && file.len() > ".slides.md".len() {
        &file[..file.len() - ".slides.md".len()]
    } else if let Some((s, _)) = file.rsplit_once('.')
        && !s.is_empty()
    {
        s
    } else {
        file
    };
    if stem.is_empty() {
        file.to_owned()
    } else {
        stem.to_owned()
    }
}

/// Strip `/mnt/cloud` prefix to canonical cloud-relative path.
pub fn to_cloud_path(path: &str) -> String {
    if path == "/mnt/cloud" {
        "/".into()
    } else if let Some(rest) = path.strip_prefix("/mnt/cloud/") {
        format!("/{rest}")
    } else {
        path.to_owned()
    }
}

/// Persistent reading places & UI preferences (`~/.local/state/os/preview/places.json`, Contract §2.12).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlacesFile {
    pub version: u32,
    #[serde(default = "default_slide_theme")]
    pub slide_theme: String,
    #[serde(default = "default_notes_size")]
    pub notes_size: u32,
    #[serde(default)]
    pub entries: Vec<(String, Value)>,
}

fn default_slide_theme() -> String {
    "light".into()
}

fn default_notes_size() -> u32 {
    24
}

impl Default for PlacesFile {
    fn default() -> Self {
        Self {
            version: PLACES_VERSION,
            slide_theme: default_slide_theme(),
            notes_size: default_notes_size(),
            entries: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum PlacesLoadOutcome {
    Loaded(PlacesFile),
    Missing,
    ResetOlder(u32),
    RefusedNewer(u32),
}

pub fn load_places_file(path: &Path) -> PlacesLoadOutcome {
    let Ok(bytes) = fs::read(path) else {
        return PlacesLoadOutcome::Missing;
    };
    let Ok(raw) = serde_json::from_slice::<Value>(&bytes) else {
        return PlacesLoadOutcome::Missing;
    };
    let Some(ver) = raw.get("version").and_then(Value::as_u64) else {
        return PlacesLoadOutcome::Missing;
    };
    let ver = ver as u32;
    if ver > PLACES_VERSION {
        return PlacesLoadOutcome::RefusedNewer(ver);
    }
    if ver < PLACES_VERSION {
        return PlacesLoadOutcome::ResetOlder(ver);
    }
    match serde_json::from_value::<PlacesFile>(raw) {
        Ok(mut pf) => {
            if !matches!(
                pf.slide_theme.as_str(),
                "light" | "dark" | "sepia" | "night"
            ) {
                pf.slide_theme = default_slide_theme();
            }
            pf.notes_size = pf.notes_size.clamp(14, 56);
            pf.entries.truncate(PLACES_MAX);
            PlacesLoadOutcome::Loaded(pf)
        }
        Err(_) => PlacesLoadOutcome::Missing,
    }
}

pub fn save_places_file_atomic(path: &Path, pf: &PlacesFile) -> io::Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static TMP_SEQ: AtomicU64 = AtomicU64::new(1);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        let _ = os_posix::chmod(parent, 0o700);
    }
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = PathBuf::from(format!("{}.tmp.{stamp:x}.{seq}", path.display()));
    let bytes =
        serde_json::to_vec(pf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let res = (|| -> io::Result<()> {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(all(unix, not(target_os = "wasi")))]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        let _ = os_posix::chmod(&tmp, 0o600);
        f.write_all(&bytes)?;
        let _ = f.sync_all();
        drop(f);
        fs::rename(&tmp, path)?;
        Ok(())
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res
}

impl PlacesFile {
    pub fn get(&self, path: &str) -> Value {
        self.entries
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| Value::Object(Default::default()))
    }

    pub fn merge(&mut self, path: &str, patch: Value) {
        let mut base = self
            .entries
            .iter()
            .find(|(p, _)| p == path)
            .and_then(|(_, v)| v.as_object().cloned())
            .unwrap_or_default();
        if let Some(obj) = patch.as_object() {
            for (k, v) in obj {
                base.insert(k.clone(), v.clone());
            }
        }
        self.entries.retain(|(p, _)| p != path);
        self.entries
            .insert(0, (path.to_owned(), Value::Object(base)));
        self.entries.truncate(PLACES_MAX);
    }
}

/// Control RPC over `/run/user/<uid>/preview.sock` (single-instance reuse for `open`/`man`/`present`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum PreviewControlReq {
    Open {
        path: String,
    },
    Manual {
        #[serde(default)]
        command: Option<String>,
    },
    Present {
        path: String,
        #[serde(default)]
        name: Option<String>,
    },
    StopPresent {
        name: String,
    },
    Focus {},
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreviewControlReply {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdout: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Live presentation controls bar state synced from `/usr/bin/preview` to `preview.js`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveBarState {
    pub path: Option<String>,
    pub user: Option<String>,
    pub presented: Vec<String>,
    pub asks: Vec<LiveAsk>,
    pub voices: Vec<LiveVoice>,
    pub sound: Option<LiveSending>,
    pub asking: Option<LiveAsking>,
    pub note: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveAsk {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub presentation: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveVoice {
    pub device: String,
    pub speaker: String,
    #[serde(default)]
    pub presentation: String,
    #[serde(default)]
    pub ask: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveSending {
    pub device: Option<String>,
    pub recording: Option<String>,
    pub since: u64,
    pub progress: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveAsking {
    pub state: String,
    pub error: Option<String>,
}

/// Audience badge info when following another user's `/dev/present/*` device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AudienceInfo {
    pub device: String,
    pub owner: String,
    pub ended: bool,
}

/// Rendered view payload sent from `/usr/bin/preview` to `web/gui/preview/preview.js`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "view", rename_all = "snake_case")]
pub enum PreviewViewPayload {
    Loading {},
    Error {
        message: String,
    },
    NoPreview {
        message: String,
    },
    Markdown {
        html: String,
        slides: Vec<Vec<Slide>>,
        as_slides: bool,
        manual: bool,
    },
    Slides {
        slides: Vec<Vec<Slide>>,
    },
    Code {
        text: String,
        language: Option<String>,
    },
    Table {
        table: Table,
        rows_max: usize,
    },
    Cards {
        cards: Vec<Card>,
    },
    Diff {
        lines: Vec<(DiffLine, String)>,
    },
    Media {
        media_kind: String,
        asset_id: u64,
        mime: String,
        mode: String,
    },
    Pdf {
        pages: Vec<PdfPageSize>,
        doc_id: u32,
        loading: bool,
        error: Option<String>,
    },
    Archive {
        loading: bool,
        entries: Vec<ArchiveMember>,
        more: bool,
        error: Option<String>,
    },
    Game {
        title: String,
    },
}

/// Messages sent from sealed `web/gui/preview/preview.js` iframe to `/usr/bin/preview`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case", deny_unknown_fields)]
pub enum PreviewUiMsg {
    Ready {},
    Close {},
    Back {},
    Download {},
    ToggleFullscreen {
        active: bool,
    },
    FollowLink {
        path: String,
    },
    RequestLocalImage {
        req_id: u64,
        path: String,
    },
    RequestHighlight {
        req_id: u64,
        info: String,
        text: String,
    },
    RequestDiagram {
        req_id: u64,
        source: String,
    },
    RequestPdfRender {
        req_id: u64,
        doc_id: u32,
        page: u32,
        width: u32,
    },
    SavePlace {
        path: String,
        patch: Value,
    },
    SetPref {
        #[serde(default)]
        slide_theme: Option<String>,
        #[serde(default)]
        notes_size: Option<u32>,
    },
    TellPresenting {
        path: String,
        column: u32,
        row: u32,
    },
    AskWhere {
        path: String,
    },
    OpenSpeaker {
        path: String,
    },
    TogglePresenting {
        path: String,
    },
    GoLive {
        path: String,
        keep: bool,
    },
    AskToSpeak {},
    AnswerAsk {
        id: String,
        allow: bool,
    },
    EndVoice {
        device: String,
    },
}

/// Messages sent from `/usr/bin/preview` to `web/gui/preview/preview.js`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum PreviewHostMsg {
    Show {
        version: u64,
        path: String,
        title: String,
        can_back: bool,
        back_title: String,
        can_download: bool,
        speaker_mode: bool,
        slide_theme: String,
        notes_size: u32,
        place: Value,
        #[serde(skip_serializing_if = "Option::is_none")]
        last_presented: Option<[u32; 2]>,
        #[serde(skip_serializing_if = "Option::is_none")]
        audience: Option<AudienceInfo>,
        #[serde(flatten)]
        payload: PreviewViewPayload,
    },
    PdfReady {
        version: u64,
        doc_id: u32,
        pages: Vec<PdfPageSize>,
    },
    PdfError {
        version: u64,
        message: String,
    },
    ArchiveReady {
        version: u64,
        entries: Vec<ArchiveMember>,
        more: bool,
    },
    ArchiveError {
        version: u64,
        message: String,
    },
    LocalImageReady {
        req_id: u64,
        asset_id: u64,
        mime: String,
    },
    LocalImageError {
        req_id: u64,
        message: String,
    },
    HighlightResult {
        req_id: u64,
        html: Option<String>,
        error: Option<String>,
    },
    DiagramResult {
        req_id: u64,
        svg: Option<String>,
        error: Option<String>,
    },
    PdfRendered {
        req_id: u64,
        doc_id: u32,
        page: u32,
        width: u32,
        height: u32,
        error: Option<String>,
    },
    Fullscreen {
        active: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    PresentUpdate {
        path: String,
        column: u32,
        row: u32,
        #[serde(default)]
        from_where: bool,
    },
    AudienceUpdate {
        #[serde(skip_serializing_if = "Option::is_none")]
        audience: Option<AudienceInfo>,
    },
    LiveBar {
        bar: LiveBarState,
    },
    Notice {
        message: String,
    },
    Focus {},
}

#[cfg(test)]
mod tests {
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
            kind_of("logo.svg", b"<?xml version=\"1.0\"?><svg xmlns=\"\"></svg>"),
            Kind::Image("image/svg+xml")
        );
        assert_eq!(kind_of("report.docx", b"PK\x03\x04...."), Kind::None);
        assert_eq!(
            kind_of("main.rs", b"fn main() {}"),
            Kind::Code {
                text: "fn main() {}".into(),
                language: Some("rust"),
            }
        );
    }

    #[test]
    fn hostile_markdown_and_svg_are_strictly_sanitized() {
        let html = markdown(
            "# Title\n\n<script>alert(1)</script>\n\n\
             <iframe src=\"/\"></iframe>\n\n\
             <img src=\"missing\" onerror=\"window.xss=true\">\n\n\
             [web](https://example.com) [bad](javascript:alert(1)) [notes](notes.md#part)\n\n\
             ![local](img/a.png)\n\n$a^2$\n",
            "/docs/readme.md",
        );
        assert!(html.contains("<h1>Title</h1>"));
        assert!(!html.contains("<script"));
        assert!(!html.contains("<iframe"));
        assert!(!html.contains("onerror"));
        assert!(!html.contains("javascript:"));
        assert!(html.contains(r#"data-local-src="/api/file?path=%2Fdocs%2Fimg%2Fa.png""#));
        assert!(html.contains("<math"));

        let hostile_svg = concat!(
            r##"<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY x "y">]>"##,
            r##"<!-- comment --><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" onload=alert(1)>"##,
            r##"<defs><linearGradient id="g1"><stop offset="0%" stop-color="#0f0"/></linearGradient></defs>"##,
            r##"<script><script>fetch('/api/sys')</script>alert(2)</script>"##,
            r##"<foreignObject><body><script>x()</script></body></foreignObject>"##,
            r##"<animate onbegin="alert(3)" attributeName="x"/>"##,
            r##"<set attributeName="href" to="javascript:alert(4)"/>"##,
            r##"<a xlink:href="&#x6a;avascript:alert(1)" href=https://evil.example/x>"##,
            r##"<rect width="10" height="10" fill="url(#g1)" style="background:url(https://evil.example/a)"/></a>"##,
            r##"<a xmlns:x="http://www.w3.org/1999/xlink" x:href="https://evil.example/ns"><use href="#g1" data-ok="1"/></a>"##,
            r##"<style>.ok { fill: #2a6; }</style>"##,
            r##"<style>u<!-- -->rl(https://evil.example/split)</style>"##,
            r##"<style>u<![CDATA[rl(https://evil.example/cdata)]]></style>"##,
            r##"<style>&#x75;rl(https://evil.example/ent)</style>"##,
            r##"<style>u\rl(https://evil.example/bs)</style>"##,
            r##"</svg>"##,
        );
        let clean_svg = sanitize_svg(hostile_svg).unwrap();
        assert!(!clean_svg.contains("<script"), "{clean_svg}");
        assert!(!clean_svg.contains("alert("), "{clean_svg}");
        assert!(!clean_svg.contains("foreignObject"), "{clean_svg}");
        assert!(!clean_svg.contains("<animate"), "{clean_svg}");
        assert!(!clean_svg.contains("<set"), "{clean_svg}");
        assert!(!clean_svg.contains("onload"), "{clean_svg}");
        assert!(!clean_svg.contains("javascript:"), "{clean_svg}");
        assert!(!clean_svg.contains("evil.example"), "{clean_svg}");
        assert!(!clean_svg.contains("x:href"), "{clean_svg}");
        assert!(!clean_svg.contains("DOCTYPE"), "{clean_svg}");
        assert!(!clean_svg.contains("<!--"), "{clean_svg}");
        assert!(clean_svg.contains(".ok { fill: #2a6; }"), "{clean_svg}");
        assert!(
            clean_svg.contains(r##"viewBox="0 0 100 100""##),
            "{clean_svg}"
        );
        assert!(clean_svg.contains("<linearGradient"), "{clean_svg}");
        assert!(clean_svg.contains(r##"fill="url(#g1)""##), "{clean_svg}");
        assert!(clean_svg.contains(r##"href="#g1""##), "{clean_svg}");
        assert!(clean_svg.contains("<rect"), "{clean_svg}");
        assert!(sanitize_svg("<div>not svg</div>").is_err());
    }

    #[test]
    fn game_manifest_validation_rejects_unregistered_and_traversal() {
        let mut games = BTreeMap::new();
        games.insert("signal".into(), "/content/signal.html".into());
        games.insert("evil".into(), "/content/../index.html".into());
        let cfg = SystemOsConfig { version: 1, games };

        assert_eq!(
            validate_game_manifest(
                r#"{"engine":"bevy","entry":"signal","title":"Signal"}"#,
                &cfg
            )
            .unwrap(),
            ("signal".into(), "Signal".into())
        );
        for bad in [
            r#"{"engine":"bevy","entry":"__proto__"}"#,
            r#"{"engine":"bevy","entry":"constructor"}"#,
            r#"{"engine":"bevy","entry":"../../index.html"}"#,
            r#"{"engine":"bevy","entry":"evil"}"#,
            r#"{"engine":"unity","entry":"signal"}"#,
        ] {
            assert!(
                validate_game_manifest(bad, &cfg).is_err(),
                "must reject {bad}"
            );
        }
    }

    #[test]
    fn places_file_versioning_and_lru_cap() {
        let dir = std::env::temp_dir().join(format!("os-preview-places-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("places.json");

        let mut pf = PlacesFile {
            slide_theme: "sepia".into(),
            notes_size: 30,
            ..Default::default()
        };
        pf.merge("/a.md", serde_json::json!({ "scroll": 400 }));
        pf.merge("/a.md", serde_json::json!({ "slides": true }));
        save_places_file_atomic(&path, &pf).unwrap();

        let PlacesLoadOutcome::Loaded(loaded) = load_places_file(&path) else {
            panic!("expected loaded");
        };
        assert_eq!(loaded.slide_theme, "sepia");
        assert_eq!(loaded.notes_size, 30);
        assert_eq!(loaded.get("/a.md")["scroll"], 400);
        assert_eq!(loaded.get("/a.md")["slides"], true);

        fs::write(&path, br#"{"version": 99}"#).unwrap();
        assert_eq!(load_places_file(&path), PlacesLoadOutcome::RefusedNewer(99));

        fs::write(&path, br#"{"version": 0}"#).unwrap();
        assert_eq!(load_places_file(&path), PlacesLoadOutcome::ResetOlder(0));

        let _ = fs::remove_dir_all(&dir);
    }
}

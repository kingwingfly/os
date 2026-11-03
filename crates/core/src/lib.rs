pub mod acl;
pub mod ansi;
pub mod archive;
pub mod bin;
pub mod cli;
pub mod completion;
pub mod devices;
pub mod find;
pub mod glob;
pub mod permissions;
pub mod shell;
pub mod text;
pub mod xattr;

use serde::{Deserialize, Serialize};

/// The most bytes one request may upload, as Cloudflare's request bodies allow ...
pub const MAX_UPLOAD: u64 = 100_000_000;
/// ... and the most a file may have, uploaded in chunks.
pub const MAX_FILE: u64 = 1_000_000_000;
/// The size of the chunks a file is uploaded and stored in; the last chunk is shorter.
pub const CHUNK_SIZE: u64 = 8 * 1024 * 1024;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub path: String,
    pub directory: bool,
    pub size: u64,
    pub kind: String,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub mode: u16,
    /// For a file still uploading, the bytes that have arrived so far, as its upload counts them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uploaded: Option<u64>,
    /// Whether it is a recording still being made (`stream`), which grows as it is heard.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub recording: bool,
    /// A symbolic link's target, as written; `directory` then says whether it leads to one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    /// A character device's driver (`present`, `snd`), for one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// When its content last changed, in seconds since 1970, as ls -l shows it.
    #[serde(default)]
    pub mtime: u64,
    /// How many names it has, as ls -l counts them.
    #[serde(default)]
    pub links: u32,
    /// Whether it has an ACL beyond its mode, which ls -l marks with `+`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub acl: bool,
    /// Whether the account it was listed for may not open it: list it, a directory (r and x),
    /// or read it, a file; through a link, what it leads to.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub denied: bool,
}

impl Entry {
    /// Its type and mode as ls -l writes them, then `+` for an ACL, or a space.
    pub fn mode_line(&self) -> String {
        let kind = if self.link.is_some() {
            'l'
        } else if self.directory {
            'd'
        } else if self.device.is_some() {
            'c'
        } else {
            '-'
        };
        format!(
            "{}{}",
            permissions::type_mode_text(self.mode, kind),
            if self.acl { "+" } else { " " }
        )
    }
    /// What follows its name in a listing: where a link points, `/` for a directory, `*` for
    /// what may be executed.
    pub fn suffix(&self) -> String {
        match &self.link {
            Some(target) => format!(" -> {target}"),
            None if self.directory => "/".into(),
            None if self.mode & 0o111 != 0 => "*".into(),
            None => String::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Listing {
    pub path: String,
    pub entries: Vec<Entry>,
}

/// Resolve a virtual path; no path is ever passed to the host filesystem.
pub fn resolve(cwd: &str, input: &str) -> Result<String, String> {
    if input.contains('\\') || input.chars().any(char::is_control) {
        return Err("Paths cannot contain control characters or backslashes".into());
    }
    let joined = if input.starts_with('/') {
        input.to_string()
    } else {
        format!("{cwd}/{input}")
    };
    let mut parts = Vec::new();
    for part in joined.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            ".directory" => return Err("Reserved directory marker name".into()),
            name if name.len() > 240 => return Err("Filename is too long".into()),
            name => parts.push(name),
        }
    }
    if parts.len() > 16 {
        return Err("Directories cannot be nested more than 16 levels".into());
    }
    let path = format!("/{}", parts.join("/"));
    if path.len() > 1024 {
        return Err("Path is too long".into());
    }
    Ok(path)
}

pub fn kind(path: &str) -> &'static str {
    let p = path.to_lowercase();
    if p.ends_with(".slides.md") {
        return "slides";
    }
    // The name's extension, or the whole name without one, e.g. `makefile`.
    let name = p.rsplit('/').next().unwrap_or("");
    match name.rsplit('.').next().unwrap_or("") {
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "avif" | "bmp" | "ico" => "image",
        "pdf" => "pdf",
        "mp4" | "webm" | "mov" | "m4v" | "ogv" => "video",
        "mp3" | "wav" | "ogg" | "oga" | "opus" | "m4a" | "aac" | "flac" | "weba" => "audio",
        "md" | "markdown" => "markdown",
        "zip" | "tar" | "gz" | "tgz" => "archive",
        // Text the previews show as code, highlighted when they know the language, as tables
        // (CSV, TSV), as cards (vCard, iCalendar), or as diffs.
        "txt" | "log" | "tex" | "typ" | "csv" | "tsv" | "diff" | "patch" | "vcf" | "vcard"
        | "ics" | "ical" | "json" | "jsonc" | "json5" | "ipynb" | "webmanifest" | "geojson"
        | "js" | "mjs" | "cjs" | "jsx" | "ts" | "mts" | "cts" | "tsx" | "html" | "htm"
        | "xhtml" | "css" | "scss" | "vue" | "xml" | "svg" | "xsl" | "xslt" | "xsd" | "plist"
        | "rss" | "atom" | "kml" | "gpx" | "yaml" | "yml" | "toml" | "ini" | "cfg" | "conf"
        | "desktop" | "php" | "phtml" | "sql" | "rs" | "c" | "h" | "cpp" | "cc" | "cxx" | "c++"
        | "hpp" | "hh" | "hxx" | "h++" | "ino" | "go" | "zig" | "zon" | "sh" | "bash" | "zsh"
        | "ksh" | "lock" | "pipfile" | "ebuild" | "mk" | "mak" | "makefile" | "gnumakefile"
        | "dockerfile" | "containerfile" | "pkgbuild" | "nix" | "proto" | "lua" | "java" | "kt"
        | "kts" | "scala" | "sc" | "sbt" | "cs" | "csx" | "swift" | "dart" | "py" | "pyw"
        | "pyi" | "rb" | "rake" | "gemspec" | "gemfile" | "rakefile" | "ex" | "exs" | "hs"
        | "ml" | "mli" | "jl" => "text",
        "game" => "game",
        _ => "unknown",
    }
}

/// The type a file is served as: its media type, text for text and for a name with no extension
/// (README), and bytes to download for anything else, which any file may be.
pub fn mime(path: &str) -> &'static str {
    let name = path.rsplit('/').next().unwrap_or("");
    match name.to_lowercase().rsplit('.').next().unwrap_or("") {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "bmp" => "image/bmp",
        "ico" => "image/x-icon",
        // Safe to serve: an image runs no scripts, and a file opened as a page is sandboxed.
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "mp4" | "m4v" => "video/mp4",
        "webm" => "video/webm",
        "mov" => "video/quicktime",
        "ogv" => "video/ogg",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" | "oga" | "opus" => "audio/ogg",
        "m4a" => "audio/mp4",
        "aac" => "audio/aac",
        "weba" => "audio/webm",
        "flac" => "audio/flac",
        "zip" => "application/zip",
        "gz" | "tgz" => "application/gzip",
        "tar" => "application/x-tar",
        _ if !name.contains('.') || matches!(kind(path), "text" | "markdown" | "slides") => {
            "text/plain; charset=utf-8"
        }
        _ => "application/octet-stream",
    }
}

pub fn parent(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) | None => "/",
        Some(n) => &path[..n],
    }
}

/// Whether a backslash escapes `next`, the character after it, within `quote`, as bash reads a
/// line: outside quotes it escapes anything; within double quotes only `$`, `` ` ``, `"`, `\`
/// and a newline, and is itself before anything else; within single quotes nothing.
pub(crate) fn escapes(quote: Option<char>, next: Option<char>) -> bool {
    match quote {
        None => true,
        Some('"') => matches!(next, Some('$' | '`' | '"' | '\\' | '\n')),
        Some(_) => false,
    }
}

pub fn split_command(input: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escaped = false;
    let mut active = false;
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if escaped {
            // A backslash and a newline join two lines.
            if c != '\n' {
                word.push(c);
                active = true;
            }
            escaped = false;
            continue;
        }
        if c == '\\' && escapes(quote, chars.peek().copied()) {
            escaped = true;
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
                words.push(std::mem::take(&mut word));
                active = false;
            }
        } else {
            word.push(c);
            active = true;
        }
    }
    if quote.is_some() || escaped {
        return Err("Unterminated quote or escape".into());
    }
    if active {
        words.push(word);
    }
    Ok(words)
}

/// A single HTTP byte range, inclusive. Malformed and unsatisfiable ranges return None.
pub fn byte_range(value: &str, size: u64) -> Option<(u64, u64)> {
    if size == 0 {
        return None;
    }
    let raw = value.strip_prefix("bytes=")?;
    if raw.contains(',') {
        return None;
    }
    let (a, b) = raw.split_once('-')?;
    if a.is_empty() {
        let n: u64 = b.parse().ok()?;
        return (n > 0).then_some((size.saturating_sub(n), size - 1));
    }
    let start: u64 = a.parse().ok()?;
    let end = if b.is_empty() {
        size - 1
    } else {
        b.parse::<u64>().ok()?.min(size - 1)
    };
    (start < size && start <= end).then_some((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn listings_write_each_type_as_ls_does() {
        let entry = |directory, link: Option<&str>, device: Option<&str>, mode| Entry {
            directory,
            link: link.map(String::from),
            device: device.map(String::from),
            mode,
            ..Entry::default()
        };
        assert_eq!(entry(true, None, None, 0o755).mode_line(), "drwxr-xr-x ");
        assert_eq!(
            entry(false, Some("/a"), None, 0o777).mode_line(),
            "lrwxrwxrwx "
        );
        assert_eq!(
            entry(false, None, Some("snd"), 0o644).mode_line(),
            "crw-r--r-- "
        );
        assert_eq!(entry(false, None, None, 0o640).mode_line(), "-rw-r----- ");
    }
    #[test]
    fn paths_stay_virtual_and_preserve_unicode() {
        assert_eq!(
            resolve("/media/music", "../../../../../hekou.md").unwrap(),
            "/hekou.md"
        );
        assert_eq!(
            resolve("/media", "./Name with spaces.mp4").unwrap(),
            "/media/Name with spaces.mp4"
        );
        assert!(resolve("/", ".directory").is_err());
        assert!(resolve("/", "bad\0name").is_err());
    }
    #[test]
    fn previewable_files_have_kinds() {
        assert_eq!(kind("/a/deck.slides.md"), "slides");
        for path in [
            "/x.vcf",
            "/x.ics",
            "/x.diff",
            "/x.tsv",
            "/main.kt",
            "/Makefile",
            "/a.svg",
        ] {
            assert_eq!(kind(path), "text", "{path}");
        }
        for path in ["/a.zip", "/a.tar", "/a.tar.gz", "/a.tgz"] {
            assert_eq!(kind(path), "archive", "{path}");
        }
        assert_eq!(mime("/a.tar.gz"), "application/gzip");
        assert_eq!(mime("/logo.SVG"), "image/svg+xml");
        assert_eq!(kind("/report.docx"), "unknown");
        // Any file uploads; what is not text or media downloads, as bytes.
        assert_eq!(kind("/song.aac"), "audio");
        assert_eq!(mime("/song.aac"), "audio/aac");
        assert_eq!(mime("/voice.opus"), "audio/ogg");
        assert_eq!(mime("/report.docx"), "application/octet-stream");
        assert_eq!(mime("/notes/README"), "text/plain; charset=utf-8");
        assert_eq!(mime("/src/main.rs"), "text/plain; charset=utf-8");
        assert_eq!(mime("/v1.2/Makefile"), "text/plain; charset=utf-8");
    }
    #[test]
    fn quoted_paths_are_one_argument() {
        assert_eq!(split_command("open 'a b.md'").unwrap(), ["open", "a b.md"]);
        assert_eq!(split_command("mkdir a\\ b").unwrap(), ["mkdir", "a b"]);
        assert!(split_command("open 'a").is_err());
    }
    #[test]
    fn backslashes_read_as_bash_reads_them() {
        for (line, word) in [
            // Within double quotes, a backslash escapes only $ ` " \ and a newline.
            (r#""a\b""#, r"a\b"),
            (r#""\d+""#, r"\d+"),
            (r#""\$x\`\"\\""#, r#"$x`"\"#),
            (r#""\*""#, r"\*"),
            // Outside quotes it escapes anything; within single quotes nothing.
            (r"a\ b\\c", r"a b\c"),
            (r"'a\b\'", r"a\b\"),
            // A backslash and a newline join lines, in double quotes too.
            ("a\\\nb", "ab"),
            ("\"a\\\nb\"", "ab"),
        ] {
            assert_eq!(split_command(line).unwrap(), [word], "{line}");
        }
        assert!(split_command(r#""a\"#).is_err());
        assert!(split_command("a\\").is_err());
    }
    #[test]
    fn rm_requires_an_explicit_path_and_known_options() {
        let parse = |command: &str| {
            cli::parse::<cli::files::Rm>(&split_command(command).unwrap())
                .map(|r| (r.paths, r.recursive, r.force))
        };
        assert_eq!(
            parse("-r 'Directory with spaces'"),
            Ok((vec!["Directory with spaces".into()], true, false))
        );
        assert_eq!(parse("-- -r"), Ok((vec!["-r".into()], false, false)));
        assert_eq!(
            parse("-Rf a 'b c'"),
            Ok((vec!["a".into(), "b c".into()], true, true))
        );
        for command in ["", "-r", "--", "-rx a", "--all a"] {
            assert!(parse(command).is_err(), "{command}");
        }
    }
    #[test]
    fn media_ranges_handle_suffixes_and_eof() {
        assert_eq!(byte_range("bytes=2-4", 10), Some((2, 4)));
        assert_eq!(byte_range("bytes=-20", 10), Some((0, 9)));
        assert_eq!(byte_range("bytes=8-", 10), Some((8, 9)));
        assert_eq!(byte_range("bytes=8-99", 10), Some((8, 9)));
        for s in ["bytes=10-", "bytes=-0", "bytes=4-2", "bytes=0-1,3-4"] {
            assert_eq!(byte_range(s, 10), None);
        }
    }
}

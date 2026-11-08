//! zip and tar archives, read and written on the container's disk. Output is deterministic:
//! the same inputs, times and options give the same bytes, so that an interrupted archive can
//! be rebuilt and checked against the chunks already stored.

pub mod faststart;

use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Seek, Write};
use std::path::Path;

use flate2::{Compression, GzBuilder, read::MultiGzDecoder};
use os_core::archive::{ENTRIES_MAX, EXPANDED_MAX, Format};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The job container's version, recorded with each archive built, since another version may build
/// different bytes.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// The deflate level, fixed for the same reason.
const LEVEL: u32 = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    File,
    Directory,
    /// A symbolic link, to `link`.
    Symlink,
    /// Another name for the earlier member `link`.
    Hardlink,
    /// A device, FIFO or anything else.
    Other,
}

/// A member of an archive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub name: String,
    pub size: u64,
    /// Its permission bits, if the archive keeps them, 0 included: a zip made on a system without
    /// them has none.
    pub mode: Option<u32>,
    pub kind: Kind,
    /// A link's target: a symbolic link's, as written, or the member a hard link names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
}

/// A member of an archive to build: a file's content on disk, or a directory.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Input {
    pub name: String,
    /// The file holding its content; none for a directory.
    #[serde(default)]
    pub file: Option<String>,
    pub mode: u32,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub uid: u64,
    #[serde(default)]
    pub gid: u64,
    /// Whether to store it as it is, as for content already compressed.
    #[serde(default)]
    pub store: bool,
    /// A symbolic link's target: it is a link, with no content.
    #[serde(default)]
    pub symlink: Option<String>,
    /// The earlier member it is another name of, in a tar.
    #[serde(default)]
    pub hardlink: Option<String>,
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// What `path` is: zip, gzipped tar or tar, from its first bytes.
pub fn detect(path: &Path) -> Result<Format, String> {
    let mut head = [0u8; 262];
    let n = File::open(path)
        .map_err(err)?
        .read(&mut head)
        .map_err(err)?;
    Ok(match &head[..n] {
        [b'P', b'K', 3, 4, ..] | [b'P', b'K', 5, 6, ..] => Format::Zip,
        [0x1F, 0x8B, ..] => Format::Tgz,
        _ => Format::Tar,
    })
}

/// Counts what has been written so far, to refuse archives that expand too far.
struct Budget {
    entries: usize,
    bytes: u64,
}
impl Budget {
    fn entry(&mut self) -> Result<(), String> {
        self.entries += 1;
        if self.entries > ENTRIES_MAX {
            return Err(format!("the archive has more than {ENTRIES_MAX} members"));
        }
        Ok(())
    }
    /// Copy `reader` to `out`, within the bytes left.
    fn copy(&mut self, reader: impl Read, out: &Path) -> Result<u64, String> {
        let left = EXPANDED_MAX - self.bytes;
        let mut writer = BufWriter::new(File::create(out).map_err(err)?);
        let copied = io::copy(&mut reader.take(left + 1), &mut writer).map_err(err)?;
        writer.flush().map_err(err)?;
        if copied > left {
            return Err(format!(
                "the archive expands to more than {} MB",
                EXPANDED_MAX / 1_000_000
            ));
        }
        self.bytes += copied;
        Ok(copied)
    }
}

/// The members of the archive at `path`, and, given `unpack`, each file member's content
/// written there as a file named by its index. Sizes are those actually read, not those an
/// archive claims.
pub fn list(path: &Path, unpack: Option<&Path>) -> Result<(Format, Vec<Member>), String> {
    let format = detect(path)?;
    let mut budget = Budget {
        entries: 0,
        bytes: 0,
    };
    let mut members = Vec::new();
    if let Some(dir) = unpack {
        fs::create_dir_all(dir).map_err(err)?;
    }
    match format {
        Format::Zip => {
            let mut archive = zip::ZipArchive::new(BufReader::new(File::open(path).map_err(err)?))
                .map_err(|e| format!("not a readable zip archive: {e}"))?;
            for index in 0..archive.len() {
                budget.entry()?;
                let mut file = archive.by_index(index).map_err(err)?;
                let name = file.name().map_err(err)?.into_owned();
                let mode = file.unix_mode().map(|mode| mode & 0o7777);
                let kind = if file.is_dir() {
                    Kind::Directory
                } else if file.is_symlink() {
                    Kind::Symlink
                } else {
                    Kind::File
                };
                let mut size = file.size();
                let mut link = None;
                if kind == Kind::Symlink {
                    // Its content is its target.
                    let mut target = String::new();
                    (&mut file)
                        .take(4096)
                        .read_to_string(&mut target)
                        .map_err(err)?;
                    link = Some(target);
                } else if kind == Kind::File
                    && let Some(dir) = unpack
                {
                    size = budget.copy(&mut file, &dir.join(index.to_string()))?;
                }
                members.push(Member {
                    name,
                    size,
                    mode,
                    kind,
                    link,
                });
            }
        }
        Format::Tar | Format::Tgz => {
            let file = BufReader::new(File::open(path).map_err(err)?);
            let reader: Box<dyn Read> = if format == Format::Tgz {
                Box::new(MultiGzDecoder::new(file))
            } else {
                Box::new(file)
            };
            let mut archive = tar::Archive::new(reader);
            let entries = archive
                .entries()
                .map_err(|e| format!("not a readable tar archive: {e}"))?;
            for (index, entry) in entries.enumerate() {
                budget.entry()?;
                let mut entry = entry.map_err(|e| format!("not a readable tar archive: {e}"))?;
                let name = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
                let header = entry.header();
                let mode = header.mode().ok().map(|mode| mode & 0o7777);
                let kind = match header.entry_type() {
                    tar::EntryType::Regular | tar::EntryType::Continuous => Kind::File,
                    tar::EntryType::Directory => Kind::Directory,
                    tar::EntryType::Symlink => Kind::Symlink,
                    tar::EntryType::Link => Kind::Hardlink,
                    _ => Kind::Other,
                };
                let link = entry
                    .link_name_bytes()
                    .map(|target| String::from_utf8_lossy(&target).into_owned())
                    .filter(|_| matches!(kind, Kind::Symlink | Kind::Hardlink));
                let mut size = header.size().unwrap_or(0);
                if kind == Kind::File
                    && let Some(dir) = unpack
                {
                    size = budget.copy(&mut entry, &dir.join(index.to_string()))?;
                }
                members.push(Member {
                    name,
                    size,
                    mode,
                    kind,
                    link,
                });
            }
        }
    }
    Ok((format, members))
}

/// The date of `days` after 1970-01-01, as (year, month, day).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}
/// `seconds` since 1970 as zip's DOS time, which counts from 1980.
fn dos_time(seconds: u64) -> zip::DateTime {
    let (year, month, day) = civil((seconds / 86_400) as i64);
    let time = seconds % 86_400;
    zip::DateTime::from_date_and_time(
        year.clamp(1980, 2107) as u16,
        month as u8,
        day as u8,
        (time / 3600) as u8,
        (time / 60 % 60) as u8,
        (time % 60) as u8,
    )
    .unwrap_or_default()
}

/// Build an archive of `inputs`, read from the directory `files`, at `out`; every member is
/// dated `mtime`. Returns its size.
pub fn build(
    format: Format,
    mtime: u64,
    inputs: &[Input],
    files: &Path,
    out: &Path,
) -> Result<u64, String> {
    let writer = BufWriter::new(File::create(out).map_err(err)?);
    let open = |input: &Input| -> Result<File, String> {
        let name = input
            .file
            .as_deref()
            .ok_or("a file member has no content")?;
        File::open(files.join(name)).map_err(|e| format!("{}: {e}", input.name))
    };
    match format {
        Format::Zip => {
            let mut zip = zip::ZipWriter::new(writer);
            for input in inputs {
                let options = zip::write::SimpleFileOptions::default()
                    .last_modified_time(dos_time(mtime))
                    .unix_permissions(input.mode & 0o777);
                if let Some(target) = &input.symlink {
                    zip.add_symlink(input.name.as_str(), target.as_str(), options)
                        .map_err(err)?;
                    continue;
                }
                if input.file.is_none() {
                    zip.add_directory(input.name.trim_end_matches('/'), options)
                        .map_err(err)?;
                    continue;
                }
                let options = if input.store {
                    options.compression_method(zip::CompressionMethod::Stored)
                } else {
                    options
                        .compression_method(zip::CompressionMethod::Deflated)
                        .compression_level(Some(i64::from(LEVEL)))
                };
                zip.start_file(input.name.as_str(), options).map_err(err)?;
                io::copy(&mut BufReader::new(open(input)?), &mut zip).map_err(err)?;
            }
            let mut file = zip.finish().map_err(err)?;
            file.flush().map_err(err)?;
            let file = file.into_inner().map_err(|e| err(e.error()))?;
            size_of(file)
        }
        Format::Tar | Format::Tgz => {
            let writer: Box<dyn Write> = if format == Format::Tgz {
                Box::new(
                    GzBuilder::new()
                        .mtime(mtime as u32)
                        .operating_system(255)
                        .write(writer, Compression::new(LEVEL)),
                )
            } else {
                Box::new(writer)
            };
            let mut tar = tar::Builder::new(writer);
            tar.mode(tar::HeaderMode::Complete);
            for input in inputs {
                let mut header = tar::Header::new_gnu();
                header.set_mode(input.mode & 0o777);
                header.set_mtime(mtime);
                header.set_uid(input.uid);
                header.set_gid(input.gid);
                header.set_username(&input.owner).map_err(err)?;
                header.set_groupname(&input.group).map_err(err)?;
                if let Some((kind, target)) = input
                    .symlink
                    .as_ref()
                    .map(|t| (tar::EntryType::Symlink, t))
                    .or(input.hardlink.as_ref().map(|t| (tar::EntryType::Link, t)))
                {
                    header.set_entry_type(kind);
                    header.set_size(0);
                    tar.append_link(&mut header, &input.name, target)
                        .map_err(err)?;
                } else if input.file.is_none() {
                    header.set_entry_type(tar::EntryType::Directory);
                    header.set_size(0);
                    let name = format!("{}/", input.name.trim_end_matches('/'));
                    tar.append_data(&mut header, name, io::empty())
                        .map_err(err)?;
                } else {
                    let file = open(input)?;
                    header.set_entry_type(tar::EntryType::Regular);
                    header.set_size(file.metadata().map_err(err)?.len());
                    tar.append_data(&mut header, &input.name, BufReader::new(file))
                        .map_err(err)?;
                }
            }
            let mut writer = tar.into_inner().map_err(err)?;
            writer.flush().map_err(err)?;
            drop(writer);
            size_of(File::open(out).map_err(err)?)
        }
    }
}
fn size_of(mut file: File) -> Result<u64, String> {
    file.seek(io::SeekFrom::End(0)).map_err(err)
}

/// The SHA-256, in hexadecimal, of each `chunk_size` bytes of the file at `path`.
pub fn chunk_hashes(path: &Path, chunk_size: u64) -> Result<Vec<String>, String> {
    let mut file = BufReader::new(File::open(path).map_err(err)?);
    let mut hashes = Vec::new();
    let mut buffer = vec![0u8; 1 << 16];
    loop {
        let mut hasher = Sha256::new();
        let mut read = 0u64;
        while read < chunk_size {
            let want = buffer.len().min((chunk_size - read) as usize);
            let n = file.read(&mut buffer[..want]).map_err(err)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
            read += n as u64;
        }
        if read == 0 {
            break;
        }
        hashes.push(
            hasher
                .finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        );
        if read < chunk_size {
            break;
        }
    }
    Ok(hashes)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scratch(std::path::PathBuf);
    impl Scratch {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("jobs-test-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(dir.join("in")).unwrap();
            Scratch(dir)
        }
        fn path(&self, name: &str) -> std::path::PathBuf {
            self.0.join(name)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn inputs(s: &Scratch) -> Vec<Input> {
        fs::write(s.path("in/0"), "alpha\n".repeat(1000)).unwrap();
        fs::write(s.path("in/1"), [0u8, 159, 146, 150]).unwrap();
        let file = |name: &str, file: &str, mode, store| Input {
            name: name.into(),
            file: Some(file.into()),
            mode,
            owner: "alice".into(),
            group: "team".into(),
            uid: 1000,
            gid: 1000,
            store,
            symlink: None,
            hardlink: None,
        };
        vec![
            Input {
                name: "docs".into(),
                file: None,
                mode: 0o750,
                owner: "alice".into(),
                group: "team".into(),
                uid: 1000,
                gid: 1000,
                store: false,
                symlink: None,
                hardlink: None,
            },
            file("docs/spéctrum notes.md", "0", 0o644, false),
            file("docs/run.sh", "1", 0o755, true),
            file(
                &format!("docs/{}.txt", "long-name-".repeat(15)),
                "0",
                0o600,
                false,
            ),
        ]
    }

    #[test]
    fn archives_round_trip_with_names_modes_and_content() {
        for format in [Format::Zip, Format::Tar, Format::Tgz] {
            let s = Scratch::new(&format!("{format:?}"));
            let inputs = inputs(&s);
            let out = s.path("out");
            let size = build(format, 1_761_400_000, &inputs, &s.path("in"), &out).unwrap();
            assert_eq!(size, fs::metadata(&out).unwrap().len());
            let (detected, members) = list(&out, Some(&s.path("unpacked"))).unwrap();
            assert_eq!(detected, format);
            let names: Vec<_> = members
                .iter()
                .map(|m| m.name.trim_end_matches('/'))
                .collect();
            assert_eq!(
                names,
                inputs.iter().map(|i| i.name.as_str()).collect::<Vec<_>>()
            );
            assert_eq!(members[0].kind, Kind::Directory);
            assert_eq!(
                (members[2].mode.map(|m| m & 0o777), members[2].kind),
                (Some(0o755), Kind::File)
            );
            assert_eq!(members[1].size, 6000);
            assert_eq!(
                fs::read(s.path("unpacked/1")).unwrap(),
                fs::read(s.path("in/0")).unwrap()
            );
            assert_eq!(
                fs::read(s.path("unpacked/2")).unwrap(),
                [0u8, 159, 146, 150]
            );
        }
    }

    #[test]
    fn a_mode_of_000_is_a_mode() {
        for format in [Format::Zip, Format::Tar] {
            let s = Scratch::new(&format!("private-{format:?}"));
            fs::write(s.path("in/0"), "new").unwrap();
            let private = Input {
                name: "private.txt".into(),
                file: Some("0".into()),
                mode: 0,
                owner: "alice".into(),
                group: "team".into(),
                uid: 1000,
                gid: 1000,
                store: false,
                symlink: None,
                hardlink: None,
            };
            build(
                format,
                1_761_400_000,
                &[private],
                &s.path("in"),
                &s.path("out"),
            )
            .unwrap();
            let (_, members) = list(&s.path("out"), None).unwrap();
            assert_eq!(members[0].mode.map(|m| m & 0o777), Some(0));
        }
    }

    #[test]
    fn links_are_kept_as_links() {
        for format in [Format::Tar, Format::Zip] {
            let s = Scratch::new(&format!("links-{format:?}"));
            fs::write(s.path("in/0"), "data").unwrap();
            let member = |name: &str,
                          file: Option<&str>,
                          symlink: Option<&str>,
                          hardlink: Option<&str>| Input {
                name: name.into(),
                file: file.map(String::from),
                mode: if symlink.is_some() { 0o777 } else { 0o644 },
                owner: "alice".into(),
                group: "team".into(),
                uid: 1000,
                gid: 1000,
                store: false,
                symlink: symlink.map(String::from),
                hardlink: hardlink.map(String::from),
            };
            let mut inputs = vec![
                member("a.txt", Some("0"), None, None),
                member("to-a", None, Some("a.txt"), None),
            ];
            if format == Format::Tar {
                inputs.push(member("a-too.txt", None, None, Some("a.txt")));
            }
            build(
                format,
                1_761_400_000,
                &inputs,
                &s.path("in"),
                &s.path("out"),
            )
            .unwrap();
            let (_, members) = list(&s.path("out"), None).unwrap();
            assert_eq!(
                (members[1].kind, members[1].link.as_deref()),
                (Kind::Symlink, Some("a.txt"))
            );
            if format == Format::Tar {
                assert_eq!(
                    (members[2].kind, members[2].link.as_deref()),
                    (Kind::Hardlink, Some("a.txt"))
                );
            }
        }
    }

    #[test]
    fn building_twice_gives_the_same_bytes() {
        for format in [Format::Zip, Format::Tgz] {
            let s = Scratch::new(&format!("same-{format:?}"));
            let inputs = inputs(&s);
            build(format, 1_761_400_000, &inputs, &s.path("in"), &s.path("a")).unwrap();
            build(format, 1_761_400_000, &inputs, &s.path("in"), &s.path("b")).unwrap();
            assert_eq!(
                fs::read(s.path("a")).unwrap(),
                fs::read(s.path("b")).unwrap()
            );
            assert_eq!(
                chunk_hashes(&s.path("a"), 1000).unwrap(),
                chunk_hashes(&s.path("b"), 1000).unwrap()
            );
            // zip times count in steps of two seconds.
            build(format, 1_761_400_060, &inputs, &s.path("in"), &s.path("c")).unwrap();
            assert_ne!(
                fs::read(s.path("a")).unwrap(),
                fs::read(s.path("c")).unwrap()
            );
        }
    }

    #[test]
    fn hostile_archives_are_listed_for_what_they_are() {
        let s = Scratch::new("hostile");
        let out = s.path("evil.tar");
        let mut tar = tar::Builder::new(File::create(&out).unwrap());
        let mut header = tar::Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        // Bypass the tar crate's own checks, as a hostile tool would.
        header.as_gnu_mut().unwrap().name[..11].copy_from_slice(b"../evil.txt");
        header.set_cksum();
        tar.append(&header, &b"evil"[..]).unwrap();
        let mut link = tar::Header::new_gnu();
        link.set_entry_type(tar::EntryType::Symlink);
        link.set_size(0);
        tar.append_link(&mut link, "passwd", "/etc/passwd").unwrap();
        tar.finish().unwrap();
        drop(tar);
        let (_, members) = list(&out, None).unwrap();
        assert_eq!(members[0].name, "../evil.txt");
        assert_eq!(members[1].kind, Kind::Symlink);
        assert!(os_core::archive::member_path("/x", &members[0].name).is_err());
        fs::write(s.path("junk"), b"not an archive at all").unwrap();
        assert!(list(&s.path("junk"), None).is_err());
    }

    #[test]
    fn dates_and_hashes() {
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(20_386), (2025, 10, 25));
        assert_eq!(dos_time(1_761_400_000).year(), 2025);
        let s = Scratch::new("hashes");
        fs::write(s.path("f"), vec![7u8; 2500]).unwrap();
        let hashes = chunk_hashes(&s.path("f"), 1000).unwrap();
        assert_eq!(hashes.len(), 3);
        fs::write(s.path("empty"), b"").unwrap();
        assert!(chunk_hashes(&s.path("empty"), 1000).unwrap().is_empty());
    }
}

//! zip, unzip and tar: what each is asked to do, and where an archive's members may go. The
//! archives themselves are read and written in a container (crates/jobs).
use serde::{Deserialize, Serialize};

use crate::cli;

use crate::resolve;

/// The most members an archive may have, ...
pub const ENTRIES_MAX: usize = 10_000;
/// ... and the most bytes they may expand to, together.
pub const EXPANDED_MAX: u64 = 1_000_000_000;

pub use abi::accelerator::{Existing, Format};

/// One zip, unzip, tar or faststart command.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "job", rename_all = "lowercase")]
pub enum Job {
    /// Write `paths` into the new archive `archive`; relative ones are found in `directory`, if
    /// given (tar -C), and stored relative to it.
    Create {
        format: Format,
        archive: String,
        paths: Vec<String>,
        recursive: bool,
        verbose: bool,
        #[serde(default)]
        directory: Option<String>,
        /// Store symbolic and hard links as links, as tar does unless -h, and zip with -y;
        /// otherwise what they lead to.
        #[serde(default)]
        links: bool,
    },
    /// Write the members of `archive`, or those named in `members`, into `directory`.
    Extract {
        /// Zip for unzip; for tar, whatever the archive is, tar or gzipped tar.
        zip: bool,
        archive: String,
        directory: Option<String>,
        existing: Existing,
        members: Vec<String>,
        verbose: bool,
    },
    /// List the members of `archive`.
    List {
        zip: bool,
        archive: String,
        verbose: bool,
    },
    /// Replace the MP4 or QuickTime file `file` with itself made faststart: its index before
    /// its media.
    Faststart { file: String },
}

/// `faststart [--] FILE`
pub fn faststart_args(args: &[String]) -> Result<Job, String> {
    let faststart = cli::parse::<cli::archives::Faststart>(args)?;
    Ok(Job::Faststart {
        file: faststart.file,
    })
}

/// zip's arguments: `zip [-r] [-y] [-q] [--] ARCHIVE PATH...`. As Info-ZIP does, a name without
/// an extension gets .zip.
pub fn zip_args(args: &[String]) -> Result<Job, String> {
    let zip = cli::parse::<cli::archives::Zip>(args)?;
    let mut archive = zip.archive;
    if !archive.rsplit('/').next().unwrap_or_default().contains('.') {
        archive.push_str(".zip");
    }
    Ok(Job::Create {
        format: Format::Zip,
        archive,
        paths: zip.paths,
        recursive: zip.recursive,
        verbose: !zip.quiet,
        directory: None,
        links: zip.links,
    })
}

/// unzip's arguments: `unzip [-l] [-o|-n] [-q] [-d DIR] [--] ARCHIVE [MEMBER...]`.
pub fn unzip_args(args: &[String]) -> Result<Job, String> {
    let unzip = cli::parse::<cli::archives::Unzip>(args)?;
    Ok(if unzip.list {
        Job::List {
            zip: true,
            archive: unzip.archive,
            verbose: true,
        }
    } else {
        Job::Extract {
            zip: true,
            archive: unzip.archive,
            directory: unzip.directory,
            existing: if unzip.overwrite {
                Existing::Replace
            } else if unzip.never {
                Existing::Skip
            } else {
                Existing::Ask
            },
            members: unzip.members,
            verbose: !unzip.quiet,
        }
    })
}

/// tar's arguments, as GNU tar takes them: bundled (`-czf a.tgz`), long (`--file=a.tgz`), or old
/// style (`czf a.tgz`), whose options' values follow it in order (`cfC a.tar dir`).
pub fn tar_args(args: &[String]) -> Result<Job, String> {
    let mut spelled = Vec::new();
    let mut rest = args.iter();
    if let Some(first) = args
        .first()
        .filter(|a| !a.starts_with('-') && !a.is_empty())
    {
        rest.next();
        for letter in first.chars() {
            spelled.push(format!("-{letter}"));
            if matches!(letter, 'f' | 'C') {
                spelled.push(
                    rest.next()
                        .cloned()
                        .ok_or(format!("tar: -{letter} needs a value"))?,
                );
            }
        }
    }
    spelled.extend(rest.cloned());
    let tar = cli::parse::<cli::archives::Tar>(&spelled)?;
    let archive = tar.file.ok_or_else(|| {
        "tar: name the archive with -f; this terminal has no tape drive".to_string()
    })?;
    if tar.create {
        if tar.paths.is_empty() {
            return Err("tar: refusing to create an empty archive; name what to put in it".into());
        }
        // -C is where the paths are found, and what their names are relative to, as GNU tar
        // works in it.
        return Ok(Job::Create {
            format: tar_format(&archive, tar.gzip),
            archive,
            paths: tar.paths,
            recursive: true,
            verbose: tar.verbose,
            directory: tar.directory,
            links: !tar.dereference,
        });
    }
    if tar.extract {
        return Ok(Job::Extract {
            zip: false,
            archive,
            directory: tar.directory,
            existing: if tar.keep_old_files {
                Existing::Keep
            } else if tar.skip_old_files {
                Existing::Skip
            } else {
                Existing::Replace
            },
            members: tar.paths,
            verbose: tar.verbose,
        });
    }
    Ok(Job::List {
        zip: false,
        archive,
        verbose: tar.verbose,
    })
}

/// The format a new archive named `name` gets: gzipped tar for .tgz and .tar.gz names.
fn tar_format(name: &str, gzip: bool) -> Format {
    let lower = name.to_lowercase();
    if gzip || lower.ends_with(".tgz") || lower.ends_with(".tar.gz") {
        Format::Tgz
    } else {
        Format::Tar
    }
}
/// Where the member `name` of an archive goes in `directory`, or why it is skipped. A leading
/// `/` is removed, as Info-ZIP and GNU tar remove it; the second value says whether one was.
pub fn member_path(directory: &str, name: &str) -> Result<(String, bool), String> {
    if name.chars().any(char::is_control) {
        return Err("its name contains a control character".into());
    }
    if name.contains('\\') {
        return Err("its name contains a backslash".into());
    }
    let relative = name.trim_start_matches('/');
    let stripped = relative.len() != name.len();
    let mut parts = Vec::new();
    for part in relative.split('/') {
        match part {
            "" | "." => {}
            ".." => return Err("its name contains '..'".into()),
            part => parts.push(part),
        }
    }
    if parts.is_empty() {
        return Err("its name is empty".into());
    }
    let path = resolve(directory, &parts.join("/"))?;
    // Without '..', the path stays inside; check anyway.
    if !path.starts_with(&format!("{}/", directory.trim_end_matches('/'))) && directory != "/" {
        return Err("it would be written outside the directory".into());
    }
    Ok((path, stripped))
}

/// The name an archive stores for the input typed as `typed`: without a leading `/` or `./`,
/// and without anything up to its last `..`, as GNU tar removes it, so that no name the archive
/// stores climbs out of where it is extracted.
pub fn stored_name(typed: &str) -> String {
    let parts: Vec<&str> = typed
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    let after = parts.iter().rposition(|p| *p == "..").map_or(0, |i| i + 1);
    parts[after..].join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(line: &str) -> Vec<String> {
        crate::split_command(line).unwrap()
    }

    #[test]
    fn faststart_takes_one_file() {
        assert_eq!(
            faststart_args(&args("clip.mp4")).unwrap(),
            Job::Faststart {
                file: "clip.mp4".into()
            }
        );
        assert_eq!(
            faststart_args(&args("-- -odd.mp4")).unwrap(),
            Job::Faststart {
                file: "-odd.mp4".into()
            }
        );
        for bad in ["", "a.mp4 b.mp4", "-v a.mp4"] {
            assert!(faststart_args(&args(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn zip_and_unzip_arguments() {
        assert_eq!(
            zip_args(&args("-rq notes docs 'a b.md'")).unwrap(),
            Job::Create {
                format: Format::Zip,
                archive: "notes.zip".into(),
                paths: vec!["docs".into(), "a b.md".into()],
                recursive: true,
                verbose: false,
                directory: None,
                links: false,
            }
        );
        assert!(matches!(
            zip_args(&args("-ry site site")).unwrap(),
            Job::Create { links: true, .. }
        ));
        assert!(matches!(
            tar_args(&args("-chf a.tar docs")).unwrap(),
            Job::Create { links: false, .. }
        ));
        assert!(zip_args(&args("only.zip")).is_err());
        assert!(zip_args(&args("-x a.zip b")).is_err());
        assert_eq!(
            unzip_args(&args("-o -d out a.zip one.txt")).unwrap(),
            Job::Extract {
                zip: true,
                archive: "a.zip".into(),
                directory: Some("out".into()),
                existing: Existing::Replace,
                members: vec!["one.txt".into()],
                verbose: true,
            }
        );
        assert!(matches!(
            unzip_args(&args("-l a.zip")).unwrap(),
            Job::List { zip: true, .. }
        ));
        assert!(matches!(
            unzip_args(&args("-nq a.zip")).unwrap(),
            Job::Extract {
                existing: Existing::Skip,
                verbose: false,
                ..
            }
        ));
        assert!(unzip_args(&args("-d")).is_err());
    }

    #[test]
    fn tar_takes_bundled_old_style_and_long_options() {
        for line in [
            "-czf a.tgz docs",
            "czf a.tgz docs",
            "-c -z -f a.tgz docs",
            "--create --gzip --file=a.tgz docs",
            "-cf a.tar.gz docs",
        ] {
            assert_eq!(
                tar_args(&args(line)).unwrap(),
                Job::Create {
                    format: Format::Tgz,
                    archive: if line.contains("tar.gz") {
                        "a.tar.gz"
                    } else {
                        "a.tgz"
                    }
                    .into(),
                    paths: vec!["docs".into()],
                    recursive: true,
                    verbose: false,
                    directory: None,
                    links: true,
                },
                "{line}"
            );
        }
        assert_eq!(
            tar_args(&args("-xvkf a.tar -C 'out dir' one")).unwrap(),
            Job::Extract {
                zip: false,
                archive: "a.tar".into(),
                directory: Some("out dir".into()),
                existing: Existing::Keep,
                members: vec!["one".into()],
                verbose: true,
            }
        );
        assert!(matches!(
            tar_args(&args("-xf a.tar --skip-old-files")).unwrap(),
            Job::Extract {
                existing: Existing::Skip,
                ..
            }
        ));
        assert!(matches!(
            tar_args(&args("tf a.tar")).unwrap(),
            Job::List { verbose: false, .. }
        ));
        assert_eq!(
            tar_args(&args("-cf a.tar -C src x /abs")).unwrap(),
            Job::Create {
                format: Format::Tar,
                archive: "a.tar".into(),
                paths: vec!["x".into(), "/abs".into()],
                recursive: true,
                verbose: false,
                directory: Some("src".into()),
                links: true,
            }
        );
        for bad in [
            "-cx -f a",
            "-c docs",
            "-cf",
            "-cf a.tar",
            "-q -f a",
            "--nope -f a",
            "docs",
        ] {
            assert!(tar_args(&args(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn members_stay_inside_their_directory() {
        assert_eq!(
            member_path("/home/a/out", "docs/spéctrum.md"),
            Ok(("/home/a/out/docs/spéctrum.md".into(), false))
        );
        assert_eq!(
            member_path("/x", "/etc/passwd"),
            Ok(("/x/etc/passwd".into(), true))
        );
        assert_eq!(member_path("/x", "./a//b/"), Ok(("/x/a/b".into(), false)));
        assert_eq!(member_path("/", "a"), Ok(("/a".into(), false)));
        for bad in [
            "../evil",
            "a/../../b",
            "",
            "/",
            "a\\b",
            "a\nb",
            "a/.directory/b",
        ] {
            assert!(member_path("/x", bad).is_err(), "{bad:?}");
        }
        assert!(member_path("/x", &"d/".repeat(20)).is_err());
        assert_eq!(stored_name("/home/a/docs/"), "home/a/docs");
        assert_eq!(stored_name("../../x/./y"), "x/y");
        assert_eq!(stored_name("./notes.md"), "notes.md");
        assert_eq!(stored_name("docs/../notes.md"), "notes.md");
        assert_eq!(stored_name("a/../../b/c"), "b/c");
    }
}

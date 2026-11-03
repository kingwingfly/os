//! Archives and video: zip, unzip, tar, faststart and jobs.

use clap::{ArgGroup, Parser, ValueHint};

use super::{Manual, Section};

/// make a zip archive
///
/// Writes PATHs into the new archive ARCHIVE (.zip is added to a name without an extension), as
/// a process of its own, from the files as they were when it started. It appears at once and can be read
/// while it is written.
///
/// Names are stored as typed, without a leading / or ../. Links are followed, their files
/// stored, unless -y stores them as links. Files already compressed are stored as they are, the
/// rest deflated. What you cannot read is reported and left out. An archive that exists is not
/// updated: remove it first.
///
/// Ctrl+C cancels and removes the unfinished archive; closing the tab does not (see jobs).
#[derive(Parser, Debug)]
#[command(name = "zip")]
pub struct Zip {
    /// what directories hold too
    #[arg(short = 'r', visible_short_alias = 'R', long = "recurse-paths")]
    pub recursive: bool,
    /// store symbolic links as links
    #[arg(short = 'y', long = "symlinks")]
    pub links: bool,
    /// quietly
    #[arg(short = 'q', long = "quiet", overrides_with = "verbose")]
    pub quiet: bool,
    /// name each member (the default)
    #[arg(short = 'v', long = "verbose", overrides_with = "quiet")]
    pub verbose: bool,
    #[arg(value_hint = ValueHint::AnyPath, value_name = "ARCHIVE")]
    pub archive: String,
    #[arg(value_hint = ValueHint::AnyPath, required = true, value_name = "PATH")]
    pub paths: Vec<String>,
}
impl Manual for Zip {
    const SECTION: Section = Section::Archives;
    const NEEDS: &'static str = "r on what is archived, w and x where the archive goes.";
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("zip -r notes.zip notes", "a tree"),
        ("zip -ry site.zip site", "links kept"),
        ("fd -e md -X zip docs.zip", "what fd found"),
    ];
    const SEE: &'static [&'static str] = &["unzip", "tar", "jobs"];
}

/// extract or list a zip archive
///
/// Extracts the members of ARCHIVE, or the MEMBERs named, into the working directory or DIR,
/// which is made if missing. Files appear one by one; Ctrl+C leaves those already extracted, and
/// -n continues later.
///
/// A file that exists is replaced only if you say so: unzip asks replace? [y]es, [n]o, [A]ll,
/// [N]one. A replaced file is removed and made anew, as Info-ZIP does: yours, with the archived
/// mode; its other names keep the old file.
///
/// New files and directories get the archived permission bits (000 too), or 644 and 755 when the
/// archive keeps none, as zips made elsewhere may. Symbolic links are made last, so nothing is
/// written through one from the same archive. Members with .. in their names, devices and
/// duplicates are skipped with a warning; a leading / is removed. Members named that are not
/// there, and an empty archive, are failures.
#[derive(Parser, Debug)]
#[command(name = "unzip")]
pub struct Unzip {
    /// list the members instead
    #[arg(short = 'l')]
    pub list: bool,
    /// replace without asking
    #[arg(short = 'o', overrides_with = "never")]
    pub overwrite: bool,
    /// never replace
    #[arg(short = 'n', overrides_with = "overwrite")]
    pub never: bool,
    /// quietly
    #[arg(short = 'q')]
    pub quiet: bool,
    /// extract into DIR
    #[arg(value_hint = ValueHint::DirPath, short = 'd', value_name = "DIR")]
    pub directory: Option<String>,
    #[arg(value_hint = ValueHint::AnyPath, value_name = "ARCHIVE")]
    pub archive: String,
    #[arg(value_name = "MEMBER")]
    pub members: Vec<String>,
}
impl Manual for Unzip {
    const SECTION: Section = Section::Archives;
    const NEEDS: &'static str = "r on the archive; w and x where members go.";
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("unzip photos.zip", "here"),
        ("unzip -d restored -o backup.zip", "elsewhere, replacing"),
        ("unzip -l backup.zip | grep report", "search the list"),
    ];
    const SEE: &'static [&'static str] = &["zip", "tar", "jobs"];
}

/// make, extract or list a tar archive
///
/// Creates (-c), extracts (-x) or lists (-t) a tar archive, gzipped with -z or a .tgz or
/// .tar.gz name (gzip is recognized on reading, whatever the name). Options may be bundled (-czf)
/// or written without a dash (czf), as in GNU tar; -f names the archive, -C the directory to work
/// in.
///
/// Creating stores symbolic links as links and a file's second name as a hard link, unless -h
/// stores what links lead to; it replaces an archive that exists. Extracting replaces files that
/// exist, removing them first, as GNU tar does; links are made, symbolic ones last.
///
/// Extracted files and directories get the archived permission bits less the umask (022), or,
/// for root, exactly, setuid, setgid and sticky too. Members with .. and devices are skipped with
/// a warning; a leading / is removed. PATHs not in the archive are failures.
#[derive(Parser, Debug)]
#[command(
    name = "tar",
    override_usage = "tar -c [-z] [-v] [-h] -f ARCHIVE [-C DIR] PATH...\n       tar -x [-z] [-v] [-k|--skip-old-files] -f ARCHIVE [-C DIR] [MEMBER...]\n       tar -t [-z] [-v] -f ARCHIVE",
    group(ArgGroup::new("mode").required(true).args(["create", "extract", "list"]))
)]
pub struct Tar {
    /// create
    #[arg(short = 'c', long = "create")]
    pub create: bool,
    /// extract
    #[arg(short = 'x', long = "extract", visible_alias = "get")]
    pub extract: bool,
    /// list
    #[arg(short = 't', long = "list")]
    pub list: bool,
    /// gzip
    #[arg(short = 'z', long = "gzip", visible_aliases = ["gunzip", "ungzip"])]
    pub gzip: bool,
    /// name each member
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
    /// store what links lead to
    #[arg(short = 'h', long = "dereference")]
    pub dereference: bool,
    /// the archive
    #[arg(value_hint = ValueHint::AnyPath, short = 'f', long = "file", value_name = "ARCHIVE")]
    pub file: Option<String>,
    /// work in DIR
    #[arg(value_hint = ValueHint::DirPath, short = 'C', long = "directory", value_name = "DIR")]
    pub directory: Option<String>,
    /// keep files that exist, reporting each
    #[arg(short = 'k', long = "keep-old-files", overrides_with_all = ["skip_old_files", "overwrite"])]
    pub keep_old_files: bool,
    /// keep them silently
    #[arg(long = "skip-old-files", overrides_with_all = ["keep_old_files", "overwrite"])]
    pub skip_old_files: bool,
    /// replace them (the default)
    #[arg(long = "overwrite", overrides_with_all = ["keep_old_files", "skip_old_files"])]
    pub overwrite: bool,
    #[arg(value_hint = ValueHint::AnyPath, value_name = "PATH")]
    pub paths: Vec<String>,
}
impl Manual for Tar {
    fn check(args: &[String]) -> Result<(), String> {
        crate::archive::tar_args(args).map(drop)
    }
    const SECTION: Section = Section::Archives;
    const NEEDS: &'static str = "r on what is archived and on the archive; w and x where files go.";
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("tar -czf notes.tgz notes", "create, gzipped"),
        ("tar -xvf notes.tgz -C restored", "extract elsewhere"),
        ("tar -tvf notes.tgz", "list with modes and links"),
    ];
    const SEE: &'static [&'static str] = &["zip", "unzip", "jobs"];
}

/// make an MP4 video or audio file play while it downloads
///
/// Moves the index of FILE, an MP4, M4V, MOV or M4A file, before its media, as ffmpeg -c copy
/// -movflags +faststart and qt-faststart do, and replaces FILE with the result. Nothing is
/// re-encoded: the boxes are reordered, and the offsets in the index follow.
///
/// Without that, a player must fetch the end of the file before it starts, and cannot play it at
/// all while it is still uploading. upload warns of such a file; this fixes it where it is.
///
/// It runs apart, in a container, as zip and tar do (see ps). FILE is written in
/// place, as it would be by an editor: it keeps its owner, mode, ACLs and other names, and shows
/// its old content until the new one is whole. A file already faststart is left as it is; one
/// that is not an MP4 or QuickTime file, or a fragmented one, is refused.
#[derive(Parser, Debug)]
#[command(name = "faststart")]
pub struct Faststart {
    #[arg(value_hint = ValueHint::AnyPath, value_name = "FILE")]
    pub file: String,
}
impl Manual for Faststart {
    const SECTION: Section = Section::Archives;
    const NEEDS: &'static str = "r and w on FILE.";
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("faststart holiday.mp4", "make it stream"),
        ("fd -e mp4 -x faststart", "every MP4 below"),
    ];
    const SEE: &'static [&'static str] = &["upload", "jobs"];
}

/// list processes and this browser's unfinished uploads
///
/// Lists your processes (zip, unzip, tar and faststart, as ps does) and the files this browser
/// is writing (uploads and recordings, by their descriptors, fdN), with their state and
/// progress. Processes go on when their tab or the page closes. jobs cancel ID stops one: a
/// process by the first characters of its PID, a descriptor as fdN, which closes it.
#[derive(Parser, Debug)]
#[command(name = "jobs", override_usage = "jobs\n       jobs cancel ID")]
pub struct Jobs {
    #[arg(value_name = "cancel", value_parser = ["cancel"], requires = "id")]
    pub cancel: Option<String>,
    #[arg(value_name = "ID")]
    pub id: Option<String>,
}
impl Manual for Jobs {
    const SECTION: Section = Section::Archives;
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("jobs", "what is running"),
        ("jobs cancel 3fa9", "stop a process"),
        ("jobs cancel fd3", "stop an upload, or a recording"),
    ];
    const SEE: &'static [&'static str] = &["zip", "unzip", "tar", "upload"];
}

/// list the account's processes
///
/// Lists your processes, the zip, unzip, tar and faststart you started, from any tab or device,
/// the latest first: its PID, state and command. They run apart, and go on when their tab or
/// the page closes.
#[derive(Parser, Debug)]
#[command(name = "ps")]
pub struct Ps {}
impl Manual for Ps {
    const SECTION: Section = Section::Archives;
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("ps", "what runs, and what ran"),
        ("ps | grep unzip", "the unzips"),
    ];
    const SEE: &'static [&'static str] = &["kill", "jobs"];
}

/// stop a process
///
/// Signals each process named by its PID (or the start of it, as ps shows it), which stops
/// between steps: what it wrote is kept. Yours, or anyone's as root.
#[derive(Parser, Debug)]
#[command(name = "kill")]
pub struct Kill {
    #[arg(value_name = "PID", required = true)]
    pub pids: Vec<String>,
}
impl Manual for Kill {
    const SECTION: Section = Section::Archives;
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[("kill 3fa9", "stop it")];
    const SEE: &'static [&'static str] = &["ps", "jobs"];
}

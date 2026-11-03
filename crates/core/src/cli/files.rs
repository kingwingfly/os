//! Files: ls, cd, pwd, open, vim, mkdir, touch, rm, mv, cp, ln, readlink, fd and upload.

use clap::{Parser, ValueHint};

use super::{Manual, Section};

/// list a directory, or show one file
///
/// Lists what the directory PATH, or the working directory, holds: directories in green with a
/// slash, executables in amber, links in cyan with where they point. Directories come first,
/// then by name; -t sorts by when content changed, newest first, -S by size, largest first, and
/// -r the other way.
///
/// A file is shown by itself. A link to a directory lists that directory, but with -l or -d the
/// link itself is shown; a trailing slash (ls -l link/) follows it. Times are UTC: the month,
/// day and time for what changed within half a year, the year for older.
#[derive(Parser, Debug)]
#[command(name = "ls")]
pub struct Ls {
    /// long format: type and mode (+ marks an ACL), names (links), owner, group, size, time
    #[arg(short = 'l')]
    pub long: bool,
    /// by when content changed, newest first
    #[arg(short = 't', overrides_with = "size")]
    pub time: bool,
    /// by size, largest first
    #[arg(short = 'S', overrides_with = "time")]
    pub size: bool,
    /// in the other order
    #[arg(short = 'r', long = "reverse")]
    pub reverse: bool,
    /// show a directory itself, not what it holds
    #[arg(short = 'd', long = "directory")]
    pub directory: bool,
    /// accepted for habit: names starting with a dot are always listed
    #[arg(short = 'a', long = "all")]
    pub all: bool,
    #[arg(value_hint = ValueHint::DirPath, value_name = "PATH")]
    pub path: Option<String>,
}
impl Manual for Ls {
    const SECTION: Section = Section::Files;
    const NEEDS: &'static str = "r and x on the directory listed, x on every directory above it.";
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("ls -l docs", "long listing of docs"),
        ("ls -ld ~", "your home itself"),
        ("ls -l link", "the link, and where it points"),
    ];
    const SEE: &'static [&'static str] = &["cd", "fd", "getfacl"];
}

/// change the working directory
///
/// Without DIR, or with ~, goes to your home; .. goes up. A link to a directory can be entered:
/// the path keeps the link's name, as bash does, and .. goes back up through it.
#[derive(Parser, Debug)]
#[command(name = "cd")]
pub struct Cd {
    #[arg(value_hint = ValueHint::DirPath, value_name = "DIR")]
    pub dir: Option<String>,
}
impl Manual for Cd {
    const SECTION: Section = Section::Files;
    const NEEDS: &'static str =
        "x on DIR and every directory above it. Without r you may enter, but not list.";
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("cd /shared", "an absolute path"),
        ("cd ..", "one up"),
        ("cd", "home"),
    ];
    const SEE: &'static [&'static str] = &["pwd", "ls"];
}

/// print the working directory
///
/// Prints the working directory, as cd named it, links included.
#[derive(Parser, Debug)]
#[command(name = "pwd")]
pub struct Pwd {}
impl Manual for Pwd {
    const SECTION: Section = Section::Files;
    const SEE: &'static [&'static str] = &["cd"];
}

/// preview a file
///
/// Shows Markdown, text and code, PDF, images, video, audio, tables, archives' contents,
/// *.slides.md presentations and registered *.game entries. Nothing is executed.
///
/// A file opens where it was left: its slide, PDF page, scroll or playback. A link in it to
/// another file opens that file, with ← to come back. Slides have themes (Light, Dark, Sepia,
/// Night) in their bar.
///
/// In text, code, diffs and Markdown, Ctrl/Cmd+F searches, by regular expression or plain text:
/// Enter and Shift+Enter step through the matches, Esc closes the search.
#[derive(Parser, Debug)]
#[command(name = "open")]
pub struct Open {
    #[arg(value_hint = ValueHint::AnyPath, value_name = "FILE")]
    pub file: String,
}
impl Manual for Open {
    const SECTION: Section = Section::Files;
    const NEEDS: &'static str = "r on FILE, x on every directory above it.";
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("open notes.md", "Markdown, rendered"),
        ("open deck.slides.md", "slides"),
    ];
    const SEE: &'static [&'static str] = &["vim", "cat"];
}

/// present slides or a PDF for others to follow
///
/// Shows FILE, slides (*.slides.md, or Markdown) or a PDF presented a page at a time, and makes
/// /dev/present/NAME, a character device, yours, with FILE's mode and ACL. Whoever may read it
/// follows the presentation with `open /dev/present/NAME`, guests too: each sees the slide shown
/// here as it turns, until they turn elsewhere themselves, which pauses following until they
/// follow again. Whoever may write it turns it too: your own windows and devices, as remotes,
/// and a co-host you let (setfacl -m u:NAME:rw /dev/present/NAME). chmod and setfacl on it say
/// who may do what; cat tells what it shows. Presenting again under the same name takes over
/// your presentation of it. Its followers hear your live sound (stream) with it, and may ask to
/// speak: once you allow them, everyone following hears them too.
///
/// It lasts until present --stop NAME, rm /dev/present/NAME, or 12 hours after its last turn.
/// The bar of the slides or PDF shown has buttons for it too: Present, Go live, and, following,
/// Ask to speak. Guests cannot present: guest is everyone signed out, who could all turn the
/// slides.
#[derive(Parser, Debug)]
#[command(name = "present")]
pub struct Present {
    /// the presentation's name, /dev/present/NAME; by default, FILE's name without its extension
    #[arg(short = 'n', long = "name", value_name = "NAME")]
    pub name: Option<String>,
    /// end the presentation NAME
    #[arg(short = 's', long = "stop", value_name = "NAME", conflicts_with_all = ["name", "file"])]
    pub stop: Option<String>,
    #[arg(value_hint = ValueHint::AnyPath, value_name = "FILE", required_unless_present = "stop")]
    pub file: Option<String>,
}
impl Manual for Present {
    const SECTION: Section = Section::Files;
    const NEEDS: &'static str =
        "r on FILE and an account of your own. Following it needs r on FILE.";
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("present talk.slides.md", "shows it, as /dev/present/talk"),
        (
            "open /dev/present/talk",
            "follows it, from anywhere FILE may be read",
        ),
        ("present --stop talk", "ends it"),
        ("rm /dev/present/talk", "ends it too"),
    ];
    const SEE: &'static [&'static str] = &["open", "stream"];
}

/// send the microphone live, and record it into a file
///
/// Signed in, the sound is live as /dev/snd/NAME, your account's name unless -n names it:
/// whoever may hear it does with open /dev/snd/NAME, guests too, and whoever follows a
/// presentation of yours hears it with the slides (the sound of the presentation's name, if you
/// send one, or else your latest). Ctrl+C, or rm /dev/snd/NAME, stops it. Live sound needs the
/// site's Cloudflare Realtime app.
///
/// With FILE, the sound is also recorded into it, a new file: Opus in WebM (.weba or .webm),
/// which every browser records. FILE grows as you speak, and may be read meanwhile; when stopped,
/// it is complete, and a recording whose page goes away keeps what arrived. Those who may read
/// FILE may read the recording. Without the Realtime app, stream only records.
///
/// /dev/snd/NAME is a character device, yours, made as a file is (the umask): those who may
/// read it may hear the sound. Without FILE, nothing is kept.
///
/// -m gives entries as setfacl -m takes them to FILE and /dev/snd/NAME, as they are made: -m
/// o::- lets no one else hear, -m u:ada:r,o::- only ada.
#[derive(Parser, Debug)]
#[command(name = "stream")]
pub struct Stream {
    /// the live sound's name, /dev/snd/NAME; by default, your account's name
    #[arg(short = 'n', long = "name", value_name = "NAME")]
    pub name: Option<String>,
    /// ACL entries, as setfacl -m takes them, for FILE, or /dev/snd/NAME without it
    #[arg(short = 'm', long = "modify", value_name = "ENTRIES")]
    pub modify: Vec<String>,
    #[arg(value_hint = ValueHint::AnyPath, value_name = "FILE")]
    pub file: Option<String>,
}
impl Manual for Stream {
    const SECTION: Section = Section::Files;
    const NEEDS: &'static str = "a microphone; live, an account of your own; with FILE, w and x on its directory. Hearing it, r on FILE, or on /dev/snd/NAME without FILE.";
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("stream", "live as /dev/snd/USER, your account's name"),
        (
            "stream talk.weba",
            "records into talk.weba, live as /dev/snd/USER",
        ),
        ("stream -n talk", "live as /dev/snd/talk, kept nowhere"),
        ("stream -n talk -m o::-,g:lab:r", "only group lab hears it"),
        ("open /dev/snd/talk", "hears it"),
        ("rm /dev/snd/talk", "stops it"),
    ];
    const SEE: &'static [&'static str] = &["present", "open"];
}

/// edit a text file
///
/// Opens a floating editor with highlighting for Markdown, Rust, Python, JS/TS, JSON, HTML/CSS,
/// C/C++, TOML, YAML and shell. It uses ordinary editing keys, not Vim's modes: Ctrl/Cmd+S
/// saves, Ctrl/Cmd+F finds, Esc asks to close.
///
/// UTF-8 text up to 2 MB. Unsaved changes need an explicit discard. A save that would overwrite
/// another session's change is refused, and your draft kept for download. Use touch first for a
/// new file without an extension.
#[derive(Parser, Debug)]
#[command(name = "vim")]
pub struct Vim {
    #[arg(value_hint = ValueHint::AnyPath, value_name = "FILE")]
    pub file: String,
}
impl Manual for Vim {
    const SECTION: Section = Section::Files;
    const NEEDS: &'static str =
        "r to open; w to save, else the file opens read-only. The kernel checks every save.";
    const EXAMPLES: &'static [(&'static str, &'static str)] =
        &[("vim notes.md", "edit, or create on save")];
    const SEE: &'static [&'static str] = &["open", "touch"];
}

/// make directories
///
/// Makes each DIR, with mode 755 (777 less the umask 022). In a directory with a default ACL,
/// the new one takes that ACL instead; in a setgid directory, it takes the directory's group and
/// the setgid bit.
///
/// Each DIR is made on its own: one that fails is reported, the others are still made. A plain
/// mkdir of a single path also makes missing parents.
#[derive(Parser, Debug)]
#[command(name = "mkdir")]
pub struct Mkdir {
    /// make missing parents; a directory that exists is no error
    #[arg(short = 'p', long = "parents")]
    pub parents: bool,
    #[arg(value_hint = ValueHint::DirPath, required = true, value_name = "DIR")]
    pub dirs: Vec<String>,
}
impl Manual for Mkdir {
    const SECTION: Section = Section::Files;
    const NEEDS: &'static str = "w and x on the directory DIR goes in.";
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("mkdir -p projects/2026/notes", "with its parents"),
        ("mkdir drafts archive", "two at once"),
    ];
    const SEE: &'static [&'static str] = &["rm", "chmod", "setfacl"];
}

/// make empty files, or set their times
///
/// Sets each FILE's access and modification times to now, or makes it, empty, owned by you,
/// with mode 644 (666 less the umask 022), or what the directory's default ACL gives. Through a
/// link, the file it points to is touched, unless -h, which touches the link and makes nothing.
///
/// -d DATE, -t STAMP and -r FILE set another time than now: DATE as `2026-10-29`, `2026-10-29
/// 14:30[:05[.5]]`, with `Z` or `+01:00`, `@SECONDS`, or `now`; STAMP as `[[CC]YY]MMDDhhmm[.ss]`;
/// FILE's own times. Times are UTC unless DATE says otherwise. -a or -m sets only the access or
/// the modification time.
///
/// Now is yours to set if you own the file or may write it; another time, only if you own it.
/// Use -- before a name that starts with a hyphen.
#[derive(Parser, Debug)]
#[command(name = "touch")]
pub struct Touch {
    /// make nothing; only touch those that exist
    #[arg(short = 'c', long = "no-create")]
    pub no_create: bool,
    /// set only the access time
    #[arg(short = 'a')]
    pub access: bool,
    /// set only the modification time
    #[arg(short = 'm')]
    pub modification: bool,
    /// set DATE rather than now
    #[arg(short = 'd', long = "date", value_name = "DATE", conflicts_with_all = ["stamp", "reference"])]
    pub date: Option<String>,
    /// set STAMP rather than now
    #[arg(short = 't', value_name = "STAMP", conflicts_with_all = ["date", "reference"])]
    pub stamp: Option<String>,
    /// set FILE's times rather than now
    #[arg(value_hint = ValueHint::AnyPath, short = 'r', long = "reference", value_name = "FILE", conflicts_with_all = ["date", "stamp"])]
    pub reference: Option<String>,
    /// touch a link itself, not what it leads to
    #[arg(short = 'h', long = "no-dereference")]
    pub no_dereference: bool,
    #[arg(value_hint = ValueHint::AnyPath, required = true, value_name = "FILE")]
    pub files: Vec<String>,
}
impl Manual for Touch {
    const SECTION: Section = Section::Files;
    const NEEDS: &'static str =
        "w and x on the directory a new file goes in; w on a file that exists.";
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("touch notes.md main.rs README", "three files"),
        ("touch -d '2026-01-01 09:00' notes.md", "as of a date"),
        ("touch -r notes.md copy.md", "as another is"),
        ("touch -- -h", "a file named -h"),
    ];
    const SEE: &'static [&'static str] = &["vim", "mkdir", "stat"];
}

/// remove files and directories
///
/// Removes each PATH: a link is removed, not what it points to; a file with other names (hard
/// links) stays under those. -r removes directories with everything in them, checking the whole
/// tree before changing anything. There is no trash.
///
/// Each PATH is removed on its own: one that fails is reported, the others are still removed.
/// The root, the working directory and the directories above it cannot be removed.
#[derive(Parser, Debug)]
#[command(name = "rm")]
pub struct Rm {
    /// remove directories and what they hold
    #[arg(short = 'r', visible_short_alias = 'R', long = "recursive")]
    pub recursive: bool,
    /// say nothing of paths that do not exist
    #[arg(short = 'f', long = "force")]
    pub force: bool,
    #[arg(value_hint = ValueHint::AnyPath, required = true, value_name = "PATH")]
    pub paths: Vec<String>,
}
impl Manual for Rm {
    const SECTION: Section = Section::Files;
    const NEEDS: &'static str = "w and x on the directory PATH is in; its own w does not matter. In a sticky directory (mode +t, as /guest), only PATH's owner, the directory's owner or root may remove it. -r needs r, w and x on every directory emptied.";
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("rm notes.md draft.md", "two files"),
        ("rm -rf old-builds", "a tree"),
        ("fd -e tmp -X rm", "every .tmp file below"),
    ];
    const SEE: &'static [&'static str] = &["mv", "ln"];
}

/// move or rename
///
/// Moves each SOURCE to DEST, or into DEST if it is, or leads to, a directory. What moves keeps
/// its owner, mode, ACLs and other names; a link moves as itself. Moving changes no content, so
/// it is instant whatever the size.
///
/// As on Linux, a file at the destination is replaced, but never a directory. The working
/// directory, the directories above it and account homes cannot be moved (usermod -d HOME -m
/// moves a home).
#[derive(Parser, Debug)]
#[command(name = "mv")]
pub struct Mv {
    /// never replace a file
    #[arg(short = 'n', long = "no-clobber", overrides_with_all = ["interactive", "force"])]
    pub no_clobber: bool,
    /// ask before replacing each file (also under sudo, xargs and fd -x)
    #[arg(short = 'i', long = "interactive", overrides_with_all = ["no_clobber", "force"])]
    pub interactive: bool,
    /// replace without asking (the default)
    #[arg(short = 'f', long = "force", overrides_with_all = ["no_clobber", "interactive"])]
    pub force: bool,
    /// say what moved
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
    #[arg(value_hint = ValueHint::AnyPath, required = true, value_name = "SOURCE")]
    pub sources: Vec<String>,
    #[arg(value_hint = ValueHint::AnyPath, value_name = "DEST")]
    pub dest: String,
}
impl Manual for Mv {
    const SECTION: Section = Section::Files;
    const NEEDS: &'static str = "w and x on both directories; w on a directory that changes directory. In a sticky directory, only the owner of what is moved or replaced, the directory's owner or root may.";
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("mv draft.md notes.md", "rename"),
        (
            "mv -i notes.md drafts.md archive/",
            "into a directory, asking",
        ),
        ("fd -e log -X mv -n {} old-logs/", "without replacing"),
    ];
    const SEE: &'static [&'static str] = &["cp", "rm"];
}

/// copy files and directories
///
/// Copies each SOURCE to DEST, or into DEST if it is, or leads to, a directory, merging into
/// directories that exist. Copies share the original content, so even large files copy at
/// once, and editing either later leaves the other as it was.
///
/// A new copy is yours, with the source's mode less the umask (022), or what the directory's
/// default ACL gives; -p keeps the mode, ACLs, times and, as far as you may, owner and group. A file that
/// exists is written as it is, keeping its owner, mode and other names; -f removes one you may
/// not write and copies anew.
///
/// Links: without -r, a link named is followed and its file copied; with -r, links are copied as
/// links (-P), unless -L follows them all or -H those named. A file with several names is copied
/// as several files, unless -d or -a keep them one. A file and another name of it are "the same
/// file". A file still uploading cannot be copied yet.
#[derive(Parser, Debug)]
#[command(name = "cp")]
pub struct Cp {
    /// copy directories and what they hold
    #[arg(short = 'r', visible_short_alias = 'R', long = "recursive")]
    pub recursive: bool,
    /// archive: -r, -d and -p, and extended attributes
    #[arg(short = 'a', long = "archive")]
    pub archive: bool,
    /// copy links as links, and keep a file's names together
    #[arg(short = 'd')]
    pub links: bool,
    /// keep mode, ACLs, times, owner and group
    #[arg(short = 'p')]
    pub preserve: bool,
    /// follow every link
    #[arg(short = 'L', long = "dereference", overrides_with_all = ["no_dereference", "command_line"])]
    pub dereference: bool,
    /// follow no link (the default with -r)
    #[arg(short = 'P', long = "no-dereference", overrides_with_all = ["dereference", "command_line"])]
    pub no_dereference: bool,
    /// follow the links named, not those below
    #[arg(short = 'H', overrides_with_all = ["dereference", "no_dereference"])]
    pub command_line: bool,
    /// never replace a file
    #[arg(short = 'n', long = "no-clobber", overrides_with_all = ["interactive", "force"])]
    pub no_clobber: bool,
    /// ask before replacing each file, also below a directory
    #[arg(short = 'i', long = "interactive", overrides_with_all = ["no_clobber", "force"])]
    pub interactive: bool,
    /// remove a file that cannot be written, and copy anew
    #[arg(short = 'f', long = "force", overrides_with_all = ["no_clobber", "interactive"])]
    pub force: bool,
    /// say what was copied
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
    #[arg(value_hint = ValueHint::AnyPath, required = true, value_name = "SOURCE")]
    pub sources: Vec<String>,
    #[arg(value_hint = ValueHint::AnyPath, value_name = "DEST")]
    pub dest: String,
}
impl Manual for Cp {
    const SECTION: Section = Section::Files;
    const NEEDS: &'static str = "r on files and r and x on directories copied; w and x where copies are made; w on a file written over.";
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("cp notes.md notes-backup.md", "a copy"),
        ("cp -r projects /shared/team", "a tree, into a directory"),
        ("cp -a site site.bak", "everything, links and modes kept"),
        ("fd -e pdf -X cp -n {} archive/", "without replacing"),
    ];
    const SEE: &'static [&'static str] = &["mv", "ln"];
}

/// make hard or symbolic links
///
/// A hard link (ln TARGET LINK) is another name for the same file: same content, owner, mode and
/// ACL, changed through any name; the file goes when its last name is removed. Directories
/// cannot be hard-linked.
///
/// A symbolic link (ln -s TARGET LINK) holds a path, read from where the link is: relative
/// targets are relative to the link's directory. It may point to nothing yet. Its own mode is
/// always rwxrwxrwx and means nothing: what it points to decides.
///
/// Into DIR if the last argument is, or leads to, a directory; with one TARGET only, a link of
/// the same name in the working directory. With -f, what is at a link's name gives way only once
/// the link can be made.
#[derive(Parser, Debug)]
#[command(
    name = "ln",
    override_usage = "ln [OPTIONS] TARGET LINK\n       ln [OPTIONS] TARGET... DIR\n       ln [OPTIONS] TARGET"
)]
pub struct Ln {
    /// symbolic link
    #[arg(short = 's', long = "symbolic")]
    pub symbolic: bool,
    /// replace a file in the way
    #[arg(short = 'f', long = "force")]
    pub force: bool,
    /// take LINK as the name even if it leads to a directory
    #[arg(short = 'n', visible_short_alias = 'T', long = "no-dereference")]
    pub no_dereference: bool,
    /// hard-link what a link points to
    #[arg(short = 'L', long = "logical", overrides_with = "physical")]
    pub logical: bool,
    /// hard-link a link itself (the default)
    #[arg(short = 'P', long = "physical", overrides_with = "logical")]
    pub physical: bool,
    /// say what was linked
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
    #[arg(value_hint = ValueHint::AnyPath, required = true, value_name = "TARGET")]
    pub operands: Vec<String>,
}
impl Manual for Ln {
    const SECTION: Section = Section::Files;
    const NEEDS: &'static str = "w and x on the directory the link goes in. Without root, you may hard-link only what you own, or a regular file you may read and write that is not setuid (protected_hardlinks). Following a link in a sticky directory others may write needs you, or the directory's owner, to own the link (protected_symlinks).";
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        (
            "ln -s ../shared/report.pdf report.pdf",
            "a relative symbolic link",
        ),
        ("ln notes.md notes-too.md", "a second name"),
        ("ln -sfn v2 current", "repoint a link"),
    ];
    const SEE: &'static [&'static str] = &["readlink", "ls", "cp"];
}

/// print where a link points
///
/// Prints the target of each symbolic link, as written. With -f, -e or -m, prints instead the
/// absolute path FILE leads to, every link followed.
#[derive(Parser, Debug)]
#[command(name = "readlink")]
pub struct Readlink {
    /// canonical path; all but the last part must exist
    #[arg(short = 'f', long = "canonicalize", overrides_with_all = ["existing", "missing"])]
    pub canonicalize: bool,
    /// canonical path; all of it must exist
    #[arg(short = 'e', long = "canonicalize-existing", overrides_with_all = ["canonicalize", "missing"])]
    pub existing: bool,
    /// canonical path; nothing need exist
    #[arg(short = 'm', long = "canonicalize-missing", overrides_with_all = ["canonicalize", "existing"])]
    pub missing: bool,
    /// no newline after the last
    #[arg(short = 'n', long = "no-newline")]
    pub no_newline: bool,
    #[arg(value_hint = ValueHint::AnyPath, required = true, value_name = "FILE")]
    pub files: Vec<String>,
}
impl Manual for Readlink {
    const SECTION: Section = Section::Files;
    const NEEDS: &'static str = "x on the directories on the way.";
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("readlink current", "its target"),
        ("readlink -f current", "where it leads"),
    ];
    const SEE: &'static [&'static str] = &["ln", "ls"];
}

/// print the absolute path a path leads to
///
/// Prints each FILE as the absolute path it leads to, every link followed, `.` and `..` gone.
/// All of it but the last part must exist, unless -e (all) or -m (none) says otherwise.
#[derive(Parser, Debug)]
#[command(name = "realpath")]
pub struct Realpath {
    /// all of it must exist
    #[arg(
        short = 'e',
        long = "canonicalize-existing",
        overrides_with = "missing"
    )]
    pub existing: bool,
    /// nothing need exist
    #[arg(
        short = 'm',
        long = "canonicalize-missing",
        overrides_with = "existing"
    )]
    pub missing: bool,
    #[arg(value_hint = ValueHint::AnyPath, required = true, value_name = "FILE")]
    pub files: Vec<String>,
}
impl Manual for Realpath {
    const SECTION: Section = Section::Files;
    const NEEDS: &'static str = "x on the directories on the way.";
    const EXAMPLES: &'static [(&'static str, &'static str)] =
        &[("realpath current/../notes.md", "where it is, really")];
    const SEE: &'static [&'static str] = &["readlink", "ln"];
}

/// show what a file is
///
/// Shows what each FILE is: its type, size, inode and links, its mode, owner and group, and
/// when it was last read, its content changed, and it changed at all, to the nanosecond (UTC).
/// Reading a file does not change its access time: the store is mounted noatime, so it is when
/// the file was made, or what touch set. A link is shown as itself, unless -L.
///
/// -c FORMAT shows what FORMAT says instead, a line a file, as GNU's: %n name, %N name with
/// where a link leads, %s size, %b blocks of %B bytes, %a mode in octal, %A as ls shows it, %F
/// type, %u %U owner, %g %G group, %h links, %i inode, %x %y %z the access, modify and change
/// times (%X %Y %Z in seconds), %w %W birth (unknown), %% a %. --printf takes \n and \t too,
/// and ends no line of its own.
#[derive(Parser, Debug)]
#[command(name = "stat")]
pub struct Stat {
    /// what a link leads to, not the link
    #[arg(short = 'L', long = "dereference")]
    pub dereference: bool,
    /// show FORMAT, and a newline
    #[arg(short = 'c', long = "format", value_name = "FORMAT")]
    pub format: Option<String>,
    /// show FORMAT, its backslash escapes read, and no newline
    #[arg(long = "printf", value_name = "FORMAT")]
    pub printf: Option<String>,
    #[arg(value_hint = ValueHint::AnyPath, required = true, value_name = "FILE")]
    pub files: Vec<String>,
}
impl Manual for Stat {
    const SECTION: Section = Section::Files;
    const NEEDS: &'static str = "x on the directories on the way.";
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("stat notes.md", "what it is"),
        ("stat -c '%A %U %s %n' *.md", "one line each"),
    ];
    const SEE: &'static [&'static str] = &["ls", "chmod", "touch"];
}

/// show how much the file system holds
///
/// Shows the file system each FILE is on, or /'s: its size, what is used and what is free, in
/// 1K blocks, or with -h in K, M, G and the like. The store is R2's, which holds as much as it
/// is given: what is free is a petabyte. /proc is the kernel's own, and takes no space.
#[derive(Parser, Debug)]
#[command(name = "df")]
pub struct Df {
    /// sizes in powers of 1024 (1.5G)
    #[arg(short = 'h', long = "human-readable")]
    pub human: bool,
    #[arg(value_hint = ValueHint::AnyPath, value_name = "FILE")]
    pub files: Vec<String>,
}
impl Manual for Df {
    const SECTION: Section = Section::Files;
    const NEEDS: &'static str = "x on the directories on the way.";
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[("df -h", "how much is stored")];
    const SEE: &'static [&'static str] = &["ls", "stat"];
}

/// remove empty directories
///
/// Removes each DIR, which must be empty; with -p, then each directory above it, as written,
/// while one goes. rm -r removes a directory with what is in it.
#[derive(Parser, Debug)]
#[command(name = "rmdir")]
pub struct Rmdir {
    /// then the directories above each, as written
    #[arg(short = 'p', long = "parents")]
    pub parents: bool,
    #[arg(value_hint = ValueHint::DirPath, required = true, value_name = "DIR")]
    pub dirs: Vec<String>,
}
impl Manual for Rmdir {
    const SECTION: Section = Section::Files;
    const NEEDS: &'static str = "w and x on the directory holding each DIR.";
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("rmdir old", "an empty directory"),
        ("rmdir -p a/b/c", "c, then b, then a"),
    ];
    const SEE: &'static [&'static str] = &["rm", "mkdir"];
}

/// find files by name
///
/// Finds what is below the working directory, or each PATH, whose name matches PATTERN, a
/// regular expression; without one, everything. It covers what you may list: directories you
/// cannot read are reported and skipped. Links are found, not followed.
///
/// Results print relative to where you searched, or absolute with -a; one a line, or
/// NUL-terminated with -0. -x runs COMMAND for each result, -X once with all of them, up to a ;
/// or the end; in COMMAND, {} is the path, {/} its name, {//} its directory, {.} the path and {/.}
/// the name without extension. Without a placeholder the paths are added at the end.
#[derive(Parser, Debug)]
#[command(name = "fd")]
pub struct Fd {
    /// files (f), directories (d), links (l) or executables (x) only
    #[arg(short = 't', long = "type", value_name = "TYPE", value_parser = ["f", "file", "d", "directory", "l", "symlink", "x", "executable"])]
    pub types: Vec<String>,
    /// with this extension
    #[arg(short = 'e', long = "extension", value_name = "EXT")]
    pub extensions: Vec<String>,
    /// at most N levels down
    #[arg(short = 'd', long = "max-depth", value_name = "N")]
    pub max_depth: Option<usize>,
    /// PATTERN is a glob
    #[arg(short = 'g', long = "glob", conflicts_with = "fixed")]
    pub glob: bool,
    /// PATTERN is a fixed string
    #[arg(short = 'F', long = "fixed-strings")]
    pub fixed: bool,
    /// ignore case (a pattern without capitals does)
    #[arg(short = 'i', long = "ignore-case", overrides_with = "case_sensitive")]
    pub ignore_case: bool,
    /// respect case
    #[arg(short = 's', long = "case-sensitive", overrides_with = "ignore_case")]
    pub case_sensitive: bool,
    /// match the whole path, not the name
    #[arg(short = 'p', long = "full-path")]
    pub full_path: bool,
    /// include names starting with a dot
    #[arg(short = 'H', long = "hidden")]
    pub hidden: bool,
    /// absolute paths
    #[arg(short = 'a', long = "absolute-path")]
    pub absolute: bool,
    /// NUL-terminated, for xargs -0
    #[arg(short = '0', long = "print0")]
    pub print0: bool,
    /// run COMMAND on each result
    #[arg(short = 'x', long = "exec", value_name = "COMMAND", num_args = 1.., allow_hyphen_values = true, value_terminator = ";", conflicts_with = "exec_batch")]
    pub exec: Option<Vec<String>>,
    /// run COMMAND once, on all results
    #[arg(short = 'X', long = "exec-batch", value_name = "COMMAND", num_args = 1.., allow_hyphen_values = true, value_terminator = ";")]
    pub exec_batch: Option<Vec<String>>,
    #[arg(value_name = "PATTERN")]
    pub pattern: Option<String>,
    #[arg(value_hint = ValueHint::DirPath, value_name = "PATH")]
    pub paths: Vec<String>,
}
impl Manual for Fd {
    const SECTION: Section = Section::Files;
    const NEEDS: &'static str = "r and x on every directory searched.";
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("fd report", "names containing report"),
        ("fd -e md -t f docs", "Markdown files in docs"),
        ("fd -t l", "every link"),
        ("fd -e txt -x mv {} {.}.md", "rename each"),
        ("fd -0 -t f | xargs -0 wc -l", "count lines, odd names too"),
    ];
    const SEE: &'static [&'static str] = &["xargs", "ls"];
}

/// upload files from this device
///
/// Choose files, or drop them onto the page, to upload into DIR or the working directory, up to
/// 1 GB each, in chunks. After an interruption, choosing the same file again resumes it. Progress
/// shows in the tab.
///
/// Ctrl+C (^C on a touch screen) stops and removes the unfinished file, as removing it elsewhere
/// does. Names that exist are not overwritten. Others can read a file while it uploads, and play
/// a video or audio file as it arrives.
///
/// MP4, MOV, M4V and M4A files are checked for faststart: one whose index (moov) is after its
/// media still uploads, with a warning that it plays only once the end has downloaded; faststart
/// FILE then makes it stream, where it is.
#[derive(Parser, Debug)]
#[command(name = "upload")]
pub struct Upload {
    #[arg(value_hint = ValueHint::DirPath, value_name = "DIR")]
    pub dir: Option<String>,
}
impl Manual for Upload {
    const SECTION: Section = Section::Files;
    const NEEDS: &'static str = "w and x on DIR. A directory anyone may write needs no sign-in.";
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("upload", "into the working directory"),
        ("upload ~/photos", "into a directory"),
    ];
    const SEE: &'static [&'static str] = &["faststart", "jobs", "open"];
}

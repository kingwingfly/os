//! /usr: the system's own files, read-only, as an image-based system mounts its /usr (systemd's
//! hermetic /usr): what the build put there (the Worker's assets), not R2's. Its tree is Arch's:
//! /bin and /sbin are links to usr/bin, /lib and /lib64 to usr/lib, /usr/sbin to bin and
//! /usr/lib64 to lib, as on merged-/usr distributions; /sys is sysfs's place, empty here.
//!
//! Only executable WASI images are installed in /usr/bin: coreutils and additional shared
//! user-space utilities, with applet symlinks. Browser dialogs and previews are shell/UI
//! actions, not fake executables. The kernel authorizes every exec and resource operation.
//!
//! The store answers for these names itself (db.rs), so that the kernel resolves, lists, stats
//! and permits them as it does any; changing any of them fails with EROFS (sys.rs).
use os_core::permissions::Node;
use std::cell::{Cell, RefCell};

/// What each binary's content is, as a node names it (none of R2's), and where the Worker's
/// assets have it.
pub const COREUTILS: &str = "usr:coreutils";
pub const OS: &str = "usr:os";
/// Additional WASI user-space programs.
pub const UTILITIES: &str = "usr:utilities";
pub fn asset(content: &str) -> Option<&'static str> {
    match content {
        COREUTILS => Some("/usr/bin/coreutils.wasm"),
        UTILITIES => Some("/usr/bin/utilities.wasm"),
        OS | "usr:terminal" => Some("/pkg/frontend_bg.wasm"),
        _ => None,
    }
}
/// How many bytes the binary `content` is.
pub fn size(content: &str) -> u64 {
    let (coreutils, frontend, utilities) = SIZES.with(Cell::get);
    match content {
        COREUTILS => coreutils,
        OS | "usr:terminal" => frontend,
        UTILITIES => utilities,
        _ => 0,
    }
}
/// What the build says of the binaries: their sizes (scripts/build.mjs).
pub const MANIFEST: &str = "/usr/manifest.json";
/// The inodes of /usr, above any the store numbers.
const INO: u64 = 1 << 40;

/// An entry of /usr/bin: a file of a binary, or a link to `coreutils`.
#[derive(Clone)]
struct Program {
    name: String,
    content: Option<&'static str>,
    target: &'static str,
}

thread_local! {
    /// The binaries' sizes, and when this instance mounted /usr, as its times.
    static SIZES: Cell<(u64, u64, u64)> = const { Cell::new((0, 0, 0)) };
    static MOUNTED: Cell<(u64, u32)> = const { Cell::new((0, 0)) };
    static PROGRAMS: RefCell<Vec<Program>> = const { RefCell::new(Vec::new()) };
}

/// The installed image manifest, independent of the browser's command catalog.
fn with_programs<R>(f: impl FnOnce(&[Program]) -> R) -> R {
    PROGRAMS.with(|programs| {
        let mut programs = programs.borrow_mut();
        if programs.is_empty() {
            let mut all = vec![
                Program {
                    name: "coreutils".into(),
                    content: Some(COREUTILS),
                    target: "",
                },
                Program {
                    name: "utilities".into(),
                    content: Some(UTILITIES),
                    target: "",
                },
            ];
            for (names, target) in [
                (os_core::bin::PROGRAMS, "coreutils"),
                (os_core::bin::UTILITIES, "utilities"),
            ] {
                all.extend(names.iter().map(|name| Program {
                    name: (*name).into(),
                    content: None,
                    target,
                }));
            }
            all.sort_by(|a, b| a.name.cmp(&b.name));
            *programs = all;
        }
        f(&programs)
    })
}

/// Mount the build's images. Legacy frontend content IDs remain readable for existing clones,
/// but no /usr/bin name advertises the frontend as an executable.
pub fn mount(coreutils: u64, frontend: u64, utilities: u64) {
    SIZES.with(|cell| cell.set((coreutils, frontend, utilities)));
    MOUNTED.with(|cell| cell.set(crate::auth::clock()));
}

/// The image's names outside /usr/bin, each a directory (None) or a link to its target, in /
/// and /usr, as Arch has them.
const TREE: &[(&str, Option<&str>)] = &[
    ("/bin", Some("usr/bin")),
    ("/lib", Some("usr/lib")),
    ("/lib64", Some("usr/lib")),
    ("/sbin", Some("usr/bin")),
    ("/sys", None),
    ("/usr", None),
    ("/usr/bin", None),
    ("/usr/include", None),
    ("/usr/lib", None),
    ("/usr/lib64", Some("lib")),
    ("/usr/libexec", None),
    ("/usr/local", None),
    ("/usr/sbin", Some("bin")),
    ("/usr/share", None),
    ("/usr/src", None),
];

/// Whether `path`, as the kernel resolved it, is the image's: /usr and what is in it, and its
/// names in /.
pub fn is(path: &str) -> bool {
    path.starts_with("/usr/")
        || path.starts_with("/sys/")
        || TREE.iter().any(|(name, _)| *name == path)
}

/// The node at `path`, if it is the image's.
pub fn node(path: &str) -> Option<Node> {
    // One name each, but for the directories, which count theirs.
    let numbered = |node: Node, ino: u64| Node {
        ino: INO + ino,
        links: node.links.max(1),
        ..node
    };
    if let Some(at) = TREE.iter().position(|(name, _)| *name == path) {
        let node = match TREE[at].1 {
            Some(target) => Node::symlink(0, 0, target),
            None if path == "/sys" => Node {
                links: 2,
                ..Node::directory(0, 0, 0o555)
            },
            None => directory(
                TREE.iter()
                    .filter(|(name, link)| link.is_none() && os_core::parent(name) == path)
                    .count() as u32,
            ),
        };
        return Some(numbered(node, at as u64));
    }
    // A program of /usr/bin: a file of a binary, or a link to coreutils.
    let name = path.strip_prefix("/usr/bin/")?;
    let (at, content, target) = with_programs(|programs| {
        let at = programs.iter().position(|program| program.name == name)?;
        Some((at, programs[at].content, programs[at].target))
    })?;
    let node = match content {
        Some(content) => Node::file(0, 0, 0o755, content.into(), size(content)),
        None => Node::symlink(0, 0, target),
    };
    Some(numbered(node, TREE.len() as u64 + at as u64))
}

/// A directory of the image, root's, 755, with `subdirectories` in it.
fn directory(subdirectories: u32) -> Node {
    Node {
        links: 2 + subdirectories,
        ..Node::directory(0, 0, 0o755)
    }
}

/// What is in the image's directory `path`, if it is one of them; and in /, the image's names.
pub fn children(path: &str) -> Option<Vec<(String, Node)>> {
    let names: Vec<String> = match path {
        "/" | "/usr" => TREE
            .iter()
            .filter(|(name, _)| os_core::parent(name) == path)
            .map(|(name, _)| name.to_string())
            .collect(),
        "/usr/bin" => with_programs(|programs| {
            programs
                .iter()
                .map(|program| format!("/usr/bin/{}", program.name))
                .collect()
        }),
        _ if TREE
            .iter()
            .any(|(name, link)| *name == path && link.is_none()) =>
        {
            Vec::new()
        }
        _ => return None,
    };
    Some(
        names
            .into_iter()
            .filter_map(|name| node(&name).map(|node| (name, node)))
            .collect(),
    )
}

/// The times of the image's inode `ino`: when it was mounted.
pub fn times(ino: u64) -> Option<kernel::Times> {
    if ino < INO {
        return None;
    }
    let at = MOUNTED.with(Cell::get);
    (ino < INO + (TREE.len() + with_programs(<[Program]>::len)) as u64).then_some(kernel::Times {
        atime: at,
        mtime: at,
        ctime: at,
    })
}

/// What statfs tells of the image: its blocks, all used.
pub fn statfs() -> abi::StatFs {
    let (coreutils, frontend, utilities) = SIZES.with(Cell::get);
    let _ = frontend;
    let blocks = coreutils.div_ceil(4096) + utilities.div_ceil(4096);
    abi::StatFs {
        bsize: 4096,
        blocks,
        files: (TREE.len() + with_programs(<[Program]>::len)) as u64,
        namelen: abi::NAME_MAX as u64,
        ..abi::StatFs::default()
    }
}

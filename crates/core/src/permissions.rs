//! Unix-style access decisions for the virtual filesystem, over any [`Store`], as Linux makes
//! them: owner, group and other bits, POSIX ACLs, the setuid, setgid and sticky bits, hard and
//! symbolic links, and the protected_symlinks and protected_hardlinks rules distributions turn
//! on. No host OS access.
use crate::acl::{self, Acl, Entries};
use crate::{parent, resolve};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
pub const GUEST: u32 = 65534;
/// The guest account's home: a shared, sticky directory, where the accounts guests make have
/// theirs.
pub const GUEST_HOME: &str = "/guest";
pub const READ: u16 = 4;
pub const WRITE: u16 = 2;
pub const EXEC: u16 = 1;
pub const SETUID: u16 = 0o4000;
pub const SETGID: u16 = 0o2000;
pub const STICKY: u16 = 0o1000;
/// The umask everything is created with: group and others may not write.
pub const UMASK: u16 = 0o022;
/// How many symbolic links one path may pass through, as on Linux.
pub const LINKS_MAX: usize = 40;
/// The longest target a symbolic link may have.
pub const LINK_TARGET_MAX: usize = 4095;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct User {
    pub id: u32,
    pub group: u32,
    pub groups: BTreeSet<u32>,
    pub home: String,
    pub locked: bool,
    pub salt: String,
    pub hash: String,
}
/// An inode, as a name shows it: what hard links share, its owner, mode and ACLs among it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Node {
    /// Which inode it is; 0 for one not stored yet, which storing creates.
    #[serde(default)]
    pub ino: u64,
    pub owner: u32,
    pub group: u32,
    /// Permission bits, and the setuid, setgid and sticky bits.
    pub mode: u16,
    pub directory: bool,
    /// The immutable content a file shows; copies share it. None for a directory or a link.
    pub file: Option<String>,
    pub size: u64,
    /// A symbolic link's target, as written.
    #[serde(default)]
    pub link: Option<String>,
    /// A character device's driver, as Linux's `i_rdev` names one (`present`, `snd`): what
    /// reading, writing and its other operations do is the driver's; who may is its mode's
    /// and ACL's, as for any file.
    #[serde(default)]
    pub rdev: Option<String>,
    /// How many names it has: for a directory, 2 and one for each directory in it. A store
    /// says; storing ignores it.
    #[serde(default)]
    pub links: u32,
    /// The entries of its access ACL beyond the mode, once extended: the mode's group bits are
    /// then its mask.
    #[serde(default)]
    pub acl: Option<Acl>,
    /// A directory's default ACL, which what is created in it takes.
    #[serde(default)]
    pub default_acl: Option<Entries>,
}
impl Node {
    pub fn directory(owner: u32, group: u32, mode: u16) -> Self {
        Self {
            ino: 0,
            owner,
            group,
            mode,
            directory: true,
            file: None,
            size: 0,
            link: None,
            rdev: None,
            links: 0,
            acl: None,
            default_acl: None,
        }
    }
    /// A character device of the driver `driver`, as mknod(2) makes one.
    pub fn device(owner: u32, group: u32, mode: u16, driver: &str) -> Self {
        Self {
            directory: false,
            rdev: Some(driver.into()),
            ..Self::directory(owner, group, mode)
        }
    }
    pub fn file(owner: u32, group: u32, mode: u16, file: String, size: u64) -> Self {
        Self {
            directory: false,
            file: Some(file),
            size,
            ..Self::directory(owner, group, mode)
        }
    }
    /// A symbolic link to `target`: its permissions are always rwxrwxrwx, and never checked.
    pub fn symlink(owner: u32, group: u32, target: &str) -> Self {
        Self {
            directory: false,
            size: target.len() as u64,
            link: Some(target.into()),
            ..Self::directory(owner, group, 0o777)
        }
    }
    pub fn is_link(&self) -> bool {
        self.link.is_some()
    }
    /// A regular file: neither a directory, nor a link, nor a device.
    pub fn is_file(&self) -> bool {
        !self.directory && !self.is_link() && !self.is_device()
    }
    pub fn is_device(&self) -> bool {
        self.rdev.is_some()
    }
    /// The same, as a new inode, which storing creates.
    pub fn fresh(&self) -> Self {
        Self {
            ino: 0,
            links: 0,
            ..self.clone()
        }
    }
    /// Its whole access ACL, as getfacl lists it.
    pub fn entries(&self) -> Entries {
        Entries::access(self.mode, self.acl.as_ref())
    }
    /// Take `entries` as its access ACL: the mode's permission bits follow it.
    pub fn set_entries(&mut self, entries: &Entries) {
        let (bits, acl) = entries.split();
        self.mode = (self.mode & 0o7000) | bits;
        self.acl = acl;
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Session {
    pub user: u32,
    pub expires: u64,
    pub sudo_until: u64,
}
#[derive(Clone, Debug)]
pub struct Identity {
    pub id: u32,
    pub group: u32,
    pub groups: BTreeSet<u32>,
}
impl Identity {
    pub fn guest() -> Self {
        Self {
            id: GUEST,
            group: GUEST,
            groups: BTreeSet::from([GUEST]),
        }
    }
    pub fn root() -> Self {
        Self {
            id: 0,
            group: 0,
            groups: BTreeSet::from([0]),
        }
    }
    pub fn of(user: &User) -> Self {
        let mut groups = user.groups.clone();
        groups.insert(user.group);
        Self {
            id: user.id,
            group: user.group,
            groups,
        }
    }
    /// Whether it may `bits` (READ, WRITE, EXEC, together or not) the node: by its owner's
    /// bits if it owns it; else by its ACL, a named user's entry first, then those of the
    /// groups it is in, the owning group's included, any of which allows; else by others'
    /// bits. Root may anything.
    pub fn allows(&self, node: &Node, bits: u16) -> bool {
        if self.id == 0 {
            return true;
        }
        if self.id == node.owner {
            return (node.mode >> 6) & bits == bits;
        }
        let class = (node.mode >> 3) & 7;
        match &node.acl {
            Some(acl) => {
                if let Some(perms) = acl.users.get(&self.id) {
                    return perms & class & bits == bits;
                }
                let owning = self.groups.contains(&node.group).then_some(acl.group);
                let named = acl
                    .groups
                    .iter()
                    .filter(|(g, _)| self.groups.contains(g))
                    .map(|(_, p)| *p);
                let mut matched = false;
                for perms in owning.into_iter().chain(named) {
                    matched = true;
                    if perms & class & bits == bits {
                        return true;
                    }
                }
                if matched {
                    return false;
                }
            }
            None if self.groups.contains(&node.group) => return class & bits == bits,
            None => {}
        }
        node.mode & bits == bits
    }
}

/// The identifiers [`Store::next_id`] hands out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Id {
    User,
    Group,
}

/// A new node in the directory `parent`, made by `who` asking for the permission bits
/// `requested`, as open(2) and mkdir(2) make one: owned by `who`, in the directory's group if
/// it is setgid, else in `who`'s; with the requested bits less `umask`, or, if the directory has
/// a default ACL, that ACL bounded by the requested bits. A directory inherits the default ACL,
/// and the setgid bit.
pub fn created(who: &Identity, parent: &Node, requested: u16, directory: bool, umask: u16) -> Node {
    let group = if parent.mode & SETGID != 0 {
        parent.group
    } else {
        who.group
    };
    let mut node = Node::directory(who.id, group, 0);
    node.directory = directory;
    let requested = requested & 0o777;
    match &parent.default_acl {
        Some(default) => {
            let (bits, acl) = acl::inherited(default, requested);
            node.mode = bits;
            node.acl = acl;
        }
        None => node.mode = requested & !umask,
    }
    if directory {
        node.default_acl = parent.default_acl.clone();
        node.mode |= parent.mode & SETGID;
    }
    node
}

/// Accounts, sessions and the tree of names, as the server keeps them. The permission rules are
/// provided methods, so every store enforces the same ones; a store only reads and writes.
///
/// A path names an inode: [`Store::node`] says what it is, and [`Store::set_node`] names an
/// inode, a new one if its `ino` is 0. An inode goes with its last name, and a file's content
/// once no inode shows it.
///
/// Paths given to the rules are physical up to their last part, as [`Store::physical`] makes
/// them: no symbolic link on the way, so that what each rule checks is what it changes.
pub trait Store {
    /// What `path` names, not following a link there, as lstat(2).
    fn node(&self, path: &str) -> Option<Node>;
    /// The nodes directly inside `path`, by path.
    fn children(&self, path: &str) -> Vec<(String, Node)>;
    /// `path` and every node below it, by path.
    fn subtree(&self, path: &str) -> Vec<(String, Node)>;
    /// Name `node` at `path`: a new inode if its `ino` is 0, else the inode `ino`, which takes
    /// its owner, mode, content and ACLs. What `path` named before loses that name.
    fn set_node(&mut self, path: &str, node: &Node);
    /// Remove the name `path`.
    fn delete_node(&mut self, path: &str);
    /// The extended attributes of the inode `ino`, ...
    fn xattrs(&self, ino: u64) -> BTreeMap<String, Vec<u8>>;
    /// ... which these replace.
    fn set_xattrs(&mut self, ino: u64, attrs: &BTreeMap<String, Vec<u8>>);

    fn user(&self, name: &str) -> Option<User>;
    fn user_by_id(&self, id: u32) -> Option<(String, User)>;
    fn users(&self) -> Vec<(String, User)>;
    /// Insert or replace the account with this user's id, under `name`.
    fn set_user(&mut self, name: &str, user: &User);
    fn delete_user(&mut self, name: &str);

    fn group(&self, name: &str) -> Option<u32>;
    fn group_name(&self, id: u32) -> Option<String>;
    fn groups(&self) -> Vec<(String, u32)>;
    fn set_group(&mut self, name: &str, id: u32);
    fn delete_group(&mut self, name: &str);

    fn session(&self, key: &str) -> Option<Session>;
    fn set_session(&mut self, key: &str, session: &Session);
    fn delete_session(&mut self, key: &str);
    /// Revoke every session of `user`.
    fn delete_sessions(&mut self, user: u32);
    fn delete_expired_sessions(&mut self, now: u64);

    fn next_id(&mut self, kind: Id) -> u32;
    /// Whether the content `file` is still being uploaded: until it is whole, it may be neither
    /// copied nor given another name.
    fn uploading(&self, _file: &str) -> bool {
        false
    }

    fn username(&self, id: u32) -> String {
        if id == GUEST {
            "guest".into()
        } else {
            self.user_by_id(id)
                .map(|(n, _)| n)
                .unwrap_or_else(|| id.to_string())
        }
    }
    fn groupname(&self, id: u32) -> String {
        self.group_name(id).unwrap_or_else(|| id.to_string())
    }
    fn can_sudo(&self, who: &Identity) -> bool {
        who.id == 0 || self.group("wheel").is_some_and(|g| who.groups.contains(&g))
    }
    /// The path `path` names physically, following each symbolic link on the way, and the last
    /// part too if `follow`, as the kernel resolves a path for `who`: a link's target is read
    /// from where the link is, relative or not. Resolution stops where `who` may not search,
    /// or where nothing is, and leaves the rest as written, for the rule that follows to refuse
    /// it. Following a link in a sticky directory others may write needs `who` to own the link,
    /// or the directory's owner to (protected_symlinks).
    fn physical(&self, who: &Identity, path: &str, follow: bool) -> Result<String, String> {
        let mut path = resolve("/", path)?;
        let mut followed = 0;
        'walk: loop {
            let parts: Vec<String> = path
                .split('/')
                .filter(|p| !p.is_empty())
                .map(String::from)
                .collect();
            let mut at = String::from("/");
            for (i, part) in parts.iter().enumerate() {
                let Some(dir) = self.node(&at).filter(|d| d.directory) else {
                    return Ok(path);
                };
                if !who.allows(&dir, EXEC) {
                    return Ok(path);
                }
                let child = if at == "/" {
                    format!("/{part}")
                } else {
                    format!("{at}/{part}")
                };
                let last = i + 1 == parts.len();
                match self.node(&child) {
                    Some(link) if link.is_link() && (!last || follow) => {
                        followed += 1;
                        if followed > LINKS_MAX {
                            return Err(format!("Too many levels of symbolic links: {path}"));
                        }
                        if dir.mode & STICKY != 0
                            && dir.mode & 0o002 != 0
                            && who.id != 0
                            && who.id != link.owner
                            && dir.owner != link.owner
                        {
                            return Err(format!(
                                "Permission denied: {child} is another account's link in a shared sticky directory"
                            ));
                        }
                        let target = link.link.unwrap_or_default();
                        let rest = parts[i + 1..].join("/");
                        let base = if target.starts_with('/') {
                            target
                        } else {
                            format!("{at}/{target}")
                        };
                        path = resolve("/", &format!("{base}/{rest}"))?;
                        continue 'walk;
                    }
                    _ => at = child,
                }
            }
            return Ok(path);
        }
    }
    /// Whether `who` may search every directory above `path`, from the root down: what lies
    /// below a directory it may not search is never looked at, not even whether it exists.
    fn traverse(&self, who: &Identity, path: &str) -> Result<(), String> {
        let mut at = String::from("/");
        let mut parts = parent(path).split('/').filter(|part| !part.is_empty());
        loop {
            let node = self.node(&at).ok_or("Parent directory does not exist")?;
            if !node.directory || !who.allows(&node, EXEC) {
                return Err(format!("Permission denied: cannot traverse {at}"));
            }
            let Some(part) = parts.next() else {
                break;
            };
            if at != "/" {
                at.push('/');
            }
            at.push_str(part);
        }
        Ok(())
    }
    fn access(&self, who: &Identity, path: &str, bits: u16) -> Result<Node, String> {
        self.traverse(who, path)?;
        let node = self.node(path).ok_or("File or directory does not exist")?;
        if !who.allows(&node, bits) {
            return Err(format!("Permission denied: {path}"));
        }
        Ok(node)
    }
    fn writable_parent(&self, who: &Identity, path: &str) -> Result<(), String> {
        let node = self.access(who, parent(path), WRITE | EXEC)?;
        if !node.directory {
            return Err("Parent path is not a directory".into());
        }
        // A home not made yet is its account's to make, or root's: no one else takes its name,
        // as anyone could in /guest, which everyone may write in.
        if who.id != 0 && self.home_of(path).is_some_and(|owner| owner != who.id) {
            return Err(format!(
                "Permission denied: {path} is another account's home"
            ));
        }
        Ok(())
    }
    /// The account whose home is `path`, if any.
    fn home_of(&self, path: &str) -> Option<u32> {
        self.users()
            .into_iter()
            .find(|(_, user)| user.home == path)
            .map(|(_, user)| user.id)
    }
    /// Whether `who` may remove or rename `node`, named `path`, from its directory, which it
    /// may write: in a sticky one, only its owner, the directory's owner and root may.
    fn unlinkable(&self, who: &Identity, path: &str, node: &Node) -> Result<(), String> {
        let Some(dir) = self.node(parent(path)) else {
            return Ok(());
        };
        if dir.mode & STICKY != 0 && who.id != 0 && who.id != node.owner && who.id != dir.owner {
            return Err(format!(
                "Operation not permitted: {path} is another account's, in a sticky directory"
            ));
        }
        Ok(())
    }
    fn mkdir(&mut self, who: &Identity, path: &str, parents: bool) -> Result<(), String> {
        let exists = || format!("cannot create directory '{path}': it already exists");
        if path == "/" {
            self.access(who, "/", EXEC)?;
            return if parents { Ok(()) } else { Err(exists()) };
        }
        let mut at = String::new();
        // Validate every component before mutating, including mkdir -p through existing directories.
        let mut pending = Vec::new();
        for part in path.trim_start_matches('/').split('/') {
            at.push('/');
            at.push_str(part);
            if let Some(node) = self.node(&at) {
                self.access(who, &at, EXEC)?;
                // A link to a directory is one for mkdir -p, at the end of the path.
                if node.is_link() && at == path {
                    let real = self.physical(who, &at, true)?;
                    return match self.node(&real) {
                        Some(n) if n.directory && parents => Ok(()),
                        _ => Err(exists()),
                    };
                }
                if !node.directory {
                    return Err("A file with this name already exists in the path".into());
                }
            } else {
                if !parents && at != path {
                    return Err("Parent directory does not exist; use mkdir -p".into());
                }
                if pending.is_empty() {
                    self.writable_parent(who, &at)?;
                }
                pending.push(at.clone());
            }
        }
        // As mkdir does without -p, a directory that exists already is an error.
        if pending.is_empty() && !parents {
            return Err(exists());
        }
        let Some(mut above) = pending.first().and_then(|p| self.node(parent(p))) else {
            return Ok(());
        };
        for path in pending {
            let node = created(who, &above, 0o777, true, UMASK);
            self.set_node(&path, &node);
            above = node;
        }
        Ok(())
    }
    fn remove(&mut self, who: &Identity, path: &str, recursive: bool) -> Result<(), String> {
        if path == "/" {
            return Err("Cannot remove the root directory".into());
        }
        self.writable_parent(who, path)?;
        let node = self.node(path).ok_or("File or directory does not exist")?;
        if node.directory && !recursive {
            return Err("This is a directory; use rm -r DIR".into());
        }
        self.unlinkable(who, path, &node)?;
        let nodes = self.subtree(path);
        // rm -r needs to enumerate and modify every directory being emptied, and, in a sticky
        // one, to be let remove each of its entries.
        for (p, n) in &nodes {
            if n.directory {
                self.access(who, p, READ | WRITE | EXEC)?;
            }
            if p != path {
                self.unlinkable(who, p, n)?;
            }
        }
        for (p, _) in nodes {
            self.delete_node(&p);
        }
        Ok(())
    }
    /// chmod: links met on the way down are left alone, as Linux has no mode for a link.
    fn chmod(
        &mut self,
        who: &Identity,
        path: &str,
        mode: &str,
        recursive: bool,
    ) -> Result<(), String> {
        self.access(who, path, 0)?;
        let nodes = if recursive {
            self.subtree(path)
        } else {
            vec![(path.into(), self.access(who, path, 0)?)]
        };
        let mut changes = Vec::new();
        for (p, mut n) in nodes {
            if n.is_link() {
                continue;
            }
            self.access(who, &p, 0)?;
            if who.id != 0 && who.id != n.owner {
                return Err("Only the owner or root can chmod".into());
            }
            n.mode = change_mode(n.mode, mode, n.directory)?;
            // Without root, setgid needs the node's group to be one of the caller's: it is
            // cleared otherwise, without an error, as Linux does.
            if who.id != 0 && !who.groups.contains(&n.group) {
                n.mode &= !SETGID;
            }
            changes.push((p, n));
        }
        for (p, n) in changes {
            self.set_node(&p, &n);
        }
        Ok(())
    }
    /// chown: of the link itself, given one, as chown -h; changing who owns a file clears its
    /// setuid bit, and its setgid bit if the group may execute it.
    fn chown(
        &mut self,
        who: &Identity,
        path: &str,
        owner: Option<u32>,
        group: Option<u32>,
        recursive: bool,
    ) -> Result<(), String> {
        self.access(who, path, 0)?;
        let nodes = if recursive {
            self.subtree(path)
        } else {
            vec![(path.into(), self.access(who, path, 0)?)]
        };
        for (p, n) in &nodes {
            self.access(who, p, 0)?;
            if who.id != 0
                && (who.id != n.owner
                    || owner.is_some_and(|id| id != n.owner)
                    || group.is_some_and(|g| !who.groups.contains(&g)))
            {
                return Err("Only root can change ownership; owners may change the group to one they belong to".into());
            }
        }
        for (p, mut n) in nodes {
            if let Some(id) = owner {
                n.owner = id;
            }
            if let Some(id) = group {
                n.group = id;
            }
            if n.is_file() && (owner.is_some() || group.is_some()) {
                n.mode &= !SETUID;
                if n.mode & 0o010 != 0 {
                    n.mode &= !SETGID;
                }
            }
            self.set_node(&p, &n);
        }
        Ok(())
    }
    /// The nodes below the directory `root` that `who` may list, by path: every directory on
    /// the way must be readable and searchable. Also how many directories hid their contents.
    /// Links are listed, not followed.
    fn walk(
        &self,
        who: &Identity,
        root: &str,
        max_depth: Option<usize>,
    ) -> Result<(Vec<(String, Node)>, usize), String> {
        let node = self.access(who, root, READ | EXEC)?;
        if !node.directory {
            return Err(format!("Not a directory: {root}"));
        }
        let depth_of = |path: &str| {
            path[root.len()..]
                .split('/')
                .filter(|p| !p.is_empty())
                .count()
        };
        let mut listable = BTreeSet::from([root.to_string()]);
        let mut found = Vec::new();
        let mut hidden = 0;
        // Parents come before their children, by path.
        for (path, node) in self.subtree(root) {
            if path == root
                || !listable.contains(parent(&path))
                || max_depth.is_some_and(|d| depth_of(&path) > d)
            {
                continue;
            }
            if node.directory {
                if who.allows(&node, READ | EXEC) {
                    listable.insert(path.clone());
                } else {
                    hidden += 1;
                }
            }
            found.push((path, node));
        }
        Ok((found, hidden))
    }
    /// Move `src` to `dst` with its owner and mode, as rename does: both parents need w+x, and
    /// a directory changing parent needs w itself; in a sticky directory, only the owner of
    /// what is moved or replaced, the directory's, or root may. An existing file at `dst` is
    /// replaced if `replace`, and skipped otherwise, returning false; a directory is never
    /// replaced. A link moves as itself.
    fn rename(
        &mut self,
        who: &Identity,
        src: &str,
        dst: &str,
        replace: bool,
    ) -> Result<bool, String> {
        if src == "/" {
            return Err("Cannot move the root directory".into());
        }
        if src == dst {
            return Err(format!("'{src}' and '{dst}' are the same file"));
        }
        if dst.starts_with(&format!("{src}/")) {
            return Err(format!("Cannot move '{src}' into itself"));
        }
        self.writable_parent(who, src)?;
        let node = self.node(src).ok_or("File or directory does not exist")?;
        self.writable_parent(who, dst)?;
        if node.directory && parent(src) != parent(dst) {
            self.access(who, src, WRITE)?;
        }
        self.unlinkable(who, src, &node)?;
        if let Some(existing) = self.node(dst) {
            if existing.ino == node.ino {
                return Err(format!("'{src}' and '{dst}' are the same file"));
            }
            if existing.directory {
                return Err(format!("Cannot overwrite the directory '{dst}'"));
            }
            if node.directory {
                return Err(format!(
                    "Cannot overwrite the file '{dst}' with a directory"
                ));
            }
            if !replace {
                return Ok(false);
            }
            self.unlinkable(who, dst, &existing)?;
        }
        let nodes = self.subtree(src);
        let mut moved = Vec::new();
        for (p, n) in &nodes {
            let target = format!("{dst}{}", &p[src.len()..]);
            resolve("/", &target)?;
            moved.push((target, n.clone()));
        }
        // Write the new paths first, so no file is ever left without a node.
        for (p, n) in moved {
            self.set_node(&p, &n);
        }
        for (p, _) in nodes {
            self.delete_node(&p);
        }
        Ok(true)
    }
    /// A hard link `dst` to `src`, which link(2) makes: not to a directory; it needs w+x on the
    /// directory `dst` goes in. Without root, one may link only what one owns, or a regular file
    /// one may read and write that is not setuid, nor setgid and executable by its group
    /// (protected_hardlinks). With `replace` (ln -f), a file at `dst` is replaced, but only once
    /// the link is known to be possible: a link that cannot be made leaves what was there.
    fn link(&mut self, who: &Identity, src: &str, dst: &str, replace: bool) -> Result<(), String> {
        let node = self.access(who, src, 0)?;
        if node.directory {
            return Err(format!("'{src}': hard link not allowed for directory"));
        }
        if node.file.as_deref().is_some_and(|id| self.uploading(id)) {
            return Err(format!(
                "'{src}' is still uploading; link it once it completes"
            ));
        }
        self.writable_parent(who, dst)?;
        if who.id != 0 && who.id != node.owner {
            let safe = node.is_file()
                && node.mode & SETUID == 0
                && !(node.mode & SETGID != 0 && node.mode & 0o010 != 0)
                && who.allows(&node, READ | WRITE);
            if !safe {
                return Err(format!(
                    "failed to create hard link '{dst}' => '{src}': Operation not permitted"
                ));
            }
        }
        if let Some(existing) = self.node(dst) {
            if existing.ino == node.ino {
                return Err(format!("'{src}' and '{dst}' are the same file"));
            }
            self.replaceable(who, dst, &existing, replace, "hard link")?;
            self.delete_node(dst);
        }
        self.set_node(dst, &node);
        Ok(())
    }
    /// A symbolic link `dst` to `target`, which symlink(2) makes: it needs w+x on the directory
    /// it goes in; what it points to need not exist. `replace` as for [`Store::link`].
    fn symlink(
        &mut self,
        who: &Identity,
        target: &str,
        dst: &str,
        replace: bool,
    ) -> Result<(), String> {
        if target.is_empty() {
            return Err(format!(
                "failed to create symbolic link '{dst}': No such file or directory"
            ));
        }
        if target.len() > LINK_TARGET_MAX
            || target.contains('\\')
            || target.chars().any(char::is_control)
        {
            return Err("A link's target cannot contain control characters or backslashes, nor be longer than 4095 bytes".into());
        }
        self.writable_parent(who, dst)?;
        let dir = self
            .node(parent(dst))
            .ok_or("Parent directory does not exist")?;
        if let Some(existing) = self.node(dst) {
            self.replaceable(who, dst, &existing, replace, "symbolic link")?;
            self.delete_node(dst);
        }
        let group = if dir.mode & SETGID != 0 {
            dir.group
        } else {
            who.group
        };
        self.set_node(dst, &Node::symlink(who.id, group, target));
        Ok(())
    }
    /// Whether `existing`, at `path`, may give way to a new link, as ln -f removes it: only with
    /// `replace`, never a directory, and in a sticky directory, only if `who` may remove it.
    fn replaceable(
        &self,
        who: &Identity,
        path: &str,
        existing: &Node,
        replace: bool,
        what: &str,
    ) -> Result<(), String> {
        if !replace {
            return Err(format!("failed to create {what} '{path}': File exists"));
        }
        if existing.directory {
            return Err(format!("'{path}': cannot overwrite directory"));
        }
        self.unlinkable(who, path, existing)
    }
    fn move_home(&mut self, old: &str, new: &str) -> Result<(), String> {
        if old == "/"
            || new == "/"
            || old == new
            || new.starts_with(&format!("{old}/"))
            || old.starts_with(&format!("{new}/"))
        {
            return Err("Home move paths must differ and cannot contain each other".into());
        }
        if self.node(new).is_some() {
            return Err("Destination already exists; the move will not overwrite it".into());
        }
        let n = self.node(old).ok_or("Original home does not exist")?;
        if !n.directory {
            return Err("Original home is not a directory".into());
        }
        let nodes = self.subtree(old);
        let mut moved = Vec::new();
        for (p, n) in &nodes {
            let target = format!("{new}{}", &p[old.len()..]);
            resolve("/", &target)?;
            moved.push((target, n.clone()));
        }
        self.mkdir(&Identity::root(), parent(new), true)?;
        // Write the new paths first, so no file is ever left without a node.
        for (p, n) in moved {
            self.set_node(&p, &n);
        }
        for (p, _) in nodes {
            self.delete_node(&p);
        }
        Ok(())
    }
}

/// A [`Store`] in memory, for tests and tools.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MemStore {
    pub users: BTreeMap<String, User>,
    pub groups: BTreeMap<String, u32>,
    /// Paths, and the inodes they name, ...
    pub names: BTreeMap<String, u64>,
    /// ... which are these.
    pub inodes: BTreeMap<u64, Node>,
    pub attrs: BTreeMap<u64, BTreeMap<String, Vec<u8>>>,
    pub sessions: BTreeMap<String, Session>,
    pub next_user: u32,
    pub next_group: u32,
    pub next_ino: u64,
    /// Files no node shows any more, in the order they were freed.
    pub freed: Vec<String>,
    /// Files still being uploaded.
    pub incomplete: BTreeSet<String>,
}
impl MemStore {
    /// A filesystem with only `root` and the system groups, and `/` as its tree.
    pub fn new(root: User) -> Self {
        let mut store = Self {
            users: BTreeMap::from([("root".into(), root)]),
            groups: BTreeMap::from([
                ("root".into(), 0),
                ("wheel".into(), 27),
                ("guest".into(), GUEST),
            ]),
            next_user: 1000,
            next_group: 1000,
            next_ino: 1,
            ..Self::default()
        };
        store.set_node("/", &Node::directory(0, 0, 0o755));
        store
    }
    /// What `path` names, which must exist.
    pub fn at(&self, path: &str) -> Node {
        self.node(path)
            .unwrap_or_else(|| panic!("{path} does not exist"))
    }
    fn release(&mut self, file: Option<String>) {
        if let Some(file) = file
            && !self
                .inodes
                .values()
                .any(|n| n.file.as_deref() == Some(&file))
        {
            self.freed.push(file);
        }
    }
    /// Let the inode `ino` go, if nothing names it.
    fn forget(&mut self, ino: u64) {
        if self.names.values().any(|i| *i == ino) {
            return;
        }
        self.attrs.remove(&ino);
        if let Some(node) = self.inodes.remove(&ino) {
            self.release(node.file);
        }
    }
}
impl Store for MemStore {
    fn node(&self, path: &str) -> Option<Node> {
        let ino = *self.names.get(path)?;
        let mut node = self.inodes.get(&ino)?.clone();
        node.links = if node.directory {
            let prefix = if path == "/" {
                "/".into()
            } else {
                format!("{path}/")
            };
            2 + self
                .names
                .iter()
                .filter(|(p, i)| {
                    p.starts_with(&prefix)
                        && parent(p) == path
                        && *p != path
                        && self.inodes.get(i).is_some_and(|n| n.directory)
                })
                .count() as u32
        } else {
            self.names.values().filter(|i| **i == ino).count() as u32
        };
        Some(node)
    }
    fn children(&self, path: &str) -> Vec<(String, Node)> {
        let prefix = if path == "/" {
            "/".into()
        } else {
            format!("{path}/")
        };
        self.names
            .iter()
            .filter(|(p, _)| p.starts_with(&prefix) && *p != path && parent(p) == path)
            .filter_map(|(p, _)| Some((p.clone(), self.node(p)?)))
            .collect()
    }
    fn subtree(&self, path: &str) -> Vec<(String, Node)> {
        let prefix = if path == "/" {
            "/".into()
        } else {
            format!("{path}/")
        };
        self.names
            .iter()
            .filter(|(p, _)| *p == path || p.starts_with(&prefix))
            .filter_map(|(p, _)| Some((p.clone(), self.node(p)?)))
            .collect()
    }
    fn set_node(&mut self, path: &str, node: &Node) {
        let ino = if node.ino == 0 {
            self.next_ino += 1;
            self.next_ino
        } else {
            node.ino
        };
        let before = self.inodes.get(&ino).and_then(|n| n.file.clone());
        self.inodes.insert(
            ino,
            Node {
                ino,
                links: 0,
                ..node.clone()
            },
        );
        if before != node.file {
            self.release(before);
        }
        if let Some(old) = self.names.insert(path.into(), ino)
            && old != ino
        {
            self.forget(old);
        }
    }
    fn delete_node(&mut self, path: &str) {
        if let Some(ino) = self.names.remove(path) {
            self.forget(ino);
        }
    }
    fn xattrs(&self, ino: u64) -> BTreeMap<String, Vec<u8>> {
        self.attrs.get(&ino).cloned().unwrap_or_default()
    }
    fn set_xattrs(&mut self, ino: u64, attrs: &BTreeMap<String, Vec<u8>>) {
        if attrs.is_empty() {
            self.attrs.remove(&ino);
        } else {
            self.attrs.insert(ino, attrs.clone());
        }
    }
    fn user(&self, name: &str) -> Option<User> {
        self.users.get(name).cloned()
    }
    fn user_by_id(&self, id: u32) -> Option<(String, User)> {
        self.users
            .iter()
            .find(|(_, u)| u.id == id)
            .map(|(n, u)| (n.clone(), u.clone()))
    }
    fn users(&self) -> Vec<(String, User)> {
        self.users
            .iter()
            .map(|(n, u)| (n.clone(), u.clone()))
            .collect()
    }
    fn set_user(&mut self, name: &str, user: &User) {
        self.users.retain(|_, u| u.id != user.id);
        self.users.insert(name.into(), user.clone());
    }
    fn delete_user(&mut self, name: &str) {
        self.users.remove(name);
    }
    fn group(&self, name: &str) -> Option<u32> {
        self.groups.get(name).copied()
    }
    fn group_name(&self, id: u32) -> Option<String> {
        self.groups
            .iter()
            .find(|(_, g)| **g == id)
            .map(|(n, _)| n.clone())
    }
    fn groups(&self) -> Vec<(String, u32)> {
        self.groups.iter().map(|(n, g)| (n.clone(), *g)).collect()
    }
    fn set_group(&mut self, name: &str, id: u32) {
        self.groups.insert(name.into(), id);
    }
    fn delete_group(&mut self, name: &str) {
        self.groups.remove(name);
    }
    fn session(&self, key: &str) -> Option<Session> {
        self.sessions.get(key).cloned()
    }
    fn set_session(&mut self, key: &str, session: &Session) {
        self.sessions.insert(key.into(), session.clone());
    }
    fn delete_session(&mut self, key: &str) {
        self.sessions.remove(key);
    }
    fn delete_sessions(&mut self, user: u32) {
        self.sessions.retain(|_, s| s.user != user);
    }
    fn delete_expired_sessions(&mut self, now: u64) {
        self.sessions.retain(|_, s| s.expires > now);
    }
    fn uploading(&self, file: &str) -> bool {
        self.incomplete.contains(file)
    }
    fn next_id(&mut self, kind: Id) -> u32 {
        let next = match kind {
            Id::User => &mut self.next_user,
            Id::Group => &mut self.next_group,
        };
        *next += 1;
        *next - 1
    }
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name.as_bytes()[0].is_ascii_lowercase()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
        && name != "guest"
}
/// `drwxr-xr-x`, `-rwsr-x---`, `drwxrwxrwt` ...: `kind` first (`d`, `-`, `l`), then the
/// permission bits, with setuid and setgid as `s` (or `S` without execute) and sticky as `t`
/// (or `T`), as ls -l writes them.
pub fn type_mode_text(mode: u16, kind: char) -> String {
    let mut out = String::from(kind);
    for (shift, special, mark) in [(6, SETUID, 's'), (3, SETGID, 's'), (0, STICKY, 't')] {
        for (bit, c) in [(4, 'r'), (2, 'w'), (1, 'x')] {
            let set = mode & (bit << shift) != 0;
            out.push(match (bit, mode & special != 0) {
                (1, true) if set => mark,
                (1, true) => mark.to_ascii_uppercase(),
                _ if set => c,
                _ => '-',
            });
        }
    }
    out
}
pub fn mode_text(mode: u16, directory: bool) -> String {
    type_mode_text(mode, if directory { 'd' } else { '-' })
}
/// The mode `spec` gives a node with `mode`, as chmod reads it: octal (up to four digits, the
/// first for setuid 4, setgid 2 and sticky 1; a directory keeps its setuid and setgid bits
/// unless five digits are given, as GNU chmod does) or symbolic (`u+s`, `g-s`, `+t`, `o=rx`...).
pub fn change_mode(mut mode: u16, spec: &str, directory: bool) -> Result<u16, String> {
    if (3..=5).contains(&spec.len()) && spec.bytes().all(|c| (b'0'..=b'7').contains(&c)) {
        let value = u16::from_str_radix(spec, 8).unwrap();
        if value > 0o7777 {
            return Err("chmod mode: at most 7777".into());
        }
        let kept = if directory && spec.len() < 5 {
            mode & (SETUID | SETGID) & !(value & (SETUID | SETGID))
        } else {
            0
        };
        return Ok(value | kept);
    }
    for clause in spec.split(',') {
        let chars: Vec<char> = clause.chars().collect();
        let mut i = 0;
        let mut mask = 0;
        let mut classes = 0;
        while i < chars.len() {
            let (bits, class) = match chars[i] {
                'u' => (0o700, 0o4),
                'g' => (0o070, 0o2),
                'o' => (0o007, 0o1),
                'a' => (0o777, 0o7),
                _ => break,
            };
            mask |= bits;
            classes |= class;
            i += 1;
        }
        let given = classes != 0;
        if !given {
            mask = 0o777;
            classes = 0o7;
        }
        // The special bits each class has: setuid the owner's, setgid the group's, sticky
        // others' (and +t without a class).
        let special = |s: bool, t: bool| {
            let mut bits = 0;
            if s && classes & 0o4 != 0 {
                bits |= SETUID;
            }
            if s && classes & 0o2 != 0 {
                bits |= SETGID;
            }
            if t && (classes & 0o1 != 0 || !given) {
                bits |= STICKY;
            }
            bits
        };
        let mut operated = false;
        while i < chars.len() {
            let op = chars[i];
            if !['+', '-', '='].contains(&op) {
                return Err("chmod mode: 640 or u+rw,g-x,o=r".into());
            }
            i += 1;
            let mut bits = 0;
            let (mut s, mut t) = (false, false);
            while i < chars.len() && !['+', '-', '='].contains(&chars[i]) {
                bits |= match chars[i] {
                    'r' => 0o444,
                    'w' => 0o222,
                    'x' => 0o111,
                    'X' => {
                        if directory || mode & 0o111 != 0 {
                            0o111
                        } else {
                            0
                        }
                    }
                    'u' => ((mode >> 6) & 7) * 0o111,
                    'g' => ((mode >> 3) & 7) * 0o111,
                    'o' => (mode & 7) * 0o111,
                    's' => {
                        s = true;
                        0
                    }
                    't' => {
                        t = true;
                        0
                    }
                    _ => return Err("Unsupported chmod permission bit".into()),
                };
                i += 1;
            }
            let bits = (bits & mask) | special(s, t);
            // = clears the classes' special bits, but a directory's setuid and setgid, as GNU
            // chmod keeps them.
            let cleared = mask | special(true, true) & !if directory { SETUID | SETGID } else { 0 };
            mode = match op {
                '+' => mode | bits,
                '-' => mode & !bits,
                _ => (mode & !cleared) | bits,
            };
            operated = true;
        }
        if !operated {
            return Err("chmod requires an operator".into());
        }
    }
    Ok(mode)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn store() -> MemStore {
        MemStore::new(User {
            id: 0,
            group: 0,
            groups: BTreeSet::new(),
            home: "/root".into(),
            locked: false,
            salt: String::new(),
            hash: String::new(),
        })
    }
    fn file(owner: u32, mode: u16, content: &str) -> Node {
        Node::file(owner, owner, mode, content.into(), 1)
    }
    #[test]
    fn unix_mode_precedence_and_root_override() {
        let owner = Identity {
            id: 1,
            group: 2,
            groups: BTreeSet::from([2]),
        };
        let n = Node::directory(1, 2, 0o077);
        assert!(!owner.allows(&n, READ));
        assert!(Identity::guest().allows(&n, READ));
        assert!(Identity::root().allows(&Node::directory(9, 9, 0), 7));
    }
    #[test]
    fn symbolic_and_numeric_modes() {
        assert_eq!(change_mode(0o640, "o+w,g-x", false).unwrap(), 0o642);
        assert_eq!(change_mode(0o777, "u=rw,go=", false).unwrap(), 0o600);
        assert_eq!(change_mode(0o600, "g=u,o=g", false).unwrap(), 0o666);
        assert_eq!(change_mode(0o644, "a+X", false).unwrap(), 0o644);
        assert_eq!(change_mode(0o644, "a+X", true).unwrap(), 0o755);
        assert_eq!(change_mode(0o644, "4755", false).unwrap(), 0o4755);
        assert_eq!(mode_text(0o750, true), "drwxr-x---");
    }
    #[test]
    fn traversal_cannot_be_bypassed_by_readable_child() {
        let mut c = store();
        c.set_node("/private", &Node::directory(0, 0, 0o700));
        c.set_node("/private/readme.txt", &file(0, 0o644, "readme"));
        assert!(
            c.access(&Identity::guest(), "/private/readme.txt", READ)
                .is_err()
        );
        assert!(
            c.access(&Identity::root(), "/private/readme.txt", READ)
                .is_ok()
        );
        // Whether something exists below a directory one cannot search does not show.
        c.set_node("/private/inner", &Node::directory(0, 0, 0o755));
        for path in ["/private/inner/x", "/private/missing/x"] {
            assert_eq!(
                c.access(&Identity::guest(), path, READ).unwrap_err(),
                "Permission denied: cannot traverse /private",
                "{path}"
            );
        }
    }
    #[test]
    fn mkdir_without_parents_refuses_what_exists() {
        let mut c = store();
        c.mkdir(&Identity::root(), "/a", false).unwrap();
        assert!(c.mkdir(&Identity::root(), "/a", false).is_err());
        assert!(c.mkdir(&Identity::root(), "/", false).is_err());
        assert!(c.mkdir(&Identity::root(), "/a", true).is_ok());
        assert!(c.mkdir(&Identity::root(), "/a/b/c", false).is_err());
        assert!(c.mkdir(&Identity::root(), "/a/b/c", true).is_ok());
    }
    #[test]
    fn deletion_checks_parent_and_every_descendant_before_mutation() {
        let mut c = store();
        let mut root = c.at("/");
        root.mode = 0o777;
        c.set_node("/", &root);
        c.set_node("/shared", &Node::directory(0, 0, 0o777));
        c.set_node("/shared/private", &Node::directory(0, 0, 0o700));
        c.set_node("/shared/a.txt", &file(0, 0o644, "a"));
        assert!(c.remove(&Identity::guest(), "/shared", true).is_err());
        assert!(c.names.contains_key("/shared/a.txt"));
        assert!(c.freed.is_empty());
        assert!(c.remove(&Identity::root(), "/shared", true).is_ok());
        assert_eq!(c.names.len(), 1);
        assert_eq!(c.freed, ["a"]);
    }
    #[test]
    fn content_is_freed_only_when_no_node_shows_it() {
        let mut c = store();
        c.set_node("/a.txt", &file(0, 0o644, "shared"));
        c.set_node("/b.txt", &file(0, 0o644, "shared"));
        c.delete_node("/a.txt");
        assert!(c.freed.is_empty());
        // Replacing a node's content frees the old content, but rewriting its mode does not.
        c.set_node("/b.txt", &file(0, 0o600, "shared"));
        assert!(c.freed.is_empty());
        c.set_node("/b.txt", &file(0, 0o600, "new"));
        assert_eq!(c.freed, ["shared"]);
    }
    #[test]
    fn children_and_subtrees_follow_path_boundaries() {
        let mut c = store();
        for path in ["/a", "/a/b", "/ab"] {
            c.set_node(path, &Node::directory(0, 0, 0o755));
        }
        c.set_node("/a/b/spéctrum.txt", &file(0, 0o644, "s"));
        let paths =
            |nodes: Vec<(String, Node)>| nodes.into_iter().map(|(p, _)| p).collect::<Vec<_>>();
        assert_eq!(paths(c.children("/")), ["/a", "/ab"]);
        assert_eq!(paths(c.children("/a")), ["/a/b"]);
        assert_eq!(paths(c.subtree("/a")), ["/a", "/a/b", "/a/b/spéctrum.txt"]);
        assert_eq!(c.subtree("/").len(), 5);
    }
    #[test]
    fn home_move_preserves_content_and_metadata() {
        let mut c = store();
        c.mkdir(&Identity::root(), "/home/alice", true).unwrap();
        c.set_node("/home/alice/a.txt", &file(1000, 0o600, "immutable"));
        c.move_home("/home/alice", "/homes/alice").unwrap();
        assert!(!c.names.contains_key("/home/alice"));
        assert_eq!(
            c.at("/homes/alice/a.txt").file.as_deref(),
            Some("immutable")
        );
        assert_eq!(c.at("/homes/alice/a.txt").mode, 0o600);
        assert!(c.freed.is_empty());
        assert!(c.move_home("/homes/alice", "/homes/alice/sub").is_err());
    }
    fn alice() -> Identity {
        Identity {
            id: 1000,
            group: 1000,
            groups: BTreeSet::from([1000]),
        }
    }
    /// /home/alice (alice's), holding a.txt, docs/b.md and a private directory.
    fn home() -> MemStore {
        let mut c = store();
        c.set_node("/home", &Node::directory(0, 0, 0o755));
        c.set_node("/home/alice", &Node::directory(1000, 1000, 0o755));
        c.set_node("/home/alice/a.txt", &file(1000, 0o664, "a"));
        c.set_node("/home/alice/docs", &Node::directory(1000, 1000, 0o755));
        c.set_node("/home/alice/docs/b.md", &file(1000, 0o644, "b"));
        c.set_node("/home/alice/private", &Node::directory(1000, 1000, 0o700));
        c.set_node("/home/alice/private/c.txt", &file(1000, 0o644, "c"));
        c
    }
    #[test]
    fn walks_show_only_what_listings_would() {
        let c = home();
        let paths = |who: &Identity| {
            let (nodes, hidden) = c.walk(who, "/home/alice", None).unwrap();
            (
                nodes.into_iter().map(|(p, _)| p).collect::<Vec<_>>(),
                hidden,
            )
        };
        assert_eq!(paths(&alice()).0.len(), 5);
        let (seen, hidden) = paths(&Identity::guest());
        assert_eq!(
            seen,
            [
                "/home/alice/a.txt",
                "/home/alice/docs",
                "/home/alice/docs/b.md",
                "/home/alice/private"
            ]
        );
        assert_eq!(hidden, 1);
        let (shallow, _) = c.walk(&alice(), "/home/alice", Some(1)).unwrap();
        assert_eq!(shallow.len(), 3);
        assert!(c.walk(&alice(), "/home/alice/a.txt", None).is_err());
    }
    #[test]
    fn renames_move_trees_and_follow_the_rules_of_rename() {
        let mut c = home();
        assert!(
            c.rename(&alice(), "/home/alice/docs", "/home/alice/notes", false)
                .unwrap()
        );
        assert!(c.names.contains_key("/home/alice/notes/b.md"));
        assert!(!c.names.contains_key("/home/alice/docs"));
        assert!(c.freed.is_empty());
        // An existing file is replaced, or skipped; its old content is freed when replaced.
        assert!(
            !c.rename(
                &alice(),
                "/home/alice/a.txt",
                "/home/alice/notes/b.md",
                false
            )
            .unwrap()
        );
        assert!(
            c.rename(
                &alice(),
                "/home/alice/a.txt",
                "/home/alice/notes/b.md",
                true
            )
            .unwrap()
        );
        assert_eq!(c.at("/home/alice/notes/b.md").file.as_deref(), Some("a"));
        assert_eq!(c.freed, ["b"]);
        for (src, dst) in [
            ("/home/alice/notes", "/home/alice/notes/inner"),
            ("/home/alice/notes", "/home/alice/private"),
            ("/home/alice/notes/b.md", "/home/alice/notes/b.md"),
        ] {
            assert!(
                c.rename(&alice(), src, dst, true).is_err(),
                "{src} -> {dst}"
            );
        }
        // Moving needs w+x on both parents.
        assert!(
            c.rename(&alice(), "/home/alice/notes/b.md", "/home/b.md", true)
                .is_err()
        );
        assert!(
            c.rename(
                &Identity::guest(),
                "/home/alice/notes/b.md",
                "/home/alice/b.md",
                true
            )
            .is_err()
        );
    }
    fn bob() -> Identity {
        Identity {
            id: 1001,
            group: 1001,
            groups: BTreeSet::from([1001]),
        }
    }
    #[test]
    fn symbolic_links_resolve_as_the_kernel_resolves_them() {
        let mut c = home();
        c.symlink(&alice(), "docs", "/home/alice/rel", false)
            .unwrap();
        c.symlink(&alice(), "/home/alice/docs/b.md", "/home/alice/abs", false)
            .unwrap();
        c.symlink(&alice(), "missing", "/home/alice/dangling", false)
            .unwrap();
        c.symlink(&alice(), "loop", "/home/alice/loop", false)
            .unwrap();
        let link = c.at("/home/alice/rel");
        assert_eq!((link.mode, link.owner, link.size), (0o777, 1000, 4));
        let resolved = |path: &str, follow| c.physical(&alice(), path, follow);
        assert_eq!(
            resolved("/home/alice/rel/b.md", false).unwrap(),
            "/home/alice/docs/b.md"
        );
        assert_eq!(
            resolved("/home/alice/rel", false).unwrap(),
            "/home/alice/rel"
        );
        assert_eq!(
            resolved("/home/alice/rel", true).unwrap(),
            "/home/alice/docs"
        );
        assert_eq!(
            resolved("/home/alice/abs", true).unwrap(),
            "/home/alice/docs/b.md"
        );
        // A missing target is where a file would be made.
        assert_eq!(
            resolved("/home/alice/dangling", true).unwrap(),
            "/home/alice/missing"
        );
        assert!(
            resolved("/home/alice/loop", true)
                .unwrap_err()
                .contains("Too many levels")
        );
        // A link into a directory one may not search leads nowhere one may go.
        c.symlink(
            &bob(),
            "/home/alice/private/c.txt",
            "/home/alice/docs/peek",
            false,
        )
        .unwrap_err();
        let mut docs = c.at("/home/alice/docs");
        docs.mode = 0o777;
        c.set_node("/home/alice/docs", &docs);
        c.symlink(
            &bob(),
            "/home/alice/private/c.txt",
            "/home/alice/docs/peek",
            false,
        )
        .unwrap();
        let real = c.physical(&bob(), "/home/alice/docs/peek", true).unwrap();
        assert_eq!(
            c.access(&bob(), &real, READ).unwrap_err(),
            "Permission denied: cannot traverse /home/alice/private"
        );
        // Removing a link leaves what it points to.
        c.remove(&alice(), "/home/alice/rel", false).unwrap();
        assert!(c.names.contains_key("/home/alice/docs/b.md"));
    }
    #[test]
    fn a_home_not_made_yet_is_its_accounts_to_make() {
        let mut c = store();
        c.set_node("/guest", &Node::directory(0, 0, 0o1777));
        c.set_user(
            "alice",
            &User {
                id: 1000,
                group: 1000,
                groups: BTreeSet::new(),
                home: "/guest/alice".into(),
                locked: false,
                salt: String::new(),
                hash: String::new(),
            },
        );
        // /guest is anyone's to write in, but not to take another's home in.
        for made in [
            c.mkdir(&bob(), "/guest/alice", false),
            c.symlink(&bob(), "/tmp", "/guest/alice", false),
        ] {
            assert!(made.unwrap_err().contains("another account's home"));
        }
        c.mkdir(&bob(), "/guest/bob-notes", false).unwrap();
        assert!(
            c.rename(&bob(), "/guest/bob-notes", "/guest/alice", false)
                .is_err()
        );
        c.mkdir(&alice(), "/guest/alice", false).unwrap();
        assert_eq!(c.node("/guest/alice").unwrap().owner, 1000);
    }
    #[test]
    fn links_in_a_sticky_directory_others_may_write_are_followed_only_by_their_owners() {
        let mut c = store();
        c.set_node("/tmp", &Node::directory(0, 0, 0o1777));
        c.set_node("/tmp/target", &file(1000, 0o644, "t"));
        c.symlink(&bob(), "/tmp/target", "/tmp/trap", false)
            .unwrap();
        assert!(
            c.physical(&alice(), "/tmp/trap", true)
                .unwrap_err()
                .contains("another account's link")
        );
        assert_eq!(
            c.physical(&bob(), "/tmp/trap", true).unwrap(),
            "/tmp/target"
        );
        // rm in a sticky directory: the owner, the directory's owner, or root.
        assert!(
            c.remove(&alice(), "/tmp/trap", false)
                .unwrap_err()
                .starts_with("Operation not permitted")
        );
        assert!(c.rename(&alice(), "/tmp/trap", "/tmp/mine", true).is_err());
        c.remove(&bob(), "/tmp/trap", false).unwrap();
        c.remove(&Identity::root(), "/tmp/target", false).unwrap();
    }
    #[test]
    fn hard_links_share_one_inode() {
        let mut c = home();
        c.link(
            &alice(),
            "/home/alice/a.txt",
            "/home/alice/docs/a-too.txt",
            false,
        )
        .unwrap();
        let (one, two) = (
            c.at("/home/alice/a.txt"),
            c.at("/home/alice/docs/a-too.txt"),
        );
        assert_eq!((one.ino, one.links, two.links), (two.ino, 2, 2));
        // A change through one name shows through the other.
        c.chmod(&alice(), "/home/alice/docs/a-too.txt", "600", false)
            .unwrap();
        assert_eq!(c.at("/home/alice/a.txt").mode, 0o600);
        // The content stays until its last name goes.
        c.remove(&alice(), "/home/alice/a.txt", false).unwrap();
        assert!(c.freed.is_empty());
        assert_eq!(c.at("/home/alice/docs/a-too.txt").links, 1);
        c.remove(&alice(), "/home/alice/docs/a-too.txt", false)
            .unwrap();
        assert_eq!(c.freed, ["a"]);
        assert!(
            c.link(&alice(), "/home/alice/docs", "/home/alice/docs2", false)
                .unwrap_err()
                .contains("not allowed for directory")
        );
        // Others may link only a regular file they may read and write (protected_hardlinks).
        let mut c = home();
        c.set_node("/tmp", &Node::directory(0, 0, 0o1777));
        c.set_node("/tmp/shared.txt", &file(1000, 0o644, "s"));
        assert!(
            c.link(&bob(), "/tmp/shared.txt", "/tmp/held", false)
                .unwrap_err()
                .contains("Operation not permitted")
        );
        c.set_node("/tmp/open.txt", &file(1000, 0o666, "o"));
        c.link(&bob(), "/tmp/open.txt", "/tmp/held", false).unwrap();
        // Directories count themselves, their entry and their subdirectories.
        assert_eq!(c.at("/home/alice").links, 4);
    }
    #[test]
    fn special_bits_show_and_change_as_chmod_and_ls_say() {
        assert_eq!(type_mode_text(0o4755, '-'), "-rwsr-xr-x");
        assert_eq!(type_mode_text(0o2640, '-'), "-rw-r-S---");
        assert_eq!(type_mode_text(0o1777, 'd'), "drwxrwxrwt");
        assert_eq!(type_mode_text(0o1776, 'd'), "drwxrwxrwT");
        assert_eq!(type_mode_text(0o777, 'l'), "lrwxrwxrwx");
        assert_eq!(change_mode(0o755, "u+s", false).unwrap(), 0o4755);
        assert_eq!(change_mode(0o755, "g+s,+t", true).unwrap(), 0o3755);
        assert_eq!(change_mode(0o3755, "g-s,o-t", true).unwrap(), 0o755);
        assert_eq!(change_mode(0o755, "1777", true).unwrap(), 0o1777);
        // A directory keeps setgid through a short numeric mode; five digits clear it.
        assert_eq!(change_mode(0o2775, "755", true).unwrap(), 0o2755);
        assert_eq!(change_mode(0o2775, "00755", true).unwrap(), 0o755);
        assert_eq!(change_mode(0o2775, "755", false).unwrap(), 0o755);
        // Without root, setgid needs the file's group to be one's own.
        let mut c = store();
        c.set_node("/f", &Node::file(1000, 50, 0o644, "f".into(), 1));
        c.chmod(&alice(), "/f", "g+s", false).unwrap();
        assert_eq!(c.at("/f").mode, 0o644);
        c.chmod(&Identity::root(), "/f", "4755", false).unwrap();
        c.chown(&Identity::root(), "/f", Some(1001), None, false)
            .unwrap();
        assert_eq!(c.at("/f").mode, 0o755);
    }
    #[test]
    fn setgid_directories_and_default_acls_pass_on_to_what_is_made_in_them() {
        let mut c = store();
        let mut team = Node::directory(0, 2000, 0o2775);
        team.default_acl = Some(Entries {
            user: 7,
            group: 7,
            other: 0,
            mask: Some(7),
            users: BTreeMap::from([(1001, 7)]),
            groups: BTreeMap::new(),
        });
        c.set_node("/team", &team);
        let mut alice = alice();
        alice.groups.insert(2000);
        let mut made = c.at("/team");
        made.mode |= 0o002;
        c.set_node("/team", &made);
        c.mkdir(&alice, "/team/sub", false).unwrap();
        let sub = c.at("/team/sub");
        assert_eq!((sub.group, sub.mode & SETGID != 0), (2000, true));
        assert_eq!(sub.default_acl, made.default_acl);
        // No umask with a default ACL: rwx for bob, others nothing.
        assert_eq!(sub.mode & 0o777, 0o770);
        assert!(bob().allows(&sub, READ | WRITE | EXEC));
        let file = created(&alice, &sub, 0o666, false, UMASK);
        assert_eq!((file.mode, file.group), (0o660, 2000));
        assert_eq!(file.acl.as_ref().unwrap().users[&1001], 7);
        // bob's entry is rwx, but the mask, the group bits, says rw.
        assert!(bob().allows(&file, READ | WRITE) && !bob().allows(&file, EXEC));
    }
    #[test]
    fn acls_grant_named_users_and_groups_within_the_mask() {
        let mut node = Node::file(1000, 1000, 0o640, "f".into(), 1);
        let mut entries = node.entries();
        entries.users.insert(1001, 6);
        entries.groups.insert(3000, 4);
        entries.recalculate_mask();
        node.set_entries(&entries);
        assert_eq!(node.mode, 0o660);
        assert!(bob().allows(&node, READ | WRITE));
        let carol = Identity {
            id: 1002,
            group: 1002,
            groups: BTreeSet::from([1002, 3000]),
        };
        assert!(carol.allows(&node, READ) && !carol.allows(&node, WRITE));
        // A matching group entry that does not allow denies, whatever others may.
        node.mode |= 0o004;
        let in_owning = Identity {
            id: 1003,
            group: 1000,
            groups: BTreeSet::from([1000]),
        };
        assert!(!in_owning.allows(&node, WRITE));
        node.mode = (node.mode & !0o070) | 0o040;
        assert!(!bob().allows(&node, WRITE));
    }
    #[test]
    fn ln_f_replaces_only_once_the_link_can_be_made() {
        let mut c = home();
        c.set_node("/home/alice/docs/old.md", &file(1000, 0o644, "old"));
        // A directory cannot be hard-linked: what was there stays.
        assert!(
            c.link(
                &alice(),
                "/home/alice/docs",
                "/home/alice/docs/old.md",
                true
            )
            .unwrap_err()
            .contains("not allowed for directory")
        );
        assert_eq!(c.at("/home/alice/docs/old.md").file.as_deref(), Some("old"));
        // Nor may one link another's file one may not write (protected_hardlinks).
        let mut open = c.at("/home/alice/docs");
        open.mode = 0o777;
        c.set_node("/home/alice/docs", &open);
        c.set_node("/home/alice/docs/bobs.md", &file(1001, 0o644, "bobs"));
        assert!(
            c.link(
                &bob(),
                "/home/alice/a.txt",
                "/home/alice/docs/bobs.md",
                true
            )
            .is_err()
        );
        assert_eq!(
            c.at("/home/alice/docs/bobs.md").file.as_deref(),
            Some("bobs")
        );
        // Without -f, nothing is replaced; with it, the name now shows the other file.
        assert!(
            c.symlink(&alice(), "b.md", "/home/alice/docs/old.md", false)
                .unwrap_err()
                .contains("File exists")
        );
        c.symlink(&alice(), "b.md", "/home/alice/docs/old.md", true)
            .unwrap();
        assert_eq!(
            c.at("/home/alice/docs/old.md").link.as_deref(),
            Some("b.md")
        );
        assert!(c.freed.contains(&"old".to_string()));
        assert!(
            c.link(
                &alice(),
                "/home/alice/docs/b.md",
                "/home/alice/docs/b.md",
                true
            )
            .unwrap_err()
            .contains("same file")
        );
    }
    #[test]
    fn ids_and_accounts() {
        let mut c = store();
        assert_eq!(c.next_id(Id::User), 1000);
        assert_eq!(c.next_id(Id::User), 1001);
        assert_eq!(c.next_id(Id::Group), 1000);
        let mut alice = c.user("root").unwrap();
        alice.id = 1000;
        c.set_user("alice", &alice);
        c.delete_user("alice");
        c.set_user("ally", &alice);
        assert_eq!(c.user_by_id(1000).unwrap().0, "ally");
        assert_eq!(c.username(GUEST), "guest");
        assert_eq!(c.groupname(27), "wheel");
        assert_eq!(c.groupname(4242), "4242");
    }
}

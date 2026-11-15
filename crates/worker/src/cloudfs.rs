//! Handle protocol authority. All functions below the HTTP adapter run synchronously in
//! one SQLite transaction. Sessions, open descriptions and lock waits survive hibernation.
use crate::{
    api::{self, Reply},
    auth,
    creds::Credential,
    db::{Db, int, text},
};
use abi::{
    Errno,
    fs::*,
    remote_fs::{self as wire, Call},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use kernel::Fs;
use os_core::{
    inode,
    permissions::{self, EXEC, Node, READ, Store, WRITE},
    xattr,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Sha256;
use worker::{Method, Request, SqlStorage, State};
type Result<T> = std::result::Result<T, Errno>;

pub fn schema(sql: &SqlStorage) -> worker::Result<()> {
    for statement in [
        "CREATE TABLE IF NOT EXISTS vfs_sessions(id TEXT PRIMARY KEY, secret TEXT NOT NULL, ns TEXT NOT NULL, expires INTEGER NOT NULL)",
        "CREATE TABLE IF NOT EXISTS vfs_opens(id INTEGER PRIMARY KEY AUTOINCREMENT, session TEXT NOT NULL, ino INTEGER NOT NULL, credential TEXT NOT NULL, access TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)",
        "CREATE INDEX IF NOT EXISTS vfs_opens_inode ON vfs_opens(ino, revoked)",
        "CREATE INDEX IF NOT EXISTS vfs_opens_session ON vfs_opens(session)",
        "CREATE INDEX IF NOT EXISTS vfs_opens_credential ON vfs_opens(credential)",
        "CREATE TABLE IF NOT EXISTS vfs_calls(session TEXT NOT NULL, ticket TEXT NOT NULL, result TEXT, open INTEGER, cancelled INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(session,ticket))",
        "CREATE TABLE IF NOT EXISTS vfs_locks(ino INTEGER PRIMARY KEY, state TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS vfs_extents(file TEXT NOT NULL, start INTEGER NOT NULL, length INTEGER NOT NULL, key TEXT NOT NULL, offset INTEGER NOT NULL, source TEXT, PRIMARY KEY(file, start))",
        "CREATE INDEX IF NOT EXISTS vfs_extents_key ON vfs_extents(key)",
        "CREATE INDEX IF NOT EXISTS vfs_extents_source ON vfs_extents(source)",
        "CREATE TABLE IF NOT EXISTS vfs_uploads(id TEXT PRIMARY KEY, session TEXT NOT NULL, open INTEGER NOT NULL, credential TEXT NOT NULL, operation TEXT NOT NULL, expires INTEGER NOT NULL)",
        "CREATE TABLE IF NOT EXISTS vfs_reads(id TEXT PRIMARY KEY, file TEXT NOT NULL, session TEXT NOT NULL)",
    ] {
        sql.exec(statement, None)?;
    }
    Ok(())
}

#[derive(Deserialize)]
struct SessionRow {
    id: String,
    secret: String,
    ns: String,
    expires: u64,
}
#[derive(Deserialize)]
struct OpenRow {
    id: u64,
    session: String,
    ino: u64,
    credential: String,
    access: String,
    revoked: u8,
}
pub(super) struct Caller {
    session: SessionRow,
    credential: Credential,
    fs: FsId,
    key: String,
}

pub async fn handle(req: &mut Request, state: &State) -> worker::Result<Reply> {
    if req.path() == "/api/fs"
        && req
            .headers()
            .get("Content-Length")?
            .and_then(|v| v.parse::<u64>().ok())
            .is_none_or(|len| len > abi::BATCH_BYTES)
    {
        return Ok(api::errno_reply(&Errno::E2BIG.into()));
    }
    if req.method() != Method::Post {
        return Ok(api::errno_reply(&Errno::EINVAL.into()));
    }
    if req.path() != "/api/fs" {
        return crate::cloud_data::authority(req, state).await;
    }
    // Request::json passes through JS Number; parse text to keep off_t exact.
    let body = req.text().await?;
    let Ok(body) = serde_json::from_str::<Value>(&body) else {
        return Ok(api::errno_reply(&Errno::EINVAL.into()));
    };
    if body.get("version").and_then(Value::as_u64) != Some(u64::from(wire::VERSION)) {
        return Ok(api::errno_reply(&Errno::EPROTONOSUPPORT.into()));
    }
    let Ok(request) = serde_json::from_value::<wire::Request>(body) else {
        return Ok(api::errno_reply(&Errno::EINVAL.into()));
    };
    let ns = Db::namespace(
        auth::token_key(req).as_deref(),
        auth::guest_key(req).as_deref(),
    );
    // Expiry cleanup has its own committed transaction, including when the ensuing call fails.
    crate::db::transact(state, |db| {
        db.sweep_cloud();
        ((), true)
    })?;
    api::run(state, move |db| {
        let result = dispatch(db, &request, &ns);
        let conversion = matches!(
            &request.call,
            Call::TryLock {
                family: LockFamily::Flock,
                ..
            }
        ) && result == Err(Errno::EAGAIN);
        let mut reply = reply(result);
        if conversion {
            reply.commit = true;
        }
        reply
    })
}
pub(super) fn reply(result: Result<Value>) -> Reply {
    match result {
        Ok(value) => Reply::ok(value),
        Err(errno) => api::errno_reply(&errno.into()),
    }
}
fn identity(db: &mut Db) -> (FsId, String) {
    let mut get = |name: &str| {
        db.meta(name).unwrap_or_else(|| {
            let value = auth::random_token();
            db.set_meta(name, &value);
            value
        })
    };
    (FsId(get("vfs_id")), get("vfs_handle_key"))
}
pub(super) fn caller(db: &mut Db, session: &wire::Session, token: &str) -> Result<Caller> {
    let row = db
        .rows::<SessionRow>(
            "SELECT id, secret, ns, expires FROM vfs_sessions WHERE id = ?",
            vec![text(&session.id)],
        )
        .pop()
        .ok_or(Errno::ENOTCONN)?;
    if row.secret != auth::token_hash(&session.secret) {
        return Err(Errno::EACCES);
    }
    if row.expires <= auth::now() {
        return Err(Errno::ENOTCONN);
    }
    let credential = db.credential(token, &row.ns).ok_or(Errno::EACCES)?;
    credential.cloud().map_err(|_| Errno::EACCES)?;
    let (fs, key) = identity(db);
    Ok(Caller {
        session: row,
        credential,
        fs,
        key,
    })
}
impl Caller {
    pub(super) fn io(
        &self,
        token: &str,
        write: bool,
        bytes: u64,
    ) -> Option<crate::resources::IoRequest> {
        self.credential
            .job()
            .is_none()
            .then(|| crate::resources::IoRequest {
                ns: self.credential.ns.clone(),
                token: token.into(),
                pid: Some(self.credential.pid),
                write,
                bytes,
            })
    }
    fn proof(&self, node: NodeId) -> Hmac<Sha256> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.key.as_bytes())
            .expect("HMAC accepts every key size");
        mac.update(
            &serde_json::to_vec(&(&self.fs, &self.session.id, node)).expect("serializable handle"),
        );
        mac
    }
    fn handle(&self, ino: u64) -> Handle {
        let node = NodeId { ino, generation: 1 };
        Handle {
            fs: self.fs.clone(),
            node,
            proof: URL_SAFE_NO_PAD.encode(self.proof(node).finalize().into_bytes()),
        }
    }
    fn node(&self, db: &Db, handle: &Handle) -> Result<Node> {
        let tag = URL_SAFE_NO_PAD
            .decode(&handle.proof)
            .map_err(|_| Errno::EACCES)?;
        if handle.fs != self.fs || self.proof(handle.node).verify_slice(&tag).is_err() {
            return Err(Errno::EACCES);
        }
        if handle.node.generation != 1 {
            return Err(Errno::ESTALE);
        }
        db.inode(handle.node.ino).ok_or(Errno::ESTALE)
    }
    fn dir(&self, db: &Db, handle: &Handle, mask: u16) -> Result<(Node, String)> {
        let node = self.node(db, handle)?;
        if !node.directory {
            return Err(Errno::ENOTDIR);
        }
        let path = db.names(node.ino).pop().ok_or(Errno::ENOENT)?;
        inode::require(&self.credential.identity(), &node, mask)?;
        Ok((node, path))
    }
    fn child(&self, db: &Db, dir: &Handle, name: &str) -> Result<(Node, String)> {
        check_component(name)?;
        let (_, path) = self.dir(db, dir, EXEC)?;
        let path = join(&path, name);
        Ok((db.persisted_node(&path).ok_or(Errno::ENOENT)?, path))
    }
    fn entry(&self, db: &Db, node: &Node) -> Entry {
        Entry {
            handle: self.handle(node.ino),
            metadata: metadata(db, node),
        }
    }
    fn open(
        &self,
        db: &mut Db,
        mut node: Node,
        options: &OpenOptions,
        created: bool,
    ) -> Result<OpenRef> {
        let access = options.access()?;
        if !created {
            inode::may_open(&self.credential.identity(), &node, access.mask())?;
        }
        if access != Access::Path && options.is_truncate() {
            if node.directory {
                return Err(Errno::EISDIR);
            }
            inode::require(
                &self.credential.identity(),
                &node,
                if created { 0 } else { WRITE },
            )?;
            if node.is_file() {
                db.cloud_truncate(&mut node, 0, &self.credential)?;
            }
        }
        #[derive(Deserialize)]
        struct Id {
            id: u64,
        }
        let id = db.rows::<Id>("INSERT INTO vfs_opens(session, ino, credential, access) VALUES(?, ?, ?, ?) RETURNING id", vec![text(&self.session.id), int(node.ino), text(&self.credential.token), text(&serde_json::to_string(&access).map_err(|_| Errno::EIO)?)]).pop().ok_or(Errno::EIO)?.id;
        Ok(OpenRef {
            fs: self.fs.clone(),
            id,
            node: NodeId {
                ino: node.ino,
                generation: 1,
            },
            access,
        })
    }
    pub(super) fn opened(&self, db: &Db, open: &OpenRef) -> Result<(Node, Credential)> {
        let row = db
            .rows::<OpenRow>("SELECT * FROM vfs_opens WHERE id = ?", vec![int(open.id)])
            .pop()
            .ok_or(Errno::EBADF)?;
        if row.session != self.session.id || open.fs != self.fs {
            return Err(Errno::EACCES);
        }
        if row.revoked != 0 {
            return Err(Errno::EACCES);
        }
        let credential = db
            .credential_of(&row.credential, &self.session.ns)
            .ok_or(Errno::EACCES)?;
        credential.cloud().map_err(|_| Errno::EACCES)?;
        if row.ino != open.node.ino
            || open.node.generation != 1
            || row.access != serde_json::to_string(&open.access).map_err(|_| Errno::EIO)?
        {
            return Err(Errno::EACCES);
        }
        Ok((db.inode(row.ino).ok_or(Errno::ESTALE)?, credential))
    }
}
fn join(dir: &str, name: &str) -> String {
    format!("{}/{name}", dir.trim_end_matches('/'))
}
fn metadata(db: &Db, node: &Node) -> Metadata {
    let times = db.times(node.ino);
    let file_type = if node.directory {
        FileType::Dir
    } else if node.is_link() {
        FileType::Symlink
    } else if node.rdev.is_some() {
        FileType::CharDevice
    } else {
        FileType::File
    };
    let nlink = if node.directory && node.links != 0 {
        2 + db.names(node.ino).first().map_or(0, |path| {
            db.children(path)
                .iter()
                .filter(|(_, n)| n.directory)
                .count() as u32
        })
    } else {
        node.links
    };
    Metadata {
        file_type,
        mode: node.mode,
        nlink,
        uid: node.owner,
        gid: node.group,
        size: node.size,
        atime: times.atime.into(),
        mtime: times.mtime.into(),
        ctime: times.ctime.into(),
        rdev: node.rdev.clone(),
        acl: node.acl.is_some(),
    }
}
fn make(
    db: &mut Db,
    c: &Caller,
    dir: &Handle,
    name: &str,
    node: impl FnOnce(&Node) -> Node,
) -> Result<Node> {
    check_component(name)?;
    let (parent, path) = c.dir(db, dir, EXEC)?;
    let path = join(&path, name);
    if db.persisted_node(&path).is_some() {
        return Err(Errno::EEXIST);
    }
    inode::may_create(&c.credential.identity(), &parent, false)?;
    db.set_node(&path, &node(&parent));
    db.persisted_node(&path).ok_or(Errno::EIO)
}
fn dispatch(db: &mut Db, request: &wire::Request, ns: &str) -> Result<Value> {
    if request.version != wire::VERSION {
        return Err(Errno::EPROTONOSUPPORT);
    }
    if matches!(request.call, Call::Connect) {
        if request.session.is_some() {
            return Err(Errno::EINVAL);
        }
        let credential = db
            .credential(&request.credential, ns)
            .ok_or(Errno::EACCES)?;
        credential.cloud().map_err(|_| Errno::EACCES)?;
        let session = wire::Session {
            id: auth::random_token(),
            secret: auth::random_token(),
        };
        let expires = auth::now() + wire::LEASE_SECONDS;
        db.run(
            "INSERT INTO vfs_sessions(id, secret, ns, expires) VALUES(?, ?, ?, ?)",
            vec![
                text(&session.id),
                text(&auth::token_hash(&session.secret)),
                text(&credential.ns),
                int(expires),
            ],
        );
        db.set_expiry("vfs_session", &session.id, expires);
        let c = caller(db, &session, &request.credential)?;
        let root = db.persisted_node("/").ok_or(Errno::EIO)?;
        return Ok(json!(wire::Connected {
            version: wire::VERSION,
            session,
            root: c.handle(root.ino),
            capabilities: os_vfs::profiles::CLOUD,
            lease_seconds: wire::LEASE_SECONDS
        }));
    }
    let c = caller(
        db,
        request.session.as_ref().ok_or(Errno::EACCES)?,
        &request.credential,
    )?;
    let who = c.credential.identity();
    use Call::*;
    let ticket = match &request.call {
        Create { ticket, .. } | Open { ticket, .. } => Some(ticket),
        _ => None,
    };
    if let Some(ticket) = ticket {
        if ticket.is_empty() || ticket.len() > 128 {
            return Err(Errno::EINVAL);
        }
        #[derive(Deserialize)]
        struct Prior {
            result: Option<String>,
            cancelled: u8,
        }
        if let Some(prior) = db
            .rows::<Prior>(
                "SELECT result,cancelled FROM vfs_calls WHERE session = ? AND ticket = ?",
                vec![text(&c.session.id), text(ticket)],
            )
            .pop()
        {
            if prior.cancelled != 0 {
                return Err(Errno::ECANCELED);
            }
            let value: Value =
                serde_json::from_str(&prior.result.ok_or(Errno::EIO)?).map_err(|_| Errno::EIO)?;
            let open: OpenRef = serde_json::from_value(if value.is_array() {
                value[1].clone()
            } else {
                value.clone()
            })
            .map_err(|_| Errno::EIO)?;
            c.opened(db, &open)?;
            return Ok(value);
        }
    }
    let result = match &request.call {
        Connect => unreachable!(),
        Renew => {
            let expires = auth::now() + wire::LEASE_SECONDS;
            db.run(
                "UPDATE vfs_sessions SET expires = ? WHERE id = ?",
                vec![int(expires), text(&c.session.id)],
            );
            db.set_expiry("vfs_session", &c.session.id, expires);
            db.run("UPDATE expiries SET due = ? WHERE kind = 'vfs_read' AND id IN (SELECT id FROM vfs_reads WHERE session = ?)",vec![int(expires),text(&c.session.id)]);
            json!(wire::LEASE_SECONDS)
        }
        Disconnect => {
            db.end_cloud_session(&c.session.id);
            Value::Null
        }
        Lookup { dir, name } => {
            let (node, _) = c.child(db, dir, name)?;
            json!(c.entry(db, &node))
        }
        Walk { dir, names } => {
            if names.len() > 1024 {
                return Err(Errno::E2BIG);
            }
            for name in names {
                check_component(name)?;
            }
            c.node(db, dir)?;
            let mut at = dir.clone();
            let mut out = Walked {
                entries: Vec::new(),
                stop: None,
            };
            for (index, name) in names.iter().enumerate() {
                let node = match c.child(db, &at, name) {
                    Ok((node, _)) => node,
                    Err(Errno::ENOENT) => {
                        out.stop = Some(Stop::Missing(index));
                        break;
                    }
                    Err(e) => return Err(e),
                };
                let entry = c.entry(db, &node);
                at = entry.handle.clone();
                out.entries.push(entry);
                if node.is_link() {
                    out.stop = Some(Stop::Symlink(index));
                    break;
                }
                if !node.directory && index + 1 < names.len() {
                    out.stop = Some(Stop::NotDirectory(index));
                    break;
                }
            }
            json!(out)
        }
        Parent { dir } => {
            let (_, path) = c.dir(db, dir, 0)?;
            if path == "/" {
                Value::Null
            } else {
                let (parent, name) = path.rsplit_once('/').ok_or(Errno::EIO)?;
                let parent = db
                    .persisted_node(if parent.is_empty() { "/" } else { parent })
                    .ok_or(Errno::ENOENT)?;
                json!((c.entry(db, &parent), name))
            }
        }
        Metadata { handle } => json!(metadata(db, &c.node(db, handle)?)),
        ReadDir { dir } => {
            let (_, path) = c.dir(db, dir, READ)?;
            let entries: Vec<_> = db
                .subtree(&path)
                .into_iter()
                .filter(|(p, _)| os_core::parent(p) == path && p != &path)
                .map(|(p, n)| DirEntry {
                    name: p.rsplit('/').next().unwrap_or("").into(),
                    node: NodeId {
                        ino: n.ino,
                        generation: 1,
                    },
                    file_type: metadata(db, &n).file_type,
                })
                .collect();
            db.cloud_accessed(dir.node.ino);
            json!(entries)
        }
        ReadLink { handle } => {
            let node = c.node(db, handle)?;
            let target = node.link.ok_or(Errno::EINVAL)?;
            db.cloud_accessed(node.ino);
            json!(target)
        }
        Create {
            dir,
            name,
            mode,
            options,
            ..
        } => {
            options.access()?;
            let node = match c.child(db, dir, name) {
                Ok((node, _)) => {
                    if options.is_create_new() {
                        return Err(Errno::EEXIST);
                    }
                    if node.directory {
                        return Err(Errno::EISDIR);
                    }
                    let open = c.open(db, node.clone(), options, false)?;
                    return remember(
                        db,
                        &c,
                        ticket,
                        json!((c.entry(db, &db.inode(node.ino).ok_or(Errno::EIO)?), open)),
                    );
                }
                Err(Errno::ENOENT) => make(db, &c, dir, name, |p| {
                    permissions::created(&who, p, *mode, false, c.credential.umask)
                })?,
                Err(e) => return Err(e),
            };
            let mut node = node;
            node.file = Some(db.empty(c.credential.uid, ""));
            db.update_inode(&node);
            let open = c.open(db, node.clone(), options, true)?;
            json!((c.entry(db, &node), open))
        }
        Mkdir { dir, name, mode } => {
            let node = make(db, &c, dir, name, |p| {
                permissions::created(&who, p, *mode, true, c.credential.umask)
            })?;
            json!(c.entry(db, &node))
        }
        Mknod {
            dir,
            name,
            mode,
            rdev,
        } => {
            if who.id != 0 {
                return Err(Errno::EPERM);
            }
            if rdev.is_empty() || rdev.len() > 255 {
                return Err(Errno::EINVAL);
            }
            let node = make(db, &c, dir, name, |p| {
                let mut n = permissions::created(&who, p, *mode, false, c.credential.umask);
                n.rdev = Some(rdev.clone());
                n
            })?;
            json!(c.entry(db, &node))
        }
        Symlink { dir, name, target } => {
            inode::check_link_target(target)?;
            let node = make(db, &c, dir, name, |p| inode::new_symlink(&who, p, target))?;
            json!(c.entry(db, &node))
        }
        Link { target, dir, name } => {
            let node = c.node(db, target)?;
            inode::may_link(&who, &node)?;
            if node.links == 0 {
                return Err(Errno::ENOENT);
            }
            let node = make(db, &c, dir, name, |_| node)?;
            json!(c.entry(db, &node))
        }
        Unlink { dir, name } | Rmdir { dir, name } => {
            let (node, path) = c.child(db, dir, name)?;
            let (parent, _) = c.dir(db, dir, 0)?;
            inode::may_delete(&who, &parent, &node)?;
            let directory = matches!(&request.call, Rmdir { .. });
            if node.directory != directory {
                return Err(if directory {
                    Errno::ENOTDIR
                } else {
                    Errno::EISDIR
                });
            }
            if directory && db.persisted_descendant(&path) {
                return Err(Errno::ENOTEMPTY);
            }
            db.set_times(node.ino, None, None);
            db.delete_node(&path);
            Value::Null
        }
        Rename {
            from_dir,
            from,
            to_dir,
            to,
            flags,
        } => {
            rename(db, &c, from_dir, from, to_dir, to, *flags)?;
            Value::Null
        }
        Setattr { handle, attr } => {
            let mut node = c.node(db, handle)?;
            if *attr == SetAttr::default() {
                return Ok(json!(metadata(db, &node)));
            }
            if let Some(mode) = attr.mode {
                inode::chmod(&who, &mut node, mode)?;
            }
            inode::chown(&who, &mut node, attr.uid, attr.gid)?;
            inode::may_set_times(&who, &node, attr.atime, attr.mtime)?;
            if let Some(size) = attr.size {
                inode::require(&who, &node, WRITE)?;
                db.cloud_truncate(&mut node, size, &c.credential)?;
            }
            db.update_inode(&node);
            if attr.atime != abi::Time::Omit || attr.mtime != abi::Time::Omit {
                db.set_times(
                    node.ino,
                    inode::time(attr.atime, auth::clock()),
                    inode::time(attr.mtime, auth::clock()),
                );
            }
            json!(metadata(db, &node))
        }
        Getxattr { handle, name } => {
            let node = c.node(db, handle)?;
            let space = xattr::space(name)?;
            xattr::readable(&who, &node, space)?;
            let value = if matches!(space, xattr::Space::Access | xattr::Space::Default) {
                serde_json::to_vec(&xattr::acl(&node, space)?).map_err(|_| Errno::EIO)?
            } else {
                db.xattrs(node.ino).remove(name).ok_or(Errno::ENODATA)?
            };
            json!(value)
        }
        Listxattr { handle } => {
            let node = c.node(db, handle)?;
            json!(xattr::listed(&who, &node, db.xattrs(node.ino).keys()))
        }
        Setxattr {
            handle,
            name,
            value,
            flags,
        } => {
            let mut node = c.node(db, handle)?;
            let space = xattr::space(name)?;
            xattr::settable(&who, &node, space)?;
            if matches!(space, xattr::Space::Access | xattr::Space::Default) {
                xattr::check_flags(flags.bits(), xattr::has_acl(&node, space))?;
                let entries = serde_json::from_slice(value).map_err(|_| Errno::EINVAL)?;
                xattr::set_acl(&who, &mut node, space, entries)?;
                db.update_inode(&node);
            } else {
                let mut attrs = db.xattrs(node.ino);
                xattr::check_flags(flags.bits(), attrs.contains_key(name))?;
                xattr::store(&mut attrs, name, value)?;
                db.set_xattrs(node.ino, &attrs);
                db.update_inode(&node);
            }
            Value::Null
        }
        Removexattr { handle, name } => {
            let mut node = c.node(db, handle)?;
            let space = xattr::space(name)?;
            xattr::settable(&who, &node, space)?;
            if matches!(space, xattr::Space::Access | xattr::Space::Default) {
                xattr::remove_acl(&mut node, space)?;
            } else {
                let mut attrs = db.xattrs(node.ino);
                attrs.remove(name).ok_or(Errno::ENODATA)?;
                db.set_xattrs(node.ino, &attrs);
            }
            db.update_inode(&node);
            Value::Null
        }
        Statfs => {
            let (bytes, files) = db.usage();
            json!(StatFs {
                block_size: 4096,
                blocks: bytes.div_ceil(4096),
                files,
                name_max: abi::NAME_MAX as u64,
                ..StatFs::default()
            })
        }
        Open {
            handle, options, ..
        } => {
            let node = c.node(db, handle)?;
            json!(c.open(db, node, options, false)?)
        }
        CancelOpen { ticket } => {
            #[derive(Deserialize)]
            struct Id {
                open: Option<u64>,
            }
            if let Some(id) = db
                .rows::<Id>(
                    "SELECT open FROM vfs_calls WHERE session = ? AND ticket = ?",
                    vec![text(&c.session.id), text(ticket)],
                )
                .pop()
                .and_then(|r| r.open)
            {
                db.release_cloud_open(id, false);
            }
            db.run("INSERT INTO vfs_calls(session,ticket,cancelled) VALUES(?,?,1) ON CONFLICT(session,ticket) DO UPDATE SET cancelled=1, result=NULL, open=NULL",vec![text(&c.session.id),text(ticket)]);
            Value::Null
        }
        SetLen { open, size } => {
            let (mut node, cred) = c.opened(db, open)?;
            if !open.access.writes() {
                return Err(Errno::EINVAL);
            }
            db.cloud_truncate(&mut node, *size, &cred)?;
            Value::Null
        }
        Sync { open, .. } => {
            c.opened(db, open)?;
            if open.access == Access::Path {
                return Err(Errno::EBADF);
            }
            Value::Null
        }
        Release { open } => {
            c.opened(db, open)?;
            db.release_cloud_open(open.id, false);
            Value::Null
        }
        TryLock { .. }
        | Lock { .. }
        | AckLock { .. }
        | CancelLock { .. }
        | Unlock { .. }
        | TestLock { .. } => locks(db, &c, &request.call)?,
    };
    remember(db, &c, ticket, result)
}
fn remember(db: &mut Db, c: &Caller, ticket: Option<&String>, result: Value) -> Result<Value> {
    if let Some(ticket) = ticket {
        let open = if result.is_array() {
            result[1]["id"].as_u64()
        } else {
            result["id"].as_u64()
        }
        .ok_or(Errno::EIO)?;
        db.run(
            "INSERT INTO vfs_calls(session,ticket,result,open) VALUES(?,?,?,?)",
            vec![
                text(&c.session.id),
                text(ticket),
                text(&result.to_string()),
                int(open),
            ],
        );
    }
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
fn rename(
    db: &mut Db,
    c: &Caller,
    from_dir: &Handle,
    from: &str,
    to_dir: &Handle,
    to: &str,
    flags: RenameFlags,
) -> Result<()> {
    if flags.bits() & !RenameFlags::NOREPLACE.bits() != 0 {
        return Err(Errno::EINVAL);
    }
    check_component(to)?;
    let (source, old) = c.child(db, from_dir, from)?;
    let (parent, _) = c.dir(db, from_dir, 0)?;
    let (dest_parent, dest) = c.dir(db, to_dir, EXEC)?;
    let new = join(&dest, to);
    let who = c.credential.identity();
    inode::may_delete(&who, &parent, &source)?;
    inode::may_create(&who, &dest_parent, false)?;
    if let Some(target) = db.persisted_node(&new) {
        if flags.contains(RenameFlags::NOREPLACE) {
            return Err(Errno::EEXIST);
        }
        if target.ino == source.ino {
            return Ok(());
        }
        inode::may_delete(&who, &dest_parent, &target)?;
        if source.directory != target.directory {
            return Err(if source.directory {
                Errno::ENOTDIR
            } else {
                Errno::EISDIR
            });
        }
        if target.directory && db.persisted_descendant(&new) {
            return Err(Errno::ENOTEMPTY);
        }
    }
    if source.directory && (dest == old || dest.starts_with(&format!("{old}/"))) {
        return Err(Errno::EINVAL);
    }
    if let Some(target) = db.persisted_node(&new) {
        db.set_times(target.ino, None, None);
    }
    db.move_names(&old, &new);
    db.set_times(source.ino, None, None);
    Ok(())
}

impl Db {
    pub(crate) fn cloud_pinned(&self, ino: u64) -> bool {
        !self
            .rows::<Value>(
                "SELECT id FROM vfs_opens WHERE ino = ? AND revoked = 0 LIMIT 1",
                vec![int(ino)],
            )
            .is_empty()
    }
    pub(crate) fn cloud_accessed(&mut self, ino: u64) {
        let times = self.times(ino);
        let now = auth::clock();
        if times.atime <= times.mtime
            || times.atime <= times.ctime
            || now.0.saturating_sub(times.atime.0) >= 86400
        {
            self.run(
                "UPDATE inodes SET atime = ?, atime_ns = ? WHERE id = ?",
                vec![int(now.0), int(now.1), int(ino)],
            );
        }
    }
    pub(crate) fn release_cloud_open(&mut self, id: u64, revoked: bool) {
        let rows = self.rows::<OpenRow>("SELECT * FROM vfs_opens WHERE id = ?", vec![int(id)]);
        for row in rows {
            if revoked {
                self.run(
                    "UPDATE vfs_opens SET revoked = 1 WHERE id = ?",
                    vec![int(id)],
                );
            } else {
                self.run("DELETE FROM vfs_opens WHERE id = ?", vec![int(id)]);
            }
            self.cloud_unlock_owner(row.ino, id);
            self.forget(row.ino);
        }
    }
    pub(crate) fn revoke_cloud_opens(&mut self, hash: &str) {
        let rows = self.rows::<OpenRow>(
            "SELECT * FROM vfs_opens WHERE credential = ? AND revoked = 0",
            vec![text(hash)],
        );
        for row in rows {
            self.release_cloud_open(row.id, true);
        }
    }
    pub(crate) fn end_cloud_session(&mut self, id: &str) {
        #[derive(Deserialize)]
        struct ReadId {
            id: String,
        }
        for read in
            self.rows::<ReadId>("SELECT id FROM vfs_reads WHERE session = ?", vec![text(id)])
        {
            self.end_cloud_read(&read.id);
        }
        let rows =
            self.rows::<OpenRow>("SELECT * FROM vfs_opens WHERE session = ?", vec![text(id)]);
        for row in rows {
            self.release_cloud_open(row.id, false);
        }
        self.run("DELETE FROM vfs_calls WHERE session = ?", vec![text(id)]);
        self.run("DELETE FROM vfs_sessions WHERE id = ?", vec![text(id)]);
        self.clear_expiry("vfs_session", id);
    }
    pub(crate) fn sweep_cloud(&mut self) {
        let rows = self.rows::<SessionRow>(
            "SELECT * FROM vfs_sessions WHERE expires <= ?",
            vec![int(auth::now())],
        );
        for row in rows {
            self.end_cloud_session(&row.id);
        }
        let rows=self.rows::<OpenRow>("SELECT o.* FROM vfs_opens o LEFT JOIN credentials c ON c.token = o.credential WHERE o.revoked = 0 AND (c.token IS NULL OR c.expires <= ? OR c.cloud_access = 0)",vec![int(auth::now())]);
        for row in rows {
            self.release_cloud_open(row.id, true);
        }
    }
}

use os_vfs::locks::{self as advisory, Held, Locks};
fn locks(db: &mut Db, c: &Caller, call: &Call) -> Result<Value> {
    use Call::*;
    let (open, family, range, kind) = match call {
        TryLock {
            open,
            family,
            range,
            kind,
        }
        | Lock {
            open,
            family,
            range,
            kind,
            ..
        } => (open, *family, *range, Some(*kind)),
        Unlock {
            open,
            family,
            range,
        } => (open, *family, *range, None),
        TestLock { open, range, .. } => (open, LockFamily::Posix, *range, None),
        AckLock { open, .. } | CancelLock { open, .. } => {
            (open, LockFamily::Posix, LockRange::WHOLE, None)
        }
        _ => return Err(Errno::EINVAL),
    };
    let (node, _) = c.opened(db, open)?;
    advisory::validate(open.access, family, kind, range)?;
    let mut state = db.cloud_locks(node.ino);
    let out = match call {
        TryLock { kind, .. } | Lock { kind, .. } => {
            let ticket = if let Lock { ticket, .. } = call {
                Some(ticket.as_str())
            } else {
                None
            };
            let all = db
                .rows::<LockRow>("SELECT state FROM vfs_locks", vec![])
                .into_iter()
                .map(|r| serde_json::from_str(&r.state).map_err(|_| Errno::EIO))
                .collect::<Result<Vec<Locks>>>()?;
            let acquired = state.acquire(
                Held {
                    owner: open.id,
                    family,
                    kind: *kind,
                    range,
                    ticket: None,
                },
                ticket,
                &all,
            );
            db.save_cloud_locks(node.ino, &state);
            let granted = acquired?;
            if ticket.is_some() {
                json!(granted)
            } else {
                Value::Null
            }
        }
        Unlock { .. } => {
            state.carve(open.id, family, range);
            state.wake();
            Value::Null
        }
        AckLock { ticket, .. } => {
            state.acknowledge(open.id, ticket);
            Value::Null
        }
        CancelLock { ticket, .. } => {
            state.cancel(open.id, ticket);
            Value::Null
        }
        TestLock { kind, .. } => json!(state.conflict(&Held {
            owner: open.id,
            family,
            kind: *kind,
            range,
            ticket: None
        })),
        _ => return Err(Errno::EINVAL),
    };
    db.save_cloud_locks(node.ino, &state);
    Ok(out)
}
#[derive(Deserialize)]
struct LockRow {
    state: String,
}
impl Db {
    fn cloud_locks(&self, ino: u64) -> Locks {
        self.rows::<LockRow>("SELECT state FROM vfs_locks WHERE ino = ?", vec![int(ino)])
            .pop()
            .map(|r| serde_json::from_str(&r.state).expect("stored locks"))
            .unwrap_or_default()
    }
    fn save_cloud_locks(&mut self, ino: u64, state: &Locks) {
        if state.held.is_empty() && state.waits.is_empty() && state.cancelled.is_empty() {
            self.run("DELETE FROM vfs_locks WHERE ino = ?", vec![int(ino)]);
        } else {
            self.run("INSERT INTO vfs_locks(ino,state) VALUES(?,?) ON CONFLICT(ino) DO UPDATE SET state=excluded.state",vec![int(ino),text(&json!(state).to_string())]);
        }
    }
    fn cloud_unlock_owner(&mut self, ino: u64, owner: u64) {
        let mut state = self.cloud_locks(ino);
        state.release(owner);
        self.save_cloud_locks(ino, &state);
    }
}

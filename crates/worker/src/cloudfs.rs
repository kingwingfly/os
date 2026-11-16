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
        "CREATE TABLE IF NOT EXISTS vfs_opens(id INTEGER PRIMARY KEY AUTOINCREMENT, session TEXT NOT NULL, ino INTEGER NOT NULL, access TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)",
        "CREATE INDEX IF NOT EXISTS vfs_opens_inode ON vfs_opens(ino, revoked)",
        "CREATE INDEX IF NOT EXISTS vfs_opens_session ON vfs_opens(session)",
        "CREATE TABLE IF NOT EXISTS vfs_open_grants(open INTEGER NOT NULL, credential TEXT NOT NULL, PRIMARY KEY(open, credential))",
        "CREATE INDEX IF NOT EXISTS vfs_open_grants_credential ON vfs_open_grants(credential)",
        "CREATE TABLE IF NOT EXISTS vfs_calls(session TEXT NOT NULL, ticket TEXT NOT NULL, credential TEXT, request TEXT, result TEXT, open INTEGER, cancelled INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(session,ticket))",
        "CREATE TABLE IF NOT EXISTS vfs_locks(ino INTEGER PRIMARY KEY, state TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS vfs_lock_cancels(open INTEGER NOT NULL, ticket TEXT NOT NULL, PRIMARY KEY(open, ticket))",
        "CREATE TABLE IF NOT EXISTS vfs_extents(file TEXT NOT NULL, start INTEGER NOT NULL, length INTEGER NOT NULL, key TEXT NOT NULL, offset INTEGER NOT NULL, source TEXT, PRIMARY KEY(file, start))",
        "CREATE INDEX IF NOT EXISTS vfs_extents_key ON vfs_extents(key)",
        "CREATE INDEX IF NOT EXISTS vfs_extents_source ON vfs_extents(source)",
        "CREATE TABLE IF NOT EXISTS vfs_uploads(id TEXT PRIMARY KEY, session TEXT NOT NULL, open INTEGER NOT NULL, credential TEXT NOT NULL, operation TEXT NOT NULL, expires INTEGER NOT NULL)",
        "CREATE TABLE IF NOT EXISTS vfs_reads(id TEXT PRIMARY KEY, file TEXT NOT NULL, session TEXT NOT NULL)",
    ] {
        sql.exec(statement, None)?;
    }
    // The filesystem's identity exists before any call reports it: v1 stat's `dev` and the
    // v2 handles' `fs` must agree from the first request.
    sql.exec(
        &format!(
            "INSERT OR IGNORE INTO meta(k, v) VALUES('{FS_ID_KEY}', lower(hex(randomblob(32))))"
        ),
        None,
    )?;
    Ok(())
}
/// The `meta` key of the cloud tree's filesystem id (contract §2.5).
pub const FS_ID_KEY: &str = "vfs_id";

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
            (&request.call, &result),
            (
                Call::TryLock {
                    family: LockFamily::Flock,
                    ..
                },
                Err(Errno::EAGAIN),
            ) | (
                Call::Lock {
                    family: LockFamily::Flock,
                    ..
                },
                Err(Errno::ENOSPC),
            )
        );
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
    (FsId(get(FS_ID_KEY)), get("vfs_handle_key"))
}
fn authorize(credential: &Credential) -> Result<()> {
    credential.cloud().map_err(|_| Errno::EACCES)?;
    // Jobs have recorded path grants enforced by executor::authorize. Until the handle
    // protocol can enforce those same restrictions, they must use the scoped job API.
    if credential.job().is_some() {
        return Err(Errno::EACCES);
    }
    Ok(())
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
    authorize(&credential)?;
    // The caller's system generation decides which paths its image owns (read-only), as it
    // does on the path API.
    crate::system::select(db, credential.generation.as_deref()).map_err(|e| e.errno)?;
    let (fs, key) = identity(db);
    Ok(Caller {
        session: row,
        credential,
        fs,
        key,
    })
}
impl Caller {
    /// The presenting credential decides metadata effects of an authorized operation.
    pub(super) fn actor(&self) -> &Credential {
        &self.credential
    }
    pub(super) fn io(
        &self,
        token: &str,
        pid: Option<u32>,
        write: bool,
        bytes: u64,
    ) -> Result<crate::resources::IoRequest> {
        Ok(crate::resources::IoRequest {
            ns: self.credential.ns.clone(),
            token: token.into(),
            pid: Some(pid.ok_or(Errno::EINVAL)?),
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
        // Permission before removal, as MemFs and Linux order them (EACCES, then ENOENT).
        inode::require(&self.credential.identity(), &node, mask)?;
        let path = db.names(node.ino).pop().ok_or(Errno::ENOENT)?;
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
        if !created && access != Access::Path {
            let mut mask = access.mask();
            if options.is_truncate() {
                mask |= WRITE;
            }
            inode::may_open(&self.credential.identity(), &node, mask)?;
            if access.writes() || options.is_truncate() {
                unchanged_names(db, node.ino)?;
            }
            if node.file.as_deref().is_some_and(|id| db.uploading(id)) {
                return Err(Errno::EBUSY);
            }
            if options.is_truncate() && node.is_file() {
                db.cloud_truncate(&mut node, 0, &self.credential)?;
            }
        }
        #[derive(Deserialize)]
        struct Id {
            id: u64,
        }
        let id = db
            .rows::<Id>(
                "INSERT INTO vfs_opens(session, ino, access) VALUES(?, ?, ?) RETURNING id",
                vec![
                    text(&self.session.id),
                    int(node.ino),
                    text(&serde_json::to_string(&access).map_err(|_| Errno::EIO)?),
                ],
            )
            .pop()
            .ok_or(Errno::EIO)?
            .id;
        db.run(
            "INSERT INTO vfs_open_grants(open, credential) VALUES(?, ?)",
            vec![int(id), text(&self.credential.token)],
        );
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
    fn open_row(&self, db: &Db, open: &OpenRef) -> Result<OpenRow> {
        let row = db
            .rows::<OpenRow>("SELECT * FROM vfs_opens WHERE id = ?", vec![int(open.id)])
            .pop()
            .ok_or(Errno::EBADF)?;
        if row.session != self.session.id || open.fs != self.fs {
            return Err(Errno::EACCES);
        }
        if row.ino != open.node.ino
            || open.node.generation != 1
            || row.access != serde_json::to_string(&open.access).map_err(|_| Errno::EIO)?
        {
            return Err(Errno::EACCES);
        }
        Ok(row)
    }
    pub(super) fn opened(&self, db: &Db, open: &OpenRef) -> Result<Node> {
        let row = self.open_row(db, open)?;
        if row.revoked != 0 || !db.cloud_granted(open.id, &self.session.ns) {
            return Err(Errno::EACCES);
        }
        db.inode(row.ino).ok_or(Errno::ESTALE)
    }
}
fn join(dir: &str, name: &str) -> String {
    format!("{}/{name}", dir.trim_end_matches('/'))
}
/// Paths the path API refuses to change (`EROFS`): the caller's system image's, /proc's, and
/// the kernel-generated account projections (/etc/passwd, /etc/group). Their persisted
/// placeholders are not writable content, and names made under an image path would block
/// later activations (`system::validate_mount`).
fn read_only(db: &Db, path: &str) -> bool {
    crate::system::owns(db, path)
        || crate::procfs::is(path)
        || matches!(path, "/etc/passwd" | "/etc/group")
}
fn read_only_descendant(db: &Db, path: &str) -> bool {
    let prefix = format!("{}/", path.trim_end_matches('/'));
    crate::system::owns_descendant(db, path)
        || ["/etc/passwd", "/etc/group", "/proc"]
            .iter()
            .any(|ro| ro.starts_with(&prefix))
}
/// `EROFS` if any name of `ino` is read-only.
pub(super) fn unchanged_names(db: &Db, ino: u64) -> Result<()> {
    if db.names(ino).iter().any(|path| read_only(db, path)) {
        return Err(Errno::EROFS);
    }
    Ok(())
}
/// The longest request ticket; a longer or empty one never named a request.
const TICKET_MAX: usize = 128;
fn ticket_valid(ticket: &str) -> bool {
    !ticket.is_empty() && ticket.len() <= TICKET_MAX
}
fn metadata(db: &Db, node: &Node) -> Metadata {
    let times = db.times(node.ino);
    let nlink = if node.directory && node.links != 0 {
        2 + db
            .names(node.ino)
            .first()
            .map_or(0, |path| db.persisted_subdirs(path))
    } else {
        node.links
    };
    let size = if node.is_file() {
        db.names(node.ino)
            .iter()
            .find_map(|path| crate::sys::generated(db, path))
            .map_or(node.size, |text| text.len() as u64)
    } else {
        node.size
    };
    Metadata {
        file_type: file_type(node),
        mode: node.mode,
        nlink,
        uid: node.owner,
        gid: node.group,
        size,
        atime: times.atime.into(),
        mtime: times.mtime.into(),
        ctime: times.ctime.into(),
        rdev: node.rdev.clone(),
        acl: node.acl.is_some(),
    }
}
fn file_type(node: &Node) -> FileType {
    if node.directory {
        FileType::Dir
    } else if node.is_link() {
        FileType::Symlink
    } else if node.rdev.is_some() {
        FileType::CharDevice
    } else {
        FileType::File
    }
}
fn check_home(db: &Db, uid: u32, path: &str) -> Result<()> {
    // An absent home belongs to its account (or root), even in a writable parent.
    if uid != 0 && db.home_of(path).is_some_and(|owner| owner != uid) {
        return Err(Errno::EACCES);
    }
    Ok(())
}
fn new_name(db: &Db, c: &Caller, dir: &Handle, name: &str) -> Result<(Node, String)> {
    check_component(name)?;
    let (parent, path) = c.dir(db, dir, EXEC)?;
    let path = join(&path, name);
    if read_only(db, &path) {
        return Err(Errno::EROFS);
    }
    if db.persisted_node(&path).is_some() {
        return Err(Errno::EEXIST);
    }
    inode::may_create(&c.credential.identity(), &parent, false)?;
    check_home(db, c.credential.uid, &path)?;
    Ok((parent, path))
}
fn make(
    db: &mut Db,
    c: &Caller,
    dir: &Handle,
    name: &str,
    node: impl FnOnce(&Node) -> Node,
) -> Result<Node> {
    let (parent, path) = new_name(db, c, dir, name)?;
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
        authorize(&credential)?;
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
        if !ticket_valid(ticket) {
            return Err(Errno::EINVAL);
        }
        #[derive(Deserialize)]
        struct Prior {
            request: Option<String>,
            result: Option<String>,
            cancelled: u8,
        }
        if let Some(prior) = db
            .rows::<Prior>(
                "SELECT request,result,cancelled FROM vfs_calls WHERE session = ? AND ticket = ?",
                vec![text(&c.session.id), text(ticket)],
            )
            .pop()
        {
            if prior.cancelled != 0 {
                return Err(Errno::ECANCELED);
            }
            let expected = serde_json::to_string(&request.call).map_err(|_| Errno::EIO)?;
            if prior.request.as_deref() != Some(expected.as_str()) {
                return Err(Errno::EINVAL);
            }
            let value: Value =
                serde_json::from_str(&prior.result.ok_or(Errno::EIO)?).map_err(|_| Errno::EIO)?;
            let open: OpenRef = serde_json::from_value(if value.is_array() {
                value[1].clone()
            } else {
                value.clone()
            })
            .map_err(|_| Errno::EIO)?;
            if !db.cloud_caller_granted(open.id, &c.credential.token) {
                return Err(Errno::EACCES);
            }
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
            db.run(
                "UPDATE vfs_uploads SET expires = ? WHERE session = ?",
                vec![int(expires), text(&c.session.id)],
            );
            db.run("UPDATE expiries SET due = ? WHERE kind = 'vfs_upload' AND id IN (SELECT id FROM vfs_uploads WHERE session = ?)",vec![int(expires),text(&c.session.id)]);
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
                if index + 1 < names.len() {
                    if node.is_link() {
                        out.stop = Some(Stop::Symlink(index));
                        break;
                    }
                    if !node.directory {
                        out.stop = Some(Stop::NotDirectory(index));
                        break;
                    }
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
        OpenMetadata { open } => json!(metadata(db, &c.opened(db, open)?)),
        ReadDir { dir } => {
            let (_, path) = c.dir(db, dir, READ)?;
            #[derive(Deserialize)]
            struct Child {
                path: String,
                ino: u64,
                file_type: FileType,
            }
            // Only names, identities and types are needed: avoid loading descendants or
            // computing their metadata/link counts inside this synchronous transaction.
            let entries: Vec<_> = db
                .rows::<Child>(
                    "SELECT n.path,i.id AS ino,CASE WHEN i.directory = 1 THEN 'dir' WHEN i.link IS NOT NULL THEN 'symlink' WHEN i.rdev IS NOT NULL THEN 'char-device' ELSE 'file' END AS file_type FROM nodes n JOIN inodes i ON i.id = n.ino WHERE n.parent = ? AND n.path != ? ORDER BY n.path",
                    vec![text(&path), text(&path)],
                )
                .into_iter()
                .map(|child| DirEntry {
                    name: child.path.rsplit('/').next().unwrap_or("").into(),
                    node: NodeId {
                        ino: child.ino,
                        generation: 1,
                    },
                    file_type: child.file_type,
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
            umask,
            options,
            ..
        } => {
            if matches!(options.access()?, Access::Exec | Access::Path) {
                return Err(Errno::EINVAL);
            }
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
                        &request.call,
                        json!((c.entry(db, &db.inode(node.ino).ok_or(Errno::EIO)?), open)),
                    );
                }
                Err(Errno::ENOENT) => make(db, &c, dir, name, |p| {
                    permissions::created(&who, p, *mode, false, *umask)
                })?,
                Err(e) => return Err(e),
            };
            let mut node = node;
            node.file = Some(db.empty(c.credential.uid, ""));
            db.update_inode(&node);
            let open = c.open(db, node.clone(), options, true)?;
            json!((c.entry(db, &node), open))
        }
        Mkdir {
            dir,
            name,
            mode,
            umask,
        } => {
            let node = make(db, &c, dir, name, |p| {
                permissions::created(&who, p, *mode, true, *umask)
            })?;
            json!(c.entry(db, &node))
        }
        Mknod {
            dir,
            name,
            mode,
            umask,
            rdev,
        } => {
            if who.id != 0 {
                return Err(Errno::EPERM);
            }
            if rdev.is_empty() || rdev.len() > 255 {
                return Err(Errno::EINVAL);
            }
            if !matches!(rdev.as_str(), "present" | "snd") {
                return Err(Errno::EOPNOTSUPP);
            }
            let (_, path) = new_name(db, &c, dir, name)?;
            // The driver creates its inode, live state and expiry together. Unlike the
            // path driver's replace operation, VFS mknod requires an unused name.
            crate::dev::mknod(
                db,
                &kernel::Process {
                    cred: who.clone(),
                    umask: *umask,
                },
                &path,
                *mode,
                rdev,
            )
            .map_err(|error| error.errno)?;
            let node = db.persisted_node(&path).ok_or(Errno::EIO)?;
            json!(c.entry(db, &node))
        }
        Symlink { dir, name, target } => {
            inode::check_link_target(target)?;
            let node = make(db, &c, dir, name, |p| inode::new_symlink(&who, p, target))?;
            json!(c.entry(db, &node))
        }
        Link { target, dir, name } => {
            let node = c.node(db, target)?;
            c.node(db, dir)?;
            check_component(name)?;
            let (parent, parent_path) = c.dir(db, dir, EXEC)?;
            let path = join(&parent_path, name);
            if read_only(db, &path) {
                return Err(Errno::EROFS);
            }
            if db.persisted_node(&path).is_some() {
                return Err(Errno::EEXIST);
            }
            // These drivers identify devices by pathname and cannot serve an alias.
            if node.is_device() {
                return Err(Errno::EPERM);
            }
            inode::may_link(&who, &node)?;
            unchanged_names(db, node.ino)?;
            if node.file.as_deref().is_some_and(|id| db.uploading(id)) {
                return Err(Errno::EBUSY);
            }
            inode::may_create(&who, &parent, false)?;
            check_home(db, c.credential.uid, &path)?;
            if node.links == 0 {
                return Err(Errno::ENOENT);
            }
            db.set_node(&path, &node);
            let node = db.persisted_node(&path).ok_or(Errno::EIO)?;
            json!(c.entry(db, &node))
        }
        Unlink { dir, name } | Rmdir { dir, name } => {
            let (node, path) = c.child(db, dir, name)?;
            if read_only(db, &path) {
                return Err(Errno::EROFS);
            }
            // Device drivers own removal permissions and teardown, including their open
            // descriptors, voices, pending requests and disappearance notifications.
            if matches!(&request.call, Unlink { .. })
                && let Some(done) = db.unlink_device(&who, &path)
            {
                return done.map(|()| Value::Null).map_err(|error| error.errno);
            }
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
            if node.is_device() {
                return Err(Errno::EPERM);
            }
            if directory && matches!(path.as_str(), "/dev" | "/dev/present" | "/dev/snd") {
                return Err(Errno::EBUSY);
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
            let original = c.node(db, handle)?;
            if *attr == SetAttr::default() {
                return Ok(json!(metadata(db, &original)));
            }
            let mut node = original.clone();
            if let Some(mode) = attr.mode {
                inode::chmod(&who, &mut node, mode)?;
            }
            inode::chown(&who, &mut node, attr.uid, attr.gid)?;
            inode::may_set_times(&who, &original, attr.atime, attr.mtime)?;
            if let Some(size) = attr.size {
                if original.directory {
                    return Err(Errno::EISDIR);
                }
                if !original.is_file() {
                    return Err(Errno::EINVAL);
                }
                inode::require(&who, &original, WRITE)?;
                if size > FILE_MAX {
                    return Err(Errno::EFBIG);
                }
            }
            unchanged_names(db, original.ino)?;
            let now = auth::clock();
            if let Some(size) = attr.size {
                db.cloud_truncate_at(&mut node, size, &c.credential, now)?;
            } else {
                db.update_inode_at(&node, now);
            }
            if attr.atime != abi::Time::Omit || attr.mtime != abi::Time::Omit {
                db.set_times_at(
                    node.ino,
                    inode::time(attr.atime, now),
                    inode::time(attr.mtime, now),
                    now,
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
            unchanged_names(db, node.ino)?;
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
            unchanged_names(db, node.ino)?;
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
            // No create/open accepted such a ticket: there is nothing to cancel or record.
            if !ticket_valid(ticket) {
                return Ok(Value::Null);
            }
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
                let allowed = c.credential.uid == 0
                    || db.cloud_caller_granted(id, &c.credential.token)
                    || !db.cloud_granted(id, &c.session.ns);
                if !allowed {
                    return Err(Errno::EACCES);
                }
                db.release_cloud_open(id, false);
            }
            db.run("INSERT INTO vfs_calls(session,ticket,cancelled) VALUES(?,?,1) ON CONFLICT(session,ticket) DO UPDATE SET cancelled=1, credential=NULL, request=NULL, result=NULL, open=NULL",vec![text(&c.session.id),text(ticket)]);
            Value::Null
        }
        SetLen { open, size } => {
            let mut node = c.opened(db, open)?;
            if open.access == Access::Path {
                return Err(Errno::EBADF);
            }
            if !open.access.writes() || !node.is_file() {
                return Err(Errno::EINVAL);
            }
            unchanged_names(db, node.ino)?;
            db.cloud_truncate(&mut node, *size, c.actor())?;
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
            // Cleanup can retire a revoked tombstone; it never renews the open's grant.
            c.open_row(db, open)?;
            db.release_cloud_open(open.id, false);
            Value::Null
        }
        wire::Call::Clone { .. } => return Err(Errno::ENOSYS),
        TryLock { .. }
        | Lock { .. }
        | AckLock { .. }
        | CancelLock { .. }
        | Unlock { .. }
        | TestLock { .. } => locks(db, &c, &request.call)?,
    };
    remember(db, &c, ticket, &request.call, result)
}
fn remember(
    db: &mut Db,
    c: &Caller,
    ticket: Option<&String>,
    call: &Call,
    result: Value,
) -> Result<Value> {
    if let Some(ticket) = ticket {
        let open = if result.is_array() {
            result[1]["id"].as_u64()
        } else {
            result["id"].as_u64()
        }
        .ok_or(Errno::EIO)?;
        let request = serde_json::to_string(call).map_err(|_| Errno::EIO)?;
        db.run(
            "INSERT INTO vfs_calls(session,ticket,credential,request,result,open) VALUES(?,?,?,?,?,?)",
            vec![
                text(&c.session.id),
                text(ticket),
                text(&c.credential.token),
                text(&request),
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
    c.node(db, from_dir)?;
    c.node(db, to_dir)?;
    let (source, old) = c.child(db, from_dir, from)?;
    check_component(to)?;
    let (dest_parent, dest) = c.dir(db, to_dir, EXEC)?;
    let new = join(&dest, to);
    let existing = db.persisted_node(&new);
    if existing.is_some() && flags.contains(RenameFlags::NOREPLACE) {
        return Err(Errno::EEXIST);
    }
    if existing.as_ref().is_some_and(|t| t.ino == source.ino) {
        return Ok(());
    }
    if source.directory && (dest == old || dest.starts_with(&format!("{old}/"))) {
        return Err(Errno::EINVAL);
    }
    // A driver knows its device by name; rename cannot move or replace it without teardown.
    if source.is_device() || existing.as_ref().is_some_and(Node::is_device) {
        return Err(Errno::EPERM);
    }
    if read_only(db, &old)
        || read_only(db, &new)
        || (source.directory && read_only_descendant(db, &old))
        || read_only_descendant(db, &new)
    {
        return Err(Errno::EROFS);
    }
    let (parent, _) = c.dir(db, from_dir, 0)?;
    let who = c.credential.identity();
    inode::may_delete(&who, &parent, &source)?;
    match &existing {
        Some(target) => {
            inode::may_delete(&who, &dest_parent, target)?;
            if source.directory != target.directory {
                return Err(if source.directory {
                    Errno::ENOTDIR
                } else {
                    Errno::EISDIR
                });
            }
        }
        None => {
            inode::may_create(&who, &dest_parent, false)?;
            check_home(db, c.credential.uid, &new)?;
        }
    }
    if source.directory && parent.ino != dest_parent.ino {
        inode::require(&who, &source, WRITE)?;
    }
    if let Some(target) = &existing
        && target.directory
        && db.persisted_descendant(&new)
    {
        return Err(Errno::ENOTEMPTY);
    }
    if source.directory
        && (matches!(old.as_str(), "/dev" | "/dev/present" | "/dev/snd")
            || !db
                .rows::<Value>(
                    "SELECT 1 FROM nodes n JOIN inodes i ON i.id = n.ino WHERE (n.path = ? OR instr(n.path, ?) = 1) AND i.rdev IS NOT NULL LIMIT 1",
                    vec![text(&old), text(&format!("{old}/"))],
                )
                .is_empty())
    {
        return Err(Errno::EPERM);
    }
    // Only usermod moves a registered home and updates the account's path. Match a whole
    // path component, including homes not created yet.
    if source.directory
        && !db
            .rows::<Value>(
                "SELECT 1 FROM users WHERE home = ? OR instr(home, ?) = 1 LIMIT 1",
                vec![text(&old), text(&format!("{old}/"))],
            )
            .is_empty()
    {
        return Err(Errno::EBUSY);
    }
    if let Some(target) = &existing {
        db.set_times(target.ino, None, None);
    }
    db.move_names(&old, &new);
    db.set_times(source.ino, None, None);
    Ok(())
}

impl Db {
    fn cloud_caller_granted(&self, open: u64, credential: &str) -> bool {
        !self
            .rows::<Value>(
                "SELECT 1 FROM vfs_open_grants g JOIN credentials c ON c.token = g.credential WHERE g.open = ? AND g.credential = ? AND c.expires > ? AND c.cloud_access != 0 LIMIT 1",
                vec![int(open), text(credential), int(auth::now())],
            )
            .is_empty()
    }
    fn cloud_granted(&self, open: u64, ns: &str) -> bool {
        !self.rows::<Value>(
            "SELECT 1 FROM vfs_open_grants g JOIN credentials c ON c.token = g.credential WHERE g.open = ? AND c.ns = ? AND c.expires > ? AND c.cloud_access != 0 LIMIT 1",
            vec![int(open), text(ns), int(auth::now())],
        ).is_empty()
    }
    /// Exec inherits existing grants without transferring them away from a fork still
    /// holding the old token. A revoked/expired token cannot acquire a successor grant.
    pub(crate) fn inherit_cloud_opens(&mut self, ns: &str, old: &str, new: &str) {
        self.run(
            "INSERT OR IGNORE INTO vfs_open_grants(open, credential) SELECT g.open, successor.token FROM vfs_open_grants g JOIN vfs_opens o ON o.id = g.open JOIN credentials prior ON prior.token = g.credential JOIN credentials successor ON successor.token = ? WHERE g.credential = ? AND o.revoked = 0 AND prior.ns = ? AND successor.ns = prior.ns AND successor.owner = prior.owner AND prior.expires > ? AND successor.expires > ? AND prior.cloud_access != 0 AND successor.cloud_access != 0",
            vec![text(new), text(old), text(ns), int(auth::now()), int(auth::now())],
        );
    }
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
        #[derive(Deserialize)]
        struct UploadId {
            id: String,
        }
        for upload in
            self.rows::<UploadId>("SELECT id FROM vfs_uploads WHERE open = ?", vec![int(id)])
        {
            self.expire_cloud_upload(&upload.id);
        }
        let rows = self.rows::<OpenRow>("SELECT * FROM vfs_opens WHERE id = ?", vec![int(id)]);
        for row in rows {
            self.run(
                "DELETE FROM vfs_open_grants WHERE open = ?",
                vec![int(row.id)],
            );
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
            "SELECT o.* FROM vfs_opens o JOIN vfs_open_grants g ON g.open = o.id WHERE g.credential = ? AND o.revoked = 0",
            vec![text(hash)],
        );
        self.run(
            "DELETE FROM vfs_open_grants WHERE credential = ?",
            vec![text(hash)],
        );
        for row in rows {
            let ns = self
                .rows::<SessionRow>(
                    "SELECT * FROM vfs_sessions WHERE id = ?",
                    vec![text(&row.session)],
                )
                .pop();
            if ns.is_none_or(|s| !self.cloud_granted(row.id, &s.ns)) {
                self.release_cloud_open(row.id, true);
            }
        }
    }
    pub(crate) fn end_cloud_session(&mut self, id: &str) {
        #[derive(Deserialize)]
        struct RowId {
            id: String,
        }
        for read in self.rows::<RowId>("SELECT id FROM vfs_reads WHERE session = ?", vec![text(id)])
        {
            self.end_cloud_read(&read.id);
        }
        for upload in self.rows::<RowId>(
            "SELECT id FROM vfs_uploads WHERE session = ?",
            vec![text(id)],
        ) {
            self.expire_cloud_upload(&upload.id);
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
        self.run("DELETE FROM vfs_open_grants WHERE credential NOT IN (SELECT token FROM credentials WHERE expires > ? AND cloud_access != 0)", vec![int(auth::now())]);
        let rows = self.rows::<OpenRow>("SELECT o.* FROM vfs_opens o WHERE o.revoked = 0 AND NOT EXISTS (SELECT 1 FROM vfs_open_grants g WHERE g.open = o.id)", vec![]);
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
    // A ticket no lock request could carry named nothing to cancel.
    if let CancelLock { ticket, .. } = call
        && !ticket_valid(ticket)
    {
        return Ok(Value::Null);
    }
    if matches!(call, CancelLock { .. }) && c.open_row(db, open)?.revoked != 0 {
        return Ok(Value::Null);
    }
    let node = c.opened(db, open)?;
    advisory::validate(open.access, family, kind, range)?;
    let mut state = db.cloud_locks(node.ino);
    let out = match call {
        TryLock { kind, .. } | Lock { kind, .. } => {
            let ticket = if let Lock { ticket, .. } = call {
                Some(ticket.as_str())
            } else {
                None
            };
            if let Some(t) = ticket
                && ticket_valid(t)
                && db.cloud_lock_cancelled(open.id, t)
            {
                return Err(Errno::ECANCELED);
            }
            // Only a new blocking POSIX request can queue and so close a wait cycle; polling
            // an existing wait, try-locks and flock never look at other inodes. This inode's
            // own table is `state`, not its stored copy.
            let polling = ticket.is_some_and(|t| {
                state
                    .waits
                    .iter()
                    .any(|w| w.lock.owner == open.id && w.ticket == t)
            });
            let all = if ticket.is_some() && family == LockFamily::Posix && !polling {
                db.rows::<LockRow>(
                    "SELECT state FROM vfs_locks WHERE ino != ?",
                    vec![int(node.ino)],
                )
                .into_iter()
                .map(|r| serde_json::from_str(&r.state).map_err(|_| Errno::EIO))
                .collect::<Result<Vec<Locks>>>()?
            } else {
                Vec::new()
            };
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
            let granted = match acquired {
                Ok(granted) => granted,
                Err(e) => {
                    db.save_cloud_locks(node.ino, &mut state);
                    return Err(e);
                }
            };
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
    db.save_cloud_locks(node.ino, &mut state);
    Ok(out)
}
#[derive(Deserialize)]
struct LockRow {
    state: String,
}
impl Db {
    fn cloud_lock_cancelled(&self, open: u64, ticket: &str) -> bool {
        !self
            .rows::<Value>(
                "SELECT 1 FROM vfs_lock_cancels WHERE open = ? AND ticket = ? LIMIT 1",
                vec![int(open), text(ticket)],
            )
            .is_empty()
    }
    fn cloud_locks(&self, ino: u64) -> Locks {
        self.rows::<LockRow>("SELECT state FROM vfs_locks WHERE ino = ?", vec![int(ino)])
            .pop()
            .map(|r| serde_json::from_str(&r.state).expect("stored locks"))
            .unwrap_or_default()
    }
    fn save_cloud_locks(&mut self, ino: u64, state: &mut Locks) {
        for (owner, ticket) in std::mem::take(&mut state.cancelled) {
            self.run(
                "INSERT OR IGNORE INTO vfs_lock_cancels(open, ticket) VALUES(?, ?)",
                vec![int(owner), text(&ticket)],
            );
        }
        if state.held.is_empty() && state.waits.is_empty() && state.displaced.is_empty() {
            self.run("DELETE FROM vfs_locks WHERE ino = ?", vec![int(ino)]);
        } else {
            self.run("INSERT INTO vfs_locks(ino,state) VALUES(?,?) ON CONFLICT(ino) DO UPDATE SET state=excluded.state",vec![int(ino),text(&json!(state).to_string())]);
        }
    }
    fn cloud_unlock_owner(&mut self, ino: u64, owner: u64) {
        self.run(
            "DELETE FROM vfs_lock_cancels WHERE open = ?",
            vec![int(owner)],
        );
        let mut state = self.cloud_locks(ino);
        state.release(owner);
        self.save_cloud_locks(ino, &mut state);
    }
}

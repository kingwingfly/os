//! Shared immutable generations. Publisher verification and operator authorization are
//! separate checks. Bulk content verification runs in the outer Worker, never in the DO.
use crate::{
    api::Reply,
    auth,
    db::{Db, int, text, transact},
};
use abi::{Errno, Error};
use os_core::permissions::Node;
use os_image::{Composition, Image, Kind, Release, Trust};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};
use worker::{Env, Method, Request, Response, State};

pub use abi::system::{CONTROL, DEVICE};
const INO: u64 = 2 << 40;
const STRIDE: u64 = 1 << 20;
const GENERATIONS_MAX: usize = 32;
type Result<T> = std::result::Result<T, Error>;
fn invalid(e: impl std::fmt::Display) -> Error {
    Error::because(Errno::EINVAL, e.to_string())
}
fn io(e: impl std::fmt::Display) -> Error {
    Error::because(Errno::EIO, e.to_string())
}

thread_local! { static TRUST: RefCell<Trust> = RefCell::new(Trust::default()); }
pub fn configure(env: &Env) -> worker::Result<()> {
    let trust = match env.var("OS_IMAGE_TRUST") {
        Ok(value) => os_image::parse(value.to_string().as_bytes())
            .map_err(|e| worker::Error::RustError(e.to_string()))?,
        Err(_) => Trust::default(),
    };
    TRUST.with(|v| *v.borrow_mut() = trust);
    Ok(())
}
pub fn schema(sql: &worker::SqlStorage) -> worker::Result<()> {
    sql.exec("CREATE TABLE IF NOT EXISTS system_releases(id TEXT PRIMARY KEY, ordinal INTEGER UNIQUE NOT NULL, package TEXT NOT NULL, state TEXT NOT NULL, ticket TEXT, expires INTEGER NOT NULL, approved INTEGER NOT NULL DEFAULT 0)", None)?;
    if sql
        .exec("SELECT pending FROM system_releases LIMIT 0", None)
        .is_err()
    {
        sql.exec("ALTER TABLE system_releases ADD COLUMN pending TEXT", None)?;
    }
    if sql
        .exec("SELECT generation FROM credentials LIMIT 0", None)
        .is_err()
    {
        sql.exec("ALTER TABLE credentials ADD COLUMN generation TEXT", None)?;
    }
    if sql
        .exec("SELECT generation FROM fds LIMIT 0", None)
        .is_err()
    {
        sql.exec("ALTER TABLE fds ADD COLUMN generation TEXT", None)?;
    }
    Ok(())
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Signed {
    bytes: String,
    signature: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Package {
    release: Signed,
    images: Vec<Signed>,
}
struct Verified {
    images: Vec<Image>,
    composition: Composition,
}
impl Package {
    fn verify(&self, id: &str) -> Result<Verified> {
        if os_image::digest(self.release.bytes.as_bytes()) != id {
            return Err(invalid("release digest mismatch"));
        }
        let release = Release::parse(self.release.bytes.as_bytes()).map_err(invalid)?;
        TRUST
            .with(|t| {
                t.borrow().verify(
                    "os.release.v1",
                    self.release.bytes.as_bytes(),
                    self.release.signature.as_bytes(),
                )
            })
            .map_err(invalid)?;
        if self.images.len() != release.images().count() {
            return Err(invalid("release image count mismatch"));
        }
        let mut images = Vec::new();
        for (id, signed) in release.images().zip(&self.images) {
            if os_image::digest(signed.bytes.as_bytes()) != id {
                return Err(invalid("image digest mismatch"));
            }
            TRUST
                .with(|t| {
                    t.borrow().verify(
                        "os.image.v1",
                        signed.bytes.as_bytes(),
                        signed.signature.as_bytes(),
                    )
                })
                .map_err(invalid)?;
            images.push(Image::parse(signed.bytes.as_bytes()).map_err(invalid)?);
        }
        for (i, image) in images.iter().enumerate() {
            let kind = match i {
                0 => Kind::Boot,
                1 => Kind::Base,
                n if n < 2 + release.sysext.len() => Kind::Sysext,
                _ => Kind::Confext,
            };
            if image.kind != kind {
                return Err(invalid("release image kind mismatch"));
            }
        }
        let composition = Composition::new(&images[1], &images[2..]).map_err(invalid)?;
        // Early boot has a fixed protocol entry point. An incomplete generation cannot
        // become the default just because a publisher signed its manifest.
        for required in [
            "/index.html",
            "/client-kernel.js",
            "/client_kernel_bg.wasm",
            "/wasi-process.js",
            "/pkg/frontend.js",
            "/pkg/frontend_bg.wasm",
        ] {
            if !images[0]
                .entries
                .iter()
                .any(|e| e.path == required && matches!(e.node, os_image::Node::File { .. }))
            {
                return Err(invalid(format!("boot resource missing: {required}")));
            }
        }
        for path in ["/usr/bin/init", "/usr/bin/supervise", "/usr/bin/sh"] {
            let resolved = composition.resolve(path).map_err(invalid)?;
            if !composition.entries.get(&resolved).is_some_and(|e| {
                e.mode & 0o111 != 0 && matches!(e.node, os_image::Node::File { .. })
            }) {
                return Err(invalid("required boot executable is missing"));
            }
        }
        Ok(Verified {
            images,
            composition,
        })
    }
}
#[derive(Deserialize)]
struct Stored {
    id: String,
    ordinal: u64,
    package: String,
    state: String,
    ticket: Option<String>,
    expires: u64,
    approved: u32,
    pending: Option<String>,
}
fn stored(db: &Db, id: &str) -> Option<Stored> {
    db.rows("SELECT id, ordinal, package, state, ticket, expires, approved, pending FROM system_releases WHERE id = ?", vec![text(id)]).pop()
}
fn verified(row: &Stored) -> Result<Verified> {
    let package: Package = os_image::parse(row.package.as_bytes()).map_err(invalid)?;
    package.verify(&row.id)
}

pub struct Mounted {
    pub id: String,
    entries: BTreeMap<String, Node>,
}
pub fn select(db: &mut Db, id: Option<&str>) -> Result<()> {
    let Some(id) = id.filter(|id| *id != "legacy") else {
        db.image = None;
        return Ok(());
    };
    if db.image.as_ref().is_some_and(|v| v.id == id) {
        return Ok(());
    }
    os_image::unhex::<32>(id).map_err(invalid)?;
    let row = stored(db, id)
        .filter(|row| row.state == "verified" && row.approved != 0)
        .ok_or(Errno::ESTALE)?;
    let view = verified(&row)?;
    let mut entries = BTreeMap::new();
    for (index, entry) in view.composition.entries.values().enumerate() {
        let node = match &entry.node {
            os_image::Node::Directory => Node::directory(entry.uid, entry.gid, entry.mode),
            os_image::Node::Symlink { target } => Node::symlink(entry.uid, entry.gid, target),
            os_image::Node::File { sha256, size } => Node::file(
                entry.uid,
                entry.gid,
                entry.mode,
                format!("image:{sha256}:{size}"),
                *size,
            ),
        };
        let mut node = Node {
            ino: INO + row.ordinal * STRIDE + index as u64,
            mode: entry.mode,
            links: 1,
            ..node
        };
        if node.directory {
            node.links = 2 + view
                .composition
                .entries
                .values()
                .filter(|e| {
                    os_image::parent(&e.path) == entry.path
                        && e.path != entry.path
                        && matches!(e.node, os_image::Node::Directory)
                })
                .count() as u32;
        }
        entries.insert(entry.path.clone(), node);
    }
    db.image = Some(Rc::new(Mounted {
        id: id.into(),
        entries,
    }));
    Ok(())
}
impl Mounted {
    pub fn node(&self, path: &str) -> Option<Node> {
        self.entries.get(path).cloned()
    }
    pub fn owns(&self, path: &str) -> bool {
        // Merge-point metadata is immutable; unclaimed children remain mutable.
        if matches!(path, "/" | "/etc" | "/opt") {
            return self.entries.contains_key(path);
        }
        self.entries.contains_key(path)
            || os_image::below(path, "/usr")
            || os_image::below(path, "/sys")
            || self.entries.iter().any(|(p, n)| {
                n.directory && p != "/" && p != "/etc" && p != "/opt" && os_image::below(path, p)
            })
    }
    pub fn children(&self, path: &str) -> Vec<(String, Node)> {
        self.entries
            .iter()
            .filter(|(p, _)| *p != path && os_image::parent(p) == path)
            .map(|(p, n)| (p.clone(), n.clone()))
            .collect()
    }
}
pub fn immutable_inode(ino: u64) -> bool {
    (INO..INO + (GENERATIONS_MAX as u64 + 1) * STRIDE).contains(&ino)
}
pub fn owns(db: &Db, path: &str) -> bool {
    db.image
        .as_ref()
        .map_or_else(|| crate::usr::is(path), |v| v.owns(path))
}
pub fn asset(content: &str) -> Option<String> {
    if let Some((hash, _)) = content
        .strip_prefix("image:")
        .and_then(|s| s.split_once(':'))
    {
        os_image::unhex::<32>(hash).ok()?;
        return Some(format!("/boot/blobs/{hash}"));
    }
    crate::usr::asset(content).map(str::to_string)
}
pub fn size(content: &str) -> u64 {
    content
        .strip_prefix("image:")
        .and_then(|s| s.split_once(':'))
        .and_then(|(_, s)| s.parse().ok())
        .unwrap_or_else(|| crate::usr::size(content))
}
pub fn authorize(db: &mut Db, session: &crate::sys::Session, fd: u32) -> Result<()> {
    let acting = session.of(db)?;
    let sid = acting.sid.ok_or(Errno::EBADF)?;
    crate::fds::yours(
        db,
        &sid,
        fd,
        acting.credential.as_ref().map(|c| c.owner()).as_deref(),
    )?;
    let device = crate::dev::request(db, &sid, fd)?.ok_or(Errno::ENOTTY)?;
    if device.node.rdev.as_deref() != Some("system") || device.flags & abi::O_PATH != 0 {
        return Err(Errno::ENOTTY.into());
    }
    if acting.process.cred.id != 0 || !device.writes() {
        return Err(Errno::EPERM.into());
    }
    Ok(())
}
async fn metadata(env: &Env, path: &str) -> Result<String> {
    let mut response = env
        .assets("ASSETS")
        .map_err(io)?
        .fetch_request(Request::new(&format!("https://assets{path}"), Method::Get).map_err(io)?)
        .await
        .map_err(io)?;
    if response.status_code() != 200 {
        return Err(Errno::ENOENT.into());
    }
    let bytes = response.bytes().await.map_err(io)?;
    if bytes.len() > os_image::MANIFEST_MAX {
        return Err(Errno::E2BIG.into());
    }
    String::from_utf8(bytes).map_err(invalid)
}
// Manifests contain filesystem names, not URL syntax. Encode each component once,
// including literal percent signs, fragments and query delimiters.
fn asset_url(path: &str) -> String {
    format!(
        "https://assets{}",
        path.split('/')
            .map(|part| {
                js_sys::encode_uri_component(part)
                    .as_string()
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>()
            .join("/")
    )
}

fn asset_path(encoded: &str) -> Result<String> {
    let mut parts = Vec::new();
    for part in encoded.split('/') {
        let decoded = js_sys::decode_uri_component(part)
            .map_err(|_| invalid("invalid asset path encoding"))?
            .as_string()
            .ok_or_else(|| invalid("invalid asset path"))?;
        if decoded.contains('/') || decoded.contains('\\') {
            return Err(invalid("encoded asset path separator"));
        }
        parts.push(decoded);
    }
    let path = parts.join("/");
    if !os_image::valid_path(&path) {
        return Err(invalid("invalid asset path"));
    }
    Ok(path)
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Content {
    path: String,
    sha256: String,
    size: u64,
    wasm: bool,
}
pub async fn stage(
    env: &Env,
    state: &State,
    session: Rc<crate::sys::Session>,
    fd: u32,
    arg: Value,
) -> Result<Value> {
    let id = arg["id"].as_str().ok_or(Errno::EINVAL)?.to_string();
    os_image::unhex::<32>(&id).map_err(invalid)?;
    let checking = session.clone();
    transact(state, move |db| (authorize(db, &checking, fd), false)).map_err(io)??;
    let release = Signed {
        bytes: metadata(env, &format!("/boot/releases/{id}/manifest.json")).await?,
        signature: metadata(env, &format!("/boot/releases/{id}/signature.json")).await?,
    };
    let parsed = Release::parse(release.bytes.as_bytes()).map_err(invalid)?;
    let mut package = Package {
        release,
        images: Vec::new(),
    };
    for hash in parsed.images() {
        package.images.push(Signed {
            bytes: metadata(env, &format!("/boot/images/{hash}.json")).await?,
            signature: metadata(env, &format!("/boot/images/{hash}.sig")).await?,
        });
    }
    let verified_package = package.verify(&id)?;
    let package = serde_json::to_string(&package).map_err(invalid)?;
    // SQLite rows and pending verification plans have a bounded deployment footprint.
    if package.len() > 1024 * 1024 {
        return Err(Errno::E2BIG.into());
    }
    let mut content = BTreeMap::new();
    for image in &verified_package.images {
        for entry in &image.entries {
            if let os_image::Node::File { sha256, size } = &entry.node {
                let path = format!("/boot/blobs/{sha256}");
                let wasm = entry.path.ends_with(".wasm")
                    || (image.kind == Kind::Base && entry.mode & 0o111 != 0);
                content.entry(path.clone()).or_insert(Content {
                    path,
                    sha256: sha256.clone(),
                    size: *size,
                    wasm,
                });
                if image.kind == Kind::Boot {
                    let path = format!("/boot/releases/{id}/assets{}", entry.path);
                    content.insert(
                        path.clone(),
                        Content {
                            path,
                            sha256: sha256.clone(),
                            size: *size,
                            wasm,
                        },
                    );
                }
            } else if image.kind == Kind::Boot
                && matches!(entry.node, os_image::Node::Symlink { .. })
            {
                return Err(invalid("boot assets cannot contain symlinks"));
            }
        }
    }
    let ticket = auth::random_token();
    transact(state, move |db| {
        let result = (|| {
            authorize(db, &session, fd)?;
            let existing = stored(db, &id);
            if let Some(row) = &existing && row.approved != 0 {
                if row.package == package && verified(row).is_ok() { return Ok(json!({"id":id,"state":row.state,"approved":true})); }
                // Key rotation re-signs the same immutable bytes. Keep the approved
                // generation readable until this replacement proof is fully checked.
                db.run("UPDATE system_releases SET pending=?,ticket=?,expires=? WHERE id=?", vec![text(&package),text(&auth::token_hash(&ticket)),int(auth::now()+600),text(&id)]);
                return Ok(json!({"_os_prepare":{"id":id,"ticket":ticket,"content":content.into_values().collect::<Vec<_>>()}}));
            }
            #[derive(Deserialize)] struct Count { n: u64 }
            let count = db.rows::<Count>("SELECT COUNT(*) AS n FROM system_releases", vec![]).pop().map_or(0, |r| r.n);
            if existing.is_none() && count >= GENERATIONS_MAX as u64 { return Err(Errno::ENOSPC.into()); }
            let ordinal = existing.map_or(count + 1, |r| r.ordinal);
            db.run("INSERT OR REPLACE INTO system_releases(id,ordinal,package,state,ticket,expires,approved) VALUES(?,?,?,'staging',?,?,0)", vec![text(&id), int(ordinal), text(&package), text(&auth::token_hash(&ticket)), int(auth::now() + 600)]);
            Ok(json!({"_os_prepare":{"id":id,"ticket":ticket,"content":content.into_values().collect::<Vec<_>>()}}))
        })();
        let commit = result.is_ok(); (result, commit)
    }).map_err(io)?
}
pub fn control(
    db: &mut Db,
    process: &kernel::Process,
    device: crate::dev::Request,
    op: u32,
    arg: Value,
) -> Result<Value> {
    if op != CONTROL {
        return Err(Errno::ENOTTY.into());
    }
    if arg["op"] == "status" {
        return status(db);
    }
    if process.cred.id != 0 || !device.writes() {
        return Err(Errno::EPERM.into());
    }
    let operation = arg["op"].as_str().unwrap_or_default();
    if !matches!(operation, "activate" | "rollback") {
        return Err(Errno::EINVAL.into());
    }
    let id = arg["id"].as_str().ok_or(Errno::EINVAL)?;
    let active = db.meta("system.active");
    if arg.get("expected").is_none() || arg["expected"].as_str() != active.as_deref() {
        return Err(Errno::ESTALE.into());
    }
    let row = stored(db, id)
        .filter(|r| r.state == "verified")
        .ok_or(Errno::EBUSY)?;
    if operation == "rollback" && row.approved == 0 {
        return Err(Errno::EPERM.into());
    }
    let view = verified(&row)?;
    validate_mount(db, &view.composition)?;
    db.run(
        "UPDATE system_releases SET approved = 1 WHERE id = ?",
        vec![text(id)],
    );
    if let Some(active) = active {
        db.set_meta("system.previous", &active);
    }
    db.set_meta("system.active", id);
    status(db)
}
fn validate_mount(db: &Db, composition: &Composition) -> Result<()> {
    for entry in composition.entries.values() {
        let Some(existing) = db.persisted_node(&entry.path) else {
            continue;
        };
        if !matches!(entry.node, os_image::Node::Directory)
            || !existing.directory
            || existing.owner != entry.uid
            || existing.group != entry.gid
            || existing.mode != entry.mode
            || existing.acl.is_some()
            || existing.default_acl.is_some()
        {
            return Err(Error::because(
                Errno::EEXIST,
                format!("image conflicts with mutable state: {}", entry.path),
            ));
        }
        if !matches!(entry.path.as_str(), "/" | "/etc" | "/opt")
            && db.persisted_descendant(&entry.path)
        {
            return Err(Error::because(
                Errno::EEXIST,
                "image would hide mutable directory contents",
            ));
        }
    }
    Ok(())
}
pub fn status(db: &Db) -> Result<Value> {
    let releases: Vec<Stored> = db.rows("SELECT id,ordinal,package,state,ticket,expires,approved,pending FROM system_releases ORDER BY ordinal", vec![]);
    Ok(
        json!({"active":db.meta("system.active"),"previous":db.meta("system.previous"),"protocol":os_image::PROTOCOL,"schema":os_image::SCHEMA,"releases":releases.iter().map(|r| json!({"id":r.id,"state":r.state,"approved":r.approved != 0,"trusted":verified(r).is_ok()})).collect::<Vec<_>>()}),
    )
}
pub async fn internal(req: &mut Request, state: &State) -> worker::Result<Reply> {
    if req.path() == "/internal/boot" {
        return transact(state, |db| {
            let result = (|| {
                if let Some(id) = db.meta("system.active") {
                    let row = stored(db, &id).ok_or(Errno::ESTALE)?;
                    verified(&row)?;
                }
                Ok::<_, Error>(
                    json!({"format":"os.boot","version":1,"default":db.meta("system.active"),"protocol":os_image::PROTOCOL,"schema":os_image::SCHEMA,"trust":TRUST.with(|t| t.borrow().clone())}),
                )
            })();
            (
                match result {
                    Ok(v) => Reply::ok(v),
                    Err(e) => crate::api::errno_reply(&e),
                },
                false,
            )
        });
    }
    let body: Value = req.json().await?;
    transact(state, move |db| {
        let result = (|| {
            let id = body["id"].as_str().ok_or(Errno::EINVAL)?;
            let ticket = body["ticket"].as_str().ok_or(Errno::EPERM)?;
            let row = stored(db, id).ok_or(Errno::ENOENT)?;
            if (row.state != "staging" && row.pending.is_none())
                || row.expires < auth::now()
                || row.ticket.as_deref() != Some(&auth::token_hash(ticket))
            {
                return Err(Errno::ESTALE.into());
            }
            let candidate = row.pending.as_deref().unwrap_or(&row.package);
            let package: Package = os_image::parse(candidate.as_bytes()).map_err(invalid)?;
            package.verify(id)?;
            if body["inspect"] == true {
                return Ok(json!({"pending":true}));
            }
            let state = if body["ok"] == true || row.approved != 0 {
                "verified"
            } else {
                "failed"
            };
            let package = if body["ok"] == true {
                candidate
            } else {
                &row.package
            };
            db.run(
                "UPDATE system_releases SET state=?,package=?,ticket=NULL,pending=NULL WHERE id=?",
                vec![text(state), text(package), text(id)],
            );
            Ok(json!({"id":id,"state":state}))
        })();
        let commit = result.is_ok();
        (
            match result {
                Ok(v) => Reply::ok(v),
                Err(e) => crate::api::errno_reply(&e),
            },
            commit,
        )
    })
}

// Outer Worker only: hash streams with bounded buffering. The authority never receives
// file bytes. A private, short-lived ticket can finish only its pending preparation.
pub async fn finish_preparation(env: &Env, mut response: Response) -> worker::Result<Response> {
    if response.status_code() != 200 {
        return Ok(response);
    }
    let mut body: Value = response.json().await?;
    let Some(results) = body["results"].as_array_mut() else {
        return Response::from_json(&body);
    };
    for result in results {
        let Some(plan) = result["ok"].get("_os_prepare").cloned() else {
            continue;
        };
        let probe = json!({"id":plan["id"],"ticket":plan["ticket"],"inspect":true});
        let mut init = worker::RequestInit::new();
        init.with_method(Method::Post)
            .with_body(Some(probe.to_string().into()));
        let checked = env
            .durable_object("AUTHORITY")?
            .id_from_name("filesystem")?
            .get_stub()?
            .fetch_with_request(Request::new_with_init(
                "https://authority/internal/system-prepared",
                &init,
            )?)
            .await?;
        if checked.status_code() != 200 {
            *result = json!({"err":{"errno":"ESTALE","detail":"release preparation expired or was revoked"}});
            continue;
        }
        let checked = check_content(env, &plan).await;
        let request = json!({"id":plan["id"],"ticket":plan["ticket"],"ok":checked.is_ok()});
        let mut init = worker::RequestInit::new();
        init.with_method(Method::Post)
            .with_body(Some(request.to_string().into()));
        let mut finished = env
            .durable_object("AUTHORITY")?
            .id_from_name("filesystem")?
            .get_stub()?
            .fetch_with_request(Request::new_with_init(
                "https://authority/internal/system-prepared",
                &init,
            )?)
            .await?;
        *result = match checked {
            Ok(()) if finished.status_code() == 200 => {
                json!({"ok":finished.json::<Value>().await?})
            }
            Ok(()) => {
                json!({"err":{"errno":"EIO","detail":"release preparation expired or was revoked"}})
            }
            Err(error) => json!({"err":{"errno":"EIO","detail":error.to_string()}}),
        };
    }
    let headers = response.headers().clone();
    Ok(Response::from_json(&body)?.with_headers(headers))
}
async fn check_content(env: &Env, plan: &Value) -> worker::Result<()> {
    use futures_util::StreamExt;
    use sha2::{Digest, Sha256};
    let entries: Vec<Content> = serde_json::from_value(plan["content"].clone())?;
    for entry in entries {
        let mut response = env
            .assets("ASSETS")?
            .fetch_request(Request::new(&asset_url(&entry.path), Method::Get)?)
            .await?;
        if response.status_code() != 200 {
            return Err(worker::Error::RustError(
                "release content unavailable".into(),
            ));
        }
        let mut stream = response.stream()?;
        let mut hash = Sha256::new();
        let mut size = 0u64;
        let mut prefix = Vec::new();
        while let Some(chunk) = stream.next().await {
            let bytes = chunk?;
            size = size
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| worker::Error::RustError("release content overflow".into()))?;
            if size > entry.size {
                return Err(worker::Error::RustError(
                    "release content length mismatch".into(),
                ));
            }
            if prefix.len() < 8 {
                prefix.extend_from_slice(&bytes[..bytes.len().min(8 - prefix.len())]);
            }
            hash.update(&bytes);
        }
        if size != entry.size
            || os_image::hex(&hash.finalize()) != entry.sha256
            || (entry.wasm && prefix != b"\0asm\x01\0\0\0")
        {
            return Err(worker::Error::RustError(
                "release content integrity/boot format check failed".into(),
            ));
        }
    }
    Ok(())
}

/// Pre-VFS boot views. Their policy is the authority's; Wrangler only makes the
/// immutable bytes obtainable. Recovery keeps account authentication available.
pub async fn route(req: Request, env: &Env) -> worker::Result<Response> {
    let url = req.url()?;
    let path = url.path();
    if path.starts_with("/boot/blobs/")
        || (path.starts_with("/boot/releases/") && path.contains("/assets/"))
    {
        return checked_asset(req, env).await;
    }
    if path == "/boot/entries"
        || matches!(
            path,
            "/" | "/index.html"
                | "/login"
                | "/login.html"
                | "/shell"
                | "/shell.html"
                | "/console"
                | "/console.html"
        )
    {
        if url.query_pairs().any(|(k, v)| k == "recovery" && v == "1") {
            return legacy_asset(req, env).await;
        }
        let mut entry = env
            .durable_object("AUTHORITY")?
            .id_from_name("filesystem")?
            .get_stub()?
            .fetch_with_request(Request::new(
                "https://authority/internal/boot",
                Method::Get,
            )?)
            .await?;
        if entry.status_code() != 200 {
            return Ok(Response::from_html("<!doctype html><title>OS recovery</title><h1>The selected release cannot boot</h1><p>Its trust or compatibility check failed. Use recovery to inspect or roll back the release.</p><a href=\"/?recovery=1\">Open recovery</a>")?.with_status(503));
        }
        let entry: Value = entry.json().await?;
        if path == "/boot/entries" {
            let mut response = Response::from_json(&entry)?;
            response.headers_mut().set("Cache-Control", "no-store")?;
            return Ok(response);
        }
        if let Some(id) = entry["default"].as_str() {
            let page = match path {
                "/" | "/index.html" => "index.html",
                "/shell" | "/shell.html" => "shell.html",
                "/console" | "/console.html" => "console.html",
                _ => "login.html",
            };
            let mut target = url.clone();
            target.set_path(&format!("/boot/releases/{id}/assets/{page}"));
            let mut response = Response::empty()?.with_status(307);
            response.headers_mut().set("Location", target.as_str())?;
            response.headers_mut().set("Cache-Control", "no-store")?;
            // Browsers apply opener policy to redirects too. Keep an OS popup in
            // its owner's isolated browsing-context group during release selection.
            response
                .headers_mut()
                .set("Cross-Origin-Opener-Policy", "same-origin")?;
            response
                .headers_mut()
                .set("Cross-Origin-Embedder-Policy", "require-corp")?;
            return Ok(response);
        }
    }
    legacy_asset(req, env).await
}

async fn legacy_asset(req: Request, env: &Env) -> worker::Result<Response> {
    let mut url = req.url()?;
    let page = match url.path() {
        "/" => Some("/index.html"),
        "/login" => Some("/login.html"),
        "/shell" => Some("/shell.html"),
        "/console" => Some("/console.html"),
        _ => None,
    };
    if let Some(page) = page {
        url.set_path(page);
        return env
            .assets("ASSETS")?
            .fetch_request(Request::new(url.as_str(), req.method())?)
            .await;
    }
    env.assets("ASSETS")?.fetch_request(req).await
}

/// Verify before returning any bytes, also after a deployment accidentally replaces an
/// immutable path. Range and conditional responses are applied only after integrity.
pub async fn checked_asset(req: Request, env: &Env) -> worker::Result<Response> {
    let url = req.url()?;
    let path = url.path();
    let expected = if let Some(hash) = path.strip_prefix("/boot/blobs/") {
        os_image::unhex::<32>(hash).map_err(|e| worker::Error::RustError(e.to_string()))?;
        hash.to_string()
    } else {
        configure(env)?;
        let (id, file) = path
            .strip_prefix("/boot/releases/")
            .and_then(|s| s.split_once("/assets"))
            .ok_or_else(|| worker::Error::RustError("invalid boot asset path".into()))?;
        os_image::unhex::<32>(id).map_err(|e| worker::Error::RustError(e.to_string()))?;
        let checked = async {
            let file = asset_path(file)?;
            let release = metadata(env, &format!("/boot/releases/{id}/manifest.json")).await?;
            let signature = metadata(env, &format!("/boot/releases/{id}/signature.json")).await?;
            if os_image::digest(release.as_bytes()) != id {
                return Err(invalid("release digest mismatch"));
            }
            TRUST
                .with(|t| {
                    t.borrow()
                        .verify("os.release.v1", release.as_bytes(), signature.as_bytes())
                })
                .map_err(invalid)?;
            let release = Release::parse(release.as_bytes()).map_err(invalid)?;
            let image = metadata(env, &format!("/boot/images/{}.json", release.boot)).await?;
            let signature = metadata(env, &format!("/boot/images/{}.sig", release.boot)).await?;
            if os_image::digest(image.as_bytes()) != release.boot {
                return Err(invalid("boot manifest digest mismatch"));
            }
            TRUST
                .with(|t| {
                    t.borrow()
                        .verify("os.image.v1", image.as_bytes(), signature.as_bytes())
                })
                .map_err(invalid)?;
            let image = Image::parse(image.as_bytes()).map_err(invalid)?;
            if image.kind != Kind::Boot {
                return Err(invalid("boot image kind mismatch"));
            }
            image
                .entries
                .into_iter()
                .find_map(|e| {
                    if e.path == file {
                        if let os_image::Node::File { sha256, .. } = e.node {
                            return Some(sha256);
                        }
                        None
                    } else {
                        None
                    }
                })
                .ok_or_else(|| Errno::ENOENT.into())
        }
        .await;
        match checked {
            Ok(hash) => hash,
            Err(e) => return crate::files::error_response(&e.to_string(), 409),
        }
    };
    let mut response = env
        .assets("ASSETS")?
        .fetch_request(Request::new(&format!("https://assets{path}"), Method::Get)?)
        .await?;
    if response.status_code() != 200 {
        return Ok(response);
    }
    let bytes = response.bytes().await?;
    if os_image::digest(&bytes) != expected {
        return crate::files::error_response("immutable artifact digest mismatch", 409);
    }
    let headers = worker::Headers::new();
    for (name, value) in response.headers().entries() {
        if !matches!(
            name.to_ascii_lowercase().as_str(),
            "content-length" | "content-encoding" | "etag" | "cache-control"
        ) {
            headers.set(&name, &value)?;
        }
    }
    // Revalidate revocation on each request; retain immutable bytes without promising a
    // year of cached execution after an operator revokes a publisher.
    headers.set("Cache-Control", "no-cache")?;
    let etag = format!("\"{expected}\"");
    headers.set("ETag", &etag)?;
    headers.set("Accept-Ranges", "bytes")?;
    if req.headers().get("If-None-Match")?.as_deref() == Some(&etag) {
        return Ok(Response::empty()?.with_status(304).with_headers(headers));
    }
    let range = req.headers().get("Range")?;
    let if_range = req.headers().get("If-Range")?;
    let range = range.filter(|_| if_range.as_ref().is_none_or(|value| value == &etag));
    let (start, end, status) = if let Some(range) = range {
        match os_core::byte_range(&range, bytes.len() as u64) {
            Some((a, b)) => {
                headers.set("Content-Range", &format!("bytes {a}-{b}/{}", bytes.len()))?;
                (a as usize, b as usize + 1, 206)
            }
            None => return Ok(Response::empty()?.with_status(416)),
        }
    } else {
        (0, bytes.len(), 200)
    };
    headers.set("Content-Length", &(end - start).to_string())?;
    let body = if req.method() == Method::Head {
        Response::empty()?
    } else {
        Response::from_bytes(bytes[start..end].to_vec())?
    };
    Ok(body.with_status(status).with_headers(headers))
}

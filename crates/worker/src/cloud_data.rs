//! Immutable byte extents. Writes upload once outside the authority, then splice their
//! extent into the inode's current content atomically (including append). Sparse ranges
//! read as zeros. Existing chunk files become extents without copying their bytes.
use crate::{
    api::{self, Reply},
    auth, cloudfs,
    creds::Credential,
    db::{Db, int, text},
};
use abi::{
    Errno,
    fs::*,
    remote_fs::{self as wire, DataOperation, DataRequest},
};
use os_core::{inode, permissions::Node};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use worker::*;
type FsResult<T> = std::result::Result<T, Errno>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Extent {
    #[serde(deserialize_with = "crate::db::exact_u64")]
    pub start: u64,
    #[serde(deserialize_with = "crate::db::exact_u64")]
    pub length: u64,
    pub key: String,
    #[serde(deserialize_with = "crate::db::exact_u64")]
    pub offset: u64,
    pub source: Option<String>,
}
#[derive(Deserialize)]
struct Upload {
    session: String,
    open: u64,
    credential: String,
    operation: String,
    expires: u64,
}
#[derive(Deserialize)]
struct Read {
    file: String,
}
impl Db {
    pub(crate) fn extents(&self, file: &str) -> Vec<Extent> {
        self.rows(
            "SELECT CAST(start AS TEXT) AS start,CAST(length AS TEXT) AS length,key,CAST(offset AS TEXT) AS offset,source FROM vfs_extents WHERE file = ? ORDER BY vfs_extents.start",
            vec![text(file)],
        )
    }
    fn content(&self, node: &Node) -> FsResult<Vec<Extent>> {
        let Some(id) = node.file.as_deref() else {
            return Ok(Vec::new());
        };
        if crate::system::asset(id).is_some() {
            return Ok(vec![Extent {
                start: 0,
                length: node.size,
                key: id.into(),
                offset: 0,
                source: Some(id.into()),
            }]);
        }
        let file = self.file(id).ok_or(Errno::EIO)?;
        if !file.complete() {
            return Err(Errno::EBUSY);
        }
        if file.chunk_size == 0 {
            return Ok(self.extents(id));
        }
        Ok(self
            .chunks(id)
            .into_iter()
            .map(|c| Extent {
                start: c.idx * file.chunk_size,
                length: file.chunk_len(c.idx),
                key: c.key,
                offset: 0,
                source: Some(id.into()),
            })
            .collect())
    }
    fn replace_content_at(
        &mut self,
        node: &mut Node,
        size: u64,
        extents: Vec<Extent>,
        cred: &Credential,
        now: (u64, u32),
    ) -> FsResult<()> {
        let file = auth::random_token();
        self.run("INSERT INTO files(id,size,chunk_size,state,uploader,target,touched) VALUES(?,?,0,'complete',?,'',?)",vec![text(&file),int(size),int(cred.uid),int(now.0)]);
        for e in extents {
            if e.length > 0 {
                self.run("INSERT INTO vfs_extents(file,start,length,key,offset,source) VALUES(?,?,?,?,?,?)",vec![text(&file),int(e.start),int(e.length),text(&e.key),int(e.offset),e.source.as_deref().into()]);
            }
        }
        node.file = Some(file);
        node.size = size;
        inode::remove_privs(&cred.identity(), node);
        self.update_inode_at(node, now);
        self.set_times_at(node.ino, None, Some(now), now);
        Ok(())
    }
    pub(crate) fn cloud_truncate(
        &mut self,
        node: &mut Node,
        size: u64,
        cred: &Credential,
    ) -> FsResult<()> {
        self.cloud_truncate_at(node, size, cred, auth::clock())
    }
    pub(crate) fn cloud_truncate_at(
        &mut self,
        node: &mut Node,
        size: u64,
        cred: &Credential,
        now: (u64, u32),
    ) -> FsResult<()> {
        if node.directory {
            return Err(Errno::EISDIR);
        }
        if !node.is_file() {
            return Err(Errno::EINVAL);
        }
        if size > FILE_MAX {
            return Err(Errno::EFBIG);
        }
        let extents = self
            .content(node)?
            .into_iter()
            .filter(|e| e.start < size)
            .map(|mut e| {
                e.length = e.length.min(size - e.start);
                e
            })
            .collect();
        self.replace_content_at(node, size, extents, cred, now)
    }
    pub(crate) fn drop_extents(&mut self, file: &str) {
        let extents = self.extents(file);
        self.run("DELETE FROM vfs_extents WHERE file = ?", vec![text(file)]);
        let mut sources = std::collections::BTreeSet::new();
        for e in extents {
            if let Some(source) = e.source {
                sources.insert(source);
            } else if self
                .rows::<Value>(
                    "SELECT file FROM vfs_extents WHERE key = ? LIMIT 1",
                    vec![text(&e.key)],
                )
                .is_empty()
            {
                self.discard(&e.key);
            }
        }
        for source in sources {
            self.release(Some(source));
        }
    }
    pub(crate) fn expire_cloud_upload(&mut self, id: &str) {
        let deleted = !self
            .rows::<Value>(
                "DELETE FROM vfs_uploads WHERE id = ? RETURNING id",
                vec![text(id)],
            )
            .is_empty();
        if deleted {
            self.discard(&format!("vfs/{id}"));
        }
        self.clear_expiry("vfs_upload", id);
    }
    pub(crate) fn end_cloud_read(&mut self, id: &str) {
        let reads = self.rows::<Read>(
            "DELETE FROM vfs_reads WHERE id = ? RETURNING file",
            vec![text(id)],
        );
        for r in reads {
            self.release(Some(r.file));
        }
        self.clear_expiry("vfs_read", id);
    }
}
fn regular(node: &Node, open: &OpenRef, write: bool) -> FsResult<()> {
    if if write {
        !open.access.writes()
    } else {
        !open.access.reads()
    } {
        return Err(Errno::EBADF);
    }
    if node.directory {
        return Err(Errno::EISDIR);
    }
    // A device's I/O is its driver's, as MemFs refuses it.
    if !node.is_file() {
        return Err(Errno::ENXIO);
    }
    Ok(())
}
fn prepare(db: &mut Db, request: &DataRequest) -> FsResult<Value> {
    if request.version != wire::VERSION {
        return Err(Errno::EPROTONOSUPPORT);
    }
    let c = cloudfs::caller(db, &request.session, &request.credential)?;
    let node = c.opened(db, &request.open)?;
    match request.operation {
        DataOperation::Read { offset, length } => {
            regular(&node, &request.open, false)?;
            if offset > FILE_MAX || length > FILE_MAX - offset {
                return Err(Errno::EINVAL);
            }
            if length > wire::DATA_MAX {
                return Err(Errno::E2BIG);
            }
            if let Some(generated) = db
                .names(node.ino)
                .iter()
                .find_map(|path| crate::sys::generated(db, path))
            {
                let bytes = generated.into_bytes();
                let start = bytes
                    .len()
                    .min(usize::try_from(offset).unwrap_or(usize::MAX));
                let end = bytes
                    .len()
                    .min(usize::try_from(offset.saturating_add(length)).unwrap_or(usize::MAX));
                let slice = &bytes[start..end];
                db.cloud_accessed(node.ino);
                return Ok(json!({
                    "generated": slice,
                    "io": c.io(&request.credential, request.pid, false, slice.len() as u64)?,
                }));
            }
            let length = length.min(node.size.saturating_sub(offset));
            let extents = db.content(&node)?;
            let id = auth::random_token();
            if let Some(file) = node.file {
                db.run(
                    "INSERT INTO vfs_reads(id,file,session) VALUES(?,?,?)",
                    vec![text(&id), text(&file), text(&request.session.id)],
                );
                db.set_expiry("vfs_read", &id, auth::now() + wire::LEASE_SECONDS);
            }
            db.cloud_accessed(node.ino);
            Ok(
                json!({"id":id,"offset":offset,"length":length,"extents":extents,"io":c.io(&request.credential,request.pid,false,length)?}),
            )
        }
        DataOperation::Write { at, length } => {
            regular(&node, &request.open, true)?;
            cloudfs::unchanged_names(db, node.ino)?;
            if length > wire::DATA_MAX {
                return Err(Errno::E2BIG);
            }
            let offset = match at {
                WriteAt::Offset(offset) => offset,
                WriteAt::End => node.size,
            };
            // Writing nothing changes nothing, at any offset, as MemFs and Linux have it.
            if length == 0 {
                return Ok(json!({
                    "written": Written { offset, len: 0 },
                    "io": c.io(&request.credential, request.pid, true, 0)?,
                }));
            }
            if offset >= FILE_MAX {
                return Err(Errno::EFBIG);
            }
            let id = auth::random_token();
            let expires = auth::now() + wire::LEASE_SECONDS;
            db.run("INSERT INTO vfs_uploads(id,session,open,credential,operation,expires) VALUES(?,?,?,?,?,?)",vec![text(&id),text(&request.session.id),int(request.open.id),text(&auth::token_hash(&request.credential)),text(&json!(request.operation).to_string()),int(expires)]);
            db.set_expiry("vfs_upload", &id, expires);
            Ok(
                json!({"id":id,"key":format!("vfs/{id}"),"io":c.io(&request.credential,request.pid,true,length)?}),
            )
        }
    }
}
fn commit(db: &mut Db, request: &DataRequest, id: &str) -> FsResult<Value> {
    if request.version != wire::VERSION {
        return Err(Errno::EPROTONOSUPPORT);
    }
    let c = cloudfs::caller(db, &request.session, &request.credential)?;
    let mut node = c.opened(db, &request.open)?;
    regular(&node, &request.open, true)?;
    cloudfs::unchanged_names(db, node.ino)?;
    let upload = db
        .rows::<Upload>("SELECT * FROM vfs_uploads WHERE id = ?", vec![text(id)])
        .pop()
        .ok_or(Errno::ESTALE)?;
    let operation = serde_json::to_string(&request.operation).map_err(|_| Errno::EIO)?;
    if upload.session != request.session.id
        || upload.open != request.open.id
        || upload.credential != auth::token_hash(&request.credential)
        || upload.operation != operation
    {
        return Err(Errno::EACCES);
    }
    if upload.expires <= auth::now() {
        return Err(Errno::ESTALE);
    }
    let DataOperation::Write { at, length } = request.operation else {
        return Err(Errno::EINVAL);
    };
    let offset = match at {
        WriteAt::Offset(offset) => offset,
        WriteAt::End => node.size,
    };
    if length == 0 {
        db.run("DELETE FROM vfs_uploads WHERE id = ?", vec![text(id)]);
        db.clear_expiry("vfs_upload", id);
        return Ok(json!(Written { offset, len: 0 }));
    }
    if offset >= FILE_MAX {
        return Err(Errno::EFBIG);
    }
    // A write starting before FILE_MAX and extending past it commits only the prefix up to
    // FILE_MAX, including when concurrent appends advance EOF between prepare and commit.
    let written = length.min(FILE_MAX - offset);
    let end = offset + written;
    let mut extents = Vec::new();
    for e in db.content(&node)? {
        let ee = e.start + e.length;
        if ee <= offset || e.start >= end {
            extents.push(e);
            continue;
        }
        if e.start < offset {
            extents.push(Extent {
                length: offset - e.start,
                ..e.clone()
            });
        }
        if ee > end {
            extents.push(Extent {
                start: end,
                length: ee - end,
                offset: e.offset + end - e.start,
                ..e
            });
        }
    }
    extents.push(Extent {
        start: offset,
        length: written,
        key: format!("vfs/{id}"),
        offset: 0,
        source: None,
    });
    let size = node.size.max(end);
    db.replace_content_at(&mut node, size, extents, c.actor(), auth::clock())?;
    db.run("DELETE FROM vfs_uploads WHERE id = ?", vec![text(id)]);
    db.clear_expiry("vfs_upload", id);
    Ok(json!(Written {
        offset,
        len: written as usize
    }))
}

pub async fn authority(req: &mut Request, state: &State) -> Result<Reply> {
    // These paths are reachable only through the binding. The outer Worker never forwards
    // public /internal requests. A caller cannot assert that an R2 upload succeeded.
    #[derive(Deserialize)]
    struct Asked {
        request: DataRequest,
        id: Option<String>,
    }
    let body = req.text().await?;
    let Ok(asked) = serde_json::from_str::<Asked>(&body) else {
        return Ok(api::errno_reply(&Errno::EINVAL.into()));
    };
    let path = req.path();
    crate::db::transact(state, |db| {
        db.sweep_cloud();
        ((), true)
    })?;
    api::run(state, move |db| {
        cloudfs::reply(match path.as_str() {
            "/internal/fs/data" => prepare(db, &asked.request),
            "/internal/fs/commit" => commit(db, &asked.request, asked.id.as_deref().unwrap_or("")),
            "/internal/fs/abandon" => {
                let id = asked.id.as_deref().unwrap_or("");
                if db
                    .rows::<Value>(
                        "SELECT file FROM vfs_extents WHERE key = ? LIMIT 1",
                        vec![text(&format!("vfs/{id}"))],
                    )
                    .is_empty()
                {
                    db.expire_cloud_upload(id);
                }
                Ok(Value::Null)
            }
            "/internal/fs/read-done" => {
                // The read id is a random service capability delivered only to the gateway.
                db.end_cloud_read(asked.id.as_deref().unwrap_or(""));
                Ok(Value::Null)
            }
            _ => Err(Errno::EINVAL),
        })
    })
}
async fn ask(env: &Env, path: &str, request: &DataRequest, id: Option<&str>) -> Result<Response> {
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_body(Some(wasm_bindgen::JsValue::from_str(
            &json!({"request":request,"id":id}).to_string(),
        )));
    env.durable_object("AUTHORITY")?
        .id_from_name("filesystem")?
        .get_stub()?
        .fetch_with_request(Request::new_with_init(
            &format!("https://authority{path}"),
            &init,
        )?)
        .await
}
pub async fn gateway(req: Request, env: &Env) -> Result<Response> {
    let Some(header) = req.headers().get("X-OS-Filesystem")? else {
        return api::errno_reply(&Errno::EINVAL.into()).response();
    };
    let Ok(body) = serde_json::from_str::<Value>(&header) else {
        return api::errno_reply(&Errno::EINVAL.into()).response();
    };
    if body.get("version").and_then(Value::as_u64) != Some(u64::from(wire::VERSION)) {
        return api::errno_reply(&Errno::EPROTONOSUPPORT.into()).response();
    }
    let Ok(request) = serde_json::from_value::<DataRequest>(body) else {
        return api::errno_reply(&Errno::EINVAL.into()).response();
    };
    let mut response = ask(env, "/internal/fs/data", &request, None).await?;
    if response.status_code() != 200 {
        return Ok(response);
    }
    let grant: Value = response.json().await?;
    let id = grant["id"].as_str().unwrap_or_default();
    if let Some(value) = grant.get("io").filter(|v| !v.is_null()) {
        let io: crate::resources::IoRequest = serde_json::from_value(value.clone())?;
        if let Err(error) = crate::resources::checked_io(env, io).await {
            if !id.is_empty() {
                let cleanup = match request.operation {
                    DataOperation::Read { .. } => "/internal/fs/read-done",
                    DataOperation::Write { .. } => "/internal/fs/abandon",
                };
                let _ = ask(env, cleanup, &request, Some(id)).await;
            }
            return crate::resources::refused(error);
        }
    }
    match request.operation {
        DataOperation::Read { .. } => {
            if let Some(generated) = grant.get("generated") {
                let bytes: Vec<u8> = serde_json::from_value(generated.clone())?;
                return Response::from_bytes(bytes);
            }
            let extents: Vec<Extent> = serde_json::from_value(grant["extents"].clone())?;
            let length = grant["length"].as_u64().unwrap_or(0);
            let offset = grant["offset"].as_u64().unwrap_or(0);
            let body = extent_stream(env, extents, offset, length)?;
            // A read pins the immutable manifest for its bounded lease. The stream owns no
            // authority transaction; alarm cleanup also covers cancelled responses.
            let env = env.clone();
            let request = request.clone();
            let id = id.to_string();
            let finished = Closure::<dyn FnMut() -> js_sys::Promise>::new(move || {
                let env = env.clone();
                let request = request.clone();
                let id = id.clone();
                future_to_promise(async move {
                    let _ = ask(&env, "/internal/fs/read-done", &request, Some(&id)).await;
                    Ok(JsValue::UNDEFINED)
                })
            });
            Response::from_body(ResponseBody::Stream(finish_read(
                &body,
                &finished.into_js_value().into(),
            )))
        }
        DataOperation::Write { length, .. } => {
            if length == 0 {
                if crate::streams::discard_stream(
                    req.inner().body().map_or(JsValue::NULL, Into::into),
                    0.0,
                )
                .await
                .is_err()
                {
                    return api::errno_reply(&Errno::EIO.into()).response();
                }
                return Response::from_json(&grant["written"]);
            }
            let result = crate::files::store(
                env,
                &req,
                &format!("vfs/{id}"),
                length,
                "application/octet-stream",
                None,
            )
            .await;
            if result.is_err() {
                let _ = ask(env, "/internal/fs/abandon", &request, Some(id)).await;
                return api::errno_reply(&Errno::EIO.into()).response();
            }
            let result = ask(env, "/internal/fs/commit", &request, Some(id)).await;
            if result.as_ref().is_err() || result.as_ref().is_ok_and(|r| r.status_code() != 200) {
                let _ = ask(env, "/internal/fs/abandon", &request, Some(id)).await;
            }
            result
        }
    }
}

use std::{cell::RefCell, collections::VecDeque, rc::Rc};
use wasm_bindgen::prelude::*;
use worker::wasm_bindgen_futures::future_to_promise;
#[wasm_bindgen(
    inline_js = "export function zeroBytes(length) { return new ReadableStream({pull(c) { const n = length > 65536n ? 65536 : Number(length); if (!n) {c.close();return;} c.enqueue(new Uint8Array(n));length -= BigInt(n); }}); }"
)]
extern "C" {
    #[wasm_bindgen(js_name=zeroBytes)]
    fn zeros(length: u64) -> web_sys::ReadableStream;
}
/// Clip extents to a read, including holes (no object key). Both inline and streamed readers
/// use the same ranges, including offsets into objects shared by multiple manifests.
pub(crate) fn extent_parts(
    extents: Vec<Extent>,
    offset: u64,
    length: u64,
) -> Vec<(Option<String>, u64, u64)> {
    let end = offset + length;
    let mut at = offset;
    let mut parts = Vec::new();
    for e in extents {
        if e.start >= end {
            break;
        }
        let from = e.start.max(offset);
        let to = (e.start + e.length).min(end);
        if from >= to {
            continue;
        }
        if from > at {
            parts.push((None, 0, from - at));
        }
        parts.push((Some(e.key), e.offset + from - e.start, to - from));
        at = to;
    }
    if at < end {
        parts.push((None, 0, end - at));
    }
    parts
}
/// Extents clipped to the requested range, with bounded-memory zero streams for holes.
pub fn extent_stream(
    env: &Env,
    extents: Vec<Extent>,
    offset: u64,
    length: u64,
) -> Result<web_sys::ReadableStream> {
    let parts = Rc::new(RefCell::new(VecDeque::from(extent_parts(
        extents, offset, length,
    ))));
    let bucket = Rc::new(env.bucket("FILES")?);
    let env = env.clone();
    let next = Closure::<dyn FnMut() -> js_sys::Promise>::new(move || {
        let part = parts.borrow_mut().pop_front();
        let bucket = bucket.clone();
        let env = env.clone();
        future_to_promise(async move {
            match part {
                None => Ok(JsValue::NULL),
                Some((None, _, length)) => Ok(zeros(length).into()),
                Some((Some(key), offset, length)) => {
                    if let Some(asset) = crate::system::asset(&key) {
                        return crate::streams::asset_range(&env, &asset, offset, length)
                            .await
                            .map(Into::into);
                    }
                    crate::streams::object_range(&bucket, &key, offset, length)
                        .await
                        .map(Into::into)
                }
            }
        })
    });
    Ok(crate::streams::fixed_length(
        &crate::streams::concatenate(&next.into_js_value().into()),
        length,
    ))
}

#[wasm_bindgen(
    inline_js = "export function finishRead(body, done) { const reader=body.getReader(); let ended=false; const finish=async()=>{ if (!ended) {ended=true; await done().catch(()=>{});} }; return new ReadableStream({async pull(c) { try { const part=await reader.read(); if(part.done){await finish();c.close();}else c.enqueue(part.value); } catch(e){await finish();c.error(e);} }, async cancel(why){try{await reader.cancel(why);}finally{await finish();}}}); }"
)]
extern "C" {
    #[wasm_bindgen(js_name=finishRead)]
    fn finish_read(
        body: &web_sys::ReadableStream,
        done: &js_sys::Function,
    ) -> web_sys::ReadableStream;
}

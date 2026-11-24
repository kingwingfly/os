//! Streaming edge of Boundary::Volume. SQLite sees grants, receipts and verified index entries.
//! An upload holds a quota reservation until the DO accepts the trailer under a live lease.
use crate::{
    resources::{self, IoRequest},
    storage_do::{self, Action, Command, Grant, VResult, pack_key},
};
use abi::{Errno, remote_volume as w};
use cowtree::{
    PackId, PackIndexEntry, VolumeId, digest_from_hex,
    pack::{PACK_FOOTER_BYTES, decode_pack_footer, decode_pack_trailer_bytes},
};
use futures_util::{StreamExt, TryStreamExt};
use serde::de::DeserializeOwned;
use sha2::{Digest as _, Sha256};
use std::{cell::RefCell, rc::Rc};
use worker::*;

fn io(_: worker::Error) -> Errno {
    Errno::EIO
}
fn header(req: &Request, key: &str) -> VResult<Option<String>> {
    req.headers().get(key).map_err(io)
}
fn internal(req: &Request, url: &str, body: Option<String>) -> VResult<Request> {
    let headers = Headers::new();
    for name in ["Cookie", "X-Process-Token", "X-OS-Instance", "X-OS-Tenant"] {
        if let Some(v) = header(req, name)? {
            headers.set(name, &v).map_err(io)?;
        }
    }
    headers
        .set("Content-Type", "application/json")
        .map_err(io)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(body.map(Into::into));
    Request::new_with_init(url, &init).map_err(io)
}
pub(crate) async fn verify(req: &Request, env: &Env) -> VResult<Grant> {
    let sub = internal(
        req,
        "https://authority/internal/service-auth/verify-volume",
        None,
    )?;
    let mut resp = env
        .durable_object("AUTHORITY")
        .map_err(io)?
        .get_by_name("filesystem")
        .map_err(io)?
        .fetch_with_request(sub)
        .await
        .map_err(io)?;
    if resp.status_code() == 403 {
        return Err(Errno::EACCES);
    }
    if resp.status_code() != 200 {
        return Err(Errno::EIO);
    }
    resp.json().await.map_err(io)
}
async fn storage(
    req: &Request,
    env: &Env,
    g: &Grant,
    v: &VolumeId,
    action: Action,
) -> VResult<Response> {
    let cmd = Command {
        grant: g.clone(),
        volume: v.clone(),
        action,
    };
    let sub = internal(
        req,
        "https://storage/internal/volume",
        Some(serde_json::to_string(&cmd).map_err(|_| Errno::EINVAL)?),
    )?;
    let mut r = env
        .durable_object("STORAGE")
        .map_err(io)?
        .get_by_name(&format!("tenant:{}", g.tenant))
        .map_err(io)?
        .fetch_with_request(sub)
        .await
        .map_err(io)?;
    if r.status_code() >= 400 {
        return Err(r
            .json::<w::VolumeError>()
            .await
            .map(|e| e.errno)
            .unwrap_or(Errno::EIO));
    }
    Ok(r)
}
async fn meta<T: DeserializeOwned>(
    req: &Request,
    env: &Env,
    g: &Grant,
    v: &VolumeId,
    action: Action,
) -> VResult<T> {
    storage(req, env, g, v, action)
        .await?
        .json()
        .await
        .map_err(io)
}
const IO_SLICE: u64 = 64 * 1024;

async fn charge_slices(env: &Env, io: &IoRequest, mut bytes: u64) -> VResult<()> {
    let mut limit = IO_SLICE;
    while bytes != 0 {
        let n = bytes.min(limit);
        let request = IoRequest {
            bytes: n,
            ..io.clone()
        };
        match resources::checked_io(env, request).await {
            Ok(()) => bytes -= n,
            Err(e) if e.errno == Errno::EAGAIN && n > 1 => limit = n / 2,
            Err(e) => return Err(e.errno),
        }
    }
    Ok(())
}

async fn paced_stream(
    req: &Request,
    env: &Env,
    g: &Grant,
    write: bool,
    stream: ByteStream,
    len: u64,
) -> VResult<impl futures_util::Stream<Item = Result<Vec<u8>>> + use<>> {
    let io = IoRequest {
        ns: g.ns.clone(),
        token: header(req, "X-Process-Token")?.ok_or(Errno::EACCES)?,
        pid: None,
        write,
        bytes: 0,
    };
    let credit = len.min(IO_SLICE);
    charge_slices(env, &io, credit).await?;
    let env = env.clone();
    Ok(futures_util::stream::try_unfold(
        (stream, credit),
        move |(mut stream, credit)| {
            let env = env.clone();
            let io = io.clone();
            async move {
                let Some(bytes) = stream.next().await.transpose()? else {
                    return Ok(None);
                };
                let n = bytes.len() as u64;
                let prepaid = credit.min(n);
                charge_slices(&env, &io, n - prepaid)
                    .await
                    .map_err(|e| Error::RustError(format!("{e:?}")))?;
                Ok(Some((bytes, (stream, credit - prepaid))))
            }
        },
    ))
}

pub async fn gateway(mut req: Request, env: &Env) -> Result<Response> {
    match route(&mut req, env).await {
        Ok(r) => Ok(r),
        Err(e) => storage_do::error(e),
    }
}
async fn route(req: &mut Request, env: &Env) -> VResult<Response> {
    let grant = verify(req, env).await?;
    let path = req.path();
    if path == "/api/volumes/rpc" && req.method() == Method::Post {
        if header(req, "Content-Length")?
            .and_then(|s| s.parse::<usize>().ok())
            .is_some_and(|n| n > w::CONTROL_BODY_MAX)
        {
            return Err(Errno::EFBIG);
        }
        let mut stream = req.stream().map_err(|_| Errno::EINVAL)?;
        let mut buf = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(io)?;
            if buf.len() + chunk.len() > w::CONTROL_BODY_MAX {
                return Err(Errno::EFBIG);
            }
            buf.extend(chunk);
        }
        let rpc = w::Request::decode(&buf)?;
        return storage(req, env, &grant, &rpc.volume, Action::Rpc(rpc.call)).await;
    }
    let id = PackId(
        path.strip_prefix("/api/volumes/packs/")
            .ok_or(Errno::ENOENT)?
            .into(),
    );
    digest_from_hex(&id.0)?;
    let v = VolumeId(header(req, "X-OS-Volume")?.ok_or(Errno::EINVAL)?);
    if !grant.scope.allows_volume(&v.0, req.method() == Method::Put) {
        return Err(Errno::EACCES);
    }
    match req.method() {
        Method::Put => upload(req, env, &grant, &v, &id).await,
        Method::Get | Method::Head => download(req, env, &grant, &v, &id).await,
        _ => Err(Errno::EINVAL),
    }
}
async fn upload(
    req: &mut Request,
    env: &Env,
    g: &Grant,
    v: &VolumeId,
    p: &PackId,
) -> VResult<Response> {
    let size = header(req, "Content-Length")?
        .ok_or(Errno::EINVAL)?
        .parse::<u64>()
        .map_err(|_| Errno::EINVAL)?;
    if size > w::PACK_MAX_BYTES as u64 {
        return Err(Errno::EFBIG);
    }
    let fence = |name| {
        header(req, name)?
            .ok_or(Errno::EINVAL)?
            .parse::<u64>()
            .map_err(|_| Errno::EINVAL)
    };
    let lease = w::Fence {
        incarnation: fence("X-OS-Incarnation")?,
        fence: fence("X-OS-Fence")?,
    };
    let id: String = meta(
        req,
        env,
        g,
        v,
        Action::Begin {
            pack_id: p.clone(),
            size: size as u32,
            lease,
        },
    )
    .await?;
    let result = async {
        let bucket = env.bucket("FILES").map_err(io)?;
        let key = pack_key(&g.tenant, p);
        let expected = digest_from_hex(&p.0)?;
        let hash = Rc::new(RefCell::new(Sha256::new()));
        let update = hash.clone();
        let input = req.stream().map_err(io)?;
        let stream = paced_stream(req, env, g, true, input, size)
            .await?
            .inspect_ok(move |chunk| update.borrow_mut().update(chunk));
        bucket
            .put(&key, FixedLengthStream::wrap(stream, size))
            .sha256(expected.to_vec())
            .execute()
            .await
            .map_err(io)?;
        let actual: [u8; 32] = hash.take().finalize().into();
        if actual != expected {
            return Err(Errno::EIO);
        }
        let entries = verified_entries(&bucket, &key, size as u32).await?;
        storage(
            req,
            env,
            g,
            v,
            Action::Seal {
                pack_id: p.clone(),
                id: id.clone(),
                lease,
                entries,
            },
        )
        .await
    }
    .await;
    if result.is_err() {
        let _ = storage(
            req,
            env,
            g,
            v,
            Action::Abandon {
                pack_id: p.clone(),
                id,
            },
        )
        .await;
    }
    result
}
async fn range(bucket: &Bucket, key: &str, offset: u32, len: u32) -> VResult<worker::Object> {
    bucket
        .get(key)
        .range(worker::Range::OffsetWithLength {
            offset: offset.into(),
            length: len.into(),
        })
        .execute()
        .await
        .map_err(io)?
        .ok_or(Errno::EIO)
}
async fn range_bytes(bucket: &Bucket, key: &str, offset: u32, len: u32) -> VResult<Vec<u8>> {
    let obj = range(bucket, key, offset, len).await?;
    let bytes = obj.body().ok_or(Errno::EIO)?.bytes().await.map_err(io)?;
    if bytes.len() != len as usize {
        return Err(Errno::EIO);
    }
    Ok(bytes)
}
async fn verified_entries(bucket: &Bucket, key: &str, size: u32) -> VResult<Vec<PackIndexEntry>> {
    let footer = size
        .checked_sub(PACK_FOOTER_BYTES as u32)
        .ok_or(Errno::EIO)?;
    let (len, sha) =
        decode_pack_footer(&range_bytes(bucket, key, footer, PACK_FOOTER_BYTES as u32).await?)?;
    let payload = footer.checked_sub(len).ok_or(Errno::EIO)?;
    let trailer =
        decode_pack_trailer_bytes(&range_bytes(bucket, key, payload, len).await?, sha, payload)?;
    // The index authenticates locations. Independently authenticate the actual block content
    // before admitting those locations. Read the payload in a single streaming R2 request.
    let mut offset = 0;
    for e in &trailer.entries {
        if e.offset != offset || e.len == 0 {
            return Err(Errno::EIO);
        }
        offset = offset.checked_add(e.len).ok_or(Errno::EIO)?;
    }
    if offset != payload {
        return Err(Errno::EIO);
    }
    if payload > 0 {
        let obj = range(bucket, key, 0, payload).await?;
        let mut stream = obj.body().ok_or(Errno::EIO)?.stream().map_err(io)?;
        let (mut index, mut seen, mut block) = (0, 0usize, Sha256::new());
        while let Some(bytes) = stream.next().await {
            let bytes = bytes.map_err(io)?;
            let mut input = bytes.as_slice();
            while !input.is_empty() {
                let e = trailer.entries.get(index).ok_or(Errno::EIO)?;
                let n = input.len().min(e.len as usize - seen);
                block.update(&input[..n]);
                seen += n;
                input = &input[n..];
                if seen == e.len as usize {
                    let actual: [u8; 32] = std::mem::take(&mut block).finalize().into();
                    if actual != e.digest {
                        return Err(Errno::EIO);
                    }
                    index += 1;
                    seen = 0;
                }
            }
        }
        if index != trailer.entries.len() || seen != 0 {
            return Err(Errno::EIO);
        }
    }
    Ok(trailer.entries)
}
async fn download(
    req: &Request,
    env: &Env,
    g: &Grant,
    v: &VolumeId,
    p: &PackId,
) -> VResult<Response> {
    let requested_range = header(req, "Range")?;
    let size: u64 = meta(
        req,
        env,
        g,
        v,
        Action::Stat {
            pack_id: p.clone(),
            read: req.method() == Method::Get,
            range: requested_range.clone(),
        },
    )
    .await?;
    let headers = Headers::new();
    headers.set("Accept-Ranges", "bytes").map_err(io)?;
    headers
        .set("Content-Type", "application/octet-stream")
        .map_err(io)?;
    headers.set("ETag", &format!("\"{}\"", p.0)).map_err(io)?;
    let (start, len, status) = if let Some(r) = requested_range {
        let Some((a, b)) = os_core::byte_range(&r, size) else {
            headers
                .set("Content-Range", &format!("bytes */{size}"))
                .map_err(io)?;
            return Ok(Response::empty()
                .map_err(io)?
                .with_headers(headers)
                .with_status(416));
        };
        headers
            .set("Content-Range", &format!("bytes {a}-{b}/{size}"))
            .map_err(io)?;
        (a, b - a + 1, 206)
    } else {
        (0, size, 200)
    };
    headers
        .set("Content-Length", &len.to_string())
        .map_err(io)?;
    let body = if req.method() == Method::Head {
        Response::empty().map_err(io)?
    } else {
        let object = range(
            &env.bucket("FILES").map_err(io)?,
            &pack_key(&g.tenant, p),
            start as u32,
            len as u32,
        )
        .await?;
        let input = object.body().ok_or(Errno::EIO)?.stream().map_err(io)?;
        Response::from_stream(paced_stream(req, env, g, false, input, len).await?).map_err(io)?
    };
    Ok(body.with_status(status).with_headers(headers))
}

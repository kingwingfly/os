//! Host-native OCI Distribution v1.1 CLI (`cargo xtask oci ...`) built on pure-Rust std
//! `TcpStream` HTTP/1.1 with zero external HTTP crates (`docs/architecture/contract.md` §2.15; #81).

use abi::Errno;
use abi::fs::{OpenOptions, Timespec, WriteAt};
use abi::registry::OciReference;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use cowfs::native_sqlite::{NativePackStore, NativeSqliteHeadStore};
use cowfs::{
    CowFs, CowFsConfig, CowFsOpenMode, OciClient, OciHttpReply, OciPushOptions,
    OciTarExportOptions, OciTarImportOptions, OciTarLayerInput, OciTransport, SetuidPolicy,
    attach_ed25519_signature, export_and_push_oci_image, export_cowfs_oci_tar_layer,
    import_oci_tar_layers, mirror_oci_artifact, pull_cowfs_snapshot, push_cowfs_snapshot,
    verify_ed25519_referrers,
};
use cowtree::{VolumeId, WriterMode};
use ed25519_dalek::{Signer, SigningKey};
use os_image::{
    Detached, SIGNING_DOMAIN_OCI_ARTIFACT_V1, Trust, digest, hex, signing_message, unhex,
};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use vfs::{BoxFuture, Cred, Filesystem};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const OCI_HELP: &str = "\
cargo xtask oci push-snapshot --store DIR --volume VOL [--snapshot SNAP] --registry URL --ref REPO:TAG [--shard-max N] [AUTH]\n\
cargo xtask oci pull-snapshot --store DIR --volume VOL [--snapshot NAME] --registry URL --ref REPO:TAG [--trust FILE] [AUTH]\n\
cargo xtask oci import-tar --store DIR --volume VOL [--snapshot NAME] [--strip-setuid] --tar FILE [--tar FILE ...] [--diff-id SHA256]\n\
cargo xtask oci export-tar --store DIR --volume VOL [--snapshot SNAP] --out FILE [--uncompressed]\n\
cargo xtask oci push-tar (--store DIR --volume VOL [--snapshot SNAP] | --root DIR) --registry URL --ref REPO:TAG [--arch ARCH] [--os OS] [--uncompressed] [AUTH]\n\
cargo xtask oci sign --registry URL --ref REPO:TAG --key-file FILE [AUTH]\n\
cargo xtask oci verify --registry URL --ref REPO:TAG --trust FILE [AUTH]\n\
cargo xtask oci mirror --src-registry URL --src-ref REPO:TAG --dst-registry URL --dst-ref REPO:TAG [--referrers] [SRC/DST AUTH]\n\
AUTH: [--user U --password P] | [--token T --instance I]";

#[derive(Clone, Debug, Default)]
pub struct NativeAuth {
    pub user: Option<String>,
    pub password: Option<String>,
    pub token: Option<String>,
    pub instance: Option<String>,
}

/// Pure-Rust `std::net::TcpStream` HTTP/1.1 [`OciTransport`] for local/host registries.
pub struct NativeOciTransport {
    base_host: String,
    base_port: u16,
    auth: NativeAuth,
}

const MAX_HTTP_BODY_BYTES: usize = 64 * 1024 * 1024;

impl NativeOciTransport {
    pub fn new(base_url: &str, auth: NativeAuth) -> Result<Self> {
        let (host, port, _) = parse_http_url(base_url)?;
        Ok(Self {
            base_host: host,
            base_port: port,
            auth,
        })
    }

    fn execute(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> vfs::Result<OciHttpReply> {
        if method.bytes().any(|b| matches!(b, b'\r' | b'\n' | b' '))
            || url.bytes().any(|b| matches!(b, b'\r' | b'\n'))
        {
            return Err(Errno::EINVAL);
        }
        let (host, port, path_and_query) = if url.starts_with("http://") {
            parse_http_url(url).map_err(|_| Errno::EINVAL)?
        } else if url.starts_with('/') {
            (self.base_host.clone(), self.base_port, url.to_string())
        } else {
            return Err(Errno::EPROTONOSUPPORT);
        };
        let same_origin = host.eq_ignore_ascii_case(&self.base_host) && port == self.base_port;
        for (k, v) in headers {
            if k.bytes().any(|b| matches!(b, b'\r' | b'\n' | b':'))
                || v.bytes().any(|b| matches!(b, b'\r' | b'\n'))
            {
                return Err(Errno::EINVAL);
            }
            if !same_origin
                && (k.eq_ignore_ascii_case("authorization")
                    || k.eq_ignore_ascii_case("x-process-token")
                    || k.eq_ignore_ascii_case("x-os-instance"))
            {
                return Err(Errno::EACCES);
            }
        }

        let mut stream = TcpStream::connect((host.as_str(), port)).map_err(|_| Errno::ENOTCONN)?;
        let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(60)));

        let mut req = format!(
            "{method} {path_and_query} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n"
        );
        let mut has_len = false;
        for (k, v) in headers {
            if k.eq_ignore_ascii_case("content-length") {
                has_len = true;
            }
            req.push_str(k);
            req.push_str(": ");
            req.push_str(v);
            req.push_str("\r\n");
        }
        if !has_len && (!body.is_empty() || matches!(method, "POST" | "PUT" | "PATCH")) {
            req.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        req.push_str("\r\n");

        stream
            .write_all(req.as_bytes())
            .map_err(|_| Errno::ENOTCONN)?;
        if !body.is_empty() {
            stream.write_all(body).map_err(|_| Errno::ENOTCONN)?;
        }
        stream.flush().map_err(|_| Errno::ENOTCONN)?;

        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).map_err(|_| Errno::EIO)?;
        let mut parts = status_line.split_ascii_whitespace();
        let _http_ver = parts.next().ok_or(Errno::EIO)?;
        let status: u16 = parts
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or(Errno::EIO)?;

        let mut resp_headers: Vec<(String, String)> = Vec::new();
        let mut content_length: Option<usize> = None;
        let mut chunked = false;
        loop {
            let mut line = String::new();
            let n = reader.read_line(&mut line).map_err(|_| Errno::EIO)?;
            if n == 0 || line == "\r\n" || line == "\n" {
                break;
            }
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if let Some((k, v)) = trimmed.split_once(':') {
                let key = k.trim().to_string();
                let val = v.trim().to_string();
                if key.eq_ignore_ascii_case("content-length") {
                    content_length = val.parse().ok();
                } else if key.eq_ignore_ascii_case("transfer-encoding")
                    && val.to_ascii_lowercase().contains("chunked")
                {
                    chunked = true;
                }
                resp_headers.push((key, val));
            }
        }

        let resp_body = if method.eq_ignore_ascii_case("HEAD")
            || status == 204
            || status == 304
            || (100..200).contains(&status)
        {
            Vec::new()
        } else if chunked {
            read_chunked_body(&mut reader)?
        } else if let Some(len) = content_length {
            if len > MAX_HTTP_BODY_BYTES {
                return Err(Errno::EFBIG);
            }
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf).map_err(|_| Errno::EIO)?;
            buf
        } else {
            let mut buf = Vec::new();
            reader
                .take((MAX_HTTP_BODY_BYTES as u64) + 1)
                .read_to_end(&mut buf)
                .map_err(|_| Errno::EIO)?;
            if buf.len() > MAX_HTTP_BODY_BYTES {
                return Err(Errno::EFBIG);
            }
            buf
        };

        Ok(OciHttpReply {
            status,
            headers: resp_headers,
            body: resp_body,
        })
    }
}

impl OciTransport for NativeOciTransport {
    fn request<'a>(
        &'a self,
        method: &'a str,
        url: &'a str,
        headers: &'a [(String, String)],
        body: &'a [u8],
    ) -> BoxFuture<'a, OciHttpReply> {
        Box::pin(async move { self.execute(method, url, headers, body) })
    }

    fn token_auth_headers(&self) -> Vec<(String, String)> {
        if let (Some(tok), Some(inst)) = (&self.auth.token, &self.auth.instance) {
            return vec![
                ("X-Process-Token".into(), tok.clone()),
                ("X-OS-Instance".into(), inst.clone()),
            ];
        }
        if let (Some(user), Some(pass)) = (&self.auth.user, &self.auth.password) {
            let encoded = STANDARD.encode(format!("{user}:{pass}"));
            return vec![("Authorization".into(), format!("Basic {encoded}"))];
        }
        Vec::new()
    }
}

fn parse_http_url(url: &str) -> Result<(String, u16, String)> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("only http:// URLs are supported by xtask oci (got {url})"))?;
    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], rest[idx..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.contains(']') || authority.contains("]:") => {
            (h.trim_matches(['[', ']']).to_string(), p.parse::<u16>()?)
        }
        _ => (authority.trim_matches(['[', ']']).to_string(), 80),
    };
    if host.is_empty() {
        return Err(format!("empty host in URL {url}").into());
    }
    Ok((host, port, path))
}

fn read_chunked_body<R: BufRead>(reader: &mut R) -> vfs::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let mut size_line = String::new();
        if reader.read_line(&mut size_line).map_err(|_| Errno::EIO)? == 0 {
            return Err(Errno::EIO);
        }
        let hex_part = size_line.split(';').next().unwrap_or("").trim();
        let chunk_len = usize::from_str_radix(hex_part, 16).map_err(|_| Errno::EIO)?;
        if chunk_len == 0 {
            loop {
                let mut trailer = String::new();
                let n = reader.read_line(&mut trailer).map_err(|_| Errno::EIO)?;
                if n == 0 || trailer == "\r\n" || trailer == "\n" {
                    break;
                }
            }
            break;
        }
        let start = out.len();
        let end = start.checked_add(chunk_len).ok_or(Errno::EFBIG)?;
        if end > MAX_HTTP_BODY_BYTES {
            return Err(Errno::EFBIG);
        }
        out.resize(end, 0);
        reader
            .read_exact(&mut out[start..end])
            .map_err(|_| Errno::EIO)?;
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).map_err(|_| Errno::EIO)?;
    }
    Ok(out)
}

fn now_timespec() -> Timespec {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    Timespec {
        sec: dur.as_secs(),
        nsec: dur.subsec_nanos(),
    }
}

fn run_sync<T>(fut: impl std::future::Future<Output = vfs::Result<T>>) -> Result<T> {
    match vfs::now_or_never(fut) {
        Some(Ok(v)) => Ok(v),
        Some(Err(e)) => Err(format!("cowfs/oci error: {e:?}").into()),
        None => Err("unexpected pending future in native xtask oci".into()),
    }
}

fn open_native_stores(dir: &Path) -> Result<(Rc<NativeSqliteHeadStore>, Rc<NativePackStore>)> {
    fs::create_dir_all(dir)?;
    let head =
        Rc::new(NativeSqliteHeadStore::open(dir).map_err(|e| format!("open head store: {e:?}"))?);
    let packs = Rc::new(NativePackStore::open(dir).map_err(|e| format!("open pack store: {e:?}"))?);
    Ok((head, packs))
}

fn load_signing_key(path: &Path) -> Result<SigningKey> {
    let mut bytes = fs::read(path)?;
    let mut seed: [u8; 32] = if bytes.len() == 32 {
        bytes.as_slice().try_into()?
    } else {
        unhex(std::str::from_utf8(&bytes)?.trim())?
    };
    let key = SigningKey::from_bytes(&seed);
    seed.fill(0);
    bytes.fill(0);
    Ok(key)
}

fn populate_cowfs_from_host_dir(
    fs: &CowFs<NativeSqliteHeadStore, NativePackStore>,
    host_root: &Path,
) -> Result<()> {
    let mut cred = Cred::root();
    cred.umask = 0;
    populate_dir_rec(fs, &cred, fs.root(), host_root)?;
    run_sync(fs.commit_tx_group())?;
    Ok(())
}

fn populate_dir_rec(
    fs: &CowFs<NativeSqliteHeadStore, NativePackStore>,
    cred: &Cred,
    dir_handle: abi::fs::Handle,
    host_dir: &Path,
) -> Result<()> {
    let mut entries: Vec<_> =
        fs::read_dir(host_dir)?.collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "non-UTF-8 filename in --root")?;
        let meta = entry.metadata()?;
        let path = entry.path();
        if meta.is_dir() {
            let child = run_sync(fs.mkdir(cred, &dir_handle, &name, 0o755))?;
            populate_dir_rec(fs, cred, child.handle, &path)?;
        } else if meta.is_file() {
            let data = fs::read(&path)?;
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                (meta.permissions().mode() & 0o777) as u16
            };
            #[cfg(not(unix))]
            let mode = 0o644u16;
            let mut create_opts = OpenOptions::new();
            create_opts.read(true).write(true).create_new(true);
            let (_, open_ref) = run_sync(fs.create(cred, &dir_handle, &name, mode, &create_opts))?;
            run_sync(fs.write_at(&open_ref, &data, WriteAt::Offset(0)))?;
            run_sync(fs.release(&open_ref))?;
        } else if meta.file_type().is_symlink() {
            let target = fs::read_link(&path)?;
            let target_str = target
                .to_str()
                .ok_or("non-UTF-8 symlink target in --root")?;
            run_sync(fs.symlink(cred, &dir_handle, &name, target_str))?;
        }
    }
    Ok(())
}

pub fn run(args: Vec<String>) -> Result<()> {
    let Some((sub, rest)) = args.split_first() else {
        println!("{OCI_HELP}");
        return Ok(());
    };
    if matches!(sub.as_str(), "help" | "--help" | "-h") {
        println!("{OCI_HELP}");
        return Ok(());
    }

    let mut opts: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut iter = rest.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--strip-setuid" | "--uncompressed" | "--referrers" => {
                opts.entry(arg.clone()).or_default().push("true".into());
            }
            k if k.starts_with("--") => {
                if let Some((flag, val)) = k.split_once('=') {
                    opts.entry(flag.to_string())
                        .or_default()
                        .push(val.to_string());
                } else {
                    let val = iter
                        .next()
                        .ok_or_else(|| format!("missing value for {k}"))?;
                    opts.entry(k.to_string()).or_default().push(val.clone());
                }
            }
            other => return Err(format!("unexpected argument {other}").into()),
        }
    }

    let get = |k: &str| opts.get(k).and_then(|v| v.first()).map(String::as_str);
    let req = |k: &str| get(k).ok_or_else(|| format!("missing required option {k}"));
    let auth_for = |prefix: &str| NativeAuth {
        user: get(&format!("--{prefix}user")).map(str::to_owned),
        password: get(&format!("--{prefix}password")).map(str::to_owned),
        token: get(&format!("--{prefix}token")).map(str::to_owned),
        instance: get(&format!("--{prefix}instance")).map(str::to_owned),
    };

    match sub.as_str() {
        "push-snapshot" => {
            let (head, packs) = open_native_stores(Path::new(req("--store")?))?;
            let vol = VolumeId(req("--volume")?.to_string());
            let registry = req("--registry")?;
            let oci_ref = OciReference::parse(req("--ref")?).ok_or("invalid --ref")?;
            let shard_max = get("--shard-max")
                .map(|s| s.parse::<usize>())
                .transpose()?
                .unwrap_or(128);
            let client = OciClient::new(
                registry,
                Rc::new(NativeOciTransport::new(registry, auth_for(""))?),
            );
            let resp = run_sync(push_cowfs_snapshot(
                &*head,
                &*packs,
                &vol,
                get("--snapshot"),
                &client,
                &oci_ref.repo,
                &oci_ref.reference,
                OciPushOptions {
                    max_layers_per_shard: shard_max,
                    ..OciPushOptions::default()
                },
            ))?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        "pull-snapshot" => {
            let (head, packs) = open_native_stores(Path::new(req("--store")?))?;
            let vol = VolumeId(req("--volume")?.to_string());
            let registry = req("--registry")?;
            let oci_ref = OciReference::parse(req("--ref")?).ok_or("invalid --ref")?;
            let trust: Option<Trust> = get("--trust")
                .map(|p| -> Result<Trust> { Ok(os_image::parse(&fs::read(p)?)?) })
                .transpose()?;
            let client = OciClient::new(
                registry,
                Rc::new(NativeOciTransport::new(registry, auth_for(""))?),
            );
            let resp = run_sync(pull_cowfs_snapshot(
                &client,
                &oci_ref.repo,
                &oci_ref.reference,
                &*head,
                &*packs,
                &vol,
                get("--snapshot"),
                now_timespec(),
                trust.as_ref(),
            ))?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        "import-tar" => {
            let (head, packs) = open_native_stores(Path::new(req("--store")?))?;
            let vol = VolumeId(req("--volume")?.to_string());
            let tar_paths = opts.get("--tar").ok_or("missing required option --tar")?;
            let diff_ids = opts.get("--diff-id").cloned().unwrap_or_default();
            let mut raw_layers: Vec<Vec<u8>> = Vec::with_capacity(tar_paths.len());
            for p in tar_paths {
                raw_layers.push(fs::read(p)?);
            }
            let inputs: Vec<OciTarLayerInput<'_>> = raw_layers
                .iter()
                .enumerate()
                .map(|(i, b)| OciTarLayerInput {
                    bytes: b.as_slice(),
                    expected_diff_id: diff_ids.get(i).map(String::as_str),
                })
                .collect();
            let import_opts = OciTarImportOptions {
                setuid_policy: if get("--strip-setuid").is_some() {
                    SetuidPolicy::Strip
                } else {
                    SetuidPolicy::Reject
                },
                ..Default::default()
            };
            let cfg = CowFsConfig::local_native(Rc::new(now_timespec));
            let report = run_sync(import_oci_tar_layers(
                head,
                packs,
                vol,
                &inputs,
                &import_opts,
                get("--snapshot"),
                cfg,
            ))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "volume": report.volume,
                    "root": report.root,
                    "epoch": report.epoch,
                    "snapshot": report.snapshot,
                    "diff_ids": report.diff_ids,
                    "entries_imported": report.entries_imported,
                    "uncompressed_bytes": report.uncompressed_bytes,
                }))?
            );
        }
        "export-tar" => {
            let (head, packs) = open_native_stores(Path::new(req("--store")?))?;
            let vol = VolumeId(req("--volume")?.to_string());
            let mode = match get("--snapshot") {
                Some(s) => CowFsOpenMode::Snapshot(s.to_string()),
                None => CowFsOpenMode::ReadOnly,
            };
            let cfg = CowFsConfig::local_native(Rc::new(now_timespec));
            let fs = run_sync(CowFs::open(head, packs, vol, mode, cfg))?;
            let export_opts = OciTarExportOptions {
                compress: get("--uncompressed").is_none(),
                reproducible: true,
                ..Default::default()
            };
            let layer = run_sync(export_cowfs_oci_tar_layer(&fs, &export_opts))?;
            let _ = run_sync(fs.close_clean());
            fs::write(req("--out")?, &layer.bytes)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "media_type": layer.media_type,
                    "diff_id": layer.diff_id,
                    "blob_digest": layer.blob_digest,
                    "blob_size": layer.blob_size,
                    "uncompressed_size": layer.uncompressed_size,
                    "entries_exported": layer.entries_exported,
                }))?
            );
        }
        "push-tar" => {
            let registry = req("--registry")?;
            let oci_ref = OciReference::parse(req("--ref")?).ok_or("invalid --ref")?;
            let client = OciClient::new(
                registry,
                Rc::new(NativeOciTransport::new(registry, auth_for(""))?),
            );
            let export_opts = OciTarExportOptions {
                compress: get("--uncompressed").is_none(),
                reproducible: true,
                ..Default::default()
            };
            let arch = get("--arch").unwrap_or("amd64");
            let os = get("--os").unwrap_or("linux");

            if let Some(root_dir) = get("--root") {
                let tmp_dir = std::env::temp_dir().join(format!(
                    "xtask-oci-push-tar-{}-{}",
                    std::process::id(),
                    now_timespec().nsec
                ));
                let _ = fs::remove_dir_all(&tmp_dir);
                let (head, packs) = open_native_stores(&tmp_dir)?;
                let vol = VolumeId("push-tar-tmp".into());
                run_sync(CowFs::format_volume(
                    &*head,
                    &*packs,
                    vol.clone(),
                    0,
                    0,
                    0o755,
                    now_timespec(),
                ))?;
                let cfg = CowFsConfig::local_native(Rc::new(now_timespec));
                let cowfs = run_sync(CowFs::open(
                    head,
                    packs,
                    vol,
                    CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
                    cfg,
                ))?;
                populate_cowfs_from_host_dir(&cowfs, Path::new(root_dir))?;
                let resp = run_sync(export_and_push_oci_image(
                    &cowfs,
                    &client,
                    &oci_ref.repo,
                    &oci_ref.reference,
                    &export_opts,
                    arch,
                    os,
                    None,
                ))?;
                let _ = run_sync(cowfs.close_clean());
                let _ = fs::remove_dir_all(&tmp_dir);
                println!("{}", serde_json::to_string_pretty(&resp)?);
            } else {
                let (head, packs) = open_native_stores(Path::new(req("--store")?))?;
                let vol = VolumeId(req("--volume")?.to_string());
                let mode = match get("--snapshot") {
                    Some(s) => CowFsOpenMode::Snapshot(s.to_string()),
                    None => CowFsOpenMode::ReadOnly,
                };
                let cfg = CowFsConfig::local_native(Rc::new(now_timespec));
                let cowfs = run_sync(CowFs::open(head, packs, vol, mode, cfg))?;
                let resp = run_sync(export_and_push_oci_image(
                    &cowfs,
                    &client,
                    &oci_ref.repo,
                    &oci_ref.reference,
                    &export_opts,
                    arch,
                    os,
                    None,
                ))?;
                let _ = run_sync(cowfs.close_clean());
                println!("{}", serde_json::to_string_pretty(&resp)?);
            }
        }
        "sign" => {
            let registry = req("--registry")?;
            let oci_ref = OciReference::parse(req("--ref")?).ok_or("invalid --ref")?;
            let key = load_signing_key(Path::new(req("--key-file")?))?;
            let client = OciClient::new(
                registry,
                Rc::new(NativeOciTransport::new(registry, auth_for(""))?),
            );
            let (subject_digest, subject_mt, subject_bytes) =
                run_sync(client.get_manifest(&oci_ref.repo, &oci_ref.reference))?;
            let sig_payload = serde_json::to_vec(&Detached {
                format: "os.signature".into(),
                version: 1,
                key: digest(key.verifying_key().as_bytes()),
                signature: hex(&key
                    .sign(&signing_message(
                        SIGNING_DOMAIN_OCI_ARTIFACT_V1,
                        &subject_bytes,
                    )?)
                    .to_bytes()),
            })?;
            let ref_digest = run_sync(attach_ed25519_signature(
                &client,
                &oci_ref.repo,
                &subject_digest,
                &subject_mt,
                subject_bytes.len() as u64,
                &sig_payload,
            ))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "subject_digest": subject_digest,
                    "referrer_digest": ref_digest,
                    "key": digest(key.verifying_key().as_bytes()),
                }))?
            );
        }
        "verify" => {
            let registry = req("--registry")?;
            let oci_ref = OciReference::parse(req("--ref")?).ok_or("invalid --ref")?;
            let trust: Trust = os_image::parse(&fs::read(req("--trust")?)?)?;
            let client = OciClient::new(
                registry,
                Rc::new(NativeOciTransport::new(registry, auth_for(""))?),
            );
            let (subject_digest, key_id) = run_sync(verify_ed25519_referrers(
                &client,
                &oci_ref.repo,
                &oci_ref.reference,
                &trust,
            ))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "verified": true,
                    "subject_digest": subject_digest,
                    "key": key_id,
                }))?
            );
        }
        "mirror" => {
            let src_reg = req("--src-registry")?;
            let dst_reg = req("--dst-registry")?;
            let src_ref = OciReference::parse(req("--src-ref")?).ok_or("invalid --src-ref")?;
            let dst_ref = OciReference::parse(req("--dst-ref")?).ok_or("invalid --dst-ref")?;
            let src_client = OciClient::new(
                src_reg,
                Rc::new(NativeOciTransport::new(src_reg, auth_for("src-"))?),
            );
            let dst_client = OciClient::new(
                dst_reg,
                Rc::new(NativeOciTransport::new(dst_reg, auth_for("dst-"))?),
            );
            let digest = run_sync(mirror_oci_artifact(
                &src_client,
                &src_ref.repo,
                &src_ref.reference,
                &dst_client,
                &dst_ref.repo,
                &dst_ref.reference,
                get("--referrers").is_some(),
            ))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "mirrored_digest": digest,
                    "dst_repo": dst_ref.repo,
                    "dst_reference": dst_ref.reference,
                }))?
            );
        }
        other => return Err(format!("unknown oci subcommand {other}\n{OCI_HELP}").into()),
    }
    Ok(())
}

//! Zero-dependency bounded HTTP/1.1 `ClusterStore` client talking to Worker `/api/cluster/rpc`.

use abi::Errno;
use abi::cluster_state::{
    CLUSTER_STATE_PROTOCOL, ClusterCall, ClusterError, ClusterReply, ClusterRpcRequest,
};
use os_cluster_state::{BoxFuture, ClusterGrant, ClusterStore, WatchBatch, WatchCursor};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const MAX_RESPONSE_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_HEADER_LINES: usize = 128;
const MAX_HEADER_LINE_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug)]
pub struct HttpClusterStore {
    base_url: String,
    cluster: String,
    token: Option<String>,
    instance_id: Option<String>,
    tenant: String,
    timeout: Duration,
}

impl HttpClusterStore {
    pub fn new(
        base_url: impl Into<String>,
        cluster: impl Into<String>,
        tenant: impl Into<String>,
        token: Option<String>,
        instance_id: Option<String>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            cluster: cluster.into(),
            token,
            instance_id,
            tenant: tenant.into(),
            timeout: Duration::from_secs(15),
        }
    }

    async fn post_rpc(&self, call: ClusterCall) -> Result<ClusterReply, ClusterError> {
        let trimmed_base = self.base_url.trim_end_matches('/');
        let endpoint = if trimmed_base.ends_with("/api/cluster/rpc") {
            trimmed_base.to_string()
        } else {
            format!("{trimmed_base}/api/cluster/rpc")
        };
        let (host, port, path, host_header) =
            parse_http_url(&endpoint).map_err(|msg| ClusterError::because(Errno::EINVAL, msg))?;
        validate_req_target(&path)?;
        validate_req_target(&host_header)?;
        let req_body = serde_json::to_vec(&ClusterRpcRequest {
            version: CLUSTER_STATE_PROTOCOL,
            cluster: self.cluster.clone(),
            call,
        })
        .map_err(|e| ClusterError::because(Errno::EINVAL, e.to_string()))?;

        let fut = async {
            let addr = if host.contains(':') && !host.starts_with('[') {
                format!("[{host}]:{port}")
            } else {
                format!("{host}:{port}")
            };
            let mut stream = TcpStream::connect(&addr)
                .await
                .map_err(|e| ClusterError::because(Errno::EIO, format!("connect {addr}: {e}")))?;
            let _ = stream.set_nodelay(true);

            let mut head = String::with_capacity(256);
            head.push_str(&format!(
                "POST {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
                req_body.len()
            ));
            if let Some(ref tok) = self.token {
                validate_hdr(tok)?;
                head.push_str(&format!("X-Process-Token: {tok}\r\n"));
            }
            if let Some(ref inst) = self.instance_id {
                validate_hdr(inst)?;
                head.push_str(&format!("X-OS-Instance: {inst}\r\n"));
            }
            validate_hdr(&self.tenant)?;
            head.push_str(&format!("X-OS-Tenant: {}\r\n", self.tenant));
            head.push_str("\r\n");

            stream
                .write_all(head.as_bytes())
                .await
                .map_err(|e| ClusterError::because(Errno::EIO, format!("write head: {e}")))?;
            stream
                .write_all(&req_body)
                .await
                .map_err(|e| ClusterError::because(Errno::EIO, format!("write body: {e}")))?;
            stream
                .flush()
                .await
                .map_err(|e| ClusterError::because(Errno::EIO, format!("flush: {e}")))?;

            let mut reader = BufReader::new(stream);
            let Some(status_line) = read_line_bounded(&mut reader, MAX_HEADER_LINE_BYTES).await?
            else {
                return Err(ClusterError::because(Errno::EIO, "empty HTTP response"));
            };
            let status: u16 = status_line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| {
                    ClusterError::because(Errno::EIO, format!("bad HTTP status: {status_line:?}"))
                })?;

            let mut content_length: Option<usize> = None;
            let mut chunked = false;
            let mut saw_end = false;
            for _ in 0..MAX_HEADER_LINES {
                let Some(line) = read_line_bounded(&mut reader, MAX_HEADER_LINE_BYTES).await?
                else {
                    return Err(ClusterError::because(
                        Errno::EIO,
                        "truncated HTTP response headers",
                    ));
                };
                let trimmed = line.trim_end_matches(['\r', '\n']);
                if trimmed.is_empty() {
                    saw_end = true;
                    break;
                }
                if let Some((k, v)) = trimmed.split_once(':') {
                    let k = k.trim();
                    let v = v.trim();
                    if k.eq_ignore_ascii_case("content-length") {
                        content_length = v.parse::<usize>().ok();
                    } else if k.eq_ignore_ascii_case("transfer-encoding")
                        && v.to_ascii_lowercase().contains("chunked")
                    {
                        chunked = true;
                    }
                }
            }
            if !saw_end {
                return Err(ClusterError::because(
                    Errno::E2BIG,
                    "too many HTTP response headers",
                ));
            }

            let body = if chunked {
                read_chunked(&mut reader).await?
            } else if let Some(len) = content_length {
                if len > MAX_RESPONSE_BODY_BYTES {
                    return Err(ClusterError::because(
                        Errno::EFBIG,
                        "HTTP response too large",
                    ));
                }
                let mut buf = vec![0u8; len];
                reader
                    .read_exact(&mut buf)
                    .await
                    .map_err(|e| ClusterError::because(Errno::EIO, format!("read body: {e}")))?;
                buf
            } else {
                let mut buf = Vec::new();
                reader
                    .take((MAX_RESPONSE_BODY_BYTES as u64) + 1)
                    .read_to_end(&mut buf)
                    .await
                    .map_err(|e| ClusterError::because(Errno::EIO, format!("read body: {e}")))?;
                if buf.len() > MAX_RESPONSE_BODY_BYTES {
                    return Err(ClusterError::because(
                        Errno::EFBIG,
                        "HTTP response too large",
                    ));
                }
                buf
            };

            if status == 200 {
                serde_json::from_slice::<ClusterReply>(&body)
                    .map_err(|e| ClusterError::because(Errno::EIO, format!("bad reply JSON: {e}")))
            } else if let Ok(ce) = serde_json::from_slice::<ClusterError>(&body) {
                Err(ce)
            } else {
                let errno = match status {
                    401 | 403 => Errno::EACCES,
                    404 => Errno::ENOENT,
                    409 => Errno::EBUSY,
                    412 => Errno::ESTALE,
                    507 => Errno::ENOSPC,
                    _ => Errno::EIO,
                };
                let snippet = String::from_utf8_lossy(&body[..body.len().min(256)]);
                Err(ClusterError::because(
                    errno,
                    format!("HTTP {status}: {snippet}"),
                ))
            }
        };

        tokio::time::timeout(self.timeout, fut)
            .await
            .map_err(|_| ClusterError::because(Errno::ETIMEDOUT, "cluster RPC timed out"))?
    }
}

impl ClusterStore for HttpClusterStore {
    fn rpc<'a>(
        &'a self,
        _grant: &'a ClusterGrant,
        call: ClusterCall,
        _now_secs: u64,
    ) -> BoxFuture<'a, Result<ClusterReply, ClusterError>> {
        Box::pin(async move { self.post_rpc(call).await })
    }

    fn poll_watch<'a>(
        &'a self,
        _grant: &'a ClusterGrant,
        _cursor: &'a mut WatchCursor,
        _limit: u32,
        _now_secs: u64,
    ) -> BoxFuture<'a, Result<WatchBatch, ClusterError>> {
        Box::pin(async move {
            Err(ClusterError::because(
                Errno::ENOSYS,
                "poll_watch not used by os-cni HTTP client",
            ))
        })
    }
}

fn validate_hdr(val: &str) -> Result<(), ClusterError> {
    if val
        .bytes()
        .any(|b| b == b'\r' || b == b'\n' || b == 0 || (b < 0x20 && b != b'\t') || b == 0x7f)
    {
        return Err(ClusterError::because(
            Errno::EINVAL,
            "invalid control character in HTTP header",
        ));
    }
    Ok(())
}

fn validate_req_target(val: &str) -> Result<(), ClusterError> {
    if val.is_empty() || val.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        return Err(ClusterError::because(
            Errno::EINVAL,
            "invalid character in HTTP request target or host",
        ));
    }
    Ok(())
}

async fn read_line_bounded<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<Option<String>, ClusterError> {
    let mut buf = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|e| ClusterError::because(Errno::EIO, format!("read HTTP line: {e}")))?;
        if available.is_empty() {
            if buf.is_empty() {
                return Ok(None);
            }
            return String::from_utf8(buf)
                .map(Some)
                .map_err(|_| ClusterError::because(Errno::EIO, "invalid UTF-8 in HTTP line"));
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            let take = pos + 1;
            if buf.len().saturating_add(take) > max_bytes {
                return Err(ClusterError::because(
                    Errno::E2BIG,
                    "HTTP header line too long",
                ));
            }
            buf.extend_from_slice(&available[..take]);
            reader.consume(take);
            return String::from_utf8(buf)
                .map(Some)
                .map_err(|_| ClusterError::because(Errno::EIO, "invalid UTF-8 in HTTP line"));
        }
        let avail_len = available.len();
        if buf.len().saturating_add(avail_len) > max_bytes {
            return Err(ClusterError::because(
                Errno::E2BIG,
                "HTTP header line too long",
            ));
        }
        buf.extend_from_slice(available);
        reader.consume(avail_len);
    }
}

fn parse_http_url(raw: &str) -> Result<(String, u16, String, String), String> {
    let rest = raw
        .strip_prefix("http://")
        .ok_or_else(|| format!("unsupported URL '{raw}' (expected http://)"))?;
    let (authority, path) = match rest.find(['/', '?']) {
        Some(idx) => {
            let p = &rest[idx..];
            let p = if p.starts_with('/') {
                p.to_string()
            } else {
                format!("/{p}")
            };
            (&rest[..idx], p)
        }
        None => (rest, "/".to_string()),
    };
    if authority.is_empty() {
        return Err(format!("missing host in URL '{raw}'"));
    }
    let (host, port, host_header) = if let Some(after_lbr) = authority.strip_prefix('[') {
        let close = after_lbr
            .find(']')
            .ok_or_else(|| format!("unterminated IPv6 host in '{raw}'"))?;
        let ip = &after_lbr[..close];
        let tail = &after_lbr[close + 1..];
        let port = if let Some(p) = tail.strip_prefix(':') {
            p.parse::<u16>()
                .map_err(|_| format!("invalid port in '{raw}'"))?
        } else if tail.is_empty() {
            80
        } else {
            return Err(format!("invalid authority in '{raw}'"));
        };
        let hh = if port == 80 {
            format!("[{ip}]")
        } else {
            format!("[{ip}]:{port}")
        };
        (ip.to_string(), port, hh)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        let port = p
            .parse::<u16>()
            .map_err(|_| format!("invalid port in '{raw}'"))?;
        let hh = if port == 80 {
            h.to_string()
        } else {
            format!("{h}:{port}")
        };
        (h.to_string(), port, hh)
    } else {
        (authority.to_string(), 80, authority.to_string())
    };
    Ok((host, port, path, host_header))
}

async fn read_chunked<R: AsyncBufReadExt + AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, ClusterError> {
    let mut out = Vec::new();
    loop {
        let Some(size_line) = read_line_bounded(reader, MAX_HEADER_LINE_BYTES).await? else {
            return Err(ClusterError::because(Errno::EIO, "truncated chunked body"));
        };
        let hex = size_line.trim().split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(hex, 16)
            .map_err(|_| ClusterError::because(Errno::EIO, format!("bad chunk size: {hex:?}")))?;
        if size == 0 {
            let mut saw_end = false;
            for _ in 0..MAX_HEADER_LINES {
                match read_line_bounded(reader, MAX_HEADER_LINE_BYTES).await? {
                    None => {
                        saw_end = true;
                        break;
                    }
                    Some(line) if line.trim_end_matches(['\r', '\n']).is_empty() => {
                        saw_end = true;
                        break;
                    }
                    Some(_) => {}
                }
            }
            if !saw_end {
                return Err(ClusterError::because(
                    Errno::E2BIG,
                    "too many HTTP chunk trailers",
                ));
            }
            break;
        }
        if out.len().saturating_add(size) > MAX_RESPONSE_BODY_BYTES {
            return Err(ClusterError::because(
                Errno::EFBIG,
                "chunked response too large",
            ));
        }
        let old_len = out.len();
        out.resize(old_len + size, 0);
        reader
            .read_exact(&mut out[old_len..])
            .await
            .map_err(|e| ClusterError::because(Errno::EIO, format!("read chunk data: {e}")))?;
        let mut crlf = [0u8; 2];
        reader
            .read_exact(&mut crlf)
            .await
            .map_err(|e| ClusterError::because(Errno::EIO, format!("read chunk CRLF: {e}")))?;
    }
    Ok(out)
}

//! Zero-dependency bounded HTTP/1.1 + RFC-6455 client WebSocket over `tokio::net::TcpStream`
//! for `os-native` kubelet control-plane, OCI registry, and remote-volume calls.

use crate::dev_backend::random_hex;
use crate::seat_server::{
    WS_HDR_LINE_MAX, WsEvent, read_bounded_line, ws_accept_key, ws_read_event, ws_write_frame,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

pub const DEFAULT_HTTP_MAX_BODY: usize = 64 * 1024 * 1024;
const MAX_HEADER_LINES: usize = 128;

#[derive(Clone, Debug)]
pub struct ParsedHttpUrl {
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
    pub origin: String,
    pub host_header: String,
}

impl ParsedHttpUrl {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let rest = if let Some(r) = raw.strip_prefix("http://") {
            r
        } else if let Some(r) = raw.strip_prefix("ws://") {
            r
        } else if raw.starts_with("https://") || raw.starts_with("wss://") {
            return Err(format!(
                "unsupported TLS scheme in '{raw}': os-native kubelet uses plain http:// / ws:// (terminate TLS at a local proxy or loopback)"
            ));
        } else {
            return Err(format!("invalid URL '{raw}': expected http:// or ws://"));
        };

        let (authority, path_and_query) = match rest.find(['/', '?']) {
            Some(idx) => {
                let auth = &rest[..idx];
                let pq = &rest[idx..];
                let pq = if pq.starts_with('/') {
                    pq.to_string()
                } else {
                    format!("/{pq}")
                };
                (auth, pq)
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

        let origin = format!("http://{host_header}");
        Ok(Self {
            host,
            port,
            path_and_query,
            origin,
            host_header,
        })
    }

    pub fn connect_addr(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Bounded HTTP/1.1 client over `tokio::net::TcpStream`.
#[derive(Clone, Debug)]
pub struct HttpClient {
    pub timeout: Duration,
    pub max_body_bytes: usize,
}

impl Default for HttpClient {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_body_bytes: DEFAULT_HTTP_MAX_BODY,
        }
    }
}

impl HttpClient {
    pub fn resolve_url(base_url: &str, path_or_url: &str) -> String {
        if path_or_url.starts_with("http://") || path_or_url.starts_with("https://") {
            path_or_url.to_string()
        } else {
            let base = base_url.trim_end_matches('/');
            if path_or_url.starts_with('/') {
                format!("{base}{path_or_url}")
            } else {
                format!("{base}/{path_or_url}")
            }
        }
    }

    pub async fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<HttpResponse, String> {
        let parsed = ParsedHttpUrl::parse(url)?;
        tokio::time::timeout(
            self.timeout,
            self.request_inner(method, &parsed, headers, body),
        )
        .await
        .map_err(|_| format!("HTTP {method} {url} timed out"))?
    }

    async fn request_inner(
        &self,
        method: &str,
        parsed: &ParsedHttpUrl,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<HttpResponse, String> {
        let mut stream = TcpStream::connect(parsed.connect_addr())
            .await
            .map_err(|e| format!("connect {}: {e}", parsed.connect_addr()))?;
        let _ = stream.set_nodelay(true);

        let mut req_head = String::with_capacity(256 + headers.len() * 48);
        req_head.push_str(method);
        req_head.push(' ');
        req_head.push_str(&parsed.path_and_query);
        req_head.push_str(" HTTP/1.1\r\n");
        req_head.push_str("Host: ");
        req_head.push_str(&parsed.host_header);
        req_head.push_str("\r\nConnection: close\r\n");

        let mut has_content_length = false;
        for (k, v) in headers {
            if k.eq_ignore_ascii_case("host") || k.eq_ignore_ascii_case("connection") {
                continue;
            }
            if k.eq_ignore_ascii_case("content-length") {
                has_content_length = true;
            }
            // Reject CR/LF header injection.
            if k.contains(['\r', '\n']) || v.contains(['\r', '\n']) {
                return Err("invalid CRLF in HTTP header".into());
            }
            req_head.push_str(k);
            req_head.push_str(": ");
            req_head.push_str(v);
            req_head.push_str("\r\n");
        }
        if !has_content_length && (!body.is_empty() || matches!(method, "POST" | "PUT" | "PATCH")) {
            req_head.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        req_head.push_str("\r\n");

        stream
            .write_all(req_head.as_bytes())
            .await
            .map_err(|e| format!("http write headers: {e}"))?;
        if !body.is_empty() {
            stream
                .write_all(body)
                .await
                .map_err(|e| format!("http write body: {e}"))?;
        }
        stream
            .flush()
            .await
            .map_err(|e| format!("http flush: {e}"))?;

        let mut reader = BufReader::new(stream);
        let status_line = read_bounded_line(&mut reader, WS_HDR_LINE_MAX)
            .await
            .map_err(|e| format!("http read status: {e}"))?
            .ok_or_else(|| "unexpected EOF reading HTTP status line".to_string())?;
        let mut parts = status_line.split_whitespace();
        let _proto = parts
            .next()
            .ok_or_else(|| format!("malformed HTTP status line: {status_line:?}"))?;
        let status_str = parts
            .next()
            .ok_or_else(|| format!("missing HTTP status code: {status_line:?}"))?;
        let status = status_str
            .parse::<u16>()
            .map_err(|_| format!("invalid HTTP status code: {status_str:?}"))?;

        let mut resp_headers: Vec<(String, String)> = Vec::new();
        let mut content_length: Option<usize> = None;
        let mut chunked = false;
        let mut saw_end = false;
        for _ in 0..MAX_HEADER_LINES {
            let Some(line) = read_bounded_line(&mut reader, WS_HDR_LINE_MAX)
                .await
                .map_err(|e| format!("http read header: {e}"))?
            else {
                break;
            };
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() {
                saw_end = true;
                break;
            }
            if let Some((k, v)) = trimmed.split_once(':') {
                let key = k.trim().to_string();
                let val = v.trim().to_string();
                if key.eq_ignore_ascii_case("content-length") {
                    content_length = val.parse::<usize>().ok();
                } else if key.eq_ignore_ascii_case("transfer-encoding")
                    && val.to_ascii_lowercase().contains("chunked")
                {
                    chunked = true;
                }
                resp_headers.push((key, val));
            }
        }
        if !saw_end {
            return Err("HTTP response headers exceeded limit or truncated".into());
        }

        let resp_body =
            if method.eq_ignore_ascii_case("HEAD") || matches!(status, 100..=199 | 204 | 304) {
                Vec::new()
            } else if chunked {
                read_chunked_body(&mut reader, self.max_body_bytes).await?
            } else if let Some(len) = content_length {
                if len > self.max_body_bytes {
                    return Err(format!(
                        "HTTP body {len} exceeds max {}",
                        self.max_body_bytes
                    ));
                }
                let mut buf = vec![0u8; len];
                reader
                    .read_exact(&mut buf)
                    .await
                    .map_err(|e| format!("http read exact body: {e}"))?;
                buf
            } else {
                read_to_eof_bounded(&mut reader, self.max_body_bytes).await?
            };

        Ok(HttpResponse {
            status,
            headers: resp_headers,
            body: resp_body,
        })
    }

    /// Connect to an RFC-6455 WebSocket endpoint with optional custom HTTP headers.
    pub async fn connect_ws(
        &self,
        url: &str,
        extra_headers: &[(String, String)],
    ) -> Result<WsClientConn, String> {
        let parsed = ParsedHttpUrl::parse(url)?;
        let stream = tokio::time::timeout(self.timeout, TcpStream::connect(parsed.connect_addr()))
            .await
            .map_err(|_| format!("ws connect {url} timed out"))?
            .map_err(|e| format!("ws connect {}: {e}", parsed.connect_addr()))?;
        let _ = stream.set_nodelay(true);
        let (r, mut w) = tokio::io::split(stream);
        let mut reader = BufReader::new(r);

        let key = B64.encode(random_hex(8).as_bytes());
        let mut req = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {key}\r\n\
             Sec-WebSocket-Version: 13\r\n",
            parsed.path_and_query, parsed.host_header
        );
        for (k, v) in extra_headers {
            if k.contains(['\r', '\n']) || v.contains(['\r', '\n']) {
                return Err("invalid CRLF in WS header".into());
            }
            req.push_str(k);
            req.push_str(": ");
            req.push_str(v);
            req.push_str("\r\n");
        }
        req.push_str("\r\n");

        w.write_all(req.as_bytes())
            .await
            .map_err(|e| format!("ws handshake write: {e}"))?;
        w.flush()
            .await
            .map_err(|e| format!("ws handshake flush: {e}"))?;

        let mut status_line = String::new();
        let mut status_ok = false;
        let mut accept_ok = false;
        let mut saw_end = false;
        let expected_accept = ws_accept_key(&key);
        for i in 0..MAX_HEADER_LINES {
            let Some(line) = read_bounded_line(&mut reader, WS_HDR_LINE_MAX)
                .await
                .map_err(|e| format!("ws handshake read: {e}"))?
            else {
                return Err("unexpected EOF in WS handshake response".into());
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                saw_end = true;
                break;
            }
            if i == 0 {
                status_line = trimmed.to_string();
                if trimmed.contains(" 101 ") || trimmed.ends_with(" 101") {
                    status_ok = true;
                }
            } else if let Some((k, v)) = trimmed.split_once(':')
                && k.eq_ignore_ascii_case("sec-websocket-accept")
                && v.trim() == expected_accept
            {
                accept_ok = true;
            }
        }
        if !saw_end || !status_ok || !accept_ok {
            return Err(format!("websocket upgrade rejected ({status_line})"));
        }

        Ok(WsClientConn {
            reader,
            writer: w,
            frag_buf: None,
        })
    }
}

async fn read_chunked_body<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let Some(size_line) = read_bounded_line(reader, 1024)
            .await
            .map_err(|e| format!("http chunk size: {e}"))?
        else {
            return Err("unexpected EOF reading HTTP chunk size".into());
        };
        let hex = size_line.split(';').next().unwrap_or("").trim();
        let chunk_len = usize::from_str_radix(hex, 16)
            .map_err(|_| format!("invalid HTTP chunk size: {hex:?}"))?;
        if chunk_len == 0 {
            // Drain optional trailing headers until blank line.
            for _ in 0..32 {
                let Some(line) = read_bounded_line(reader, WS_HDR_LINE_MAX)
                    .await
                    .map_err(|e| format!("http chunk trailer: {e}"))?
                else {
                    break;
                };
                if line.trim().is_empty() {
                    break;
                }
            }
            break;
        }
        if out.len().saturating_add(chunk_len) > max_bytes {
            return Err(format!("chunked HTTP body exceeds max {max_bytes}"));
        }
        let start = out.len();
        out.resize(start + chunk_len, 0);
        reader
            .read_exact(&mut out[start..])
            .await
            .map_err(|e| format!("http chunk data: {e}"))?;
        let mut crlf = [0u8; 2];
        reader
            .read_exact(&mut crlf)
            .await
            .map_err(|e| format!("http chunk crlf: {e}"))?;
    }
    Ok(out)
}

async fn read_to_eof_bounded<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = reader
            .read(&mut buf)
            .await
            .map_err(|e| format!("http read eof body: {e}"))?;
        if n == 0 {
            break;
        }
        if out.len().saturating_add(n) > max_bytes {
            return Err(format!("HTTP body exceeds max {max_bytes}"));
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

/// Active RFC-6455 client WebSocket connection.
pub struct WsClientConn {
    reader: BufReader<tokio::io::ReadHalf<TcpStream>>,
    writer: tokio::io::WriteHalf<TcpStream>,
    frag_buf: Option<Vec<u8>>,
}

impl WsClientConn {
    pub async fn send_text(&mut self, text: &str) -> Result<(), String> {
        ws_write_frame(&mut self.writer, 0x1, text.as_bytes(), true).await
    }

    pub async fn recv_text(&mut self) -> Result<Option<String>, String> {
        loop {
            match ws_read_event(&mut self.reader, false, &mut self.frag_buf).await? {
                Some(WsEvent::Text(s)) => return Ok(Some(s)),
                Some(WsEvent::Ping(p)) => {
                    let _ = ws_write_frame(&mut self.writer, 0xA, &p, true).await;
                }
                Some(WsEvent::Close) | None => return Ok(None),
            }
        }
    }

    pub async fn close(&mut self) {
        let _ = ws_write_frame(&mut self.writer, 0x8, &[], true).await;
    }
}

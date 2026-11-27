// Browser host bridge for `/run/net/host.sock` (`#86` Phase 10a).
//
// Lazily started ONLY when verified `/usr/bin/netd` executes (`netd.service`, ZERO network
// requests at boot). Bridges `HostNetReq::Open` + `SCM_RIGHTS` -> `kernel.authorize_netd_open`
// -> `POST /api/net/ticket` -> WebSocket `/api/net/connect?ticket=...` with strict credit-windowed
// binary frame pumping (`[0x01..0x05]`).

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: false });

const CONTROL_MAX_BYTES = 16 * 1024;
const DATA_CHUNK_MAX = 16 * 1024;
const INITIAL_WINDOW_BYTES = 64 * 1024;

const FRAME_DATA = 0x01;
const FRAME_CREDIT = 0x02;
const FRAME_HALF_CLOSE = 0x03;
const FRAME_CANCEL = 0x04;
const FRAME_CLOSED = 0x05;

function bytesToB64(bytes) {
  let bin = '';
  const step = 0x8000;
  for (let i = 0; i < bytes.length; i += step) {
    bin += String.fromCharCode(...bytes.subarray(i, i + step));
  }
  return btoa(bin);
}

function b64ToBytes(b64) {
  if (!b64) return new Uint8Array(0);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function encodeControlFrame(obj) {
  const body = encoder.encode(JSON.stringify(obj));
  const frame = new Uint8Array(4 + body.length);
  new DataView(frame.buffer).setUint32(0, body.length, false);
  frame.set(body, 4);
  return frame;
}

function encodeUnixDataFrame(tag, payload = new Uint8Array(0)) {
  const frame = new Uint8Array(5 + payload.length);
  frame[0] = tag;
  new DataView(frame.buffer).setUint32(1, payload.length, false);
  if (payload.length) frame.set(payload, 5);
  return frame;
}

function parseNetError(err, fallbackErrno = 'EIO', fallbackKind = 'host_unavailable') {
  if (typeof err === 'string') {
    try {
      const parsed = JSON.parse(err);
      if (parsed && typeof parsed === 'object' && parsed.errno) {
        return {
          kind: 'error',
          errno: parsed.errno,
          error: parsed.error || fallbackKind,
          message: String(parsed.message || parsed.errno),
        };
      }
    } catch { /* fall through */ }
    return { kind: 'error', errno: fallbackErrno, error: fallbackKind, message: err };
  }
  if (err && typeof err === 'object' && err.errno) {
    return {
      kind: 'error',
      errno: err.errno,
      error: err.error || fallbackKind,
      message: String(err.message || err.errno),
    };
  }
  return {
    kind: 'error',
    errno: fallbackErrno,
    error: fallbackKind,
    message: String(err?.message ?? err ?? fallbackErrno),
  };
}

async function sendAllUnix(socketOp, sockId, bytes, isAborted) {
  let offset = 0;
  while (offset < bytes.length) {
    if (isAborted()) throw Object.assign(new Error('canceled'), { errno: 'ECANCELED' });
    const slice = bytes.subarray(offset, Math.min(bytes.length, offset + 4096));
    try {
      const res = await socketOp({ op: 'sendmsg', sockId, fds: [], data: bytesToB64(slice) });
      if (!res?.sent) throw Object.assign(new Error('peer closed'), { errno: 'EPIPE' });
      offset += res.sent;
    } catch (e) {
      if (e?.errno === 'EAGAIN') {
        await new Promise(r => setTimeout(r, 4));
        continue;
      }
      throw e;
    }
  }
}

function wsUrlFromOrigin(origin, pathAndQuery) {
  const base = origin.replace(/^http:/i, 'ws:').replace(/^https:/i, 'wss:');
  return `${base}${pathAndQuery}`;
}

let activeHost = null;
let activeHostPromise = null;

export function ensureNetdHost({ kernel, socketOp }) {
  if (activeHost) return Promise.resolve(activeHost);
  if (activeHostPromise) return activeHostPromise;
  const p = startNetdHost({ kernel, socketOp }).finally(() => {
    if (activeHostPromise === p) activeHostPromise = null;
  });
  activeHostPromise = p;
  return p;
}

async function startNetdHost({ kernel, socketOp }) {
  const listenerId = await kernel.bind_netd_host_socket();
  let closed = false;
  let activeStreams = 0;
  const openSockets = new Set();

  const handleClient = async (hostSockId, acceptedCred) => {
    let clientSockId = null;
    let ws = null;
    let streamCounted = false;
    let aborted = false;
    const isAborted = () => closed || aborted;

    const closeWs = (code = 1000, reason = 'done') => {
      if (ws) {
        const s = ws;
        ws = null;
        openSockets.delete(s);
        try { s.close(code, reason); } catch { /* ignore */ }
      }
    };

    try {
      const cred = acceptedCred ?? await socketOp({ op: 'peercred', sockId: hostSockId });
      if (!cred || cred.uid !== 0 || !kernel.is_service_image(cred.pid, 'netd')) {
        return;
      }

      // 1. Read one length-prefixed JSON `HostNetReq` + optional `SCM_RIGHTS` client socket fd.
      const rxChunks = [];
      let rxBytes = 0;
      let expectedTotal = null;
      const deadline = Date.now() + 10_000;
      while (!isAborted() && Date.now() < deadline) {
        const msg = await socketOp({
          op: 'recvmsg',
          sockId: hostSockId,
          sabStream: true,
          bufLen: 4096,
          maxFds: clientSockId == null ? 1 : 0,
        });
        if (msg?.wouldBlock) {
          await new Promise(r => setTimeout(r, 5));
          continue;
        }
        if (Array.isArray(msg?.fds)) {
          for (const fd of msg.fds) {
            if (fd?.kind === 'unix_sock' && clientSockId == null) {
              clientSockId = fd.sockId;
            } else if (fd?.kind === 'unix_sock') {
              await socketOp({ op: 'close', sockId: fd.sockId }).catch(() => {});
            }
          }
        }
        const chunk = typeof msg?.data === 'string'
          ? b64ToBytes(msg.data)
          : msg?.data instanceof Uint8Array ? msg.data : new Uint8Array(msg?.data ?? []);
        if (!chunk.length) return;
        rxChunks.push(chunk);
        rxBytes += chunk.length;
        if (rxBytes > CONTROL_MAX_BYTES + 4) {
          await sendAllUnix(socketOp, hostSockId, encodeControlFrame({
            kind: 'error', errno: 'E2BIG', error: 'protocol_error', message: 'control frame too large',
          }), isAborted).catch(() => {});
          return;
        }
        if (expectedTotal === null && rxBytes >= 4) {
          const hdr = new Uint8Array(4);
          let off = 0;
          for (const c of rxChunks) {
            const take = Math.min(4 - off, c.length);
            hdr.set(c.subarray(0, take), off);
            off += take;
            if (off >= 4) break;
          }
          const len = new DataView(hdr.buffer).getUint32(0, false);
          if (len === 0 || len > CONTROL_MAX_BYTES) {
            await sendAllUnix(socketOp, hostSockId, encodeControlFrame({
              kind: 'error', errno: 'EINVAL', error: 'protocol_error', message: 'invalid control length',
            }), isAborted).catch(() => {});
            return;
          }
          expectedTotal = 4 + len;
        }
        if (expectedTotal !== null && rxBytes >= expectedTotal) break;
      }

      if (expectedTotal === null || rxBytes < expectedTotal) return;
      const merged = new Uint8Array(rxBytes);
      let pos = 0;
      for (const c of rxChunks) { merged.set(c, pos); pos += c.length; }
      const reqJson = decoder.decode(merged.subarray(4, expectedTotal));
      const leftover = merged.subarray(expectedTotal);
      let req;
      try {
        req = JSON.parse(reqJson);
      } catch {
        await sendAllUnix(socketOp, hostSockId, encodeControlFrame({
          kind: 'error', errno: 'EINVAL', error: 'protocol_error', message: 'invalid JSON',
        }), isAborted).catch(() => {});
        return;
      }

      if (req.op === 'hello') {
        const ok = Array.isArray(req.versions) && req.versions.includes(1);
        await sendAllUnix(socketOp, hostSockId, encodeControlFrame(ok
          ? { kind: 'welcome', version: 1, host_kind: 'browser' }
          : { kind: 'error', errno: 'EPROTONOSUPPORT', error: 'protocol_error', message: 'netd v1 required' }),
        isAborted);
        return;
      }
      if (req.op === 'status') {
        await sendAllUnix(socketOp, hostSockId, encodeControlFrame({
          kind: 'status',
          version: 1,
          host_kind: 'browser',
          active_streams: activeStreams,
          ready: true,
        }), isAborted);
        return;
      }
      if (req.op === 'resolve') {
        await sendAllUnix(socketOp, hostSockId, encodeControlFrame({
          kind: 'error',
          errno: 'EOPNOTSUPP',
          error: 'unsupported',
          message: 'browser gateway resolves hostnames inside Connect; raw Resolve is unsupported',
        }), isAborted);
        return;
      }
      if (req.op !== 'open' || clientSockId == null) {
        await sendAllUnix(socketOp, hostSockId, encodeControlFrame({
          kind: 'error',
          errno: 'EINVAL',
          error: 'invalid_argument',
          message: 'expected HostNetReq::Open with SCM_RIGHTS client socket',
        }), isAborted);
        return;
      }

      // 2. Kernel authorizes BOTH peers, mints/reuses ServiceAuth v2 token, validates NetScope+SSRF,
      //    and closes `clientSockId` deterministically inside Rust.
      const cid = clientSockId;
      clientSockId = null;
      let auth;
      try {
        auth = JSON.parse(await kernel.authorize_netd_open(hostSockId, cid, reqJson));
      } catch (e) {
        await sendAllUnix(socketOp, hostSockId, encodeControlFrame(parseNetError(e, 'EACCES', 'policy_denied')), isAborted).catch(() => {});
        return;
      }

      // 3. Request single-use gateway stream ticket from Worker (`POST /api/net/ticket`).
      const origin = typeof self !== 'undefined' && self.location ? self.location.origin : '';
      let ticketResp;
      try {
        const res = await fetch(`${origin}/api/net/ticket`, {
          method: 'POST',
          credentials: 'same-origin',
          headers: {
            'Content-Type': 'application/json',
            'X-Process-Token': auth.token,
            'X-OS-Instance': auth.instance_id,
          },
          body: JSON.stringify({
            host: req.host,
            port: req.port,
            tls: req.tls ?? 'off',
            ...(req.timeout_ms != null ? { timeout_ms: req.timeout_ms } : {}),
          }),
        });
        const body = await res.json().catch(() => null);
        if (!res.ok) {
          await sendAllUnix(socketOp, hostSockId, encodeControlFrame({
            kind: 'error',
            errno: body?.errno || (res.status === 403 ? 'EACCES' : res.status === 429 || res.status === 507 ? 'EDQUOT' : 'EIO'),
            error: body?.error || (res.status === 403 ? 'policy_denied' : 'host_unavailable'),
            message: body?.message || `gateway ticket failed (HTTP ${res.status})`,
          }), isAborted).catch(() => {});
          return;
        }
        ticketResp = body;
      } catch (e) {
        await sendAllUnix(socketOp, hostSockId, encodeControlFrame({
          kind: 'error',
          errno: 'ENOTCONN',
          error: 'offline',
          message: `gateway ticket request failed: ${e?.message ?? e}`,
        }), isAborted).catch(() => {});
        return;
      }

      // 4. Open WebSocket `/api/net/connect?ticket=...` and await initial JSON `opened`/`error` frame.
      activeStreams += 1;
      streamCounted = true;
      const wsUrl = wsUrlFromOrigin(origin, `/api/net/connect?ticket=${encodeURIComponent(ticketResp.ticket)}`);
      ws = new WebSocket(wsUrl);
      ws.binaryType = 'arraybuffer';
      openSockets.add(ws);

      const wsQueue = [];
      let wsClosed = false;
      let wsError = null;
      let wakeWs = null;
      const notifyWs = () => { if (wakeWs) { const fn = wakeWs; wakeWs = null; fn(); } };

      ws.addEventListener('message', ev => {
        wsQueue.push(ev.data);
        notifyWs();
      });
      ws.addEventListener('close', () => {
        wsClosed = true;
        notifyWs();
      });
      ws.addEventListener('error', () => {
        wsError = new Error('gateway WebSocket error');
        wsClosed = true;
        notifyWs();
      });

      let rxBuf = new Uint8Array(leftover.length);
      rxBuf.set(leftover);
      let opened = null;
      const connectDeadline = Date.now() + Math.min(35_000, Number(req.timeout_ms || auth.quota?.connect_timeout_ms || 10_000) + 5000);

      // Race initial Worker handshake (`opened` / `error`) against `netd` disconnect / `CANCEL`.
      while (!opened && !isAborted()) {
        if (wsQueue.length > 0) {
          const item = wsQueue.shift();
          if (typeof item === 'string') {
            const msg = JSON.parse(item);
            if (msg.kind === 'opened') {
              opened = msg;
              break;
            }
            if (msg.kind === 'error') {
              await sendAllUnix(socketOp, hostSockId, encodeControlFrame(msg), isAborted).catch(() => {});
              return;
            }
          }
          continue;
        }
        if (wsClosed) {
          await sendAllUnix(socketOp, hostSockId, encodeControlFrame({
            kind: 'error',
            errno: 'ECONNRESET',
            error: 'connect_failed',
            message: wsError ? wsError.message : 'gateway closed before stream opened',
          }), isAborted).catch(() => {});
          return;
        }
        if (Date.now() >= connectDeadline) {
          try { ws.send(new Uint8Array([FRAME_CANCEL])); } catch { /* ignore */ }
          await sendAllUnix(socketOp, hostSockId, encodeControlFrame({
            kind: 'error',
            errno: 'ETIMEDOUT',
            error: 'timeout',
            message: 'gateway connect timed out',
          }), isAborted).catch(() => {});
          return;
        }
        // Check if `netd` disconnected or sent CANCEL while connecting!
        const check = await socketOp({ op: 'recvmsg', sockId: hostSockId, sabStream: true, bufLen: 64, maxFds: 0 });
        if (!check?.wouldBlock) {
          const part = typeof check?.data === 'string' ? b64ToBytes(check.data) : new Uint8Array(0);
          if (!part.length || part[0] === FRAME_CANCEL) {
            aborted = true;
            try { ws.send(new Uint8Array([FRAME_CANCEL])); } catch { /* ignore */ }
            return;
          }
          const combined = new Uint8Array(rxBuf.length + part.length);
          combined.set(rxBuf);
          combined.set(part, rxBuf.length);
          rxBuf = combined;
        }
        await new Promise(r => {
          const t = setTimeout(() => { wakeWs = null; r(); }, 10);
          wakeWs = () => { clearTimeout(t); r(); };
        });
      }

      if (!opened || isAborted()) return;

      // 5. Send `HostNetResp::Opened` to `netd` and run bidirectional binary frame pump.
      await sendAllUnix(socketOp, hostSockId, encodeControlFrame({
        kind: 'opened',
        stream_id: opened.stream_id ?? ticketResp.stream_id ?? 'stream',
        peer_addr: opened.peer_addr ?? null,
        initial_window: opened.initial_window ?? INITIAL_WINDOW_BYTES,
        quota: opened.quota ?? auth.quota,
      }), isAborted);

      let unixClosed = false;
      const wsToUnix = (async () => {
        while (!isAborted() && !unixClosed) {
          while (wsQueue.length > 0) {
            const item = wsQueue.shift();
            if (typeof item === 'string') continue;
            const raw = item instanceof ArrayBuffer ? new Uint8Array(item) : new Uint8Array(item);
            if (!raw.length) continue;
            const tag = raw[0];
            const payload = raw.subarray(1);
            await sendAllUnix(socketOp, hostSockId, encodeUnixDataFrame(tag, payload), isAborted);
            if (tag === FRAME_CLOSED) {
              aborted = true;
              return;
            }
          }
          if (wsClosed) {
            const payload = encoder.encode(JSON.stringify({
              errno: wsError ? 'ECONNRESET' : null,
              error: wsError ? 'stream_reset' : null,
              message: wsError ? wsError.message : null,
              bytes_sent: 0,
              bytes_received: 0,
            }));
            await sendAllUnix(socketOp, hostSockId, encodeUnixDataFrame(FRAME_CLOSED, payload), () => closed).catch(() => {});
            aborted = true;
            return;
          }
          await new Promise(r => {
            const t = setTimeout(() => { wakeWs = null; r(); }, 25);
            wakeWs = () => { clearTimeout(t); r(); };
          });
        }
      })();

      const unixToWs = (async () => {
        while (!isAborted() && !wsClosed) {
          while (rxBuf.length >= 5) {
            const tag = rxBuf[0];
            const len = new DataView(rxBuf.buffer, rxBuf.byteOffset + 1, 4).getUint32(0, false);
            if (len > DATA_CHUNK_MAX && tag !== FRAME_CLOSED) {
              aborted = true;
              return;
            }
            if (rxBuf.length < 5 + len) break;
            const wsMsg = new Uint8Array(1 + len);
            wsMsg[0] = tag;
            if (len > 0) wsMsg.set(rxBuf.subarray(5, 5 + len), 1);
            rxBuf = rxBuf.subarray(5 + len);
            if (ws && ws.readyState === WebSocket.OPEN) {
              ws.send(wsMsg);
            }
            if (tag === FRAME_CANCEL) {
              aborted = true;
              return;
            }
          }
          const msg = await socketOp({ op: 'recvmsg', sockId: hostSockId, sabStream: true, bufLen: DATA_CHUNK_MAX + 64, maxFds: 0 });
          if (msg?.wouldBlock) {
            await new Promise(r => setTimeout(r, 4));
            continue;
          }
          const part = typeof msg?.data === 'string' ? b64ToBytes(msg.data) : new Uint8Array(0);
          if (!part.length) {
            unixClosed = true;
            if (ws && ws.readyState === WebSocket.OPEN) {
              try { ws.send(new Uint8Array([FRAME_CANCEL])); } catch { /* ignore */ }
            }
            return;
          }
          const combined = new Uint8Array(rxBuf.length + part.length);
          combined.set(rxBuf);
          combined.set(part, rxBuf.length);
          rxBuf = combined;
        }
      })();

      await Promise.allSettled([wsToUnix, unixToWs]);
    } catch {
      /* peer closed or timed out */
    } finally {
      aborted = true;
      closeWs();
      if (streamCounted) activeStreams = Math.max(0, activeStreams - 1);
      if (clientSockId != null) {
        await socketOp({ op: 'close', sockId: clientSockId }).catch(() => {});
      }
      await socketOp({ op: 'close', sockId: hostSockId }).catch(() => {});
    }
  };

  const pollLoop = (async () => {
    while (!closed) {
      try {
        const res = await socketOp({ op: 'accept', sockId: listenerId });
        if (closed) break;
        if (res?.wouldBlock) {
          await new Promise(r => setTimeout(r, 15));
          continue;
        }
        if (res?.sockId != null) {
          void handleClient(res.sockId, res.peerCred);
        }
      } catch {
        if (closed) break;
        await new Promise(r => setTimeout(r, 50));
      }
    }
  })();

  activeHost = {
    listenerId,
    async stop() {
      closed = true;
      for (const s of [...openSockets]) {
        try { s.close(1001, 'host reset'); } catch { /* ignore */ }
      }
      openSockets.clear();
      await socketOp({ op: 'close', sockId: listenerId }).catch(() => {});
      await pollLoop.catch(() => {});
      if (activeHost?.listenerId === listenerId) activeHost = null;
    },
  };
  return activeHost;
}

export async function resetNetdHost() {
  if (activeHostPromise) {
    try { await activeHostPromise; } catch { /* ignore */ }
  }
  if (!activeHost) return;
  const host = activeHost;
  activeHost = null;
  await host.stop();
}

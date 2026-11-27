// Lazy-loaded browser L3 overlay datagram transport (`Phase 10b #87`).
//
// NEVER imported at boot (zero `/api/overlay/*` or WebRTC calls on default page load).
// Loaded strictly on first `ioctl(/dev/net/tun, TUNSETIFF, ...)`.
//
// Layered datagram transport:
//   1. Authenticated `OverlayRelay` WebSocket (`/api/overlay/attach` -> `/api/overlay/connect?ticket=...`,
//      `binaryType = 'arraybuffer'`, `[0x01][raw L3 packet]` binary frames + JSON control/WebRTC signaling).
//   2. Opportunistic `WebTransport` datagrams when `typeof WebTransport === 'function'` and
//      `reply.webtransport_url` is advertised on HTTPS/HTTP3.
//   3. Window-brokered WebRTC unordered DataChannel (`ordered: false, maxRetransmits: 0`,
//      `new RTCPeerConnection({ iceServers: [] })`) signaled strictly intra-tenant via `OverlayRelay`,
//      falling back transparently to `OverlayRelay` WebSocket when ICE is unavailable.

const FRAME_L3_PACKET = 0x01;
const MAX_WS_BUFFERED_BYTES = 1024 * 1024; // 1 MiB backpressure threshold

const byEndpoint = new Map();
const byTunId = new Map();
const pendingDetaches = new Set();

let hostCtx = {
  kernel: null,
  wake: () => {},
  openWebRtcBroker: null,
};

export function configureOverlayTransport({ kernel, wake, openWebRtcBroker }) {
  hostCtx = {
    kernel,
    wake: typeof wake === 'function' ? wake : () => {},
    openWebRtcBroker: typeof openWebRtcBroker === 'function' ? openWebRtcBroker : null,
  };
}

function errnoFromHttp(status, hdrErrno) {
  if (hdrErrno && /^[A-Z0-9_]+$/.test(hdrErrno)) return hdrErrno;
  if (status === 401 || status === 403) return 'EACCES';
  if (status === 404) return 'ENOENT';
  if (status === 409) return 'EBUSY';
  if (status === 412) return 'ESTALE';
  if (status === 507) return 'ENOSPC';
  return 'EIO';
}

function wsUrlFor(wsPath) {
  if (wsPath.startsWith('ws://') || wsPath.startsWith('wss://')) return wsPath;
  const origin = self.location?.origin || '';
  const wsOrigin = origin.replace(/^http:\/\//, 'ws://').replace(/^https:\/\//, 'wss://');
  return wsPath.startsWith('/') ? `${wsOrigin}${wsPath}` : `${wsOrigin}/${wsPath}`;
}

function frameL3Packet(pkt) {
  const src = pkt instanceof Uint8Array ? pkt : new Uint8Array(pkt);
  const out = new Uint8Array(1 + src.length);
  out[0] = FRAME_L3_PACKET;
  out.set(src, 1);
  return out;
}

function ipv6ToBytes(str) {
  if (typeof str !== 'string' || !str.includes(':')) return null;
  const halves = str.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - (left.length + right.length);
  if (halves.length === 1 ? missing !== 0 : missing < 1) return null;
  const groups = [...left, ...new Array(missing).fill('0'), ...right];
  if (groups.length !== 8) return null;
  const out = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(groups[i])) return null;
    const v = parseInt(groups[i], 16);
    out[i * 2] = (v >> 8) & 0xff;
    out[i * 2 + 1] = v & 0xff;
  }
  return out;
}

function bytesToHexKey(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}

function bytesEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function packetDstKey(pkt) {
  if (!pkt || pkt.length < 20) return null;
  const ver = pkt[0] >> 4;
  if (ver === 4) {
    return `4:${pkt[16]}.${pkt[17]}.${pkt[18]}.${pkt[19]}`;
  }
  if (ver === 6 && pkt.length >= 40) {
    return `6:${bytesToHexKey(pkt.subarray(24, 40))}`;
  }
  return null;
}

function packetMatchesPeerSource(pkt, peer) {
  if (!pkt || !peer || pkt.length < 20) return false;
  const ver = pkt[0] >> 4;
  if (ver === 4) {
    if (!peer.ip) return false;
    const src = `${pkt[12]}.${pkt[13]}.${pkt[14]}.${pkt[15]}`;
    return src === peer.ip;
  }
  if (ver === 6) {
    if (pkt.length < 40 || !peer.ipv6) return false;
    const want = ipv6ToBytes(peer.ipv6);
    return want !== null && bytesEqual(pkt.subarray(8, 24), want);
  }
  return false;
}

function cleanupPeerRtc(ep, peerEndpointId) {
  const rtc = ep.rtcPeers.get(peerEndpointId);
  if (!rtc) return;
  ep.rtcPeers.delete(peerEndpointId);
  try { rtc.port.postMessage({ type: 'close' }); } catch {}
  try { rtc.port.close(); } catch {}
}

async function ensureRtcPeer(ep, peerEndpointId, role) {
  if (ep.closed || !hostCtx.openWebRtcBroker) return null;
  const existing = ep.rtcPeers.get(peerEndpointId);
  if (existing) return existing;
  const inflight = ep.pendingRtcPeers.get(peerEndpointId);
  if (inflight) return inflight;

  const promise = (async () => {
    let port = null;
    try {
      port = await hostCtx.openWebRtcBroker(role);
    } catch {
      ep.debug.fallbackToWs = true;
      return null;
    }
    if (!port || ep.closed) {
      if (port) {
        try { port.postMessage({ type: 'close' }); } catch {}
        try { port.close(); } catch {}
      }
      ep.debug.fallbackToWs = true;
      return null;
    }

    const rtc = {
      peerEndpointId,
      role,
      port,
      open: false,
      dcConfig: null,
      state: 'connecting',
    };
    ep.rtcPeers.set(peerEndpointId, rtc);
    ep.debug.webrtcAttempts += 1;

    port.onmessage = ({ data }) => {
      if (ep.closed || !data) return;
      if (data.type === 'dc-config') {
        rtc.dcConfig = data.config;
        ep.debug.dcConfig = data.config;
        return;
      }
      if (data.type === 'signal') {
        ep.debug.signalsSent += 1;
        sendWsJson(ep, {
          kind: 'signal',
          to_endpoint_id: peerEndpointId,
          payload: data.payload,
        });
        return;
      }
      if (data.type === 'open') {
        rtc.open = true;
        rtc.state = 'open';
        ep.debug.activeMode = 'webrtc';
        return;
      }
      if (data.type === 'packet' && data.bytes) {
        const raw = data.bytes instanceof Uint8Array ? data.bytes : new Uint8Array(data.bytes);
        if (raw.length >= 2 && raw[0] === FRAME_L3_PACKET && ep.tunId != null && hostCtx.kernel) {
          const l3 = raw.subarray(1);
          const peer = ep.peersById.get(peerEndpointId);
          // Strict per-peer source-IP binding on direct WebRTC DataChannel RX so a compromised
          // intra-tenant peer cannot spoof another tenant peer's source IP.
          if (!packetMatchesPeerSource(l3, peer)) {
            hostCtx.kernel.tun_record_drop(ep.tunId, 'rx_policy_denied');
            return;
          }
          ep.debug.rtcRxPackets += 1;
          hostCtx.kernel.tun_inject_rx(ep.tunId, l3);
          hostCtx.wake();
        }
        return;
      }
      if (data.type === 'closed' || data.type === 'failed') {
        rtc.open = false;
        rtc.state = data.type;
        ep.debug.fallbackToWs = true;
        if (ep.debug.activeMode === 'webrtc') ep.debug.activeMode = 'ws';
        cleanupPeerRtc(ep, peerEndpointId);
      }
    };
    port.start?.();
    return rtc;
  })().finally(() => {
    ep.pendingRtcPeers.delete(peerEndpointId);
  });

  ep.pendingRtcPeers.set(peerEndpointId, promise);
  return promise;
}

function sendWsJson(ep, obj) {
  if (!ep.ws || ep.ws.readyState !== WebSocket.OPEN) return false;
  try {
    ep.ws.send(JSON.stringify(obj));
    return true;
  } catch {
    return false;
  }
}

async function startWebTransportIfAvailable(ep, url) {
  if (!url || typeof WebTransport !== 'function' || ep.closed) return;
  try {
    const wt = new WebTransport(url);
    await wt.ready;
    if (ep.closed) {
      wt.close();
      return;
    }
    ep.wt = wt;
    ep.wtWriter = wt.datagrams.writable.getWriter();
    ep.debug.activeMode = 'webtransport';
    const reader = wt.datagrams.readable.getReader();
    (async () => {
      try {
        while (!ep.closed) {
          const { value, done } = await reader.read();
          if (done) break;
          if (value && value.length >= 2 && value[0] === FRAME_L3_PACKET && ep.tunId != null && hostCtx.kernel) {
            hostCtx.kernel.tun_inject_rx(ep.tunId, value.subarray(1));
            hostCtx.wake();
          }
        }
      } catch {
        /* fallback transparently to WS */
      } finally {
        ep.wt = null;
        ep.wtWriter = null;
        if (ep.debug.activeMode === 'webtransport') ep.debug.activeMode = 'ws';
      }
    })();
  } catch {
    ep.wt = null;
    ep.wtWriter = null;
  }
}

export async function attachOverlay({ token, instance_id, network, ifname, mtu, static_ip }) {
  const res = await fetch('/api/overlay/attach', {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      'X-Process-Token': token,
      'X-OS-Instance': instance_id,
    },
    body: JSON.stringify({
      network: network || 'default',
      ifname,
      mtu,
      ...(static_ip ? { static_ip } : {}),
      host_kind: 'browser',
    }),
  });
  if (!res.ok) {
    const errHdr = res.headers.get('X-OS-Errno');
    let detail = `overlay attach failed (${res.status})`;
    try {
      const body = await res.json();
      if (body?.message || body?.detail) detail = body.message || body.detail;
    } catch {}
    throw Object.assign(new Error(detail), { errno: errnoFromHttp(res.status, errHdr) });
  }
  const reply = await res.json();

  const wsAbs = wsUrlFor(reply.ws_url);
  const ws = new WebSocket(wsAbs);
  ws.binaryType = 'arraybuffer';

  const ep = {
    token,
    instance_id,
    endpoint_id: reply.endpoint_id,
    tenant: reply.tenant,
    network: reply.network,
    ip: reply.ip,
    lease_id: reply.lease_id,
    lease_ttl_secs: reply.lease_ttl_secs || 60,
    tunId: null,
    ws,
    wt: null,
    wtWriter: null,
    renewTimer: null,
    closed: false,
    peersById: new Map(),
    peerIdByIp: new Map(),
    rtcPeers: new Map(),
    pendingRtcPeers: new Map(),
    debug: {
      endpoint_id: reply.endpoint_id,
      tenant: reply.tenant,
      network: reply.network,
      ip: reply.ip,
      activeMode: 'ws',
      fallbackToWs: true,
      webrtcAttempts: 0,
      dcConfig: null,
      signalsSent: 0,
      signalsReceived: 0,
      signalErrors: [],
      rtcRxPackets: 0,
      rtcTxPackets: 0,
      wsRxPackets: 0,
      wsTxPackets: 0,
    },
  };

  try {
    await new Promise((resolve, reject) => {
      let settled = false;
      const timeout = setTimeout(() => {
        if (!settled) {
          settled = true;
          try { ws.close(); } catch {}
          reject(Object.assign(new Error('overlay welcome timed out'), { errno: 'ETIMEDOUT' }));
        }
      }, 8000);

      ws.onopen = () => {
        try {
          ws.send(JSON.stringify({ kind: 'hello', versions: [1] }));
        } catch (e) {
          if (!settled) {
            settled = true;
            clearTimeout(timeout);
            reject(Object.assign(new Error(String(e)), { errno: 'EIO' }));
          }
        }
      };

      ws.onerror = () => {
        if (!settled) {
          settled = true;
          clearTimeout(timeout);
          reject(Object.assign(new Error('overlay websocket error'), { errno: 'EIO' }));
        }
      };

      ws.onclose = ev => {
        if (!settled) {
          settled = true;
          clearTimeout(timeout);
          const errno = ev.code === 1008 ? 'EACCES' : 'ECONNRESET';
          reject(Object.assign(new Error(`overlay websocket closed (${ev.code})`), { errno }));
          return;
        }
        if (!ep.closed) {
          const errno = ev.code === 1008 ? 'EACCES' : 'ENOTCONN';
          if (ep.tunId != null && hostCtx.kernel) {
            hostCtx.kernel.tun_mark_hungup(ep.tunId, errno);
            hostCtx.wake();
          }
          teardownEndpoint(ep, false);
        }
      };

      ws.onmessage = ev => {
        if (ep.closed) return;
        if (ev.data instanceof ArrayBuffer) {
          const raw = new Uint8Array(ev.data);
          if (raw.length >= 2 && raw[0] === FRAME_L3_PACKET && ep.tunId != null && hostCtx.kernel) {
            ep.debug.wsRxPackets += 1;
            hostCtx.kernel.tun_inject_rx(ep.tunId, raw.subarray(1));
            hostCtx.wake();
          }
          return;
        }
        if (typeof ev.data !== 'string') return;
        let msg;
        try { msg = JSON.parse(ev.data); } catch { return; }

        if (!settled) {
          if (msg.kind === 'welcome') {
            settled = true;
            clearTimeout(timeout);
            for (const peer of msg.peers || []) {
              recordPeerJoined(ep, peer);
            }
            resolve();
            return;
          }
          if (msg.kind === 'error') {
            settled = true;
            clearTimeout(timeout);
            reject(Object.assign(new Error(msg.message || 'overlay error'), { errno: msg.errno || 'EIO' }));
            return;
          }
        }

        if (msg.kind === 'peer_joined') {
          recordPeerJoined(ep, msg);
        } else if (msg.kind === 'peer_left') {
          const prev = ep.peersById.get(msg.endpoint_id);
          if (prev) removePeerIpIndex(ep, prev);
          ep.peersById.delete(msg.endpoint_id);
          cleanupPeerRtc(ep, msg.endpoint_id);
        } else if (msg.kind === 'signal') {
          ep.debug.signalsReceived += 1;
          void handleIncomingSignal(ep, msg.from_endpoint_id, msg.payload);
        } else if (msg.kind === 'drop_notice') {
          if (ep.tunId != null && hostCtx.kernel && msg.reason) {
            hostCtx.kernel.tun_record_drop(ep.tunId, msg.reason);
          }
        } else if (msg.kind === 'error') {
          ep.debug.signalErrors.push({ errno: msg.errno || 'EIO', message: msg.message || '' });
        }
      };
    });
  } catch (err) {
    // Best-effort detach so failed WS connect / welcome never leaks the newly leased IPAM slot.
    ep.closed = true;
    for (const peerId of Array.from(ep.rtcPeers.keys())) {
      cleanupPeerRtc(ep, peerId);
    }
    try { ws.close(); } catch {}
    sendDetachRequest(ep);
    throw err;
  }

  byEndpoint.set(ep.endpoint_id, ep);

  // Periodic lease renewal (`ttl / 3`, min 5s).
  const renewMs = Math.max(5, Math.floor(ep.lease_ttl_secs / 3)) * 1000;
  ep.renewTimer = setInterval(async () => {
    if (ep.closed) return;
    try {
      const r = await fetch('/api/overlay/renew', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'X-Process-Token': ep.token,
          'X-OS-Instance': ep.instance_id,
        },
        body: JSON.stringify({
          endpoint_id: ep.endpoint_id,
          lease_id: ep.lease_id,
          network: ep.network,
        }),
      });
      if (!r.ok && ep.tunId != null && hostCtx.kernel) {
        const errno = r.status === 401 || r.status === 403 ? 'EACCES' : r.status === 404 || r.status === 412 ? 'ESTALE' : null;
        if (errno) {
          hostCtx.kernel.tun_mark_hungup(ep.tunId, errno);
          hostCtx.wake();
          teardownEndpoint(ep, false);
        }
      }
    } catch { /* transient network failure; retry next tick */ }
  }, renewMs);

  if (reply.webtransport_url) {
    void startWebTransportIfAvailable(ep, reply.webtransport_url);
  }

  return reply;
}

function removePeerIpIndex(ep, peer) {
  if (peer.ip) ep.peerIdByIp.delete(`4:${peer.ip}`);
  if (peer.ipv6) {
    const v6 = ipv6ToBytes(peer.ipv6);
    if (v6) ep.peerIdByIp.delete(`6:${bytesToHexKey(v6)}`);
  }
}

function recordPeerJoined(ep, peer) {
  if (!peer || !peer.endpoint_id || peer.endpoint_id === ep.endpoint_id) return;
  const prev = ep.peersById.get(peer.endpoint_id);
  if (prev) removePeerIpIndex(ep, prev);
  ep.peersById.set(peer.endpoint_id, peer);
  if (peer.ip) ep.peerIdByIp.set(`4:${peer.ip}`, peer.endpoint_id);
  if (peer.ipv6) {
    const v6 = ipv6ToBytes(peer.ipv6);
    if (v6) ep.peerIdByIp.set(`6:${bytesToHexKey(v6)}`, peer.endpoint_id);
  }
  // Organically initiate an opportunistic unordered WebRTC DataChannel (`os-overlay-l3`):
  // - browser-to-browser uses deterministic offerer tie-break (`ep.endpoint_id < peer.endpoint_id`)
  // - browser-to-native opportunistically offers and falls back transparently to OverlayRelay WS
  //   when the native peer does not complete ICE.
  if (
    hostCtx.openWebRtcBroker &&
    (peer.host_kind !== 'browser' || ep.endpoint_id < peer.endpoint_id)
  ) {
    void ensureRtcPeer(ep, peer.endpoint_id, 'offerer');
  }
}

async function handleIncomingSignal(ep, fromEndpointId, payload) {
  if (!payload || typeof payload !== 'object') return;
  if (payload.sdp || payload.candidate) {
    const rtc = await ensureRtcPeer(ep, fromEndpointId, 'answerer');
    if (rtc) {
      try { rtc.port.postMessage({ type: 'signal', payload }); } catch {}
    }
  }
}

export function bindTunId(endpointId, tunId) {
  const ep = byEndpoint.get(endpointId);
  if (!ep) return;
  ep.tunId = tunId;
  byTunId.set(tunId, ep);
}

export function sendOverlayTx(tunId, pktBytes) {
  const ep = byTunId.get(tunId);
  if (!ep || ep.closed || !ep.ws || ep.ws.readyState !== WebSocket.OPEN) {
    throw Object.assign(new Error('overlay disconnected'), { errno: 'ENOTCONN' });
  }
  const framed = frameL3Packet(pktBytes);

  // 1. Prefer direct unordered WebRTC DataChannel when open for destination IP (v4 or v6).
  const dstKey = packetDstKey(pktBytes);
  if (dstKey) {
    const peerId = ep.peerIdByIp.get(dstKey);
    const rtc = peerId ? ep.rtcPeers.get(peerId) : null;
    if (rtc && rtc.open) {
      try {
        rtc.port.postMessage({ type: 'packet', bytes: framed }, [framed.buffer]);
        ep.debug.rtcTxPackets += 1;
        return true;
      } catch {
        ep.debug.fallbackToWs = true;
      }
    }
  }

  // 2. Opportunistic WebTransport datagrams if ready.
  if (ep.wtWriter) {
    try {
      void ep.wtWriter.write(framed).catch(() => {});
      return true;
    } catch { /* fall through to WS */ }
  }

  // 3. Deterministic authenticated OverlayRelay WebSocket fallback.
  if (ep.ws.bufferedAmount > MAX_WS_BUFFERED_BYTES) {
    return false; // signals EAGAIN backpressure to TunRegistry
  }
  ep.ws.send(framed);
  ep.debug.wsTxPackets += 1;
  return true;
}

function sendDetachRequest(ep) {
  const p = fetch('/api/overlay/detach', {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      'X-Process-Token': ep.token,
      'X-OS-Instance': ep.instance_id,
    },
    body: JSON.stringify({
      endpoint_id: ep.endpoint_id,
      lease_id: ep.lease_id,
      network: ep.network,
    }),
  })
    .catch(() => {})
    .finally(() => {
      pendingDetaches.delete(p);
    });
  pendingDetaches.add(p);
  return p;
}

export async function flushOverlayDetaches(timeoutMs = 3000) {
  if (pendingDetaches.size === 0) return;
  const inFlight = Array.from(pendingDetaches);
  let timer = null;
  try {
    await Promise.race([
      Promise.allSettled(inFlight),
      new Promise(resolve => {
        timer = setTimeout(resolve, timeoutMs);
      }),
    ]);
  } finally {
    if (timer !== null) clearTimeout(timer);
  }
}

function teardownEndpoint(ep, sendDetach) {
  if (ep.closed) return;
  ep.closed = true;
  if (ep.renewTimer) {
    clearInterval(ep.renewTimer);
    ep.renewTimer = null;
  }
  byEndpoint.delete(ep.endpoint_id);
  if (ep.tunId != null) byTunId.delete(ep.tunId);
  for (const peerId of Array.from(ep.rtcPeers.keys())) {
    cleanupPeerRtc(ep, peerId);
  }
  ep.pendingRtcPeers.clear();
  try { ep.wt?.close(); } catch {}
  try { ep.ws?.close(1000, 'detach'); } catch {}
  if (sendDetach) {
    sendDetachRequest(ep);
  }
}

export function closeOverlayTun(tunId, endpointId) {
  const ep = (tunId != null ? byTunId.get(tunId) : null) || (endpointId ? byEndpoint.get(endpointId) : null);
  if (ep) teardownEndpoint(ep, true);
}

export function detachAllOverlays() {
  for (const ep of Array.from(byEndpoint.values())) {
    teardownEndpoint(ep, true);
  }
}

export function getOverlayDebugState() {
  return {
    loaded: true,
    activeCount: byEndpoint.size,
    endpoints: Array.from(byEndpoint.values()).map(ep => ({
      endpoint_id: ep.debug.endpoint_id,
      tenant: ep.debug.tenant,
      network: ep.debug.network,
      ip: ep.debug.ip,
      activeMode: ep.debug.activeMode,
      fallbackToWs: ep.debug.fallbackToWs,
      webrtcAttempts: ep.debug.webrtcAttempts,
      dcConfig: ep.debug.dcConfig,
      signalsSent: ep.debug.signalsSent,
      signalsReceived: ep.debug.signalsReceived,
      rtcRxPackets: ep.debug.rtcRxPackets,
      rtcTxPackets: ep.debug.rtcTxPackets,
      wsRxPackets: ep.debug.wsRxPackets,
      wsTxPackets: ep.debug.wsTxPackets,
    })),
  };
}

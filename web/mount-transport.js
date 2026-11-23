// WebRTC is a Window API. This broker owns transport only; the execution host
// retains the filesystem grant and validates every operation received here.
export function mountTransport({ p2p = true, ipcPort } = {}) {
  if (ipcPort) return { port: ipcPort, close: () => ipcPort.close() };
  const channel = new MessageChannel(), port = channel.port1;
  let socket, peer, data, role, closed = false, expires, readyTimer, leaseTimer;
  const candidates = [];
  let frameRoute, requiredRoute;
  const tell = message => { if (!closed) port.postMessage(message); };
  const close = errno => {
    if (closed) return; tell({ type: 'closed', errno }); closed = true;
    clearTimeout(readyTimer); clearTimeout(leaseTimer); socket?.close(); data?.close(); peer?.close(); port.close();
  };
  const received = (text, transport) => {
    if (text instanceof ArrayBuffer) {
      if (!text.byteLength || text.byteLength > MAX_FRAME + 4) { close('E2BIG'); return; }
      if ((requiredRoute && requiredRoute !== transport) || (frameRoute && frameRoute !== transport)) { close('EIO'); return; }
      frameRoute ??= transport;
      port.postMessage({ type: 'frame', bytes: text }, [text]);
      return;
    }
    if (typeof text !== 'string' || text.length > MAX_FRAME) { close('E2BIG'); return; }
    try { tell({ type: 'message', message: JSON.parse(text) }); }
    catch { close('EIO'); }
  };
  const sendSignal = message => { if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: 'signal', data: message })); };
  const configure = dc => {
    data = dc;
    dc.binaryType = 'arraybuffer';
    dc.onopen = () => {
      if (requiredRoute === 'p2p') { clearTimeout(readyTimer); frameRoute = 'p2p'; tell({ type: 'ready', mode: 'p2p' }); }
      tell({ type: 'transport', mode: 'p2p' });
    };
    dc.onmessage = event => received(event.data, 'p2p');
    dc.onerror = () => close('ENOTCONN');
    dc.onclose = () => { if (dc.everOpened) close('ENODEV'); };
    dc.addEventListener('open', () => { dc.everOpened = true; });
  };
  const connection = () => {
    if (peer || !p2p || requiredRoute === 'relay' || typeof RTCPeerConnection !== 'function') return peer;
    // Direct candidates only. No implicit third-party STUN/TURN disclosure; when
    // direct connectivity is unavailable the authenticated relay stays in use.
    peer = new RTCPeerConnection({ iceServers: [] });
    peer.onicecandidate = event => { if (event.candidate) sendSignal({ candidate: event.candidate.toJSON() }); };
    peer.ondatachannel = event => configure(event.channel);
    return peer;
  };
  let signaling = Promise.resolve();
  const signal = message => {
    signaling = signaling.then(async () => {
      const pc = connection(); if (!pc) return;
      if (message.description) {
        if (!['offer', 'answer'].includes(message.description.type) || (role === 'owner') !== (message.description.type === 'answer')) return;
        await pc.setRemoteDescription(message.description);
        for (const candidate of candidates.splice(0)) await pc.addIceCandidate(candidate);
        if (message.description.type === 'offer') { await pc.setLocalDescription(await pc.createAnswer()); sendSignal({ description: pc.localDescription.toJSON() }); }
      } else if (message.candidate) {
        if (pc.remoteDescription) await pc.addIceCandidate(message.candidate);
        else if (candidates.length < 32) candidates.push(message.candidate);
      }
    }).catch(() => { if (!data?.everOpened) { peer?.close(); peer = null; } else close('ENOTCONN'); });
  };
  port.onmessage = ({ data: command }) => {
    if (command.type === 'close') { close('ENODEV'); return; }
    if (command.type === 'connect' && !socket) {
      const url = new URL(command.url, location.href);
      if (url.origin !== location.origin || !url.pathname.startsWith('/api/mounts/channel/')) { close('EACCES'); return; }
      role = command.role; expires = command.expires; requiredRoute = command.transport;
      if (!Number.isFinite(expires) || expires <= Date.now() || expires > Date.now() + 3600000) { close('ESTALE'); return; }
      url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:'; socket = new WebSocket(url); socket.binaryType = 'arraybuffer';
      readyTimer = setTimeout(() => close('ETIMEDOUT'), 15000);
      leaseTimer = setTimeout(() => close('ESTALE'), expires - Date.now());
      socket.onmessage = ({ data: text }) => {
        try {
          if (text instanceof ArrayBuffer) { received(text, 'relay'); return; }
          if (typeof text !== 'string' || text.length > 384 * 1024) throw new Error('oversized frame');
          const message = JSON.parse(text);
          if (message.type === 'ready') {
            if (requiredRoute !== 'p2p') { clearTimeout(readyTimer); tell({ type: 'ready', mode: 'relay' }); tell({ type: 'transport', mode: 'relay' }); }
          }
          else if (message.type === 'closed') close(message.errno);
          else if (message.type === 'peer' && role === 'owner' && connection()) {
            configure(peer.createDataChannel('filesystem', { ordered: true }));
            signaling = signaling.then(async () => { await peer.setLocalDescription(await peer.createOffer()); sendSignal({ description: peer.localDescription.toJSON() }); }).catch(() => {});
          } else if (message.type === 'signal') signal(message.data);
          else if (['request', 'reply'].includes(message.type)) received(text, 'relay');
        } catch { close('EIO'); }
      };
      socket.onerror = () => close('ENODEV'); socket.onclose = () => close('ENODEV');
    } else if (['frame', 'send'].includes(command.type) && !closed) {
      try {
        const binary = command.type === 'frame';
        const text = binary ? command.bytes : JSON.stringify(command.message);
        const size = binary ? text.byteLength : text.length;
        if (Date.now() >= expires || size > MAX_FRAME + (binary ? 4 : 0)) throw new Error('expired or oversized');
        // Keep each binary stream on one ordered carrier. Both directions use
        // the carrier selected by its first request, including after ICE changes.
        const available = data?.readyState === 'open' ? 'p2p' : 'relay';
        const selected = binary ? (frameRoute ??= requiredRoute ?? available) : available;
        if (selected === 'p2p') {
          if (data?.readyState !== 'open' || data.bufferedAmount > 512 * 1024) throw new Error('peer unavailable or congested');
          const max = Math.min(peer.sctp?.maxMessageSize || 65536, 65536);
          if (binary) {
            for (let start = 0; start < size; start += max) data.send(text.slice(start, start + max));
          } else data.send(text);
        } else {
          if (socket?.readyState !== WebSocket.OPEN || socket.bufferedAmount > 512 * 1024) throw new Error('relay unavailable or congested');
          socket.send(text);
        }
      } catch { close('ENOTCONN'); }
    }
  };
  port.start();
  return { port: channel.port2, close: () => close('ENODEV') };
}

// One listener publishes a service. Each explicitly requested client mount gets
// its own transport, credits and lifetime; the listener never mounts anything.
export function mountListener(options) {
  const channel = new MessageChannel(), port = channel.port1, clients = new Map();
  let socket, closed = false, timer;
  const close = errno => {
    if (closed) return; closed = true; clearTimeout(timer);
    port.postMessage({ type: 'closed', errno }); socket?.close();
    for (const transport of clients.values()) transport.close(); clients.clear(); port.close();
  };
  port.onmessage = ({ data }) => {
    if (data.type === 'close') { close('ENODEV'); return; }
    if (data.type === 'reject') { if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: 'reject', session: data.session, errno: data.errno })); return; }
    if (data.type !== 'listen' || socket || closed) return;
    const url = new URL(data.url, location.href);
    if (url.origin !== location.origin || !url.pathname.startsWith('/api/mounts/listen/')) { close('EACCES'); return; }
    url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:'; socket = new WebSocket(url);
    timer = setTimeout(() => close('ESTALE'), Math.max(0, Math.min(3600000, data.expires - Date.now())));
    socket.onmessage = ({ data: text }) => {
      try {
        if (typeof text !== 'string' || text.length > 16384) throw new Error('invalid listener message');
        const message = JSON.parse(text);
        if (message.type === 'ready') port.postMessage(message);
        else if (message.type === 'closed') close(message.errno);
        else if (message.type === 'client') {
          if (clients.size >= 16 || clients.has(message.session)) throw new Error('too many clients');
          const transport = mountTransport(options); clients.set(message.session, transport);
          port.postMessage({ ...message, port: transport.port }, [transport.port]);
        } else if (message.type === 'disconnected') { clients.get(message.session)?.close(); clients.delete(message.session); port.postMessage(message); }
      } catch { close('EIO'); }
    };
    socket.onerror = () => close('ENODEV'); socket.onclose = () => close('ENODEV');
  };
  port.start(); return { port: channel.port2, close: () => close('ENODEV') };
}

const MAX_FRAME = 384 * 1024;
const frameError = errno => Object.assign(new Error(errno === 'ENOTCONN' ? 'The shared folder is disconnected.' : errno), { errno });
const textEncoder = new TextEncoder(), textDecoder = new TextDecoder('utf-8', { fatal: true });

function encodeFrame(frame) {
  const bytes = textEncoder.encode(JSON.stringify(frame));
  if (bytes.length > MAX_FRAME) throw frameError('E2BIG');
  const result = new Uint8Array(bytes.length + 4);
  new DataView(result.buffer).setUint32(0, bytes.length);
  result.set(bytes, 4);
  return result.buffer;
}

// Applies only to requests the receiver has handed to the stream.
function isMutation(request) {
  const { op, options, flags } = request.call ?? request;
  if (op === 'open' || op === 'create') {
    return options ? !options.path && (options.create || options.create_new || options.truncate)
      : Number.isSafeInteger(flags) && !(flags & 0o10000000) && !!(flags & 0o1100);
  }
  return ['write', 'ftruncate', 'mkdir', 'remove', 'unlink', 'rmdir', 'unlink_if', 'removeIf', 'remove_if', 'rename', 'link', 'symlink', 'mknod', 'setattr', 'setxattr', 'removexattr'].includes(op);
}

// Client for PortShareTransport. The same port can come from WebRTC, a
// relay, or an explicitly transferred same-host MessageChannel.
export function attachPortTransport(port, initialMode) {
  const pending = new Map();
  let next = 0, terminal, uncertain = false, partial = new Uint8Array(0), handshake;
  let mode = initialMode;
  const close = (errno = 'ENOTCONN') => {
    if (terminal) return;
    const lost = ['ENOTCONN', 'ENODEV', 'ETIMEDOUT', 'EPIPE', 'ECONNRESET'].includes(errno);
    terminal = lost ? 'ENOTCONN' : errno;
    handshake?.reject(frameError(terminal)); handshake = null;
    for (const { reject, mutation, timer } of pending.values()) {
      clearTimeout(timer);
      if (lost && mutation) {
        uncertain = true;
        reject(Object.assign(new Error('Connection lost before the file change was confirmed. It may already have been saved.'), { errno: 'EIO', uncertain_writes: true }));
      } else reject(Object.assign(frameError(terminal), { uncertain_writes: false }));
    }
    pending.clear();
    port.postMessage({ type: 'close' }); port.close();
  };
  const accept = frame => {
    if (frame.type === 'closed') { close(frame.errno); return; }
    const waiting = pending.get(frame.request_id);
    if (frame.type !== 'reply' || !waiting || !frame.result) throw frameError('EIO');
    clearTimeout(waiting.timer);
    pending.delete(frame.request_id);
    if (Object.hasOwn(frame.result, 'Err')) waiting.reject(frameError(frame.result.Err));
    else if (Object.hasOwn(frame.result, 'Ok')) waiting.resolve(frame.result.Ok);
    else { waiting.reject(frameError('EIO')); throw frameError('EIO'); }
  };
  port.onmessage = ({ data }) => {
    try {
      if (data.type === 'closed') { close(data.errno); return; }
      if (data.type === 'ready') { mode = data.mode; handshake?.resolve(); handshake = null; return; }
      if (data.type === 'transport') { mode = data.mode; return; }
      if (data.type === 'message') { accept(data.message); return; }
      if (data.type !== 'frame') return;
      const chunk = new Uint8Array(data.bytes);
      if (chunk.length > MAX_FRAME + 4) throw frameError('E2BIG');
      const buffer = new Uint8Array(partial.length + chunk.length);
      buffer.set(partial); buffer.set(chunk, partial.length);
      let at = 0;
      while (buffer.length - at >= 4) {
        const count = new DataView(buffer.buffer).getUint32(at);
        if (!count || count > MAX_FRAME) throw frameError('E2BIG');
        if (buffer.length - at - 4 < count) break;
        accept(JSON.parse(textDecoder.decode(buffer.subarray(at + 4, at + 4 + count))));
        at += count + 4;
      }
      partial = buffer.slice(at);
    } catch (e) { close(e.errno ?? 'EIO'); }
  };
  port.onmessageerror = () => close();
  const onClose = () => close();
  port.addEventListener('close', onClose);
  port.start();
  return {
    close,
    // A Rust receiver can take the negotiated stream before its first RPC.
    // It then owns framing, all request IDs and the terminal notification.
    takePort() {
      if (terminal || handshake || next || partial.length) throw frameError(terminal ?? 'EBUSY');
      terminal = 'ENOTCONN';
      port.removeEventListener('close', onClose);
      port.onmessage = port.onmessageerror = null;
      return port;
    },
    get uncertain_writes() { return uncertain; },
    get mode() { return mode; },
    connect(args) {
      if (terminal || handshake) return Promise.reject(frameError(terminal ?? 'EBUSY'));
      return new Promise((resolve, reject) => {
        handshake = { resolve, reject };
        port.postMessage({ ...args, type: 'connect', role: 'target' });
      });
    },
    request(request) {
      if (terminal) return Promise.reject(frameError(terminal));
      if (pending.size >= (request.op === 'cancel' ? 5 : 4)) return Promise.reject(frameError('EAGAIN'));
      const id = ++next;
      const answer = new Promise((resolve, reject) => {
        const bytes = encodeFrame({ type: 'request', request_id: id, request });
        port.postMessage({ type: 'frame', bytes }, [bytes]);
        const timer = setTimeout(() => close('ETIMEDOUT'), 15000);
        pending.set(id, { resolve, reject, timer, mutation: isMutation(request) });
      });
      answer.request_id = id;
      return answer;
    },
  };
}

// Host I/O for the kernel's relay adapter. An admission is redeemed using
// the publisher's authenticated cookie and a one-use listener ticket.
export async function exportRelayRpc({ op, id, session, ticket, expires_at, ...args }) {
  const action = op === 'publish' ? 'publish' : op === 'admit' ? `admit/${encodeURIComponent(id)}/${encodeURIComponent(session)}` : op === 'revoke' ? `revoke/${encodeURIComponent(id)}` : null;
  if (!action) throw frameError('EINVAL');
  const body = op === 'publish' ? { ...args, id, seconds: Math.max(1, Math.ceil((expires_at - Date.now()) / 1000)) } : op === 'admit' ? { ticket } : { reason: args.reason };
  let response;
  try { response = await fetch('/api/mounts/' + action, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(15000) }); }
  catch { throw frameError('ENOTCONN'); }
  const value = await response.json();
  if (!response.ok) throw Object.assign(new Error(value.error ?? value.errno), { errno: value.errno });
  return value;
}

// Construct in the trusted worker with the listener port obtained from the
// publisher. CLI publications use a window listener supplied by the same host.
export function exportRelayAdapter(listenerFor, attachClient) {
  const listeners = new Map();
  return async args => {
    if (args.op === 'revoke') {
      const port = listeners.get(args.id);
      listeners.delete(args.id);
      try { return await exportRelayRpc(args); }
      finally { port?.postMessage({ type: 'close' }); port?.close(); }
    }
    const { publisher_pid, owner_uid, ...registration } = args;
    const grant = await exportRelayRpc(registration);
    if (args.op !== 'publish') return grant;
    const listener = await listenerFor({ id: args.id, publisher_pid, owner_uid });
    const port = listener?.port;
    if (!port) {
      await exportRelayRpc({ op: 'revoke', id: args.id });
      throw frameError('ENOTCONN');
    }
    listeners.set(args.id, port);
    try {
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(frameError('ETIMEDOUT')), 15000);
        port.onmessage = ({ data }) => {
          if (data.type === 'ready') { clearTimeout(timer); resolve(); }
          else if (data.type === 'closed') { clearTimeout(timer); listeners.delete(args.id); reject(frameError(data.errno)); }
          else if (data.type === 'client') {
            const channel = data.port;
            // Only the authenticated claim endpoint can mint the kernel grant.
            // The port forwards bytes and the one-time admission ticket.
            const kind = data.transport ?? 'relay';
            void attachClient({ publisherSession: listener.session, export_id: args.id, session: data.session, ticket: data.admission, transport: kind, port: channel }).then(() => {
              channel.postMessage({ type: 'connect', role: 'owner', transport: kind, expires: grant.expires,
                url: `/api/mounts/channel/${args.id}/${data.session}?ticket=${data.ticket}` });
            }).catch(error => {
              port.postMessage({ type: 'reject', session: data.session, errno: error.errno });
              channel.postMessage({ type: 'close' }); channel.close();
            });
          }
        };
        port.start();
        port.postMessage({ type: 'listen', expires: grant.expires, url: `/api/mounts/listen/${args.id}?ticket=${grant.ticket}` });
      });
      return { id: grant.id, uid: grant.uid };
    } catch (e) {
      listeners.delete(args.id); port.postMessage({ type: 'close' }); port.close();
      await exportRelayRpc({ op: 'revoke', id: args.id });
      throw e;
    }
  };
}

// One window-side broker can allocate a fresh connection if ICE fails before
// admission. An established stream never retries a filesystem request.
export function mountConnector(options = {}) {
  if (options.ipcPort) return mountTransport({ ipcPort: options.ipcPort });
  const { port1, port2 } = new MessageChannel(), active = new Set();
  const close = () => { for (const t of active) t.close(); active.clear(); port1.close(); };
  port1.onmessage = ({ data }) => {
    if (data.type === 'close') { close(); return; }
    if (data.type === 'connected') { active.clear(); port1.close(); return; }
    if (data.type !== 'open') return;
    const t = mountTransport({ ...options, p2p: data.transport === 'p2p' });
    active.add(t);
    port1.postMessage({ type: 'port', port: t.port }, [t.port]);
  };
  port1.start();
  return { port: port2, close };
}

export async function connectExportTransport(broker, { id, password = '', writable = false, execute = false, transport }) {
  // A connected cross-tab port is supplied only by the authenticated host.
  // Same-instance IPC uses connect_share_ipc directly in the kernel.
  if (transport === 'ipc') return attachPortTransport(broker, 'ipc');
  const candidates = transport ? [transport] : ['p2p', 'relay'];
  try {
    for (const kind of candidates) {
      const reply = await fetch('/api/mounts/connect/' + encodeURIComponent(id), {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password, write: writable, execute, transport: kind }),
      });
      const grant = await reply.json();
      if (!reply.ok) {
        if (grant.errno === 'EPROTONOSUPPORT' && kind !== candidates.at(-1)) continue;
        throw Object.assign(new Error(grant.error ?? grant.errno), { errno: grant.errno });
      }
      const port = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(frameError('ETIMEDOUT')), 15000);
        broker.addEventListener('message', ({ data }) => { clearTimeout(timer); resolve(data.port); }, { once: true });
        broker.start(); broker.postMessage({ type: 'open', transport: kind });
      });
      const client = attachPortTransport(port);
      try {
        await client.connect({ transport: kind, expires: grant.expires, url: `/api/mounts/channel/${id}/${grant.session}?ticket=${grant.ticket}` });
        client.expires_at = grant.expires;
        broker.postMessage({ type: 'connected' }); broker.close();
        return client;
      } catch (e) {
        client.close();
        if (kind === candidates.at(-1) || !['ENOTCONN', 'ETIMEDOUT', 'EPROTONOSUPPORT'].includes(e.errno)) throw e;
      }
    }
    throw frameError('ENOTCONN');
  } catch (e) { broker.postMessage({ type: 'close' }); broker.close(); throw e; }
}

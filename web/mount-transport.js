// WebRTC is a Window API. This broker owns transport only; the execution host
// retains the filesystem grant and validates every operation received here.
export function mountTransport({ p2p = true } = {}) {
  const channel = new MessageChannel(), port = channel.port1;
  let socket, peer, data, role, closed = false, expires, readyTimer, leaseTimer;
  const routes = new Map(), candidates = [];
  const tell = message => { if (!closed) port.postMessage(message); };
  const close = errno => {
    if (closed) return; tell({ type: 'closed', errno }); closed = true;
    clearTimeout(readyTimer); clearTimeout(leaseTimer); socket?.close(); data?.close(); peer?.close(); routes.clear(); port.close();
  };
  const received = (text, transport) => {
    if (typeof text !== 'string' || text.length > 384 * 1024) { close('E2BIG'); return; }
    try {
      const message = JSON.parse(text);
      if (message.type === 'request') {
        if (routes.size >= 4 || routes.has(message.id)) throw new Error('request window exceeded');
        routes.set(message.id, transport);
      }
      tell({ type: 'message', message });
    } catch { close('EIO'); }
  };
  const sendSignal = message => { if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: 'signal', data: message })); };
  const configure = dc => {
    data = dc;
    dc.onopen = () => tell({ type: 'transport', mode: 'p2p' });
    dc.onmessage = event => received(event.data, 'p2p');
    dc.onerror = () => close('EIO');
    dc.onclose = () => { if (dc.everOpened) close('ENODEV'); };
    dc.addEventListener('open', () => { dc.everOpened = true; });
  };
  const connection = () => {
    if (peer || !p2p || typeof RTCPeerConnection !== 'function') return peer;
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
    }).catch(() => { if (!data?.everOpened) { peer?.close(); peer = null; } else close('EIO'); });
  };
  port.onmessage = ({ data: command }) => {
    if (command.type === 'close') { close('ENODEV'); return; }
    if (command.type === 'connect' && !socket) {
      const url = new URL(command.url, location.href);
      if (url.origin !== location.origin || !url.pathname.startsWith('/api/mounts/channel/')) { close('EACCES'); return; }
      role = command.role; expires = command.expires;
      if (!Number.isFinite(expires) || expires <= Date.now() || expires > Date.now() + 3600000) { close('ESTALE'); return; }
      url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:'; socket = new WebSocket(url);
      readyTimer = setTimeout(() => close('ETIMEDOUT'), 15000);
      leaseTimer = setTimeout(() => close('ESTALE'), expires - Date.now());
      socket.onmessage = ({ data: text }) => {
        try {
          if (typeof text !== 'string' || text.length > 384 * 1024) throw new Error('oversized frame');
          const message = JSON.parse(text);
          if (message.type === 'ready') { clearTimeout(readyTimer); tell({ type: 'ready' }); tell({ type: 'transport', mode: 'relay' }); }
          else if (message.type === 'closed') close(message.errno);
          else if (message.type === 'peer' && role === 'owner' && connection()) {
            configure(peer.createDataChannel('filesystem', { ordered: true }));
            signaling = signaling.then(async () => { await peer.setLocalDescription(await peer.createOffer()); sendSignal({ description: peer.localDescription.toJSON() }); }).catch(() => {});
          } else if (message.type === 'signal') signal(message.data);
          else if (['request', 'reply'].includes(message.type)) received(text, 'relay');
        } catch { close('EIO'); }
      };
      socket.onerror = () => close('ENODEV'); socket.onclose = () => close('ENODEV');
    } else if (command.type === 'send' && !closed) {
      try {
        const message = command.message, text = JSON.stringify(message);
        const selected = message.type === 'reply' ? routes.get(message.id) : data?.readyState === 'open' ? 'p2p' : 'relay';
        if (message.type === 'reply') routes.delete(message.id);
        if (Date.now() >= expires || text.length > 384 * 1024) throw new Error('expired or oversized');
        if (selected === 'p2p') {
          if (data?.readyState !== 'open' || data.bufferedAmount > 256 * 1024 || text.length > Math.min(peer.sctp?.maxMessageSize || 65536, 65536)) throw new Error('peer unavailable or congested');
          data.send(text);
        } else {
          if (socket?.readyState !== WebSocket.OPEN || socket.bufferedAmount > 512 * 1024) throw new Error('relay unavailable or congested');
          socket.send(text);
        }
      } catch { close('EIO'); }
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

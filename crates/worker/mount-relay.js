// The relay authenticates OS accounts and optional export passwords. The owner
// serves its published subtree and enforces VFS ACLs for that verified identity.
// Publishing never targets a device and never creates a receiver's mount.
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
const bad = (errno, message = errno) => Object.assign(new Error(message), { errno });
const hex = bytes => [...new Uint8Array(bytes)].map(n => n.toString(16).padStart(2, '0')).join('');
const secret = () => hex(crypto.getRandomValues(new Uint8Array(32)));
const digest = async text => hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
const id = value => typeof value === 'string' && /^[a-f0-9-]{36}$/.test(value);
const FRAME_MAX = 384 * 1024;
async function passwordHash(password, salt) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: new TextEncoder().encode(salt), iterations: 100000, hash: 'SHA-256' }, key, 256));
}
const equal = (a, b) => { let diff = a.length ^ b.length; for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ (b.charCodeAt(i) || 0); return diff === 0; };
async function body(request) {
  if (request.method !== 'POST') throw bad('EINVAL');
  const reader = request.body?.getReader(); let text = '', size = 0; const decoder = new TextDecoder();
  if (reader) for (;;) { const { value, done } = await reader.read(); if (done) break; size += value.length; if (size > 16384) { await reader.cancel(); throw bad('E2BIG'); } text += decoder.decode(value, { stream: true }); }
  const value = JSON.parse(text + decoder.decode()); if (!value || Array.isArray(value) || typeof value !== 'object') throw bad('EINVAL'); return value;
}
export async function mountRoute(request, env, ctx, worker) {
  const url = new URL(request.url);
  if (request.headers.get('Origin') !== url.origin || request.headers.has('X-Process-Token') || request.headers.has('X-Process-Pid')) return json({ errno: 'EACCES' }, 403);
  const auth = new Request(new URL('/api/sys', url), { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: url.origin, Cookie: request.headers.get('Cookie') ?? '' }, body: JSON.stringify({ calls: ['getcreds'] }) });
  const response = await worker.fetch(auth, env, ctx), identity = response.ok && (await response.json()).results?.[0]?.ok;
  if (!Number.isSafeInteger(identity?.uid)) return json({ errno: 'EACCES' }, 403);
  // Overwrite all authority-bearing fields; neither body fields nor caller
  // headers may claim an account, supplementary group or password result.
  const headers = new Headers(request.headers);
  headers.set('X-OS-Mount-Identity', JSON.stringify({ id: identity.uid, group: identity.gid, groups: identity.groups }));
  const parts = url.pathname.slice('/api/mounts/'.length).split('/');
  const name = ['publish', 'list'].includes(parts[0]) && parts.length === 1 ? 'account:' + identity.uid
    : ['connect', 'listen', 'channel', 'revoke'].includes(parts[0]) && id(parts[1]) ? 'export:' + parts[1] : null;
  if (!name) return json({ errno: 'ENOSYS' }, 404); // Old enrollment/grant endpoints fail closed.
  const result = await env.MOUNTS.get(env.MOUNTS.idFromName(name)).fetch(new Request(request, { headers }));
  if (result.status !== 101 && response.headers.has('Set-Cookie')) {
    const copy = new Response(result.body, result); copy.headers.append('Set-Cookie', response.headers.get('Set-Cookie')); return copy;
  }
  return result;
}
export class MountRelay {
  constructor(state, env) { this.state = state; this.env = env; this.sessions = new Map(); this.tickets = new Map(); this.serial = Promise.resolve(); this.attempts = new Map(); }
  relay(id) { return this.env.MOUNTS.get(this.env.MOUNTS.idFromName('export:' + id)); }
  async fetch(request) {
    const work = this.serial.then(() => this.route(request)); this.serial = work.catch(() => {});
    try { return await work; } catch (error) { return json({ errno: error.errno ?? 'EIO', error: error.message ?? 'mount request failed' }, error.errno === 'ENOENT' ? 404 : 403); }
  }
  async route(request) {
    const url = new URL(request.url);
    if (url.pathname === '/internal/status') {
      const grant = await this.state.storage.get('export'); return json({ active: grant?.version === 2 && !grant.closed && grant.expires > Date.now() });
    }
    if (url.pathname === '/internal/configure') {
      if (await this.state.storage.get('export')) throw bad('EEXIST');
      const grant = await request.json(); await this.state.storage.put('export', grant); await this.state.storage.setAlarm(grant.expires);
      const ticket = await this.ticket('listen', grant.owner.id); return json({ ticket });
    }
    const identity = JSON.parse(request.headers.get('X-OS-Mount-Identity') ?? 'null');
    if (!Number.isSafeInteger(identity?.id)) throw bad('EACCES');
    const [action, exportId, sessionId] = url.pathname.slice('/api/mounts/'.length).split('/');
    if (action === 'publish' || action === 'list') {
      const args = await body(request), exports = await this.state.storage.get('exports-v2') ?? {};
      for (const [key, g] of Object.entries(exports)) {
        if (g.expires <= Date.now() || !(await (await this.relay(key).fetch('https://mount/internal/status')).json()).active) delete exports[key];
      }
      if (action === 'list') {
        await this.state.storage.put('exports-v2', exports); return json({ uid: identity.id, exports: Object.values(exports) });
      }
      if (Object.keys(exports).length >= 32) throw bad('ENOSPC');
      if (typeof args.name !== 'string' || !args.name || args.name.length > 80 || !Number.isInteger(args.seconds) || args.seconds < 30 || args.seconds > 3600 || typeof args.write !== 'boolean' || typeof args.execute !== 'boolean' || typeof args.password !== 'string' || args.password.length > 256) throw bad('EINVAL');
      const grant = { version: 2, id: crypto.randomUUID(), owner: identity, name: args.name, write: args.write, execute: args.execute, expires: Date.now() + args.seconds * 1000, password: !!args.password };
      const salt = secret(), verifier = args.password ? { salt, hash: await passwordHash(args.password, salt) } : null;
      const configured = await this.relay(grant.id).fetch(new Request('https://mount/internal/configure', { method: 'POST', body: JSON.stringify({ ...grant, verifier }) }));
      if (!configured.ok) throw bad('EIO');
      exports[grant.id] = grant; await this.state.storage.put('exports-v2', exports);
      return json({ ...grant, ...(await configured.json()), uid: identity.id });
    }
    const grant = await this.state.storage.get('export');
    if (grant?.version !== 2 || grant.id !== exportId) throw bad('ESTALE');
    if (action === 'revoke') {
      await body(request); if (identity.id !== grant.owner.id) throw bad('EACCES'); await this.finish('ESTALE'); return json({ uid: identity.id, revoked: true });
    }
    if (grant.closed || grant.expires <= Date.now()) throw bad('ESTALE');
    if (action === 'connect') {
      const args = await body(request);
      if (!this.listener) throw bad('ENODEV', 'the publishing host is offline');
      if (this.sessions.size >= 16) throw bad('EBUSY');
      if (typeof args.password !== 'string' || args.password.length > 256 || typeof args.write !== 'boolean' || typeof args.execute !== 'boolean') throw bad('EINVAL');
      let password = false;
      if (args.password) {
        const minute = Math.floor(Date.now() / 60000), attempts = await this.state.storage.get('attempts') ?? { minute, total: 0, users: {} };
        if (attempts.minute !== minute) { attempts.minute = minute; attempts.total = 0; attempts.users = {}; }
        if (++attempts.total > 32 || (attempts.users[identity.id] = (attempts.users[identity.id] ?? 0) + 1) > 5) { await this.state.storage.put('attempts', attempts); throw bad('EAGAIN', 'too many password attempts; try again in a minute'); }
        await this.state.storage.put('attempts', attempts);
        if (!grant.verifier || !equal(await passwordHash(args.password, grant.verifier.salt), grant.verifier.hash)) throw bad('EACCES', 'invalid export credentials');
        password = true;
      }
      if (args.write && !grant.write || args.execute && !grant.execute) throw bad('EACCES', 'requested access exceeds the export');
      const session = crypto.randomUUID(), value = { sockets: new Map(), pending: new Set(), identity, write: args.write, execute: args.execute };
      this.sessions.set(session, value); value.timer = setTimeout(() => this.closeSession(session, 'ETIMEDOUT'), 15000);
      const ownerTicket = await this.ticket('owner', grant.owner.id, session), targetTicket = await this.ticket('target', identity.id, session);
      this.listener.send(JSON.stringify({ type: 'client', session, ticket: ownerTicket, identity, password, write: args.write, execute: args.execute }));
      return json({ id: grant.id, name: grant.name, expires: grant.expires, session, ticket: targetTicket, write: args.write, execute: args.execute, uid: identity.id });
    }
    if (!['listen', 'channel'].includes(action) || request.method !== 'GET' || request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') throw bad('EINVAL');
    const hash = await digest(url.searchParams.get('ticket') ?? ''), ticket = this.tickets.get(hash); this.tickets.delete(hash);
    if (!ticket || ticket.uid !== identity.id || ticket.expires <= Date.now() || (action === 'listen' ? ticket.role !== 'listen' : ticket.session !== sessionId)) throw bad('EACCES');
    if (action === 'listen') return this.listen(grant);
    return this.socket(grant, sessionId, ticket.role, ticket.closed);
  }
  async ticket(role, uid, session) {
    for (const [key, ticket] of this.tickets) if (ticket.expires <= Date.now()) this.tickets.delete(key);
    if (this.tickets.size >= 64) throw bad('EAGAIN');
    const value = secret(); this.tickets.set(await digest(value), { role, uid, session, expires: Date.now() + 30000 }); return value;
  }
  listen(grant) {
    if (this.listener) throw bad('EBUSY');
    const [client, server] = Object.values(new WebSocketPair()); server.accept(); this.listener = server;
    server.addEventListener('message', event => {
      try {
        if (typeof event.data !== 'string' || event.data.length > 1024) throw bad('E2BIG');
        const message = JSON.parse(event.data);
        if (message.type !== 'reject' || !id(message.session)) throw bad('EINVAL');
        this.closeSession(message.session, message.errno === 'EACCES' ? 'EACCES' : 'ENODEV');
      } catch { void this.finish('EIO'); }
    });
    server.addEventListener('close', () => { void this.finish('ENODEV'); }); server.addEventListener('error', () => { void this.finish('ENODEV'); });
    server.send(JSON.stringify({ type: 'ready', expires: grant.expires })); return new Response(null, { status: 101, webSocket: client });
  }
  socket(grant, session, role, closed) {
    // The owner may refuse access before the receiver opens its socket. Its
    // authenticated, one-use ticket retains the reason until consumed/expired.
    if (closed) {
      const [client, server] = Object.values(new WebSocketPair()); server.accept();
      server.send(JSON.stringify({ type: 'closed', errno: closed })); server.close(1000, closed);
      return new Response(null, { status: 101, webSocket: client });
    }
    const state = this.sessions.get(session); if (!state || !['owner', 'target'].includes(role)) throw bad('ESTALE');
    if (state.sockets.has(role)) throw bad('EBUSY');
    const [client, server] = Object.values(new WebSocketPair()); server.accept(); state.sockets.set(role, server);
    let signals = 0, window = Date.now();
    server.addEventListener('message', event => {
      try {
        if (typeof event.data !== 'string' || event.data.length > FRAME_MAX || Date.now() >= grant.expires) throw bad('ESTALE');
        const message = JSON.parse(event.data), other = state.sockets.get(role === 'owner' ? 'target' : 'owner');
        if (!other) throw bad('ENODEV');
        if (message.type === 'signal') {
          if (Date.now() - window > 60000) { signals = 0; window = Date.now(); }
          if (event.data.length > 32768 || ++signals > 128) throw bad('E2BIG');
        } else if (role === 'target' && message.type === 'request' && Number.isSafeInteger(message.id) && message.id > 0) {
          if (state.pending.size >= 4 || state.pending.has(message.id)) throw bad('EAGAIN'); state.pending.add(message.id);
        } else if (role === 'owner' && message.type === 'reply' && state.pending.has(message.id)) state.pending.delete(message.id);
        else throw bad('EACCES');
        other.send(event.data);
      } catch { this.closeSession(session, 'EIO'); }
    });
    server.addEventListener('close', () => this.closeSession(session, 'ENODEV')); server.addEventListener('error', () => this.closeSession(session, 'ENODEV'));
    if (state.sockets.size === 2) {
      clearTimeout(state.timer);
      for (const [peerRole, socket] of state.sockets) socket.send(JSON.stringify({ type: 'ready', role: peerRole, expires: grant.expires }));
      for (const socket of state.sockets.values()) socket.send(JSON.stringify({ type: 'peer' }));
    }
    return new Response(null, { status: 101, webSocket: client });
  }
  closeSession(session, errno) {
    const state = this.sessions.get(session); if (!state) return; this.sessions.delete(session); clearTimeout(state.timer);
    for (const ticket of this.tickets.values()) if (ticket.session === session) ticket.closed = errno;
    for (const socket of state.sockets.values()) { try { socket.send(JSON.stringify({ type: 'closed', errno })); socket.close(1000, errno); } catch {} }
    try { this.listener?.send(JSON.stringify({ type: 'disconnected', session })); } catch {}
  }
  async finish(errno) {
    const listener = this.listener; this.listener = null;
    for (const session of this.sessions.keys()) this.closeSession(session, errno); this.tickets.clear();
    try { listener?.send(JSON.stringify({ type: 'closed', errno })); listener?.close(1000, errno); } catch {}
    const grant = await this.state.storage.get('export'); if (grant && !grant.closed) await this.state.storage.put('export', { ...grant, closed: true });
  }
  async alarm() { await this.finish('ESTALE'); }
}

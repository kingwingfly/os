import { localImage, pinImage } from './local-mounts.js';
const bad = (errno, message = errno) => Object.assign(new Error(message), { errno });
const CHUNK = 24 * 1024, MAX = 128 * 1024 * 1024;
const mutations = new Set(['write', 'mkdir', 'remove', 'rename']);
const disconnected = errno => bad(errno, errno === 'EACCES'
  ? 'Permission denied. Your OS account cannot access this directory. Ask the owner to check its permissions or ACL, or enter the export password if one is set.'
  : errno === 'ESTALE' ? 'This share has expired or was stopped. Ask the owner for a new address.'
  : errno === 'ETIMEDOUT' ? 'The shared folder did not respond. Check that the owner’s tab is online, then reconnect.'
  : 'The shared folder is disconnected. Check that the owner’s tab is online and still publishing it.');
const encode = bytes => { let text = ''; for (let i = 0; i < bytes.length; i += 8192) text += String.fromCharCode(...bytes.subarray(i, i + 8192)); return btoa(text); };
const decode = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));
const digest = async bytes => [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(n => n.toString(16).padStart(2, '0')).join('');

export async function mountApi(workspace, action, args = {}) {
  workspace.check();
  const response = await fetch('/api/mounts/' + action, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(args) });
  const value = await response.json();
  if (!response.ok) throw bad(value.errno ?? 'EIO', value.error);
  if (value.uid !== undefined && value.uid !== workspace.identity.uid) throw bad('EACCES', 'account changed during mount authorization');
  workspace.check(); return value;
}

class Connection {
  constructor(port, expires) {
    if (!(port instanceof MessagePort)) throw bad('EINVAL', 'a private transport port is required');
    this.port = port; this.expires = expires; this.active = true; this.mode = 'relay'; this.pending = new Map(); this.sequence = 0;
    this.ready = new Promise((resolve, reject) => { this.readyResolve = resolve; this.readyReject = reject; });
    this.timer = setTimeout(() => this.close('ESTALE'), Math.max(0, expires - Date.now()));
    this.connectionTimer = setTimeout(() => this.close('ETIMEDOUT'), 15000);
    port.onmessage = ({ data }) => {
      if (data.type === 'closed') this.close(data.errno);
      else if (data.type === 'ready') { clearTimeout(this.connectionTimer); this.readyResolve(); }
      else if (data.type === 'transport') this.mode = data.mode;
      else if (data.type === 'message') {
        const message = data.message;
        if (message?.type === 'reply') {
          const waiting = this.pending.get(message.id); if (!waiting) { this.close('EIO'); return; }
          clearTimeout(waiting.timer); this.pending.delete(message.id);
          if (message.error) waiting.reject(bad(message.error.errno ?? 'EIO', message.error.message)); else waiting.resolve(message.value);
        } else if (message?.type === 'request') void this.serve?.(message);
      }
    };
    port.onmessageerror = () => this.close('EIO'); port.start();
  }
  check() { if (!this.active || Date.now() >= this.expires) throw bad('ENODEV', 'shared mount is offline, revoked or expired'); }
  async connect(url, role) { this.port.postMessage({ type: 'connect', url, role, expires: this.expires }); await this.ready; this.check(); }
  send(message) { this.check(); this.port.postMessage({ type: 'send', message }); }
  request(op, args) {
    this.check(); if (this.pending.size >= 4) return Promise.reject(bad('EAGAIN', 'shared mount request window is full'));
    const id = ++this.sequence;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.close('ETIMEDOUT'), 15000);
      this.pending.set(id, { resolve, reject, timer, mutation: mutations.has(op) });
      try { this.send({ type: 'request', id, op, args }); } catch (error) { clearTimeout(timer); this.pending.delete(id); reject(error); }
    });
  }
  close(errno = 'ENODEV') {
    if (!this.active) return; this.active = false; clearTimeout(this.timer); clearTimeout(this.connectionTimer);
    const error = disconnected(errno);
    this.readyReject(error);
    for (const waiting of this.pending.values()) {
      clearTimeout(waiting.timer);
      waiting.reject(waiting.mutation ? bad(errno, 'Connection lost before the file change was confirmed. It may already have been saved. Check the shared folder before repeating the change.') : error);
    }
    this.pending.clear();
    this.port.postMessage({ type: 'close' }); this.port.close(); this.onclose?.();
  }
}
async function connect(grant, port, role) {
  const connection = new Connection(port, grant.expires);
  try { await connection.connect('/api/mounts/channel/' + grant.id + '/' + grant.session + '?ticket=' + grant.ticket, role); return connection; }
  catch (error) { connection.close(); throw error; }
}
const safePath = path => {
  if (typeof path !== 'string' || path.length > 4096 || path.startsWith('/') || /[\0\\]/.test(path) || path.split('/').includes('..')) throw bad('EACCES', 'path escapes exported directory');
  return path.split('/').filter(name => name && name !== '.').join('/');
};
export async function exportMount(workspace, args) {
  const found = workspace.resolve(args.path);
  if (!found || !found.mount.provider.forIdentity) throw bad('EACCES', 'publish a local filesystem');
  const { provider, grant: source } = found.mount;
  if ((await provider.stat(source, found.relative)).kind !== 'directory') throw bad('ENOTDIR');
  if (source.kind === 'native-directory' && provider.identitySupported !== true) throw bad('EPROTONOSUPPORT', 'Update os-local-helper before sharing this folder.');
  const grant = await mountApi(workspace, 'publish', { name: args.name, write: !source.readOnly, execute: source.execute, seconds: args.seconds, password: args.password ?? '' });
  const clients = new Map(), port = args.port;
  if (!(port instanceof MessagePort)) throw bad('EINVAL');
  let readyResolve, readyReject, active = true;
  const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
  const controller = { get active() { return active; }, mode: 'listening', close() {
    if (!active) return; active = false; clearTimeout(timer); readyReject(bad('ENODEV'));
    for (const connection of clients.values()) connection.close(); clients.clear();
    port.postMessage({ type: 'close' }); port.close();
  } };
  const timer = setTimeout(() => controller.close(), 15000);
  port.onmessage = ({ data }) => {
    if (data.type === 'ready') { clearTimeout(timer); readyResolve(); }
    else if (data.type === 'closed') controller.close();
    else if (data.type === 'disconnected') { clients.get(data.session)?.close(); clients.delete(data.session); }
    else if (data.type === 'client') void (async () => {
      // The authenticated listener supplies this identity; request frames from
      // the receiver never supply or replace it. Password auth is scoped here.
      const identity = data.password ? provider.owner : data.identity;
      const service = provider.forIdentity(identity, found.relative);
      await service.access(source, found.relative, 1);
      workspace.check(); if (!active) throw bad('ENODEV');
      const connection = new Connection(data.port, grant.expires); clients.set(data.session, connection);
      serve(workspace, found, service, source, { ...grant, write: data.write, execute: data.execute }, connection);
      await connection.connect('/api/mounts/channel/' + grant.id + '/' + data.session + '?ticket=' + data.ticket, 'owner');
    })().catch(error => { data.port?.postMessage({ type: 'close' }); data.port?.close(); if (active) port.postMessage({ type: 'reject', session: data.session, errno: error.errno ?? 'EACCES' }); });
  };
  port.onmessageerror = () => controller.close(); port.start();
  port.postMessage({ type: 'listen', url: '/api/mounts/listen/' + grant.id + '?ticket=' + grant.ticket, expires: grant.expires });
  try { await ready; } catch (error) { controller.close(); await mountApi(workspace, 'revoke/' + grant.id).catch(() => {}); throw error; }
  workspace.exports ??= new Map(); workspace.exports.set(grant.id, { connection: controller, grant, mount: found.mount, clients });
  const { ticket, ...publicGrant } = grant;
  return { ...publicGrant, address: 'osfs:' + grant.id };
}
function serve(workspace, found, provider, source, grant, connection) {
  const pins = new Map(), handles = new Map(), seen = new Set(); let busy = 0, highest = 0;
  connection.onclose = () => { pins.clear(); for (const handle of handles.values()) void provider.release?.(source, handle)?.catch(() => {}); handles.clear(); };
  connection.serve = async message => {
    try {
      connection.check(); workspace.check();
      if (!Number.isSafeInteger(message.id) || message.id <= 0 || message.id <= highest - 16 || seen.has(message.id) || busy >= 4) throw bad('EAGAIN');
      seen.add(message.id); highest = Math.max(highest, message.id); for (const id of seen) if (id <= highest - 16) seen.delete(id);
      busy++;
      let value;
      try {
        const args = message.args ?? {}, path = args.handle === undefined ? args.path === undefined ? null : [found.relative, safePath(args.path)].filter(Boolean).join('/') : handles.get(args.handle);
        if (args.handle !== undefined && !path) throw bad('EBADF');
        switch (message.op) {
          case 'hold': {
            if (handles.size >= 128) throw bad('EMFILE');
            const held = await provider.hold(source, path, found.relative), id = crypto.randomUUID(); handles.set(id, held); value = id; break;
          }
          case 'release': { if (!handles.has(args.handle)) throw bad('EBADF'); await provider.release(source, path); handles.delete(args.handle); value = null; break; }
          case 'policy':
            if (!['access', 'getxattr', 'listxattr'].includes(args.name)) throw bad('EPERM');
            value = await provider.policy(source, path, args.name, args.options); break;
          case 'stat': value = await provider.stat(source, path, { follow: args.follow !== false }); break;
          case 'list': {
            value = await provider.list(source, path, { offset: args.offset, limit: Math.min(16, args.limit ?? 16) });
            for (const entry of value.entries) entry.stat = await provider.stat(source, [path, entry.name].filter(Boolean).join('/'), { follow: false });
            break;
          }
          case 'read': value = encode(await provider.read(source, path, args.offset, Math.min(CHUNK, args.count ?? CHUNK))); break;
          case 'write':
            if (!grant.write || typeof args.data !== 'string' || args.data.length > CHUNK * 4 / 3) throw bad('EACCES');
            value = await provider.write(source, path, decode(args.data), { offset: args.offset, append: !!args.append, truncate: args.truncate ?? null, create: !!args.create }); break;
          case 'mkdir': case 'remove': case 'rename':
            if (!grant.write) throw bad('EROFS');
            value = message.op === 'mkdir' ? await provider.mkdir(source, path) : message.op === 'remove'
              ? await provider.remove(source, path, !!args.directory)
              : await provider.rename(source, path, [found.relative, safePath(args.to)].filter(Boolean).join('/')); break;
          case 'pin': {
            if (!grant.execute || pins.size >= 2) throw bad('EACCES');
            const pin = await provider.pin(source, path), id = crypto.randomUUID(); pins.set(id, await localImage(pin));
            value = { id, size: pin.size, digest: pin.digest }; break;
          }
          case 'image': {
            const pin = pins.get(args.id); if (!pin) throw bad('ESTALE');
            if (!Number.isSafeInteger(args.offset) || args.offset < 0) throw bad('EINVAL');
            await pin.check(); value = encode(pin.bytes.subarray(args.offset, args.offset + CHUNK)); break;
          }
          case 'unpin': pins.delete(args.id); value = null; break;
          default: throw bad('EOPNOTSUPP');
        }
      } finally { busy--; }
      connection.check(); connection.send({ type: 'reply', id: message.id, value });
    } catch (error) { try { connection.send({ type: 'reply', id: message.id, error: { errno: error.errno ?? 'EIO', message: error.message } }); } catch {} }
  };
}

export async function attachMount(workspace, args) {
  const exportId = String(args.address ?? args.export ?? '').replace(/^osfs:/, '');
  if (!/^[a-f0-9-]{36}$/.test(exportId)) throw bad('EINVAL', 'enter an osfs: export address');
  const grant = await mountApi(workspace, 'connect/' + exportId, { password: args.password ?? '', write: args.writable === true, execute: args.execute === true });
  const connection = await connect(grant, args.port, 'target');
  return new RemoteMount(connection, grant);
}
class RemoteMount {
  #handles = new WeakMap();
  constructor(connection, grant) {
    this.connection = connection; this.remote = grant;
    this.grant = Object.freeze({ kind: 'shared', name: grant.name, readOnly: !grant.write, execute: grant.execute });
  }
  check(grant) { if (grant !== this.grant) throw bad('EACCES'); this.connection.check(); }
  request(grant, op, args) {
    this.check(grant);
    if (args.path && typeof args.path === 'object') {
      const handle = this.#handles.get(args.path); if (!handle) throw bad('EBADF');
      const { path, ...rest } = args; args = { ...rest, handle };
    } else if (args.path !== undefined) safePath(args.path);
    return this.connection.request(op, args);
  }
  async hold(grant, path) { const id = await this.request(grant, 'hold', { path }); const handle = Object.freeze({}); this.#handles.set(handle, id); return handle; }
  async release(grant, path) { try { await this.request(grant, 'release', { path }); } finally { this.#handles.delete(path); } }
  policy(grant, path, name, options) { return this.request(grant, 'policy', { path, name, options }); }
  async access(grant, path, mode) {
    if (mode & 2 && grant.readOnly) throw bad('EROFS');
    await this.policy(grant, path, 'access', { mode });
    if (mode & 1 && !grant.execute && (await this.stat(grant, path)).kind !== 'directory') throw bad('EACCES');
  }
  async stat(grant, path, { follow = true } = {}) {
    const value = await this.request(grant, 'stat', { path, follow });
    if (!['file', 'directory', 'symlink'].includes(value.kind) || value.kind === 'file' && (!Number.isSafeInteger(value.size) || value.size < 0)) throw bad('EIO', 'invalid remote metadata');
    return { ...value, readOnly: grant.readOnly };
  }
  async list(grant, path, { offset = 0, limit = 256 } = {}) {
    const value = await this.request(grant, 'list', { path, offset, limit: Math.min(16, limit) });
    if (!Array.isArray(value.entries) || value.entries.length > Math.min(16, limit) || value.entries.some(entry => typeof entry.name !== 'string' || !entry.name || entry.name.includes('/') || ['.', '..'].includes(entry.name) || !entry.stat || !['file', 'directory', 'symlink'].includes(entry.stat.kind) || entry.stat.kind === 'file' && (!Number.isSafeInteger(entry.stat.size) || entry.stat.size < 0)) || value.next !== null && (!value.entries.length || value.next !== offset + value.entries.length)) throw bad('EIO', 'invalid remote directory page');
    for (const entry of value.entries) entry.stat = { ...entry.stat, readOnly: grant.readOnly, executable: grant.execute && entry.stat.executable };
    return value;
  }
  async read(grant, path, offset, length) {
    const data = decode(await this.request(grant, 'read', { path, offset, count: Math.min(CHUNK, length) }));
    if (data.length > Math.min(CHUNK, length)) throw bad('EIO'); return data;
  }
  async write(grant, path, bytes, options = {}) {
    if (grant.readOnly) throw bad('EROFS'); let written = 0, answer;
    do {
      const chunk = bytes.subarray(written, written + CHUNK);
      answer = await this.request(grant, 'write', { path, ...options, offset: (options.offset ?? 0) + written, truncate: written ? null : options.truncate, data: encode(chunk) });
      if (answer.written !== chunk.length) throw bad('EIO', 'invalid remote write acknowledgment'); written += chunk.length;
    } while (written < bytes.length);
    return { ...answer, written };
  }
  mkdir(grant, path) { return this.request(grant, 'mkdir', { path }); }
  remove(grant, path, directory) { return this.request(grant, 'remove', { path, directory }); }
  rename(grant, path, to) { safePath(to); return this.request(grant, 'rename', { path, to }); }
  async pin(grant, path) {
    if (!grant.execute) throw bad('EACCES');
    const pin = await this.request(grant, 'pin', { path });
    try {
      if (!Number.isSafeInteger(pin.size) || pin.size < 8 || pin.size > MAX || !/^[a-f0-9]{64}$/.test(pin.digest)) throw bad('ENOEXEC');
      const bytes = new Uint8Array(pin.size);
      for (let offset = 0; offset < bytes.length; offset += CHUNK) {
        const part = decode(await this.request(grant, 'image', { id: pin.id, offset }));
        if (part.length !== Math.min(CHUNK, bytes.length - offset)) throw bad('ESTALE'); bytes.set(part, offset);
      }
      if (await digest(bytes) !== pin.digest) throw bad('EIO', 'remote executable snapshot digest mismatch');
      return pinImage(bytes, () => this.check(grant));
    } finally { await this.request(grant, 'unpin', { id: pin.id }).catch(() => {}); }
  }
  unmount(grant) { if (grant !== this.grant) throw bad('EACCES'); this.connection.close(); }
}

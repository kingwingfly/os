import { localImage, pinImage } from './local-mounts.js';
import { NativeMount } from './native-mount.js';
const bad = (errno, message = errno) => Object.assign(new Error(message), { errno });
const CHUNK = 24 * 1024, MAX = 128 * 1024 * 1024;
const mutations = new Set(['write', 'ftruncate', 'mkdir', 'remove', 'removeIf', 'rename', 'link', 'symlink']);
const isMutation = (op, args) => mutations.has(op)
  || (op === 'open' && Number.isSafeInteger(args?.flags) && !(args.flags & 0o10000000) && (args.flags & 0o1100) !== 0);
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
  if (value.uid !== undefined) {
    // Under Wave 4B, MountRelay authenticates the server/cloud cookie UID (guest >= 1_000_000
    // when Cloud is signed out, or `cloud_uid` when signed in), which is separate from the local
    // `os-cowfs` UID (`workspace.identity.uid`). Pin the expected server relay UID per workspace
    // (or active `cloud_status().cloud_uid`) so mid-request account changes still fail EACCES.
    let expectedRelayUid = workspace.relayUid;
    try {
      const cloud = globalThis.kernel?.cloud_status ? JSON.parse(globalThis.kernel.cloud_status()) : null;
      if (cloud?.signed_in && typeof cloud.cloud_uid === 'number') {
        expectedRelayUid = cloud.cloud_uid;
        workspace.relayUid = cloud.cloud_uid;
      }
    } catch { /* fallback to pinned relayUid */ }
    if (expectedRelayUid === undefined) {
      workspace.relayUid = value.uid;
    } else if (value.uid !== expectedRelayUid) {
      throw bad('EACCES', 'account changed during mount authorization');
    }
  }
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
      const mutation = op === 'checked' ? isMutation(args.op, args.args) : isMutation(op, args);
      this.pending.set(id, { resolve, reject, timer, mutation });
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
    this.port.postMessage({ type: 'close' }); this.port.close(); this.onclose?.(errno);
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
  const resolved = workspace.resolveExport
    ? await workspace.resolveExport(args.path)
    : (() => {
        const f = workspace.resolve?.(args.path);
        return f ? { mountPath: f.mount.path, relative: f.relative, grant: f.mount.grant, provider: f.mount.provider, mountRef: f.mount } : null;
      })();
  if (!resolved || !resolved.provider?.forIdentity) throw bad('EACCES', 'publish a local filesystem');
  const { provider, grant: source, relative, mountPath } = resolved;
  const found = { relative, mount: resolved.mountRef ?? { path: mountPath, provider, grant: source } };
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
      // Same-account tabs share the publisher's relay UID (`grant.uid`) and act as the
      // local mount owner (`provider.owner`) while distinct relay accounts remain gated by
      // POSIX permissions/ACLs against their own relay UID.
      const ownerRelayId = grant.owner?.id ?? grant.uid;
      const clientRelayId = data.identity?.id ?? data.identity?.uid;
      const isPublisherAccount = typeof ownerRelayId === 'number' && clientRelayId === ownerRelayId;
      const identity = (data.password || isPublisherAccount) ? provider.owner : data.identity;
      const service = provider.forIdentity(identity, found.relative);
      await service.access(source, found.relative, 1);
      workspace.check(); if (!active) throw bad('ENODEV');
      const connection = new Connection(data.port, grant.expires); clients.set(data.session, connection);
      serve(workspace, found, service, source, { ...grant, write: Boolean(data.write) && !source.readOnly, execute: Boolean(data.execute) && source.execute }, connection);
      await connection.connect('/api/mounts/channel/' + grant.id + '/' + data.session + '?ticket=' + data.ticket, 'owner');
    })().catch(error => { data.port?.postMessage({ type: 'close' }); data.port?.close(); if (active) port.postMessage({ type: 'reject', session: data.session, errno: error.errno ?? 'EACCES' }); });
  };
  port.onmessageerror = () => controller.close(); port.start();
  port.postMessage({ type: 'listen', url: '/api/mounts/listen/' + grant.id + '?ticket=' + grant.ticket, expires: grant.expires });
  try { await ready; } catch (error) { controller.close(); await mountApi(workspace, 'revoke/' + grant.id).catch(() => {}); throw error; }
  workspace.exports ??= new Map(); workspace.exports.set(grant.id, { connection: controller, grant, mount: found.mount, mountPath: mountPath ?? found.mount.path, clients });
  const { ticket, ...publicGrant } = grant;
  return { ...publicGrant, address: 'osfs:' + grant.id };
}
const PATH_ONLY_OPS = new Set(['open', 'hold', 'parentOf', 'list', 'mkdir', 'remove', 'removeIf', 'rename', 'link', 'symlink', 'readlink', 'pin']);
const VFS_SAFE_MAX = 0x1fffffffffffff;
const VFS_U32_MAX = 0xffffffff;
const KIND_TYPE_BITS = { file: 0o100000, directory: 0o040000, symlink: 0o120000 };
const isSafeNonNeg = n => Number.isSafeInteger(n) && n >= 0;
const isSafePos53 = n => Number.isSafeInteger(n) && n >= 1 && n <= VFS_SAFE_MAX;
const isU32 = n => Number.isSafeInteger(n) && n >= 0 && n <= VFS_U32_MAX;
const isNsec = n => Number.isSafeInteger(n) && n >= 0 && n <= 999_999_999;

function sanitizeRemoteStat(value, grant) {
  if (!value || typeof value !== 'object') throw bad('EIO', 'invalid remote metadata');
  if (!['file', 'directory', 'symlink'].includes(value.kind)) throw bad('EIO', 'invalid remote metadata');
  if (value.kind === 'file' && !isSafeNonNeg(value.size)) throw bad('EIO', 'invalid remote metadata');
  if (value.link !== undefined && (typeof value.link !== 'string' || value.link.includes('\0'))) throw bad('EIO', 'invalid remote metadata');
  if (value.vfs === null) throw bad('EIO', 'invalid remote metadata');
  let sanitizedVfs;
  if (value.vfs !== undefined) {
    const raw = value.vfs;
    if (!raw || typeof raw !== 'object') throw bad('EIO', 'invalid remote metadata');
    if (!isSafePos53(raw.dev) || !isSafePos53(raw.ino)) throw bad('EIO', 'invalid remote metadata');
    if (!Number.isSafeInteger(raw.mode) || raw.mode < 0 || raw.mode > 0o177777) throw bad('EIO', 'invalid remote metadata');
    const typeBits = raw.mode & 0o170000;
    if (typeBits !== KIND_TYPE_BITS[value.kind]) throw bad('EIO', 'invalid remote metadata');
    if (!isU32(raw.uid) || !isU32(raw.gid) || !isU32(raw.nlink) || !isSafeNonNeg(raw.size)) throw bad('EIO', 'invalid remote metadata');
    if (!isSafeNonNeg(raw.mtime) || !isSafeNonNeg(raw.ctime) || !isSafeNonNeg(raw.atime)) throw bad('EIO', 'invalid remote metadata');
    for (const ns of [raw.mtime_nsec, raw.ctime_nsec, raw.atime_nsec]) {
      if (ns !== undefined && !isNsec(ns)) throw bad('EIO', 'invalid remote metadata');
    }
    if (raw.link != null && (typeof raw.link !== 'string' || raw.link.includes('\0'))) throw bad('EIO', 'invalid remote metadata');
    let mode = raw.mode;
    if (grant.readOnly) mode &= ~0o222;
    if (!grant.execute && value.kind === 'file') mode &= ~0o111;
    sanitizedVfs = {
      dev: raw.dev,
      ino: raw.ino,
      ...(isSafePos53(raw.generation) ? { generation: raw.generation } : {}),
      mode,
      nlink: raw.nlink,
      uid: raw.uid,
      gid: raw.gid,
      user: typeof raw.user === 'string' ? raw.user : '',
      group: typeof raw.group === 'string' ? raw.group : '',
      size: raw.size,
      mtime: raw.mtime,
      mtime_nsec: raw.mtime_nsec ?? 0,
      ctime: raw.ctime,
      ctime_nsec: raw.ctime_nsec ?? 0,
      atime: raw.atime,
      atime_nsec: raw.atime_nsec ?? 0,
      ...(raw.link != null ? { link: raw.link } : {}),
      ...(typeof raw.rdev === 'string' ? { rdev: raw.rdev } : {}),
      ...(raw.acl !== undefined ? { acl: Boolean(raw.acl) } : {}),
    };
  }
  return {
    ...value,
    readOnly: grant.readOnly,
    executable: value.kind === 'directory' || (grant.execute && !!value.executable),
    ...(typeof value.fsId === 'string' && value.fsId ? { fsId: value.fsId } : {}),
    ...(sanitizedVfs ? { vfs: sanitizedVfs } : {}),
  };
}

function serve(workspace, found, baseProvider, source, grant, connection) {
  const pins = new Map(), handles = new Map(), seen = new Set(); let busy = 0, highest = 0;
  const retainHandle = handle => {
    if (!connection.active) {
      void baseProvider.release?.(source, handle)?.catch(() => {});
      throw bad('ENODEV');
    }
    const id = crypto.randomUUID();
    handles.set(id, handle);
    return id;
  };
  connection.onclose = () => { pins.clear(); for (const handle of handles.values()) void baseProvider.release?.(source, handle)?.catch(() => {}); handles.clear(); };
  connection.serve = async message => {
    try {
      connection.check(); workspace.check();
      if (!Number.isSafeInteger(message.id) || message.id <= 0 || message.id <= highest - 16 || seen.has(message.id) || busy >= 4) throw bad('EAGAIN');
      seen.add(message.id); highest = Math.max(highest, message.id); for (const id of seen) if (id <= highest - 16) seen.delete(id);
      busy++;
      let value, scoped;
      try {
        const checked = message.op === 'checked';
        const op = checked ? message.args?.op : message.op;
        const args = (checked ? message.args?.args : message.args) ?? {};
        if (checked) {
          const checks = message.args.checks;
          if (!Array.isArray(checks) || checks.length > 2 || !baseProvider.withPathChecks) throw bad('EOPNOTSUPP');
          scoped = baseProvider.withPathChecks(checks.map(([relative, node]) => [
            [found.relative, safePath(relative)].filter(Boolean).join('/'), node,
          ]));
        }
        const provider = scoped ?? baseProvider;
        if (args.handle !== undefined && PATH_ONLY_OPS.has(op)) throw bad('EINVAL', 'handle is not valid for path operation');
        const path = args.handle === undefined ? args.path === undefined ? null : [found.relative, safePath(args.path)].filter(Boolean).join('/') : handles.get(args.handle);
        if (args.handle !== undefined && !path) throw bad('EBADF');
        switch (op) {
          case 'open': {
            if (handles.size >= 128) throw bad('EMFILE');
            const flags = Number.isSafeInteger(args.flags) ? args.flags : 0;
            const exec = Boolean(args.exec);
            let openFlags = flags;
            if (exec) {
              if (!grant.execute) throw bad('EACCES');
              if ((flags & 3) !== 0 || (flags & 0o10000000) || (flags & (0o100 | 0o1000 | 0o200000))) throw bad('EINVAL');
            }
            if (!grant.write && !(flags & 0o10000000)) {
              if ((flags & 3) !== 0 || (flags & 0o1000) !== 0) throw bad('EROFS');
              if (flags & 0o100) {
                try {
                  await provider.stat(source, path, { follow: !(flags & 0o400000) && !(flags & 0o200) });
                } catch (err) {
                  if (err?.errno === 'ENOENT') throw bad('EROFS');
                  throw err;
                }
                if (flags & 0o200) throw bad('EEXIST');
                openFlags &= ~(0o100 | 0o200);
              }
            }
            if (!provider.open) {
              if (openFlags & 0o200) throw bad('EOPNOTSUPP');
              const st = await provider.stat(source, path, { follow: !(openFlags & 0o400000) });
              if ((openFlags & 0o400000) && st.kind === 'symlink') throw bad('ELOOP');
              if (st.kind === 'directory') throw bad(exec ? 'EACCES' : (openFlags & 0o200000) ? 'EOPNOTSUPP' : 'EISDIR');
              if (openFlags & 0o200000) throw bad('ENOTDIR');
              if (exec && !st.executable) throw bad('EACCES');
              value = retainHandle(await provider.hold(source, path, found.relative)); break;
            }
            value = retainHandle(await provider.open(source, path, openFlags, args.mode ?? 0o666, args.umask ?? 0o077, exec)); break;
          }
          case 'hold': {
            if (handles.size >= 128) throw bad('EMFILE');
            value = retainHandle(await provider.hold(source, path, found.relative)); break;
          }
          case 'release': { if (!handles.has(args.handle)) throw bad('EBADF'); await provider.release(source, path); handles.delete(args.handle); value = null; break; }
          case 'policy': {
            const readOps = ['access', 'getxattr', 'listxattr', 'statfs'];
            const writeOps = ['chmod', 'chown', 'utimens', 'setxattr', 'removexattr'];
            if (!readOps.includes(args.name) && !(grant.write && writeOps.includes(args.name))) throw bad('EPERM');
            if (!provider.policy) throw bad('EOPNOTSUPP');
            value = await provider.policy(source, path, args.name, args.options); break;
          }
          case 'tryLock':
          case 'lock':
          case 'unlock': {
            if (args.handle === undefined) throw bad('EBADF');
            const fn = provider[op];
            if (typeof fn !== 'function') throw bad('EOPNOTSUPP');
            value = op === 'unlock'
              ? await fn.call(provider, source, path, args.family, args.start, args.end ?? null)
              : await fn.call(provider, source, path, args.family, args.kind, args.start, args.end ?? null);
            break;
          }
          case 'testLock': {
            if (args.handle === undefined) throw bad('EBADF');
            if (typeof provider.testLock !== 'function') throw bad('EOPNOTSUPP');
            value = await provider.testLock(source, path, args.kind, args.start, args.end ?? null);
            break;
          }
          case 'parentOf':
            if (!provider.parentOf) throw bad('EOPNOTSUPP');
            value = await provider.parentOf(source, path, args.node); break;
          case 'stat': value = await provider.stat(source, path, { follow: args.follow !== false }); break;
          case 'list': {
            value = await provider.list(source, path, { offset: args.offset, limit: Math.min(16, args.limit ?? 16) });
            for (const entry of value.entries) entry.stat = await provider.stat(source, [path, entry.name].filter(Boolean).join('/'), { follow: false });
            break;
          }
          case 'read': value = encode(await provider.read(source, path, args.offset, Math.min(CHUNK, args.count ?? CHUNK))); break;
          case 'write':
            if (!grant.write || typeof args.data !== 'string' || args.data.length > CHUNK * 4 / 3) throw bad('EACCES');
            value = await provider.write(source, path, decode(args.data), { offset: args.offset, append: !!args.append, truncate: args.truncate ?? null, create: !!args.create, umask: args.umask }); break;
          case 'ftruncate':
            if (!grant.write) throw bad('EROFS');
            if (!Number.isSafeInteger(args.size) || args.size < 0) throw bad('EINVAL');
            value = provider.ftruncate
              ? await provider.ftruncate(source, path, args.size)
              : await provider.write(source, path, new Uint8Array(), { truncate: args.size });
            break;
          case 'fsync':
            if (args.handle === undefined) throw bad('EBADF');
            if (!provider.fsync) throw bad('EINVAL');
            value = await provider.fsync(source, path, !!args.dataOnly); break;
          case 'mkdir':
            if (!grant.write) throw bad('EROFS');
            value = await provider.mkdir(source, path, args.mode ?? 0o777, args.umask ?? 0o077); break;
          case 'removeIf':
            if (!grant.write) throw bad('EROFS');
            if (typeof provider.removeIf !== 'function') throw bad('EOPNOTSUPP');
            value = await provider.removeIf(source, path, args.node); break;
          case 'remove':
            if (!grant.write) throw bad('EROFS');
            value = await provider.remove(source, path, !!args.directory); break;
          case 'rename':
            if (!grant.write) throw bad('EROFS');
            if (args.noreplace && provider instanceof NativeMount) throw bad('EOPNOTSUPP', 'atomic no-replace rename is unavailable on this filesystem');
            value = await provider.rename(source, path, [found.relative, safePath(args.to)].filter(Boolean).join('/'), !!args.noreplace); break;
          case 'link':
            if (!grant.write) throw bad('EROFS');
            if (!provider.link) throw bad('EOPNOTSUPP');
            value = await provider.link(source, path, [found.relative, safePath(args.to)].filter(Boolean).join('/'), !!args.follow); break;
          case 'symlink':
            if (!grant.write) throw bad('EROFS');
            if (!provider.symlink) throw bad('EOPNOTSUPP');
            if (typeof args.target !== 'string' || !args.target || args.target.length > 4096 || args.target.includes('\0')) throw bad('EINVAL');
            value = await provider.symlink(source, args.target, path); break;
          case 'readlink': {
            if (provider.readlink) { value = await provider.readlink(source, path); break; }
            const st = await provider.stat(source, path, { follow: false });
            if (st.link === undefined) throw bad('EINVAL');
            value = st.link; break;
          }
          case 'pin': {
            if (!grant.execute || pins.size >= 2) throw bad('EACCES');
            const pin = await provider.pin(source, path), image = await localImage(pin), id = crypto.randomUUID();
            if (!connection.active) throw bad('ENODEV');
            pins.set(id, image);
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
      } finally { scoped?.free(); busy--; }
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
  constructor(connection, grant, parent, checks) {
    this.connection = connection; this.remote = grant;
    if (parent) {
      this.grant = parent.grant;
      this.#handles = parent.#handles;
      this.checks = checks;
      return;
    }
    this.grant = Object.freeze({ kind: 'shared', name: grant.name, readOnly: !grant.write, execute: grant.execute });
    this.connection.onclose = errno => {
      this.onProviderEvent?.(errno === 'EACCES' ? 'revoked' : 'lost');
    };
  }
  withPathChecks(checks) { return new RemoteMount(this.connection, this.remote, this, checks); }
  check(grant) { if (grant !== this.grant) throw bad('EACCES'); this.connection.check(); }
  request(grant, op, args) {
    this.check(grant);
    if (args.path && typeof args.path === 'object') {
      const handle = this.#handles.get(args.path); if (!handle) throw bad('EBADF');
      const { path, ...rest } = args; args = { ...rest, handle };
    } else if (args.path !== undefined) safePath(args.path);
    return this.checks ? this.connection.request('checked', { op, args, checks: this.checks }) : this.connection.request(op, args);
  }
  async open(grant, path, flags = 0, mode = 0o666, umask = 0o077, exec = false) {
    if (exec && !grant.execute) throw bad('EACCES');
    if (!(flags & 0o10000000) && ((flags & 3) !== 0 || (flags & 0o1000) !== 0) && grant.readOnly) throw bad('EROFS');
    const id = await this.request(grant, 'open', { path, flags, mode, umask, exec: Boolean(exec) });
    const handle = Object.freeze({}); this.#handles.set(handle, id); return handle;
  }
  async hold(grant, path) { const id = await this.request(grant, 'hold', { path }); const handle = Object.freeze({}); this.#handles.set(handle, id); return handle; }
  async release(grant, path) { try { await this.request(grant, 'release', { path }); } finally { this.#handles.delete(path); } }
  tryLock(grant, handle, family, kind, start, end = null) { return this.request(grant, 'tryLock', { path: handle, family, kind, start, end }); }
  lock(grant, handle, family, kind, start, end = null) { return this.request(grant, 'lock', { path: handle, family, kind, start, end }); }
  unlock(grant, handle, family, start, end = null) { return this.request(grant, 'unlock', { path: handle, family, start, end }); }
  testLock(grant, handle, kind, start, end = null) { return this.request(grant, 'testLock', { path: handle, kind, start, end }); }
  policy(grant, path, name, options) { return this.request(grant, 'policy', { path, name, options }); }
  async access(grant, path, mode) {
    if (mode & 2 && grant.readOnly) throw bad('EROFS');
    await this.policy(grant, path, 'access', { mode });
    if (mode & 1 && !grant.execute && (await this.stat(grant, path)).kind !== 'directory') throw bad('EACCES');
  }
  async stat(grant, path, { follow = true } = {}) {
    return sanitizeRemoteStat(await this.request(grant, 'stat', { path, follow }), grant);
  }
  async list(grant, path, { offset = 0, limit = 256 } = {}) {
    const value = await this.request(grant, 'list', { path, offset, limit: Math.min(16, limit) });
    if (!Array.isArray(value.entries) || value.entries.length > Math.min(16, limit) || value.entries.some(entry => typeof entry.name !== 'string' || !entry.name || entry.name.includes('/') || ['.', '..'].includes(entry.name) || !entry.stat) || value.next !== null && (!value.entries.length || value.next !== offset + value.entries.length)) throw bad('EIO', 'invalid remote directory page');
    for (const entry of value.entries) entry.stat = sanitizeRemoteStat(entry.stat, grant);
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
  ftruncate(grant, path, size) {
    if (grant.readOnly) throw bad('EROFS');
    return this.request(grant, 'ftruncate', { path, size });
  }
  fsync(grant, path, dataOnly = false) {
    return this.request(grant, 'fsync', { path, dataOnly: !!dataOnly });
  }
  mkdir(grant, path, mode = 0o777, umask = 0o077) { return this.request(grant, 'mkdir', { path, mode, umask }); }
  async parentOf(grant, path, node) {
    return sanitizeRemoteStat(await this.request(grant, 'parentOf', { path, node }), grant);
  }
  removeIf(grant, path, node) { return this.request(grant, 'removeIf', { path, node }); }
  remove(grant, path, directory) { return this.request(grant, 'remove', { path, directory }); }
  rename(grant, path, to, noreplace = false) { safePath(to); return this.request(grant, 'rename', { path, to, noreplace: !!noreplace }); }
  link(grant, path, to, follow = false) { safePath(to); return this.request(grant, 'link', { path, to, follow: !!follow }); }
  symlink(grant, target, path) {
    if (typeof target !== 'string' || !target || target.length > 4096 || target.includes('\0')) throw bad('EINVAL');
    return this.request(grant, 'symlink', { path, target });
  }
  readlink(grant, path) { return this.request(grant, 'readlink', { path }); }
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

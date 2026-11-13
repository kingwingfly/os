// Per-login execution-host VFS. Mount paths select a provider; only retained object
// grants authorize it. No path, read token or fd received from another host is trusted.
import { LocalMounts } from './local-mounts.js';
import { loadLocal } from './loader.js';
import { privateExtension } from './private-extension.js';
import { PermissionMount } from './mount-policy.js';
import { NativeMount } from './native-mount.js';

export const LOCAL_ROOT = '/mnt/local';
export const LOCAL_FD = 0x60000000;
export const localFdPath = path => {
  if (typeof path !== 'string') return false;
  try { path = absolute(path); } catch { return false; }
  return /^\/proc\/self\/fd\/\d+$/.test(path) && Number(path.split('/').at(-1)) >= LOCAL_FD;
};
const INLINE = 256 * 1024;
const bad = (errno, message = errno) => Object.assign(new Error(message), { errno });
const encoded = bytes => { let text = ''; for (let i = 0; i < bytes.length; i += 8192) text += String.fromCharCode(...bytes.subarray(i, i + 8192)); return btoa(text); };
const decoded = data => Uint8Array.from(atob(data), c => c.charCodeAt(0));
export function absolute(path, cwd = '/') {
  if (typeof path !== 'string' || !path || path.includes('\0') || path.includes('\\') || path.length > 4096) throw bad('EINVAL');
  const out = [];
  for (const part of (path.startsWith('/') ? path : cwd + '/' + path).split('/')) {
    if (!part || part === '.') continue;
    if (part === '..') out.pop(); else out.push(part);
  }
  return '/' + out.join('/');
}
export const localPath = path => {
  if (typeof path !== 'string') return false;
  const reserved = path => [LOCAL_ROOT, '/mnt/shared', '/opt/private'].some(root => path === root || path.startsWith(root + '/'));
  if (reserved(path)) return true; // Keep attempted escapes inside the rejecting provider.
  try { return reserved(absolute(path)); } catch { return false; }
};

let nextFd = LOCAL_FD, nextInode = 0x60000000;
let compilation = Promise.resolve();
export class Workspace {
  constructor(identity, { provider = new LocalMounts(), evaluate } = {}) {
    this.identity = Object.freeze({ id: identity.id, uid: identity.uid, gid: identity.gid, groups: identity.groups });
    this.evaluatePolicy = evaluate; this.provider = provider; this.mounts = new Map(); this.fds = new Map(); this.inodes = new Map();
    this.page = {}; this.alive = true;
  }
  check() { if (!this.alive) throw bad('ENODEV', 'workspace is closed'); }
  scope() { this.check(); return {}; }
  list() { this.check(); return [...this.mounts.values()].filter(m => m.active).map(({ path, name, grant, cloud }) => ({ path, name, kind: grant.kind, writable: !grant.readOnly, execute: grant.execute, cloud })); }
  async mount(args) {
    this.check();
    if (this.list().length >= 16) throw bad('ENOSPC');
    if (typeof args.cloud !== 'boolean') throw bad('EINVAL', 'cloud delegation must be explicit');
    const name = String(args.name ?? args.handle?.name ?? 'files');
    if (!/^[\p{L}\p{N}_. -]{1,80}$/u.test(name) || name === '.' || name === '..') throw bad('EINVAL', 'invalid mount name');
    const path = LOCAL_ROOT + '/' + name;
    if (this.mounts.get(path)?.active) throw bad('EEXIST', 'mount name is already in use');
    if (!args.files && !args.url && !args.handle && args.storage !== true) throw bad('EINVAL', 'a directory handle, helper connection or browser storage is required');
    let handle = args.handle;
    if (args.storage === true) {
      // Acquire OPFS in its execution host. Passing filesystem handles between
      // browser threads is not portable (and crashes some WebKit builds).
      try {
        const root = await navigator.storage.getDirectory();
        handle = await root.getDirectoryHandle('os-workspace', { create: true });
      } catch {
        throw bad('ENOTSUP', 'Browser storage is unavailable in this session. Use a regular browser window or mount a host folder.');
      }
    }
    const provider = args.url ? await NativeMount.connect(args) : this.provider;
    const grant = args.url ? provider.grant : args.files ? await provider.mountFiles(args.files, { execute: !!args.execute })
      : await provider.mountDirectory(handle, { execute: !!args.execute, writable: !!args.writable, originPrivate: args.storage === true || args.originPrivate === true });
    if (!this.alive) { provider.unmount(grant); this.check(); }
    if (this.mounts.get(path)?.active) { provider.unmount(grant); throw bad('EEXIST'); }
    if (this.list().length >= 16) { provider.unmount(grant); throw bad('ENOSPC'); }
    const mount = { path, name, grant, provider: new PermissionMount(provider, grant, this.identity, this.evaluatePolicy), cloud: args.cloud, active: true };
    this.mounts.set(path, mount);
    return this.list().find(m => m.path === path);
  }
  async activate(args, validate) {
    this.check();
    if (this.list().length >= 16) throw bad('ENOSPC');
    if (!/^[a-zA-Z0-9_.-]{1,80}$/.test(args.name) || ['.', '..'].includes(args.name) || typeof args.cloud !== 'boolean') throw bad('EINVAL');
    const path = '/opt/private/' + args.name;
    if (this.mounts.get(path)?.active) throw bad('EEXIST');
    const paths = args.sources ?? [args.source];
    if (!Array.isArray(paths) || paths.length > 16) throw bad('EINVAL');
    const sources = paths.map(path => {
      const found = this.resolve(path); if (!found) throw bad('EACCES', 'private packages require a local mount');
      return { provider: found.mount.provider, grant: found.mount.grant, prefix: found.relative ? found.relative.replace(/\/$/, '') + '/' : '' };
    });
    const provider = await privateExtension(sources, validate);
    this.check();
    if (this.mounts.get(path)?.active) { provider.unmount(provider.grant); throw bad('EEXIST'); }
    if (this.list().length >= 16) { provider.unmount(provider.grant); throw bad('ENOSPC'); }
    this.mounts.set(path, { path, name: args.name, grant: provider.grant, provider, cloud: args.cloud, active: true });
    return this.list().find(mount => mount.path === path);
  }
  unmount(path) {
    this.check(); const mount = this.mounts.get(path);
    if (!mount?.active) throw bad('ENOENT', 'mount does not exist');
    mount.active = false; mount.provider.unmount(mount.grant);
    for (const exported of this.exports?.values() ?? []) if (exported.mount === mount) exported.connection.close();
    for (const [fd, value] of this.fds) if (value.mount === mount) this.fds.delete(fd);
  }
  close() { this.alive = false; this.fds.clear(); for (const exported of this.exports?.values() ?? []) exported.connection.close(); for (const m of this.mounts.values()) { if (m.active) m.provider.unmount(m.grant); m.active = false; } }
  resolve(path) {
    this.check();
    const clean = absolute(path);
    const mount = [...this.mounts.values()].filter(m => clean === m.path || clean.startsWith(m.path + '/')).sort((a, b) => b.path.length - a.path.length)[0];
    if (mount && !mount.active) throw bad('ENODEV', 'mount was detached');
    // A lexical path beginning in a mounted tree cannot escape that grant through '..'.
    const entered = [...this.mounts.values()].find(m => path === m.path || path.startsWith(m.path + '/'));
    if (entered && entered !== mount) throw bad('EACCES', 'path escapes its local mount');
    return mount ? { mount, path: clean, relative: clean.slice(mount.path.length).replace(/^\//, '') } : null;
  }
  virtual(path) { return ['/', '/mnt', LOCAL_ROOT, '/mnt/shared', '/opt', '/opt/private'].includes(path); }
  async image(path, cwd) {
    const absolutePath = path.startsWith('/') ? path : cwd.replace(/\/$/, '') + '/' + path;
    const found = this.resolve(absolutePath);
    if (!found) { if (localPath(absolute(absolutePath))) throw bad('ENOENT'); return null; }
    const pin = await found.mount.provider.pin(found.mount.grant, found.relative);
    return { pin, path: found.path, local: { digest: pin.digest, size: pin.size, cloud: found.mount.cloud }, load: () => { const next = compilation.then(() => loadLocal(pin)); compilation = next.catch(() => {}); return next; } };
  }
  inode(path) { if (!this.inodes.has(path)) this.inodes.set(path, nextInode++); return this.inodes.get(path); }
  metadata(path, metadata, mount) {
    if (metadata.vfs) return { ...metadata.vfs, ino: this.inode(path), size: metadata.size ?? 0 };
    const directory = metadata.kind === 'directory', executable = directory || !!mount?.grant.execute && (metadata.executable ?? true);
    const time = Math.floor((metadata.lastModified ?? 0) / 1000);
    // These are the virtual grant's permissions, never a claim about host ownership/x bits.
    const link = metadata.link?.startsWith('/') ? mount.path + metadata.link : metadata.link;
    return { ino: this.inode(path), mode: (directory ? 0o040000 : metadata.kind === 'symlink' ? 0o120000 : 0o100000) | 0o400 | (metadata.readOnly ? 0 : 0o200) | (executable ? 0o100 : 0),
      ...(link === undefined ? {} : { link }),
      nlink: 1, uid: this.identity.uid, gid: this.identity.gid ?? this.identity.uid, user: 'local', group: 'local', size: metadata.size ?? 0,
      mtime: time, ctime: time, atime: time };
  }
  async stat(path, follow = true) {
    const found = this.resolve(path);
    if (found) return this.metadata(found.path, await found.mount.provider.stat(found.mount.grant, found.relative, { follow }), found.mount);
    path = absolute(path);
    if (this.virtual(path)) return this.metadata(path, { kind: 'directory', readOnly: true });
    throw bad('ENOENT');
  }
  descriptor(fd, scope) {
    this.check(); const found = this.fds.get(fd);
    if (!found || found.scope !== scope) throw bad('EBADF');
    if (!found.mount.active) throw bad('ENODEV');
    return found;
  }
  async open(path, flags, scope) {
    const found = this.resolve(path);
    if (!found) { await this.stat(path); throw bad('EISDIR'); }
    if (!Number.isSafeInteger(flags) || flags < 0 || (flags & 3) === 3) throw bad('EINVAL');
    const write = (flags & 3) !== 0;
    if (write && found.mount.grant.readOnly) throw bad('EROFS');
    if (found.mount.provider.open) {
      if (this.fds.size >= 1024 || nextFd >= 0x7fffffff) throw bad('EMFILE');
      const handle = await found.mount.provider.open(found.mount.grant, found.relative, flags);
      try {
        const stat = this.metadata(found.path, await found.mount.provider.stat(found.mount.grant, handle), found.mount);
        const fd = nextFd++, token = 'local:' + crypto.randomUUID();
        this.fds.set(fd, { ...found, handle, scope, read: (flags & 3) !== 1, write, append: !!(flags & 0o2000), token });
        return { fd, token, size: stat.size, stat, chunk_size: INLINE, local: true };
      } catch (error) { await found.mount.provider.release(found.mount.grant, handle).catch(() => {}); throw error; }
    }
    if (flags & 0o200) throw bad('EOPNOTSUPP', 'atomic exclusive creation is unavailable on this filesystem');
    if (flags & ~(3 | 0o100 | 0o1000 | 0o2000 | 0o200000 | 0o400000 | 0o2000000)) throw bad('EOPNOTSUPP');
    let stat;
    try { stat = await this.stat(path); } catch (error) {
      if (error.errno !== 'ENOENT' || !write || !(flags & 0o100)) throw error;
      await found.mount.provider.write(found.mount.grant, found.relative, new Uint8Array(), { create: true });
      stat = await this.stat(path);
    }
    if ((stat.mode & 0o170000) === 0o040000) throw bad('EISDIR');
    if (flags & 0o200000) throw bad('ENOTDIR');
    if ((flags & 0o400000) && (await this.stat(path, false)).link !== undefined) throw bad('ELOOP');
    if ((flags & 0o1000) && !write) throw bad('EACCES');
    if (this.fds.size >= 1024 || nextFd >= 0x7fffffff) throw bad('EMFILE');
    if (found.mount.provider.access) await found.mount.provider.access(found.mount.grant, found.relative, (flags & 3) === 0 ? 4 : (flags & 3) === 1 ? 2 : 6);
    const handle = found.mount.provider.hold ? await found.mount.provider.hold(found.mount.grant, found.relative) : found.relative;
    try {
      if (flags & 0o1000) await found.mount.provider.write(found.mount.grant, handle, new Uint8Array(), { truncate: 0 });
      stat = this.metadata(found.path, await found.mount.provider.stat(found.mount.grant, handle), found.mount);
    } catch (error) {
      try { await found.mount.provider.release?.(found.mount.grant, handle); } catch {}
      throw error;
    }
    const fd = nextFd++, token = 'local:' + crypto.randomUUID();
    this.fds.set(fd, { ...found, handle, scope, read: (flags & 3) !== 1, write, append: !!(flags & 0o2000), token });
    return { fd, token, size: stat.size, stat, chunk_size: INLINE, local: true };
  }
  async read(fd, offset, count, scope) {
    const found = this.descriptor(fd, scope);
    if (!found.read) throw bad('EBADF');
    if (!Number.isSafeInteger(count) || count < 0 || count > INLINE) throw bad('EINVAL');
    const bytes = await found.mount.provider.read(found.mount.grant, found.handle, offset, count);
    return { data: encoded(bytes), size: (await this.fstat(fd, scope)).size };
  }
  async write(fd, bytes, offset, scope, append) {
    const found = this.descriptor(fd, scope);
    if (!found.write) throw bad('EBADF');
    return found.mount.provider.write(found.mount.grant, found.handle, bytes, { offset, append: append ?? found.append });
  }
  async fstat(fd, scope) { const file = this.descriptor(fd, scope); return this.metadata(file.path, await file.mount.provider.stat(file.mount.grant, file.handle), file.mount); }
  async closeFd(fd, scope) { const file = this.descriptor(fd, scope); this.fds.delete(fd); await file.mount.provider.release?.(file.mount.grant, file.handle); }
  closeScope(scope) { for (const [fd, found] of this.fds) if (found.scope === scope) void this.closeFd(fd, scope).catch(() => {}); }
  async entries(path, cookie = 0, count = null) {
    const all = count == null; count ??= 4096;
    if (!Number.isSafeInteger(cookie) || cookie < 0 || !Number.isSafeInteger(count) || count < 0 || count > 4096) throw bad('EINVAL');
    const found = this.resolve(path); let names = [];
    if (found) {
      let offset = cookie;
      while (names.length < count) {
        const page = await found.mount.provider.list(found.mount.grant, found.relative, { offset, limit: Math.min(256, count - names.length) });
        names.push(...page.entries); if (page.next === null) break;
        if (all && names.length === count) throw bad('E2BIG', 'directory requires paginated reads');
        offset = page.next;
      }
    } else {
      path = absolute(path); if (!this.virtual(path)) throw bad('ENOENT');
      const prefix = path === '/' ? '/' : path + '/';
      names = [...new Set([...this.mounts.values()].filter(m => m.active && m.path.startsWith(prefix)).map(m => m.path.slice(prefix.length).split('/')[0]))].slice(cookie, cookie + count);
    }
    const entries = [];
    // Bound outstanding metadata requests by the shared provider's credit window.
    for (let offset = 0; offset < names.length; offset += 4) {
      entries.push(...await Promise.all(names.slice(offset, offset + 4).map(async row => {
        const name = typeof row === 'string' ? row : row.name, full = path.replace(/\/$/, '') + '/' + name;
        return { name, stat: row.stat && found ? this.metadata(full, row.stat, found.mount) : await this.stat(full, false) };
      })));
    }
    return entries;
  }
  async calls(calls, scope, cloud, { allowClosedCloud = false } = {}) {
    if (!allowClosedCloud) this.check();
    if (!Array.isArray(calls) || calls.length > 256) throw bad('E2BIG');
    const results = [];
    for (const call of calls) {
      try {
        const name = typeof call === 'string' ? call : Object.keys(call)[0], arg = typeof call === 'string' ? {} : { ...call[name] };
        if (arg.fd && typeof arg.fd === 'object') {
          const reference = results[arg.fd.ref];
          if (reference?.err) throw bad(reference.err.errno);
          if (!Number.isInteger(reference?.ok?.fd)) throw bad('EBADF'); arg.fd = reference.ok.fd;
        }
        const target = arg.path ?? arg.from;
        if (!this.alive) {
          // Shutdown revokes private mounts immediately. Existing processes may
          // still run ordinary cleanup through their original server credentials.
          const privateAccess = arg.fd >= LOCAL_FD || [arg.path, arg.from, arg.to].some(path => localPath(path) || localFdPath(path));
          if (!allowClosedCloud || privateAccess) throw bad('ENODEV');
          results.push(...await cloud([typeof call === 'string' ? call : { [name]: arg }])); continue;
        }
        if (localFdPath(target)) {
          const fd = Number(absolute(target).split('/').at(-1)), file = this.descriptor(fd, scope);
          if (name === 'readlink') results.push({ ok: file.path });
          else if (name === 'stat') results.push({ ok: await this.fstat(fd, scope) });
          else throw bad('EOPNOTSUPP');
          continue;
        }
        const clean = typeof target === 'string' ? absolute(target) : null;
        const owned = clean && (localPath(clean) || this.resolve(target)) || (arg.to && localPath(absolute(arg.to)));
        const localFd = Number.isInteger(arg.fd) && arg.fd >= LOCAL_FD;
        if (!owned && !localFd && !(clean && this.virtual(clean))) {
          results.push(...await cloud([typeof call === 'string' ? call : { [name]: arg }])); continue;
        }
        if (clean && this.virtual(clean) && !localPath(clean) && !this.resolve(target)) {
          const [answer] = await cloud([{ [name]: name === 'getdents' ? { ...arg, cookie: 0, count: null } : arg }]);
          if (name === 'getdents') {
            const extra = await this.entries(clean);
            const existing = answer.ok ?? [], merged = [...existing, ...extra.filter(e => !existing.some(x => x.name === e.name))];
            const offset = arg.cookie ?? 0;
            results.push({ ok: merged.slice(offset, arg.count == null ? undefined : offset + arg.count) }); continue;
          }
          if (answer.ok !== undefined) { results.push(answer); continue; }
        }
        let value;
        switch (name) {
          case 'stat': case 'lstat': value = await this.stat(target, name === 'stat'); break;
          case 'fstat': value = await this.fstat(arg.fd, scope); break;
          case 'access': {
            const found = this.resolve(target);
            if (found?.mount.provider.access) { value = await found.mount.provider.access(found.mount.grant, found.relative, arg.mode); break; }
            const stat = await this.stat(target); if ((arg.mode & 7) & ~((stat.mode >> 6) & 7)) throw bad('EACCES'); value = null; break;
          }
          case 'getdents': value = await this.entries(target, arg.cookie, arg.count); break;
          case 'open':
            if (arg.version != null || arg.sha256 != null) throw bad('EOPNOTSUPP', 'versioned atomic uploads are unavailable on this filesystem');
            value = await this.open(target, arg.flags ?? 0, scope); break;
          case 'close': await this.closeFd(arg.fd, scope); value = { closed: true }; break;
          case 'pread': {
            if (arg.fd !== undefined) value = await this.read(arg.fd, arg.offset ?? 0, arg.count ?? INLINE, scope);
            else { const fd = await this.open(target, 0, scope); try { value = await this.read(fd.fd, arg.offset ?? 0, arg.count ?? INLINE, scope); } finally { await this.closeFd(fd.fd, scope).catch(() => {}); } }
            break;
          }
          case 'pwrite': value = await this.write(arg.fd, decoded(arg.data), (arg.index ?? 0) * INLINE, scope); break;
          case 'ftruncate': {
            const file = this.descriptor(arg.fd, scope); if (!file.write) throw bad('EBADF');
            value = await file.mount.provider.write(file.mount.grant, file.handle, new Uint8Array(), { truncate: arg.size }); break;
          }
          case 'mkdir': case 'rmdir': case 'unlink': {
            const file = this.resolve(target); if (!file) throw bad('EROFS');
            if (file.mount.grant.readOnly) throw bad('EROFS');
            value = name === 'mkdir' ? await file.mount.provider.mkdir(file.mount.grant, file.relative, arg.mode)
              : await file.mount.provider.remove(file.mount.grant, file.relative, name === 'rmdir'); break;
          }
          case 'rename': {
            if (arg.noreplace) throw bad('EOPNOTSUPP', 'atomic no-replace rename is unavailable on this filesystem');
            const a = this.resolve(arg.from), b = this.resolve(arg.to);
            if (!a || !b || a.mount !== b.mount) throw bad('EXDEV');
            if (a.mount.grant.readOnly) throw bad('EROFS');
            value = await a.mount.provider.rename(a.mount.grant, a.relative, b.relative); break;
          }
          case 'chmod': case 'chown': case 'getxattr': case 'setxattr': case 'listxattr': case 'removexattr': case 'fchmod': {
            const file = name === 'fchmod' ? this.descriptor(arg.fd, scope) : this.resolve(target);
            if (!file?.mount.provider.policy) throw bad('EOPNOTSUPP');
            value = await file.mount.provider.policy(file.mount.grant, name === 'fchmod' ? file.handle : file.relative, name === 'fchmod' ? 'chmod' : name, arg); break;
          }
          case 'readlink': { const stat = await this.stat(target, false); if (stat.link === undefined) throw bad('EINVAL'); value = stat.link; break; }
          default: throw bad('EOPNOTSUPP', 'operation is unsupported by this local filesystem');
        }
        // Void provider methods still need an explicit ABI success value.
        // JSON drops undefined properties, leaving Rust an invalid Return ({}).
        results.push({ ok: value ?? null });
      } catch (error) { results.push({ err: { errno: error.errno ?? 'EIO', detail: error.message } }); }
    }
    return results;
  }
}

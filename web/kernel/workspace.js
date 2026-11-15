// Per-login execution-host VFS. Mount paths select a provider; only retained object
// grants authorize it. No path, read token or fd received from another host is trusted.
import { pinImage } from './local-mounts.js';
import { loadLocal } from './loader.js';
import { privateExtension } from './private-extension.js';
import { NativeMount } from './native-mount.js';
import { createOpfsStore, createDirectoryStore } from './fs-store.js';

export const LOCAL_ROOT = '/mnt/local';
export const LOCAL_FD = 0x60000000;
export const localFdPath = path => {
  if (typeof path !== 'string') return false;
  try { path = absolute(path); } catch { return false; }
  return /^\/proc\/self\/fd\/\d+$/.test(path) && Number(path.split('/').at(-1)) >= LOCAL_FD;
};

const INLINE = 256 * 1024;
const bad = (errno, message = errno) => Object.assign(new Error(message), { errno });
const encoded = bytes => {
  let text = '';
  for (let i = 0; i < bytes.length; i += 8192) text += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(text);
};
const decoded = data => Uint8Array.from(atob(data), c => c.charCodeAt(0));

// 53-bit FNV-1a64 matching `abi::fs::FsId::dev()` (`1..=0x1fffffffffffff`).
function fnv53(text) {
  let hash = 0xcbf29ce484222325n;
  for (let i = 0; i < text.length; i++) {
    hash ^= BigInt(text.charCodeAt(i) & 0xff);
    hash = (hash * 0x100000001b3n) & 0xffffffffffffffffn;
  }
  return Number(hash & 0x1fffffffffffffn) || 1;
}

const VIRTUAL_DEV = fnv53('virtual');

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
  const reserved = p => [LOCAL_ROOT, '/mnt/shared', '/opt/private'].some(root => p === root || p.startsWith(root + '/'));
  if (reserved(path)) return true; // Keep attempted escapes inside the rejecting provider.
  try { return reserved(absolute(path)); } catch { return false; }
};

function ownerCredential(identity) {
  return {
    id: identity.uid,
    group: identity.gid ?? identity.uid,
    groups: identity.groups ?? [],
  };
}

let nextFd = LOCAL_FD;
let compilation = Promise.resolve();

export class Workspace {
  constructor(identity, { wasm, storeOptions } = {}) {
    globalThis.__osPinImage ??= pinImage;
    this.identity = Object.freeze({ id: identity.id, uid: identity.uid, gid: identity.gid, groups: identity.groups });
    this.wasm = wasm ?? null;
    this.storeOptions = storeOptions ?? null;
    this.mounts = new Map();
    this.fds = new Map();
    this.page = {};
    this.alive = true;
  }

  #wasmBindings() {
    // `wasm-bindgen --target no-modules` declares a global lexical `let wasm_bindgen`, not a
    // property of `globalThis`, unless mirrored explicitly.
    // eslint-disable-next-line no-undef
    const w = this.wasm ?? globalThis.wasm_bindgen ?? (typeof wasm_bindgen !== 'undefined' ? wasm_bindgen : null);
    if (!w || typeof w.mount_opfs !== 'function') {
      throw bad('ENOSYS', 'client-kernel wasm bindings are not initialized');
    }
    return w;
  }

  check() { if (!this.alive) throw bad('ENODEV', 'workspace is closed'); }
  scope() { this.check(); return {}; }

  list() {
    this.check();
    return [...this.mounts.values()]
      .filter(m => m.active)
      .map(({ path, name, grant, cloud }) => ({
        path,
        name,
        kind: grant.kind,
        writable: !grant.readOnly,
        execute: grant.execute,
        cloud,
      }));
  }

  async mount(args) {
    this.check();
    if (this.list().length >= 16) throw bad('ENOSPC');
    if (typeof args.cloud !== 'boolean') throw bad('EINVAL', 'cloud delegation must be explicit');
    const name = String(args.name ?? args.handle?.name ?? 'files');
    if (!/^[\p{L}\p{N}_. -]{1,80}$/u.test(name) || name === '.' || name === '..') throw bad('EINVAL', 'invalid mount name');
    const path = LOCAL_ROOT + '/' + name;
    if (this.mounts.get(path)?.active) throw bad('EEXIST', 'mount name is already in use');
    if (!args.files && !args.url && !args.handle && args.storage !== true) {
      throw bad('EINVAL', 'a directory handle, helper connection or browser storage is required');
    }

    const owner = ownerCredential(this.identity);
    let provider;
    if (args.url) {
      provider = await NativeMount.connect({ ...args, name, owner }, owner);
    } else if (args.files) {
      const wasm = this.#wasmBindings();
      const grantJson = JSON.stringify({
        kind: 'snapshot',
        name: 'Selected files',
        readOnly: true,
        execute: !!args.execute,
        owner,
      });
      provider = await wasm.mount_snapshot(args.files, grantJson);
    } else if (args.storage === true || args.originPrivate === true) {
      const wasm = this.#wasmBindings();
      const store = await createOpfsStore(args.storage === true ? null : args.handle, {
        execute: !!args.execute,
        writable: !!args.writable,
        ...this.storeOptions,
      });
      const grantJson = JSON.stringify({
        kind: 'browser-storage',
        name: args.storage === true ? 'os-workspace' : (args.handle?.name ?? name),
        readOnly: !args.writable,
        execute: !!args.execute,
        owner,
      });
      provider = await wasm.mount_opfs(store, grantJson);
    } else {
      const wasm = this.#wasmBindings();
      const store = await createDirectoryStore(args.handle, {
        execute: !!args.execute,
        writable: !!args.writable,
        ...this.storeOptions,
      });
      const grantJson = JSON.stringify({
        kind: 'directory',
        name: args.handle?.name ?? name,
        readOnly: !args.writable,
        execute: !!args.execute,
        owner,
      });
      provider = await wasm.mount_directory(store, grantJson);
    }

    const grant = provider.grant;
    if (!this.alive) { provider.unmount(grant); this.check(); }
    if (this.mounts.get(path)?.active) { provider.unmount(grant); throw bad('EEXIST'); }
    if (this.list().length >= 16) { provider.unmount(grant); throw bad('ENOSPC'); }

    const mount = { path, name, grant, provider, cloud: args.cloud, active: true };
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
    const sources = paths.map(p => {
      const found = this.resolve(p);
      if (!found) throw bad('EACCES', 'private packages require a local mount');
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
    this.check();
    const mount = this.mounts.get(path);
    if (!mount?.active) throw bad('ENOENT', 'mount does not exist');
    mount.active = false;
    mount.provider.unmount(mount.grant);
    for (const exported of this.exports?.values() ?? []) if (exported.mount === mount) exported.connection.close();
    for (const [fd, value] of this.fds) if (value.mount === mount) this.fds.delete(fd);
  }

  close() {
    this.alive = false;
    this.fds.clear();
    for (const exported of this.exports?.values() ?? []) exported.connection.close();
    for (const m of this.mounts.values()) {
      if (m.active) m.provider.unmount(m.grant);
      m.active = false;
    }
  }

  resolve(path) {
    this.check();
    const clean = absolute(path);
    const mount = [...this.mounts.values()]
      .filter(m => clean === m.path || clean.startsWith(m.path + '/'))
      .sort((a, b) => b.path.length - a.path.length)[0];
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
    return {
      pin,
      path: found.path,
      local: { digest: pin.digest, size: pin.size, cloud: found.mount.cloud },
      load: () => {
        const next = compilation.then(() => loadLocal(pin));
        compilation = next.catch(() => {});
        return next;
      },
    };
  }

  metadata(path, metadata, mount) {
    if (metadata.vfs) {
      return {
        ...metadata.vfs,
        size: metadata.size ?? metadata.vfs.size ?? 0,
      };
    }
    const directory = metadata.kind === 'directory';
    const executable = directory || (!!mount?.grant.execute && (metadata.executable ?? true));
    const time = Math.floor((metadata.lastModified ?? 0) / 1000);
    const link = metadata.link?.startsWith('/') && mount ? mount.path + metadata.link : metadata.link;
    const dev = mount ? fnv53('private:' + mount.path) : VIRTUAL_DEV;
    const ino = fnv53((mount ? 'private:' : 'virtual:') + path);
    return {
      dev,
      ino,
      mode: (directory ? 0o040000 : metadata.kind === 'symlink' ? 0o120000 : 0o100000)
        | 0o400
        | (metadata.readOnly ? 0 : 0o200)
        | (executable ? 0o100 : 0),
      ...(link === undefined ? {} : { link }),
      nlink: 1,
      uid: this.identity.uid,
      gid: this.identity.gid ?? this.identity.uid,
      user: 'local',
      group: 'local',
      size: metadata.size ?? 0,
      mtime: time,
      mtime_nsec: 0,
      ctime: time,
      ctime_nsec: 0,
      atime: time,
      atime_nsec: 0,
    };
  }

  async stat(path, follow = true) {
    const found = this.resolve(path);
    if (found) return this.metadata(found.path, await found.mount.provider.stat(found.mount.grant, found.relative, { follow }), found.mount);
    path = absolute(path);
    if (this.virtual(path)) return this.metadata(path, { kind: 'directory', readOnly: true });
    throw bad('ENOENT');
  }

  descriptor(fd, scope) {
    this.check();
    const found = this.fds.get(fd);
    if (!found || found.scope !== scope) throw bad('EBADF');
    if (!found.mount.active) throw bad('ENODEV');
    return found;
  }

  async open(path, flags, scope, mode = 0o666, umask = 0o077) {
    const found = this.resolve(path);
    if (!found) { await this.stat(path); throw bad('EISDIR'); }
    const pathOnly = !!(flags & 0o10000000);
    if (!Number.isSafeInteger(flags) || flags < 0 || (!pathOnly && (flags & 3) === 3)) throw bad('EINVAL');
    const write = !pathOnly && (flags & 3) !== 0;
    if (write && found.mount.grant.readOnly) throw bad('EROFS');

    if (found.mount.provider.open) {
      if (this.fds.size >= 1024 || nextFd >= 0x7fffffff) throw bad('EMFILE');
      const handle = await found.mount.provider.open(found.mount.grant, found.relative, flags, mode, umask);
      try {
        const stat = this.metadata(found.path, await found.mount.provider.stat(found.mount.grant, handle), found.mount);
        // WASI `process.js` opens directories without `O_DIRECTORY` and catches `EISDIR` to create
        // its `{ kind: 'dir', path }` descriptor entry for `fd_readdir` and `openat`.
        if (!pathOnly && (stat.mode & 0o170000) === 0o040000 && !(flags & 0o200000)) {
          await found.mount.provider.release(found.mount.grant, handle).catch(() => {});
          throw bad('EISDIR');
        }
        const fd = nextFd++, token = 'local:' + crypto.randomUUID();
        this.fds.set(fd, { ...found, handle, scope, read: !pathOnly && (flags & 3) !== 1, write, append: !pathOnly && !!(flags & 0o2000), pathOnly, token });
        return { fd, token, size: stat.size, stat, chunk_size: INLINE, local: true };
      } catch (error) {
        if (error?.errno !== 'EISDIR') await found.mount.provider.release(found.mount.grant, handle).catch(() => {});
        throw error;
      }
    }

    // Read-only fallback for `PrivateExtension` (`/opt/private/*`) which has no `open` method.
    if (flags & 0o200) throw bad('EOPNOTSUPP', 'atomic exclusive creation is unavailable on this filesystem');
    if (flags & ~(3 | 0o100 | 0o1000 | 0o2000 | 0o200000 | 0o400000 | 0o2000000)) throw bad('EOPNOTSUPP');
    let stat = await this.stat(path);
    if ((stat.mode & 0o170000) === 0o040000) throw bad('EISDIR');
    if (flags & 0o200000) throw bad('ENOTDIR');
    if ((flags & 0o400000) && (await this.stat(path, false)).link !== undefined) throw bad('ELOOP');
    if ((flags & 0o1000) && !write) throw bad('EACCES');
    if (this.fds.size >= 1024 || nextFd >= 0x7fffffff) throw bad('EMFILE');
    const handle = found.relative;
    stat = this.metadata(found.path, await found.mount.provider.stat(found.mount.grant, handle), found.mount);
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

  async fsync(fd, dataOnly, scope) {
    const file = this.descriptor(fd, scope);
    if (file.pathOnly) throw bad('EBADF');
    if (!file.mount.provider.fsync) throw bad('EINVAL');
    return file.mount.provider.fsync(file.mount.grant, file.handle, !!dataOnly);
  }

  async tryLock(fd, family, kind, start = 0, end = null, scope) {
    const file = this.descriptor(fd, scope);
    if (!file.mount.provider.tryLock) throw bad('EOPNOTSUPP');
    return file.mount.provider.tryLock(file.mount.grant, file.handle, family, kind, start, end ?? undefined);
  }

  async lock(fd, family, kind, start = 0, end = null, scope) {
    const file = this.descriptor(fd, scope);
    if (!file.mount.provider.lock) throw bad('EOPNOTSUPP');
    return file.mount.provider.lock(file.mount.grant, file.handle, family, kind, start, end ?? undefined);
  }

  async unlock(fd, family, start = 0, end = null, scope) {
    const file = this.descriptor(fd, scope);
    if (!file.mount.provider.unlock) throw bad('EOPNOTSUPP');
    return file.mount.provider.unlock(file.mount.grant, file.handle, family, start, end ?? undefined);
  }

  async testLock(fd, kind, start = 0, end = null, scope) {
    const file = this.descriptor(fd, scope);
    if (!file.mount.provider.testLock) throw bad('EOPNOTSUPP');
    return file.mount.provider.testLock(file.mount.grant, file.handle, kind, start, end ?? undefined);
  }

  async fstat(fd, scope) {
    const file = this.descriptor(fd, scope);
    return this.metadata(file.path, await file.mount.provider.stat(file.mount.grant, file.handle), file.mount);
  }

  async closeFd(fd, scope) {
    const file = this.descriptor(fd, scope);
    this.fds.delete(fd);
    await file.mount.provider.release?.(file.mount.grant, file.handle);
  }

  closeScope(scope) {
    for (const [fd, found] of this.fds) if (found.scope === scope) void this.closeFd(fd, scope).catch(() => {});
  }

  async entries(path, cookie = 0, count = null) {
    const all = count == null;
    count ??= 4096;
    if (!Number.isSafeInteger(cookie) || cookie < 0 || !Number.isSafeInteger(count) || count < 0 || count > 4096) throw bad('EINVAL');
    const found = this.resolve(path);
    let names = [];
    if (found) {
      let offset = cookie;
      while (names.length < count) {
        const page = await found.mount.provider.list(found.mount.grant, found.relative, { offset, limit: Math.min(256, count - names.length) });
        names.push(...page.entries);
        if (page.next === null) break;
        if (all && names.length === count) throw bad('E2BIG', 'directory requires paginated reads');
        offset = page.next;
      }
    } else {
      path = absolute(path);
      if (!this.virtual(path)) throw bad('ENOENT');
      const prefix = path === '/' ? '/' : path + '/';
      names = [...new Set([...this.mounts.values()].filter(m => m.active && m.path.startsWith(prefix)).map(m => m.path.slice(prefix.length).split('/')[0]))].slice(cookie, cookie + count);
    }
    const entries = [];
    // Bound outstanding metadata requests by the shared provider's credit window.
    for (let offset = 0; offset < names.length; offset += 4) {
      entries.push(...await Promise.all(names.slice(offset, offset + 4).map(async row => {
        const name = typeof row === 'string' ? row : row.name;
        const full = path.replace(/\/$/, '') + '/' + name;
        return { name, stat: row.stat && found ? this.metadata(full, row.stat, found.mount) : await this.stat(full, false) };
      })));
    }
    return entries;
  }

  async calls(calls, scope, cloud, { allowClosedCloud = false, umask } = {}) {
    if (!allowClosedCloud) this.check();
    if (!Array.isArray(calls) || calls.length > 256) throw bad('E2BIG');
    const effectiveUmask = Number.isInteger(umask) ? (umask & 0o777) : 0o077;
    const results = [];
    for (const call of calls) {
      try {
        const name = typeof call === 'string' ? call : Object.keys(call)[0];
        const arg = typeof call === 'string' ? {} : { ...call[name] };
        if (arg.fd && typeof arg.fd === 'object') {
          const reference = results[arg.fd.ref];
          if (reference?.err) throw bad(reference.err.errno);
          if (!Number.isInteger(reference?.ok?.fd)) throw bad('EBADF');
          arg.fd = reference.ok.fd;
        }
        const target = arg.path ?? arg.from;
        if (!this.alive) {
          // Shutdown revokes private mounts immediately. Existing processes may
          // still run ordinary cleanup through their original server credentials.
          const privateAccess = arg.fd >= LOCAL_FD || [arg.path, arg.from, arg.to].some(p => localPath(p) || localFdPath(p));
          if (!allowClosedCloud || privateAccess) throw bad('ENODEV');
          results.push(...await cloud([typeof call === 'string' ? call : { [name]: arg }]));
          continue;
        }
        if (localFdPath(target)) {
          const fd = Number(absolute(target).split('/').at(-1));
          const file = this.descriptor(fd, scope);
          if (name === 'readlink') results.push({ ok: file.path });
          else if (name === 'stat') results.push({ ok: await this.fstat(fd, scope) });
          else throw bad('EOPNOTSUPP');
          continue;
        }
        const clean = typeof target === 'string' ? absolute(target) : null;
        const owned = (clean && (localPath(clean) || this.resolve(target))) || (arg.to && localPath(absolute(arg.to)));
        const localFd = Number.isInteger(arg.fd) && arg.fd >= LOCAL_FD;
        if (!owned && !localFd && !(clean && this.virtual(clean))) {
          results.push(...await cloud([typeof call === 'string' ? call : { [name]: arg }]));
          continue;
        }
        if (clean && this.virtual(clean) && !localPath(clean) && !this.resolve(target)) {
          const [answer] = await cloud([{ [name]: name === 'getdents' ? { ...arg, cookie: 0, count: null } : arg }]);
          if (name === 'getdents') {
            const extra = await this.entries(clean);
            const existing = answer.ok ?? [];
            const merged = [...existing, ...extra.filter(e => !existing.some(x => x.name === e.name))];
            const offset = arg.cookie ?? 0;
            results.push({ ok: merged.slice(offset, arg.count == null ? undefined : offset + arg.count) });
            continue;
          }
          if (answer.ok !== undefined) {
            results.push(answer);
            continue;
          }
        }

        let value;
        switch (name) {
          case 'stat':
          case 'lstat':
            value = await this.stat(target, name === 'stat');
            break;
          case 'fstat':
            value = await this.fstat(arg.fd, scope);
            break;
          case 'access': {
            const found = this.resolve(target);
            if (found?.mount.provider.access) {
              value = await found.mount.provider.access(found.mount.grant, found.relative, arg.mode);
              break;
            }
            const stat = await this.stat(target);
            if ((arg.mode & 7) & ~((stat.mode >> 6) & 7)) throw bad('EACCES');
            value = null;
            break;
          }
          case 'getdents':
            value = await this.entries(target, arg.cookie, arg.count);
            break;
          case 'open':
            if (arg.version != null || arg.sha256 != null) {
              throw bad('EOPNOTSUPP', 'versioned atomic uploads are unavailable on this filesystem');
            }
            value = await this.open(target, arg.flags ?? 0, scope, arg.mode ?? 0o666, effectiveUmask);
            break;
          case 'close':
            await this.closeFd(arg.fd, scope);
            value = { closed: true };
            break;
          case 'pread': {
            if (arg.fd !== undefined) {
              value = await this.read(arg.fd, arg.offset ?? 0, arg.count ?? INLINE, scope);
            } else {
              const fd = await this.open(target, 0, scope);
              try {
                value = await this.read(fd.fd, arg.offset ?? 0, arg.count ?? INLINE, scope);
              } finally {
                await this.closeFd(fd.fd, scope).catch(() => {});
              }
            }
            break;
          }
          case 'pwrite':
            value = await this.write(arg.fd, decoded(arg.data), arg.offset ?? ((arg.index ?? 0) * INLINE), scope);
            break;
          case 'ftruncate': {
            const file = this.descriptor(arg.fd, scope);
            if (!file.write) throw bad('EBADF');
            value = file.mount.provider.ftruncate
              ? await file.mount.provider.ftruncate(file.mount.grant, file.handle, arg.size)
              : await file.mount.provider.write(file.mount.grant, file.handle, new Uint8Array(), { truncate: arg.size });
            break;
          }
          case 'fsync':
            value = await this.fsync(arg.fd, !!arg.data_only, scope);
            break;
          case 'try_lock':
            value = await this.tryLock(arg.fd, arg.family, arg.kind, arg.start ?? 0, arg.end ?? null, scope);
            break;
          case 'lock':
            value = await this.lock(arg.fd, arg.family, arg.kind, arg.start ?? 0, arg.end ?? null, scope);
            break;
          case 'unlock':
            value = await this.unlock(arg.fd, arg.family, arg.start ?? 0, arg.end ?? null, scope);
            break;
          case 'test_lock':
            value = await this.testLock(arg.fd, arg.kind, arg.start ?? 0, arg.end ?? null, scope);
            break;
          case 'mkdir':
          case 'rmdir':
          case 'unlink': {
            const file = this.resolve(target);
            if (!file) throw bad('EROFS');
            if (file.mount.grant.readOnly) throw bad('EROFS');
            value = name === 'mkdir'
              ? await file.mount.provider.mkdir(file.mount.grant, file.relative, arg.mode ?? 0o777, effectiveUmask)
              : await file.mount.provider.remove(file.mount.grant, file.relative, name === 'rmdir');
            break;
          }
          case 'rename': {
            const a = this.resolve(arg.from), b = this.resolve(arg.to);
            if (!a || !b || a.mount !== b.mount) throw bad('EXDEV');
            if (a.mount.grant.readOnly) throw bad('EROFS');
            if (arg.noreplace && a.mount.provider instanceof NativeMount) {
              throw bad('EOPNOTSUPP', 'atomic no-replace rename is unavailable on this filesystem');
            }
            value = await a.mount.provider.rename(a.mount.grant, a.relative, b.relative, !!arg.noreplace);
            break;
          }
          case 'link': {
            const a = this.resolve(arg.from), b = this.resolve(arg.to);
            if (!a || !b || a.mount !== b.mount) throw bad('EXDEV');
            if (a.mount.grant.readOnly) throw bad('EROFS');
            if (!a.mount.provider.link) throw bad('EOPNOTSUPP');
            value = await a.mount.provider.link(a.mount.grant, a.relative, b.relative, !!arg.follow);
            break;
          }
          case 'symlink': {
            const file = this.resolve(arg.path);
            if (!file) throw bad('EROFS');
            if (file.mount.grant.readOnly) throw bad('EROFS');
            if (!file.mount.provider.symlink) throw bad('EOPNOTSUPP');
            value = await file.mount.provider.symlink(file.mount.grant, arg.target, file.relative);
            break;
          }
          case 'chmod':
          case 'chown':
          case 'utimens':
          case 'statfs':
          case 'getxattr':
          case 'setxattr':
          case 'listxattr':
          case 'removexattr':
          case 'fchmod': {
            const file = name === 'fchmod' ? this.descriptor(arg.fd, scope) : this.resolve(target);
            if (name === 'fchmod' && file.pathOnly) throw bad('EBADF');
            if (!file?.mount.provider.policy) throw bad('EOPNOTSUPP');
            value = await file.mount.provider.policy(
              file.mount.grant,
              name === 'fchmod' ? file.handle : file.relative,
              name === 'fchmod' ? 'chmod' : name,
              arg,
            );
            break;
          }
          case 'readlink': {
            const found = this.resolve(target);
            if (found?.mount.provider.readlink) {
              value = await found.mount.provider.readlink(found.mount.grant, found.relative);
              break;
            }
            const stat = await this.stat(target, false);
            if (stat.link === undefined) throw bad('EINVAL');
            value = stat.link;
            break;
          }
          default:
            throw bad('EOPNOTSUPP', 'operation is unsupported by this local filesystem');
        }
        // Void provider methods still need an explicit ABI success value.
        // JSON drops undefined properties, leaving Rust an invalid Return ({}).
        results.push({ ok: value ?? null });
      } catch (error) {
        results.push({ err: { errno: error.errno ?? 'EIO', detail: error.message } });
      }
    }
    return results;
  }
}

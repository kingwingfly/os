// OS metadata over a host provider, without copying file content. All permission
// decisions and ACL mutation run in the shared Rust VFS, not a second JS ACL engine.
import { localImage, pinImage } from './local-mounts.js';
const bad = (errno, message = errno) => Object.assign(new Error(message), { errno });
const parent = path => path.split('/').slice(0, -1).join('/');
const pathOf = path => {
  if (typeof path !== 'string' || path.length > 4096 || path.split('/').length > 256 || path.startsWith('/') || /[\0\\]/.test(path) || path.split('/').includes('..')) throw bad('EACCES');
  return path.split('/').filter(p => p && p !== '.').join('/');
};
export const credential = value => ({ id: value.uid, group: value.gid ?? value.uid, groups: value.groups ?? [] });
export class PermissionMount {
  constructor(provider, grant, identity, evaluate = async input => globalThis.kernelRequest('vfs_policy', { input })) {
    this.provider = provider; this.grant = grant; this.identity = credential(identity); this.owner = this.identity;
    this.state = { nodes: new Map(), pending: new Map(), evaluate, revision: 0 }; this.boundary = ''; this.remote = false;
    this.handles = new WeakMap(); if (!provider.open) this.open = undefined;
  }
  forIdentity(identity, boundary) {
    const view = Object.create(this); view.identity = identity; view.boundary = pathOf(boundary); view.remote = true; view.handles = new WeakMap(); return view;
  }
  async evaluate(input) {
    const result = await this.state.evaluate(input);
    if (result.err) throw bad(result.err.errno, result.err.detail); return result.ok;
  }
  check(grant) { if (grant !== this.grant) throw bad('EACCES'); }
  path(value) { return typeof value === 'object' ? this.handles.get(value)?.path ?? (() => { throw bad('EBADF'); })() : pathOf(value); }
  held(value) { return typeof value === 'object' ? this.handles.get(value)?.held ?? (() => { throw bad('EBADF'); })() : pathOf(value); }
  async ensure(path) {
    if (this.state.nodes.has(path)) return this.state.nodes.get(path);
    if (this.state.pending.has(path)) return this.state.pending.get(path);
    if (this.state.nodes.size + this.state.pending.size >= 65536) throw bad('ENOSPC', 'mount metadata limit reached');
    const promise = (async () => {
      const meta = await this.provider.stat(this.grant, path, { follow: false });
      const mode = 0o400 | (this.grant.readOnly ? 0 : 0o200) | (meta.kind === 'directory' || this.grant.execute && (meta.executable ?? true) ? 0o100 : 0);
      const node = await this.evaluate({ identity: this.owner, create: { directory: meta.kind === 'directory', mode } });
      node.file = meta.kind === 'file' ? 'host' : null; node.link = meta.link ?? null;
      this.state.nodes.set(path, node); return node;
    })();
    this.state.pending.set(path, promise);
    try { return await promise; } finally { this.state.pending.delete(path); }
  }
  async tree(path, follow = true, depth = 0) {
    if (depth > 40) throw bad('ELOOP');
    const retained = typeof path === 'object' ? this.handles.get(path) : null;
    if (!this.remote && retained && this.state.nodes.get(retained.path) !== retained.node) {
      return { path: '/held', nodes: { '/': await this.ensure(''), '/held': retained.node }, keys: new Map() };
    }
    if (this.remote && typeof path === 'object') {
      const held = this.held(path), current = await this.provider.stat(this.grant, this.path(path), { follow: false });
      const opened = await this.provider.stat(this.grant, held);
      if (current.identity !== undefined && current.identity !== opened.identity) throw bad('ESTALE', 'file moved or was replaced in the export');
    }
    path = this.path(path);
    if (this.boundary && path !== this.boundary && !path.startsWith(this.boundary + '/')) throw bad('EACCES');
    const relative = path.slice(this.boundary.length).replace(/^\//, '');
    const parts = relative ? relative.split('/') : [], nodes = {}, keys = new Map(); let key = this.boundary;
    for (let i = 0; i <= parts.length; i++) {
      const name = '/' + parts.slice(0, i).join('/'), node = await this.ensure(key);
      // Host symlinks do not have a portable stable inode identity in browser
      // APIs. Exported walks fail closed instead of checking ACLs on an alias.
      const live = this.remote ? await this.provider.stat(this.grant, key, { follow: false }) : null;
      if (this.remote && this.grant.kind === 'native-directory' && typeof live.identity !== 'string') throw bad('EPROTONOSUPPORT', 'Update os-local-helper before sharing this folder.');
      if ((node.link || live?.kind === 'symlink') && this.remote && (follow || i < parts.length)) throw bad('ELOOP', 'symlink traversal is unavailable on shared mounts');
      if (node.link && (follow || i < parts.length)) {
        const target = node.link.startsWith('/') ? node.link.slice(1) : [parent(key), node.link].filter(Boolean).join('/');
        const resolved = [];
        for (const part of [target, ...parts.slice(i)].join('/').split('/')) {
          if (part === '..') { if (!resolved.length) throw bad('EACCES'); resolved.pop(); }
          else if (part && part !== '.') resolved.push(part);
        }
        return this.tree(resolved.join('/'), follow, depth + 1);
      }
      nodes[name] = node; keys.set(name, key);
      if (i < parts.length) key = [key, parts[i]].filter(Boolean).join('/');
    }
    return { nodes, keys, path: '/' + parts.join('/') };
  }
  async policy(grant, path, name, args = {}) {
    this.check(grant);
    const tree = await this.tree(path, !args.nofollow && name !== 'lstat');
    if (name === 'access') {
      if (args.mode & 2 && grant.readOnly) throw bad('EROFS');
      if (args.mode & 1 && !grant.execute && !tree.nodes[tree.path].directory) throw bad('EACCES');
    }
    const result = await this.evaluate({ identity: this.identity, nodes: tree.nodes, call: { [name]: { ...args, path: tree.path } } });
    if (['chmod', 'chown', 'setxattr', 'removexattr'].includes(name)) {
      // A receiver may read metadata, but only the publishing account controls
      // export permissions, including files created by an authenticated peer.
      if (this.remote) throw bad('EPERM');
      Object.assign(tree.nodes[tree.path], result.nodes[tree.path]);
      this.state.revision++;
    }
    return result.value;
  }
  async access(grant, path, mode) { return this.policy(grant, path, 'access', { mode }); }
  async stat(grant, path = '', options = {}) {
    const vfs = await this.policy(grant, path, options.follow === false ? 'lstat' : 'stat');
    const meta = await this.provider.stat(grant, this.held(path), options);
    if (grant.kind === 'native-directory') this.identitySupported = typeof meta.identity === 'string';
    const { identity: _hostIdentity, ...publicMeta } = meta;
    const time = Math.floor((meta.lastModified ?? 0) / 1000), nanos = Math.floor((meta.lastModified ?? 0) % 1000) * 1000000;
    return { ...publicMeta, vfs: { ...vfs, mode: (vfs.mode & 0o7777) | (meta.kind === 'directory' ? 0o40000 : meta.kind === 'symlink' ? 0o120000 : 0o100000), size: meta.size ?? 0, mtime: time, mtime_nsec: nanos, atime: time, atime_nsec: nanos, ctime: time, ctime_nsec: nanos } };
  }
  async list(grant, path, options) { await this.access(grant, path, 5); return this.provider.list(grant, this.held(path), options); }
  async hold(grant, path, root = this.boundary) {
    await this.access(grant, path, 0);
    const held = await this.provider.hold(grant, this.path(path), root), handle = Object.freeze({});
    this.handles.set(handle, { path: this.path(path), held, node: await this.ensure(this.path(path)) }); return handle;
  }
  async release(grant, handle) { const held = this.held(handle); this.handles.delete(handle); await this.provider.release?.(grant, held); }
  async read(grant, path, offset, count) { await this.access(grant, path, 4); const bytes = await this.provider.read(grant, this.held(path), offset, count); await this.access(grant, path, 4); return bytes; }
  async newNode(path, directory, mode) {
    const p = await this.ensure(parent(path));
    // The publishing account owns policy even when another account creates data.
    const node = await this.evaluate({ identity: this.owner, create: { parent: p, directory, mode: p.default_acl ? mode : mode & 0o700 } });
    if (!directory) node.file = 'host'; this.state.nodes.set(path, node);
  }
  async write(grant, path, bytes, options = {}) {
    this.check(grant); if (grant.readOnly) throw bad('EROFS'); let create = false;
    try { await this.access(grant, path, 2); } catch (error) {
      if (error.errno !== 'ENOENT' || !options.create || typeof path !== 'string') throw error;
      await this.access(grant, parent(path), 3); create = true;
    }
    const result = await this.provider.write(grant, this.held(path), bytes, options);
    if (create) await this.newNode(path, false, 0o666); return result;
  }
  async open(grant, path, flags) {
    // Preserve native provider's atomic open, append, O_EXCL and directory fds.
    let create = false;
    try { await this.access(grant, path, (flags & 3) === 0 ? 4 : (flags & 3) === 1 ? 2 : 6); } catch (error) {
      if (error.errno !== 'ENOENT' || !(flags & 0o100)) throw error;
      await this.access(grant, parent(path), 3); create = true;
    }
    if ((flags & 3) && grant.readOnly) throw bad('EROFS');
    const held = await this.provider.open(grant, path, flags), handle = Object.freeze({});
    if (create) await this.newNode(path, false, 0o666);
    this.handles.set(handle, { path, held, node: await this.ensure(path) }); return handle;
  }
  async mkdir(grant, path, mode = 0o777) {
    this.check(grant); if (grant.readOnly) throw bad('EROFS'); await this.access(grant, parent(path), 3);
    const result = await this.provider.mkdir(grant, path); await this.newNode(path, true, mode); return result;
  }
  forget(path) { for (const key of this.state.nodes.keys()) if (key === path || key.startsWith(path + '/')) this.state.nodes.delete(key); this.state.revision++; }
  async remove(grant, path, directory) {
    this.check(grant); if (grant.readOnly) throw bad('EROFS'); if (!path || path === this.boundary) throw bad('EBUSY');
    await this.policy(grant, path, directory ? 'rmdir' : 'unlink');
    const result = await this.provider.remove(grant, path, directory); this.forget(path); return result;
  }
  async rename(grant, path, to) {
    this.check(grant); if (grant.readOnly) throw bad('EROFS'); if (!path || !to || path === this.boundary || to === this.boundary) throw bad('EBUSY');
    await this.access(grant, path, 0); await this.access(grant, parent(path), 3); await this.access(grant, parent(to), 3);
    const source = await this.tree(path), targetParent = await this.tree(parent(to));
    let target; try { target = await this.tree(to); } catch (error) { if (error.errno !== 'ENOENT') throw error; }
    const destination = '/' + to.slice(this.boundary.length).replace(/^\//, '');
    await this.evaluate({ identity: this.identity, nodes: { ...source.nodes, ...targetParent.nodes, ...target?.nodes }, call: { rename: { from: source.path, to: destination, noreplace: false } } });
    const result = await this.provider.rename(grant, path, to), moved = [...this.state.nodes].filter(([key]) => key === path || key.startsWith(path + '/'));
    this.forget(to); this.forget(path); for (const [key, node] of moved) this.state.nodes.set(to + key.slice(path.length), node); return result;
  }
  async pin(grant, path) {
    if (!grant.execute) throw bad('EACCES'); await this.access(grant, path, 5);
    const revision = this.state.revision, pin = await this.provider.pin(grant, this.held(path));
    // Caller checks ACL again for every image read; this revision also invalidates
    // already prepared executable images after any namespace/policy change.
    const image = await localImage(pin);
    return pinImage(image.bytes, async () => { if (revision !== this.state.revision) throw bad('ESTALE'); await this.access(grant, path, 5); await image.check(); });
  }
  unmount(grant) { this.check(grant); return this.provider.unmount(grant); }
}

import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { accessSync, constants as fsConstants, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { prepareUserMount, CLIENT_PAGE_FD_BASE } from '../web/kernel/workspace.js';
import { currentWorkspace, mountRequest, endWorkspace } from '../web/kernel/workspaces.js';
import { localImage } from '../web/kernel/local-mounts.js';
import { NativeMount } from '../web/kernel/native-mount.js';
import { exportMount, attachMount } from '../web/kernel/mount-sharing.js';

const LOCAL_FD = CLIENT_PAGE_FD_BASE;
const OS_FD_ROOT = 0x7ffffffd;

// --- Compile & load real `os-client-kernel` Wasm module for Node.js ---
const repoRoot = fileURLToPath(new URL('..', import.meta.url));
function resolveCargoTargetDir() {
  if (process.env.CARGO_TARGET_DIR) return process.env.CARGO_TARGET_DIR;
  try {
    const dir = JSON.parse(
      execFileSync('cargo', ['metadata', '--no-deps', '--format-version=1'], {
        cwd: repoRoot,
        encoding: 'utf8',
      }),
    ).target_directory;
    mkdirSync(dir, { recursive: true });
    accessSync(dir, fsConstants.W_OK);
    return dir;
  } catch {
    return join(tmpdir(), 'os-client-kernel-target');
  }
}

const targetDir = resolveCargoTargetDir();
const wasmOutDir = mkdtempSync(join(tmpdir(), 'os-wasm-node-'));
process.on('exit', () => {
  try { rmSync(wasmOutDir, { recursive: true, force: true }); } catch {}
});

execFileSync(
  'cargo',
  ['build', '--quiet', '--locked', '-p', 'os-client-kernel', '--target', 'wasm32-unknown-unknown', '--target-dir', targetDir],
  {
    cwd: repoRoot,
    stdio: 'inherit',
    env: { ...process.env, CARGO_PROFILE_DEV_DEBUG: process.env.CARGO_PROFILE_DEV_DEBUG ?? '0' },
  },
);
execFileSync(
  'wasm-bindgen',
  [
    '--target', 'nodejs',
    '--no-typescript',
    '--out-dir', wasmOutDir,
    '--out-name', 'client_kernel',
    join(targetDir, 'wasm32-unknown-unknown/debug/os_client_kernel.wasm'),
  ],
  { cwd: repoRoot, stdio: 'inherit' },
);
const require = createRequire(import.meta.url);
globalThis.wasm_bindgen = require(join(wasmOutDir, 'client_kernel.js'));

// --- Spec-faithful in-memory IndexedDB + Web Locks + OPFS environment for Node tests ---
function createMemoryIdb() {
  const databases = new Map();

  function cloneVal(val) {
    if (val === undefined || val === null || typeof val !== 'object') return val;
    return structuredClone(val);
  }

  function makeRequest(fn) {
    const req = { result: undefined, error: null, onsuccess: null, onerror: null, onupgradeneeded: null };
    queueMicrotask(() => {
      try {
        req.result = fn(req);
        req.onsuccess?.({ target: req });
      } catch (err) {
        req.error = err;
        req.onerror?.({ target: req });
      }
    });
    return req;
  }

  return {
    databases,
    open(name, version = 1) {
      const req = { result: undefined, error: null, onsuccess: null, onerror: null, onupgradeneeded: null, onblocked: null };
      queueMicrotask(() => {
        try {
          let entry = databases.get(name);
          const isUpgrade = !entry || entry.version < version;
          if (!entry) {
            entry = { version, stores: new Map() };
            databases.set(name, entry);
          } else if (isUpgrade) {
            entry.version = version;
          }

          const db = {
            name,
            version: entry.version,
            objectStoreNames: {
              contains: storeName => entry.stores.has(storeName),
            },
            createObjectStore(storeName, opts = {}) {
              const store = {
                keyPath: opts.keyPath ?? null,
                records: new Map(),
                indexes: new Map(),
              };
              entry.stores.set(storeName, store);
              return {
                createIndex(indexName, keyPath) {
                  store.indexes.set(indexName, { keyPath });
                },
              };
            },
            transaction(storeNames, _mode = 'readonly') {
              const names = Array.isArray(storeNames) ? storeNames : [storeNames];
              for (const n of names) {
                if (!entry.stores.has(n)) throw new DOMException(`Missing store ${n}`, 'NotFoundError');
              }
              const tx = { oncomplete: null, onerror: null, onabort: null, error: null };
              let pending = 0;
              let finished = false;
              const maybeComplete = () => {
                if (!finished && pending === 0) {
                  finished = true;
                  queueMicrotask(() => tx.oncomplete?.({ target: tx }));
                }
              };
              queueMicrotask(maybeComplete);

              const wrapOp = op => {
                pending++;
                const r = { result: undefined, error: null, onsuccess: null, onerror: null, onupgradeneeded: null };
                queueMicrotask(() => {
                  try {
                    r.result = op(r);
                    r.onsuccess?.({ target: r });
                    pending--;
                    maybeComplete();
                  } catch (err) {
                    r.error = err;
                    tx.error = err;
                    finished = true;
                    r.onerror?.({ target: r });
                    queueMicrotask(() => tx.onerror?.({ target: tx }));
                  }
                });
                return r;
              };

              return Object.assign(tx, {
                objectStore(storeName) {
                  const store = entry.stores.get(storeName);
                  return {
                    get: key => wrapOp(() => cloneVal(store.records.get(key))),
                    getAll: () => wrapOp(() => [...store.records.values()].map(cloneVal)),
                    put: (value, explicitKey) => {
                      const cloned = cloneVal(value);
                      return wrapOp(() => {
                        const k = store.keyPath ? cloned[store.keyPath] : explicitKey;
                        store.records.set(k, cloned);
                        return k;
                      });
                    },
                    delete: key => wrapOp(() => {
                      store.records.delete(key);
                      return undefined;
                    }),
                    clear: () => wrapOp(() => {
                      store.records.clear();
                      return undefined;
                    }),
                    index(indexName) {
                      const idx = store.indexes.get(indexName);
                      return {
                        get: searchKey => wrapOp(() => {
                          for (const rec of store.records.values()) {
                            if (rec?.[idx.keyPath] === searchKey) return cloneVal(rec);
                          }
                          return undefined;
                        }),
                      };
                    },
                  };
                },
              });
            },
            close() {},
          };
          req.result = db;
          if (isUpgrade) req.onupgradeneeded?.({ target: req });
          req.onsuccess?.({ target: req });
        } catch (err) {
          req.error = err;
          req.onerror?.({ target: req });
        }
      });
      return req;
    },
  };
}

function createMemoryWebLocks() {
  // name -> { mode: 'exclusive'|'shared', holders: Set<symbol>, queue: Array }
  const state = new Map();

  function pump(name) {
    const slot = state.get(name);
    if (!slot) return;
    while (slot.queue.length > 0) {
      const next = slot.queue[0];
      if (next.aborted) {
        slot.queue.shift();
        continue;
      }
      const canGrant = slot.holders.size === 0 || (slot.mode === 'shared' && next.mode === 'shared');
      if (!canGrant) break;
      slot.queue.shift();
      slot.mode = next.mode;
      const token = Symbol(name);
      slot.holders.add(token);
      next.grant(token);
    }
    if (slot.holders.size === 0 && slot.queue.length === 0) {
      state.delete(name);
    }
  }

  function releaseHolder(name, token) {
    const slot = state.get(name);
    if (!slot) return;
    slot.holders.delete(token);
    pump(name);
  }

  return {
    state,
    forceReleaseByPrefix(prefix) {
      for (const [name, slot] of [...state.entries()]) {
        if (name.startsWith(prefix)) {
          slot.holders.clear();
          pump(name);
        }
      }
    },
    async query() {
      const held = [];
      const pending = [];
      for (const [name, slot] of state.entries()) {
        for (let i = 0; i < slot.holders.size; i++) held.push({ name, mode: slot.mode });
        for (const q of slot.queue) if (!q.aborted) pending.push({ name, mode: q.mode });
      }
      return { held, pending };
    },
    request(name, optsOrCb, maybeCb) {
      const opts = typeof optsOrCb === 'function' ? {} : (optsOrCb ?? {});
      const cb = typeof optsOrCb === 'function' ? optsOrCb : maybeCb;
      const mode = opts.mode ?? 'exclusive';
      const ifAvailable = !!opts.ifAvailable;
      const signal = opts.signal ?? null;

      if (signal?.aborted) {
        return Promise.reject(new DOMException('The request was aborted.', 'AbortError'));
      }

      let slot = state.get(name);
      if (!slot) {
        slot = { mode, holders: new Set(), queue: [] };
        state.set(name, slot);
      }

      if (ifAvailable) {
        const canGrant = slot.holders.size === 0 || (slot.mode === 'shared' && mode === 'shared' && slot.queue.length === 0);
        if (!canGrant) {
          return Promise.resolve().then(() => cb(null));
        }
        slot.mode = mode;
        const token = Symbol(name);
        slot.holders.add(token);
        return Promise.resolve()
          .then(() => cb({ name, mode }))
          .finally(() => releaseHolder(name, token));
      }

      return new Promise((resolve, reject) => {
        const item = {
          mode,
          aborted: false,
          grant(token) {
            Promise.resolve()
              .then(() => cb({ name, mode }))
              .then(resolve, reject)
              .finally(() => releaseHolder(name, token));
          },
        };
        if (signal) {
          signal.addEventListener(
            'abort',
            () => {
              if (item.aborted) return;
              item.aborted = true;
              reject(new DOMException('The request was aborted.', 'AbortError'));
              pump(name);
            },
            { once: true },
          );
        }
        slot.queue.push(item);
        pump(name);
      });
    },
  };
}

function createFakeFsTree(name = 'root', { originPrivate = false, permission = 'granted' } = {}) {
  const treeState = { permission, quotaExceeded: false, failFlush: false };

  function makeDirNode(dirName) {
    return { kind: 'directory', name: dirName, children: new Map() };
  }
  function makeFileNode(fileName, bytes = new Uint8Array(0), mtime = 1700000000123) {
    return { kind: 'file', name: fileName, bytes: new Uint8Array(bytes), lastModified: mtime };
  }

  const rootNode = makeDirNode(name);

  function findPath(cur, target, prefix = []) {
    if (cur === target) return prefix;
    if (cur.kind !== 'directory') return null;
    for (const [childName, childNode] of cur.children) {
      const found = findPath(childNode, target, [...prefix, childName]);
      if (found) return found;
    }
    return null;
  }

  function wrapFile(node) {
    const handle = {
      kind: 'file',
      name: node.name,
      __node: node,
      async isSameEntry(other) {
        return other?.__node === node;
      },
      async getFile() {
        return new File([node.bytes], node.name, { lastModified: node.lastModified });
      },
      async flush() {
        if (treeState.failFlush) throw new DOMException('Simulated disk flush error', 'NotReadableError');
      },
      async move(destDirHandle, newName) {
        const parentRel = findPath(rootNode, node);
        if (!parentRel) throw new DOMException('Moved source missing', 'NotFoundError');
        let oldParent = rootNode;
        for (const seg of parentRel.slice(0, -1)) oldParent = oldParent.children.get(seg);
        const oldName = parentRel[parentRel.length - 1];
        const destNode = destDirHandle.__node;
        oldParent.children.delete(oldName);
        node.name = newName;
        destNode.children.set(newName, node);
      },
      async createWritable({ keepExistingData = false } = {}) {
        let buf = keepExistingData ? node.bytes.slice() : new Uint8Array(0);
        return {
          async write(chunk) {
            if (treeState.quotaExceeded) {
              throw new DOMException('Storage quota exceeded', 'QuotaExceededError');
            }
            const pos = chunk?.type === 'write' ? (chunk.position ?? 0) : 0;
            const raw = chunk?.type === 'write' ? chunk.data : chunk;
            const bytes = raw instanceof Uint8Array ? raw : new TextEncoder().encode(String(raw));
            const nextLen = Math.max(buf.length, pos + bytes.length);
            if (nextLen > buf.length) {
              const grown = new Uint8Array(nextLen);
              grown.set(buf);
              buf = grown;
            }
            buf.set(bytes, pos);
          },
          async truncate(len) {
            if (len < buf.length) {
              buf = buf.slice(0, len);
            } else if (len > buf.length) {
              const grown = new Uint8Array(len);
              grown.set(buf);
              buf = grown;
            }
          },
          async close() {
            if (treeState.quotaExceeded) {
              throw new DOMException('Storage quota exceeded', 'QuotaExceededError');
            }
            node.bytes = buf;
            node.lastModified += 10;
          },
          async abort() {},
        };
      },
    };
    return handle;
  }

  function wrapDir(node) {
    const handle = {
      kind: 'directory',
      name: node.name,
      __node: node,
      ...(originPrivate
        ? {}
        : {
            async queryPermission() {
              return treeState.permission;
            },
          }),
      async isSameEntry(other) {
        return other?.__node === node;
      },
      async resolve(child) {
        if (!child?.__node) return null;
        return findPath(node, child.__node);
      },
      async *entries() {
        for (const [childName, childNode] of [...node.children.entries()]) {
          yield [childName, childNode.kind === 'directory' ? wrapDir(childNode) : wrapFile(childNode)];
        }
      },
      async getDirectoryHandle(childName, { create = false } = {}) {
        const existing = node.children.get(childName);
        if (existing) {
          if (existing.kind !== 'directory') throw new DOMException('Not a directory', 'TypeMismatchError');
          return wrapDir(existing);
        }
        if (!create) throw new DOMException('Directory not found', 'NotFoundError');
        const created = makeDirNode(childName);
        node.children.set(childName, created);
        return wrapDir(created);
      },
      async getFileHandle(childName, { create = false } = {}) {
        const existing = node.children.get(childName);
        if (existing) {
          if (existing.kind !== 'file') throw new DOMException('Is a directory', 'TypeMismatchError');
          return wrapFile(existing);
        }
        if (!create) throw new DOMException('File not found', 'NotFoundError');
        const created = makeFileNode(childName, new Uint8Array(0), Date.now());
        node.children.set(childName, created);
        return wrapFile(created);
      },
      async removeEntry(childName, { recursive = false } = {}) {
        const existing = node.children.get(childName);
        if (!existing) throw new DOMException('Entry not found', 'NotFoundError');
        if (existing.kind === 'directory' && existing.children.size > 0 && !recursive) {
          throw new DOMException('Directory not empty', 'InvalidModificationError');
        }
        node.children.delete(childName);
      },
    };
    return handle;
  }

  return {
    state: treeState,
    rootNode,
    handle: () => wrapDir(rootNode),
    hostWrite(relPath, content, mtime = Date.now() + 5000) {
      const parts = relPath.split('/').filter(Boolean);
      let dir = rootNode;
      for (const seg of parts.slice(0, -1)) {
        let next = dir.children.get(seg);
        if (!next) {
          next = makeDirNode(seg);
          dir.children.set(seg, next);
        }
        dir = next;
      }
      const bytes = typeof content === 'string' ? new TextEncoder().encode(content) : new Uint8Array(content);
      const leaf = parts[parts.length - 1];
      dir.children.set(leaf, makeFileNode(leaf, bytes, mtime));
    },
    hostNames(relDir = '') {
      const parts = relDir.split('/').filter(Boolean);
      let dir = rootNode;
      for (const seg of parts) {
        dir = dir?.children.get(seg);
      }
      return dir ? [...dir.children.keys()].sort() : [];
    },
  };
}

function installBrowserEnv() {
  const idb = createMemoryIdb();
  const locks = createMemoryWebLocks();
  const opfs = createFakeFsTree('', { originPrivate: true });
  globalThis.indexedDB = idb;
  Object.defineProperty(globalThis, 'navigator', {
    configurable: true,
    writable: true,
    value: {
      locks,
      storage: {
        async getDirectory() {
          return opfs.handle();
        },
      },
    },
  });
  return { idb, locks, opfs };
}

installBrowserEnv();

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const file = (name, text) => new File([text], name, { lastModified: 1700000000123 });
const cloud = async calls => calls.map(() => ({ err: { errno: 'ENOENT' } }));
const acl = (users, mask = 5, group = 0, other = 0, groups = {}) => ({ user: 7, group, other, mask, users, groups });
const aclAttr = (entries, name = 'system.posix_acl_access') => ({
  name,
  value: btoa(JSON.stringify(entries)),
  flags: 0,
  nofollow: false,
});

function encodeB64Bytes(u8) {
  let text = '';
  for (let i = 0; i < u8.length; i += 0x8000) {
    text += String.fromCharCode(...u8.subarray(i, i + 0x8000));
  }
  return btoa(text);
}

// Test-only harness wrapping `os-client-kernel`'s `Kernel` (`os_vfs::Vfs`) per login session/tab.
class TestSession {
  constructor({ id, uid, gid = uid, groups = [gid] }) {
    this.id = id;
    this.identity = Object.freeze({
      id,
      uid,
      gid,
      groups: Object.freeze([...groups]),
    });
    this.kernel = new globalThis.wasm_bindgen.Kernel(`inst-${crypto.randomUUID()}`, `k-${crypto.randomUUID()}`);
    this.alive = true;
    this.exports = new Map();
    this.sharedConnections = new Map();
    this.cleanups = new Map();
    this.mounts = new Map();
    this.fds = new Set();
    this._nextPid = 200;
    this.page = 200;
    this._spawnedPids = new Set([200]);
    this._ready = (async () => {
      await this.kernel.session_begin(id, uid, gid, new Uint32Array(groups));
      await this.kernel.proc_spawn_init(JSON.stringify({
        pid: 200,
        ppid: 1,
        sessionId: id,
        uid,
        gid,
        groups,
        umask: 0o022,
        cwd: '/',
      }));
    })();
  }

  check() {
    if (!this.alive) throw Object.assign(new Error('workspace is closed'), { errno: 'ENODEV' });
  }

  scope() {
    return ++this._nextPid;
  }

  async _ensureScope(pid = this.page) {
    await this._ready;
    if (!this._spawnedPids.has(pid)) {
      this._spawnedPids.add(pid);
      await this.kernel.proc_spawn_init(JSON.stringify({
        pid,
        ppid: 1,
        sessionId: this.id,
        uid: this.identity.uid,
        gid: this.identity.gid,
        groups: [...this.identity.groups],
        umask: 0o022,
        cwd: '/',
      }));
    }
    return pid;
  }

  async resolveExport(path) {
    await this._ready;
    this.check();
    return this.kernel.export_provider(this.id, path);
  }

  async mount(args) {
    await this._ready;
    this.check();
    const prepared = await prepareUserMount(args, this.identity);
    let summary;
    try {
      this.check();
      summary = await this.kernel.mount_user(this.id, JSON.stringify(prepared.spec), prepared.hostObj);
    } catch (err) {
      try { prepared.cleanup?.(); } catch {}
      throw err;
    }
    if (prepared.cleanup) this.cleanups.set(summary.path, prepared.cleanup);
    let exp = null;
    try { exp = this.kernel.export_provider(this.id, summary.path); } catch {}
    const rec = { ...summary, ...(exp ?? {}), active: true };
    this.mounts.set(summary.path, rec);
    return rec;
  }

  async attachShared(path, remote, { cloud = false } = {}) {
    await this._ready;
    this.check();
    const name = path.split('/').filter(Boolean).pop();
    const summary = await this.kernel.mount_user(
      this.id,
      JSON.stringify({
        kind: 'sharefs',
        name,
        target: path,
        writable: !remote.grant.readOnly,
        execute: !!remote.grant.execute,
        cloud,
      }),
      remote,
    );
    const rec = { ...summary, provider: remote, grant: remote.grant, active: true };
    this.mounts.set(summary.path, rec);
    this.sharedConnections.set(summary.path, remote.connection);
    this.cleanups.set(summary.path, () => remote.unmount(remote.grant));
    return rec;
  }

  async activate({ name, source, sources, cloud = false }) {
    await this._ready;
    this.check();
    const summary = await this.kernel.mount_user(
      this.id,
      JSON.stringify({
        kind: 'image',
        name,
        source,
        sources: sources ?? [source],
        cloud,
      }),
      null,
    );
    this.mounts.set(summary.path, { ...summary, active: true });
    return summary;
  }

  list() {
    return [...this.mounts.values()];
  }

  async unmount(path, flags = 2) {
    await this._ready;
    await this.kernel.unmount_user(this.id, path, flags);
    this.mounts.delete(path);
    for (const [id, exported] of this.exports) {
      if (exported.mountPath === path || exported.mount?.path === path) {
        try { exported.connection.close(); } catch {}
        this.exports.delete(id);
      }
    }
    const conn = this.sharedConnections.get(path);
    if (conn) {
      this.sharedConnections.delete(path);
      try { conn.close(); } catch {}
    }
    const cleanup = this.cleanups.get(path);
    if (cleanup) {
      this.cleanups.delete(path);
      try { cleanup(); } catch {}
    }
  }

  close() {
    if (!this.alive) return;
    this.alive = false;
    for (const exported of this.exports.values()) {
      try { exported.connection.close(); } catch {}
    }
    this.exports.clear();
    for (const conn of this.sharedConnections.values()) {
      try { conn.close(); } catch {}
    }
    this.sharedConnections.clear();
    for (const fn of this.cleanups.values()) {
      try { fn?.(); } catch {}
    }
    this.cleanups.clear();
    this.mounts.clear();
    this.fds.clear();
    void this._ready.then(async () => {
      for (const pid of this._spawnedPids) {
        await this.kernel.proc_exit(pid).catch(() => {});
      }
      await this.kernel.session_end(this.id).catch(() => {});
    });
  }

  async calls(calls, _scope = this.page, _cloudFn = null, opts = {}) {
    await this._ready;
    this.check();
    const resolveFdRef = (fdArg, results) => {
      if (typeof fdArg === 'number') return fdArg;
      if (fdArg && typeof fdArg === 'object' && typeof fdArg.ref === 'number') {
        const prev = results[fdArg.ref]?.ok?.fd;
        return typeof prev === 'number' ? prev : -1;
      }
      return -1;
    };
    const normalizeCall = (c, results) => {
      if (!c || typeof c !== 'object') return c;
      const [key, val] = Object.entries(c)[0];
      const next = val && typeof val === 'object' ? { ...val } : val;
      if (next && typeof next === 'object' && next.fd && typeof next.fd === 'object' && 'ref' in next.fd && results) {
        const resolved = resolveFdRef(next.fd, results);
        if (resolved < 0) return { __badRef: true };
        next.fd = resolved;
      }
      if (key === 'open' && next && next.flags === undefined) next.flags = 0;
      return { [key]: next };
    };

    const hasSynthetic = calls.some(c => c && typeof c === 'object' && ('fstat' in c || 'fsync' in c || 'ftruncate' in c));
    if (!hasSynthetic) {
      const normCalls = calls.map(c => normalizeCall(c, null));
      const raw = await this.kernel.vfs_sys(
        this.id,
        JSON.stringify({ calls: normCalls, sudo: !!opts.sudo, umask: opts.umask }),
      );
      const results = JSON.parse(raw).results;
      for (let i = 0; i < normCalls.length; i++) {
        const c = normCalls[i];
        const r = results[i];
        if (c?.open && r?.ok?.fd >= CLIENT_PAGE_FD_BASE) this.fds.add(r.ok.fd);
        if (c?.close && r && 'ok' in r) {
          const refIdx = c.close.fd?.ref;
          const closedFd = typeof refIdx === 'number' ? results[refIdx]?.ok?.fd : c.close.fd;
          if (typeof closedFd === 'number') this.fds.delete(closedFd);
        }
      }
      return results;
    }

    const results = [];
    for (const orig of calls) {
      const c = normalizeCall(orig, results);
      if (c?.__badRef) {
        results.push({ err: { errno: 'EBADF' } });
        continue;
      }
      if (c && typeof c === 'object' && 'fstat' in c) {
        const fd = resolveFdRef(c.fstat.fd, results);
        if (fd < 0) { results.push({ err: { errno: 'EBADF' } }); continue; }
        try {
          const st = await this.kernel.vfs_fstat_fd(this.id, fd);
          results.push({ ok: st });
        } catch (err) {
          results.push({ err: { errno: err.errno ?? 'EIO', detail: err.detail ?? err.message } });
        }
        continue;
      }
      if (c && typeof c === 'object' && 'fsync' in c) {
        const fd = resolveFdRef(c.fsync.fd, results);
        if (fd < 0) { results.push({ err: { errno: 'EBADF' } }); continue; }
        try {
          await this.kernel.vfs_fsync_fd(this.id, fd, !!c.fsync.data_only);
          results.push({ ok: null });
        } catch (err) {
          results.push({ err: { errno: err.errno ?? 'EIO', detail: err.detail ?? err.message } });
        }
        continue;
      }
      if (c && typeof c === 'object' && 'ftruncate' in c) {
        const fd = resolveFdRef(c.ftruncate.fd, results);
        if (fd < 0) { results.push({ err: { errno: 'EBADF' } }); continue; }
        try {
          await this.kernel.vfs_ftruncate_fd(this.id, fd, BigInt(c.ftruncate.size ?? 0));
          results.push({ ok: null });
        } catch (err) {
          results.push({ err: { errno: err.errno ?? 'EIO', detail: err.detail ?? err.message } });
        }
        continue;
      }
      const raw = await this.kernel.vfs_sys(
        this.id,
        JSON.stringify({ calls: [c], sudo: !!opts.sudo, umask: opts.umask }),
      );
      const [one] = JSON.parse(raw).results;
      if (c?.open && one?.ok?.fd >= CLIENT_PAGE_FD_BASE) this.fds.add(one.ok.fd);
      if (c?.close && one && 'ok' in one && typeof c.close.fd === 'number') this.fds.delete(c.close.fd);
      results.push(one);
    }
    return results;
  }

  async stat(path, follow = true) {
    await this._ready;
    this.check();
    return this.kernel.proc_statat(this.page, OS_FD_ROOT, path, follow);
  }

  async image(path, cwd = '/') {
    await this._ready;
    this.check();
    return this.kernel.session_resolve_exec(this.id, path, JSON.stringify([path]), cwd, '/usr/bin', false, false);
  }

  async open(path, flags = 0, scope = this.page) {
    this.check();
    const pid = await this._ensureScope(scope);
    const opened = await this.kernel.proc_openat(pid, OS_FD_ROOT, path, flags, 0o666, false);
    return { fd: opened.kfd, kfd: opened.kfd, stat: opened.stat };
  }

  async read(fd, offset = 0, count = 4096, scope = this.page) {
    this.check();
    if (fd >= CLIENT_PAGE_FD_BASE) {
      const [res] = await this.calls([{ pread: { fd, offset, count } }]);
      if (res.err) throw Object.assign(new Error(res.err.detail ?? res.err.errno), { errno: res.err.errno });
      return res.ok;
    }
    const pid = await this._ensureScope(scope);
    const bytes = await this.kernel.kfd_pread(pid, fd, count, BigInt(offset));
    return { data: encodeB64Bytes(bytes) };
  }

  async write(fd, data, offset = 0, scope = this.page) {
    this.check();
    const bytes = data instanceof Uint8Array ? data : encoder.encode(String(data));
    if (fd >= CLIENT_PAGE_FD_BASE) {
      const res = await this.kernel.vfs_pwrite_chunk(this.id, fd, BigInt(offset), bytes);
      return typeof res === 'number' ? { written: res } : res;
    }
    const pid = await this._ensureScope(scope);
    const written = await this.kernel.kfd_pwrite(pid, fd, bytes, BigInt(offset));
    return { written };
  }

  async fstat(fd, scope = this.page) {
    this.check();
    if (fd >= CLIENT_PAGE_FD_BASE) {
      const [res] = await this.calls([{ fstat: { fd } }]);
      if (res.err) throw Object.assign(new Error(res.err.detail ?? res.err.errno), { errno: res.err.errno });
      return res.ok;
    }
    const pid = await this._ensureScope(scope);
    return this.kernel.kfd_fstat(pid, fd);
  }

  async closeFd(fd, scope = this.page) {
    this.check();
    if (fd >= CLIENT_PAGE_FD_BASE) {
      const [res] = await this.calls([{ close: { fd } }]);
      if (res.err) throw Object.assign(new Error(res.err.detail ?? res.err.errno), { errno: res.err.errno });
      return;
    }
    const pid = await this._ensureScope(scope);
    await this.kernel.kfd_close(pid, fd);
  }

  async tryLock(fd, family, kind, start = 0, end = null, scope = this.page) {
    this.check();
    const pid = await this._ensureScope(scope);
    await this.kernel.kfd_lock(pid, fd, family, kind, BigInt(start), end != null ? BigInt(end) : undefined, false);
  }

  async lock(fd, family, kind, start = 0, end = null, scope = this.page) {
    this.check();
    const pid = await this._ensureScope(scope);
    await this.kernel.kfd_lock(pid, fd, family, kind, BigInt(start), end != null ? BigInt(end) : undefined, true);
  }

  async unlock(fd, family, start = 0, end = null, scope = this.page) {
    this.check();
    const pid = await this._ensureScope(scope);
    await this.kernel.kfd_unlock(pid, fd, family, BigInt(start), end != null ? BigInt(end) : undefined);
  }

  async testLock(fd, kind, start = 0, end = null, scope = this.page) {
    this.check();
    const pid = await this._ensureScope(scope);
    return this.kernel.kfd_test_lock(pid, fd, kind, BigInt(start), end != null ? BigInt(end) : undefined);
  }
}

const Workspace = TestSession;

const create = async () => {
  const space = new Workspace({ id: 'test-session', uid: 12 });
  await space.mount({ name: 'project', files: [file('text', 'abc')], execute: false, cloud: false });
  return space;
};

// ============================================================================
// 1. Session MountNamespace & Provider Contract Tests (L2 `os_vfs::Vfs`)
// ============================================================================

test('browser host mounts retain handles without reading a tree at admission', async () => {
  installBrowserEnv();
  const space = new Workspace({ id: 'host', uid: 12 });
  let content = 'first', reads = 0, lookups = 0, permission = 'granted';
  const fileHandle = { kind: 'file', name: 'note', async getFile() { reads++; return file('note', content); } };
  const handle = {
    kind: 'directory', name: 'project',
    async queryPermission() { return permission; },
    async resolve(child) { return child === handle ? [] : child === fileHandle ? ['note'] : null; },
    async *entries() { throw new Error('must not enumerate at mount'); },
    async getDirectoryHandle() { lookups++; throw new DOMException('file', 'TypeMismatchError'); },
    async getFileHandle() { lookups++; return fileHandle; },
  };
  const mount = await space.mount({ handle, execute: false, cloud: false });
  assert.equal(mount.kind, 'directory'); assert.equal(reads, 0); assert.equal(lookups, 0);
  const read = async () => {
    const fd = await space.open('/mnt/local/project/note', 0, space.page);
    try { return atob((await space.read(fd.fd, 0, 32, space.page)).data); }
    finally { await space.closeFd(fd.fd, space.page); }
  };
  assert.equal(await read(), 'first'); content = 'edited on host';
  assert.equal(await read(), 'edited on host'); permission = 'denied';
  await assert.rejects(read(), { errno: 'EACCES' });
  await assert.rejects(space.stat('/mnt/local/project/note'), { errno: 'EACCES' });
  space.close();
});

test('a folder selection cannot be attached to a different login', async () => {
  const previous = globalThis.kernelRequest;
  let id = 'picker-owner';
  try {
    globalThis.kernelRequest = async () => ({ id, uid: 12 });
    const login = await mountRequest('mount_identity');
    id = 'picker-other';
    await assert.rejects(mountRequest('mount_attach', { login, name: 'project', cloud: false, files: [file('note', 'private')] }), { errno: 'EACCES' });
    assert.deepEqual(await mountRequest('mount_list'), []);
  } finally { endWorkspace('picker-owner'); endWorkspace('picker-other'); globalThis.kernelRequest = previous; }
});

test('a new account joins its workspace but explicit shutdown is never revived', async () => {
  const previous = globalThis.kernelRequest;
  let joined = false, refreshes = 0, shutdown = false, id = 'new-account';
  const ended = [];
  try {
    globalThis.kernelRequest = async (type, args) => {
      if (type === 'login_refresh') { joined = true; refreshes++; return; }
      if (type === 'workspace_credentials') return { uid: 42 };
      if (type === 'session_end') { ended.push(args.sessionId); return; }
      if (type === 'vfs_read_stream_chunk' || type === 'vfs_close_read_stream') return args.sessionId;
      if (type === 'session_begin' || type === 'set_active_session') return null;
      assert.equal(type, 'login_lifecycle');
      return joined ? { id, uid: 42, shutdown } : null;
    };
    assert.equal((await currentWorkspace()).identity.uid, 42);
    assert.equal(refreshes, 1);
    id = 'next-login';
    for (const type of ['mount_vfs_read_chunk', 'mount_vfs_close_read']) {
      assert.equal(await mountRequest(type, { sessionId: 'new-account', streamId: 1 }), id);
    }
    assert.ok(ended.includes('new-account'));
    shutdown = true;
    await assert.rejects(currentWorkspace(), { errno: 'EACCES' });
    assert.equal(refreshes, 1);
  } finally { await endWorkspace(id); globalThis.kernelRequest = previous; }
});

test('descriptors are private to their process lineage and mount detaches cleanly on unmount', async () => {
  const space = await create(), scope = space.scope(), foreign = space.scope();
  const fd = await space.open('/mnt/local/project/text', 0, scope);
  assert.equal(atob((await space.read(fd.fd, 0, 3, scope)).data), 'abc');
  await assert.rejects(space.read(fd.fd, 0, 3, foreign), { errno: 'EBADF' });
  await space.unmount('/mnt/local/project');
  await assert.rejects(space.stat('/mnt/local/project/text'), { errno: 'ENOENT' });
  await space.closeFd(fd.fd, scope);
  await assert.rejects(space.read(fd.fd, 0, 3, scope), { errno: 'EBADF' });
  space.close();
});

test('cross-mount rename returns EXDEV without forwarding to cloud', async () => {
  const space = await create();
  await space.calls([{ open: { path: '/tmp/cloud-src', flags: 0o102, mode: 0o600 } }, { close: { fd: { ref: 0 } } }]);
  const [result] = await space.calls([{ rename: { from: '/tmp/cloud-src', to: '/mnt/local/project/new' } }], space.page, () => assert.fail('cross-provider mutation reached cloud'));
  assert.equal(result.err.errno, 'EXDEV');
  space.close();
});

test('mixed local batches retain fd reference indices and never forward private fds', async () => {
  const space = await create();
  const answers = await space.calls([{ stat: { path: '/cloud-missing' } }, { open: { path: '/mnt/local/project/text' } }, { pread: { fd: { ref: 1 }, count: 3 } }, { close: { fd: { ref: 1 } } }], space.page, cloud);
  assert.equal(answers[0].err.errno, 'ENOENT'); assert.equal(atob(answers[2].ok.data), 'abc'); assert.equal(space.fds.size, 0);
  space.close();
});

test('metadata describes granted virtual permissions and cannot claim root ownership', async () => {
  const space = await create(), stat = await space.stat('/mnt/local/project/text');
  assert.equal(stat.uid, 12); assert.equal(stat.mode & 0o7777, 0o400);
  assert.equal(stat.mtime, 1700000000); assert.equal(stat.mtime_nsec, 123000000);
  assert.ok(stat.dev >= 1 && stat.dev <= Number.MAX_SAFE_INTEGER);
  assert.ok(stat.ino >= 1 && stat.ino <= Number.MAX_SAFE_INTEGER);
  const [denied] = await space.calls([{ chmod: { path: '/mnt/local/project/text', mode: 0o4755 } }], space.page, cloud);
  assert.equal(denied.ok, null);
  const [chown] = await space.calls([{ chown: { path: '/mnt/local/project/text', uid: 0, gid: null, nofollow: false } }], space.page, cloud);
  assert.equal(chown.err.errno, 'EPERM');
  assert.equal((await space.stat('/mnt/local/project/text')).uid, 12);
  await assert.rejects(space.image('/mnt/local/project/text', '/'), { errno: 'EACCES' });
  space.close();
});

test('concurrent mount admission cannot exceed the workspace mount limit', async () => {
  const space = new Workspace({ id: 'bounded', uid: 12 });
  for (let i = 0; i < 15; i++) await space.mount({ name: 'm' + i, files: [file('text', 'abc')], execute: false, cloud: false });
  const results = await Promise.allSettled(['last', 'overflow'].map(name => space.mount({ name, files: [file('text', 'abc')], execute: false, cloud: false })));
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  assert.equal(results.find(result => result.status === 'rejected').reason.errno, 'ENOSPC');
  assert.equal(space.list().length, 16); space.close();
});

test('an absent login can bypass only the root overlay and never retry dispatched filesystem calls', async () => {
  const previousKernel = globalThis.kernelRequest;
  const previousPageSys = globalThis.pageSysPost;
  const k = new globalThis.wasm_bindgen.Kernel(`inst-${crypto.randomUUID()}`, `k-${crypto.randomUUID()}`);
  try {
    globalThis.kernelRequest = async () => { throw { errno: 'ENOENT' }; };
    assert.equal(await mountRequest('mount_overlay', { calls: [{ getdents: { path: '/' } }] }), null);
    await assert.rejects(mountRequest('mount_sys', { calls: [{ stat: { path: '/mnt/local/project/text' } }] }), { errno: 'ENOENT' });
    await assert.rejects(mountRequest('mount_overlay', { calls: [{ stat: { path: '/mnt/local/project/text' } }] }), { errno: 'EACCES' });
    await assert.rejects(mountRequest('mount_overlay', { calls: [{ stat: { path: '/mnt/./local/project/text' } }] }), { errno: 'EACCES' });
    let calls = 0;
    globalThis.kernelRequest = async (type, args) => {
      if (type === 'login_lifecycle' || type === 'workspace_credentials') return { id: 'overlay-test', uid: 12 };
      if (type === 'session_begin') return k.session_begin(args.sessionId, args.uid, args.gid ?? args.uid, new Uint32Array(args.groups ?? []));
      if (type === 'session_end') return k.session_end(args.sessionId);
      if (type === 'set_active_session') return null;
      if (type === 'vfs_sys') return JSON.parse(await k.vfs_sys(args.sessionId, JSON.stringify(args.batch)));
      return null;
    };
    await currentWorkspace();
    globalThis.pageSysPost = async () => { calls++; throw new Error('lost response'); };
    const result = await mountRequest('mount_overlay', { calls: [{ stat: { path: '/nonexistent-cloud-path' } }] });
    assert.equal(result[0].err.errno, 'EIO'); assert.equal(calls, 1);
  } finally {
    endWorkspace('overlay-test');
    await k.session_end('overlay-test').catch(() => {});
    globalThis.kernelRequest = previousKernel;
    globalThis.pageSysPost = previousPageSys;
  }
});

test('mount_overlay rejects normalized private carrier paths and client page descriptors', async () => {
  await assert.rejects(mountRequest('mount_overlay', { calls: [{ stat: { path: '/mnt/./local/project/text' } }] }), { errno: 'EACCES' });
  await assert.rejects(mountRequest('mount_overlay', { calls: [{ stat: { path: '/opt/scratch/../private/dev/text' } }] }), { errno: 'EACCES' });
  await assert.rejects(mountRequest('mount_overlay', { calls: [{ pread: { fd: LOCAL_FD, count: 4 } }] }), { errno: 'EACCES' });
});

test('session_end tears down private descriptors and detaches user mounts cleanly', async () => {
  const space = await create(), scope = space.scope();
  const opened = await space.open('/mnt/local/project/text', 0, scope);
  space.close();
  await assert.rejects(space.read(opened.fd, 0, 3, scope), { errno: 'ENODEV' });
  await assert.rejects(space.calls([{ stat: { path: '/' } }], scope, cloud), { errno: 'ENODEV' });
});

// ============================================================================
// 2. Ported Denial, ACL, Pin & Narrowed-Export Tests (from mount-policy.test.mjs)
// ============================================================================

async function snapshotPolicyFixture() {
  const space = new Workspace({ id: 'policy-fixture', uid: 12, gid: 9, groups: [9] });
  await space.mount({
    name: 'snap',
    files: [
      new File(['private'], 'text', { lastModified: 1700000000123 }),
      new File([new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0])], 'tool', { lastModified: 1700000000123 }),
    ],
    execute: true,
    cloud: false,
  });
  const mount = space.mounts.get('/mnt/local/snap');
  const owner = mount.provider;
  const grant = mount.grant;
  const peer = owner.forIdentity({ id: 13, group: 10, groups: [10] }, '');
  return { space, owner, peer, grant };
}

test('the Rust VFS ACL checks apply to the root, each file and retained handles', async () => {
  const { space, owner, peer, grant } = await snapshotPolicyFixture();
  await assert.rejects(peer.read(grant, 'text', 0, 8), { errno: 'EACCES' });
  await owner.policy(grant, '', 'setxattr', aclAttr(acl({ 13: 5 })));
  await assert.rejects(peer.read(grant, 'text', 0, 8), { errno: 'EACCES' });
  await owner.policy(grant, 'text', 'setxattr', aclAttr(acl({ 13: 4 }, 4)));
  const held = await peer.hold(grant, 'text');
  assert.equal(decoder.decode(await peer.read(grant, held, 0, 8)), 'private');
  assert.equal((await peer.stat(grant, held, {})).vfs.uid, 12);
  await owner.policy(grant, 'text', 'chmod', { mode: 0o700 });
  await assert.rejects(peer.read(grant, held, 0, 8), { errno: 'EACCES' });
  await peer.release(grant, held);
  await assert.rejects(peer.policy(grant, '', 'chmod', { mode: 0o777 }), { errno: 'EPERM' });
  space.close();
});

test('ACL masks, supplementary groups and source ceilings remain authoritative', async () => {
  const { space, owner, grant } = await snapshotPolicyFixture();
  const peer = owner.forIdentity({ id: 13, group: 10, groups: [9, 10] }, '');
  for (const path of ['', 'text']) await owner.policy(grant, path, 'setxattr', aclAttr(acl({}, 5, 5)));
  assert.equal(decoder.decode(await peer.read(grant, 'text', 0, 8)), 'private');
  await assert.rejects(peer.write(grant, 'text', encoder.encode('no'), {}), { errno: 'EROFS' });
  await assert.rejects(peer.access(grant, 'text', 2), { errno: 'EROFS' });
  await owner.policy(grant, 'text', 'setxattr', aclAttr(acl({ 13: 0 }, 5, 5, 5)));
  // A named-user denial takes precedence over membership in an allowed group.
  await assert.rejects(peer.read(grant, 'text', 0, 8), { errno: 'EACCES' });
  space.close();
});

test('an already pinned executable loses authorization after a policy change', async () => {
  const { space, owner, peer, grant } = await snapshotPolicyFixture();
  for (const path of ['', 'tool']) await owner.policy(grant, path, 'setxattr', aclAttr(acl({ 13: 5 })));
  const pin = await peer.pin(grant, 'tool');
  assert.equal((await localImage(pin)).bytes.length, 8);
  await owner.policy(grant, 'tool', 'chmod', { mode: 0o700 });
  await assert.rejects(localImage(pin), { errno: 'ESTALE' });
  space.close();
});

test('a narrowed export cannot walk its parent even when that parent is readable', async () => {
  const { space, owner, grant } = await snapshotPolicyFixture();
  const scoped = owner.forIdentity({ id: 12, group: 9, groups: [9] }, 'folder');
  await assert.rejects(scoped.read(grant, 'text', 0, 4), { errno: 'EACCES' });
  await assert.rejects(scoped.read(grant, 'folder/../text', 0, 4), { errno: 'EACCES' });
  space.close();
});

// ============================================================================
// 3. Track C — OPFS & Directory Handle Identity, Persistence, Links, Locks & Durability
// ============================================================================

test('OPFS workspace persists 53-bit st_dev/st_ino, modes, ACLs, xattrs, umask and setgid across aliases, remounts and tabs', async () => {
  installBrowserEnv();
  const tab1 = new Workspace({ id: 'tab-1', uid: 100, gid: 100, groups: [100, 200] });
  const tab2 = new Workspace({ id: 'tab-2', uid: 100, gid: 100, groups: [100, 200] });

  await tab1.mount({ name: 'alpha', storage: true, writable: true, execute: true, cloud: false });
  await tab1.mount({ name: 'beta', storage: true, writable: true, execute: true, cloud: false });
  await tab2.mount({ name: 'work', storage: true, writable: true, execute: true, cloud: false });

  // Create directory with setgid + default ACL and explicit umask 0o027
  const setup = await tab1.calls([
    { mkdir: { path: '/mnt/local/alpha/shared', mode: 0o775 } },
    { chown: { path: '/mnt/local/alpha/shared', uid: null, gid: 200, nofollow: false } },
    { chmod: { path: '/mnt/local/alpha/shared', mode: 0o2770 } },
    { setxattr: { path: '/mnt/local/alpha/shared', ...aclAttr(acl({ 101: 6 }, 7, 7, 0), 'system.posix_acl_default') } },
    { open: { path: '/mnt/local/alpha/shared/doc.txt', flags: 0o102, mode: 0o666 } },
    { pwrite: { fd: { ref: 4 }, index: 0, data: btoa('hello-opfs') } },
    { setxattr: { path: '/mnt/local/alpha/shared/doc.txt', name: 'user.tag', value: btoa('v1'), flags: 0, nofollow: false } },
    { close: { fd: { ref: 4 } } },
  ], tab1.page, cloud, { umask: 0o022 });
  assert.ok(setup.every(r => 'ok' in r), JSON.stringify(setup));

  const stAlpha = await tab1.stat('/mnt/local/alpha/shared/doc.txt');
  const stBeta = await tab1.stat('/mnt/local/beta/shared/doc.txt');
  const stTab2 = await tab2.stat('/mnt/local/work/shared/doc.txt');

  assert.ok(stAlpha.dev >= 1 && stAlpha.dev <= Number.MAX_SAFE_INTEGER);
  assert.ok(stAlpha.ino >= 1 && stAlpha.ino <= Number.MAX_SAFE_INTEGER);
  assert.equal(stAlpha.dev, stBeta.dev);
  assert.equal(stAlpha.ino, stBeta.ino);
  assert.equal(stAlpha.dev, stTab2.dev);
  assert.equal(stAlpha.ino, stTab2.ino);
  assert.equal(stTab2.gid, 200);
  assert.equal(stTab2.acl, true);

  // Remount in a fresh tab and verify xattrs, ACLs, and inode identity survived
  tab1.close();
  tab2.close();
  const tab3 = new Workspace({ id: 'tab-3', uid: 100, gid: 100, groups: [100, 200] });
  await tab3.mount({ name: 'reattached', storage: true, writable: true, execute: true, cloud: false });
  const stRemount = await tab3.stat('/mnt/local/reattached/shared/doc.txt');
  assert.equal(stRemount.dev, stAlpha.dev);
  assert.equal(stRemount.ino, stAlpha.ino);
  assert.equal(stRemount.gid, 200);
  const [xattrRes] = await tab3.calls([
    { getxattr: { path: '/mnt/local/reattached/shared/doc.txt', name: 'user.tag', nofollow: false } },
  ], tab3.page, cloud);
  assert.equal(atob(xattrRes.ok), 'v1');
  tab3.close();
});

test('OPFS supports open-unlink across tabs with nlink 0, crash orphan sweep, open-rename, hard links and symlinks', async () => {
  const env = installBrowserEnv();
  const tab1 = new Workspace({ id: 'tab-1', uid: 12 });
  const tab2 = new Workspace({ id: 'tab-2', uid: 12 });
  await tab1.mount({ name: 'opfs', storage: true, writable: true, execute: false, cloud: false });
  await tab2.mount({ name: 'opfs', storage: true, writable: true, execute: false, cloud: false });

  // 1. Open-unlink across two tabs: Tab 1 opens RW, Tab 2 unlinks; Tab 1 still reads/writes with nlink === 0
  const [cr] = await tab1.calls([
    { open: { path: '/mnt/local/opfs/live.txt', flags: 0o102, mode: 0o600 } },
  ], tab1.page, cloud);
  const fd = cr.ok.fd;
  await tab1.write(fd, encoder.encode('before-unlink'), 0, tab1.page);

  const [unl] = await tab2.calls([{ unlink: { path: '/mnt/local/opfs/live.txt' } }], tab2.page, cloud);
  assert.equal(unl.ok, null);
  await assert.rejects(tab2.stat('/mnt/local/opfs/live.txt'), { errno: 'ENOENT' });

  const openStat = await tab1.fstat(fd, tab1.page);
  assert.equal(openStat.nlink, 0);
  assert.equal(atob((await tab1.read(fd, 0, 32, tab1.page)).data), 'before-unlink');
  await tab1.write(fd, encoder.encode('after-unlink!'), 0, tab1.page);
  assert.equal(atob((await tab1.read(fd, 0, 32, tab1.page)).data), 'after-unlink!');

  // Orphan exists in /os-orphans/<uuid>/<ino> while fd is open, and is cleaned up when closed
  const orphanSubdirs = env.opfs.hostNames('os-orphans');
  assert.equal(orphanSubdirs.length, 1);
  assert.equal(env.opfs.hostNames(`os-orphans/${orphanSubdirs[0]}`).length, 1);
  await tab1.closeFd(fd, tab1.page);
  assert.equal(env.opfs.hostNames(`os-orphans/${orphanSubdirs[0]}`).length, 0);

  // 2. Simulated crashed tab orphan: inject an unheld orphan file and verify startup sweep deletes it
  env.opfs.hostWrite(`os-orphans/${orphanSubdirs[0]}/999999`, 'crashed-orphan');
  assert.deepEqual(env.opfs.hostNames(`os-orphans/${orphanSubdirs[0]}`), ['999999']);
  const tab3 = new Workspace({ id: 'tab-3', uid: 12 });
  await tab3.mount({ name: 'opfs', storage: true, writable: true, execute: false, cloud: false });
  assert.deepEqual(env.opfs.hostNames(`os-orphans/${orphanSubdirs[0]}`), []);
  tab3.close();

  // 3. Hard links, symlinks, O_NOFOLLOW, and open-rename
  const linkBatch = await tab1.calls([
    { open: { path: '/mnt/local/opfs/orig', flags: 0o102, mode: 0o600 } },
    { pwrite: { fd: { ref: 0 }, index: 0, data: btoa('shared-bytes') } },
    { link: { from: '/mnt/local/opfs/orig', to: '/mnt/local/opfs/hard', follow: false } },
    { symlink: { target: 'hard', path: '/mnt/local/opfs/sym' } },
    { readlink: { path: '/mnt/local/opfs/sym' } },
    { rename: { from: '/mnt/local/opfs/orig', to: '/mnt/local/opfs/moved', noreplace: true } },
  ], tab1.page, cloud);
  assert.ok(linkBatch.every(r => 'ok' in r), JSON.stringify(linkBatch));
  assert.equal(linkBatch[4].ok, 'hard');

  const stMoved = await tab1.stat('/mnt/local/opfs/moved');
  const stHard = await tab1.stat('/mnt/local/opfs/hard');
  const stSymNoFollow = await tab1.stat('/mnt/local/opfs/sym', false);
  assert.equal(stMoved.ino, stHard.ino);
  assert.equal(stMoved.nlink, 2);
  assert.equal((stSymNoFollow.mode & 0o170000), 0o120000);

  const [nofollow] = await tab1.calls([
    { open: { path: '/mnt/local/opfs/sym', flags: 0o400000 } },
  ], tab1.page, cloud);
  assert.equal(nofollow.err.errno, 'ELOOP');

  // Symlink traversing `..` out of `/mnt/local/opfs` walks session namespace (`ENOENT` on missing `/outside`),
  // while direct `LocalMount` provider confines `..` with `ELOOP`!
  await tab1.calls([{ symlink: { target: '../../outside', path: '/mnt/local/opfs/escape' } }], tab1.page, cloud);
  await assert.rejects(tab1.stat('/mnt/local/opfs/escape'), { errno: 'ENOENT' });
  const mOpfs = tab1.mounts.get('/mnt/local/opfs');
  await assert.rejects(mOpfs.provider.stat(mOpfs.grant, 'escape', { follow: true }), { errno: 'ELOOP' });

  await tab1.closeFd(linkBatch[0].ok.fd, tab1.page);
  tab1.close();
  tab2.close();
});

test('Directory Handle enforces zero sidecars, EPERM on link/symlink, ESTALE and private reset on outside host edits', async () => {
  installBrowserEnv();
  const hostTree = createFakeFsTree('host-proj', { originPrivate: false });
  hostTree.hostWrite('hello.txt', 'initial-host');

  const tab1 = new Workspace({ id: 'dir-1', uid: 20, gid: 20, groups: [20] });
  const tab2 = new Workspace({ id: 'dir-2', uid: 20, gid: 20, groups: [20] });
  await tab1.mount({ name: 'proj', handle: hostTree.handle(), writable: true, execute: false, cloud: false });
  await tab2.mount({ name: 'proj', handle: hostTree.handle(), writable: true, execute: false, cloud: false });

  const st1 = await tab1.stat('/mnt/local/proj/hello.txt');
  const st2 = await tab2.stat('/mnt/local/proj/hello.txt');
  assert.equal(st1.dev, st2.dev);
  assert.equal(st1.ino, st2.ino);

  // Mutate mode + ACL inside OS and write via OS so fingerprint tracks OS state
  const osSetup = await tab1.calls([
    { chmod: { path: '/mnt/local/proj/hello.txt', mode: 0o644 } },
    { setxattr: { path: '/mnt/local/proj/hello.txt', ...aclAttr(acl({ 99: 4 }, 4, 4, 4)) } },
    { open: { path: '/mnt/local/proj/hello.txt', flags: 2 } },
    { pwrite: { fd: { ref: 2 }, index: 0, data: btoa('os-written-data') } },
  ], tab1.page, cloud);
  assert.ok(osSetup.every(r => 'ok' in r), JSON.stringify(osSetup));
  const openFd = osSetup[2].ok.fd;

  // Verify ZERO sidecar files exist in the user's host folder!
  assert.deepEqual(hostTree.hostNames(), ['hello.txt']);

  // Directory handle explicitly refuses hard link and symlink with EPERM
  const [hardErr, symErr] = await tab1.calls([
    { link: { from: '/mnt/local/proj/hello.txt', to: '/mnt/local/proj/hard.txt', follow: false } },
    { symlink: { target: 'hello.txt', path: '/mnt/local/proj/sym.txt' } },
  ], tab1.page, cloud);
  assert.equal(hardErr.err.errno, 'EPERM');
  assert.equal(symErr.err.errno, 'EPERM');

  // Outside host edit changes size/mtime -> open fd returns ESTALE, path resets to private defaults (0o600, no ACL)!
  hostTree.hostWrite('hello.txt', 'modified-outside-os-with-different-size!', Date.now() + 99_999);
  await assert.rejects(tab1.read(openFd, 0, 16, tab1.page), { errno: 'ESTALE' });
  await assert.rejects(tab1.closeFd(openFd, tab1.page), { errno: 'ESTALE' });

  const resetStat = await tab2.stat('/mnt/local/proj/hello.txt');
  assert.notEqual(resetStat.ino, st1.ino);
  assert.equal(resetStat.mode & 0o7777, 0o600);
  const [aclAfterReset] = await tab2.calls([
    { getxattr: { path: '/mnt/local/proj/hello.txt', name: 'system.posix_acl_access' } },
  ], tab2.page, cloud);
  assert.equal(aclAfterReset.err.errno, 'ENODATA');
  assert.equal(resetStat.uid, 20);

  // Open-unlink on directory handle marks open descriptor ESTALE
  const [opened2] = await tab1.calls([{ open: { path: '/mnt/local/proj/hello.txt', flags: 0 } }], tab1.page, cloud);
  await tab2.calls([{ unlink: { path: '/mnt/local/proj/hello.txt' } }], tab2.page, cloud);
  await assert.rejects(tab1.read(opened2.ok.fd, 0, 8, tab1.page), { errno: 'ESTALE' });
  await tab1.closeFd(opened2.ok.fd, tab1.page);

  tab1.close();
  tab2.close();
});

test('atomic O_EXCL, RENAME_NOREPLACE, fsync durability/errors, EDQUOT and store format versioning (§2.12)', async () => {
  const env = installBrowserEnv();
  const hostTree = createFakeFsTree('durability', { originPrivate: false });
  const tab1 = new Workspace({ id: 't1', uid: 12 });
  const tab2 = new Workspace({ id: 't2', uid: 12 });
  await tab1.mount({ name: 'opfs', storage: true, writable: true, execute: false, cloud: false });
  await tab2.mount({ name: 'opfs', storage: true, writable: true, execute: false, cloud: false });
  await tab1.mount({ name: 'dir', handle: hostTree.handle(), writable: true, execute: false, cloud: false });

  // Concurrent cross-tab O_CREAT | O_EXCL: exactly one succeeds, one fails with EEXIST
  const exclRace = await Promise.all([
    tab1.calls([{ open: { path: '/mnt/local/opfs/lockfile', flags: 0o302, mode: 0o600 } }], tab1.page, cloud),
    tab2.calls([{ open: { path: '/mnt/local/opfs/lockfile', flags: 0o302, mode: 0o600 } }], tab2.page, cloud),
  ]);
  const winners = exclRace.filter(([r]) => 'ok' in r);
  const losers = exclRace.filter(([r]) => r.err?.errno === 'EEXIST');
  assert.equal(winners.length, 1);
  assert.equal(losers.length, 1);

  // RENAME_NOREPLACE on both OPFS and Directory Handle
  await tab1.calls([
    { open: { path: '/mnt/local/opfs/other', flags: 0o302, mode: 0o600 } },
    { close: { fd: { ref: 0 } } },
    { open: { path: '/mnt/local/dir/a', flags: 0o302, mode: 0o600 } },
    { close: { fd: { ref: 2 } } },
    { open: { path: '/mnt/local/dir/b', flags: 0o302, mode: 0o600 } },
    { close: { fd: { ref: 4 } } },
  ], tab1.page, cloud);
  const [nrOpfs, nrDir] = await tab1.calls([
    { rename: { from: '/mnt/local/opfs/other', to: '/mnt/local/opfs/lockfile', noreplace: true } },
    { rename: { from: '/mnt/local/dir/a', to: '/mnt/local/dir/b', noreplace: true } },
  ], tab1.page, cloud);
  assert.equal(nrOpfs.err.errno, 'EEXIST');
  assert.equal(nrDir.err.errno, 'EEXIST');

  // fsync / fdatasync: bad fd -> EBADF, valid file & directory -> ok, flush failure -> EIO, quota -> EDQUOT
  const [badSync] = await tab1.calls([{ fsync: { fd: LOCAL_FD + 99999, data_only: false } }], tab1.page, cloud);
  assert.equal(badSync.err.errno, 'EBADF');

  const [dirOpen] = await tab1.calls([{ open: { path: '/mnt/local/dir', flags: 0o200000 } }], tab1.page, cloud);
  assert.ok(dirOpen.ok.fd >= LOCAL_FD);
  const [dirSync] = await tab1.calls([{ fsync: { fd: dirOpen.ok.fd, data_only: false } }], tab1.page, cloud);
  assert.equal(dirSync.ok, null);
  await tab1.closeFd(dirOpen.ok.fd, tab1.page);

  const [fOpen] = await tab1.calls([{ open: { path: '/mnt/local/dir/a', flags: 2 } }], tab1.page, cloud);
  assert.equal((await tab1.calls([{ fsync: { fd: fOpen.ok.fd, data_only: true } }], tab1.page, cloud))[0].ok, null);
  hostTree.state.failFlush = true;
  assert.equal((await tab1.calls([{ fsync: { fd: fOpen.ok.fd, data_only: false } }], tab1.page, cloud))[0].err.errno, 'EIO');
  hostTree.state.failFlush = false;
  hostTree.state.quotaExceeded = true;
  await assert.rejects(tab1.write(fOpen.ok.fd, encoder.encode('too-big'), 0, tab1.page), { errno: 'EDQUOT' });
  hostTree.state.quotaExceeded = false;
  await tab1.closeFd(fOpen.ok.fd, tab1.page);

  // Store format versioning (§2.12):
  // 1) Older version (0) resets metadata once to private defaults WITHOUT deleting user files!
  await tab1.calls([{ chmod: { path: '/mnt/local/opfs/other', mode: 0o644 } }], tab1.page, cloud);
  await tab1.write((await tab1.open('/mnt/local/opfs/other', 2, tab1.page)).fd, encoder.encode('keep-my-bytes'), 0, tab1.page);
  tab1.close();
  tab2.close();

  const opfsDb = env.idb.databases.get('os-fs-opfs:os-workspace');
  opfsDb.stores.get('meta').records.set('version', 0);

  const tabReset = new Workspace({ id: 'reset', uid: 12 });
  await tabReset.mount({ name: 'opfs', storage: true, writable: true, execute: false, cloud: false });
  const afterReset = await tabReset.stat('/mnt/local/opfs/other');
  assert.equal(afterReset.mode & 0o7777, 0o600);
  const [preservedRead] = await tabReset.calls([{ pread: { path: '/mnt/local/opfs/other', count: 32 } }], tabReset.page, cloud);
  assert.equal(atob(preservedRead.ok.data), 'keep-my-bytes');
  tabReset.close();

  // 2) Newer version (99) is left untouched and fails attachment with EPROTONOSUPPORT!
  opfsDb.stores.get('meta').records.set('version', 99);
  const tabNewer = new Workspace({ id: 'newer', uid: 12 });
  await assert.rejects(
    tabNewer.mount({ name: 'opfs', storage: true, writable: true, execute: false, cloud: false }),
    { errno: 'EPROTONOSUPPORT' },
  );
  assert.equal(opfsDb.stores.get('meta').records.get('version'), 99);
  tabNewer.close();
});

test('multi-tab flock and fcntl byte-range locks enforce EAGAIN, blocking wakeup, EDEADLK, crash release and ENOLCK', async () => {
  const env = installBrowserEnv();
  const tab1 = new Workspace({ id: 'lock-1', uid: 12 });
  const tab2 = new Workspace({ id: 'lock-2', uid: 12 });
  await tab1.mount({ name: 'opfs', storage: true, writable: true, execute: false, cloud: false });
  await tab2.mount({ name: 'opfs', storage: true, writable: true, execute: false, cloud: false });

  await tab1.calls([
    { open: { path: '/mnt/local/opfs/f1', flags: 0o102, mode: 0o600 } },
    { close: { fd: { ref: 0 } } },
    { open: { path: '/mnt/local/opfs/f2', flags: 0o102, mode: 0o600 } },
    { close: { fd: { ref: 2 } } },
  ], tab1.page, cloud);

  const a1 = (await tab1.open('/mnt/local/opfs/f1', 2, tab1.page)).fd;
  const b1 = (await tab2.open('/mnt/local/opfs/f1', 2, tab2.page)).fd;

  // Cross-tab flock conflict + blocking wakeup on unlock
  await tab1.tryLock(a1, 'flock', 'exclusive', 0, null, tab1.page);
  await assert.rejects(tab2.tryLock(b1, 'flock', 'exclusive', 0, null, tab2.page), { errno: 'EAGAIN' });

  let woke = false;
  const waiter = tab2.lock(b1, 'flock', 'exclusive', 0, null, tab2.page).then(() => { woke = true; });
  await new Promise(r => setTimeout(r, 25));
  assert.equal(woke, false);
  await tab1.unlock(a1, 'flock', 0, null, tab1.page);
  await waiter;
  assert.equal(woke, true);
  await tab2.unlock(b1, 'flock', 0, null, tab2.page);

  // Cross-tab fcntl byte-range conflict, testLock (F_GETLK), and 2-cycle EDEADLK detection
  await tab1.tryLock(a1, 'posix', 'exclusive', 0, 10, tab1.page);
  await tab2.tryLock(b1, 'posix', 'exclusive', 20, 30, tab2.page);
  // Non-overlapping range succeeds
  await tab2.tryLock(b1, 'posix', 'exclusive', 10, 20, tab2.page);
  await tab2.unlock(b1, 'posix', 10, 20, tab2.page);

  const conflict = await tab2.testLock(b1, 'exclusive', 0, 10, tab2.page);
  assert.equal(conflict.kind, 'exclusive');
  assert.equal(conflict.range.start, 0);
  assert.equal(conflict.range.end, 10);

  // Tab 1 (holding [0,10)) blocks waiting for b1's [20,30); Tab 2 (b1) requests [0,10) -> EDEADLK!
  const tab1Wait = tab1.lock(a1, 'posix', 'exclusive', 20, 30, tab1.page);
  await new Promise(r => setTimeout(r, 30));
  await assert.rejects(tab2.lock(b1, 'posix', 'exclusive', 0, 10, tab2.page), { errno: 'EDEADLK' });
  await tab2.unlock(b1, 'posix', 20, 30, tab2.page);
  await tab1Wait;

  // Simulated tab-1 crash: releasing its `os-fs-open:` Web Locks immediately frees its persisted locks!
  env.locks.forceReleaseByPrefix('os-fs-open:');
  await tab2.tryLock(b1, 'posix', 'exclusive', 0, 10, tab2.page);
  await tab2.unlock(b1, 'posix', 0, 10, tab2.page);

  // Missing lock coordinator -> ENOLCK
  globalThis.__osForceEnolck = true;
  try {
    await assert.rejects(tab2.tryLock(b1, 'flock', 'shared', 0, null, tab2.page), { errno: 'ENOLCK' });
  } finally {
    globalThis.__osForceEnolck = false;
  }

  tab1.close();
  tab2.close();
});

test('RemoteMount and exportMount support O_EXCL, RENAME_NOREPLACE, links, fsync, open-unlink, open-rename and subtree confinement', async () => {
  installBrowserEnv();
  const hostTree = createFakeFsTree('shared-host', { originPrivate: false });
  hostTree.hostWrite('export/file.txt', 'PUBLIC');
  hostTree.hostWrite('secret.txt', 'SECRET');

  const owner = new Workspace({ id: 'owner-s', uid: 50, gid: 50, groups: [50] });
  const peer = new Workspace({ id: 'peer-s', uid: 51, gid: 51, groups: [51] });
  await owner.mount({ name: 'opfs', storage: true, writable: true, execute: true, cloud: false });
  await owner.mount({ name: 'host', handle: hostTree.handle(), writable: true, execute: false, cloud: false });

  await owner.calls([
    { mkdir: { path: '/mnt/local/opfs/sub', mode: 0o700 } },
    { setxattr: { path: '/mnt/local/opfs/sub', ...aclAttr(acl({ 51: 7 }, 7)) } },
    { setxattr: { path: '/mnt/local/opfs/sub', ...aclAttr(acl({ 51: 7 }, 7), 'system.posix_acl_default') } },
    { symlink: { target: '../outside', path: '/mnt/local/opfs/sub/escape' } },
  ], owner.page, cloud);

  // Wire a pure in-memory MessageChannel relay harness between exportMount and attachMount
  const prevFetch = globalThis.fetch;
  const listeners = new Map();
  const grants = new Map();
  const channels = [];
  function makeRelayBridge(identity, isOwner) {
    const ch = new MessageChannel();
    channels.push(ch);
    ch.port2.onmessage = ({ data }) => {
      if (data.type === 'listen') {
        const id = data.url.split('/listen/')[1].split('?')[0];
        listeners.set(id, ch.port2);
        queueMicrotask(() => ch.port2.postMessage({ type: 'ready' }));
      } else if (data.type === 'connect') {
        const parts = data.url.split('/channel/')[1].split('?')[0].split('/');
        const key = parts[0] + ':' + parts[1];
        const pair = grants.get(key);
        pair[isOwner ? 'ownerPort' : 'targetPort'] = ch.port2;
        if (pair.ownerPort && pair.targetPort) {
          queueMicrotask(() => {
            pair.ownerPort.postMessage({ type: 'ready' });
            pair.targetPort.postMessage({ type: 'ready' });
          });
        }
      } else if (data.type === 'send') {
        for (const pair of grants.values()) {
          if (pair.ownerPort === ch.port2) pair.targetPort?.postMessage({ type: 'message', message: data.message });
          else if (pair.targetPort === ch.port2) pair.ownerPort?.postMessage({ type: 'message', message: data.message });
        }
      } else if (data.type === 'close') {
        for (const pair of grants.values()) {
          if (pair.ownerPort === ch.port2) pair.targetPort?.postMessage({ type: 'closed', errno: 'ENODEV' });
          else if (pair.targetPort === ch.port2) pair.ownerPort?.postMessage({ type: 'closed', errno: 'ENODEV' });
        }
      } else if (data.type === 'reject') {
        for (const [k, pair] of grants.entries()) {
          if (k.endsWith(':' + data.session)) pair.targetPort?.postMessage({ type: 'closed', errno: data.errno });
        }
      }
    };
    ch.port2.start();
    void identity;
    return ch.port1;
  }

  let currentFetchUid = 50;
  try {
    globalThis.fetch = async (url, init) => {
      const body = init?.body ? JSON.parse(init.body) : {};
      if (url === '/api/mounts/publish') {
        const id = crypto.randomUUID();
        grants.set(id, { write: body.write, execute: body.execute, password: body.password, expires: Date.now() + 60_000 });
        return new Response(JSON.stringify({ id, uid: currentFetchUid, ticket: 't', expires: Date.now() + 60_000, name: body.name, write: body.write, execute: body.execute }), { status: 200 });
      }
      if (url.startsWith('/api/mounts/connect/')) {
        const id = url.split('/connect/')[1];
        const g = grants.get(id);
        const session = crypto.randomUUID();
        const key = id + ':' + session;
        grants.set(key, { ownerPort: null, targetPort: null });
        const ownerClientBridge = makeRelayBridge(null, true);
        listeners.get(id).postMessage({
          type: 'client',
          session,
          ticket: 't',
          port: ownerClientBridge,
          password: !!g.password && body.password === g.password,
          identity: { id: 51, group: 51, groups: [51] },
          write: g.write && body.write,
          execute: g.execute && body.execute,
        }, [ownerClientBridge]);
        return new Response(JSON.stringify({ id, session, uid: currentFetchUid, ticket: 't', expires: g.expires, name: 'shared', write: g.write && body.write, execute: g.execute && body.execute }), { status: 200 });
      }
      return new Response(JSON.stringify({ exports: [] }), { status: 200 });
    };

    currentFetchUid = 50;
    const pubOpfs = await exportMount(owner, { path: '/mnt/local/opfs/sub', name: 'sub', seconds: 60, port: makeRelayBridge(owner, true) });
    currentFetchUid = 51;
    const remoteOpfs = await attachMount(peer, { address: pubOpfs.address, writable: true, execute: true, port: makeRelayBridge(peer, false) });
    await peer.attachShared('/mnt/shared/sub', remoteOpfs);

    // Publisher-side rename and replacement must not redirect a peer's retained directory.
    const folder = '/mnt/local/opfs/sub/retained';
    await owner.calls([{ mkdir: { path: folder, mode: 0o777 } }], owner.page, cloud);
    const [pinned] = await peer.calls([{ open: { path: '/mnt/shared/sub/retained', flags: 0o200000 } }], peer.page, cloud);
    assert.ok(pinned.ok, JSON.stringify(pinned));
    const moved = await owner.calls([
      { rename: { from: folder, to: folder + '-old' } }, { mkdir: { path: folder, mode: 0o777 } },
    ], owner.page, cloud);
    assert.ok(moved.every(r => 'ok' in r), JSON.stringify(moved));
    const [stale] = await peer.calls([{ mkdir_at: { dirfd: pinned.ok.fd, path: 'child', mode: 0o755 } }], peer.page, cloud);
    assert.equal(stale.err.errno, 'ESTALE');
    const [replacement] = await owner.calls([{ stat: { path: folder + '/child' } }], owner.page, cloud);
    assert.equal(replacement.err.errno, 'ENOENT');
    await peer.calls([{ close: { fd: pinned.ok.fd } }], peer.page, cloud);

    // Direct RemoteMount confines escaping symlinks with ELOOP, while VFS mount walks `..` into `/mnt/shared` (`ENOENT`).
    await assert.rejects(remoteOpfs.open(remoteOpfs.grant, 'escape', 0), { errno: 'ELOOP' });

    // Test O_EXCL, link, symlink, readlink, RENAME_NOREPLACE, open-rename, open-unlink, and fsync over RemoteMount!
    const remoteOps = await peer.calls([
      { open: { path: '/mnt/shared/sub/a.txt', flags: 0o302, mode: 0o666 } },
      { pwrite: { fd: { ref: 0 }, index: 0, data: btoa('remote-hello') } },
      { fsync: { fd: { ref: 0 }, data_only: false } },
      { open: { path: '/mnt/shared/sub/a.txt', flags: 0o302, mode: 0o666 } }, // EEXIST!
      { link: { from: '/mnt/shared/sub/a.txt', to: '/mnt/shared/sub/hard.txt', follow: false } },
      { symlink: { target: 'hard.txt', path: '/mnt/shared/sub/sym.txt' } },
      { readlink: { path: '/mnt/shared/sub/sym.txt' } },
      { rename: { from: '/mnt/shared/sub/a.txt', to: '/mnt/shared/sub/hard.txt', noreplace: true } }, // EEXIST!
      { rename: { from: '/mnt/shared/sub/a.txt', to: '/mnt/shared/sub/renamed.txt', noreplace: true } },
      { pread: { fd: { ref: 0 }, count: 32 } },
      { unlink: { path: '/mnt/shared/sub/hard.txt' } },
      { unlink: { path: '/mnt/shared/sub/renamed.txt' } },
      { fstat: { fd: { ref: 0 } } },
      { pread: { fd: { ref: 0 }, count: 32 } },
      { open: { path: '/mnt/shared/sub/escape', flags: 0 } }, // ENOENT in /mnt/shared!
      { close: { fd: { ref: 0 } } },
    ], peer.page, cloud);

    assert.equal(remoteOps[2].ok, null, JSON.stringify(remoteOps));
    assert.equal(remoteOps[3].err.errno, 'EEXIST');
    assert.equal(remoteOps[6].ok, 'hard.txt');
    assert.equal(remoteOps[7].err.errno, 'EEXIST');
    assert.equal(atob(remoteOps[9].ok.data), 'remote-hello');
    assert.equal(remoteOps[12].ok.nlink, 0);
    assert.equal(atob(remoteOps[13].ok.data), 'remote-hello');
    assert.equal(remoteOps[14].err.errno, 'ENOENT');
  } finally {
    globalThis.fetch = prevFetch;
    peer.close();
    owner.close();
    for (const ch of channels) {
      try { ch.port1.close(); } catch {}
      try { ch.port2.close(); } catch {}
    }
  }
});

test('O_PATH rejects I/O and fchmod with EBADF while allowing fstat and symlink targets, and NativeMount rejects noreplace rename', async () => {
  installBrowserEnv();
  const ws = new Workspace({ id: 'opath-ws', uid: 77, gid: 77, groups: [77] });
  await ws.mount({ name: 'opfs', storage: true, writable: true, execute: false, cloud: false });

  await ws.calls([
    { open: { path: '/mnt/local/opfs/file.txt', flags: 0o302, mode: 0o600 } },
    { pwrite: { fd: { ref: 0 }, index: 0, data: btoa('hello') } },
    { close: { fd: { ref: 0 } } },
    { mkdir: { path: '/mnt/local/opfs/dir', mode: 0o700 } },
    { symlink: { target: 'file.txt', path: '/mnt/local/opfs/sym' } },
  ], ws.page, cloud);

  const O_PATH = 0o10000000;
  const O_NOFOLLOW = 0o400000;
  const f = await ws.calls([
    { open: { path: '/mnt/local/opfs/file.txt', flags: O_PATH } },
    { fstat: { fd: { ref: 0 } } },
    { pread: { fd: { ref: 0 }, count: 8 } },
    { pwrite: { fd: { ref: 0 }, index: 0, data: btoa('x') } },
    { ftruncate: { fd: { ref: 0 }, size: 0 } },
    { fsync: { fd: { ref: 0 }, data_only: false } },
    { fchmod: { fd: { ref: 0 }, mode: 0o644 } },
    { close: { fd: { ref: 0 } } },
    { open: { path: '/mnt/local/opfs/dir', flags: O_PATH } },
    { fstat: { fd: { ref: 8 } } },
    { fchmod: { fd: { ref: 8 }, mode: 0o755 } },
    { close: { fd: { ref: 8 } } },
    { open: { path: '/mnt/local/opfs/sym', flags: O_PATH | O_NOFOLLOW } },
    { fstat: { fd: { ref: 12 } } },
    { close: { fd: { ref: 12 } } },
  ], ws.page, cloud);

  assert.equal(f[1].ok.size, 5);
  assert.equal(f[2].err.errno, 'EBADF');
  assert.equal(f[3].err.errno, 'EBADF');
  assert.equal(f[4].err.errno, 'EBADF');
  assert.equal(f[5].err.errno, 'EBADF');
  assert.equal(f[6].err.errno, 'EBADF');
  assert.equal(f[9].ok.mode & 0o170000, 0o040000);
  assert.equal(f[10].err.errno, 'EBADF');
  assert.equal(f[13].ok.mode & 0o170000, 0o120000);

  // Also test direct LocalMount facade handles for O_PATH (`!held`).
  const m = ws.mounts.get('/mnt/local/opfs');
  const mh = await m.provider.open(m.grant, 'file.txt', O_PATH);
  const dh = await m.provider.open(m.grant, 'dir', O_PATH);
  assert.equal((await m.provider.stat(m.grant, mh)).size, 5);
  for (const op of [
    () => m.provider.read(m.grant, mh, 0, 4),
    () => m.provider.write(m.grant, mh, new Uint8Array([1]), {}),
    () => m.provider.ftruncate(m.grant, mh, 0),
    () => m.provider.fsync(m.grant, mh, false),
    () => m.provider.policy(m.grant, mh, 'chmod', { mode: 0o644 }),
    () => m.provider.tryLock(m.grant, mh, 'flock', 'shared', 0),
    () => m.provider.list(m.grant, dh, {}),
  ]) {
    await assert.rejects(op, { errno: 'EBADF' });
  }
  await m.provider.release(m.grant, mh);
  await m.provider.release(m.grant, dh);

  // HelperFs (`NativeMount` transport) passes `noreplace` over the helper protocol and maps unsupported/existing appropriately.
  let helperSawNoreplace = false;
  const fakeHelperTransport = {
    clientId: () => 'cid-test',
    close() {},
    async postRaw(bodyJson) {
      const req = JSON.parse(bodyJson);
      const ok = obj => ({ status: 200, body: JSON.stringify(obj) });
      if (req.hello) {
        return ok({ boundary: 'local-helper', version: 1, write: true, execute: false, handshake: 'hs-1' });
      }
      if (req.attach) {
        return ok({
          version: 1,
          session: 'sess-1',
          fs: 'helper:1',
          root: { fs: 'helper:1', node: { ino: 1, generation: 1 }, proof: '' },
          capabilities: {
            identity: 'host-local',
            open_survives_unlink: 'yes',
            open_survives_rename: 'yes',
            hard_links: 'yes',
            symlinks: 'yes',
            exclusive_create: 'yes',
            atomic_rename: 'yes',
            rename_noreplace: 'yes',
            durability: 'host-fsync',
            locks: 'host',
          },
          grant: { write: true, execute: false },
          lease_seconds: 60,
        });
      }
      if (req.call?.call?.open) {
        return ok({
          fs: 'helper:1',
          id: 1,
          node: req.call.call.open.handle.node,
          access: 'path',
        });
      }
      if (req.call?.call?.release) {
        return ok(null);
      }
      if (req.call?.call?.metadata) {
        return ok({
          file_type: 'dir', mode: 0o755, nlink: 2, uid: 77, gid: 77, size: 0,
          atime: { sec: 0, nsec: 0 }, mtime: { sec: 0, nsec: 0 }, ctime: { sec: 0, nsec: 0 },
          rdev: null, acl: false,
        });
      }
      if (req.call?.call?.lookup) {
        const name = req.call.call.lookup.name;
        return ok({
          handle: { fs: 'helper:1', node: { ino: name === 'a' ? 2 : 3, generation: 1 }, proof: '' },
          metadata: {
            file_type: 'file', mode: 0o644, nlink: 1, uid: 77, gid: 77, size: 1,
            atime: { sec: 0, nsec: 0 }, mtime: { sec: 0, nsec: 0 }, ctime: { sec: 0, nsec: 0 },
            rdev: null, acl: false,
          },
        });
      }
      if (req.call?.call?.walk) {
        const names = req.call.call.walk.names ?? [];
        return ok({
          entries: names.map(name => ({
            handle: { fs: 'helper:1', node: { ino: name === 'a' ? 2 : 3, generation: 1 }, proof: '' },
            metadata: {
              file_type: 'file', mode: 0o644, nlink: 1, uid: 77, gid: 77, size: 1,
              atime: { sec: 0, nsec: 0 }, mtime: { sec: 0, nsec: 0 }, ctime: { sec: 0, nsec: 0 },
              rdev: null, acl: false,
            },
          })),
          stop: null,
        });
      }
      if (req.call?.call?.rename) {
        const rf = req.call.call.rename.flags;
        helperSawNoreplace = Boolean(rf?.noreplace ?? (typeof rf === 'number' ? rf !== 0 : JSON.stringify(rf).toLowerCase().includes('noreplace')));
        return { status: 400, body: JSON.stringify({ errno: 'EOPNOTSUPP' }) };
      }
      return ok({ lease_seconds: 60 });
    },
  };
  await ws.kernel.mount_user(
    ws.id,
    JSON.stringify({ kind: 'helperfs', name: 'nat', writable: true, execute: false, cloud: false }),
    fakeHelperTransport,
  );
  const [natRes] = await ws.calls([{ rename: { from: '/mnt/local/nat/a', to: '/mnt/local/nat/b', noreplace: true } }], ws.page, cloud);
  assert.equal(helperSawNoreplace, true);
  assert.equal(natRes.err.errno, 'EOPNOTSUPP');

  ws.close();
});

test('RemoteMount enforces O_CREAT target auth, final symlinks, RO O_CREAT|O_EXCL, O_WRONLY fstat, unlinked fchmod revocation, mutating open disconnects, and unmount open drain', async () => {
  installBrowserEnv();
  const owner = new Workspace({ id: 'owner-sec', uid: 50, gid: 50, groups: [50] });
  const peer = new Workspace({ id: 'peer-sec', uid: 51, gid: 51, groups: [51] });
  await owner.mount({ name: 'opfs', storage: true, writable: true, execute: true, cloud: false });

  await owner.calls([
    { mkdir: { path: '/mnt/local/opfs/sub', mode: 0o700 } },
    { setxattr: { path: '/mnt/local/opfs/sub', ...aclAttr(acl({ 51: 7 }, 7)) } },
    { open: { path: '/mnt/local/opfs/sub/pub.txt', flags: 0o302, mode: 0o600 } },
    { pwrite: { fd: { ref: 2 }, index: 0, data: btoa('PUB') } },
    { close: { fd: { ref: 2 } } },
    { symlink: { target: 'pub.txt', path: '/mnt/local/opfs/sub/pubsym' } },
    { open: { path: '/mnt/local/opfs/sub/writable.txt', flags: 0o302, mode: 0o666 } },
    { chmod: { path: '/mnt/local/opfs/sub/writable.txt', mode: 0o666 } },
    { pwrite: { fd: { ref: 6 }, index: 0, data: btoa('OLD') } },
    { close: { fd: { ref: 6 } } },
    { symlink: { target: 'writable.txt', path: '/mnt/local/opfs/sub/wsym' } },
    { symlink: { target: 'dangling-target.txt', path: '/mnt/local/opfs/sub/dsym' } },
    { open: { path: '/mnt/local/opfs/sub/writeonly.txt', flags: 0o302, mode: 0o222 } },
    { chmod: { path: '/mnt/local/opfs/sub/writeonly.txt', mode: 0o222 } },
    { close: { fd: { ref: 12 } } },
    { open: { path: '/mnt/local/opfs/sub/ephem.txt', flags: 0o302, mode: 0o644 } },
    { chmod: { path: '/mnt/local/opfs/sub/ephem.txt', mode: 0o644 } },
    { pwrite: { fd: { ref: 15 }, index: 0, data: btoa('SECRET') } },
    { close: { fd: { ref: 15 } } },
  ], owner.page, cloud);

  const prevFetch = globalThis.fetch;
  const listeners = new Map();
  const grants = new Map();
  const channels = [];
  function makeRelayBridge(isOwner) {
    const ch = new MessageChannel();
    channels.push(ch);
    ch.port2.onmessage = ({ data }) => {
      if (data.type === 'listen') {
        const id = data.url.split('/listen/')[1].split('?')[0];
        listeners.set(id, ch.port2);
        queueMicrotask(() => ch.port2.postMessage({ type: 'ready' }));
      } else if (data.type === 'connect') {
        const parts = data.url.split('/channel/')[1].split('?')[0].split('/');
        const pair = grants.get(parts[0] + ':' + parts[1]);
        pair[isOwner ? 'ownerPort' : 'targetPort'] = ch.port2;
        if (pair.ownerPort && pair.targetPort) {
          queueMicrotask(() => {
            pair.ownerPort.postMessage({ type: 'ready' });
            pair.targetPort.postMessage({ type: 'ready' });
          });
        }
      } else if (data.type === 'send') {
        for (const pair of grants.values()) {
          if (pair.ownerPort === ch.port2) pair.targetPort?.postMessage({ type: 'message', message: data.message });
          else if (pair.targetPort === ch.port2) pair.ownerPort?.postMessage({ type: 'message', message: data.message });
        }
      } else if (data.type === 'close') {
        for (const pair of grants.values()) {
          if (pair.ownerPort === ch.port2) pair.targetPort?.postMessage({ type: 'closed', errno: 'ENODEV' });
          else if (pair.targetPort === ch.port2) pair.ownerPort?.postMessage({ type: 'closed', errno: 'ENODEV' });
        }
      }
    };
    ch.port2.start();
    return ch.port1;
  }

  let currentFetchUid = 50;
  try {
    globalThis.fetch = async (url, init) => {
      const body = init?.body ? JSON.parse(init.body) : {};
      if (url === '/api/mounts/publish') {
        const id = crypto.randomUUID();
        grants.set(id, { write: body.write, execute: body.execute, expires: Date.now() + 60_000 });
        return new Response(JSON.stringify({ id, uid: currentFetchUid, ticket: 't', expires: Date.now() + 60_000, name: body.name, write: body.write, execute: body.execute }), { status: 200 });
      }
      if (url.startsWith('/api/mounts/connect/')) {
        const id = url.split('/connect/')[1];
        const g = grants.get(id);
        const session = crypto.randomUUID();
        grants.set(id + ':' + session, { ownerPort: null, targetPort: null });
        const ownerPort = makeRelayBridge(true);
        listeners.get(id).postMessage({
          type: 'client',
          session,
          ticket: 't',
          port: ownerPort,
          password: false,
          identity: { id: 51, group: 51, groups: [51] },
          write: g.write && body.write,
          execute: g.execute && body.execute,
        }, [ownerPort]);
        return new Response(JSON.stringify({ id, session, uid: currentFetchUid, ticket: 't', expires: g.expires, name: 'shared', write: g.write && body.write, execute: g.execute && body.execute }), { status: 200 });
      }
      return new Response(JSON.stringify({ exports: [] }), { status: 200 });
    };

    currentFetchUid = 50;
    const pub = await exportMount(owner, { path: '/mnt/local/opfs/sub', name: 'sub', seconds: 60, port: makeRelayBridge(true) });
    currentFetchUid = 51;
    const remoteRw = await attachMount(peer, { address: pub.address, writable: true, execute: false, port: makeRelayBridge(false) });
    const remoteRo = await attachMount(peer, { address: pub.address, writable: false, execute: false, port: makeRelayBridge(false) });
    await peer.attachShared('/mnt/shared/rw', remoteRw);
    await peer.attachShared('/mnt/shared/ro', remoteRo);

    // 1. Existing 0600 publisher file cannot be opened/truncated by receiver via O_CREAT or write(create:true),
    // while non-exclusive O_CREAT follows final symlinks (both existing target and dangling symlink).
    const peerRes = await peer.calls([
      { open: { path: '/mnt/shared/rw/pub.txt', flags: 0o1102, mode: 0o600 } }, // EACCES!
      { open: { path: '/mnt/shared/rw/pubsym', flags: 0o1102, mode: 0o600 } }, // EACCES!
      { open: { path: '/mnt/shared/rw/wsym', flags: 0o1102, mode: 0o600 } },
      { pwrite: { fd: { ref: 2 }, index: 0, data: btoa('W1') } },
      { close: { fd: { ref: 2 } } },
      { open: { path: '/mnt/shared/rw/dsym', flags: 0o102, mode: 0o600 } },
      { pwrite: { fd: { ref: 5 }, index: 0, data: btoa('DAN') } },
      { close: { fd: { ref: 5 } } },
      { open: { path: '/mnt/shared/rw/writeonly.txt', flags: 1 } }, // O_WRONLY on 0222!
      { fstat: { fd: { ref: 8 } } },
      { pwrite: { fd: { ref: 8 }, index: 0, data: btoa('WO') } },
      { close: { fd: { ref: 8 } } },
      { open: { path: '/mnt/shared/ro/absent.txt', flags: 0o300, mode: 0o600 } }, // O_RDONLY|O_CREAT|O_EXCL -> EROFS!
      { open: { path: '/mnt/shared/ro/pub.txt', flags: 0o300, mode: 0o600 } }, // existing -> EEXIST!
    ], peer.page, cloud);

    assert.equal(peerRes[0].err.errno, 'EACCES');
    assert.equal(peerRes[1].err.errno, 'EACCES');
    assert.equal(peerRes[3].ok.written, 2);
    assert.equal(peerRes[6].ok.written, 3);
    assert.equal(peerRes[9].ok.mode & 0o777, 0o222, JSON.stringify(peerRes));
    assert.equal(peerRes[10].ok.written, 2);
    assert.equal(peerRes[12].err.errno, 'EROFS');
    assert.equal(peerRes[13].err.errno, 'EEXIST');
    await assert.rejects(
      remoteRw.write(remoteRw.grant, 'pub.txt', new TextEncoder().encode('HACK'), { create: true }),
      { errno: 'EACCES' },
    );
    await assert.rejects(owner.stat('/mnt/local/opfs/sub/absent.txt'), { errno: 'ENOENT' });
    const [pubAfter] = await owner.calls([{ pread: { path: '/mnt/local/opfs/sub/pub.txt', count: 16 } }], owner.page, cloud);
    assert.equal(atob(pubAfter.ok.data), 'PUB');
    const [danglingAfter] = await owner.calls([{ pread: { path: '/mnt/local/opfs/sub/dangling-target.txt', count: 16 } }], owner.page, cloud);
    assert.equal(atob(danglingAfter.ok.data), 'DAN');

    // 2. Unlinked OPFS file retains permission rechecks: fchmod(0) revokes an already-open peer fd!
    const [ownerEphem] = await owner.calls([{ open: { path: '/mnt/local/opfs/sub/ephem.txt', flags: 2 } }], owner.page, cloud);
    const openedPeerEphem = await peer.calls([{ open: { path: '/mnt/shared/rw/ephem.txt', flags: 0 } }], peer.page, cloud);
    const pFd = openedPeerEphem[0].ok.fd;
    await owner.calls([{ unlink: { path: '/mnt/local/opfs/sub/ephem.txt' } }], owner.page, cloud);
    const [readUnlinked] = await peer.calls([{ pread: { fd: pFd, count: 16 } }], peer.page, cloud);
    assert.equal(atob(readUnlinked.ok.data), 'SECRET');
    await owner.calls([
      { fchmod: { fd: ownerEphem.ok.fd, mode: 0o000 } },
      { close: { fd: ownerEphem.ok.fd } },
    ], owner.page, cloud);
    const [readAfterRevoke] = await peer.calls([{ pread: { fd: pFd, count: 16 } }], peer.page, cloud);
    assert.equal(readAfterRevoke.err.errno, 'EACCES');
    await peer.calls([{ close: { fd: pFd } }], peer.page, cloud);

    // 3. Disconnect during mutating `open` reports the uncertain-write warning, while read-only `open` does not.
    const dropRo = remoteRo.open(remoteRo.grant, 'pub.txt', 0);
    remoteRo.connection.close('ENODEV');
    await assert.rejects(dropRo, err => !/already have been saved/i.test(err.message));

    const dropMut = remoteRw.open(remoteRw.grant, 'lost-create.txt', 0o102);
    remoteRw.connection.close('ENODEV');
    await assert.rejects(dropMut, /already have been saved/i);

    // 4. `unmount()` on the owner mount drains remote `forIdentity` open refs and frees `os-fs-open` locks!
    const remoteRw2 = await attachMount(peer, { address: pub.address, writable: true, execute: false, port: makeRelayBridge(false) });
    await peer.attachShared('/mnt/shared/rw2', remoteRw2);
    await peer.calls([{ open: { path: '/mnt/shared/rw2/orphan-drain.txt', flags: 0o302, mode: 0o600 } }], peer.page, cloud);
    await owner.calls([{ unlink: { path: '/mnt/local/opfs/sub/orphan-drain.txt' } }], owner.page, cloud);
    const locksBeforeUnmount = (await navigator.locks.query()).held.filter(l => l.name.startsWith('os-fs-open:'));
    assert.ok(locksBeforeUnmount.length >= 1);

    await owner.unmount('/mnt/local/opfs');
    await new Promise(r => setTimeout(r, 30));
    const locksAfterUnmount = (await navigator.locks.query()).held.filter(l => l.name.startsWith('os-fs-open:'));
    assert.equal(locksAfterUnmount.length, 0);
  } finally {
    globalThis.fetch = prevFetch;
    peer.close();
    owner.close();
    for (const ch of channels) {
      try { ch.port1.close(); } catch {}
      try { ch.port2.close(); } catch {}
    }
  }
});

test('LocalMount enforces O_PATH symlink following, sticky protected symlinks, cross-alias creator revocation, and fs-store I/O/directory identity', async () => {
  installBrowserEnv();
  const O_PATH = 0o10000000;
  const O_DIRECTORY = 0o200000;
  const O_NOFOLLOW = 0o400000;

  const ownerA = new Workspace({ id: 'owner-a', uid: 50, gid: 50, groups: [50] });
  const ownerB = new Workspace({ id: 'owner-b', uid: 50, gid: 50, groups: [50] });
  const thirdParty = new Workspace({ id: 'third', uid: 52, gid: 52, groups: [52] });
  const peer = new Workspace({ id: 'peer-c', uid: 51, gid: 51, groups: [51] });

  await ownerA.mount({ name: 'opfs', storage: true, writable: true, execute: false, cloud: false });
  await ownerB.mount({ name: 'opfs', storage: true, writable: true, execute: false, cloud: false });

  await ownerA.calls([
    { chmod: { path: '/mnt/local/opfs', mode: 0o755 } },
    { mkdir: { path: '/mnt/local/opfs/sub', mode: 0o777 } },
    { chmod: { path: '/mnt/local/opfs/sub', mode: 0o777 } },
    { mkdir: { path: '/mnt/local/opfs/sub/targetdir', mode: 0o755 } },
    { open: { path: '/mnt/local/opfs/sub/targetfile.txt', flags: 0o302, mode: 0o644 } },
    { pwrite: { fd: { ref: 3 }, index: 0, data: btoa('target-ok') } },
    { close: { fd: { ref: 3 } } },
    { chmod: { path: '/mnt/local/opfs/sub/targetfile.txt', mode: 0o644 } },
    { symlink: { target: 'targetfile.txt', path: '/mnt/local/opfs/sub/symfile' } },
    { symlink: { target: 'targetdir', path: '/mnt/local/opfs/sub/symdir' } },
    { mkdir: { path: '/mnt/local/opfs/sub/sticky', mode: 0o1777 } },
    { chmod: { path: '/mnt/local/opfs/sub/sticky', mode: 0o1777 } },
  ], ownerA.page, cloud);

  // `O_PATH` follows final symlinks unless `O_NOFOLLOW` is set.
  const opathRes = await ownerA.calls([
    { open: { path: '/mnt/local/opfs/sub/symfile', flags: O_PATH } },
    { fstat: { fd: { ref: 0 } } },
    { close: { fd: { ref: 0 } } },
    { open: { path: '/mnt/local/opfs/sub/symdir', flags: O_PATH | O_DIRECTORY } },
    { fstat: { fd: { ref: 3 } } },
    { close: { fd: { ref: 3 } } },
    { open: { path: '/mnt/local/opfs/sub/symdir', flags: O_PATH | O_DIRECTORY | O_NOFOLLOW } },
    { open: { path: '/mnt/local/opfs/sub/symfile', flags: O_PATH | O_NOFOLLOW } },
    { fstat: { fd: { ref: 7 } } },
    { close: { fd: { ref: 7 } } },
  ], ownerA.page, cloud);
  assert.equal(opathRes[1].ok.mode & 0o170000, 0o100000);
  assert.equal(opathRes[4].ok.mode & 0o170000, 0o040000);
  assert.equal(opathRes[6].err.errno, 'ENOTDIR');
  assert.equal(opathRes[8].ok.mode & 0o170000, 0o120000);

  // Sticky world-writable protected symlink: thirdParty (uid 52) creates foreign-sym inside
  // ownerA-owned sticky dir (uid 50, mode 01777) -> target owned by uid 50.
  await thirdParty.mount({ name: 'opfs', storage: true, writable: true, execute: false, cloud: false });
  const [symCreate] = await thirdParty.calls([
    { symlink: { target: '../targetfile.txt', path: '/mnt/local/opfs/sub/sticky/foreign-sym' } },
  ], thirdParty.page, cloud);
  assert.equal(symCreate.ok, null);
  const mA = ownerA.mounts.get('/mnt/local/opfs');
  const exportView = mA.provider.forIdentity({ id: 51, group: 51, groups: [51] }, 'sub');

  await assert.rejects(
    exportView.open(mA.grant, 'sub/sticky/foreign-sym', 0),
    { errno: 'EACCES' },
  );
  await assert.rejects(
    exportView.open(mA.grant, 'sub/sticky/foreign-sym', 0o102, 0o600),
    { errno: 'EACCES' },
  );
  // Non-creator (including sticky dir owner uid 50 and third user uid 51) cannot follow foreign symlink;
  // owner of the symlink (uid 52) and links owned by dir.owner (uid 50) ARE allowed.
  const [ownerFollow] = await ownerA.calls([
    { open: { path: '/mnt/local/opfs/sub/sticky/foreign-sym', flags: 0 } },
  ], ownerA.page, cloud);
  assert.equal(ownerFollow.err.errno, 'EACCES');
  const [thirdFollow] = await thirdParty.calls([
    { open: { path: '/mnt/local/opfs/sub/sticky/foreign-sym', flags: 0 } },
    { close: { fd: { ref: 0 } } },
  ], thirdParty.page, cloud);
  assert.ok('ok' in thirdFollow, JSON.stringify(thirdFollow));
  const [ownerSym] = await ownerA.calls([
    { symlink: { target: '../targetfile.txt', path: '/mnt/local/opfs/sub/sticky/owner-sym' } },
  ], ownerA.page, cloud);
  assert.equal(ownerSym.ok, null);
  const ownerSymFd = await exportView.open(mA.grant, 'sub/sticky/owner-sym', 0);
  await exportView.release(mA.grant, ownerSymFd);

  // Cross-alias creator-grant revocation: creator opens writable via ownerA's attachment, then
  // ownerB (distinct LocalMount instance on same FsId) runs chmod(0) -> existing fd sees EACCES!
  const creatorFd = await exportView.open(mA.grant, 'sub/creator-revoke.txt', 0o302, 0o600);
  await exportView.write(mA.grant, creatorFd, new TextEncoder().encode('ok'), {});
  const [chmodB] = await ownerB.calls([
    { chmod: { path: '/mnt/local/opfs/sub/creator-revoke.txt', mode: 0o000 } },
  ], ownerB.page, cloud);
  assert.equal(chmodB.ok, null);
  await assert.rejects(
    exportView.write(mA.grant, creatorFd, new TextEncoder().encode('revoked'), {}),
    { errno: 'EACCES' },
  );
  await exportView.release(mA.grant, creatorFd);

  // Direct `fs-store.js` binding tests: mid-I/O host swap & replaced directory `isSameEntry`.
  const hostTree = createFakeFsTree('race-dir', { originPrivate: false });
  hostTree.hostWrite('race.txt', 'INITIAL');
  const dirWs = new Workspace({ id: 'dir-race', uid: 20, gid: 20, groups: [20] });
  await dirWs.mount({ name: 'race', handle: hostTree.handle(), writable: true, execute: false, cloud: false });

  const [openRace] = await dirWs.calls([
    { open: { path: '/mnt/local/race/race.txt', flags: 2 } },
    { mkdir: { path: '/mnt/local/race/sub', mode: 0o755 } },
    { chmod: { path: '/mnt/local/race/sub', mode: 0o755 } },
    { setxattr: { path: '/mnt/local/race/sub', name: 'user.tag', value: btoa('keep-no') } },
  ], dirWs.page, cloud);
  const raceFd = openRace.ok.fd;

  // Intercept `getFileHandle('race.txt')` via a custom handle wrapper that swaps hostTree on close-time!
  let raceSwapped = false;
  const swapTree = createFakeFsTree('swap-wrap', { originPrivate: false });
  swapTree.hostWrite('race.txt', 'ORIG_DATA', 1700000001000);
  const rawSwapHandle = swapTree.handle();
  const baseGetFileHandle = rawSwapHandle.getFileHandle.bind(rawSwapHandle);
  let armSwapBeforeClose = false;
  rawSwapHandle.getFileHandle = async (childName, opts) => {
    const fh = await baseGetFileHandle(childName, opts);
    if (childName !== 'race.txt' || !fh.createWritable) return fh;
    const origCreateWritable = fh.createWritable.bind(fh);
    return {
      ...fh,
      async isSameEntry(other) {
        return fh.isSameEntry(other);
      },
      async createWritable(wOpts) {
        const w = await origCreateWritable(wOpts);
        if (armSwapBeforeClose) {
          armSwapBeforeClose = false;
          // Host externally replaces `race.txt` while writable swap stream is open!
          swapTree.hostWrite('race.txt', 'EXTERNAL_REPLACEMENT_INTACT', 1700000009000);
          raceSwapped = true;
        }
        return w;
      },
    };
  };
  const swapWs = new Workspace({ id: 'swap-ws', uid: 20, gid: 20, groups: [20] });
  await swapWs.mount({ name: 'swap', handle: rawSwapHandle, writable: true, execute: false, cloud: false });
  const [swapOpen] = await swapWs.calls([
    { open: { path: '/mnt/local/swap/race.txt', flags: 2 } },
  ], swapWs.page, cloud);
  armSwapBeforeClose = true;
  const [swapWrite] = await swapWs.calls([
    { pwrite: { fd: swapOpen.ok.fd, index: 0, data: btoa('STALE_OVERWRITE') } },
  ], swapWs.page, cloud);
  assert.equal(raceSwapped, true);
  assert.equal(swapWrite.err.errno, 'ESTALE');
  const afterSwapBytes = new TextDecoder().decode(swapTree.rootNode.children.get('race.txt').bytes);
  assert.equal(afterSwapBytes, 'EXTERNAL_REPLACEMENT_INTACT');
  await swapWs.calls([{ close: { fd: swapOpen.ok.fd } }], swapWs.page, cloud);
  swapWs.close();

  // Directory external replacement (`isSameEntry === false`) invalidates old directory & resets defaults!
  const beforeSubStat = await dirWs.stat('/mnt/local/race/sub');
  const [subDirOpen] = await dirWs.calls([
    { open: { path: '/mnt/local/race/sub', flags: O_DIRECTORY } },
  ], dirWs.page, cloud);
  hostTree.rootNode.children.set('sub', {
    kind: 'directory',
    name: 'sub',
    children: new Map(),
  });
  const [staleDirMeta, freshDirStat, freshTag] = await dirWs.calls([
    { fstat: { fd: subDirOpen.ok.fd } },
    { stat: { path: '/mnt/local/race/sub' } },
    { getxattr: { path: '/mnt/local/race/sub', name: 'user.tag' } },
  ], dirWs.page, cloud);
  assert.equal(staleDirMeta.err.errno, 'ESTALE');
  assert.notEqual(freshDirStat.ok.ino, beforeSubStat.ino);
  assert.equal(freshDirStat.ok.mode & 0o7777, 0o700);
  assert.equal(freshTag.err.errno, 'ENODATA');

  await dirWs.calls([
    { close: { fd: raceFd } },
    { close: { fd: subDirOpen.ok.fd } },
  ], dirWs.page, cloud);
  dirWs.close();
  ownerA.close();
  ownerB.close();
  thirdParty.close();
  peer.close();
});

test('PR #73 P1-4 & P2-5: RemoteMount validates/clamps vfs, rejects args.handle on path ops, UTF-8 fnv53, NativeMount identity & wasm', async () => {
  installBrowserEnv();
  const owner = new Workspace({ id: 'p14-owner', uid: 50, gid: 50, groups: [50] });
  const peer = new Workspace({ id: 'p14-peer', uid: 51, gid: 51, groups: [51] });
  await owner.mount({ name: 'opfs', storage: true, writable: true, execute: true, cloud: false });
  await owner.calls([
    { mkdir: { path: '/mnt/local/opfs/sub', mode: 0o777 } },
    { chmod: { path: '/mnt/local/opfs/sub', mode: 0o777 } },
    { open: { path: '/mnt/local/opfs/sub/exec.txt', flags: 0o302, mode: 0o777 } },
    { chmod: { path: '/mnt/local/opfs/sub/exec.txt', mode: 0o777 } },
    { pwrite: { fd: { ref: 2 }, index: 0, data: btoa('hi') } },
    { close: { fd: { ref: 2 } } },
    { symlink: { target: '/secret', path: '/mnt/local/opfs/sub/abssym' } },
  ], owner.page, cloud);

  const prevFetch = globalThis.fetch;
  const listeners = new Map();
  const grants = new Map();
  const channels = [];
  let interceptStat = null;
  let interceptList = null;

  function makeBridge(isOwner) {
    const ch = new MessageChannel();
    channels.push(ch);
    ch.port2.onmessage = ({ data }) => {
      if (data.type === 'listen') {
        listeners.set(data.url.split('/listen/')[1].split('?')[0], ch.port2);
        queueMicrotask(() => ch.port2.postMessage({ type: 'ready' }));
      } else if (data.type === 'connect') {
        const [id, sess] = data.url.split('/channel/')[1].split('?')[0].split('/');
        const pair = grants.get(id + ':' + sess);
        pair[isOwner ? 'ownerPort' : 'targetPort'] = ch.port2;
        if (pair.ownerPort && pair.targetPort) {
          queueMicrotask(() => {
            pair.ownerPort.postMessage({ type: 'ready' });
            pair.targetPort.postMessage({ type: 'ready' });
          });
        }
      } else if (data.type === 'send') {
        let msg = data.message;
        if (isOwner && msg?.type === 'reply' && !msg.error) {
          if (interceptStat && msg.value && typeof msg.value === 'object' && 'kind' in msg.value && !('entries' in msg.value)) {
            msg = { ...msg, value: interceptStat(msg.value) };
          } else if (interceptList && msg.value && Array.isArray(msg.value.entries)) {
            msg = { ...msg, value: interceptList(msg.value) };
          }
        }
        for (const pair of grants.values()) {
          if (pair.ownerPort === ch.port2) pair.targetPort?.postMessage({ type: 'message', message: msg });
          else if (pair.targetPort === ch.port2) pair.ownerPort?.postMessage({ type: 'message', message: msg });
        }
      } else if (data.type === 'close') {
        for (const pair of grants.values()) {
          if (pair.ownerPort === ch.port2) pair.targetPort?.postMessage({ type: 'closed', errno: 'ENODEV' });
          else if (pair.targetPort === ch.port2) pair.ownerPort?.postMessage({ type: 'closed', errno: 'ENODEV' });
        }
      }
    };
    ch.port2.start();
    return ch.port1;
  }

  let fetchUid = 50;
  try {
    globalThis.fetch = async (url, init) => {
      const body = init?.body ? JSON.parse(init.body) : {};
      if (url === '/api/mounts/publish') {
        const id = crypto.randomUUID();
        grants.set(id, { write: body.write, execute: body.execute, expires: Date.now() + 60_000 });
        return new Response(JSON.stringify({ id, uid: fetchUid, ticket: 't', expires: Date.now() + 60_000, name: body.name, write: body.write, execute: body.execute }), { status: 200 });
      }
      if (url.startsWith('/api/mounts/connect/')) {
        const id = url.split('/connect/')[1];
        const g = grants.get(id);
        const session = crypto.randomUUID();
        grants.set(id + ':' + session, { ownerPort: null, targetPort: null });
        const ownerPort = makeBridge(true);
        listeners.get(id).postMessage({
          type: 'client',
          session,
          ticket: 't',
          port: ownerPort,
          password: false,
          identity: { id: 51, group: 51, groups: [51] },
          write: g.write && body.write,
          execute: g.execute && body.execute,
        }, [ownerPort]);
        return new Response(JSON.stringify({ id, session, uid: fetchUid, ticket: 't', expires: g.expires, name: 'ro', write: g.write && body.write, execute: g.execute && body.execute }), { status: 200 });
      }
      return new Response('{}', { status: 200 });
    };

    const pub = await exportMount(owner, { path: '/mnt/local/opfs/sub', name: 'ro', seconds: 60, port: makeBridge(true) });
    fetchUid = 51;
    const remoteRo = await attachMount(peer, { address: pub.address, writable: false, execute: false, port: makeBridge(false) });
    await peer.attachShared('/mnt/shared/ro', remoteRo);

    // 1. args.handle is rejected with EINVAL on all path-only export operations.
    for (const op of ['open', 'hold', 'list', 'mkdir', 'remove', 'rename', 'link', 'symlink', 'readlink', 'pin']) {
      await assert.rejects(
        remoteRo.connection.request(op, { handle: 'fake-handle', path: '' }),
        { errno: 'EINVAL' },
        `expected EINVAL for args.handle on ${op}`,
      );
    }

    // 2. RemoteMount clamps vfs.mode against readOnly (~0o222) and !execute (~0o111 on regular files),
    // and ShareFs exposes raw readlink target while VFS rebases absolute symlinks toFsContext.root.
    const fileSt = await remoteRo.stat(remoteRo.grant, 'exec.txt');
    assert.equal(fileSt.readOnly, true);
    assert.equal(fileSt.executable, false);
    assert.equal(fileSt.vfs.mode & 0o777, 0o444);

    const peerMeta = await peer.stat('/mnt/shared/ro/exec.txt');
    assert.equal(peerMeta.mode & 0o777, 0o444);

    const symSt = await peer.stat('/mnt/shared/ro/abssym', false);
    assert.equal(symSt.mode & 0o170000, 0o120000);
    const [symTarget] = await peer.calls([{ readlink: { path: '/mnt/shared/ro/abssym' } }], peer.page, cloud);
    assert.equal(symTarget.ok, '/secret');

    const listed = await remoteRo.list(remoteRo.grant, '');
    const execEntry = listed.entries.find(e => e.name === 'exec.txt');
    assert.equal(execEntry.stat.vfs.mode & 0o777, 0o444);

    // 3. Malformed peer vfs fields are rejected with EIO on both stat and list.
    for (const mutateVfs of [
      vfs => ({ ...vfs, dev: 0 }),
      vfs => ({ ...vfs, ino: 2 ** 54 }),
      vfs => ({ ...vfs, uid: -1 }),
      vfs => ({ ...vfs, mode: 0o040755 }), // wrong file-type bits for regular file
      () => null,
    ]) {
      interceptStat = v => ({ ...v, vfs: mutateVfs(v.vfs) });
      await assert.rejects(remoteRo.stat(remoteRo.grant, 'exec.txt'), { errno: 'EIO' });
      interceptStat = null;

      interceptList = page => ({
        ...page,
        entries: page.entries.map(e => e.name === 'exec.txt' ? { ...e, stat: { ...e.stat, vfs: mutateVfs(e.stat.vfs) } } : e),
      });
      await assert.rejects(remoteRo.list(remoteRo.grant, ''), { errno: 'EIO' });
      interceptList = null;
    }

    // 4. P2-5: fnv53 uses UTF-8 bytes so /opt/private/pkg/I and /opt/private/pkg/汉 never collide.
    const blobBytesI = encoder.encode('I-file');
    const blobBytesHan = encoder.encode('han-file');
    const shaHex = async bytes => [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(b => b.toString(16).padStart(2, '0')).join('');
    const shaI = await shaHex(blobBytesI);
    const shaHan = await shaHex(blobBytesHan);
    const manifest = JSON.stringify({
      format: 'os.image',
      version: 1,
      kind: 'sysext',
      name: 'unicode-pkg',
      revision: '1',
      abi: 1,
      level: 1,
      features: [],
      provenance: {},
      entries: [
        { path: '/', uid: 0, gid: 0, mode: 0o755, node: { type: 'directory' } },
        { path: '/usr', uid: 0, gid: 0, mode: 0o755, node: { type: 'directory' } },
        { path: '/usr/I', uid: 0, gid: 0, mode: 0o644, node: { type: 'file', sha256: shaI, size: blobBytesI.length } },
        { path: '/usr/汉', uid: 0, gid: 0, mode: 0o644, node: { type: 'file', sha256: shaHan, size: blobBytesHan.length } },
      ],
    });
    await owner.calls([
      { mkdir: { path: '/mnt/local/opfs/ext', mode: 0o755 } },
      { mkdir: { path: '/mnt/local/opfs/ext/blobs', mode: 0o755 } },
      { open: { path: '/mnt/local/opfs/ext/manifest.json', flags: 0o302, mode: 0o644 } },
      { pwrite: { fd: { ref: 2 }, index: 0, data: encodeB64Bytes(encoder.encode(manifest)) } },
      { close: { fd: { ref: 2 } } },
      { open: { path: '/mnt/local/opfs/ext/blobs/' + shaI, flags: 0o302, mode: 0o644 } },
      { pwrite: { fd: { ref: 5 }, index: 0, data: encodeB64Bytes(blobBytesI) } },
      { close: { fd: { ref: 5 } } },
      { open: { path: '/mnt/local/opfs/ext/blobs/' + shaHan, flags: 0o302, mode: 0o644 } },
      { pwrite: { fd: { ref: 8 }, index: 0, data: encodeB64Bytes(blobBytesHan) } },
      { close: { fd: { ref: 8 } } },
    ], owner.page, cloud);
    await owner.activate({ name: 'pkg', source: '/mnt/local/opfs/ext', cloud: false });
    const stI = await owner.stat('/opt/private/pkg/usr/I');
    const stHan = await owner.stat('/opt/private/pkg/usr/汉');
    assert.notEqual(stI.ino, stHan.ino);

    // 5. P2-5: NativeMount.connect checks `args.wasm`.
    let calledWasmHelper = false;
    const prevBindgen = globalThis.wasm_bindgen;
    globalThis.wasm_bindgen = undefined;
    try {
      const sentinel = { grant: Object.freeze({ kind: 'native-directory', name: 'h', readOnly: false, execute: true }) };
      const connected = await NativeMount.connect({
        url: 'http://127.0.0.1:45555/',
        token: 'b'.repeat(64),
        name: 'h',
        writable: true,
        execute: true,
        wasm: {
          connect_helper_mount: async (transport, grantJson) => {
            calledWasmHelper = true;
            assert.ok(transport);
            assert.equal(JSON.parse(grantJson).name, 'h');
            return sentinel;
          },
        },
      }, { id: 50, group: 50, groups: [50] });
      assert.equal(calledWasmHelper, true);
      assert.equal(connected, sentinel);
    } finally {
      globalThis.wasm_bindgen = prevBindgen;
    }
  } finally {
    globalThis.fetch = prevFetch;
    peer.close();
    owner.close();
    for (const ch of channels) {
      try { ch.port1.close(); } catch {}
      try { ch.port2.close(); } catch {}
    }
  }
});

test('PR #73 P2-2, P2-3, P2-4, P2-6: LocalMount symlink .. walk, alias rename revalidation, distinct snapshots, O_RDONLY|O_TRUNC, EFBIG', async () => {
  installBrowserEnv();

  // P2-4: independent snapshots must get distinct st_dev.
  const snapWs = new Workspace({ id: 'snap-distinct', uid: 20, gid: 20, groups: [20] });
  try {
    await snapWs.mount({ name: 's1', files: [file('same.txt', 'one')], execute: false, cloud: false });
    await snapWs.mount({ name: 's2', files: [file('same.txt', 'one')], execute: false, cloud: false });
    const snapStat1 = await snapWs.stat('/mnt/local/s1/same.txt');
    const snapStat2 = await snapWs.stat('/mnt/local/s2/same.txt');
    assert.notEqual(snapStat1.dev, snapStat2.dev);
  } finally {
    snapWs.close();
  }

  // P2-2, P2-3, P2-6 on multi-alias OPFS mounts:
  const ownerA = new Workspace({ id: 'p2-ownerA', uid: 50, gid: 50, groups: [50] });
  const ownerB = new Workspace({ id: 'p2-ownerB', uid: 50, gid: 50, groups: [50] });
  try {
    await ownerA.mount({ name: 'opfs', storage: true, writable: true, execute: true, cloud: false });
    await ownerB.mount({ name: 'opfs', storage: true, writable: true, execute: true, cloud: false });

    await ownerA.calls([
      { chmod: { path: '/mnt/local/opfs', mode: 0o755 } },
      { mkdir: { path: '/mnt/local/opfs/nest', mode: 0o755 } },
      { chmod: { path: '/mnt/local/opfs/nest', mode: 0o755 } },
      { mkdir: { path: '/mnt/local/opfs/nest/deep', mode: 0o755 } },
      { chmod: { path: '/mnt/local/opfs/nest/deep', mode: 0o755 } },
      { mkdir: { path: '/mnt/local/opfs/nest/blocked', mode: 0o700 } },
      { chmod: { path: '/mnt/local/opfs/nest/blocked', mode: 0o700 } },
      { open: { path: '/mnt/local/opfs/target', flags: 0o302, mode: 0o644 } },
      { pwrite: { fd: { ref: 7 }, index: 0, data: btoa('ROOT') } },
      { close: { fd: { ref: 7 } } },
      { chmod: { path: '/mnt/local/opfs/target', mode: 0o644 } },
      { open: { path: '/mnt/local/opfs/nest/target', flags: 0o302, mode: 0o644 } },
      { pwrite: { fd: { ref: 11 }, index: 0, data: btoa('NEST') } },
      { close: { fd: { ref: 11 } } },
      { chmod: { path: '/mnt/local/opfs/nest/target', mode: 0o644 } },
      { symlink: { target: 'nest/deep', path: '/mnt/local/opfs/dirlink' } },
      { symlink: { target: 'dirlink/../target', path: '/mnt/local/opfs/indirect' } },
      { symlink: { target: 'dirlink/../made.txt', path: '/mnt/local/opfs/dangling' } },
      { symlink: { target: 'nest/blocked/../target', path: '/mnt/local/opfs/blocked_dot' } },
    ], ownerA.page, cloud);

    // P2-2: `indirect -> dirlink/../target` walks dirlink (`nest/deep`), then `..`, resolving `nest/target`!
    const symlinkOps = await ownerA.calls([
      { open: { path: '/mnt/local/opfs/indirect', flags: 2 } },
      { pread: { fd: { ref: 0 }, count: 16 } },
      { pwrite: { fd: { ref: 0 }, index: 0, data: btoa('UPDATED') } },
      { close: { fd: { ref: 0 } } },
      { open: { path: '/mnt/local/opfs/dangling', flags: 0o102, mode: 0o644 } },
      { pwrite: { fd: { ref: 4 }, index: 0, data: btoa('MADE') } },
      { close: { fd: { ref: 4 } } },
      { pread: { path: '/mnt/local/opfs/nest/target', count: 16 } },
      { pread: { path: '/mnt/local/opfs/nest/made.txt', count: 16 } },
      { pread: { path: '/mnt/local/opfs/target', count: 16 } },
    ], ownerA.page, cloud);
    assert.equal(atob(symlinkOps[1].ok.data), 'NEST');
    assert.equal(atob(symlinkOps[7].ok.data), 'UPDATED');
    assert.equal(atob(symlinkOps[8].ok.data), 'MADE');
    assert.equal(atob(symlinkOps[9].ok.data), 'ROOT');
    await assert.rejects(ownerA.stat('/mnt/local/opfs/made.txt'), { errno: 'ENOENT' });

    // Non-searchable blocked ancestor inside `nest/blocked/../target` fails EACCES for unprivileged identity,
    // while direct readable `nest/target` succeeds!
    const mA = ownerA.mounts.get('/mnt/local/opfs');
    const mPeerView = mA.provider.forIdentity({ id: 51, group: 51, groups: [51] }, '');
    const peerOkFd = await mPeerView.open(mA.grant, 'nest/target', 0);
    await mPeerView.release(mA.grant, peerOkFd);
    await assert.rejects(mPeerView.open(mA.grant, 'blocked_dot', 0), { errno: 'EACCES' });

    // P2-3: cross-alias rename while an exported descriptor is open must remain live inside boundary,
    // and become ESTALE once renamed outside boundary.
    await ownerA.calls([
      { mkdir: { path: '/mnt/local/opfs/sub', mode: 0o755 } },
      { chmod: { path: '/mnt/local/opfs/sub', mode: 0o755 } },
      { mkdir: { path: '/mnt/local/opfs/sub/subdir', mode: 0o755 } },
      { chmod: { path: '/mnt/local/opfs/sub/subdir', mode: 0o755 } },
      { mkdir: { path: '/mnt/local/opfs/sub/moved', mode: 0o755 } },
      { chmod: { path: '/mnt/local/opfs/sub/moved', mode: 0o755 } },
      { open: { path: '/mnt/local/opfs/sub/alias.txt', flags: 0o302, mode: 0o644 } },
      { pwrite: { fd: { ref: 6 }, index: 0, data: btoa('LIVE-ALIAS') } },
      { close: { fd: { ref: 6 } } },
      { chmod: { path: '/mnt/local/opfs/sub/alias.txt', mode: 0o644 } },
    ], ownerA.page, cloud);
    const subView = mA.provider.forIdentity({ id: 51, group: 51, groups: [51] }, 'sub');
    const openAliasFd = await subView.open(mA.grant, 'sub/alias.txt', 0);
    const openDirFd = await subView.open(mA.grant, 'sub/subdir', 0);

    // Alias ownerB moves BOTH inside `sub` without ownerA knowing:
    await ownerB.calls([
      { rename: { from: '/mnt/local/opfs/sub/alias.txt', to: '/mnt/local/opfs/sub/moved/alias2.txt' } },
      { rename: { from: '/mnt/local/opfs/sub/subdir', to: '/mnt/local/opfs/sub/subdir2' } },
    ], ownerB.page, cloud);
    const aliasBytes = await subView.read(mA.grant, openAliasFd, 0, 32);
    assert.equal(decoder.decode(aliasBytes), 'LIVE-ALIAS');
    const listedRenamedDir = await subView.list(mA.grant, openDirFd, {});
    assert.ok(Array.isArray(listedRenamedDir.entries));

    // Alias ownerB moves file OUTSIDE `sub` boundary -> ESTALE!
    await ownerB.calls([
      { rename: { from: '/mnt/local/opfs/sub/moved/alias2.txt', to: '/mnt/local/opfs/outside.txt' } },
    ], ownerB.page, cloud);
    await assert.rejects(subView.read(mA.grant, openAliasFd, 0, 32), { errno: 'ESTALE' });
    await subView.release(mA.grant, openAliasFd);
    await subView.release(mA.grant, openDirFd);

    // P2-3 + known_paths pruning on ownerA `unlink` when hardlink exists outside `sub`:
    await ownerA.calls([
      { open: { path: '/mnt/local/opfs/sub/linked.txt', flags: 0o302, mode: 0o644 } },
      { pwrite: { fd: { ref: 0 }, index: 0, data: btoa('LNK') } },
      { close: { fd: { ref: 0 } } },
      { chmod: { path: '/mnt/local/opfs/sub/linked.txt', mode: 0o644 } },
      { link: { from: '/mnt/local/opfs/sub/linked.txt', to: '/mnt/local/opfs/outside_keep.txt' } },
    ], ownerA.page, cloud);
    const openLinked = await subView.open(mA.grant, 'sub/linked.txt', 0);
    await ownerA.calls([{ unlink: { path: '/mnt/local/opfs/sub/linked.txt' } }], ownerA.page, cloud);
    await assert.rejects(subView.read(mA.grant, openLinked, 0, 16), { errno: 'ESTALE' });
    await subView.release(mA.grant, openLinked);

    // P2-6: O_RDONLY|O_TRUNC truncates regular file, EISDIR on directory, ENOENT on missing; RO ordering; invalid write offset & EFBIG!
    await ownerA.calls([
      { open: { path: '/mnt/local/opfs/truncme.txt', flags: 0o302, mode: 0o644 } },
      { pwrite: { fd: { ref: 0 }, index: 0, data: btoa('LONGDATA') } },
      { close: { fd: { ref: 0 } } },
    ], ownerA.page, cloud);
    const roTrunc = await mA.provider.open(mA.grant, 'truncme.txt', 0o1000, 0o644, 0o022); // O_RDONLY | O_TRUNC
    assert.equal((await mA.provider.stat(mA.grant, 'truncme.txt')).size, 0);
    await mA.provider.release(mA.grant, roTrunc);
    await assert.rejects(mA.provider.open(mA.grant, 'missing.txt', 0o1000, 0o644, 0o022), { errno: 'ENOENT' });
    await assert.rejects(mA.provider.open(mA.grant, 'nest', 0o1000, 0o644, 0o022), { errno: 'EISDIR' });

    // RO mount: missing O_WRONLY -> ENOENT, dir O_WRONLY / O_RDONLY|O_TRUNC -> EISDIR, file O_WRONLY / O_RDONLY|O_TRUNC -> EROFS.
    const roWs = new Workspace({ id: 'p2-ro', uid: 50, gid: 50, groups: [50] });
    try {
      await roWs.mount({ name: 'opfs', storage: true, writable: false, execute: true, cloud: false });
      const mRo = roWs.mounts.get('/mnt/local/opfs');
      await assert.rejects(mRo.provider.open(mRo.grant, 'missing.txt', 1, 0o644, 0o022), { errno: 'ENOENT' });
      await assert.rejects(mRo.provider.open(mRo.grant, 'nest', 1, 0o644, 0o022), { errno: 'EISDIR' });
      await assert.rejects(mRo.provider.open(mRo.grant, 'nest', 0o1000, 0o644, 0o022), { errno: 'EISDIR' });
      await assert.rejects(mRo.provider.open(mRo.grant, 'target', 1, 0o644, 0o022), { errno: 'EROFS' });
      await assert.rejects(mRo.provider.open(mRo.grant, 'target', 0o1000, 0o644, 0o022), { errno: 'EROFS' });
    } finally {
      roWs.close();
    }

    // Invalid write offset -> EINVAL; > JS_SAFE -> EFBIG in hostfs.
    await assert.rejects(mA.provider.write(mA.grant, 'target', new Uint8Array([1]), { offset: -1 }), { errno: 'EINVAL' });
    await assert.rejects(mA.provider.write(mA.grant, 'target', new Uint8Array([1]), { offset: 1.5 }), { errno: 'EINVAL' });
    await assert.rejects(mA.provider.write(mA.grant, 'target', new Uint8Array([1]), { offset: 2 ** 54 }), { errno: 'EFBIG' });
    const fTruncHandle = await mA.provider.open(mA.grant, 'target', 2, 0o644, 0o022);
    await assert.rejects(mA.provider.ftruncate(mA.grant, fTruncHandle, 2 ** 54), { errno: 'EFBIG' });
    await mA.provider.release(mA.grant, fTruncHandle);

    // P2-6: LocalMount::pin preserves remote: self.remote for boundary revalidation.
    const wasmMagic = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]);
    await ownerA.calls([
      { open: { path: '/mnt/local/opfs/sub/bin.wasm', flags: 0o302, mode: 0o755 } },
      { pwrite: { fd: { ref: 0 }, index: 0, data: encodeB64Bytes(wasmMagic) } },
      { close: { fd: { ref: 0 } } },
      { chmod: { path: '/mnt/local/opfs/sub/bin.wasm', mode: 0o755 } },
    ], ownerA.page, cloud);
    const pinnedRemote = await subView.pin(mA.grant, 'sub/bin.wasm');
    assert.equal((await localImage(pinnedRemote)).bytes.length, 8);
    await ownerA.calls([{ chmod: { path: '/mnt/local/opfs/sub/bin.wasm', mode: 0o600 } }], ownerA.page, cloud);
    await assert.rejects(localImage(pinnedRemote), { errno: 'ESTALE' });
  } finally {
    ownerA.close();
    ownerB.close();
  }
});

test('PR #73 P1-5: WASI process.js openPath rejects O_RDONLY|O_TRUNC on directories with EISDIR and passes atomic O_NOFOLLOW to localFs', async () => {
  let binaryen = null;
  try { binaryen = (await import('binaryen')).default; } catch {}
  const { Worker } = await import('node:worker_threads');
  installBrowserEnv();

  function buildProbeWasm(kind) {
    const uleb = n => { const o = []; do { let b = n & 0x7f; n >>>= 7; if (n) b |= 0x80; o.push(b); } while (n); return o; };
    const sleb = n => { const o = []; let more = true; while (more) { let b = n & 0x7f; n >>= 7; if ((n === 0 && !(b & 0x40)) || (n === -1 && (b & 0x40))) more = false; else b |= 0x80; o.push(b); } return o; };
    const wstr = s => { const b = encoder.encode(s); return [...uleb(b.length), ...b]; };
    const sec = (id, body) => [id, ...uleb(body.length), ...body];
    const i32c = v => [0x41, ...sleb(v)];
    const i64c = v => [0x42, ...sleb(v)];
    const callOpen = (dirflags, ptr, len, oflags, openIdx = 0) => [
      ...i32c(3), ...i32c(dirflags), ...i32c(ptr), ...i32c(len), ...i32c(oflags),
      ...i64c(2), ...i64c(2), ...i32c(0), ...i32c(500), 0x10, ...uleb(openIdx),
    ];
    const checkRc = (expect, base, exitIdx) => [
      0x21, 0x00, 0x20, 0x00, ...i32c(expect), 0x47,
      0x04, 0x40, ...i32c(base), 0x20, 0x00, 0x6a, 0x10, ...uleb(exitIdx), 0x0b,
    ];
    if (kind === 'local') {
      const types = [3,
        0x60, 9, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7e, 0x7e, 0x7f, 0x7f, 1, 0x7f,
        0x60, 1, 0x7f, 0,
        0x60, 0, 0,
      ];
      const imports = [2,
        ...wstr('wasi_snapshot_preview1'), ...wstr('path_open'), 0x00, 0x00,
        ...wstr('wasi_snapshot_preview1'), ...wstr('proc_exit'), 0x00, 0x01,
      ];
      const funcs = [1, 0x02];
      const mems = [1, 0x00, 0x01];
      const exports = [2, ...wstr('memory'), 0x02, 0x00, ...wstr('_start'), 0x00, 0x02];
      const body = [
        1, 1, 0x7f,
        ...callOpen(0, 100, 18, 8, 0), ...checkRc(31, 100, 1),
        ...callOpen(0, 140, 18, 0, 0), ...checkRc(32, 200, 1),
        ...i32c(0), 0x10, 0x01, 0x0b,
      ];
      const code = [1, ...uleb(body.length), ...body];
      const d1 = encoder.encode('mnt/local/proj/dir'), d2 = encoder.encode('mnt/local/proj/sym');
      const data = [2,
        0x00, ...i32c(100), 0x0b, ...uleb(d1.length), ...d1,
        0x00, ...i32c(140), 0x0b, ...uleb(d2.length), ...d2,
      ];
      return new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
        ...sec(1, types), ...sec(2, imports), ...sec(3, funcs), ...sec(5, mems),
        ...sec(7, exports), ...sec(10, code), ...sec(11, data)]);
    }
    const types = [4,
      0x60, 9, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7e, 0x7e, 0x7f, 0x7f, 1, 0x7f,
      0x60, 1, 0x7f, 1, 0x7f,
      0x60, 1, 0x7f, 0,
      0x60, 0, 0,
    ];
    const imports = [3,
      ...wstr('wasi_snapshot_preview1'), ...wstr('path_open'), 0x00, 0x00,
      ...wstr('wasi_snapshot_preview1'), ...wstr('fd_close'), 0x00, 0x01,
      ...wstr('wasi_snapshot_preview1'), ...wstr('proc_exit'), 0x00, 0x02,
    ];
    const funcs = [1, 0x03];
    const mems = [1, 0x00, 0x01];
    const exports = [2, ...wstr('memory'), 0x02, 0x00, ...wstr('_start'), 0x00, 0x03];
    const body = [
      1, 1, 0x7f,
      ...callOpen(0, 180, 9, 8, 0), ...checkRc(31, 300, 2),
      ...callOpen(1, 180, 9, 0, 0), ...checkRc(0, 400, 2),
      ...i32c(500), 0x28, 0x02, 0x00, 0x10, 0x01, 0x1a,
      ...i32c(0), 0x10, 0x02, 0x0b,
    ];
    const code = [1, ...uleb(body.length), ...body];
    const d1 = encoder.encode('cloud-dir');
    const data = [1, 0x00, ...i32c(180), 0x0b, ...uleb(d1.length), ...d1];
    return new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
      ...sec(1, types), ...sec(2, imports), ...sec(3, funcs), ...sec(5, mems),
      ...sec(7, exports), ...sec(10, code), ...sec(11, data)]);
  }

  const ws = new Workspace({ id: 'wasi-p15', uid: 20, gid: 20, groups: [20] });
  await ws.mount({ name: 'proj', storage: true, writable: true, execute: false, cloud: false });
  await ws.calls([
    { mkdir: { path: '/mnt/local/proj/dir', mode: 0o755 } },
    { open: { path: '/mnt/local/proj/target', flags: 0o302, mode: 0o644 } },
    { close: { fd: { ref: 1 } } },
    { symlink: { target: 'target', path: '/mnt/local/proj/sym' } },
  ], ws.page, cloud);

  // Worker 1 (localFs + channel): tests (1) local dir + OFLAG_TRUNC -> EISDIR(31) with atomic O_NOFOLLOW|O_TRUNC,
  // (2) local sym + !FOLLOW -> ELOOP(32).
  const localWat = `(module
    (import "wasi_snapshot_preview1" "path_open" (func $open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
    (memory (export "memory") 1)
    (data (i32.const 100) "mnt/local/proj/dir")
    (data (i32.const 140) "mnt/local/proj/sym")
    (func (export "_start")
      (local $rc i32)
      ;; 1. localFs dir + OFLAG_TRUNC (8), dirflags=0 (!FOLLOW), RIGHT_READ(2) -> expect 31 (EISDIR)
      (local.set $rc (call $open (i32.const 3) (i32.const 0) (i32.const 100) (i32.const 18) (i32.const 8) (i64.const 2) (i64.const 2) (i32.const 0) (i32.const 500)))
      (if (i32.ne (local.get $rc) (i32.const 31)) (then (call $exit (i32.add (i32.const 100) (local.get $rc)))))
      ;; 2. localFs sym, dirflags=0 (!FOLLOW), RIGHT_READ(2) -> expect 32 (ELOOP)
      (local.set $rc (call $open (i32.const 3) (i32.const 0) (i32.const 140) (i32.const 18) (i32.const 0) (i64.const 2) (i64.const 2) (i32.const 0) (i32.const 500)))
      (if (i32.ne (local.get $rc) (i32.const 32)) (then (call $exit (i32.add (i32.const 200) (local.get $rc)))))
      (call $exit (i32.const 0))))`;

  // Worker 2 (no channel, openRead fallback): tests (1) dir + OFLAG_TRUNC -> EISDIR(31) + O_NOFOLLOW|O_TRUNC sent,
  // (2) dir without OFLAG_TRUNC -> 0.
  const fallbackWat = `(module
    (import "wasi_snapshot_preview1" "path_open" (func $open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_close" (func $close (param i32) (result i32)))
    (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
    (memory (export "memory") 1)
    (data (i32.const 180) "cloud-dir")
    (func (export "_start")
      (local $rc i32)
      ;; 1. openRead fallback dir + OFLAG_TRUNC (8), dirflags=0 (!FOLLOW), RIGHT_READ(2) -> expect 31 (EISDIR)
      (local.set $rc (call $open (i32.const 3) (i32.const 0) (i32.const 180) (i32.const 9) (i32.const 8) (i64.const 2) (i64.const 2) (i32.const 0) (i32.const 500)))
      (if (i32.ne (local.get $rc) (i32.const 31)) (then (call $exit (i32.add (i32.const 300) (local.get $rc)))))
      ;; 2. openRead fallback dir without OFLAG_TRUNC, dirflags=1 (FOLLOW), RIGHT_READ(2) -> expect 0
      (local.set $rc (call $open (i32.const 3) (i32.const 1) (i32.const 180) (i32.const 9) (i32.const 0) (i64.const 2) (i64.const 2) (i32.const 0) (i32.const 500)))
      (if (i32.ne (local.get $rc) (i32.const 0)) (then (call $exit (i32.add (i32.const 400) (local.get $rc)))))
      (drop (call $close (i32.load (i32.const 500))))
      (call $exit (i32.const 0))))`;

  const processUrl = new URL('../web/wasi/process.js', import.meta.url).href;
  const workerCode = `
    import { parentPort, workerData } from 'node:worker_threads';
    const pending = [];
    let handler = null;
    Object.defineProperty(globalThis, 'onmessage', {
      configurable: true,
      get() { return handler; },
      set(fn) {
        handler = fn;
        while (pending.length && handler) handler(pending.shift());
      },
    });
    globalThis.postMessage = (msg, _transfer) => parentPort.postMessage(msg);
    globalThis.fetch = async (url, init) => {
      if (url === '/api/sys') {
        const body = JSON.parse(init.body);
        for (const c of body.calls) {
          if (c.open) parentPort.postMessage({ observedSysOpen: c.open });
        }
        const results = body.calls.map(c => {
          if (c.stat || c.lstat) return { ok: { mode: 0o040755, nlink: 2, size: 0, ino: 77 } };
          if (c.open) return { err: { errno: 'EISDIR', detail: 'is a directory' } };
          return { ok: null };
        });
        return new Response(JSON.stringify({ results }), { status: 200 });
      }
      return new Response('{}', { status: 404 });
    };
    parentPort.on('message', data => {
      const ev = { data };
      if (handler) handler(ev);
      else pending.push(ev);
    });
    await import(workerData.processUrl);
  `;

  async function runWasiCase(wat, { localFs, useChannel, kind }) {
    const modBytes = binaryen ? binaryen.parseText(wat).emitBinary() : buildProbeWasm(kind);
    const channelBuf = useChannel ? new SharedArrayBuffer(1 << 20) : null;
    const opens = [];
    const worker = new Worker(workerCode, { eval: true, workerData: { processUrl } });
    try {
      const module = await WebAssembly.compile(modBytes);
      const channelState = channelBuf ? new Int32Array(channelBuf, 0, 2) : null;
      const channelData = channelBuf ? new Uint8Array(channelBuf, 8) : null;
      const exitResult = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          reject(new Error(`worker timed out; opens=${JSON.stringify(opens)}`));
        }, 5000);
        const finish = fn => val => { clearTimeout(timer); fn(val); };
        worker.on('error', finish(reject));
        worker.on('exit', code => finish(reject)(new Error(`worker exited unexpectedly with code ${code}`)));
        worker.on('message', async msg => {
          if (msg?.observedSysOpen) {
            opens.push(msg.observedSysOpen);
            return;
          }
          if (msg?.host?.type === 'vfs') {
            const { op, ...vargs } = msg.host.args;
            if (op === 'openat') {
              opens.push({ path: vargs.path, flags: vargs.oflags, dirfd: vargs.dirfd });
            }
            let reply;
            try {
              await ws._ready;
              if (op === 'openat') {
                reply = await ws.kernel.proc_openat(ws.page, vargs.dirfd, vargs.path, vargs.oflags ?? 0, vargs.mode ?? 0, !!vargs.cloexec);
              } else if (op === 'close') {
                await ws.kernel.kfd_close(ws.page, vargs.kfd);
                reply = {};
              } else if (op === 'fstat') {
                reply = await ws.kernel.kfd_fstat(ws.page, vargs.kfd);
              } else {
                reply = {};
              }
            } catch (err) {
              reply = { errno: err.errno ?? 'EIO' };
            }
            const bytes = encoder.encode(JSON.stringify(reply));
            channelData.set(bytes, 0);
            Atomics.store(channelState, 1, bytes.length);
            Atomics.store(channelState, 0, 1);
            Atomics.notify(channelState, 0);
          } else if (msg?.host) {
            const bytes = encoder.encode('{}');
            channelData.set(bytes, 0);
            Atomics.store(channelState, 1, bytes.length);
            Atomics.store(channelState, 0, 1);
            Atomics.notify(channelState, 0);
          } else if (msg?.exit !== undefined) {
            finish(resolve)(msg);
          }
        });
        worker.postMessage({
          module,
          argv: ['probe'],
          env: [],
          cwd: '/',
          pid: 1,
          ppid: 0,
          umask: 0o022,
          sudo: false,
          localFs,
          channel: channelBuf,
        });
      });
      return { exitResult, opens };
    } finally {
      await worker.terminate();
    }
  }

  try {
    const adminPid = ws.scope();
    await ws.kernel.proc_spawn_init(JSON.stringify({ pid: adminPid, ppid: 1, sessionId: ws.id, uid: 0, gid: 0, groups: [0], umask: 0o022, cwd: '/' }));
    await ws.kernel.proc_mkdirat(adminPid, OS_FD_ROOT, '/cloud-dir', 0o755);
    await ws.kernel.proc_exit(adminPid);
    const localRes = await runWasiCase(localWat, { localFs: true, useChannel: true, kind: 'local' });
    assert.equal(localRes.exitResult.exit, 0, `unexpected local WASI exit code ${localRes.exitResult.exit}`);
    const dirOpen = localRes.opens.find(o => o.path === 'mnt/local/proj/dir' || o.path === '/mnt/local/proj/dir');
    assert.ok(dirOpen, 'expected VFS open on mnt/local/proj/dir');
    assert.notEqual(dirOpen.flags & 0o400000, 0, 'O_NOFOLLOW must be passed to proc_openat');
    assert.notEqual(dirOpen.flags & 0o1000, 0, 'O_TRUNC must be passed to proc_openat');

    const fallbackRes = await runWasiCase(fallbackWat, { localFs: false, useChannel: true, kind: 'fallback' });
    assert.equal(fallbackRes.exitResult.exit, 0, `unexpected cloud-dir WASI exit code ${fallbackRes.exitResult.exit}`);
    const truncSysOpen = fallbackRes.opens.find(o => (o.path === 'cloud-dir' || o.path === '/cloud-dir') && (o.flags & 0o1000));
    assert.ok(truncSysOpen, 'expected proc_openat with O_TRUNC on cloud-dir');
    assert.notEqual(truncSysOpen.flags & 0o400000, 0, 'O_NOFOLLOW must be passed when !FOLLOW');
  } finally {
    ws.close();
  }
});

test('PR #74 Track C: WASI process.js kfd FDFLAG_NONBLOCK, /proc/self/fd translation & ELOOP, raw descriptor mapping, posix_spawn serviceGrant validation', async () => {
  const { Worker } = await import('node:worker_threads');
  installBrowserEnv();

  const uleb = n => { const o = []; do { let b = n & 0x7f; n >>>= 7; if (n) b |= 0x80; o.push(b); } while (n); return o; };
  const sleb = n => { const o = []; let more = true; while (more) { let b = n & 0x7f; n >>= 7; if ((n === 0 && !(b & 0x40)) || (n === -1 && (b & 0x40))) more = false; else b |= 0x80; o.push(b); } return o; };
  const wstr = s => { const b = encoder.encode(s); return [...uleb(b.length), ...b]; };
  const sec = (id, body) => [id, ...uleb(body.length), ...body];
  const i32c = v => [0x41, ...sleb(v)];
  const i64c = v => [0x42, ...sleb(v)];

  const sTarget = 'mnt/local/proj/target';
  const sSubdir = 'mnt/local/proj/subdir';
  const sSelfFd4 = '/proc/self/fd/4';
  const sInfo4 = '/proc/self/fdinfo/4';
  const sSelfFd5 = '/proc/self/fd/5';
  const sSelfFd99 = '/proc/self/fd/99';
  const sSysBatch = JSON.stringify([
    { open: { path: '/mnt/local/proj/target', flags: 0 } },
    { close: { fd: { ref: 0 } } },
    { open: { path: sSelfFd4, flags: 0 } },
    { pread: { fd: { ref: 2 }, offset: 0, count: 11 } },
    { close: { fd: { ref: 2 } } },
    { chmod: { path: sSelfFd4, mode: 0o640 } },
    { ioctl: { fd: 4, request: 0x54570101, arg: { operation: {
      operation: 'extract', source: { directory: 5 }, destination: { directory: 5 },
    } } } },
  ]);
  const sBadGrant = JSON.stringify({
    argv: ['/usr/bin/true'],
    env: [],
    cwd: '/',
    stdin: 'null',
    serviceGrant: { mountNamespace: 42 },
  });

  // Type indices:
  // 0: path_open (9 i32/i64 -> i32)
  // 1: (i32, i32) -> i32  [fd_fdstat_set_flags, fd_fdstat_get, os.sys]
  // 2: (i32, i32, i32, i32, i32, i32) -> i32 [path_readlink]
  // 3: (i32, i32, i32, i32, i32) -> i32 [path_filestat_get]
  // 4: (i32) -> i32 [fd_close]
  // 5: (i32, i32, i32) -> i32 [os.posix_spawn]
  // 6: (i32) -> void [proc_exit]
  // 7: () -> void [_start]
  const types = [8,
    0x60, 9, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7e, 0x7e, 0x7f, 0x7f, 1, 0x7f,
    0x60, 2, 0x7f, 0x7f, 1, 0x7f,
    0x60, 6, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f,
    0x60, 5, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f,
    0x60, 1, 0x7f, 1, 0x7f,
    0x60, 3, 0x7f, 0x7f, 0x7f, 1, 0x7f,
    0x60, 1, 0x7f, 0,
    0x60, 0, 0,
  ];
  const imports = [9,
    ...wstr('wasi_snapshot_preview1'), ...wstr('path_open'), 0x00, 0x00,
    ...wstr('wasi_snapshot_preview1'), ...wstr('fd_fdstat_set_flags'), 0x00, 0x01,
    ...wstr('wasi_snapshot_preview1'), ...wstr('fd_fdstat_get'), 0x00, 0x01,
    ...wstr('wasi_snapshot_preview1'), ...wstr('path_readlink'), 0x00, 0x02,
    ...wstr('wasi_snapshot_preview1'), ...wstr('path_filestat_get'), 0x00, 0x03,
    ...wstr('wasi_snapshot_preview1'), ...wstr('fd_close'), 0x00, 0x04,
    ...wstr('os'), ...wstr('sys'), 0x00, 0x01,
    ...wstr('os'), ...wstr('posix_spawn'), 0x00, 0x05,
    ...wstr('wasi_snapshot_preview1'), ...wstr('proc_exit'), 0x00, 0x06,
  ];
  const bailIfNe = (expect, code) => [
    0x21, 0x00, 0x20, 0x00, ...i32c(expect), 0x47,
    0x04, 0x40, ...i32c(code), 0x20, 0x00, 0x6a, 0x10, 0x08, 0x0b,
  ];
  const body = [
    1, 3, 0x7f, // local $rc (0), local $fd (1), local $dfd (2)
    // 1. open mnt/local/proj/target -> guest fd 4 at out=500; mnt/local/proj/subdir -> guest fd 5 at out=504
    ...i32c(3), ...i32c(1), ...i32c(100), ...i32c(sTarget.length), ...i32c(0), ...i64c(2), ...i64c(2), ...i32c(0), ...i32c(500), 0x10, 0x00,
    ...bailIfNe(0, 100),
    ...i32c(500), 0x28, 0x02, 0x00, 0x21, 0x01, // $fd = i32[500]
    ...i32c(4), 0x20, 0x01, 0x47, 0x04, 0x40, ...i32c(91), 0x10, 0x08, 0x0b, // expect guest $fd == 4 (while Rust kfd == 0)
    ...i32c(3), ...i32c(1), ...i32c(600), ...i32c(sSubdir.length), ...i32c(2), ...i64c(2), ...i64c(2), ...i32c(0), ...i32c(504), 0x10, 0x00,
    ...bailIfNe(0, 105),
    ...i32c(504), 0x28, 0x02, 0x00, 0x21, 0x02, // $dfd = i32[504] (guest fd 5, Rust kfd 1)
    ...i32c(5), 0x20, 0x02, 0x47, 0x04, 0x40, ...i32c(95), 0x10, 0x08, 0x0b,
    // 2. fd_fdstat_set_flags($fd, FDFLAG_NONBLOCK=4) & fd_fdstat_get($fd, 512)
    0x20, 0x01, ...i32c(4), 0x10, 0x01, ...bailIfNe(0, 110),
    0x20, 0x01, ...i32c(512), 0x10, 0x02, ...bailIfNe(0, 120),
    ...i32c(512), 0x2f, 0x01, 0x02, ...i32c(4), 0x71, ...i32c(4), 0x47,
    0x04, 0x40, ...i32c(92), 0x10, 0x08, 0x0b,
    // 3. open(/proc/self/fd/4, !FOLLOW) -> ELOOP(32); open(/proc/self/fd/99, !FOLLOW) -> ENOENT(44)
    ...i32c(3), ...i32c(0), ...i32c(140), ...i32c(sSelfFd4.length), ...i32c(0), ...i64c(2), ...i64c(2), ...i32c(0), ...i32c(540), 0x10, 0x00,
    ...bailIfNe(32, 200),
    ...i32c(3), ...i32c(0), ...i32c(180), ...i32c(sSelfFd99.length), ...i32c(0), ...i64c(2), ...i64c(2), ...i32c(0), ...i32c(540), 0x10, 0x00,
    ...bailIfNe(44, 210),
    // 4. path_readlink(3, /proc/self/fd/5, 700, 128, 560) & path_filestat_get(3, FOLLOW=1, /proc/self/fd/4, 768)
    ...i32c(3), ...i32c(640), ...i32c(sSelfFd5.length), ...i32c(700), ...i32c(128), ...i32c(560), 0x10, 0x03,
    ...bailIfNe(0, 220),
    ...i32c(560), 0x28, 0x02, 0x00, ...i32c(sSubdir.length + 1), 0x47,
    0x04, 0x40, ...i32c(93), 0x10, 0x08, 0x0b,
    ...i32c(3), ...i32c(1), ...i32c(140), ...i32c(sSelfFd4.length), ...i32c(768), 0x10, 0x04,
    ...bailIfNe(0, 230),
    ...i32c(768), 0x29, 0x03, 0x20, 0x42, 0x0b, 0x52, // fstat.size == 11 ("target-data")
    0x04, 0x40, ...i32c(94), 0x10, 0x08, 0x0b,
    ...i32c(3), ...i32c(1), ...i32c(1000), ...i32c(sInfo4.length), ...i32c(768), 0x10, 0x04,
    ...bailIfNe(0, 235),
    // 5. Raw opens, batch references and proc-fd reopens share the guest fd table.
    ...i32c(1300), ...i32c(sSysBatch.length), 0x10, 0x06, 0x1a,
    0x20, 0x01, ...i32c(512), 0x10, 0x02, ...bailIfNe(0, 240),
    0x20, 0x01, 0x10, 0x05, ...bailIfNe(0, 250),
    0x20, 0x02, 0x10, 0x05, ...bailIfNe(0, 255),
    // 6. os.posix_spawn validates invalid serviceGrant -> EINVAL(28)
    ...i32c(400), ...i32c(sBadGrant.length), ...i32c(580), 0x10, 0x07,
    ...bailIfNe(28, 260),
    ...i32c(0), 0x10, 0x08, 0x0b,
  ];
  const dSegs = [
    [100, sTarget],
    [140, sSelfFd4],
    [1000, sInfo4],
    [180, sSelfFd99],
    [1300, sSysBatch],
    [400, sBadGrant],
    [600, sSubdir],
    [640, sSelfFd5],
  ];
  const dataSec = [dSegs.length, ...dSegs.flatMap(([off, str]) => {
    const b = encoder.encode(str);
    return [0x00, ...i32c(off), 0x0b, ...uleb(b.length), ...b];
  })];
  const wasmBytes = new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    ...sec(1, types), ...sec(2, imports),
    ...sec(3, [1, 0x07]), ...sec(5, [1, 0x00, 0x01]),
    ...sec(7, [2, ...wstr('memory'), 0x02, 0x00, ...wstr('_start'), 0x00, 0x09]),
    ...sec(10, [1, ...uleb(body.length), ...body]),
    ...sec(11, dataSec),
  ]);

  const ws = new Workspace({ id: 'wasi-track-c', uid: 20, gid: 20, groups: [20] });
  await ws.mount({ name: 'proj', storage: true, writable: true, execute: false, cloud: false });
  await ws.calls([
    { mkdir: { path: '/mnt/local/proj/subdir', mode: 0o755 } },
    { open: { path: '/mnt/local/proj/target', flags: 0o1102, mode: 0o644 } },
    { pwrite: { fd: { ref: 1 }, index: 0, data: btoa('target-data') } },
    { close: { fd: { ref: 1 } } },
  ], ws.page, cloud);

  const processUrl = new URL('../web/wasi/process.js', import.meta.url).href;
  const workerCode = `
    import { parentPort, workerData } from 'node:worker_threads';
    const pending = [];
    let handler = null;
    Object.defineProperty(globalThis, 'onmessage', {
      configurable: true,
      get() { return handler; },
      set(fn) {
        handler = fn;
        while (pending.length && handler) handler(pending.shift());
      },
    });
    globalThis.postMessage = msg => parentPort.postMessage(msg);
    parentPort.on('message', data => {
      const ev = { data };
      if (handler) handler(ev);
      else pending.push(ev);
    });
    await import(workerData.processUrl);
  `;

  const module = await WebAssembly.compile(wasmBytes);
  const channelBuf = new SharedArrayBuffer(1 << 20);
  const channelState = new Int32Array(channelBuf, 0, 2);
  const channelData = new Uint8Array(channelBuf, 8);
  const worker = new Worker(workerCode, { eval: true, workerData: { processUrl } });
  let rawRead, archiveDirectories;
  try {
    const exitResult = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('worker timed out')), 5000);
      const finish = fn => val => { clearTimeout(timer); fn(val); };
      worker.on('error', finish(reject));
      worker.on('exit', code => finish(reject)(new Error(`worker exited unexpectedly with code ${code}`)));
      worker.on('message', async msg => {
        if (msg?.host?.type === 'vfs') {
          const { op, ...vargs } = msg.host.args;
          let reply;
          try {
            await ws._ready;
            if (op === 'openat') reply = await ws.kernel.proc_openat(ws.page, vargs.dirfd, vargs.path, vargs.oflags ?? 0, vargs.mode ?? 0, !!vargs.cloexec);
            else if (op === 'close') { await ws.kernel.kfd_close(ws.page, vargs.kfd); reply = {}; }
            else if (op === 'fstat') reply = await ws.kernel.kfd_fstat(ws.page, vargs.kfd);
            else if (op === 'statat') reply = await ws.kernel.proc_statat(ws.page, vargs.dirfd, vargs.path, vargs.follow !== false);
            else if (op === 'statfs') reply = await ws.kernel.sys_statfs(ws.page, vargs.dirfd, vargs.path);
            else if (op === 'readlinkat') reply = { target: await ws.kernel.proc_readlinkat(ws.page, vargs.dirfd, vargs.path) };
            else if (op === 'set_append') { ws.kernel.kfd_set_append(ws.page, vargs.kfd, !!vargs.append); reply = {}; }
            else if (op === 'is_append') reply = { append: ws.kernel.kfd_is_append(ws.page, vargs.kfd) };
            else if (op === 'sys') {
              const ioctl = vargs.batch.calls[0]?.ioctl;
              if (ioctl?.request === 0x54570101) {
                archiveDirectories = [ioctl.arg.operation.source.directory, ioctl.arg.operation.destination.directory];
              }
              reply = JSON.parse(await ws.kernel.proc_sys(ws.page, JSON.stringify(vargs.batch)));
              if (vargs.batch.calls[0]?.pread) rawRead = reply.results[0];
            }
            else reply = {};
          } catch (err) {
            reply = { errno: err.errno ?? 'EIO' };
          }
          const bytes = encoder.encode(JSON.stringify(reply));
          channelData.set(bytes, 0);
          Atomics.store(channelState, 1, bytes.length);
          Atomics.store(channelState, 0, 1);
          Atomics.notify(channelState, 0);
        } else if (msg?.exit !== undefined) {
          finish(resolve)(msg);
        }
      });
      worker.postMessage({
        module,
        argv: ['probe-track-c'],
        env: [],
        cwd: '/',
        pid: ws.page,
        ppid: 1,
        umask: 0o022,
        sudo: false,
        channel: channelBuf,
      });
    });
    assert.equal(rawRead?.ok?.data, btoa('target-data'), JSON.stringify(rawRead));
    assert.deepEqual(archiveDirectories, [1, 1]);
    assert.equal((await ws.kernel.proc_statat(ws.page, OS_FD_ROOT, '/mnt/local/proj/target', true)).mode & 0o777, 0o640);
    assert.equal(exitResult.exit, 0, `unexpected exit code ${exitResult.exit}`);
  } finally {
    await worker.terminate();
    ws.close();
  }
});

test('PR #74 Track C: local-files.js routes groupmod to network, streams GET /api/file with abort close, and passes 8 MiB chunkIndex on PUT /api/pwrite', async () => {
  const prevLocation = globalThis.location;
  const prevFetch = globalThis.fetch;
  const prevWorker = globalThis.Worker;
  const networkCalls = [];
  const kernelCalls = [];
  let streamClosed = false, finishOpen;
  let readCalls = 0;

  globalThis.location = { origin: 'https://os.example', href: 'https://os.example/' };
  globalThis.fetch = async (input, init) => {
    const req = new Request(input, init);
    networkCalls.push(new URL(req.url).pathname);
    return new Response(JSON.stringify({ results: [{ ok: null }] }), { status: 200 });
  };
  globalThis.Worker = class MockKernelWorker {
    postMessage(msg) {
      queueMicrotask(() => {
        kernelCalls.push({ type: msg.type, args: msg.args });
        let okVal = null;
        if (msg.type === 'mount_vfs_pwrite') okVal = msg.args.data.length;
        else if (msg.type === 'mount_vfs_open_read') {
          if (msg.args.path === '/pending') {
            finishOpen = () => this.onmessage({ data: { v: msg.v, id: msg.id, ok: { status: 200, totalSize: 600000, streamId: 78 } } });
            return;
          }
          readCalls = 0;
          okVal = { status: 200, totalSize: 600000, contentType: 'application/octet-stream', streamId: 77 };
        } else if (msg.type === 'mount_vfs_read_chunk') {
          readCalls++;
          okVal = readCalls === 1 ? new Uint8Array([1, 2, 3, 4]) : new Uint8Array(0);
        } else if (msg.type === 'mount_vfs_close_read') {
          streamClosed = true;
          okVal = null;
        }
        this.onmessage?.({ data: { v: msg.v, id: msg.id, ok: okVal } });
      });
    }
  };

  try {
    const { installLocalFiles } = await import('../web/local-files.js');
    installLocalFiles();

    // 1. groupmod must hit network, NOT mount_vfs_sys
    const gRes = await globalThis.fetch('https://os.example/api/sys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ calls: [{ groupmod: { name: 'devs' } }] }),
    });
    assert.equal(gRes.status, 200);
    assert.deepEqual(networkCalls, ['/api/sys']);
    assert.equal(kernelCalls.some(c => c.type === 'mount_vfs_sys'), false);

    // 2. PUT /api/pwrite accepts >256 KiB chunks (up to 8 MiB) and passes chunkIndex
    const big = new Uint8Array(300 * 1024);
    const pRes = await globalThis.fetch(`https://os.example/api/pwrite?fd=${LOCAL_FD}&index=3`, {
      method: 'PUT',
      body: big,
    });
    assert.equal(pRes.status, 200);
    assert.deepEqual(await pRes.json(), { written: 300 * 1024 });
    const pwCall = kernelCalls.find(c => c.type === 'mount_vfs_pwrite');
    assert.equal(pwCall.args.chunkIndex, 3);
    assert.equal(pwCall.args.fd, LOCAL_FD);

    // 3. Streamed GET /api/file reads chunks via streamId and cancelling closes stream
    const ac = new AbortController();
    const fRes = await globalThis.fetch('https://os.example/api/file?path=%2Fmnt%2Flocal%2Fproj%2Fbig.bin', {
      signal: ac.signal,
    });
    assert.equal(fRes.status, 200);
    const reader = fRes.body.getReader();
    const first = await reader.read();
    assert.deepEqual(Array.from(first.value), [1, 2, 3, 4]);
    ac.abort();
    await reader.cancel().catch(() => {});
    await new Promise(r => setTimeout(r, 20));
    assert.equal(streamClosed, true);

    const abortOpen = new AbortController();
    const pending = globalThis.fetch('https://os.example/api/file?path=/pending', { signal: abortOpen.signal });
    await new Promise(resolve => setImmediate(resolve));
    assert.ok(finishOpen);
    abortOpen.abort();
    await assert.rejects(pending, { name: 'AbortError' });
    finishOpen();
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(kernelCalls.filter(c => c.type === 'mount_vfs_close_read' && c.args.streamId === 78).length, 1);
  } finally {
    globalThis.location = prevLocation;
    globalThis.fetch = prevFetch;
    globalThis.Worker = prevWorker;
  }
});

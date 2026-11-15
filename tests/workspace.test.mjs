import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { accessSync, constants as fsConstants, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { Workspace, localPath, localFdPath, LOCAL_FD } from '../web/kernel/workspace.js';
import { currentWorkspace, mountRequest, endWorkspace } from '../web/kernel/workspaces.js';
import { localImage } from '../web/kernel/local-mounts.js';
import { NativeMount } from '../web/kernel/native-mount.js';
import { exportMount, attachMount } from '../web/kernel/mount-sharing.js';

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

const create = async () => {
  const space = new Workspace({ id: 'test-session', uid: 12 });
  await space.mount({ name: 'project', files: [file('text', 'abc')], execute: false, cloud: false });
  return space;
};

// ============================================================================
// 1. Existing Workspace Contract Tests (updated off legacy PermissionMount)
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
  await assert.rejects(space.stat('/mnt/local/project/note'), { errno: 'ENODEV' });
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
  let joined = false, refreshes = 0, shutdown = false;
  try {
    globalThis.kernelRequest = async type => {
      if (type === 'login_refresh') { joined = true; refreshes++; return; }
      if (type === 'workspace_credentials') return { uid: 42 };
      assert.equal(type, 'login_lifecycle');
      return joined ? { id: 'new-account', uid: 42, shutdown } : null;
    };
    assert.equal((await currentWorkspace()).identity.uid, 42);
    assert.equal(refreshes, 1);
    shutdown = true;
    await assert.rejects(currentWorkspace(), { errno: 'EACCES' });
    assert.equal(refreshes, 1);
  } finally { endWorkspace('new-account'); globalThis.kernelRequest = previous; }
});

test('descriptors are private to their process lineage and revoked on unmount', async () => {
  const space = await create(), scope = space.scope(), foreign = space.scope();
  const fd = await space.open('/mnt/local/project/text', 0, scope);
  assert.equal(atob((await space.read(fd.fd, 0, 3, scope)).data), 'abc');
  await assert.rejects(space.read(fd.fd, 0, 3, foreign), { errno: 'EBADF' });
  space.unmount('/mnt/local/project');
  await assert.rejects(space.read(fd.fd, 0, 3, scope), { errno: 'EBADF' });
  await assert.rejects(space.stat('/mnt/local/project/text'), { errno: 'ENODEV' });
});

test('local paths cannot escape through dot segments or cross-provider rename', async () => {
  const space = await create();
  await assert.rejects(space.stat('/mnt/local/project/../../../etc/passwd'), { errno: 'EACCES' });
  const [result] = await space.calls([{ rename: { from: '/cloud', to: '/mnt/local/project/new' } }], space.page, () => assert.fail('cross-provider mutation reached cloud'));
  assert.equal(result.err.errno, 'EXDEV');
});

test('mixed local batches retain fd reference indices and never forward private fds', async () => {
  const space = await create();
  const answers = await space.calls([{ stat: { path: '/cloud' } }, { open: { path: '/mnt/local/project/text' } }, { pread: { fd: { ref: 1 }, count: 3 } }, { close: { fd: { ref: 1 } } }], space.page, cloud);
  assert.equal(answers[0].err.errno, 'ENOENT'); assert.equal(atob(answers[2].ok.data), 'abc'); assert.equal(space.fds.size, 0);
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
  const previousKernel = globalThis.kernelRequest, previousFetch = globalThis.fetch;
  try {
    globalThis.kernelRequest = async () => { throw { errno: 'ENOENT' }; };
    assert.equal(await mountRequest('mount_overlay', { calls: [{ getdents: { path: '/' } }] }), null);
    await assert.rejects(mountRequest('mount_sys', { calls: [{ stat: { path: '/mnt/local/project/text' } }] }), { errno: 'ENOENT' });
    await assert.rejects(mountRequest('mount_overlay', { calls: [{ stat: { path: '/mnt/local/project/text' } }] }), { errno: 'EACCES' });
    await assert.rejects(mountRequest('mount_overlay', { calls: [{ stat: { path: '/mnt/./local/project/text' } }] }), { errno: 'EACCES' });
    let calls = 0;
    globalThis.kernelRequest = async () => ({ id: 'overlay-test', uid: 12 });
    globalThis.fetch = async () => { calls++; throw new Error('lost response'); };
    const result = await mountRequest('mount_overlay', { calls: [{ stat: { path: '/' } }] });
    assert.equal(result[0].err.errno, 'EIO'); assert.equal(calls, 1);
  } finally { endWorkspace('overlay-test'); globalThis.kernelRequest = previousKernel; globalThis.fetch = previousFetch; }
});

test('normalized private path aliases and descriptor paths cannot fall through to cloud', () => {
  assert.equal(localPath('/mnt/./local/project/text'), true);
  assert.equal(localPath('/opt/scratch/../private/dev/text'), true);
  assert.equal(localPath('/mnt/local/project/../../../etc/passwd'), true);
  assert.equal(localPath('/usr/bin/ls'), false);
  assert.equal(localFdPath('/proc/self/./fd/' + LOCAL_FD), true);
  assert.equal(localFdPath('/proc/self/fd/3'), false);
});

test('shutdown revokes private descriptors but permits credential-checked process cleanup', async () => {
  const space = await create(), scope = space.scope();
  const opened = await space.open('/mnt/local/project/text', 0, scope); space.close();
  const forwarded = [];
  const results = await space.calls([{ stat: { path: '/' } }, { stat: { path: '/mnt/local/project/text' } }, { pread: { fd: opened.fd, count: 3 } }, 'getcreds'], scope, async calls => {
    forwarded.push(...calls); return calls.map(() => ({ ok: 'authorized by server' }));
  }, { allowClosedCloud: true });
  assert.deepEqual(forwarded, [{ stat: { path: '/' } }, 'getcreds']);
  assert.equal(results[1].err.errno, 'ENODEV'); assert.equal(results[2].err.errno, 'ENODEV');
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

  // Symlink escaping mount root fails with ELOOP
  await tab1.calls([{ symlink: { target: '../../outside', path: '/mnt/local/opfs/escape' } }], tab1.page, cloud);
  await assert.rejects(tab1.stat('/mnt/local/opfs/escape'), { errno: 'ELOOP' });

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
  await tab1.closeFd(openFd, tab1.page);

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
    peer.mounts.set('/mnt/shared/sub', {
      path: '/mnt/shared/sub',
      name: 'sub',
      grant: remoteOpfs.grant,
      provider: remoteOpfs,
      cloud: false,
      active: true,
    });

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
      { open: { path: '/mnt/shared/sub/escape', flags: 0 } }, // ELOOP!
      { close: { fd: { ref: 0 } } },
    ], peer.page, cloud);

    assert.equal(remoteOps[2].ok, null, JSON.stringify(remoteOps));
    assert.equal(remoteOps[3].err.errno, 'EEXIST');
    assert.equal(remoteOps[6].ok, 'hard.txt');
    assert.equal(remoteOps[7].err.errno, 'EEXIST');
    assert.equal(atob(remoteOps[9].ok.data), 'remote-hello');
    assert.equal(remoteOps[12].ok.nlink, 0);
    assert.equal(atob(remoteOps[13].ok.data), 'remote-hello');
    assert.equal(remoteOps[14].err.errno, 'ELOOP');
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

  // NativeMount standalone must fail `rename(..., { noreplace: true })` with `EOPNOTSUPP`.
  const native = new NativeMount('http://127.0.0.1:1/');
  native.grant = Object.freeze({ kind: 'native-directory', name: 'nat', readOnly: false, execute: false });
  native.rename = () => assert.fail('NativeMount.rename must not run when noreplace is set');
  ws.mounts.set('/mnt/local/nat', {
    path: '/mnt/local/nat',
    name: 'nat',
    grant: native.grant,
    provider: native,
    cloud: false,
    active: true,
  });
  const [natRes] = await ws.calls([{ rename: { from: '/mnt/local/nat/a', to: '/mnt/local/nat/b', noreplace: true } }], ws.page, cloud);
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
    peer.mounts.set('/mnt/shared/rw', { path: '/mnt/shared/rw', name: 'rw', grant: remoteRw.grant, provider: remoteRw, cloud: false, active: true });
    peer.mounts.set('/mnt/shared/ro', { path: '/mnt/shared/ro', name: 'ro', grant: remoteRo.grant, provider: remoteRo, cloud: false, active: true });

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
    peer.mounts.set('/mnt/shared/rw2', { path: '/mnt/shared/rw2', name: 'rw2', grant: remoteRw2.grant, provider: remoteRw2, cloud: false, active: true });
    await peer.calls([{ open: { path: '/mnt/shared/rw2/orphan-drain.txt', flags: 0o302, mode: 0o600 } }], peer.page, cloud);
    await owner.calls([{ unlink: { path: '/mnt/local/opfs/sub/orphan-drain.txt' } }], owner.page, cloud);
    const locksBeforeUnmount = (await navigator.locks.query()).held.filter(l => l.name.startsWith('os-fs-open:'));
    assert.equal(locksBeforeUnmount.length, 1);

    owner.unmount('/mnt/local/opfs');
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

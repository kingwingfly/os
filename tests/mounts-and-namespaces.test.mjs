import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { accessSync, constants as fsConstants, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { createOpfsStore, createDirectoryStore } from '../web/kernel/fs-store.js';

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
const wasmOutDir = mkdtempSync(join(tmpdir(), 'os-l2-mntns-wasm-'));
process.on('exit', () => {
  try {
    rmSync(wasmOutDir, { recursive: true, force: true });
  } catch {}
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
    '--target',
    'nodejs',
    '--no-typescript',
    '--out-dir',
    wasmOutDir,
    '--out-name',
    'client_kernel',
    join(targetDir, 'wasm32-unknown-unknown/debug/os_client_kernel.wasm'),
  ],
  { cwd: repoRoot, stdio: 'inherit' },
);
const require = createRequire(import.meta.url);
const wasm = require(join(wasmOutDir, 'client_kernel.js'));
globalThis.wasm_bindgen = wasm;

// --- Constants ---
const OS_FD_ROOT = 0x7ffffffd;
const OS_FD_CWD = 0x7ffffffe;

const O_RDONLY = 0;
const O_WRONLY = 1;
const O_RDWR = 2;
const O_CREAT = 0o100;
const O_TRUNC = 0o1000;
const O_DIRECTORY = 0o200000;

const MS_RDONLY = 1n;
const MS_NOSUID = 2n;
const MS_NODEV = 4n;
const MS_REMOUNT = 32n;
const MS_BIND = 4096n;
const MS_UNBINDABLE = 1n << 17n;
const MS_PRIVATE = 1n << 18n;
const MS_SLAVE = 1n << 19n;
const MS_SHARED = 1n << 20n;

const MNT_FORCE = 1;
const MNT_DETACH = 2;
const MNT_EXPIRE = 4;

const CLONE_FS = 0x00000200;
const CLONE_NEWNS = 0x00020000;

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const WASM_HEADER = new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);

async function expectErrno(fn, expected) {
  await assert.rejects(
    async () => await fn(),
    err => {
      assert.equal(
        err?.errno ?? err?.code,
        expected,
        `expected errno ${expected}, got ${JSON.stringify({ errno: err?.errno, code: err?.code, message: err?.message })}`,
      );
      return true;
    },
  );
}

// --- Minimal in-memory IndexedDB + Web Locks + OPFS environment ---
function createMemoryIdb() {
  const databases = new Map();
  const cloneVal = val => (val === undefined || val === null || typeof val !== 'object' ? val : structuredClone(val));

  return {
    open(name, version = 1) {
      const req = { result: undefined, error: null, onsuccess: null, onerror: null, onupgradeneeded: null };
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
            objectStoreNames: { contains: s => entry.stores.has(s) },
            createObjectStore(storeName, opts = {}) {
              const store = { keyPath: opts.keyPath ?? null, records: new Map(), indexes: new Map() };
              entry.stores.set(storeName, store);
              return { createIndex(idxName, kp) { store.indexes.set(idxName, { keyPath: kp }); } };
            },
            transaction(storeNames) {
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
                const r = { result: undefined, error: null, onsuccess: null, onerror: null };
                queueMicrotask(() => {
                  try {
                    r.result = op();
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
                    delete: key => wrapOp(() => { store.records.delete(key); }),
                    clear: () => wrapOp(() => { store.records.clear(); }),
                    index(idxName) {
                      const idx = store.indexes.get(idxName);
                      return {
                        get: sk => wrapOp(() => {
                          for (const rec of store.records.values()) {
                            if (rec?.[idx.keyPath] === sk) return cloneVal(rec);
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
    if (slot.holders.size === 0 && slot.queue.length === 0) state.delete(name);
  }
  return {
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
      const ifAvailable = Boolean(opts.ifAvailable);
      const signal = opts.signal ?? null;
      if (signal?.aborted) return Promise.reject(new DOMException('Aborted', 'AbortError'));
      let slot = state.get(name);
      if (!slot) {
        slot = { mode, holders: new Set(), queue: [] };
        state.set(name, slot);
      }
      const release = token => {
        const cur = state.get(name);
        if (!cur) return;
        cur.holders.delete(token);
        pump(name);
      };
      if (ifAvailable) {
        const canGrant = slot.holders.size === 0 || (slot.mode === 'shared' && mode === 'shared' && slot.queue.length === 0);
        if (!canGrant) return Promise.resolve().then(() => cb(null));
        slot.mode = mode;
        const token = Symbol(name);
        slot.holders.add(token);
        return Promise.resolve().then(() => cb({ name, mode })).finally(() => release(token));
      }
      return new Promise((resolve, reject) => {
        const item = {
          mode,
          aborted: false,
          grant(token) {
            Promise.resolve().then(() => cb({ name, mode })).then(resolve, reject).finally(() => release(token));
          },
        };
        if (signal) {
          signal.addEventListener('abort', () => {
            if (item.aborted) return;
            item.aborted = true;
            reject(new DOMException('Aborted', 'AbortError'));
            pump(name);
          }, { once: true });
        }
        slot.queue.push(item);
        pump(name);
      });
    },
  };
}

function createFakeFsTree(name = 'root', { originPrivate = false, permission = 'granted', onBeforeWrite = null, onBeforeRead = null } = {}) {
  const rootNode = { kind: 'directory', name, children: new Map() };
  function findPath(cur, target, prefix = []) {
    if (cur === target) return prefix;
    if (cur.kind !== 'directory') return null;
    for (const [cn, child] of cur.children) {
      const found = findPath(child, target, [...prefix, cn]);
      if (found) return found;
    }
    return null;
  }
  function wrapFile(node) {
    return {
      kind: 'file',
      name: node.name,
      __node: node,
      async isSameEntry(other) { return other?.__node === node; },
      async getFile() {
        if (onBeforeRead) await onBeforeRead(node.name);
        return new File([node.bytes], node.name, { lastModified: node.lastModified });
      },
      async flush() {},
      async createWritable({ keepExistingData = false } = {}) {
        let buf = keepExistingData ? node.bytes.slice() : new Uint8Array(0);
        return {
          async write(chunk) {
            if (onBeforeWrite) await onBeforeWrite(node.name);
            const pos = chunk?.type === 'write' ? (chunk.position ?? 0) : 0;
            const raw = chunk?.type === 'write' ? chunk.data : chunk;
            const b = raw instanceof Uint8Array ? raw : encoder.encode(String(raw));
            const nextLen = Math.max(buf.length, pos + b.length);
            if (nextLen > buf.length) {
              const grown = new Uint8Array(nextLen);
              grown.set(buf);
              buf = grown;
            }
            buf.set(b, pos);
          },
          async truncate(len) {
            if (len < buf.length) buf = buf.slice(0, len);
            else if (len > buf.length) {
              const grown = new Uint8Array(len);
              grown.set(buf);
              buf = grown;
            }
          },
          async close() {
            if (onBeforeWrite) await onBeforeWrite(node.name);
            node.bytes = buf;
            node.lastModified += 10;
          },
          async abort() {},
        };
      },
    };
  }
  function wrapDir(node) {
    return {
      kind: 'directory',
      name: node.name,
      __node: node,
      ...(originPrivate ? {} : { async queryPermission() { return permission; } }),
      async isSameEntry(other) { return other?.__node === node; },
      async resolve(child) { return child?.__node ? findPath(node, child.__node) : null; },
      async *entries() {
        for (const [cn, child] of [...node.children.entries()]) {
          yield [cn, child.kind === 'directory' ? wrapDir(child) : wrapFile(child)];
        }
      },
      async getDirectoryHandle(cn, { create = false } = {}) {
        const ex = node.children.get(cn);
        if (ex) {
          if (ex.kind !== 'directory') throw new DOMException('Not a directory', 'TypeMismatchError');
          return wrapDir(ex);
        }
        if (!create) throw new DOMException('Not found', 'NotFoundError');
        const created = { kind: 'directory', name: cn, children: new Map() };
        node.children.set(cn, created);
        return wrapDir(created);
      },
      async getFileHandle(cn, { create = false } = {}) {
        const ex = node.children.get(cn);
        if (ex) {
          if (ex.kind !== 'file') throw new DOMException('Is a directory', 'TypeMismatchError');
          return wrapFile(ex);
        }
        if (!create) throw new DOMException('Not found', 'NotFoundError');
        const created = { kind: 'file', name: cn, bytes: new Uint8Array(0), lastModified: 1700000000123 };
        node.children.set(cn, created);
        return wrapFile(created);
      },
      async removeEntry(cn, { recursive = false } = {}) {
        const ex = node.children.get(cn);
        if (!ex) throw new DOMException('Not found', 'NotFoundError');
        if (ex.kind === 'directory' && ex.children.size > 0 && !recursive) {
          throw new DOMException('Not empty', 'InvalidModificationError');
        }
        node.children.delete(cn);
      },
    };
  }
  return {
    rootNode,
    handle: () => wrapDir(rootNode),
    putFile(fileName, content) {
      const bytes = typeof content === 'string' ? encoder.encode(content) : new Uint8Array(content);
      rootNode.children.set(fileName, { kind: 'file', name: fileName, bytes, lastModified: 1700000000123 });
    },
  };
}

function installEnv() {
  const idb = createMemoryIdb();
  const locks = createMemoryWebLocks();
  const opfs = createFakeFsTree('', { originPrivate: true });
  globalThis.indexedDB = idb;
  Object.defineProperty(globalThis, 'navigator', {
    configurable: true,
    writable: true,
    value: {
      locks,
      storage: { async getDirectory() { return opfs.handle(); } },
    },
  });
  return { idb, locks, opfs };
}

function createHarness(t) {
  const env = installEnv();
  const k = new wasm.Kernel(`inst-${crypto.randomUUID()}`, `k-${crypto.randomUUID()}`);
  const pids = new Set();
  const sessions = new Set();

  t.after(async () => {
    for (const pid of [...pids]) {
      await k.proc_exit(pid).catch(() => {});
    }
    for (const sid of [...sessions]) {
      await k.session_end(sid).catch(() => {});
    }
  });

  return {
    env,
    k,
    async beginSession(sid, uid, gid = uid, groups = [gid]) {
      const info = await k.session_begin(sid, uid, gid, new Uint32Array(groups));
      sessions.add(sid);
      return info;
    },
    async spawn(opts) {
      const res = await k.proc_spawn_init(JSON.stringify(opts));
      pids.add(opts.pid);
      return res;
    },
    fork(parentPid, childPid, cloneFlags = 0, token = null, cloudAccess = true) {
      const res = k.proc_fork(parentPid, childPid, cloneFlags, token, cloudAccess);
      pids.add(childPid);
      return res;
    },
    async readText(pid, path, dirfd = OS_FD_ROOT) {
      const opened = await k.proc_openat(pid, dirfd, path, O_RDONLY, 0, false);
      try {
        const chunks = [];
        while (true) {
          const buf = await k.kfd_read(pid, opened.kfd, 16384);
          if (!buf || buf.length === 0) break;
          chunks.push(buf);
        }
        const total = chunks.reduce((s, c) => s + c.length, 0);
        const merged = new Uint8Array(total);
        let off = 0;
        for (const c of chunks) {
          merged.set(c, off);
          off += c.length;
        }
        return decoder.decode(merged);
      } finally {
        await k.kfd_close(pid, opened.kfd);
      }
    },
    async writeText(pid, path, text, mode = 0o644, dirfd = OS_FD_ROOT) {
      const opened = await k.proc_openat(pid, dirfd, path, O_RDWR | O_CREAT | O_TRUNC, mode, false);
      try {
        await k.kfd_write(pid, opened.kfd, encoder.encode(text));
      } finally {
        await k.kfd_close(pid, opened.kfd);
      }
    },
  };
}

// ============================================================================
// Tests
// ============================================================================

test('system_mnt_ns topology, /proc/self/mountinfo escaping, /proc/mounts, sysfs -> ENODEV, and propagation flags', async t => {
  const h = createHarness(t);
  const { k } = h;

  const sysListing = await k.list_mounts('');
  const byTarget = new Map(sysListing.mounts.map(m => [m.target, m]));
  for (const target of ['/', '/usr', '/proc', '/dev', '/dev/pts', '/run', '/mnt/local', '/mnt/shared', '/opt/private']) {
    assert.ok(byTarget.has(target), `expected ${target} in system_mnt_ns`);
  }
  assert.equal(byTarget.get('/usr').fstype, 'image');
  assert.equal(byTarget.get('/usr').readOnly, true);
  assert.equal(byTarget.get('/proc').fstype, 'proc');
  assert.equal(byTarget.get('/dev').fstype, 'devtmpfs');
  assert.equal(byTarget.get('/dev/pts').fstype, 'devpts');
  assert.equal(byTarget.get('/run').fstype, 'tmpfs');

  await h.spawn({ pid: 10, ppid: 1, uid: 0, gid: 0, groups: [0] });

  // sysfs and unknown fstypes must fail with ENODEV (contract §5)
  await assert.rejects(k.sys_mount(10, 'sysfs', '/sys', 'sysfs', 0n, ''), { errno: 'ENODEV' });
  await assert.rejects(k.sys_mount(10, 'none', '/tmp', 'ext99', 0n, ''), { errno: 'ENODEV' });

  // MS_SHARED, MS_SLAVE, MS_UNBINDABLE fail with EINVAL; MS_PRIVATE is accepted
  await assert.rejects(k.sys_mount(10, '', '/run', '', MS_SHARED, ''), { errno: 'EINVAL' });
  await assert.rejects(k.sys_mount(10, '', '/run', '', MS_SLAVE, ''), { errno: 'EINVAL' });
  await assert.rejects(k.sys_mount(10, '', '/run', '', MS_UNBINDABLE, ''), { errno: 'EINVAL' });
  await k.sys_mount(10, '', '/run', '', MS_PRIVATE, '');

  // Mount tmpfs at path containing a space and inspect /proc/self/mountinfo & /proc/mounts
  await k.proc_mkdirat(10, OS_FD_ROOT, '/tmp/mnt space', 0o755);
  await k.sys_mount(10, 'scratchsrc', '/tmp/mnt space', 'tmpfs', 0n, 'mode=0755');

  const mountinfo = await h.readText(10, '/proc/self/mountinfo');
  assert.match(mountinfo, /\/tmp\/mnt\\040space\s+\S+.*-\s+tmpfs\s+scratchsrc\s+/);
  for (const line of mountinfo.trim().split('\n')) {
    const tokens = line.trim().split(/\s+/);
    const sep = tokens.indexOf('-');
    assert.ok(sep >= 6 && sep + 2 < tokens.length, `malformed mountinfo line: ${line}`);
  }

  assert.equal(await k.proc_readlinkat(10, OS_FD_ROOT, '/proc/mounts'), 'self/mounts');
  const mountsText = await h.readText(10, '/proc/mounts');
  assert.match(mountsText, /scratchsrc\s+\/tmp\/mnt\\040space\s+tmpfs\s+/);
  for (const line of mountsText.trim().split('\n')) {
    assert.equal(line.trim().split(/\s+/).length, 6, `malformed /proc/mounts line: ${line}`);
  }
});

test('session_begin derives isolated per-account namespaces and enforces user-mount uid 0 EACCES ceiling + locked nosuid,nodev', async t => {
  const h = createHarness(t);
  const { k } = h;

  const aliceNs = await h.beginSession('sess-alice', 1001, 1001, [1001]);
  const bobNs = await h.beginSession('sess-bob', 1002, 1002, [1002]);
  assert.notEqual(aliceNs.nsId, bobNs.nsId);

  const opfsStore = await createOpfsStore(null, { writable: true, execute: true });
  const mounted = await k.mount_user(
    'sess-alice',
    JSON.stringify({ kind: 'opfs', name: 'work', writable: true, execute: true, cloud: false }),
    opfsStore,
  );
  assert.equal(mounted.target ?? mounted.path, '/mnt/local/work');

  await h.spawn({ pid: 101, ppid: 1, sessionId: 'sess-alice', uid: 1001, gid: 1001, groups: [1001] });
  await h.spawn({ pid: 102, ppid: 1, sessionId: 'sess-alice', uid: 0, gid: 0, groups: [0] }); // sudo in Alice's session
  await h.spawn({ pid: 103, ppid: 1, sessionId: 'sess-bob', uid: 1002, gid: 1002, groups: [1002] });
  await h.spawn({ pid: 104, ppid: 1, uid: 0, gid: 0, groups: [0], serviceGrant: { mountNamespace: 'system' } });
  const isoSvc = await h.spawn({ pid: 105, ppid: 1, uid: 0, gid: 0, groups: [0], serviceGrant: { mountNamespace: 'isolated' } });
  assert.notEqual(isoSvc.nsId, 1);

  await h.writeText(101, '/mnt/local/work/secret.txt', 'alice-private-payload');
  assert.equal(await h.readText(101, '/mnt/local/work/secret.txt'), 'alice-private-payload');

  // Verify forced nosuid,nodev and ownerUid metadata
  const aliceMounts = (await k.list_mounts('sess-alice')).mounts;
  const workMeta = aliceMounts.find(m => m.target === '/mnt/local/work');
  assert.ok(workMeta);
  assert.equal(workMeta.nosuid, true);
  assert.equal(workMeta.nodev, true);
  assert.equal(workMeta.ownerUid, 1001);

  // Attempting to clear locked MS_NOSUID or MS_NODEV via MS_REMOUNT fails with EPERM
  await assert.rejects(k.sys_mount(101, '', '/mnt/local/work', '', MS_REMOUNT, ''), { errno: 'EPERM' });

  // Instance uid 0 (sudo) in Alice's OWN session namespace gets EACCES on Alice's user mount!
  await assert.rejects(k.proc_statat(102, OS_FD_ROOT, '/mnt/local/work/secret.txt', true), { errno: 'EACCES' });
  await assert.rejects(k.proc_openat(102, OS_FD_ROOT, '/mnt/local/work', O_RDONLY | O_DIRECTORY, 0, false), { errno: 'EACCES' });

  // Even if system root (pid 104) opens /proc/101/ns/mnt and calls setns into Alice's namespace, uid 0 STILL gets EACCES!
  const aliceNsFd = await k.proc_openat(104, OS_FD_ROOT, '/proc/101/ns/mnt', O_RDONLY, 0, false);
  k.sys_setns(104, aliceNsFd.kfd, CLONE_NEWNS);
  await k.kfd_close(104, aliceNsFd.kfd);
  await assert.rejects(k.proc_statat(104, OS_FD_ROOT, '/mnt/local/work/secret.txt', true), { errno: 'EACCES' });

  // Bob's session namespace and vfs_sys do not even have /mnt/local/work mounted
  const bobMounts = (await k.list_mounts('sess-bob')).mounts;
  assert.equal(bobMounts.some(m => m.target === '/mnt/local/work'), false);
  await assert.rejects(k.proc_statat(103, OS_FD_ROOT, '/mnt/local/work/secret.txt', true), { errno: 'ENOENT' });

  const bobPageRes = JSON.parse(
    await k.vfs_sys('sess-bob', JSON.stringify({ calls: [{ stat: { path: '/mnt/local/work' } }] })),
  ).results;
  assert.equal(bobPageRes[0].err.errno, 'ENOENT');
});

test('ImageFs mounts validated private extensions at /opt/private/<name>, enforces EROFS & owner ceiling, and rejects invalid manifests', async t => {
  const h = createHarness(t);
  const { k } = h;

  await h.beginSession('sess-alice', 1001, 1001, [1001]);
  await h.spawn({ pid: 201, ppid: 1, sessionId: 'sess-alice', uid: 1001, gid: 1001, groups: [1001] });
  await h.spawn({ pid: 202, ppid: 1, sessionId: 'sess-alice', uid: 0, gid: 0, groups: [0] });

  const hash = createHash('sha256').update(WASM_HEADER).digest('hex');
  const dirEntry = path => ({ path, uid: 0, gid: 0, mode: 0o755, node: { type: 'directory' } });
  const validManifest = {
    format: 'os.image',
    version: 2,
    kind: 'sysext',
    name: 'devtools',
    revision: '1',
    abi: 1,
    level: 1,
    features: [],
    provenance: {},
    entries: [
      dirEntry('/'),
      dirEntry('/usr'),
      dirEntry('/usr/bin'),
      { path: '/usr/bin/probe', uid: 0, gid: 0, mode: 0o755, node: { type: 'file', sha256: hash, size: WASM_HEADER.length, chunk_size: 262144, chunks: [hash] } },
      { path: '/usr/bin/probe-link', uid: 0, gid: 0, mode: 0o777, node: { type: 'symlink', target: '/usr/bin/probe' } },
    ],
  };

  await k.mount_user(
    'sess-alice',
    JSON.stringify({ kind: 'snapshot', name: 'pkgsrc', writable: false, execute: false, cloud: false }),
    [new File([JSON.stringify(validManifest)], 'manifest.json'), new File([WASM_HEADER], `blobs/${hash}`)],
  );

  const extMount = await k.mount_user(
    'sess-alice',
    JSON.stringify({ kind: 'image', name: 'devtools', sources: ['/mnt/local/pkgsrc'], cloud: false }),
    null,
  );
  assert.equal(extMount.fstype, 'image');
  assert.equal(extMount.readOnly, true);

  // Unmounting source snapshot leaves activated ImageFs intact
  await k.unmount_user('sess-alice', '/mnt/local/pkgsrc', 0);

  const st = await k.proc_statat(201, OS_FD_ROOT, '/opt/private/devtools/usr/bin/probe-link', true);
  assert.equal(st.size, WASM_HEADER.length);
  assert.equal(st.mode & 0o6000, 0);

  // ImageFs is strictly read-only (EROFS) and denies uid 0 (EACCES)
  await assert.rejects(k.proc_mkdirat(201, OS_FD_ROOT, '/opt/private/devtools/usr/newdir', 0o755), { errno: 'EROFS' });
  await assert.rejects(k.proc_statat(202, OS_FD_ROOT, '/opt/private/devtools/usr/bin/probe', true), { errno: 'EACCES' });

  // Corrupt digest and setuid manifests fail validation
  const setuidManifest = structuredClone(validManifest);
  setuidManifest.entries[3].mode = 0o4755;
  await k.mount_user(
    'sess-alice',
    JSON.stringify({ kind: 'snapshot', name: 'badsrc', writable: false, execute: false, cloud: false }),
    [new File([JSON.stringify(setuidManifest)], 'manifest.json'), new File([WASM_HEADER], `blobs/${hash}`)],
  );
  await assert.rejects(
    k.mount_user('sess-alice', JSON.stringify({ kind: 'image', name: 'badext', sources: ['/mnt/local/badsrc'], cloud: false }), null),
  );
  await k.unmount_user('sess-alice', '/opt/private/devtools', 0);
  await k.unmount_user('sess-alice', '/opt/private/devtools', 0);
});

test('all 4 unmount and provider ending states: EBUSY, MNT_DETACH with live open fds, Revoked -> EACCES, and Lost -> ENOTCONN + EIO uncertain writes', async t => {
  const h = createHarness(t);
  const { k } = h;

  await h.beginSession('sess-alice', 1001, 1001, [1001]);
  await h.spawn({ pid: 300, ppid: 1, uid: 0, gid: 0, groups: [0] });
  await h.spawn({ pid: 301, ppid: 1, sessionId: 'sess-alice', uid: 1001, gid: 1001, groups: [1001] });

  // --- 1 & 2: EBUSY vs MNT_DETACH ---
  await k.proc_mkdirat(300, OS_FD_ROOT, '/tmp/busy-mnt', 0o755);
  await k.sys_mount(300, 'tmpfs', '/tmp/busy-mnt', 'tmpfs', 0n, '');
  await h.writeText(300, '/tmp/busy-mnt/live.txt', 'before-detach');

  const held = await k.proc_openat(300, OS_FD_ROOT, '/tmp/busy-mnt/live.txt', O_RDWR, 0, false);

  // MNT_EXPIRE -> EINVAL; non-root MNT_FORCE -> EPERM; ordinary umount while fd open -> EBUSY
  await assert.rejects(k.sys_umount2(300, '/tmp/busy-mnt', MNT_EXPIRE), { errno: 'EINVAL' });
  await assert.rejects(k.sys_umount2(301, '/run', MNT_FORCE), { errno: 'EPERM' });
  await assert.rejects(k.sys_umount2(300, '/tmp/busy-mnt', 0), { errno: 'EBUSY' });

  // MNT_DETACH removes mount from namespace immediately while held fd continues reading & writing
  await k.sys_umount2(300, '/tmp/busy-mnt', MNT_DETACH);
  assert.equal((await h.readText(300, '/proc/self/mountinfo')).includes('/tmp/busy-mnt'), false);
  await assert.rejects(k.proc_statat(300, OS_FD_ROOT, '/tmp/busy-mnt/live.txt', true), { errno: 'ENOENT' });

  assert.equal(decoder.decode(await k.kfd_pread(300, held.kfd, 64, 0n)), 'before-detach');
  await k.kfd_pwrite(300, held.kfd, encoder.encode('-updated'), 13n);
  assert.equal(decoder.decode(await k.kfd_pread(300, held.kfd, 64, 0n)), 'before-detach-updated');
  await k.kfd_close(300, held.kfd);

  // --- 3: Revoked -> EACCES (mount stays in mountinfo until unmounted) ---
  await k.mount_user(
    'sess-alice',
    JSON.stringify({ kind: 'snapshot', name: 'revoked-mnt', writable: false, execute: false, cloud: false }),
    [new File(['revokable-body'], 'doc.txt')],
  );
  const openRev = await k.proc_openat(301, OS_FD_ROOT, '/mnt/local/revoked-mnt/doc.txt', O_RDONLY, 0, false);
  assert.equal(decoder.decode(await k.kfd_pread(301, openRev.kfd, 32, 0n)), 'revokable-body');

  k.revoke_mount_provider('sess-alice', '/mnt/local/revoked-mnt');
  const afterRevokeList = (await k.list_mounts('sess-alice')).mounts;
  assert.ok(afterRevokeList.some(m => m.target === '/mnt/local/revoked-mnt'), 'revoked mount stays attached until unmounted');

  await assert.rejects(k.proc_statat(301, OS_FD_ROOT, '/mnt/local/revoked-mnt/doc.txt', true), { errno: 'EACCES' });
  await assert.rejects(k.kfd_pread(301, openRev.kfd, 32, 0n), { errno: 'EACCES' });
  await k.kfd_close(301, openRev.kfd);
  await k.unmount_user('sess-alice', '/mnt/local/revoked-mnt', MNT_DETACH);

  // --- 4: Lost -> ENOTCONN on reads/subsequent ops + EIO & uncertainWrites on in-flight mutations ---
  let writeGateResolve;
  let notifyWriteEntered;
  const writeEntered = new Promise(r => { notifyWriteEntered = r; });
  const slowTree = createFakeFsTree('host-dir', {
    originPrivate: false,
    permission: 'granted',
    onBeforeWrite: () => {
      notifyWriteEntered?.();
      return new Promise(r => { writeGateResolve = r; });
    },
  });
  slowTree.putFile('note.txt', 'initial');
  const dirStore = await createDirectoryStore(slowTree.handle(), { writable: true, execute: false });
  await k.mount_user(
    'sess-alice',
    JSON.stringify({ kind: 'hostfs', name: 'lost-mnt', writable: true, execute: false, cloud: false }),
    dirStore,
  );

  const openLost = await k.proc_openat(301, OS_FD_ROOT, '/mnt/local/lost-mnt/note.txt', O_RDWR, 0, false);
  assert.equal(decoder.decode(await k.kfd_pread(301, openLost.kfd, 32, 0n)), 'initial');

  // Start an in-flight write, then trigger provider loss before host write acknowledges
  const inflightWrite = k.kfd_pwrite(301, openLost.kfd, encoder.encode('mutating'), 0n);
  await writeEntered;
  k.lose_mount_provider('sess-alice', '/mnt/local/lost-mnt');
  writeGateResolve?.();

  await assert.rejects(inflightWrite, { errno: 'EIO' });

  const lostInfo = (await k.list_mounts('sess-alice')).mounts.find(m => m.target === '/mnt/local/lost-mnt');
  assert.ok(lostInfo, 'lost mount stays attached until unmounted');
  assert.ok(lostInfo.uncertainWrites >= 1, `expected uncertainWrites >= 1, got ${lostInfo.uncertainWrites}`);

  // Subsequent operations on both path walk and open fd fail with ENOTCONN without increasing uncertainWrites
  const beforeUncertain = lostInfo.uncertainWrites;
  await assert.rejects(k.kfd_pread(301, openLost.kfd, 16, 0n), { errno: 'ENOTCONN' });
  await assert.rejects(k.proc_statat(301, OS_FD_ROOT, '/mnt/local/lost-mnt/note.txt', true), { errno: 'ENOTCONN' });
  const lostInfoAfter = (await k.list_mounts('sess-alice')).mounts.find(m => m.target === '/mnt/local/lost-mnt');
  assert.equal(lostInfoAfter.uncertainWrites, beforeUncertain);

  await k.kfd_close(301, openLost.kfd);
  await k.unmount_user('sess-alice', '/mnt/local/lost-mnt', MNT_DETACH);
});

test('unshare(CLONE_NEWNS) and setns enforce privilege, reject forged/non-ns/shared-CLONE_FS fds, and isolate mount tables', async t => {
  const h = createHarness(t);
  const { k } = h;

  await h.spawn({ pid: 400, ppid: 1, uid: 0, gid: 0, groups: [0] });
  await h.spawn({ pid: 401, ppid: 1, uid: 0, gid: 0, groups: [0] });
  await h.spawn({ pid: 402, ppid: 1, uid: 1001, gid: 1001, groups: [1001] });

  // Unknown unshare flags -> EINVAL; flags == 0 -> no-op; non-root CLONE_NEWNS -> EPERM
  await expectErrno(() => k.sys_unshare(400, 0x10000000), 'EINVAL');
  await k.sys_unshare(402, 0);
  await expectErrno(() => k.sys_unshare(402, CLONE_NEWNS), 'EPERM');

  // Root 401 unshares CLONE_NEWNS and mounts private tmpfs invisible to 400
  await k.proc_mkdirat(400, OS_FD_ROOT, '/tmp/ns-only', 0o755);
  await k.sys_unshare(401, CLONE_NEWNS);
  await k.sys_mount(401, 'tmpfs', '/tmp/ns-only', 'tmpfs', 0n, '');
  await h.writeText(401, '/tmp/ns-only/inside.txt', 'ns401');

  assert.equal(await h.readText(401, '/tmp/ns-only/inside.txt'), 'ns401');
  await expectErrno(() => k.proc_statat(400, OS_FD_ROOT, '/tmp/ns-only/inside.txt', true), 'ENOENT');

  // setns denials:
  // 1) Forged/closed fd -> EBADF
  await expectErrno(() => k.sys_setns(400, 9999, CLONE_NEWNS), 'EBADF');

  // 2) Open regular/directory fd (not a MountNsFile) -> EINVAL
  const dirFd = await k.proc_openat(400, OS_FD_ROOT, '/tmp', O_RDONLY | O_DIRECTORY, 0, false);
  await expectErrno(() => k.sys_setns(400, dirFd.kfd, CLONE_NEWNS), 'EINVAL');
  await k.kfd_close(400, dirFd.kfd);

  // 3) Non-root with a real /proc/<pid>/ns/mnt fd -> EPERM
  const nonRootNsFd = await k.proc_openat(402, OS_FD_ROOT, '/proc/402/ns/mnt', O_RDONLY, 0, false);
  await expectErrno(() => k.sys_setns(402, nonRootNsFd.kfd, CLONE_NEWNS), 'EPERM');
  await k.kfd_close(402, nonRootNsFd.kfd);

  // 4) Invalid nstype -> EINVAL
  const rootNsFd = await k.proc_openat(400, OS_FD_ROOT, '/proc/401/ns/mnt', O_RDONLY, 0, false);
  await expectErrno(() => k.sys_setns(400, rootNsFd.kfd, 0x20000000), 'EINVAL');

  // 5) Process sharing CLONE_FS cannot setns(CLONE_NEWNS) -> EINVAL until unshare(CLONE_FS)
  h.fork(400, 403, CLONE_FS);
  const sharedNsFd = await k.proc_openat(403, OS_FD_ROOT, '/proc/401/ns/mnt', O_RDONLY, 0, false);
  await expectErrno(() => k.sys_setns(403, sharedNsFd.kfd, CLONE_NEWNS), 'EINVAL');
  await k.sys_unshare(403, CLONE_FS);
  await k.sys_setns(403, sharedNsFd.kfd, CLONE_NEWNS);
  await k.kfd_close(403, sharedNsFd.kfd);
  assert.equal(await h.readText(403, '/tmp/ns-only/inside.txt'), 'ns401');

  // 400 is still in system_mnt_ns until it calls setns itself
  await expectErrno(() => k.proc_statat(400, OS_FD_ROOT, '/tmp/ns-only/inside.txt', true), 'ENOENT');
  await k.sys_setns(400, rootNsFd.kfd, 0);
  await k.kfd_close(400, rootNsFd.kfd);
  assert.equal(await h.readText(400, '/tmp/ns-only/inside.txt'), 'ns401');
});

function syncLocalAccount(k, uid) {
  const user = uid === 0 ? 'root' : `user${uid}`;
  k.sync_account(JSON.stringify({
    uid, gid: uid, groups: [uid], user, group: user,
    home: uid === 0 ? '/root' : `/home/${user}`, shell: '/usr/bin/dash', signed_in: uid !== 65534,
  }));
}

function mockRemoteAuthAndDevices(t, uid) {
  const prevAuth = globalThis.serviceAuthPost;
  const prevCloud = globalThis.cloudFsPost;
  const events = [];
  let seq = 0, nextDevice = 0;
  const tokens = new Set();
  globalThis.serviceAuthPost = async raw => {
    const req = JSON.parse(raw);
    events.push({ auth: req });
    if (req.attach_instance) {
      return JSON.stringify({
        status: 200,
        text: JSON.stringify({
          attached: {
            version: 2,
            instance_id: req.attach_instance.instance.instance,
            lease_seconds: 1800,
            host_epoch: 1,
          },
        }),
      });
    }
    if (req.mint_service_cred || req.derive_service_cred) {
      const m = req.mint_service_cred ?? req.derive_service_cred;
      const token = (`${(++seq).toString(16)}`).padStart(64, 'a');
      tokens.add(token);
      if (req.derive_service_cred?.revoke_parent) tokens.delete(req.derive_service_cred.parent_token);
      return JSON.stringify({
        status: 200,
        text: JSON.stringify({
          cred: {
            version: 2,
            token,
            uid,
            gid: uid,
            groups: [uid],
            umask: m.umask ?? 0o022,
            cloud_access: m.cloud_access !== false,
            scope: m.scope ?? { cloud_fs: true, devices: ['archive', 'media', 'present', 'snd'], containers: true, relay: true },
            expires: Math.floor(Date.now() / 1000) + 3600,
            instance_id: m.instance_id,
            lineage: 'lin-1',
          },
        }),
      });
    }
    if (req.revoke_tokens) {
      for (const tok of req.revoke_tokens.tokens) tokens.delete(tok);
      return JSON.stringify({ status: 200, text: JSON.stringify({ revoked: { count: req.revoke_tokens.tokens.length } }) });
    }
    return JSON.stringify({ status: 200, text: JSON.stringify({ ok: null }) });
  };
  globalThis.cloudFsPost = async (path, headers, body) => {
    if (path === '/api/fs') {
      return { status: 404, body: new TextEncoder().encode(JSON.stringify({ errno: 'ENOENT' })) };
    }
    assert.equal(path, '/api/sys');
    const raw = new TextDecoder().decode(body);
    const batch = JSON.parse(raw);
    assert.equal(headers['X-Process-Token'], batch.proc);
    assert.ok(tokens.has(batch.proc), 'remote token must be active');
    const results = batch.calls.map(call => {
      events.push(call);
      if (call.open) return { ok: { fd: nextDevice++, size: 0, device: 'archive' } };
      return { ok: null };
    });
    return { status: 200, body: new TextEncoder().encode(JSON.stringify({ results })) };
  };
  t.after(() => {
    if (prevAuth) globalThis.serviceAuthPost = prevAuth; else delete globalThis.serviceAuthPost;
    if (prevCloud) globalThis.cloudFsPost = prevCloud; else delete globalThis.cloudFsPost;
  });
  return events;
}

test('failed credential admission exits and reaps every successful pipeline stage', async t => {
  const { k } = createHarness(t);
  syncLocalAccount(k, 1000);
  // Stage 2 requests a nonexistent session namespace -> VFS registration fails with EPERM/ENOENT;
  // all admitted stages must be exited and reaped from LocalProcessTable with zero leaks.
  const stages = [
    { path: '/usr/bin/true', argv: ['true'], env: [] },
    { path: '/usr/bin/true', argv: ['true'], env: [], sessionId: 'no-such-session', serviceGrant: { mountNamespace: 'session', bindMounts: [] } },
    { path: '/usr/bin/true', argv: ['true'], env: [] },
  ];
  await assert.rejects(k.execs(JSON.stringify(stages), false, '', 'host'));
  const remaining = JSON.parse(await k.poll('[]'));
  assert.deepEqual(remaining.map(p => p.pid), [1]);
});

test('only an authorized supervisor outside a chroot can grant a namespace to its child', async t => {
  const h = createHarness(t);
  const { k } = h;
  await h.spawn({ pid: 610, ppid: 1, uid: 0, gid: 0, groups: [0] });
  h.fork(610, 611);
  const grant = JSON.stringify({ mountNamespace: 'system', bindMounts: [] });
  await expectErrno(() => k.proc_apply_service_grant(611, 610, grant), 'EPERM');
  syncLocalAccount(k, 0);
  const stages = [{ path: '/usr/bin/supervise', argv: ['supervise'], env: [] }];
  const supPid = JSON.parse(await k.execs(JSON.stringify(stages), false, '', 'host'))[0].ok.pid;
  assert.ok(supPid > 1);
  k.proc_authorize_service_grant(supPid);
  await k.proc_mkdirat(supPid, OS_FD_ROOT, '/tmp/service-root', 0o755);
  await k.sys_chroot(supPid, '/tmp/service-root');
  h.fork(supPid, 613);
  await expectErrno(() => k.proc_apply_service_grant(613, supPid, grant), 'EPERM');
  await expectErrno(() => k.proc_statat(613, OS_FD_ROOT, '/usr', true), 'ENOENT');
});

test('an ordinary supervise image may grant default, session and isolated namespaces to its own account', async t => {
  const h = createHarness(t), { k } = h;
  await h.beginSession('ordinary', 1000);
  syncLocalAccount(k, 1000);
  const [admission] = JSON.parse(await k.execs(JSON.stringify([{
    path: '/usr/bin/supervise', argv: ['supervise'], env: [], sessionId: 'ordinary',
  }]), false, '', 'host'));
  const supPid = admission.ok.pid;
  assert.ok(supPid > 1);
  for (const [index, mountNamespace] of ['', 'session', 'isolated'].entries()) {
    const child = 700 + index;
    const inherited = h.fork(supPid, child);
    const granted = await k.proc_apply_service_grant(child, supPid, JSON.stringify({ mountNamespace }));
    assert.equal(granted.nsId === inherited.nsId, mountNamespace === '');
    await expectErrno(() => k.proc_apply_service_grant(child, supPid, '{"mountNamespace":"system"}'), 'EPERM');
    k.proc_set_creds(child, 2000, 2000, new Uint32Array([2000]), undefined, true);
    await expectErrno(() => k.proc_apply_service_grant(child, supPid, '{}'), 'EPERM');
  }
});

test('a credential failure after authority exec ends the replaced image', async t => {
  const { k } = createHarness(t);
  syncLocalAccount(k, 0);
  mockRemoteAuthAndDevices(t, 0);
  await k.cloud_sign_in('root', 0, 0, '[0]', JSON.stringify({ cloud_fs: false, devices: ['archive'], containers: false, relay: false }));
  const path = '/usr/bin/true';
  const pid = JSON.parse(await k.execs(JSON.stringify([{ path, argv: ['true'], env: [], remote: true }]), false, '', 'host'))[0].ok.pid;
  await k.attach_remote_device('archive', pid, 'host');
  await k.proc_openat(pid, OS_FD_ROOT, '/dev/archive', O_RDWR, 0, true);
  // Fail remote cloexec close after local reexec commits -> reexec rejects with execCommitted and exits the process.
  globalThis.cloudFsPost = async () => ({ status: 503, body: new Uint8Array() });
  await assert.rejects(k.reexec(pid, 'null', path, '["true"]', '[]', '/', '', 'host'),
    err => err?.execCommitted === true);
  await expectErrno(() => k.proc_statat(pid, OS_FD_ROOT, '/', true), 'ESRCH');
  await k.wait(pid, 'host');
});

test('exec closes the final close-on-exec device mapping on the authority', async t => {
  const { k } = createHarness(t);
  syncLocalAccount(k, 1000);
  const events = mockRemoteAuthAndDevices(t, 1000);
  await k.cloud_sign_in('user', 1000, 1000, '[1000]', JSON.stringify({ cloud_fs: false, devices: ['archive'], containers: false, relay: false }));
  const path = '/usr/bin/true';
  const pid = JSON.parse(await k.execs(JSON.stringify([{ path, argv: ['true'], env: [], remote: true }]), false, '', 'host'))[0].ok.pid;
  await k.attach_remote_device('archive', pid, 'host');
  const device = await k.proc_openat(pid, OS_FD_ROOT, '/dev/archive', O_RDWR, 0, true);
  assert.equal(device.serverDev, true);
  const kept = k.kfd_dup(pid, device.kfd);
  const second = await k.proc_openat(pid, OS_FD_ROOT, '/dev/archive', O_RDWR, 0, false);
  await k.reexec(pid, 'null', path, '["true"]', '[]', '/', '', 'host');
  assert.equal(events.filter(c => c.close).length, 0);
  assert.equal(k.kfd_is_cloexec(pid, kept), false);
  const transport = globalThis.cloudFsPost;
  globalThis.cloudFsPost = async () => ({ status: 503, body: new Uint8Array() });
  await assert.rejects(k.kfd_close(pid, kept));
  globalThis.cloudFsPost = transport;
  await k.kfd_close(pid, kept);
  assert.deepEqual(events.filter(c => c.close).map(c => c.close.fd), [0]);
  k.kfd_set_cloexec(pid, second.kfd, true);
  await k.reexec(pid, 'null', path, '["true"]', '[]', '/', '', 'host');
  assert.deepEqual(events.filter(c => c.close).map(c => c.close.fd), [0, 1]);
});

test('top-level admission applies binds and logout evicts executable tickets on system mounts', async t => {
  const h = createHarness(t);
  const { k } = h;
  const sid = 'login-with-isolated-service';
  await h.beginSession(sid, 0);
  syncLocalAccount(k, 0);
  await h.spawn({ pid: 630, uid: 0, gid: 0, groups: [0] });
  await k.proc_mkdirat(630, OS_FD_ROOT, '/tmp/service-run', 0o755);
  await h.writeText(630, '/run/tool', '\x00asm\x01\x00\x00\x00', 0o755);
  const grant = { mountNamespace: 'isolated', bindMounts: [{ source: '/run', target: '/tmp/service-run', readOnly: true }] };
  const stage = { path: '/usr/bin/true', argv: ['true'], env: [], sessionId: sid, serviceGrant: grant };
  const [admitted] = JSON.parse(await k.execs(JSON.stringify([stage]), false, '', 'host'));
  const pid = admitted.ok.pid;
  assert.ok(pid > 1);
  await expectErrno(() => k.proc_openat(pid, OS_FD_ROOT, '/tmp/service-run/tool', O_WRONLY, 0, false), 'EROFS');
  const tickets = [];
  for (let stage = 0; stage < 40; stage++) {
    const { execTicket } = await k.proc_resolve_exec(pid, '/run/tool', '["tool"]', '/usr/bin', false);
    tickets.push(execTicket);
  }
  for (const ticket of tickets.slice(0, -1)) {
    assert.deepEqual(k.take_local_exec_bytes(ticket, false), WASM_HEADER);
    assert.ok(k.take_local_exec_bytes(ticket, true));
    k.release_exec_ticket(ticket);
    assert.equal(k.take_local_exec_bytes(ticket, true), undefined);
  }
  await k.session_end(sid);
  assert.equal(k.take_local_exec_bytes(tickets.at(-1), false), undefined);
});

test('write-only page upload verifies a sparse file above 128 MiB', async t => {
  const { k } = createHarness(t);
  const block = Buffer.alloc(1024 * 1024);
  const size = 128 * block.length + 1;
  const hash = createHash('sha256');
  for (let i = 0; i < 128; i++) hash.update(block);
  hash.update(block.subarray(0, 1));
  const batch = async call => JSON.parse(await k.vfs_sys('', JSON.stringify({ calls: [call] }))).results[0];
  const opened = await batch({ open: { path: '/tmp/large-upload', flags: O_WRONLY | O_CREAT | O_TRUNC, mode: 0o600, size, sha256: hash.digest('hex') } });
  assert.ok(opened.ok, JSON.stringify(opened));
  await k.vfs_ftruncate_fd('', opened.ok.fd, BigInt(size));
  const closed = await batch({ close: { fd: opened.ok.fd } });
  assert.equal(closed.ok?.size, size, JSON.stringify(closed));
});

test('ordinary page uploads verify mode 0200 files after sequential and out-of-order writes', async t => {
  const h = createHarness(t), sid = 'write-only';
  await h.beginSession(sid, 1001);
  const batch = async call => JSON.parse(await h.k.vfs_sys(sid, JSON.stringify({ calls: [call] }))).results[0];
  const sha256 = createHash('sha256').update('abcd').digest('hex');
  for (const offsets of [[0, 2], [2, 0]]) {
    const path = '/tmp/write-only-' + offsets[0];
    const { ok: opened } = await batch({ open: { path, mode: 0o200, flags: O_CREAT | O_WRONLY, size: 4, sha256 } });
    for (const offset of offsets) {
      await h.k.vfs_pwrite_chunk(sid, opened.fd, BigInt(offset), encoder.encode(offset ? 'cd' : 'ab'));
    }
    const result = await batch({ close: { fd: opened.fd } });
    assert.equal(result.ok?.size, 4, JSON.stringify(result));
    assert.equal(result.ok.stat.uid, 1001);
    assert.equal(result.ok.stat.mode & 0o777, 0o200);
    assert.equal((await batch({ open: { path, flags: O_RDONLY } })).err.errno, 'EACCES');
  }
});

test('Local root page descriptors enforce permissions, remount EBUSY while open for write, and make zero pageSysPost calls', async t => {
  const MS_DIRSYNC = 128n;
  const h = createHarness(t), { k } = h, sid = 'local-root-page', path = '/home/user/local-file';
  await h.beginSession(sid, 1000);
  const seen = [];
  const saved = globalThis.pageSysPost;
  globalThis.pageSysPost = async raw => {
    seen.push(raw);
    return JSON.stringify({ status: 500, text: '{}' });
  };
  t.after(() => { if (saved) globalThis.pageSysPost = saved; else delete globalThis.pageSysPost; });
  const sys = async (call, sudo = false) => JSON.parse(await k.vfs_sys(sid, JSON.stringify({ calls: [call], sudo }))).results[0];
  const remount = flags => sys({ mount: { target: '/', flags: Number(MS_REMOUNT | flags) } }, true);
  const dirsync = await remount(MS_DIRSYNC);
  assert.ok('ok' in dirsync, JSON.stringify(dirsync));
  const made = await sys({ mkdir: { path: '/home/user/dropbox', mode: 0o700 } });
  assert.ok('ok' in made, JSON.stringify(made));
  const child = await sys({ mkdir: { path: '/home/user/dropbox/child', mode: 0o700 } });
  assert.ok('ok' in child, JSON.stringify(child));
  const opened = await sys({ open: { path, flags: O_CREAT | O_RDWR, mode: 0o600 } });
  assert.ok(opened.ok, JSON.stringify(opened));
  const fd = opened.ok.fd;
  await k.vfs_pwrite_chunk(sid, fd, 0n, encoder.encode('test'));
  const chmod = await sys({ fchmod: { fd, mode: 0o640 } });
  assert.ok('ok' in chmod, JSON.stringify(chmod));
  const st = await sys({ stat: { path } });
  assert.equal(st.ok.mode & 0o777, 0o640);
  const read = await sys({ pread: { fd, offset: 0, count: 4 } });
  assert.equal(atob(read.ok.data), 'test');
  // Open write descriptor prevents MS_RDONLY remount with EBUSY until closed.
  assert.equal((await remount(MS_RDONLY)).err?.errno, 'EBUSY');
  assert.ok('ok' in await sys({ close: { fd } }));
  const mounted = await remount(MS_RDONLY);
  assert.ok('ok' in mounted, JSON.stringify(mounted));
  // Zero network calls hit pageSysPost across all `/` operations!
  assert.deepEqual(seen, []);
});

test('anonymous page directory descriptors survive batches and fdinfo uses the page descriptor', async t => {
  const { k } = createHarness(t);
  const batch = async (...calls) => JSON.parse(await k.vfs_sys('', JSON.stringify({ calls }))).results;
  const [opened] = await batch({ open: { path: '/tmp', flags: O_RDONLY | O_DIRECTORY } });
  const dirfd = opened.ok.fd;
  assert.ok(dirfd >= 0x40000000);
  const [child, info] = await batch(
    { open_at: { dirfd, path: 'guest-file', flags: O_CREAT | O_RDWR, mode: 0o600 } },
    { pread: { path: `/proc/self/fdinfo/${dirfd}`, count: 256 } },
  );
  assert.ok(child.ok.fd >= 0x40000000, JSON.stringify(child));
  assert.match(atob(info.ok.data), /mnt_id:/);
  const [st, fs, closed] = await batch(
    { fstat_at: { dirfd, path: 'guest-file' } }, { fstatfs: { fd: dirfd } }, { close: { fd: dirfd } },
  );
  assert.equal(st.ok.mode & 0o170000, 0o100000);
  assert.ok(fs.ok, JSON.stringify(fs));
  assert.ok(closed.ok);
  assert.ok((await batch({ close: { fd: child.ok.fd } }))[0].ok);
});

test('Contract 4 serviceGrant (system/isolated/session), streamed vfs_open_read, chunkIndex pwrite, and execTicket liveness', async t => {
  const h = createHarness(t);
  const { k } = h;

  await h.beginSession('sess-svc', 1000, 1000, [1000]);
  const opfsStore = await createOpfsStore(null, { writable: true, execute: true });
  await k.mount_user('sess-svc', JSON.stringify({
    kind: 'opfs',
    name: 'proj',
    writable: true,
    execute: true,
    cloud: false,
  }), opfsStore);

  // Root setup in session + supervisor process running in system_namespace while retaining session attribution
  syncLocalAccount(k, 1000);
  const admitted = await k.execs(JSON.stringify([{ path: '/usr/bin/supervise', argv: ['supervise'], env: [],
    sessionId: 'sess-svc', serviceGrant: { mountNamespace: 'session', bindMounts: [] } }]), false, '', 'host');
  const supPid = JSON.parse(admitted)[0].ok.pid;
  assert.ok(supPid > 1);
  await h.writeText(supPid, '/mnt/local/proj/hello.txt', 'from-session');
  const appFd = await k.proc_openat(supPid, OS_FD_ROOT, '/mnt/local/proj/app.wasm', O_RDWR | O_CREAT | O_TRUNC, 0o755, false);
  await k.kfd_write(supPid, appFd.kfd, new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x02]));
  await k.kfd_close(supPid, appFd.kfd);

  // One-shot execTicket + non-consuming checkOnly
  const resolved = await k.proc_resolve_exec(supPid, '/mnt/local/proj/app.wasm', JSON.stringify(['app.wasm']), '/usr/bin', false);
  assert.ok(resolved.execTicket, 'expected execTicket');
  assert.ok(k.take_local_exec_bytes(resolved.execTicket, true), 'checkOnly must report live without consuming ticket');
  const took = k.take_local_exec_bytes(resolved.execTicket, false);
  assert.equal(took.length, 10);
  assert.equal(k.take_local_exec_bytes(resolved.execTicket, false), undefined);
  assert.ok(k.take_local_exec_bytes(resolved.execTicket, true), 'live check works post-consume until unmount');

  // Root cannot obtain a "session" serviceGrant -> EPERM
  await h.spawn({ pid: 501, ppid: 1, uid: 0, gid: 0, groups: [0] });
  await expectErrno(
    () => k.proc_apply_service_grant(501, 1, JSON.stringify({ mountNamespace: 'session', bindMounts: [] })),
    'EPERM',
  );

  // Forked child inheriting an open kfd switches to "session" + read-only bindMount and retains kfd
  const openDir = await k.proc_openat(supPid, OS_FD_ROOT, '/mnt/local/proj', O_RDONLY | O_DIRECTORY, 0, false);
  h.fork(supPid, 502, 0);
  await k.proc_spawn_init(JSON.stringify({
    pid: 503,
    ppid: 1,
    uid: 0,
    gid: 0,
    groups: [0],
  }));
  // Root-owned mount target cannot be bound by non-root user unit (Contract 2 -> EPERM);
  // user-owned target (/tmp/svc-ro created by uid 1000) succeeds while keeping inherited kfd.
  await k.proc_mkdirat(503, OS_FD_ROOT, '/tmp/root-only-svc', 0o755);
  await expectErrno(
    () => k.proc_apply_service_grant(502, supPid, JSON.stringify({
      mountNamespace: 'session',
      bindMounts: [{ source: '/mnt/local/proj', target: '/tmp/root-only-svc', readOnly: true }],
    })),
    'EPERM',
  );
  await k.proc_mkdirat(supPid, OS_FD_ROOT, '/tmp/svc-ro', 0o755);

  await k.proc_apply_service_grant(502, supPid, JSON.stringify({
    mountNamespace: 'session',
    bindMounts: [{ source: '/mnt/local/proj', target: '/tmp/svc-ro', readOnly: true }],
  }));
  assert.equal(await h.readText(502, '/tmp/svc-ro/hello.txt'), 'from-session');
  await expectErrno(
    () => k.proc_openat(502, OS_FD_ROOT, '/tmp/svc-ro/hello.txt', O_WRONLY, 0, false),
    'EROFS',
  );
  // Inherited kfd survived namespace switch
  const fstatKeep = await k.kfd_fstat(502, openDir.kfd);
  assert.equal(fstatKeep.mode & 0o170000, 0o040000);
  await k.kfd_close(supPid, openDir.kfd);
  await k.kfd_close(502, openDir.kfd);

  // An ordinary supervisor may inherit its namespace, but cannot select the system namespace.
  h.fork(supPid, 504, 0);
  await expectErrno(() => k.proc_apply_service_grant(504, supPid, JSON.stringify({ mountNamespace: 'system' })), 'EPERM');
  await k.proc_apply_service_grant(504, supPid, JSON.stringify({}));
  assert.equal(await h.readText(504, '/mnt/local/proj/hello.txt'), 'from-session');

  // Streamed vfs_open_read (> 256 KiB inline cutoff) + vfs_pwrite_chunk with chunkIndex
  const bigSize = 300 * 1024;
  const chunk = new Uint8Array(bigSize);
  for (let i = 0; i < bigSize; i++) chunk[i] = i & 0xff;
  const openBatch = JSON.parse(await k.vfs_sys('sess-svc', JSON.stringify({
    calls: [{ open: { path: '/mnt/local/proj/big.bin', flags: O_WRONLY | O_CREAT | O_TRUNC, mode: 0o644,
      size: bigSize, sha256: createHash('sha256').update(chunk).digest('hex') } }],
    sudo: false,
    umask: 0o022,
  })));
  const pageFd = openBatch.results[0].ok.fd;
  await k.vfs_pwrite_chunk('sess-svc', pageFd, 0n, chunk, 0n);
  const closed = JSON.parse(await k.vfs_sys('sess-svc', JSON.stringify({ calls: [{ close: { fd: pageFd } }], sudo: false, umask: 0o022 })));
  assert.equal(closed.results[0].ok.size, bigSize);

  const pageSys = async (...calls) => JSON.parse(await k.vfs_sys('sess-svc', JSON.stringify({ calls }))).results;
  const saved = '/mnt/local/proj/existing.txt';
  await h.writeText(supPid, saved, 'old');
  const [conflict] = await pageSys({ open: { path: saved, flags: O_WRONLY | O_CREAT, size: 3 } });
  assert.equal(conflict.err.errno, 'EEXIST');
  assert.equal(await h.readText(supPid, saved), 'old');
  const badUpload = path => ({ open: { path, flags: O_WRONLY | O_CREAT | O_TRUNC, size: 1, sha256: '0'.repeat(64) } });
  const [existing] = await pageSys(badUpload(saved));
  const [write] = await pageSys({ pwrite: { fd: existing.ok.fd, index: 0, data: btoa('x') } });
  assert.ok('ok' in write, JSON.stringify(write));
  const [failedClose] = await pageSys({ close: { fd: existing.ok.fd } });
  assert.equal(failedClose.err.errno, 'EIO');
  assert.equal(await h.readText(supPid, saved), 'x');
  const created = '/mnt/local/proj/created.txt';
  const [fresh] = await pageSys(badUpload(created));
  await pageSys({ discard: { fd: fresh.ok.fd } });
  assert.equal((await pageSys({ stat: { path: created } }))[0].err.errno, 'ENOENT');
  const [replaced] = await pageSys(badUpload(created));
  await pageSys({ rename: { from: created, to: created + '.old' } });
  await h.writeText(supPid, created, 'replacement');
  await pageSys({ discard: { fd: replaced.ok.fd } });
  assert.equal(await h.readText(supPid, created), 'replacement');

  const openedStream = await k.vfs_open_read('sess-svc', '/mnt/local/proj/big.bin', undefined, undefined, false, false);
  assert.ok(openedStream.streamId > 0);
  assert.equal(openedStream.totalSize, bigSize);
  await h.beginSession('sess-other', 1001);
  await expectErrno(() => k.vfs_read_stream_chunk('sess-other', openedStream.streamId, 1), 'EBADF');
  await expectErrno(() => k.vfs_close_read_stream('sess-other', openedStream.streamId), 'EBADF');
  const parts = [];
  for (;;) {
    const part = await k.vfs_read_stream_chunk('sess-svc', openedStream.streamId, 65536);
    if (!part.length) break;
    parts.push(...part);
  }
  await k.vfs_close_read_stream('sess-svc', openedStream.streamId);
  assert.equal(parts.length, bigSize);
  assert.equal(parts[299999], 299999 & 0xff);
  const pending = await k.vfs_open_read('sess-svc', '/mnt/local/proj/big.bin', undefined, undefined, false, false);
  await k.session_end('sess-svc');
  await expectErrno(() => k.vfs_read_stream_chunk('sess-svc', pending.streamId, 1), 'EBADF');
  assert.equal(k.take_local_exec_bytes(resolved.execTicket, true), undefined);
});

test('Contract 1: eval_fchmod and kfd_futimens enforce caller Cred, O_PATH EBADF, and MS_RDONLY EROFS via fsetattr', async t => {
  const h = createHarness(t);
  const sid = 'sess-contract1';
  await h.beginSession(sid, 1000, 1000, [1000]);

  const opfsStore = await createOpfsStore(null, { writable: true, execute: false });
  await h.k.mount_user(
    sid,
    JSON.stringify({ kind: 'opfs', name: 'u1', writable: true, execute: false, cloud: false }),
    opfsStore,
  );

  await h.spawn({
    pid: 5100,
    uid: 1000,
    gid: 1000,
    groups: [1000],
    sessionId: sid,
  });

  // Open a regular writable kfd and an O_PATH kfd as uid 1000.
  const O_PATH = 0o10000000;
  const rwOpen = await h.k.proc_openat(
    5100,
    OS_FD_ROOT,
    '/mnt/local/u1/target.txt',
    O_RDWR | O_CREAT | O_TRUNC,
    0o644,
    false,
  );
  const rwKfd = rwOpen.kfd;
  const pathOpen = await h.k.proc_openat(
    5100,
    OS_FD_ROOT,
    '/mnt/local/u1/target.txt',
    O_PATH,
    0,
    false,
  );
  const pathKfd = pathOpen.kfd;

  // Regular kfd: kfd_futimens updates mtime and Fchmod via proc_sys updates mode.
  const omit = JSON.stringify('omit');
  const now = JSON.stringify('now');
  const targetTs = JSON.stringify({ sec: 1700000123, nsec: 456000000 });
  await h.k.kfd_futimens(5100, rwKfd, omit, targetTs);
  const fchmodRes = JSON.parse(await h.k.proc_sys(
    5100,
    JSON.stringify({ calls: [{ fchmod: { fd: rwKfd, mode: 0o600 } }] }),
  ));
  assert.equal(fchmodRes.results[0].ok, null);
  const stAfter = await h.k.kfd_fstat(5100, rwKfd);
  assert.equal(stAfter.mode & 0o777, 0o600);
  assert.equal(stAfter.mtime, 1700000123);
  assert.equal(stAfter.mtime_nsec, 456000000);

  // O_PATH kfd: kfd_futimens and Fchmod both return EBADF.
  await expectErrno(() => h.k.kfd_futimens(5100, pathKfd, omit, now), 'EBADF');
  const pathFchmod = JSON.parse(await h.k.proc_sys(
    5100,
    JSON.stringify({ calls: [{ fchmod: { fd: pathKfd, mode: 0o644 } }] }),
  ));
  assert.equal(pathFchmod.results[0].err.errno, 'EBADF');

  // Fork and escalate child credentials to uid 0 while keeping inherited rwKfd:
  // FileRef::setattr_as must evaluate caller Cred (uid 0 != owner_uid 1000) -> EACCES.
  h.fork(5100, 5101, 0);
  h.k.proc_set_creds(5101, 0, 0, new Uint32Array([0]), null, false);
  await expectErrno(() => h.k.kfd_futimens(5101, rwKfd, omit, now), 'EACCES');
  const escalatedFchmod = JSON.parse(await h.k.proc_sys(
    5101,
    JSON.stringify({ calls: [{ fchmod: { fd: rwKfd, mode: 0o644 } }] }),
  ));
  assert.equal(escalatedFchmod.results[0].err.errno, 'EACCES');

  // Remount MS_RDONLY as uid 1000 (preserving locked MS_NOSUID | MS_NODEV | MS_NOEXEC):
  // fails with EBUSY while writable rwKfd is open, then succeeds once closed;
  // page fd eval_fchmod and kfd_futimens return EROFS.
  await expectErrno(
    () => h.k.sys_mount(5100, '', '/mnt/local/u1', '', 1n | 2n | 4n | 8n | 32n, ''),
    'EBUSY',
  );
  await h.k.kfd_close(5101, rwKfd);
  await h.k.kfd_close(5100, rwKfd);
  const roOpen = await h.k.proc_openat(
    5100,
    OS_FD_ROOT,
    '/mnt/local/u1/target.txt',
    O_RDONLY,
    0,
    false,
  );
  const roKfd = roOpen.kfd;
  await h.k.sys_mount(5100, '', '/mnt/local/u1', '', 1n | 2n | 4n | 8n | 32n, '');
  const pageOpen = JSON.parse(await h.k.vfs_sys(
    sid,
    JSON.stringify({
      calls: [
        {
          open: {
            path: '/mnt/local/u1/target.txt',
            flags: O_RDONLY,
            mode: 0o644,
          },
        },
        {
          open: {
            path: '/mnt/local/u1/target.txt',
            flags: O_PATH,
            mode: 0o644,
          },
        },
      ],
    }),
  ));
  const pageReadFd = pageOpen.results[0].ok.fd;
  const pagePathFd = pageOpen.results[1].ok.fd;
  const pageRes = JSON.parse(await h.k.vfs_sys(
    sid,
    JSON.stringify({
      calls: [
        { fchmod: { fd: pageReadFd, mode: 0o644 } },
        { fchmod: { fd: pagePathFd, mode: 0o644 } },
        { close: { fd: pageReadFd } },
        { close: { fd: pagePathFd } },
      ],
    }),
  ));
  assert.equal(pageRes.results[0].err.errno, 'EROFS');
  assert.equal(pageRes.results[1].err.errno, 'EBADF');
  await expectErrno(() => h.k.kfd_futimens(5100, roKfd, now, now), 'EROFS');

  await h.k.kfd_close(5100, roKfd);
  await h.k.kfd_close(5100, pathKfd);
});

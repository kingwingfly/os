// Node.js unit + real-Wasm (`os-client-kernel`) integration suite for `web/kernel/cowfs-store.js`
// (#77, Blueprint §3.2):
// - Crash between OPFS `writePack` (SyncAccessHandle flush+close) and IndexedDB `{durability:"strict"}`
//   `commitHead`, clean reopen at prior epoch, GC orphan sweep, and `cowfsck`.
// - `QuotaExceededError` -> `ENOSPC` keeping previous committed head intact.
// - Bit-flip in OPFS pack and in IndexedDB B+tree node -> fail-closed `EIO`.
// - Format version mismatch (<1 and >1) -> `EPROTONOSUPPORT` without wiping user volume.
// - Web Locks `os-vol:<uuid>` fencing (`exclusive`, `fork-on-busy` unmodified prune vs modified
//   preserve, `force-takeover` bumping `local_fence` -> `ESTALE`, lock-free `getFile().slice()` RO).
// - O(1) snapshot, fork, and `FICLONE` (0 pack bytes written; cross-volume `EXDEV`).
// - `/dev/vd0` `BLK_INFO` / `COWFS_IOC_*` root vs non-root `EPERM` and `mkfs.cowfs` `ENOTBLK`.
// - Fixed 32 MiB wasm32 arena bounds on 8 GiB sparse cold read & sustained >8 MiB write.

import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { accessSync, constants as fsConstants, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { createCowfsStore, COWFS_FORMAT_VERSION } from '../web/kernel/cowfs-store.js';

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
const wasmOutDir = mkdtempSync(join(tmpdir(), 'os-l25a-cowfs-wasm-'));
writeFileSync(join(wasmOutDir, 'package.json'), '{"type":"commonjs"}\n');
process.on('exit', () => {
  try {
    rmSync(wasmOutDir, { recursive: true, force: true });
  } catch {}
});

execFileSync(
  'cargo',
  [
    'build',
    '--quiet',
    '--locked',
    '--offline',
    '-p',
    'os-client-kernel',
    '--target',
    'wasm32-unknown-unknown',
    '--target-dir',
    targetDir,
  ],
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

const COWFS_IOC_SNAPSHOT = 0x5457_0201;
const COWFS_IOC_FORK = 0x5457_0202;
const COWFS_IOC_INFO = 0x5457_0203;
const BLK_INFO = 0x5457_0210;

async function expectErrno(fn, expected) {
  await assert.rejects(
    async () => await fn(),
    err => {
      assert.equal(
        err?.errno,
        expected,
        `expected errno ${expected}, got ${JSON.stringify({ errno: err?.errno, message: err?.message })}`,
      );
      return true;
    },
  );
}

// --- In-memory IndexedDB (with strict durability tracking, openCursor, ConstraintError, & rollback) ---
function createMemoryIdb(idbOpts = {}) {
  const databases = new Map();
  let strictTxCount = 0;
  let nodesGetAllCount = 0;

  return {
    get strictTxCount() {
      return strictTxCount;
    },
    get nodesGetAllCount() {
      return nodesGetAllCount;
    },
    resetCounters() {
      strictTxCount = 0;
      nodesGetAllCount = 0;
    },
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
              const store = {
                keyPath: opts.keyPath ?? null,
                autoIncrement: Boolean(opts.autoIncrement),
                nextId: 1,
                records: new Map(),
              };
              entry.stores.set(storeName, store);
              return { createIndex() {} };
            },
            transaction(storeNames, mode = 'readonly', opts = {}) {
              if (mode === 'readwrite' && opts?.durability === 'strict') {
                if (idbOpts.throwOnStrictDurability) {
                  throw new TypeError('strict durability unsupported');
                }
                strictTxCount += 1;
              }
              const names = Array.isArray(storeNames) ? storeNames : [storeNames];
              const snapshots = new Map();
              for (const n of names) {
                const st = entry.stores.get(n);
                if (!st) throw new DOMException(`Missing store ${n}`, 'NotFoundError');
                if (mode === 'readwrite') {
                  snapshots.set(n, new Map(st.records));
                }
              }
              const durability = idbOpts.downgradeStrictDurability
                ? 'relaxed'
                : (opts?.durability ?? 'default');
              const tx = { durability, oncomplete: null, onerror: null, onabort: null, error: null };
              let pending = 0;
              let aborted = false;
              let finished = false;
              const maybeComplete = () => {
                if (!finished && !aborted && pending === 0) {
                  setImmediate(() => {
                    if (!finished && !aborted && pending === 0) {
                      finished = true;
                      tx.oncomplete?.({ target: tx });
                    }
                  });
                }
              };
              tx.abort = () => {
                if (finished || aborted) return;
                aborted = true;
                for (const [n, snap] of snapshots) {
                  entry.stores.get(n).records = snap;
                }
                queueMicrotask(() => tx.onabort?.({ target: tx }));
              };
              const runOp = fn => {
                const r = { result: undefined, error: null, onsuccess: null, onerror: null };
                pending += 1;
                queueMicrotask(() => {
                  if (aborted) {
                    pending -= 1;
                    return;
                  }
                  try {
                    r.result = fn();
                    r.onsuccess?.({ target: r });
                  } catch (e) {
                    r.error = e;
                    tx.error = e;
                    r.onerror?.({ target: r });
                    tx.abort();
                  } finally {
                    pending -= 1;
                    maybeComplete();
                  }
                });
                return r;
              };
              tx.objectStore = storeName => {
                const st = entry.stores.get(storeName);
                return {
                  get: key => runOp(() => {
                    const v = st.records.get(key);
                    return v === undefined ? undefined : structuredClone(v);
                  }),
                  getAll: () => runOp(() => {
                    if (storeName === 'nodes') nodesGetAllCount += 1;
                    return [...st.records.values()].map(v => structuredClone(v));
                  }),
                  put: (value, key) => runOp(() => {
                    const cloned = structuredClone(value);
                    const k = st.keyPath ? cloned[st.keyPath] : key;
                    st.records.set(k, cloned);
                    return k;
                  }),
                  add: (value, key) => runOp(() => {
                    const cloned = structuredClone(value);
                    let k;
                    if (st.autoIncrement) {
                      k = st.keyPath && cloned[st.keyPath] !== undefined ? cloned[st.keyPath] : st.nextId++;
                      if (st.keyPath) cloned[st.keyPath] = k;
                    } else {
                      k = st.keyPath ? cloned[st.keyPath] : key;
                    }
                    if (st.records.has(k)) {
                      throw new DOMException(`Key already exists: ${k}`, 'ConstraintError');
                    }
                    st.records.set(k, cloned);
                    return k;
                  }),
                  delete: key => runOp(() => {
                    st.records.delete(key);
                  }),
                  openCursor: () => {
                    const r = { result: undefined, error: null, onsuccess: null, onerror: null };
                    const entries = [...st.records.entries()];
                    let idx = 0;
                    const step = () => {
                      pending += 1;
                      queueMicrotask(() => {
                        if (aborted) {
                          pending -= 1;
                          return;
                        }
                        try {
                          if (idx >= entries.length) {
                            r.result = null;
                            r.onsuccess?.({ target: r });
                          } else {
                            const [k, v] = entries[idx++];
                            r.result = {
                              key: k,
                              primaryKey: k,
                              value: structuredClone(v),
                              delete() {
                                st.records.delete(k);
                              },
                              continue() {
                                step();
                              },
                            };
                            r.onsuccess?.({ target: r });
                          }
                        } catch (e) {
                          r.error = e;
                          tx.error = e;
                          r.onerror?.({ target: r });
                          tx.abort();
                        } finally {
                          pending -= 1;
                          maybeComplete();
                        }
                      });
                    };
                    step();
                    return r;
                  },
                };
              };
              queueMicrotask(maybeComplete);
              return tx;
            },
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

// --- In-memory Web Locks supporting shared, exclusive, queued waiting, ifAvailable, and steal ---
function createMemoryWebLocks() {
  const states = new Map(); // name -> { held: Set<{ id, mode }>, queue: Array<{ mode, resolve }> }
  let seq = 1;

  const getState = name => {
    let s = states.get(name);
    if (!s) {
      s = { held: new Set(), queue: [] };
      states.set(name, s);
    }
    return s;
  };

  const isBusy = (s, mode) =>
    mode === 'exclusive'
      ? s.held.size > 0
      : [...s.held].some(h => h.mode === 'exclusive');

  const drain = name => {
    const s = states.get(name);
    if (!s) return;
    while (s.queue.length > 0) {
      const next = s.queue[0];
      if (isBusy(s, next.mode)) break;
      s.queue.shift();
      const token = { id: seq++, mode: next.mode, name };
      s.held.add(token);
      next.resolve(token);
      if (next.mode === 'exclusive') break;
    }
  };

  return {
    async request(name, opts, cb) {
      await Promise.resolve();
      const mode = opts?.mode ?? 'exclusive';
      const ifAvailable = Boolean(opts?.ifAvailable);
      const steal = Boolean(opts?.steal);
      const s = getState(name);

      let token;
      if (steal) {
        s.held.clear();
        token = { id: seq++, mode, name };
        s.held.add(token);
      } else if (!isBusy(s, mode) && (s.queue.length === 0 || (mode === 'shared' && s.queue[0].mode === 'shared'))) {
        token = { id: seq++, mode, name };
        s.held.add(token);
      } else if (ifAvailable) {
        return await cb(null);
      } else {
        token = await new Promise(resolve => {
          s.queue.push({ mode, resolve });
        });
      }

      try {
        return await cb({ name, mode });
      } finally {
        s.held.delete(token);
        drain(name);
      }
    },
  };
}

// --- In-memory OPFS with dedicated-Worker `createSyncAccessHandle`, atomic `move()`, & lock-free `getFile().slice()` ---
function createMemoryOpfs(opts = {}) {
  const quotaBytes = opts.quotaBytes ?? Infinity;
  const disableMove = Boolean(opts.disableMove);
  const totalBytes = () => {
    let sum = 0;
    const walk = dir => {
      for (const child of dir._children.values()) {
        if (child.kind === 'file') sum += child._bytes.byteLength;
        else walk(child);
      }
    };
    walk(root);
    return sum;
  };
  const makeFile = (parentDir, initialName) => {
    let currentName = initialName;
    const fh = {
      kind: 'file',
      _bytes: new Uint8Array(0),
      async createSyncAccessHandle() {
        let closed = false;
        return {
          truncate(sz) {
            if (closed) throw new DOMException('closed', 'InvalidStateError');
            const next = new Uint8Array(sz);
            next.set(fh._bytes.subarray(0, Math.min(sz, fh._bytes.length)));
            fh._bytes = next;
          },
          write(buf, { at = 0 } = {}) {
            if (closed) throw new DOMException('closed', 'InvalidStateError');
            const src = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
            const needed = Math.max(fh._bytes.length, at + src.length);
            if (totalBytes() - fh._bytes.length + needed > quotaBytes) {
              throw new DOMException('quota exceeded', 'QuotaExceededError');
            }
            if (needed > fh._bytes.length) {
              const next = new Uint8Array(needed);
              next.set(fh._bytes);
              fh._bytes = next;
            }
            fh._bytes.set(src, at);
            return src.length;
          },
          flush() {},
          close() {
            closed = true;
          },
        };
      },
      async getFile() {
        const snapshot = new Uint8Array(fh._bytes);
        return {
          size: snapshot.byteLength,
          slice(start, end) {
            const sub = snapshot.slice(start, end);
            return {
              async arrayBuffer() {
                return sub.buffer.slice(sub.byteOffset, sub.byteOffset + sub.byteLength);
              },
            };
          },
          async arrayBuffer() {
            return snapshot.buffer.slice(snapshot.byteOffset, snapshot.byteOffset + snapshot.byteLength);
          },
        };
      },
    };
    if (!disableMove) {
      fh.move = async newName => {
        if (parentDir._children.get(currentName) === fh) {
          parentDir._children.delete(currentName);
        }
        currentName = newName;
        parentDir._children.set(newName, fh);
      };
    }
    return fh;
  };
  const makeDir = () => ({
    kind: 'directory',
    _children: new Map(),
    async getDirectoryHandle(name, { create = false } = {}) {
      let child = this._children.get(name);
      if (!child) {
        if (!create) throw new DOMException('not found', 'NotFoundError');
        child = makeDir();
        this._children.set(name, child);
      }
      return child;
    },
    async getFileHandle(name, { create = false } = {}) {
      let child = this._children.get(name);
      if (!child) {
        if (!create) throw new DOMException('not found', 'NotFoundError');
        child = makeFile(this, name);
        this._children.set(name, child);
      }
      return child;
    },
    async removeEntry(name) {
      if (!this._children.has(name)) throw new DOMException('not found', 'NotFoundError');
      this._children.delete(name);
    },
    async *entries() {
      for (const pair of this._children.entries()) yield pair;
    },
  });
  const root = makeDir();
  return root;
}

function makeEnv(extra = {}) {
  const idb = extra.idb ?? createMemoryIdb(extra.idbOpts);
  const locks = extra.locks ?? createMemoryWebLocks();
  const opfsRoot = extra.opfsRoot ?? createMemoryOpfs(extra.opfs);
  const storage = {
    persistCalled: false,
    async persist() {
      this.persistCalled = true;
      return true;
    },
    async estimate() {
      return extra.estimate ?? { usage: 0, quota: 1024 * 1024 * 1024 };
    },
  };
  const store = createCowfsStore({
    dbName: extra.dbName ?? 'os-cowfs-test',
    idb,
    locks,
    opfsRoot,
    storage,
    graceWindowSecs: extra.graceWindowSecs ?? 60,
    hooks: extra.hooks,
  });
  return { idb, locks, opfsRoot, storage, store };
}

test('crash between OPFS SyncAccessHandle pack write and strict IDB commitHead preserves epoch & GC sweeps orphan', async () => {
  let failCommit = false;
  const env = makeEnv({
    hooks: {
      onCommitHead() {
        if (failCommit) {
          failCommit = false;
          throw Object.assign(new Error('simulated crash'), { errno: 'EIO' });
        }
      },
    },
  });
  await wasm.cowfs_format_volume(env.store, 'vol-crash', 0o755);
  assert.equal(env.storage.persistCalled, true);
  assert.ok(env.idb.strictTxCount >= 1);

  const vol = await wasm.CowFsVolume.open_rw(env.store, 'vol-crash', 'exclusive');
  const payload1 = new Uint8Array(128 * 1024).fill(0x33);
  await vol.write_file('/good.bin', payload1, 0o644, null);
  const head1 = await vol.sync_fs();
  assert.equal(head1.epoch, 1);
  assert.ok(env.store.stats.syncHandleWrites >= 1);

  // Inject crash between writePack and commitHead: tab dies abruptly (no close_clean flush!).
  await vol.write_file('/lost.bin', new Uint8Array(128 * 1024).fill(0x99), 0o644, null);
  failCommit = true;
  await expectErrno(() => vol.sync_fs(), 'EIO');
  assert.equal((await env.store.listPacks()).length, 2, 'orphan pack remains on OPFS after crash');
  vol.free(); // drop dead handle without flushing (releases crashed tab lock)
  // Reopen cleanly using a fresh store wrapper sharing the same IDB/OPFS/locks.
  const store2 = createCowfsStore({
    dbName: env.store.dbName,
    idb: env.idb,
    locks: env.locks,
    opfsRoot: env.opfsRoot,
    storage: env.storage,
    graceWindowSecs: 0,
  });
  const vol2 = await wasm.CowFsVolume.open_rw(store2, 'vol-crash', 'force-takeover');
  assert.equal(vol2.info().epoch, 1);
  await expectErrno(() => vol2.stat('/lost.bin', true, null), 'ENOENT');
  const readBack = await vol2.read_file('/good.bin', null);
  assert.deepEqual(readBack, payload1);
  assert.ok(store2.stats.sliceReads >= 1, 'RO/pack reads use lock-free getFile().slice()');
  await vol2.close_clean();

  const fsckBefore = await wasm.cowfs_verify_volume(store2, 'vol-crash');
  assert.equal(fsckBefore.ok, true, JSON.stringify(fsckBefore.errors));

  // Sweep orphan pack with GC.
  const futureSec = Math.floor(Date.now() / 1000) + 3600;
  const gc = await wasm.cowfs_collect_garbage(store2, futureSec);
  assert.equal(gc.swept_packs.length, 1);
  assert.equal((await store2.listPacks()).length, 1);
  const fsckAfter = await wasm.cowfs_verify_volume(store2, 'vol-crash');
  assert.equal(fsckAfter.ok, true, JSON.stringify(fsckAfter.errors));
});

test('QuotaExceededError -> ENOSPC keeps prior head intact; bit-flip -> EIO; format_version mismatch -> EPROTONOSUPPORT without wiping', async () => {
  const env = makeEnv({ opfs: { quotaBytes: 200 * 1024 } });
  await wasm.cowfs_format_volume(env.store, 'vol-refuse', 0o755);
  const vol = await wasm.CowFsVolume.open_rw(env.store, 'vol-refuse', 'exclusive');

  const base = new Uint8Array(64 * 1024).fill(0x55);
  await vol.write_file('/base.bin', base, 0o644, null);
  const h1 = await vol.sync_fs();
  assert.equal(h1.epoch, 1);

  // Exceed OPFS quota with 4 distinct 64 KiB blocks (256 KiB > 200 KiB quota) -> ENOSPC, previous head intact!
  const huge = new Uint8Array(256 * 1024);
  for (let blk = 0; blk < 4; blk++) {
    huge.fill(0xa0 + blk, blk * 65536, (blk + 1) * 65536);
  }
  await vol.write_file('/huge.bin', huge, 0o644, null);
  await expectErrno(() => vol.sync_fs(), 'ENOSPC');
  assert.equal((await env.store.readHead('vol-refuse')).epoch, 1);
  vol.free(); // simulate reload after ENOSPC without flushing huge.bin
  const env2 = createCowfsStore({
    dbName: env.store.dbName,
    idb: env.idb,
    locks: env.locks,
    opfsRoot: env.opfsRoot,
    storage: env.storage,
  });

  // Format version mismatch (> 1 and < 1) refuses with EPROTONOSUPPORT and NEVER wipes volume!
  for (const badVer of [COWFS_FORMAT_VERSION + 1, 0]) {
    await env.store._setFormatVersionForTest(badVer);
    await expectErrno(() => wasm.CowFsVolume.open_ro(env2, 'vol-refuse'), 'EPROTONOSUPPORT');
    await expectErrno(() => wasm.cowfs_verify_volume(env2, 'vol-refuse'), 'EPROTONOSUPPORT');
  }
  await env.store._setFormatVersionForTest(COWFS_FORMAT_VERSION);
  assert.equal((await wasm.cowfs_verify_volume(env2, 'vol-refuse')).ok, true);

  // Bit-flip 1 byte in OPFS pack -> cold read fails closed with EIO!
  const packs = await env2.listPacks();
  assert.equal(packs.length, 1);
  await env2._corruptPackByteForTest(packs[0], 10);
  const ro = await wasm.CowFsVolume.open_ro(env2, 'vol-refuse');
  await expectErrno(() => ro.read_file('/base.bin', null), 'EIO');
  // Un-flip pack, then flip 1 byte in root B+tree node -> open fails with EIO!
  await env2._corruptPackByteForTest(packs[0], 10);
  const rootHex = h1.root.map(b => b.toString(16).padStart(2, '0')).join('');
  await env2._corruptNodeByteForTest(rootHex, 12);
  await expectErrno(() => wasm.CowFsVolume.open_ro(env2, 'vol-refuse'), 'EIO');
});

test('Web Locks fencing (exclusive, fork-on-busy prune vs keep, force-takeover), O(1) snapshot/fork/FICLONE, ioctl EPERM, ENOTBLK, and 32 MiB arena', async () => {
  const env = makeEnv();
  await wasm.cowfs_format_volume(env.store, 'vol-main', 0o755);
  await wasm.cowfs_format_volume(env.store, 'vol-other', 0o755);

  const w1 = await wasm.CowFsVolume.open_rw(env.store, 'vol-main', 'exclusive');
  const oneMb = new Uint8Array(1024 * 1024);
  for (let i = 0; i < oneMb.length; i += 65536) oneMb[i] = (i / 65536) & 0xff;
  await w1.write_file('/data.bin', oneMb, 0o644, null);
  await w1.sync_fs();

  // Exclusive contention -> EBUSY.
  await expectErrno(() => wasm.CowFsVolume.open_rw(env.store, 'vol-main', 'exclusive'), 'EBUSY');

  // ForkOnBusy unmodified -> auto-pruned on clean shutdown!
  const fUnmod = await wasm.CowFsVolume.open_rw(env.store, 'vol-main', 'fork-on-busy');
  assert.equal(fUnmod.forked_from(), 'vol-main');
  const unmodId = fUnmod.volume_id();
  await fUnmod.close_clean();
  await expectErrno(() => env.store.readHead(unmodId), 'ENOENT');

  // ForkOnBusy modified -> preserved on clean shutdown!
  const fMod = await wasm.CowFsVolume.open_rw(env.store, 'vol-main', 'fork-on-busy');
  const modId = fMod.volume_id();
  await fMod.write_file('/note.txt', new TextEncoder().encode('kept'), 0o644, null);
  await fMod.close_clean();
  assert.equal((await env.store.readHead(modId)).modified, true);

  // O(1) snapshot + fork + FICLONE copy 0 pack bytes!
  env.store.resetStats();
  const snap = await w1.snapshot('s1');
  await w1.fork('s1', 'vol-fork', false);
  await w1.ficlone('/data.bin', '/clone.bin', null);
  await w1.sync_fs();
  assert.equal(env.store.stats.packBytesWritten, 0, 'snapshot+fork+FICLONE must copy 0 pack bytes');

  // Cross-volume FICLONE -> EXDEV.
  const other = await wasm.CowFsVolume.open_rw(env.store, 'vol-other', 'exclusive');
  await expectErrno(() => other.ficlone_from_other(w1, '/data.bin', '/x.bin', null), 'EXDEV');
  await other.close_clean();

  // /dev/vd0 ioctl authorization: root succeeds, non-root snapshot/fork -> EPERM, mkfs on dir -> ENOTBLK.
  const rootInfo = await w1.ioctl(BLK_INFO, '', null);
  assert.equal(rootInfo.volume, 'vol-main');
  assert.equal((await w1.ioctl(COWFS_IOC_INFO, '', null)).volume, 'vol-main');
  await w1.ioctl(COWFS_IOC_SNAPSHOT, JSON.stringify({ name: 's2', ro: true }), null);
  await w1.ioctl(COWFS_IOC_FORK, JSON.stringify({ snapshot: 's2', new_volume: 'vol-ioc-fork' }), null);
  const alice = { id: 1000, group: 1000, groups: [1000] };
  await expectErrno(() => w1.ioctl(COWFS_IOC_SNAPSHOT, JSON.stringify({ name: 'nope' }), alice), 'EPERM');
  await expectErrno(() => w1.ioctl(COWFS_IOC_FORK, JSON.stringify({ new_volume: 'nope' }), alice), 'EPERM');
  await w1.mkdir('/mydir', 0o755, null);
  await expectErrno(() => w1.mkfs_target('/mydir', false, null), 'ENOTBLK');
  await expectErrno(() => w1.mkfs_target('hostfs:folder', false, null), 'ENOTBLK');

  // 8 GiB sparse cold read within 32 MiB wasm32 arena!
  const EIGHT_GIB = 8 * 1024 * 1024 * 1024;
  await w1.write_file('/sparse.bin', new Uint8Array(0), 0o644, null);
  await w1.truncate('/sparse.bin', EIGHT_GIB, null);
  const needle = new TextEncoder().encode('cowfs-8gib-marker');
  await w1.write_at_offset('/sparse.bin', EIGHT_GIB - 4096, needle, 0o644, null);
  await w1.sync_fs();
  w1.drop_clean_caches();
  const got = await w1.read_range('/sparse.bin', EIGHT_GIB - 4096, needle.length, null);
  assert.deepEqual(got, needle);
  const arena = w1.arena_stats();
  assert.ok(arena.peak_tree_lru_bytes <= 8 * 1024 * 1024);
  assert.ok(arena.peak_clean_data_bytes <= 16 * 1024 * 1024);
  assert.ok(arena.peak_dirty_bytes <= 8 * 1024 * 1024);
  assert.ok(arena.peak_total_bytes <= 32 * 1024 * 1024);

  // ForceTakeover bumps fence -> w1's next sync fails ESTALE!
  const w2 = await wasm.CowFsVolume.open_rw(env.store, 'vol-main', 'force-takeover');
  await w1.write_file('/stale.txt', new TextEncoder().encode('nope'), 0o644, null);
  await expectErrno(() => w1.sync_fs(), 'ESTALE');
  await w2.write_file('/winner.txt', new TextEncoder().encode('ok'), 0o644, null);
  await w2.close_clean();
});

test('F1-03: multi-dbName stores sharing one OPFS origin isolate pack directories across GC', async () => {
  const opfsRoot = createMemoryOpfs();
  const locks = createMemoryWebLocks();
  const idb = createMemoryIdb();
  const envA = makeEnv({ dbName: 'db-alpha', idb, locks, opfsRoot, graceWindowSecs: 0 });
  const envB = makeEnv({ dbName: 'db-beta', idb, locks, opfsRoot, graceWindowSecs: 0 });

  await wasm.cowfs_format_volume(envA.store, 'vol-a', 0o755);
  await wasm.cowfs_format_volume(envB.store, 'vol-b', 0o755);

  const volA = await wasm.CowFsVolume.open_rw(envA.store, 'vol-a', 'exclusive');
  const volB = await wasm.CowFsVolume.open_rw(envB.store, 'vol-b', 'exclusive');
  const dataA = new Uint8Array(64 * 1024).fill(0x1a);
  const dataB = new Uint8Array(64 * 1024).fill(0x2b);
  await volA.write_file('/a.bin', dataA, 0o644, null);
  await volB.write_file('/b.bin', dataB, 0o644, null);
  await volA.close_clean();
  await volB.close_clean();

  assert.equal((await envA.store.listPacks()).length, 1);
  assert.equal((await envB.store.listPacks()).length, 1);

  // Aggressive GC on db-alpha MUST NOT delete db-beta's packs!
  const futureSec = Math.floor(Date.now() / 1000) + 86400;
  const gcA = await wasm.cowfs_collect_garbage(envA.store, futureSec);
  assert.equal(gcA.swept_packs.length, 0);
  assert.equal((await envB.store.listPacks()).length, 1);

  const verifyB = await wasm.cowfs_verify_volume(envB.store, 'vol-b');
  assert.equal(verifyB.ok, true, JSON.stringify(verifyB.errors));
  const roB = await wasm.CowFsVolume.open_ro(envB.store, 'vol-b');
  assert.deepEqual(await roB.read_file('/b.bin', null), dataB);
  await roB.close_clean();
});

test('F1-14: atomic writePack verifies SHA-256 and replaces corrupt/torn existing pack file', async () => {
  const env = makeEnv();
  const payload = new Uint8Array(128).fill(0x5c);
  const digestBuf = await crypto.subtle.digest('SHA-256', payload);
  const packId = [...new Uint8Array(digestBuf)].map(b => b.toString(16).padStart(2, '0')).join('');

  // Pre-seed a torn/corrupt pack file at the exact pack path inside OPFS.
  await env.store.writePack(packId, payload);
  await env.store._corruptPackByteForTest(packId, 5);
  const corrupt = await env.store.readPackRange(packId, 0, payload.length);
  assert.notDeepEqual(corrupt, payload);

  // Re-writing the valid pack MUST detect SHA-256 mismatch and atomically replace the corrupt file!
  await env.store.writePack(packId, payload);
  const repaired = await env.store.readPackRange(packId, 0, payload.length);
  assert.deepEqual(repaired, payload);
});

test('F1-16: strict IDB durability fails closed without silent fallback', async () => {
  const envThrow = makeEnv({ idbOpts: { throwOnStrictDurability: true } });
  await expectErrno(() => wasm.cowfs_format_volume(envThrow.store, 'vol-no-strict', 0o755), 'EOPNOTSUPP');

  const envDowngrade = makeEnv({ idbOpts: { downgradeStrictDurability: true } });
  await expectErrno(() => wasm.cowfs_format_volume(envDowngrade.store, 'vol-downgraded', 0o755), 'EOPNOTSUPP');
});

test('F1-10, F1-13, F1-21, F1-22, F1-29: RO GC pin, ForceTakeover lock retention, queued writer GC lock, exact 1x grace, & cursor sweep', async () => {
  const env = makeEnv({ graceWindowSecs: 600 });
  await wasm.cowfs_format_volume(env.store, 'vol-gc-pin', 0o755);

  const w1 = await wasm.CowFsVolume.open_rw(env.store, 'vol-gc-pin', 'exclusive');
  const v1Data = new Uint8Array(64 * 1024).fill(0x71);
  await w1.write_file('/doc.bin', v1Data, 0o644, null);
  const h1 = await w1.sync_fs();
  const createdSec = Number(h1.updated_at.sec);

  // Open RO mount pinned at v1 BEFORE overwriting & deleting doc.bin.
  const ro = await wasm.CowFsVolume.open_ro(env.store, 'vol-gc-pin');
  await w1.unlink('/doc.bin', null);
  await w1.sync_fs();

  // Run GC far past grace window while RO is open -> RO root pin MUST protect v1's pack!
  env.idb.resetCounters();
  const gcPinned = await wasm.cowfs_collect_garbage(env.store, createdSec + 3600);
  assert.equal(gcPinned.swept_packs.length, 0);
  assert.equal(env.idb.nodesGetAllCount, 0, 'F1-29: sweepMetadata must stream via cursor, never nodes.getAll()');
  ro.drop_clean_caches();
  assert.deepEqual(await ro.read_file('/doc.bin', null), v1Data);
  await ro.close_clean();

  // Exact 1x grace window (F1-22): at createdSec + 599 pack stays, at createdSec + 601 pack is swept!
  const gcBeforeGrace = await wasm.cowfs_collect_garbage(env.store, createdSec + 599);
  assert.equal(gcBeforeGrace.swept_packs.length, 0);
  const gcAfterGrace = await wasm.cowfs_collect_garbage(env.store, createdSec + 601);
  assert.equal(gcAfterGrace.swept_packs.length, 1);
  assert.equal(env.idb.nodesGetAllCount, 0);

  // Queued shared writer GC lock (F1-21): while exclusive GC lock is held, writer waits instead of EBUSY.
  const exclGc = await env.store.acquireGcLock(true);
  let sharedAcquired = false;
  const waiter = env.store.acquireGcLock(false).then(id => {
    sharedAcquired = true;
    return id;
  });
  await new Promise(r => setTimeout(r, 15));
  assert.equal(sharedAcquired, false, 'shared GC lock must wait while exclusive GC lock is held');
  await env.store.releaseGcLock(exclGc);
  const sharedId = await waiter;
  assert.equal(sharedAcquired, true);
  await env.store.releaseGcLock(sharedId);

  // ForceTakeover retains exclusive lock (F1-13): even after w1 closes, w3 exclusive MUST fail EBUSY!
  const w2 = await wasm.CowFsVolume.open_rw(env.store, 'vol-gc-pin', 'force-takeover');
  await expectErrno(() => wasm.CowFsVolume.open_rw(env.store, 'vol-gc-pin', 'exclusive'), 'EBUSY');
  await expectErrno(() => w1.sync_fs(), 'ESTALE');
  await w1.close_clean();
  await expectErrno(() => wasm.CowFsVolume.open_rw(env.store, 'vol-gc-pin', 'exclusive'), 'EBUSY');
  await w2.close_clean();
});

test('F1-07, F1-18, F1-19: wasm32 4 GiB truncate, negative/NaN EINVAL, /dev/vd0 & symlink ENOTBLK, and distinct UID isolation', async () => {
  const env = makeEnv();
  await wasm.cowfs_format_volume(env.store, 'vol-bridge', 0o755);
  const vol = await wasm.CowFsVolume.open_rw(env.store, 'vol-bridge', 'exclusive');

  // F1-19: /dev/vd0 is mounted & stat-able; mkfs on mounted /dev/vd0 -> EBUSY; symlink -> /dev/vd0 -> ENOTBLK (F1-18).
  const vd0 = await vol.stat('/dev/vd0', true, null);
  assert.equal(vd0.rdev, 'vblk:vd0');
  await expectErrno(() => vol.mkfs_target('/dev/vd0', true, null), 'EBUSY');
  await vol.symlink('/dev/vd0', '/dev-link', null);
  await expectErrno(() => vol.mkfs_target('/dev-link', true, null), 'ENOTBLK');

  // F1-19: negative, NaN, fractional, and > MAX_SAFE_INTEGER arguments return EINVAL (never truncate to 0).
  await vol.write_file('/keep.txt', new TextEncoder().encode('dont-wipe'), 0o644, null);
  await expectErrno(() => vol.truncate('/keep.txt', -1, null), 'EINVAL');
  await expectErrno(() => vol.truncate('/keep.txt', Number.NaN, null), 'EINVAL');
  await expectErrno(() => vol.truncate('/keep.txt', 1.5, null), 'EINVAL');
  await expectErrno(() => vol.read_range('/keep.txt', -5, 4, null), 'EINVAL');
  await expectErrno(() => vol.write_at_offset('/keep.txt', -1, new Uint8Array([1]), 0o644, null), 'EINVAL');
  assert.deepEqual(await vol.read_file('/keep.txt', null), new TextEncoder().encode('dont-wipe'));

  // F1-19: UIDs 1 and 10001 do NOT collide in process identity table.
  await vol.mkdir('/shared', 0o777, null);
  await vol.chmod('/shared', 0o777, null);
  const id1 = { id: 1, group: 1, groups: [1] };
  const id10001 = { id: 10001, group: 10001, groups: [10001] };
  await vol.write_file('/shared/u1.txt', new TextEncoder().encode('a'), 0o644, id1);
  await vol.write_file('/shared/u10001.txt', new TextEncoder().encode('b'), 0o644, id10001);
  assert.equal((await vol.stat('/shared/u1.txt', true, null)).uid, 1);
  assert.equal((await vol.stat('/shared/u10001.txt', true, null)).uid, 10001);

  // F1-07: 8 GiB -> 4 GiB sparse truncate on real 32-bit wasm32 preserves <= 2 KiB inline prefix!
  const prefix = new TextEncoder().encode('INLINE-SURVIVES-4GIB-TRUNCATE');
  await vol.write_file('/inline4g.bin', prefix, 0o644, null);
  await vol.truncate('/inline4g.bin', 8 * 1024 * 1024 * 1024, null);
  await vol.truncate('/inline4g.bin', 4 * 1024 * 1024 * 1024, null);
  assert.deepEqual(await vol.read_range('/inline4g.bin', 0, prefix.length, null), prefix);
  assert.equal((await vol.stat('/inline4g.bin', true, null)).size, 4 * 1024 * 1024 * 1024);

  await vol.close_clean();
});

test('L2.5c: listVolumeHeads and atomic commitReceivedRoot (new volume, incremental lease+snapshot, EEXIST, ESTALE, receipt idempotency)', async () => {
  const env = makeEnv();
  await wasm.cowfs_format_volume(env.store, 'vol-src', 0o755);
  const srcHead = await env.store.readHead('vol-src');
  const rootHex = srcHead.root.map(b => b.toString(16).padStart(2, '0')).join('');
  const rootBytes = await env.store.getNode(rootHex);
  assert.ok(rootBytes && rootBytes.length > 0);

  // Create a brand new volume via commitReceivedRoot with an atomic snapshot in one strict IDB tx.
  const now = { sec: 1_700_000_100, nsec: 0 };
  const h0 = await env.store.commitReceivedRoot(
    JSON.stringify({
      opId: '0102030405060708090a0b0c0d0e0f10',
      volume: 'vol-rx',
      expectedLease: null,
      newRoot: rootHex,
      putPacks: [],
      putBlocks: [],
      snapshotName: 'snapA',
      committedAt: now,
    }),
    [{ digest: rootHex, bytes: rootBytes }],
  );
  assert.equal(h0.volume, 'vol-rx');
  assert.equal(h0.epoch, 0);
  const snaps0 = await env.store.listSnapshots('vol-rx');
  assert.equal(snaps0.length, 1);
  assert.equal(snaps0[0].name, 'snapA');

  // Replaying the same opId with the same root is idempotent!
  const replay = await env.store.commitReceivedRoot(
    JSON.stringify({
      opId: '0102030405060708090a0b0c0d0e0f10',
      volume: 'vol-rx',
      expectedLease: null,
      newRoot: rootHex,
      putPacks: [],
      putBlocks: [],
      snapshotName: 'snapA',
      committedAt: now,
    }),
    [],
  );
  assert.equal(replay.epoch, 0);

  // Attempting to create an already-existing volume with expectedLease=null fails EEXIST!
  await expectErrno(
    () =>
      env.store.commitReceivedRoot(
        JSON.stringify({
          opId: '1112131415161718191a1b1c1d1e1f20',
          volume: 'vol-rx',
          expectedLease: null,
          newRoot: rootHex,
          putPacks: [],
          putBlocks: [],
          snapshotName: null,
          committedAt: now,
        }),
        [],
      ),
    'EEXIST',
  );

  // Stale lease fails ESTALE; matching lease advances epoch + records snapB!
  await expectErrno(
    () =>
      env.store.commitReceivedRoot(
        JSON.stringify({
          opId: '2122232425262728292a2b2c2d2e2f30',
          volume: 'vol-rx',
          expectedLease: { incarnation: h0.incarnation, fence: h0.fence, epoch: 99 },
          newRoot: rootHex,
          putPacks: [],
          putBlocks: [],
          snapshotName: 'snapB',
          committedAt: now,
        }),
        [],
      ),
    'ESTALE',
  );
  const h1 = await env.store.commitReceivedRoot(
    JSON.stringify({
      opId: '3132333435363738393a3b3c3d3e3f40',
      volume: 'vol-rx',
      expectedLease: { incarnation: h0.incarnation, fence: h0.fence, epoch: h0.epoch },
      newRoot: rootHex,
      putPacks: [],
      putBlocks: [],
      snapshotName: 'snapB',
      committedAt: now,
    }),
    [],
  );
  assert.equal(h1.epoch, 1);

  const heads = await env.store.listVolumeHeads();
  assert.deepEqual(
    heads.map(h => h.volume),
    ['vol-rx', 'vol-src'],
  );

  // Finding #4: reformatVolumeWithLease MUST refuse EBUSY while an active RO pin exists!
  const roVol = await wasm.CowFsVolume.open_ro(env.store, 'vol-src');
  const lease = await env.store.acquireWriter('vol-src', 'exclusive');
  await expectErrno(
    () =>
      env.store.reformatVolumeWithLease(
        lease.leaseId,
        'vol-src',
        lease.incarnation,
        lease.fence,
        lease.epoch,
        JSON.stringify(srcHead),
        [{ digest: rootHex, bytes: rootBytes }],
      ),
    'EBUSY',
  );
  await roVol.close_clean();

  // After RO mount closes, reformat succeeds and bumps incarnation!
  const lease2 = await env.store.acquireWriter('vol-src', 'exclusive');
  const reformatted = await env.store.reformatVolumeWithLease(
    lease2.leaseId,
    'vol-src',
    lease2.incarnation,
    lease2.fence,
    lease2.epoch,
    JSON.stringify(srcHead),
    [{ digest: rootHex, bytes: rootBytes }],
  );
  assert.equal(reformatted.incarnation, 2);
});

// Host I/O, IndexedDB metadata store, and Web Locks adapter for `HostFs` (contract §2.2, §2.5, §2.12).
// Zero portable policy lives here: Rust `os-vfs` decides permissions, ACLs, xattrs, open-unlink,
// fingerprints, store format versions, and advisory lock state; this module strictly performs
// primitive browser host I/O, durable IndexedDB record transactions, and Web Locks coordination.

export const STORE_FORMAT_VERSION = 3;
const HANDLE_REGISTRY_DB = 'os-fs-handles';
const LOCK_CHANNEL_NAME = 'os-fs-locks';
const WASM_MAGIC = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

const error = (errno, message = errno) => Object.assign(new Error(message), { errno });

function refusal(reason) {
  if (reason?.errno) return reason;
  const errno = {
    NotAllowedError: 'EACCES',
    SecurityError: 'EACCES',
    NotFoundError: 'ENOENT',
    NotReadableError: 'EIO',
    InvalidStateError: 'EIO',
    AbortError: 'EIO',
    TypeMismatchError: 'ENOTDIR',
    NoModificationAllowedError: 'EBUSY',
    InvalidModificationError: 'ENOTEMPTY',
    NotSupportedError: 'EOPNOTSUPP',
    QuotaExceededError: 'EDQUOT',
  }[reason?.name] ?? 'EIO';
  return error(errno, reason?.message ?? 'local filesystem operation failed');
}

function lockRefusal(reason) {
  if (reason?.errno) return reason;
  return error('ENOLCK', reason?.message ?? 'Web Locks coordinator failed');
}

function splitPath(path) {
  if (!path) return [];
  return path.split('/').filter(Boolean);
}

// Local in-process listeners so same-tab `F_SETLKW` waiters wake even without BroadcastChannel loopback.
const localLockListeners = new Set();
// Per-IndexedDB fallback handle registries for non-cloneable mock directory handles in unit tests.
const nonCloneableRegistries = new WeakMap();
// Fallback Map<storeKey, Map<string, FileSystemHandle>> for non-cloneable mock entry handles.
const nonCloneableEntryHandles = new Map();

function fallbackRegistryFor(idb) {
  let state = nonCloneableRegistries.get(idb);
  if (!state) {
    state = { rows: [] };
    nonCloneableRegistries.set(idb, state);
  }
  return state;
}

function fileMtimeParts(file) {
  const raw = typeof file?.lastModified === 'number' ? file.lastModified : 0;
  if (!Number.isFinite(raw) || raw <= 0) return { wholeMs: 0, subNs: 0 };
  const wholeMs = Math.trunc(raw);
  const subNs = Math.min(999_999, Math.round((raw - wholeMs) * 1_000_000));
  return { wholeMs, subNs };
}

function fingerprintMatches(file, expectedFp) {
  if (!expectedFp) return true;
  if (file.size !== expectedFp.size) return false;
  const { wholeMs, subNs } = fileMtimeParts(file);
  return wholeMs === expectedFp.mtimeWholeMs && subNs === expectedFp.mtimeSubNs;
}

async function sameEntry(a, b) {
  if (!a || !b) return false;
  if (a === b) return true;
  if (typeof a.isSameEntry === 'function') {
    return Boolean(await a.isSameEntry(b).catch(() => false));
  }
  return false;
}

function getIdb(override) {
  const idb = override ?? globalThis.indexedDB;
  if (!idb || typeof idb.open !== 'function') {
    throw error('ENOTSUP', 'IndexedDB is unavailable in this session');
  }
  return idb;
}

function getWebLocks(override, lockName = '') {
  if (
    globalThis.__osForceEnolck &&
    (lockName.startsWith('os-fs-lock:') || lockName.startsWith('os-fs-wait:'))
  ) {
    throw error('ENOLCK', 'advisory lock coordinator unavailable');
  }
  const locks = override ?? globalThis.navigator?.locks;
  if (!locks || typeof locks.request !== 'function' || typeof locks.query !== 'function') {
    throw error('ENOLCK', 'Web Locks coordinator is unavailable');
  }
  return locks;
}

function reqPromise(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(refusal(req.error));
  });
}

const TX_DONE = Symbol('os.txDone');

function txDone(tx) {
  return tx[TX_DONE];
}

function openTransaction(db, stores, mode, strict = false) {
  let tx;
  if (strict && mode === 'readwrite') {
    try {
      tx = db.transaction(stores, mode, { durability: 'strict' });
    } catch {
      tx = db.transaction(stores, mode);
    }
  } else {
    tx = db.transaction(stores, mode);
  }
  const done = new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(refusal(tx.error));
    tx.onabort = () => reject(refusal(tx.error ?? new Error('IndexedDB transaction aborted')));
  });
  done.catch(() => {});
  tx[TX_DONE] = done;
  return tx;
}

function openMetaDb(idb, dbName) {
  return new Promise((resolve, reject) => {
    const req = idb.open(dbName, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('meta')) {
        db.createObjectStore('meta');
      }
      if (!db.objectStoreNames.contains('inodes')) {
        const inodes = db.createObjectStore('inodes', { keyPath: 'ino' });
        inodes.createIndex('backing', 'backing', { unique: false });
      }
      if (!db.objectStoreNames.contains('locks')) {
        db.createObjectStore('locks', { keyPath: 'ino' });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(refusal(req.error));
    req.onblocked = () => reject(error('EBUSY', 'IndexedDB metadata store upgrade blocked'));
  });
}

function openHandleRegistryDb(idb) {
  return new Promise((resolve, reject) => {
    const req = idb.open(HANDLE_REGISTRY_DB, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('meta')) {
        db.createObjectStore('meta');
      }
      if (!db.objectStoreNames.contains('handles')) {
        db.createObjectStore('handles', { keyPath: 'uuid' });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(refusal(req.error));
  });
}

async function isWasmExecutable(blob, executeEnabled) {
  if (!executeEnabled || blob.size < 8) return false;
  const header = new Uint8Array(await blob.slice(0, 8).arrayBuffer());
  if (header.length < 8) return false;
  for (let i = 0; i < 8; i++) {
    if (header[i] !== WASM_MAGIC[i]) return false;
  }
  return true;
}

async function acquireExclusiveLock(locks, name, fn) {
  return locks.request(name, { mode: 'exclusive' }, () => fn());
}

async function handlesOverlap(a, b) {
  if (typeof a?.resolve === 'function' && (await a.resolve(b).catch(() => null)) !== null) {
    return true;
  }
  if (typeof b?.resolve === 'function' && (await b.resolve(a).catch(() => null)) !== null) {
    return true;
  }
  return false;
}

async function resolveDirectoryUuid(handle, { idb, locks }) {
  const fallback = fallbackRegistryFor(idb);
  return acquireExclusiveLock(locks, 'os-fs-mint', async () => {
    const db = await openHandleRegistryDb(idb);
    try {
      const rtx = openTransaction(db, ['meta', 'handles'], 'readonly');
      const [storedVersion, existing] = await Promise.all([
        reqPromise(rtx.objectStore('meta').get('version')),
        reqPromise(rtx.objectStore('handles').getAll()),
        txDone(rtx),
      ]);
      if (storedVersion !== undefined && storedVersion !== null && storedVersion > STORE_FORMAT_VERSION) {
        throw error('EPROTONOSUPPORT', 'directory handle registry belongs to a newer OS release');
      }

      const registered = [
        ...fallback.rows,
        ...(existing ?? []).filter(row => row?.handle && typeof row.uuid === 'string'),
      ];
      let matchedUuid = null;
      for (const row of registered) {
        if (await sameEntry(handle, row.handle)) {
          matchedUuid ??= row.uuid;
          continue;
        }
        // Always check every other registered handle (including legacy entries) for
        // ancestor/descendant overlap before returning an existing or newly minted UUID.
        if (await handlesOverlap(handle, row.handle)) {
          throw error('EACCES', 'cannot mount a directory overlapping an already registered folder');
        }
      }

      if (matchedUuid !== null) {
        if (storedVersion !== STORE_FORMAT_VERSION) {
          const wtx = openTransaction(db, ['meta'], 'readwrite', true);
          wtx.objectStore('meta').put(STORE_FORMAT_VERSION, 'version');
          await txDone(wtx);
        }
        return matchedUuid;
      }

      const uuid = crypto.randomUUID();
      try {
        const wtx = openTransaction(db, ['meta', 'handles'], 'readwrite', true);
        wtx.objectStore('meta').put(STORE_FORMAT_VERSION, 'version');
        await Promise.all([
          reqPromise(wtx.objectStore('handles').put({ uuid, handle })),
          txDone(wtx),
        ]);
      } catch (err) {
        // Plain JS mock handles in unit tests have method functions and cannot be structured-cloned;
        // retain them in the per-IDB fallback table without failing mount admission.
        if (err?.name === 'DataCloneError' || /clone/i.test(err?.message ?? '')) {
          fallback.rows.push({ uuid, handle });
          const vtx = openTransaction(db, ['meta'], 'readwrite', true);
          vtx.objectStore('meta').put(STORE_FORMAT_VERSION, 'version');
          await txDone(vtx);
        } else {
          throw err;
        }
      }
      return uuid;
    } finally {
      db.close();
    }
  });
}

function buildStore({
  rootHandle,
  opfsRoot,
  originPrivate,
  execute,
  writable,
  db,
  dbName,
  fixedUuid,
  locksOption,
}) {
  let closed = false;
  let onRevoke = null;
  let currentUuid = fixedUuid ?? null;
  const storeKey = dbName ?? db?.name ?? fixedUuid ?? 'default';
  const fileQueues = new Map();
  const dirtyFiles = new Set();

  function fallbackEntryMap(create = false) {
    let map = nonCloneableEntryHandles.get(storeKey);
    if (!map && create) {
      map = new Map();
      nonCloneableEntryHandles.set(storeKey, map);
    }
    return map;
  }

  async function saveEntryHandle(ino, handle) {
    const keyStr = String(ino);
    const idbKey = `entryHandle:${keyStr}`;
    try {
      const tx = openTransaction(db, ['meta'], 'readwrite', false);
      tx.objectStore('meta').put(handle, idbKey);
      await txDone(tx);
      fallbackEntryMap(false)?.delete(keyStr);
    } catch (err) {
      if (err?.name === 'DataCloneError' || /clone/i.test(err?.message ?? '')) {
        fallbackEntryMap(true).set(keyStr, handle);
      } else {
        throw err;
      }
    }
  }

  async function loadEntryHandle(ino) {
    const keyStr = String(ino);
    const mem = fallbackEntryMap(false)?.get(keyStr);
    if (mem) return mem;
    const tx = openTransaction(db, ['meta'], 'readonly');
    const raw = await reqPromise(tx.objectStore('meta').get(`entryHandle:${keyStr}`));
    await txDone(tx);
    return raw ?? null;
  }

  async function deleteEntryHandle(ino) {
    const keyStr = String(ino);
    fallbackEntryMap(false)?.delete(keyStr);
    const tx = openTransaction(db, ['meta'], 'readwrite', false);
    tx.objectStore('meta').delete(`entryHandle:${keyStr}`);
    await txDone(tx);
  }

  const channel = typeof globalThis.BroadcastChannel === 'function'
    ? new globalThis.BroadcastChannel(LOCK_CHANNEL_NAME)
    : null;
  channel?.unref?.();

  function ensureOpen() {
    if (closed) throw error('ENODEV', 'local mount is detached');
  }

  function revoke(reason) {
    if (!closed) {
      closed = true;
      try { db.close(); } catch {}
      try { channel?.close(); } catch {}
      const cb = onRevoke;
      onRevoke = null;
      if (cb) {
        try { cb(); } catch {}
      }
    }
    throw refusal(reason);
  }

  async function checkPermission() {
    ensureOpen();
    if (!originPrivate) {
      let state;
      try {
        state = await rootHandle.queryPermission({ mode: writable ? 'readwrite' : 'read' });
      } catch (reason) {
        revoke(reason);
      }
      if (state !== 'granted') {
        revoke(error('EACCES', 'local directory permission was revoked'));
      }
    }
    ensureOpen();
  }

  async function verifyConfined(childHandle) {
    ensureOpen();
    if (typeof rootHandle.resolve === 'function') {
      const rel = await rootHandle.resolve(childHandle);
      if (rel === null) {
        throw error('EACCES', 'entry left local mount during access');
      }
    }
  }

  async function runHost(fn) {
    await checkPermission();
    try {
      const value = await fn();
      await checkPermission();
      return value;
    } catch (reason) {
      if (['NotAllowedError', 'SecurityError'].includes(reason?.name)) {
        revoke(reason);
      }
      throw refusal(reason);
    }
  }

  function serializeFile(key, fn) {
    const prev = fileQueues.get(key) ?? Promise.resolve();
    const run = prev.then(fn, fn);
    const tail = run.catch(() => {});
    fileQueues.set(key, tail);
    tail.then(() => {
      if (fileQueues.get(key) === tail) fileQueues.delete(key);
    });
    return run;
  }

  async function resolveDirHandle(parts, create = false) {
    let dir = rootHandle;
    for (let i = 0; i < parts.length; i++) {
      try {
        dir = await dir.getDirectoryHandle(parts[i], create ? { create: true } : undefined);
      } catch (reason) {
        if (reason?.name === 'TypeMismatchError') throw error('ENOTDIR', 'not a directory');
        if (reason?.name === 'NotFoundError') throw error('ENOENT', 'no such directory');
        throw reason;
      }
      await verifyConfined(dir);
    }
    return dir;
  }

  async function resolveParent(path) {
    const segs = splitPath(path);
    if (!segs.length) throw error('EINVAL', 'empty entry name');
    const parent = await resolveDirHandle(segs.slice(0, -1), false);
    return { parent, name: segs[segs.length - 1] };
  }

  async function orphanDirHandle(create = false) {
    if (!originPrivate || !opfsRoot) throw error('EOPNOTSUPP', 'orphans require OPFS');
    const ns = currentUuid || 'default';
    const rootOrphans = await opfsRoot.getDirectoryHandle('os-orphans', { create: true });
    return rootOrphans.getDirectoryHandle(ns, create ? { create: true } : undefined);
  }

  async function resolveBackingFile(kind, target) {
    if (kind === 'orphan') {
      try {
        const dir = await orphanDirHandle(false);
        return await dir.getFileHandle(target);
      } catch (reason) {
        if (reason?.name === 'NotFoundError') throw error('ESTALE', 'orphan backing missing');
        throw reason;
      }
    }
    const segs = splitPath(target);
    if (!segs.length) throw error('EISDIR', 'root is a directory');
    try {
      const parent = await resolveDirHandle(segs.slice(0, -1), false);
      const fh = await parent.getFileHandle(segs[segs.length - 1]);
      await verifyConfined(fh);
      return fh;
    } catch (reason) {
      if (reason?.errno === 'ENOENT' || reason?.name === 'NotFoundError') {
        throw error('ESTALE', 'backing file was removed or renamed outside the OS');
      }
      if (reason?.name === 'TypeMismatchError') {
        throw error('ESTALE', 'backing file was replaced by a directory');
      }
      throw reason;
    }
  }

  async function resolveEntryHandle(path, isDir) {
    const segs = splitPath(path);
    if (!segs.length) return rootHandle;
    if (isDir) {
      return resolveDirHandle(segs, false);
    }
    return resolveBackingFile('path', path);
  }

  async function openValidatedBacking(kind, target, expectedFp, expectedIno) {
    const fh = await resolveBackingFile(kind, target);
    if (kind === 'path' && !originPrivate) {
      if (expectedIno !== undefined && expectedIno !== null) {
        const saved = await loadEntryHandle(expectedIno);
        if (!saved || !(await sameEntry(saved, fh))) {
          throw error('ESTALE', 'backing file identity changed outside the OS');
        }
      }
      const file = await fh.getFile();
      if (expectedFp && !fingerprintMatches(file, expectedFp)) {
        throw error('ESTALE', 'backing file changed outside the OS');
      }
      return { fh, file };
    }
    return { fh, file: null };
  }

  async function assertBackingUnchanged(target, fh, expectedFp, expectedIno) {
    const currentFh = await resolveBackingFile('path', target);
    if (!(await sameEntry(fh, currentFh))) {
      throw error('ESTALE', 'backing file was replaced during OS I/O');
    }
    await verifyConfined(fh);
    if (expectedIno !== undefined && expectedIno !== null) {
      const saved = await loadEntryHandle(expectedIno);
      if (!saved || !(await sameEntry(saved, currentFh))) {
        throw error('ESTALE', 'backing file identity changed during OS I/O');
      }
    }
    if (expectedFp) {
      const currentFile = await currentFh.getFile();
      if (!fingerprintMatches(currentFile, expectedFp)) {
        throw error('ESTALE', 'backing file modified externally during OS I/O');
      }
    }
  }

  async function hostEntryFromFileHandle(fh) {
    const file = await fh.getFile();
    const executable = await isWasmExecutable(file, execute);
    return {
      fileType: 'file',
      size: file.size,
      mtimeMs: typeof file.lastModified === 'number' ? file.lastModified : 0,
      executable,
    };
  }

  function dirHostEntry() {
    return {
      fileType: 'dir',
      size: 0,
      mtimeMs: 0,
      executable: false,
    };
  }

  async function copyFileHandle(srcFileHandle, destDirHandle, destName) {
    const srcFile = await srcFileHandle.getFile();
    const bytes = new Uint8Array(await srcFile.arrayBuffer());
    const destFileHandle = await destDirHandle.getFileHandle(destName, { create: true });
    const stream = await destFileHandle.createWritable({ keepExistingData: false });
    try {
      if (bytes.byteLength > 0) await stream.write(bytes);
      await stream.close();
    } catch (reason) {
      await stream.abort().catch(() => {});
      throw reason;
    }
    const after = await destFileHandle.getFile();
    return { size: after.size, mtimeMs: typeof after.lastModified === 'number' ? after.lastModified : 0 };
  }

  async function collectDirFingerprints(dirHandle, relPrefix, out) {
    for await (const [childName, childHandle] of dirHandle.entries()) {
      const childPath = relPrefix ? `${relPrefix}/${childName}` : childName;
      if (childHandle.kind === 'directory') {
        await collectDirFingerprints(childHandle, childPath, out);
      } else if (childHandle.kind === 'file') {
        const f = await childHandle.getFile();
        out.push([childPath, { size: f.size, mtimeMs: typeof f.lastModified === 'number' ? f.lastModified : 0 }]);
      }
    }
  }

  async function copyDirectoryRecursive(srcDir, destParent, destName, destRelPath, out) {
    const destDir = await destParent.getDirectoryHandle(destName, { create: true });
    for await (const [childName, childHandle] of srcDir.entries()) {
      const childRel = destRelPath ? `${destRelPath}/${childName}` : childName;
      if (childHandle.kind === 'directory') {
        await copyDirectoryRecursive(childHandle, destDir, childName, childRel, out);
      } else if (childHandle.kind === 'file') {
        const fp = await copyFileHandle(childHandle, destDir, childName);
        out.push([childRel, fp]);
      }
    }
  }

  return {
    setOnRevoke(fn) {
      onRevoke = typeof fn === 'function' ? fn : null;
    },

    close() {
      if (!closed) {
        closed = true;
        onRevoke = null;
        try { db.close(); } catch {}
        try { channel?.close(); } catch {}
      }
    },

    // --- HostTree ---
    statPath(path) {
      return runHost(async () => {
        const segs = splitPath(path);
        if (!segs.length) return dirHostEntry();
        let parent;
        try {
          parent = await resolveDirHandle(segs.slice(0, -1), false);
        } catch (err) {
          if (err?.errno === 'ENOENT') return null;
          throw err;
        }
        const name = segs[segs.length - 1];
        try {
          const dh = await parent.getDirectoryHandle(name);
          await verifyConfined(dh);
          return dirHostEntry();
        } catch (dirErr) {
          if (dirErr?.name === 'NotFoundError') return null;
          if (dirErr?.name !== 'TypeMismatchError') throw dirErr;
        }
        try {
          const fh = await parent.getFileHandle(name);
          await verifyConfined(fh);
          return await hostEntryFromFileHandle(fh);
        } catch (fileErr) {
          if (fileErr?.name === 'NotFoundError') return null;
          throw fileErr;
        }
      });
    },

    listDir(path) {
      return runHost(async () => {
        const dir = await resolveDirHandle(splitPath(path), false);
        const out = [];
        for await (const [name, entry] of dir.entries()) {
          await verifyConfined(entry);
          if (entry.kind === 'directory') {
            out.push([name, dirHostEntry()]);
          } else if (entry.kind === 'file') {
            out.push([name, await hostEntryFromFileHandle(entry)]);
          }
        }
        return out;
      });
    },

    createFile(path, createNew, truncate) {
      return runHost(async () => {
        const { parent, name } = await resolveParent(path);
        if (createNew) {
          let exists = false;
          try {
            await parent.getFileHandle(name);
            exists = true;
          } catch (err) {
            if (err?.name === 'TypeMismatchError') exists = true;
            else if (err?.name !== 'NotFoundError') throw err;
          }
          if (exists) throw error('EEXIST', 'file already exists');
        } else {
          try {
            await parent.getDirectoryHandle(name);
            throw error('EISDIR', 'path is a directory');
          } catch (err) {
            if (err?.errno === 'EISDIR') throw err;
            if (err?.name !== 'NotFoundError' && err?.name !== 'TypeMismatchError') throw err;
          }
        }

        const fh = await parent.getFileHandle(name, { create: true });
        try {
          await verifyConfined(fh);
          if (truncate) {
            await serializeFile(`path:${path}`, async () => {
              const stream = await fh.createWritable({ keepExistingData: false });
              try {
                await stream.close();
              } catch (err) {
                await stream.abort().catch(() => {});
                throw err;
              }
            });
          }
          return await hostEntryFromFileHandle(fh);
        } catch (err) {
          if (createNew) {
            await parent.removeEntry(name, { recursive: false }).catch(() => {});
          }
          throw err;
        }
      });
    },

    createDir(path) {
      return runHost(async () => {
        const { parent, name } = await resolveParent(path);
        let exists = false;
        try {
          await parent.getDirectoryHandle(name);
          exists = true;
        } catch (err) {
          if (err?.name === 'TypeMismatchError') exists = true;
          else if (err?.name !== 'NotFoundError') throw err;
        }
        if (exists) throw error('EEXIST', 'entry already exists');
        const dh = await parent.getDirectoryHandle(name, { create: true });
        try {
          await verifyConfined(dh);
        } catch (err) {
          await parent.removeEntry(name, { recursive: false }).catch(() => {});
          throw err;
        }
        return dirHostEntry();
      });
    },

    readFile(kind, target, offset, len, expectedFp = null, expectedIno = null) {
      return runHost(async () => {
        const key = `${kind}:${target}`;
        return serializeFile(key, async () => {
          const { fh, file: validatedFile } = await openValidatedBacking(
            kind,
            target,
            expectedFp,
            expectedIno,
          );
          const file = validatedFile ?? await fh.getFile();
          if (offset >= file.size || len <= 0) return new Uint8Array(0);
          const end = Math.min(file.size, offset + len);
          const buf = await file.slice(offset, end).arrayBuffer();
          if (kind === 'path' && !originPrivate) {
            await assertBackingUnchanged(target, fh, expectedFp, expectedIno);
          }
          return new Uint8Array(buf);
        });
      });
    },

    writeFile(kind, target, offset, data, append, expectedFp = null, expectedIno = null) {
      return runHost(async () => {
        const key = `${kind}:${target}`;
        return serializeFile(key, async () => {
          const { fh, file: validatedFile } = await openValidatedBacking(
            kind,
            target,
            expectedFp,
            expectedIno,
          );
          if (typeof fh.createWritable !== 'function') {
            throw error('EOPNOTSUPP', 'this browser cannot write local files');
          }
          const before = validatedFile ?? await fh.getFile();
          const pos = append ? before.size : offset;
          const stream = await fh.createWritable({ keepExistingData: true });
          try {
            if (data.byteLength > 0) {
              await stream.write({ type: 'write', position: pos, data });
            }
            if (kind === 'path' && !originPrivate) {
              await assertBackingUnchanged(target, fh, expectedFp, expectedIno);
            } else if (kind === 'path') {
              await verifyConfined(fh);
            }
            await stream.close();
          } catch (err) {
            await stream.abort().catch(() => {});
            throw err;
          }
          dirtyFiles.add(key);
          const after = await fh.getFile();
          return {
            offset: pos,
            len: data.byteLength,
            size: after.size,
            mtimeMs: typeof after.lastModified === 'number' ? after.lastModified : 0,
          };
        });
      });
    },

    setFileLen(kind, target, size, expectedFp = null, expectedIno = null) {
      return runHost(async () => {
        const key = `${kind}:${target}`;
        return serializeFile(key, async () => {
          const { fh } = await openValidatedBacking(
            kind,
            target,
            expectedFp,
            expectedIno,
          );
          if (typeof fh.createWritable !== 'function') {
            throw error('EOPNOTSUPP', 'this browser cannot truncate local files');
          }
          const stream = await fh.createWritable({ keepExistingData: true });
          try {
            await stream.truncate(size);
            if (kind === 'path' && !originPrivate) {
              await assertBackingUnchanged(target, fh, expectedFp, expectedIno);
            } else if (kind === 'path') {
              await verifyConfined(fh);
            }
            await stream.close();
          } catch (err) {
            await stream.abort().catch(() => {});
            throw err;
          }
          dirtyFiles.add(key);
          const after = await fh.getFile();
          return {
            size: after.size,
            mtimeMs: typeof after.lastModified === 'number' ? after.lastModified : 0,
          };
        });
      });
    },

    flushFile(kind, target, _dataOnly, expectedFp = null, expectedIno = null) {
      return runHost(async () => {
        const key = `${kind}:${target}`;
        return serializeFile(key, async () => {
          const { fh } = await openValidatedBacking(
            kind,
            target,
            expectedFp,
            expectedIno,
          );
          if (typeof fh.flush === 'function') {
            await fh.flush();
          } else if (originPrivate && typeof fh.createSyncAccessHandle === 'function') {
            const sh = await fh.createSyncAccessHandle();
            try {
              sh.flush();
            } finally {
              sh.close();
            }
          }
          dirtyFiles.delete(key);
          const after = await fh.getFile();
          return {
            size: after.size,
            mtimeMs: typeof after.lastModified === 'number' ? after.lastModified : 0,
          };
        });
      });
    },

    retainEntryHandle(ino, path, isDir) {
      return runHost(async () => {
        if (originPrivate) return;
        const entry = await resolveEntryHandle(path, isDir);
        await saveEntryHandle(ino, entry);
      });
    },

    verifyEntryHandle(ino, path, isDir) {
      return runHost(async () => {
        if (originPrivate) return true;
        const saved = await loadEntryHandle(ino);
        if (!saved) return false;
        let current;
        try {
          current = await resolveEntryHandle(path, isDir);
        } catch (err) {
          if (err?.errno === 'ENOENT' || err?.errno === 'ESTALE' || err?.errno === 'ENOTDIR') {
            return false;
          }
          throw err;
        }
        return sameEntry(saved, current);
      });
    },

    forgetEntryHandle(ino) {
      return runHost(async () => {
        if (originPrivate) return;
        await deleteEntryHandle(ino);
      });
    },

    removeFile(path) {
      return runHost(async () => {
        const { parent, name } = await resolveParent(path);
        try {
          await parent.getFileHandle(name);
        } catch (err) {
          if (err?.name === 'TypeMismatchError') throw error('EISDIR', 'path is a directory');
          if (err?.name === 'NotFoundError') return;
          throw err;
        }
        await parent.removeEntry(name, { recursive: false });
      });
    },

    removeDir(path) {
      return runHost(async () => {
        const { parent, name } = await resolveParent(path);
        try {
          await parent.getDirectoryHandle(name);
        } catch (err) {
          if (err?.name === 'TypeMismatchError') throw error('ENOTDIR', 'not a directory');
          if (err?.name === 'NotFoundError') return;
          throw err;
        }
        await parent.removeEntry(name, { recursive: false });
      });
    },

    moveEntry(from, to, isDir) {
      return runHost(async () => {
        const { parent: srcParent, name: srcName } = await resolveParent(from);
        const { parent: dstParent, name: dstName } = await resolveParent(to);
        const entry = isDir
          ? await srcParent.getDirectoryHandle(srcName)
          : await srcParent.getFileHandle(srcName);
        await verifyConfined(entry);

        if (typeof entry.move === 'function') {
          try {
            await entry.move(dstParent, dstName);
            const updates = [];
            if (isDir) {
              const movedDir = await dstParent.getDirectoryHandle(dstName);
              await collectDirFingerprints(movedDir, to, updates);
            } else {
              const movedFile = await dstParent.getFileHandle(dstName);
              const f = await movedFile.getFile();
              updates.push([to, { size: f.size, mtimeMs: typeof f.lastModified === 'number' ? f.lastModified : 0 }]);
            }
            return updates;
          } catch (moveErr) {
            if (!['NotSupportedError', 'InvalidModificationError', 'TypeError'].includes(moveErr?.name)) {
              throw moveErr;
            }
          }
        }

        // Remove destination only when falling back to directory copy; files overwrite atomically
        // via `createWritable` only when `stream.close()` succeeds.
        let removedDestDir = false;
        if (isDir) {
          try {
            await dstParent.removeEntry(dstName, { recursive: false });
            removedDestDir = true;
          } catch (err) {
            if (err?.name !== 'NotFoundError') throw err;
          }
        }

        const updates = [];
        try {
          if (isDir) {
            await copyDirectoryRecursive(entry, dstParent, dstName, to, updates);
            await srcParent.removeEntry(srcName, { recursive: true });
          } else {
            const fp = await copyFileHandle(entry, dstParent, dstName);
            updates.push([to, fp]);
            await srcParent.removeEntry(srcName, { recursive: false });
          }
        } catch (err) {
          if (isDir) {
            await dstParent.removeEntry(dstName, { recursive: true }).catch(() => {});
          }
          if (removedDestDir) {
            await dstParent.getDirectoryHandle(dstName, { create: true }).catch(() => {});
          }
          throw err;
        }
        return updates;
      });
    },

    moveToOrphan(path, inoStr) {
      return runHost(async () => {
        const { parent: srcParent, name: srcName } = await resolveParent(path);
        const fh = await srcParent.getFileHandle(srcName);
        await verifyConfined(fh);
        const orphanDir = await orphanDirHandle(true);
        if (typeof fh.move === 'function') {
          try {
            await fh.move(orphanDir, inoStr);
            return;
          } catch (moveErr) {
            if (!['NotSupportedError', 'InvalidModificationError', 'TypeError'].includes(moveErr?.name)) {
              throw moveErr;
            }
          }
        }
        await copyFileHandle(fh, orphanDir, inoStr);
        await srcParent.removeEntry(srcName, { recursive: false });
      });
    },

    restoreOrphan(inoStr, path) {
      return runHost(async () => {
        const orphanDir = await orphanDirHandle(false);
        const fh = await orphanDir.getFileHandle(inoStr);
        const { parent: dstParent, name: dstName } = await resolveParent(path);
        if (typeof fh.move === 'function') {
          try {
            await fh.move(dstParent, dstName);
            return;
          } catch (moveErr) {
            if (!['NotSupportedError', 'InvalidModificationError', 'TypeError'].includes(moveErr?.name)) {
              throw moveErr;
            }
          }
        }
        await copyFileHandle(fh, dstParent, dstName);
        await orphanDir.removeEntry(inoStr, { recursive: false });
      });
    },

    removeOrphan(inoStr) {
      return runHost(async () => {
        let orphanDir;
        try {
          orphanDir = await orphanDirHandle(false);
        } catch (err) {
          if (err?.name === 'NotFoundError') return;
          throw err;
        }
        await orphanDir.removeEntry(inoStr, { recursive: false }).catch(err => {
          if (err?.name !== 'NotFoundError') throw err;
        });
      });
    },

    listOrphans() {
      return runHost(async () => {
        let orphanDir;
        try {
          orphanDir = await orphanDirHandle(false);
        } catch (err) {
          if (err?.name === 'NotFoundError') return [];
          throw err;
        }
        const names = [];
        for await (const [name, entry] of orphanDir.entries()) {
          if (entry.kind === 'file') names.push(name);
        }
        return names;
      });
    },

    // --- MetaStore ---
    async readVersion() {
      ensureOpen();
      const tx = openTransaction(db, ['meta'], 'readonly');
      const v = await reqPromise(tx.objectStore('meta').get('version'));
      await txDone(tx);
      return v === undefined ? null : v;
    },

    async readHeader() {
      ensureOpen();
      const tx = openTransaction(db, ['meta'], 'readonly');
      const raw = await reqPromise(tx.objectStore('meta').get('header'));
      await txDone(tx);
      if (typeof raw === 'string') {
        try {
          const parsed = JSON.parse(raw);
          if (typeof parsed?.uuid === 'string' && parsed.uuid) currentUuid = parsed.uuid;
        } catch {}
        return raw;
      }
      return null;
    },

    async resetToCurrent(version, headerJson, rootIno, rootBacking, rootJson) {
      ensureOpen();
      try {
        const parsed = JSON.parse(headerJson);
        if (typeof parsed?.uuid === 'string' && parsed.uuid) currentUuid = parsed.uuid;
      } catch {}
      fallbackEntryMap(false)?.clear();
      const tx = openTransaction(db, ['meta', 'inodes', 'locks'], 'readwrite', true);
      const meta = tx.objectStore('meta');
      const inodes = tx.objectStore('inodes');
      const locks = tx.objectStore('locks');
      meta.clear();
      inodes.clear();
      locks.clear();
      meta.put(version, 'version');
      meta.put(headerJson, 'header');
      inodes.put({ ino: rootIno, backing: rootBacking, json: rootJson });
      await txDone(tx);
    },

    async mintUuid() {
      ensureOpen();
      if (fixedUuid) return fixedUuid;
      const u = crypto.randomUUID();
      currentUuid = u;
      return u;
    },

    async getInode(ino) {
      ensureOpen();
      const tx = openTransaction(db, ['inodes'], 'readonly');
      const row = await reqPromise(tx.objectStore('inodes').get(ino));
      await txDone(tx);
      return row?.json ?? null;
    },

    async findByBacking(path) {
      ensureOpen();
      const tx = openTransaction(db, ['inodes'], 'readonly');
      const row = await reqPromise(tx.objectStore('inodes').index('backing').get(path));
      await txDone(tx);
      return row?.json ?? null;
    },

    async listAllInodes() {
      ensureOpen();
      const tx = openTransaction(db, ['inodes'], 'readonly');
      const rows = await reqPromise(tx.objectStore('inodes').getAll());
      await txDone(tx);
      return (rows ?? []).map(r => r.json);
    },

    async getLocks(ino) {
      ensureOpen();
      const tx = openTransaction(db, ['locks'], 'readonly');
      const row = await reqPromise(tx.objectStore('locks').get(ino));
      await txDone(tx);
      return row?.json ?? null;
    },

    async listAllLocks() {
      ensureOpen();
      const tx = openTransaction(db, ['locks'], 'readonly');
      const rows = await reqPromise(tx.objectStore('locks').getAll());
      await txDone(tx);
      return (rows ?? []).map(r => [r.ino, r.json]);
    },

    async commit(batch, strict) {
      ensureOpen();
      const tx = openTransaction(db, ['meta', 'inodes', 'locks'], 'readwrite', strict);
      const meta = tx.objectStore('meta');
      const inodes = tx.objectStore('inodes');
      const locks = tx.objectStore('locks');
      if (batch.version !== undefined && batch.version !== null) {
        meta.put(batch.version, 'version');
      }
      if (typeof batch.headerJson === 'string') {
        try {
          const parsed = JSON.parse(batch.headerJson);
          if (typeof parsed?.uuid === 'string' && parsed.uuid) currentUuid = parsed.uuid;
        } catch {}
        meta.put(batch.headerJson, 'header');
      }
      for (const ino of batch.deleteInodes ?? []) {
        inodes.delete(ino);
      }
      for (const row of batch.putInodes ?? []) {
        inodes.put({ ino: row.ino, backing: row.backing ?? null, json: row.json });
      }
      for (const ino of batch.deleteLocks ?? []) {
        locks.delete(ino);
      }
      for (const row of batch.putLocks ?? []) {
        locks.put({ ino: row.ino, json: row.json });
      }
      await txDone(tx);
    },

    async syncStrict() {
      ensureOpen();
      const tx = openTransaction(db, ['meta'], 'readwrite', true);
      tx.objectStore('meta').put(Date.now(), 'lastSync');
      await txDone(tx);
    },

    // --- ProfileLocks ---
    startAcquireLock(name, shared) {
      const locks = getWebLocks(locksOption, name);
      const controller = new AbortController();
      let cancelled = false;
      let releaseFn = null;
      const cancel = () => {
        cancelled = true;
        if (releaseFn) {
          const fn = releaseFn;
          releaseFn = null;
          fn();
        } else {
          controller.abort();
        }
      };
      const promise = new Promise((resolveAcquire, rejectAcquire) => {
        locks
          .request(name, { mode: shared ? 'shared' : 'exclusive', signal: controller.signal }, () => {
            if (cancelled) {
              resolveAcquire(() => {});
              return;
            }
            return new Promise(releaseLock => {
              releaseFn = () => {
                releaseFn = null;
                releaseLock();
              };
              resolveAcquire(() => {
                if (releaseFn) releaseFn();
              });
            });
          })
          .catch(err => {
            if (cancelled || err?.name === 'AbortError') return;
            rejectAcquire(lockRefusal(err));
          });
      });
      return { promise, cancel };
    },

    tryAcquireLock(name, shared) {
      const locks = getWebLocks(locksOption, name);
      return new Promise((resolveAcquire, rejectAcquire) => {
        locks
          .request(name, { mode: shared ? 'shared' : 'exclusive', ifAvailable: true }, lock => {
            if (!lock) {
              resolveAcquire(null);
              return;
            }
            return new Promise(releaseLock => {
              let done = false;
              resolveAcquire(() => {
                if (!done) {
                  done = true;
                  releaseLock();
                }
              });
            });
          })
          .catch(err => rejectAcquire(lockRefusal(err)));
      });
    },

    async heldLocks() {
      const locks = getWebLocks(locksOption, 'os-fs-lock:query');
      const snap = await locks.query().catch(err => {
        throw lockRefusal(err);
      });
      return (snap?.held ?? []).map(item => item.name).filter(Boolean);
    },

    notifyLocks() {
      try {
        channel?.postMessage({ type: 'wake' });
      } catch {}
      for (const wake of [...localLockListeners]) {
        try { wake(); } catch {}
      }
    },

    startWaitForChange(blockingLocks) {
      const locks = getWebLocks(locksOption, 'os-fs-wait:watch');
      const controller = new AbortController();
      let settled = false;
      let finishFn = null;

      const cleanup = () => {
        if (settled) return;
        settled = true;
        controller.abort();
        if (finishFn) {
          localLockListeners.delete(finishFn);
          channel?.removeEventListener?.('message', finishFn);
        }
      };

      const promise = new Promise((resolve, reject) => {
        finishFn = () => {
          if (settled) return;
          cleanup();
          resolve();
        };
        localLockListeners.add(finishFn);
        channel?.addEventListener?.('message', finishFn);

        // Also subscribe via shared Web Locks on each blocking `os-fs-open` lock so an abrupt tab
        // crash (which releases Web Locks without posting to BroadcastChannel) wakes immediately!
        for (const lockName of blockingLocks ?? []) {
          locks
            .request(lockName, { mode: 'shared', signal: controller.signal }, () => {})
            .then(finishFn, err => {
              if (!settled && err?.name !== 'AbortError') {
                cleanup();
                reject(lockRefusal(err));
              }
            });
        }
      });

      return { promise, cancel: cleanup };
    },

    newTicket() {
      return crypto.randomUUID();
    },
  };
}

export async function createOpfsStore(handle, { execute = false, writable = true, indexedDB: idbOpt, locks: locksOpt } = {}) {
  if (typeof execute !== 'boolean' || typeof writable !== 'boolean') {
    throw error('EINVAL', 'invalid browser storage mount options');
  }
  if (!globalThis.navigator?.storage?.getDirectory) {
    throw error('ENOTSUP', 'Browser storage is unavailable in this session. Use a regular browser window or mount a host folder.');
  }
  const opfsRoot = await navigator.storage.getDirectory().catch(reason => {
    throw refusal(reason);
  });
  let rootHandle = handle;
  let storeKey = 'os-workspace';
  if (rootHandle) {
    if (
      rootHandle?.kind !== 'directory' ||
      ['resolve', 'entries', 'getDirectoryHandle', 'getFileHandle'].some(name => typeof rootHandle[name] !== 'function')
    ) {
      throw error('EINVAL', 'a directory handle is required');
    }
    const rel = await opfsRoot.resolve(rootHandle);
    if (rel === null) throw error('EACCES', 'handle is outside browser storage');
    if (rel.length === 0) throw error('EACCES', 'cannot mount browser storage root');
    if (rel[0] === 'os-orphans') throw error('EACCES', 'cannot mount internal orphan storage');
    if (rel.length > 1) {
      throw error('EACCES', 'cannot mount a nested subdirectory inside browser storage');
    }
    storeKey = rel[0];
  } else {
    rootHandle = await opfsRoot.getDirectoryHandle('os-workspace', { create: true });
  }

  const idb = getIdb(idbOpt);
  getWebLocks(locksOpt, 'os-fs-mint');
  const dbName = `os-fs-opfs:${storeKey}`;
  const db = await openMetaDb(idb, dbName);
  return buildStore({
    rootHandle,
    opfsRoot,
    originPrivate: true,
    execute,
    writable,
    db,
    dbName,
    fixedUuid: null,
    locksOption: locksOpt,
  });
}

export async function createDirectoryStore(handle, { execute = false, writable = false, indexedDB: idbOpt, locks: locksOpt } = {}) {
  if (typeof execute !== 'boolean' || typeof writable !== 'boolean') {
    throw error('EINVAL', 'invalid local mount options');
  }
  if (
    handle?.kind !== 'directory' ||
    ['resolve', 'entries', 'getDirectoryHandle', 'getFileHandle'].some(name => typeof handle[name] !== 'function')
  ) {
    throw error('EINVAL', 'a directory handle is required');
  }
  if (typeof handle.queryPermission !== 'function') {
    throw error('ENOTSUP', 'directory permissions cannot be checked');
  }
  if (globalThis.navigator?.storage?.getDirectory) {
    const opfsRoot = await navigator.storage.getDirectory().catch(() => null);
    if (opfsRoot && (await opfsRoot.resolve(handle).catch(() => null)) !== null) {
      throw error('EACCES', 'browser storage handles must use browser storage mount');
    }
  }

  let perm;
  try {
    perm = await handle.queryPermission({ mode: writable ? 'readwrite' : 'read' });
  } catch (reason) {
    throw refusal(reason);
  }
  if (perm !== 'granted') {
    throw error('EACCES', 'local directory permission was not granted');
  }

  const idb = getIdb(idbOpt);
  const locks = getWebLocks(locksOpt, 'os-fs-mint');
  const uuid = await resolveDirectoryUuid(handle, { idb, locks });
  const dbName = `os-fs-dir:${uuid}`;
  const db = await openMetaDb(idb, dbName);

  return buildStore({
    rootHandle: handle,
    opfsRoot: null,
    originPrivate: false,
    execute,
    writable,
    db,
    dbName,
    fixedUuid: uuid,
    locksOption: locksOpt,
  });
}

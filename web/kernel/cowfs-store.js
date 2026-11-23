// Browser OPFS immutable `COWP` packs + IndexedDB `{durability: "strict"}` HeadStore + Web Locks
// (`os-vol:<uuid>`, `os-cowfs-gc`) host adapter for `os-cowfs` (contract §2.5, §2.12, §2.15, #77).
//
// Zero portable filesystem policy lives here: all CoW B+tree SHA-256 verification, POSIX modes/
// ACLs/xattrs, `DIR_INDEX` paging, `ORPHAN_ITEM` reaping, `FICLONE`, `32 MiB` arena accounting,
// GC reachability, and `cowfsck` execute in Rust (`os-cowtree` + `os-cowfs`).

export const COWFS_FORMAT_VERSION = 1;
export const PACK_MAX_BYTES = 8 * 1024 * 1024;
const DEFAULT_DB_NAME = 'os-cowfs-v1';
const PACKS_DIR_ROOT = ['os-cowfs', 'packs'];
const DEFAULT_GRACE_WINDOW_SECS = 600;
const IDB_SCHEMA_VERSION = 2;

const errnoError = (errno, message = errno) => Object.assign(new Error(message), { errno });

function mapDomError(reason) {
  if (reason?.errno) return reason;
  const errno = {
    QuotaExceededError: 'ENOSPC',
    NotFoundError: 'ENOENT',
    ConstraintError: 'EEXIST',
    NotAllowedError: 'EACCES',
    SecurityError: 'EACCES',
    NoModificationAllowedError: 'EBUSY',
    InvalidModificationError: 'ENOTEMPTY',
    NotSupportedError: 'EOPNOTSUPP',
    NotReadableError: 'EIO',
    InvalidStateError: 'EIO',
    AbortError: 'EIO',
  }[reason?.name] ?? 'EIO';
  return errnoError(errno, reason?.message ?? 'cowfs browser storage operation failed');
}

function bytesToHex(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}

function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0) {
    throw errnoError('EINVAL', 'invalid hex digest');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function digestArrayToHex(arr) {
  if (typeof arr === 'string') return arr;
  return bytesToHex(arr instanceof Uint8Array ? arr : Uint8Array.from(arr));
}

async function sha256Hex(bytes) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle || typeof subtle.digest !== 'function') {
    throw errnoError('EOPNOTSUPP', 'WebCrypto SHA-256 is unavailable');
  }
  const input = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  const digest = await subtle.digest('SHA-256', input);
  return bytesToHex(new Uint8Array(digest));
}

function randomId() {
  if (typeof globalThis.crypto?.randomUUID === 'function') {
    return globalThis.crypto.randomUUID();
  }
  if (typeof globalThis.crypto?.getRandomValues === 'function') {
    const buf = new Uint8Array(16);
    globalThis.crypto.getRandomValues(buf);
    return bytesToHex(buf);
  }
  throw errnoError('EOPNOTSUPP', 'CSPRNG is unavailable');
}

function reqPromise(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(mapDomError(req.error));
  });
}

function forEachCursor(store, onRecord) {
  return new Promise((resolve, reject) => {
    const req = store.openCursor();
    req.onsuccess = () => {
      const cursor = req.result;
      if (!cursor) {
        resolve();
        return;
      }
      try {
        onRecord(cursor);
        cursor.continue();
      } catch (err) {
        reject(mapDomError(err));
      }
    };
    req.onerror = () => reject(mapDomError(req.error));
  });
}

const TX_DONE = Symbol('os.cowfs.txDone');

function openTx(db, stores, mode, strict = false) {
  let tx;
  if (strict && mode === 'readwrite') {
    // Contract §2.15: NEVER silently fall back from `{ durability: 'strict' }` to relaxed/default!
    try {
      tx = db.transaction(stores, mode, { durability: 'strict' });
    } catch (err) {
      if (err?.name === 'TypeError' || err?.name === 'NotSupportedError') {
        throw errnoError('EOPNOTSUPP', 'IndexedDB strict durability transactions are unsupported');
      }
      throw mapDomError(err);
    }
    if (tx.durability !== undefined && tx.durability !== 'strict') {
      try { tx.abort(); } catch {}
      throw errnoError(
        'EOPNOTSUPP',
        `IndexedDB returned durability=${tx.durability} instead of strict`,
      );
    }
  } else {
    try {
      tx = db.transaction(stores, mode);
    } catch (err) {
      throw mapDomError(err);
    }
  }
  const done = new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(mapDomError(tx.error));
    tx.onabort = () => reject(mapDomError(tx.error ?? new Error('IndexedDB transaction aborted')));
  });
  done.catch(() => {});
  tx[TX_DONE] = done;
  return tx;
}

function txDone(tx) {
  return tx[TX_DONE];
}

function openCowfsDb(idb, dbName) {
  return new Promise((resolve, reject) => {
    const req = idb.open(dbName, IDB_SCHEMA_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('meta')) {
        db.createObjectStore('meta');
      }
      if (!db.objectStoreNames.contains('heads')) {
        db.createObjectStore('heads', { keyPath: 'volume' });
      }
      if (!db.objectStoreNames.contains('nodes')) {
        db.createObjectStore('nodes', { keyPath: 'digest' });
      }
      if (!db.objectStoreNames.contains('packs')) {
        db.createObjectStore('packs', { keyPath: 'packId' });
      }
      if (!db.objectStoreNames.contains('blocks')) {
        db.createObjectStore('blocks', { keyPath: 'digest' });
      }
      if (!db.objectStoreNames.contains('snapshots')) {
        const s = db.createObjectStore('snapshots', { keyPath: 'key' });
        s.createIndex('volume', 'volume', { unique: false });
      }
      if (!db.objectStoreNames.contains('receipts')) {
        db.createObjectStore('receipts', { keyPath: 'opId' });
      }
      if (!db.objectStoreNames.contains('gracePins')) {
        db.createObjectStore('gracePins', { keyPath: 'id', autoIncrement: true });
      }
      if (!db.objectStoreNames.contains('roPins')) {
        db.createObjectStore('roPins', { keyPath: 'pinId' });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(mapDomError(req.error));
    req.onblocked = () => reject(errnoError('EBUSY', 'cowfs IndexedDB open blocked'));
  });
}

function tsGt(a, b) {
  if (!a || !b) return false;
  return a.sec > b.sec || (a.sec === b.sec && a.nsec > b.nsec);
}

function tsExpired(createdAt, now, graceWindowSecs) {
  if (!createdAt || !now) return true;
  const expSec = (createdAt.sec ?? 0) + (graceWindowSecs ?? 0);
  const nowSec = now.sec ?? 0;
  return expSec < nowSec || (expSec === nowSec && (createdAt.nsec ?? 0) <= (now.nsec ?? 0));
}

/**
 * Create a browser OPFS + IndexedDB (`{durability: "strict"}`) + Web Locks `os-cowfs` store.
 *
 * @param {object} [options]
 * @param {string} [options.dbName] IndexedDB database name (default `'os-cowfs-v1'`)
 * @param {IDBFactory} [options.idb] Override `indexedDB` (for Node.js unit tests)
 * @param {LockManager} [options.locks] Override `navigator.locks` (for Node.js unit tests)
 * @param {FileSystemDirectoryHandle} [options.opfsRoot] Override `navigator.storage.getDirectory()`
 * @param {object} [options.storage] Override `navigator.storage` (for `persist()` / `estimate()`)
 * @param {number} [options.graceWindowSecs] GC grace window seconds (default 600)
 * @param {object} [options.hooks] Optional test fault-injection hooks (`onWritePack`, `onCommitHead`, `onReadPackRange`)
 */
export function createCowfsStore(options = {}) {
  const dbName = options.dbName ?? DEFAULT_DB_NAME;
  const graceWindowSecs = options.graceWindowSecs ?? DEFAULT_GRACE_WINDOW_SECS;
  const hooks = options.hooks ?? {};
  const idbFactory = options.idb ?? globalThis.indexedDB;
  const locksApi = options.locks ?? globalThis.navigator?.locks;
  const storageApi = options.storage ?? globalThis.navigator?.storage;

  let dbPromise = null;
  let dbKeyPromise = null;
  let packsDirPromise = null;
  let persistRequested = false;
  let nextLeaseSeq = 1;
  let nextGcSeq = 1;

  // Active held Web Lock releasers keyed by leaseId / gcLockId / roPinId.
  const writerReleasers = new Map();
  const gcReleasers = new Map();
  const roPinReleasers = new Map();
  const lockReleasePromises = new Set();

  // Telemetry counters for verification tests (zero-copy snapshot/fork/FICLONE assertions).
  const stats = {
    packWrites: 0,
    packBytesWritten: 0,
    packBytesRead: 0,
    commits: 0,
    syncHandleWrites: 0,
    sliceReads: 0,
    persistCalled: false,
  };

  async function getDbKey() {
    if (!dbKeyPromise) {
      dbKeyPromise = sha256Hex(new TextEncoder().encode(`os-cowfs-db-v1:${dbName}`)).catch(err => {
        dbKeyPromise = null;
        throw err;
      });
    }
    return dbKeyPromise;
  }

  async function volLockName(volume) {
    if (dbName === DEFAULT_DB_NAME) {
      return `os-vol:${volume}`;
    }
    const key = await getDbKey();
    return `os-vol:${key.slice(0, 16)}:${volume}`;
  }

  async function gcLockName() {
    const key = await getDbKey();
    return `os-cowfs-gc:${key.slice(0, 16)}`;
  }

  async function roPinLockName(pinId) {
    const key = await getDbKey();
    return `os-cowfs-ro:${key.slice(0, 16)}:${pinId}`;
  }

  async function packLockName(packId) {
    const key = await getDbKey();
    return `os-cowfs-pack:${key.slice(0, 16)}:${packId}`;
  }

  async function getDb() {
    if (!idbFactory || typeof idbFactory.open !== 'function') {
      throw errnoError('EOPNOTSUPP', 'IndexedDB is unavailable');
    }
    if (!dbPromise) {
      dbPromise = (async () => {
        const db = await openCowfsDb(idbFactory, dbName);
        // Verify `{ durability: 'strict' }` support immediately on store open so relaxed/unsupported
        // backends fail closed rather than silently acknowledging non-durable commits.
        const probe = openTx(db, ['meta'], 'readwrite', true);
        await Promise.all([
          reqPromise(probe.objectStore('meta').get('format_version')),
          txDone(probe),
        ]);
        return db;
      })().catch(err => {
        dbPromise = null;
        throw mapDomError(err);
      });
    }
    return dbPromise;
  }

  async function getPacksDir() {
    if (!packsDirPromise) {
      packsDirPromise = (async () => {
        let dir = options.opfsRoot;
        if (!dir) {
          if (!storageApi || typeof storageApi.getDirectory !== 'function') {
            throw errnoError('EOPNOTSUPP', 'OPFS is unavailable');
          }
          dir = await storageApi.getDirectory();
        }
        const dbKey = await getDbKey();
        for (const seg of [...PACKS_DIR_ROOT, dbKey]) {
          dir = await dir.getDirectoryHandle(seg, { create: true });
        }
        return dir;
      })().catch(err => {
        packsDirPromise = null;
        throw mapDomError(err);
      });
    }
    return packsDirPromise;
  }

  async function ensurePersisted() {
    if (persistRequested) return;
    persistRequested = true;
    stats.persistCalled = true;
    if (storageApi && typeof storageApi.persist === 'function') {
      try {
        await storageApi.persist();
      } catch {
        // Best effort; browser permission or headless context may decline.
      }
    }
  }

  async function checkQuotaEstimate(neededBytes = 0) {
    if (storageApi && typeof storageApi.estimate === 'function') {
      try {
        const est = await storageApi.estimate();
        if (
          typeof est?.quota === 'number' &&
          typeof est?.usage === 'number' &&
          est.quota > 0 &&
          est.usage + neededBytes > est.quota
        ) {
          throw errnoError('ENOSPC', 'browser storage quota exhausted');
        }
      } catch (err) {
        if (err?.errno === 'ENOSPC') throw err;
      }
    }
  }

  async function formatVersion() {
    const db = await getDb();
    const tx = openTx(db, ['meta'], 'readonly');
    const [ver] = await Promise.all([
      reqPromise(tx.objectStore('meta').get('format_version')),
      txDone(tx),
    ]);
    return ver === undefined || ver === null ? null : Number(ver);
  }

  async function ensureFormatCompatible() {
    const ver = await formatVersion();
    if (ver !== null && ver !== COWFS_FORMAT_VERSION) {
      throw errnoError(
        'EPROTONOSUPPORT',
        `incompatible os-cowfs format version ${ver} (expected ${COWFS_FORMAT_VERSION}); volume preserved untouched`,
      );
    }
  }

  async function createVolume(headJson, initialNodes = []) {
    await ensureFormatCompatible();
    await ensurePersisted();
    const head = typeof headJson === 'string' ? JSON.parse(headJson) : headJson;
    if (head.format_version !== COWFS_FORMAT_VERSION) {
      throw errnoError('EPROTONOSUPPORT', 'incompatible volume format_version');
    }
    const db = await getDb();
    const tx = openTx(db, ['meta', 'heads', 'nodes'], 'readwrite', true);
    const metaStore = tx.objectStore('meta');
    const headsStore = tx.objectStore('heads');
    const nodesStore = tx.objectStore('nodes');

    const existing = await reqPromise(headsStore.get(head.volume));
    if (existing) {
      try { tx.abort(); } catch {}
      throw errnoError('EEXIST', `volume ${head.volume} already exists`);
    }
    metaStore.put(COWFS_FORMAT_VERSION, 'format_version');
    for (const node of initialNodes) {
      const bytes = node.bytes instanceof Uint8Array ? new Uint8Array(node.bytes) : Uint8Array.from(node.bytes);
      nodesStore.put({
        digest: node.digest,
        bytes,
        createdAt: head.updated_at,
      });
    }
    headsStore.add(head);
    await txDone(tx);
    return head;
  }

  async function readHead(volume) {
    await ensureFormatCompatible();
    const db = await getDb();
    const tx = openTx(db, ['heads'], 'readonly');
    const [head] = await Promise.all([
      reqPromise(tx.objectStore('heads').get(volume)),
      txDone(tx),
    ]);
    if (!head) {
      throw errnoError('ENOENT', `volume ${volume} not found`);
    }
    if (head.format_version !== COWFS_FORMAT_VERSION) {
      throw errnoError('EPROTONOSUPPORT', 'incompatible volume head format_version');
    }
    return head;
  }

  function requestHeldWebLock(lockName, opts) {
    if (!locksApi || typeof locksApi.request !== 'function') {
      throw errnoError('ENOLCK', 'Web Locks API is unavailable');
    }
    return new Promise((resolve, reject) => {
      let settled = false;
      let releaseFn = null;
      const holdPromise = new Promise(r => {
        releaseFn = r;
      });
      let req;
      try {
        req = locksApi.request(lockName, opts, lock => {
          if (!lock) {
            if (!settled) {
              settled = true;
              resolve(null);
            }
            return;
          }
          queueMicrotask(() => {
            if (!settled) {
              settled = true;
              resolve({ release: releaseFn, done: req });
            }
          });
          return holdPromise;
        });
      } catch (err) {
        reject(mapDomError(err));
        return;
      }
      req.catch(err => {
        if (!settled) {
          settled = true;
          reject(mapDomError(err));
        }
      });
    });
  }

  function releaseHeldLock(held) {
    if (!held) return;
    held.release();
    if (held.done) {
      const p = held.done.catch(() => {});
      lockReleasePromises.add(p);
      p.finally(() => lockReleasePromises.delete(p));
    }
  }

  async function pinRoRoot(volume, snapshot = null) {
    await ensureFormatCompatible();
    const gcLockId = await acquireGcLock(false);
    let pinLock = null;
    try {
      const pinId = randomId();
      const lName = await roPinLockName(pinId);
      pinLock = await requestHeldWebLock(lName, { mode: 'exclusive', ifAvailable: true });
      if (!pinLock) {
        throw errnoError('ENOLCK', 'failed to acquire RO root pin lock');
      }
      const db = await getDb();
      const tx = openTx(db, ['heads', 'snapshots', 'nodes', 'roPins'], 'readwrite', true);
      const headsStore = tx.objectStore('heads');
      const snapsStore = tx.objectStore('snapshots');
      const nodesStore = tx.objectStore('nodes');
      const pinsStore = tx.objectStore('roPins');

      const cur = await reqPromise(headsStore.get(volume));
      if (!cur) {
        try { tx.abort(); } catch {}
        throw errnoError('ENOENT', `volume ${volume} not found`);
      }
      if (cur.format_version !== COWFS_FORMAT_VERSION) {
        try { tx.abort(); } catch {}
        throw errnoError('EPROTONOSUPPORT', 'incompatible volume head format_version');
      }
      const pinnedHead = { ...cur };
      if (snapshot !== null && snapshot !== undefined) {
        const snap = await reqPromise(snapsStore.get(`${volume}\0${snapshot}`));
        if (!snap) {
          try { tx.abort(); } catch {}
          throw errnoError('ENOENT', `snapshot ${snapshot} not found`);
        }
        pinnedHead.root = snap.root;
        pinnedHead.epoch = snap.epoch;
        pinnedHead.updated_at = snap.created_at;
      }
      const rootHex = digestArrayToHex(pinnedHead.root);
      const rootNode = await reqPromise(nodesStore.get(rootHex));
      if (!rootNode) {
        try { tx.abort(); } catch {}
        throw errnoError('ENOENT', 'pinned root node missing');
      }
      pinsStore.put({ pinId, volume, root: pinnedHead.root });
      await txDone(tx);
      roPinReleasers.set(pinId, pinLock);
      return { pinId, head: pinnedHead };
    } catch (err) {
      if (pinLock) releaseHeldLock(pinLock);
      throw err;
    } finally {
      releaseGcLock(gcLockId);
    }
  }

  function unpinRoRootSync(pinId) {
    const held = roPinReleasers.get(pinId);
    if (held) {
      roPinReleasers.delete(pinId);
      releaseHeldLock(held);
    }
    // Best-effort async delete of IDB record; GC also reaps any record whose Web Lock is free.
    getDb()
      .then(db => {
        const tx = openTx(db, ['roPins'], 'readwrite', true);
        tx.objectStore('roPins').delete(pinId);
        return txDone(tx);
      })
      .catch(() => {});
  }

  async function unpinRoRoot(pinId) {
    const held = roPinReleasers.get(pinId);
    if (held) {
      roPinReleasers.delete(pinId);
      releaseHeldLock(held);
    }
    try {
      const db = await getDb();
      const tx = openTx(db, ['roPins'], 'readwrite', true);
      tx.objectStore('roPins').delete(pinId);
      await txDone(tx);
    } catch {
      // Lock is already released; GC will reap any leftover row.
    }
    await flushLocks();
  }

  async function acquireWriter(volume, mode = 'exclusive') {
    await ensureFormatCompatible();
    // Hold shared GC lock across head inspection + writer lock / fork creation so concurrent GC
    // cannot sweep objects reachable from the selected root or prune the head mid-acquisition.
    const gcLockId = await acquireGcLock(false);
    try {
      await readHead(volume);
      const lockName = await volLockName(volume);

      if (mode === 'force-takeover') {
        // Fail closed if Web Lock steal cannot be established: NEVER issue a writer lease without
        // an active exclusion lock (`held == null` would permit split-brain writers once the prior
        // holder exits).
        let held;
        try {
          held = await requestHeldWebLock(lockName, { mode: 'exclusive', steal: true });
        } catch (err) {
          throw err?.errno ? err : errnoError('ENOLCK', 'force-takeover failed to steal writer lock');
        }
        if (!held) {
          throw errnoError('ENOLCK', 'force-takeover did not acquire writer lock');
        }
        try {
          const db = await getDb();
          const tx = openTx(db, ['heads'], 'readwrite', true);
          const headsStore = tx.objectStore('heads');
          const cur = await reqPromise(headsStore.get(volume));
          if (!cur) {
            try { tx.abort(); } catch {}
            throw errnoError('ENOENT', `volume ${volume} not found`);
          }
          if (cur.format_version !== COWFS_FORMAT_VERSION) {
            try { tx.abort(); } catch {}
            throw errnoError('EPROTONOSUPPORT', 'incompatible volume head format_version');
          }
          const nextHead = { ...cur, fence: Number(cur.fence) + 1 };
          headsStore.put(nextHead);
          await txDone(tx);

          const leaseId = `lease-${nextLeaseSeq++}`;
          writerReleasers.set(leaseId, held);
          return {
            leaseId,
            volume: nextHead.volume,
            incarnation: nextHead.incarnation,
            fence: nextHead.fence,
            epoch: nextHead.epoch,
            head: nextHead,
            forkedFrom: null,
            expiresAt: null,
          };
        } catch (err) {
          releaseHeldLock(held);
          throw err;
        }
      }

      const held = await requestHeldWebLock(lockName, { mode: 'exclusive', ifAvailable: true });
      if (held) {
        try {
          const latest = await readHead(volume);
          const leaseId = `lease-${nextLeaseSeq++}`;
          writerReleasers.set(leaseId, held);
          return {
            leaseId,
            volume: latest.volume,
            incarnation: latest.incarnation,
            fence: latest.fence,
            epoch: latest.epoch,
            head: latest,
            forkedFrom: null,
            expiresAt: null,
          };
        } catch (err) {
          releaseHeldLock(held);
          throw err;
        }
      }

      if (mode === 'exclusive') {
        throw errnoError('EBUSY', `volume ${volume} writer lock is held by another tab`);
      }

      if (mode === 'fork-on-busy') {
        const db = await getDb();
        for (let attempt = 0; attempt < 16; attempt++) {
          const forkVol = `${volume}-fork-${randomId()}`;
          const forkLockName = await volLockName(forkVol);
          const forkLock = await requestHeldWebLock(forkLockName, {
            mode: 'exclusive',
            ifAvailable: true,
          });
          if (!forkLock) continue;
          try {
            const tx = openTx(db, ['heads', 'nodes'], 'readwrite', true);
            const headsStore = tx.objectStore('heads');
            const nodesStore = tx.objectStore('nodes');
            const latest = await reqPromise(headsStore.get(volume));
            if (!latest) {
              try { tx.abort(); } catch {}
              throw errnoError('ENOENT', `volume ${volume} not found`);
            }
            if (latest.format_version !== COWFS_FORMAT_VERSION) {
              try { tx.abort(); } catch {}
              throw errnoError('EPROTONOSUPPORT', 'incompatible volume head format_version');
            }
            const rootHex = digestArrayToHex(latest.root);
            const rootNode = await reqPromise(nodesStore.get(rootHex));
            if (!rootNode) {
              try { tx.abort(); } catch {}
              throw errnoError('ENOENT', 'source root missing');
            }
            const forkHead = {
              format_version: COWFS_FORMAT_VERSION,
              volume: forkVol,
              incarnation: 1,
              fence: 1,
              epoch: 0,
              root: latest.root,
              parent_volume: volume,
              ephemeral_if_unmodified: true,
              modified: false,
              updated_at: latest.updated_at,
            };
            // Create-only `add()` NEVER overwrites an existing volume head.
            await reqPromise(headsStore.add(forkHead));
            await txDone(tx);

            const leaseId = `lease-${nextLeaseSeq++}`;
            writerReleasers.set(leaseId, forkLock);
            return {
              leaseId,
              volume: forkHead.volume,
              incarnation: forkHead.incarnation,
              fence: forkHead.fence,
              epoch: forkHead.epoch,
              head: forkHead,
              forkedFrom: volume,
              expiresAt: null,
            };
          } catch (err) {
            releaseHeldLock(forkLock);
            if (err?.errno === 'EEXIST') continue;
            throw err;
          }
        }
        throw errnoError('EEXIST', `failed to allocate unique fork name for ${volume}`);
      }

      throw errnoError('EINVAL', `unknown writer mode: ${mode}`);
    } finally {
      releaseGcLock(gcLockId);
    }
  }

  async function renewWriter(payloadJson) {
    const req = typeof payloadJson === 'string' ? JSON.parse(payloadJson) : payloadJson;
    const cur = await readHead(req.volume);
    if (cur.incarnation !== req.incarnation || cur.fence !== req.fence) {
      throw errnoError('ESTALE', 'writer lease fenced');
    }
  }

  function releaseWriter(leaseId) {
    const held = writerReleasers.get(leaseId);
    if (!held) return;
    writerReleasers.delete(leaseId);
    releaseHeldLock(held);
  }

  async function flushLocks() {
    if (lockReleasePromises.size > 0) {
      await Promise.all([...lockReleasePromises]);
    }
  }

  async function getNode(digestHex) {
    const db = await getDb();
    const tx = openTx(db, ['nodes'], 'readonly');
    const [row] = await Promise.all([
      reqPromise(tx.objectStore('nodes').get(digestHex)),
      txDone(tx),
    ]);
    if (!row) {
      throw errnoError('ENOENT', `node ${digestHex} not found`);
    }
    return row.bytes instanceof Uint8Array ? row.bytes : Uint8Array.from(row.bytes);
  }

  async function lookupBlock(digestHex) {
    const db = await getDb();
    const tx = openTx(db, ['blocks'], 'readonly');
    const [row] = await Promise.all([
      reqPromise(tx.objectStore('blocks').get(digestHex)),
      txDone(tx),
    ]);
    if (!row) return null;
    return {
      pack_id: row.packId,
      offset: row.offset,
      len: row.len,
      raw_len: row.rawLen,
      flags: row.flags,
    };
  }

  async function commitHead(metaJson, putNodes = []) {
    await ensureFormatCompatible();
    const meta = typeof metaJson === 'string' ? JSON.parse(metaJson) : metaJson;
    if (hooks.onCommitHead) {
      await hooks.onCommitHead(meta, putNodes);
    }
    let nodeBytesTotal = 0;
    for (const n of putNodes) nodeBytesTotal += n.bytes?.byteLength ?? n.bytes?.length ?? 0;
    await checkQuotaEstimate(nodeBytesTotal);

    const db = await getDb();
    const tx = openTx(
      db,
      ['heads', 'nodes', 'packs', 'blocks', 'receipts', 'gracePins'],
      'readwrite',
      true,
    );
    const headsStore = tx.objectStore('heads');
    const nodesStore = tx.objectStore('nodes');
    const packsStore = tx.objectStore('packs');
    const blocksStore = tx.objectStore('blocks');
    const receiptsStore = tx.objectStore('receipts');
    const graceStore = tx.objectStore('gracePins');

    // 1. Idempotency receipt check.
    const existingReceipt = await reqPromise(receiptsStore.get(meta.opId));
    if (existingReceipt) {
      await txDone(tx);
      if (existingReceipt.rootHex !== meta.newRoot) {
        throw errnoError('EINVAL', 'op_id reused with different root');
      }
      return existingReceipt.head;
    }

    // 2. Verify (incarnation, fence, epoch) CAS match.
    const cur = await reqPromise(headsStore.get(meta.volume));
    if (!cur) {
      try { tx.abort(); } catch {}
      throw errnoError('ENOENT', `volume ${meta.volume} not found`);
    }
    if (
      cur.incarnation !== meta.expectedIncarnation ||
      cur.fence !== meta.expectedFence ||
      cur.epoch !== meta.expectedEpoch
    ) {
      try { tx.abort(); } catch {}
      throw errnoError('ESTALE', 'writer fenced or epoch stale');
    }

    // 3. Insert put_nodes, put_packs, put_blocks.
    for (const node of putNodes) {
      const bytes = node.bytes instanceof Uint8Array ? new Uint8Array(node.bytes) : Uint8Array.from(node.bytes);
      nodesStore.put({
        digest: node.digest,
        bytes,
        createdAt: meta.committedAt,
      });
    }
    for (const pm of meta.putPacks ?? []) {
      packsStore.put({
        packId: pm.pack_id,
        size: pm.size,
        entryCount: pm.entry_count,
        createdAt: meta.committedAt,
      });
    }
    for (const blk of meta.putBlocks ?? []) {
      blocksStore.put({
        digest: blk.digest,
        packId: blk.packId,
        offset: blk.offset,
        len: blk.len,
        rawLen: blk.rawLen,
        flags: blk.flags,
      });
    }

    if (graceWindowSecs > 0) {
      graceStore.add({
        volume: meta.volume,
        root: cur.root,
        pinnedUntil: {
          sec: (meta.committedAt?.sec ?? 0) + graceWindowSecs,
          nsec: meta.committedAt?.nsec ?? 0,
        },
      });
    }

    // 4. Advance head atomically. Once a fork commits a user modification (`modified: true`),
    // it is retained permanently (`ephemeral_if_unmodified: false`) and surfaced in `listVolumes()`.
    const nextHead = {
      format_version: COWFS_FORMAT_VERSION,
      volume: meta.volume,
      incarnation: cur.incarnation,
      fence: cur.fence,
      epoch: cur.epoch + 1,
      root: [...hexToBytes(meta.newRoot)],
      parent_volume: cur.parent_volume ?? null,
      ephemeral_if_unmodified: false,
      modified: true,
      updated_at: meta.committedAt,
    };
    headsStore.put(nextHead);
    receiptsStore.put({
      opId: meta.opId,
      volume: meta.volume,
      epoch: nextHead.epoch,
      rootHex: meta.newRoot,
      head: nextHead,
      createdAt: meta.committedAt,
    });

    await txDone(tx);
    stats.commits += 1;
    return nextHead;
  }

  async function commitReceivedRoot(metaJson, putNodes = []) {
    await ensureFormatCompatible();
    const meta = typeof metaJson === 'string' ? JSON.parse(metaJson) : metaJson;
    if (meta.snapshotName && (meta.snapshotName.includes('/') || meta.snapshotName.includes('\0'))) {
      throw errnoError('EINVAL', 'invalid snapshot name');
    }
    let nodeBytesTotal = 0;
    for (const n of putNodes) nodeBytesTotal += n.bytes?.byteLength ?? n.bytes?.length ?? 0;
    await checkQuotaEstimate(nodeBytesTotal);

    const db = await getDb();
    const tx = openTx(
      db,
      ['meta', 'heads', 'nodes', 'packs', 'blocks', 'snapshots', 'receipts', 'gracePins'],
      'readwrite',
      true,
    );
    const metaStore = tx.objectStore('meta');
    const headsStore = tx.objectStore('heads');
    const nodesStore = tx.objectStore('nodes');
    const packsStore = tx.objectStore('packs');
    const blocksStore = tx.objectStore('blocks');
    const snapsStore = tx.objectStore('snapshots');
    const receiptsStore = tx.objectStore('receipts');
    const graceStore = tx.objectStore('gracePins');

    const storedVer = await reqPromise(metaStore.get('format_version'));
    if (storedVer === undefined) {
      metaStore.put(COWFS_FORMAT_VERSION, 'format_version');
    } else if (storedVer !== COWFS_FORMAT_VERSION) {
      try { tx.abort(); } catch {}
      throw errnoError('EPROTONOSUPPORT', `incompatible format version ${storedVer}`);
    }

    const existingReceipt = await reqPromise(receiptsStore.get(meta.opId));
    if (existingReceipt) {
      await txDone(tx);
      if (existingReceipt.rootHex !== meta.newRoot) {
        throw errnoError('EINVAL', 'op_id reused with different root');
      }
      return existingReceipt.head;
    }

    let nextHead;
    if (meta.expectedLease) {
      const cur = await reqPromise(headsStore.get(meta.volume));
      if (!cur) {
        try { tx.abort(); } catch {}
        throw errnoError('ENOENT', `volume ${meta.volume} not found`);
      }
      if (
        cur.incarnation !== meta.expectedLease.incarnation ||
        cur.fence !== meta.expectedLease.fence ||
        cur.epoch !== meta.expectedLease.epoch
      ) {
        try { tx.abort(); } catch {}
        throw errnoError('ESTALE', 'writer fenced or epoch stale');
      }
      if (meta.snapshotName) {
        const existingSnap = await reqPromise(snapsStore.get(`${meta.volume}\0${meta.snapshotName}`));
        if (existingSnap) {
          try { tx.abort(); } catch {}
          throw errnoError('EEXIST', `snapshot ${meta.snapshotName} already exists`);
        }
      }
      if (graceWindowSecs > 0) {
        graceStore.add({
          volume: meta.volume,
          root: cur.root,
          pinnedUntil: {
            sec: (meta.committedAt?.sec ?? 0) + graceWindowSecs,
            nsec: meta.committedAt?.nsec ?? 0,
          },
        });
      }
      nextHead = {
        format_version: COWFS_FORMAT_VERSION,
        volume: meta.volume,
        incarnation: cur.incarnation,
        fence: cur.fence,
        epoch: cur.epoch + 1,
        root: [...hexToBytes(meta.newRoot)],
        parent_volume: cur.parent_volume ?? null,
        ephemeral_if_unmodified: false,
        modified: true,
        updated_at: meta.committedAt,
      };
    } else {
      const existing = await reqPromise(headsStore.get(meta.volume));
      if (existing) {
        try { tx.abort(); } catch {}
        throw errnoError('EEXIST', `volume ${meta.volume} already exists`);
      }
      nextHead = {
        format_version: COWFS_FORMAT_VERSION,
        volume: meta.volume,
        incarnation: 1,
        fence: 1,
        epoch: 0,
        root: [...hexToBytes(meta.newRoot)],
        parent_volume: null,
        ephemeral_if_unmodified: false,
        modified: true,
        updated_at: meta.committedAt,
      };
    }

    for (const node of putNodes) {
      const bytes = node.bytes instanceof Uint8Array ? new Uint8Array(node.bytes) : Uint8Array.from(node.bytes);
      nodesStore.put({
        digest: node.digest,
        bytes,
        createdAt: meta.committedAt,
      });
    }
    for (const pm of meta.putPacks ?? []) {
      packsStore.put({
        packId: pm.pack_id,
        size: pm.size,
        entryCount: pm.entry_count,
        createdAt: meta.committedAt,
      });
    }
    for (const blk of meta.putBlocks ?? []) {
      blocksStore.put({
        digest: blk.digest,
        packId: blk.packId,
        offset: blk.offset,
        len: blk.len,
        rawLen: blk.rawLen,
        flags: blk.flags,
      });
    }

    headsStore.put(nextHead);
    if (meta.snapshotName) {
      snapsStore.put({
        key: `${meta.volume}\0${meta.snapshotName}`,
        volume: meta.volume,
        name: meta.snapshotName,
        root: nextHead.root,
        epoch: nextHead.epoch,
        created_at: meta.committedAt,
      });
    }
    receiptsStore.put({
      opId: meta.opId,
      volume: meta.volume,
      epoch: nextHead.epoch,
      rootHex: meta.newRoot,
      head: nextHead,
      createdAt: meta.committedAt,
    });

    await txDone(tx);
    stats.commits += 1;
    return nextHead;
  }

  async function createSnapshot(payloadJson) {
    await ensureFormatCompatible();
    const { volume, name, head, now } = typeof payloadJson === 'string' ? JSON.parse(payloadJson) : payloadJson;
    if (!name || name.includes('/') || name.includes('\0')) {
      throw errnoError('EINVAL', 'invalid snapshot name');
    }
    const db = await getDb();
    const tx = openTx(db, ['snapshots'], 'readwrite', true);
    const store = tx.objectStore('snapshots');
    const key = `${volume}\0${name}`;
    const existing = await reqPromise(store.get(key));
    if (existing) {
      try { tx.abort(); } catch {}
      throw errnoError('EEXIST', `snapshot ${name} already exists`);
    }
    const record = {
      volume,
      name,
      root: head.root,
      epoch: head.epoch,
      created_at: now,
    };
    store.put({ key, ...record });
    await txDone(tx);
    return record;
  }

  async function getSnapshot(volume, name) {
    const db = await getDb();
    const tx = openTx(db, ['snapshots'], 'readonly');
    const [row] = await Promise.all([
      reqPromise(tx.objectStore('snapshots').get(`${volume}\0${name}`)),
      txDone(tx),
    ]);
    if (!row) {
      throw errnoError('ENOENT', `snapshot ${name} not found`);
    }
    const { key: _k, ...record } = row;
    return record;
  }

  async function listSnapshots(volume) {
    const db = await getDb();
    const tx = openTx(db, ['snapshots'], 'readonly');
    const out = [];
    await forEachCursor(tx.objectStore('snapshots'), cursor => {
      const r = cursor.value;
      if (r.volume === volume) {
        const { key: _k, ...rec } = r;
        out.push(rec);
      }
    });
    await txDone(tx);
    return out.sort((a, b) => a.name.localeCompare(b.name));
  }

  async function deleteSnapshot(volume, name) {
    const db = await getDb();
    const tx = openTx(db, ['snapshots'], 'readwrite', true);
    const store = tx.objectStore('snapshots');
    const key = `${volume}\0${name}`;
    const existing = await reqPromise(store.get(key));
    if (!existing) {
      try { tx.abort(); } catch {}
      throw errnoError('ENOENT', `snapshot ${name} not found`);
    }
    store.delete(key);
    await txDone(tx);
  }

  async function forkVolume(reqJson) {
    await ensureFormatCompatible();
    const req = typeof reqJson === 'string' ? JSON.parse(reqJson) : reqJson;
    const db = await getDb();
    const tx = openTx(db, ['heads', 'nodes'], 'readwrite', true);
    const headsStore = tx.objectStore('heads');
    const nodesStore = tx.objectStore('nodes');
    const rootHex = digestArrayToHex(req.source_root);
    const [existing, rootNode] = await Promise.all([
      reqPromise(headsStore.get(req.new_volume)),
      reqPromise(nodesStore.get(rootHex)),
    ]);
    if (existing) {
      try { tx.abort(); } catch {}
      throw errnoError('EEXIST', `volume ${req.new_volume} already exists`);
    }
    if (!rootNode) {
      try { tx.abort(); } catch {}
      throw errnoError('ENOENT', 'source root missing');
    }
    const head = {
      format_version: COWFS_FORMAT_VERSION,
      volume: req.new_volume,
      incarnation: 1,
      fence: 1,
      epoch: 0,
      root: req.source_root,
      parent_volume: req.source_volume,
      ephemeral_if_unmodified: Boolean(req.ephemeral_if_unmodified),
      modified: false,
      updated_at: req.created_at,
    };
    headsStore.add(head);
    await txDone(tx);
    return head;
  }

  async function deleteVolumeSnapshotsAndReceiptsInTx(tx, volume) {
    await forEachCursor(tx.objectStore('snapshots'), cursor => {
      if (cursor.value?.volume === volume) {
        cursor.delete();
      }
    });
    await forEachCursor(tx.objectStore('receipts'), cursor => {
      const rec = cursor.value;
      const recVol = rec?.volume ?? rec?.head?.volume;
      if (recVol === volume) {
        cursor.delete();
      }
    });
  }

  async function deleteVolume(volume) {
    // Refuse deletion if another writer currently holds the volume lock.
    const lockName = await volLockName(volume);
    const held = await requestHeldWebLock(lockName, {
      mode: 'exclusive',
      ifAvailable: true,
    });
    if (!held) {
      throw errnoError('EBUSY', `volume ${volume} is currently held`);
    }
    try {
      const db = await getDb();
      const tx = openTx(db, ['heads', 'snapshots', 'receipts'], 'readwrite', true);
      const headsStore = tx.objectStore('heads');
      const existing = await reqPromise(headsStore.get(volume));
      if (!existing) {
        try { tx.abort(); } catch {}
        throw errnoError('ENOENT', `volume ${volume} not found`);
      }
      await deleteVolumeSnapshotsAndReceiptsInTx(tx, volume);
      headsStore.delete(volume);
      await txDone(tx);
    } finally {
      held.release();
      await held.done?.catch(() => {});
    }
  }

  async function deleteVolumeWithLease(
    leaseId,
    volume,
    incarnation,
    fence,
    epoch,
    onlyIfUnmodifiedEphemeral = false,
  ) {
    try {
      const db = await getDb();
      const tx = openTx(db, ['heads', 'snapshots', 'receipts'], 'readwrite', true);
      const headsStore = tx.objectStore('heads');
      const cur = await reqPromise(headsStore.get(volume));
      if (!cur) {
        try { tx.abort(); } catch {}
        throw errnoError('ENOENT', `volume ${volume} not found`);
      }
      if (cur.incarnation !== incarnation || cur.fence !== fence || cur.epoch !== epoch) {
        try { tx.abort(); } catch {}
        throw errnoError('ESTALE', 'writer lease fenced or stale');
      }
      if (onlyIfUnmodifiedEphemeral && (!cur.ephemeral_if_unmodified || cur.modified)) {
        await txDone(tx);
        return false;
      }
      await deleteVolumeSnapshotsAndReceiptsInTx(tx, volume);
      headsStore.delete(volume);
      await txDone(tx);
      return true;
    } finally {
      releaseWriter(leaseId);
      await flushLocks();
    }
  }

  async function reformatVolumeWithLease(
    leaseId,
    volume,
    incarnation,
    fence,
    epoch,
    newHeadJson,
    initialNodes = [],
  ) {
    try {
      await ensureFormatCompatible();
      const newHead = typeof newHeadJson === 'string' ? JSON.parse(newHeadJson) : newHeadJson;
      const db = await getDb();
      const tx = openTx(db, ['heads', 'nodes', 'snapshots', 'receipts'], 'readwrite', true);
      const headsStore = tx.objectStore('heads');
      const nodesStore = tx.objectStore('nodes');
      const cur = await reqPromise(headsStore.get(volume));
      if (!cur) {
        try { tx.abort(); } catch {}
        throw errnoError('ENOENT', `volume ${volume} not found`);
      }
      if (cur.incarnation !== incarnation || cur.fence !== fence || cur.epoch !== epoch) {
        try { tx.abort(); } catch {}
        throw errnoError('ESTALE', 'writer lease fenced or stale');
      }
      await deleteVolumeSnapshotsAndReceiptsInTx(tx, volume);
      for (const node of initialNodes) {
        const bytes = node.bytes instanceof Uint8Array ? new Uint8Array(node.bytes) : Uint8Array.from(node.bytes);
        nodesStore.put({
          digest: node.digest,
          bytes,
          createdAt: newHead.updated_at,
        });
      }
      const replaced = {
        format_version: COWFS_FORMAT_VERSION,
        volume,
        incarnation: Number(cur.incarnation) + 1,
        fence: 1,
        epoch: 0,
        root: newHead.root,
        parent_volume: null,
        ephemeral_if_unmodified: false,
        modified: false,
        updated_at: newHead.updated_at,
      };
      headsStore.put(replaced);
      await txDone(tx);
      return replaced;
    } finally {
      releaseWriter(leaseId);
      await flushLocks();
    }
  }

  async function acquireGcLock(exclusive) {
    const lName = await gcLockName();
    // Writers (`exclusive === false`) queue cleanly for the shared lock (no `ifAvailable: true`)
    // so live commits never fail with `EBUSY` while GC runs. GC (`exclusive === true`) uses
    // `ifAvailable: true` and returns `EBUSY` if writers are currently committing.
    const opts = exclusive ? { mode: 'exclusive', ifAvailable: true } : { mode: 'shared' };
    const held = await requestHeldWebLock(lName, opts);
    if (!held) {
      throw errnoError('EBUSY', 'GC lock is contended');
    }
    const lockId = `gc-${nextGcSeq++}`;
    gcReleasers.set(lockId, held);
    return lockId;
  }

  function releaseGcLock(lockId) {
    const held = gcReleasers.get(lockId);
    if (!held) return;
    gcReleasers.delete(lockId);
    releaseHeldLock(held);
  }

  async function listAllRoots() {
    const db = await getDb();
    const tx = openTx(db, ['heads', 'snapshots', 'gracePins', 'roPins'], 'readonly');
    const out = [];
    const roPinRows = [];
    await Promise.all([
      forEachCursor(tx.objectStore('heads'), cursor => {
        const h = cursor.value;
        out.push({ volume: h.volume, root: h.root, pinned_until: null });
      }),
      forEachCursor(tx.objectStore('snapshots'), cursor => {
        const s = cursor.value;
        out.push({ volume: s.volume, root: s.root, pinned_until: null });
      }),
      forEachCursor(tx.objectStore('gracePins'), cursor => {
        const p = cursor.value;
        out.push({ volume: p.volume, root: p.root, pinned_until: p.pinnedUntil ?? null });
      }),
      forEachCursor(tx.objectStore('roPins'), cursor => {
        roPinRows.push(cursor.value);
      }),
    ]);
    await txDone(tx);

    // Check which RO pins are still backed by a live tab/Worker Web Lock; reap crashed pins.
    const stalePinIds = [];
    for (const p of roPinRows) {
      const lName = await roPinLockName(p.pinId);
      try {
        const probe = await requestHeldWebLock(lName, { mode: 'exclusive', ifAvailable: true });
        if (!probe) {
          // Lock is held by an active RO/snapshot mount -> keep root live!
          out.push({ volume: p.volume, root: p.root, pinned_until: null });
        } else {
          probe.release();
          await probe.done?.catch(() => {});
          stalePinIds.push(p.pinId);
        }
      } catch {
        // Fail safe on transient lock query error: preserve pinned root.
        out.push({ volume: p.volume, root: p.root, pinned_until: null });
      }
    }
    if (stalePinIds.length > 0) {
      const delTx = openTx(db, ['roPins'], 'readwrite', true);
      const pinsStore = delTx.objectStore('roPins');
      for (const id of stalePinIds) pinsStore.delete(id);
      await txDone(delTx);
    }
    return out;
  }

  async function listIndexedPacks() {
    const db = await getDb();
    const tx = openTx(db, ['packs', 'blocks'], 'readonly');
    const packIds = new Set();
    await Promise.all([
      forEachCursor(tx.objectStore('packs'), cursor => {
        if (cursor.value?.packId) packIds.add(cursor.value.packId);
      }),
      forEachCursor(tx.objectStore('blocks'), cursor => {
        if (cursor.value?.packId) packIds.add(cursor.value.packId);
      }),
    ]);
    await txDone(tx);
    return [...packIds];
  }

  async function pruneAbandonedEphemeralForks(nowJson, graceSecs = graceWindowSecs) {
    const now = typeof nowJson === 'string' ? JSON.parse(nowJson) : nowJson;
    const db = await getDb();
    const candidates = [];
    {
      const tx = openTx(db, ['heads'], 'readonly');
      await forEachCursor(tx.objectStore('heads'), cursor => {
        const h = cursor.value;
        if (h?.ephemeral_if_unmodified && !h.modified && tsExpired(h.updated_at, now, graceSecs)) {
          candidates.push(h.volume);
        }
      });
      await txDone(tx);
    }
    let pruned = 0;
    for (const volume of candidates) {
      const lockName = await volLockName(volume);
      const held = await requestHeldWebLock(lockName, { mode: 'exclusive', ifAvailable: true });
      if (!held) continue;
      try {
        const tx = openTx(db, ['heads', 'snapshots', 'receipts'], 'readwrite', true);
        const headsStore = tx.objectStore('heads');
        const cur = await reqPromise(headsStore.get(volume));
        if (cur && cur.ephemeral_if_unmodified && !cur.modified && tsExpired(cur.updated_at, now, graceSecs)) {
          await deleteVolumeSnapshotsAndReceiptsInTx(tx, volume);
          headsStore.delete(volume);
          await txDone(tx);
          pruned += 1;
        } else {
          await txDone(tx);
        }
      } finally {
        held.release();
        await held.done?.catch(() => {});
      }
    }
    return pruned;
  }

  async function sweepMetadata(payloadJson) {
    const payload = typeof payloadJson === 'string' ? JSON.parse(payloadJson) : payloadJson;
    const keepNodeSet = new Set(payload.keepNodes ?? []);
    const keepPackSet = new Set(payload.keepPacks ?? []);
    const now = payload.now ?? payload.graceBefore;
    const graceSecs = payload.graceWindowSecs ?? (payload.now ? graceWindowSecs : 0);

    const db = await getDb();
    const tx = openTx(
      db,
      ['heads', 'nodes', 'packs', 'blocks', 'gracePins', 'receipts'],
      'readwrite',
      true,
    );
    const headsStore = tx.objectStore('heads');
    const nodesStore = tx.objectStore('nodes');
    const packsStore = tx.objectStore('packs');
    const blocksStore = tx.objectStore('blocks');
    const graceStore = tx.objectStore('gracePins');
    const receiptsStore = tx.objectStore('receipts');

    const liveEpochs = new Map();
    await forEachCursor(headsStore, cursor => {
      const h = cursor.value;
      if (h?.volume) liveEpochs.set(h.volume, h.epoch);
    });

    // Cursor-based streaming sweep: never materializes all node payloads into RAM at once.
    await forEachCursor(graceStore, cursor => {
      const p = cursor.value;
      if (p?.pinnedUntil && !tsGt(p.pinnedUntil, now)) {
        cursor.delete();
      }
    });

    await forEachCursor(nodesStore, cursor => {
      const n = cursor.value;
      if (!keepNodeSet.has(n.digest) && tsExpired(n.createdAt, now, graceSecs)) {
        cursor.delete();
      }
    });

    const sweptPacks = [];
    const sweptPackSet = new Set();
    await forEachCursor(packsStore, cursor => {
      const p = cursor.value;
      if (!keepPackSet.has(p.packId) && tsExpired(p.createdAt, now, graceSecs)) {
        cursor.delete();
        sweptPacks.push(p.packId);
        sweptPackSet.add(p.packId);
      }
    });

    if (sweptPackSet.size > 0) {
      await forEachCursor(blocksStore, cursor => {
        if (sweptPackSet.has(cursor.value?.packId)) {
          cursor.delete();
        }
      });
    }

    await forEachCursor(receiptsStore, cursor => {
      const rec = cursor.value;
      const vol = rec?.volume ?? rec?.head?.volume;
      const ep = rec?.epoch ?? rec?.head?.epoch;
      if (liveEpochs.get(vol) !== ep && tsExpired(rec?.createdAt ?? rec?.head?.updated_at, now, graceSecs)) {
        cursor.delete();
      }
    });

    await txDone(tx);
    return sweptPacks;
  }

  // ---------------------------------------------------------------------------
  // OPFS immutable PackStore (`FileSystemSyncAccessHandle` in Workers + lock-free
  // `getFile().slice()` reads for concurrent cross-tab access)
  // ---------------------------------------------------------------------------

  async function existingPackVerified(dir, filename, packId, expectedLen) {
    try {
      const existingHandle = await dir.getFileHandle(filename, { create: false });
      const existingFile = await existingHandle.getFile();
      if (existingFile.size !== expectedLen) return false;
      const existingBytes = new Uint8Array(await existingFile.arrayBuffer());
      return (await sha256Hex(existingBytes)) === packId;
    } catch {
      return false;
    }
  }

  async function writeBytesToHandle(fileHandle, raw) {
    if (typeof fileHandle.createSyncAccessHandle === 'function') {
      const syncHandle = await fileHandle.createSyncAccessHandle().catch(err => {
        throw mapDomError(err);
      });
      try {
        syncHandle.truncate(0);
        let written = 0;
        while (written < raw.byteLength) {
          const n = syncHandle.write(raw.subarray(written), { at: written });
          if (n <= 0) throw errnoError('EIO', 'short sync handle write');
          written += n;
        }
        syncHandle.flush();
        stats.syncHandleWrites += 1;
      } catch (err) {
        throw mapDomError(err);
      } finally {
        try {
          syncHandle.close();
        } catch {}
      }
    } else if (typeof fileHandle.createWritable === 'function') {
      const writable = await fileHandle.createWritable().catch(err => {
        throw mapDomError(err);
      });
      try {
        await writable.write(raw);
        await writable.close();
      } catch (err) {
        try {
          await writable.abort();
        } catch {}
        throw mapDomError(err);
      }
    } else {
      throw errnoError('EOPNOTSUPP', 'OPFS file handle supports neither sync access nor writable');
    }
  }

  async function withOptionalPackLock(packId, fn) {
    if (!locksApi || typeof locksApi.request !== 'function') {
      return await fn();
    }
    const lName = await packLockName(packId);
    const held = await requestHeldWebLock(lName, { mode: 'exclusive' });
    try {
      return await fn();
    } finally {
      if (held) {
        held.release();
        await held.done?.catch(() => {});
      }
    }
  }

  async function writePack(packId, bytes) {
    const raw = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
    if (raw.byteLength > PACK_MAX_BYTES) {
      throw errnoError('EFBIG', 'pack exceeds 8 MiB limit');
    }
    if ((await sha256Hex(raw)) !== packId) {
      throw errnoError('EINVAL', 'pack bytes do not match packId SHA-256');
    }
    if (hooks.onWritePack) {
      await hooks.onWritePack(packId, raw);
    }
    await checkQuotaEstimate(raw.byteLength);

    const dir = await getPacksDir();
    const filename = `${packId}.pack`;

    // Fast path: verify full SHA-256 (never length alone!) before skipping rewrite.
    if (await existingPackVerified(dir, filename, packId, raw.byteLength)) {
      return {
        pack_id: packId,
        size: raw.byteLength,
        entry_count: 0,
        created_at: { sec: 0, nsec: 0 },
      };
    }

    // Write to a unique temporary file, flush & close, then atomically publish under a per-pack
    // lock via `move()` (or serialized fallback when `move()` is unavailable).
    const tmpName = `.tmp-${packId.slice(0, 16)}-${randomId()}`;
    let tmpExists = false;
    try {
      const tmpHandle = await dir.getFileHandle(tmpName, { create: true }).catch(err => {
        throw mapDomError(err);
      });
      tmpExists = true;
      await writeBytesToHandle(tmpHandle, raw);

      await withOptionalPackLock(packId, async () => {
        if (await existingPackVerified(dir, filename, packId, raw.byteLength)) {
          return;
        }
        if (typeof tmpHandle.move === 'function') {
          try {
            await tmpHandle.move(filename);
            tmpExists = false;
          } catch (moveErr) {
            if (await existingPackVerified(dir, filename, packId, raw.byteLength)) {
              return;
            }
            throw mapDomError(moveErr);
          }
        } else {
          // Fallback for OPFS mocks/environments without `FileSystemFileHandle.move()`.
          const finalHandle = await dir.getFileHandle(filename, { create: true }).catch(err => {
            throw mapDomError(err);
          });
          await writeBytesToHandle(finalHandle, raw);
        }
        stats.packWrites += 1;
        stats.packBytesWritten += raw.byteLength;
      });
    } finally {
      if (tmpExists) {
        try {
          await dir.removeEntry(tmpName);
        } catch {}
      }
    }

    return {
      pack_id: packId,
      size: raw.byteLength,
      entry_count: 0,
      created_at: { sec: 0, nsec: 0 },
    };
  }

  async function readPackRange(packId, offset, len) {
    if (hooks.onReadPackRange) {
      const override = await hooks.onReadPackRange(packId, offset, len);
      if (override !== undefined) return override;
    }
    const dir = await getPacksDir();
    const handle = await dir.getFileHandle(`${packId}.pack`, { create: false }).catch(err => {
      throw mapDomError(err);
    });
    // Lock-free cross-tab slice read (never contends with SyncAccessHandle once pack is closed).
    const file = await handle.getFile().catch(err => {
      throw mapDomError(err);
    });
    if (offset + len > file.size) {
      throw errnoError('EIO', `pack ${packId} truncated`);
    }
    const slice = file.slice(offset, offset + len);
    const buf = new Uint8Array(await slice.arrayBuffer());
    stats.sliceReads += 1;
    stats.packBytesRead += buf.byteLength;
    return buf;
  }

  async function statPack(packId) {
    const dir = await getPacksDir();
    try {
      const handle = await dir.getFileHandle(`${packId}.pack`, { create: false });
      const file = await handle.getFile();
      return file.size;
    } catch (err) {
      if (err?.name === 'NotFoundError' || err?.errno === 'ENOENT') return null;
      throw mapDomError(err);
    }
  }

  async function listPacks() {
    const dir = await getPacksDir();
    const ids = [];
    for await (const [name, handle] of dir.entries()) {
      if (handle.kind === 'file' && name.endsWith('.pack') && !name.startsWith('.')) {
        ids.push(name.slice(0, -'.pack'.length));
      }
    }
    ids.sort();
    return ids;
  }

  async function deletePack(packId) {
    const dir = await getPacksDir();
    try {
      await dir.removeEntry(`${packId}.pack`);
    } catch (err) {
      if (err?.name === 'NotFoundError' || err?.errno === 'ENOENT') return;
      throw mapDomError(err);
    }
  }

  async function listVolumes({ probeLocks = true } = {}) {
    const db = await getDb();
    const tx = openTx(db, ['heads'], 'readonly');
    const heads = [];
    await forEachCursor(tx.objectStore('heads'), cursor => {
      if (cursor.value) heads.push(structuredClone(cursor.value));
    });
    await txDone(tx);

    const out = [];
    for (const h of heads) {
      let busy = false;
      if (probeLocks && locksApi && typeof locksApi.request === 'function') {
        try {
          const lName = await volLockName(h.volume);
          const probe = await requestHeldWebLock(lName, { mode: 'exclusive', ifAvailable: true });
          if (!probe) {
            busy = true;
          } else {
            probe.release();
            await probe.done?.catch(() => {});
          }
        } catch {
          busy = false;
        }
      }
      out.push({
        volume: h.volume,
        format_version: h.format_version,
        incarnation: h.incarnation,
        fence: h.fence,
        epoch: h.epoch,
        root: digestArrayToHex(h.root),
        parent_volume: h.parent_volume ?? null,
        ephemeral_if_unmodified: Boolean(h.ephemeral_if_unmodified),
        modified: Boolean(h.modified),
        updated_at: h.updated_at ?? null,
        busy,
      });
    }
    return out.sort((a, b) => a.volume.localeCompare(b.volume));
  }

  async function listVolumeHeads() {
    await ensureFormatCompatible();
    const db = await getDb();
    const tx = openTx(db, ['heads'], 'readonly');
    const heads = [];
    await forEachCursor(tx.objectStore('heads'), cursor => {
      if (cursor.value) heads.push(structuredClone(cursor.value));
    });
    await txDone(tx);
    return heads.sort((a, b) => a.volume.localeCompare(b.volume));
  }

  // Test helpers (explicitly named for diagnostics / corruption injection in tests).
  async function _setFormatVersionForTest(version) {
    const db = await getDb();
    const tx = openTx(db, ['meta'], 'readwrite', true);
    tx.objectStore('meta').put(version, 'format_version');
    await txDone(tx);
  }

  async function _corruptNodeByteForTest(digestHex, byteOffset) {
    const db = await getDb();
    const tx = openTx(db, ['nodes'], 'readwrite', true);
    const store = tx.objectStore('nodes');
    const row = await reqPromise(store.get(digestHex));
    if (!row) {
      await txDone(tx);
      return false;
    }
    const copy = new Uint8Array(row.bytes);
    if (byteOffset >= copy.length) {
      await txDone(tx);
      return false;
    }
    copy[byteOffset] ^= 0x01;
    store.put({ ...row, bytes: copy });
    await txDone(tx);
    return true;
  }

  async function _corruptPackByteForTest(packId, byteOffset) {
    const dir = await getPacksDir();
    const handle = await dir.getFileHandle(`${packId}.pack`, { create: false });
    const file = await handle.getFile();
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (byteOffset >= bytes.length) return false;
    bytes[byteOffset] ^= 0x01;
    await writeBytesToHandle(handle, bytes);
    return true;
  }

  return {
    dbName,
    graceWindowSecs,
    stats,
    resetStats() {
      stats.packWrites = 0;
      stats.packBytesWritten = 0;
      stats.packBytesRead = 0;
      stats.commits = 0;
      stats.syncHandleWrites = 0;
      stats.sliceReads = 0;
    },
    formatVersion,
    listVolumes,
    listVolumeHeads,
    createVolume,
    readHead,
    pinRoRoot,
    unpinRoRoot,
    unpinRoRootSync,
    acquireWriter,
    renewWriter,
    releaseWriter,
    flushLocks,
    getNode,
    lookupBlock,
    commitHead,
    commitReceivedRoot,
    createSnapshot,
    getSnapshot,
    listSnapshots,
    deleteSnapshot,
    forkVolume,
    deleteVolume,
    deleteVolumeWithLease,
    reformatVolumeWithLease,
    acquireGcLock,
    releaseGcLock,
    listAllRoots,
    listIndexedPacks,
    pruneAbandonedEphemeralForks,
    sweepMetadata,
    writePack,
    readPackRange,
    statPack,
    listPacks,
    deletePack,
    _setFormatVersionForTest,
    _corruptNodeByteForTest,
    _corruptPackByteForTest,
  };
}

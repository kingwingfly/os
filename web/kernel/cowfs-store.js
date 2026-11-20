// Browser OPFS immutable `COWP` packs + IndexedDB `{durability: "strict"}` HeadStore + Web Locks
// (`os-vol:<uuid>`, `os-cowfs-gc`) host adapter for `os-cowfs` (contract §2.5, §2.12, §2.15, #77).
//
// Zero portable filesystem policy lives here: all CoW B+tree SHA-256 verification, POSIX modes/
// ACLs/xattrs, `DIR_INDEX` paging, `ORPHAN_ITEM` reaping, `FICLONE`, `32 MiB` arena accounting,
// GC reachability, and `cowfsck` execute in Rust (`os-cowtree` + `os-cowfs`).

export const COWFS_FORMAT_VERSION = 1;
export const PACK_MAX_BYTES = 8 * 1024 * 1024;
const DEFAULT_DB_NAME = 'os-cowfs-v1';
const PACKS_DIR_PATH = ['os-cowfs', 'packs'];
const GC_LOCK_NAME = 'os-cowfs-gc';
const DEFAULT_GRACE_WINDOW_SECS = 600;

const errnoError = (errno, message = errno) => Object.assign(new Error(message), { errno });

function mapDomError(reason) {
  if (reason?.errno) return reason;
  const errno = {
    QuotaExceededError: 'ENOSPC',
    NotFoundError: 'ENOENT',
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

function reqPromise(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(mapDomError(req.error));
  });
}

const TX_DONE = Symbol('os.cowfs.txDone');

function openTx(db, stores, mode, strict = false) {
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
    const req = idb.open(dbName, 1);
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
  let packsDirPromise = null;
  let persistRequested = false;
  let nextLeaseSeq = 1;
  let nextForkSeq = 1;
  let nextGcSeq = 1;

  // Active held Web Lock releasers keyed by leaseId / gcLockId.
  const writerReleasers = new Map();
  const gcReleasers = new Map();
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

  async function getDb() {
    if (!idbFactory || typeof idbFactory.open !== 'function') {
      throw errnoError('EOPNOTSUPP', 'IndexedDB is unavailable');
    }
    if (!dbPromise) {
      dbPromise = openCowfsDb(idbFactory, dbName);
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
        for (const seg of PACKS_DIR_PATH) {
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
    headsStore.put(head);
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
      req.catch(err => {
        if (!settled) {
          settled = true;
          reject(mapDomError(err));
        }
      });
    });
  }

  async function acquireWriter(volume, mode = 'exclusive') {
    await ensureFormatCompatible();
    const existing = await readHead(volume);
    const lockName = `os-vol:${volume}`;

    if (mode === 'force-takeover') {
      // Steal Web Lock (best-effort; browsers support `{ steal: true }`) AND bump local_fence
      // atomically in strict IndexedDB so any paused/bfcached tab fails with ESTALE.
      let held = null;
      try {
        held = await requestHeldWebLock(lockName, { mode: 'exclusive', steal: true });
      } catch {
        // If lock steal isn't supported in a minimal environment, rely on local_fence CAS.
      }
      const db = await getDb();
      const tx = openTx(db, ['heads'], 'readwrite', true);
      const headsStore = tx.objectStore('heads');
      const cur = await reqPromise(headsStore.get(volume));
      if (!cur) {
        try { tx.abort(); } catch {}
        held?.release?.();
        throw errnoError('ENOENT', `volume ${volume} not found`);
      }
      const nextHead = { ...cur, fence: Number(cur.fence) + 1 };
      headsStore.put(nextHead);
      await txDone(tx);

      const leaseId = `lease-${nextLeaseSeq++}`;
      if (held) {
        writerReleasers.set(leaseId, held);
      }
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
    }

    const held = await requestHeldWebLock(lockName, { mode: 'exclusive', ifAvailable: true });
    if (held) {
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
    }

    if (mode === 'exclusive') {
      throw errnoError('EBUSY', `volume ${volume} writer lock is held by another tab`);
    }

    if (mode === 'fork-on-busy') {
      // O(1) persistent fork of the last committed head (`ephemeral_if_unmodified: true`).
      const latest = await readHead(volume);
      const suffix = globalThis.crypto?.randomUUID?.().slice(0, 8) ?? String(nextForkSeq++);
      const forkVol = `${volume}-fork-${suffix}-${nextForkSeq++}`;
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
      const db = await getDb();
      const tx = openTx(db, ['heads'], 'readwrite', true);
      tx.objectStore('heads').put(forkHead);
      await txDone(tx);

      const forkLock = await requestHeldWebLock(`os-vol:${forkVol}`, {
        mode: 'exclusive',
        ifAvailable: true,
      });
      if (!forkLock) {
        throw errnoError('EBUSY', `failed to acquire lock for forked volume ${forkVol}`);
      }
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
    }

    throw errnoError('EINVAL', `unknown writer mode: ${mode}`);
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
    held.release();
    if (held.done) {
      const p = held.done.catch(() => {});
      lockReleasePromises.add(p);
      p.finally(() => lockReleasePromises.delete(p));
    }
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

    // 4. Advance head atomically.
    const nextHead = {
      format_version: COWFS_FORMAT_VERSION,
      volume: meta.volume,
      incarnation: cur.incarnation,
      fence: cur.fence,
      epoch: cur.epoch + 1,
      root: [...hexToBytes(meta.newRoot)],
      parent_volume: cur.parent_volume ?? null,
      ephemeral_if_unmodified: Boolean(cur.ephemeral_if_unmodified),
      modified: true,
      updated_at: meta.committedAt,
    };
    headsStore.put(nextHead);
    receiptsStore.put({
      opId: meta.opId,
      rootHex: meta.newRoot,
      head: nextHead,
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
    const [all] = await Promise.all([
      reqPromise(tx.objectStore('snapshots').getAll()),
      txDone(tx),
    ]);
    return (all ?? [])
      .filter(r => r.volume === volume)
      .map(({ key: _k, ...rec }) => rec)
      .sort((a, b) => a.name.localeCompare(b.name));
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
    headsStore.put(head);
    await txDone(tx);
    return head;
  }

  async function deleteVolume(volume) {
    // Refuse deletion if another writer currently holds the volume lock.
    const held = await requestHeldWebLock(`os-vol:${volume}`, {
      mode: 'exclusive',
      ifAvailable: true,
    });
    if (!held) {
      throw errnoError('EBUSY', `volume ${volume} is currently held`);
    }
    try {
      const db = await getDb();
      const tx = openTx(db, ['heads'], 'readwrite', true);
      const store = tx.objectStore('heads');
      const existing = await reqPromise(store.get(volume));
      if (!existing) {
        try { tx.abort(); } catch {}
        throw errnoError('ENOENT', `volume ${volume} not found`);
      }
      store.delete(volume);
      await txDone(tx);
    } finally {
      held.release();
      await held.done?.catch(() => {});
    }
  }

  async function acquireGcLock(exclusive) {
    const mode = exclusive ? 'exclusive' : 'shared';
    const held = await requestHeldWebLock(GC_LOCK_NAME, { mode, ifAvailable: true });
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
    held.release();
    if (held.done) {
      const p = held.done.catch(() => {});
      lockReleasePromises.add(p);
      p.finally(() => lockReleasePromises.delete(p));
    }
  }

  async function listAllRoots() {
    const db = await getDb();
    const tx = openTx(db, ['heads', 'snapshots', 'gracePins'], 'readonly');
    const [heads, snaps, pins] = await Promise.all([
      reqPromise(tx.objectStore('heads').getAll()),
      reqPromise(tx.objectStore('snapshots').getAll()),
      reqPromise(tx.objectStore('gracePins').getAll()),
      txDone(tx),
    ]);
    const out = [];
    for (const h of heads ?? []) {
      out.push({ volume: h.volume, root: h.root, pinned_until: null });
    }
    for (const s of snaps ?? []) {
      out.push({ volume: s.volume, root: s.root, pinned_until: null });
    }
    for (const p of pins ?? []) {
      out.push({ volume: p.volume, root: p.root, pinned_until: p.pinnedUntil ?? null });
    }
    return out;
  }

  async function sweepMetadata(payloadJson) {
    const { keepNodes, keepPacks, graceBefore } =
      typeof payloadJson === 'string' ? JSON.parse(payloadJson) : payloadJson;
    const keepNodeSet = new Set(keepNodes ?? []);
    const keepPackSet = new Set(keepPacks ?? []);

    const db = await getDb();
    const tx = openTx(db, ['nodes', 'packs', 'blocks', 'gracePins'], 'readwrite', true);
    const nodesStore = tx.objectStore('nodes');
    const packsStore = tx.objectStore('packs');
    const blocksStore = tx.objectStore('blocks');
    const graceStore = tx.objectStore('gracePins');

    const [allNodes, allPacks, allBlocks, allPins] = await Promise.all([
      reqPromise(nodesStore.getAll()),
      reqPromise(packsStore.getAll()),
      reqPromise(blocksStore.getAll()),
      reqPromise(graceStore.getAll()),
    ]);

    for (const p of allPins ?? []) {
      if (p.pinnedUntil && !tsGt(p.pinnedUntil, graceBefore)) {
        graceStore.delete(p.id);
      }
    }
    for (const n of allNodes ?? []) {
      if (!keepNodeSet.has(n.digest) && !tsGt(n.createdAt, graceBefore)) {
        nodesStore.delete(n.digest);
      }
    }
    const sweptPacks = [];
    const sweptPackSet = new Set();
    for (const p of allPacks ?? []) {
      if (!keepPackSet.has(p.packId) && !tsGt(p.createdAt, graceBefore)) {
        packsStore.delete(p.packId);
        sweptPacks.push(p.packId);
        sweptPackSet.add(p.packId);
      }
    }
    for (const b of allBlocks ?? []) {
      if (sweptPackSet.has(b.packId)) {
        blocksStore.delete(b.digest);
      }
    }
    await txDone(tx);
    return sweptPacks;
  }

  // ---------------------------------------------------------------------------
  // OPFS immutable PackStore (`FileSystemSyncAccessHandle` in Workers + lock-free
  // `getFile().slice()` reads for concurrent cross-tab access)
  // ---------------------------------------------------------------------------

  async function writePack(packId, bytes) {
    const raw = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
    if (raw.byteLength > PACK_MAX_BYTES) {
      throw errnoError('EFBIG', 'pack exceeds 8 MiB limit');
    }
    if (hooks.onWritePack) {
      await hooks.onWritePack(packId, raw);
    }
    await checkQuotaEstimate(raw.byteLength);

    const dir = await getPacksDir();
    const filename = `${packId}.pack`;

    // Immutable content-addressed pack: if already sealed, skip rewrite.
    try {
      const existingHandle = await dir.getFileHandle(filename, { create: false });
      const existingFile = await existingHandle.getFile();
      if (existingFile.size === raw.byteLength) {
        return {
          pack_id: packId,
          size: raw.byteLength,
          entry_count: 0,
          created_at: { sec: 0, nsec: 0 },
        };
      }
    } catch {
      // Not present yet.
    }

    const fileHandle = await dir.getFileHandle(filename, { create: true }).catch(err => {
      throw mapDomError(err);
    });

    if (typeof fileHandle.createSyncAccessHandle === 'function') {
      // Dedicated Worker fast & crash-safe OPFS path: write + flush + close!
      let writeFailed = false;
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
        writeFailed = true;
        throw mapDomError(err);
      } finally {
        try {
          syncHandle.close();
        } catch {}
        if (writeFailed) {
          try {
            await dir.removeEntry(filename);
          } catch {}
        }
      }
    } else if (typeof fileHandle.createWritable === 'function') {
      // Main-thread / test fallback using FileSystemWritableFileStream.
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
        try {
          await dir.removeEntry(filename);
        } catch {}
        throw mapDomError(err);
      }
    } else {
      throw errnoError('EOPNOTSUPP', 'OPFS file handle supports neither sync access nor writable');
    }

    stats.packWrites += 1;
    stats.packBytesWritten += raw.byteLength;
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
    if (typeof handle.createSyncAccessHandle === 'function') {
      const sh = await handle.createSyncAccessHandle();
      try {
        sh.truncate(0);
        sh.write(bytes, { at: 0 });
        sh.flush();
      } finally {
        sh.close();
      }
    } else {
      const w = await handle.createWritable();
      await w.write(bytes);
      await w.close();
    }
    return true;
  }

  return {
    dbName,
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
    createVolume,
    readHead,
    acquireWriter,
    renewWriter,
    releaseWriter,
    flushLocks,
    getNode,
    lookupBlock,
    commitHead,
    createSnapshot,
    getSnapshot,
    listSnapshots,
    deleteSnapshot,
    forkVolume,
    deleteVolume,
    acquireGcLock,
    releaseGcLock,
    listAllRoots,
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

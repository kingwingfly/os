// Persisted local Boot Profile store (`os-boot-profile-v1`, Contract §1, §2.1, §2.15; #56 L3c).
//
// Zero network requests: stores the browser profile's Stage 0 -> Stage 1 boot configuration
// in IndexedDB (`{ durability: "strict" }`), injected read-only (`0444`) into Stage 1 initramfs
// at `/run/os/boot-profile.json`.

export const BOOT_PROFILE_DB_NAME = 'os-boot-profile-v1';
export const BOOT_PROFILE_DB_VERSION = 1;
export const BOOT_PROFILE_STORE = 'profile';
export const BOOT_PROFILE_KEY = 'default';
export const BOOT_PROFILE_VERSION = 1;

const HEX64 = /^[a-f0-9]{64}$/;
const VALID_WRITER_MODES = new Set(['fork_on_busy', 'exclusive']);
const VALID_USERS = new Set(['user', 'root']);

/**
 * Returns the default standalone offline boot profile:
 * local `os-cowfs` root volume (`volume_uuid: null` until first boot mints & persists one),
 * `fork_on_busy` second-tab O(1) persistent fork mode, and zero-friction local `user`.
 */
export function defaultBootProfile() {
  return {
    version: BOOT_PROFILE_VERSION,
    root: {
      cow_fs: {
        volume_uuid: null,
        writer_mode: 'fork_on_busy',
      },
    },
    default_user: 'user',
    generation: null,
    recovery: false,
  };
}

/**
 * Validate and normalize a BootProfile matching `crates/client-kernel/src/boot_stage.rs`.
 */
export function validateBootProfile(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('Boot profile must be an object.');
  }
  const version = input.version ?? BOOT_PROFILE_VERSION;
  if (version !== BOOT_PROFILE_VERSION) {
    throw new Error(`Unsupported boot profile version: ${version}`);
  }
  const rawRoot = input.root;
  let root;
  if (rawRoot === 'ephemeral') {
    root = 'ephemeral';
  } else if (!rawRoot || typeof rawRoot !== 'object' || Array.isArray(rawRoot)) {
    throw new Error('Boot profile missing root specification.');
  } else if ('cow_fs' in rawRoot) {
    const spec = rawRoot.cow_fs;
    if (!spec || typeof spec !== 'object' || Array.isArray(spec)) {
      throw new Error('Invalid cow_fs root specification.');
    }
    const volumeUuid = spec.volume_uuid ?? null;
    if (volumeUuid !== null && (typeof volumeUuid !== 'string' || !volumeUuid.trim() || volumeUuid.includes('\0') || volumeUuid.includes('/'))) {
      throw new Error('Invalid cow_fs volume_uuid.');
    }
    const writerMode = spec.writer_mode ?? 'fork_on_busy';
    if (!VALID_WRITER_MODES.has(writerMode)) {
      throw new Error(`Invalid cow_fs writer_mode: ${writerMode}`);
    }
    root = {
      cow_fs: {
        volume_uuid: volumeUuid,
        writer_mode: writerMode,
      },
    };
  } else if ('snapshot' in rawRoot) {
    const spec = rawRoot.snapshot;
    if (!spec || typeof spec !== 'object' || Array.isArray(spec)) {
      throw new Error('Invalid snapshot root specification.');
    }
    const volumeUuid = spec.volume_uuid;
    const snapshot = spec.snapshot;
    if (typeof volumeUuid !== 'string' || !volumeUuid.trim() || volumeUuid.length > 128 || volumeUuid.includes('\0') || volumeUuid.includes('/')) {
      throw new Error('Invalid snapshot root volume_uuid.');
    }
    if (typeof snapshot !== 'string' || !snapshot.trim() || snapshot.length > 128 || snapshot.includes('\0') || snapshot.includes('/')) {
      throw new Error('Invalid snapshot root snapshot name.');
    }
    root = {
      snapshot: {
        volume_uuid: volumeUuid,
        snapshot,
      },
    };
  } else if ('ephemeral' in rawRoot) {
    const spec = rawRoot.ephemeral;
    if (spec !== null && spec !== true && (typeof spec !== 'object' || Array.isArray(spec))) {
      throw new Error('Invalid ephemeral root specification.');
    }
    root = 'ephemeral';
  } else if ('cloud_opt_in' in rawRoot) {
    const spec = rawRoot.cloud_opt_in;
    if (!spec || typeof spec !== 'object' || Array.isArray(spec)) {
      throw new Error('Invalid cloud_opt_in root specification.');
    }
    const subpath = spec.subpath ?? null;
    if (subpath !== null && (typeof subpath !== 'string' || subpath.includes('\0'))) {
      throw new Error('Invalid cloud_opt_in subpath.');
    }
    root = { cloud_opt_in: { subpath } };
  } else {
    throw new Error('Unknown boot profile root kind.');
  }

  const defaultUser = input.default_user ?? 'user';
  if (typeof defaultUser !== 'string' || !VALID_USERS.has(defaultUser)) {
    throw new Error(`Invalid default_user: ${defaultUser}`);
  }
  const generation = input.generation ?? null;
  if (generation !== null && (typeof generation !== 'string' || !HEX64.test(generation))) {
    throw new Error('Invalid pinned Release v2 generation digest.');
  }
  const recovery = Boolean(input.recovery);

  return {
    version: BOOT_PROFILE_VERSION,
    root,
    default_user: defaultUser,
    generation,
    recovery,
  };
}

function openProfileDb(idbFactory, dbName) {
  if (!idbFactory || typeof idbFactory.open !== 'function') {
    throw new Error('IndexedDB is unavailable for boot profile storage.');
  }
  return new Promise((resolve, reject) => {
    const req = idbFactory.open(dbName, BOOT_PROFILE_DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(BOOT_PROFILE_STORE)) {
        db.createObjectStore(BOOT_PROFILE_STORE);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('Failed to open boot profile IndexedDB.'));
    req.onblocked = () => reject(new Error('Boot profile IndexedDB open blocked.'));
  });
}

function openStrictWriteTx(db) {
  try {
    return db.transaction(BOOT_PROFILE_STORE, 'readwrite', { durability: 'strict' });
  } catch {
    return db.transaction(BOOT_PROFILE_STORE, 'readwrite');
  }
}

/**
 * Creates a zero-network persisted Boot Profile store backed by `os-boot-profile-v1` IndexedDB.
 *
 * @param {object} [options]
 * @param {string} [options.dbName] Override IndexedDB database name (default `'os-boot-profile-v1'`)
 * @param {IDBFactory} [options.idb] Override `indexedDB` (for Node.js unit tests)
 */
export function createBootProfileStore(options = {}) {
  const dbName = options.dbName ?? BOOT_PROFILE_DB_NAME;
  const idbFactory = options.idb ?? globalThis.indexedDB;

  async function load() {
    const db = await openProfileDb(idbFactory, dbName);
    try {
      const raw = await new Promise((resolve, reject) => {
        const tx = db.transaction(BOOT_PROFILE_STORE, 'readonly');
        const req = tx.objectStore(BOOT_PROFILE_STORE).get(BOOT_PROFILE_KEY);
        req.onsuccess = () => resolve(req.result ?? null);
        req.onerror = () => reject(req.error ?? new Error('Failed to read boot profile.'));
      });
      if (!raw) return defaultBootProfile();
      return validateBootProfile(raw);
    } finally {
      db.close();
    }
  }

  async function save(profile) {
    const normalized = validateBootProfile(profile);
    const db = await openProfileDb(idbFactory, dbName);
    try {
      await new Promise((resolve, reject) => {
        const tx = openStrictWriteTx(db);
        tx.objectStore(BOOT_PROFILE_STORE).put(normalized, BOOT_PROFILE_KEY);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error ?? new Error('Failed to persist boot profile.'));
        tx.onabort = () => reject(tx.error ?? new Error('Boot profile write aborted.'));
      });
      return normalized;
    } finally {
      db.close();
    }
  }

  async function update(mutator) {
    const db = await openProfileDb(idbFactory, dbName);
    try {
      let next;
      await new Promise((resolve, reject) => {
        const tx = openStrictWriteTx(db);
        const store = tx.objectStore(BOOT_PROFILE_STORE);
        const getReq = store.get(BOOT_PROFILE_KEY);
        getReq.onsuccess = () => {
          try {
            const current = getReq.result ? validateBootProfile(getReq.result) : defaultBootProfile();
            next = validateBootProfile(mutator(structuredClone(current)));
            store.put(next, BOOT_PROFILE_KEY);
          } catch (err) {
            try { tx.abort(); } catch {}
            reject(err);
          }
        };
        getReq.onerror = () => reject(getReq.error ?? new Error('Failed to read boot profile for update.'));
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error ?? new Error('Failed to update boot profile.'));
        tx.onabort = () => reject(tx.error ?? new Error('Boot profile update aborted.'));
      });
      return next;
    } finally {
      db.close();
    }
  }

  async function setVolumeUuid(volumeUuid) {
    return update(profile => {
      if (!profile.root || typeof profile.root !== 'object' || !profile.root.cow_fs) {
        profile.root = { cow_fs: { volume_uuid: volumeUuid, writer_mode: 'fork_on_busy' } };
      } else {
        profile.root.cow_fs.volume_uuid = volumeUuid;
      }
      return profile;
    });
  }

  /**
   * Atomically claim the initial default `cow_fs.volume_uuid` when unset (compare-and-set
   * serialized across tabs via Web Locks + strict IDB transaction, Codex Finding #11).
   * Returns `{ won: true, volumeUuid: candidateUuid, profile }` if this caller installed the
   * profile UUID, or `{ won: false, volumeUuid: existingUuid, profile }` if another tab won first.
   */
  async function claimVolumeUuid(candidateUuid, { locked = false } = {}) {
    if (typeof candidateUuid !== 'string' || !candidateUuid.trim() || candidateUuid.includes('\0') || candidateUuid.includes('/')) {
      throw new Error('Invalid candidate volume_uuid.');
    }
    const runCas = async () => {
      const db = await openProfileDb(idbFactory, dbName);
      try {
        let won = false;
        let resolvedUuid = candidateUuid;
        let resolvedProfile = null;
        await new Promise((resolve, reject) => {
          const tx = openStrictWriteTx(db);
          const store = tx.objectStore(BOOT_PROFILE_STORE);
          const getReq = store.get(BOOT_PROFILE_KEY);
          getReq.onsuccess = () => {
            try {
              const current = getReq.result ? validateBootProfile(getReq.result) : defaultBootProfile();
              const existing = current.root?.cow_fs?.volume_uuid ?? null;
              if (existing) {
                won = existing === candidateUuid;
                resolvedUuid = existing;
                resolvedProfile = current;
                return;
              }
              const next = structuredClone(current);
              if (!next.root || typeof next.root !== 'object' || !next.root.cow_fs) {
                next.root = { cow_fs: { volume_uuid: candidateUuid, writer_mode: 'fork_on_busy' } };
              } else {
                next.root.cow_fs.volume_uuid = candidateUuid;
              }
              resolvedProfile = validateBootProfile(next);
              resolvedUuid = candidateUuid;
              won = true;
              store.put(resolvedProfile, BOOT_PROFILE_KEY);
            } catch (err) {
              try { tx.abort(); } catch {}
              reject(err);
            }
          };
          getReq.onerror = () => reject(getReq.error ?? new Error('Failed to read boot profile for claim.'));
          tx.oncomplete = () => resolve();
          tx.onerror = () => reject(tx.error ?? new Error('Failed to claim boot profile volume UUID.'));
          tx.onabort = () => reject(tx.error ?? new Error('Boot profile volume UUID claim aborted.'));
        });
        return { won, volumeUuid: resolvedUuid, profile: resolvedProfile };
      } finally {
        db.close();
      }
    };
    if (locked) return runCas();
    const locksApi = options.locks ?? globalThis.navigator?.locks;
    if (locksApi && typeof locksApi.request === 'function') {
      return locksApi.request(`os-boot-profile-provision:${dbName}`, { mode: 'exclusive' }, runCas);
    }
    return runCas();
  }

  /**
   * Run a first-boot provisioning callback serialized across concurrent tabs on this profile
   * (Codex Finding #11) so only one tab formats & persists the initial default root UUID.
   */
  async function withProvisionLock(fn) {
    const locksApi = options.locks ?? globalThis.navigator?.locks;
    if (locksApi && typeof locksApi.request === 'function') {
      return locksApi.request(`os-boot-profile-provision:${dbName}`, { mode: 'exclusive' }, fn);
    }
    return fn();
  }

  async function setWriterMode(writerMode) {
    return update(profile => {
      if (!profile.root.cow_fs) {
        profile.root = { cow_fs: { volume_uuid: null, writer_mode: writerMode } };
      } else {
        profile.root.cow_fs.writer_mode = writerMode;
      }
      return profile;
    });
  }

  async function setDefaultUser(defaultUser) {
    return update(profile => {
      profile.default_user = defaultUser;
      return profile;
    });
  }

  async function setGeneration(generation) {
    return update(profile => {
      profile.generation = generation;
      return profile;
    });
  }

  async function setRecovery(recovery) {
    return update(profile => {
      profile.recovery = Boolean(recovery);
      return profile;
    });
  }

  async function reset() {
    return save(defaultBootProfile());
  }

  return {
    dbName,
    load,
    save,
    update,
    setVolumeUuid,
    claimVolumeUuid,
    withProvisionLock,
    setWriterMode,
    setDefaultUser,
    setGeneration,
    setRecovery,
    reset,
  };
}

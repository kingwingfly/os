// The document/Worker URL pins the entire generation. A digest selects an approved
// filesystem view; it never authenticates a process or grants additional authority.
const match = globalThis.location?.pathname?.match(/^\/boot\/releases\/([a-f0-9]{64})\/assets(?:\/|$)/);
export const releaseId = match?.[1] ?? 'legacy';
const prefix = match ? `/boot/releases/${releaseId}/assets` : '';
export function asset(path) {
  if (!prefix || typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//') || path.startsWith('/api/') || path.startsWith('/boot/')) return path;
  return prefix + (path === '/' ? '/index.html' : path);
}
export function entryPath(path) { return path.replace(/^\/boot\/releases\/[a-f0-9]{64}\/assets/, ''); }
// Recovery windows stay on the operator's fallback assets, including child windows.
// Selecting an active release in a redirect would mix generations during recovery.
export function entry(path) {
  const pinned = asset(path);
  if (prefix || new URLSearchParams(globalThis.location?.search).get('recovery') !== '1') return pinned;
  const target = new URL(pinned, location.href);
  target.searchParams.set('recovery', '1');
  return target.pathname + target.search + target.hash;
}

// Includes wasm-bindgen's HTTP calls and all browser applications. Dedicated Workers
// install this independently; process credentials remain authoritative on the server.
if (globalThis.location && globalThis.fetch && !globalThis.__osReleaseFetch) {
  const original = globalThis.fetch.bind(globalThis);
  globalThis.fetch = (input, init) => {
    const requested = new URL(input instanceof Request ? input.url : input, location.href);
    if (requested.origin !== location.origin) return original(input, init);
    if (requested.pathname.startsWith('/api/')) {
      const request = new Request(input, init);
      const headers = new Headers(request.headers);
      if (!headers.has('X-OS-Release')) headers.set('X-OS-Release', releaseId);
      return original(new Request(request, { headers }));
    }
    const pinned = asset(requested.pathname);
    if (pinned !== requested.pathname) {
      requested.pathname = pinned;
      return original(input instanceof Request ? new Request(requested, input) : requested, init);
    }
    return original(input, init);
  };
  globalThis.__osReleaseFetch = true;
}

const HEX64 = /^[a-f0-9]{64}$/;
const hex = bytes => [...new Uint8Array(bytes)].map(v => v.toString(16).padStart(2, '0')).join('');
const unhex = value => {
  if (typeof value !== 'string' || value.length % 2 || !/^[a-f0-9]+$/.test(value)) throw new Error('Invalid release signature encoding.');
  return Uint8Array.from(value.match(/../g), s => Number.parseInt(s, 16));
};

const OFFLINE_DB_NAME = 'os-offline-releases-v2';
const OFFLINE_DB_VERSION = 1;
const OFFLINE_STORE = 'state';
const OFFLINE_STATE_KEY = 'generations';

function openOfflineDb() {
  const idb = globalThis.indexedDB;
  if (!idb) return Promise.resolve(null);
  return new Promise(resolve => {
    try {
      const req = idb.open(OFFLINE_DB_NAME, OFFLINE_DB_VERSION);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(OFFLINE_STORE)) {
          db.createObjectStore(OFFLINE_STORE);
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
}

async function readOfflineState() {
  const db = await openOfflineDb();
  if (!db) return null;
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(OFFLINE_STORE, 'readonly');
      const req = tx.objectStore(OFFLINE_STORE).get(OFFLINE_STATE_KEY);
      req.onsuccess = () => resolve(req.result ?? null);
      req.onerror = () => reject(req.error);
    });
  } catch {
    return null;
  } finally {
    db.close();
  }
}

async function readProfileTrustRoot() {
  const state = await readOfflineState();
  return state?.trustRoot ?? null;
}

/**
 * Zero-network Stage 0 offline lookup of an installed Release v2 generation (active or pinned).
 * Returns `{ releaseId, manifestBytes, signature, trust, state }` directly from OPFS + IDB
 * with ZERO outbound `fetch()` requests, or `null` if no generation is installed locally.
 */
export async function resolveOfflineInstalledRelease(preferredGeneration = null) {
  const state = await readOfflineState();
  const targetId = preferredGeneration || state?.active || null;
  if (!targetId || !HEX64.test(targetId) || !state?.trustRoot) return null;
  const local = await readLocalPinned(targetId);
  if (!local) return null;
  return {
    releaseId: targetId,
    manifestBytes: local.bytes,
    signature: local.signature,
    trust: {
      keys: { ...(state.trustRoot.keys ?? {}) },
      revoked: [...(state.trustRoot.revoked ?? [])],
    },
    state,
  };
}

async function ratchetProfileTrust(incomingTrust, incomingMinSeq) {
  if (!incomingTrust || typeof incomingTrust !== 'object') return null;
  const db = await openOfflineDb();
  if (!db) return null;
  try {
    return await new Promise((resolve, reject) => {
      let tx;
      try {
        tx = db.transaction(OFFLINE_STORE, 'readwrite', { durability: 'strict' });
      } catch {
        tx = db.transaction(OFFLINE_STORE, 'readwrite');
      }
      const store = tx.objectStore(OFFLINE_STORE);
      let updatedRoot = null;
      const getReq = store.get(OFFLINE_STATE_KEY);
      getReq.onsuccess = () => {
        try {
          const cur = getReq.result;
          if (!cur?.trustRoot) {
            updatedRoot = null;
            return;
          }
          const root = structuredClone(cur.trustRoot);
          const revoked = new Set(Array.isArray(root.revoked) ? root.revoked : []);
          let changed = false;
          if (Array.isArray(incomingTrust.revoked)) {
            for (const keyId of incomingTrust.revoked) {
              if (typeof keyId === 'string' && HEX64.test(keyId) && !revoked.has(keyId)) {
                revoked.add(keyId);
                changed = true;
              }
            }
          }
          if (Number.isSafeInteger(incomingMinSeq) && incomingMinSeq > (root.minReleaseSeq || 0)) {
            root.minReleaseSeq = incomingMinSeq;
            changed = true;
          }
          root.revoked = [...revoked].sort();
          updatedRoot = root;
          if (changed) {
            cur.trustRoot = root;
            store.put(cur, OFFLINE_STATE_KEY);
          }
        } catch (err) {
          try { tx.abort(); } catch {}
          reject(err);
        }
      };
      getReq.onerror = () => reject(getReq.error);
      tx.oncomplete = () => resolve(updatedRoot);
      tx.onerror = () => reject(tx.error ?? new Error('Failed to ratchet profile trust.'));
      tx.onabort = () => reject(tx.error ?? new Error('Profile trust update aborted.'));
    });
  } catch {
    return null;
  } finally {
    db.close();
  }
}

function mergeMonotonicTrust(profileRoot, incomingTrust) {
  if (!profileRoot) return incomingTrust;
  const keys = { ...(profileRoot.keys ?? {}) };
  const revoked = new Set(Array.isArray(profileRoot.revoked) ? profileRoot.revoked : []);
  if (incomingTrust && typeof incomingTrust === 'object') {
    if (Array.isArray(incomingTrust.revoked)) {
      for (const k of incomingTrust.revoked) {
        if (typeof k === 'string' && HEX64.test(k)) revoked.add(k);
      }
    }
    if (incomingTrust.keys && typeof incomingTrust.keys === 'object') {
      for (const [k, v] of Object.entries(incomingTrust.keys)) {
        if (k in keys && keys[k] !== v) {
          throw new Error('Publisher key identifier mismatch.');
        }
      }
    }
  }
  return { keys, revoked: [...revoked].sort() };
}

async function readLocalPinned(id) {
  try {
    const root = await globalThis.navigator?.storage?.getDirectory?.();
    if (!root) return null;
    const relDir = await (await (await root.getDirectoryHandle('os-releases')).getDirectoryHandle('releases')).getDirectoryHandle(id);
    const read = async name => new Uint8Array(await (await (await relDir.getFileHandle(name)).getFile()).arrayBuffer());
    const [bytes, sigBytes] = await Promise.all([read('manifest.json'), read('signature.json')]);
    const signature = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(sigBytes));
    return { bytes, signature };
  } catch {
    return null;
  }
}

/**
 * Explicitly refresh and ratchet the profile-wide monotonic trust root from `/boot/entries`
 * AFTER Stage 2 boot when online (Codex Finding #7: Stage 0 verification MUST remain 100%
 * offline with zero network fetches whenever a locally installed release is present).
 */
export async function refreshOnlineTrustRoot() {
  if (globalThis.navigator?.onLine === false) return null;
  try {
    const res = await fetch('/boot/entries', { cache: 'no-store' });
    if (res.status === 503) {
      throw new Error('Release publisher is not trusted.');
    }
    if (!res.ok) return null;
    const liveEntries = await res.json();
    if (liveEntries.format !== 'os.boot' || liveEntries.version !== 2 || liveEntries.protocol !== 2 || liveEntries.schema !== 10) {
      throw new Error('The authority is incompatible with this release.');
    }
    return await ratchetProfileTrust(liveEntries.trust, liveEntries.min_release_seq);
  } catch (err) {
    if (err?.message === 'Release publisher is not trusted.' || err?.message === 'The authority is incompatible with this release.' || err?.message === 'Publisher key identifier mismatch.') {
      throw err;
    }
    return null;
  }
}

let checking;
export function verifyRelease(options = {}) {
  if (releaseId === 'legacy') return Promise.resolve();
  return checking ??= (async () => {
    let entries = null;
    let bytes;
    let signature;
    let profileRoot = await readProfileTrustRoot();
    const local = await readLocalPinned(releaseId);

    if (local) {
      ({ bytes, signature } = local);
      // Stage 0 verification of a locally installed Release v2 is strictly zero-network
      // (Codex Finding #7): verify solely against the profile-wide monotonic `trustRoot`.
      // Online trust refresh runs explicitly post-boot via `refreshOnlineTrustRoot()`.
      if (!profileRoot) {
        throw new Error('Release publisher is not trusted.');
      }
      entries = {
        format: 'os.boot',
        version: 2,
        protocol: 2,
        schema: 10,
        default: releaseId,
        trust: { keys: { ...(profileRoot.keys ?? {}) }, revoked: [...(profileRoot.revoked ?? [])] },
      };
    } else {
      const get = async path => { const response = await fetch(path, { cache: 'no-store' }); if (!response.ok) throw new Error('The release is unavailable. Open recovery.'); return response; };
      entries = await (await get('/boot/entries')).json();
      if (entries.format !== 'os.boot' || entries.version !== 2 || entries.protocol !== 2 || entries.schema !== 10) {
        throw new Error('The authority is incompatible with this release.');
      }
      if (profileRoot) {
        const ratcheted = await ratchetProfileTrust(entries.trust, entries.min_release_seq);
        if (ratcheted) profileRoot = ratcheted;
        entries = { ...entries, trust: mergeMonotonicTrust(profileRoot, entries.trust) };
      }
      bytes = new Uint8Array(await (await get(`/boot/releases/${releaseId}/manifest.json`)).arrayBuffer());
      signature = await (await get(`/boot/releases/${releaseId}/signature.json`)).json();
    }
    if (entries.format !== 'os.boot' || entries.version !== 2 || entries.protocol !== 2 || entries.schema !== 10) {
      throw new Error('The authority is incompatible with this release.');
    }
    if (hex(await crypto.subtle.digest('SHA-256', bytes)) !== releaseId) throw new Error('Release digest mismatch.');
    const trusted = entries.trust?.keys?.[signature.key];
    const revoked = Array.isArray(entries.trust?.revoked) ? entries.trust.revoked : [];
    if (signature.format !== 'os.signature' || signature.version !== 1 || !trusted || revoked.includes(signature.key)) throw new Error('Release publisher is not trusted.');
    const publicKey = unhex(trusted);
    if (hex(await crypto.subtle.digest('SHA-256', publicKey)) !== signature.key) throw new Error('Publisher key identifier mismatch.');
    const key = await crypto.subtle.importKey('raw', publicKey, 'Ed25519', false, ['verify']);
    const domain = new TextEncoder().encode('os.release.v2\0');
    const message = new Uint8Array(domain.length + bytes.length); message.set(domain); message.set(bytes, domain.length);
    if (!await crypto.subtle.verify('Ed25519', key, unhex(signature.signature), message)) throw new Error('Invalid release signature.');
    const release = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (
      release.format !== 'os.release'
      || release.version !== 2
      || !release.protocol || release.protocol.min > 2 || release.protocol.max < 2
      || !release.schema || release.schema.min > 10 || release.schema.max < 10
      || !release.loader?.host_adapter || release.loader.host_adapter.min > 2 || release.loader.host_adapter.max < 2
      || !HEX64.test(release.boot ?? '')
      || !HEX64.test(release.initramfs ?? '')
      || !HEX64.test(release.root_template ?? '')
      || !HEX64.test(release.base ?? '')
    ) {
      throw new Error('Incompatible release metadata.');
    }
  })();
}

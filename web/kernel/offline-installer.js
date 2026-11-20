// Atomic Offline Release v2 Installer & Offline Service Worker (#78 L2.5b, Blueprint §2.4 & §3.3).
//
// - Pins the complete Release v2 boot set (`manifest.json`, `signature.json`, `images/*.json`,
//   `images/*.sig`, `boot` assets, `initramfs`, `root_template`, `base`, `sysext`, `confext` blobs)
//   into OPFS `/os-releases/staging/<releaseId>` + Cache Storage `os-release-v2:<releaseId>`.
// - Verifies Ed25519 signatures (`os.release.v2` / `os.image.v2`), `Trust` keys & revocations,
//   Stage 1 `Initramfs` & `RootTemplate` invariants, and every blob's full + per-chunk SHA-256
//   digests BEFORE atomically updating IndexedDB `{ durability: "strict" }`.
// - Preserves `previous` generation intact until `markBootHealthy(releaseId)` succeeds, enabling
//   clean automatic or explicit rollback on crash or failed verification.
// - When evaluated in a ServiceWorkerGlobalScope (`/offline-sw.js`), serves active installed
//   generations from Cache Storage + OPFS with ZERO outbound network requests.

export const OFFLINE_DB_NAME = 'os-offline-releases-v2';
export const OFFLINE_DB_VERSION = 1;
export const OFFLINE_STORE = 'state';
export const OFFLINE_STATE_KEY = 'generations';
export const CACHE_PREFIX = 'os-release-v2:';

export const RELEASE_VERSION = 2;
export const IMAGE_VERSION = 2;
export const PROTOCOL_VERSION = 2;
export const SCHEMA_VERSION = 10;
export const HOST_ADAPTER_VERSION = 2;
export const CHUNK_SIZE_MIN = 64 * 1024;
export const CHUNK_SIZE_MAX = 1024 * 1024;
export const SIGNING_DOMAIN_RELEASE_V2 = 'os.release.v2';
export const SIGNING_DOMAIN_IMAGE_V2 = 'os.image.v2';
export const EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

export const REQUIRED_INITRAMFS_BINS = [
  '/init',
  '/bin/mount',
  '/bin/switch_root',
  '/bin/cowfsck',
  '/bin/sh',
];

const PROTECTED_PATHS = [
  '/etc/passwd',
  '/etc/group',
  '/etc/shadow',
  '/etc/gshadow',
  '/etc/sudoers',
  '/etc/sudoers.d',
  '/etc/os-trust',
];

const HEX64 = /^[a-f0-9]{64}$/;
const HEX128 = /^[a-f0-9]{128}$/;

function toHex(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}

function unhex(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length % 2 !== 0 || !/^[a-f0-9]+$/.test(value)) {
    throw new Error('Invalid hexadecimal encoding.');
  }
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function isPowerOfTwo(n) {
  return Number.isInteger(n) && n > 0 && (n & (n - 1)) === 0;
}

function below(path, root) {
  return path === root || path.startsWith(root + '/');
}

function isProtected(path) {
  return PROTECTED_PATHS.some(p => below(path, p));
}

function parentPath(path) {
  const idx = path.lastIndexOf('/');
  if (idx <= 0) return '/';
  return path.slice(0, idx);
}

function validPath(path) {
  if (typeof path !== 'string' || !path.startsWith('/') || path.length > 4096 || path.includes('\0')) return false;
  if (path === '/') return true;
  return path.slice(1).split('/').every(p => p.length > 0 && p !== '.' && p !== '..' && p.length <= 255);
}

function mimeTypeFor(path) {
  if (path.endsWith('.html')) return 'text/html; charset=utf-8';
  if (path.endsWith('.js') || path.endsWith('.mjs')) return 'application/javascript; charset=utf-8';
  if (path.endsWith('.wasm')) return 'application/wasm';
  if (path.endsWith('.css')) return 'text/css; charset=utf-8';
  if (path.endsWith('.json')) return 'application/json; charset=utf-8';
  if (path.endsWith('.svg')) return 'image/svg+xml';
  if (path.endsWith('.png')) return 'image/png';
  return 'application/octet-stream';
}

function isolatedHeaders(contentType, etag) {
  const headers = new Headers({
    'Content-Type': contentType,
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Embedder-Policy': 'require-corp',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Cache-Control': 'no-cache',
  });
  if (etag) headers.set('ETag', etag);
  return headers;
}

async function sha256Hex(bytes, cryptoApi = globalThis.crypto) {
  const subtle = cryptoApi?.subtle ?? globalThis.crypto?.subtle;
  if (!subtle) throw new Error('WebCrypto SHA-256 unavailable.');
  return toHex(await subtle.digest('SHA-256', bytes));
}

export async function verifyEd25519Detached(domain, bytes, sigObj, trust, cryptoApi = globalThis.crypto) {
  if (domain !== SIGNING_DOMAIN_RELEASE_V2 && domain !== SIGNING_DOMAIN_IMAGE_V2) {
    throw new Error(`Unsupported signing domain: ${domain}`);
  }
  if (!sigObj || sigObj.format !== 'os.signature' || sigObj.version !== 1) {
    throw new Error('Unsupported signature format.');
  }
  if (typeof sigObj.key !== 'string' || !HEX64.test(sigObj.key)) {
    throw new Error('Invalid publisher key identifier.');
  }
  if (typeof sigObj.signature !== 'string' || !HEX128.test(sigObj.signature)) {
    throw new Error('Invalid Ed25519 signature encoding.');
  }
  if (!trust || typeof trust !== 'object' || typeof trust.keys !== 'object') {
    throw new Error('Missing publisher trust configuration.');
  }
  const revoked = Array.isArray(trust.revoked) ? trust.revoked : [];
  if (revoked.includes(sigObj.key)) {
    throw new Error('Release publisher key is revoked.');
  }
  const pubHex = trust.keys[sigObj.key];
  if (typeof pubHex !== 'string' || !HEX64.test(pubHex)) {
    throw new Error('Release publisher is not trusted.');
  }
  const pubBytes = unhex(pubHex);
  if (await sha256Hex(pubBytes, cryptoApi) !== sigObj.key) {
    throw new Error('Publisher key identifier mismatch.');
  }
  const subtle = cryptoApi?.subtle ?? globalThis.crypto?.subtle;
  const key = await subtle.importKey('raw', pubBytes, 'Ed25519', false, ['verify']);
  const prefix = new TextEncoder().encode(domain + '\0');
  const message = new Uint8Array(prefix.length + bytes.byteLength);
  message.set(prefix, 0);
  message.set(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes), prefix.length);
  const ok = await subtle.verify('Ed25519', key, unhex(sigObj.signature), message);
  if (!ok) throw new Error('Invalid release/image Ed25519 signature.');
  return sigObj.key;
}

export function validateReleaseV2Manifest(release) {
  if (!release || typeof release !== 'object') throw new Error('Invalid release manifest.');
  if (release.format !== 'os.release' || release.version !== RELEASE_VERSION) {
    throw new Error(`Unsupported release format/version (${release.format} v${release.version}).`);
  }
  if (typeof release.name !== 'string' || !release.name || release.name.length > 128) {
    throw new Error('Invalid release name.');
  }
  if (!release.protocol || release.protocol.min > PROTOCOL_VERSION || release.protocol.max < PROTOCOL_VERSION) {
    throw new Error('Incompatible release protocol range.');
  }
  if (!release.schema || release.schema.min > SCHEMA_VERSION || release.schema.max < SCHEMA_VERSION) {
    throw new Error('Incompatible release schema range.');
  }
  const loader = release.loader;
  if (!loader || typeof loader !== 'object') throw new Error('Missing release loader metadata.');
  for (const field of ['entry', 'client_kernel_js', 'client_kernel_wasm']) {
    if (!validPath(loader[field]) || loader[field] === '/') {
      throw new Error(`Invalid loader.${field}`);
    }
  }
  if (typeof loader.client_kernel_sha256 !== 'string' || !HEX64.test(loader.client_kernel_sha256)) {
    throw new Error('Invalid loader.client_kernel_sha256.');
  }
  if (!loader.host_adapter || loader.host_adapter.min > HOST_ADAPTER_VERSION || loader.host_adapter.max < HOST_ADAPTER_VERSION) {
    throw new Error('Incompatible host_adapter version range.');
  }
  if (!Array.isArray(release.sysext) || !Array.isArray(release.confext) || release.sysext.length + release.confext.length > 32) {
    throw new Error('Invalid release extension lists.');
  }
  const all = [release.boot, release.initramfs, release.root_template, release.base, ...release.sysext, ...release.confext];
  const seen = new Set();
  for (const id of all) {
    if (typeof id !== 'string' || !HEX64.test(id)) throw new Error('Invalid image digest in release.');
    if (seen.has(id)) throw new Error('Duplicate image digest in release.');
    seen.add(id);
  }
  return all;
}

function resolveInMap(entriesMap, path) {
  if (!validPath(path)) throw new Error(`Invalid lookup path: ${path}`);
  const todo = path.split('/').filter(Boolean);
  const parts = [];
  let links = 0;
  while (todo.length > 0) {
    const part = todo.shift();
    if (part === '.' || part === '') continue;
    if (part === '..') {
      if (parts.length === 0) throw new Error('Symlink escapes root.');
      parts.pop();
      continue;
    }
    parts.push(part);
    const cur = '/' + parts.join('/');
    const entry = entriesMap.get(cur);
    if (!entry) throw new Error(`Dangling symlink target: ${cur}`);
    if (entry.node.type === 'symlink') {
      links++;
      if (links > 40) throw new Error('Symlink loop.');
      parts.pop();
      if (entry.node.target.startsWith('/')) parts.length = 0;
      const targetParts = entry.node.target.split('/');
      for (let i = targetParts.length - 1; i >= 0; i--) todo.unshift(targetParts[i]);
    } else if (todo.length > 0 && entry.node.type !== 'directory') {
      throw new Error('Symlink traverses non-directory.');
    }
  }
  return '/' + parts.join('/');
}

export function validateImageV2Manifest(image, expectedKind) {
  if (!image || typeof image !== 'object') throw new Error('Invalid image manifest.');
  if (image.format !== 'os.image' || image.version !== IMAGE_VERSION) {
    throw new Error(`Unsupported image format/version (${image.format} v${image.version}).`);
  }
  if (expectedKind && image.kind !== expectedKind) {
    throw new Error(`Image kind mismatch: expected ${expectedKind}, got ${image.kind}.`);
  }
  if (!Array.isArray(image.entries) || image.entries.length > 16384) {
    throw new Error('Invalid image entries.');
  }
  let prev = null;
  const byPath = new Map();
  for (const entry of image.entries) {
    if (!validPath(entry.path)) throw new Error(`Invalid image path: ${entry.path}`);
    if (prev !== null && !(prev < entry.path)) throw new Error('Image entries must be sorted and unique.');
    prev = entry.path;
    if (!Number.isInteger(entry.mode) || entry.mode < 0 || entry.mode > 0o1777) {
      throw new Error('Unsupported permission bits in image.');
    }
    if (entry.path === '/') {
      if (entry.node?.type !== 'directory') throw new Error('Image root entry must be a directory.');
    } else if (image.kind === 'confext' && (!below(entry.path, '/etc') || isProtected(entry.path))) {
      throw new Error(`Confext entry disallowed: ${entry.path}`);
    }
    if (image.kind === 'boot' && entry.node?.type === 'symlink') {
      throw new Error('Boot assets cannot contain symlinks.');
    }
    if (entry.node?.type === 'file') {
      const { sha256, size, chunk_size: chunkSize, chunks } = entry.node;
      if (typeof sha256 !== 'string' || !HEX64.test(sha256)) throw new Error('Invalid file sha256.');
      if (!Number.isSafeInteger(size) || size < 0) throw new Error('Invalid file size.');
      if (!isPowerOfTwo(chunkSize) || chunkSize < CHUNK_SIZE_MIN || chunkSize > CHUNK_SIZE_MAX) {
        throw new Error('Invalid file chunk_size.');
      }
      const expectedCount = size === 0 ? 0 : Math.ceil(size / chunkSize);
      if (!Array.isArray(chunks) || chunks.length !== expectedCount) {
        throw new Error(`Chunk digest count mismatch on ${entry.path}.`);
      }
      for (const c of chunks) {
        if (typeof c !== 'string' || !HEX64.test(c)) throw new Error('Invalid chunk digest hex.');
      }
      if (size === 0 && sha256 !== EMPTY_SHA256) throw new Error('Empty file sha256 mismatch.');
      if (chunks.length === 1 && chunks[0] !== sha256) throw new Error('Single-chunk digest mismatch.');
    } else if (entry.node?.type !== 'directory' && entry.node?.type !== 'symlink') {
      throw new Error('Unknown image node type.');
    }
    byPath.set(entry.path, entry);
  }

  if (image.kind === 'initramfs' || image.kind === 'roottemplate') {
    if (byPath.get('/')?.node?.type !== 'directory') throw new Error('Missing root directory.');
    for (const entry of image.entries) {
      if (entry.path !== '/' && byPath.get(parentPath(entry.path))?.node?.type !== 'directory') {
        throw new Error(`Missing directory parent for ${entry.path}`);
      }
    }
    if (image.kind === 'initramfs') {
      for (const required of REQUIRED_INITRAMFS_BINS) {
        const resolved = resolveInMap(byPath, required);
        const target = byPath.get(resolved);
        if (!target || target.node.type !== 'file' || (target.mode & 0o111) === 0) {
          throw new Error(`Required initramfs executable missing: ${required}`);
        }
      }
    } else {
      for (const dir of ['/etc', '/var', '/root']) {
        if (byPath.get(dir)?.node?.type !== 'directory') throw new Error(`RootTemplate missing dir ${dir}`);
      }
      for (const file of ['/etc/passwd', '/etc/group']) {
        if (byPath.get(file)?.node?.type !== 'file') throw new Error(`RootTemplate missing file ${file}`);
      }
      if (byPath.has('/etc/os-trust')) throw new Error('RootTemplate cannot include /etc/os-trust.');
    }
  }
  return byPath;
}

// --- Default browser IndexedDB ({ durability: "strict" }) state adapter ---

function openBrowserDb(idbFactory = globalThis.indexedDB) {
  return new Promise((resolve, reject) => {
    const req = idbFactory.open(OFFLINE_DB_NAME, OFFLINE_DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(OFFLINE_STORE)) {
        db.createObjectStore(OFFLINE_STORE);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('Failed to open offline release IndexedDB.'));
  });
}

function createBrowserStateStore(idbFactory = globalThis.indexedDB) {
  function emptyState() {
    return {
      format: 'os.offline.state',
      version: 2,
      active: null,
      previous: null,
      activeBootVerified: false,
      bootAttempts: 0,
      generations: {},
    };
  }
  return {
    async read() {
      const db = await openBrowserDb(idbFactory);
      try {
        return await new Promise((resolve, reject) => {
          const tx = db.transaction(OFFLINE_STORE, 'readonly');
          const req = tx.objectStore(OFFLINE_STORE).get(OFFLINE_STATE_KEY);
          req.onsuccess = () => resolve(req.result ?? emptyState());
          req.onerror = () => reject(req.error);
        });
      } finally {
        db.close();
      }
    },
    async updateStrict(mutator) {
      const db = await openBrowserDb(idbFactory);
      try {
        return await new Promise((resolve, reject) => {
          let tx;
          try {
            tx = db.transaction(OFFLINE_STORE, 'readwrite', { durability: 'strict' });
          } catch {
            tx = db.transaction(OFFLINE_STORE, 'readwrite');
          }
          const store = tx.objectStore(OFFLINE_STORE);
          let nextState;
          const getReq = store.get(OFFLINE_STATE_KEY);
          getReq.onsuccess = () => {
            try {
              const current = getReq.result ?? emptyState();
              nextState = mutator(structuredClone(current));
              store.put(nextState, OFFLINE_STATE_KEY);
            } catch (err) {
              try { tx.abort(); } catch {}
              reject(err);
            }
          };
          getReq.onerror = () => reject(getReq.error);
          tx.oncomplete = () => resolve(nextState);
          tx.onerror = () => reject(tx.error ?? new Error('Strict IndexedDB transaction failed.'));
          tx.onabort = () => reject(tx.error ?? new Error('Strict IndexedDB transaction aborted.'));
        });
      } finally {
        db.close();
      }
    },
  };
}

// --- Default browser OPFS hierarchical file adapter ---

async function ensureDir(root, parts) {
  let dir = root;
  for (const part of parts) {
    dir = await dir.getDirectoryHandle(part, { create: true });
  }
  return dir;
}

async function getDir(root, parts) {
  let dir = root;
  for (const part of parts) {
    dir = await dir.getDirectoryHandle(part);
  }
  return dir;
}

function createBrowserOpfsStore(rootProvider) {
  const getRoot = () => (rootProvider ? rootProvider() : globalThis.navigator.storage.getDirectory());
  return {
    async writeFile(relPath, bytes) {
      const parts = relPath.split('/').filter(Boolean);
      const name = parts.pop();
      const dir = await ensureDir(await getRoot(), parts);
      const handle = await dir.getFileHandle(name, { create: true });
      const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
      if (typeof handle.createSyncAccessHandle === 'function') {
        const sync = await handle.createSyncAccessHandle();
        try {
          sync.truncate(0);
          sync.write(data, { at: 0 });
          sync.flush();
        } finally {
          sync.close();
        }
      } else {
        const writable = await handle.createWritable();
        try {
          await writable.write(data);
          await writable.close();
        } catch (err) {
          await writable.abort().catch(() => {});
          throw err;
        }
      }
    },
    async readFile(relPath) {
      const parts = relPath.split('/').filter(Boolean);
      const name = parts.pop();
      try {
        const dir = await getDir(await getRoot(), parts);
        const handle = await dir.getFileHandle(name);
        const file = await handle.getFile();
        return new Uint8Array(await file.arrayBuffer());
      } catch (err) {
        if (err?.name === 'NotFoundError') return null;
        throw err;
      }
    },
    async exists(relPath) {
      const parts = relPath.split('/').filter(Boolean);
      const name = parts.pop();
      try {
        const dir = await getDir(await getRoot(), parts);
        await dir.getFileHandle(name);
        return true;
      } catch {
        return false;
      }
    },
    async removeDir(relPath) {
      const parts = relPath.split('/').filter(Boolean);
      const name = parts.pop();
      if (!name) return;
      try {
        const parent = await getDir(await getRoot(), parts);
        await parent.removeEntry(name, { recursive: true });
      } catch (err) {
        if (err?.name !== 'NotFoundError') throw err;
      }
    },
  };
}

// --- Default browser Cache Storage adapter ---

function createBrowserCacheStore(cachesApi = globalThis.caches) {
  return {
    async put(cacheName, urlPath, bytes, contentType, etag) {
      const cache = await cachesApi.open(cacheName);
      const response = new Response(bytes, { status: 200, headers: isolatedHeaders(contentType, etag) });
      await cache.put(urlPath, response);
    },
    async match(cacheName, urlPath) {
      const cache = await cachesApi.open(cacheName);
      return await cache.match(urlPath);
    },
    async deleteCache(cacheName) {
      await cachesApi.delete(cacheName);
    },
  };
}

async function verifyBytesAgainstFileNode(bytes, node, cryptoApi) {
  if (bytes.byteLength !== node.size) {
    throw new Error(`Blob length mismatch: got ${bytes.byteLength}, expected ${node.size}.`);
  }
  const fullSha = await sha256Hex(bytes, cryptoApi);
  if (fullSha !== node.sha256) {
    throw new Error(`Blob SHA-256 mismatch: got ${fullSha}, expected ${node.sha256}.`);
  }
  const cs = node.chunk_size;
  const expectedChunks = node.chunks;
  if (bytes.byteLength === 0) {
    if (expectedChunks.length !== 0) throw new Error('Non-empty chunk list for empty blob.');
    return;
  }
  let idx = 0;
  for (let off = 0; off < bytes.byteLength; off += cs, idx++) {
    const slice = bytes.subarray(off, Math.min(bytes.byteLength, off + cs));
    const chunkSha = await sha256Hex(slice, cryptoApi);
    if (chunkSha !== expectedChunks[idx]) {
      throw new Error(`Chunk ${idx} SHA-256 mismatch: got ${chunkSha}, expected ${expectedChunks[idx]}.`);
    }
  }
  if (idx !== expectedChunks.length) {
    throw new Error('Chunk count mismatch during verification.');
  }
}

function encodeAssetPath(path) {
  return path.split('/').map(part => encodeURIComponent(part)).join('/');
}

/**
 * Creates an atomic Release v2 offline installer.
 * Accepts optional injected `{ fetch, opfs, stateStore, cacheStore, crypto }` for deterministic unit tests;
 * defaults to real browser OPFS, IndexedDB `{ durability: "strict" }`, and Cache Storage.
 */
export function createOfflineInstaller(options = {}) {
  const fetchFn = options.fetch ?? ((...args) => globalThis.fetch(...args));
  const cryptoApi = options.crypto ?? globalThis.crypto;
  const opfs = options.opfs ?? createBrowserOpfsStore(options.opfsRoot);
  const stateStore = options.stateStore ?? createBrowserStateStore(options.indexedDB);
  const cacheStore = options.cacheStore ?? createBrowserCacheStore(options.caches);

  async function fetchBytesStrict(url) {
    const res = await fetchFn(url, { cache: 'no-store' });
    if (!res.ok) throw new Error(`Failed to fetch ${url} (HTTP ${res.status}).`);
    return new Uint8Array(await res.arrayBuffer());
  }

  async function install(releaseId, installOpts = {}) {
    if (typeof releaseId !== 'string' || !HEX64.test(releaseId)) {
      throw new Error('Invalid Release v2 digest identifier.');
    }

    const stagingDir = `os-releases/staging/${releaseId}`;
    const cacheName = `${CACHE_PREFIX}${releaseId}`;
    const existingState = await stateStore.read();
    const keepCacheOnFailure = existingState.active === releaseId || existingState.previous === releaseId;

    // Request durable browser storage persistence per Contract §2.15.
    try {
      await globalThis.navigator?.storage?.persist?.();
    } catch {
      /* optional in non-browser or denied environments */
    }

    try {
      // 1. Acquire & verify trust policy.
      let trust = installOpts.trust;
      if (!trust) {
        const entriesBytes = await fetchBytesStrict('/boot/entries');
        const entries = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(entriesBytes));
        if (
          entries.format !== 'os.boot'
          || entries.version !== RELEASE_VERSION
          || entries.protocol !== PROTOCOL_VERSION
          || entries.schema !== SCHEMA_VERSION
        ) {
          throw new Error('Incompatible boot authority entries.');
        }
        trust = entries.trust;
      }

      // 2. Fetch & cryptographically verify Release v2 manifest + Ed25519 signature (`os.release.v2`).
      const manifestBytes = await fetchBytesStrict(`/boot/releases/${releaseId}/manifest.json`);
      if (await sha256Hex(manifestBytes, cryptoApi) !== releaseId) {
        throw new Error('Release manifest SHA-256 digest mismatch.');
      }
      const sigBytes = await fetchBytesStrict(`/boot/releases/${releaseId}/signature.json`);
      const sigObj = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(sigBytes));
      await verifyEd25519Detached(SIGNING_DOMAIN_RELEASE_V2, manifestBytes, sigObj, trust, cryptoApi);
      const release = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(manifestBytes));
      const imageHashes = validateReleaseV2Manifest(release);

      // 3. Fetch & verify every image manifest (`Boot`, `Initramfs`, `RootTemplate`, `Base`, `Sysext`, `Confext`).
      const expectedKinds = [
        'boot',
        'initramfs',
        'roottemplate',
        'base',
        ...release.sysext.map(() => 'sysext'),
        ...release.confext.map(() => 'confext'),
      ];
      const imageRecords = [];
      for (let i = 0; i < imageHashes.length; i++) {
        const hash = imageHashes[i];
        const imgBytes = await fetchBytesStrict(`/boot/images/${hash}.json`);
        if (await sha256Hex(imgBytes, cryptoApi) !== hash) {
          throw new Error(`Image ${hash} digest mismatch.`);
        }
        const imgSigBytes = await fetchBytesStrict(`/boot/images/${hash}.sig`);
        const imgSigObj = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(imgSigBytes));
        await verifyEd25519Detached(SIGNING_DOMAIN_IMAGE_V2, imgBytes, imgSigObj, trust, cryptoApi);
        const parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(imgBytes));
        const byPath = validateImageV2Manifest(parsed, expectedKinds[i]);
        imageRecords.push({ hash, bytes: imgBytes, sigBytes: imgSigBytes, parsed, byPath });
      }

      // Bind ReleaseV2.loader to actual Boot image entries.
      const bootMap = imageRecords[0].byPath;
      for (const field of ['entry', 'client_kernel_js', 'client_kernel_wasm']) {
        const found = bootMap.get(release.loader[field]);
        if (!found || found.node.type !== 'file') {
          throw new Error(`Boot image missing loader asset ${release.loader[field]}.`);
        }
      }
      if (bootMap.get(release.loader.client_kernel_wasm).node.sha256 !== release.loader.client_kernel_sha256) {
        throw new Error('Loader client_kernel_sha256 does not match boot image.');
      }

      // Check Base + Sysext + Confext composition collisions.
      const composed = new Map();
      for (const rec of imageRecords.slice(3)) {
        for (const entry of rec.parsed.entries) {
          const prev = composed.get(entry.path);
          if (prev) {
            if (
              prev.node.type !== 'directory'
              || entry.node.type !== 'directory'
              || prev.uid !== entry.uid
              || prev.gid !== entry.gid
              || prev.mode !== entry.mode
            ) {
              throw new Error(`Composition collision at ${entry.path}.`);
            }
          } else {
            composed.set(entry.path, entry);
          }
        }
      }

      // 4. Stage & verify ALL blobs (full SHA-256 + every chunk SHA-256!) into OPFS staging + Cache Storage.
      const stagedBlobs = new Map(); // sha256 -> Uint8Array
      const stagedBootAssets = [];   // { path, bytes, sha256 }

      for (const rec of imageRecords) {
        for (const entry of rec.parsed.entries) {
          if (entry.node.type !== 'file') continue;
          const node = entry.node;
          if (rec.parsed.kind === 'boot') {
            const assetUrl = `/boot/releases/${releaseId}/assets${encodeAssetPath(entry.path)}`;
            const bytes = await fetchBytesStrict(assetUrl);
            await verifyBytesAgainstFileNode(bytes, node, cryptoApi);
            stagedBootAssets.push({ path: entry.path, bytes, sha256: node.sha256 });
            if (!stagedBlobs.has(node.sha256)) {
              stagedBlobs.set(node.sha256, bytes);
              await opfs.writeFile(`${stagingDir}/blobs/${node.sha256}`, bytes);
            }
          } else {
            if (!stagedBlobs.has(node.sha256)) {
              const bytes = await fetchBytesStrict(`/boot/blobs/${node.sha256}`);
              await verifyBytesAgainstFileNode(bytes, node, cryptoApi);
              stagedBlobs.set(node.sha256, bytes);
              await opfs.writeFile(`${stagingDir}/blobs/${node.sha256}`, bytes);
            } else {
              // Still validate chunk list matches the already-verified blob bytes!
              await verifyBytesAgainstFileNode(stagedBlobs.get(node.sha256), node, cryptoApi);
            }
          }
        }
      }

      // Write staged release metadata + trust snapshot to OPFS staging.
      const trustBytes = new TextEncoder().encode(JSON.stringify(trust));
      await opfs.writeFile(`${stagingDir}/manifest.json`, manifestBytes);
      await opfs.writeFile(`${stagingDir}/signature.json`, sigBytes);
      await opfs.writeFile(`${stagingDir}/trust.json`, trustBytes);
      for (const rec of imageRecords) {
        await opfs.writeFile(`${stagingDir}/images/${rec.hash}.json`, rec.bytes);
        await opfs.writeFile(`${stagingDir}/images/${rec.hash}.sig`, rec.sigBytes);
      }

      // 5. Populate Cache Storage (`os-release-v2:<releaseId>`) with verified responses.
      const offlineEntriesBytes = new TextEncoder().encode(JSON.stringify({
        format: 'os.boot',
        version: RELEASE_VERSION,
        default: releaseId,
        protocol: PROTOCOL_VERSION,
        schema: SCHEMA_VERSION,
        trust,
      }));
      await cacheStore.put(cacheName, '/boot/entries', offlineEntriesBytes, 'application/json; charset=utf-8');
      await cacheStore.put(cacheName, `/boot/releases/${releaseId}/manifest.json`, manifestBytes, 'application/json; charset=utf-8', `"${releaseId}"`);
      await cacheStore.put(cacheName, `/boot/releases/${releaseId}/signature.json`, sigBytes, 'application/json; charset=utf-8');
      for (const rec of imageRecords) {
        await cacheStore.put(cacheName, `/boot/images/${rec.hash}.json`, rec.bytes, 'application/json; charset=utf-8', `"${rec.hash}"`);
        await cacheStore.put(cacheName, `/boot/images/${rec.hash}.sig`, rec.sigBytes, 'application/json; charset=utf-8');
      }
      for (const item of stagedBootAssets) {
        const mime = mimeTypeFor(item.path);
        const etag = `"${item.sha256}"`;
        const pinnedUrl = `/boot/releases/${releaseId}/assets${encodeAssetPath(item.path)}`;
        await cacheStore.put(cacheName, pinnedUrl, item.bytes, mime, etag);
        await cacheStore.put(cacheName, encodeAssetPath(item.path), item.bytes, mime, etag);
        if (item.path === '/index.html') {
          await cacheStore.put(cacheName, '/', item.bytes, mime, etag);
        }
      }

      // 6. Promote staged files into committed OPFS store (`/os-releases/blobs/*` and `/os-releases/releases/<id>/*`).
      for (const [sha, bytes] of stagedBlobs.entries()) {
        if (!(await opfs.exists(`os-releases/blobs/${sha}`))) {
          await opfs.writeFile(`os-releases/blobs/${sha}`, bytes);
        }
      }
      const committedDir = `os-releases/releases/${releaseId}`;
      await opfs.writeFile(`${committedDir}/manifest.json`, manifestBytes);
      await opfs.writeFile(`${committedDir}/signature.json`, sigBytes);
      await opfs.writeFile(`${committedDir}/trust.json`, trustBytes);
      for (const rec of imageRecords) {
        await opfs.writeFile(`${committedDir}/images/${rec.hash}.json`, rec.bytes);
        await opfs.writeFile(`${committedDir}/images/${rec.hash}.sig`, rec.sigBytes);
      }
      await opfs.removeDir(stagingDir);

      // 7. Atomically swap IndexedDB `{ durability: "strict" }` generation pointer.
      // Preserves `previous` generation intact until `markBootHealthy(releaseId)` is called!
      const activate = installOpts.activate !== false;
      const nextState = await stateStore.updateStrict(state => {
        state.generations[releaseId] = {
          id: releaseId,
          name: release.name,
          installedAt: Date.now(),
          healthy: false,
          trust,
          loader: release.loader,
          images: {
            boot: release.boot,
            initramfs: release.initramfs,
            root_template: release.root_template,
            base: release.base,
            sysext: release.sysext,
            confext: release.confext,
          },
          blobs: [...stagedBlobs.keys()],
        };
        if (activate) {
          if (state.active && state.active !== releaseId) {
            state.previous = state.active;
          }
          state.active = releaseId;
          state.activeBootVerified = false;
          state.bootAttempts = 0;
        }
        return state;
      });

      return {
        releaseId,
        release,
        state: nextState,
        pinnedBlobs: stagedBlobs.size,
        pinnedBootAssets: stagedBootAssets.length,
      };
    } catch (error) {
      await opfs.removeDir(stagingDir).catch(() => {});
      if (!keepCacheOnFailure) {
        await cacheStore.deleteCache(cacheName).catch(() => {});
      }
      throw error;
    }
  }

  /**
   * Verifies a locally pinned Release v2 completely offline (0 network requests):
   * Ed25519 signatures, Trust revocations, manifest structure, and full + chunk SHA-256 of every pinned blob.
   */
  async function verifyInstalledOffline(releaseId, { verifyAllBlobs = true } = {}) {
    const dir = `os-releases/releases/${releaseId}`;
    const manifestBytes = await opfs.readFile(`${dir}/manifest.json`);
    const sigBytes = await opfs.readFile(`${dir}/signature.json`);
    const trustBytes = await opfs.readFile(`${dir}/trust.json`);
    if (!manifestBytes || !sigBytes || !trustBytes) {
      throw new Error(`Release ${releaseId} is not fully pinned in OPFS.`);
    }
    if (await sha256Hex(manifestBytes, cryptoApi) !== releaseId) {
      throw new Error('Pinned release manifest digest mismatch.');
    }
    const trust = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(trustBytes));
    const sigObj = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(sigBytes));
    await verifyEd25519Detached(SIGNING_DOMAIN_RELEASE_V2, manifestBytes, sigObj, trust, cryptoApi);
    const release = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(manifestBytes));
    const imageHashes = validateReleaseV2Manifest(release);

    const expectedKinds = [
      'boot',
      'initramfs',
      'roottemplate',
      'base',
      ...release.sysext.map(() => 'sysext'),
      ...release.confext.map(() => 'confext'),
    ];
    const imagesRaw = [];
    const sigsRaw = [];
    const parsedImages = [];
    const checkedBlobs = new Set();

    for (let i = 0; i < imageHashes.length; i++) {
      const hash = imageHashes[i];
      const imgBytes = await opfs.readFile(`${dir}/images/${hash}.json`);
      const imgSigBytes = await opfs.readFile(`${dir}/images/${hash}.sig`);
      if (!imgBytes || !imgSigBytes) throw new Error(`Pinned image ${hash} missing in OPFS.`);
      if (await sha256Hex(imgBytes, cryptoApi) !== hash) throw new Error(`Pinned image ${hash} digest mismatch.`);
      const imgSigObj = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(imgSigBytes));
      await verifyEd25519Detached(SIGNING_DOMAIN_IMAGE_V2, imgBytes, imgSigObj, trust, cryptoApi);
      const parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(imgBytes));
      validateImageV2Manifest(parsed, expectedKinds[i]);
      imagesRaw.push(new TextDecoder('utf-8', { fatal: true }).decode(imgBytes));
      sigsRaw.push(new TextDecoder('utf-8', { fatal: true }).decode(imgSigBytes));
      parsedImages.push(parsed);

      if (verifyAllBlobs) {
        for (const entry of parsed.entries) {
          if (entry.node.type !== 'file') continue;
          if (checkedBlobs.has(entry.node.sha256)) continue;
          const blobBytes = await opfs.readFile(`os-releases/blobs/${entry.node.sha256}`);
          if (!blobBytes) throw new Error(`Pinned blob missing in OPFS: ${entry.node.sha256}`);
          await verifyBytesAgainstFileNode(blobBytes, entry.node, cryptoApi);
          checkedBlobs.add(entry.node.sha256);
        }
      }
    }

    return {
      releaseId,
      release,
      trust,
      manifestText: new TextDecoder('utf-8', { fatal: true }).decode(manifestBytes),
      signatureText: new TextDecoder('utf-8', { fatal: true }).decode(sigBytes),
      trustText: new TextDecoder('utf-8', { fatal: true }).decode(trustBytes),
      imagesRaw,
      sigsRaw,
      images: {
        boot: parsedImages[0],
        initramfs: parsedImages[1],
        root_template: parsedImages[2],
        base: parsedImages[3],
        sysext: parsedImages.slice(4, 4 + release.sysext.length),
        confext: parsedImages.slice(4 + release.sysext.length),
      },
    };
  }

  /**
   * Begins an offline boot of the active generation.
   * - If the previous boot attempt crashed BEFORE calling `markBootHealthy(active)`,
   *   automatically rolls back to `previous` in a strict IDB transaction.
   * - If verifying `active` fails and `previous` is intact, rolls back to `previous`.
   */
  async function beginOfflineBoot({ verifyAllBlobs = true } = {}) {
    let rolledBack = false;
    let rolledBackFrom = null;
    const state = await stateStore.updateStrict(cur => {
      if (!cur.active) return cur;
      if (!cur.activeBootVerified && cur.bootAttempts >= 1 && cur.previous && cur.generations[cur.previous]) {
        rolledBack = true;
        rolledBackFrom = cur.active;
        cur.active = cur.previous;
        cur.previous = null;
        cur.activeBootVerified = true;
        cur.bootAttempts = 0;
        return cur;
      }
      if (!cur.activeBootVerified) {
        cur.bootAttempts = (cur.bootAttempts || 0) + 1;
      }
      return cur;
    });

    if (!state.active) {
      throw new Error('No offline Release v2 generation is installed.');
    }

    try {
      const verified = await verifyInstalledOffline(state.active, { verifyAllBlobs });
      return { ...verified, rolledBack, rolledBackFrom, state };
    } catch (primaryError) {
      if (state.previous && state.generations[state.previous]) {
        const prevId = state.previous;
        const failedId = state.active;
        const fallbackVerified = await verifyInstalledOffline(prevId, { verifyAllBlobs });
        const rolledState = await stateStore.updateStrict(cur => {
          cur.active = prevId;
          cur.previous = null;
          cur.activeBootVerified = true;
          cur.bootAttempts = 0;
          return cur;
        });
        return {
          ...fallbackVerified,
          rolledBack: true,
          rolledBackFrom: failedId,
          rollbackReason: primaryError.message,
          state: rolledState,
        };
      }
      throw primaryError;
    }
  }

  async function markBootHealthy(releaseId) {
    return stateStore.updateStrict(cur => {
      if (cur.active !== releaseId) {
        throw new Error(`Cannot mark ${releaseId} healthy: active generation is ${cur.active}.`);
      }
      cur.activeBootVerified = true;
      cur.bootAttempts = 0;
      if (cur.generations[releaseId]) {
        cur.generations[releaseId].healthy = true;
      }
      return cur;
    });
  }

  async function rollback() {
    return stateStore.updateStrict(cur => {
      if (!cur.previous || !cur.generations[cur.previous]) {
        throw new Error('No previous healthy generation available for rollback.');
      }
      cur.active = cur.previous;
      cur.previous = null;
      cur.activeBootVerified = true;
      cur.bootAttempts = 0;
      return cur;
    });
  }

  async function getState() {
    return stateStore.read();
  }

  return {
    install,
    verifyInstalledOffline,
    beginOfflineBoot,
    markBootHealthy,
    rollback,
    getState,
  };
}

export async function registerOfflineServiceWorker(swUrl = '/offline-sw.js') {
  if (!globalThis.navigator?.serviceWorker) {
    throw new Error('Service Worker API is unavailable.');
  }
  const reg = await globalThis.navigator.serviceWorker.register(swUrl, { scope: '/' });
  await globalThis.navigator.serviceWorker.ready;
  if (!globalThis.navigator.serviceWorker.controller) {
    await new Promise(resolve => {
      const done = () => {
        globalThis.navigator.serviceWorker.removeEventListener('controllerchange', done);
        resolve();
      };
      globalThis.navigator.serviceWorker.addEventListener('controllerchange', done);
      setTimeout(done, 3000);
    });
  }
  return reg;
}

// --- Service Worker runtime (when bundled as `/offline-sw.js`) ---

if (typeof ServiceWorkerGlobalScope !== 'undefined' && self instanceof ServiceWorkerGlobalScope) {
  const swStateStore = createBrowserStateStore(self.indexedDB);
  const swOpfs = createBrowserOpfsStore();

  self.addEventListener('install', event => {
    event.waitUntil(self.skipWaiting());
  });

  self.addEventListener('activate', event => {
    event.waitUntil(self.clients.claim());
  });

  async function serveOpfsBlob(request, sha) {
    const bytes = await swOpfs.readFile(`os-releases/blobs/${sha}`);
    if (!bytes) return null;
    if (await sha256Hex(bytes, self.crypto) !== sha) {
      return new Response('corrupted local blob', { status: 409 });
    }
    const etag = `"${sha}"`;
    const headers = isolatedHeaders('application/octet-stream', etag);
    headers.set('Accept-Ranges', 'bytes');
    if (request.headers.get('If-None-Match') === etag) {
      return new Response(null, { status: 304, headers });
    }
    const range = request.headers.get('Range');
    const ifRange = request.headers.get('If-Range');
    const useRange = range && (!ifRange || ifRange === etag);
    if (useRange) {
      const match = /^bytes=(\d+)-(\d*)$/.exec(range.trim());
      if (!match) return new Response(null, { status: 416 });
      const start = Number(match[1]);
      const end = match[2] === '' ? bytes.byteLength - 1 : Math.min(Number(match[2]), bytes.byteLength - 1);
      if (start > end || start >= bytes.byteLength) return new Response(null, { status: 416 });
      const slice = bytes.subarray(start, end + 1);
      headers.set('Content-Range', `bytes ${start}-${end}/${bytes.byteLength}`);
      headers.set('Content-Length', String(slice.byteLength));
      return new Response(request.method === 'HEAD' ? null : slice, { status: 206, headers });
    }
    headers.set('Content-Length', String(bytes.byteLength));
    return new Response(request.method === 'HEAD' ? null : bytes, { status: 200, headers });
  }

  self.addEventListener('fetch', event => {
    const { request } = event;
    if (request.method !== 'GET' && request.method !== 'HEAD') return;
    const url = new URL(request.url);
    if (url.origin !== self.location.origin) return;
    if (url.pathname.startsWith('/api/')) return;

    event.respondWith((async () => {
      let state;
      try {
        state = await swStateStore.read();
      } catch {
        return fetch(request);
      }
      if (!state?.active) {
        return fetch(request);
      }

      // Auto-rollback on navigation if the prior attempt crashed before `markBootHealthy`.
      if (
        request.mode === 'navigate'
        && !state.activeBootVerified
        && state.bootAttempts >= 1
        && state.previous
        && state.generations?.[state.previous]
      ) {
        state = await swStateStore.updateStrict(cur => {
          if (!cur.activeBootVerified && cur.bootAttempts >= 1 && cur.previous && cur.generations?.[cur.previous]) {
            cur.rolledBackFrom = cur.active;
            cur.active = cur.previous;
            cur.previous = null;
            cur.activeBootVerified = true;
            cur.bootAttempts = 0;
          }
          return cur;
        });
      }

      // Direct content-addressed blob lookup from OPFS.
      if (url.pathname.startsWith('/boot/blobs/')) {
        const sha = url.pathname.slice('/boot/blobs/'.length);
        if (HEX64.test(sha)) {
          const local = await serveOpfsBlob(request, sha);
          if (local) return local;
        }
        return fetch(request);
      }

      // Check explicitly pinned release cache first if URL addresses a release.
      const releaseMatch = /^\/boot\/releases\/([a-f0-9]{64})(?:\/|$)/.exec(url.pathname);
      if (releaseMatch) {
        const targetId = releaseMatch[1];
        if (state.generations?.[targetId]) {
          const cache = await caches.open(`${CACHE_PREFIX}${targetId}`);
          const hit = await cache.match(url.pathname, { ignoreSearch: true });
          if (hit) return hit;
        }
        return fetch(request);
      }

      // Serve active offline generation from Cache Storage with ZERO network calls.
      const activeCache = await caches.open(`${CACHE_PREFIX}${state.active}`);
      const hit = await activeCache.match(url.pathname, { ignoreSearch: true });
      if (hit) return hit;
      if (request.mode === 'navigate' && url.pathname === '/') {
        const indexHit = await activeCache.match('/index.html', { ignoreSearch: true });
        if (indexHit) return indexHit;
      }

      return fetch(request);
    })());
  });
}

// Atomic Offline Release v2 Installer & Offline Service Worker (#78 L2.5b, Blueprint §2.4 & §3.3).
//
// - Persists a profile-wide anchored monotonic trust root in IndexedDB `{ durability: "strict" }`:
//   revocations ratchet monotonically across all generations and rollback targets; new publisher
//   keys are accepted only via a cryptographically signed rotation statement (or pinned root);
//   downgrades below `minReleaseSeq` / previously superseded generations are refused.
// - Streams & verifies every blob (full SHA-256 + every chunk SHA-256) in bounded `<= 1 MiB`
//   buffers straight into OPFS staging using atomic temp-file + checked write + rename.
// - Enforces full symlink-confinement and `Base + Sysext + Confext` composition rules plus
//   Cache Storage loader asset integrity checks on both install and offline boot.
// - Holds a shared Web Lock (`os-boot-attempt:<releaseId>`) during Stage 1 boot so concurrent
//   tab/iframe navigations never prematurely auto-roll back a healthy upgrade.
// - When evaluated in a ServiceWorkerGlobalScope (`/offline-sw.js`), routes `/boot/entries`
//   network-first (ratcheting revocations into IDB on every online visit) and serves OPFS
//   `/boot/blobs/*` Range requests via bounded `file.slice(...)` + covering-chunk verification.

export const OFFLINE_DB_NAME = 'os-offline-releases-v2';
export const OFFLINE_DB_VERSION = 1;
export const OFFLINE_STORE = 'state';
export const OFFLINE_STATE_KEY = 'generations';
export const CACHE_PREFIX = 'os-release-v2:';
export const BOOT_LOCK_PREFIX = 'os-boot-attempt:';

export const RELEASE_VERSION = 2;
export const IMAGE_VERSION = 2;
export const IMAGE_ABI = 1;
export const IMAGE_LEVEL = 1;
export const PROTOCOL_VERSION = 2;
export const SCHEMA_VERSION = 10;
export const HOST_ADAPTER_VERSION = 2;
export const MANIFEST_MAX = 4 * 1024 * 1024;
export const CHUNK_SIZE_MIN = 64 * 1024;
export const CHUNK_SIZE_MAX = 1024 * 1024;
export const SIGNING_DOMAIN_RELEASE_V2 = 'os.release.v2';
export const SIGNING_DOMAIN_IMAGE_V2 = 'os.image.v2';
export const SIGNING_DOMAIN_TRUST_V2 = 'os.trust.v2';
export const EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

const ALLOWED_IMAGE_FEATURES = new Set(['wasi-preview1', 'os-abi-1', 'wasix-fork-v4']);
const INITRAMFS_DIRS = new Set(['/dev', '/proc', '/run', '/sysroot', '/tmp']);
const ROOT_TEMPLATE_DIRS = new Set([
  '/boot', '/dev', '/dev/pts', '/mnt', '/mnt/local', '/mnt/shared',
  '/opt', '/opt/private', '/proc', '/run', '/srv', '/sys', '/tmp', '/usr',
]);
const BASE_TOP_LINKS = new Set(['/bin', '/sbin', '/lib', '/lib64']);
const BASE_MERGE_DIRS = new Set(['/opt', '/etc']);

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
const DIGITS_RE = /^\d+$/;

// Incremental FIPS 180-4 SHA-256 for bounded streaming verification (O(1) memory).
const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

class IncrementalSha256 {
  constructor() {
    this.h = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]);
    this.w = new Uint32Array(64);
    this.buf = new Uint8Array(64);
    this.bufLen = 0;
    this.totalBytes = 0;
  }

  _compress(block, offset) {
    const w = this.w;
    for (let i = 0; i < 16; i++) {
      const j = offset + i * 4;
      w[i] = ((block[j] << 24) | (block[j + 1] << 16) | (block[j + 2] << 8) | block[j + 3]) >>> 0;
    }
    for (let i = 16; i < 64; i++) {
      const x = w[i - 15];
      const s0 = (((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3)) >>> 0;
      const y = w[i - 2];
      const s1 = (((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10)) >>> 0;
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    const h = this.h;
    let a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (let i = 0; i < 64; i++) {
      const s1 = (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) >>> 0;
      const ch = ((e & f) ^ ((~e) & g)) >>> 0;
      const temp1 = (hh + s1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const s0 = (((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const temp2 = (s0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + temp1) >>> 0;
      d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0;
    h[1] = (h[1] + b) >>> 0;
    h[2] = (h[2] + c) >>> 0;
    h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0;
    h[5] = (h[5] + f) >>> 0;
    h[6] = (h[6] + g) >>> 0;
    h[7] = (h[7] + hh) >>> 0;
  }

  update(data) {
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    this.totalBytes += bytes.byteLength;
    let pos = 0;
    if (this.bufLen > 0) {
      const take = Math.min(64 - this.bufLen, bytes.byteLength);
      this.buf.set(bytes.subarray(0, take), this.bufLen);
      this.bufLen += take;
      pos += take;
      if (this.bufLen === 64) {
        this._compress(this.buf, 0);
        this.bufLen = 0;
      }
    }
    while (pos + 64 <= bytes.byteLength) {
      this._compress(bytes, pos);
      pos += 64;
    }
    if (pos < bytes.byteLength) {
      const rem = bytes.byteLength - pos;
      this.buf.set(bytes.subarray(pos), 0);
      this.bufLen = rem;
    }
  }

  hex() {
    const padLen = this.bufLen < 56 ? 64 : 128;
    const pad = new Uint8Array(padLen);
    pad.set(this.buf.subarray(0, this.bufLen), 0);
    pad[this.bufLen] = 0x80;
    const totalBitsHi = Math.floor(this.totalBytes / 0x20000000);
    const totalBitsLo = (this.totalBytes * 8) >>> 0;
    const dv = new DataView(pad.buffer);
    dv.setUint32(padLen - 8, totalBitsHi >>> 0, false);
    dv.setUint32(padLen - 4, totalBitsLo, false);
    this._compress(pad, 0);
    if (padLen === 128) this._compress(pad, 64);
    let out = '';
    for (let i = 0; i < 8; i++) out += this.h[i].toString(16).padStart(8, '0');
    return out;
  }
}

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

function randomHex(bytes = 12) {
  const buf = new Uint8Array(bytes);
  if (globalThis.crypto?.getRandomValues) {
    globalThis.crypto.getRandomValues(buf);
  } else {
    for (let i = 0; i < bytes; i++) buf[i] = Math.floor(Math.random() * 256);
  }
  return toHex(buf);
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

function bytesEqual(a, b) {
  if (!a || !b || a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
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
  if (
    domain !== SIGNING_DOMAIN_RELEASE_V2
    && domain !== SIGNING_DOMAIN_IMAGE_V2
    && domain !== SIGNING_DOMAIN_TRUST_V2
  ) {
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

// --- Anchored monotonic trust store helpers ---

async function normalizeTrustObject(trust, cryptoApi) {
  if (!trust || typeof trust !== 'object' || !trust.keys || typeof trust.keys !== 'object' || Array.isArray(trust.keys)) {
    throw new Error('Invalid publisher trust configuration.');
  }
  const keys = {};
  for (const [k, v] of Object.entries(trust.keys)) {
    if (!HEX64.test(k) || typeof v !== 'string' || !HEX64.test(v)) {
      throw new Error('Invalid publisher key entry in trust policy.');
    }
    if (await sha256Hex(unhex(v), cryptoApi) !== k) {
      throw new Error('Publisher key identifier mismatch in trust policy.');
    }
    keys[k] = v;
  }
  const revokedSet = new Set();
  const revokedRaw = trust.revoked ?? [];
  if (!Array.isArray(revokedRaw)) throw new Error('Invalid revoked key list in trust policy.');
  for (const r of revokedRaw) {
    if (typeof r !== 'string' || !HEX64.test(r)) {
      throw new Error('Invalid revoked key identifier in trust policy.');
    }
    revokedSet.add(r);
  }
  return { keys, revoked: [...revokedSet].sort() };
}

function cloneTrustRoot(root) {
  return {
    keys: { ...(root.keys ?? {}) },
    revoked: [...new Set(Array.isArray(root.revoked) ? root.revoked : [])].sort(),
    minReleaseSeq: Number.isSafeInteger(root.minReleaseSeq) ? root.minReleaseSeq : 0,
    requireExplicitSeq: Boolean(root.requireExplicitSeq),
    maxInstalledSeq: Number.isSafeInteger(root.maxInstalledSeq) ? root.maxInstalledSeq : 0,
    releaseSeqs: { ...(root.releaseSeqs ?? {}) },
  };
}

function publicTrustOf(root) {
  return {
    keys: { ...(root.keys ?? {}) },
    revoked: [...new Set(Array.isArray(root.revoked) ? root.revoked : [])].sort(),
  };
}

async function applySignedTrustRotation(rotation, root, cryptoApi) {
  if (!rotation || typeof rotation !== 'object') throw new Error('Invalid trust rotation statement.');
  if (rotation.format !== 'os.trust.rotation' || rotation.version !== 1 || typeof rotation.payload !== 'string') {
    throw new Error('Unsupported trust rotation format.');
  }
  const payloadBytes = new TextEncoder().encode(rotation.payload);
  await verifyEd25519Detached(SIGNING_DOMAIN_TRUST_V2, payloadBytes, rotation.signature, publicTrustOf(root), cryptoApi);
  const parsed = JSON.parse(rotation.payload);
  if (!parsed || typeof parsed !== 'object') throw new Error('Invalid trust rotation payload.');

  const revoked = new Set(root.revoked);
  if (Array.isArray(parsed.revoke_keys)) {
    for (const keyId of parsed.revoke_keys) {
      if (typeof keyId !== 'string' || !HEX64.test(keyId)) {
        throw new Error('Invalid revoked key identifier in trust rotation.');
      }
      revoked.add(keyId);
    }
  }
  if (parsed.add_keys && typeof parsed.add_keys === 'object' && !Array.isArray(parsed.add_keys)) {
    for (const [k, v] of Object.entries(parsed.add_keys)) {
      if (!HEX64.test(k) || typeof v !== 'string' || !HEX64.test(v)) {
        throw new Error('Invalid added key in trust rotation.');
      }
      if (await sha256Hex(unhex(v), cryptoApi) !== k) {
        throw new Error('Added publisher key identifier mismatch in trust rotation.');
      }
      if (k in root.keys && root.keys[k] !== v) {
        throw new Error('Conflicting publisher public key in trust rotation.');
      }
      if (!revoked.has(k)) {
        root.keys[k] = v;
      }
    }
  }
  if (parsed.min_release_seq !== undefined) {
    if (!Number.isSafeInteger(parsed.min_release_seq) || parsed.min_release_seq < 0) {
      throw new Error('Invalid min_release_seq in trust rotation.');
    }
    root.minReleaseSeq = Math.max(root.minReleaseSeq, parsed.min_release_seq);
    if (parsed.min_release_seq > 0) root.requireExplicitSeq = true;
  }
  root.revoked = [...revoked].sort();
}

async function reconcileTrustRoot(existingRoot, incomingTrust, {
  pinnedTrust = null,
  rotation = null,
  incomingMinReleaseSeq = undefined,
  allowBootstrap = true,
  cryptoApi = globalThis.crypto,
} = {}) {
  let root;
  if (existingRoot) {
    root = cloneTrustRoot(existingRoot);
    if (pinnedTrust) {
      const normPinned = await normalizeTrustObject(pinnedTrust, cryptoApi);
      const rev = new Set(root.revoked);
      for (const r of normPinned.revoked) rev.add(r);
      for (const [k, v] of Object.entries(normPinned.keys)) {
        if (k in root.keys && root.keys[k] !== v) {
          throw new Error('Conflicting publisher public key against pinned trust root.');
        }
        root.keys[k] = v;
      }
      root.revoked = [...rev].sort();
    }
  } else if (pinnedTrust) {
    const normPinned = await normalizeTrustObject(pinnedTrust, cryptoApi);
    root = cloneTrustRoot({ ...normPinned, minReleaseSeq: 0, requireExplicitSeq: false, maxInstalledSeq: 0, releaseSeqs: {} });
  } else if (allowBootstrap && incomingTrust) {
    const normIncoming = await normalizeTrustObject(incomingTrust, cryptoApi);
    root = cloneTrustRoot({ ...normIncoming, minReleaseSeq: 0, requireExplicitSeq: false, maxInstalledSeq: 0, releaseSeqs: {} });
  } else {
    throw new Error('No anchored profile trust root available.');
  }

  if (rotation) {
    await applySignedTrustRotation(rotation, root, cryptoApi);
  }

  if (incomingTrust) {
    // When anchored, monotonically merge revocations and verify key consistency,
    // but NEVER adopt unauthenticated new keys from an unverified /boot/entries response.
    const normIncoming = await normalizeTrustObject(incomingTrust, cryptoApi);
    const rev = new Set(root.revoked);
    for (const r of normIncoming.revoked) rev.add(r);
    for (const [k, v] of Object.entries(normIncoming.keys)) {
      if (k in root.keys && root.keys[k] !== v) {
        throw new Error('Conflicting publisher public key for existing key identifier.');
      }
    }
    root.revoked = [...rev].sort();
  }

  if (incomingMinReleaseSeq !== undefined) {
    if (!Number.isSafeInteger(incomingMinReleaseSeq) || incomingMinReleaseSeq < 0) {
      throw new Error('Invalid min_release_seq in boot entries.');
    }
    root.minReleaseSeq = Math.max(root.minReleaseSeq, incomingMinReleaseSeq);
    if (incomingMinReleaseSeq > 0) root.requireExplicitSeq = true;
  }

  return { trustRoot: root, trust: publicTrustOf(root) };
}

function trustRootChanged(before, after) {
  if (!before) return false;
  if ((before.minReleaseSeq || 0) !== (after.minReleaseSeq || 0)) return true;
  if (Boolean(before.requireExplicitSeq) !== Boolean(after.requireExplicitSeq)) return true;
  const bRev = [...new Set(before.revoked ?? [])].sort();
  const aRev = [...new Set(after.revoked ?? [])].sort();
  if (bRev.length !== aRev.length || bRev.some((v, i) => v !== aRev[i])) return true;
  const bKeys = Object.keys(before.keys ?? {}).sort();
  const aKeys = Object.keys(after.keys ?? {}).sort();
  if (bKeys.length !== aKeys.length || bKeys.some((k, i) => k !== aKeys[i] || before.keys[k] !== after.keys[k])) return true;
  return false;
}

function isGenerationRevoked(gen, trustRoot) {
  if (!gen || !trustRoot) return true;
  const revoked = new Set(Array.isArray(trustRoot.revoked) ? trustRoot.revoked : []);
  const keys = trustRoot.keys ?? {};
  const signers = [];
  if (typeof gen.signer === 'string') signers.push(gen.signer);
  if (Array.isArray(gen.imageSigners)) signers.push(...gen.imageSigners);
  if (signers.length === 0) return false;
  return signers.some(k => revoked.has(k) || !keys[k]);
}

function extractReleaseSeq(release) {
  let explicit = null;
  if (release.release_seq !== undefined) {
    if (!Number.isSafeInteger(release.release_seq) || release.release_seq < 0) {
      throw new Error('Invalid release_seq in release manifest.');
    }
    explicit = release.release_seq;
  }
  const provSeq = release.provenance?.release_seq;
  if (provSeq !== undefined) {
    if (typeof provSeq !== 'string' || !DIGITS_RE.test(provSeq)) {
      throw new Error('Invalid provenance.release_seq in release manifest.');
    }
    const parsed = Number(provSeq);
    if (!Number.isSafeInteger(parsed) || parsed < 0) {
      throw new Error('Out-of-range provenance.release_seq in release manifest.');
    }
    if (explicit !== null && explicit !== parsed) {
      throw new Error('Conflicting release_seq and provenance.release_seq.');
    }
    explicit = parsed;
  }
  return explicit;
}

function checkAndAdvanceAntiDowngrade(root, releaseId, explicitSeq, { allowDowngrade = false } = {}) {
  const next = cloneTrustRoot(root);
  if (explicitSeq !== null) {
    if (!allowDowngrade && explicitSeq < next.minReleaseSeq) {
      throw new Error(`Release downgrade refused (seq ${explicitSeq} < minReleaseSeq ${next.minReleaseSeq}).`);
    }
    next.minReleaseSeq = Math.max(next.minReleaseSeq, explicitSeq);
    next.requireExplicitSeq = true;
    next.releaseSeqs[releaseId] = explicitSeq;
  } else {
    if (!allowDowngrade && next.requireExplicitSeq) {
      throw new Error('Release downgrade refused: missing release_seq after sequenced release.');
    }
    const recorded = next.releaseSeqs[releaseId];
    if (!allowDowngrade && recorded !== undefined && recorded < next.maxInstalledSeq) {
      throw new Error(`Release downgrade refused (release ${releaseId} seq ${recorded} < ${next.maxInstalledSeq}).`);
    }
    if (recorded === undefined) {
      const assigned = next.maxInstalledSeq + 1;
      next.maxInstalledSeq = assigned;
      next.releaseSeqs[releaseId] = assigned;
    }
  }
  return next;
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
  extractReleaseSeq(release);
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

function allowsImagePath(kind, path, isDir) {
  if (path === '/') return isDir;
  switch (kind) {
    case 'boot':
      return !below(path, '/boot') && !below(path, '/api');
    case 'initramfs':
      return (
        path === '/init'
        || below(path, '/bin')
        || below(path, '/sbin')
        || below(path, '/lib')
        || below(path, '/lib64')
        || below(path, '/usr')
        || (below(path, '/etc') && !isProtected(path))
        || (isDir && INITRAMFS_DIRS.has(path))
      );
    case 'roottemplate':
      return (
        !below(path, '/etc/os-trust')
        && (
          below(path, '/etc')
          || below(path, '/var')
          || below(path, '/root')
          || below(path, '/home')
          || (isDir && ROOT_TEMPLATE_DIRS.has(path))
        )
      );
    case 'base':
      return (
        below(path, '/usr')
        || below(path, '/sys')
        || BASE_TOP_LINKS.has(path)
        || (isDir && BASE_MERGE_DIRS.has(path))
      );
    case 'sysext':
      return below(path, '/usr') || below(path, '/opt');
    case 'confext':
      return below(path, '/etc') && !isProtected(path);
    case 'workload':
      return below(path, '/workload');
    default:
      return false;
  }
}

export function validateImageV2Manifest(image, expectedKind) {
  if (!image || typeof image !== 'object') throw new Error('Invalid image manifest.');
  if (image.format !== 'os.image' || image.version !== IMAGE_VERSION) {
    throw new Error(`Unsupported image format/version (${image.format} v${image.version}).`);
  }
  if (image.abi !== IMAGE_ABI || image.level !== IMAGE_LEVEL) {
    throw new Error(`Incompatible image ABI/level (abi=${image.abi}, level=${image.level}).`);
  }
  if (typeof image.name !== 'string' || !image.name || image.name.length > 128) {
    throw new Error('Invalid image name.');
  }
  if (typeof image.revision !== 'string' || !image.revision || image.revision.length > 128) {
    throw new Error('Invalid image revision.');
  }
  if (!Array.isArray(image.features)) {
    throw new Error('Invalid image features.');
  }
  const seenFeatures = new Set();
  for (const feat of image.features) {
    if (typeof feat !== 'string' || !ALLOWED_IMAGE_FEATURES.has(feat) || seenFeatures.has(feat)) {
      throw new Error(`Unknown or duplicate image feature: ${feat}`);
    }
    seenFeatures.add(feat);
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
    const isDir = entry.node?.type === 'directory';
    if (!allowsImagePath(image.kind, entry.path, isDir)) {
      throw new Error(`Image ${image.kind} entry disallowed: ${entry.path}`);
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
    } else if (entry.node?.type === 'symlink') {
      const target = entry.node.target;
      if (typeof target !== 'string' || !target || target.length > 4096 || target.includes('\0')) {
        throw new Error(`Invalid symlink target on ${entry.path}.`);
      }
    } else if (!isDir) {
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
    // Validate ALL symlinks in standalone Initramfs and RootTemplate images against
    // root escape (`..`), dangling/looping targets, allowed roots, and protected paths.
    for (const entry of image.entries) {
      if (entry.node.type === 'symlink') {
        const physical = resolveInMap(byPath, entry.path);
        const targetIsDir = byPath.get(physical)?.node?.type === 'directory';
        if (!allowsImagePath(image.kind, physical, targetIsDir)) {
          throw new Error(`Image symlink escapes its roots: ${entry.path} -> ${physical}`);
        }
        if (image.kind === 'initramfs' && isProtected(physical)) {
          throw new Error(`Initramfs symlink targets protected path: ${entry.path} -> ${physical}`);
        }
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
      if (image.entries.some(e => below(e.path, '/etc/os-trust'))) {
        throw new Error('RootTemplate cannot include /etc/os-trust.');
      }
    }
  }
  return byPath;
}

function validateBootLoaderBinding(release, bootByPath) {
  for (const field of ['entry', 'client_kernel_js', 'client_kernel_wasm']) {
    const found = bootByPath.get(release.loader[field]);
    if (!found || found.node.type !== 'file') {
      throw new Error(`Boot image missing loader asset ${release.loader[field]}.`);
    }
  }
  if (bootByPath.get(release.loader.client_kernel_wasm).node.sha256 !== release.loader.client_kernel_sha256) {
    throw new Error('Loader client_kernel_sha256 does not match boot image.');
  }
}

/**
 * Enforces `Base + Sysext + Confext` composition rules matching `crates/image/src/composition.rs`:
 * - Only identical shared directories may collide across layers (closes file/symlink shadowing).
 * - Every non-root entry must have an explicit directory ancestor (closes `/usr/link/file`).
 * - Every symlink across all layers must resolve inside the composed tree without escaping its
 *   layer's allowed roots or targeting protected identity/trust paths.
 */
export function validateSystemComposition(baseImage, extensionImages = []) {
  if (!baseImage || baseImage.kind !== 'base') {
    throw new Error('Composition requires a base image.');
  }
  const layers = [baseImage, ...extensionImages];
  const composed = new Map();
  for (let i = 0; i < layers.length; i++) {
    const img = layers[i];
    if (i > 0 && img.kind !== 'sysext' && img.kind !== 'confext') {
      throw new Error(`Unsupported composition extension kind: ${img.kind}`);
    }
    for (const entry of img.entries) {
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
  if (composed.get('/')?.node?.type !== 'directory') {
    throw new Error('Composed tree missing root directory.');
  }
  for (const entry of composed.values()) {
    if (entry.path !== '/' && composed.get(parentPath(entry.path))?.node?.type !== 'directory') {
      throw new Error(`Missing/non-directory image parent for ${entry.path}`);
    }
  }
  for (const img of layers) {
    for (const entry of img.entries) {
      if (entry.node.type === 'symlink') {
        const physical = resolveInMap(composed, entry.path);
        if (isProtected(physical) || !allowsImagePath(img.kind, physical, false)) {
          throw new Error(`Image symlink escapes its roots: ${entry.path} -> ${physical}`);
        }
      }
    }
  }
  return composed;
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

function emptyOfflineState() {
  return {
    format: 'os.offline.state',
    version: 2,
    active: null,
    previous: null,
    activeBootVerified: false,
    bootAttempts: 0,
    trustRoot: null,
    generations: {},
  };
}

function createBrowserStateStore(idbFactory = globalThis.indexedDB) {
  return {
    async read() {
      const db = await openBrowserDb(idbFactory);
      try {
        return await new Promise((resolve, reject) => {
          const tx = db.transaction(OFFLINE_STORE, 'readonly');
          const req = tx.objectStore(OFFLINE_STORE).get(OFFLINE_STATE_KEY);
          req.onsuccess = () => resolve(req.result ?? emptyOfflineState());
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
              const current = getReq.result ?? emptyOfflineState();
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

// --- Default browser OPFS hierarchical file adapter (atomic temp + checked write + rename) ---

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

function writeAllSync(sync, data, atOffset, label) {
  let written = 0;
  while (written < data.byteLength) {
    const n = sync.write(data.subarray(written), { at: atOffset + written });
    if (!Number.isFinite(n) || n <= 0) {
      throw new Error(`OPFS short write on ${label} (${written}/${data.byteLength}).`);
    }
    written += n;
  }
  return written;
}

export function createBrowserOpfsStore(rootProvider) {
  const getRoot = () => (rootProvider ? rootProvider() : globalThis.navigator.storage.getDirectory());

  async function atomicMoveOrFallback(dir, tmpName, tmpHandle, finalName, fallbackData) {
    if (typeof tmpHandle.move === 'function') {
      await tmpHandle.move(dir, finalName);
      return;
    }
    // Fallback for environments lacking FileSystemFileHandle.move: write via createWritable
    // (which uses an internal atomic swap file in browsers) then delete temp file.
    const finalHandle = await dir.getFileHandle(finalName, { create: true });
    const writable = await finalHandle.createWritable();
    try {
      if (fallbackData) {
        await writable.write(fallbackData);
      } else {
        const tmpFile = await tmpHandle.getFile();
        let off = 0;
        while (off < tmpFile.size) {
          const slice = new Uint8Array(await tmpFile.slice(off, Math.min(tmpFile.size, off + CHUNK_SIZE_MAX)).arrayBuffer());
          await writable.write(slice);
          off += slice.byteLength;
        }
      }
      await writable.close();
    } catch (err) {
      await writable.abort().catch(() => {});
      throw err;
    } finally {
      await dir.removeEntry(tmpName).catch(() => {});
    }
  }

  return {
    async writeFile(relPath, bytes) {
      const parts = relPath.split('/').filter(Boolean);
      const name = parts.pop();
      const dir = await ensureDir(await getRoot(), parts);
      const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
      const tmpName = `.${name}.tmp-${randomHex(8)}`;
      const tmpHandle = await dir.getFileHandle(tmpName, { create: true });
      try {
        if (typeof tmpHandle.createSyncAccessHandle === 'function') {
          const sync = await tmpHandle.createSyncAccessHandle();
          try {
            sync.truncate(0);
            writeAllSync(sync, data, 0, relPath);
            sync.flush();
          } finally {
            sync.close();
          }
        } else {
          const writable = await tmpHandle.createWritable();
          try {
            await writable.write(data);
            await writable.close();
          } catch (err) {
            await writable.abort().catch(() => {});
            throw err;
          }
        }
        await atomicMoveOrFallback(dir, tmpName, tmpHandle, name, data);
      } catch (err) {
        await dir.removeEntry(tmpName).catch(() => {});
        throw err;
      }
    },
    async openWriter(relPath) {
      const parts = relPath.split('/').filter(Boolean);
      const name = parts.pop();
      const dir = await ensureDir(await getRoot(), parts);
      const tmpName = `.${name}.tmp-${randomHex(8)}`;
      const tmpHandle = await dir.getFileHandle(tmpName, { create: true });
      let sync = null;
      let writable = null;
      let offset = 0;
      let closed = false;
      if (typeof tmpHandle.createSyncAccessHandle === 'function') {
        sync = await tmpHandle.createSyncAccessHandle();
        sync.truncate(0);
      } else {
        writable = await tmpHandle.createWritable();
      }
      return {
        async write(chunk) {
          const data = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
          if (data.byteLength === 0) return;
          if (sync) {
            offset += writeAllSync(sync, data, offset, relPath);
          } else {
            await writable.write(data);
            offset += data.byteLength;
          }
        },
        async commit() {
          if (closed) return;
          closed = true;
          try {
            if (sync) {
              sync.flush();
              sync.close();
              sync = null;
            } else if (writable) {
              await writable.close();
              writable = null;
            }
            await atomicMoveOrFallback(dir, tmpName, tmpHandle, name, null);
          } catch (err) {
            await dir.removeEntry(tmpName).catch(() => {});
            throw err;
          }
        },
        async abort() {
          if (closed) return;
          closed = true;
          try {
            if (sync) {
              sync.close();
              sync = null;
            } else if (writable) {
              await writable.abort().catch(() => {});
              writable = null;
            }
          } finally {
            await dir.removeEntry(tmpName).catch(() => {});
          }
        },
      };
    },
    async getFile(relPath) {
      const parts = relPath.split('/').filter(Boolean);
      const name = parts.pop();
      try {
        const dir = await getDir(await getRoot(), parts);
        const handle = await dir.getFileHandle(name);
        return await handle.getFile();
      } catch (err) {
        if (err?.name === 'NotFoundError') return null;
        throw err;
      }
    },
    async fileSize(relPath) {
      const file = await this.getFile(relPath);
      return file ? file.size : null;
    },
    async readRange(relPath, start, endExclusive) {
      const file = await this.getFile(relPath);
      if (!file) return null;
      const slice = file.slice(start, endExclusive);
      return new Uint8Array(await slice.arrayBuffer());
    },
    async readFile(relPath) {
      const file = await this.getFile(relPath);
      if (!file) return null;
      return new Uint8Array(await file.arrayBuffer());
    },
    async moveFile(fromPath, toPath) {
      const fromParts = fromPath.split('/').filter(Boolean);
      const fromName = fromParts.pop();
      const toParts = toPath.split('/').filter(Boolean);
      const toName = toParts.pop();
      const root = await getRoot();
      const fromDir = await getDir(root, fromParts);
      const fromHandle = await fromDir.getFileHandle(fromName);
      const toDir = await ensureDir(root, toParts);
      if (typeof fromHandle.move === 'function') {
        await fromHandle.move(toDir, toName);
        return;
      }
      const file = await fromHandle.getFile();
      const writer = await this.openWriter(toPath);
      try {
        let off = 0;
        while (off < file.size) {
          const piece = new Uint8Array(await file.slice(off, Math.min(file.size, off + CHUNK_SIZE_MAX)).arrayBuffer());
          await writer.write(piece);
          off += piece.byteLength;
        }
        await writer.commit();
      } catch (err) {
        await writer.abort().catch(() => {});
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

async function readCacheHitBytes(hit) {
  if (!hit) return null;
  if (hit instanceof Uint8Array) return hit;
  if (hit.bytes instanceof Uint8Array) return hit.bytes;
  if (typeof hit.arrayBuffer === 'function') {
    return new Uint8Array(await hit.arrayBuffer());
  }
  return null;
}

// --- Web Lock boot-attempt guard (prevents concurrent-tab premature auto-rollback) ---

async function isBootAttemptLocked(releaseId, locksApi = globalThis.navigator?.locks) {
  if (!releaseId || !locksApi || typeof locksApi.request !== 'function') return false;
  try {
    return await locksApi.request(
      `${BOOT_LOCK_PREFIX}${releaseId}`,
      { mode: 'exclusive', ifAvailable: true },
      lock => !lock,
    );
  } catch {
    return false;
  }
}

async function acquireBootAttemptLock(releaseId, locksApi = globalThis.navigator?.locks) {
  if (!releaseId || !locksApi || typeof locksApi.request !== 'function') {
    return async () => {};
  }
  let releaseLock;
  const held = new Promise(resolve => { releaseLock = resolve; });
  let acquiredResolve;
  const acquired = new Promise(resolve => { acquiredResolve = resolve; });
  const reqPromise = locksApi.request(
    `${BOOT_LOCK_PREFIX}${releaseId}`,
    { mode: 'shared' },
    () => {
      acquiredResolve();
      return held;
    },
  );
  reqPromise.catch(() => { acquiredResolve(); });
  await acquired;
  return async () => {
    if (!releaseLock) return;
    const done = releaseLock;
    releaseLock = null;
    done();
    await reqPromise.catch(() => {});
  };
}

// --- Bounded streaming helpers ---

async function cancelBody(res, reason) {
  try {
    await res?.body?.cancel?.(reason);
  } catch {
    /* ignore */
  }
}

async function readResponseBytesCapped(res, maxBytes, controller, label) {
  const cl = res.headers?.get?.('Content-Length');
  if (cl !== null && cl !== undefined && cl !== '') {
    if (!DIGITS_RE.test(cl.trim()) || Number(cl) > maxBytes) {
      await cancelBody(res, 'response exceeded maxBytes');
      controller?.abort?.();
      throw new Error(`Response for ${label} exceeded byte limit (${maxBytes}).`);
    }
  }
  if (!res.body || typeof res.body.getReader !== 'function') {
    const buf = new Uint8Array(await res.arrayBuffer());
    if (buf.byteLength > maxBytes) {
      throw new Error(`Response for ${label} exceeded byte limit (${maxBytes}).`);
    }
    return buf;
  }
  const reader = res.body.getReader();
  const pieces = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value || value.byteLength === 0) continue;
      const piece = value instanceof Uint8Array ? value : new Uint8Array(value);
      total += piece.byteLength;
      if (total > maxBytes) {
        await reader.cancel('response exceeded maxBytes').catch(() => {});
        controller?.abort?.();
        throw new Error(`Response for ${label} exceeded byte limit (${maxBytes}).`);
      }
      pieces.push(piece);
    }
  } finally {
    try { reader.releaseLock?.(); } catch {}
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of pieces) {
    out.set(p, off);
    off += p.byteLength;
  }
  return out;
}

async function verifyOpfsBlobStreaming(opfs, relPath, node, cryptoApi) {
  const expectedSize = node.size;
  const cs = node.chunk_size;
  const expectedChunks = node.chunks;

  if (typeof opfs.fileSize === 'function' && typeof opfs.readRange === 'function') {
    const actualSize = await opfs.fileSize(relPath);
    if (actualSize === null || actualSize === undefined) {
      throw new Error(`Pinned blob missing in OPFS: ${node.sha256}`);
    }
    if (actualSize !== expectedSize) {
      throw new Error(`Blob length mismatch: got ${actualSize}, expected ${expectedSize}.`);
    }
    if (expectedSize === 0) {
      if (node.sha256 !== EMPTY_SHA256 || expectedChunks.length !== 0) {
        throw new Error('Invalid empty blob metadata.');
      }
      return;
    }
    const wholeHash = new IncrementalSha256();
    let idx = 0;
    for (let off = 0; off < expectedSize; off += cs, idx++) {
      const end = Math.min(expectedSize, off + cs);
      const slice = await opfs.readRange(relPath, off, end);
      if (!slice || slice.byteLength !== end - off) {
        throw new Error(`OPFS blob short read at chunk ${idx}.`);
      }
      const chunkSha = await sha256Hex(slice, cryptoApi);
      if (chunkSha !== expectedChunks[idx]) {
        throw new Error(`Chunk ${idx} SHA-256 mismatch: got ${chunkSha}, expected ${expectedChunks[idx]}.`);
      }
      wholeHash.update(slice);
    }
    if (idx !== expectedChunks.length) {
      throw new Error('Chunk count mismatch during verification.');
    }
    const fullSha = wholeHash.hex();
    if (fullSha !== node.sha256) {
      throw new Error(`Blob SHA-256 mismatch: got ${fullSha}, expected ${node.sha256}.`);
    }
    return;
  }

  // Fallback for minimal in-memory test mocks without readRange/fileSize.
  const bytes = await opfs.readFile(relPath);
  if (!bytes) throw new Error(`Pinned blob missing in OPFS: ${node.sha256}`);
  if (bytes.byteLength !== expectedSize) {
    throw new Error(`Blob length mismatch: got ${bytes.byteLength}, expected ${expectedSize}.`);
  }
  const fullSha = await sha256Hex(bytes, cryptoApi);
  if (fullSha !== node.sha256) {
    throw new Error(`Blob SHA-256 mismatch: got ${fullSha}, expected ${node.sha256}.`);
  }
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

async function verifyExistingCommittedBlob(opfs, blobPath, expectedSha, expectedSize, cryptoApi) {
  if (typeof opfs.fileSize === 'function' && typeof opfs.readRange === 'function') {
    const actualSize = await opfs.fileSize(blobPath).catch(() => null);
    if (actualSize !== expectedSize) return false;
    if (expectedSize === 0) return expectedSha === EMPTY_SHA256;
    const hash = new IncrementalSha256();
    for (let off = 0; off < expectedSize; off += CHUNK_SIZE_MAX) {
      const end = Math.min(expectedSize, off + CHUNK_SIZE_MAX);
      const slice = await opfs.readRange(blobPath, off, end).catch(() => null);
      if (!slice || slice.byteLength !== end - off) return false;
      hash.update(slice);
    }
    return hash.hex() === expectedSha;
  }
  const existing = await opfs.readFile(blobPath).catch(() => null);
  return existing !== null
    && existing.byteLength === expectedSize
    && (await sha256Hex(existing, cryptoApi)) === expectedSha;
}

function encodeAssetPath(path) {
  return path.split('/').map(part => encodeURIComponent(part)).join('/');
}

/**
 * Creates an atomic Release v2 offline installer.
 * Accepts optional injected `{ fetch, opfs, stateStore, cacheStore, crypto, locks, pinnedTrust }`
 * for deterministic unit tests; defaults to real browser OPFS, IndexedDB `{ durability: "strict" }`,
 * Web Locks, and Cache Storage.
 */
export function createOfflineInstaller(options = {}) {
  const fetchFn = options.fetch ?? ((...args) => globalThis.fetch(...args));
  const cryptoApi = options.crypto ?? globalThis.crypto;
  const opfs = options.opfs ?? createBrowserOpfsStore(options.opfsRoot);
  const stateStore = options.stateStore ?? createBrowserStateStore(options.indexedDB);
  const cacheStore = options.cacheStore ?? createBrowserCacheStore(options.caches);
  const locksApi = options.locks !== undefined ? options.locks : globalThis.navigator?.locks;
  const pinnedTrust = options.pinnedTrust ?? null;

  const activeBootLockReleases = new Map();

  async function releaseBootLock(releaseId) {
    if (releaseId) {
      const rel = activeBootLockReleases.get(releaseId);
      if (rel) {
        activeBootLockReleases.delete(releaseId);
        await rel();
      }
      return;
    }
    const releases = [...activeBootLockReleases.values()];
    activeBootLockReleases.clear();
    await Promise.all(releases.map(rel => rel()));
  }

  async function fetchBytesStrict(url, maxBytes = MANIFEST_MAX) {
    const controller = new AbortController();
    const res = await fetchFn(url, { cache: 'no-store', signal: controller.signal });
    if (!res.ok) {
      await cancelBody(res, `HTTP ${res.status}`);
      throw new Error(`Failed to fetch ${url} (HTTP ${res.status}).`);
    }
    return readResponseBytesCapped(res, maxBytes, controller, url);
  }

  /**
   * Streams a verified blob directly to OPFS staging using at most ONE chunk (`<= 1 MiB`)
   * of working memory plus an incremental SHA-256 hasher.
   * When `captureForCache` is true (boot assets only), also returns the verified bytes
   * for immediate insertion into Cache Storage so the caller can drop them immediately.
   */
  async function streamFetchAndVerifyToOpfs(url, node, destPath, { captureForCache = false, writeToOpfs = true } = {}) {
    const expectedSize = node.size;
    const cs = node.chunk_size;
    const expectedChunks = node.chunks;
    const controller = new AbortController();
    const res = await fetchFn(url, { cache: 'no-store', signal: controller.signal });
    if (!res.ok) {
      await cancelBody(res, `HTTP ${res.status}`);
      throw new Error(`Failed to fetch ${url} (HTTP ${res.status}).`);
    }
    const cl = res.headers?.get?.('Content-Length');
    if (cl !== null && cl !== undefined && cl !== '') {
      if (!DIGITS_RE.test(cl.trim()) || Number(cl) !== expectedSize) {
        await cancelBody(res, 'Content-Length mismatch');
        controller.abort();
        throw new Error(`Blob length mismatch for ${url}: Content-Length=${cl}, expected ${expectedSize}.`);
      }
    }

    const useStreamWriter = writeToOpfs && typeof opfs.openWriter === 'function';
    const writer = useStreamWriter ? await opfs.openWriter(destPath) : null;
    const fallbackBuf = (!useStreamWriter && writeToOpfs) || captureForCache
      ? new Uint8Array(expectedSize)
      : null;

    const wholeHash = new IncrementalSha256();
    const chunkBuf = new Uint8Array(Math.min(cs, Math.max(1, expectedSize)));
    let chunkFilled = 0;
    let chunkIdx = 0;
    let totalRead = 0;

    async function flushChunk() {
      if (chunkFilled === 0) return;
      if (chunkIdx >= expectedChunks.length) {
        throw new Error('Chunk count exceeded manifest.');
      }
      const view = chunkBuf.subarray(0, chunkFilled);
      const chunkSha = await sha256Hex(view, cryptoApi);
      if (chunkSha !== expectedChunks[chunkIdx]) {
        throw new Error(`Chunk ${chunkIdx} SHA-256 mismatch: got ${chunkSha}, expected ${expectedChunks[chunkIdx]}.`);
      }
      if (writer) await writer.write(view);
      chunkFilled = 0;
      chunkIdx++;
    }

    async function ingestPiece(piece) {
      if (totalRead + piece.byteLength > expectedSize) {
        throw new Error(`Blob length exceeded manifest (${expectedSize} bytes) for ${url}.`);
      }
      wholeHash.update(piece);
      if (fallbackBuf) fallbackBuf.set(piece, totalRead);
      totalRead += piece.byteLength;

      let pos = 0;
      while (pos < piece.byteLength) {
        const take = Math.min(cs - chunkFilled, piece.byteLength - pos);
        chunkBuf.set(piece.subarray(pos, pos + take), chunkFilled);
        chunkFilled += take;
        pos += take;
        if (chunkFilled === cs) {
          await flushChunk();
        }
      }
    }

    try {
      if (res.body && typeof res.body.getReader === 'function') {
        const reader = res.body.getReader();
        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            if (!value || value.byteLength === 0) continue;
            const piece = value instanceof Uint8Array ? value : new Uint8Array(value);
            await ingestPiece(piece);
          }
        } catch (err) {
          await reader.cancel(err.message).catch(() => {});
          controller.abort();
          throw err;
        } finally {
          try { reader.releaseLock?.(); } catch {}
        }
      } else {
        const raw = new Uint8Array(await res.arrayBuffer());
        await ingestPiece(raw);
      }

      await flushChunk();

      if (totalRead !== expectedSize) {
        throw new Error(`Blob length mismatch: got ${totalRead}, expected ${expectedSize}.`);
      }
      if (chunkIdx !== expectedChunks.length) {
        throw new Error('Chunk count mismatch during verification.');
      }
      const fullSha = wholeHash.hex();
      if (fullSha !== node.sha256) {
        throw new Error(`Blob SHA-256 mismatch: got ${fullSha}, expected ${node.sha256}.`);
      }

      if (writer) {
        await writer.commit();
      } else if (writeToOpfs) {
        await opfs.writeFile(destPath, fallbackBuf);
      }
      return captureForCache ? fallbackBuf : null;
    } catch (err) {
      if (writer) await writer.abort().catch(() => {});
      throw err;
    }
  }

  async function writeFileIfChanged(relPath, bytes) {
    const existing = await opfs.readFile(relPath).catch(() => null);
    if (existing && bytesEqual(existing, bytes)) return;
    await opfs.writeFile(relPath, bytes);
  }

  async function install(releaseId, installOpts = {}) {
    if (typeof releaseId !== 'string' || !HEX64.test(releaseId)) {
      throw new Error('Invalid Release v2 digest identifier.');
    }

    const stagingDir = `os-releases/staging/${releaseId}`;
    const committedDir = `os-releases/releases/${releaseId}`;
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
      // 1. Acquire & reconcile anchored monotonic trust policy (NEVER blindly adopt entries.trust!).
      let incomingTrust = installOpts.trust ?? null;
      let incomingRotation = installOpts.trustRotation ?? null;
      let incomingMinReleaseSeq = installOpts.minReleaseSeq;
      if (!incomingTrust) {
        const entriesBytes = await fetchBytesStrict('/boot/entries', MANIFEST_MAX);
        const entries = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(entriesBytes));
        if (
          entries.format !== 'os.boot'
          || entries.version !== RELEASE_VERSION
          || entries.protocol !== PROTOCOL_VERSION
          || entries.schema !== SCHEMA_VERSION
        ) {
          throw new Error('Incompatible boot authority entries.');
        }
        incomingTrust = entries.trust;
        if (!incomingRotation && entries.trust_rotation) incomingRotation = entries.trust_rotation;
        if (incomingMinReleaseSeq === undefined && entries.min_release_seq !== undefined) {
          incomingMinReleaseSeq = entries.min_release_seq;
        }
      }

      const reconciled = await reconcileTrustRoot(existingState.trustRoot, incomingTrust, {
        pinnedTrust: installOpts.pinnedTrust ?? pinnedTrust,
        rotation: incomingRotation,
        incomingMinReleaseSeq,
        allowBootstrap: true,
        cryptoApi,
      });

      // Immediately ratchet newly learned revocations / minReleaseSeq / verified rotations
      // into strict IDB when already anchored, even if installing the candidate subsequently fails!
      if (existingState.trustRoot && trustRootChanged(existingState.trustRoot, reconciled.trustRoot)) {
        await stateStore.updateStrict(cur => {
          const base = cur.trustRoot ? cloneTrustRoot(cur.trustRoot) : cloneTrustRoot(reconciled.trustRoot);
          const rev = new Set([...base.revoked, ...reconciled.trustRoot.revoked]);
          for (const [k, v] of Object.entries(reconciled.trustRoot.keys)) {
            if (!(k in base.keys)) base.keys[k] = v;
          }
          base.revoked = [...rev].sort();
          base.minReleaseSeq = Math.max(base.minReleaseSeq, reconciled.trustRoot.minReleaseSeq);
          base.requireExplicitSeq = base.requireExplicitSeq || reconciled.trustRoot.requireExplicitSeq;
          cur.trustRoot = base;
          return cur;
        });
      }

      const trust = reconciled.trust;

      // 2. Fetch & cryptographically verify Release v2 manifest + Ed25519 signature (`os.release.v2`).
      const manifestBytes = await fetchBytesStrict(`/boot/releases/${releaseId}/manifest.json`, MANIFEST_MAX);
      if (await sha256Hex(manifestBytes, cryptoApi) !== releaseId) {
        throw new Error('Release manifest SHA-256 digest mismatch.');
      }
      const sigBytes = await fetchBytesStrict(`/boot/releases/${releaseId}/signature.json`, MANIFEST_MAX);
      const sigObj = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(sigBytes));
      const releaseSigner = await verifyEd25519Detached(SIGNING_DOMAIN_RELEASE_V2, manifestBytes, sigObj, trust, cryptoApi);
      const release = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(manifestBytes));
      const imageHashes = validateReleaseV2Manifest(release);
      const explicitSeq = extractReleaseSeq(release);

      // Enforce monotonic anti-downgrade policy before fetching or staging any image blobs.
      const nextTrustRoot = checkAndAdvanceAntiDowngrade(reconciled.trustRoot, releaseId, explicitSeq, {
        allowDowngrade: Boolean(installOpts.allowDowngrade),
      });

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
      const imageSignerSet = new Set();
      for (let i = 0; i < imageHashes.length; i++) {
        const hash = imageHashes[i];
        const imgBytes = await fetchBytesStrict(`/boot/images/${hash}.json`, MANIFEST_MAX);
        if (await sha256Hex(imgBytes, cryptoApi) !== hash) {
          throw new Error(`Image ${hash} digest mismatch.`);
        }
        const imgSigBytes = await fetchBytesStrict(`/boot/images/${hash}.sig`, MANIFEST_MAX);
        const imgSigObj = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(imgSigBytes));
        const imgSigner = await verifyEd25519Detached(SIGNING_DOMAIN_IMAGE_V2, imgBytes, imgSigObj, trust, cryptoApi);
        imageSignerSet.add(imgSigner);
        const parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(imgBytes));
        const byPath = validateImageV2Manifest(parsed, expectedKinds[i]);
        imageRecords.push({ hash, bytes: imgBytes, sigBytes: imgSigBytes, parsed, byPath });
      }

      // Bind ReleaseV2.loader to actual Boot image entries and enforce full Base+Sysext+Confext composition rules.
      validateBootLoaderBinding(release, imageRecords[0].byPath);
      validateSystemComposition(imageRecords[3].parsed, imageRecords.slice(4).map(r => r.parsed));

      // 4. Stream-fetch & verify ALL blobs directly to OPFS staging (`<= 1 MiB` working buffer).
      // `stagedBlobs` retains ONLY metadata (`{ size, chunk_size, chunks }`), NEVER full blob bytes!
      const stagedBlobs = new Map();
      let pinnedBootAssets = 0;

      for (const rec of imageRecords) {
        for (const entry of rec.parsed.entries) {
          if (entry.node.type !== 'file') continue;
          const node = entry.node;
          const alreadyStaged = stagedBlobs.get(node.sha256);

          if (rec.parsed.kind === 'boot') {
            const assetUrl = `/boot/releases/${releaseId}/assets${encodeAssetPath(entry.path)}`;
            const assetBytes = await streamFetchAndVerifyToOpfs(
              assetUrl,
              node,
              `${stagingDir}/blobs/${node.sha256}`,
              { captureForCache: true, writeToOpfs: !alreadyStaged },
            );
            // Populate Cache Storage immediately and release `assetBytes` right away.
            const mime = mimeTypeFor(entry.path);
            const etag = `"${node.sha256}"`;
            const pinnedUrl = `/boot/releases/${releaseId}/assets${encodeAssetPath(entry.path)}`;
            await cacheStore.put(cacheName, pinnedUrl, assetBytes, mime, etag);
            await cacheStore.put(cacheName, encodeAssetPath(entry.path), assetBytes, mime, etag);
            if (entry.path === '/index.html') {
              await cacheStore.put(cacheName, '/', assetBytes, mime, etag);
            }
            pinnedBootAssets++;
            if (!alreadyStaged) {
              stagedBlobs.set(node.sha256, {
                size: node.size,
                chunk_size: node.chunk_size,
                chunks: node.chunks,
              });
            }
          } else if (!alreadyStaged) {
            await streamFetchAndVerifyToOpfs(
              `/boot/blobs/${node.sha256}`,
              node,
              `${stagingDir}/blobs/${node.sha256}`,
              { captureForCache: false, writeToOpfs: true },
            );
            stagedBlobs.set(node.sha256, {
              size: node.size,
              chunk_size: node.chunk_size,
              chunks: node.chunks,
            });
          } else {
            // Re-verify chunk list if another image references the same blob with a different chunk_size/chunks.
            const sameManifest = alreadyStaged.size === node.size
              && alreadyStaged.chunk_size === node.chunk_size
              && alreadyStaged.chunks.length === node.chunks.length
              && alreadyStaged.chunks.every((c, i) => c === node.chunks[i]);
            if (!sameManifest) {
              await verifyOpfsBlobStreaming(opfs, `${stagingDir}/blobs/${node.sha256}`, node, cryptoApi);
            }
          }
        }
      }

      // Write staged release metadata to OPFS staging.
      const trustBytes = new TextEncoder().encode(JSON.stringify(trust));
      await opfs.writeFile(`${stagingDir}/manifest.json`, manifestBytes);
      await opfs.writeFile(`${stagingDir}/signature.json`, sigBytes);
      await opfs.writeFile(`${stagingDir}/trust.json`, trustBytes);
      for (const rec of imageRecords) {
        await opfs.writeFile(`${stagingDir}/images/${rec.hash}.json`, rec.bytes);
        await opfs.writeFile(`${stagingDir}/images/${rec.hash}.sig`, rec.sigBytes);
      }

      // 5. Populate Cache Storage (`os-release-v2:<releaseId>`) metadata entries.
      await cacheStore.put(cacheName, `/boot/releases/${releaseId}/manifest.json`, manifestBytes, 'application/json; charset=utf-8', `"${releaseId}"`);
      await cacheStore.put(cacheName, `/boot/releases/${releaseId}/signature.json`, sigBytes, 'application/json; charset=utf-8');
      for (const rec of imageRecords) {
        await cacheStore.put(cacheName, `/boot/images/${rec.hash}.json`, rec.bytes, 'application/json; charset=utf-8', `"${rec.hash}"`);
        await cacheStore.put(cacheName, `/boot/images/${rec.hash}.sig`, rec.sigBytes, 'application/json; charset=utf-8');
      }

      // 6. Promote staged files into committed OPFS store atomically without truncating live pinned files.
      for (const [sha, meta] of stagedBlobs.entries()) {
        const blobPath = `os-releases/blobs/${sha}`;
        const validExisting = await verifyExistingCommittedBlob(opfs, blobPath, sha, meta.size, cryptoApi);
        if (!validExisting) {
          if (typeof opfs.moveFile === 'function') {
            await opfs.moveFile(`${stagingDir}/blobs/${sha}`, blobPath);
          } else {
            const staged = await opfs.readFile(`${stagingDir}/blobs/${sha}`);
            if (!staged) throw new Error(`Staged blob missing during promotion: ${sha}`);
            await opfs.writeFile(blobPath, staged);
          }
        }
        const metaBytes = new TextEncoder().encode(JSON.stringify(meta));
        await writeFileIfChanged(`os-releases/blob-meta/${sha}.json`, metaBytes);
      }
      await writeFileIfChanged(`${committedDir}/manifest.json`, manifestBytes);
      await writeFileIfChanged(`${committedDir}/signature.json`, sigBytes);
      await writeFileIfChanged(`${committedDir}/trust.json`, trustBytes);
      for (const rec of imageRecords) {
        await writeFileIfChanged(`${committedDir}/images/${rec.hash}.json`, rec.bytes);
        await writeFileIfChanged(`${committedDir}/images/${rec.hash}.sig`, rec.sigBytes);
      }
      await opfs.removeDir(stagingDir);

      // 7. Atomically swap IndexedDB `{ durability: "strict" }` generation pointer & anchored trustRoot.
      // Preserves known-good `previous` generation intact across back-to-back unverified installs
      // until `markBootHealthy(releaseId)` is called!
      const activate = installOpts.activate !== false;
      const nextState = await stateStore.updateStrict(state => {
        const mergedRoot = state.trustRoot ? cloneTrustRoot(state.trustRoot) : cloneTrustRoot(nextTrustRoot);
        const rev = new Set([...mergedRoot.revoked, ...nextTrustRoot.revoked]);
        for (const [k, v] of Object.entries(nextTrustRoot.keys)) {
          if (!(k in mergedRoot.keys)) mergedRoot.keys[k] = v;
        }
        mergedRoot.revoked = [...rev].sort();
        mergedRoot.minReleaseSeq = Math.max(mergedRoot.minReleaseSeq, nextTrustRoot.minReleaseSeq);
        mergedRoot.requireExplicitSeq = mergedRoot.requireExplicitSeq || nextTrustRoot.requireExplicitSeq;
        mergedRoot.maxInstalledSeq = Math.max(mergedRoot.maxInstalledSeq, nextTrustRoot.maxInstalledSeq);
        mergedRoot.releaseSeqs = { ...mergedRoot.releaseSeqs, ...nextTrustRoot.releaseSeqs };
        state.trustRoot = mergedRoot;

        state.generations[releaseId] = {
          id: releaseId,
          name: release.name,
          installedAt: Date.now(),
          healthy: Boolean(state.generations?.[releaseId]?.healthy && state.active === releaseId && state.activeBootVerified),
          signer: releaseSigner,
          imageSigners: [...imageSignerSet],
          releaseSeq: explicitSeq,
          trust: publicTrustOf(mergedRoot),
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
          if (state.active && state.active !== releaseId && (state.activeBootVerified || !state.previous)) {
            state.previous = state.active;
          }
          if (state.previous === releaseId) {
            state.previous = null;
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
        pinnedBootAssets,
      };
    } catch (error) {
      await opfs.removeDir(stagingDir).catch(() => {});
      if (!keepCacheOnFailure) {
        await opfs.removeDir(committedDir).catch(() => {});
        await cacheStore.deleteCache(cacheName).catch(() => {});
      }
      throw error;
    }
  }

  /**
   * Verifies a locally pinned Release v2 completely offline (0 network requests):
   * - Profile-wide monotonic `trustRoot` (NEVER trusts a generation's frozen `trust.json`!)
   * - Ed25519 signatures, manifest structure, full symlink confinement, `Base+Sysext+Confext` composition
   * - Cache Storage loader asset integrity (`entry`, `client_kernel_js`, `client_kernel_wasm`)
   * - Streaming bounded full + per-chunk SHA-256 verification of every pinned OPFS blob.
   */
  async function verifyInstalledOffline(releaseId, { verifyAllBlobs = true, verifyCache = true } = {}) {
    const state = await stateStore.read();
    const { trust } = await reconcileTrustRoot(state?.trustRoot ?? null, null, {
      pinnedTrust,
      allowBootstrap: false,
      cryptoApi,
    });
    const trustText = JSON.stringify(trust);

    const dir = `os-releases/releases/${releaseId}`;
    const manifestBytes = await opfs.readFile(`${dir}/manifest.json`);
    const sigBytes = await opfs.readFile(`${dir}/signature.json`);
    if (!manifestBytes || !sigBytes) {
      throw new Error(`Release ${releaseId} is not fully pinned in OPFS.`);
    }
    if (await sha256Hex(manifestBytes, cryptoApi) !== releaseId) {
      throw new Error('Pinned release manifest digest mismatch.');
    }
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
    const imageMaps = [];
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
      const byPath = validateImageV2Manifest(parsed, expectedKinds[i]);
      imagesRaw.push(new TextDecoder('utf-8', { fatal: true }).decode(imgBytes));
      sigsRaw.push(new TextDecoder('utf-8', { fatal: true }).decode(imgSigBytes));
      parsedImages.push(parsed);
      imageMaps.push(byPath);

      if (verifyAllBlobs) {
        for (const entry of parsed.entries) {
          if (entry.node.type !== 'file') continue;
          const cacheKey = `${entry.node.sha256}:${entry.node.chunk_size}:${entry.node.chunks.length}`;
          if (checkedBlobs.has(cacheKey)) continue;
          await verifyOpfsBlobStreaming(opfs, `os-releases/blobs/${entry.node.sha256}`, entry.node, cryptoApi);
          checkedBlobs.add(cacheKey);
        }
      }
    }

    // Enforce loader bindings and Base+Sysext+Confext composition offline as well.
    validateBootLoaderBinding(release, imageMaps[0]);
    validateSystemComposition(parsedImages[3], parsedImages.slice(4));

    // Verify Cache Storage loader assets against signed `Boot` image digests.
    if (verifyCache && cacheStore && typeof cacheStore.match === 'function') {
      const cacheName = `${CACHE_PREFIX}${releaseId}`;
      const bootMap = imageMaps[0];
      for (const field of ['entry', 'client_kernel_js', 'client_kernel_wasm']) {
        const assetPath = release.loader[field];
        const expectedSha = bootMap.get(assetPath).node.sha256;
        const pinnedUrl = `/boot/releases/${releaseId}/assets${encodeAssetPath(assetPath)}`;
        for (const candidateUrl of [pinnedUrl, encodeAssetPath(assetPath)]) {
          const hit = await cacheStore.match(cacheName, candidateUrl);
          const cachedBytes = await readCacheHitBytes(hit);
          if (!cachedBytes) {
            throw new Error(`Cached loader asset missing: ${candidateUrl}`);
          }
          if (await sha256Hex(cachedBytes, cryptoApi) !== expectedSha) {
            throw new Error(`Cached loader asset digest mismatch: ${candidateUrl}`);
          }
        }
      }
    }

    return {
      releaseId,
      release,
      trust,
      manifestText: new TextDecoder('utf-8', { fatal: true }).decode(manifestBytes),
      signatureText: new TextDecoder('utf-8', { fatal: true }).decode(sigBytes),
      trustText,
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
   * - Holds a shared Web Lock `os-boot-attempt:<releaseId>` until `markBootHealthy` or `abortOfflineBoot`
   *   so concurrent tab/iframe navigations never prematurely roll back a healthy upgrade.
   * - Only triggers crash auto-rollback when `!activeBootVerified && bootAttempts >= 1` AND no tab
   *   currently holds `os-boot-attempt:<active>` AND `previous` passes monotonic trust verification.
   */
  async function beginOfflineBoot({ verifyAllBlobs = true, verifyCache = true } = {}) {
    const pre = await stateStore.read();
    if (!pre.active) {
      throw new Error('No offline Release v2 generation is installed.');
    }

    let rolledBack = false;
    let rolledBackFrom = null;
    let state = pre;

    if (
      !pre.activeBootVerified
      && pre.bootAttempts >= 1
      && pre.previous
      && pre.generations?.[pre.previous]
    ) {
      // Release any prior uncompleted attempt lock held by THIS same installer instance
      // before probing whether any OTHER tab/context is currently running Stage 1 boot.
      await releaseBootLock(pre.active);
      const bootInProgress = await isBootAttemptLocked(pre.active, locksApi);
      if (!bootInProgress) {
        // Verify rollback target against profile-wide monotonic trust BEFORE switching active!
        const prevVerified = await verifyInstalledOffline(pre.previous, { verifyAllBlobs, verifyCache });
        const failedId = pre.active;
        const prevId = pre.previous;
        state = await stateStore.updateStrict(cur => {
          if (cur.active === failedId && cur.previous === prevId) {
            cur.active = prevId;
            cur.previous = null;
            cur.activeBootVerified = Boolean(cur.generations?.[prevId]?.healthy);
            cur.bootAttempts = 0;
          }
          return cur;
        });
        return {
          ...prevVerified,
          rolledBack: true,
          rolledBackFrom: failedId,
          state,
        };
      }
    }

    const activeId = state.active;
    if (!activeBootLockReleases.has(activeId)) {
      const release = await acquireBootAttemptLock(activeId, locksApi);
      activeBootLockReleases.set(activeId, release);
    }

    state = await stateStore.updateStrict(cur => {
      if (cur.active === activeId && !cur.activeBootVerified) {
        cur.bootAttempts = (cur.bootAttempts || 0) + 1;
      }
      return cur;
    });

    try {
      const verified = await verifyInstalledOffline(state.active, { verifyAllBlobs, verifyCache });
      return { ...verified, rolledBack, rolledBackFrom, state };
    } catch (primaryError) {
      await releaseBootLock(activeId);
      if (state.previous && state.generations?.[state.previous]) {
        const prevId = state.previous;
        const failedId = state.active;
        // Fails closed if `previous` was signed by a now-revoked key!
        const fallbackVerified = await verifyInstalledOffline(prevId, { verifyAllBlobs, verifyCache });
        const rolledState = await stateStore.updateStrict(cur => {
          cur.active = prevId;
          cur.previous = null;
          cur.activeBootVerified = Boolean(cur.generations?.[prevId]?.healthy);
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

  async function abortOfflineBoot(releaseId) {
    await releaseBootLock(releaseId);
  }

  async function markBootHealthy(releaseId) {
    try {
      return await stateStore.updateStrict(cur => {
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
    } finally {
      await releaseBootLock(releaseId);
    }
  }

  async function rollback() {
    const pre = await stateStore.read();
    if (!pre.previous || !pre.generations?.[pre.previous]) {
      throw new Error('No previous healthy generation available for rollback.');
    }
    const prevId = pre.previous;
    // Verify rollback target against profile-wide monotonic trust BEFORE switching active.
    await verifyInstalledOffline(prevId, { verifyAllBlobs: false, verifyCache: false });
    await releaseBootLock();
    return stateStore.updateStrict(cur => {
      if (!cur.previous || !cur.generations?.[cur.previous]) {
        throw new Error('No previous healthy generation available for rollback.');
      }
      const targetId = cur.previous;
      cur.active = targetId;
      cur.previous = null;
      cur.activeBootVerified = Boolean(cur.generations[targetId]?.healthy);
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
    abortOfflineBoot,
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

// --- Service Worker bounded OPFS blob server & request router (exported for unit tests too) ---

async function readOpfsBlobSlice(opfs, relPath, start, endExclusive) {
  if (typeof opfs.readRange === 'function') {
    return opfs.readRange(relPath, start, endExclusive);
  }
  if (typeof opfs.getFile === 'function') {
    const file = await opfs.getFile(relPath);
    if (!file) return null;
    return new Uint8Array(await file.slice(start, endExclusive).arrayBuffer());
  }
  const full = await opfs.readFile(relPath);
  if (!full) return null;
  return full.subarray(start, endExclusive);
}

async function getOpfsBlobSize(opfs, relPath) {
  if (typeof opfs.fileSize === 'function') return opfs.fileSize(relPath);
  if (typeof opfs.getFile === 'function') {
    const f = await opfs.getFile(relPath);
    return f ? f.size : null;
  }
  const full = await opfs.readFile(relPath);
  return full ? full.byteLength : null;
}

export function createOfflineSwHandler({
  stateStore,
  opfs,
  cachesApi,
  fetchFn = (...args) => globalThis.fetch(...args),
  locksApi = globalThis.navigator?.locks,
  cryptoApi = globalThis.crypto,
  origin = globalThis.location?.origin ?? 'http://localhost',
} = {}) {
  async function serveOpfsBlob(request, sha) {
    const blobPath = `os-releases/blobs/${sha}`;
    const totalSize = await getOpfsBlobSize(opfs, blobPath);
    if (totalSize === null || totalSize === undefined) return null;

    const etag = `"${sha}"`;
    const headers = isolatedHeaders('application/octet-stream', etag);
    headers.set('Accept-Ranges', 'bytes');
    if (request.headers.get('If-None-Match') === etag) {
      return new Response(null, { status: 304, headers });
    }

    // Load optional per-blob chunk manifest (`<= 1 MiB` covering-chunk verification for Range).
    let chunkMeta = null;
    try {
      const metaBytes = await opfs.readFile(`os-releases/blob-meta/${sha}.json`);
      if (metaBytes) {
        const parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(metaBytes));
        if (
          parsed
          && parsed.size === totalSize
          && isPowerOfTwo(parsed.chunk_size)
          && Array.isArray(parsed.chunks)
        ) {
          chunkMeta = parsed;
        }
      }
    } catch {
      chunkMeta = null;
    }

    const range = request.headers.get('Range');
    const ifRange = request.headers.get('If-Range');
    const useRange = Boolean(range && (!ifRange || ifRange === etag));

    if (useRange) {
      const match = /^bytes=(\d+)-(\d*)$/.exec(range.trim());
      if (!match) return new Response(null, { status: 416 });
      const start = Number(match[1]);
      const end = match[2] === '' ? totalSize - 1 : Math.min(Number(match[2]), totalSize - 1);
      if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start > end || start >= totalSize) {
        return new Response(null, { status: 416 });
      }
      const sliceLen = end - start + 1;
      headers.set('Content-Range', `bytes ${start}-${end}/${totalSize}`);
      headers.set('Content-Length', String(sliceLen));
      if (request.method === 'HEAD') {
        return new Response(null, { status: 206, headers });
      }

      if (chunkMeta) {
        const cs = chunkMeta.chunk_size;
        const firstChunk = Math.floor(start / cs);
        const lastChunk = Math.floor(end / cs);
        const out = new Uint8Array(sliceLen);
        let dst = 0;
        for (let idx = firstChunk; idx <= lastChunk; idx++) {
          const cStart = idx * cs;
          const cEndExclusive = Math.min(totalSize, cStart + cs);
          const chunkBytes = await readOpfsBlobSlice(opfs, blobPath, cStart, cEndExclusive);
          if (!chunkBytes || chunkBytes.byteLength !== cEndExclusive - cStart) {
            return new Response('corrupted local blob', { status: 409 });
          }
          if (await sha256Hex(chunkBytes, cryptoApi) !== chunkMeta.chunks[idx]) {
            return new Response('corrupted local blob', { status: 409 });
          }
          const copyStart = Math.max(0, start - cStart);
          const copyEnd = Math.min(chunkBytes.byteLength, end + 1 - cStart);
          out.set(chunkBytes.subarray(copyStart, copyEnd), dst);
          dst += copyEnd - copyStart;
        }
        return new Response(out, { status: 206, headers });
      }

      // No chunk metadata stored: return bounded slice directly without reading whole file into RAM.
      const slice = await readOpfsBlobSlice(opfs, blobPath, start, end + 1);
      if (!slice || slice.byteLength !== sliceLen) {
        return new Response('corrupted local blob', { status: 409 });
      }
      return new Response(slice, { status: 206, headers });
    }

    headers.set('Content-Length', String(totalSize));
    if (request.method === 'HEAD') {
      return new Response(null, { status: 200, headers });
    }
    if (totalSize === 0) {
      if (sha !== EMPTY_SHA256) return new Response('corrupted local blob', { status: 409 });
      return new Response(new Uint8Array(0), { status: 200, headers });
    }
    if (totalSize <= CHUNK_SIZE_MAX) {
      const bytes = await readOpfsBlobSlice(opfs, blobPath, 0, totalSize);
      if (!bytes || bytes.byteLength !== totalSize || await sha256Hex(bytes, cryptoApi) !== sha) {
        return new Response('corrupted local blob', { status: 409 });
      }
      return new Response(bytes, { status: 200, headers });
    }
    // Stream large 200 responses chunk-by-chunk (bounded <= 1 MiB RAM).
    const step = chunkMeta ? chunkMeta.chunk_size : CHUNK_SIZE_MAX;
    let offset = 0;
    let chunkIdx = 0;
    const wholeHash = new IncrementalSha256();
    const stream = new ReadableStream({
      async pull(controller) {
        if (offset >= totalSize) {
          if (wholeHash.hex() !== sha) {
            controller.error(new Error('corrupted local blob'));
            return;
          }
          controller.close();
          return;
        }
        const end = Math.min(totalSize, offset + step);
        const piece = await readOpfsBlobSlice(opfs, blobPath, offset, end);
        if (!piece || piece.byteLength !== end - offset) {
          controller.error(new Error('corrupted local blob'));
          return;
        }
        if (chunkMeta && await sha256Hex(piece, cryptoApi) !== chunkMeta.chunks[chunkIdx]) {
          controller.error(new Error('corrupted local blob chunk'));
          return;
        }
        wholeHash.update(piece);
        offset = end;
        chunkIdx++;
        controller.enqueue(piece);
      },
    });
    return new Response(stream, { status: 200, headers });
  }

  async function handleBootEntries(request) {
    // ALWAYS network-first for `/boot/entries` so online revocations propagate immediately!
    try {
      const controller = new AbortController();
      const netRes = await fetchFn(request.url, { cache: 'no-store', signal: controller.signal });
      if (netRes.status === 503 || !netRes.ok) {
        return netRes;
      }
      const rawBytes = await readResponseBytesCapped(netRes, MANIFEST_MAX, controller, '/boot/entries');
      let entries;
      try {
        entries = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(rawBytes));
      } catch {
        return new Response(rawBytes, { status: netRes.status, headers: netRes.headers });
      }
      if (entries?.format === 'os.boot' && entries.version === RELEASE_VERSION && entries.trust) {
        const curState = await stateStore.read().catch(() => null);
        if (curState?.trustRoot) {
          const reconciled = await reconcileTrustRoot(curState.trustRoot, entries.trust, {
            rotation: entries.trust_rotation ?? null,
            incomingMinReleaseSeq: entries.min_release_seq,
            allowBootstrap: false,
            cryptoApi,
          });
          if (trustRootChanged(curState.trustRoot, reconciled.trustRoot)) {
            await stateStore.updateStrict(cur => {
              if (!cur.trustRoot) return cur;
              const merged = cloneTrustRoot(cur.trustRoot);
              const rev = new Set([...merged.revoked, ...reconciled.trustRoot.revoked]);
              for (const [k, v] of Object.entries(reconciled.trustRoot.keys)) {
                if (!(k in merged.keys)) merged.keys[k] = v;
              }
              merged.revoked = [...rev].sort();
              merged.minReleaseSeq = Math.max(merged.minReleaseSeq, reconciled.trustRoot.minReleaseSeq);
              merged.requireExplicitSeq = merged.requireExplicitSeq || reconciled.trustRoot.requireExplicitSeq;
              cur.trustRoot = merged;
              return cur;
            }).catch(() => {});
          }
          const outEntries = { ...entries, trust: reconciled.trust };
          const headers = new Headers(netRes.headers);
          headers.set('Content-Type', 'application/json; charset=utf-8');
          headers.set('Cache-Control', 'no-store');
          return new Response(JSON.stringify(outEntries), { status: 200, headers });
        }
      }
      const headers = new Headers(netRes.headers);
      headers.set('Cache-Control', 'no-store');
      return new Response(rawBytes, { status: 200, headers });
    } catch {
      // Offline fallback: synthesize `/boot/entries` strictly from profile-wide monotonic `trustRoot`.
      const state = await stateStore.read().catch(() => null);
      if (state?.active && state.trustRoot) {
        const offlineEntries = {
          format: 'os.boot',
          version: RELEASE_VERSION,
          default: state.active,
          protocol: PROTOCOL_VERSION,
          schema: SCHEMA_VERSION,
          trust: publicTrustOf(state.trustRoot),
        };
        const headers = isolatedHeaders('application/json; charset=utf-8');
        headers.set('Cache-Control', 'no-store');
        return new Response(JSON.stringify(offlineEntries), { status: 200, headers });
      }
      return new Response('Offline and no trusted boot entries installed.', { status: 503 });
    }
  }

  return async function handleFetch(request) {
    if (request.method !== 'GET' && request.method !== 'HEAD') return null;
    const url = new URL(request.url, origin);
    if (url.origin !== origin) return null;
    if (url.pathname.startsWith('/api/')) return null;

    if (url.pathname === '/boot/entries') {
      return handleBootEntries(request);
    }

    let state;
    try {
      state = await stateStore.read();
    } catch {
      return fetchFn(request);
    }
    if (!state?.active) {
      return fetchFn(request);
    }

    // Auto-rollback on navigation ONLY if prior attempt crashed AND no tab holds `os-boot-attempt:<active>`
    // AND the rollback target is not revoked in the profile-wide monotonic trust root.
    if (
      request.mode === 'navigate'
      && !state.activeBootVerified
      && state.bootAttempts >= 1
      && state.previous
      && state.generations?.[state.previous]
      && !isGenerationRevoked(state.generations[state.previous], state.trustRoot)
    ) {
      const bootInProgress = await isBootAttemptLocked(state.active, locksApi);
      if (!bootInProgress) {
        state = await stateStore.updateStrict(cur => {
          if (
            !cur.activeBootVerified
            && cur.bootAttempts >= 1
            && cur.previous
            && cur.generations?.[cur.previous]
            && !isGenerationRevoked(cur.generations[cur.previous], cur.trustRoot)
          ) {
            const prevId = cur.previous;
            cur.rolledBackFrom = cur.active;
            cur.active = prevId;
            cur.previous = null;
            cur.activeBootVerified = Boolean(cur.generations[prevId]?.healthy);
            cur.bootAttempts = 0;
          }
          return cur;
        });
      }
    }

    // Direct content-addressed blob lookup from OPFS (bounded Range slicing).
    if (url.pathname.startsWith('/boot/blobs/')) {
      const sha = url.pathname.slice('/boot/blobs/'.length);
      if (HEX64.test(sha)) {
        const local = await serveOpfsBlob(request, sha);
        if (local) return local;
      }
      return fetchFn(request);
    }

    // Check explicitly pinned release cache first if URL addresses a release.
    const releaseMatch = /^\/boot\/releases\/([a-f0-9]{64})(?:\/|$)/.exec(url.pathname);
    if (releaseMatch) {
      const targetId = releaseMatch[1];
      const targetGen = state.generations?.[targetId];
      if (targetGen) {
        if (state.trustRoot && isGenerationRevoked(targetGen, state.trustRoot)) {
          return new Response('Release publisher key is revoked.', { status: 409 });
        }
        const cache = await cachesApi.open(`${CACHE_PREFIX}${targetId}`);
        const hit = await cache.match(url.pathname, { ignoreSearch: true });
        if (hit) return hit;
      }
      return fetchFn(request);
    }

    // Refuse cached assets if the active generation's signing key has been revoked!
    const activeGen = state.generations?.[state.active];
    if (state.trustRoot && activeGen && isGenerationRevoked(activeGen, state.trustRoot)) {
      if (request.mode === 'navigate') {
        return new Response(
          '<!doctype html><title>OS recovery</title><h1>The selected release cannot boot</h1><p>Its publisher key was revoked.</p>',
          { status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } },
        );
      }
      return new Response('Release publisher key is revoked.', { status: 409 });
    }

    // Serve active offline generation from Cache Storage with ZERO network calls.
    const activeCache = await cachesApi.open(`${CACHE_PREFIX}${state.active}`);
    const hit = await activeCache.match(url.pathname, { ignoreSearch: true });
    if (hit) return hit;
    if (request.mode === 'navigate' && url.pathname === '/') {
      const indexHit = await activeCache.match('/index.html', { ignoreSearch: true });
      if (indexHit) return indexHit;
    }

    return fetchFn(request);
  };
}

// --- Service Worker runtime (when bundled as `/offline-sw.js`) ---

if (typeof ServiceWorkerGlobalScope !== 'undefined' && self instanceof ServiceWorkerGlobalScope) {
  const swStateStore = createBrowserStateStore(self.indexedDB);
  const swOpfs = createBrowserOpfsStore();
  const handleSwFetch = createOfflineSwHandler({
    stateStore: swStateStore,
    opfs: swOpfs,
    cachesApi: self.caches,
    fetchFn: (...args) => self.fetch(...args),
    locksApi: self.navigator?.locks,
    cryptoApi: self.crypto,
    origin: self.location.origin,
  });

  self.addEventListener('install', event => {
    event.waitUntil(self.skipWaiting());
  });

  self.addEventListener('activate', event => {
    event.waitUntil(self.clients.claim());
  });

  self.addEventListener('fetch', event => {
    const { request } = event;
    if (request.method !== 'GET' && request.method !== 'HEAD') return;
    const url = new URL(request.url);
    if (url.origin !== self.location.origin) return;
    if (url.pathname.startsWith('/api/')) return;
    event.respondWith(handleSwFetch(request));
  });
}

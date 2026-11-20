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

async function readLocalPinned(id) {
  try {
    const root = await globalThis.navigator?.storage?.getDirectory?.();
    if (!root) return null;
    const relDir = await (await (await root.getDirectoryHandle('os-releases')).getDirectoryHandle('releases')).getDirectoryHandle(id);
    const read = async name => new Uint8Array(await (await (await relDir.getFileHandle(name)).getFile()).arrayBuffer());
    const [bytes, sigBytes, trustBytes] = await Promise.all([read('manifest.json'), read('signature.json'), read('trust.json')]);
    const signature = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(sigBytes));
    const trust = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(trustBytes));
    return {
      entries: { format: 'os.boot', version: 2, protocol: 2, schema: 10, default: id, trust },
      bytes,
      signature,
    };
  } catch {
    return null;
  }
}

let checking;
export function verifyRelease() {
  if (releaseId === 'legacy') return Promise.resolve();
  return checking ??= (async () => {
    let entries, bytes, signature;
    const local = await readLocalPinned(releaseId);
    if (local) {
      ({ entries, bytes, signature } = local);
    } else {
      const get = async path => { const response = await fetch(path, { cache: 'no-store' }); if (!response.ok) throw new Error('The release is unavailable. Open recovery.'); return response; };
      entries = await (await get('/boot/entries')).json();
      bytes = new Uint8Array(await (await get(`/boot/releases/${releaseId}/manifest.json`)).arrayBuffer());
      signature = await (await get(`/boot/releases/${releaseId}/signature.json`)).json();
    }
    if (entries.format !== 'os.boot' || entries.version !== 2 || entries.protocol !== 2 || entries.schema !== 10) {
      throw new Error('The authority is incompatible with this release.');
    }
    if (hex(await crypto.subtle.digest('SHA-256', bytes)) !== releaseId) throw new Error('Release digest mismatch.');
    const trusted = entries.trust?.keys?.[signature.key];
    if (signature.format !== 'os.signature' || signature.version !== 1 || !trusted || entries.trust.revoked.includes(signature.key)) throw new Error('Release publisher is not trusted.');
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

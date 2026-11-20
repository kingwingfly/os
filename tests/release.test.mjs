import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign, webcrypto } from 'node:crypto';
import {
  CHUNK_SIZE_MIN,
  SIGNING_DOMAIN_IMAGE_V2,
  SIGNING_DOMAIN_RELEASE_V2,
  createOfflineInstaller,
} from '../web/kernel/offline-installer.js';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');

function chunkDigests(bytes, chunkSize = 256 * 1024) {
  const out = [];
  for (let off = 0; off < bytes.length; off += chunkSize) {
    out.push(hash(bytes.subarray(off, Math.min(bytes.length, off + chunkSize))));
  }
  return out;
}

let sequence = 0;
async function fixture(change = () => {}) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32), key = hash(raw);
  const manifestObj = {
    format: 'os.release',
    version: 2,
    name: 'unit-v2',
    loader: {
      entry: '/index.html',
      client_kernel_js: '/client-kernel.js',
      client_kernel_wasm: '/client_kernel_bg.wasm',
      client_kernel_sha256: hash(Buffer.from('\0asm\x01\0\0\0')),
      host_adapter: { min: 2, max: 2 },
    },
    boot: hash(Buffer.from('boot')),
    initramfs: hash(Buffer.from('initramfs')),
    root_template: hash(Buffer.from('root_template')),
    base: hash(Buffer.from('base')),
    sysext: [],
    confext: [],
    protocol: { min: 2, max: 2 },
    schema: { min: 10, max: 10 },
    provenance: {},
  };
  const state = {
    manifestObj,
    domain: 'os.release.v2',
    entries: { format: 'os.boot', version: 2, protocol: 2, schema: 10, default: '', trust: { keys: { [key]: raw.toString('hex') }, revoked: [] } },
    key,
    privateKey,
    raw,
    tamperBytes: null,
    tamperSig: null,
  };
  change(state);
  const bytes = state.tamperBytes ?? Buffer.from(JSON.stringify(state.manifestObj));
  const id = state.idOverride ?? hash(Buffer.from(JSON.stringify(state.manifestObj)));
  state.entries.default = id;
  const prefix = `/boot/releases/${id}/assets`;
  const signature = state.tamperSig ?? {
    format: 'os.signature',
    version: 1,
    key,
    signature: sign(null, Buffer.concat([Buffer.from(state.domain + '\0'), bytes]), privateKey).toString('hex'),
  };
  const saved = { location: globalThis.location, fetch: globalThis.fetch, flag: globalThis.__osReleaseFetch };
  const requests = [];
  globalThis.location = { pathname: prefix + '/index.html', href: 'https://os.test' + prefix + '/index.html', origin: 'https://os.test' };
  globalThis.fetch = async (input, init) => {
    const path = new URL(input instanceof Request ? input.url : input, location.href).pathname;
    requests.push({ path, headers: input instanceof Request ? input.headers : new Headers(init?.headers) });
    if (path === '/boot/entries') return Response.json(state.entries);
    if (path.endsWith('/manifest.json')) return new Response(bytes);
    if (path.endsWith('/signature.json')) return Response.json(signature);
    return Response.json({});
  };
  delete globalThis.__osReleaseFetch;
  const module = await import(`../web/release.js?test=${sequence++}`);
  return {
    ...module,
    requests,
    id,
    prefix,
    close() {
      globalThis.location = saved.location;
      globalThis.fetch = saved.fetch;
      globalThis.__osReleaseFetch = saved.flag;
    },
  };
}

test('release v2 handshake verifies exact bytes and asset/API requests retain the selected generation', async () => {
  assert.ok(webcrypto.subtle);
  const f = await fixture();
  try {
    await f.verifyRelease();
    assert.equal(f.asset('/client-kernel.js'), f.prefix + '/client-kernel.js');
    assert.equal(f.asset('/api/sys'), '/api/sys');
    assert.equal(f.asset('/boot/blobs/abc'), '/boot/blobs/abc');
    assert.equal(f.asset('//another.test/script.js'), '//another.test/script.js');
    await fetch('https://os.test/api/sys', { method: 'POST', body: '{}' });
    assert.equal(f.requests.at(-1).headers.get('X-OS-Release'), f.id);
    await fetch('https://os.test/os-config.json');
    assert.equal(f.requests.at(-1).path, f.prefix + '/os-config.json');
  } finally {
    f.close();
  }
});

for (const [name, change, message] of [
  ['byte tampering', s => { s.tamperBytes = Buffer.concat([Buffer.from(JSON.stringify(s.manifestObj)), Buffer.from(' ')]); }, /digest mismatch/],
  ['revoked publisher', s => s.entries.trust.revoked.push(s.key), /not trusted/],
  ['unknown publisher', s => { s.entries.trust.keys = {}; }, /not trusted/],
  ['signature tampering', s => { s.tamperSig = { format: 'os.signature', version: 1, key: s.key, signature: '00'.repeat(64) }; }, /Invalid release signature/],
  ['v1 signature domain', s => { s.domain = 'os.release.v1'; }, /Invalid release signature/],
  ['v1 release version', s => { s.manifestObj.version = 1; }, /Incompatible release metadata/],
  ['v1 authority protocol', s => { s.entries.protocol = 1; }, /incompatible/],
  ['incompatible authority schema', s => { s.entries.schema = 9; }, /incompatible/],
]) {
  test(`release v2 handshake rejects ${name} before application initialization`, async () => {
    const f = await fixture(change);
    try {
      await assert.rejects(f.verifyRelease(), message);
    } finally {
      f.close();
    }
  });
}

test('recovery navigation keeps child entry points on the same fallback generation', async () => {
  const saved = { location: globalThis.location, flag: globalThis.__osReleaseFetch };
  globalThis.location = { pathname: '/', search: '?recovery=1', href: 'https://os.test/?recovery=1', origin: 'https://os.test' };
  globalThis.__osReleaseFetch = true;
  try {
    const f = await import(`../web/release.js?test=${sequence++}`);
    assert.equal(f.entry('/console.html'), '/console.html?recovery=1');
    assert.equal(f.entry('/shell.html'), '/shell.html?recovery=1');
    assert.equal(f.entry('/shell.html?managed=1#status'), '/shell.html?managed=1&recovery=1#status');
    assert.equal(f.entry('/shell.html?managed=1&recovery=0'), '/shell.html?managed=1&recovery=1');
    assert.equal(f.asset('/client-kernel.js'), '/client-kernel.js');
  } finally {
    globalThis.location = saved.location;
    globalThis.__osReleaseFetch = saved.flag;
  }
});

// --- OfflineInstaller atomic install, refusal, and rollback unit tests ---

function buildMemoryStores() {
  const files = new Map();
  const cachesMap = new Map();
  let state = {
    format: 'os.offline.state',
    version: 2,
    active: null,
    previous: null,
    activeBootVerified: false,
    bootAttempts: 0,
    generations: {},
  };
  let strictTransactions = 0;

  const opfs = {
    async writeFile(relPath, bytes) {
      files.set(relPath, new Uint8Array(bytes));
    },
    async readFile(relPath) {
      const v = files.get(relPath);
      return v ? new Uint8Array(v) : null;
    },
    async exists(relPath) {
      return files.has(relPath);
    },
    async removeDir(relPath) {
      const prefix = relPath.endsWith('/') ? relPath : relPath + '/';
      for (const k of [...files.keys()]) {
        if (k === relPath || k.startsWith(prefix)) files.delete(k);
      }
    },
    files,
  };
  const stateStore = {
    async read() {
      return structuredClone(state);
    },
    async updateStrict(mutator) {
      strictTransactions++;
      const next = mutator(structuredClone(state));
      state = structuredClone(next);
      return structuredClone(state);
    },
    strictCount: () => strictTransactions,
  };
  const cacheStore = {
    async put(cacheName, urlPath, bytes, contentType, etag) {
      if (!cachesMap.has(cacheName)) cachesMap.set(cacheName, new Map());
      cachesMap.get(cacheName).set(urlPath, { bytes: new Uint8Array(bytes), contentType, etag });
    },
    async match(cacheName, urlPath) {
      return cachesMap.get(cacheName)?.get(urlPath) ?? null;
    },
    async deleteCache(cacheName) {
      cachesMap.delete(cacheName);
    },
    cachesMap,
  };
  return { opfs, stateStore, cacheStore };
}

function makeSignedReleaseBundle(name, { keyPair, extraConfext, mutate = () => {} } = {}) {
  const { privateKey, publicKey } = keyPair ?? generateKeyPairSync('ed25519');
  const rawPub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const keyId = hash(rawPub);
  const trust = { keys: { [keyId]: rawPub.toString('hex') }, revoked: [] };
  const blobs = new Map();
  const routes = new Map();

  const fileNode = (bytes, chunkSize = CHUNK_SIZE_MIN) => {
    const buf = Buffer.from(bytes);
    const sha = hash(buf);
    blobs.set(sha, buf);
    return { type: 'file', sha256: sha, size: buf.length, chunk_size: chunkSize, chunks: chunkDigests(buf, chunkSize) };
  };
  const dirEntry = (path, mode = 0o755) => ({ path, uid: 0, gid: 0, mode, node: { type: 'directory' } });
  const signDoc = (domain, buf) => Buffer.from(JSON.stringify({
    format: 'os.signature',
    version: 1,
    key: keyId,
    signature: sign(null, Buffer.concat([Buffer.from(domain + '\0'), buf]), privateKey).toString('hex'),
  }));

  const wasmBytes = Buffer.concat([Buffer.from('\0asm\x01\0\0\0'), Buffer.alloc(CHUNK_SIZE_MIN + 32, name.charCodeAt(0))]);
  const kernelWasm = Buffer.from('\0asm\x01\0\0\0' + name);
  const indexHtml = Buffer.from(`<!doctype html><title>${name}</title>`);
  const kernelJs = Buffer.from(`// kernel ${name}`);

  const bootImg = {
    format: 'os.image',
    version: 2,
    kind: 'boot',
    name,
    revision: '1',
    abi: 1,
    features: [],
    level: 1,
    provenance: {},
    entries: [
      dirEntry('/'),
      { path: '/client-kernel.js', uid: 0, gid: 0, mode: 0o644, node: fileNode(kernelJs) },
      { path: '/client_kernel_bg.wasm', uid: 0, gid: 0, mode: 0o644, node: fileNode(kernelWasm) },
      { path: '/index.html', uid: 0, gid: 0, mode: 0o644, node: fileNode(indexHtml) },
    ],
  };
  const initramfsImg = {
    format: 'os.image',
    version: 2,
    kind: 'initramfs',
    name,
    revision: '1',
    abi: 1,
    features: [],
    level: 1,
    provenance: {},
    entries: [
      dirEntry('/'),
      dirEntry('/bin'),
      { path: '/bin/cowfsck', uid: 0, gid: 0, mode: 0o777, node: { type: 'symlink', target: 'utilities' } },
      { path: '/bin/dash', uid: 0, gid: 0, mode: 0o755, node: fileNode(wasmBytes) },
      { path: '/bin/mount', uid: 0, gid: 0, mode: 0o777, node: { type: 'symlink', target: 'utilities' } },
      { path: '/bin/sh', uid: 0, gid: 0, mode: 0o777, node: { type: 'symlink', target: 'dash' } },
      { path: '/bin/switch_root', uid: 0, gid: 0, mode: 0o777, node: { type: 'symlink', target: 'utilities' } },
      { path: '/bin/utilities', uid: 0, gid: 0, mode: 0o755, node: fileNode(wasmBytes) },
      { path: '/init', uid: 0, gid: 0, mode: 0o755, node: fileNode(wasmBytes) },
    ],
  };
  const rootTemplateImg = {
    format: 'os.image',
    version: 2,
    kind: 'roottemplate',
    name,
    revision: '1',
    abi: 1,
    features: [],
    level: 1,
    provenance: {},
    entries: [
      dirEntry('/'),
      dirEntry('/etc'),
      { path: '/etc/group', uid: 0, gid: 0, mode: 0o644, node: fileNode(Buffer.from('root:x:0:\nwheel:x:10:root,user\n')) },
      { path: '/etc/passwd', uid: 0, gid: 0, mode: 0o644, node: fileNode(Buffer.from('root:x:0:0:root:/root:/bin/sh\nuser:x:1000:1000::/home/user:/bin/sh\n')) },
      dirEntry('/root', 0o700),
      dirEntry('/var'),
    ],
  };
  const baseImg = {
    format: 'os.image',
    version: 2,
    kind: 'base',
    name,
    revision: '1',
    abi: 1,
    features: [],
    level: 1,
    provenance: {},
    entries: [
      dirEntry('/'),
      dirEntry('/etc'),
      dirEntry('/opt'),
      dirEntry('/usr'),
      dirEntry('/usr/bin'),
      { path: '/usr/bin/init', uid: 0, gid: 0, mode: 0o755, node: fileNode(wasmBytes) },
    ],
  };

  const ctx = { bootImg, initramfsImg, rootTemplateImg, baseImg, confextImgs: extraConfext ? [extraConfext(fileNode, dirEntry)] : [], trust, blobs, routes };
  mutate(ctx);

  const registerImage = img => {
    img.entries.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    const buf = Buffer.from(JSON.stringify(img));
    const id = hash(buf);
    routes.set(`/boot/images/${id}.json`, buf);
    routes.set(`/boot/images/${id}.sig`, signDoc(SIGNING_DOMAIN_IMAGE_V2, buf));
    return id;
  };
  const bootId = registerImage(ctx.bootImg);
  const initramfsId = registerImage(ctx.initramfsImg);
  const rootTemplateId = registerImage(ctx.rootTemplateImg);
  const baseId = registerImage(ctx.baseImg);
  const confextIds = ctx.confextImgs.map(registerImage);

  const releaseObj = {
    format: 'os.release',
    version: ctx.releaseVersion ?? 2,
    name,
    loader: {
      entry: '/index.html',
      client_kernel_js: '/client-kernel.js',
      client_kernel_wasm: '/client_kernel_bg.wasm',
      client_kernel_sha256: hash(kernelWasm),
      host_adapter: { min: 2, max: 2 },
    },
    boot: bootId,
    initramfs: initramfsId,
    root_template: rootTemplateId,
    base: baseId,
    sysext: [],
    confext: confextIds,
    protocol: { min: 2, max: 2 },
    schema: { min: 10, max: 10 },
    provenance: {},
  };
  const releaseBuf = Buffer.from(JSON.stringify(releaseObj));
  const releaseId = hash(releaseBuf);
  routes.set(`/boot/releases/${releaseId}/manifest.json`, releaseBuf);
  routes.set(`/boot/releases/${releaseId}/signature.json`, ctx.customReleaseSig ?? signDoc(SIGNING_DOMAIN_RELEASE_V2, releaseBuf));
  for (const entry of ctx.bootImg.entries) {
    if (entry.node.type === 'file') {
      routes.set(`/boot/releases/${releaseId}/assets${entry.path}`, blobs.get(entry.node.sha256));
    }
  }
  for (const [sha, buf] of blobs.entries()) {
    routes.set(`/boot/blobs/${sha}`, buf);
  }
  routes.set('/boot/entries', Buffer.from(JSON.stringify({
    format: 'os.boot',
    version: 2,
    default: releaseId,
    protocol: 2,
    schema: 10,
    trust: ctx.trust,
  })));
  ctx.postMutate?.({ routes, releaseId, trust: ctx.trust, blobs, keyId });
  return { releaseId, routes, trust: ctx.trust, keyId, blobs };
}

test('OfflineInstaller pins Release v2 atomically, refuses tampered/incomplete/revoked/v1 updates keeping active A intact, and rolls back on crash before markBootHealthy', async () => {
  const keyPair = generateKeyPairSync('ed25519');
  const genA = makeSignedReleaseBundle('gen-A', { keyPair });
  const genB = makeSignedReleaseBundle('gen-B', { keyPair });

  const stores = buildMemoryStores();
  let activeRoutes = genA.routes;
  let networkEnabled = true;

  const installer = createOfflineInstaller({
    ...stores,
    fetch: async url => {
      if (!networkEnabled) throw new Error('Network disabled (offline boot)');
      const buf = activeRoutes.get(url);
      if (!buf) return new Response(null, { status: 404 });
      return new Response(buf, { status: 200 });
    },
  });

  // 1. Install healthy generation A and boot offline with network disabled.
  await installer.install(genA.releaseId);
  assert.equal((await installer.getState()).active, genA.releaseId);
  assert.equal((await installer.getState()).activeBootVerified, false);

  networkEnabled = false;
  const bootA = await installer.beginOfflineBoot();
  assert.equal(bootA.releaseId, genA.releaseId);
  assert.equal(bootA.rolledBack, false);
  await installer.markBootHealthy(genA.releaseId);
  assert.equal((await installer.getState()).activeBootVerified, true);

  // 2. Tampered/revoked/unknown/incomplete/bad-initramfs/v1 installs MUST fail and keep A intact!
  networkEnabled = true;
  const badCases = [
    ['tampered blob byte', makeSignedReleaseBundle('bad-blob', {
      keyPair,
      mutate: ctx => {
        ctx.postMutate = ({ routes, blobs }) => {
          const utilSha = ctx.initramfsImg.entries.find(e => e.path === '/bin/utilities').node.sha256;
          const mutated = Buffer.from(blobs.get(utilSha));
          mutated[0] ^= 0xff;
          routes.set(`/boot/blobs/${utilSha}`, mutated);
        };
      },
    })],
    ['tampered boot asset byte', makeSignedReleaseBundle('bad-boot-asset', {
      keyPair,
      mutate: ctx => {
        ctx.postMutate = ({ routes, releaseId }) => {
          routes.set(`/boot/releases/${releaseId}/assets/index.html`, Buffer.from('<!doctype html><title>tampered</title>'));
        };
      },
    })],
    ['tampered chunk digest', makeSignedReleaseBundle('bad-chunk', {
      keyPair,
      mutate: ctx => {
        const util = ctx.initramfsImg.entries.find(e => e.path === '/bin/utilities');
        util.node.chunks[1] = 'f'.repeat(64);
      },
    })],
    ['revoked publisher key', makeSignedReleaseBundle('bad-revoked', {
      keyPair,
      mutate: ctx => {
        ctx.postMutate = ({ trust, keyId, routes, releaseId }) => {
          trust.revoked.push(keyId);
          routes.set('/boot/entries', Buffer.from(JSON.stringify({ format: 'os.boot', version: 2, default: releaseId, protocol: 2, schema: 10, trust })));
        };
      },
    })],
    ['unknown publisher key', makeSignedReleaseBundle('bad-unknown', {
      keyPair: generateKeyPairSync('ed25519'),
      mutate: ctx => {
        ctx.postMutate = ({ routes, releaseId }) => {
          routes.set('/boot/entries', Buffer.from(JSON.stringify({ format: 'os.boot', version: 2, default: releaseId, protocol: 2, schema: 10, trust: genA.trust })));
        };
      },
    })],
    ['invalid signature', makeSignedReleaseBundle('bad-sig', {
      keyPair,
      mutate: ctx => {
        ctx.postMutate = ({ routes, releaseId, keyId }) => {
          routes.set(`/boot/releases/${releaseId}/signature.json`, Buffer.from(JSON.stringify({ format: 'os.signature', version: 1, key: keyId, signature: '00'.repeat(64) })));
        };
      },
    })],
    ['interrupted missing blob', makeSignedReleaseBundle('bad-missing', {
      keyPair,
      mutate: ctx => {
        ctx.postMutate = ({ routes }) => {
          const utilSha = ctx.initramfsImg.entries.find(e => e.path === '/bin/utilities').node.sha256;
          routes.delete(`/boot/blobs/${utilSha}`);
        };
      },
    })],
    ['missing initramfs binary (/bin/cowfsck)', makeSignedReleaseBundle('bad-initramfs', {
      keyPair,
      mutate: ctx => {
        ctx.initramfsImg.entries = ctx.initramfsImg.entries.filter(e => e.path !== '/bin/cowfsck');
      },
    })],
    ['protected /etc/passwd in confext', makeSignedReleaseBundle('bad-confext', {
      keyPair,
      extraConfext: (fileNode, dirEntry) => ({
        format: 'os.image',
        version: 2,
        kind: 'confext',
        name: 'evil-confext',
        revision: '1',
        abi: 1,
        features: [],
        level: 1,
        provenance: {},
        entries: [
          dirEntry('/'),
          dirEntry('/etc'),
          { path: '/etc/passwd', uid: 0, gid: 0, mode: 0o644, node: fileNode(Buffer.from('evil')) },
        ],
      }),
    })],
    ['v1 release version', makeSignedReleaseBundle('bad-v1', {
      keyPair,
      mutate: ctx => { ctx.releaseVersion = 1; },
    })],
  ];

  for (const [label, bad] of badCases) {
    activeRoutes = bad.routes;
    await assert.rejects(installer.install(bad.releaseId), undefined, `expected refusal for ${label}`);
    const st = await installer.getState();
    assert.equal(st.active, genA.releaseId, `active changed on ${label}`);
    assert.equal(st.activeBootVerified, true, `activeBootVerified cleared on ${label}`);
    // Confirm staging dir was cleaned up.
    assert.equal([...stores.opfs.files.keys()].some(k => k.includes(`/staging/${bad.releaseId}`)), false);
  }

  // 3. Install valid generation B -> previous A is preserved until markBootHealthy(B).
  activeRoutes = genB.routes;
  await installer.install(genB.releaseId);
  const afterInstallB = await installer.getState();
  assert.equal(afterInstallB.active, genB.releaseId);
  assert.equal(afterInstallB.previous, genA.releaseId);
  assert.equal(afterInstallB.activeBootVerified, false);

  // 4. Simulate crash during first offline boot of B (beginOfflineBoot without markBootHealthy).
  networkEnabled = false;
  const firstAttemptB = await installer.beginOfflineBoot();
  assert.equal(firstAttemptB.releaseId, genB.releaseId);
  assert.equal(firstAttemptB.rolledBack, false);
  assert.equal((await installer.getState()).bootAttempts, 1);

  // 5. Next offline boot detects prior unverified crash and automatically rolls back to A!
  const recovered = await installer.beginOfflineBoot();
  assert.equal(recovered.rolledBack, true);
  assert.equal(recovered.rolledBackFrom, genB.releaseId);
  assert.equal(recovered.releaseId, genA.releaseId);
  assert.equal((await installer.getState()).active, genA.releaseId);
  assert.equal((await installer.getState()).activeBootVerified, true);
});

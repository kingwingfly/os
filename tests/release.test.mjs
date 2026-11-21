import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign, webcrypto } from 'node:crypto';
import {
  BOOT_LOCK_PREFIX,
  CHUNK_SIZE_MIN,
  MANIFEST_MAX,
  SIGNING_DOMAIN_IMAGE_V2,
  SIGNING_DOMAIN_RELEASE_V2,
  SIGNING_DOMAIN_TRUST_V2,
  createBrowserOpfsStore,
  createOfflineInstaller,
  createOfflineSwHandler,
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
    trustRoot: null,
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
  const sysextIds = (ctx.extraSysext ?? []).map(registerImage);
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
    sysext: sysextIds,
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
  const revokedKeyPair = generateKeyPairSync('ed25519');
  const revokedRawPub = revokedKeyPair.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const revokedKeyId = hash(revokedRawPub);
  const addSecondaryKey = ctx => {
    ctx.trust.keys[revokedKeyId] = revokedRawPub.toString('hex');
  };
  const genA = makeSignedReleaseBundle('gen-A', { keyPair, mutate: addSecondaryKey });
  const genB = makeSignedReleaseBundle('gen-B', { keyPair, mutate: addSecondaryKey });

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
      keyPair: revokedKeyPair,
      mutate: ctx => {
        ctx.postMutate = ({ trust, keyId, routes, releaseId }) => {
          Object.assign(trust.keys, genA.trust.keys);
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

test('OfflineInstaller preserves known-good previous A across back-to-back unverified installs (A healthy -> B unverified -> C crash -> restores A)', async () => {
  const keyPair = generateKeyPairSync('ed25519');
  const genA = makeSignedReleaseBundle('gen-A', { keyPair });
  const genB = makeSignedReleaseBundle('gen-B', { keyPair });
  const genC = makeSignedReleaseBundle('gen-C', { keyPair });

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

  // Install A and verify healthy boot.
  await installer.install(genA.releaseId);
  networkEnabled = false;
  await installer.beginOfflineBoot();
  await installer.markBootHealthy(genA.releaseId);
  assert.equal((await installer.getState()).activeBootVerified, true);

  // Install B without booting/marking B healthy -> previous = A.
  networkEnabled = true;
  activeRoutes = genB.routes;
  await installer.install(genB.releaseId);
  let state = await installer.getState();
  assert.equal(state.active, genB.releaseId);
  assert.equal(state.previous, genA.releaseId);
  assert.equal(state.activeBootVerified, false);

  // Install C before B ever boots cleanly -> previous MUST remain healthy A (NOT unverified B)!
  activeRoutes = genC.routes;
  await installer.install(genC.releaseId);
  state = await installer.getState();
  assert.equal(state.active, genC.releaseId);
  assert.equal(state.previous, genA.releaseId);
  assert.equal(state.activeBootVerified, false);

  // Simulate crash of C before markBootHealthy(C) -> next offline boot rolls back to healthy A!
  networkEnabled = false;
  const attemptC = await installer.beginOfflineBoot();
  assert.equal(attemptC.releaseId, genC.releaseId);
  assert.equal(attemptC.rolledBack, false);

  const recovered = await installer.beginOfflineBoot();
  assert.equal(recovered.rolledBack, true);
  assert.equal(recovered.rolledBackFrom, genC.releaseId);
  assert.equal(recovered.releaseId, genA.releaseId);
  state = await installer.getState();
  assert.equal(state.active, genA.releaseId);
  assert.equal(state.previous, null);
  assert.equal(state.activeBootVerified, true);

  // Also verify rolling back to an unverified previous generation does NOT falsely mark it healthy.
  const stores2 = buildMemoryStores();
  let routes2 = genA.routes;
  const installer2 = createOfflineInstaller({
    ...stores2,
    fetch: async url => {
      const buf = routes2.get(url);
      return buf ? new Response(buf, { status: 200 }) : new Response(null, { status: 404 });
    },
  });
  await installer2.install(genA.releaseId);
  routes2 = genB.routes;
  await installer2.install(genB.releaseId);
  const rolledUnverified = await installer2.rollback();
  assert.equal(rolledUnverified.active, genA.releaseId);
  assert.equal(rolledUnverified.activeBootVerified, false);
});

test('OfflineInstaller enforces image ABI/level and full kind path allowlists (boot, initramfs, roottemplate, base, sysext)', async () => {
  const keyPair = generateKeyPairSync('ed25519');
  const genA = makeSignedReleaseBundle('gen-A-policy', { keyPair });
  const stores = buildMemoryStores();
  let activeRoutes = genA.routes;

  const installer = createOfflineInstaller({
    ...stores,
    fetch: async url => {
      const buf = activeRoutes.get(url);
      if (!buf) return new Response(null, { status: 404 });
      return new Response(buf, { status: 200 });
    },
  });

  await installer.install(genA.releaseId);
  await installer.beginOfflineBoot();
  await installer.markBootHealthy(genA.releaseId);

  const fileNodeOf = (blobs, buf) => {
    const sha256 = hash(buf);
    blobs.set(sha256, buf);
    return { type: 'file', sha256, size: buf.length, chunk_size: 262144, chunks: [sha256] };
  };
  const dir = path => ({ path, uid: 0, gid: 0, mode: 0o755, node: { type: 'directory' } });

  const policyCases = [
    ['wrong image ABI', makeSignedReleaseBundle('bad-abi', {
      keyPair,
      mutate: ctx => { ctx.baseImg.abi = 99; },
    })],
    ['wrong image level', makeSignedReleaseBundle('bad-level', {
      keyPair,
      mutate: ctx => { ctx.baseImg.level = 99; },
    })],
    ['unknown image feature', makeSignedReleaseBundle('bad-feature', {
      keyPair,
      mutate: ctx => { ctx.baseImg.features = ['nonexistent-feature']; },
    })],
    ['boot image containing /boot/override', makeSignedReleaseBundle('bad-boot-path', {
      keyPair,
      mutate: ctx => {
        ctx.bootImg.entries.push(dir('/boot'), { path: '/boot/entries', uid: 0, gid: 0, mode: 0o644, node: fileNodeOf(ctx.blobs, Buffer.from('{}')) });
      },
    })],
    ['boot image containing /api/spoof', makeSignedReleaseBundle('bad-api-path', {
      keyPair,
      mutate: ctx => {
        ctx.bootImg.entries.push(dir('/api'), { path: '/api/sys', uid: 0, gid: 0, mode: 0o644, node: fileNodeOf(ctx.blobs, Buffer.from('{}')) });
      },
    })],
    ['initramfs containing protected /etc/passwd', makeSignedReleaseBundle('bad-initramfs-passwd', {
      keyPair,
      mutate: ctx => {
        ctx.initramfsImg.entries.push(dir('/etc'), { path: '/etc/passwd', uid: 0, gid: 0, mode: 0o644, node: fileNodeOf(ctx.blobs, Buffer.from('evil')) });
      },
    })],
    ['initramfs containing disallowed /home/evil', makeSignedReleaseBundle('bad-initramfs-home', {
      keyPair,
      mutate: ctx => {
        ctx.initramfsImg.entries.push(dir('/home'), { path: '/home/evil', uid: 0, gid: 0, mode: 0o644, node: fileNodeOf(ctx.blobs, Buffer.from('evil')) });
      },
    })],
    ['roottemplate containing nested /etc/os-trust/key.json', makeSignedReleaseBundle('bad-roottemplate-trust', {
      keyPair,
      mutate: ctx => {
        ctx.rootTemplateImg.entries.push(
          dir('/etc/os-trust'),
          { path: '/etc/os-trust/key.json', uid: 0, gid: 0, mode: 0o644, node: fileNodeOf(ctx.blobs, Buffer.from('{}')) },
        );
      },
    })],
    ['base image containing disallowed /var/evil', makeSignedReleaseBundle('bad-base-var', {
      keyPair,
      mutate: ctx => {
        ctx.baseImg.entries.push(dir('/var'), { path: '/var/evil', uid: 0, gid: 0, mode: 0o644, node: fileNodeOf(ctx.blobs, Buffer.from('evil')) });
      },
    })],
    ['sysext image containing disallowed /etc/evil', makeSignedReleaseBundle('bad-sysext-etc', {
      keyPair,
      mutate: ctx => {
        ctx.extraSysext = [{
          format: 'os.image',
          version: 2,
          kind: 'sysext',
          name: 'evil-sysext',
          revision: '1',
          abi: 1,
          features: [],
          level: 1,
          provenance: {},
          entries: [
            dir('/'),
            dir('/etc'),
            { path: '/etc/evil', uid: 0, gid: 0, mode: 0o644, node: fileNodeOf(ctx.blobs, Buffer.from('evil')) },
          ],
        }];
      },
    })],
  ];

  for (const [label, bad] of policyCases) {
    activeRoutes = bad.routes;
    await assert.rejects(installer.install(bad.releaseId), undefined, `expected policy refusal for ${label}`);
    const st = await installer.getState();
    assert.equal(st.active, genA.releaseId, `active must stay on A after ${label}`);
    assert.equal(st.activeBootVerified, true, `activeBootVerified must stay true after ${label}`);
  }
});

test('OfflineInstaller repairs pre-existing truncated or corrupted OPFS blob on reinstall', async () => {
  const keyPair = generateKeyPairSync('ed25519');
  const genA = makeSignedReleaseBundle('gen-A-repair', { keyPair });
  const stores = buildMemoryStores();

  // Pre-seed OPFS with a truncated/corrupted copy of one of genA's blobs (as if a prior crash interrupted promotion).
  const targetSha = [...genA.blobs.keys()][0];
  await stores.opfs.writeFile(`os-releases/blobs/${targetSha}`, new Uint8Array([0xde, 0xad, 0xbe, 0xef]));

  const installer = createOfflineInstaller({
    ...stores,
    fetch: async url => {
      const buf = genA.routes.get(url);
      if (!buf) return new Response(null, { status: 404 });
      return new Response(buf, { status: 200 });
    },
  });

  await installer.install(genA.releaseId);
  const verified = await installer.verifyInstalledOffline(genA.releaseId, { verifyAllBlobs: true });
  assert.equal(verified.releaseId, genA.releaseId);
  const repaired = await stores.opfs.readFile(`os-releases/blobs/${targetSha}`);
  assert.equal(hash(Buffer.from(repaired)), targetSha);
});

// --- Track F2 security, durability, streaming, and concurrency regression tests ---

function createMockWebLocks() {
  const sharedCounts = new Map();
  const exclusiveHeld = new Set();
  return {
    async request(name, opts, cb) {
      const mode = opts?.mode ?? 'exclusive';
      const ifAvailable = Boolean(opts?.ifAvailable);
      if (mode === 'exclusive') {
        const busy = exclusiveHeld.has(name) || (sharedCounts.get(name) ?? 0) > 0;
        if (busy) {
          if (ifAvailable) return cb(null);
          throw new Error('exclusive lock busy');
        }
        exclusiveHeld.add(name);
        try {
          return await cb({ name, mode });
        } finally {
          exclusiveHeld.delete(name);
        }
      }
      if (exclusiveHeld.has(name)) {
        if (ifAvailable) return cb(null);
        throw new Error('shared lock blocked by exclusive');
      }
      sharedCounts.set(name, (sharedCounts.get(name) ?? 0) + 1);
      try {
        return await cb({ name, mode });
      } finally {
        const next = (sharedCounts.get(name) ?? 1) - 1;
        if (next <= 0) sharedCounts.delete(name);
        else sharedCounts.set(name, next);
      }
    },
    isHeld(name) {
      return exclusiveHeld.has(name) || (sharedCounts.get(name) ?? 0) > 0;
    },
  };
}

function makeMemoryCachesApi(cacheStore) {
  return {
    async open(name) {
      return {
        async match(urlPath) {
          const hit = await cacheStore.match(name, urlPath);
          if (!hit) return undefined;
          return new Response(hit.bytes, {
            status: 200,
            headers: { 'Content-Type': hit.contentType ?? 'application/octet-stream' },
          });
        },
      };
    },
  };
}

test('F2-01: SW network-first /boot/entries propagates revocations monotonically to active & rollback targets, blocks unanchored keys & downgrades, and supports signed rotation', async () => {
  const keyA = generateKeyPairSync('ed25519');
  const keyB = generateKeyPairSync('ed25519');
  const keyC = generateKeyPairSync('ed25519');
  const attackerKey = generateKeyPairSync('ed25519');

  const pubHex = kp => kp.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
  const keyIdOf = kp => hash(kp.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32));
  const idA = keyIdOf(keyA);
  const idB = keyIdOf(keyB);
  const idC = keyIdOf(keyC);
  const idAttacker = keyIdOf(attackerKey);

  const initialKeys = { [idA]: pubHex(keyA), [idB]: pubHex(keyB) };
  const gen1 = makeSignedReleaseBundle('seq-1', {
    keyPair: keyA,
    mutate: ctx => {
      ctx.trust = { keys: { ...initialKeys }, revoked: [] };
      ctx.postMutate = ({ routes }) => {
        // Re-wrap with explicit release_seq = 1 via provenance.release_seq
      };
    },
  });
  // Build sequenced releases cleanly by injecting provenance.release_seq into manifests.
  const makeSequenced = (name, keyPair, seq, extraTrust = null) => {
    const b = makeSignedReleaseBundle(name, {
      keyPair,
      mutate: ctx => {
        ctx.trust = extraTrust ? structuredClone(extraTrust) : { keys: { ...initialKeys }, revoked: [] };
      },
    });
    const rel = JSON.parse(b.routes.get(`/boot/releases/${b.releaseId}/manifest.json`).toString('utf8'));
    rel.release_seq = seq;
    const relBuf = Buffer.from(JSON.stringify(rel));
    const newId = hash(relBuf);
    const sig = Buffer.from(JSON.stringify({
      format: 'os.signature',
      version: 1,
      key: keyIdOf(keyPair),
      signature: sign(null, Buffer.concat([Buffer.from(SIGNING_DOMAIN_RELEASE_V2 + '\0'), relBuf]), keyPair.privateKey).toString('hex'),
    }));
    const routes = new Map(b.routes);
    routes.set(`/boot/releases/${newId}/manifest.json`, relBuf);
    routes.set(`/boot/releases/${newId}/signature.json`, sig);
    for (const [k, v] of [...b.routes.entries()]) {
      if (k.startsWith(`/boot/releases/${b.releaseId}/assets/`)) {
        routes.set(k.replace(b.releaseId, newId), v);
      }
    }
    routes.set('/boot/entries', Buffer.from(JSON.stringify({
      format: 'os.boot',
      version: 2,
      default: newId,
      protocol: 2,
      schema: 10,
      trust: b.trust,
    })));
    return { ...b, releaseId: newId, routes };
  };

  const rel1 = makeSequenced('rel-1', keyA, 1);
  const rel2 = makeSequenced('rel-2', keyB, 2);
  const relDowngrade = makeSequenced('rel-old', keyB, 1);
  const relUnsequenced = gen1;
  const relAttacker = makeSequenced('rel-evil', attackerKey, 3, {
    keys: { ...initialKeys, [idAttacker]: pubHex(attackerKey) },
    revoked: [],
  });
  const relRotated = makeSequenced('rel-rot', keyC, 3, {
    keys: { ...initialKeys, [idC]: pubHex(keyC) },
    revoked: [idA],
  });

  const stores = buildMemoryStores();
  let activeRoutes = rel1.routes;
  let online = true;
  const origin = 'https://os.test';

  const networkFetch = async url => {
    if (!online) throw new Error('offline');
    const rawUrl = typeof url === 'string' ? url : url.url;
    const path = new URL(rawUrl, origin).pathname;
    const buf = activeRoutes.get(path);
    return buf ? new Response(buf, { status: 200 }) : new Response(null, { status: 404 });
  };

  const swFetch = createOfflineSwHandler({
    stateStore: stores.stateStore,
    opfs: stores.opfs,
    cachesApi: makeMemoryCachesApi(stores.cacheStore),
    fetchFn: networkFetch,
    origin,
  });

  const installer = createOfflineInstaller({
    ...stores,
    fetch: async (url, init) => swFetch(new Request(new URL(url, origin), init)),
  });

  // 1. Install rel1 (seq 1, signed by keyA) and boot healthy.
  await installer.install(rel1.releaseId);
  await installer.beginOfflineBoot();
  await installer.markBootHealthy(rel1.releaseId);

  // 2. Unanchored attacker key in /boot/entries MUST be rejected!
  activeRoutes = relAttacker.routes;
  await assert.rejects(installer.install(relAttacker.releaseId), /not trusted/);

  // 3. Install rel2 (seq 2, signed by keyB). Previous = rel1 (signed by keyA).
  activeRoutes = rel2.routes;
  await installer.install(rel2.releaseId);
  assert.equal((await installer.getState()).previous, rel1.releaseId);

  // 4. Downgrade below minReleaseSeq (seq 1 < 2) and unsequenced release MUST be refused!
  activeRoutes = relDowngrade.routes;
  await assert.rejects(installer.install(relDowngrade.releaseId), /downgrade refused/i);
  activeRoutes = relUnsequenced.routes;
  await assert.rejects(installer.install(relUnsequenced.releaseId), /downgrade refused/i);

  // 5. Online SW `/boot/entries` revokes keyA (network-first, NEVER cache-first!).
  const revokedEntries = Buffer.from(JSON.stringify({
    format: 'os.boot',
    version: 2,
    default: rel2.releaseId,
    protocol: 2,
    schema: 10,
    trust: { keys: { ...initialKeys }, revoked: [idA] },
  }));
  activeRoutes = new Map([['/boot/entries', revokedEntries]]);
  const entriesRes = await swFetch(new Request(`${origin}/boot/entries`));
  assert.equal(entriesRes.status, 200);
  const parsedEntries = await entriesRes.json();
  assert.ok(parsedEntries.trust.revoked.includes(idA));
  assert.ok((await installer.getState()).trustRoot.revoked.includes(idA));

  // 6. Even offline AND even if a stale server later drops keyA from `revoked`,
  //    rel1 (signed by revoked keyA) CANNOT verify, CANNOT boot, CANNOT be rolled back to,
  //    and SW refuses its cached assets!
  online = false;
  await assert.rejects(installer.verifyInstalledOffline(rel1.releaseId), /revoked/);
  await assert.rejects(installer.rollback(), /revoked/);
  const pinnedAssetRes = await swFetch(new Request(`${origin}/boot/releases/${rel1.releaseId}/assets/index.html`));
  assert.equal(pinnedAssetRes.status, 409);

  // Stale /boot/entries omitting keyA cannot un-revoke keyA!
  online = true;
  activeRoutes = rel1.routes;
  const staleRes = await swFetch(new Request(`${origin}/boot/entries`));
  assert.ok((await staleRes.json()).trust.revoked.includes(idA));

  // 7. Signed key rotation (`os.trust.v2`) by non-revoked keyB adds keyC cleanly!
  const rotPayload = JSON.stringify({ add_keys: { [idC]: pubHex(keyC) }, revoke_keys: [idA] });
  const trustRotation = {
    format: 'os.trust.rotation',
    version: 1,
    payload: rotPayload,
    signature: {
      format: 'os.signature',
      version: 1,
      key: idB,
      signature: sign(null, Buffer.concat([Buffer.from(SIGNING_DOMAIN_TRUST_V2 + '\0'), Buffer.from(rotPayload)]), keyB.privateKey).toString('hex'),
    },
  };
  relRotated.routes.set('/boot/entries', Buffer.from(JSON.stringify({
    format: 'os.boot',
    version: 2,
    default: relRotated.releaseId,
    protocol: 2,
    schema: 10,
    trust: { keys: { ...initialKeys, [idC]: pubHex(keyC) }, revoked: [idA] },
    trust_rotation: trustRotation,
  })));
  activeRoutes = relRotated.routes;
  await installer.install(relRotated.releaseId);
  assert.equal((await installer.getState()).active, relRotated.releaseId);
});

test('F2-02: OfflineInstaller rejects symlink escapes, Base+Sysext+Confext composition violations, and tampered Cache Storage loader assets', async () => {
  const keyPair = generateKeyPairSync('ed25519');
  const genGood = makeSignedReleaseBundle('good-comp', { keyPair });
  const stores = buildMemoryStores();
  let activeRoutes = genGood.routes;
  const installer = createOfflineInstaller({
    ...stores,
    fetch: async url => {
      const buf = activeRoutes.get(url);
      return buf ? new Response(buf, { status: 200 }) : new Response(null, { status: 404 });
    },
  });

  await installer.install(genGood.releaseId);

  const dir = path => ({ path, uid: 0, gid: 0, mode: 0o755, node: { type: 'directory' } });
  const link = (path, target) => ({ path, uid: 0, gid: 0, mode: 0o777, node: { type: 'symlink', target } });
  const fileOf = (blobs, text) => {
    const buf = Buffer.from(text);
    const sha256 = hash(buf);
    blobs.set(sha256, buf);
    return { type: 'file', sha256, size: buf.length, chunk_size: CHUNK_SIZE_MIN, chunks: [sha256] };
  };

  const badCases = [
    ['initramfs extra symlink escaping root', makeSignedReleaseBundle('escape-initramfs', {
      keyPair,
      mutate: ctx => {
        ctx.initramfsImg.entries.push(link('/bin/escape', '../../../outside'));
      },
    })],
    ['roottemplate symlink escaping to /etc/os-trust', makeSignedReleaseBundle('escape-roottpl', {
      keyPair,
      mutate: ctx => {
        ctx.rootTemplateImg.entries.push(link('/etc/escape-trust', 'os-trust'));
      },
    })],
    ['sysext symlink escaping to /etc', makeSignedReleaseBundle('escape-sysext', {
      keyPair,
      mutate: ctx => {
        ctx.extraSysext = [{
          format: 'os.image',
          version: 2,
          kind: 'sysext',
          name: 'bad-link',
          revision: '1',
          abi: 1,
          features: [],
          level: 1,
          provenance: {},
          entries: [dir('/'), dir('/usr'), link('/usr/leak', '/etc')],
        }];
      },
    })],
    ['sysext symlink-parent shadowing (/usr/alias/file)', makeSignedReleaseBundle('shadow-sysext', {
      keyPair,
      mutate: ctx => {
        ctx.extraSysext = [{
          format: 'os.image',
          version: 2,
          kind: 'sysext',
          name: 'shadow',
          revision: '1',
          abi: 1,
          features: [],
          level: 1,
          provenance: {},
          entries: [
            dir('/'),
            dir('/usr'),
            link('/usr/alias', 'bin'),
            { path: '/usr/alias/hidden', uid: 0, gid: 0, mode: 0o644, node: fileOf(ctx.blobs, 'x') },
          ],
        }];
      },
    })],
  ];

  for (const [label, bad] of badCases) {
    activeRoutes = bad.routes;
    await assert.rejects(installer.install(bad.releaseId), undefined, `expected rejection for ${label}`);
  }

  // Tampering cached client_kernel_bg.wasm in Cache Storage MUST fail verifyInstalledOffline!
  const cacheMap = stores.cacheStore.cachesMap.get(`os-release-v2:${genGood.releaseId}`);
  const wasmUrl = `/boot/releases/${genGood.releaseId}/assets/client_kernel_bg.wasm`;
  cacheMap.get(wasmUrl).bytes = new Uint8Array([0, 1, 2, 3, 4]);
  await assert.rejects(installer.verifyInstalledOffline(genGood.releaseId), /Cached loader asset digest mismatch/);
});

test('F2-04: install streams blobs via bounded openWriter, cancels oversized responses, and SW serveOpfsBlob slices bounded Range without full-file read', async () => {
  const keyPair = generateKeyPairSync('ed25519');
  const gen = makeSignedReleaseBundle('stream-gen', { keyPair });
  const stores = buildMemoryStores();

  let maxStreamWriteChunk = 0;
  let fullReadCallsOnLargeBlob = 0;
  let rangeReadBytes = 0;

  // Enhance OPFS mock with streaming openWriter, fileSize, readRange, and moveFile.
  const files = stores.opfs.files;
  const streamingOpfs = {
    ...stores.opfs,
    async openWriter(relPath) {
      const chunks = [];
      return {
        async write(chunk) {
          maxStreamWriteChunk = Math.max(maxStreamWriteChunk, chunk.byteLength);
          chunks.push(new Uint8Array(chunk));
        },
        async commit() {
          const total = chunks.reduce((s, c) => s + c.byteLength, 0);
          const out = new Uint8Array(total);
          let off = 0;
          for (const c of chunks) { out.set(c, off); off += c.byteLength; }
          files.set(relPath, out);
        },
        async abort() {},
      };
    },
    async fileSize(relPath) {
      return files.has(relPath) ? files.get(relPath).byteLength : null;
    },
    async readRange(relPath, start, endExclusive) {
      const v = files.get(relPath);
      if (!v) return null;
      const slice = new Uint8Array(v.subarray(start, endExclusive));
      if (relPath.startsWith('os-releases/blobs/')) rangeReadBytes += slice.byteLength;
      return slice;
    },
    async readFile(relPath) {
      if (relPath.startsWith('os-releases/blobs/')) fullReadCallsOnLargeBlob++;
      return stores.opfs.readFile(relPath);
    },
    async moveFile(fromPath, toPath) {
      files.set(toPath, files.get(fromPath));
      files.delete(fromPath);
    },
  };

  // 1. Oversized /boot/entries stream (> MANIFEST_MAX) cancels stream and rejects!
  {
    let cancelled = false;
    const badInstaller = createOfflineInstaller({
      opfs: streamingOpfs,
      stateStore: stores.stateStore,
      cacheStore: stores.cacheStore,
      fetch: async () => new Response(new ReadableStream({
        pull(controller) { controller.enqueue(new Uint8Array(1024 * 1024)); },
        cancel() { cancelled = true; },
      }), { status: 200 }),
    });
    await assert.rejects(badInstaller.install(gen.releaseId), new RegExp(String(MANIFEST_MAX)));
    assert.equal(cancelled, true);
  }

  // 2. Normal install streams multi-chunk wasm via openWriter in <= CHUNK_SIZE_MIN writes.
  const installer = createOfflineInstaller({
    opfs: streamingOpfs,
    stateStore: stores.stateStore,
    cacheStore: stores.cacheStore,
    fetch: async url => {
      const buf = gen.routes.get(url);
      return buf ? new Response(buf, { status: 200 }) : new Response(null, { status: 404 });
    },
  });
  await installer.install(gen.releaseId);
  assert.ok(maxStreamWriteChunk > 0 && maxStreamWriteChunk <= CHUNK_SIZE_MIN, `maxStreamWriteChunk=${maxStreamWriteChunk}`);

  // 3. SW serveOpfsBlob serves a 206 Range request for the multi-chunk wasm blob by reading ONLY
  //    the covering chunk via readRange (0 full-file reads!).
  const largeEntry = [...gen.blobs.entries()].find(([, b]) => b.length > CHUNK_SIZE_MIN);
  assert.ok(largeEntry);
  const [largeSha, largeBytes] = largeEntry;
  fullReadCallsOnLargeBlob = 0;
  rangeReadBytes = 0;

  const swFetch = createOfflineSwHandler({
    stateStore: stores.stateStore,
    opfs: streamingOpfs,
    cachesApi: makeMemoryCachesApi(stores.cacheStore),
    fetchFn: async () => new Response(null, { status: 404 }),
    origin: 'https://os.test',
  });

  const rangeRes = await swFetch(new Request(`https://os.test/boot/blobs/${largeSha}`, {
    headers: { Range: `bytes=${CHUNK_SIZE_MIN}-${CHUNK_SIZE_MIN + 15}`, 'If-Range': `"${largeSha}"` },
  }));
  assert.equal(rangeRes.status, 206);
  assert.equal(rangeRes.headers.get('Content-Range'), `bytes ${CHUNK_SIZE_MIN}-${CHUNK_SIZE_MIN + 15}/${largeBytes.length}`);
  assert.deepEqual(Buffer.from(await rangeRes.arrayBuffer()), largeBytes.subarray(CHUNK_SIZE_MIN, CHUNK_SIZE_MIN + 16));
  assert.equal(fullReadCallsOnLargeBlob, 0, 'SW Range must never read full blob');
  assert.equal(rangeReadBytes, largeBytes.length - CHUNK_SIZE_MIN, 'SW Range must read only the covering tail chunk');

  // Corrupting that tail chunk in OPFS causes SW Range to fail closed with 409!
  files.get(`os-releases/blobs/${largeSha}`)[CHUNK_SIZE_MIN + 3] ^= 0xff;
  const corruptRes = await swFetch(new Request(`https://os.test/boot/blobs/${largeSha}`, {
    headers: { Range: `bytes=${CHUNK_SIZE_MIN}-${CHUNK_SIZE_MIN + 15}`, 'If-Range': `"${largeSha}"` },
  }));
  assert.equal(corruptRes.status, 409);
});

test('F2-05: Web Lock boot-attempt guard prevents concurrent tab/SW navigation from rolling back healthy upgrade', async () => {
  const keyPair = generateKeyPairSync('ed25519');
  const genA = makeSignedReleaseBundle('lock-A', { keyPair });
  const genB = makeSignedReleaseBundle('lock-B', { keyPair });
  const stores = buildMemoryStores();
  const locks = createMockWebLocks();
  let activeRoutes = genA.routes;

  const makeInstaller = () => createOfflineInstaller({
    ...stores,
    locks,
    fetch: async url => {
      const buf = activeRoutes.get(url);
      return buf ? new Response(buf, { status: 200 }) : new Response(null, { status: 404 });
    },
  });

  const tab1 = makeInstaller();
  const tab2 = makeInstaller();
  const swFetch = createOfflineSwHandler({
    stateStore: stores.stateStore,
    opfs: stores.opfs,
    cachesApi: makeMemoryCachesApi(stores.cacheStore),
    fetchFn: async () => new Response(null, { status: 404 }),
    locksApi: locks,
    origin: 'https://os.test',
  });

  // Install A -> healthy -> install B.
  await tab1.install(genA.releaseId);
  await tab1.beginOfflineBoot();
  await tab1.markBootHealthy(genA.releaseId);
  assert.equal(locks.isHeld(`${BOOT_LOCK_PREFIX}${genA.releaseId}`), false);

  activeRoutes = genB.routes;
  await tab1.install(genB.releaseId);

  // Tab 1 begins Stage 1 boot of B (holds shared Web Lock `os-boot-attempt:<B>`).
  const boot1 = await tab1.beginOfflineBoot();
  assert.equal(boot1.releaseId, genB.releaseId);
  assert.equal(boot1.rolledBack, false);
  assert.equal(locks.isHeld(`${BOOT_LOCK_PREFIX}${genB.releaseId}`), true);

  // Concurrent SW navigation while Tab 1 is still booting MUST NOT roll back to A!
  const navReq = { url: 'https://os.test/index.html', method: 'GET', mode: 'navigate', headers: new Headers() };
  const navRes = await swFetch(navReq);
  assert.equal(navRes.status, 200);
  assert.equal((await tab1.getState()).active, genB.releaseId);

  // Concurrent Tab 2 beginOfflineBoot() MUST ALSO NOT roll back to A!
  const boot2 = await tab2.beginOfflineBoot();
  assert.equal(boot2.releaseId, genB.releaseId);
  assert.equal(boot2.rolledBack, false);
  assert.equal((await tab1.getState()).active, genB.releaseId);

  // Tab 1 finishes Stage 1 boot -> markBootHealthy succeeds cleanly!
  await tab1.markBootHealthy(genB.releaseId);
  await tab2.abortOfflineBoot(genB.releaseId);
  assert.equal((await tab1.getState()).active, genB.releaseId);
  assert.equal((await tab1.getState()).activeBootVerified, true);
  assert.equal(locks.isHeld(`${BOOT_LOCK_PREFIX}${genB.releaseId}`), false);
});

test('F2-06: createBrowserOpfsStore writes atomically via temp+move with checked sync.write count and install cleans failed promotion dirs', async () => {
  // 1. Mock OPFS directory verifying temp-file write, partial sync.write loop, flush, close, atomic move, and error cleanup.
  const entries = new Map();
  let failZeroWrite = false;
  let partialStep = 3;
  const moveLog = [];

  function makeDirHandle() {
    const dir = {
      async getDirectoryHandle(name, { create = false } = {}) {
        if (!entries.has(name)) {
          if (!create) throw Object.assign(new Error('not found'), { name: 'NotFoundError' });
          entries.set(name, makeDirHandle());
        }
        return entries.get(name);
      },
      async getFileHandle(name, { create = false } = {}) {
        if (!entries.has(name)) {
          if (!create) throw Object.assign(new Error('not found'), { name: 'NotFoundError' });
          entries.set(name, { kind: 'file', data: new Uint8Array(0) });
        }
        const rec = entries.get(name);
        let curName = name;
        return {
          async createSyncAccessHandle() {
            let buf = new Uint8Array(rec.data);
            let flushed = false;
            return {
              truncate(len) { buf = buf.slice(0, len); },
              write(view, { at = 0 } = {}) {
                if (failZeroWrite) return 0;
                const take = Math.min(view.byteLength, partialStep);
                const needed = at + take;
                if (needed > buf.byteLength) {
                  const next = new Uint8Array(needed);
                  next.set(buf);
                  buf = next;
                }
                buf.set(view.subarray(0, take), at);
                return take;
              },
              flush() { flushed = true; rec.data = new Uint8Array(buf); },
              close() { if (!flushed) rec.data = new Uint8Array(buf); },
            };
          },
          async getFile() {
            return {
              size: rec.data.byteLength,
              slice: (s, e) => ({ arrayBuffer: async () => rec.data.slice(s, e).buffer }),
              arrayBuffer: async () => rec.data.slice().buffer,
            };
          },
          async move(_targetDir, newName) {
            moveLog.push({ from: curName, to: newName });
            entries.delete(curName);
            entries.set(newName, rec);
            curName = newName;
          },
        };
      },
      async removeEntry(name) {
        entries.delete(name);
      },
      entries,
    };
    return dir;
  }

  const rootDir = makeDirHandle();
  const opfs = createBrowserOpfsStore(async () => rootDir);

  // Partial writes (3 bytes at a time) loop until complete, then atomically move tmp -> target.
  const payload = new TextEncoder().encode('atomic-payload-0123456789');
  await opfs.writeFile('manifest.json', payload);
  assert.deepEqual(await opfs.readFile('manifest.json'), payload);
  assert.equal(moveLog.length, 1);
  assert.ok(moveLog[0].from.startsWith('.manifest.json.tmp-'));
  assert.equal(moveLog[0].to, 'manifest.json');
  assert.equal([...entries.keys()].some(k => k.includes('.tmp-')), false);

  // Zero-byte short write throws and cleans up temp file while leaving committed manifest.json untouched!
  failZeroWrite = true;
  await assert.rejects(opfs.writeFile('manifest.json', new Uint8Array([1, 2, 3, 4])), /short write/);
  assert.deepEqual(await opfs.readFile('manifest.json'), payload);
  assert.equal([...entries.keys()].some(k => k.includes('.tmp-')), false);

  // 2. Failed promotion in install() cleans up `os-releases/releases/<id>` when !keepCacheOnFailure!
  const keyPair = generateKeyPairSync('ed25519');
  const gen = makeSignedReleaseBundle('fail-promote', { keyPair });
  const stores = buildMemoryStores();
  const failingOpfs = {
    ...stores.opfs,
    async writeFile(relPath, bytes) {
      if (relPath === `os-releases/releases/${gen.releaseId}/signature.json`) {
        throw new Error('simulated mid-promotion crash');
      }
      return stores.opfs.writeFile(relPath, bytes);
    },
  };
  const installer = createOfflineInstaller({
    opfs: failingOpfs,
    stateStore: stores.stateStore,
    cacheStore: stores.cacheStore,
    fetch: async url => {
      const buf = gen.routes.get(url);
      return buf ? new Response(buf, { status: 200 }) : new Response(null, { status: 404 });
    },
  });
  await assert.rejects(installer.install(gen.releaseId), /simulated mid-promotion crash/);
  assert.equal(
    [...stores.opfs.files.keys()].some(k => k.startsWith(`os-releases/releases/${gen.releaseId}/`)),
    false,
    'failed promotion must clean up partial release dir',
  );
  assert.equal(stores.cacheStore.cachesMap.has(`os-release-v2:${gen.releaseId}`), false);
});

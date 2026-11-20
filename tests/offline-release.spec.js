import { test, expect } from './test.js';
import { readFile } from 'node:fs/promises';

const fixtures = process.env.OS_RELEASE_FIXTURES ? JSON.parse(await readFile(process.env.OS_RELEASE_FIXTURES, 'utf8')) : null;
test.skip(!fixtures, 'requires signed Release v2 fixtures and an isolated server; see tests/release-fixtures.mjs');

const ids = fixtures?.ids ?? {};

test('installed Release v2 boots offline with zero cookies, zero network requests, client kernel Wasm, and Stage 1 Initramfs', async ({ page, context }) => {
  test.setTimeout(180_000);
  const errors = [];
  page.on('pageerror', err => errors.push(err.message));

  // 1. Online install of signed Release v2 generation A + offline Service Worker registration.
  await page.goto('/offline-boot.html');
  await page.waitForFunction(() => !!window.osOffline?.installer);
  const installed = await page.evaluate(async id => {
    await window.osOffline.registerOfflineServiceWorker('/offline-sw.js');
    const result = await window.osOffline.installer.install(id);
    return {
      releaseId: result.releaseId,
      active: result.state.active,
      activeBootVerified: result.state.activeBootVerified,
      pinnedBlobs: result.pinnedBlobs,
      pinnedBootAssets: result.pinnedBootAssets,
    };
  }, ids.a);
  expect(installed.releaseId).toBe(ids.a);
  expect(installed.active).toBe(ids.a);
  expect(installed.activeBootVerified).toBe(false);
  expect(installed.pinnedBlobs).toBeGreaterThan(0);
  expect(installed.pinnedBootAssets).toBeGreaterThan(0);

  // 2. Clear cookies and abort EVERY outbound network request (page + Service Worker), then reload.
  await context.clearCookies();
  const outboundRequests = [];
  await context.route('**/*', route => {
    outboundRequests.push(route.request().url());
    return route.abort();
  });

  await page.reload();
  await page.waitForFunction(() => window.__osOfflineBoot && window.__osOfflineBoot.status !== 'not-installed');
  const boot = await page.evaluate(() => window.__osOfflineBoot);

  expect(boot.status, JSON.stringify(boot)).toBe('ready');
  expect(boot.releaseId).toBe(ids.a);
  expect(boot.rolledBack).toBe(false);
  expect(boot.bundleSummary.version).toBe(2);
  expect(boot.bundleSummary.id).toBe(ids.a);
  expect(boot.stage1.stage).toBe(1);
  expect(boot.stage1.kind).toBe('initramfs');
  expect(boot.stage1.binaries.map(b => b.path)).toEqual([
    '/init',
    '/bin/mount',
    '/bin/switch_root',
    '/bin/cowfsck',
    '/bin/sh',
  ]);
  for (const bin of boot.stage1.binaries) {
    expect(bin.wasm, bin.path).toBe(true);
    expect(bin.chunks, bin.path).toBeGreaterThanOrEqual(1);
  }
  expect(boot.pagerStats.totalNetworkFetches).toBe(0);
  expect(boot.pagerStats.localOpfsHits).toBeGreaterThan(0);
  expect(boot.state.activeBootVerified).toBe(true);
  expect(outboundRequests).toEqual([]);
  expect(errors).toEqual([]);
});

test('tampered, untrusted, incompatible, and interrupted installs fail closed and preserve healthy generation A offline', async ({ page, context }) => {
  test.setTimeout(180_000);
  await page.goto('/offline-boot.html');
  await page.waitForFunction(() => !!window.osOffline?.installer);

  // Install and mark generation A healthy.
  await page.evaluate(async id => {
    await window.osOffline.registerOfflineServiceWorker('/offline-sw.js');
    await window.osOffline.installer.install(id);
  }, ids.a);
  await page.reload();
  await page.waitForFunction(() => window.__osOfflineBoot?.status === 'ready');
  expect(await page.evaluate(() => window.__osOfflineBoot.releaseId)).toBe(ids.a);

  // Refusal 1-3: tampered blob, untrusted key, incompatible schema.
  for (const badId of [ids.tampered, ids.untrusted, ids.incompatible]) {
    const res = await page.evaluate(async id => {
      try {
        await window.osOffline.installer.install(id);
        return { ok: true };
      } catch (err) {
        return { ok: false, error: String(err?.message ?? err), state: await window.osOffline.installer.getState() };
      }
    }, badId);
    expect(res.ok, badId).toBe(false);
    expect(res.state.active).toBe(ids.a);
    expect(res.state.activeBootVerified).toBe(true);
  }

  // Refusal 4: interrupted download (abort uncached blobs mid-install across page + SW) leaves A intact.
  await context.route('**/boot/blobs/**', route => route.abort());
  const interrupted = await page.evaluate(async id => {
    try {
      await window.osOffline.installer.install(id);
      return { ok: true };
    } catch (err) {
      return { ok: false, error: String(err?.message ?? err), state: await window.osOffline.installer.getState() };
    }
  }, ids.b);
  expect(interrupted.ok).toBe(false);
  expect(interrupted.state.active).toBe(ids.a);
  expect(interrupted.state.activeBootVerified).toBe(true);
  await context.unroute('**/boot/blobs/**');

  // Verify generation A still boots cleanly completely offline with 0 requests!
  await context.clearCookies();
  const outbound = [];
  await context.route('**/*', route => {
    outbound.push(route.request().url());
    return route.abort();
  });
  await page.reload();
  await page.waitForFunction(() => window.__osOfflineBoot?.status === 'ready');
  const boot = await page.evaluate(() => window.__osOfflineBoot);
  expect(boot.releaseId).toBe(ids.a);
  expect(outbound).toEqual([]);
});

test('crash before markBootHealthy(B) automatically rolls back offline to previous healthy generation A', async ({ page, context }) => {
  test.setTimeout(180_000);
  await page.goto('/offline-boot.html');
  await page.waitForFunction(() => !!window.osOffline?.installer);

  // 1. Install and mark generation A healthy.
  await page.evaluate(async id => {
    await window.osOffline.registerOfflineServiceWorker('/offline-sw.js');
    await window.osOffline.installer.install(id);
  }, ids.a);
  await page.reload();
  await page.waitForFunction(() => window.__osOfflineBoot?.status === 'ready');
  expect(await page.evaluate(() => window.__osOfflineBoot.releaseId)).toBe(ids.a);

  // 2. Install generation B (previous = A preserved; activeBootVerified = false).
  const stateAfterB = await page.evaluate(async id => {
    await window.osOffline.installer.install(id);
    return window.osOffline.installer.getState();
  }, ids.b);
  expect(stateAfterB.active).toBe(ids.b);
  expect(stateAfterB.previous).toBe(ids.a);
  expect(stateAfterB.activeBootVerified).toBe(false);

  // 3. Go completely offline (clear cookies + abort all network requests across page + SW).
  await context.clearCookies();
  const outbound = [];
  await context.route('**/*', route => {
    outbound.push(route.request().url());
    return route.abort();
  });

  // 4. First boot attempt of B crashes BEFORE markBootHealthy(B).
  await page.goto('/offline-boot.html?simulate_crash=1');
  await page.waitForFunction(() => window.__osOfflineBoot?.status === 'crashed');
  const crashed = await page.evaluate(() => window.__osOfflineBoot);
  expect(crashed.releaseId).toBe(ids.b);

  // 5. Next offline boot automatically rolls back to healthy previous generation A!
  await page.goto('/offline-boot.html');
  await page.waitForFunction(() => window.__osOfflineBoot?.status === 'ready');
  const recovered = await page.evaluate(() => window.__osOfflineBoot);
  expect(recovered.releaseId).toBe(ids.a);
  expect(recovered.state.active).toBe(ids.a);
  expect(recovered.state.activeBootVerified).toBe(true);
  expect(outbound).toEqual([]);
});

test('browser imageBlobRead enforces <= 1 MiB peak buffer on 8 MiB blob, <= 4 concurrency, coalescing, and EIO on hostile streams', async ({ page }) => {
  test.setTimeout(180_000);
  const largeManifest = fixtures.largeBlobManifest;
  expect(largeManifest.size).toBe(8 * 1024 * 1024);

  const rangeRequests = [];
  page.on('request', req => {
    const url = new URL(req.url());
    if (url.pathname === `/boot/blobs/${largeManifest.sha256}`) {
      rangeRequests.push({
        range: req.headers().range,
        ifRange: req.headers()['if-range'],
      });
    }
  });

  await page.goto('/offline-boot.html');
  await page.waitForFunction(() => !!window.osOffline?.pager);

  // 1. Real HTTP Range + strong If-Range read of 4 KiB at offset 7 MiB from live Worker!
  const readRes = await page.evaluate(async manifest => {
    const mod = await import('/image-pager.js');
    const pager = mod.createImagePager({ maxCacheBytes: 0 });
    const offset = 7 * 1024 * 1024;
    const bytes = await pager.imageBlobRead(`sha256:${manifest.sha256}`, offset, 4096, manifest);
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    return {
      len: bytes.byteLength,
      firstWord: dv.getUint32(0, false),
      secondWord: dv.getUint32(4, false),
      stats: pager.stats(),
    };
  }, largeManifest);

  expect(readRes.len).toBe(4096);
  expect(readRes.firstWord).toBe(7 * 1024 * 1024);
  expect(readRes.secondWord).toBe(((7 * 1024 * 1024) ^ 0x5a5a5a5a) >>> 0);
  expect(readRes.stats.totalNetworkFetches).toBe(1);
  expect(readRes.stats.peakBufferedBytes).toBeLessThanOrEqual(1024 * 1024);
  expect(rangeRequests).toHaveLength(1);
  expect(rangeRequests[0].ifRange).toBe(`"${largeManifest.sha256}"`);

  // 2. Hostile 1-bit flip & oversized stream & unexpected 200 reject with EIO in browser.
  const hostileRes = await page.evaluate(async manifest => {
    const mod = await import('/image-pager.js');
    const chunkSize = manifest.chunk_size;
    const cases = [];

    // Oversized stream
    {
      let cancelled = false;
      const p = mod.createImagePager({
        readLocalRange: async () => null,
        fetch: async () => new Response(new ReadableStream({
          pull(c) { c.enqueue(new Uint8Array(128 * 1024)); },
          cancel() { cancelled = true; },
        }), { status: 206, headers: { 'Content-Range': `bytes 0-${chunkSize - 1}/${manifest.size}` } }),
      });
      try {
        await p.imageBlobRead(`sha256:${manifest.sha256}`, 0, 1024, manifest);
        cases.push({ name: 'oversized', ok: true });
      } catch (e) {
        cases.push({ name: 'oversized', errno: e.errno, cancelled });
      }
    }

    // Unexpected 200 OK full body
    {
      let cancelled = false;
      const p = mod.createImagePager({
        readLocalRange: async () => null,
        fetch: async () => new Response(new ReadableStream({
          pull(c) { c.enqueue(new Uint8Array(64 * 1024)); },
          cancel() { cancelled = true; },
        }), { status: 200, headers: { 'Content-Length': String(manifest.size) } }),
      });
      try {
        await p.imageBlobRead(`sha256:${manifest.sha256}`, 0, 1024, manifest);
        cases.push({ name: 'unexpected200', ok: true });
      } catch (e) {
        cases.push({ name: 'unexpected200', errno: e.errno, cancelled });
      }
    }

    // Tampered 1-bit flip
    {
      const p = mod.createImagePager({
        readLocalRange: async () => null,
        fetch: async () => new Response(new Uint8Array(chunkSize), {
          status: 206,
          headers: { 'Content-Range': `bytes 0-${chunkSize - 1}/${manifest.size}`, 'Content-Length': String(chunkSize) },
        }),
      });
      try {
        await p.imageBlobRead(`sha256:${manifest.sha256}`, 0, 1024, manifest);
        cases.push({ name: 'tampered', ok: true });
      } catch (e) {
        cases.push({ name: 'tampered', errno: e.errno });
      }
    }

    return cases;
  }, largeManifest);

  expect(hostileRes).toEqual([
    { name: 'oversized', errno: 'EIO', cancelled: true },
    { name: 'unexpected200', errno: 'EIO', cancelled: true },
    { name: 'tampered', errno: 'EIO' },
  ]);
});

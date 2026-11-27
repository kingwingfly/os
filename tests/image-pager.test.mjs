import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  CHUNK_SIZE_DEFAULT,
  CHUNK_SIZE_MAX,
  CHUNK_SIZE_MIN,
  MAX_CONCURRENT_FETCHES,
  createImagePager,
} from '../web/kernel/image-pager.js';

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

function makeBlob(size, chunkSize = CHUNK_SIZE_DEFAULT) {
  const data = new Uint8Array(size);
  for (let i = 0; i < size; i++) {
    data[i] = (i * 31 + (i >> 8) * 17) & 0xff;
  }
  const chunks = [];
  for (let off = 0; off < size; off += chunkSize) {
    chunks.push(sha256(data.subarray(off, Math.min(size, off + chunkSize))));
  }
  const manifest = {
    sha256: sha256(data),
    size,
    chunk_size: chunkSize,
    chunks,
  };
  return { data, manifest };
}

function streamFromPieces(pieces, { onCancel, delayMs = 0 } = {}) {
  let index = 0;
  return new ReadableStream({
    async pull(controller) {
      if (delayMs > 0) await new Promise(r => setTimeout(r, delayMs));
      if (index >= pieces.length) {
        controller.close();
        return;
      }
      controller.enqueue(pieces[index++]);
    },
    cancel(reason) {
      onCancel?.(reason);
    },
  });
}

function slicePieces(bytes, pieceSize = 64 * 1024) {
  const out = [];
  for (let off = 0; off < bytes.length; off += pieceSize) {
    out.push(bytes.slice(off, Math.min(bytes.length, off + pieceSize)));
  }
  return out;
}

test('4 KiB slice at offset 7 MiB of an 8 MiB blob issues 1 Range+If-Range request and stays <= 1 MiB peak buffered', async () => {
  const SIZE = 8 * 1024 * 1024;
  for (const chunkSize of [CHUNK_SIZE_DEFAULT, CHUNK_SIZE_MAX]) {
    const { data, manifest } = makeBlob(SIZE, chunkSize);
    const requests = [];
    const pager = createImagePager({
      readLocalRange: async () => null,
      maxCacheBytes: 0,
      fetch: async (url, init) => {
        const range = init.headers.Range;
        const ifRange = init.headers['If-Range'];
        requests.push({ url, range, ifRange });
        const [, s, e] = /^bytes=(\d+)-(\d+)$/.exec(range);
        const start = Number(s);
        const end = Number(e);
        const slice = data.subarray(start, end + 1);
        return new Response(streamFromPieces(slicePieces(slice)), {
          status: 206,
          headers: {
            'Content-Range': `bytes ${start}-${end}/${SIZE}`,
            'Content-Length': String(slice.byteLength),
            ETag: `"${manifest.sha256}"`,
          },
        });
      },
    });

    const offset = 7 * 1024 * 1024;
    const len = 4096;
    const got = await pager.imageBlobRead(`sha256:${manifest.sha256}`, offset, len, manifest);
    assert.deepEqual(got, data.subarray(offset, offset + len));
    assert.equal(requests.length, 1);
    assert.equal(requests[0].url, `/boot/blobs/${manifest.sha256}`);
    assert.equal(requests[0].ifRange, `"${manifest.sha256}"`);
    const stats = pager.stats();
    assert.equal(stats.totalNetworkFetches, 1);
    assert.ok(stats.peakBufferedBytes <= CHUNK_SIZE_MAX, `peakBufferedBytes=${stats.peakBufferedBytes} exceeded 1 MiB`);
    assert.equal(stats.peakBufferedBytes, chunkSize);
    assert.equal(stats.currentBufferedBytes, 0);
  }
});

test('cross-chunk read splices multiple verified chunks accurately', async () => {
  const { data, manifest } = makeBlob(CHUNK_SIZE_MIN * 3 + 500, CHUNK_SIZE_MIN);
  const pager = createImagePager({
    readLocalRange: async () => null,
    fetch: async (_url, init) => {
      const [, s, e] = /^bytes=(\d+)-(\d+)$/.exec(init.headers.Range);
      const start = Number(s);
      const end = Number(e);
      const slice = data.subarray(start, end + 1);
      return new Response(streamFromPieces(slicePieces(slice, 16384)), {
        status: 206,
        headers: {
          'Content-Range': `bytes ${start}-${end}/${data.byteLength}`,
          'Content-Length': String(slice.byteLength),
        },
      });
    },
  });

  const offset = CHUNK_SIZE_MIN - 1024;
  const len = 4096;
  const got = await pager.imageBlobRead(`sha256:${manifest.sha256}`, offset, len, manifest);
  assert.deepEqual(got, data.subarray(offset, offset + len));
  assert.equal(pager.stats().totalNetworkFetches, 2);
});

test('16 parallel reads enforce <= 4 concurrency and duplicate chunk reads coalesce to 1 fetch', async () => {
  const CHUNK_COUNT = 16;
  const { data, manifest } = makeBlob(CHUNK_SIZE_MIN * CHUNK_COUNT, CHUNK_SIZE_MIN);
  let active = 0;
  let observedPeak = 0;
  const pager = createImagePager({
    readLocalRange: async () => null,
    maxCacheBytes: 0,
    fetch: async (_url, init) => {
      active++;
      observedPeak = Math.max(observedPeak, active);
      try {
        await new Promise(r => setTimeout(r, 15));
        const [, s, e] = /^bytes=(\d+)-(\d+)$/.exec(init.headers.Range);
        const start = Number(s);
        const end = Number(e);
        const slice = data.subarray(start, end + 1);
        return new Response(streamFromPieces([slice]), {
          status: 206,
          headers: {
            'Content-Range': `bytes ${start}-${end}/${data.byteLength}`,
            'Content-Length': String(slice.byteLength),
          },
        });
      } finally {
        active--;
      }
    },
  });

  // 16 distinct chunks in parallel -> concurrency strictly <= 4.
  const distinctResults = await Promise.all(
    Array.from({ length: CHUNK_COUNT }, (_, idx) =>
      pager.imageBlobRead(`sha256:${manifest.sha256}`, idx * CHUNK_SIZE_MIN + 7, 128, manifest),
    ),
  );
  for (let idx = 0; idx < CHUNK_COUNT; idx++) {
    const start = idx * CHUNK_SIZE_MIN + 7;
    assert.deepEqual(distinctResults[idx], data.subarray(start, start + 128));
  }
  assert.ok(observedPeak <= MAX_CONCURRENT_FETCHES, `observedPeak=${observedPeak}`);
  assert.ok(pager.stats().peakConcurrentFetches <= MAX_CONCURRENT_FETCHES);
  assert.equal(pager.stats().totalNetworkFetches, CHUNK_COUNT);

  // 12 concurrent duplicate reads of chunk 3 -> coalesced into 1 network fetch!
  const beforeFetches = pager.stats().totalNetworkFetches;
  const dupResults = await Promise.all(
    Array.from({ length: 12 }, (_, i) =>
      pager.imageBlobRead(`sha256:${manifest.sha256}`, 3 * CHUNK_SIZE_MIN + i * 16, 64, manifest),
    ),
  );
  for (let i = 0; i < 12; i++) {
    const start = 3 * CHUNK_SIZE_MIN + i * 16;
    assert.deepEqual(dupResults[i], data.subarray(start, start + 64));
  }
  assert.equal(pager.stats().totalNetworkFetches, beforeFetches + 1);
  assert.equal(pager.stats().coalescedHits, 11);
});

test('OPFS-first local read succeeds with zero network requests and rejects tampered local chunk with EIO', async () => {
  const { data, manifest } = makeBlob(CHUNK_SIZE_MIN * 2, CHUNK_SIZE_MIN);
  let networkCalls = 0;
  let corruptLocal = false;

  const pager = createImagePager({
    maxCacheBytes: 0,
    readLocalRange: async (sha, start, endExclusive) => {
      assert.equal(sha, manifest.sha256);
      const copy = data.slice(start, endExclusive);
      if (corruptLocal) copy[10] ^= 0xff;
      return copy;
    },
    fetch: async () => {
      networkCalls++;
      throw new Error('network must not be called when OPFS has verified blob');
    },
  });

  const got = await pager.imageBlobRead(`sha256:${manifest.sha256}`, CHUNK_SIZE_MIN + 32, 256, manifest);
  assert.deepEqual(got, data.subarray(CHUNK_SIZE_MIN + 32, CHUNK_SIZE_MIN + 288));
  assert.equal(networkCalls, 0);
  assert.equal(pager.stats().localOpfsHits, 1);

  corruptLocal = true;
  await assert.rejects(
    pager.imageBlobRead(`sha256:${manifest.sha256}`, CHUNK_SIZE_MIN + 32, 256, manifest),
    err => err.errno === 'EIO',
  );
  assert.equal(networkCalls, 0);
});

test('hostile streams (oversized, wrong Content-Range, unexpected 200, truncated, 1-bit flip) cancel stream and reject EIO before exposing bytes', async () => {
  const { data, manifest } = makeBlob(CHUNK_SIZE_MIN * 4, CHUNK_SIZE_MIN);

  // 1. Oversized stream (> chunk_size) cancels stream mid-flight and rejects EIO.
  {
    let cancelled = false;
    let pushedPieces = 0;
    const pager = createImagePager({
      readLocalRange: async () => null,
      fetch: async () => {
        const body = new ReadableStream({
          pull(controller) {
            pushedPieces++;
            // Stream 32 KiB chunks; the 3rd piece exceeds 64 KiB expected chunk length!
            controller.enqueue(new Uint8Array(32 * 1024));
          },
          cancel() {
            cancelled = true;
          },
        });
        return new Response(body, {
          status: 206,
          headers: {
            'Content-Range': `bytes 0-${CHUNK_SIZE_MIN - 1}/${data.byteLength}`,
          },
        });
      },
    });
    await assert.rejects(
      pager.imageBlobRead(`sha256:${manifest.sha256}`, 0, 1024, manifest),
      err => err.errno === 'EIO',
    );
    assert.equal(cancelled, true, 'oversized stream must be cancelled mid-flight');
    assert.ok(pushedPieces <= 4, `stream must stop promptly, pushedPieces=${pushedPieces}`);
    assert.equal(pager.stats().currentBufferedBytes, 0);
  }

  // 2. Wrong Content-Range cancels stream and rejects EIO.
  for (const badRange of [
    `bytes 1-${CHUNK_SIZE_MIN}/${data.byteLength}`,
    `bytes 0-${CHUNK_SIZE_MIN - 1}/${data.byteLength + 1}`,
    'invalid',
    '',
  ]) {
    let cancelled = false;
    const pager = createImagePager({
      readLocalRange: async () => null,
      fetch: async () => new Response(
        streamFromPieces([data.slice(0, CHUNK_SIZE_MIN)], { onCancel: () => { cancelled = true; } }),
        {
          status: 206,
          headers: badRange ? { 'Content-Range': badRange } : {},
        },
      ),
    });
    await assert.rejects(
      pager.imageBlobRead(`sha256:${manifest.sha256}`, 0, 512, manifest),
      err => err.errno === 'EIO',
    );
    assert.equal(cancelled, true, `stream for bad Content-Range "${badRange}" must be cancelled`);
  }

  // 3. Unexpected 200 OK full-body response on a multi-chunk blob cancels stream and rejects EIO.
  {
    let cancelled = false;
    const pager = createImagePager({
      readLocalRange: async () => null,
      fetch: async () => new Response(
        streamFromPieces([data.slice(0, CHUNK_SIZE_MIN)], { onCancel: () => { cancelled = true; } }),
        { status: 200, headers: { 'Content-Length': String(data.byteLength) } },
      ),
    });
    await assert.rejects(
      pager.imageBlobRead(`sha256:${manifest.sha256}`, 0, 512, manifest),
      err => err.errno === 'EIO',
    );
    assert.equal(cancelled, true, 'unexpected 200 full-body response must be cancelled');
  }

  // 4. Truncated stream rejects EIO.
  {
    const pager = createImagePager({
      readLocalRange: async () => null,
      fetch: async () => new Response(
        streamFromPieces([data.slice(0, CHUNK_SIZE_MIN - 10)]),
        {
          status: 206,
          headers: { 'Content-Range': `bytes 0-${CHUNK_SIZE_MIN - 1}/${data.byteLength}` },
        },
      ),
    });
    await assert.rejects(
      pager.imageBlobRead(`sha256:${manifest.sha256}`, 0, 512, manifest),
      err => err.errno === 'EIO',
    );
  }

  // 5. 1-bit flip in chunk payload rejects EIO before exposing any byte.
  {
    const tampered = data.slice(0, CHUNK_SIZE_MIN);
    tampered[CHUNK_SIZE_MIN - 1] ^= 0x01;
    const pager = createImagePager({
      readLocalRange: async () => null,
      fetch: async () => new Response(
        streamFromPieces([tampered]),
        {
          status: 206,
          headers: {
            'Content-Range': `bytes 0-${CHUNK_SIZE_MIN - 1}/${data.byteLength}`,
            'Content-Length': String(CHUNK_SIZE_MIN),
          },
        },
      ),
    });
    await assert.rejects(
      pager.imageBlobRead(`sha256:${manifest.sha256}`, 0, 16, manifest),
      err => err.errno === 'EIO',
    );
  }

  // 6. 404 rejects ENOENT.
  {
    const pager = createImagePager({
      readLocalRange: async () => null,
      fetch: async () => new Response(null, { status: 404 }),
    });
    await assert.rejects(
      pager.imageBlobRead(`sha256:${manifest.sha256}`, 0, 16, manifest),
      err => err.errno === 'ENOENT',
    );
  }
});

test('single-chunk blob accepts 200 OK after verifying exact length and SHA-256', async () => {
  const { data, manifest } = makeBlob(4096, CHUNK_SIZE_DEFAULT);
  const pager = createImagePager({
    readLocalRange: async () => null,
    fetch: async () => new Response(streamFromPieces([data]), {
      status: 200,
      headers: { 'Content-Length': String(data.byteLength) },
    }),
  });
  const got = await pager.imageBlobRead(`sha256:${manifest.sha256}`, 100, 200, manifest);
  assert.deepEqual(got, data.subarray(100, 300));
});

test('two manifests sharing one blob sha256 with different chunk_size never cross-contaminate cache', async () => {
  const SIZE = CHUNK_SIZE_DEFAULT * 2 + 1024;
  const { data, manifest: manifest64k } = makeBlob(SIZE, CHUNK_SIZE_MIN);
  // Build second manifest for the exact same blob bytes using 256 KiB chunk_size.
  const chunks256k = [];
  for (let off = 0; off < SIZE; off += CHUNK_SIZE_DEFAULT) {
    chunks256k.push(sha256(data.subarray(off, Math.min(SIZE, off + CHUNK_SIZE_DEFAULT))));
  }
  const manifest256k = {
    sha256: manifest64k.sha256,
    size: SIZE,
    chunk_size: CHUNK_SIZE_DEFAULT,
    chunks: chunks256k,
  };

  const pager = createImagePager({
    readLocalRange: async () => null,
    maxCacheBytes: 4 * 1024 * 1024,
    fetch: async (_url, init) => {
      const [, s, e] = /^bytes=(\d+)-(\d+)$/.exec(init.headers.Range);
      const start = Number(s);
      const end = Number(e);
      const slice = data.subarray(start, end + 1);
      return new Response(streamFromPieces([slice]), {
        status: 206,
        headers: {
          'Content-Range': `bytes ${start}-${end}/${SIZE}`,
          'Content-Length': String(slice.byteLength),
        },
      });
    },
  });

  // Populate cache with chunk index 1 of 64 KiB manifest (file offset 64 KiB).
  const slice64k = await pager.imageBlobRead(`sha256:${manifest64k.sha256}`, CHUNK_SIZE_MIN + 16, 64, manifest64k);
  assert.deepEqual(slice64k, data.subarray(CHUNK_SIZE_MIN + 16, CHUNK_SIZE_MIN + 80));

  // Now read chunk index 1 of 256 KiB manifest (file offset 256 KiB) -> MUST NOT return 64 KiB cached bytes!
  const slice256k = await pager.imageBlobRead(`sha256:${manifest256k.sha256}`, CHUNK_SIZE_DEFAULT + 16, 64, manifest256k);
  assert.deepEqual(slice256k, data.subarray(CHUNK_SIZE_DEFAULT + 16, CHUNK_SIZE_DEFAULT + 80));
  assert.equal(pager.stats().totalNetworkFetches, 2);

  // Reading the same chunk again under manifest256k hits cache cleanly.
  const cachedAgain = await pager.imageBlobRead(`sha256:${manifest256k.sha256}`, CHUNK_SIZE_DEFAULT + 32, 64, manifest256k);
  assert.deepEqual(cachedAgain, data.subarray(CHUNK_SIZE_DEFAULT + 32, CHUNK_SIZE_DEFAULT + 96));
  assert.equal(pager.stats().totalNetworkFetches, 2);
  assert.equal(pager.stats().cacheHits, 1);
});

test('unmanifested sha256 reads are refused (EINVAL) and unmanifested asset 206 validates Content-Range strictly', async () => {
  const { data, manifest } = makeBlob(CHUNK_SIZE_MIN, CHUNK_SIZE_MIN);

  // 1. Unmanifested content-addressed sha256 read fails closed even when OPFS has bytes.
  {
    let localCalls = 0;
    const pager = createImagePager({
      readLocalRange: async () => {
        localCalls++;
        return data.slice(0, 16);
      },
      fetch: async () => { throw new Error('must not fetch'); },
    });
    for (const id of [`sha256:${manifest.sha256}`, manifest.sha256]) {
      await assert.rejects(
        pager.imageBlobRead(id, 0, 16, null),
        err => err.errno === 'EINVAL',
      );
    }
    assert.equal(localCalls, 0);
  }

  // 2. Unmanifested asset path (`/usr/bin/foo.wasm`) rejects wrong/missing HTTP 206 Content-Range.
  const assetBytes = new Uint8Array(4096);
  for (let i = 0; i < assetBytes.length; i++) assetBytes[i] = i & 0xff;

  for (const badRange of [
    '',
    'invalid',
    'bytes 0-15/4096',     // wrong start offset (requested 100..115)
    'bytes 100-120/4096',  // exceeds requested end (115)
    'bytes 100-110/4096',  // short range not at EOF
  ]) {
    let cancelled = false;
    const pager = createImagePager({
      fetch: async () => new Response(
        streamFromPieces([assetBytes.slice(100, 116)], { onCancel: () => { cancelled = true; } }),
        {
          status: 206,
          headers: badRange ? { 'Content-Range': badRange } : {},
        },
      ),
    });
    await assert.rejects(
      pager.imageBlobRead('/usr/bin/foo.wasm', 100, 16, null),
      err => err.errno === 'EIO',
    );
    assert.equal(cancelled, true, `bad Content-Range "${badRange}" must cancel stream`);
  }

  // 3. Valid HTTP 206 Content-Range on unmanifested asset succeeds (including EOF clamp).
  {
    const pager = createImagePager({
      fetch: async (_url, init) => {
        const [, s, e] = /^bytes=(\d+)-(\d+)$/.exec(init.headers.Range);
        const start = Number(s);
        const end = Math.min(Number(e), assetBytes.length - 1);
        const slice = assetBytes.subarray(start, end + 1);
        return new Response(streamFromPieces([slice]), {
          status: 206,
          headers: {
            'Content-Range': `bytes ${start}-${end}/${assetBytes.length}`,
            'Content-Length': String(slice.byteLength),
          },
        });
      },
    });
    const exact = await pager.imageBlobRead('/usr/bin/foo.wasm', 100, 16, null);
    assert.deepEqual(exact, assetBytes.subarray(100, 116));
    const eofClamped = await pager.imageBlobRead('/usr/bin/foo.wasm', 4090, 32, null);
    assert.deepEqual(eofClamped, assetBytes.subarray(4090, 4096));
  }
});

test('unmanifested GUI JSON bundles cache boundedly for offline reads and reject oversized streams', async () => {
  const bundle = new TextEncoder().encode(JSON.stringify({ html: '<div>ok</div>', css: '', js: '' }));
  let offline = false;
  let fetches = 0;
  const pager = createImagePager({
    fetch: async () => {
      if (offline) throw new Error('offline');
      fetches++;
      return new Response(streamFromPieces(slicePieces(bundle, 16)), {
        status: 200,
        headers: { 'Content-Length': String(bundle.byteLength) },
      });
    },
  });

  // Warm with a partial read (e.g. `cat` chunk), then go offline and read with a different slice size.
  const part1 = await pager.imageBlobRead('/usr/share/gui/mounts/mounts.json', 0, 12, null);
  assert.deepEqual(part1, bundle.subarray(0, 12));
  const cfgPart = await pager.imageBlobRead('/usr/share/os/config.json', 0, 10, null);
  assert.deepEqual(cfgPart, bundle.subarray(0, 10));
  offline = true;
  const full = await pager.imageBlobRead('/usr/share/gui/mounts/mounts.json', 0, bundle.byteLength + 100, null);
  assert.deepEqual(full, bundle);
  const cfgFull = await pager.imageBlobRead('/usr/share/os/config.json', 0, bundle.byteLength + 100, null);
  assert.deepEqual(cfgFull, bundle);
  const eof = await pager.imageBlobRead('/usr/share/gui/mounts/mounts.json', bundle.byteLength, 32, null);
  assert.equal(eof.byteLength, 0);
  assert.equal(fetches, 2);
  assert.equal(pager.stats().cacheHits, 3);

  // 1.25 MiB GUI bundle (e.g. CodeMirror editor.json <= 2 MiB MAX_BUNDLE) caches boundedly for offline reads.
  const largePayload = new Uint8Array(1280 * 1024);
  largePayload.fill(0x61);
  let largeOffline = false;
  let largeFetches = 0;
  const largePager = createImagePager({
    fetch: async () => {
      if (largeOffline) throw new Error('offline');
      largeFetches++;
      return new Response(streamFromPieces(slicePieces(largePayload, 64 * 1024)), {
        status: 200,
        headers: { 'Content-Length': String(largePayload.byteLength) },
      });
    },
  });
  const head = await largePager.imageBlobRead('/usr/share/gui/editor/editor.json', 0, 1024, null);
  assert.equal(head.byteLength, 1024);
  largeOffline = true;
  const tail = await largePager.imageBlobRead('/usr/share/gui/editor/editor.json', largePayload.byteLength - 512, 1024, null);
  assert.equal(tail.byteLength, 512);
  assert.equal(largeFetches, 1);

  // Oversized GUI bundle (> 2 MiB MAX_BUNDLE) cancels stream and rejects EIO.
  let cancelled = false;
  const hostile = createImagePager({
    fetch: async () => new Response(
      new ReadableStream({
        pull(controller) { controller.enqueue(new Uint8Array(256 * 1024)); },
        cancel() { cancelled = true; },
      }),
      { status: 200 },
    ),
  });
  await assert.rejects(
    hostile.imageBlobRead('/usr/share/gui/mounts/mounts.json', 0, 64, null),
    err => err.errno === 'EIO',
  );
  assert.equal(cancelled, true);
  assert.equal(hostile.stats().currentBufferedBytes, 0);
});

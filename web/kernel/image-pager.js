import { asset } from '../release.js';

export const CHUNK_SIZE_MIN = 64 * 1024;
export const CHUNK_SIZE_DEFAULT = 256 * 1024;
export const CHUNK_SIZE_MAX = 1024 * 1024;
export const MAX_CONCURRENT_FETCHES = 4;
const DEFAULT_MAX_CACHE_BYTES = 4 * 1024 * 1024;

const HEX64 = /^[a-f0-9]{64}$/;
const CONTENT_RANGE_RE = /^bytes (\d+)-(\d+)\/(\d+)$/;
const DIGITS_RE = /^\d+$/;

function errnoError(errno, detail) {
  const err = new Error(detail || errno);
  err.errno = errno;
  err.detail = detail || errno;
  return err;
}

function toHex(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}

function isPowerOfTwo(n) {
  return Number.isInteger(n) && n > 0 && (n & (n - 1)) === 0;
}

function validateManifest(manifest) {
  if (!manifest || typeof manifest !== 'object') {
    throw errnoError('EINVAL', 'invalid chunk manifest');
  }
  const sha256 = manifest.sha256;
  const size = Number(manifest.size);
  const chunkSize = Number(manifest.chunk_size ?? manifest.chunkSize);
  const chunks = manifest.chunks;
  if (typeof sha256 !== 'string' || !HEX64.test(sha256)) {
    throw errnoError('EINVAL', 'invalid manifest sha256');
  }
  if (!Number.isSafeInteger(size) || size < 0) {
    throw errnoError('EINVAL', 'invalid manifest size');
  }
  if (!isPowerOfTwo(chunkSize) || chunkSize < CHUNK_SIZE_MIN || chunkSize > CHUNK_SIZE_MAX) {
    throw errnoError('EINVAL', 'invalid manifest chunk_size');
  }
  const expectedCount = size === 0 ? 0 : Math.ceil(size / chunkSize);
  if (!Array.isArray(chunks) || chunks.length !== expectedCount) {
    throw errnoError('EINVAL', 'chunk digest list length mismatch');
  }
  for (let i = 0; i < chunks.length; i++) {
    if (typeof chunks[i] !== 'string' || !HEX64.test(chunks[i])) {
      throw errnoError('EINVAL', `invalid chunk digest at index ${i}`);
    }
  }
  if (chunks.length === 1 && chunks[0] !== sha256) {
    throw errnoError('EINVAL', 'single-chunk digest must match file sha256');
  }
  return { sha256, size, chunkSize, chunks };
}

function defaultResolveUrl(blobId) {
  if (typeof blobId !== 'string' || !blobId) {
    throw errnoError('EINVAL', 'missing blobId');
  }
  if (blobId.startsWith('sha256:')) {
    const hash = blobId.slice(7);
    if (!HEX64.test(hash)) throw errnoError('EINVAL', 'invalid sha256 blobId');
    return `/boot/blobs/${hash}`;
  }
  if (HEX64.test(blobId)) {
    return `/boot/blobs/${blobId}`;
  }
  return asset(blobId.startsWith('/') ? blobId : `/${blobId}`);
}

export async function readOpfsBlobRange(sha256, start, endExclusive, rootProvider) {
  if (!HEX64.test(sha256)) return null;
  let root;
  try {
    root = rootProvider ? await rootProvider() : await globalThis.navigator?.storage?.getDirectory?.();
  } catch {
    return null;
  }
  if (!root) return null;
  try {
    const releasesDir = await root.getDirectoryHandle('os-releases');
    const blobsDir = await releasesDir.getDirectoryHandle('blobs');
    const fileHandle = await blobsDir.getFileHandle(sha256);
    const file = await fileHandle.getFile();
    const slice = file.slice(start, endExclusive);
    return new Uint8Array(await slice.arrayBuffer());
  } catch (err) {
    if (err?.name === 'NotFoundError') return null;
    return null;
  }
}

async function cancelBody(response, reason) {
  try {
    await response?.body?.cancel?.(reason);
  } catch {
    /* ignore cancel errors on already-closed streams */
  }
}

/**
 * Creates a bounded, streaming, range-verified Release v2 image pager:
 * - OPFS-first local read (`/os-releases/blobs/<sha256>`) with ZERO network requests when installed.
 * - On remote miss: bounded `Range` + strong `If-Range: "<sha256>"` fetch per `<= 1 MiB` chunk.
 * - Max 4 concurrent network fetches via shared semaphore.
 * - In-flight `(sha256, chunkIdx)` promise coalescing.
 * - Streaming byte counter via `response.body.getReader()` aborting oversized, truncated,
 *   mismatched `Content-Range`, or unexpected `200 OK` full-body responses with `EIO`.
 * - SHA-256 verification of every chunk BEFORE exposing any byte.
 */
export function createImagePager(options = {}) {
  const fetchFn = options.fetch ?? ((...args) => globalThis.fetch(...args));
  const cryptoApi = options.crypto ?? globalThis.crypto;
  const resolveUrl = options.resolveUrl ?? defaultResolveUrl;
  const readLocalRange = options.readLocalRange
    ?? ((sha256, start, endExclusive) => readOpfsBlobRange(sha256, start, endExclusive, options.opfsRoot));
  const maxConcurrent = options.maxConcurrent ?? MAX_CONCURRENT_FETCHES;
  const maxCacheBytes = options.maxCacheBytes ?? DEFAULT_MAX_CACHE_BYTES;

  // Bounded LRU clean chunk cache (key -> Uint8Array).
  const cache = new Map();
  let cacheBytes = 0;

  // In-flight chunk fetches keyed by `${sha256}:${chunkIdx}`.
  const inFlight = new Map();

  // Concurrency semaphore for network fetches (strictly <= maxConcurrent).
  let activeFetches = 0;
  const waiters = [];

  // Diagnostics / telemetry for bounded-memory and concurrency assertions.
  let peakConcurrentFetches = 0;
  let totalNetworkFetches = 0;
  let coalescedHits = 0;
  let localOpfsHits = 0;
  let cacheHits = 0;
  let currentBufferedBytes = 0;
  let peakBufferedBytes = 0;

  async function sha256Hex(bytes) {
    const subtle = cryptoApi?.subtle ?? globalThis.crypto?.subtle;
    if (!subtle) throw errnoError('EIO', 'WebCrypto SHA-256 unavailable');
    return toHex(await subtle.digest('SHA-256', bytes));
  }

  function acquireSlot() {
    if (activeFetches < maxConcurrent) {
      activeFetches++;
      if (activeFetches > peakConcurrentFetches) peakConcurrentFetches = activeFetches;
      return Promise.resolve();
    }
    return new Promise(resolve => {
      waiters.push(() => {
        activeFetches++;
        if (activeFetches > peakConcurrentFetches) peakConcurrentFetches = activeFetches;
        resolve();
      });
    });
  }

  function releaseSlot() {
    activeFetches--;
    if (waiters.length > 0) {
      const next = waiters.shift();
      next();
    }
  }

  function cacheGet(key) {
    const hit = cache.get(key);
    if (!hit) return null;
    // Refresh LRU order.
    cache.delete(key);
    cache.set(key, hit);
    return hit;
  }

  function cacheDelete(key) {
    const existing = cache.get(key);
    if (!existing) return;
    cacheBytes -= existing.byteLength;
    cache.delete(key);
  }

  function cachePut(key, bytes) {
    if (maxCacheBytes <= 0 || bytes.byteLength > maxCacheBytes) return;
    if (cache.has(key)) {
      cacheBytes -= cache.get(key).byteLength;
      cache.delete(key);
    }
    while (cacheBytes + bytes.byteLength > maxCacheBytes && cache.size > 0) {
      const oldestKey = cache.keys().next().value;
      cacheBytes -= cache.get(oldestKey).byteLength;
      cache.delete(oldestKey);
    }
    cache.set(key, bytes);
    cacheBytes += bytes.byteLength;
  }

  async function fetchVerifiedChunkRemote(url, sha256, chunkIdx, cStart, cEnd, totalSize, chunkSize, expectedChunkSha) {
    const expectedLen = cEnd - cStart + 1;
    await acquireSlot();
    const controller = new AbortController();
    let trackedBytes = 0;
    try {
      totalNetworkFetches++;
      const headers = {
        Range: `bytes=${cStart}-${cEnd}`,
        'If-Range': `"${sha256}"`,
      };
      const response = await fetchFn(url, { headers, cache: 'no-store', signal: controller.signal });
      if (response.status === 404) {
        await cancelBody(response, 'not found');
        throw errnoError('ENOENT', `blob not found: ${url}`);
      }
      if (response.status === 206) {
        const cr = response.headers?.get?.('Content-Range') ?? '';
        const match = CONTENT_RANGE_RE.exec(cr.trim());
        if (!match) {
          await cancelBody(response, 'missing Content-Range');
          controller.abort();
          throw errnoError('EIO', `invalid Content-Range: ${cr}`);
        }
        const rStart = Number(match[1]);
        const rEnd = Number(match[2]);
        const rTotal = Number(match[3]);
        if (rStart !== cStart || rEnd !== cEnd || rTotal !== totalSize) {
          await cancelBody(response, 'Content-Range mismatch');
          controller.abort();
          throw errnoError('EIO', `Content-Range mismatch: got ${cr}, expected bytes ${cStart}-${cEnd}/${totalSize}`);
        }
      } else if (response.status === 200) {
        // Only legal when the entire blob fits in this single chunk.
        const isSingleFullChunk = cStart === 0 && totalSize === expectedLen && totalSize <= chunkSize;
        if (!isSingleFullChunk) {
          await cancelBody(response, 'unexpected 200 full body');
          controller.abort();
          throw errnoError('EIO', 'unexpected 200 OK full-body response for multi-chunk range fetch');
        }
      } else {
        await cancelBody(response, `HTTP ${response.status}`);
        controller.abort();
        throw errnoError('EIO', `unexpected HTTP status ${response.status}`);
      }

      const contentLength = response.headers?.get?.('Content-Length');
      if (contentLength !== null && contentLength !== undefined && contentLength !== '') {
        if (!DIGITS_RE.test(contentLength.trim()) || Number(contentLength) !== expectedLen) {
          await cancelBody(response, 'Content-Length mismatch');
          controller.abort();
          throw errnoError('EIO', `Content-Length mismatch: got ${contentLength}, expected ${expectedLen}`);
        }
      }

      if (!response.body || typeof response.body.getReader !== 'function') {
        controller.abort();
        throw errnoError('EIO', 'streaming response body is required');
      }

      const chunkBuf = new Uint8Array(expectedLen);
      trackedBytes = expectedLen;
      currentBufferedBytes += trackedBytes;
      if (currentBufferedBytes > peakBufferedBytes) peakBufferedBytes = currentBufferedBytes;

      const reader = response.body.getReader();
      let received = 0;
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (!value || value.byteLength === 0) continue;
          const piece = value instanceof Uint8Array ? value : new Uint8Array(value);
          if (received + piece.byteLength > expectedLen) {
            await reader.cancel('chunk stream exceeded expected length').catch(() => {});
            controller.abort();
            throw errnoError('EIO', `chunk stream exceeded expected length (${expectedLen} bytes)`);
          }
          chunkBuf.set(piece, received);
          received += piece.byteLength;
        }
      } finally {
        try {
          reader.releaseLock?.();
        } catch {
          /* ignore */
        }
      }

      if (received !== expectedLen) {
        throw errnoError('EIO', `truncated chunk stream: got ${received}, expected ${expectedLen}`);
      }

      const actualDigest = await sha256Hex(chunkBuf);
      if (actualDigest !== expectedChunkSha) {
        chunkBuf.fill(0);
        throw errnoError('EIO', `chunk ${chunkIdx} SHA-256 mismatch`);
      }

      return chunkBuf;
    } finally {
      if (trackedBytes > 0) {
        currentBufferedBytes -= trackedBytes;
      }
      releaseSlot();
    }
  }

  async function getVerifiedChunk(url, manifest, chunkIdx) {
    const { sha256, size, chunkSize, chunks } = manifest;
    const cStart = chunkIdx * chunkSize;
    const cEnd = Math.min(size, cStart + chunkSize) - 1;
    const expectedLen = cEnd - cStart + 1;
    const expectedChunkSha = chunks[chunkIdx];
    const key = `${sha256}:${chunkSize}:${chunkIdx}:${expectedChunkSha}`;

    const cached = cacheGet(key);
    if (cached) {
      if (cached.byteLength === expectedLen && (await sha256Hex(cached)) === expectedChunkSha) {
        cacheHits++;
        return cached;
      }
      cacheDelete(key);
    }

    if (inFlight.has(key)) {
      coalescedHits++;
      return inFlight.get(key);
    }

    const promise = (async () => {
      // 1. OPFS-first local read (ZERO network calls when Release v2 is installed).
      const localBytes = await readLocalRange(sha256, cStart, cEnd + 1);
      if (localBytes !== null && localBytes !== undefined) {
        if (localBytes.byteLength !== expectedLen) {
          throw errnoError('EIO', `OPFS chunk ${chunkIdx} length mismatch`);
        }
        const actualDigest = await sha256Hex(localBytes);
        if (actualDigest !== expectedChunkSha) {
          throw errnoError('EIO', `OPFS chunk ${chunkIdx} SHA-256 mismatch`);
        }
        localOpfsHits++;
        cachePut(key, localBytes);
        return localBytes;
      }

      // 2. Bounded streaming remote Range + strong If-Range fetch.
      const remoteBytes = await fetchVerifiedChunkRemote(
        url,
        sha256,
        chunkIdx,
        cStart,
        cEnd,
        size,
        chunkSize,
        expectedChunkSha,
      );
      cachePut(key, remoteBytes);
      return remoteBytes;
    })();

    inFlight.set(key, promise);
    try {
      return await promise;
    } finally {
      if (inFlight.get(key) === promise) {
        inFlight.delete(key);
      }
    }
  }

  async function readUnmanifestedRange(blobId, url, start, count) {
    const sha = blobId.startsWith('sha256:')
      ? blobId.slice(7)
      : HEX64.test(blobId)
        ? blobId
        : null;

    // Content-addressed blobs MUST supply a chunk manifest so every exposed byte is SHA-256 verified.
    if (sha) {
      throw errnoError('EINVAL', 'chunk manifest is required for content-addressed sha256 blob reads');
    }

    const out = new Uint8Array(count);
    let filled = 0;
    while (filled < count) {
      const sliceStart = start + filled;
      const sliceLen = Math.min(CHUNK_SIZE_MAX, count - filled);
      const sliceEnd = sliceStart + sliceLen - 1;
      await acquireSlot();
      const controller = new AbortController();
      let trackedBytes = 0;
      try {
        totalNetworkFetches++;
        const headers = { Range: `bytes=${sliceStart}-${sliceEnd}` };
        const response = await fetchFn(url, { headers, cache: 'no-store', signal: controller.signal });
        if (response.status === 404) {
          await cancelBody(response, 'not found');
          throw errnoError('ENOENT', `asset not found: ${url}`);
        }
        if (response.status === 416) {
          await cancelBody(response, 'range not satisfiable');
          break;
        }
        if (response.status !== 206 && response.status !== 200) {
          await cancelBody(response, `HTTP ${response.status}`);
          controller.abort();
          throw errnoError('EIO', `unexpected HTTP status ${response.status}`);
        }
        if (!response.body || typeof response.body.getReader !== 'function') {
          controller.abort();
          throw errnoError('EIO', 'streaming response body is required');
        }

        if (response.status === 206) {
          const cr = response.headers?.get?.('Content-Range') ?? '';
          const match = CONTENT_RANGE_RE.exec(cr.trim());
          if (!match) {
            await cancelBody(response, 'missing Content-Range');
            controller.abort();
            throw errnoError('EIO', `invalid Content-Range: ${cr}`);
          }
          const rStart = Number(match[1]);
          const rEnd = Number(match[2]);
          const rTotal = Number(match[3]);
          const validEnd = rEnd >= rStart && rEnd <= sliceEnd && rEnd < rTotal
            && (rEnd === sliceEnd || rEnd === rTotal - 1);
          if (rStart !== sliceStart || !validEnd) {
            await cancelBody(response, 'Content-Range mismatch');
            controller.abort();
            throw errnoError('EIO', `Content-Range mismatch: got ${cr}, expected start ${sliceStart}..=${sliceEnd}`);
          }
          const expectedSliceLen = rEnd - rStart + 1;
          const contentLength = response.headers?.get?.('Content-Length');
          if (contentLength !== null && contentLength !== undefined && contentLength !== '') {
            if (!DIGITS_RE.test(contentLength.trim()) || Number(contentLength) !== expectedSliceLen) {
              await cancelBody(response, 'Content-Length mismatch');
              controller.abort();
              throw errnoError('EIO', `Content-Length mismatch: got ${contentLength}, expected ${expectedSliceLen}`);
            }
          }
          const reader = response.body.getReader();
          const buf = new Uint8Array(expectedSliceLen);
          trackedBytes = expectedSliceLen;
          currentBufferedBytes += trackedBytes;
          if (currentBufferedBytes > peakBufferedBytes) peakBufferedBytes = currentBufferedBytes;
          let got = 0;
          try {
            while (true) {
              const { done, value } = await reader.read();
              if (done) break;
              if (!value || value.byteLength === 0) continue;
              const piece = value instanceof Uint8Array ? value : new Uint8Array(value);
              if (got + piece.byteLength > expectedSliceLen) {
                await reader.cancel('oversized range stream').catch(() => {});
                controller.abort();
                throw errnoError('EIO', 'range stream exceeded expected Content-Range length');
              }
              buf.set(piece, got);
              got += piece.byteLength;
            }
          } finally {
            try { reader.releaseLock?.(); } catch {}
          }
          if (got !== expectedSliceLen) {
            throw errnoError('EIO', `truncated range stream: got ${got}, expected ${expectedSliceLen}`);
          }
          out.set(buf, filled);
          filled += got;
          if (rEnd === rTotal - 1 || got < sliceLen) break;
        } else {
          // Dev server without Range support: stream and retain ONLY the requested slice.
          const reader = response.body.getReader();
          let streamPos = 0;
          let got = 0;
          const targetEnd = sliceStart + sliceLen;
          try {
            while (true) {
              const { done, value } = await reader.read();
              if (done) break;
              if (!value || value.byteLength === 0) continue;
              const piece = value instanceof Uint8Array ? value : new Uint8Array(value);
              const pieceStart = streamPos;
              const pieceEnd = streamPos + piece.byteLength;
              streamPos = pieceEnd;
              if (pieceEnd <= sliceStart) continue;
              const copyFrom = Math.max(0, sliceStart - pieceStart);
              const copyTo = Math.min(piece.byteLength, targetEnd - pieceStart);
              if (copyTo > copyFrom) {
                out.set(piece.subarray(copyFrom, copyTo), filled + got);
                got += copyTo - copyFrom;
              }
              if (streamPos >= targetEnd) {
                await reader.cancel('requested slice complete').catch(() => {});
                controller.abort();
                break;
              }
            }
          } finally {
            try { reader.releaseLock?.(); } catch {}
          }
          filled += got;
          if (got < sliceLen) break;
        }
      } finally {
        if (trackedBytes > 0) currentBufferedBytes -= trackedBytes;
        releaseSlot();
      }
    }
    return filled === count ? out : out.subarray(0, filled);
  }

  async function imageBlobRead(blobId, offset, len, chunkManifest) {
    const start = Number(offset);
    const count = Number(len);
    if (!Number.isSafeInteger(start) || start < 0 || !Number.isSafeInteger(count) || count < 0) {
      throw errnoError('EINVAL', 'invalid read offset/length');
    }
    if (count === 0) return new Uint8Array(0);

    const url = resolveUrl(blobId);
    if (chunkManifest !== undefined && chunkManifest !== null) {
      const manifest = validateManifest(chunkManifest);
      if (start >= manifest.size) return new Uint8Array(0);
      const effectiveLen = Math.min(count, manifest.size - start);
      const firstChunk = Math.floor(start / manifest.chunkSize);
      const lastChunk = Math.floor((start + effectiveLen - 1) / manifest.chunkSize);
      const out = new Uint8Array(effectiveLen);

      if (firstChunk === lastChunk) {
        const chunkBytes = await getVerifiedChunk(url, manifest, firstChunk);
        const relStart = start - firstChunk * manifest.chunkSize;
        out.set(chunkBytes.subarray(relStart, relStart + effectiveLen), 0);
        return out;
      }

      const indices = [];
      for (let idx = firstChunk; idx <= lastChunk; idx++) indices.push(idx);
      const fetched = await Promise.all(indices.map(idx => getVerifiedChunk(url, manifest, idx)));
      let dst = 0;
      for (let i = 0; i < indices.length; i++) {
        const idx = indices[i];
        const chunkBytes = fetched[i];
        const chunkBase = idx * manifest.chunkSize;
        const sliceStart = Math.max(0, start - chunkBase);
        const sliceEnd = Math.min(chunkBytes.byteLength, start + effectiveLen - chunkBase);
        out.set(chunkBytes.subarray(sliceStart, sliceEnd), dst);
        dst += sliceEnd - sliceStart;
      }
      return out;
    }

    return readUnmanifestedRange(blobId, url, start, count);
  }

  return {
    imageBlobRead,
    clearCache() {
      cache.clear();
      cacheBytes = 0;
    },
    stats() {
      return {
        activeFetches,
        peakConcurrentFetches,
        totalNetworkFetches,
        coalescedHits,
        localOpfsHits,
        cacheHits,
        currentBufferedBytes,
        peakBufferedBytes,
        cacheBytes,
        cacheEntries: cache.size,
      };
    },
  };
}

export const defaultPager = createImagePager();

export function imageBlobRead(blobId, offset, len, chunkManifest) {
  return defaultPager.imageBlobRead(blobId, offset, len, chunkManifest);
}

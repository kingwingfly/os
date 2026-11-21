import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Worker } from 'node:worker_threads';
import {
  ARENA_BYTES,
  ARENA_SLOTS,
  HEADER_BYTES,
  RING_CAPACITY,
  SLOT_BYTES,
  ArenaRing,
  createSockArenaBuffer,
  fenceArenaSlot,
  initArenaSlot,
} from '../web/wasi/sock-arena.js';
import { ArenaPipe, PIPE_ATOMIC } from '../web/wasi/pipe.js';

test('SockArena allocates 8 MiB backing 128 x 64 KiB slots', () => {
  assert.equal(ARENA_SLOTS, 128);
  assert.equal(SLOT_BYTES, 65536);
  assert.equal(HEADER_BYTES, 64);
  assert.equal(RING_CAPACITY, 65472);
  assert.equal(ARENA_BYTES, 8 * 1024 * 1024);

  const arena = createSockArenaBuffer();
  assert.ok(arena instanceof SharedArrayBuffer);
  assert.equal(arena.byteLength, ARENA_BYTES);
});

test('ArenaRing generation fencing invalidates stale holders on slot reuse', () => {
  const arena = createSockArenaBuffer();
  initArenaSlot(arena, 7, 1, 1, 1);

  const writer = new ArenaRing(arena, 7, 1, 10);
  const reader = new ArenaRing(arena, 7, 1, 20);
  assert.equal(writer.alive, true);
  assert.equal(reader.alive, true);

  const res = writer.tryWrite(new TextEncoder().encode('first-gen'));
  assert.equal(res.broken, false);
  assert.equal(res.written, 9);
  assert.equal(new TextDecoder().decode(reader.read(32, undefined, { nonblock: true })), 'first-gen');

  // Fence and reuse slot 7 at generation 2.
  fenceArenaSlot(arena, 7, 2);
  assert.equal(writer.alive, false);
  assert.equal(reader.alive, false);
  assert.equal(writer.rdClosed, true);
  assert.equal(reader.wrClosed, true);
  assert.equal(writer.tryWrite(new Uint8Array([1, 2, 3])).broken, true);
  assert.equal(reader.read(8, undefined, { nonblock: true }).length, 0);

  initArenaSlot(arena, 7, 2, 1, 1);
  const writer2 = new ArenaRing(arena, 7, 2, 30);
  const reader2 = new ArenaRing(arena, 7, 2, 40);
  assert.equal(writer.alive, false, 'gen-1 handle remains permanently fenced');
  assert.equal(writer2.alive, true);
  assert.equal(writer2.tryWrite(new TextEncoder().encode('second-gen')).written, 10);
  assert.equal(new TextDecoder().decode(reader2.read(32, undefined, { nonblock: true })), 'second-gen');
});

test('ArenaRing enforces exact SCM_RIGHTS ancillary byte-offset boundaries (U-05)', () => {
  const arena = createSockArenaBuffer();
  initArenaSlot(arena, 3, 1, 1, 1);

  const tx = new ArenaRing(arena, 3, 1, 10);
  const rx = new ArenaRing(arena, 3, 1, 20);
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  // Plain prefix [0..5), mark1 "AAA" [5..8), mark2 "BBB" [8..11).
  const p0 = tx.tryWrite(enc.encode('PLAIN'));
  assert.equal(p0.startOffset, 0);
  assert.equal(p0.endOffset, 5);

  tx.setAncillary(5);
  const p1 = tx.tryWrite(enc.encode('AAA'));
  assert.equal(p1.startOffset, 5);
  assert.equal(p1.endOffset, 8);
  const p2 = tx.tryWrite(enc.encode('BBB'));
  assert.equal(p2.startOffset, 8);
  assert.equal(p2.endOffset, 11);

  assert.equal(rx.hasAncillary, true);
  assert.equal(rx.ancillaryOffset, 5);

  // Read before ancillary offset stops strictly at byte 5.
  const got0 = rx.read(64, undefined, { nonblock: true, maxOffset: 5 });
  assert.equal(dec.decode(got0), 'PLAIN');
  assert.equal(rx.tailOffset, 5);

  // First ancillary read stops strictly at byte 8 even though "BBB" is queued.
  const got1 = rx.read(64, undefined, { nonblock: true, maxOffset: 8 });
  assert.equal(dec.decode(got1), 'AAA');
  assert.equal(rx.tailOffset, 8);

  // Advance ancillary mark to 8, then read second ancillary segment [8..11).
  rx.setAncillary(8);
  assert.equal(rx.ancillaryOffset, 8);
  const got2 = rx.read(64, undefined, { nonblock: true, maxOffset: 11 });
  assert.equal(dec.decode(got2), 'BBB');
  assert.equal(rx.tailOffset, 11);
  rx.clearAncillary();
  assert.equal(rx.hasAncillary, false);
});

test('ArenaRing multi-MiB concurrent streaming across two independent Workers over shared SockArena', async () => {
  const arena = createSockArenaBuffer();
  initArenaSlot(arena, 12, 1, 1, 1);

  const totalBytes = 2 * 1024 * 1024 + 137; // > 32 full ring wraps
  const writerCode = `
    import { workerData, parentPort } from 'node:worker_threads';
    import { ArenaRing } from ${JSON.stringify(new URL('../web/wasi/sock-arena.js', import.meta.url).href)};
    const { arena, slot, gen, totalBytes } = workerData;
    const ring = new ArenaRing(arena, slot, gen, 101);
    const chunk = new Uint8Array(8192);
    let offset = 0;
    while (offset < totalBytes) {
      const n = Math.min(chunk.length, totalBytes - offset);
      for (let i = 0; i < n; i++) chunk[i] = ((offset + i) * 31 + 17) & 0xff;
      const res = ring.write(chunk.subarray(0, n), undefined, { atomicLimit: 1 });
      if (res.broken || res.written !== n) throw new Error('unexpected write failure');
      offset += res.written;
    }
    ring.closeWriter();
    parentPort.postMessage({ written: offset, headOffset: ring.headOffset });
  `;

  const readerCode = `
    import { workerData, parentPort } from 'node:worker_threads';
    import { ArenaRing } from ${JSON.stringify(new URL('../web/wasi/sock-arena.js', import.meta.url).href)};
    const { arena, slot, gen } = workerData;
    const ring = new ArenaRing(arena, slot, gen, 202);
    let offset = 0;
    for (;;) {
      const part = ring.read(5003);
      if (part.length === 0) break;
      for (let i = 0; i < part.length; i++) {
        const expected = ((offset + i) * 31 + 17) & 0xff;
        if (part[i] !== expected) {
          throw new Error(\`corruption at \${offset + i}: got \${part[i]} want \${expected}\`);
        }
      }
      offset += part.length;
    }
    parentPort.postMessage({ received: offset, tailOffset: ring.tailOffset });
  `;

  const runWorker = (code, workerData) =>
    new Promise((resolve, reject) => {
      const w = new Worker(code, { eval: true, workerData });
      w.once('message', resolve);
      w.once('error', reject);
      w.once('exit', codeExit => {
        if (codeExit !== 0) reject(new Error(`worker exited ${codeExit}`));
      });
    });

  const [wRes, rRes] = await Promise.all([
    runWorker(writerCode, { arena, slot: 12, gen: 1, totalBytes }),
    runWorker(readerCode, { arena, slot: 12, gen: 1 }),
  ]);

  assert.equal(wRes.written, totalBytes);
  assert.equal(wRes.headOffset, totalBytes);
  assert.equal(rRes.received, totalBytes);
  assert.equal(rRes.tailOffset, totalBytes);
});

test('ArenaPipe honors PIPE_ATOMIC, EAGAIN, EOF, and EPIPE broken-reader semantics', () => {
  const arena = createSockArenaBuffer();
  initArenaSlot(arena, 0, 1, 1, 1);

  const rEnd = new ArenaPipe(arena, 0, 1, 10);
  const wEnd = new ArenaPipe(arena, 0, 1, 20);
  assert.equal(PIPE_ATOMIC, 4096);
  assert.equal(rEnd.empty, true);
  assert.equal(rEnd.read(16, undefined, false, true), null);

  const payload = new TextEncoder().encode('arena-pipe-data');
  assert.deepEqual(wEnd.tryWrite(payload), { written: payload.length, broken: false });
  assert.equal(rEnd.queued, payload.length);
  assert.equal(new TextDecoder().decode(rEnd.read(64, undefined, false, true)), 'arena-pipe-data');

  // Closing writer triggers EOF (0-byte read).
  wEnd.closeWriter();
  assert.equal(rEnd.writerGone, true);
  assert.equal(rEnd.read(16, undefined, false, true).length, 0);

  // Fresh slot: closing reader triggers broken pipe on write.
  initArenaSlot(arena, 1, 1, 1, 1);
  const r2 = new ArenaPipe(arena, 1, 1, 10);
  const w2 = new ArenaPipe(arena, 1, 1, 20);
  r2.closeReader();
  assert.equal(w2.readerGone, true);
  assert.deepEqual(w2.tryWrite(payload), { written: 0, broken: true });
});

test('WASI socket errno constants stay synchronized across JS and Rust', () => {
  const processJs = readFileSync(new URL('../web/wasi/process.js', import.meta.url), 'utf8');
  const expected = {
    EADDRINUSE: 3,
    EADDRNOTAVAIL: 4,
    EAFNOSUPPORT: 5,
    ECONNABORTED: 13,
    ECONNREFUSED: 14,
    ECONNRESET: 15,
    EISCONN: 30,
    EMSGSIZE: 35,
    ENOBUFS: 42,
    ENOTSOCK: 57,
    EPROTOTYPE: 67,
    ETOOMANYREFS: 109,
  };
  for (const [name, num] of Object.entries(expected)) {
    assert.match(processJs, new RegExp(`\\b${name}:\\s*${num}\\b`), `missing ${name}=${num} in web/wasi/process.js`);
  }
});

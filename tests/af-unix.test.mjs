import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Worker } from 'node:worker_threads';
import {
  ARENA_BYTES,
  ARENA_SLOTS,
  HEADER_BYTES,
  HDR_RD_LOCK,
  HDR_WR_LOCK,
  HOST_LOCK_BIT,
  RING_CAPACITY,
  SLOT_BYTES,
  U64_HEAD,
  U64_TAIL,
  ArenaRing,
  createSockArenaBuffer,
  fenceArenaSlot,
  initArenaSlot,
  releaseWorkerLocks,
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

  // Fence gen 1 -> 2 and reuse slot 7 at generation 3.
  assert.equal(fenceArenaSlot(arena, 7, 1, 2), true);
  assert.equal(writer.alive, false);
  assert.equal(reader.alive, false);
  assert.equal(writer.rdClosed, true);
  assert.equal(reader.wrClosed, true);
  assert.equal(writer.tryWrite(new Uint8Array([1, 2, 3])).broken, true);
  assert.equal(reader.read(8, undefined, { nonblock: true }).length, 0);

  initArenaSlot(arena, 7, 3, 1, 1);
  const writer2 = new ArenaRing(arena, 7, 3, 30);
  const reader2 = new ArenaRing(arena, 7, 3, 40);
  assert.equal(writer.alive, false, 'gen-1 handle remains permanently fenced');
  assert.equal(writer2.alive, true);
  // Delayed stale fence for gen 1 MUST fail CAS and leave live gen 3 completely untouched!
  assert.equal(fenceArenaSlot(arena, 7, 1, 2), false);
  assert.equal(writer2.alive, true);
  assert.equal(writer2.rdClosed, false);
  assert.equal(writer2.wrClosed, false);
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

test('ArenaRing concurrent multi-Worker stopAtAncillary prevents TOCTOU coalescing across SCM_RIGHTS boundaries (U-05)', async () => {
  const arena = createSockArenaBuffer();
  initArenaSlot(arena, 15, 1, 1, 1);
  // Small lock-free coordination buffer modeling the kernel Worker's ancillary queue state:
  // [0]=queuedCount, [1]=ackCount, [2..]=ancillary [startOff, endOff] spans (up to 512 entries).
  const rounds = 200;
  const ctrl = new Int32Array(new SharedArrayBuffer((2 + rounds * 2) * 4));

  const writerCode = `
    import { workerData, parentPort } from 'node:worker_threads';
    import { ArenaRing, HDR_WR_LOCK } from ${JSON.stringify(new URL('../web/wasi/sock-arena.js', import.meta.url).href)};
    const { arena, slot, gen, ctrlBuf, rounds } = workerData;
    const ring = new ArenaRing(arena, slot, gen, 301);
    const ctrl = new Int32Array(ctrlBuf);
    const plain = new Uint8Array([0x50, 0x4c, 0x4e]); // "PLN"
    const anc = new Uint8Array([0x41, 0x4e, 0x43, 0x21]); // "ANC!"

    let totalPlain = 0;
    let totalAnc = 0;
    for (let r = 0; r < rounds; r++) {
      // 1. Interleave plain stream bytes (varying 0..3 chunks) before each ancillary send.
      const bursts = (r % 3) + 1;
      for (let b = 0; b < bursts; b++) {
        const res = ring.write(plain, undefined, { atomicLimit: 1 });
        if (res.broken || res.written !== plain.length) throw new Error('plain write failed');
        totalPlain += res.written;
      }
      // 2. Wait for previous ancillary barrier to drain (1-deep kernel mark simulation), then
      //    atomically setAncillary BEFORE _copyIn under HDR_WR_LOCK — identical to exec.mjs!
      while (Atomics.load(ctrl, 1) < r) {
        Atomics.wait(ctrl, 1, Atomics.load(ctrl, 1), 1);
      }
      for (;;) {
        if (ring.room >= anc.length && ring.lock(HDR_WR_LOCK)) break;
      }
      try {
        const startOff = ring.headOffset;
        const endOff = startOff + anc.length;
        Atomics.store(ctrl, 2 + r * 2, startOff);
        Atomics.store(ctrl, 2 + r * 2 + 1, endOff);
        ring.setAncillary(startOff);
        ring._copyIn(anc);
        Atomics.store(ctrl, 0, r + 1);
        Atomics.notify(ctrl, 0);
        totalAnc += anc.length;
      } finally {
        ring.unlock(HDR_WR_LOCK);
      }
    }
    ring.closeWriter();
    parentPort.postMessage({ totalPlain, totalAnc, headOffset: ring.headOffset });
  `;

  const readerCode = `
    import { workerData, parentPort } from 'node:worker_threads';
    import { ArenaRing } from ${JSON.stringify(new URL('../web/wasi/sock-arena.js', import.meta.url).href)};
    const { arena, slot, gen, ctrlBuf, rounds } = workerData;
    const ring = new ArenaRing(arena, slot, gen, 302);
    const ctrl = new Int32Array(ctrlBuf);

    let plainBytes = 0;
    let ancMsgs = 0;
    let ancBytes = 0;
    for (;;) {
      // Continuously hammer fast-path read with stopAtAncillary: true (exact race window of sockRecvStream!).
      const fast = ring.read(64, undefined, { nonblock: true, stopAtAncillary: true });
      if (fast && fast.length > 0) {
        for (let i = 0; i < fast.length; i++) {
          if (fast[i] === 0x41 || fast[i] === 0x21) {
            throw new Error(\`TOCTOU breach: plain stopAtAncillary read stole ancillary byte 0x\${fast[i].toString(16)} at tail=\${ring.tailOffset}\`);
          }
        }
        plainBytes += fast.length;
        continue;
      }
      if (ring.hasAncillary) {
        const tail = ring.tailOffset;
        const ancOff = ring.ancillaryOffset;
        if (tail > ancOff) {
          throw new Error(\`TOCTOU desync: tail (\${tail}) > ancillaryOffset (\${ancOff})\`);
        }
        if (tail === ancOff) {
          const idx = ancMsgs;
          while (Atomics.load(ctrl, 0) <= idx) {
            Atomics.wait(ctrl, 0, Atomics.load(ctrl, 0), 1);
          }
          const startOff = Atomics.load(ctrl, 2 + idx * 2);
          const endOff = Atomics.load(ctrl, 2 + idx * 2 + 1);
          if (tail !== startOff) {
            throw new Error(\`ancillary start mismatch: tail=\${tail} startOff=\${startOff}\`);
          }
          ring.clearAncillary();
          const payload = ring.read(endOff - startOff, undefined, { nonblock: false, maxOffset: endOff });
          if (payload.length !== 4 || payload[0] !== 0x41 || payload[1] !== 0x4e || payload[2] !== 0x43 || payload[3] !== 0x21) {
            throw new Error(\`corrupt ancillary payload at round \${idx}: \${[...payload]}\`);
          }
          ancBytes += payload.length;
          ancMsgs++;
          Atomics.store(ctrl, 1, ancMsgs);
          Atomics.notify(ctrl, 1);
          continue;
        }
      }
      if (ring.wrClosed && ring.queued === 0 && !ring.hasAncillary) break;
    }
    parentPort.postMessage({ plainBytes, ancMsgs, ancBytes, tailOffset: ring.tailOffset });
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
    runWorker(writerCode, { arena, slot: 15, gen: 1, ctrlBuf: ctrl.buffer, rounds }),
    runWorker(readerCode, { arena, slot: 15, gen: 1, ctrlBuf: ctrl.buffer, rounds }),
  ]);

  assert.equal(rRes.ancMsgs, rounds);
  assert.equal(rRes.ancBytes, wRes.totalAnc);
  assert.equal(rRes.plainBytes, wRes.totalPlain);
  assert.equal(rRes.tailOffset, wRes.headOffset);
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

test('ArenaRing 64-bit cursors cross 4 GiB boundary with zero tearing and bound occupancy by RING_CAPACITY', () => {
  const arena = createSockArenaBuffer();
  initArenaSlot(arena, 21, 5, 1, 1);
  const tx = new ArenaRing(arena, 21, 5, 10);
  const rx = new ArenaRing(arena, 21, 5, 20);

  // Position both cursors 4 bytes below 4 GiB (0xfffffffc) and write/read across 2^32.
  const start = 0xfffffffcn;
  Atomics.store(tx.u64, U64_HEAD, start);
  Atomics.store(tx.u64, U64_TAIL, start);

  const msg = new TextEncoder().encode('cross-4gib-boundary!');
  const w = tx.tryWrite(msg);
  assert.equal(w.broken, false);
  assert.equal(w.written, msg.length);
  assert.equal(w.startOffset, Number(start));
  assert.equal(w.endOffset, Number(start) + msg.length);
  assert.equal(rx.queued, msg.length);

  const got = rx.read(64, undefined, { nonblock: true });
  assert.equal(new TextDecoder().decode(got), 'cross-4gib-boundary!');
  assert.equal(rx.tailOffset, Number(start) + msg.length);
  assert.equal(rx.queued, 0);

  // Occupancy is strictly clamped to RING_CAPACITY even if head is far ahead.
  Atomics.store(tx.u64, U64_HEAD, start + BigInt(RING_CAPACITY) + 50000n);
  assert.equal(rx.queued, RING_CAPACITY);
});

test('ArenaRing closeWriter() rejects subsequent tryWrite/write (SHUT_WR) and notifies sockNotify', () => {
  const arena = createSockArenaBuffer();
  const sockNotify = new Int32Array(new SharedArrayBuffer(4));
  initArenaSlot(arena, 22, 9, 1, 1, sockNotify);
  const tx = new ArenaRing(arena, 22, 9, 10, sockNotify);
  const rx = new ArenaRing(arena, 22, 9, 20, sockNotify);

  const before = Atomics.load(sockNotify, 0);
  const w1 = tx.tryWrite(new TextEncoder().encode('ok'));
  assert.equal(w1.written, 2);
  assert.ok(Atomics.load(sockNotify, 0) > before, 'fast ring write must notify sockNotify');

  // After closeWriter (SHUT_WR), further writes MUST fail broken=true while queued bytes stay readable.
  tx.closeWriter();
  assert.equal(tx.tryWrite(new TextEncoder().encode('late')).broken, true);
  assert.equal(tx.write(new TextEncoder().encode('late')).broken, true);
  assert.equal(new TextDecoder().decode(rx.read(16, undefined, { nonblock: true })), 'ok');
  assert.equal(rx.read(16, undefined, { nonblock: true }).length, 0);
});

test('releaseWorkerLocks clears dead Worker stream mutexes without touching HOST_LOCK_BIT host locks', () => {
  const arena = createSockArenaBuffer();
  initArenaSlot(arena, 30, 1, 1, 1);
  initArenaSlot(arena, 31, 1, 1, 1);

  const workerRing = new ArenaRing(arena, 30, 1, 42);
  const hostRing = new ArenaRing(arena, 31, 1, (HOST_LOCK_BIT | 42) | 0);
  assert.equal(workerRing.lock(HDR_RD_LOCK), true);
  assert.equal(workerRing.lock(HDR_WR_LOCK), true);
  assert.equal(hostRing.lock(HDR_RD_LOCK), true);
  assert.equal(hostRing.lock(HDR_WR_LOCK), true);

  // Forced Worker termination for pid 42 clears ONLY slot 30's guest locks, never slot 31's host locks!
  assert.equal(releaseWorkerLocks(arena, 42), 2);
  const other = new ArenaRing(arena, 30, 1, 99);
  assert.equal(other.lock(HDR_RD_LOCK), true);
  assert.equal(other.lock(HDR_WR_LOCK), true);
  other.unlock(HDR_RD_LOCK);
  other.unlock(HDR_WR_LOCK);

  const contendHost = new ArenaRing(arena, 31, 1, 99);
  assert.equal(contendHost.lock(HDR_RD_LOCK), false);
  assert.equal(contendHost.lock(HDR_WR_LOCK), false);
  hostRing.unlock(HDR_RD_LOCK);
  hostRing.unlock(HDR_WR_LOCK);
  assert.equal(contendHost.lock(HDR_RD_LOCK), true);
  contendHost.unlock(HDR_RD_LOCK);
});

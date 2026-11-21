// Instance-wide 8 MiB shared-memory ring arena (`SockArena`, #55 L3b).
//
// Allocated once per OS instance in the dedicated kernel Worker (`web/wasi/exec.mjs`) and passed
// in every process Worker's initial `start` message. Unrelated Workers map any slot `0..127` into
// a zero-copy 64-byte atomic header + `Uint8Array` ring view with ZERO mid-syscall `postMessage`
// SAB transfers — working identically in synchronous `Atomics.wait` and JSPI modes.

export const ARENA_SLOTS = 128;
export const SLOT_BYTES = 65536; // 64 KiB per unidirectional ring
export const HEADER_BYTES = 64; // 4 x BigUint64 (bytes 0..31) + 8 x Int32 (bytes 32..63)
export const RING_CAPACITY = SLOT_BYTES - HEADER_BYTES; // 65,472 bytes
export const ARENA_BYTES = ARENA_SLOTS * SLOT_BYTES; // 8,388,608 bytes (8 MiB)

// Aligned 64-bit atomic word offsets (bytes 0..31, BigUint64Array index 0..3):
export const U64_HEAD = 0; // monotonic 64-bit write byte offset (single atomic word: zero 4 GiB tearing)
export const U64_TAIL = 1; // monotonic 64-bit read byte offset (single atomic word: zero 4 GiB tearing)
export const U64_ANCILLARY_OFFSET = 2; // 64-bit byte offset of next AncillaryMark boundary
export const U64_GEN = 3; // monotonic 64-bit generation counter fenced via CAS on slot reuse

// 32-bit atomic word offsets (bytes 32..63, Int32Array index 8..15):
export const HDR_FLAGS = 8; // bitmask of FLAG_* below
export const HDR_READERS = 9; // reader holder count
export const HDR_WRITERS = 10; // writer holder count
export const HDR_CHANGES = 11; // futex wakeup counter notified on every state change
export const HDR_RD_LOCK = 12; // reader mutex (Worker pid OR HOST_LOCK_BIT | pid, 0 = unlocked)
export const HDR_WR_LOCK = 13; // writer mutex (Worker pid OR HOST_LOCK_BIT | pid, 0 = unlocked)

// Flag bits in `HDR_FLAGS`:
export const FLAG_WR_CLOSED = 1;
export const FLAG_RD_CLOSED = 2;
export const FLAG_HAS_ANCILLARY = 4;
export const FLAG_PASSCRED = 8; // peer enabled SO_PASSCRED: writers must record sender cred marks
export const FLAG_SOCK_NONBLOCK = 16; // shared O_NONBLOCK for this socket's open-file description (on its TX slot)
export const FLAG_PIPE_RD_NONBLOCK = 32; // shared O_NONBLOCK for an arena-pipe read-end open-file description
export const FLAG_PIPE_WR_NONBLOCK = 64; // shared O_NONBLOCK for an arena-pipe write-end open-file description

// Lock ownership tag distinguishing kernel-host transactions (`exec.mjs`) from guest Worker locks.
// Forced Worker termination clears ONLY guest Worker locks (`pid`), never active host transactions.
export const HOST_LOCK_BIT = 0x40000000;

export const PIPE_ATOMIC = 4096;
const RING_CAP_BIG = BigInt(RING_CAPACITY);

/** Allocate one 8 MiB instance-wide SharedArrayBuffer backing 128 x 64 KiB ring slots. */
export function createSockArenaBuffer() {
  return new SharedArrayBuffer(ARENA_BYTES);
}

/**
 * Initialize or reset one slot in `arenaBuffer` for a newly allocated generation `gen`.
 * First zeroes `U64_GEN` so any stale holder immediately observes `!alive`, clears all counters,
 * locks, and flags, then publishes `BigInt(gen)` and notifies waiters.
 */
export function initArenaSlot(arenaBuffer, slot, gen, readers = 1, writers = 1, notifyWord = null) {
  const base = slot * SLOT_BYTES;
  const u64 = new BigUint64Array(arenaBuffer, base, 4);
  const hdr = new Int32Array(arenaBuffer, base, HEADER_BYTES / 4);
  Atomics.store(u64, U64_GEN, 0n);
  Atomics.add(hdr, HDR_CHANGES, 1);
  Atomics.notify(hdr, HDR_CHANGES);
  Atomics.store(u64, U64_HEAD, 0n);
  Atomics.store(u64, U64_TAIL, 0n);
  Atomics.store(u64, U64_ANCILLARY_OFFSET, 0n);
  Atomics.store(hdr, HDR_FLAGS, 0);
  Atomics.store(hdr, HDR_READERS, readers | 0);
  Atomics.store(hdr, HDR_WRITERS, writers | 0);
  Atomics.store(hdr, HDR_RD_LOCK, 0);
  Atomics.store(hdr, HDR_WR_LOCK, 0);
  Atomics.store(u64, U64_GEN, BigInt(gen));
  Atomics.add(hdr, HDR_CHANGES, 1);
  Atomics.notify(hdr, HDR_CHANGES);
  if (notifyWord) {
    Atomics.add(notifyWord, 0, 1);
    Atomics.notify(notifyWord, 0);
  }
}

/**
 * Atomically fence a freed slot ONLY if its current generation still equals `expectedGen`.
 * Returns `true` if this call fenced the slot, or `false` if the slot was already fenced or
 * re-allocated to a newer live generation (preventing delayed cleanup from clobbering live slots).
 */
export function fenceArenaSlot(arenaBuffer, slot, expectedGen, fenceGen, notifyWord = null) {
  const base = slot * SLOT_BYTES;
  const u64 = new BigUint64Array(arenaBuffer, base, 4);
  const hdr = new Int32Array(arenaBuffer, base, HEADER_BYTES / 4);
  const want = BigInt(expectedGen);
  const next = BigInt(fenceGen);
  if (Atomics.compareExchange(u64, U64_GEN, want, next) !== want) {
    return false;
  }
  Atomics.or(hdr, HDR_FLAGS, FLAG_WR_CLOSED | FLAG_RD_CLOSED);
  Atomics.store(hdr, HDR_RD_LOCK, 0);
  Atomics.store(hdr, HDR_WR_LOCK, 0);
  Atomics.add(hdr, HDR_CHANGES, 1);
  Atomics.notify(hdr, HDR_CHANGES);
  if (notifyWord) {
    Atomics.add(notifyWord, 0, 1);
    Atomics.notify(notifyWord, 0);
  }
  return true;
}

/**
 * Recover any guest-Worker-held stream or arena-pipe ring mutexes abandoned when `pid`'s Worker
 * was forcefully terminated (`SIGKILL` / `worker.terminate()`). Never clears active kernel-host
 * locks tagged with `HOST_LOCK_BIT`.
 */
export function releaseWorkerLocks(arenaBuffer, pid, notifyWord = null) {
  if (!arenaBuffer) return 0;
  const owner = (pid | 0) & ~HOST_LOCK_BIT;
  if (owner <= 0) return 0;
  let released = 0;
  for (let slot = 0; slot < ARENA_SLOTS; slot++) {
    const hdr = new Int32Array(arenaBuffer, slot * SLOT_BYTES, HEADER_BYTES / 4);
    let woke = false;
    if (Atomics.compareExchange(hdr, HDR_RD_LOCK, owner, 0) === owner) {
      woke = true;
      released++;
    }
    if (Atomics.compareExchange(hdr, HDR_WR_LOCK, owner, 0) === owner) {
      woke = true;
      released++;
    }
    if (woke) {
      Atomics.add(hdr, HDR_CHANGES, 1);
      Atomics.notify(hdr, HDR_CHANGES);
    }
  }
  if (released > 0 && notifyWord) {
    Atomics.add(notifyWord, 0, 1);
    Atomics.notify(notifyWord, 0);
  }
  return released;
}

/** Direct view over one 64 KiB unidirectional ring slot inside `SockArena`. */
export class ArenaRing {
  constructor(arenaBuffer, slot, expectedGen, owner = 1, notifyWord = null) {
    if (!Number.isInteger(slot) || slot < 0 || slot >= ARENA_SLOTS) {
      throw new RangeError(`invalid SockArena slot ${slot}`);
    }
    this.arena = arenaBuffer;
    this.slot = slot;
    this.gen = BigInt(expectedGen);
    this.owner = (owner | 0) || 1;
    this.notify = notifyWord;
    const base = slot * SLOT_BYTES;
    this.u64 = new BigUint64Array(arenaBuffer, base, 4);
    this.hdr = new Int32Array(arenaBuffer, base, HEADER_BYTES / 4);
    this.data = new Uint8Array(arenaBuffer, base + HEADER_BYTES, RING_CAPACITY);
  }

  /** Whether this slot still belongs to the generation we were constructed for. */
  get alive() {
    return Atomics.load(this.u64, U64_GEN) === this.gen;
  }

  /** Monotonic 53-bit-safe total bytes written to this ring (single 64-bit atomic load). */
  get headOffset() {
    return Number(Atomics.load(this.u64, U64_HEAD));
  }

  /** Monotonic 53-bit-safe total bytes read from this ring (single 64-bit atomic load). */
  get tailOffset() {
    return Number(Atomics.load(this.u64, U64_TAIL));
  }

  /** Queued byte count strictly bounded to `[0, RING_CAPACITY]`. */
  get queued() {
    if (!this.alive) return 0;
    const head = Atomics.load(this.u64, U64_HEAD);
    const tail = Atomics.load(this.u64, U64_TAIL);
    if (head <= tail) return 0;
    const diff = head - tail;
    return diff > RING_CAP_BIG ? RING_CAPACITY : Number(diff);
  }

  get room() {
    if (!this.alive) return 0;
    return Math.max(0, RING_CAPACITY - this.queued);
  }

  get wrClosed() {
    return !this.alive || (Atomics.load(this.hdr, HDR_FLAGS) & FLAG_WR_CLOSED) !== 0;
  }

  get rdClosed() {
    return !this.alive || (Atomics.load(this.hdr, HDR_FLAGS) & FLAG_RD_CLOSED) !== 0;
  }

  get hasAncillary() {
    return this.alive && (Atomics.load(this.hdr, HDR_FLAGS) & FLAG_HAS_ANCILLARY) !== 0;
  }

  get ancillaryOffset() {
    return Number(Atomics.load(this.u64, U64_ANCILLARY_OFFSET));
  }

  get passcred() {
    return this.alive && (Atomics.load(this.hdr, HDR_FLAGS) & FLAG_PASSCRED) !== 0;
  }

  get sockNonblock() {
    return this.alive && (Atomics.load(this.hdr, HDR_FLAGS) & FLAG_SOCK_NONBLOCK) !== 0;
  }

  pipeNonblock(end) {
    const bit = end === 'r' ? FLAG_PIPE_RD_NONBLOCK : FLAG_PIPE_WR_NONBLOCK;
    return this.alive && (Atomics.load(this.hdr, HDR_FLAGS) & bit) !== 0;
  }

  get empty() {
    return this.queued === 0 && !this.wrClosed;
  }

  changed() {
    Atomics.add(this.hdr, HDR_CHANGES, 1);
    Atomics.notify(this.hdr, HDR_CHANGES);
    if (this.notify) {
      Atomics.add(this.notify, 0, 1);
      Atomics.notify(this.notify, 0);
    }
  }

  setPasscred(enabled) {
    if (!this.alive) return;
    if (enabled) Atomics.or(this.hdr, HDR_FLAGS, FLAG_PASSCRED);
    else Atomics.and(this.hdr, HDR_FLAGS, ~FLAG_PASSCRED);
    this.changed();
  }

  setSockNonblock(enabled) {
    if (!this.alive) return;
    if (enabled) Atomics.or(this.hdr, HDR_FLAGS, FLAG_SOCK_NONBLOCK);
    else Atomics.and(this.hdr, HDR_FLAGS, ~FLAG_SOCK_NONBLOCK);
  }

  setPipeNonblock(end, enabled) {
    if (!this.alive) return;
    const bit = end === 'r' ? FLAG_PIPE_RD_NONBLOCK : FLAG_PIPE_WR_NONBLOCK;
    if (enabled) Atomics.or(this.hdr, HDR_FLAGS, bit);
    else Atomics.and(this.hdr, HDR_FLAGS, ~bit);
  }

  setAncillary(offset) {
    if (!this.alive) return;
    Atomics.store(this.u64, U64_ANCILLARY_OFFSET, BigInt(offset));
    Atomics.or(this.hdr, HDR_FLAGS, FLAG_HAS_ANCILLARY);
    this.changed();
  }

  clearAncillary() {
    if (!this.alive) return;
    Atomics.and(this.hdr, HDR_FLAGS, ~FLAG_HAS_ANCILLARY);
    this.changed();
  }

  closeWriter() {
    if (!this.alive) return;
    Atomics.or(this.hdr, HDR_FLAGS, FLAG_WR_CLOSED);
    this.changed();
  }

  closeReader() {
    if (!this.alive) return;
    Atomics.or(this.hdr, HDR_FLAGS, FLAG_RD_CLOSED);
    this.changed();
  }

  holdReader(count = 1) {
    if (!this.alive) return 0;
    return Atomics.add(this.hdr, HDR_READERS, count) + count;
  }

  dropReader(count = 1) {
    if (!this.alive) return 0;
    const left = Math.max(0, Atomics.sub(this.hdr, HDR_READERS, count) - count);
    if (left === 0) this.closeReader();
    return left;
  }

  holdWriter(count = 1) {
    if (!this.alive) return 0;
    return Atomics.add(this.hdr, HDR_WRITERS, count) + count;
  }

  dropWriter(count = 1) {
    if (!this.alive) return 0;
    const left = Math.max(0, Atomics.sub(this.hdr, HDR_WRITERS, count) - count);
    if (left === 0) this.closeWriter();
    return left;
  }

  lock(word) {
    return this.alive && Atomics.compareExchange(this.hdr, word, 0, this.owner) === 0;
  }

  unlock(word) {
    if (this.alive) {
      Atomics.compareExchange(this.hdr, word, this.owner, 0);
      this.changed();
    }
  }

  releaseLocks(pid) {
    const owner = (pid | 0) & ~HOST_LOCK_BIT;
    if (owner <= 0) return;
    let woke = false;
    if (this.alive && Atomics.compareExchange(this.hdr, HDR_RD_LOCK, owner, 0) === owner) woke = true;
    if (this.alive && Atomics.compareExchange(this.hdr, HDR_WR_LOCK, owner, 0) === owner) woke = true;
    if (woke) this.changed();
  }

  _copyIn(bytes) {
    const count = bytes.length;
    const headBig = Atomics.load(this.u64, U64_HEAD);
    const at = Number(headBig % RING_CAP_BIG);
    const first = Math.min(count, RING_CAPACITY - at);
    this.data.set(bytes.subarray(0, first), at);
    if (count > first) this.data.set(bytes.subarray(first, count), 0);
    const nextBig = headBig + BigInt(count);
    Atomics.store(this.u64, U64_HEAD, nextBig);
    this.changed();
    return { count, startOffset: Number(headBig), endOffset: Number(nextBig) };
  }

  _copyOut(count, advance = true) {
    const out = new Uint8Array(count);
    const tailBig = Atomics.load(this.u64, U64_TAIL);
    const at = Number(tailBig % RING_CAP_BIG);
    const first = Math.min(count, RING_CAPACITY - at);
    out.set(this.data.subarray(at, at + first), 0);
    if (count > first) out.set(this.data.subarray(0, count - first), first);
    if (advance) {
      Atomics.store(this.u64, U64_TAIL, tailBig + BigInt(count));
      this.changed();
    }
    return out;
  }

  /**
   * Non-blocking single write attempt. Returns `{ written, broken, startOffset, endOffset }`.
   * Rejects writes after local `SHUT_WR` (`wrClosed`) as well as peer close (`rdClosed`).
   */
  tryWrite(bytes, { atomicLimit = PIPE_ATOMIC } = {}) {
    if (!this.alive || this.rdClosed || this.wrClosed) {
      return { written: 0, broken: true, startOffset: 0, endOffset: 0 };
    }
    if (!bytes.length) {
      const off = this.headOffset;
      return { written: 0, broken: false, startOffset: off, endOffset: off };
    }
    if (!this.lock(HDR_WR_LOCK)) return { written: 0, broken: false, startOffset: 0, endOffset: 0 };
    try {
      if (!this.alive || this.rdClosed || this.wrClosed) {
        return { written: 0, broken: true, startOffset: 0, endOffset: 0 };
      }
      const want = bytes.length <= atomicLimit ? bytes.length : 1;
      const avail = this.room;
      if (avail < want) return { written: 0, broken: false, startOffset: 0, endOffset: 0 };
      const { count, startOffset, endOffset } = this._copyIn(bytes.subarray(0, Math.min(bytes.length, avail)));
      return { written: count, broken: false, startOffset, endOffset };
    } finally {
      this.unlock(HDR_WR_LOCK);
    }
  }

  /**
   * Blocking write waiting via `Atomics.wait` until all bytes are written (or either end closes).
   * Returns `{ written, broken, startOffset, endOffset }`.
   */
  write(bytes, meanwhile, { nonblock = false, atomicLimit = PIPE_ATOMIC } = {}) {
    if (nonblock) return this.tryWrite(bytes, { atomicLimit });
    if (!bytes.length) {
      if (!this.alive || this.rdClosed || this.wrClosed) {
        return { written: 0, broken: true, startOffset: 0, endOffset: 0 };
      }
      const off = this.headOffset;
      return { written: 0, broken: false, startOffset: off, endOffset: off };
    }
    let done = 0;
    let firstStart = -1;
    let lastEnd = 0;
    while (done < bytes.length) {
      const seen = Atomics.load(this.hdr, HDR_CHANGES);
      if (!this.alive || this.rdClosed || this.wrClosed) {
        return { written: done, broken: true, startOffset: firstStart < 0 ? 0 : firstStart, endOffset: lastEnd };
      }
      const want = bytes.length <= atomicLimit ? bytes.length : 1;
      if (this.room < want || !this.lock(HDR_WR_LOCK)) {
        if (Atomics.wait(this.hdr, HDR_CHANGES, seen, 50) === 'timed-out' && meanwhile?.(done) === false) {
          return { written: done, broken: false, startOffset: firstStart < 0 ? 0 : firstStart, endOffset: lastEnd };
        }
        continue;
      }
      try {
        if (!this.alive || this.rdClosed || this.wrClosed) {
          return { written: done, broken: true, startOffset: firstStart < 0 ? 0 : firstStart, endOffset: lastEnd };
        }
        const avail = this.room;
        if (avail >= want) {
          const { count, startOffset, endOffset } = this._copyIn(bytes.subarray(done, done + avail));
          if (firstStart < 0) firstStart = startOffset;
          lastEnd = endOffset;
          done += count;
        }
      } finally {
        this.unlock(HDR_WR_LOCK);
      }
    }
    return { written: done, broken: false, startOffset: firstStart < 0 ? 0 : firstStart, endOffset: lastEnd };
  }

  /**
   * Read up to `count` bytes (stopping at `maxOffset` if set, and when `stopAtAncillary` is true,
   * atomically refusing to cross `ancillaryOffset` under `HDR_RD_LOCK` by loading `U64_HEAD`
   * BEFORE checking `hasAncillary`, matching the sender's `setAncillary` -> `_copyIn` order).
   * Returns `Uint8Array` (length 0 on EOF) or `null` on `EAGAIN` / ancillary boundary hit when
   * `nonblock` is true. If `peek` is true, bytes are copied without advancing `U64_TAIL`.
   */
  read(count, meanwhile, { nonblock = false, peek = false, maxOffset = Infinity, stopAtAncillary = false } = {}) {
    if (count === 0) return new Uint8Array(0);
    for (;;) {
      if (!this.alive || this.rdClosed) return new Uint8Array(0);
      const seen = Atomics.load(this.hdr, HDR_CHANGES);
      const queued = this.queued;
      if (queued > 0 && this.lock(HDR_RD_LOCK)) {
        try {
          if (!this.alive || this.rdClosed) return new Uint8Array(0);
          // Snapshot `head` BEFORE checking `hasAncillary`: because `sendmsg` executes
          // `setAncillary` before `_copyIn` advances `U64_HEAD`, any bytes written by an
          // ancillary send that are visible in `head` guarantee `hasAncillary` is also visible.
          const tailBig = Atomics.load(this.u64, U64_TAIL);
          const headBig = Atomics.load(this.u64, U64_HEAD);
          const tail = Number(tailBig);
          let limit = maxOffset;
          if (stopAtAncillary && this.hasAncillary) {
            limit = Math.min(limit, this.ancillaryOffset);
          }
          const rawNow = headBig > tailBig ? headBig - tailBig : 0n;
          const now = rawNow > RING_CAP_BIG ? RING_CAPACITY : Number(rawNow);
          if (now > 0) {
            const allowed = Number.isFinite(limit) ? Math.max(0, limit - tail) : now;
            const take = Math.min(count, now, allowed);
            if (take > 0) return this._copyOut(take, !peek);
            if (stopAtAncillary && allowed === 0) return null;
            if (allowed === 0) return new Uint8Array(0);
          }
        } finally {
          this.unlock(HDR_RD_LOCK);
        }
        continue;
      }
      if (queued === 0 && (this.wrClosed || this.rdClosed)) return new Uint8Array(0);
      if (nonblock) return null;
      if (Atomics.wait(this.hdr, HDR_CHANGES, seen, meanwhile ? 50 : Infinity) === 'timed-out') {
        meanwhile?.();
      }
    }
  }
}

// Instance-wide 8 MiB shared-memory ring arena (`SockArena`, #55 L3b).
//
// Allocated once per OS instance in the dedicated kernel Worker (`web/wasi/exec.mjs`) and passed
// in every process Worker's initial `start` message. Unrelated Workers map any slot `0..127` into
// a zero-copy `Int32Array` atomic header + `Uint8Array` ring view with ZERO mid-syscall
// `postMessage` SAB transfers — working identically in synchronous `Atomics.wait` and JSPI modes.

export const ARENA_SLOTS = 128;
export const SLOT_BYTES = 65536; // 64 KiB per unidirectional ring
export const HEADER_BYTES = 64; // 16 x Int32 atomic header
export const RING_CAPACITY = SLOT_BYTES - HEADER_BYTES; // 65,472 bytes
export const ARENA_BYTES = ARENA_SLOTS * SLOT_BYTES; // 8,388,608 bytes (8 MiB)

// Header Int32 word offsets (per slot, 16 words total):
export const HDR_HEAD = 0; // low 32 bits of monotonic write byte offset
export const HDR_TAIL = 1; // low 32 bits of monotonic read byte offset
export const HDR_FLAGS = 2; // bit0: WR_CLOSED, bit1: RD_CLOSED, bit2: HAS_ANCILLARY
export const HDR_GEN = 3; // generation counter fenced on slot reuse
export const HDR_ANCILLARY_OFFSET_LO = 4; // low 32 bits of next AncillaryMark stream byte offset
export const HDR_ANCILLARY_OFFSET_HI = 5; // high 32 bits of next AncillaryMark stream byte offset
export const HDR_READERS = 6; // reader holder count
export const HDR_WRITERS = 7; // writer holder count
export const HDR_CHANGES = 8; // futex wakeup counter notified on every state change
export const HDR_RD_LOCK = 9; // reader mutex (owner pid or 0)
export const HDR_WR_LOCK = 10; // writer mutex (owner pid or 0)
export const HDR_HEAD_HI = 11; // high 32 bits of monotonic write byte offset
export const HDR_TAIL_HI = 12; // high 32 bits of monotonic read byte offset

export const FLAG_WR_CLOSED = 1;
export const FLAG_RD_CLOSED = 2;
export const FLAG_HAS_ANCILLARY = 4;

export const PIPE_ATOMIC = 4096;

/** Allocate one 8 MiB instance-wide SharedArrayBuffer backing 128 x 64 KiB ring slots. */
export function createSockArenaBuffer() {
  return new SharedArrayBuffer(ARENA_BYTES);
}

/**
 * Initialize or reset one slot in `arenaBuffer` for a newly allocated generation `gen`.
 * Increments/stores `HDR_GEN` and notifies `HDR_CHANGES` so stale holders unblock immediately.
 */
export function initArenaSlot(arenaBuffer, slot, gen, readers = 1, writers = 1) {
  const base = slot * SLOT_BYTES;
  const hdr = new Int32Array(arenaBuffer, base, HEADER_BYTES / 4);
  Atomics.store(hdr, HDR_HEAD, 0);
  Atomics.store(hdr, HDR_HEAD_HI, 0);
  Atomics.store(hdr, HDR_TAIL, 0);
  Atomics.store(hdr, HDR_TAIL_HI, 0);
  Atomics.store(hdr, HDR_FLAGS, 0);
  Atomics.store(hdr, HDR_ANCILLARY_OFFSET_LO, 0);
  Atomics.store(hdr, HDR_ANCILLARY_OFFSET_HI, 0);
  Atomics.store(hdr, HDR_READERS, readers);
  Atomics.store(hdr, HDR_WRITERS, writers);
  Atomics.store(hdr, HDR_RD_LOCK, 0);
  Atomics.store(hdr, HDR_WR_LOCK, 0);
  Atomics.store(hdr, HDR_GEN, gen | 0);
  Atomics.add(hdr, HDR_CHANGES, 1);
  Atomics.notify(hdr, HDR_CHANGES);
}

/**
 * Fence a freed slot with `newGen` and close both ends so any stale reader/writer fails immediately.
 */
export function fenceArenaSlot(arenaBuffer, slot, newGen) {
  const base = slot * SLOT_BYTES;
  const hdr = new Int32Array(arenaBuffer, base, HEADER_BYTES / 4);
  Atomics.or(hdr, HDR_FLAGS, FLAG_WR_CLOSED | FLAG_RD_CLOSED);
  Atomics.store(hdr, HDR_GEN, newGen | 0);
  Atomics.store(hdr, HDR_RD_LOCK, 0);
  Atomics.store(hdr, HDR_WR_LOCK, 0);
  Atomics.add(hdr, HDR_CHANGES, 1);
  Atomics.notify(hdr, HDR_CHANGES);
}

/** Direct view over one 64 KiB unidirectional ring slot inside `SockArena`. */
export class ArenaRing {
  constructor(arenaBuffer, slot, expectedGen, owner = 1) {
    if (!Number.isInteger(slot) || slot < 0 || slot >= ARENA_SLOTS) {
      throw new RangeError(`invalid SockArena slot ${slot}`);
    }
    this.arena = arenaBuffer;
    this.slot = slot;
    this.gen = expectedGen | 0;
    this.owner = (owner | 0) || 1;
    const base = slot * SLOT_BYTES;
    this.hdr = new Int32Array(arenaBuffer, base, HEADER_BYTES / 4);
    this.ancU64 = new BigUint64Array(arenaBuffer, base + HDR_ANCILLARY_OFFSET_LO * 4, 1);
    this.data = new Uint8Array(arenaBuffer, base + HEADER_BYTES, RING_CAPACITY);
  }

  /** Whether this slot still belongs to the generation we were constructed for. */
  get alive() {
    return Atomics.load(this.hdr, HDR_GEN) === this.gen;
  }

  /** Monotonic 53-bit-safe total bytes written to this ring. */
  get headOffset() {
    for (;;) {
      const hi1 = Atomics.load(this.hdr, HDR_HEAD_HI) >>> 0;
      const lo = Atomics.load(this.hdr, HDR_HEAD) >>> 0;
      const hi2 = Atomics.load(this.hdr, HDR_HEAD_HI) >>> 0;
      if (hi1 === hi2) return hi1 * 0x100000000 + lo;
    }
  }

  /** Monotonic 53-bit-safe total bytes read from this ring. */
  get tailOffset() {
    for (;;) {
      const hi1 = Atomics.load(this.hdr, HDR_TAIL_HI) >>> 0;
      const lo = Atomics.load(this.hdr, HDR_TAIL) >>> 0;
      const hi2 = Atomics.load(this.hdr, HDR_TAIL_HI) >>> 0;
      if (hi1 === hi2) return hi1 * 0x100000000 + lo;
    }
  }

  get queued() {
    if (!this.alive) return 0;
    return (Atomics.load(this.hdr, HDR_HEAD) - Atomics.load(this.hdr, HDR_TAIL)) >>> 0;
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
    return Number(Atomics.load(this.ancU64, 0));
  }

  get empty() {
    return this.queued === 0 && !this.wrClosed;
  }

  changed() {
    Atomics.add(this.hdr, HDR_CHANGES, 1);
    Atomics.notify(this.hdr, HDR_CHANGES);
  }

  setAncillary(offset) {
    if (!this.alive) return;
    Atomics.store(this.ancU64, 0, BigInt(offset));
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
    const owner = (pid | 0) || 1;
    let woke = false;
    if (this.alive && Atomics.compareExchange(this.hdr, HDR_RD_LOCK, owner, 0) === owner) woke = true;
    if (this.alive && Atomics.compareExchange(this.hdr, HDR_WR_LOCK, owner, 0) === owner) woke = true;
    if (woke) this.changed();
  }

  _storeHead(nextOffset) {
    const lo = nextOffset >>> 0;
    const hi = Math.floor(nextOffset / 0x100000000) >>> 0;
    Atomics.store(this.hdr, HDR_HEAD_HI, hi | 0);
    Atomics.store(this.hdr, HDR_HEAD, lo | 0);
  }

  _storeTail(nextOffset) {
    const lo = nextOffset >>> 0;
    const hi = Math.floor(nextOffset / 0x100000000) >>> 0;
    Atomics.store(this.hdr, HDR_TAIL_HI, hi | 0);
    Atomics.store(this.hdr, HDR_TAIL, lo | 0);
  }

  _copyIn(bytes) {
    const count = bytes.length;
    const head = this.headOffset;
    const at = head % RING_CAPACITY;
    const first = Math.min(count, RING_CAPACITY - at);
    this.data.set(bytes.subarray(0, first), at);
    if (count > first) this.data.set(bytes.subarray(first, count), 0);
    this._storeHead(head + count);
    this.changed();
    return { count, startOffset: head, endOffset: head + count };
  }

  _copyOut(count, advance = true) {
    const out = new Uint8Array(count);
    const tail = this.tailOffset;
    const at = tail % RING_CAPACITY;
    const first = Math.min(count, RING_CAPACITY - at);
    out.set(this.data.subarray(at, at + first), 0);
    if (count > first) out.set(this.data.subarray(0, count - first), first);
    if (advance) {
      this._storeTail(tail + count);
      this.changed();
    }
    return out;
  }

  /**
   * Non-blocking single write attempt. Returns `{ written, broken, startOffset, endOffset }`.
   */
  tryWrite(bytes, { atomicLimit = PIPE_ATOMIC } = {}) {
    if (!this.alive || this.rdClosed) return { written: 0, broken: true, startOffset: 0, endOffset: 0 };
    if (!bytes.length) {
      const off = this.headOffset;
      return { written: 0, broken: false, startOffset: off, endOffset: off };
    }
    if (!this.lock(HDR_WR_LOCK)) return { written: 0, broken: false, startOffset: 0, endOffset: 0 };
    try {
      if (!this.alive || this.rdClosed) return { written: 0, broken: true, startOffset: 0, endOffset: 0 };
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
   * Blocking write waiting via `Atomics.wait` until all bytes are written (or peer closes).
   * Returns `{ written, broken, startOffset, endOffset }`.
   */
  write(bytes, meanwhile, { nonblock = false, atomicLimit = PIPE_ATOMIC } = {}) {
    if (nonblock) return this.tryWrite(bytes, { atomicLimit });
    if (!bytes.length) {
      if (!this.alive || this.rdClosed) return { written: 0, broken: true, startOffset: 0, endOffset: 0 };
      const off = this.headOffset;
      return { written: 0, broken: false, startOffset: off, endOffset: off };
    }
    let done = 0;
    let firstStart = -1;
    let lastEnd = 0;
    while (done < bytes.length) {
      const seen = Atomics.load(this.hdr, HDR_CHANGES);
      if (!this.alive || this.rdClosed) {
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
        if (!this.alive || this.rdClosed) {
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
   * atomically refusing to cross `ancillaryOffset` under `HDR_RD_LOCK` by loading `headOffset`
   * BEFORE checking `hasAncillary`, matching the sender's `setAncillary` -> `_copyIn` order).
   * Returns `Uint8Array` (length 0 on EOF) or `null` on `EAGAIN` / ancillary boundary hit when
   * `nonblock` is true. If `peek` is true, bytes are copied without advancing `HDR_TAIL`.
   */
  read(count, meanwhile, { nonblock = false, peek = false, maxOffset = Infinity, stopAtAncillary = false } = {}) {
    if (count === 0) return new Uint8Array(0);
    for (;;) {
      if (!this.alive) return new Uint8Array(0);
      const seen = Atomics.load(this.hdr, HDR_CHANGES);
      const queued = this.queued;
      if (queued > 0 && this.lock(HDR_RD_LOCK)) {
        try {
          if (!this.alive) return new Uint8Array(0);
          // Snapshot `head` BEFORE checking `hasAncillary`: because `sendmsg` executes
          // `setAncillary` before `_copyIn` advances `HDR_HEAD`, any bytes written by an
          // ancillary send that are visible in `head` guarantee `hasAncillary` is also visible.
          const tail = this.tailOffset;
          const head = this.headOffset;
          let limit = maxOffset;
          if (stopAtAncillary && this.hasAncillary) {
            limit = Math.min(limit, this.ancillaryOffset);
          }
          const now = Math.max(0, head - tail);
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
      if (queued === 0 && this.wrClosed) return new Uint8Array(0);
      if (nonblock) return null;
      if (Atomics.wait(this.hdr, HDR_CHANGES, seen, meanwhile ? 50 : Infinity) === 'timed-out') {
        meanwhile?.();
      }
    }
  }
}

// What fork(2) shares of open files between processes (web/wasi/process.js), in memory they
// share: an open file description is one, whoever holds it, as Linux's struct file is.
//
// - `Shares`: the table of a fork line's open file descriptions: per description, how many
//   descriptors refer to it, in every process of the line, and its offset. Only the last close
//   closes it at the kernel, or commits what was written; a read or a write by any of them
//   moves the offset for all.
// - `Bytes`: what a file open for writing holds before it goes to the kernel (a file written in
//   order, chunk by chunk, or one rewritten whole at its close), so that each process holding
//   it writes to the same bytes, one at a time.

// A description's words in the table: in use, references, offset (low and high halves).
const SLOT = 4, USED = 0, REFS = 1, POS = 2;

export class Shares {
  constructor(buffer = new SharedArrayBuffer(512 * SLOT * 4)) {
    this.buffer = buffer;
    this.words = new Int32Array(buffer);
  }
  get slots() { return this.words.length / SLOT; }
  // A slot for a description that `refs` descriptors refer to, at offset `pos`: -1 if none is
  // free.
  claim(refs, pos) {
    for (let slot = 0; slot < this.slots; slot++) {
      if (Atomics.compareExchange(this.words, slot * SLOT + USED, 0, 1) !== 0) continue;
      Atomics.store(this.words, slot * SLOT + REFS, refs);
      this.setPos(slot, pos);
      return slot;
    }
    return -1;
  }
  add(slot, count) { Atomics.add(this.words, slot * SLOT + REFS, count); }
  // One reference fewer: how many are left; the slot is free once none is.
  drop(slot) {
    const left = Atomics.sub(this.words, slot * SLOT + REFS, 1) - 1;
    if (left <= 0) Atomics.store(this.words, slot * SLOT + USED, 0);
    return left;
  }
  pos(slot) {
    const low = Atomics.load(this.words, slot * SLOT + POS) >>> 0, high = Atomics.load(this.words, slot * SLOT + POS + 1) >>> 0;
    return high * 2 ** 32 + low;
  }
  setPos(slot, pos) {
    Atomics.store(this.words, slot * SLOT + POS, pos % 2 ** 32 | 0);
    Atomics.store(this.words, slot * SLOT + POS + 1, Math.floor(pos / 2 ** 32) | 0);
  }
  // Make the description `found` the table's slot `slot`: its offset is the slot's from now on.
  attach(found, slot) {
    found.share = slot;
    Object.defineProperty(found, 'pos', {
      configurable: true, enumerable: true,
      get: () => this.pos(slot),
      set: value => this.setPos(slot, value),
    });
  }
}

// A written file's bytes' words: the lock, how many bytes, where the first is in the file
// (low and high halves), whether they changed.
const LOCK = 0, LENGTH = 1, FROM = 2, DIRTY = 4, WORDS = 8;
const sharing = typeof SharedArrayBuffer === 'function';

export class Bytes {
  // New bytes, as many as `length` may grow to (`max`); or those of `state`, another
  // process's.
  constructor(state) {
    this.state = state;
    this.words = new Int32Array(state.words);
    this.view = new Uint8Array(state.data);
  }
  static create(max, initial = 64 * 1024) {
    const words = sharing ? new SharedArrayBuffer(WORDS * 4) : new ArrayBuffer(WORDS * 4);
    // Memory a fork shares grows where it is (a growable SharedArrayBuffer); elsewhere, as
    // much as it may hold.
    let data;
    if (sharing) {
      data = new SharedArrayBuffer(Math.min(initial, max), { maxByteLength: max });
      if (!data.growable) data = new SharedArrayBuffer(max);
    } else {
      data = new ArrayBuffer(Math.min(initial, max), { maxByteLength: max });
    }
    return new Bytes({ words, data, max });
  }
  get shareable() { return sharing; }
  get length() { return Atomics.load(this.words, LENGTH); }
  set length(value) { Atomics.store(this.words, LENGTH, value); }
  get from() { return (Atomics.load(this.words, FROM + 1) >>> 0) * 2 ** 32 + (Atomics.load(this.words, FROM) >>> 0); }
  set from(value) {
    Atomics.store(this.words, FROM, value % 2 ** 32 | 0);
    Atomics.store(this.words, FROM + 1, Math.floor(value / 2 ** 32) | 0);
  }
  get dirty() { return Atomics.load(this.words, DIRTY) === 1; }
  set dirty(value) { Atomics.store(this.words, DIRTY, value ? 1 : 0); }
  // Room for `length` bytes: false past what they may hold.
  ensure(length) {
    if (length > this.state.max) return false;
    const data = this.state.data;
    if (length <= data.byteLength) return true;
    const want = Math.min(this.state.max, Math.max(length, data.byteLength * 2));
    if (data.growable) data.grow(want);
    else if (data.resizable) data.resize(want);
    else if (!(data instanceof ArrayBuffer)) return false;
    else {
      // Bytes no other process holds (no memory is shared here) move to a larger buffer.
      const grown = new ArrayBuffer(want);
      new Uint8Array(grown).set(this.view);
      this.state.data = grown;
    }
    this.view = new Uint8Array(this.state.data);
    return length <= this.view.length;
  }
  bytes(start = 0, end = this.length) { return this.view.subarray(start, end); }
  // One holder at a time; waiting where a Worker may.
  lock() {
    while (Atomics.compareExchange(this.words, LOCK, 0, 1) !== 0) {
      if (typeof Atomics.wait === 'function') Atomics.wait(this.words, LOCK, 1, 50);
    }
  }
  unlock() { Atomics.store(this.words, LOCK, 0); Atomics.notify(this.words, LOCK); }
  // What another process needs to hold them too.
  get transferable() { return this.state; }
}

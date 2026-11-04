// What fork(2) shares of open files between processes (web/wasi/process.js), in memory they
// share: an open file description is one, whoever holds it, as Linux's struct file is.
//
// - `Shares`: the table of a process line's open file descriptions (a process its host started,
//   and what it forked): per description, how many descriptors refer to it, in every process
//   of the line, and how many each process holds (by pid), its offset, and a lock that a read
//   or a write holds from choosing its offset to moving it, so that two processes never read or
//   write at one offset. Only the last close closes it at the kernel, or commits what was
//   written; a read or a write by any of them moves the offset for all. A process that is
//   killed closes nothing itself: its host lets go of what it held (`release`), and whoever
//   then held the last reference closes the description.
// - `Bytes`: what a file open for writing holds before it goes to the kernel (a file written in
//   order, chunk by chunk, or one rewritten whole at its close), so that each process holding
//   it writes to the same bytes, one at a time.

// A description's words: in use, references, offset (low and high halves), the pid holding its
// lock, its generation (a slot used again is another description), then its holders, each a
// pid and how many references it holds.
const USED = 0, REFS = 1, POS = 2, LOCK = 4, GEN = 5, HOLDERS = 6, HOLDERS_MAX = 16;
const SLOT = HOLDERS + HOLDERS_MAX * 2, SLOTS = 512;

// Wait on `words[at]` while it is `value`, for at most `ms`, where a Worker may; `meanwhile`
// is called between waits (a signal to heed).
function waitOn(words, at, value, ms, meanwhile) {
  if (typeof Atomics.wait === 'function') Atomics.wait(words, at, value, ms);
  meanwhile?.();
}

export class Shares {
  constructor(buffer = new SharedArrayBuffer(SLOTS * SLOT * 4)) {
    this.buffer = buffer;
    this.words = new Int32Array(buffer);
  }
  get slots() { return this.words.length / SLOT; }
  at(slot, word) { return slot * SLOT + word; }
  // A slot for a description that `pid` holds `refs` references to, at offset `pos`: -1 if
  // none is free.
  claim(pid, refs, pos) {
    for (let slot = 0; slot < this.slots; slot++) {
      if (Atomics.compareExchange(this.words, this.at(slot, USED), 0, 1) !== 0) continue;
      for (let index = 0; index < HOLDERS_MAX * 2; index++) Atomics.store(this.words, this.at(slot, HOLDERS) + index, 0);
      Atomics.store(this.words, this.at(slot, REFS), 0);
      Atomics.store(this.words, this.at(slot, LOCK), 0);
      Atomics.add(this.words, this.at(slot, GEN), 1);
      this.setPos(slot, pos);
      this.add(slot, pid, refs);
      return slot;
    }
    return -1;
  }
  gen(slot) { return Atomics.load(this.words, this.at(slot, GEN)); }
  // The word counting `pid`'s references to `slot`, claimed if it holds none yet: -1 if every
  // holder's place is taken (its references are then counted, but not as its).
  holder(slot, pid, claim) {
    const first = this.at(slot, HOLDERS);
    for (let index = 0; index < HOLDERS_MAX; index++) {
      if (Atomics.load(this.words, first + index * 2) === pid) return first + index * 2 + 1;
    }
    if (!claim) return -1;
    for (let index = 0; index < HOLDERS_MAX; index++) {
      const at = first + index * 2;
      if (Atomics.compareExchange(this.words, at, 0, pid) === 0 || Atomics.load(this.words, at) === pid) return at + 1;
    }
    return -1;
  }
  // `pid` holds `count` more references to `slot` (a fork's child, its parent's).
  add(slot, pid, count) {
    const at = this.holder(slot, pid, true);
    if (at >= 0) Atomics.add(this.words, at, count);
    Atomics.add(this.words, this.at(slot, REFS), count);
  }
  // `pid` closed one of its references: how many are left, of everyone's; the slot is free
  // once none is.
  drop(slot, pid) {
    const at = this.holder(slot, pid, false);
    if (at >= 0 && Atomics.load(this.words, at) > 0) Atomics.sub(this.words, at, 1);
    return this.left(slot, Atomics.sub(this.words, this.at(slot, REFS), 1) - 1);
  }
  left(slot, refs) {
    if (refs <= 0) Atomics.store(this.words, this.at(slot, USED), 0);
    return refs;
  }
  // What the killed process `pid` held goes, as its descriptors close when it dies: the
  // descriptions it held the last references to ({slot, gen}), for its host to close, and the
  // locks it held, let go.
  release(pid) {
    const closed = [];
    for (let slot = 0; slot < this.slots; slot++) {
      if (Atomics.load(this.words, this.at(slot, USED)) === 0) continue;
      if (Atomics.compareExchange(this.words, this.at(slot, LOCK), pid, 0) === pid) Atomics.notify(this.words, this.at(slot, LOCK));
      const at = this.holder(slot, pid, false);
      if (at < 0) continue;
      const count = Atomics.exchange(this.words, at, 0);
      Atomics.store(this.words, at - 1, 0);
      if (count <= 0) continue;
      const gen = this.gen(slot);
      if (this.left(slot, Atomics.sub(this.words, this.at(slot, REFS), count) - count) <= 0) closed.push({ slot, gen });
    }
    return closed;
  }
  // The offset of `slot`, read or set where its lock is held.
  pos(slot) {
    const low = Atomics.load(this.words, this.at(slot, POS)) >>> 0, high = Atomics.load(this.words, this.at(slot, POS) + 1) >>> 0;
    return high * 2 ** 32 + low;
  }
  setPos(slot, pos) {
    Atomics.store(this.words, this.at(slot, POS), pos % 2 ** 32 | 0);
    Atomics.store(this.words, this.at(slot, POS) + 1, Math.floor(pos / 2 ** 32) | 0);
  }
  // The description's lock, held by `pid` from a read's or write's choice of its offset until
  // it moved it.
  lock(slot, pid, meanwhile) {
    const at = this.at(slot, LOCK);
    for (;;) {
      const holder = Atomics.compareExchange(this.words, at, 0, pid);
      if (holder === 0) return;
      waitOn(this.words, at, holder, 50, meanwhile);
    }
  }
  unlock(slot) {
    const at = this.at(slot, LOCK);
    Atomics.store(this.words, at, 0);
    Atomics.notify(this.words, at);
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

// A written file's bytes' words: the pid holding them (their lock), how many bytes, where the
// first is in the file (low and high halves), whether they changed.
const HOLDER = 0, LENGTH = 1, FROM = 2, DIRTY = 4, WORDS = 8;
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
  // One holder at a time (`pid`), waiting where a Worker may; `meanwhile` between waits.
  lock(pid = 1, meanwhile) {
    for (;;) {
      const holder = Atomics.compareExchange(this.words, HOLDER, 0, pid);
      if (holder === 0) return;
      waitOn(this.words, HOLDER, holder, 50, meanwhile);
    }
  }
  unlock() { Atomics.store(this.words, HOLDER, 0); Atomics.notify(this.words, HOLDER); }
  // What a killed process `pid` held, let go.
  release(pid) {
    if (Atomics.compareExchange(this.words, HOLDER, pid, 0) === pid) Atomics.notify(this.words, HOLDER);
  }
  // What another process needs to hold them too.
  get transferable() { return this.state; }
}

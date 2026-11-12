// pipe(2), between processes (web/wasi/process.js) and the page: bytes from one end to the other
// through memory both share, as the kernel's pipe buffer is. A reader waits while it is empty, a
// writer while it is full; a read at its end, once every writer is gone, reads nothing (end of
// file), and a write once every reader is gone fails (EPIPE, which a process hears as SIGPIPE).
// A terminal's input is one too, which the page writes typed lines to: there, Ctrl+D ends a read
// without ending the input, as a terminal's line discipline does.
//
// Each end may be held by several processes, as fork(2) and dup(2) share an open pipe: the
// pipe counts each holder's references to each end (`hold`, `drop`), by pid, so that an end is
// gone once its last holder closed it, and the page can let go of what a process it killed
// held (`release`), as a process's descriptors close when it dies, its locks too. Writers
// write, and readers read, one at a time: a write that fits is not mixed with another's.
//
// Waiting (Atomics.wait) is for Workers; the page only ever writes what fits, and tries again.

// The buffer a pipe holds, as Linux's: 64 KiB; and the most a write writes at once (POSIX's
// PIPE_BUF, Linux's 4 KiB).
export const PIPE_BUF = 65536;
export const PIPE_ATOMIC = 4096;
// Its state, as 32-bit words before the bytes: where reading and writing are (counts that wrap),
// whether each end is gone, ends of file pending (Ctrl+D), a count of changes to wait on, the
// writers' and the readers' locks (the pid holding each), then each holder's pid and how many
// references it holds to the reading and the writing end: as many holders as a namespace has
// processes (abi::PROC_MAX), and the page; one is never held uncounted.
const READ = 0, WRITE = 1, WRITER_GONE = 2, READER_GONE = 3, EOF = 4, CHANGES = 5, WRITING = 6, READING = 7;
const HOLDERS = 8, HOLDER = 3, HOLDERS_MAX = 65, WORDS = HOLDERS + HOLDERS_MAX * HOLDER;
// The ends, as a holder's words count them.
const ENDS = { r: 1, w: 2 };
// The page, as a holder of the ends it writes (the terminal's input).
export const PAGE = 0x7fffffff;

export const pipeBuffer = (capacity = PIPE_BUF) => new SharedArrayBuffer(WORDS * 4 + capacity);

export class Pipe {
  // The pipe of `buffer`, as the process `owner` uses it: the pid its locks are held by.
  constructor(buffer, owner = PAGE) {
    this.buffer = buffer;
    this.owner = owner;
    this.state = new Int32Array(buffer, 0, WORDS);
    this.data = new Uint8Array(buffer, WORDS * 4);
  }
  // What is there to read, and what room to write.
  get queued() { return (Atomics.load(this.state, WRITE) - Atomics.load(this.state, READ)) >>> 0; }
  get room() { return this.data.length - this.queued; }
  get readerGone() { return Atomics.load(this.state, READER_GONE) === 1; }
  get writerGone() { return Atomics.load(this.state, WRITER_GONE) === 1; }
  changed() { Atomics.add(this.state, CHANGES, 1); Atomics.notify(this.state, CHANGES); }

  // ---- Holders ----

  // The word of `pid`'s holding, claimed if it holds nothing yet: -1 where every slot is taken.
  slot(pid, claim) {
    for (let index = 0; index < HOLDERS_MAX; index++) {
      const at = HOLDERS + index * HOLDER;
      if (Atomics.load(this.state, at) === pid) return at;
    }
    if (!claim) return -1;
    for (let index = 0; index < HOLDERS_MAX; index++) {
      const at = HOLDERS + index * HOLDER;
      if (Atomics.compareExchange(this.state, at, 0, pid) === 0) return at;
      if (Atomics.load(this.state, at) === pid) return at;
    }
    return -1;
  }
  // Whether `pid` may hold an end (unlike `room`, the space left to write): it holds one, or a
  // holder's slot is free.
  holdable(pid) {
    for (let index = 0; index < HOLDERS_MAX; index++) {
      const holder = Atomics.load(this.state, HOLDERS + index * HOLDER);
      if (holder === 0 || holder === pid) return true;
    }
    return false;
  }
  // `pid` holds `count` more references to the end `end` ('r' or 'w'): false, and nothing
  // counted, if no slot is free for it.
  hold(pid, end, count = 1) {
    const at = this.slot(pid, true);
    if (at < 0) return false;
    Atomics.add(this.state, at + ENDS[end], count);
    return true;
  }
  // `pid` closed `count` of its references to `end`: the end is gone once none holds it.
  drop(pid, end, count = 1) {
    const at = this.slot(pid, false);
    if (at < 0) return;
    const word = at + ENDS[end], taken = Math.min(count, Atomics.load(this.state, word));
    if (Atomics.sub(this.state, word, taken) - taken > 0) return;
    // A holder of nothing gives its slot back.
    if (Atomics.load(this.state, at + ENDS.r) === 0 && Atomics.load(this.state, at + ENDS.w) === 0) Atomics.compareExchange(this.state, at, pid, 0);
    this.settle(end);
  }
  // What `pid` held goes, as a process's descriptors close when it ends: by its own closes, or
  // by its host's, for one it killed.
  release(pid) {
    for (const word of [WRITING, READING]) {
      if (Atomics.compareExchange(this.state, word, pid, 0) === pid) this.changed();
    }
    const at = this.slot(pid, false);
    if (at < 0) return;
    const held = ['r', 'w'].filter(end => Atomics.exchange(this.state, at + ENDS[end], 0) > 0);
    Atomics.store(this.state, at, 0);
    for (const end of held) this.settle(end);
  }
  // How many references every holder has to `end`.
  held(end) {
    let count = 0;
    for (let index = 0; index < HOLDERS_MAX; index++) count += Atomics.load(this.state, HOLDERS + index * HOLDER + ENDS[end]);
    return count;
  }
  // The end `end`, which a holder let go of, is gone if no holder holds it any more. Only that
  // end: the other may have a writer that holds nothing here (the page, writing the terminal).
  settle(end) {
    if (this.held(end) > 0) return;
    if (end === 'w' && !this.writerGone) this.closeWriter();
    if (end === 'r' && !this.readerGone) this.closeReader();
  }

  // ---- Reading ----

  // Read at most `count` bytes, waiting for some: none at the end, or where Ctrl+D ended a read.
  // `meanwhile`, if given, is called now and then as it waits (a stop to heed).
  read(count, meanwhile, line = false, nonblock = false) {
    for (;;) {
      const seen = Atomics.load(this.state, CHANGES), queued = this.queued;
      if (queued > 0 && this.lock(READING)) {
        try {
          const now = this.queued;
          if (now > 0) {
            let length = Math.min(count, now);
            if (line) {
              const start = Atomics.load(this.state, READ) >>> 0;
              for (let i = 0; i < length; i++) if (this.data[(start + i) % this.data.length] === 10) { length = i + 1; break; }
            }
            return this.take(length);
          }
        } finally { this.unlock(READING); }
        continue;
      }
      if (queued === 0 && this.ending) { Atomics.sub(this.state, EOF, 1); return new Uint8Array(0); }
      if (queued === 0 && this.writerGone) return new Uint8Array(0);
      if (nonblock) return null;
      if (Atomics.wait(this.state, CHANGES, seen, meanwhile ? 200 : Infinity) === 'timed-out') meanwhile?.();
    }
  }
  // Whether a read would wait; whether one is to end with nothing (Ctrl+D) before more is read.
  get empty() { return this.queued === 0 && !this.ending && !this.writerGone; }
  get ending() { return Atomics.load(this.state, EOF) > 0; }
  take(count) {
    const out = new Uint8Array(count), read = Atomics.load(this.state, READ), at = (read >>> 0) % this.data.length;
    const first = Math.min(count, this.data.length - at);
    out.set(this.data.subarray(at, at + first));
    out.set(this.data.subarray(0, count - first), first);
    Atomics.store(this.state, READ, (read + count) | 0);
    this.changed();
    return out;
  }

  // ---- Writing ----

  // One nonblocking attempt. PIPE_BUF-sized writes remain atomic even with other
  // writers; a larger write may report partial progress without ever waiting.
  tryWrite(bytes) {
    if (!bytes.length) return { written: 0, broken: false };
    if (this.readerGone) return { written: 0, broken: true };
    if (!this.lock(WRITING)) return { written: 0, broken: false };
    try {
      if (this.readerGone) return { written: 0, broken: true };
      const want = bytes.length <= PIPE_ATOMIC ? bytes.length : 1;
      return { written: this.room >= want ? this.copy(bytes.subarray(0, this.room)) : 0, broken: false };
    } finally { this.unlock(WRITING); }
  }

  // Write bytes, waiting for room. Report partial progress and whether every reader is gone.
  // Returning false from `meanwhile(written)` interrupts the write without losing progress.
  // A write of at most
  // PIPE_ATOMIC bytes goes at once, not mixed with another writer's, as POSIX has it; a longer one
  // goes as room comes. `meanwhile`, if given, is called as it waits (a signal to heed).
  write(bytes, meanwhile) {
    let done = 0;
    while (done < bytes.length) {
      const seen = Atomics.load(this.state, CHANGES);
      if (this.readerGone) return { written: done, broken: true };
      const want = bytes.length <= PIPE_ATOMIC ? bytes.length : 1;
      if (this.room < want || !this.lock(WRITING)) {
        if (Atomics.wait(this.state, CHANGES, seen, 200) === 'timed-out' && meanwhile?.(done) === false) return { written: done, broken: false };
        continue;
      }
      try {
        const room = this.room;
        if (room >= want) done += this.copy(bytes.subarray(done, done + room));
      } finally { this.unlock(WRITING); }
    }
    return { written: done, broken: false };
  }
  // Write what fits of `bytes`, waiting for nothing: how much (none while another writes).
  put(bytes) {
    if (!this.lock(WRITING)) return 0;
    try { return this.copy(bytes.subarray(0, Math.min(bytes.length, this.room))); } finally { this.unlock(WRITING); }
  }
  copy(bytes) {
    const count = bytes.length;
    const write = Atomics.load(this.state, WRITE), at = (write >>> 0) % this.data.length;
    const first = Math.min(count, this.data.length - at);
    this.data.set(bytes.subarray(0, first), at);
    this.data.set(bytes.subarray(first, count), 0);
    Atomics.store(this.state, WRITE, (write + count) | 0);
    this.changed();
    return count;
  }
  lock(word) { return Atomics.compareExchange(this.state, word, 0, this.owner) === 0; }
  unlock(word) { Atomics.store(this.state, word, 0); this.changed(); }

  // Ctrl+D: the read waiting, or the next, ends with nothing.
  endOfFile() { Atomics.add(this.state, EOF, 1); this.changed(); }
  discard() {
    // The kernel flushes input while a reader may hold the read lock. Retry at the caller
    // rather than moving the cursor under a concurrent read.
    if (!this.lock(READING)) return false;
    try { Atomics.store(this.state, READ, Atomics.load(this.state, WRITE)); Atomics.store(this.state, EOF, 0); }
    finally { this.unlock(READING); }
    return true;
  }
  // An end gone at once, whoever holds it: one its process never started to hold.
  closeWriter() { Atomics.store(this.state, WRITER_GONE, 1); this.changed(); }
  closeReader() { Atomics.store(this.state, READER_GONE, 1); this.changed(); }
}

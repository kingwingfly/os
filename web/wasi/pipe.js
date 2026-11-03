// pipe(2), between processes (web/wasi/process.js) and the page: bytes from one end to the other
// through memory both share, as the kernel's pipe buffer is. A reader waits while it is empty, a
// writer while it is full; a read at its end, once the writer is gone, reads nothing (end of
// file), and a write once the reader is gone fails (EPIPE, which a process hears as SIGPIPE). A
// terminal's input is one too, which the page writes typed lines to: there, Ctrl+D ends a read
// without ending the input, as a terminal's line discipline does.
//
// Waiting (Atomics.wait) is for Workers; the page only ever writes what fits, and tries again.

// The buffer a pipe holds, as Linux's: 64 KiB.
export const PIPE_BUF = 65536;
// Its state, as 32-bit words before the bytes: where reading and writing are (counts that wrap),
// whether each end is gone, ends of file pending (Ctrl+D), and a count of changes to wait on.
const READ = 0, WRITE = 1, WRITER_GONE = 2, READER_GONE = 3, EOF = 4, CHANGES = 5, WORDS = 8;

export const pipeBuffer = (capacity = PIPE_BUF) => new SharedArrayBuffer(WORDS * 4 + capacity);

export class Pipe {
  constructor(buffer) {
    this.state = new Int32Array(buffer, 0, WORDS);
    this.data = new Uint8Array(buffer, WORDS * 4);
  }
  // What is there to read, and what room to write.
  get queued() { return (Atomics.load(this.state, WRITE) - Atomics.load(this.state, READ)) >>> 0; }
  get room() { return this.data.length - this.queued; }
  get readerGone() { return Atomics.load(this.state, READER_GONE) === 1; }
  get writerGone() { return Atomics.load(this.state, WRITER_GONE) === 1; }
  changed() { Atomics.add(this.state, CHANGES, 1); Atomics.notify(this.state, CHANGES); }

  // Read at most `count` bytes, waiting for some: none at the end, or where Ctrl+D ended a read.
  read(count) {
    for (;;) {
      const seen = Atomics.load(this.state, CHANGES), queued = this.queued;
      if (queued > 0) return this.take(Math.min(count, queued));
      if (this.ending) { Atomics.sub(this.state, EOF, 1); return new Uint8Array(0); }
      if (this.writerGone) return new Uint8Array(0);
      Atomics.wait(this.state, CHANGES, seen);
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

  // Write all of `bytes`, waiting for room: false if the reader is gone.
  write(bytes) {
    let done = 0;
    while (done < bytes.length) {
      const seen = Atomics.load(this.state, CHANGES);
      if (this.readerGone) return false;
      const room = this.room;
      if (room === 0) { Atomics.wait(this.state, CHANGES, seen); continue; }
      done += this.put(bytes.subarray(done, done + room));
    }
    return true;
  }
  // Write what fits of `bytes`, waiting for nothing: how much.
  put(bytes) {
    const count = Math.min(bytes.length, this.room);
    const write = Atomics.load(this.state, WRITE), at = (write >>> 0) % this.data.length;
    const first = Math.min(count, this.data.length - at);
    this.data.set(bytes.subarray(0, first), at);
    this.data.set(bytes.subarray(first, count), 0);
    Atomics.store(this.state, WRITE, (write + count) | 0);
    this.changed();
    return count;
  }

  // Ctrl+D: the read waiting, or the next, ends with nothing.
  endOfFile() { Atomics.add(this.state, EOF, 1); this.changed(); }
  closeWriter() { Atomics.store(this.state, WRITER_GONE, 1); this.changed(); }
  closeReader() { Atomics.store(this.state, READER_GONE, 1); this.changed(); }
}

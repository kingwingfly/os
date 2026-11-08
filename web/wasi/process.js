// A process (owner's design, 2026-10-29: the page is user space, the API its system calls): a
// program built for wasm32-wasip1, or for WASIX, run in a Worker of its own. Its WASI calls are
// made here over the kernel's (POST /api/sys, GET /api/file, PUT /api/pwrite), and block, as a
// program's calls do (change request 4): where the engine can suspend the image on a promise
// (JSPI: the imports that may ask the kernel are WebAssembly.Suspending, `_start` runs
// WebAssembly.promising), a call that asks the kernel is a fetch the image is suspended on, and
// the Worker is free while it is answered; elsewhere, and for an image with a start function
// (which runs as it is instantiated, outside promising), a synchronous XHR. The code is the same
// for both: what may ask the kernel is a generator that yields its requests (`request`), and
// `drive` sends them. What waits on shared memory still blocks the Worker either way
// (`Atomics.wait`): a pipe's read or write, a sleep, the stop word, the host's answer to a call
// it waits on. `terminal.sys` reaches the kernel's own calls, which WASI has no words for
// (modes, owners, ACLs, devices, accounts). WASIX's (`wasix_32v1`) are WASI's and a process's
// own: fork, execve, wait, pipe, dup, the working directory, setjmp and longjmp (phase 3).
//
// Started with {module, memory, startSection, argv, env, cwd, pid, ppid, proc, umask, sudo,
// stdin, stdout, stderr, control, channel, shares}: `startSection`, the loader's word that the
// image has a start function; standard input is {data} (bytes given whole) or {pipe} (a pipe's
// buffer, web/wasi/pipe.js), the terminal if {tty}; standard output {pipe}, or the page's, a
// terminal if {tty}, whose reader may close it ({closed}, a word of shared memory); standard
// error {tty}; {control}, the word the page signals it by (stopped, continued, or ended, which
// it heeds at its next call, closing what it has open as an exit does); {channel}, memory its
// host answers its waiting calls in (wait, execve); {shares}, its line's table of open files
// (web/wasi/shared.js). A fork's child is started with {fork}: its parent's memory, globals,
// descriptors and stack, rewound in it. It posts {out, fd} as it writes to the page, {reading}
// as it waits on the terminal, {stopped} and {continued}, {described} as it opens a file of the
// kernel's and {closed} as it closes one ({slot, gen}, and the description, for its host to
// close should it be killed), {fork} as it forks, {host} as it asks its host, and {exit, signal}
// as it ends; it is posted {forked} (a fork's answer) and {image} (an execve's: module, memory,
// startSection, token, argv, env). Started with {close: descriptions} instead, it closes them,
// as the process that held them last would have, and exits: what its host does for a process
// it had to kill outright.
//
// fork(2) is binaryen's asyncify (web/wasi/fork.js): the loader adds it to an image that
// imports fork, setjmp or longjmp, and a fork unwinds the image, copies it into a child, and
// rewinds both. The pid, the child's registration and the reaping are the client kernel's
// (crates/client-kernel); the open files the child shares are memory both share
// (web/wasi/shared.js), and pipes count their holders (web/wasi/pipe.js).
import { Pipe, pipeBuffer } from './pipe.js';
import { Engine } from './fork.js';
import { Bytes, Shares } from './shared.js';

// WASI's errno numbers, by Linux's names, as the kernel answers.
const ERRNO = {
  E2BIG: 1, EACCES: 2, EAGAIN: 6, EBADF: 8, EBUSY: 10, ECANCELED: 11, ECHILD: 12, EEXIST: 20, EFBIG: 22, EINTR: 27,
  EINVAL: 28, EIO: 29, EISDIR: 31, ELOOP: 32, EMFILE: 33, EMLINK: 34, ENAMETOOLONG: 37, ENODEV: 43, ENOENT: 44,
  ENOEXEC: 45, ENOMEM: 48, ENOSPC: 51, ENOSYS: 52, ENOTDIR: 54, ENOTEMPTY: 55, ENOTSUP: 58, EOPNOTSUPP: 58,
  ENOTTY: 59, ENXIO: 60, EPERM: 63, EPIPE: 64, ERANGE: 68, EROFS: 69, ESPIPE: 70, ESRCH: 71, ESTALE: 72,
  ETIMEDOUT: 73, ETXTBSY: 74, EXDEV: 75, ENODATA: 44,
};
const { EBADF, EINVAL, EIO, EISDIR, ENOENT, ENOSYS, ENOTDIR, ESPIPE, EFBIG } = ERRNO;
// What an execve that fails says, as a shell says it.
const STRERROR = { 2: 'Permission denied', 44: 'No such file or directory', 45: 'Exec format error', 54: 'Not a directory', 31: 'Is a directory' };
// The kinds of descriptor standard input and output are: bytes given, the page's, a pipe's end.
const STDIO = new Set(['in', 'out', 'pipe-in', 'pipe-out']);
// What a file is, as WASI numbers it.
const CHARACTER_DEVICE = 2, DIRECTORY = 3, REGULAR_FILE = 4, SYMBOLIC_LINK = 7, UNKNOWN = 0;
// open(2)'s flags, as the kernel takes them (Linux's).
const O_RDONLY = 0, O_WRONLY = 1, O_RDWR = 2, O_CREAT = 0o100, O_EXCL = 0o200, O_TRUNC = 0o1000;
const W_OK = 2;
// path_open's: oflags, fdflags, lookupflags, and the rights a descriptor has.
const OFLAG_CREAT = 1, OFLAG_DIRECTORY = 2, OFLAG_EXCL = 4, OFLAG_TRUNC = 8, FDFLAG_APPEND = 1, FOLLOW = 1;
const RIGHT_READ = 1n << 1n, RIGHT_SEEK = 1n << 2n, RIGHT_TELL = 1n << 5n, RIGHT_WRITE = 1n << 6n;
const ALL_RIGHTS = (1n << 30n) - 1n;
// The most a call carries in a batch (abi::INLINE_MAX), what a read fetches at a time, and the
// most of an existing file rewritten here (a write to one not truncated, an append).
const INLINE = 256 * 1024, WINDOW = 4 << 20, REWRITE_MAX = 64 << 20;

// The end of the process: its exit status, and the signal that ended it, if one did.
class Exit { constructor(code, signal) { this.code = code; this.signal = signal; } }
const killedBy = signal => new Exit(128 + signal, signal);
const SIGABRT = 6, SIGPIPE = 13;
// execve(2) went through: the image ends here, and the new one starts in its place.
class Replaced {}
class Errno extends Error { constructor(errno) { super(String(errno)); this.errno = errno; } }
const errnoOf = err => ERRNO[err?.errno] ?? EIO;

// The image running, its memory, and its fork engine; the process.
let memory, instance, engine, process = {};
const view = () => new DataView(memory.buffer);
const bytes = () => new Uint8Array(memory.buffer);
const encoder = new TextEncoder(), decoder = new TextDecoder();
const string = (ptr, len) => decoder.decode(bytes().slice(ptr, ptr + len));
const base64 = data => { let text = ''; for (let i = 0; i < data.length; i += 0x8000) text += String.fromCharCode(...data.subarray(i, i + 0x8000)); return btoa(text); };
const unbase64 = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));

// ---- The kernel ----

// Descriptors to close with the next batch: a read one's close can wait for it.
let closing = [];
// What stat and lstat said of paths, while nothing this process did changed anything.
const cache = new Map();
const forget = () => cache.clear();

// A request to the kernel, as the code that needs it yields it (each function that may make one
// is a generator, `yield*` from the one that calls it): the driver (`drive`) sends it and goes on
// with the answer, {status, text, bytes}. Where the engine can suspend a call (JSPI), it is a
// fetch, and the Worker waits on nothing while it is answered; elsewhere, synchronous XHR.
function* request(method, url, body, headers = {}, binary = false) {
  return yield { method, url, body, headers, binary };
}
function sendSync({ method, url, body, headers, binary }) {
  const xhr = new XMLHttpRequest();
  xhr.open(method, url, false);
  if (binary) xhr.responseType = 'arraybuffer';
  for (const [name, value] of Object.entries(headers)) xhr.setRequestHeader(name, value);
  try { xhr.send(body ?? null); } catch { throw new Errno(EIO); }
  return { status: xhr.status, text: binary ? '' : xhr.responseText, bytes: binary ? new Uint8Array(xhr.response) : null };
}
// A transfer that fails, sent or read back, is EIO, as XHR's is.
async function send({ method, url, body, headers, binary }) {
  try {
    const response = await fetch(url, { method, body: body ?? undefined, headers });
    return { status: response.status, text: binary ? '' : await response.text(), bytes: binary ? new Uint8Array(await response.arrayBuffer()) : null };
  } catch { throw new Errno(EIO); }
}
// Whether the engine can suspend an image on a promise (JSPI: WebAssembly.Suspending and
// promising), and whether the image running is suspended so: not one with a start function,
// which runs as it is instantiated, outside any promising frame (a suspendable call there fails,
// SuspendError, whatever it returns).
const capable = typeof WebAssembly.Suspending === 'function' && typeof WebAssembly.promising === 'function';
let suspending = false;
// Run `work`, a generator of the kernel's requests, to its end: its value, at once if it asked
// nothing (a write to the terminal, a pipe), else as the driver has it: at once by synchronous
// XHR, or a promise of it, by fetch, where the image is suspended meanwhile.
function drive(work) {
  let step = work.next();
  if (step.done) return step.value;
  if (!suspending) {
    while (!step.done) {
      let answer;
      try { answer = sendSync(step.value); } catch (error) { step = work.throw(error); continue; }
      step = work.next(answer);
    }
    return step.value;
  }
  return (async () => {
    while (!step.done) {
      let answer;
      try { answer = await send(step.value); } catch (error) { step = work.throw(error); continue; }
      step = work.next(answer);
    }
    return step.value;
  })();
}
// A batch of calls: each one's result, {ok} or {err}. Descriptors to close go after them, so
// that a call's {ref: i} names the i-th of `calls`. A process's batch carries the pid and token
// its exec gave it (crates/client-kernel): the kernel runs it as that process, with the
// credentials snapshotted at exec.
function* batch(calls) {
  const sent = [...calls, ...closing.map(fd => ({ close: { fd } }))];
  closing = [];
  const body = { calls: sent, umask: process.umask, sudo: process.sudo };
  if (process.pid) body.pid = process.pid;
  if (process.proc) body.proc = process.proc;
  const answer = yield* request('POST', '/api/sys', JSON.stringify(body), { 'Content-Type': 'application/json' });
  if (answer.status !== 200) return calls.map(() => ({ err: { errno: 'EIO' } }));
  return JSON.parse(answer.text).results.slice(0, calls.length);
}
// One call: its value, or an Errno thrown.
function* call(one) {
  const [result] = yield* batch([one]);
  if ('err' in result) throw new Errno(errnoOf(result.err));
  return result.ok;
}
const ok = result => { if ('err' in result) throw new Errno(errnoOf(result.err)); return result.ok; };
function* stat(path, follow = true) {
  const key = (follow ? 's:' : 'l:') + path;
  if (cache.has(key)) return cache.get(key);
  const found = yield* call(follow ? { stat: { path } } : { lstat: { path } });
  cache.set(key, found);
  return found;
}
// Bytes `start`..`end` of the file at `path`, by a ranged GET: by its descriptor's token, which
// the Worker serves without asking the kernel each time, if it has one. A process's request
// carries the process's token: the kernel answers as whom it was executed.
function* range(path, start, end, token) {
  const url = token ? '/api/file?token=' + encodeURIComponent(token) : '/api/file?path=' + encodeURIComponent(path);
  const headers = { Range: `bytes=${start}-${end - 1}` };
  if (process.proc) headers['X-Process-Token'] = process.proc;
  const answer = yield* request('GET', url, null, headers, true);
  if (answer.status === 416) return new Uint8Array(0);
  if (answer.status !== 200 && answer.status !== 206) throw new Errno(answer.status === 404 ? ENOENT : answer.status === 403 ? ERRNO.EACCES : EIO);
  return answer.bytes;
}
// The whole of a file, for one written here anew.
function* whole(path, size) {
  if (size > REWRITE_MAX) throw new Errno(EFBIG);
  if (size <= INLINE) return unbase64((yield* call({ pread: { path, count: INLINE } })).data);
  return yield* range(path, 0, size);
}
const join = (dir, path) => path.startsWith('/') ? path : (dir === '/' ? '' : dir) + '/' + (path === '.' ? '' : path).replace(/^\.\//, '');
const clean = path => path.length > 1 ? path.replace(/\/+$/, '').replace(/\/\/+/g, '/') || '/' : path;

// ---- Descriptors ----

// What each descriptor is: the terminal or a pipe (in, out), a directory, or a file read through
// a kernel descriptor (kfd), one written (in order, in chunks), or one rewritten here whole.
// Several descriptors may be one open file (dup, fork): `refs` counts this process's; its line's
// table (`shares`, where memory may be shared) counts every process's, by pid, and holds its
// offset, so that its host can close what a process it killed held last.
const fds = new Map();
// The descriptors an execve closes (FD_CLOEXEC).
const cloexec = new Set();
let shares = null;
function descriptor(fd) { const found = fds.get(fd); if (!found) throw new Errno(EBADF); return found; }
// The lowest descriptor free from `min` on, as open(2) and dup(2) take.
function lowest(min = 0) { let fd = min; while (fds.has(fd)) fd++; return fd; }
// `fd` is `found`, one more descriptor of it; a pipe's end is held once more, a shared open
// file counted once more (unless what started this process counted it already: its host, for
// the pipes it gave, or its parent, for what it forked with).
function install(fd, found, counted = false) {
  found.refs = (found.refs ?? 0) + 1;
  fds.set(fd, found);
  if (counted) return;
  if (found.kind === 'pipe-in') found.pipe.hold(process.pid, 'r');
  else if (found.kind === 'pipe-out') found.pipe.hold(process.pid, 'w');
  else if (found.share != null) shares.add(found.share, process.pid, 1);
  else if (shares && found.kind === 'file') share(found);
}
// A file of the kernel's, just opened, in its line's table: its host is told of it.
function share(found) {
  const slot = shares.claim(process.pid, found.refs, found.pos ?? 0);
  if (slot < 0) return;
  shares.attach(found, slot);
  postMessage({ described: { slot, gen: shares.gen(slot), description: describe(found) } });
}
// close(2) of `fd`: its open file closes once no descriptor of it is left, here or in another
// process.
function* uninstall(fd) {
  const found = descriptor(fd);
  fds.delete(fd);
  cloexec.delete(fd);
  found.refs--;
  if (found.kind === 'pipe-in') return found.pipe.drop(process.pid, 'r');
  if (found.kind === 'pipe-out') return found.pipe.drop(process.pid, 'w');
  if (found.share != null) {
    const gen = shares.gen(found.share);
    if (shares.drop(found.share, process.pid) > 0) return;
    postMessage({ closed: { slot: found.share, gen } });
  } else if (found.refs > 0) return;
  yield* closeFd(found);
}
// `work`, a generator, holding the lock of `found`'s description, where processes share it: a
// read or write chooses its offset and moves it with no other's in between.
function* exclusive(found, work) {
  if (found.share == null || !shares) return yield* work();
  shares.lock(found.share, process.pid, pause);
  try { return yield* work(); } finally { shares.unlock(found.share); }
}
function filetype(found) {
  if (STDIO.has(found.kind)) return found.tty ? CHARACTER_DEVICE : UNKNOWN;
  if (found.kind === 'dir') return DIRECTORY;
  return REGULAR_FILE;
}
function kindOf(mode) {
  switch (mode & 0o170000) {
    case 0o040000: return DIRECTORY;
    case 0o120000: return SYMBOLIC_LINK;
    case 0o020000: return CHARACTER_DEVICE;
    default: return REGULAR_FILE;
  }
}
const nanos = (seconds, nsec = 0) => BigInt(seconds ?? 0) * 1000000000n + BigInt(nsec ?? 0);
function writeFilestat(ptr, found) {
  const v = view();
  v.setBigUint64(ptr, 1n, true);
  v.setBigUint64(ptr + 8, BigInt(found.ino ?? 0), true);
  v.setUint8(ptr + 16, found.filetype ?? kindOf(found.mode));
  v.setBigUint64(ptr + 24, BigInt(found.nlink ?? 1), true);
  v.setBigUint64(ptr + 32, BigInt(found.size ?? 0), true);
  v.setBigUint64(ptr + 40, nanos(found.atime ?? found.mtime, found.atime_nsec ?? found.mtime_nsec), true);
  v.setBigUint64(ptr + 48, nanos(found.mtime, found.mtime_nsec), true);
  v.setBigUint64(ptr + 56, nanos(found.ctime, found.ctime_nsec), true);
}
// What a descriptor's file is now, as fstat says.
function* fstat(found) {
  if (STDIO.has(found.kind)) return { filetype: filetype(found), mode: found.tty ? 0o020620 : 0o010600 };
  if (found.kind === 'dir') return yield* stat(found.path);
  if (found.writer || found.rewrite) {
    const now = Math.floor(Date.now() / 1000);
    return { ...(found.stat ?? {}), filetype: REGULAR_FILE, size: size(found), mtime: now, ctime: now };
  }
  return found.stat ?? (yield* stat(found.path));
}
const size = found => found.rewrite ? found.bytes.length : found.writer ? found.bytes.from + found.bytes.length : found.size;

// Open the file at `path` for reading: the descriptor, its first bytes and its stat, in one
// request.
function* openRead(path) {
  const [opened, read, stated] = yield* batch([{ open: { path, flags: O_RDONLY } }, { pread: { fd: { ref: 0 }, count: INLINE } }, { stat: { path } }]);
  if (opened.err?.errno === 'EISDIR') return { kind: 'dir', path };
  const { fd, token } = ok(opened);
  // What cannot be read closes, as it goes: a directory, opened as open(2) opens one, is one.
  if ('err' in read) {
    closing.push(fd);
    if (read.err.errno === 'EISDIR') return { kind: 'dir', path };
    ok(read);
  }
  const first = read.ok;
  return { kind: 'file', path, kfd: fd, token, read: true, pos: 0, size: first.size, window: { start: 0, data: unbase64(first.data) }, stat: stated.ok };
}
// Open it for writing in order: a growing file, truncated or new. What is not sent yet is held
// in memory a fork shares (shared.js): at most two chunks and an inline write.
function* openWriter(path, flags, read) {
  const opened = yield* call({ open: { path, flags: flags | O_WRONLY } });
  forget();
  const chunk = opened.chunk_size || (8 << 20);
  return { kind: 'file', path, kfd: opened.fd, writer: true, read, chunk, bytes: Bytes.create(chunk * 2 + INLINE), pos: 0 };
}
// Open an existing file to change in place, or append to: its content, written back whole when
// it closes, if it changed.
function* openRewrite(path, found, append, read) {
  const [allowed] = yield* batch([{ access: { path, mode: W_OK } }]);
  ok(allowed);
  const data = yield* whole(path, found.size);
  const bytes = Bytes.create(REWRITE_MAX, Math.max(data.length, 64 * 1024));
  bytes.ensure(data.length);
  bytes.view.set(data);
  bytes.length = data.length;
  return { kind: 'file', path, rewrite: true, read, bytes, pos: append ? data.length : 0, append, stat: found };
}

function* readFrom(found, at, count) {
  if (found.kind === 'dir') throw new Errno(EISDIR);
  if (found.kind === 'in') {
    const out = found.data.subarray(found.pos, found.pos + count);
    found.pos += out.length;
    return out;
  }
  if (found.kind === 'pipe-in') {
    if (count === 0) return new Uint8Array(0);
    // A read that waits shows what was written first; on the terminal, the page hears it asks.
    if (found.pipe.empty) { flush(); if (found.tty) postMessage({ reading: true }); }
    const read = found.pipe.read(count, pause);
    pause();
    return read;
  }
  if (found.kind === 'out' || found.kind === 'pipe-out') throw new Errno(EBADF);
  if (!found.read) throw new Errno(EBADF);
  if (found.rewrite) return found.bytes.bytes(at, Math.min(found.bytes.length, at + count)).slice();
  if (found.writer) {
    const { from, length } = found.bytes;
    if (at < from) throw new Errno(ESPIPE);
    return found.bytes.bytes(at - from, Math.min(length, at - from + count)).slice();
  }
  const window = found.window;
  if (at < window.start || at >= window.start + window.data.length) {
    if (at >= found.size) return new Uint8Array(0);
    const want = Math.max(count, INLINE);
    if (want <= INLINE) {
      const read = yield* call({ pread: { fd: found.kfd, offset: at, count: want } });
      found.size = read.size;
      found.window = { start: at, data: unbase64(read.data) };
    } else {
      found.window = { start: at, data: (yield* range(found.path, at, Math.min(found.size, at + Math.min(want, WINDOW)), found.token)) };
    }
  }
  const from = at - found.window.start;
  return found.window.data.subarray(from, from + count);
}

function* writeTo(found, at, data) {
  // A pipe whose reader is gone, or the page's whose reader has closed its end (head, with its
  // lines): SIGPIPE, whose default is to end the process, quietly.
  if (found.kind === 'out') {
    if (found.closed && Atomics.load(found.closed, 0)) { flush(); throw killedBy(SIGPIPE); }
    output(found.fd, data);
    return data.length;
  }
  if (found.kind === 'pipe-out') {
    // A write that waits for room shows what was written first.
    if (found.pipe.room < data.length) flush();
    if (!found.pipe.write(data, pause)) { flush(); throw killedBy(SIGPIPE); }
    return data.length;
  }
  if (found.kind === 'pipe-in') throw new Errno(EBADF);
  if (found.kind !== 'file' || (!found.writer && !found.rewrite)) throw new Errno(EBADF);
  const bytes = found.bytes;
  bytes.lock(process.pid, pause);
  try {
    if (found.rewrite) {
      if (found.append) at = bytes.length;
      const end = at + data.length;
      if (end > REWRITE_MAX || !bytes.ensure(end)) throw new Errno(EFBIG);
      // A hole is zeros, whatever a truncation left.
      if (at > bytes.length) bytes.view.fill(0, bytes.length, at);
      bytes.view.set(data, at);
      bytes.length = Math.max(bytes.length, end);
      bytes.dirty = true;
      return data.length;
    }
    // Written in order: whole chunks go before more is held, and at most a chunk at a time is
    // added, so that what is held stays within two chunks.
    for (let done = 0; done < data.length;) {
      while (bytes.length > found.chunk) (yield* flushChunk(found));
      const offset = at + done - bytes.from;
      if (offset < 0) throw new Errno(ESPIPE);
      const piece = data.subarray(done, done + found.chunk);
      if (!bytes.ensure(offset + piece.length)) throw new Errno(EFBIG);
      if (offset > bytes.length) bytes.view.fill(0, bytes.length, offset);
      bytes.view.set(piece, offset);
      bytes.length = Math.max(bytes.length, offset + piece.length);
      done += piece.length;
    }
    return data.length;
  } finally { bytes.unlock(); }
}
// Send the next chunk, whole, or the last, short (its bytes' lock held).
function* flushChunk(found) {
  const bytes = found.bytes;
  const count = Math.min(found.chunk, bytes.length);
  const chunk = bytes.bytes(0, count).slice();
  const index = bytes.from / found.chunk;
  const headers = { 'Content-Type': 'application/octet-stream' };
  if (process.proc) headers['X-Process-Token'] = process.proc;
  const answer = yield* request('PUT', `/api/pwrite?fd=${found.kfd}&index=${index}`, chunk, headers);
  if (answer.status >= 300) throw new Errno(errnoOf(safeJson(answer.text)));
  bytes.view.copyWithin(0, count, bytes.length);
  bytes.length -= count;
  bytes.from += count;
}
const safeJson = text => { try { return JSON.parse(text); } catch { return {}; } };

// Close an open file, its last descriptor gone: what it wrote goes, with the close, in one
// request where it can.
function* closeFd(found) {
  if (found.kind === 'file' && found.writer) {
    const bytes = found.bytes;
    bytes.lock(process.pid);
    try {
      while (bytes.length > found.chunk) (yield* flushChunk(found));
      const calls = [];
      if (bytes.length > INLINE) (yield* flushChunk(found));
      if (bytes.length > 0) calls.push({ pwrite: { fd: found.kfd, index: bytes.from / found.chunk, data: base64(bytes.bytes(0, bytes.length)) } });
      calls.push({ close: { fd: found.kfd } });
      const results = yield* batch(calls);
      forget();
      for (const result of results) ok(result);
    } finally { bytes.unlock(); }
  } else if (found.kind === 'file' && found.rewrite && found.bytes.dirty) {
    forget();
    const data = found.bytes.bytes(0, found.bytes.length).slice();
    if (data.length <= INLINE) {
      const results = yield* batch([
        { open: { path: found.path, flags: O_WRONLY | O_TRUNC } },
        ...(data.length ? [{ pwrite: { fd: { ref: 0 }, index: 0, data: base64(data) } }] : []),
        { close: { fd: { ref: 0 } } },
      ]);
      for (const result of results) ok(result);
    } else {
      const writer = yield* openWriter(found.path, O_TRUNC, false);
      yield* writeTo(writer, 0, data);
      yield* closeFd(writer);
    }
  } else if (found.kind === 'file' && found.kfd !== undefined) {
    closing.push(found.kfd);
  }
}

// ---- What the program writes ----

let pending = [], pendingBytes = 0, written = 0, lastFlush = 0;
function output(fd, data) {
  written += data.length;
  if (written > process.limit) { flush(); postMessage({ truncated: true }); throw killedBy(SIGPIPE); }
  pending.push([fd, data.slice()]);
  pendingBytes += data.length;
  const now = performance.now();
  if (pendingBytes >= 16384 || now - lastFlush > 100) flush();
}
function flush() {
  lastFlush = performance.now();
  if (!pending.length) return;
  // Runs of one descriptor's writes go as one message.
  let fd = pending[0][0], parts = [];
  const send = () => { if (parts.length) { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let at = 0; for (const p of parts) { out.set(p, at); at += p.length; } postMessage({ fd, out }, [out.buffer]); } };
  for (const [which, data] of pending) { if (which !== fd) { send(); fd = which; parts = []; } parts.push(data); }
  send();
  pending = []; pendingBytes = 0;
}

// ---- WASI preview 1 ----

function iovecs(ptr, count) {
  const v = view(), out = [];
  for (let i = 0; i < count; i++) out.push([v.getUint32(ptr + i * 8, true), v.getUint32(ptr + i * 8 + 4, true)]);
  return out;
}
function strings(list, ptrs, buf) {
  const v = view(), b = bytes();
  for (const item of list) {
    v.setUint32(ptrs, buf, true); ptrs += 4;
    const data = encoder.encode(item + '\0'); b.set(data, buf); buf += data.length;
  }
  return 0;
}
function sizes(list, countPtr, sizePtr) {
  view().setUint32(countPtr, list.length, true);
  view().setUint32(sizePtr, list.reduce((n, item) => n + encoder.encode(item).length + 1, 0), true);
  return 0;
}
// Run `work`, a generator of the kernel's requests: 0, or its errno, or, where the call
// suspends the image (JSPI), a promise of that.
function attempt(work) {
  const failed = err => { if (err instanceof Errno) return err.errno; throw err; };
  let done;
  try { done = drive(work()); } catch (err) { return failed(err); }
  return done instanceof Promise ? done.then(value => value ?? 0, failed) : done ?? 0;
}
function pathAt(fd, ptr, len) {
  const dir = descriptor(fd);
  if (dir.kind !== 'dir') throw new Errno(ENOTDIR);
  return clean(join(dir.path, string(ptr, len)));
}
let environ = [];

const wasi = {
  args_get: (argv, buf) => strings(process.argv, argv, buf),
  args_sizes_get: (count, size) => sizes(process.argv, count, size),
  environ_get: (env, buf) => strings(environ, env, buf),
  environ_sizes_get: (count, size) => sizes(environ, count, size),
  clock_res_get: (id, ptr) => { view().setBigUint64(ptr, 1000n, true); return 0; },
  clock_time_get: (id, precision, ptr) => {
    const ms = id === 0 ? performance.timeOrigin + performance.now() : performance.now();
    view().setBigUint64(ptr, BigInt(Math.round(ms * 1e6)), true);
    return 0;
  },
  fd_advise: () => 0,
  fd_allocate: () => 0,
  fd_datasync: () => 0,
  fd_sync: () => 0,
  fd_close: fd => attempt(function* () { return yield* uninstall(fd); }),
  fd_fdstat_get: (fd, ptr) => attempt(function* () {
    const found = descriptor(fd), v = view();
    v.setUint8(ptr, filetype(found));
    v.setUint16(ptr + 2, found.append ? FDFLAG_APPEND : 0, true);
    // A terminal cannot seek, which is how libc's isatty tells it.
    const rights = found.tty ? ALL_RIGHTS & ~(RIGHT_SEEK | RIGHT_TELL) : ALL_RIGHTS;
    v.setBigUint64(ptr + 8, rights, true);
    v.setBigUint64(ptr + 16, ALL_RIGHTS, true);
  }),
  fd_fdstat_set_flags: () => 0,
  fd_fdstat_set_rights: () => 0,
  fd_filestat_get: (fd, ptr) => attempt(function* () { return writeFilestat(ptr, (yield* fstat(descriptor(fd)))); }),
  fd_filestat_set_size: (fd, len) => attempt(function* () {
    const found = descriptor(fd), length = Number(len);
    if (!found.rewrite && !found.writer) throw new Errno(EINVAL);
    const bytes = found.bytes;
    if (found.writer) {
      if (length < bytes.from) throw new Errno(EINVAL);
      if (length > size(found)) yield* writeTo(found, size(found), new Uint8Array(length - size(found)));
    }
    bytes.lock(process.pid, pause);
    try {
      const keep = length - (found.writer ? bytes.from : 0);
      if (!bytes.ensure(keep)) throw new Errno(EFBIG);
      if (keep > bytes.length) bytes.view.fill(0, bytes.length, keep);
      bytes.length = keep;
      if (found.rewrite) bytes.dirty = true;
    } finally { bytes.unlock(); }
  }),
  fd_filestat_set_times: (fd, atim, mtim, flags) => attempt(function* () { yield* times(descriptor(fd).path, atim, mtim, flags); }),
  fd_pread: (fd, iovs, count, offset, nread) => attempt(function* () {
    const found = descriptor(fd);
    let at = Number(offset), total = 0;
    for (const [ptr, len] of iovecs(iovs, count)) {
      const data = yield* readFrom(found, at, len);
      bytes().set(data, ptr); total += data.length; at += data.length;
      if (data.length < len) break;
    }
    view().setUint32(nread, total, true);
  }),
  fd_prestat_get: (fd, ptr) => {
    if (!preopen(fd)) return EBADF;
    view().setUint8(ptr, 0); view().setUint32(ptr + 4, 1, true);
    return 0;
  },
  fd_prestat_dir_name: (fd, ptr, len) => { if (!preopen(fd)) return EBADF; bytes().set(encoder.encode('/').subarray(0, len), ptr); return 0; },
  fd_pwrite: (fd, iovs, count, offset, nwritten) => attempt(function* () {
    const found = descriptor(fd);
    let at = Number(offset), total = 0;
    for (const [ptr, len] of iovecs(iovs, count)) { total += yield* writeTo(found, at, bytes().slice(ptr, ptr + len)); at += len; }
    view().setUint32(nwritten, total, true);
  }),
  fd_read: (fd, iovs, count, nread) => attempt(function* () {
    const found = descriptor(fd);
    let total = 0;
    yield* exclusive(found, function* () {
      for (const [ptr, len] of iovecs(iovs, count)) {
        const at = found.pos ?? 0;
        const data = yield* readFrom(found, at, len);
        bytes().set(data, ptr); total += data.length;
        if (!STDIO.has(found.kind)) found.pos = at + data.length;
        if (data.length < len) break;
        // A pipe gives what it has: once some is read, the read waits for no more.
        if (found.kind === 'pipe-in' && total > 0 && found.pipe.queued === 0) break;
      }
    });
    view().setUint32(nread, total, true);
  }),
  fd_readdir: (fd, buf, len, cookie, used) => attempt(function* () {
    const found = descriptor(fd);
    if (found.kind !== 'dir') throw new Errno(ENOTDIR);
    if (!found.entries) {
      const listed = yield* call({ getdents: { path: found.path } });
      for (const entry of listed) {
        if (!entry.stat) continue;
        const path = clean(join(found.path, entry.name));
        cache.set('l:' + path, entry.stat);
        // What is not a link is what it names, as stat follows it.
        if ((entry.stat.mode & 0o170000) !== 0o120000) cache.set('s:' + path, entry.stat);
      }
      found.entries = [{ name: '.', type: DIRECTORY }, { name: '..', type: DIRECTORY }, ...listed.map(entry => ({ name: entry.name, ino: entry.stat?.ino, type: entry.stat ? kindOf(entry.stat.mode) : UNKNOWN }))];
    }
    const out = [];
    let total = 0;
    for (let i = Number(cookie); i < found.entries.length && total < len; i++) {
      const entry = found.entries[i], name = encoder.encode(entry.name);
      const record = new Uint8Array(24 + name.length), v = new DataView(record.buffer);
      v.setBigUint64(0, BigInt(i + 1), true);
      v.setBigUint64(8, BigInt(entry.ino ?? 0), true);
      v.setUint32(16, name.length, true);
      v.setUint8(20, entry.type);
      record.set(name, 24);
      out.push(record); total += record.length;
    }
    let at = buf;
    for (const record of out) { const part = record.subarray(0, Math.min(record.length, buf + len - at)); bytes().set(part, at); at += part.length; }
    view().setUint32(used, at - buf, true);
  }),
  // WASI's renumber moves a descriptor: `from` is closed, `to` is what it was.
  fd_renumber: (from, to) => attempt(function* () {
    const found = descriptor(from);
    if (from === to) return;
    if (fds.has(to)) yield* uninstall(to);
    fds.set(to, found);
    fds.delete(from);
    if (cloexec.delete(from)) cloexec.add(to);
  }),
  fd_seek: (fd, offset, whence, ptr) => attempt(function* () {
    const found = descriptor(fd);
    if (found.kind !== 'file') throw new Errno(ESPIPE);
    yield* exclusive(found, function* () {
      const base = whence === 0 ? 0 : whence === 1 ? found.pos : size(found);
      const pos = base + Number(offset);
      if (pos < 0) throw new Errno(EINVAL);
      found.pos = pos;
      view().setBigUint64(ptr, BigInt(pos), true);
    });
  }),
  fd_tell: (fd, ptr) => attempt(function* () {
    const found = descriptor(fd);
    if (found.kind !== 'file') throw new Errno(ESPIPE);
    yield* exclusive(found, function* () { view().setBigUint64(ptr, BigInt(found.pos), true); });
  }),
  fd_write: (fd, iovs, count, nwritten) => attempt(function* () {
    const found = descriptor(fd);
    let total = 0;
    yield* exclusive(found, function* () {
      for (const [ptr, len] of iovecs(iovs, count)) {
        const data = bytes().slice(ptr, ptr + len);
        if (found.kind !== 'file') { total += yield* writeTo(found, 0, data); continue; }
        const at = found.append ? size(found) : found.pos;
        total += yield* writeTo(found, at, data);
        found.pos = at + len;
      }
    });
    view().setUint32(nwritten, total, true);
  }),
  path_create_directory: (fd, ptr, len) => attempt(function* () { yield* call({ mkdir: { path: pathAt(fd, ptr, len), mode: 0o777 } }); forget(); }),
  path_filestat_get: (fd, flags, ptr, len, out) => attempt(function* () { return writeFilestat(out, (yield* stat(pathAt(fd, ptr, len), (flags & FOLLOW) !== 0))); }),
  path_filestat_set_times: (fd, flags, ptr, len, atim, mtim, fst) => attempt(function* () { return yield* times(pathAt(fd, ptr, len), atim, mtim, fst); }),
  path_link: (fd, flags, ptr, len, fd2, ptr2, len2) => attempt(function* () { yield* call({ link: { from: pathAt(fd, ptr, len), to: pathAt(fd2, ptr2, len2), follow: (flags & FOLLOW) !== 0 } }); forget(); }),
  path_open: (fd, dirflags, ptr, len, oflags, base, inheriting, fdflags, out) => attempt(function* () {
    const path = pathAt(fd, ptr, len);
    const write = (base & RIGHT_WRITE) !== 0n, read = (base & RIGHT_READ) !== 0n || !write;
    const append = (fdflags & FDFLAG_APPEND) !== 0;
    let found;
    if (oflags & OFLAG_DIRECTORY) {
      if (kindOf((yield* stat(path, (dirflags & FOLLOW) !== 0)).mode) !== DIRECTORY) throw new Errno(ENOTDIR);
      found = { kind: 'dir', path };
    } else if (!write) {
      found = yield* openRead(path);
    } else if (oflags & (OFLAG_TRUNC | OFLAG_EXCL)) {
      found = yield* openWriter(path, (oflags & OFLAG_CREAT ? O_CREAT : 0) | (oflags & OFLAG_EXCL ? O_EXCL : 0) | (oflags & OFLAG_TRUNC ? O_TRUNC : 0), read);
    } else {
      // Written without truncating: a new file is written in order; one there is changed here.
      let there;
      try { there = yield* stat(path); } catch (err) { if (!(err instanceof Errno) || err.errno !== ENOENT || !(oflags & OFLAG_CREAT)) throw err; }
      if (!there) found = yield* openWriter(path, O_CREAT, read);
      else if (kindOf(there.mode) === DIRECTORY) throw new Errno(EISDIR);
      else found = yield* openRewrite(path, there, append, read);
    }
    found.append ||= append && found.kind === 'file';
    const number = lowest();
    install(number, found);
    view().setUint32(out, number, true);
  }),
  path_readlink: (fd, ptr, len, buf, bufLen, used) => attempt(function* () {
    const target = encoder.encode((yield* call({ readlink: { path: pathAt(fd, ptr, len) } })));
    const part = target.subarray(0, bufLen);
    bytes().set(part, buf);
    view().setUint32(used, part.length, true);
  }),
  path_remove_directory: (fd, ptr, len) => attempt(function* () { yield* call({ rmdir: { path: pathAt(fd, ptr, len) } }); forget(); }),
  path_rename: (fd, ptr, len, fd2, ptr2, len2) => attempt(function* () { yield* call({ rename: { from: pathAt(fd, ptr, len), to: pathAt(fd2, ptr2, len2) } }); forget(); }),
  path_symlink: (ptr, len, fd, ptr2, len2) => attempt(function* () { yield* call({ symlink: { target: string(ptr, len), path: pathAt(fd, ptr2, len2) } }); forget(); }),
  path_unlink_file: (fd, ptr, len) => attempt(function* () { yield* call({ unlink: { path: pathAt(fd, ptr, len) } }); forget(); }),
  poll_oneoff: (input, output, count, events) => attempt(function* () {
    const v = view();
    let until = 0, ready = 0;
    for (let i = 0; i < count; i++) {
      const sub = input + i * 48, tag = v.getUint8(sub + 8);
      if (tag === 0) {
        const timeout = Number(v.getBigUint64(sub + 24, true)) / 1e6, absolute = v.getUint16(sub + 40, true) & 1;
        until = Math.max(until, absolute ? timeout - performance.timeOrigin : performance.now() + timeout);
      }
      const event = output + ready++ * 32;
      v.setBigUint64(event, v.getBigUint64(sub, true), true);
      v.setUint16(event + 8, 0, true);
      v.setUint8(event + 10, tag);
      v.setBigUint64(event + 16, 0n, true);
    }
    sleepUntil(until);
    v.setUint32(events, ready, true);
  }),
  proc_exit: code => { throw new Exit(code); },
  proc_raise: () => ENOSYS,
  // Into memory of its own first: shared memory (WASIX's) is not the crypto's to fill.
  random_get: (ptr, len) => { for (let at = 0; at < len; at += 65536) bytes().set(crypto.getRandomValues(new Uint8Array(Math.min(65536, len - at))), ptr + at); return 0; },
  sched_yield: () => 0,
};
// What WASI has that a program here cannot do (sockets): not implemented.
// Each call waits first while the process is stopped (`pause`).
const preview1 = new Proxy(wasi, {
  get: (target, name) => {
    const call = target[name] ?? (() => ENOSYS);
    return (...args) => { pause(); return call(...args); };
  },
});

// Signals, as a word of memory the page shares (web/wasi/exec.mjs): 0 while the process runs, 1
// while it is stopped (SIGSTOP, SIGTSTP, Ctrl+Z), KILLED and the signal once one ends it. It
// heeds the word at its next system call, and as a blocking wait wakes: stopped, it waits until
// continued (SIGCONT), as a stopped process runs no further, and the page hears it stop and go
// on; ended, it exits by the signal, closing what it has open as an exit does. A loop that makes
// no call cannot be stopped this way; its host ends it outright.
const KILLED = 0x100;
let control = null;
// Whether it is exiting: what it has open closes then, whatever signal comes.
let exiting = false;
function pause() {
  if (!control || exiting) return;
  let word = Atomics.load(control, 0);
  if (word === 0) return;
  if (word & KILLED) { flush(); throw killedBy(word & 0xff); }
  flush();
  postMessage({ stopped: true });
  while ((word = Atomics.load(control, 0)) !== 0) {
    if (word & KILLED) { postMessage({ continued: true }); throw killedBy(word & 0xff); }
    Atomics.wait(control, 0, word);
  }
  postMessage({ continued: true });
}

// ---- WASIX ----

// The root directory WASI's libc finds its paths under, as long as the program keeps it open.
const preopen = fd => fds.get(fd)?.kind === 'dir' && fds.get(fd)?.path === '/' && fd === 3;
// The host's answer to a call that waits on it (wait, execve, getppid, kill): the page
// (web/wasi/exec.mjs) answers in memory both share, as the kernel answers a blocking call.
let channel = null;
function host(type, args) {
  if (!channel) throw new Errno(ENOSYS);
  flush();
  Atomics.store(channel.state, 0, 0);
  postMessage({ host: { type, args } });
  // A stop while it waits, it heeds.
  while (Atomics.load(channel.state, 0) === 0) {
    if (Atomics.wait(channel.state, 0, 0, 200) === 'timed-out') pause();
  }
  return JSON.parse(decoder.decode(channel.data.slice(0, Atomics.load(channel.state, 1))));
}
const hostErrno = reply => { if (reply?.errno) throw new Errno(ERRNO[reply.errno] ?? EIO); return reply; };
// Lines of a string WASIX passes a list as (arguments, environment).
const lines = (ptr, len) => string(ptr, len).split(/[\n\r]/).filter(line => line !== '');
// Signals whose default is to end the process, by Linux's numbers.
const ENDING = new Set([1, 2, 3, 6, 9, 11, 13, 14, 15]);
// setjmp's saved stacks, by the jmp_buf's address: what longjmp goes back to.
let snapshots = new Map(), saved = 0;

// execve(2) of `name` (a path, or a name PATH finds): it does not return, if it goes through;
// the new image starts in this process once this one is unwound (`Replaced`).
function* execve(name, argv, env, search = !name.includes('/')) {
  let path = name;
  if (search) {
    const PATH = env.find(entry => entry.startsWith('PATH='))?.slice(5) || '/usr/bin';
    path = undefined;
    for (const dir of PATH.split(':').filter(Boolean)) {
      const candidate = clean(join(join(process.cwd, dir), name));
      try { if (kindOf((yield* stat(candidate)).mode) === REGULAR_FILE) { path = candidate; break; } } catch { /* not there */ }
    }
    if (!path) throw new Errno(ENOENT);
  } else path = clean(join(process.cwd, name));
  // The working directory goes with the process, which a WASI program learns from PWD.
  const environment = [...env.filter(entry => !entry.startsWith('PWD=')), `PWD=${process.cwd}`];
  hostErrno(host('exec', { path, argv, env: environment, cwd: process.cwd }));
  throw new Replaced();
}
// The old execve, which cannot fail: what fails ends the process, as a shell would say it.
function* execOrExit(name, argv, env) {
  try { yield* execve(name, argv, env); } catch (err) {
    if (!(err instanceof Errno)) throw err;
    output(2, encoder.encode(`${name}: ${STRERROR[err.errno] ?? 'cannot execute'}\n`));
    flush();
    throw new Exit(err.errno === ENOENT ? 127 : 126);
  }
}

const wasixCalls = {
  ...wasi,
  // WASIX's renumber is dup2(2): `from` stays open.
  fd_renumber: (from, to) => attempt(function* () {
    const found = descriptor(from);
    if (from === to) return;
    if (fds.has(to)) yield* uninstall(to);
    install(to, found);
  }),
  fd_dup: (fd, out) => attempt(function* () { const found = descriptor(fd), number = lowest(); install(number, found); view().setUint32(out, number, true); }),
  fd_dup2: (fd, min, closeOnExec, out) => attempt(function* () {
    const found = descriptor(fd), number = lowest(min);
    install(number, found);
    if (closeOnExec) cloexec.add(number);
    view().setUint32(out, number, true);
  }),
  fd_pipe: (readEnd, writeEnd) => attempt(function* () {
    if (typeof SharedArrayBuffer !== 'function') throw new Errno(ENOSYS);
    const pipe = new Pipe(pipeBuffer(), process.pid);
    const r = lowest();
    install(r, { kind: 'pipe-in', pipe });
    const w = lowest();
    install(w, { kind: 'pipe-out', pipe });
    view().setUint32(readEnd, r, true);
    view().setUint32(writeEnd, w, true);
  }),
  getcwd: (ptr, lengthPtr) => {
    const cwd = encoder.encode(process.cwd), room = view().getUint32(lengthPtr, true);
    view().setUint32(lengthPtr, cwd.length, true);
    if (cwd.length >= room) return ERRNO.ERANGE;
    bytes().set(cwd, ptr);
    bytes()[ptr + cwd.length] = 0;
    return 0;
  },
  chdir: (ptr, len) => attempt(function* () {
    const path = clean(join(process.cwd, string(ptr, len)));
    const [found, searchable] = yield* batch([{ stat: { path } }, { access: { path, mode: 1 } }]);
    if (kindOf(ok(found).mode) !== DIRECTORY) throw new Errno(ENOTDIR);
    ok(searchable);
    process.cwd = path;
  }),
  proc_id: ptr => { view().setUint32(ptr, process.pid, true); return 0; },
  // getppid: its parent now (init's, once its parent ended), as its kernel has it.
  proc_parent: (pid, ptr) => attempt(function* () {
    const found = hostErrno(host('getpid', { pid }));
    view().setUint32(ptr, found.ppid, true);
  }),
  proc_signal: (pid, signal) => attempt(function* () { hostErrno(host('kill', { pid, signal })); }),
  // fork(2): unwound, copied into a child by the host, and rewound (the run loop below).
  proc_fork: (copy, pidPtr) => {
    if (engine?.rewinding) {
      const answer = engine.resume();
      if (answer.errno) return answer.errno;
      view().setUint32(pidPtr, answer.pid, true);
      return 0;
    }
    if (!engine?.able || !channel) return ENOSYS;
    flush();
    try { engine.unwind({ kind: 'fork' }); } catch { return ERRNO.ENOMEM; }
    return 0;
  },
  proc_exec: (name, nameLen, args, argsLen) => drive(execOrExit(string(name, nameLen), lines(args, argsLen), environ)),
  proc_exec2: (name, nameLen, args, argsLen, envs, envsLen) => drive(execOrExit(string(name, nameLen), lines(args, argsLen), lines(envs, envsLen))),
  proc_exec3: (name, nameLen, args, argsLen, envs, envsLen, search, path, pathLen) => attempt(function* () {
    const env = lines(envs, envsLen);
    const PATH = string(path, pathLen);
    yield* execve(string(name, nameLen), lines(args, argsLen), search && PATH ? [...env.filter(entry => !entry.startsWith('PATH=')), `PATH=${PATH}`] : env, !!search && !string(name, nameLen).includes('/'));
  }),
  // wait4(2): a child of this process (or the one named) once it ended, reaped; with
  // NON_BLOCKING, none if none ended yet.
  proc_join: (pidPtr, flags, statusPtr) => attempt(function* () {
    const v = view(), tag = v.getUint8(pidPtr);
    if (tag > 1) throw new Errno(EINVAL);
    const reply = hostErrno(host('join', { pid: tag === 1 ? v.getUint32(pidPtr + 4, true) : null, nohang: (flags & 1) !== 0 }));
    for (let at = 0; at < 6; at++) v.setUint8(statusPtr + at, 0);
    if (reply.nothing) { v.setUint8(pidPtr, 0); v.setUint32(pidPtr + 4, 0, true); return; }
    v.setUint8(pidPtr, 1);
    v.setUint32(pidPtr + 4, reply.pid, true);
    if (reply.signal != null) { v.setUint8(statusPtr, 2); v.setUint8(statusPtr + 4, reply.signal); }
    else { v.setUint8(statusPtr, 1); v.setUint16(statusPtr + 2, reply.code & 0xffff, true); }
  }),
  // A program's signal handlers are not called: each signal does what it does by default.
  callback_signal: () => {},
  thread_id: ptr => { view().setUint32(ptr, 1, true); return 0; },
  // raise(3), abort(3): a signal to itself, whose default ends it.
  thread_signal: (tid, signal) => { if (ENDING.has(signal)) { flush(); throw killedBy(signal); } return 0; },
  thread_exit: code => { throw new Exit(code); },
  // One thread: nothing else could change the word or wake it, so a wait returns at once.
  futex_wait: (addr, expected, timeout, woken) => { view().setUint8(woken, 0); return 0; },
  futex_wake: (addr, woken) => { view().setUint8(woken, 0); return 0; },
  futex_wake_all: (addr, woken) => { view().setUint8(woken, 0); return 0; },
  // setjmp: the stack saved (unwound and rewound at once); longjmp: unwound, and the saved one
  // rewound, with its value.
  stack_checkpoint: (snapshot, result) => {
    if (engine?.rewinding) { view().setBigUint64(result, BigInt(engine.resume().value), true); return 0; }
    if (!engine?.able) return ENOSYS;
    try { engine.unwind({ kind: 'checkpoint', snapshot, sp: engine.stackPointer() }); } catch { return ERRNO.ENOMEM; }
    return 0;
  },
  stack_restore: (snapshot, value) => {
    const found = snapshots.get(snapshot);
    if (!engine?.able || !found || found.id !== view().getBigUint64(snapshot, true)) { flush(); throw killedBy(SIGABRT); }
    engine.unwind({ kind: 'restore', found, value: value === 0n ? 1n : value });
  },
};
// Each call waits first while the process is stopped, as WASI's do.
const wasix = new Proxy(wasixCalls, {
  get: (target, name) => {
    const call = target[name] ?? (() => ENOSYS);
    return (...args) => { pause(); return call(...args); };
  },
});

// ---- Fork ----

// What a child gets of this process's open files: each description, shared through the line's
// table (`shares`), and which descriptors are which. Its host counts the child's references to
// each (and holds its pipes' ends) once it has the child's pid, before the child starts.
function forkState() {
  if (!shares) throw new Errno(ENOSYS);
  const ids = new Map(), descriptions = [], table = [];
  for (const [fd, found] of fds) {
    if (!ids.has(found)) {
      ids.set(found, descriptions.length);
      descriptions.push(describe(found));
    }
    table.push([fd, ids.get(found), cloexec.has(fd)]);
  }
  return { fds: table, descriptions };
}
function describe(found) {
  switch (found.kind) {
    case 'in': return { kind: 'in', tty: found.tty, data: found.data.slice(found.pos) };
    case 'out': return { kind: 'out', fd: found.fd, tty: found.tty, closed: found.closed?.buffer ?? null };
    case 'pipe-in': case 'pipe-out': return { kind: found.kind, tty: !!found.tty, buffer: found.pipe.buffer, refs: found.refs };
    case 'dir': return { kind: 'dir', path: found.path };
    default: {
      if (found.share == null) share(found);
      if (found.share == null) throw new Errno(ERRNO.EMFILE);
      const { kind, path, kfd, token, read, size: length, stat: stated, writer, rewrite, append, chunk, share: slot, refs } = found;
      return { kind, path, kfd, token, read, size: length, stat: stated, writer, rewrite, append, chunk, share: slot, refs, bytes: found.bytes?.transferable };
    }
  }
}
// The child's descriptors, as its parent had them (its host holds its pipes' ends for it).
function adopt(state) {
  const made = state.descriptions.map(description => {
    switch (description.kind) {
      case 'in': return { kind: 'in', tty: description.tty, data: description.data, pos: 0 };
      case 'out': return { kind: 'out', fd: description.fd, tty: description.tty, closed: description.closed ? new Int32Array(description.closed) : null };
      case 'pipe-in': case 'pipe-out': return { kind: description.kind, tty: description.tty, pipe: new Pipe(description.buffer, process.pid) };
      case 'dir': return { kind: 'dir', path: description.path };
      default: {
        const found = adopted(description);
        if (shares) shares.attach(found, description.share);
        return found;
      }
    }
  });
  for (const [fd, id, closeOnExec] of state.fds) {
    install(fd, made[id], true);
    if (closeOnExec) cloexec.add(fd);
  }
}
// A file of the kernel's another process described (`describe`): one to read or write here.
function adopted(description) {
  const { bytes, share, refs, ...rest } = description;
  const found = { ...rest, window: { start: 0, data: new Uint8Array(0) } };
  if (bytes) found.bytes = new Bytes(bytes);
  return found;
}
// fork(2), the image unwound: the host makes the child (a pid, a Worker) of this snapshot.
async function fork() {
  let state;
  try { state = forkState(); } catch (err) { return { errno: err instanceof Errno ? err.errno : EIO }; }
  const snapshot = engine.snapshot();
  snapshot.initializing = initializing;
  postMessage({ fork: { ...state, snapshot, snapshots, shares: shares.buffer, argv: process.argv, env: environ, cwd: process.cwd, wasix: process.wasix } }, [snapshot.memory]);
  const { forked } = await next('forked');
  if (forked.errno) return { errno: ERRNO[forked.errno] ?? EIO };
  return { pid: forked.pid };
}

// ---- The image ----

// What the host posts after the start: a fork's answer, an execve's image.
const inbox = [], waiting = [];
function received(data) {
  const at = waiting.findIndex(([key]) => key in data);
  if (at < 0) { inbox.push(data); return; }
  const [[, resolve]] = waiting.splice(at, 1);
  resolve(data);
}
function next(key) {
  const at = inbox.findIndex(data => key in data);
  if (at >= 0) return Promise.resolve(inbox.splice(at, 1)[0]);
  return new Promise(resolve => waiting.push([key, resolve]));
}
// Instantiate `module`: a memory of the type it imports (`type`), or its own; a fork's child's,
// as large as its parent's (`snapshot`), which it becomes.
let initializing = false;
async function instantiate(module, type, snapshot, startSection = false) {
  suspending = capable && !startSection;
  const pages = snapshot ? snapshot.memory.byteLength / 65536 : 0;
  // A module importing its memory (WASIX's do) gets one of the type it declared, so that a
  // shared or larger memory links; its own otherwise, as wasip1's, exported as `memory`.
  const env = type ? { memory: new WebAssembly.Memory({
    initial: Math.max(type.initial, pages),
    ...(type.maximum == null ? {} : { maximum: type.maximum }),
    ...(type.shared ? { shared: true } : {}),
  }) } : {};
  // Where calls may suspend, each import may: one that answers at once returns at once.
  const imports = suspending
    ? { wasi_snapshot_preview1: suspendable(preview1), terminal: suspendable(terminal), wasix_32v1: suspendable(wasix), env }
    : { wasi_snapshot_preview1: preview1, terminal, wasix_32v1: wasix, env };
  // An imported memory is this process's before the instance is: a start function, which runs
  // as it is instantiated, may already write through it (a memory of the module's own is not
  // there to reach until the instance is).
  if (type) memory = env.memory;
  instance = await WebAssembly.instantiate(module, imports);
  memory = type ? env.memory : instance.exports.memory;
  if (!(memory instanceof WebAssembly.Memory)) throw new Error('the module exports no memory');
  process.wasix = WebAssembly.Module.imports(module).some(entry => entry.module === 'wasix_32v1');
  engine = snapshot ? Engine.child(instance, () => memory, snapshot) : new Engine(instance, () => memory);
  initializing = snapshot ? !!snapshot.initializing : !!instance.exports.__tw_initialize;
}
// The calls that never ask the kernel (arguments, clocks, randomness, descriptors' numbers,
// the working directory, fork and setjmp, and those its host answers in shared memory): they
// are not wrapped to suspend, as they never do.
const NEVER_SUSPENDS = new Set([
  'args_get', 'args_sizes_get', 'environ_get', 'environ_sizes_get', 'clock_res_get', 'clock_time_get',
  'fd_advise', 'fd_allocate', 'fd_datasync', 'fd_sync', 'fd_fdstat_get', 'fd_fdstat_set_flags',
  'fd_fdstat_set_rights', 'fd_prestat_get', 'fd_prestat_dir_name', 'fd_seek', 'fd_tell', 'fd_dup',
  'fd_dup2', 'fd_pipe', 'poll_oneoff', 'proc_exit', 'proc_raise', 'random_get', 'sched_yield', 'getcwd',
  'proc_id', 'proc_parent', 'proc_signal', 'proc_join', 'proc_fork', 'stack_checkpoint', 'stack_restore',
  'callback_signal', 'thread_id', 'thread_signal', 'thread_exit', 'futex_wait', 'futex_wake',
  'futex_wake_all', 'reply',
]);
// The imports a module asks for of `namespace`: those that may ask the kernel, able to suspend
// the image (JSPI).
function suspendable(namespace) {
  return new Proxy({}, { get: (_, name) => {
    const call = namespace[name];
    return typeof call === 'function' && !NEVER_SUSPENDS.has(name) ? new WebAssembly.Suspending(call) : call;
  } });
}
// Run the image, and what replaces it: its exit status, if `_start` returns. Where calls may
// suspend, `_start` runs as a promise (WebAssembly.promising), awaited.
async function run() {
  for (;;) {
    try {
      const entry = initializing ? instance.exports.__tw_initialize : instance.exports._start;
      const start = suspending ? WebAssembly.promising(entry) : entry;
      await start();
    } catch (err) {
      if (!(err instanceof Replaced)) throw err;
      await replace();
      continue;
    }
    const pending = engine.unwound();
    if (!pending) {
      if (!initializing) return 0;
      initializing = false;
      engine.top = engine.stackPointer();
      continue;
    }
    if (pending.kind === 'fork') engine.rewind(await fork());
    else if (pending.kind === 'checkpoint') {
      // The stack, and the shadow stack it ran on, as setjmp saw them.
      const top = engine.top, sp = pending.sp;
      const id = BigInt(++saved);
      snapshots.set(pending.snapshot, { id, stack: engine.saved(), sp, memory: sp != null && top > sp ? bytes().slice(sp, top) : null });
      view().setBigUint64(pending.snapshot, id, true);
      bytes().fill(0, pending.snapshot + 8, pending.snapshot + 24);
      engine.rewind({ value: 0n });
    } else if (pending.kind === 'restore') {
      const { found, value } = pending;
      if (found.memory) bytes().set(found.memory, found.sp);
      if (found.sp != null) engine.setStackPointer(found.sp);
      engine.rewind({ value }, found.stack);
    }
  }
}
// execve(2) went through: the image the host loaded starts in this process, its descriptors
// open but those marked close-on-exec.
async function replace() {
  const { image } = await next('image');
  for (const fd of [...cloexec]) { try { await drive(uninstall(fd)); } catch { /* closed already */ } }
  flush();
  forget();
  snapshots = new Map();
  Object.assign(process, { argv: image.argv, proc: image.token });
  environ = image.env;
  await instantiate(image.module, image.memory, undefined, image.startSection);
}


// utimensat(2), as WASI asks it: each time given, now, or left.
function* times(path, atim, mtim, flags) {
  const time = (value, set, now) => flags & now ? 'now' : flags & set ? { sec: Number(value / 1000000000n), nsec: Number(value % 1000000000n) } : 'omit';
  yield* call({ utimens: { path, atime: time(atim, 1, 2), mtime: time(mtim, 4, 8) } });
  forget();
}
// Wait, as a sleeping process does: on a lock nobody releases, where the page may share memory;
// on the clock otherwise.
function sleepUntil(until) {
  if (until - performance.now() <= 0) return;
  // What it wrote shows while it sleeps.
  flush();
  // On its stop word: a stop wakes it, and it waits stopped, then sleeps out what is left.
  if (control) {
    for (let left = until - performance.now(); left > 0; left = until - performance.now()) {
      if (Atomics.load(control, 0) !== 0) pause();
      else Atomics.wait(control, 0, 0, left);
    }
    return;
  }
  if (typeof SharedArrayBuffer === 'function') { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, until - performance.now()); return; }
  while (performance.now() < until) { /* the clock is the only thing to wait on */ }
}

// terminal.sys: a batch of the kernel's calls (abi::Batch's `calls`, as JSON), sent as it is.
// `sys` sends it and gives the reply's length; `reply` copies the reply where the program says.
let reply = new Uint8Array(0);
const terminal = {
  sys: (ptr, len) => {
    pause();
    const calls = JSON.parse(string(ptr, len));
    forget();
    return drive((function* () {
      reply = encoder.encode(JSON.stringify({ results: yield* batch(calls) }));
      return reply.length;
    })());
  },
  reply: ptr => { bytes().set(reply, ptr); },
};

let started = false;
onmessage = ({ data }) => {
  if (started) { received(data); return; }
  started = true;
  if (data.close) {
    process = { ...data };
    void closeAll(data.close);
    return;
  }
  void start(data);
};
async function start(data) {
  process = { ...data, limit: data.limit ?? 10 << 20, ppid: data.ppid ?? 1 };
  control = data.control ? new Int32Array(data.control) : null;
  channel = data.channel ? { state: new Int32Array(data.channel, 0, 2), data: new Uint8Array(data.channel, 8) } : null;
  const { stdin = {}, stdout = {}, stderr = {}, fork: parent } = data;
  let code = 0, signal;
  try {
    if (parent) {
      // A fork's child: its parent's argument vector, environment, directory and descriptors.
      environ = parent.env;
      shares = new Shares(parent.shares);
      snapshots = parent.snapshots;
      Object.assign(process, { argv: parent.argv, cwd: parent.cwd });
      adopt(parent);
    } else {
      environ = Array.isArray(data.env) ? data.env : Object.entries(data.env ?? {}).map(([name, value]) => `${name}=${value}`);
      process.cwd ??= environ.find(entry => entry.startsWith('PWD='))?.slice(4) || '/';
      shares = data.shares ? new Shares(data.shares) : null;
      // The page holds the pipes' ends it gives a process, for it, before it starts.
      install(0, stdin.pipe ? { kind: 'pipe-in', pipe: new Pipe(stdin.pipe, process.pid), tty: !!stdin.tty } : { kind: 'in', tty: !!stdin.tty, data: stdin.data ?? new Uint8Array(0), pos: 0 }, true);
      install(1, stdout.pipe ? { kind: 'pipe-out', pipe: new Pipe(stdout.pipe, process.pid) } : { kind: 'out', fd: 1, tty: !!stdout.tty, closed: stdout.closed ? new Int32Array(stdout.closed) : null }, true);
      install(2, { kind: 'out', fd: 2, tty: !!stderr.tty }, true);
      install(3, { kind: 'dir', path: '/' });
    }
    await instantiate(data.module, data.memory, parent?.snapshot, data.startSection);
    // The child returns from fork with 0.
    if (parent) engine.rewind({ pid: 0 });
    code = await run();
  } catch (err) {
    if (err instanceof Exit) ({ code, signal } = err);
    else {
      // A trap, or the engine's own failure: it ends as abort(3) ends a process.
      output(2, encoder.encode(`${process.argv?.[0] ?? 'process'}: ${err?.message ?? err}\n`));
      ({ code, signal } = killedBy(SIGABRT));
    }
  }
  // What it left open closes as it exits, as a process's descriptors do: its pipes too, so that
  // the next reads to their end, and the one before hears SIGPIPE.
  exiting = true;
  for (const fd of [...fds.keys()]) { try { await drive(uninstall(fd)); } catch { /* it exits all the same */ } }
  if (closing.length) { try { await drive(batch([])); } catch { /* likewise */ } }
  flush();
  postMessage({ exit: code, signal });
}
// Close the open files a process its host killed held last, as it would have at its exit:
// what they wrote goes, and their descriptors close.
async function closeAll(descriptions) {
  for (const description of descriptions) {
    try { await drive(closeFd(adopted(description))); } catch { /* closed as it may be */ }
  }
  if (closing.length) { try { await drive(batch([])); } catch { /* likewise */ } }
  postMessage({ exit: 0 });
}

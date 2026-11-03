// A process (owner's design, 2026-10-29: the page is user space, the API its system calls): a
// program built for wasm32-wasip1, run in a Worker of its own. Its WASI calls are made here over
// the kernel's (POST /api/sys, GET /api/file, PUT /api/pwrite), synchronously, as a program's
// calls block: the Worker waits on each request. `terminal.sys` reaches the kernel's own calls,
// which WASI has no words for (modes, owners, ACLs, devices, accounts).
//
// Started with {module, argv, env, umask, sudo, stdin, stdout, stderr}: standard input is
// {data} (bytes given whole) or {pipe} (a pipe's buffer, web/wasi/pipe.js), the terminal if
// {tty}; standard output {pipe}, or the page's, a terminal if {tty}, whose reader may close it
// ({closed}, a word of shared memory); standard error {tty}. It posts {out, fd} as it writes to
// the page, {reading} as it waits on the terminal, and {exit} as it ends.
import { Pipe } from './pipe.js';

// WASI's errno numbers, by Linux's names, as the kernel answers.
const ERRNO = {
  E2BIG: 1, EACCES: 2, EAGAIN: 6, EBADF: 8, EBUSY: 10, ECANCELED: 11, EEXIST: 20, EFBIG: 22, EINVAL: 28, EIO: 29,
  EISDIR: 31, ELOOP: 32, EMFILE: 33, EMLINK: 34, ENAMETOOLONG: 37, ENODEV: 43, ENOENT: 44, ENOSPC: 51,
  ENOSYS: 52, ENOTDIR: 54, ENOTEMPTY: 55, ENOTSUP: 58, EOPNOTSUPP: 58, ENOTTY: 59, ENXIO: 60, EPERM: 63,
  ERANGE: 68, EROFS: 69, ESPIPE: 70, ESRCH: 71, ESTALE: 72, ETIMEDOUT: 73, ETXTBSY: 74, EXDEV: 75, ENODATA: 44,
};
const { EBADF, EINVAL, EIO, EISDIR, ENOENT, ENOSYS, ENOTDIR, ESPIPE, EFBIG } = ERRNO;
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

class Exit { constructor(code) { this.code = code; } }
class Errno extends Error { constructor(errno) { super(String(errno)); this.errno = errno; } }
const errnoOf = err => ERRNO[err?.errno] ?? EIO;

let memory, process = {};
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

function request(method, url, body, headers = {}, binary = false) {
  const xhr = new XMLHttpRequest();
  xhr.open(method, url, false);
  if (binary) xhr.responseType = 'arraybuffer';
  for (const [name, value] of Object.entries(headers)) xhr.setRequestHeader(name, value);
  try { xhr.send(body ?? null); } catch { throw new Errno(EIO); }
  return xhr;
}
// A batch of calls: each one's result, {ok} or {err}. Descriptors to close go after them, so
// that a call's {ref: i} names the i-th of `calls`.
function batch(calls) {
  const sent = [...calls, ...closing.map(fd => ({ close: { fd } }))];
  closing = [];
  const xhr = request('POST', '/api/sys', JSON.stringify({ calls: sent, umask: process.umask, sudo: process.sudo }), { 'Content-Type': 'application/json' });
  if (xhr.status !== 200) return calls.map(() => ({ err: { errno: 'EIO' } }));
  return JSON.parse(xhr.responseText).results.slice(0, calls.length);
}
// One call: its value, or an Errno thrown.
function call(one) {
  const [result] = batch([one]);
  if ('err' in result) throw new Errno(errnoOf(result.err));
  return result.ok;
}
const ok = result => { if ('err' in result) throw new Errno(errnoOf(result.err)); return result.ok; };
function stat(path, follow = true) {
  const key = (follow ? 's:' : 'l:') + path;
  if (cache.has(key)) return cache.get(key);
  const found = call(follow ? { stat: { path } } : { lstat: { path } });
  cache.set(key, found);
  return found;
}
// Bytes `start`..`end` of the file at `path`, by a ranged GET: by its descriptor's token, which
// the Worker serves without asking the kernel each time, if it has one.
function range(path, start, end, token) {
  const url = token ? '/api/file?token=' + encodeURIComponent(token) : '/api/file?path=' + encodeURIComponent(path);
  const xhr = request('GET', url, null, { Range: `bytes=${start}-${end - 1}` }, true);
  if (xhr.status === 416) return new Uint8Array(0);
  if (xhr.status !== 200 && xhr.status !== 206) throw new Errno(xhr.status === 404 ? ENOENT : xhr.status === 403 ? ERRNO.EACCES : EIO);
  return new Uint8Array(xhr.response);
}
// The whole of a file, for one written here anew.
function whole(path, size) {
  if (size > REWRITE_MAX) throw new Errno(EFBIG);
  if (size <= INLINE) return unbase64(call({ pread: { path, count: INLINE } }).data);
  return range(path, 0, size);
}
const join = (dir, path) => path.startsWith('/') ? path : (dir === '/' ? '' : dir) + '/' + (path === '.' ? '' : path).replace(/^\.\//, '');
const clean = path => path.length > 1 ? path.replace(/\/+$/, '').replace(/\/\/+/g, '/') || '/' : path;

// ---- Descriptors ----

// What each descriptor is: the terminal or a pipe (in, out), a directory, or a file read through
// a kernel descriptor (kfd), one written (in order, in chunks), or one rewritten here whole.
const fds = new Map();
let nextFd = 4;
function descriptor(fd) { const found = fds.get(fd); if (!found) throw new Errno(EBADF); return found; }
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
function fstat(found) {
  if (STDIO.has(found.kind)) return { filetype: filetype(found), mode: found.tty ? 0o020620 : 0o010600 };
  if (found.kind === 'dir') return stat(found.path);
  if (found.writer || found.rewrite) {
    const now = Math.floor(Date.now() / 1000);
    return { ...(found.stat ?? {}), filetype: REGULAR_FILE, size: size(found), mtime: now, ctime: now };
  }
  return found.stat ?? stat(found.path);
}
const size = found => found.rewrite ? found.data.length : found.writer ? found.flushed + found.length : found.size;

// Open the file at `path` for reading: the descriptor, its first bytes and its stat, in one
// request.
function openRead(path) {
  const [opened, read, stated] = batch([{ open: { path, flags: O_RDONLY } }, { pread: { fd: { ref: 0 }, count: INLINE } }, { stat: { path } }]);
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
// Open it for writing in order: a growing file, truncated or new.
function openWriter(path, flags, read) {
  const opened = call({ open: { path, flags: flags | O_WRONLY } });
  forget();
  return { kind: 'file', path, kfd: opened.fd, writer: true, read, chunk: opened.chunk_size || (8 << 20), flushed: 0, buffer: new Uint8Array(64 * 1024), length: 0, pos: 0 };
}
// Open an existing file to change in place, or append to: its content, written back whole when
// it closes, if it changed.
function openRewrite(path, found, append, read) {
  const [allowed] = batch([{ access: { path, mode: W_OK } }]);
  ok(allowed);
  const data = whole(path, found.size);
  return { kind: 'file', path, rewrite: true, read, data, pos: append ? data.length : 0, append, dirty: false, stat: found };
}

function readFrom(found, at, count) {
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
    return found.pipe.read(count);
  }
  if (found.kind === 'out' || found.kind === 'pipe-out') throw new Errno(EBADF);
  if (!found.read) throw new Errno(EBADF);
  if (found.rewrite) return found.data.subarray(at, at + count);
  if (found.writer) {
    if (at < found.flushed) throw new Errno(ESPIPE);
    return found.buffer.subarray(at - found.flushed, Math.min(found.length, at - found.flushed + count));
  }
  const window = found.window;
  if (at < window.start || at >= window.start + window.data.length) {
    if (at >= found.size) return new Uint8Array(0);
    const want = Math.max(count, INLINE);
    if (want <= INLINE) {
      const read = call({ pread: { fd: found.kfd, offset: at, count: want } });
      found.size = read.size;
      found.window = { start: at, data: unbase64(read.data) };
    } else {
      found.window = { start: at, data: range(found.path, at, Math.min(found.size, at + Math.min(want, WINDOW)), found.token) };
    }
  }
  const from = at - found.window.start;
  return found.window.data.subarray(from, from + count);
}

function writeTo(found, at, data) {
  // A pipe whose reader is gone, or the page's whose reader has closed its end (head, with its
  // lines): SIGPIPE, whose default is to end the process, quietly.
  if (found.kind === 'out') {
    if (found.closed && Atomics.load(found.closed, 0)) { flush(); throw new Exit(141); }
    output(found.fd, data);
    return data.length;
  }
  if (found.kind === 'pipe-out') {
    // A write that waits for room shows what was written first.
    if (found.pipe.room < data.length) flush();
    if (!found.pipe.write(data)) { flush(); throw new Exit(141); }
    return data.length;
  }
  if (found.kind === 'pipe-in') throw new Errno(EBADF);
  if (found.kind !== 'file' || (!found.writer && !found.rewrite)) throw new Errno(EBADF);
  if (found.rewrite) {
    if (found.append) at = found.data.length;
    const end = at + data.length;
    if (end > REWRITE_MAX) throw new Errno(EFBIG);
    if (end > found.data.length) { const grown = new Uint8Array(end); grown.set(found.data); found.data = grown; }
    found.data.set(data, at);
    found.dirty = true;
    return data.length;
  }
  if (at < found.flushed) throw new Errno(ESPIPE);
  const end = at - found.flushed + data.length;
  if (end > found.buffer.length) {
    const grown = new Uint8Array(Math.max(end, found.buffer.length * 2));
    grown.set(found.buffer.subarray(0, found.length));
    found.buffer = grown;
  }
  found.buffer.set(data, at - found.flushed);
  found.length = Math.max(found.length, end);
  // Whole chunks go as they fill: what is left stays to be written on, or with the close.
  while (found.length >= found.chunk + found.chunk) flushChunk(found);
  return data.length;
}
// Send the next chunk, whole, or the last, short.
function flushChunk(found) {
  const count = Math.min(found.chunk, found.length);
  const chunk = found.buffer.slice(0, count);
  const index = found.flushed / found.chunk;
  const xhr = request('PUT', `/api/pwrite?fd=${found.kfd}&index=${index}`, chunk, { 'Content-Type': 'application/octet-stream' });
  if (xhr.status >= 300) throw new Errno(errnoOf(safeJson(xhr.responseText)));
  found.buffer.copyWithin(0, count, found.length);
  found.length -= count;
  found.flushed += count;
}
const safeJson = text => { try { return JSON.parse(text); } catch { return {}; } };

// Close a descriptor: what it wrote goes, with the close, in one request where it can.
function closeFd(found) {
  if (found.kind === 'pipe-in') found.pipe.closeReader();
  else if (found.kind === 'pipe-out') found.pipe.closeWriter();
  else if (found.kind === 'file' && found.writer) {
    while (found.length > found.chunk) flushChunk(found);
    const calls = [];
    if (found.length > INLINE) flushChunk(found);
    if (found.length > 0) calls.push({ pwrite: { fd: found.kfd, index: found.flushed / found.chunk, data: base64(found.buffer.subarray(0, found.length)) } });
    calls.push({ close: { fd: found.kfd } });
    const results = batch(calls);
    forget();
    for (const result of results) ok(result);
  } else if (found.kind === 'file' && found.rewrite && found.dirty) {
    forget();
    if (found.data.length <= INLINE) {
      const results = batch([
        { open: { path: found.path, flags: O_WRONLY | O_TRUNC } },
        ...(found.data.length ? [{ pwrite: { fd: { ref: 0 }, index: 0, data: base64(found.data) } }] : []),
        { close: { fd: { ref: 0 } } },
      ]);
      for (const result of results) ok(result);
    } else {
      const writer = openWriter(found.path, O_TRUNC, false);
      writeTo(writer, 0, found.data);
      closeFd(writer);
    }
  } else if (found.kind === 'file' && found.kfd !== undefined) {
    closing.push(found.kfd);
  }
}

// ---- What the program writes ----

let pending = [], pendingBytes = 0, written = 0, lastFlush = 0;
function output(fd, data) {
  written += data.length;
  if (written > process.limit) { flush(); postMessage({ truncated: true }); throw new Exit(141); }
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
// Run `work`: 0, or its errno.
function attempt(work) {
  try { return work() ?? 0; } catch (err) { if (err instanceof Errno) return err.errno; throw err; }
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
  fd_close: fd => attempt(() => { const found = descriptor(fd); if (fd > 2) fds.delete(fd); closeFd(found); }),
  fd_fdstat_get: (fd, ptr) => attempt(() => {
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
  fd_filestat_get: (fd, ptr) => attempt(() => writeFilestat(ptr, fstat(descriptor(fd)))),
  fd_filestat_set_size: (fd, len) => attempt(() => {
    const found = descriptor(fd), length = Number(len);
    if (found.rewrite) {
      const data = new Uint8Array(length); data.set(found.data.subarray(0, length)); found.data = data; found.dirty = true;
    } else if (found.writer) {
      if (length < found.flushed) throw new Errno(EINVAL);
      writeTo(found, found.flushed + found.length, new Uint8Array(Math.max(0, length - found.flushed - found.length)));
      found.length = length - found.flushed;
    } else throw new Errno(EINVAL);
  }),
  fd_filestat_set_times: (fd, atim, mtim, flags) => attempt(() => { times(descriptor(fd).path, atim, mtim, flags); }),
  fd_pread: (fd, iovs, count, offset, nread) => attempt(() => {
    const found = descriptor(fd);
    let at = Number(offset), total = 0;
    for (const [ptr, len] of iovecs(iovs, count)) {
      const data = readFrom(found, at, len);
      bytes().set(data, ptr); total += data.length; at += data.length;
      if (data.length < len) break;
    }
    view().setUint32(nread, total, true);
  }),
  fd_prestat_get: (fd, ptr) => {
    if (fd !== 3) return EBADF;
    view().setUint8(ptr, 0); view().setUint32(ptr + 4, 1, true);
    return 0;
  },
  fd_prestat_dir_name: (fd, ptr, len) => { if (fd !== 3) return EBADF; bytes().set(encoder.encode('/').subarray(0, len), ptr); return 0; },
  fd_pwrite: (fd, iovs, count, offset, nwritten) => attempt(() => {
    const found = descriptor(fd);
    let at = Number(offset), total = 0;
    for (const [ptr, len] of iovecs(iovs, count)) { total += writeTo(found, at, bytes().slice(ptr, ptr + len)); at += len; }
    view().setUint32(nwritten, total, true);
  }),
  fd_read: (fd, iovs, count, nread) => attempt(() => {
    const found = descriptor(fd);
    let total = 0;
    for (const [ptr, len] of iovecs(iovs, count)) {
      const at = found.pos ?? 0;
      const data = readFrom(found, at, len);
      bytes().set(data, ptr); total += data.length;
      if (!STDIO.has(found.kind)) found.pos = at + data.length;
      if (data.length < len) break;
      // A pipe gives what it has: once some is read, the read waits for no more.
      if (found.kind === 'pipe-in' && total > 0 && found.pipe.queued === 0) break;
    }
    view().setUint32(nread, total, true);
  }),
  fd_readdir: (fd, buf, len, cookie, used) => attempt(() => {
    const found = descriptor(fd);
    if (found.kind !== 'dir') throw new Errno(ENOTDIR);
    if (!found.entries) {
      const listed = call({ getdents: { path: found.path } });
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
  fd_renumber: (from, to) => attempt(() => { const found = descriptor(from); if (fds.has(to)) closeFd(fds.get(to)); fds.set(to, found); fds.delete(from); }),
  fd_seek: (fd, offset, whence, ptr) => attempt(() => {
    const found = descriptor(fd);
    if (found.kind !== 'file') throw new Errno(ESPIPE);
    const base = whence === 0 ? 0 : whence === 1 ? found.pos : size(found);
    const pos = base + Number(offset);
    if (pos < 0) throw new Errno(EINVAL);
    found.pos = pos;
    view().setBigUint64(ptr, BigInt(pos), true);
  }),
  fd_tell: (fd, ptr) => attempt(() => { const found = descriptor(fd); if (found.kind !== 'file') throw new Errno(ESPIPE); view().setBigUint64(ptr, BigInt(found.pos), true); }),
  fd_write: (fd, iovs, count, nwritten) => attempt(() => {
    const found = descriptor(fd);
    let total = 0;
    for (const [ptr, len] of iovecs(iovs, count)) {
      const data = bytes().slice(ptr, ptr + len);
      if (found.kind !== 'file') { total += writeTo(found, 0, data); continue; }
      const at = found.append ? size(found) : found.pos;
      total += writeTo(found, at, data);
      found.pos = at + len;
    }
    view().setUint32(nwritten, total, true);
  }),
  path_create_directory: (fd, ptr, len) => attempt(() => { call({ mkdir: { path: pathAt(fd, ptr, len), mode: 0o777 } }); forget(); }),
  path_filestat_get: (fd, flags, ptr, len, out) => attempt(() => writeFilestat(out, stat(pathAt(fd, ptr, len), (flags & FOLLOW) !== 0))),
  path_filestat_set_times: (fd, flags, ptr, len, atim, mtim, fst) => attempt(() => times(pathAt(fd, ptr, len), atim, mtim, fst)),
  path_link: (fd, flags, ptr, len, fd2, ptr2, len2) => attempt(() => { call({ link: { from: pathAt(fd, ptr, len), to: pathAt(fd2, ptr2, len2), follow: (flags & FOLLOW) !== 0 } }); forget(); }),
  path_open: (fd, dirflags, ptr, len, oflags, base, inheriting, fdflags, out) => attempt(() => {
    const path = pathAt(fd, ptr, len);
    const write = (base & RIGHT_WRITE) !== 0n, read = (base & RIGHT_READ) !== 0n || !write;
    const append = (fdflags & FDFLAG_APPEND) !== 0;
    let found;
    if (oflags & OFLAG_DIRECTORY) {
      if (kindOf(stat(path, (dirflags & FOLLOW) !== 0).mode) !== DIRECTORY) throw new Errno(ENOTDIR);
      found = { kind: 'dir', path };
    } else if (!write) {
      found = openRead(path);
    } else if (oflags & (OFLAG_TRUNC | OFLAG_EXCL)) {
      found = openWriter(path, (oflags & OFLAG_CREAT ? O_CREAT : 0) | (oflags & OFLAG_EXCL ? O_EXCL : 0) | (oflags & OFLAG_TRUNC ? O_TRUNC : 0), read);
    } else {
      // Written without truncating: a new file is written in order; one there is changed here.
      let there;
      try { there = stat(path); } catch (err) { if (!(err instanceof Errno) || err.errno !== ENOENT || !(oflags & OFLAG_CREAT)) throw err; }
      if (!there) found = openWriter(path, O_CREAT, read);
      else if (kindOf(there.mode) === DIRECTORY) throw new Errno(EISDIR);
      else found = openRewrite(path, there, append, read);
    }
    found.append ||= append && found.kind === 'file';
    const number = nextFd++;
    fds.set(number, found);
    view().setUint32(out, number, true);
  }),
  path_readlink: (fd, ptr, len, buf, bufLen, used) => attempt(() => {
    const target = encoder.encode(call({ readlink: { path: pathAt(fd, ptr, len) } }));
    const part = target.subarray(0, bufLen);
    bytes().set(part, buf);
    view().setUint32(used, part.length, true);
  }),
  path_remove_directory: (fd, ptr, len) => attempt(() => { call({ rmdir: { path: pathAt(fd, ptr, len) } }); forget(); }),
  path_rename: (fd, ptr, len, fd2, ptr2, len2) => attempt(() => { call({ rename: { from: pathAt(fd, ptr, len), to: pathAt(fd2, ptr2, len2) } }); forget(); }),
  path_symlink: (ptr, len, fd, ptr2, len2) => attempt(() => { call({ symlink: { target: string(ptr, len), path: pathAt(fd, ptr2, len2) } }); forget(); }),
  path_unlink_file: (fd, ptr, len) => attempt(() => { call({ unlink: { path: pathAt(fd, ptr, len) } }); forget(); }),
  poll_oneoff: (input, output, count, events) => attempt(() => {
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
  random_get: (ptr, len) => { for (let at = 0; at < len; at += 65536) crypto.getRandomValues(bytes().subarray(ptr + at, ptr + Math.min(len, at + 65536))); return 0; },
  sched_yield: () => 0,
};
// What WASI has that a program here cannot do (sockets): not implemented.
const preview1 = new Proxy(wasi, { get: (target, name) => target[name] ?? (() => ENOSYS) });

// utimensat(2), as WASI asks it: each time given, now, or left.
function times(path, atim, mtim, flags) {
  const time = (value, set, now) => flags & now ? 'now' : flags & set ? { sec: Number(value / 1000000000n), nsec: Number(value % 1000000000n) } : 'omit';
  call({ utimens: { path, atime: time(atim, 1, 2), mtime: time(mtim, 4, 8) } });
  forget();
}
// Wait, as a sleeping process does: on a lock nobody releases, where the page may share memory;
// on the clock otherwise.
function sleepUntil(until) {
  const left = until - performance.now();
  if (left <= 0) return;
  // What it wrote shows while it sleeps.
  flush();
  if (typeof SharedArrayBuffer === 'function') { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, left); return; }
  while (performance.now() < until) { /* the clock is the only thing to wait on */ }
}

// terminal.sys: a batch of the kernel's calls (abi::Batch's `calls`, as JSON), sent as it is.
// `sys` sends it and gives the reply's length; `reply` copies the reply where the program says.
let reply = new Uint8Array(0);
const terminal = {
  sys: (ptr, len) => {
    const calls = JSON.parse(string(ptr, len));
    forget();
    reply = encoder.encode(JSON.stringify({ results: batch(calls) }));
    return reply.length;
  },
  reply: ptr => { bytes().set(reply, ptr); },
};

onmessage = async ({ data }) => {
  process = { ...data, limit: data.limit ?? 10 << 20 };
  environ = Object.entries(data.env ?? {}).map(([name, value]) => `${name}=${value}`);
  const { stdin = {}, stdout = {}, stderr = {} } = data;
  fds.set(0, stdin.pipe ? { kind: 'pipe-in', pipe: new Pipe(stdin.pipe), tty: !!stdin.tty } : { kind: 'in', tty: !!stdin.tty, data: stdin.data ?? new Uint8Array(0), pos: 0 });
  fds.set(1, stdout.pipe ? { kind: 'pipe-out', pipe: new Pipe(stdout.pipe) } : { kind: 'out', fd: 1, tty: !!stdout.tty, closed: stdout.closed ? new Int32Array(stdout.closed) : null });
  fds.set(2, { kind: 'out', fd: 2, tty: !!stderr.tty });
  fds.set(3, { kind: 'dir', path: '/' });
  let code = 0;
  try {
    const instance = await WebAssembly.instantiate(data.module, { wasi_snapshot_preview1: preview1, terminal });
    memory = instance.exports.memory;
    instance.exports._start();
  } catch (err) {
    if (err instanceof Exit) code = err.code;
    else { output(2, encoder.encode(`${process.argv[0]}: ${err?.message ?? err}\n`)); code = 134; }
  }
  // What it left open closes as it exits, as a process's descriptors do: its pipes too, so that
  // the next reads to their end, and the one before hears SIGPIPE.
  for (const [, found] of fds) { try { closeFd(found); } catch { /* it exits all the same */ } }
  if (closing.length) { try { batch([]); } catch { /* likewise */ } }
  flush();
  postMessage({ exit: code });
};

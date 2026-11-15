import { releaseId } from '../release.js';
import { localPath, localFdPath, LOCAL_FD } from '../kernel/workspace.js';
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
// it waits on. `os.sys` reaches the kernel's own calls, which WASI has no words for
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
import { Signals, bit, valid, ignoredByDefault, stoppedByDefault, SA_RESTART, SA_NODEFER, SA_RESETHAND } from './signals.mjs';
import { execCandidates } from './resolve.mjs';
import { Pipe, pipeBuffer, PIPE_ATOMIC } from './pipe.js';
import { Engine } from './fork.js';
import { Bytes, Shares } from './shared.js';
import { TtyState, TtyControl, IOCTL, CC, LF } from '../kernel/pty.js';
import { isByteDevice, readDevice } from './devices.mjs';

// WASI's errno numbers, by Linux's names, as the kernel answers.
const ERRNO = {
  E2BIG: 1, EACCES: 2, EAGAIN: 6, EBADF: 8, EBUSY: 10, ECANCELED: 11, ECHILD: 12, EDEADLK: 16, EEXIST: 20, EFAULT: 21, EFBIG: 22, EINTR: 27,
  EINVAL: 28, EIO: 29, EISDIR: 31, ELOOP: 32, EMFILE: 33, EMLINK: 34, ENAMETOOLONG: 37, ENODEV: 43, ENOENT: 44,
  ENOEXEC: 45, ENOMEM: 48, ENOSPC: 51, ENOSYS: 52, ENOTCONN: 53, ENOTDIR: 54, ENOTEMPTY: 55, ENOTSUP: 58, EOPNOTSUPP: 58,
  ENOTTY: 59, ENXIO: 60, EPERM: 63, EPIPE: 64, EPROTONOSUPPORT: 66, ERANGE: 68, EROFS: 69, ESPIPE: 70, ESRCH: 71, ESTALE: 72,
  ETIMEDOUT: 73, ETXTBSY: 74, EXDEV: 75, ENODATA: 44,
};
const { EBADF, EINVAL, EIO, EISDIR, ENOENT, ENOSYS, ENOTDIR, ESPIPE, EFBIG } = ERRNO;
// What an execve that fails says, as a shell says it.
const STRERROR = { 2: 'Permission denied', 44: 'No such file or directory', 45: 'Exec format error', 54: 'Not a directory', 31: 'Is a directory' };
// The kinds of descriptor standard input and output are: bytes given, the page's, a pipe's end.
const STDIO = new Set(['in', 'out', 'pipe-in', 'pipe-out', 'tty', 'pty']);
// What a file is, as WASI numbers it.
const CHARACTER_DEVICE = 2, DIRECTORY = 3, REGULAR_FILE = 4, SYMBOLIC_LINK = 7, UNKNOWN = 0;
// open(2)'s flags, as the kernel takes them (Linux's).
const O_RDONLY = 0, O_WRONLY = 1, O_RDWR = 2, O_CREAT = 0o100, O_EXCL = 0o200, O_TRUNC = 0o1000, O_APPEND = 0o2000;
const W_OK = 2;
// path_open's: oflags, fdflags, lookupflags, and the rights a descriptor has.
const OFLAG_CREAT = 1, OFLAG_DIRECTORY = 2, OFLAG_EXCL = 4, OFLAG_TRUNC = 8, FDFLAG_APPEND = 1, FDFLAG_NONBLOCK = 4, FOLLOW = 1;
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
class SignalJump { constructor(pending) { this.pending = pending; } }
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
  xhr.setRequestHeader('X-OS-Release', releaseId);
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
  if (process.localFs && sent.some(call => {
    if (!call || typeof call !== 'object') return false;
    const arg = Object.values(call)[0];
    return arg && (arg.fd >= LOCAL_FD || [arg.path, arg.from, arg.to].some(path => localPath(path) || localFdPath(path) || ['/', '/mnt', '/opt'].includes(path)));
  })) return hostErrno(host('filesystem', { calls: sent, umask: process.umask })).slice(0, calls.length);
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
  if (allocatedPath(path) || path === '/dev/pts') return hostErrno(host('pty', { op: 'stat', path }));
  if (isTerminal(path)) return { ino: process.pty.number, mode: 0o020620, nlink: 1, size: 0 };
  const key = (follow ? 's:' : 'l:') + path;
  if (!localPath(path) && cache.has(key)) return cache.get(key);
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
  if (process.pid) headers['X-Process-Pid'] = String(process.pid);
  const answer = yield* request('GET', url, null, headers, true);
  if (answer.status === 416) return new Uint8Array(0);
  if (answer.status !== 200 && answer.status !== 206) throw new Errno(answer.status === 429 ? ERRNO.EAGAIN : answer.status === 404 ? ENOENT : answer.status === 403 ? ERRNO.EACCES : EIO);
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
let shares = null, ttyState = null, ttyControl = null, membership = null;
let lastTtyFds = '';
function reportTty() {
  if (!process.pty) return;
  const numbers = [...fds].filter(([, description]) => description.kind === 'tty').map(([fd]) => fd);
  const value = JSON.stringify(numbers);
  if (value !== lastTtyFds) { lastTtyFds = value; postMessage({ ttyFds: numbers }); }
}
const controllingTerminal = () => !!process.pty && Atomics.load(membership, 2) === process.pty.number;
const isTerminal = path => {
  if (path === '/dev/tty' && !Atomics.load(membership, 2)) throw new Errno(ERRNO.ENXIO);
  const matches = !!process.pty && (path === '/dev/tty' || path === `/dev/pts/${process.pty.number}`);
  if (matches && ttyControl?.hungup) throw new Errno(path === '/dev/tty' ? ERRNO.ENXIO : ENOENT);
  return matches;
};
const allocatedNumber = path => path === '/dev/tty' ? Atomics.load(membership, 2) : Number(path.slice('/dev/pts/'.length));
const allocatedPath = path => path === '/dev/ptmx' || path === '/dev/tty' && Atomics.load(membership, 2) >= 0x40000000 || /^\/dev\/pts\/[1-9][0-9]*$/.test(path) && allocatedNumber(path) >= 0x40000000;
const localDescriptor = path => {
  const match = new RegExp(`^/proc/(?:self|${process.pid})/fd/([0-9]+)$`).exec(path);
  return match && fds.get(Number(match[1]));
};
const localLink = path => {
  const found = localDescriptor(path);
  return found?.kind === 'pty' ? (found.master ? '/dev/ptmx' : `/dev/pts/${found.number}`) : null;
};
const ptyCall = (found, op, args = {}) => hostErrno(host('pty', { handle: found.handle, op, ...args }));
const ttyCall = (found, request, arg) => {
  if (!found.tty || found.kind !== 'pty' && !ttyState) throw new Errno(ERRNO.ENOTTY);
  return hostErrno(host('tty', { handle: found.handle, request, arg, readable: found.readable !== false }));
};
const terminalFd = (fd, readable = true, writable = true) => ({ kind: 'tty', tty: true, fd, readable, writable, pipe: new Pipe(process.pty.input, process.pid) });
function descriptor(fd) { const found = fd >= 0 ? fds.get(fd) : null; if (!found) throw new Errno(EBADF); return found; }
// The lowest descriptor free from `min` on, as open(2) and dup(2) take.
function lowest(min = 0) { if (min < 0) throw new Errno(EBADF); let fd = min; while (fds.has(fd)) fd++; return fd; }
// Non-isolated hosts still run sequential programs; only fork needs shared flags.
const descriptorFlags = () => typeof SharedArrayBuffer === 'function' ? new SharedArrayBuffer(4) : new ArrayBuffer(4);
// `fd` is `found`, one more descriptor of it; a pipe's end is held once more, a shared open
// file counted once more (unless what started this process counted it already: its host, for
// the pipes it gave, or its parent, for what it forked with).
function install(fd, found, counted = false) {
  // An open description's flags survive dup/fork/exec and are shared with its holders.
  if (STDIO.has(found.kind) && found.kind !== 'pty') found.flags ??= descriptorFlags();
  if (!counted && found.kind === 'pty') ptyCall(found, 'hold');
  found.refs = (found.refs ?? 0) + 1;
  fds.set(fd, found);
  reportTty();
  if (counted) return;
  if (found.kind === 'pipe-in' || found.kind === 'tty') found.pipe.hold(process.pid, 'r');
  else if (found.kind === 'pipe-out') found.pipe.hold(process.pid, 'w');
  else if (found.share != null) shares.add(found.share, process.pid, 1);
  else if (shares && found.kind === 'file') share(found);
}
const nonblocking = found => found.kind === 'pty' ? ptyCall(found, 'flags').nonblock
  : !!(found.flags && Atomics.load(new Int32Array(found.flags), 0) & FDFLAG_NONBLOCK);
// A file of the kernel's, just opened, in its line's table: its host is told of it.
function share(found) {
  const slot = shares.claim(process.pid, found.refs, found.pos ?? 0);
  if (slot < 0) return;
  if (found.kind === 'in' && !(found.data.buffer instanceof SharedArrayBuffer)) {
    const data = new Uint8Array(new SharedArrayBuffer(found.data.length));
    data.set(found.data);
    found.data = data;
  }
  shares.attach(found, slot);
  postMessage({ described: { slot, gen: shares.gen(slot), description: describe(found) } });
}
// close(2) of `fd`: its open file closes once no descriptor of it is left, here or in another
// process.
function* uninstall(fd) {
  const found = fds.get(fd);
  if (!found) throw new Errno(EBADF);
  fds.delete(fd);
  reportTty();
  cloexec.delete(fd);
  found.refs--;
  if (found.kind === 'pty') return ptyCall(found, 'close');
  if (found.kind === 'pipe-in' || found.kind === 'tty') return found.pipe.drop(process.pid, 'r');
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
  locked++;
  let result;
  try { result = yield* work(); } finally { locked--; shares.unlock(found.share); }
  dispatchSignals();
  return result;
}
function filetype(found) {
  if (isByteDevice(found.device)) return CHARACTER_DEVICE;
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
  if (found.local) return yield* call({ fstat: { fd: found.kfd } });
  if (found.kind === 'pty') return { ino: found.number, filetype: CHARACTER_DEVICE, mode: 0o020600 };
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
  const { fd, token, device } = ok(opened);
  // What cannot be read closes, as it goes: a directory, opened as open(2) opens one, is one.
  if ('err' in read) {
    closing.push(fd);
    if (read.err.errno === 'EISDIR') return { kind: 'dir', path };
    ok(read);
  }
  const first = read.ok;
  return { kind: 'file', path, kfd: fd, token, device, read: true, pos: 0, size: first.size, window: { start: 0, data: unbase64(first.data) }, stat: stated.ok };
}
// Open it for writing in order: a growing file, truncated or new. What is not sent yet is held
// in memory a fork shares (shared.js): at most two chunks and an inline write.
function* openWriter(path, flags, read, mode = 0o666) {
  const opened = yield* call({ open: { path, flags: flags | (read ? O_RDWR : O_WRONLY), mode } });
  forget();
  if (isByteDevice(opened.device)) return { kind: 'file', path, kfd: opened.fd, device: opened.device, writable: true, read, pos: 0, size: 0 };
  const chunk = opened.chunk_size || (8 << 20);
  return { kind: 'file', path, kfd: opened.fd, writer: true, read, chunk, bytes: Bytes.create(chunk * 2 + INLINE), pos: 0 };
}
// Open an existing file to change in place, or append to: its content, written back whole when
// it closes, if it changed.
function* openRewrite(path, found, append, read) {
  if (isByteDevice(found.rdev)) return yield* openWriter(path, 0, read);
  const [allowed] = yield* batch([{ access: { path, mode: W_OK } }]);
  ok(allowed);
  const data = yield* whole(path, found.size);
  const bytes = Bytes.create(REWRITE_MAX, Math.max(data.length, 64 * 1024));
  bytes.ensure(data.length);
  bytes.view.set(data);
  bytes.length = data.length;
  return { kind: 'file', path, rewrite: true, read, bytes, pos: append ? data.length : 0, append, stat: found };
}

// VMIN/VTIME govern raw reads; canonical reads never consume a second line. Waiting
// checks the process signal word, so a blocked read remains stoppable and cancellable.
function readTerminal(pipe, count) {
  if (ttyControl.hungup) return new Uint8Array(0);
  if (count) ttyAccess(21);
  if (ttyState.canonical) {
    const data = pipe.read(count, () => pause(true), true);
    return ttyControl.hungup ? new Uint8Array(0) : data;
  }
  const minimum = Math.min(count, ttyState.cc(CC.VMIN)), timeout = ttyState.cc(CC.VTIME) * 100;
  const parts = []; let length = 0, until = minimum === 0 && timeout ? performance.now() + timeout : Infinity;
  for (;;) {
    pause();
    if (ttyControl.hungup) return new Uint8Array(0);
    if (pipe.queued || pipe.ending || pipe.writerGone) {
      const part = pipe.read(count - length, () => pause(true)); parts.push(part); length += part.length;
      if (!part.length || length >= minimum || length >= count) break;
      if (timeout) until = performance.now() + timeout;
    }
    if ((!minimum && !timeout) || performance.now() >= until) break;
    if (control) Atomics.wait(control, 0, 0, 10);
    else break;
  }
  const out = new Uint8Array(length); let at = 0;
  for (const part of parts) { out.set(part, at); at += part.length; }
  return out;
}

function readPty(found, count) {
  if (!count) return new Uint8Array(0);
  if (!found.master) ttyAccess(21, found);
  const modes = found.master ? null : ttyCall(found, IOCTL.TCGETS);
  const canonical = !modes || !!(modes.lflag & LF.ICANON);
  const minimum = canonical ? 1 : Math.min(count, modes.cc[CC.VMIN]);
  const timeout = canonical ? 0 : modes.cc[CC.VTIME] * 100;
  let until = minimum === 0 && timeout ? performance.now() + timeout : Infinity, total = 0;
  const chunks = [];
  for (;;) {
    let result;
    try { pause(true); result = ptyCall(found, 'read', { count: Math.min(4096, count - total) }); }
    catch (error) { if (total && error instanceof Errno && error.errno === ERRNO.EINTR) break; throw error; }
    if (result.data) {
      const chunk = Uint8Array.from(result.data); chunks.push(chunk); total += chunk.length;
      if (!chunk.length || canonical || total >= minimum || total >= count) break;
      if (timeout) until = performance.now() + timeout;
    } else if (result.nonblock) { if (!total) throw new Errno(ERRNO.EAGAIN); break; }
    if ((!minimum && !timeout) || performance.now() >= until) break;
    try { sleepUntil(Math.min(until, performance.now() + 10)); }
    catch (error) { if (total && error instanceof Errno && error.errno === ERRNO.EINTR) break; throw error; }
  }
  const out = new Uint8Array(total); let at = 0;
  for (const chunk of chunks) { out.set(chunk, at); at += chunk.length; }
  return out;
}
function writePty(found, data) {
  if (!found.master && data.length && ttyCall(found, IOCTL.TCGETS).lflag & LF.TOSTOP) ttyAccess(22, found);
  let total = 0;
  while (total < data.length) {
    try {
      pause(true);
      const result = ptyCall(found, 'write', { data: Array.from(data.subarray(total, total + 4096)) });
      if (result.wait) {
        if (result.nonblock) { if (!total) throw new Errno(ERRNO.EAGAIN); break; }
        sleepUntil(performance.now() + 10);
      } else total += result.count;
    } catch (error) { if (total && error instanceof Errno && [ERRNO.EINTR, ERRNO.EIO].includes(error.errno)) break; throw error; }
  }
  return total;
}
function* readFrom(found, at, count) {
  if (found.local) {
    if (!found.read) throw new Errno(EBADF);
    const result = hostErrno(host('local_read', { fd: found.kfd, offset: at, count: Math.min(INLINE, count) }));
    found.size = result.size; return unbase64(result.data);
  }
  if (found.tty && found.readable === false) throw new Errno(EBADF);
  if (found.kind === 'pty') return readPty(found, count);
  if (found.kind === 'dir') throw new Errno(EISDIR);
  if (found.kind === 'in') {
    const out = found.data.subarray(found.pos, found.pos + count);
    found.pos += out.length;
    return out;
  }
  if (found.kind === 'pipe-in' || found.kind === 'tty') {
    if (count === 0) return new Uint8Array(0);
    const nonblock = nonblocking(found);
    if (nonblock && found.tty) ttyAccess(21);
    // A read that waits shows what was written first; on the terminal, the page hears it asks.
    if (found.pipe.empty) { flush(nonblock); if (found.tty) postMessage({ reading: true }); }
    const read = nonblock ? found.pipe.read(count, undefined, !!(found.tty && ttyState?.canonical), true)
      : found.tty && ttyState ? readTerminal(found.pipe, count) : found.pipe.read(count, () => pause(true));
    if (read === null) throw new Errno(ERRNO.EAGAIN);
    pause();
    return read;
  }
  if (found.kind === 'out' || found.kind === 'pipe-out') throw new Errno(EBADF);
  if (!found.read) throw new Errno(EBADF);
  if (isByteDevice(found.device)) {
    try { return readDevice(found.device, count); } catch { throw new Errno(EIO); }
  }
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
  if (found.local) {
    if (!found.writable) throw new Errno(EBADF);
    let written = 0;
    while (written < data.length) {
      const chunk = data.subarray(written, written + INLINE);
      const result = hostErrno(host('local_write', { fd: found.kfd, offset: at + written, append: !!found.append, data: base64(chunk) }));
      written += result.written; found.size = result.size;
    }
    return written;
  }
  if (found.tty && found.writable === false) throw new Errno(EBADF);
  if (found.kind === 'pty') return writePty(found, data);
  if (found.kind === 'tty' && ttyControl.hungup) throw new Errno(EIO);
  if (isByteDevice(found.device)) {
    if (!found.writable) throw new Errno(EBADF);
    if (found.device === 'full') throw new Errno(ERRNO.ENOSPC);
    return data.length;
  }
  // A pipe whose reader is gone, or the page's whose reader has closed its end (head, with its
  // lines): SIGPIPE, whose default is to end the process, quietly.
  if (data.length && found.tty && ttyState && (ttyState.get(2) & LF.TOSTOP)) ttyAccess(22);
  if (found.kind === 'tty') {
    if (nonblocking(found)) return outputNonblocking(found.fd ?? 1, data, ttyState);
    output(found.fd ?? 1, ttyState.output(data), true); return data.length;
  }
  if (found.kind === 'out') {
    if (found.closed && Atomics.load(found.closed, 0)) brokenPipe();
    if (nonblocking(found)) return outputNonblocking(found.fd, data, found.tty ? ttyState : null, !!found.tty);
    output(found.fd, found.tty && ttyState ? ttyState.output(data) : data);
    return data.length;
  }
  if (found.kind === 'pipe-out') {
    if (nonblocking(found)) {
      const { written, broken } = found.pipe.tryWrite(data);
      if (broken) return brokenPipe(written);
      if (!written && data.length) throw new Errno(ERRNO.EAGAIN);
      return written;
    }
    // A write that waits for room shows what was written first.
    if (found.pipe.room < data.length) flush();
    const { written, broken } = found.pipe.write(data, done => {
      try { pause(true); }
      catch (error) {
        if (done && error instanceof Errno && error.errno === ERRNO.EINTR) return false;
        throw error;
      }
    });
    return broken ? brokenPipe(written) : written;
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
function brokenPipe(written = 0) {
  signals.queue(SIGPIPE);
  dispatchSignals();
  if (written) return written;
  throw new Errno(ERRNO.EPIPE);
}
// Send the next chunk, whole, or the last, short (its bytes' lock held).
function* flushChunk(found) {
  const bytes = found.bytes;
  const count = Math.min(found.chunk, bytes.length);
  const chunk = bytes.bytes(0, count).slice();
  const index = bytes.from / found.chunk;
  const headers = { 'Content-Type': 'application/octet-stream' };
  if (process.proc) headers['X-Process-Token'] = process.proc;
  if (process.pid) headers['X-Process-Pid'] = String(process.pid);
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

let pending = [], pendingBytes = 0, written = 0, lastFlush = 0, outputCredit = null;
const OUTPUT_CHUNK = 4096;
function output(fd, data, tty = false) {
  // A real terminal applies backpressure instead of ending a verbose program at a byte cap.
  // Captured/non-isolated output retains its explicit limit.
  if (!tty || !outputCredit) {
    written += data.length;
    if (written > process.limit) { flush(); postMessage({ truncated: true }); throw killedBy(SIGPIPE); }
  }
  for (let at = 0; at < data.length;) {
    const end = Math.min(data.length, at + OUTPUT_CHUNK - pendingBytes);
    pending.push([fd, data.slice(at, end), tty]);
    pendingBytes += end - at;
    at = end;
    if (pendingBytes >= OUTPUT_CHUNK || performance.now() - lastFlush > 100) flush();
  }
}
function flush(nonblock = false) {
  lastFlush = performance.now();
  if (!pending.length) return true;
  // Each frame needs one credit. Flags may have changed after buffered writes;
  // defer those frames without turning a nonblocking write into a hidden wait.
  if (nonblock && outputCredit) {
    let frames = 1;
    for (let i = 1; i < pending.length; i++) if (pending[i][0] !== pending[i - 1][0] || pending[i][2] !== pending[i - 1][2]) frames++;
    for (;;) {
      const available = Atomics.load(outputCredit, 0);
      if (available < frames) return false;
      if (Atomics.compareExchange(outputCredit, 0, available, available - frames) === available) break;
    }
  }
  // Detach first: checking a signal while waiting for credit can itself call flush().
  const sending = pending;
  pending = []; pendingBytes = 0;
  let fd = sending[0][0], tty = sending[0][2], parts = [];
  const send = () => {
    if (!parts.length) return;
    if (outputCredit && !nonblock) {
      for (;;) {
        pause();
        const available = Atomics.load(outputCredit, 0);
        if (available > 0 && Atomics.compareExchange(outputCredit, 0, available, available - 1) === available) break;
        Atomics.wait(outputCredit, 0, available, 50);
      }
    }
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let at = 0;
    for (const part of parts) { out.set(part, at); at += part.length; }
    postMessage({ fd, out, tty, credit: !!outputCredit }, [out.buffer]);
  };
  for (const [which, data, terminal] of sending) {
    if (which !== fd || terminal !== tty) { send(); fd = which; tty = terminal; parts = []; }
    parts.push(data);
  }
  send();
  return true;
}

function outputNonblocking(fd, data, state, tty = true) {
  if (!data.length) return 0;
  if (!flush(true)) throw new Errno(ERRNO.EAGAIN);
  if (outputCredit) {
    for (;;) {
      const credit = Atomics.load(outputCredit, 0);
      if (credit <= 0) throw new Errno(ERRNO.EAGAIN);
      if (Atomics.compareExchange(outputCredit, 0, credit, credit - 1) === credit) break;
    }
  }
  const count = Math.min(data.length, state ? OUTPUT_CHUNK / 2 : OUTPUT_CHUNK);
  const out = state ? state.output(data.slice(0, count)) : data.slice(0, count);
  if (!tty || !outputCredit) {
    written += out.length;
    if (written > process.limit) { postMessage({ truncated: true }); throw killedBy(SIGPIPE); }
  }
  postMessage({ fd, out, tty, credit: !!outputCredit }, [out.buffer]);
  return count;
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
// Newer WASIX exec uses counted arrays of pointers to NUL-terminated strings.
function pointerStrings(ptr, count) {
  if (count < 0 || count > 4096) throw new Errno(ERRNO.E2BIG);
  const v = view(), b = bytes(), result = [];
  if (ptr < 0 || ptr + count * 4 > b.length) throw new Errno(ERRNO.EFAULT);
  let total = 0;
  for (let i = 0; i < count; i++) {
    const start = v.getUint32(ptr + i * 4, true);
    if (start >= b.length) throw new Errno(ERRNO.EFAULT);
    // Bound scanning as well as allocation for malformed guest pointer arrays.
    const limit = Math.min(b.length, start + (1 << 20) - total);
    const relativeEnd = b.subarray(start, limit).indexOf(0);
    if (relativeEnd < 0) throw new Errno(limit === b.length ? ERRNO.EFAULT : ERRNO.E2BIG);
    const end = start + relativeEnd;
    total += end - start + 1;
    if (total > 1 << 20) throw new Errno(ERRNO.E2BIG);
    result.push(decoder.decode(b.slice(start, end)));
  }
  return result;
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
  const path = string(ptr, len);
  // Like openat(2), an absolute path does not depend on the directory descriptor.
  // Resource access still goes through the process-authenticated kernel calls.
  if (path.startsWith('/')) return clean(path);
  const dir = descriptor(fd);
  if (dir.kind !== 'dir') throw new Errno(ENOTDIR);
  return clean(join(dir.path, path));
}
let environ = [];

function* openPath(path, dirflags, oflags, base, fdflags, noctty = false, mode = 0o666) {
    const write = (base & RIGHT_WRITE) !== 0n, read = (base & RIGHT_READ) !== 0n || !write;
    const append = (fdflags & FDFLAG_APPEND) !== 0;
    const original = localDescriptor(path);
    // Reopening a pipe or terminal creates a new open description. Unlike dup,
    // its status flags are independent of the shell's inherited descriptors.
    if (original?.kind === 'pty' && !original.master) path = localLink(path);
    let found;
    if (original && ['out', 'pipe-in', 'pipe-out', 'tty'].includes(original.kind)) {
      if (oflags & OFLAG_DIRECTORY) throw new Errno(ENOTDIR);
      if (oflags & OFLAG_CREAT && oflags & OFLAG_EXCL) throw new Errno(ERRNO.EEXIST);
      if (fdflags & ~FDFLAG_NONBLOCK) throw new Errno(ERRNO.EOPNOTSUPP);
      const readable = original.kind === 'pipe-in' || original.kind === 'tty' && original.readable !== false;
      const writable = ['out', 'pipe-out'].includes(original.kind) || original.kind === 'tty' && original.writable !== false;
      if (read && !readable || write && !writable) throw new Errno(ERRNO.EACCES);
      found = { ...original, refs: 0, flags: descriptorFlags(), readable: read, writable: write };
    } else if (path === '/dev/pts') {
      if (write) throw new Errno(EISDIR);
      found = { kind: 'dir', path };
    } else if (allocatedPath(path)) {
      if (oflags & OFLAG_DIRECTORY) throw new Errno(ENOTDIR);
      if (oflags & OFLAG_CREAT && oflags & OFLAG_EXCL) throw new Errno(ERRNO.EEXIST);
      found = { kind: 'pty', tty: true, ...hostErrno(host('pty', { op: 'open', path, readable: read, writable: write, nonblock: !!(fdflags & FDFLAG_NONBLOCK), noctty })) };
    } else if (isTerminal(path)) {
      if (oflags & OFLAG_DIRECTORY) throw new Errno(ENOTDIR);
      found = terminalFd(1, read, write);
      if (!noctty && path !== '/dev/tty') ttyCall(found, 'open');
    } else if (process.localFs && localPath(path)) {
      if (oflags & OFLAG_DIRECTORY) {
        if (kindOf((yield* stat(path)).mode) !== DIRECTORY) throw new Errno(ENOTDIR);
        found = { kind: 'dir', path };
      } else {
        try {
          const opened = yield* call({ open: { path, flags: (write ? read ? O_RDWR : O_WRONLY : O_RDONLY) |
            (oflags & OFLAG_CREAT ? O_CREAT : 0) | (oflags & OFLAG_TRUNC ? O_TRUNC : 0) | (oflags & OFLAG_EXCL ? O_EXCL : 0) | (append ? O_APPEND : 0) } });
          found = { kind: 'file', local: true, path, kfd: opened.fd, token: opened.token, read, writable: write, pos: 0, size: opened.size, stat: opened.stat };
        } catch (error) {
          if (!(error instanceof Errno) || error.errno !== EISDIR || write) throw error;
          found = { kind: 'dir', path };
        }
      }
    } else if (oflags & OFLAG_DIRECTORY) {
      if (kindOf((yield* stat(path, (dirflags & FOLLOW) !== 0)).mode) !== DIRECTORY) throw new Errno(ENOTDIR);
      found = { kind: 'dir', path };
    } else if (!write) {
      found = yield* openRead(path);
    } else if (oflags & (OFLAG_TRUNC | OFLAG_EXCL)) {
      found = yield* openWriter(path, (oflags & OFLAG_CREAT ? O_CREAT : 0) | (oflags & OFLAG_EXCL ? O_EXCL : 0) | (oflags & OFLAG_TRUNC ? O_TRUNC : 0), read, mode);
    } else {
      // Written without truncating: a new file is written in order; one there is changed here.
      let there;
      try { there = yield* stat(path); } catch (err) { if (!(err instanceof Errno) || err.errno !== ENOENT || !(oflags & OFLAG_CREAT)) throw err; }
      if (!there) found = yield* openWriter(path, O_CREAT, read, mode);
      else if (kindOf(there.mode) === DIRECTORY) throw new Errno(EISDIR);
      else found = yield* openRewrite(path, there, append, read);
    }
    found.append ||= append && found.kind === 'file';
    const number = lowest();
    install(number, found, found.kind === 'pty');
    if (found.flags) Atomics.store(new Int32Array(found.flags), 0, fdflags & FDFLAG_NONBLOCK);
    return number;
}

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
  fd_close: fd => attempt(function* () { descriptor(fd); return yield* uninstall(fd); }),
  fd_fdstat_get: (fd, ptr) => attempt(function* () {
    const found = descriptor(fd), v = view();
    v.setUint8(ptr, filetype(found));
    v.setUint16(ptr + 2, (found.append ? FDFLAG_APPEND : 0) | (nonblocking(found) ? FDFLAG_NONBLOCK : 0), true);
    // A terminal cannot seek, which is how libc's isatty tells it.
    let rights = found.tty ? ALL_RIGHTS & ~(RIGHT_SEEK | RIGHT_TELL) : ALL_RIGHTS;
    if (found.tty && found.readable === false) rights &= ~RIGHT_READ;
    if (found.tty && found.writable === false) rights &= ~RIGHT_WRITE;
    v.setBigUint64(ptr + 8, rights, true);
    v.setBigUint64(ptr + 16, ALL_RIGHTS, true);
  }),
  fd_fdstat_set_flags: (fd, flags) => attempt(function* () {
    const found = descriptor(fd);
    if (found.kind === 'pty') {
      if (flags & ~FDFLAG_NONBLOCK) throw new Errno(ERRNO.EOPNOTSUPP);
      ptyCall(found, 'flags', { nonblock: !!(flags & FDFLAG_NONBLOCK) });
    } else if (found.flags) {
      if (flags & ~FDFLAG_NONBLOCK) throw new Errno(ERRNO.EOPNOTSUPP);
      Atomics.store(new Int32Array(found.flags), 0, flags);
    }
  }),
  fd_fdstat_set_rights: () => 0,
  fd_filestat_get: (fd, ptr) => attempt(function* () { return writeFilestat(ptr, (yield* fstat(descriptor(fd)))); }),
  fd_filestat_set_size: (fd, len) => attempt(function* () {
    const found = descriptor(fd), length = Number(len);
    if (found.local) {
      yield* call({ ftruncate: { fd: found.kfd, size: length } }); found.size = length; return;
    }
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
        if (!STDIO.has(found.kind)) found.pos = isByteDevice(found.device) ? 0 : at + data.length;
        if (data.length < len) break;
        // A pipe gives what it has: once some is read, the read waits for no more.
        if (['pipe-in', 'tty'].includes(found.kind) && total > 0 && found.pipe.queued === 0) break;
        if (found.kind === 'pty' && total > 0 && !ptyCall(found, 'poll', { writing: false }).nbytes) break;
      }
    });
    view().setUint32(nread, total, true);
  }),
  fd_readdir: (fd, buf, len, cookie, used) => attempt(function* () {
    const found = descriptor(fd);
    if (found.kind !== 'dir') throw new Errno(ENOTDIR);
    if (process.localFs && localPath(found.path)) { yield* stat(found.path); found.entries = null; }
    if (!found.entries) {
      const listed = found.path === '/dev/pts' ? hostErrno(host('pty', { op: 'list' })).entries : yield* call({ getdents: { path: found.path } });
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
    if (to < 0) throw new Errno(EBADF);
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
      if (isByteDevice(found.device)) {
        found.pos = 0;
        view().setBigUint64(ptr, 0n, true);
        return;
      }
      const base = whence === 0 ? 0 : whence === 1 ? found.pos : found.local ? (yield* fstat(found)).size : size(found);
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
    try { yield* exclusive(found, function* () {
      const vectors = iovecs(iovs, count);
      // PIPE_BUF atomicity applies to the complete writev, not each vector.
      // Combine only small nonblocking pipe writes; larger writes may be partial.
      if (found.kind === 'pipe-out' && vectors.length > 1 && nonblocking(found)) {
        const length = vectors.reduce((sum, [, len]) => sum + len, 0);
        if (length <= PIPE_ATOMIC) {
          const data = new Uint8Array(length), memory = bytes();
          let at = 0;
          for (const [ptr, len] of vectors) {
            if (ptr + len > memory.length) throw new Errno(ERRNO.EFAULT);
            data.set(memory.subarray(ptr, ptr + len), at); at += len;
          }
          total = yield* writeTo(found, 0, data);
          return;
        }
      }
      for (const [ptr, len] of vectors) {
        const data = bytes().slice(ptr, ptr + len);
        if (found.kind !== 'file') {
          const written = yield* writeTo(found, 0, data);
          total += written;
          if (written < data.length) break;
          continue;
        }
        const at = found.append ? size(found) : found.pos;
        total += yield* writeTo(found, at, data);
        found.pos = isByteDevice(found.device) ? 0 : found.local && found.append ? found.size : at + len;
      }
    }); } catch (error) {
      // writev may have finished earlier vectors before a signal interrupts a
      // later one. Report those bytes so libc does not resend them.
      if (!total || !(error instanceof Errno) || ![ERRNO.EINTR, ERRNO.EPIPE, ERRNO.EAGAIN].includes(error.errno)) throw error;
    }
    view().setUint32(nwritten, total, true);
  }),
  path_create_directory: (fd, ptr, len) => attempt(function* () { yield* call({ mkdir: { path: pathAt(fd, ptr, len), mode: 0o777 } }); forget(); }),
  path_filestat_get: (fd, flags, ptr, len, out) => attempt(function* () { return writeFilestat(out, (yield* stat(pathAt(fd, ptr, len), (flags & FOLLOW) !== 0))); }),
  path_filestat_set_times: (fd, flags, ptr, len, atim, mtim, fst) => attempt(function* () { return yield* times(pathAt(fd, ptr, len), atim, mtim, fst, (flags & FOLLOW) !== 0); }),
  path_link: (fd, flags, ptr, len, fd2, ptr2, len2) => attempt(function* () { yield* call({ link: { from: pathAt(fd, ptr, len), to: pathAt(fd2, ptr2, len2), follow: (flags & FOLLOW) !== 0 } }); forget(); }),
  path_open: (fd, dirflags, ptr, len, oflags, base, inheriting, fdflags, out) => attempt(function* () {
    view().setUint32(out, yield* openPath(pathAt(fd, ptr, len), dirflags, oflags, base, fdflags), true);
  }),
  path_readlink: (fd, ptr, len, buf, bufLen, used) => attempt(function* () {
    const path = pathAt(fd, ptr, len);
    const target = encoder.encode(localLink(path) ?? (yield* call({ readlink: { path } })));
    const part = target.subarray(0, bufLen);
    bytes().set(part, buf);
    view().setUint32(used, part.length, true);
  }),
  path_remove_directory: (fd, ptr, len) => attempt(function* () { yield* call({ rmdir: { path: pathAt(fd, ptr, len) } }); forget(); }),
  path_rename: (fd, ptr, len, fd2, ptr2, len2) => attempt(function* () { yield* call({ rename: { from: pathAt(fd, ptr, len), to: pathAt(fd2, ptr2, len2) } }); forget(); }),
  path_symlink: (ptr, len, fd, ptr2, len2) => attempt(function* () { yield* call({ symlink: { target: string(ptr, len), path: pathAt(fd, ptr2, len2) } }); forget(); }),
  path_unlink_file: (fd, ptr, len) => attempt(function* () { yield* call({ unlink: { path: pathAt(fd, ptr, len) } }); forget(); }),
  poll_oneoff: (input, output, count, events) => attempt(function* () {
    if (!count || count > 1024) throw new Errno(EINVAL);
    const v = view(), subscriptions = [];
    for (let i = 0; i < count; i++) {
      const at = input + i * 48, type = v.getUint8(at + 8);
      let until = Infinity;
      if (type === 0) {
        const timeout = Number(v.getBigUint64(at + 24, true)) / 1e6;
        until = v.getUint16(at + 40, true) & 1 ? timeout - (v.getUint32(at + 16, true) === 0 ? performance.timeOrigin : 0) : performance.now() + timeout;
      }
      subscriptions.push({ userdata: v.getBigUint64(at, true), type, fd: v.getUint32(at + 16, true), until });
    }
    flush();
    for (;;) {
      pause(); let ready = 0;
      for (const sub of subscriptions) {
        const found = fds.get(sub.fd); let error = 0, nbytes = 0, hangup = false;
        if (sub.type === 0) { if (performance.now() < sub.until) continue; }
        else if (sub.type !== 1 && sub.type !== 2) error = EINVAL;
        else if (!found) error = EBADF;
        else if (found.kind === 'tty' && ttyControl.hungup) hangup = true;
        else if (found.kind === 'pty') {
          try {
            const result = ptyCall(found, 'poll', { writing: sub.type === 2 });
            if (!result.ready) continue;
            nbytes = result.nbytes; hangup = result.hangup;
          } catch (err) { error = err instanceof Errno ? err.errno : EIO; }
        }
        else if (sub.type === 1 && ['pipe-in', 'tty'].includes(found.kind)) {
          if (found.pipe.empty) continue;
          nbytes = found.pipe.queued; hangup = found.pipe.writerGone;
        } else if (sub.type === 2 && found.kind === 'pipe-out') {
          hangup = found.pipe.readerGone;
          if (!hangup && !found.pipe.room) continue;
          nbytes = found.pipe.room;
        } else if (sub.type === 1 && ['out', 'pipe-out'].includes(found.kind) || sub.type === 2 && ['in', 'pipe-in'].includes(found.kind)) error = EBADF;
        const at = output + ready++ * 32;
        v.setBigUint64(at, sub.userdata, true); v.setUint16(at + 8, error, true); v.setUint8(at + 10, sub.type);
        v.setBigUint64(at + 16, BigInt(nbytes), true); v.setUint16(at + 24, hangup ? 1 : 0, true);
      }
      if (ready) { v.setUint32(events, ready, true); return; }
      const until = Math.min(...subscriptions.map(sub => sub.until));
      sleepUntil(Math.min(until, performance.now() + 10));
    }
  }),
  proc_exit: code => { throw new Exit(code); },
  proc_raise: signal => attempt(function* () {
    // SIGSTOP is already recorded when delivered by the registry. Local raises
    // must take that route too, so a parent's WUNTRACED wait observes the stop.
    if (signal === 19) hostErrno(host('kill', { pid: process.pid, signal }));
    else { const error = signals.queue(signal); if (error) throw new Errno(error); }
    dispatchSignals(); pause();
  }),
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
let exiting = false, signals, inHost = false, identity, delivered = 0, locked = 0, stopCause = 19;
function dispatchSignals(interruptible = false) {
  if (!signals || inHost || locked || exiting || engine?.rewinding) return false;
  let handled = false, interrupted = false, next;
  while ((next = signals.take())) {
    const { n, kind, mask, flags } = next;
    if (kind === 1 || kind === 0 && ignoredByDefault.has(n)) continue;
    if (kind === 0) {
      if (n === 18) continue;
      if (stoppedByDefault.has(n)) { stopCause = n; if (control) Atomics.store(control, 0, 1); continue; }
      flush(); throw killedBy(n);
    }
    const callback = instance?.exports[signals.callback];
    if (typeof callback !== 'function') throw new Errno(EINVAL);
    const savedMask = signals.mask, savedSuspending = suspending;
    if (flags & SA_RESETHAND) signals.action(n, 0, 0, 0);
    signals.mask = savedMask | mask | (flags & SA_NODEFER ? 0 : bit(n));
    suspending = false;
    let pending;
    try { callback(n); pending = engine?.unwound(); }
    finally { suspending = savedSuspending; signals.mask = savedMask; }
    // longjmp from a callback has unwound its own Wasm entry. Discard the
    // interrupted JS/Wasm call chain before rewinding the saved main entry.
    if (pending) {
      if (pending.kind !== 'restore') throw new Errno(ENOSYS);
      throw new SignalJump(pending);
    }
    handled = true; delivered++;
    flush();
    interrupted ||= !(flags & SA_RESTART);
  }
  if (interruptible && interrupted) throw new Errno(ERRNO.EINTR);
  return handled;
}
function pause(interruptible = false) {
  if (!control || exiting) return;
  let word = Atomics.load(control, 0);
  if (word & KILLED) { flush(); throw killedBy(word & 0xff); }
  if (word === 0) { dispatchSignals(interruptible); word = Atomics.load(control, 0); if (word === 0) return; }
  if (word & KILLED) { flush(); throw killedBy(word & 0xff); }
  flush();
  postMessage({ stopped: true, cause: stopCause });
  stopCause = 19;
  while ((word = Atomics.load(control, 0)) !== 0) {
    if (word & KILLED) { postMessage({ continued: true }); throw killedBy(word & 0xff); }
    Atomics.wait(control, 0, word);
  }
  postMessage({ continued: true });
  dispatchSignals(interruptible);
}

// ---- WASIX ----

// The root directory WASI's libc finds its paths under, as long as the program keeps it open.
const preopen = fd => !!fds.get(fd)?.preopen;
// The host's answer to a call that waits on it (wait, execve, getppid, kill): the page
// (web/wasi/exec.mjs) answers in memory both share, as the kernel answers a blocking call.
let channel = null;
function host(type, args) {
  if (!channel) throw new Errno(ENOSYS);
  flush();
  Atomics.store(channel.state, 0, 0);
  postMessage({ host: { type, args } });
  // Do not re-enter this one-response channel from a signal callback. Blocking
  // waitpid polls nonblocking host joins and dispatches between complete requests.
  inHost = true;
  try {
    while (Atomics.load(channel.state, 0) === 0) {
      if (Atomics.wait(channel.state, 0, 0, 200) === 'timed-out') pause();
    }
    return JSON.parse(decoder.decode(channel.data.slice(0, Atomics.load(channel.state, 1))));
  } finally { inHost = false; }
}
const hostErrno = reply => { if (reply?.errno) throw new Errno(ERRNO[reply.errno] ?? EIO); return reply; };
// Lines of a string WASIX passes a list as (arguments, environment).
function waitChild(pid, nohang, options = 0) {
  for (;;) {
    const child = hostErrno(host('join', { pid, nohang: true, options }));
    if (!child.nothing || nohang) return child;
    dispatchSignals(true);
    sleepUntil(performance.now() + 50);
  }
}
const lines = (ptr, len) => string(ptr, len).split(/[\n\r]/).filter(line => line !== '');
// Signals whose default is to end the process, by Linux's numbers.
// setjmp's saved stacks, by the jmp_buf's address: what longjmp goes back to.
let snapshots = new Map(), saved = 0;

// execve(2) of `name` (a path, or a name PATH finds): it does not return, if it goes through;
// the new image starts in this process once this one is unwound (`Replaced`).
function* execve(name, argv, env, search = !name.includes('/')) {
  const PATH = env.find(entry => entry.startsWith('PATH='))?.slice(5) ?? '/usr/bin';
  const candidates = search ? execCandidates(name, PATH) : [name];
  // The working directory goes with the process, which a WASI program learns from PWD.
  const environment = [...env.filter(entry => !entry.startsWith('PWD=')), `PWD=${process.cwd}`];
  let denied;
  for (const candidate of candidates) {
    const path = clean(join(process.cwd, candidate));
    try {
      // Try exec itself: stat cannot decide execute permission or validate an image.
      hostErrno(host('exec', { path, argv, env: environment, cwd: process.cwd }));
      throw new Replaced();
    } catch (err) {
      if (!search || !(err instanceof Errno) || ![ERRNO.ENOENT, ERRNO.ENOTDIR, ERRNO.EACCES].includes(err.errno)) throw err;
      if (err.errno === ERRNO.EACCES) denied = err;
    }
  }
  throw denied ?? new Errno(ENOENT);
}
// Runtime diagnostics use the process's stderr, including dup2/redirection, shared offsets
// and terminal output processing. A failed diagnostic must not replace the original status.
function* diagnostic(text) {
  try {
    const found = descriptor(2), data = encoder.encode(text);
    yield* exclusive(found, function* () {
      const at = found.kind === 'file' ? (found.append ? size(found) : found.pos) : 0;
      const count = yield* writeTo(found, at, data);
      if (found.kind === 'file') found.pos = at + count;
    });
  } catch { /* stderr may be closed or unwritable; the process still exits */ }
}
// The old execve, which cannot fail: what fails ends the process, as a shell would say it.
function* execOrExit(name, argv, env) {
  try { yield* execve(name, argv, env); } catch (err) {
    if (!(err instanceof Errno)) throw err;
    yield* diagnostic(`${name}: ${STRERROR[err.errno] ?? 'cannot execute'}\n`);
    flush();
    throw new Exit(err.errno === ENOENT ? 127 : 126);
  }
}

const wasixCalls = {
  ...wasi,
  proc_exit2: wasi.proc_exit,
  // Legacy WASIX initialization. The platform adapter obtains inherited ignored
  // dispositions through os.sigaction; old libc signal tables are not emulated.
  proc_signals_sizes_get: ptr => { view().setUint32(ptr, 0, true); return 0; },
  proc_signals_get: () => 0,
  path_open2: (fd, dirflags, ptr, len, oflags, base, inheriting, fdflags, extra, out) => {
    if (extra & ~1) return EINVAL;
    const opened = wasi.path_open(fd, dirflags, ptr, len, oflags, base, inheriting, fdflags, out);
    const finish = errno => { if (!errno && (extra & 1)) cloexec.add(view().getUint32(out, true)); return errno; };
    return opened instanceof Promise ? opened.then(finish) : finish(opened);
  },
  fd_fdflags_get: (fd, ptr) => attempt(function* () { descriptor(fd); view().setUint16(ptr, cloexec.has(fd) ? 1 : 0, true); }),
  fd_fdflags_set: (fd, flags) => attempt(function* () {
    descriptor(fd);
    if (flags & ~1) throw new Errno(EINVAL);
    if (flags & 1) cloexec.add(fd); else cloexec.delete(fd);
  }),
  // WASIX 32v1's 24-byte tty record (api_wasix.h). The three descriptor flags
  // describe this process, including redirections; modes belong to its controlling PTY.
  tty_get: ptr => {
    const found = fds.get(0);
    if (found?.kind === 'pty') {
      try {
        const state = TtyState.create(ttyCall(found, IOCTL.TIOCGWINSZ));
        state.configure(ttyCall(found, IOCTL.TCGETS));
        state.wasix(view(), ptr, [0, 1, 2].map(fd => !!fds.get(fd)?.tty));
        return 0;
      } catch (err) { return err instanceof Errno ? err.errno : EIO; }
    }
    if (!ttyState) return ERRNO.ENOTTY;
    ttyState.wasix(view(), ptr, [0, 1, 2].map(fd => !!fds.get(fd)?.tty));
    return 0;
  },
  tty_set: ptr => attempt(function* () {
    if (fds.get(0)?.kind !== 'pty' && !ttyState) throw new Errno(ERRNO.ENOTTY);
    const found = fds.get(0)?.kind === 'pty' ? descriptor(0) : terminalFd(0);
    const v = view();
    ttyAccess(22, found);
    ttyCall(found, 'wasix', { echo: !!v.getUint8(ptr + 19), canonical: !!v.getUint8(ptr + 20), lineFeeds: !!v.getUint8(ptr + 21) });
  }),
  // WASIX's renumber is dup2(2): `from` stays open.
  fd_renumber: (from, to) => attempt(function* () {
    const found = descriptor(from);
    if (to < 0) throw new Errno(EBADF);
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
    // WASIX libc uses this length to allocate on ERANGE, including the trailing NUL.
    view().setUint32(lengthPtr, cwd.length + 1, true);
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
  proc_signal: (pid, signal) => attempt(function* () { hostErrno(host('kill', { pid, signal })); pause(); }),
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
  proc_exec4: (name, nameLen, args, argsLen, envs, envsLen, search, path, pathLen) => attempt(function* () {
    const argv = pointerStrings(args, argsLen), env = pointerStrings(envs, envsLen);
    const PATH = string(path, pathLen), executable = string(name, nameLen);
    yield* execve(executable, argv, search && PATH ? [...env.filter(entry => !entry.startsWith('PATH=')), `PATH=${PATH}`] : env, !!search && !executable.includes('/'));
  }),
  // wait4(2): a child of this process (or the one named) once it ended, reaped; with
  // NON_BLOCKING, none if none ended yet.
  proc_join: (pidPtr, flags, statusPtr) => attempt(function* () {
    const v = view(), tag = v.getUint8(pidPtr);
    if (tag > 1) throw new Errno(EINVAL);
    const reply = waitChild(tag === 1 ? v.getInt32(pidPtr + 4, true) : -1, (flags & 1) !== 0, flags & 2);
    for (let at = 0; at < 6; at++) v.setUint8(statusPtr + at, 0);
    if (reply.nothing) { v.setUint8(pidPtr, 0); v.setUint32(pidPtr + 4, 0, true); return; }
    v.setUint8(pidPtr, 1);
    v.setUint32(pidPtr + 4, reply.pid, true);
    if (reply.stopped) { v.setUint8(statusPtr, 3); v.setUint8(statusPtr + 4, reply.status >> 8); }
    else if (reply.signal != null) { v.setUint8(statusPtr, 2); v.setUint8(statusPtr + 4, reply.signal); }
    else { v.setUint8(statusPtr, 1); v.setUint16(statusPtr + 2, reply.code & 0xffff, true); }
  }),
  // The callback is paired with the platform's sigaction/mask imports.
  callback_signal: (ptr, len) => { signals.callback = string(ptr, len); },
  thread_id: ptr => { view().setUint32(ptr, 1, true); return 0; },
  // raise(3), abort(3): a signal to itself, whose default ends it.
  thread_signal: (tid, signal) => {
    if (tid !== 1) return ERRNO.ESRCH;
    const error = signals.queue(signal); dispatchSignals(); pause(); return error;
  },
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
function forkState({ exec = false, stdin = 'inherit', tty = null, dup2 = [] } = {}) {
  if (!shares) throw new Errno(ENOSYS);
  const ids = new Map(), descriptions = [], table = [];
  // Apply dup2 against a child-only table before CLOEXEC filtering. Parent fds never
  // change, and each source must be an actual descriptor held by this process.
  const inherited = new Map(fds), closes = new Set(cloexec);
  const inputAction = dup2.some(([, to]) => to === 0);
  for (const [from, to] of dup2) {
    if (!inherited.has(from)) throw new Errno(EBADF);
    inherited.set(to, inherited.get(from)); closes.delete(to);
  }
  for (const [fd, found] of inherited) {
    if (exec && closes.has(fd) || fd === 0 && stdin !== 'inherit' && !inputAction) continue;
    if (!ids.has(found)) {
      ids.set(found, descriptions.length);
      descriptions.push({ ...describe(found), refs: 0 });
    }
    descriptions[ids.get(found)].refs++;
    table.push([fd, ids.get(found), closes.has(fd)]);
  }
  if (stdin !== 'inherit' && !inputAction) {
    if (stdin === 'tty' && !tty && !controllingTerminal()) throw new Errno(ERRNO.ENXIO);
    table.push([0, descriptions.length, false]);
    descriptions.push(stdin === 'tty' ? { ...describe(tty ?? terminalFd(1)), refs: 1 }
      : { kind: 'in', tty: false, data: new Uint8Array(0), refs: 1 });
  }
  return { signals: signals.snapshot(), fds: table, descriptions };
}
function describe(found) {
  switch (found.kind) {
    case 'pty': return { kind: 'pty', tty: true, handle: found.handle, master: found.master, number: found.number, readable: found.readable, writable: found.writable, refs: found.refs };
    case 'in':
      if (shares && found.share == null) share(found);
      if (shares && found.share == null) throw new Errno(ERRNO.EMFILE);
      return { kind: 'in', tty: found.tty, flags: found.flags, data: found.share == null ? found.data.slice(found.pos) : found.data, share: found.share, refs: found.refs };
    case 'out': return { kind: 'out', fd: found.fd, tty: found.tty, flags: found.flags, closed: found.closed?.buffer ?? null };
    case 'tty': case 'pipe-in': case 'pipe-out': return { fd: found.fd, kind: found.kind, tty: !!found.tty, flags: found.flags, readable: found.readable, writable: found.writable, buffer: found.pipe.buffer, refs: found.refs };
    case 'dir': return { kind: 'dir', path: found.path, preopen: !!found.preopen };
    default: {
      if (found.share == null) share(found);
      if (found.share == null) throw new Errno(ERRNO.EMFILE);
      const { kind, local, path, kfd, token, device, writable, read, size: length, stat: stated, writer, rewrite, append, chunk, share: slot, refs } = found;
      return { kind, local, path, kfd, token, device, writable, read, size: length, stat: stated, writer, rewrite, append, chunk, share: slot, refs, bytes: found.bytes?.transferable };
    }
  }
}
// The child's descriptors, as its parent had them (its host holds its pipes' ends for it).
function adopt(state) {
  const made = state.descriptions.map(description => {
    switch (description.kind) {
      case 'pty': { const { refs, ...found } = description; return found; }
      case 'in': {
        const found = { kind: 'in', tty: description.tty, flags: description.flags, data: description.data, pos: 0 };
        if (description.share != null) shares.attach(found, description.share);
        return found;
      }
      case 'out': return { kind: 'out', fd: description.fd, tty: description.tty, flags: description.flags, closed: description.closed ? new Int32Array(description.closed) : null };
      case 'tty': case 'pipe-in': case 'pipe-out': return { fd: description.fd, kind: description.kind, tty: description.tty, flags: description.flags, readable: description.readable, writable: description.writable, pipe: new Pipe(description.buffer, process.pid) };
      case 'dir': return { kind: 'dir', path: description.path, preopen: !!description.preopen };
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
  postMessage({ fork: { ...state, snapshot, snapshots, shares: shares.buffer, argv: process.argv, env: environ, cwd: process.cwd, umask: process.umask, wasix: process.wasix } }, [snapshot.memory]);
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
let linearBytes = 0, growReserved = 0;
function checkTermination() {
  const word = control ? Atomics.load(control, 0) : 0;
  if (word & KILLED) throw killedBy(word & 0xff);
}
function reserveMemory(bytes) {
  // A fork inherits handlers that cannot run until its instance is restored.
  // Unconditional termination is safe to honor even before that restoration.
  checkTermination();
  try {
    const answer = sendSync({ method: 'POST', url: '/api/sys',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pid: process.pid, proc: process.proc, calls: [{ resource: { memory: bytes } }] }) });
    if (answer.status !== 200) throw new Errno(EIO);
    ok(JSON.parse(answer.text).results[0]); linearBytes = bytes;
  } catch (error) {
    // SIGKILL revokes the credential before its event reaches this host. Resolve
    // that event before treating a denied reservation as an executable failure.
    if (error.errno === ERRNO.EPERM && channel) host('reconcile', {});
    checkTermination();
    throw error;
  }
  checkTermination();
}
const resourceImports = {
  memory_grow_pre: (_, delta) => {
    growReserved = 0;
    const bytes = (delta >>> 0) * 65536;
    if (!bytes) return delta;
    try { reserveMemory(linearBytes + bytes); growReserved = bytes; return delta; }
    catch (error) { if (error.errno === ERRNO.EAGAIN || error.errno === EINVAL) return -1; throw error; }
  },
  memory_grow_post: (_, result) => {
    if (result === -1 && growReserved) reserveMemory(linearBytes - growReserved);
    growReserved = 0; return result;
  },
};
async function instantiate(module, type, snapshot, startSection = false, memoryBytes) {
  if (memoryBytes !== undefined) {
    const cloned = snapshot ? snapshot.memory.byteLength + Object.values(snapshot.memories ?? {}).reduce((n, bytes) => n + bytes.byteLength, 0) : 0;
    reserveMemory(Math.max(memoryBytes, cloned));
  }
  // Exec preserves user fds. Recreate a closed/replaced root preopen at a free
  // number; libc must discover preopens without assuming fd 3 is available.
  // A fork keeps its copied libc table and must retain the same descriptor numbers.
  if (!snapshot && ![...fds.keys()].some(preopen)) {
    const fd = lowest(3);
    if (fd >= 1024) throw new Errno(ERRNO.EMFILE);
    install(fd, { kind: 'dir', path: '/', preopen: true });
  }
  const required = WebAssembly.Module.imports(module);
  if (required.some(entry => entry.module === 'os' && ['getuid', 'getgid', 'getgroups'].includes(entry.name))) {
    identity = await drive(call('getcreds'));
  }
  // A synchronous signal callback re-enters Wasm from an active host import.
  // JSPI cannot suspend across that JS frame, even for a handler's write(2).
  // Use the existing synchronous transport for images using this signal ABI.
  // Other images retain JSPI; this choice follows imports, never program names.
  suspending = capable && !startSection && !required.some(entry => entry.module === 'os' && entry.name === 'sigaction');
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
    ? { wasi_snapshot_preview1: suspendable(preview1), os: suspendable(osApi), terminal: suspendable(osApi), wasix_32v1: suspendable(wasix), env }
    : { wasi_snapshot_preview1: preview1, os: osApi, terminal: osApi, wasix_32v1: wasix, env };
  imports.os_runtime = resourceImports;
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
  'proc_exit2', 'proc_signals_get', 'proc_signals_sizes_get', 'fd_fdflags_get', 'fd_fdflags_set',
  'sigpoll', 'getuid', 'getgid', 'getgroups', 'getpgid', 'getsid', 'setpgid', 'setsid', 'tcgetpgrp', 'tcsetpgrp', 'waitpid2', 'sigaction', 'sigmask', 'sigpending', 'sigsuspend',
  'futex_wake_all', 'reply', 'umask', 'tty_get', 'tty_set', 'posix_spawn', 'waitpid',
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
    let pending;
    try {
      const entry = initializing ? instance.exports.__tw_initialize : instance.exports._start;
      const start = suspending ? WebAssembly.promising(entry) : entry;
      await start();
    } catch (err) {
      if (err instanceof Replaced) { await replace(); continue; }
      if (!(err instanceof SignalJump)) throw err;
      pending = err.pending;
    }
    pending ??= engine.unwound();
    if (!pending) {
      if (!initializing) return 0;
      initializing = false;
      engine.top = engine.stackPointer();
      continue;
    }
    if (pending.kind === 'fork') engine.rewind(await fork());
    else if (pending.kind === 'checkpoint') {
      // Restore control flow and the stack pointer, not guest memory: volatile
      // locals changed since setjmp must retain their current values.
      const sp = pending.sp;
      const id = BigInt(++saved);
      snapshots.set(pending.snapshot, { id, stack: engine.saved(), sp });
      view().setBigUint64(pending.snapshot, id, true);
      bytes().fill(0, pending.snapshot + 8, pending.snapshot + 24);
      engine.rewind({ value: 0n });
    } else if (pending.kind === 'restore') {
      const { found, value } = pending;
      if (found.sp != null) engine.setStackPointer(found.sp);
      engine.rewind({ value }, found.stack);
    }
  }
}
// execve(2) went through: the image the host loaded starts in this process, its descriptors
// open but those marked close-on-exec.
async function replace() {
  const { image } = await next('image');
  // reexec revoked the old credential; flushing close-on-exec writers uses the new image's
  // token and the unchanged descriptor lineage.
  process.proc = image.token;
  for (const fd of [...cloexec]) { try { await drive(uninstall(fd)); } catch { /* closed already */ } }
  flush();
  forget();
  snapshots = new Map();
  Object.assign(process, { argv: image.argv, proc: image.token });
  environ = image.env;
  if (image.error) {
    await drive(diagnostic(`${image.error}\n`));
    throw new Exit(126);
  }
  signals.exec();
  await instantiate(image.module, image.memory, undefined, image.startSection, image.memoryBytes);
}


// utimensat(2), as WASI asks it: each time given, now, or left.
function* times(path, atim, mtim, flags, follow = true) {
  const time = (value, set, now) => flags & now ? 'now' : flags & set ? { sec: Number(value / 1000000000n), nsec: Number(value % 1000000000n) } : 'omit';
  yield* call({ utimens: { path, atime: time(atim, 1, 2), mtime: time(mtim, 4, 8), nofollow: !follow } });
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
      pause(true);
      Atomics.wait(control, 0, 0, Math.min(left, 200));
    }
    return;
  }
  if (typeof SharedArrayBuffer === 'function') { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, until - performance.now()); return; }
  while (performance.now() < until) { /* the clock is the only thing to wait on */ }
}

// Terminal ioctls use the process's local descriptor table. They cannot address another
// run's PTY or turn a server descriptor into a device. Other calls retain their batch path.
const ttyRequests = new Set(Object.values(IOCTL));
// Raw ABI descriptors occupy a disjoint, private part of the process's descriptor table.
// They consequently inherit and close with the same reference accounting as WASI files,
// including a killed child whose parent shell keeps the credential lineage alive.
const rawNumber = fd => -fd - 1;
function forgetRaw(fd) {
  const number = rawNumber(fd), found = fds.get(number);
  if (!found) return 0;
  fds.delete(number);
  if (found.share == null) return 0;
  const gen = shares.gen(found.share), left = shares.drop(found.share, process.pid);
  if (!left) postMessage({ closed: { slot: found.share, gen } });
  return left;
}
function trackRaw(calls, results, reserved = null) {
  for (let i = 0; i < calls.length; i++) {
    const one = calls[i], result = results[i];
    if (one.open && Number.isInteger(result?.ok?.fd)) {
      const fd = result.ok.fd;
      const found = { kind: 'file', kfd: fd, path: one.open.path, pos: 0, read: false, writer: false };
      if (reserved != null) shares.attach(found, reserved);
      install(rawNumber(fd), found, reserved != null);
      if (reserved != null) postMessage({ described: { slot: reserved, gen: shares.gen(reserved), description: describe(found) } });
    } else if (one.open && reserved != null) {
      shares.drop(reserved, process.pid);
    }
    if (one.close || one.discard) {
      const arg = one.close ?? one.discard;
      const fd = arg.fd?.ref != null ? results[arg.fd.ref]?.ok?.fd : arg.fd;
      if (Number.isInteger(fd)) forgetRaw(fd);
    }
  }
  return results;
}
const localMetadata = call => ['stat', 'lstat', 'access'].some(op => call[op] && (allocatedPath(call[op].path) || call[op].path === '/dev/pts')) || call.getdents?.path === '/dev/pts';
// Known tty requests use runtime fds. Other ioctls keep a tracked raw file's
// namespace even when its server number matches a local PTY descriptor.
const processCalls = call => call === 'setsid' || !!(call.getpgid || call.getsid || call.setpgid || call.waitpid || call.proc_stopped || call.prctl);
function* osBatch(calls) {
  if (calls.some(call => call && typeof call === "object" && "resource" in call)) return calls.map(() => ({ err: { errno: "EPERM" } }));
  const split = calls.some(call => localMetadata(call) || call.readlink && localLink(call.readlink.path) || processCalls(call) || call.open || ttyRequests.has(call.ioctl?.request) || call.ioctl && fds.get(call.ioctl.fd)?.kind === 'pty' && !fds.has(rawNumber(call.ioctl.fd))
    || Number.isInteger(call.close?.fd) && fds.has(rawNumber(call.close.fd)));
  if (!split) return trackRaw(calls, yield* batch(calls));
  const results = [];
  for (const original of calls) {
    const call = structuredClone(original);
    const args = Object.values(call)[0];
    for (const key of ['fd', ...(call.ioctl?.request === 0x40049409 ? ['arg'] : [])]) {
      if (args?.[key]?.ref == null) continue;
      // Preserve the server batch contract when terminal calls split the batch:
      // forward references fail, and a failed open carries its original errno.
      const prior = results[args[key].ref];
      const fd = prior?.ok?.fd;
      const err = !prior ? { errno: 'EINVAL' } : prior.err ??
        (!Number.isInteger(fd) || fd < 0 || fd > 0xffffffff ? { errno: 'EBADF' } : null);
      if (err) { args.invalidReference = err; break; }
      args[key] = fd;
    }
    if (args?.invalidReference) { results.push({ err: args.invalidReference }); continue; }
    if (localMetadata(call)) {
      const op = Object.keys(call)[0], args = call[op];
      if (op === 'getdents') {
        const { cookie = 0, count } = args;
        if (!Number.isSafeInteger(cookie) || cookie < 0 || count != null && (!Number.isSafeInteger(count) || count < 0)) {
          results.push({ err: { errno: 'EINVAL' } }); continue;
        }
        const reply = host('pty', { op: 'list' });
        results.push(reply.errno ? { err: { errno: reply.errno } } : { ok: reply.entries.slice(cookie, count == null ? undefined : cookie + count) });
      } else {
        const reply = host('pty', { op: op === 'access' ? 'access' : 'stat', path: args.path, mode: args.mode });
        results.push(reply.errno ? { err: { errno: reply.errno } } : { ok: op === 'access' ? null : reply });
      }
    } else if (call.readlink && localLink(call.readlink.path)) {
      results.push({ ok: localLink(call.readlink.path) });
    } else if (processCalls(call)) {
      const result = host('process_call', call);
      results.push(result?.errno ? { err: { errno: result.errno } } : { ok: result });
    } else if (call.close && fds.has(rawNumber(call.close.fd))) {
      const remaining = forgetRaw(call.close.fd);
      results.push(remaining ? { ok: null } : (yield* batch([call]))[0]);
    } else if (ttyRequests.has(call.ioctl?.request) || call.ioctl && fds.get(call.ioctl.fd)?.kind === 'pty' && !fds.has(rawNumber(call.ioctl.fd))) {
      try {
        const { fd, request, arg } = call.ioctl;
        const found = descriptor(fd);
        if (!found.tty || found.kind !== 'pty' && !ttyState) throw new Errno(ERRNO.ENOTTY);
        if ([IOCTL.TIOCSPGRP, IOCTL.TCSETS, IOCTL.TCSETSW, IOCTL.TCSETSF].includes(request)) ttyAccess(22, found);
        flush();
        results.push({ ok: ttyCall(found, request, arg) });
      } catch (err) {
        const errno = err instanceof Errno ? Object.keys(ERRNO).find(key => ERRNO[key] === err.errno) ?? 'EIO' : 'EIO';
        results.push({ err: { errno } });
      }
    } else {
      const reserved = call.open && shares ? shares.claim(process.pid, 1, 0) : null;
      if (reserved != null && reserved < 0) { results.push({ err: { errno: 'EMFILE' } }); continue; }
      try { results.push(...trackRaw([call], yield* batch([call]), reserved)); }
      catch (error) { if (reserved != null) shares.drop(reserved, process.pid); throw error; }
    }
  }
  return results;
}

// os.sys: a batch of the kernel's calls (abi::Batch's `calls`, as JSON), sent as it is.
// `sys` sends it and gives the reply's length; `reply` copies the reply where the program says.
let reply = new Uint8Array(0);
function processCall(call) { return hostErrno(host('process_call', call)); }
function posixCall(call) {
  pause();
  try { return call(); } catch (err) { if (!(err instanceof Errno)) throw err; return -err.errno; }
}
function ttyAccess(signal, found = null) {
  if (found?.kind === 'pty') {
    for (;;) {
      const suppressed = signals.actions[signal].kind === 1 || signals.mask & (1 << (signal - 1));
      const result = ttyCall(found, 'access', { signal, suppressed });
      if (!result.signalled) return;
      if (dispatchSignals(true)) throw new Errno(ERRNO.EINTR);
      pause(true);
    }
  }
  if (!ttyState) return;
  while (controllingTerminal() && Atomics.load(membership, 0) !== ttyControl.pgrp) {
    const suppressed = signals.actions[signal].kind === 1 || signals.mask & (1 << (signal - 1));
    if (suppressed) { if (signal === 21) throw new Errno(EIO); return; }
    hostErrno(host('tty', { request: 'access', arg: signal }));
    if (dispatchSignals(true)) throw new Errno(ERRNO.EINTR);
    pause(true);
  }
}
const osApi = {
  // POSIX flag adapter over the same descriptor/open driver as WASI. Linux flag
  // values include O_NOCTTY, which preview 1 cannot express.
  open: (ptr, len, flags, mode) => drive((function* () {
    try {
      pause();
      if (flags & ~(3 | 0o100 | 0o200 | 0o400 | 0o1000 | 0o2000 | 0o4000 | 0o200000 | 0o400000 | 0o2000000) || (flags & 3) === 3) throw new Errno(EINVAL);
      const path = clean(join(process.cwd, string(ptr, len)));
      if (flags & 0o400000 && kindOf((yield* stat(path, false)).mode) === SYMBOLIC_LINK) throw new Errno(ERRNO.ELOOP);
      const oflags = (flags & O_CREAT ? OFLAG_CREAT : 0) | (flags & O_EXCL ? OFLAG_EXCL : 0) | (flags & O_TRUNC ? OFLAG_TRUNC : 0) | (flags & 0o200000 ? OFLAG_DIRECTORY : 0);
      const rights = (flags & 3) === O_RDONLY ? RIGHT_READ : (flags & 3) === O_WRONLY ? RIGHT_WRITE : RIGHT_READ | RIGHT_WRITE;
      const fdflags = (flags & 0o2000 ? FDFLAG_APPEND : 0) | (flags & 0o4000 ? FDFLAG_NONBLOCK : 0);
      const fd = yield* openPath(path, FOLLOW, oflags, rights, fdflags, !!(flags & 0o400), mode);
      if (flags & 0o2000000) cloexec.add(fd);
      return fd;
    } catch (err) { if (err instanceof Errno) return -err.errno; throw err; }
  })()),
  getpgid: pid => posixCall(() => processCall({ getpgid: { pid } }).pgid),
  getsid: pid => posixCall(() => processCall({ getsid: { pid } }).sid),
  setpgid: (pid, pgid) => posixCall(() => { processCall({ setpgid: { pid, pgid } }); return 0; }),
  setsid: () => posixCall(() => processCall('setsid').sid),
  tcgetpgrp: fd => posixCall(() => {
    return ttyCall(descriptor(fd), IOCTL.TIOCGPGRP).pgrp;
  }),
  tcsetpgrp: (fd, pgid) => posixCall(() => {
    const found = descriptor(fd); ttyAccess(22, found); ttyCall(found, IOCTL.TIOCSPGRP, pgid); return 0;
  }),
  waitpid2: (pid, ptr, options) => posixCall(() => {
    if (options & ~11) throw new Errno(EINVAL);
    const child = waitChild(pid, !!(options & 1), options);
    if (child.nothing) return 0;
    if (ptr) view().setInt32(ptr, child.status, true);
    return child.pid;
  }),
  getuid: () => identity.uid,
  getgid: () => identity.gid,
  getgroups: (count, ptr) => {
    if (count < 0 || count && count < identity.groups.length) return -EINVAL;
    if (count) for (let i = 0; i < identity.groups.length; i++) view().setUint32(ptr + 4 * i, identity.groups[i], true);
    return identity.groups.length;
  },
  sigaction: (n, kind, mask, flags) => signals.action(n, kind, mask, flags),
  sigmask: (how, mask) => {
    const previous = signals.mask;
    if (how === 0) signals.mask = previous | mask;
    else if (how === 1) signals.mask = previous & ~mask;
    else if (how === 2) signals.mask = mask;
    return previous;
  },
  sigpoll: () => { dispatchSignals(); },
  sigpending: () => signals.pending,
  sigsuspend: mask => {
    const previous = signals.mask;
    signals.mask = mask;
    try {
      for (;;) {
        if (dispatchSignals()) return ERRNO.EINTR;
        const before = delivered;
        pause();
        if (delivered !== before) return ERRNO.EINTR;
        if (!control) return ENOSYS;
        Atomics.wait(control, 0, 0, 100);
      }
    } finally { signals.mask = previous; }
  },
  posix_spawn: (ptr, len, result) => {
    pause();
    let tty;
    try {
      if (len > 1 << 20) throw new Errno(ERRNO.E2BIG);
      const request = JSON.parse(string(ptr, len));
      const vector = value => Array.isArray(value) && value.every(item => typeof item === 'string' && !item.includes('\0'));
      if (!vector(request.argv) || !request.argv[0] || !vector(request.env) || typeof request.cwd !== 'string'
        || request.cwd.includes('\0') || !['inherit', 'null', 'tty'].includes(request.stdin)) throw new Errno(EINVAL);
      if (request.pgroup != null && (!Number.isInteger(request.pgroup) || request.pgroup < 0 || request.pgroup > 0x7fffffff)) throw new Errno(EINVAL);
      if (request.cgroup != null && (typeof request.cgroup !== 'string' || !request.cgroup.startsWith('/') || request.cgroup.length > 4096 || request.cgroup.includes('\0'))) throw new Errno(EINVAL);
      const dup2 = request.dup2 ?? [];
      if (!Array.isArray(dup2) || dup2.length > 64 || !dup2.every(pair => Array.isArray(pair) && pair.length === 2 && pair.every(fd => Number.isInteger(fd) && fd >= 0 && fd <= 65535))) throw new Errno(EINVAL);
      const size = values => values.reduce((sum, value) => sum + encoder.encode(value).length + 1, 0);
      if (size(request.argv) > 128 * 1024 || size(request.env) > 128 * 1024) throw new Errno(ERRNO.E2BIG);
      if (request.stdin === 'tty' && Atomics.load(membership, 2) >= 0x40000000)
        tty = { kind: 'pty', tty: true, ...hostErrno(host('pty', { op: 'open', path: '/dev/tty', readable: true, writable: false, noctty: true })) };
      const state = { argv: request.argv, env: request.env, cwd: request.cwd, pgroup: request.pgroup, cgroup: request.cgroup, ...forkState({ exec: true, stdin: request.stdin, tty, dup2 }), shares: shares.buffer, umask: process.umask };
      const child = hostErrno(host('spawn', state));
      view().setUint32(result, child.pid, true);
      return 0;
    } catch (err) { if (err instanceof Exit) throw err; return err instanceof Errno ? err.errno : EINVAL; }
    finally { if (tty) { try { ptyCall(tty, 'close'); } catch { /* host cleanup handles a concurrent exit */ } } }
  },
  waitpid: (pid, result) => {
    pause();
    try {
      const child = waitChild(pid, false);
      view().setUint32(result, child.status, true);
      return 0;
    } catch (err) { if (err instanceof Exit) throw err; return err instanceof Errno ? err.errno : EIO; }
  },
  umask: mask => { const previous = process.umask ?? 0o022; process.umask = mask & 0o777; return previous; },
  sys: (ptr, len) => {
    pause();
    const calls = JSON.parse(string(ptr, len));
    forget();
    return drive((function* () {
      reply = encoder.encode(JSON.stringify({ results: yield* osBatch(calls) }));
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
  ttyState = data.pty ? new TtyState(data.pty.state) : null;
  ttyControl = data.pty ? new TtyControl(data.pty.control) : null;
  membership = data.membership ? new Int32Array(data.membership) : new Int32Array([1, 1, 0]);
  outputCredit = data.outputCredit ? new Int32Array(data.outputCredit) : null;
  control = data.control ? new Int32Array(data.control) : null;
  channel = data.channel ? { state: new Int32Array(data.channel, 0, 2), data: new Uint8Array(data.channel, 8) } : null;
  const { stdin = {}, stdout = {}, stderr = {} } = data;
  const parent = data.fork ?? data.inherit;
  signals = new Signals(control, parent?.signals);
  if (data.inherit) signals.exec();
  let code = 0, signal;
  try {
    if (parent) {
      // A fork's child: its parent's argument vector, environment, directory and descriptors.
      environ = parent.env;
      shares = new Shares(parent.shares);
      if (data.fork) snapshots = parent.snapshots;
      Object.assign(process, { argv: parent.argv, cwd: parent.cwd, umask: parent.umask ?? process.umask });
      adopt(parent);
    } else {
      environ = Array.isArray(data.env) ? data.env : Object.entries(data.env ?? {}).map(([name, value]) => `${name}=${value}`);
      process.cwd ??= environ.find(entry => entry.startsWith('PWD='))?.slice(4) || '/';
      shares = data.shares ? new Shares(data.shares) : null;
      // The page holds the pipes' ends it gives a process, for it, before it starts.
      install(0, stdin.tty && ttyState ? terminalFd(1) : stdin.pipe ? { kind: 'pipe-in', pipe: new Pipe(stdin.pipe, process.pid), tty: !!stdin.tty } : { kind: 'in', tty: !!stdin.tty, data: stdin.data ?? new Uint8Array(0), pos: 0 }, true);
      install(1, stdout.tty && ttyState ? terminalFd(1) : stdout.pipe ? { kind: 'pipe-out', pipe: new Pipe(stdout.pipe, process.pid) } : { kind: 'out', fd: 1, tty: !!stdout.tty, closed: stdout.closed ? new Int32Array(stdout.closed) : null }, !(stdout.tty && ttyState));
      install(2, stderr.tty && ttyState ? terminalFd(2) : { kind: 'out', fd: 2, tty: !!stderr.tty }, !(stderr.tty && ttyState));
      install(3, { kind: 'dir', path: '/', preopen: true });
    }
    // Fresh/exec images have no inherited caught handlers to instantiate first.
    // Deliver pending stop/termination before their start section can do I/O.
    if (!data.fork) pause();
    await instantiate(data.module, data.memory, parent?.snapshot, data.startSection, data.memoryBytes);
    // The child returns from fork with 0.
    if (data.fork) engine.rewind({ pid: 0 });
    code = await run();
  } catch (err) {
    if (err instanceof Exit) ({ code, signal } = err);
    else {
      // A trap, or the engine's own failure: it ends as abort(3) ends a process.
      await drive(diagnostic(`${process.argv?.[0] ?? 'process'}: ${err?.message ?? err}\n`));
      ({ code, signal } = killedBy(SIGABRT));
    }
  }
  // What it left open closes as it exits, as a process's descriptors do: its pipes too, so that
  // the next reads to their end, and the one before hears SIGPIPE.
  exiting = true;
  // A registry signal may already have revoked this image. The trusted host selects
  // a surviving credential of this same open-file lineage for descriptor cleanup.
  if (signal != null && channel) process.proc = host('cleanup', {}).token ?? process.proc;
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

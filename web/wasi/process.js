import { PixelSurface } from '../gui/pixel-surface.js';
import { releaseId } from '../release.js';
// A process: a program built for wasm32-wasip1, or for WASIX, run in a Worker of its own.
// All filesystem resolution, mount namespaces, `chroot`, handle-backed `cwd`, and open file
// descriptions are owned by `os_vfs::Vfs` inside `crates/client-kernel`, reached over the
// shared-memory host channel (`vfsCall`).
import { Signals, bit, valid, ignoredByDefault, stoppedByDefault, SA_RESTART, SA_NODEFER, SA_RESETHAND } from './signals.mjs';
import { Pipe, ArenaPipe, pipeBuffer, PIPE_ATOMIC } from './pipe.js';
import { ArenaRing, HDR_CHANGES, RING_CAPACITY } from './sock-arena.js';
import { Engine } from './fork.js';
import { Shares } from './shared.js';
import { TtyState, TtyControl, IOCTL, CC, LF } from '../kernel/pty.js';
import { isByteDevice, readDevice } from './devices.mjs';

// WASI's errno numbers, by Linux's names, as the kernel answers.
const ERRNO = {
  E2BIG: 1, EACCES: 2, EADDRINUSE: 3, EADDRNOTAVAIL: 4, EAFNOSUPPORT: 5, EAGAIN: 6, EBADF: 8, EBUSY: 10, ECANCELED: 11, ECHILD: 12,
  ECONNABORTED: 13, ECONNREFUSED: 14, ECONNRESET: 15, EDEADLK: 16, EDQUOT: 19, EEXIST: 20, EFAULT: 21, EFBIG: 22, EINTR: 27,
  EINVAL: 28, EIO: 29, EISCONN: 30, EISDIR: 31, ELOOP: 32, EMFILE: 33, EMLINK: 34, EMSGSIZE: 35, ENAMETOOLONG: 37, ENOBUFS: 42,
  ENODEV: 43, ENOENT: 44, ENOEXEC: 45, ENOLCK: 46, ENOMEM: 48, ENOSPC: 51, ENOSYS: 52, ENOTCONN: 53, ENOTDIR: 54, ENOTEMPTY: 55,
  ENOTSOCK: 57, ENOTSUP: 58, EOPNOTSUPP: 58, ENOTTY: 59, ENXIO: 60, EPERM: 63, EPIPE: 64, EPROTONOSUPPORT: 66, EPROTOTYPE: 67,
  ERANGE: 68, EROFS: 69, ESPIPE: 70, ESRCH: 71, ESTALE: 72, ETIMEDOUT: 73, ETXTBSY: 74, EXDEV: 75, ENODATA: 44, ETOOMANYREFS: 109,
  ENOTBLK: 218,
};
const { EBADF, EINVAL, EIO, EISDIR, ENOENT, ENOSYS, ENOTDIR, ESPIPE } = ERRNO;
const STRERROR = { 2: 'Permission denied', 44: 'No such file or directory', 45: 'Exec format error', 54: 'Not a directory', 31: 'Is a directory' };
const STDIO = new Set(['in', 'out', 'pipe-in', 'pipe-out', 'arena-pipe-in', 'arena-pipe-out', 'tty', 'pty']);
const CHARACTER_DEVICE = 2, DIRECTORY = 3, REGULAR_FILE = 4, SOCKET_DGRAM = 5, SOCKET_STREAM = 6, SYMBOLIC_LINK = 7, UNKNOWN = 0;

// AF_UNIX / SCM_RIGHTS / SO_PEERCRED ABI constants (`crates/abi/src/socket.rs`).
const AF_UNIX = 1;
const SOCK_STREAM = 1, SOCK_DGRAM = 2, SOCK_SEQPACKET = 5;
const SOCK_TYPE_MASK = 0xf, SOCK_NONBLOCK = 0x800, SOCK_CLOEXEC = 0x80000;
const MSG_PEEK = 0x2, MSG_CTRUNC = 0x8, MSG_TRUNC = 0x20, MSG_DONTWAIT = 0x40, MSG_NOSIGNAL = 0x4000, MSG_CMSG_CLOEXEC = 0x40000000;
const SCM_MAX_FD = 64, FD_MAX = 1024;

// Sentinel anchor descriptors (`abi::OS_FD_ROOT` and `abi::OS_FD_CWD`).
const OS_FD_ROOT = 0x7ffffffd;
const OS_FD_CWD = 0x7ffffffe;

// Linux open(2) flags.
const O_RDONLY = 0, O_WRONLY = 1, O_RDWR = 2, O_CREAT = 0o100, O_EXCL = 0o200, O_NOCTTY = 0o400;
const O_TRUNC = 0o1000, O_APPEND = 0o2000, O_NONBLOCK = 0o4000, O_DIRECTORY = 0o200000;
const O_NOFOLLOW = 0o400000, O_CLOEXEC = 0o2000000, O_PATH = 0o10000000;

// WASI path_open flags & rights.
const OFLAG_CREAT = 1, OFLAG_DIRECTORY = 2, OFLAG_EXCL = 4, OFLAG_TRUNC = 8, FDFLAG_APPEND = 1, FDFLAG_NONBLOCK = 4, FOLLOW = 1;
const RIGHT_READ = 1n << 1n, RIGHT_SEEK = 1n << 2n, RIGHT_TELL = 1n << 5n, RIGHT_WRITE = 1n << 6n;
const ALL_RIGHTS = (1n << 30n) - 1n;
const INLINE = 256 * 1024, VFS_CHUNK = 512 * 1024;
const EXPORT_DIR_IOCTL = 0x45580001;
const FICLONE = 0x40049409, FICLONERANGE = 0x4020940d, ACCEL_SUBMIT = 0x54570101;
const COWFS_IOC_SEND = 0x54570209, COWFS_IOC_RECEIVE = 0x5457020a, LOOP_SET_FD = 0x4c00;
const COWFS_IOC_OCI_IMPORT = 0x54570222, COWFS_IOC_OCI_EXPORT = 0x54570223;

class Exit { constructor(code, signal) { this.code = code; this.signal = signal; } }
const killedBy = signal => new Exit(128 + signal, signal);
const SIGABRT = 6, SIGPIPE = 13;
class Replaced {}
class GuiDispatch {}
const pixelSurfaces = new PixelSurface(event => postMessage({ guiDisplayEvent: event }));
const GUI_IOC_NEXT_EVENT = 0x47550002, GUI_IOC_BIND_SURFACE = 0x47550004, GUI_IOC_CHECK_BUNDLE = 0x47550007, GUI_IOC_PEER_ROLES = 0x4755000c;
class SignalJump { constructor(pending) { this.pending = pending; } }
class Errno extends Error { constructor(errno) { super(String(errno)); this.errno = errno; } }
const errnoOf = err => ERRNO[err?.errno] ?? EIO;

let memory, instance, engine, process = {};
const view = () => new DataView(memory.buffer);
const bytes = () => new Uint8Array(memory.buffer);
const encoder = new TextEncoder(), decoder = new TextDecoder();
const string = (ptr, len) => decoder.decode(bytes().slice(ptr, ptr + len));
const base64 = data => { let text = ''; for (let i = 0; i < data.length; i += 0x8000) text += String.fromCharCode(...data.subarray(i, i + 0x8000)); return btoa(text); };
const unbase64 = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));

// ---- Kernel & Host Transport ----

let closing = [];
const forget = () => {};

function* request(method, url, body, headers = {}, binary = false) {
  return yield { method, url: new URL(url, self.location.origin).href, body, headers, binary };
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
async function send({ method, url, body, headers, binary }) {
  try {
    const response = await fetch(url, { method, body: body ?? undefined, headers });
    return { status: response.status, text: binary ? '' : await response.text(), bytes: binary ? new Uint8Array(await response.arrayBuffer()) : null };
  } catch { throw new Errno(EIO); }
}

const capable = typeof WebAssembly.Suspending === 'function' && typeof WebAssembly.promising === 'function';
let suspending = false;

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

// Process batch helper: routes through the client kernel (`proc_sys`) when isolated so
// local calls (`getcreds`, cgroups, signals) execute with ZERO network RPCs and remote calls
// carry verified `ServiceAuth v2` credentials + `X-OS-Instance`.
function* serverBatch(calls) {
  const sent = [...calls, ...closing.map(fd => ({ close: { fd } }))];
  closing = [];
  if (!sent.length) return [];
  const body = { calls: sent, umask: process.umask, sudo: process.sudo };
  if (process.pid) body.pid = process.pid;
  if (process.proc) body.proc = process.proc;
  if (channel) {
    const res = host('vfs', { op: 'sys', batch: JSON.stringify(body) });
    if (res?.errno) return calls.map(() => ({ err: { errno: res.errno } }));
    return (res?.results ?? []).slice(0, calls.length);
  }
  const answer = yield* request('POST', '/api/sys', JSON.stringify(body), { 'Content-Type': 'application/json' });
  if (answer.status !== 200) return calls.map(() => ({ err: { errno: 'EIO' } }));
  return JSON.parse(answer.text).results.slice(0, calls.length);
}
function* serverCall(one) {
  const [result] = yield* serverBatch([one]);
  if ('err' in result) throw new Errno(errnoOf(result.err));
  return result.ok;
}
const ok = result => { if ('err' in result) throw new Errno(errnoOf(result.err)); return result.ok; };

// ---- Descriptors ----

const fds = new Map();
const cloexec = new Set();
let shares = null, ttyState = null, ttyControl = null, membership = null;
let sockArena = null, sockNotify = null;
let lastTtyFds = '';

function reportTty() {
  const ctty = membership ? Atomics.load(membership, 2) : 0;
  if (process.pty) {
    const numbers = [...fds].filter(([, description]) => description.kind === 'tty').map(([fd]) => fd);
    const value = `${process.pty.number}:${JSON.stringify(numbers)}`;
    if (value !== lastTtyFds) { lastTtyFds = value; postMessage({ ttyFds: numbers, ttyNum: process.pty.number }); }
    return;
  }
  const slave = [...fds.values()].find(d => d.kind === 'pty' && !d.master);
  const ttyNum = ctty || slave?.number || 0;
  if (!ttyNum) return;
  const numbers = [...fds].filter(([, d]) => d.kind === 'pty' && !d.master && d.number === ttyNum).map(([fd]) => fd);
  const value = `${ttyNum}:${JSON.stringify(numbers)}`;
  if (value !== lastTtyFds) { lastTtyFds = value; postMessage({ ttyFds: numbers, ttyNum }); }
}
const controllingTerminal = () => !!process.pty && Atomics.load(membership, 2) === process.pty.number;
function normalizeAbs(path) {
  const parts = [];
  for (const seg of path.split('/')) {
    if (!seg || seg === '.') continue;
    if (seg === '..') parts.pop();
    else parts.push(seg);
  }
  return '/' + parts.join('/');
}

const procFdCandidate = path => typeof path === 'string' && /(?:^|\/)(?:proc\/(?:self|[0-9]+)\/fd|dev\/fd)\/[0-9]+$/.test(path);
function hasProcFsMount(path) {
  try {
    const sfs = vfsCall('statfs', { dirfd: OS_FD_ROOT, path: path.replace(/\/[0-9]+$/, '') });
    return sfs?.f_type === 0x9fa0;
  } catch {
    return false;
  }
}
function resolveProcFd(anchor, rawPath, info = false) {
  if (typeof rawPath !== 'string' || !rawPath) return null;
  let norm = null;
  if (rawPath.startsWith('/')) {
    norm = normalizeAbs(rawPath);
  } else if (anchor === OS_FD_ROOT) {
    norm = normalizeAbs('/' + rawPath);
  } else if (anchor === OS_FD_CWD && (/(?:^|\/)(?:proc|dev|fd|fdinfo)\//.test(rawPath) || /^[0-9]+$/.test(rawPath))) {
    try {
      norm = normalizeAbs(vfsCall('getcwd', {}).cwd + '/' + rawPath);
    } catch {
      return null;
    }
  } else if (anchor >= 0 && /^[0-9]+$/.test(rawPath)) {
    try {
      const dirPath = vfsCall('readlinkat', { dirfd: OS_FD_ROOT, path: `/proc/self/fd/${anchor}` }).target;
      norm = normalizeAbs(dirPath + '/' + rawPath);
    } catch {
      return null;
    }
  }
  if (!norm) return null;
  const pattern = info ? /^\/proc\/(self|[0-9]+)\/fdinfo\/([0-9]+)$/
    : /^\/(?:proc\/(self|[0-9]+)\/fd|dev\/fd)\/([0-9]+)$/;
  const match = pattern.exec(norm);
  if (!match) return null;
  if (match[1] && match[1] !== 'self' && Number(match[1]) !== process.pid) return null;
  if (!hasProcFsMount(norm)) return null;
  const guestFd = Number(match[2]);
  return { guestFd, found: fds.get(guestFd) ?? null, procPath: norm };
}
function procInfo(anchor, path) {
  const entry = resolveProcFd(anchor, path, true);
  if (!entry) return null;
  const { guestFd, found } = entry;
  if (!found) throw new Errno(ENOENT);
  if (found.kind === 'kfd') return { path: `/proc/self/fdinfo/${found.kfd}` };
  const access = found.writable ? (found.read || found.readable ? O_RDWR : O_WRONLY) : O_RDONLY;
  const flags = access | (found.append ? O_APPEND : 0) | (cloexec.has(guestFd) ? O_CLOEXEC : 0);
  const data = encoder.encode(`pos:\t${found.pos ?? 0}\nflags:\t0${flags.toString(8)}\n`);
  return { data, stat: { ino: guestFd + 1, mode: 0o100400, nlink: 1, uid: identity.uid, gid: identity.gid, size: data.length } };
}

function openProcInfo(info, flags) {
  if (flags & O_DIRECTORY) throw new Errno(ENOTDIR);
  if (flags & (3 | O_TRUNC)) throw new Errno(ERRNO.EACCES);
  const fd = lowest();
  install(fd, { kind: 'in', procInfo: true, stat: info.stat, data: info.data, pos: 0, pathOnly: !!(flags & O_PATH) });
  if (flags & O_CLOEXEC) cloexec.add(fd);
  return fd;
}

function procFdDirectory(path) {
  if (typeof path !== 'string') return null;
  const match = /^\/(?:proc\/(self|[0-9]+)\/(fd|fdinfo)|dev\/(fd))\/?$/.exec(path);
  if (!match || (match[1] && match[1] !== 'self' && Number(match[1]) !== process.pid) || !hasProcFsMount(path)) return null;
  const info = match[2] === 'fdinfo';
  return Array.from(fds.keys()).sort((a, b) => a - b).map(fd => ({
    name: String(fd), ino: fd + 1, type: info ? REGULAR_FILE : SYMBOLIC_LINK,
    stat: { ino: fd + 1, mode: info ? 0o100400 : 0o120700, nlink: 1, uid: identity.uid, gid: identity.gid },
  }));
}

function linkTextFor(found) {
  if (!found) return '';
  if (found.kind === 'pty') return found.master ? '/dev/ptmx' : `/dev/pts/${found.number}`;
  if (found.kind === 'tty') return process.pty ? `/dev/pts/${process.pty.number}` : '/dev/tty';
  if (found.preopen && found.kfd == null) return '/';
  if (found.kind === 'kfd' && found.kfd != null) {
    return vfsCall('readlinkat', { dirfd: OS_FD_ROOT, path: `/proc/self/fd/${found.kfd}` }).target;
  }
  if (found.serverDev) {
    const d = found.device ?? 'null';
    return (d.startsWith('present:') || d.startsWith('snd:')) ? `/dev/${d.replace(':', '/')}` : `/dev/${d}`;
  }
  if (found.kind === 'unix-sock') return `socket:[${found.sockId}]`;
  if (found.kind === 'inet-sock') return 'socket:[inet]';
  if (found.kind === 'arena-pipe-in' || found.kind === 'arena-pipe-out') return `pipe:[${found.slot}]`;
  if (found.tty && process.pty) return `/dev/pts/${process.pty.number}`;
  return 'pipe:[0]';
}

const ptyCall = (found, op, args = {}) => hostErrno(host('pty', { handle: found.handle, op, ...args }));
const ttyCall = (found, request, arg) => {
  if (!found.tty || found.kind !== 'pty' && !ttyState) throw new Errno(ERRNO.ENOTTY);
  return hostErrno(host('tty', { handle: found.handle, request, arg, readable: found.readable !== false }));
};
const vfsCall = (op, args = {}) => hostErrno(host('vfs', { op, ...args }));
const sockCall = (op, args = {}) => hostErrno(host('sock', { op, ...args }));

function attachSockRings(found) {
  if (!sockArena) { found.txRing = null; found.rxRing = null; return; }
  found.txRing = found.txSlot ? new ArenaRing(sockArena, found.txSlot.slot, found.txSlot.gen, process.pid, sockNotify) : null;
  found.rxRing = found.rxSlot ? new ArenaRing(sockArena, found.rxSlot.slot, found.rxSlot.gen, process.pid, sockNotify) : null;
}

function syncStreamTransport(found) {
  if (found.sockType !== SOCK_STREAM || (found.txRing && found.rxRing) || !sockArena) return;
  try {
    const info = sockCall('describe', { sockId: found.sockId });
    if (info.txSlot || info.rxSlot) {
      found.txSlot = info.txSlot ?? null;
      found.rxSlot = info.rxSlot ?? null;
      attachSockRings(found);
    }
  } catch { /* unbound/listening or closed; caller handles */ }
}

function sockDescriptor(fd) {
  const found = descriptor(fd);
  if (found.kind !== 'unix-sock') throw new Errno(ERRNO.ENOTSOCK);
  return found;
}

const terminalFd = (fd, readable = true, writable = true) => ({ kind: 'tty', tty: true, fd, readable, writable, pipe: new Pipe(process.pty.input, process.pid) });
function descriptor(fd) {
  const found = fd >= 0 ? fds.get(fd) : null;
  if (!found) throw new Errno(EBADF);
  return found;
}
function lowest(min = 0) {
  if (min < 0) throw new Errno(EBADF);
  let fd = min;
  while (fds.has(fd) || fd === OS_FD_ROOT || fd === OS_FD_CWD) fd++;
  if (fd >= FD_MAX) throw new Errno(ERRNO.EMFILE);
  return fd;
}
function lowestPair(min = 0) {
  const first = lowest(min);
  const second = lowest(first + 1);
  return [first, second];
}

const descriptorFlags = () => typeof SharedArrayBuffer === 'function' ? new SharedArrayBuffer(4) : new ArrayBuffer(4);

function sentinelAnchor(fd) {
  const u = fd >>> 0;
  if (u === OS_FD_ROOT) return OS_FD_ROOT;
  if (u === OS_FD_CWD) return OS_FD_CWD;
  return null;
}

function dirfdToAnchor(fd) {
  const sentinel = sentinelAnchor(fd);
  if (sentinel != null) return sentinel;
  if ((fd | 0) === -100) return OS_FD_CWD;
  const found = descriptor(fd);
  if (found.preopen && found.kfd == null) return OS_FD_ROOT;
  if (found.kfd == null) throw new Errno(ENOTDIR);
  return found.kfd;
}

function resolveAnchorForPath(dirfd, rawPath) {
  if (typeof rawPath !== 'string') throw new Errno(EINVAL);
  if (rawPath.startsWith('/')) return OS_FD_ROOT;
  return dirfdToAnchor(dirfd);
}

function install(fd, found, counted = false) {
  if ((STDIO.has(found.kind) && found.kind !== 'pty') || found.kind === 'unix-sock' || found.kind === 'inet-sock') found.flags ??= descriptorFlags();
  if (!counted && found.kind === 'pty') ptyCall(found, 'hold');
  if (!counted && found.kind === 'unix-sock') sockCall('hold', { sockId: found.sockId, count: 1 });
  if (!counted && found.kind === 'arena-pipe-in') sockCall('pipe_hold', { slot: found.slot, gen: found.gen, end: 'r', count: 1 });
  if (!counted && found.kind === 'arena-pipe-out') sockCall('pipe_hold', { slot: found.slot, gen: found.gen, end: 'w', count: 1 });
  found.refs = (found.refs ?? 0) + 1;
  fds.set(fd, found);
  reportTty();
  if (counted) return;
  if (found.kind === 'pipe-in' || found.kind === 'tty') found.pipe.hold(process.pid, 'r');
  else if (found.kind === 'pipe-out') found.pipe.hold(process.pid, 'w');
  else if (found.kind === 'unix-sock' || found.kind === 'inet-sock' || found.kind === 'arena-pipe-in' || found.kind === 'arena-pipe-out') return;
  else if (found.share != null) shares.add(found.share, process.pid, 1);
  else if (shares && (found.kind === 'file' || (found.kind === 'kfd' && !found.isDir && !found.mountNs && !found.pathOnly && !isByteDevice(found.device)))) share(found);
}

const nonblocking = found => {
  if (found.kind === 'pty') return ptyCall(found, 'flags').nonblock;
  if (found.kind === 'unix-sock') {
    if (found.txRing?.alive) return found.txRing.sockNonblock;
    return sockCall('get_nonblock', { sockId: found.sockId }).nonblock;
  }
  if (found.kind === 'arena-pipe-in' || found.kind === 'arena-pipe-out') {
    if (found.privateFlags) return !!(Atomics.load(new Int32Array(found.privateFlags), 0) & FDFLAG_NONBLOCK);
    return found.pipe.nonblock(found.kind === 'arena-pipe-in' ? 'r' : 'w');
  }
  return !!(found.flags && Atomics.load(new Int32Array(found.flags), 0) & FDFLAG_NONBLOCK);
};

function share(found) {
  const slot = shares.claim(process.pid, found.refs, found.pos ?? 0);
  if (slot < 0) return;
  if (found.kind === 'in' && !(found.data.buffer instanceof SharedArrayBuffer)) {
    const data = new Uint8Array(new SharedArrayBuffer(found.data.length));
    data.set(found.data);
    found.data = data;
  }
  if (found.kind === 'kfd') found.share = slot;
  else shares.attach(found, slot);
  postMessage({ described: { slot, gen: shares.gen(slot), description: describe(found) } });
}

const kernelDescriptor = found => found?.kind === 'kfd' || found?.serverDev === true;

function* uninstall(fd, kernelClosed = false) {
  const found = fds.get(fd);
  if (!found) throw new Errno(EBADF);
  fds.delete(fd);
  reportTty();
  cloexec.delete(fd);
  found.refs--;
  if (found.kind === 'pty') return ptyCall(found, 'close');
  if (found.kind === 'unix-sock') {
    if (!kernelClosed) sockCall('close', { sockId: found.sockId, count: 1 });
    return;
  }
  if (found.kind === 'inet-sock') return;
  if (found.kind === 'arena-pipe-in') return sockCall('pipe_close', { slot: found.slot, gen: found.gen, end: 'r', count: 1 });
  if (found.kind === 'arena-pipe-out') return sockCall('pipe_close', { slot: found.slot, gen: found.gen, end: 'w', count: 1 });
  if (found.kind === 'pipe-in' || found.kind === 'tty') return found.pipe.drop(process.pid, 'r');
  if (found.kind === 'pipe-out') return found.pipe.drop(process.pid, 'w');
  if (found.share != null) {
    const gen = shares.gen(found.share);
    const left = shares.drop(found.share, process.pid);
    if (left <= 0) postMessage({ closed: { slot: found.share, gen } });
    if (!kernelDescriptor(found) && left > 0) return;
  }
  if (found.refs > 0) return;
  if (kernelDescriptor(found)) {
    if (!kernelClosed) vfsCall('close', { kfd: found.kfd });
    forget();
    return;
  }
  yield* closeFd(found);
}

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
  if (found.procInfo) return REGULAR_FILE;
  if (found.preopen) return DIRECTORY;
  if (found.kind === 'unix-sock') return found.sockType === SOCK_DGRAM ? SOCKET_DGRAM : SOCKET_STREAM;
  if (found.kind === 'inet-sock') return SOCKET_STREAM;
  if (found.kind === 'kfd') {
    if (found.isDir) return DIRECTORY;
    if (found.device) return CHARACTER_DEVICE;
    if (found.typeMode != null) return kindOf(found.typeMode);
    if (found.stat) return kindOf(found.stat.mode);
    return REGULAR_FILE;
  }
  if (isByteDevice(found.device)) return CHARACTER_DEVICE;
  if (STDIO.has(found.kind)) return found.tty ? CHARACTER_DEVICE : UNKNOWN;
  return REGULAR_FILE;
}

function kindOf(mode) {
  switch (mode & 0o170000) {
    case 0o040000: return DIRECTORY;
    case 0o120000: return SYMBOLIC_LINK;
    case 0o020000: return CHARACTER_DEVICE;
    case 0o140000: return SOCKET_STREAM;
    default: return REGULAR_FILE;
  }
}

const nanos = (seconds, nsec = 0) => BigInt(seconds ?? 0) * 1000000000n + BigInt(nsec ?? 0);
function writeFilestat(ptr, found) {
  const v = view();
  v.setBigUint64(ptr, BigInt(found.dev ?? 0), true);
  v.setBigUint64(ptr + 8, BigInt(found.ino ?? 0), true);
  v.setUint8(ptr + 16, found.filetype ?? kindOf(found.mode));
  v.setBigUint64(ptr + 24, BigInt(found.nlink ?? 1), true);
  v.setBigUint64(ptr + 32, BigInt(found.size ?? 0), true);
  v.setBigUint64(ptr + 40, nanos(found.atime ?? found.mtime, found.atime_nsec ?? found.mtime_nsec), true);
  v.setBigUint64(ptr + 48, nanos(found.mtime, found.mtime_nsec), true);
  v.setBigUint64(ptr + 56, nanos(found.ctime, found.ctime_nsec), true);
}

function writeRawStatFs(outPtr, sfs) {
  const b = bytes();
  if (outPtr < 0 || outPtr + 80 > b.length) throw new Errno(ERRNO.EFAULT);
  const v = view();
  const bsize = BigInt(sfs.bsize ?? 4096);
  const frsize = sfs.frsize ? BigInt(sfs.frsize) : bsize;
  v.setBigUint64(outPtr + 0, BigInt(sfs.f_type ?? 0), true);
  v.setBigUint64(outPtr + 8, bsize, true);
  v.setBigUint64(outPtr + 16, frsize, true);
  v.setBigUint64(outPtr + 24, BigInt(sfs.blocks ?? 0), true);
  v.setBigUint64(outPtr + 32, BigInt(sfs.bfree ?? 0), true);
  v.setBigUint64(outPtr + 40, BigInt(sfs.bavail ?? 0), true);
  v.setBigUint64(outPtr + 48, BigInt(sfs.files ?? 0), true);
  v.setBigUint64(outPtr + 56, BigInt(sfs.ffree ?? 0), true);
  v.setBigUint64(outPtr + 64, BigInt(sfs.namelen ?? 255), true);
  v.setBigUint64(outPtr + 72, BigInt(sfs.flags ?? 0), true);
}

function kfdRead(found, offset, count) {
  if (!found.read) throw new Errno(EBADF);
  if (found.isDir) throw new Errno(EISDIR);
  if (isByteDevice(found.device)) {
    try { return readDevice(found.device, count); } catch { throw new Errno(EIO); }
  }
  if (count === 0) return new Uint8Array(0);
  const out = new Uint8Array(count);
  let got = 0;
  while (got < count) {
    const want = Math.min(VFS_CHUNK, count - got);
    let reply;
    try {
      reply = offset != null
        ? vfsCall('pread', { kfd: found.kfd, len: want, offset: (BigInt(offset) + BigInt(got)).toString() })
        : vfsCall('read', { kfd: found.kfd, len: want });
    } catch (error) {
      if (got > 0 && error instanceof Errno) break;
      throw error;
    }
    const chunk = unbase64(reply.data);
    out.set(chunk, got);
    got += chunk.length;
    if (chunk.length < want) break;
  }
  return out.subarray(0, got);
}

function kfdWrite(found, offset, data) {
  if (!found.writable) throw new Errno(EBADF);
  if (isByteDevice(found.device)) {
    if (found.device === 'full') throw new Errno(ERRNO.ENOSPC);
    return data.length;
  }
  if (!data.length) return 0;
  let sent = 0;
  while (sent < data.length) {
    const chunk = data.subarray(sent, sent + VFS_CHUNK);
    let reply;
    try {
      reply = offset != null
        ? vfsCall('pwrite', { kfd: found.kfd, data: base64(chunk), offset: (BigInt(offset) + BigInt(sent)).toString() })
        : vfsCall('write', { kfd: found.kfd, data: base64(chunk) });
    } catch (error) {
      if (sent > 0 && error instanceof Errno) return sent;
      throw error;
    }
    if (!reply.written) break;
    sent += reply.written;
    if (reply.written < chunk.length) break;
  }
  return sent;
}

function* syncFd(fd, dataOnly) {
  const found = descriptor(fd);
  if (found.kind === 'kfd') {
    vfsCall('fsync', { kfd: found.kfd, dataOnly: !!dataOnly });
    return;
  }
  if (found.preopen) {
    vfsCall('statat', { dirfd: OS_FD_ROOT, path: '/', follow: true });
    return;
  }
  throw new Errno(EINVAL);
}

function statOf(found) {
  if (found.procInfo) return found.stat;
  if (found.kind === 'kfd') return vfsCall('fstat', { kfd: found.kfd });
  if (found.preopen) return vfsCall('statat', { dirfd: OS_FD_ROOT, path: '/', follow: true });
  if (found.kind === 'unix-sock') return { ino: found.sockId, filetype: filetype(found), mode: 0o140777 };
  if (found.kind === 'inet-sock') return { ino: 0, filetype: SOCKET_STREAM, mode: 0o140777 };
  if (found.kind === 'pty') return { ino: found.number, filetype: CHARACTER_DEVICE, mode: 0o020600 };
  if (STDIO.has(found.kind)) return { filetype: filetype(found), mode: found.tty ? 0o020620 : 0o010600 };
  return found.stat ?? { filetype: REGULAR_FILE, mode: 0o100644, size: found.size ?? 0 };
}
function* fstat(found) { return statOf(found); }

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

function waitSockNotify(seen, timeoutMs = 20) {
  flush();
  pause(true);
  if (sockNotify) {
    if (Atomics.wait(sockNotify, 0, seen, timeoutMs) === 'timed-out') pause(true);
    return;
  }
  sleepUntil(performance.now() + timeoutMs);
}

function checkedSlice(ptr, len) {
  const b = bytes();
  const p = ptr >>> 0, n = len >>> 0;
  if (p + n > b.length) throw new Errno(ERRNO.EFAULT);
  return b.slice(p, p + n);
}

function checkedString(ptr, len) {
  return decoder.decode(checkedSlice(ptr, len));
}

function checkWritable(ptr, len) {
  const b = bytes();
  const p = ptr >>> 0, n = len >>> 0;
  if (p + n > b.length) throw new Errno(ERRNO.EFAULT);
  return p;
}

function writePeerCred(ptr, cred) {
  if (!ptr) return;
  const p = checkWritable(ptr, 12);
  const v = view();
  v.setUint32(p, cred?.pid ?? 0, true);
  v.setUint32(p + 4, cred?.uid ?? 0, true);
  v.setUint32(p + 8, cred?.gid ?? 0, true);
}

function cachedPeerCred(found) {
  if (found.peerCred) return found.peerCred;
  try {
    found.peerCred = sockCall('peercred', { sockId: found.sockId });
    return found.peerCred;
  } catch {
    return { pid: 0, uid: 0, gid: 0 };
  }
}

function encodeSendFd(guestFd) {
  const fd = guestFd | 0;
  const found = fd >= 0 ? fds.get(fd) : null;
  if (!found) throw new Errno(EBADF);
  if (found.kind === 'kfd' && found.kfd != null) {
    return {
      kind: 'kfd',
      kfd: found.kfd,
      isDir: !!found.isDir,
      mountNs: !!found.mountNs,
      device: found.device ?? null,
      read: !!found.read,
      writable: !!found.writable,
      append: !!found.append,
      pathOnly: !!found.pathOnly,
    };
  }
  if (found.serverDev && found.kfd != null) {
    return {
      kind: 'server_dev',
      vfd: found.kfd,
      device: found.device ?? '',
      read: !!found.read,
      writable: !!found.writable,
    };
  }
  if (found.kind === 'unix-sock') {
    return { kind: 'unix_sock', sockId: found.sockId };
  }
  if (found.kind === 'arena-pipe-in') {
    return { kind: 'arena_pipe', slot: found.slot, gen: found.gen, end: 'r', pathOnly: !!found.pathOnly };
  }
  if (found.kind === 'arena-pipe-out') {
    return { kind: 'arena_pipe', slot: found.slot, gen: found.gen, end: 'w', pathOnly: !!found.pathOnly };
  }
  if (found.kind === 'pty') {
    return {
      kind: 'pty',
      handle: found.handle,
      master: !!found.master,
      number: found.number ?? 0,
      read: found.readable !== false,
      writable: found.writable !== false,
    };
  }
  throw new Errno(ERRNO.EOPNOTSUPP);
}

function disposeUninstalledFd(spec) {
  try {
    if (spec.kind === 'kfd') vfsCall('close', { kfd: spec.kfd });
    else if (spec.kind === 'server_dev') vfsCall('sys', { batch: { calls: [{ close: { fd: spec.kfd } }], umask: process.umask } });
    else if (spec.kind === 'unix_sock') sockCall('close', { sockId: spec.sockId, count: 1 });
    else if (spec.kind === 'arena_pipe') sockCall('pipe_close', { slot: spec.slot, gen: spec.gen, end: spec.end, count: 1 });
    else if (spec.kind === 'pty') host('pty', { handle: spec.handle, op: 'close' });
  } catch { /* best-effort cleanup */ }
}

function installReceivedFd(spec, cmsgCloexec) {
  const num = lowest();
  let desc;
  let counted = false;
  if (spec.kind === 'kfd') {
    desc = {
      kind: 'kfd',
      kfd: spec.kfd,
      isDir: !!spec.isDir,
      mountNs: !!spec.mountNs,
      device: spec.device ?? null,
      read: spec.read !== false,
      writable: !!spec.writable,
      append: !!spec.append,
      pathOnly: !!spec.pathOnly,
      typeMode: spec.typeMode ?? spec.stat?.mode,
    };
  } else if (spec.kind === 'server_dev') {
    desc = {
      kind: 'file',
      serverDev: true,
      kfd: spec.kfd,
      device: spec.device ?? '',
      read: spec.read !== false,
      writable: !!spec.writable,
      pos: 0,
      size: 0,
    };
  } else if (spec.kind === 'unix_sock') {
    desc = {
      kind: 'unix-sock',
      sockId: spec.sockId,
      sockType: spec.sockType,
      txSlot: spec.txSlot ?? null,
      rxSlot: spec.rxSlot ?? null,
      peerCred: null,
    };
    attachSockRings(desc);
    counted = true;
  } else if (spec.kind === 'arena_pipe') {
    desc = {
      kind: spec.end === 'r' ? 'arena-pipe-in' : 'arena-pipe-out',
      slot: spec.slot,
      gen: spec.gen,
      pipe: new ArenaPipe(sockArena, spec.slot, spec.gen, process.pid, sockNotify),
      ...(spec.pathOnly ? { pathOnly: true } : {}),
    };
    counted = true;
  } else if (spec.kind === 'pty') {
    desc = {
      kind: 'pty',
      tty: true,
      handle: spec.handle,
      master: !!spec.master,
      number: spec.number ?? 0,
      readable: spec.read !== false,
      writable: spec.writable !== false,
    };
    counted = true;
  } else {
    throw new Errno(EIO);
  }
  install(num, desc, counted);
  if (cmsgCloexec) cloexec.add(num);
  return num;
}

function sockSendMsg(found, data, fdsList, addr, flags) {
  syncStreamTransport(found);
  const nonblock = nonblocking(found) || !!(flags & MSG_DONTWAIT);
  const nosignal = !!(flags & MSG_NOSIGNAL);
  // Fast zero-copy SAB ring path for connected SOCK_STREAM without ancillary fds, dest addr,
  // or peer `SO_PASSCRED` (which requires per-write sender credentials from LocalProcessTable).
  if (found.sockType === SOCK_STREAM && found.txRing && fdsList.length === 0 && addr == null && !found.txRing.passcred) {
    const ring = found.txRing;
    if (data.length === 0) {
      if (!ring.alive || ring.rdClosed || ring.wrClosed) return brokenPipe(0, nosignal);
      return 0;
    }
    if (nonblock) {
      const { written, broken } = ring.tryWrite(data, { atomicLimit: 1 });
      if (broken) return brokenPipe(written, nosignal);
      if (!written && data.length) throw new Errno(ERRNO.EAGAIN);
      return written;
    }
    if (ring.room < data.length) flush();
    const { written, broken } = ring.write(data, done => {
      try { pause(true); }
      catch (error) {
        if (done && error instanceof Errno && error.errno === ERRNO.EINTR) return false;
        throw error;
      }
    }, { atomicLimit: 1 });
    return broken ? brokenPipe(written, nosignal) : written;
  }

  // Atomic SOCK_STREAM SAB send with SCM_RIGHTS or SO_PASSCRED: exec.mjs validates & reserves
  // quota BEFORE copying bytes into `txRing`.
  if (found.sockType === SOCK_STREAM && found.txRing && addr == null) {
    const ring = found.txRing;
    const chunk = data.length > RING_CAPACITY ? data.subarray(0, RING_CAPACITY) : data;
    for (;;) {
      pause(true);
      if (!ring.alive || ring.rdClosed || ring.wrClosed) return brokenPipe(0, nosignal);
      if (chunk.length === 0) return 0;
      const seen = Atomics.load(ring.hdr, HDR_CHANGES);
      if (ring.room === 0) {
        if (nonblock) throw new Errno(ERRNO.EAGAIN);
        flush();
        if (Atomics.wait(ring.hdr, HDR_CHANGES, seen, 20) === 'timed-out') pause(true);
        continue;
      }
      try {
        const res = sockCall('sendmsg', {
          sockId: found.sockId,
          txSlot: found.txSlot,
          data: base64(chunk),
          fds: fdsList,
        });
        return res.sent ?? chunk.length;
      } catch (err) {
        if (err instanceof Errno && err.errno === ERRNO.EPIPE) return brokenPipe(0, nosignal);
        if (err instanceof Errno && err.errno === ERRNO.EAGAIN && !nonblock) {
          if (Atomics.wait(ring.hdr, HDR_CHANGES, seen, 20) === 'timed-out') pause(true);
          continue;
        }
        throw err;
      }
    }
  }

  // SOCK_DGRAM / SOCK_SEQPACKET / unconnected SOCK_STREAM -> Rust UnixSocketTable.
  for (;;) {
    pause(true);
    const seen = sockNotify ? Atomics.load(sockNotify, 0) : 0;
    try {
      const res = sockCall('sendmsg', {
        sockId: found.sockId,
        data: data.length ? base64(data) : '',
        fds: fdsList,
        addr,
      });
      return res.sent ?? data.length;
    } catch (err) {
      if (err instanceof Errno && err.errno === ERRNO.EPIPE) return brokenPipe(0, nosignal);
      if (err instanceof Errno && err.errno === ERRNO.EAGAIN && !nonblock) {
        waitSockNotify(seen, 20);
        continue;
      }
      throw err;
    }
  }
}

function sockRecvStream(found, bufLen, maxFds, flags) {
  const ring = found.rxRing;
  const nonblock = nonblocking(found) || !!(flags & MSG_DONTWAIT);
  const peek = !!(flags & MSG_PEEK);
  const cmsgCloexec = !!(flags & MSG_CMSG_CLOEXEC);
  for (;;) {
    pause(true);
    const seen = Atomics.load(ring.hdr, HDR_CHANGES);
    if (ring.rdClosed) {
      return { data: new Uint8Array(0), reportedLen: 0, fds: [], peerCred: cachedPeerCred(found), outFlags: 0 };
    }
    if (bufLen === 0 && ring.queued > 0) {
      return { data: new Uint8Array(0), reportedLen: 0, fds: [], peerCred: cachedPeerCred(found), outFlags: 0 };
    }
    if (ring.hasAncillary) {
      const tail = ring.tailOffset;
      const ancOff = ring.ancillaryOffset;
      if (tail >= ancOff) {
        const res = sockCall('recvmsg', {
          sockId: found.sockId,
          rxSlot: found.rxSlot,
          sabStream: true,
          bufLen,
          maxFds,
          flags,
          cmsgCloexec,
        });
        if (res.lockBusy) {
          Atomics.wait(ring.hdr, HDR_CHANGES, seen, 2);
          continue;
        }
        if (!res.wouldBlock) {
          const data = res.data ? unbase64(res.data) : new Uint8Array(0);
          return {
            data,
            reportedLen: res.reportedLen ?? data.length,
            fds: res.fds ?? [],
            peerCred: res.peerCred,
            outFlags: res.flags ?? 0,
          };
        }
      } else if (ring.queued > 0) {
        const data = ring.read(bufLen, undefined, { nonblock: true, peek, maxOffset: ancOff, stopAtAncillary: true });
        if (data && (data.length > 0 || bufLen === 0)) {
          return { data, reportedLen: data.length, fds: [], peerCred: cachedPeerCred(found), outFlags: 0 };
        }
      }
    } else if (ring.queued > 0) {
      const data = ring.read(bufLen, undefined, { nonblock: true, peek, stopAtAncillary: true });
      if (data && (data.length > 0 || bufLen === 0)) {
        return { data, reportedLen: data.length, fds: [], peerCred: cachedPeerCred(found), outFlags: 0 };
      }
      if (ring.hasAncillary) continue;
    }
    if ((ring.wrClosed || ring.rdClosed) && ring.queued === 0 && !ring.hasAncillary) {
      return { data: new Uint8Array(0), reportedLen: 0, fds: [], peerCred: cachedPeerCred(found), outFlags: 0 };
    }
    if (nonblock) throw new Errno(ERRNO.EAGAIN);
    flush();
    if (Atomics.wait(ring.hdr, HDR_CHANGES, seen, 20) === 'timed-out') pause(true);
  }
}

function sockRecvMsg(found, bufLen, maxFds, flags) {
  syncStreamTransport(found);
  if (found.sockType === SOCK_STREAM && found.rxRing) {
    return sockRecvStream(found, bufLen, maxFds, flags);
  }
  const nonblock = nonblocking(found) || !!(flags & MSG_DONTWAIT);
  const cmsgCloexec = !!(flags & MSG_CMSG_CLOEXEC);
  for (;;) {
    pause(true);
    const seen = sockNotify ? Atomics.load(sockNotify, 0) : 0;
    const res = sockCall('recvmsg', {
      sockId: found.sockId,
      bufLen,
      maxFds,
      flags,
      cmsgCloexec,
    });
    if (res.wouldBlock) {
      if (nonblock) throw new Errno(ERRNO.EAGAIN);
      waitSockNotify(seen, 20);
      continue;
    }
    const data = res.data ? unbase64(res.data) : new Uint8Array(0);
    return {
      data,
      reportedLen: res.reportedLen ?? data.length,
      fds: res.fds ?? [],
      peerCred: res.peerCred,
      outFlags: res.flags ?? 0,
    };
  }
}

function sockReadBytes(found, count) {
  if (count === 0) return new Uint8Array(0);
  const res = sockRecvMsg(found, count, 0, 0);
  for (const spec of res.fds) disposeUninstalledFd(spec);
  return res.data;
}

function sockWriteBytes(found, data) {
  return sockSendMsg(found, data, [], null, 0);
}

function* readFrom(found, at, count) {
  if (found.tty && found.readable === false) throw new Errno(EBADF);
  if (found.kind === 'pty') return readPty(found, count);
  if (found.kind === 'unix-sock') return sockReadBytes(found, count);
  if (found.kind === 'inet-sock') throw new Errno(ERRNO.ENOTCONN);
  if (found.preopen) throw new Errno(EISDIR);
  if (found.kind === 'in') {
    if (found.pathOnly) throw new Errno(EBADF);
    const out = found.data.subarray(found.pos, found.pos + count);
    found.pos += out.length;
    return out;
  }
  if (found.kind === 'pipe-in' || found.kind === 'arena-pipe-in' || found.kind === 'tty') {
    if (found.pathOnly) throw new Errno(EBADF);
    if (count === 0) return new Uint8Array(0);
    const nonblock = nonblocking(found);
    if (nonblock && found.tty) ttyAccess(21);
    if (found.pipe.empty) { flush(nonblock); if (found.tty) postMessage({ reading: true }); }
    const read = nonblock ? found.pipe.read(count, undefined, !!(found.tty && ttyState?.canonical), true)
      : found.tty && ttyState ? readTerminal(found.pipe, count) : found.pipe.read(count, () => pause(true));
    if (read === null) throw new Errno(ERRNO.EAGAIN);
    pause();
    return read;
  }
  if (found.kind === 'out' || found.kind === 'pipe-out' || found.kind === 'arena-pipe-out') throw new Errno(EBADF);
  if (!found.read) throw new Errno(EBADF);
  if (isByteDevice(found.device)) {
    try { return readDevice(found.device, count); } catch { throw new Errno(EIO); }
  }
  if (found.serverDev) {
    const want = Math.min(count, INLINE);
    const res = vfsCall('sys', { batch: { calls: [{ pread: { fd: found.kfd, offset: at, count: want } }], umask: process.umask } }).results[0];
    const read = ok(res);
    found.size = read.size ?? 0;
    return unbase64(read.data);
  }
  throw new Errno(EBADF);
}

function* writeTo(found, at, data) {
  if (found.tty && found.writable === false) throw new Errno(EBADF);
  if (found.kind === 'pty') return writePty(found, data);
  if (found.kind === 'unix-sock') return sockWriteBytes(found, data);
  if (found.kind === 'inet-sock') throw new Errno(ERRNO.ENOTCONN);
  if (found.kind === 'tty' && ttyControl.hungup) throw new Errno(EIO);
  if (isByteDevice(found.device)) {
    if (!found.writable) throw new Errno(EBADF);
    if (found.device === 'full') throw new Errno(ERRNO.ENOSPC);
    return data.length;
  }
  if (found.serverDev) {
    if (!found.writable) throw new Errno(EBADF);
    let sent = 0;
    while (sent < data.length) {
      const chunk = data.subarray(sent, sent + INLINE);
      const res = vfsCall('sys', { batch: { calls: [{ pwrite: { fd: found.kfd, index: Math.floor((at + sent) / INLINE), data: base64(chunk) } }], umask: process.umask } }).results[0];
      ok(res);
      sent += chunk.length;
    }
    return sent;
  }
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
  if (found.kind === 'pipe-out' || found.kind === 'arena-pipe-out') {
    if (found.pathOnly) throw new Errno(EBADF);
    if (nonblocking(found)) {
      const { written, broken } = found.pipe.tryWrite(data);
      if (broken) return brokenPipe(written);
      if (!written && data.length) throw new Errno(ERRNO.EAGAIN);
      return written;
    }
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
  throw new Errno(EBADF);
}

function brokenPipe(written = 0, nosignal = false) {
  if (written) return written;
  if (!nosignal) {
    signals.queue(SIGPIPE);
    dispatchSignals();
  }
  throw new Errno(ERRNO.EPIPE);
}

function* closeFd(found) {
  if (found.kind === 'file' && found.serverDev && found.kfd !== undefined) {
    vfsCall('sys', { batch: { calls: [{ close: { fd: found.kfd } }], umask: process.umask } });
    return;
  }
  if (found.kind === 'file' && found.kfd !== undefined) {
    closing.push(found.kfd);
  }
}

// ---- Output Buffering ----

let pending = [], pendingBytes = 0, written = 0, lastFlush = 0, outputCredit = null;
const OUTPUT_CHUNK = 4096;
function output(fd, data, tty = false) {
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
  if (nonblock && outputCredit) {
    let frames = 1;
    for (let i = 1; i < pending.length; i++) if (pending[i][0] !== pending[i - 1][0] || pending[i][2] !== pending[i - 1][2]) frames++;
    for (;;) {
      const available = Atomics.load(outputCredit, 0);
      if (available < frames) return false;
      if (Atomics.compareExchange(outputCredit, 0, available, available - frames) === available) break;
    }
  }
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
function pointerStrings(ptr, count) {
  if (count < 0 || count > 4096) throw new Errno(ERRNO.E2BIG);
  const v = view(), b = bytes(), result = [];
  if (ptr < 0 || ptr + count * 4 > b.length) throw new Errno(ERRNO.EFAULT);
  let total = 0;
  for (let i = 0; i < count; i++) {
    const start = v.getUint32(ptr + i * 4, true);
    if (start >= b.length) throw new Errno(ERRNO.EFAULT);
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
function attempt(work) {
  const failed = err => { if (err instanceof Errno) return err.errno; throw err; };
  let done;
  try { done = drive(work()); } catch (err) { return failed(err); }
  return done instanceof Promise ? done.then(value => value ?? 0, failed) : done ?? 0;
}

let environ = [];

function openPathAt(dirfd, rawPath, dirflags, oflags, base, fdflags, noctty = false, mode = 0o666, extraFlags = 0) {
  const pathOnly = (extraFlags & O_PATH) !== 0;
  const write = !pathOnly && (base & RIGHT_WRITE) !== 0n;
  const read = !pathOnly && ((base & RIGHT_READ) !== 0n || !write);
  const append = !pathOnly && (fdflags & FDFLAG_APPEND) !== 0;
  const cloexecFlag = (extraFlags & O_CLOEXEC) !== 0;
  let anchor = resolveAnchorForPath(dirfd, rawPath);

  const info = procInfo(anchor, rawPath);
  if (info?.data) return openProcInfo(info, (write ? O_WRONLY : 0) | extraFlags | (oflags & OFLAG_DIRECTORY ? O_DIRECTORY : 0));
  if (info) { anchor = OS_FD_ROOT; rawPath = info.path; }

  // Reopening a descriptor via `/proc/self/fd/<N>`, `/proc/<pid>/fd/<N>`, or `/dev/fd/<N>`
  // verifies first that genuine `ProcFs` (`0x9fa0`) is mounted in this root/namespace.
  const procEntry = resolveProcFd(anchor, rawPath);
  if (procEntry) {
    if (!procEntry.found) throw new Errno(ENOENT);
    if (!(dirflags & FOLLOW) && !pathOnly) throw new Errno(ERRNO.ELOOP);
    const original = procEntry.found;
    if (original.kind === 'unix-sock' || original.kind === 'inet-sock') {
      throw new Errno(ERRNO.ENXIO);
    } else if (original.kind === 'pty') {
      if (original.master) throw new Errno(ERRNO.EACCES);
      rawPath = `/dev/pts/${original.number}`;
      anchor = OS_FD_ROOT;
    } else if (['out', 'pipe-in', 'pipe-out', 'arena-pipe-in', 'arena-pipe-out', 'tty'].includes(original.kind)) {
      if (oflags & OFLAG_DIRECTORY) throw new Errno(ENOTDIR);
      if ((oflags & OFLAG_CREAT) && (oflags & OFLAG_EXCL)) throw new Errno(ERRNO.EEXIST);
      if (fdflags & ~FDFLAG_NONBLOCK) throw new Errno(ERRNO.EOPNOTSUPP);
      const readable = ['pipe-in', 'arena-pipe-in'].includes(original.kind) || (original.kind === 'tty' && original.readable !== false);
      const writable = ['out', 'pipe-out', 'arena-pipe-out'].includes(original.kind) || (original.kind === 'tty' && original.writable !== false);
      if ((read && !readable) || (write && !writable)) throw new Errno(ERRNO.EACCES);
      const isArenaPipe = original.kind === 'arena-pipe-in' || original.kind === 'arena-pipe-out';
      const reopenedFlags = descriptorFlags();
      const found = {
        ...original,
        refs: 0,
        flags: reopenedFlags,
        ...(isArenaPipe ? { privateFlags: reopenedFlags } : {}),
        readable: read,
        writable: write,
        ...(pathOnly ? { pathOnly: true } : {}),
      };
      const number = lowest();
      install(number, found, false);
      Atomics.store(new Int32Array(reopenedFlags), 0, fdflags & FDFLAG_NONBLOCK);
      if (cloexecFlag) cloexec.add(number);
      return number;
    } else if (original.kind === 'in') {
      if (oflags & OFLAG_DIRECTORY) throw new Errno(ENOTDIR);
      if ((oflags & OFLAG_CREAT) && (oflags & OFLAG_EXCL)) throw new Errno(ERRNO.EEXIST);
      if (!pathOnly && write) throw new Errno(ERRNO.EACCES);
      const found = { ...original, refs: 0, flags: descriptorFlags(), ...(pathOnly ? { pathOnly: true } : {}) };
      const number = lowest();
      install(number, found, false);
      if (found.flags) Atomics.store(new Int32Array(found.flags), 0, fdflags & FDFLAG_NONBLOCK);
      if (cloexecFlag) cloexec.add(number);
      return number;
    } else if (original.preopen && original.kfd == null) {
      rawPath = '/';
      anchor = OS_FD_ROOT;
    } else if (original.kind === 'kfd' && original.kfd != null) {
      rawPath = `/proc/self/fd/${original.kfd}`;
      anchor = OS_FD_ROOT;
    } else if (original.serverDev) {
      rawPath = linkTextFor(original);
      anchor = OS_FD_ROOT;
    }
  }

  const linuxFlags = (pathOnly ? O_PATH : (write ? (read ? O_RDWR : O_WRONLY) : O_RDONLY))
    | (oflags & OFLAG_CREAT ? O_CREAT : 0)
    | (oflags & OFLAG_TRUNC ? O_TRUNC : 0)
    | (oflags & OFLAG_EXCL ? O_EXCL : 0)
    | (append ? O_APPEND : 0)
    | (oflags & OFLAG_DIRECTORY ? O_DIRECTORY : 0)
    | (dirflags & FOLLOW ? 0 : O_NOFOLLOW);

  const opened = vfsCall('openat', {
    dirfd: anchor,
    path: rawPath,
    oflags: linuxFlags,
    mode,
    cloexec: cloexecFlag,
  });

  let found;
  const dev = opened.device;
  if (!pathOnly && dev === 'ptmx') {
    vfsCall('close', { kfd: opened.kfd });
    if (oflags & OFLAG_DIRECTORY) throw new Errno(ENOTDIR);
    found = {
      kind: 'pty',
      tty: true,
      ...hostErrno(host('pty', { op: 'open', path: '/dev/ptmx', readable: read, writable: write, nonblock: !!(fdflags & FDFLAG_NONBLOCK), noctty })),
    };
  } else if (!pathOnly && (dev === 'tty' || dev === 'console')) {
    vfsCall('close', { kfd: opened.kfd });
    if (oflags & OFLAG_DIRECTORY) throw new Errno(ENOTDIR);
    const ctty = Atomics.load(membership, 2);
    if (!ctty) throw new Errno(ERRNO.ENXIO);
    if (ctty >= 0x40000000) {
      found = {
        kind: 'pty',
        tty: true,
        ...hostErrno(host('pty', { op: 'open', path: '/dev/tty', readable: read, writable: write, nonblock: !!(fdflags & FDFLAG_NONBLOCK), noctty })),
      };
    } else if (process.pty && ctty === process.pty.number) {
      if (ttyControl?.hungup) throw new Errno(ERRNO.ENXIO);
      found = terminalFd(1, read, write);
    } else {
      throw new Errno(ERRNO.ENXIO);
    }
  } else if (!pathOnly && typeof dev === 'string' && dev.startsWith('pts:')) {
    vfsCall('close', { kfd: opened.kfd });
    if (oflags & OFLAG_DIRECTORY) throw new Errno(ENOTDIR);
    const ptsNum = Number(dev.slice(4));
    if (ptsNum >= 0x40000000) {
      found = {
        kind: 'pty',
        tty: true,
        ...hostErrno(host('pty', { op: 'open', path: `/dev/pts/${ptsNum}`, readable: read, writable: write, nonblock: !!(fdflags & FDFLAG_NONBLOCK), noctty })),
      };
    } else if (process.pty && ptsNum === process.pty.number) {
      if (ttyControl?.hungup) throw new Errno(ENOENT);
      found = terminalFd(1, read, write);
      if (!noctty) ttyCall(found, 'open');
    } else {
      throw new Errno(ENOENT);
    }
  } else if (opened.serverDev) {
    found = { kind: 'file', serverDev: true, kfd: opened.fd, device: dev, read, writable: write, pos: 0, size: 0, stat: opened.stat };
  } else {
    found = {
      kind: 'kfd',
      kfd: opened.kfd,
      isDir: !!opened.isDir,
      mountNs: !!opened.mountNs,
      device: dev ?? null,
      read,
      writable: write,
      append,
      pathOnly,
      stat: opened.stat,
    };
    if (fdflags & FDFLAG_NONBLOCK) found.flags = descriptorFlags();
  }

  const number = lowest();
  install(number, found, found.kind === 'pty');
  if (found.flags) Atomics.store(new Int32Array(found.flags), 0, fdflags & FDFLAG_NONBLOCK);
  if (cloexecFlag) cloexec.add(number);
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
  fd_datasync: fd => attempt(() => syncFd(fd, true)),
  fd_sync: fd => attempt(() => syncFd(fd, false)),
  fd_close: fd => attempt(function* () { descriptor(fd); return yield* uninstall(fd); }),
  fd_fdstat_get: (fd, ptr) => attempt(function* () {
    const v = view();
    if (sentinelAnchor(fd) != null) {
      v.setUint8(ptr, DIRECTORY);
      v.setUint16(ptr + 2, 0, true);
      v.setBigUint64(ptr + 8, ALL_RIGHTS, true);
      v.setBigUint64(ptr + 16, ALL_RIGHTS, true);
      return;
    }
    const found = descriptor(fd);
    const appending = found.kind === 'kfd' && !found.isDir && !found.pathOnly
      ? vfsCall('is_append', { kfd: found.kfd }).append
      : !!found.append;
    v.setUint8(ptr, filetype(found));
    v.setUint16(ptr + 2, (appending ? FDFLAG_APPEND : 0) | (nonblocking(found) ? FDFLAG_NONBLOCK : 0), true);
    const nonSeekable = found.tty || found.kind === 'unix-sock' || found.kind === 'inet-sock' || found.kind === 'pipe-in' || found.kind === 'pipe-out' || found.kind === 'arena-pipe-in' || found.kind === 'arena-pipe-out';
    let rights = nonSeekable ? ALL_RIGHTS & ~(RIGHT_SEEK | RIGHT_TELL) : ALL_RIGHTS;
    if (found.tty && found.readable === false) rights &= ~RIGHT_READ;
    if (found.tty && found.writable === false) rights &= ~RIGHT_WRITE;
    v.setBigUint64(ptr + 8, rights, true);
    v.setBigUint64(ptr + 16, ALL_RIGHTS, true);
  }),
  fd_fdstat_set_flags: (fd, flags) => attempt(function* () {
    const found = descriptor(fd);
    if (found.kind === 'kfd') {
      if (flags & ~(FDFLAG_APPEND | FDFLAG_NONBLOCK)) throw new Errno(ERRNO.EOPNOTSUPP);
      vfsCall('set_append', { kfd: found.kfd, append: !!(flags & FDFLAG_APPEND) });
      found.append = !!(flags & FDFLAG_APPEND);
      found.flags ??= descriptorFlags();
      Atomics.store(new Int32Array(found.flags), 0, flags & FDFLAG_NONBLOCK);
      return;
    }
    if (found.kind === 'unix-sock') {
      if (flags & ~FDFLAG_NONBLOCK) throw new Errno(ERRNO.EOPNOTSUPP);
      sockCall('set_nonblock', { sockId: found.sockId, nonblock: !!(flags & FDFLAG_NONBLOCK) });
      return;
    }
    if (found.kind === 'arena-pipe-in' || found.kind === 'arena-pipe-out') {
      if (flags & ~FDFLAG_NONBLOCK) throw new Errno(ERRNO.EOPNOTSUPP);
      if (found.privateFlags) Atomics.store(new Int32Array(found.privateFlags), 0, flags & FDFLAG_NONBLOCK);
      else found.pipe.setNonblock(found.kind === 'arena-pipe-in' ? 'r' : 'w', !!(flags & FDFLAG_NONBLOCK));
      return;
    }
    if (found.kind === 'pty') {
      if (flags & ~FDFLAG_NONBLOCK) throw new Errno(ERRNO.EOPNOTSUPP);
      ptyCall(found, 'flags', { nonblock: !!(flags & FDFLAG_NONBLOCK) });
    } else if (found.flags) {
      if (flags & ~FDFLAG_NONBLOCK) throw new Errno(ERRNO.EOPNOTSUPP);
      Atomics.store(new Int32Array(found.flags), 0, flags);
    }
  }),
  fd_fdstat_set_rights: () => 0,
  fd_filestat_get: (fd, ptr) => attempt(function* () {
    const anchor = sentinelAnchor(fd);
    if (anchor != null) return writeFilestat(ptr, vfsCall('statat', { dirfd: anchor, path: '.', follow: true }));
    return writeFilestat(ptr, (yield* fstat(descriptor(fd))));
  }),
  fd_filestat_set_size: (fd, len) => attempt(function* () {
    const found = descriptor(fd);
    if (found.kind === 'kfd') {
      if (len < 0n) throw new Errno(EINVAL);
      vfsCall('ftruncate', { kfd: found.kfd, size: len.toString() });
      return;
    }
    throw new Errno(EINVAL);
  }),
  fd_filestat_set_times: (fd, atim, mtim, flags) => attempt(function* () {
    const time = (value, set, now) => (flags & now) ? 'now' : (flags & set) ? { sec: Number(value / 1000000000n), nsec: Number(value % 1000000000n) } : 'omit';
    const atime = time(atim, 1, 2);
    const mtime = time(mtim, 4, 8);
    const sentinel = sentinelAnchor(fd);
    if (sentinel != null) {
      vfsCall('utimensat', { dirfd: sentinel, path: '.', atime, mtime, follow: false });
      return;
    }
    const found = descriptor(fd);
    if (found.preopen && found.kfd == null) {
      vfsCall('utimensat', { dirfd: OS_FD_ROOT, path: '.', atime, mtime, follow: false });
      return;
    }
    if (found.kind !== 'kfd' || found.kfd == null) throw new Errno(EINVAL);
    vfsCall('futimens', { kfd: found.kfd, atime, mtime });
  }),
  fd_pread: (fd, iovs, count, offset, nread) => attempt(function* () {
    const found = descriptor(fd);
    if (found.kind === 'unix-sock' || found.kind === 'inet-sock' || found.kind === 'arena-pipe-in' || found.kind === 'arena-pipe-out') throw new Errno(ESPIPE);
    if (found.kind === 'kfd') {
      if (offset < 0n) throw new Errno(EINVAL);
      let at = offset, total = 0;
      try {
        for (const [ptr, len] of iovecs(iovs, count)) {
          const data = kfdRead(found, at, len);
          bytes().set(data, ptr); total += data.length; at += BigInt(data.length);
          if (data.length < len) break;
        }
      } catch (error) {
        if (!total || !(error instanceof Errno)) throw error;
      }
      view().setUint32(nread, total, true);
      return;
    }
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
  fd_prestat_dir_name: (fd, ptr, len) => {
    if (!preopen(fd)) return EBADF;
    bytes().set(encoder.encode('/').subarray(0, len), ptr);
    return 0;
  },
  fd_pwrite: (fd, iovs, count, offset, nwritten) => attempt(function* () {
    const found = descriptor(fd);
    if (found.kind === 'unix-sock' || found.kind === 'inet-sock' || found.kind === 'arena-pipe-in' || found.kind === 'arena-pipe-out') throw new Errno(ESPIPE);
    if (found.kind === 'kfd') {
      if (offset < 0n) throw new Errno(EINVAL);
      let at = offset, total = 0;
      try {
        for (const [ptr, len] of iovecs(iovs, count)) {
          const wrote = kfdWrite(found, at, bytes().slice(ptr, ptr + len));
          total += wrote; at += BigInt(wrote);
          if (wrote < len) break;
        }
      } catch (error) {
        if (!total || !(error instanceof Errno)) throw error;
      }
      view().setUint32(nwritten, total, true);
      return;
    }
    let at = Number(offset), total = 0;
    for (const [ptr, len] of iovecs(iovs, count)) { total += yield* writeTo(found, at, bytes().slice(ptr, ptr + len)); at += len; }
    view().setUint32(nwritten, total, true);
  }),
  fd_read: (fd, iovs, count, nread) => attempt(function* () {
    const found = descriptor(fd);
    let total = 0;
    try {
      yield* exclusive(found, function* () {
        const vectors = iovecs(iovs, count);
        if (found.kind === 'unix-sock') {
          const want = vectors.reduce((sum, [, len]) => sum + len, 0);
          const data = sockReadBytes(found, want);
          let off = 0;
          for (const [ptr, len] of vectors) {
            if (off >= data.length) break;
            const take = Math.min(len, data.length - off);
            bytes().set(data.subarray(off, off + take), ptr);
            off += take;
          }
          total = off;
          return;
        }
        for (const [ptr, len] of vectors) {
          if (found.kind === 'kfd') {
            const data = kfdRead(found, null, len);
            bytes().set(data, ptr); total += data.length;
            if (data.length < len) break;
            continue;
          }
          const at = found.pos ?? 0;
          const data = yield* readFrom(found, at, len);
          bytes().set(data, ptr); total += data.length;
          if (!STDIO.has(found.kind)) found.pos = isByteDevice(found.device) ? 0 : at + data.length;
          if (data.length < len) break;
          if (['pipe-in', 'arena-pipe-in', 'tty'].includes(found.kind) && total > 0 && found.pipe.queued === 0) break;
          if (found.kind === 'pty' && total > 0 && !ptyCall(found, 'poll', { writing: false }).nbytes) break;
        }
      });
    } catch (error) {
      if (found.kind !== 'kfd' || !total || !(error instanceof Errno)) throw error;
    }
    view().setUint32(nread, total, true);
  }),
  fd_readdir: (fd, buf, len, cookie, used) => attempt(function* () {
    let entries;
    const anchor = sentinelAnchor(fd);
    const found = anchor == null ? descriptor(fd) : null;
    const openAnchor = anchor ?? (found.preopen && found.kfd == null ? OS_FD_ROOT : null);
    if (openAnchor != null) {
      const opened = vfsCall('openat', { dirfd: openAnchor, path: '.', oflags: O_RDONLY | O_DIRECTORY, mode: 0, cloexec: true });
      try {
        entries = vfsCall('readdir', { kfd: opened.kfd }).entries;
      } finally {
        vfsCall('close', { kfd: opened.kfd });
      }
    } else if (found.kind === 'kfd' && found.isDir) {
      entries = vfsCall('readdir', { kfd: found.kfd }).entries;
      try {
        const dir = vfsCall('readlinkat', { dirfd: OS_FD_ROOT, path: `/proc/self/fd/${found.kfd}` }).target;
        entries = procFdDirectory(dir) ?? entries;
      } catch { /* procfs may be absent in this namespace */ }
    } else {
      throw new Errno(ENOTDIR);
    }
    const all = [{ name: '.', ino: 0, type: DIRECTORY }, { name: '..', ino: 0, type: DIRECTORY }, ...entries];
    const out = [];
    let total = 0;
    const wireType = t => typeof t === 'number' ? t : ({
      dir: DIRECTORY,
      file: REGULAR_FILE,
      symlink: SYMBOLIC_LINK,
      char: CHARACTER_DEVICE,
      socket: SOCKET_STREAM,
      dgram: SOCKET_DGRAM,
    }[t] ?? UNKNOWN);
    for (let i = Number(cookie); i < all.length && total < len; i++) {
      const entry = all[i], name = encoder.encode(entry.name);
      const record = new Uint8Array(24 + name.length), v = new DataView(record.buffer);
      v.setBigUint64(0, BigInt(i + 1), true);
      v.setBigUint64(8, BigInt(entry.ino ?? 0), true);
      v.setUint32(16, name.length, true);
      v.setUint8(20, wireType(entry.type));
      record.set(name, 24);
      out.push(record); total += record.length;
    }
    let at = buf;
    for (const record of out) { const part = record.subarray(0, Math.min(record.length, buf + len - at)); bytes().set(part, at); at += part.length; }
    view().setUint32(used, at - buf, true);
  }),
  fd_renumber: (from, to) => attempt(function* () {
    const found = descriptor(from);
    if (to < 0 || to >= FD_MAX) throw new Errno(EBADF);
    if (from === to) return;
    if (fds.has(to)) yield* uninstall(to);
    fds.set(to, found);
    fds.delete(from);
    if (cloexec.delete(from)) cloexec.add(to);
  }),
  fd_seek: (fd, offset, whence, ptr) => attempt(function* () {
    const found = descriptor(fd);
    if (found.kind === 'kfd') {
      if (found.isDir || found.pathOnly) throw new Errno(EBADF);
      yield* exclusive(found, function* () {
        if (isByteDevice(found.device)) {
          view().setBigUint64(ptr, 0n, true);
          return;
        }
        const result = vfsCall('seek', { kfd: found.kfd, offset: offset.toString(), whence });
        view().setBigUint64(ptr, BigInt(result.pos), true);
      });
      return;
    }
    if (found.kind !== 'file') throw new Errno(ESPIPE);
    yield* exclusive(found, function* () {
      if (isByteDevice(found.device)) {
        found.pos = 0;
        view().setBigUint64(ptr, 0n, true);
        return;
      }
      if (whence < 0 || whence > 2) throw new Errno(EINVAL);
      const base = whence === 0 ? 0 : whence === 1 ? found.pos : (found.size ?? 0);
      const pos = base + Number(offset);
      if (pos < 0) throw new Errno(EINVAL);
      found.pos = pos;
      view().setBigUint64(ptr, BigInt(pos), true);
    });
  }),
  fd_tell: (fd, ptr) => attempt(function* () {
    const found = descriptor(fd);
    if (found.kind === 'kfd') {
      if (found.isDir || found.pathOnly) throw new Errno(EBADF);
      yield* exclusive(found, function* () {
        if (isByteDevice(found.device)) {
          view().setBigUint64(ptr, 0n, true);
          return;
        }
        const result = vfsCall('seek', { kfd: found.kfd, offset: '0', whence: 1 });
        view().setBigUint64(ptr, BigInt(result.pos), true);
      });
      return;
    }
    if (found.kind !== 'file') throw new Errno(ESPIPE);
    yield* exclusive(found, function* () {
      view().setBigUint64(ptr, BigInt(found.pos ?? 0), true);
    });
  }),
  fd_write: (fd, iovs, count, nwritten) => attempt(function* () {
    const found = descriptor(fd);
    let total = 0;
    try {
      yield* exclusive(found, function* () {
        const vectors = iovecs(iovs, count);
        if (found.kind === 'kfd' && !found.writable && !vectors.length) throw new Errno(EBADF);
        if (found.kind === 'unix-sock' && vectors.length > 1) {
          const length = vectors.reduce((sum, [, len]) => sum + len, 0);
          const data = new Uint8Array(length), mem = bytes();
          let at = 0;
          for (const [ptr, len] of vectors) {
            if (ptr + len > mem.length) throw new Errno(ERRNO.EFAULT);
            data.set(mem.subarray(ptr, ptr + len), at); at += len;
          }
          total = sockWriteBytes(found, data);
          return;
        }
        if ((found.kind === 'pipe-out' || found.kind === 'arena-pipe-out') && vectors.length > 1) {
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
          if (found.kind === 'kfd') {
            const wrote = kfdWrite(found, null, data);
            total += wrote;
            if (wrote < len) break;
            continue;
          }
          if (found.kind !== 'file') {
            const w = yield* writeTo(found, 0, data);
            total += w;
            if (w < data.length) break;
            continue;
          }
          const at = found.append ? (found.size ?? 0) : (found.pos ?? 0);
          total += yield* writeTo(found, at, data);
          found.pos = isByteDevice(found.device) ? 0 : at + len;
        }
      });
    } catch (error) {
      if (!total || !(error instanceof Errno) || (found.kind !== 'kfd' && ![ERRNO.EINTR, ERRNO.EPIPE, ERRNO.EAGAIN].includes(error.errno))) throw error;
    }
    view().setUint32(nwritten, total, true);
  }),
  path_create_directory: (fd, ptr, len) => attempt(function* () {
    const raw = string(ptr, len);
    vfsCall('mkdirat', { dirfd: resolveAnchorForPath(fd, raw), path: raw, mode: 0o777 });
  }),
  path_filestat_get: (fd, flags, ptr, len, out) => attempt(function* () {
    const raw = string(ptr, len);
    const anchor = resolveAnchorForPath(fd, raw);
    const info = procInfo(anchor, raw);
    if (info) return writeFilestat(out, info.stat ?? vfsCall('statat', { dirfd: OS_FD_ROOT, path: info.path, follow: true }));
    const procEntry = resolveProcFd(anchor, raw);
    if (procEntry) {
      if (!procEntry.found) throw new Errno(ENOENT);
      if ((flags & FOLLOW) !== 0) return writeFilestat(out, statOf(procEntry.found));
      if (procEntry.found.kind === 'kfd' && procEntry.found.kfd != null) {
        return writeFilestat(out, vfsCall('statat', { dirfd: OS_FD_ROOT, path: `/proc/self/fd/${procEntry.found.kfd}`, follow: false }));
      }
      const targetStr = linkTextFor(procEntry.found);
      return writeFilestat(out, { dev: 0, ino: procEntry.guestFd, filetype: SYMBOLIC_LINK, mode: 0o120700, nlink: 1, size: targetStr.length });
    }
    const st = vfsCall('statat', { dirfd: anchor, path: raw, follow: (flags & FOLLOW) !== 0 });
    return writeFilestat(out, st);
  }),
  path_filestat_set_times: (fd, flags, ptr, len, atim, mtim, fst) => attempt(function* () {
    const raw = string(ptr, len);
    const time = (value, set, now) => (fst & now) ? 'now' : (fst & set) ? { sec: Number(value / 1000000000n), nsec: Number(value % 1000000000n) } : 'omit';
    vfsCall('utimensat', {
      dirfd: resolveAnchorForPath(fd, raw),
      path: raw,
      atime: time(atim, 1, 2),
      mtime: time(mtim, 4, 8),
      follow: (flags & FOLLOW) !== 0,
    });
  }),
  path_link: (fd, flags, ptr, len, fd2, ptr2, len2) => attempt(function* () {
    const oldpath = string(ptr, len), newpath = string(ptr2, len2);
    vfsCall('linkat', {
      olddirfd: resolveAnchorForPath(fd, oldpath),
      oldpath,
      newdirfd: resolveAnchorForPath(fd2, newpath),
      newpath,
      follow: (flags & FOLLOW) !== 0,
    });
  }),
  path_open: (fd, dirflags, ptr, len, oflags, base, inheriting, fdflags, out) => attempt(function* () {
    const raw = string(ptr, len);
    view().setUint32(out, openPathAt(fd, raw, dirflags, oflags, base, fdflags), true);
  }),
  path_readlink: (fd, ptr, len, buf, bufLen, used) => attempt(function* () {
    const raw = string(ptr, len);
    const anchor = resolveAnchorForPath(fd, raw);
    if (procInfo(anchor, raw)) throw new Errno(EINVAL);
    const procEntry = resolveProcFd(anchor, raw);
    let targetStr;
    if (procEntry) {
      if (!procEntry.found) throw new Errno(ENOENT);
      targetStr = linkTextFor(procEntry.found);
    } else {
      targetStr = vfsCall('readlinkat', { dirfd: anchor, path: raw }).target;
    }
    const target = encoder.encode(targetStr);
    const part = target.subarray(0, bufLen);
    bytes().set(part, buf);
    view().setUint32(used, part.length, true);
  }),
  path_remove_directory: (fd, ptr, len) => attempt(function* () {
    const raw = string(ptr, len);
    vfsCall('unlinkat', { dirfd: resolveAnchorForPath(fd, raw), path: raw, removedir: true });
  }),
  path_rename: (fd, ptr, len, fd2, ptr2, len2) => attempt(function* () {
    const oldpath = string(ptr, len), newpath = string(ptr2, len2);
    vfsCall('renameat', {
      olddirfd: resolveAnchorForPath(fd, oldpath),
      oldpath,
      newdirfd: resolveAnchorForPath(fd2, newpath),
      newpath,
      flags: 0,
    });
  }),
  path_symlink: (ptr, len, fd, ptr2, len2) => attempt(function* () {
    const target = string(ptr, len), linkpath = string(ptr2, len2);
    vfsCall('symlinkat', { target, newdirfd: resolveAnchorForPath(fd, linkpath), linkpath });
  }),
  path_unlink_file: (fd, ptr, len) => attempt(function* () {
    const raw = string(ptr, len);
    vfsCall('unlinkat', { dirfd: resolveAnchorForPath(fd, raw), path: raw, removedir: false });
  }),
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
      const seenNotify = sockNotify ? Atomics.load(sockNotify, 0) : 0;
      let hasSocketLike = false;
      for (const sub of subscriptions) {
        const found = fds.get(sub.fd); let error = 0, nbytes = 0, hangup = false;
        if (sub.type === 0) { if (performance.now() < sub.until) continue; }
        else if (sub.type !== 1 && sub.type !== 2) error = EINVAL;
        else if (!found) error = EBADF;
        else if (found.kind === 'tty' && ttyControl.hungup) hangup = true;
        else if (found.kind === 'pty') {
          hasSocketLike = true;
          try {
            const result = ptyCall(found, 'poll', { writing: sub.type === 2 });
            if (!result.ready) continue;
            nbytes = result.nbytes; hangup = result.hangup;
          } catch (err) { error = err instanceof Errno ? err.errno : EIO; }
        }
        else if (found.device?.startsWith('gui:')) {
          hasSocketLike = true;
          try {
            nbytes = vfsCall('gui_poll', { kfd: found.kfd, writing: sub.type === 2 }).ready;
            if (!nbytes) continue;
          } catch (err) { error = err instanceof Errno ? err.errno : EIO; }
        }
        else if (found.kind === 'unix-sock') {
          hasSocketLike = true;
          const pollSabStream = () => {
            if (sub.type === 1) {
              hangup = found.rxRing.wrClosed || found.rxRing.rdClosed;
              const hasData = found.rxRing.queued > 0 || found.rxRing.hasAncillary;
              if (!hasData && !hangup) return false;
              nbytes = found.rxRing.queued;
              return true;
            }
            hangup = found.txRing.rdClosed || found.txRing.wrClosed;
            if (!hangup && !found.txRing.room) return false;
            nbytes = hangup ? 0 : found.txRing.room;
            return true;
          };
          if (found.sockType === SOCK_STREAM && found.rxRing && found.txRing) {
            if (!pollSabStream()) continue;
          } else {
            try {
              const result = sockCall('poll', { sockId: found.sockId, writing: sub.type === 2 });
              if (found.sockType === SOCK_STREAM && sockArena && (result.txSlot || result.rxSlot)) {
                found.txSlot = result.txSlot ?? null;
                found.rxSlot = result.rxSlot ?? null;
                attachSockRings(found);
                if (found.rxRing && found.txRing) {
                  if (!pollSabStream()) continue;
                } else {
                  if (!result.ready) continue;
                  nbytes = result.nbytes ?? 0; hangup = !!result.hangup;
                }
              } else {
                if (!result.ready) continue;
                nbytes = result.nbytes ?? 0; hangup = !!result.hangup;
              }
            } catch (err) { error = err instanceof Errno ? err.errno : EIO; }
          }
        }
        else if (found.kind === 'inet-sock') {
          error = ERRNO.ENOTCONN;
        }
        else if (sub.type === 1 && ['pipe-in', 'arena-pipe-in', 'tty'].includes(found.kind)) {
          if (found.kind === 'arena-pipe-in') hasSocketLike = true;
          if (found.pipe.empty) continue;
          nbytes = found.pipe.queued; hangup = found.pipe.writerGone;
        } else if (sub.type === 2 && ['pipe-out', 'arena-pipe-out'].includes(found.kind)) {
          if (found.kind === 'arena-pipe-out') hasSocketLike = true;
          hangup = found.pipe.readerGone;
          if (!hangup && !found.pipe.room) continue;
          nbytes = found.pipe.room;
        } else if (sub.type === 1 && ['out', 'pipe-out', 'arena-pipe-out'].includes(found.kind) || sub.type === 2 && ['in', 'pipe-in', 'arena-pipe-in'].includes(found.kind)) error = EBADF;
        const at = output + ready++ * 32;
        v.setBigUint64(at, sub.userdata, true); v.setUint16(at + 8, error, true); v.setUint8(at + 10, sub.type);
        v.setBigUint64(at + 16, BigInt(nbytes), true); v.setUint16(at + 24, hangup ? 1 : 0, true);
      }
      if (ready) { v.setUint32(events, ready, true); return; }
      const until = Math.min(...subscriptions.map(sub => sub.until));
      const waitMs = Math.max(0, Math.min(until - performance.now(), 10));
      if (waitMs > 0) {
        if (hasSocketLike && sockNotify) {
          Atomics.wait(sockNotify, 0, seenNotify, waitMs);
        } else {
          sleepUntil(performance.now() + waitMs);
        }
      }
    }
  }),
  proc_exit: code => { throw new Exit(code); },
  proc_raise: signal => attempt(function* () {
    if (signal === 19) hostErrno(host('kill', { pid: process.pid, signal }));
    else { const error = signals.queue(signal); if (error) throw new Errno(error); }
    dispatchSignals(); pause();
  }),
  random_get: (ptr, len) => { for (let at = 0; at < len; at += 65536) bytes().set(crypto.getRandomValues(new Uint8Array(Math.min(65536, len - at))), ptr + at); return 0; },
  sched_yield: () => 0,
  // ---- Phase 10a (`#86`): WASI preview1 socket operations ----
  sock_accept: (fd, fdflags, roFd) => {
    pause();
    try {
      const found = descriptor(fd);
      if (found.kind === 'inet-sock') throw new Errno(ERRNO.EOPNOTSUPP);
      if (found.kind !== 'unix-sock') throw new Errno(ERRNO.ENOTSOCK);
      const outPtr = checkWritable(roFd, 4);
      const nbNew = !!(fdflags & FDFLAG_NONBLOCK);
      for (;;) {
        pause(true);
        const targetFd = lowest();
        const nb = nonblocking(found);
        const seen = sockNotify ? Atomics.load(sockNotify, 0) : 0;
        const res = sockCall('accept', { sockId: found.sockId });
        if (res.wouldBlock) {
          if (nb) throw new Errno(ERRNO.EAGAIN);
          waitSockNotify(seen, 20);
          continue;
        }
        const desc = {
          kind: 'unix-sock',
          sockId: res.sockId,
          sockType: found.sockType,
          txSlot: res.txSlot ?? null,
          rxSlot: res.rxSlot ?? null,
          peerCred: res.peerCred ?? null,
        };
        attachSockRings(desc);
        install(targetFd, desc, true);
        if (nbNew) sockCall('set_nonblock', { sockId: res.sockId, nonblock: true });
        view().setUint32(outPtr, targetFd, true);
        return 0;
      }
    } catch (err) { if (!(err instanceof Errno)) throw err; return err.errno; }
  },
  sock_recv: (fd, riDataPtr, riDataLen, riFlags, roDataLenPtr, roFlagsPtr) => {
    pause();
    try {
      const MAX_SOCK_IO_BYTES = 16 * 1024 * 1024;
      const flags16 = riFlags & 0xffff;
      if (flags16 & ~3) throw new Errno(EINVAL);
      const found = descriptor(fd);
      if (found.kind === 'inet-sock') throw new Errno(ERRNO.ENOTCONN);
      if (found.kind !== 'unix-sock') throw new Errno(ERRNO.ENOTSOCK);
      const vectors = iovecs(riDataPtr, riDataLen);
      const outLenPtr = checkWritable(roDataLenPtr, 4);
      const outFlagsPtr = checkWritable(roFlagsPtr, 2);
      const memLen = bytes().length;
      let want = 0;
      for (const [ptr, len] of vectors) {
        if (len > 0 && (ptr > memLen || ptr + len > memLen)) throw new Errno(ERRNO.EFAULT);
        want = Math.min(MAX_SOCK_IO_BYTES, want + len);
      }
      const peek = !!(flags16 & 1);
      const waitall = !!(flags16 & 2) && !peek;
      const msgFlags = peek ? MSG_PEEK : 0;
      let collected = new Uint8Array(0);
      if (want > 0) {
        if (!waitall) {
          const res = sockRecvMsg(found, want, 0, msgFlags);
          for (const spec of res.fds) disposeUninstalledFd(spec);
          collected = res.data;
        } else {
          const chunks = [];
          let got = 0;
          while (got < want) {
            let res;
            try {
              res = sockRecvMsg(found, want - got, 0, 0);
            } catch (err) {
              if (got > 0 && err instanceof Errno && (err.errno === ERRNO.EAGAIN || err.errno === ERRNO.EINTR)) break;
              throw err;
            }
            for (const spec of res.fds) disposeUninstalledFd(spec);
            if (!res.data.length) break;
            chunks.push(res.data);
            got += res.data.length;
          }
          collected = new Uint8Array(got);
          let pos = 0;
          for (const c of chunks) { collected.set(c, pos); pos += c.length; }
        }
      }
      let off = 0;
      const mem = bytes();
      for (const [ptr, len] of vectors) {
        if (off >= collected.length) break;
        const take = Math.min(len, collected.length - off);
        if (ptr > mem.length || ptr + take > mem.length) throw new Errno(ERRNO.EFAULT);
        mem.set(collected.subarray(off, off + take), ptr);
        off += take;
      }
      view().setUint32(outLenPtr, off, true);
      view().setUint16(outFlagsPtr, 0, true);
      return 0;
    } catch (err) { if (!(err instanceof Errno)) throw err; return err.errno; }
  },
  sock_send: (fd, siDataPtr, siDataLen, siFlags, roDataLenPtr) => {
    pause();
    try {
      const MAX_SOCK_IO_BYTES = 16 * 1024 * 1024;
      if ((siFlags & 0xffff) !== 0) throw new Errno(EINVAL);
      const found = descriptor(fd);
      if (found.kind === 'inet-sock') throw new Errno(ERRNO.ENOTCONN);
      if (found.kind !== 'unix-sock') throw new Errno(ERRNO.ENOTSOCK);
      const vectors = iovecs(siDataPtr, siDataLen);
      const outLenPtr = checkWritable(roDataLenPtr, 4);
      const mem = bytes();
      let totalLen = 0;
      for (const [ptr, len] of vectors) {
        if (len > 0 && (ptr > mem.length || ptr + len > mem.length)) throw new Errno(ERRNO.EFAULT);
        totalLen = Math.min(MAX_SOCK_IO_BYTES, totalLen + len);
      }
      const payload = new Uint8Array(totalLen);
      let at = 0;
      for (const [ptr, len] of vectors) {
        if (at >= totalLen) break;
        const take = Math.min(len, totalLen - at);
        if (ptr > mem.length || ptr + take > mem.length) throw new Errno(ERRNO.EFAULT);
        payload.set(mem.subarray(ptr, ptr + take), at);
        at += take;
      }
      const sent = sockSendMsg(found, payload, [], null, MSG_NOSIGNAL);
      view().setUint32(outLenPtr, sent, true);
      return 0;
    } catch (err) { if (!(err instanceof Errno)) throw err; return err.errno; }
  },
  sock_shutdown: (fd, how) => {
    pause();
    try {
      const sd = how & 0xff;
      let posixHow;
      if (sd === 1) posixHow = 0;      // SHUT_RD
      else if (sd === 2) posixHow = 1; // SHUT_WR
      else if (sd === 3) posixHow = 2; // SHUT_RDWR
      else throw new Errno(EINVAL);
      const found = descriptor(fd);
      if (found.kind === 'inet-sock') throw new Errno(ERRNO.ENOTCONN);
      if (found.kind !== 'unix-sock') throw new Errno(ERRNO.ENOTSOCK);
      sockCall('shutdown', { sockId: found.sockId, how: posixHow });
      return 0;
    } catch (err) { if (!(err instanceof Errno)) throw err; return err.errno; }
  },
};

const preview1 = new Proxy(wasi, {
  get: (target, name) => {
    const call = target[name] ?? (() => ENOSYS);
    return (...args) => { pause(); return call(...args); };
  },
});

// ---- Signals ----

const KILLED = 0x100;
let control = null;
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

const preopen = fd => !!fds.get(fd)?.preopen;
let channel = null;
let seatChannel = null;
const replyChannel = buffer => ({ state: new Int32Array(buffer, 0, 2), data: new Uint8Array(buffer, 8) });

function host(type, args, response = channel) {
  if (!channel) throw new Errno(ENOSYS);
  flush();
  Atomics.store(response.state, 0, 0);
  postMessage({ host: { type, args, replyBuffer: response === channel ? undefined : response.state.buffer } });
  inHost = true;
  try {
    while (Atomics.load(response.state, 0) === 0) {
      if (Atomics.wait(response.state, 0, 0, 200) === 'timed-out') pause();
    }
    return JSON.parse(decoder.decode(response.data.slice(0, Atomics.load(response.state, 1))));
  } finally { inHost = false; }
}
const hostErrno = reply => { if (reply?.errno) throw new Errno(ERRNO[reply.errno] ?? EIO); return reply; };

function waitChild(pid, nohang, options = 0) {
  for (;;) {
    const child = hostErrno(host('join', { pid, nohang: true, options }));
    if (!child.nothing || nohang) return child;
    dispatchSignals(true);
    sleepUntil(performance.now() + 50);
  }
}

const lines = (ptr, len) => string(ptr, len).split(/[\n\r]/).filter(line => line !== '');
let snapshots = new Map(), saved = 0;

function execve(file, argv, env, search = !file.includes('/')) {
  hostErrno(host('exec', { file, argv, env, search: !!search }));
  throw new Replaced();
}

function* diagnostic(text) {
  try {
    const found = descriptor(2), data = encoder.encode(text);
    yield* exclusive(found, function* () {
      if (found.kind === 'kfd') { kfdWrite(found, null, data); return; }
      const at = found.kind === 'file' ? (found.append ? (found.size ?? 0) : (found.pos ?? 0)) : 0;
      const count = yield* writeTo(found, at, data);
      if (found.kind === 'file') found.pos = at + count;
    });
  } catch { /* stderr may be closed or unwritable; the process still exits */ }
}

function* execOrExit(name, argv, env) {
  try { execve(name, argv, env); } catch (err) {
    if (!(err instanceof Errno)) throw err;
    yield* diagnostic(`${name}: ${STRERROR[err.errno] ?? 'cannot execute'}\n`);
    flush();
    throw new Exit(err.errno === ENOENT ? 127 : 126);
  }
}

function duplicateDescriptor(found, closeOnExec = false) {
  if (kernelDescriptor(found)) {
    const dupKfd = vfsCall('dup', { kfd: found.kfd }).kfd;
    if (closeOnExec) vfsCall('set_cloexec', { kfd: dupKfd, cloexec: true });
    return { ...found, kfd: dupKfd, refs: 0 };
  }
  return found;
}

const wasixCalls = {
  ...wasi,
  proc_exit2: wasi.proc_exit,
  proc_signals_sizes_get: ptr => { view().setUint32(ptr, 0, true); return 0; },
  proc_signals_get: () => 0,
  path_open2: (fd, dirflags, ptr, len, oflags, base, inheriting, fdflags, extra, out) => {
    if (extra & ~1) return EINVAL;
    return attempt(function* () {
      const raw = string(ptr, len);
      const num = openPathAt(fd, raw, dirflags, oflags, base, fdflags, false, 0o666, (extra & 1) ? O_CLOEXEC : 0);
      view().setUint32(out, num, true);
    });
  },
  fd_fdflags_get: (fd, ptr) => attempt(function* () {
    const found = descriptor(fd);
    const isClo = kernelDescriptor(found) ? vfsCall('is_cloexec', { kfd: found.kfd }).cloexec : cloexec.has(fd);
    view().setUint16(ptr, isClo ? 1 : 0, true);
  }),
  fd_fdflags_set: (fd, flags) => attempt(function* () {
    const found = descriptor(fd);
    if (flags & ~1) throw new Errno(EINVAL);
    const setClo = (flags & 1) !== 0;
    if (kernelDescriptor(found)) vfsCall('set_cloexec', { kfd: found.kfd, cloexec: setClo });
    if (setClo) cloexec.add(fd); else cloexec.delete(fd);
  }),
  tty_get: ptr => {
    const findPty = () => {
      for (const n of [0, 1, 2]) {
        const d = fds.get(n);
        if (d?.kind === 'pty' && !d.master) return d;
      }
      for (const d of fds.values()) if (d?.kind === 'pty' && !d.master) return d;
      return null;
    };
    const found = findPty();
    if (found) {
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
    let found = null;
    for (const n of [0, 1, 2]) {
      const d = fds.get(n);
      if (d?.kind === 'pty' && !d.master) { found = d; break; }
    }
    if (!found) for (const d of fds.values()) if (d?.kind === 'pty' && !d.master) { found = d; break; }
    if (!found && !ttyState) throw new Errno(ERRNO.ENOTTY);
    const target = found ?? terminalFd(0);
    const v = view();
    ttyAccess(22, target);
    ttyCall(target, 'wasix', { echo: !!v.getUint8(ptr + 19), canonical: !!v.getUint8(ptr + 20), lineFeeds: !!v.getUint8(ptr + 21) });
  }),
  fd_renumber: (from, to) => attempt(function* () {
    const found = descriptor(from);
    if (to < 0 || to >= FD_MAX) throw new Errno(EBADF);
    if (from === to) return;
    const duped = duplicateDescriptor(found, false);
    if (fds.has(to)) yield* uninstall(to);
    install(to, duped);
  }),
  fd_dup: (fd, out) => attempt(function* () {
    const found = descriptor(fd), number = lowest();
    install(number, duplicateDescriptor(found, false));
    view().setUint32(out, number, true);
  }),
  fd_dup2: (fd, min, closeOnExec, out) => attempt(function* () {
    const found = descriptor(fd), number = lowest(min);
    install(number, duplicateDescriptor(found, !!closeOnExec));
    if (closeOnExec) cloexec.add(number);
    view().setUint32(out, number, true);
  }),
  fd_pipe: (readEnd, writeEnd) => attempt(function* () {
    if (typeof SharedArrayBuffer !== 'function') throw new Errno(ENOSYS);
    const [r, w] = lowestPair();
    if (sockArena && channel) {
      const { slot, gen } = sockCall('pipe_alloc');
      install(r, { kind: 'arena-pipe-in', slot, gen, pipe: new ArenaPipe(sockArena, slot, gen, process.pid, sockNotify) }, true);
      install(w, { kind: 'arena-pipe-out', slot, gen, pipe: new ArenaPipe(sockArena, slot, gen, process.pid, sockNotify) }, true);
      view().setUint32(readEnd, r, true);
      view().setUint32(writeEnd, w, true);
      return;
    }
    const pipe = new Pipe(pipeBuffer(), process.pid);
    install(r, { kind: 'pipe-in', pipe });
    install(w, { kind: 'pipe-out', pipe });
    view().setUint32(readEnd, r, true);
    view().setUint32(writeEnd, w, true);
  }),
  getcwd: (ptr, lengthPtr) => attempt(function* () {
    const cwd = encoder.encode(vfsCall('getcwd', {}).cwd);
    const room = view().getUint32(lengthPtr, true);
    view().setUint32(lengthPtr, cwd.length + 1, true);
    if (cwd.length >= room) throw new Errno(ERRNO.ERANGE);
    bytes().set(cwd, ptr);
    bytes()[ptr + cwd.length] = 0;
  }),
  chdir: (ptr, len) => attempt(function* () {
    const p = string(ptr, len);
    if (!p) throw new Errno(ENOENT);
    vfsCall('chdir', { path: p });
  }),
  proc_id: ptr => { view().setUint32(ptr, process.pid, true); return 0; },
  proc_parent: (pid, ptr) => attempt(function* () {
    const found = hostErrno(host('getpid', { pid }));
    view().setUint32(ptr, found.ppid, true);
  }),
  proc_signal: (pid, signal) => attempt(function* () { hostErrno(host('kill', { pid, signal })); pause(); }),
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
    const executable = string(name, nameLen);
    execve(executable, lines(args, argsLen), search && PATH ? [...env.filter(entry => !entry.startsWith('PATH=')), `PATH=${PATH}`] : env, !!search && !executable.includes('/'));
  }),
  proc_exec4: (name, nameLen, args, argsLen, envs, envsLen, search, path, pathLen) => attempt(function* () {
    const argv = pointerStrings(args, argsLen), env = pointerStrings(envs, envsLen);
    const PATH = string(path, pathLen), executable = string(name, nameLen);
    execve(executable, argv, search && PATH ? [...env.filter(entry => !entry.startsWith('PATH=')), `PATH=${PATH}`] : env, !!search && !executable.includes('/'));
  }),
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
  callback_signal: (ptr, len) => { signals.callback = string(ptr, len); },
  thread_id: ptr => { view().setUint32(ptr, 1, true); return 0; },
  thread_signal: (tid, signal) => {
    if (tid !== 1) return ERRNO.ESRCH;
    const error = signals.queue(signal); dispatchSignals(); pause(); return error;
  },
  thread_exit: code => { throw new Exit(code); },
  futex_wait: (addr, expected, timeout, woken) => { view().setUint8(woken, 0); return 0; },
  futex_wake: (addr, woken) => { view().setUint8(woken, 0); return 0; },
  futex_wake_all: (addr, woken) => { view().setUint8(woken, 0); return 0; },
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
  // ---- Phase 10a (`#86`): WASIX outbound stream routing via `/run/netd.sock` ----
  sock_open: (af, ty, pt, roFd) => {
    try {
      const af8 = af & 0xff, ty8 = ty & 0xff, pt32 = pt >>> 0;
      const outPtr = checkWritable(roFd, 4);
      if (af8 === 1 || af8 === 2) { // WASIX_AF_INET4 / WASIX_AF_INET6
        if (ty8 === 1 || ty8 === 3 || pt32 === 1 || pt32 === 17 || pt32 === 58) {
          throw new Errno(ERRNO.EPROTONOSUPPORT);
        }
        if (ty8 !== 2) throw new Errno(ERRNO.EPROTOTYPE); // only SOCK_STREAM
        if (pt32 !== 0 && pt32 !== 6) throw new Errno(ERRNO.EPROTONOSUPPORT);
        const fd = lowest();
        install(fd, { kind: 'inet-sock', af: af8, sockType: SOCK_STREAM, proto: pt32 || 6, flags: descriptorFlags() }, true);
        view().setUint32(outPtr, fd, true);
        return 0;
      }
      if (af8 === 3) { // WASIX_AF_UNIX
        if (pt32 !== 0) throw new Errno(ERRNO.EPROTONOSUPPORT);
        const baseType = ty8 === 2 ? SOCK_STREAM : ty8 === 1 ? SOCK_DGRAM : ty8 === 4 ? SOCK_SEQPACKET : 0;
        if (!baseType) throw new Errno(ERRNO.EPROTOTYPE);
        const fd = lowest();
        const { sockId } = sockCall('create', { sockType: baseType });
        const desc = { kind: 'unix-sock', sockId, sockType: baseType, txSlot: null, rxSlot: null, txRing: null, rxRing: null, peerCred: null };
        install(fd, desc, true);
        view().setUint32(outPtr, fd, true);
        return 0;
      }
      throw new Errno(ERRNO.EAFNOSUPPORT);
    } catch (err) { if (!(err instanceof Errno)) throw err; return err.errno; }
  },
  sock_connect: (fd, addrPtr) => {
    try {
      const found = descriptor(fd);
      if (found.kind === 'unix-sock') throw new Errno(ERRNO.EISCONN);
      if (found.kind !== 'inet-sock') throw new Errno(ERRNO.ENOTSOCK);
      const raw = checkedSlice(addrPtr, 20);
      const decoded = decodeWasixAddrPort(raw);
      if (decoded.af !== found.af) throw new Errno(ERRNO.EAFNOSUPPORT);
      const nb = nonblocking(found);
      const connected = netdConnectOverUnix(decoded.host, decoded.port, nb);
      // Preserve POSIX dup() alias semantics & exact kernel socket refcounts: update every
      // fd slot aliasing `found` and acquire matching kernel refs for extra aliases.
      const aliasedFds = [];
      for (const [slotFd, desc] of fds.entries()) {
        if (desc === found) aliasedFds.push(slotFd);
      }
      if (aliasedFds.length > 1) {
        sockCall('hold', { sockId: connected.sockId, count: aliasedFds.length - 1 });
      }
      connected.refs = aliasedFds.length || 1;
      for (const slotFd of aliasedFds) fds.set(slotFd, connected);
      return 0;
    } catch (err) { if (!(err instanceof Errno)) throw err; return err.errno; }
  },
  sock_bind: (fd, _addrPtr) => {
    try {
      const found = descriptor(fd);
      if (found.kind === 'inet-sock' || found.kind === 'unix-sock') throw new Errno(ERRNO.EOPNOTSUPP);
      throw new Errno(ERRNO.ENOTSOCK);
    } catch (err) { if (!(err instanceof Errno)) throw err; return err.errno; }
  },
  sock_listen: (fd, _backlog) => {
    try {
      const found = descriptor(fd);
      if (found.kind === 'inet-sock' || found.kind === 'unix-sock') throw new Errno(ERRNO.EOPNOTSUPP);
      throw new Errno(ERRNO.ENOTSOCK);
    } catch (err) { if (!(err instanceof Errno)) throw err; return err.errno; }
  },
  sock_send_to: (fd) => {
    try {
      const found = descriptor(fd);
      if (found.kind === 'inet-sock' || found.kind === 'unix-sock') throw new Errno(ERRNO.EPROTONOSUPPORT);
      throw new Errno(ERRNO.ENOTSOCK);
    } catch (err) { if (!(err instanceof Errno)) throw err; return err.errno; }
  },
  sock_recv_from: (fd) => {
    try {
      const found = descriptor(fd);
      if (found.kind === 'inet-sock' || found.kind === 'unix-sock') throw new Errno(ERRNO.EPROTONOSUPPORT);
      throw new Errno(ERRNO.ENOTSOCK);
    } catch (err) { if (!(err instanceof Errno)) throw err; return err.errno; }
  },
  sock_addr_resolve: (hostPtr, hostLen, port, _hintsPtr, resultsPtr, resultsLen, outCountPtr) => {
    try {
      const host = checkedString(hostPtr, hostLen).trim();
      const outPtr = checkWritable(outCountPtr, 4);
      const cap = resultsLen >>> 0;
      const addrs = parseIpLiteralToWasix(host) ?? netdResolveOverUnix(host, port & 0xffff);
      const count = Math.min(addrs.length, cap);
      if (count > 0) checkWritable(resultsPtr, count * 18);
      const mem = bytes();
      for (let i = 0; i < count; i++) {
        mem.set(addrs[i], resultsPtr + i * 18);
      }
      view().setUint32(outPtr, count, true);
      return 0;
    } catch (err) { if (!(err instanceof Errno)) throw err; return err.errno; }
  },
};

function decodeWasixAddrPort(buf) {
  if (buf.length < 20) throw new Errno(EINVAL);
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const tag = buf[0];
  const port = dv.getUint16(2, true);
  if (tag === 1) {
    return { af: 1, host: `${buf[4]}.${buf[5]}.${buf[6]}.${buf[7]}`, port };
  }
  if (tag === 2) {
    const segs = [];
    for (let i = 0; i < 8; i++) segs.push(dv.getUint16(4 + i * 2, true).toString(16));
    return { af: 2, host: segs.join(':'), port };
  }
  throw new Errno(ERRNO.EAFNOSUPPORT);
}

function encodeWasixIpBytes(ipStr) {
  const s = ipStr.trim();
  const v4 = /^(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})$/.exec(s);
  if (v4) {
    const octets = v4.slice(1).map(Number);
    if (octets.every(o => o >= 0 && o <= 255)) {
      const out = new Uint8Array(18);
      out[0] = 1;
      out[2] = octets[0]; out[3] = octets[1]; out[4] = octets[2]; out[5] = octets[3];
      return out;
    }
  }
  if (s.includes(':')) {
    const halves = s.split('::');
    if (halves.length <= 2) {
      const left = halves[0] ? halves[0].split(':') : [];
      const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
      const missing = 8 - left.length - right.length;
      if ((halves.length === 1 && missing === 0) || (halves.length === 2 && missing >= 0)) {
        const parts = [...left, ...Array(Math.max(0, missing)).fill('0'), ...right];
        if (parts.length === 8) {
          const out = new Uint8Array(18);
          const dv = new DataView(out.buffer);
          out[0] = 2;
          let ok = true;
          for (let i = 0; i < 8; i++) {
            const val = parseInt(parts[i], 16);
            if (!/^[0-9a-fA-F]{1,4}$/.test(parts[i]) || Number.isNaN(val)) { ok = false; break; }
            dv.setUint16(2 + i * 2, val, true);
          }
          if (ok) return out;
        }
      }
    }
  }
  return null;
}

function parseIpLiteralToWasix(host) {
  const encoded = encodeWasixIpBytes(host);
  return encoded ? [encoded] : null;
}

function encodeNetdControlFrame(obj) {
  const payload = encoder.encode(JSON.stringify(obj));
  if (payload.length === 0 || payload.length > 16384) throw new Errno(EINVAL);
  const frame = new Uint8Array(4 + payload.length);
  new DataView(frame.buffer).setUint32(0, payload.length, false);
  frame.set(payload, 4);
  return frame;
}

function netdSendAll(desc, data) {
  let off = 0;
  while (off < data.length) {
    const n = sockSendMsg(desc, data.subarray(off), [], null, MSG_NOSIGNAL);
    if (n <= 0) throw new Errno(ERRNO.EPIPE);
    off += n;
  }
}

function netdRecvExact(desc, len) {
  const out = new Uint8Array(len);
  let off = 0;
  while (off < len) {
    const res = sockRecvMsg(desc, len - off, 0, 0);
    for (const spec of res.fds) disposeUninstalledFd(spec);
    if (!res.data.length) throw new Errno(ERRNO.ECONNRESET);
    out.set(res.data, off);
    off += res.data.length;
  }
  return out;
}

function netdRecvControlResp(desc) {
  const hdr = netdRecvExact(desc, 4);
  const len = new DataView(hdr.buffer).getUint32(0, false);
  if (len === 0 || len > 16384) throw new Errno(EIO);
  const body = netdRecvExact(desc, len);
  try {
    return JSON.parse(decoder.decode(body));
  } catch {
    throw new Errno(EIO);
  }
}

function netdOpenAndHello() {
  const { sockId } = sockCall('create', { sockType: SOCK_STREAM });
  const desc = { kind: 'unix-sock', sockId, sockType: SOCK_STREAM, txSlot: null, rxSlot: null, txRing: null, rxRing: null, peerCred: null, flags: descriptorFlags() };
  try {
    for (;;) {
      pause(true);
      const seen = sockNotify ? Atomics.load(sockNotify, 0) : 0;
      try {
        const res = sockCall('connect', { sockId, path: '/run/netd.sock' });
        if (res.txSlot || res.rxSlot) {
          desc.txSlot = res.txSlot ?? null;
          desc.rxSlot = res.rxSlot ?? null;
          attachSockRings(desc);
        }
        if (res.peerCred) desc.peerCred = res.peerCred;
        break;
      } catch (err) {
        if (err instanceof Errno && err.errno === ERRNO.EAGAIN) {
          waitSockNotify(seen, 20);
          continue;
        }
        throw err;
      }
    }
    netdSendAll(desc, encodeNetdControlFrame({ op: 'hello', versions: [1] }));
    const welcome = netdRecvControlResp(desc);
    if (welcome?.kind === 'error') throw new Errno(ERRNO[welcome.errno] ?? EIO);
    if (welcome?.kind !== 'welcome') throw new Errno(ERRNO.EPROTONOSUPPORT);
    return desc;
  } catch (err) {
    try { sockCall('close', { sockId, count: 1 }); } catch {}
    throw err;
  }
}

function netdConnectOverUnix(host, port, nonblock) {
  const desc = netdOpenAndHello();
  try {
    netdSendAll(desc, encodeNetdControlFrame({
      op: 'connect',
      host,
      port,
      tls: 'off',
      mode: 'raw',
      timeout_ms: null,
    }));
    const resp = netdRecvControlResp(desc);
    if (resp?.kind === 'error') throw new Errno(ERRNO[resp.errno] ?? EIO);
    if (resp?.kind !== 'connected') throw new Errno(EIO);
    if (nonblock) sockCall('set_nonblock', { sockId: desc.sockId, nonblock: true });
    return desc;
  } catch (err) {
    try { sockCall('close', { sockId: desc.sockId, count: 1 }); } catch {}
    throw err;
  }
}

function netdResolveOverUnix(host, port) {
  const desc = netdOpenAndHello();
  try {
    netdSendAll(desc, encodeNetdControlFrame({ op: 'resolve', host, port }));
    const resp = netdRecvControlResp(desc);
    if (resp?.kind === 'error') throw new Errno(ERRNO[resp.errno] ?? EIO);
    if (resp?.kind !== 'resolved' || !Array.isArray(resp.addrs)) throw new Errno(EIO);
    const out = [];
    for (const a of resp.addrs) {
      const enc = encodeWasixIpBytes(String(a));
      if (enc) out.push(enc);
    }
    return out;
  } finally {
    try { sockCall('close', { sockId: desc.sockId, count: 1 }); } catch {}
  }
}

const wasix = new Proxy(wasixCalls, {
  get: (target, name) => {
    const call = target[name] ?? (() => ENOSYS);
    return (...args) => { pause(); return call(...args); };
  },
});

// ---- Fork & Spawn ----

function forkState({ exec = false, stdin = 'inherit', tty = null, dup2 = [] } = {}) {
  if (!shares) throw new Errno(ENOSYS);
  const ids = new Map(), descriptions = [], table = [];
  const inherited = new Map(fds), closes = new Set(cloexec);
  const inputAction = dup2.some(([, to]) => to === 0);
  const parentKfds = new Set();
  for (const found of fds.values()) {
    if (kernelDescriptor(found)) parentKfds.add(found.kfd);
  }
  const keepOpenKfds = new Set();
  for (const [from, to] of dup2) {
    if (!inherited.has(from)) throw new Errno(EBADF);
    const src = inherited.get(from);
    if (from !== to) inherited.set(to, kernelDescriptor(src) ? { ...src, dupSource: src.kfd } : src);
    closes.delete(to);
  }
  for (const [fd, found] of inherited) {
    if ((exec && closes.has(fd)) || (fd === 0 && stdin !== 'inherit' && !inputAction)) continue;
    if (kernelDescriptor(found) && found.dupSource == null) keepOpenKfds.add(found.kfd);
    if (!ids.has(found)) {
      ids.set(found, descriptions.length);
      const description = { ...describe(found), refs: 0 };
      if (found.dupSource != null) description.dupSource = found.dupSource;
      descriptions.push(description);
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
  const closeKfds = exec ? [...parentKfds].filter(k => !keepOpenKfds.has(k)) : [];
  return { signals: signals.snapshot(), fds: table, descriptions, keepOpenKfds: [...keepOpenKfds], closeKfds };
}

function describe(found) {
  if (found.preopen && found.kfd == null) return { kind: 'preopen', preopen: true };
  switch (found.kind) {
    case 'pty': return { kind: 'pty', tty: true, handle: found.handle, master: found.master, number: found.number, readable: found.readable, writable: found.writable, refs: found.refs };
    case 'unix-sock': return { kind: 'unix-sock', sockId: found.sockId, sockType: found.sockType, txSlot: found.txSlot, rxSlot: found.rxSlot, flags: found.flags, refs: found.refs };
    case 'inet-sock': return { kind: 'inet-sock', af: found.af, sockType: found.sockType, proto: found.proto, flags: found.flags, refs: found.refs };
    case 'arena-pipe-in': case 'arena-pipe-out': return { kind: found.kind, slot: found.slot, gen: found.gen, flags: found.flags, ...(found.privateFlags ? { privateFlags: found.privateFlags } : {}), ...(found.pathOnly ? { pathOnly: true } : {}), refs: found.refs };
    case 'in':
      if (shares && found.share == null) share(found);
      if (shares && found.share == null) throw new Errno(ERRNO.EMFILE);
      return { kind: 'in', procInfo: found.procInfo, pathOnly: found.pathOnly, stat: found.stat, tty: found.tty, flags: found.flags, data: found.share == null ? found.data.slice(found.pos) : found.data, share: found.share, refs: found.refs };
    case 'out': return { kind: 'out', fd: found.fd, tty: found.tty, flags: found.flags, closed: found.closed?.buffer ?? null };
    case 'tty': case 'pipe-in': case 'pipe-out': return { fd: found.fd, kind: found.kind, tty: !!found.tty, flags: found.flags, ...(found.pathOnly ? { pathOnly: true } : {}), readable: found.readable, writable: found.writable, buffer: found.pipe.buffer, refs: found.refs };
    case 'kfd': {
      const { kind, kfd, isDir, mountNs, device, read, writable, append, pathOnly, flags, stat, typeMode, share: slot } = found;
      return { kind, kfd, isDir, mountNs, device, read, writable, append, pathOnly, ...(flags ? { flags } : {}), stat, typeMode, ...(slot != null ? { share: slot } : {}), refs: found.refs };
    }
    default: {
      if (shares && found.share == null) share(found);
      if (shares && found.share == null) throw new Errno(ERRNO.EMFILE);
      const { kind, serverDev, kfd, device, writable, read, size: length, stat: stated, append, share: slot, refs } = found;
      return { kind, serverDev, kfd, device, writable, read, size: length, stat: stated, append, share: slot, refs };
    }
  }
}

function adopt(state) {
  const made = state.descriptions.map(description => {
    if (description.preopen || description.kind === 'preopen') return { kind: 'preopen', preopen: true };
    switch (description.kind) {
      case 'pty': { const { refs, ...found } = description; return found; }
      case 'unix-sock': {
        const desc = { kind: 'unix-sock', sockId: description.sockId, sockType: description.sockType, txSlot: description.txSlot ?? null, rxSlot: description.rxSlot ?? null, flags: description.flags, peerCred: null };
        attachSockRings(desc);
        return desc;
      }
      case 'inet-sock':
        return { kind: 'inet-sock', af: description.af, sockType: description.sockType, proto: description.proto, flags: description.flags ?? descriptorFlags() };
      case 'arena-pipe-in': case 'arena-pipe-out':
        return { kind: description.kind, slot: description.slot, gen: description.gen, flags: description.flags, ...(description.privateFlags ? { privateFlags: description.privateFlags } : {}), ...(description.pathOnly ? { pathOnly: true } : {}), pipe: new ArenaPipe(sockArena, description.slot, description.gen, process.pid, sockNotify) };
      case 'in': {
        const found = { kind: 'in', procInfo: description.procInfo, pathOnly: description.pathOnly, stat: description.stat, tty: description.tty, flags: description.flags, data: description.data, pos: 0 };
        if (description.share != null) shares.attach(found, description.share);
        return found;
      }
      case 'out': return { kind: 'out', fd: description.fd, tty: description.tty, flags: description.flags, closed: description.closed ? new Int32Array(description.closed) : null };
      case 'tty': case 'pipe-in': case 'pipe-out': return { fd: description.fd, kind: description.kind, tty: description.tty, flags: description.flags, ...(description.pathOnly ? { pathOnly: true } : {}), readable: description.readable, writable: description.writable, pipe: new Pipe(description.buffer, process.pid) };
      case 'kfd': { const { refs, ...rest } = description; return { ...rest }; }
      default: {
        const found = adopted(description);
        if (shares && description.share != null) shares.attach(found, description.share);
        return found;
      }
    }
  });
  for (const [fd, id, closeOnExec] of state.fds) {
    install(fd, made[id], true);
    if (closeOnExec) cloexec.add(fd);
  }
}

function adopted(description) {
  const { share, refs, ...rest } = description;
  return { ...rest, pos: 0 };
}

async function fork() {
  let state;
  try { state = forkState(); } catch (err) { return { errno: err instanceof Errno ? err.errno : EIO }; }
  const snapshot = engine.snapshot();
  snapshot.initializing = initializing;
  postMessage({ fork: { ...state, snapshot, snapshots, shares: shares.buffer, argv: process.argv, env: environ, umask: process.umask, wasix: process.wasix } }, [snapshot.memory]);
  const { forked } = await next('forked');
  if (forked.errno) return { errno: ERRNO[forked.errno] ?? EIO };
  return { pid: forked.pid };
}

// ---- Image Instantiation & Execution ----

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

let initializing = false;
let linearBytes = 0, growReserved = 0;

function checkTermination() {
  const word = control ? Atomics.load(control, 0) : 0;
  if (word & KILLED) throw killedBy(word & 0xff);
}
function reserveMemory(bytesCount) {
  checkTermination();
  if (!channel) { linearBytes = bytesCount; return; }
  try {
    const answer = host('resource', { memory: bytesCount });
    if (answer?.errno) throw new Errno(ERRNO[answer.errno] ?? EIO);
    linearBytes = bytesCount;
  } catch (error) {
    if (error.errno === ERRNO.EPERM && channel) host('reconcile', {});
    checkTermination();
    throw error;
  }
  checkTermination();
}

const resourceImports = {
  memory_grow_pre: (_, delta) => {
    growReserved = 0;
    const bytesCount = (delta >>> 0) * 65536;
    if (!bytesCount) return delta;
    try { reserveMemory(linearBytes + bytesCount); growReserved = bytesCount; return delta; }
    catch (error) { if (error.errno === ERRNO.EAGAIN || error.errno === EINVAL) return -1; throw error; }
  },
  memory_grow_post: (_, result) => {
    if (result === -1 && growReserved) reserveMemory(linearBytes - growReserved);
    growReserved = 0; return result;
  },
};

async function instantiate(module, type, snapshot, startSection = false, memoryBytes) {
  if (memoryBytes !== undefined) {
    const cloned = snapshot ? snapshot.memory.byteLength + Object.values(snapshot.memories ?? {}).reduce((n, b) => n + b.byteLength, 0) : 0;
    reserveMemory(Math.max(memoryBytes, cloned));
  }
  if (!snapshot && ![...fds.keys()].some(preopen)) {
    const fd = lowest(3);
    if (fd >= 1024) throw new Errno(ERRNO.EMFILE);
    install(fd, { kind: 'preopen', preopen: true });
  }
  const required = WebAssembly.Module.imports(module);
  if (required.some(entry => entry.module === 'os' && ['getuid', 'getgid', 'getgroups'].includes(entry.name))) {
    if (channel) {
      const answer = host('getcreds', {});
      if (answer?.errno) throw new Errno(ERRNO[answer.errno] ?? EIO);
      identity = answer;
    } else {
      identity = await drive(serverCall('getcreds'));
    }
  }
  suspending = capable && !startSection && !required.some(entry => entry.module === 'os' && entry.name === 'sigaction');
  const pages = snapshot ? snapshot.memory.byteLength / 65536 : 0;
  const env = type ? { memory: new WebAssembly.Memory({
    initial: Math.max(type.initial, pages),
    ...(type.maximum == null ? {} : { maximum: type.maximum }),
    ...(type.shared ? { shared: true } : {}),
  }) } : {};
  const imports = suspending
    ? { wasi_snapshot_preview1: suspendable(preview1), os: suspendable(osApi), wasix_32v1: suspendable(wasix), env }
    : { wasi_snapshot_preview1: preview1, os: osApi, wasix_32v1: wasix, env };
  imports.os_runtime = resourceImports;
  if (type) memory = env.memory;
  instance = await WebAssembly.instantiate(module, imports);
  memory = type ? env.memory : instance.exports.memory;
  if (!(memory instanceof WebAssembly.Memory)) throw new Error('the module exports no memory');
  process.wasix = WebAssembly.Module.imports(module).some(entry => entry.module === 'wasix_32v1');
  engine = snapshot ? Engine.child(instance, () => memory, snapshot) : new Engine(instance, () => memory);
  initializing = snapshot ? !!snapshot.initializing : !!instance.exports.__tw_initialize;
}

// Note: `'getcwd'` is intentionally omitted so JSPI can suspend `os.getcwd` / `wasix.getcwd`.
const NEVER_SUSPENDS = new Set([
  'args_get', 'args_sizes_get', 'environ_get', 'environ_sizes_get', 'clock_res_get', 'clock_time_get',
  'fd_advise', 'fd_allocate', 'fd_fdstat_get', 'fd_fdstat_set_flags',
  'fd_fdstat_set_rights', 'fd_prestat_get', 'fd_prestat_dir_name', 'fd_tell', 'fd_dup',
  'fd_dup2', 'fd_pipe', 'poll_oneoff', 'proc_exit', 'proc_raise', 'random_get', 'sched_yield',
  'proc_id', 'proc_parent', 'proc_signal', 'proc_join', 'proc_fork', 'stack_checkpoint', 'stack_restore',
  'callback_signal', 'thread_id', 'thread_signal', 'thread_exit', 'futex_wait', 'futex_wake',
  'proc_exit2', 'proc_signals_get', 'proc_signals_sizes_get', 'fd_fdflags_get', 'fd_fdflags_set',
  'sigpoll', 'getuid', 'getgid', 'getgroups', 'getpgid', 'getsid', 'setpgid', 'setsid', 'tcgetpgrp', 'tcsetpgrp', 'waitpid2', 'sigaction', 'sigmask', 'sigpending', 'sigsuspend',
  'futex_wake_all', 'reply', 'umask', 'tty_get', 'tty_set', 'posix_spawn', 'waitpid',
  'sock_socket', 'sock_socketpair', 'sock_bind', 'sock_listen', 'sock_accept', 'sock_connect',
  'sock_shutdown', 'sock_sendmsg', 'sock_recvmsg', 'sock_peercred', 'sock_getsockname',
  'sock_getpeername', 'sock_getsockopt', 'sock_setsockopt',
  'sock_open', 'sock_recv', 'sock_send', 'sock_send_to', 'sock_recv_from', 'sock_addr_resolve',
]);

function suspendable(namespace) {
  return new Proxy({}, { get: (_, name) => {
    const call = namespace[name];
    return typeof call === 'function' && !NEVER_SUSPENDS.has(name) ? new WebAssembly.Suspending(call) : call;
  } });
}

async function run() {
  for (;;) {
    let pending;
    try {
      const entry = initializing ? instance.exports.__tw_initialize : instance.exports._start;
      const startFn = suspending ? WebAssembly.promising(entry) : entry;
      await startFn();
    } catch (err) {
      if (err instanceof GuiDispatch) {
        const tick = instance.exports.gui_client_tick;
        if (typeof tick !== 'function') throw new Error('missing GUI event callback');
        const dispatch = suspending ? WebAssembly.promising(tick) : tick;
        for (;;) {
          pause();
          if (!await dispatch()) return 0;
          await new Promise(resolve => setTimeout(resolve, 12));
        }
      }
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

async function replace() {
  const { image } = await next('image');
  process.proc = image.token;
  for (const fd of [...cloexec]) {
    const found = fds.get(fd);
    if (found?.kind === 'kfd' || found?.serverDev) {
      // `reexec` already closed `FD_CLOEXEC` kfds and serverDev fds in `client-kernel`; drop JS table entry & share ref.
      fds.delete(fd);
      cloexec.delete(fd);
      found.refs--;
      if (found.share != null) {
        const gen = shares.gen(found.share);
        const left = shares.drop(found.share, process.pid);
        if (left <= 0) postMessage({ closed: { slot: found.share, gen } });
      }
    } else {
      try { await drive(uninstall(fd)); } catch { /* closed already */ }
    }
  }
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

function sleepUntil(until) {
  if (until - performance.now() <= 0) return;
  flush();
  if (control) {
    for (let left = until - performance.now(); left > 0; left = until - performance.now()) {
      pause(true);
      Atomics.wait(control, 0, 0, Math.min(left, 200));
    }
    return;
  }
  if (typeof SharedArrayBuffer === 'function') { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, until - performance.now()); return; }
  while (performance.now() < until) { /* busy wait */ }
}

// ---- `os.sys` Batch & `(module "os")` Syscall Imports ----

const ttyRequests = new Set(Object.values(IOCTL));
function trackOpened(request, result) {
  const opened = result?.ok;
  if (!request || !Number.isInteger(opened?.fd)) return result;
  const kfd = opened.fd, flags = request.flags ?? 0, pathOnly = !!(flags & O_PATH);
  const access = flags & 3, serverDev = kfd >= 0x20000000 && kfd < 0x40000000;
  const fd = lowest();
  install(fd, {
    kind: serverDev ? 'file' : 'kfd', serverDev, kfd, device: opened.device,
    read: !pathOnly && access !== O_WRONLY, writable: !pathOnly && access !== O_RDONLY,
    pathOnly, append: !!(flags & O_APPEND), isDir: !!(flags & O_DIRECTORY) || kindOf(opened.stat?.mode ?? 0) === DIRECTORY,
    stat: opened.stat, pos: 0, size: opened.size,
  });
  if (flags & O_CLOEXEC) cloexec.add(fd);
  return { ok: { ...opened, fd } };
}

function translateGuestFd(fd) {
  if (!Number.isInteger(fd)) return fd;
  const anchor = sentinelAnchor(fd);
  if (anchor != null) return anchor;
  if ((fd | 0) === -100) return OS_FD_CWD;
  if (fd >= 0x20000000 && fd < 0x40000000) return fd;
  const found = fds.get(fd);
  if (found?.preopen && found.kfd == null) return OS_FD_ROOT;
  return found?.kfd ?? 0xffffffff;
}

function translateAcceleratorSubmit(arg) {
  const op = arg?.operation;
  if (!op || typeof op !== 'object') return;
  const patchPathAt = pa => {
    if (pa && typeof pa === 'object' && Number.isInteger(pa.directory)) {
      pa.directory = translateGuestFd(pa.directory);
    }
  };
  switch (op.operation) {
    case 'create':
      patchPathAt(op.output);
      for (const input of op.inputs ?? []) patchPathAt(input.source);
      break;
    case 'extract': patchPathAt(op.source); patchPathAt(op.destination); break;
    case 'list': patchPathAt(op.source); break;
    case 'faststart': patchPathAt(op.file); break;
  }
}

function translateCallFds(call) {
  if (!call || typeof call !== 'object') return call;
  const cloned = structuredClone(call);
  const name = Object.keys(cloned)[0];
  const args = cloned[name];
  if (!args || typeof args !== 'object') return cloned;
  for (const key of ['dirfd', 'from_dirfd', 'to_dirfd', 'fd']) {
    if (Number.isInteger(args[key])) {
      args[key] = translateGuestFd(args[key]);
    }
  }
  if (name === 'ioctl') {
    if (args.request === GUI_IOC_BIND_SURFACE && args.arg) {
      args.arg.socket_fd = sockDescriptor(args.arg.socket_fd).sockId;
    } else if (args.request === GUI_IOC_PEER_ROLES && Number.isInteger(args.arg)) {
      args.arg = sockDescriptor(args.arg).sockId;
    } else if (args.request === 0x47550008) {
      args.arg[2] = translateGuestFd(args.arg[2]);
    } else if (args.request === 0x47550009) {
      args.arg[0] = translateGuestFd(args.arg[0]);
    } else if (args.request === 0x4755000d) {
      args.arg[1] = translateGuestFd(args.arg[1]);
    } else if (args.request === GUI_IOC_CHECK_BUNDLE) {
      args.arg = translateGuestFd(args.arg);
    } else if (args.request === EXPORT_DIR_IOCTL && args.arg?.op === 'admit_local') {
      args.arg.socket_fd = sockDescriptor(args.arg.socket_fd).sockId;
    } else if ((args.request === FICLONE || args.request === LOOP_SET_FD) && Number.isInteger(args.arg)) {
      args.arg = translateGuestFd(args.arg);
    } else if (args.request === FICLONERANGE && args.arg && typeof args.arg === 'object' && Number.isInteger(args.arg.src_fd)) {
      args.arg.src_fd = translateGuestFd(args.arg.src_fd);
    } else if ((args.request === COWFS_IOC_SEND || args.request === COWFS_IOC_RECEIVE || args.request === COWFS_IOC_OCI_IMPORT || args.request === COWFS_IOC_OCI_EXPORT) && args.arg && typeof args.arg === 'object' && Number.isInteger(args.arg.stream_fd)) {
      args.arg.stream_fd = translateGuestFd(args.arg.stream_fd);
    } else if (args.request === ACCEL_SUBMIT && args.arg && typeof args.arg === 'object') {
      translateAcceleratorSubmit(args.arg);
    }
  }
  return cloned;
}

const processCalls = call =>
  call === 'setsid' || !!(call?.getpgid || call?.getsid || call?.setpgid || call?.waitpid || call?.proc_stopped || call?.prctl);

function isPtyIoctl(call) {
  if (!call?.ioctl) return false;
  if (ttyRequests.has(call.ioctl.request)) return true;
  return Number.isInteger(call.ioctl.fd) && fds.get(call.ioctl.fd)?.kind === 'pty';
}

function guestStorageStream(call) {
  const ioctl = call?.ioctl;
  if (ioctl?.request !== COWFS_IOC_SEND && ioctl?.request !== COWFS_IOC_RECEIVE && ioctl?.request !== COWFS_IOC_OCI_IMPORT && ioctl?.request !== COWFS_IOC_OCI_EXPORT) return null;
  const found = fds.get(ioctl.arg?.stream_fd);
  return found && found.kfd == null ? found : null;
}

function transferStorageStream(ioctl, found) {
  const sending = ioctl.request === COWFS_IOC_SEND || ioctl.request === COWFS_IOC_OCI_EXPORT;
  const kinds = sending ? ['out', 'pipe-out', 'arena-pipe-out', 'tty', 'pty'] : ['in', 'pipe-in', 'arena-pipe-in', 'tty', 'pty'];
  if (found.pathOnly || !kinds.includes(found.kind)) return { err: { errno: 'EBADF' } };
  let step = vfsCall('cowfs_stream', { ioctl: { ...ioctl, fd: translateGuestFd(ioctl.fd) } });
  try {
    while (!step.result) {
      // Pipe, terminal and buffered stdio descriptions perform synchronous I/O
      // in the process worker. Their usual backpressure and signal handling apply.
      const op = sending ? writeTo(found, 0, unbase64(step.write)) : readFrom(found, 0, step.read);
      const chunk = op.next();
      if (!chunk.done) throw new Errno(EIO);
      step = vfsCall('cowfs_ack', { ack: chunk.value });
    }
    return step.result;
  } catch (error) {
    vfsCall('cowfs_cancel');
    throw error;
  }
}

function kernelBatch(calls) {
  let response = channel;
  if (channel && calls.some(c => c?.ioctl?.request === GUI_IOC_NEXT_EVENT)) {
    // Every byte of a 1 MiB paste can require a six-byte JSON escape.
    seatChannel ??= replyChannel(new SharedArrayBuffer(8 + 6 * (1 << 20) + 1024));
    response = seatChannel;
  }
  const reply = host('vfs', { op: 'sys', batch: { calls, umask: process.umask } }, response);
  return reply.errno ? calls.map(() => ({ err: { errno: reply.errno } })) : reply.results;
}

function osBatch(calls) {
  if (calls.some(c => c && typeof c === 'object' && 'resource' in c)) {
    return calls.map(() => ({ err: { errno: 'EPERM' } }));
  }
  const split = calls.some(c =>
    processCalls(c) || c?.getdents || c?.pread || c?.readlink_at || c?.fstat_at ||
    /(?:^|\/)fdinfo\/[0-9]+$/.test((c?.stat ?? c?.lstat ?? c?.readlink ?? c?.fstat_at)?.path ?? '') ||
    procFdCandidate(c?.readlink?.path) ||
    procFdCandidate(c?.stat?.path) ||
    procFdCandidate(c?.lstat?.path) || procFdCandidate(c?.chmod?.path) ||
    c?.open || c?.open_at ||
    isPtyIoctl(c) || guestStorageStream(c) ||
    c?.close || c?.discard
  );
  if (!split) {
    const translated = calls.map(translateCallFds);
    return kernelBatch(translated);
  }
  const results = [];
  for (const original of calls) {
    const call = structuredClone(original);
    const args = typeof call === 'object' && call !== null ? Object.values(call)[0] : null;
    const scalarRefKeys = [
      'fd', 'dirfd', 'from_dirfd', 'to_dirfd',
      ...(call?.ioctl?.request === FICLONE || call?.ioctl?.request === LOOP_SET_FD ? ['arg'] : []),
    ];
    for (const key of scalarRefKeys) {
      if (args?.[key]?.ref == null) continue;
      const prior = results[args[key].ref];
      const fd = prior?.ok?.fd;
      const err = !prior ? { errno: 'EINVAL' } : prior.err ??
        (!Number.isInteger(fd) || fd < 0 || fd > 0xffffffff ? { errno: 'EBADF' } : null);
      if (err) { args.invalidReference = err; break; }
      args[key] = fd;
    }
    if (!args?.invalidReference && call?.ioctl && args?.arg && typeof args.arg === 'object') {
      const nestedKey = call.ioctl.request === GUI_IOC_BIND_SURFACE ? 'socket_fd' : call.ioctl.request === FICLONERANGE
        ? 'src_fd'
        : (call.ioctl.request === COWFS_IOC_SEND || call.ioctl.request === COWFS_IOC_RECEIVE || call.ioctl.request === COWFS_IOC_OCI_IMPORT || call.ioctl.request === COWFS_IOC_OCI_EXPORT)
          ? 'stream_fd'
          : null;
      if (nestedKey && args.arg[nestedKey]?.ref != null) {
        const prior = results[args.arg[nestedKey].ref];
        const fd = prior?.ok?.fd;
        const err = !prior ? { errno: 'EINVAL' } : prior.err ??
          (!Number.isInteger(fd) || fd < 0 || fd > 0xffffffff ? { errno: 'EBADF' } : null);
        if (err) { args.invalidReference = err; } else { args.arg[nestedKey] = fd; }
      }
    }
    if (args?.invalidReference) { results.push({ err: args.invalidReference }); continue; }
    try {
      const arg = call?.chmod ?? call?.pread ?? call?.stat ?? call?.lstat ?? call?.open ?? call?.open_at ?? call?.readlink ?? call?.readlink_at ?? call?.fstat_at;
      const virtualPath = typeof arg?.path === 'string' && (arg.path.startsWith('/') || arg.dirfd != null);
      const info = virtualPath && !call.chmod && procInfo(translateGuestFd(arg.dirfd ?? OS_FD_CWD), arg.path);
      const dir = procFdDirectory(call?.getdents?.path);
      if (dir) {
        const { cookie = 0, count = dir.length } = call.getdents;
        results.push({ ok: dir.slice(cookie, cookie + count) }); continue;
      }
      if (info?.path) {
        arg.path = info.path;
      } else if (info || (call?.pread && fds.get(call.pread.fd)?.procInfo)) {
        const value = info ?? fds.get(call.pread.fd);
        if (call.readlink) throw new Errno(EINVAL);
        if (call.pread) {
          if (value.pathOnly) throw new Errno(EBADF);
          const { offset = 0, count = INLINE } = call.pread;
          results.push({ ok: { size: value.data.length, stat: value.stat, data: base64(value.data.subarray(offset, offset + count)) } });
        } else if (call.open || call.open_at) {
          results.push({ ok: { fd: openProcInfo(value, arg.flags ?? 0), size: value.data.length } });
        } else results.push({ ok: value.stat });
        continue;
      }
      const entry = !info && virtualPath && resolveProcFd(translateGuestFd(arg.dirfd ?? OS_FD_CWD), arg.path);
      if (entry) {
        const { guestFd, found } = entry;
        if (!found) throw new Errno(ENOENT);
        if (call.open || call.open_at) {
          if (arg.size != null || arg.sha256 != null || arg.version != null) throw new Errno(ERRNO.EOPNOTSUPP);
          const fd = openLinuxPathAt(arg.dirfd ?? OS_FD_CWD, arg.path, arg.flags ?? 0, arg.mode);
          const opened = descriptor(fd);
          results.push({ ok: { fd, size: opened.size ?? 0, device: opened.device, stat: opened.stat } });
          continue;
        }
        if (call.readlink || call.readlink_at) {
          results.push({ ok: linkTextFor(found) });
          continue;
        }
        if (call.stat || (call.fstat_at && !arg.nofollow)) {
          results.push({ ok: statOf(found) });
          continue;
        }
        if (call.chmod && found.serverDev) {
          call.fchmod = { fd: guestFd, mode: arg.mode };
          delete call.chmod;
        } else if (call.chmod && found.preopen) arg.path = '/';
        else if (call.chmod && found.kind !== 'kfd') throw new Errno(ERRNO.EOPNOTSUPP);
        else if (found.kind === 'kfd') {
          arg.path = `/proc/self/fd/${found.kfd}`;
        } else if (call.lstat || call.fstat_at) {
          results.push({ ok: { dev: 0, ino: guestFd, mode: 0o120700, nlink: 1, uid: identity.uid, gid: identity.gid, size: linkTextFor(found).length } });
          continue;
        } else if (call.pread) {
          if (found.preopen) throw new Errno(ERRNO.EISDIR);
          if (found.kind === 'in') {
            const { offset = 0, count = INLINE } = arg;
            results.push({ ok: { size: found.data.length, data: base64(found.data.subarray(offset, offset + Math.min(INLINE, count))) } });
            continue;
          }
          if (!found.serverDev) throw new Errno(ERRNO.ESPIPE);
          delete arg.path;
          arg.fd = guestFd;
        }
      }
    } catch (error) {
      if (!(error instanceof Errno)) throw error;
      results.push({ err: { errno: Object.keys(ERRNO).find(key => ERRNO[key] === error.errno) ?? 'EIO' } });
      continue;
    }
    if (processCalls(call)) {
      const result = host('process_call', call);
      results.push(result?.errno ? { err: { errno: result.errno } } : { ok: result });
    } else if (call?.close || call?.discard) {
      const fd = (call.close ?? call.discard).fd, found = fds.get(fd);
      if (!found) {
        if (call.close && Number.isInteger(fd) && fd >= 0x20000000 && fd < 0x40000000) {
          results.push(kernelBatch([translateCallFds(call)])[0]);
          continue;
        }
        results.push({ err: { errno: 'EBADF' } });
        continue;
      }
      const isKernel = kernelDescriptor(found);
      if (call.discard && !isKernel) { results.push({ err: { errno: 'EINVAL' } }); continue; }
      const result = isKernel
        ? kernelBatch([translateCallFds(call)])[0]
        : { ok: null };
      drive(uninstall(fd, isKernel));
      results.push(result);
    } else {
      const stream = guestStorageStream(call);
      if (stream) {
        try {
          results.push(transferStorageStream(call.ioctl, stream));
        } catch (err) {
          if (!(err instanceof Errno)) throw err;
          results.push({ err: { errno: Object.keys(ERRNO).find(key => ERRNO[key] === err.errno) ?? 'EIO' } });
        }
      } else if (isPtyIoctl(call)) {
        try {
          const { fd, request: reqCode, arg } = call.ioctl;
          const found = descriptor(fd);
          if (!found.tty || (found.kind !== 'pty' && !ttyState)) throw new Errno(ERRNO.ENOTTY);
          if ([IOCTL.TIOCSPGRP, IOCTL.TCSETS, IOCTL.TCSETSW, IOCTL.TCSETSF].includes(reqCode)) ttyAccess(22, found);
          flush();
          results.push({ ok: ttyCall(found, reqCode, arg) });
        } catch (err) {
          const errno = err instanceof Errno ? Object.keys(ERRNO).find(key => ERRNO[key] === err.errno) ?? 'EIO' : 'EIO';
          results.push({ err: { errno } });
        }
      } else {
        const translated = translateCallFds(call);
        const [result] = kernelBatch([translated]);
        results.push(trackOpened(call?.open ?? call?.open_at, result));
      }
    }
  }
  return results;
}

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

const optString = (ptr, len) => (ptr === 0 && len === 0) ? null : string(ptr, len);

function openLinuxPathAt(dirfd, raw, flags, mode) {
  const allowed = 3 | O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC | O_APPEND | O_NONBLOCK | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_PATH;
  if ((flags & ~allowed) || (!(flags & O_PATH) && (flags & 3) === 3)) throw new Errno(EINVAL);
  const oflags = (flags & O_CREAT ? OFLAG_CREAT : 0) | (flags & O_EXCL ? OFLAG_EXCL : 0) | (flags & O_TRUNC ? OFLAG_TRUNC : 0) | (flags & O_DIRECTORY ? OFLAG_DIRECTORY : 0);
  const rights = (flags & 3) === O_RDONLY ? RIGHT_READ : (flags & 3) === O_WRONLY ? RIGHT_WRITE : RIGHT_READ | RIGHT_WRITE;
  const fdflags = (flags & O_APPEND ? FDFLAG_APPEND : 0) | (flags & O_NONBLOCK ? FDFLAG_NONBLOCK : 0);
  const extra = (flags & O_CLOEXEC) | (flags & O_PATH);
  return openPathAt(dirfd, raw, (flags & O_NOFOLLOW) ? 0 : FOLLOW, oflags, rights, fdflags, !!(flags & O_NOCTTY), mode, extra);
}

const osApi = {
  gui_dispatch() { throw new GuiDispatch(); },
  gui_paint(id, generation, color) { pixelSurfaces.paint(Number(id), generation, color); },
  gui_resize(id, width, height) { pixelSurfaces.resize(Number(id), width, height); },
  open: (ptr, len, flags, mode) => posixCall(() => openLinuxPathAt(OS_FD_CWD, string(ptr, len), flags, mode)),
  // ---- All 11 Wave 2 L2 `(module "os")` Wasm imports ----
  chdir: (pathPtr, pathLen) => posixCall(() => {
    const p = string(pathPtr, pathLen);
    if (!p) throw new Errno(ENOENT);
    vfsCall('chdir', { path: p });
    return 0;
  }),
  fchdir: fd => posixCall(() => {
    const found = descriptor(fd);
    const kfd = found.preopen && found.kfd == null ? OS_FD_ROOT : found.kfd;
    if (kfd == null) throw new Errno(ENOTDIR);
    vfsCall('fchdir', { kfd });
    return 0;
  }),
  getcwd: (bufPtr, bufCap) => posixCall(() => {
    if (bufCap <= 0) throw new Errno(EINVAL);
    const cwd = vfsCall('getcwd', {}).cwd;
    const encoded = encoder.encode(cwd);
    if (encoded.length + 1 > bufCap) throw new Errno(ERRNO.ERANGE);
    const b = bytes();
    if (bufPtr < 0 || bufPtr + encoded.length + 1 > b.length) throw new Errno(ERRNO.EFAULT);
    b.set(encoded, bufPtr);
    b[bufPtr + encoded.length] = 0;
    return encoded.length + 1;
  }),
  chroot: (pathPtr, pathLen) => posixCall(() => {
    const p = string(pathPtr, pathLen);
    if (!p) throw new Errno(ENOENT);
    vfsCall('chroot', { path: p });
    return 0;
  }),
  mount: (srcPtr, srcLen, tgtPtr, tgtLen, fsPtr, fsLen, flagsBigInt, dataPtr, dataLen) => posixCall(() => {
    const target = string(tgtPtr, tgtLen);
    if (!target) throw new Errno(ENOENT);
    vfsCall('mount', {
      source: optString(srcPtr, srcLen),
      target,
      fstype: optString(fsPtr, fsLen),
      flags: BigInt.asUintN(64, BigInt(flagsBigInt)).toString(),
      data: optString(dataPtr, dataLen),
    });
    return 0;
  }),
  umount2: (tgtPtr, tgtLen, flags) => posixCall(() => {
    const target = string(tgtPtr, tgtLen);
    if (!target) throw new Errno(ENOENT);
    vfsCall('umount2', { target, flags: flags >>> 0 });
    return 0;
  }),
  statfs: (pathPtr, pathLen, outPtr) => posixCall(() => {
    const raw = string(pathPtr, pathLen);
    if (!raw) throw new Errno(ENOENT);
    const sfs = vfsCall('statfs', { dirfd: resolveAnchorForPath(OS_FD_CWD, raw), path: raw });
    writeRawStatFs(outPtr, sfs);
    return 0;
  }),
  fstatfs: (fd, outPtr) => posixCall(() => {
    const found = descriptor(fd);
    if (found.preopen && found.kfd == null) {
      writeRawStatFs(outPtr, vfsCall('statfs', { dirfd: OS_FD_ROOT, path: '/' }));
      return 0;
    }
    if (found.kind === 'kfd' && found.kfd != null) {
      writeRawStatFs(outPtr, vfsCall('fstatfs', { kfd: found.kfd }));
      return 0;
    }
    if (found.kind === 'pty' || found.tty) {
      writeRawStatFs(outPtr, { f_type: 0x00001cd1, bsize: 4096, frsize: 4096, namelen: 255, flags: 6 });
      return 0;
    }
    if (found.kind === 'unix-sock' || found.kind === 'inet-sock') {
      writeRawStatFs(outPtr, { f_type: 0x534f434b, bsize: 4096, frsize: 4096, namelen: 255, flags: 0 });
      return 0;
    }
    if (found.kind === 'pipe-in' || found.kind === 'pipe-out' || found.kind === 'arena-pipe-in' || found.kind === 'arena-pipe-out') {
      writeRawStatFs(outPtr, { f_type: 0x50495045, bsize: 4096, frsize: 4096, namelen: 255, flags: 0 });
      return 0;
    }
    if (found.serverDev) {
      writeRawStatFs(outPtr, { f_type: 0x01021994, bsize: 4096, frsize: 4096, namelen: 255, flags: 6 });
      return 0;
    }
    throw new Errno(ENOSYS);
  }),
  unshare: flags => posixCall(() => {
    vfsCall('unshare', { flags: flags >>> 0 });
    return 0;
  }),
  setns: (fd, nstype) => posixCall(() => {
    const found = descriptor(fd);
    if (found.kind !== 'kfd' || found.kfd == null) throw new Errno(EINVAL);
    vfsCall('setns', { kfd: found.kfd, nstype: nstype | 0 });
    return 0;
  }),
  execve: (reqPtr, reqLen) => {
    pause();
    try {
      if (reqLen < 0 || reqLen > 1 << 20) throw new Errno(ERRNO.E2BIG);
      const req = JSON.parse(string(reqPtr, reqLen));
      if (typeof req.file !== 'string' || !req.file) throw new Errno(ENOENT);
      if (!Array.isArray(req.argv) || !req.argv.length || !Array.isArray(req.env)) throw new Errno(EINVAL);
      hostErrno(host('exec', { file: req.file, argv: req.argv, env: req.env, search: !!req.search }));
    } catch (err) {
      if (err instanceof Exit) throw err;
      return -(err instanceof Errno ? err.errno : EINVAL);
    }
    throw new Replaced();
  },
  // ---- Existing process, signal, TTY & batch imports ----
  getpgid: pid => posixCall(() => processCall({ getpgid: { pid } }).pgid),
  getsid: pid => posixCall(() => processCall({ getsid: { pid } }).sid),
  setpgid: (pid, pgid) => posixCall(() => { processCall({ setpgid: { pid, pgid } }); return 0; }),
  setsid: () => posixCall(() => processCall('setsid').sid),
  tcgetpgrp: fd => posixCall(() => ttyCall(descriptor(fd), IOCTL.TIOCGPGRP).pgrp),
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
    if (count < 0 || (count && count < identity.groups.length)) return -EINVAL;
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
      const req = JSON.parse(string(ptr, len));
      const vector = value => Array.isArray(value) && value.every(item => typeof item === 'string' && !item.includes('\0'));
      if (!vector(req.argv) || !req.argv[0] || !vector(req.env) || typeof req.cwd !== 'string'
        || req.cwd.includes('\0') || !['inherit', 'null', 'tty'].includes(req.stdin)) throw new Errno(EINVAL);
      if (req.pgroup != null && (!Number.isInteger(req.pgroup) || req.pgroup < 0 || req.pgroup > 0x7fffffff)) throw new Errno(EINVAL);
      if (req.setsid != null && typeof req.setsid !== 'boolean') throw new Errno(EINVAL);
      if (req.setsid && req.pgroup != null) throw new Errno(EINVAL);
      if (req.cttyFd != null && (!Number.isInteger(req.cttyFd) || req.cttyFd < 0 || req.cttyFd > 65535)) throw new Errno(EINVAL);
      if (req.cgroup != null && (typeof req.cgroup !== 'string' || !req.cgroup.startsWith('/') || req.cgroup.length > 4096 || req.cgroup.includes('\0'))) throw new Errno(EINVAL);
      const dup2 = req.dup2 ?? [];
      if (!Array.isArray(dup2) || dup2.length > 64 || !dup2.every(pair => Array.isArray(pair) && pair.length === 2 && pair.every(fd => Number.isInteger(fd) && fd >= 0 && fd <= 65535))) throw new Errno(EINVAL);
      let serviceGrant = null;
      if (req.serviceGrant != null) {
        const g = req.serviceGrant;
        if (typeof g !== 'object' || Array.isArray(g) || typeof g.mountNamespace !== 'string' || g.mountNamespace.includes('\0')) throw new Errno(EINVAL);
        if (g.user != null && (typeof g.user !== 'string' || !g.user || g.user.includes('\0') || g.user.length > 64)) throw new Errno(EINVAL);
        if (g.group != null && (typeof g.group !== 'string' || !g.group || g.group.includes('\0') || g.group.length > 64)) throw new Errno(EINVAL);
        const binds = g.bindMounts ?? [];
        if (!Array.isArray(binds) || binds.length > 32 || !binds.every(b => b && typeof b === 'object' && typeof b.source === 'string' && !b.source.includes('\0') && typeof b.target === 'string' && !b.target.includes('\0') && typeof b.readOnly === 'boolean')) throw new Errno(EINVAL);
        const devs = g.devices ?? [];
        if (!Array.isArray(devs) || devs.length > 32 || !devs.every(d => typeof d === 'string' && d.length > 0 && d.length <= 64 && !d.includes('/') && !d.includes('\0') && d !== '.' && d !== '..')) throw new Errno(EINVAL);
        let cloudScope = undefined;
        if (g.cloudScope != null) {
          if (typeof g.cloudScope !== 'object' || Array.isArray(g.cloudScope)) throw new Errno(EINVAL);
          const csDevs = g.cloudScope.devices ?? [];
          if (!Array.isArray(csDevs) || csDevs.length > 32 || !csDevs.every(d => typeof d === 'string' && d.length > 0 && !d.includes('/') && !d.includes('\0'))) throw new Errno(EINVAL);
          cloudScope = {
            cloud_fs: Boolean(g.cloudScope.cloud_fs ?? g.cloudScope.cloudFs),
            devices: csDevs,
            containers: Boolean(g.cloudScope.containers),
            relay: Boolean(g.cloudScope.relay),
          };
        }
        serviceGrant = {
          mountNamespace: g.mountNamespace,
          ...(g.exportImpersonate === true ? { exportImpersonate: true } : {}),
          bindMounts: binds.map(b => ({ source: b.source, target: b.target, readOnly: b.readOnly })),
          ...(g.user != null ? { user: g.user } : {}),
          ...(g.group != null ? { group: g.group } : {}),
          ...(devs.length > 0 ? { devices: devs } : {}),
          ...(cloudScope !== undefined ? { cloudScope } : {}),
        };
      }
      const totalSize = values => values.reduce((sum, value) => sum + encoder.encode(value).length + 1, 0);
      if (totalSize(req.argv) > 128 * 1024 || totalSize(req.env) > 128 * 1024) throw new Errno(ERRNO.E2BIG);
      if (req.stdin === 'tty' && Atomics.load(membership, 2) >= 0x40000000) {
        tty = { kind: 'pty', tty: true, ...hostErrno(host('pty', { op: 'open', path: '/dev/tty', readable: true, writable: false, noctty: true })) };
      }
      const state = { argv: req.argv, env: req.env, cwd: req.cwd, pgroup: req.pgroup, setsid: !!req.setsid, cttyFd: req.cttyFd ?? null, cgroup: req.cgroup, serviceGrant, ...forkState({ exec: true, stdin: req.stdin, tty, dup2 }), shares: shares.buffer, umask: process.umask };
      const child = hostErrno(host('spawn', state));
      view().setUint32(result, child.pid, true);
      return 0;
    } catch (err) { if (err instanceof Exit) throw err; return err instanceof Errno ? err.errno : EINVAL; }
    finally { if (tty) { try { ptyCall(tty, 'close'); } catch {} } }
  },
  waitpid: (pid, result) => {
    pause();
    try {
      const child = waitChild(pid, false);
      view().setUint32(result, child.status, true);
      return 0;
    } catch (err) { if (err instanceof Exit) throw err; return err instanceof Errno ? err.errno : EIO; }
  },
  umask: mask => {
    const nextMask = mask & 0o777;
    const previous = channel ? vfsCall('set_umask', { umask: nextMask }).previous : (process.umask ?? 0o022);
    process.umask = nextMask;
    return previous;
  },
  sys: (ptr, len) => {
    pause();
    const calls = JSON.parse(string(ptr, len));
    const results = osBatch(calls).map(result => result.err?.detail != null
      ? { err: { detail: result.err.detail, errno: result.err.errno } }
      : result);
    reply = encoder.encode(JSON.stringify({ results }));
    return reply.length;
  },
  reply: ptr => { bytes().set(reply, ptr); },
  // ---- Wave 4A Track 1 (`#55` L3b): AF_UNIX / SCM_RIGHTS / SO_PEERCRED `(module "os")` imports ----
  sock_socket: (domain, sockType, protocol, outFd) => {
    pause();
    try {
      if ((domain >>> 0) !== AF_UNIX) throw new Errno(ERRNO.EAFNOSUPPORT);
      if ((protocol >>> 0) !== 0) throw new Errno(ERRNO.EPROTONOSUPPORT);
      const rawType = sockType >>> 0;
      if (rawType & ~(SOCK_TYPE_MASK | SOCK_NONBLOCK | SOCK_CLOEXEC)) throw new Errno(EINVAL);
      const baseType = rawType & SOCK_TYPE_MASK;
      if (baseType !== SOCK_STREAM && baseType !== SOCK_DGRAM && baseType !== SOCK_SEQPACKET) throw new Errno(ERRNO.EPROTOTYPE);
      const outPtr = checkWritable(outFd, 4);
      const fd = lowest();
      const { sockId } = sockCall('create', { sockType: baseType });
      const desc = { kind: 'unix-sock', sockId, sockType: baseType, txSlot: null, rxSlot: null, txRing: null, rxRing: null, peerCred: null };
      install(fd, desc, true);
      if (rawType & SOCK_NONBLOCK) sockCall('set_nonblock', { sockId, nonblock: true });
      if (rawType & SOCK_CLOEXEC) cloexec.add(fd);
      view().setUint32(outPtr, fd, true);
      return 0;
    } catch (err) { if (!(err instanceof Errno)) throw err; return err.errno; }
  },
  sock_socketpair: (domain, sockType, protocol, outFds) => {
    pause();
    try {
      if ((domain >>> 0) !== AF_UNIX) throw new Errno(ERRNO.EAFNOSUPPORT);
      if ((protocol >>> 0) !== 0) throw new Errno(ERRNO.EPROTONOSUPPORT);
      const rawType = sockType >>> 0;
      if (rawType & ~(SOCK_TYPE_MASK | SOCK_NONBLOCK | SOCK_CLOEXEC)) throw new Errno(EINVAL);
      const baseType = rawType & SOCK_TYPE_MASK;
      if (baseType !== SOCK_STREAM && baseType !== SOCK_DGRAM && baseType !== SOCK_SEQPACKET) throw new Errno(ERRNO.EPROTOTYPE);
      const outPtr = checkWritable(outFds, 8);
      const [fdA, fdB] = lowestPair();
      const res = sockCall('socketpair', { sockType: baseType });
      const descA = { kind: 'unix-sock', sockId: res.sockA, sockType: baseType, txSlot: res.slotAB ?? null, rxSlot: res.slotBA ?? null, peerCred: null };
      const descB = { kind: 'unix-sock', sockId: res.sockB, sockType: baseType, txSlot: res.slotBA ?? null, rxSlot: res.slotAB ?? null, peerCred: null };
      attachSockRings(descA);
      attachSockRings(descB);
      install(fdA, descA, true);
      install(fdB, descB, true);
      if (rawType & SOCK_NONBLOCK) {
        sockCall('set_nonblock', { sockId: res.sockA, nonblock: true });
        sockCall('set_nonblock', { sockId: res.sockB, nonblock: true });
      }
      if (rawType & SOCK_CLOEXEC) { cloexec.add(fdA); cloexec.add(fdB); }
      const v = view();
      v.setUint32(outPtr, fdA, true);
      v.setUint32(outPtr + 4, fdB, true);
      return 0;
    } catch (err) { if (!(err instanceof Errno)) throw err; return err.errno; }
  },
  sock_bind: (fd, pathPtr, pathLen) => {
    pause();
    try {
      const found = sockDescriptor(fd);
      const path = checkedString(pathPtr, pathLen);
      sockCall('bind', { sockId: found.sockId, path });
      return 0;
    } catch (err) { if (!(err instanceof Errno)) throw err; return err.errno; }
  },
  sock_listen: (fd, backlog) => {
    pause();
    try {
      const found = sockDescriptor(fd);
      sockCall('listen', { sockId: found.sockId, backlog: backlog >>> 0 });
      return 0;
    } catch (err) { if (!(err instanceof Errno)) throw err; return err.errno; }
  },
  sock_accept: (fd, flags, outFd) => {
    pause();
    try {
      const found = sockDescriptor(fd);
      const rawFlags = flags >>> 0;
      if (rawFlags & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)) throw new Errno(EINVAL);
      const outPtr = checkWritable(outFd, 4);
      for (;;) {
        pause(true);
        // Reserve a guest fd BEFORE dequeueing so transient EMFILE never drops a pending client!
        const targetFd = lowest();
        const nb = nonblocking(found);
        const seen = sockNotify ? Atomics.load(sockNotify, 0) : 0;
        const res = sockCall('accept', { sockId: found.sockId });
        if (res.wouldBlock) {
          if (nb) throw new Errno(ERRNO.EAGAIN);
          waitSockNotify(seen, 20);
          continue;
        }
        const desc = {
          kind: 'unix-sock',
          sockId: res.sockId,
          sockType: found.sockType,
          txSlot: res.txSlot ?? null,
          rxSlot: res.rxSlot ?? null,
          peerCred: res.peerCred ?? null,
        };
        attachSockRings(desc);
        install(targetFd, desc, true);
        if (rawFlags & SOCK_NONBLOCK) sockCall('set_nonblock', { sockId: res.sockId, nonblock: true });
        if (rawFlags & SOCK_CLOEXEC) cloexec.add(targetFd);
        view().setUint32(outPtr, targetFd, true);
        return 0;
      }
    } catch (err) { if (!(err instanceof Errno)) throw err; return err.errno; }
  },
  sock_connect: (fd, pathPtr, pathLen) => {
    pause();
    try {
      const found = sockDescriptor(fd);
      const path = checkedString(pathPtr, pathLen);
      for (;;) {
        pause(true);
        const nb = nonblocking(found);
        const seen = sockNotify ? Atomics.load(sockNotify, 0) : 0;
        let res;
        try {
          res = sockCall('connect', { sockId: found.sockId, path });
        } catch (err) {
          if (err instanceof Errno && err.errno === ERRNO.EAGAIN && !nb) {
            waitSockNotify(seen, 20);
            continue;
          }
          throw err;
        }
        if (res.txSlot || res.rxSlot) {
          found.txSlot = res.txSlot ?? null;
          found.rxSlot = res.rxSlot ?? null;
          attachSockRings(found);
        }
        if (res.peerCred) found.peerCred = res.peerCred;
        return 0;
      }
    } catch (err) { if (!(err instanceof Errno)) throw err; return err.errno; }
  },
  sock_shutdown: (fd, how) => {
    pause();
    try {
      const found = sockDescriptor(fd);
      sockCall('shutdown', { sockId: found.sockId, how: how >>> 0 });
      return 0;
    } catch (err) { if (!(err instanceof Errno)) throw err; return err.errno; }
  },
  sock_sendmsg: (fd, dataPtr, dataLen, fdsPtr, fdsLen, addrPtr, addrLen, flags, outSent) => {
    pause();
    try {
      const found = sockDescriptor(fd);
      const nFds = fdsLen >>> 0;
      if (nFds > SCM_MAX_FD) throw new Errno(EINVAL);
      const outPtr = checkWritable(outSent, 4);
      const data = (dataLen >>> 0) > 0 ? checkedSlice(dataPtr, dataLen) : new Uint8Array(0);
      const addr = (addrLen >>> 0) > 0 ? checkedString(addrPtr, addrLen) : null;
      const fdsList = [];
      if (nFds > 0) {
        const fPtr = checkWritable(fdsPtr, nFds * 4);
        const v = view();
        for (let i = 0; i < nFds; i++) fdsList.push(encodeSendFd(v.getUint32(fPtr + i * 4, true)));
      }
      const sent = sockSendMsg(found, data, fdsList, addr, flags >>> 0);
      view().setUint32(outPtr, sent, true);
      return 0;
    } catch (err) { if (!(err instanceof Errno)) throw err; return err.errno; }
  },
  sock_recvmsg: (fd, bufPtr, bufLen, fdsPtr, fdsCap, outFdsLen, outPeerPtr, flags, outRecv, outFlags) => {
    pause();
    try {
      const found = sockDescriptor(fd);
      const bLen = bufLen >>> 0;
      const cap = fdsCap >>> 0;
      const bPtr = bLen > 0 ? checkWritable(bufPtr, bLen) : 0;
      const fPtr = cap > 0 ? checkWritable(fdsPtr, cap * 4) : 0;
      const fdsLenPtr = checkWritable(outFdsLen, 4);
      const recvPtr = checkWritable(outRecv, 4);
      const flagsPtr = checkWritable(outFlags, 4);
      if (outPeerPtr) checkWritable(outPeerPtr, 12);
      const rawFlags = flags >>> 0;
      const cmsgCloexec = !!(rawFlags & MSG_CMSG_CLOEXEC);
      const availFds = Math.max(0, FD_MAX - fds.size);
      const effectiveMaxFds = Math.min(cap, availFds);
      const res = sockRecvMsg(found, bLen, effectiveMaxFds, rawFlags);
      const installed = [];
      let resFlags = res.outFlags ?? 0;
      for (const spec of res.fds) {
        try {
          installed.push(installReceivedFd(spec, cmsgCloexec));
        } catch {
          disposeUninstalledFd(spec);
          resFlags |= MSG_CTRUNC;
        }
      }
      const copyLen = Math.min(bLen, res.data.length);
      if (copyLen > 0) bytes().set(res.data.subarray(0, copyLen), bPtr);
      const v = view();
      for (let i = 0; i < installed.length; i++) v.setUint32(fPtr + i * 4, installed[i], true);
      v.setUint32(fdsLenPtr, installed.length, true);
      writePeerCred(outPeerPtr, res.peerCred);
      v.setUint32(recvPtr, res.reportedLen ?? copyLen, true);
      v.setUint32(flagsPtr, resFlags, true);
      return 0;
    } catch (err) { if (!(err instanceof Errno)) throw err; return err.errno; }
  },
  sock_peercred: (fd, outCred) => {
    pause();
    try {
      const found = sockDescriptor(fd);
      const cred = sockCall('peercred', { sockId: found.sockId });
      found.peerCred = cred;
      writePeerCred(outCred, cred);
      return 0;
    } catch (err) { if (!(err instanceof Errno)) throw err; return err.errno; }
  },
  sock_getsockname: (fd, bufPtr, bufLen, outLen) => {
    pause();
    try {
      const found = sockDescriptor(fd);
      const bLen = bufLen >>> 0;
      const bPtr = bLen > 0 ? checkWritable(bufPtr, bLen) : 0;
      const lPtr = checkWritable(outLen, 4);
      const { path } = sockCall('getsockname', { sockId: found.sockId });
      const encoded = encoder.encode(path ?? '');
      const take = Math.min(bLen, encoded.length);
      if (take > 0) bytes().set(encoded.subarray(0, take), bPtr);
      view().setUint32(lPtr, encoded.length, true);
      return 0;
    } catch (err) { if (!(err instanceof Errno)) throw err; return err.errno; }
  },
  sock_getpeername: (fd, bufPtr, bufLen, outLen) => {
    pause();
    try {
      const found = sockDescriptor(fd);
      const bLen = bufLen >>> 0;
      const bPtr = bLen > 0 ? checkWritable(bufPtr, bLen) : 0;
      const lPtr = checkWritable(outLen, 4);
      const { path } = sockCall('getpeername', { sockId: found.sockId });
      const encoded = encoder.encode(path ?? '');
      const take = Math.min(bLen, encoded.length);
      if (take > 0) bytes().set(encoded.subarray(0, take), bPtr);
      view().setUint32(lPtr, encoded.length, true);
      return 0;
    } catch (err) { if (!(err instanceof Errno)) throw err; return err.errno; }
  },
  sock_getsockopt: (fd, level, optname, outVal) => {
    pause();
    try {
      const found = sockDescriptor(fd);
      const outPtr = checkWritable(outVal, 4);
      const { val } = sockCall('getsockopt', { sockId: found.sockId, level: level >>> 0, optname: optname >>> 0 });
      view().setInt32(outPtr, val | 0, true);
      return 0;
    } catch (err) { if (!(err instanceof Errno)) throw err; return err.errno; }
  },
  sock_setsockopt: (fd, level, optname, val) => {
    pause();
    try {
      const found = sockDescriptor(fd);
      sockCall('setsockopt', { sockId: found.sockId, level: level >>> 0, optname: optname >>> 0, val: val | 0 });
      return 0;
    } catch (err) { if (!(err instanceof Errno)) throw err; return err.errno; }
  },
};

let started = false;
onmessage = ({ data }) => {
  if (started && data.guiDisposeCanvas) { pixelSurfaces.dispose(data.guiDisposeCanvas); return; }
  if (started && data.guiCanvas) { void pixelSurfaces.bind(data.guiCanvas); return; }
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
  channel = data.channel ? replyChannel(data.channel) : null;
  sockArena = data.sockArena ?? null;
  sockNotify = data.sockNotify ? new Int32Array(data.sockNotify) : null;
  const { stdin = {}, stdout = {}, stderr = {} } = data;
  const parent = data.fork ?? data.inherit;
  signals = new Signals(control, parent?.signals);
  if (data.inherit) signals.exec();
  let code = 0, signal;
  try {
    if (parent) {
      environ = parent.env;
      shares = new Shares(parent.shares);
      if (data.fork) snapshots = parent.snapshots;
      Object.assign(process, { argv: parent.argv, umask: parent.umask ?? process.umask });
      adopt(parent);
    } else {
      environ = Array.isArray(data.env) ? data.env : Object.entries(data.env ?? {}).map(([name, value]) => `${name}=${value}`);
      shares = data.shares ? new Shares(data.shares) : null;
      install(0, stdin.tty && ttyState ? terminalFd(1) : stdin.pipe ? { kind: 'pipe-in', pipe: new Pipe(stdin.pipe, process.pid), tty: !!stdin.tty } : { kind: 'in', tty: !!stdin.tty, data: stdin.data ?? new Uint8Array(0), pos: 0 }, true);
      install(1, stdout.tty && ttyState ? terminalFd(1) : stdout.pipe ? { kind: 'pipe-out', pipe: new Pipe(stdout.pipe, process.pid) } : { kind: 'out', fd: 1, tty: !!stdout.tty, closed: stdout.closed ? new Int32Array(stdout.closed) : null }, !(stdout.tty && ttyState));
      install(2, stderr.tty && ttyState ? terminalFd(2) : { kind: 'out', fd: 2, tty: !!stderr.tty }, !(stderr.tty && ttyState));
      install(3, { kind: 'preopen', preopen: true });
    }
    if (!data.fork) pause();
    await instantiate(data.module, data.memory, parent?.snapshot, data.startSection, data.memoryBytes);
    if (data.fork) engine.rewind({ pid: 0 });
    code = await run();
  } catch (err) {
    if (err instanceof Exit) ({ code, signal } = err);
    else {
      await drive(diagnostic(`${process.argv?.[0] ?? 'process'}: ${err?.message ?? err}\n`));
      ({ code, signal } = killedBy(SIGABRT));
    }
  }
  exiting = true;
  if (signal != null && channel) process.proc = host('cleanup', {}).token ?? process.proc;
  for (const fd of [...fds.keys()]) { try { await drive(uninstall(fd)); } catch {} }
  if (closing.length) { try { await drive(serverBatch([])); } catch {} }
  flush();
  postMessage({ exit: code, signal });
}

async function closeAll(descriptions) {
  for (const description of descriptions) {
    try { await drive(closeFd(adopted(description))); } catch {}
  }
  if (closing.length) { try { await drive(serverBatch([])); } catch {} }
  postMessage({ exit: 0 });
}

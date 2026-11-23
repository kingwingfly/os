import { asset } from '../release.js';
import { Signals, CONTROL_WORDS, bit, valid, ignoredByDefault, stoppedByDefault } from './signals.mjs';
// exec(2), as the page does it: programs of /usr/bin, built for wasm32-wasip1, each run as a
// process of its own (web/wasi/process.js, a Worker), with their arguments, environment, standard
// input and the terminal. The binary is compiled once, and each process instantiates it anew.
//
// A pipeline's processes run at once, each one's output the next one's input through a pipe
// (web/wasi/pipe.js), and the first may read the terminal: what is typed into the command line,
// a line at a time. Pipes are memory the page and its processes share, which a page may have
// only when isolated from other sites (web/_headers); where it is not, they run one after
// another, each given what the one before wrote, and nothing reads the terminal.
import { Pipe, pipeBuffer } from './pipe.js';
import {
  createSockArenaBuffer, initArenaSlot, fenceArenaSlot, releaseWorkerLocks,
  ArenaRing, HDR_RD_LOCK, HDR_WR_LOCK, HOST_LOCK_BIT,
} from './sock-arena.js';
import { Pty, TtyState, IOCTL, LF, IF } from '../kernel/pty.js';
import { PtyDevices } from '../kernel/ptmx.js';
import { Bytes, Shares } from './shared.js';
const kernelCall = (type, args) => globalThis.kernelRequest(type, args);
import { load, loadLocalBytes } from '../kernel/loader.js';
import { STRERROR } from '../http.mjs';
import { requireExecutionSupport } from '../kernel/capabilities.js';

// Executables are the build's own /usr/bin images by default; a stage may name its own path
// (an uploaded wasm the shell resolved against the working directory). Each process is a
// registry process: the client kernel asks for the pipeline's stages at once (execve, one
// request), and each one's token goes with every batch the process makes. The loader compiles
// once per immutable content.
// Why execve or the loader said no, as the shell says it: the name as typed, then glibc's words.
const refused = (name, error) => {
  const why = error.errno && error.message === error.errno ? (STRERROR[error.errno] ?? error.errno) : error.message;
  const tag = (error.errno === 'ENOTCONN' || error.errno === 'ENODEV') && !/offline|disconnected|ENODEV|ENOTCONN/.test(why)
    ? ` (${error.errno})`
    : '';
  return Object.assign(new Error(`${name}: ${why}${tag}`), { errno: error.errno });
};
// exit(2) of the process `pid`, then waitpid for it, so no zombie stays in the registry: both
// happen in the client kernel, which tells the browser's machine in a batch. The wait goes even
// when the exit fails: a process the machine already ended (kill(2) from another tab) is a
// zombie the exit cannot reach but the wait reaps. A forked process is its parent's to wait
// for: only once it is init's (its parent ended first) does its host reap it, as init would.
const reap = async (pid, { status, signal }, forked = false) => {
  let exitInfo = null;
  try { exitInfo = await kernelCall('exit', { pid, status, signal }); } catch { /* ended already */ }
  // Release AF_UNIX sockets AFTER `exit` marks the process dead and revokes its remote credentials,
  // so peers waking on socket EOF observe revoked attenuated descriptors deterministically (U-10).
  if (globalThis.kernel?.sock_release_process) {
    try { await applySockCleanup(await globalThis.kernel.sock_release_process(pid)); } catch { /* kernel torn down */ }
  }
  const shouldHostReap = typeof exitInfo?.host_reap === 'boolean'
    ? exitInfo.host_reap
    : (!forked || exitInfo?.ppid === 1);
  if (shouldHostReap) {
    try { await kernelCall('wait', { pid }); } catch { /* reaped already, or still running */ }
  }
  await reconcile();
  // A wait that waits on it hears it ended.
  wakeChildren();
};
// How many processes hosted here ended, and the waits that wait for the next: a wait4 that
// found its children running waits for one to end, and misses none that ended meanwhile.
let exits = 0;
const exited = new Set();
function wakeChildren() { exits++; for (const wake of [...exited]) wake(); exited.clear(); }
// wait4(2) of the process `ppid` for its child `pid`, or any: its status once it ends, or,
// with `nohang`, none if none ended yet.
async function join(ppid, pid, nohang, options = 0) {
  for (;;) {
    const seen = exits;
    try {
      const result = await kernelCall('process_call', { pid: ppid, call: { waitpid: { pid: pid ?? -1, options: options | (nohang ? 1 : 0) } } });
      if ('code' in result) {
        // SIGKILL ends the registry entry before a busy Worker releases its file
        // references. Complete that cleanup before its parent observes the exit
        // and closes what may now be the last shared writer.
        const child = hosted.get(result.pid);
        child?.kill(result.signal ?? SIG.KILL);
        await (child?.exited ?? completing.get(result.pid));
      }
      return result;
    } catch (error) {
      if (error.errno !== 'EAGAIN') return { errno: error.errno ?? 'EIO' };
      if (nohang) return { nothing: true };
    }
    if (exits === seen) await new Promise(resolve => exited.add(resolve));
  }
}
// The pipes this page's processes hold: what a process it ends held of them, it lets go, as a
// process's descriptors close when it dies (a killed Worker closes nothing itself).
const pipes = new Map();
// Instance-wide 8 MiB `SockArena` SAB (128 x 64 KiB slots) shared by every Worker in this OS
// instance from startup so unrelated Workers exchange `AF_UNIX` streams and arena-backed pipes
// over `SCM_RIGHTS` with zero mid-syscall SAB transfers (#55 L3b).
const sockArena = typeof SharedArrayBuffer === 'function' ? createSockArenaBuffer() : null;
const sockNotify = typeof SharedArrayBuffer === 'function' ? new Int32Array(new SharedArrayBuffer(4)) : null;
const notifySockets = () => {
  if (!sockNotify) return;
  Atomics.add(sockNotify, 0, 1);
  Atomics.notify(sockNotify, 0);
};
// Sentinel PID used to keep `PtyDevices` handles alive while queued inside `SCM_RIGHTS`.
const PTY_INFLIGHT_PID = -1;
const MSG_PEEK = 0x2;
// Unified PTY close path for both ordinary and in-flight last-master disposal so `/dev/pts/<N>`
// is always deregistered even when zero slave fds remain open.
async function closeInflightPty(handle) {
  let pair = null;
  try { pair = devices.get(PTY_INFLIGHT_PID, handle).pair; } catch { /* already closed */ }
  await devices.close(PTY_INFLIGHT_PID, handle).catch(() => {});
  if (pair?.masterClosed) {
    await kernelCall('pty_close', { index: pair.number }).catch(() => {});
  }
}
// Active arena-backed pipe slots: slot -> { gen, readers: Map<pid, n>, writers: Map<pid, n>, inflightR, inflightW }.
const arenaPipes = new Map();
function arenaPipeTotal(map) {
  let n = 0;
  for (const v of map.values()) n += v;
  return n;
}
function settleArenaPipe(slot, entry) {
  if (!sockArena || !entry) return;
  const rTotal = arenaPipeTotal(entry.readers) + entry.inflightR;
  const wTotal = arenaPipeTotal(entry.writers) + entry.inflightW;
  const ring = new ArenaRing(sockArena, slot, entry.gen, 1, sockNotify);
  if (rTotal === 0) ring.closeReader();
  if (wTotal === 0) ring.closeWriter();
  if (rTotal === 0 && wTotal === 0) {
    arenaPipes.delete(slot);
    try {
      const res = globalThis.kernel?.sock_arena_free_pipe?.(slot, entry.gen);
      if (res?.freed) fenceArenaSlot(sockArena, res.slot, res.expectedGen, res.gen, sockNotify);
    } catch { /* kernel torn down */ }
  }
  notifySockets();
}
function holdArenaPipe(slot, gen, end, pid, count = 1) {
  const entry = arenaPipes.get(slot);
  if (!entry || entry.gen !== gen) throw { errno: 'EBADF' };
  const map = end === 'r' ? entry.readers : entry.writers;
  map.set(pid, (map.get(pid) ?? 0) + count);
  if (sockArena) {
    const ring = new ArenaRing(sockArena, slot, gen, 1, sockNotify);
    if (end === 'r') ring.holdReader(count);
    else ring.holdWriter(count);
  }
}
function dropArenaPipe(slot, gen, end, pid, count = 1) {
  const entry = arenaPipes.get(slot);
  if (!entry || entry.gen !== gen) return;
  const map = end === 'r' ? entry.readers : entry.writers;
  const cur = map.get(pid) ?? 0;
  const taken = Math.min(cur, count);
  if (taken <= 0) return;
  if (cur - taken <= 0) map.delete(pid);
  else map.set(pid, cur - taken);
  if (sockArena) {
    const ring = new ArenaRing(sockArena, slot, gen, 1, sockNotify);
    if (end === 'r') ring.dropReader(taken);
    else ring.dropWriter(taken);
  }
  settleArenaPipe(slot, entry);
}
function releaseArenaPipes(pid) {
  for (const [slot, entry] of [...arenaPipes]) {
    if (sockArena) new ArenaRing(sockArena, slot, entry.gen, 1, sockNotify).releaseLocks(pid);
    const r = entry.readers.get(pid) ?? 0;
    const w = entry.writers.get(pid) ?? 0;
    if (r) dropArenaPipe(slot, entry.gen, 'r', pid, r);
    if (w) dropArenaPipe(slot, entry.gen, 'w', pid, w);
  }
}
async function applySockCleanup(res) {
  if (!res) return;
  const hasWork = (res.peerWrClosed?.length ?? 0) > 0
    || (res.peerRdClosed?.length ?? 0) > 0
    || (res.freedSlots?.length ?? 0) > 0
    || (res.droppedPtys?.length ?? 0) > 0
    || (res.droppedPipes?.length ?? 0) > 0;
  if (!hasWork) return;
  if (sockArena) {
    for (const s of res.peerWrClosed ?? []) new ArenaRing(sockArena, s.slot, s.gen, 1, sockNotify).closeWriter();
    for (const s of res.peerRdClosed ?? []) new ArenaRing(sockArena, s.slot, s.gen, 1, sockNotify).closeReader();
    for (const s of res.freedSlots ?? []) fenceArenaSlot(sockArena, s.slot, s.expectedGen, s.gen, sockNotify);
  }
  for (const p of res.droppedPtys ?? []) {
    await closeInflightPty(p.handle);
  }
  for (const p of res.droppedPipes ?? []) {
    const entry = arenaPipes.get(p.slot);
    if (entry && entry.gen === p.gen) {
      if (p.end === 'r') entry.inflightR = Math.max(0, entry.inflightR - 1);
      else entry.inflightW = Math.max(0, entry.inflightW - 1);
      if (sockArena) {
        const ring = new ArenaRing(sockArena, p.slot, p.gen, 1, sockNotify);
        if (p.end === 'r') ring.dropReader(1);
        else ring.dropWriter(1);
      }
      settleArenaPipe(p.slot, entry);
    }
  }
  notifySockets();
}
async function drainPendingSockCleanup() {
  if (!globalThis.kernel?.sock_drain_cleanup) return;
  try {
    const res = globalThis.kernel.sock_drain_cleanup();
    await applySockCleanup(res);
  } catch { /* kernel torn down */ }
}
// A process line's open files (web/wasi/shared.js): the table a process started here shares
// with what it forks, and what each of its descriptions is, as its processes said when they
// opened them ({gen, description}, by slot), so that what a process killed outright held last
// can be closed for it.
const line = () => ({ shares: new Shares(), descriptions: new Map() });
// Close what the process `pid` (its token `token`, its umask and sudo `as`) held last of its
// line's open files, as its exit would have: in a Worker of its own, as the process, before its
// parent hears it ended. The locks it held go first.
async function closeHeld(of, pid, token, as) {
  if (!of) return;
  for (const { description } of of.descriptions.values()) {
    if (description.bytes) new Bytes(description.bytes).release(pid);
  }
  const last = of.shares.release(pid).map(({ slot, gen }) => {
    const known = of.descriptions.get(slot);
    if (known?.gen !== gen) return null;
    of.descriptions.delete(slot);
    return known.description;
  }).filter(Boolean).filter(description => {
    if (description.kind !== 'file' || description.serverDev || description.cloud != null) return false;
    return description.kfd != null;
  });
  if (!last.length) return;
  const closer = new Worker(asset('/wasi-process.js'));
  await new Promise(resolve => {
    closer.onmessage = ({ data }) => { if ('exit' in data) resolve(); };
    closer.onerror = () => resolve();
    closer.postMessage({ close: last, pid, proc: token, ...as });
  });
  closer.terminate();
}
const known = buffer => {
  if (!pipes.has(buffer)) pipes.set(buffer, new Pipe(buffer));
  return pipes.get(buffer);
};
function release(pid) {
  for (const [buffer, pipe] of pipes) {
    pipe.release(pid);
    if (pipe.writerGone && pipe.readerGone) pipes.delete(buffer);
  }
}
// What a process's waiting call is answered with, in the memory it waits on: a JSON reply.
const CHANNEL = 1024 * 1024;
function respond(channel, reply) {
  const data = new TextEncoder().encode(JSON.stringify(reply ?? {}));
  const state = new Int32Array(channel, 0, 2);
  new Uint8Array(channel, 8).set(data.length <= CHANNEL - 8 ? data : new TextEncoder().encode('{"errno":"E2BIG"}'));
  Atomics.store(state, 1, data.length <= CHANNEL - 8 ? data.length : 17);
  Atomics.store(state, 0, 1);
  Atomics.notify(state, 0);
}
const encoder = new TextEncoder();
const toBase64 = data => {
  let text = '';
  for (let i = 0; i < data.length; i += 0x8000) text += String.fromCharCode(...data.subarray(i, i + 0x8000));
  return btoa(text);
};
const fromBase64 = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));
// One request and one acknowledgement per pipe chunk. The kernel cannot advance
// while the process worker is blocked on its pipe or terminal.
export function beginStorageTransfer(start) {
  let reply, acknowledge, rejectAck, cancelled = false;
  const first = new Promise(resolve => { reply = resolve; });
  const exchange = message => new Promise((resolve, reject) => {
    if (cancelled) { reject({ errno: 'EINTR' }); return; }
    acknowledge = resolve;
    rejectAck = reject;
    reply(message);
  });
  const adapter = {
    write: bytes => exchange({ write: toBase64(bytes) }),
    read: count => exchange({ read: count }),
  };
  Promise.resolve().then(() => start(adapter))
    .then(json => ({ ok: JSON.parse(json) }))
    .catch(err => ({ err: { errno: err?.errno ?? 'EIO' } }))
    .then(result => reply({ result }));
  return {
    first,
    advance: ack => new Promise(resolve => {
      reply = resolve;
      acknowledge(ack);
    }),
    cancel() { cancelled = true; rejectAck?.({ errno: 'EINTR' }); },
  };
}

// Signals, by Linux's numbers: those that end a process by default, and those that stop and
// continue one. A process ended by one exits 128 and its number.
const SIG = { HUP: 1, INT: 2, QUIT: 3, KILL: 9, PIPE: 13, TERM: 15, CONT: 18, STOP: 19, TSTP: 20 };
const ENDING = new Set([SIG.HUP, SIG.INT, SIG.QUIT, SIG.KILL, SIG.PIPE, SIG.TERM]);
const killedBy = signal => ({ code: 128 + signal, signal });
// A signal word's value once a signal ends the process (web/wasi/process.js), and how long a
// process has to heed it before its host ends it outright (a loop that makes no call).
const KILLED = 0x100, GRACE = 1000;

// The processes this tab hosts, by pid: a signal to one, from any tab or device, is told on the
// page's events line (app.js `os:signal`), and the tab that hosts it acts on it.
const hosted = new Map();
// The host owns one devpts namespace, including processes from independent runs.
// Keep loading stages visible to ownership changes before they have a Worker.
const pendingMemberships = new Map();
const terminalMembers = () => [...pendingMemberships.values(), ...hosted.values()];
function clearTerminal(sid, number) {
  for (const member of terminalMembers()) if (member.sid === sid && member.ctty === number) member.ctty = 0;
}
async function hangupTerminal(tty, resume, fallback = 0) {
  const sid = tty.session, pgrp = tty.control.pgrp || fallback;
  const recipients = terminalMembers().filter(p => !p.ended && p.sid === sid && p.pgid === pgrp);
  clearTerminal(sid, tty.number);
  tty.session = 0; tty.control.pgrp = 0;
  // Device-generated delivery uses each recipient's own proof, including when
  // the master holder and the slave's session belong to different accounts.
  if (!recipients.length) return;
  for (const signal of resume ? [SIG.HUP, SIG.CONT] : [SIG.HUP]) {
    await Promise.allSettled(recipients.map(p => kernelCall('kill', { pid: p.pid, from: p.pid, signal })));
  }
  await reconciling; await reconcile();
}
function signalTerminal(tty, number) {
  for (const member of terminalMembers()) if (member.sid === tty.session && member.pgid === tty.control.pgrp) {
    if (member.signal) member.signal(number);
    else void kernelCall('kill', { pid: member.pid, from: member.pid, signal: number }).catch(() => {});
  }
}
const devices = new PtyDevices({
  signal: signalTerminal,
  hangup: tty => hangupTerminal(tty, true),
});
// Retain an exiting host's completion while its shared descriptors are closing.
const completing = new Map();
export const deliverSignal = async ({ pid }) => {
  if (pid && !hosted.has(pid)) {
    await drainPendingSockCleanup();
    return;
  }
  await reconciling;
  await reconcile();
};

let reconciling;
export function reconcile() {
  if (!hosted.size) return drainPendingSockCleanup();
  if (reconciling) return reconciling;
  const checking = new Map(hosted);
  const versions = new Map([...checking].map(([pid, process]) => [pid, process.membershipVersion]));
  // Complete the sync reconciliation (and clear `reconciling = null`) BEFORE awaiting
  // `drainPendingSockCleanup()`, because last-master PTY disposal invokes `hangupTerminal()`
  // which awaits `reconciling` and calls `reconcile()`.
  const run = kernelCall('sync', { acknowledged: Object.fromEntries([...checking].map(([pid, process]) => [pid, [...process.received.values()]])) }).then(rows => {
    let acknowledge = false;
    const found = new Map(rows.map(row => [row.pid, row]));
    // Pass 1: terminate dead/zombie processes first so their pipes and PTY masters
    // close (and clear controlling terminals) before siblings/children receive SIGHUP/SIGCONT.
    for (const [pid, process] of checking) {
      if (hosted.get(pid) !== process) continue;
      const row = found.get(pid);
      if (!row) process.signal(SIG.KILL);
      else if (row.state === 'zombie') process.kill(row.signal ?? SIG.KILL);
    }
    // Pass 2: update live memberships and deliver queued signals.
    for (const [pid, process] of checking) {
      if (hosted.get(pid) !== process) continue;
      const row = found.get(pid);
      if (!row || row.state === 'zombie') continue;
      if (process.membershipVersion === versions.get(pid)) process.membership(row);
      // STOP/CONT come from the ordered, acknowledged queue too. Reapplying a
      // stale state snapshot here can stop a process again after `fg` resumes it.
      for (const event of row?.pending_signals ?? []) {
        if ((process.received.get(event.signal) ?? 0) < event.sequence) { process.signal(event.signal); process.received.set(event.signal, event.sequence); }
        acknowledge = true;
      }
    }
    if (acknowledge) setTimeout(() => { void reconcile(); }, 0);
  }).catch(() => {}).finally(() => { if (reconciling === run) reconciling = null; });
  reconciling = run;
  return run.then(() => drainPendingSockCleanup());
}

// Run the pipeline `stages`, each an argv, as `options` say: {cwd, home, user, sudo, umask;
// stdin, a string, or none for the terminal; tty, whether the last writes to the terminal;
// enough, how many lines of its output its reader takes, before it closes the pipe; cancelled,
// asked now and then (Ctrl+C); onOutput(fd, text), what the last writes to the terminal and any
// writes to standard error, as they write it; onTty(input), the terminal's input
// ({write(text), eof()}) while the pipeline may read it, and null after; onReading(), as the
// first waits on it; onJob(group), the pipeline's process group as it starts: {pids, signal(n),
// stoppable}, by which the shell stops, continues and ends it; onState(state), 'stopped' once
// every process of it is, 'running' as one goes on}. The last's exit status, and what it wrote
// if not to the terminal.
export async function exec(stages, options = {}) {
  requireExecutionSupport();
  const workspace = options.workspace;
  const sessionId = options.sessionId ?? workspace?.identity?.id ?? '';
  const tickets = new Set();
  const releaseTicket = async ticket => {
    if (ticket) await kernelCall('release_exec_ticket', { ticket }).catch(() => {});
  };
  const loadImage = async image => {
    if (image.resolvedAsset) {
      image.asset = image.resolvedAsset;
      if (image.resolvedExecPath) image.path = image.resolvedExecPath;
      return load(image);
    }
    if (!image.localExec) return load(image);
    const expected = image.localExec, admitted = image.local;
    if (!globalThis.crossOriginIsolated) {
      throw Object.assign(new Error('local execution requires cross-origin isolation'), { errno: 'ENOTSUP' });
    }
    // An older authority can ignore new request fields. Never run private code
    // with credentials that did not explicitly acknowledge this admission and
    // its cloud attenuation, even if a cloud executable exists at the same path.
    if (!admitted || admitted.digest !== expected.digest || admitted.size !== expected.size
      || typeof admitted.cloud !== 'boolean' || (admitted.cloud && !expected.cloud)
      || image.size !== expected.size || image.asset != null || image.fd != null || image.token_read != null) {
      throw Object.assign(new Error('authority did not confirm the requested local execution grant'), { errno: 'EACCES' });
    }
    const ticketKey = image.execTicket ?? expected.digest;
    const bytes = await kernelCall('take_local_exec_bytes', { ticket: ticketKey });
    if (!bytes) throw Object.assign(new Error('executable image is no longer available'), { errno: 'ESTALE' });
    return loadLocalBytes(expected.digest, bytes, async () => {
      const stillLive = await kernelCall('take_local_exec_bytes', { ticket: ticketKey, checkOnly: true });
      if (!stillLive) throw Object.assign(new Error('executable mount was detached'), { errno: 'ESTALE' });
    });
  };
  const { cwd = '/', home = '/', user = 'guest', stdin = null, sudo = false, umask = 0o022, tty = false, enough = null,
    cancelled = () => false, onTty = () => {}, onJob = () => {} } = options;
  // The shell's callbacks last as long as the run: a process that outlives it (a child left in
  // the background) is heard no more.
  let finished = false;
  const onOutput = (fd, text) => finished ? undefined : options.onOutput?.(fd, text);
  const onReading = () => { if (!finished) options.onReading?.(); };
  const onState = state => { if (!finished) options.onState?.(state); };
  const env = piped => ({
    HOME: home, USER: user, LOGNAME: user, PATH: '/usr/bin', SHELL: '/usr/bin/sh', LANG: 'C.UTF-8',
    TERM: piped ? 'dumb' : 'xterm-256color', COLUMNS: String(options.columns ?? 80), LINES: String(options.rows ?? 24),
    TZ: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
    ...options.environment,
    PWD: cwd,
  });
  const last = stages.length - 1, isolated = globalThis.crossOriginIsolated;
  let stdout = '', truncated = false, lines = 0, full = false, stopped = false;
  const truncatedBy = new Set();
  // Whether the last's reader, which takes only so much, has closed its end: the last hears
  // SIGPIPE at its next write and ends as a process does, closing what it has open (memory it
  // shares, where the page may share it; else the page ends it).
  const closed = isolated && enough != null && !tty ? new Int32Array(new SharedArrayBuffer(4)) : null;
  // The browser job owns its pipeline and descendants; a shell can split them
  // into several POSIX process groups within its session.
  const processes = [], forks = [];
  const group = () => [...processes, ...forks];
  let input = null, terminal = null, pgid = 0, foreground = true, savedForeground = 0;
  let consoleClosed = false;
  const memberships = new Map();
  const queuedJobSignals = new Set();
  let stopSignal = SIG.INT;
  // End every process still running, by `signal`.
  const stop = signal => { stopped = true; stopSignal = signal; for (const process of group()) process.kill(signal); };
  // Browser job controls apply to its whole process tree. PTY input signals below
  // instead address the foreground POSIX group. Stopping requires shared memory.
  const job = {
    foreground: active => { foreground = active; if (terminal && pgid && terminal.session) { if (active) terminal.control.pgrp = savedForeground || pgid; else if (group().some(p => p.pgid === terminal.control.pgrp)) { savedForeground = terminal.control.pgrp; terminal.control.pgrp = 0; } } },
    hangup: async () => {
      if (consoleClosed) return;
      consoleClosed = true;
      // Deliver hangup before waking a blocking read with EOF: otherwise a
      // process can exit successfully before its default SIGHUP is observed.
      if (terminal) { try { await releaseTerminal(true); } finally { terminal.close(); } }
      else await hangupWithoutTerminal();
    },
    get pids() {
      const ended = new Set(group().filter(process => process.ended).map(process => process.pid));
      const live = new Set();
      for (const process of group()) {
        if (!process.ended) live.add(process.pid);
      }
      for (const pid of memberships.keys()) {
        if (!ended.has(pid)) live.add(pid);
      }
      return [...live];
    },
    stoppable: !!isolated,
    signal: signal => {
      if (!valid(signal)) return;
      // SIGKILL also ends admitted stages whose image is still loading. Their
      // revoked-token response must settle as cancellation, not an image error.
      if (signal === SIG.KILL) stop(signal);
      if (!memberships.size) {
        if (signal === SIG.CONT) for (const stopped of [19, 20, 21, 22]) queuedJobSignals.delete(stopped);
        else if (stoppedByDefault.has(signal)) queuedJobSignals.delete(SIG.CONT);
        queuedJobSignals.add(signal); return;
      }
      const members = new Map([...memberships.values(), ...group()].map(p => [p.pid, p]));
      for (const process of members.values()) {
        if (process.ended) continue;
        if (!process.signal || [SIG.STOP, SIG.CONT].includes(signal)) {
          void kernelCall('kill', { pid: process.pid, from: process.pid, signal })
            .then(() => deliverSignal({ pid: process.pid })).catch(() => {});
          continue;
        }
        process.signal(signal);
        if (signal === SIG.KILL) void kernelCall('kill', { pid: process.pid, from: process.pid, signal }).catch(() => {});
      }
    },
  };
  // Stopped once every process still running is; running as one goes on.
  let state = 'running';
  const changed = () => {
    const live = group().filter(process => !process.ended);
    const now = live.length && live.every(process => process.stopped) ? 'stopped' : 'running';
    if (now !== state) { state = now; onState(now); }
    onJob(job);
  };
  onJob(job);
  if (isolated && (tty || stdin == null)) {
    terminal = new Pty({ state: options.terminalState ?? TtyState.create(options),
      echo: text => onOutput(0, text), signal: number => signalTerminal(terminal, number),
      mode: value => options.onMode?.(value) });
    if (options.columns && options.rows) terminal.state.resize(options);
    known(terminal.pipe.buffer);
  }
  // What a process writes when not to the terminal: the next one's, or the last's reader's,
  // which may want only so much.
  const collect = (text, isLast) => {
    stdout += text;
    if (!isLast || enough == null || full) return;
    for (let at = text.indexOf('\n'); at !== -1 && lines < enough; at = text.indexOf('\n', at + 1)) lines++;
    if (lines < enough) return;
    full = true;
    if (closed) Atomics.store(closed, 0, 1);
    else stop(SIG.PIPE);
  };
  // A process made for a stage whose pipeline ends before the stage starts runs no image: it
  // exits as a hostless process would, and is reaped, so that no process is left in the
  // registry. The stage's place in the pipeline takes the status that ended it.
  const abandon = image => { pendingMemberships.delete(image.pid); return reap(image.pid,
    stopped ? { status: 128 + stopSignal, signal: stopSignal } : { status: 126 }); };
  // Each stage's environment: a terminal's for the last one when it writes to the terminal.
  const environments = stages.map((_, index) => env(!(index === last && tty)));
  // execve of every stage at once: the worker kernel checks each image and snapshots the
  // credentials, in one request; each process's token goes with each batch the host makes for
  // it. A stage may name its own image (an uploaded wasm); the loader compiles it once per
  // content.
  // The internal boot callback supplies an already authorized reserved process.
  // Page execution options do not expose this callback or its private proof.
  const asked = options.prepare ? options.prepare() : (async () => {
    const replies = new Array(stages.length);
    const prepared = [];
    for (let index = 0; index < stages.length; index++) {
      const stage = stages[index];
      const argv = stage.argv ?? stage;
      const file = stage.path ?? argv[0] ?? '';
      const envMap = environments[index];
      const envList = Object.entries(envMap).map(([name, value]) => `${name}=${value}`);
      const searchPath = stage.searchPath ?? !file.includes('/');
      try {
        const resolved = await kernelCall('session_resolve_exec', {
          sessionId,
          file,
          argv,
          cwd,
          pathEnv: envMap.PATH ?? '/usr/bin',
          searchPath,
          sudo,
        });
        if (resolved.execTicket) tickets.add(resolved.execTicket);
        if (resolved.local && !resolved.asset && !globalThis.crossOriginIsolated) {
          throw Object.assign(new Error('local execution requires cross-origin isolation'), { errno: 'ENOTSUP' });
        }
        prepared.push({
          index,
          resolved,
          stage: {
            path: resolved.execPath,
            local: resolved.local ?? undefined,
            runtime: resolved.runtime,
            sessionId: sessionId || undefined,
            ...(index === 0 && options.serviceGrant ? { serviceGrant: options.serviceGrant } : {}),
            argv: resolved.argv,
            env: envList,
            cwd,
            cgroup: stage.cgroup,
          },
        });
      } catch (err) {
        replies[index] = { err };
      }
    }
    const registered = prepared.length
      ? await kernelCall('execs', { stages: prepared.map(p => p.stage), sudo })
      : [];
    for (let i = 0; i < prepared.length; i++) {
      const { index, resolved } = prepared[i];
      const result = registered[i];
      if (result?.ok) {
        result.ok.resolvedArgv = resolved.argv;
        result.ok.resolvedAsset = resolved.asset;
        result.ok.resolvedExecPath = resolved.execPath;
        result.ok.localExec = resolved.asset ? null : resolved.local;
        result.ok.execTicket = resolved.execTicket;
      }
      replies[index] = result;
    }
    return replies;
  })();
  const images = stages.map((stage, index) => asked.then(results => {
    const result = results[index];
    if (result?.ok) return result.ok;
    const error = result?.err ?? { errno: 'EIO', detail: 'no process was made' };
    throw Object.assign(new Error(error.detail ?? error.errno), error);
  }).catch(error => { throw refused((stage.argv ?? stage)[0], error); }));
  // A stage's refusal is its own to throw, when it starts, if it does.
  for (const image of images) image.catch(() => {});
  // What each stage was given, once it is used: a stage never started gives its process back.
  const taken = new Set();
  // A process this job hosts, in a Worker of its own: a stage's, or one a process of it forked
  // (`forked`, its start the parent's snapshot). `write` is where its output goes, as its
  // stage's does.
  const host = ({ pid, token, ppid, module, memory, memoryBytes, startSection = false, argv, write, forked, start, transfer = [], files = null, membership }) => {
    const worker = new Worker(asset('/wasi-process.js'));
    const decoders = { 1: new TextDecoder(), 2: new TextDecoder() };
    // Each writer has two small compositor credits. A killed worker cannot leak credits
    // needed by another writer, and fork children get their own bounded output channel.
    const outputCredit = isolated ? new Int32Array(new SharedArrayBuffer(4)) : null;
    if (outputCredit) Atomics.store(outputCredit, 0, 2);
    const releaseOutput = () => { if (outputCredit) { Atomics.add(outputCredit, 0, 1); Atomics.notify(outputCredit, 0); } };
    const displaying = new Set();
    const publish = (fd, text, tty = false) => {
      const done = Promise.resolve().then(() => (tty ? onOutput : write)(fd, text));
      displaying.add(done);
      void done.then(() => displaying.delete(done), () => displaying.delete(done));
      return done;
    };
    let settle, status = null, killing = null, stopVersion = 0;
    const exited = new Promise(resolve => { settle = resolve; });
    // The word it is signalled by (stopped, continued, ended: process.js); the memory its
    // waiting calls are answered in.
    const control = isolated ? new Int32Array(new SharedArrayBuffer(CONTROL_WORDS * 4)) : null;
    if (control) {
      // Delivery may precede Worker startup. Honor inherited ignore/mask state
      // immediately, including exec's reset of caught dispositions.
      const dispositions = new Signals(control, (start.fork ?? start.inherit)?.signals);
      if (start.inherit) dispositions.exec();
    }
    const channel = isolated ? new SharedArrayBuffer(8 + CHANNEL) : null;
    const ids = new Int32Array(isolated ? new SharedArrayBuffer(12) : new ArrayBuffer(12));
    const process = { uid: (membership ?? memberships.get(pid)).uid, received: new Map(), pid, ppid, token, files, stopped: false, ended: false, forked, exited, membershipVersion: 0,
      get pgid() { return Atomics.load(ids, 0); }, get sid() { return Atomics.load(ids, 1); },
      get ctty() { return Atomics.load(ids, 2); }, set ctty(value) { Atomics.store(ids, 2, value); },
      membership(row) {
        this.membershipVersion++;
        if (row.pid === pid && row.ppid != null) this.ppid = row.ppid;
        if (this.sid !== row.sid) this.ctty = 0;
        Atomics.store(ids, 0, row.pgid); Atomics.store(ids, 1, row.sid);
      },
      image: { module, memory, memoryBytes, startSection } };
    process.membership(membership ?? memberships.get(pid));
    process.ctty = (membership ?? memberships.get(pid)).ctty ?? 0;
    // An external kill can revoke this image before the host hears its signal. The
    // descriptor table belongs to its whole fork lineage: a surviving holder may close
    // its last references. If none survives, authority revocation closes the lineage.
    const cleanupToken = () => [...hosted.values()].find(peer => peer !== process &&
      peer.files === files && !peer.ended && !peer.ending)?.token ?? process.token;
    // It ended, by its exit status `code` or the signal `signal`: by its own exit, which closed
    // what it had open, or outright (a Worker that could not heed a signal, or failed), whose
    // open files its host closes for it. Its parent waits for it, or, init's, it is reaped at
    // once, as init would.
    let storageTransfer;
    const end = ({ code, signal }, outright = false) => {
      if (status != null) return;
      status = code;
      clearTimeout(killing);
      process.ended = true;
      storageTransfer?.cancel();
      completing.set(pid, exited);
      hosted.delete(pid);
      // The host bootstrap owns a whole pipeline. One stage exiting must not
      // hang up siblings that are still draining its output. A standalone shell
      // ending (or the last pipeline stage ending) releases that session's PTY.
      const ownsTerminal = terminal && process.ctty === terminal.number && process.pid === terminal.session;
      const hangup = terminal && ((ownsTerminal && !processes.includes(process)) ||
        (processes.includes(process) && processes.length === stages.length && processes.every(stage => stage.ended))) ? releaseTerminal(false) : Promise.resolve();
      worker.terminate();
      changed();
      // Recover any abandoned guest-Worker ring mutexes across ALL SockArena slots (streams AND
      // arena-pipes) without disturbing active host-side transactions tagged with `HOST_LOCK_BIT`.
      releaseWorkerLocks(sockArena, pid, sockNotify);
      // What it held of pipes goes as it goes, its locks too.
      release(pid);
      releaseArenaPipes(pid);
      for (const fd of [1, 2]) { const text = decoders[fd].decode(); if (text) void publish(fd, text); }
      const trackedPairs = [...devices.pairs.values()];
      const owned = trackedPairs.filter(pair => pair.terminal.session === pid);
      // Last-master close needs the owning session/foreground group to send
      // HUP+CONT, including when a stuck Worker could not close its own fds.
      const deviceCleanup = devices.release(pid).then(() => {
        for (const pair of trackedPairs) {
          if (pair.masterClosed) void kernelCall('pty_close', { index: pair.number }).catch(() => {});
        }
        return Promise.all(owned.filter(pair => pair.terminal.session === pid).map(pair => releaseTerminal(false, pair.terminal)));
      });
      const closing = Promise.all([hangup, deviceCleanup, outright ? closeHeld(files, pid, cleanupToken(), { umask, sudo }) : Promise.resolve()]);
      const reaped = closing.then(() => reap(pid, { status: code, signal }, forked));
      void Promise.allSettled([reaped, ...displaying]).then(() => { completing.delete(pid); settle(code); });
    };
    // A signal that ends it: heeded at its next call, as it exits; outright immediately for
    // uncatchable SIGKILL or after GRACE if it cannot heed a catchable signal.
    const kill = signal => {
      if (status != null || killing != null) return;
      process.ending = true;
      if (!control || signal === SIG.KILL) return end(killedBy(signal), true);
      Atomics.store(control, 0, KILLED | signal);
      Atomics.notify(control, 0);
      killing = setTimeout(() => end(killedBy(signal), true), GRACE);
    };
    // A call it waits on: answered in its channel.
    const vfsRequest = async args => {
      switch (args.op) {
        case 'openat': return await kernelCall('proc_openat', { pid, dirfd: args.dirfd, path: args.path, oflags: args.oflags, mode: args.mode, cloexec: !!args.cloexec });
        case 'statat': return await kernelCall('proc_statat', { pid, dirfd: args.dirfd, path: args.path, follow: args.follow !== false });
        case 'accessat': await kernelCall('proc_accessat', { pid, dirfd: args.dirfd, path: args.path, amode: args.amode, follow: args.follow !== false }); return {};
        case 'mkdirat': await kernelCall('proc_mkdirat', { pid, dirfd: args.dirfd, path: args.path, mode: args.mode }); return {};
        case 'mknodat': await kernelCall('proc_mknodat', { pid, dirfd: args.dirfd, path: args.path, mode: args.mode, rdev: args.rdev }); return {};
        case 'unlinkat': await kernelCall('proc_unlinkat', { pid, dirfd: args.dirfd, path: args.path, removedir: !!args.removedir }); return {};
        case 'renameat': await kernelCall('proc_renameat', { pid, olddirfd: args.olddirfd, oldpath: args.oldpath, newdirfd: args.newdirfd, newpath: args.newpath, flags: args.flags ?? 0 }); return {};
        case 'linkat': await kernelCall('proc_linkat', { pid, olddirfd: args.olddirfd, oldpath: args.oldpath, newdirfd: args.newdirfd, newpath: args.newpath, follow: !!args.follow }); return {};
        case 'symlinkat': await kernelCall('proc_symlinkat', { pid, target: args.target, newdirfd: args.newdirfd, linkpath: args.linkpath }); return {};
        case 'readlinkat': return { target: await kernelCall('proc_readlinkat', { pid, dirfd: args.dirfd, path: args.path }) };
        case 'utimensat': await kernelCall('proc_utimensat', { pid, dirfd: args.dirfd, path: args.path, atime: args.atime, mtime: args.mtime, follow: args.follow !== false }); return {};
        case 'cowfs_stream': {
          if (storageTransfer) throw { errno: 'EBUSY' };
          const { fd, request, arg } = args.ioctl;
          storageTransfer = beginStorageTransfer(adapter =>
            globalThis.kernel.proc_cowfs_stream(pid, fd, request, JSON.stringify(arg), adapter));
          const step = await storageTransfer.first;
          if (step.result) storageTransfer = null;
          return step;
        }
        case 'cowfs_ack': {
          if (!storageTransfer) throw { errno: 'EBADF' };
          const step = await storageTransfer.advance(args.ack);
          if (step.result) storageTransfer = null;
          return step;
        }
        case 'cowfs_cancel':
          storageTransfer?.cancel();
          storageTransfer = null;
          return {};
        case 'sys': return await kernelCall('proc_sys', { pid, batch: args.batch });
        case 'read': return { data: toBase64(await kernelCall('kfd_read', { pid, kfd: args.kfd, len: args.len })) };
        case 'write': return { written: await kernelCall('kfd_write', { pid, kfd: args.kfd, data: fromBase64(args.data) }) };
        case 'pread': return { data: toBase64(await kernelCall('kfd_pread', { pid, kfd: args.kfd, len: args.len, offset: args.offset })) };
        case 'pwrite': return { written: await kernelCall('kfd_pwrite', { pid, kfd: args.kfd, data: fromBase64(args.data), offset: args.offset }) };
        case 'seek': return { pos: await kernelCall('kfd_seek', { pid, kfd: args.kfd, offset: args.offset, whence: args.whence }) };
        case 'readdir': return { entries: await kernelCall('kfd_readdir', { pid, kfd: args.kfd }) };
        case 'fstat': return await kernelCall('kfd_fstat', { pid, kfd: args.kfd });
        case 'ftruncate': await kernelCall('kfd_ftruncate', { pid, kfd: args.kfd, size: args.size }); return {};
        case 'futimens': await kernelCall('kfd_futimens', { pid, kfd: args.kfd, atime: args.atime, mtime: args.mtime }); return {};
        case 'fsync': await kernelCall('kfd_fsync', { pid, kfd: args.kfd, dataOnly: !!args.dataOnly }); return {};
        case 'set_append': await kernelCall('kfd_set_append', { pid, kfd: args.kfd, append: !!args.append }); return {};
        case 'is_append': return { append: await kernelCall('kfd_is_append', { pid, kfd: args.kfd }) };
        case 'lock': await kernelCall('kfd_lock', { pid, kfd: args.kfd, family: args.family, kind: args.kind, start: args.start, end: args.end, wait: !!args.wait }); return {};
        case 'cancel': await kernelCall('kfd_cancel', { pid, kfd: args.kfd }); return {};
        case 'unlock': await kernelCall('kfd_unlock', { pid, kfd: args.kfd, family: args.family, start: args.start, end: args.end }); return {};
        case 'test_lock': return { conflict: await kernelCall('kfd_test_lock', { pid, kfd: args.kfd, kind: args.kind, start: args.start, end: args.end }) };
        case 'dup': return { kfd: await kernelCall('kfd_dup', { pid, kfd: args.kfd }) };
        case 'dup2': return { kfd: await kernelCall('kfd_dup2', { pid, oldKfd: args.oldKfd, newKfd: args.newKfd }) };
        case 'set_cloexec': await kernelCall('kfd_set_cloexec', { pid, kfd: args.kfd, cloexec: !!args.cloexec }); return {};
        case 'is_cloexec': return { cloexec: await kernelCall('kfd_is_cloexec', { pid, kfd: args.kfd }) };
        case 'close': await kernelCall('kfd_close', { pid, kfd: args.kfd }); return {};
        case 'set_umask': return { previous: await kernelCall('proc_set_umask', { pid, umask: args.umask }) };
        case 'chdir': await kernelCall('sys_chdir', { pid, path: args.path }); return {};
        case 'fchdir': await kernelCall('sys_fchdir', { pid, kfd: args.kfd }); return {};
        case 'chroot': await kernelCall('sys_chroot', { pid, path: args.path }); return {};
        case 'getcwd': return { cwd: await kernelCall('sys_getcwd', { pid }) };
        case 'mount': await kernelCall('sys_mount', { pid, source: args.source, target: args.target, fstype: args.fstype, flags: args.flags, data: args.data }); return {};
        case 'umount2': await kernelCall('sys_umount2', { pid, target: args.target, flags: args.flags }); return {};
        case 'statfs': return await kernelCall('sys_statfs', { pid, dirfd: args.dirfd, path: args.path });
        case 'fstatfs': return await kernelCall('sys_fstatfs', { pid, kfd: args.kfd });
        case 'unshare': await kernelCall('sys_unshare', { pid, flags: args.flags }); return {};
        case 'setns': await kernelCall('sys_setns', { pid, kfd: args.kfd, nstype: args.nstype }); return {};
        default: throw { errno: 'ENOSYS' };
      }
    };
    const answer = async ({ type, args }) => {
      let reply;
      try {
        if (type === 'vfs') {
          if (process.ended) throw { errno: 'EBADF' };
          reply = await vfsRequest(args);
        }
        else if (type === 'join') reply = await join(pid, args.pid, args.nohang, args.options);
        else if (type === 'process_call') {
          reply = args.waitpid
            ? await join(pid, args.waitpid.pid, !!(args.waitpid.options & 1), args.waitpid.options)
            : await kernelCall('process_call', { pid, call: args });
          if (reply?.pgid != null) hosted.get(reply.pid)?.membership(reply);
        }
        else if (type === 'cleanup') {
          await kernelCall('proc_close_server_fds', { pid }).catch(() => {});
          reply = { token: cleanupToken() };
        }
        else if (type === 'reconcile') { await reconciling; await reconcile(); reply = {}; }
        else if (type === 'getpid') reply = await kernelCall('getpid', { pid: args.pid });
        else if (type === 'getcreds') reply = await kernelCall('getcreds_proc', { pid });
        else if (type === 'resource') { await kernelCall('reserve_memory', { pid, bytes: args.memory }); reply = {}; }
        // kill(2) from a process is the process's, by its own credentials.
        else if (type === 'kill') {
          reply = (await kernelCall('kill', { pid: args.pid, signal: args.signal, from: pid })) ?? {};
          // A self-signal must be pending before kill returns. An older sync
          // may predate this request, so finish it before fetching delivery.
          await reconciling;
          await reconcile();
        }
        else if (type === 'exec') reply = await replace(args);
        else if (type === 'spawn') reply = await spawn(args);
        else if (type === 'tty') reply = await ttyRequest(process, args);
        else if (type === 'pty') reply = await ptyRequest(process, args);
        else if (type === 'sock') reply = await sockRequest(process, args);
        else reply = { errno: 'ENOSYS' };
      } catch (error) {
        reply = { errno: error.errno ?? 'EIO' };
      }
      // Zero and null are valid syscall results, not missing replies.
      respond(channel, reply ?? null);
    };
    // execve(2) of the process itself: resolves in the process's own MountNamespace + FsContext
    // (`root` & `cwd`) BEFORE calling `reexec`. If resolution or admission fails, `replace` throws
    // `{ errno }` so the caller receives `-errno` without unwinding its stack.
    const replace = async ({ file, path, argv: args, env, search = false }) => {
      if (process.ended) throw { errno: 'ESRCH' };
      const targetFile = file ?? path ?? args?.[0] ?? '';
      const pathEnv = env?.find(entry => entry.startsWith('PATH='))?.slice(5);
      const resolved = await kernelCall('proc_resolve_exec', {
        pid,
        file: targetFile,
        argv: args,
        pathEnv,
        searchPath: !!search,
      });
      try {
        return await replaceResolved(resolved, targetFile, env);
      } finally {
        await releaseTicket(resolved.execTicket);
      }
    };
    const replaceResolved = async (resolved, targetFile, env) => {
      if (resolved.local && !resolved.asset && !globalThis.crossOriginIsolated) {
        throw { errno: 'ENOTSUP', detail: 'local execution requires cross-origin isolation' };
      }
      if (process.ended) throw { errno: 'ESRCH' };
      let cwdNow = '/';
      let hasCwd = false;
      try {
        cwdNow = await kernelCall('sys_getcwd', { pid });
        hasCwd = true;
      } catch { /* cwd outside chroot: leave PWD untouched */ }
      const updatedEnv = hasCwd
        ? [...(env ?? []).filter(entry => !entry.startsWith('PWD=')), `PWD=${cwdNow}`]
        : [...(env ?? [])];
      let image;
      try {
        image = await kernelCall('reexec', {
          pid,
          path: resolved.execPath,
          local: resolved.local ?? null,
          argv: resolved.argv,
          env: updatedEnv,
          cwd: cwdNow,
        });
      } catch (error) {
        if (!error.execCommitted) throw error;
        worker.postMessage({ image: { error: refused(resolved.argv?.[0] ?? targetFile, error).message,
          argv: resolved.argv, env: updatedEnv } });
        return {};
      }
      image.resolvedArgv = resolved.argv;
      image.resolvedAsset = resolved.asset;
      image.resolvedExecPath = resolved.execPath;
      image.localExec = resolved.asset ? null : resolved.local;
      image.execTicket = resolved.execTicket;
      process.token = image.token;
      let loaded;
      try {
        loaded = await loadImage(image);
      } catch (error) {
        // The replacement already owns the credential. Its Worker still owns stdio and
        // must emit the loader diagnostic through fd 2 before closing/reaping normally.
        worker.postMessage({ image: { error: refused(resolved.argv?.[0] ?? targetFile, error).message,
          token: image.token, argv: resolved.argv, env: updatedEnv } });
        return {};
      }
      process.image = loaded;
      worker.postMessage({ image: { module: loaded.module, memory: loaded.memory, memoryBytes: loaded.memoryBytes, startSection: loaded.startSection, token: image.token, argv: resolved.argv, env: updatedEnv } });
      return {};
    };
    const checkInheritance = state => {
      const full = description => ['tty', 'pipe-in', 'pipe-out'].includes(description.kind)
        ? !known(description.buffer).holdable(0)
        : description.share != null && !files?.shares.holdable(description.share);
      if (state.descriptions.some(full)) throw Object.assign(new Error('no holder free'), { errno: 'EAGAIN' });
    };
    const holdInheritance = async (state, child) => {
      for (const description of state.descriptions) {
        if (description.kind === 'pty') devices.hold(pid, child, description.handle, description.refs);
        else if (description.kind === 'unix-sock') globalThis.kernel?.sock_hold?.(child, description.sockId, description.refs);
        else if (description.kind === 'arena-pipe-in') holdArenaPipe(description.slot, description.gen, 'r', child, description.refs);
        else if (description.kind === 'arena-pipe-out') holdArenaPipe(description.slot, description.gen, 'w', child, description.refs);
        else if (description.kind === 'pipe-in' || description.kind === 'tty') known(description.buffer).hold(child, 'r', description.refs);
        else if (description.kind === 'pipe-out') known(description.buffer).hold(child, 'w', description.refs);
        else if (description.share != null) files?.shares.add(description.share, child, description.refs);
      }
    };
    // posix_spawn: the same authorized fork/exec lifecycle, without copying guest memory.
    // The host derives credentials from this parent; the request cannot supply a token.
    const spawn = async state => {
      let child, membership, execTicket, held = false;
      const alive = () => {
        if (process.ended || killing != null || stopped) throw { errno: 'EINTR' };
      };
      try {
        alive();
        if (state.serviceGrant != null) await kernelCall('proc_authorize_service_grant', { pid });
        checkInheritance(state);
        child = await kernelCall('fork', { pid, emptyMemory: true });
        alive();
        if (state.serviceGrant != null) {
          await kernelCall('proc_apply_service_grant', { pid: child.pid, parentPid: pid, grant: state.serviceGrant });
          alive();
        }
        if (state.cwd) {
          let parentCwd = null;
          try { parentCwd = await kernelCall('sys_getcwd', { pid: child.pid }); } catch {}
          if (parentCwd !== state.cwd) {
            await kernelCall('sys_chdir', { pid: child.pid, path: state.cwd });
            alive();
          }
        }
        if (state.cgroup != null) {
          await kernelCall('process_call', { pid, call: { cgroup_attach: { pid: child.pid, path: state.cgroup } } });
          alive();
        }
        if (state.pgroup != null) {
          membership = await kernelCall('process_call', { pid, call: { setpgid: { pid: child.pid, pgid: state.pgroup } } });
          membership.ctty = process.ctty;
          alive();
        }
        const pathEnv = state.env?.find(entry => entry.startsWith('PATH='))?.slice(5);
        const resolved = await kernelCall('proc_resolve_exec', {
          pid: child.pid,
          file: state.argv[0],
          argv: state.argv,
          pathEnv,
          searchPath: !state.argv[0].includes('/'),
        });
        execTicket = resolved.execTicket;
        if (resolved.local && !resolved.asset && !globalThis.crossOriginIsolated) {
          throw { errno: 'ENOTSUP', detail: 'local execution requires cross-origin isolation' };
        }
        alive();
        // Allocate each dup2 destination in the child's table before releasing any source.
        for (const description of state.descriptions) {
          if (description.dupSource == null) continue;
          description.kfd = await kernelCall('kfd_dup', { pid: child.pid, kfd: description.dupSource });
          delete description.dupSource;
        }
        for (const kfd of state.keepOpenKfds ?? []) {
          await kernelCall('kfd_set_cloexec', { pid: child.pid, kfd, cloexec: false });
        }
        for (const kfd of state.closeKfds ?? []) {
          await kernelCall('kfd_close', { pid: child.pid, kfd });
        }
        const image = await kernelCall('reexec', {
          pid: child.pid,
          path: resolved.execPath,
          local: resolved.local ?? null,
          argv: resolved.argv,
          env: state.env,
          cwd: state.cwd ?? '/',
        });
        image.resolvedArgv = resolved.argv;
        image.resolvedAsset = resolved.asset;
        image.resolvedExecPath = resolved.execPath;
        image.localExec = resolved.asset ? null : resolved.local;
        image.execTicket = resolved.execTicket;
        child.token = image.token;
        alive();
        const loaded = await loadImage(image).catch(error => { throw { errno: error?.errno ?? 'ENOEXEC', detail: error.message }; });
        alive();
        await holdInheritance(state, child.pid);
        held = true;
        alive();
        const made = host({ pid: child.pid, token: child.token, ppid: pid, ...loaded, argv: resolved.argv,
          write, forked: true, start: { inherit: state }, files, membership: membership ?? process });
        forks.push(made);
        if (control && Atomics.load(control, 0) === 1) made.signal(SIG.STOP);
        changed();
        return { pid: child.pid };
      } catch (error) {
        if (child) {
          release(child.pid);
          releaseArenaPipes(child.pid);
          await devices.release(child.pid);
          if (globalThis.kernel?.sock_release_process) {
            await globalThis.kernel.sock_release_process(child.pid).then(res => applySockCleanup(res)).catch(() => {});
          }
          if (held) await closeHeld(files, child.pid, child.token, { umask: state.umask, sudo });
          await reap(child.pid, { status: 126 }, true);
          await kernelCall('waitchild', { ppid: pid, pid: child.pid }).catch(() => {});
        }
        throw error;
      } finally {
        await releaseTicket(execTicket);
      }
    };
    // fork(2): a child with a pid the client kernel gives, its parent's snapshot, and its pipes'
    // ends held for it before it starts.
    const fork = async state => {
      let child, held = false;
      try {
        // Each pipe and open file it shares must have a place for another holder (as many as a
        // namespace has processes): EAGAIN otherwise, as fork(2) says, before a pid is taken.
        checkInheritance(state);
        child = await kernelCall('fork', { pid });
        // The parent can end while registry admission is in flight. Do not let
        // its late child execute or retain a charged slot without a host.
        if (process.ended || killing != null) throw { errno: 'EINTR' };
        checkInheritance(state);
        await holdInheritance(state, child.pid);
        held = true;
        if (process.ended || killing != null) throw { errno: 'EINTR' };
        const made = host({ pid: child.pid, token: child.token, ppid: pid, ...process.image, argv: state.argv, write, forked: true, start: { fork: state }, transfer: [state.snapshot.memory], files, membership: process });
        forks.push(made);
        changed();
        worker.postMessage({ forked: { pid: child.pid } });
      } catch (error) {
        if (child) {
          release(child.pid);
          releaseArenaPipes(child.pid);
          await devices.release(child.pid);
          if (globalThis.kernel?.sock_release_process) {
            await globalThis.kernel.sock_release_process(child.pid).then(res => applySockCleanup(res)).catch(() => {});
          }
          if (held) await closeHeld(files, child.pid, child.token, { umask: state.umask, sudo });
          await reap(child.pid, { status: 126 }, true);
          await kernelCall('waitchild', { ppid: pid, pid: child.pid }).catch(() => {});
        }
        worker.postMessage({ forked: { errno: error.errno ?? 'EIO' } });
      }
    };
    worker.onmessage = ({ data }) => {
      if (data.out) {
        const shown = publish(data.fd, decoders[data.fd].decode(data.out, { stream: true }), data.tty);
        if (data.credit) void shown.then(releaseOutput, releaseOutput);
      }
      else if (data.ttyFds) void kernelCall('tty_fds', { pid, tty: terminal?.number, fds: data.ttyFds }).catch(() => {});
      else if (data.reading) onReading();
      else if (data.stopped || data.continued) {
        const version = ++stopVersion;
        // Only a caught/default job-control decision needs reporting. A STOP
        // delivered by the registry is already recorded; echoing it can race CONT.
        const recorded = data.stopped && data.cause !== SIG.STOP
          ? kernelCall('process_call', { pid, call: { proc_stopped: { signal: data.cause ?? SIG.STOP } } }).then(() => reconcile())
          : Promise.resolve();
        void recorded.catch(() => {}).then(() => {
          if (version !== stopVersion || process.ended) return;
          process.stopped = !!data.stopped; changed();
          wakeChildren();
        });
      }
      else if (data.truncated) { truncated = true; truncatedBy.add(argv[0]); }
      else if (data.described) files?.descriptions.set(data.described.slot, data.described);
      else if (data.closed) { if (files?.descriptions.get(data.closed.slot)?.gen === data.closed.gen) files.descriptions.delete(data.closed.slot); }
      else if (data.host) void answer(data.host);
      else if (data.fork) void fork(data.fork);
      else if ('exit' in data) end({ code: data.exit, signal: data.signal ?? undefined });
    };
    worker.onerror = event => { onOutput(2, `${argv[0]}: ${event.message}\n`); end({ code: 126 }, true); };
    // Catchable signals remain pending until a safe point. Only SIGKILL is
    // irrevocable. A handler or blocked disposition prevents the fallback kill.
    const signal = number => {
      if (!valid(number) || status != null) return;
      if (number === SIG.KILL) return kill(number);
      if (!control) return kill(number);
      const flag = bit(number);
      if (number === SIG.CONT) {
        Atomics.compareExchange(control, 0, 1, 0);
        Atomics.and(control, 1, ~(bit(19) | bit(20) | bit(21) | bit(22)));
      }
      if (stoppedByDefault.has(number)) Atomics.and(control, 1, ~bit(18));
      if (number === SIG.STOP) Atomics.compareExchange(control, 0, 0, 1);
      else if (!(Atomics.load(control, 3) & flag)) Atomics.or(control, 1, flag);
      Atomics.notify(control, 0);
      if (!ignoredByDefault.has(number) && number !== SIG.CONT && !stoppedByDefault.has(number)) {
        setTimeout(() => {
          if (status == null && Atomics.load(control, 0) === 0 && Atomics.load(control, 1) & flag &&
              !((Atomics.load(control, 2) | Atomics.load(control, 3) | Atomics.load(control, 4)) & flag)) kill(number);
        }, GRACE);
      }
    };
    Object.assign(process, { kill, signal });
    hosted.set(pid, process);
    pendingMemberships.delete(pid);
    // Signals can arrive while an image is loading, before it has a Worker.
    // Recover that delivery before entering user code, including for fork children.
    void (async () => {
      await reconciling; await reconcile();
      await kernelCall('proc_set_umask', { pid, umask }).catch(() => {});
      if (!process.ended) worker.postMessage({ ...start, module, memory, memoryBytes, startSection, argv, umask, sudo, pid, ppid, proc: token, stderr: { tty: !!terminal }, pty: terminal?.transferable, control: control?.buffer, outputCredit: outputCredit?.buffer, channel, membership: ids.buffer, shares: files?.shares.buffer, sockArena, sockNotify: sockNotify?.buffer }, transfer);
    })().catch(() => end({ code: 126 }, true));
    return process;
  };
  const releaseTerminal = (resume, tty = terminal) => {
    const fallback = tty === terminal ? savedForeground : 0;
    if (tty === terminal) savedForeground = 0;
    return hangupTerminal(tty, resume, fallback);
  };
  const hangupWithoutTerminal = async () => {
    const live = [...new Map([...memberships.values(), ...group()].map(p => [p.pid, p])).values()].filter(p => !p.ended);
    if (!live.length) return;
    for (const signal of [SIG.HUP, SIG.CONT]) await Promise.allSettled(live.map(p => kernelCall('kill', { pid: p.pid, from: p.pid, signal })));
    await reconciling; await reconcile();
  };
  const ptyRequest = async (process, args) => {
    const { op, handle } = args;
    const stat = (number = 0, uid = 0, mode = 0o020600) => ({ ino: number, uid, gid: 0, user: uid ? String(uid) : 'root', group: 'root', mode, nlink: 1, size: 0, mtime: 0, ctime: 0 });
    if (op === 'list') {
      const entries = [...devices.pairs.values()].filter(pair => !pair.masterClosed)
        .map(pair => ({ name: String(pair.number), stat: stat(pair.number, pair.uid) }));
      if (terminal && !terminal.closed) entries.unshift({ name: String(terminal.number), stat: stat(terminal.number, process.uid, 0o020620) });
      return { entries };
    }
    if (op === 'stat' || op === 'access') {
      let result;
      if (args.path === '/dev/pts') result = stat(0, 0, 0o040755);
      else {
        const target = devices.path(args.path, process.ctty);
        if (!target) throw { errno: args.path === '/dev/tty' ? 'ENXIO' : 'ENOENT' };
        result = stat(target.pair?.number, target.pair?.uid, target.master ? 0o020666 : 0o020600);
      }
      if (op === 'access') {
        if (!Number.isInteger(args.mode) || args.mode < 0 || args.mode > 7) throw { errno: 'EINVAL' };
        const allowed = process.uid === result.uid ? result.mode >> 6 & 7 : result.mode & 7;
        if (process.uid === 0 ? args.mode & 1 && !(result.mode & 0o111) : (allowed & args.mode) !== args.mode) throw { errno: 'EACCES' };
        return {};
      }
      return result;
    }
    if (op === 'open') {
      const opened = devices.open(process, args.path, args);
      const { pair, master } = devices.get(process.pid, opened.handle);
      if (master) {
        await kernelCall('pty_register', { index: pair.number, uid: pair.uid, gid: 0, mode: 0o600 }).catch(() => {});
      }
      if (!master && !args.noctty && !process.ctty && !pair.terminal.session && process.pid === process.sid && (opened.readable || process.uid === 0))
        await ttyRequest(process, { handle: opened.handle, request: IOCTL.TIOCSCTTY });
      return opened;
    }
    const description = devices.get(process.pid, handle);
    if (op === 'hold') { devices.hold(process.pid, process.pid, handle); return {}; }
    if (op === 'close') {
      const pair = description.pair;
      await devices.close(process.pid, handle);
      if (pair?.masterClosed) await kernelCall('pty_close', { index: pair.number }).catch(() => {});
      return {};
    }
    if (op === 'flags') {
      if (args.nonblock != null) description.nonblock = !!args.nonblock;
      return { nonblock: description.nonblock };
    }
    if (op === 'read') {
      const result = devices.read(process.pid, handle, args.count);
      return result instanceof Uint8Array ? { data: Array.from(result) } : result;
    }
    if (op === 'write') return devices.write(process.pid, handle, Uint8Array.from(args.data));
    if (op === 'poll') return devices.poll(process.pid, handle, args.writing);
    throw { errno: 'EINVAL' };
  };
  const sockRequest = async (process, args) => {
    const k = globalThis.kernel;
    if (!k) throw { errno: 'ENOSYS' };
    const { op } = args;
    const hostOwner = (HOST_LOCK_BIT | process.pid) | 0;
    const releaseInflightPipe = p => {
      const entry = arenaPipes.get(p.slot);
      if (entry && entry.gen === p.gen) {
        if (p.end === 'r') entry.inflightR = Math.max(0, entry.inflightR - 1);
        else entry.inflightW = Math.max(0, entry.inflightW - 1);
        if (sockArena) {
          const ring = new ArenaRing(sockArena, p.slot, p.gen, 1, sockNotify);
          if (p.end === 'r') ring.dropReader(1);
          else ring.dropWriter(1);
        }
        settleArenaPipe(p.slot, entry);
      }
    };
    const cleanupDeadRecv = async (res, peek) => {
      for (const fdSpec of res?.fds ?? []) {
        if (fdSpec.kind === 'kfd' || fdSpec.kind === 'server_dev') {
          await kernelCall('kfd_close', { pid: process.pid, kfd: fdSpec.kfd }).catch(() => {});
        } else if (fdSpec.kind === 'unix_sock') {
          await k.sock_close(process.pid, fdSpec.sockId, 1).then(c => applySockCleanup(c)).catch(() => {});
        } else if (fdSpec.kind === 'pty' && !peek) {
          await closeInflightPty(fdSpec.handle);
        } else if (fdSpec.kind === 'arena_pipe' && !peek) {
          releaseInflightPipe(fdSpec);
        }
      }
      await applySockCleanup(res);
      throw { errno: 'ESRCH' };
    };
    const transferRecvJsFds = async (res, peek) => {
      for (const fdSpec of res.fds ?? []) {
        if (fdSpec.kind === 'pty') {
          devices.hold(PTY_INFLIGHT_PID, process.pid, fdSpec.handle, 1);
          if (!peek) await closeInflightPty(fdSpec.handle);
        } else if (fdSpec.kind === 'arena_pipe') {
          if (peek) {
            holdArenaPipe(fdSpec.slot, fdSpec.gen, fdSpec.end, process.pid, 1);
          } else {
            const entry = arenaPipes.get(fdSpec.slot);
            if (entry && entry.gen === fdSpec.gen) {
              const map = fdSpec.end === 'r' ? entry.readers : entry.writers;
              map.set(process.pid, (map.get(process.pid) ?? 0) + 1);
              if (fdSpec.end === 'r') entry.inflightR = Math.max(0, entry.inflightR - 1);
              else entry.inflightW = Math.max(0, entry.inflightW - 1);
            }
          }
        }
      }
    };
    switch (op) {
      case 'pipe_alloc': {
        if (!sockArena) throw { errno: 'ENOSYS' };
        const res = k.sock_arena_alloc_pipe();
        initArenaSlot(sockArena, res.slot, res.gen, 1, 1, sockNotify);
        arenaPipes.set(res.slot, {
          gen: res.gen,
          readers: new Map([[process.pid, 1]]),
          writers: new Map([[process.pid, 1]]),
          inflightR: 0,
          inflightW: 0,
        });
        return res;
      }
      case 'pipe_hold':
        holdArenaPipe(args.slot, args.gen, args.end, process.pid, args.count ?? 1);
        return {};
      case 'pipe_close':
        dropArenaPipe(args.slot, args.gen, args.end, process.pid, args.count ?? 1);
        return {};
      case 'create':
        return k.sock_create(process.pid, args.sockType);
      case 'socketpair': {
        const res = k.sock_socketpair(process.pid, args.sockType);
        if (sockArena) {
          if (res.slotAB) initArenaSlot(sockArena, res.slotAB.slot, res.slotAB.gen, 1, 1, sockNotify);
          if (res.slotBA) initArenaSlot(sockArena, res.slotBA.slot, res.slotBA.gen, 1, 1, sockNotify);
        }
        return res;
      }
      case 'bind':
        return await k.sock_bind(process.pid, args.sockId, args.path);
      case 'listen':
        return k.sock_listen(process.pid, args.sockId, args.backlog);
      case 'connect': {
        const res = await k.sock_connect(process.pid, args.sockId, args.path);
        if (sockArena) {
          if (res.txSlot) {
            initArenaSlot(sockArena, res.txSlot.slot, res.txSlot.gen, 1, 1, sockNotify);
            const txRing = new ArenaRing(sockArena, res.txSlot.slot, res.txSlot.gen, 1, sockNotify);
            if (res.nonblock) txRing.setSockNonblock(true);
            if (res.peerPasscred) txRing.setPasscred(true);
          }
          if (res.rxSlot) {
            initArenaSlot(sockArena, res.rxSlot.slot, res.rxSlot.gen, 1, 1, sockNotify);
            if (res.clientPasscred) {
              new ArenaRing(sockArena, res.rxSlot.slot, res.rxSlot.gen, 1, sockNotify).setPasscred(true);
            }
          }
        }
        notifySockets();
        return res;
      }
      case 'accept': {
        const res = k.sock_accept(process.pid, args.sockId);
        if (!res.wouldBlock) notifySockets();
        return res;
      }
      case 'describe':
        return k.sock_describe(process.pid, args.sockId);
      case 'set_nonblock': {
        const res = k.sock_set_nonblock(process.pid, args.sockId, !!args.nonblock);
        if (sockArena && res?.txSlot) {
          new ArenaRing(sockArena, res.txSlot.slot, res.txSlot.gen, 1, sockNotify).setSockNonblock(!!res.nonblock);
        }
        return res;
      }
      case 'get_nonblock':
        return k.sock_get_nonblock(process.pid, args.sockId);
      case 'shutdown': {
        const res = await k.sock_shutdown(process.pid, args.sockId, args.how);
        if (sockArena) {
          if (res.closeTxWr && res.txSlot) {
            new ArenaRing(sockArena, res.txSlot.slot, res.txSlot.gen, 1, sockNotify).closeWriter();
          }
          if (res.closeRxRd && res.rxSlot) {
            const rx = new ArenaRing(sockArena, res.rxSlot.slot, res.rxSlot.gen, 1, sockNotify);
            rx.closeReader();
            rx.clearAncillary();
          }
        }
        await applySockCleanup(res);
        notifySockets();
        return res;
      }
      case 'hold':
        return k.sock_hold(process.pid, args.sockId, args.count ?? 1);
      case 'close': {
        const res = await k.sock_close(process.pid, args.sockId, args.count ?? 1);
        await applySockCleanup(res);
        notifySockets();
        return {};
      }
      case 'sendmsg': {
        // Never allow guest payload to supply or override peer credentials (`U-08`).
        const fdsList = Array.isArray(args.fds) ? args.fds : [];
        const heldPtys = [];
        const heldPipes = [];
        const rollback = async () => {
          for (const h of heldPtys) await closeInflightPty(h);
          for (const p of heldPipes) releaseInflightPipe(p);
        };
        let lockedRing = null;
        try {
          for (const spec of fdsList) {
            if (spec.kind === 'pty') {
              devices.hold(process.pid, PTY_INFLIGHT_PID, spec.handle, 1);
              heldPtys.push(spec.handle);
            } else if (spec.kind === 'arena_pipe') {
              const entry = arenaPipes.get(spec.slot);
              if (!entry || entry.gen !== spec.gen) throw { errno: 'EBADF' };
              const map = spec.end === 'r' ? entry.readers : entry.writers;
              if (!(map.get(process.pid) > 0)) throw { errno: 'EBADF' };
              if (spec.end === 'r') entry.inflightR++;
              else entry.inflightW++;
              if (sockArena) {
                const ring = new ArenaRing(sockArena, spec.slot, spec.gen, 1, sockNotify);
                if (spec.end === 'r') ring.holdReader(1);
                else ring.holdWriter(1);
              }
              heldPipes.push({ slot: spec.slot, gen: spec.gen, end: spec.end });
            }
          }
          // Resolve `txSlot` from kernel if the sender held a pre-connect snapshot of a shared stream.
          let txSlot = args.txSlot ?? null;
          if (!txSlot && sockArena && args.addr == null) {
            try {
              const info = k.sock_describe(process.pid, args.sockId);
              if (info?.sockType === 1 && info.txSlot) txSlot = info.txSlot;
            } catch { /* let sock_sendmsg return the authoritative errno */ }
          }
          // Atomic SOCK_STREAM SAB send with SCM_RIGHTS or SO_PASSCRED: validate & reserve quota
          // in Rust BEFORE copying payload into `txSlot` so failures leave zero partial bytes!
          if (txSlot && sockArena) {
            const ring = new ArenaRing(sockArena, txSlot.slot, txSlot.gen, hostOwner, sockNotify);
            if (!ring.alive || ring.rdClosed || ring.wrClosed) throw { errno: 'EPIPE' };
            const raw = args.data ? fromBase64(args.data) : new Uint8Array(0);
            if (raw.length === 0) {
              await rollback();
              return { sent: 0 };
            }
            if (ring.room === 0) throw { errno: 'EAGAIN' };
            if (!ring.lock(HDR_WR_LOCK)) throw { errno: 'EAGAIN' };
            lockedRing = ring;
            if (!ring.alive || ring.rdClosed || ring.wrClosed) throw { errno: 'EPIPE' };
            const chunkLen = Math.min(raw.length, ring.room);
            if (chunkLen === 0) throw { errno: 'EAGAIN' };
            const startOff = ring.headOffset;
            const endOff = startOff + chunkLen;
            const res = await k.sock_sendmsg(process.pid, args.sockId, JSON.stringify({
              data: '',
              fds: fdsList,
              sabSpan: [startOff, endOff],
            }));
            if (res.hasAncillary) ring.setAncillary(res.headAncillaryOffset);
            ring._copyIn(raw.subarray(0, chunkLen));
            notifySockets();
            return { ...res, sent: chunkLen };
          }
          const res = await k.sock_sendmsg(process.pid, args.sockId, JSON.stringify({
            data: args.data ?? '',
            fds: fdsList,
            addr: args.addr ?? null,
          }));
          // On SOCK_STREAM without SAB, a 0-byte send commits no bytes and drops ancillary fds;
          // SOCK_DGRAM / SOCK_SEQPACKET legitimately carry SCM_RIGHTS on 0-byte packets.
          if (res.sent === 0 && fdsList.length > 0 && !sockArena && !args.addr) {
            let isStream = false;
            try { isStream = k.sock_describe(process.pid, args.sockId)?.sockType === 1; } catch { /* ignore */ }
            if (isStream) await rollback();
          }
          if (res.targetRxSlot && res.hasAncillary && sockArena) {
            new ArenaRing(sockArena, res.targetRxSlot.slot, res.targetRxSlot.gen, 1, sockNotify).setAncillary(res.headAncillaryOffset);
          }
          notifySockets();
          return res;
        } catch (err) {
          await rollback();
          throw err;
        } finally {
          if (lockedRing) lockedRing.unlock(HDR_WR_LOCK);
        }
      }
      case 'recvmsg': {
        const peek = !!((args.flags ?? 0) & MSG_PEEK);
        if (args.sabStream && sockArena) {
          let rxSlot = args.rxSlot ?? null;
          if (!rxSlot) {
            const info = k.sock_describe(process.pid, args.sockId);
            rxSlot = info?.rxSlot ?? null;
          }
          if (rxSlot) {
            const ring = new ArenaRing(sockArena, rxSlot.slot, rxSlot.gen, hostOwner, sockNotify);
            if (!ring.lock(HDR_RD_LOCK)) return { wouldBlock: true, lockBusy: true };
            try {
              const safePeerCred = () => {
                try { return k.sock_peercred(process.pid, args.sockId); } catch { return { pid: 0, uid: 0, gid: 0 }; }
              };
              if (!ring.alive || ring.rdClosed) {
                return { data: '', reportedLen: 0, fds: [], peerCred: safePeerCred(), flags: 0 };
              }
              const tail = ring.tailOffset;
              const queued = ring.queued;
              if (queued === 0) {
                if (ring.wrClosed) {
                  return { data: '', reportedLen: 0, fds: [], peerCred: safePeerCred(), flags: 0 };
                }
                return { wouldBlock: true };
              }
              const bufLen = args.bufLen ?? 0;
              if (bufLen === 0) {
                return { data: '', reportedLen: 0, fds: [], peerCred: safePeerCred(), flags: 0 };
              }
              const res = await k.sock_recvmsg(process.pid, args.sockId, JSON.stringify({
                bufLen,
                maxFds: args.maxFds ?? 0,
                flags: args.flags ?? 0,
                sabRxTail: tail,
                cmsgCloexec: !!args.cmsgCloexec,
              }));
              if (process.ended) await cleanupDeadRecv(res, peek);
              if (!res.wouldBlock) {
                const take = Math.min(bufLen, res.maxStreamBytes ?? bufLen, ring.queued);
                const payload = take > 0 ? ring._copyOut(take, !peek) : new Uint8Array(0);
                if (res.hasNextAncillary) ring.setAncillary(res.nextAncillaryOffset);
                else ring.clearAncillary();
                res.data = payload.length ? toBase64(payload) : '';
                res.reportedLen = payload.length;
                await transferRecvJsFds(res, peek);
                await applySockCleanup(res);
              }
              return res;
            } finally {
              ring.unlock(HDR_RD_LOCK);
            }
          }
        }
        const res = await k.sock_recvmsg(process.pid, args.sockId, JSON.stringify({
          bufLen: args.bufLen ?? 0,
          maxFds: args.maxFds ?? 0,
          flags: args.flags ?? 0,
          sabRxTail: args.sabRxTail ?? null,
          cmsgCloexec: !!args.cmsgCloexec,
        }));
        if (process.ended) await cleanupDeadRecv(res, peek);
        if (!res.wouldBlock) {
          await transferRecvJsFds(res, peek);
          await applySockCleanup(res);
        }
        return res;
      }
      case 'peercred':
        return k.sock_peercred(process.pid, args.sockId);
      case 'getsockname':
        return { path: k.sock_getsockname(process.pid, args.sockId) };
      case 'getpeername':
        return { path: k.sock_getpeername(process.pid, args.sockId) };
      case 'getsockopt':
        return { val: k.sock_getsockopt(process.pid, args.sockId, args.level, args.optname) };
      case 'setsockopt': {
        const res = k.sock_setsockopt(process.pid, args.sockId, args.level, args.optname, args.val);
        if (sockArena && res?.rxSlot && typeof res.passcred === 'boolean') {
          new ArenaRing(sockArena, res.rxSlot.slot, res.rxSlot.gen, 1, sockNotify).setPasscred(res.passcred);
        }
        return res ?? {};
      }
      case 'poll':
        return k.sock_poll(process.pid, args.sockId, !!args.writing);
      case 'stats':
        return k.sock_stats();
      default:
        throw { errno: 'ENOSYS' };
    }
  };
  const ttyRequest = async (process, { request, arg, readable = true, handle }) => {
    const description = handle != null ? devices.get(process.pid, handle) : null;
    const tty = description?.pair.terminal ?? terminal;
    if (!tty) throw { errno: 'ENOTTY' };
    if (tty.closed && (request === 'open' || request === IOCTL.TIOCSCTTY)) throw { errno: 'EIO' };
    if (description) {
      readable = description.readable;
      if ([IOCTL.TIOCGPTN, IOCTL.TIOCSPTLCK, IOCTL.TIOCGPTLCK].includes(request)) return devices.ioctl(process.pid, handle, request, arg);
      if (description.master && [IOCTL.TIOCSCTTY, IOCTL.TIOCNOTTY].includes(request)) throw { errno: 'ENOTTY' };
      if (description.pair.masterClosed && request === IOCTL.TIOCSCTTY) throw { errno: 'EIO' };
    }
    const state = tty.state, control = tty.control;
    const controlling = () => process.ctty === tty.number && process.sid === tty.session;
    switch (request) {
      case 'open':
        if (!process.ctty && !tty.session && process.pid === process.sid && (readable || process.uid === 0)) {
          tty.session = process.sid; control.pgrp = process.pgid; process.ctty = tty.number;
          if (tty === terminal) savedForeground = process.pgid;
        }
        return {};
      case 'access': {
        if (description?.master || !controlling() || process.pgid === control.pgrp) return {};
        const number = typeof arg === 'object' ? arg.signal : arg;
        if (arg?.suppressed) { if (number === 21) throw { errno: 'EIO' }; return {}; }
        const members = terminalMembers().filter(p => !p.ended && p.pgid === process.pgid && p.sid === process.sid);
        const orphaned = !members.some(p => { const parent = hosted.get(p.ppid); return parent && parent.sid === p.sid && parent.pgid !== p.pgid; });
        if (orphaned) return { errno: 'EIO' };
        await kernelCall('kill', { pid: -process.pgid, from: process.pid, signal: number });
        await reconciling; await reconcile();
        return { signalled: true };
      }
      case IOCTL.TIOCGSID:
        if (!controlling()) throw { errno: 'ENOTTY' };
        return { sid: tty.session };
      case IOCTL.TIOCNOTTY:
        if (!controlling()) throw { errno: 'ENOTTY' };
        if (process.pid === process.sid) await releaseTerminal(true, tty);
        else process.ctty = 0;
        return {};
      case IOCTL.TIOCSCTTY: {
        if (arg != null && !Number.isInteger(arg)) throw { errno: 'EINVAL' };
        // The proof-checked bootstrap supplies uid; fork and exec preserve it.
        // A page login or a program's environment cannot change this snapshot.
        const privileged = process.uid === 0;
        if (process.ended) throw { errno: 'ESRCH' };
        if (process.pid === process.sid && tty.session === process.sid) return {};
        if (process.pid !== process.sid || process.ctty) throw { errno: 'EPERM' };
        if (tty.session && !(privileged && arg === 1) || !readable && !privileged) throw { errno: 'EPERM' };
        clearTerminal(tty.session, tty.number);
        tty.session = process.sid;
        control.pgrp = process.pgid; if (tty === terminal) savedForeground = process.pgid;
        process.ctty = tty.number;
        return {};
      }
      case IOCTL.TCGETS: return state.termios;
      case IOCTL.TCSETS: case IOCTL.TCSETSW: case IOCTL.TCSETSF:
        tty.configure(arg, request === IOCTL.TCSETSF); return {};
      case IOCTL.TIOCGWINSZ: return state.size;
      case IOCTL.TIOCSWINSZ: state.resize(arg); if (tty === terminal) options.onSize?.(state.size); return {};
      case IOCTL.TIOCGPGRP:
        if (!description?.master && !controlling()) throw { errno: 'ENOTTY' };
        return { pgrp: control.pgrp };
      case IOCTL.TIOCSPGRP:
        if (!controlling()) throw { errno: 'ENOTTY' };
        if (!Number.isInteger(arg) || arg <= 0) throw { errno: 'EINVAL' };
        if (!terminalMembers().some(p => !p.ended && p.pgid === arg && p.sid === process.sid)) throw { errno: 'EPERM' };
        control.pgrp = arg; if (tty === terminal) savedForeground = arg; return {};
      case IOCTL.TIOCGPTN: return { name: tty.name };
      case 'wasix': {
        const modes = state.termios;
        modes.lflag = arg.echo ? modes.lflag | LF.ECHO : modes.lflag & ~LF.ECHO;
        modes.lflag = arg.canonical ? modes.lflag | LF.ICANON : modes.lflag & ~LF.ICANON;
        modes.iflag = arg.lineFeeds ? modes.iflag | IF.IGNCR : modes.iflag & ~IF.IGNCR;
        tty.configure(modes); return {};
      }
      default: throw { errno: 'ENOTTY' };
    }
  };
  const start = async (index, io) => {
    const stage = stages[index], argv = stage.argv ?? stage;
    const environment = environments[index];
    let image;
    taken.add(index);
    try {
      image = await images[index];
      if (workspace && image.login_scope !== workspace.identity.id) throw { errno: 'EACCES', message: 'login changed during local workspace launch' };
      if (stopped) return await canceled(image);
      const { module, memory, memoryBytes, startSection } = await loadImage(image).catch(error => { throw refused(argv[0], error); })
        .finally(async () => {
          if (tickets.delete(image.execTicket)) await releaseTicket(image.execTicket);
        });
      if (stopped) return await canceled(image);
      // Hosts may require a fresh authorization after slow loading, before any guest code.
      if (options.beforeStart) await options.beforeStart(image.pid, image);
      if (stopped) return await canceled(image);
      const write = (fd, text) => {
        if (!text) return;
        // Background hosts can stream final stdout without allocating a PTY or collecting it.
        if (fd === 1 && !io.stdout.tty && !(index === last && options.streamOutput)) collect(text, index === last);
        else return onOutput(fd, text);
      };
      // Its pipes' ends are its own from the start: held for it before it runs.
      io.stdin.reader?.hold(image.pid, 'r');
      io.stdout.writer?.hold(image.pid, 'w');
      const effectiveArgv = image.resolvedArgv ?? argv;
      const process = host({ pid: image.pid, token: image.token, ppid: image.ppid ?? 1, module, memory, memoryBytes, startSection, argv: effectiveArgv, write, forked: false,
        start: { env: environment, cwd, stdin: io.stdin.message, stdout: io.stdout.message }, files: isolated ? line() : null });
      processes.push(process);
      changed();
      return process;
    } catch (error) {
      // Whatever was made for the stage ends here: no process may outlive a host that never
      // started, and none may wait for the next boot to be reaped. The ends of its pipes it
      // was to hold are gone.
      io.stdin.reader?.closeReader(); io.stdout.writer?.closeWriter();
      if (image && stopped) return canceled(image);
      if (image) await abandon(image);
      throw error;
    }
  };
  const canceled = async image => {
    await abandon(image);
    return { pid: image.pid, kill: () => {}, exited: Promise.resolve(128 + stopSignal) };
  };
  const watch = setInterval(() => { if (cancelled()) stop(SIG.INT); }, 100);
  const statuses = [];
  try {
    const ready = await Promise.all(images);
    const session = options.prepare ? ready.map(image => image.membership)
      : await kernelCall('session', { pids: ready.map(image => image.pid) });
    for (const row of session) { memberships.set(row.pid, row); pendingMemberships.set(row.pid, row); }
    pgid = session[0].pgid; savedForeground = pgid;
    onJob(job);
    if (terminal) terminal.session = session[0].sid;
    if (isolated) {
      // Resolve the leader before starting stages concurrently: every stage must inherit
      // the same slave number even if a later image loads first.
      if (terminal) {
        const leader = ready[0];
        terminal.state.number ??= leader.pid; terminal.number = terminal.state.number;
        await kernelCall('pty_register', { index: terminal.number, uid: session[0].uid ?? 0, gid: 0, mode: 0o620 }).catch(() => {});
        for (const member of memberships.values()) member.ctty = terminal.number;
        terminal.name = `/dev/pts/${terminal.number}`; pgid = leader.pid;
        if (foreground) terminal.control.pgrp = pgid;
      }
      // A pane can close while authentication or image loading is pending. Queue
      // hangup before fresh code starts, without reviving the closed master.
      if (consoleClosed) {
        if (terminal) { terminal.close(); await releaseTerminal(true); }
        else await hangupWithoutTerminal();
      }
      for (const signal of queuedJobSignals) job.signal(signal);
      queuedJobSignals.clear();
      // At once, through pipes; the first reads the terminal unless given its input.
      input = stdin == null ? terminal : null;
      // A program with redirected stdin can still read its controlling terminal by
      // opening /dev/tty. Keep the master attached independently of fd 0's source.
      if (terminal) {
        terminal.resize = size => { terminal.state.resize(size); options.onSize?.(terminal.state.size); };
        onTty(consoleClosed ? null : terminal);
        options.onMode?.({ raw: !terminal.state.canonical, echo: terminal.state.echo });
        options.onSize?.(terminal.state.size);
      }
      const links = stages.slice(1).map(() => pipeBuffer());
      const starting = [];
      for (let index = 0; index <= last; index++) {
        const from = index === 0 ? null : links[index - 1], to = index === last ? null : links[index];
        starting.push(start(index, {
          stdin: from ? { message: { pipe: from }, reader: known(from) }
            : input ? { message: { pipe: input.pipe.buffer, tty: true }, reader: known(input.pipe.buffer) }
            : { message: { data: encoder.encode(stdin) } },
          stdout: to ? { message: { pipe: to }, writer: known(to) } : { message: { tty, closed: closed?.buffer }, tty },
        }));
      }
      let started;
      try {
        started = await Promise.all(starting);
      } catch (error) {
        // A stage that failed ends the pipeline: stop the ones running, and wait for the ones
        // still being given a process to abandon theirs, so nothing outlives this run.
        stop(SIG.INT);
        await Promise.allSettled(starting);
        throw error;
      }
      // Each stage's status is its own, whatever order the processes end in.
      const exited = await Promise.all(started.map(process => process.exited));
      started.forEach((_, index) => { statuses[index] = exited[index]; });
    } else {
      if (consoleClosed) await hangupWithoutTerminal();
      for (const signal of queuedJobSignals) job.signal(signal);
      queuedJobSignals.clear();
      // One after another, each given what the one before wrote.
      let given = stdin ?? '';
      for (let index = 0; index <= last && !stopped; index++) {
        const piped = index < last;
        const process = await start(index, {
          stdin: { message: { data: encoder.encode(given), tty: index === 0 && stdin == null } },
          stdout: { message: { tty: !piped && tty }, tty: !piped && tty },
        });
        statuses.push(await process.exited);
        if (piped) { given = stdout; stdout = ''; }
      }
    }
  } finally {
    await asked.catch(() => {});
    await Promise.all([...tickets].map(releaseTicket));
    // What still runs, if starting one failed, ends with the pipeline; what was made for a
    // stage that never started is given back.
    for (const process of processes) process.kill(SIG.INT);
    images.forEach((image, index) => { if (!taken.has(index)) image.then(abandon, () => {}); });
    clearInterval(watch);
    job.foreground(false);
    terminal?.close();
    if (terminal?.number != null) void kernelCall('pty_close', { index: terminal.number }).catch(() => {});
    // A rejected image may never have acquired a reader, so no process release would
    // otherwise remove this master buffer from the host's bookkeeping.
    if (terminal && !terminal.pipe.held('r')) pipes.delete(terminal.pipe.buffer);
    if (terminal) onTty(null);
    finished = true;
  }
  return { status: statuses[last] ?? 128 + SIG.INT, stdout, truncated, truncatedBy: [...truncatedBy] };
}

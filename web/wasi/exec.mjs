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
import { Pty, TtyState, IOCTL, LF, IF } from '../kernel/pty.js';
import { PtyDevices } from '../kernel/ptmx.js';
import { Bytes, Shares } from './shared.js';
const kernelCall = (type, args) => globalThis.kernelRequest(type, args);
import { load } from '../kernel/loader.js';
import { STRERROR } from '../http.mjs';
import { resolveExecs } from './resolve.mjs';

// Executables are the build's own /usr/bin images by default; a stage may name its own path
// (an uploaded wasm the shell resolved against the working directory). Each process is a
// registry process: the client kernel asks for the pipeline's stages at once (execve, one
// request), and each one's token goes with every batch the process makes. The loader compiles
// once per immutable content.
// Why execve or the loader said no, as the shell says it: the name as typed, then glibc's words.
const refused = (name, error) => {
  const why = error.errno && error.message === error.errno ? (STRERROR[error.errno] ?? error.errno) : error.message;
  return Object.assign(new Error(`${name}: ${why}`), { errno: error.errno });
};
// exit(2) of the process `pid`, then waitpid for it, so no zombie stays in the registry: both
// happen in the client kernel, which tells the browser's machine in a batch. The wait goes even
// when the exit fails: a process the machine already ended (kill(2) from another tab) is a
// zombie the exit cannot reach but the wait reaps. A forked process is its parent's to wait
// for: only once it is init's (its parent ended first) does its host reap it, as init would.
const reap = async (pid, { status, signal }, forked = false) => {
  let parent = null;
  try { parent = (await kernelCall('exit', { pid, status, signal }))?.ppid ?? null; } catch { /* ended already */ }
  if (!forked || parent === 1) {
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
  }).filter(Boolean);
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
const CHANNEL = 64 * 1024;
function respond(channel, reply) {
  const data = new TextEncoder().encode(JSON.stringify(reply ?? {}));
  const state = new Int32Array(channel, 0, 2);
  new Uint8Array(channel, 8).set(data.length <= CHANNEL - 8 ? data : new TextEncoder().encode('{"errno":"E2BIG"}'));
  Atomics.store(state, 1, data.length <= CHANNEL - 8 ? data.length : 17);
  Atomics.store(state, 0, 1);
  Atomics.notify(state, 0);
}
const encoder = new TextEncoder();
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
  if (pid && !hosted.has(pid)) return;
  await reconciling;
  await reconcile();
};

let reconciling;
export function reconcile() {
  if (!hosted.size) return Promise.resolve();
  if (reconciling) return reconciling;
  const checking = new Map(hosted);
  const versions = new Map([...checking].map(([pid, process]) => [pid, process.membershipVersion]));
  return reconciling = kernelCall('sync', { acknowledged: Object.fromEntries([...checking].map(([pid, process]) => [pid, [...process.received.values()]])) }).then(rows => {
    let acknowledge = false;
    const found = new Map(rows.map(row => [row.pid, row]));
    for (const [pid, process] of checking) {
      if (hosted.get(pid) !== process) continue;
      const row = found.get(pid);
      if (!row) process.signal(SIG.KILL);
      else if (row.state === 'zombie') process.kill(row.signal ?? SIG.KILL);
      else if (process.membershipVersion === versions.get(pid)) process.membership(row);
      // STOP/CONT come from the ordered, acknowledged queue too. Reapplying a
      // stale state snapshot here can stop a process again after `fg` resumes it.
      for (const event of row?.pending_signals ?? []) {
        if ((process.received.get(event.signal) ?? 0) < event.sequence) { process.signal(event.signal); process.received.set(event.signal, event.sequence); }
        acknowledge = true;
      }
    }
    if (acknowledge) setTimeout(() => { void reconcile(); }, 0);
  }).catch(() => {}).finally(() => { reconciling = null; });
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
    get pids() { return group().filter(process => !process.ended).map(process => process.pid); },
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
  const asked = options.prepare ? options.prepare() : resolveExecs(
    stages.map((stage, index) => ({
      path: stage.path ?? (stage.argv ?? stage)[0],
      argv: stage.argv ?? stage,
      cgroup: stage.cgroup,
      env: Object.entries(environments[index]).map(([name, value]) => `${name}=${value}`),
      cwd,
    })),
    stages => kernelCall('execs', { stages, sudo }),
    abandon,
  );
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
    const end = ({ code, signal }, outright = false) => {
      if (status != null) return;
      status = code;
      clearTimeout(killing);
      process.ended = true;
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
      // What it held of pipes goes as it goes, its locks too.
      release(pid);
      for (const fd of [1, 2]) { const text = decoders[fd].decode(); if (text) void publish(fd, text); }
      const owned = [...devices.pairs.values()].filter(pair => pair.terminal.session === pid);
      // Last-master close needs the owning session/foreground group to send
      // HUP+CONT, including when a stuck Worker could not close its own fds.
      const deviceCleanup = devices.release(pid).then(() => Promise.all(owned
        .filter(pair => pair.terminal.session === pid).map(pair => releaseTerminal(false, pair.terminal))));
      const closing = Promise.all([hangup, deviceCleanup, outright ? closeHeld(files, pid, cleanupToken(), { umask, sudo }) : Promise.resolve()]);
      void closing.then(() => reap(pid, { status: code, signal }, forked));
      void Promise.allSettled([closing, ...displaying]).then(() => { completing.delete(pid); settle(code); });
    };
    // A signal that ends it: heeded at its next call, as it exits; outright if it cannot.
    const kill = signal => {
      if (status != null || killing != null) return;
      process.ending = true;
      if (!control) return end(killedBy(signal), true);
      Atomics.store(control, 0, KILLED | signal);
      Atomics.notify(control, 0);
      killing = setTimeout(() => end(killedBy(signal), true), GRACE);
    };
    // A call it waits on: answered in its channel.
    const answer = async ({ type, args }) => {
      let reply;
      try {
        if (type === 'join') reply = await join(pid, args.pid, args.nohang, args.options);
        else if (type === 'process_call') {
          reply = args.waitpid
            ? await join(pid, args.waitpid.pid, !!(args.waitpid.options & 1), args.waitpid.options)
            : await kernelCall('process_call', { pid, call: args });
          if (reply?.pgid != null) hosted.get(reply.pid)?.membership(reply);
        }
        else if (type === 'cleanup') reply = { token: cleanupToken() };
        else if (type === 'reconcile') { await reconciling; await reconcile(); reply = {}; }
        else if (type === 'getpid') reply = await kernelCall('getpid', { pid: args.pid });
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
        else reply = { errno: 'ENOSYS' };
      } catch (error) {
        reply = { errno: error.errno ?? 'EIO' };
      }
      // Zero and null are valid syscall results, not missing replies.
      respond(channel, reply ?? null);
    };
    // execve(2) of the process itself: the image the kernel allows, loaded, replaces its own. A
    // format the loader refuses once the kernel replaced the image ends the process, as an
    // execve past its point of no return does.
    const replace = async ({ path, argv: args, env, cwd }) => {
      const image = await kernelCall('reexec', { pid, path, argv: args, env, cwd });
      process.token = image.token;
      let loaded;
      try {
        loaded = await load(image);
      } catch (error) {
        // The replacement already owns the credential. Its Worker still owns stdio and
        // must emit the loader diagnostic through fd 2 before closing/reaping normally.
        worker.postMessage({ image: { error: refused(args[0] ?? path, error).message,
          token: image.token, argv: args, env } });
        return {};
      }
      process.image = loaded;
      worker.postMessage({ image: { module: loaded.module, memory: loaded.memory, memoryBytes: loaded.memoryBytes, startSection: loaded.startSection, token: image.token, argv: args, env } });
      return {};
    };
    const checkInheritance = state => {
      const full = description => ['tty', 'pipe-in', 'pipe-out'].includes(description.kind)
        ? !known(description.buffer).holdable(0)
        : description.share != null && !files?.shares.holdable(description.share);
      if (state.descriptions.some(full)) throw Object.assign(new Error('no holder free'), { errno: 'EAGAIN' });
    };
    const holdInheritance = (state, child) => {
      for (const description of state.descriptions) {
        if (description.kind === 'pty') devices.hold(pid, child, description.handle, description.refs);
        else if (description.kind === 'pipe-in' || description.kind === 'tty') known(description.buffer).hold(child, 'r', description.refs);
        else if (description.kind === 'pipe-out') known(description.buffer).hold(child, 'w', description.refs);
        else if (description.share != null) files?.shares.add(description.share, child, description.refs);
      }
    };
    // posix_spawn: the same authorized fork/exec lifecycle, without copying guest memory.
    // The host derives credentials from this parent; the request cannot supply a token.
    const spawn = async state => {
      let child, membership, held = false;
      const alive = () => {
        if (process.ended || killing != null || stopped) throw { errno: 'EINTR' };
      };
      try {
        alive();
        checkInheritance(state);
        child = await kernelCall('fork', { pid, emptyMemory: true });
        alive();
        if (state.cgroup != null) {
          await kernelCall('process_call', { pid, call: { cgroup_attach: { pid: child.pid, path: state.cgroup } } });
          alive();
        }
        if (state.pgroup != null) {
          membership = await kernelCall('process_call', { pid, call: { setpgid: { pid: child.pid, pgid: state.pgroup } } });
          membership.ctty = process.ctty;
          alive();
        }
        const [result] = await resolveExecs([{ path: state.argv[0], argv: state.argv, env: state.env, cwd: state.cwd }],
          stages => Promise.all(stages.map(async stage => {
            alive();
            try { return { ok: await kernelCall('reexec', { pid: child.pid, ...stage }) }; }
            catch (err) { return { err }; }
          })));
        if (result.err) throw result.err;
        child.token = result.ok.token;
        alive();
        const loaded = await load(result.ok).catch(error => { throw { errno: 'ENOEXEC', detail: error.message }; });
        alive();
        holdInheritance(state, child.pid);
        held = true;
        const made = host({ pid: child.pid, token: child.token, ppid: pid, ...loaded, argv: state.argv,
          write, forked: true, start: { inherit: state }, files, membership: membership ?? process });
        forks.push(made);
        if (control && Atomics.load(control, 0) === 1) made.signal(SIG.STOP);
        changed();
        return { pid: child.pid };
      } catch (error) {
        if (child) {
          release(child.pid);
          await devices.release(child.pid);
          if (held) await closeHeld(files, child.pid, child.token, { umask: state.umask, sudo });
          await reap(child.pid, { status: 126 }, true);
          await kernelCall('waitchild', { ppid: pid, pid: child.pid }).catch(() => {});
        }
        throw error;
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
        holdInheritance(state, child.pid);
        held = true;
        const made = host({ pid: child.pid, token: child.token, ppid: pid, ...process.image, argv: state.argv, write, forked: true, start: { fork: state }, transfer: [state.snapshot.memory], files, membership: process });
        forks.push(made);
        changed();
        worker.postMessage({ forked: { pid: child.pid } });
      } catch (error) {
        if (child) {
          release(child.pid);
          await devices.release(child.pid);
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
      if (!process.ended) worker.postMessage({ ...start, module, memory, memoryBytes, startSection, argv, umask, sudo, pid, ppid, proc: token, stderr: { tty: !!terminal }, pty: terminal?.transferable, control: control?.buffer, outputCredit: outputCredit?.buffer, channel, membership: ids.buffer, shares: files?.shares.buffer }, transfer);
    })().catch(() => end({ code: 126 }, true));
    return process;
  };
  const releaseTerminal = (resume, tty = terminal) => {
    const fallback = tty === terminal ? savedForeground : 0;
    if (tty === terminal) savedForeground = 0;
    return hangupTerminal(tty, resume, fallback);
  };
  const hangupWithoutTerminal = async () => {
    const members = new Map([...memberships.values(), ...group()].map(p => [p.pid, p]));
    for (const signal of [SIG.HUP, SIG.CONT]) await Promise.allSettled([...members.values()]
      .filter(p => !p.ended).map(p => kernelCall('kill', { pid: p.pid, from: p.pid, signal })));
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
      if (!master && !args.noctty && !process.ctty && !pair.terminal.session && process.pid === process.sid && (opened.readable || process.uid === 0))
        await ttyRequest(process, { handle: opened.handle, request: IOCTL.TIOCSCTTY });
      return opened;
    }
    const description = devices.get(process.pid, handle);
    if (op === 'hold') { devices.hold(process.pid, process.pid, handle); return {}; }
    if (op === 'close') { await devices.close(process.pid, handle); return {}; }
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
      if (stopped) return await canceled(image);
      const { module, memory, memoryBytes, startSection } = await load(image).catch(error => { throw refused(argv[0], error); });
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
      const process = host({ pid: image.pid, token: image.token, ppid: image.ppid ?? 1, module, memory, memoryBytes, startSection, argv, write, forked: false,
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
    if (terminal) terminal.session = session[0].sid;
    if (isolated) {
      // Resolve the leader before starting stages concurrently: every stage must inherit
      // the same slave number even if a later image loads first.
      if (terminal) {
        const leader = ready[0];
        terminal.state.number ??= leader.pid; terminal.number = terminal.state.number;
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
    // What still runs, if starting one failed, ends with the pipeline; what was made for a
    // stage that never started is given back.
    for (const process of processes) process.kill(SIG.INT);
    images.forEach((image, index) => { if (!taken.has(index)) image.then(abandon, () => {}); });
    clearInterval(watch);
    job.foreground(false);
    terminal?.close();
    // A rejected image may never have acquired a reader, so no process release would
    // otherwise remove this master buffer from the host's bookkeeping.
    if (terminal && !terminal.pipe.held('r')) pipes.delete(terminal.pipe.buffer);
    if (terminal) onTty(null);
    finished = true;
  }
  return { status: statuses[last] ?? 128 + SIG.INT, stdout, truncated, truncatedBy: [...truncatedBy] };
}

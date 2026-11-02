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
import { kernelCall } from '../kernel/protocol.js';
import { load } from '../kernel/loader.js';
import { STRERROR } from '../http.mjs';

// Executables are the build's own /usr/bin images by default; a stage may name its own path
// (an uploaded wasm the shell resolved against the working directory). Each process is a
// registry process: the client kernel asks the worker kernel for it (execve), and its token
// goes with every batch the process makes. The loader compiles once per immutable content.
const COREUTILS = '/usr/bin/coreutils';
// Why execve or the loader said no, as the shell says it: the name as typed, then glibc's words.
const refused = (name, error) => {
  const why = error.errno && error.message === error.errno ? (STRERROR[error.errno] ?? error.errno) : error.message;
  return Object.assign(new Error(`${name}: ${why}`), { errno: error.errno });
};
// exit(2) of the process `pid`, then waitpid for it, so no zombie stays in the registry. The
// wait goes even when the exit fails: a process the registry already ended (kill(2) from
// another tab, whose token is then dead) is a zombie the exit cannot reach but the wait reaps.
const reap = async (pid, { status, signal }) => {
  try { await kernelCall('exit', { pid, status, signal }); } catch { /* ended already */ }
  try { await kernelCall('wait', { pid }); } catch { /* reaped already, or still running */ }
};
const encoder = new TextEncoder();
// Status of a process killed by a signal: 128 and its number.
const SIGINT = 130, SIGPIPE = 141;
// Signals, by Linux's numbers: those that end a process by default, and those that stop and
// continue one.
const SIG = { HUP: 1, INT: 2, QUIT: 3, KILL: 9, PIPE: 13, TERM: 15, CONT: 18, STOP: 19, TSTP: 20 };
const ENDING = new Set([SIG.HUP, SIG.INT, SIG.QUIT, SIG.KILL, SIG.PIPE, SIG.TERM]);

// The processes this tab hosts, by pid: a signal to one, from any tab or device, is told on the
// page's events line (app.js `terminal:signal`), and the tab that hosts it acts on it.
const hosted = new Map();
globalThis.addEventListener?.('terminal:signal', ({ detail }) => hosted.get(detail?.pid)?.signal(detail.signal));

// How many columns the terminal's transcript has, for programs that lay out their output.
function columns() {
  const transcript = document.querySelector('.transcript') ?? document.body;
  // A line of the transcript's own, measured.
  const probe = document.createElement('pre');
  probe.textContent = '0'.repeat(10);
  probe.style.cssText = 'position:absolute;visibility:hidden;white-space:pre;width:auto';
  transcript.append(probe);
  const width = probe.getBoundingClientRect().width / 10 || 12;
  probe.remove();
  const style = getComputedStyle(transcript);
  const inner = transcript.clientWidth - parseFloat(style.paddingLeft || 0) - parseFloat(style.paddingRight || 0);
  return Math.max(20, Math.floor((inner || 800) / width));
}

// The terminal's input, which the page writes typed lines to: what does not fit yet waits, and
// Ctrl+D ends a read after what was typed before it, and before what is typed after it.
function terminalInput() {
  const pipe = new Pipe(pipeBuffer()), queue = [];
  let timer = 0;
  const pump = () => {
    timer = 0;
    // Nothing reads it any more: what was typed goes nowhere.
    if (pipe.readerGone) { queue.length = 0; return; }
    while (queue.length) {
      if (queue[0] === null) { pipe.endOfFile(); queue.shift(); continue; }
      // What follows Ctrl+D waits until a read has ended with it.
      if (pipe.ending) break;
      const put = pipe.put(queue[0]);
      if (put < queue[0].length) { queue[0] = queue[0].subarray(put); break; }
      queue.shift();
    }
    if (queue.length) timer = setTimeout(pump, 20);
  };
  const send = item => { queue.push(item); if (!timer) pump(); };
  return { pipe, write: text => send(encoder.encode(text)), eof: () => send(null), close: () => { clearTimeout(timer); pipe.closeWriter(); } };
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
    cancelled = () => false, onOutput = () => {}, onTty = () => {}, onReading = () => {}, onJob = () => {},
    onState = () => {} } = options;
  const env = piped => ({
    PWD: cwd, HOME: home, USER: user, LOGNAME: user, PATH: '/usr/bin', SHELL: '/usr/bin/sh', LANG: 'C.UTF-8',
    TERM: piped ? 'dumb' : 'xterm-256color', COLUMNS: String(columns()),
    TZ: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
  });
  const last = stages.length - 1, isolated = globalThis.crossOriginIsolated;
  let stdout = '', truncated = false, lines = 0, full = false, stopped = false;
  // Whether the last's reader, which takes only so much, has closed its end: the last hears
  // SIGPIPE at its next write and ends as a process does, closing what it has open (memory it
  // shares, where the page may share it; else the page ends it).
  const closed = isolated && enough != null && !tty ? new Int32Array(new SharedArrayBuffer(4)) : null;
  const processes = [];
  let stopStatus = SIGINT;
  // Stop every process still running, as `status` would end it.
  const stop = status => { stopped = true; stopStatus = status; for (const process of processes) process.kill(status); };
  // The pipeline as a process group: a signal to it is to each of its processes; one that ends
  // a process ends the pipeline. Stopping needs memory shared with the processes.
  const group = {
    get pids() { return processes.map(process => process.pid); },
    stoppable: !!isolated,
    signal: signal => {
      if (ENDING.has(signal)) return stop(128 + signal);
      for (const process of processes) process.signal(signal);
    },
  };
  // Stopped once every process still running is; running as one goes on.
  let state = 'running';
  const changed = () => {
    const live = processes.filter(process => !process.ended);
    const now = live.length && live.every(process => process.stopped) ? 'stopped' : 'running';
    if (now !== state) { state = now; onState(now); }
  };
  onJob(group);
  // What a process writes when not to the terminal: the next one's, or the last's reader's,
  // which may want only so much.
  const collect = (text, isLast) => {
    stdout += text;
    if (!isLast || enough == null || full) return;
    for (let at = text.indexOf('\n'); at !== -1 && lines < enough; at = text.indexOf('\n', at + 1)) lines++;
    if (lines < enough) return;
    full = true;
    if (closed) Atomics.store(closed, 0, 1);
    else stop(SIGPIPE);
  };
  // A process made for a stage whose pipeline ends before the stage starts runs no image: it
  // exits as a hostless process would, and is reaped, so that no process is left in the
  // registry. The stage's place in the pipeline takes the status that ended it.
  const abandon = image => reap(image.pid, { status: 126 });
  const start = async (index, io) => {
    const stage = stages[index], argv = stage.argv ?? stage;
    const decoders = { 1: new TextDecoder(), 2: new TextDecoder() };
    const environment = env(!io.stdout.tty);
    let image, worker;
    try {
      // execve: the worker kernel checks the image and snapshots the credentials; the process's
      // token goes with each batch the host makes for it. A stage may name its own image (an
      // uploaded wasm); the loader compiles it once per content.
      image = await kernelCall('exec', {
        path: stage.path ?? COREUTILS,
        argv,
        env: Object.entries(environment).map(([name, value]) => `${name}=${value}`),
        cwd,
        sudo,
      }).catch(error => { throw refused(argv[0], error); });
      if (stopped) return await canceled(image);
      const { module, memory } = await load(image).catch(error => { throw refused(argv[0], error); });
      if (stopped) return await canceled(image);
      worker = new Worker('/wasi-process.js');
      let settle, status = null;
      const exited = new Promise(resolve => { settle = resolve; });
      // The word that stops it, set by SIGSTOP and SIGTSTP, cleared by SIGCONT.
      const control = isolated ? new Int32Array(new SharedArrayBuffer(4)) : null;
      const process = { stopped: false, ended: false };
      const write = (fd, text) => { if (!text) return; if (fd === 1 && !io.stdout.tty) collect(text, index === last); else onOutput(fd, text); };
      const end = code => {
        if (status != null) return;
        status = code;
        process.ended = true;
        hosted.delete(image.pid);
        worker.terminate();
        changed();
        // What a killed process leaves open, its pipes, closes as it goes.
        io.stdin.reader?.closeReader(); io.stdout.writer?.closeWriter();
        for (const fd of [1, 2]) write(fd, decoders[fd].decode());
        // exit(2), then wait for it: the registry reaps the zombie at once, as init would.
        const signal = code >= 128 ? code - 128 : undefined;
        void reap(image.pid, { status: code, signal });
        settle(code);
      };
      worker.onmessage = ({ data }) => {
        if (data.out) write(data.fd, decoders[data.fd].decode(data.out, { stream: true }));
        else if (data.reading) onReading();
        else if (data.stopped || data.continued) { process.stopped = !!data.stopped; changed(); }
        else if (data.truncated) truncated = true;
        else if ('exit' in data) end(data.exit);
      };
      worker.onerror = event => { onOutput(2, `${argv[0]}: ${event.message}\n`); end(126); };
      worker.postMessage({ module, memory, argv, env: environment, umask, sudo, pid: image.pid, proc: image.token, stdin: io.stdin.message, stdout: io.stdout.message, stderr: { tty: true }, control: control?.buffer });
      // A signal, as its default action has it: ended, stopped at its next system call, or
      // continued.
      const signal = number => {
        if (ENDING.has(number)) return end(128 + number);
        if (!control) return;
        // Stopped: one asleep on its word wakes to stop.
        if (number === SIG.STOP || number === SIG.TSTP) { Atomics.store(control, 0, 1); Atomics.notify(control, 0); }
        else if (number === SIG.CONT) { Atomics.store(control, 0, 0); Atomics.notify(control, 0); }
      };
      Object.assign(process, { pid: image.pid, kill: end, exited, signal });
      hosted.set(image.pid, process);
      processes.push(process);
      return process;
    } catch (error) {
      // Whatever was made for the stage ends here: no process may outlive a host that never
      // started, and none may wait for the next boot to be reaped.
      worker?.terminate();
      if (image) await abandon(image);
      throw error;
    }
  };
  const canceled = async image => {
    await abandon(image);
    return { pid: image.pid, kill: () => {}, exited: Promise.resolve(stopStatus) };
  };
  const watch = setInterval(() => { if (cancelled()) stop(SIGINT); }, 100);
  const statuses = [];
  let input = null;
  try {
    if (isolated) {
      // At once, through pipes; the first reads the terminal unless given its input.
      input = stdin == null ? terminalInput() : null;
      if (input) onTty(input);
      const pipes = stages.slice(1).map(() => pipeBuffer());
      const starting = [];
      for (let index = 0; index <= last; index++) {
        const from = index === 0 ? null : pipes[index - 1], to = index === last ? null : pipes[index];
        starting.push(start(index, {
          stdin: from ? { message: { pipe: from }, reader: new Pipe(from) }
            : input ? { message: { pipe: input.pipe.state.buffer, tty: true }, reader: null }
            : { message: { data: encoder.encode(stdin) } },
          stdout: to ? { message: { pipe: to }, writer: new Pipe(to) } : { message: { tty, closed: closed?.buffer }, tty },
        }));
      }
      let started;
      try {
        started = await Promise.all(starting);
      } catch (error) {
        // A stage that failed ends the pipeline: stop the ones running, and wait for the ones
        // still being given a process to abandon theirs, so nothing outlives this run.
        stop(SIGINT);
        await Promise.allSettled(starting);
        throw error;
      }
      // Each stage's status is its own, whatever order the processes end in.
      const exited = await Promise.all(started.map(process => process.exited));
      started.forEach((_, index) => { statuses[index] = exited[index]; });
    } else {
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
    // What still runs, if starting one failed, ends with the pipeline.
    for (const process of processes) process.kill(SIGINT);
    clearInterval(watch);
    if (input) { input.close(); onTty(null); }
  }
  return { status: statuses[last] ?? SIGINT, stdout, truncated };
}

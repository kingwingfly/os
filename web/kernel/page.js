// The page is a terminal/compositor for its dedicated kernel. Only messages cross this
// boundary; the kernel Worker owns process Workers, pipe buffers and the process table.
import { kernelCall, kernelPort } from './protocol.js';
import { requireExecutionSupport } from './capabilities.js';

globalThis.loaderStats = { compiled: 0 };
globalThis.addEventListener('os:signal', ({ detail }) => { void kernelCall('deliver_signal', detail).catch(() => {}); });
globalThis.addEventListener('os:changed', () => { void kernelCall('reconcile').catch(() => {}); });
globalThis.addEventListener('os:login-changed', () => { void kernelCall('login_refresh').catch(() => {}); });
globalThis.addEventListener('pagehide', () => {
  void kernelCall('login_leave').catch(() => {});
  void kernelCall('machine_init_leave').catch(() => {});
  void changeSeat(false).catch(() => {});
});
globalThis.addEventListener('pageshow', event => { if (event.persisted) {
  void kernelCall('login_refresh').catch(() => {});
  void kernelCall('machine_init_resume').catch(() => {});
  void changeSeat(desiredSeatActive).catch(() => {});
} });
let localSeat = { active: true }, watchingSeat = false, desiredSeatActive = true;
let seatChanges = Promise.resolve();
const rememberSeat = value => {
  // An older status reply must not undo an activation event already received.
  if (value.id === localSeat.id && value.generation < localSeat.generation) return localSeat;
  localSeat = value;
  globalThis.dispatchEvent(new CustomEvent('os:seat', { detail: value }));
  return value;
};
export const currentSeat = () => localSeat;
export function seatStatus() {
  if (!watchingSeat) { watchingSeat = true; kernelPort().on('seat', rememberSeat); }
  return kernelCall('seat_status').then(rememberSeat);
}
function changeSeat(active) {
  const change = seatChanges.then(async () => {
    const expected = await seatStatus();
    return rememberSeat(await kernelCall('seat_set_active', { active, expected: { id: expected.id, generation: expected.generation } }));
  });
  seatChanges = change.catch(() => {});
  return change;
}
export function setSeatActive(active) {
  if (typeof active !== 'boolean') return Promise.reject(Object.assign(new Error('seat activity must be boolean'), { errno: 'EINVAL' }));
  desiredSeatActive = active;
  return changeSeat(active);
}
let watchingInit = false;
export function machineInit() {
  if (!watchingInit) {
    watchingInit = true;
    kernelPort().on('machine_init', detail => globalThis.dispatchEvent(new CustomEvent('os:machine-init', { detail })));
  }
  return kernelCall('machine_init_status');
}
// Explicit lifecycle operations preserve ordinary cookie sign-out semantics. They target
// a retained public expectation; the server authenticates the current account each time.
export async function endLoginSession(expected) {
  const session = expected ?? (await loginSession()).session;
  if (!session?.id) throw Object.assign(new Error('No current login session.'), { errno: 'ESTALE' });
  return kernelCall('login_lifecycle', { op: 'end', session: session.id });
}
export async function restartLoginSession(expected) {
  const session = expected ?? (await loginSession()).session;
  if (!session?.id) throw Object.assign(new Error('No current login session.'), { errno: 'ESTALE' });
  return kernelCall('login_lifecycle', { op: 'restart', session: session.id });
}
export async function rebootMachine(expected) {
  const init = expected ?? (await machineInit()).init;
  if (!init?.boot) throw Object.assign(new Error('No current Machine boot.'), { errno: 'ESTALE' });
  return kernelCall('machine_reboot', { boot: init.boot });
}
let watchingLogin = false;
export function loginSession() {
  if (!watchingLogin) {
    watchingLogin = true;
    kernelPort().on('login', detail => globalThis.dispatchEvent(new CustomEvent('os:login-session', { detail })));
  }
  return kernelCall('login_status');
}
export async function configureSeatSharing(sharing, expected) {
  if (!['none','view','control'].includes(sharing)) throw new TypeError('sharing must be none, view or control');
  const session = expected ?? (await loginSession()).session;
  return kernelCall('login_seat_policy', { sharing, session: session?.id, expected: session?.seat_policy?.revision });
}
// Opt into one managed supervisor for the current login. The public expectation
// fences delayed UI actions; private membership and process proofs stay in the kernel.
export async function startLoginServices(file, options = {}) {
  if (typeof file !== 'string' || !file.startsWith('/') || file.includes('\0')) throw new TypeError('an absolute unit-file path is required');
  const value = await loginSession();
  if (!value.coordinator) throw Object.assign(new Error('this tab does not own login service management'), { errno: 'EACCES' });
  return exec([{ path: '/usr/bin/supervise', argv: ['supervise', file] }], {
    ...options, stdin: '', sudo: false,
    managedLogin: { session: value.session.id, generation: value.session.generation },
  });
}
// Configuration belongs to this account on this Machine and applies to future logins too.
export async function configureLoginServices(file, expected) {
  if (file !== null && (typeof file !== 'string' || !file.startsWith('/') || file.includes('\0'))) throw new TypeError('an absolute unit-file path or null is required');
  const value = expected ?? (await loginSession()).session;
  return kernelCall('login_configure', { file, expected: { session: value?.id, generation: value?.generation } });
}
export function signalLoginServices(expected, signal = 15) {
  return kernelCall('login_service_signal', { expected: { session: expected?.id, generation: expected?.generation }, pid: expected?.managed?.pid, signal });
}
const localRuns = new Map(), foregroundRuns = new Map();
export function consoleStatus(terminalId) {
  const record = localRuns.get(foregroundRuns.get(String(terminalId)));
  return record ? { run: record.run, ready: record.ready, ...record.sharing } : null;
}
const consoleChanged = terminalId => globalThis.dispatchEvent(new CustomEvent('os:console-state', { detail: { terminalId } }));
export function stopConsoleSharing(run) { return kernelCall('console_unshare', { run }); }

export function closeConsole(terminalId) {
  void kernelCall('console_close', { terminalId: String(terminalId) }).catch(() => {});
}

// The owner explicitly transfers one end of a channel; the receiving page
// transfers the other to its own execution host. Neither side discovers peers
// or authorizes them using public tab, console or process names.
export function grantConsole(terminalId, port, { access = 'view', run } = {}) {
  return kernelCall('console_grant', { terminalId: String(terminalId), port, access, expectedRun: run }, [port]);
}
export function revokeConsole(grant) { return kernelCall('console_revoke', { grant }); }

function displayed(acknowledge) {
  let frame, timer, done = false;
  const finish = () => {
    if (done) return;
    done = true; cancelAnimationFrame(frame); clearTimeout(timer); acknowledge();
  };
  frame = requestAnimationFrame(finish); timer = setTimeout(finish, 50);
}

export async function attachConsole(port, options = {}) {
  const attachment = crypto.randomUUID(), queued = [];
  let initialized = false, ended = false, access, tty = false, foreground = false, finish, active = false, stamp;
  const closed = new Promise(resolve => { finish = resolve; });
  const command = (type, args = {}) => kernelCall(type, { attachment, ...args });
  const makeInput = stamp => {
    const operation = (operation, value) => command('attachment_input', { operation, value, stamp });
    return { raw: false, echo: true, write: text => operation('input', text), reply: text => operation('reply', text),
      resize: size => operation('resize', size), eof: () => operation('eof') };
  };
  let input = makeInput();
  const terminal = () => options.onTty?.(!ended && active && access === 'control' && tty && foreground ? input : null);
  const apply = event => {
    switch (event.type) {
      case 'output': options.onOutput?.(event.fd, event.text); break;
      case 'mode': input.raw = event.raw; input.echo = event.echo; options.onMode?.(event); break;
      case 'size': options.onSize?.(event.size); break;
      case 'state': options.onState?.(event.state); break;
      case 'reading': options.onReading?.(); break;
      case 'tty': tty = event.active; terminal(); break;
      case 'foreground': foreground = event.active; terminal(); break;
    }
  };
  const receive = message => {
    if (message.type === 'closed') {
      ended = true; off(); terminal(); finish(message.err); options.onClose?.(message.err); return;
    }
    if (message.type === 'device') {
      const previous = input; stamp = message.stamp; active = message.active;
      input = Object.assign(makeInput(stamp), { raw: previous.raw, echo: previous.echo }); terminal(); return;
    }
    try { apply(message.event); }
    finally { displayed(() => { void command('attachment_ack', { sequence: message.sequence }).catch(() => {}); }); }
  };
  const off = kernelPort().on('attachment', message => {
    if (message.attachment !== attachment) return;
    if (!initialized) queued.push(message); else receive(message);
  });
  try {
    const ready = await kernelCall('attachment_connect', { attachment, port }, [port]);
    access = ready.access;
    for (const event of ready.snapshot) apply(event);
    initialized = true;
    for (const message of queued) receive(message);
    return { access, get input() { return input; }, closed, detach: () => ended ? Promise.resolve() : command('attachment_close') };
  } catch (error) {
    off(); void command('attachment_close').catch(() => {}); throw error;
  }
}

export function dimensions(element) {
  const transcript = element ?? document.querySelector('.terminal-panel:not([hidden]) .transcript') ?? document.body;
  const probe = document.createElement('pre');
  probe.textContent = '0'.repeat(10);
  probe.style.cssText = 'position:absolute;visibility:hidden;white-space:pre;width:auto';
  transcript.append(probe);
  const width = probe.getBoundingClientRect().width / 10 || 12;
  const lineHeight = parseFloat(getComputedStyle(probe).lineHeight) || 34;
  probe.remove();
  const style = getComputedStyle(transcript);
  const inner = transcript.clientWidth - parseFloat(style.paddingLeft || 0) - parseFloat(style.paddingRight || 0);
  const height = (transcript.clientHeight || 480) - parseFloat(style.paddingTop || 0) - parseFloat(style.paddingBottom || 0);
  return { columns: Math.max(2, Math.min(500, Math.floor((inner || 800) / width))), rows: Math.max(2, Math.min(200, Math.floor(height / lineHeight))), width: Math.max(0, Math.round(inner || 800)), height: Math.max(0, Math.round(height)) };
}

export async function exec(stages, options = {}) {
  // A pane may close while the shell is still resolving its command. Do not
  // create a new run after cancellation already reached that launch.
  if (options.cancelled?.()) return { status: 130, stdout: '', truncated: false, truncatedBy: [] };
  requireExecutionSupport();
  const run = crypto.randomUUID();
  const terminalId = String(options.terminalId ?? run);
  const record = { run, ready: false, sharing: { count: 0, control: false } };
  localRuns.set(run, record); foregroundRuns.set(terminalId, run); consoleChanged(terminalId);
  const command = (type, args = {}) => { void kernelCall(type, { run, ...args }).catch(() => {}); };
  const select = active => {
    if (active) foregroundRuns.set(terminalId, run);
    else if (foregroundRuns.get(terminalId) === run) foregroundRuns.delete(terminalId);
    consoleChanged(terminalId);
  };
  const group = { foreground: active => { select(active); command('run_foreground', { active }); }, pids: [], stoppable: !!globalThis.crossOriginIsolated, signal: signal => command('run_signal', { signal }) };
  // The shell captures this object while launching, before the first Worker reply arrives.
  // Its fields update in place as processes start and end.
  options.onJob?.(group);
  const makeInput = stamp => ({ raw: false, echo: true,
    reply: text => command('run_input', { reply: text, stamp }), resize: size => command('run_resize', { size, stamp }),
    write: text => command('run_input', { text, stamp }), eof: () => command('run_input', { eof: true, stamp }),
    close: () => command('run_input', { close: true, stamp }) });
  let input = makeInput(), deviceActive = false, tty = false, reading = false;
  const terminal = () => {
    options.onTty?.(tty && deviceActive ? input : null);
    if (tty && deviceActive && reading) options.onReading?.();
  };
  const off = kernelPort().on('run', event => {
    if (event.run !== run) return;
    switch (event.type) {
      case 'output': {
        try { options.onOutput?.(event.fd, event.text); }
        finally {
          // Acknowledge after the DOM has had a chance to render and handle input. The timer
          // also drains background tabs, where animation frames may be suspended.
          displayed(() => command('run_output_ack', { sequence: event.sequence }));
        }
        break;
      }
      case 'mode': input.raw = event.raw; input.echo = event.echo; options.onMode?.(event); break;
      case 'size': options.onSize?.(event.size); break;
      case 'reading': reading = true; if (deviceActive) options.onReading?.(); break;
      case 'state': options.onState?.(event.state); break;
      case 'tty': record.ready = tty = event.active; consoleChanged(terminalId); terminal(); break;
      case 'device': {
        const previous = input; deviceActive = event.active;
        input = Object.assign(makeInput(event.stamp), { raw: previous.raw, echo: previous.echo }); terminal();
        if (deviceActive && transcript?.clientWidth) input.resize(dimensions(transcript));
        break;
      }
      case 'foreground': select(event.active); break;
      case 'sharing': record.sharing = { count: event.count, control: event.control }; consoleChanged(terminalId); break;
      case 'job': group.pids = event.pids; group.stoppable = event.stoppable; break;
      case 'stats': Object.assign(globalThis.loaderStats, event.stats); break;
    }
  });
  const transcript = options.terminalId != null
    ? document.querySelector(`.terminal-panel[data-terminal="${CSS.escape(String(options.terminalId))}"] .transcript`)
    : document.querySelector('.terminal-panel:not([hidden]) .transcript');
  const plain = dimensions(transcript);
  for (const key of ['terminalId', 'cwd', 'home', 'user', 'environment', 'stdin', 'sudo', 'umask', 'tty', 'enough', 'managedLogin', 'expectedSession']) {
    if (options[key] !== undefined) plain[key] = options[key];
  }
  const observer = new ResizeObserver(() => {
    if (transcript?.clientWidth) input.resize(dimensions(transcript));
  });
  if (transcript) observer.observe(transcript);
  const timer = setInterval(() => { if (options.cancelled?.()) command('run_cancel'); }, 100);
  try { return await kernelCall('run', { run, stages, options: plain }); }
  finally {
    clearInterval(timer); observer.disconnect(); off(); localRuns.delete(run);
    if (foregroundRuns.get(terminalId) === run) foregroundRuns.delete(terminalId);
    consoleChanged(terminalId);
  }
}

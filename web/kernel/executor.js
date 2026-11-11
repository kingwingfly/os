// Runs inside the same dedicated Worker as the Rust client kernel. The page receives
// terminal events, while Workers and shared memory remain owned here.
import { exec, deliverSignal, reconcile } from '../wasi/exec.mjs';
// The private boot path shares the same process host and signal reconciliation.
export { exec };
import { Consoles } from './console.js';
import { SeatDevices } from './seat.js';
import { ConsoleGrants, ConsolePeer, consoleInput } from './attachment.js';
import { stats } from './loader.js';
import { validateExpectedSession, checkExpectedSession } from './launch-context.js';
import { sharingAllowed } from './sharing-policy.js';

const runs = new Map();
const consoles = new Consoles();
const seat = new SeatDevices();
let sharingStatus = () => null;
const grants = new ConsoleGrants({ allowed: access => sharingAllowed(sharingStatus(), access) }), peers = new Map();
export function setSharingPolicy(source) { sharingStatus = source; grants.sweep(); }
setInterval(() => {
  void reconcile(); grants.sweep(); for (const peer of peers.values()) peer.sweep();
}, 5000);

export async function request(type, args, send, seatChanged = () => {}) {
  const reportSeat = () => seatChanged(seat.current());
  if (type === 'seat_status') return seat.current();
  if (type === 'seat_set_active') {
    const generation = seat.generation;
    const value = seat.change(args.active, args.expected);
    if (generation !== seat.generation) {
      for (const run of runs.values()) run.seatChanged();
      for (const peer of peers.values()) peer.seatChanged();
      reportSeat();
    }
    return value;
  }
  if (type.startsWith('seat_')) throw { errno: 'ENOSYS', detail: 'unsupported seat request' };
  if (type === 'deliver_signal') return deliverSignal(args);
  if (type === 'reconcile') return reconcile();
  if (type === 'console_close') return consoles.close(String(args.terminalId));
  if (type === 'console_grant') {
    const run = consoles.entries.get(String(args.terminalId))?.active;
    if (args.expectedRun !== undefined && runs.get(args.expectedRun) !== run) {
      if (args.port instanceof MessagePort) args.port.close();
      throw { errno: 'ESRCH', detail: 'selected console command has changed' };
    }
    return grants.grant(run, args.port, args.access);
  }
  if (type === 'console_revoke') return grants.revoke(args.grant);
  if (type === 'console_unshare') { const run = runs.get(args.run); if (run) grants.revokeRun(run); return; }
  if (type === 'attachment_connect') {
    if (typeof args.attachment !== 'string' || !args.attachment.length || args.attachment.length > 128) {
      if (args.port instanceof MessagePort) args.port.close();
      throw { errno: 'EINVAL', detail: 'invalid local console attachment ID' };
    }
    if (peers.has(args.attachment) || peers.size >= 64) {
      if (args.port instanceof MessagePort) args.port.close();
      throw { errno: 'ENOSPC', detail: 'too many or duplicate console attachments' };
    }
    if (!(args.port instanceof MessagePort)) throw { errno: 'EINVAL', detail: 'a transferred MessagePort is required' };
    let device;
    try { device = seat.open('attachment'); } catch (error) { args.port.close(); throw error; }
    const peer = new ConsolePeer(args.port, {
      event: (event, sequence) => send({ attachment: args.attachment, type: 'event', event, sequence }),
      closed: err => { seat.close(device); reportSeat(); peers.delete(args.attachment); send({ attachment: args.attachment, type: 'closed', err }); },
    });
    peer.device = device;
    peer.seatChanged = () => send({ attachment: args.attachment, type: 'device', active: seat.active, stamp: seat.stamp(device) });
    if (!peer.ended) { peers.set(args.attachment, peer); peer.seatChanged(); reportSeat(); }
    return peer.ready;
  }
  if (type.startsWith('attachment_')) {
    const peer = peers.get(args.attachment);
    if (!peer) throw { errno: 'ENOENT', detail: 'console attachment does not exist' };
    if (type === 'attachment_input') { seat.check(peer.device, args.stamp); return peer.request(args.operation, args.value); }
    if (type === 'attachment_ack') return peer.ack(args.sequence);
    if (type === 'attachment_close') return peer.close();
    throw { errno: 'ENOSYS', detail: 'unsupported console attachment request' };
  }
  if (type !== 'run') {
    const run = runs.get(args.run);
    if (!run) return;
    if (type === 'run_output_ack') { run.displayed.get(args.sequence)?.(); run.displayed.delete(args.sequence); }
    else if (type === 'run_foreground') consoles.foreground(run, args.active);
    else if (type === 'run_signal') run.group?.signal(args.signal);
    else if (type === 'run_cancel') { if (!run.closed) run.cancelled = true; }
    else if (type === 'run_resize') { seat.check(run.device, args.stamp); if (consoles.accepts(run)) run.input?.resize(args.size); }
    else if (type === 'run_input') {
      seat.check(run.device, args.stamp);
      if (!consoles.accepts(run)) throw { errno: 'EACCES', detail: 'run does not own console input' };
      if (args.reply != null) run.input?.enqueue(new TextEncoder().encode(args.reply));
      else if (args.eof) run.input?.eof();
      else if (args.close) await run.group?.hangup();
      else run.input?.write(args.text);
    }
    return;
  }
  if (runs.has(args.run)) throw { errno: 'EINVAL', detail: 'duplicate run id' };
  const managed = args.options?.managedLogin;
  const expectedSession = args.options?.expectedSession === undefined ? null : validateExpectedSession(args.options.expectedSession);
  if (managed) {
    if (!globalThis.crossOriginIsolated || args.stages?.length !== 1 || args.options.sudo) {
      throw { errno: 'EINVAL', detail: 'login management requires one isolated, unelevated process' };
    }
    await globalThis.kernelRequest('login_service_check', { expected: managed });
  }
  const run = { cancelled: false, displayed: new Map(), sequence: 0 };
  const key = String(args.options?.terminalId ?? args.run);
  run.device = seat.open('console');
  let terminalState;
  try { terminalState = consoles.acquire(key, run, args.options); }
  catch (error) { seat.close(run.device); throw error; }
  const state = new Map([
    ['mode', { type: 'mode', raw: terminalState ? !terminalState.canonical : false, echo: terminalState?.echo ?? true }],
    ['size', { type: 'size', size: terminalState?.size ?? { columns: 80, rows: 24, width: 0, height: 0 } }],
    ['state', { type: 'state', state: 'running' }], ['tty', { type: 'tty', active: false }],
    ['foreground', { type: 'foreground', active: true }],
  ]);
  const event = (type, value = {}) => {
    const message = { type, ...value };
    if (state.has(type)) state.set(type, message);
    send({ run: args.run, ...message }); grants.publish(run, message);
  };
  run.snapshot = () => [...state.values()];
  run.sharing = value => event('sharing', value);
  run.detach = () => grants.end(run, 'console pane closed', false);
  run.focus = active => event('foreground', { active });
  run.remoteInput = (controller, operation, value) => {
    if (!consoles.accepts(run, controller)) throw { errno: 'EACCES', detail: 'run does not own console input' };
    consoleInput(run, operation, value);
  };
  run.refresh = () => {
    if (!terminalState || run.closed) return;
    event('mode', { raw: !terminalState.canonical, echo: terminalState.echo });
    event('size', { size: terminalState.size });
  };
  run.seatChanged = () => event('device', { active: seat.active, stamp: seat.stamp(run.device) });
  runs.set(args.run, run); run.seatChanged(); reportSeat();
  try {
    return await exec(args.stages, { ...args.options, terminalState,
      beforeStart: async (pid, image) => {
        if (expectedSession) checkExpectedSession(expectedSession, image);
        if (managed) await globalThis.kernelRequest('login_service_attach', { pid, expected: managed });
      },
      cancelled: () => run.cancelled,
      onOutput: (fd, text) => run.closed ? undefined : new Promise(resolve => {
        const sequence = ++run.sequence;
        run.displayed.set(sequence, resolve);
        event('output', { fd, text, sequence });
      }),
      onMode: value => event('mode', value),
      onSize: size => event('size', { size }),
      onReading: () => event('reading'),
      onState: state => event('state', { state }),
      onTty: input => { run.input = input; event('tty', { active: !!input && !run.closed }); },
      onJob: group => {
        if (run.group !== group) {
          run.group = group;
          if (run.closed) void group.hangup();
          else group.foreground(run.foreground);
        }
        event('job', { pids: group.pids, stoppable: group.stoppable });
      },
    });
  } finally {
    for (const resolve of run.displayed.values()) resolve();
    grants.end(run); consoles.release(run); event('stats', { stats }); runs.delete(args.run); seat.close(run.device); reportSeat();
  }
}

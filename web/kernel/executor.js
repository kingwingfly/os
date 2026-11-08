// Runs inside the same dedicated Worker as the Rust client kernel. The page receives
// terminal events, while Workers and shared memory remain owned here.
import { exec, deliverSignal, reconcile } from '../wasi/exec.mjs';
import { TtyState } from './pty.js';
import { stats } from './loader.js';

const runs = new Map();
const terminals = new Map();
setInterval(() => { void reconcile(); }, 5000);

export async function request(type, args, send) {
  if (type === 'deliver_signal') return deliverSignal(args);
  if (type === 'reconcile') return reconcile();
  if (type !== 'run') {
    const run = runs.get(args.run);
    if (!run) return;
    if (type === 'run_output_ack') { run.displayed.get(args.sequence)?.(); run.displayed.delete(args.sequence); }
    else if (type === 'run_foreground') run.group?.foreground(args.active);
    else if (type === 'run_signal') run.group?.signal(args.signal);
    else if (type === 'run_cancel') run.cancelled = true;
    else if (type === 'run_resize') run.input?.resize(args.size);
    else if (type === 'run_input') {
      if (args.reply != null) run.input?.enqueue(new TextEncoder().encode(args.reply));
      else if (args.eof) run.input?.eof();
      else if (args.close) run.input?.close();
      else run.input?.write(args.text);
    }
    return;
  }
  if (runs.has(args.run)) throw { errno: 'EINVAL', detail: 'duplicate run id' };
  const run = { cancelled: false, displayed: new Map(), sequence: 0 };
  const key = String(args.options?.terminalId ?? args.run);
  let terminalState;
  if (globalThis.crossOriginIsolated) {
    terminalState = terminals.get(key) ?? TtyState.create(args.options);
    terminals.set(key, terminalState);
    // Idle shell state is bounded; running PTYs retain their own reference.
    if (terminals.size > 64) terminals.delete(terminals.keys().next().value);
  }
  const event = (type, value = {}) => send({ run: args.run, type, ...value });
  runs.set(args.run, run);
  try {
    return await exec(args.stages, { ...args.options, terminalState,
      cancelled: () => run.cancelled,
      onOutput: (fd, text) => new Promise(resolve => {
        const sequence = ++run.sequence;
        run.displayed.set(sequence, resolve);
        event('output', { fd, text, sequence });
      }),
      onMode: value => event('mode', value),
      onSize: size => event('size', { size }),
      onReading: () => event('reading'),
      onState: state => event('state', { state }),
      onTty: input => { run.input = input; event('tty', { active: !!input }); },
      onJob: group => { run.group = group; event('job', { pids: group.pids, stoppable: group.stoppable }); },
    });
  } finally { for (const resolve of run.displayed.values()) resolve(); event('stats', { stats }); runs.delete(args.run); }
}

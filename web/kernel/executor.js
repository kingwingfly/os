// Runs inside the same dedicated Worker as the Rust client kernel. The page receives
// terminal events, while Workers and shared memory remain owned here.
import { exec, deliverSignal, reconcile } from '../wasi/exec.mjs';
import { stats } from './loader.js';

const runs = new Map();
setInterval(() => { void reconcile(); }, 5000);

export async function request(type, args, send) {
  if (type === 'deliver_signal') return deliverSignal(args);
  if (type === 'reconcile') return reconcile();
  if (type !== 'run') {
    const run = runs.get(args.run);
    if (!run) return;
    if (type === 'run_signal') run.group?.signal(args.signal);
    else if (type === 'run_cancel') run.cancelled = true;
    else if (type === 'run_input') {
      if (args.eof) run.input?.eof();
      else if (args.close) run.input?.close();
      else run.input?.write(args.text);
    }
    return;
  }
  if (runs.has(args.run)) throw { errno: 'EINVAL', detail: 'duplicate run id' };
  const run = { cancelled: false };
  const event = (type, value = {}) => send({ run: args.run, type, ...value });
  runs.set(args.run, run);
  try {
    return await exec(args.stages, { ...args.options,
      cancelled: () => run.cancelled,
      onOutput: (fd, text) => event('output', { fd, text }),
      onReading: () => event('reading'),
      onState: state => event('state', { state }),
      onTty: input => { run.input = input; event('tty', { active: !!input }); },
      onJob: group => { run.group = group; event('job', { pids: group.pids, stoppable: group.stoppable }); },
    });
  } finally { event('stats', { stats }); runs.delete(args.run); }
}

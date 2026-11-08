// The page is a terminal/compositor for its dedicated kernel. Only messages cross this
// boundary; the kernel Worker owns process Workers, pipe buffers and the process table.
import { kernelCall, kernelPort } from './protocol.js';

globalThis.loaderStats = { compiled: 0 };
globalThis.addEventListener('terminal:signal', ({ detail }) => { void kernelCall('deliver_signal', detail).catch(() => {}); });
globalThis.addEventListener('terminal:changed', () => { void kernelCall('reconcile').catch(() => {}); });

function columns() {
  const transcript = document.querySelector('.transcript') ?? document.body;
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

export async function exec(stages, options = {}) {
  const run = crypto.randomUUID();
  const command = (type, args = {}) => { void kernelCall(type, { run, ...args }).catch(() => {}); };
  const group = { pids: [], stoppable: !!globalThis.crossOriginIsolated, signal: signal => command('run_signal', { signal }) };
  // The shell captures this object while launching, before the first Worker reply arrives.
  // Its fields update in place as processes start and end.
  options.onJob?.(group);
  const input = { write: text => command('run_input', { text }), eof: () => command('run_input', { eof: true }), close: () => command('run_input', { close: true }) };
  const off = kernelPort().on('run', event => {
    if (event.run !== run) return;
    switch (event.type) {
      case 'output': options.onOutput?.(event.fd, event.text); break;
      case 'reading': options.onReading?.(); break;
      case 'state': options.onState?.(event.state); break;
      case 'tty': options.onTty?.(event.active ? input : null); break;
      case 'job': group.pids = event.pids; group.stoppable = event.stoppable; break;
      case 'stats': Object.assign(globalThis.loaderStats, event.stats); break;
    }
  });
  const plain = { columns: columns() };
  for (const key of ['cwd', 'home', 'user', 'stdin', 'sudo', 'umask', 'tty', 'enough']) {
    if (options[key] !== undefined) plain[key] = options[key];
  }
  const timer = setInterval(() => { if (options.cancelled?.()) command('run_cancel'); }, 100);
  try { return await kernelCall('run', { run, stages, options: plain }); }
  finally { clearInterval(timer); off(); }
}

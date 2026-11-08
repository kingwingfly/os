// The page is a terminal/compositor for its dedicated kernel. Only messages cross this
// boundary; the kernel Worker owns process Workers, pipe buffers and the process table.
import { kernelCall, kernelPort } from './protocol.js';

globalThis.loaderStats = { compiled: 0 };
globalThis.addEventListener('os:signal', ({ detail }) => { void kernelCall('deliver_signal', detail).catch(() => {}); });
globalThis.addEventListener('os:changed', () => { void kernelCall('reconcile').catch(() => {}); });
let fallbackNotified = false;

function dimensions(element) {
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
  if (!globalThis.crossOriginIsolated && !fallbackNotified) {
    fallbackNotified = true;
    options.onOutput?.(2, 'Interactive terminal input is unavailable in this browser; commands run sequentially.\n');
  }
  const run = crypto.randomUUID();
  const command = (type, args = {}) => { void kernelCall(type, { run, ...args }).catch(() => {}); };
  const group = { foreground: active => command('run_foreground', { active }), pids: [], stoppable: !!globalThis.crossOriginIsolated, signal: signal => command('run_signal', { signal }) };
  // The shell captures this object while launching, before the first Worker reply arrives.
  // Its fields update in place as processes start and end.
  options.onJob?.(group);
  const input = { raw: false, echo: true, reply: text => command('run_input', { reply: text }), resize: size => command('run_resize', { size }), write: text => command('run_input', { text }), eof: () => command('run_input', { eof: true }), close: () => command('run_input', { close: true }) };
  const off = kernelPort().on('run', event => {
    if (event.run !== run) return;
    switch (event.type) {
      case 'output': {
        try { options.onOutput?.(event.fd, event.text); }
        finally {
          // Acknowledge after the DOM has had a chance to render and handle input. The timer
          // also drains background tabs, where animation frames may be suspended.
          let frame, timer, acknowledged = false;
          const acknowledge = () => {
            if (acknowledged) return;
            acknowledged = true; cancelAnimationFrame(frame); clearTimeout(timer);
            command('run_output_ack', { sequence: event.sequence });
          };
          frame = requestAnimationFrame(acknowledge);
          timer = setTimeout(acknowledge, 50);
        }
        break;
      }
      case 'mode': input.raw = event.raw; input.echo = event.echo; options.onMode?.(event); break;
      case 'size': options.onSize?.(event.size); break;
      case 'reading': options.onReading?.(); break;
      case 'state': options.onState?.(event.state); break;
      case 'tty': options.onTty?.(event.active ? input : null); break;
      case 'job': group.pids = event.pids; group.stoppable = event.stoppable; break;
      case 'stats': Object.assign(globalThis.loaderStats, event.stats); break;
    }
  });
  const transcript = options.terminalId != null
    ? document.querySelector(`.terminal-panel[data-terminal="${CSS.escape(String(options.terminalId))}"] .transcript`)
    : document.querySelector('.terminal-panel:not([hidden]) .transcript');
  const plain = dimensions(transcript);
  for (const key of ['terminalId', 'cwd', 'home', 'user', 'environment', 'stdin', 'sudo', 'umask', 'tty', 'enough']) {
    if (options[key] !== undefined) plain[key] = options[key];
  }
  const observer = new ResizeObserver(() => {
    if (transcript?.clientWidth) input.resize(dimensions(transcript));
  });
  if (transcript) observer.observe(transcript);
  const timer = setInterval(() => { if (options.cancelled?.()) command('run_cancel'); }, 100);
  try { return await kernelCall('run', { run, stages, options: plain }); }
  finally { clearInterval(timer); observer.disconnect(); off(); }
}

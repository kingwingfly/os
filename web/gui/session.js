import { kernelCall, kernelPort } from '../kernel/protocol.js';
import { HostPresentationAdapter } from './host-adapter.js';

const status = document.querySelector('#status'), restart = document.querySelector('#restart');
const mode = new URLSearchParams(location.search).get('drag') === 'roundtrip' ? 'roundtrip' : 'local_lease';
const report = e => { if (!['ENODEV','ESTALE'].includes(e.errno)) status.textContent = e.message || e.errno; };
const call = (name, args, transfer) => kernelCall(name, args, transfer).catch(report);
function pick(cmd) {
  const panel = document.createElement('div'); panel.className = 'picker'; panel.dataset.request = cmd.request_id;
  const choose = document.createElement('button'), cancel = document.createElement('button');
  choose.textContent = 'Choose file'; cancel.textContent = 'Cancel';
  const result = file => { panel.remove(); return call('gui_picker_result', { request_id: cmd.request_id, surface_id: cmd.surface_id, file }); };
  choose.onclick = async () => {
    if (window.showOpenFilePicker) {
      try { const [handle] = await window.showOpenFilePicker(); await result(await handle.getFile()); } catch { await result(null); }
    } else {
      const input = document.createElement('input'); input.type = 'file';
      input.onchange = () => result(input.files[0]); input.oncancel = () => result(null); input.click();
    }
  };
  cancel.onclick = () => result(null);
  panel.append(choose, cancel); document.body.append(panel); choose.focus();
}
const adapter = new HostPresentationAdapter(document.querySelector('#seat'), {
  input: event => call('gui_host_event', { event }),
  error: report,
  revoke: surface_id => call('gui_revoke_port', { surface_id }),
  port: (surface_id, port) => kernelCall('gui_surface_port', { surface_id, port }, [port]),
  canvas: (surface_id, generation, canvas, backend) => call('gui_pixel_canvas', { surface_id, generation, canvas, backend }, [canvas]),
  pick,
  cancelPick: id => document.querySelector('.picker[data-request="' + id + '"]')?.remove(),
  clipboard: async item => {
    if (!navigator.clipboard?.write || typeof ClipboardItem !== 'function') {
      status.textContent = 'Copied to the seat clipboard. System clipboard unavailable.'; return;
    }
    const data = Uint8Array.from(atob(item.data), c => c.charCodeAt(0));
    await navigator.clipboard.write([new ClipboardItem({ [item.mime]: new Blob([data], { type: item.mime }) })]).catch(e => {
      status.textContent = 'Copied to the seat clipboard. System clipboard write failed (' + e.name + ').';
    });
  },
});
const launch = (program, argv = []) => kernelCall('gui_start', { program, argv });
const viewport = () => call('gui_viewport', { bounds: adapter.bounds(), mode });
let seatReady = false;
let presentation = Promise.resolve();
kernelPort().on('gui-display', cmd => {
  presentation = presentation.then(async () => {
    if (cmd.op === 'seat_reset') { seatReady = false; restart.hidden = false; document.querySelector('.picker')?.remove(); }
    if (cmd.op === 'set_drag_mode' && !seatReady) { seatReady = true; restart.hidden = true; void viewport(); }
    await adapter.display(cmd);
  }).catch(report);
});
kernelPort().on('gui-exit', value => {
  if (value.pid === window.guiSession.compositorPid) restart.hidden = false;
  if (value.stderr) status.textContent = value.stderr;
});
async function start() {
  status.textContent = 'Opening seat 0…';
  window.guiSession.compositorPid = await launch('compositor');
  await Promise.all([launch('gui-sample-doc'), launch('gui-sample-pixel')]); status.textContent = '';
}
restart.onclick = () => start().catch(report);
document.querySelector('#doc').onclick = () => launch('gui-sample-doc').catch(report);
document.querySelector('#pixel').onclick = () => launch('gui-sample-pixel').catch(report);
window.addEventListener('resize', () => { if (seatReady) void viewport(); });
function active(value) { if (seatReady) void adapter.input({ op: 'seat_active', active: value }); }
document.addEventListener('visibilitychange', () => active(!document.hidden));
window.addEventListener('pagehide', () => active(false));
window.addEventListener('pageshow', () => active(true));
window.guiSession = { adapter, launch, call: kernelCall, events: kernelPort().on };
start().catch(report);

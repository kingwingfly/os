import { verifyRelease } from './release.js';
import { attachConsole, dimensions } from './kernel/page.js';
import init from './pkg/frontend.js';

const nonce = crypto.randomUUID(), owner = window.opener;
let listener, peer, activeInput, connected = false, ended = false, access = 'view', state = 'running';
let status = owner ? 'Connecting to the selected command…' : 'Open this window from a running terminal.';
const emit = value => listener?.(value);
const notify = () => emit({ type: 'status', text: status, live: connected && !ended, input: !!activeInput && !ended });
const left = () => { try { owner?.postMessage({ type: 'os-console-left', nonce }, location.origin); } catch { /* owner gone */ } };
const close = message => {
  if (ended) return;
  ended = true; connected = false; activeInput = null; status = message; clearTimeout(timeout); notify(); left();
};
const describe = () => { if (ended) return; status = state === 'stopped' ? 'Command stopped' : access === 'view' ? 'View only · live output' : activeInput ? 'Keyboard connected' : 'Waiting for foreground input'; notify(); };
const fit = () => {
  if (!activeInput || ended) return;
  const viewport = document.querySelector('.console-window .transcript');
  if (viewport) void activeInput.resize(dimensions(viewport)).catch(() => {});
};
const timeout = owner ? setTimeout(() => close('The connection timed out. Open a new window from the original terminal.'), 30_000) : null;
window.addEventListener('message', async event => {
  if (ended || connected || !listener || event.origin !== location.origin || event.source !== owner || event.data?.nonce !== nonce) return;
  if (event.data.type === 'os-console-error') { close('The selected command is no longer available.'); return; }
  if (event.data.type !== 'os-console-port' || event.ports.length !== 1) return;
  connected = true; clearTimeout(timeout);
  try {
    peer = await attachConsole(event.ports[0], {
      onOutput: (fd, text) => emit({ type: 'output', text }),
      onMode: mode => emit({ type: 'mode', echo: mode.echo }),
      onSize: size => emit({ type: 'size', columns: size.columns, rows: size.rows }),
      onState: value => { state = value; if (peer) describe(); },
      onTty: input => { activeInput = input; if (peer) { describe(); requestAnimationFrame(fit); } },
      onClose: error => close(error.errno === 'EPIPE' ? 'Command ended' : error.errno === 'ECANCELED' ? 'Sharing ended' : error.errno === 'EOVERFLOW' ? 'Disconnected: output arrived too quickly.' : 'Connection lost. The original window may have closed.'),
    });
    if (ended) { await peer.detach(); return; }
    access = peer.access; describe(); requestAnimationFrame(fit);
  } catch { close('The connection could not be established. Open a new window to try again.'); }
});
let writing = Promise.resolve(), queued = 0;
window.osConsole = {
  listen(callback) {
    listener = callback; notify();
    if (owner) owner.postMessage({ type: 'os-console-ready', nonce }, location.origin);
    const viewport = document.querySelector('.console-window .transcript');
    if (viewport) new ResizeObserver(fit).observe(viewport);
  },
  send(operation, text) {
    if (!activeInput || ended) return;
    const input = activeInput;
    if (queued + text.length > 65536) { status = 'Input is too large; paste a smaller amount.'; notify(); return; }
    queued += text.length;
    writing = writing.then(async () => {
      if (input !== activeInput || ended) return;
      for (let at = 0; at < text.length;) {
        if (input !== activeInput || ended) return;
        let end = Math.min(at + 4096, text.length);
        if (end < text.length && /[\uD800-\uDBFF]/.test(text[end - 1]) && /[\uDC00-\uDFFF]/.test(text[end])) end--;
        await input[operation === 'reply' ? 'reply' : 'write'](text.slice(at, end)); at = end;
      }
    }).catch(() => { if (!ended) { status = 'Input is unavailable; use the original window to restore control.'; notify(); } })
      .finally(() => { queued -= text.length; });
  },
  detach() { void peer?.detach().catch(() => {}); close('Disconnected. The command remains in the original window.'); },
};
window.addEventListener('pagehide', () => { void peer?.detach().catch(() => {}); left(); });
verifyRelease().then(() => init()).catch(() => { document.getElementById('app').textContent = 'The terminal could not load. Close this window and try again.'; left(); });

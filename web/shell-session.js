import { verifyRelease } from './release.js';
import init from './pkg/frontend.js';
import './session-viewport.js';
import { call } from './http.mjs';
import { ShellSession } from './shell-session-controller.js';
import { executionSupport } from './kernel/capabilities.js';

async function boot() {
  const { exec, closeConsole } = await import('./kernel/page.js');
  let listener;
  const windows = 'BroadcastChannel' in window ? new BroadcastChannel('os-session') : null;
  if (windows) windows.onmessage = () => dispatchEvent(new Event('os:login-changed'));
  const session = new ShellSession({ identity: () => call('getcreds'), execute: exec, close: closeConsole,
    emit: event => listener?.(event) });
  window.osConsole = {
    listen(callback) { listener = callback; session.notify(); },
    send: (operation, text) => session.send(operation, text),
    detach: () => session.stop(), restart: () => { void session.start(); },
  };
  window.addEventListener('pagehide', () => session.stop());
  await verifyRelease();
  await init();
  void session.start();
}
const support = executionSupport();
const legacyManaged = new URLSearchParams(location.search).get('managed') === '1';
if (!support.supported || legacyManaged) {
  const root = document.getElementById('app');
  root.textContent = legacyManaged ? 'This managed shell link is no longer supported. ' : support.reason + ' ';
  const link = document.createElement('a'); link.href = '/'; link.textContent = 'Open the desktop'; root.append(link);
} else {
  boot().catch(() => { document.getElementById('app').textContent = 'The shell could not load. Refresh to try again.'; });
}

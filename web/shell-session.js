import { verifyRelease } from './release.js';
import init from './pkg/frontend.js';
import './session-viewport.js';
import { call } from './http.mjs';
import { ShellSession } from './shell-session-controller.js';
import { managedApplication } from './application-client.js';

async function boot() {
  // Managed URLs alone cannot launch work. Wait for the opening desktop's private port.
  const application = await managedApplication();
  let session;
  application?.onStop(() => session?.stop());
  if (application?.stopping) return;
  // Capability failure must not initialize execution, even from a pagehide listener.
  const { exec, closeConsole } = await import('./kernel/page.js');
  if (application) {
    const checkLogin = value => { if (value.connected && (value.session?.id !== application.expectedSession.session || value.session?.shutdown)) application.stop(); };
    const checkBoot = value => { if (value.connected && (value.init?.boot !== application.expectedSession.boot || value.init?.shutdown)) application.stop(); };
    window.addEventListener('os:login-session', event => checkLogin(event.detail));
    window.addEventListener('os:machine-init', event => checkBoot(event.detail));
    try {
      const { applicationContext } = await import('./application-context.js');
      const current = await applicationContext(() => application.stopping);
      if (current.session !== application.expectedSession.session || current.boot !== application.expectedSession.boot) application.stop();
    } catch (error) { application.failed(error.message); }
    if (application.stopping) return;
  }
  let listener;
  const windows = 'BroadcastChannel' in window ? new BroadcastChannel('os-session') : null;
  if (windows) windows.onmessage = () => dispatchEvent(new Event('os:login-changed'));
  session = new ShellSession({ identity: () => call('getcreds'), execute: exec, close: closeConsole,
    expectedSession: application?.expectedSession,
    emit: event => { if (event.type === 'ready') application?.ready(); else listener?.(event); } });
  window.osConsole = {
    listen(callback) { listener = callback; session.notify(); },
    send: (operation, text) => session.send(operation, text),
    detach: () => application ? application.stop() : session.stop(), restart: () => { if (!application) void session.start(); },
  };
  window.addEventListener('pagehide', () => session.stop());
  try {
    await verifyRelease();
    await init();
    if (!application?.stopping) void session.start().then(result => application?.exited(result.status));
  } catch (error) { application?.failed(error.message ?? 'The shell could not load.'); throw error; }
}
if (!crossOriginIsolated) {
  const root = document.getElementById('app');
  root.textContent = 'Interactive shells require an isolated browser context. ';
  const link = document.createElement('a'); link.href = '/'; link.textContent = 'Open the desktop'; root.append(link);
} else {
  boot().catch(() => { document.getElementById('app').textContent = 'The shell could not load. Refresh to try again.'; });
}

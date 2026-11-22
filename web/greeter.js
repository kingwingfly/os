import { verifyRelease } from './release.js';
import init from './pkg/frontend.js';
import './session-viewport.js';
import { call } from './http.mjs';
import { kernelCall } from './kernel/protocol.js';
import { enterSession, sessionTarget } from './session-targets.js';

let target = new URLSearchParams(location.search).get('target') ?? 'desktop';
try { sessionTarget(target); } catch { target = 'desktop'; }
const windows = 'BroadcastChannel' in window ? new BroadcastChannel('os-session') : null;
let expected;
let lastWho;
let session, boot;
let controlsInspected = false;

async function greeterCall(op, args) {
  if (op && typeof op === 'object') {
    if ('login_session' in op) return kernelCall('login_session_action', { action: op.login_session.action });
    if ('machine_init' in op) return kernelCall('machine_init_action', { action: op.machine_init.action });
  }
  if (op === 'login') {
    const res = await fetch('/api/cloud-auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: args?.username ?? 'root', password: args?.password ?? '' }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `Sign-in failed (${res.status})`);
    return body;
  }
  if (op === 'logout') {
    const res = await fetch('/api/cloud-auth/logout', { method: 'POST' });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `Sign-out failed (${res.status})`);
    return body;
  }
  return call(op, args);
}

async function inspectControls(who) {
  await kernelCall('sync_account', who).catch(() => {});
  const nextSession = await kernelCall('login_session_action', { action: { op: 'inspect' } });
  if (nextSession && nextSession.uid !== who.uid) {
    throw new Error('The account changed while loading. Refresh to try again.');
  }
  const nextBoot = who.uid === 0
    ? await kernelCall('machine_init_action', { action: { op: 'inspect' } })
    : null;
  controlsInspected = true;
  session = nextSession;
  boot = nextBoot;
  return { session, boot };
}

window.osGreeter = {
  target: () => target,
  state: () => ({ session, boot }),
  identity: async () => {
    // Keep cold guest `/login.html` completely lazy (ZERO client-kernel/executor-host/usr/bin
    // requests before sign-in or session control action), while eagerly inspecting root
    // Machine controls (or refreshing after lifecycle controls have been inspected).
    const who = await call('getcreds');
    const confirm = await call('getcreds');
    if (confirm.uid !== who.uid || confirm.signed_in !== who.signed_in) {
      throw new Error('The account changed while loading. Refresh to try again.');
    }
    lastWho = who;
    expected = { uid: who.uid, signed_in: who.signed_in };
    if (who.uid === 0 || controlsInspected) {
      await inspectControls(who);
      return {
        user: who.user,
        signed_in: who.signed_in,
        can_end: !!session && !session.shutdown?.complete,
        root: who.uid === 0,
      };
    }
    session = null;
    boot = null;
    return { user: who.user, signed_in: who.signed_in, can_end: true, root: false };
  },
  lifecycle: async operation => {
    if (!['end', 'reboot'].includes(operation)) throw new TypeError('Unknown session operation.');
    if (operation === 'end') {
      if (!session?.id) {
        if (!lastWho) throw new Error('Refresh the account before ending its session.');
        await inspectControls(lastWho);
      }
      if (!session?.id) throw new Error('Refresh the account before ending its session.');
      const id = session.id;
      let view = await kernelCall('login_session_action', { action: { op: 'end', session: id } });
      const deadline = performance.now() + 45000;
      while (!view?.shutdown?.complete) {
        if (performance.now() >= deadline) throw new Error('Shutdown is still pending. Refresh to check its status.');
        await new Promise(resolve => setTimeout(resolve, 500));
        view = await kernelCall('login_session_action', { action: { op: 'inspect' } });
        if (view?.id !== id) throw new Error('The account or session changed. Refresh to check its status.');
      }
    } else {
      if (!boot?.boot) {
        if (!lastWho || lastWho.uid !== 0) throw new Error('Refresh the root account before restarting this Machine.');
        await inspectControls(lastWho);
      }
      if (!boot?.boot) throw new Error('Refresh the root account before restarting this Machine.');
      const id = boot.boot;
      let view = await kernelCall('machine_init_action', { action: { op: 'reboot', boot: id } });
      const deadline = performance.now() + 45000;
      while (view.boot === id) {
        if (performance.now() >= deadline) throw new Error('Restart is still pending. Refresh to check its status.');
        await new Promise(resolve => setTimeout(resolve, 500));
        view = await kernelCall('machine_init_action', { action: { op: 'inspect' } });
      }
    }
    windows?.postMessage('changed');
  },
  enter: (mode, target, username, password) => enterSession({ mode, target, username, password, expected }, {
    call: greeterCall, changed: () => windows?.postMessage('changed'), navigate: path => location.replace(path),
  }),
};
verifyRelease().then(() => init()).catch(() => {
  document.getElementById('app').textContent = 'Sign-in could not load. Refresh to try again.';
});

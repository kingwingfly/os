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
let session, boot;

async function greeterCall(op, args) {
  if (op && typeof op === 'object') {
    if ('login_session' in op) return kernelCall('login_session_action', { action: op.login_session.action });
    if ('machine_init' in op) return kernelCall('machine_init_action', { action: op.machine_init.action });
  }
  const value = await call(op, args);
  if (op === 'login' || op === 'logout' || op === 'getcreds') {
    if (op === 'logout') await kernelCall('sync_account', { uid: 65534, gid: 65534, groups: [65534], user: 'guest', group: 'guest', home: '/tmp', shell: '/usr/bin/dash', signed_in: false }).catch(() => {});
    else if (value && typeof value.uid === 'number') await kernelCall('sync_account', value).catch(() => {});
  }
  return value;
}

window.osGreeter = {
  target: () => target,
  state: () => ({ session, boot }),
  identity: async () => {
    const who = await call('getcreds');
    const confirm = await call('getcreds');
    if (confirm.uid !== who.uid || confirm.signed_in !== who.signed_in) {
      throw new Error('The account changed while loading. Refresh to try again.');
    }
    await kernelCall('sync_account', who).catch(() => {});
    const nextSession = await kernelCall('login_session_action', { action: { op: 'inspect' } });
    if (nextSession && nextSession.uid !== who.uid) throw new Error('The account changed while loading. Refresh to try again.');
    const nextBoot = who.uid === 0 ? await kernelCall('machine_init_action', { action: { op: 'inspect' } }) : null;
    expected = { uid: who.uid, signed_in: who.signed_in };
    session = nextSession; boot = nextBoot;
    return { user: who.user, signed_in: who.signed_in, can_end: !!session && !session.shutdown?.complete, root: who.uid === 0 };
  },
  lifecycle: async operation => {
    if (!['end', 'reboot'].includes(operation)) throw new TypeError('Unknown session operation.');
    if (operation === 'end') {
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

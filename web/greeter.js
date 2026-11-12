import { verifyRelease } from './release.js';
import init from './pkg/frontend.js';
import './session-viewport.js';
import { call } from './http.mjs';
import { enterSession, sessionTarget } from './session-targets.js';

let target = new URLSearchParams(location.search).get('target') ?? 'desktop';
try { sessionTarget(target); } catch { target = 'desktop'; }
const windows = 'BroadcastChannel' in window ? new BroadcastChannel('os-session') : null;
let expected;
let session, boot;
window.osGreeter = {
  target: () => target,
  identity: async () => {
    const who = await call('getcreds');
    const nextSession = await call({ login_session: { action: { op: 'inspect' } } });
    if (nextSession && nextSession.uid !== who.uid) throw new Error('The account changed while loading. Refresh to try again.');
    const nextBoot = who.uid === 0 ? await call({ machine_init: { action: { op: 'inspect' } } }) : null;
    expected = { uid: who.uid, signed_in: who.signed_in };
    session = nextSession; boot = nextBoot;
    return { user: who.user, signed_in: who.signed_in, can_end: !!session && !session.shutdown?.complete, root: who.uid === 0 };
  },
  lifecycle: async operation => {
    if (!['end', 'reboot'].includes(operation)) throw new TypeError('Unknown session operation.');
    if (operation === 'end') {
      if (!session?.id) throw new Error('Refresh the account before ending its session.');
      const id = session.id;
      let view = await call({ login_session: { action: { op: 'end', session: id } } });
      const deadline = performance.now() + 45000;
      while (!view?.shutdown?.complete) {
        if (performance.now() >= deadline) throw new Error('Shutdown is still pending. Refresh to check its status.');
        await new Promise(resolve => setTimeout(resolve, 500));
        view = await call({ login_session: { action: { op: 'inspect' } } });
        if (view?.id !== id) throw new Error('The account or session changed. Refresh to check its status.');
      }
    } else {
      if (!boot?.boot) throw new Error('Refresh the root account before restarting this Machine.');
      const id = boot.boot;
      let view = await call({ machine_init: { action: { op: 'reboot', boot: id } } });
      const deadline = performance.now() + 45000;
      while (view.boot === id) {
        if (performance.now() >= deadline) throw new Error('Restart is still pending. Refresh to check its status.');
        await new Promise(resolve => setTimeout(resolve, 500));
        view = await call({ machine_init: { action: { op: 'inspect' } } });
      }
    }
    windows?.postMessage('changed');
  },
  enter: (mode, target, username, password) => enterSession({ mode, target, username, password, expected }, {
    call, changed: () => windows?.postMessage('changed'), navigate: path => location.replace(path),
  }),
};
verifyRelease().then(() => init()).catch(() => {
  document.getElementById('app').textContent = 'Sign-in could not load. Refresh to try again.';
});

import { entry } from './release.js';
// Browser session entry points are host applications. They do not confer process authority.
const targets = Object.freeze({ desktop: '/', shell: '/shell.html' });
export function sessionTarget(name) {
  if (!Object.hasOwn(targets, name)) throw new TypeError('Choose Desktop or Shell.');
  return entry(targets[name]);
}

export async function enterSession({ mode, target, username, password, expected }, { call, changed, navigate }) {
  const path = sessionTarget(target);
  if (mode === 'login') await call('login', { username, password });
  else if (mode === 'guest') await call('logout');
  else if (mode === 'current') {
    const who = await call('getcreds');
    if (!expected || who.uid !== expected.uid || who.signed_in !== expected.signed_in) {
      throw new Error('The account changed in another window. Refresh the account and choose again.');
    }
  }
  else throw new TypeError('Choose an account to continue.');
  // Publish only a change notification, never credentials or the login response.
  if (mode !== 'current') changed();
  // Starting a new session is explicit; ordinary hosts never revive an ended scope.
  const session = await call({ login_session: { action: { op: 'inspect' } } });
  if (session?.shutdown) {
    if (!session.shutdown.complete) throw new Error('The previous session is still shutting down. Try again shortly.');
    await call({ login_session: { action: { op: 'restart', session: session.id } } });
  }
  navigate(path);
}

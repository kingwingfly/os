import { loginSession, machineInit } from './kernel/page.js';

// A fresh dedicated kernel may answer its first status request before joining.
export async function applicationContext(cancelled = () => false) {
  const deadline = performance.now() + 10000;
  while (!cancelled()) {
    const [login, boot] = await Promise.all([loginSession(), machineInit()]);
    if (cancelled()) break;
    if (login.connected && boot.connected) {
      if (!login.session || login.session.shutdown || !boot.init || boot.init.shutdown) throw new Error('The session is shutting down. Start a new session from the greeter.');
      return { session: login.session.id, boot: boot.init.boot };
    }
    if (performance.now() >= deadline) throw new Error('The session could not be verified. Refresh and try again.');
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error('Application startup was cancelled.');
}

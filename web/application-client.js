import { validateExpectedSession } from './kernel/launch-context.js';

// A transferred port controls only this browser application's lifetime.
export class ApplicationPeer {
  constructor(port, expectedSession, { now = () => performance.now(), ownerAlive = () => true } = {}) {
    Object.assign(this, { port, expectedSession, now, ownerAlive });
    this.seen = now(); this.stopping = false; this.ended = false;
    port.onmessage = event => {
      if (this.ended) return;
      if (event.data?.type === 'ping') { this.seen = this.now(); this.send({ type: 'pong' }); }
      else if (event.data?.type === 'stop') this.stop();
    };
    port.onmessageerror = () => this.stop();
    port.start?.();
  }
  send(value) { try { this.port.postMessage(value); } catch { this.stop(); } }
  onStop(fn) { this.cleanup = fn; if (this.stopping) this.clean(); }
  stop() { if (this.ended || this.stopping) return; this.stopping = true; this.send({ type: 'stopping' }); this.clean(); }
  clean() {
    if (!this.cleanup || this.cleaning) return;
    this.cleaning = true;
    Promise.resolve().then(() => this.cleanup()).then(() => this.exited(0), () => this.exited(1));
  }
  ready() { if (!this.ended && !this.stopping) this.send({ type: 'ready' }); }
  failed(reason) { if (!this.ended) { this.send({ type: 'failed', reason: String(reason).slice(0, 256) }); this.stop(); } }
  exited(status) {
    if (this.ended) return;
    this.ended = true; this.send({ type: 'exit', status }); this.release?.(); this.port.close();
  }
  left() {
    if (this.ended) return;
    // Cleanup can finish after navigation begins. It must not close the destination.
    this.departed = true;
    this.send({ type: 'left' }); this.stop();
  }
  tick() { if (!this.ended && (!this.ownerAlive() || this.now() - this.seen >= 75000)) this.stop(); }
}

export async function managedApplication() {
  if (new URLSearchParams(location.search).get('managed') !== '1') return null;
  const owner = window.opener;
  if (!owner) throw new Error('Open managed applications from App windows on the desktop.');
  const nonce = window.osManagedApplicationNonce = crypto.randomUUID();
  const peer = await new Promise((resolve, reject) => {
    const finish = () => { clearTimeout(timer); window.removeEventListener('message', receive); window.removeEventListener('pagehide', left); };
    const left = () => { finish(); reject(new Error('Application startup was cancelled.')); };
    const receive = event => {
      if (event.origin !== location.origin || event.source !== owner || event.data?.type !== 'os-application-port' || event.data.nonce !== nonce || event.ports.length !== 1) return;
      try {
        const expected = validateExpectedSession(event.data.context);
        finish(); resolve(new ApplicationPeer(event.ports[0], expected, { ownerAlive: () => !owner.closed }));
      } catch (error) { event.ports[0].close(); finish(); reject(error); }
    };
    const timer = setTimeout(() => { finish(); reject(new Error('Application startup timed out. Open a new window from the desktop.')); }, 30000);
    window.addEventListener('message', receive); window.addEventListener('pagehide', left);
    owner.postMessage({ type: 'os-application-hello', nonce }, location.origin);
  });
  const timer = setInterval(() => peer.tick(), 1000);
  const left = () => peer.left();
  window.addEventListener('pagehide', left);
  peer.release = () => {
    clearInterval(timer); window.removeEventListener('pagehide', left);
    if (peer.stopping && !peer.departed && window.osManagedApplicationNonce === nonce) window.close();
  };
  return peer;
}

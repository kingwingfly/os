// User-space lifecycle policy for explicitly opened browser applications. No registry PIDs.
import { validateExpectedSession } from './kernel/launch-context.js';

export const applicationCatalog = Object.freeze({ shell: Object.freeze({ title: 'Shell', path: '/shell.html?managed=1' }) });
const active = record => ['starting', 'ready', 'stopping'].includes(record.state);
export class ApplicationSupervisor {
  constructor({ open, context, connect, close, changed = () => {}, now = () => performance.now(), token = () => crypto.randomUUID() }) {
    Object.assign(this, { open, context, connect, close, changed, now, token });
    this.records = new Map();
  }
  snapshot() {
    return [...this.records.values()].map(({ id, target, state, reason }) => ({ id, target, state, reason }));
  }
  launch(target) {
    if (!Object.hasOwn(applicationCatalog, target)) throw new TypeError('Choose an installed application.');
    if ([...this.records.values()].filter(active).length >= 8) throw new Error('Close an application before opening another.');
    const window = this.open(applicationCatalog[target].path);
    if (!window) throw new Error('Allow pop-ups for this site, then try again.');
    while (this.records.size >= 16) this.records.delete([...this.records.values()].find(r => !active(r)).id);
    const record = { id: this.token(), target, window, state: 'starting', reason: '', deadline: this.now() + 30000, seen: this.now() };
    this.records.set(record.id, record); this.changed();
    void this.prepare(record);
    return record.id;
  }
  async prepare(record) {
    try {
      const context = validateExpectedSession(await this.context(() => record.state !== 'starting'));
      if (record.state !== 'starting') return;
      record.context = context; this.deliver(record);
    } catch (error) { if (record.state === 'starting') this.fail(record, error.message ?? 'The session is unavailable.'); }
  }
  hello(window, nonce) {
    const record = [...this.records.values()].find(r => r.window === window && active(r));
    if (!record || typeof nonce !== 'string' || nonce.length !== 36) return;
    if (record.nonce && record.nonce !== nonce) {
      this.finish(record, 'failed', 'The application document changed. Open a new window.'); return;
    }
    if (record.state !== 'starting') return;
    record.nonce = nonce; this.deliver(record);
  }
  deliver(record) {
    if (record.port || !record.nonce || !record.context || record.state !== 'starting') return;
    if (this.now() >= record.deadline) { this.fail(record, 'Application startup timed out.'); return; }
    try { record.port = this.connect(record, data => this.message(record, data)); }
    catch { this.fail(record, 'The application window is no longer available.'); }
  }
  message(record, data) {
    if (this.records.get(record.id) !== record || !active(record) || !data || typeof data !== 'object') return;
    if (data.type === 'pong') { record.seen = this.now(); return; }
    if (data.type === 'stopping') { this.stop(record.id); return; }
    if (data.type === 'ready' && record.state === 'starting') {
      if (this.now() >= record.deadline) { this.fail(record, 'Application startup timed out.'); return; }
      record.state = 'ready'; record.seen = this.now(); this.changed();
    } else if (data.type === 'exit' && Number.isInteger(data.status) && data.status >= 0 && data.status <= 255) {
      const stopping = record.state === 'stopping';
      this.finish(record, stopping ? record.finalState : data.status === 0 && record.state === 'ready' ? 'exited' : 'failed',
        stopping ? record.reason : `Shell exited (${data.status}).`, stopping);
    } else if (data.type === 'failed' && typeof data.reason === 'string') this.fail(record, data.reason.slice(0, 256));
    else if (data.type === 'left') this.finish(record, record.state === 'stopping' ? record.finalState : 'exited', 'Application window left.');
  }
  finish(record, state, reason, close = false) {
    if (!active(record)) return;
    record.state = state; record.reason = reason;
    record.port?.close(); record.port = null;
    if (close) this.close(record);
    this.changed();
  }
  fail(record, reason) { this.stop(record.id, reason, 'failed'); }
  stop(id, reason = 'Application stopped.', finalState = 'stopped') {
    const record = this.records.get(id);
    if (!record || !active(record) || record.state === 'stopping') return;
    record.state = 'stopping'; record.finalState = finalState; record.reason = reason; record.deadline = this.now() + 8000;
    if (!record.port) { this.finish(record, finalState, reason, true); return; }
    try { record.port.postMessage({ type: 'stop' }); } catch { this.finish(record, finalState, reason, true); }
    this.changed();
  }
  stopAll(reason) { for (const record of this.records.values()) this.stop(record.id, reason); }
  login(status) {
    if (!status.connected) return;
    for (const r of this.records.values()) if (r.context && (status.session?.id !== r.context.session || status.session?.shutdown)) this.stop(r.id, 'Login session ended or changed.');
  }
  boot(status) {
    if (!status.connected) return;
    for (const r of this.records.values()) if (r.context && (status.init?.boot !== r.context.boot || status.init?.shutdown)) this.stop(r.id, 'Machine restarted or is shutting down.');
  }
  tick() {
    const now = this.now();
    for (const r of this.records.values()) {
      if (!active(r)) continue;
      if (r.window.closed) { this.finish(r, r.state === 'stopping' ? r.finalState : 'exited', 'Application window closed.'); continue; }
      if (r.state === 'stopping' && now >= r.deadline) { this.finish(r, r.finalState, r.reason + ' Window closed after the stop deadline.', true); continue; }
      if (r.state === 'starting' && now >= r.deadline) this.fail(r, 'Application startup timed out.');
      else if (r.state === 'ready' && now - r.seen >= 75000) this.fail(r, 'Application connection lost.');
      if (r.port && (!r.ping || now - r.ping >= 5000)) {
        r.ping = now;
        try { r.port.postMessage({ type: 'ping' }); } catch { this.fail(r, 'Application connection lost.'); }
      }
    }
  }
}

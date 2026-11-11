// A transferred MessagePort is the grant. Names and process IDs grant nothing.
// Only console events and bounded terminal input cross it; never process proofs,
// shared memory, execution requests or filesystem handles.
const VERSION = 1;
const WINDOW = 4, FRAMES = 32, BYTES = 64 * 1024, TEXT = 8192;
export const ATTACHMENT_LEASE = 30_000;
const error = (errno, detail = errno) => Object.assign(new Error(detail), { errno, detail });
const failure = e => ({ errno: e?.errno ?? 'EIO', detail: e?.detail ?? e?.message ?? 'console attachment failed' });
const remoteError = value => error(typeof value?.errno === 'string' && /^E[A-Z0-9]{1,31}$/.test(value.errno) ? value.errno : 'EPROTO',
  typeof value?.detail === 'string' ? value.detail.slice(0, 256) : 'console attachment closed');
const sizeValid = size => size && ['columns', 'rows', 'width', 'height'].every(key =>
  Number.isInteger(size[key]) && size[key] >= (key === 'columns' || key === 'rows' ? 1 : 0) && size[key] <= 65535);
const eventValid = event => {
  switch (event?.type) {
    case 'output': return [0, 1, 2].includes(event.fd) && typeof event.text === 'string' && event.text.length <= TEXT;
    case 'mode': return typeof event.raw === 'boolean' && typeof event.echo === 'boolean';
    case 'size': return sizeValid(event.size);
    case 'state': return ['running', 'stopped'].includes(event.state);
    case 'tty': case 'foreground': return typeof event.active === 'boolean';
    case 'reading': return true;
    default: return false;
  }
};
// Reconstruct the wire record instead of forwarding extra fields supplied by a
// peer (or owner-only fields such as run IDs and output acknowledgements).
const wireEvent = event => {
  switch (event.type) {
    case 'output': return { type: event.type, fd: event.fd, text: event.text };
    case 'mode': return { type: event.type, raw: event.raw, echo: event.echo };
    case 'size': return { type: event.type, size: Object.fromEntries(['columns', 'rows', 'width', 'height'].map(k => [k, event.size[k]])) };
    case 'state': return { type: event.type, state: event.state };
    case 'tty': case 'foreground': return { type: event.type, active: event.active };
    default: return { type: 'reading' };
  }
};
const weight = event => event.type === 'output' ? event.text.length * 2 : 128;
const portValid = port => port instanceof MessagePort;

export class ConsoleGrants {
  constructor({ limit = 64, now = () => performance.now(), lease = ATTACHMENT_LEASE, allowed = () => true } = {}) {
    this.limit = limit; this.now = now; this.lease = lease; this.records = new Map();
    this.allowed = allowed;
  }
  grant(run, port, access = 'view') {
    if (!portValid(port)) throw error('EINVAL', 'a transferred MessagePort is required');
    try {
      if (!['view', 'control'].includes(access)) throw error('EINVAL', 'unknown console access');
      if (!this.allowed(access)) throw error('EACCES', 'console sharing is disabled by the current account policy');
      if (!run || run.closed || !run.console || run.console.closed) throw error('ESRCH', 'console is not running');
      // The PTY arrives after authenticated registration/session bootstrap. A
      // grant cannot preauthorize a launch whose credentials are still unknown.
      if (!run.input) throw error('EAGAIN', 'console terminal is not ready');
      if (this.records.size >= this.limit) throw error('ENOSPC', 'too many console attachments');
      if (access === 'control' && [...this.records.values()].some(r => r.run === run && r.access === 'control'))
        throw error('EBUSY', 'console control is already granted');
      const record = { id: crypto.randomUUID(), run, port, access, connected: false, heard: this.now(),
        queue: [], pending: new Map(), bytes: 0, sequence: 0, request: 0 };
      this.records.set(record.id, record);
      this.changed(run);
      port.onmessage = ({ data }) => this.receive(record, data);
      port.onmessageerror = () => this.close(record, 'EPROTO', 'invalid console message');
      port.start();
      return record.id;
    } catch (e) { port.close(); throw e; }
  }
  receive(record, message) {
    if (!this.records.has(record.id)) return;
    if (!this.allowed(record.access)) return this.close(record, 'EACCES', 'console sharing policy changed or expired');
    if (message?.v !== VERSION) return this.close(record, 'EPROTO', 'unsupported console protocol');
    record.heard = this.now();
    if (message.type === 'close') return this.close(record, 'ECANCELED', 'console attachment detached');
    if (message.type === 'connect' && !record.connected) {
      record.connected = true;
      if (record.access === 'control') record.run.controller = record;
      this.changed(record.run);
      this.enqueue(record, { type: 'ready', access: record.access, snapshot: record.run.snapshot() });
      return;
    }
    if (!record.connected) return this.close(record, 'EPROTO', 'console attachment has not connected');
    if (message.type === 'ping') return this.send(record, { type: 'pong' });
    if (message.type === 'ack') {
      const pending = record.pending.get(message.sequence);
      if (!pending) return;
      record.bytes -= pending.bytes; record.pending.delete(message.sequence); this.flush(record); return;
    }
    if (message.type !== 'request' || !Number.isSafeInteger(message.id) || message.id <= record.request)
      return this.close(record, 'EPROTO', 'invalid console request');
    record.request = message.id;
    try {
      if (record.ending) throw error('EPIPE', 'console command ended');
      if (record.access !== 'control') throw error('EACCES', 'console attachment is view-only');
      // The original run must still own this pane's input. A grant never follows
      // a newer command, even if the pane, run ID or account is reused.
      record.run.remoteInput(record, message.operation, message.value);
      this.send(record, { type: 'reply', id: message.id, ok: null });
    } catch (e) { this.send(record, { type: 'reply', id: message.id, err: failure(e) }); }
  }
  send(record, value) {
    try { record.port.postMessage({ v: VERSION, ...value }); }
    catch { this.close(record, 'EPIPE', 'console attachment port failed'); }
  }
  publish(run, event) {
    if (event.type === 'output' && typeof event.text === 'string' && event.text.length > TEXT) {
      for (let at = 0; at < event.text.length;) {
        let end = Math.min(at + TEXT, event.text.length);
        // A renderer may consume each frame independently. Keep surrogate pairs
        // together rather than making two invalid strings from one character.
        const high = event.text.charCodeAt(end - 1), low = event.text.charCodeAt(end);
        if (high >= 0xd800 && high <= 0xdbff && low >= 0xdc00 && low <= 0xdfff) end--;
        this.publish(run, { type: 'output', fd: event.fd, text: event.text.slice(at, end) }); at = end;
      }
      return;
    }
    if (!eventValid(event)) return;
    for (const record of this.records.values()) if (record.run === run && record.connected && !record.ending) this.enqueue(record, wireEvent(event));
  }
  enqueue(record, event) {
    if (!this.allowed(record.access)) return this.close(record, 'EACCES', 'console sharing policy changed or expired');
    const bytes = weight(event), last = record.queue.at(-1);
    const merge = event.type === 'output' && last?.type === 'output' && last.fd === event.fd && last.text.length + event.text.length <= TEXT;
    if (record.bytes + bytes > BYTES || !merge && record.queue.length + record.pending.size >= FRAMES)
      return this.close(record, 'EOVERFLOW', 'console attachment cannot keep up with output');
    record.bytes += bytes;
    // A paste echoes one character at a time. Coalesce it before sending while
    // keeping the total pending data bounded independently of the owner display.
    if (merge) last.text += event.text;
    else record.queue.push({ ...event });
    if (!record.scheduled) {
      record.scheduled = true;
      queueMicrotask(() => { record.scheduled = false; this.flush(record); });
    }
  }
  flush(record) {
    if (!this.records.has(record.id)) return;
    while (record.queue.length && record.pending.size < WINDOW) {
      const event = record.queue.shift(), sequence = ++record.sequence;
      record.pending.set(sequence, { bytes: weight(event), at: this.now() });
      this.send(record, { type: 'event', sequence, event });
    }
    if (record.ending && !record.queue.length && !record.pending.size) this.close(record, 'EPIPE', record.ending);
  }
  revoke(id) {
    const record = this.records.get(id);
    if (!record) throw error('ENOENT', 'console grant does not exist');
    this.close(record, 'ECANCELED', 'console grant revoked');
  }
  revokeRun(run) {
    for (const record of this.records.values()) if (record.run === run) this.revoke(record.id);
  }
  changed(run) {
    run.sharing?.({ count: [...this.records.values()].filter(record => record.run === run).length,
      control: !!run.controller });
  }
  end(run, detail = 'console command ended', drain = true) {
    for (const record of this.records.values()) if (record.run === run) {
      if (!drain || !record.connected) this.close(record, 'EPIPE', detail);
      else {
        record.ending = detail;
        if (run.controller === record) run.controller = null;
        this.flush(record);
      }
    }
  }
  close(record, errno, detail) {
    if (!this.records.delete(record.id)) return;
    if (record.run.controller === record) record.run.controller = null;
    this.changed(record.run);
    try { record.port.postMessage({ v: VERSION, type: 'closed', err: { errno, detail } }); } catch { /* peer already gone */ }
    record.port.onmessage = record.port.onmessageerror = null; record.port.close();
    record.queue = []; record.pending.clear(); record.bytes = 0;
  }
  sweep() {
    const now = this.now();
    for (const record of this.records.values()) if (!this.allowed(record.access)) this.close(record, 'EACCES', 'console sharing policy changed or expired');
    for (const record of this.records.values()) if (now - record.heard >= this.lease ||
      [...record.pending.values()].some(pending => now - pending.at >= this.lease))
      this.close(record, 'ETIMEDOUT', 'console attachment lease expired');
  }
}

// The receiving execution host owns this endpoint. Its page acknowledges rendered
// events; an absent or stalled page cannot build an unbounded output queue.
export class ConsolePeer {
  constructor(port, { event = () => {}, closed = () => {}, now = () => performance.now(), lease = ATTACHMENT_LEASE } = {}) {
    if (!portValid(port)) throw error('EINVAL', 'a transferred MessagePort is required');
    this.port = port; this.event = event; this.onClosed = closed; this.now = now; this.lease = lease;
    this.opened = this.heard = now(); this.pending = new Map(); this.events = new Set(); this.next = 0; this.sequence = 0;
    this.ready = new Promise((resolve, reject) => { this.resolve = resolve; this.reject = reject; });
    port.onmessage = ({ data }) => this.receive(data);
    port.onmessageerror = () => this.close(error('EPROTO', 'invalid console message'));
    port.start(); this.send({ type: 'connect' });
  }
  send(message) {
    if (this.ended) return;
    try { this.port.postMessage({ v: VERSION, ...message }); }
    catch { this.close(error('EPIPE', 'console attachment port failed')); }
  }
  receive(message) {
    if (this.ended) return;
    if (message?.v !== VERSION) return this.close(error('EPROTO', 'unsupported console protocol'));
    this.heard = this.now();
    if (message.type === 'closed') return this.close(remoteError(message.err));
    if (message.type === 'pong') return;
    if (message.type === 'reply') {
      const pending = this.pending.get(message.id);
      if (pending) {
        this.pending.delete(message.id);
        if (message.err) pending.reject(remoteError(message.err));
        else pending.resolve();
      }
      return;
    }
    const event = message.event;
    if (message.type !== 'event' || message.sequence !== this.sequence + 1 || this.events.size >= WINDOW)
      return this.close(error('EPROTO', 'invalid console event sequence'));
    this.sequence = message.sequence;
    if (!this.connected) {
      if (event?.type !== 'ready' || !['view', 'control'].includes(event.access) || !Array.isArray(event.snapshot) ||
        event.snapshot.length > 5 || !Array.from(event.snapshot).every(e => eventValid(e) && ['mode', 'size', 'state', 'tty', 'foreground'].includes(e.type)))
        return this.close(error('EPROTO', 'invalid console snapshot'));
      this.connected = true; this.access = event.access;
      this.send({ type: 'ack', sequence: message.sequence }); this.resolve({ access: event.access, snapshot: event.snapshot.map(wireEvent) });
      return;
    }
    if (!eventValid(event)) return this.close(error('EPROTO', 'invalid console event'));
    this.events.add(message.sequence);
    this.event(wireEvent(event), message.sequence);
  }
  ack(sequence) { if (this.events.delete(sequence)) this.send({ type: 'ack', sequence }); }
  request(operation, value) {
    if (this.ended) return Promise.reject(error('EPIPE', 'console attachment closed'));
    if (!this.connected) return Promise.reject(error('EAGAIN', 'console attachment is connecting'));
    if (this.pending.size >= 16) return Promise.reject(error('EAGAIN', 'too many pending console requests'));
    return new Promise((resolve, reject) => {
      const id = ++this.next; this.pending.set(id, { resolve, reject, at: this.now() });
      this.send({ type: 'request', id, operation, value });
    });
  }
  close(reason = error('ECANCELED', 'console attachment detached')) {
    if (this.ended) return;
    this.ended = true;
    try { this.port.postMessage({ v: VERSION, type: 'close' }); } catch { /* peer already gone */ }
    this.port.onmessage = this.port.onmessageerror = null; this.port.close();
    this.reject(reason);
    for (const pending of this.pending.values()) pending.reject(reason);
    this.pending.clear(); this.events.clear(); this.onClosed(failure(reason));
  }
  sweep() {
    if (this.ended) return;
    const now = this.now();
    if ((!this.connected && now - this.opened >= this.lease) || now - this.heard >= this.lease || [...this.pending.values()].some(pending => now - pending.at >= this.lease))
      this.close(error('ETIMEDOUT', 'console attachment lease expired'));
    else this.send({ type: 'ping' });
  }
}

// Validate before reaching the PTY. The control grant covers only these operations.
export function consoleInput(run, operation, value) {
  if (!run.input) throw error('EAGAIN', 'console input is not ready');
  if (operation === 'input' || operation === 'reply') {
    if (typeof value !== 'string' || value.length > TEXT) throw error('EINVAL', 'console input is too large');
    if (operation === 'input') run.input.write(value);
    else run.input.enqueue(new TextEncoder().encode(value));
  } else if (operation === 'eof') run.input.eof();
  else if (operation === 'resize') {
    if (!sizeValid(value)) throw error('EINVAL', 'invalid console dimensions');
    run.input.resize(value);
  } else throw error('ENOSYS', 'unsupported console operation');
}

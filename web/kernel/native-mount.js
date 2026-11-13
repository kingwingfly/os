import { pinImage } from './local-mounts.js';
const bad = (errno, message = errno) => Object.assign(new Error(message), { errno });
const CHUNK = 256 * 1024;
const decode = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));
const encode = bytes => { let text = ''; for (let i = 0; i < bytes.length; i += 8192) text += String.fromCharCode(...bytes.subarray(i, i + 8192)); return btoa(text); };
const hash = async bytes => [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(b => b.toString(16).padStart(2, '0')).join('');

export class NativeMount {
  #url; #proof; #handles = new WeakMap(); #alive = true; #timer;
  static async connect(args) {
    const url = new URL(args.url);
    if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port || url.pathname !== '/' || url.search || url.hash || url.username || url.password || !/^[a-f0-9]{64}$/.test(args.token)) throw bad('EINVAL', 'use the loopback URL and token printed by os-local-helper');
    const provider = new NativeMount(url.href);
    const mounted = await provider.rpc(args.token, { op: 'mount', write: !!args.writable, execute: !!args.execute });
    if (mounted.protocol !== 1 || !/^[a-f0-9]{64}$/.test(mounted.proof)) throw bad('EPROTONOSUPPORT');
    provider.#proof = mounted.proof;
    provider.grant = Object.freeze({ kind: 'native-directory', name: args.name, readOnly: !mounted.write, execute: mounted.execute });
    provider.#timer = setInterval(() => { void provider.request(provider.grant, 'keep', {}).catch(() => provider.unmount(provider.grant)); }, 20000);
    return provider;
  }
  constructor(url) { this.#url = url; }
  check(grant) { if (grant !== this.grant) throw bad('EACCES'); if (!this.#alive) throw bad('ENODEV', 'local filesystem adapter is disconnected'); }
  async rpc(proof, args) {
    let response;
    try { response = await fetch(this.#url, { method: 'POST', credentials: 'omit', redirect: 'error', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + proof }, body: JSON.stringify(args), signal: AbortSignal.timeout(15000) }); }
    catch { throw bad('ENODEV', 'local filesystem adapter is offline or the browser denied loopback access'); }
    const reply = await response.json();
    if (reply.err) throw bad(reply.err.errno, reply.err.detail);
    if (!response.ok || !Object.hasOwn(reply, 'ok')) throw bad('EIO'); return reply.ok;
  }
  async request(grant, op, args) {
    this.check(grant);
    if (args.path && typeof args.path === 'object') {
      const handle = this.#handles.get(args.path); if (!handle) throw bad('EBADF');
      const { path, ...rest } = args; args = { ...rest, handle };
    }
    const value = await this.rpc(this.#proof, { ...args, op }); this.check(grant); return value;
  }
  async open(grant, path, flags, root = '') {
    if (grant.readOnly && ((flags & 3) !== 0 || flags & (0o100 | 0o1000))) throw bad('EROFS');
    const id = await this.request(grant, 'open', { path, flags, root }), handle = Object.freeze({}); this.#handles.set(handle, id); return handle;
  }
  hold(grant, path, root = '') { return this.open(grant, path, grant.readOnly ? 0 : 2, root); }
  async release(grant, path) { try { await this.request(grant, 'release', { path }); } finally { this.#handles.delete(path); } }
  async stat(grant, path, { follow = true } = {}) {
    const value = await this.request(grant, 'stat', { path, follow });
    if (value.kind === 'file' && grant.execute) {
      const header = await this.read(grant, path, 0, 8).catch(() => new Uint8Array());
      value.executable = [0, 97, 115, 109, 1, 0, 0, 0].every((b, i) => header[i] === b);
    }
    return { ...value, readOnly: grant.readOnly, executable: grant.execute && value.executable };
  }
  list(grant, path, options) { return this.request(grant, 'list', { path, ...options }); }
  async read(grant, path, offset, count) { return decode(await this.request(grant, 'read', { path, offset, count: Math.min(CHUNK, count) })); }
  async write(grant, path, bytes, options = {}) {
    if (grant.readOnly) throw bad('EROFS'); let written = 0, answer;
    do {
      const chunk = bytes.subarray(written, written + CHUNK);
      answer = await this.request(grant, 'write', { path, ...options, offset: (options.offset ?? 0) + written, truncate: written ? null : options.truncate, data: encode(chunk) });
      if (!Number.isSafeInteger(answer.written) || answer.written < 0 || answer.written > chunk.length || chunk.length && !answer.written) throw bad('EIO');
      written += answer.written;
    } while (written < bytes.length);
    return { ...answer, written };
  }
  mkdir(grant, path) { return this.request(grant, 'mkdir', { path }); }
  remove(grant, path, directory) { return this.request(grant, 'remove', { path, directory }); }
  rename(grant, path, to) { return this.request(grant, 'rename', { path, to }); }
  async pin(grant, path) {
    if (!grant.execute) throw bad('EACCES');
    const pin = await this.request(grant, 'pin', { path });
    try {
      if (!Number.isSafeInteger(pin.size) || pin.size < 8 || pin.size > 128 * 1024 * 1024) throw bad('ENOEXEC');
      const bytes = new Uint8Array(pin.size);
      for (let offset = 0; offset < bytes.length; offset += CHUNK) {
        const part = decode(await this.request(grant, 'image', { id: pin.id, offset }));
        if (part.length !== Math.min(CHUNK, bytes.length - offset)) throw bad('ESTALE'); bytes.set(part, offset);
      }
      if (await hash(bytes) !== pin.digest) throw bad('EIO');
      return pinImage(bytes, () => this.request(grant, 'keep', {}));
    } finally { await this.request(grant, 'unpin', { id: pin.id }).catch(() => {}); }
  }
  unmount(grant) {
    if (grant !== this.grant) throw bad('EACCES'); if (!this.#alive) return;
    this.#alive = false; clearInterval(this.#timer); void this.rpc(this.#proof, { op: 'unmount' }).catch(() => {});
  }
}

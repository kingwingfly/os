// The host adapter owns structured-cloneable directory handles and helper credentials.
// Only the public projection is mirrored into the kernel's HostSourceTable.
const fail = (errno, message) => Object.assign(new Error(message), { errno });
const permission = writable => ({ mode: writable ? 'readwrite' : 'read' });
const cancelled = () => fail('ECANCELED', 'Session changed. Choose the folder again.');
const publicInfo = ({ id, kind, label, location, state, writable, execute, saved, owner_uid }) =>
  ({ id, kind, label, location, state, writable, execute, saved, owner_uid });

export function savedSourceStore(idb = globalThis.indexedDB) {
  let opened;
  const database = () => opened ??= new Promise((resolve, reject) => {
    if (!idb) { reject(fail('ENOTSUP', 'Saved folders require IndexedDB.')); return; }
    const req = idb.open('os-mount-sources-v2', 1);
    req.onupgradeneeded = () => req.result.createObjectStore('sources', { keyPath: ['volume', 'uid', 'id'] });
    req.onerror = () => { opened = undefined; reject(req.error); };
    req.onsuccess = () => resolve(req.result);
  });
  async function operation(mode, fn, signal) {
    const db = await database();
    if (signal?.aborted) throw cancelled();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('sources', mode);
      const abort = () => tx.abort();
      signal?.addEventListener('abort', abort, { once: true });
      const request = fn(tx.objectStore('sources'));
      const finish = () => signal?.removeEventListener('abort', abort);
      tx.oncomplete = () => { finish(); resolve(request.result); };
      tx.onabort = tx.onerror = () => { finish(); reject(tx.error ?? cancelled()); };
    });
  }
  return {
    list: (volume, uid, signal) => !idb ? Promise.resolve([]) : operation('readonly', s => s.getAll(IDBKeyRange.bound([volume, uid, ''], [volume, uid, []])), signal),
    get: (volume, uid, id) => operation('readonly', s => s.get([volume, uid, id])),
    put: (record, signal) => operation('readwrite', s => s.put(record), signal),
    remove: (volume, uid, id, signal) => operation('readwrite', s => s.delete([volume, uid, id]), signal),
  };
}

export class SourceRegistry {
  #session;
  #entries = new Map();
  #abort;
  #queue = Promise.resolve();
  #store;
  #opfs;
  #uuid;
  #table;
  #connectShare;
  constructor({ store = savedSourceStore(), opfs = () => navigator.storage.getDirectory(), uuid = () => crypto.randomUUID(), table, connectShare } = {}) {
    this.#store = store; this.#opfs = opfs; this.#uuid = uuid; this.#table = table; this.#connectShare = connectShare;
  }
  beginSession({ uid, gid = uid, id, volume, loginEpoch }) {
    if (!Number.isSafeInteger(uid) || uid < 0 || !id || !Number.isSafeInteger(loginEpoch) ||
        (this.#session && loginEpoch <= this.#session.loginEpoch)) throw cancelled();
    this.#abort?.abort();
    this.#abort = new AbortController();
    this.#entries.clear();
    this.#table?.change_session(uid, loginEpoch);
    this.#session = Object.freeze({ uid, gid, id, volume, loginEpoch });
    this.#queue = Promise.resolve();
    return this.#serial(loginEpoch, async session => {
      if (!volume) return;
      for (const record of await this.#store.list(volume, uid, this.#abort.signal)) {
        this.#check(session);
        const info = publicInfo(record.info);
        if (record.volume !== volume || record.uid !== uid || info.owner_uid !== uid || record.id !== info.id || info.kind !== 'hostfs') continue;
        info.state = await this.#permissionState(record.handle, info.writable);
        this.#check(session);
        this.#record(info, { handle: record.handle }, record.cloud === true);
      }
    });
  }
  get session() { return this.#abort?.signal.aborted ? undefined : this.#session; }
  #check(session) {
    if (!session || session !== this.#session || this.#abort.signal.aborted) throw cancelled();
  }
  endSession() {
    this.#abort?.abort();
    if (this.#session) this.#table?.end_session(this.#session.loginEpoch);
    this.#entries.clear();
  }
  #serial(epoch, fn) {
    const session = this.#session;
    if (epoch !== session?.loginEpoch) return Promise.reject(cancelled());
    const next = this.#queue.then(() => { this.#check(session); return fn(session); });
    this.#queue = next.catch(() => {});
    return next;
  }
  async #permissionState(handle, writable) {
    try { return await handle.queryPermission(permission(writable)) === 'granted' ? 'granted' : 'needs_renewal'; }
    catch { return 'needs_renewal'; }
  }
  #record(info, provider, cloud) {
    if (this.#entries.has(info.id)) throw fail('EEXIST', 'Source ID already exists.');
    this.#table?.register_source_grant(this.#session.loginEpoch, JSON.stringify(info), []);
    this.#entries.set(info.id, { info, provider, cloud });
  }
  #setState(entry, state) {
    this.#table?.set_source_state(this.#session.loginEpoch, entry.info.id, state);
    entry.info.state = state;
  }
  register(kind, args) {
    return this.#serial(args.loginEpoch, async session => {
      const { writable = false, execute = false, save = false, cloud = false } = args;
      if (![writable, execute, save, cloud].every(v => typeof v === 'boolean')) throw fail('EINVAL', 'Invalid grant options.');
      const id = 'src:' + this.#uuid();
      let provider, label, location;
      if (kind === 'hostfs' && Array.isArray(args.files)) {
        if (!args.files.length || save || writable) throw fail('EINVAL', 'Selected files must be read-only.');
        provider = { files: args.files }; label = location = 'Selected files';
      } else if (kind === 'hostfs') {
        const handle = args.handle;
        if (handle?.kind !== 'directory' || typeof handle.isSameEntry !== 'function' || typeof handle.resolve !== 'function') throw fail('EINVAL', 'Choose a directory.');
        const root = await this.#opfs();
        if (await root.isSameEntry(handle) || await root.resolve(handle) !== null) throw fail('EINVAL', 'These browser storage handles must use browser storage mount. Choose a host folder outside browser storage.');
        for (const entry of this.#entries.values()) {
          const other = entry.provider.handle;
          if (other && (await other.isSameEntry(handle) || await other.resolve(handle) !== null || await handle.resolve(other) !== null)) {
            throw fail('EEXIST', 'This folder overlaps an existing source.');
          }
        }
        if (await this.#permissionState(handle, writable) !== 'granted') throw fail('EACCES', 'The requested local directory permission was not granted.');
        provider = { handle }; label = location = handle.name;
      } else if (kind === 'opfs') {
        const root = await this.#opfs();
        provider = { storage: true }; label = 'Browser storage'; location = 'opfs:root';
        if (args.handle) {
          const path = await root.resolve(args.handle);
          if (args.handle.kind !== 'directory' || path?.length !== 1 || path[0] === 'os-orphans') {
            throw fail('EACCES', 'Choose a top-level browser storage directory.');
          }
          provider = { originPrivate: true, handle: args.handle };
          location = 'opfs:' + path[0];
        }
      } else if (kind === 'helperfs') {
        const url = new URL(args.url);
        if (!['http:', 'https:'].includes(url.protocol) || !['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname) ||
            url.username || url.password || url.search || url.hash || !args.token) throw fail('EINVAL', 'A loopback helper URL and token are required.');
        // The visible location must not include a bearer token or a URL path.
        provider = { url: url.href, token: args.token }; label = 'Local helper'; location = url.origin;
      } else if (kind === 'sharefs' && /^osfs:[A-Za-z0-9._-]+$/.test(args.address)) {
        provider = { address: args.address, password: args.password }; label = 'Shared directory'; location = args.address;
      } else throw fail('ENODEV', 'Unknown source kind.');
      this.#check(session);
      const info = { id, kind: provider.files ? 'selected_files' : kind, label, location, state: 'granted', writable, execute, saved: save, owner_uid: session.uid };
      if (save && kind !== 'hostfs') throw fail('EINVAL', 'Only browser folder handles can be saved.');
      if (save) {
        if (!session.volume) throw fail('ENOTSUP', 'Saving a folder requires a persistent root volume.');
        await this.#store.put({ volume: session.volume, uid: session.uid, id, info, handle: provider.handle, cloud }, this.#abort.signal);
        this.#check(session);
      }
      this.#record(info, provider, cloud);
      return { source_id: id };
    });
  }
  list(loginEpoch) {
    return this.#serial(loginEpoch, async session => {
      const sources = [];
      for (const entry of this.#entries.values()) {
        if (entry.info.kind === 'hostfs' && entry.provider.handle) {
          const state = await this.#permissionState(entry.provider.handle, entry.info.writable);
          this.#check(session); this.#setState(entry, state);
        }
        sources.push(publicInfo(entry.info));
      }
      return sources;
    });
  }
  renew(source_id, loginEpoch) {
    return this.#serial(loginEpoch, async session => {
      const entry = this.#entries.get(source_id);
      if (!entry || entry.info.kind !== 'hostfs') throw fail('ENOENT', 'Unknown folder grant.');
      const state = await this.#permissionState(entry.provider.handle, entry.info.writable);
      this.#check(session); this.#setState(entry, state);
      if (state !== 'granted') throw fail('EACCES', 'Folder access denied.');
      return publicInfo(entry.info);
    });
  }
  forget(source_id, loginEpoch) {
    return this.#serial(loginEpoch, async session => {
      const entry = this.#entries.get(source_id);
      if (!entry) throw fail('ENOENT', 'Unknown source.');
      if (entry.info.saved) await this.#store.remove(session.volume, session.uid, source_id, this.#abort.signal);
      this.#check(session); this.#entries.delete(source_id);
    });
  }
  // Called only on the worker's private mountd backend channel.
  async #prepare(operation, session) {
    const entry = this.#entries.get(operation.source_id);
    const shared = operation.fstype === 'sharefs';
    const implicit = !entry && ((shared && operation.source_id.startsWith('osfs:')) ||
      (operation.fstype === 'opfs' && !operation.source_id.startsWith('src:')));
    if (!implicit && (!entry || (entry.info.kind === 'selected_files' ? 'hostfs' : entry.info.kind) !== operation.fstype)) throw fail('EACCES', 'Source unavailable.');
    if (entry?.info.kind === 'hostfs' && entry.provider.handle) {
      const state = await this.#permissionState(entry.provider.handle, entry.info.writable);
      this.#check(session); this.#setState(entry, state);
    }
    if (entry && entry.info.state !== 'granted') throw fail('EACCES', 'Renew this source in Mounts.');
    const access = { writable: !(operation.flags & 1) && (entry?.info.writable ?? true),
      execute: !(operation.flags & 8) && (entry?.info.execute ?? true), cloud: entry?.cloud ?? false };
    const name = operation.target.split('/').at(-1);
    const { prepareUserMount } = await import('./workspace.js');
    if (shared && !this.#connectShare) throw fail('ENOTCONN', 'Export transport unavailable.');
    const prepared = shared ?
      { spec: { kind: 'sharefs', name, ...access }, hostObj: await this.#connectShare({
        ...operation, address: entry?.provider.address ?? operation.source_id, password: entry?.provider.password
      }, session) } :
      await prepareUserMount({ ...(entry?.provider ?? { storage: true }), name, target: operation.target, ...access }, session);
    try { this.#check(session); return prepared; }
    catch (e) { prepared.cleanup?.(); throw e; }
  }
  openImageSource(operation, loginEpoch) {
    return this.#serial(loginEpoch, session => this.#prepare(operation, session));
  }
  attach(operation, loginEpoch, kernel) {
    return this.#serial(loginEpoch, async session => {
      const prepared = await this.#prepare(operation, session);
      try {
        this.#check(session);
        const reply = await kernel.mount_user(session.id, JSON.stringify({ ...prepared.spec, flags: operation.flags, target: operation.target }), prepared.hostObj);
        this.#check(session);
        return reply;
      } catch (e) { prepared.cleanup?.(); throw e; }
    });
  }
}

// Window-side capability handling. Preload only the renewal closure so requestPermission
// runs in the click's user activation even though IndexedDB reads are asynchronous.
export async function prepareRenewal(session, source, current, call, store = savedSourceStore()) {
  const record = await store.get(session.volume, session.uid, source.id);
  if (!record || record.volume !== session.volume || record.uid !== session.uid) throw fail('ENOENT', 'Saved folder unavailable.');
  return () => {
    if (!current()) throw cancelled();
    return record.handle.requestPermission(permission(source.writable)).then(async result => {
      if (!current()) throw cancelled();
      if (result !== 'granted') throw fail('EACCES', 'Folder access denied.');
      return call('source_renew', { source_id: source.id, loginEpoch: session.loginEpoch });
    });
  };
}

export async function registerPickedFolder(selection, options, current, call) {
  const handle = await selection;
  if (!current()) throw cancelled();
  return call('source_register_host', { ...options, handle });
}

export function registerHelperFolder(form, options, call) {
  return call('source_register_helper', { ...options, url: form.elements.url.value, token: form.elements.token.value });
}

export function registerSharedFolder(form, options, call) {
  return call('source_register_share', {
    ...options, address: form.elements.address.value.trim(), password: form.elements.password.value,
  });
}

// The worker passes its authenticated session/proxy here. No page argument selects a PID or UID.
export function mountPageRequest(type, args, { registry, kernel, proxyPid, socketOp }) {
  const session = registry.session;
  if (!session) throw cancelled();
  if (type === 'source_session') return session;
  if (args.loginEpoch !== session.loginEpoch) throw cancelled();
  switch (type) {
    case 'source_register_host': return registry.register('hostfs', args);
    case 'source_register_opfs': return registry.register('opfs', args);
    case 'source_register_helper': return registry.register('helperfs', args);
    case 'source_register_share': return registry.register('sharefs', args);
    case 'source_renew': return registry.renew(args.source_id, args.loginEpoch);
    case 'unix_rpc':
      if (args.fd != null) throw fail('EBADF');
      return kernel.page_unix_rpc(session.id, proxyPid, args.socket, JSON.stringify(args.request), args.fd, socketOp);
    default: throw fail('EINVAL', 'Unknown mount adapter operation.');
  }
}

// One AF_UNIX stream per backend operation. The kernel-side holder owns
// every SCM_RIGHTS reference it receives and closes it after one bounded primitive.
export async function serveMountBackend({ kernel, table, registry, pid, sockId, socketOp, exportsFor, isMountService, signal }) {
  const sock = args => socketOp({ pid, args: { sockId, ...args } });
  const encoder = new TextEncoder(), decoder = new TextDecoder('utf-8', { fatal: true });
  const deadline = performance.now() + 45000;
  const wait = async () => {
    if (signal?.aborted) throw cancelled();
    if (performance.now() >= deadline) throw fail('ETIMEDOUT', 'Mount backend timed out.');
    await new Promise(resolve => setTimeout(resolve, 5));
  };
  const adapter = ({ pid: caller, uid, sessionId, loginEpoch, operation }) => {
    if (operation.op === 'exports') return exportsFor ? exportsFor(uid) : [];
    if (!sessionId || uid !== registry.session?.uid || sessionId !== registry.session.id ||
        loginEpoch !== registry.session.loginEpoch) throw cancelled();
    switch (operation.op) {
      case 'refresh_sources': return registry.list(loginEpoch).then(() => null);
      case 'attach': return registry.attach({ ...operation, pid: caller }, loginEpoch, kernel);
      case 'image_source': return registry.openImageSource({ ...operation, pid: caller }, loginEpoch);
      case 'forget': return registry.forget(operation.source_id, loginEpoch);
      default: throw fail('EINVAL', 'Unknown host operation.');
    }
  };
  try {
    // Only a process executing the verified mountd image gets this adapter. The executor
    // owns the launch record and invalidates it on exec/exit. A pathname alone grants nothing.
    const daemon = await sock({ op: 'peercred' });
    if (!isMountService(daemon.pid)) throw fail('EACCES', 'Untrusted mount service.');
    const buffer = new Uint8Array(65536);
    let length = 0, accepted;
    try {
      while (length < buffer.length) {
        const msg = await sock({ op: 'recvmsg', sabStream: true, bufLen: Math.min(4096, buffer.length - length), maxFds: 1 });
        if (msg.wouldBlock) { await wait(); continue; }
        const chunk = Uint8Array.from(atob(msg.data), ch => ch.charCodeAt(0));
        if (!chunk.length) return;
        for (const fd of msg.fds) {
          if (fd.kind !== 'unix_sock') throw fail('EPROTO', 'Expected a client socket.');
          if (accepted != null) {
            await sock({ op: 'close', sockId: fd.sockId });
            throw fail('EINVAL', 'Duplicate client socket.');
          }
          accepted = fd.sockId;
        }
        buffer.set(chunk, length); length += chunk.length;
        if (chunk.includes(10)) break;
      }
      if (accepted == null || buffer[length - 1] !== 10 || buffer.subarray(0, length - 1).includes(10)) {
        throw fail('EINVAL', 'Invalid backend frame.');
      }
      let reply;
      try {
        if (!isMountService(daemon.pid)) throw fail('EACCES', 'Mount service exited.');
        reply = { Ok: await kernel.mount_backend_call(pid, sockId, accepted, decoder.decode(buffer.subarray(0, length)), table, adapter) };
      } catch (e) { reply = { Err: e.errno ?? 'EIO' }; }
      let bytes = encoder.encode(JSON.stringify(reply) + '\n');
      if (bytes.length > 65536) bytes = encoder.encode('{"Err":"E2BIG"}\n');
      let sent = 0;
      while (sent < bytes.length) {
        const data = btoa(String.fromCharCode(...bytes.subarray(sent, sent + 4096)));
        try {
          const res = await sock({ op: 'sendmsg', data });
          if (!res.sent) throw fail('EPIPE', 'Backend closed.');
          sent += res.sent;
        } catch (e) { if (e.errno !== 'EAGAIN') throw e; await wait(); }
      }
    } finally { if (accepted != null) await sock({ op: 'close', sockId: accepted }); }
  } finally { await sock({ op: 'close' }); }
}

// PID 1 holds the host listener in the instance socket table. The executor supplies
// socketOp from the guest socket dispatcher and isMountService from verified process images.
export async function startMountHost(context) {
  const pid = 1, sockId = await context.kernel.mount_host_listener();
  const pending = new Set();
  const controller = new AbortController();
  async function accept() {
    while (!controller.signal.aborted) {
      const client = await context.socketOp({ pid, args: { op: 'accept', sockId } });
      if (client.wouldBlock) { await new Promise(resolve => setTimeout(resolve, 10)); continue; }
      if (!context.isMountService(client.peerCred.pid) || pending.size >= 64) {
        await context.socketOp({ pid, args: { op: 'close', sockId: client.sockId } });
        continue;
      }
      const job = serveMountBackend({ ...context, pid, sockId: client.sockId, signal: controller.signal });
      pending.add(job);
      job.catch(e => context.onError?.(e)).finally(() => pending.delete(job));
    }
  }
  const serving = accept();
  serving.catch(e => context.onError?.(e));
  return async () => {
    controller.abort();
    try { await serving; await Promise.allSettled(pending); }
    finally { await context.socketOp({ pid, args: { op: 'close', sockId } }); }
  };
}

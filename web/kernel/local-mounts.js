// Private execution-host capabilities, not mount names or server credentials. The host
// must retain these objects; serializing their metadata does not delegate access. This
// provider does not invent host POSIX ownership, x bits or symlinks.
import { IMAGE_MAX } from './transform.js';

const pins = new WeakMap();
const READ_MAX = 1024 * 1024, FILES_MAX = 1024, MOUNTS_MAX = 16;
const error = (errno, message) => Object.assign(new Error(message), { errno });
function refusal(reason) {
  if (reason?.errno) return reason;
  const errno = { NotAllowedError: 'EACCES', SecurityError: 'EACCES', NotFoundError: 'ENOENT',
    NotReadableError: 'EIO', InvalidStateError: 'EIO', AbortError: 'EIO', TypeMismatchError: 'ENOTDIR',
    NoModificationAllowedError: 'EBUSY', InvalidModificationError: 'ENOTEMPTY', NotSupportedError: 'EOPNOTSUPP', QuotaExceededError: 'ENOSPC' }[reason?.name] ?? 'EIO';
  return error(errno, reason?.message ?? 'local filesystem unavailable');
}
function parts(path) {
  if (typeof path !== 'string' || path.length > 4096 || /[\0\\]/.test(path)) throw error('EINVAL', 'invalid mount-relative path');
  if (path.startsWith('/') || path.split('/').includes('..')) throw error('EACCES', 'path escapes local mount');
  const names = path.split('/').filter(name => name && name !== '.');
  if (names.length > 256 || names.some(name => name.length > 255)) throw error('ENAMETOOLONG', 'local path is too long');
  return names;
}
const hex = bytes => [...new Uint8Array(bytes)].map(value => value.toString(16).padStart(2, '0')).join('');

// Host providers mint capabilities only after validating their source grant. The
// bytes are copied and the provider's live authorization is checked at every load.
export async function pinImage(source, check) {
  await check();
  if (!(source instanceof Uint8Array) || source.length > IMAGE_MAX || typeof check !== 'function') throw error('EINVAL', 'invalid image snapshot');
  const bytes = source.slice(), digest = hex(await crypto.subtle.digest('SHA-256', bytes));
  await check();
  const pin = Object.freeze({ source: 'local', digest, size: bytes.length });
  pins.set(pin, { bytes, check }); return pin;
}

export class LocalMounts {
  #states = new WeakMap();
  #held = new WeakMap();
  #active = new Set();
  #add(info, source) {
    if (this.#active.size >= MOUNTS_MAX) throw error('ENOSPC', 'too many local mounts');
    const grant = Object.freeze({ readOnly: true, ...info });
    const state = { grant, source, active: true, writes: Promise.resolve(), waiting: 0, held: new Set() };
    this.#states.set(grant, state); this.#active.add(grant);
    return state;
  }
  #state(grant) {
    const state = this.#states.get(grant);
    if (!state) throw error('EACCES', 'unknown local mount grant');
    if (!state.active) throw error('ENODEV', 'local mount is detached');
    return state;
  }
  async #check(state) {
    this.#state(state.grant);
    try {
      if (state.grant.kind === 'directory' && await state.source.queryPermission({ mode: state.grant.readOnly ? 'read' : 'readwrite' }) !== 'granted') {
        throw error('EACCES', 'local directory permission was revoked');
      }
    } catch (reason) {
      this.unmount(state.grant);
      throw refusal(reason);
    }
    this.#state(state.grant); // unmount may have won while permission was being queried
  }
  async #operation(grant, run) {
    const state = this.#state(grant);
    await this.#check(state);
    try {
      const operation = { ...state, resolved: new Set(), boundaries: new Map() };
      const value = await run(operation);
      // A path may move out of the granted tree while getFile/read/hash is pending.
      // Revalidate the handles used by this operation before returning any result.
      for (const handle of operation.resolved) {
        this.#state(grant);
        if (await state.source.resolve(handle) === null) throw error('EACCES', 'entry left local mount during access');
        const boundary = operation.boundaries.get(handle);
        if (boundary && await boundary.resolve(handle) === null) throw error('ESTALE', 'entry left exported directory during access');
      }
      await this.#check(state);
      return value;
    } catch (reason) {
      this.#state(grant);
      const failure = refusal(reason);
      if (['NotAllowedError', 'SecurityError'].includes(reason?.name)) this.unmount(grant);
      throw failure;
    }
  }
  async mountDirectory(handle, { execute = false, originPrivate = false, writable = false } = {}) {
    if ([execute, originPrivate, writable].some(value => typeof value !== 'boolean')) throw error('EINVAL', 'invalid local mount options');
    if (handle?.kind !== 'directory' || ['resolve', 'entries', 'getDirectoryHandle', 'getFileHandle'].some(name => typeof handle[name] !== 'function')) {
      throw error('EINVAL', 'a directory handle is required');
    }
    if (!originPrivate && typeof handle.queryPermission !== 'function') throw error('ENOTSUP', 'directory permissions cannot be checked');
    const state = this.#add({ kind: originPrivate ? 'browser-storage' : 'directory', name: handle.name, execute, readOnly: !writable }, handle);
    try {
      if (originPrivate) {
        // A caller cannot bypass permission checks by labelling a host handle as OPFS.
        if (!globalThis.navigator?.storage?.getDirectory) throw error('ENOTSUP', 'browser storage is unavailable');
        const root = await navigator.storage.getDirectory();
        if (await root.resolve(handle) === null) throw error('EACCES', 'handle is outside browser storage');
      }
      await this.#check(state);
      return state.grant;
    } catch (reason) { this.unmount(state.grant); throw refusal(reason); }
  }
  async mountFiles(files, { execute = false } = {}) {
    if (typeof execute !== 'boolean' || !Array.isArray(files) || !files.length || files.length > FILES_MAX) throw error('EINVAL', 'select between 1 and 1024 files');
    const entries = new Map([['', { kind: 'directory', name: '' }]]);
    const state = this.#add({ kind: 'snapshot', name: 'Selected files', execute }, entries);
    let size = 0;
    try {
      for (const file of files) {
        if (!(file instanceof Blob) || typeof file.name !== 'string') throw error('EINVAL', 'a selected File is required');
        const names = parts(file.webkitRelativePath || file.name), name = names.join('/');
        if (!name || entries.has(name)) throw error('EEXIST', 'duplicate or empty selected path');
        size += file.size;
        if (size > IMAGE_MAX) throw error('EFBIG', 'selected files exceed 128 MiB');
        for (let i = 1; i < names.length; i++) {
          const parent = names.slice(0, i).join('/');
          if (entries.get(parent)?.kind === 'file') throw error('ENOTDIR', 'a selected file is also a directory');
          entries.set(parent, { kind: 'directory', name: names[i - 1] });
        }
        // Copy at selection, not at a later read: a File backed by a changed host file can
        // become unreadable. The fallback promises a snapshot, never a live host mount.
        const bytes = await file.arrayBuffer();
        this.#state(state.grant);
        if (bytes.byteLength !== file.size) throw error('EIO', 'selected file changed while reading');
        entries.set(name, { kind: 'file', name: names.at(-1), file: new Blob([bytes]), lastModified: file.lastModified });
      }
      this.#state(state.grant);
      return state.grant;
    } catch (reason) { this.unmount(state.grant); throw refusal(reason); }
  }
  async #find(state, path) {
    if (path && typeof path === 'object') {
      const held = this.#held.get(path);
      if (!held || held.grant !== state.grant) throw error('EBADF', 'unknown local file description');
      if (state.grant.kind !== 'snapshot') {
        if (await state.source.resolve(held.entry) === null || await held.boundary.resolve(held.entry) === null) throw error('ESTALE', 'open file left its granted directory');
        state.resolved.add(held.entry);
        state.boundaries.set(held.entry, held.boundary);
      }
      return held.entry;
    }
    const names = parts(path);
    let entry;
    if (state.grant.kind === 'snapshot') {
      for (let i = 1; i < names.length; i++) {
        if (state.source.get(names.slice(0, i).join('/'))?.kind === 'file') throw error('ENOTDIR', 'not a directory');
      }
      entry = state.source.get(names.join('/'));
      if (!entry) throw error('ENOENT', 'local path does not exist');
    } else {
      entry = state.source;
      for (let i = 0; i < names.length; i++) {
        try { entry = await entry.getDirectoryHandle(names[i]); }
        catch (reason) {
          if (reason.name !== 'TypeMismatchError' || i !== names.length - 1) throw reason;
          entry = await entry.getFileHandle(names[i]);
        }
      }
      // Handles must remain within the chosen root, including after a concurrent move.
      if (await state.source.resolve(entry) === null) throw error('EACCES', 'entry is outside local mount');
      state.resolved.add(entry);
    }
    if ((path.endsWith('/') || path.endsWith('/.')) && entry.kind !== 'directory') throw error('ENOTDIR', 'not a directory');
    return entry;
  }
  async #file(state, path) {
    const entry = await this.#find(state, path);
    if (entry.kind !== 'file') throw error('EISDIR', 'local path is a directory');
    if (path && typeof path === 'object') return this.#held.get(path).file;
    return state.grant.kind === 'snapshot' ? entry.file : await entry.getFile();
  }
  hold(grant, path, root = '') {
    return this.#operation(grant, async state => {
      const entry = await this.#find(state, path), boundary = await this.#find(state, root);
      if (entry.kind !== 'file' || boundary.kind !== 'directory') throw error('EISDIR', 'a regular file is required');
      if (grant.kind !== 'snapshot' && await boundary.resolve(entry) === null) throw error('EACCES', 'file is outside exported directory');
      if (state.held.size >= 1024) throw error('EMFILE', 'too many open local files');
      const reference = Object.freeze({}), held = { grant, entry, boundary, file: grant.kind === 'snapshot' ? entry.file : await entry.getFile() };
      this.#held.set(reference, held); state.held.add(held); return reference;
    });
  }
  release(grant, reference) {
    if (this.#held.get(reference)?.grant !== grant) throw error('EBADF', 'unknown local file description');
    this.#states.get(grant).held.delete(this.#held.get(reference)); this.#held.delete(reference);
  }
  stat(grant, path = '') {
    return this.#operation(grant, async state => {
      const entry = await this.#find(state, path);
      const file = entry.kind === 'file' ? await this.#file(state, path) : null;
      const header = file && grant.execute ? new Uint8Array(await file.slice(0, 8).arrayBuffer()) : null;
      const executable = !!header && [0, 97, 115, 109, 1, 0, 0, 0].every((byte, i) => header[i] === byte);
      return { kind: entry.kind, name: entry.name, readOnly: grant.readOnly,
        ...(file ? { size: file.size, lastModified: entry.lastModified ?? file.lastModified, executable } : {}) };
    });
  }
  read(grant, path, offset = 0, length = READ_MAX) {
    if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(length) || length < 0 || length > READ_MAX || !Number.isSafeInteger(offset + length)) {
      return Promise.reject(error('EINVAL', 'invalid local read range (maximum 1 MiB)'));
    }
    return this.#operation(grant, async state => new Uint8Array(await (await this.#file(state, path)).slice(offset, offset + length).arrayBuffer()));
  }
  list(grant, path = '', { offset = 0, limit = 256 } = {}) {
    if (!Number.isSafeInteger(offset) || offset < 0 || offset > 100_000 || !Number.isSafeInteger(limit) || limit < 1 || limit > 256) {
      return Promise.reject(error('EINVAL', 'invalid local directory page'));
    }
    return this.#operation(grant, async state => {
      const entry = await this.#find(state, path);
      if (entry.kind !== 'directory') throw error('ENOTDIR', 'not a directory');
      const prefix = parts(path).join('/');
      const children = state.grant.kind === 'snapshot'
        ? [...state.source].filter(([key]) => key && key.slice(0, Math.max(0, key.lastIndexOf('/'))) === prefix).map(([, value]) => [value.name, value])
        : entry.entries();
      const entries = []; let at = 0;
      for await (const [name, child] of children) {
        if (at++ < offset) continue;
        if (entries.length === limit) return { entries, next: offset + entries.length };
        entries.push({ name, kind: child.kind });
      }
      return { entries, next: null };
    });
  }
  pin(grant, path) {
    return this.#operation(grant, async state => {
      if (!grant.execute) throw error('EACCES', 'local mount has no execution grant');
      const file = await this.#file(state, path);
      if (file.size > IMAGE_MAX) throw error('EFBIG', 'executable exceeds 128 MiB');
      const bytes = new Uint8Array(await file.arrayBuffer());
      if (bytes.byteLength !== file.size) throw error('EIO', 'executable changed while reading');
      return pinImage(bytes, () => this.#check(this.#state(grant)));
    });
  }
  async #parent(state, path) {
    if (state.grant.readOnly) throw error('EROFS', 'local mount is read-only');
    const names = parts(path), name = names.pop();
    if (!name) throw error('EBUSY', 'cannot change the mount root');
    const parent = await this.#find(state, names.join('/'));
    if (parent.kind !== 'directory') throw error('ENOTDIR', 'not a directory');
    return { parent, name };
  }
  async #mutate(grant, run) {
    const state = this.#state(grant);
    if (state.waiting >= 8) throw error('EAGAIN', 'local write queue is full');
    state.waiting++;
    const next = state.writes.then(() => this.#operation(grant, run));
    state.writes = next.catch(() => {});
    try { return await next; } finally { state.waiting--; }
  }
  // Every write commits before acknowledging. No writable stream survives an operation
  // or unmount; browsers reject an unavailable exclusive writer rather than losing data.
  write(grant, path, bytes, { offset = 0, append = false, truncate = null, create = false } = {}) {
    if (!(bytes instanceof Uint8Array) || bytes.length > READ_MAX || !Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(offset + bytes.length) ||
      truncate !== null && (!Number.isSafeInteger(truncate) || truncate < 0)) return Promise.reject(error('EINVAL', 'invalid local write'));
    return this.#mutate(grant, async state => {
      if (grant.readOnly) throw error('EROFS', 'local mount is read-only');
      let handle;
      if (path && typeof path === 'object') {
        handle = await this.#find(state, path);
        // Browser locators can rebind when a file is replaced. A retained File
        // snapshot refuses a changed backing file instead of writing that replacement.
        try { await this.#held.get(path).file.slice(0, 1).arrayBuffer(); }
        catch { throw error('ESTALE', 'open browser file changed outside this mount'); }
      }
      else { const { parent, name } = await this.#parent(state, path); handle = await parent.getFileHandle(name, { create }); }
      state.resolved.add(handle);
      if (typeof handle.createWritable !== 'function') throw error('EOPNOTSUPP', 'this browser cannot write local files');
      const stream = await handle.createWritable({ keepExistingData: true, mode: 'exclusive' });
      try {
        if (append) offset = (await handle.getFile()).size;
        if (truncate !== null) await stream.truncate(truncate);
        if (bytes.length) await stream.write({ type: 'write', position: offset, data: bytes });
        await this.#check(this.#state(grant));
        if (path && typeof path === 'object') await this.#find(state, path);
        if (await state.source.resolve(handle) === null) throw error('EACCES', 'entry left local mount during write');
        await stream.close();
        const committed = await handle.getFile();
        for (const held of state.held) if (held.entry === handle || await held.entry.isSameEntry?.(handle)) held.file = committed;
        return { written: bytes.length, offset, size: committed.size };
      } catch (reason) { await stream.abort().catch(() => {}); throw reason; }
    });
  }
  mkdir(grant, path) {
    return this.#mutate(grant, async state => {
      const { parent, name } = await this.#parent(state, path);
      try { await parent.getDirectoryHandle(name); throw error('EEXIST', 'directory exists'); }
      catch (reason) { if (reason.name !== 'NotFoundError') throw reason; }
      await parent.getDirectoryHandle(name, { create: true });
      return null;
    });
  }
  remove(grant, path, directory = false) {
    return this.#mutate(grant, async state => {
      const { parent, name } = await this.#parent(state, path);
      const entry = await this.#find(state, path);
      if (directory !== (entry.kind === 'directory')) throw error(directory ? 'ENOTDIR' : 'EISDIR', 'wrong entry type');
      // The removed handle no longer resolves by definition. Its parent remains scoped.
      state.resolved.delete(entry);
      await parent.removeEntry(name, { recursive: false });
      return null;
    });
  }
  rename(grant, path, to) {
    return this.#mutate(grant, async state => {
      await this.#parent(state, path);
      const { parent, name } = await this.#parent(state, to);
      const entry = await this.#find(state, path);
      if (typeof entry.move !== 'function') throw error('EOPNOTSUPP', 'atomic rename is unavailable in this browser filesystem');
      await entry.move(parent, name);
      return null;
    });
  }
  unmount(grant) {
    const state = this.#states.get(grant);
    if (!state) throw error('EACCES', 'unknown local mount grant');
    state.active = false; state.source = null; state.held.clear(); this.#active.delete(grant);
  }
  close() { for (const grant of this.#active) this.unmount(grant); }
}

// Only the host loader consumes pins. A digest, filename or JSON clone is not authority;
// callers never receive the original buffer. Check again after asynchronous compilation.
export async function localImage(pin) {
  const value = pins.get(pin);
  if (!value) throw error('EACCES', 'unknown local executable grant');
  await value.check();
  return { bytes: value.bytes.slice(), check: value.check };
}

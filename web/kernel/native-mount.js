import { pinImage } from './local-mounts.js';

const PROTOCOL_VERSION = 1;
const BOUNDARY = 'local-helper';
const DATA_CHUNK = 256 * 1024;
const IMAGE_MAX = 128 * 1024 * 1024;
const RENEW_MILLIS = 20000;
const RETRY_MILLIS = 5000;
const ROOT_CRED = Object.freeze({ id: 0, group: 0, groups: [0], umask: 0o022 });

const bad = (errno, message = errno) => Object.assign(new Error(message), { errno });
const decode = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));
const encode = bytes => {
  let text = '';
  for (let i = 0; i < bytes.length; i += 8192) {
    text += String.fromCharCode(...bytes.subarray(i, i + 8192));
  }
  return btoa(text);
};
const hash = async bytes =>
  [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))]
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

function splitPath(path) {
  if (typeof path !== 'string' || path.length > 4096 || /[\0]/.test(path)) {
    throw bad('EINVAL', 'invalid helper path');
  }
  if (path.startsWith('/') || path.split('/').includes('..')) {
    throw bad('EACCES', 'path escapes mount');
  }
  return path.split('/').filter(name => name && name !== '.');
}

function readTimestamp(ts) {
  if (!ts || typeof ts.sec !== 'number') return 0;
  return ts.sec * 1000 + Math.floor((ts.nsec ?? 0) / 1e6);
}

function normalizeOwner(owner) {
  const raw = owner && typeof owner === 'object' ? owner : {};
  const id = Number.isSafeInteger(raw.id)
    ? raw.id
    : Number.isSafeInteger(raw.uid)
      ? raw.uid
      : 0;
  const group = Number.isSafeInteger(raw.group)
    ? raw.group
    : Number.isSafeInteger(raw.gid)
      ? raw.gid
      : id;
  const groupList = Array.isArray(raw.groups)
    ? raw.groups
    : raw.groups && typeof raw.groups[Symbol.iterator] === 'function'
      ? [...raw.groups]
      : [group];
  return {
    id,
    group,
    groups: [...new Set([group, ...groupList.filter(g => Number.isSafeInteger(g))])],
  };
}

function validateHelperConnection(args) {
  const url = new URL(args.url);
  if (
    url.protocol !== 'http:' ||
    url.hostname !== '127.0.0.1' ||
    !url.port ||
    url.pathname !== '/' ||
    url.search ||
    url.hash ||
    url.username ||
    url.password ||
    !/^[a-f0-9]{64}$/.test(args.token)
  ) {
    throw bad('EINVAL', 'use the loopback URL and token printed by os-local-helper');
  }
  return url;
}

export class NativeMount {
  #url;
  #token;
  #alive = true;
  #clientId;
  #handshake = null;
  #session = null;
  #fs = 'native';
  #root = null;
  #leaseMs = 60000;
  #failedMs = 0;
  #timer = null;
  #attachPromise = null;
  #handles = new WeakMap();

  static async connect(args, owner = null) {
    const url = validateHelperConnection(args);
    const wasm = args?.wasm ?? null;
    // eslint-disable-next-line no-undef
    const defaultWasm = globalThis.wasm_bindgen ?? (typeof wasm_bindgen !== 'undefined' ? wasm_bindgen : null);
    const connectHelper =
      args.connectHelper ??
      (args.standalone === true
        ? null
        : (wasm?.connect_helper_mount ?? defaultWasm?.connect_helper_mount));

    if (typeof connectHelper === 'function') {
      const transport = new NativeMount(url.href, args.token);
      const grantJson = JSON.stringify({
        kind: 'native-directory',
        name: args.name ?? 'native',
        readOnly: !args.writable,
        execute: Boolean(args.execute),
        owner: normalizeOwner(owner ?? args.owner),
      });
      try {
        return await connectHelper(transport, grantJson);
      } catch (reason) {
        transport.close();
        throw reason;
      }
    }

    const provider = new NativeMount(url.href, args.token);
    const hello = await provider.#negotiateHello();
    const write = Boolean(args.writable) && Boolean(hello.write);
    const execute = Boolean(args.execute) && Boolean(hello.execute);
    provider.grant = Object.freeze({
      kind: 'native-directory',
      name: args.name ?? 'native',
      readOnly: !write,
      execute,
    });
    return provider;
  }

  constructor(url, token) {
    this.#url = url;
    this.#token = token;
    this.#clientId = crypto.randomUUID();
  }

  clientId() {
    return this.#clientId;
  }

  check(grant) {
    if (grant !== this.grant) throw bad('EACCES');
    if (!this.#alive) throw bad('ENODEV', 'local filesystem adapter is disconnected');
  }

  async postRaw(bodyJson) {
    if (!this.#alive) {
      throw bad('ENODEV', 'local filesystem adapter is disconnected');
    }
    let response;
    try {
      response = await fetch(this.#url, {
        method: 'POST',
        credentials: 'omit',
        redirect: 'error',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer ' + this.#token,
        },
        body: bodyJson,
        signal: AbortSignal.timeout(15000),
      });
      return { status: response.status, body: await response.text() };
    } catch (reason) {
      if (reason?.name === 'TimeoutError') {
        throw bad('ETIMEDOUT', 'local filesystem request timed out');
      }
      throw bad('ENOTCONN', 'local filesystem adapter is offline or the browser denied loopback access');
    }
  }

  async #rpc(envelope) {
    const { status, body } = await this.postRaw(JSON.stringify(envelope));
    let parsed = null;
    try {
      parsed = JSON.parse(body);
    } catch {
      throw bad('EIO', 'malformed JSON response from local-helper');
    }
    if (status !== 200) {
      const errno = typeof parsed?.errno === 'string'
        ? parsed.errno
        : status === 401 || status === 403
          ? 'EACCES'
          : 'EIO';
      throw bad(errno, parsed?.error ?? errno);
    }
    return parsed;
  }

  async #negotiateHello() {
    const { status, body } = await this.postRaw(
      JSON.stringify({ hello: { boundary: BOUNDARY, versions: [PROTOCOL_VERSION] } }),
    );
    let parsed = null;
    try {
      parsed = JSON.parse(body);
    } catch {
      throw bad('EPROTONOSUPPORT', 'invalid local-helper hello reply');
    }
    if (status !== 200) {
      const errno = typeof parsed?.errno === 'string'
        ? parsed.errno
        : status === 401 || status === 403
          ? 'EACCES'
          : 'EPROTONOSUPPORT';
      throw bad(errno, parsed?.error ?? errno);
    }
    if (
      parsed?.boundary !== BOUNDARY ||
      parsed?.version !== PROTOCOL_VERSION ||
      typeof parsed?.handshake !== 'string' ||
      !parsed.handshake
    ) {
      throw bad('EPROTONOSUPPORT', 'unsupported local-helper protocol version');
    }
    this.#handshake = parsed.handshake;
    return parsed;
  }

  #scheduleRenew(delay = RENEW_MILLIS) {
    if (!this.#alive || !this.#session) return;
    clearTimeout(this.#timer);
    this.#timer = setTimeout(() => {
      if (!this.#alive || !this.#session) return;
      void this.#rpc({ renew: { version: PROTOCOL_VERSION, session: this.#session } })
        .then(reply => {
          this.#failedMs = 0;
          if (Number.isFinite(reply?.lease_seconds) && reply.lease_seconds > 0) {
            this.#leaseMs = reply.lease_seconds * 1000;
          }
          this.#scheduleRenew(RENEW_MILLIS);
        })
        .catch(reason => {
          const errno = reason?.errno;
          if (errno === 'ENODEV' || errno === 'EACCES' || errno === 'EPROTONOSUPPORT') {
            this.unmount(this.grant);
            return;
          }
          this.#failedMs += delay;
          if (this.#failedMs >= this.#leaseMs) {
            this.unmount(this.grant);
            return;
          }
          this.#scheduleRenew(Math.min(RETRY_MILLIS, RENEW_MILLIS));
        });
    }, delay);
  }

  async #ensureAttached() {
    if (this.#session) return;
    if (!this.#attachPromise) {
      this.#attachPromise = (async () => {
        if (!this.#handshake) {
          await this.#negotiateHello();
        }
        const handshake = this.#handshake;
        this.#handshake = null;
        const reply = await this.#rpc({
          attach: {
            version: PROTOCOL_VERSION,
            client_id: this.#clientId,
            handshake,
            cred: ROOT_CRED,
            grant: {
              write: !this.grant.readOnly,
              execute: this.grant.execute,
            },
          },
        });
        if (reply?.version !== PROTOCOL_VERSION || !reply?.session || !reply?.root) {
          throw bad('EPROTONOSUPPORT', 'invalid attach reply from local-helper');
        }
        this.#session = reply.session;
        this.#root = reply.root;
        this.#fs = typeof reply.fs === 'string' && reply.fs ? reply.fs : 'native';
        if (Number.isFinite(reply.lease_seconds) && reply.lease_seconds > 0) {
          this.#leaseMs = reply.lease_seconds * 1000;
        }
        this.#failedMs = 0;
        this.#scheduleRenew(RENEW_MILLIS);
      })().finally(() => {
        this.#attachPromise = null;
      });
    }
    await this.#attachPromise;
  }

  async #call(call) {
    await this.#ensureAttached();
    return this.#rpc({
      call: {
        version: PROTOCOL_VERSION,
        session: this.#session,
        cred: ROOT_CRED,
        call,
      },
    });
  }

  async #callWithOpenTicket(kind, payload) {
    const ticket = crypto.randomUUID();
    try {
      return await this.#call({ [kind]: { ticket, ...payload } });
    } catch (error) {
      if (error?.errno === 'ETIMEDOUT' || error?.errno === 'ENOTCONN') {
        void this.#call({ cancel_open: { ticket } }).catch(() => {});
      }
      throw error;
    }
  }

  async #resolveEntry(path) {
    if (path && typeof path === 'object') {
      throw bad('EINVAL', 'expected path');
    }
    await this.#ensureAttached();
    const parts = splitPath(path);
    if (parts.length === 0) {
      const metadata = await this.#call({ metadata: { handle: this.#root } });
      return { handle: this.#root, metadata };
    }
    const walked = await this.#call({ walk: { dir: this.#root, names: parts } });
    if (walked.stop) {
      if (walked.stop.Missing !== undefined) throw bad('ENOENT');
      if (walked.stop.Symlink !== undefined) throw bad('ELOOP');
      if (walked.stop.NotDirectory !== undefined) throw bad('ENOTDIR');
      throw bad('ENOENT');
    }
    return walked.entries[walked.entries.length - 1];
  }

  async #resolveParent(path) {
    await this.#ensureAttached();
    const parts = splitPath(path);
    if (parts.length === 0) throw bad('EINVAL');
    const name = parts.pop();
    const parent = parts.length === 0
      ? { handle: this.#root }
      : await this.#resolveEntry(parts.join('/'));
    return { dir: parent.handle, name };
  }

  async open(grant, path, flags = 0, _mode = 0o666, _umask = 0o077, exec = false) {
    this.check(grant);
    const isPath = Boolean(flags & 0o10000000);
    const acc = flags & 3;
    if (!isPath && acc === 3) {
      throw bad('EINVAL', 'invalid access mode');
    }
    if (exec) {
      if (isPath || acc !== 0 || (flags & (0o100 | 0o1000 | 0o200000)) !== 0) {
        throw bad('EINVAL', 'invalid exec open flags');
      }
      if (!grant.execute) throw bad('EACCES');
    }
    if (!isPath && grant.readOnly && (acc !== 0 || (flags & (0o100 | 0o1000)) !== 0)) {
      throw bad('EROFS');
    }
    const options = isPath
      ? {
          read: false,
          write: false,
          append: false,
          append_implies_write: false,
          truncate: false,
          create: false,
          create_new: false,
          exec: false,
          path: true,
        }
      : {
          read: !exec && (acc === 0 || acc === 2),
          write: acc === 1 || acc === 2,
          append: Boolean(flags & 0o2000),
          append_implies_write: false,
          truncate: Boolean(flags & 0o1000),
          create: Boolean(flags & 0o100),
          create_new: Boolean((flags & 0o100) && (flags & 0o200)),
          exec: Boolean(exec),
          path: false,
        };
    let openRef;
    if (options.create) {
      if (flags & 0o200000) throw bad('EINVAL');
      const { dir, name } = await this.#resolveParent(path);
      const [, createdOpen] = await this.#callWithOpenTicket('create', {
        dir,
        name,
        mode: 0o644,
        options,
      });
      openRef = createdOpen;
    } else {
      const entry = await this.#resolveEntry(path);
      if (!isPath && (flags & 0o200000) !== 0 && entry.metadata.file_type !== 'dir') {
        throw bad('ENOTDIR');
      }
      openRef = await this.#callWithOpenTicket('open', {
        handle: entry.handle,
        options,
      });
    }
    const handle = Object.freeze({});
    this.#handles.set(handle, openRef);
    return handle;
  }

  hold(grant, path) {
    return this.open(grant, path, grant.readOnly ? 0 : 2);
  }

  async release(grant, handle) {
    this.check(grant);
    const open = this.#handles.get(handle);
    if (!open) throw bad('EBADF');
    try {
      await this.#call({ release: { open } });
    } finally {
      this.#handles.delete(handle);
    }
  }

  async stat(grant, path = '', _options = {}) {
    this.check(grant);
    let metadata;
    let node = null;
    let symlinkHandle = null;
    if (path && typeof path === 'object') {
      const open = this.#handles.get(path);
      if (!open) throw bad('EBADF');
      metadata = await this.#call({ open_metadata: { open } });
      node = open.node;
    } else {
      const entry = await this.#resolveEntry(path);
      metadata = entry.metadata;
      node = entry.handle?.node ?? null;
      if (metadata.file_type === 'symlink') {
        symlinkHandle = entry.handle;
      }
    }
    const kind = metadata.file_type === 'dir'
      ? 'directory'
      : metadata.file_type === 'symlink'
        ? 'symlink'
        : 'file';
    let link;
    if (kind === 'symlink' && symlinkHandle) {
      link = await this.#call({ read_link: { link: symlinkHandle } });
    }
    let executable = false;
    if (kind === 'file' && grant.execute) {
      const header = await this.read(grant, path, 0, 8).catch(() => new Uint8Array());
      executable = [0, 97, 115, 109, 1, 0, 0, 0].every((b, i) => header[i] === b);
    }
    const name = typeof path === 'string' ? (splitPath(path).at(-1) ?? '') : '';
    const identity = node ? `${this.#fs}:${node.ino}:${node.generation}` : undefined;
    return {
      kind,
      name,
      size: metadata.size,
      lastModified: readTimestamp(metadata.mtime),
      readOnly: grant.readOnly,
      executable: grant.execute && executable,
      ...(identity !== undefined ? { identity } : {}),
      ...(link !== undefined ? { link } : {}),
    };
  }

  async list(grant, path = '', { offset = 0, limit = 256 } = {}) {
    this.check(grant);
    if (
      !Number.isSafeInteger(offset) ||
      offset < 0 ||
      offset > 100_000 ||
      !Number.isSafeInteger(limit) ||
      limit < 1 ||
      limit > 256
    ) {
      throw bad('EINVAL', 'invalid local directory page');
    }
    const entry = await this.#resolveEntry(path);
    const items = await this.#call({ read_dir: { dir: entry.handle } });
    const mapped = items.map(item => ({
      name: item.name,
      kind: item.file_type === 'dir' ? 'directory' : item.file_type === 'symlink' ? 'symlink' : 'file',
    }));
    const entries = mapped.slice(offset, offset + limit);
    const next = offset + entries.length < mapped.length ? offset + entries.length : null;
    return { entries, next };
  }

  async read(grant, path, offset, count) {
    this.check(grant);
    const capped = Math.min(DATA_CHUNK, count);
    if (path && typeof path === 'object') {
      const open = this.#handles.get(path);
      if (!open) throw bad('EBADF');
      const reply = await this.#call({ read_at: { open, offset, count: capped } });
      return decode(reply.data);
    }
    const entry = await this.#resolveEntry(path);
    const open = await this.#callWithOpenTicket('open', {
      handle: entry.handle,
      options: {
        read: true,
        write: false,
        append: false,
        append_implies_write: false,
        truncate: false,
        create: false,
        create_new: false,
        exec: false,
        path: false,
      },
    });
    try {
      const reply = await this.#call({ read_at: { open, offset, count: capped } });
      return decode(reply.data);
    } finally {
      await this.#call({ release: { open } }).catch(() => {});
    }
  }

  async write(grant, path, bytes, options = {}) {
    this.check(grant);
    if (grant.readOnly) throw bad('EROFS');
    let truncateSize = null;
    if (options.truncate === true) {
      truncateSize = 0;
    } else if (options.truncate !== undefined && options.truncate !== null && options.truncate !== false) {
      if (!Number.isSafeInteger(options.truncate) || options.truncate < 0) {
        throw bad('EINVAL', 'invalid truncate size');
      }
      truncateSize = options.truncate;
    }

    let open;
    let releaseAfter = false;
    if (path && typeof path === 'object') {
      open = this.#handles.get(path);
      if (!open) throw bad('EBADF');
    } else {
      const openOpts = {
        read: false,
        write: true,
        append: Boolean(options.append),
        append_implies_write: false,
        truncate: truncateSize === 0,
        create: Boolean(options.create),
        create_new: Boolean(options.exclusive),
        exec: false,
        path: false,
      };
      if (openOpts.create) {
        const { dir, name } = await this.#resolveParent(path);
        const [, createdOpen] = await this.#callWithOpenTicket('create', {
          dir,
          name,
          mode: 0o644,
          options: openOpts,
        });
        open = createdOpen;
      } else {
        const entry = await this.#resolveEntry(path);
        open = await this.#callWithOpenTicket('open', {
          handle: entry.handle,
          options: openOpts,
        });
      }
      releaseAfter = true;
    }

    try {
      if (truncateSize !== null && (releaseAfter ? truncateSize > 0 : true)) {
        await this.#call({ set_len: { open, size: truncateSize } });
      }
      if (bytes.length === 0) {
        return { written: 0 };
      }
      let written = 0;
      do {
        const chunk = bytes.subarray(written, written + DATA_CHUNK);
        const at = options.append ? 'end' : { offset: (options.offset ?? 0) + written };
        const res = await this.#call({ write_at: { open, data: encode(chunk), at } });
        if (!Number.isSafeInteger(res.len) || res.len < 0 || res.len > chunk.length || (chunk.length && !res.len)) {
          throw bad('EIO');
        }
        written += res.len;
      } while (written < bytes.length);
      return { written };
    } finally {
      if (releaseAfter) {
        await this.#call({ release: { open } }).catch(() => {});
      }
    }
  }

  async mkdir(grant, path) {
    this.check(grant);
    if (grant.readOnly) throw bad('EROFS');
    const { dir, name } = await this.#resolveParent(path);
    await this.#call({ mkdir: { dir, name, mode: 0o755 } });
  }

  async remove(grant, path, directory = false) {
    this.check(grant);
    if (grant.readOnly) throw bad('EROFS');
    const { dir, name } = await this.#resolveParent(path);
    await this.#call(directory ? { rmdir: { dir, name } } : { unlink: { dir, name } });
  }

  async rename(grant, path, to) {
    this.check(grant);
    if (grant.readOnly) throw bad('EROFS');
    const src = await this.#resolveParent(path);
    const dst = await this.#resolveParent(to);
    await this.#call({
      rename: {
        from_dir: src.dir,
        from: src.name,
        to_dir: dst.dir,
        to: dst.name,
        flags: '',
      },
    });
  }

  async pin(grant, path) {
    this.check(grant);
    if (!grant.execute) throw bad('EACCES');
    const entry = await this.#resolveEntry(path);
    if (entry.metadata.file_type !== 'file') throw bad('ENOEXEC');
    const open = await this.#callWithOpenTicket('open', {
      handle: entry.handle,
      options: {
        read: true,
        write: false,
        append: false,
        append_implies_write: false,
        truncate: false,
        create: false,
        create_new: false,
        exec: false,
        path: false,
      },
    });
    try {
      const meta = await this.#call({ open_metadata: { open } });
      if (meta.file_type !== 'file') throw bad('ENOEXEC');
      if (meta.size > IMAGE_MAX) throw bad('EFBIG', 'executable exceeds 128 MiB');
      if (meta.size < 8) throw bad('ENOEXEC');
      const buf = new Uint8Array(meta.size);
      let offset = 0;
      while (offset < buf.length) {
        const count = Math.min(DATA_CHUNK, buf.length - offset);
        const reply = await this.#call({ read_at: { open, offset, count } });
        const part = decode(reply.data);
        if (part.length === 0) throw bad('ESTALE', 'executable shrank while reading');
        if (part.length > buf.length - offset) throw bad('ESTALE', 'executable grew while reading');
        buf.set(part, offset);
        offset += part.length;
      }
      const probe = await this.#call({ open_metadata: { open } });
      if (probe.size !== buf.length) throw bad('ESTALE', 'executable changed while reading');
      if (![0, 97, 115, 109, 1, 0, 0, 0].every((b, i) => buf[i] === b)) {
        throw bad('ENOEXEC');
      }
      if (await hash(buf) === '') throw bad('EIO');
      return pinImage(buf, () => this.#call('statfs'));
    } finally {
      await this.#call({ release: { open } }).catch(() => {});
    }
  }

  close() {
    if (!this.#alive) return;
    this.#alive = false;
    clearTimeout(this.#timer);
    this.#timer = null;
  }

  unmount(grant) {
    if (grant !== this.grant) throw bad('EACCES');
    if (!this.#alive) return;
    const session = this.#session;
    this.close();
    if (session) {
      void fetch(this.#url, {
        method: 'POST',
        credentials: 'omit',
        redirect: 'error',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer ' + this.#token,
        },
        body: JSON.stringify({ detach: { version: PROTOCOL_VERSION, session } }),
        signal: AbortSignal.timeout(5000),
      }).catch(() => {});
    }
  }
}

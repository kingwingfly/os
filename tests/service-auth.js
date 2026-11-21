// Shared ServiceAuth v2, HostAdapter v2 (client-kernel Worker), and Cloud VFS mock helpers
// for migrated E2E and authority tests (Contract v2 / #54).
import { randomBytes, randomUUID } from 'node:crypto';

export const DEFAULT_ORIGIN = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';

export const FULL_SCOPE = Object.freeze({
  cloud_fs: true,
  devices: ['archive', 'media', 'present', 'snd'],
  containers: true,
  relay: true,
});

export const CLOUD_SCOPE = Object.freeze({
  cloud_fs: true,
  devices: [],
  containers: false,
  relay: false,
});

export const NO_CLOUD_SCOPE = Object.freeze({
  cloud_fs: false,
  devices: [],
  containers: false,
  relay: false,
});

let syntheticPid = 100;
const nextSyntheticPid = () => ++syntheticPid;

export async function serviceAuth(request, payload, extraHeaders = {}, { origin = DEFAULT_ORIGIN } = {}) {
  const response = await request.post(`${origin}/api/service-auth`, {
    headers: {
      Origin: origin,
      'Content-Type': 'application/json',
      ...extraHeaders,
    },
    data: payload,
  });
  const text = await response.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = { raw: text };
  }
  return { ok: response.ok(), status: response.status(), body };
}

function unwrapAuth(res, key, label) {
  if (!res.ok) {
    const err = new Error(`ServiceAuth ${label} failed (${res.status}): ${JSON.stringify(res.body)}`);
    err.errno = res.body?.errno;
    err.status = res.status;
    err.body = res.body;
    throw err;
  }
  return key ? res.body?.[key] ?? res.body : res.body;
}

export async function attachInstance(
  request,
  {
    instanceId = `inst-${randomUUID()}`,
    host = 'test-host',
    hostProof = randomBytes(32).toString('hex'),
    headers = {},
    origin = DEFAULT_ORIGIN,
  } = {},
) {
  const res = await serviceAuth(
    request,
    {
      attach_instance: {
        instance: { instance: instanceId, host },
        host_proof: hostProof,
      },
    },
    headers,
    { origin },
  );
  const attached = unwrapAuth(res, 'attached', 'attach_instance');
  const instanceHeaders = { 'X-OS-Instance': instanceId };

  return {
    instanceId,
    host,
    hostProof,
    hostEpoch: attached.host_epoch,
    leaseSeconds: attached.lease_seconds,
    origin,
    headers: instanceHeaders,
    fsHeaders(extra = {}) {
      return { Origin: origin, ...instanceHeaders, ...extra };
    },
    raw(payload, extraHeaders = {}) {
      return serviceAuth(request, payload, { ...headers, ...extraHeaders }, { origin });
    },
    async mint({
      scope = FULL_SCOPE,
      cloud_access = true,
      umask = 0o022,
      cgroup = '/user',
      generation,
      sudo = false,
      headers: extraHeaders = {},
    } = {}) {
      const payload = {
        mint_service_cred: {
          instance_id: instanceId,
          host_proof: hostProof,
          scope,
          cloud_access,
          umask,
          cgroup,
          ...(generation != null ? { generation } : {}),
          sudo,
        },
      };
      const out = await serviceAuth(request, payload, { ...headers, ...extraHeaders }, { origin });
      const cred = unwrapAuth(out, 'cred', 'mint_service_cred');
      return { ...cred, pid: nextSyntheticPid(), instanceId };
    },
    async derive(
      parentToken,
      {
        scope = FULL_SCOPE,
        cloud_access = true,
        umask,
        cgroup,
        revoke_parent = false,
        headers: extraHeaders = {},
      } = {},
    ) {
      const payload = {
        derive_service_cred: {
          instance_id: instanceId,
          host_proof: hostProof,
          parent_token: parentToken,
          scope,
          cloud_access,
          ...(umask != null ? { umask } : {}),
          ...(cgroup != null ? { cgroup } : {}),
          revoke_parent,
        },
      };
      const out = await serviceAuth(request, payload, { ...headers, ...extraHeaders }, { origin });
      const cred = unwrapAuth(out, 'cred', 'derive_service_cred');
      return { ...cred, pid: nextSyntheticPid(), instanceId };
    },
    async renew(activeTokens = [], extraHeaders = {}) {
      const out = await serviceAuth(
        request,
        {
          renew_instance: {
            instance_id: instanceId,
            host_proof: hostProof,
            active_tokens: activeTokens,
          },
        },
        { ...headers, ...extraHeaders },
        { origin },
      );
      return unwrapAuth(out, 'renewed', 'renew_instance');
    },
    async revoke(tokens, extraHeaders = {}) {
      const list = Array.isArray(tokens) ? tokens : [tokens];
      const out = await serviceAuth(
        request,
        {
          revoke_tokens: {
            instance_id: instanceId,
            host_proof: hostProof,
            tokens: list,
          },
        },
        { ...headers, ...extraHeaders },
        { origin },
      );
      return unwrapAuth(out, 'revoked', 'revoke_tokens');
    },
    async detach(extraHeaders = {}) {
      const out = await serviceAuth(
        request,
        {
          detach_instance: {
            instance_id: instanceId,
            host_proof: hostProof,
          },
        },
        { ...headers, ...extraHeaders },
        { origin },
      );
      return unwrapAuth(out, 'detached', 'detach_instance');
    },
    async setIoQuota({ token, cgroup = '/user', rbps = null, wbps = null, headers: extraHeaders = {} }) {
      const out = await serviceAuth(
        request,
        {
          set_remote_io_quota: {
            instance_id: instanceId,
            host_proof: hostProof,
            token,
            cgroup,
            ...(rbps !== undefined ? { rbps } : {}),
            ...(wbps !== undefined ? { wbps } : {}),
          },
        },
        { ...headers, ...extraHeaders },
        { origin },
      );
      return unwrapAuth(out, null, 'set_remote_io_quota');
    },
  };
}

// Dedicated HostAdapter v2 client-kernel Worker connection inside a Playwright page.
export async function connectKernel(page, { name = '__testKernel', tab, hold = false, init = true } = {}) {
  await page.evaluate(
    async ({ name, tab, hold }) => {
      if (hold && tab) {
        await new Promise(resolve => {
          void navigator.locks.request(`tw-tab-${tab}`, () => {
            resolve();
            return new Promise(() => {});
          });
        });
      }
      const worker = new Worker('/client-kernel.js');
      const pending = new Map();
      const events = [];
      let next = 0;
      worker.onmessage = ({ data }) => {
        if (data?.type === 'event') events.push(data);
        if (data?.id != null && pending.has(data.id)) {
          pending.get(data.id)(data);
          pending.delete(data.id);
        }
      };
      const raw = msg =>
        new Promise(resolve => {
          const id = ++next;
          pending.set(id, resolve);
          worker.postMessage({ ...msg, id });
        });
      window[name] = {
        raw,
        call: (type, args = {}) => raw({ v: 2, type, args, ...(tab != null ? { tab } : {}) }),
        hello: (versions = [2], boundary = 'host-adapter') =>
          raw({ v: 2, type: 'hello', boundary, versions, ...(tab != null ? { tab } : {}) }),
        events: () => events.slice(),
        clearEvents: () => {
          events.length = 0;
        },
        terminate: () => worker.terminate(),
      };
    },
    { name, tab, hold },
  );

  const client = {
    raw: msg => page.evaluate(([n, m]) => window[n].raw(m), [name, msg]),
    hello: (versions = [2], boundary = 'host-adapter') =>
      page.evaluate(([n, v, b]) => window[n].hello(v, b), [name, versions, boundary]),
    call: (type, args = {}) => page.evaluate(([n, t, a]) => window[n].call(t, a), [name, type, args]),
    async value(type, args = {}) {
      const reply = await client.call(type, args);
      if (reply?.err) {
        const err = new Error(`${type}: ${reply.err.detail ?? reply.err.errno}`);
        err.errno = reply.err.errno;
        err.detail = reply.err.detail;
        throw err;
      }
      return reply?.ok;
    },
    events: () => page.evaluate(n => window[n].events(), name),
    clearEvents: () => page.evaluate(n => window[n].clearEvents(), name),
    terminate: () => page.evaluate(n => window[n].terminate(), name),
  };

  if (init) await client.value('init');
  return client;
}

// Intercept the page's own `/client-kernel.js` Worker so tests can inspect/signal the page's
// live LocalProcessTable, login coordinator, cgroups, and machine init coordinator directly.
export async function hookPageKernel(page, { name = '__pageKernel' } = {}) {
  await page.addInitScript(hookName => {
    const NativeWorker = window.Worker;
    window.Worker = class extends NativeWorker {
      constructor(url, options) {
        super(url, options);
        if (new URL(String(url), location.href).pathname.endsWith('/client-kernel.js')) {
          const worker = this;
          const pending = new Map();
          let next = 900_000;
          worker.addEventListener('message', ({ data }) => {
            if (data?.id != null && pending.has(data.id)) {
              pending.get(data.id)(data);
              pending.delete(data.id);
            }
          });
          const raw = msg =>
            new Promise(resolve => {
              const id = ++next;
              pending.set(id, resolve);
              worker.postMessage({ ...msg, id });
            });
          window[hookName] = {
            raw,
            call: (type, args = {}) => raw({ v: 2, type, args }),
          };
        }
      }
    };
  }, name);

  const client = {
    ready: () => page.waitForFunction(n => Boolean(window[n]), name),
    raw: msg => page.evaluate(([n, m]) => window[n].raw(m), [name, msg]),
    call: (type, args = {}) => page.evaluate(([n, t, a]) => window[n].call(t, a), [name, type, args]),
    async value(type, args = {}) {
      const reply = await client.call(type, args);
      if (reply?.err) {
        const err = new Error(`${type}: ${reply.err.detail ?? reply.err.errno}`);
        err.errno = reply.err.errno;
        err.detail = reply.err.detail;
        throw err;
      }
      return reply?.ok;
    },
  };
  return client;
}

// Client-kernel-compatible mock for page VFS `/api/sys` + `/api/pwrite` + `/api/file` routes
// (RootCloudDriver requires unique inodes, fd_epoch + stat on open, pread data, and close metadata).
export function createFakeCloud(getFiles, options = {}) {
  const {
    creds = {
      uid: 65534,
      gid: 65534,
      groups: [65534],
      user: 'guest',
      group: 'guest',
      group_names: ['guest'],
      home: '/',
      signed_in: false,
      can_sudo: false,
      sudo_active: false,
    },
    onWrite,
  } = options;
  const inodes = new Map([['/', 1]]);
  let nextIno = 2;
  const inoOf = path => {
    if (!inodes.has(path)) inodes.set(path, nextIno++);
    return inodes.get(path);
  };
  const fds = new Map();
  let nextFd = 10;
  let revision = 1;
  const fdEpoch = 'a'.repeat(64);

  const normalize = () => (typeof getFiles === 'function' ? getFiles() : getFiles);
  const bytesOf = entry => {
    if (entry?.content == null) return Buffer.alloc(entry?.size ?? 0);
    return Buffer.isBuffer(entry.content) ? entry.content : Buffer.from(String(entry.content), 'utf8');
  };
  const makeStat = (path, entry = {}, directory = false) => {
    const size = entry.content != null ? bytesOf(entry).length : (entry.size ?? 0);
    return {
      dev: 1,
      ino: inoOf(path),
      mode: (directory ? 0o040000 : 0o100000) | (entry.mode ?? (directory ? 0o755 : 0o644)),
      nlink: 1,
      uid: entry.uid ?? creds.uid,
      gid: entry.gid ?? creds.gid,
      user: entry.user ?? creds.user,
      group: entry.group ?? creds.group,
      size,
      atime: 0,
      mtime: 0,
      ctime: 0,
      version: `"${entry.version ?? revision}"`,
    };
  };

  return {
    handleSys(route) {
      const known = normalize();
      const { calls = [] } = JSON.parse(route.request().postData() || '{}');
      const results = calls.map(call => {
        if (call === 'getcreds') return { ok: creds };
        const [name, args = {}] = Object.entries(call)[0];
        if (name === 'getdents') {
          const dir = args.path === '/' ? '/' : String(args.path).replace(/\/$/, '');
          if (dir !== '/') return { err: { errno: 'ENOENT' } };
          return {
            ok: Object.entries(known)
              .filter(([p]) => p.lastIndexOf('/') === 0)
              .map(([p, f]) => ({ name: p.slice(1), stat: makeStat(p, f, false) })),
          };
        }
        if (name === 'open') {
          const path = args.path;
          const flags = args.flags ?? 0;
          const writable = (flags & 3) !== 0;
          if (!(path in known) && !(flags & 0o100)) return { err: { errno: 'ENOENT' } };
          const entry = known[path] ?? { content: '', mode: args.mode ?? 0o644 };
          const fd = nextFd++;
          fds.set(fd, { path, writable, chunks: [], bytes: bytesOf(entry) });
          return {
            ok: {
              fd,
              fd_epoch: fdEpoch,
              size: writable ? 0 : bytesOf(entry).length,
              chunk_size: 8 * 1024 * 1024,
              created: !(path in known),
              stat: makeStat(path, entry, false),
            },
          };
        }
        if (name === 'pread') {
          let bytes;
          if (args.fd != null) {
            const open = fds.get(args.fd);
            if (!open) return { err: { errno: 'EBADF' } };
            bytes = open.bytes;
          } else {
            const path = args.path;
            if (!(path in known)) return { err: { errno: 'ENOENT' } };
            bytes = bytesOf(known[path]);
          }
          const offset = Number(args.offset ?? 0);
          const count = Number(args.count ?? 4096);
          const slice = bytes.subarray(offset, offset + count);
          return { ok: { data: slice.toString('base64'), size: bytes.length } };
        }
        if (name === 'close') {
          const open = fds.get(args.fd);
          if (!open) return { err: { errno: 'EBADF' } };
          fds.delete(args.fd);
          if (open.writable) {
            revision++;
            const written = Buffer.concat(open.chunks);
            if (onWrite) onWrite(open.path, written);
            return { ok: { path: open.path, size: written.length, version: `"${revision}"` } };
          }
          return { ok: { path: open.path, size: open.bytes.length, version: `"${revision}"` } };
        }
        if (name === 'fstat') {
          const open = fds.get(args.fd);
          if (!open) return { err: { errno: 'EBADF' } };
          return { ok: makeStat(open.path, known[open.path] ?? {}, false) };
        }
        const path = args.path;
        if (path === '/') {
          return { ok: name === 'access' ? null : makeStat('/', { mode: 0o755 }, true) };
        }
        if (!(path in known)) return { err: { errno: 'ENOENT' } };
        if (name === 'access') return { ok: null };
        if (name === 'stat' || name === 'lstat') return { ok: makeStat(path, known[path], false) };
        return { ok: null };
      });
      return route.fulfill({ json: { results } });
    },
    handlePwrite(route) {
      const req = route.request();
      const url = new URL(req.url());
      const fd = Number(url.searchParams.get('fd'));
      const open = fds.get(fd);
      const buf = req.postDataBuffer() ?? Buffer.from(req.postData() ?? '', 'utf8');
      if (open) open.chunks.push(buf);
      else if (onWrite) onWrite('/focus.txt', buf);
      return route.fulfill({ json: { committed: Number(url.searchParams.get('index') ?? 0) } });
    },
    handleFile(route) {
      const req = route.request();
      const url = new URL(req.url());
      const path = url.searchParams.get('path');
      const known = normalize();
      if (!(path in known)) return route.fulfill({ status: 404, json: { errno: 'ENOENT', error: 'No such file or directory' } });
      const entry = known[path];
      const bytes = bytesOf(entry);
      const contentType = entry.contentType || 'text/plain';
      const headers = { 'Content-Type': contentType, ETag: `"${entry.version ?? revision}"` };
      const range = req.headers()['range'];
      if (range) {
        const m = /^bytes=(\d+)-(\d*)$/.exec(range);
        if (m) {
          const start = Number(m[1]);
          const end = m[2] ? Math.min(bytes.length - 1, Number(m[2])) : bytes.length - 1;
          if (start >= bytes.length) return route.fulfill({ status: 416 });
          return route.fulfill({
            status: 206,
            body: req.method() === 'HEAD' ? Buffer.alloc(0) : bytes.subarray(start, end + 1),
            headers: { ...headers, 'Content-Range': `bytes ${start}-${end}/${bytes.length}` },
          });
        }
      }
      return route.fulfill({ status: 200, body: req.method() === 'HEAD' ? Buffer.alloc(0) : bytes, headers });
    },
  };
}

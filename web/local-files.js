// Page-side VFS transport. Routes page `POST /api/sys` filesystem calls, path-addressed
// `GET`/`HEAD` `/api/file` reads, and client-fd `PUT /api/pwrite` chunks through
// `crates/client-kernel`'s active session `MountNamespace` so `Files`, `shell.rs`, `Mounts`,
// and CLI processes all observe the exact same mount table.
import { kernelCall, kernelPort } from './kernel/protocol.js';
import { CLIENT_PAGE_FD_BASE } from './kernel/workspace.js';
export { localMounts } from './mount-api.js';

const json = (value, status = 200) =>
  new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });

const FS_CALL_NAMES = new Set([
  'stat', 'lstat', 'fstat', 'fstat_at', 'getdents', 'access', 'access_at',
  'readlink', 'readlink_at', 'mkdir', 'mkdir_at', 'mknod', 'mknod_at',
  'rmdir', 'unlink', 'unlink_at', 'rename', 'rename_at', 'link', 'link_at',
  'symlink', 'symlink_at', 'chmod', 'fchmod', 'fchmod_at', 'chown', 'fchown_at',
  'utimens', 'utimens_at', 'statfs', 'fstatfs', 'mount', 'umount2',
  'getxattr', 'setxattr', 'listxattr', 'removexattr',
  'open', 'open_at', 'close', 'discard', 'pread', 'pwrite',
  'ftruncate', 'fsync', 'lock', 'try_lock', 'unlock', 'test_lock',
  'ioctl', 'inotify_add_watch', 'inotify_rm_watch',
]);

const LOCAL_ACCOUNT_CALLS = new Set([
  'getcreds', 'login', 'logout', 'sudo', 'passwd',
  'useradd', 'usermod', 'userdel', 'groupadd', 'groupmod', 'groupdel',
]);

const SERVER_ONLY_SYS_CALLS = new Set([
  'register', 'gpasswd', 'login_session', 'machine_init',
]);

function isRemoteServerDevPath(raw, includeDir = false) {
  if (typeof raw !== 'string') return false;
  const parts = [];
  for (const seg of raw.split('/')) {
    if (!seg || seg === '.') continue;
    if (seg === '..') parts.pop();
    else parts.push(seg);
  }
  const norm = '/' + parts.join('/');
  if (includeDir && (norm === '/dev/present' || norm === '/dev/snd')) return true;
  return norm.startsWith('/dev/present/') || norm.startsWith('/dev/snd/');
}

const REMOTE_DEV_PATH_OPS = new Set([
  'stat', 'lstat', 'access', 'getdents', 'mknod', 'unlink', 'chmod',
  'getxattr', 'setxattr', 'listxattr', 'removexattr', 'open', 'inotify_add_watch',
]);
const REMOTE_DEV_REF_OPS = new Set(['ioctl', 'close', 'fstat', 'pread', 'pwrite']);

function isAttendingCloudPath(raw) {
  const scope = globalThis.__osAttendingCloudScope;
  if (!scope || typeof raw !== 'string') return false;
  return raw === scope.file || (scope.dir && raw.startsWith(scope.dir));
}

function isRemoteServerDevBatch(calls) {
  if (!Array.isArray(calls) || calls.length === 0) return false;
  const devOpenIndices = new Set();
  let hasDevPathOp = false;
  for (let i = 0; i < calls.length; i++) {
    const c = calls[i];
    const name = callName(c);
    const arg = typeof c === 'object' && c !== null ? Object.values(c)[0] : null;
    if (!arg || typeof arg !== 'object') return false;
    if (REMOTE_DEV_PATH_OPS.has(name)) {
      const includeDir = name === 'getdents' || name === 'stat' || name === 'lstat' || name === 'access' || name === 'inotify_add_watch';
      if (!isRemoteServerDevPath(arg.path, includeDir)) {
        return false;
      }
      hasDevPathOp = true;
      if (name === 'open') devOpenIndices.add(i);
    } else if (REMOTE_DEV_REF_OPS.has(name)) {
      const ref = arg.fd && typeof arg.fd === 'object' ? arg.fd.ref : null;
      if (typeof ref !== 'number' || !devOpenIndices.has(ref)) return false;
    } else if (name === 'inotify_rm_watch') {
      // Allowed when piggybacked by HttpSys onto a remote /dev/{present,snd} batch.
    } else {
      return false;
    }
  }
  return hasDevPathOp;
}

function callName(call) {
  return typeof call === 'string' ? call : (call && typeof call === 'object' ? Object.keys(call)[0] : '');
}

function isPrivateCarrierPath(raw) {
  if (typeof raw !== 'string') return false;
  const parts = [];
  for (const seg of raw.split('/')) {
    if (!seg || seg === '.') continue;
    if (seg === '..') parts.pop();
    else parts.push(seg);
  }
  const norm = '/' + parts.join('/');
  return ['/mnt/local', '/mnt/shared', '/opt/private'].some(
    root => norm === root || norm.startsWith(root + '/') || raw === root || raw.startsWith(root + '/'),
  );
}

function touchesPrivateCarrier(call) {
  const arg = typeof call === 'object' && call !== null ? Object.values(call)[0] : null;
  if (!arg) return false;
  if (typeof arg.fd === 'number' && arg.fd >= CLIENT_PAGE_FD_BASE) return true;
  return [arg.path, arg.from, arg.to].some(isPrivateCarrierPath);
}

function parseHttpRange(header) {
  if (!header) return { hasRange: false, start: undefined, end: undefined };
  const match = /^bytes=(\d+)-(\d*)$/.exec(header.trim());
  if (!match) return { invalid: true };
  const start = Number(match[1]);
  const end = match[2] ? Number(match[2]) : undefined;
  if (!Number.isSafeInteger(start) || start < 0 || (end !== undefined && (!Number.isSafeInteger(end) || end < start))) {
    return { invalid: true };
  }
  return { hasRange: true, start, end };
}

function statusForErrno(errno) {
  switch (errno) {
    case 'ENOENT': return 404;
    case 'EACCES':
    case 'EPERM': return 403;
    case 'EINVAL':
    case 'EISDIR':
    case 'ENOTDIR': return 400;
    default: return 403;
  }
}

export function installLocalFiles() {
  const network = globalThis.fetch.bind(globalThis);

  // Propagate kernel mount-table updates to `/usr/bin/files` and `/usr/bin/mounts`.
  if (typeof globalThis.Worker === 'function') {
    try {
      kernelPort().on('mounts-changed', value => {
        globalThis.dispatchEvent?.(new CustomEvent('os:mounts-changed', { detail: value }));
      });
    } catch { /* headless environment without Worker */ }
  }

  let cookieBootstrap = null;
  let sessionBootstrapped = false;
  let lastSyncedKey = null;

  async function serializedNetwork(send) {
    if (!sessionBootstrapped) {
      if (cookieBootstrap) {
        await cookieBootstrap;
        return send();
      }
      let release;
      cookieBootstrap = new Promise(resolve => { release = resolve; });
      try {
        const res = await send();
        sessionBootstrapped = true;
        return res;
      } finally {
        cookieBootstrap = null;
        release();
      }
    }
    return send();
  }

  globalThis.fetch = async (input, options) => {
    const request = new Request(input, options);
    const url = new URL(request.url);
    if (url.origin !== location.origin || !url.pathname.startsWith('/api/')) return network(request);
    if (request.headers.has('X-Process-Token') || request.headers.has('X-Registry')) {
      return network(request);
    }

    try {
      // 1. Page `POST /api/sys` batches: filesystem + local OS account calls run 100% locally
      // inside `crates/client-kernel` (`os-cowfs` + `LocalAccountStore`) with ZERO network RPCs!
      if (url.pathname === '/api/sys' && request.method === 'POST') {
        const rawBody = typeof options?.body === 'string' ? options.body : await request.clone().text();
        const body = JSON.parse(rawBody);
        const sendSys = typeof input === 'string' && typeof options?.body === 'string'
          ? () => network(input, options)
          : () => network(request.url, {
              method: request.method,
              headers: request.headers,
              body: rawBody,
              credentials: request.credentials,
              signal: request.signal,
            });
        if (Array.isArray(body.calls) && body.calls.length > 0) {
          const hasFsOrLocalAccount = body.calls.some(c => {
            const name = callName(c);
            return FS_CALL_NAMES.has(name) || LOCAL_ACCOUNT_CALLS.has(name);
          });
          const hasServerOnly = body.calls.some(c => SERVER_ONLY_SYS_CALLS.has(callName(c)));
          if (body.proc || body.pid) {
            if (body.calls.some(touchesPrivateCarrier)) {
              return json({ error: 'process credentials are not page filesystem grants', errno: 'EACCES' }, 403);
            }
            return sendSys();
          }
          // `hold` on a client page fd is a local no-op; on a server upload fd it goes to `/api/sys`.
          if (body.calls.length === 1 && callName(body.calls[0]) === 'hold') {
            const hfd = body.calls[0]?.hold?.fd;
            if (typeof hfd === 'number' && hfd >= CLIENT_PAGE_FD_BASE) {
              return json({ results: [{ ok: null }] });
            }
            return serializedNetwork(sendSys);
          }
          if (hasFsOrLocalAccount && !hasServerOnly) {
            if (isRemoteServerDevBatch(body.calls)) {
              return serializedNetwork(sendSys);
            }
            const results = await kernelCall('mount_vfs_sys', {
              calls: body.calls,
              fdEpoch: request.headers.get('X-Fd-Epoch') ?? undefined,
              sudo: !!body.sudo,
              umask: body.umask,
            });
            return json({ results });
          }
        }
        return serializedNetwork(sendSys);
      }

      // 2. Client-fd chunked uploads (`PUT /api/pwrite?fd=...&index=...` when `fd >= CLIENT_PAGE_FD_BASE`)
      if (url.pathname === '/api/pwrite' && Number(url.searchParams.get('fd')) >= CLIENT_PAGE_FD_BASE) {
        if (request.method !== 'PUT') return json({ errno: 'EINVAL' }, 400);
        const body = new Uint8Array(await request.arrayBuffer());
        const index = Number(url.searchParams.get('index'));
        if (!Number.isSafeInteger(index) || index < 0 || body.length > 8 * 1024 * 1024) {
          return json({ errno: 'E2BIG' }, 400);
        }
        const written = await kernelCall('mount_vfs_pwrite', {
          fd: Number(url.searchParams.get('fd')),
          offset: 0,
          chunkIndex: index,
          data: body,
        });
        return json({ written });
      }

      // 3. Path-addressed page `/api/file?path=...` reads (leaving `?compile=`, `?token=`, and
      // live server character devices `/dev/{present,snd}/*` on `network`)
      if (
        url.pathname === '/api/file' &&
        url.searchParams.has('path') &&
        !url.searchParams.has('compile') &&
        !url.searchParams.has('token') &&
        !isRemoteServerDevPath(url.searchParams.get('path')) &&
        !isAttendingCloudPath(url.searchParams.get('path'))
      ) {
        if (!['GET', 'HEAD'].includes(request.method)) return json({ errno: 'EINVAL' }, 400);
        const path = url.searchParams.get('path');
        const range = parseHttpRange(request.headers.get('Range'));
        if (range.invalid) return new Response(null, { status: 416 });
        request.signal.throwIfAborted();

        let streamId;
        const closeStream = () => {
          request.signal.removeEventListener('abort', onAbort);
          if (streamId != null) {
            void kernelCall('mount_vfs_close_read', { streamId }).catch(() => {});
            streamId = undefined;
          }
        };
        let onAbort;
        const aborted = new Promise((_, reject) => {
          onAbort = () => {
            closeStream();
            reject(request.signal.reason);
          };
          request.signal.addEventListener('abort', onAbort, { once: true });
        });
        let res;
        try {
          const opening = kernelCall('mount_vfs_open_read', {
            path,
            rangeStart: range.hasRange ? range.start : undefined,
            rangeEnd: range.hasRange ? range.end : undefined,
            headOnly: request.method === 'HEAD',
            sudo: false,
          }).then(opened => {
            streamId = opened.streamId;
            if (request.signal.aborted) closeStream();
            return opened;
          });
          res = await Promise.race([opening, aborted]);
          request.signal.throwIfAborted();
        } catch (error) {
          closeStream();
          throw error;
        }
        if (streamId == null) closeStream();
        if (res.status === 416) return new Response(null, { status: 416 });
        const rangeLen = range.hasRange && res.contentRange
          ? (() => {
              const m = /^bytes (\d+)-(\d+)\//.exec(res.contentRange);
              return m ? Number(m[2]) - Number(m[1]) + 1 : res.totalSize;
            })()
          : res.totalSize;
        if (res.streamId != null) {
          const headers = {
            'Content-Type': res.contentType || 'application/octet-stream',
            'Content-Length': String(rangeLen),
            'Accept-Ranges': 'bytes',
            'Cache-Control': 'no-store',
          };
          if (res.contentRange) headers['Content-Range'] = res.contentRange;
          const stream = new ReadableStream({
            async pull(controller) {
              if (streamId == null) {
                controller.close();
                return;
              }
              try {
                const chunk = await kernelCall('mount_vfs_read_chunk', { streamId: res.streamId });
                const bytes = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk ?? []);
                if (streamId == null || !bytes.byteLength) {
                  closeStream();
                  controller.close();
                  return;
                }
                controller.enqueue(bytes);
              } catch (err) {
                closeStream();
                controller.error(err);
              }
            },
            async cancel() {
              closeStream();
            },
          });
          return new Response(stream, {
            status: res.status || (range.hasRange ? 206 : 200),
            headers,
          });
        }
        const bodyBytes = res.inlineBytes instanceof Uint8Array
          ? res.inlineBytes
          : new Uint8Array(res.inlineBytes ?? res.bytes ?? []);
        const contentLen = request.method === 'HEAD' ? rangeLen : bodyBytes.byteLength;
        const headers = {
          'Content-Type': res.contentType || 'application/octet-stream',
          'Content-Length': String(contentLen),
          'Accept-Ranges': 'bytes',
          'Cache-Control': 'no-store',
        };
        if (res.contentRange) headers['Content-Range'] = res.contentRange;
        return new Response(request.method === 'HEAD' ? null : bodyBytes, {
          status: res.status || (range.hasRange ? 206 : 200),
          headers,
        });
      }

      return network(request);
    } catch (error) {
      if (request.signal.aborted || error?.name === 'AbortError') throw error;
      return json(
        { errno: error.errno ?? 'EIO', error: error.detail ?? error.message ?? error.errno ?? 'Filesystem unavailable' },
        statusForErrno(error.errno),
      );
    }
  };
}

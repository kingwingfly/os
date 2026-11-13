// Page-side VFS transport. Rust applications keep their usual filesystem calls;
// private paths are served by the execution host and never fall through to HTTP.
import { kernelCall } from './kernel/protocol.js';
import { localPath, localFdPath, LOCAL_FD } from './kernel/workspace.js';

const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
const unbase64 = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));
const mounted = call => {
  const arg = typeof call === 'object' && call !== null ? Object.values(call)[0] : null;
  return arg && (arg.fd >= LOCAL_FD || [arg.path, arg.from, arg.to].some(path => localPath(path) || localFdPath(path)) || ['/', '/mnt', '/opt'].includes(arg.path));
};
const privateCall = call => {
  const arg = typeof call === 'object' && call !== null ? Object.values(call)[0] : null;
  return arg && (arg.fd >= LOCAL_FD || [arg.path, arg.from, arg.to].some(path => localPath(path) || localFdPath(path)));
};
export function installLocalFiles() {
  const network = globalThis.fetch.bind(globalThis);
  globalThis.fetch = async (input, options) => {
    const request = new Request(input, options), url = new URL(request.url);
    if (url.origin !== location.origin || !url.pathname.startsWith('/api/')) return network(request);
    try {
      if (url.pathname === '/api/sys' && request.method === 'POST') {
        const body = await request.clone().json();
        if (Array.isArray(body.calls) && body.calls.some(mounted)) {
          const privateAccess = body.calls.some(privateCall);
          if (body.proc || body.pid) {
            if (!privateAccess) return network(request);
            return json({ error: 'process credentials are not page filesystem grants', errno: 'EACCES' }, 403);
          }
          const results = await kernelCall(privateAccess ? 'mount_sys' : 'mount_overlay', body);
          // Root listings can work before a login workspace exists. Only this
          // explicit, pre-dispatch result permits ordinary cloud dispatch.
          if (results === null) return network(request);
          return json({ results });
        }
      }
      if (url.pathname === '/api/pwrite' && Number(url.searchParams.get('fd')) >= LOCAL_FD) {
        if (request.method !== 'PUT') return json({ errno: 'EINVAL' }, 400);
        const body = new Uint8Array(await request.arrayBuffer()), index = Number(url.searchParams.get('index'));
        if (!Number.isSafeInteger(index) || index < 0 || body.length > 256 * 1024) return json({ errno: 'E2BIG' }, 400);
        return json(await kernelCall('mount_write', { fd: Number(url.searchParams.get('fd')), offset: index * 256 * 1024, bytes: body }));
      }
      if (url.pathname === '/api/file' && (localPath(url.searchParams.get('path')) || url.searchParams.get('token')?.startsWith('local:'))) {
        if (!['GET', 'HEAD'].includes(request.method)) return json({ errno: 'EINVAL' }, 400);
        let source = Object.fromEntries([...url.searchParams].filter(([key]) => ['path', 'token'].includes(key)));
        let owned, closed = false;
        const close = async () => {
          if (closed) return; closed = true;
          request.signal.removeEventListener('abort', aborted);
          if (owned !== undefined) await kernelCall('mount_sys', { calls: [{ close: { fd: owned } }] }).catch(() => {});
        };
        const aborted = () => { void close(); };
        try {
          let stat;
          if (source.path) {
            const [opened] = await kernelCall('mount_sys', { calls: [{ open: { path: source.path, flags: 0 } }] });
            if (opened.err) throw Object.assign(new Error(opened.err.detail ?? opened.err.errno), opened.err);
            owned = opened.ok.fd; source = { fd: owned }; stat = opened.ok.stat;
          } else stat = await kernelCall('mount_read', { ...source, stat: true });
          if ((stat.mode & 0o170000) !== 0o100000) throw Object.assign(new Error('not a regular file'), { errno: 'EISDIR' });
          let start = 0, end = stat.size - 1;
          const range = request.headers.get('Range');
          if (range) {
            const match = /^bytes=(\d+)-(\d*)$/.exec(range);
            if (!match) { await close(); return new Response(null, { status: 416 }); }
            start = Number(match[1]); end = match[2] ? Math.min(end, Number(match[2])) : end;
            if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start > end) { await close(); return new Response(null, { status: 416 }); }
          }
          let at = start;
          const headers = { 'Content-Type': 'application/octet-stream', 'Content-Length': String(Math.max(0, end - start + 1)), 'Accept-Ranges': 'bytes', 'Cache-Control': 'no-store' };
          if (range) headers['Content-Range'] = `bytes ${start}-${end}/${stat.size}`;
          if (request.method === 'HEAD') { await close(); return new Response(null, { status: range ? 206 : 200, headers }); }
          request.signal.addEventListener('abort', aborted, { once: true });
          if (request.signal.aborted) { await close(); throw new DOMException('Aborted', 'AbortError'); }
          const stream = new ReadableStream({
            async pull(controller) {
              if (closed) { controller.error(new DOMException('Aborted', 'AbortError')); return; }
              if (at > end) { await close(); controller.close(); return; }
              try {
                const read = await kernelCall('mount_read', { ...source, offset: at, count: Math.min(256 * 1024, end - at + 1) });
                const bytes = unbase64(read.data);
                if (!bytes.length) throw new Error('local file changed during read');
                at += bytes.length; controller.enqueue(bytes);
                if (at > end) { await close(); controller.close(); }
              } catch (error) { await close(); controller.error(error); }
            },
            cancel: close,
          });
          return new Response(stream, { status: range ? 206 : 200, headers });
        } catch (error) { await close(); throw error; }
      }
      return network(request);
    } catch (error) { return json({ errno: error.errno ?? 'EIO', error: error.message ?? error.errno ?? 'Local filesystem unavailable' }, error.errno === 'ENOENT' ? 404 : 403); }
  };
}

export async function localMounts() {
  const { openMountManager } = await import('./mount-manager.js');
  openMountManager('mounted');
}

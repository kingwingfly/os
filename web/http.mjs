// What a request of the terminal's API answered: its JSON, or, refused, an error that carries the
// API's message and the status, which callers tell apart (a 409 from a 404, say).
export async function json(response) {
  let body = {}; try { body = await response.json(); } catch {}
  if (!response.ok) { const error = new Error(body.error || `Request failed (${response.status})`); error.status = response.status; throw error; }
  return body;
}

// System calls (owner's design, 2026-10-29: the page is user space): `calls`, one batch, each
// answered on its own, `{ok}` or `{err: {errno, detail}}`; `options` are the process's (umask,
// sudo).
export async function sys(calls, options = {}) {
  const response = await fetch('/api/sys', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ calls, ...options }) });
  return (await json(response)).results;
}

// open(2)'s flags, as Linux numbers them (abi::O_*).
export const O_WRONLY = 0o1, O_CREAT = 0o100, O_EXCL = 0o200, O_TRUNC = 0o1000, O_APPEND = 0o2000;
// glibc's words for the errnos a page meets, for a failure the kernel gave no words of its own.
const STRERROR = {
  EPERM: 'Operation not permitted', ENOENT: 'No such file or directory', EIO: 'Input/output error',
  EBADF: 'Bad file descriptor', EACCES: 'Permission denied', EBUSY: 'Device or resource busy',
  EEXIST: 'File exists', ENOTDIR: 'Not a directory', EISDIR: 'Is a directory', EINVAL: 'Invalid argument',
  EFBIG: 'File too large', ESTALE: 'Stale file handle',
};
// What one call answered: its value, or, failed, an error that carries its errno.
export function answered(answer) {
  if ('ok' in answer) return answer.ok;
  const error = new Error(answer.err.detail || STRERROR[answer.err.errno] || answer.err.errno);
  error.errno = answer.err.errno; throw error;
}
// One system call, `{name: args}` (one without arguments, as getcreds, its name alone): its
// value, or an error with its errno.
export async function call(name, args, options) { return answered((await sys([args === undefined ? name : { [name]: args }], options))[0]); }
// Close the descriptors `fds` as the page goes, when no request may wait for an answer.
export function closeOnLeaving(fds) {
  if (fds.length) navigator.sendBeacon('/api/sys', new Blob([JSON.stringify({ calls: fds.map(fd => ({ close: { fd } })) })], { type: 'application/json' }));
}
// pwrite(2) of chunk `index` through the descriptor `fd`, which R2 checks against `sha256` if
// given: the Worker's answer, or an error with its errno and HTTP status.
export async function pwrite(fd, index, body, sha256) {
  const headers = sha256 ? { 'X-Chunk-SHA256': sha256 } : {};
  const response = await fetch(`/api/pwrite?fd=${fd}&index=${index}`, { method: 'PUT', headers, body });
  let reply = {}; try { reply = await response.json(); } catch {}
  if (!response.ok) { const error = new Error(reply.error || `Write failed (${response.status})`); error.status = response.status; error.errno = reply.errno; throw error; }
  return reply;
}

// Descriptors the page holds. The kernel keeps a session's descriptors while it hears from it:
// each batch renews them all. While the page holds any, it says so every few seconds, asking of
// each (`/proc/self/fd/N`) whether it is still open; `gone` hears of one closed elsewhere (jobs
// cancel in another tab). `hold` gives what lets go of it.
const HEARTBEAT = 8000;
const held = new Map();
let beating = null;
export function hold(fd, gone = () => {}) {
  held.set(fd, gone);
  beating ??= setInterval(async () => {
    const fds = [...held.keys()];
    const results = await sys(fds.map(fd => ({ readlink: { path: `/proc/self/fd/${fd}` } }))).catch(() => null);
    results?.forEach((result, i) => { if (result.err?.errno === 'ENOENT') held.get(fds[i])?.(); });
  }, HEARTBEAT);
  return () => {
    held.delete(fd);
    if (!held.size) { clearInterval(beating); beating = null; }
  };
}

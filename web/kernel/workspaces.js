// Login-session binding and host-handle registry over `crates/client-kernel`'s unified `Vfs`.
import { CLIENT_PAGE_FD_BASE } from './workspace.js';

const spaces = new Map();
const FORBIDDEN_SYS_CALLS = new Set([
  'login_lifecycle', 'init',
]);

const bad = (errno, detail = errno) => Object.assign(new Error(detail), { errno, detail });

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

function callTouchesPrivateCarrier(call) {
  const arg = typeof call === 'object' && call !== null ? Object.values(call)[0] : null;
  if (!arg) return false;
  if (typeof arg.fd === 'number' && arg.fd >= CLIENT_PAGE_FD_BASE) return true;
  return [arg.path, arg.from, arg.to].some(isPrivateCarrierPath);
}

class SessionHost {
  constructor(identity) {
    this.id = identity.id;
    this.identity = Object.freeze({
      id: identity.id,
      uid: identity.uid,
      gid: identity.gid,
      groups: Object.freeze([...(identity.groups ?? [])]),
    });
    this.alive = true;
  }

  check() {
    if (!this.alive) throw bad('ENODEV', 'workspace is closed');
  }

  close() { this.alive = false; }
}

// Fresh account-bound inspection, not cached coordinator state or a caller's claimed uid.
let inspecting = Promise.resolve();
export function currentWorkspace() {
  const next = inspecting.then(inspectWorkspace);
  inspecting = next.catch(() => {});
  return next;
}

async function inspectWorkspace() {
  let view = await globalThis.kernelRequest('login_lifecycle', { op: 'inspect' });
  // A cookie can change without a page event (for example while a shell has
  // exited). Join the new account before resolving its private namespace.
  // An explicitly ended login remains ended; never refresh past shutdown.
  if (!view?.id && !view?.shutdown) {
    await globalThis.kernelRequest('login_refresh', { skipCompatRebind: true });
    view = await globalThis.kernelRequest('login_lifecycle', { op: 'inspect' });
  }
  for (const [id, entry] of [...spaces.entries()]) {
    const resolved = await Promise.resolve(entry).catch(() => null);
    if (id !== view?.id || view?.shutdown || (resolved && resolved.identity.uid !== view?.uid)) {
      await endWorkspace(id);
    }
  }
  if (!view?.id || view.shutdown) {
    await globalThis.kernelRequest('set_active_session', { sessionId: null }).catch(() => {});
    throw bad('EACCES', 'login workspace is unavailable');
  }
  let host = spaces.get(view.id);
  if (!host) {
    const joining = (async () => {
      const creds = await globalThis.kernelRequest('workspace_credentials');
      if (!creds || creds.uid !== view.uid) throw bad('EACCES');
      await globalThis.kernelRequest('session_begin', {
        sessionId: view.id,
        uid: creds.uid,
        gid: creds.gid ?? creds.uid,
        groups: creds.groups ?? [],
      });
      return new SessionHost({ ...view, gid: creds.gid ?? creds.uid, groups: creds.groups ?? [] });
    })();
    spaces.set(view.id, joining);
    try {
      host = await joining;
    } catch (error) {
      if (spaces.get(view.id) === joining) spaces.delete(view.id);
      throw error;
    }
  }
  host = await host;
  if (host.identity.uid !== view.uid) throw bad('EACCES');
  host.check();
  if (!spaces.has(view.id)) throw bad('EACCES');
  await globalThis.kernelRequest('set_active_session', { sessionId: host.id });
  return host;
}

export async function endWorkspace(id) {
  const request = globalThis.kernelRequest;
  const space = spaces.get(id);
  spaces.delete(id);

  if (space) await Promise.resolve(space).then(value => value.close()).catch(() => {});
  if (typeof request === 'function' && id) {
    await request('session_end', { sessionId: id }).catch(() => {});
  }
}

async function resolveOptionalSessionId() {
  try {
    const ws = await currentWorkspace();
    return ws.id;
  } catch (err) {
    if (err?.errno === 'EACCES' || err?.errno === 'EIO') return '';
    throw err;
  }
}

export async function mountRequest(type, args = {}) {
  if (type === 'mount_overlay') {
    if (!Array.isArray(args.calls) || args.calls.some(callTouchesPrivateCarrier)) {
      throw bad('EACCES');
    }
  }
  // Unified page VFS entrypoints (work for both authenticated login sessions and guest `system_mnt_ns`).
  if (type === 'mount_vfs_sys') {
    if (!Array.isArray(args.calls) || args.calls.some(call => FORBIDDEN_SYS_CALLS.has(typeof call === 'string' ? call : Object.keys(call)[0]))) {
      throw bad('EINVAL');
    }
    const sessionId = await resolveOptionalSessionId();
    return (await globalThis.kernelRequest('vfs_sys', {
      sessionId,
      fdEpoch: args.fdEpoch,
      batch: { calls: args.calls, sudo: !!args.sudo, umask: args.umask },
    })).results;
  }
  if (type === 'mount_vfs_open_read') {
    const sessionId = (await currentWorkspace()).id;
    return globalThis.kernelRequest('vfs_open_read', { ...args, sessionId });
  }
  if (type === 'mount_vfs_read_chunk') {
    return globalThis.kernelRequest('vfs_read_stream_chunk', { ...args, sessionId: (await currentWorkspace()).id });
  }
  if (type === 'mount_vfs_close_read') {
    return globalThis.kernelRequest('vfs_close_read_stream', { ...args, sessionId: (await currentWorkspace()).id });
  }
  if (type === 'mount_vfs_read_file') {
    const sessionId = await resolveOptionalSessionId();
    return globalThis.kernelRequest('vfs_read_file', { ...args, sessionId });
  }
  if (type === 'mount_vfs_pwrite') {
    const sessionId = await resolveOptionalSessionId();
    return globalThis.kernelRequest('vfs_pwrite_chunk', { ...args, sessionId });
  }

  let workspace;
  if (type === 'mount_overlay') {
    if (!Array.isArray(args.calls) || args.calls.some(callTouchesPrivateCarrier)) {
      throw bad('EACCES');
    }
    try {
      workspace = await currentWorkspace();
    } catch {
      return null;
    }
  } else {
    workspace = await currentWorkspace();
  }

  if (type === 'mount_identity') return workspace.identity.id;

  if (type === 'mount_write') {
    if (!(args.bytes instanceof Uint8Array) || args.bytes.length > 8 * 1024 * 1024) throw bad('E2BIG');
    const written = await globalThis.kernelRequest('vfs_pwrite_chunk', {
      sessionId: workspace.id,
      fd: args.fd,
      offset: args.offset ?? 0,
      chunkIndex: args.chunkIndex,
      data: args.bytes,
    });
    return { written };
  }

  if (type === 'mount_sys' || type === 'mount_overlay') {
    if (!Array.isArray(args.calls) || args.calls.some(call => FORBIDDEN_SYS_CALLS.has(typeof call === 'string' ? call : Object.keys(call)[0]))) {
      throw bad('EINVAL');
    }
    return (await globalThis.kernelRequest('vfs_sys', {
      sessionId: workspace.id,
      batch: { calls: args.calls, sudo: !!args.sudo, umask: args.umask },
    })).results;
  }

  throw bad('ENOSYS');
}

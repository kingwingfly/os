// Login-session binding and host-handle registry over `crates/client-kernel`'s unified `Vfs`.
import { prepareUserMount, CLIENT_PAGE_FD_BASE } from './workspace.js';
import { mountApi, exportMount, attachMount } from './mount-sharing.js';

const spaces = new Map();
const FORBIDDEN_SYS_CALLS = new Set([
  'login', 'logout', 'sudo', 'passwd', 'useradd', 'userdel', 'usermod', 'login_lifecycle', 'init',
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
    this.exports = new Map();
    this.sharedConnections = new Map();
    this.cleanups = new Map();
  }

  check() {
    if (!this.alive) throw bad('ENODEV', 'workspace is closed');
  }

  async resolveExport(path) {
    this.check();
    return globalThis.kernelRequest('export_provider', { sessionId: this.id, path });
  }

  close() {
    if (!this.alive) return;
    this.alive = false;
    for (const exported of this.exports.values()) {
      try { exported.connection.close(); } catch {}
    }
    this.exports.clear();
    for (const conn of this.sharedConnections.values()) {
      try { conn.close(); } catch {}
    }
    this.sharedConnections.clear();
    for (const fn of this.cleanups.values()) {
      try { fn?.(); } catch {}
    }
    this.cleanups.clear();
  }
}

// Fresh account-bound inspection, not cached coordinator state or a caller's claimed uid.
export async function currentWorkspace() {
  let view = await globalThis.kernelRequest('login_lifecycle', { op: 'inspect' });
  // A cookie can change without a page event (for example while a shell has
  // exited). Join the new account before resolving its private namespace.
  // An explicitly ended login remains ended; never refresh past shutdown.
  if (!view?.id && !view?.shutdown) {
    await globalThis.kernelRequest('login_refresh');
    view = await globalThis.kernelRequest('login_lifecycle', { op: 'inspect' });
  }
  if (!view?.id || view.shutdown) {
    await globalThis.kernelRequest('set_active_session', { sessionId: null }).catch(() => {});
    throw bad('EACCES', 'login workspace is unavailable');
  }
  let host = spaces.get(view.id);
  if (!host) {
    if (spaces.size >= 16) throw bad('ENOSPC', 'too many login workspaces in this host');
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
  await globalThis.kernelRequest('set_active_session', { sessionId: host.id });
  return host;
}

export function endWorkspace(id) {
  const space = spaces.get(id);
  spaces.delete(id);
  if (space) {
    void Promise.resolve(space)
      .then(value => value.close())
      .catch(() => {});
  }
  if (typeof globalThis.kernelRequest === 'function' && id) {
    void globalThis.kernelRequest('session_end', { sessionId: id }).catch(() => {});
  }
}

async function formatSessionMountList(sessionId) {
  const info = await globalThis.kernelRequest('list_mounts', { sessionId });
  return (info.mounts ?? [])
    .filter(m => !m.baseline)
    .map(m => ({
      path: m.path,
      name: m.name || m.path.split('/').filter(Boolean).pop() || '/',
      kind: m.kind,
      fstype: m.fstype,
      source: m.source,
      writable: !m.readOnly,
      execute: !!m.execute,
      cloud: !!m.cloud,
      userMount: !!m.userMount,
      health: m.health,
      uncertainWrites: m.uncertainWrites ?? 0,
    }));
}

async function resolveOptionalSessionId() {
  try {
    const ws = await currentWorkspace();
    return ws.id;
  } catch (err) {
    if (err?.errno === 'EACCES') return '';
    throw err;
  }
}

export async function mountRequest(type, args = {}) {
  // Unified page VFS entrypoints (work for both authenticated login sessions and guest `system_mnt_ns`).
  if (type === 'mount_vfs_sys') {
    if (!Array.isArray(args.calls) || args.calls.some(call => FORBIDDEN_SYS_CALLS.has(typeof call === 'string' ? call : Object.keys(call)[0]))) {
      throw bad('EINVAL');
    }
    const sessionId = await resolveOptionalSessionId();
    return (await globalThis.kernelRequest('vfs_sys', {
      sessionId,
      batch: { calls: args.calls, sudo: !!args.sudo, umask: args.umask },
    })).results;
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

  if (type === 'mount_list') {
    return formatSessionMountList(workspace.id);
  }

  if (type === 'mount_attach') {
    if (args.login !== undefined && args.login !== workspace.identity.id) {
      throw bad('EACCES', 'Session changed. Choose the folder again.');
    }
    const current = await formatSessionMountList(workspace.id);
    if (current.filter(m => m.userMount).length >= 16) throw bad('ENOSPC');
    const prepared = await prepareUserMount(args, workspace.identity);
    try {
      workspace.check();
      const summary = await globalThis.kernelRequest('mount_user', {
        sessionId: workspace.id,
        spec: prepared.spec,
        hostObj: prepared.hostObj,
      });
      if (prepared.cleanup) workspace.cleanups.set(summary.path, prepared.cleanup);
      const updated = await formatSessionMountList(workspace.id);
      return updated.find(m => m.path === summary.path) ?? {
        path: summary.path,
        name: summary.name,
        kind: summary.kind,
        writable: !summary.readOnly,
        execute: !!summary.execute,
        cloud: !!summary.cloud,
      };
    } catch (error) {
      try { prepared.cleanup?.(); } catch {}
      throw error;
    }
  }

  if (type === 'mount_activate') {
    if (!/^[a-zA-Z0-9_.-]{1,80}$/.test(args.name) || ['.', '..'].includes(args.name) || typeof args.cloud !== 'boolean') {
      throw bad('EINVAL');
    }
    const paths = args.sources ?? [args.source];
    if (!Array.isArray(paths) || paths.length === 0 || paths.length > 16 || paths.some(p => typeof p !== 'string' || !p)) {
      throw bad('EINVAL');
    }
    const current = await formatSessionMountList(workspace.id);
    if (current.filter(m => m.userMount).length >= 16) throw bad('ENOSPC');
    const summary = await globalThis.kernelRequest('mount_user', {
      sessionId: workspace.id,
      spec: {
        kind: 'image',
        name: args.name,
        cloud: args.cloud,
        source: args.source,
        sources: paths,
      },
      hostObj: null,
    });
    const updated = await formatSessionMountList(workspace.id);
    return updated.find(m => m.path === summary.path) ?? {
      path: summary.path,
      name: summary.name,
      kind: summary.kind,
      writable: false,
      execute: true,
      cloud: !!summary.cloud,
    };
  }

  if (type === 'mount_exports') return mountApi(workspace, 'list');
  if (type === 'mount_export') return exportMount(workspace, args);
  if (type === 'mount_revoke') {
    const result = await mountApi(workspace, 'revoke/' + args.export);
    const exported = workspace.exports.get(args.export);
    exported?.connection.close();
    workspace.exports.delete(args.export);
    return result;
  }

  if (type === 'mount_shared') {
    if (!/^[a-zA-Z0-9_.-]{1,80}$/.test(args.name) || ['.', '..'].includes(args.name) || typeof args.cloud !== 'boolean') {
      throw bad('EINVAL');
    }
    const path = '/mnt/shared/' + args.name;
    const current = await formatSessionMountList(workspace.id);
    if (current.some(m => m.path === path)) throw bad('EEXIST');
    if (current.filter(m => m.userMount).length >= 16) throw bad('ENOSPC');
    const remote = await attachMount(workspace, args);
    if (!workspace.alive) {
      remote.unmount(remote.grant);
      throw bad('ESTALE');
    }
    try {
      const summary = await globalThis.kernelRequest('mount_user', {
        sessionId: workspace.id,
        spec: {
          kind: 'sharefs',
          name: args.name,
          writable: !remote.grant.readOnly,
          execute: !!remote.grant.execute,
          cloud: args.cloud,
        },
        hostObj: remote,
      });
      workspace.sharedConnections.set(summary.path, remote.connection);
      workspace.cleanups.set(summary.path, () => remote.unmount(remote.grant));
      const updated = await formatSessionMountList(workspace.id);
      return updated.find(m => m.path === summary.path);
    } catch (error) {
      try { remote.unmount(remote.grant); } catch {}
      throw error;
    }
  }

  if (type === 'mount_transports') {
    return {
      exports: [...workspace.exports.values()].map(({ grant, connection, clients }) => ({
        id: grant.id,
        active: connection.active,
        mode: connection.mode,
        clients: [...clients.values()].map(client => ({ active: client.active, mode: client.mode })),
      })),
      mounts: [...workspace.sharedConnections.entries()].map(([path, connection]) => ({
        path,
        active: connection.active,
        mode: connection.mode,
      })),
    };
  }

  if (type === 'mount_detach') {
    const target = args.path;
    await globalThis.kernelRequest('unmount_user', {
      sessionId: workspace.id,
      target,
      flags: args.flags ?? 0,
    });
    for (const [id, exported] of workspace.exports) {
      if (exported.mountPath === target || exported.mount?.path === target) {
        try { exported.connection.close(); } catch {}
        workspace.exports.delete(id);
      }
    }
    const sharedConn = workspace.sharedConnections.get(target);
    if (sharedConn) {
      try { sharedConn.close(); } catch {}
      workspace.sharedConnections.delete(target);
    }
    const cleanup = workspace.cleanups.get(target);
    if (cleanup) {
      workspace.cleanups.delete(target);
      try { cleanup(); } catch {}
    }
    return null;
  }

  if (type === 'mount_write') {
    if (!(args.bytes instanceof Uint8Array) || args.bytes.length > 256 * 1024) throw bad('E2BIG');
    const written = await globalThis.kernelRequest('vfs_pwrite_chunk', {
      sessionId: workspace.id,
      fd: args.fd,
      offset: args.offset ?? 0,
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

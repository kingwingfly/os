import { Workspace, LOCAL_FD, localPath, localFdPath } from './workspace.js';
import { mountApi, exportMount, attachMount } from './mount-sharing.js';

const spaces = new Map();
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
  if (!view?.id || view.shutdown) throw Object.assign(new Error('login workspace is unavailable'), { errno: 'EACCES' });
  let workspace = spaces.get(view.id);
  if (!workspace) {
    if (spaces.size >= 16) throw Object.assign(new Error('too many login workspaces in this host'), { errno: 'ENOSPC' });
    const joining = (async () => {
    const creds = await globalThis.kernelRequest('workspace_credentials');
    if (!creds || creds.uid !== view.uid) throw { errno: 'EACCES' };
    return new Workspace({ ...view, gid: creds.gid, groups: creds.groups });
    })();
    spaces.set(view.id, joining);
    try { workspace = await joining; } catch (error) { if (spaces.get(view.id) === joining) spaces.delete(view.id); throw error; }
  }
  workspace = await workspace;
  if (workspace.identity.uid !== view.uid) throw { errno: 'EACCES' };
  workspace.check(); return workspace;
}
export function endWorkspace(id) { const space = spaces.get(id); spaces.delete(id); if (space) void Promise.resolve(space).then(value => value.close()).catch(() => {}); }
export async function mountRequest(type, args) {
  let workspace;
  if (type === 'mount_overlay') {
    if (!Array.isArray(args.calls) || args.calls.some(call => {
      const arg = typeof call === 'object' && call !== null ? Object.values(call)[0] : null;
      return arg && (arg.fd >= LOCAL_FD || [arg.path, arg.from, arg.to].some(path => localPath(path) || localFdPath(path)));
    })) throw { errno: 'EACCES' };
    try { workspace = await currentWorkspace(); } catch { return null; }
  } else workspace = await currentWorkspace();
  if (type === 'mount_identity') return workspace.identity.id;
  if (type === 'mount_list') return workspace.list();
  if (type === 'mount_attach') {
    // A picker can remain open across account changes. Its selection belongs to
    // the login that opened it, never whichever account happens to be current.
    if (args.login !== undefined && args.login !== workspace.identity.id) throw { errno: 'EACCES', detail: 'Session changed. Choose the folder again.' };
    return workspace.mount(args);
  }
  if (type === 'mount_activate') return workspace.activate(args, manifests => globalThis.kernelRequest('private_extension', { manifests }));
  if (type === 'mount_exports') return mountApi(workspace, 'list');
  if (type === 'mount_export') return exportMount(workspace, args);
  if (type === 'mount_revoke') {
    const result = await mountApi(workspace, 'revoke/' + args.export);
    const exported = workspace.exports?.get(args.export); exported?.connection.close(); workspace.exports?.delete(args.export);
    return result;
  }
  if (type === 'mount_shared') {
    if (!/^[a-zA-Z0-9_.-]{1,80}$/.test(args.name) || ['.', '..'].includes(args.name) || typeof args.cloud !== 'boolean') throw { errno: 'EINVAL' };
    const path = '/mnt/shared/' + args.name;
    if (workspace.mounts.get(path)?.active || workspace.list().length >= 16) throw { errno: 'EEXIST' };
    const provider = await attachMount(workspace, args);
    if (!workspace.alive || workspace.mounts.get(path)?.active) { provider.unmount(provider.grant); throw { errno: 'ESTALE' }; }
    if (workspace.list().length >= 16) { provider.unmount(provider.grant); throw { errno: 'ENOSPC' }; }
    workspace.mounts.set(path, { path, name: args.name, grant: provider.grant, provider, cloud: args.cloud, active: true });
    return workspace.list().find(mount => mount.path === path);
  }
  if (type === 'mount_transports') return { exports: [...workspace.exports?.values() ?? []].map(({ grant, connection, clients }) => ({ id: grant.id, active: connection.active, mode: connection.mode, clients: [...clients.values()].map(client => ({ active: client.active, mode: client.mode })) })), mounts: [...workspace.mounts.values()].filter(mount => mount.provider.connection).map(mount => ({ path: mount.path, active: mount.provider.connection.active, mode: mount.provider.connection.mode })) };
  if (type === 'mount_detach') { workspace.unmount(args.path); return null; }
  if (type === 'mount_read') {
    let fd = args.fd, opened;
    if (args.token) fd = [...workspace.fds].find(([, file]) => file.scope === workspace.page && file.token === args.token)?.[0];
    if (args.path) { opened = await workspace.open(args.path, 0, workspace.page); fd = opened.fd; }
    if (!Number.isInteger(fd) || fd < LOCAL_FD) throw { errno: 'EBADF' };
    try {
      if (args.stat) return await workspace.fstat(fd, workspace.page);
      return await workspace.read(fd, args.offset ?? 0, args.count ?? 256 * 1024, workspace.page);
    } finally { if (opened) await workspace.closeFd(fd, workspace.page).catch(() => {}); }
  }
  if (type === 'mount_write') {
    if (!(args.bytes instanceof Uint8Array) || args.bytes.length > 256 * 1024) throw { errno: 'E2BIG' };
    return workspace.write(args.fd, args.bytes, args.offset, workspace.page);
  }
  if (type === 'mount_sys' || type === 'mount_overlay') {
    // Account-changing calls must never straddle a private namespace operation.
    const forbidden = new Set(['login', 'logout', 'sudo', 'passwd', 'useradd', 'userdel', 'usermod', 'login_lifecycle', 'init']);
    if (!Array.isArray(args.calls) || args.calls.some(call => forbidden.has(typeof call === 'string' ? call : Object.keys(call)[0]))) throw { errno: 'EINVAL' };
    return workspace.calls(args.calls, workspace.page, async calls => {
      const response = await fetch('/api/sys', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ calls, sudo: !!args.sudo, umask: args.umask }) });
      if (!response.ok) throw { errno: 'EIO' }; return (await response.json()).results;
    });
  }
  throw { errno: 'ENOSYS' };
}

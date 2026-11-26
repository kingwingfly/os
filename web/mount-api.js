// UI-free programmatic mount & sharing facade (`window.os.*`).
// Interactive Mounts UI runs as the ordinary GUI process `/usr/bin/mounts` (#63 L6b-2).
import { kernelCall } from './kernel/protocol.js';
import { mountConnector, mountListener } from './mount-transport.js';

const session = () => kernelCall('source_session');
const failure = (errno, message) => Object.assign(new Error(message ?? errno), { errno });

async function rpc(local, service, request, extra = {}, transfer = []) {
  const args = { loginEpoch: local.loginEpoch, socket: `/run/user/${local.uid}/${service}.sock`, request, ...extra };
  // Resolve the active listener before transferring a one-use MessagePort.
  const reply = await kernelCall('unix_rpc', { ...args, fallbackSocket: `/run/${service}/control.sock` }, transfer);
  if (reply.status === 'error') {
    const message = reply.errno === 'EPROTONOSUPPORT' ? 'Update os-local-helper before sharing this folder.'
      : reply.errno === 'EACCES' ? 'Permission denied. Check the export credentials or ACL.'
      : reply.errno === 'EAGAIN' ? 'Too many password attempts. Try again in a minute.' : reply.message;
    const detail = request.op === 'activate_private' && request.additional_sources?.length && reply.errno === 'EINVAL'
      ? 'Cannot compose these images. Check for a path collision or incompatible metadata.' : message;
    throw failure(reply.errno, [reply.errno, detail].filter(Boolean).join(' '));
  }
  return reply;
}

const summary = e => ({ ...e, address: 'osfs:' + e.id, expires: e.expires_at, write: e.rule.writable, execute: e.rule.execute });

export async function shareMount(args, options = {}) {
  const local = await session();
  const automatic = !args.transport && options.p2p == null;
  const ipc = args.ipcOnly || args.transport === 'ipc' || (automatic && local.relayUid == null);
  let transports = [];
  if (ipc) transports = ['ipc'];
  else if (options.p2p === false || args.transport === 'relay') transports = ['ipc', 'relay'];
  else if (!automatic) transports = ['ipc', 'p2p', 'relay'];
  const listener = ipc ? null : mountListener(options);
  try {
    const reply = await rpc(local, 'export', {
      op: 'publish',
      source_path: args.path,
      name: args.name ?? args.path?.split('/').filter(Boolean).at(-1) ?? 'share',
      writable: args.writable ?? true,
      execute: args.execute ?? true,
      seconds: args.seconds ?? 300,
      password: args.password || null,
      transports,
    }, { open: { path: args.path, flags: 0o200000 | 0o400000 }, ...(listener && { port: listener.port }) }, listener ? [listener.port] : []);
    if (reply.export.transports.every(t => t === 'ipc')) listener?.close();
    return summary(reply.export);
  } catch (e) {
    listener?.close();
    if (e.errno === 'EPROTONOSUPPORT') throw failure(e.errno, 'Update os-local-helper before sharing this folder.');
    throw e;
  }
}

export async function attachShared(args, options = {}) {
  const local = await session();
  const target = '/mnt/shared/' + args.name;
  const kind = args.transport ?? options.transport ?? (options.ipcPort ? 'ipc' : options.p2p === false ? 'relay' : undefined);
  const transport = kind === 'ipc' && !options.ipcPort ? null : mountConnector(options);
  const flags = 2 | 4 | (args.writable ? 0 : 1) | (args.execute ? 0 : 8);
  const opts = [];
  if (kind) opts.push('transport=' + kind);
  if (args.password) opts.push('password=' + encodeURIComponent(args.password));
  const request = { op: 'attach', source: args.address, target, fstype: 'sharefs', flags, options: opts.join(',') };
  try {
    await rpc(local, 'mount', request, transport ? { port: transport.port } : {}, transport ? [transport.port] : []);
    const { attachments } = await rpc(local, 'mount', { op: 'list_attachments' });
    const mount = attachments.find(m => m.target === target);
    if (!mount) throw failure('ESTALE');
    return { ...mount, path: target, kind: 'sharefs', readOnly: mount.read_only };
  } catch (e) { transport?.close(); throw e; }
}

export const detachShared = async path => rpc(await session(), 'mount', { op: 'detach', target: path });

export async function sharedMounts() {
  const local = await session(), { exports } = await rpc(local, 'export', { op: 'list' });
  return { uid: local.relayUid ?? local.uid, exports: exports.map(summary) };
}

export const revokeMount = async id => rpc(await session(), 'export', { op: 'revoke', id });

export const exportStatus = async id => summary((await rpc(await session(), 'export', { op: 'status', id })).export);

export async function mountTransports() {
  const local = await session();
  const [{ exports }, { attachments }] = await Promise.all([
    rpc(local, 'export', { op: 'transports' }),
    rpc(local, 'mount', { op: 'list_attachments' }),
  ]);
  const rows = exports.map(({ id, clients }) => ({
    id, active: true, mode: 'listening', clients: clients.map(c => ({ ...c, active: true, mode: c.transport })),
  }));
  const mounts = attachments.filter(m => m.fstype === 'sharefs').map(m => ({
    path: m.target, health: m.health, active: m.health === 'connected', mode: m.options.find(o => o.startsWith('transport='))?.slice(10),
  }));
  return { exports: rows, mounts };
}

export async function localMounts(pane = 'mounted') {
  const normalized = pane === 'sharing' ? 'publish' : pane;
  return window.osDesktop?.openMounts?.(normalized);
}

export async function sharingDialog() {
  return localMounts('publish');
}

function userAttachment(row) {
  const kind = { opfs: 'browser-storage', helperfs: 'native-directory', hostfs: 'directory', sharefs: 'shared', image: 'private-extension' };
  return {
    ...row,
    path: row.target,
    name: row.target.split('/').at(-1),
    kind: kind[row.fstype] ?? row.fstype,
    writable: !row.read_only,
    execute: !row.noexec,
    userMount: row.user_mount,
    uncertainWrites: row.uncertain_writes,
  };
}

export async function localMountList(local = null) {
  const { attachments } = await rpc(local ?? await session(), 'mount', { op: 'list_attachments' });
  return attachments.filter(row => row.user_mount).map(userAttachment);
}

export async function mountLocal(args) {
  const local = await session();
  if (args.login !== undefined && args.login !== local.id) throw failure('EACCES', 'Session changed. Choose the folder again.');
  const fstype = args.url ? 'helperfs' : args.storage || args.originPrivate ? 'opfs' : 'hostfs';
  const operation = { hostfs: 'source_register_host', helperfs: 'source_register_helper', opfs: 'source_register_opfs' }[fstype];
  const { source_id } = await kernelCall(operation, { ...args, loginEpoch: local.loginEpoch });
  const target = '/mnt/local/' + (args.name ?? args.handle?.name ?? 'files');
  await rpc(local, 'mount', {
    op: 'attach',
    source_id,
    source: source_id,
    fstype,
    target,
    flags: (args.writable ? 0 : 1) | (args.execute ? 0 : 8),
  });
  return (await localMountList(local)).find(m => m.path === target);
}

export async function unmountLocal(path) {
  return rpc(await session(), 'mount', { op: 'detach', target: path });
}

export async function activatePrivate({ name, source, sources, execute = true }) {
  const local = await session(), rows = await localMountList(local);
  const ids = (sources ?? [source]).map(path => {
    const row = rows.find(r => r.path === path);
    if (!row?.source_id) throw failure('ENOENT');
    return row.source_id;
  });
  await rpc(local, 'mount', { op: 'activate_private', name, source_id: ids[0], additional_sources: ids.slice(1), execute });
  return (await localMountList(local)).find(m => m.path === '/opt/private/' + name);
}

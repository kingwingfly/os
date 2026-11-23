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
      : reply.errno === 'EACCES' ? 'Permission denied. Check the export permissions or password.' : reply.message;
    throw failure(reply.errno, message);
  }
  return reply;
}
const summary = e => ({ ...e, address: 'osfs:' + e.id, expires: e.expires_at, write: e.rule.writable, execute: e.rule.execute });

export async function shareMount(args, options = {}) {
  const local = await session();
  const ipc = args.ipcOnly || args.transport === 'ipc';
  const listener = ipc ? null : mountListener(options);
  try {
    const reply = await rpc(local, 'export', {
      op: 'publish', source_path: args.path, name: args.name, writable: args.writable ?? true, execute: args.execute ?? true,
      seconds: args.seconds ?? 300, password: args.password || null,
      transports: ipc ? ['ipc'] : options.p2p === false ? ['ipc', 'relay'] : ['ipc', 'p2p', 'relay'],
    }, { open: { path: args.path, flags: 0o200000 | 0o400000 }, ...(listener && { port: listener.port }) }, listener ? [listener.port] : []);
    if (reply.export.transports.every(t => t === 'ipc')) listener?.close();
    return summary(reply.export);
  } catch (e) { listener?.close(); throw e; }
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
    path: m.target, active: m.health === 'connected', mode: m.options.find(o => o.startsWith('transport='))?.slice(10),
  }));
  return { exports: rows, mounts };
}
export async function sharingDialog() {
  const { openMountManager } = await import('./mount-manager.js');
  openMountManager('sharing');
}

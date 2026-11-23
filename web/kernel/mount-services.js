// Worker-side ownership of browser grants, authenticated page sockets and transferred ports.
import { SourceRegistry, mountPageRequest, startMountHost } from './source-registry.js';
import { connectExportTransport, exportRelayAdapter, mountConnector, mountListener } from '../mount-transport.js';
import { mountSocketOp } from '../wasi/exec.mjs';
import { currentWorkspace } from './workspaces.js';

const fail = (errno, message = errno) => Object.assign(new Error(message), { errno });
const missing = e => ['ENOENT', 'ECONNREFUSED'].includes(e?.errno);
let table, registry, starting, joining, epoch = 0;
const incarnation = crypto.randomUUID();
const publishers = new Map(), connectors = new Map();
const reached = new Set();

function checkedSession(id) {
  const s = registry?.session;
  if (!s || s.id !== id) throw fail('ECANCELED', 'Login session changed.');
  return s;
}

function call(s, socket, request, fd) {
  checkedSession(s.id);
  const k = globalThis.kernel;
  return k.page_unix_rpc(s.id, k.mount_page_proxy(s.id), socket, JSON.stringify(request), fd, mountSocketOp);
}

async function serviceCall(s, socket, fallback, request, fd) {
  const key = fallback ?? socket, start = Date.now();
  for (;;) {
    try {
      let reply;
      try { reply = await call(s, socket, request, fd); }
      catch (e) {
        if (!missing(e) || !fallback) throw e;
        // Give a logging-in user's exportd time to claim new publications.
        if (s.uid && request.op === 'publish' && Date.now() - start < 1000) {
          await new Promise(resolve => setTimeout(resolve, 25));
          continue;
        }
        reply = await call(s, fallback, request, fd);
        reached.add(key);
        return reply;
      }
      reached.add(key);
      if (fallback !== '/run/export/control.sock' || socket !== `/run/user/${s.uid}/export.sock`) return reply;
      const listing = Array.isArray(reply.exports) && ['list', 'transports'].includes(request.op);
      const lookup = reply.errno === 'EACCES' && ['revoke', 'status', 'list_clients'].includes(request.op);
      if (!listing && !lookup) return reply;
      // Both daemons authorize the caller independently. A system grant keeps its original owner.
      try {
        const system = await call(s, fallback, request);
        return listing && system.exports ? { ...reply, exports: [...reply.exports, ...system.exports] } : system;
      } catch (e) { if (!missing(e)) throw e; return reply; }
    } catch (e) {
      if (!missing(e) || reached.has(key) || Date.now() - start >= 5000) throw e;
      await new Promise(resolve => setTimeout(resolve, 25));
    }
  }
}

async function exportsFor(uid) {
  const s = registry.session;
  if (s?.uid !== uid || uid === 0) return [];
  try {
    const socket = `/run/user/${uid}/export.sock`, fallback = '/run/export/control.sock';
    const { exports, errno } = await serviceCall(s, socket, fallback, { op: 'list' });
    if (!exports) throw fail(errno);
    const { exports: routes } = await serviceCall(s, socket, fallback, { op: 'transports' });
    return exports.map(e => ({ id: e.id, name: e.name, address: 'osfs:' + e.id, source_path: e.source_path,
      owner_uid: e.owner_uid, writable: e.rule.writable, execute: e.rule.execute, password_protected: e.password,
      expires_at: e.expires_at, active_clients: routes.find(r => r.id === e.id)?.clients.length ?? 0, transports: e.transports }));
  } catch (e) { if (missing(e)) return []; throw e; }
}

async function connectShare(op, s) {
  const id = op.address.slice(5), options = new URLSearchParams((op.options ?? '').replaceAll(',', '&'));
  const supplied = connectors.get(op.pid)?.get(op.target);
  const rule = { writable: !(op.flags & 1), execute: !(op.flags & 8) };
  const selected = options.get('transport');
  const password = op.password || options.get('password') || '';
  const description = { id, session: s.id, caller: op.pid, rule };
  if ((!selected || selected === 'ipc') && globalThis.kernel.local_export_available(id)) {
    return { description: JSON.stringify({ ...description, password, transport: 'ipc' }) };
  }
  if (selected === 'ipc' && !supplied) throw fail('ENOENT');
  const broker = supplied ?? mountConnector().port;
  const client = await connectExportTransport(broker, { id, ...rule,
    password, transport: selected }, () => relayCredential(s));
  checkedSession(s.id);
  connectors.get(op.pid)?.delete(op.target);
  return { description: JSON.stringify({ ...description, transport: client.mode,
    expires_at: client.expires_at ?? Date.now() + 3600000 }), port: client.takePort() };
}

function relayCredential(s) {
  checkedSession(s.id);
  return JSON.parse(globalThis.kernel.relay_credential(s.uid));
}

function ensureRegistry() {
  if (!registry) {
    table = new globalThis.wasm_bindgen.HostSourceTable(0, 0);
    registry = new SourceRegistry({ table, connectShare });
    globalThis.mountSocketOp = mountSocketOp;
    globalThis.closeRelayListeners = () => globalThis.exportRelayCall?.endSession?.(registry.session?.id);
    globalThis.exportRelayCall = exportRelayAdapter(({ publisher_pid, owner_uid }) => {
      const s = registry.session;
      if (!s || s.uid !== owner_uid) throw fail('EACCES');
      relayCredential(s);
      return { port: publishers.get(publisher_pid) ?? mountListener().port, session: s.id, credential: () => relayCredential(s) };
    }, ({ port, publisherSession, ...header }) => {
      checkedSession(publisherSession);
      return globalThis.kernel.accept_export_port(publisherSession, JSON.stringify(header), port);
    });
  }
}

export function ensureMountHost() {
  ensureRegistry();
  starting ??= startMountHost({ kernel: globalThis.kernel, registry, table, socketOp: mountSocketOp, exportsFor,
    isMountService: pid => globalThis.kernel.is_service_image(pid, 'mountd') }).catch(e => { starting = null; throw e; });
  return starting;
}

export async function resetMountHost() {
  const stop = await starting;
  if (stop) await stop();
  starting = null;
  if (registry?.session) endMountSession(registry.session.id);
  joining = undefined;
  reached.clear();
  publishers.clear();
  connectors.clear();
}

export function endMountSession(id) {
  globalThis.exportRelayCall?.endSession?.(id);
  if (registry?.session?.id === id) registry.endSession();
}

export async function syncMountSession(workspace) {
  workspace ??= await currentWorkspace();
  ensureRegistry();
  if (joining?.workspace !== workspace || !registry.session) {
    reached.clear();
    if (registry.session) endMountSession(registry.session.id);
    const root = JSON.parse(globalThis.kernel.boot_status()).mounted_root;
    const volume = root?.volume_uuid && root.volume_uuid !== 'ephemeral' ? root.volume_uuid : null;
    const ready = registry.beginSession({ ...workspace.identity, volume, loginEpoch: ++epoch });
    joining = { workspace, ready };
    ready.catch(() => { if (joining?.ready === ready) joining = null; });
  }
  await joining.ready;
  return checkedSession(workspace.id);
}

export async function mountServiceRequest(type, args) {
  const s = await syncMountSession(), k = globalThis.kernel;
  const proxyPid = k.mount_page_proxy(s.id);
  const stamp = JSON.stringify([incarnation, s.id, s.loginEpoch]);
  if (type === 'source_session') {
    const cloud = JSON.parse(k.cloud_status());
    let relayUid = null;
    if (cloud.signed_in && cloud.scope?.relay) {
      try { relayCredential(s); relayUid = 0x80000000 + cloud.cloud_uid; } catch { /* local login has no active relay grant */ }
    }
    return { ...s, relayUid, loginEpoch: stamp };
  }
  if (stamp !== args.loginEpoch) throw fail('ECANCELED', 'Session changed. Choose the folder again.');
  if (type !== 'unix_rpc') return mountPageRequest(type, { ...args, loginEpoch: s.loginEpoch }, { registry, kernel: k, proxyPid, socketOp: mountSocketOp });
  const { request, socket, port } = args;
  let fd, tracked;
  try {
    if (args.fd != null) throw fail('EBADF');
    if (request.op === 'publish') {
      if (!args.open || args.open.path !== request.source_path) throw fail('EINVAL');
      if (publishers.has(proxyPid)) throw fail('EBUSY');
      publishers.set(proxyPid, port ?? null);
      tracked = 'publish';
      fd = await k.open_export_root(s.id, request.source_path);
    } else if (args.open) throw fail('EINVAL');
    if (port && request.op === 'attach' && request.fstype === 'sharefs') {
      let byTarget = connectors.get(proxyPid);
      if (!byTarget) connectors.set(proxyPid, byTarget = new Map());
      if (byTarget.has(request.target)) throw fail('EBUSY');
      byTarget.set(request.target, port);
      tracked = 'attach';
    } else if (port && tracked !== 'publish') throw fail('EINVAL');
    const reply = await serviceCall(s, socket, args.fallbackSocket, request, fd);
    if (tracked === 'publish' && reply.export?.transports.some(t => t !== 'ipc')) publishers.delete(proxyPid);
    return reply;
  } finally {
    if (fd != null) await k.kfd_close(proxyPid, fd);
    if (tracked === 'publish' && publishers.has(proxyPid)) { publishers.delete(proxyPid); port?.postMessage({ type: 'close' }); port?.close(); }
    if (tracked === 'attach') {
      const byTarget = connectors.get(proxyPid);
      if (byTarget.delete(request.target)) { port.postMessage({ type: 'close' }); port.close(); }
      if (!byTarget.size) connectors.delete(proxyPid);
    }
  }
}

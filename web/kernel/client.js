import { asset } from '../release.js';
import { imageBlobRead } from './image-pager.js';
// The client kernel: a classic dedicated Worker (one isolated OS instance per tab), so it can
// importScripts the no-modules wasm-bindgen build. The Rust kernel (crates/client-kernel) owns
// this instance's LocalProcessTable, local /proc, instance-local /run and /tmp, local cgroup v2
// policy, and explicit remote ServiceAuth v2 credentials. Boot, exec, fork, wait, kill, pipe,
// setsid, and /proc run 100% locally with zero network RPCs; remote cloud filesystem and remote
// devices attach lazily over ServiceAuth v2 (/api/service-auth) only when needed.
//
// A process belongs exclusively to its port's host identity (never the public tab label). Only
// that port forks it, replaces its image, ends it, waits for its children, or signals as it;
// another tab runs its own isolated Worker instance and cannot observe or address its processes.
importScripts(asset('/client_kernel.js'));

const VERSION = 2;
const ports = new Set();
let kernel;
let starting;
let login, machineInit;
// This instance's unique local identifier (never shared across tabs).
const kernelId = self.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`;
// Each port's host: an identity of its own, made here, and the tab it first said it was.
const hosts = new WeakMap();
// What the kernel does, one thing at a time for serialized lifecycle ops.
let queue = Promise.resolve();
const serially = task => {
  const done = queue.then(task);
  queue = done.catch(() => {});
  return done;
};

// ServiceAuth v2 transport: POST /api/service-auth (lazy first-remote-use only; NEVER X-Registry).
self.serviceAuthPost = async (body, signal) => {
  const response = await fetch('/api/service-auth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body,
    signal,
  });
  return JSON.stringify({ status: response.status, text: await response.text() });
};

// Surface version mismatch notices without auto-reloading (docs/architecture/contract.md §2.10).
self.onProtocolMismatch = value => {
  broadcast({ v: VERSION, type: 'event', event: 'protocol-mismatch', value });
};

// Cookie-authenticated authority batch transport for page VFS calls (NEVER X-Registry).
self.pageSysPost = async (body, extraHeaders = {}) => {
  const response = await fetch('/api/sys', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(extraHeaders ?? {}) },
    body,
  });
  return JSON.stringify({ status: response.status, text: await response.text() });
};

self.pagePwrite = async (fd, index, bytes, extraHeaders = {}) => {
  const response = await fetch(`/api/pwrite?fd=${Number(fd)}&index=${Number(index)}`, {
    method: 'PUT',
    headers: extraHeaders ?? {},
    body: bytes,
  });
  return JSON.stringify({ status: response.status, text: await response.text() });
};

self.pageFileRead = async (path, offset, len) => {
  const start = Number(offset);
  const count = Number(len);
  if (count <= 0) return { status: 200, body: new Uint8Array(0), etag: '' };
  const end = start + count - 1;
  const response = await fetch('/api/file?path=' + encodeURIComponent(path), {
    headers: { Range: `bytes=${start}-${end}` },
  });
  const etag = response.headers.get('ETag') ?? '';
  if (response.status === 416) return { status: 416, body: new Uint8Array(0), etag };
  const raw = response.status === 200 || response.status === 206
    ? new Uint8Array(await response.arrayBuffer())
    : new Uint8Array(0);
  const body = response.status === 200 ? raw.subarray(start, start + count) : raw;
  return { status: response.status, body, etag };
};

self.imageBlobRead = imageBlobRead;

self.onKernelMountsChanged = value => {
  broadcast({ v: VERSION, type: 'event', event: 'mounts-changed', value });
};

self.cloudFsPost = async (path, headers, body) => {
  const response = await fetch(path, { method: 'POST', headers, body });
  return { status: response.status, body: new Uint8Array(await response.arrayBuffer()) };
};
self.cloudFsSleep = ms => new Promise(resolve => setTimeout(resolve, ms));
self.cloudFsTicket = () => self.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`;

function boot() {
  starting ??= wasm_bindgen(asset('/client_kernel_bg.wasm')).then(async () => {
    self.wasm_bindgen = wasm_bindgen;
    kernel = new wasm_bindgen.Kernel('', kernelId);
    const value = JSON.parse(await kernel.init());
    const [{ LoginCoordinator, LoginStartup }, { InitCoordinator, InitReaper }] = await Promise.all([import(asset('/login-session.js')), import(asset('/init-owner.js'))]);
    const proof = [...crypto.getRandomValues(new Uint8Array(32))].map(byte => byte.toString(16).padStart(2, '0')).join('');
    let lastLogin;
    login = new LoginCoordinator({ host: kernelId, proof,
      changed: value => {
        const id = value.session?.id;
        if (id && id !== lastLogin) {
          const previous = lastLogin;
          lastLogin = id;
          if (previous) void import(asset('/executor-host.js')).then(executor => {
            if (lastLogin !== previous) return executor.endWorkspace(previous);
          }).catch(() => {});
        }
        login.startup?.update(value);
        broadcast({ v: VERSION, type: 'event', event: 'login', value: { ...value, services: login.startup?.current(value) } });
      },
      call: async action => {
        try {
          return JSON.parse(await kernel.login_session_action(JSON.stringify(action), kernelId));
        } catch (error) {
          throw failure(error);
        }
      },
    });
    login.startup = new LoginStartup({
      token: () => [...crypto.getRandomValues(new Uint8Array(32))].map(byte => byte.toString(16).padStart(2, '0')).join(''),
      begin: (expected, launch) => login.control('begin', { launch }, expected),
      finish: value => login.call({ op: 'finish', ...value }),
      changed: () => {
        const value = login.current();
        broadcast({ v: VERSION, type: 'event', event: 'login', value: { ...value, services: login.startup.current(value) } });
      },
      execute: async (run, onOutput) => {
        const executor = await import(asset('/executor-host.js'));
        const workspace = await executor.currentWorkspace().catch(() => null);
        return executor.exec([['supervise', run.file]], { stdin: '', streamOutput: true,
          sessionId: run.session,
          serviceGrant: { mountNamespace: 'system', bindMounts: [] },
          ...(workspace?.id === run.session ? { workspace } : {}),
          cancelled: () => run.cancelled, onOutput,
          onJob: job => { run.job = job; },
          beforeStart: async pid => {
            await self.kernelRequest('login_service_attach', { pid, expected: run.expected, launch: run.launch });
            run.stop = async () => {
              try {
                await self.kernelRequest('kill', { pid, from: pid, signal: 15 });
                await self.kernelRequest('kill', { pid, from: pid, signal: 18 });
              } catch { /* normal exit or expiry can win; the host deadline still bounds cleanup */ }
            };
            run.attached = true;
          },
        });
      },
    });
    machineInit = new InitCoordinator({ host: kernelId,
      proof: [...crypto.getRandomValues(new Uint8Array(32))].map(byte => byte.toString(16).padStart(2, '0')).join(''),
      changed: value => {
        machineInit.reaper?.update(value, machineInit.ownership);
        broadcast({ v: VERSION, type: 'event', event: 'machine_init', value: { ...value, reaper: machineInit.reaper?.current() } });
      },
      call: async action => {
        try {
          return JSON.parse(await kernel.machine_init_action(JSON.stringify(action), kernelId));
        } catch (error) {
          throw failure(error);
        }
      },
    });
    machineInit.reaper = new InitReaper({
      token: () => [...crypto.getRandomValues(new Uint8Array(32))].map(byte => byte.toString(16).padStart(2, '0')).join(''),
      release: owner => machineInit.call({ op: 'release', owner }),
      exhausted: () => { void machineInit.stop(); },
      changed: () => {
        if (!machineInit.reaper.run && machineInit.reaper.state === 'stopped'
          && machineInit.current().coordinator && machineInit.ownership) {
          queueMicrotask(() => machineInit.reaper.update(machineInit.current(), machineInit.ownership));
        }
        broadcast({ v: VERSION, type: 'event', event: 'machine_init',
          value: { ...machineInit.current(), reaper: machineInit.reaper.current() } });
      },
      start: async (owner, token, cancelled, running) => {
        const { exec } = await import(asset('/executor-host.js'));
        let error = '';
        const result = await exec([['init']], { stdin: '', cancelled,
          prepare: async () => [{ ok: await self.kernelRequest('boot_init', { owner, token }) }],
          onJob: job => { if (job.pids.includes(1)) running(); },
          onOutput: (fd, text) => { if (fd === 2) error = (error + text).slice(-4096); },
        });
        if (!cancelled()) throw new Error(error.trim() || `init exited (${result.status})`);
      },
    });
    await login.tick();
    void machineInit.tick();
    broadcast({ v: VERSION, type: 'event', event: 'started', value });
    return value;
  }).catch(error => {
    kernel = undefined;
    starting = undefined;
    throw error;
  });
  return starting;
}

function broadcast(message) {
  for (const port of ports) port.postMessage(message);
}

// execve of a pipeline's stages locally inside this instance's LocalProcessTable.
async function execs(args, seat, host) {
  const stages = (args.stages ?? []).map(stage => ({
    path: stage.path,
    local: stage.local,
    runtime: stage.runtime,
    parentPid: stage.parentPid,
    sessionId: stage.sessionId,
    serviceGrant: stage.serviceGrant,
    ...(stage.remote !== undefined ? { remote: stage.remote } : {}),
    argv: stage.argv ?? [],
    env: stage.env ?? [],
    cwd: stage.cwd ?? '/',
    cgroup: stage.cgroup ?? '',
  }));
  return JSON.parse(await kernel.execs(JSON.stringify(stages), !!args.sudo, seat ?? '', host));
}
// execve of one image: a pipeline of one stage.
async function exec(args, seat, host) {
  const [result] = await execs({ stages: [args], sudo: args.sudo }, seat, host);
  if (result.err) throw result.err;
  return result.ok;
}

function failure(error) {
  if (typeof error === 'string') {
    try { return JSON.parse(error); } catch { /* not our envelope */ }
  }
  // Structured cloning an Error keeps its message, but drops errno and detail. The
  // protocol carries a plain record so loader failures survive the worker boundary.
  if (error && typeof error === 'object' && error.errno) {
    return { errno: error.errno, detail: error.detail ?? error.message ?? error.errno,
      ...(error.execCommitted ? { execCommitted: true } : {}) };
  }
  return { errno: 'EIO', detail: String(error?.message ?? error) };
}

async function dispatch(message, host, tab, internal = false) {
  const { type, args = {} } = message;
  if (!internal && ['vfs_open_read', 'vfs_read_stream_chunk', 'vfs_close_read_stream'].includes(type)) {
    const executor = await import(asset('/executor-host.js'));
    const { id } = await executor.currentWorkspace();
    return dispatch({ type, args: { ...args, sessionId: id } }, host, tab, true);
  }
  switch (type) {
    case 'init': return boot();
    case 'version': return kernel.version();
    case 'instance_id': return kernel.instance_id();
    case 'namespace': return kernel.namespace();
    case 'workspace_credentials': return JSON.parse(kernel.workspace_credentials());
    case 'sync_account': return JSON.parse(kernel.sync_account(typeof args === 'string' ? args : JSON.stringify(args)));
    case 'sync_account_from_server': return JSON.parse(await kernel.sync_account_from_server());
    case 'machine_init_action': return JSON.parse(await kernel.machine_init_action(JSON.stringify(args.action ?? args), host));
    case 'login_session_action': return JSON.parse(await kernel.login_session_action(JSON.stringify(args.action ?? args), host));
    case 'machine_init_status': return { ...machineInit.current(), reaper: machineInit.reaper.current() };
    case 'machine_init_resume': return machineInit.resume();
    case 'machine_init_leave': await machineInit.stop(); return null;
    case 'machine_reboot': {
      const value = await machineInit.call({ op: 'reboot', boot: args.boot });
      const executor = await import(asset('/executor-host.js'));
      void executor.reconcile().catch(() => {});
      await login.reset();
      await machineInit.resume();
      return value;
    }
    case 'machine_inspect': return machineInit.call({ op: 'inspect' });
    case 'login_lifecycle': {
      if (!['end', 'restart', 'inspect'].includes(args.op)) throw { errno: 'EINVAL' };
      const value = await login.call({ op: args.op, ...(args.op === 'inspect' ? {} : { session: args.session }) });
      if (args.op !== 'inspect') {
        const executor = await import(asset('/executor-host.js'));
        void executor.reconcile().catch(() => {});
        await executor.endWorkspace(args.session);
        await login.reset();
      }
      return value;
    }
    case 'login_status': {
      if (login.view?.shutdown && !login.view.shutdown.complete) {
        try {
          const fresh = JSON.parse(await kernel.login_session_action(JSON.stringify({ op: 'inspect' }), kernelId));
          if (fresh?.id === login.view.id) login.view = fresh;
        } catch { /* keep cached view */ }
      }
      const value = login.current();
      return { ...value, services: login.startup.current(value) };
    }
    case 'login_configure': return login.control('configure', { file: args.file }, args.expected);
    case 'login_seat_policy': {
      const value = await login.call({ op: 'seat_policy', session: args.session, expected: args.expected, sharing: args.sharing });
      await login.tick();
      const executor = await import(asset('/executor-host.js'));
      executor.setSharingPolicy(() => login.current());
      return value;
    }
    case 'login_refresh': {
      if (args?.fromServer !== false) {
        try { await kernel.sync_account_from_server(); } catch { /* offline or guest */ }
      }
      return login.reset();
    }
    case 'login_leave': await login.stop(); return null;
    case 'login_service_check': login.capture(args.expected); return null;
    case 'login_service_attach': {
      const ticket = login.capture(args.expected);
      const view = JSON.parse(await kernel.login_attach(args.pid, JSON.stringify(ticket.member), BigInt(ticket.generation), args.launch ? JSON.stringify(args.launch) : undefined, host));
      return login.checked(ticket, view);
    }
    case 'login_service_signal': return login.control('signal', { pid: args.pid, signal: args.signal }, args.expected);
    case 'reserve_memory': kernel.reserve_memory(args.pid, BigInt(args.bytes ?? 0), host); return null;
    case 'getcreds_proc': return JSON.parse(kernel.getcreds_proc(args.pid, host));
    case 'set_proc_cred': return JSON.parse(await kernel.set_proc_cred(args.pid, args.uid, args.gid ?? args.uid, new Uint32Array(args.groups ?? []), args.remote != null ? JSON.stringify(args.remote) : undefined, host));
    case 'attach_remote_device': return JSON.parse(await kernel.attach_remote_device(args.driver, args.pid ?? undefined, host));
    case 'detach_remote_device': kernel.detach_remote_device(args.driver); return null;
    case 'service_auth_hello': return JSON.parse(await kernel.service_auth_hello(args.versions ? JSON.stringify(args.versions) : undefined));
    case 'service_auth_attach': return JSON.parse(await kernel.service_auth_attach());
    case 'mint_remote_cred': return JSON.parse(await kernel.mint_remote_cred(args.pid, args.scope ? JSON.stringify(args.scope) : undefined, !!args.sudo, host));
    case 'detach_instance': return JSON.parse(await kernel.detach_instance());
    case 'exec':
      if (args.serviceGrant && !internal) throw { errno: 'EPERM' };
      return exec(args, tab, host);
    case 'execs':
      if (!internal && args.stages?.some(stage => stage.serviceGrant)) throw { errno: 'EPERM' };
      return execs(args, tab, host);
    // A process's own execve: its image replaced, its pid, credentials and descriptors kept.
    case 'reexec': return JSON.parse(await kernel.reexec(args.pid, JSON.stringify(args.local ?? null), args.path, JSON.stringify(args.argv ?? []), JSON.stringify(args.env ?? []), args.cwd ?? '/', tab ?? '', host));
    case 'fork': return JSON.parse(await kernel.fork(args.pid, host, args.emptyMemory === true));
    case 'session': return JSON.parse(await kernel.session(JSON.stringify(args.pids), host));
    case 'boot_init': return JSON.parse(await kernel.boot_init(JSON.stringify(args.owner), args.token, host));
    case 'process_call': return JSON.parse(await kernel.process_call(args.pid, JSON.stringify(args.call), host));
    case 'exit': return JSON.parse(await kernel.exit(args.pid, args.status ?? 0, args.signal ?? undefined, host));
    case 'wait': return JSON.parse(await kernel.wait(args.pid, host));
    // wait4 of a process for its children (`pid`, or any).
    case 'waitchild': return JSON.parse(await kernel.waitchild(args.ppid, args.pid ?? undefined, host));
    // kill(2): as the page's account, or `from` a process this port runs, as that process.
    case 'kill': return JSON.parse(await kernel.kill(args.pid, args.signal ?? undefined, args.from ?? undefined, host));
    case 'poll': return JSON.parse(await kernel.poll(JSON.stringify(args.pids ?? [])));
    case 'tty_fds': return kernel.terminal(args.pid, args.tty, JSON.stringify(args.fds), host);
    case 'sync': return JSON.parse(await kernel.sync(host, JSON.stringify(args?.acknowledged ?? {})));
    case 'getpid': return JSON.parse(await kernel.getpid(args.pid));
    case 'cgroup_create': return JSON.parse(await kernel.cgroup_create(args.path));
    case 'cgroup_set': return JSON.parse(await kernel.cgroup_set(args.path, args.key, args.value));
    case 'cgroup_attach': return JSON.parse(await kernel.cgroup_attach(args.pid, args.path));
    case 'cgroup_remove': return JSON.parse(await kernel.cgroup_remove(args.path));
    case 'cgroup_stat': return JSON.parse(await kernel.cgroup_stat(args.path));
    case 'cgroup_list': return JSON.parse(await kernel.cgroup_list(args.path ?? '/'));
    case 'cloud_renew': await kernel.cloud_renew(); return null;
    case 'boot_vfs': await kernel.boot_vfs(args.opts != null ? (typeof args.opts === 'string' ? args.opts : JSON.stringify(args.opts)) : undefined); return null;
    case 'session_begin': return await kernel.session_begin(args.sessionId, args.uid, args.gid ?? args.uid, new Uint32Array(args.groups ?? []));
    case 'set_active_session': kernel.set_active_session(args.sessionId ?? undefined); return null;
    case 'session_end': await kernel.session_end(args.sessionId); return null;
    case 'mount_user': return await kernel.mount_user(args.sessionId, typeof args.spec === 'string' ? args.spec : JSON.stringify(args.spec), args.hostObj);
    case 'unmount_user': await kernel.unmount_user(args.sessionId, args.target, args.flags ?? 0); return null;
    case 'revoke_mount_provider': kernel.revoke_mount_provider(args.sessionId, args.target); return null;
    case 'lose_mount_provider': kernel.lose_mount_provider(args.sessionId, args.target); return null;
    case 'export_provider': return kernel.export_provider(args.sessionId, args.path);
    case 'list_mounts': return await kernel.list_mounts(args.sessionId ?? '');
    case 'vfs_sys': return JSON.parse(await kernel.vfs_sys(args.sessionId ?? '', typeof args.batch === 'string' ? args.batch : JSON.stringify(args.batch), args.fdEpoch));
    case 'vfs_open_read': return await kernel.vfs_open_read(
      args.sessionId ?? '',
      args.path,
      args.rangeStart != null ? BigInt(args.rangeStart) : undefined,
      args.rangeEnd != null ? BigInt(args.rangeEnd) : undefined,
      !!args.headOnly,
      !!args.sudo,
    );
    case 'vfs_read_stream_chunk': return await kernel.vfs_read_stream_chunk(args.sessionId, args.streamId, args.maxBytes ?? undefined);
    case 'vfs_close_read_stream': await kernel.vfs_close_read_stream(args.sessionId, args.streamId); return null;
    case 'vfs_read_file': {
      const sid = args.sessionId ?? '';
      const first = await kernel.vfs_read_file(sid, args.path, 0n, args.headOnly ? 0 : (args.rangeStart != null ? 0 : 4 * 1024 * 1024));
      const totalSize = Number(first.stat?.size ?? 0);
      if (args.rangeStart != null) {
        const start = Number(args.rangeStart);
        if (start >= totalSize && totalSize > 0) return { status: 416, totalSize };
        if (start >= totalSize && totalSize === 0) return { status: 416, totalSize: 0 };
        const end = Math.min(totalSize - 1, args.rangeEnd != null ? Number(args.rangeEnd) : totalSize - 1);
        const contentRange = `bytes ${start}-${end}/${totalSize}`;
        if (args.headOnly) return { status: 206, totalSize, contentRange, bytes: new Uint8Array(0) };
        const want = end - start + 1;
        const out = new Uint8Array(want);
        let pos = 0;
        while (pos < want) {
          const step = Math.min(4 * 1024 * 1024, want - pos);
          const part = await kernel.vfs_read_file(sid, args.path, BigInt(start + pos), step);
          if (!part.bytes?.byteLength) break;
          out.set(part.bytes, pos);
          pos += part.bytes.byteLength;
        }
        return { status: 206, totalSize, contentRange, bytes: pos === want ? out : out.subarray(0, pos) };
      }
      if (args.headOnly) return { status: 200, totalSize, bytes: new Uint8Array(0) };
      if (totalSize <= first.bytes.byteLength) return { status: 200, totalSize, bytes: first.bytes };
      const out = new Uint8Array(totalSize);
      out.set(first.bytes, 0);
      let pos = first.bytes.byteLength;
      while (pos < totalSize) {
        const step = Math.min(4 * 1024 * 1024, totalSize - pos);
        const part = await kernel.vfs_read_file(sid, args.path, BigInt(pos), step);
        if (!part.bytes?.byteLength) break;
        out.set(part.bytes, pos);
        pos += part.bytes.byteLength;
      }
      return { status: 200, totalSize, bytes: pos === totalSize ? out : out.subarray(0, pos) };
    }
    case 'vfs_pwrite_chunk': {
      const r = await kernel.vfs_pwrite_chunk(
        args.sessionId ?? '',
        args.fd,
        BigInt(args.offset ?? 0),
        args.data instanceof Uint8Array ? args.data : new Uint8Array(args.data),
        args.chunkIndex != null ? BigInt(args.chunkIndex) : undefined,
      );
      return typeof r === 'number' ? r : (r?.written ?? 0);
    }
    case 'proc_spawn_init': {
      const opts = typeof args.opts === 'string' ? JSON.parse(args.opts) : args.opts;
      if (!internal && opts.serviceGrant != null) throw { errno: 'EPERM' };
      return await kernel.proc_spawn_init(JSON.stringify(opts));
    }
    case 'proc_authorize_service_grant': return kernel.proc_authorize_service_grant(args.pid);
    case 'proc_apply_service_grant':
      if (!internal) throw { errno: 'EPERM' };
      return await kernel.proc_apply_service_grant(args.pid, args.parentPid, typeof args.grant === 'string' ? args.grant : JSON.stringify(args.grant));
    case 'proc_fork': return kernel.proc_fork(args.parentPid, args.childPid, args.cloneFlags ?? 0);
    case 'proc_exec_preserve': await kernel.proc_exec_preserve(args.pid); return null;
    case 'proc_set_creds': kernel.proc_set_creds(args.pid, args.uid, args.gid, new Uint32Array(args.groups ?? []), args.token ?? undefined, args.cloudAccess !== false); return null;
    case 'proc_set_umask': return kernel.proc_set_umask(args.pid, args.umask);
    case 'proc_close_server_fds': await kernel.proc_close_server_fds(args.pid); return null;
    case 'proc_exit': await kernel.proc_exit(args.pid); return null;
    case 'sys_chdir': await kernel.sys_chdir(args.pid, args.path); return null;
    case 'sys_fchdir': await kernel.sys_fchdir(args.pid, args.kfd); return null;
    case 'sys_chroot': await kernel.sys_chroot(args.pid, args.path); return null;
    case 'sys_getcwd': return await kernel.sys_getcwd(args.pid);
    case 'sys_mount': await kernel.sys_mount(args.pid, args.source ?? undefined, args.target, args.fstype ?? undefined, BigInt(args.flags ?? 0), args.data ?? undefined); return null;
    case 'sys_umount2': await kernel.sys_umount2(args.pid, args.target, args.flags ?? 0); return null;
    case 'sys_statfs': return await kernel.sys_statfs(args.pid, args.dirfd ?? 0x7ffffffe, args.path);
    case 'sys_fstatfs': return await kernel.sys_fstatfs(args.pid, args.kfd);
    case 'sys_unshare': kernel.sys_unshare(args.pid, args.flags ?? 0); return null;
    case 'sys_setns': kernel.sys_setns(args.pid, args.kfd, args.nstype ?? 0); return null;
    case 'proc_openat': return await kernel.proc_openat(args.pid, args.dirfd, args.path, args.oflags ?? 0, args.mode ?? 0, !!args.cloexec);
    case 'proc_statat': return await kernel.proc_statat(args.pid, args.dirfd, args.path, args.follow !== false);
    case 'proc_accessat': await kernel.proc_accessat(args.pid, args.dirfd, args.path, args.amode ?? 0, args.follow !== false); return null;
    case 'proc_mkdirat': await kernel.proc_mkdirat(args.pid, args.dirfd, args.path, args.mode ?? 0o777); return null;
    case 'proc_mknodat': await kernel.proc_mknodat(args.pid, args.dirfd, args.path, args.mode, args.rdev ?? undefined); return null;
    case 'proc_unlinkat': await kernel.proc_unlinkat(args.pid, args.dirfd, args.path, !!args.removedir); return null;
    case 'proc_renameat': await kernel.proc_renameat(args.pid, args.olddirfd, args.oldpath, args.newdirfd, args.newpath, args.flags ?? 0); return null;
    case 'proc_linkat': await kernel.proc_linkat(args.pid, args.olddirfd, args.oldpath, args.newdirfd, args.newpath, !!args.follow); return null;
    case 'proc_symlinkat': await kernel.proc_symlinkat(args.pid, args.target, args.newdirfd, args.linkpath); return null;
    case 'proc_readlinkat': return await kernel.proc_readlinkat(args.pid, args.dirfd, args.path);
    case 'proc_utimensat': {
      const encodeTime = v => (typeof v === 'string' && (v.startsWith('"') || v.startsWith('{'))) ? v : JSON.stringify(v ?? 'now');
      await kernel.proc_utimensat(args.pid, args.dirfd, args.path, encodeTime(args.atime), encodeTime(args.mtime), args.follow !== false);
      return null;
    }
    case 'proc_sys': return JSON.parse(await kernel.proc_sys(args.pid, typeof args.batch === 'string' ? args.batch : JSON.stringify(args.batch)));
    case 'kfd_read': return await kernel.kfd_read(args.pid, args.kfd, args.len);
    case 'kfd_write': return await kernel.kfd_write(args.pid, args.kfd, args.data instanceof Uint8Array ? args.data : new Uint8Array(args.data));
    case 'kfd_pread': return await kernel.kfd_pread(args.pid, args.kfd, args.len, BigInt(args.offset ?? 0));
    case 'kfd_pwrite': return await kernel.kfd_pwrite(args.pid, args.kfd, args.data instanceof Uint8Array ? args.data : new Uint8Array(args.data), BigInt(args.offset ?? 0));
    case 'kfd_seek': return (await kernel.kfd_seek(args.pid, args.kfd, BigInt(args.offset ?? 0), args.whence ?? 0)).toString();
    case 'kfd_readdir': return await kernel.kfd_readdir(args.pid, args.kfd);
    case 'kfd_fstat': return await kernel.kfd_fstat(args.pid, args.kfd);
    case 'kfd_ftruncate': await kernel.kfd_ftruncate(args.pid, args.kfd, BigInt(args.size ?? 0)); return null;
    case 'kfd_futimens': {
      const encodeTime = v => (typeof v === 'string' && (v.startsWith('"') || v.startsWith('{'))) ? v : JSON.stringify(v ?? 'now');
      await kernel.kfd_futimens(args.pid, args.kfd, encodeTime(args.atime), encodeTime(args.mtime));
      return null;
    }
    case 'kfd_fsync': await kernel.kfd_fsync(args.pid, args.kfd, !!args.dataOnly); return null;
    case 'kfd_set_append': kernel.kfd_set_append(args.pid, args.kfd, !!args.append); return null;
    case 'kfd_is_append': return kernel.kfd_is_append(args.pid, args.kfd);
    case 'kfd_lock': await kernel.kfd_lock(args.pid, args.kfd, args.family, args.kind, BigInt(args.start ?? 0), args.end != null ? BigInt(args.end) : undefined, !!args.wait); return null;
    case 'kfd_cancel': kernel.kfd_cancel(args.pid, args.kfd); return null;
    case 'kfd_unlock': await kernel.kfd_unlock(args.pid, args.kfd, args.family, BigInt(args.start ?? 0), args.end != null ? BigInt(args.end) : undefined); return null;
    case 'kfd_test_lock': return await kernel.kfd_test_lock(args.pid, args.kfd, args.kind, BigInt(args.start ?? 0), args.end != null ? BigInt(args.end) : undefined);
    case 'kfd_dup': return kernel.kfd_dup(args.pid, args.kfd);
    case 'kfd_dup2': return await kernel.kfd_dup2(args.pid, args.oldKfd, args.newKfd);
    case 'kfd_set_cloexec': kernel.kfd_set_cloexec(args.pid, args.kfd, !!args.cloexec); return null;
    case 'kfd_is_cloexec': return kernel.kfd_is_cloexec(args.pid, args.kfd);
    case 'kfd_close': await kernel.kfd_close(args.pid, args.kfd); return null;
    case 'pty_register': kernel.pty_register(args.index, args.uid ?? 0, args.gid ?? 0, args.mode ?? 0o600); return null;
    case 'pty_close': return kernel.pty_close(args.index);
    case 'proc_resolve_exec': return await kernel.proc_resolve_exec(args.pid, args.file, typeof args.argv === 'string' ? args.argv : JSON.stringify(args.argv ?? []), args.pathEnv ?? undefined, !!args.searchPath);
    case 'session_resolve_exec': return await kernel.session_resolve_exec(args.sessionId ?? '', args.file, typeof args.argv === 'string' ? args.argv : JSON.stringify(args.argv ?? []), args.cwd ?? '/', args.pathEnv ?? undefined, !!args.searchPath, !!args.sudo);
    case 'release_exec_ticket': kernel.release_exec_ticket(args.ticket); return null;
    case 'take_local_exec_bytes': return kernel.take_local_exec_bytes(args.ticket ?? args.digest, args.checkOnly);
    default: throw { errno: 'ENOSYS', detail: `no client-kernel call ${type}` };
  }
}

const isConcurrentCall = type => (
  type.startsWith('cloud_') ||
  type.startsWith('kfd_') ||
  type.startsWith('proc_') ||
  type.startsWith('sys_') ||
  type.startsWith('vfs_') ||
  type.startsWith('pty_') ||
  type.startsWith('session_') ||
  (type.startsWith('login_') && type !== 'login_service_attach') ||
  type.startsWith('machine_init_') ||
  [
    'boot_vfs', 'set_active_session', 'mount_user', 'unmount_user',
    'revoke_mount_provider', 'lose_mount_provider', 'export_provider',
    'list_mounts', 'take_local_exec_bytes', 'release_exec_ticket',
  ].includes(type)
);

async function handle(port, message) {
  if (message?.type === 'hello') {
    const versions = Array.isArray(message.versions) ? message.versions : [];
    const boundary = message.boundary ?? 'host-adapter';
    if (boundary !== 'host-adapter' || !versions.includes(VERSION)) {
      const err = { errno: 'EPROTONOSUPPORT', detail: `HostAdapter v${VERSION} required` };
      port.postMessage({ v: VERSION, id: message.id, err });
      port.postMessage({ v: VERSION, type: 'event', event: 'protocol-mismatch', value: { boundary: 'host-adapter', ...err } });
      return;
    }
    port.postMessage({ v: VERSION, id: message.id, ok: { boundary: 'host-adapter', version: VERSION } });
    return;
  }
  if (message?.v !== VERSION) {
    const err = { errno: 'EPROTONOSUPPORT', detail: `HostAdapter v${VERSION} required (received v${message?.v})` };
    port.postMessage({ v: VERSION, id: message?.id, err });
    port.postMessage({ v: VERSION, type: 'event', event: 'protocol-mismatch', value: { boundary: 'host-adapter', ...err } });
    return;
  }
  ports.add(port);
  // A port's authority is an identity of its own, not the tab it names: another port that says
  // the same tab is still another host. The tab it first said it was cannot change.
  if (!hosts.has(port)) hosts.set(port, {
    id: `port-${self.crypto?.randomUUID?.() ?? Math.random()}`,
    tab: message.tab,
  });
  const host = hosts.get(port);
  if (message.tab != null) {
    if (host.tab == null) host.tab = message.tab;
    else if (message.tab !== host.tab) {
      port.postMessage({ v: VERSION, id: message.id, err: { errno: 'EPERM', detail: 'a port speaks for the tab it first said it was' } });
      return;
    }
  }
  try {
    self.kernel = kernel;
    self.kernelRequest = async (type, args) => {
      const run = () => dispatch({ type, args }, host.id, host.tab, true);
      return await (isConcurrentCall(type) ? run() : serially(run)).catch(error => {
        const refused = failure(error);
        throw Object.assign(new Error(refused.detail ?? refused.errno), refused);
      });
    };
    try { await boot(); self.kernel = kernel; } catch (error) {
      if (message.type === 'mount_overlay') {
        port.postMessage({ v: VERSION, id: message.id, ok: null }); return;
      }
      throw error;
    }
    let value;
    if (message.type === 'run' || message.type.startsWith('mount_') || message.type.startsWith('run_') || message.type.startsWith('console_') || message.type.startsWith('attachment_') || message.type.startsWith('seat_') || ['deliver_signal', 'reconcile'].includes(message.type)) {
      const executor = await import(asset('/executor-host.js'));
      if (message.type === 'console_grant') await login.tick();
      executor.setSharingPolicy(() => login.current());
      value = await executor.request(message.type, message.args ?? {}, value => port.postMessage({ v: VERSION, type: 'event', event: message.type.startsWith('attachment_') ? 'attachment' : 'run', value }), value => broadcast({ v: VERSION, type: 'event', event: 'seat', value }));
    } else if (isConcurrentCall(message.type)) value = await dispatch(message, host.id, host.tab);
    else value = await serially(() => dispatch(message, host.id, host.tab));
    port.postMessage({ v: VERSION, id: message.id, ok: value });
  } catch (error) {
    port.postMessage({ v: VERSION, id: message.id, err: failure(error) });
  }
}

// Exactly one host owns this dedicated Worker instance.
self.onmessage = ({ data }) => handle(self, data);
// Renew remote ServiceAuth v2 & CloudFs leases only when this instance has attached remotely.
setInterval(() => { if (kernel) void kernel.cloud_renew().catch(() => {}); }, 30000);

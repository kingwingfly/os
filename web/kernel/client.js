import { asset } from '../release.js';
// The client kernel: a classic worker, so it can importScripts the no-modules wasm-bindgen
// build, with the Rust kernel (crates/client-kernel) holding the processes its tabs host and
// their tokens. Each tab owns a dedicated Worker, which owns its process Workers and pipes.
// The page communicates through messages. Its requests go to the browser's machine (a Durable Object of
// its own, by a batch marked X-Registry). The machine verifies account identity with the
// authority for tokenless batches; process-token calls use their stored snapshot.
// Forks await registry admission before the child runs. Exits and waits are batched with
// the next request or a moment after. Requests run serially so pending exit/wait reports
// reach the registry before another fork asks for capacity.
//
// Each tab holds a Web Lock, `tw-tab-<tab>`, for as long as it lives (web/kernel/protocol.js),
// and each process says which tab runs it (its seat). A process whose seat's lock is free was
// left by a tab that closed, crashed or reloaded while it ran: the kernel reaps it, at once
// where it waits on that tab's lock, and at boot, or when the namespace has no room for another
// process, by asking which locks are held. Each kernel holds one too, `tw-kernel-<id>`: the pids
// a kernel that is gone was lent go back the same way.
//
// A process is its host's: the port that executed it, under an identity of the port's own (not
// the tab it said it was, whose lock any same-origin page can see). Only that port forks it,
// replaces its image, ends it, waits for its children, or signals as it; another tab's page
// learns nothing of its token.
importScripts(asset('/client_kernel.js'));

const VERSION = 1;
const ports = new Set();
const locks = self.navigator?.locks;
// The tabs waited on, by seat.
let kernel;
let starting;
let login, machineInit;
// This kernel's id, and the lock it holds of it while it runs.
const kernelId = self.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`;
const kernelLock = id => `tw-kernel-${id}`;
if (locks) void locks.request(kernelLock(kernelId), () => new Promise(() => {})).catch(() => {});
// Each port's host: an identity of its own, made here, and the tab it first said it was. A tab
// id is a Web Lock's name, which any same-origin page can read: it says whose lock ends the
// port's processes, never which port owns them.
const hosts = new WeakMap();
// What the kernel does, one thing at a time.
let queue = Promise.resolve();
const serially = task => {
  const done = queue.then(task);
  queue = done.catch(() => {});
  return done;
};
// What happened here goes to the machine a moment after, if nothing took it sooner: the
// exits and waits of a pipeline's stages, which end together, go together.
const REPORT_AFTER = 25;
let reporting = null;
function report() {
  if (!kernel?.pending()) return reporting ?? Promise.resolve();
  reporting ??= new Promise(resolve => setTimeout(resolve, REPORT_AFTER))
    .then(() => serially(() => kernel.flush()))
    .catch(() => {})
    .finally(() => { reporting = null; void report(); });
  return reporting;
}
// Once the machine heard what happened here so far (a few tries, if it cannot be reached).
async function heard() {
  const mine = kernel.queued();
  for (let tries = 0; kernel.reported() < mine && tries < 5; tries++) await report();
}

// The Rust kernel's transport: one POST to the browser's machine, its status and text.
// Same-origin, so the browser's cookies go with it; the kernel never sees them.
self.kernelSys = async (body, signal) => {
  const response = await fetch('/api/sys', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Registry': '1' },
    body,
    signal,
  });
  return JSON.stringify({ status: response.status, text: await response.text() });
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

self.imageBlobRead = async (blobId, offset, len) => {
  const start = Number(offset);
  const count = Number(len);
  if (count <= 0) return new Uint8Array(0);
  const url = blobId.startsWith('sha256:')
    ? `/boot/blobs/${blobId.slice(7)}`
    : asset(blobId.startsWith('/') ? blobId : `/${blobId}`);
  const response = await fetch(url);
  if (response.status === 404) throw { errno: 'ENOENT' };
  if (!response.ok) throw { errno: 'EIO' };
  const full = new Uint8Array(await response.arrayBuffer());
  if (start === 0 && count >= full.length) return full;
  if (start >= full.length) return new Uint8Array(0);
  return full.subarray(start, start + count);
};

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
    // A dedicated kernel never resets the namespace on boot; locks and leases reclaim it.
    const id = '';
    kernel = new wasm_bindgen.Kernel(id, locks ? kernelId : '');
    const value = JSON.parse(await kernel.init());
    const [{ LoginCoordinator, LoginStartup }, { InitCoordinator, InitReaper }] = await Promise.all([import(asset('/login-session.js')), import(asset('/init-owner.js'))]);
    const proof = [...crypto.getRandomValues(new Uint8Array(32))].map(byte => byte.toString(16).padStart(2, '0')).join('');
    login = new LoginCoordinator({ host: kernelId, proof,
      changed: value => {
        login.startup?.update(value);
        broadcast({ v: VERSION, type: 'event', event: 'login', value: { ...value, services: login.startup?.current(value) } });
      },
      call: async action => {
        const answer = JSON.parse(await self.kernelSys(JSON.stringify({ calls: [{ login_session: { action } }] }), AbortSignal.timeout(10000)));
        if (answer.status !== 200) throw { errno: 'EIO', detail: 'login coordinator is unavailable' };
        const result = JSON.parse(answer.text).results[0];
        if (result.err) throw result.err;
        return result.ok;
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
            // Graceful shutdown targets the supervisor, which owns dependency/group policy.
            // Its original process proof remains valid after cookie logout.
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
        const answer = JSON.parse(await self.kernelSys(JSON.stringify({ calls: [{ machine_init: { action } }] }), AbortSignal.timeout(10000)));
        if (answer.status !== 200) throw { errno: 'EIO', detail: 'init coordinator is unavailable' };
        const result = JSON.parse(answer.text).results[0];
        if (result.err) throw result.err;
        return result.ok;
      },
    });
    machineInit.reaper = new InitReaper({
      token: () => [...crypto.getRandomValues(new Uint8Array(32))].map(byte => byte.toString(16).padStart(2, '0')).join(''),
      release: owner => machineInit.call({ op: 'release', owner }),
      exhausted: () => { void machineInit.stop(); },
      changed: () => broadcast({ v: VERSION, type: 'event', event: 'machine_init',
        value: { ...machineInit.current(), reaper: machineInit.reaper.current() } }),
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
    void machineInit.tick();
    void login.tick();
    broadcast({ v: VERSION, type: 'event', event: 'started', value });
    void serially(() => reapGone()).catch(() => {});
    return value;
  }).catch(error => {
    // A boot that failed (offline, a 5xx) is tried again by the next request, not kept as
    // every tab's answer for as long as this worker lives.
    kernel = undefined;
    starting = undefined;
    throw error;
  });
  return starting;
}

function broadcast(message) {
  for (const port of ports) port.postMessage(message);
}

// The lock a tab holds while it lives.
const tabLock = seat => `tw-tab-${seat}`;
// Reap the processes whose tab is gone: those of `seat`, or of any seat whose lock is free.
// The machine ends them as SIGKILL would, and init reaps them. The pids lent to kernels whose
// lock is free go back.
async function reapGone(seat) {
  if (!locks || !kernel) return;
  if (seat) { await kernel.gone(seat); return; }
  const held = new Set(((await locks.query()).held ?? []).map(lock => lock.name));
  const { seats = [], kernels = [] } = JSON.parse(await kernel.seats());
  for (const running of seats) {
    if (!held.has(tabLock(running))) await kernel.gone(running);
  }
  for (const lender of kernels) {
    if (lender !== kernelId && !held.has(kernelLock(lender))) await kernel.reclaim(lender);
  }
}
// execve of a pipeline's stages, in one request, as the tab `seat` asks it: each stage's
// process, or its error. Where the namespace has no room (EAGAIN), what gone tabs left is
// reaped, and it is asked once more.
async function execs(args, seat, host) {
  const stages = (args.stages ?? []).map(stage => ({
    path: stage.path,
    local: stage.local,
    runtime: stage.runtime,
    parentPid: stage.parentPid,
    sessionId: stage.sessionId,
    serviceGrant: stage.serviceGrant,
    argv: stage.argv ?? [],
    env: stage.env ?? [],
    cwd: stage.cwd ?? '/',
    cgroup: stage.cgroup ?? '',
  }));
  const call = async () => JSON.parse(await kernel.execs(JSON.stringify(stages), !!args.sudo, seat ?? '', host));
  const results = await call();
  if (!locks || !results.some(result => result.err?.errno === 'EAGAIN')) return results;
  // The stages that were given processes give them back before the pipeline is asked again.
  for (const result of results) {
    if (!result.ok) continue;
    try { await kernel.exit(result.ok.pid, 126, undefined, host); await kernel.wait(result.ok.pid, host); } catch { /* gone already */ }
  }
  await reapGone();
  return call();
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
    return { errno: error.errno, detail: error.detail ?? error.message ?? error.errno };
  }
  return { errno: 'EIO', detail: String(error?.message ?? error) };
}

async function dispatch(message, host, tab) {
  const { type, args = {} } = message;
  switch (type) {
    case 'init': return boot();
    case 'version': return kernel.version();
    case 'namespace': return kernel.namespace();
    case 'workspace_credentials': {
      const response = await fetch('/api/sys', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ calls: ['getcreds'] }) });
      if (!response.ok) throw { errno: 'EACCES' };
      return (await response.json()).results?.[0]?.ok;
    }
    case 'machine_init_status': return { ...machineInit.current(), reaper: machineInit.reaper.current() };
    case 'machine_init_resume': return machineInit.resume();
    case 'machine_init_leave': await machineInit.stop(); return null;
    case 'machine_reboot': {
      const value = await machineInit.call({ op: 'reboot', boot: args.boot });
      await machineInit.resume(); return value;
    }
    case 'machine_inspect': return machineInit.call({ op: 'inspect' });
    case 'login_lifecycle': {
      if (!['end', 'restart', 'inspect'].includes(args.op)) throw { errno: 'EINVAL' };
      const value = await login.call({ op: args.op, ...(args.op === 'inspect' ? {} : { session: args.session }) });
      if (args.op !== 'inspect') (await import(asset('/executor-host.js'))).endWorkspace(args.session);
      if (args.op !== 'inspect') await login.reset();
      return value;
    }
    case 'login_status': { const value = login.current(); return { ...value, services: login.startup.current(value) }; }
    case 'login_configure': return login.control('configure', { file: args.file }, args.expected);
    case 'login_seat_policy': {
      const value = await login.call({ op: 'seat_policy', session: args.session, expected: args.expected, sharing: args.sharing });
      await login.tick();
      const executor = await import(asset('/executor-host.js'));
      executor.setSharingPolicy(() => login.current());
      return value;
    }
    case 'login_refresh': return login.reset();
    case 'login_leave': await login.stop(); return null;
    case 'login_service_check': login.capture(args.expected); return null;
    case 'login_service_attach': {
      const ticket = login.capture(args.expected);
      const view = JSON.parse(await kernel.login_attach(args.pid, JSON.stringify(ticket.member), BigInt(ticket.generation), args.launch ? JSON.stringify(args.launch) : undefined, host));
      return login.checked(ticket, view);
    }
    case 'login_service_signal': return login.control('signal', { pid: args.pid, signal: args.signal }, args.expected);
    case 'exec': return exec(args, tab, host);
    case 'execs': return execs(args, tab, host);
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
    case 'vfs_sys': return JSON.parse(await kernel.vfs_sys(args.sessionId ?? '', typeof args.batch === 'string' ? args.batch : JSON.stringify(args.batch)));
    case 'vfs_open_read': return await kernel.vfs_open_read(
      args.sessionId ?? '',
      args.path,
      args.rangeStart != null ? BigInt(args.rangeStart) : undefined,
      args.rangeEnd != null ? BigInt(args.rangeEnd) : undefined,
      !!args.headOnly,
      !!args.sudo,
    );
    case 'vfs_read_stream_chunk': return await kernel.vfs_read_stream_chunk(args.streamId, args.maxBytes ?? undefined);
    case 'vfs_close_read_stream': await kernel.vfs_close_read_stream(args.streamId); return null;
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
    case 'proc_spawn_init': return await kernel.proc_spawn_init(typeof args.opts === 'string' ? args.opts : JSON.stringify(args.opts));
    case 'proc_apply_service_grant': return await kernel.proc_apply_service_grant(args.pid, args.parentPid, typeof args.grant === 'string' ? args.grant : JSON.stringify(args.grant));
    case 'proc_fork': return kernel.proc_fork(args.parentPid, args.childPid, args.cloneFlags ?? 0);
    case 'proc_exec_preserve': await kernel.proc_exec_preserve(args.pid); return null;
    case 'proc_set_creds': kernel.proc_set_creds(args.pid, args.uid, args.gid, new Uint32Array(args.groups ?? []), args.token ?? undefined, args.cloudAccess !== false); return null;
    case 'proc_set_umask': return kernel.proc_set_umask(args.pid, args.umask);
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
    case 'proc_utimensat': await kernel.proc_utimensat(args.pid, args.dirfd, args.path, typeof args.atime === 'string' ? args.atime : JSON.stringify(args.atime), typeof args.mtime === 'string' ? args.mtime : JSON.stringify(args.mtime), args.follow !== false); return null;
    case 'proc_sys': return JSON.parse(await kernel.proc_sys(args.pid, typeof args.batch === 'string' ? args.batch : JSON.stringify(args.batch)));
    case 'kfd_read': return await kernel.kfd_read(args.pid, args.kfd, args.len);
    case 'kfd_write': return await kernel.kfd_write(args.pid, args.kfd, args.data instanceof Uint8Array ? args.data : new Uint8Array(args.data));
    case 'kfd_pread': return await kernel.kfd_pread(args.pid, args.kfd, args.len, BigInt(args.offset ?? 0));
    case 'kfd_pwrite': return await kernel.kfd_pwrite(args.pid, args.kfd, args.data instanceof Uint8Array ? args.data : new Uint8Array(args.data), BigInt(args.offset ?? 0));
    case 'kfd_seek': return (await kernel.kfd_seek(args.pid, args.kfd, BigInt(args.offset ?? 0), args.whence ?? 0)).toString();
    case 'kfd_readdir': return await kernel.kfd_readdir(args.pid, args.kfd);
    case 'kfd_fstat': return await kernel.kfd_fstat(args.pid, args.kfd);
    case 'kfd_ftruncate': await kernel.kfd_ftruncate(args.pid, args.kfd, BigInt(args.size ?? 0)); return null;
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
    'list_mounts', 'take_local_exec_bytes',
  ].includes(type)
);

async function handle(port, message) {
  if (message?.v !== VERSION) {
    port.postMessage({ v: VERSION, id: message?.id, err: { errno: 'EPROTO', detail: `client kernel speaks version ${VERSION}` } });
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
  if (message.tab != null && message.tab !== host.tab) {
    port.postMessage({ v: VERSION, id: message.id, err: { errno: 'EPERM', detail: 'a port speaks for the tab it first said it was' } });
    return;
  }
  // This kernel goes with its tab; other kernels and the Machine lease reclaim what it leaves.
  try {
    self.kernel = kernel;
    self.kernelRequest = async (type, args) => {
      const run = () => dispatch({ type, args }, host.id, host.tab);
      const answer = await (isConcurrentCall(type) ? run() : serially(run)).catch(error => {
        const refused = failure(error);
        throw Object.assign(new Error(refused.detail ?? refused.errno), refused);
      });
      if (type === 'wait' || type === 'waitchild') await heard();
      void report();
      return answer;
    };
    try { await boot(); self.kernel = kernel; } catch (error) {
      // An optional root-listing overlay must not prevent ordinary filesystem
      // access before this execution host boots. No call has been dispatched.
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
    // A wait answers once the machine heard of it, so that /proc agrees.
    if (message.type === 'wait' || message.type === 'waitchild') await heard();
    port.postMessage({ v: VERSION, id: message.id, ok: value });
  } catch (error) {
    port.postMessage({ v: VERSION, id: message.id, err: failure(error) });
  }
  void report();
}

// Exactly one host owns this worker. SharedWorker is not part of process execution.
self.onmessage = ({ data }) => handle(self, data);
setInterval(() => { if (kernel) void serially(() => reapGone()).catch(() => {}); }, 10000);
setInterval(() => { if (login) void login.tick(); if (machineInit) void machineInit.tick(); }, 5000);
setInterval(() => { if (kernel) void kernel.cloud_renew().catch(() => {}); }, 30000);

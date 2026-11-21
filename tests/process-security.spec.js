import { test, expect } from './test.js';
import { readFile } from 'node:fs/promises';
import binaryen from 'binaryen';
import { api, call as syscall, put, rmrf } from './sys.js';

const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const rootPassword = process.env.OS_TEST_ADMIN_PASSWORD || (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const sleep = { path: '/usr/bin/coreutils', argv: ['coreutils', 'sleep', '60'], env: [], cwd: '/' };
const ROOT_ACCOUNT = { uid: 0, gid: 0, groups: [0], user: 'root', group: 'root', home: '/root', shell: '/usr/bin/dash', signed_in: true };
const GUEST_ACCOUNT = { uid: 65534, gid: 65534, groups: [65534], user: 'guest', group: 'guest', home: '/tmp', shell: '/usr/bin/dash', signed_in: false };

let sequence = 0;
async function login(request) {
  const response = await api(request, 'login', {
    headers: { 'CF-Connecting-IP': `process-security-${Date.now()}-${++sequence}` },
    data: { username: 'root', password: rootPassword },
  });
  expect(response.ok()).toBe(true);
}

// A separate dedicated client-kernel Worker per page (HostAdapter v2).
async function connect(page, { tab, hold = false } = {}) {
  await page.evaluate(async ({ tab, hold }) => {
    if (hold) await new Promise(resolve => {
      void navigator.locks.request(`tw-tab-${tab}`, () => { resolve(); return new Promise(() => {}); });
    });
    const port = new Worker('/client-kernel.js');
    const pending = new Map();
    let next = 0;
    port.onmessage = ({ data }) => {
      if (!pending.has(data?.id)) return;
      pending.get(data.id)(data);
      pending.delete(data.id);
    };
    port.start?.();
    window.securityKernel = (type, args) => new Promise(resolve => {
      const id = ++next;
      pending.set(id, resolve);
      port.postMessage({ v: 2, id, type, args, tab });
    });
  }, { tab, hold });
  value(await kernel(page, 'init'));
}
const kernel = (page, type, args = {}) => page.evaluate(([type, args]) => window.securityKernel(type, args), [type, args]);
function value(reply) {
  expect(reply.err, JSON.stringify(reply.err)).toBeUndefined();
  return reply.ok;
}

async function batch(page, calls, options = {}, extraHeaders = {}) {
  return page.evaluate(async ({ calls, options, extraHeaders }) => {
    const response = await fetch('/api/sys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...extraHeaders },
      body: JSON.stringify({ calls, ...options }),
    });
    return { status: response.status, ok: response.ok, body: await response.json().catch(() => ({})) };
  }, { calls, options, extraHeaders });
}

test('signal queues survive missed events, monotonic acks cannot clear newer signals, and SIGKILL revokes remote creds immediately', async ({ page, context }) => {
  await page.goto('/');
  await connect(page);
  await login(context.request);
  value(await kernel(page, 'sync_account', ROOT_ACCOUNT));
  const instanceId = value(await kernel(page, 'instance_id'));
  const proc = value(await kernel(page, 'exec', { ...sleep, remote: true }));
  expect(proc.token).toMatch(/^[0-9a-f]{64}$/);
  const poll = async () => value(await kernel(page, 'sync')).find(row => row.pid === proc.pid);
  const kill = signal => kernel(page, 'kill', { pid: proc.pid, signal });
  try {
    value(await kill(0));
    expect((await poll()).pending_signals ?? []).toEqual([]);
    expect((await kill(32)).err?.errno).toBe('EINVAL');

    // Standard signals coalesce in order; repeated poll preserves unacknowledged queue.
    value(await kill(10));
    value(await kill(10));
    value(await kill(15));
    const queued = await poll();
    expect(queued.state).toBe('running');
    expect(queued.pending_signals.map(event => event.signal)).toEqual([10, 15]);
    expect((await poll()).pending_signals).toEqual(queued.pending_signals);
    const sequences = queued.pending_signals.map(event => event.sequence);

    // Acknowledging clears delivered sequences.
    expect(value(await kernel(page, 'sync', { acknowledged: { [proc.pid]: sequences } }))
      .find(row => row.pid === proc.pid).pending_signals ?? []).toEqual([]);

    // A new delivery of the same signal cannot be cleared by an older acknowledgement sequence.
    value(await kill(10));
    const fresh = value(await kernel(page, 'sync', { acknowledged: { [proc.pid]: sequences } }))
      .find(row => row.pid === proc.pid);
    expect(fresh.pending_signals[0].sequence).toBeGreaterThan(Math.max(...sequences));

    value(await kill(19));
    value(await kill(18));
    const resumed = await poll();
    expect(resumed.state).toBe('running');
    expect(resumed.pending_signals.map(event => event.signal)).toEqual([10, 18]);

    // Logout changes the instance's ambient account to guest: cross-uid kill fails EPERM,
    // while the running root process keeps its stored credentials & pending signals.
    expect((await api(context.request, 'logout')).ok()).toBe(true);
    value(await kernel(page, 'sync_account', GUEST_ACCOUNT));
    expect((await kill(12)).err?.errno).toBe('EPERM');
    expect((await kernel(page, 'getcreds_proc', { pid: proc.pid })).ok.uid).toBe(0);

    // Re-authenticate as root and send SIGKILL -> immediate zombie + immediate remote token revocation.
    await login(context.request);
    value(await kernel(page, 'sync_account', ROOT_ACCOUNT));
    value(await kill(9));
    expect((await poll()).state).toBe('zombie');
    const revokedSys = await batch(page, ['getcreds'], { pid: proc.pid, proc: proc.token }, { 'X-OS-Instance': instanceId });
    expect(revokedSys.body.results?.[0]?.err?.errno).toBe('EPERM');
    const revokedFs = await (await context.request.post(origin + '/api/fs', {
      headers: { Origin: origin, 'X-OS-Instance': instanceId },
      data: { version: 2, credential: proc.token, session: null, call: 'connect' },
    })).json();
    expect(['EACCES', 'EPERM']).toContain(revokedFs.errno);
  } finally {
    await login(context.request);
    value(await kernel(page, 'sync_account', ROOT_ACCOUNT));
    await kernel(page, 'exit', { pid: proc.pid, status: 0 });
    await kernel(page, 'wait', { pid: proc.pid });
  }
});

test('retired server registry routes, X-Registry header, and forged ServiceAuth proofs fail closed', async ({ page, context }) => {
  await page.goto('/login');
  await login(context.request);

  // X-Registry header is unconditionally rejected (403 EPERM).
  const regHeader = await batch(page, ['getcreds'], {}, { 'X-Registry': '1' });
  expect(regHeader.status).toBe(403);
  expect(regHeader.body.errno).toBe('EPERM');

  // Every retired server-side registry Call fails closed on /api/sys.
  const retiredCalls = [
    { proc_init: { boot: 'untrusted-reset' } },
    'seats',
    { gone: { seat: '' } },
    { execve: sleep },
    { fork: { pid: 1 } },
    { exit: { status: 0 } },
    { pids: { count: 2 } },
    { proc_keep: { processes: [] } },
    { machine_init: { action: { op: 'inspect' } } },
    { login_session: { action: { op: 'inspect' } } },
  ];
  for (const call of retiredCalls) {
    const res = await batch(page, [call]);
    expect(res.ok, JSON.stringify(call)).toBe(false);
  }

  // Forged instance_id / host_proof on /api/service-auth fail closed with EACCES.
  const forged = await context.request.post(origin + '/api/service-auth', {
    headers: { Origin: origin, 'Content-Type': 'application/json' },
    data: {
      mint_service_cred: {
        instance_id: 'inst-forged-0000',
        host_proof: 'f'.repeat(64),
      },
    },
  });
  expect(forged.ok()).toBe(false);
  expect((await forged.json()).errno).toBe('EACCES');
});

test('a rejected sudo launch does not block local exit, wait, or remote token revocation', async ({ page, context }) => {
  await page.goto('/login');
  await connect(page);
  await login(context.request);
  value(await kernel(page, 'sync_account', ROOT_ACCOUNT));
  const instanceId = value(await kernel(page, 'instance_id'));
  const proc = value(await kernel(page, 'exec', { ...sleep, remote: true }));
  try {
    expect((await api(context.request, 'logout')).ok()).toBe(true);
    value(await kernel(page, 'sync_account', GUEST_ACCOUNT));
    // Rejected sudo exec fails without affecting local process exit/wait.
    const denied = await kernel(page, 'exec', { ...sleep, sudo: true });
    expect(denied.err).toBeTruthy();

    value(await kernel(page, 'exit', { pid: proc.pid, status: 3 }));
    // F3-02: A signed-out guest cannot reap root's PID 1 child; root still can.
    expect((await kernel(page, 'wait', { pid: proc.pid })).err?.errno).toBe('EPERM');

    // Exiting the last local holder revoked its remote token even after logout.
    const revokedFs = await (await context.request.post(origin + '/api/fs', {
      headers: { Origin: origin, 'X-OS-Instance': instanceId },
      data: { version: 2, credential: proc.token, session: null, call: 'connect' },
    })).json();
    expect(['EACCES', 'EPERM']).toContain(revokedFs.errno);

    // Restoring root allows reaping the exited root child cleanly.
    value(await kernel(page, 'sync_account', ROOT_ACCOUNT));
    const waited = value(await kernel(page, 'wait', { pid: proc.pid }));
    expect(waited).toMatchObject({ pid: proc.pid, status: 3 << 8 });
  } finally {
    await login(context.request);
  }
});

// Wait for the test to switch the page's account, then call the real WASIX proc_signal.
// Its WASI errno is the exit status: EPERM = 63; success = 0.
function signalProgram(pid) {
  const module = binaryen.parseText(`(module
    (import "wasi_snapshot_preview1" "fd_read" (func $read (param i32 i32 i32 i32) (result i32)))
    (import "wasix_32v1" "proc_signal" (func $signal (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
    (memory (export "memory") 1)
    (func (export "_start")
      (i32.store (i32.const 0) (i32.const 64))
      (i32.store (i32.const 4) (i32.const 1))
      (drop (call $read (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 8)))
      (call $exit (call $signal (i32.const ${pid}) (i32.const 9)))))`);
  try { return Buffer.from(module.emitBinary()); } finally { module.dispose(); }
}

async function hookPageKernel(page) {
  await page.addInitScript(() => {
    const NativeWorker = window.Worker;
    window.Worker = class extends NativeWorker {
      constructor(url, options) {
        super(url, options);
        if (new URL(url, location.href).pathname.endsWith('/client-kernel.js')) {
          const worker = this;
          const pending = new Map();
          let next = 900_000;
          worker.addEventListener('message', ({ data }) => {
            if (data?.id != null && pending.has(data.id)) {
              pending.get(data.id)(data);
              pending.delete(data.id);
            }
          });
          window.__pageKernel = (type, args = {}) => new Promise(resolve => {
            const id = ++next;
            pending.set(id, resolve);
            worker.postMessage({ v: 2, id, type, args });
          });
        }
      }
    };
  });
}

for (const startsRoot of [false, true]) {
  test(`proc_signal keeps the process's ${startsRoot ? 'root credentials after logout' : 'guest credentials after root login'}`, async ({ page, context }) => {
    await hookPageKernel(page);
    await login(context.request);
    await page.goto('/');
    await page.waitForFunction(() => !!window.os?.exec && !!window.__pageKernel);
    await page.evaluate(() => dispatchEvent(new Event('os:login-changed')));
    await expect.poll(async () => (await page.evaluate(() => window.os.loginSession())).session?.uid).toBe(0);

    // Start a root target process inside THIS page's kernel instance.
    await page.evaluate(() => {
      window.targetRun = window.os.exec([{ path: '/usr/bin/coreutils', argv: ['coreutils', 'sleep', '60'] }], {
        stdin: '',
        onJob: job => { window.targetJob = job; },
      });
    });
    await page.waitForFunction(() => window.targetJob?.pids?.length === 1);
    const targetPid = await page.evaluate(() => window.targetJob.pids[0]);

    const path = `/guest/proc-signal-${Date.now()}-${++sequence}.wasm`;
    try {
      expect((await put(context.request, `/api/file?path=${path}`, { data: signalProgram(targetPid) })).ok()).toBe(true);
      await syscall(context.request, { chmod: { path, mode: 0o755 } });
      if (!startsRoot) {
        expect((await api(context.request, 'logout')).ok()).toBe(true);
        await page.evaluate(() => dispatchEvent(new Event('os:login-changed')));
        await expect.poll(async () => (await page.evaluate(() => window.os.loginSession())).session?.uid).not.toBe(0);
      }
      const before = await syscall(context.request, 'getcreds');
      await page.evaluate(path => {
        window.securityReading = false;
        window.securityRun = window.os.exec([{ path, argv: [path] }], {
          onTty: input => { window.securityInput = input; },
          onReading: () => { window.securityReading = true; },
          onJob: job => { window.securityJob = job; },
        });
      }, path);
      await page.waitForFunction(() => window.securityReading && window.securityInput && window.securityJob.pids.length === 1);
      const pid = await page.evaluate(() => window.securityJob.pids[0]);
      const polled = await page.evaluate(pid => window.__pageKernel('poll', { pids: [pid] }), pid);
      expect(value(polled)[0].uid).toBe(before.uid);

      if (startsRoot) {
        expect((await api(context.request, 'logout')).ok()).toBe(true);
        await page.evaluate(() => dispatchEvent(new Event('os:login-changed')));
        await expect.poll(async () => (await page.evaluate(() => window.os.loginSession())).session?.uid).not.toBe(0);
      } else {
        await login(context.request);
        await page.evaluate(() => dispatchEvent(new Event('os:login-changed')));
        await expect.poll(async () => (await page.evaluate(() => window.os.loginSession())).session?.uid).toBe(0);
      }
      await page.evaluate(() => window.securityInput.write('x\n'));
      expect((await page.evaluate(() => window.securityRun)).status).toBe(startsRoot ? 0 : 63);
      if (startsRoot) {
        expect((await page.evaluate(() => window.targetRun)).status).toBe(137);
      } else {
        const targetState = await page.evaluate(pid => window.__pageKernel('poll', { pids: [pid] }), targetPid);
        expect(value(targetState)[0]?.state).toBe('running');
      }
    } finally {
      await page.evaluate(() => { window.securityJob?.signal(9); window.targetJob?.signal(9); });
      await login(context.request);
      await rmrf(context.request, path);
    }
  });
}

for (const removed of [false, true]) {
  test(`another tab cannot fork, replace, exit, wait for children or signal as a hosted process (SharedWorker ${removed ? 'removed' : 'unchanged'})`, async ({ page, context }) => {
    if (removed) await context.addInitScript(() => { delete globalThis.SharedWorker; });
    await page.goto('/login');
    await connect(page);
    await login(context.request);
    value(await kernel(page, 'sync_account', ROOT_ACCOUNT));
    const instanceId = value(await kernel(page, 'instance_id'));
    const parent = value(await kernel(page, 'exec', { ...sleep, remote: true }));
    const child = value(await kernel(page, 'fork', { pid: parent.pid }));
    value(await kernel(page, 'exit', { pid: child.pid, status: 7 }));
    // Drop the page's privileges; the already running parent remains root.
    expect((await api(context.request, 'logout')).ok()).toBe(true);
    value(await kernel(page, 'sync_account', GUEST_ACCOUNT));
    const other = await context.newPage();
    try {
      await other.goto('/login');
      await connect(other);
      const attempts = [
        ['fork', { pid: parent.pid }],
        ['process_call', { pid: parent.pid, call: 'setsid' }],
        ['session', { pids: [parent.pid] }],
        ['reexec', { ...sleep, pid: parent.pid }],
        ['exit', { pid: parent.pid, status: 99 }],
        ['waitchild', { ppid: parent.pid, pid: child.pid }],
        ['kill', { pid: parent.pid, signal: 9, from: parent.pid }],
        ['wait', { pid: child.pid }],
      ];
      for (const [type, args] of attempts) {
        const reply = await kernel(other, type, args);
        expect(reply.ok, type).toBeUndefined();
        expect(reply.err?.errno, type).toBe(type === 'wait' ? 'ECHILD' : 'ESRCH');
      }
      // Tab A can still fork, reap its zombie child, and reexec with its root snapshot preserved.
      const later = value(await kernel(page, 'fork', { pid: parent.pid }));
      value(await kernel(page, 'exit', { pid: later.pid, status: 0 }));
      value(await kernel(page, 'waitchild', { ppid: parent.pid, pid: later.pid }));
      expect(value(await kernel(page, 'waitchild', { ppid: parent.pid, pid: child.pid }))).toMatchObject({ pid: child.pid, status: 7 << 8 });
      const replaced = value(await kernel(page, 'reexec', { ...sleep, pid: parent.pid }));
      expect(replaced.pid).toBe(parent.pid);
      expect(replaced.token).toMatch(/^[0-9a-f]{64}$/);
      const credsReply = await batch(page, ['getcreds'], { pid: parent.pid, proc: replaced.token }, { 'X-OS-Instance': instanceId });
      expect(credsReply.body.results[0].ok.uid).toBe(0);
      expect(value(await kernel(page, 'kill', { pid: parent.pid, signal: 0, from: parent.pid }))).toBeNull();
    } finally {
      await kernel(page, 'exit', { pid: parent.pid, status: 0 });
      await kernel(page, 'wait', { pid: parent.pid });
      await other.close();
    }
  });
}

test('a new port cannot impersonate the tab named by a visible Web Lock', async ({ page, context }) => {
  await page.goto('/login');
  const tab = `security-owner-${Date.now()}-${++sequence}`;
  await connect(page, { tab, hold: true });
  await login(context.request);
  value(await kernel(page, 'sync_account', ROOT_ACCOUNT));
  const parent = value(await kernel(page, 'exec', sleep));
  expect((await api(context.request, 'logout')).ok()).toBe(true);
  value(await kernel(page, 'sync_account', GUEST_ACCOUNT));
  const other = await context.newPage();
  let stolen;
  try {
    await other.goto('/login');
    const visible = await other.evaluate(async () => (await navigator.locks.query()).held
      .map(lock => lock.name).find(name => name.startsWith('tw-tab-security-owner-')));
    expect(visible).toBe(`tw-tab-${tab}`);
    await connect(other, { tab: visible.slice('tw-tab-'.length) });
    stolen = await kernel(other, 'fork', { pid: parent.pid });
    expect(stolen.err?.errno).toBe('ESRCH');
    expect(stolen.ok).toBeUndefined();
  } finally {
    if (stolen?.ok) await kernel(page, 'exit', { pid: stolen.ok.pid, status: 0 });
    await kernel(page, 'exit', { pid: parent.pid, status: 0 });
    await kernel(page, 'wait', { pid: parent.pid });
    await other.close();
  }
});

test('exec replacement rotates remote token while preserving lineage open-refs and rejecting strangers', async ({ page, context }) => {
  await page.goto('/login');
  await connect(page);
  await login(context.request);
  value(await kernel(page, 'sync_account', ROOT_ACCOUNT));
  const instanceId = value(await kernel(page, 'instance_id'));
  const path = `/guest/exec-lineage-${crypto.randomUUID()}.wasm`;
  const output = path + '.txt';
  const image = Buffer.from(binaryen.parseText('(module (memory (export "memory") 1) (func (export "_start")))').emitBinary());
  expect((await put(context.request, '/api/file?path=' + encodeURIComponent(path), { data: image })).ok()).toBe(true);
  await syscall(context.request, { chmod: { path, mode: 0o755 } });
  const first = value(await kernel(page, 'exec', { ...sleep, path, argv: [path] }));
  expect(first.token).toMatch(/^[0-9a-f]{64}$/);
  let stranger;
  const fsOrigin = await page.evaluate(() => location.origin);
  const fsRpc = async (credential, session, call) => {
    const response = await context.request.post(fsOrigin + '/api/fs', {
      headers: { Origin: fsOrigin, 'X-OS-Instance': instanceId },
      data: { version: 2, credential, session, call },
    });
    return { ok: response.ok(), status: response.status(), body: await response.json() };
  };
  let fsSession;
  let openRef;
  try {
    const old = { pid: first.pid, proc: first.token };
    // Processes use /api/fs v2 handles; direct v1 /api/sys regular-file path opens are refused.
    const directOpen = await batch(page, [{ open: { path: output, flags: 0o101, mode: 0o600 } }], old, { 'X-OS-Instance': instanceId });
    expect(directOpen.body.results[0].err?.errno).toBe('EPERM');

    const conn = await fsRpc(first.token, null, 'connect');
    expect(conn.ok, JSON.stringify(conn.body)).toBe(true);
    fsSession = conn.body.session;
    const guestDir = await fsRpc(first.token, fsSession, { lookup: { dir: conn.body.root, name: 'guest' } });
    expect(guestDir.ok, JSON.stringify(guestDir.body)).toBe(true);
    const created = await fsRpc(first.token, fsSession, {
      create: {
        ticket: `exec-lineage-${crypto.randomUUID()}`,
        dir: guestDir.body.handle,
        name: output.split('/').pop(),
        mode: 0o600,
        umask: 0o022,
        options: { read: false, write: true, append: false, append_implies_write: false, truncate: false, create: true, create_new: true, exec: false, path: false },
      },
    });
    expect(created.ok, JSON.stringify(created.body)).toBe(true);
    openRef = created.body[1];

    const replaced = value(await kernel(page, 'reexec', { ...sleep, pid: first.pid }));
    expect(replaced.token).toMatch(/^[0-9a-f]{64}$/);
    expect(replaced.token).not.toBe(first.token);
    // Old token is revoked immediately on reexec rotation.
    const oldCreds = await batch(page, ['getcreds'], old, { 'X-OS-Instance': instanceId });
    expect(oldCreds.body.results[0].err?.errno).toBe('EPERM');

    // A stranger process with its own remote token cannot write to another lineage's /api/fs open-ref.
    stranger = value(await kernel(page, 'exec', { ...sleep, remote: true }));
    const strangerConn = await fsRpc(stranger.token, null, 'connect');
    expect(strangerConn.ok, JSON.stringify(strangerConn.body)).toBe(true);
    const payload = Buffer.from('survived exec\n');
    const strangerWrite = await context.request.post(fsOrigin + '/api/fs/data', {
      headers: {
        Origin: fsOrigin,
        'X-OS-Instance': instanceId,
        'X-OS-Filesystem': JSON.stringify({
          version: 2,
          credential: stranger.token,
          pid: stranger.pid,
          session: strangerConn.body.session,
          open: openRef,
          operation: { write: { at: { offset: 0 }, length: payload.length } },
        }),
      },
      data: payload,
    });
    await fsRpc(stranger.token, strangerConn.body.session, 'disconnect').catch(() => {});
    expect(strangerWrite.ok()).toBe(false);
    expect(['EACCES', 'EPERM']).toContain((await strangerWrite.json()).errno);

    // Browser logout does not kill the running process's remote descriptors.
    expect((await api(context.request, 'logout')).ok()).toBe(true);
    const currentWrite = await context.request.post(fsOrigin + '/api/fs/data', {
      headers: {
        Origin: fsOrigin,
        'X-OS-Instance': instanceId,
        'X-OS-Filesystem': JSON.stringify({
          version: 2,
          credential: replaced.token,
          pid: replaced.pid,
          session: fsSession,
          open: openRef,
          operation: { write: { at: { offset: 0 }, length: payload.length } },
        }),
      },
      data: payload,
    });
    expect(currentWrite.ok(), await currentWrite.text()).toBe(true);
    const released = await fsRpc(replaced.token, fsSession, { release: { open: openRef } });
    expect(released.ok, JSON.stringify(released.body)).toBe(true);
    openRef = null;
    await fsRpc(replaced.token, fsSession, 'disconnect');
    fsSession = null;
    await login(context.request);
    expect(await (await context.request.get('/api/file?path=' + encodeURIComponent(output))).text()).toBe('survived exec\n');
  } finally {
    if (fsSession) {
      await fsRpc(first.token, fsSession, 'disconnect').catch(() => {});
    }
    for (const proc of [first, stranger].filter(Boolean)) {
      await kernel(page, 'exit', { pid: proc.pid, status: 0 });
      await kernel(page, 'wait', { pid: proc.pid });
    }
    await login(context.request);
    await rmrf(context.request, output);
    await rmrf(context.request, path);
  }
});

test('F3-01: set_proc_cred and mint_remote_cred block privilege escalation and preserve non-root local UID', async ({ page, context }) => {
  await page.goto('/login');
  await connect(page);
  await login(context.request);
  value(await kernel(page, 'sync_account', ROOT_ACCOUNT));

  // Spawn a root process, then drop it to non-root uid 1001.
  const proc = value(await kernel(page, 'exec', { ...sleep }));
  const noCloud = value(await kernel(page, 'exec', { ...sleep, remote: false }));
  try {
    value(await kernel(page, 'set_proc_cred', { pid: proc.pid, uid: 1001, gid: 1001, groups: [1001] }));
    expect(value(await kernel(page, 'getcreds_proc', { pid: proc.pid })).uid).toBe(1001);

    // Non-root process cannot re-escalate to uid 0 via set_proc_cred.
    expect((await kernel(page, 'set_proc_cred', { pid: proc.pid, uid: 0, gid: 0, groups: [0] })).err?.errno).toBe('EPERM');

    // F3-01: Non-root local process (uid 1001) cannot mint or bind a root (uid 0) remote cred
    // from the browser's root cookie, and its local UID remains 1001.
    expect((await kernel(page, 'mint_remote_cred', { pid: proc.pid, sudo: false })).err?.errno).toBe('EACCES');
    expect(['EACCES', 'EPERM']).toContain((await kernel(page, 'mint_remote_cred', { pid: proc.pid, sudo: true })).err?.errno);
    expect(value(await kernel(page, 'getcreds_proc', { pid: proc.pid })).uid).toBe(1001);

    // Cloud-denied process cannot re-enable cloud_access via set_proc_cred or mint_remote_cred.
    expect((await kernel(page, 'set_proc_cred', {
      pid: noCloud.pid,
      uid: 0,
      gid: 0,
      groups: [0],
      remote: {
        token: '0'.repeat(64),
        uid: 0,
        gid: 0,
        groups: [0],
        instance_id: 'inst-forged',
        lineage: 'lin-forged',
        cloud_access: true,
        scope: { cloud_fs: true, devices: [], containers: false, relay: false },
      },
    })).err?.errno).toBe('EPERM');
    expect((await kernel(page, 'mint_remote_cred', { pid: noCloud.pid, sudo: false })).err?.errno).toBe('EACCES');
  } finally {
    for (const p of [proc, noCloud]) {
      await kernel(page, 'exit', { pid: p.pid, status: 0 });
      await kernel(page, 'wait', { pid: p.pid });
    }
  }
});

test('F3-08/F3-10: immediate /api/file revocation bypasses TOKEN_FRESH cache, /dev/present/../../proc is denied, and DevTmpFs gates remote opens per caller', async ({ page, context }) => {
  await page.goto('/login');
  await connect(page);
  await login(context.request);
  value(await kernel(page, 'sync_account', ROOT_ACCOUNT));
  const instanceId = value(await kernel(page, 'instance_id'));
  const filePath = `/guest/revoke-immediate-${crypto.randomUUID()}.txt`;
  expect((await put(context.request, '/api/file?path=' + encodeURIComponent(filePath), { data: 'SECRET_TOKEN_DATA' })).ok()).toBe(true);

  const remoteProc = value(await kernel(page, 'exec', { ...sleep, remote: true }));
  const presentOnly = value(await kernel(page, 'exec', {
    ...sleep,
    remote: { cloud_fs: false, devices: ['present'], containers: false, relay: false },
  }));
  const noCloud = value(await kernel(page, 'exec', { ...sleep, remote: false }));
  const OS_FD_ROOT = 0x7ffffffd;
  try {
    // 1. /api/file?path=... with X-Process-Token succeeds while live, then fails IMMEDIATELY after SIGKILL (no TOKEN_FRESH lag).
    const liveRes = await context.request.get(origin + '/api/file?path=' + encodeURIComponent(filePath), {
      headers: {
        Origin: origin,
        'X-Process-Token': remoteProc.token,
        'X-Process-Pid': String(remoteProc.pid),
        'X-OS-Instance': instanceId,
      },
    });
    expect(liveRes.status()).toBe(200);
    expect(await liveRes.text()).toBe('SECRET_TOKEN_DATA');

    value(await kernel(page, 'kill', { pid: remoteProc.pid, signal: 9 }));
    const revokedRes = await context.request.get(origin + '/api/file?path=' + encodeURIComponent(filePath), {
      headers: {
        Origin: origin,
        'X-Process-Token': remoteProc.token,
        'X-Process-Pid': String(remoteProc.pid),
        'X-OS-Instance': instanceId,
      },
    });
    expect(revokedRes.status()).not.toBe(200);
    expect([401, 403]).toContain(revokedRes.status());

    // 2. Cloud-denied token with present device scope cannot escape into /proc via /dev/present/../../proc.
    const traversalRes = await context.request.get(origin + '/api/file?path=' + encodeURIComponent('/dev/present/../../proc/uptime'), {
      headers: {
        Origin: origin,
        'X-Process-Token': presentOnly.token,
        'X-Process-Pid': String(presentOnly.pid),
        'X-OS-Instance': instanceId,
      },
    });
    expect(traversalRes.ok()).toBe(false);
    expect([403, 404]).toContain(traversalRes.status());

    // 3. DevTmpFs remote device open hook: after attaching /dev/archive, stat succeeds for all,
    //    but open is denied (EACCES) for cloud_access=false or device-scope-denied callers.
    value(await kernel(page, 'attach_remote_device', { driver: 'archive' }));
    expect((await kernel(page, 'proc_statat', { pid: noCloud.pid, dirfd: OS_FD_ROOT, path: '/dev/archive', follow: true })).ok).toBeTruthy();
    expect((await kernel(page, 'proc_openat', { pid: noCloud.pid, dirfd: OS_FD_ROOT, path: '/dev/archive', oflags: 0, mode: 0, cloexec: false })).err?.errno).toBe('EACCES');
    expect((await kernel(page, 'proc_openat', { pid: presentOnly.pid, dirfd: OS_FD_ROOT, path: '/dev/archive', oflags: 0, mode: 0, cloexec: false })).err?.errno).toBe('EACCES');
  } finally {
    await kernel(page, 'detach_remote_device', { driver: 'archive' }).catch(() => {});
    for (const p of [remoteProc, presentOnly, noCloud]) {
      await kernel(page, 'exit', { pid: p.pid, status: 0 }).catch(() => {});
      await kernel(page, 'wait', { pid: p.pid }).catch(() => {});
    }
    await rmrf(context.request, filePath);
  }
});

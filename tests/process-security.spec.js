import { test, expect } from './test.js';
import { readFile } from 'node:fs/promises';
import binaryen from 'binaryen';
import { api, call as syscall, put, rmrf } from './sys.js';

const rootPassword = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const sleep = { path: '/usr/bin/coreutils', argv: ['coreutils', 'sleep', '60'], env: [], cwd: '/' };
let sequence = 0;
async function login(request) {
  const response = await api(request, 'login', {
    headers: { 'CF-Connecting-IP': `process-security-${Date.now()}-${++sequence}` },
    data: { username: 'root', password: rootPassword },
  });
  expect(response.ok()).toBe(true);
}

// A separate client-kernel port per page. Omitting a tab id exercises the port's own host
// identity without inventing a Web Lock that would outlive this test's connection.
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
      port.postMessage({ v: 1, id, type, args, tab });
    });
  }, { tab, hold });
  value(await kernel(page, 'init'));
}
const kernel = (page, type, args = {}) => page.evaluate(([type, args]) => window.securityKernel(type, args), [type, args]);
function value(reply) {
  expect(reply.err, JSON.stringify(reply.err)).toBeUndefined();
  return reply.ok;
}
async function batch(page, calls, options = {}, registry = false) {
  return page.evaluate(async ({ calls, options, registry }) => {
    const response = await fetch('/api/sys', {
      method: 'POST', headers: { 'Content-Type': 'application/json', ...(registry ? { 'X-Registry': '1' } : {}) },
      body: JSON.stringify({ calls, ...options }),
    });
    if (!response.ok) throw new Error(`sys: ${response.status} ${await response.text()}`);
    return (await response.json()).results;
  }, { calls, options, registry });
}

test('the machine refuses route-only bookkeeping from pages and process tokens on either route', async ({ page, context }) => {
  await page.goto('/');
  await connect(page);
  // Even root's page and root's process are user space, not the client kernel.
  await login(context.request);
  const process = value(await kernel(page, 'exec', sleep));
  const own = { pid: process.pid, proc: process.token };
  const calls = [{ proc_init: { boot: 'untrusted-reset' } }, 'seats', { gone: { seat: '' } }];
  try {
    for (const [options, registry] of [[{}, false], [own, false], [own, true]]) {
      const refused = await batch(page, calls, options, registry);
      expect(refused.map(result => result.err?.errno)).toEqual(calls.map(() => 'EPERM'));
      // In particular, proc_init and gone must not have reaped the running process.
      expect(value((await batch(page, ['getpid'], own))[0]).pid).toBe(process.pid);
      expect(value(await kernel(page, 'poll', { pids: [process.pid] }))[0].state).toBe('running');
    }
    const lifecycle = [{ fork: { pid: process.pid } }, { exit: { status: 0 } }, { wait: { pid: String(process.pid) } }];
    expect((await batch(page, lifecycle)).map(result => result.err?.errno)).toEqual(lifecycle.map(() => 'EPERM'));
    expect((await batch(page, [{ pids: { count: 2 } }]))[0].err?.errno).toBe('EPERM');
    // A process can reserve pids, scoped to its snapshot and token, on either route.
    for (const route of [false, true]) {
      expect(value((await batch(page, [{ pids: { count: 1 } }], own, route))[0])).toHaveLength(1);
    }
    expect(value((await batch(page, ['seats'], {}, true))[0])).toHaveProperty('seats');
    expect(value((await batch(page, ['getpid'], own, true))[0]).pid).toBe(process.pid);
  } finally {
    await kernel(page, 'exit', { pid: process.pid, status: 0 });
    await kernel(page, 'wait', { pid: process.pid });
  }
});

test('a forged registry header cannot reset, reap, inspect or reclaim another account', async ({ page, context }) => {
  const seat = `registry-owner-${Date.now()}-${++sequence}`;
  const lender = `${seat}-kernel`;
  // These registry-only processes model a live host. Claim its locks before the app
  // boots, so ordinary abandoned-host cleanup cannot race the authorization checks.
  await page.addInitScript(({ seat, lender }) => {
    window.registryLocks = Promise.all([`tw-tab-${seat}`, `tw-kernel-${lender}`].map(name =>
      new Promise(resolve => { void navigator.locks.request(name, () => { resolve(); return new Promise(() => {}); }); })));
  }, { seat, lender });
  await page.goto('/');
  await page.evaluate(() => window.registryLocks);
  await login(context.request);
  const call = async (entry, options = {}, route = true) => (await batch(page, [entry], options, route))[0];
  const exec = async seat => value(await call({ execve: { ...sleep, seat } }));
  value(await call({ proc_init: { boot: 'root-boot' } }));
  const parent = await exec(seat);
  const zombie = await exec(seat);
  value(await call({ exit: { pid: zombie.pid, proc: zombie.token, status: 7 } }));
  const [reserved] = value(await call({ pids: { count: 1, kernel: lender } }));
  try {
    expect((await api(context.request, 'logout')).ok()).toBe(true);
    const guest = await exec(seat); // A tab can contain both accounts' processes.
    for (const route of [false, true]) {
      expect((await call({ kill: { pid: String(parent.pid), signal: 9 } }, {}, route)).err?.errno).toBe('EPERM');
    }
    const listed = value(await call('seats'));
    expect(listed.kernels).not.toContain(lender);
    // The shared seat is visible because it also contains the guest's process. A mixed seat
    // is checked as a whole before any process or reservation is changed.
    for (const entry of [
      { gone: { seat } },
      { gone: { kernel: lender } },
      { gone: { seat, kernel: lender } },
      { wait: { pid: String(zombie.pid) } },
      { wait: { pid: String(zombie.pid), proc: 'invalid-token' } },
    ]) expect((await call(entry)).err?.errno).toBe('EPERM');
    expect(value(await call('getpid', { pid: guest.pid, proc: guest.token })).pid).toBe(guest.pid);
    // A guest cannot consume a reservation belonging to root, even if it guesses the pid.
    expect((await call({ fork: { pid: guest.pid, child: reserved } }, { pid: guest.pid, proc: guest.token })).err?.errno).toBe('EINVAL');
    const reset = value(await call({ proc_init: { boot: 'guest-boot' } }));
    expect(reset.pids).toEqual([1]);
    expect(value(await call('seats'))).toEqual({ seats: [], kernels: [] });
    // Root's old process and lend survived. Possessing that process's token still authorizes
    // its fork after logout, unlike merely setting the routing header.
    expect(value(await call('getpid', { pid: parent.pid, proc: parent.token })).pid).toBe(parent.pid);
    const child = value(await call({ fork: { pid: parent.pid, child: reserved, proc: parent.token } }));
    expect(child.pid).toBe(reserved);
    await login(context.request);
    const rows = value(await call({ proc_poll: { pids: [parent.pid, zombie.pid, child.pid, guest.pid] } }));
    expect(rows.map(row => row.pid).sort()).toEqual([parent.pid, zombie.pid, child.pid].sort());
    expect(rows.find(row => row.pid === parent.pid).state).toBe('running');
    expect(rows.find(row => row.pid === zombie.pid)).toMatchObject({ state: 'zombie', status: 7 << 8 });
    expect(value(await call({ wait: { pid: String(zombie.pid) } })).status).toBe(7 << 8);
  } finally {
    await login(context.request);
    value(await call({ gone: { seat, kernel: lender } }));
  }
});

test('a rejected sudo command does not discard token-authorized exit and wait reports', async ({ page, context }) => {
  await page.goto('/');
  await login(context.request);
  const process = value((await batch(page, [{ execve: sleep }], {}, true))[0]);
  try {
    expect((await api(context.request, 'logout')).ok()).toBe(true);
    const [ended, waited, denied] = await batch(page, [
      { exit: { pid: process.pid, proc: process.token, status: 3 } },
      { wait: { pid: String(process.pid), proc: process.token } },
      { execve: sleep },
    ], { sudo: true }, true);
    expect(value(ended)).toBeNull();
    expect(value(waited)).toMatchObject({ pid: process.pid, status: 3 << 8 });
    expect(denied.err).toBeTruthy();
    expect((await batch(page, ['getpid'], { pid: process.pid, proc: process.token }, true))[0].err?.errno).toBe('EPERM');
  } finally {
    await login(context.request);
    await batch(page, [{ kill: { pid: String(process.pid), signal: 9 } }, { wait: { pid: String(process.pid) } }], {}, true);
  }
});

test('PID lends belong to a process lineage and are released with its last live holder', async ({ page }) => {
  await page.goto('/');
  const lender = `lineage-${Date.now()}-${++sequence}`;
  const call = async (entry, options = {}) => (await batch(page, [entry], options, true))[0];
  const exec = async () => value(await call({ execve: { ...sleep, seat: lender } }));
  const one = await exec(), two = await exec();
  const as = process => ({ pid: process.pid, proc: process.token });
  try {
    const [first, second] = value(await call({ pids: { count: 2, kernel: lender } }, as(one)));
    expect((await call({ fork: { pid: two.pid, child: first } }, as(two))).err?.errno).toBe('EINVAL');
    const child = value(await call({ fork: { pid: one.pid, child: first } }, as(one)));
    value(await call({ exit: { status: 0 } }, as(one)));
    // A fork shares the lineage and keeps its unused reservations alive after its parent exits.
    const grandchild = value(await call({ fork: { pid: child.pid, child: second } }, as(child)));
    value(await call({ pids: { count: 2, kernel: lender } }, as(grandchild)));
    value(await call({ exit: { status: 0 } }, as(child)));
    expect(value(await call('seats')).kernels).toContain(lender);
    value(await call({ exit: { status: 0 } }, as(grandchild)));
    expect(value(await call('seats')).kernels).not.toContain(lender);
  } finally {
    value(await call({ gone: { seat: lender, kernel: lender } }));
  }
});

test('a registry caller can clean up its own seat and lends without affecting other accounts', async ({ page, context }) => {
  await page.goto('/');
  await login(context.request);
  const seat = `registry-cleanup-${Date.now()}-${++sequence}`;
  const call = async entry => (await batch(page, [entry], {}, true))[0];
  const root = value(await call({ execve: { ...sleep, seat: seat + '-root' } }));
  try {
    expect((await api(context.request, 'logout')).ok()).toBe(true);
    const guest = value(await call({ execve: { ...sleep, seat } }));
    value(await call({ pids: { count: 2, kernel: seat } }));
    expect(value(await call('seats'))).toEqual({ seats: [seat], kernels: [seat] });
    expect(value(await call({ gone: { seat, kernel: seat } }))).toEqual([guest.pid]);
    expect(value(await call('seats'))).toEqual({ seats: [], kernels: [] });
    expect(value((await batch(page, ['getpid'], { pid: root.pid, proc: root.token }))[0]).pid).toBe(root.pid);
  } finally {
    await login(context.request);
    value(await call({ gone: { seat: seat + '-root' } }));
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

for (const startsRoot of [false, true]) {
  test(`proc_signal keeps the process's ${startsRoot ? 'root credentials after logout' : 'guest credentials after root login'}`, async ({ page, context }) => {
    await page.goto('/');
    await connect(page);
    await login(context.request);
    const target = value(await kernel(page, 'exec', sleep));
    const path = `/tmp/proc-signal-${Date.now()}-${++sequence}.wasm`;
    try {
      expect((await put(context.request, `/api/file?path=${path}`, { data: signalProgram(target.pid) })).ok()).toBe(true);
      await syscall(context.request, { chmod: { path, mode: 0o755 } });
      if (!startsRoot) expect((await api(context.request, 'logout')).ok()).toBe(true);
      const before = await syscall(context.request, 'getcreds');
      await page.waitForFunction(() => !!window.terminal?.exec);
      await page.evaluate(path => {
        window.securityReading = false;
        window.securityRun = window.terminal.exec([{ path, argv: [path] }], {
          onTty: input => { window.securityInput = input; },
          onReading: () => { window.securityReading = true; },
          onJob: job => { window.securityJob = job; },
        });
      }, path);
      await page.waitForFunction(() => window.securityReading && window.securityInput && window.securityJob.pids.length === 1);
      const pid = await page.evaluate(() => window.securityJob.pids[0]);
      expect(value(await kernel(page, 'poll', { pids: [pid] }))[0].uid).toBe(before.uid);

      if (startsRoot) expect((await api(context.request, 'logout')).ok()).toBe(true);
      else await login(context.request);
      expect((await syscall(context.request, 'getcreds')).uid === 0).toBe(!startsRoot);
      await page.evaluate(() => window.securityInput.write('x\n')); // Commit the canonical input line.
      expect((await page.evaluate(() => window.securityRun)).status).toBe(startsRoot ? 0 : 63);
      // Inspect as root: the guest page must not be able to see root's process list.
      if (startsRoot) await login(context.request);
      const [after] = value(await kernel(page, 'poll', { pids: [target.pid] }));
      expect(after.state).toBe(startsRoot ? 'zombie' : 'running');
      if (startsRoot) expect(after.status).toBe(9);
    } finally {
      await page.evaluate(() => window.securityJob?.signal(9));
      await login(context.request);
      await kernel(page, 'exit', { pid: target.pid, status: 0 });
      await kernel(page, 'wait', { pid: target.pid });
      await rmrf(context.request, path);
    }
  });
}

for (const removed of [false, true]) {
  test(`another tab cannot fork, replace, exit, wait for children or signal as a hosted process (SharedWorker ${removed ? 'removed' : 'unchanged'})`, async ({ page, context }) => {
    if (removed) await context.addInitScript(() => { delete globalThis.SharedWorker; });
    await page.goto('/');
    await connect(page);
    await login(context.request);
    const parent = value(await kernel(page, 'exec', sleep));
    const child = value(await kernel(page, 'fork', { pid: parent.pid }));
    value(await kernel(page, 'exit', { pid: child.pid, status: 7 }));
    // Drop the page's privileges; the already running parent remains root.
    expect((await api(context.request, 'logout')).ok()).toBe(true);
    const other = await context.newPage();
    try {
      await other.goto('/');
      await connect(other);
      const attempts = [
        ['fork', { pid: parent.pid }],
        ['reexec', { ...sleep, pid: parent.pid }],
        ['exit', { pid: parent.pid, status: 99 }],
        ['waitchild', { ppid: parent.pid, pid: child.pid }],
        ['kill', { pid: parent.pid, signal: 9, from: parent.pid }],
      ];
      for (const [type, args] of attempts) {
        const reply = await kernel(other, type, args);
        expect(reply.ok, type).toBeUndefined();
        expect(reply.err?.errno, type).toBe('ESRCH');
      }
      // A generic wait must not let another port use the kernel's retained zombie token.
      expect((await kernel(other, 'wait', { pid: child.pid })).err?.errno).toBe('EPERM');
      // PID lending uses the parent's snapshot, even though the page is now guest.
      const later = value(await kernel(page, 'fork', { pid: parent.pid }));
      value(await kernel(page, 'exit', { pid: later.pid, status: 0 }));
      value(await kernel(page, 'waitchild', { ppid: parent.pid, pid: later.pid }));
      // The owning port can still act, and the other tab did not steal the child's status.
      expect(value(await kernel(page, 'waitchild', { ppid: parent.pid, pid: child.pid }))).toMatchObject({ pid: child.pid, status: 7 << 8 });
      const replaced = value(await kernel(page, 'reexec', { ...sleep, pid: parent.pid }));
      expect(replaced.pid).toBe(parent.pid);
      expect(replaced.token).toMatch(/^[0-9a-f]{64}$/);
      expect(value((await batch(page, ['getcreds'], { pid: parent.pid, proc: replaced.token }))[0]).uid).toBe(0);
      expect(value(await kernel(page, 'kill', { pid: parent.pid, signal: 0, from: parent.pid }))).toBeNull();
    } finally {
      await kernel(page, 'exit', { pid: parent.pid, status: 0 });
      await kernel(page, 'wait', { pid: parent.pid });
      await other.close();
    }
  });
}

test('a new port cannot impersonate the tab named by a visible Web Lock', async ({ page, context }) => {
  await page.goto('/');
  const tab = `security-owner-${Date.now()}-${++sequence}`;
  await connect(page, { tab, hold: true });
  await login(context.request);
  const parent = value(await kernel(page, 'exec', sleep));
  expect((await api(context.request, 'logout')).ok()).toBe(true);
  const other = await context.newPage();
  let stolen;
  try {
    await other.goto('/');
    // Same-origin tabs can enumerate the lock names; the tab id is not a secret.
    const visible = await other.evaluate(async () => (await navigator.locks.query()).held
      .map(lock => lock.name).find(name => name.startsWith('tw-tab-security-owner-')));
    expect(visible).toBe(`tw-tab-${tab}`);
    await connect(other, { tab: visible.slice('tw-tab-'.length) });
    stolen = await kernel(other, 'fork', { pid: parent.pid });
    // The tab id is public; it names the lock that ends the port's processes, not the port that
    // runs them. Another port claiming it is still another host, and gets no token.
    expect(stolen.err?.errno).toBe('ESRCH');
    expect(stolen.ok).toBeUndefined();
  } finally {
    if (stolen?.ok) await kernel(page, 'exit', { pid: stolen.ok.pid, status: 0 });
    await kernel(page, 'exit', { pid: parent.pid, status: 0 });
    await kernel(page, 'wait', { pid: parent.pid });
    await other.close();
  }
});

test('exec replacement revokes its image grant while preserving ordinary descriptors', async ({ page, context }) => {
  await page.goto('/');
  await connect(page);
  await login(context.request);
  const path = `/guest/exec-lineage-${crypto.randomUUID()}.wasm`;
  const output = path + '.txt';
  const image = Buffer.from(binaryen.parseText('(module (memory (export "memory") 1) (func (export "_start")))').emitBinary());
  expect((await put(context.request, '/api/file?path=' + encodeURIComponent(path), { data: image })).ok()).toBe(true);
  await syscall(context.request, { chmod: { path, mode: 0o755 } });
  const first = value(await kernel(page, 'exec', { ...sleep, path, argv: [path] }));
  let stranger;
  try {
    const old = { pid: first.pid, proc: first.token };
    const opened = value((await batch(page, [{ open: { path: output, flags: 0o101, mode: 0o600 } }], old))[0]);
    const replaced = value(await kernel(page, 'reexec', { ...sleep, pid: first.pid }));
    const current = { pid: replaced.pid, proc: replaced.token };
    expect(replaced.token).not.toBe(first.token);
    expect((await batch(page, ['getcreds'], old))[0].err?.errno).toBe('EPERM');
    // The loader's descriptor is image-specific even when its owner key is also the original
    // process lineage. A replacement must not retain this old image capability.
    expect((await batch(page, [{ pread: { fd: first.fd, count: 4 } }], current))[0].err?.errno).toBe('EBADF');
    stranger = value(await kernel(page, 'exec', sleep));
    expect((await batch(page, [{ pwrite: { fd: opened.fd, index: 0, data: 'eA==' } }], { pid: stranger.pid, proc: stranger.token }))[0].err?.errno).toBe('EBADF');
    const written = await batch(page, [
      { pwrite: { fd: opened.fd, index: 0, data: Buffer.from('survived exec\n').toString('base64') } },
      { close: { fd: opened.fd } },
    ], current);
    for (const result of written) value(result);
    expect(await (await context.request.get('/api/file?path=' + encodeURIComponent(output))).text()).toBe('survived exec\n');
  } finally {
    for (const process of [first, stranger].filter(Boolean)) {
      await kernel(page, 'exit', { pid: process.pid, status: 0 });
      await kernel(page, 'wait', { pid: process.pid });
    }
    await rmrf(context.request, output);
    await rmrf(context.request, path);
  }
});

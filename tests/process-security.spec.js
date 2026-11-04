import { test, expect } from '@playwright/test';
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
    const shared = typeof SharedWorker === 'function';
    const worker = shared ? new SharedWorker('/client-kernel.js') : new Worker('/client-kernel.js');
    const port = shared ? worker.port : worker;
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

test('the machine refuses kernel-only calls from pages and process tokens on either route', async ({ page, context }) => {
  await page.goto('/');
  await connect(page);
  // Even root's page and root's process are user space, not the client kernel.
  await login(context.request);
  const process = value(await kernel(page, 'exec', sleep));
  const own = { pid: process.pid, proc: process.token };
  const calls = [{ proc_init: { boot: 'untrusted-reset' } }, { pids: { count: 2 } }, 'seats', { gone: { seat: '' } }];
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
    expect(value((await batch(page, ['seats'], {}, true))[0])).toHaveProperty('seats');
    expect(value((await batch(page, ['getpid'], own, true))[0]).pid).toBe(process.pid);
  } finally {
    await kernel(page, 'exit', { pid: process.pid, status: 0 });
    await kernel(page, 'wait', { pid: process.pid });
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
      await page.evaluate(() => window.securityInput.write('x'));
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

for (const dedicated of [false, true]) {
  test(`another tab cannot fork, replace, exit, wait for children or signal as a hosted process (${dedicated ? 'dedicated' : 'shared'} kernel)`, async ({ page, context }) => {
    if (dedicated) await context.addInitScript(() => { delete globalThis.SharedWorker; });
    await page.goto('/');
    if (!dedicated) expect(await page.evaluate(() => typeof SharedWorker)).toBe('function');
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

import { test, expect } from './test.js';
import { hookPageKernel } from './service-auth.js';

// The client kernel (crates/client-kernel, web/kernel/client.js): one dedicated Worker per tab,
// owning its own isolated LocalProcessTable, local /proc, local cgroups, and lazy ServiceAuth v2
// remote credentials (Contract v2 §2.1). A page's port speaks the HostAdapter v2 envelope
// (web/kernel/protocol.js).

// A page's port to its own client kernel, kept on the page so calls can follow.
async function connect(page) {
  await page.evaluate(() => {
    const port = new Worker('/client-kernel.js');
    const pending = new Map();
    let next = 0;
    port.onmessage = ({ data }) => {
      if (data?.id != null && pending.has(data.id)) {
        pending.get(data.id)(data);
        pending.delete(data.id);
      }
    };
    window.__kernel = (type, args = {}) => new Promise(resolve => {
      const id = ++next;
      pending.set(id, resolve);
      port.postMessage({ v: 2, id, type, args });
    });
  });
}

async function call(page, type, args = {}) {
  return page.evaluate(([type, args]) => window.__kernel(type, args), [type, args]);
}

function value(reply) {
  expect(reply.err, JSON.stringify(reply.err)).toBeUndefined();
  return reply.ok;
}

// A page's own batch, as user space makes it.
async function sys(page, calls, options = {}) {
  return page.evaluate(async ([calls, options]) => {
    const response = await fetch('/api/sys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ calls, ...options }),
    });
    return (await response.json()).results;
  }, [calls, options]);
}

const ENV = ['PWD=/', 'HOME=/guest', 'PATH=/usr/bin', 'LANG=C.UTF-8'];

test('two dedicated kernels are isolated per tab, and each tracks its own processes', async ({ browser }) => {
  const context = await browser.newContext();
  const one = await context.newPage();
  const two = await context.newPage();
  await one.goto('/');
  await two.goto('/');
  await connect(one);
  await connect(two);
  const first = value(await call(one, 'init'));
  const second = value(await call(two, 'init'));
  expect(first.version).toBe(2);
  expect(first.local).toBe(true);
  expect(first.instance_id).toBeTruthy();
  expect(second.instance_id).toBeTruthy();
  expect(first.instance_id).not.toBe(second.instance_id);
  expect(first.boot).not.toBe(second.boot);
  expect(value(await call(one, 'poll', { pids: [1] }))[0]?.pid).toBe(1);
  // Sync tab one with the browser's account and start a process in its local table.
  const [creds] = await sys(one, ['getcreds']);
  value(await call(one, 'sync_account_from_server'));
  const running = value(await call(one, 'exec', { path: '/usr/bin/coreutils', argv: ['coreutils', 'sleep', '30'], env: ENV, cwd: '/' }));
  expect(running.pid).toBeGreaterThan(1);
  expect(running.asset).toBe('/usr/bin/coreutils.wasm');
  const polled = value(await call(one, 'poll', { pids: [] }));
  expect(polled.map(process => process.pid)).toContain(running.pid);
  const status = value(await call(one, 'getpid', { pid: running.pid }));
  expect(status).toEqual({ pid: running.pid, ppid: 1 });
  const seen = value(await call(one, 'poll', { pids: [running.pid] }));
  expect(seen[0].uid).toBe(creds.ok.uid);
  // Contract v2 §2.1: another tab's kernel instance cannot see, query, or reap tab one's process.
  expect(value(await call(two, 'poll', { pids: [running.pid] }))).toEqual([]);
  expect((await call(two, 'getpid', { pid: running.pid })).err?.errno).toBe('ESRCH');
  expect((await call(two, 'wait', { pid: running.pid })).err?.errno).toBe('ECHILD');
  // End it and reap it inside its owning instance.
  value(await call(one, 'exit', { pid: running.pid, status: 0 }));
  expect(value(await call(one, 'poll', { pids: [running.pid] }))[0]?.state).toBe('zombie');
  const reaped = value(await call(one, 'wait', { pid: running.pid }));
  expect(reaped.status).toBe(0);
  expect(value(await call(one, 'poll', { pids: [running.pid] }))).toEqual([]);
  await context.close();
});

test('a fork copies the registry, and wait gives its status to its parent', async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto('/');
  await connect(page);
  value(await call(page, 'init'));
  const parent = value(await call(page, 'exec', { path: '/usr/bin/coreutils', argv: ['coreutils', 'sleep', '30'], env: ENV, cwd: '/' }));
  const child = value(await call(page, 'fork', { pid: parent.pid }));
  expect(child.pid).not.toBe(parent.pid);
  expect(value(await call(page, 'getpid', { pid: child.pid }))).toEqual({ pid: child.pid, ppid: parent.pid });
  value(await call(page, 'exit', { pid: child.pid, status: 7 }));
  // The parent waits via waitchild: its child's status is waitpid's 7 << 8; init wait may not reap it.
  expect((await call(page, 'wait', { pid: child.pid })).err?.errno).toBe('ECHILD');
  const reaped = value(await call(page, 'waitchild', { ppid: parent.pid, pid: child.pid }));
  expect(reaped.status).toBe(7 << 8);
  value(await call(page, 'exit', { pid: parent.pid, status: 0 }));
  value(await call(page, 'wait', { pid: parent.pid }));
  await context.close();
});

test('cgroups are created, written, attached, listed and removed, as cgroup v2 has them', async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto('/');
  await connect(page);
  value(await call(page, 'init'));
  const process = value(await call(page, 'exec', { path: '/usr/bin/coreutils', argv: ['coreutils', 'sleep', '30'], env: ENV, cwd: '/' }));
  value(await call(page, 'cgroup_create', { path: '/user/job' }));
  value(await call(page, 'cgroup_set', { path: '/user/job', key: 'memory.max', value: '16777216' }));
  value(await call(page, 'cgroup_set', { path: '/user/job', key: 'pids.max', value: '4' }));
  expect((await call(page, 'cgroup_set', { path: '/user/job', key: 'cgroup.freeze', value: '1' })).err.errno).toBe('EOPNOTSUPP');
  value(await call(page, 'cgroup_attach', { pid: process.pid, path: '/user/job' }));
  const stat = value(await call(page, 'cgroup_stat', { path: '/user/job' }));
  expect(stat).toMatchObject({
    path: '/user/job',
    'memory.max': '16777216',
    'pids.max': 4,
    'cgroup.freeze': '0',
    'cgroup.procs': [process.pid],
  });
  expect(value(await call(page, 'cgroup_list', { path: '/user' }))).toContain('/user/job');
  // A value cgroup v2 does not take is refused.
  const refused = await call(page, 'cgroup_set', { path: '/user/job', key: 'cpu.weight', value: '0' });
  expect(refused.err.errno).toBe('EINVAL');
  value(await call(page, 'exit', { pid: process.pid, status: 0 }));
  value(await call(page, 'wait', { pid: process.pid }));
  value(await call(page, 'cgroup_remove', { path: '/user/job' }));
  const gone = await call(page, 'cgroup_stat', { path: '/user/job' });
  expect(gone.err.errno).toBe('ENOENT');
  await context.close();
});

test('the protocol is versioned: another version, an unknown call and a refusal each say so', async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto('/');
  await connect(page);
  const foreign = await page.evaluate(() => new Promise(resolve => {
    const port = new Worker('/client-kernel.js');
    port.onmessage = ({ data }) => {
      if (data?.id === 1) { port.terminate(); resolve(data); }
    };
    port.postMessage({ v: 1, id: 1, type: 'init' });
  }));
  expect(foreign).toMatchObject({ v: 2, id: 1, err: { errno: 'EPROTONOSUPPORT' } });
  const oldHello = await page.evaluate(() => new Promise(resolve => {
    const port = new Worker('/client-kernel.js');
    port.onmessage = ({ data }) => {
      if (data?.id === 2) { port.terminate(); resolve(data); }
    };
    port.postMessage({ v: 2, id: 2, type: 'hello', boundary: 'host-adapter', versions: [1] });
  }));
  expect(oldHello).toMatchObject({ v: 2, id: 2, err: { errno: 'EPROTONOSUPPORT' } });
  value(await call(page, 'init'));
  const missing = await call(page, 'session_resolve_exec', { file: '/nowhere', argv: ['nowhere'], cwd: '/', searchPath: false });
  expect(missing.err.errno).toBe('ENOENT');
  const unknown = await call(page, 'no_such_call');
  expect(unknown.err.errno).toBe('ENOSYS');
  await context.close();
});

test('a tab signed out is guest-<uuid>:guest, and its process runs as that account', async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto('/');
  await connect(page);
  value(await call(page, 'init'));
  const [creds] = await sys(page, ['getcreds']);
  expect(creds.ok.user).toMatch(/^guest-[0-9a-f]{16}$/);
  expect(creds.ok.uid).toBeGreaterThanOrEqual(1_000_000);
  expect(creds.ok.uid).toBeLessThan(2_000_000);
  expect([creds.ok.home, creds.ok.signed_in, creds.ok.group]).toEqual(['/guest', false, 'guest']);
  value(await call(page, 'sync_account_from_server'));
  value(await call(page, 'session_begin', { sessionId: 'guest-proc', uid: creds.ok.uid, gid: creds.ok.gid, groups: creds.ok.groups }));
  const process = value(await call(page, 'exec', { path: '/usr/bin/coreutils', argv: ['coreutils', 'id'], env: ENV, cwd: '/' }));
  const [seen] = value(await call(page, 'poll', { pids: [process.pid] }));
  expect([seen.uid, seen.path, seen.argv]).toEqual([creds.ok.uid, '/usr/bin/coreutils', ['coreutils', 'id']]);
  // Instance-local /proc names it while it runs.
  const [status] = value(await call(page, 'vfs_sys', {
    sessionId: 'guest-proc',
    batch: { calls: [{ pread: { path: `/proc/${process.pid}/status`, count: 4096 } }] },
  })).results;
  expect(status.ok).toBeTruthy();
  const text = Buffer.from(status.ok.data, 'base64').toString();
  expect(text).toContain('Name:\tcoreutils');
  expect(text).toContain(`Uid:\t${creds.ok.uid}`);
  value(await call(page, 'exit', { pid: process.pid, status: 0 }));
  value(await call(page, 'wait', { pid: process.pid }));
  const [gone] = value(await call(page, 'vfs_sys', {
    sessionId: 'guest-proc',
    batch: { calls: [{ pread: { path: `/proc/${process.pid}/status`, count: 4096 } }] },
  })).results;
  expect(gone.err.errno).toBe('ENOENT');
  await context.close();
});

// Through the terminal, as a person runs a command, and what ps lists after.
async function command(page, text, { wait = true } = {}) {
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  const busy = page.locator('#command').locator('xpath=ancestor::form');
  await expect(busy).toHaveAttribute('data-state', 'idle');
  await input.fill(text); await input.press('Enter');
  if (wait) await expect(busy).toHaveAttribute('data-state', 'idle', { timeout: 30_000 });
}
async function listed(page) {
  await command(page, 'ps');
  return page.locator('.transcript pre').last().innerText();
}

test('a tab runs processes inside its own isolated kernel instance and closing it leaves other tabs clean', async ({ browser }) => {
  const context = await browser.newContext();
  try {
    const [one, two] = [await context.newPage(), await context.newPage()];
    const kernelOne = await hookPageKernel(one);
    await one.goto('/'); await two.goto('/');
    await kernelOne.ready();
    await command(one, 'coreutils sleep 120', { wait: false });
    await expect.poll(async () => (await kernelOne.value('poll', { pids: [] })).some(p => p.argv?.join(' ').includes('sleep 120')), { timeout: 15_000 }).toBe(true);
    // Contract v2 §2.1: another tab's kernel instance does not observe tab one's processes.
    expect(await listed(two)).not.toContain('sleep 120');
    // Closing tab one tears down its dedicated Worker instance without affecting tab two.
    await one.close();
    expect(await listed(two)).not.toContain('sleep 120');
    await command(two, 'seq 1');
    await expect(two.locator('.transcript pre').last()).toHaveText('1');
  } finally { await context.close(); }
});

test('without SharedWorker, each tab still runs an isolated dedicated kernel instance', async ({ browser }) => {
  const context = await browser.newContext();
  await context.addInitScript(() => { delete globalThis.SharedWorker; });
  try {
    const [one, two] = [await context.newPage(), await context.newPage()];
    const kernelOne = await hookPageKernel(one);
    await one.goto('/'); await two.goto('/');
    await kernelOne.ready();
    expect(await one.evaluate(() => typeof SharedWorker)).toBe('undefined');
    // Pipes and processes work as before, through this tab's own dedicated kernel.
    await command(one, 'seq 3 | tr 123 abc');
    await expect(one.locator('.transcript pre').last()).toHaveText('a\nb\nc');
    // Another tab's kernel is isolated from what tab one runs.
    await command(one, 'coreutils sleep 120', { wait: false });
    await expect.poll(async () => (await kernelOne.value('poll', { pids: [] })).some(p => p.argv?.join(' ').includes('sleep 120')), { timeout: 15_000 }).toBe(true);
    await command(two, 'seq 1');
    expect(await listed(two)).not.toContain('sleep 120');
    // Closing tab one leaves a fresh tab completely clean with its own isolated instance.
    await one.close();
    const three = await context.newPage();
    await three.goto('/');
    expect(await listed(three)).not.toContain('sleep 120');
  } finally { await context.close(); }
});

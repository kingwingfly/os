import { test, expect } from '@playwright/test';

// The client kernel (crates/client-kernel, web/kernel/client.js): one SharedWorker per browser,
// a process table shared by its tabs, and execve/fork/exit/wait/cgroups asked of the worker
// kernel through /api/sys. A page's port is the versioned envelope web/kernel/protocol.js speaks.

// A page's port to the browser's one client kernel, kept on the page so calls can follow.
async function connect(page) {
  await page.evaluate(() => {
    const port = new SharedWorker('/client-kernel.js').port;
    const pending = new Map();
    let next = 0;
    port.onmessage = ({ data }) => {
      if (data?.id != null && pending.has(data.id)) {
        pending.get(data.id)(data);
        pending.delete(data.id);
      }
    };
    port.start();
    window.__kernel = (type, args = {}) => new Promise(resolve => {
      const id = ++next;
      pending.set(id, resolve);
      port.postMessage({ v: 1, id, type, args });
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

test('two tabs share one client kernel, and each sees the other tab\'s process', async ({ browser }) => {
  const context = await browser.newContext();
  const one = await context.newPage();
  const two = await context.newPage();
  await one.goto('/');
  await two.goto('/');
  await connect(one);
  await connect(two);
  const first = value(await call(one, 'init'));
  const second = value(await call(two, 'init'));
  expect(first.namespace).toBe(second.namespace);
  expect(first.pid).toBe(1);
  // Both tabs' init calls are the same namespace's, not two.
  const running = value(await call(one, 'exec', { path: '/usr/bin/coreutils', argv: ['coreutils', 'sleep', '30'], env: ENV, cwd: '/' }));
  expect(running.pid).toBeGreaterThan(1);
  expect(running.asset).toBe('/usr/bin/coreutils.wasm');
  const polled = value(await call(two, 'poll', { pids: [] }));
  expect(polled.map(process => process.pid)).toContain(running.pid);
  const status = value(await call(two, 'getpid', { pid: running.pid }));
  expect(status).toEqual({ pid: running.pid, ppid: 1 });
  // The process is the account's, in the tab that did not start it.
  const [creds] = await sys(one, ['getcreds']);
  const seen = value(await call(two, 'poll', { pids: [running.pid] }));
  expect(seen[0].uid).toBe(creds.ok.uid);
  // End it, and let the namespace reap it.
  value(await call(one, 'exit', { pid: running.pid, status: 0 }));
  const zombie = value(await call(two, 'poll', { pids: [running.pid] }));
  expect(zombie[0].state).toBe('zombie');
  const reaped = value(await call(two, 'wait', { pid: running.pid }));
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
  // The parent waits: its child's status is waitpid's 7 << 8; the page may not wait for it.
  const reaped = value(await call(page, 'wait', { pid: child.pid }));
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
  value(await call(page, 'cgroup_set', { path: '/user/job', key: 'cgroup.freeze', value: '1' }));
  value(await call(page, 'cgroup_attach', { pid: process.pid, path: '/user/job' }));
  const stat = value(await call(page, 'cgroup_stat', { path: '/user/job' }));
  expect(stat).toMatchObject({
    path: '/user/job',
    'memory.max': '16777216',
    'pids.max': 4,
    'cgroup.freeze': '1',
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
    const port = new SharedWorker('/client-kernel.js').port;
    port.onmessage = ({ data }) => resolve(data);
    port.start();
    port.postMessage({ v: 2, id: 1, type: 'init' });
  }));
  expect(foreign).toMatchObject({ v: 1, id: 1, err: { errno: 'EPROTO' } });
  value(await call(page, 'init'));
  const missing = await call(page, 'exec', { path: '/nowhere', argv: ['nowhere'], env: ENV, cwd: '/' });
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
  const process = value(await call(page, 'exec', { path: '/usr/bin/coreutils', argv: ['coreutils', 'id'], env: ENV, cwd: '/' }));
  const [seen] = value(await call(page, 'poll', { pids: [process.pid] }));
  expect([seen.uid, seen.path, seen.argv]).toEqual([creds.ok.uid, '/usr/bin/coreutils', ['coreutils', 'id']]);
  // /proc names it while it runs.
  const [status] = await sys(page, [{ pread: { path: `/proc/${process.pid}/status`, count: 4096 } }]);
  expect(status.ok).toBeTruthy();
  const text = Buffer.from(status.ok.data, 'base64').toString();
  expect(text).toContain('Name:\tcoreutils');
  expect(text).toContain(`Uid:\t${creds.ok.uid}`);
  value(await call(page, 'exit', { pid: process.pid, status: 0 }));
  value(await call(page, 'wait', { pid: process.pid }));
  const [gone] = await sys(page, [{ pread: { path: `/proc/${process.pid}/status`, count: 4096 } }]);
  expect(gone.err.errno).toBe('ENOENT');
  await context.close();
});

// Through the terminal, as a person runs a command, and what ps lists after.
async function command(page, text, { wait = true } = {}) {
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  const busy = page.locator('#command').locator('xpath=ancestor::form').locator('.busy');
  await expect(busy).toHaveText('↵');
  await input.fill(text); await input.press('Enter');
  if (wait) await expect(busy).toHaveText('↵', { timeout: 30_000 });
}
async function listed(page) {
  await command(page, 'ps');
  return page.locator('.transcript pre').last().innerText();
}

test('a tab that goes leaves no process running: the kernel reaps it by the tab\'s lock', async ({ browser }) => {
  const context = await browser.newContext();
  try {
    const [one, two] = [await context.newPage(), await context.newPage()];
    await one.goto('/'); await two.goto('/');
    await command(one, 'coreutils sleep 120', { wait: false });
    await expect.poll(() => listed(two), { timeout: 15_000 }).toContain('sleep 120');
    // The tab that ran it closes while it runs: its lock is let go, and the kernel reaps it.
    await one.close();
    await expect.poll(() => listed(two), { timeout: 15_000 }).not.toContain('sleep 120');
  } finally { await context.close(); }
});

test('without SharedWorker, each tab runs a kernel of its own, reaping only what gone tabs left', async ({ browser }) => {
  const context = await browser.newContext();
  await context.addInitScript(() => { delete globalThis.SharedWorker; });
  try {
    const [one, two] = [await context.newPage(), await context.newPage()];
    await one.goto('/'); await two.goto('/');
    expect(await one.evaluate(() => typeof SharedWorker)).toBe('undefined');
    // Pipes and processes work as before, through this tab's own kernel.
    await command(one, 'seq 3 | tr 123 abc');
    await expect(one.locator('.transcript pre').last()).toHaveText('a\nb\nc');
    // Another tab's kernel, starting, does not reap what a live tab runs.
    await command(one, 'coreutils sleep 120', { wait: false });
    await command(two, 'seq 1');
    await expect.poll(() => listed(two), { timeout: 15_000 }).toContain('sleep 120');
    // Once its tab is gone, the next kernel to start reaps it.
    await one.close();
    const three = await context.newPage();
    await three.goto('/');
    await expect.poll(() => listed(three), { timeout: 15_000 }).not.toContain('sleep 120');
  } finally { await context.close(); }
});

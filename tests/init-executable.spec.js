import { executableAsset } from './executable-asset.js';
import { test, expect } from './test.js';
import { call, sys } from './sys.js';
import { connectKernel, hookPageKernel } from './service-auth.js';
import { randomBytes, randomUUID } from 'node:crypto';

const secret = () => randomBytes(32).toString('hex');

async function freshKernel(page, name = '__initExecKernel') {
  await page.goto('/login');
  const kernel = await connectKernel(page, { name });
  await kernel.value('machine_init_leave');
  return kernel;
}

async function invoke(kernel, action, errno) {
  const result = await kernel.call('machine_init_action', { action });
  if (errno) {
    expect(result.err?.errno, JSON.stringify(result)).toBe(errno);
    return;
  }
  expect(result.err, JSON.stringify(result)).toBeUndefined();
  return result.ok;
}

async function claim(kernel) {
  const view = await invoke(kernel, { op: 'inspect' });
  const owner = { boot: view.boot, generation: view.generation, host: randomUUID(), proof: secret() };
  const next = await invoke(kernel, { op: 'claim', owner });
  owner.generation = next.generation;
  return owner;
}

const spawnProc = kernel =>
  kernel.value('exec', { path: '/usr/bin/coreutils', argv: ['true'], env: [], cwd: '/' });

async function exitProc(kernel, p, status = 0) {
  await kernel.value('exit', { pid: p.pid, status });
}

const status = page => page.evaluate(() => window.os.machineInit());

async function ready(page, pageKernel) {
  await call(page.request, 'getcreds');
  await page.goto('/');
  await pageKernel.ready();
  await expect.poll(async () => (await status(page))?.reaper?.state, { timeout: 20_000 }).toBe('running');
  await expect
    .poll(async () => (await invoke(pageKernel, { op: 'inspect' })).execution?.role, { timeout: 20_000 })
    .toBe('init-reaper');
}

test('boot requires the current private owner, is idempotent, and issues no account authority', async ({ page, request }) => {
  await call(request, 'getcreds');
  const kernel = await freshKernel(page);
  try {
    const owner = await claim(kernel), token = secret();
    await invoke(kernel, { op: 'start', owner: { ...owner, proof: secret() }, token }, 'EACCES');
    await invoke(kernel, { op: 'start', owner, token: 'short' }, 'EINVAL');
    const started = await invoke(kernel, { op: 'start', owner, token });
    expect((await invoke(kernel, { op: 'start', owner, token })).execution).toEqual(started.execution);
    await invoke(kernel, { op: 'start', owner, token: secret() }, 'EBUSY');
    expect(JSON.stringify(started)).not.toContain(token);
    expect(JSON.stringify(started)).not.toContain(owner.proof);

    const booted = await kernel.value('boot_init', { owner, token });
    expect(booted).toMatchObject({ pid: 1, ppid: 0, token: '' });
    expect(await kernel.value('process_call', { pid: 1, call: 'getpid' })).toEqual({ pid: 1, ppid: 0 });
    expect(await kernel.value('getcreds_proc', { pid: 1 })).toMatchObject({
      has_remote: false,
      cloud_access: false,
    });

    // PID 1 cannot be exited, killed with SIGKILL, moved out of /init, waited on as a child, or reparented.
    expect((await kernel.call('exit', { pid: 1, status: 0 })).err?.errno).toBe('EPERM');
    expect((await kernel.call('kill', { pid: 1, signal: 9 })).err?.errno).toBe('EPERM');
    expect((await kernel.call('cgroup_attach', { pid: 1, path: '/user' })).err?.errno).toBe('EPERM');
    expect((await kernel.call('wait', { pid: 1 })).err?.errno).toBe('ECHILD');
    for (const value of ['setsid', { setpgid: { pid: 1, pgid: 1 } }]) {
      expect((await kernel.call('process_call', { pid: 1, call: value })).err?.errno, JSON.stringify(value)).toBe('EPERM');
    }

    // Presenting the local boot token to the server grants no account authority and X-Registry fails closed.
    for (const value of ['getcreds', { stat: { path: '/etc/shadow' } }]) {
      const [result] = await sys(request, [value], { pid: 1, proc: token });
      expect(result.err, JSON.stringify(result)).toBeTruthy();
    }
    const regResp = await request.post('/api/sys', {
      headers: {
        Origin: process.env.OS_TEST_URL || 'http://127.0.0.1:8787',
        'Content-Type': 'application/json',
        'X-Registry': '1',
      },
      data: { calls: ['getcreds'] },
    });
    expect(regResp.status()).toBe(403);

    await invoke(kernel, { op: 'release', owner });
  } finally {
    await kernel.terminate();
  }
});

test('takeover revokes old reaping, heartbeat, and delayed exit proofs', async ({ page }) => {
  const kernel = await freshKernel(page);
  const other = await connectKernel(page, { name: '__otherInitKernel' });
  try {
    const owner = await claim(kernel), token = secret();
    await invoke(kernel, { op: 'start', owner, token });
    await invoke(kernel, { op: 'release', owner });

    const next = await claim(kernel), fresh = secret();
    await invoke(kernel, { op: 'start', owner: next, token: fresh });
    await invoke(kernel, { op: 'start', owner, token }, 'ESTALE');
    await invoke(kernel, { op: 'renew', owner }, 'ESTALE');
    await invoke(kernel, { op: 'release', owner }, 'ESTALE');

    // A separate kernel instance is isolated and cannot use `owner` or `next` proofs.
    expect((await other.call('machine_init_action', { action: { op: 'start', owner: next, token: fresh } })).err?.errno).toBe('ESTALE');
    expect((await other.call('machine_init_action', { action: { op: 'release', owner: next } })).err?.errno).toBe('ESTALE');

    await kernel.value('boot_init', { owner: next, token: fresh });
    expect((await kernel.value('process_call', { pid: 1, call: 'getpid' })).pid).toBe(1);
    expect((await kernel.call('exit', { pid: 1, status: 0 })).err?.errno).toBe('EPERM');

    await invoke(kernel, { op: 'release', owner: next });
    expect((await invoke(kernel, { op: 'inspect' })).execution).toBe(null);
  } finally {
    await other.terminate();
    await kernel.terminate();
  }
});

test('PID 1 reaps reparented zombies exactly once without consuming a live parents child', async ({ page }) => {
  const kernel = await freshKernel(page);
  try {
    const owner = await claim(kernel), token = secret();
    await kernel.value('boot_init', { owner, token });
    const parent = await spawnProc(kernel);
    const child = await kernel.value('fork', { pid: parent.pid });
    await exitProc(kernel, child, 23);
    expect((await kernel.call('process_call', { pid: 1, call: { waitpid: { pid: child.pid, options: 1 } } })).err?.errno).toBe('ECHILD');
    await exitProc(kernel, parent, 0);
    for (const p of [child, parent]) {
      const waited = await kernel.value('process_call', { pid: 1, call: { waitpid: { pid: p.pid, options: 1 } } });
      expect(waited.pid).toBe(p.pid);
      expect(waited.code).toBe(p === child ? 23 : 0);
      expect((await kernel.call('process_call', { pid: 1, call: { waitpid: { pid: p.pid, options: 1 } } })).err?.errno).toBe('ECHILD');
    }
    expect((await invoke(kernel, { op: 'inspect' })).execution.reaped).toBe(2);
    await invoke(kernel, { op: 'release', owner });
  } finally {
    await kernel.terminate();
  }
});

test('the browser boots an executable PID 1 and it reaps orphaned children', async ({ page }) => {
  const pageKernel = await hookPageKernel(page);
  await ready(page, pageKernel);
  const before = await invoke(pageKernel, { op: 'inspect' });
  const parent = await spawnProc(pageKernel);
  const child = await pageKernel.value('fork', { pid: parent.pid });
  await exitProc(pageKernel, child, 23);
  await exitProc(pageKernel, parent, 0);
  await expect
    .poll(async () => (await invoke(pageKernel, { op: 'inspect' })).execution?.reaped, { timeout: 15_000 })
    .toBeGreaterThanOrEqual((before.execution?.reaped ?? 0) + 2);
  expect(await pageKernel.value('poll', { pids: [parent.pid, child.pid] })).toEqual([]);
  expect((await status(page)).reaper.state).toBe('running');
  // An installed copy launched normally cannot become PID 1 or acquire its capability.
  await page.locator('#command').fill('init');
  await page.locator('#command').press('Enter');
  await expect(page.locator('.terminal-screen')).toContainText(/requires (?:PID 1|the Machine) boot capability/);
});

test('host loss starts a replacement executable while keeping the Machine boot', async ({ page, context }) => {
  const pageKernel = await hookPageKernel(page);
  await ready(page, pageKernel);
  const before = await status(page);

  // Per Contract v2 §2.1, another tab runs its own isolated instance with its own boot and PID 1.
  const other = await context.newPage();
  try {
    await other.goto('/');
    await expect.poll(async () => (await status(other))?.reaper?.state, { timeout: 20_000 }).toBe('running');
    expect((await status(other)).init.boot).not.toBe(before.init.boot);

    // Releasing and resuming ownership within the same instance preserves its boot ID,
    // advances generation, starts a replacement executable PID 1, and reaps newly orphaned children.
    await pageKernel.value('machine_init_leave');
    await expect.poll(async () => (await status(page)).coordinator, { timeout: 10_000 }).toBe(false);
    await pageKernel.value('machine_init_resume');
    await expect.poll(async () => (await status(page)).reaper?.state, { timeout: 20_000 }).toBe('running');
    const after = await status(page);
    expect(after.init.boot).toBe(before.init.boot);
    expect(after.init.generation).toBeGreaterThan(before.init.generation);
    const child = await spawnProc(pageKernel);
    await exitProc(pageKernel, child, 0);
    await expect
      .poll(async () => (await invoke(pageKernel, { op: 'inspect' })).execution?.reaped, { timeout: 15_000 })
      .toBeGreaterThan(0);
  } finally {
    await other.close();
  }
});

test('a failed image load releases its execution and retries with a fresh generation', async ({ page, context }) => {
  let loads = 0;
  const pageKernel = await hookPageKernel(page);
  await page.addInitScript(() => {
    window.initEvents = [];
    addEventListener('os:machine-init', event => window.initEvents.push(event.detail));
  });
  await context.route(executableAsset('init'), async route => {
    if (++loads === 1) {
      return route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ errno: 'EIO', error: 'temporary init image outage' }),
      });
    }
    await route.continue();
  });
  await call(page.request, 'getcreds');
  await page.goto('/');
  await pageKernel.ready();
  await expect.poll(async () => (await status(page))?.reaper?.state, { timeout: 20_000 }).toBe('running');
  // At least 2 loads (failed 503 attempt #1 + succeeded attempt #2); PID 1 may also launch
  // `/usr/bin/init --user <uid>` (`user-session@<uid>.service`) which loads the same asset.
  expect(loads).toBeGreaterThanOrEqual(2);
  const after = await status(page);
  expect(after.reaper.attempts).toBe(2);
  const failed = await page.evaluate(() => window.initEvents.find(event => event.reaper?.state === 'failed'));
  expect(failed.reaper.error).toContain('temporary init image outage');
  expect(after.init.generation).toBeGreaterThan(failed.init.generation);
  const child = await spawnProc(pageKernel);
  await exitProc(pageKernel, child, 0);
  await expect
    .poll(async () => (await invoke(pageKernel, { op: 'inspect' })).execution?.reaped, { timeout: 15_000 })
    .toBeGreaterThan(0);
});

test('an idle executable init does not poll waitpid over the network', async ({ page, context }) => {
  let waits = 0;
  context.on('request', request => {
    if (!request.url().endsWith('/api/sys') || request.method() !== 'POST') return;
    const batch = request.postDataJSON();
    if (batch?.pid === 1 && Array.isArray(batch.calls)) {
      waits += batch.calls.filter(c => c?.waitpid).length;
    }
  });
  const pageKernel = await hookPageKernel(page);
  await ready(page, pageKernel);
  await page.waitForTimeout(700);
  expect(waits).toBe(0);
  expect((await status(page)).reaper.state).toBe('running');
  // Reaping an orphaned child also happens 100% locally with zero network waitpid RPCs.
  const child = await spawnProc(pageKernel);
  await exitProc(pageKernel, child, 0);
  await expect.poll(async () => (await pageKernel.value('poll', { pids: [child.pid] })).length, { timeout: 15_000 }).toBe(0);
  expect(waits).toBe(0);
});

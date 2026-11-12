import { executableAsset } from './executable-asset.js';
import { test, expect } from './test.js';
import { call, sys } from './sys.js';
import { randomBytes, randomUUID } from 'node:crypto';

const registry = { 'X-Registry': '1' };
const secret = () => randomBytes(32).toString('hex');
async function invoke(request, action, errno) {
  const [result] = await sys(request, [{ machine_init: { action } }], {}, registry);
  if (errno) { expect(result.err?.errno, JSON.stringify(result)).toBe(errno); return; }
  expect(result.err, JSON.stringify(result)).toBeUndefined(); return result.ok;
}
async function claim(request) {
  await call(request, 'getcreds');
  const view = await invoke(request, { op: 'inspect' });
  const owner = { boot: view.boot, generation: view.generation, host: randomUUID(), proof: secret() };
  const next = await invoke(request, { op: 'claim', owner });
  owner.generation = next.generation;
  return owner;
}
const process = request => call(request, { execve: { path: '/usr/bin/coreutils', argv: ['true'], env: [], cwd: '/' } });
const proof = p => ({ pid: p.pid, proc: p.token });
async function exit(request, p, status = 0) {
  const [result] = await sys(request, [{ exit: { ...proof(p), status } }], {}, registry);
  expect(result.err).toBeUndefined();
}
async function reaperCall(request, token, value) {
  return (await sys(request, [value], { pid: 1, proc: token }, registry))[0];
}
const status = page => page.evaluate(() => window.os.machineInit());
async function ready(page) {
  await page.goto('/');
  await expect.poll(async () => (await status(page))?.reaper?.state).toBe('running');
  await expect.poll(async () => (await invoke(page.request, { op: 'inspect' })).execution?.role).toBe('init-reaper');
}

test('boot requires the current private owner, is idempotent, and issues no account authority', async ({ request }) => {
  const owner = await claim(request), token = secret();
  await invoke(request, { op: 'start', owner: { ...owner, proof: secret() }, token }, 'EACCES');
  await invoke(request, { op: 'start', owner, token: 'short' }, 'EINVAL');
  const started = await invoke(request, { op: 'start', owner, token });
  expect((await invoke(request, { op: 'start', owner, token })).execution).toEqual(started.execution);
  await invoke(request, { op: 'start', owner, token: secret() }, 'EBUSY');
  expect(JSON.stringify(started)).not.toContain(token);
  expect(JSON.stringify(started)).not.toContain(owner.proof);
  expect((await reaperCall(request, token, 'getpid')).ok).toEqual({ pid: 1, ppid: 0 });
  // A boot proof is not the reserved row's ordinary process token.
  expect((await sys(request, [{ wait: { pid: '1', proc: token } }], {}, registry))[0].err?.errno).toBe('EPERM');
  for (const value of [
    { pids: { count: 1 } }, { fork: { pid: 1 } }, { kill: { pid: '-1', signal: 9 } },
    { cgroup_create: { path: '/system/boot-proof' } }, { proc_poll: { pids: [1] } },
    'setsid', { setpgid: { pid: 1, pgid: 1 } },
  ]) expect((await reaperCall(request, token, value)).err?.errno, JSON.stringify(value)).toBe('EPERM');
  for (const value of ['getcreds', { stat: { path: '/etc/shadow' } },
    { execve: { pid: 1, proc: token, path: '/usr/bin/sh', argv: ['sh'], env: [], cwd: '/' } }]) {
    const [result] = await sys(request, [value], { pid: 1, proc: token });
    expect(result.err, JSON.stringify(result)).toBeTruthy();
  }
  for (const value of [
    { fork: { pid: 1, proc: token } },
    { execve: { pid: 1, proc: token, path: '/usr/bin/sh', argv: ['sh'], env: [], cwd: '/' } },
    { proc_tty: { pid: 1, proc: token, tty: 2, fds: [0] } },
  ]) expect((await sys(request, [value], {}, registry))[0].err?.errno).toBe('EPERM');
  await invoke(request, { op: 'release', owner });
});

test('takeover revokes old reaping, heartbeat, and delayed exit proofs', async ({ request }) => {
  const owner = await claim(request), token = secret();
  await invoke(request, { op: 'start', owner, token });
  await invoke(request, { op: 'release', owner });
  const next = await claim(request), fresh = secret();
  await invoke(request, { op: 'start', owner: next, token: fresh });
  expect((await reaperCall(request, token, { waitpid: { pid: -1, options: 1 } })).err?.errno).toBe('EPERM');
  const [kept, ended] = await sys(request, [
    { proc_keep: { processes: [{ pid: 1, proc: token, signals: [] }] } },
    { exit: { pid: 1, proc: token, status: 0 } },
  ], {}, registry);
  expect(kept.ok).toEqual([]); expect(ended.err?.errno).toBe('ESRCH');
  await invoke(request, { op: 'start', owner, token }, 'ESTALE');
  expect((await reaperCall(request, fresh, 'getpid')).ok.pid).toBe(1);
  await exit(request, { pid: 1, token: fresh });
  expect((await invoke(request, { op: 'inspect' })).execution).toBe(null);
  expect((await reaperCall(request, fresh, 'getpid')).err?.errno).toBe('EPERM');
  await invoke(request, { op: 'release', owner: next });
});

test('PID 1 reaps reparented zombies exactly once without consuming a live parents child', async ({ request }) => {
  const owner = await claim(request), token = secret();
  await invoke(request, { op: 'start', owner, token });
  const parent = await process(request);
  const [forked] = await sys(request, [{ fork: { pid: parent.pid, proc: parent.token } }], {}, registry);
  expect(forked.err).toBeUndefined();
  const child = { pid: forked.ok.pid, token: parent.token };
  await exit(request, child, 23);
  expect((await reaperCall(request, token, { waitpid: { pid: child.pid, options: 1 } })).err?.errno).toBe('ECHILD');
  await exit(request, parent);
  for (const p of [child, parent]) {
    const waited = await reaperCall(request, token, { waitpid: { pid: p.pid, options: 1 } });
    expect(waited.ok.pid).toBe(p.pid); expect(waited.ok.code).toBe(p === child ? 23 : 0);
    expect((await reaperCall(request, token, { waitpid: { pid: p.pid, options: 1 } })).err?.errno).toBe('ECHILD');
  }
  expect((await invoke(request, { op: 'inspect' })).execution.reaped).toBe(2);
  await invoke(request, { op: 'release', owner });
});

test('the browser boots an executable PID 1 and it reaps orphaned children', async ({ page }) => {
  await ready(page);
  const before = await invoke(page.request, { op: 'inspect' });
  const parent = await process(page.request);
  const [forked] = await sys(page.request, [{ fork: { pid: parent.pid, proc: parent.token } }], {}, registry);
  expect(forked.err).toBeUndefined();
  await exit(page.request, { pid: forked.ok.pid, token: parent.token }, 23);
  await exit(page.request, parent);
  await expect.poll(async () => (await invoke(page.request, { op: 'inspect' })).execution?.reaped, { timeout: 15_000 }).toBeGreaterThanOrEqual(before.execution.reaped + 2);
  expect((await sys(page.request, [{ proc_poll: { pids: [parent.pid, forked.ok.pid] } }], {}, registry))[0].ok).toEqual([]);
  expect((await status(page)).reaper.state).toBe('running');
  // An installed copy launched normally cannot become PID 1 or acquire its capability.
  await page.locator('#command').fill('init'); await page.locator('#command').press('Enter');
  await expect(page.locator('.terminal-screen')).toContainText('requires the Machine boot capability');
});

test('host loss starts a replacement executable while keeping the Machine boot', async ({ page, context }) => {
  await ready(page); const before = await status(page);
  const other = await context.newPage(); await other.goto('/');
  await expect.poll(async () => (await status(other))?.connected).toBe(true);
  expect((await status(other)).reaper.state).toBe('waiting');
  await page.close();
  await expect.poll(async () => (await status(other)).reaper.state, { timeout: 45_000, intervals: [500] }).toBe('running');
  const after = await status(other);
  expect(after.init.boot).toBe(before.init.boot);
  expect(after.init.generation).toBeGreaterThan(before.init.generation);
  const child = await process(other.request); await exit(other.request, child);
  await expect.poll(async () => (await invoke(other.request, { op: 'inspect' })).execution?.reaped, { timeout: 15_000 }).toBeGreaterThan(0);
});

test('a failed image load releases its execution and retries with a fresh generation', async ({ page, context }) => {
  let loads = 0;
  await page.addInitScript(() => {
    window.initEvents = [];
    addEventListener('os:machine-init', event => window.initEvents.push(event.detail));
  });
  await context.route(executableAsset('init'), async route => {
    if (++loads === 1) return route.fulfill({ status: 503, contentType: 'application/json',
      body: JSON.stringify({ errno: 'EIO', error: 'temporary init image outage' }) });
    await route.continue();
  });
  await page.goto('/');
  await expect.poll(async () => (await status(page))?.reaper?.state, { timeout: 20_000 }).toBe('running');
  expect(loads).toBe(2);
  const after = await status(page);
  expect(after.reaper.attempts).toBe(2);
  const failed = await page.evaluate(() => window.initEvents.find(event => event.reaper?.state === 'failed'));
  expect(failed.reaper.error).toContain('temporary init image outage');
  expect(after.init.generation).toBeGreaterThan(failed.init.generation);
  const child = await process(page.request); await exit(page.request, child);
  await expect.poll(async () => (await invoke(page.request, { op: 'inspect' })).execution?.reaped, { timeout: 15_000 }).toBeGreaterThan(0);
});

test('an idle executable init does not poll waitpid over the network', async ({ page, context }) => {
  let waits = 0;
  context.on('request', request => {
    if (!request.url().endsWith('/api/sys') || request.method() !== 'POST') return;
    const batch = request.postDataJSON();
    if (batch.pid === 1) waits += batch.calls.filter(call => call.waitpid).length;
  });
  await ready(page);
  await expect.poll(() => waits).toBeGreaterThan(0); // Observe the executable's startup drain.
  const before = waits;
  await page.waitForTimeout(700);
  expect(waits).toBe(before);
  expect((await status(page)).reaper.state).toBe('running');
});

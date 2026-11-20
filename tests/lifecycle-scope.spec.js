import { test, expect } from './test.js';
import { api, call } from './sys.js';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const password = process.env.OS_TEST_ADMIN_PASSWORD || (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];

async function signIn(request) {
  expect((await api(request, 'login', {
    headers: { 'CF-Connecting-IP': 'lifecycle-scope-' + randomUUID() },
    data: { password },
  })).ok()).toBe(true);
}

async function connect(page) {
  await page.goto('/login');
  await page.evaluate(() => {
    const worker = new Worker('/client-kernel.js');
    const pending = new Map();
    let next = 0;
    worker.onmessage = ({ data }) => {
      if (data?.id != null && pending.has(data.id)) {
        pending.get(data.id)(data);
        pending.delete(data.id);
      }
    };
    window.scopeKernel = (type, args = {}) => new Promise(resolve => {
      const id = ++next;
      pending.set(id, resolve);
      worker.postMessage({ v: 2, id, type, args });
    });
  });
  const init = await kc(page, 'init');
  expect(init.err, JSON.stringify(init)).toBeUndefined();
}
const kc = (page, type, args = {}) => page.evaluate(([type, args]) => window.scopeKernel(type, args), [type, args]);
async function kv(page, type, args = {}) {
  const r = await kc(page, type, args);
  expect(r.err, `${type}: ${JSON.stringify(r)}`).toBeUndefined();
  return r.ok;
}
async function login(page, action) {
  return kv(page, 'login_session_action', { action });
}

test('an unattached process from an earlier login cannot be moved into the current managed scope', async ({ page }) => {
  await connect(page);
  await kv(page, 'sync_account', { uid: 0, gid: 0, groups: [0], user: 'root', group: 'root', home: '/root', shell: '/usr/bin/dash', signed_in: true });
  const p = await kv(page, 'exec', { path: '/usr/bin/sleep', argv: ['sleep', '60'], cwd: '/', env: [] });
  await kv(page, 'session', { pids: [p.pid] });
  // Switch to a fresh login scope (account change / re-login starts a new session id).
  await kv(page, 'sync_account', { uid: 65534, gid: 65534, groups: [65534], user: 'guest', group: 'guest', home: '/tmp', shell: '/usr/bin/dash', signed_in: false });
  await kv(page, 'sync_account', { uid: 0, gid: 0, groups: [0], user: 'root', group: 'root', home: '/root', shell: '/usr/bin/dash', signed_in: true });

  const host = { host: randomUUID(), proof: randomBytes(32).toString('hex') };
  const joined = await login(page, { op: 'join', ...host });
  const member = { ...host, session: joined.id };
  const owner = await login(page, { op: 'claim', member, generation: joined.generation });
  const denied = await kc(page, 'login_session_action', {
    action: { op: 'attach', member, generation: owner.generation, process: { pid: p.pid, proc: p.token, signals: [] } },
  });
  expect(denied.err?.errno).toBe('EPERM');
  expect((await login(page, { op: 'inspect' })).managed).toBe(null);
  expect((await login(page, { op: 'end', session: joined.id })).shutdown.complete).toBe(true);
  expect((await kv(page, 'getpid', { pid: p.pid })).pid).toBe(p.pid);
  await kv(page, 'exit', { pid: p.pid, status: 0 });
  await kv(page, 'wait', { pid: p.pid });
});

test('the greeter exposes restart only to root and completes the real Machine restart control', async ({ page }) => {
  await page.goto('/login');
  await expect(page.getByRole('button', { name: 'Continue as guest', exact: true })).toBeEnabled();
  await expect(page.getByRole('button', { name: 'Restart Machine', exact: true })).toHaveCount(0);
  await signIn(page.request);
  await page.reload();
  await expect(page.getByRole('button', { name: 'Continue as root', exact: true })).toBeEnabled();
  await page.getByText('Session controls', { exact: true }).click();
  const before = await page.evaluate(() => window.osGreeter.state().boot);
  expect(before?.boot).toBeTruthy();
  await page.getByRole('button', { name: 'Restart Machine', exact: true }).click();
  await expect(page.getByRole('status')).toContainText('Machine restarted');
  const after = await page.evaluate(async () => {
    await window.osGreeter.identity();
    return window.osGreeter.state().boot;
  });
  expect(after?.boot).not.toBe(before.boot);
  await expect(page.getByRole('button', { name: 'Continue as root', exact: true })).toBeEnabled();
});

test('a shutdown handler can fork and exec cleanup while retaining its original login scope', async ({ page }) => {
  test.setTimeout(60000);
  await page.goto('/');
  await expect.poll(async () => (await page.evaluate(() => window.os.loginSession())).connected).toBe(true);
  await page.evaluate(() => {
    window.cleanupOutput = '';
    window.cleanupRun = window.os.exec([['sh', '-c', "trap 'printf CLEANUP-FORK | cat; exit 0' HUP TERM; echo CLEANUP-READY; while :; do sleep 1; done"]], {
      tty: true, stdin: '', onOutput: (_fd, text) => { window.cleanupOutput += text; },
    });
  });
  await expect.poll(() => page.evaluate(() => window.cleanupOutput)).toContain('CLEANUP-READY');
  await page.evaluate(async () => window.os.endLoginSession((await window.os.loginSession()).session));
  await expect.poll(() => page.evaluate(() => window.cleanupOutput), { timeout: 15000 }).toContain('CLEANUP-FORK');
  await expect.poll(async () => (await page.evaluate(() => window.os.loginSession())).session?.shutdown?.complete).toBe(true);
});

test('an account switch during greeter loading cannot pair one account label with another session control', async ({ page, context }) => {
  await call(page.request, 'getcreds');
  await signIn(page.request);
  let changed = false;
  await context.route('**/api/sys', async route => {
    const body = route.request().postDataJSON();
    if (changed || !body.calls?.includes('getcreds')) return route.fallback();
    changed = true;
    const response = await route.fetch();
    await api(page.request, 'logout');
    return route.fulfill({ response });
  });
  await page.goto('/login');
  await expect(page.getByRole('alert')).toContainText('account changed while loading');
  await expect(page.getByRole('button', { name: 'End session', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Restart Machine', exact: true })).toHaveCount(0);
  await context.unroute('**/api/sys');
  await page.getByRole('button', { name: 'Retry connection', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Continue as guest', exact: true })).toBeEnabled();
});

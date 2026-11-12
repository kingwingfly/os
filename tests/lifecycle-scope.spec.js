import { test, expect } from './test.js';
import { api, call, sys } from './sys.js';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const registry = { 'X-Registry': '1' };
async function signIn(request) {
  expect((await api(request, 'login', { headers: { 'CF-Connecting-IP': 'lifecycle-scope-' + randomUUID() }, data: { password } })).ok()).toBe(true);
}
async function login(request, action) {
  const [result] = await sys(request, [{ login_session: { action } }], {}, registry);
  expect(result.err).toBeUndefined(); return result.ok;
}

test('an unattached process from an earlier login cannot be moved into the current managed scope', async ({ request }) => {
  await call(request, 'getcreds'); await signIn(request);
  const p = await call(request, { execve: { path: '/usr/bin/sleep', argv: ['sleep', '60'] } });
  const proof = { pid: p.pid, proc: p.token };
  expect((await sys(request, [{ proc_session: { processes: [proof] } }], {}, registry))[0].err).toBeUndefined();
  await signIn(request);
  const host = { host: randomUUID(), proof: randomBytes(32).toString('hex') };
  const joined = await login(request, { op: 'join', ...host });
  const member = { ...host, session: joined.id };
  const owner = await login(request, { op: 'claim', member, generation: joined.generation });
  const [denied] = await sys(request, [{ login_session: { action: { op: 'attach', member, generation: owner.generation, process: proof } } }], {}, registry);
  expect(denied.err?.errno).toBe('EPERM');
  expect((await login(request, { op: 'inspect' })).managed).toBe(null);
  expect((await login(request, { op: 'end', session: joined.id })).shutdown.complete).toBe(true);
  expect((await sys(request, ['getpid'], proof, registry))[0].ok.pid).toBe(p.pid);
  await sys(request, [{ exit: { ...proof, status: 0 } }, { wait: { pid: String(p.pid), proc: p.token } }], {}, registry);
});

test('the greeter exposes restart only to root and completes the real Machine restart control', async ({ page }) => {
  await page.goto('/login');
  await expect(page.getByRole('button', { name: 'Continue as guest', exact: true })).toBeEnabled();
  await expect(page.getByRole('button', { name: 'Restart Machine', exact: true })).toHaveCount(0);
  await signIn(page.request); await page.reload();
  await expect(page.getByRole('button', { name: 'Continue as root', exact: true })).toBeEnabled();
  await page.getByText('Session controls', { exact: true }).click();
  const before = (await sys(page.request, [{ machine_init: { action: { op: 'inspect' } } }], {}, registry))[0].ok;
  await page.screenshot({ path: '/home/ai/os-lifecycle-validation/greeter-controls.png' });
  await page.getByRole('button', { name: 'Restart Machine', exact: true }).click();
  await expect(page.getByRole('status')).toContainText('Machine restarted');
  const after = (await sys(page.request, [{ machine_init: { action: { op: 'inspect' } } }], {}, registry))[0].ok;
  expect(after.boot).not.toBe(before.boot);
  await expect(page.getByRole('button', { name: 'Continue as root', exact: true })).toBeEnabled();
});

test('a shutdown handler can fork and exec cleanup while retaining its original login scope', async ({ page }) => {
  test.setTimeout(60000);
  await page.goto('/'); await expect.poll(async () => (await page.evaluate(() => window.os.loginSession())).connected).toBe(true);
  await page.evaluate(() => {
    window.cleanupOutput = '';
    window.cleanupRun = window.os.exec([['sh', '-c', "trap 'printf CLEANUP-FORK | cat; exit 0' HUP TERM; echo CLEANUP-READY; while :; do sleep 1; done"]], {
      tty: true, stdin: '', onOutput: (_fd, text) => { window.cleanupOutput += text; },
    });
  });
  await expect.poll(() => page.evaluate(() => window.cleanupOutput)).toContain('CLEANUP-READY');
  await page.evaluate(async () => window.os.endLoginSession((await window.os.loginSession()).session));
  await expect.poll(() => page.evaluate(() => window.cleanupOutput), { timeout: 15000 }).toContain('CLEANUP-FORK');
  await expect.poll(async () => (await login(page.request, { op: 'inspect' })).shutdown.complete).toBe(true);
});

test('an account switch during greeter loading cannot pair one account label with another session control', async ({ page, context }) => {
  await call(page.request, 'getcreds');
  await login(page.request, { op: 'join', host: randomUUID(), proof: randomBytes(32).toString('hex') });
  await signIn(page.request);
  let changed = false;
  await context.route('**/api/sys', async route => {
    const body = route.request().postDataJSON();
    if (changed || !body.calls?.includes('getcreds')) return route.fallback();
    changed = true; const response = await route.fetch();
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

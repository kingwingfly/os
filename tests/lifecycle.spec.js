import { executableAsset } from './executable-asset.js';
import { test, expect } from './test.js';
import { api, call, sys, put, rmrf } from './sys.js';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
test.setTimeout(70000);
const registry = { 'X-Registry': '1' };
const proof = p => ({ pid: p.pid, proc: p.token });
async function action(request, kind, value, errno, options = {}) {
  const [result] = await sys(request, [{ [kind]: { action: value } }], options, registry);
  if (errno) { expect(result.err?.errno, JSON.stringify(result)).toBe(errno); return; }
  expect(result.err, JSON.stringify(result)).toBeUndefined(); return result.ok;
}
const login = (request, value = { op: 'inspect' }, errno, options) => action(request, 'login_session', value, errno, options);
const init = (request, value = { op: 'inspect' }, errno, options) => action(request, 'machine_init', value, errno, options);
const launch = request => call(request, { execve: { path: '/usr/bin/sleep', argv: ['sleep', '60'], cwd: '/', env: [] } });
async function finish(request, p) {
  await sys(request, [{ exit: { ...proof(p), status: 0 } }, { wait: { pid: String(p.pid), proc: p.token } }], {}, registry);
}
async function signIn(request) {
  expect((await api(request, 'login', { headers: { 'CF-Connecting-IP': 'lifecycle-' + randomUUID() }, data: { password } })).ok()).toBe(true);
}
async function processCall(request, p, command) {
  const [result] = await sys(request, [command], proof(p), registry);
  expect(result.err, JSON.stringify(result)).toBeUndefined(); return result.ok;
}

test('ending an exact login is authenticated, idempotent and fences new launches until explicit restart', async ({ request }) => {
  await call(request, 'getcreds'); const p = await launch(request), original = await login(request);
  expect(original.shutdown).toBe(null);
  await login(request, { op: 'end', session: 'stale' }, 'ESTALE');
  await login(request, { op: 'end', session: original.id }, 'EPERM', proof(p));
  await login(request, { op: 'end', session: original.id }, 'EPERM', { sudo: true });
  await signIn(request); const root = await launch(request);
  await login(request, { op: 'end', session: original.id }, 'ESTALE');
  await api(request, 'logout');
  const stopped = await login(request, { op: 'end', session: original.id });
  const retry = await login(request, { op: 'end', session: original.id });
  expect(retry.shutdown.deadline).toBe(stopped.shutdown.deadline);
  expect((await sys(request, [{ execve: { path: '/usr/bin/true' } }]))[0].err.errno).toBe('EBUSY');
  await login(request, { op: 'restart', session: original.id }, 'EBUSY');
  expect((await processCall(request, root, 'getpid')).pid).toBe(root.pid);
  await finish(request, p);
  expect((await login(request)).shutdown.complete).toBe(true);
  const next = await login(request, { op: 'restart', session: original.id });
  expect(next.id).not.toBe(original.id); expect(next.shutdown).toBe(null);
  await login(request, { op: 'end', session: original.id }, 'ESTALE');
  const replacement = await launch(request); expect(replacement.pid).toBeGreaterThan(root.pid);
  await finish(request, replacement); await finish(request, root);
});

test('shutdown contains orphaned setsid and exec descendants and the durable deadline revokes their credentials', async ({ request }) => {
  test.setTimeout(65000);
  await call(request, 'getcreds'); const parent = await launch(request);
  const child = await processCall(request, parent, { fork: { pid: parent.pid } }); child.token = parent.token;
  await processCall(request, child, 'setsid');
  const [replacement] = await sys(request, [{ execve: { ...proof(child), path: '/usr/bin/sleep', argv: ['sleep', '60'], cwd: '/' } }], {}, registry);
  expect(replacement.err).toBeUndefined(); const replaced = replacement.ok;
  await finish(request, parent);
  const session = await login(request);
  const ended = await login(request, { op: 'end', session: session.id });
  expect(ended.shutdown.complete).toBe(false);
  expect((await processCall(request, replaced, 'getpid')).pid).toBe(child.pid);
  await expect.poll(async () => (await login(request)).shutdown.complete, { timeout: 45000, intervals: [1000] }).toBe(true);
  const denied = (await sys(request, ['getpid'], proof(replaced), registry))[0]; expect(denied.err).toBeTruthy();
  const fileDenied = (await sys(request, [{ stat: { path: '/guest' } }], proof(replaced)))[0]; expect(fileDenied.err).toBeTruthy();
});

test('root restart is scoped to one Machine, preserves data and profiles, and fences old boot proofs and PIDs', async ({ request, browser }) => {
  await call(request, 'getcreds'); const guest = await launch(request), before = await init(request);
  await init(request, { op: 'reboot', boot: before.boot }, 'EPERM');
  await init(request, { op: 'reboot', boot: before.boot }, 'EPERM', { sudo: true });
  await signIn(request); const root = await launch(request);
  await init(request, { op: 'reboot', boot: before.boot }, 'EPERM', proof(root));
  const host = { host: randomUUID(), proof: randomBytes(32).toString('hex') };
  const claimed = await init(request, { op: 'claim', owner: { ...host, boot: before.boot, generation: before.generation } });
  const owner = { ...host, boot: before.boot, generation: claimed.generation };
  const joined = await login(request, { op: 'join', ...host });
  const member = { ...host, session: joined.id };
  const controlled = await login(request, { op: 'claim', member, generation: joined.generation });
  await login(request, { op: 'configure', member, generation: controlled.generation, file: '/root/lifecycle-units.json' });
  const other = await browser.newContext();
  try {
    await call(other.request, 'getcreds'); const otherBoot = await init(other.request);
    const base = '/guest/reboot-' + randomUUID(); await call(request, { mkdir: { path: base, mode: 0o700 } });
    expect((await put(request, '/api/file?path=' + base + '/saved', { data: 'keep me' })).ok()).toBe(true);
    await init(request, { op: 'reboot', boot: 'old-boot' }, 'ESTALE');
    const stopping = await init(request, { op: 'reboot', boot: before.boot });
    expect(stopping.shutdown.complete).toBe(false);
    expect((await init(request, { op: 'reboot', boot: before.boot })).shutdown.deadline).toBe(stopping.shutdown.deadline);
    expect((await sys(request, [{ execve: { path: '/usr/bin/true' } }]))[0].err.errno).toBe('EBUSY');
    await finish(request, guest); await finish(request, root);
    const after = await init(request); expect(after.boot).not.toBe(before.boot); expect(after.shutdown).toBe(null);
    await init(request, { op: 'renew', owner }, 'ESTALE');
    await init(request, { op: 'reboot', boot: before.boot }, 'ESTALE');
    expect((await init(other.request)).boot).toBe(otherBoot.boot);
    expect((await call(request, 'getcreds')).uid).toBe(0);
    expect(await (await request.get('/api/file?path=' + base + '/saved')).text()).toBe('keep me');
    const next = await launch(request); expect(next.pid).toBeGreaterThan(root.pid);
    expect((await login(request)).startup.file).toBe('/root/lifecycle-units.json');
    await finish(request, next); await rmrf(request, base);
  } finally { await other.close(); }
});

test('a restart deadline runs without any execution host and rejects stale ordinary credentials', async ({ request }) => {
  test.setTimeout(65000);
  await call(request, 'getcreds'); await signIn(request); const p = await launch(request), before = await init(request);
  await init(request, { op: 'reboot', boot: before.boot });
  await expect.poll(async () => (await init(request)).boot, { timeout: 45000, intervals: [1000] }).not.toBe(before.boot);
  expect((await sys(request, ['getpid'], proof(p), registry))[0].err).toBeTruthy();
  expect((await sys(request, [{ stat: { path: '/root' } }], proof(p)))[0].err).toBeTruthy();
});

const state = page => page.evaluate(() => window.os.loginSession());
async function ready(page) { await page.goto('/'); await expect.poll(async () => (await state(page))?.connected).toBe(true); }
async function run(page, key, script) {
  await page.evaluate(({ key, script }) => {
    const run = window[key] = { output: '' };
    run.done = window.os.exec([['sh', '-c', script]], { stdin: '', tty: true, onOutput: (_fd, text) => { run.output += text; } })
      .then(result => { run.result = result; }, error => { run.error = String(error); });
  }, { key, script });
}

test('explicit end-session stops real workloads across tabs while ordinary sign-out preserves an older login', async ({ page, context }) => {
  await signIn(page.request); await ready(page);
  await run(page, 'older', 'echo OLD-READY; sleep 120');
  await expect.poll(() => page.evaluate(() => window.older.output)).toContain('OLD-READY');
  await api(page.request, 'logout');
  await expect.poll(async () => (await state(page)).session?.uid, { timeout: 15000 }).not.toBe(0);
  const second = await context.newPage(); await ready(second);
  for (const [host, key] of [[page, 'first'], [second, 'second']]) {
    await run(host, key, "trap 'echo CLEAN; exit 0' HUP TERM; echo READY; while :; do sleep 1; done");
    await expect.poll(() => host.evaluate(key => window[key].output, key)).toContain('READY');
  }
  const current = (await state(second)).session;
  await second.evaluate(expected => window.os.endLoginSession(expected), current);
  await expect.poll(() => page.evaluate(() => window.first.output), { timeout: 15000 }).toContain('CLEAN');
  await expect.poll(() => second.evaluate(() => window.second.output), { timeout: 15000 }).toContain('CLEAN');
  await expect.poll(async () => (await login(page.request)).shutdown.complete).toBe(true);
  expect(await page.evaluate(() => window.older.result)).toBeUndefined();
  await second.evaluate(expected => window.os.restartLoginSession(expected), current);
  await run(second, 'replacement', 'echo NEW-SCOPE');
  await expect.poll(() => second.evaluate(() => window.replacement.output)).toContain('NEW-SCOPE');
});

test('the greeter can end a running shell and explicitly enter a fresh scope', async ({ page, context }) => {
  await page.goto('/shell'); const input = page.getByRole('textbox', { name: 'Shell input' });
  await expect(input).toBeEnabled({ timeout: 30000 });
  await expect(page.locator('.terminal-screen')).toContainText(/[#$]\s*$/);
  const before = await login(page.request);
  const greeter = await context.newPage(); await greeter.goto('/login?target=shell');
  await greeter.getByText('Session controls', { exact: true }).click();
  await greeter.getByRole('button', { name: 'End session', exact: true }).click();
  await expect(greeter.getByRole('status')).toContainText('Session ended', { timeout: 45000 });
  await expect(input).toBeDisabled();
  await greeter.getByRole('button', { name: 'Continue as guest', exact: true }).click();
  await expect(greeter).toHaveURL(/\/shell(?:\.html)?$/);
  await expect(greeter.getByRole('textbox', { name: 'Shell input' })).toBeEnabled({ timeout: 30000 });
  expect((await login(greeter.request)).id).not.toBe(before.id);
});

test('real Machine restart stops workloads and starts a new reaper and login generation in existing tabs', async ({ page }) => {
  await signIn(page.request); await ready(page);
  const before = await page.evaluate(() => window.os.machineInit()), session = (await state(page)).session;
  await run(page, 'running', "trap 'echo REBOOT-CLEAN; exit 0' HUP TERM; echo REBOOT-READY; while :; do sleep 1; done");
  await expect.poll(() => page.evaluate(() => window.running.output)).toContain('REBOOT-READY');
  await page.evaluate(expected => window.os.rebootMachine(expected), before.init);
  await expect.poll(() => page.evaluate(() => window.running.output), { timeout: 15000 }).toContain('REBOOT-CLEAN');
  await expect.poll(async () => (await page.evaluate(() => window.os.machineInit())).init?.boot, { timeout: 20000 }).not.toBe(before.init.boot);
  await expect.poll(async () => (await state(page)).session?.id, { timeout: 20000 }).not.toBe(session.id);
  await expect.poll(async () => (await page.evaluate(() => window.os.machineInit())).reaper?.state, { timeout: 20000 }).toBe('running');
  await run(page, 'after', 'echo AFTER-REBOOT | cat; sleep 0.01');
  await expect.poll(() => page.evaluate(() => window.after.output)).toContain('AFTER-REBOOT');
});

test('session shutdown while an image loads cannot admit its delayed command into a replacement scope', async ({ page, context }) => {
  await ready(page); const original = (await state(page)).session;
  const base = '/guest/lifecycle-loading-' + randomUUID();
  await call(page.request, { mkdir: { path: base, mode: 0o700 } });
  let release, loading = false; const hold = new Promise(resolve => { release = resolve; });
  await context.route(executableAsset('dash'), async route => { loading = true; await hold; await route.continue(); });
  try {
    await run(page, 'delayed', `echo forbidden > ${base}/marker`);
    await expect.poll(() => loading).toBe(true);
    await page.evaluate(expected => window.os.endLoginSession(expected), original);
    // Force the already registered candidate to end while its bytes are unavailable.
    // A later response must not run it with either stale credentials or the new scope.
    const [processes] = await sys(page.request, [{ proc_poll: { pids: [] } }], {}, registry);
    for (const p of processes.ok.filter(p => p.pid !== 1 && p.state !== 'zombie')) {
      await call(page.request, { kill: { pid: String(p.pid), signal: 9 } });
    }
    await expect.poll(async () => (await login(page.request)).shutdown.complete).toBe(true);
    await page.evaluate(expected => window.os.restartLoginSession(expected), original);
    release();
    await expect.poll(() => page.evaluate(() => !!(window.delayed.result || window.delayed.error)), { timeout: 20000 }).toBe(true);
    expect((await sys(page.request, [{ stat: { path: base + '/marker' } }]))[0].err?.errno).toBe('ENOENT');
    await context.unroute(executableAsset('dash'));
    await run(page, 'fresh', 'echo FRESH-ADMISSION');
    await expect.poll(() => page.evaluate(() => window.fresh.output)).toContain('FRESH-ADMISSION');
  } finally { release(); await rmrf(page.request, base); }
});

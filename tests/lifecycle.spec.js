import { executableAsset } from './executable-asset.js';
import { test, expect } from './test.js';
import { api, call, put, rmrf } from './sys.js';
import { pageErrno, pageMkdirp, pageRmrf, switchLocalUser } from './ui.js';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const password = process.env.OS_TEST_ADMIN_PASSWORD || process.env.OS_PASSWORD || (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const CLOUD_SCOPE = { cloud_fs: true, devices: [], containers: false, relay: false };
test.setTimeout(70000);

const ROOT_ACCOUNT = { uid: 0, gid: 0, groups: [0], user: 'root', group: 'root', home: '/root', shell: '/usr/bin/dash', signed_in: true };
const GUEST_ACCOUNT = { uid: 65534, gid: 65534, groups: [65534], user: 'guest', group: 'guest', home: '/tmp', shell: '/usr/bin/dash', signed_in: false };

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
    window.lifecycleKernel = (type, args = {}) => new Promise(resolve => {
      const id = ++next;
      pending.set(id, resolve);
      worker.postMessage({ v: 2, id, type, args });
    });
  });
  expect((await kc(page, 'init')).err).toBeUndefined();
}
const kc = (page, type, args = {}) => page.evaluate(([type, args]) => window.lifecycleKernel(type, args), [type, args]);
async function kv(page, type, args = {}) {
  const r = await kc(page, type, args);
  expect(r.err, `${type}: ${JSON.stringify(r)}`).toBeUndefined();
  return r.ok;
}
async function loginAct(page, action, errno) {
  const r = await kc(page, 'login_session_action', { action });
  if (errno) { expect(r.err?.errno, JSON.stringify(r)).toBe(errno); return; }
  expect(r.err, JSON.stringify(r)).toBeUndefined();
  return r.ok;
}
async function initAct(page, action, errno) {
  const r = await kc(page, 'machine_init_action', { action });
  if (errno) { expect(r.err?.errno, JSON.stringify(r)).toBe(errno); return; }
  expect(r.err, JSON.stringify(r)).toBeUndefined();
  return r.ok;
}
const launch = (page, extra = {}) => kv(page, 'exec', { path: '/usr/bin/sleep', argv: ['sleep', '60'], cwd: '/', env: [], ...extra });
async function finish(page, p) {
  await kc(page, 'exit', { pid: p.pid, status: 0 });
  await kc(page, 'wait', { pid: p.pid });
}
async function signIn(request) {
  expect((await api(request, 'login', { headers: { 'CF-Connecting-IP': 'lifecycle-' + randomUUID() }, data: { password } })).ok()).toBe(true);
}
const fsConnect = async (request, token, instanceId) =>
  (await request.post(origin + '/api/fs', {
    headers: { Origin: origin, ...(instanceId ? { 'X-OS-Instance': instanceId } : {}) },
    data: { version: 2, credential: token, session: null, call: 'connect' },
  })).json();

test('restarted login IDs accept completion and departure without reviving the old scope', async ({ page }) => {
  await connect(page);
  const host = { host: randomUUID(), proof: randomBytes(32).toString('hex') };
  let current = await loginAct(page, { op: 'join', ...host });
  for (let attempt = 0; attempt < 2; attempt++) {
    const old = current.id;
    await loginAct(page, { op: 'end', session: old });
    current = await loginAct(page, { op: 'restart', session: old });
    expect(current.id).not.toBe(old);
    await loginAct(page, { op: 'join', ...host });
    const member = { ...host, session: current.id };
    current = await loginAct(page, { op: 'claim', member, generation: current.generation });
    current = await loginAct(page, { op: 'configure', member, generation: current.generation, file: '/guest/restart-units.json' });
    const launchCap = { revision: current.startup.revision, proof: randomBytes(32).toString('hex') };
    await loginAct(page, { op: 'begin', member, generation: current.generation, launch: launchCap });
    await loginAct(page, { op: 'finish', session: old, launch: launchCap, status: 126, error: 'image unavailable' }, 'ESTALE');
    await loginAct(page, { op: 'finish', session: current.id, launch: launchCap, status: 126, error: 'image unavailable' });
    expect((await loginAct(page, { op: 'inspect' })).startup).toMatchObject({ state: 'finished', status: 126 });
    await loginAct(page, { op: 'configure', member, generation: current.generation, file: null });
    await loginAct(page, { op: 'leave', member });
    expect((await loginAct(page, { op: 'inspect' })).hosts).toEqual([]);
    await loginAct(page, { op: 'leave', member: { ...member, session: old } }, 'ESTALE');
  }
  await loginAct(page, { op: 'end', session: current.id });
});

test('ending an exact login is authenticated, idempotent and fences new launches until explicit restart', async ({ page }) => {
  await connect(page);
  const p = await launch(page);
  const original = await loginAct(page, { op: 'inspect' });
  expect(original.shutdown).toBe(null);
  await loginAct(page, { op: 'end', session: 'stale' }, 'ESTALE');

  // Switching to root creates a new login scope; ending old scope fails ESTALE until back on guest, or we end current.
  const stopped = await loginAct(page, { op: 'end', session: original.id });
  const retry = await loginAct(page, { op: 'end', session: original.id });
  expect(retry.shutdown.deadline).toBe(stopped.shutdown.deadline);
  expect((await kc(page, 'exec', { path: '/usr/bin/true', argv: ['true'], cwd: '/', env: [] })).err?.errno).toBe('EBUSY');
  // Non-root cannot restart while shutdown is incomplete.
  await loginAct(page, { op: 'restart', session: original.id }, 'EPERM');
  await finish(page, p);
  expect((await loginAct(page, { op: 'inspect' })).shutdown.complete).toBe(true);
  const next = await loginAct(page, { op: 'restart', session: original.id });
  expect(next.id).not.toBe(original.id);
  expect(next.shutdown).toBe(null);
  await loginAct(page, { op: 'end', session: original.id }, 'ESTALE');
  const replacement = await launch(page);
  expect(replacement.pid).toBeGreaterThan(p.pid);
  await finish(page, replacement);
});

test('shutdown contains orphaned setsid and exec descendants and revokes their remote credentials immediately', async ({ page }) => {
  const request = page.request;
  await signIn(request);
  await connect(page);
  await kv(page, 'cloud_sign_in', { cloudUser: 'root', cloudUid: 0, cloudGid: 0, cloudGroups: [0], scope: CLOUD_SCOPE });
  const instanceId = await kv(page, 'instance_id');
  const parent = await launch(page, { remote: true });
  const child = await kv(page, 'fork', { pid: parent.pid });
  await kv(page, 'process_call', { pid: child.pid, call: 'setsid' });
  const replaced = await kv(page, 'reexec', { pid: child.pid, path: '/usr/bin/sleep', argv: ['sleep', '60'], cwd: '/', env: [] });
  expect(replaced.token).toMatch(/^[0-9a-f]{64}$/);
  await finish(page, parent);

  // Confirm remote credential works before login scope end.
  const before = await fsConnect(request, replaced.token, instanceId);
  expect(before.session, JSON.stringify(before)).toBeTruthy();
  await request.post(origin + '/api/fs', {
    headers: { Origin: origin, 'X-OS-Instance': instanceId },
    data: { version: 2, credential: replaced.token, session: before.session, call: 'disconnect' },
  });

  const session = await loginAct(page, { op: 'inspect' });
  const ended = await loginAct(page, { op: 'end', session: session.id });
  expect(ended.shutdown.complete).toBe(false);
  // Remote credential of the orphaned setsid+exec descendant is revoked immediately on scope end.
  const after = await fsConnect(request, replaced.token, instanceId);
  expect(['EACCES', 'EPERM']).toContain(after.errno);
  await finish(page, replaced);
  expect((await loginAct(page, { op: 'inspect' })).shutdown.complete).toBe(true);
});

test('root restart is scoped to one instance, preserves data and profiles, revokes old remote credentials, and fences old boot proofs', async ({ page, browser }) => {
  const request = page.request;
  await call(request, 'getcreds');
  await connect(page);
  const instanceId = await kv(page, 'instance_id');
  const guest = await launch(page);
  const before = await initAct(page, { op: 'inspect' });
  await initAct(page, { op: 'reboot', boot: before.boot }, 'EPERM');

  await signIn(request);
  await kv(page, 'sync_account', ROOT_ACCOUNT);
  await kv(page, 'cloud_sign_in', { cloudUser: 'root', cloudUid: 0, cloudGid: 0, cloudGroups: [0], scope: CLOUD_SCOPE });
  const root = await launch(page, { remote: true });
  const host = { host: randomUUID(), proof: randomBytes(32).toString('hex') };
  const joined = await loginAct(page, { op: 'join', ...host });
  const member = { ...host, session: joined.id };
  const controlled = await loginAct(page, { op: 'claim', member, generation: joined.generation });
  await loginAct(page, { op: 'configure', member, generation: controlled.generation, file: '/root/lifecycle-units.json' });

  const other = await browser.newContext();
  const base = '/guest/reboot-' + randomUUID();
  try {
    const otherPage = await other.newPage();
    await connect(otherPage);
    const otherBoot = await initAct(otherPage, { op: 'inspect' });
    await call(request, { mkdir: { path: base, mode: 0o700 } });
    expect((await put(request, '/api/file?path=' + base + '/saved', { data: 'keep me' })).ok()).toBe(true);
    await initAct(page, { op: 'reboot', boot: 'old-boot' }, 'ESTALE');

    const after = await initAct(page, { op: 'reboot', boot: before.boot });
    expect(after.boot).not.toBe(before.boot);
    await initAct(page, { op: 'reboot', boot: before.boot }, 'ESTALE');
    // Other instance's boot is untouched.
    expect((await initAct(otherPage, { op: 'inspect' })).boot).toBe(otherBoot.boot);
    // Remote data survives and old remote credential was revoked by reboot.
    expect(await (await request.get('/api/file?path=' + base + '/saved')).text()).toBe('keep me');
    const denied = await fsConnect(request, root.token, instanceId);
    expect(['EACCES', 'EPERM']).toContain(denied.errno);
    // Login startup profile persists across instance reboot.
    expect((await loginAct(page, { op: 'inspect' })).startup?.file).toBe('/root/lifecycle-units.json');
    await finish(page, guest);
    const next = await launch(page);
    expect(next.pid).toBeGreaterThan(1);
    await finish(page, next);
  } finally {
    await rmrf(request, base);
    await other.close();
  }
});

const state = page => page.evaluate(() => window.os.loginSession());
async function ready(page) { await page.goto('/'); await expect.poll(async () => (await state(page))?.connected).toBe(true); }
async function run(page, key, script) {
  await page.evaluate(({ key, script }) => {
    const run = window[key] = { output: '' };
    run.done = window.os.exec([['sh', '-c', script]], {
      stdin: '', tty: true,
      onJob: job => { run.job = job; },
      onOutput: (_fd, text) => { run.output += text; },
    }).then(result => { run.result = result; }, error => { run.error = String(error); });
  }, { key, script });
}

test('explicit end-session stops workloads in its own instance without affecting another tab, while ordinary account switch preserves running workloads', async ({ page, context }) => {
  await ready(page);
  await switchLocalUser(page, 'root');
  await run(page, 'older', 'echo OLD-READY; sleep 120');
  await expect.poll(() => page.evaluate(() => window.older.output), { timeout: 15000 }).toContain('OLD-READY');
  await switchLocalUser(page, 'user');
  await expect.poll(async () => (await state(page)).session?.uid, { timeout: 15000 }).not.toBe(0);

  const second = await context.newPage();
  try {
    await ready(second);
    for (const [host, key] of [[page, 'first'], [second, 'second']]) {
      await run(host, key, "trap 'echo CLEAN; exit 0' HUP TERM; echo READY; while :; do sleep 1; done");
      await expect.poll(() => host.evaluate(key => window[key].output, key), { timeout: 15000 }).toContain('READY');
    }
    const current = (await state(second)).session;
    await second.evaluate(expected => window.os.endLoginSession(expected), current);
    await expect.poll(() => second.evaluate(() => window.second.output), { timeout: 15000 }).toContain('CLEAN');
    await expect.poll(async () => (await state(second)).session?.shutdown?.complete, { timeout: 15000 }).toBe(true);
    // Instance isolation: ending Tab 2's login scope never touches Tab 1's workloads.
    expect(await page.evaluate(() => window.first.result)).toBeUndefined();
    expect(await page.evaluate(() => window.older.result)).toBeUndefined();
    await second.evaluate(expected => window.os.restartLoginSession(expected), current);
    await run(second, 'replacement', 'echo NEW-SCOPE');
    await expect.poll(() => second.evaluate(() => window.replacement.output), { timeout: 15000 }).toContain('NEW-SCOPE');
  } finally {
    await page.evaluate(() => { window.older?.job?.signal(9); window.first?.job?.signal(9); });
    await second.close();
  }
});

test('a standalone shell can end its session scope and enter a fresh shell scope', async ({ page }) => {
  await page.goto('/shell.html');
  await expect.poll(async () => (await state(page))?.connected, { timeout: 20000 }).toBe(true);
  await expect(page.getByRole('textbox', { name: 'Shell input' })).toBeEnabled({ timeout: 30000 });
  const current = (await state(page)).session;
  await page.evaluate(expected => window.os.endLoginSession(expected), current);
  await expect.poll(async () => (await state(page)).session?.shutdown?.complete, { timeout: 20000 }).toBe(true);
  await page.evaluate(expected => window.os.restartLoginSession(expected), current);
  await page.getByRole('button', { name: 'Start shell', exact: true }).click();
  await expect(page.getByRole('textbox', { name: 'Shell input' })).toBeEnabled({ timeout: 30000 });
  await expect(page.locator('.terminal-screen')).toContainText(/[#$]\s*$/);
});

test('real Machine restart stops workloads and starts a new reaper and login generation in existing tabs', async ({ page }) => {
  await ready(page);
  await switchLocalUser(page, 'root');
  await expect.poll(async () => (await state(page)).session?.uid, { timeout: 15000 }).toBe(0);
  const before = await page.evaluate(() => window.os.machineInit()), session = (await state(page)).session;
  await run(page, 'running', "trap 'echo REBOOT-CLEAN; exit 0' HUP TERM; echo REBOOT-READY; while :; do sleep 1; done");
  await expect.poll(() => page.evaluate(() => window.running.output), { timeout: 15000 }).toContain('REBOOT-READY');
  await page.evaluate(expected => window.os.rebootMachine(expected), before.init);
  await expect.poll(() => page.evaluate(() => window.running.output), { timeout: 15000 }).toContain('REBOOT-CLEAN');
  await expect.poll(async () => (await page.evaluate(() => window.os.machineInit())).init?.boot, { timeout: 20000 }).not.toBe(before.init.boot);
  await expect.poll(async () => (await state(page)).session?.id, { timeout: 20000 }).not.toBe(session.id);
  await expect.poll(async () => (await page.evaluate(() => window.os.machineInit())).reaper?.state, { timeout: 20000 }).toBe('running');
  await run(page, 'after', 'echo AFTER-REBOOT | cat; sleep 0.01');
  await expect.poll(() => page.evaluate(() => window.after.output), { timeout: 15000 }).toContain('AFTER-REBOOT');
});

test('session shutdown while an image loads cannot admit its delayed command into a replacement scope', async ({ page, context }) => {
  await ready(page);
  const original = (await state(page)).session;
  const base = '/tmp/lifecycle-loading-' + randomUUID();
  await pageMkdirp(page, base, 0o700);
  let release, loading = false;
  const hold = new Promise(resolve => { release = resolve; });
  await context.route(executableAsset('dash'), async route => { loading = true; await hold; await route.continue(); });
  try {
    await run(page, 'delayed', `echo forbidden > ${base}/marker`);
    await expect.poll(() => loading).toBe(true);
    await page.evaluate(expected => window.os.endLoginSession(expected), original);
    await page.evaluate(() => window.delayed.job?.signal(9));
    await expect.poll(async () => (await state(page)).session?.shutdown?.complete, { timeout: 15000 }).toBe(true);
    await page.evaluate(expected => window.os.restartLoginSession(expected), original);
    release();
    await expect.poll(() => page.evaluate(() => !!(window.delayed.result || window.delayed.error)), { timeout: 20000 }).toBe(true);
    expect(await pageErrno(page, { stat: { path: base + '/marker' } })).toBe('ENOENT');
    await context.unroute(executableAsset('dash'));
    await run(page, 'fresh', 'echo FRESH-ADMISSION');
    await expect.poll(() => page.evaluate(() => window.fresh.output), { timeout: 15000 }).toContain('FRESH-ADMISSION');
  } finally {
    release();
    await pageRmrf(page, base).catch(() => {});
  }
});

import { executableAsset } from './executable-asset.js';
import { test, expect } from './test.js';
import { api, call, put, rmrf } from './sys.js';
import { connectKernel, hookPageKernel } from './service-auth.js';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const password = process.env.OS_TEST_ADMIN_PASSWORD || (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const ROOT_ACCOUNT = { uid: 0, gid: 0, groups: [0], user: 'root', group: 'root', home: '/root', shell: '/usr/bin/dash', signed_in: true };
const GUEST_ACCOUNT = { uid: 65534, gid: 65534, groups: [65534], user: 'guest', group: 'guest', home: '/tmp', shell: '/usr/bin/dash', signed_in: false };
const secret = () => randomBytes(32).toString('hex');

async function freshKernel(page, name = '__loginBootKernel') {
  await page.goto('/login');
  const kernel = await connectKernel(page, { name });
  await kernel.value('login_leave');
  await kernel.value('machine_init_leave');
  return kernel;
}

async function invoke(kernel, action, errno) {
  const result = await kernel.call('login_session_action', { action });
  if (errno) {
    expect(result.err?.errno, JSON.stringify(result)).toBe(errno);
    return;
  }
  expect(result.err, JSON.stringify(result)).toBeUndefined();
  return result.ok;
}

async function owner(kernel) {
  const host = { host: randomUUID(), proof: secret() };
  const joined = await invoke(kernel, { op: 'join', ...host });
  const member = { session: joined.id, ...host };
  const claimed = await invoke(kernel, { op: 'claim', member, generation: joined.generation });
  return { member, generation: claimed.generation };
}

async function configure(kernel, own, file = '/guest/units.json') {
  return invoke(kernel, { op: 'configure', ...own, file });
}

async function begin(kernel, own, startup) {
  const launch = { revision: startup.revision, proof: secret() };
  await invoke(kernel, { op: 'begin', ...own, launch });
  return launch;
}

async function spawnProc(kernel) {
  const p = await kernel.value('exec', { path: '/usr/bin/coreutils', argv: ['true'], env: [], cwd: '/' });
  await kernel.value('session', { pids: [p.pid] });
  return p;
}

const attach = (own, launch, p) => ({
  op: 'attach',
  ...own,
  ...(launch !== undefined ? { launch } : {}),
  process: { pid: p.pid, proc: p.token ?? '' },
});
const finish = (own, launch, status = 0) => ({ op: 'finish', session: own.member.session, launch, status, error: null });

async function endProc(kernel, p) {
  await kernel.call('exit', { pid: p.pid, status: 0 });
  await kernel.call('wait', { pid: p.pid });
}

async function signIn(request) {
  expect((await api(request, 'login', { headers: { 'CF-Connecting-IP': 'login-boot-' + randomUUID() }, data: { password } })).ok()).toBe(true);
}

test('automatic startup requires coordinator and process proofs and retains its completion across takeover', async ({ page, request }) => {
  await call(request, 'getcreds');
  const kernel = await freshKernel(page);
  const own = await owner(kernel);
  let p;
  try {
    await invoke(kernel, { op: 'configure', ...own, file: 'relative' }, 'EINVAL');
    await invoke(kernel, { op: 'configure', ...own, member: { ...own.member, proof: secret() }, file: '/units' }, 'EACCES');
    // Retired server /api/sys login_session route (including with sudo) fails closed.
    const retired = await request.post(origin + '/api/sys', {
      headers: { Origin: origin, 'Content-Type': 'application/json' },
      data: { calls: [{ login_session: { action: { op: 'configure', ...own, file: '/units' } } }], sudo: true },
    });
    expect(retired.ok()).toBe(false);

    const selected = await configure(kernel, own), launch = await begin(kernel, own, selected.startup);
    await invoke(kernel, { op: 'begin', ...own, launch });
    await invoke(kernel, { op: 'begin', ...own, launch: { ...launch, proof: secret() } }, 'ESTALE');
    p = await spawnProc(kernel);

    // Process calls cannot configure login startup.
    expect((await kernel.call('process_call', { pid: p.pid, call: { login_session: { action: { op: 'configure', ...own, file: '/units' } } } })).err).toBeTruthy();
    await invoke(kernel, attach(own, undefined, p), 'EBUSY');
    await invoke(kernel, attach(own, { ...launch, proof: secret() }, p), 'ESTALE');
    const attached = await invoke(kernel, attach(own, launch, p));
    expect(attached.startup.state).toBe('running');
    expect(attached.startup.pid).toBe(p.pid);
    expect(JSON.stringify(attached)).not.toContain(launch.proof);
    expect(JSON.stringify(attached)).not.toContain(own.member.proof);

    await invoke(kernel, finish(own, { ...launch, proof: secret() }), 'ESTALE');
    await invoke(kernel, finish(own, launch), 'EBUSY');
    await endProc(kernel, p);
    await invoke(kernel, finish(own, launch));
    await invoke(kernel, finish(own, launch));
    await invoke(kernel, finish(own, launch, 1), 'ESTALE');

    await invoke(kernel, { op: 'leave', member: own.member });
    const next = await owner(kernel);
    const seen = await invoke(kernel, { op: 'inspect' });
    expect(seen.startup.status).toBe(0);
    expect(seen.startup.state).toBe('finished');
    await invoke(kernel, { op: 'begin', ...next, launch: { revision: launch.revision, proof: secret() } }, 'EBUSY');
  } finally {
    if (p) await endProc(kernel, p);
    await kernel.terminate();
  }
});

test('account configuration follows fresh logins and disabling removes future automatic startup', async ({ page }) => {
  const kernel = await freshKernel(page);
  try {
    await kernel.value('sync_account', ROOT_ACCOUNT);
    const root = await owner(kernel), configured = await configure(kernel, root, '/root/units.json');
    await kernel.value('sync_account', GUEST_ACCOUNT);
    await owner(kernel);
    expect((await invoke(kernel, { op: 'inspect' })).startup).toBe(null);

    await kernel.value('sync_account', ROOT_ACCOUNT);
    const next = await owner(kernel), seen = await invoke(kernel, { op: 'inspect' });
    expect(next.member.session).not.toBe(root.member.session);
    expect(seen.startup.revision).toBe(configured.startup.revision);
    expect(seen.startup.state).toBe('pending');

    await configure(kernel, next, null);
    await kernel.value('sync_account', GUEST_ACCOUNT);
    await kernel.value('sync_account', ROOT_ACCOUNT);
    await owner(kernel);
    expect((await invoke(kernel, { op: 'inspect' })).startup).toBe(null);
  } finally {
    await kernel.terminate();
  }
});

test('a previous login may report only its ended startup and cannot configure the replacement', async ({ page }) => {
  const kernel = await freshKernel(page);
  let p;
  try {
    const own = await owner(kernel), selected = await configure(kernel, own), launch = await begin(kernel, own, selected.startup);
    p = await spawnProc(kernel);
    await invoke(kernel, attach(own, launch, p));

    await kernel.value('sync_account', ROOT_ACCOUNT);
    const root = await owner(kernel);
    await invoke(kernel, { op: 'configure', ...own, file: '/root/units.json' }, 'ESTALE');
    expect(await invoke(kernel, { op: 'inspect' })).toMatchObject({ uid: 0, startup: null });
    // Superseded login finish cannot alter the replacement login scope.
    await invoke(kernel, finish(own, launch), 'ESTALE');
    await endProc(kernel, p);
    p = null;
    await invoke(kernel, finish(own, launch), 'ESTALE');
    expect((await invoke(kernel, { op: 'inspect' })).id).toBe(root.member.session);
    expect((await invoke(kernel, { op: 'inspect' })).startup).toBe(null);
  } finally {
    if (p) await endProc(kernel, p);
    await kernel.terminate();
  }
});

test('pre-execution host loss fences old attempts and stops automatic admission after three losses', async ({ page }) => {
  const kernel = await freshKernel(page);
  let own = await owner(kernel);
  const selected = await configure(kernel, own);
  const p = await spawnProc(kernel);
  let previous;
  try {
    for (let n = 1; n <= 3; n++) {
      const launch = await begin(kernel, own, selected.startup);
      if (previous) await invoke(kernel, attach(own, previous, p), 'ESTALE');
      await invoke(kernel, { op: 'leave', member: own.member });
      previous = launch;
      own = await owner(kernel);
    }
    const seen = await invoke(kernel, { op: 'inspect' });
    expect(seen.startup.state).toBe('finished');
    expect(seen.startup.attempts).toBe(3);
    await invoke(kernel, { op: 'begin', ...own, launch: { revision: selected.startup.revision, proof: secret() } }, 'EBUSY');
  } finally {
    await endProc(kernel, p);
    await kernel.terminate();
  }
});

test('disabling invalidates an unstarted attempt and does not signal an already running service', async ({ page }) => {
  const kernel = await freshKernel(page);
  const own = await owner(kernel);
  let selected = await configure(kernel, own), launch = await begin(kernel, own, selected.startup);
  const p = await spawnProc(kernel);
  try {
    await configure(kernel, own, null);
    await invoke(kernel, attach(own, launch, p), 'ESTALE');
    selected = await configure(kernel, own);
    launch = await begin(kernel, own, selected.startup);
    await invoke(kernel, attach(own, launch, p));
    await invoke(kernel, { op: 'configure', ...own, file: '/replacement.json' }, 'EBUSY');
    const disabled = await configure(kernel, own, null);
    expect(disabled.startup.enabled).toBe(false);
    expect(disabled.startup.state).toBe('running');
    const live = (await kernel.value('sync')).find(row => row.pid === p.pid);
    expect(live.state).toBe('running');
    expect(live.pending_signals ?? []).toEqual([]);
    await endProc(kernel, p);
    await invoke(kernel, finish(own, launch));
  } finally {
    await endProc(kernel, p);
    await kernel.terminate();
  }
});

const state = page => page.evaluate(() => window.os.loginSession());
async function ready(page) {
  await call(page.request, 'getcreds');
  const pageKernel = await hookPageKernel(page);
  await page.goto('/');
  await pageKernel.ready();
  await expect.poll(async () => (await state(page))?.coordinator, { timeout: 20_000 }).toBe(true);
  await pageKernel.value('sync_account_from_server');
  return pageKernel;
}
async function selected(page, file) { return page.evaluate(file => window.os.configureLoginServices(file), file); }
async function completed(page, status = 0) {
  await expect.poll(async () => (await state(page)).session?.startup?.status, { timeout: 30_000 }).toBe(status);
}
async function units(page, script) {
  const base = '/guest/login-boot-' + randomUUID();
  await call(page.request, { mkdir: { path: base, mode: 0o777 } });
  await call(page.request, { chmod: { path: base, mode: 0o777 } });
  const file = base + '/units.json';
  const write = async command => expect((await put(page.request, '/api/file?path=' + file + '&overwrite=true', {
    data: JSON.stringify({ version: 1, units: [{ name: 'login', argv: ['/usr/bin/sh', '-c', command.replaceAll('$BASE', base)] }] }),
  })).ok()).toBe(true);
  await write(script);
  return { base, file, write };
}
async function read(request, path) { return call(request, { pread: { path, offset: 0, count: 65536 } }); }
async function text(request, path) {
  const value = await read(request, path);
  return Buffer.from(value.data, 'base64').toString();
}
async function refresh(page) { await page.evaluate(() => dispatchEvent(new Event('os:login-changed'))); }
async function stop(page) {
  const current = (await state(page)).session;
  if (current?.managed) await page.evaluate(session => window.os.signalLoginServices(session), current).catch(() => {});
}

test('automatic units execute once and a follower does not rerun completed units after takeover', async ({ page, context }) => {
  const pageKernel = await ready(page);
  const { base, file } = await units(page, 'echo BOOT; echo once >> $BASE/count');
  const other = await context.newPage();
  try {
    await selected(page, file);
    await completed(page);
    expect((await state(page)).services.output).toContain('BOOT');
    expect(await text(page.request, base + '/count')).toBe('once\n');
    const before = (await state(page)).session;

    // Per Contract v2 §2.1, another tab runs its own isolated login session without inheriting this tab's state.
    await other.goto('/');
    await expect.poll(async () => (await state(other))?.connected).toBe(true);
    expect((await state(other)).session.id).not.toBe(before.id);

    // Releasing and reclaiming coordination within the same instance advances generation
    // while retaining completed startup status and never rerunning units.
    await pageKernel.value('login_leave');
    await expect.poll(async () => (await state(page)).coordinator).toBe(false);
    await pageKernel.value('login_refresh', { fromServer: false });
    await expect.poll(async () => (await state(page)).coordinator, { timeout: 20_000 }).toBe(true);
    const after = (await state(page)).session;
    expect(after.id).toBe(before.id);
    expect(after.generation).toBeGreaterThan(before.generation);
    expect(after.startup.status).toBe(0);
    expect(await text(page.request, base + '/count')).toBe('once\n');
  } finally {
    await other.close();
    await rmrf(page.request, base);
  }
});

test('losing a running execution host records an ended run without repeating its units', async ({ page }) => {
  const pageKernel = await ready(page);
  const { base, file } = await units(page, 'echo once >> $BASE/count; echo STARTED; while :; do sleep 1; done');
  try {
    await selected(page, file);
    await expect.poll(async () => (await state(page)).services.output, { timeout: 30_000 }).toContain('STARTED');
    const managedPid = (await state(page)).session.managed?.pid;
    expect(managedPid).toBeGreaterThan(1);

    // Terminate the running managed supervisor directly; startup records the ended run
    // without repeating its units on coordinator refresh.
    await pageKernel.value('kill', { pid: managedPid, signal: 9 });
    await expect.poll(async () => (await state(page)).session.startup.state, { timeout: 30_000, intervals: [250] }).toBe('finished');
    await pageKernel.value('login_leave');
    await pageKernel.value('login_refresh', { fromServer: false });
    await expect.poll(async () => (await state(page)).coordinator, { timeout: 20_000 }).toBe(true);
    expect((await state(page)).session.startup.attempts).toBe(1);
    expect((await state(page)).session.managed).toBe(null);
    expect(await text(page.request, base + '/count')).toBe('once\n');
  } finally {
    await stop(page).catch(() => {});
    await rmrf(page.request, base);
  }
});

test('enabled units start again on a fresh authenticated login while guest startup stays separate', async ({ page }) => {
  await ready(page);
  const { base, file } = await units(page, 'echo signed-in >> $BASE/count');
  try {
    await signIn(page.request);
    await refresh(page);
    await expect.poll(async () => (await state(page)).session?.uid).toBe(0);
    await selected(page, file);
    await completed(page);
    const first = (await state(page)).session;

    await api(page.request, 'logout');
    await refresh(page);
    await expect.poll(async () => { const s = await state(page); return s.connected && s.session?.uid > 0; }).toBe(true);
    expect((await state(page)).session.startup).toBe(null);
    expect((await state(page)).services.output).toBe('');

    await signIn(page.request);
    await refresh(page);
    await expect.poll(async () => (await state(page)).session?.uid).toBe(0);
    await completed(page);
    expect((await state(page)).session.id).not.toBe(first.id);
    expect(await text(page.request, base + '/count')).toBe('signed-in\nsigned-in\n');
    await selected(page, null);
  } finally {
    await stop(page);
    await rmrf(page.request, base);
  }
});

test('confirmed logout stops automatic services gracefully and preserves an independent process', async ({ page }) => {
  await ready(page);
  const { base, file } = await units(page, 'trap "id -u > $BASE/stopped; exit 0" TERM; echo PRIVATE-ROOT; while :; do sleep 0.1; done');
  try {
    await signIn(page.request);
    await refresh(page);
    await expect.poll(async () => (await state(page)).session?.uid).toBe(0);
    await selected(page, file);
    await expect.poll(async () => (await state(page)).services.output, { timeout: 30_000 }).toContain('PRIVATE-ROOT');
    await page.evaluate(() => {
      window.independent = { output: '' };
      window.independent.done = window.os.exec([['sh', '-c', 'echo INDEPENDENT; while :; do sleep 0.1; done']], {
        stdin: '',
        tty: true,
        onOutput: (_fd, s) => { independent.output += s; },
        onJob: job => { independent.job = job; },
      }).then(result => { independent.result = result; });
    });
    await expect.poll(() => page.evaluate(() => independent.output)).toContain('INDEPENDENT');
    await api(page.request, 'logout');
    await refresh(page);
    await expect.poll(async () => { const s = await state(page); return s.connected && s.session?.uid > 0; }).toBe(true);
    expect((await state(page)).services.output).toBe('');
    await expect.poll(async () => { try { return await text(page.request, base + '/stopped'); } catch { return ''; } }, { timeout: 15_000 }).toBe('0\n');
    expect(await page.evaluate(() => independent.result)).toBeUndefined();
  } finally {
    await page.evaluate(async () => { independent?.job?.signal(9); await independent?.done; }).catch(() => {});
    await stop(page);
    await rmrf(page.request, base);
  }
});

test('takeover while the supervisor image loads abandons the old candidate before guest execution', async ({ page, context }) => {
  const pageKernel = await ready(page);
  const { base, file } = await units(page, 'echo once >> $BASE/count');
  let release, waiting = false;
  const blocked = new Promise(resolve => { release = resolve; });
  await context.route(executableAsset('supervise'), async route => {
    if (!waiting) {
      waiting = true;
      await blocked;
    }
    await route.continue();
  });
  try {
    await selected(page, file);
    await expect.poll(() => waiting).toBe(true);
    // Departure while the first candidate is still loading fences its attempt; reclaiming starts attempt 2.
    await pageKernel.value('login_leave');
    await expect.poll(async () => (await state(page)).coordinator).toBe(false);
    await pageKernel.value('login_refresh', { fromServer: false });
    await expect.poll(async () => (await state(page)).coordinator, { timeout: 20_000 }).toBe(true);
    await completed(page);
    release();
    await page.waitForTimeout(800);
    expect((await state(page)).session.startup.attempts).toBe(2);
    expect(await text(page.request, base + '/count')).toBe('once\n');
  } finally {
    release();
    await rmrf(page.request, base).catch(() => {});
  }
});

test('manifest failure stays terminal until explicitly reconfigured, and output remains bounded', async ({ page }) => {
  await ready(page);
  const { base, file, write } = await units(page, 'echo bad');
  try {
    expect((await put(page.request, '/api/file?path=' + file + '&overwrite=true', { data: JSON.stringify({ version: 99, units: [] }) })).ok()).toBe(true);
    await selected(page, file);
    await completed(page, 1);
    const failed = (await state(page)).session.startup;
    await page.waitForTimeout(5500);
    expect((await state(page)).session.startup.attempts).toBe(1);
    await write('yes LOGIN-OUTPUT | head -n 3000');
    await selected(page, file);
    await completed(page);
    const after = await state(page);
    expect(after.session.startup.revision).not.toBe(failed.revision);
    expect(after.services.output.length).toBeLessThanOrEqual(8192);
    expect(after.services.truncated).toBe(true);
    expect(after.services.output).toContain('LOGIN-OUTPUT');
  } finally {
    await stop(page);
    await rmrf(page.request, base);
  }
});

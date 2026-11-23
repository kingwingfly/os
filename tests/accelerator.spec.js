import { test, expect, request as requests } from './test.js';
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { api, call, errno, mkdirp, put, rmrf, sys } from './sys.js';
import { attachInstance, FULL_SCOPE } from './service-auth.js';
import { device, directory, ACCEL } from './accelerator.js';
import { zipOf } from './archive-fixtures.js';
const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const password = process.env.OS_TEST_ADMIN_PASSWORD || process.env.OS_PASSWORD || (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const file = path => '/api/file?path=' + encodeURIComponent(path);
test.setTimeout(180_000);
let base, headers;
test.beforeEach(async ({ request }) => {
  base = '/accelerator-' + Date.now().toString(36);
  headers = { Origin: origin, 'CF-Connecting-IP': base };
  expect((await api(request, 'login', { headers, data: { password } })).ok()).toBe(true);
  await mkdirp(request, base + '/dest');
  await put(request, file(base + '/input.txt'), { headers, data: 'original\n' });
  await put(request, file(base + '/source.zip'), { headers, data: zipOf([['file.txt', 'replacement\n']]) });
  await put(request, file(base + '/dest/file.txt'), { headers, data: 'keep\n' });
});
test.afterEach(async ({ request }) => { await rmrf(request, base).catch(() => {}); });
async function extraction(request, target = 'dest') {
  const driver = await device(request), at = await directory(request, base);
  const operation = { operation: 'extract', format: 'zip', source: at('source.zip'),
    destination: at(target), existing: 'ask', members: [], verbose: false };
  return { driver, at, operation, task: await driver.submit(operation) };
}
async function question(task) {
  await expect.poll(async () => (await task.poll()).state, { timeout: 120_000 }).toBe('question');
  return (await task.poll()).events.find(e => e.event === 'conflict');
}

test('versioned requests reject forged handles and retries never repeat completed writes', async ({ request }) => {
  const driver = await device(request), at = await directory(request, base);
  const operation = { operation: 'create', format: 'zip', output: at('result.zip'),
    inputs: [{ source: at('input.txt'), name: 'input.txt' }], recursive: false, links: false, verbose: false };
  const task = await driver.submit(operation, 'stable-retry');
  await expect.poll(async () => (await task.poll()).state, { timeout: 120_000 }).toBe('done');
  await call(request, { unlink: { path: base + '/result.zip' } });
  expect((await driver.submit(operation, 'stable-retry')).id).toBe(task.id);
  expect(await errno(request, { stat: { path: base + '/result.zip' } })).toBe('ENOENT');
  const submit = operation => ({ ioctl: { fd: driver.fd, request: ACCEL.submit,
    arg: { version: 1, request: 'bad-request', operation } } });
  expect(await errno(request, submit({ ...operation, output: { directory: 0xffffffff, name: 'bad.zip' } }))).toBe('EBADF');
  expect(await errno(request, submit({ ...operation, output: at('../bad.zip') }))).toBe('EINVAL');
  expect(await errno(request, { ioctl: { fd: driver.fd, request: ACCEL.submit,
    arg: { version: 1, request: 'stable-retry', operation: { ...operation, verbose: true } } } })).toBe('EEXIST');
  expect(await errno(request, { pread: { fd: at('.').directory, count: 1 } })).toBe('EBADF');
  expect(await errno(request, { ioctl: { fd: driver.fd, request: ACCEL.poll,
    arg: { version: 1, id: task.id, after: 0, limit: 129 } } })).toBe('EINVAL');
  await task.close();
});

test('a stale decision or replaced destination cannot expand a remote write grant', async ({ request }) => {
  const { task, driver } = await extraction(request);
  const conflict = await question(task), decisions = Object.fromEntries(conflict.paths.map(p => [p, true]));
  expect(await errno(request, { ioctl: { fd: driver.fd, request: ACCEL.answer,
    arg: { version: 1, id: task.id, sequence: conflict.sequence + 1, decisions } } })).toBe('EAGAIN');
  await call(request, { rename: { from: base + '/dest', to: base + '/original' } });
  await mkdirp(request, base + '/dest');
  await task.answer(conflict.sequence, decisions);
  await expect.poll(async () => (await task.poll()).status, { timeout: 120_000 }).toBe(1);
  expect(await errno(request, { stat: { path: base + '/dest/file.txt' } })).toBe('ENOENT');
  expect(await (await request.get(file(base + '/original/file.txt'))).text()).toBe('keep\n');
  await task.close();
});

test('pre-existing symlinks do not turn directory grants into access outside the destination', async ({ request }) => {
  await mkdirp(request, base + '/outside');
  await put(request, file(base + '/outside/file.txt'), { headers, data: 'untouched\n' });
  await put(request, file(base + '/source.zip') + '&overwrite=true', { headers, data: zipOf([['pivot/file.txt', 'escape\n']]) });
  await call(request, { symlink: { path: base + '/dest/pivot', target: base + '/outside' } });
  const driver = await device(request), at = await directory(request, base);
  const task = await driver.submit({ operation: 'extract', format: 'zip', source: at('source.zip'),
    destination: at('dest'), existing: 'replace', members: [], verbose: true });
  await expect.poll(async () => (await task.poll()).status, { timeout: 120_000 }).toBe(1);
  expect(await (await request.get(file(base + '/outside/file.txt'))).text()).toBe('untouched\n');
  await task.close();
});

test('submission backpressure is bounded and closing the owner cancels every attached task', async ({ request }) => {
  const driver = await device(request), at = await directory(request, base);
  const operation = { operation: 'extract', format: 'zip', source: at('source.zip'),
    destination: at('dest'), existing: 'ask', members: [], verbose: false };
  const tasks = [];
  try {
    for (let i = 0; i < 16; i++) tasks.push(await driver.submit(operation));
    expect(await errno(request, { ioctl: { fd: driver.fd, request: ACCEL.submit,
      arg: { version: 1, request: 'queue-full', operation } } })).toBe('EAGAIN');
  } finally { await call(request, { close: { fd: driver.fd } }); }
  const observer = await device(request);
  for (const { id } of tasks) {
    const task = await observer.attach(id);
    expect((await task.poll()).state).toBe('cancelled');
  }
  await call(request, { close: { fd: observer.fd } });
});

test('O_PATH directories need search permission, without granting read access or another account control', async ({ request }) => {
  await call(request, { chmod: { path: base + '/dest', mode: 0o111 } });
  const guest = await requests.newContext({ baseURL: origin, extraHTTPHeaders: { Origin: origin } });
  try {
    expect(await errno(guest, { open: { path: base + '/dest', flags: 0 } })).toBe('EACCES');
    const at = await directory(guest, base + '/dest');
    expect(await errno(guest, { pread: { fd: at('.').directory, count: 1 } })).toBe('EBADF');
    expect(await errno(guest, { getdents: { path: `/proc/self/fd/${at('.').directory}` } })).toBe('EACCES');
    await call(guest, { close: { fd: at('.').directory } });
  } finally { await guest.dispose(); }
});

test('remote sudo is retired (ENOSYS) and non-root cloud users cannot escalate via ServiceAuth v2 mint', async ({ request }) => {
  const suffix = randomUUID().replaceAll('-', '').slice(0, 8);
  const name = 'accel' + suffix, secret = 'accelerator test password ' + name;
  const user = await requests.newContext({
    baseURL: origin,
    extraHTTPHeaders: { Origin: origin, 'CF-Connecting-IP': 'accel-refusal-' + suffix },
  });
  let inst, cred, home;
  try {
    expect((await api(user, 'register', { data: { username: name, password: secret, create_home: true } })).ok()).toBe(true);
    const creds = await call(user, 'getcreds');
    expect(creds.uid).not.toBe(0);
    home = creds.home;
    // Contract v2 §2.4: server Call::Sudo is retired and returns ENOSYS.
    expect(await errno(user, { sudo: { password: secret, revoke: false } })).toBe('ENOSYS');
    const sudoRes = await api(user, 'sudo', { data: { password: secret } });
    expect(sudoRes.status()).toBe(501);
    expect((await sudoRes.json()).errno).toBe('ENOSYS');
    // ServiceAuth v2 mint with sudo: true fails closed (EPERM) for non-root cloud users.
    inst = await attachInstance(user, { origin });
    let mintError = null;
    try {
      await inst.mint({ scope: FULL_SCOPE, cloud_access: true, sudo: true });
    } catch (err) {
      mintError = err;
    }
    expect(mintError).toBeTruthy();
    expect(mintError.errno).toBe('EPERM');
    // Ordinary non-sudo mint succeeds with the non-root cloud user's own uid (never uid 0).
    cred = await inst.mint({ scope: FULL_SCOPE, cloud_access: true });
    expect(cred.uid).toBe(creds.uid);
    expect(cred.uid).not.toBe(0);
  } finally {
    if (cred && inst) await inst.revoke([cred.token]).catch(() => {});
    if (inst) await inst.detach().catch(() => {});
    await user.dispose();
    if (home) await rmrf(request, home).catch(() => {});
  }
});

test('explicit cloud root ServiceAuth v2 credentials preserve controller ownership and root execution across detach and token revocation', async ({ request }) => {
  const suffix = randomUUID().replaceAll('-', '').slice(0, 8);
  const rootUser = await requests.newContext({
    baseURL: origin,
    extraHTTPHeaders: { Origin: origin, 'CF-Connecting-IP': 'accel-root-' + suffix },
  });
  const stranger = await requests.newContext({
    baseURL: origin,
    extraHTTPHeaders: { Origin: origin, 'CF-Connecting-IP': 'accel-stranger-' + suffix },
  });
  let inst, cred, fsConn;
  const fsCall = async (token, session, fsOp) => {
    const res = await rootUser.post(origin + '/api/fs', {
      headers: { Origin: origin, 'X-OS-Instance': inst.instanceId },
      data: { version: 2, credential: token, session, call: fsOp },
    });
    const body = await res.json();
    expect(res.ok(), JSON.stringify(body)).toBe(true);
    return body;
  };
  try {
    expect((await api(rootUser, 'login', { data: { username: 'root', password } })).ok()).toBe(true);
    expect((await api(stranger, 'register', { data: { username: 'stranger' + suffix, password: 'stranger test pass ' + suffix, create_home: false } })).ok()).toBe(true);
    inst = await attachInstance(rootUser, { origin });
    cred = await inst.mint({ scope: FULL_SCOPE, cloud_access: true });
    expect(cred.uid).toBe(0);

    // Open base directory as a v2 O_PATH OpenRef under the explicit cloud root ServiceAuth v2 credential.
    fsConn = await fsCall(cred.token, null, 'connect');
    const walked = await fsCall(cred.token, fsConn.session, { walk: { dir: fsConn.root, names: base.split('/').filter(Boolean) } });
    const baseHandle = walked.entries.at(-1).handle;
    const baseOpen = await fsCall(cred.token, fsConn.session, {
      open: {
        ticket: randomUUID(),
        handle: baseHandle,
        options: { read: false, write: false, append: false, append_implies_write: false, truncate: false, create: false, create_new: false, exec: false, path: true },
      },
    });
    const at = entry => ({ directory: 0, open: baseOpen, name: entry });
    const extra = {
      'X-OS-Instance': inst.instanceId,
      'X-Fs-Session': fsConn.session.id,
      'X-Fs-Secret': fsConn.session.secret,
    };
    const procCall = async c => {
      const [res] = await sys(rootUser, [c], { proc: cred.token }, extra);
      expect(res.err, JSON.stringify(res)).toBeUndefined();
      return res.ok;
    };
    const { fd } = await procCall({ open: { path: '/dev/archive', flags: 2 } });
    const ioctl = (op, arg) => procCall({ ioctl: { fd, request: ACCEL[op], arg } });
    const submitted = await ioctl('submit', {
      version: 1,
      request: randomUUID(),
      operation: {
        operation: 'extract',
        format: 'zip',
        source: at('source.zip'),
        destination: at('dest'),
        existing: 'ask',
        members: [],
        verbose: false,
      },
    });
    const task = {
      id: submitted.id,
      poll: (after = 0, limit = 128) => ioctl('poll', { version: 1, id: submitted.id, after, limit }),
      detach: () => ioctl('detach', { version: 1, id: submitted.id }),
    };
    await question(task);
    await task.detach();
    await procCall({ close: { fd } });
    await fsCall(cred.token, fsConn.session, { release: { open: baseOpen } });
    await fsCall(cred.token, fsConn.session, 'disconnect');
    fsConn = null;
    const revokedToken = cred.token;
    await inst.revoke([revokedToken]);
    cred = null;

    // Revoked ServiceAuth v2 token is rejected immediately; non-root cloud users cannot attach.
    const [revokedOpen] = await sys(rootUser, [{ open: { path: '/dev/archive', flags: 2 } }], { proc: revokedToken }, { 'X-OS-Instance': inst.instanceId });
    expect(revokedOpen.err?.errno).toBe('EPERM');
    const strangerDev = await device(stranger);
    expect(await errno(stranger, { ioctl: { fd: strangerDev.fd, request: ACCEL.attach, arg: { version: 1, id: task.id } } })).toBe('EPERM');
    await call(stranger, { close: { fd: strangerDev.fd } });

    // Re-attach from another explicit cloud root handle and complete extraction as uid 0.
    const resumed = await (await device(rootUser)).attach(task.id);
    const conflict = await question(resumed);
    await resumed.answer(conflict.sequence, Object.fromEntries(conflict.paths.map(p => [p, true])));
    await expect.poll(async () => (await resumed.poll()).status, { timeout: 120_000 }).toBe(0);
    expect(await (await request.get(file(base + '/dest/file.txt'))).text()).toBe('replacement\n');
    expect((await call(request, { stat: { path: base + '/dest/file.txt' } })).uid).toBe(0);
    await resumed.close();
  } finally {
    if (fsConn && cred && inst) await fsCall(cred.token, fsConn.session, 'disconnect').catch(() => {});
    if (inst) await inst.detach().catch(() => {});
    await stranger.dispose();
    await rootUser.dispose();
  }
});

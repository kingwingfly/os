import { test, expect, request as requests } from './test.js';
import { readFile } from 'node:fs/promises';
import { api, call, errno, mkdirp, program, put, rmrf } from './sys.js';
import { device, directory, ACCEL } from './accelerator.js';
import { zipOf } from './archive-fixtures.js';
const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
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

test('sudo preserves the initiating account as controller while execution retains root credentials', async ({ request }) => {
  const name = 'accel' + Date.now().toString(36).slice(-7), secret = 'accelerator test password ' + name;
  expect((await program(request, ['useradd', '-m', '-G', 'wheel', name])).ok()).toBe(true);
  await api(request, 'passwd', { data: { username: name, password: secret, force: true, sudo: true } });
  const user = await requests.newContext({ baseURL: origin, extraHTTPHeaders: { Origin: origin } });
  let process;
  try {
    expect((await api(user, 'login', { data: { username: name, password: secret } })).ok()).toBe(true);
    expect((await api(user, 'sudo', { data: { password: secret } })).ok()).toBe(true);
    process = await call(user, { execve: { path: '/usr/bin/utilities', argv: ['unzip'], cwd: base } }, { sudo: true });
    const options = { pid: process.pid, proc: process.token };
    const driver = await device(user, '/dev/archive', options), at = await directory(user, base, options);
    const task = await driver.submit({ operation: 'extract', format: 'zip', source: at('source.zip'),
      destination: at('dest'), existing: 'ask', members: [], verbose: false });
    await question(task);
    await task.detach();
    await call(user, { exit: { status: 0 } }, options);
    process = null;
    const resumed = await (await device(user)).attach(task.id);
    const conflict = await question(resumed);
    await resumed.answer(conflict.sequence, Object.fromEntries(conflict.paths.map(p => [p, true])));
    await expect.poll(async () => (await resumed.poll()).status, { timeout: 120_000 }).toBe(0);
    expect(await (await request.get(file(base + '/dest/file.txt'))).text()).toBe('replacement\n');
    expect((await call(request, { stat: { path: base + '/dest/file.txt' } })).uid).toBe(0);
    await resumed.close();
  } finally {
    if (process) await call(user, { exit: { status: 1 } }, { pid: process.pid, proc: process.token }).catch(() => {});
    await user.dispose();
    await call(request, { userdel: { name, remove: true } }, { sudo: true }).catch(() => {});
  }
});

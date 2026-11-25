import { test, expect, request as playwrightRequest } from './test.js';
import { randomUUID } from 'node:crypto';
import { device, directory, ACCEL } from './accelerator.js';
import { readFile } from 'node:fs/promises';
import { zipOf, tarOf } from './archive-fixtures.js';
import { api, call, errno, listing, mkdirp, processes, program, put, rmrf, sys } from './sys.js';
import { attachInstance, FULL_SCOPE, hookPageKernel } from './service-auth.js';
import {
  cloudSignIn,
  cloudSignOut,
  pageCall,
  runTerminal,
  sendTerminalLine,
  terminalInput,
  terminalScreen,
  terminalViewport,
  waitForTerminalReady,
} from './ui.js';
const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const password = process.env.OS_TEST_ADMIN_PASSWORD || process.env.OS_PASSWORD || (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const file = path => '/api/file?path=' + encodeURIComponent(path);
const ls = (request, path) => listing(request, path).catch(() => []);
// Archive jobs start a container; give them time.
test.setTimeout(240_000);
let base, headers;

async function registerCloudUser(prefix, { createHome = false } = {}) {
  const suffix = randomUUID().replaceAll('-', '').slice(0, 8);
  const name = `${prefix}${suffix}`;
  const secret = `archive user passphrase ${name}`;
  const ctx = await playwrightRequest.newContext({
    baseURL: origin,
    extraHTTPHeaders: { Origin: origin, 'CF-Connecting-IP': `${prefix}-${suffix}` },
  });
  const res = await api(ctx, 'register', { data: { username: name, password: secret, create_home: createHome } });
  expect(res.ok(), await res.text()).toBe(true);
  return { name, secret, ctx };
}

test.beforeEach(async ({ request, page }) => {
  base = '/archive-' + Date.now().toString(36);
  headers = { Origin: origin, 'CF-Connecting-IP': 'archive-' + base };
  await page.setExtraHTTPHeaders({ 'CF-Connecting-IP': 'archive-ui-' + base });
  expect((await api(request, 'login', { headers, data: { password } })).ok()).toBe(true);
  for (const dir of ['/docs/deep', '/ro']) await mkdirp(request, base + dir);
  const files = { 'docs/a.md': 'alpha\n'.repeat(2000), 'docs/deep/spéctrum notes.txt': 'γάμμα\n', 'docs/run.sh': '#!/bin/sh\necho hi\n' };
  for (const [name, text] of Object.entries(files)) expect((await put(request, file(base + '/' + name), { headers, data: text })).status()).toBe(201);
  expect((await program(request, ['chmod', '755', base + '/docs/run.sh'])).ok()).toBe(true);
  expect((await program(request, ['chmod', '555', base + '/ro'])).ok()).toBe(true);
});
test.afterEach(async ({ request }) => {
  await program(request, ['chmod', '755', base + '/ro']);
  await rmrf(request, base);
});

const screen = page => terminalScreen(page);
async function promptSeq(page) {
  return Number((await terminalViewport(page).getAttribute('data-prompt-seq')) || '0');
}
async function waitIdleAfter(page, before, timeout = 180_000) {
  await expect.poll(async () => {
    const vp = terminalViewport(page);
    return (await vp.getAttribute('data-state')) === 'idle'
      && Number((await vp.getAttribute('data-prompt-seq')) || '0') > before;
  }, { timeout }).toBe(true);
}
async function run(page, text, { wait = true } = {}) {
  await runTerminal(page, text, { wait, timeout: 180_000 });
}
async function runOutput(page, command) {
  const id = randomUUID().slice(0, 8);
  const start = `__S_${id}__`, end = `__E_${id}__`;
  await run(page, `echo ${start}; ${command}; echo ${end}`);
  await expect(screen(page)).toContainText(end, { timeout: 30_000 });
  const raw = '\n' + (await screen(page).innerText());
  const from = raw.lastIndexOf('\n' + start + '\n');
  expect(from, `start marker ${start} missing from screen`).toBeGreaterThanOrEqual(0);
  const bodyStart = from + start.length + 2;
  const to = raw.indexOf(end, bodyStart);
  expect(to, `end marker ${end} missing from screen`).toBeGreaterThanOrEqual(bodyStart);
  return raw.slice(bodyStart, to).replace(/\n$/, '');
}
async function terminal(page, { username = 'root', secret = password, cwd = `/mnt/cloud${base}` } = {}) {
  await page.goto('/');
  await page.waitForFunction(() => Boolean(window.os?.cloudSignIn && window.os?.exec));
  await waitForTerminalReady(page, 60_000);
  const status = await cloudSignIn(page, username, secret);
  expect(status.signed_in).toBe(true);
  expect(status.cloud_mounted).toBe(true);
  if (cwd) await run(page, 'cd ' + cwd);
}

test('zip, unzip and tar round-trip files, names and modes through the container', async ({ page, request }) => {
  await terminal(page);
  await run(page, 'zip -r notes.zip docs');
  await expect(screen(page)).toContainText('adding: docs/deep/spéctrum notes.txt');
  expect(await runOutput(page, 'unzip -l notes.zip | grep -c docs/')).toBe('5');
  await run(page, 'unzip -d restored notes.zip');
  await expect(screen(page)).toContainText('inflating: ' + base + '/restored/docs/a.md');
  for (const name of ['docs/a.md', 'docs/deep/spéctrum notes.txt', 'docs/run.sh']) {
    const [original, copy] = await Promise.all([request.get(file(base + '/' + name)), request.get(file(base + '/restored/' + name))]);
    expect(await copy.text()).toBe(await original.text());
  }
  const restored = Object.fromEntries((await ls(request, base + '/restored/docs')).map(e => [e.name, e.mode]));
  expect(restored['run.sh']).toBe(0o755); expect(restored['a.md']).toBe(0o644);
  await run(page, 'tar -czf notes.tgz docs');
  expect(await runOutput(page, 'tar -tf notes.tgz | sort')).toBe('docs/\ndocs/a.md\ndocs/deep/\ndocs/deep/spéctrum notes.txt\ndocs/run.sh');
  await run(page, 'mkdir untarred'); await run(page, 'tar -xvf notes.tgz -C untarred');
  expect(await (await request.get(file(base + '/untarred/docs/deep/spéctrum notes.txt'))).text()).toBe('γάμμα\n');
  // zip does not update an archive; tar -c replaces one.
  expect(await runOutput(page, 'zip -r notes.zip docs')).toContain('does not update archives');
  await run(page, 'tar -cf notes.tgz docs/a.md');
  expect(await runOutput(page, 'tar -tf notes.tgz')).toBe('docs/a.md');
  // Immutable /usr directories have synthetic inode handles; their bytes still stream
  // through the registered asset gateway rather than an R2 object invented by the client.
  await run(page, 'tar -cf system.tar -C /usr/bin utilities');
  await run(page, 'mkdir system-copy');
  await run(page, 'tar -xf system.tar -C system-copy');
  const [installed, archived] = await Promise.all([
    request.get(file('/usr/bin/utilities')), request.get(file(base + '/system-copy/utilities')),
  ]);
  expect(await archived.body()).toEqual(await installed.body());
});

test('typed devices separate completion events from executor lifecycle and enforce control ownership', async ({ page, request }) => {
  const resource = await directory(request, base), driver = await device(request);
  const create = await driver.submit({ operation: 'create', format: 'zip', output: resource('docs.zip'),
    inputs: [{ source: resource('docs'), name: 'docs' }], recursive: true, links: false, verbose: true });
  const pid = create.id;
  await expect.poll(async () => (await create.poll()).state, { timeout: 120_000 }).toBe('done');
  expect((await ls(request, base)).map(entry => entry.name)).toContain('docs.zip');
  expect((await processes(request)).map(process => process.pid)).toContain(pid);
  const waited = await call(request, { wait: { pid } });
  expect(waited).toEqual({ pid, state: 'zombie', status: 0 });
  const asking = await driver.submit({ operation: 'extract', format: 'zip', source: resource('docs.zip'),
    destination: resource('.'), existing: 'ask', members: [], verbose: true });
  await expect.poll(async () => (await asking.poll()).state, { timeout: 120_000 }).toBe('question');
  const question = (await asking.poll()).events.find(event => event.event === 'conflict');
  const decisions = Object.fromEntries(question.paths.map(path => [path, false]));
  await asking.answer(question.sequence, decisions);
  await expect.poll(async () => (await asking.poll()).state, { timeout: 120_000 }).toBe('done');
  expect(await errno(request, { ioctl: { fd: driver.fd, request: ACCEL.submit,
    arg: { version: 2, request: 'unsupported', operation: { operation: 'list', format: 'zip', source: resource('docs.zip'), verbose: false } } } })).toBe('EOPNOTSUPP');
  expect(await errno(request, { kill: { pid: 'f'.repeat(32) } })).toBe('ESRCH');
  const stranger = await playwrightRequest.newContext({ baseURL: origin, extraHTTPHeaders: { Origin: origin, 'CF-Connecting-IP': 'archive-stranger-' + base } });
  try {
    expect(await errno(stranger, { kill: { pid } })).toBe('EPERM');
    const other = await device(stranger);
    expect(await errno(stranger, { ioctl: { fd: other.fd, request: ACCEL.attach, arg: { version: 1, id: pid } } })).toBe('EPERM');
  } finally { await stranger.dispose(); }
  await terminal(page);
  expect(await runOutput(page, 'kill ffffffff')).toContain('kill: (ffffffff) - No such process');
});

test('a job keeps the credentials it was spawned with, and its own descriptors', async ({ request }) => {
  // Phase 4 (issue #20) + Contract v2: a job is a server process whose spawn snapshots who started
  // it (uid/gid/groups + umask). Revoking the initiating user's ServiceAuth v2 token and logging
  // out its Cloud session while the container starts does not fail the detached job, and its open
  // source descriptor shows in /proc/PID/fd until completion revokes the job's own credential.
  const { name, secret, ctx: user } = await registerCloudUser('jobber', { createHome: true });
  let home, inst, cred, fsConn, observer;
  const fsCall = async (token, session, fsOp) => {
    const res = await user.post(origin + '/api/fs', {
      headers: { Origin: origin, 'X-OS-Instance': inst.instanceId },
      data: { version: 2, credential: token, session, call: fsOp },
    });
    const body = await res.json();
    expect(res.ok(), JSON.stringify(body)).toBe(true);
    return body;
  };
  try {
    const creds = await call(user, 'getcreds');
    const uid = creds.uid;
    home = creds.home;
    expect((await put(user, file(`${home}/greeting.zip`), { headers: { Origin: origin }, data: zipOf([['private/hello.txt', 'hello\n']]) })).status()).toBe(201);
    inst = await attachInstance(user, { origin });
    cred = await inst.mint({ scope: FULL_SCOPE, cloud_access: true, umask: 0o077 });
    expect(cred.uid).toBe(uid);
    fsConn = await fsCall(cred.token, null, 'connect');
    const walked = await fsCall(cred.token, fsConn.session, { walk: { dir: fsConn.root, names: home.split('/').filter(Boolean) } });
    const homeHandle = walked.entries.at(-1).handle;
    const homeOpen = await fsCall(cred.token, fsConn.session, {
      open: {
        ticket: randomUUID(),
        handle: homeHandle,
        options: { read: false, write: false, append: false, append_implies_write: false, truncate: false, create: false, create_new: false, exec: false, path: true },
      },
    });
    const resource = entry => ({ directory: 0, open: homeOpen, name: entry });
    const extra = {
      'X-OS-Instance': inst.instanceId,
      'X-Fs-Session': fsConn.session.id,
      'X-Fs-Secret': fsConn.session.secret,
    };
    const procCall = async c => {
      const [res] = await sys(user, [c], { proc: cred.token }, extra);
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
        source: resource('greeting.zip'),
        destination: resource('.'),
        existing: 'ask',
        members: [],
        verbose: true,
      },
    });
    const pid = submitted.id;
    await ioctl('detach', { version: 1, id: pid });
    // The archive it reads is a descriptor of its own.
    const fds = await call(user, { getdents: { path: `/proc/${pid}/fd` } });
    expect(fds).toHaveLength(1);
    expect(await call(user, { readlink: { path: `/proc/${pid}/fd/${fds[0].name}` } })).toBe(`${home}/greeting.zip`);
    // Revoke the user's ServiceAuth v2 token AND log out its Cloud session while its container
    // starts: the detached job goes on with the credentials and umask it was spawned with.
    await procCall({ close: { fd } });
    await fsCall(cred.token, fsConn.session, { release: { open: homeOpen } });
    await fsCall(cred.token, fsConn.session, 'disconnect');
    fsConn = null;
    await inst.revoke([cred.token]);
    cred = null;
    expect((await api(user, 'logout')).ok()).toBe(true);
    observer = await (await device(request)).attach(pid);
    let state;
    await expect.poll(async () => (state = await observer.poll()).state, { timeout: 120_000 }).toMatch(/^(done|failed|cancelled)$/);
    expect(state.state, JSON.stringify(state.lines)).toBe('done');
    const made = await call(request, { stat: { path: `${home}/private/hello.txt` } });
    expect(made.uid).toBe(uid);
    expect(await (await request.get(file(`${home}/private/hello.txt`))).text()).toBe('hello\n');
    // The runner omits umask from its requests: implicit parents retain the spawn mask.
    expect((await call(request, { stat: { path: `${home}/private` } })).mode & 0o777).toBe(0o700);
    // Ended, its credentials are revoked, and what it had open is closed.
    expect((await api(user, 'login', { data: { username: name, password: secret } })).ok()).toBe(true);
    expect(await call(user, { getdents: { path: `/proc/${pid}/fd` } })).toEqual([]);
  } finally {
    if (observer) await observer.close().catch(() => {});
    if (fsConn && cred && inst) await fsCall(cred.token, fsConn.session, 'disconnect').catch(() => {});
    if (inst) await inst.detach().catch(() => {});
    await user.dispose();
    if (home) await rmrf(request, home).catch(() => {});
  }
});

test('unzip asks before replacing, -o and -n decide, tar -k keeps, and hostile members are skipped', async ({ page, request }) => {
  await terminal(page);
  await run(page, 'zip -rq notes.zip docs');
  await run(page, 'unzip -q notes.zip -d copy');
  for (const name of ['a.md', 'run.sh']) await put(request, file(`${base}/copy/docs/${name}`) + '&overwrite=true', { headers, data: 'changed\n' });
  // Asked: yes for the first, then None for the rest.
  const beforeAsk = await promptSeq(page);
  await run(page, 'unzip notes.zip -d copy', { wait: false });
  await expect(screen(page)).toContainText('replace ' + base + '/copy/docs/a.md? [y]es, [n]o, [A]ll, [N]one', { timeout: 120_000 });
  await sendTerminalLine(page, 'y');
  await expect.poll(async () => (await screen(page).innerText()).split('? [y]es, [n]o, [A]ll, [N]one').length - 1, { timeout: 30_000 }).toBeGreaterThanOrEqual(2);
  await sendTerminalLine(page, 'N');
  await waitIdleAfter(page, beforeAsk, 120_000);
  expect(await (await request.get(file(base + '/copy/docs/a.md'))).text()).toBe('alpha\n'.repeat(2000));
  expect(await (await request.get(file(base + '/copy/docs/run.sh'))).text()).toBe('changed\n');
  await run(page, 'unzip -qn notes.zip -d copy');
  expect(await (await request.get(file(base + '/copy/docs/run.sh'))).text()).toBe('changed\n');
  await run(page, 'unzip -qo notes.zip -d copy');
  expect(await (await request.get(file(base + '/copy/docs/run.sh'))).text()).toBe('#!/bin/sh\necho hi\n');
  await run(page, 'tar -cf notes.tar docs');
  await put(request, file(base + '/copy/docs/a.md') + '&overwrite=true', { headers, data: 'kept\n' });
  await run(page, 'tar -xkf notes.tar -C copy');
  await expect(screen(page)).toContainText('copy/docs/a.md: Cannot open: File exists');
  expect(await (await request.get(file(base + '/copy/docs/a.md'))).text()).toBe('kept\n');
  await run(page, 'tar -xf notes.tar -C copy');
  expect(await (await request.get(file(base + '/copy/docs/a.md'))).text()).toBe('alpha\n'.repeat(2000));
  // A hostile archive: .. is skipped, a leading / removed, the rest extracted, its link as one.
  expect((await put(request, file(base + '/slip.zip'), { headers, data: await readFile('tests/fixtures/slip.zip') })).status()).toBe(201);
  await run(page, 'unzip slip.zip -d out');
  await expect(screen(page)).toContainText("skipping ../evil.txt: its name contains '..'");
  await expect(screen(page)).toContainText(`linking: ${base}/out/safe/link  -> ok.txt`);
  expect(await (await request.get(file(base + '/out/safe/link'))).text()).toBe('kept\n');
  expect(await (await request.get(file(base + '/out/safe/ok.txt'))).text()).toBe('kept\n');
  expect(await (await request.get(file(base + '/out/abs/root.txt'))).text()).toBe('rooted\n');
  expect((await request.head(file(base + '/evil.txt'))).status()).toBe(404);
  expect((await request.head(file('/evil.txt'))).status()).toBe(404);
  // Signed-out Cloud detaches /mnt/cloud and /dev/archive; non-root Cloud accounts cannot extract
  // into a directory they may not write.
  await run(page, 'cd /');
  await cloudSignOut(page);
  expect(await runOutput(page, `unzip /mnt/cloud${base}/notes.zip -d /mnt/cloud${base}/ro`)).toMatch(/No such file|Permission denied|not connected/i);
  const { name: guestName, secret: guestSecret, ctx: guestCtx } = await registerCloudUser('unpriv');
  try {
    const status = await cloudSignIn(page, guestName, guestSecret);
    expect(status.signed_in).toBe(true);
    expect(status.cloud_mounted).toBe(true);
    expect(await runOutput(page, `unzip /mnt/cloud${base}/notes.zip -d /mnt/cloud${base}/ro`)).toContain('Permission denied');
  } finally {
    await guestCtx.dispose();
  }
});

test('Ctrl+C cancels owned work; explicit detach survives closing its control handle', async ({ page, request }) => {
  await mkdirp(request, base + '/docs/many');
  for (let i = 0; i < 40; i++) expect((await put(request, file(`${base}/docs/many/f${String(i).padStart(2, '0')}.txt`), { headers, data: 'x'.repeat(1000 + i) })).status()).toBe(201);
  await terminal(page);
  await run(page, 'zip -rq many.zip docs/many');
  const beforeCancel = await promptSeq(page);
  await run(page, 'unzip many.zip -d stopped', { wait: false });
  await expect(screen(page)).toContainText('inflating:', { timeout: 120_000 });
  await terminalInput(page).press('Control+c');
  await waitIdleAfter(page, beforeCancel, 120_000);
  const stopped = await ls(request, base + '/stopped/docs/many');
  expect(stopped.length).toBeGreaterThan(0); expect(stopped.length).toBeLessThan(40);
  // What was extracted is whole; nothing is left half-written.
  expect(stopped.every(e => e.uploaded === undefined)).toBe(true);
  // A job started in a tab that closes runs to its end.
  await mkdirp(request, base + '/detached');
  const resource = await directory(request, base), driver = await device(request);
  const detached = await driver.submit({ operation: 'extract', format: 'zip', source: resource('many.zip'),
    destination: resource('detached'), existing: 'replace', members: [], verbose: false });
  await detached.detach();
  await detached.close();
  await expect.poll(async () => (await ls(request, base + '/detached/docs/many')).length, { timeout: 180_000 }).toBe(40);
});

test('extracting nothing ends at once and says why; modes are those archived, 000 too; long listings come whole', async ({ page, request }) => {
  const make = async (name, data) => expect((await put(request, file(base + '/' + name), { headers, data })).status()).toBe(201);
  await make('empty.zip', zipOf([])); await make('empty.tar', tarOf([])); await make('one.zip', zipOf([['a.txt', 'a']]));
  await make('modes.tar', tarOf([['normal.txt', 'new', 0o644], ['private.txt', 'new', 0], ['private-dir', '', 0, true], ['open', '', 0o755, true], ['closed', '', 0o755, true]]));
  await make('many.zip', zipOf(Array.from({ length: 700 }, (_, i) => [String(i).padStart(4, '0') + '.txt', 'x'])));
  await terminal(page);
  // Each ends once, rather than plan again and again.
  await run(page, 'unzip -d out empty.zip');
  await expect(screen(page)).toContainText('warning [' + base + '/empty.zip]:  zipfile is empty');
  await run(page, 'mkdir none'); await run(page, 'tar -xf empty.tar -C none');
  await run(page, 'unzip one.zip missing.txt -d out');
  await expect(screen(page)).toContainText('caution: filename not matched:  missing.txt');
  await run(page, 'tar -xf modes.tar -C none private.txt nothing.txt');
  await expect(screen(page)).toContainText('tar: nothing.txt: Not found in archive');
  expect((await screen(page).innerText()).split('zipfile is empty').length - 1).toBe(1);
  // The modes archived, less group and other write, also for files and directories that were
  // there; 644 for a file a zip says none of.
  await run(page, 'mkdir dest dest/open dest/closed');
  for (const [dir, mode] of [['open', '777'], ['closed', '700']]) expect((await program(request, ['chmod', mode, base + '/dest/' + dir])).ok()).toBe(true);
  expect((await put(request, file(base + '/dest/normal.txt'), { headers, data: 'old' })).status()).toBe(201);
  expect((await program(request, ['chmod', '755', base + '/dest/normal.txt'])).ok()).toBe(true);
  await run(page, 'tar -xf modes.tar -C dest'); await run(page, 'unzip -q one.zip -d dest');
  const modes = Object.fromEntries((await ls(request, base + '/dest')).map(e => [e.name, e.mode]));
  expect(modes).toEqual({ 'normal.txt': 0o644, 'private.txt': 0, 'private-dir': 0, 'open': 0o755, 'closed': 0o755, 'a.txt': 0o644 });
  const guest = await playwrightRequest.newContext({ baseURL: origin, extraHTTPHeaders: { 'CF-Connecting-IP': 'archive-guest-' + base } });
  expect((await guest.get(file(base + '/dest/private.txt'))).status()).toBe(401);
  expect((await put(guest, file(base + '/dest/open/guest.txt'), { headers: { Origin: origin }, data: 'x' })).status()).toBe(401);
  await guest.dispose();
  // A job's output comes page after page, to its end.
  expect(await runOutput(page, 'unzip -l many.zip | wc -l')).toBe('705');
});

test('extraction tells a guest nothing of what lies where it may not look', async ({ page, request }) => {
  await mkdirp(request, base + '/shared/private');
  expect((await program(request, ['chmod', '777', base + '/shared'])).ok()).toBe(true);
  expect((await program(request, ['chmod', '700', base + '/shared/private'])).ok()).toBe(true);
  expect((await put(request, file(base + '/shared/private/exists.txt'), { headers, data: 'kept' })).status()).toBe(201);
  expect((await put(request, file(base + '/probe.zip'), { headers, data: zipOf([['private/exists.txt', 'x'], ['private/missing.txt', 'y']]) })).status()).toBe(201);
  const { name: guestName, secret: guestSecret, ctx: guestCtx } = await registerCloudUser('probe');
  try {
    await terminal(page, { username: guestName, secret: guestSecret, cwd: null });
    // Not asked whether to replace the file that is there: both fail alike.
    await run(page, `unzip /mnt/cloud${base}/probe.zip -d /mnt/cloud${base}/shared`);
    await expect(screen(page)).not.toContainText('replace ');
    for (const name of ['exists.txt', 'missing.txt']) await expect(screen(page)).toContainText(`${base}/shared/private/${name}: Permission denied`);
    expect(await (await request.get(file(base + '/shared/private/exists.txt'), { headers })).text()).toBe('kept');
  } finally {
    await guestCtx.dispose();
  }
});

test('tar keeps symbolic and hard links, zip follows them unless -y, and extraction makes them, links last', async ({ page, request }) => {
  await terminal(page);
  await run(page, 'ln -s a.md docs/to-a'); await run(page, 'ln docs/a.md docs/a-too.md'); await run(page, 'ln -s ../outside docs/away');
  await run(page, 'tar -cf links.tar docs');
  await run(page, 'tar -tvf links.tar');
  // A job's lines come one by one.
  await expect(screen(page)).toContainText('docs/to-a -> a.md');
  await expect(screen(page)).toContainText('docs/away -> ../outside');
  await expect(screen(page)).toContainText(/docs\/a(-too)?\.md link to docs\/a(-too)?\.md/);
  await run(page, 'mkdir out'); await run(page, 'tar -xf links.tar -C out');
  expect(await runOutput(page, 'readlink out/docs/to-a')).toBe('a.md');
  expect(await (await request.get(file(base + '/out/docs/to-a'))).text()).toBe('alpha\n'.repeat(2000));
  // The two names are one file again, as ls -l counts them.
  expect(await runOutput(page, 'ls -l out/docs | grep a-too')).toContain(' 2 root root');
  // Extracted again over itself, a link replaces what is there, and leaves nothing beside it: a
  // hard link made again names the same file it names already.
  await run(page, 'tar -xf links.tar -C out');
  expect((await ls(request, base + '/out/docs')).map(entry => entry.name).filter(name => name.startsWith('.'))).toEqual([]);
  expect(await runOutput(page, 'ls -l out/docs | grep a-too')).toContain(' 2 root root');
  // zip stores what a link leads to; -y the link.
  await run(page, 'zip -r followed.zip docs'); await run(page, 'zip -ry kept.zip docs');
  await run(page, 'mkdir z1 z2'); await run(page, 'unzip -q followed.zip -d z1'); await run(page, 'unzip -q kept.zip -d z2');
  expect(await runOutput(page, 'ls -l z1/docs | grep to-a')).toContain('-rw');
  const keptLink = await runOutput(page, 'ls -l z2/docs | grep to-a');
  expect(keptLink).toContain('lrwxrwxrwx');
  expect(keptLink).toContain('to-a -> a.md');
});

test('faststart moves a video\'s index before its media, in place, once', async ({ page, request }) => {
  const video = await readFile('tests/fixtures/tail-moov.mp4');
  expect((await put(request, file(base + '/clip.mp4'), { headers, data: video })).status()).toBe(201);
  expect((await program(request, ['chmod', '640', base + '/clip.mp4'])).ok()).toBe(true);
  const boxes = bytes => { const kinds = []; for (let i = 0; i < bytes.length; i += bytes.readUInt32BE(i)) kinds.push(bytes.toString('latin1', i + 4, i + 8)); return kinds; };
  expect(boxes(video).indexOf('moov')).toBeGreaterThan(boxes(video).indexOf('mdat'));
  await terminal(page);
  await run(page, 'faststart clip.mp4');
  await expect(screen(page)).toContainText(`faststart: ${base}/clip.mp4: its index`);
  const fixed = Buffer.from(await (await request.get(file(base + '/clip.mp4'), { headers })).body());
  expect(fixed.length).toBe(video.length);
  expect(boxes(fixed).indexOf('moov')).toBeLessThan(boxes(fixed).indexOf('mdat'));
  // The same file, in place: its mode is kept.
  const [entry] = (await ls(request, base)).filter(e => e.name === 'clip.mp4');
  expect(entry.mode).toBe(0o640);
  // Once is enough; what is not a video is refused.
  await run(page, 'faststart clip.mp4'); await expect(screen(page)).toContainText('is already faststart; left as it was');
  await run(page, 'faststart docs/a.md'); await expect(screen(page)).toContainText('not a readable MP4 or QuickTime file');
});

test('dash executes archive clients and a killed child releases its device while its parent stays alive', async ({ page, request }) => {
  test.skip(!process.env.WASIX_DASH, 'set WASIX_DASH to the approved WASIX dash');
  const pageKernel = await hookPageKernel(page);
  await put(request, file(base + '/dash.wasm'), { headers, data: await readFile(process.env.WASIX_DASH) });
  await program(request, ['chmod', '755', base + '/dash.wasm']);
  const before = new Set((await processes(request)).map(p => p.pid));
  await terminal(page);
  await pageKernel.ready();
  const beforeDash = await promptSeq(page);
  await run(page, `./dash.wasm -c 'cd /mnt/cloud${base}; zip -rq shell.zip docs; tar -cf shell.tar docs; tar -tf shell.tar | wc -l; unzip shell.zip; /usr/bin/printf "parent-alive\\n"; /usr/bin/sleep 20'`, { wait: false });
  await expect(screen(page)).toContainText('replace ', { timeout: 120_000 });
  let child;
  await expect.poll(async () => {
    const entries = await pageCall(page, { getdents: { path: '/proc' } });
    for (const pid of entries.map(e => e.name).filter(name => /^\d+$/.test(name))) {
      const data = await pageCall(page, { pread: { path: `/proc/${pid}/cmdline`, count: 4096 } }).catch(() => null);
      if (!data) continue;
      const cmdline = Buffer.from(data.data, 'base64').toString().split('\0').filter(Boolean);
      if (cmdline[0]?.endsWith('unzip')) {
        child = { pid: Number(pid), cmdline };
        return true;
      }
    }
    return false;
  }, { timeout: 15_000 }).toBe(true);
  await pageKernel.value('kill', { pid: child.pid, signal: 9 });
  await expect(screen(page)).toContainText(/(^|\n)parent-alive(\n|$)/, { timeout: 120_000 });
  await expect(terminalViewport(page)).not.toHaveAttribute('data-state', 'idle');
  await expect.poll(async () => (await processes(request)).find(p => !before.has(p.pid) && p.name === 'unzip')?.state,
    { timeout: 10_000 }).toBe('cancelled');
  await terminalInput(page).press('Control+c');
  await waitIdleAfter(page, beforeDash, 30_000);
  expect((await ls(request, base)).map(e => e.name)).toEqual(expect.arrayContaining(['shell.zip', 'shell.tar']));
});

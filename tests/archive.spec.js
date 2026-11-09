import { test, expect, request as playwrightRequest } from './test.js';
import { device, directory, ACCEL } from './accelerator.js';
import { readFile } from 'node:fs/promises';
import { zipOf, tarOf } from './archive-fixtures.js';
import { api, call, errno, listing, mkdirp, processes, program, put, rmrf } from './sys.js';
const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const file = path => '/api/file?path=' + encodeURIComponent(path);
const ls = (request, path) => listing(request, path).catch(() => []);
// Archive jobs start a container; give them time.
test.setTimeout(240_000);
let base, headers;

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

// A ZIP of stored files, as a system without Unix modes makes one, and a tar of
// [name, text, mode, directory], as their formats lay them out.
const form = page => page.locator('#command').locator('xpath=ancestor::form');
async function run(page, text, { wait = true } = {}) {
  await expect(form(page)).toHaveAttribute('data-state', 'idle', { timeout: 180_000 });
  await page.locator('#command').fill(text); await page.locator('#command').press('Enter');
  if (wait) await expect(form(page)).toHaveAttribute('data-state', 'idle', { timeout: 180_000 });
}
const transcript = page => page.locator('.terminal-panel:not([hidden]) .transcript');
async function terminal(page) {
  await page.goto('/');
  await run(page, 'su root', { wait: false });
  await page.getByLabel('Password', { exact: true }).fill(password); await page.locator('#auth button[type=submit]').click();
  await expect(page.locator('#auth')).not.toBeVisible();
  await run(page, 'cd ' + base);
}

test('zip, unzip and tar round-trip files, names and modes through the container', async ({ page, request }) => {
  await terminal(page);
  await run(page, 'zip -r notes.zip docs');
  await expect(transcript(page)).toContainText('adding: docs/deep/spéctrum notes.txt');
  await run(page, 'unzip -l notes.zip | grep -c docs/');
  await expect(transcript(page).locator('pre').last()).toHaveText('5');
  await run(page, 'unzip -d restored notes.zip');
  await expect(transcript(page)).toContainText('inflating: ' + base + '/restored/docs/a.md');
  for (const name of ['docs/a.md', 'docs/deep/spéctrum notes.txt', 'docs/run.sh']) {
    const [original, copy] = await Promise.all([request.get(file(base + '/' + name)), request.get(file(base + '/restored/' + name))]);
    expect(await copy.text()).toBe(await original.text());
  }
  const restored = Object.fromEntries((await ls(request, base + '/restored/docs')).map(e => [e.name, e.mode]));
  expect(restored['run.sh']).toBe(0o755); expect(restored['a.md']).toBe(0o644);
  await run(page, 'tar -czf notes.tgz docs');
  await run(page, 'tar -tf notes.tgz | sort');
  await expect(transcript(page).locator('pre').last()).toHaveText('docs/\ndocs/a.md\ndocs/deep/\ndocs/deep/spéctrum notes.txt\ndocs/run.sh');
  await run(page, 'mkdir untarred'); await run(page, 'tar -xvf notes.tgz -C untarred');
  expect(await (await request.get(file(base + '/untarred/docs/deep/spéctrum notes.txt'))).text()).toBe('γάμμα\n');
  // zip does not update an archive; tar -c replaces one.
  await run(page, 'zip -r notes.zip docs'); await expect(transcript(page).locator('pre').last()).toContainText('does not update archives');
  await run(page, 'tar -cf notes.tgz docs/a.md'); await run(page, 'tar -tf notes.tgz');
  await expect(transcript(page).locator('pre').last()).toHaveText('docs/a.md');
  await run(page, 'jobs'); await expect(transcript(page).locator('pre').last()).toContainText('done');
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
  await run(page, 'ps');
  await expect(transcript(page).locator('pre').last()).toContainText(`${pid.slice(0, 8)}  done        zip`);
  await run(page, 'kill ffffffff');
  await expect(transcript(page).locator('pre').last()).toContainText('kill: (ffffffff) - No such process');
});

test('a job keeps the credentials it was spawned with, and its own descriptors', async ({ request }) => {
  // Phase 4 (issue #20): a job is a process. Its spawn snapshots who started it, and its runner
  // makes its file calls with them: locking the account afterwards does not fail it, as a
  // running process keeps its credentials on Linux. What it has open shows in /proc/PID/fd.
  const name = 'jobber' + Date.now().toString(36).slice(-6), secret = 'a passphrase of jobs ' + name;
  await call(request, { useradd: { name, create_home: true } }, { sudo: true });
  expect((await api(request, 'passwd', { data: { username: name, password: secret, force: true, sudo: true } })).ok()).toBe(true);
  const user = await playwrightRequest.newContext({ baseURL: origin, extraHTTPHeaders: { Origin: origin, 'CF-Connecting-IP': 'archive-user-' + base } });
  try {
    expect((await api(user, 'login', { data: { username: name, password: secret } })).ok()).toBe(true);
    const { uid, home } = await call(user, 'getcreds');
    expect((await put(user, file(`${home}/greeting.zip`), { headers: { Origin: origin }, data: zipOf([['private/hello.txt', 'hello\n']]) })).status()).toBe(201);
    const resource = await directory(user, home), driver = await device(user, '/dev/archive', { umask: 0o077 });
    const task = await driver.submit({ operation: 'extract', format: 'zip', source: resource('greeting.zip'),
      destination: resource('.'), existing: 'ask', members: [], verbose: true });
    const pid = task.id;
    await task.detach();
    // The archive it reads is a descriptor of its own.
    const fds = await call(user, { getdents: { path: `/proc/${pid}/fd` } });
    expect(fds).toHaveLength(1);
    expect(await call(user, { readlink: { path: `/proc/${pid}/fd/${fds[0].name}` } })).toBe(`${home}/greeting.zip`);
    // Locked while its container starts: the job goes on as it was spawned.
    await call(request, { usermod: { name, lock: true } }, { sudo: true });
    const observer = await (await device(request)).attach(pid);
    let state;
    await expect.poll(async () => (state = await observer.poll()).state, { timeout: 120_000 }).toMatch(/^(done|failed|cancelled)$/);
    expect(state.state, JSON.stringify(state.lines)).toBe('done');
    const made = await call(request, { stat: { path: `${home}/private/hello.txt` } });
    expect(made.uid).toBe(uid);
    expect(await (await request.get(file(`${home}/private/hello.txt`))).text()).toBe('hello\n');
    // The runner omits umask from its requests: implicit parents retain the spawn mask.
    expect((await call(request, { stat: { path: `${home}/private` } })).mode & 0o777).toBe(0o700);
    // Ended, its credentials are revoked, and what it had open is closed.
    await call(request, { usermod: { name, unlock: true } }, { sudo: true });
    expect((await api(user, 'login', { data: { username: name, password: secret } })).ok()).toBe(true);
    expect(await call(user, { getdents: { path: `/proc/${pid}/fd` } })).toEqual([]);
  } finally {
    await user.dispose();
    await call(request, { userdel: { name, remove: true } }, { sudo: true }).catch(() => {});
  }
});

test('unzip asks before replacing, -o and -n decide, tar -k keeps, and hostile members are skipped', async ({ page, request }) => {
  await terminal(page);
  await run(page, 'zip -rq notes.zip docs');
  await run(page, 'unzip -q notes.zip -d copy');
  for (const name of ['a.md', 'run.sh']) await put(request, file(`${base}/copy/docs/${name}`) + '&overwrite=true', { headers, data: 'changed\n' });
  // Asked: no for the first, then None for the rest.
  await run(page, 'unzip notes.zip -d copy', { wait: false });
  await expect(form(page)).toHaveAttribute('data-state', 'input', { timeout: 120_000 });
  await expect(transcript(page)).toContainText('replace ' + base + '/copy/docs/a.md? [y]es, [n]o, [A]ll, [N]one');
  await page.locator('#command').fill('y'); await page.locator('#command').press('Enter');
  await expect(form(page)).toHaveAttribute('data-state', 'input');
  await page.locator('#command').fill('N'); await page.locator('#command').press('Enter');
  await expect(form(page)).toHaveAttribute('data-state', 'idle', { timeout: 120_000 });
  expect(await (await request.get(file(base + '/copy/docs/a.md'))).text()).toBe('alpha\n'.repeat(2000));
  expect(await (await request.get(file(base + '/copy/docs/run.sh'))).text()).toBe('changed\n');
  await run(page, 'unzip -qn notes.zip -d copy');
  expect(await (await request.get(file(base + '/copy/docs/run.sh'))).text()).toBe('changed\n');
  await run(page, 'unzip -qo notes.zip -d copy');
  expect(await (await request.get(file(base + '/copy/docs/run.sh'))).text()).toBe('#!/bin/sh\necho hi\n');
  await run(page, 'tar -cf notes.tar docs');
  await put(request, file(base + '/copy/docs/a.md') + '&overwrite=true', { headers, data: 'kept\n' });
  await run(page, 'tar -xkf notes.tar -C copy');
  await expect(transcript(page)).toContainText('copy/docs/a.md: Cannot open: File exists');
  expect(await (await request.get(file(base + '/copy/docs/a.md'))).text()).toBe('kept\n');
  await run(page, 'tar -xf notes.tar -C copy');
  expect(await (await request.get(file(base + '/copy/docs/a.md'))).text()).toBe('alpha\n'.repeat(2000));
  // A hostile archive: .. is skipped, a leading / removed, the rest extracted, its link as one.
  expect((await put(request, file(base + '/slip.zip'), { headers, data: await readFile('tests/fixtures/slip.zip') })).status()).toBe(201);
  await run(page, 'unzip slip.zip -d out');
  await expect(transcript(page)).toContainText("skipping ../evil.txt: its name contains '..'");
  await expect(transcript(page)).toContainText(`linking: ${base}/out/safe/link  -> ok.txt`);
  expect(await (await request.get(file(base + '/out/safe/link'))).text()).toBe('kept\n');
  expect(await (await request.get(file(base + '/out/safe/ok.txt'))).text()).toBe('kept\n');
  expect(await (await request.get(file(base + '/out/abs/root.txt'))).text()).toBe('rooted\n');
  expect((await request.head(file(base + '/evil.txt'))).status()).toBe(404);
  expect((await request.head(file('/evil.txt'))).status()).toBe(404);
  // Guests cannot extract into a directory they may not write.
  await run(page, 'exit');
  await run(page, `unzip ${base}/notes.zip -d ${base}/ro`);
  await expect(transcript(page).locator('pre').last()).toContainText('Permission denied');
});

test('Ctrl+C cancels owned work; explicit detach survives closing its control handle', async ({ page, request }) => {
  await mkdirp(request, base + '/docs/many');
  for (let i = 0; i < 40; i++) expect((await put(request, file(`${base}/docs/many/f${String(i).padStart(2, '0')}.txt`), { headers, data: 'x'.repeat(1000 + i) })).status()).toBe(201);
  await terminal(page);
  await run(page, 'zip -rq many.zip docs/many');
  await run(page, 'unzip many.zip -d stopped', { wait: false });
  await expect(transcript(page)).toContainText('inflating:', { timeout: 120_000 });
  await page.locator('#command').press('Control+c');
  await expect(form(page)).toHaveAttribute('data-state', 'idle', { timeout: 120_000 });
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
  await run(page, 'jobs');
  await expect(transcript(page).locator('pre').last()).toContainText('cancelled');
});

test('extracting nothing ends at once and says why; modes are those archived, 000 too; long listings come whole', async ({ page, request }) => {
  const make = async (name, data) => expect((await put(request, file(base + '/' + name), { headers, data })).status()).toBe(201);
  await make('empty.zip', zipOf([])); await make('empty.tar', tarOf([])); await make('one.zip', zipOf([['a.txt', 'a']]));
  await make('modes.tar', tarOf([['normal.txt', 'new', 0o644], ['private.txt', 'new', 0], ['private-dir', '', 0, true], ['open', '', 0o755, true], ['closed', '', 0o755, true]]));
  await make('many.zip', zipOf(Array.from({ length: 700 }, (_, i) => [String(i).padStart(4, '0') + '.txt', 'x'])));
  await terminal(page);
  // Each ends once, rather than plan again and again.
  const ends = async text => { await run(page, text, { wait: false }); await expect(form(page)).toHaveAttribute('data-state', 'idle', { timeout: 120_000 }); };
  await ends('unzip -d out empty.zip');
  await expect(transcript(page)).toContainText('warning [' + base + '/empty.zip]:  zipfile is empty');
  await run(page, 'mkdir none'); await ends('tar -xf empty.tar -C none');
  await ends('unzip one.zip missing.txt -d out');
  await expect(transcript(page)).toContainText('caution: filename not matched:  missing.txt');
  await ends('tar -xf modes.tar -C none private.txt nothing.txt');
  await expect(transcript(page)).toContainText('tar: nothing.txt: Not found in archive');
  expect(await transcript(page).evaluate(e => e.textContent.split('zipfile is empty').length - 1)).toBe(1);
  // The modes archived, less group and other write, also for files and directories that were
  // there; 644 for a file a zip says none of.
  await run(page, 'mkdir dest dest/open dest/closed');
  for (const [dir, mode] of [['open', '777'], ['closed', '700']]) expect((await program(request, ['chmod', mode, base + '/dest/' + dir])).ok()).toBe(true);
  expect((await put(request, file(base + '/dest/normal.txt'), { headers, data: 'old' })).status()).toBe(201);
  expect((await program(request, ['chmod', '755', base + '/dest/normal.txt'])).ok()).toBe(true);
  await ends('tar -xf modes.tar -C dest'); await ends('unzip -q one.zip -d dest');
  const modes = Object.fromEntries((await ls(request, base + '/dest')).map(e => [e.name, e.mode]));
  expect(modes).toEqual({ 'normal.txt': 0o644, 'private.txt': 0, 'private-dir': 0, 'open': 0o755, 'closed': 0o755, 'a.txt': 0o644 });
  const guest = await playwrightRequest.newContext({ baseURL: origin, extraHTTPHeaders: { 'CF-Connecting-IP': 'archive-guest-' + base } });
  expect((await guest.get(file(base + '/dest/private.txt'))).status()).toBe(401);
  expect((await put(guest, file(base + '/dest/open/guest.txt'), { headers: { Origin: origin }, data: 'x' })).status()).toBe(401);
  await guest.dispose();
  // A job's output comes page after page, to its end.
  await ends('unzip -l many.zip | wc -l');
  await expect(transcript(page).locator('pre').last()).toHaveText('705');
});

test('extraction tells a guest nothing of what lies where it may not look', async ({ page, request }) => {
  await mkdirp(request, base + '/shared/private');
  expect((await program(request, ['chmod', '777', base + '/shared'])).ok()).toBe(true);
  expect((await program(request, ['chmod', '700', base + '/shared/private'])).ok()).toBe(true);
  expect((await put(request, file(base + '/shared/private/exists.txt'), { headers, data: 'kept' })).status()).toBe(201);
  expect((await put(request, file(base + '/probe.zip'), { headers, data: zipOf([['private/exists.txt', 'x'], ['private/missing.txt', 'y']]) })).status()).toBe(201);
  await page.goto('/');
  // Not asked whether to replace the file that is there: both fail alike.
  await run(page, `unzip ${base}/probe.zip -d ${base}/shared`, { wait: false });
  await expect(form(page)).toHaveAttribute('data-state', 'idle', { timeout: 120_000 });
  await expect(transcript(page)).not.toContainText('replace ');
  for (const name of ['exists.txt', 'missing.txt']) await expect(transcript(page)).toContainText(`${base}/shared/private/${name}: Permission denied`);
  expect(await (await request.get(file(base + '/shared/private/exists.txt'), { headers })).text()).toBe('kept');
});

test('tar keeps symbolic and hard links, zip follows them unless -y, and extraction makes them, links last', async ({ page, request }) => {
  await terminal(page);
  await run(page, 'ln -s a.md docs/to-a'); await run(page, 'ln docs/a.md docs/a-too.md'); await run(page, 'ln -s ../outside docs/away');
  await run(page, 'tar -cf links.tar docs');
  await run(page, 'tar -tvf links.tar');
  // A job's lines come one by one.
  const listed = transcript(page);
  await expect(listed).toContainText('docs/to-a -> a.md'); await expect(listed).toContainText('docs/away -> ../outside');
  await expect(listed).toContainText(/docs\/a(-too)?\.md link to docs\/a(-too)?\.md/);
  await run(page, 'mkdir out'); await run(page, 'tar -xf links.tar -C out');
  await run(page, 'readlink out/docs/to-a'); await expect(transcript(page).locator('pre').last()).toHaveText('a.md');
  expect(await (await request.get(file(base + '/out/docs/to-a'))).text()).toBe('alpha\n'.repeat(2000));
  // The two names are one file again, as ls -l counts them.
  await run(page, 'ls -l out/docs | grep a-too'); await expect(transcript(page).locator('pre').last()).toContainText(' 2 root root');
  // Extracted again over itself, a link replaces what is there, and leaves nothing beside it: a
  // hard link made again names the same file it names already.
  await run(page, 'tar -xf links.tar -C out');
  expect((await ls(request, base + '/out/docs')).map(entry => entry.name).filter(name => name.startsWith('.'))).toEqual([]);
  await run(page, 'ls -l out/docs | grep a-too'); await expect(transcript(page).locator('pre').last()).toContainText(' 2 root root');
  // zip stores what a link leads to; -y the link.
  await run(page, 'zip -r followed.zip docs'); await run(page, 'zip -ry kept.zip docs');
  await run(page, 'mkdir z1 z2'); await run(page, 'unzip -q followed.zip -d z1'); await run(page, 'unzip -q kept.zip -d z2');
  await run(page, 'ls -l z1/docs | grep to-a'); await expect(transcript(page).locator('pre').last()).toContainText('-rw');
  await run(page, 'ls -l z2/docs | grep to-a'); await expect(transcript(page).locator('pre').last()).toContainText('lrwxrwxrwx');
  await expect(transcript(page).locator('pre').last()).toContainText('to-a -> a.md');
});

test('faststart moves a video\'s index before its media, in place, once', async ({ page, request }) => {
  const video = await readFile('tests/fixtures/tail-moov.mp4');
  expect((await put(request, file(base + '/clip.mp4'), { headers, data: video })).status()).toBe(201);
  expect((await program(request, ['chmod', '640', base + '/clip.mp4'])).ok()).toBe(true);
  const boxes = bytes => { const kinds = []; for (let i = 0; i < bytes.length; i += bytes.readUInt32BE(i)) kinds.push(bytes.toString('latin1', i + 4, i + 8)); return kinds; };
  expect(boxes(video).indexOf('moov')).toBeGreaterThan(boxes(video).indexOf('mdat'));
  await terminal(page);
  await run(page, 'faststart clip.mp4');
  await expect(transcript(page)).toContainText(`faststart: ${base}/clip.mp4: its index`);
  const fixed = Buffer.from(await (await request.get(file(base + '/clip.mp4'), { headers })).body());
  expect(fixed.length).toBe(video.length);
  expect(boxes(fixed).indexOf('moov')).toBeLessThan(boxes(fixed).indexOf('mdat'));
  // The same file, in place: its mode is kept.
  const [entry] = (await ls(request, base)).filter(e => e.name === 'clip.mp4');
  expect(entry.mode).toBe(0o640);
  // Once is enough; what is not a video is refused.
  await run(page, 'faststart clip.mp4'); await expect(transcript(page)).toContainText('is already faststart; left as it was');
  await run(page, 'faststart docs/a.md'); await expect(transcript(page)).toContainText('not a readable MP4 or QuickTime file');
});

test('dash executes archive clients and a killed child releases its device while its parent stays alive', async ({ page, request }) => {
  test.skip(!process.env.WASIX_DASH, 'set WASIX_DASH to the approved WASIX dash');
  await put(request, file(base + '/dash.wasm'), { headers, data: await readFile(process.env.WASIX_DASH) });
  await program(request, ['chmod', '755', base + '/dash.wasm']);
  const before = new Set((await processes(request)).map(p => p.pid));
  await terminal(page);
  await run(page, `./dash.wasm -c 'cd ${base}; zip -rq shell.zip docs; tar -cf shell.tar docs; tar -tf shell.tar | wc -l; unzip shell.zip; /usr/bin/printf "parent-alive\\n"; /usr/bin/sleep 20'`, { wait: false });
  await expect(transcript(page).locator('pre').last()).toContainText('replace ', { timeout: 120_000 });
  const child = (await processes(page.request)).find(p => /^\d+$/.test(p.pid) && p.cmdline[0]?.endsWith('unzip'));
  expect(child).toBeDefined();
  await call(page.request, { kill: { pid: child.pid, signal: 9 } });
  await expect(transcript(page).locator('pre').last()).toContainText(/(^|\n)parent-alive(\n|$)/, { timeout: 120_000 });
  await expect(form(page)).not.toHaveAttribute('data-state', 'idle');
  await expect.poll(async () => (await processes(request)).find(p => !before.has(p.pid) && p.name === 'unzip')?.state,
    { timeout: 10_000 }).toBe('cancelled');
  await page.locator('#command').press('Control+c');
  await expect(form(page)).toHaveAttribute('data-state', 'idle');
  expect((await ls(request, base)).map(e => e.name)).toEqual(expect.arrayContaining(['shell.zip', 'shell.tar']));
});

import { test, expect, request as playwrightRequest } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { crc32 } from 'node:zlib';
import { api, call, errno, listing, mkdirp, processes, program, put, rmrf } from './sys.js';
const origin = process.env.TERMINAL_TEST_URL || 'http://127.0.0.1:8787';
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
function zipOf(files) {
  const parts = [], central = []; let offset = 0;
  for (const [name, text] of files) {
    const data = Buffer.from(text), path = Buffer.from(name), crc = crc32(data);
    const local = Buffer.alloc(30); local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt32LE(crc, 14); local.writeUInt32LE(data.length, 18); local.writeUInt32LE(data.length, 22); local.writeUInt16LE(path.length, 26);
    const entry = Buffer.alloc(46); entry.writeUInt32LE(0x02014b50, 0); entry.writeUInt16LE(20, 4); entry.writeUInt16LE(20, 6); entry.writeUInt32LE(crc, 16); entry.writeUInt32LE(data.length, 20); entry.writeUInt32LE(data.length, 24); entry.writeUInt16LE(path.length, 28); entry.writeUInt32LE(offset, 42);
    parts.push(local, path, data); central.push(entry, path); offset += 30 + path.length + data.length;
  }
  const directory = Buffer.concat(central), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10); end.writeUInt32LE(directory.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...parts, directory, end]);
}
function tarOf(members) {
  const blocks = [];
  for (const [name, text, mode, directory] of members) {
    const data = Buffer.from(text), header = Buffer.alloc(512);
    header.write(name, 0); header.write(mode.toString(8).padStart(7, '0') + '\0', 100); header.write('0000000\0', 108); header.write('0000000\0', 116);
    header.write(data.length.toString(8).padStart(11, '0') + '\0', 124); header.write('00000000000\0', 136); header.write('        ', 148);
    header.write(directory ? '5' : '0', 156); header.write('ustar\0', 257); header.write('00', 263);
    let sum = 0; for (const byte of header) sum += byte; header.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
    blocks.push(header, data, Buffer.alloc((512 - data.length % 512) % 512));
  }
  return Buffer.concat([...blocks, Buffer.alloc(1024)]);
}

const form = page => page.locator('#command').locator('xpath=ancestor::form');
async function run(page, text, { wait = true } = {}) {
  await expect(form(page).locator('.busy')).toHaveText('↵', { timeout: 180_000 });
  await page.locator('#command').fill(text); await page.locator('#command').press('Enter');
  if (wait) await expect(form(page).locator('.busy')).toHaveText('↵', { timeout: 180_000 });
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
});

test('a job is a process: spawned, waited for, listed by ps, asked on its stdin, and signalled by kill', async ({ page, request }) => {
  const O = { cwd: base };
  // spawn runs it apart, as the caller; wait reads what it wrote, and how it ended.
  const { pid } = await call(request, { spawn: { argv: ['zip', '-r', 'docs.zip', 'docs'], ...O } });
  const finished = async () => {
    let state;
    await expect.poll(async () => (state = await call(request, { wait: { pid } })).state, { timeout: 120_000 }).toMatch(/^(done|failed|cancelled)$/);
    return state;
  };
  expect((await finished()).state).toBe('done');
  expect((await ls(request, base)).map(entry => entry.name)).toContain('docs.zip');
  expect((await processes(request)).map(process => process.pid)).toContain(pid);
  // A question goes to its stdin: unzip asks before replacing what is there.
  const { pid: asking, stdin } = await call(request, { spawn: { argv: ['unzip', 'docs.zip'], ...O } });
  await expect.poll(async () => (await call(request, { wait: { pid: asking } })).state, { timeout: 120_000 }).toBe('question');
  const { question } = await call(request, { wait: { pid: asking } });
  const decisions = Object.fromEntries(question.replace.map(path => [path, false]));
  // Its standard input is a descriptor of the session, written as a pipe is.
  expect(await call(request, { readlink: { path: `/proc/self/fd/${stdin}` } })).toBe(`/proc/${asking}/fd/0`);
  const answer = Buffer.from(JSON.stringify({ decisions })).toString('base64');
  expect((await call(request, { pwrite: { fd: stdin, index: 0, data: answer } })).state).toBe('queued');
  expect((await call(request, { close: { fd: stdin } })).path).toBe(`/proc/${asking}/fd/0`);
  await expect.poll(async () => (await call(request, { wait: { pid: asking } })).state, { timeout: 120_000 }).toBe('done');
  // Only programs are spawned; signals go to what is there, and its owner's (or root's).
  expect(await errno(request, { spawn: { argv: ['sh', '-c', 'true'], ...O } })).toBe('ENOENT');
  expect(await errno(request, { kill: { pid: 'f'.repeat(32) } })).toBe('ESRCH');
  const stranger = await playwrightRequest.newContext({ baseURL: origin, extraHTTPHeaders: { Origin: origin, 'CF-Connecting-IP': 'archive-stranger-' + base } });
  try { expect(await errno(stranger, { kill: { pid } })).toBe('EPERM'); }
  finally { await stranger.dispose(); }
  // ps and kill, in the terminal, as procps' are.
  await terminal(page);
  await run(page, 'ps');
  await expect(transcript(page).locator('pre').last()).toContainText(`${pid.slice(0, 8)}  done        zip`);
  await run(page, 'kill ffffffff');
  await expect(transcript(page).locator('pre').last()).toContainText('kill: (ffffffff) - No such process');
});

test('unzip asks before replacing, -o and -n decide, tar -k keeps, and hostile members are skipped', async ({ page, request }) => {
  await terminal(page);
  await run(page, 'zip -rq notes.zip docs');
  await run(page, 'unzip -q notes.zip -d copy');
  for (const name of ['a.md', 'run.sh']) await put(request, file(`${base}/copy/docs/${name}`) + '&overwrite=true', { headers, data: 'changed\n' });
  // Asked: no for the first, then None for the rest.
  await run(page, 'unzip notes.zip -d copy', { wait: false });
  await expect(form(page).locator('.busy')).toHaveText('Answer ↵', { timeout: 120_000 });
  await expect(transcript(page)).toContainText('replace ' + base + '/copy/docs/a.md? [y]es, [n]o, [A]ll, [N]one');
  await page.locator('#command').fill('y'); await page.locator('#command').press('Enter');
  await expect(form(page).locator('.busy')).toHaveText('Answer ↵');
  await page.locator('#command').fill('N'); await page.locator('#command').press('Enter');
  await expect(form(page).locator('.busy')).toHaveText('↵', { timeout: 120_000 });
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

test('Ctrl+C stops an extraction between files, and a closed tab leaves its job running', async ({ page, request }) => {
  await mkdirp(request, base + '/docs/many');
  for (let i = 0; i < 40; i++) expect((await put(request, file(`${base}/docs/many/f${String(i).padStart(2, '0')}.txt`), { headers, data: 'x'.repeat(1000 + i) })).status()).toBe(201);
  await terminal(page);
  await run(page, 'zip -rq many.zip docs/many');
  await run(page, 'unzip many.zip -d stopped', { wait: false });
  await expect(transcript(page)).toContainText('inflating:', { timeout: 120_000 });
  await page.locator('#command').press('Control+c');
  await expect(form(page).locator('.busy')).toHaveText('↵', { timeout: 120_000 });
  const stopped = await ls(request, base + '/stopped/docs/many');
  expect(stopped.length).toBeGreaterThan(0); expect(stopped.length).toBeLessThan(40);
  // What was extracted is whole; nothing is left half-written.
  expect(stopped.every(e => e.uploaded === undefined)).toBe(true);
  // A job started in a tab that closes runs to its end.
  await page.keyboard.press('Alt+t'); await expect(page.getByRole('tab')).toHaveCount(2);
  await run(page, 'unzip -q many.zip -d detached', { wait: false });
  await expect(form(page).locator('.busy')).toHaveText('Working...');
  await page.getByRole('button', { name: 'Close tab 2' }).click();
  await expect(page.getByRole('tab')).toHaveCount(1);
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
  const ends = async text => { await run(page, text, { wait: false }); await expect(form(page).locator('.busy')).toHaveText('↵', { timeout: 120_000 }); };
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
  await expect(form(page).locator('.busy')).toHaveText('↵', { timeout: 120_000 });
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

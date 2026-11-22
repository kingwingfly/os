import { test, expect } from './test.js';
import { readFile } from 'node:fs/promises';
import { put, rmrf } from './sys.js';
import { cloudSignIn, cloudSignOut, pageGetBytes, pageRmrf } from './ui.js';

const rootPassword = process.env.OS_TEST_ADMIN_PASSWORD
  || process.env.OS_PASSWORD
  || (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];

// Processes of /usr/bin (web/wasi/exec.mjs): a pipeline's run at once, through pipes in memory the
// page shares with them, which it may only when isolated from other sites (web/_headers); the
// first reads the terminal, as typed; head closes its input once it has its lines, and what
// writes to it hears SIGPIPE. Where the page is not isolated, they run one after another.
const input = page => page.getByRole('combobox', { name: 'Terminal command' });
const busy = page => page.locator('#command').locator('xpath=ancestor::form');
const last = page => page.locator('.transcript pre').last();
async function run(page, text, { wait = true } = {}) {
  await expect(busy(page)).toHaveAttribute('data-state', 'idle');
  await input(page).fill(text); await input(page).press('Enter');
  if (wait) await expect(busy(page)).toHaveAttribute('data-state', 'idle', { timeout: 30_000 });
}
async function ready(page) {
  await page.goto('/');
  await expect(busy(page)).toHaveAttribute('data-state', 'idle');
}

test('a pipeline of processes runs at once through pipes, and head stops what it reads', async ({ page }) => {
  await ready(page);
  expect(await page.evaluate(() => crossOriginIsolated)).toBe(true);
  // yes would write forever: head takes three lines, and closes the pipe.
  const started = Date.now();
  await run(page, 'yes | head -n 3');
  await expect(last(page)).toHaveText('y\ny\ny');
  expect(Date.now() - started).toBeLessThan(10_000);
  // Through two pipes; and SIGPIPE ends yes as coreutils' head exits.
  await run(page, 'seq 1 3 | tr 1-3 a-c | fold -w 1');
  await expect(last(page)).toHaveText('a\nb\nc');
  await run(page, 'yes | coreutils head -n 2');
  await expect(last(page)).toHaveText('y\ny');
  await expect(page.locator('.transcript')).not.toContainText('Broken pipe');
  // Errors show as they are written, a line each.
  await run(page, 'coreutils cat /nothing-here');
  await expect(last(page)).toHaveText("cat: /nothing-here: No such file or directory");
});

test('the first process reads the terminal: a line as typed, Ctrl+D ends a read, Ctrl+C kills it', async ({ page }) => {
  await ready(page);
  // tr waits on the terminal; what it writes for each line shows while it runs.
  await run(page, 'tr a-z A-Z', { wait: false });
  await expect(busy(page)).toHaveAttribute('data-state', 'input');
  await input(page).fill('hello there'); await input(page).press('Enter');
  await expect(last(page)).toHaveText('hello there\nHELLO THERE');
  await expect(busy(page)).toHaveAttribute('data-state', 'input');
  // Typed lines are the program's, not the shell's history.
  await input(page).press('Control+d');
  await expect(busy(page)).toHaveAttribute('data-state', 'idle');
  await input(page).press('ArrowUp');
  await expect(input(page)).toHaveValue('tr a-z A-Z');
  await input(page).fill('');
  // Ctrl+D after text gives the text, without a newline; on nothing, it ends the read.
  await run(page, 'coreutils wc -c', { wait: false });
  await expect(busy(page)).toHaveAttribute('data-state', 'input');
  await input(page).fill('abc'); await input(page).press('Control+d');
  await expect(busy(page)).toHaveAttribute('data-state', 'input');
  await input(page).press('Control+d');
  await expect(busy(page)).toHaveAttribute('data-state', 'idle');
  await expect(last(page)).toHaveText('abc3');
  // Ctrl+C kills what reads.
  await run(page, 'coreutils cat', { wait: false });
  await expect(busy(page)).toHaveAttribute('data-state', 'input');
  await input(page).press('Control+c');
  await expect(busy(page)).toHaveAttribute('data-state', 'idle', { timeout: 5_000 });
  // What reads its input from a pipe does not read the terminal.
  await run(page, 'seq 2 | tr 12 xy');
  await expect(last(page)).toHaveText('x\ny');
});

test('head takes its lines as they come, a prompt shows as it waits, and NULs are ignored', async ({ page }) => {
  await ready(page);
  // A line at a time: head has two of its three, and the pipeline goes on.
  await run(page, 'tr a-z A-Z | head -n 3', { wait: false });
  for (const line of ['one', 'two']) {
    await expect(busy(page)).toHaveAttribute('data-state', 'input');
    await input(page).fill(line); await input(page).press('Enter');
  }
  await page.waitForTimeout(1_000);
  await expect(busy(page)).toHaveAttribute('data-state', 'input');
  await input(page).fill('three'); await input(page).press('Enter');
  await expect(busy(page)).toHaveAttribute('data-state', 'input');
  await input(page).press('Control+d');
  await expect(busy(page)).toHaveAttribute('data-state', 'idle', { timeout: 10_000 });
  await expect(last(page)).toHaveText('one\ntwo\nthree\nONE\nTWO\nTHREE');
  // head by its path closes its input too.
  await run(page, 'yes | /bin/head -n 2');
  await expect(last(page)).toHaveText('y\ny');
  await expect(page.locator('.transcript')).not.toContainText('cut short');
  // A question on standard error, its line not ended, shows while it waits for the answer.
  const name = '/tmp/asked-' + Date.now().toString(36);
  await run(page, 'coreutils touch ' + name);
  await run(page, 'rm -i ' + name, { wait: false });
  await expect(busy(page)).toHaveAttribute('data-state', 'input');
  await expect(page.locator('.transcript')).toContainText(`rm: remove regular empty file '${name}'?`);
  await input(page).fill('y'); await input(page).press('Enter');
  await expect(busy(page)).toHaveAttribute('data-state', 'idle', { timeout: 10_000 });
  await run(page, 'coreutils ls ' + name);
  await expect(last(page)).toContainText('No such file or directory');
  // A real terminal ignores NUL control bytes.
  await run(page, "coreutils printf 'a\\0b'");
  await expect(last(page)).toHaveText('ab');
});

test('a page not isolated shows an execution notice and refuses command execution', async ({ page }) => {
  await page.route(url => new URL(url).pathname === '/', async route => {
    const response = await route.fetch();
    const headers = { ...response.headers() };
    delete headers['cross-origin-embedder-policy']; delete headers['cross-origin-opener-policy'];
    await route.fulfill({ response, headers });
  });
  await ready(page);
  expect(await page.evaluate(() => crossOriginIsolated)).toBe(false);
  await expect(page.locator('.execution-notice')).toContainText('isolated browser page');
  await run(page, 'seq 1 3 | tr 1-3 a-c');
  await expect(last(page)).toContainText('Command execution needs an isolated browser page');
  await expect(page.evaluate(() => window.os.exec([['/usr/bin/seq', '1', '3']]))).rejects.toThrow(/isolated browser page/);
  await run(page, 'echo still-responsive');
  await expect(last(page)).toContainText('Command execution needs an isolated browser page');
});

test('a process reads one file after another; cp copies what the kernel makes, reading it', async ({ page }) => {
  await ready(page);
  await run(page, 'coreutils md5sum /etc/passwd /etc/group');
  await expect(last(page)).toHaveText(/^[0-9a-f]{32}  \/etc\/passwd\n[0-9a-f]{32}  \/etc\/group$/);
  const copy = '/tmp/passwd-' + Date.now().toString(36);
  try {
    await run(page, `cp /etc/passwd ${copy}`);
    const source = await pageGetBytes(page, '/etc/passwd');
    const target = await pageGetBytes(page, copy);
    expect(source).toBeTruthy(); expect(target).toBeTruthy();
    expect(Buffer.compare(target, source)).toBe(0);
    await run(page, `cat ${copy} | head -n 1`);
    await expect(last(page)).toContainText('root:x:0:0');
  } finally {
    await pageRmrf(page, copy);
  }
});

test('cp copies generated size-zero files beyond the inline syscall limit', async ({ page }) => {
  await ready(page);
  await cloudSignIn(page, 'root', rootPassword);
  const source = '/guest/copy-large-' + crypto.randomUUID(), target = source + '-copy';
  const bytes = Buffer.from('large fallback data\n'.repeat(20000));
  expect(bytes.length).toBeGreaterThan(256 * 1024);
  expect((await put(page.request, '/api/file?path=' + source, { data: bytes })).ok()).toBe(true);
  // Intercept both v1 /api/sys and v2 /api/fs to model generated size-zero metadata and EOPNOTSUPP reflink
  // while all opens, reads, writes and closes still use real authenticated CloudFs storage at `/mnt/cloud`.
  await page.route('**/api/sys', async route => {
    const body = route.request().postDataJSON(), indexes = [], metadata = [];
    body.calls = body.calls.map((call, i) => {
      if ((call.stat?.path ?? call.lstat?.path) === source) metadata.push(i);
      if (call.ioctl?.request !== 0x40049409) return call;
      indexes.push(i); return { stat: { path: source } };
    });
    if (!indexes.length && !metadata.length) return route.continue();
    const response = await route.fetch({ postData: JSON.stringify(body) });
    const reply = await response.json();
    for (const i of metadata) if (reply.results[i].ok) reply.results[i].ok.size = 0;
    for (const i of indexes) reply.results[i] = { err: { errno: 'EOPNOTSUPP' } };
    await route.fulfill({ response, json: reply });
  });
  const sourceName = source.split('/').pop();
  await page.route('**/api/fs', async route => {
    const body = route.request().postDataJSON();
    if (body?.call?.clone) {
      return route.fulfill({ status: 400, json: { errno: 'EOPNOTSUPP', error: 'Operation not supported' } });
    }
    const response = await route.fetch();
    const reply = await response.json().catch(() => null);
    if (reply && typeof reply === 'object') {
      if (body?.call?.lookup?.name === sourceName && reply.metadata) reply.metadata.size = 0;
      if (body?.call?.walk && Array.isArray(reply.entries)) {
        const names = body.call.walk.names ?? [];
        const idx = names.indexOf(sourceName);
        if (idx >= 0 && reply.entries[idx]?.metadata) reply.entries[idx].metadata.size = 0;
      }
      return route.fulfill({ response, json: reply });
    }
    return route.fulfill({ response });
  });
  try {
    await run(page, `cp /mnt/cloud${source} /mnt/cloud${target}`);
    const copied = await page.request.get('/api/file?path=' + target);
    expect(copied.ok()).toBe(true);
    const result = await copied.body(); expect(result.length).toBe(bytes.length); expect(Buffer.compare(result, bytes)).toBe(0);
  } finally {
    await page.unroute('**/api/sys');
    await page.unroute('**/api/fs');
    await rmrf(page.request, target); await rmrf(page.request, source);
    await cloudSignOut(page).catch(() => {});
  }
});

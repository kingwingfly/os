import { test, expect } from './test.js';
import { readFile } from 'node:fs/promises';
import { put, rmrf } from './sys.js';
import {
  cloudSignIn,
  cloudSignOut,
  execCmd,
  execSh,
  pageGetBytes,
  pageRmrf,
  runTerminal,
  sendTerminalLine,
  terminalInput,
  terminalScreen,
  terminalText,
  terminalViewport,
  waitForTerminalReady,
} from './ui.js';

const rootPassword = process.env.OS_TEST_ADMIN_PASSWORD
  || process.env.OS_PASSWORD
  || (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];

// Processes of /usr/bin (web/wasi/exec.mjs): a pipeline's run at once, through pipes in memory the
// page shares with them, which it may only when isolated from other sites (web/_headers); the
// first reads the terminal, as typed; head closes its input once it has its lines, and what
// writes to it hears SIGPIPE. Where the page is not isolated, they run one after another.
async function ready(page) {
  await page.goto('/');
  await waitForTerminalReady(page);
}

test('a pipeline of processes runs at once through pipes, and head stops what it reads', async ({ page }) => {
  await ready(page);
  expect(await page.evaluate(() => crossOriginIsolated)).toBe(true);
  // yes would write forever: head takes three lines, and closes the pipe.
  const started = Date.now();
  const y3 = await execSh(page, 'yes | head -n 3');
  expect(y3.status, y3.stderr).toBe(0);
  expect(y3.stdout.trim()).toBe('y\ny\ny');
  expect(Date.now() - started).toBeLessThan(10_000);
  // Through two pipes; and SIGPIPE ends yes as coreutils' head exits.
  const twoPipes = await execSh(page, 'seq 1 3 | tr 1-3 a-c | fold -w 1');
  expect(twoPipes.status, twoPipes.stderr).toBe(0);
  expect(twoPipes.stdout.trim()).toBe('a\nb\nc');
  const coreHead = await execSh(page, 'yes | coreutils head -n 2');
  expect(coreHead.status, coreHead.stderr).toBe(0);
  expect(coreHead.stdout.trim()).toBe('y\ny');
  expect(coreHead.stderr).not.toContain('Broken pipe');
  // Errors show as they are written, a line each.
  const missing = await execCmd(page, ['/usr/bin/coreutils', 'cat', '/nothing-here']);
  expect(missing.status).not.toBe(0);
  expect(missing.stderr.trim()).toBe('cat: /nothing-here: No such file or directory');
});

test('the first process reads the terminal: a line as typed, Ctrl+D ends a read, Ctrl+C kills it', async ({ page }) => {
  await ready(page);
  const input = terminalInput(page);
  const viewport = terminalViewport(page);
  // tr waits on the terminal; what it writes for each line shows while it runs.
  await runTerminal(page, 'tr a-z A-Z', { wait: false });
  await expect(viewport).toHaveAttribute('data-state', 'busy', { timeout: 15_000 });
  await sendTerminalLine(page, 'hello there');
  await expect.poll(() => terminalText(page), { timeout: 15_000 }).toContain('hello there\nHELLO THERE');
  await expect(viewport).toHaveAttribute('data-state', 'busy');
  // Typed lines are the program's, not the shell's history.
  await input.press('Control+d');
  await expect(viewport).toHaveAttribute('data-state', 'idle', { timeout: 15_000 });
  await input.press('ArrowUp');
  await expect.poll(() => terminalText(page).then(t => t.trimEnd()), { timeout: 10_000 }).toMatch(/tr a-z A-Z$/);
  await input.press('Control+c');
  await expect(terminalScreen(page)).toContainText('^C');
  // Ctrl+D after text gives the text, without a newline; on nothing, it ends the read.
  await runTerminal(page, 'coreutils wc -c', { wait: false });
  await expect(viewport).toHaveAttribute('data-state', 'busy', { timeout: 15_000 });
  await input.fill('abc');
  await expect.poll(() => terminalText(page), { timeout: 10_000 }).toContain('abc');
  await input.press('Control+d');
  await expect(viewport).toHaveAttribute('data-state', 'busy');
  await input.press('Control+d');
  await expect(viewport).toHaveAttribute('data-state', 'idle', { timeout: 15_000 });
  await expect.poll(() => terminalText(page), { timeout: 10_000 }).toContain('abc3');
  // Ctrl+C kills what reads.
  await runTerminal(page, 'coreutils cat', { wait: false });
  await expect(viewport).toHaveAttribute('data-state', 'busy', { timeout: 15_000 });
  await input.press('Control+c');
  await expect(viewport).toHaveAttribute('data-state', 'idle', { timeout: 10_000 });
  // What reads its input from a pipe does not read the terminal.
  await runTerminal(page, 'seq 2 | tr 12 xy');
  await expect.poll(() => terminalText(page), { timeout: 10_000 }).toMatch(/^x\s*\ny\s*$/m);
});

test('head takes its lines as they come, a prompt shows as it waits, and NULs are ignored', async ({ page }) => {
  await ready(page);
  const input = terminalInput(page);
  const viewport = terminalViewport(page);
  // A line at a time: head has two of its three, and the pipeline goes on.
  await runTerminal(page, 'tr a-z A-Z | head -n 3', { wait: false });
  for (const line of ['one', 'two']) {
    await expect(viewport).toHaveAttribute('data-state', 'busy', { timeout: 15_000 });
    await sendTerminalLine(page, line);
  }
  await page.waitForTimeout(1_000);
  await expect(viewport).toHaveAttribute('data-state', 'busy');
  await sendTerminalLine(page, 'three');
  await expect(viewport).toHaveAttribute('data-state', 'busy');
  await input.press('Control+d');
  await expect(viewport).toHaveAttribute('data-state', 'idle', { timeout: 15_000 });
  await expect.poll(() => terminalText(page), { timeout: 10_000 }).toContain('one\ntwo\nthree\nONE\nTWO\nTHREE');
  // head by its path closes its input too.
  const binHead = await execSh(page, 'yes | /bin/head -n 2');
  expect(binHead.status, binHead.stderr).toBe(0);
  expect(binHead.stdout.trim()).toBe('y\ny');
  expect(binHead.stderr).not.toContain('cut short');
  // A question on standard error, its line not ended, shows while it waits for the answer.
  const name = '/tmp/asked-' + Date.now().toString(36);
  expect((await execCmd(page, ['/usr/bin/coreutils', 'touch', name])).status).toBe(0);
  await runTerminal(page, 'rm -i ' + name, { wait: false });
  await expect(viewport).toHaveAttribute('data-state', 'busy', { timeout: 15_000 });
  await expect(terminalScreen(page)).toContainText(`rm: remove regular empty file '${name}'?`, { timeout: 15_000 });
  await sendTerminalLine(page, 'y');
  await expect(viewport).toHaveAttribute('data-state', 'idle', { timeout: 15_000 });
  const gone = await execCmd(page, ['/usr/bin/coreutils', 'ls', name]);
  expect(gone.status).not.toBe(0);
  expect(gone.stderr).toContain('No such file or directory');
  // A real terminal ignores NUL control bytes.
  await runTerminal(page, "coreutils printf 'nul%s\\0%s\\n' A B");
  await expect.poll(() => terminalText(page), { timeout: 10_000 }).toMatch(/^nulAB\s*$/m);
});

test('a process reads one file after another; cp copies what the kernel makes, reading it', async ({ page }) => {
  await ready(page);
  const md5 = await execCmd(page, ['/usr/bin/coreutils', 'md5sum', '/etc/passwd', '/etc/group']);
  expect(md5.status, md5.stderr).toBe(0);
  expect(md5.stdout.trim()).toMatch(/^[0-9a-f]{32}  \/etc\/passwd\n[0-9a-f]{32}  \/etc\/group$/);
  const copy = '/tmp/passwd-' + Date.now().toString(36);
  try {
    const cp = await execCmd(page, ['/usr/bin/cp', '/etc/passwd', copy]);
    expect(cp.status, cp.stderr).toBe(0);
    const source = await pageGetBytes(page, '/etc/passwd');
    const target = await pageGetBytes(page, copy);
    expect(source).toBeTruthy(); expect(target).toBeTruthy();
    expect(Buffer.compare(target, source)).toBe(0);
    const firstLine = await execSh(page, `cat ${copy} | head -n 1`);
    expect(firstLine.status, firstLine.stderr).toBe(0);
    expect(firstLine.stdout).toContain('root:x:0:0');
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
    const cp = await execCmd(page, ['/usr/bin/cp', `/mnt/cloud${source}`, `/mnt/cloud${target}`]);
    expect(cp.status, cp.stderr).toBe(0);
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

import { test, expect } from './test.js';

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

test('a page not isolated runs a pipeline one process after another, and nothing reads the terminal', async ({ page }) => {
  await page.route(url => new URL(url).pathname === '/', async route => {
    const response = await route.fetch();
    const headers = { ...response.headers() };
    delete headers['cross-origin-embedder-policy']; delete headers['cross-origin-opener-policy'];
    await route.fulfill({ response, headers });
  });
  await ready(page);
  expect(await page.evaluate(() => crossOriginIsolated)).toBe(false);
  await run(page, 'seq 1 3 | tr 1-3 a-c | fold -w 1');
  await expect(last(page)).toHaveText('a\nb\nc');
  await run(page, 'yes | head -n 2');
  // Without shared memory this fallback buffers stages sequentially, so an infinite
  // producer reaches its buffer limit before head can run. Report the producer accurately.
  await expect(page.locator('.transcript pre').filter({ hasText: /^y\ny$/ })).toHaveCount(1);
  await expect(last(page)).toContainText('yes: output larger than 10 MB was cut short');
  await run(page, 'tr a-z A-Z');
  await expect(last(page)).toHaveText(/tr a-z A-Z$/);
  await run(page, 'echo item | xargs echo');
  await expect(last(page)).toContainText('Function not implemented');
  await run(page, 'echo still-responsive'); await expect(last(page)).toHaveText('still-responsive');
});

test('a process reads one file after another; cp copies what the kernel makes, reading it', async ({ page }) => {
  await ready(page);
  await run(page, 'coreutils md5sum /etc/passwd /etc/group');
  await expect(last(page)).toHaveText(/^[0-9a-f]{32}  \/etc\/passwd\n[0-9a-f]{32}  \/etc\/group$/);
  const copy = '/tmp/passwd-' + Date.now().toString(36);
  await run(page, `cp /etc/passwd ${copy}`);
  await run(page, `cat ${copy}`);
  await expect(last(page)).toContainText('root:x:0:0');
  await run(page, `rm ${copy}`);
});

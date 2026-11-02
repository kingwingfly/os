import { test, expect } from '@playwright/test';

// Job control (crates/frontend/src/shell/jobs.rs, web/wasi/exec.mjs): a pipeline of /usr/bin run
// with & is a job; Ctrl+Z stops the one in the foreground, a job from then on; fg, bg and
// kill %N take them; a signal from any tab reaches the process where it runs, over the page's
// events line. Stopped processes wait at their next system call.
const input = page => page.getByRole('combobox', { name: 'Terminal command' });
const busy = page => page.locator('#command').locator('xpath=ancestor::form').locator('.busy');
const last = page => page.locator('.transcript pre').last();
const transcript = page => page.locator('.transcript');
async function run(page, text, { wait = true } = {}) {
  await expect(busy(page)).toHaveText('↵');
  await input(page).fill(text); await input(page).press('Enter');
  if (wait) await expect(busy(page)).toHaveText('↵', { timeout: 30_000 });
}
async function ready(page) {
  await page.goto('/');
  await expect(busy(page)).toHaveText('↵');
}

test('& runs a pipeline as a job: jobs lists it, kill %N ends it, and its end is said', async ({ page }) => {
  await ready(page);
  await run(page, 'coreutils sleep 30 &');
  await expect(last(page)).toHaveText(/^\[1\] \d+$/);
  await run(page, 'jobs');
  await expect(last(page)).toHaveText('[1]+  Running                 coreutils sleep 30 &');
  await run(page, 'kill %1');
  await expect(last(page)).toHaveText('[1]+  Terminated              coreutils sleep 30');
  await run(page, 'jobs');
  await expect(last(page)).toHaveText('No jobs or unfinished uploads');
  // What a job writes shows as it writes it; its end says how it ended.
  await run(page, 'seq 3 | tr 123 abc &');
  await expect(last(page)).toHaveText('[1]+  Done                    seq 3 | tr 123 abc');
  expect(await page.locator('.transcript pre').allInnerTexts()).toContain('a\nb\nc');
  // The terminal's own commands do not run so.
  await run(page, 'ls &');
  await expect(last(page)).toContainText('ls: & runs programs of /usr/bin');
});

test('Ctrl+Z stops the program in the foreground; fg gives it the terminal again; bg goes on with one', async ({ page }) => {
  await ready(page);
  await run(page, 'tr a-z A-Z', { wait: false });
  await expect(busy(page)).toHaveText('Input ↵');
  await input(page).press('Control+z');
  await expect(busy(page)).toHaveText('↵');
  await expect(last(page)).toHaveText('[1]+  Stopped                 tr a-z A-Z');
  // The kernel's record says so too.
  await run(page, 'ps');
  await expect(last(page)).toContainText(/T \(stopped\)\s+tr a-z A-Z/);
  await run(page, 'fg', { wait: false });
  await expect(busy(page)).toHaveText('Input ↵');
  await input(page).fill('hello'); await input(page).press('Enter');
  await expect(last(page)).toHaveText('HELLO');
  await input(page).press('Control+d');
  await expect(busy(page)).toHaveText('↵');
  await run(page, 'jobs');
  await expect(last(page)).toHaveText('No jobs or unfinished uploads');
  // A sleep stopped wakes to stop, and, continued in the background, sleeps out the rest.
  await run(page, 'coreutils sleep 2', { wait: false });
  await expect(busy(page)).not.toHaveText('↵');
  await input(page).press('Control+z');
  await expect(last(page)).toHaveText('[1]+  Stopped                 coreutils sleep 2');
  await run(page, 'bg');
  await expect(last(page)).toHaveText('[1]+ coreutils sleep 2 &');
  await expect(last(page)).toHaveText('[1]+  Done                    coreutils sleep 2', { timeout: 15_000 });
  await run(page, 'fg');
  await expect(last(page)).toHaveText('! fg: current: no such job');
});

test('a signal from another tab reaches the process where it runs: stopped, then ended', async ({ browser }) => {
  const context = await browser.newContext();
  try {
    const [one, two] = [await context.newPage(), await context.newPage()];
    await ready(one); await ready(two);
    await run(one, 'coreutils sleep 60 &');
    await expect(last(one)).toHaveText(/^\[1\] \d+$/);
    const pid = (await last(one).innerText()).split(' ')[1];
    await run(two, `kill -STOP ${pid}`);
    await expect(last(one)).toHaveText('[1]+  Stopped                 coreutils sleep 60');
    await run(two, 'kill -l');
    await expect(last(two)).toHaveText('HUP INT QUIT KILL PIPE TERM CHLD CONT STOP TSTP');
    await run(two, `kill ${pid}`);
    await expect(last(one)).toHaveText('[1]+  Terminated              coreutils sleep 60');
  } finally { await context.close(); }
});

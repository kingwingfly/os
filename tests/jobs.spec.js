import { test, expect } from './test.js';
import { call as syscall } from './sys.js';

// Job control (crates/frontend/src/shell/jobs.rs, web/wasi/exec.mjs): a pipeline of /usr/bin run
// with & is a job; Ctrl+Z stops the one in the foreground, a job from then on; fg, bg and
// kill %N take them; a signal from any tab reaches the process where it runs, over the page's
// events line. Stopped processes wait at their next system call.
const input = page => page.getByRole('combobox', { name: 'Terminal command' });
const busy = page => page.locator('#command').locator('xpath=ancestor::form');
const last = page => page.locator('.transcript pre').last();
const transcript = page => page.locator('.transcript');
async function run(page, text, { wait = true } = {}) {
  await expect(busy(page)).toHaveAttribute('data-state', 'idle');
  await input(page).fill(text); await input(page).press('Enter');
  if (wait) await expect(busy(page)).toHaveAttribute('data-state', 'idle', { timeout: 30_000 });
}
async function ready(page) {
  await page.goto('/');
  await expect(busy(page)).toHaveAttribute('data-state', 'idle');
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
  // ls is an external program now, with the same background lifecycle as other executables.
  await run(page, 'ls &');
  await expect(last(page)).toHaveText('[1]+  Done                    ls');
  // A shell-state builtin still belongs to this terminal.
  await run(page, 'cd &');
  await expect(last(page)).toContainText('cd: & runs programs of /usr/bin');
});

test('Ctrl+Z stops the program in the foreground; fg gives it the terminal again; bg goes on with one', async ({ page }) => {
  await ready(page);
  await run(page, 'tr a-z A-Z', { wait: false });
  await expect(busy(page)).toHaveAttribute('data-state', 'input');
  await input(page).press('Control+z');
  await expect(busy(page)).toHaveAttribute('data-state', 'idle');
  await expect(last(page)).toHaveText('[1]+  Stopped                 tr a-z A-Z');
  // The kernel's record says so too.
  await run(page, 'ps');
  await expect(last(page)).toContainText(/T \(stopped\)\s+tr a-z A-Z/);
  await run(page, 'fg', { wait: false });
  await expect(busy(page)).toHaveAttribute('data-state', 'input');
  await input(page).fill('hello'); await input(page).press('Enter');
  await expect(last(page)).toContainText('hello\nHELLO');
  await input(page).press('Control+d');
  await expect(busy(page)).toHaveAttribute('data-state', 'idle');
  await run(page, 'jobs');
  await expect(last(page)).toHaveText('No jobs or unfinished uploads');
  // A sleep stopped wakes to stop, and, continued in the background, sleeps out the rest.
  await run(page, 'coreutils sleep 2', { wait: false });
  await expect(busy(page)).not.toHaveAttribute('data-state', 'idle');
  await input(page).press('Control+z');
  await expect(last(page)).toHaveText('[1]+  Stopped                 coreutils sleep 2');
  await run(page, 'bg');
  await expect(last(page)).toHaveText('[1]+ coreutils sleep 2 &');
  await expect(last(page)).toHaveText('[1]+  Done                    coreutils sleep 2', { timeout: 15_000 });
  await run(page, 'fg');
  await expect(last(page)).toHaveText('fg: current: no such job');
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
    // The terminal may wrap inside a signal name. Compare the ordered catalog without visual whitespace.
    await expect.poll(async () => (await last(two).textContent()).replace(/\s/g, '')).toBe(
      'HUP INT QUIT ILL TRAP ABRT BUS FPE KILL USR1 SEGV USR2 PIPE ALRM TERM STKFLT CHLD CONT STOP TSTP TTIN TTOU URG XCPU XFSZ VTALRM PROF WINCH IO PWR SYS'.replace(/\s/g, ''));
    await run(two, `kill ${pid}`);
    // Catchable signals stay pending while stopped, even past the host's fallback deadline.
    await one.waitForTimeout(1500);
    expect((await syscall(one.request, { proc_poll: { pids: [Number(pid)] } }))[0].state).toBe('stopped');
    await run(two, `kill -CONT ${pid}`);
    await expect(last(one)).toHaveText('[1]+  Terminated              coreutils sleep 60');
  } finally { await context.close(); }
});

test('registry polling recovers a kill missed during an events outage', async ({ page }) => {
  await page.addInitScript(() => {
    const Native = WebSocket;
    window.eventsSockets = [];
    window.WebSocket = class extends Native {
      constructor(...args) { super(...args); window.eventsSockets.push(this); }
    };
  });
  await ready(page);
  await run(page, 'coreutils sleep 60 &');
  await expect(last(page)).toHaveText(/^\[1\] \d+$/);
  const pid = Number((await last(page).innerText()).split(' ')[1]);
  await page.evaluate(() => { for (const socket of window.eventsSockets) socket.close(); });
  const result = await page.evaluate(async pid => (await (await fetch('/api/sys', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ calls: [{ kill: { pid: String(pid), signal: 15 } }] }),
  })).json()).results[0], pid);
  expect(result).toHaveProperty('ok');
  await expect(last(page)).toHaveText('[1]+  Terminated              coreutils sleep 60', { timeout: 15_000 });
  await run(page, 'jobs');
  await expect(last(page)).toHaveText('No jobs or unfinished uploads');
});

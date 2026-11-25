import { test, expect } from './test.js';
import { hookPageKernel } from './service-auth.js';
import {
  runTerminal,
  sendTerminalLine,
  terminalInput,
  terminalScreen,
  terminalViewport,
  waitForTerminalReady,
} from './ui.js';

// Job control (`/usr/bin/osh`, `crates/services/src/osh.rs`): a pipeline run with & is a job;
// Ctrl+Z stops the one in the foreground; fg, bg and kill %N manage jobs; stopped processes wait
// at their next system call.
const screen = page => terminalScreen(page);
async function promptSeq(page) {
  return Number((await terminalViewport(page).getAttribute('data-prompt-seq')) || '0');
}
async function waitIdleAfter(page, before, timeout = 30_000) {
  await expect.poll(async () => {
    const vp = terminalViewport(page);
    return (await vp.getAttribute('data-state')) === 'idle'
      && Number((await vp.getAttribute('data-prompt-seq')) || '0') > before;
  }, { timeout }).toBe(true);
}
async function ready(page) {
  await page.goto('/');
  await waitForTerminalReady(page);
}
async function runOutput(page, command) {
  const id = crypto.randomUUID().slice(0, 8);
  const start = `__S_${id}__`, end = `__E_${id}__`;
  await runTerminal(page, `echo ${start}; ${command}; echo ${end}`, { timeout: 30_000 });
  await expect(screen(page)).toContainText(end, { timeout: 15_000 });
  const raw = '\n' + (await screen(page).innerText());
  const from = raw.lastIndexOf('\n' + start + '\n');
  expect(from, `start marker ${start} missing`).toBeGreaterThanOrEqual(0);
  const bodyStart = from + start.length + 2;
  const to = raw.indexOf(end, bodyStart);
  expect(to, `end marker ${end} missing`).toBeGreaterThanOrEqual(bodyStart);
  return raw.slice(bodyStart, to).replace(/\n$/, '');
}
async function pollUntilScreen(page, pattern, timeout = 15_000) {
  await expect.poll(async () => {
    await runTerminal(page, ':');
    return pattern.test(await screen(page).innerText());
  }, { timeout, intervals: [200, 400, 600] }).toBe(true);
}

test('& runs a pipeline as a job: jobs lists it, kill %N ends it, and its end is said', async ({ page }) => {
  await ready(page);
  await runTerminal(page, 'coreutils sleep 30 &');
  await expect(screen(page)).toContainText(/\[1\] \d+/);
  expect(await runOutput(page, 'jobs')).toMatch(/^\[1\]\+\s+Running\s+coreutils sleep 30$/);
  await runTerminal(page, 'kill %1');
  await pollUntilScreen(page, /\[1\]\s+Exit 143\s+coreutils sleep 30/);
  expect(await runOutput(page, 'jobs')).toBe('');
  // What a job writes shows as it writes it; its end says how it ended.
  await runTerminal(page, 'seq 3 | tr 123 abc &');
  await expect(screen(page)).toContainText('a\nb\nc', { timeout: 15_000 });
  await pollUntilScreen(page, /\[\d+\]\s+Done\s+seq 3 \| tr 123 abc/);
  // ls is an external program, with the same background lifecycle as other executables.
  await runTerminal(page, 'ls &');
  await pollUntilScreen(page, /\[\d+\]\s+Done\s+ls/);
});

test('Ctrl+Z stops the program in the foreground; fg gives it the terminal again; bg goes on with one', async ({ page }) => {
  await ready(page);
  const input = terminalInput(page);
  const vp = terminalViewport(page);

  let seq = await promptSeq(page);
  await runTerminal(page, 'tr a-z A-Z', { wait: false });
  await expect(vp).toHaveAttribute('data-state', 'busy', { timeout: 15_000 });
  await input.press('Control+z');
  await waitIdleAfter(page, seq);
  await expect(screen(page)).toContainText(/\[1\]\+\s+Stopped\s+tr a-z A-Z/);

  // The kernel's record says so too.
  expect(await runOutput(page, 'ps')).toMatch(/T \(stopped\)\s+tr a-z A-Z/);

  seq = await promptSeq(page);
  await runTerminal(page, 'fg', { wait: false });
  await expect(vp).toHaveAttribute('data-state', 'busy', { timeout: 15_000 });
  await sendTerminalLine(page, 'hello');
  await expect(screen(page)).toContainText('hello\nHELLO', { timeout: 15_000 });
  await input.press('Control+d');
  await waitIdleAfter(page, seq);
  expect(await runOutput(page, 'jobs')).toBe('');

  // A sleep stopped wakes to stop, and, continued in the background, sleeps out the rest.
  seq = await promptSeq(page);
  await runTerminal(page, 'coreutils sleep 2', { wait: false });
  await expect(vp).toHaveAttribute('data-state', 'busy', { timeout: 15_000 });
  await input.press('Control+z');
  await waitIdleAfter(page, seq);
  await expect(screen(page)).toContainText(/\[\d+\]\+\s+Stopped\s+coreutils sleep 2/);
  await runTerminal(page, 'bg');
  await expect(screen(page)).toContainText(/\[\d+\]\+ coreutils sleep 2 &/);
  await pollUntilScreen(page, /\[\d+\]\s+Done\s+coreutils sleep 2/, 15_000);
  await runTerminal(page, 'fg');
  await expect(screen(page)).toContainText('fg: no current job');
});

test('signals stay isolated across tabs and control local jobs: stopped, then ended', async ({ browser }) => {
  const context = await browser.newContext();
  try {
    const [one, two] = [await context.newPage(), await context.newPage()];
    const kernelOne = await hookPageKernel(one);
    await ready(one); await ready(two);
    await kernelOne.ready();
    // Advance tab one's PID counter so its job PID does not coincide with another tab's init/shell.
    await runTerminal(one, 'coreutils true');
    await runTerminal(one, 'coreutils sleep 60 &');
    await expect(screen(one)).toContainText(/\[1\] \d+/);
    const match = (await screen(one).innerText()).match(/\[1\] (\d+)/);
    expect(match).not.toBeNull();
    const pid = match[1];
    // Contract v2 §2.1: another tab's kernel instance cannot signal tab one's process.
    await runTerminal(two, `kill -STOP ${pid}`);
    await expect(screen(two)).toContainText(/No such process|ESRCH/i);
    expect((await kernelOne.value('poll', { pids: [Number(pid)] }))[0]?.state).toBe('running');
    // The terminal may wrap inside a signal name. Compare the ordered catalog without visual whitespace.
    const catalog = (await runOutput(two, 'kill -l')).replace(/\s/g, '');
    expect(catalog).toBe(
      'HUP INT QUIT ILL TRAP ABRT BUS FPE KILL USR1 SEGV USR2 PIPE ALRM TERM STKFLT CHLD CONT STOP TSTP TTIN TTOU URG XCPU XFSZ VTALRM PROF WINCH IO PWR SYS'.replace(/\s/g, ''),
    );
    // Signals within the owning instance stop, hold catchable signals while stopped, and terminate on CONT.
    await runTerminal(one, `kill -STOP ${pid}`);
    await expect.poll(async () => (await kernelOne.value('poll', { pids: [Number(pid)] }))[0]?.state, { timeout: 10_000 }).toBe('stopped');
    await pollUntilScreen(one, /\[1\]\+\s+Stopped(?:\(\d+\))?\s+coreutils sleep 60/);
    await runTerminal(one, `kill ${pid}`);
    // Catchable signals stay pending while stopped, even past the host's fallback deadline.
    await one.waitForTimeout(1500);
    expect((await kernelOne.value('poll', { pids: [Number(pid)] }))[0]?.state).toBe('stopped');
    await runTerminal(one, `kill -CONT ${pid}`);
    await pollUntilScreen(one, /\[1\]\s+Exit 143\s+coreutils sleep 60/, 15_000);
  } finally { await context.close(); }
});

test('local sync polling recovers a kill missed during an events outage', async ({ page }) => {
  await page.addInitScript(() => {
    const Native = WebSocket;
    window.eventsSockets = [];
    window.WebSocket = class extends Native {
      constructor(...args) { super(...args); window.eventsSockets.push(this); }
    };
  });
  const kernel = await hookPageKernel(page);
  await ready(page);
  await kernel.ready();
  await runTerminal(page, 'coreutils sleep 60 &');
  await expect(screen(page)).toContainText(/\[1\] \d+/);
  const match = (await screen(page).innerText()).match(/\[1\] (\d+)/);
  expect(match).not.toBeNull();
  const pid = Number(match[1]);
  await page.evaluate(() => { for (const socket of window.eventsSockets) socket.close(); });
  // Queue SIGTERM directly in the local client-kernel without sending deliver_signal,
  // verifying that periodic local `sync` reconciliation recovers the signal offline.
  const result = await kernel.call('kill', { pid, signal: 15 });
  expect(result).toHaveProperty('ok');
  await pollUntilScreen(page, /\[1\]\s+Exit 143\s+coreutils sleep 60/, 15_000);
  expect(await runOutput(page, 'jobs')).toBe('');
});

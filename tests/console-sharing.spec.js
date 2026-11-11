import { test, expect } from './test.js';
import { call } from './sys.js';

const command = page => page.locator('#command');
const panel = page => page.locator('.terminal-panel:not([hidden])');
const prompt = page => panel(page).locator('.command-line');
const screen = page => panel(page).locator('.terminal-screen').last();
const attachedInput = page => page.getByLabel('Attached terminal input');
const connection = page => page.locator('.console-connection');
test.beforeEach(async ({ page }) => { await page.goto('/'); await expect(prompt(page)).toHaveAttribute('data-state', 'idle'); });

async function start(page, text = 'cat') {
  await command(page).fill(text); await command(page).press('Enter');
  await expect(prompt(page)).toHaveAttribute('data-state', 'input', { timeout: 60_000 });
  await expect(panel(page).getByRole('button', { name: 'Open in new window' })).toBeVisible();
}
async function open(page, control = false) {
  await panel(page).getByRole('button', { name: 'Open in new window' }).click();
  const dialog = page.getByRole('dialog', { name: 'Open command in a new window' });
  await expect(dialog.getByRole('radio', { name: 'View only', exact: true })).toBeChecked();
  if (control) await dialog.getByRole('radio', { name: 'Use keyboard in new window', exact: true }).check();
  const [other] = await Promise.all([page.waitForEvent('popup'), dialog.getByRole('button', { name: 'Open window', exact: true }).click()]);
  await expect(connection(other)).toHaveText(control ? 'Keyboard connected' : 'View only · live output', { timeout: 60_000 });
  if (control) await expect(attachedInput(other)).toBeFocused();
  return other;
}

test('the sharing dialog defaults to view-only and Stop sharing preserves the running command', async ({ page, browserName }) => {
  await expect(panel(page).getByRole('button', { name: 'Open in new window' })).toBeDisabled();
  const top = (await panel(page).locator('.transcript').boundingBox()).y;
  await start(page);
  expect((await panel(page).locator('.transcript').boundingBox()).y).toBe(top);
  const other = await open(page);
  await page.screenshot({ path: `/tmp/os-attachment-ui-owner-${browserName}.png` });
  await expect(attachedInput(other)).toBeDisabled(); await expect(command(page)).toBeEnabled();
  await command(page).pressSequentially('owner-only'); await command(page).press('Enter');
  await expect(other.locator('.terminal-screen')).toContainText('owner-only');
  await panel(page).getByRole('button', { name: 'Stop sharing' }).click();
  await expect(connection(other)).toHaveText('Sharing ended');
  await page.keyboard.type('after-sharing'); await page.keyboard.press('Enter');
  await expect(screen(page)).toContainText('after-sharing');
  await expect(other.locator('.terminal-screen')).not.toContainText('after-sharing');
  await command(page).press('Control+d'); await expect(prompt(page)).toHaveAttribute('data-state', 'idle');
  await expect(panel(page).getByRole('button', { name: 'Open in new window' })).toBeDisabled();
  expect((await panel(page).locator('.transcript').boundingBox()).y).toBe(top);
});

test('keyboard control moves to the attached window and Disconnect returns it with working focus', async ({ page, browserName }) => {
  await start(page); const other = await open(page, true);
  await expect(command(page)).toBeDisabled(); await expect(attachedInput(other)).toBeEnabled();
  await other.keyboard.type('remote-input'); await other.keyboard.press('Enter');
  await expect(screen(page)).toContainText('remote-input'); await expect(other.locator('.terminal-screen')).toContainText('remote-input');
  await other.screenshot({ path: `/tmp/os-attachment-ui-desktop-${browserName}.png` });
  await other.setViewportSize({ width: 430, height: 700 });
  await other.screenshot({ path: `/tmp/os-attachment-ui-mobile-${browserName}.png` });
  await other.getByRole('button', { name: 'Disconnect', exact: true }).click();
  await expect(connection(other)).toContainText('Disconnected');
  await expect(command(page)).toBeEnabled();
  await command(page).focus(); await page.keyboard.type('restored'); await page.keyboard.press('Enter');
  await expect(screen(page)).toContainText('restored');
  await command(page).press('Control+c'); await expect(prompt(page)).toHaveAttribute('data-state', 'idle');
});

test('an attached interactive shell uses the existing ANSI renderer, resize and Ctrl+C behavior', async ({ page }) => {
  await start(page, 'sh -i'); const other = await open(page, true);
  await other.keyboard.type("printf '\\033[?1049h\\033[2J\\033[HREMOTE\\n'"); await other.keyboard.press('Enter');
  await expect(other.locator('.terminal-screen[data-alternate="true"]')).toContainText('REMOTE');
  await expect(other.locator('.terminal-screen[data-alternate="true"]')).toBeVisible();
  await other.keyboard.type("printf '\\033[?1049l'"); await other.keyboard.press('Enter');
  await expect(other.locator('.terminal-screen')).toHaveAttribute('data-alternate', 'false');
  await other.keyboard.type('stty size'); await other.keyboard.press('Enter');
  await expect(other.locator('.terminal-screen')).toContainText(/\n\d+ \d+\n/);
  const before = (await other.locator('.terminal-screen').textContent()).match(/\n(\d+ \d+)\n/)[1];
  await other.setViewportSize({ width: 700, height: 480 });
  // ResizeObserver and the remote driver update asynchronously. Ask for a fresh
  // observation on each attempt instead of polling one earlier stty result.
  await expect.poll(async () => {
    await other.keyboard.type('stty size'); await other.keyboard.press('Enter');
    return [...(await other.locator('.terminal-screen').textContent()).matchAll(/\n(\d+ \d+)\n/g)].at(-1)?.[1] ?? before;
  }).not.toBe(before);
  await other.keyboard.type('sleep 60'); await other.keyboard.press('Enter');
  await expect.poll(async () => (await call(page.request, { proc_poll: { pids: [] } })).some(row => row.argv[0] === 'sleep')).toBe(true);
  await other.keyboard.press('Control+c');
  await expect(other.locator('.terminal-screen')).toHaveText(/\$\s*$/);
  await other.keyboard.type('echo after-interrupt'); await other.keyboard.press('Enter');
  await expect(other.locator('.terminal-screen')).toContainText(/\nafter-interrupt/);
  await other.keyboard.type('exit'); await other.keyboard.press('Enter');
  await expect(connection(other)).toHaveText('Command ended');
  await expect(prompt(page)).toHaveAttribute('data-state', 'idle');
});

test('closing an attached window promptly returns keyboard control without ending the command', async ({ page }) => {
  await start(page); const other = await open(page, true); await other.close();
  await expect(command(page)).toBeEnabled({ timeout: 5000 });
  await command(page).pressSequentially('after-close'); await command(page).press('Enter');
  await expect(screen(page)).toContainText('after-close');
  await command(page).press('Control+d'); await expect(prompt(page)).toHaveAttribute('data-state', 'idle');
});

test('blocked popups and Cancel restore real keyboard input without creating a grant', async ({ page, context }) => {
  await start(page);
  await page.evaluate(() => { window.originalOpen = window.open; window.open = () => null; });
  await panel(page).getByRole('button', { name: 'Open in new window' }).click();
  const dialog = page.getByRole('dialog', { name: 'Open command in a new window' });
  await dialog.getByRole('button', { name: 'Open window', exact: true }).click();
  await expect(dialog.getByRole('alert')).toContainText('Allow pop-ups');
  await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
  await page.keyboard.type('after-cancel'); await page.keyboard.press('Enter');
  await expect(screen(page)).toContainText('after-cancel');
  expect(context.pages()).toHaveLength(1);
  await expect(panel(page).getByRole('button', { name: 'Stop sharing' })).toBeHidden();
  await command(page).press('Control+d'); await expect(prompt(page)).toHaveAttribute('data-state', 'idle');
});

test('an open sharing dialog cannot grant a newer command in the same pane', async ({ page }) => {
  await start(page);
  const terminalId = await panel(page).getAttribute('data-terminal');
  await panel(page).getByRole('button', { name: 'Open in new window' }).click();
  await page.evaluate(id => window.os.closeConsole(id), terminalId);
  await expect(prompt(page)).toHaveAttribute('data-state', 'idle');
  await page.evaluate(terminalId => {
    window.newerDone = window.os.exec([{ path: '/usr/bin/coreutils', argv: ['coreutils', 'cat'] }], {
      terminalId, tty: true, onTty: input => { window.newerInput = input; }, onOutput: () => {},
    });
  }, terminalId);
  await expect.poll(() => page.evaluate(() => !!window.newerInput)).toBe(true);
  try {
    const [other] = await Promise.all([page.waitForEvent('popup'), page.getByRole('dialog').getByRole('button', { name: 'Open window', exact: true }).click()]);
    await expect(connection(other)).toHaveText('The selected command is no longer available.', { timeout: 60_000 });
    await expect(attachedInput(other)).toBeDisabled();
  } finally { await page.evaluate(async () => { window.newerInput?.eof(); await window.newerDone; }); }
});

test('opening the attached-terminal address directly grants no console access', async ({ page }) => {
  await page.goto('/console.html');
  await expect(connection(page)).toHaveText('Open this window from a running terminal.');
  await expect(attachedInput(page)).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Disconnect', exact: true })).toBeDisabled();
});

test('an unrelated window cannot consume the prepared console grant by announcing readiness', async ({ page, context }) => {
  await start(page);
  let resume, continued, blocked = false;
  const waiting = new Promise(resolve => { resume = resolve; });
  const finished = new Promise(resolve => { continued = resolve; });
  const delay = async route => {
    blocked = true; await waiting;
    try { await route.continue(); } finally { continued(); }
  };
  await context.route('**/console-window.js', delay);
  await panel(page).getByRole('button', { name: 'Open in new window' }).click();
  await page.getByLabel('Use keyboard in new window').check();
  const [recipient] = await Promise.all([page.waitForEvent('popup'), page.getByRole('button', { name: 'Open window', exact: true }).click()]);
  try {
    await expect.poll(() => blocked).toBe(true);
    const [unrelated] = await Promise.all([page.waitForEvent('popup'), page.evaluate(() => window.open('/'))]);
    await unrelated.waitForLoadState();
    await unrelated.evaluate(() => {
      window.receivedPorts = 0;
      addEventListener('message', event => { window.receivedPorts += event.ports.length; });
      opener.postMessage({ type: 'os-console-ready', nonce: crypto.randomUUID() }, location.origin);
    });
    await command(page).pressSequentially('owner-still-controls'); await command(page).press('Enter');
    await expect(screen(page)).toContainText('owner-still-controls');
    expect(await unrelated.evaluate(() => window.receivedPorts)).toBe(0);
    await unrelated.close();
  } finally { resume(); if (blocked) await finished; await context.unroute('**/console-window.js', delay); }
  await expect(connection(recipient)).toHaveText('Keyboard connected', { timeout: 60_000 });
  await expect(command(page)).toBeDisabled();
  await recipient.getByRole('button', { name: 'Disconnect', exact: true }).click();
  await expect(command(page)).toBeEnabled(); await command(page).press('Control+c');
});

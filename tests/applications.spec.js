import { executableAsset } from './executable-asset.js';
import { test, expect } from './test.js';
import { api, call, errno, rmrf } from './sys.js';
import { readFile } from 'node:fs/promises';
const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const field = page => page.getByLabel('Shell input', { exact: true });
const screen = page => page.locator('.terminal-screen');
const records = page => page.evaluate(() => window.os.applications());
let base;
test.beforeEach(async ({ page }) => {
  await page.goto('/'); await page.waitForFunction(() => !!window.os?.applications);
  await expect.poll(() => page.evaluate(async () => (await window.os.loginSession()).connected && (await window.os.machineInit()).connected)).toBe(true);
  base = '/guest/gui-' + crypto.randomUUID(); await call(page.request, { mkdir: { path: base, mode: 0o700 } });
});
test.afterEach(async ({ page, context }) => {
  if (!page.isClosed()) await page.evaluate(() => { for (const r of window.os?.applications?.() ?? []) window.os.stopApplication(r.id); }).catch(() => {});
  for (const other of context.pages()) if (other !== page) await other.close();
  await rmrf(context.request, base);
});
async function open(page, ready = true) {
  if (!await page.locator('#applications').isVisible()) await page.getByRole('button', { name: 'App windows', exact: true }).click();
  const promise = page.waitForEvent('popup'); await page.getByRole('button', { name: 'Open shell', exact: true }).click();
  const child = await promise;
  if (ready) {
    await expect.poll(async () => (await records(page)).at(-1)?.state, { timeout: 45000 }).toBe('ready');
    await expect(field(child)).toBeEnabled();
    await expect(screen(child)).toContainText(/[#$]\s*$/, { timeout: 30000 });
  }
  return child;
}
async function command(page, command, expected) {
  await expect(screen(page)).toContainText(/[#$]\s*$/, { timeout: 30000 });
  await field(page).fill(command); await field(page).press('Enter');
  if (expected) await expect(screen(page)).toContainText(expected, { timeout: 30000 });
}
async function closed(page) { await expect.poll(() => page.isClosed(), { timeout: 15000 }).toBe(true); }
async function signIn(request) { expect((await api(request, 'login', { headers: { 'CF-Connecting-IP': 'gui-' + crypto.randomUUID() }, data: { password } })).ok()).toBe(true); }

test('Applications opens a ready shell with real processes and preserves output after natural exit', async ({ page }) => {
  const child = await open(page); const record = (await records(page))[0];
  expect(Object.keys(record).sort()).toEqual(['id', 'reason', 'state', 'target']);
  await page.screenshot({ path: '/home/ai/os-gui-supervision-validation/application-status.png' });
  await command(child, 'echo SHELL_PID:$$; id -u', /SHELL_PID:\d+/);
  const pid = (await screen(child).textContent()).match(/SHELL_PID:(\d+)/)[1];
  expect((await call(page.request, { stat: { path: `/proc/${pid}` } })).mode).toBeTruthy();
  await command(child, 'exit 0');
  await expect.poll(async () => (await records(page))[0].state).toBe('exited');
  expect(child.isClosed()).toBe(false); await expect(field(child)).toBeDisabled();
  await expect(child.getByRole('button', { name: 'Start shell', exact: true })).toBeHidden();
  await expect.poll(() => errno(page.request, { stat: { path: `/proc/${pid}` } })).toBe('ENOENT');
  await child.screenshot({ path: '/home/ai/os-gui-supervision-validation/managed-shell.png' });
});

test('Stop waits for shell cleanup and does not end an independent desktop command', async ({ page }) => {
  await page.evaluate(() => { window.independent = window.os.exec([['/usr/bin/sleep', '30']], { onJob: group => { window.independentGroup = group; } }); });
  const child = await open(page);
  await command(child, `trap 'echo clean > ${base}/stopped; exit 0' HUP TERM; echo CLEANUP_READY; while :; do sleep 0.1; done`, /\nCLEANUP_READY\n/);
  await page.locator('[data-application]').getByRole('button', { name: 'Stop', exact: true }).click(); await closed(child);
  expect(await (await page.request.get('/api/file?path=' + base + '/stopped')).text()).toBe('clean\n');
  const pid = await page.evaluate(() => window.independentGroup.pids[0]);
  expect(await errno(page.request, { stat: { path: `/proc/${pid}` } })).toBe(null);
  await page.evaluate(async () => { window.independentGroup.signal(15); await window.independent; });
  await expect.poll(async () => (await records(page))[0].state).toBe('stopped');
  const second = await open(page); await second.getByRole('button', { name: 'End shell', exact: true }).click(); await closed(second);
  await expect.poll(async () => (await records(page)).at(-1).state).toBe('stopped');
});

test('image loading stays Starting with disabled input and stopping cancels the candidate', async ({ page, context }) => {
  let release, loading = false; const held = new Promise(resolve => { release = resolve; });
  await context.route(executableAsset('dash'), async route => { loading = true; await held; await route.continue(); });
  try {
    const child = await open(page, false); await expect.poll(() => loading).toBe(true);
    expect((await records(page))[0].state).toBe('starting'); await expect(field(child)).toBeDisabled();
    await page.locator('[data-application]').getByRole('button', { name: 'Stop', exact: true }).click(); release();
    await closed(child); await expect.poll(async () => (await records(page))[0].state).toBe('stopped');
  } finally { release(); }
});

test('startup timeout closes a loading application without launching another window', async ({ page, context }) => {
  let release; const held = new Promise(resolve => { release = resolve; }); let popups = 0;
  page.on('popup', () => popups++);
  await context.route(executableAsset('dash'), async route => { await held; await route.abort(); });
  try {
    const child = await open(page, false);
    await expect.poll(async () => (await records(page))[0].state, { timeout: 45000 }).toBe('failed');
    await closed(child); expect((await records(page))[0].reason).toContain('startup timed out'); expect(popups).toBe(1);
  } finally { release(); }
});

test('an application startup failure remains visible and does not retry automatically', async ({ page, context }) => {
  await context.route(executableAsset('dash'), route => route.abort());
  const child = await open(page, false);
  await expect.poll(async () => (await records(page))[0].state, { timeout: 30000 }).toBe('failed');
  await expect(child.locator('.console-connection')).toContainText('could not start');
  expect((await records(page)).length).toBe(1); await expect(field(child)).toBeDisabled();
});

test('leaving the desktop stops its application while a navigated child document is left alone', async ({ page }) => {
  const child = await open(page); await child.goto('/login.html');
  await expect(child.getByRole('button', { name: 'Continue as guest', exact: true })).toBeVisible();
  await expect.poll(async () => (await records(page))[0].state).toBe('exited');
  expect(child.isClosed()).toBe(false);
  const second = await open(page); await page.reload(); await closed(second);
  await page.waitForFunction(() => !!window.os?.applications); expect(await records(page)).toEqual([]);
  expect(child.isClosed()).toBe(false);
});

test('a confirmed account change stops managed windows and preserves an independent shell snapshot', async ({ page, context }) => {
  const ordinary = await context.newPage(); await ordinary.goto('/shell.html'); await expect(field(ordinary)).toBeEnabled({ timeout: 30000 });
  const guest = await call(page.request, 'getcreds'), child = await open(page);
  await signIn(page.request);
  await closed(child);
  await command(ordinary, 'id -u', new RegExp(`\\n${guest.uid}\\n`));
  expect((await call(page.request, 'getcreds')).uid).toBe(0);
});

test('explicit login shutdown and Machine restart end managed windows', async ({ page }) => {
  let child = await open(page);
  await page.evaluate(() => window.os.endLoginSession()); await closed(child);
  await expect.poll(() => page.evaluate(async () => (await window.os.loginSession()).session?.shutdown?.complete), { timeout: 45000 }).toBe(true);
  await page.evaluate(() => window.os.restartLoginSession());
  await signIn(page.request); await page.reload(); await page.waitForFunction(() => !!window.os?.applications);
  child = await open(page); await page.evaluate(() => window.os.rebootMachine()); await closed(child);
});

test('blocked popups and unknown targets cannot create application records', async ({ page }) => {
  await page.evaluate(() => { window.open = () => null; });
  await page.getByRole('button', { name: 'App windows', exact: true }).click(); await page.getByRole('button', { name: 'Open shell', exact: true }).click();
  await expect(page.locator('#application-error')).toContainText('Allow pop-ups'); expect(await records(page)).toEqual([]);
  expect(await page.evaluate(() => { try { window.os.launchApplication('__proto__'); } catch (e) { return e.message; } })).toContain('installed application');
});

test('a managed URL without the opening desktop cannot start a shell', async ({ context }) => {
  const child = await context.newPage(); const images = [];
  child.on('request', request => { if (/usr\/bin|client-kernel/.test(request.url())) images.push(request.url()); });
  await child.goto('/shell.html?managed=1'); await expect(child.locator('#app')).toContainText('could not load'); expect(images).toEqual([]);
});

test('unrelated window messages cannot stop an attached managed shell', async ({ page }) => {
  const child = await open(page);
  await child.evaluate(() => { window.postMessage({ type: 'stop' }, location.origin); window.opener.postMessage({ type: 'os-application-hello', nonce: 'bad' }, location.origin); });
  await command(child, 'echo PORT_ONLY', /\nPORT_ONLY\n/); expect((await records(page))[0].state).toBe('ready');
});

test('authenticated exec metadata fences a stale login or boot before guest instructions run', async ({ page }) => {
  const expected = await page.evaluate(async () => ({ session: (await window.os.loginSession()).session.id, boot: (await window.os.machineInit()).init.boot }));
  const exec = values => page.evaluate(async ({ expected, base }) => {
    let output = '';
    try { const result = await window.os.exec([['/usr/bin/sh', '-c', `echo WRONG > ${base}/unexpected`]], { expectedSession: expected, onOutput: (_fd, text) => { output += text; } }); return { status: result.status, output }; }
    catch (e) { return { error: String(e.message ?? e) }; }
  }, { expected: values, base });
  for (const stale of [{ ...expected, session: 'wrong' }, { ...expected, boot: 'wrong' }]) {
    const result = await exec(stale); expect(result.status ?? 1).not.toBe(0);
    expect(await errno(page.request, { stat: { path: base + '/unexpected' } })).toBe('ENOENT');
  }
  await signIn(page.request); const result = await exec(expected); expect(result.status ?? 1).not.toBe(0);
  expect(await errno(page.request, { stat: { path: base + '/unexpected' } })).toBe('ENOENT');
});

test('Applications remains usable on a narrow viewport', async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 600 });
  await page.getByRole('button', { name: 'App windows', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Open shell', exact: true })).toBeInViewport();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(375);
  await page.screenshot({ path: '/home/ai/os-gui-supervision-validation/applications-mobile.png' });
});

test('closing App windows restores native terminal typing after either Close or Escape', async ({ page }) => {
  const input = page.locator('#command');
  for (const method of ['button', 'escape']) {
    const marker = 'APP_FOCUS_' + method, command = 'printf ' + marker;
    await expect(input).toBeEnabled(); await expect(input).toHaveValue('');
    await page.getByRole('button', { name: 'App windows', exact: true }).click();
    if (method === 'escape') await page.keyboard.press('Escape');
    else await page.locator('#applications-close').click();
    await expect(page.locator('#applications')).toBeHidden(); await expect(input).toBeFocused();
    // Native typing verifies Chromium's focus handoff; fill/click/Tab would hide a failure.
    await page.keyboard.type(command); await expect(input).toHaveValue(command);
    await page.keyboard.press('Enter'); await expect(page.locator('.transcript pre').last()).toHaveText(marker);
  }
});

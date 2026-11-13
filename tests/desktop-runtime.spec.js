import { test, expect } from './test.js';
import { call, put, rmrf } from './sys.js';

async function ready(page) { await page.goto('/'); await expect(page.locator('#command').locator('xpath=ancestor::form')).toHaveAttribute('data-state', 'idle'); }

test('Applications opens existing desktop windows and stays anchored to its dock button', async ({ page, context }) => {
  await ready(page);
  await expect(page.getByRole('link', { name: 'Start session', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'App windows', exact: true })).toHaveCount(0);
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 900 });
    const trigger = page.getByRole('button', { name: 'Applications', exact: true });
    await trigger.click(); const menu = page.getByRole('menu', { name: 'Applications', exact: true });
    const a = await trigger.boundingBox(), b = await menu.boundingBox();
    expect(Math.abs(b.x - a.x)).toBeLessThan(2); expect(b.y + b.height).toBeLessThan(a.y);
    expect(b.x + b.width).toBeLessThanOrEqual(width);
    await menu.getByRole('menuitem', { name: 'Terminal', exact: true }).click();
    await expect(page.locator('#window-terminal')).toHaveClass(/window-focused/); expect(context.pages()).toHaveLength(1);
    await trigger.click(); await trigger.press('Escape'); await expect(menu).toBeHidden();
  }
});

test('isolated processes fork, supervise services and interrupt unbounded terminal output', async ({ page }) => {
  test.setTimeout(120000); await ready(page);
  expect(await page.evaluate(() => ({ isolated: crossOriginIsolated, shared: typeof SharedArrayBuffer }))).toEqual({ isolated: true, shared: 'function' });
  const result = await page.evaluate(() => window.os.exec([['/usr/bin/sh', '-c', 'printf fork-ok; /usr/bin/true']], { stdin: '' }));
  expect(result).toMatchObject({ status: 0, stdout: 'fork-ok' });
  const base = '/guest/desktop-runtime-' + crypto.randomUUID(); await call(page.request, { mkdir: { path: base, mode: 0o700 } });
  try {
    expect((await put(page.request, '/api/file?path=' + base + '/services.json', { data: JSON.stringify({ version: 1, units: [{ name: 'ticker', argv: ['/usr/bin/sh', '-c', 'while :; do echo SERVICE_TICK; sleep 0.2; done'], stop_timeout_ms: 1000 }] }) })).ok()).toBe(true);
    const field = page.getByRole('combobox', { name: 'Terminal command' }), state = page.locator('#command').locator('xpath=ancestor::form');
    await field.fill('supervise ' + base + '/services.json'); await field.press('Enter');
    await expect(page.locator('#window-terminal')).toContainText('SERVICE_TICK');
    await field.press('Control+c'); await expect(state).toHaveAttribute('data-state', 'idle', { timeout: 10000 });
    await field.fill('yes'); await field.press('Enter');
    await expect(state).not.toHaveAttribute('data-state', 'idle');
    await expect(page.locator('.terminal-screen').filter({ visible: true })).toContainText('y');
    await field.press('Control+c'); await expect(state).toHaveAttribute('data-state', 'idle', { timeout: 10000 });
    await expect(page.locator('#window-terminal')).not.toContainText('output larger than');
  } finally { await rmrf(page.request, base); }
});

test('interactive shell prompt shows identity and follows cd without an extra start action', async ({ page }) => {
  await page.goto('/shell.html'); const input = page.getByLabel('Shell input', { exact: true }), screen = page.locator('.terminal-screen');
  await expect(input).toBeEnabled(); await expect(screen).toContainText(/guest-[^\s]+@os:\/[^\n]* \$\s*$/);
  await expect(page.getByRole('button', { name: 'Start shell', exact: true })).toBeHidden();
  await input.fill('cd /tmp'); await input.press('Enter');
  await expect(screen).toContainText(/@os:\/tmp \$\s*$/);
  await input.fill('exit'); await input.press('Enter');
  await expect(page.getByRole('button', { name: 'Start shell', exact: true })).toBeVisible();
});

test('missing isolation refuses command admission instead of running a broken sequential fallback', async ({ page, context }) => {
  await context.route('**/*', async route => {
    if (route.request().resourceType() !== 'document') return route.continue();
    const response = await route.fetch(), headers = response.headers();
    delete headers['cross-origin-opener-policy']; delete headers['cross-origin-embedder-policy'];
    await route.fulfill({ response, headers });
  });
  await ready(page); await expect(page.locator('.execution-notice')).toContainText('isolated browser page');
  let admissions = 0; page.on('request', request => { if (request.method() === 'POST' && new URL(request.url()).pathname === '/api/sys' && request.postDataJSON()?.calls?.some(call => call.execve?.argv?.includes('yes'))) admissions++; });
  await expect(page.evaluate(() => window.os.exec([['/usr/bin/yes']], { stdin: '' }))).rejects.toThrow(/isolated browser page/);
  expect(admissions).toBe(0);
  await context.unrouteAll({ behavior: 'wait' });
});

test('unavailable browser storage explains the supported alternatives without creating a mount', async ({ page }) => {
  // OPFS is acquired in the kernel worker, not passed from the page. Inject the
  // storage failure in that execution host so the real admission path is tested.
  await page.route('**/client-kernel.js', async route => {
    const response = await route.fetch();
    await route.fulfill({ response, body: "navigator.storage.getDirectory = () => Promise.reject(new DOMException('Unavailable', 'UnknownError'));\n" + await response.text() });
  });
  await ready(page); await page.locator('.files-mounts').click();
  const window = page.locator('#window-mounts');
  await window.getByRole('tab', { name: 'Add mount', exact: true }).click();
  await window.locator('[name=kind]').selectOption('storage');
  await window.getByRole('button', { name: 'Mount storage', exact: true }).click();
  await expect(window.locator('.mount-notice')).toContainText('Browser storage is unavailable in this session');
  expect(await page.evaluate(() => window.os.localMountList())).toEqual([]);
  await window.locator('[name=kind]').selectOption('host');
  const direct = await page.evaluate(() => typeof showDirectoryPicker === 'function');
  await expect(window.locator('[data-connect]')).toHaveText(direct ? 'Choose folder…' : 'Connect folder');
});

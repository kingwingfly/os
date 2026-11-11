import { executableAsset } from './executable-asset.js';
import { test, expect } from './test.js';
import { api, call, put, rmrf, sys } from './sys.js';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const input = page => page.getByLabel('Shell input', { exact: true });
const screen = page => page.locator('.terminal-screen');
const status = page => page.locator('.console-connection');
const end = page => page.getByRole('button', { name: 'End shell', exact: true });
async function ready(page) { await page.goto('/shell.html'); await expect(input(page)).toBeEnabled({ timeout: 30_000 }); }
async function command(page, text, expected) {
  await expect(screen(page)).toContainText(/[#$]\s*$/, { timeout: 30_000 });
  await input(page).fill(text); await input(page).press('Enter');
  if (expected) await expect(screen(page)).toContainText(expected, { timeout: 30_000 });
}
async function signIn(request) {
  expect((await api(request, 'login', { headers: { 'CF-Connecting-IP': 'targets-' + randomUUID() }, data: { password } })).ok()).toBe(true);
}
async function loginAction(request, action) {
  const [answer] = await sys(request, [{ login_session: { action } }], {}, { 'X-Registry': '1' });
  expect(answer.err, JSON.stringify(answer)).toBeUndefined(); return answer.ok;
}
const secret = () => randomBytes(32).toString('hex');

test.beforeEach(async ({ context }) => { await context.setExtraHTTPHeaders({ 'CF-Connecting-IP': 'targets-' + randomUUID() }); });

test('greeter offers fixed session choices and guest desktop without booting an execution host', async ({ page }) => {
  const hosts = []; page.on('request', request => { if (/client-kernel|executor-host|usr\/bin/.test(request.url())) hosts.push(request.url()); });
  await page.goto('/login.html?target=https://example.invalid');
  await expect(page.getByLabel('Desktop', { exact: true })).toBeChecked();
  await expect(page.getByRole('button', { name: 'Continue as guest', exact: true })).toBeEnabled();
  expect(hosts).toEqual([]);
  await page.screenshot({ path: '/home/ai/os-session-targets-validation/greeter.png' });
  await page.getByRole('button', { name: 'Continue as guest', exact: true }).click();
  await expect(page).toHaveURL(/\/(?:index\.html)?$/); await expect(page.locator('#command')).toBeVisible();
  await expect(page.getByRole('link', { name: 'Start session', exact: true })).toHaveAttribute('target', '_blank');
});

test('sign-in selects a real root shell with its account home and no credentials in the URL', async ({ page }) => {
  await page.goto('/login.html?target=shell'); await expect(page.getByLabel('Shell', { exact: true })).toBeChecked();
  await page.getByLabel('Username', { exact: true }).fill('root');
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Sign in and start', exact: true }).click();
  await expect(page).toHaveURL(/\/shell(?:\.html)?$/); await expect(input(page)).toBeEnabled({ timeout: 30_000 });
  await command(page, 'id -u; pwd', /\n0\n\/root\n/);
  await page.screenshot({ path: '/home/ai/os-session-targets-validation/shell.png' });
  await end(page).click(); await expect(input(page)).toBeDisabled();
  await expect(status(page)).toContainText('Shell exited', { timeout: 15_000 });
});

test('failed sign-in stays on the greeter, clears the password and can retry', async ({ page }) => {
  await page.goto('/login.html'); await page.getByLabel('Username', { exact: true }).fill('root');
  await page.getByLabel('Password', { exact: true }).fill('incorrect-' + randomUUID());
  await page.getByRole('button', { name: 'Sign in and start', exact: true }).click();
  await expect(page.getByRole('alert')).not.toBeEmpty(); await expect(page.getByLabel('Password', { exact: true })).toHaveValue('');
  await expect(page).toHaveURL(/\/login(?:\.html)?$/); expect((await call(page.request, 'getcreds')).signed_in).toBe(false);
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Sign in and start', exact: true }).click();
  await expect(page.locator('#command')).toBeVisible(); expect((await call(page.request, 'getcreds')).uid).toBe(0);
});

test('continuing an authenticated account does not reauthenticate it', async ({ page }) => {
  await call(page.request, 'getcreds'); await signIn(page.request);
  const logins = []; page.on('request', request => { if (request.postData()?.includes('"login":')) logins.push(request.url()); });
  await page.goto('/login.html'); await page.getByRole('button', { name: 'Continue as root', exact: true }).click();
  await expect(page.locator('#command')).toBeVisible(); expect(logins).toEqual([]);
});

test('a stale Continue choice cannot silently enter an account selected in another window', async ({ page }) => {
  await page.goto('/login.html'); await expect(page.getByRole('button', { name: 'Continue as guest', exact: true })).toBeEnabled();
  await signIn(page.request);
  await page.getByRole('button', { name: 'Continue as guest', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('account changed'); await expect(page).toHaveURL(/\/login(?:\.html)?$/);
  await page.getByRole('button', { name: 'Refresh account', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Continue as root', exact: true })).toBeEnabled();
});

test('greeter logout starts a guest shell while an existing root shell keeps its credentials', async ({ page, context }) => {
  await call(page.request, 'getcreds'); await signIn(page.request); await ready(page);
  await command(page, 'id -u', /\n0\n/);
  const other = await context.newPage(); await other.goto('/login.html?target=shell');
  await other.getByRole('button', { name: 'Sign out and continue as guest', exact: true }).click();
  await expect(input(other)).toBeEnabled({ timeout: 30_000 });
  const guest = await call(other.request, 'getcreds'); expect(guest.uid).toBeGreaterThan(0);
  await command(other, 'id -u', new RegExp(`\\n${guest.uid}\\n`));
  await command(page, "printf 'old:'; id -u", /\nold:0\n/);
  await end(page).click(); await end(other).click();
});

test('standalone shell executes real pipelines, redirection and PATH commands', async ({ page }) => {
  await ready(page); const base = '/guest/session-target-' + randomUUID();
  await call(page.request, { mkdir: { path: base, mode: 0o700 } });
  try {
    await command(page, `cd ${base}; printf 'a\\nb\\n' > letters; cat letters | wc -l; ls`, /\n2\nletters\n/);
    expect(await (await page.request.get('/api/file?path=' + base + '/letters')).text()).toBe('a\nb\n');
    await command(page, 'echo $$', /\n\d+\n/); await end(page).click();
    await expect(status(page)).toContainText('Shell exited', { timeout: 15_000 });
  } finally { await rmrf(page.request, base); }
});

test('Ctrl+C interrupts yes and returns to the shell without a busy label', async ({ page }) => {
  await ready(page); await command(page, 'yes SESSION-SPAM', /\nSESSION-SPAM\n/);
  await input(page).press('Control+c'); await command(page, "printf 'recovered\\n'", /\nrecovered\n/);
  await expect(status(page)).toHaveText(''); await expect(page.getByText('Working', { exact: true })).toHaveCount(0);
  await end(page).click();
});

test('shell PTY preserves no-echo input, alternate screens and resize', async ({ page }) => {
  await ready(page);
  await command(page, 'stty -echo; echo SECRET-READY; read answer; stty echo; printf "chars:%s\\n" "${#answer}"', /\nSECRET-READY\n/);
  await expect(input(page)).toHaveAttribute('type', 'password');
  await input(page).fill('quiet-secret'); await input(page).press('Enter');
  await expect(screen(page)).toContainText(/\nchars:12\n/); await expect(screen(page)).not.toContainText('quiet-secret');
  await command(page, "printf '\\033[?1049h'"); await expect(screen(page)).toHaveAttribute('data-alternate', 'true');
  await command(page, "printf '\\033[?1049l'"); await expect(screen(page)).toHaveAttribute('data-alternate', 'false');
  await command(page, 'stty size', /\n\d+ \d+\n/);
  const before = (await screen(page).textContent()).match(/\n(\d+ \d+)\n/g).at(-1);
  await page.setViewportSize({ width: 700, height: 420 });
  await expect.poll(async () => {
    await command(page, 'stty size');
    return (await screen(page).textContent()).match(/\n(\d+ \d+)\n/g)?.at(-1);
  }).not.toBe(before);
  await end(page).click();
});

test('exit disables input and explicit restart uses the current account with a fresh screen', async ({ page }) => {
  await ready(page); await command(page, "stty -echo; printf 'OLD-SCREEN\\n'; exit 7");
  await expect(status(page)).toHaveText('Shell exited (7)'); await expect(input(page)).toBeDisabled();
  await signIn(page.request); await page.getByRole('button', { name: 'Start shell', exact: true }).click();
  await expect(input(page)).toBeEnabled(); await command(page, 'true'); await expect(input(page)).toHaveAttribute('type', 'text'); await expect(screen(page)).not.toContainText('OLD-SCREEN');
  await command(page, 'id -u', /\n0\n/); await end(page).click();
});

test('a failed shell image does not restart automatically and can be retried explicitly', async ({ page, context }) => {
  let loads = 0;
  await context.route(executableAsset('dash'), route => { loads++; return route.abort(); });
  await page.goto('/shell.html'); await expect(status(page)).toContainText('Shell could not start', { timeout: 30_000 });
  await expect(input(page)).toBeDisabled(); const before = loads; await page.waitForTimeout(1200); expect(loads).toBe(before);
  await context.unroute(executableAsset('dash')); await page.getByRole('button', { name: 'Start shell', exact: true }).click();
  await expect(input(page)).toBeEnabled({ timeout: 30_000 }); await command(page, "printf 'image-recovered\\n'", /\nimage-recovered\n/);
  await end(page).click();
});

test('ending while the shell image loads abandons the candidate and cannot revive input', async ({ page, context }) => {
  let release, loading = false; const hold = new Promise(resolve => { release = resolve; });
  await context.route(executableAsset('dash'), async route => { loading = true; await hold; await route.continue(); });
  try {
    await page.goto('/shell.html'); await expect.poll(() => loading).toBe(true);
    await end(page).click(); await expect(input(page)).toBeDisabled(); release();
    await expect(status(page)).toContainText('Shell exited', { timeout: 30_000 }); await expect(input(page)).toBeDisabled();
  } finally { release(); }
});

test('the selected shell starts automatic login units once; the greeter does not start them', async ({ page }) => {
  await call(page.request, 'getcreds'); const base = '/guest/target-units-' + randomUUID();
  await call(page.request, { mkdir: { path: base, mode: 0o700 } });
  const file = base + '/units.json';
  expect((await put(page.request, '/api/file?path=' + file, { data: JSON.stringify({ version: 1, units: [{ name: 'once', argv: ['sh', '-c', `echo once >> ${base}/count`] }] }) })).ok()).toBe(true);
  const host = { host: randomUUID(), proof: secret() };
  const joined = await loginAction(page.request, { op: 'join', ...host });
  const member = { session: joined.id, ...host };
  const owned = await loginAction(page.request, { op: 'claim', member, generation: joined.generation });
  await loginAction(page.request, { op: 'configure', member, generation: owned.generation, file });
  await loginAction(page.request, { op: 'leave', member });
  try {
    await page.goto('/login.html?target=shell'); await expect(page.getByRole('button', { name: 'Continue as guest', exact: true })).toBeEnabled();
    expect((await sys(page.request, [{ stat: { path: base + '/count' } }]))[0].err?.errno).toBe('ENOENT');
    await page.getByRole('button', { name: 'Continue as guest', exact: true }).click(); await expect(input(page)).toBeEnabled({ timeout: 30_000 });
    await expect.poll(async () => (await loginAction(page.request, { op: 'inspect' })).startup.status, { timeout: 30_000 }).toBe(0);
    expect(await (await page.request.get('/api/file?path=' + base + '/count')).text()).toBe('once\n');
    await page.reload(); await expect(input(page)).toBeEnabled({ timeout: 30_000 });
    expect((await loginAction(page.request, { op: 'inspect' })).startup.status).toBe(0);
    expect(await (await page.request.get('/api/file?path=' + base + '/count')).text()).toBe('once\n'); await end(page).click();
  } finally { await rmrf(page.request, base); }
});

test('short mobile viewports can scroll the greeter and run the selected shell', async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 380 }); await page.goto('/login.html?target=shell');
  await page.getByLabel('Password', { exact: true }).click();
  expect(await page.locator('.greeter').evaluate(element => element.scrollTop)).toBeGreaterThan(0);
  const box = await page.getByLabel('Password', { exact: true }).boundingBox();
  expect(box.y).toBeGreaterThanOrEqual(0); expect(box.y + box.height).toBeLessThanOrEqual(380);
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(375);
  await page.screenshot({ path: '/home/ai/os-session-targets-validation/greeter-mobile.png' });
  await page.getByRole('button', { name: 'Continue as guest', exact: true }).click();
  await expect(input(page)).toBeEnabled({ timeout: 30_000 }); await command(page, 'echo mobile-ok', /\nmobile-ok\n/); await end(page).click();
});

test('missing browser isolation offers a desktop fallback without starting a kernel or shell', async ({ page }) => {
  const execution = []; page.on('request', request => { if (/client-kernel|usr\/bin/.test(request.url())) execution.push(request.url()); });
  await page.route('**/shell', async route => {
    const response = await route.fetch(); const headers = response.headers();
    delete headers['cross-origin-opener-policy']; delete headers['cross-origin-embedder-policy'];
    await route.fulfill({ response, headers });
  });
  await page.goto('/shell'); expect(await page.evaluate(() => crossOriginIsolated)).toBe(false);
  await expect(page.locator('#app')).toContainText('Interactive shells require');
  await expect(page.getByRole('link', { name: 'Open the desktop' })).toHaveAttribute('href', '/');
  expect(execution).toEqual([]); await expect(input(page)).toHaveCount(0);
});

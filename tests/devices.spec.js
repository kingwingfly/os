import { test, expect, request as playwrightRequest } from './test.js';
import { api, cloudAuth, mkdirp, rmrf } from './sys.js';
import { browse, cloudSignIn, cloudSignOut, cloudStatus, pageCall, pageMkdirp, pagePut, pageRmrf } from './ui.js';

const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const rootPassword = process.env.OS_TEST_ADMIN_PASSWORD || process.env.OS_PASSWORD;
const file = path => '/api/file?path=' + encodeURIComponent(path);
const CHUNK = 8 * 1024 * 1024;
let sequence = 0;
const address = name => `devices-${name}-${Date.now()}-${++sequence}`;

// A cloud-connected device: a browser context of its own with explicit Cloud Sign-In mounted at /mnt/cloud.
async function device(browser, username = 'root', password = rootPassword) {
  const context = await browser.newContext({ extraHTTPHeaders: { 'CF-Connecting-IP': address(username) } });
  const page = await context.newPage();
  await page.goto(origin + '/');
  await page.waitForFunction(() => Boolean(window.os?.cloudSignIn && window.os?.exec));
  await expect(page.locator('.cloud-panel-trigger')).toContainText('Local: user · Cloud: Signed out', { timeout: 20_000 });
  const status = await cloudSignIn(page, username, password);
  expect(status.signed_in).toBe(true);
  await expect(page.locator('.cloud-panel-trigger')).toContainText(`Local: user · Cloud: ${username}`, { timeout: 20_000 });
  return { context, page };
}
const busy = page => page.locator('.terminal-panel:not([hidden]) .command-line');
const transcript = page => page.locator('.terminal-panel:not([hidden]) .transcript');
async function run(page, text) {
  await expect(busy(page)).toHaveAttribute('data-state', 'idle');
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  await input.fill(text); await input.press('Enter');
}
// What an upload in the Files says.
const progress = page => page.getByRole('status', { name: 'Upload progress' });
async function upload(page, name, buffer) {
  const chooser = page.waitForEvent('filechooser');
  await page.getByRole('button', { name: 'Upload' }).click();
  await (await chooser).setFiles({ name, mimeType: 'application/octet-stream', buffer });
}

test('two devices of one account never send one upload at once, and one stopping leaves the other going', async ({ browser }) => {
  test.setTimeout(120_000);
  const root = await playwrightRequest.newContext({ baseURL: origin, extraHTTPHeaders: { Origin: origin, 'CF-Connecting-IP': address('api') } });
  expect((await api(root, 'login', { data: { password: rootPassword } })).ok()).toBe(true);
  const base = '/devices-' + Date.now().toString(36);
  const cloudBase = '/mnt/cloud' + base;
  const a = await device(browser), b = await device(browser);
  try {
    await mkdirp(root, base);
    for (const { page } of [a, b]) await browse(page, cloudBase);
    const bytes = Buffer.alloc(CHUNK + 1000);
    for (let i = 0; i < bytes.length; i += 4) bytes.writeUInt32LE(i, i);
    // Pause A's chunked uploads until B has attempted to upload the same file;
    // B must be refused without interfering with A's in-flight upload.
    let release; const released = new Promise(resolve => { release = resolve; });
    await a.page.route('**/api/pwrite?**', async route => { await released; await route.continue().catch(() => {}); });
    await upload(a.page, 'data.bin', bytes);
    await expect(progress(a.page)).toContainText(/data\.bin · \d+%/, { timeout: 30_000 });
    await upload(b.page, 'data.bin', bytes);
    await expect(progress(b.page)).toContainText(/✕ data\.bin: .*(already exists|another tab or device)/, { timeout: 30_000 });
    release();
    await expect(progress(a.page)).toContainText('✓ data.bin', { timeout: 60_000 });
    expect(Buffer.compare(await (await root.get(file(base + '/data.bin'), { headers: { 'Accept-Encoding': 'identity' } })).body(), bytes)).toBe(0);
    await expect(a.page.locator('.files .file').filter({ hasText: 'data.bin' })).toContainText('KB');
  } finally {
    await rmrf(root, base).catch(() => {});
    await a.context.close(); await b.context.close(); await root.dispose();
  }
});

test('tabs of one instance follow local account switches while separate browser windows stay isolated, and remote cloud sign-out stays decoupled from local accounts', async ({ browser }) => {
  test.setTimeout(120_000);
  const name = 'dev' + Date.now().toString(36).slice(-5);
  const password = 'device-password-' + Date.now();
  // Register a cloud user via /api/cloud-auth/register for the remote device context.
  const reg = await playwrightRequest.newContext({ baseURL: origin, extraHTTPHeaders: { Origin: origin, 'CF-Connecting-IP': address('reg') } });
  expect((await cloudAuth(reg, 'register', { data: { username: name, password, create_home: true } })).ok()).toBe(true);
  await reg.dispose();

  const phone = await device(browser, name, password);
  // Two windows in one browser context boot isolated dedicated client-kernel Workers (ForkOnBusy);
  // two terminal tabs inside one window share that instance's local account.
  const desktop = await browser.newContext({ extraHTTPHeaders: { 'CF-Connecting-IP': address('desktop') } });
  const first = await desktop.newPage(), second = await desktop.newPage();
  try {
    for (const page of [first, second]) {
      await page.goto(origin + '/');
      await expect(page.locator('.cloud-panel-trigger')).toContainText('Local: user · Cloud: Signed out', { timeout: 20_000 });
    }
    // Open a second terminal tab in `first`, switch back to tab 1, create a local user and switch to it.
    await first.getByRole('button', { name: 'New tab' }).click();
    await first.getByRole('tab').nth(0).click();
    await pageCall(first, { useradd: { name, password, short_password: true, create_home: true } }, { sudo: true });
    await run(first, 'sudo -u ' + name);
    await expect(first.locator('.cloud-panel-trigger')).toContainText(`Local: ${name}`);
    // Tab 2 inside `first` follows immediately; separate browser window `second` stays isolated as `user`.
    await first.getByRole('tab').nth(1).click();
    await expect(transcript(first)).toContainText(`Account changed to ${name} in another tab`);
    await expect(second.locator('.cloud-panel-trigger')).toContainText('Local: user · Cloud: Signed out');

    // Logging out in tab 1 returns both tabs of `first` to default local `user`.
    await first.getByRole('tab').nth(0).click();
    await run(first, 'logout');
    await expect(first.locator('.cloud-panel-trigger')).toContainText('Local: user');
    await first.getByRole('tab').nth(1).click();
    await expect(transcript(first)).toContainText('Account changed to user in another tab');

    // On `phone`, remote Cloud session ending elsewhere invalidates the server session without mutating local `user`.
    expect((await cloudAuth(phone.context.request, 'logout')).ok()).toBe(true);
    const serverStatus = await (await cloudAuth(phone.context.request, 'status')).json();
    expect(serverStatus.signed_in).toBe(false);
    await cloudSignOut(phone.page);
    await expect(phone.page.locator('.cloud-panel-trigger')).toContainText('Local: user · Cloud: Signed out');
    expect((await cloudStatus(phone.page)).signed_in).toBe(false);
  } finally {
    await pageCall(first, { userdel: { name, remove: true } }, { sudo: true }).catch(() => {});
    await phone.context.close(); await desktop.close();
  }
});

test('the file panel dims what the account may not open, and says why when clicked, with the terminal hidden', async ({ page }) => {
  const base = '/home/user/panel-' + Date.now().toString(36);
  await page.goto(origin + '/');
  await expect(busy(page)).toHaveAttribute('data-state', 'idle');
  try {
    await pageMkdirp(page, base, 0o755);
    await pageMkdirp(page, base + '/locked', 0o700, { sudo: true });
    await pageCall(page, { chmod: { path: base + '/locked', mode: 0o700 } }, { sudo: true });
    await pageMkdirp(page, base + '/open', 0o755, { sudo: true });
    await pagePut(page, base + '/secret.txt', 'no', { mode: 0o600, sudo: true });
    await pageCall(page, { chmod: { path: base + '/secret.txt', mode: 0o600 } }, { sudo: true });
    await pagePut(page, base + '/notes.txt', 'yes', { mode: 0o644, sudo: true });
    await pageCall(page, { symlink: { target: base + '/nowhere', path: base + '/dangling' } }, { sudo: true });

    await run(page, 'cd ' + base);
    await browse(page, base);
    const entry = name => page.locator('.files .file').filter({ hasText: name });
    await expect(entry('locked/')).toHaveClass(/denied/); await expect(entry('secret.txt')).toHaveClass(/denied/);
    await expect(entry('open/')).not.toHaveClass(/denied/); await expect(entry('notes.txt')).not.toHaveClass(/denied/);
    // The executable reports the real modes; Files owns its permission hints and icons.
    await run(page, 'ls -l');
    await expect(transcript(page).locator('pre').last()).toContainText('drwx------');
    await expect(transcript(page).locator('pre').last()).toContainText('-rw-------');
    // A click on one says why, in the panel.
    // aria-disabled, which Playwright will not click; people may, and are told why.
    await entry('secret.txt').click({ force: true });
    await expect(page.locator('.file-notice')).toContainText('Permission denied: secret.txt is -rw------- root:root');
    await expect(page.locator('#viewer')).not.toBeVisible();
    // What it may open opens; and an error of what it did shows there too.
    await entry('notes.txt').click();
    await expect(page.locator('#viewer')).toBeVisible();
    await page.getByRole('button', { name: 'Close preview' }).click();
    await expect(page.locator('.file-notice')).toBeEmpty();
    await entry('dangling').click();
    await expect(page.locator('.file-notice')).toContainText('No such file or directory');
  } finally {
    await pageRmrf(page, base, { sudo: true }).catch(() => {});
  }
});

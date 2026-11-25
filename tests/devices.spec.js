import { test, expect, request as playwrightRequest } from './test.js';
import { api, mkdirp, rmrf } from './sys.js';
import {
  browse,
  cloudSignIn,
  execCmd,
  pageCall,
  pageMkdirp,
  pagePut,
  pageRmrf,
  waitForDesktopReady,
} from './ui.js';

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

test('the file panel dims what the account may not open, and says why when clicked, with the terminal hidden', async ({ page }) => {
  const base = '/home/user/panel-' + Date.now().toString(36);
  await page.goto(origin + '/');
  await waitForDesktopReady(page);
  try {
    await pageMkdirp(page, base, 0o755);
    await pageMkdirp(page, base + '/locked', 0o700, { sudo: true });
    await pageCall(page, { chmod: { path: base + '/locked', mode: 0o700 } }, { sudo: true });
    await pageMkdirp(page, base + '/open', 0o755, { sudo: true });
    await pagePut(page, base + '/secret.txt', 'no', { mode: 0o600, sudo: true });
    await pageCall(page, { chmod: { path: base + '/secret.txt', mode: 0o600 } }, { sudo: true });
    await pagePut(page, base + '/notes.txt', 'yes', { mode: 0o644, sudo: true });
    await pageCall(page, { symlink: { target: base + '/nowhere', path: base + '/dangling' } }, { sudo: true });

    await browse(page, base);
    const entry = name => page.locator('.files .file').filter({ hasText: name });
    await expect(entry('locked/')).toHaveClass(/denied/); await expect(entry('secret.txt')).toHaveClass(/denied/);
    await expect(entry('open/')).not.toHaveClass(/denied/); await expect(entry('notes.txt')).not.toHaveClass(/denied/);
    // The executable reports the real modes; Files owns its permission hints and icons.
    const listed = await execCmd(page, ['ls', '-l', base]);
    expect(listed.status).toBe(0);
    expect(listed.stdout).toContain('drwx------');
    expect(listed.stdout).toContain('-rw-------');
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

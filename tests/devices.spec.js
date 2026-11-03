import { test, expect, request as playwrightRequest } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { api, mkdirp, program, put, rmrf } from './sys.js';
// The Files go to `path` of their own: its location typed (files.rs).
async function browse(page, path) {
  const location = page.getByRole('textbox', { name: 'Location' });
  await location.fill(path); await location.press('Enter');
  await expect(location).toHaveValue(path);
}
const origin = process.env.TERMINAL_TEST_URL || 'http://127.0.0.1:8787';
const rootPassword = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const file = path => '/api/file?path=' + encodeURIComponent(path);
const CHUNK = 8 * 1024 * 1024;
let sequence = 0;
const address = name => `devices-${name}-${Date.now()}-${++sequence}`;

// A device: a browser context of its own, signed in through the API, showing the terminal.
async function device(browser, username = 'root', password = rootPassword) {
  const context = await browser.newContext({ extraHTTPHeaders: { 'CF-Connecting-IP': address(username) } });
  expect((await api(context.request, 'login', { headers: { Origin: origin }, data: { username, password } })).ok()).toBe(true);
  const page = await context.newPage(); await page.goto(origin + '/');
  await expect(page.locator('.lock')).toContainText(username);
  return { context, page };
}
const busy = page => page.locator('.terminal-panel:not([hidden]) .busy');
const transcript = page => page.locator('.terminal-panel:not([hidden]) .transcript');
async function run(page, text) {
  await expect(busy(page)).toHaveText('↵');
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  await input.fill(text); await input.press('Enter');
}
// What an upload in the Files says.
const progress = page => page.getByRole('status', { name: 'Upload progress' });
async function upload(page, name, buffer) {
  const chooser = page.waitForEvent('filechooser');
  await page.getByRole('button', { name: '↑ Upload files' }).click();
  await (await chooser).setFiles({ name, mimeType: 'application/octet-stream', buffer });
}

test('two devices of one account never send one upload at once, and one stopping leaves the other going', async ({ browser }) => {
  const root = await playwrightRequest.newContext({ baseURL: origin, extraHTTPHeaders: { Origin: origin, 'CF-Connecting-IP': address('api') } });
  expect((await api(root, 'login', { data: { password: rootPassword } })).ok()).toBe(true);
  const base = '/devices-' + Date.now().toString(36);
  const a = await device(browser), b = await device(browser);
  try {
    await mkdirp(root, base);
    for (const { page } of [a, b]) await browse(page, base);
    const bytes = Buffer.alloc(CHUNK * 2 + 1000);
    for (let i = 0; i < bytes.length; i += 4) bytes.writeUInt32LE(i, i);
    // A's chunks wait until B has tried, so that A is still sending however long B takes to hash
    // the file; B chooses the same file meanwhile, and is told to wait.
    let release; const released = new Promise(resolve => { release = resolve; });
    await a.page.route('**/api/pwrite?**', async route => { await released; await route.continue().catch(() => {}); });
    await upload(a.page, 'data.bin', bytes);
    await expect(progress(a.page)).toContainText(/data\.bin · \d+%/, { timeout: 30_000 });
    await upload(b.page, 'data.bin', bytes);
    await expect(progress(b.page)).toContainText('✕ data.bin: ' + base + '/data.bin is being uploaded from another tab or device', { timeout: 30_000 });
    release();
    await expect(progress(a.page)).toContainText('✓ data.bin', { timeout: 60_000 });
    expect(Buffer.compare(await (await root.get(file(base + '/data.bin'), { headers: { 'Accept-Encoding': 'identity' } })).body(), bytes)).toBe(0);
    // A's file panel showed the same progress as its upload line, as both count what arrived.
    await expect(a.page.locator('.files .file').filter({ hasText: 'data.bin' })).toContainText('KB');
  } finally {
    await rmrf(root, base);
    await a.context.close(); await b.context.close(); await root.dispose();
  }
});

test('a page hears when its session ends elsewhere, and windows of one browser follow each other', async ({ browser }) => {
  const root = await playwrightRequest.newContext({ baseURL: origin, extraHTTPHeaders: { Origin: origin, 'CF-Connecting-IP': address('api') } });
  expect((await api(root, 'login', { data: { password: rootPassword } })).ok()).toBe(true);
  const name = 'dev' + Date.now().toString(36), password = 'device-password-' + Date.now();
  const command = args => program(root, args);
  expect((await command(['useradd', '-m', name])).ok()).toBe(true);
  expect((await api(root, 'passwd', { data: { username: name, password } })).ok()).toBe(true);
  const phone = await device(browser, name, password);
  // Two windows of one browser, as guest; one signs in, and the other follows at once.
  const desktop = await browser.newContext({ extraHTTPHeaders: { 'CF-Connecting-IP': address('desktop') } });
  const first = await desktop.newPage(), second = await desktop.newPage();
  try {
    for (const page of [first, second]) { await page.goto(origin + '/'); await expect(page.locator('.lock')).toContainText('guest'); }
    await run(first, 'su ' + name);
    await first.getByLabel('Password', { exact: true }).fill(password); await first.locator('#auth button[type=submit]').click();
    await expect(first.locator('.lock')).toContainText(name);
    await expect(second.locator('.lock')).toContainText(name);
    await expect(transcript(second)).toContainText(`Account changed to ${name} in another window`);
    // Another device changes the password: every session of the account ends, and its pages
    // say so and show guest, before anything is typed there.
    expect((await api(root, 'passwd', { data: { username: name, password: password + '-new' } })).ok()).toBe(true);
    for (const page of [phone.page, first, second]) {
      await expect(page.locator('.lock')).toContainText('guest');
      await expect(transcript(page)).toContainText('Signed out: this session ended elsewhere');
    }
  } finally {
    await command(['userdel', '-r', name]);
    await phone.context.close(); await desktop.close(); await root.dispose();
  }
});

test('the file panel dims what the account may not open, and says why when clicked, with the terminal hidden', async ({ browser }) => {
  const root = await playwrightRequest.newContext({ baseURL: origin, extraHTTPHeaders: { Origin: origin, 'CF-Connecting-IP': address('api') } });
  expect((await api(root, 'login', { data: { password: rootPassword } })).ok()).toBe(true);
  const base = '/panel-' + Date.now().toString(36);
  const command = args => program(root, args);
  const context = await browser.newContext({ extraHTTPHeaders: { 'CF-Connecting-IP': address('guest') } });
  const page = await context.newPage();
  try {
    for (const dir of ['', '/locked', '/open']) await mkdirp(root, base + dir);
    expect((await put(root, file(base + '/secret.txt'), { data: 'no' })).status()).toBe(201);
    expect((await put(root, file(base + '/notes.txt'), { data: 'yes' })).status()).toBe(201);
    for (const args of [['chmod', '700', base + '/locked'], ['chmod', '600', base + '/secret.txt'], ['ln', '-s', base + '/nowhere', base + '/dangling']]) expect((await command(args)).ok()).toBe(true);
    await page.goto(origin + '/');
    await run(page, 'cd ' + base);
    await browse(page, base);
    const entry = name => page.locator('.files .file').filter({ hasText: name });
    await expect(entry('locked/')).toHaveClass(/denied/); await expect(entry('secret.txt')).toHaveClass(/denied/);
    await expect(entry('open/')).not.toHaveClass(/denied/); await expect(entry('notes.txt')).not.toHaveClass(/denied/);
    // ls in the terminal dims them too.
    await run(page, 'ls'); await expect(transcript(page).locator('.entry-denied')).toHaveCount(2);
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
    await rmrf(root, base);
    await context.close(); await root.dispose();
  }
});

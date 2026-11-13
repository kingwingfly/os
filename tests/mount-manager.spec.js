import { test, expect } from './storage-test.js';
import { readFile, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn, execFileSync } from 'node:child_process';
import { createInterface } from 'node:readline';
import { api } from './sys.js';

const app = page => page.locator('#window-mounts');
async function ready(page) { await page.goto('/'); await expect(page.locator('.files-mounts')).toBeVisible(); }
async function open(page, pane = 'mounted') {
  await page.evaluate(() => window.os.localMounts());
  await expect(app(page)).toBeVisible();
  if (pane !== 'mounted') await app(page).getByRole('tab', { name: { add: 'Add mount', publish: 'Publish', connect: 'Connect' }[pane], exact: true }).click();
}
async function storage(page) {
  await open(page, 'add'); await app(page).locator('[name=kind]').selectOption('storage');
  await app(page).getByLabel('User write', { exact: true }).check();
  await app(page).getByRole('button', { name: 'Mount storage', exact: true }).click();
  await expect(app(page).locator('[data-selected]')).toHaveText('/mnt/local/project');
}

test('the browser picker retains a live directory handle and writes back to it', async ({ page, browserName }) => {
  test.skip(browserName !== 'chromium', 'Host directory handle transport is a Chromium feature; OPFS uses worker acquisition elsewhere.');
  await ready(page);
  // The native OS dialog is outside Playwright. Substitute only its selection,
  // using a real browser directory handle so cloning and worker I/O remain real.
  await page.evaluate(async () => {
    window.pickedFolder = await (await navigator.storage.getDirectory()).getDirectoryHandle('picker-contract', { create: true });
    window.writePicked = async text => { const f = await pickedFolder.getFileHandle('note', { create: true }), w = await f.createWritable(); await w.write(text); await w.close(); };
    await writePicked('first');
    window.showDirectoryPicker = async options => { window.pickerOptions = options; window.pickerActivated = navigator.userActivation.isActive; return pickedFolder; };
  });
  await open(page, 'add'); await app(page).getByLabel('User write', { exact: true }).check();
  await app(page).getByRole('button', { name: 'Choose folder…', exact: true }).click();
  await expect(app(page).locator('[data-selected]')).toHaveText('/mnt/local/project');
  expect(await page.evaluate(() => ({ options: pickerOptions, activated: pickerActivated }))).toEqual({ options: { mode: 'readwrite', id: 'os-host-folder' }, activated: true });
  await expect(app(page).locator('.mount-table')).toContainText('Host folder · browser');
  const read = () => page.evaluate(async () => (await fetch('/api/file?path=/mnt/local/project/note')).text());
  expect(await read()).toBe('first'); await page.evaluate(() => writePicked('external edit')); expect(await read()).toBe('external edit');
  const results = await page.evaluate(async () => (await (await fetch('/api/sys', { method: 'POST', body: JSON.stringify({ calls: [
    { open: { path: '/mnt/local/project/note', flags: 0o1001 } },
    { pwrite: { fd: { ref: 0 }, index: 0, data: btoa('from OS') } }, { close: { fd: { ref: 0 } } },
  ] }) })).json()).results);
  expect(results.every(result => !result.err)).toBe(true);
  expect(await page.evaluate(async () => (await (await pickedFolder.getFileHandle('note')).getFile()).text())).toBe('from OS');
});

test('picker cancellation and permission denial never downgrade to the helper', async ({ page }) => {
  await ready(page);
  await page.evaluate(() => { window.pickerError = 'AbortError'; window.showDirectoryPicker = async () => { throw new DOMException('Folder access denied', window.pickerError); }; });
  await open(page, 'add');
  const choose = app(page).getByRole('button', { name: 'Choose folder…', exact: true });
  await choose.click(); await expect(choose).toBeEnabled(); await expect(app(page).locator('.mount-notice')).toHaveText('');
  await page.evaluate(() => { window.pickerError = 'NotAllowedError'; }); await choose.click();
  await expect(app(page).locator('.mount-notice')).toContainText('Folder access denied');
  await expect(app(page).locator('[data-helper]')).toBeHidden();
  expect(await page.evaluate(() => window.os.localMountList())).toEqual([]);
});

test('a real host directory handle sees host changes without importing files', async ({ page, browserName, context }) => {
  test.skip(browserName !== 'chromium', 'Chromium provides host directory handles and CDP drag selection.');
  const directory = await mkdtemp(join(tmpdir(), 'os-browser-host-'));
  try {
    await writeFile(join(directory, 'note'), 'host original'); await ready(page);
    // CDP can deliver a real OS directory through drag-and-drop, avoiding a
    // native dialog while retaining real host-backed handles and permissions.
    await page.evaluate(() => {
      addEventListener('dragover', event => event.preventDefault());
      addEventListener('drop', event => { event.preventDefault(); window.hostFolder = event.dataTransfer.items[0].getAsFileSystemHandle(); }, { once: true });
    });
    const cdp = await context.newCDPSession(page);
    for (const type of ['dragEnter', 'dragOver', 'drop']) await cdp.send('Input.dispatchDragEvent', { type, x: 500, y: 300, data: { items: [], files: [directory], dragOperationsMask: 1 } });
    await page.evaluate(async () => { const handle = await hostFolder; window.showDirectoryPicker = async () => handle; });
    await open(page, 'add'); await app(page).getByRole('button', { name: 'Choose folder…', exact: true }).click();
    await expect(app(page).locator('[data-selected]')).toHaveText('/mnt/local/project');
    const read = () => page.evaluate(async () => (await fetch('/api/file?path=/mnt/local/project/note')).text());
    expect(await read()).toBe('host original');
    await writeFile(join(directory, 'note'), 'host changed after mounting');
    expect(await read()).toBe('host changed after mounting');
    await app(page).getByRole('button', { name: 'Unmount', exact: true }).click();
    await expect(app(page).locator('[data-empty]')).toBeVisible();
    expect(await page.evaluate(async () => (await fetch('/api/file?path=/mnt/local/project/note')).ok)).toBe(false);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('an unsupported picker offers the one helper flow', async ({ page }) => {
  await ready(page);
  await page.evaluate(() => { window.showDirectoryPicker = async () => { throw new DOMException('Unsupported', 'NotSupportedError'); }; });
  await open(page, 'add'); await app(page).getByRole('button', { name: 'Choose folder…', exact: true }).click();
  await expect(app(page).getByLabel('Helper URL', { exact: true })).toBeVisible();
  await expect(app(page).locator('[name=kind] option')).toHaveText(['Host folder', 'Browser storage']);
  await expect(app(page).locator('[data-connect]')).toHaveText('Connect folder');
});

test('a pending picker is discarded when the login changes', async ({ page }) => {
  await ready(page);
  await page.evaluate(() => { window.showDirectoryPicker = () => new Promise(resolve => { window.finishPicker = resolve; }); });
  await open(page, 'add'); await app(page).getByRole('button', { name: 'Choose folder…', exact: true }).click();
  await page.waitForFunction(() => window.finishPicker);
  await page.evaluate(() => { dispatchEvent(new Event('os:login-changed')); finishPicker({ kind: 'directory' }); });
  await expect(app(page).locator('[data-connect]')).toBeEnabled();
  expect(await page.evaluate(() => window.os.localMountList())).toEqual([]);
  await expect(app(page).locator('.mount-notice')).toHaveText('Session changed. Refresh to view its mounts.');
});

test('browsers without a picker mount the original folder through the helper', async ({ page }) => {
  const directory = await mkdtemp(join(tmpdir(), 'os-mount-ui-'));
  const binary = process.env.OS_LOCAL_HELPER_BINARY || join(JSON.parse(execFileSync('cargo', ['metadata', '--no-deps', '--format-version=1'], { encoding: 'utf8' })).target_directory, 'debug/os-local-helper');
  const helper = spawn(binary, ['--root', directory, '--origin', process.env.OS_TEST_URL || 'http://127.0.0.1:8787', '--write'], { stdio: ['ignore', 'pipe', 'pipe'] });
  try {
    const connection = await new Promise((resolve, reject) => {
      const lines = createInterface({ input: helper.stdout }), timer = setTimeout(() => reject(new Error('helper startup timeout')), 5000);
      lines.once('line', line => { clearTimeout(timer); lines.close(); resolve(JSON.parse(line)); });
      helper.once('error', failure => { clearTimeout(timer); reject(failure); });
    });
    await ready(page); await page.evaluate(() => { window.showDirectoryPicker = undefined; }); await open(page, 'add');
    await app(page).getByLabel('Helper URL', { exact: true }).fill(connection.url);
    await app(page).getByLabel('Token', { exact: true }).fill(connection.token);
    await app(page).getByLabel('User write', { exact: true }).check(); await app(page).getByLabel('User execute', { exact: true }).uncheck();
    await app(page).getByRole('button', { name: 'Connect folder', exact: true }).click();
    await expect(app(page).locator('[data-selected]')).toHaveText('/mnt/local/project');
    await expect(app(page).locator('.mount-table')).toContainText('Host folder · helper');
    await writeFile(join(directory, 'note'), 'created after mount');
    expect(await page.evaluate(async () => (await fetch('/api/file?path=/mnt/local/project/note')).text())).toBe('created after mount');
    expect(await page.evaluate(async () => (await (await fetch('/api/sys', { method: 'POST', body: JSON.stringify({ calls: [
      { open: { path: '/mnt/local/project/note', flags: 0o1001 } },
      { pwrite: { fd: { ref: 0 }, index: 0, data: btoa('OS edit') } }, { close: { fd: { ref: 0 } } },
    ] }) })).json()).results.every(result => !result.err))).toBe(true);
    expect(await readFile(join(directory, 'note'), 'utf8')).toBe('OS edit');
  } finally {
    helper.kill('SIGTERM'); if (helper.exitCode === null && helper.signalCode === null) await new Promise(resolve => helper.once('exit', resolve));
    await rm(directory, { recursive: true, force: true });
  }
});

test('Mounts is a desktop window with separate panes, scoped rwx grants and normal close controls', async ({ page }) => {
  await ready(page); await page.locator('.files-mounts').click();
  await expect(app(page)).toBeVisible(); await expect(page.locator('dialog.local-mounts')).toHaveCount(0);
  await app(page).getByRole('tab', { name: 'Add mount', exact: true }).click();
  await expect(app(page).locator('[name=kind]')).toHaveValue('host');
  await expect(app(page).locator('[name=kind] option')).toHaveText(['Host folder', 'Browser storage']);
  const direct = await page.evaluate(() => typeof window.showDirectoryPicker === 'function');
  await expect(app(page).locator('[data-helper]')).toBeVisible({ visible: !direct });
  await expect(app(page).getByLabel('User write', { exact: true })).toBeEnabled();
  await expect(app(page).locator('[data-connect]')).toHaveText(direct ? 'Choose folder…' : 'Connect folder');
  await storage(page);
  await expect(app(page).locator('.mount-table')).toContainText('rwx------');
  await expect(app(page).getByRole('button', { name: 'Activate package', exact: true })).toHaveCount(0);
  await app(page).getByRole('button', { name: 'Close Mounts', exact: true }).click();
  await expect(app(page)).toBeHidden();
  expect(await page.evaluate(() => window.os.localMountList())).toHaveLength(1);
  await open(page); await app(page).getByRole('button', { name: 'Open in Files', exact: true }).click();
  await expect(page.locator('#window-files')).toHaveClass(/window-focused/);
  await expect(page.locator('#window-files').getByLabel('Location', { exact: true })).toHaveValue('/mnt/local/project');
  await open(page); await app(page).getByRole('button', { name: 'Unmount', exact: true }).click();
  await expect(app(page).locator('[data-empty]')).toBeVisible();
  expect(await page.evaluate(() => window.os.localMountList())).toHaveLength(0);
});

test('Mounts keeps its fields inside the frame and separates mounted filesystems from sharing', async ({ page }) => {
  await ready(page); await open(page, 'add');
  await app(page).getByRole('button', { name: 'Maximize Mounts', exact: true }).click();
  const margins = await page.locator('.mount-content').evaluate(element => { const r = element.getBoundingClientRect(), child = element.querySelector('[data-view=add]').getBoundingClientRect(); return { left: child.left - r.left, right: r.right - child.right }; });
  expect(margins.left).toBeGreaterThanOrEqual(18); expect(margins.right).toBeGreaterThanOrEqual(18);
  await page.setViewportSize({ width: 390, height: 844 });
  for (const name of ['Add mount', 'Mounted', 'Connect', 'Publish']) {
    await app(page).getByRole('tab', { name, exact: true }).click();
    expect(await page.locator('#mount-manager').evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
  }
  await expect(app(page).locator('[data-view=mounted]')).toBeHidden();
  await expect(app(page).locator('[data-view=publish]')).toBeVisible();
});

test('a selected package activates into a separate immutable private mount', async ({ page }) => {
  await ready(page);
  await page.evaluate(async () => {
    const bytes = new TextEncoder().encode('private package'), hash = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(b => b.toString(16).padStart(2, '0')).join('');
    const directory = path => ({ path, uid: 0, gid: 0, mode: 0o755, node: { type: 'directory' } });
    const image = { format: 'os.image', version: 1, kind: 'sysext', name: 'package', revision: '1', abi: 1, level: 1, features: [], provenance: {}, entries: [directory('/'), directory('/usr'), directory('/usr/share'), { path: '/usr/share/readme', uid: 0, gid: 0, mode: 0o644, node: { type: 'file', sha256: hash, size: bytes.length } }] };
    await window.os.mountLocal({ name: 'package', cloud: false, execute: false, files: [new File([JSON.stringify(image)], 'manifest.json'), new File([bytes], 'blobs/' + hash)] });
  });
  await open(page);
  await app(page).getByLabel('Extension name', { exact: true }).fill('tools');
  await app(page).getByRole('button', { name: 'Activate package', exact: true }).click();
  await expect(app(page).locator('[data-selected]')).toHaveText('/opt/private/tools');
  expect(await page.evaluate(async () => (await fetch('/api/file?path=/opt/private/tools/usr/share/readme')).text())).toBe('private package');
  await app(page).getByRole('button', { name: 'Deactivate', exact: true }).click();
  expect(await page.evaluate(async () => (await window.os.localMountList()).map(m => m.path))).toEqual(['/mnt/local/package']);
});

test('Publish and Connect are separate panes and mounting is explicit', async ({ page, context }) => {
  test.setTimeout(120000); const other = await context.newPage();
  try {
    await ready(page); await ready(other); await storage(page);
    await open(page, 'publish');
    await expect(app(page).locator('[data-shared-form]')).toBeHidden();
    await expect(app(page).getByText('Enroll device', { exact: true })).toHaveCount(0);
    await app(page).getByRole('button', { name: 'Publish', exact: true }).click();
    await expect(app(page).getByRole('button', { name: 'Stop publishing', exact: true })).toBeVisible();
    const address = await app(page).locator('[data-shares] input').inputValue();
    await expect(app(page).getByRole('button', { name: 'Copy address', exact: true })).toBeVisible();
    expect(await other.evaluate(() => window.os.localMountList())).toEqual([]);
    await open(other, 'connect');
    await expect(app(other).locator('[data-export-form]')).toBeHidden();
    const form = app(other).locator('[data-shared-form]');
    await form.getByLabel('Mount name', { exact: true }).fill('peer');
    await expect(form.locator('[data-shared-path]')).toHaveText('/mnt/shared/peer');
    await form.getByLabel('Export address', { exact: true }).fill(address);
    await form.getByRole('button', { name: 'Mount', exact: true }).click();
    await expect(app(other).locator('[data-selected]')).toHaveText('/mnt/shared/peer');
    await app(page).getByRole('button', { name: 'Stop publishing', exact: true }).click();
    await expect(app(page).locator('[data-shares]')).toContainText('No directories published.');
  } finally { await other.close(); }
});

test('Files gives its path room and keeps compact action buttons together', async ({ page }) => {
  await ready(page); const window = page.locator('#window-files');
  for (const width of [340, 270]) {
    await window.evaluate((element, width) => { element.style.minWidth = '0'; element.style.width = width + 'px'; }, width);
    const path = window.getByLabel('Location', { exact: true }), refresh = window.getByRole('button', { name: 'Refresh', exact: true }), upload = window.getByRole('button', { name: 'Upload', exact: true }), mounts = window.getByRole('button', { name: 'Mounts', exact: true });
    await expect(upload).toHaveAttribute('title', 'Upload'); await expect(mounts).toHaveAttribute('title', 'Mount and manage filesystems');
    const [p, r, u, m] = await Promise.all([path.boundingBox(), refresh.boundingBox(), upload.boundingBox(), mounts.boundingBox()]);
    expect(p.width).toBeGreaterThan(width - 151); expect(r.y).toBe(u.y); expect(u.y).toBe(m.y); expect(r.width).toBeLessThanOrEqual(34); expect(u.width).toBeLessThanOrEqual(34); expect(m.x + m.width).toBeLessThanOrEqual((await window.boundingBox()).x + width);
  }
});

test('Mounted displays current VFS permission bits after chmod', async ({ page }) => {
  await ready(page); await storage(page);
  const result = await page.evaluate(async () => (await (await fetch('/api/sys', { method: 'POST', body: JSON.stringify({ calls: [{ chmod: { path: '/mnt/local/project', mode: 0o750 } }] }) })).json()).results);
  expect(result[0].err).toBeUndefined();
  await app(page).locator('[data-action=refresh]').click();
  await expect(app(page).locator('.mount-table')).toContainText('rwxr-x---');
});

test('browser storage mounts alias existing files and unmount does not erase them', async ({ page }) => {
  await ready(page); await storage(page);
  await page.evaluate(async () => {
    const response = await fetch('/api/sys', { method: 'POST', body: JSON.stringify({ calls: [
      { open: { path: '/mnt/local/project/retained.txt', flags: 0o1101 } },
      { pwrite: { fd: { ref: 0 }, data: btoa('same filesystem') } },
      { close: { fd: { ref: 0 } } },
    ] }) });
    if ((await response.json()).results.some(result => result.err)) throw new Error('could not write mounted storage');
  });
  await open(page, 'add');
  await expect(app(page).locator('[data-source=storage]')).toContainText('same files');
  await app(page).locator('[data-add-form]').getByLabel('Mount name', { exact: true }).fill('alias');
  await app(page).getByRole('button', { name: 'Mount storage', exact: true }).click();
  await expect(app(page).locator('[data-selected]')).toHaveText('/mnt/local/alias');
  const read = () => page.evaluate(async () => (await fetch('/api/file?path=/mnt/local/alias/retained.txt')).text());
  expect(await read()).toBe('same filesystem');
  await page.evaluate(() => window.os.unmountLocal('/mnt/local/project'));
  expect(await read()).toBe('same filesystem');
  await page.evaluate(async () => {
    await window.os.unmountLocal('/mnt/local/alias');
    await window.os.mountLocal({ name: 'alias', storage: true, writable: false, execute: false, cloud: false });
  });
  expect(await read()).toBe('same filesystem');
});

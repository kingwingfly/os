import { test, expect } from './test.js';
import { openGui, launch, stop, exitOf, probe, documentWindow, pixelWindow, beginDrag, finishDrag } from './gui-harness.js';

const geometry = element => element.evaluate(el => window.guiSession.adapter.surfaces.get(Number(el.dataset.surfaceId)).rect);
const owner = element => element.getAttribute('data-pid').then(Number);
const surface = element => element.getAttribute('data-surface-id').then(Number);
const syscall = (page, call, sudo = false) => page.evaluate(async ([call, sudo]) =>
  (await window.guiSession.call('mount_sys', { calls: [call], sudo }))[0], [call, sudo]);
const input = (page, event) => page.evaluate(event => window.guiSession.call('gui_host_event', { event }), event);

test.beforeEach(async ({ page }) => { await openGui(page); });

test('G-01 seat devices require root, explicit grants and exclusive open descriptions', async ({ page }) => {
  for (const name of ['display', 'input']) {
    const path = '/dev/' + name;
    const { ok: info } = await syscall(page, { stat: { path } });
    expect([info.uid, info.gid, info.mode & 0o777]).toEqual([0, 0, 0o600]);
    expect((await syscall(page, { open: { path, flags: 0 } })).err.errno).toBe('EACCES');
    expect((await syscall(page, { open: { path, flags: 0 } }, true)).err.errno).toBe('EPERM');
    const { ok: handle } = await syscall(page, { open: { path, flags: 0o10000000 } });
    expect(handle.fd).toBeGreaterThanOrEqual(0);
    expect(await syscall(page, { close: { fd: handle.fd } })).toHaveProperty('ok');
  }
  const second = await exitOf(page, await launch(page, 'compositor'));
  expect(second.stderr).toContain('EBUSY');
  await expect(documentWindow(page)).toBeVisible();
});

test('G-02 negotiation refuses unknown versions and required capabilities', async ({ page }) => {
  for (const [versions, required, errno] of [[[33], [], 'EPROTONOSUPPORT'], [[1], ['future'], 'EOPNOTSUPP']]) {
    expect(await probe(page, { op: 'hello', versions, required })).toEqual({ op: 'error', errno });
  }
});

test('G-03 two processes render independently and input reaches its owning document', async ({ page }) => {
  const doc = documentWindow(page), pixel = pixelWindow(page);
  expect(await owner(pixel)).not.toBe(await owner(doc));
  const secondPid = await launch(page, 'gui-sample-doc');
  const second = page.locator('section[data-pid="' + secondPid + '"]');
  const editor = second.frameLocator('iframe').getByLabel('Document text');
  await editor.fill('private');
  await expect(second.frameLocator('iframe').locator('output')).toHaveText('7 characters');
  await expect(doc.frameLocator('iframe').getByLabel('Document text')).toHaveValue('');
  for (const req of [{ op: 'destroy' }, { op: 'set_title', title: 'foreign' }, { op: 'clipboard_read' }]) {
    expect(await probe(page, { ...req, surface_id: await surface(pixel) })).toEqual({ op: 'error', errno: 'EACCES' });
  }
  await expect(pixel.getByRole('img')).toHaveAccessibleName('Geometric color study');
  await pixel.locator('canvas').click();
  await expect(pixel.locator('[aria-live]')).toHaveText(/Pointer at/);
  await page.keyboard.press('x');
  await expect(pixel.locator('[aria-live]')).toHaveText('Key x');
  await editor.focus();
  await expect(second).toHaveAttribute('data-focused', 'true');
  const minimize = pixel.getByRole('button', { name: 'Minimize' });
  await minimize.focus();
  await page.keyboard.press('Delete');
  await expect(minimize).toBeFocused();
  await pixel.locator('canvas').press('y');
  await expect(pixel.locator('[aria-live]')).toHaveText('Key y');
});

test('G-04 privileged roles require a designated root socket peer', async ({ page }) => {
  for (const role of ['panel', 'background', 'launcher', 'lock', 'greeter']) {
    const spec = { role, kind: 'pixel', title: role, rect: { x: 0, y: 0, width: 160, height: 100 },
      min_size: { width: 1, height: 1 }, max_size: null, resizable: false };
    expect(await probe(page, { op: 'create_surface', spec })).toEqual({ op: 'error', errno: 'EPERM' });
  }
  await expect(page.locator('.modal-layer .surface')).toHaveCount(0);
});

test('G-05 content hash, unique origin, CSP and page credentials are enforced in the frame', async ({ page }) => {
  const iframe = documentWindow(page).locator('iframe');
  await expect(iframe).toHaveAttribute('sandbox', 'allow-scripts');
  const frame = await (await iframe.elementHandle()).contentFrame();
  const requests = [];
  page.on('request', req => { if (req.url().includes('/api/sys?gui-frame-probe')) requests.push(req.url()); });
  const result = await frame.evaluate(async () => {
    const results = {};
    const probes = {
      cookie: () => document.cookie, local: () => localStorage.length, session: () => sessionStorage.length,
      indexed: () => indexedDB.open('gui-isolation'), parent: () => parent.document,
      caches: () => caches.open('gui-isolation'), opfs: () => navigator.storage.getDirectory(),
      worker: () => navigator.serviceWorker.getRegistrations(), network: () => fetch('/api/sys?gui-frame-probe'),
    };
    for (const [name, fn] of Object.entries(probes)) {
      try { await fn(); results[name] = 'accessible'; } catch (e) { results[name] = e.name; }
    }
    return { origin: window.origin, csp: document.querySelector('meta[http-equiv]').content, probes: results };
  });
  expect(result.origin).toBe('null');
  expect(result.csp).toContain("connect-src 'none'");
  expect(result.csp).toMatch(/script-src 'sha256-[^']+' 'sha256-/);
  for (const name of ['cookie','local','session','indexed','parent']) expect(result.probes[name]).toBe('SecurityError');
  for (const name of ['caches','opfs','worker']) expect(['SecurityError','TypeError','ReferenceError']).toContain(result.probes[name]);
  expect(result.probes.network).toBe('TypeError');
  expect(requests).toEqual([]);
  const bad = await exitOf(page, await launch(page, 'gui-sample-doc', ['--sha256', '00'.repeat(32)]));
  expect(bad.stderr).toMatch(/EIO|EACCES/);
  await expect(page.locator('iframe')).toHaveCount(1);
});

test('G-05 application messages and synthetic input cannot grant a seat gesture', async ({ page }) => {
  const pid = await launch(page, 'gui-sample-doc'), doc = page.locator('section[data-pid="' + pid + '"]');
  const frame = doc.frameLocator('iframe');
  await expect(frame.getByLabel('Document text')).toBeVisible();
  const child = await (await doc.locator('iframe').elementHandle()).contentFrame();
  for (const [action, errno] of [['copy','EACCES'],['paste','EACCES'],['pick','EACCES'],['drag','EPERM']]) {
    await child.evaluate(action => {
      document.querySelector('output').textContent = '';
      dispatchEvent(new PointerEvent('pointerdown', { button: 0, pointerId: 1 }));
      dispatchEvent(new KeyboardEvent('keydown', { key: 'v', ctrlKey: true }));
      dispatchEvent(new Event('paste'));
      window.gui.send(JSON.stringify({ action, ...(['copy','drag'].includes(action) ? { text: 'sample' } : {}) }));
    }, action);
    await expect(frame.locator('output')).toHaveText(errno);
  }
  expect(await child.evaluate(() => window.gui.send('界'.repeat(1366)))).toBe('E2BIG');
  await expect(page.locator('.picker')).toHaveCount(0);
});

test('G-06 iframe focus, window cycling and tiling, lease move and resize clamps', async ({ page }) => {
  const doc = documentWindow(page), pixel = pixelWindow(page), editor = doc.frameLocator('iframe').getByLabel('Document text');
  await editor.click();
  await expect(doc).toHaveAttribute('data-focused', 'true');
  await page.keyboard.press('Alt+Backquote');
  await expect(pixel).toHaveAttribute('data-focused', 'true');
  await page.keyboard.press('Alt+Shift+Backquote');
  await expect(doc).toHaveAttribute('data-focused', 'true');
  await page.keyboard.press('Control+Alt+ArrowLeft');
  const bounds = await page.evaluate(() => window.guiSession.adapter.bounds());
  await expect.poll(() => geometry(doc)).toMatchObject({ x: 0, width: Math.floor(bounds.width / 2) });
  await page.keyboard.press('Control+Alt+ArrowDown');
  await expect.poll(() => geometry(doc)).toMatchObject({ width: 375 });
  for (const el of [pixel, doc]) await expect(el.locator('.resize')).toHaveCount(8);
  const start = await geometry(doc), p = await beginDrag(page, doc.locator('.title'));
  await page.mouse.move(p.x + 70, p.y + 65);
  await finishDrag(page);
  await expect.poll(() => geometry(doc)).toMatchObject({ x: start.x + 70, y: start.y + 65 });
  const q = await beginDrag(page, doc.locator('[data-edge="se"]'));
  await page.mouse.move(q.x - 650, q.y - 620); await finishDrag(page);
  await expect.poll(() => geometry(doc)).toMatchObject({ width: 160, height: 100 });
  await editor.focus();
  await expect(editor).toBeFocused();
  const beforeCancel = await geometry(doc), at = await beginDrag(page, doc.locator('.title'));
  await page.mouse.move(at.x + 52, at.y + 28);
  await expect.poll(() => doc.evaluate(el => new DOMMatrixReadOnly(getComputedStyle(el).transform).m41)).toBe(beforeCancel.x + 52);
  await expect(editor).toBeFocused();
  await page.keyboard.press('Escape');
  await page.waitForFunction(() => !window.guiSession.adapter.drag);
  await finishDrag(page);
  expect(await geometry(doc)).toEqual(beforeCancel);
  await expect.poll(() => doc.evaluate(el => new DOMMatrixReadOnly(getComputedStyle(el).transform).m41)).toBe(beforeCancel.x);
  await expect(doc).toHaveAttribute('data-focused', 'true');
});

test('G-07 CDP CJK composition preserves focus and accessible content spans the opaque frame', async ({ page, context }) => {
  const doc = documentWindow(page), editor = doc.frameLocator('iframe').getByLabel('Document text');
  await editor.click();
  await expect(doc).toHaveAttribute('data-focused', 'true');
  await expect(editor).toBeFocused();
  const child = await (await doc.locator('iframe').elementHandle()).contentFrame();
  const cdp = await context.newCDPSession(child).catch(() => context.newCDPSession(page));
  await cdp.send('Input.imeSetComposition', { text: 'にほん', selectionStart: 3, selectionEnd: 3 });
  await expect(editor).toHaveValue('にほん');
  // Chromium reports composition on a real native key delivered to this editing context.
  await cdp.send('Input.dispatchKeyEvent', { type: 'rawKeyDown', key: '`', code: 'Backquote', modifiers: 1, windowsVirtualKeyCode: 229 });
  await cdp.send('Input.dispatchKeyEvent', { type: 'keyUp', key: '`', code: 'Backquote', modifiers: 1, windowsVirtualKeyCode: 229 });
  await cdp.send('Input.insertText', { text: '日本語' });
  await expect(editor).toHaveValue('日本語');
  await expect(doc.frameLocator('iframe').locator('output')).toHaveText('3 characters');
  await expect(doc).toHaveAttribute('data-focused', 'true');
  const pageTree = await page.locator('#seat').ariaSnapshot();
  expect(pageTree).toContain('region "Document"');
  expect(pageTree).toContain('Geometric color study');
  const { frameTree } = await cdp.send('Page.getFrameTree');
  const frameId = frameTree.childFrames?.find(f => f.frame.url === 'about:srcdoc')?.frame.id ?? frameTree.frame.id;
  const { nodes } = await cdp.send('Accessibility.getFullAXTree', { frameId });
  expect(nodes.some(n => n.role?.value === 'textbox' && n.name?.value === 'Document text')).toBe(true);
  await expect(pixelWindow(page).locator('[aria-live="polite"]')).toHaveText(/Rendered generation/);
  await cdp.detach();
});

test('G-08 simulated loss replaces the actual canvas and the owning client redraws in software', async ({ page }) => {
  await page.evaluate(() => {
    window.initialCanvases = new Map();
    window.firstRender = new Map();
    window.guiSession.events('gui-display', cmd => {
      const gen = cmd.op === 'set_a11y' && /^Rendered generation (\d+)$/.exec(cmd.a11y.live_announcement);
      if (gen && !window.firstRender.has(cmd.surface_id)) window.firstRender.set(cmd.surface_id, Number(gen[1]));
    });
    new MutationObserver(records => {
      for (const r of records) for (const node of r.removedNodes) {
        if (node instanceof HTMLCanvasElement) window.initialCanvases.set(r.target.closest('section')?.dataset.pid, node);
      }
    }).observe(document.querySelector('#seat'), { subtree: true, childList: true });
  });
  const pid = await launch(page, 'gui-sample-pixel', ['--simulate-loss']);
  const el = page.locator('section[data-pid="' + pid + '"]');
  await expect(el.locator('canvas')).toHaveAttribute('data-backend', 'software2d');
  const id = await surface(el);
  const first = await page.waitForFunction(id => window.firstRender.get(id), id);
  const generation = (await first.jsonValue()) + 1;
  await expect(el.locator('canvas')).toHaveAttribute('data-generation', String(generation));
  await expect(el.locator('[aria-live]')).toHaveText('Rendered generation ' + generation);
  await expect.poll(() => el.locator('canvas').evaluate(async canvas => {
    const bitmap = await createImageBitmap(canvas);
    const matches = bitmap.width === canvas.parentElement.clientWidth && bitmap.height === canvas.parentElement.clientHeight;
    bitmap.close(); return matches;
  })).toBe(true);
  await expect.poll(() => el.locator('canvas').evaluate(async canvas => {
    const bitmap = await createImageBitmap(canvas);
    const ctx = new OffscreenCanvas(1, 1).getContext('2d');
    ctx.drawImage(bitmap, 1, 1, 1, 1, 0, 0, 1, 1); bitmap.close();
    return [...ctx.getImageData(0, 0, 1, 1).data];
  })).toEqual([41, 114, 104, 255]);
  expect(await el.evaluate(el => {
    const old = window.initialCanvases.get(el.dataset.pid), fresh = el.querySelector('canvas');
    return !!old && !old.isConnected && fresh !== old && Number(fresh.dataset.generation) === Number(old.dataset.generation) + 1;
  })).toBe(true);
});

test('G-09 clipboard, file selection and notifications follow seat gestures and login scope', async ({ page, context }) => {
  const doc = documentWindow(page), frame = doc.frameLocator('iframe');
  const send = async (action, text) => (await (await doc.locator('iframe').elementHandle()).contentFrame())
    .evaluate(args => window.gui.send(JSON.stringify(args)), { action, text });
  await pixelWindow(page).locator('canvas').click();
  for (const action of ['copy','pick','paste']) {
    await frame.locator('output').evaluate(el => { el.textContent = ''; });
    await send(action, action === 'copy' ? 'private' : undefined); await expect(frame.locator('output')).toHaveText('EACCES');
  }
  await page.locator('#doc').focus();
  await page.keyboard.press('Control+v');
  await frame.locator('output').evaluate(el => { el.textContent = ''; });
  await send('paste'); await expect(frame.locator('output')).toHaveText('EACCES');
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await frame.getByLabel('Document text').fill('from this seat');
  await frame.getByRole('button', { name: 'Copy' }).click();
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe('from this seat');
  await frame.getByLabel('Document text').press('Control+v');
  await expect(frame.locator('output')).toHaveText('from this seat');
  await page.evaluate(() => navigator.clipboard.writeText('external clipboard'));
  await frame.getByLabel('Document text').press('Control+v');
  await expect(frame.locator('output')).toHaveText('external clipboard');
  await page.evaluate(() => navigator.clipboard.writeText('pixel native paste'));
  const pixel = pixelWindow(page);
  await pixel.locator('canvas').press('Control+v');
  await expect(pixel.locator('[aria-live]')).toHaveText('Pasted 18 bytes');
  await frame.getByRole('button', { name: 'Choose file' }).click();
  await expect(page.locator('.picker').getByText('Choose file')).toBeFocused();
  await page.keyboard.press('Control+v');
  for (const action of ['paste','pick']) {
    await frame.locator('output').evaluate(el => { el.textContent = ''; });
    await send(action); await expect(frame.locator('output')).toHaveText('EACCES');
  }
  await page.locator('.picker').getByText('Cancel').click();
  await expect(frame.locator('output')).toHaveText('ECANCELED');
  // Use the trusted host chooser result; the client receives only SCM_RIGHTS.
  await page.evaluate(() => { window.showOpenFilePicker = async () => [{ getFile: async () => new File(['hello'], 'chosen.txt') }]; });
  await frame.getByRole('button', { name: 'Choose file' }).click();
  await page.locator('.picker').getByText('Choose file').click();
  await expect(frame.locator('output')).toHaveText('Selected 5 bytes');
  for (let i = 1; i <= 3; i++) {
    await frame.getByRole('button', { name: 'Notify' }).click();
    await expect(page.locator('[data-notification]')).toHaveCount(i);
  }
  await frame.getByRole('button', { name: 'Notify' }).click();
  await expect(frame.locator('output')).toHaveText('EAGAIN');
});

for (const role of ['lock','greeter']) test('G-09 a designated ' + role + ' retains modal focus until dismissed', async ({ page }) => {
  await stop(page, await page.evaluate(() => window.guiSession.compositorPid));
  await expect(page.locator('.surface')).toHaveCount(0);
  const shellPid = await page.evaluate(securityRole => window.guiSession.call('gui_start', { program: 'gui-sample-doc', securityRole }), role);
  await page.evaluate(shellPid => window.guiSession.call('gui_start', { program: 'compositor', shellPid }), shellPid);
  const desktop = await launch(page, 'gui-sample-pixel');
  await expect(page.locator('section[data-pid="' + desktop + '"] canvas')).toBeAttached();
  const lock = page.getByRole('dialog');
  await expect(lock).toHaveAttribute('aria-modal', 'true');
  await expect(lock.locator('.titlebar')).toHaveCount(0);
  await expect(page.locator('.desktop-layer')).toHaveJSProperty('inert', true);
  await lock.frameLocator('iframe').getByRole('button', { name: 'Notify' }).click();
  await expect(lock.frameLocator('iframe').locator('output')).toHaveText('EACCES');
  await expect(page.locator('[data-notification]')).toHaveCount(0);
  await lock.frameLocator('iframe').locator('output').evaluate(el => { el.textContent = ''; });
  await page.keyboard.press('Alt+F4');
  await lock.frameLocator('iframe').getByRole('button', { name: 'Notify' }).click();
  await expect(lock.frameLocator('iframe').locator('output')).toHaveText('EACCES');
  await expect(lock).toBeVisible();
  await expect(page.locator('.desktop-layer')).toHaveJSProperty('inert', true);
  await stop(page, shellPid);
  await expect(page.locator('.desktop-layer')).toHaveJSProperty('inert', false);
});

test('G-09 drag offers expose a MIME type, then drop delivers bytes to the target process', async ({ page }) => {
  const source = documentWindow(page), sourceFrame = source.frameLocator('iframe');
  const targetPid = await launch(page, 'gui-sample-doc'), target = page.locator('section[data-pid="' + targetPid + '"]');
  const targetFrame = target.frameLocator('iframe');
  await expect(targetFrame.getByLabel('Document text')).toBeVisible();
  const title = await beginDrag(page, target.locator('.title'));
  await page.mouse.move(title.x + 580, title.y + 30); await finishDrag(page);
  await sourceFrame.getByLabel('Document text').fill('only on drop');
  const handle = await sourceFrame.getByRole('button', { name: 'Drag text' }).boundingBox();
  await page.mouse.move(handle.x + 8, handle.y + 6); await page.mouse.down();
  await expect(page.locator('#seat')).toHaveClass(/dnd-active/);
  const area = await target.locator('.content').boundingBox();
  await page.mouse.move(area.x + 90, area.y + 60);
  await expect(targetFrame.locator('output')).toHaveText('Offered text/plain');
  await page.mouse.up();
  await expect(targetFrame.locator('output')).toHaveText('only on drop');
  await expect(page.locator('#seat')).not.toHaveClass(/dnd-active/);
});

test('G-10 suspend/resume and SIGKILL preserve or reset exactly the owning seat resources', async ({ page }) => {
  const doc = documentWindow(page), pixel = pixelWindow(page);
  const docPid = await owner(doc), pixelPid = await owner(pixel);
  await input(page, { op: 'seat_active', active: false });
  await expect(page.locator('.surface')).toHaveCount(2);
  await input(page, { op: 'seat_active', active: true });
  await pixel.locator('canvas').click(); await expect(pixel).toHaveAttribute('data-focused', 'true');
  await stop(page, pixelPid);
  await expect(page.locator('.surface')).toHaveCount(1);
  await expect(doc).toHaveAttribute('data-focused', 'true');
  expect(await owner(doc)).toBe(docPid);
  const old = await surface(doc);
  await stop(page, await page.evaluate(() => window.guiSession.compositorPid));
  await expect(page.locator('.surface')).toHaveCount(0);
  await page.getByRole('button', { name: 'Restart compositor' }).click();
  await expect(documentWindow(page).frameLocator('iframe').getByLabel('Document text')).toBeVisible();
  await expect(pixelWindow(page).getByRole('img')).toHaveAccessibleName('Geometric color study');
  expect(await surface(documentWindow(page))).not.toBe(old);
});

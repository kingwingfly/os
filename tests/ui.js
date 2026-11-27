// What specs do in the page, shared, so a change to the Files or the prompt is one change here.
import { expect, test } from '@playwright/test';

// Native Mounts GUI surface (`/usr/bin/mounts` Document iframe, #63 L6b-2).
export const mountsSurface = page => page.locator('.surface[data-app-id="mounts"]');
export const mountsFrame = page => mountsSurface(page).frameLocator('iframe');

// Native Editor GUI surface (`/usr/bin/editor` Document iframe, #64 L6c-1).
export const editorSurface = page => page.locator('.surface[data-app-id="editor"]');
export const editorFrame = page => editorSurface(page).frameLocator('iframe');
export const editorContent = page => editorFrame(page).getByRole('textbox', { name: 'File contents' });
export const editorStatus = page => editorFrame(page).locator('#editor-status');
export const editorDirty = page => editorFrame(page).locator('#editor-dirty');
export const editorDiscard = page => editorFrame(page).locator('#editor-discard');
export const editorSave = page => editorFrame(page).locator('#editor-save');
export const editorClose = page => editorFrame(page).getByRole('button', { name: 'Close editor' });

// Native Preview GUI surface (`/usr/bin/preview` Document iframe, #64 L6c-2).
export const previewSurface = page => page.locator('.surface[data-app-id="preview"]');
export const previewFrame = page => previewSurface(page).frameLocator('iframe');
export const previewTitle = page => previewFrame(page).locator('#viewer-title');
export const previewContent = page => previewFrame(page).locator('#viewer-content');
export const previewClose = page => previewFrame(page).getByRole('button', { name: 'Close preview' });

export async function closePreview(page) {
  await previewClose(page).click();
  await expect(previewSurface(page)).toBeHidden();
}

export async function waitForMountsReady(page, timeout = 25_000) {
  await expect(mountsSurface(page)).toBeVisible({ timeout });
  await expect(mountsFrame(page).locator('#mount-manager')).toBeVisible({ timeout });
  await expect(mountsFrame(page).locator('[data-connect]')).toHaveJSProperty('disabled', false, { timeout });
}

// Native Files GUI surface (`/usr/bin/files` Document iframe, #63 L6b-1).
export const filesSurface = page => page.locator('.surface[data-app-id="files"]');
export const filesFrame = page => filesSurface(page).frameLocator('iframe');
export const filesLocation = page => filesFrame(page).getByRole('textbox', { name: 'Location' });
export const filesList = page => filesFrame(page).locator('.files');
export const filesNames = page => filesFrame(page).locator('.files .filename');
export const filesNotice = page => filesFrame(page).locator('.file-notice');
export const filesProgress = page => filesFrame(page).getByRole('status', { name: 'Upload progress' });

export async function waitForFilesReady(page, timeout = 25_000) {
  await expect(filesSurface(page)).toBeVisible({ timeout });
  await expect(filesLocation(page)).toBeVisible({ timeout });
  await expect.poll(async () => {
    const val = await filesLocation(page).inputValue().catch(() => '');
    return val.startsWith('/');
  }, { timeout }).toBe(true);
}

// The Files go to `path` of their own: its location typed (`/usr/bin/files`).
export async function browse(page, path) {
  await waitForFilesReady(page);
  const location = filesLocation(page);
  await location.fill(path); await location.press('Enter');
  await expect(location).toHaveValue(path);
}

// Native Terminal GUI surface (`/usr/bin/terminal` Document iframe + `/usr/bin/osh`, #62 L6a).
export const terminalSurface = page => page.locator('.surface[data-app-id="terminal"]');
export const terminalFrame = page => terminalSurface(page).frameLocator('iframe');
export const terminalViewport = page => terminalFrame(page).locator('#viewport');
export const terminalInput = page => terminalFrame(page).getByRole('textbox', { name: 'Terminal input' });
export const terminalScreen = page => terminalFrame(page).locator('#screen');
export const terminalTabs = page => terminalFrame(page).locator('.term-tab');

// The terminal's working directory, reported via OSC 7 from `/usr/bin/osh`.
export const promptPath = page => terminalFrame(page).locator('#prompt-path');

export async function waitForTerminalReady(page, timeout = 25_000) {
  await expect(terminalSurface(page)).toBeVisible({ timeout });
  await expect(terminalViewport(page)).toHaveAttribute('data-state', 'idle', { timeout });
}

export async function waitForDesktopReady(page, timeout = 25_000) {
  await waitForTerminalReady(page, timeout);
  const vw = page.viewportSize()?.width ?? 1280;
  if (vw > 650) {
    await waitForFilesReady(page, timeout);
  }
}

export async function runTerminal(page, command, { wait = true, timeout = 25_000 } = {}) {
  await waitForTerminalReady(page, timeout);
  const before = Number((await terminalViewport(page).getAttribute('data-prompt-seq')) || '0');
  const input = terminalInput(page);
  await input.fill(command);
  await input.press('Enter');
  if (wait) {
    await expect.poll(async () => {
      const vp = terminalViewport(page);
      const state = await vp.getAttribute('data-state');
      const seq = Number((await vp.getAttribute('data-prompt-seq')) || '0');
      return state === 'idle' && seq > before;
    }, { timeout }).toBe(true);
  }
}

export async function sendTerminalLine(page, text) {
  const input = terminalInput(page);
  await input.fill(text);
  await input.press('Enter');
}

export async function terminalText(page) {
  return terminalScreen(page).innerText();
}

export async function execCmd(page, argv, { cwd, env, sudo = false, stdin = '', tty = false } = {}) {
  return page.evaluate(
    async ({ argv, cwd, env, sudo, stdin, tty }) => {
      let out = '';
      let stderr = '';
      const opts = {
        stdin,
        sudo,
        onOutput: (fd, text) => {
          if (fd === 2) stderr += text;
          else if (fd === 1) out += text;
        },
      };
      if (cwd !== undefined) opts.cwd = cwd;
      if (env !== undefined) opts.environment = env;
      if (tty) opts.tty = true;
      const result = await window.os.exec([argv], opts);
      return { ...result, stdout: result.stdout || out, stderr };
    },
    { argv, cwd, env, sudo, stdin, tty },
  );
}

export async function execSh(page, script, opts = {}) {
  return execCmd(page, ['/bin/sh', '-c', script], opts);
}

// Explicit Cloud / Cluster Sign-In & Sign-Out helpers (#57 L3d).
// Local OS accounts are 100% local on `os-cowfs` (auto-login `user` uid 1000 in `wheel`);
// tests requiring `/mnt/cloud` or remote devices (`/dev/{archive,media,present,snd}`) call this explicitly.
export async function cloudSignIn(page, username, password, scope) {
  return page.evaluate(
    ([u, p, s]) => window.os.cloudSignIn(u, p, s),
    [username, password, scope ?? null],
  );
}

export async function signInForRelay(page, existing) {
  const account = existing ?? { username: 'share' + crypto.randomUUID().slice(0, 8), password: crypto.randomUUID() };
  await waitForUserServices(page);
  // Registration and login each allow 12 requests per IP in a 60-second window.
  // Charge the fixture's backoff to setup so lease and UI assertions keep their own deadlines.
  async function withLoginLimit(action) {
    if (await action() !== 429) return;
    const info = test.info(), delay = 61000;
    if (info.timeout) info.setTimeout(info.timeout + delay);
    await new Promise(resolve => setTimeout(resolve, delay));
    expect(await action(), 'relay account rate limit after one full window').not.toBe(429);
  }
  if (!existing) {
    const url = new URL('/api/cloud-auth/register', page.url());
    await withLoginLimit(async () => {
      const registered = await page.request.post(url.href, {
        headers: { Origin: url.origin }, data: { ...account, create_home: false },
      });
      if (registered.status() !== 429) expect(registered.ok(), await registered.text()).toBe(true);
      return registered.status();
    });
  }
  await withLoginLimit(() => page.evaluate(async ({ username, password }) => {
    try {
      await window.os.cloudSignIn(username, password, { cloud_fs: false, devices: [], containers: false, relay: true });
      return 200;
    } catch (error) {
      if (error.status === 429) return 429;
      throw error;
    }
  }, account));
  return account;
}

// Exercise the raw control route from the credential-holding worker, just as the transport does.
export async function relayRequest(page, path, body, headers = {}) {
  const worker = page.workers().find(w => new URL(w.url()).pathname.endsWith('/client-kernel.js'));
  return worker.evaluate(async ({ path, body, headers }) => {
    const uid = JSON.parse(self.kernel.workspace_credentials()).uid;
    const response = await fetch('/api/mounts/' + path, { method: 'POST', credentials: 'omit',
      headers: { 'Content-Type': 'application/json', ...JSON.parse(self.kernel.relay_credential(uid)), ...headers },
      body: JSON.stringify(body) });
    return { status: response.status, value: await response.json() };
  }, { path, body, headers });
}

export async function waitForUserServices(page) {
  const { uid } = await pageCall(page, 'getcreds');
  await expect.poll(async () => {
    const rows = await pageSys(page, ['mount', 'export'].map(name => ({ stat: { path: `/run/user/${uid}/${name}.sock` } })));
    return rows.every(r => (r.ok?.mode & 0o170000) === 0o140000);
  }, { timeout: 30000 }).toBe(true);
}

export async function cloudSignOut(page) {
  return page.evaluate(() => window.os.cloudSignOut());
}

export async function cloudStatus(page) {
  return page.evaluate(() => window.os.cloudStatus());
}

export async function bootStatus(page) {
  return page.evaluate(() => window.os.bootStatus());
}

// Page-local VFS helpers (`fetch('/api/sys')` / `/api/pwrite` / `/api/file` inside the browser page,
// routed by `web/local-files.js` straight to the tab's local `os-cowfs` + `/tmp` with 0 network RPCs).
export async function pageSys(page, calls, options = {}) {
  return page.evaluate(async ([calls, options]) => {
    const res = await fetch('/api/sys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ calls, ...options }),
    });
    if (!res.ok) throw new Error(`/api/sys: ${res.status} ${await res.text()}`);
    return (await res.json()).results;
  }, [calls, options]);
}

export async function pageCall(page, call, options = {}) {
  const [result] = await pageSys(page, [call], options);
  if ('ok' in result) return result.ok;
  const err = new Error(`${typeof call === 'string' ? call : Object.keys(call)[0]}: ${result.err.detail || result.err.errno}`);
  err.errno = result.err.errno;
  throw err;
}

export async function pageErrno(page, call, options = {}) {
  const [result] = await pageSys(page, [call], options);
  return 'err' in result ? result.err.errno : null;
}

export async function pageMkdirp(page, path, mode = 0o755, options = {}) {
  const parts = path.split('/').filter(Boolean);
  const calls = parts.map((_, i) => ({ mkdir: { path: '/' + parts.slice(0, i + 1).join('/'), mode } }));
  if (!calls.length) return;
  const results = await pageSys(page, calls, options);
  const failed = results.findLast(r => r.err && r.err.errno !== 'EEXIST');
  if (failed) {
    const err = new Error(`mkdir -p ${path}: ${failed.err.detail || failed.err.errno}`);
    err.errno = failed.err.errno;
    throw err;
  }
}

export async function pagePut(page, path, data, { mode = 0o644, overwrite = true, sudo = false } = {}) {
  const base64 = Buffer.from(data).toString('base64');
  const res = await page.evaluate(async ({ path, base64, mode, overwrite, sudo }) => {
    const bin = atob(base64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    const flags = 0o1 | 0o100 | (overwrite ? 0o1000 : 0o200);
    const openRes = await fetch('/api/sys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ calls: [{ open: { path, flags, mode, size: bytes.length } }], sudo }),
    });
    const [opened] = (await openRes.json()).results;
    if (opened.err) return { ok: false, errno: opened.err.errno, detail: opened.err.detail };
    const { fd, chunk_size: chunk = 8 * 1024 * 1024 } = opened.ok;
    for (let idx = 0; idx * chunk < bytes.length; idx++) {
      const slice = bytes.subarray(idx * chunk, (idx + 1) * chunk);
      const pw = await fetch(`/api/pwrite?fd=${fd}&index=${idx}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: slice,
      });
      if (!pw.ok) {
        await fetch('/api/sys', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ calls: [{ close: { fd } }], sudo }),
        });
        return { ok: false, status: pw.status, detail: await pw.text() };
      }
    }
    const closeRes = await fetch('/api/sys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ calls: [{ close: { fd } }], sudo }),
    });
    const [closed] = (await closeRes.json()).results;
    if (closed.err) return { ok: false, errno: closed.err.errno, detail: closed.err.detail };
    return { ok: true, result: closed.ok };
  }, { path, base64, mode, overwrite, sudo });
  if (!res.ok) {
    const err = new Error(`pagePut(${path}): ${res.errno ?? res.status} ${res.detail ?? ''}`);
    err.errno = res.errno;
    throw err;
  }
  return res.result;
}

export async function pageGetBytes(page, path) {
  const res = await page.evaluate(async path => {
    const r = await fetch('/api/file?path=' + encodeURIComponent(path));
    if (!r.ok) return { ok: false, status: r.status, text: await r.text() };
    const buf = new Uint8Array(await r.arrayBuffer());
    let bin = '';
    for (let i = 0; i < buf.length; i += 0x8000) {
      bin += String.fromCharCode(...buf.subarray(i, i + 0x8000));
    }
    return { ok: true, status: r.status, base64: btoa(bin) };
  }, path);
  if (!res.ok) return null;
  return Buffer.from(res.base64, 'base64');
}

export async function pageGetText(page, path) {
  const bytes = await pageGetBytes(page, path);
  return bytes ? bytes.toString('utf8') : null;
}

export async function pageListing(page, path, options = {}) {
  const entries = (await pageCall(page, { getdents: { path } }, options)).map(({ name, stat }) => ({
    name,
    directory: !!stat && (stat.mode & 0o170000) === 0o040000,
    owner: stat?.user,
    group: stat?.group,
    mode: stat ? stat.mode & 0o7777 : 0,
    size: stat?.size,
    link: stat?.link,
  }));
  return entries.sort((a, b) => (b.directory - a.directory) || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}

export async function pageRmrf(page, path, options = {}) {
  const [found] = await pageSys(page, [{ lstat: { path } }], options);
  if (found.err) return found.err.errno === 'ENOENT' ? null : found.err.errno;
  if ((found.ok.mode & 0o170000) !== 0o040000) return pageErrno(page, { unlink: { path } }, options);
  const [listed] = await pageSys(page, [{ getdents: { path } }], options);
  if (listed.err) return listed.err.errno;
  let failure = null;
  for (const e of listed.ok) {
    failure ??= await pageRmrf(page, path.replace(/\/$/, '') + '/' + e.name, options);
  }
  return failure ?? pageErrno(page, { rmdir: { path } }, options);
}

// Switch the page's local OS account (100% local, zero network RPCs) and emit `os:login-changed`.
export async function switchLocalUser(page, username, { password = '', sudo = true } = {}) {
  const creds = await pageCall(
    page,
    { login: { username, password, ...(sudo && !password ? { force: true } : {}) } },
    { sudo },
  );
  await page.evaluate(() => window.dispatchEvent(new Event('os:login-changed')));
  return creds;
}

export async function logoutLocalUser(page) {
  const out = await pageCall(page, 'logout');
  await page.evaluate(() => window.dispatchEvent(new Event('os:login-changed')));
  return out;
}

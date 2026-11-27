import { test, expect } from './test.js';
import {
  closePreview,
  editorSurface,
  execCmd,
  filesSurface,
  logoutLocalUser,
  pageCall,
  pagePut,
  pageSys,
  previewContent,
  previewSurface,
  runTerminal,
  switchLocalUser,
  waitForDesktopReady,
  waitForTerminalReady,
  waitForUserServices,
} from './ui.js';

test('zero legacy page-as-account dialogs, APIs, or /api/sys network calls on boot', async ({ page }) => {
  const sysNetworkCalls = [];
  page.on('request', req => {
    const pathname = new URL(req.url()).pathname;
    if (pathname === '/api/sys') sysNetworkCalls.push(req.url());
  });

  await page.goto('/');
  await waitForDesktopReady(page);

  expect(sysNetworkCalls).toEqual([]);

  for (const selector of ['#auth', '#viewer', '#editor', '#window-files', '#window-mounts']) {
    await expect(page.locator(selector)).toHaveCount(0);
  }

  const surface = await page.evaluate(() => ({
    hasBootStatus: typeof window.os?.bootStatus === 'function',
    hasExec: typeof window.os?.exec === 'function',
    hasCloudSignIn: typeof window.os?.cloudSignIn === 'function',
    hasAccountCommand: 'accountCommand' in (window.os ?? {}),
    hasUnlock: 'unlock' in (window.os ?? {}),
    hasSudo: 'sudo' in (window.os ?? {}),
    hasSetDirectory: 'setDirectory' in (window.os ?? {}),
    hasUploadsSha256: typeof window.osUploads?.sha256 === 'function',
    hasUploadsSetfacl: 'setfacl' in (window.osUploads ?? {}),
  }));

  expect(surface).toEqual({
    hasBootStatus: true,
    hasExec: true,
    hasCloudSignIn: true,
    hasAccountCommand: false,
    hasUnlock: false,
    hasSudo: false,
    hasSetDirectory: false,
    hasUploadsSha256: true,
    hasUploadsSetfacl: false,
  });
});

test('desktop-actions.sock (open, man, vim) works and rebinds across local UID switch without compatConn', async ({ page }) => {
  test.setTimeout(120_000);
  await page.goto('/');
  await waitForDesktopReady(page);
  await waitForUserServices(page);

  const initial = await pageCall(page, 'getcreds');
  expect(initial.user).toBe('user');
  expect(initial.uid).toBe(1000);

  // Verify open, man, and vim over /run/user/1000/desktop-actions.sock.
  const userNote = '/home/user/l6d-note.txt';
  await pagePut(page, userNote, 'hello-from-l6d\n');

  const openRes = await execCmd(page, ['/usr/bin/open', userNote]);
  expect(openRes.status).toBe(0);
  await expect(previewSurface(page)).toBeVisible({ timeout: 20_000 });
  await expect(previewContent(page)).toContainText('hello-from-l6d', { timeout: 20_000 });
  await closePreview(page);

  const manPipe = await execCmd(page, ['/usr/bin/man', 'open']);
  expect(manPipe.status, manPipe.stderr).toBe(0);
  expect(manPipe.stdout).toContain('open');
  await waitForTerminalReady(page);
  await runTerminal(page, 'man open');
  await expect(previewSurface(page)).toBeVisible({ timeout: 20_000 });
  await closePreview(page);

  const vimPromise = execCmd(page, ['/usr/bin/vim', userNote]);
  await expect(editorSurface(page)).toBeVisible({ timeout: 20_000 });
  await editorSurface(page).getByRole('button', { name: 'Close', exact: true }).click();
  await expect(editorSurface(page)).toBeHidden({ timeout: 15_000 });
  expect((await vimPromise).status).toBe(0);

  // Create a second local user and switch UIDs; desktop-actions.sock must rebind cleanly.
  const bobName = 'bob' + Date.now().toString(36).slice(-4);
  await pageCall(page, { useradd: { name: bobName, password: 'bob-local-password-123', create_home: true } }, { sudo: true });
  await switchLocalUser(page, bobName, { password: 'bob-local-password-123', sudo: false });

  try {
    const bob = await pageCall(page, 'getcreds');
    expect(bob.user).toBe(bobName);
    expect(bob.uid).not.toBe(initial.uid);

    await expect.poll(async () => {
      const [st] = await pageSys(page, [{ stat: { path: `/run/user/${bob.uid}/desktop-actions.sock` } }]);
      return Boolean(st.ok && (st.ok.mode & 0o170000) === 0o140000);
    }, { timeout: 25_000 }).toBe(true);

    await expect(filesSurface(page)).toBeVisible({ timeout: 25_000 });

    const bobNote = `${bob.home}/bob-doc.txt`;
    await pagePut(page, bobNote, 'rebound-uid-ok\n');
    const bobOpen = await execCmd(page, ['/usr/bin/open', bobNote]);
    expect(bobOpen.status).toBe(0);
    await expect(previewSurface(page)).toBeVisible({ timeout: 20_000 });
    await expect(previewContent(page)).toContainText('rebound-uid-ok', { timeout: 20_000 });
    await closePreview(page);
  } finally {
    await logoutLocalUser(page);
  }
});

test('local two-UID exportd and desktop-actions.sock enforce SO_PEERCRED isolation', async ({ page }) => {
  test.setTimeout(120_000);
  await page.goto('/');
  await waitForDesktopReady(page);
  await waitForUserServices(page);

  const owner = await pageCall(page, 'getcreds');
  expect(owner.uid).toBe(1000);

  const srcDir = `${owner.home}/l6d-iso-${Date.now().toString(36)}`;
  const mk = await execCmd(page, ['/usr/bin/mkdir', '-m', '700', srcDir]);
  expect(mk.status).toBe(0);
  await pagePut(page, `${srcDir}/secret.txt`, 'OWNER_ONLY_SECRET\n', { mode: 0o600 });

  const pub = await execCmd(page, ['/usr/bin/exportctl', 'publish', '--ipc-only', '--json', srcDir]);
  expect(pub.status, pub.stderr).toBe(0);
  const { export: grant } = JSON.parse(pub.stdout);
  expect(grant.owner_uid).toBe(owner.uid);

  const otherName = 'mallory' + Date.now().toString(36).slice(-4);
  await pageCall(page, { useradd: { name: otherName, password: 'mallory-local-password-123', create_home: true } }, { sudo: true });
  await switchLocalUser(page, otherName, { password: 'mallory-local-password-123', sudo: false });

  try {
    const other = await pageCall(page, 'getcreds');
    expect(other.uid).not.toBe(owner.uid);
    await expect.poll(async () => {
      const [st] = await pageSys(page, [{ stat: { path: `/run/user/${other.uid}/desktop-actions.sock` } }]);
      return Boolean(st.ok && (st.ok.mode & 0o170000) === 0o140000);
    }, { timeout: 25_000 }).toBe(true);

    // Other UID cannot inspect or connect into uid 1000's private /run/user/1000 directory.
    const [exportSockStat, actionsSockStat] = await pageSys(page, [
      { stat: { path: `/run/user/${owner.uid}/export.sock` } },
      { stat: { path: `/run/user/${owner.uid}/desktop-actions.sock` } },
    ]);
    expect(exportSockStat.err?.errno).toBe('EACCES');
    expect(actionsSockStat.err?.errno).toBe('EACCES');

    // Other UID cannot mount uid 1000's private IPC export without an ACL grant.
    const mountAttempt = await execCmd(
      page,
      ['/usr/bin/mount', '-t', 'sharefs', '-o', 'transport=ipc', `osfs:${grant.id}`, '/mnt/shared/stolen'],
    );
    expect(mountAttempt.status).not.toBe(0);
  } finally {
    await logoutLocalUser(page);
    await execCmd(page, ['/usr/bin/exportctl', 'revoke', grant.id]).catch(() => {});
  }
});

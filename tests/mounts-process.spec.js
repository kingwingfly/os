import { test, expect } from './storage-test.js';
import {
  execCmd,
  filesFrame,
  mountsFrame,
  mountsSurface,
  runTerminal,
  signInForRelay,
  waitForDesktopReady,
  waitForMountsReady,
} from './ui.js';

async function findProcessPids(page, programName) {
  const res = await execCmd(page, ['/usr/bin/ps']);
  expect(res.status, res.stderr).toBe(0);
  const pids = [];
  for (const line of res.stdout.split('\n')) {
    const m = line.trim().match(/^(\d+)\s+\S+\s+\S+\s+(\S+)/);
    if (m && (m[2] === programName || m[2].endsWith('/' + programName))) {
      pids.push(Number(m[1]));
    }
  }
  return pids;
}

test('Mounts runs as /usr/bin/mounts in a sealed Document iframe, zero #window-mounts, and Host compat mounts returns EPERM', async ({ page }) => {
  await page.goto('/');
  await waitForDesktopReady(page);

  await expect(page.locator('#window-mounts')).toHaveCount(0);
  await expect(page.locator('#mount-manager')).toHaveCount(0);

  await filesFrame(page).locator('.files-mounts').click();
  await waitForMountsReady(page);

  await expect(page.locator('#window-mounts')).toHaveCount(0);
  await expect(page.locator('#mount-manager')).toHaveCount(0);
  const iframe = mountsSurface(page).locator('iframe');
  await expect(iframe).toBeVisible();
  await expect(iframe).toHaveAttribute('sandbox', 'allow-scripts');

  const mountsPids = await findProcessPids(page, 'mounts');
  expect(mountsPids.length).toBe(1);

  const req = JSON.stringify({
    op: 'create_surface',
    spec: {
      role: 'window',
      kind: { host: { component: 'mounts' } },
      title: 'Spoofed Mounts',
      rect: { x: 0, y: 0, width: 320, height: 240 },
      min_size: { width: 100, height: 80 },
      max_size: null,
      resizable: true,
      app_id: 'mounts',
    },
  });
  const spoof = await execCmd(page, ['/usr/bin/gui-sample-doc', '--request', req]);
  expect(spoof.status).toBe(0);
  expect(JSON.parse(spoof.stdout.trim())).toEqual({ op: 'error', errno: 'EPERM' });
});

test('closing Mounts terminates /usr/bin/mounts cleanly while keeping mounts attached and respawning shows them', async ({ page }) => {
  await page.goto('/');
  await waitForDesktopReady(page);

  await page.evaluate(() => window.os.localMounts('add'));
  await waitForMountsReady(page);

  const app = mountsFrame(page);
  await app.getByRole('tab', { name: 'Add mount', exact: true }).click();
  await app.locator('[name=kind]').selectOption('storage');
  await app.getByLabel('User write', { exact: true }).check();
  await app.getByRole('button', { name: 'Mount storage', exact: true }).click();
  await expect(app.locator('[data-selected]')).toHaveText('/mnt/local/project');

  const beforePids = await findProcessPids(page, 'mounts');
  expect(beforePids.length).toBe(1);
  const oldPid = beforePids[0];

  await mountsSurface(page).getByRole('button', { name: 'Close', exact: true }).click();
  await expect(mountsSurface(page)).toHaveCount(0, { timeout: 15_000 });
  await expect.poll(async () => findProcessPids(page, 'mounts'), { timeout: 15_000 }).toEqual([]);

  // Mount remains attached after /usr/bin/mounts exits.
  const list = await page.evaluate(() => window.os.localMountList());
  expect(list.map(m => m.path)).toContain('/mnt/local/project');

  // Re-opening spawns a fresh /usr/bin/mounts PID displaying the live mount.
  await page.evaluate(() => window.os.localMounts());
  await waitForMountsReady(page);
  await expect(mountsFrame(page).locator('[data-selected]')).toHaveText('/mnt/local/project');
  const afterPids = await findProcessPids(page, 'mounts');
  expect(afterPids.length).toBe(1);
  expect(afterPids[0]).not.toBe(oldPid);
});

test('running mounts --tab <pane> in Terminal and localMounts(<pane>) reuse the running process over mounts.sock', async ({ page }) => {
  await page.goto('/');
  await waitForDesktopReady(page);

  await page.evaluate(() => window.os.localMounts());
  await waitForMountsReady(page);
  const beforePids = await findProcessPids(page, 'mounts');
  expect(beforePids.length).toBe(1);
  const pid = beforePids[0];

  await runTerminal(page, 'mounts --tab add');
  await expect(mountsFrame(page).getByRole('tab', { name: 'Add mount', exact: true })).toHaveAttribute('aria-selected', 'true', { timeout: 15_000 });
  await expect(mountsSurface(page)).toHaveCount(1);
  expect(await findProcessPids(page, 'mounts')).toEqual([pid]);

  await page.evaluate(() => window.os.localMounts('publish'));
  await expect(mountsFrame(page).getByRole('tab', { name: 'Publish', exact: true })).toHaveAttribute('aria-selected', 'true', { timeout: 15_000 });
  await expect(mountsSurface(page)).toHaveCount(1);
  expect(await findProcessPids(page, 'mounts')).toEqual([pid]);
});

test('Publish and Connect across two tabs work end-to-end purely through /usr/bin/mounts and the blind Window WebRTC broker', async ({ page, context }) => {
  test.setTimeout(120_000);
  const other = await context.newPage();
  try {
    await page.goto('/');
    await other.goto('/');
    await waitForDesktopReady(page);
    await waitForDesktopReady(other);

    const account = await signInForRelay(page);
    await signInForRelay(other, account);

    // Mount browser storage in publisher via /usr/bin/mounts UI and write a file into it.
    await page.evaluate(() => window.os.localMounts('add'));
    await waitForMountsReady(page);
    const pubApp = mountsFrame(page);
    await pubApp.getByRole('tab', { name: 'Add mount', exact: true }).click();
    await pubApp.locator('[name=kind]').selectOption('storage');
    await pubApp.getByLabel('User write', { exact: true }).check();
    await pubApp.getByRole('button', { name: 'Mount storage', exact: true }).click();
    await expect(pubApp.locator('[data-selected]')).toHaveText('/mnt/local/project');

    const write = await execCmd(page, ['/usr/bin/sh', '-c', 'printf "from-mounts-proc" > /mnt/local/project/hello.txt']);
    expect(write.status, write.stderr).toBe(0);

    const { uid } = await other.evaluate(() => window.os.sharedMounts());
    const acl = await execCmd(page, ['/usr/bin/setfacl', '-m', `u:${uid}:rx`, '/mnt/local/project']);
    expect(acl.status, acl.stderr).toBe(0);

    // Publish directly from /usr/bin/mounts Publish tab (SCM_RIGHTS dirfd -> exportd + Window WebRTC listener).
    await pubApp.getByRole('tab', { name: 'Publish', exact: true }).click();
    await pubApp.getByRole('button', { name: 'Publish', exact: true }).click();
    await expect(pubApp.getByRole('button', { name: 'Stop publishing', exact: true })).toBeVisible({ timeout: 15_000 });
    const address = await pubApp.locator('[data-shares] input').inputValue();
    expect(address).toMatch(/^osfs:/);

    // Connect from the second tab's /usr/bin/mounts Connect tab (Window WebRTC connector -> sharefs).
    await other.evaluate(() => window.os.localMounts('connect'));
    await waitForMountsReady(other);
    const recvApp = mountsFrame(other);
    await recvApp.getByRole('tab', { name: 'Connect', exact: true }).click();
    const form = recvApp.locator('[data-shared-form]');
    await form.getByLabel('Mount name', { exact: true }).fill('frompub');
    await form.getByLabel('Export address', { exact: true }).fill(address);
    await form.getByRole('button', { name: 'Mount', exact: true }).click();
    await expect(recvApp.locator('[data-selected]')).toHaveText('/mnt/shared/frompub', { timeout: 20_000 });

    const cat = await execCmd(other, ['/usr/bin/cat', '/mnt/shared/frompub/hello.txt']);
    expect(cat.status, cat.stderr).toBe(0);
    expect(cat.stdout).toBe('from-mounts-proc');

    await pubApp.getByRole('button', { name: 'Stop publishing', exact: true }).click();
    await expect(pubApp.locator('[data-shares]')).toContainText('No directories published.');
  } finally {
    await other.close();
  }
});

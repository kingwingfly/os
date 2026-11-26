import { test, expect } from './test.js';
import {
  browse,
  execCmd,
  filesFrame,
  filesLocation,
  filesNames,
  filesProgress,
  filesSurface,
  pageGetText,
  pageMkdirp,
  pageRmrf,
  runTerminal,
  terminalSurface,
  waitForDesktopReady,
  waitForFilesReady,
} from './ui.js';

const dock = (page, name) =>
  page.getByRole('navigation', { name: 'Dock' }).getByRole('button', { name, exact: true });

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

test('Files runs as /usr/bin/files in a sealed Document iframe, zero #window-files, and Host compat files returns EPERM', async ({ page }) => {
  await page.goto('/');
  await waitForDesktopReady(page);

  await expect(page.locator('#window-files')).toHaveCount(0);
  await expect(filesSurface(page)).toBeVisible();
  const iframe = filesSurface(page).locator('iframe');
  await expect(iframe).toBeVisible();
  await expect(iframe).toHaveAttribute('sandbox', 'allow-scripts');

  const filesPids = await findProcessPids(page, 'files');
  expect(filesPids.length).toBe(1);

  const req = JSON.stringify({
    op: 'create_surface',
    spec: {
      role: 'window',
      kind: { host: { component: 'files' } },
      title: 'Spoofed Files',
      rect: { x: 0, y: 0, width: 320, height: 240 },
      min_size: { width: 100, height: 80 },
      max_size: null,
      resizable: true,
      app_id: 'files',
    },
  });
  const spoof = await execCmd(page, ['/usr/bin/gui-sample-doc', '--request', req]);
  expect(spoof.status).toBe(0);
  expect(JSON.parse(spoof.stdout.trim())).toEqual({ op: 'error', errno: 'EPERM' });
});

test('local multi-file upload, duplicate conflict refusal, and external drop isolation between Files and Terminal', async ({ page }) => {
  const dir = '/home/user/files-proc-' + Date.now().toString(36);
  await page.goto('/');
  await waitForDesktopReady(page);
  await pageMkdirp(page, dir, 0o755);
  try {
    await browse(page, dir);

    const chooser = page.waitForEvent('filechooser');
    await filesFrame(page).getByRole('button', { name: 'Upload', exact: true }).click();
    await (await chooser).setFiles([
      { name: 'one.txt', mimeType: 'text/plain', buffer: Buffer.from('first-payload') },
      { name: 'two.txt', mimeType: 'text/plain', buffer: Buffer.from('second-payload') },
    ]);

    await expect(filesProgress(page)).toContainText('✓ one.txt', { timeout: 20_000 });
    await expect(filesProgress(page)).toContainText('✓ two.txt', { timeout: 20_000 });
    await expect(filesNames(page)).toHaveText(['one.txt', 'two.txt']);
    expect(await pageGetText(page, dir + '/one.txt')).toBe('first-payload');
    expect(await pageGetText(page, dir + '/two.txt')).toBe('second-payload');

    // Duplicate upload refuses to overwrite with exact conflict message.
    const dupChooser = page.waitForEvent('filechooser');
    await filesFrame(page).getByRole('button', { name: 'Upload', exact: true }).click();
    await (await dupChooser).setFiles([
      { name: 'one.txt', mimeType: 'text/plain', buffer: Buffer.from('overwrite-attempt') },
    ]);
    await expect(filesProgress(page)).toContainText('File already exists; rename it before uploading', { timeout: 20_000 });
    expect(await pageGetText(page, dir + '/one.txt')).toBe('first-payload');

    // External drop onto Terminal is ignored (never uploaded into Files).
    const ignoredTransfer = await page.evaluateHandle(() => {
      const dt = new DataTransfer();
      dt.items.add(new File(['nope'], 'ignored.txt', { type: 'text/plain' }));
      return dt;
    });
    await terminalSurface(page).dispatchEvent('drop', { dataTransfer: ignoredTransfer });
    await ignoredTransfer.dispose();
    await page.waitForTimeout(300);
    await expect(filesNames(page)).toHaveText(['one.txt', 'two.txt']);
    expect(await pageGetText(page, dir + '/ignored.txt')).toBeNull();

    // External drop onto Files surface uploads into Files' cwd.
    const acceptedTransfer = await page.evaluateHandle(() => {
      const dt = new DataTransfer();
      dt.items.add(new File(['accepted-bytes'], 'accepted.txt', { type: 'text/plain' }));
      return dt;
    });
    await filesSurface(page).dispatchEvent('drop', { dataTransfer: acceptedTransfer });
    await acceptedTransfer.dispose();
    await expect(filesProgress(page)).toContainText('✓ accepted.txt', { timeout: 20_000 });
    await expect(filesNames(page)).toHaveText(['accepted.txt', 'one.txt', 'two.txt']);
    expect(await pageGetText(page, dir + '/accepted.txt')).toBe('accepted-bytes');
  } finally {
    await pageRmrf(page, dir).catch(() => {});
  }
});

test('closing Files terminates /usr/bin/files cleanly and Dock respawns a fresh process restoring ~/.config/os/files.json', async ({ page }) => {
  const dir = '/home/user/files-respawn-' + Date.now().toString(36);
  await page.goto('/');
  await waitForDesktopReady(page);
  await pageMkdirp(page, dir, 0o755);
  try {
    await browse(page, dir);
    const beforePids = await findProcessPids(page, 'files');
    expect(beforePids.length).toBe(1);
    const oldPid = beforePids[0];

    await filesSurface(page).getByRole('button', { name: 'Close', exact: true }).click();
    await expect(filesSurface(page)).toHaveCount(0, { timeout: 15_000 });
    await expect.poll(async () => findProcessPids(page, 'files'), { timeout: 15_000 }).toEqual([]);

    await dock(page, 'Files').click();
    await waitForFilesReady(page, 20_000);
    await expect(filesLocation(page)).toHaveValue(dir);

    const afterPids = await findProcessPids(page, 'files');
    expect(afterPids.length).toBe(1);
    expect(afterPids[0]).not.toBe(oldPid);
  } finally {
    await pageRmrf(page, dir).catch(() => {});
  }
});

test('running files <dir> in Terminal reuses the running Files process over files.sock without duplicating windows', async ({ page }) => {
  await page.goto('/');
  await waitForDesktopReady(page);

  const beforePids = await findProcessPids(page, 'files');
  expect(beforePids.length).toBe(1);
  const pid = beforePids[0];

  await runTerminal(page, 'files /tmp');
  await expect(filesLocation(page)).toHaveValue('/tmp', { timeout: 15_000 });
  await expect(filesSurface(page)).toHaveCount(1);
  expect(await findProcessPids(page, 'files')).toEqual([pid]);
});

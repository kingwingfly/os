import { test, expect } from './test.js';
import { execCmd, settingsFrame, settingsSurface, waitForDesktopReady, waitForSettingsReady } from './ui.js';

const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';

test('Settings runs as /usr/bin/settings over unified Portal IPC, persists ~/.config/os/settings.json, and live-syncs with Quick Settings', async ({ page }) => {
  test.setTimeout(90_000);
  await page.goto(origin + '/');
  await waitForDesktopReady(page);

  // Zero embedded Cloud popover in the Dock.
  await expect(page.locator('.cloud-panel-popover')).toHaveCount(0);

  // Open Settings from the Dock icon.
  await page.locator('.dock button[aria-label="Settings"]').click();
  await waitForSettingsReady(page);
  const frame = settingsFrame(page);

  // Accounts & Cloud section displays Local OS Identity and Cloud credentials.
  await expect(frame.locator('[data-local-summary]')).toContainText('user (uid=1000, gid=1000)');
  await expect(frame.locator('[data-cloud-badge]')).toContainText('Offline / Signed out');

  // Switch to Appearance & Dock, switch to Dark theme and enable Always auto-hide Dock.
  await frame.locator('#settings-tab-appearance').click();
  await expect(frame.locator('#settings-pane-appearance')).toBeVisible();
  await frame.locator('[data-theme-choice="dark"]').click();
  await expect.poll(() => page.evaluate(() => document.documentElement.dataset.theme)).toBe('dark');

  await frame.locator('[data-pref-autohide]').click();
  await expect(frame.locator('[data-pref-autohide]')).toHaveAttribute('aria-checked', 'true');

  // Verify ~/.config/os/settings.json exists with mode 600 and expected JSON payload on os-cowfs.
  const statRes = await execCmd(page, ['stat', '-c', '%a', '/home/user/.config/os/settings.json']);
  expect(statRes.status, statRes.stderr).toBe(0);
  expect(statRes.stdout.trim()).toBe('600');

  const fileRes = await execCmd(page, ['cat', '/home/user/.config/os/settings.json']);
  expect(fileRes.status, fileRes.stderr).toBe(0);
  const diskPrefs = JSON.parse(fileRes.stdout);
  expect(diskPrefs).toEqual({ version: 1, theme: 'dark', dock_autohide: true });

  // Clear localStorage pre-paint cache and reload to prove preferences restore from ~/.config/os/settings.json!
  await page.evaluate(() => {
    localStorage.removeItem('os-theme');
    localStorage.removeItem('os-dock-autohide');
  });
  await page.evaluate(() => window.os.closeCleanRoot());
  await page.reload();
  await waitForDesktopReady(page);
  await expect.poll(() => page.evaluate(() => document.documentElement.dataset.theme), { timeout: 15_000 }).toBe('dark');

  // Re-open Settings and verify bidirectional live sync when toggling Light via top-right Quick Settings.
  await page.evaluate(() => window.os.openSettings('appearance'));
  await waitForSettingsReady(page);
  await expect(frame.locator('[data-theme-choice="dark"]')).toHaveAttribute('aria-pressed', 'true');
  await expect(frame.locator('[data-pref-autohide]')).toHaveAttribute('aria-checked', 'true');

  await page.locator('.topbar-qs-btn').click();
  await page.locator('.cc-popover button', { hasText: 'Light' }).click();
  await expect.poll(() => page.evaluate(() => document.documentElement.dataset.theme)).toBe('light');
  await expect(frame.locator('[data-theme-choice="light"]')).toHaveAttribute('aria-pressed', 'true', { timeout: 10_000 });

  // Disk file updated back to light by Quick Settings writeback.
  await expect.poll(async () => {
    const r = await execCmd(page, ['cat', '/home/user/.config/os/settings.json']);
    return JSON.parse(r.stdout).theme;
  }, { timeout: 10_000 }).toBe('light');

  // Close Settings window cleanly.
  await settingsSurface(page).locator('.titlebar button[aria-label="Close"]').click();
  await expect(settingsSurface(page)).toHaveCount(0, { timeout: 10_000 });
});

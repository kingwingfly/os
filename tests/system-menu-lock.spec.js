import { test, expect } from './test.js';
import { terminalSurface, waitForTerminalReady } from './ui.js';

async function execCmd(page, argv, { sudo = false, stdin = '' } = {}) {
  return page.evaluate(
    ({ argv, sudo, stdin }) => window.os.exec([argv], { stdin, sudo }),
    { argv, sudo, stdin },
  );
}

async function waitDesktopReady(page) {
  await waitForTerminalReady(page, 25_000);
  await expect.poll(async () => {
    const comp = await execCmd(page, ['/usr/bin/service', '--json', 'status', 'compositor.service']);
    const shell = await execCmd(page, ['/usr/bin/service', '--user', '--json', 'status', 'desktop-shell.service']);
    try {
      const c = JSON.parse(comp.stdout);
      const s = JSON.parse(shell.stdout);
      return c.unit?.state === 'active' && s.unit?.state === 'active'
        ? { compositorPid: c.unit.pid, shellPid: s.unit.pid }
        : null;
    } catch {
      return null;
    }
  }, { timeout: 20_000 }).not.toBeNull();
}

test('1. desktop boot keeps disabled kubelet.service inactive while explicit start still works', async ({ page }) => {
  await page.goto('/');
  await waitDesktopReady(page);

  const initRes = await execCmd(page, ['/usr/bin/service', '--json', 'status', 'kubelet.service']);
  expect(initRes.status).toBe(0);
  const initUnit = JSON.parse(initRes.stdout).unit;
  expect(initUnit.state).toBe('inactive');
  expect(initUnit.enabled).toBe(false);
  expect(initUnit.pid ?? null).toBeNull();

  const psBefore = await execCmd(page, ['/usr/bin/ps'], { sudo: true });
  expect(psBefore.status).toBe(0);
  expect(psBefore.stdout).not.toContain('/usr/bin/kubelet');

  // Re-activating `graphical.target` or `multi-user.target` must NOT start disabled `kubelet.service`.
  const startGfx = await execCmd(page, ['/usr/bin/service', 'start', 'graphical.target'], { sudo: true });
  expect(startGfx.status).toBe(0);
  const afterGfx = JSON.parse(
    (await execCmd(page, ['/usr/bin/service', '--json', 'status', 'kubelet.service'])).stdout,
  ).unit;
  expect(afterGfx.state).toBe('inactive');
  expect(afterGfx.enabled).toBe(false);

  // Explicit `service start kubelet.service` still works even while disabled, then stops cleanly.
  const startKube = await execCmd(page, ['/usr/bin/service', 'start', 'kubelet.service'], { sudo: true });
  expect(startKube.status).toBe(0);
  await expect.poll(async () => {
    const st = await execCmd(page, ['/usr/bin/service', '--json', 'status', 'kubelet.service']);
    try { return JSON.parse(st.stdout).unit; } catch { return null; }
  }, { timeout: 20_000 }).toMatchObject({ state: 'active', enabled: false });

  const stopKube = await execCmd(page, ['/usr/bin/service', 'stop', 'kubelet.service'], { sudo: true });
  expect(stopKube.status).toBe(0);
  await expect.poll(async () => {
    const st = await execCmd(page, ['/usr/bin/service', '--json', 'status', 'kubelet.service']);
    try { return JSON.parse(st.stdout).unit?.state; } catch { return null; }
  }, { timeout: 15_000 }).toBe('inactive');
});

test('2. clickable top-left wordmark opens macOS-style System Menu and locks/unlocks desktop', async ({ page }) => {
  await page.goto('/');
  await waitDesktopReady(page);

  const wordmark = page.locator('.topbar .wordmark-btn');
  await expect(wordmark).toBeVisible();
  await wordmark.click();

  const menu = page.getByRole('menu', { name: 'System Menu' });
  await expect(menu).toBeVisible();
  await expect(menu.getByRole('menuitem', { name: 'About This OS' })).toBeVisible();
  await expect(menu.getByRole('menuitem', { name: /Lock Screen/ })).toBeVisible();
  await expect(menu.getByRole('menuitem', { name: 'Restart Graphical Session' })).toBeVisible();

  // "About This OS" opens Settings.
  await menu.getByRole('menuitem', { name: 'About This OS' }).click();
  await expect(menu).toBeHidden();
  await expect(page.locator('.surface[data-app-id="settings"]')).toBeVisible({ timeout: 20_000 });

  // Open System Menu again and trigger Lock Screen.
  await wordmark.click();
  await expect(menu).toBeVisible();
  await menu.getByRole('menuitem', { name: /Lock Screen/ }).click();

  // Lock screen modal appears, greeter.service is active, and topbar/dock become inert.
  const overlay = page.locator('.greeter-modal-overlay');
  await expect(overlay).toBeVisible({ timeout: 15_000 });
  await expect(overlay.locator('[data-role="greeter"]')).toBeVisible();
  await expect(overlay.locator('.greeter-lock-time')).toBeVisible();
  await expect(overlay.getByRole('heading', { name: 'user' })).toBeVisible();

  await expect.poll(async () => {
    const st = await execCmd(page, ['/usr/bin/service', '--json', 'status', 'greeter.service']);
    try { return JSON.parse(st.stdout).unit?.state; } catch { return null; }
  }, { timeout: 10_000 }).toBe('active');

  const inertState = await page.evaluate(() => ({
    topbar: Boolean(document.querySelector('.topbar')?.inert),
    dock: Boolean(document.querySelector('.dock')?.inert),
  }));
  expect(inertState).toEqual({ topbar: true, dock: true });

  // Default account has no password set -> Unlock button dismisses lock screen cleanly.
  const unlockBtn = overlay.getByRole('button', { name: 'Unlock' });
  await expect(unlockBtn).toBeEnabled({ timeout: 10_000 });
  await unlockBtn.click();

  await expect(overlay).toBeHidden({ timeout: 15_000 });
  await expect.poll(async () => {
    const st = await execCmd(page, ['/usr/bin/service', '--json', 'status', 'greeter.service']);
    try { return JSON.parse(st.stdout).unit?.state; } catch { return null; }
  }, { timeout: 10_000 }).toBe('inactive');

  const restoredInert = await page.evaluate(() => ({
    topbar: Boolean(document.querySelector('.topbar')?.inert),
    dock: Boolean(document.querySelector('.dock')?.inert),
  }));
  expect(restoredInert).toEqual({ topbar: false, dock: false });
  await expect(terminalSurface(page)).toBeVisible();
});

test('3. lock screen verifies /etc/shadow password after passwd is set and rejects wrong password', async ({ page }) => {
  await page.goto('/');
  await waitDesktopReady(page);

  // Set a local password for `user` via real `/usr/bin/passwd`.
  const secret = 'os-lock-passphrase-42';
  const pwRes = await execCmd(
    page,
    ['/usr/bin/passwd', 'user'],
    { sudo: true, stdin: `${secret}\n${secret}\n` },
  );
  expect(pwRes.status, pwRes.stderr).toBe(0);

  // Trigger Lock Screen via Quick Settings (Control Center).
  await page.getByRole('button', { name: 'Control Center' }).click();
  const cc = page.getByRole('dialog', { name: 'Control Center' });
  await expect(cc).toBeVisible();
  await cc.getByRole('button', { name: 'Lock Screen' }).click();

  const overlay = page.locator('.greeter-modal-overlay');
  await expect(overlay).toBeVisible({ timeout: 15_000 });
  const pwInput = overlay.locator('#lock-password');
  await expect(pwInput).toBeVisible({ timeout: 10_000 });

  // Wrong password MUST be rejected while keeping greeter.service active and desktop locked!
  await pwInput.fill('wrong-password-123');
  await overlay.getByRole('button', { name: 'Unlock' }).click();
  await expect(overlay.getByRole('alert')).toContainText(/Incorrect password/i, { timeout: 10_000 });
  await expect(overlay).toBeVisible();
  const stillActive = JSON.parse(
    (await execCmd(page, ['/usr/bin/service', '--json', 'status', 'greeter.service'])).stdout,
  ).unit;
  expect(stillActive.state).toBe('active');

  // Correct password unlocks cleanly!
  await pwInput.fill(secret);
  await overlay.getByRole('button', { name: 'Unlock' }).click();
  await expect(overlay).toBeHidden({ timeout: 15_000 });
  await expect.poll(async () => {
    const st = await execCmd(page, ['/usr/bin/service', '--json', 'status', 'greeter.service']);
    try { return JSON.parse(st.stdout).unit?.state; } catch { return null; }
  }, { timeout: 10_000 }).toBe('inactive');

  // Re-lock via Ctrl+Alt+L shortcut works too!
  await page.locator('.topbar').click({ position: { x: 200, y: 12 } });
  await page.keyboard.press('Control+Alt+KeyL');
  await expect(overlay).toBeVisible({ timeout: 15_000 });
  await expect(pwInput).toBeVisible({ timeout: 10_000 });
  await pwInput.fill(secret);
  await pwInput.press('Enter');
  await expect(overlay).toBeHidden({ timeout: 15_000 });
});

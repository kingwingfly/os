import { test, expect } from './test.js';
import { pagePut } from './ui.js';

const dock = (page, name) =>
  page.getByRole('navigation', { name: 'Dock' }).getByRole('button', { name, exact: true });

async function execCmd(page, argv, { sudo = false } = {}) {
  return page.evaluate(
    ({ argv, sudo }) => window.os.exec([argv], { stdin: '', sudo }),
    { argv, sudo },
  );
}

async function waitDesktopReady(page) {
  await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'idle', { timeout: 20_000 });
  await expect(page.locator('#window-terminal')).toHaveAttribute('style', /left/, { timeout: 20_000 });
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

test('1. default / boots compositor.service and desktop-shell.service supervised by init', async ({ page }) => {
  await page.goto('/');
  await waitDesktopReady(page);

  const compRes = await execCmd(page, ['/usr/bin/service', '--json', 'status', 'compositor.service']);
  expect(compRes.status).toBe(0);
  const comp = JSON.parse(compRes.stdout);
  expect(comp.unit.state).toBe('active');
  expect(comp.unit.pid).toBeGreaterThan(1);

  const shellRes = await execCmd(page, ['/usr/bin/service', '--user', '--json', 'status', 'desktop-shell.service']);
  expect(shellRes.status).toBe(0);
  const shell = JSON.parse(shellRes.stdout);
  expect(shell.unit.state).toBe('active');
  expect(shell.unit.pid).toBeGreaterThan(1);

  const psRes = await execCmd(page, ['/usr/bin/ps']);
  expect(psRes.status).toBe(0);
  expect(psRes.stdout).toContain('compositor');
  expect(psRes.stdout).toContain('desktop-shell');
});

test('2. terminal-only session (/shell.html) starts neither compositor nor desktop-shell', async ({ page }) => {
  await page.goto('/shell.html');
  const input = page.getByLabel('Shell input', { exact: true });
  const screen = page.locator('.terminal-screen');
  await expect(input).toBeEnabled({ timeout: 20_000 });
  await expect(screen).toContainText(/user@os:[^\n]* \$\s*$/, { timeout: 20_000 });

  await input.fill('service status compositor.service; service --user status desktop-shell.service');
  await input.press('Enter');
  await expect(screen).toContainText('Unit:    compositor.service', { timeout: 15_000 });
  await expect(screen).toContainText('Unit:    desktop-shell.service', { timeout: 15_000 });
  const out = await screen.innerText();
  expect(out).not.toContain('State:   active');
});

test('3. killing desktop-shell auto-restarts it under a new PID while open windows stay alive', async ({ page }) => {
  await page.goto('/');
  await waitDesktopReady(page);

  await pagePut(page, '/home/user/stay-alive.md', '# Alive\n\nSurvives shell restart.\n');
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  await input.fill('open /home/user/stay-alive.md');
  await input.press('Enter');
  await expect(page.locator('#viewer')).toBeVisible();
  await expect(dock(page, 'Preview')).toBeVisible();

  const before = JSON.parse(
    (await execCmd(page, ['/usr/bin/service', '--user', '--json', 'status', 'desktop-shell.service'])).stdout,
  ).unit;
  expect(before.state).toBe('active');
  const oldPid = before.pid;

  const killRes = await execCmd(page, ['/usr/bin/kill', '-9', String(oldPid)]);
  expect(killRes.status).toBe(0);

  // Open windows stay alive throughout restart and reconnect in the dock under a new shell PID.
  await expect(page.locator('#viewer')).toBeVisible();
  await expect(page.locator('#window-terminal')).toBeVisible();
  await expect(page.locator('.graphical-ended-banner')).toHaveCount(0);

  await expect.poll(async () => {
    const res = await execCmd(page, ['/usr/bin/service', '--user', '--json', 'status', 'desktop-shell.service']);
    try {
      const u = JSON.parse(res.stdout).unit;
      return u?.state === 'active' && u.pid !== oldPid ? u.pid : null;
    } catch {
      return null;
    }
  }, { timeout: 15_000 }).not.toBeNull();

  await expect(dock(page, 'Preview')).toBeVisible();
  await expect(dock(page, 'Terminal')).toBeVisible();
  await expect(dock(page, 'Files')).toBeVisible();
});

test('4. killing compositor ends only the graphical session and Restart graphical session recovers cleanly', async ({ page }) => {
  await page.goto('/');
  await waitDesktopReady(page);

  const beforeComp = JSON.parse(
    (await execCmd(page, ['/usr/bin/service', '--json', 'status', 'compositor.service'])).stdout,
  ).unit;
  expect(beforeComp.state).toBe('active');
  const oldCompPid = beforeComp.pid;

  const killRes = await execCmd(page, ['/usr/bin/kill', '-9', String(oldCompPid)], { sudo: true });
  expect(killRes.status).toBe(0);

  // Recovery banner appears, while mountd and non-graphical command execution remain alive!
  const banner = page.locator('.graphical-ended-banner');
  await expect(banner).toBeVisible({ timeout: 15_000 });
  const mountdRes = await execCmd(page, ['/usr/bin/service', '--json', 'status', 'mountd.service']);
  expect(JSON.parse(mountdRes.stdout).unit.state).toBe('active');
  const aliveCheck = await execCmd(page, ['/usr/bin/sh', '-c', 'echo STILL_ALIVE']);
  expect(aliveCheck.stdout.trim()).toBe('STILL_ALIVE');

  // Clicking "Restart graphical session" restores compositor + desktop-shell cleanly.
  await banner.getByRole('button', { name: 'Restart graphical session' }).click();
  await expect(banner).toBeHidden({ timeout: 20_000 });
  await waitDesktopReady(page);

  const afterComp = JSON.parse(
    (await execCmd(page, ['/usr/bin/service', '--json', 'status', 'compositor.service'])).stdout,
  ).unit;
  expect(afterComp.state).toBe('active');
  expect(afterComp.pid).not.toBe(oldCompPid);
  await expect(page.locator('#window-terminal')).toBeVisible();
  await expect(page.locator('#window-files')).toBeVisible();
});

test('5. unprivileged clients attempting privileged roles or SurfaceKind::Host receive EPERM', async ({ page }) => {
  await page.goto('/');
  await waitDesktopReady(page);

  for (const role of ['panel', 'background', 'launcher', 'lock', 'greeter']) {
    const req = JSON.stringify({
      op: 'create_surface',
      spec: {
        role,
        kind: 'pixel',
        title: 'Rogue',
        rect: { x: 0, y: 0, width: 200, height: 150 },
        min_size: { width: 100, height: 80 },
        max_size: null,
        resizable: true,
      },
    });
    const res = await execCmd(page, ['/usr/bin/gui-sample-doc', '--request', req]);
    expect(res.status).toBe(0);
    expect(JSON.parse(res.stdout.trim())).toEqual({ op: 'error', errno: 'EPERM' });
  }

  const hostReq = JSON.stringify({
    op: 'create_surface',
    spec: {
      role: 'window',
      kind: { host: { component: 'terminal' } },
      title: 'Spoofed',
      rect: { x: 0, y: 0, width: 300, height: 200 },
      min_size: { width: 100, height: 80 },
      max_size: null,
      resizable: true,
      app_id: 'terminal',
    },
  });
  const hostRes = await execCmd(page, ['/usr/bin/gui-sample-doc', '--request', hostReq]);
  expect(hostRes.status).toBe(0);
  expect(JSON.parse(hostRes.stdout.trim())).toEqual({ op: 'error', errno: 'EPERM' });

  // Manually launching /usr/bin/desktop-shell outside service supervision fails with EPERM.
  const rogueShell = await execCmd(page, ['/usr/bin/desktop-shell']);
  expect(rogueShell.status).not.toBe(0);
});

test('6. pre-seeded localStorage os-desktop migrates once into ~/.config/os/desktop-layout.json and persists across reload', async ({ page }) => {
  await page.goto('/');
  await page.evaluate(() => {
    localStorage.setItem('os-desktop', JSON.stringify({
      terminal: { x: 260, y: 24, w: 640, h: 420, place: 'free', minimized: false },
      files: { x: 16, y: 24, w: 320, h: 420, place: 'free', minimized: false },
    }));
  });
  await page.reload();
  await waitDesktopReady(page);

  // Legacy localStorage key is cleared after one-time conversion.
  await expect.poll(() => page.evaluate(() => localStorage.getItem('os-desktop')), { timeout: 15_000 }).toBeNull();

  // Persisted layout file exists in `~/.config/os/desktop-layout.json` with version 1 and seat0 coordinates.
  await expect.poll(async () => {
    const res = await execCmd(page, ['/usr/bin/cat', '/home/user/.config/os/desktop-layout.json']);
    if (res.status !== 0) return null;
    try { return JSON.parse(res.stdout); } catch { return null; }
  }, { timeout: 15_000 }).toMatchObject({
    version: 1,
    displays: {
      seat0: {
        terminal: { rect: { x: 260, y: 24, width: 640, height: 420 } },
      },
    },
  });

  // Reload without localStorage preserves the migrated window placement.
  await page.reload();
  await waitDesktopReady(page);
  const termBox = await page.locator('#window-terminal').evaluate(e => {
    const r = e.getBoundingClientRect();
    const a = document.querySelector('.desktop-area').getBoundingClientRect();
    return { x: Math.round(r.x - a.x), y: Math.round(r.y - a.y), w: Math.round(r.width), h: Math.round(r.height) };
  });
  expect(Math.abs(termBox.x - 260)).toBeLessThanOrEqual(2);
  expect(Math.abs(termBox.y - 24)).toBeLessThanOrEqual(2);
  expect(Math.abs(termBox.w - 640)).toBeLessThanOrEqual(2);
  expect(Math.abs(termBox.h - 420)).toBeLessThanOrEqual(2);
});

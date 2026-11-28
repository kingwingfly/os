import { test, expect } from './test.js';
import {
  browse,
  closePreview,
  filesFrame,
  filesSurface,
  pageMkdirp,
  pagePut,
  pageRmrf,
  previewFrame,
  previewSurface,
  runTerminal,
  settingsSurface,
  terminalSurface,
  waitForDesktopReady,
  waitForSettingsReady,
} from './ui.js';

const dock = (page, name) =>
  page.getByRole('navigation', { name: 'Dock' }).getByRole('button', { name, exact: true });

const box = async locator => {
  const b = await locator.boundingBox();
  expect(b).not.toBeNull();
  return b;
};

const zIndexOf = locator => locator.evaluate(el => Number(getComputedStyle(el).zIndex) || 0);

async function dragTitlebar(page, win, dx, dy) {
  const bar = await box(win.locator('.titlebar'));
  const sx = bar.x + bar.width / 2;
  const sy = bar.y + bar.height / 2;
  await page.mouse.move(sx, sy);
  await page.mouse.down();
  await page.mouse.move(sx + dx, sy + dy, { steps: 10 });
  await page.mouse.up();
}

test('overlapping window B absorbs the first content click to focus only, then handles the second click', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/');
  await waitForDesktopReady(page);

  const dir = '/home/user/overlap-guard-' + Date.now();
  await pageMkdirp(page, dir);
  await pagePut(page, `${dir}/click-guard.md`, '# Click Guard\n\nFirst click must only focus.\n');
  try {
    await browse(page, dir);
    const fileRow = filesFrame(page).locator('.files .file', { hasText: 'click-guard.md' });
    await expect(fileRow).toBeVisible();

    // Side-by-side non-overlapping windows are not obscured.
    await expect(filesSurface(page)).toHaveAttribute('data-obscured', 'false');
    await expect(terminalSurface(page)).toHaveAttribute('data-obscured', 'false');

    // Drag Terminal left so it clearly overlaps Files while leaving the left part of Files exposed.
    const fBox = await box(filesSurface(page));
    const tBox = await box(terminalSurface(page));
    const overlapShift = (fBox.x + fBox.width - 90) - tBox.x;
    await dragTitlebar(page, terminalSurface(page), overlapShift, 0);

    await expect(terminalSurface(page)).toHaveAttribute('data-focused', 'true');
    await expect(filesSurface(page)).toHaveAttribute('data-focused', 'false');
    await expect(filesSurface(page)).toHaveAttribute('data-obscured', 'true');
    await expect(filesSurface(page).locator('.focus-shield')).toBeVisible();
    expect(await zIndexOf(terminalSurface(page))).toBeGreaterThan(await zIndexOf(filesSurface(page)));

    // Pick a point on the exposed left portion of the clickable file row in Files.
    const rowBox = await box(fileRow);
    const tMoved = await box(terminalSurface(page));
    const clickX = Math.min(rowBox.x + 28, tMoved.x - 16);
    const clickY = rowBox.y + rowBox.height / 2;
    expect(clickX).toBeGreaterThan(rowBox.x);
    expect(clickX).toBeLessThan(tMoved.x);

    // 1st click on obscured window B: raises & focuses Files ONLY; does NOT open click-guard.md.
    await page.mouse.click(clickX, clickY);

    await expect(filesSurface(page)).toHaveAttribute('data-focused', 'true');
    await expect(filesSurface(page)).toHaveAttribute('data-obscured', 'false');
    await expect(filesSurface(page).locator('.focus-shield')).toBeHidden();
    await expect(terminalSurface(page)).toHaveAttribute('data-obscured', 'true');
    expect(await zIndexOf(filesSurface(page))).toBeGreaterThan(await zIndexOf(terminalSurface(page)));

    // Wait briefly and verify no accidental click-through opened Preview.
    await page.waitForTimeout(600);
    await expect(previewSurface(page)).toHaveCount(0);

    // 2nd click on now-focused Files DOES activate click-guard.md and opens Preview.
    await page.mouse.click(clickX, clickY);
    await expect(previewSurface(page)).toBeVisible({ timeout: 20_000 });
    await expect(previewFrame(page).locator('.markdown h1')).toHaveText('Click Guard', { timeout: 15_000 });
    await closePreview(page);
  } finally {
    await pageRmrf(page, dir).catch(() => {});
  }
});

test('lazy app launch and Tree-sitter syntax engine show clear loading indicators until ready', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/');
  await waitForDesktopReady(page);

  // 1. Slow the lazy Settings WASM binary so we can verify immediate Dock + top bar feedback.
  let releaseSettings = null;
  const settingsHold = new Promise(done => { releaseSettings = done; });
  const settingsIntercepted = new Promise(resolve => {
    void page.route('**/usr/bin/settings.wasm.rv1', async route => {
      resolve();
      await settingsHold;
      await route.continue();
    }, { times: 1 });
  });

  const settingsDockBtn = dock(page, 'Settings');
  await settingsDockBtn.click();

  await expect(settingsDockBtn).toHaveClass(/dock-launching/);
  await expect(settingsDockBtn).toHaveAttribute('aria-busy', 'true');
  await expect(page.locator('.topbar-loading-pill')).toBeVisible();
  await expect(page.locator('.topbar-loading-pill')).toContainText('Opening Settings…');
  await expect(page.locator('main.desktop')).toHaveClass(/desktop-busy/);

  await settingsIntercepted;
  releaseSettings?.();

  await waitForSettingsReady(page);
  await expect(settingsDockBtn).not.toHaveClass(/dock-launching/);
  await expect(settingsDockBtn).toHaveAttribute('aria-busy', 'false');
  await expect(page.locator('.topbar-loading-pill')).toHaveCount(0);
  await settingsSurface(page).getByRole('button', { name: 'Close', exact: true }).click();
  await expect(settingsSurface(page)).toHaveCount(0);

  // 2. Slow the lazy Systems Tree-sitter WASM worker and verify both Preview + top bar indicators.
  const rsPath = `/home/user/lazy-ts-${Date.now()}.rs`;
  await pagePut(page, rsPath, 'fn main() {\n    let answer = 42;\n    println!("{answer}");\n}\n');

  let releaseTreeSitter = null;
  const tsHold = new Promise(done => { releaseTreeSitter = done; });
  const tsIntercepted = new Promise(resolve => {
    void page.route('**/preview_code_systems_bg.wasm', async route => {
      resolve();
      await tsHold;
      await route.continue();
    }, { times: 1 });
  });

  try {
    await runTerminal(page, `open ${rsPath}`);
    await expect(previewSurface(page)).toBeVisible({ timeout: 20_000 });
    await tsIntercepted;

    // Preview inline badge + top bar pill both indicate lazy syntax engine loading.
    const viewerActivity = previewFrame(page).locator('#viewer-activity');
    await expect(viewerActivity).toBeVisible();
    await expect(viewerActivity).toContainText('Highlighting rust…');
    await expect(page.locator('.topbar-loading-pill')).toBeVisible();
    await expect(page.locator('.topbar-loading-pill')).toContainText('Loading Systems syntax engine…');

    releaseTreeSitter?.();

    // Once loaded, syntax spans appear and both loading indicators disappear cleanly.
    await expect(previewFrame(page).locator('.text-preview .hl-keyword').first()).toBeVisible({ timeout: 25_000 });
    await expect(viewerActivity).toBeHidden();
    await expect(page.locator('.topbar-loading-pill')).toHaveCount(0);
    await closePreview(page);
  } finally {
    releaseTreeSitter?.();
    await pageRmrf(page, rsPath).catch(() => {});
  }
});

test('rapid tap-then-drag and mid-drag lostpointercapture on titlebar still move windows reliably', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/');
  await waitForDesktopReady(page);

  const term = terminalSurface(page);
  const bar = term.locator('.titlebar');

  // 1. Rapid tap-then-drag (same pointerId=1, reproducing macOS trackpad tap-to-drag / quick click-then-drag
  // where the first tap's BeginInteractiveOp arrives after the second drag's PointerDown starts).
  for (let i = 0; i < 4; i++) {
    const startBox = await box(term);
    const barBox = await box(bar);
    const sx = barBox.x + barBox.width / 2;
    const sy = barBox.y + barBox.height / 2;
    const dx = i % 2 === 0 ? -90 : 90;
    const dy = i % 2 === 0 ? 35 : -35;

    // Quick tap immediately followed by a drag with zero pause.
    await page.mouse.move(sx, sy);
    await page.mouse.down();
    await page.mouse.up();
    await page.mouse.down();
    await page.mouse.move(sx + dx, sy + dy, { steps: 6 });
    await page.mouse.up();

    await expect.poll(async () => {
      const cur = await box(term);
      return Math.abs(cur.x - (startBox.x + dx)) <= 4 && Math.abs(cur.y - (startBox.y + dy)) <= 4;
    }, { timeout: 5_000 }).toBe(true);
  }

  // 2. Firing lostpointercapture on the titlebar mid-drag must NOT cancel/rollback the drag.
  const beforeLost = await box(term);
  const barBox = await box(bar);
  const sx = barBox.x + barBox.width / 2;
  const sy = barBox.y + barBox.height / 2;
  await page.mouse.move(sx, sy);
  await page.mouse.down();
  await page.mouse.move(sx - 60, sy + 20, { steps: 4 });
  await bar.evaluate(el => {
    el.dispatchEvent(new PointerEvent('lostpointercapture', { pointerId: 1, bubbles: true }));
  });
  await page.mouse.move(sx - 120, sy + 45, { steps: 4 });
  await page.mouse.up();

  await expect.poll(async () => {
    const cur = await box(term);
    return Math.abs(cur.x - (beforeLost.x - 120)) <= 4 && Math.abs(cur.y - (beforeLost.y + 45)) <= 4;
  }, { timeout: 5_000 }).toBe(true);
});

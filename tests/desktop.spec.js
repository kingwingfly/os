import { test, expect } from '@playwright/test';

// The desktop (crates/frontend/src/desktop.rs): windows a pointer moves, resizes and snaps, that
// minimize to the dock and come back, laid out again as they were after a reload; the preview a
// window among them; the launcher; and the keyboard's shortcuts.
const box = locator => locator.evaluate(e => { const r = e.getBoundingClientRect(); return { x: r.x, y: r.y, w: r.width, h: r.height }; });
// Within a pixel: the desktop lays windows out in fractions of one.
const near = (actual, expected) => { for (const [key, value] of Object.entries(expected)) expect(Math.abs(actual[key] - value), `${key}: ${actual[key]} ≉ ${value}`).toBeLessThan(1); };
const dock = (page, name) => page.getByRole('navigation', { name: 'Dock' }).getByRole('button', { name, exact: true });
const terminal = page => page.locator('#window-terminal');
const files = page => page.locator('#window-files');
async function drag(page, locator, dx, dy, at = 'bar') {
  const handle = at === 'bar' ? locator.locator('[data-window-bar]') : locator.locator('.window-resize-' + at);
  const from = await box(handle);
  // The middle, of a bar clear of its title and buttons.
  const x = from.x + from.w / 2, y = from.y + from.h / 2;
  await page.mouse.move(x, y); await page.mouse.down();
  await page.mouse.move(x + dx, y + dy, { steps: 6 }); await page.mouse.up();
}
async function ready(page) {
  await page.goto('/');
  await page.evaluate(() => localStorage.removeItem('terminal-desktop'));
  await page.reload();
  await expect(page.locator('.busy')).toHaveText('↵');
  await expect(terminal(page)).toHaveAttribute('style', /left/);
}

test('windows move, resize, snap, minimize to the dock, and keep their places', async ({ page }) => {
  await ready(page);
  const area = await box(page.locator('.desktop-area'));
  // Files to the left, the Terminal beside them, both in the dock; the Terminal has the keyboard.
  const [left, right] = [await box(files(page)), await box(terminal(page))];
  expect(left.x + left.w).toBeLessThan(right.x);
  await expect(dock(page, 'Terminal')).toHaveAttribute('aria-pressed', 'true');
  await expect(dock(page, 'Files')).toHaveAttribute('aria-pressed', 'false');
  await expect(page.getByRole('combobox', { name: 'Terminal command' })).toBeFocused();
  // Moved by its bar; resized by a corner, no smaller than its least.
  await drag(page, terminal(page), -200, -5);
  const moved = await box(terminal(page));
  near(moved, { x: right.x - 200, y: right.y - 5, w: right.w, h: right.h });
  await drag(page, terminal(page), -120, -80, 'se');
  near(await box(terminal(page)), { x: moved.x, y: moved.y, w: moved.w - 120, h: moved.h - 80 });
  await drag(page, terminal(page), -moved.w, -moved.h + 60, 'se');
  near(await box(terminal(page)), { w: 280, h: 180 });
  await drag(page, terminal(page), 400, 300, 'se');
  const free = await box(terminal(page));
  // A press on a window brings it up, and gives it the keyboard: typed there, nothing goes to
  // the terminal.
  await files(page).locator('.directory-bar').click({ position: { x: 5, y: 5 } });
  await expect(files(page)).toHaveClass(/window-focused/);
  await expect(dock(page, 'Files')).toHaveAttribute('aria-pressed', 'true');
  await expect(files(page)).toBeFocused();
  await page.keyboard.type('ls');
  await expect(page.getByRole('combobox', { name: 'Terminal command' })).toHaveValue('');
  // Let go at the top, it fills the desktop; dragged off, it is free again, at its own size.
  await drag(page, terminal(page), 0, area.y - free.y - 30);
  near(await box(terminal(page)), area);
  await expect(terminal(page)).toHaveClass(/window-filled/);
  await drag(page, terminal(page), 100, 200);
  near(await box(terminal(page)), { w: free.w, h: free.h });
  // At a side, that half; a double click on the bar fills it, another frees it, where it was
  // before it was dragged there.
  const before = await box(terminal(page)), bar = await box(terminal(page).locator('[data-window-bar]'));
  await drag(page, terminal(page), area.x + area.w - (bar.x + bar.w / 2) - 1, 0);
  near(await box(terminal(page)), { x: area.x + Math.floor(area.w / 2), w: area.w - Math.floor(area.w / 2), h: area.h });
  await terminal(page).locator('.window-title').dblclick();
  near(await box(terminal(page)), area);
  await terminal(page).locator('.window-title').dblclick();
  near(await box(terminal(page)), before);
  const kept = await box(terminal(page));
  // Minimized, the dock shows it open but not up; the dock brings it back.
  await page.getByRole('button', { name: 'Minimize Terminal' }).click();
  await expect(terminal(page)).toBeHidden();
  await expect(dock(page, 'Terminal')).toHaveClass(/dock-open/);
  await dock(page, 'Terminal').click();
  await expect(terminal(page)).toBeVisible();
  await expect(page.getByRole('combobox', { name: 'Terminal command' })).toBeFocused();
  // Closed, the Files come back from the dock too.
  await page.getByRole('button', { name: 'Close Files' }).click();
  await expect(files(page)).toBeHidden();
  await expect(dock(page, 'Files')).not.toHaveClass(/dock-open/);
  await dock(page, 'Files').click();
  await expect(files(page)).toBeVisible();
  // A reload lays them out as they were.
  await page.reload();
  await expect(page.locator('.busy')).toHaveText('↵');
  await expect(terminal(page)).toHaveAttribute('style', /left/);
  near(await box(terminal(page)), kept);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test('the preview is a window: it takes the keyboard, sits among the others, and Escape closes it', async ({ page }) => {
  await ready(page);
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  await input.fill('open welcome.md'); await input.press('Enter');
  const viewer = page.locator('#viewer');
  await expect(viewer).toBeVisible();
  await expect(viewer).toHaveClass(/window-focused/);
  await expect(dock(page, 'Preview')).toHaveAttribute('aria-pressed', 'true');
  expect(await page.evaluate(() => !!document.activeElement?.closest('#viewer'))).toBe(true);
  // Typing in the preview stays there; nothing modal: the terminal under it takes a click.
  await page.keyboard.type('xyz');
  await expect(input).toHaveValue('');
  await terminal(page).locator('.window-title').click();
  await expect(terminal(page)).toHaveClass(/window-focused/);
  await expect(viewer).toBeVisible();
  const z = locator => locator.evaluate(e => Number(getComputedStyle(e).zIndex));
  expect(await z(terminal(page))).toBeGreaterThan(await z(viewer));
  // Escape in the terminal leaves the preview; in the preview, closes it.
  await input.focus(); await page.keyboard.press('Escape');
  await expect(viewer).toBeVisible();
  await dock(page, 'Preview').click();
  await expect(viewer).toHaveClass(/window-focused/);
  await page.keyboard.press('Escape');
  await expect(viewer).toBeHidden();
  await expect(dock(page, 'Preview')).toHaveCount(0);
  // Its own place, as the others have: moved, it opens there again.
  await input.fill('open welcome.md'); await input.press('Enter');
  await expect(viewer).toBeVisible();
  const before = await box(viewer);
  await drag(page, viewer, 40, 30);
  await page.getByRole('button', { name: 'Close preview' }).click();
  await input.fill('open welcome.md'); await input.press('Enter');
  await expect(viewer).toBeVisible();
  near(await box(viewer), { x: before.x + 40, y: before.y + 30, w: before.w, h: before.h });
});

test('the launcher opens apps, and the keyboard places and cycles windows', async ({ page }) => {
  await ready(page);
  const area = await box(page.locator('.desktop-area'));
  await page.getByRole('button', { name: 'Applications' }).click();
  const menu = page.getByRole('menu', { name: 'Applications' });
  await expect(menu).toBeVisible();
  await menu.getByRole('menuitem', { name: 'Manual' }).click();
  await expect(menu).toBeHidden();
  await expect(page.locator('#viewer .manual')).toBeVisible();
  await page.getByRole('button', { name: 'Close preview' }).click();
  // Ctrl+Alt+Left: the focused window to the left half; Up fills; Down frees, then minimizes.
  await page.getByRole('combobox', { name: 'Terminal command' }).focus();
  await page.keyboard.press('Control+Alt+ArrowLeft');
  near(await box(terminal(page)), { x: area.x, w: Math.floor(area.w / 2), h: area.h });
  await page.keyboard.press('Control+Alt+ArrowUp');
  near(await box(terminal(page)), area);
  await page.keyboard.press('Control+Alt+ArrowDown');
  await expect(terminal(page)).not.toHaveClass(/window-filled/);
  await page.keyboard.press('Control+Alt+ArrowDown');
  await expect(terminal(page)).toBeHidden();
  await expect(files(page)).toHaveClass(/window-focused/);
  // Alt+`: the next window up.
  await dock(page, 'Terminal').click();
  await expect(terminal(page)).toHaveClass(/window-focused/);
  await page.keyboard.press('Alt+Backquote');
  await expect(files(page)).toHaveClass(/window-focused/);
  await page.keyboard.press('Alt+Backquote');
  await expect(terminal(page)).toHaveClass(/window-focused/);
});

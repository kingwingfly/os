import { test, expect } from './test.js';
import { filesFrame, filesSurface, pagePut, runTerminal, terminalInput, terminalScreen, terminalSurface, waitForDesktopReady } from './ui.js';

// The desktop (supervised compositor + desktop-shell): windows a pointer moves, resizes and snaps, that
// minimize to the dock and come back, laid out again as they were after a reload; the preview a
// window among them; the launcher; and the keyboard's shortcuts.
const box = locator => locator.evaluate(e => { const r = e.getBoundingClientRect(); return { x: r.x, y: r.y, w: r.width, h: r.height }; });
// Within a pixel: wait for the supervised compositor's geometry commit to land.
const near = async (locator, expected) => {
  await expect.poll(async () => {
    const actual = await box(locator);
    return Object.fromEntries(Object.keys(expected).map(key => [key, Math.abs(actual[key] - expected[key]) < 1]));
  }).toEqual(Object.fromEntries(Object.keys(expected).map(key => [key, true])));
};
const dock = (page, name) => page.getByRole('navigation', { name: 'Dock' }).getByRole('button', { name, exact: true });
const terminal = page => terminalSurface(page);
const files = page => filesSurface(page);
async function drag(page, locator, dx, dy, at = 'bar') {
  const isSurface = await locator.evaluate(el => el.classList.contains('surface'));
  const handle = at === 'bar'
    ? locator.locator(isSurface ? '.titlebar' : '[data-window-bar]')
    : locator.locator(isSurface ? `.resize[data-edge="${at}"]` : '.window-resize-' + at);
  const from = await box(handle);
  // The middle, of a bar clear of its title and buttons.
  const x = from.x + from.w / 2, y = from.y + from.h / 2;
  await page.mouse.move(x, y); await page.mouse.down();
  await page.mouse.move(x + dx, y + dy, { steps: 6 }); await page.mouse.up();
}
async function ready(page) {
  await page.goto('/');
  await page.evaluate(() => localStorage.removeItem('os-desktop'));
  await page.reload();
  await waitForDesktopReady(page);
}

test('windows move, resize, snap, minimize to the dock, and keep their places', async ({ page }) => {
  await ready(page);
  const area = await box(page.locator('.desktop-area'));
  // Files to the left, the Terminal beside them, both in the dock; the Terminal has the keyboard.
  const [left, right] = [await box(files(page)), await box(terminal(page))];
  expect(left.x + left.w).toBeLessThan(right.x);
  await expect(dock(page, 'Terminal')).toHaveAttribute('aria-pressed', 'true');
  await expect(dock(page, 'Files')).toHaveAttribute('aria-pressed', 'false');
  await expect(terminalInput(page)).toBeFocused();
  // Moved by its bar; resized by a corner, no smaller than its least.
  await drag(page, terminal(page), -200, -5);
  await near(terminal(page), { x: right.x - 200, y: right.y - 5, w: right.w, h: right.h });
  const moved = await box(terminal(page));
  await drag(page, terminal(page), -120, -80, 'se');
  await near(terminal(page), { x: moved.x, y: moved.y, w: moved.w - 120, h: moved.h - 80 });
  await drag(page, terminal(page), -moved.w, -moved.h + 60, 'se');
  await near(terminal(page), { w: 280, h: 180 });
  await drag(page, terminal(page), 400, 300, 'se');
  await near(terminal(page), { w: 680, h: 480 });
  const free = await box(terminal(page));
  // A press on a window brings it up, and gives it the keyboard: typed there, nothing goes to
  // the terminal.
  const beforeScreen = await terminalScreen(page).innerText();
  await filesFrame(page).locator('.directory-bar').click({ position: { x: 5, y: 5 } });
  await expect(files(page)).toHaveAttribute('data-focused', 'true');
  await expect(dock(page, 'Files')).toHaveAttribute('aria-pressed', 'true');
  await page.keyboard.type('ls');
  expect(await terminalScreen(page).innerText()).toBe(beforeScreen);
  // Let go at the top, it fills the desktop; dragged off, it is free again, at its own size.
  await drag(page, terminal(page), 0, area.y - free.y - 30);
  await near(terminal(page), area);
  await expect(terminal(page)).toHaveAttribute('data-filled', 'true');
  await drag(page, terminal(page), 100, 200);
  await near(terminal(page), { w: free.w, h: free.h });
  // At a side, that half; a double click on the bar fills it, another frees it, where it was
  // before it was dragged there.
  const before = await box(terminal(page)), bar = await box(terminal(page).locator('.titlebar'));
  await drag(page, terminal(page), area.x + area.w - (bar.x + bar.w / 2) - 1, 0);
  await near(terminal(page), { x: area.x + Math.floor(area.w / 2), w: area.w - Math.floor(area.w / 2), h: area.h });
  await terminal(page).locator('.title').dblclick();
  await near(terminal(page), area);
  await terminal(page).locator('.title').dblclick();
  await near(terminal(page), before);
  const kept = await box(terminal(page));
  // Minimized, the dock shows it open but not up; the dock brings it back.
  await terminal(page).getByRole('button', { name: 'Minimize' }).click();
  await expect(terminal(page)).toBeHidden();
  await expect(dock(page, 'Terminal')).toHaveClass(/dock-open/);
  await dock(page, 'Terminal').click();
  await expect(terminal(page)).toBeVisible();
  await expect(terminalInput(page)).toBeFocused();
  // Closed, the Files come back from the dock too.
  await files(page).getByRole('button', { name: 'Close' }).click();
  await expect(files(page)).toBeHidden();
  await expect(dock(page, 'Files')).not.toHaveClass(/dock-open/);
  await dock(page, 'Files').click();
  await expect(files(page)).toBeVisible();
  // A reload lays them out as they were.
  await page.reload();
  await waitForDesktopReady(page);
  await near(terminal(page), kept);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test('the preview is a window: it takes the keyboard, sits among the others, and Escape closes it', async ({ page }) => {
  await ready(page);
  await pagePut(page, '/home/user/welcome.md', '# Welcome\n\nLocal preview fixture.\n');
  await runTerminal(page, 'open /home/user/welcome.md');
  const viewer = page.locator('#viewer');
  await expect(viewer).toBeVisible();
  await expect(viewer).toHaveClass(/window-focused/);
  await expect(dock(page, 'Preview')).toHaveAttribute('aria-pressed', 'true');
  expect(await page.evaluate(() => !!document.activeElement?.closest('#viewer'))).toBe(true);
  // Typing in the preview stays there; nothing modal: the terminal under it takes a click.
  const screenBefore = await terminalScreen(page).innerText();
  await page.keyboard.type('xyz');
  expect(await terminalScreen(page).innerText()).toBe(screenBefore);
  await terminal(page).locator('.title').click();
  await expect(terminal(page)).toHaveAttribute('data-focused', 'true');
  await expect(viewer).toBeVisible();
  const z = locator => locator.evaluate(e => Number(getComputedStyle(e).zIndex));
  expect(await z(terminal(page))).toBeGreaterThan(await z(viewer));
  // Escape in the terminal leaves the preview; in the preview, closes it.
  await terminalInput(page).focus(); await page.keyboard.press('Escape');
  await expect(viewer).toBeVisible();
  await dock(page, 'Preview').click();
  await expect(viewer).toHaveClass(/window-focused/);
  await page.keyboard.press('Escape');
  await expect(viewer).toBeHidden();
  await expect(dock(page, 'Preview')).toHaveCount(0);
  // Its own place, as the others have: moved, it opens there again.
  await runTerminal(page, 'open /home/user/welcome.md');
  await expect(viewer).toBeVisible();
  await expect(viewer).toHaveClass(/window-focused/);
  const before = await box(viewer);
  await drag(page, viewer, 40, 30);
  await near(viewer, { x: before.x + 40, y: before.y + 30, w: before.w, h: before.h });
  await page.getByRole('button', { name: 'Close preview' }).click();
  await runTerminal(page, 'open /home/user/welcome.md');
  await expect(viewer).toBeVisible();
  await near(viewer, { x: before.x + 40, y: before.y + 30, w: before.w, h: before.h });
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
  await terminalInput(page).focus();
  await page.keyboard.press('Control+Alt+ArrowLeft');
  await near(terminal(page), { x: area.x, w: Math.floor(area.w / 2), h: area.h });
  await page.keyboard.press('Control+Alt+ArrowUp');
  await near(terminal(page), area);
  await page.keyboard.press('Control+Alt+ArrowDown');
  await expect(terminal(page)).not.toHaveAttribute('data-filled', 'true');
  await page.keyboard.press('Control+Alt+ArrowDown');
  await expect(terminal(page)).toBeHidden();
  await expect(files(page)).toHaveAttribute('data-focused', 'true');
  // Alt+`: the next window up.
  await dock(page, 'Terminal').click();
  await expect(terminal(page)).toHaveAttribute('data-focused', 'true');
  await page.keyboard.press('Alt+Backquote');
  await expect(files(page)).toHaveAttribute('data-focused', 'true');
  await page.keyboard.press('Alt+Backquote');
  await expect(terminal(page)).toHaveAttribute('data-focused', 'true');
});

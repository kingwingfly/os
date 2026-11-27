import { test, expect } from './test.js';
import { closePreview, pagePut, previewFrame, previewSurface, runTerminal, terminalInput, waitForTerminalReady } from './ui.js';

const FIXTURES = {
  'welcome.md': '# OS\n\nLocal offline OS.\n',
  'demo.slides.md': '# Slide 1\n\nWelcome to fullscreen slides.\n\nNote:\nSpeaker notes.\n\n---\n\n# One filesystem\n\nSecond slide content.\n',
};

async function open(page, path) {
  await page.goto('/');
  await waitForTerminalReady(page);
  if (FIXTURES[path]) {
    await pagePut(page, '/' + path, FIXTURES[path], { mode: 0o644, sudo: true });
  }
  await runTerminal(page, 'open ' + path);
  await expect(previewSurface(page)).toBeVisible();
}
async function enter(page) {
  const pf = previewFrame(page);
  await pf.getByRole('button', { name: 'Fullscreen', exact: true }).click();
  await expect.poll(() => page.evaluate(() => document.fullscreenElement?.dataset?.appId)).toBe('preview');
  await expect(pf.getByRole('button', { name: 'Exit fullscreen', exact: true })).toBeVisible();
  await expect(pf.locator('#fullscreen-error')).toBeHidden();
  await expect.poll(() => previewSurface(page).evaluate(el => {
    const box = el.getBoundingClientRect();
    return Math.abs(box.width - innerWidth) + Math.abs(box.height - innerHeight) + Math.abs(box.x) + Math.abs(box.y);
  })).toBeLessThan(3);
}

test('preview enters fullscreen, toggles out, and closes cleanly while fullscreen', async ({ page }) => {
  await open(page, 'welcome.md');
  const pf = previewFrame(page);
  await expect(pf.locator('.markdown h1')).toBeVisible();
  await enter(page);
  await pf.getByRole('button', { name: 'Exit fullscreen', exact: true }).click();
  await expect.poll(() => page.evaluate(() => document.fullscreenElement === null)).toBe(true);
  await expect(previewSurface(page)).toBeVisible();
  await enter(page);
  // A browser-initiated exit (such as Escape) must update the toolbar too.
  await page.evaluate(() => document.exitFullscreen());
  await expect(pf.getByRole('button', { name: 'Fullscreen', exact: true })).toBeVisible();
  await enter(page);
  await closePreview(page);
  await expect.poll(() => page.evaluate(() => document.fullscreenElement === null)).toBe(true);
  await expect(terminalInput(page)).toBeFocused();
});

test('slides remain interactive inside the fullscreen surface', async ({ page }) => {
  await open(page, 'demo.slides.md');
  const pf = previewFrame(page);
  await expect(pf.locator('.slides-current .slide:visible')).toBeVisible();
  const scale = () => pf.locator('.slides-current').evaluate(el => Number(getComputedStyle(el).getPropertyValue('--scale')));
  const windowed = await scale();
  await enter(page);
  // Full screen, the slides scale up to the space they have.
  await expect.poll(scale).toBeGreaterThan(windowed);
  // The bars float over the slides, and hide until the pointer moves; on a bar, they stay.
  const shown = () => pf.locator('.viewer-bar').evaluate(e => getComputedStyle(e).opacity);
  await expect.poll(() => pf.locator('.slides-bar').evaluate(e => getComputedStyle(e).position)).toBe('absolute');
  await page.mouse.move(640, 400);
  await expect.poll(shown, { timeout: 5000 }).toBe('0');
  await page.mouse.move(650, 410);
  await expect.poll(shown).toBe('1');
  await pf.locator('.viewer-bar').hover();
  await page.waitForTimeout(2500);
  expect(await shown()).toBe('1');
  await page.keyboard.press('ArrowRight');
  await expect(pf.locator('.slides-current .slide:visible')).toContainText('One filesystem');
  // The speaker view's clock is under no bar: it may be clicked, to start again, with the bars
  // shown.
  await page.mouse.move(640, 300);
  await pf.getByRole('button', { name: 'Speaker view' }).click();
  const clock = await pf.locator('.slides-elapsed').boundingBox();
  await page.mouse.move(clock.x + clock.width / 2, clock.y + clock.height / 2);
  await expect.poll(shown).toBe('1');
  expect(await pf.locator('.slides-elapsed').evaluate(el => {
    const r = el.getBoundingClientRect();
    return !!document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2)?.closest('.slides-elapsed');
  })).toBe(true);
  await closePreview(page);
  await expect.poll(() => page.evaluate(() => document.fullscreenElement === null)).toBe(true);
});

test('a rejected request explains the failure within the modal', async ({ page }) => {
  await open(page, 'welcome.md');
  const pf = previewFrame(page);
  await page.evaluate(() => {
    document.querySelector('.surface[data-app-id="preview"]').requestFullscreen = () =>
      Promise.reject(new DOMException('denied by test policy', 'NotAllowedError'));
  });
  await pf.getByRole('button', { name: 'Fullscreen', exact: true }).click();
  await expect(pf.locator('#fullscreen-error')).toBeVisible();
  await expect(pf.locator('#fullscreen-error')).toContainText('denied by test policy');
  await expect(pf.locator('#fullscreen-error')).not.toContainText('This browser does not support');
  await expect(previewSurface(page)).toBeVisible();
});

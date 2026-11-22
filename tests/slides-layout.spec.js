import { test, expect } from './test.js';
import { pageMkdirp, pagePut, pageRmrf } from './ui.js';

// Exercise the real Rust preview and shipped CSS on local os-cowfs without remote accounts or R2 uploads.
test('image-only slides fit the preview and fullscreen without shrinking into Markdown', async ({ page }) => {
  const base = '/home/user/slides-layout-' + Date.now().toString(36);
  const source = '![Wide slide](wide.svg)\n\nNote:\nSpeaker notes.\n\n---\n\n![Portrait slide](portrait.svg)\n\n---\n\nA caption ![Inline image](wide.svg)\n\n---\n\n# A heading\n\n![Illustration](wide.svg)\n';
  const svg = (w, h) => `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}"><rect width="100%" height="100%" fill="#091012"/><text x="60" y="120" fill="#76c2aa" font-size="64">Presentation frame</text></svg>`;
  await page.goto('/');
  await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'idle');
  await pageMkdirp(page, base, 0o755);
  try {
    await pagePut(page, base + '/fit.slides.md', source);
    await pagePut(page, base + '/wide.svg', svg(1600, 900));
    await pagePut(page, base + '/portrait.svg', svg(900, 1600));
    const input = page.getByRole('combobox', { name: 'Terminal command' });
    await input.fill('open ' + base + '/fit.slides.md'); await input.press('Enter');
    const slide = page.locator('.slides-current .slide:visible'), image = slide.locator('img');
    await expect(slide).toHaveClass(/slide-image/);
    const fitted = async () => {
      await expect.poll(() => image.evaluate(e => e.naturalWidth)).toBeGreaterThan(0);
      await expect.poll(() => image.evaluate(e => {
        const stage = e.closest('.enhanced').getBoundingClientRect(), frame = e.getBoundingClientRect();
        return Math.abs(frame.x - stage.x) + Math.abs(frame.y - stage.y) + Math.abs(frame.width - stage.width) + Math.abs(frame.height - stage.height);
      })).toBeLessThan(4);
      await expect(image).toHaveCSS('object-fit', 'contain');
      await expect.poll(() => slide.evaluate(e => getComputedStyle(e).zoom)).toBe('1');
      expect(await slide.evaluate(e => e.scrollHeight - e.clientHeight)).toBeLessThan(2);
    };
    for (const size of [{ width: 1920, height: 1080 }, { width: 1280, height: 800 }, { width: 390, height: 844 }]) {
      await page.setViewportSize(size); await fitted();
      await page.getByRole('button', { name: 'Fullscreen', exact: true }).click();
      await expect.poll(() => page.evaluate(() => document.fullscreenElement?.id)).toBe('viewer-surface');
      await fitted();
      if (size.width === 1920) expect((await image.boundingBox()).height).toBeGreaterThan(1000);
      await page.evaluate(() => document.exitFullscreen());
      await expect.poll(() => page.evaluate(() => document.fullscreenElement === null)).toBe(true);
    }
    await page.keyboard.press('ArrowRight'); await expect(image).toHaveAttribute('alt', 'Portrait slide'); await fitted();
    await page.keyboard.press('ArrowRight'); await expect(slide).not.toHaveClass(/slide-image/); await expect(slide).toContainText('A caption'); await expect(image).toHaveCSS('max-height', '460px');
    await page.keyboard.press('ArrowRight'); await expect(slide.locator('h1')).toHaveText('A heading'); await expect(slide).not.toHaveClass(/slide-image/);
  } finally {
    await pageRmrf(page, base).catch(() => {});
  }
});

import { test, expect } from './test.js';
import { pagePut, pageRmrf } from './ui.js';

test('uploaded manifests cannot select unregistered or prototype game entries', async ({ page }) => {
  const path = '/home/user/unregistered-' + Date.now().toString(36) + '.game';
  await page.goto('/');
  await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'idle');
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  try {
    for (const entry of ['signal', '__proto__', 'constructor', 'https://example.com/game.html']) {
      await pagePut(page, path, JSON.stringify({ engine: 'bevy', entry }), { mode: 0o644, overwrite: true });
      await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'idle');
      await input.fill('open ' + path); await input.press('Enter');
      await expect(page.locator('#viewer')).toBeVisible();
      await expect(page.locator('#viewer-content')).toContainText('Game entry is not registered');
      await expect(page.locator('#viewer iframe')).toHaveCount(0);
      await page.getByRole('button', { name: 'Close preview' }).click();
    }
  } finally {
    await pageRmrf(page, path).catch(() => {});
  }
});

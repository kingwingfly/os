import { test, expect } from '@playwright/test';
import { fakeKernel } from './sys.js';
test('uploaded manifests cannot select unregistered or prototype game entries', async ({ page }) => {
  await page.route('**/api/sys', fakeKernel({ '/unregistered.game': { size: 64 } }));
  await page.goto('/');
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  for (const entry of ['signal', '__proto__', 'constructor', 'https://example.com/game.html']) {
    await page.route('**/api/file?*', route => route.fulfill({ contentType: 'application/json', body: JSON.stringify({ engine: 'bevy', entry }) }));
    await input.fill('open /unregistered.game'); await input.press('Enter');
    await expect(page.locator('#viewer')).toBeVisible();
    await expect(page.locator('#viewer-content')).toContainText('Game entry is not registered');
    await expect(page.locator('#viewer iframe')).toHaveCount(0);
    await page.getByRole('button', { name: 'Close preview' }).click();
    await page.unroute('**/api/file?*');
  }
});

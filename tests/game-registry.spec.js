import { test, expect } from './test.js';
import { createFakeCloud } from './service-auth.js';
test('uploaded manifests cannot select unregistered or prototype game entries', async ({ page }) => {
  let manifestBody = JSON.stringify({ engine: 'bevy', entry: 'signal' });
  const cloud = createFakeCloud(() => ({
    '/unregistered.game': { content: manifestBody, contentType: 'application/json' },
  }));
  await page.route('**/api/sys', route => cloud.handleSys(route));
  await page.route('**/api/file?*', route => cloud.handleFile(route));
  await page.goto('/');
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  for (const entry of ['signal', '__proto__', 'constructor', 'https://example.com/game.html']) {
    manifestBody = JSON.stringify({ engine: 'bevy', entry });
    await input.fill('open /unregistered.game'); await input.press('Enter');
    await expect(page.locator('#viewer')).toBeVisible();
    await expect(page.locator('#viewer-content')).toContainText('Game entry is not registered');
    await expect(page.locator('#viewer iframe')).toHaveCount(0);
    await page.getByRole('button', { name: 'Close preview' }).click();
  }
});

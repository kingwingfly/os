import { test, expect } from './test.js';
import { pagePut, pageRmrf, runTerminal, waitForTerminalReady } from './ui.js';

test('uploaded manifests cannot select unregistered or prototype game entries', async ({ page }) => {
  const path = '/home/user/unregistered-' + Date.now().toString(36) + '.game';
  await page.goto('/');
  await waitForTerminalReady(page);
  try {
    for (const entry of ['signal', '__proto__', 'constructor', 'https://example.com/game.html']) {
      await pagePut(page, path, JSON.stringify({ engine: 'bevy', entry }), { mode: 0o644, overwrite: true });
      await runTerminal(page, 'open ' + path);
      await expect(page.locator('#viewer')).toBeVisible();
      await expect(page.locator('#viewer-content')).toContainText('Game entry is not registered');
      await expect(page.locator('#viewer iframe')).toHaveCount(0);
      await page.getByRole('button', { name: 'Close preview' }).click();
    }
  } finally {
    await pageRmrf(page, path).catch(() => {});
  }
});

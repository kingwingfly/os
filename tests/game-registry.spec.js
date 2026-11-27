import { test, expect } from './test.js';
import { closePreview, pagePut, pageRmrf, previewContent, previewFrame, previewSurface, runTerminal, waitForTerminalReady } from './ui.js';

test('uploaded manifests cannot select unregistered or prototype game entries', async ({ page }) => {
  const path = '/home/user/unregistered-' + Date.now().toString(36) + '.game';
  await page.goto('/');
  await waitForTerminalReady(page);
  try {
    for (const entry of ['signal', '__proto__', 'constructor', 'https://example.com/game.html']) {
      await pagePut(page, path, JSON.stringify({ engine: 'bevy', entry }), { mode: 0o644, overwrite: true });
      await runTerminal(page, 'open ' + path);
      await expect(previewSurface(page)).toBeVisible();
      await expect(previewContent(page)).toContainText('Game entry is not registered');
      await expect(previewSurface(page).locator('iframe.game-embed-frame')).toHaveCount(0);
      await expect(previewFrame(page).locator('iframe')).toHaveCount(0);
      await closePreview(page);
    }
  } finally {
    await pageRmrf(page, path).catch(() => {});
  }
});

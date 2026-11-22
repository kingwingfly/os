import { test, expect } from './test.js';
import { pagePut, pageRmrf } from './ui.js';

// Keep this regression independent of remote accounts, passwords and server state.
test('editor close restores actual typing after Escape, close button and discarded changes', async ({ page }) => {
  const path = '/home/user/focus-' + Date.now().toString(36) + '.txt';
  await page.goto('/');
  const input = page.locator('#command');
  const run = async command => {
    await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'idle');
    await input.fill(command);
    await input.press('Enter');
  };
  await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'idle');
  await pagePut(page, path, 'original text', { mode: 0o644 });
  try {
    for (const close of ['escape', 'button', 'discard']) {
      await run('vim ' + path);
      const editor = page.getByRole('textbox', { name: 'File contents' });
      await expect(editor).toBeVisible();
      await editor.fill('edited with ' + close);
      if (close === 'discard') {
        await page.keyboard.press('Escape');
        await expect(page.locator('#editor')).toBeVisible();
        await expect(page.locator('#editor-discard')).toBeVisible();
        await expect(input).not.toBeFocused();
        await page.locator('#editor-discard').click();
      } else {
        await page.keyboard.press('Control+s');
        await expect(page.locator('#editor-status')).toHaveText('Saved');
        if (close === 'escape') await page.keyboard.press('Escape');
        else await page.getByRole('button', { name: 'Close editor' }).click();
      }
      await expect(page.locator('#editor')).not.toBeVisible();
      await expect(input).toBeFocused();
      // focus() alone can pass while the browser still refuses native text input.
      // Deliberately avoid fill(), click() or Tab after closing the editor.
      await page.keyboard.type('pwd');
      await expect(input).toHaveValue('pwd');
      await page.keyboard.press('Enter');
      await expect(page.locator('.transcript pre').last()).toHaveText('/');
    }
  } finally {
    await pageRmrf(page, path).catch(() => {});
  }
});

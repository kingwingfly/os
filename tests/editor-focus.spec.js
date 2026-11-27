import { test, expect } from './test.js';
import {
  editorClose,
  editorContent,
  editorDiscard,
  editorStatus,
  editorSurface,
  pagePut,
  pageRmrf,
  runTerminal,
  terminalInput,
  terminalScreen,
  terminalViewport,
  waitForTerminalReady,
} from './ui.js';

// Keep this regression independent of remote accounts, passwords and server state.
test('editor close restores actual typing after Escape, close button and discarded changes', async ({ page }) => {
  const path = '/home/user/focus-' + Date.now().toString(36) + '.txt';
  await page.goto('/');
  await waitForTerminalReady(page);
  await pagePut(page, path, 'original text', { mode: 0o644 });
  try {
    for (const close of ['escape', 'button', 'discard']) {
      await runTerminal(page, 'vim ' + path, { wait: false });
      const editor = editorContent(page);
      await expect(editor).toBeVisible({ timeout: 15_000 });
      await editor.fill('edited with ' + close);
      if (close === 'discard') {
        await page.keyboard.press('Escape');
        await expect(editorSurface(page)).toBeVisible();
        await expect(editorDiscard(page)).toBeVisible();
        await expect(terminalInput(page)).not.toBeFocused();
        await editorDiscard(page).click();
      } else {
        await page.keyboard.press('Control+s');
        await expect(editorStatus(page)).toHaveText('Saved');
        if (close === 'escape') await page.keyboard.press('Escape');
        else await editorClose(page).click();
      }
      await expect(editorSurface(page)).not.toBeVisible();
      await expect(terminalViewport(page)).toHaveAttribute('data-state', 'idle', { timeout: 15_000 });
      await expect(terminalInput(page)).toBeFocused();
      // focus() alone can pass while the browser still refuses native text input.
      // Deliberately avoid fill(), click() or Tab after closing the editor.
      await page.keyboard.type(`echo FOCUS_${close}`);
      await page.keyboard.press('Enter');
      await expect(terminalScreen(page)).toContainText(`FOCUS_${close}`);
      await expect(terminalViewport(page)).toHaveAttribute('data-state', 'idle', { timeout: 15_000 });
    }
  } finally {
    await pageRmrf(page, path).catch(() => {});
  }
});

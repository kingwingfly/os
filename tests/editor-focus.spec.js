import { test, expect } from './test.js';
import { createFakeCloud } from './service-auth.js';

// Keep this regression independent of local accounts, passwords and stored files.
test('editor close restores actual typing after Escape, close button and discarded changes', async ({ page }) => {
  let content = 'original text';
  const cloud = createFakeCloud(
    () => ({ '/focus.txt': { content, mode: 0o644, user: 'editor', group: 'editor', uid: 1000, gid: 1000, contentType: 'text/plain' } }),
    {
      creds: {
        uid: 1000, gid: 1000, groups: [1000], user: 'editor', group: 'editor',
        group_names: ['editor'], home: '/', signed_in: true, can_sudo: false, sudo_active: false,
      },
      onWrite(_path, buf) { content = buf.toString('utf8'); },
    },
  );
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url());
    if (url.pathname === '/api/session') return route.fulfill({ json: { authenticated: true, username: 'editor', uid: 1000, home: '/', can_write: true } });
    if (url.pathname === '/api/sys') return cloud.handleSys(route);
    if (url.pathname === '/api/pwrite') return cloud.handlePwrite(route);
    if (url.pathname === '/api/file') return cloud.handleFile(route);
    return route.fulfill({ status: 404, json: { error: 'unexpected test request' } });
  });
  await page.goto('/');
  const input = page.locator('#command');
  const run = async command => { await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'idle');await input.fill(command);await input.press('Enter'); };
  for (const close of ['escape', 'button', 'discard']) {
    await run('vim /focus.txt');
    const editor = page.getByRole('textbox',{name:'File contents'});
    await expect(editor).toBeVisible();
    await editor.fill('edited with '+close);
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
      else await page.getByRole('button',{name:'Close editor'}).click();
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
});

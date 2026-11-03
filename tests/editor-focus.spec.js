import { test, expect } from '@playwright/test';
import { fakeKernel } from './sys.js';

// Keep this regression independent of local accounts, passwords and stored files.
test('editor close restores actual typing after Escape, close button and discarded changes', async ({ page }) => {
  let content = 'original text', revision = 1;
  const entry = () => ({name:'focus.txt',path:'/focus.txt',directory:false,kind:'text',size:content.length,mode:420,owner:'editor',group:'editor',readable:true,writable:true});
  await page.route('**/api/**', async route => {
    const request = route.request(), url = new URL(request.url());
    if (url.pathname === '/api/session') return route.fulfill({json:{authenticated:true,username:'editor',uid:1000,home:'/',can_write:true}});
    if (url.pathname === '/api/sys') {
      // A save: open, a pwrite, close, which makes the new version.
      const [name] = Object.keys(JSON.parse(request.postData()).calls[0]);
      if (name === 'open') return route.fulfill({json:{results:[{ok:{fd:3,size:0,chunk_size:8388608}}]}});
      if (name === 'close') { revision++; return route.fulfill({json:{results:[{ok:{path:'/focus.txt',size:content.length,version:`"${revision}"`}}]}}); }
      return fakeKernel(() => ({'/focus.txt': {size: content.length, user: 'editor'}}))(route);
    }
    if (url.pathname === '/api/pwrite') { content = request.postData(); return route.fulfill({json:{committed:0}}); }
    if (url.pathname === '/api/file') return route.fulfill({body:request.method() === 'HEAD' ? '' : content,headers:{'Content-Type':'text/plain','ETag':`"${revision}"`}});
    return route.fulfill({status:404,json:{error:'unexpected test request'}});
  });
  await page.goto('/');
  const input = page.locator('#command');
  const run = async command => { await expect(page.locator('.busy')).toHaveText('↵');await input.fill(command);await input.press('Enter'); };
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

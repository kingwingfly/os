import { test, expect } from './storage-test.js';

async function mountForm(page) {
  await page.goto('/'); await expect(page.locator('.files-mounts')).toBeVisible();
  await page.evaluate(() => window.os.localMounts());
  await page.locator('#window-mounts').getByRole('tab', { name: 'Add mount', exact: true }).click();
  return page.locator('#window-mounts');
}

test('source choices use the desktop menu, preserve change handlers and support keyboard cancellation', async ({ page }) => {
  const app = await mountForm(page), source = app.getByRole('combobox', { name: 'Source', exact: true });
  await expect(source).toHaveText('Host folder⌄'); await source.click();
  const menu = page.getByRole('listbox', { name: 'Source', exact: true });
  await expect(menu).toBeVisible(); await expect(menu).toHaveClass('os-select-menu');
  expect(await menu.evaluate(e => getComputedStyle(e).backgroundColor)).toBe('rgb(17, 29, 22)');
  await expect(menu.getByRole('option', { name: 'Host folder', exact: true })).toHaveAttribute('aria-selected', 'true');
  await source.press('ArrowDown'); await source.press('Escape');
  await expect(menu).toHaveCount(0); await expect(source).toContainText('Host folder'); await expect(source).toBeFocused();
  await source.press('Enter'); await source.press('End'); await source.press('Enter');
  await expect(source).toContainText('Browser storage'); await expect(app.locator('[name=kind]')).toHaveValue('storage');
  await expect(app.getByRole('button', { name: 'Mount storage', exact: true })).toBeVisible();
  await source.press('h'); await expect(source).toContainText('Host folder');
  await source.click(); await page.getByRole('option', { name: 'Browser storage', exact: true }).click();
  await expect(source).toContainText('Browser storage');
});

test('menus stay within a narrow viewport, close on outside click and follow the selected value after reset', async ({ page }) => {
  const app = await mountForm(page); await page.setViewportSize({ width: 390, height: 844 });
  const source = app.getByRole('combobox', { name: 'Source', exact: true }); await source.click();
  const menu = page.getByRole('listbox', { name: 'Source', exact: true });
  const geometry = await menu.evaluate(e => { const r = e.getBoundingClientRect(); return { left: r.left, right: r.right, top: r.top, bottom: r.bottom, width: innerWidth, height: innerHeight }; });
  expect(geometry.left).toBeGreaterThanOrEqual(0); expect(geometry.right).toBeLessThanOrEqual(geometry.width);
  expect(geometry.top).toBeGreaterThanOrEqual(0); expect(geometry.bottom).toBeLessThanOrEqual(geometry.height);
  await app.getByRole('heading', { name: 'Add a filesystem', exact: true }).click(); await expect(menu).toHaveCount(0);
  await app.locator('[name=kind]').selectOption('storage'); await expect(source).toContainText('Browser storage');
  await page.evaluate(() => dispatchEvent(new Event('os:login-changed'))); await expect(source).toContainText('Host folder');
});

test('the same dropdown works inside a modal, including disabled options and dynamic choices', async ({ page }) => {
  await mountForm(page);
  await page.evaluate(() => {
    const dialog = document.createElement('dialog'); dialog.id = 'select-test-dialog';
    dialog.innerHTML = '<form><label>Transport<select name="transport"><option value="one">One</option><option value="two" disabled>Two</option><option value="three">Three</option></select></label><button type="button">Next control</button></form>';
    document.body.append(dialog); dialog.showModal();
    dialog.querySelector('select').onchange = event => { window.selectedTransport = event.target.value; };
  });
  const dialog = page.locator('#select-test-dialog'), source = dialog.getByRole('combobox', { name: 'Transport', exact: true });
  await source.click(); await source.press('ArrowDown'); await source.press('Tab');
  expect(await page.evaluate(() => window.selectedTransport)).toBe('three'); await expect(dialog.getByRole('button', { name: 'Next control' })).toBeFocused();
  await dialog.locator('select').evaluate(select => { select.replaceChildren(new Option('Replacement', 'new'), new Option('Another', 'another')); });
  await expect(source).toContainText('Replacement'); await source.click();
  await page.getByRole('option', { name: 'Another', exact: true }).click(); expect(await page.evaluate(() => window.selectedTransport)).toBe('another');
  await dialog.locator('select').evaluate(select => { select.value = 'new'; }); await expect(source).toContainText('Replacement');
  expect(await page.evaluate(() => window.selectedTransport)).toBe('another'); // State restoration is not a user change.
  await dialog.locator('select').evaluate(select => { select.selectedIndex = 1; }); await expect(source).toContainText('Another');
  await source.click(); await dialog.evaluate(dialog => dialog.close()); await expect(page.locator('.os-select-menu')).toHaveCount(0);
});

test('unsupported browsers explain the API gap and recommend another browser before the renamed helper', async ({ page, browserName }) => {
  await page.addInitScript(() => { window.showDirectoryPicker = undefined; });
  const app = await mountForm(page), message = app.locator('[data-browser-limitation]');
  await expect(message).toContainText('directory picker API');
  if (browserName === 'firefox') await expect(message).toContainText('Firefox');
  if (browserName === 'webkit') await expect(message).toContainText('Safari');
  await expect(app.locator('[data-helper]')).toContainText('Chrome or Edge on macOS, Windows or Linux');
  await expect(app.locator('[data-helper-command]')).toContainText('os-local-helper --root');
  await expect(app.locator('[data-helper]')).not.toContainText('os-local-fs');
  await expect(app.locator('[data-helper]')).toContainText('currently Linux only');
});

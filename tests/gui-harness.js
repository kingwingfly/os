import { expect } from './test.js';

export const documentWindow = page => page.locator('section[data-role="window"]').filter({ has: page.locator('iframe') }).first();
export const pixelWindow = page => page.locator('section[data-role="window"]').filter({ has: page.locator('canvas') }).first();

export async function openGui(page, query = '') {
  await page.goto('/gui-session.html' + query);
  await page.waitForFunction(() => window.guiSession?.compositorPid > 0, null, { timeout: 45000 });
  await expect(documentWindow(page).frameLocator('iframe').getByLabel('Document text')).toBeVisible({ timeout: 45000 });
  await expect(pixelWindow(page).locator('[aria-live]')).toHaveText(/Rendered generation/, { timeout: 45000 });
  await page.evaluate(() => {
    window.guiExits = [];
    window.guiSession.events('gui-exit', value => window.guiExits.push(value));
  });
}
export const launch = (page, program, argv = []) => page.evaluate(
  args => window.guiSession.call('gui_start', args), { program, argv });
export const stop = (page, pid) => page.evaluate(pid => window.guiSession.call('gui_stop', { pid }), pid);
export async function exitOf(page, pid) {
  const result = await page.waitForFunction(pid => window.guiExits.find(e => e.pid === pid), pid);
  return result.jsonValue();
}
export async function probe(page, req) {
  const response = await exitOf(page, await launch(page, 'gui-sample-doc', ['--request', JSON.stringify(req)]));
  expect(response.status).toBe(0);
  return JSON.parse(response.stdout);
}
export async function beginDrag(page, handle) {
  const box = await handle.boundingBox();
  const x = box.x + Math.min(35, box.width / 2), y = box.y + box.height / 2;
  await page.mouse.move(x, y);
  await page.mouse.down();
  await page.waitForFunction(() => !!window.guiSession.adapter.drag?.lease);
  return { x, y };
}
export const finishDrag = async page => {
  await page.mouse.up();
  await page.waitForFunction(() => !window.guiSession.adapter.drag);
};

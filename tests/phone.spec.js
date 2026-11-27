import { test, expect, devices } from './test.js';
import { readFile } from 'node:fs/promises';
import {
  browse,
  filesFrame,
  filesLocation,
  filesProgress,
  filesSurface,
  pageMkdirp,
  pagePut,
  pageRmrf,
  previewFrame,
  previewSurface,
  promptPath,
  terminalFrame,
  terminalInput,
  terminalScreen,
  terminalSurface,
  terminalViewport,
  waitForTerminalReady,
} from './ui.js';

const { defaultBrowserType, ...pixel } = devices['Pixel 7'];
test.use(pixel);

let base;
async function initPhone(page) {
  base = '/home/user/phone-' + Date.now().toString(36);
  await page.goto('/');
  await waitForTerminalReady(page);
  await pageMkdirp(page, base, 0o755);
}
test.afterEach(async ({ page }) => {
  if (base) await pageRmrf(page, base, { sudo: true }).catch(() => {});
});
const dock = (page, name) => page.getByRole('navigation', { name: 'Dock' }).getByRole('button', { name, exact: true });

test('a phone shows the terminal as an app that keeps its command line above the keyboard', async ({ page }) => {
  await initPhone(page);
  const input = terminalInput(page);
  // The wallpaper gives way, and the terminal fills the desktop alone; the account stays on
  // one line.
  await expect(page.locator('.intro')).toBeHidden();
  await expect(filesSurface(page)).toBeHidden();
  await expect(page.getByRole('navigation', { name: 'Dock' })).toBeVisible();
  expect(await page.locator('.cloud-panel-trigger').evaluate(e => e.getBoundingClientRect().height)).toBeLessThan(60);
  const bottom = async () => { const box = await input.boundingBox(); return box.y + box.height; };
  expect(await bottom()).toBeLessThanOrEqual(page.viewportSize().height);
  // Nothing types capitals or corrections into commands.
  await expect(input).toHaveAttribute('autocapitalize', 'off');
  await expect(input).toHaveAttribute('autocorrect', 'off');
  // ls writes to the same terminal grid as other executables, within the phone viewport.
  await input.tap(); await input.fill('ls -l /'); await input.press('Enter');
  const screen = terminalScreen(page);
  await expect(screen).toContainText('drwx');
  await expect(terminalViewport(page)).toHaveAttribute('data-state', 'idle');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  // The keyboard takes half the screen: the header and the files make room, and the command
  // line stays in what is left (app.js keeps --app-height as the visible height).
  await page.evaluate(() => { document.documentElement.style.setProperty('--app-height', '400px'); document.documentElement.classList.add('keyboard'); });
  await expect(page.locator('header.topbar')).toBeHidden();
  await expect(filesSurface(page)).toBeHidden();
  // The desktop lays its window out again as the area resizes, the next frame.
  await expect.poll(bottom).toBeLessThanOrEqual(400);
  // A tap on the transcript goes to the command line.
  await input.blur();
  await terminalViewport(page).tap();
  await expect(input).toBeFocused();
});

test('keys a phone lacks are buttons, and Upload opens the chooser at once, before any request', async ({ page }) => {
  await initPhone(page);
  const frame = terminalFrame(page);
  const input = terminalInput(page);
  const screen = terminalScreen(page);
  await input.fill('cd ' + base); await input.press('Enter');
  await expect(promptPath(page)).toHaveText(base);
  // Tab completes, ↑ recalls, ^C clears.
  await input.fill('mkd');
  await frame.getByRole('button', { name: 'Tab: complete' }).tap();
  await expect(screen).toContainText('mkdir', { timeout: 15_000 });
  await frame.getByRole('button', { name: 'Ctrl+C: stop' }).tap();
  await expect(screen).toContainText('^C');
  await frame.getByRole('button', { name: 'Previous command' }).tap();
  await expect(screen).toContainText('cd ' + base);
  await frame.getByRole('button', { name: 'Ctrl+C: stop' }).tap();
  await dock(page, 'Files').tap();
  await browse(page, base);
  // Phones open a chooser only while the tap is fresh: a slow server must not delay it.
  await page.route('**/api/sys', async route => { await new Promise(r => setTimeout(r, 3000)); await route.continue(); });
  const chooser = page.waitForEvent('filechooser', { timeout: 1000 });
  await filesFrame(page).getByRole('button', { name: 'Upload' }).tap();
  await (await chooser).setFiles({ name: 'photo.png', mimeType: 'image/png', buffer: await readFile('tests/fixtures/pixel.png') });
  await page.unroute('**/api/sys');
  // What it says, it says in the Files.
  await expect(filesProgress(page)).toContainText('✓ photo.png', { timeout: 20_000 });
});

test('long names keep one line and scroll; titles keep the file name; the dock switches windows; Escape closes only the dialog', async ({ page }) => {
  await initPhone(page);
  const long = 'a-very-long-file-name-that-does-not-fit-on-a-phone-screen-at-all.txt';
  await pagePut(page, base + '/' + long, 'long\n', { mode: 0o644 });
  await dock(page, 'Files').tap();
  await browse(page, base);
  // One line, sliding to show the rest: a touch screen points at nothing to wait for.
  const name = filesFrame(page).locator('.files .filename', { hasText: long });
  await expect(name).toHaveAttribute('data-overflow', '');
  expect(await name.evaluate(e => e.getBoundingClientRect().height)).toBeLessThan(40);
  expect(await name.locator('.filename-text').evaluate(e => getComputedStyle(e).animationName)).toBe('name-scroll');
  // A title too long for the bar keeps its end, the file name, in view.
  await name.tap();
  const pf = previewFrame(page);
  await expect(pf.locator('#viewer-title')).toHaveText(base + '/' + long);
  const [title, text] = await pf.locator('#viewer-title').evaluate(e => [e.getBoundingClientRect(), e.firstElementChild.getBoundingClientRect()].map(r => [r.left, r.right]));
  expect(text[1]).toBeLessThanOrEqual(title[1] + 1); expect(text[0]).toBeLessThan(title[0]);
  expect(await pf.locator('.viewer-bar').evaluate(e => e.scrollWidth <= e.clientWidth)).toBe(true);
  // The download button shows too, small, within the bar, framed as the bar's other buttons are.
  await expect(pf.getByRole('button', { name: 'Download' })).toBeVisible();
  const [bar, link] = await pf.locator('.viewer-bar').evaluate(el => [el, document.getElementById('download')].map(e => e.getBoundingClientRect().right));
  expect(link).toBeLessThanOrEqual(bar);
  const frame = element => pf.locator(element).evaluate(e => { const style = getComputedStyle(e); return [style.borderTopStyle, style.borderTopWidth, Math.round(e.getBoundingClientRect().height)]; });
  expect(await frame('#download')).toEqual(await frame('#close-viewer'));
  // Escape closes the preview without leaking an un-prevented Escape to the host page.
  await page.evaluate(() => { window.hostEscapeLeaked = false; window.addEventListener('keydown', e => { if (e.key === 'Escape' && !e.defaultPrevented) window.hostEscapeLeaked = true; }); });
  await page.keyboard.press('Escape');
  await expect(previewSurface(page)).toBeHidden();
  expect(await page.evaluate(() => window.hostEscapeLeaked)).toBe(false);
  // One window at a time, filling the screen: the dock goes from one to another, and
  // minimizing the one shown shows the next.
  const files = filesSurface(page), terminal = terminalSurface(page);
  await expect(files).toBeVisible(); await expect(terminal).toBeHidden();
  await dock(page, 'Terminal').tap();
  await expect(terminal).toBeVisible(); await expect(files).toBeHidden();
  expect(await terminal.evaluate(e => e.getBoundingClientRect().width)).toBe(page.viewportSize().width);
  await terminal.getByRole('button', { name: 'Minimize' }).tap();
  await expect(files).toBeVisible(); await expect(terminal).toBeHidden();
  await dock(page, 'Terminal').tap();
  await expect(terminal).toBeVisible();
});

test('a tap on the files opens what it means, in the Files, without the terminal or its keyboard', async ({ page }) => {
  await initPhone(page);
  await pageMkdirp(page, base + '/docs', 0o755);
  await dock(page, 'Files').tap();
  await browse(page, base);
  await filesLocation(page).blur();
  // The directory opens; the command line, and so the on-screen keyboard, stays closed, and
  // the terminal hears nothing of it.
  await filesFrame(page).locator('.files .file', { hasText: 'docs' }).tap();
  await expect(filesLocation(page)).toHaveValue(base + '/docs');
  await expect(terminalSurface(page)).toBeHidden();
  expect(await page.evaluate(() => document.activeElement !== document.querySelector('.surface[data-app-id="terminal"] iframe'))).toBe(true);
  await expect(filesLocation(page)).not.toBeFocused();
  await dock(page, 'Terminal').tap();
  await expect(terminalScreen(page)).not.toContainText('cd ');
});

import { test, expect } from './test.js';
import binaryen from 'binaryen';
import {
  browse,
  filesFrame,
  pageCall,
  pageMkdirp,
  pagePut,
  pageRmrf,
  previewSurface,
  runTerminal,
  terminalInput,
  terminalScreen,
  terminalTabs,
  terminalViewport,
  waitForTerminalReady,
} from './ui.js';

const module = binaryen.parseText(`(module
  (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 32) "CLICKED_WASM\\0a")
  (func (export "_start")
    (i32.store (i32.const 0) (i32.const 32))
    (i32.store (i32.const 4) (i32.const 13))
    (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))))`);
const wasm = Buffer.from(module.emitBinary()); module.dispose();
const interactiveModule = binaryen.parseText(`(module
  (import "wasi_snapshot_preview1" "fd_read" (func $read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    (i32.store (i32.const 0) (i32.const 32))
    (i32.store (i32.const 4) (i32.const 64))
    (drop (call $read (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 8)))
    (i32.store (i32.const 4) (i32.load (i32.const 8)))
    (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))))`);
const interactive = Buffer.from(interactiveModule.emitBinary()); interactiveModule.dispose();
let base;
test.beforeEach(async ({ page }) => {
  base = '/home/user/launch-' + crypto.randomUUID();
  await page.goto('/');
  await waitForTerminalReady(page);
  await pageMkdirp(page, base, 0o755);
  for (const [name, mode] of [['demo-a.wasm', 0o755], ['demo-b.wasm', 0o755], ['run "me".wasm', 0o755], ['locked.wasm', 0o644], ['execute-only.wasm', 0o111], ['input.wasm', 0o755]]) {
    const path = `${base}/${name}`;
    await pagePut(page, path, name === 'input.wasm' ? interactive : wasm, { mode: 0o644 });
    expect(await pageCall(page, { chmod: { path, mode } })).toBeNull();
  }
  await runTerminal(page, 'cd ' + base);
});
test.afterEach(async ({ page }) => {
  if (base) await pageRmrf(page, base, { sudo: true }).catch(() => {});
});

test('choosing a WASM completion inserts an executable path and Enter runs it', async ({ page }) => {
  const input = terminalInput(page);
  await input.fill('demo'); await input.press('Tab');
  await expect(terminalScreen(page)).toContainText('demo-a.wasm');
  await input.press('Tab');
  await input.press('Enter');
  await expect(previewSurface(page)).not.toBeVisible();
  await expect(terminalScreen(page)).toContainText('CLICKED_WASM', { timeout: 15_000 });
  await expect(terminalViewport(page)).toHaveAttribute('data-state', 'idle', { timeout: 15_000 });
});

test('Files launches quoted program paths in a new terminal tab and honors execute permissions', async ({ page }) => {
  await browse(page, base);
  await terminalInput(page).fill('echo unfinished');
  await filesFrame(page).locator('.file').filter({ hasText: 'run "me".wasm' }).click();
  await expect(terminalTabs(page)).toHaveCount(2, { timeout: 15_000 });
  await expect(terminalScreen(page)).toContainText('CLICKED_WASM', { timeout: 15_000 });
  await expect(previewSurface(page)).not.toBeVisible();
  await filesFrame(page).locator('.file').filter({ hasText: 'locked.wasm' }).click();
  await expect(terminalScreen(page)).toContainText(/Permission denied|Failed/i, { timeout: 15_000 });
  expect((await pageCall(page, { stat: { path: base + '/locked.wasm' } })).mode & 0o777).toBe(0o644);
  await filesFrame(page).locator('.file').filter({ hasText: 'execute-only.wasm' }).click();
  await expect(terminalScreen(page)).toContainText('CLICKED_WASM', { timeout: 15_000 });
  await expect(previewSurface(page)).not.toBeVisible();
});

test('clicking an interactive program gives it keyboard focus immediately', async ({ page }) => {
  await browse(page, base);
  await filesFrame(page).locator('.file').filter({ hasText: 'input.wasm' }).click();
  await expect(terminalTabs(page)).toHaveCount(2, { timeout: 15_000 });
  await expect(terminalInput(page)).toBeFocused();
  await page.keyboard.type('hello'); await page.keyboard.press('Enter');
  await expect(terminalScreen(page)).toContainText('hello\nhello', { timeout: 15_000 });
  await expect(previewSurface(page)).not.toBeVisible();
});

import { test, expect } from './test.js';
import binaryen from 'binaryen';
import { readFile } from 'node:fs/promises';
import { api, mkdirp, put, rmrf, call as sysCall } from './sys.js';
import { browse } from './ui.js';

const origin = process.env.TERMINAL_TEST_URL || 'http://127.0.0.1:8787', headers = { Origin: origin };
const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
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
const input = page => page.getByRole('combobox', { name: 'Terminal command' });
const busy = page => input(page).locator('xpath=ancestor::form');
const last = page => page.locator('.terminal-panel:not([hidden]) .transcript pre').last();
let base;
test.beforeEach(async ({ request, page }) => {
  base = '/launch-' + crypto.randomUUID();
  expect((await api(request, 'login', { headers, data: { password } })).ok()).toBe(true);
  await mkdirp(request, base);
  for (const [name, mode] of [['demo-a.wasm', 0o755], ['demo-b.wasm', 0o755], ['run "me".wasm', 0o755], ['locked.wasm', 0o644], ['execute-only.wasm', 0o111], ['input.wasm', 0o755]]) {
    const path = `${base}/${name}`;
    expect((await put(request, '/api/file?path=' + encodeURIComponent(path), { headers, data: name === 'input.wasm' ? interactive : wasm })).status()).toBe(201);
    expect(await sysCall(request, { chmod: { path, mode } }, { headers })).toBeNull();
  }
  await page.goto('/');
  await expect(busy(page)).toHaveAttribute('data-state', 'idle');
  await input(page).fill('cd ' + base); await input(page).press('Enter');
  await expect(busy(page)).toHaveAttribute('data-state', 'idle');
});
test.afterEach(async ({ request }) => { await rmrf(request, base); });

test('choosing a WASM completion inserts an executable path and Enter runs it', async ({ page }) => {
  await input(page).fill('demo'); await input(page).press('Tab');
  const options = page.getByRole('option'); await expect(options).toHaveCount(2);
  await options.filter({ hasText: 'demo-a.wasm' }).click();
  await expect(input(page)).toHaveValue('./demo-a.wasm ');
  await expect(page.locator('#viewer')).not.toBeVisible();
  await input(page).press('Enter');
  await expect(last(page)).toHaveText('CLICKED_WASM');
  await expect(busy(page)).toHaveAttribute('data-state', 'idle');
});

test('Files launches quoted program paths, preserves unfinished input, and honors execute permissions', async ({ page, request }) => {
  await browse(page, base);
  await input(page).fill('echo unfinished');
  await page.locator('#window-files .file').filter({ hasText: 'run "me".wasm' }).click();
  await expect(last(page)).toHaveText('CLICKED_WASM');
  await expect(page.locator('#viewer')).not.toBeVisible();
  await expect(page.locator('.terminal-panel[hidden] .command-input')).toHaveValue('echo unfinished');
  await expect(busy(page)).toHaveAttribute('data-state', 'idle');
  await page.locator('#window-files .file').filter({ hasText: 'locked.wasm' }).click();
  await expect(last(page)).toContainText('Permission denied');
  expect((await sysCall(request, { stat: { path: base + '/locked.wasm' } }, { headers })).mode & 0o777).toBe(0o644);
  await page.locator('#window-files .file').filter({ hasText: 'execute-only.wasm' }).click();
  await expect(last(page)).toHaveText('CLICKED_WASM');
  await expect(page.locator('#viewer')).not.toBeVisible();
});


test('clicking an interactive program gives it keyboard focus immediately', async ({ page }) => {
  await browse(page, base);
  await page.locator('#window-files .file').filter({ hasText: 'input.wasm' }).click();
  await expect(busy(page)).toHaveAttribute('data-state', 'input');
  await expect(input(page)).toBeFocused();
  await page.keyboard.type('hello'); await page.keyboard.press('Enter');
  await expect(busy(page)).toHaveAttribute('data-state', 'idle');
  await expect(last(page)).toHaveText('hello\nhello');
  await expect(page.locator('#viewer')).not.toBeVisible();
});

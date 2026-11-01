import { test, expect } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Phase 0 browser gate: the Rust wasix-runtime and a prebuilt WASIX dash run inside a module
// Worker, and proc_fork creates a child that rewinds its own asyncify stack. The fixture is
// third-party and external; the test skips unless WASIX_DASH names it.
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const dash = process.env.WASIX_DASH;
let server;
let origin;
let bindings;

test.beforeAll(async () => {
  if (!dash) return;
  bindings = mkdtempSync(join(tmpdir(), 'wasix-web-'));
  execFileSync(process.execPath, ['scripts/build-wasix-runtime.mjs', bindings], {
    cwd: root,
    stdio: 'pipe',
  });
  const host = readFileSync(join(root, 'web/kernel/host.js'));
  const runtimeJs = readFileSync(join(bindings, 'wasix_runtime.js'));
  const runtimeWasm = readFileSync(join(bindings, 'wasix_runtime_bg.wasm'));
  const dashBytes = readFileSync(dash);
  const page = `<!doctype html><meta charset="utf-8"><title>wasix</title><script>
    window.results = { out: [], exits: [], error: null, done: false };
    const worker = new Worker('/host.js', { type: 'module' });
    worker.onmessage = event => {
      const message = event.data;
      if (message.type === 'output') window.results.out.push(message.text);
      else if (message.type === 'exit') window.results.exits.push({ pid: message.pid, code: message.code });
      else if (message.type === 'error') window.results.error = message.error;
      else if (message.type === 'done') window.results.done = true;
    };
    worker.onerror = event => { window.results.error = event.message; };
    worker.postMessage({ type: 'start', dash: '/dash.wasm' });
  </script>`;
  server = http.createServer((req, res) => {
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Embedder-Policy', 'credentialless');
    res.setHeader('Cache-Control', 'no-store');
    if (req.url === '/') {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(page);
    } else if (req.url === '/host.js') {
      res.setHeader('Content-Type', 'text/javascript');
      res.end(host);
    } else if (req.url === '/wasix_runtime.js') {
      res.setHeader('Content-Type', 'text/javascript');
      res.end(runtimeJs);
    } else if (req.url === '/wasix_runtime_bg.wasm') {
      res.setHeader('Content-Type', 'application/wasm');
      res.end(runtimeWasm);
    } else if (req.url === '/dash.wasm') {
      res.setHeader('Content-Type', 'application/wasm');
      res.end(dashBytes);
    } else {
      res.statusCode = 404;
      res.end('not found');
    }
  });
  await new Promise(done => server.listen(0, '127.0.0.1', done));
  origin = `http://127.0.0.1:${server.address().port}`;
});

test.afterAll(async () => {
  if (server) await new Promise(done => server.close(done));
});

test('the Rust WASIX runtime forks dash in a Worker', async ({ page }) => {
  test.skip(!dash, 'set WASIX_DASH to a WASIX dash binary');
  await page.goto(origin + '/');
  await page.waitForFunction(() => window.results?.done || window.results?.error, null, { timeout: 60_000 });
  const results = await page.evaluate(() => window.results);
  expect(results.error).toBeNull();
  const output = results.out.join('');
  expect(output).toContain('one');
  expect(output).toContain('two');
  expect(output).toContain('three');
  expect(results.exits).toEqual(expect.arrayContaining([
    expect.objectContaining({ pid: 2, code: 0 }),
    expect.objectContaining({ pid: 1, code: 0 }),
  ]));
});

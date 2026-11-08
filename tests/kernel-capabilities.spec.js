import { test, expect } from './test.js';
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Phase 0: what the target browser actually gives a page, a dedicated Worker and a SharedWorker
// with the same COOP/COEP headers the site serves. The probe is served directly, so this spec
// needs neither Wrangler nor a built frontend.
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const probe = await readFile(resolve(root, 'web/kernel/probe.js'), 'utf8');
let server;
let origin;

test.beforeAll(async () => {
  server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://probe');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Embedder-Policy', 'credentialless');
    res.setHeader('Cache-Control', 'no-store');
    if (url.pathname === '/probe.js') {
      res.setHeader('Content-Type', 'text/javascript');
      res.end(probe);
    } else if (url.pathname === '/ping') {
      res.setHeader('Content-Type', 'text/plain');
      res.end('pong');
    } else if (url.pathname === '/cookie') {
      res.setHeader('Set-Cookie', 'probe=ok; Path=/; SameSite=Lax');
      res.end('set');
    } else if (url.pathname === '/cookies') {
      res.setHeader('Content-Type', 'text/plain');
      res.end(req.headers.cookie || '');
    } else if (url.pathname === '/') {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end('<!doctype html><meta charset="utf-8"><title>probe</title><script>fetch("/cookie")</script>');
    } else {
      res.statusCode = 404;
      res.end('not found');
    }
  });
  await new Promise(done => server.listen(0, '127.0.0.1', done));
  origin = `http://127.0.0.1:${server.address().port}`;
});

test.afterAll(async () => {
  await new Promise(done => server.close(done));
});

function collect(page, kind) {
  return page.evaluate(kind => new Promise(resolve => {
    let worker;
    let timer = setTimeout(() => {
      worker?.terminate?.();
      resolve({ error: `${kind} timed out` });
    }, 5000);
    const finish = value => {
      clearTimeout(timer);
      worker?.terminate?.();
      resolve(value);
    };
    try {
      if (kind === 'shared') {
        worker = new SharedWorker('/probe.js');
        worker.port.onmessage = event => finish(event.data);
        worker.port.start();
        worker.port.postMessage('go');
      } else {
        worker = new Worker('/probe.js');
        worker.onmessage = event => finish(event.data);
        worker.onerror = event => finish({ error: event.message });
        worker.postMessage('go');
      }
    } catch (error) {
      resolve({ error: String(error) });
    }
  }), kind);
}

test('page, dedicated Worker and SharedWorker capabilities', async ({ page }) => {
  await page.goto(origin + '/');
  await page.waitForTimeout(100);
  const pageCapabilities = await page.evaluate(() => ({
    crossOriginIsolated: self.crossOriginIsolated,
    sharedArrayBuffer: typeof SharedArrayBuffer,
    showDirectoryPicker: typeof window.showDirectoryPicker,
    offscreenCanvas: typeof OffscreenCanvas,
    webgpu: Boolean(navigator.gpu),
    originPrivateFileSystem: Boolean(navigator.storage?.getDirectory),
  }));
  const dedicated = await collect(page, 'dedicated');
  const shared = await collect(page, 'shared');
  const capabilities = { page: pageCapabilities, dedicated, shared };
  console.log('CAPABILITIES ' + JSON.stringify(capabilities));
  test.info().annotations.push({ type: 'capabilities', description: JSON.stringify(capabilities) });

  // The page must be cross-origin isolated for the rest of the plan; the worker results are the
  // measurement, not an assertion, because SharedWorker isolation is the open question.
  expect(pageCapabilities.crossOriginIsolated).toBe(true);
  expect(pageCapabilities.sharedArrayBuffer).toBe('function');
  expect(dedicated).toBeTruthy();
  expect(shared).toBeTruthy();
});

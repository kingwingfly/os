// Browser Worker primitives for running the packaged kernel and its actual WASI children in Node.
// Only release assets are available. An HTTP request from an offline mount fails the test.
import { Worker, parentPort, workerData } from 'node:worker_threads';
import { resolveObjectURL } from 'node:buffer';
import { readFileSync } from 'node:fs';
import { registerHooks } from 'node:module';
import { runInThisContext, constants } from 'node:vm';

const root = new URL('../dist/', import.meta.url);
const asset = path => new URL(path.slice(1), root);
registerHooks({ resolve(specifier, context, next) {
  return next(specifier.startsWith('/') ? asset(specifier).href : specifier, context);
} });
globalThis.self = globalThis;
globalThis.crossOriginIsolated = true;
globalThis.location = new URL(workerData.path ?? workerData, 'http://os.test/');
let offline = false;
const offlineRequests = [];
function checkNetwork(path) {
  if (offline) { offlineRequests.push(path); throw Error('Offline: ' + path); }
}
globalThis.fetch = async input => {
  const path = new URL(input.url ?? input, location).pathname;
  checkNetwork(path);
  if (path.startsWith('/api/')) throw Error('Unexpected network request ' + path);
  try {
    const type = path.endsWith('.js') ? 'text/javascript' : path.endsWith('.wasm') ? 'application/wasm' : 'application/octet-stream';
    return new Response(readFileSync(asset(path)), { headers: { 'Content-Type': type } });
  } catch (error) { if (error.code !== 'ENOENT') throw error; return new Response(null, { status: 404 }); }
};
globalThis.postMessage = (data, transfer) => parentPort.postMessage(data, transfer);
globalThis.Worker = class {
  constructor(path) {
    const url = new URL(path, location);
    if (url.protocol !== 'blob:') checkNetwork(url.pathname);
    const script = url.protocol === 'blob:' ? { path: '/wasi-process.js', blob: resolveObjectURL(url.href) } : url.pathname;
    const fixture = workerData.fixture ?? import.meta.url;
    this.worker = new Worker(new URL(fixture), { workerData: typeof script === 'string' ? script : { ...script, fixture } });
    this.worker.on('message', data => this.onmessage?.({ data }));
    this.worker.on('error', error => this.onerror?.(error));
  }
  postMessage(data, transfer) { this.worker.postMessage(data, transfer); }
  terminate() { return this.worker.terminate(); }
};
globalThis.importScripts = path => runInThisContext(readFileSync(asset(path), 'utf8'), {
  filename: path, importModuleDynamically: constants.USE_MAIN_CONTEXT_DEFAULT_LOADER,
});
if (workerData.blob) runInThisContext(await workerData.blob.text(), { filename: workerData.path });
else globalThis.importScripts(workerData.path ?? workerData);
parentPort.on('message', async data => {
  if (data.type === 'test_offline') {
    offline = data.args.enabled;
    parentPort.postMessage({ id: data.id, ok: offlineRequests.splice(0) });
  } else if (data.type === 'test_page_fsync') {
    const { session, fd } = data.args;
    try {
      await globalThis.kernel.vfs_fsync_fd(session, fd, false);
      parentPort.postMessage({ id: data.id, ok: null });
    } catch (err) {
      parentPort.postMessage({ id: data.id, err: { errno: err.errno ?? 'EIO', detail: String(err) } });
    }
  } else globalThis.onmessage({ data });
});

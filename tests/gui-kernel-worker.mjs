// Instrument the existing packaged-Worker fixture at its host I/O boundaries.
import './mount-service-worker.mjs';
import { parentPort } from 'node:worker_threads';

const notify = (event, value) => parentPort.postMessage({ event, value });
const fetchAsset = globalThis.fetch;
let blockedBundle, releaseCopy;
globalThis.fetch = async (input, ...args) => {
  if (blockedBundle && new URL(input.url ?? input, location).pathname.endsWith('/gui/samples/doc-view.json')) {
    notify('test-bundle-pending', true);
    await blockedBundle.promise;
  }
  return fetchAsset(input, ...args);
};
const post = globalThis.Worker.prototype.postMessage;
globalThis.Worker.prototype.postMessage = function (data, transfer) {
  if (data.guiDisposeCanvas) notify('test-canvas-dispose', data.guiDisposeCanvas);
  return post.call(this, data, transfer);
};
const handle = globalThis.onmessage;
globalThis.onmessage = ({ data }) => {
  if (data.type === 'test_gui_bundle') {
    if (data.args.hold) blockedBundle = Promise.withResolvers();
    else { blockedBundle.resolve(); blockedBundle = null; }
    parentPort.postMessage({ id: data.id, ok: true }); return;
  }
  if (data.type === 'test_gui_slow_pick') {
    // Pause after the first chunk is copied into the actual VFS staging file.
    const file = new File([new Uint8Array(65537)], 'two-chunks');
    const slice = file.slice.bind(file);
    file.slice = (start, end) => {
      const blob = slice(start, end);
      if (!start) return blob;
      return { async arrayBuffer() {
        notify('test-copy-pending', true);
        await new Promise(resolve => { releaseCopy = resolve; });
        return blob.arrayBuffer();
      } };
    };
    return handle({ data: { ...data, type: 'gui_picker_result', args: { ...data.args, file } } });
  }
  if (data.type === 'test_gui_finish_copy') {
    releaseCopy(); parentPort.postMessage({ id: data.id, ok: true }); return;
  }
  if (data.guiCanvas) {
    // Node has transferable ports, with no native OffscreenCanvas. The process
    // Worker still owns the renderer and calls the sample's real paint import.
    const canvas = data.guiCanvas.canvas;
    Object.assign(canvas, { width: 320, height: 250, getContext: () => ({
      fillRect() {}, beginPath() {}, arc() {}, fill() {},
    }) });
  }
  return handle({ data });
};

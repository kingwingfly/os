// Phase 0 capability probe. The same file is loaded as a SharedWorker and as a dedicated
// Worker; `?nested=1` makes it the nested worker used to test Worker creation and module
// transfer. It reports what the browser actually provides; it changes nothing.
const MINIMAL_WASM = new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);

async function probe() {
  const result = {
    scope: self.constructor?.name ?? 'unknown',
    crossOriginIsolated: self.crossOriginIsolated,
    sharedArrayBuffer: typeof SharedArrayBuffer,
    atomicsWait: null,
    syncXhr: null,
    fetchCookies: null,
    websocket: typeof WebSocket,
    nestedWorker: false,
    nestedModule: false,
    offscreenCanvas: typeof OffscreenCanvas,
    webgpu: !!(self.navigator && 'gpu' in self.navigator),
    wasmCompile: false,
    errors: [],
  };
  try {
    const word = new Int32Array(new SharedArrayBuffer(4));
    result.atomicsWait = Atomics.wait(word, 0, 0, 10);
  } catch (error) {
    result.errors.push(`atomicsWait: ${error}`);
  }
  try {
    const xhr = new XMLHttpRequest();
    xhr.open('GET', '/ping', false);
    xhr.send();
    result.syncXhr = xhr.status;
  } catch (error) {
    result.errors.push(`syncXhr: ${error}`);
  }
  try {
    const response = await fetch('/cookies', { credentials: 'include', cache: 'no-store' });
    result.fetchCookies = await response.text();
  } catch (error) {
    result.errors.push(`fetchCookies: ${error}`);
  }
  let module;
  try {
    module = await WebAssembly.compile(MINIMAL_WASM);
    result.wasmCompile = true;
  } catch (error) {
    result.errors.push(`wasmCompile: ${error}`);
  }
  try {
    const nested = new Worker('/probe.js?nested=1');
    result.nestedWorker = true;
    result.nestedModule = await new Promise(resolve => {
      const timer = setTimeout(() => resolve(false), 2000);
      nested.onmessage = event => {
        clearTimeout(timer);
        resolve(Boolean(event.data?.module));
        nested.terminate();
      };
      nested.onerror = () => {
        clearTimeout(timer);
        resolve(false);
      };
      nested.postMessage({ module, ping: true });
    });
  } catch (error) {
    result.errors.push(`nestedWorker: ${error}`);
  }
  return result;
}

if (new URL(self.location.href).searchParams.get('nested') === '1') {
  onmessage = event => {
    postMessage({
      nested: true,
      module: event.data?.module instanceof WebAssembly.Module,
      crossOriginIsolated: self.crossOriginIsolated,
      sharedArrayBuffer: typeof SharedArrayBuffer,
    });
  };
} else if (typeof onconnect !== 'undefined') {
  onconnect = event => {
    const port = event.ports[0];
    port.onmessage = async () => {
      try {
        port.postMessage(await probe());
      } catch (error) {
        port.postMessage({ error: String(error) });
      }
    };
    port.start();
  };
} else {
  onmessage = async () => {
    try {
      postMessage(await probe());
    } catch (error) {
      postMessage({ error: String(error) });
    }
  };
}

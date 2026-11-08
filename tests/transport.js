// Playwright does not route scripts of nested Workers. Serve a kernel that creates its
// process Workers with JSPI absent before their runtime loads. No production feature switch.
function fallbackProcessWorkers() {
  const NativeWorker = self.Worker;
  self.Worker = class extends NativeWorker {
    constructor(url, options) {
      const original = new URL(url, self.location.href);
      if (original.pathname !== '/wasi-process.js') { super(url, options); return; }
      const source = `
        delete WebAssembly.Suspending; delete WebAssembly.promising;
        const open = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(method, url, ...args) {
          return open.call(this, method, new URL(url, ${JSON.stringify(original.href)}).href, ...args);
        };
        importScripts(${JSON.stringify(original.href)});
      `;
      super(URL.createObjectURL(new Blob([source], { type: 'text/javascript' })), options);
    }
  };
}

export const withoutJspi = page => page.context().route('**/client-kernel.js', async route => {
  const response = await route.fetch();
  await route.fulfill({ response, body: `(${fallbackProcessWorkers.toString()})();\n` + await response.text() });
});

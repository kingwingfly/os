// A disposable, lazily loaded compiler Worker. The input travels only through a local
// message port; there is no fetch, upload, execution or fallback to the cloud compiler.
import { transformImage } from './transform.js';

self.onmessage = async ({ data }) => {
  self.onmessage = null;
  try {
    // Install the handler before Binaryen's asynchronous initialization. A message sent
    // while a module Worker awaits a static import can otherwise arrive without a listener.
    const binaryen = (await import('binaryen')).default;
    const bytes = await transformImage(binaryen, data);
    self.postMessage({ bytes }, [bytes.buffer]);
  } catch (error) {
    self.postMessage({ error: String(error?.message ?? error) });
  } finally { self.close(); }
};

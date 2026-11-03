// The loader's asyncify (web/kernel/asyncify.js), off the page: binaryen is large, and its pass
// takes a while on a large image. Asked {id, bytes, imports}; answers {id, bytes} or {id, error}.
import { asyncify } from './asyncify.js';

let loading;
onmessage = async ({ data: { id, bytes, imports } }) => {
  try {
    loading ??= import('/binaryen.js').then(module => module.default);
    const out = asyncify(await loading, new Uint8Array(bytes), imports);
    postMessage({ id, bytes: out }, [out.buffer]);
  } catch (error) {
    postMessage({ id, error: String(error?.message ?? error) });
  }
};

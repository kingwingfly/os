// Shared compiler policy. Neither compiler instantiates application code. Changing the
// emitted format requires changing the server profile and local cache version together.
import { asyncify } from './asyncify.js';
import { instrumentMemory } from './memory.js';

export const IMAGE_MAX = 128 * 1024 * 1024;
export const LOCAL_FORMAT = 'abi1-wasm32-resources-v1-binaryen132-local1';

export async function transformImage(binaryen, input, profile = 'resources-v1') {
  if (!['resources-v1', 'fork-v4'].includes(profile)) throw new Error('unknown compiler profile');
  if (!(input instanceof Uint8Array) || input.byteLength > IMAGE_MAX) throw new Error('image exceeds 128 MiB');
  const original = await WebAssembly.compile(input);
  const imports = WebAssembly.Module.imports(original);
  for (const entry of imports) {
    if (entry.kind === 'function' && ['wasi_snapshot_preview1', 'os', 'terminal', 'wasix_32v1'].includes(entry.module)) continue;
    if (entry.kind === 'memory' && entry.module === 'env' && entry.name === 'memory') continue;
    throw new Error(`unsupported import ${entry.module}.${entry.name}`);
  }
  const exports = WebAssembly.Module.exports(original);
  if (exports.some(entry => entry.name.startsWith('__tw_'))) throw new Error('reserved runtime export');
  const unwinds = imports.filter(entry => entry.module === 'wasix_32v1' && ['proc_fork', 'stack_checkpoint', 'stack_restore'].includes(entry.name)).map(entry => `${entry.module}.${entry.name}`);
  const built = exports.some(entry => entry.name === 'asyncify_start_unwind');
  let bytes;
  if (profile === 'resources-v1') {
    bytes = instrumentMemory(binaryen, input, !unwinds.length);
    if (unwinds.length) bytes = asyncify(binaryen, bytes, unwinds, !built);
  } else bytes = asyncify(binaryen, input, unwinds, !built);
  if (bytes.byteLength > IMAGE_MAX) throw new Error('transformed image exceeds 128 MiB');
  await WebAssembly.compile(bytes);
  return bytes;
}

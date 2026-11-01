// Build the Rust client kernel for its SharedWorker: wasm32-unknown-unknown + wasm-bindgen
// no-modules, so a classic SharedWorker can importScripts it. Usage:
// node scripts/build-client-kernel.mjs <out-dir>
import { execFileSync } from 'node:child_process';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const out = resolve(process.argv[2] ?? join(root, 'target/client-kernel'));
const target = JSON.parse(
  execFileSync('cargo', ['metadata', '--format-version', '1', '--no-deps'], {
    cwd: root,
    encoding: 'utf8',
  }),
).target_directory;
execFileSync(
  'cargo',
  ['build', '-p', 'terminal-worker-client-kernel', '--target', 'wasm32-unknown-unknown', '--release'],
  { cwd: root, stdio: 'inherit' },
);
execFileSync(
  'wasm-bindgen',
  [
    '--target', 'no-modules',
    '--no-typescript',
    '--out-dir', out,
    '--out-name', 'client_kernel',
    join(target, 'wasm32-unknown-unknown/release/terminal_worker_client_kernel.wasm'),
  ],
  { cwd: root, stdio: 'inherit' },
);
console.log(out);

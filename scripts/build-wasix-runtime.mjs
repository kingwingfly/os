// Build the Rust wasix-runtime for the browser: wasm32-unknown-unknown + wasm-bindgen web.
// Usage: node scripts/build-wasix-runtime.mjs <out-dir>
import { execFileSync } from 'node:child_process';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const out = resolve(process.argv[2] ?? join(root, 'target/wasix-web'));
const target = JSON.parse(
  execFileSync('cargo', ['metadata', '--format-version', '1', '--no-deps'], {
    cwd: root,
    encoding: 'utf8',
  }),
).target_directory;
execFileSync(
  'cargo',
  ['build', '-p', 'os-wasix-runtime', '--target', 'wasm32-unknown-unknown', '--release'],
  { cwd: root, stdio: 'inherit' },
);
execFileSync(
  'wasm-bindgen',
  [
    '--target', 'web',
    '--out-dir', out,
    '--out-name', 'wasix_runtime',
    join(target, 'wasm32-unknown-unknown/release/os_wasix_runtime.wasm'),
  ],
  { cwd: root, stdio: 'inherit' },
);
console.log(out);

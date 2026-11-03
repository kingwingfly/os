import { execFileSync } from 'node:child_process';
import { mkdir, readFile, writeFile, readdir, stat, realpath } from 'node:fs/promises';
import { resolve, dirname, join, relative, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { build } from 'esbuild';
const { values } = parseArgs({ options: { content: { type: 'string' }, 'out-dir': { type: 'string' }, 'web-only': { type: 'boolean' } } });
const caller = process.cwd();
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const out = resolve(caller, values['out-dir'] || join(root, 'dist'));
const configPath = values.content && resolve(caller, values.content);
process.chdir(root);
const config = configPath ? JSON.parse(await readFile(configPath, 'utf8')) : {};
const branding = { name: 'R2 TERMINAL', subtitle: '', heading: 'Your files, right here.', description: 'An R2 terminal with accounts, groups, and file permissions.', ...config.branding };
for (const value of Object.values(branding)) if (typeof value !== 'string') throw new Error('Branding values must be strings');
const games = {};
let assets;
if (config.assets) {
  assets = await realpath(resolve(dirname(configPath), config.assets));
  const overlap = relative(assets, out);
  if (!overlap.startsWith('..') && !isAbsolute(overlap)) throw new Error('Output directory cannot be inside the content assets directory');
}
for (const [entry, path] of Object.entries(config.games || {})) {
  if (!assets || typeof path !== 'string' || !/^[a-zA-Z0-9_./-]+\.html$/.test(path) || path.startsWith('/') || path.split('/').includes('..')) throw new Error('Game entries must be relative HTML paths inside content assets');
  const actual = await realpath(join(assets, path));
  const rel = relative(assets, actual);
  if (rel.startsWith('..') || isAbsolute(rel) || !(await stat(actual)).isFile()) throw new Error('Game entry escapes the content assets directory');
  Object.defineProperty(games, entry, { value: '/content/' + path, enumerable: true });
}
const run = (command, args) => execFileSync(command, args, { stdio: 'inherit' });
const target = JSON.parse(execFileSync('cargo', ['metadata', '--format-version', '1', '--no-deps'], { encoding: 'utf8' })).target_directory;
const copy = async (from, to) => writeFile(to, await readFile(from));
async function copyTree(from, to) {
  await mkdir(to, { recursive: true });
  for (const item of await readdir(from, { withFileTypes: true })) {
    if (item.isSymbolicLink()) throw new Error('Content assets cannot contain symlinks');
    if (item.isDirectory()) await copyTree(join(from, item.name), join(to, item.name));
    else await copy(join(from, item.name), join(to, item.name));
  }
}
await mkdir(join(out, 'pkg'), { recursive: true });
run('cargo', ['build', '-p', 'terminal-worker-ui', '--target', 'wasm32-unknown-unknown', '--release']);
run('wasm-bindgen', ['--target', 'web', '--out-dir', join(out, 'pkg'), '--out-name', 'frontend', join(target, 'wasm32-unknown-unknown/release/terminal_worker_ui.wasm')]);
// The preview workers, started by the page when a preview first needs one: PDF pages, archive
// listings, Mermaid diagrams, and code highlighted in four groups of languages, as
// crates/preview/src/lib.rs names their loaders. Each feature set builds on its own, so a worker
// links only its own engine.
for (const [feature, profile, bins] of [
  ['pdf', 'release', ['preview_pdf']],
  ['archive', 'release', ['preview_archive']],
  ['diagram', 'size', ['preview_diagram']],
  ['code', 'release', ['preview_code_web', 'preview_code_systems', 'preview_code_apps', 'preview_code_scripts']],
]) {
  run('cargo', ['build', '-p', 'terminal-worker-preview', '--target', 'wasm32-unknown-unknown', '--profile', profile, '--features', feature + ',worker', ...bins.flatMap(bin => ['--bin', bin])]);
  for (const bin of bins) {
    run('wasm-bindgen', ['--target', 'no-modules', '--no-typescript', '--out-dir', out, '--out-name', bin, join(target, 'wasm32-unknown-unknown', profile, bin + '.wasm')]);
    // A worker whose code cannot load or start says so, as the failure of its being ready.
    await writeFile(join(out, bin + '_loader.js'), `importScripts('./${bin}.js');wasm_bindgen('./${bin}_bg.wasm').catch(e=>postMessage([0,false,String(e&&e.message||e)]));\n`);
  }
}
await build({ absWorkingDir: root, entryPoints: { bridge: 'web/app.js' },
  splitting: true,
  chunkNames: 'chunks/[name]-[hash]', bundle: true, format: 'esm', outdir: out, minify: true });
// The WASI engine's process, a Worker of its own (web/wasi/process.js), and /usr/bin's binary:
// uutils' coreutils, built for wasm32-wasip1 (rustup target add wasm32-wasip1).
await build({ absWorkingDir: root, entryPoints: { 'wasi-process': 'web/wasi/process.js' }, bundle: true, format: 'iife', outdir: out, minify: true });
run('cargo', ['build', '--release', '--target', 'wasm32-wasip1', '--manifest-path', 'crates/coreutils/Cargo.toml', '--target-dir', join(target, 'coreutils')]);
await mkdir(join(out, 'usr/bin'), { recursive: true });
await copy(join(target, 'coreutils/wasm32-wasip1/release/coreutils.wasm'), join(out, 'usr/bin/coreutils.wasm'));
// What the kernel's /usr says of its binaries (crates/worker/src/usr.rs), which it cannot ask the
// assets: their sizes.
const sizes = {};
for (const asset of ['/usr/bin/coreutils.wasm', '/pkg/frontend_bg.wasm']) sizes[asset] = (await stat(join(out, asset))).size;
await writeFile(join(out, 'usr/manifest.json'), JSON.stringify(sizes));
for (const name of ['index.html', 'style.css', '_headers']) await copy('web/' + name, join(out, name));
if (assets) await copyTree(assets, join(out, 'content'));
await writeFile(join(out, 'terminal-config.json'), JSON.stringify({ branding, games }));
console.log('Terminal built: ' + out);


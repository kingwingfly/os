import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { rm, mkdir, readFile, writeFile, readdir, stat, realpath } from 'node:fs/promises';
import { resolve, dirname, join, relative, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import binaryen from 'binaryen';
import { build } from 'esbuild';
import { LOCAL_FORMAT, transformImage } from '../web/kernel/transform.js';
const { values } = parseArgs({ options: { content: { type: 'string' }, 'out-dir': { type: 'string' }, 'web-only': { type: 'boolean' } } });
const caller = process.cwd();
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const out = resolve(caller, values['out-dir'] || join(root, 'dist'));
const configPath = values.content && resolve(caller, values.content);
process.chdir(root);
const config = configPath ? JSON.parse(await readFile(configPath, 'utf8')) : {};
const branding = { name: 'OS', subtitle: '', heading: 'Your OS, in the browser.', description: 'A browser OS with processes, a filesystem, accounts, and applications.', ...config.branding };
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
const target = JSON.parse(execFileSync('cargo', ['metadata', '--format-version', '1', '--no-deps'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] })).target_directory;
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
run('cargo', ['build', '--locked', '-p', 'os-ui', '--target', 'wasm32-unknown-unknown', '--release']);
run('wasm-bindgen', ['--target', 'web', '--out-dir', join(out, 'pkg'), '--out-name', 'frontend', join(target, 'wasm32-unknown-unknown/release/os_ui.wasm')]);
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
  run('cargo', ['build', '--locked', '-p', 'os-preview', '--target', 'wasm32-unknown-unknown', '--profile', profile, '--features', feature + ',worker', ...bins.flatMap(bin => ['--bin', bin])]);
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
// Local-only images must never use the container compiler. Binaryen is embedded in this
// separate Worker and loaded only for a local launch, not by the page or cloud loader.
await build({ absWorkingDir: root, entryPoints: { 'local-compiler': 'web/kernel/local-compiler.js' }, external: ['node:*'], bundle: true, format: 'esm', outdir: out, minify: true });
await build({ absWorkingDir: root, entryPoints: { 'console-window': 'web/console-window.js' }, external: ['./pkg/*'], bundle: true, format: 'esm', outdir: out, minify: true });
await build({ absWorkingDir: root, entryPoints: { 'gui-session': 'web/gui/session.js' }, bundle: true, format: 'esm', outdir: out, minify: true });
for (const name of ['greeter', 'shell-session']) await build({ absWorkingDir: root, entryPoints: { [name]: 'web/' + name + '.js' }, external: ['./pkg/*'], bundle: true, format: 'esm', outdir: out, minify: true });
await build({ absWorkingDir: root, entryPoints: { 'login-session': 'web/kernel/login.js' }, bundle: true, format: 'esm', outdir: out, minify: true });
await build({ absWorkingDir: root, entryPoints: { 'image-pager': 'web/kernel/image-pager.js' }, bundle: true, format: 'esm', outdir: out, minify: true });
await build({ absWorkingDir: root, entryPoints: { 'offline-installer': 'web/kernel/offline-installer.js' }, bundle: true, format: 'esm', outdir: out, minify: true });
await build({ absWorkingDir: root, entryPoints: { 'offline-sw': 'web/kernel/offline-installer.js' }, bundle: true, format: 'iife', outdir: out, minify: true });
await build({ absWorkingDir: root, entryPoints: { 'sandbox-worker': 'web/kernel/sandbox-worker.js' }, external: ['node:*'], bundle: true, format: 'esm', outdir: out, minify: true });
await build({ absWorkingDir: root, entryPoints: { 'kubelet-agent': 'web/kernel/kubelet-agent.js' }, external: ['node:*'], bundle: true, format: 'esm', outdir: out, minify: true });
await build({ absWorkingDir: root, entryPoints: { 'netd-host': 'web/kernel/netd-host.js' }, external: ['node:*'], bundle: true, format: 'esm', outdir: out, minify: true });
await build({ absWorkingDir: root, entryPoints: { 'overlay-transport': 'web/kernel/overlay-transport.js' }, external: ['node:*'], bundle: true, format: 'esm', outdir: out, minify: true });
// Remove obsolete pre-overhaul compiler and server-lease init artifacts.
for (const name of ['wasi-asyncify.js', 'binaryen.js', 'init-owner.js']) await rm(join(out, name), { force: true });
// Build /usr/bin/*.wasm binaries first so their exact sizes and pre-transformed `.rv1` sidecars
// can be embedded into `client-kernel.js`, `executor-host.js`, and `usr/manifest.json`.
run('cargo', ['build', '--locked', '--release', '--target', 'wasm32-wasip1', '--manifest-path', 'crates/coreutils/Cargo.toml', '--target-dir', join(target, 'coreutils')]);
await mkdir(join(out, 'usr/bin'), { recursive: true });
await copy(join(target, 'coreutils/wasm32-wasip1/release/coreutils.wasm'), join(out, 'usr/bin/coreutils.wasm'));
run('cargo', ['build', '--locked', '--release', '--target', 'wasm32-wasip1', '-p', 'os-utilities']);
await copy(join(target, 'wasm32-wasip1/release/utilities.wasm'), join(out, 'usr/bin/utilities.wasm'));
run('cargo', ['build', '--locked', '--release', '--target', 'wasm32-wasip1', '-p', 'os-services']);
for (const name of ['supervise', 'init', 'early_init', 'mountd', 'exportd', 'kubelet', 'netd', 'compositor', 'desktop-shell', 'greeter', 'gui-sample-doc', 'gui-sample-pixel', 'osh', 'terminal', 'files', 'mounts', 'editor', 'preview']) {
  await copy(join(target, `wasm32-wasip1/release/${name}.wasm`), join(out, `usr/bin/${name}.wasm`));
}
run(process.execPath, ['scripts/build-shell.mjs', '--out-dir', out]);
// Emit pre-transformed static `.rv1` sidecars alongside raw `/usr/bin/*.wasm` binaries so cold
// browser contexts compile system tools directly without running Binaryen in-browser. Raw `.wasm`
// binaries remain untouched for `/api/file`, inspection, and Release v2 packaging.
const transformedDigests = {};
const systemAssets = ['coreutils', 'utilities', 'dash', 'supervise', 'init', 'mountd', 'exportd', 'kubelet', 'netd', 'compositor', 'desktop-shell', 'greeter', 'gui-sample-doc', 'gui-sample-pixel', 'osh', 'terminal', 'files', 'mounts', 'editor', 'preview'].map(name => `/usr/bin/${name}.wasm`);
for (const asset of systemAssets) {
  const raw = new Uint8Array(await readFile(join(out, asset)));
  const rv1 = await transformImage(binaryen, raw, 'resources-v1');
  await writeFile(join(out, asset + '.rv1'), rv1);
  transformedDigests[asset] = createHash('sha256').update(rv1).digest('hex');
}
const docAsset = '/usr/share/gui/samples/doc-view.json';
await mkdir(dirname(join(out, docAsset)), { recursive: true });
await writeFile(join(out, docAsset), JSON.stringify({ html: '', css: await readFile('web/gui/samples/doc-view.css', 'utf8'), js: await readFile('web/gui/samples/doc-view.js', 'utf8') }));
const terminalAsset = '/usr/share/gui/terminal/terminal.json';
await mkdir(dirname(join(out, terminalAsset)), { recursive: true });
await writeFile(join(out, terminalAsset), JSON.stringify({
  html: await readFile('web/gui/terminal/index.html', 'utf8'),
  css: await readFile('web/gui/terminal/terminal.css', 'utf8'),
  js: await readFile('web/gui/terminal/terminal.js', 'utf8'),
}));
const filesAsset = '/usr/share/gui/files/files.json';
await mkdir(dirname(join(out, filesAsset)), { recursive: true });
await writeFile(join(out, filesAsset), JSON.stringify({
  html: await readFile('web/gui/files/index.html', 'utf8'),
  css: await readFile('web/gui/files/files.css', 'utf8'),
  js: await readFile('web/gui/files/files.js', 'utf8'),
}));
const mountsAsset = '/usr/share/gui/mounts/mounts.json';
await mkdir(dirname(join(out, mountsAsset)), { recursive: true });
await writeFile(join(out, mountsAsset), JSON.stringify({
  html: await readFile('web/gui/mounts/index.html', 'utf8'),
  css: await readFile('web/gui/mounts/mounts.css', 'utf8'),
  js: await readFile('web/gui/mounts/mounts.js', 'utf8'),
}));
const editorAsset = '/usr/share/gui/editor/editor.json';
const editorJsBuild = await build({
  absWorkingDir: root,
  entryPoints: ['web/gui/editor/editor.mjs'],
  bundle: true,
  format: 'iife',
  minify: true,
  write: false,
});
await mkdir(dirname(join(out, editorAsset)), { recursive: true });
await writeFile(join(out, editorAsset), JSON.stringify({
  html: await readFile('web/gui/editor/index.html', 'utf8'),
  css: await readFile('web/gui/editor/editor.css', 'utf8'),
  js: editorJsBuild.outputFiles[0].text,
}));
const previewAsset = '/usr/share/gui/preview/preview.json';
await mkdir(dirname(join(out, previewAsset)), { recursive: true });
await writeFile(join(out, previewAsset), JSON.stringify({
  html: await readFile('web/gui/preview/index.html', 'utf8'),
  css: await readFile('web/gui/preview/preview.css', 'utf8'),
  js: await readFile('web/gui/preview/preview.js', 'utf8'),
}));
const osConfigAsset = '/usr/share/os/config.json';
await mkdir(dirname(join(out, osConfigAsset)), { recursive: true });
await writeFile(join(out, osConfigAsset), JSON.stringify({ version: 1, games }));
const associationsAsset = '/usr/share/desktop/associations.json';
await mkdir(dirname(join(out, associationsAsset)), { recursive: true });
await copy('web/desktop/associations.json', join(out, associationsAsset));
const transformed = { format: LOCAL_FORMAT, digests: transformedDigests };
// What the kernel's /usr says of its binaries (crates/worker/src/usr.rs), which it cannot ask the
// assets: their sizes, plus pre-transformed sidecar integrity metadata.
const sizes = {};
for (const asset of [...systemAssets, docAsset, terminalAsset, filesAsset, mountsAsset, editorAsset, previewAsset, osConfigAsset, associationsAsset, '/pkg/frontend_bg.wasm']) sizes[asset] = (await stat(join(out, asset))).size;
await writeFile(join(out, 'usr/manifest.json'), JSON.stringify({ ...sizes, transformed }));
await build({
  absWorkingDir: root,
  entryPoints: { 'executor-host': 'web/kernel/executor.js' },
  bundle: true,
  format: 'esm',
  outdir: out,
  minify: true,
  define: { __OS_BUILD_TRANSFORMED__: JSON.stringify(transformed) },
});
// The client kernel (crates/client-kernel), a classic dedicated Worker: no-modules wasm-bindgen,
// imported by web/kernel/client.js, with the page's protocol module bundled into the bridge.
run('cargo', ['build', '--locked', '-p', 'os-client-kernel', '--target', 'wasm32-unknown-unknown', '--release']);
run('wasm-bindgen', ['--target', 'no-modules', '--no-typescript', '--out-dir', out, '--out-name', 'client_kernel', join(target, 'wasm32-unknown-unknown/release/os_client_kernel.wasm')]);
await build({
  absWorkingDir: root,
  entryPoints: { 'client-kernel': 'web/kernel/client.js' },
  bundle: true,
  format: 'iife',
  outdir: out,
  minify: true,
  define: { __OS_BUILD_ASSET_SIZES__: JSON.stringify(sizes) },
});
for (const name of ['index.html', 'console.html', 'login.html', 'shell.html', 'gui-session.html', 'style.css', '_headers']) await copy('web/' + name, join(out, name));
await writeFile(join(out, 'offline-boot.html'), `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>OS Offline Boot (Release v2)</title><link rel="icon" href="data:,"></head>
<body><pre id="status">Booting offline Release v2…</pre>
<script src="./client_kernel.js"></script>
<script type="module">
import { createOfflineInstaller, registerOfflineServiceWorker } from './offline-installer.js';
import { createImagePager } from './image-pager.js';
const installer = createOfflineInstaller();
const pager = createImagePager();
globalThis.imageBlobRead = pager.imageBlobRead;
globalThis.osOffline = { installer, pager, registerOfflineServiceWorker };
const params = new URLSearchParams(location.search);
function hexOf(buf) {
  const bytes = new Uint8Array(buf);
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}
async function bootStage1() {
  const statusEl = document.getElementById('status');
  const state = await installer.getState();
  if (!state.active) {
    statusEl.textContent = 'No offline Release v2 installed.';
    globalThis.__osOfflineBoot = { status: 'not-installed', state };
    return;
  }
  const boot = await installer.beginOfflineBoot({ verifyAllBlobs: true });
  const wasmUrl = '/boot/releases/' + boot.releaseId + '/assets' + boot.release.loader.client_kernel_wasm;
  const wasmRes = await fetch(wasmUrl, { cache: 'no-store' });
  if (!wasmRes.ok) {
    await installer.abortOfflineBoot(boot.releaseId).catch(() => {});
    throw new Error('Failed to load client kernel Wasm (HTTP ' + wasmRes.status + ')');
  }
  const wasmBytes = new Uint8Array(await wasmRes.arrayBuffer());
  const actualWasmSha = hexOf(await crypto.subtle.digest('SHA-256', wasmBytes));
  if (actualWasmSha !== boot.release.loader.client_kernel_sha256) {
    await installer.abortOfflineBoot(boot.releaseId).catch(() => {});
    throw new Error('Client kernel Wasm SHA-256 mismatch before instantiation.');
  }
  await wasm_bindgen({ module_or_path: wasmBytes });
  const bundleSummary = wasm_bindgen.verify_release_v2_bundle(
    boot.manifestText,
    boot.signatureText,
    boot.trustText,
    boot.imagesRaw,
    boot.sigsRaw,
  );
  if (params.get('simulate_crash') === '1') {
    await installer.abortOfflineBoot(boot.releaseId);
    const err = new Error('Simulated crash before markBootHealthy');
    globalThis.__osOfflineBoot = { status: 'crashed', releaseId: boot.releaseId, rolledBack: boot.rolledBack, error: err.message };
    statusEl.textContent = 'Boot crashed before markBootHealthy: ' + boot.releaseId;
    return;
  }
  const stage1 = await wasm_bindgen.boot_stage1_initramfs(boot.imagesRaw[1]);
  const healthyState = await installer.markBootHealthy(boot.releaseId);
  globalThis.__osOfflineBoot = {
    status: 'ready',
    releaseId: boot.releaseId,
    rolledBack: boot.rolledBack,
    rolledBackFrom: boot.rolledBackFrom,
    bundleSummary,
    stage1,
    pagerStats: pager.stats(),
    state: healthyState,
  };
  statusEl.textContent = 'Stage 1 offline boot healthy: ' + boot.releaseId;
}
bootStage1().catch(err => {
  globalThis.__osOfflineBoot = { status: 'error', error: String(err?.message ?? err) };
  document.getElementById('status').textContent = 'Offline boot failed: ' + String(err?.message ?? err);
  console.error(err);
});
</script></body></html>
`);
if (assets) await copyTree(assets, join(out, 'content'));
await writeFile(join(out, 'os-config.json'), JSON.stringify({ branding, games }));
await rm(join(out, 'terminal-config.json'), { force: true });
console.log('OS built: ' + out);


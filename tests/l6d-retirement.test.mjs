import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';

async function walkFiles(dir, exts, out = []) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (entry.name === 'target' || entry.name === 'node_modules' || entry.name === 'build' || entry.name === 'pkg' || entry.name === 'dist') {
      continue;
    }
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      await walkFiles(full, exts, out);
    } else if (exts.some(ext => entry.name.endsWith(ext))) {
      out.push(full);
    }
  }
  return out;
}

test('L6d retired legacy files are deleted from the repository', () => {
  const deleted = [
    'wrangler.legacy.toml',
    'web/compat.mjs',
    'tests/compat.test.mjs',
    'crates/frontend/src/sys.rs',
    'crates/frontend/src/shell.rs',
    'crates/frontend/src/files.rs',
    'crates/frontend/src/viewer.rs',
    'crates/frontend/src/preview.rs',
    'crates/frontend/src/manual.rs',
    'web/editor.mjs',
    'web/dev.mjs',
    'web/record.mjs',
    'web/sound.mjs',
    'web/mount-manager.js',
    'web/mount-sharing-ui.js',
    'web/kernel/login-boot.js',
    'web/kernel/init.js',
  ];
  for (const path of deleted) {
    assert.equal(existsSync(path), false, `retired file must remain deleted: ${path}`);
  }
});

test('L6d retired legacy rename identifiers, L5b compat socket, dead kernel RPCs, and page auth are absent from production sources', async () => {
  const sourceFiles = [
    ...(await walkFiles('crates', ['.rs', '.js', '.mjs'])),
    ...(await walkFiles('web', ['.js', '.mjs', '.html', '.css'])),
  ].filter(path => !path.startsWith('crates/os-native/tests/'));

  const forbidden = [
    'TerminalAuthority',
    'terminal-authority-v2',
    'terminal_session',
    'terminal_guest',
    'usr:terminal',
    'LEGACY_COOKIE',
    'LEGACY_GUEST_COOKIE',
    'migratePreferences',
    'allow_compat_apps',
    'compat_gui_host',
    'compat_peers',
    'compatConn',
    'ensureCompatConn',
    'closeCompatConn',
    'sendCompatReq',
    'gui_compat_req',
    'gui-compat-event',
    'gui-compat-rebind',
    'gui_compat_proxy',
    'compatDisplay',
    'vfs_read_file',
    'mount_vfs_read_file',
    'mount_write',
    'mount_identity',
    'sync_account_from_server',
    'accountCommand',
    'askCredentials',
    'sudoAuthenticate',
    'id="auth"',
  ];

  const hits = [];
  for (const file of sourceFiles) {
    const content = await readFile(file, 'utf8');
    for (const token of forbidden) {
      if (content.includes(token)) {
        hits.push(`${file}: ${token}`);
      }
    }
  }
  assert.deepEqual(hits, [], `retired L6d tokens still present:\n${hits.join('\n')}`);
});

test('L6d legacy "terminal" WASM import namespace is rejected in browser and native loaders', async () => {
  const loader = await readFile('web/kernel/loader.js', 'utf8');
  assert.doesNotMatch(loader, /['"]terminal['"]/);
  assert.match(loader, /['"]os['"]/);
  assert.match(loader, /['"]wasi_snapshot_preview1['"]/);
  assert.match(loader, /['"]wasix_32v1['"]/);

  const transform = await readFile('web/kernel/transform.js', 'utf8');
  assert.doesNotMatch(transform, /['"]terminal['"]/);

  const processJs = await readFile('web/wasi/process.js', 'utf8');
  assert.doesNotMatch(processJs, /\bterminal\s*:/);

  const wasiHost = await readFile('crates/os-native/src/wasi_host.rs', 'utf8');
  assert.doesNotMatch(wasiHost, /register_os_module\s*\(\s*linker\s*,\s*"terminal"\s*\)/);
  assert.match(wasiHost, /register_os_module\s*\(\s*linker\s*,\s*"os"\s*\)/);
});

test('L6d crates/frontend no longer depends on os-userland, gloo-net, or futures and drops window.osUploads.setfacl', async () => {
  const cargoToml = await readFile('crates/frontend/Cargo.toml', 'utf8');
  assert.doesNotMatch(cargoToml, /os-userland|userland\s*=|gloo-net|^futures\s*=/m);

  const uploadsRs = await readFile('crates/frontend/src/uploads.rs', 'utf8');
  assert.doesNotMatch(uploadsRs, /\bsetfacl\b/);

  const mediaBroker = await readFile('web/gui/media-broker.js', 'utf8');
  assert.match(mediaBroker, /\/usr\/bin\/setfacl/);
  assert.doesNotMatch(mediaBroker, /rust\.setfacl/);
});

test('L6d conformance OS runner uses post-L6c native GUI surfaces and local /proc instead of retired selectors/RPCs', async () => {
  const osRunner = await readFile('scripts/conformance/os.mjs', 'utf8');
  for (const retired of ['.command-line', "'#command'", "'#editor'", "'#viewer'", 'proc_poll:', 'machine_init:']) {
    assert.equal(osRunner.includes(retired), false, `scripts/conformance/os.mjs still references retired ${retired}`);
  }
  assert.match(osRunner, /\/api\/cloud-auth\/register/);
  assert.match(osRunner, /window\.os\.cloudSignIn/);
  assert.match(osRunner, /\.surface\[data-app-id="terminal"\]/);
  assert.match(osRunner, /\.surface\[data-app-id="editor"\]/);
  assert.match(osRunner, /\.surface\[data-app-id="preview"\]/);
  assert.match(osRunner, /\/proc\/\$\{pid\}\/status/);
});

test('L6d optional CloudFs (/mnt/cloud) remains retained feature-frozen per #75', async () => {
  const graph = await readFile('crates/services/src/graph.rs', 'utf8');
  assert.match(graph, /cloud\.mount/);
  assert.match(graph, /\/mnt\/cloud/);
  assert.equal(existsSync('crates/vfs/src/cloud.rs'), true);
});

test('L6d scripts/seed.mjs authenticates via /api/cloud-auth/login rather than retired /api/sys login', async () => {
  const seed = await readFile('scripts/seed.mjs', 'utf8');
  assert.match(seed, /\/api\/cloud-auth\/login/);
  assert.doesNotMatch(seed, /\{\s*login\s*:/);
});

test('L6d crates/worker/src/usr.rs carries no legacy "usr:terminal" alias', async () => {
  const usr = await readFile('crates/worker/src/usr.rs', 'utf8');
  assert.doesNotMatch(usr, /"usr:terminal"/);
});

// OCI-08 host E2E: isolated local `wrangler dev --local` on port 18880 + disposable host `podman`
// (`--root`/`--runroot`, zero host pollution, offline `FROM scratch` 2-layer build/login/push/rmi/pull
// + `cargo xtask oci push-tar` pulled and verified by host `podman`).
// Build crates/worker with `worker-build --release` first.
import assert from 'node:assert/strict';
import {spawn, spawnSync} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

const REPO = resolve('.');
const PORT = Number(process.env.OCI_E2E_PORT || 18880);
const REGISTRY = `127.0.0.1:${PORT}`;
const BASE_URL = `http://${REGISTRY}`;
const ADMIN_PASSWORD = 'e2e-admin-' + randomUUID();
const SESSION_SECRET = 'e2e-secret-' + randomUUID();

function runChecked(cmd, args, opts = {}) {
  const res = spawnSync(cmd, args, {encoding: 'utf8', ...opts});
  if (res.status !== 0) {
    throw new Error(
      `Command failed (${res.status}): ${cmd} ${args.join(' ')}\nSTDOUT:\n${res.stdout}\nSTDERR:\n${res.stderr}`,
    );
  }
  return res;
}

async function waitForRegistry(url, timeoutMs = 45_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${url}/v2/`, {redirect: 'manual'});
      if (res.status === 401 && res.headers.get('docker-distribution-api-version') === 'registry/2.0') {
        return;
      }
    } catch {
      // retry until wrangler dev binds port
    }
    await new Promise(r => setTimeout(r, 300));
  }
  throw new Error(`Timed out waiting for local OCI registry at ${url}/v2/`);
}

function inspectOciDirFiles(ociDir) {
  const idx = JSON.parse(readFileSync(join(ociDir, 'index.json'), 'utf8'));
  const manDigest = idx.manifests[0].digest.replace('sha256:', '');
  const man = JSON.parse(readFileSync(join(ociDir, 'blobs', 'sha256', manDigest), 'utf8'));
  const extracted = mkdtempSync(join(tmpdir(), 'oci-e2e-extract-'));
  try {
    for (const layer of man.layers) {
      const hex = layer.digest.replace('sha256:', '');
      const blobPath = join(ociDir, 'blobs', 'sha256', hex);
      runChecked('tar', ['-xf', blobPath, '-C', extracted]);
    }
    return extracted;
  } catch (err) {
    rmSync(extracted, {recursive: true, force: true});
    throw err;
  }
}

async function main() {
  assert.ok(
    existsSync(join(REPO, 'crates/worker/build/index.js')),
    'Build crates/worker with `worker-build --release` before running tests/podman-oci-e2e.mjs',
  );

  const work = mkdtempSync(join(tmpdir(), 'os-podman-oci-e2e-'));
  const podRoot = join(work, 'podman-root');
  const podRun = join(work, 'podman-run');
  const podTmp = join(work, 'podman-tmp');
  const authFile = join(work, 'auth.json');
  const persistDir = join(work, 'wrangler-persist');
  const assetsDir = join(work, 'assets');
  mkdirSync(podRoot, {recursive: true});
  mkdirSync(podRun, {recursive: true});
  mkdirSync(podTmp, {recursive: true});
  mkdirSync(persistDir, {recursive: true});
  mkdirSync(assetsDir, {recursive: true});
  writeFileSync(join(assetsDir, 'index.html'), '<!doctype html><title>oci-e2e</title>');

  const wranglerCfg = join(work, 'wrangler.toml');
  writeFileSync(
    wranglerCfg,
    `name = "os-oci-e2e"
main = ${JSON.stringify(join(REPO, 'crates/worker/entry.js'))}
compatibility_date = "2026-10-24"

[assets]
directory = ${JSON.stringify(assetsDir)}
binding = "ASSETS"
run_worker_first = ["/v2", "/v2/*", "/api/*"]

[[r2_buckets]]
binding = "FILES"
bucket_name = "os-files-e2e"

[[durable_objects.bindings]]
name = "AUTHORITY"
class_name = "OsAuthority"

[[durable_objects.bindings]]
name = "MACHINE"
class_name = "Machine"

[[durable_objects.bindings]]
name = "STORAGE"
class_name = "StorageVolume"

[[durable_objects.bindings]]
name = "MOUNTS"
class_name = "MountRelay"

[[migrations]]
tag = "v1"
new_sqlite_classes = ["OsAuthority", "Machine", "StorageVolume", "MountRelay"]
`,
  );

  const wranglerBin = existsSync(join(REPO, 'node_modules/.bin/wrangler'))
    ? join(REPO, 'node_modules/.bin/wrangler')
    : 'wrangler';

  const wranglerLogs = [];
  const child = spawn(
    wranglerBin,
    [
      'dev',
      '--local',
      '--ip', '127.0.0.1',
      '--port', String(PORT),
      '--config', wranglerCfg,
      '--persist-to', persistDir,
      '--var', `ADMIN_PASSWORD:${ADMIN_PASSWORD}`,
      '--var', `SESSION_SECRET:${SESSION_SECRET}`,
      '--var', `VOLUME_QUOTA_BYTES:${32 * 1024 * 1024}`,
    ],
    {
      cwd: REPO,
      env: {...process.env, WRANGLER_SEND_METRICS: 'false'},
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );
  child.stdout.on('data', d => wranglerLogs.push(d.toString()));
  child.stderr.on('data', d => wranglerLogs.push(d.toString()));

  const podEnv = {
    ...process.env,
    XDG_RUNTIME_DIR: podRun,
    TMPDIR: podTmp,
    REGISTRY_AUTH_FILE: authFile,
  };
  const podman = (args, opts = {}) =>
    runChecked('podman', ['--root', podRoot, '--runroot', podRun, ...args], {env: podEnv, ...opts});

  try {
    await waitForRegistry(BASE_URL);

    // Seed OsAuthority root user via /api/sys (initializes ADMIN_PASSWORD hash in SQLite).
    const bootRes = await fetch(`${BASE_URL}/api/sys`, {
      method: 'POST',
      headers: {Origin: BASE_URL, 'Content-Type': 'application/json'},
      body: JSON.stringify({calls: ['getcreds']}),
    });
    assert.equal(bootRes.status, 200, `failed to seed authority: ${await bootRes.text()}`);

    // 1. Offline 2-layer FROM scratch image build.
    const ctxDir = join(work, 'ctx');
    mkdirSync(ctxDir, {recursive: true});
    writeFileSync(join(ctxDir, 'layer1.txt'), 'hello-from-layer-1\n');
    writeFileSync(join(ctxDir, 'layer2.txt'), 'hello-from-layer-2\n');
    writeFileSync(
      join(ctxDir, 'Containerfile'),
      `FROM scratch\nCOPY layer1.txt /etc/layer1.txt\nCOPY layer2.txt /etc/layer2.txt\n`,
    );
    const localTag = `${REGISTRY}/e2e/scratch:v1`;
    podman(['build', '--format', 'oci', '--layers=true', '-t', localTag, ctxDir]);

    // 2. Unauthenticated pull MUST fail.
    const unauthPull = spawnSync(
      'podman',
      ['--root', podRoot, '--runroot', podRun, 'pull', '--tls-verify=false', `${REGISTRY}/e2e/scratch:v1`],
      {env: podEnv, encoding: 'utf8'},
    );
    assert.notEqual(unauthPull.status, 0, 'unauthenticated podman pull must fail');

    // 3. podman login -> push -> rmi -> pull -> verify extracted files + /v2/<repo>/tags/list.
    podman(['login', '--tls-verify=false', '-u', 'root', '-p', ADMIN_PASSWORD, REGISTRY]);
    podman(['push', '--tls-verify=false', localTag]);
    podman(['rmi', localTag]);
    podman(['pull', '--tls-verify=false', localTag]);

    const savedDir = join(work, 'saved-scratch');
    podman(['save', '--format', 'oci-dir', '-o', savedDir, localTag]);
    const extracted = inspectOciDirFiles(savedDir);
    try {
      assert.equal(readFileSync(join(extracted, 'etc/layer1.txt'), 'utf8'), 'hello-from-layer-1\n');
      assert.equal(readFileSync(join(extracted, 'etc/layer2.txt'), 'utf8'), 'hello-from-layer-2\n');
    } finally {
      rmSync(extracted, {recursive: true, force: true});
    }

    // Verify /v2/e2e/scratch/tags/list returns ["v1"].
    const tokRes = await fetch(`${BASE_URL}/v2/token?service=registry&scope=repository:e2e/scratch:pull`, {
      headers: {Authorization: `Basic ${Buffer.from(`root:${ADMIN_PASSWORD}`).toString('base64')}`},
    });
    assert.equal(tokRes.status, 200);
    const {token} = await tokRes.json();
    const tagsRes = await fetch(`${BASE_URL}/v2/e2e/scratch/tags/list`, {
      headers: {Authorization: `Bearer ${token}`},
    });
    assert.equal(tagsRes.status, 200);
    assert.deepEqual(await tagsRes.json(), {name: 'e2e/scratch', tags: ['v1']});

    // 4. Push a cowfs-exported OCI tar+gzip image via `cargo xtask oci push-tar` and pull with host `podman`!
    const cowfsSrc = join(work, 'cowfs-tree');
    mkdirSync(join(cowfsSrc, 'etc'), {recursive: true});
    writeFileSync(join(cowfsSrc, 'etc/cowfs.txt'), 'exported-by-os-cowfs\n');
    runChecked(
      'cargo',
      [
        'run', '--locked', '--offline', '-p', 'xtask', '--',
        'oci', 'push-tar',
        '--root', cowfsSrc,
        '--registry', BASE_URL,
        '--ref', 'e2e/from-cowfs:v1',
        '--user', 'root',
        '--password', ADMIN_PASSWORD,
      ],
      {cwd: REPO, env: {...process.env, CARGO_NET_OFFLINE: 'true'}},
    );
    const cowfsRef = `${REGISTRY}/e2e/from-cowfs:v1`;
    podman(['pull', '--tls-verify=false', cowfsRef]);
    const savedCowfs = join(work, 'saved-cowfs');
    podman(['save', '--format', 'oci-dir', '-o', savedCowfs, cowfsRef]);
    const extractedCowfs = inspectOciDirFiles(savedCowfs);
    try {
      assert.equal(
        readFileSync(join(extractedCowfs, 'etc/cowfs.txt'), 'utf8'),
        'exported-by-os-cowfs\n',
      );
    } finally {
      rmSync(extractedCowfs, {recursive: true, force: true});
    }

    console.log('OCI-08 host podman E2E passed: scratch 2-layer push/pull + cowfs-exported image pull verified.');
  } catch (err) {
    console.error('Wrangler logs:\n' + wranglerLogs.join(''));
    throw err;
  } finally {
    child.kill('SIGTERM');
    await new Promise(r => setTimeout(r, 500));
    if (!child.killed) child.kill('SIGKILL');
    rmSync(work, {recursive: true, force: true});
  }
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});

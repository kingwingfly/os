// Build everything, then deploy. `wrangler deploy` builds only the Worker ([build] in
// wrangler.toml, which `wrangler dev` reruns on every Worker or core change, so it is kept to the
// Worker) and uploads `dist/` as it is; the page in it, the terminal and its preview workers,
// comes from scripts/build.mjs, which this runs first, so that a deploy never ships a stale page.
// The job container's image is built and pushed by wrangler too: where Docker is absent and
// Podman present, through scripts/podman-docker.sh. Arguments go to wrangler deploy:
//
//   npm run deploy
//   npm run deploy -- --dry-run
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const scripts = dirname(fileURLToPath(import.meta.url));
const has = command => spawnSync('sh', ['-c', `command -v ${command}`], { stdio: 'ignore' }).status === 0;
// Run `command`, stopping here, with its status, if it fails.
function run(command, args, env = process.env) {
  const { status, signal, error } = spawnSync(command, args, { stdio: 'inherit', env });
  if (error) throw error;
  if (status !== 0) process.exit(status ?? (signal ? 1 : 0));
}

run(process.execPath, [join(scripts, 'build.mjs')]);
const env = { ...process.env };
if (!env.WRANGLER_DOCKER_BIN && !has('docker') && has('podman')) {
  env.WRANGLER_DOCKER_BIN = join(scripts, 'podman-docker.sh');
  console.log('The job container is built and pushed with Podman, through scripts/podman-docker.sh');
}
run('npx', ['wrangler', 'deploy', ...process.argv.slice(2)], env);

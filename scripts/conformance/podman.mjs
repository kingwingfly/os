// A private Podman API service for one conformance run. `npm run dev` keeps its own
// bootstrap in scripts/dev.mjs; sharing the two is a separate follow-up (#67).
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { start, stop } from './process.mjs';
const scripts=join(dirname(fileURLToPath(import.meta.url)),'..');
const has=command=>spawnSync('sh',['-c',`command -v ${command}`],{stdio:'ignore'}).status===0;
export const needsPodman=env=>!env.WRANGLER_DOCKER_HOST&&!env.DOCKER_HOST&&!has('docker')&&has('podman');
// Podman resolves only qualified image names, so Wrangler's egress sidecar needs its registry.
// A run fails here, before starting anything, when that cannot be determined.
export function egressImage(env,readMiniflare=()=>readFileSync(join(scripts,'../node_modules/miniflare/dist/src/index.js'),'utf8')) {
  if(env.MINIFLARE_CONTAINER_EGRESS_IMAGE)return env.MINIFLARE_CONTAINER_EGRESS_IMAGE;
  const image=readMiniflare().match(/DEFAULT_CONTAINER_EGRESS_INTERCEPTOR_IMAGE = "([^"]+)"/)?.[1];
  if(!image)throw new Error('Miniflare egress image not found; set MINIFLARE_CONTAINER_EGRESS_IMAGE explicitly');
  return image.split('/')[0].includes('.')?image:'docker.io/'+image;
}
// Start the service at `socket`, in its own process group. `env` receives the engine settings
// only once the socket exists; the run's container lease then puts the one Docker API proxy
// in front of it (scripts/conformance/containers.mjs).
export async function startPodman(env,{socket,stdio='ignore',signal,startupTimeout=10000,readMiniflare}) {
  const egress=egressImage(env,readMiniflare);
  if(existsSync(socket))throw new Error('isolated Podman socket already exists');
  signal?.throwIfAborted();
  const cgroups=env.DBUS_SESSION_BUS_ADDRESS?[]:['--cgroup-manager=cgroupfs'];
  const service=start('podman',[...cgroups,'system','service','--time=0','unix://'+socket],{stdio,env,detached:true});
  const close=()=>stop(service);
  try {
    const deadline=Date.now()+startupTimeout;
    while(!existsSync(socket)) {
      signal?.throwIfAborted();
      if(service.spawnError)throw service.spawnError;
      if(service.exitCode!==null||service.signalCode!==null)throw new Error('Podman service exited before opening its socket');
      if(Date.now()>=deadline)throw new Error('Podman service did not start');
      await new Promise(resolve=>setTimeout(resolve,50));
    }
    signal?.throwIfAborted();
  } catch(error) {
    try {await close();} catch(cleanupError) {console.error('Podman startup cleanup failed:',cleanupError.message);}
    throw error;
  }
  Object.assign(env,{WRANGLER_DOCKER_BIN:join(scripts,'podman-docker.sh'),WRANGLER_DOCKER_HOST:'unix://'+socket,MINIFLARE_CONTAINER_EGRESS_IMAGE:egress});
  return {close,socket};
}

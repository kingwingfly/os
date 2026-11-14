// Podman's Docker-compatible API service, for `npm run dev` (scripts/dev.mjs) and the conformance
// harness (scripts/conformance/os.mjs). Every caller starts a private service on its own socket;
// none borrows another session's, so no session can lose its engine when another exits.
//
// The service runs under a small shell "lifeline" in a process group of its own. Terminal
// signals (Ctrl-C, a closed terminal) therefore never reach it directly, so Wrangler can still
// remove its containers while it shuts down. The lifeline reads its standard input, a pipe held
// by the owner, and stops the service when that pipe closes: when the owner calls close(), or
// when the owner dies in any way, SIGKILL included. The service cannot outlive its owner.
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { start, stop } from './process.mjs';
const scripts=dirname(fileURLToPath(import.meta.url));
export const has=command=>spawnSync('sh',['-c',`command -v ${command}`],{stdio:'ignore'}).status===0;
export const needsPodman=env=>!env.WRANGLER_DOCKER_HOST&&!env.DOCKER_HOST&&!has('docker')&&has('podman');

// Podman resolves only qualified image names, so Wrangler's egress sidecar needs its registry.
// With strict, a missing Miniflare source or declaration is an error; otherwise (development)
// only the override is skipped and containers stay available.
export function egressImage(env,{strict=false,readMiniflare=()=>readFileSync(join(scripts,'../node_modules/miniflare/dist/src/index.js'),'utf8')}={}) {
  if(env.MINIFLARE_CONTAINER_EGRESS_IMAGE)return env.MINIFLARE_CONTAINER_EGRESS_IMAGE;
  try {
    const image=readMiniflare().match(/DEFAULT_CONTAINER_EGRESS_INTERCEPTOR_IMAGE = "([^"]+)"/)?.[1];
    if(!image)throw new Error('Miniflare egress image not found; set MINIFLARE_CONTAINER_EGRESS_IMAGE explicitly');
    return image.split('/')[0].includes('.')?image:'docker.io/'+image;
  } catch(error) {if(strict)throw error;return undefined;}
}
// Point Wrangler at a Docker API socket backed by Podman.
export function configureWrangler(env,{host,egress}) {
  env.WRANGLER_DOCKER_BIN=join(scripts,'podman-docker.sh');
  env.WRANGLER_DOCKER_HOST='unix://'+host;
  if(egress)env.MINIFLARE_CONTAINER_EGRESS_IMAGE=egress;
}

// The lifeline: start the service, and stop it when standard input reaches end of file.
// It exits with the service, so a service that fails to start is seen at once. Background
// jobs of a non-interactive shell read /dev/null, so the pipe is passed on explicitly as fd 3.
const lifeline=`exec 3<&0
podman "$@" </dev/null 3<&- & service=$!
(while read -r _; do :; done <&3; kill "$service" 2>/dev/null) &
exec 3<&-
wait "$service"`;

// Start a private service at `socket`. With allowLate (development), a service still opening
// its socket at the deadline is kept, and requests succeed once it listens; otherwise that is
// an error. `output` receives the service's stdout and stderr.
export async function startPodman(env,{socket,output='ignore',signal,startupTimeout=10000,allowLate=false}) {
  if(existsSync(socket))throw new Error('Podman socket already exists: '+socket);
  signal?.throwIfAborted();
  const cgroups=env.DBUS_SESSION_BUS_ADDRESS?[]:['--cgroup-manager=cgroupfs'];
  const service=start('/bin/sh',['-c',lifeline,'podman-lifeline',...cgroups,'system','service','--time=0','unix://'+socket],{stdio:['pipe',output,output],env,detached:true});
  // The owner never writes; the pipe only has to stay open.
  service.stdin?.on('error',()=>{});
  let closing;
  const close=()=>closing??=(async()=>{
    service.stdin?.end();
    const exited=service.exitCode!==null||service.signalCode!==null?Promise.resolve():new Promise(resolve=>service.once('exit',resolve));
    const timer=new Promise(resolve=>setTimeout(resolve,5000).unref());
    // A service that ignores the lifeline is stopped with its whole group.
    if(await Promise.race([exited.then(()=>true),timer.then(()=>false)])===false)await stop(service);
    else await stop(service,{timeout:1000});
  })();
  try {
    const deadline=Date.now()+startupTimeout;
    while(!existsSync(socket)) {
      signal?.throwIfAborted();
      if(service.spawnError)throw service.spawnError;
      if(service.exitCode!==null||service.signalCode!==null)throw new Error('Podman service exited before opening its socket');
      if(Date.now()>=deadline) {if(allowLate)break;throw new Error('Podman service did not start');}
      await new Promise(resolve=>setTimeout(resolve,50));
    }
    signal?.throwIfAborted();
  } catch(error) {
    try {await close();} catch(cleanupError) {console.error('Podman startup cleanup failed: '+cleanupError.message);}
    throw error;
  }
  return {close,socket,pid:service.pid};
}

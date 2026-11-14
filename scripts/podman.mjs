// Podman's Docker-compatible API service, for `npm run dev` (scripts/dev.mjs) and the conformance
// harness (scripts/conformance/os.mjs). Every caller starts a private service on its own socket;
// none borrows another session's, so no session can lose its engine when another exits.
//
// The service runs under a small shell "lifeline" in a process group of its own. Terminal
// signals (Ctrl-C, a closed terminal) therefore never reach it directly, so Wrangler can still
// remove its containers while it shuts down. The lifeline reads its standard input, a pipe held
// by the owner, and stops the service when that pipe closes: when the owner dies in any way,
// SIGKILL included. It sends SIGTERM, then SIGKILL after five seconds, so the service cannot
// outlive its owner.
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, lstatSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { start, stop, startTime } from './process.mjs';
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

// A private directory for one development session's sockets, recording its owner. Directories
// left by sessions whose owner has died (SIGKILL, a crash) are removed first; a directory whose
// owner is alive, or that records no owner, is left alone.
export function sessionDirectory(base=tmpdir()) {
  for(const name of readdirSync(base)) {
    if(!/^os-podman-[A-Za-z0-9]{6}$/.test(name))continue;
    const dir=join(base,name);
    try {
      const info=lstatSync(dir);
      if(!info.isDirectory()||info.uid!==process.getuid())continue;
      const owner=JSON.parse(readFileSync(join(dir,'owner.json'),'utf8'));
      if(owner.pid&&owner.start&&startTime(owner.pid)===owner.start)continue;
      rmSync(dir,{recursive:true,force:true});
    } catch {}
  }
  const dir=mkdtempSync(join(base,'os-podman-'));
  writeFileSync(join(dir,'owner.json'),JSON.stringify({pid:process.pid,start:startTime(process.pid)})+'\n');
  return dir;
}

// The lifeline. A reader subshell turns end of input into SIGTERM to this shell, whose trap stops
// the service, escalating to SIGKILL after five seconds. The service is this shell's own child
// and is not reaped before the trap's wait, so its PID cannot have been reused when signalled.
// When the service exits by itself, the shell stops the reader before exiting, so the reader
// never signals a PID that is no longer this shell. Background jobs of a non-interactive shell
// read /dev/null, so the pipe is passed on as fd 3.
const lifeline=`exec 3<&0
podman "$@" </dev/null 3<&- & service=$!
(while read -r _; do :; done <&3; kill -TERM $$ 2>/dev/null) & reader=$!
exec 3<&-
stop() {
  kill -TERM "$service" 2>/dev/null
  (trap 'kill "$timer" 2>/dev/null; exit 0' TERM; sleep 5 & timer=$!; wait "$timer" && kill -KILL "$service" 2>/dev/null) & killer=$!
  wait "$service"; status=$?
  kill "$killer" 2>/dev/null
  exit "$status"
}
trap stop TERM
wait "$service"; status=$?
kill "$reader" 2>/dev/null
exit "$status"`;

// Start a private service at `socket`. With allowLate (development), a service still opening
// its socket at the deadline is kept; `ready` then resolves true once it listens, or false if
// it exits first, so the caller can report what happened. Otherwise a late service is an error.
// `output` receives the service's stdout and stderr. close() stops the service and its
// lifeline; a failed close can be retried.
export async function startPodman(env,{socket,output='ignore',signal,startupTimeout=10000,allowLate=false}) {
  if(existsSync(socket))throw new Error('Podman socket already exists: '+socket);
  signal?.throwIfAborted();
  const cgroups=env.DBUS_SESSION_BUS_ADDRESS?[]:['--cgroup-manager=cgroupfs'];
  const service=start('/bin/sh',['-c',lifeline,'podman-lifeline',...cgroups,'system','service','--time=0','unix://'+socket],{stdio:['pipe',output,output],env,detached:true});
  // The owner never writes; the pipe only has to stay open while the owner lives.
  service.stdin?.on('error',()=>{});
  const exited=()=>service.exitCode!==null||service.signalCode!==null;
  const close=()=>stop(service);
  try {
    const deadline=Date.now()+startupTimeout;
    while(!existsSync(socket)) {
      signal?.throwIfAborted();
      if(service.spawnError)throw service.spawnError;
      if(exited())throw new Error('Podman service exited before opening its socket');
      if(Date.now()>=deadline) {if(allowLate)break;throw new Error('Podman service did not start');}
      await new Promise(resolve=>setTimeout(resolve,50));
    }
    signal?.throwIfAborted();
  } catch(error) {
    try {await close();} catch(cleanupError) {console.error('Podman startup cleanup failed: '+cleanupError.message);}
    throw error;
  }
  const late=!existsSync(socket);
  const ready=late?new Promise(resolve=>{
    const poll=setInterval(()=>{
      if(existsSync(socket)) {clearInterval(poll);resolve(true);}
      else if(exited()) {clearInterval(poll);resolve(false);}
    },100);
    poll.unref();
  }):Promise.resolve(true);
  return {close,socket,pid:service.pid,late,ready};
}

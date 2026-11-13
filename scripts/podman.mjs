// Shared Docker-compatible Podman bootstrap for development and isolated tests.
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { podmanProxy } from './podman-proxy.mjs';
import { start, stop } from './process.mjs';
const scripts=dirname(fileURLToPath(import.meta.url));
export const has=command=>spawnSync('sh',['-c',`command -v ${command}`],{stdio:'ignore'}).status===0;
export const needsPodman=env=>!env.WRANGLER_DOCKER_HOST&&!env.DOCKER_HOST&&!has('docker')&&has('podman');
export function podmanEnvironment(env,proxySocket,miniflare) {
  let egress=env.MINIFLARE_CONTAINER_EGRESS_IMAGE;
  if(!env.MINIFLARE_CONTAINER_EGRESS_IMAGE) {
    const source=miniflare??readFileSync(join(scripts,'../node_modules/miniflare/dist/src/index.js'),'utf8');
    const image=source.match(/DEFAULT_CONTAINER_EGRESS_INTERCEPTOR_IMAGE = "([^"]+)"/)?.[1];
    if(image)egress=image.split('/')[0].includes('.')?image:'docker.io/'+image;
  }
  env.WRANGLER_DOCKER_BIN=join(scripts,'podman-docker.sh');
  env.WRANGLER_DOCKER_HOST='unix://'+proxySocket;
  if(egress)env.MINIFLARE_CONTAINER_EGRESS_IMAGE=egress;
}
// A successful connect proves a listener exists without waiting for an API
// response. Only refusal/absence proves staleness; ambiguous errors preserve it.
export function socketLive(path,timeout=2000) {
  return new Promise((resolve,reject)=>{
    const socket=connect(path);
    const finish=(error,live)=>{socket.destroy();if(error)reject(error);else resolve(live);};
    socket.once('connect',()=>finish(null,true));
    socket.once('error',error=>['ECONNREFUSED','ENOENT'].includes(error.code)?finish(null,false):finish(error));
    socket.setTimeout(timeout,()=>finish(new Error('Podman socket connect timed out; shared socket preserved')));
  });
}
export async function startPodman(env,{socket,proxySocket,reuse=false,stdio='ignore',detached=false,signal,startupTimeout=10000,allowLate=false}) {
  let service,proxy,closing,privateDir;
  const close=()=>closing??=(async()=>{
    try {proxy?.close();} finally {try {await stop(service);}finally {if(privateDir)await rm(privateDir,{recursive:true,force:true});}}
  })();
  try {
    const borrowed=reuse&&existsSync(socket)&&await socketLive(socket);
    if(!borrowed) {
      if(!reuse&&existsSync(socket))throw new Error('isolated Podman socket already exists');
      if(reuse) {
        // Do not unlink even a stale shared name: its owner could restart between
        // the connect check and unlink. Start this session on its own private path.
        privateDir=await mkdtemp(join(tmpdir(),'os-podman-'));
        socket=join(privateDir,'service.sock');
      }
      const cgroups=env.DBUS_SESSION_BUS_ADDRESS?[]:['--cgroup-manager=cgroupfs'];
      service=start('podman',[...cgroups,'system','service','--time=0','unix://'+socket],{stdio,env,detached});
      const deadline=Date.now()+startupTimeout;
      while(!existsSync(socket)) {
        signal?.throwIfAborted();
        if(service.spawnError)throw service.spawnError;
        if(service.exitCode!==null||service.signalCode!==null)throw new Error('Podman service exited before opening its socket');
        if(Date.now()>=deadline) {if(allowLate)break;throw new Error('Podman service did not start');}
        await new Promise(resolve=>setTimeout(resolve,50));
      }
      signal?.throwIfAborted();
    }
    proxy=podmanProxy(proxySocket,socket);
    podmanEnvironment(env,proxySocket);
    return {close,socket};
  } catch(error) {
    try {await close();} catch(cleanupError) {console.error('Podman startup cleanup failed:',cleanupError.message);}
    throw error;
  }
}

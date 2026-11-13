// Shared Docker-compatible Podman bootstrap for development and isolated tests.
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { podmanProxy } from './podman-proxy.mjs';
import { start, stop } from './process.mjs';
const scripts=dirname(fileURLToPath(import.meta.url));
const has=command=>spawnSync('sh',['-c',`command -v ${command}`],{stdio:'ignore'}).status===0;
export const needsPodman=env=>!env.WRANGLER_DOCKER_HOST&&!env.DOCKER_HOST&&!has('docker')&&has('podman');
export function podmanEnvironment(env,proxySocket,miniflare) {
  env.WRANGLER_DOCKER_BIN=join(scripts,'podman-docker.sh');
  env.WRANGLER_DOCKER_HOST='unix://'+proxySocket;
  if(!env.MINIFLARE_CONTAINER_EGRESS_IMAGE) {
    const source=miniflare??readFileSync(join(scripts,'../node_modules/miniflare/dist/src/index.js'),'utf8');
    const image=source.match(/DEFAULT_CONTAINER_EGRESS_INTERCEPTOR_IMAGE = "([^"]+)"/)?.[1];
    if(image)env.MINIFLARE_CONTAINER_EGRESS_IMAGE=image.split('/')[0].includes('.')?image:'docker.io/'+image;
  }
}
export async function startPodman(env,{socket,proxySocket,reuse=false,stdio='ignore',detached=false,signal,startupTimeout=10000,allowLate=false}) {
  let service,proxy,closing;
  const close=()=>closing??=(async()=>{
    try {proxy?.close();} finally {await stop(service);}
  })();
  try {
    const answers=()=>spawnSync('podman',['--url','unix://'+socket,'version'],{env,stdio:'ignore',timeout:2000}).status===0;
    if(!reuse||!existsSync(socket)||!answers()) {
      if(!reuse&&existsSync(socket))throw new Error('isolated Podman socket already exists');
      if(reuse)rmSync(socket,{force:true});
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
    return {close};
  } catch(error) {
    try {await close();} catch(cleanupError) {console.error('Podman startup cleanup failed:',cleanupError.message);}
    throw error;
  }
}

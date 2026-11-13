// Shared Docker-compatible Podman bootstrap for development and isolated tests.
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { podmanProxy } from './podman-proxy.mjs';
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
export async function startPodman(env,{socket,proxySocket,reuse=false,stdio='ignore',detached=false}) {
  let service,proxy,closing;
  const close=()=>closing??=(async()=>{
    try {proxy?.close();} finally {
      if(service?.pid&&service.exitCode===null&&service.signalCode===null) {
        const exited=new Promise(resolve=>service.once('exit',resolve));
        const kill=signal=>{try {if(detached)process.kill(-service.pid,signal);else service.kill(signal);}catch{}};
        kill('SIGTERM');const timer=setTimeout(()=>kill('SIGKILL'),5000);
        await exited;clearTimeout(timer);
      }
    }
  })();
  try {
    const answers=()=>spawnSync('podman',['--url','unix://'+socket,'version'],{env,stdio:'ignore'}).status===0;
    if(!reuse||!existsSync(socket)||!answers()) {
      if(!reuse&&existsSync(socket))throw new Error('isolated Podman socket already exists');
      if(reuse)rmSync(socket,{force:true});
      const cgroups=env.DBUS_SESSION_BUS_ADDRESS?[]:['--cgroup-manager=cgroupfs'];
      service=spawn('podman',[...cgroups,'system','service','--time=0','unix://'+socket],{stdio,env,detached});
      let spawnError;service.once('error',error=>{spawnError=error;});
      for(let i=0;i<100&&!existsSync(socket)&&!spawnError;i++)await new Promise(resolve=>setTimeout(resolve,100));
      if(spawnError)throw spawnError;
      if(!existsSync(socket))throw new Error('Podman service did not start');
    }
    proxy=podmanProxy(proxySocket,socket);
    podmanEnvironment(env,proxySocket);
    return {close};
  } catch(error) {
    try {await close();} catch(cleanupError) {console.error('Podman startup cleanup failed:',cleanupError.message);}
    throw error;
  }
}

// Mark only containers created through this run's engine connection. This works
// with Docker or Podman and does not mistake concurrent users' containers for ours.
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { podmanProxy } from '../podman-proxy.mjs';
import { run } from './common.mjs';
export function engineTarget(env) {
  let endpoint=env.WRANGLER_DOCKER_HOST||env.DOCKER_HOST;
  if(!endpoint) {
    const contexts=run(env.WRANGLER_DOCKER_BIN||'docker',['context','ls','--format','json'],{env}).trim().split('\n').map(line=>JSON.parse(line));
    endpoint=contexts.find(c=>c.Current)?.DockerEndpoint||'unix:///var/run/docker.sock';
  }
  if(endpoint.startsWith('unix://'))return {socketPath:endpoint.slice(7)};
  const url=new URL(endpoint.replace(/^tcp:/,'http:'));
  if(!['http:','https:'].includes(url.protocol))throw new Error('unsupported container engine endpoint: '+url.protocol);
  // URL normalizes explicit HTTP(S) ports 80/443 away; retain those too.
  const explicitPort=new URL(endpoint.replace(/^[a-z]+:/i,'tcp:')).port;
  const target={hostname:url.hostname,port:Number(explicitPort||(env.DOCKER_TLS_VERIFY||url.protocol==='https:'?2376:2375)),protocol:url.protocol};
  if(env.DOCKER_TLS_VERIFY||url.protocol==='https:') {
    target.protocol='https:';
    const dir=env.DOCKER_CERT_PATH;if(!dir)throw new Error('TLS container endpoint requires DOCKER_CERT_PATH');
    for(const [key,file] of [['ca','ca.pem'],['cert','cert.pem'],['key','key.pem']])target[key]=readFileSync(join(dir,file));
  }
  return target;
}
export async function containerLease(env,socket) {
  const label={'os.conformance.run':randomUUID()};
  const proxy=podmanProxy(socket,engineTarget(env),{label,stripMemorySwappiness:false});
  await once(proxy,'listening');
  env.WRANGLER_DOCKER_HOST='unix://'+socket;
  const request=(method,path)=>new Promise((resolve,reject)=>{
    const req=http.request({socketPath:socket,method,path},res=>{
      const chunks=[];res.on('data',c=>chunks.push(c));res.on('error',reject);
      res.on('end',()=>{const body=Buffer.concat(chunks).toString();if(res.statusCode>=400&&res.statusCode!==404)reject(new Error(`container cleanup ${method}: ${res.statusCode} ${body}`));else resolve(body);});
    });
    req.setTimeout(30000,()=>req.destroy(new Error('container cleanup timeout')));req.on('error',reject);req.end();
  });
  return {async close() {
    try {
      const filters=encodeURIComponent(JSON.stringify({label:Object.entries(label).map(([k,v])=>k+'='+v)}));
      const containers=JSON.parse(await request('GET','/containers/json?all=true&filters='+filters));
      for(const {Id} of containers)await request('DELETE','/containers/'+encodeURIComponent(Id)+'?force=true');
    } finally {proxy.closeAllConnections();await new Promise((resolve,reject)=>proxy.close(error=>error?reject(error):resolve()));}
  }};
}

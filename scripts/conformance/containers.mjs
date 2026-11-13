// Mark only containers created through this run's engine connection. This works
// with Docker or Podman and does not mistake concurrent users' containers for ours.
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { engineProxy } from './engine-proxy.mjs';
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
  // URL keeps IPv6 brackets in hostname; socket APIs and certificate checks need the bare address.
  const hostname=url.hostname.replace(/^\[(.*)\]$/,'$1');
  const target={hostname,port:Number(explicitPort||(env.DOCKER_TLS_VERIFY||url.protocol==='https:'?2376:2375)),protocol:url.protocol};
  if(env.DOCKER_TLS_VERIFY||url.protocol==='https:') {
    target.protocol='https:';
    const dir=env.DOCKER_CERT_PATH;if(!dir)throw new Error('TLS container endpoint requires DOCKER_CERT_PATH');
    for(const [key,file] of [['ca','ca.pem'],['cert','cert.pem'],['key','key.pem']])target[key]=readFileSync(join(dir,file));
  }
  return target;
}
// Removal is complete only when the engine no longer lists a labelled container. A DELETE can
// answer 404 (already gone) or 409 (removal already in progress, as for workerd's AutoRemove
// containers); both are followed by listing again until nothing is left or the deadline passes.
export async function containerLease(env,socket,{stripMemorySwappiness=false,removalTimeout=30000}={}) {
  const label={'os.conformance.run':randomUUID()};
  const proxy=engineProxy(socket,engineTarget(env),{label,stripMemorySwappiness});
  await once(proxy,'listening');
  env.WRANGLER_DOCKER_HOST='unix://'+socket;
  const request=(method,path)=>new Promise((resolve,reject)=>{
    const req=http.request({socketPath:socket,method,path},res=>{
      const chunks=[];res.on('data',c=>chunks.push(c));res.on('error',reject);
      res.on('end',()=>{const body=Buffer.concat(chunks).toString();if(res.statusCode>=400&&!(method==='DELETE'&&[404,409].includes(res.statusCode)))reject(new Error(`container cleanup ${method}: ${res.statusCode} ${body}`));else resolve(body);});
    });
    req.setTimeout(30000,()=>req.destroy(new Error('container cleanup timeout')));req.on('error',reject);req.end();
  });
  const filters=encodeURIComponent(JSON.stringify({label:Object.entries(label).map(([k,v])=>k+'='+v)}));
  const owned=async()=>{
    const containers=JSON.parse(await request('GET','/containers/json?all=true&filters='+filters));
    if(!Array.isArray(containers))throw new Error('container cleanup GET: expected an array');
    return containers.map(c=>c.Id);
  };
  return {async close() {
    try {
      const deadline=Date.now()+removalTimeout;
      for(let ids=await owned();ids.length;ids=await owned()) {
        if(Date.now()>=deadline)throw new Error('container cleanup: still present after '+removalTimeout+' ms: '+ids.join(', '));
        for(const id of ids)await request('DELETE','/containers/'+encodeURIComponent(id)+'?force=true');
        await new Promise(resolve=>setTimeout(resolve,250));
      }
    } finally {proxy.destroyAllSockets();await new Promise((resolve,reject)=>proxy.close(error=>error?reject(error):resolve()));}
  }};
}

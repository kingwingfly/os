// Mark only containers created through this run's engine connection. This works
// with Docker or Podman and does not mistake concurrent users' containers for ours.
import http from 'node:http';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { engineProxy } from '../engine-proxy.mjs';
import { run } from './common.mjs';
const hint='set DOCKER_HOST to the engine API socket, for example unix:///run/user/$UID/podman/podman.sock';
// The current endpoint in `context ls --format json` output. Docker 23 and later print one
// object per line ({Current, DockerEndpoint}); Podman, and Docker's command line provided by
// podman-docker, print one array ({Default, URI}). Returns null when no context is current
// (the engine's default applies) and undefined when the output is not such a listing, as
// with Docker before 23, which prints the word "json" for each context.
export function contextEndpoint(output) {
  const text=output.trim();
  if(!text)return null;
  let entries;
  try {entries=text.startsWith('[')?JSON.parse(text):text.split('\n').map(line=>JSON.parse(line));}catch {return undefined;}
  if(!Array.isArray(entries)||entries.some(entry=>!entry||typeof entry!=='object'||Array.isArray(entry)))return undefined;
  const current=entries.find(entry=>entry.Current===true||entry.Default===true);
  if(!current)return null;
  const endpoint=current.DockerEndpoint??current.URI;
  return typeof endpoint==='string'&&endpoint?endpoint:undefined;
}
// Without DOCKER_HOST, ask the engine's command line which endpoint is current.
function discoverEndpoint(env,defaultSocket,cli) {
  const bin=env.WRANGLER_DOCKER_BIN||'docker';
  const attempt=args=>{try {return {output:cli(bin,args,{env,stdio:['ignore','pipe','pipe']})};}catch(error) {return {error};}};
  const listed=attempt(['context','ls','--format','json']);
  if(listed.output!==undefined) {
    const endpoint=contextEndpoint(listed.output);
    if(endpoint!==undefined)return endpoint??'unix://'+defaultSocket;
  }
  // Docker before 23: `context inspect` describes the current context.
  const inspected=attempt(['context','inspect']);
  if(inspected.output!==undefined) {
    try {
      const contexts=JSON.parse(inspected.output);
      const host=Array.isArray(contexts)?contexts[0]?.Endpoints?.docker?.Host:undefined;
      if(typeof host==='string'&&host)return host;
    } catch {}
  }
  const reason=(listed.error??inspected.error)?.message?.split('\n')[0]??'unrecognized output';
  throw new Error(`cannot determine the container engine endpoint from \`${bin} context ls\` or \`${bin} context inspect\` (${reason}); ${hint}`);
}
export function engineTarget(env,{defaultSocket='/var/run/docker.sock',cli=run}={}) {
  const endpoint=env.WRANGLER_DOCKER_HOST||env.DOCKER_HOST||discoverEndpoint(env,defaultSocket,cli);
  if(endpoint.startsWith('unix://')) {
    const socketPath=endpoint.slice(7);
    if(!existsSync(socketPath))throw new Error(`container engine socket ${socketPath} does not exist; start the engine or ${hint}`);
    return {socketPath};
  }
  const url=new URL(endpoint.replace(/^tcp:/,'http:'));
  if(!['http:','https:'].includes(url.protocol))throw new Error(`unsupported container engine endpoint ${endpoint}; ${hint}`);
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
  return {label:Object.entries(label).map(([k,v])=>k+'='+v)[0],async close() {
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

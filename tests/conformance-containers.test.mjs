import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { containerLease } from '../scripts/conformance/containers.mjs';
const request=(socket,method,path,body)=>new Promise((resolve,reject)=>{
  const req=http.request({socketPath:socket,method,path,headers:{'Content-Type':'application/json'}},res=>{
    const chunks=[];res.on('data',c=>chunks.push(c));res.on('end',()=>resolve(JSON.parse(Buffer.concat(chunks)||'null')));res.on('error',reject);
  });req.on('error',reject);req.end(body?JSON.stringify(body):undefined);
});
for(const selection of ['docker context','DOCKER_HOST','WRANGLER_DOCKER_HOST'])test('container ownership and cleanup through '+selection,async()=>{
  const dir=await mkdtemp(join(tmpdir(),'conformance-engine-')),socket=join(dir,'engine.sock');
  const containers=new Map([['existing',{Id:'existing',Labels:{}}]]),removed=[];let lease,created;
  const server=http.createServer(async(req,res)=>{
    const url=new URL(req.url,'http://engine');let result;
    if(req.method==='POST') {
      const chunks=[];for await(const c of req)chunks.push(c);
      const body=JSON.parse(Buffer.concat(chunks));created=body;
      result={Id:'owned'};containers.set('owned',{...result,Labels:body.Labels});
    } else if(req.method==='DELETE') {
      const id=url.pathname.split('/').at(-1);removed.push(id);containers.delete(id);result=null;
    } else {
      const [label]=JSON.parse(url.searchParams.get('filters')).label;
      const [key,value]=label.split('=');result=[...containers.values()].filter(c=>c.Labels[key]===value);
    }
    res.setHeader('Content-Type','application/json');res.end(JSON.stringify(result));
  });
  try {
    server.listen(socket);await once(server,'listening');
    const env={};
    if(selection==='docker context') {
      const cli=join(dir,'docker');
      await writeFile(cli,'#!'+process.execPath+'\nconsole.log('+JSON.stringify(JSON.stringify({Current:true,DockerEndpoint:'unix://'+socket}))+');\n',{mode:0o755});
      env.WRANGLER_DOCKER_BIN=cli;
    } else if(selection==='DOCKER_HOST') {
      // Exercise TCP Docker as well as Unix sockets.
      const tcp=http.createServer(server.listeners('request')[0]);tcp.listen(0,'127.0.0.1');await once(tcp,'listening');
      env.DOCKER_HOST='tcp://127.0.0.1:'+tcp.address().port;
      server.once('close',()=>{tcp.closeAllConnections();tcp.close();});
    } else env.WRANGLER_DOCKER_HOST='unix://'+socket;
    lease=await containerLease(env,join(dir,'lease.sock'));
    await request(env.WRANGLER_DOCKER_HOST.slice(7),'POST','/v1.45/containers/create',{Image:'fixture',Labels:{original:'preserved'},HostConfig:{MemorySwappiness:0}});
    assert.equal(created.Labels.original,'preserved');assert.equal(created.HostConfig.MemorySwappiness,0);
    // Concurrent unrelated creation must survive too.
    containers.set('concurrent',{Id:'concurrent',Labels:{}});
    await lease.close();lease=null;
    assert.deepEqual(removed,['owned']);assert.deepEqual([...containers.keys()],['existing','concurrent']);
  } finally {await lease?.close();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));await rm(dir,{recursive:true,force:true});}
});

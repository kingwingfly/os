import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { once } from 'node:events';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { containerLease, engineTarget, contextEndpoint } from '../scripts/conformance/containers.mjs';
import { engineProxy, serverName } from '../scripts/engine-proxy.mjs';

test('proxy explicitly destroys upgraded sockets without replacing Node closeAllConnections',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'conformance-upgrade-')),upstream=http.createServer(),sockets=[];let proxy,client;
  upstream.on('upgrade',(_req,socket)=>{sockets.push(socket);socket.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: fixture\r\n\r\n');});
  try {
    upstream.listen(join(dir,'upstream.sock'));await once(upstream,'listening');
    proxy=engineProxy(join(dir,'proxy.sock'),{socketPath:join(dir,'upstream.sock')});await once(proxy,'listening');
    assert(!Object.hasOwn(proxy,'closeAllConnections'));assert.equal(proxy.closeAllConnections,http.Server.prototype.closeAllConnections);
    client=net.connect(join(dir,'proxy.sock'));await once(client,'connect');
    client.write('GET /attach HTTP/1.1\r\nHost: fixture\r\nConnection: Upgrade\r\nUpgrade: fixture\r\n\r\n');
    assert.match(String((await once(client,'data'))[0]),/101 Switching Protocols/);
    const closed=once(client,'close');proxy.destroyAllSockets();await closed;
  } finally {
    client?.destroy();proxy?.destroyAllSockets();
    if(proxy?.listening)await new Promise(resolve=>proxy.close(resolve));
    for(const socket of sockets)socket.destroy();
    if(upstream.listening)await new Promise(resolve=>upstream.close(resolve));
    await rm(dir,{recursive:true,force:true});
  }
});
const request=(socket,method,path,body)=>new Promise((resolve,reject)=>{
  const req=http.request({socketPath:socket,method,path,headers:{'Content-Type':'application/json'}},res=>{
    const chunks=[];res.on('data',c=>chunks.push(c));res.on('end',()=>resolve(JSON.parse(Buffer.concat(chunks)||'null')));res.on('error',reject);
  });req.on('error',reject);req.end(body?JSON.stringify(body):undefined);
});
// 'already deleted': DELETE answers 404 and the next listing is empty. 'removal in progress':
// workerd's AutoRemove containers answer 409 and disappear shortly after. 'never removed':
// the container stays listed, so cleanup fails at its deadline instead of reporting success.
for(const scenario of ['missing list','invalid list','already deleted','removal in progress','never removed'])test('container cleanup reports '+scenario,async()=>{
  const dir=await mkdtemp(join(tmpdir(),'conformance-engine-error-')),socket=join(dir,'engine.sock');let lease,listings=0,deletes=0;
  const server=http.createServer((req,res)=>{
    res.setHeader('Content-Type','application/json');
    if(scenario==='missing list') {res.statusCode=404;res.end('{"message":"missing endpoint"}');return;}
    if(req.method==='DELETE') {deletes++;res.statusCode=scenario==='already deleted'?404:409;res.end('{"message":"removal already in progress"}');return;}
    listings++;
    const remaining=scenario==='never removed'||scenario==='removal in progress'&&listings<3||scenario==='already deleted'&&listings<2;
    res.end(JSON.stringify(scenario==='invalid list'?{message:'unexpected shape'}:remaining?[{Id:'owned'}]:[]));
  });
  try {
    server.listen(socket);await once(server,'listening');
    lease=await containerLease({DOCKER_HOST:'unix://'+socket},join(dir,'proxy.sock'),{removalTimeout:1000});
    const closing=lease.close();lease=null;
    if(scenario==='already deleted'||scenario==='removal in progress') {await closing;assert(deletes>=1);}
    else await assert.rejects(closing,scenario==='missing list'?/cleanup GET: 404.*missing endpoint/:scenario==='invalid list'?/cleanup GET: expected an array/:/still present after 1000 ms: owned/);
  } finally {await lease?.close();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));await rm(dir,{recursive:true,force:true});}
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


test('Docker TLS defaults to 2376 while plaintext and explicit ports are preserved',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'conformance-tls-options-'));
  try {
    for(const file of ['ca.pem','cert.pem','key.pem'])await writeFile(join(dir,file),'fixture');
    assert.equal(engineTarget({DOCKER_HOST:'tcp://example.test',DOCKER_TLS_VERIFY:'1',DOCKER_CERT_PATH:dir}).port,2376);
    assert.equal(engineTarget({DOCKER_HOST:'https://example.test',DOCKER_CERT_PATH:dir}).port,2376);
    assert.equal(engineTarget({DOCKER_HOST:'tcp://example.test'}).port,2375);
    assert.equal(engineTarget({DOCKER_HOST:'https://example.test:443',DOCKER_CERT_PATH:dir}).port,443);
    assert.equal(engineTarget({DOCKER_HOST:'tcp://example.test:80'}).port,80);
    assert.equal(engineTarget({DOCKER_HOST:'tcp://example.test:1234',DOCKER_TLS_VERIFY:'1',DOCKER_CERT_PATH:dir}).port,1234);
  } finally {await rm(dir,{recursive:true,force:true});}
});

test('IPv6 engine addresses lose their URL brackets; TLS names the engine host, never the client Host header',()=>{
  assert.deepEqual(engineTarget({DOCKER_HOST:'tcp://[::1]:2375'}),{hostname:'::1',port:2375,protocol:'http:'});
  assert.equal(serverName('docker.example'),'docker.example');
  assert.equal(serverName('::1'),'');assert.equal(serverName('192.0.2.1'),'');
});

test('an IPv6 TCP engine is reachable through the proxy',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'conformance-ipv6-'));let proxy;
  const engine=http.createServer((_req,res)=>res.end('engine'));
  try {
    try {engine.listen(0,'::1');await once(engine,'listening');}
    catch(error) {if(['EADDRNOTAVAIL','EAFNOSUPPORT'].includes(error.code))return;throw error;}
    proxy=engineProxy(join(dir,'proxy.sock'),engineTarget({DOCKER_HOST:`tcp://[::1]:${engine.address().port}`}));await once(proxy,'listening');
    const body=await new Promise((resolve,reject)=>http.get({socketPath:join(dir,'proxy.sock'),path:'/_ping'},res=>{let text='';res.on('data',c=>{text+=c;});res.on('end',()=>resolve(text));}).on('error',reject));
    assert.equal(body,'engine');
  } finally {
    proxy?.destroyAllSockets();if(proxy?.listening)await new Promise(resolve=>proxy.close(resolve));
    if(engine.listening)await new Promise(resolve=>engine.close(resolve));
    await rm(dir,{recursive:true,force:true});
  }
});

// A fake engine command line: `context ls` and `context inspect` print fixed output, or fail.
async function fakeCli(dir,{ls,inspect},name='docker') {
  const cli=join(dir,name);
  await writeFile(cli,'#!'+process.execPath+`
const [,,command,sub]=process.argv,out=${JSON.stringify({ls,inspect})}[sub==='ls'?'ls':'inspect'];
if(command!=='context'||out===null){console.error('docker: unknown command');process.exit(1);}
process.stdout.write(out);
`,{mode:0o755});
  return cli;
}
// Real shapes: Docker 23+ prints one object per line; Podman 6.1 (and podman-docker) prints an
// array with Name/URI/Default/ReadWrite; Docker before 23 prints the template text "json".
const contextCases={
  'Docker 23+ one object per line':{ls:JSON.stringify({Current:false,DockerEndpoint:'unix:///other.sock',Name:'default'})+'\n'+JSON.stringify({Current:true,DockerEndpoint:'unix://SOCKET',Name:'work'})+'\n',inspect:null},
  'podman-docker array':{ls:JSON.stringify([{Name:'remote',URI:'ssh://core@host/run/podman.sock',Default:false,ReadWrite:true},{Name:'local',URI:'unix://SOCKET',Default:true,ReadWrite:true}],null,4),inspect:null},
  'Docker before 23':{ls:'json\njson\n',inspect:JSON.stringify([{Name:'default',Endpoints:{docker:{Host:'unix://SOCKET',SkipTLSVerify:false}}}])},
};
for(const [name,outputs] of Object.entries(contextCases))test('engine discovery: '+name,async()=>{
  const dir=await mkdtemp(join(tmpdir(),'conformance-context-')),socket=join(dir,'engine.sock');
  try {
    await writeFile(socket,'');
    const fill=text=>text&&text.replaceAll('SOCKET',socket);
    const cli=await fakeCli(dir,{ls:fill(outputs.ls),inspect:fill(outputs.inspect)});
    assert.deepEqual(engineTarget({WRANGLER_DOCKER_BIN:cli}),{socketPath:socket});
    // An explicit endpoint always wins over discovery.
    assert.deepEqual(engineTarget({WRANGLER_DOCKER_BIN:cli,DOCKER_HOST:'tcp://127.0.0.1:2375'}),{hostname:'127.0.0.1',port:2375,protocol:'http:'});
  } finally {await rm(dir,{recursive:true,force:true});}
});
test('engine discovery: no current context uses the default socket, and a missing socket is explained',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'conformance-context-')),socket=join(dir,'default.sock');
  try {
    const cli=await fakeCli(dir,{ls:'[]\n',inspect:'[]\n'});
    assert.throws(()=>engineTarget({WRANGLER_DOCKER_BIN:cli},{defaultSocket:socket}),/does not exist; start the engine or set DOCKER_HOST/);
    await writeFile(socket,'');
    assert.deepEqual(engineTarget({WRANGLER_DOCKER_BIN:cli},{defaultSocket:socket}),{socketPath:socket});
  } finally {await rm(dir,{recursive:true,force:true});}
});
test('engine discovery: a command line without contexts, and remote endpoints, fail with guidance',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'conformance-context-'));
  try {
    const old=await fakeCli(dir,{ls:null,inspect:null},'old-docker');
    assert.throws(()=>engineTarget({WRANGLER_DOCKER_BIN:old}),/cannot determine the container engine endpoint .*set DOCKER_HOST/);
    const ssh=await fakeCli(dir,{ls:JSON.stringify([{Name:'remote',URI:'ssh://core@host/run/podman.sock',Default:true}]),inspect:null},'ssh-docker');
    assert.throws(()=>engineTarget({WRANGLER_DOCKER_BIN:ssh}),/unsupported container engine endpoint ssh:\/\/core@host.*set DOCKER_HOST/);
  } finally {await rm(dir,{recursive:true,force:true});}
});
test('context listings parse by shape, not by guessing',()=>{
  assert.equal(contextEndpoint(''),null);assert.equal(contextEndpoint('[]'),null);
  assert.equal(contextEndpoint('json\njson'),undefined);assert.equal(contextEndpoint('{"Current":true}'),undefined);
  assert.equal(contextEndpoint('[{"Name":"a","URI":"unix:///a.sock","Default":false}]'),null);
});

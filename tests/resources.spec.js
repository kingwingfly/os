import { test, expect } from './test.js';
import { call, sys, put, rmrf } from './sys.js';
import binaryen from 'binaryen';
const PAGE=65536, proof=p=>({pid:p.pid,proc:p.token});
const image={path:'/usr/bin/sleep',argv:['sleep','60'],cwd:'/',env:[],runtime:'resources-v1'};
async function result(r,c,p={}) { return (await sys(r,[c],p))[0]; }
async function ok(r,c,p={}) { const v=await result(r,c,p);expect(v.err,JSON.stringify(v)).toBeUndefined();return v.ok; }
const set=(r,path,key,value)=>ok(r,{cgroup_set:{path,key,value:String(value)}});
const stat=(r,path)=>ok(r,{cgroup_stat:{path}});
const launch=(r,path)=>ok(r,{execve:{...image,cgroup:path}});
const memory=(r,p,bytes)=>result(r,{resource:{memory:bytes}},proof(p));
async function group(r) { await call(r,'getcreds');const path='/user/resources-'+crypto.randomUUID();await ok(r,{cgroup_create:{path}});return path; }
async function end(r,p) { await sys(r,[{exit:{...proof(p),status:0}},{wait:{pid:String(p.pid),proc:p.token}}],{}, {'X-Registry':'1'}); }
async function remove(r,path) {
  const s=await result(r,{cgroup_stat:{path}});if(s.err)return;
  await set(r,path,'cgroup.kill',1);
  for(const pid of s.ok['subtree.procs'])await sys(r,[{wait:{pid:String(pid)}}],{}, {'X-Registry':'1'});
  for(const child of s.ok.children)await remove(r,child);
  await ok(r,{cgroup_remove:{path}});
}
test('linear-memory limits cover growth, fork, exec, migration, ancestors and exit',async({request:r})=>{
  const path=await group(r), outside=await group(r);let p,q;
  try {
    await ok(r,{cgroup_create:{path:path+'/nested'}});await set(r,path,'memory.max',3*PAGE);
    p=await launch(r,path+'/nested');expect((await memory(r,p,PAGE)).err).toBeUndefined();
    q={...await ok(r,{fork:{pid:p.pid}},proof(p)),token:p.token};
    expect((await stat(r,path))['memory.current']).toBe(2*PAGE);
    expect((await memory(r,q,2*PAGE)).err).toBeUndefined();
    expect((await memory(r,p,2*PAGE)).err?.errno).toBe('EAGAIN');
    expect((await result(r,{fork:{pid:p.pid}},proof(p))).err?.errno).toBe('EAGAIN');
    await set(r,path,'memory.max',PAGE);
    await ok(r,{cgroup_attach:{pid:p.pid,path:path+'/nested'}});
    const replacement=await ok(r,{execve:{...image,...proof(p)}});p.token=replacement.token;
    expect((await stat(r,path))['memory.current']).toBe(3*PAGE);
    expect((await memory(r,p,0)).err).toBeUndefined();
    await ok(r,{cgroup_attach:{pid:q.pid,path:outside}});
    expect((await stat(r,path))['memory.current']).toBe(0);
    expect((await result(r,{cgroup_attach:{pid:q.pid,path}})).err?.errno).toBe('EAGAIN');
    expect((await stat(r,outside))['memory.current']).toBe(2*PAGE);
    await ok(r,{exit:{status:0}},proof(q));
    expect((await stat(r,outside))['memory.current']).toBe(0);
    expect((await stat(r,outside))['pids.current']).toBe(1);
  }finally{for(const x of [p,q])if(x)await end(r,x);await remove(r,path);await remove(r,outside);}
});
test('parallel reservations share one budget and legacy hosts cannot claim enforcement',async({request:r})=>{
  const path=await group(r), processes=[];
  try {
    await set(r,path,'memory.max',3*PAGE);
    expect((await result(r,{resource:{memory:0}})).err?.errno).toBe('EPERM');
    expect((await result(r,{execve:{...image,runtime:null,cgroup:path}})).err?.errno).toBe('EOPNOTSUPP');
    for(let i=0;i<8;i++)processes.push(await launch(r,path));
    const answers=await Promise.all(processes.map(p=>memory(r,p,PAGE)));
    expect(answers.filter(r=>'ok' in r)).toHaveLength(3);
    expect(answers.filter(r=>r.err).map(r=>r.err.errno)).toEqual(Array(5).fill('EAGAIN'));
    expect((await stat(r,path))['memory.current']).toBe(3*PAGE);
    for(const [key,value] of [['cpu.max','1000 100000'],['cpu.weight','200'],['cgroup.freeze','1']])
      expect((await result(r,{cgroup_set:{path,key,value}})).err?.errno).toBe('EOPNOTSUPP');
    expect((await stat(r,path))['resource.unsupported']).toEqual(['cpu.max','cpu.weight','cgroup.freeze']);
  }finally{for(const p of processes)await end(r,p);await remove(r,path);}
});

test('memoryless spawn does not copy the parent charge and a small service fits its own memory limit',async({page})=>{
  test.setTimeout(180000);const r=page.request,path=await group(r);let parent,child;
  const file=await wasm(r,`(module ${output} (memory (export "memory") 1) (data (i32.const 100) "UNIT_OK") (func (export "_start") ${say}))`);
  const config=file+'.json';
  try {
    await set(r,path,'memory.max',PAGE);parent=await launch(r,path);await memory(r,parent,PAGE);
    expect((await result(r,{fork:{pid:parent.pid}},proof(parent))).err?.errno).toBe('EAGAIN');
    child={...await ok(r,{fork:{pid:parent.pid,empty_memory:true}},proof(parent)),token:parent.token};
    expect((await stat(r,path))['memory.current']).toBe(PAGE);
    await end(r,child);child=null;await end(r,parent);parent=null;
    expect((await put(r,'/api/file?path='+config,{data:JSON.stringify({version:1,units:[{name:'small',argv:[file],limits:{memory:PAGE}}]})})).ok()).toBe(true);
    await page.goto('/?recovery=1');await page.waitForFunction(()=>!!window.os?.exec);
    const answer=await page.evaluate(config=>window.os.exec([{path:'/usr/bin/supervise',argv:['supervise',config]}],{stdin:''}),config);
    expect(answer.status,answer.stderr).toBe(0);expect(answer.stdout).toContain('UNIT_OK');
  }finally{for(const p of [child,parent])if(p)await end(r,p);await remove(r,path);await rmrf(r,file);await rmrf(r,config);}
});
test('storage I/O is paced across inline and ranged reads and denied writes never commit',async({request:r})=>{
  test.setTimeout(120000);
  const path=await group(r), file='/guest/io-'+crypto.randomUUID();let p,fd;
  try {
    expect((await put(r,'/api/file?path='+file,{data:'x'.repeat(1000)})).ok()).toBe(true);
    p=await launch(r,path);await set(r,path,'io.max','rbps=1000 wbps=0');
    const started=Date.now();
    const inline=await ok(r,{pread:{path:file,count:100}},proof(p));
    expect(Buffer.from(inline.data,'base64')).toHaveLength(100);
    const headers={'X-Process-Token':p.token,'X-Process-Pid':String(p.pid),Range:'bytes=0-199'};
    const reads=await Promise.all(Array.from({length:3},()=>r.get('/api/file?path='+file,{headers})));
    for(const read of reads){expect(read.status()).toBe(206);expect(await read.body()).toHaveLength(200);}
    expect(Date.now()-started).toBeGreaterThanOrEqual(650);
    expect((await stat(r,path))['io.stat'].read_bytes).toBe(700);
    expect((await r.get('/api/file?path='+file,{headers:{'X-Process-Token':p.token,Range:'bytes=0-1'}})).status()).toBe(400);
    fd=(await ok(r,{open:{path:file+'-out',flags:0o301,mode:0o600,size:1}},proof(p))).fd;
    expect((await result(r,{pwrite:{fd,index:0,data:'eA=='}},proof(p))).err?.errno).toBe('EAGAIN');
    expect((await r.put('/api/pwrite?fd='+fd+'&index=0',{headers:{Origin:process.env.OS_TEST_URL,'X-Process-Token':p.token,'X-Process-Pid':String(p.pid)},data:'x'})).status()).toBe(429);
    expect((await stat(r,path))['io.stat'].write_bytes).toBe(0);
    await set(r,path,'io.max','rbps=max wbps=1000');
    expect((await result(r,{pwrite:{fd,index:0,data:'eA=='}},proof(p))).err).toBeUndefined();
    await ok(r,{close:{fd}},proof(p));fd=null;
    expect((await r.get('/api/file?path='+file+'-out')).ok()).toBe(true);
    for(const value of ['garbage','rbps=-1','rbps=1 rbps=2','riops=1'])expect((await result(r,{cgroup_set:{path,key:'io.max',value}})).err?.errno).toBe('EINVAL');
    // The compatibility path must treat every explicit unlimited spelling as max.
    for(const value of ['max','rbps=max wbps=max','wbps=max rbps=max']) {
      await set(r,path,'io.max',value);
      const legacy=await r.get('/api/file?path='+file,{headers:{'X-Process-Token':p.token,Range:'bytes=0-1'}});
      expect(legacy.status()).toBe(206);expect(await legacy.body()).toHaveLength(2);
    }
  }finally{if(fd&&p)await result(r,{close:{fd}},proof(p));if(p)await end(r,p);await remove(r,path);await rmrf(r,file);await rmrf(r,file+'-out');}
});
async function wasm(r,wat) {
  const path='/guest/memory-'+crypto.randomUUID(), module=binaryen.parseText(wat);
  try{expect((await put(r,'/api/file?path='+path,{data:Buffer.from(module.emitBinary())})).ok()).toBe(true);}finally{module.dispose();}
  await call(r,{chmod:{path,mode:0o755}});return path;
}
const output = `(import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))`;
const say = `(i32.store (i32.const 0) (i32.const 100)) (i32.store (i32.const 4) (i32.const 7)) (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))`;
async function execute(page,path,cgroup) {
  return page.evaluate(async({path,cgroup})=>{
    let diagnostic='';const result=await window.os.exec([{path,argv:[path],cwd:'/',cgroup}],{stdin:'',onOutput:(_,s)=>{diagnostic+=s;}});
    return {...result,diagnostic};
  },{path,cgroup});
}
test('unchanged WASM memory.grow fails at its cgroup ceiling and initial allocation is admitted first',async({page})=>{
  test.setTimeout(180000);const r=page.request,path=await group(r);
  const file=await wasm(r,`(module ${output} (memory (export "memory") 1 10) (data (i32.const 100) "GROW_OK")
    (func (export "_start")
      (if (i32.ne (memory.grow (i32.const 1)) (i32.const 1)) (then unreachable))
      (if (i32.ne (memory.grow (i32.const 1)) (i32.const -1)) (then unreachable)) ${say}))`);
  try {
    await page.goto('/?recovery=1');await page.waitForFunction(()=>!!window.os?.exec);
    await set(r,path,'memory.max',2*PAGE);
    const answer=await execute(page,file,path);expect(answer.status,answer.diagnostic).toBe(0);expect(answer.stdout).toBe('GROW_OK');
    await expect.poll(async()=>(await stat(r,path))['memory.current']).toBe(0);
    await set(r,path,'memory.max',0);
    const denied=await execute(page,file,path);expect(denied.status).not.toBe(0);expect(denied.stdout).toBe('');
    await expect.poll(async()=>(await stat(r,path))['memory.current']).toBe(0);
  }finally{await remove(r,path);await rmrf(r,file);}
});
test('fork reserves scratch and copied linear memories before starting the child',async({page})=>{
  test.setTimeout(180000);const r=page.request,path=await group(r);
  const file=await wasm(r,`(module ${output}
    (import "wasix_32v1" "proc_fork" (func $fork (param i32 i32) (result i32)))
    (memory (export "memory") 1) (data (i32.const 100) "FORK_OK")
    (func (export "_start")
      (if (i32.ne (call $fork (i32.const 1) (i32.const 32)) (i32.const 6)) (then unreachable)) ${say}))`);
  try {
    await page.goto('/?recovery=1');await page.waitForFunction(()=>!!window.os?.exec);
    await set(r,path,'memory.max',5*PAGE);
    const answer=await execute(page,file,path);expect(answer.status,answer.diagnostic).toBe(0);expect(answer.stdout).toBe('FORK_OK');
    await expect.poll(async()=>(await stat(r,path))['memory.current']).toBe(0);
  }finally{await remove(r,path);await rmrf(r,file);}
});

test('a child killed during its first memory reservation is reaped without a startup diagnostic',async({page})=>{
  const r=page.request,path=await group(r);
  const file=await wasm(r,`(module ${output}
    (import "wasix_32v1" "proc_fork" (func $fork (param i32 i32) (result i32)))
    (import "wasix_32v1" "proc_signal" (func $kill (param i32 i32) (result i32)))
    (import "wasix_32v1" "proc_join" (func $join (param i32 i32 i32) (result i32)))
    (memory (export "memory") 2)
    (global $__stack_pointer (export "__stack_pointer") (mut i32) (i32.const 60000))
    (data (i32.const 100) "REAP_OK")
    (func (export "_start")
      (if (call $fork (i32.const 1) (i32.const 32)) (then unreachable))
      (if (i32.eqz (i32.load (i32.const 32))) (then unreachable))
      (if (call $kill (i32.load (i32.const 32)) (i32.const 9)) (then unreachable))
      (i32.store8 (i32.const 40) (i32.const 1))
      (i32.store (i32.const 44) (i32.load (i32.const 32)))
      (if (call $join (i32.const 40) (i32.const 0) (i32.const 48)) (then unreachable))
      (if (i32.ne (i32.load8_u (i32.const 48)) (i32.const 2)) (then unreachable))
      (if (i32.ne (i32.load8_u (i32.const 52)) (i32.const 9)) (then unreachable)) ${say}))`);
  let parent,child,denied=false,releaseKill,releaseReservation,startedReservation;
  const killed=new Promise(resolve=>{releaseKill=resolve;});
  const reserved=new Promise(resolve=>{releaseReservation=resolve;});
  const reserving=new Promise(resolve=>{startedReservation=resolve;});
  const handler=async route=>{
    const body=route.request().postDataJSON(),calls=body?.calls??[];
    if(calls.some(c=>c.resource)) {
      parent??=body.pid;
      if(body.pid!==parent) {
        child=body.pid;startedReservation();await killed;
        const response=await route.fetch();
        denied=(await response.json()).results[0].err?.errno==='EPERM';
        await route.fulfill({response});releaseReservation();return;
      }
    }
    const kill=calls.find(c=>c.kill?.signal===9);
    if(kill) {
      // Commit revocation while the child is still reserving, but hold the
      // parent's kill reply until the denied reservation has reached the child.
      await reserving;const response=await route.fetch();releaseKill();await reserved;
      await route.fulfill({response});return;
    }
    await route.continue();
  };
  try {
    await page.goto('/?recovery=1');await page.waitForFunction(()=>!!window.os?.exec);
    await page.route('**/api/sys',handler);
    const answer=await execute(page,file,path);
    expect(child).toBeGreaterThan(parent);expect(denied).toBe(true);
    expect(answer.status,answer.diagnostic).toBe(0);
    expect(answer.stdout).toBe('REAP_OK');expect(answer.diagnostic).toBe('');
    await expect.poll(async()=>(await stat(r,path))['memory.current']).toBe(0);
  }finally{startedReservation();releaseKill();releaseReservation();await page.unroute('**/api/sys',handler);await remove(r,path);await rmrf(r,file);}
});

test('guest syscalls cannot forge runtime accounting or import its private callbacks',async({page})=>{
  test.setTimeout(180000);const r=page.request,path=await group(r);
  const request=JSON.stringify([{resource:{memory:0}}]);
  const data=Buffer.from(request).toString('hex').match(/../g).map(b=>'\\'+b).join('');
  const file=await wasm(r,`(module ${output}
    (import "os" "sys" (func $sys (param i32 i32) (result i32)))
    (import "os" "reply" (func $reply (param i32)))
    (memory (export "memory") 1) (data (i32.const 100) "${data}")
    (func (export "_start") (local $n i32)
      (local.set $n (call $sys (i32.const 100) (i32.const ${request.length})))
      (call $reply (i32.const 500))
      (if (i32.ne (memory.grow (i32.const 1)) (i32.const -1)) (then unreachable))
      (i32.store (i32.const 0) (i32.const 500)) (i32.store (i32.const 4) (local.get $n))
      (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))))`);
  const forged=await wasm(r,`(module (import "os_runtime" "memory_grow_pre" (func (param i32 i32) (result i32))) (memory (export "memory") 1) (func (export "_start")))`);
  try {
    await page.goto('/?recovery=1');await page.waitForFunction(()=>!!window.os?.exec);
    await set(r,path,'memory.max',PAGE);
    const answer=await execute(page,file,path);expect(answer.status,answer.diagnostic).toBe(0);expect(answer.stdout).toContain('EPERM');
    await expect(execute(page,forged,path)).rejects.toThrow(/unknown import/);
  }finally{await remove(r,path);await rmrf(r,file);await rmrf(r,forged);}
});

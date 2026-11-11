import { test, expect } from './test.js';
import { api, call, errno, put, rmrf, sys } from './sys.js';
import { readFile } from 'node:fs/promises';
import binaryen from 'binaryen';
const registry={'X-Registry':'1'}, proof=p=>({pid:p.pid,proc:p.token});
const image={path:'/usr/bin/sleep',argv:['sleep','60'],cwd:'/',env:[]};
async function reply(request,command,options={}) { return (await sys(request,[command],options,registry))[0]; }
async function ok(request,command,options={}) { const r=await reply(request,command,options);expect(r.err,JSON.stringify(r)).toBeUndefined();return r.ok; }
async function denied(request,command,errno,options={}) { expect((await reply(request,command,options)).err?.errno).toBe(errno); }
const stat=(r,path)=>ok(r,{cgroup_stat:{path}});
const limit=(r,path,value)=>ok(r,{cgroup_set:{path,key:'pids.max',value:String(value)}});
const launch=(r,path)=>ok(r,{execve:{...image,cgroup:path}});
const fork=async(r,p,child)=>({...await ok(r,{fork:{pid:p.pid,...(child==null?{}:{child})}},proof(p)),token:p.token});
async function finish(r,p) { await sys(r,[{exit:{...proof(p),status:0}},{wait:{pid:String(p.pid),proc:p.token}}],{},registry); }
async function make(r) { await call(r,'getcreds');const path='/user/pids-'+crypto.randomUUID();await ok(r,{cgroup_create:{path}});return path; }
async function remove(r,path) {
  const s=await reply(r,{cgroup_stat:{path}});if(s.err)return;
  await ok(r,{cgroup_set:{path,key:'cgroup.kill',value:'1'}});
  for(const pid of s.ok['subtree.procs']) await reply(r,{wait:{pid:String(pid)}});
  for(const child of s.ok.children) await remove(r,child);
  await ok(r,{cgroup_remove:{path}});
}

test('hierarchical PID limits count zombies until reap and exec preserves a full slot',async({request})=>{
  const path=await make(request);let parent;
  try {
    await ok(request,{cgroup_create:{path:path+'/nested'}});await limit(request,path,2);
    await limit(request,path+'/nested',10);parent=await launch(request,path+'/nested');
    const child=await fork(request,parent);
    expect((await stat(request,path))['pids.current']).toBe(2);
    await denied(request,{fork:{pid:parent.pid}},'EAGAIN',proof(parent));
    const replaced=await ok(request,{execve:{...image,...proof(parent)}});parent.token=replaced.token;
    expect(replaced.cgroup).toBe(path+'/nested');
    await ok(request,{exit:{status:0}},proof(child));
    expect((await stat(request,path))['pids.current']).toBe(2);
    await denied(request,{fork:{pid:parent.pid}},'EAGAIN',proof(parent));
    await ok(request,{waitpid:{pid:child.pid,options:1}},proof(parent));
    expect((await stat(request,path))['pids.current']).toBe(1);
    const next=await fork(request,parent);await finish(request,next);
    await limit(request,path,0);
    await denied(request,{fork:{pid:parent.pid}},'EAGAIN',proof(parent));
    expect((await stat(request,path))['pids.current']).toBe(1);
    await limit(request,path,'max');await finish(request,await fork(request,parent));
  }finally{if(parent)await finish(request,parent);await remove(request,path);}
});

test('parallel exec admission grants exactly the available slots and isolates a sibling',async({request})=>{
  const path=await make(request), sibling=path+'-sibling';
  await ok(request,{cgroup_create:{path:sibling}});
  try {
    await limit(request,path,3);
    const results=await Promise.all(Array.from({length:12},()=>reply(request,{execve:{...image,cgroup:path}})));
    expect(results.filter(r=>r.ok)).toHaveLength(3);
    expect(results.filter(r=>r.err).map(r=>r.err.errno)).toEqual(Array(9).fill('EAGAIN'));
    expect((await stat(request,path))['pids.current']).toBe(3);
    const other=await launch(request,sibling);await finish(request,other);
    for(const r of results.filter(r=>r.ok))await finish(request,r.ok);
    expect((await stat(request,path))['pids.current']).toBe(0);
    await finish(request,await launch(request,path));
  }finally{await remove(request,path);await remove(request,sibling);}
});

test('parallel forks and preallocated PID numbers cannot overrun a group',async({request})=>{
  const path=await make(request);let parent;
  try {
    await limit(request,path,4);parent=await launch(request,path);
    const results=await Promise.all(Array.from({length:12},()=>reply(request,{fork:{pid:parent.pid}},proof(parent))));
    expect(results.filter(r=>r.ok)).toHaveLength(3);
    expect(results.filter(r=>r.err).every(r=>r.err.errno==='EAGAIN')).toBe(true);
    const [lent]=await ok(request,{pids:{count:1,kernel:'pid-limit-'+crypto.randomUUID()}},proof(parent));
    for(let i=0;i<12;i++)await denied(request,{fork:{pid:parent.pid,child:lent}},'EAGAIN',proof(parent));
    expect((await stat(request,path))['pids.current']).toBe(4);
    for(const r of results.filter(r=>r.ok))await finish(request,{...r.ok,token:parent.token});
    expect((await fork(request,parent,lent)).pid).toBe(lent);
  }finally{if(parent)await finish(request,parent);await remove(request,path);}
});

test('migration checks only gaining ancestors and refuses overflow without moving the process',async({request})=>{
  const path=await make(request), outside=await make(request);let p,q;
  try {
    for(const name of ['a','b'])await ok(request,{cgroup_create:{path:path+'/'+name}});
    await limit(request,path,1);p=await launch(request,path+'/a');q=await launch(request,outside);
    await ok(request,{cgroup_attach:{pid:p.pid,path:path+'/b'}});
    await limit(request,path,0);
    await ok(request,{cgroup_attach:{pid:p.pid,path:path+'/a'}});
    await ok(request,{cgroup_attach:{pid:p.pid,path:path+'/a'}});
    await denied(request,{cgroup_attach:{pid:q.pid,path:path+'/b'}},'EAGAIN');
    expect((await stat(request,outside))['cgroup.procs']).toContain(q.pid);
    await denied(request,{fork:{pid:p.pid}},'EAGAIN',proof(p));
    await limit(request,path,'max');await limit(request,path+'/b',0);
    await denied(request,{cgroup_attach:{pid:p.pid,path:path+'/b'}},'EAGAIN');
    expect((await stat(request,path+'/a'))['cgroup.procs']).toContain(p.pid);
  }finally{for(const p0 of [p,q])if(p0)await finish(request,p0);await remove(request,path);await remove(request,outside);}
});

test('parallel migrations share the same atomic destination budget',async({request})=>{
  const path=await make(request), outside=await make(request);const processes=[];
  try {
    for(let i=0;i<6;i++)processes.push(await launch(request,outside));
    await limit(request,path,1);
    const results=await Promise.all(processes.map(p=>reply(request,{cgroup_attach:{pid:p.pid,path}})));
    expect(results.filter(r=>'ok' in r)).toHaveLength(1);
    expect(results.filter(r=>r.err).map(r=>r.err.errno)).toEqual(Array(5).fill('EAGAIN'));
    expect((await stat(request,path))['pids.current']).toBe(1);
    expect((await stat(request,outside))['pids.current']).toBe(5);
  }finally{for(const p of processes)await finish(request,p);await remove(request,path);await remove(request,outside);}
});

test('failed authorization uses no PID slot and capability reporting distinguishes stored limits',async({request})=>{
  const path=await make(request);
  try {
    await limit(request,path,1);
    for(const value of ['-1','+1','1.5','4294967296',''])await denied(request,{cgroup_set:{path,key:'pids.max',value}},'EINVAL');
    await ok(request,{cgroup_set:{path,key:'memory.max',value:'1024'}});
    for(let i=0;i<5;i++)await denied(request,{execve:{...image,path:'/usr/bin/missing-pid-limit',cgroup:path}},'ENOENT');
    const s=await stat(request,path);
    expect(s).toMatchObject({'pids.current':0,'pids.max':1,'memory.max':'1024','resource.enforced':['pids.max','memory.max','io.max']});
    await denied(request,{execve:{...image,cgroup:path}},'EOPNOTSUPP');
    await ok(request,{cgroup_set:{path,key:'memory.max',value:'max'}});
    await finish(request,await launch(request,path));
    expect((await stat(request,path))['pids.current']).toBe(0);
  }finally{await remove(request,path);}
});

test('root-owned PID policy remains authoritative after browser logout',async({request})=>{
  await call(request,'getcreds');
  const password=(await readFile('.dev.vars','utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
  expect((await api(request,'login',{headers:{'CF-Connecting-IP':'pids-'+crypto.randomUUID()},data:{password}})).ok()).toBe(true);
  const path=await make(request);let parent;
  try {
    await limit(request,path,1);parent=await launch(request,path);await api(request,'logout');
    await denied(request,{cgroup_set:{path,key:'pids.max',value:'max'}},'EACCES');
    await denied(request,{fork:{pid:parent.pid}},'EAGAIN',proof(parent));
    await ok(request,{cgroup_set:{path,key:'pids.max',value:'2'}},proof(parent));
    await finish(request,await fork(request,parent));
  }finally{
    if(parent){await ok(request,{cgroup_attach:{pid:parent.pid,path:'/user'}},proof(parent));await ok(request,{cgroup_remove:{path}},proof(parent));await finish(request,parent);}
    await api(request,'logout');
  }
});

test('exec and migration racing keep the final authorized membership',async({request})=>{
  const path=await make(request), destination=await make(request);let p;
  try {
    await limit(request,path,1);await limit(request,destination,1);p=await launch(request,path);
    for(let i=0;i<8;i++) {
      const target=i%2?path:destination;
      const [replaced]=await Promise.all([ok(request,{execve:{...image,...proof(p)}}),ok(request,{cgroup_attach:{pid:p.pid,path:target}})]);
      p.token=replaced.token;
      expect((await stat(request,target))['cgroup.procs']).toContain(p.pid);
      expect((await stat(request,target===path?destination:path))['pids.current']).toBe(0);
    }
  }finally{if(p)await finish(request,p);await remove(request,path);await remove(request,destination);}
});

async function connect(page) {
  await page.goto('/login');
  await page.evaluate(()=>{
    const worker=new Worker('/client-kernel.js'),pending=new Map();let next=0;
    worker.onmessage=({data})=>{if(pending.has(data.id)){pending.get(data.id)(data);pending.delete(data.id);}};
    window.pidKernel=(type,args={})=>new Promise(resolve=>{const id=++next;pending.set(id,resolve);worker.postMessage({v:1,id,type,args});});
  });
}
const kc=(page,type,args={})=>page.evaluate(([type,args])=>window.pidKernel(type,args),[type,args]);
async function kv(page,type,args={}) {const r=await kc(page,type,args);expect(r.err,JSON.stringify(r)).toBeUndefined();return r.ok;}

test('client kernel waits for admission and reuses rejected lends after capacity returns',async({page})=>{
  await connect(page);await kv(page,'init');const path=await make(page.request);let parent;
  try {
    await limit(page.request,path,1);parent=await kv(page,'exec',{...image,cgroup:path});
    for(let i=0;i<24;i++)expect((await kc(page,'fork',{pid:parent.pid})).err?.errno).toBe('EAGAIN');
    expect((await stat(page.request,path))['pids.current']).toBe(1);
    await limit(page.request,path,2);const child=await kv(page,'fork',{pid:parent.pid});
    expect((await stat(page.request,path))['pids.current']).toBe(2);
    await kv(page,'exit',{pid:child.pid,status:0});await kv(page,'waitchild',{ppid:parent.pid,pid:child.pid});
    const replacement=await kv(page,'fork',{pid:parent.pid});
    expect((await stat(page.request,path))['cgroup.procs']).toContain(replacement.pid);
    await kv(page,'exit',{pid:replacement.pid,status:0});await kv(page,'waitchild',{ppid:parent.pid,pid:replacement.pid});
  }finally{if(parent){await kv(page,'exit',{pid:parent.pid,status:0});await kv(page,'wait',{pid:parent.pid});}await remove(page.request,path);}
});

async function run(page,units) {
  await page.goto('/');await page.waitForFunction(()=>!!window.os?.exec);
  const base='/guest/pids-'+crypto.randomUUID();await call(page.request,{mkdir:{path:base,mode:0o700}});
  const file=base+'/units.json';expect((await put(page.request,'/api/file?path='+file,{data:JSON.stringify({version:1,units})})).ok()).toBe(true);
  await page.evaluate(file=>{
    const r=window.pidRun={output:''};r.done=window.os.exec([{path:'/usr/bin/supervise',argv:['supervise',file]}],{tty:true,stdin:'',onJob:j=>{r.job=j;},onOutput:(_fd,s)=>{r.output+=s;}}).then(result=>{r.result=result;},e=>{r.error=String(e);});
  },file);
  return base;
}
async function complete(page,status) {
  await expect.poll(()=>page.evaluate(()=>window.pidRun.result?.status??window.pidRun.error),{timeout:60000}).toBe(status);
  return page.evaluate(()=>window.pidRun.output);
}
async function cleanup(page,base) {
  await page.evaluate(async()=>{window.pidRun?.job?.signal(9);await window.pidRun?.done;});await rmrf(page.request,base);
}

test('supervisor enforces zero before guest code and allows exec with a single PID slot',async({page})=>{
  let base=await run(page,[{name:'zero',argv:['printf','UNEXPECTED_GUEST'],limits:{pids:0}}]);
  try{expect(await complete(page,1)).not.toContain('UNEXPECTED_GUEST');}finally{await cleanup(page,base);}
  base=await run(page,[{name:'one',argv:['sh','-c','exec printf SINGLE_PID_OK'],limits:{pids:1}}]);
  try{expect(await complete(page,0)).toContain('SINGLE_PID_OK');}finally{await cleanup(page,base);}
});

test('real WASIX fork returns EAGAIN before a denied child can execute',async({page})=>{
  await call(page.request,'getcreds');const path='/guest/pid-fork-'+crypto.randomUUID();
  const module=binaryen.parseText(`(module
    (import "wasix_32v1" "proc_fork" (func $fork (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
    (memory (export "memory") 1) (data (i32.const 100) "FORK_DENIED_OK")
    (func (export "_start") (local $i i32)
      (loop $again
        (if (i32.ne (call $fork (i32.const 1) (i32.const 32)) (i32.const 6)) (then unreachable))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br_if $again (i32.lt_u (local.get $i) (i32.const 16))))
      (i32.store (i32.const 0) (i32.const 100)) (i32.store (i32.const 4) (i32.const 14))
      (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))))`);
  try{expect((await put(page.request,'/api/file?path='+path,{data:Buffer.from(module.emitBinary())})).ok()).toBe(true);}finally{module.dispose();}
  await call(page.request,{chmod:{path,mode:0o755}});
  const base=await run(page,[{name:'forks',argv:[path],limits:{pids:1}},{name:'independent',argv:['printf','OTHER_SERVICE_OK'],limits:{pids:1}}]);
  try{const output=await complete(page,0);expect(output).toContain('FORK_DENIED_OK');expect(output).toContain('OTHER_SERVICE_OK');}
  finally{await cleanup(page,base);await call(page.request,{unlink:{path}});}
});

test('failed service image admission and retries leave no group capacity behind',async({page})=>{
  const base=await run(page,[{name:'bad',argv:['/usr/bin/missing-pids-image'],limits:{pids:1},restart:'on-failure',max_restarts:2,restart_delay_ms:100}]);
  try{
    expect((await complete(page,1)).match(/start failed:/g)).toHaveLength(3);
    expect((await ok(page.request,{cgroup_list:{path:'/user'}})).filter(p=>p.startsWith('/user/supervise-'))).toEqual([]);
  }finally{await cleanup(page,base);}
});

test('cancelling a parent during fork admission prevents late child execution and releases its row',async({page,context})=>{
  await page.goto('/');await page.waitForFunction(()=>!!window.os?.exec);
  const base='/guest/late-fork-'+crypto.randomUUID();await call(page.request,{mkdir:{path:base,mode:0o700}});
  const marker=base+'/unexpected', args='touch\n'+marker;
  const escaped=[...Buffer.from(args)].map(b=>'\\'+b.toString(16).padStart(2,'0')).join('');
  const module=binaryen.parseText(`(module
    (import "wasix_32v1" "proc_fork" (func $fork (param i32 i32) (result i32)))
    (import "wasix_32v1" "proc_exec" (func $exec (param i32 i32 i32 i32)))
    (memory (export "memory") 1)
    (data (i32.const 100) "/usr/bin/touch") (data (i32.const 200) "${escaped}")
    (func (export "_start")
      (if (call $fork (i32.const 1) (i32.const 32)) (then unreachable))
      (if (i32.eqz (i32.load (i32.const 32))) (then
        (call $exec (i32.const 100) (i32.const 14) (i32.const 200) (i32.const ${Buffer.byteLength(args)}))))))`);
  try{expect((await put(page.request,'/api/file?path='+base+'/probe',{data:Buffer.from(module.emitBinary())})).ok()).toBe(true);}finally{module.dispose();}
  await call(page.request,{chmod:{path:base+'/probe',mode:0o755}});
  let release,admitted,held=false;const released=new Promise(r=>{release=r;}),arrived=new Promise(r=>{admitted=r;});
  const handler=async route=>{
    const body=route.request().postDataJSON();const index=body?.calls?.findIndex(c=>c?.fork);
    if(held||!(index>=0))return route.continue();
    held=true;const response=await route.fetch();const data=await response.json();
    admitted(data.results[index]);await released;await route.fulfill({response});
  };
  await context.route('**/api/sys',handler);
  try {
    await page.evaluate(path=>{const r=window.pidRun={output:''};r.done=window.os.exec([{path,argv:[path]}],{tty:true,stdin:'',onJob:j=>{r.job=j;}}).then(v=>{r.result=v;});},base+'/probe');
    const result=await Promise.race([arrived,new Promise((_,reject)=>setTimeout(()=>reject(new Error('fork was not admitted')),30000))]);
    expect(result.err).toBeUndefined();const child=result.ok.pid;
    await page.evaluate(()=>{window.pidRun.job.signal(9);});release();
    await complete(page,137);
    await expect.poll(async()=>(await ok(page.request,{proc_poll:{pids:[child]}})).length,{timeout:20000}).toBe(0);
    expect(await errno(page.request,{stat:{path:marker}})).toBe('ENOENT');
  }finally{release();await context.unroute('**/api/sys',handler);await cleanup(page,base);}
});

test('authorized invalid executable loading releases admitted service slots across retries',async({page})=>{
  await call(page.request,'getcreds');const path='/guest/invalid-pid-image-'+crypto.randomUUID();
  expect((await put(page.request,'/api/file?path='+path,{data:'not a WebAssembly module'})).ok()).toBe(true);
  await call(page.request,{chmod:{path,mode:0o755}});
  const base=await run(page,[{name:'invalid',argv:[path],limits:{pids:1},restart:'on-failure',max_restarts:2,restart_delay_ms:100},
    {name:'healthy',argv:['printf','HEALTHY_PID_SLOT'],limits:{pids:1}}]);
  try {
    const output=await complete(page,1);expect(output.match(/start failed:/g)).toHaveLength(3);expect(output).toContain('HEALTHY_PID_SLOT');
    expect((await ok(page.request,{cgroup_list:{path:'/user'}})).filter(p=>p.startsWith('/user/supervise-'))).toEqual([]);
    expect((await ok(page.request,{proc_poll:{pids:[]}})).some(p=>p.path===path)).toBe(false);
  }finally{await cleanup(page,base);await call(page.request,{unlink:{path}});}
});

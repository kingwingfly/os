import { test, expect } from './test.js';
import { api, call, errno, put, rmrf, sys } from './sys.js';
import { readFile } from 'node:fs/promises';
import binaryen from 'binaryen';
const password=(await readFile('.dev.vars','utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const registry={'X-Registry':'1'}, proof=p=>({pid:p.pid,proc:p.token});
const image={path:'/usr/bin/sleep',argv:['sleep','60'],cwd:'/',env:[]};
async function result(request, command, options={}, denied) {
  const [answer]=await sys(request,[command],options,registry);
  if(denied) { expect(answer.err?.errno,JSON.stringify(answer)).toBe(denied); return; }
  expect(answer.err,JSON.stringify(answer)).toBeUndefined(); return answer.ok;
}
const invoke=(request,p,command,denied)=>result(request,command,proof(p),denied);
const launch=request=>result(request,{execve:image});
async function fork(request,parent) { const child=await invoke(request,parent,{fork:{pid:parent.pid}}); return {...child,token:parent.token}; }
async function finish(request,p) { await sys(request,[{exit:{...proof(p),status:0}},{wait:{pid:String(p.pid),proc:p.token}}],{},registry); }

test('subreapers adopt nearest descendants, survive exec, and are not inherited by fork', async ({request})=>{
  await call(request,'getcreds'); const root=await launch(request);
  try {
    await result(request,{prctl:{option:36,value:1}},{},'EPERM');
    await invoke(request,root,{prctl:{option:36,value:1}});
    const middle=await fork(request,root);
    expect(await invoke(request,middle,{prctl:{option:37}})).toBe(0);
    await invoke(request,middle,{prctl:{option:36,value:1}});
    const parent=await fork(request,middle), leaf=await fork(request,parent);
    const replacement=await result(request,{execve:{...image,...proof(root)}}); root.token=replacement.token;
    expect(await invoke(request,root,{prctl:{option:37}})).toBe(1);
    await invoke(request,root,{prctl:{option:999}},'EINVAL');
    await invoke(request,leaf,'setsid'); await invoke(request,parent,{exit:{status:0}});
    expect((await invoke(request,leaf,'getpid')).ppid).toBe(middle.pid);
    await invoke(request,middle,{waitpid:{pid:parent.pid,options:1}});
    await invoke(request,middle,{exit:{status:0}});
    expect((await invoke(request,leaf,'getpid')).ppid).toBe(root.pid);
    await invoke(request,leaf,{exit:{status:7}});
    expect((await invoke(request,root,{waitpid:{pid:leaf.pid,options:1}})).status).toBe(7<<8);
    await invoke(request,root,{waitpid:{pid:middle.pid,options:1}});
  } finally { await finish(request,root); }
});

test('recursive cgroup kill and owner death contain detached descendants without matching sibling prefixes', async ({request})=>{
  await call(request,'getcreds'); const owner=await launch(request), path='/user/bound-'+crypto.randomUUID();
  const sibling=path+'-other';
  try {
    await invoke(request,owner,{cgroup_create:{path,lifetime:'process'}});
    await invoke(request,owner,{cgroup_create:{path:path+'/nested'}});
    await invoke(request,owner,{cgroup_create:{path:sibling}});
    const child=await fork(request,owner), other=await fork(request,owner);
    await invoke(request,owner,{cgroup_attach:{pid:child.pid,path:path+'/nested'}});
    await invoke(request,owner,{cgroup_attach:{pid:other.pid,path:sibling}});
    await invoke(request,child,'setsid');
    await invoke(request,owner,{cgroup_set:{path,key:'cgroup.kill',value:'0'}},'EINVAL');
    expect((await invoke(request,child,'getpid')).pid).toBe(child.pid);
    await invoke(request,owner,{cgroup_set:{path,key:'cgroup.kill',value:'1'}});
    expect((await invoke(request,owner,{waitpid:{pid:child.pid,options:1}})).signal).toBe(9);
    expect((await invoke(request,other,'getpid')).pid).toBe(other.pid);
    const last=await fork(request,owner); await invoke(request,owner,{cgroup_attach:{pid:last.pid,path}});
    await result(request,{kill:{pid:String(owner.pid),signal:9}});
    await invoke(request,last,'getpid','EPERM');
    expect((await invoke(request,other,'getpid')).pid).toBe(other.pid);
    await result(request,{cgroup_stat:{path}},{},'ENOENT');
    await finish(request,other);
  } finally { await finish(request,owner); await result(request,{cgroup_remove:{path:sibling}}); }
});

test('process lifetime creation requires a real process and enforces bounded ownership',async({request})=>{
  await call(request,'getcreds'); const owner=await launch(request), base='/user/budget-'+crypto.randomUUID();
  await result(request,{cgroup_create:{path:base,lifetime:'process'}},{},'EPERM');
  try {
    for(let i=0;i<32;i++) await invoke(request,owner,{cgroup_create:{path:base+'-'+i,lifetime:'process'}});
    await invoke(request,owner,{cgroup_create:{path:base+'-excess',lifetime:'process'}},'ENOSPC');
  } finally { await finish(request,owner); }
  const children=await result(request,{cgroup_list:{path:'/user'}});
  expect(children.filter(path=>path.startsWith(base))).toEqual([]);
});

test('retiring cgroups reject late attach exec and creation until their zombies are reaped',async({request})=>{
  await call(request,'getcreds'); const owner=await launch(request), parent=await launch(request), path='/user/retired-'+crypto.randomUUID();
  try {
    await invoke(request,owner,{cgroup_create:{path,lifetime:'process'}});
    const child=await fork(request,parent); await invoke(request,parent,{cgroup_attach:{pid:child.pid,path}});
    await result(request,{kill:{pid:String(owner.pid),signal:9}});
    expect((await result(request,{cgroup_stat:{path}})).lifetime.retiring).toBe(true);
    await invoke(request,parent,{cgroup_attach:{pid:parent.pid,path}},'ESTALE');
    await result(request,{execve:{...image,cgroup:path}},{},'ESTALE');
    await invoke(request,parent,{cgroup_create:{path:path+'/late'}},'ESTALE');
    expect((await invoke(request,parent,{waitpid:{pid:child.pid,options:1}})).signal).toBe(9);
    await result(request,{cgroup_stat:{path}},{},'ENOENT');
  } finally {await finish(request,owner);await finish(request,parent);}
});

test('guest cannot kill a root cgroup through the registry route',async({request})=>{
  await call(request,'getcreds');
  expect((await api(request,'login',{headers:{'CF-Connecting-IP':'containment-'+crypto.randomUUID()},data:{password}})).ok()).toBe(true);
  const owner=await launch(request), path='/user/root-'+crypto.randomUUID();
  try {
    await invoke(request,owner,{cgroup_create:{path,lifetime:'process'}});
    const child=await fork(request,owner); await invoke(request,owner,{cgroup_attach:{pid:child.pid,path}});
    await api(request,'logout'); await result(request,{cgroup_set:{path,key:'cgroup.kill',value:'1'}},{},'EACCES');
    expect((await invoke(request,child,'getpid')).pid).toBe(child.pid);
    await invoke(request,owner,{cgroup_set:{path,key:'cgroup.kill',value:'1'}});
    expect((await invoke(request,owner,{waitpid:{pid:child.pid,options:1}})).signal).toBe(9);
  } finally { await finish(request,owner); }
});

let base;
async function setup(page) {
  await page.goto('/'); await page.waitForFunction(()=>!!window.os?.exec);
  base='/guest/contained-'+crypto.randomUUID(); await call(page.request,{mkdir:{path:base,mode:0o700}});
}
async function start(page,units,{journal=false,shell=false,check=false}={}) {
  const path=base+'/units.json';
  expect((await put(page.request,'/api/file?path='+path+'&overwrite=true',{data:JSON.stringify({version:1,units})})).ok()).toBe(true);
  await page.evaluate(({path,journal,shell,check})=>{
    const run=window.contained={output:''};
    const argv=['supervise',...(journal?['--journal',journal]:[]),...(check?['--check']:[]),path];
    const command=shell?{path:'/usr/bin/sh',argv:['sh','-c','supervise "$1" & wait','sh',path]}:{path:'/usr/bin/supervise',argv};
    run.done=window.os.exec([command],{tty:true,stdin:'',onOutput:(_fd,s)=>{run.output=(run.output+s).slice(-262144);},onJob:j=>{run.job=j;}}).then(r=>{run.result=r;},e=>{run.error=String(e);});
  },{path,journal:journal?base+'/journal':null,shell,check});
}
const output=page=>page.evaluate(()=>window.contained.output.replace(/\r\n/g,'\n'));
async function seen(page,text) {
  await page.waitForFunction(text=>window.contained.output.includes(text)||window.contained.result||window.contained.error,text,{timeout:60000});
  expect(await output(page),await page.evaluate(()=>JSON.stringify(window.contained.result??window.contained.error))).toContain(text);
}
async function done(page,status=0) {
  await expect.poll(()=>page.evaluate(()=>window.contained.result?.status??window.contained.error),{timeout:60000}).toBe(status);
  return output(page);
}
async function cleanup(page) {
  await page.evaluate(async()=>{window.contained?.job?.signal(9);await window.contained?.done;window.independent?.job?.signal(9);await window.independent?.done;});
  await call(page.request,{chmod:{path:base,mode:0o700}});
  if(await errno(page.request,{stat:{path:base+'/journal'}})===null) await call(page.request,{chmod:{path:base+'/journal',mode:0o700}});
  await rmrf(page.request,base);
}
const unit=(name,argv,extra={})=>({name,argv,...extra});
async function daemon(page) {
  // A real double fork and setsid; the final child execs an ordinary sleep image.
  const module=binaryen.parseText(`(module
    (import "wasix_32v1" "proc_fork" (func $fork (param i32 i32) (result i32)))
    (import "wasix_32v1" "proc_exec" (func $exec (param i32 i32 i32 i32)))
    (import "os" "setsid" (func $setsid (result i32)))
    (import "wasix_32v1" "proc_id" (func $pid (param i32) (result i32)))
    (import "wasix_32v1" "proc_parent" (func $parent (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
    (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
    (memory (export "memory") 1)
    (data (i32.const 100) "DETACHED_READY\\0a") (data (i32.const 200) "/usr/bin/sleep") (data (i32.const 230) "sleep\\0a60")
    (func (export "_start")
      (if (call $fork (i32.const 1) (i32.const 32)) (then unreachable))
      (if (i32.load (i32.const 32)) (then (call $exit (i32.const 0))))
      (if (i32.lt_s (call $setsid) (i32.const 1)) (then unreachable))
      (drop (call $pid (i32.const 40)))
      (if (call $fork (i32.const 1) (i32.const 36)) (then unreachable))
      (if (i32.load (i32.const 36)) (then (call $exit (i32.const 0))))
      (drop (call $pid (i32.const 44)))
      (block $adopted (loop $observe
        (drop (call $parent (i32.load (i32.const 44)) (i32.const 48)))
        (br_if $adopted (i32.and (i32.gt_u (i32.load (i32.const 48)) (i32.const 1))
          (i32.ne (i32.load (i32.const 48)) (i32.load (i32.const 40)))))
        (br $observe)))
      (i32.store (i32.const 0) (i32.const 100)) (i32.store (i32.const 4) (i32.const 15))
      (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))
      (call $exec (i32.const 200) (i32.const 14) (i32.const 230) (i32.const 8))))`);
  try { expect((await put(page.request,'/api/file?path='+base+'/daemon',{data:Buffer.from(module.emitBinary())})).ok()).toBe(true); }
  finally { module.dispose(); }
  await call(page.request,{chmod:{path:base+'/daemon',mode:0o755}});
}
async function group(page) {
  const paths=await result(page.request,{cgroup_list:{path:'/user'}});
  const found=paths.find(path=>path.startsWith('/user/supervise-'));
  expect(found).toBeTruthy(); return {path:found,...await result(page.request,{cgroup_stat:{path:found}})};
}
for(const stop of ['leader exit','TERM','supervisor KILL']) test(`double-forked setsid descendants are contained after ${stop}`,async({page})=>{
  await setup(page);
  try {
    await daemon(page);
    await page.evaluate(()=>{const r=window.independent={};r.done=window.os.exec([{path:'/usr/bin/sleep',argv:['sleep','60']}],{onJob:j=>{r.job=j;}}).then(v=>{r.result=v;});});
    await start(page,[unit('daemon',['sh','-c',`${base}/daemon; echo LEADER_READY; while [ ! -f '${base}/release' ]; do sleep 0.1; done`])],{shell:stop==='supervisor KILL'});
    await seen(page,'DETACHED_READY'); await seen(page,'LEADER_READY'); const before=await group(page);
    const rows=await result(page.request,{proc_poll:{pids:before['subtree.procs']}});
    expect(rows.some(p=>p.ppid===before.lifetime.pid&&p.sid!==rows.find(p=>p.pid===p.pgid)?.sid)).toBe(true);
    if(stop==='leader exit') expect((await put(page.request,'/api/file?path='+base+'/release',{data:''})).ok()).toBe(true);
    else await result(page.request,{kill:{pid:String(before.lifetime.pid),signal:stop==='TERM'?15:9}});
    await done(page,stop==='TERM'?143:0);
    await expect.poll(()=>errno(page.request,{cgroup_stat:{path:before.path}}),{timeout:15000}).toBe('ENOENT');
    expect(await page.evaluate(()=>window.independent.result)).toBeUndefined();
    expect((await result(page.request,{proc_poll:{pids:before['subtree.procs']}})).filter(p=>p.state!=='zombie')).toEqual([]);
  } finally {await cleanup(page);}
});

test('journals preserve distinct stdout stderr and lifecycle records with exact binary bytes',async({page})=>{
  await setup(page);
  try {
    await start(page,[unit('alpha',['sh','-c',"printf '\\360\\237\\246\\200\\000\\377'; printf error >&2"]),unit('beta',['printf','BETA'])],{journal:true});
    await done(page);
    for(const [i,name] of ['alpha','beta'].entries()) {
      const r=await page.request.get('/api/file?path='+base+`/journal/${i}-${name}.jsonl`);expect(r.ok()).toBe(true);
      const records=(await r.text()).trim().split('\n').map(JSON.parse);expect(records[0]).toMatchObject({format:'os.service-journal',unit:name,dropped:0});
      const bytes=stream=>Buffer.concat(records.filter(r=>r.stream===stream).map(r=>Buffer.from(r.data,'base64')));
      expect(bytes('stdout')).toEqual(name==='alpha'?Buffer.from([240,159,166,128,0,255]):Buffer.from('BETA'));
      expect(bytes('stderr').toString()).toBe(name==='alpha'?'error':'');
      expect(records.filter(r=>r.stream==='event').map(r=>r.text).join('\n')).toContain('exited 0');
      expect(records.slice(1).map(r=>r.sequence)).toEqual(records.slice(1).map((_,i)=>i+1));
    }
    expect((await call(page.request,{stat:{path:base+'/journal'}})).mode&0o777).toBe(0o700);
  }finally{await cleanup(page);}
});

test('noisy journals rotate complete records and retain the final output within 64 KiB',async({page})=>{
  await setup(page);
  try{
    await start(page,[unit('noisy',['sh','-c',"head -c 300000 /dev/zero; printf FINAL_STDOUT; printf FINAL_STDERR >&2"])],{journal:true});
    await done(page);
    const r=await page.request.get('/api/file?path='+base+'/journal/0-noisy.jsonl');const bytes=await r.body();expect(bytes.length).toBeLessThanOrEqual(65536);
    const records=bytes.toString().trim().split('\n').map(JSON.parse);expect(records[0].dropped).toBeGreaterThan(0);
    for(const stream of ['stdout','stderr']) expect(Buffer.concat(records.filter(r=>r.stream===stream).map(r=>Buffer.from(r.data,'base64'))).toString()).toContain('FINAL_'+stream.toUpperCase());
    expect(records.slice(1).every((r,i,a)=>i===0||r.sequence===a[i-1].sequence+1)).toBe(true);
  }finally{await cleanup(page);}
});

test('an existing journal directory is rejected before a service starts',async({page})=>{
  await setup(page);
  try{
    await call(page.request,{mkdir:{path:base+'/journal',mode:0o700}});
    expect((await put(page.request,'/api/file?path='+base+'/journal/keep',{data:'KEEP'})).ok()).toBe(true);
    await start(page,[unit('blocked',['touch',base+'/unexpected'])],{journal:true});await done(page,1);
    expect(await errno(page.request,{stat:{path:base+'/unexpected'}})).toBe('ENOENT');
    expect(await (await page.request.get('/api/file?path='+base+'/journal/keep')).text()).toBe('KEEP');
  }finally{await cleanup(page);}
});

test('journal attempts remain isolated and old descendant groups are removed before retry',async({page})=>{
  await setup(page);
  try {
    await daemon(page);
    await start(page,[unit('retry',['sh','-c',`${base}/daemon; sleep 0.2; if [ ! -f '${base}/tried' ]; then touch '${base}/tried'; exit 1; fi; printf RETRY_DONE`],{restart:'on-failure',max_restarts:1,restart_delay_ms:100})],{journal:true});
    await done(page);
    const records=(await (await page.request.get('/api/file?path='+base+'/journal/0-retry.jsonl')).text()).trim().split('\n').map(JSON.parse);
    expect(records.filter(r=>r.text?.startsWith('started pid ')).map(r=>r.attempt)).toEqual([1,2]);
    expect(records.filter(r=>r.text?.startsWith('exited ')).map(r=>r.text)).toEqual(['exited 1','exited 0']);
    expect((await result(page.request,{cgroup_list:{path:'/user'}})).filter(path=>path.startsWith('/user/supervise-'))).toEqual([]);
  }finally{await cleanup(page);}
});

test('check-only validates without creating its requested journal directory',async({page})=>{
  await setup(page);
  try {
    await start(page,[unit('check',['touch',base+'/unexpected'])],{journal:true,check:true});await done(page);
    for(const path of [base+'/journal',base+'/unexpected']) expect(await errno(page.request,{stat:{path}})).toBe('ENOENT');
  }finally{await cleanup(page);}
});

test('a journal storage failure stops its services and preserves the last published snapshot',async({page})=>{
  await setup(page);
  try {
    await start(page,[unit('writer',['sh','-c','while :; do echo JOURNAL_TICK; sleep 0.1; done'])],{journal:true});
    const path=base+'/journal/0-writer.jsonl';
    await expect.poll(()=>errno(page.request,{stat:{path}}),{timeout:30000}).toBe(null);
    await call(page.request,{chmod:{path:base+'/journal',mode:0o500}});
    const before=await (await page.request.get('/api/file?path='+path)).text();
    await done(page,1);
    expect(await (await page.request.get('/api/file?path='+path)).text()).toBe(before);
    await expect.poll(async()=>(await result(page.request,{cgroup_list:{path:'/user'}})).filter(p=>p.startsWith('/user/supervise-')),{timeout:15000}).toEqual([]);
  }finally{await cleanup(page);}
});

test('account reset retires process-owned cgroups without leaving lifetime records',async({request})=>{
  await call(request,'getcreds');const owner=await launch(request),path='/user/reset-'+crypto.randomUUID();
  await invoke(request,owner,{cgroup_create:{path,lifetime:'process'}});
  await result(request,{proc_init:{boot:'reset-'+crypto.randomUUID()}});
  await result(request,{cgroup_stat:{path}},{},'ENOENT');
});

test('spawn rejects unowned descriptors and cgroups before execution and ignores forged descriptor tables',async({page})=>{
  await setup(page);
  const encode=value=>[...Buffer.from(JSON.stringify(value))].map(b=>'\\'+b.toString(16).padStart(2,'0')).join('');
  const common={argv:['/usr/bin/touch',base+'/unexpected'],cwd:'/',env:[],stdin:'inherit'};
  const requests=[{...common,dup2:[[65535,1]]},{...common,cgroup:'/system'},
    {...common,argv:['/usr/bin/printf','CHILD_STDIO'],fds:[],descriptions:[]}];
  const module=binaryen.parseText(`(module
    (import "os" "posix_spawn" (func $spawn (param i32 i32 i32) (result i32)))
    (import "os" "waitpid" (func $wait (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
    (memory (export "memory") 1)
    ${requests.map((r,i)=>`(data (i32.const ${1024+i*4096}) "${encode(r)}")`).join('\n')}
    (data (i32.const 100) "PARENT_STDIO")
    (func $assert (param i32) (if (i32.eqz (local.get 0)) (then unreachable)))
    (func (export "_start")
      (call $assert (i32.eq (call $spawn (i32.const 1024) (i32.const ${Buffer.byteLength(JSON.stringify(requests[0]))}) (i32.const 64)) (i32.const 8)))
      (call $assert (i32.eq (call $spawn (i32.const 5120) (i32.const ${Buffer.byteLength(JSON.stringify(requests[1]))}) (i32.const 64)) (i32.const 2)))
      (call $assert (i32.eqz (call $spawn (i32.const 9216) (i32.const ${Buffer.byteLength(JSON.stringify(requests[2]))}) (i32.const 64))))
      (call $assert (i32.eqz (call $wait (i32.load (i32.const 64)) (i32.const 68))))
      (call $assert (i32.eqz (i32.load (i32.const 68))))
      (i32.store (i32.const 0) (i32.const 100)) (i32.store (i32.const 4) (i32.const 12))
      (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))))`);
  try {
    const path=base+'/spawn-probe';
    expect((await put(page.request,'/api/file?path='+path,{data:Buffer.from(module.emitBinary())})).ok()).toBe(true);
    await call(page.request,{chmod:{path,mode:0o755}});
    await page.evaluate(path=>{const run=window.contained={output:''};run.done=window.os.exec([{path,argv:[path]}],{tty:true,stdin:'',onOutput:(_fd,s)=>{run.output+=s;},onJob:j=>{run.job=j;}}).then(r=>{run.result=r;},e=>{run.error=String(e);});},path);
    const output=await done(page);expect(output).toBe('CHILD_STDIOPARENT_STDIO');
    expect(await errno(page.request,{stat:{path:base+'/unexpected'}})).toBe('ENOENT');
  } finally {module.dispose();await cleanup(page);}
});

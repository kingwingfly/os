import { test, expect, request as contexts } from './test.js';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { api, call, mkdirp, put, rmrf, sys } from './sys.js';
import { attachInstance, FULL_SCOPE, NO_CLOUD_SCOPE } from './service-auth.js';
const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const password = process.env.OS_PASSWORD || readFileSync('.local-password', 'utf8').trim();
const options = (access='read-write', extra={}) => ({read:access==='read'||access==='read-write',write:access==='write'||access==='read-write',append:false,append_implies_write:false,truncate:false,create:false,create_new:false,exec:access==='exec',path:access==='path',...extra});
const attrs = extra => ({mode:null,uid:null,gid:null,size:null,atime:'omit',mtime:'omit',...extra});
const instances = new WeakMap();
const tokenInstance = new Map();
async function getInstance(request) {
  let inst = instances.get(request);
  if (!inst) {
    inst = await attachInstance(request, { origin });
    instances.set(request, inst);
  }
  return inst;
}
async function admit(request, opts = {}) {
  const inst = await getInstance(request);
  const cred = await inst.mint({
    scope: opts.scope ?? FULL_SCOPE,
    cloud_access: opts.cloud_access ?? true,
    cgroup: opts.cgroup ?? '/user',
    sudo: !!opts.sudo,
  });
  tokenInstance.set(cred.token, inst.instanceId);
  return { ...cred, inst };
}
async function revokeCred(p) {
  if (p?.inst && p?.token) await p.inst.revoke([p.token]);
}
async function rpc(request,credential,session,call,errno,version=2,instanceId) {
  const instId = instanceId !== undefined ? instanceId : tokenInstance.get(credential);
  const response=await request.post(origin+'/api/fs',{headers:{Origin:origin,...(instId?{'X-OS-Instance':instId}:{})},data:{version,credential,session,call}});const body=await response.json();
  if(errno){expect(body?.errno,JSON.stringify(body)).toBe(errno);return body;}
  expect(response.ok(),JSON.stringify(body)).toBe(true);return body;
}
async function connection(request,{token,pid,inst,instanceId}) {
  const instId = instanceId ?? inst?.instanceId ?? tokenInstance.get(token);
  const c={...await rpc(request,token,null,'connect',undefined,2,instId),request,token,pid,inst,instanceId:instId,umask:0o022};
  c.call=(op,args,errno)=>{
    if(['create','mkdir','mknod'].includes(op))args={umask:c.umask,...args};
    return rpc(request,c.token,c.session,args===undefined?op:{[op]:args},errno,2,tokenInstance.get(c.token)??c.instanceId);
  };
  c.data=async(open,operation,bytes,errno)=>{
    const id = tokenInstance.get(c.token) ?? c.instanceId;
    const response=await request.post(origin+'/api/fs/data',{headers:{Origin:origin,...(id?{'X-OS-Instance':id}:{}),'X-OS-Filesystem':JSON.stringify({version:2,credential:c.token,pid:c.pid,session:c.session,open,operation})},data:bytes??Buffer.alloc(0)});
    if(errno){expect((await response.json()).errno).toBe(errno);return;}
    expect(response.ok(),response.ok()?'':await response.text()).toBe(true);return 'read' in operation?response.body():response.json();
  };
  c.open=(handle,access='read-write',extra={})=>c.call('open',{ticket:randomUUID(),handle,options:options(access,extra)});
  c.create=(dir,name,mode=0o600)=>c.call('create',{ticket:randomUUID(),dir,name,mode,options:options('read-write',{create_new:true})});
  c.read=(open,offset=0,length=4096)=>c.data(open,{read:{offset,length}});
  c.write=(open,bytes,at='end')=>c.data(open,{write:{at,length:Buffer.byteLength(bytes)}},Buffer.from(bytes));
  return c;
}
async function setup(request) {
  await call(request,'getcreds');expect((await api(request,'login',{headers:{'CF-Connecting-IP':'cloudfs-'+randomUUID()},data:{username:'root',password}})).ok()).toBe(true);
  const p=await admit(request);const c=await connection(request,p);
  const dir=await c.call('mkdir',{dir:c.root,name:'vfs-'+randomUUID(),mode:0o777});return {c,dir:dir.handle,p};
}
test('v2 checks credentials, version, instance ownership, proofs and component syntax',async({request})=>{
  const {c,dir}=await setup(request);const other=await connection(request,c);
  await c.call('metadata',{handle:other.root},'EACCES');await other.call('metadata',{handle:dir},'EACCES');
  const forged=structuredClone(dir);forged.node.ino++;await c.call('metadata',{handle:forged},'EACCES');
  await rpc(request,'forged',c.session,{metadata:{handle:dir}},'EACCES');await rpc(request,c.token,{...c.session,secret:'forged'},{metadata:{handle:dir}},'EACCES');
  await rpc(request,c.token,c.session,'statfs','EPROTONOSUPPORT',1);
  await rpc(request,c.token,c.session,{old_path_call:{path:'/'}},'EPROTONOSUPPORT',1);
  for(const name of ['','..','.','a/b','x\0y'])await c.call('lookup',{dir,name},'EINVAL');
  await c.call('walk',{dir,names:['missing','..']},'EINVAL');
  const p=await admit(request);expect((await rpc(request,p.token,c.session,{metadata:{handle:dir}})).file_type).toBe('dir');
  await c.call('disconnect');await other.call('disconnect');
});
test('open access, rename/unlink, O_PATH, sparse bytes and old readers share one inode tree',async({request})=>{
  const {c,dir}=await setup(request);const [entry,open]=await c.create(dir,'file',0o400);
  expect(await c.write(open,'abcdef')).toEqual({offset:0,len:6});
  await c.call('rename',{from_dir:dir,from:'file',to_dir:dir,to:'renamed',flags:''});
  expect((await c.call('lookup',{dir,name:'renamed'})).handle.node).toEqual(entry.handle.node);
  const ro=await c.open(entry.handle,'read');await c.data(ro,{write:{at:'end',length:1}},Buffer.from('x'),'EBADF');
  await c.call('set_len',{open,size:3});await c.call('set_len',{open,size:7});expect(await c.read(open)).toEqual(Buffer.from([97,98,99,0,0,0,0]));
  expect(await c.write(open,'Z',{offset:5})).toEqual({offset:5,len:1});
  const name=(await c.call('parent',{dir}))[1];const old=await request.get(origin+'/api/file?path='+encodeURIComponent('/'+name+'/renamed'));
  expect(old.ok(),old.ok()?'':await old.text()).toBe(true);expect(await old.body()).toEqual(await c.read(open));
  await c.call('unlink',{dir,name:'renamed'});expect((await c.call('metadata',{handle:entry.handle})).nlink).toBe(0);expect((await c.call('open_metadata',{open})).nlink).toBe(0);expect((await c.read(open)).length).toBe(7);
  await c.call('release',{open});await c.call('release',{open:ro});await c.call('metadata',{handle:entry.handle},'ESTALE');
  const sub=await c.call('mkdir',{dir,name:'cwd',mode:0});const path=await c.open(sub.handle,'path');await c.call('rmdir',{dir,name:'cwd'});
  expect((await c.call('metadata',{handle:sub.handle})).nlink).toBe(0);await c.call('parent',{dir:sub.handle},'ENOENT');await c.call('read_dir',{dir:sub.handle},'ENOENT');
  expect(await c.call('open_metadata',{open:path})).toMatchObject({file_type:'dir',nlink:0});
  await c.data(path,{read:{offset:0,length:1}},undefined,'EBADF');await c.call('release',{open:path});await c.call('disconnect');
});
test('atomic append, lock families, durable waits, cancellation and resume',async({request})=>{
  const {c,dir}=await setup(request);const [entry,a]=await c.create(dir,'file');const b=await c.open(entry.handle);const d=await c.open(entry.handle);
  const writes=await Promise.all(Array.from({length:12},(_,i)=>c.write(i%2?a:b,String.fromCharCode(65+i))));expect(new Set(writes.map(w=>w.offset)).size).toBe(12);expect((await c.read(a)).length).toBe(12);
  const range={start:0,end:null};const lock=(open,kind='exclusive',family='posix')=>({open,kind,family,range});
  await c.call('try_lock',lock(a));await c.call('try_lock',lock(b),'EAGAIN');await c.call('try_lock',lock(b,'exclusive','flock'));
  const ticket=randomUUID();expect(await c.call('lock',{...lock(b),ticket})).toBe(false);expect((await c.call('test_lock',{open:d,kind:'exclusive',range})).owner).toBe(a.id);
  await c.call('renew');await c.call('unlock',{open:a,family:'posix',range});expect(await c.call('lock',{...lock(b),ticket})).toBe(true);await c.call('ack_lock',{open:b,ticket});
  await c.call('cancel_lock',{open:b,ticket});expect(await c.call('test_lock',{open:d,kind:'exclusive',range})).toBeNull();
  const cancelled=randomUUID();await c.call('cancel_lock',{open:b,ticket:cancelled});await c.call('lock',{...lock(b),ticket:cancelled},'ECANCELED');await c.call('disconnect');
});
test('cancelled opens are idempotent, stale handles stay stale, and reads reject invalid offsets',async({request})=>{
  const {c,dir}=await setup(request);const [entry,open]=await c.create(dir,'file');
  const ticket=randomUUID();const ask={ticket,handle:entry.handle,options:options()};const retained=await c.call('open',ask);expect(await c.call('open',ask)).toEqual(retained);
  await c.call('cancel_open',{ticket});await c.call('open',ask,'ECANCELED');const early=randomUUID();await c.call('cancel_open',{ticket:early});await c.call('open',{...ask,ticket:early},'ECANCELED');
  await c.data(open,{read:{offset:2**63,length:0}},undefined,'EINVAL');
  await c.call('unlink',{dir,name:'file'});await c.call('release',{open});await c.call('metadata',{handle:entry.handle},'ESTALE');
  const [replacement]=await c.create(dir,'file');expect(replacement.handle.node.ino).not.toBe(entry.handle.node.ino);await c.call('metadata',{handle:entry.handle},'ESTALE');await c.call('disconnect');
});
test('metadata, hardlinks, xattrs, relatime and grants use current credentials at the correct boundary',async({request})=>{
  const {c,dir}=await setup(request);const [entry,open]=await c.create(dir,'file');await c.write(open,'data');
  const linked=await c.call('link',{target:entry.handle,dir,name:'linked'});expect(linked.metadata.nlink).toBe(2);
  await c.call('rename',{from_dir:dir,from:'file',to_dir:dir,to:'linked',flags:'NOREPLACE'},'EEXIST');
  await c.call('setxattr',{handle:entry.handle,name:'user.test',value:[0,1,255],flags:'CREATE'});
  expect(await c.call('getxattr',{handle:linked.handle,name:'user.test'})).toEqual([0,1,255]);
  await c.call('setxattr',{handle:entry.handle,name:'user.test',value:[2],flags:'CREATE'},'EEXIST');
  await c.call('setattr',{handle:entry.handle,attr:attrs({mode:0,atime:{sec:1,nsec:0}})});
  expect((await c.call('metadata',{handle:entry.handle})).atime.sec).toBe(1);await c.read(open);expect((await c.call('metadata',{handle:entry.handle})).atime.sec).toBeGreaterThan(1);
  await c.call('open',{ticket:randomUUID(),handle:entry.handle,options:options('exec')},'EACCES');
  await api(request,'logout');const guest=await admit(request);
  await rpc(request,guest.token,c.session,{open:{ticket:randomUUID(),handle:entry.handle,options:options('read')}},'EACCES');
  const path=await rpc(request,guest.token,c.session,{open:{ticket:randomUUID(),handle:entry.handle,options:options('path')}});
  await c.call('release',{open:path}); // another valid credential in the same instance
  expect((await c.read(open)).toString()).toBe('data');await c.write(open,'!');
  const sym=await c.call('symlink',{dir,name:'sym',target:'linked'});await c.call('setattr',{handle:sym.handle,attr:attrs({atime:{sec:1,nsec:0}})});
  expect(await c.call('read_link',{handle:sym.handle})).toBe('linked');expect((await c.call('metadata',{handle:sym.handle})).atime.sec).toBeGreaterThan(1);
  expect((await c.call('walk',{dir,names:['sym','child']})).stop).toEqual({Symlink:0});
  await c.call('disconnect');
});
test('revoking an opener releases its inode and locks even when another credential presents the reference',async({request})=>{
  const {c,dir,p}=await setup(request);const observer=await admit(request);
  const [entry,open]=await c.create(dir,'file');await c.write(open,'kept');await c.call('unlink',{dir,name:'file'});
  await revokeCred(p);
  await rpc(request,observer.token,c.session,{sync:{open,data_only:false}},'EACCES');
  await rpc(request,observer.token,c.session,{metadata:{handle:entry.handle}},'ESTALE');
  await rpc(request,observer.token,c.session,'disconnect');
});
const replace=async(request,p,local)=>{
  const inst=p.inst??await getInstance(request);
  const cloud=local?.cloud!==false;
  const cred=await inst.derive(p.token,{scope:cloud?FULL_SCOPE:NO_CLOUD_SCOPE,cloud_access:cloud,revoke_parent:true});
  tokenInstance.set(cred.token,inst.instanceId);
  return {...cred,inst,pid:p.pid};
};
test('exec retains unlinked cloud opens and locks across repeated token rotation',async({request})=>{
  const {c,dir}=await setup(request);const observer=await admit(request);
  const [entry,open]=await c.create(dir,'exec');await c.write(open,'kept');
  const peer=await rpc(request,observer.token,c.session,{open:{ticket:randomUUID(),handle:entry.handle,options:options()}});
  const range={start:0,end:null};await c.call('try_lock',{open,family:'flock',kind:'exclusive',range});
  await c.call('unlink',{dir,name:'exec'});
  for(let i=0;i<2;i++){
    const old=c.token;const next=await replace(request,c);expect(next.pid).toBe(c.pid);c.token=next.token;
    await rpc(request,old,c.session,{sync:{open,data_only:false}},'EACCES');
    await rpc(request,old,c.session,{open_metadata:{open}},'EACCES');
    await c.call('renew');await c.call('sync',{open,data_only:false});
    expect(await c.call('open_metadata',{open})).toMatchObject({nlink:0,size:4+i});
    expect((await c.read(open)).toString()).toBe('kept'+'!'.repeat(i));await c.write(open,'!');
    await rpc(request,observer.token,c.session,{try_lock:{open:peer,family:'flock',kind:'exclusive',range}},'EAGAIN');
  }
  await revokeCred(c);
  await rpc(request,observer.token,c.session,{sync:{open,data_only:false}},'EACCES');
  await rpc(request,observer.token,c.session,{open_metadata:{open}},'EACCES');
  await rpc(request,observer.token,c.session,{try_lock:{open:peer,family:'flock',kind:'exclusive',range}});
  await rpc(request,observer.token,c.session,{cancel_lock:{open,ticket:randomUUID()}});
  await rpc(request,observer.token,c.session,{release:{open}});
  await rpc(request,observer.token,c.session,{release:{open:peer}});
  await rpc(request,observer.token,c.session,{metadata:{handle:entry.handle}},'ESTALE');
  await rpc(request,observer.token,c.session,'disconnect');
});
test('fork and exec retain inherited opens until the last credential is revoked',async({request})=>{
  for(const endParentFirst of [true,false]){
    const {c,dir,p}=await setup(request);const observer=await admit(request);
    const [entry,open]=await c.create(dir,'fork-exec');await c.write(open,'shared');await c.call('unlink',{dir,name:'fork-exec'});
    const forked=await p.inst.derive(p.token,{scope:FULL_SCOPE,cloud_access:true,revoke_parent:false});
    tokenInstance.set(forked.token,p.inst.instanceId);
    const child=await replace(request,{...forked,inst:p.inst});
    const [late,later]=await c.create(dir,'after-fork-exec');await c.call('unlink',{dir,name:'after-fork-exec'});
    const first=endParentFirst?p:child,last=endParentFirst?child:p;
    await revokeCred(first);
    c.token=last.token;c.pid=last.pid;
    await c.call('sync',{open,data_only:false});expect((await c.read(open)).toString()).toBe('shared');await c.write(open,'!');
    if(endParentFirst){
      // A successor inherits only the descriptions open at its exec, never later opens.
      await c.call('sync',{open:later,data_only:false},'EACCES');await c.call('metadata',{handle:late.handle},'ESTALE');
    }
    await revokeCred(last);
    await rpc(request,observer.token,c.session,{sync:{open,data_only:false}},'EACCES');
    await rpc(request,observer.token,c.session,{metadata:{handle:entry.handle}},'ESTALE');
    await rpc(request,observer.token,c.session,'disconnect');
  }
});
test('exec cannot retain cloud grants when the replacement drops cloud access',async({request})=>{
  const {c,dir}=await setup(request);const observer=await admit(request);
  const [entry,open]=await c.create(dir,'attenuated');await c.write(open,'private');await c.call('unlink',{dir,name:'attenuated'});
  const denied=await replace(request,c,{digest:'a'.repeat(64),size:8,cloud:false});
  await rpc(request,denied.token,c.session,{sync:{open,data_only:false}},'EACCES');
  await rpc(request,observer.token,c.session,{sync:{open,data_only:false}},'EACCES');
  await rpc(request,observer.token,c.session,{metadata:{handle:entry.handle}},'ESTALE');
  await rpc(request,observer.token,c.session,'disconnect');
});
test('open control calls reject revoked and cloud-denied callers while the opener remains valid',async({request})=>{
  const {c,dir,p}=await setup(request);const [entry,open]=await c.create(dir,'caller');await c.write(open,'keep data');
  const peer=await c.open(entry.handle);const range={start:0,end:null};const lock={open,family:'posix',kind:'exclusive',range};
  await c.call('try_lock',lock);
  const revoked=await admit(request);await revokeCred(revoked);
  const denied=await admit(request,{scope:NO_CLOUD_SCOPE,cloud_access:false});
  const ungranted=await admit(request);
  const actor=await p.inst.derive(p.token,{scope:FULL_SCOPE,cloud_access:true,revoke_parent:false});
  tokenInstance.set(actor.token,p.inst.instanceId);
  try {
    for(const caller of [revoked,denied,ungranted]) {
      for(const operation of [
        {open_metadata:{open}},
        {set_len:{open,size:0}},
        {sync:{open,data_only:false}},
        {sync:{open,data_only:true}},
        {try_lock:lock},
        {lock:{...lock,ticket:randomUUID()}},
        {unlock:{open,family:'posix',range}},
        {test_lock:{open,kind:'exclusive',range}},
      ])await rpc(request,caller.token,c.session,operation,'EACCES');
    }
    expect((await c.read(open)).toString()).toBe('keep data');
    expect((await c.call('test_lock',{open:peer,kind:'exclusive',range})).owner).toBe(open.id);
    await rpc(request,actor.token,c.session,{set_len:{open,size:4}});expect((await c.read(open)).toString()).toBe('keep');
    await rpc(request,actor.token,c.session,{unlock:{open,family:'posix',range}});
    expect(await c.call('test_lock',{open:peer,kind:'exclusive',range})).toBeNull();
    const ticket=randomUUID();expect(await rpc(request,actor.token,c.session,{lock:{...lock,ticket}})).toBe(true);
    await rpc(request,actor.token,c.session,{ack_lock:{open,ticket}});
    expect((await c.call('test_lock',{open:peer,kind:'exclusive',range})).owner).toBe(open.id);
  } finally {
    await c.call('disconnect');
    for(const process of [denied,ungranted,{...actor,inst:p.inst}])await revokeCred(process);
  }
});
test('lease expiry releases references while an independently renewed session remains usable',async({request})=>{
  test.setTimeout(180000);
  const {c,dir,p}=await setup(request);const other=await connection(request,c);
  const [entry,open]=await c.create(dir,'expire');await c.write(open,'lease');
  const dirName=(await c.call('parent',{dir}))[1];const otherDir=(await other.call('lookup',{dir:other.root,name:dirName})).handle;
  const observed=(await other.call('lookup',{dir:otherDir,name:'expire'})).handle;await c.call('unlink',{dir,name:'expire'});
  for(let i=0;i<5;i++){await new Promise(r=>setTimeout(r,25000));await p.inst.renew([p.token]);await other.call('renew');}
  await other.call('metadata',{handle:observed},'ESTALE');await c.call('renew',undefined,'ENOTCONN');await other.call('disconnect');
});
test('signed 64-bit offsets retain precision across SQLite and the Worker gateway',async({request})=>{
  const {c,dir}=await setup(request);const [entry,open]=await c.create(dir,'large');
  const data={version:2,credential:c.token,pid:c.pid,session:c.session,open,operation:{write:{at:{offset:'LARGE_OFFSET'},length:1}}};
  const response=await request.post(origin+'/api/fs/data',{headers:{Origin:origin,'X-OS-Instance':c.instanceId,'X-OS-Filesystem':JSON.stringify(data).replace('"LARGE_OFFSET"','9223372036854775806')},data:Buffer.from('x')});
  expect(response.ok(),response.ok()?'':await response.text()).toBe(true);
  expect(await response.text()).toContain('9223372036854775806');
  const meta=await request.post(origin+'/api/fs',{headers:{Origin:origin,'X-OS-Instance':c.instanceId},data:{version:2,credential:c.token,session:c.session,call:{metadata:{handle:entry.handle}}}});
  expect(meta.ok()).toBe(true);expect(await meta.text()).toContain('"size":9223372036854775807');
  data.operation={read:{offset:'LARGE_OFFSET',length:1}};
  const read=await request.post(origin+'/api/fs/data',{headers:{Origin:origin,'X-OS-Instance':c.instanceId,'X-OS-Filesystem':JSON.stringify(data).replace('"LARGE_OFFSET"','9223372036854775806')},data:Buffer.alloc(0)});
  expect(read.ok(),read.ok()?'':await read.text()).toBe(true);expect((await read.body()).toString()).toBe('x');
  await c.call('unlink',{dir,name:'large'});await c.call('disconnect');
});
test('moving a directory preserves descendant inode metadata and revocation denies writes',async({request})=>{
  const {c,dir,p}=await setup(request);const sub=await c.call('mkdir',{dir,name:'from',mode:0o700});
  const [entry,open]=await c.create(sub.handle,'file');await c.write(open,'before');
  const before=await c.call('metadata',{handle:entry.handle});
  await c.call('rename',{from_dir:dir,from:'from',to_dir:dir,to:'to',flags:''});
  expect(await c.call('metadata',{handle:entry.handle})).toEqual(before);
  // Existing path uploads are read through the v2 adapter, and become shared extents on edit.
  const rootName=(await c.call('parent',{dir}))[1];
  expect((await put(request,origin+'/api/file?path='+encodeURIComponent('/'+rootName+'/old'),{data:'legacy'})).ok()).toBe(true);
  const old=await c.call('lookup',{dir,name:'old'});const oldOpen=await c.open(old.handle);
  await c.write(oldOpen,'NEW',{offset:0});expect((await c.read(oldOpen)).toString()).toBe('NEWacy');
  await revokeCred(p);
  await c.data(open,{write:{at:'end',length:1}},Buffer.from('x'),'EACCES');
});
test('separate service instances share inode locks but cannot exchange handle proofs',async({request})=>{
  const {c,dir}=await setup(request);const [entry,open]=await c.create(dir,'shared');await c.write(open,'shared');
  const other=await connection(request,c);expect(other.root.fs).toBe(c.root.fs);
  const name=(await c.call('parent',{dir}))[1];const od=(await other.call('lookup',{dir:other.root,name})).handle;
  const theirs=(await other.call('lookup',{dir:od,name:'shared'})).handle;expect(theirs.node).toEqual(entry.handle.node);expect(theirs.proof).not.toBe(entry.handle.proof);
  const peer=await other.open(theirs);const range={start:0,end:null};
  await c.call('try_lock',{open,family:'flock',kind:'exclusive',range});await other.call('try_lock',{open:peer,family:'flock',kind:'exclusive',range},'EAGAIN');
  await c.call('unlink',{dir,name:'shared'});await c.call('disconnect');
  await other.call('try_lock',{open:peer,family:'flock',kind:'exclusive',range});expect((await other.read(peer)).toString()).toBe('shared');
  await other.call('release',{open:peer});await other.call('metadata',{handle:theirs},'ESTALE');await other.call('disconnect');
});
test('account lock revokes open grants and unlocking never revives them',async({request})=>{
  const {c:admin}=await setup(request);const name='vfsc'+randomUUID().replaceAll('-','').slice(0,12);const password='account-'+randomUUID();
  await call(request,{useradd:{name,create_home:true}});
  const account=await contexts.newContext({extraHTTPHeaders:{'CF-Connecting-IP':'cloudfs-'+randomUUID()}});
  try{
    expect((await api(request,'passwd',{data:{username:name,password}})).ok()).toBe(true);
    await call(account,'getcreds');expect((await api(account,'login',{data:{username:name,password}})).ok()).toBe(true);
    const actor=await admit(account);const c=await connection(account,actor);const creds=await call(account,'getcreds');
    const walked=await c.call('walk',{dir:c.root,names:creds.home.split('/').filter(Boolean)});const home=walked.entries.at(-1).handle;
    const [entry,open]=await c.create(home,'retained');await c.write(open,'private');await c.call('unlink',{dir:home,name:'retained'});
    await call(request,{usermod:{name,lock:true}});await c.data(open,{read:{offset:0,length:7}},undefined,'EACCES');
    const guest=await admit(account);await rpc(account,guest.token,c.session,{metadata:{handle:entry.handle}},'ESTALE');
    await call(request,{usermod:{name,unlock:true}});await c.call('renew',undefined,'EACCES');
    await rpc(account,guest.token,c.session,'disconnect');
  }finally{await account.dispose();await call(request,{userdel:{name,remove:true}});await admin.call('disconnect');}
});
test('inline pread reads extents, object offsets and sparse holes through paths and retained descriptors',async({request})=>{
  const {c,dir}=await setup(request);const [entry,open]=await c.create(dir,'inline');
  const name=(await c.call('parent',{dir}))[1];const path='/'+name+'/inline';
  const pread=async(target,offset,count)=>{
    const result=await call(request,{pread:{...target,offset,count}});
    return {bytes:Buffer.from(result.data,'base64'),size:result.size};
  };
  await c.write(open,'hello');expect(await pread({path},0,20)).toEqual({bytes:Buffer.from('hello'),size:5});
  await c.call('set_len',{open,size:12});await c.write(open,'XYZ',{offset:8});await c.write(open,'AB',{offset:1});
  await c.call('set_len',{open,size:10});await c.call('set_len',{open,size:14});
  const bytes=Buffer.from([104,65,66,108,111,0,0,0,88,89,0,0,0,0]);
  expect(await pread({path},0,30)).toEqual({bytes,size:bytes.length});
  for(const offset of [1,3,5,7,9,10,13,14,99]){
    expect(await pread({path},offset,5)).toEqual({bytes:bytes.subarray(offset,offset+5),size:bytes.length});
  }
  expect(await pread({path},3,0)).toEqual({bytes:Buffer.alloc(0),size:14});
  const {fd}=await call(request,{open:{path,flags:0,mode:0}});
  try{
    await c.call('rename',{from_dir:dir,from:'inline',to_dir:dir,to:'moved',flags:''});
    await c.call('unlink',{dir,name:'moved'});await c.call('release',{open});
    expect(await pread({fd},0,30)).toEqual({bytes,size:bytes.length});
  }finally{await call(request,{close:{fd}});}
  const [,hole]=await c.create(dir,'hole');await c.call('set_len',{open:hole,size:7});
  expect(await pread({path:'/'+name+'/hole'},0,10)).toEqual({bytes:Buffer.alloc(7),size:7});
  await c.call('unlink',{dir,name:'hole'});await c.call('release',{open:hole});await c.call('disconnect');
});
test('I/O-denied reads release their prepared manifests before session renewal',async({request})=>{
  const {c,dir,p}=await setup(request);const group='/user/cloudfs-'+randomUUID();
  const baseline=(await c.call('statfs')).blocks;const [entry,open]=await c.create(dir,'denied');
  try{
    await c.write(open,Buffer.alloc(4096,42));expect((await c.call('statfs')).blocks).toBe(baseline+1);
    await p.inst.setIoQuota({token:p.token,cgroup:group,rbps:0,wbps:null});
    for(let i=0;i<3;i++)await c.data(open,{read:{offset:0,length:4096}},undefined,'EAGAIN');
    await c.call('unlink',{dir,name:'denied'});await c.call('release',{open});
    await c.call('metadata',{handle:entry.handle},'ESTALE');
    expect((await c.call('statfs')).blocks).toBe(baseline);
    await c.call('renew');expect((await c.call('statfs')).blocks).toBe(baseline);
  }finally{
    await p.inst.setIoQuota({token:p.token,cgroup:'/user',rbps:null,wbps:null}).catch(()=>{});
    await c.call('disconnect');
  }
});
test('flock conversion wakes queued owners and POSIX updates preserve ownership and queue order',async({request})=>{
  const {c,dir}=await setup(request);const [entry,a]=await c.create(dir,'locks');const b=await c.open(entry.handle);const d=await c.open(entry.handle);
  const range={start:0,end:null};const lock=(open,family,kind='exclusive')=>({open,family,kind,range});
  await c.call('try_lock',lock(a,'flock'));const flockTicket=randomUUID();
  expect(await c.call('lock',{...lock(b,'flock'),ticket:flockTicket})).toBe(false);
  await c.call('try_lock',lock(a,'flock'));await c.call('try_lock',lock(a,'flock','shared'),'EAGAIN');
  expect(await c.call('lock',{...lock(b,'flock'),ticket:flockTicket})).toBe(true);
  await c.call('ack_lock',{open:b,ticket:flockTicket});await c.call('try_lock',lock(d,'flock'),'EAGAIN');
  await c.call('try_lock',lock(a,'posix'));const writer=randomUUID(),reader=randomUUID(),downgrade=randomUUID();
  expect(await c.call('lock',{...lock(b,'posix'),ticket:writer})).toBe(false);
  await c.call('try_lock',lock(a,'posix'));
  expect(await c.call('lock',{...lock(a,'posix','shared'),ticket:downgrade})).toBe(true);
  await c.call('ack_lock',{open:a,ticket:downgrade});
  expect(await c.call('lock',{...lock(d,'posix','shared'),ticket:reader})).toBe(false);
  await c.call('unlock',{open:a,family:'posix',range});
  expect(await c.call('lock',{...lock(b,'posix'),ticket:writer})).toBe(true);
  expect(await c.call('lock',{...lock(d,'posix','shared'),ticket:reader})).toBe(false);
  await c.call('release',{open:b});expect(await c.call('lock',{...lock(d,'posix','shared'),ticket:reader})).toBe(true);
  await c.call('disconnect');
});
test('POSIX ranges coalesce across grants without losing cancellation ownership',async({request})=>{
  const {c,dir}=await setup(request);const [entry,a]=await c.create(dir,'ranges');const b=await c.open(entry.handle);const peer=await c.open(entry.handle);
  const span=(start,end)=>({start,end});
  const lock=(open,start,end,kind='exclusive')=>({open,family:'posix',kind,range:span(start,end)});
  const conflict=(start,end)=>c.call('test_lock',{open:peer,kind:'exclusive',range:span(start,end)});
  for(const start of [20,0,10])await c.call('try_lock',lock(a,start,start+10));
  expect((await conflict(1,2)).range).toEqual(span(0,30));
  await c.call('unlock',{open:a,family:'posix',range:span(10,20)});
  await c.call('try_lock',lock(a,0,5,'shared'));
  await c.call('try_lock',lock(a,10,20));
  expect((await conflict(10,11)).range).toEqual(span(5,30));
  await c.call('try_lock',lock(a,30,null));expect((await conflict(25,26)).range).toEqual(span(5,null));
  await c.call('unlock',{open:a,family:'posix',range:span(0,null)});
  await c.call('try_lock',lock(a,0,10));
  const right=randomUUID(),middle=randomUUID();
  expect(await c.call('lock',{...lock(a,20,30),ticket:right})).toBe(true);await c.call('ack_lock',{open:a,ticket:right});
  await c.call('try_lock',lock(b,10,20));
  expect(await c.call('lock',{...lock(a,10,20),ticket:middle})).toBe(false);
  await c.call('release',{open:b});
  expect(await c.call('lock',{...lock(a,10,20),ticket:middle})).toBe(true);await c.call('ack_lock',{open:a,ticket:middle});
  expect((await conflict(25,26)).range).toEqual(span(0,30));
  await c.call('try_lock',lock(a,15,25));
  await c.call('cancel_lock',{open:a,ticket:middle});
  expect(await conflict(10,15)).toBeNull();expect((await conflict(15,16)).range).toEqual(span(15,30));
  await c.call('cancel_lock',{open:a,ticket:right});
  expect(await conflict(25,30)).toBeNull();expect((await conflict(15,16)).range).toEqual(span(15,25));
  expect((await conflict(1,2)).range).toEqual(span(0,10));
  await c.call('disconnect');
});
test('empty setattr preserves metadata for both owners and non-owners',async({request})=>{
  const {c,dir}=await setup(request);const [entry,open]=await c.create(dir,'no-op');await c.write(open,'unchanged');
  const before=await c.call('metadata',{handle:entry.handle});
  expect(await c.call('setattr',{handle:entry.handle,attr:attrs()})).toEqual(before);
  await api(request,'logout');const guest=await admit(request);
  expect(await rpc(request,guest.token,c.session,{setattr:{handle:entry.handle,attr:attrs()}})).toEqual(before);
  await rpc(request,guest.token,c.session,{setattr:{handle:entry.handle,attr:attrs({mode:0o777})}},'EPERM');
  expect(await c.call('metadata',{handle:entry.handle})).toEqual(before);
  await c.call('unlink',{dir,name:'no-op'});await c.call('release',{open});
  await c.call('setattr',{handle:entry.handle,attr:attrs()},'ESTALE');await c.call('disconnect');
});
test('forked callers use their own I/O limits and survive the credential issuer process',async({request})=>{
  const {c,dir,p}=await setup(request);const group='/user/cloudfs-fork-'+randomUUID();
  const [,open]=await c.create(dir,'fork');await c.write(open,'parent');
  const child=await p.inst.derive(p.token,{scope:FULL_SCOPE,cloud_access:true,cgroup:group,revoke_parent:false});
  tokenInstance.set(child.token,p.inst.instanceId);
  try{
    await p.inst.setIoQuota({token:child.token,cgroup:group,rbps:0,wbps:0});
    c.token=child.token;c.pid=child.pid;
    await c.data(open,{write:{at:'end',length:1}},Buffer.from('!'),'EAGAIN');
    await c.data(open,{read:{offset:0,length:6}},undefined,'EAGAIN');
    // Revoking the issuer credential leaves the derived child credential usable once its quota lifts.
    await revokeCred(p);
    await p.inst.setIoQuota({token:child.token,cgroup:group,rbps:null,wbps:null});
    expect((await c.read(open)).toString()).toBe('parent');await c.write(open,' child');
    expect((await c.read(open)).toString()).toBe('parent child');
    // Revoked parent token and mismatched/missing X-OS-Instance fail closed on /api/fs/data.
    const wrongInst=await request.post(origin+'/api/fs/data',{headers:{Origin:origin,'X-OS-Instance':'inst-wrong','X-OS-Filesystem':JSON.stringify({version:2,credential:child.token,pid:child.pid,session:c.session,open,operation:{read:{offset:0,length:1}}})},data:Buffer.alloc(0)});
    expect(['EACCES','EPERM']).toContain((await wrongInst.json()).errno);
    const revokedParent=await request.post(origin+'/api/fs/data',{headers:{Origin:origin,'X-OS-Instance':p.inst.instanceId,'X-OS-Filesystem':JSON.stringify({version:2,credential:p.token,pid:p.pid,session:c.session,open,operation:{read:{offset:0,length:1}}})},data:Buffer.alloc(0)});
    expect(['EACCES','EPERM']).toContain((await revokedParent.json()).errno);
    await c.call('unlink',{dir,name:'fork'});await c.call('release',{open});
  }finally{await c.call('disconnect');await revokeCred({...child,inst:p.inst}).catch(()=>{});await revokeCred(p).catch(()=>{});}
});
test('ordinary image-backed clones support v2 reads, edits and sparse truncation across readers',async({request})=>{
  const {c,dir}=await setup(request);const name=(await c.call('parent',{dir}))[1];const base='/'+name;
  const source='/usr/bin/coreutils';
  const original=await call(request,{pread:{path:source,offset:0,count:64}});
  const head=Buffer.from(original.data,'base64');expect(head).toHaveLength(64);
  const clone=async name=>{
    const from=await call(request,{open:{path:source,flags:0}});
    const to=await call(request,{open:{path:base+'/'+name,flags:0o301,mode:0o600}});
    try{await call(request,{ioctl:{fd:to.fd,request:0x40049409,arg:from.fd}});}
    finally{await call(request,{close:{fd:to.fd}});await call(request,{close:{fd:from.fd}});}
    const entry=await c.call('lookup',{dir,name});return {entry,open:await c.open(entry.handle)};
  };
  const {entry,open}=await clone('edited');
  expect(await c.read(open,3,17)).toEqual(head.subarray(3,20));
  await c.write(open,'edit',{offset:4});const edited=Buffer.from(head);edited.write('edit',4);
  expect(await c.read(open,0,64)).toEqual(edited);
  const inline=await call(request,{pread:{path:base+'/edited',offset:0,count:64}});
  expect(Buffer.from(inline.data,'base64')).toEqual(edited);
  const file=await request.get(origin+'/api/file?path='+encodeURIComponent(base+'/edited'),{headers:{Range:'bytes=0-63'}});
  expect(file.status()).toBe(206);expect(await file.body()).toEqual(edited);
  await c.call('set_len',{open,size:12});await c.call('set_len',{open,size:24});await c.write(open,'after',{offset:16});
  const sparse=Buffer.alloc(24);edited.copy(sparse,0,0,12);sparse.write('after',16);
  expect(await c.read(open)).toEqual(sparse);
  const zero=await clone('zero');await c.call('set_len',{open:zero.open,size:0});await c.call('set_len',{open:zero.open,size:8});
  expect(await c.read(zero.open)).toEqual(Buffer.alloc(8));
  await c.call('unlink',{dir,name:'edited'});await c.call('unlink',{dir,name:'zero'});await c.call('release',{open});await c.call('release',{open:zero.open});
  await c.call('metadata',{handle:entry.handle},'ESTALE');
  const unchanged=await call(request,{pread:{path:source,offset:0,count:64}});
  expect(Buffer.from(unchanged.data,'base64')).toEqual(head);await c.call('disconnect');
});
test('compound setattr checks the original owner permissions before applying any change',async({request})=>{
  const {c:admin,dir:shared}=await setup(request);await admin.call('setattr',{handle:shared,attr:attrs({mode:0o777})});
  const name=(await admin.call('parent',{dir:shared}))[1];await api(request,'logout');
  const guest=await admit(request);const c=await connection(request,guest);const dir=(await c.call('lookup',{dir:c.root,name})).handle;
  const [entry,open]=await c.create(dir,'compound',0o600);await c.write(open,'original');
  const changed=await c.call('setattr',{handle:entry.handle,attr:attrs({mode:0o400,size:0,mtime:'now'})});
  expect([changed.mode,changed.size]).toEqual([0o400,0]);
  await c.call('setattr',{handle:entry.handle,attr:attrs({mode:0o600,size:3})},'EACCES');
  expect(await c.call('metadata',{handle:entry.handle})).toEqual(changed);
  await c.call('setattr',{handle:entry.handle,attr:attrs({mode:0o600})});await c.write(open,'updated');
  const truncated=await c.call('setattr',{handle:entry.handle,attr:attrs({mode:0o400,size:2})});
  expect([truncated.mode,truncated.size]).toEqual([0o400,2]);expect((await c.read(open)).toString()).toBe('up');
  await c.call('unlink',{dir,name:'compound'});await c.call('disconnect');await admin.call('disconnect');
});
test('directory enumeration returns only immediate persisted children of a nested tree',async({request})=>{
  const {c,dir}=await setup(request);const name=(await c.call('parent',{dir}))[1];const base='/'+name;
  const nested=await c.call('mkdir',{dir,name:'nested',mode:0o700});const [entry,open]=await c.create(dir,'file');
  const link=await c.call('symlink',{dir,name:'link',target:'nested'});
  for(let d=0;d<10;d++){
    await call(request,{mkdir:{path:base+'/nested/d'+d,mode:0o700}});
    const results=await sys(request,Array.from({length:40},(_,i)=>({symlink:{target:'missing',path:base+'/nested/d'+d+'/child'+i}})));
    expect(results.every(r=>'ok' in r)).toBe(true);
  }
  const entries=await c.call('read_dir',{dir});
  expect(entries.map(e=>[e.name,e.node.ino,e.file_type])).toEqual([
    ['file',entry.handle.node.ino,'file'],['link',link.handle.node.ino,'symlink'],['nested',nested.handle.node.ino,'dir']
  ]);
  expect((await c.call('read_dir',{dir:nested.handle})).map(e=>e.name)).toEqual(Array.from({length:10},(_,i)=>'d'+i));
  expect((await c.call('read_dir',{dir:c.root})).some(e=>e.name===name&&e.node.ino===dir.node.ino)).toBe(true);
  await c.call('release',{open});await c.call('disconnect');
});
test('reserved home destinations allow only the account owner or root',async({request})=>{
  const {c:admin}=await setup(request);const name='reserved-'+randomUUID().slice(0,12);
  const owner=await contexts.newContext({extraHTTPHeaders:{'CF-Connecting-IP':'cloudfs-'+randomUUID()}});
  const stranger=await contexts.newContext();let owned,attacker;
  try {
    await call(owner,'getcreds');expect((await api(owner,'register',{data:{username:name,password}})).ok()).toBe(true);
    const identity=await call(owner,'getcreds');expect(identity.home).toBe('/guest/'+name);
    owned=await connection(owner,await admit(owner));
    await call(stranger,'getcreds');attacker=await connection(stranger,await admit(stranger));
    const guest=(await attacker.call('lookup',{dir:attacker.root,name:'guest'})).handle;
    const source='source-'+randomUUID();const [file,open]=await attacker.create(guest,source);
    expect((await sys(stranger,[{mkdir:{path:identity.home,mode:0o700}}]))[0].err.errno).toBe('EACCES');
    for(const operation of [
      {mkdir:{dir:guest,name,mode:0o700,umask:0o022}},
      {create:{ticket:randomUUID(),dir:guest,name,mode:0o600,umask:0o022,options:options('read-write',{create_new:true})}},
      {symlink:{dir:guest,name,target:source}},
      {link:{target:file.handle,dir:guest,name}},
      {rename:{from_dir:guest,from:source,to_dir:guest,to:name,flags:''}},
    ]) {
      await rpc(stranger,attacker.token,attacker.session,operation,'EACCES');
      await attacker.call('lookup',{dir:guest,name},'ENOENT');
      expect((await attacker.call('lookup',{dir:guest,name:source})).handle.node).toEqual(file.handle.node);
    }
    const rootGuest=(await admin.call('lookup',{dir:admin.root,name:'guest'})).handle;
    const made=await admin.call('mkdir',{dir:rootGuest,name,mode:0o700});expect(made.metadata.uid).toBe(0);
    await admin.call('rmdir',{dir:rootGuest,name});
    const ownerGuest=(await owned.call('lookup',{dir:owned.root,name:'guest'})).handle;
    const home=await owned.call('mkdir',{dir:ownerGuest,name,mode:0o700});expect(home.metadata.uid).toBe(identity.uid);
    await attacker.call('unlink',{dir:guest,name:source});await attacker.call('release',{open});
  } finally {
    if(attacker)await attacker.call('disconnect');if(owned)await owned.call('disconnect');
    await owner.dispose();await stranger.dispose();await sys(request,[{userdel:{name,remove:true}}]);await admin.call('disconnect');
  }
});
test('cross-parent directory rename requires write access to the source directory',async({request})=>{
  await call(request,'getcreds');const c=await connection(request,await admit(request));
  const guest=(await c.call('lookup',{dir:c.root,name:'guest'})).handle;
  const name='rename-'+randomUUID();const base='/guest/'+name;
  const top=(await c.call('mkdir',{dir:guest,name,mode:0o700})).handle;
  const a=(await c.call('mkdir',{dir:top,name:'a',mode:0o700})).handle;
  const b=(await c.call('mkdir',{dir:top,name:'b',mode:0o700})).handle;
  const source=(await c.call('mkdir',{dir:a,name:'source',mode:0o700})).handle;
  const target=(await c.call('mkdir',{dir:b,name:'existing',mode:0o700})).handle;
  const [child,open]=await c.create(source,'child');await c.write(open,'kept');
  try {
    await c.call('setattr',{handle:source,attr:attrs({mode:0o555})});
    const before=await c.call('metadata',{handle:source});
    expect((await sys(request,[{rename:{from:base+'/a/source',to:base+'/b/moved'}}]))[0].err.errno).toBe('EACCES');
    for(const to of ['moved','existing'])await c.call('rename',{from_dir:a,from:'source',to_dir:b,to,flags:''},'EACCES');
    expect(await c.call('metadata',{handle:source})).toEqual(before);
    expect((await c.call('lookup',{dir:a,name:'source'})).handle.node).toEqual(source.node);
    expect((await c.call('lookup',{dir:b,name:'existing'})).handle.node).toEqual(target.node);
    await c.call('lookup',{dir:b,name:'moved'},'ENOENT');
    await c.call('rename',{from_dir:a,from:'source',to_dir:a,to:'renamed',flags:''});
    await c.call('setattr',{handle:source,attr:attrs({mode:0o755})});
    await c.call('rename',{from_dir:a,from:'renamed',to_dir:b,to:'moved',flags:''});
    expect((await c.call('parent',{dir:source}))[0].handle.node).toEqual(b.node);
    expect((await c.call('lookup',{dir:source,name:'child'})).handle.node).toEqual(child.handle.node);
    expect((await c.read(open)).toString()).toBe('kept');
  } finally {
    await c.call('setattr',{handle:source,attr:attrs({mode:0o700})});await c.call('disconnect');await rmrf(request,base);
  }
});
test('device unlink tears down descriptors and pending asks before another account reuses the name',async({request})=>{
  const {c,dir:files}=await setup(request);const name='device-'+randomUUID().slice(0,12);
  const account=await contexts.newContext({extraHTTPHeaders:{'CF-Connecting-IP':'cloudfs-'+randomUUID()}});let user;
  const paths=[];
  try {
    await call(account,'getcreds');expect((await api(account,'register',{data:{username:name,password}})).ok()).toBe(true);
    user=await connection(account,await admit(account));
    for(const driver of ['present','snd']) {
      const path='/dev/'+driver+'/'+name;paths.push(path);
      await call(request,{mknod:{path,mode:0o644,rdev:driver}});
      const writer=await call(request,{open:{path,flags:2}});const reader=await call(account,{open:{path,flags:0}});
      if(driver==='present')await call(account,{ioctl:{fd:reader.fd,request:0x5002,arg:{}}});
      const dir=(await c.call('walk',{dir:c.root,names:['dev',driver]})).entries.at(-1).handle;
      const ownDir=(await user.call('walk',{dir:user.root,names:['dev',driver]})).entries.at(-1).handle;
      await user.call('unlink',{dir:ownDir,name},'EPERM');
      await c.call('rmdir',{dir,name},'ENOTDIR');
      const [file,open]=await c.create(files,driver);await c.call('release',{open});
      await c.call('rename',{from_dir:dir,from:name,to_dir:files,to:'moved',flags:''},'EPERM');
      await c.call('rename',{from_dir:files,from:driver,to_dir:dir,to:name,flags:''},'EPERM');
      expect((await c.call('lookup',{dir:files,name:driver})).handle.node).toEqual(file.handle.node);
      await c.call('unlink',{dir,name});await c.call('lookup',{dir,name},'ENOENT');
      for(const [client,opened] of [[request,writer],[account,reader]]) {
        expect((await sys(client,[{ioctl:{fd:opened.fd,request:0x5002,arg:{}}}]))[0].err.errno).toBe('EBADF');
        expect((await sys(client,[{close:{fd:opened.fd}}]))[0].err.errno).toBe('EBADF');
      }
      // A stale device row would deny reuse by a different owner; stale asks would reappear.
      await call(account,{mknod:{path,mode:0o644,rdev:driver}});
      const replacement=await call(account,{open:{path,flags:2}});
      const state=await call(account,{pread:{fd:replacement.fd,offset:0,count:4096}});
      if(driver==='present')expect(JSON.parse(Buffer.from(state.data,'base64').toString()).asks).toEqual([]);
      await user.call('unlink',{dir:ownDir,name});
      expect((await sys(account,[{ioctl:{fd:replacement.fd,request:0x5002,arg:{}}}]))[0].err.errno).toBe('EBADF');
      expect((await sys(account,[{close:{fd:replacement.fd}}]))[0].err.errno).toBe('EBADF');
    }
  } finally {
    if(user)await user.call('disconnect');
    for(const path of paths)await sys(request,[{unlink:{path}}]);
    await account.dispose();await sys(request,[{userdel:{name,remove:true}}]);await c.call('disconnect');
  }
});
test('exec and path creation are rejected without adding names or changing existing files',async({request})=>{
  const {c,dir}=await setup(request);const [entry,open]=await c.create(dir,'existing',0);await c.write(open,'kept');
  const before=await c.call('metadata',{handle:entry.handle});const directory=await c.call('metadata',{handle:dir});
  try {
    for(const access of ['exec','path'])for(const createNew of [false,true])for(const name of ['missing','existing']) {
      await c.call('create',{ticket:randomUUID(),dir,name,mode:0,options:options(access,{create:true,create_new:createNew})},'EINVAL');
      await c.call('lookup',{dir,name:'missing'},'ENOENT');
      expect(await c.call('metadata',{handle:entry.handle})).toEqual(before);
      expect(await c.call('metadata',{handle:dir})).toEqual(directory);
    }
    await c.call('open',{ticket:randomUUID(),handle:entry.handle,options:options('exec')},'EACCES');
    expect((await c.read(open)).toString()).toBe('kept');
  } finally {
    await c.call('disconnect');
  }
});
test('registered homes and their containing directories require usermod to move',async({request})=>{
  const {c,dir}=await setup(request);const baseName=(await c.call('parent',{dir}))[1];const base='/'+baseName;
  const name='home-'+randomUUID().slice(0,12);const pending=name+'-pending';const path=base+'/homes/account';
  const accountHome=async user=>Buffer.from((await call(request,{pread:{path:'/etc/passwd',offset:0,count:262144}})).data,'base64').toString().split('\n').find(line=>line.startsWith(user+':')).split(':')[5];
  try {
    await call(request,{useradd:{name,home:path,create_home:true}});
    const homes=(await c.call('lookup',{dir,name:'homes'})).handle;const home=(await c.call('lookup',{dir:homes,name:'account'})).handle;
    await c.call('mkdir',{dir,name:'reserved',mode:0o755});
    await call(request,{useradd:{name:pending,home:base+'/reserved/unmade'}});
    const [,open]=await c.create(home,'kept');await c.write(open,'home data');
    const before=await c.call('metadata',{handle:home});
    expect((await sys(request,[{rename:{from:path,to:base+'/homes/moved'}}]))[0].err.errno).toBe('EBUSY');
    for(const flags of ['','NOREPLACE'])for(const [parent,from] of [[homes,'account'],[dir,'homes'],[dir,'reserved'],[c.root,baseName]]) {
      await c.call('rename',{from_dir:parent,from,to_dir:parent,to:from+'-moved',flags},'EBUSY');
      await c.call('lookup',{dir:parent,name:from+'-moved'},'ENOENT');
    }
    expect(await accountHome(name)).toBe(path);expect(await accountHome(pending)).toBe(base+'/reserved/unmade');
    expect(await c.call('metadata',{handle:home})).toEqual(before);
    await c.call('rename',{from_dir:homes,from:'account',to_dir:homes,to:'account',flags:''});
    await c.call('mkdir',{dir,name:'home',mode:0o755});
    await c.call('rename',{from_dir:dir,from:'home',to_dir:dir,to:'home-moved',flags:''});
    await call(request,{usermod:{name,home:base+'/relocated',move_home:true}});
    expect(await accountHome(name)).toBe(base+'/relocated');
    expect((await c.call('lookup',{dir,name:'relocated'})).handle.node).toEqual(home.node);
    expect((await c.read(open)).toString()).toBe('home data');
    await c.call('rename',{from_dir:dir,from:'relocated',to_dir:dir,to:'again',flags:''},'EBUSY');
  } finally {
    await c.call('disconnect');await sys(request,[{userdel:{name,remove:true}},{userdel:{name:pending,remove:true}},{groupdel:{name}},{groupdel:{name:pending}}]);await rmrf(request,base);
  }
});
for(const operation of ['write','truncate'])test(`${operation} privilege bits follow the actor independently of the opener`,async({request})=>{
  const {c,dir,p}=await setup(request);const [entry,rootOpen]=await c.create(dir,'privileged',0o666);
  await c.call('setattr',{handle:entry.handle,attr:attrs({mode:0o666})});
  await api(request,'logout');const guest=await admit(request);
  const guestOpen=await rpc(request,guest.token,c.session,{open:{ticket:randomUUID(),handle:entry.handle,options:options()}});
  try {
    // Under ServiceAuth v2, OpenRef grants are strictly per-credential: cross-credential use fails closed.
    c.token=guest.token;c.pid=guest.pid;
    if(operation==='write')await c.data(rootOpen,{write:{at:'end',length:1}},Buffer.from('x'),'EACCES');
    else await rpc(request,guest.token,c.session,{set_len:{open:rootOpen,size:2}},'EACCES');
    c.token=p.token;c.pid=p.pid;
    if(operation==='write')await c.data(guestOpen,{write:{at:'end',length:1}},Buffer.from('x'),'EACCES');
    else await rpc(request,p.token,c.session,{set_len:{open:guestOpen,size:2}},'EACCES');

    // On each credential's own open, privilege-bit stripping follows the actor's uid (root preserves, non-root strips).
    for(const [open,actor] of [[rootOpen,p],[guestOpen,guest]])for(const mode of [0o6755,0o6744]) {
      c.token=p.token;c.pid=p.pid;
      await c.call('set_len',{open:rootOpen,size:4});await c.call('setattr',{handle:entry.handle,attr:attrs({mode})});
      c.token=actor.token;c.pid=actor.pid;
      if(operation==='write') {
        await c.write(open,'',{offset:0});expect((await c.call('metadata',{handle:entry.handle})).mode).toBe(mode);
        await c.write(open,'x',{offset:0});
      } else {
        await rpc(request,actor.token,c.session,{set_len:{open,size:2}});
      }
      const expected=actor===p?mode:mode===0o6755?0o755:0o2744;
      expect((await c.call('metadata',{handle:entry.handle})).mode).toBe(expected);
    }
    await revokeCred(guest);
    c.token=p.token;c.pid=p.pid;
    if(operation==='write')await c.data(guestOpen,{write:{at:'end',length:1}},Buffer.from('x'),'EACCES');
    else await c.call('set_len',{open:guestOpen,size:0},'EACCES');
  } finally {
    await c.call('disconnect');
  }
});
test('driver-backed device creation initializes usable state and rejects unsupported drivers',async({request})=>{
  const {c,dir}=await setup(request);const name='created-'+randomUUID().slice(0,12);const paths=[];
  try {
    for(const driver of ['present','snd']) {
      const parent=(await c.call('walk',{dir:c.root,names:['dev',driver]})).entries.at(-1).handle;
      const path='/dev/'+driver+'/'+name;paths.push(path);
      const entry=await c.call('mknod',{dir:parent,name,mode:0o666,rdev:driver});
      expect(entry.metadata).toMatchObject({file_type:'char-device',rdev:driver,mode:0o644,uid:0,nlink:1});
      const opened=await call(request,{open:{path,flags:2}});expect(opened.device).toBe(driver);
      await c.call('mknod',{dir:parent,name,mode:0o600,rdev:driver},'EEXIST');
      expect((await c.call('lookup',{dir:parent,name})).handle.node).toEqual(entry.handle.node);
      const state=JSON.parse(Buffer.from((await call(request,{pread:{fd:opened.fd,offset:0,count:4096}})).data,'base64').toString());
      expect(state).toMatchObject({device:path,owner:'root'});
      if(driver==='present')expect(state.asks).toEqual([]);else expect(state.live).toBe(false);
      await c.call('unlink',{dir:parent,name});
      expect((await sys(request,[{ioctl:{fd:opened.fd,request:0x5002,arg:{}}}]))[0].err.errno).toBe('EBADF');
    }
    for(const [rdev,errno] of [['unknown-driver','EOPNOTSUPP'],['present','EPERM'],['snd','EPERM'],['','EINVAL']]) {
      await c.call('mknod',{dir,name:'unsupported',mode:0o600,rdev},errno);
      await c.call('lookup',{dir,name:'unsupported'},'ENOENT');
    }
    await api(request,'logout');const guest=await admit(request);
    await rpc(request,guest.token,c.session,{mknod:{dir,name:'guest-device',mode:0o600,umask:0o022,rdev:'present'}},'EPERM');
    await c.call('lookup',{dir,name:'guest-device'},'ENOENT');
  } finally {
    // Also repairs the inode-only result when running this probe against the old code.
    for(const path of paths)await sys(request,[{unlink:{path}}]);
    await c.call('disconnect');
  }
});
test('device hardlinks are denied for both root and the device owner without creating aliases',async({request})=>{
  const {c,dir}=await setup(request);const base='/'+(await c.call('parent',{dir}))[1];const name='linkdev-'+randomUUID().slice(0,12);
  const account=await contexts.newContext({extraHTTPHeaders:{'CF-Connecting-IP':'cloudfs-'+randomUUID()}});let user;const paths=[];
  try {
    await call(account,'getcreds');expect((await api(account,'register',{data:{username:name,password,create_home:true}})).ok()).toBe(true);
    user=await connection(account,await admit(account));const identity=await call(account,'getcreds');
    const home=(await user.call('walk',{dir:user.root,names:identity.home.split('/').filter(Boolean)})).entries.at(-1).handle;
    for(const driver of ['present','snd']) {
      const path='/dev/'+driver+'/'+name;paths.push(path);await call(account,{mknod:{path,mode:0o644,rdev:driver}});
      expect((await sys(request,[{link:{from:path,to:base+'/legacy-'+driver,follow:false}}]))[0].err.errno).toBe('EPERM');
      for(const [client,dest] of [[c,dir],[user,home]]) {
        const parent=(await client.call('walk',{dir:client.root,names:['dev',driver]})).entries.at(-1).handle;
        const device=await client.call('lookup',{dir:parent,name});
        await client.call('link',{target:device.handle,dir:dest,name:'alias-'+driver},'EPERM');
        await client.call('lookup',{dir:dest,name:'alias-'+driver},'ENOENT');
        expect((await client.call('metadata',{handle:device.handle})).nlink).toBe(1);
      }
      await call(account,{unlink:{path}});
    }
  } finally {
    if(user)await user.call('disconnect');for(const path of paths)await sys(request,[{unlink:{path}}]);
    await account.dispose();await sys(request,[{userdel:{name,remove:true}}]);await c.call('disconnect');await rmrf(request,base);
  }
});
test('truncate on creation preserves privilege bits while reopening an existing file strips them',async({request})=>{
  await call(request,'getcreds');const c=await connection(request,await admit(request));
  const guest=(await c.call('lookup',{dir:c.root,name:'guest'})).handle;const name='create-truncate-'+randomUUID();
  const dir=(await c.call('mkdir',{dir:guest,name,mode:0o700})).handle;
  try {
    for(const mode of [0o4755,0o6755]) {
      const args={dir,name:'mode-'+mode,mode,options:options('read-write',{create:true,truncate:true})};
      const [entry,open]=await c.call('create',{ticket:randomUUID(),...args});
      expect(entry.metadata.mode).toBe(mode);
      expect(await c.call('metadata',{handle:entry.handle})).toEqual(entry.metadata);
      expect((await c.read(open)).length).toBe(0);
      await c.write(open,'existing data');await c.call('setattr',{handle:entry.handle,attr:attrs({mode})});
      const [reopened,next]=await c.call('create',{ticket:randomUUID(),...args});
      expect(reopened.handle.node).toEqual(entry.handle.node);
      expect(reopened.metadata).toMatchObject({mode:0o755,size:0});
      expect(await c.call('metadata',{handle:entry.handle})).toEqual(reopened.metadata);
      expect((await c.read(open)).length).toBe(0);await c.call('release',{open:next});
    }
  } finally {
    await c.call('disconnect');await rmrf(request,'/guest/'+name);
  }
});
test('creation uses the current per-call umask and requires it even when it is zero',async({request})=>{
  const {c,dir}=await setup(request);const devices=(await c.call('walk',{dir:c.root,names:['dev','present']})).entries.at(-1).handle;
  let privateFile,publicFile;
  try {
    for(const mask of [0o022,0o077,0o002,0]) {
      c.umask=mask;
      const [file]=await c.create(dir,'file-'+mask,0o666);
      const directory=await c.call('mkdir',{dir,name:'dir-'+mask,mode:0o777});
      const name='mask-'+randomUUID();const device=await c.call('mknod',{dir:devices,name,mode:0o666,rdev:'present'});
      expect(file.metadata.mode).toBe(0o666&~mask);expect(directory.metadata.mode).toBe(0o777&~mask);expect(device.metadata.mode).toBe(0o666&~mask);
      expect((await c.call('metadata',{handle:file.handle})).mode).toBe(file.metadata.mode);
      await c.call('unlink',{dir:devices,name});
      if(mask===0o077)privateFile=file.handle;if(mask===0)publicFile=file.handle;
    }
    for(const [operation,args] of [
      ['create',{dir,name:'omitted',ticket:randomUUID(),mode:0o666,options:options('read-write',{create_new:true})}],
      ['mkdir',{dir,name:'omitted',mode:0o777}],
      ['mknod',{dir:devices,name:'omitted-'+randomUUID(),mode:0o666,rdev:'present'}],
    ]) {
      await rpc(request,c.token,c.session,{[operation]:args},'EINVAL');
      await c.call('lookup',{dir:args.dir,name:args.name},'ENOENT');
    }
    await api(request,'logout');const guest=await admit(request);
    await rpc(request,guest.token,c.session,{open:{ticket:randomUUID(),handle:privateFile,options:options('read')}},'EACCES');
    const opened=await rpc(request,guest.token,c.session,{open:{ticket:randomUUID(),handle:publicFile,options:options('read')}});
    await c.call('release',{open:opened});
  } finally {
    await c.call('disconnect');
  }
});
test('default ACL inheritance takes precedence over the current umask without changing existing files',async({request})=>{
  const {c,dir}=await setup(request);const acl={user:7,group:5,other:0,mask:5,users:{1001:7},groups:{}};
  const decode=value=>JSON.parse(Buffer.from(value).toString());
  try {
    await c.call('setattr',{handle:dir,attr:attrs({mode:0o2777,gid:1234})});
    await c.call('setxattr',{handle:dir,name:'system.posix_acl_default',value:[...Buffer.from(JSON.stringify(acl))],flags:'CREATE'});
    c.umask=0o077;
    const [file,open]=await c.create(dir,'file',0o666);const child=await c.call('mkdir',{dir,name:'child',mode:0o777});
    expect(file.metadata).toMatchObject({mode:0o640,gid:1234,acl:true});expect(child.metadata).toMatchObject({mode:0o2750,gid:1234,acl:true});
    expect(decode(await c.call('getxattr',{handle:file.handle,name:'system.posix_acl_access'}))).toMatchObject({mask:4,users:{1001:7}});
    expect(decode(await c.call('getxattr',{handle:child.handle,name:'system.posix_acl_default'}))).toEqual(acl);
    c.umask=0o777;
    const [nested]=await c.create(child.handle,'nested',0o666);expect(nested.metadata).toMatchObject({mode:0o640,gid:1234,acl:true});
    await c.write(open,'kept');const before=await c.call('metadata',{handle:file.handle});
    const [existing]=await c.call('create',{ticket:randomUUID(),dir,name:'file',mode:0o600,options:options('read-write',{create:true})});
    expect(existing.metadata).toEqual(before);
    expect((await c.call('symlink',{dir,name:'link',target:'file'})).metadata.mode).toBe(0o777);
  } finally {
    await c.call('disconnect');
  }
});
test('system-image, procfs and generated account projections are read-only while large-offset and empty writes follow Linux',async({request})=>{
  const {c,dir}=await setup(request);
  const exact=(open,rawOp,bytes)=>request.post(origin+'/api/fs/data',{headers:{Origin:origin,'X-OS-Instance':c.instanceId,'X-OS-Filesystem':`{"version":2,"credential":${JSON.stringify(c.token)},"pid":${c.pid},"session":${JSON.stringify(c.session)},"open":${JSON.stringify(open)},"operation":${rawOp}}`},data:bytes??Buffer.alloc(0)});
  try {
    const rootChildren=await c.call('read_dir',{dir:c.root});
    expect((await c.call('metadata',{handle:c.root})).nlink).toBe(2+rootChildren.filter(e=>e.file_type==='dir').length);
    for(const name of ['usr','sys'])await c.call('mkdir',{dir:c.root,name,mode:0o755},'EROFS');
    await c.call('create',{ticket:randomUUID(),dir:c.root,name:'usr',mode:0o644,options:options('read-write',{create:true})},'EROFS');
    await c.call('symlink',{dir:c.root,name:'sys',target:'/tmp'},'EROFS');
    const proc=await c.call('lookup',{dir:c.root,name:'proc'});
    await c.call('mkdir',{dir:proc.handle,name:'shadow',mode:0o755},'EROFS');
    await c.call('setattr',{handle:proc.handle,attr:attrs({mode:0o777})},'EROFS');
    await c.call('setxattr',{handle:proc.handle,name:'user.shadow',value:[1],flags:''},'EROFS');
    await c.call('rmdir',{dir:c.root,name:'proc'},'EROFS');
    const etc=(await c.call('lookup',{dir:c.root,name:'etc'})).handle;
    for(const [name,needle] of [['passwd','root:x:0:0:'],['group','root:x:0:']]) {
      const entry=await c.call('lookup',{dir:etc,name});const ro=await c.open(entry.handle,'read');
      const full=await c.read(ro,0,65536);
      expect(entry.metadata.size).toBe(full.length);expect(full.toString()).toContain(needle);
      expect(await c.read(ro,2,5)).toEqual(full.subarray(2,7));
      await c.call('release',{open:ro});
      await c.call('open',{ticket:randomUUID(),handle:entry.handle,options:options('write')},'EROFS');
      await c.call('create',{ticket:randomUUID(),dir:etc,name,mode:0o644,options:options('read-write',{create:true})},'EROFS');
      await c.call('setattr',{handle:entry.handle,attr:attrs({mode:0o600})},'EROFS');
      await c.call('link',{target:entry.handle,dir,name:'alias-'+name},'EROFS');
      await c.call('unlink',{dir:etc,name},'EROFS');
      await c.call('rename',{from_dir:etc,from:name,to_dir:dir,to:'moved-'+name,flags:''},'EROFS');
    }
    const [file,open]=await c.create(dir,'file');
    await c.call('rename',{from_dir:dir,from:'file',to_dir:c.root,to:'usr',flags:''},'EROFS');
    await c.call('rename',{from_dir:dir,from:'file',to_dir:proc.handle,to:'file',flags:''},'EROFS');
    // ftruncate of an O_PATH reference is EBADF; writing nothing is no error at any offset.
    const path=await c.open(file.handle,'path');await c.call('set_len',{open:path,size:0},'EBADF');
    for(const rawOffset of ['9223372036854775807','9223372036854775808']) {
      const res=await exact(open,`{"write":{"at":{"offset":${rawOffset}},"length":0}}`);
      expect(res.ok(),await res.text()).toBe(true);expect(await res.json()).toMatchObject({len:0});
    }
    // Straddling i64::MAX (9223372036854775807) commits a short write; starting at or past it returns EFBIG.
    const shortOff=await exact(open,'{"write":{"at":{"offset":9223372036854775805},"length":5}}',Buffer.from('hello'));
    expect(shortOff.ok(),shortOff.ok()?'':await shortOff.text()).toBe(true);expect(await shortOff.text()).toBe('{"len":2,"offset":9223372036854775805}');
    const tail=await exact(open,'{"read":{"offset":9223372036854775805,"length":2}}');
    expect((await tail.body()).toString()).toBe('he');
    const atMax=await exact(open,'{"write":{"at":{"offset":9223372036854775807},"length":1}}',Buffer.from('x'));
    expect((await atMax.json()).errno).toBe('EFBIG');
    const appendAtMax=await exact(open,'{"write":{"at":"end","length":1}}',Buffer.from('x'));
    expect((await appendAtMax.json()).errno).toBe('EFBIG');
    const shrink=await request.post(origin+'/api/fs',{headers:{Origin:origin,'X-OS-Instance':c.instanceId,'Content-Type':'application/json'},data:'{"version":2,"credential":'+JSON.stringify(c.token)+',"session":'+JSON.stringify(c.session)+',"call":{"set_len":{"open":'+JSON.stringify(open)+',"size":9223372036854775805}}}'});
    expect(shrink.ok(),shrink.ok()?'':await shrink.text()).toBe(true);
    const shortEnd=await exact(open,'{"write":{"at":"end","length":5}}',Buffer.from('world'));
    expect(shortEnd.ok(),shortEnd.ok()?'':await shortEnd.text()).toBe(true);expect(await shortEnd.text()).toBe('{"len":2,"offset":9223372036854775805}');
    await c.call('unlink',{dir,name:'file'});await c.call('release',{open:path});await c.call('release',{open});
  } finally {
    await c.call('disconnect');
  }
});
test('fixed kernel devices and device directories refuse unlink, rmdir and rename',async({request})=>{
  const {c,dir}=await setup(request);const dev=(await c.call('lookup',{dir:c.root,name:'dev'})).handle;
  try {
    for(const fixed of ['null','zero','system']) {
      expect((await sys(request,[{unlink:{path:'/dev/'+fixed}}]))[0].err.errno).toBe('EPERM');
      await c.call('unlink',{dir:dev,name:fixed},'EPERM');
      expect((await c.call('lookup',{dir:dev,name:fixed})).metadata.file_type).toBe('char-device');
    }
    await c.call('rename',{from_dir:c.root,from:'dev',to_dir:dir,to:'moved-dev',flags:''},'EPERM');
    await c.call('rename',{from_dir:dev,from:'present',to_dir:dir,to:'moved-present',flags:''},'EPERM');
    await c.call('rmdir',{dir:c.root,name:'dev'},'EBUSY');
    const present=(await c.call('lookup',{dir:dev,name:'present'})).handle;
    if((await c.call('read_dir',{dir:present})).length===0)await c.call('rmdir',{dir:dev,name:'present'},'EBUSY');
    await api(request,'logout');const guest=await admit(request);
    const guestConn=await connection(request,guest);
    const guestDev=(await guestConn.call('lookup',{dir:guestConn.root,name:'dev'})).handle;
    await guestConn.call('unlink',{dir:guestDev,name:'null'},'EACCES');
    expect((await sys(request,[{unlink:{path:'/dev/null'}}]))[0].err.errno).toBe('EACCES');
    await guestConn.call('disconnect');
  } finally {
    await c.call('disconnect');
  }
});
test('chained lock cancellations, >1024 cancellation receipts, and partial downgrade rollbacks hold across SQLite',async({request})=>{
  const {c,dir}=await setup(request);const [entry,a]=await c.create(dir,'locks-reg');
  const b=await c.open(entry.handle);const d=await c.open(entry.handle);
  const span=(start,end)=>({start,end});
  const lock=(open,start,end,kind='exclusive')=>({open,family:'posix',kind,range:span(start,end)});
  try {
    // 1. Out-of-order cancellation of overlapping ticketed grants must not resurrect the earlier grant.
    const tA=randomUUID(),tB=randomUUID();
    expect(await c.call('lock',{...lock(a,0,80),ticket:tA})).toBe(true);
    expect(await c.call('lock',{...lock(a,20,100),ticket:tB})).toBe(true);
    await c.call('cancel_lock',{open:a,ticket:tA});
    await c.call('cancel_lock',{open:a,ticket:tB});
    await c.call('try_lock',lock(b,0,100));
    await c.call('unlock',{open:b,family:'posix',range:span(0,100)});

    // 2. Cancelling a downgrade splits at conflicting subranges and restores exclusive elsewhere.
    await c.call('try_lock',lock(a,0,100,'exclusive'));
    const down=randomUUID();
    expect(await c.call('lock',{...lock(a,0,100,'shared'),ticket:down})).toBe(true);
    await c.call('try_lock',lock(b,0,10,'shared'));
    await c.call('cancel_lock',{open:a,ticket:down});
    await c.call('try_lock',lock(d,0,10,'shared'));
    await c.call('try_lock',lock(d,10,100,'shared'),'EAGAIN');
    await c.call('unlock',{open:d,family:'posix',range:span(0,10)});
    await c.call('unlock',{open:b,family:'posix',range:span(0,10)});
    await c.call('unlock',{open:a,family:'posix',range:span(0,100)});

    // 3. >1,024 subsequent cancellations must not evict an unretired cancellation receipt.
    const early=randomUUID();
    await c.call('cancel_lock',{open:a,ticket:early});
    for(let batch=0;batch<22;batch++) {
      await Promise.all(Array.from({length:50},(_,i)=>c.call('cancel_lock',{open:i%2?a:b,ticket:`noise-${batch}-${i}-${randomUUID()}`})));
    }
    await c.call('lock',{...lock(a,0,10),ticket:early},'ECANCELED');
  } finally {
    await c.call('unlink',{dir,name:'locks-reg'});
    for(const open of [a,b,d])await c.call('release',{open});
    await c.call('disconnect');
  }
});
test('walk final symlinks, ticket/cancel_open authorization, read-only subtree renames, owner-scoped lock tickets, zero/EOF relatime, and POSIX error order',async({request})=>{
  const {c,dir}=await setup(request);
  try {
    // 1. Walk returns stop: null when the final component is a symlink, and Symlink(index) only when intermediate.
    const sub=await c.call('mkdir',{dir,name:'sub',mode:0o755});
    const sym=await c.call('symlink',{dir,name:'sym',target:'sub'});
    await c.call('symlink',{dir:sub.handle,name:'leaf-sym',target:'target'});
    const walkFinal=await c.call('walk',{dir,names:['sym']});
    expect(walkFinal.stop).toBeNull();
    expect(walkFinal.entries).toHaveLength(1);
    expect(walkFinal.entries[0].metadata.file_type).toBe('symlink');
    const walkNestedFinal=await c.call('walk',{dir,names:['sub','leaf-sym']});
    expect(walkNestedFinal.stop).toBeNull();
    expect(walkNestedFinal.entries).toHaveLength(2);
    expect(walkNestedFinal.entries[1].metadata.file_type).toBe('symlink');
    const walkMid=await c.call('walk',{dir,names:['sym','leaf-sym']});
    expect(walkMid.stop).toEqual({Symlink:0});
    expect(walkMid.entries).toHaveLength(1);

    // 2. Renaming an ancestor of read-only projections (/etc) returns EROFS even for root.
    await c.call('rename',{from_dir:c.root,from:'etc',to_dir:dir,to:'moved-etc',flags:''},'EROFS');

    // 3. Same lock wait ticket across two opens on the same inode stays independent per owner.
    const [fileEntry,o1]=await c.create(dir,'file',0o644);
    const o2=await c.open(fileEntry.handle);
    const o3=await c.open(fileEntry.handle);
    const span=(start,end)=>({start,end});
    await c.call('try_lock',{open:o3,family:'posix',kind:'shared',range:span(0,50)});
    const sharedTicket=randomUUID();
    expect(await c.call('lock',{ticket:sharedTicket,open:o1,family:'posix',kind:'exclusive',range:span(0,100)})).toBe(false);
    expect(await c.call('lock',{ticket:sharedTicket,open:o2,family:'posix',kind:'shared',range:span(50,100)})).toBe(false);
    await c.call('unlock',{open:o3,family:'posix',range:span(0,50)});
    expect(await c.call('lock',{ticket:sharedTicket,open:o2,family:'posix',kind:'shared',range:span(50,100)})).toBe(false);
    expect(await c.call('lock',{ticket:sharedTicket,open:o1,family:'posix',kind:'exclusive',range:span(0,100)})).toBe(true);
    await c.call('ack_lock',{open:o1,ticket:sharedTicket});
    await c.call('unlock',{open:o1,family:'posix',range:span(0,100)});
    expect(await c.call('lock',{ticket:sharedTicket,open:o2,family:'posix',kind:'shared',range:span(50,100)})).toBe(true);
    await c.call('ack_lock',{open:o2,ticket:sharedTicket});
    await c.call('unlock',{open:o2,family:'posix',range:span(50,100)});

    // 4. Zero-byte reads and reads at/past EOF update atime under relatime.
    await c.write(o1,'hello');
    await c.call('setattr',{handle:fileEntry.handle,attr:attrs({atime:{sec:1,nsec:0}})});
    expect((await c.call('metadata',{handle:fileEntry.handle})).atime.sec).toBe(1);
    expect((await c.read(o1,0,0)).length).toBe(0);
    expect((await c.call('metadata',{handle:fileEntry.handle})).atime.sec).toBeGreaterThan(1);
    await c.call('setattr',{handle:fileEntry.handle,attr:attrs({atime:{sec:1,nsec:0}})});
    expect((await c.call('metadata',{handle:fileEntry.handle})).atime.sec).toBe(1);
    expect((await c.read(o1,100,16)).length).toBe(0);
    expect((await c.call('metadata',{handle:fileEntry.handle})).atime.sec).toBeGreaterThan(1);

    // 5. POSIX / MemFs check ordering and atomic mtime == ctime on truncate.
    await c.call('open',{ticket:randomUUID(),handle:sym.handle,options:options('write')},'ELOOP');
    const etc=(await c.call('lookup',{dir:c.root,name:'etc'})).handle;
    await c.call('open',{ticket:randomUUID(),handle:etc,options:options('read',{truncate:true})},'EISDIR');
    const [,passwdRo]=await c.call('create',{ticket:randomUUID(),dir:etc,name:'passwd',mode:0o644,options:options('read',{create:true})});
    expect((await c.read(passwdRo,0,128)).toString()).toContain('root:x:0:0:');
    await c.call('release',{open:passwdRo});
    await c.call('link',{target:sub.handle,dir,name:'file'},'EEXIST');
    await c.call('setattr',{handle:fileEntry.handle,attr:attrs({size:2})});
    const truncMeta=await c.call('metadata',{handle:fileEntry.handle});
    expect(truncMeta.mtime).toEqual(truncMeta.ctime);

    // Prepare a read-only directory fixture before switching to an unprivileged credential in the same namespace.
    const roDir=await c.call('mkdir',{dir,name:'ro-dir',mode:0o755});
    const [aEntry,aOpen]=await c.create(roDir.handle,'a',0o644);
    await c.call('release',{open:aOpen});
    await c.call('link',{target:aEntry.handle,dir:roDir.handle,name:'a-link'});
    const [,bOpen]=await c.create(roDir.handle,'b',0o644);
    await c.call('release',{open:bOpen});
    const cycleDir=await c.call('mkdir',{dir:roDir.handle,name:'cycle',mode:0o555});
    await c.call('setattr',{handle:roDir.handle,attr:attrs({mode:0o555})});

    // 6. Ticket replay validates call shape (EINVAL) and caller grant (EACCES), and CancelOpen rejects ungranted callers.
    const tOpen=randomUUID();
    const askOpen={ticket:tOpen,handle:fileEntry.handle,options:options('read-write')};
    const retained=await c.call('open',askOpen);
    expect(await c.call('open',askOpen)).toEqual(retained);
    await c.call('open',{...askOpen,options:options('read')},'EINVAL');
    await c.call('create',{ticket:tOpen,dir,name:'other',mode:0o644,options:options('read-write',{create:true})},'EINVAL');

    await api(request,'logout');
    const guest=await admit(request);
    await rpc(request,guest.token,c.session,{open:askOpen},'EACCES');
    await rpc(request,guest.token,c.session,{cancel_open:{ticket:tOpen}},'EACCES');
    expect((await c.read(retained)).toString()).toBe('he');

    // Unprivileged error ordering on directories and non-writable parents matches MemFs/Linux.
    await rpc(request,guest.token,c.session,{setattr:{handle:sub.handle,attr:attrs({size:0})}},'EISDIR');
    await rpc(request,guest.token,c.session,{rename:{from_dir:roDir.handle,from:'a',to_dir:roDir.handle,to:'b',flags:'NOREPLACE'}},'EEXIST');
    expect(await rpc(request,guest.token,c.session,{rename:{from_dir:roDir.handle,from:'a',to_dir:roDir.handle,to:'a-link',flags:''}})).toBeNull();
    await rpc(request,guest.token,c.session,{rename:{from_dir:roDir.handle,from:'cycle',to_dir:cycleDir.handle,to:'sub',flags:''}},'EINVAL');

    await c.call('cancel_open',{ticket:tOpen});
    await c.call('open',askOpen,'ECANCELED');
    for(const o of [o1,o2,o3])await c.call('release',{open:o});
  } finally {
    await c.call('disconnect');
  }
});

test('client-kernel CloudFs manages descriptions, SEEK_END, O_APPEND, fsync, lock cancel, fork inheritance and unlinked exit cleanup', async ({ context, request }) => {
  const ip = 'cloudfs-ck-' + randomUUID();
  const extra = { Origin: origin, 'CF-Connecting-IP': ip };
  await context.setExtraHTTPHeaders({ 'CF-Connecting-IP': ip });
  expect((await api(request, 'login', { headers: extra, data: { password } })).ok()).toBe(true);
  expect((await api(context.request, 'login', { headers: extra, data: { password } })).ok()).toBe(true);
  const base = '/cloudfs-ck-' + randomUUID();
  await mkdirp(request, base, 0o755);
  const page = await context.newPage();
  try {
    await page.goto('/');
    await page.evaluate(() => {
      const port = new Worker('/client-kernel.js');
      const pending = new Map();
      let next = 0;
      port.onmessage = ({ data }) => {
        if (data?.id != null && pending.has(data.id)) {
          pending.get(data.id)(data);
          pending.delete(data.id);
        }
      };
      window.__kernel = (type, args = {}) => new Promise(resolve => {
        const id = ++next;
        pending.set(id, resolve);
        port.postMessage({ v: 2, id, type, args });
      });
    });
    const k = async (type, args = {}) => {
      const reply = await page.evaluate(([t, a]) => window.__kernel(t, a), [type, args]);
      if (reply.err) throw Object.assign(new Error(reply.err.detail ?? reply.err.errno), reply.err);
      return reply.ok;
    };
    const kErr = async (type, args = {}) => {
      const reply = await page.evaluate(([t, a]) => window.__kernel(t, a), [type, args]);
      expect(reply.err, `expected error for ${type}`).toBeTruthy();
      return reply.err.errno;
    };
    const ROOT_FD = 0x7ffffffd;
    const ENV = ['PWD=/', 'PATH=/usr/bin', 'LANG=C.UTF-8'];
    const sleepCmd = { path: '/usr/bin/coreutils', argv: ['coreutils', 'sleep', '60'], env: ENV, cwd: '/' };
    await k('init');
    await k('sync_account_from_server');
    const p1 = await k('exec', sleepCmd);
    const p2 = await k('exec', sleepCmd);

    // 1. Open creates regular files with shared CloudFs st_dev and opens /dev/null via DevTmpFs.
    const devNull = await k('proc_openat', { pid: p1.pid, dirfd: ROOT_FD, path: '/dev/null', oflags: 2, mode: 0 });
    expect(devNull).toMatchObject({ device: 'null', fstype: 'devtmpfs' });
    await k('kfd_close', { pid: p1.pid, kfd: devNull.kfd });
    const f = await k('proc_openat', { pid: p1.pid, dirfd: ROOT_FD, path: `${base}/f.txt`, oflags: 0o2 | 0o100 | 0o200, mode: 0o644 });
    const g = await k('proc_openat', { pid: p1.pid, dirfd: ROOT_FD, path: `${base}/g.txt`, oflags: 0o2 | 0o100 | 0o200, mode: 0o644 });
    expect(f.stat.dev).toBeGreaterThan(0);
    expect(g.stat.dev).toBe(f.stat.dev);
    expect(g.stat.ino).not.toBe(f.stat.ino);
    expect(f.stat.nlink).toBe(1);

    // 2. Write, SEEK_END, O_APPEND toggle (F_SETFL/F_GETFL), and fsync/fdatasync.
    expect(await k('kfd_write', { pid: p1.pid, kfd: f.kfd, data: Array.from(Buffer.from('hello')) })).toBe(5);
    expect(await k('kfd_seek', { pid: p1.pid, kfd: f.kfd, offset: '0', whence: 2 })).toBe('5');
    expect(await k('kfd_is_append', { pid: p1.pid, kfd: f.kfd })).toBe(false);
    await k('kfd_set_append', { pid: p1.pid, kfd: f.kfd, append: true });
    expect(await k('kfd_is_append', { pid: p1.pid, kfd: f.kfd })).toBe(true);
    expect(await k('kfd_seek', { pid: p1.pid, kfd: f.kfd, offset: '1', whence: 0 })).toBe('1');
    expect(await k('kfd_write', { pid: p1.pid, kfd: f.kfd, data: Array.from(Buffer.from('!')) })).toBe(1);
    expect(await k('kfd_seek', { pid: p1.pid, kfd: f.kfd, offset: '0', whence: 2 })).toBe('6');
    await k('kfd_fsync', { pid: p1.pid, kfd: f.kfd, dataOnly: false });
    await k('kfd_fsync', { pid: p1.pid, kfd: f.kfd, dataOnly: true });

    // 3. Fork inheritance + parent close + unlink while child still holds the open inode.
    const child = await k('fork', { pid: p1.pid });
    await k('kfd_close', { pid: p1.pid, kfd: f.kfd });
    expect(await kErr('kfd_fstat', { pid: p1.pid, kfd: f.kfd })).toBe('EBADF');
    expect(await kErr('kfd_fstat', { pid: p2.pid, kfd: f.kfd })).toBe('EBADF');
    const [unlinked] = await sys(request, [{ unlink: { path: `${base}/f.txt` } }], {}, extra);
    expect(unlinked.ok).toBeNull();
    const unlinkedStat = await k('kfd_fstat', { pid: child.pid, kfd: f.kfd });
    expect(unlinkedStat.dev).toBe(f.stat.dev);
    expect(unlinkedStat.ino).toBe(f.stat.ino);
    expect(unlinkedStat.nlink).toBe(0);
    expect(unlinkedStat.size).toBe(6);
    const bytes = await k('kfd_pread', { pid: child.pid, kfd: f.kfd, len: 16, offset: '0' });
    expect(Buffer.from(bytes).toString()).toBe('hello!');

    // 4. Blocking lock wait + kfd_cancel unblocks concurrently with EINTR.
    const g2 = await k('proc_openat', { pid: p2.pid, dirfd: ROOT_FD, path: `${base}/g.txt`, oflags: 0o2, mode: 0 });
    await k('kfd_lock', { pid: p1.pid, kfd: g.kfd, family: 'posix', kind: 'exclusive', start: '0', wait: false });
    const conflict = await k('kfd_test_lock', { pid: p2.pid, kfd: g2.kfd, kind: 'exclusive', start: '0' });
    expect(conflict).toBeTruthy();
    const waitLock = kErr('kfd_lock', { pid: p2.pid, kfd: g2.kfd, family: 'posix', kind: 'exclusive', start: '0', wait: true });
    await page.waitForTimeout(100);
    await k('kfd_cancel', { pid: p2.pid, kfd: g2.kfd });
    expect(await waitLock).toBe('EINTR');
    await k('kfd_unlock', { pid: p1.pid, kfd: g.kfd, family: 'posix', start: '0' });
    await k('kfd_lock', { pid: p2.pid, kfd: g2.kfd, family: 'posix', kind: 'exclusive', start: '0', wait: false });
    await k('kfd_close', { pid: p1.pid, kfd: g.kfd });
    await k('kfd_close', { pid: p2.pid, kfd: g2.kfd });

    // 5. Replacement reexec retains caller access & cloud_renew succeeds; exit releases unlinked file.
    await k('reexec', { pid: child.pid, ...sleepCmd });
    expect(await k('kfd_write', { pid: child.pid, kfd: f.kfd, data: Array.from(Buffer.from('?')) })).toBe(1);
    await k('cloud_renew');
    await k('exit', { pid: child.pid, status: 0 });
    await k('exit', { pid: p1.pid, status: 0 });
    await k('exit', { pid: p2.pid, status: 0 });
    await k('wait', { pid: p1.pid });
    await k('wait', { pid: p2.pid });
    const [afterExit] = await sys(request, [{ stat: { path: `${base}/f.txt` } }], {}, extra);
    expect(afterExit.err?.errno).toBe('ENOENT');

    // 6. Traversal permission checks (..), protected symlinks with Call::Getcreds identity, and non-aliasing reconnect IDs.
    await mkdirp(request, `${base}/blocked`, 0o700);
    await call(request, { chmod: { path: `${base}/blocked`, mode: 0o700 } }, { headers: extra });
    expect((await put(request, '/api/file?path=' + encodeURIComponent(`${base}/ok`), { headers: extra, data: 'ok' })).status()).toBe(201);
    await mkdirp(request, `${base}/sticky`, 0o777);
    await call(request, { chmod: { path: `${base}/sticky`, mode: 0o1777 } }, { headers: extra });
    expect((await put(request, '/api/file?path=' + encodeURIComponent(`${base}/sticky/target`), { headers: extra, data: 'secret-ok' })).status()).toBe(201);

    const aliceName = 'alice' + randomUUID().replaceAll('-', '').slice(0, 8);
    const alicePassword = 'account-' + randomUUID();
    expect((await api(context.request, 'logout', { headers: extra })).ok()).toBe(true);
    await k('sync_account_from_server');
    const pGuest = await k('exec', sleepCmd);

    await call(context.request, 'getcreds');
    expect((await api(context.request, 'register', { headers: extra, data: { username: aliceName, password: alicePassword, create_home: false } })).ok()).toBe(true);
    await k('sync_account_from_server');
    const pAlice = await k('exec', sleepCmd);
    expect(await call(context.request, { symlink: { target: 'target', path: `${base}/sticky/link` } }, { headers: extra })).toBeNull();

    expect(await kErr('proc_openat', { pid: pGuest.pid, dirfd: ROOT_FD, path: `${base}/blocked/../ok`, oflags: 0, mode: 0 })).toBe('EACCES');
    expect(await kErr('proc_openat', { pid: pGuest.pid, dirfd: ROOT_FD, path: `${base}/sticky/link`, oflags: 0, mode: 0 })).toBe('EACCES');

    const aliceOpen = await k('proc_openat', { pid: pAlice.pid, dirfd: ROOT_FD, path: `${base}/sticky/link`, oflags: 0, mode: 0 });
    expect(Buffer.from(await k('kfd_pread', { pid: pAlice.pid, kfd: aliceOpen.kfd, len: 16, offset: '0' })).toString()).toBe('secret-ok');
    await k('kfd_close', { pid: pAlice.pid, kfd: aliceOpen.kfd });

    const beforeReconnect = await k('proc_openat', { pid: pAlice.pid, dirfd: ROOT_FD, path: `${base}/ok`, oflags: 0, mode: 0 });
    let dropRenew = true;
    let reconnectConnects = 0;
    const dropOnce = async route => {
      const post = route.request().postData();
      if (dropRenew && post?.includes('"renew"')) {
        dropRenew = false;
        await route.fulfill({ status: 410, contentType: 'application/json', body: JSON.stringify({ errno: 'ENOTCONN' }) });
        return;
      }
      if (!dropRenew && post?.includes('"connect"')) reconnectConnects++;
      await route.continue();
    };
    await context.route('**/api/fs', dropOnce);
    expect(await kErr('cloud_renew')).toBe('ENOTCONN');
    const afterReconnect = await k('proc_openat', { pid: pAlice.pid, dirfd: ROOT_FD, path: `${base}/ok`, oflags: 0, mode: 0 });
    await context.unroute('**/api/fs', dropOnce);
    expect(reconnectConnects).toBe(1);
    expect(afterReconnect.kfd).toBeGreaterThan(beforeReconnect.kfd);
    expect(Buffer.from(await k('kfd_pread', { pid: pAlice.pid, kfd: afterReconnect.kfd, len: 16, offset: '0' })).toString()).toBe('ok');
    await k('kfd_close', { pid: pAlice.pid, kfd: beforeReconnect.kfd });
    await k('kfd_close', { pid: pAlice.pid, kfd: afterReconnect.kfd });

    await k('exit', { pid: pAlice.pid, status: 0 });
    await k('wait', { pid: pAlice.pid });
    await k('exit', { pid: pGuest.pid, status: 0 });
    // Non-root Alice cannot reap another account's (guest's) zombie process; root (or PID 1) can.
    expect(await kErr('wait', { pid: pGuest.pid })).toBe('EPERM');
    expect((await api(context.request, 'login', { headers: extra, data: { password } })).ok()).toBe(true);
    await k('sync_account_from_server');
    const rootWait = await page.evaluate(pid => window.__kernel('wait', { pid }), pGuest.pid);
    expect(rootWait.ok != null || rootWait.err?.errno === 'ECHILD').toBe(true);
  } finally {
    await rmrf(request, base);
  }
});

test('WASI and WASIX processes use CloudFs for dev/ino/nlink==0, SEEK_END, O_APPEND, fsync/EBADF/EINVAL and fork/exec', async ({ context, page, request }) => {
  const binaryen = (await import('binaryen')).default;
  const assemble = wat => Buffer.from(binaryen.parseText(wat).emitBinary());
  const ip = 'cloudfs-wasi-' + randomUUID();
  const extra = { Origin: origin, 'CF-Connecting-IP': ip };
  await context.setExtraHTTPHeaders({ 'CF-Connecting-IP': ip });
  expect((await api(request, 'login', { headers: extra, data: { password } })).ok()).toBe(true);
  expect((await api(context.request, 'login', { headers: extra, data: { password } })).ok()).toBe(true);

  const base = '/cloudfs-wasi-' + randomUUID();
  await mkdirp(request, base, 0o755);
  const rel = base.slice(1);
  const upload = async (name, data) => {
    expect((await put(request, '/api/file?path=' + encodeURIComponent(`${base}/${name}`), { headers: extra, data })).status()).toBe(201);
    expect(await call(request, { chmod: { path: `${base}/${name}`, mode: 0o755 } }, { headers: extra })).toBeNull();
  };

  // Probe 1: WASI preview1 CloudFs lifecycle & fsync/SEEK_END/O_APPEND/unlinked-fstat checks.
  const WASI_PROBE = assemble(`(module
    (import "wasi_snapshot_preview1" "args_sizes_get" (func $args_sizes (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "args_get" (func $args_get (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "path_open" (func $open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_pread" (func $pread (param i32 i32 i32 i64 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_seek" (func $seek (param i32 i64 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_tell" (func $tell (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_sync" (func $sync (param i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_datasync" (func $datasync (param i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_fdstat_get" (func $fdstat_get (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_fdstat_set_flags" (func $fdstat_set (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_filestat_get" (func $fstat (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "path_filestat_get" (func $pstat (param i32 i32 i32 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "path_unlink_file" (func $unlink (param i32 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_filestat_set_size" (func $trunc (param i32 i64) (result i32)))
    (import "wasi_snapshot_preview1" "fd_close" (func $close (param i32) (result i32)))
    (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
    (memory (export "memory") 2)
    (data (i32.const 1000) "hello")
    (data (i32.const 1008) "world")
    (func $check (param $ok i32) (param $code i32)
      (if (i32.eqz (local.get $ok)) (then (call $exit (local.get $code)))))
    (func $cstrlen (param $p i32) (result i32)
      (local $n i32)
      (block $done (loop $loop
        (br_if $done (i32.eqz (i32.load8_u (i32.add (local.get $p) (local.get $n)))))
        (local.set $n (i32.add (local.get $n) (i32.const 1)))
        (br $loop)))
      (local.get $n))
    (func (export "_start")
      (local $p i32) (local $plen i32) (local $fd i32)
      (local $dev i64) (local $ino i64)
      (drop (call $args_sizes (i32.const 2000) (i32.const 2004)))
      (drop (call $args_get (i32.const 2016) (i32.const 8192)))
      (local.set $p (i32.load (i32.const 2020)))
      (local.set $plen (call $cstrlen (local.get $p)))
      (call $check (i32.eqz (call $open (i32.const 3) (i32.const 1) (local.get $p) (local.get $plen) (i32.const 1) (i64.const 0x3fffffff) (i64.const 0x3fffffff) (i32.const 0) (i32.const 2200))) (i32.const 1))
      (local.set $fd (i32.load (i32.const 2200)))
      (i32.store (i32.const 2208) (i32.const 1000))
      (i32.store (i32.const 2212) (i32.const 5))
      (call $check (i32.eqz (call $write (local.get $fd) (i32.const 2208) (i32.const 1) (i32.const 2204))) (i32.const 2))
      (call $check (i32.eq (i32.load (i32.const 2204)) (i32.const 5)) (i32.const 3))
      (call $check (i32.eqz (call $sync (local.get $fd))) (i32.const 4))
      (call $check (i32.eqz (call $datasync (local.get $fd))) (i32.const 5))
      (call $check (i32.eqz (call $sync (i32.const 3))) (i32.const 6))
      (call $check (i32.eq (call $sync (i32.const 999)) (i32.const 8)) (i32.const 7))
      (call $check (i32.eq (call $datasync (i32.const 1)) (i32.const 28)) (i32.const 8))
      (call $check (i32.eqz (call $seek (local.get $fd) (i64.const 0) (i32.const 2) (i32.const 2216))) (i32.const 9))
      (call $check (i64.eq (i64.load (i32.const 2216)) (i64.const 5)) (i32.const 10))
      (call $check (i32.eqz (call $fdstat_set (local.get $fd) (i32.const 1))) (i32.const 11))
      (call $check (i32.eqz (call $fdstat_get (local.get $fd) (i32.const 2224))) (i32.const 12))
      (call $check (i32.eq (i32.and (i32.load16_u (i32.const 2226)) (i32.const 1)) (i32.const 1)) (i32.const 13))
      (call $check (i32.eqz (call $seek (local.get $fd) (i64.const 0) (i32.const 0) (i32.const 2216))) (i32.const 14))
      (i32.store (i32.const 2208) (i32.const 1008))
      (i32.store (i32.const 2212) (i32.const 5))
      (call $check (i32.eqz (call $write (local.get $fd) (i32.const 2208) (i32.const 1) (i32.const 2204))) (i32.const 15))
      (call $check (i32.eqz (call $tell (local.get $fd) (i32.const 2216))) (i32.const 16))
      (call $check (i64.eq (i64.load (i32.const 2216)) (i64.const 10)) (i32.const 17))
      (call $check (i32.eqz (call $fstat (local.get $fd) (i32.const 3000))) (i32.const 18))
      (call $check (i32.eqz (call $pstat (i32.const 3) (i32.const 1) (local.get $p) (local.get $plen) (i32.const 3100))) (i32.const 19))
      (local.set $dev (i64.load (i32.const 3000)))
      (local.set $ino (i64.load (i32.const 3008)))
      (call $check (i64.gt_u (local.get $dev) (i64.const 0)) (i32.const 20))
      (call $check (i64.gt_u (local.get $ino) (i64.const 0)) (i32.const 21))
      (call $check (i64.eq (local.get $dev) (i64.load (i32.const 3100))) (i32.const 22))
      (call $check (i64.eq (local.get $ino) (i64.load (i32.const 3108))) (i32.const 23))
      (call $check (i64.eq (i64.load (i32.const 3024)) (i64.const 1)) (i32.const 24))
      (call $check (i64.eq (i64.load (i32.const 3032)) (i64.const 10)) (i32.const 25))
      (call $check (i32.eqz (call $unlink (i32.const 3) (local.get $p) (local.get $plen))) (i32.const 26))
      (call $check (i32.eqz (call $fstat (local.get $fd) (i32.const 3200))) (i32.const 27))
      (call $check (i64.eq (i64.load (i32.const 3200)) (local.get $dev)) (i32.const 28))
      (call $check (i64.eq (i64.load (i32.const 3208)) (local.get $ino)) (i32.const 29))
      (call $check (i64.eq (i64.load (i32.const 3224)) (i64.const 0)) (i32.const 30))
      (call $check (i32.eqz (call $trunc (local.get $fd) (i64.const 4))) (i32.const 31))
      (call $check (i32.eqz (call $seek (local.get $fd) (i64.const 0) (i32.const 2) (i32.const 2216))) (i32.const 32))
      (call $check (i64.eq (i64.load (i32.const 2216)) (i64.const 4)) (i32.const 33))
      (i32.store (i32.const 2208) (i32.const 4000))
      (i32.store (i32.const 2212) (i32.const 10))
      (call $check (i32.eqz (call $pread (local.get $fd) (i32.const 2208) (i32.const 1) (i64.const 0) (i32.const 2204))) (i32.const 34))
      (call $check (i32.eq (i32.load (i32.const 2204)) (i32.const 4)) (i32.const 35))
      (i32.store (i32.const 2212) (i32.const 4))
      (drop (call $write (i32.const 1) (i32.const 2208) (i32.const 1) (i32.const 2204)))
      (call $check (i32.eqz (call $close (local.get $fd))) (i32.const 36))
      (call $exit (i32.const 0))))`);

  // Probe 2: WASIX fork + CLOEXEC + exec replacement retaining fd 4 + pipe fd_sync EINVAL.
  const CHILD_EXEC = assemble(`(module
    (import "wasix_32v1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
    (import "wasix_32v1" "fd_sync" (func $sync (param i32) (result i32)))
    (import "wasix_32v1" "proc_exit" (func $exit (param i32)))
    (memory (export "memory") 1)
    (data (i32.const 1000) "exec")
    (func (export "_start")
      (if (call $sync (i32.const 5)) (then) (else (call $exit (i32.const 90))))
      (i32.store (i32.const 1024) (i32.const 1000))
      (i32.store (i32.const 1028) (i32.const 4))
      (if (call $write (i32.const 4) (i32.const 1024) (i32.const 1) (i32.const 1032)) (then (call $exit (i32.const 91))))
      (if (call $sync (i32.const 4)) (then (call $exit (i32.const 92))))
      (call $exit (i32.const 0))))`);

  const FORK_PROBE = assemble(`(module
    (import "wasix_32v1" "args_sizes_get" (func $args_sizes (param i32 i32) (result i32)))
    (import "wasix_32v1" "args_get" (func $args_get (param i32 i32) (result i32)))
    (import "wasix_32v1" "path_open" (func $open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
    (import "wasix_32v1" "path_open2" (func $open2 (param i32 i32 i32 i32 i32 i64 i64 i32 i32 i32) (result i32)))
    (import "wasix_32v1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
    (import "wasix_32v1" "fd_pread" (func $pread (param i32 i32 i32 i64 i32) (result i32)))
    (import "wasix_32v1" "fd_seek" (func $seek (param i32 i64 i32 i32) (result i32)))
    (import "wasix_32v1" "fd_sync" (func $sync (param i32) (result i32)))
    (import "wasix_32v1" "fd_pipe" (func $pipe (param i32 i32) (result i32)))
    (import "wasix_32v1" "fd_close" (func $close (param i32) (result i32)))
    (import "wasix_32v1" "proc_fork" (func $fork (param i32 i32) (result i32)))
    (import "wasix_32v1" "proc_join" (func $join (param i32 i32 i32) (result i32)))
    (import "wasix_32v1" "proc_exec" (func $exec (param i32 i32 i32 i32)))
    (import "wasix_32v1" "proc_exit" (func $exit (param i32)))
    (memory (export "memory") 2)
    (global $sp (mut i32) (i32.const 65536))
    (export "__stack_pointer" (global $sp))
    (data (i32.const 1000) "child:")
    (func $check (param $ok i32) (param $code i32)
      (if (i32.eqz (local.get $ok)) (then (call $exit (local.get $code)))))
    (func $cstrlen (param $p i32) (result i32)
      (local $n i32)
      (block $done (loop $loop
        (br_if $done (i32.eqz (i32.load8_u (i32.add (local.get $p) (local.get $n)))))
        (local.set $n (i32.add (local.get $n) (i32.const 1)))
        (br $loop)))
      (local.get $n))
    (func (export "_start")
      (local $p1 i32) (local $l1 i32) (local $p2 i32) (local $l2 i32) (local $p3 i32) (local $l3 i32)
      (local $sfd i32) (local $cfd i32)
      (drop (call $args_sizes (i32.const 2000) (i32.const 2004)))
      (drop (call $args_get (i32.const 2016) (i32.const 8192)))
      (local.set $p1 (i32.load (i32.const 2020))) (local.set $l1 (call $cstrlen (local.get $p1)))
      (local.set $p2 (i32.load (i32.const 2024))) (local.set $l2 (call $cstrlen (local.get $p2)))
      (local.set $p3 (i32.load (i32.const 2028))) (local.set $l3 (call $cstrlen (local.get $p3)))
      (call $check (i32.eqz (call $open (i32.const 3) (i32.const 1) (local.get $p1) (local.get $l1) (i32.const 1) (i64.const 0x3fffffff) (i64.const 0x3fffffff) (i32.const 0) (i32.const 2200))) (i32.const 1))
      (local.set $sfd (i32.load (i32.const 2200)))
      (call $check (i32.eq (local.get $sfd) (i32.const 4)) (i32.const 2))
      (call $check (i32.eqz (call $open2 (i32.const 3) (i32.const 1) (local.get $p2) (local.get $l2) (i32.const 1) (i64.const 0x3fffffff) (i64.const 0x3fffffff) (i32.const 0) (i32.const 1) (i32.const 2200))) (i32.const 3))
      (local.set $cfd (i32.load (i32.const 2200)))
      (call $check (i32.eq (local.get $cfd) (i32.const 5)) (i32.const 4))
      (call $check (i32.eqz (call $pipe (i32.const 2300) (i32.const 2304))) (i32.const 5))
      (call $check (i32.eq (call $sync (i32.load (i32.const 2304))) (i32.const 28)) (i32.const 6))
      (drop (call $close (i32.load (i32.const 2300))))
      (drop (call $close (i32.load (i32.const 2304))))
      (call $check (i32.eqz (call $fork (i32.const 1) (i32.const 2060))) (i32.const 7))
      (if (i32.eqz (i32.load (i32.const 2060)))
        (then
          (i32.store (i32.const 2208) (i32.const 1000))
          (i32.store (i32.const 2212) (i32.const 6))
          (call $check (i32.eqz (call $write (local.get $sfd) (i32.const 2208) (i32.const 1) (i32.const 2204))) (i32.const 8))
          (call $exec (local.get $p3) (local.get $l3) (local.get $p3) (local.get $l3))
          (call $exit (i32.const 9))))
      (drop (call $close (local.get $cfd)))
      (i32.store8 (i32.const 2064) (i32.const 1))
      (i32.store (i32.const 2068) (i32.load (i32.const 2060)))
      (drop (call $join (i32.const 2064) (i32.const 0) (i32.const 2080)))
      (call $check (i32.and (i32.eq (i32.load8_u (i32.const 2080)) (i32.const 1)) (i32.eqz (i32.load16_u (i32.const 2082)))) (i32.const 10))
      (call $check (i32.eqz (call $seek (local.get $sfd) (i64.const 0) (i32.const 2) (i32.const 2216))) (i32.const 11))
      (call $check (i64.eq (i64.load (i32.const 2216)) (i64.const 10)) (i32.const 12))
      (i32.store (i32.const 2208) (i32.const 4000))
      (i32.store (i32.const 2212) (i32.const 10))
      (call $check (i32.eqz (call $pread (local.get $sfd) (i32.const 2208) (i32.const 1) (i64.const 0) (i32.const 2204))) (i32.const 13))
      (call $check (i32.eq (i32.load (i32.const 2204)) (i32.const 10)) (i32.const 14))
      (drop (call $write (i32.const 1) (i32.const 2208) (i32.const 1) (i32.const 2204)))
      (drop (call $close (local.get $sfd)))
      (call $exit (i32.const 0))))`);

  const SHARED_IO_PROBE = assemble(`(module
    (import "wasix_32v1" "args_sizes_get" (func $args_sizes (param i32 i32) (result i32)))
    (import "wasix_32v1" "args_get" (func $args_get (param i32 i32) (result i32)))
    (import "wasix_32v1" "path_open" (func $open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
    (import "wasix_32v1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
    (import "wasix_32v1" "fd_close" (func $close (param i32) (result i32)))
    (import "wasix_32v1" "proc_fork" (func $fork (param i32 i32) (result i32)))
    (import "wasix_32v1" "proc_join" (func $join (param i32 i32 i32) (result i32)))
    (import "wasix_32v1" "proc_exit" (func $exit (param i32)))
    (memory (export "memory") 16)
    (global $sp (mut i32) (i32.const 65536))
    (export "__stack_pointer" (global $sp))
    (func $check (param $ok i32) (param $code i32)
      (if (i32.eqz (local.get $ok)) (then (call $exit (local.get $code)))))
    (func $cstrlen (param $p i32) (result i32)
      (local $n i32)
      (block $done (loop $loop
        (br_if $done (i32.eqz (i32.load8_u (i32.add (local.get $p) (local.get $n)))))
        (local.set $n (i32.add (local.get $n) (i32.const 1)))
        (br $loop)))
      (local.get $n))
    (func $fill (param $word i32)
      (local $i i32)
      (loop $fill_loop
        (i32.store (i32.add (i32.const 65536) (local.get $i)) (local.get $word))
        (local.set $i (i32.add (local.get $i) (i32.const 4)))
        (br_if $fill_loop (i32.lt_u (local.get $i) (i32.const 614400)))))
    (func (export "_start")
      (local $p i32) (local $plen i32) (local $sfd i32)
      (drop (call $args_sizes (i32.const 2000) (i32.const 2004)))
      (drop (call $args_get (i32.const 2016) (i32.const 8192)))
      (local.set $p (i32.load (i32.const 2020)))
      (local.set $plen (call $cstrlen (local.get $p)))
      (call $check (i32.eqz (call $open (i32.const 3) (i32.const 1) (local.get $p) (local.get $plen) (i32.const 1) (i64.const 0x3fffffff) (i64.const 0x3fffffff) (i32.const 0) (i32.const 2200))) (i32.const 1))
      (local.set $sfd (i32.load (i32.const 2200)))
      (call $check (i32.eqz (call $fork (i32.const 1) (i32.const 2060))) (i32.const 2))
      (if (i32.eqz (i32.load (i32.const 2060)))
        (then
          (call $fill (i32.const 0x43434343))
          (i32.store (i32.const 2208) (i32.const 65536))
          (i32.store (i32.const 2212) (i32.const 614400))
          (call $check (i32.eqz (call $write (local.get $sfd) (i32.const 2208) (i32.const 1) (i32.const 2204))) (i32.const 3))
          (call $check (i32.eq (i32.load (i32.const 2204)) (i32.const 614400)) (i32.const 4))
          (drop (call $close (local.get $sfd)))
          (call $exit (i32.const 0))))
      (call $fill (i32.const 0x50505050))
      (i32.store (i32.const 2208) (i32.const 65536))
      (i32.store (i32.const 2212) (i32.const 614400))
      (call $check (i32.eqz (call $write (local.get $sfd) (i32.const 2208) (i32.const 1) (i32.const 2204))) (i32.const 5))
      (call $check (i32.eq (i32.load (i32.const 2204)) (i32.const 614400)) (i32.const 6))
      (i32.store8 (i32.const 2064) (i32.const 1))
      (i32.store (i32.const 2068) (i32.load (i32.const 2060)))
      (drop (call $join (i32.const 2064) (i32.const 0) (i32.const 2080)))
      (call $check (i32.and (i32.eq (i32.load8_u (i32.const 2080)) (i32.const 1)) (i32.eqz (i32.load16_u (i32.const 2082)))) (i32.const 7))
      (drop (call $close (local.get $sfd)))
      (call $exit (i32.const 0))))`);

  try {
    await upload('wasi-probe', WASI_PROBE);
    await upload('child-writer', CHILD_EXEC);
    await upload('fork-probe', FORK_PROBE);
    await upload('shared-io-probe', SHARED_IO_PROBE);
    await page.goto('/');
    const input = page.getByRole('combobox', { name: 'Terminal command' });
    const busy = page.locator('#command').locator('xpath=ancestor::form');
    const run = async text => {
      await expect(busy).toHaveAttribute('data-state', 'idle');
      await input.fill(text);
      await input.press('Enter');
      await expect(busy).toHaveAttribute('data-state', 'idle', { timeout: 30_000 });
    };
    await expect(busy).toHaveAttribute('data-state', 'idle');
    await run(`sh -c '${base}/wasi-probe ${rel}/probe.txt; printf probe=%d $?'`);
    await expect(page.locator('.transcript pre').last()).toHaveText('hellprobe=0');
    const [afterUnlink] = await sys(request, [{ stat: { path: `${base}/probe.txt` } }], {}, extra);
    expect(afterUnlink.err?.errno).toBe('ENOENT');

    await run(`sh -c '${base}/fork-probe ${rel}/shared.txt ${rel}/clo.txt ${base}/child-writer; printf fork=%d $?'`);
    await expect(page.locator('.transcript pre').last()).toHaveText('child:execfork=0');

    await run(`sh -c '${base}/shared-io-probe ${rel}/shared-big.bin; printf io=%d $?'`);
    await expect(page.locator('.transcript pre').last()).toHaveText('io=0');
    const bigRes = await request.get(origin + '/api/file?path=' + encodeURIComponent(`${base}/shared-big.bin`), { headers: extra });
    expect(bigRes.ok()).toBe(true);
    const bigBuf = await bigRes.body();
    expect(bigBuf.length).toBe(1228800);
    const firstByte = bigBuf[0];
    const secondByte = bigBuf[614400];
    expect([0x43, 0x50]).toContain(firstByte);
    expect(secondByte).toBe(firstByte === 0x43 ? 0x50 : 0x43);
    expect(bigBuf.subarray(0, 614400).every(b => b === firstByte)).toBe(true);
    expect(bigBuf.subarray(614400).every(b => b === secondByte)).toBe(true);
  } finally {
    await rmrf(request, base);
  }
});

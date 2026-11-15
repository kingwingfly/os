import { test, expect, request as contexts } from './test.js';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { api, call, put, sys } from './sys.js';
const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const password = process.env.OS_PASSWORD || readFileSync('.local-password', 'utf8').trim();
const options = (access='read-write', extra={}) => ({read:access==='read'||access==='read-write',write:access==='write'||access==='read-write',append:false,append_implies_write:false,truncate:false,create:false,create_new:false,exec:access==='exec',path:access==='path',...extra});
const attrs = extra => ({mode:null,uid:null,gid:null,size:null,atime:'omit',mtime:'omit',...extra});
async function admit(request) { return call(request,{execve:{path:'/usr/bin/coreutils',argv:['coreutils','sleep','300'],env:[],cwd:'/'}}); }
async function rpc(request,credential,session,call,errno,version=2) {
  const response=await request.post(origin+'/api/fs',{headers:{Origin:origin},data:{version,credential,session,call}});const body=await response.json();
  if(errno){expect(body.errno,JSON.stringify(body)).toBe(errno);return body;}
  expect(response.ok(),JSON.stringify(body)).toBe(true);return body;
}
async function connection(request,{token,pid}) {
  const c={...await rpc(request,token,null,'connect'),request,token,pid};
  c.call=(op,args,errno)=>rpc(request,token,c.session,args===undefined?op:{[op]:args},errno);
  c.data=async(open,operation,bytes,errno)=>{
    const response=await request.post(origin+'/api/fs/data',{headers:{Origin:origin,'X-OS-Filesystem':JSON.stringify({version:2,credential:c.token,pid:c.pid,session:c.session,open,operation})},data:bytes??Buffer.alloc(0)});
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
  await call(request,'getcreds');expect((await api(request,'login',{data:{username:'root',password}})).ok()).toBe(true);
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
  await c.call('unlink',{dir,name:'renamed'});expect((await c.call('metadata',{handle:entry.handle})).nlink).toBe(0);expect((await c.read(open)).length).toBe(7);
  await c.call('release',{open});await c.call('release',{open:ro});await c.call('metadata',{handle:entry.handle},'ESTALE');
  const sub=await c.call('mkdir',{dir,name:'cwd',mode:0});const path=await c.open(sub.handle,'path');await c.call('rmdir',{dir,name:'cwd'});
  expect((await c.call('metadata',{handle:sub.handle})).nlink).toBe(0);await c.call('parent',{dir:sub.handle},'ENOENT');await c.call('read_dir',{dir:sub.handle},'ENOENT');
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
  await call(request,{kill:{pid:String(p.pid),signal:9}});
  await rpc(request,observer.token,c.session,{sync:{open,data_only:false}},'EACCES');
  await rpc(request,observer.token,c.session,{metadata:{handle:entry.handle}},'ESTALE');
  await rpc(request,observer.token,c.session,'disconnect');
});
test('lease expiry releases references while an independently renewed session remains usable',async({request})=>{
  test.setTimeout(180000);
  const {c,dir,p}=await setup(request);const other=await connection(request,c);
  const [entry,open]=await c.create(dir,'expire');await c.write(open,'lease');
  const dirName=(await c.call('parent',{dir}))[1];const otherDir=(await other.call('lookup',{dir:other.root,name:dirName})).handle;
  const observed=(await other.call('lookup',{dir:otherDir,name:'expire'})).handle;await c.call('unlink',{dir,name:'expire'});
  for(let i=0;i<5;i++){await new Promise(r=>setTimeout(r,25000));expect((await sys(request,[{proc_keep:{processes:[{pid:p.pid,proc:p.token}]}}],{}, {"X-Registry":"1"}))[0].err).toBeUndefined();await other.call('renew');}
  await other.call('metadata',{handle:observed},'ESTALE');await c.call('renew',undefined,'ENOTCONN');await other.call('disconnect');
});
test('signed 64-bit offsets retain precision across SQLite and the Worker gateway',async({request})=>{
  const {c,dir}=await setup(request);const [entry,open]=await c.create(dir,'large');
  const data={version:2,credential:c.token,pid:c.pid,session:c.session,open,operation:{write:{at:{offset:'LARGE_OFFSET'},length:1}}};
  const response=await request.post(origin+'/api/fs/data',{headers:{Origin:origin,'X-OS-Filesystem':JSON.stringify(data).replace('"LARGE_OFFSET"','9223372036854775806')},data:Buffer.from('x')});
  expect(response.ok(),response.ok()?'':await response.text()).toBe(true);
  expect(await response.text()).toContain('9223372036854775806');
  const meta=await request.post(origin+'/api/fs',{headers:{Origin:origin},data:{version:2,credential:c.token,session:c.session,call:{metadata:{handle:entry.handle}}}});
  expect(meta.ok()).toBe(true);expect(await meta.text()).toContain('"size":9223372036854775807');
  data.operation={read:{offset:'LARGE_OFFSET',length:1}};
  const read=await request.post(origin+'/api/fs/data',{headers:{Origin:origin,'X-OS-Filesystem':JSON.stringify(data).replace('"LARGE_OFFSET"','9223372036854775806')},data:Buffer.alloc(0)});
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
  await call(request,{kill:{pid:String(p.pid),signal:9}});
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
  await call(request,{cgroup_create:{path:group}});await call(request,{cgroup_attach:{pid:p.pid,path:group}});
  const baseline=(await c.call('statfs')).blocks;const [entry,open]=await c.create(dir,'denied');
  try{
    await c.write(open,Buffer.alloc(4096,42));expect((await c.call('statfs')).blocks).toBe(baseline+1);
    await call(request,{cgroup_set:{path:group,key:'io.max',value:'rbps=0'}});
    for(let i=0;i<3;i++)await c.data(open,{read:{offset:0,length:4096}},undefined,'EAGAIN');
    await c.call('unlink',{dir,name:'denied'});await c.call('release',{open});
    await c.call('metadata',{handle:entry.handle},'ESTALE');
    expect((await c.call('statfs')).blocks).toBe(baseline);
    await c.call('renew');expect((await c.call('statfs')).blocks).toBe(baseline);
  }finally{
    await c.call('disconnect');await call(request,{cgroup_attach:{pid:p.pid,path:'/user'}});
    await call(request,{cgroup_remove:{path:group}});
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
  const child={...await call(request,{fork:{pid:p.pid}},{pid:p.pid,proc:p.token}),token:p.token};
  const end=process=>sys(request,[{exit:{pid:process.pid,proc:process.token,status:0}},{wait:{pid:String(process.pid),proc:process.token}}],{}, {'X-Registry':'1'});
  await call(request,{cgroup_create:{path:group}});await call(request,{cgroup_attach:{pid:child.pid,path:group}});
  try{
    const [,open]=await c.create(dir,'fork');await c.write(open,'parent');
    await call(request,{cgroup_set:{path:group,key:'io.max',value:'rbps=0 wbps=0'}});
    c.pid=child.pid;
    await c.data(open,{write:{at:'end',length:1}},Buffer.from('!'),'EAGAIN');
    await c.data(open,{read:{offset:0,length:6}},undefined,'EAGAIN');
    const usage=(await call(request,{cgroup_stat:{path:group}}))['io.stat'];
    expect([usage.read_bytes,usage.write_bytes]).toEqual([0,0]);
    await end(p);await call(request,{cgroup_set:{path:group,key:'io.max',value:'max'}});
    expect((await c.read(open)).toString()).toBe('parent');await c.write(open,' child');
    expect((await c.read(open)).toString()).toBe('parent child');
    const unrelated=await admit(request);
    for(const pid of [p.pid,unrelated.pid,0]){
      c.pid=pid;await c.data(open,{read:{offset:0,length:1}},undefined,'EPERM');
      await c.data(open,{write:{at:'end',length:0}},undefined,'EPERM');
    }
    c.pid=null;await c.data(open,{read:{offset:0,length:1}},undefined,'EINVAL');
    c.pid=child.pid;await c.call('unlink',{dir,name:'fork'});await c.call('release',{open});await end(unrelated);
  }finally{await c.call('disconnect');await end(child);await end(p);await call(request,{cgroup_remove:{path:group}});}
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

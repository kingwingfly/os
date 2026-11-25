import { test, expect } from './test.js';
import { readFile } from 'node:fs/promises';
import { randomBytes, randomUUID } from 'node:crypto';
import { api, call, errno, mkdirp, put, rmrf } from './sys.js';
import { cloudSignIn } from './ui.js';
import { connectKernel } from './service-auth.js';
import { device, directory, ACCEL } from './accelerator.js';
import { zipOf } from './archive-fixtures.js';
const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const password=process.env.OS_TEST_ADMIN_PASSWORD || process.env.OS_PASSWORD || (await readFile('.dev.vars','utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const ROOT_ACCOUNT={uid:0,gid:0,groups:[0],user:'root',group:'root',home:'/root',shell:'/usr/bin/dash',signed_in:true};
const GUEST_ACCOUNT={uid:65534,gid:65534,groups:[65534],user:'guest',group:'guest',home:'/tmp',shell:'/usr/bin/dash',signed_in:false};
async function login(r) { expect((await api(r,'login',{headers:{'CF-Connecting-IP':'policy-'+randomUUID()},data:{password}})).ok()).toBe(true); }
async function freshKernel(page, name='__policyKernel') {
  await page.goto('/login');
  const kernel=await connectKernel(page,{name});
  await kernel.value('login_leave');
  await kernel.value('machine_init_leave');
  return kernel;
}
const action=(kernel,act)=>kernel.call('login_session_action',{action:act});
async function join(kernel) {
  const answer=await action(kernel,{op:'join',host:randomUUID(),proof:randomBytes(32).toString('hex')});
  expect(answer.err,JSON.stringify(answer)).toBeUndefined();return answer.ok;
}
const configure=(kernel,session,sharing,expected=session.seat_policy.revision)=>action(kernel,{op:'seat_policy',session:session.id,expected,sharing});

test('seat policy persists across logins and rejects stale, process, sudo and foreign session updates',async({page,browser})=>{
  const r=page.request;
  await call(r,'getcreds');
  const kernel=await freshKernel(page);
  let p;
  try {
    await kernel.value('sync_account',GUEST_ACCOUNT);
    const session=await join(kernel), initial=session.seat_policy;
    expect(initial.sharing).toBe('control');
    const changed=await configure(kernel,session,'view');expect(changed.err).toBeUndefined();
    expect(changed.ok.seat_policy).toEqual({revision:initial.revision+1,sharing:'view'});
    expect((await configure(kernel,session,'none')).err?.errno).toBe('ESTALE');
    p=await kernel.value('exec',{path:'/usr/bin/sleep',argv:['sleep','10'],cwd:'/',env:[]});
    const operation={op:'seat_policy',session:session.id,expected:initial.revision+1,sharing:'none'};
    // Process calls and retired server /api/sys routes (process token or sudo) cannot mutate seat policy.
    expect((await kernel.call('process_call',{pid:p.pid,call:{login_session:{action:operation}}})).err).toBeTruthy();
    for(const options of [{pid:p.pid,proc:p.token||randomBytes(32).toString('hex')},{sudo:true}]) {
      const res=await r.post(origin+'/api/sys',{headers:{Origin:origin,'Content-Type':'application/json'},data:{calls:[{login_session:{action:operation}}],...options}});
      expect(res.ok()).toBe(false);
    }
    const foreign=await browser.newContext();
    try {
      const foreignPage=await foreign.newPage();
      const foreignKernel=await freshKernel(foreignPage,'__policyForeignKernel');
      try {
        await join(foreignKernel);
        expect((await action(foreignKernel,operation)).err?.errno).toBe('ESTALE');
      }finally{await foreignKernel.terminate();}
    }finally{await foreign.close();}
    await kernel.value('sync_account',ROOT_ACCOUNT);
    const root=await join(kernel);expect(root.seat_policy.sharing).toBe('control');
    await kernel.value('sync_account',GUEST_ACCOUNT);
    const next=await join(kernel);
    expect(next.seat_policy).toEqual(changed.ok.seat_policy);
    expect((await configure(kernel,next,'control')).err).toBeUndefined();
  }finally{
    if(p){await kernel.call('exit',{pid:p.pid,status:0});await kernel.call('wait',{pid:p.pid});}
    await kernel.terminate();
  }
});

test('seat sharing policy revokes live console control and remains saved after reload',async({page})=>{
  await page.goto('/?recovery=1');
  await page.waitForFunction(()=>!!window.os?.configureSeatSharing&&!!window.os?.grantConsole&&!!window.os?.exec);
  await expect.poll(()=>page.evaluate(async()=>(await window.os.loginSession()).connected)).toBe(true);
  await page.evaluate(()=>window.os.configureSeatSharing('control'));
  let peer;
  try {
    await page.evaluate(()=>{
      const run={output:''};window.policyRun=run;
      run.done=window.os.exec([{path:'/usr/bin/coreutils',argv:['coreutils','cat']}],{
        terminalId:'policy-share',tty:true,
        onOutput:(_,text)=>{run.output=(run.output+text).slice(-65536);},
        onTty:input=>{run.input=input;},
        onJob:group=>{run.group=group;},
      }).then(result=>{run.result=result;});
    });
    await expect.poll(()=>page.evaluate(()=>!!window.policyRun.input&&window.policyRun.group?.pids.length>0),{timeout:60000}).toBe(true);

    const [popup]=await Promise.all([
      page.waitForEvent('popup'),
      page.evaluate(()=>{window.policyTarget=window.open('/?recovery=1');}),
    ]);
    peer=popup;
    await peer.waitForFunction(()=>!!window.os?.attachConsole);
    await peer.evaluate(()=>{
      window.policyPeer={output:'',closed:null,input:null};
      addEventListener('message',async event=>{
        if(event.source!==opener||event.origin!==location.origin||event.data!=='policy-port')return;
        window.policyPeer.peer=await window.os.attachConsole(event.ports[0],{
          onTty:input=>{window.policyPeer.input=input;},
          onOutput:(_,text)=>{window.policyPeer.output+=text;},
          onClose:error=>{window.policyPeer.closed=error||{errno:'CLOSED'};},
        });
      });
    });
    await page.evaluate(async()=>{
      const channel=new MessageChannel();
      window.policyGrant=await window.os.grantConsole('policy-share',channel.port1,{access:'control'});
      window.policyTarget.postMessage('policy-port',location.origin,[channel.port2]);
    });
    await expect.poll(()=>peer.evaluate(()=>!!window.policyPeer.input),{timeout:20000}).toBe(true);
    await peer.evaluate(()=>window.policyPeer.input.write('before-revoke\n'));
    await expect.poll(()=>page.evaluate(()=>window.policyRun.output.replace(/\r\n/g,'\n'))).toContain('before-revoke\nbefore-revoke');

    // Disabling seat sharing revokes live control grants and rejects new grants.
    await page.evaluate(()=>window.os.configureSeatSharing('none'));
    await expect.poll(()=>peer.evaluate(()=>!!window.policyPeer.closed&&window.policyPeer.input===null),{timeout:15000}).toBe(true);
    await expect.poll(()=>page.evaluate(()=>!!window.policyRun.input),{timeout:15000}).toBe(true);
    const denied=await page.evaluate(async()=>{
      const channel=new MessageChannel();
      try {
        await window.os.grantConsole('policy-share',channel.port1,{access:'control'});
        return null;
      } catch(error) {
        return error.errno||error.message||'rejected';
      } finally {
        channel.port1.close();channel.port2.close();
      }
    });
    expect(denied).toBeTruthy();

    await page.evaluate(async()=>{window.policyRun?.group?.signal(9);await window.policyRun?.done;});
    await page.reload();
    await page.waitForFunction(()=>!!window.os?.configureSeatSharing);
    await expect.poll(()=>page.evaluate(async()=>(await window.os.loginSession()).session?.seat_policy?.sharing)).toBe('none');
  } finally {
    await page.evaluate(async()=>{
      window.policyRun?.group?.signal(9);
      await window.policyRun?.done;
      await window.os?.configureSeatSharing?.('control');
    }).catch(()=>{});
    if(peer)await peer.close().catch(()=>{});
  }
});

test('provider policy is account scoped, revision checked and available through the installed CLI',async({page,browser})=>{
  const r=page.request;await login(r);const driver=await device(r),before=await driver.ioctl('policy',{});
  try {
    const desired={...before,enabled:false,detached:false,max_active:2,max_seconds:30};
    const changed=await driver.ioctl('configure',desired);expect(changed.revision).toBe(before.revision+1);
    expect(await errno(r,{ioctl:{fd:driver.fd,request:ACCEL.configure,arg:desired}})).toBe('ESTALE');
    expect(await errno(r,{ioctl:{fd:driver.fd,request:ACCEL.configure,arg:{...changed,uid:0}}})).toBe('EINVAL');
    const media=await device(r,'/dev/media');expect(await media.ioctl('policy',{})).toEqual(changed);await call(r,{close:{fd:media.fd}});
    const foreign=await browser.newContext();
    try {await call(foreign.request,'getcreds');const guest=await device(foreign.request);expect((await guest.ioctl('policy',{})).enabled).toBe(true);await call(foreign.request,{close:{fd:guest.fd}});}finally{await foreign.close();}
    await call(r,{close:{fd:driver.fd}});
    await page.goto('/?recovery=1');await page.waitForFunction(()=>!!window.os?.exec);
    await cloudSignIn(page, 'root', password);
    const result=await page.evaluate(async()=>{let diagnostic='';const result=await window.os.exec([{path:'/usr/bin/providerctl',argv:['providerctl']}],{stdin:'',onOutput:(_,text)=>{diagnostic+=text;}});return {...result,diagnostic};});
    expect(result.status,result.diagnostic).toBe(0);expect(JSON.parse(result.stdout)).toEqual(changed);
    const reopened=await device(r);expect(await reopened.ioctl('policy',{})).toEqual(changed);await call(r,{close:{fd:reopened.fd}});
  }finally{const reset=await device(r),current=await reset.ioctl('policy',{});await reset.ioctl('configure',{...before,revision:current.revision});await call(r,{close:{fd:reset.fd}});}
});

test('provider admission, detach permission and durable deadline bound real container jobs',async({request:r})=>{
  test.setTimeout(180000);await login(r);const driver=await device(r),before=await driver.ioctl('policy',{});
  const base='/provider-'+randomUUID();await mkdirp(r,base+'/dest');
  await put(r,'/api/file?path='+base+'/source.zip',{data:zipOf([['file.txt','replacement']])});
  await put(r,'/api/file?path='+base+'/dest/file.txt',{data:'keep'});
  const at=await directory(r,base),operation={operation:'extract',format:'zip',source:at('source.zip'),destination:at('dest'),existing:'ask',members:[],verbose:false};
  let task,observer;
  try {
    let policy=await driver.ioctl('configure',{...before,max_active:1,max_seconds:12,detached:false});
    task=await driver.submit(operation);
    expect(await errno(r,{ioctl:{fd:driver.fd,request:ACCEL.submit,arg:{version:1,request:randomUUID(),operation}}})).toBe('EAGAIN');
    expect(await errno(r,{ioctl:{fd:driver.fd,request:ACCEL.detach,arg:{version:1,id:task.id}}})).toBe('EACCES');
    policy=await driver.ioctl('configure',{...policy,enabled:false,detached:true});
    expect((await driver.submit(operation,task.request)).id).toBe(task.id);
    expect(await errno(r,{ioctl:{fd:driver.fd,request:ACCEL.submit,arg:{version:1,request:randomUUID(),operation}}})).toBe('EACCES');
    await task.detach();await task.close();
    observer=await device(r);const retained=await observer.attach(task.id);
    await retained.detach();
    await expect.poll(async()=>(await retained.poll()).state,{timeout:45000}).toBe('cancelled');
    expect((await retained.poll()).events.some(e=>JSON.stringify(e).includes('deadline'))).toBe(true);
    expect(await (await r.get('/api/file?path='+base+'/dest/file.txt')).text()).toBe('keep');
  }finally{
    if(task)await task.cancel().catch(()=>{});
    const reset=await device(r),current=await reset.ioctl('policy',{});await reset.ioctl('configure',{...before,revision:current.revision});
    for(const fd of [driver.fd,observer?.fd,at('.').directory,reset.fd])if(fd!==undefined)await call(r,{close:{fd}}).catch(()=>{});
    await rmrf(r,base);
  }
});

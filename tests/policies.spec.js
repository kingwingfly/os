import { test, expect } from './test.js';
import { readFile } from 'node:fs/promises';
import { randomBytes, randomUUID } from 'node:crypto';
import { api, call, errno, sys, mkdirp, put, rmrf } from './sys.js';
import { device, directory, ACCEL } from './accelerator.js';
import { zipOf } from './archive-fixtures.js';
const password=(await readFile('.dev.vars','utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const registry={'X-Registry':'1'};
async function login(r) { expect((await api(r,'login',{headers:{'CF-Connecting-IP':'policy-'+randomUUID()},data:{password}})).ok()).toBe(true); }
async function action(r,action,options={}) {return (await sys(r,[{login_session:{action}}],options))[0];}
async function join(r) {
  await call(r,'getcreds');const answer=await action(r,{op:'join',host:randomUUID(),proof:randomBytes(32).toString('hex')});
  expect(answer.err).toBeUndefined();return answer.ok;
}
const configure=(r,session,sharing,expected=session.seat_policy.revision)=>action(r,{op:'seat_policy',session:session.id,expected,sharing});

test('seat policy persists across logins and rejects stale, process, sudo and foreign session updates',async({request:r,browser})=>{
  const session=await join(r), initial=session.seat_policy;
  expect(initial.sharing).toBe('control');
  const changed=await configure(r,session,'view');expect(changed.err).toBeUndefined();
  expect(changed.ok.seat_policy).toEqual({revision:initial.revision+1,sharing:'view'});
  expect((await configure(r,session,'none')).err?.errno).toBe('ESTALE');
  const p=await call(r,{execve:{path:'/usr/bin/sleep',argv:['sleep','10'],cwd:'/'}});
  try {
    const operation={op:'seat_policy',session:session.id,expected:initial.revision+1,sharing:'none'};
    expect((await action(r,operation,{pid:p.pid,proc:p.token})).err?.errno).toBe('EPERM');
    expect((await action(r,operation,{sudo:true})).err).toBeTruthy();
    const foreign=await browser.newContext();
    try {await join(foreign.request);expect((await action(foreign.request,operation)).err?.errno).toBe('ESTALE');}finally{await foreign.close();}
    await login(r);const root=await join(r);expect(root.seat_policy.sharing).toBe('control');
    await api(r,'logout');const next=await join(r);
    expect(next.seat_policy).toEqual(changed.ok.seat_policy);
    expect((await configure(r,next,'control')).err).toBeUndefined();
  }finally{await sys(r,[{exit:{pid:p.pid,proc:p.token,status:0}},{wait:{pid:String(p.pid),proc:p.token}}],{},registry);}
});

test('sharing preference UI revokes live control and remains saved after reload',async({page})=>{
  await page.goto('/?recovery=1');await page.waitForFunction(()=>!!window.os?.configureSeatSharing);
  await expect.poll(()=>page.evaluate(async()=>(await window.os.loginSession()).connected)).toBe(true);
  const input=page.locator('#command');await input.fill('cat');await input.press('Enter');
  await expect(page.locator('.terminal-panel:not([hidden]) .command-line')).toHaveAttribute('data-state','input',{timeout:60000});
  const open=page.getByRole('button',{name:'Open in new window',exact:true});await open.click();
  const dialog=page.getByRole('dialog',{name:'Open command in a new window'});
  await expect(dialog.getByLabel('Use keyboard in new window')).toBeEnabled();
  await dialog.getByLabel('Use keyboard in new window').check();
  const [peer]=await Promise.all([page.waitForEvent('popup'),dialog.getByRole('button',{name:'Open window',exact:true}).click()]);
  await expect(peer.locator('.console-connection')).toHaveText('Keyboard connected');
  await open.click();await dialog.getByRole('combobox',{name:'Sharing allowed for this account',exact:true}).click();
  await page.getByRole('option',{name:'Disabled',exact:true}).click();
  await dialog.getByRole('button',{name:'Save preference'}).click();
  await expect(dialog.locator('[role=alert]')).toHaveText('Preference saved.');
  await expect(peer.locator('.console-connection')).not.toHaveText('Keyboard connected');
  await expect(input).toBeEnabled();await expect(dialog.getByRole('button',{name:'Open window',exact:true})).toBeDisabled();
  await dialog.getByRole('button',{name:'Cancel',exact:true}).click();await input.press('Control+c');
  await page.reload();await page.waitForFunction(()=>!!window.os?.configureSeatSharing);
  await expect.poll(()=>page.evaluate(async()=>(await window.os.loginSession()).session?.seat_policy?.sharing)).toBe('none');
  await page.evaluate(()=>window.os.configureSeatSharing('control'));
  await peer.close();
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
    await page.goto('/?recovery=1');await page.waitForFunction(()=>!!window.os?.exec);
    const result=await page.evaluate(async()=>{let diagnostic='';const result=await window.os.exec([{path:'/usr/bin/providerctl',argv:['providerctl']}],{stdin:'',onOutput:(_,text)=>{diagnostic+=text;}});return {...result,diagnostic};});
    expect(result.status,result.diagnostic).toBe(0);expect(JSON.parse(result.stdout)).toEqual(changed);
    await call(r,{close:{fd:driver.fd}});const reopened=await device(r);expect(await reopened.ioctl('policy',{})).toEqual(changed);await call(r,{close:{fd:reopened.fd}});
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

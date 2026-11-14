import { chromium, expect } from '@playwright/test';
import { mkdtemp, mkdir, readFile, writeFile, rm, open } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
import { needsPodman, egressImage, startPodman, configureWrangler } from '../podman.mjs';
import { conformanceConfig, compilerConfig, compilerImage, isSleep, sameSleep, withCleanup, mountHandle, browserOptions, directoryProfile, helperConnection, recordReattach, putFile, mountOutcome, heldProbe } from './fixtures.mjs';
import { ShutdownScope } from '../process.mjs';
import { containerLease } from './containers.mjs';
import { imageStore } from './storage.mjs';
import { RunRecord, recoverInterrupted, runPrefix } from './recovery.mjs';
import { performance } from 'node:perf_hooks';
import { run, targetDir, jsonLines, requireProbeSuccess, ok, ports, start, stop, sourceEvidence, filesystems, operations, probeOperations } from './common.mjs';

async function batch(page,calls,options={}) {
  return page.evaluate(async ({calls,options})=>{
    const response=await fetch('/api/sys',{method:'POST',body:JSON.stringify({calls,...options})});
    if (!response.ok) throw new Error('sys HTTP '+response.status);
    return (await response.json()).results;
  },{calls,options});
}
async function checked(page,calls,options={}) {
  const rows=await batch(page,calls,options);
  for (const row of rows) if (row.err) throw new Error(JSON.stringify(row.err));
  return rows.map(row=>row.ok);
}
async function put(page,path,bytes) {
  return putFile(calls=>checked(page,calls),path,bytes);
}
async function exec(page,path,args=[],cwd='/') {
  return page.evaluate(async ({path,args,cwd})=>{
    let error='';const started=Date.now();const result=await window.os.exec([{path,argv:[path,...args]}],{cwd,stdin:'',cancelled:()=>Date.now()-started>120000,onOutput:(fd,text)=>{if(fd===2) error+=text;}});
    if (result.status!==0) throw new Error(`${path}: status ${result.status}: ${error}`);
    return result.stdout;
  },{path,args,cwd});
}
async function ready(page,url) {
  await page.goto(url);await page.waitForFunction(()=>window.os?.exec && window.os?.mountLocal);
  await expect(page.locator('.command-line').first()).toHaveAttribute('data-state','idle',{timeout:120000});
}
async function uploadTool(page,bytes) {
  await page.evaluate(async bytes=>{
    await window.os.mountLocal({name:'conformance-tool',files:[new File([Uint8Array.from(atob(bytes),c=>c.charCodeAt(0))],'probe')],execute:true,cloud:true});
  },bytes.toString('base64'));
}
const tool='/mnt/local/conformance-tool/probe';
async function probe(page,mode,root,alias,cross,creds,extra=[]) {
  return jsonLines(await exec(page,tool,[mode,root,alias,cross,String(creds.uid),String(creds.gid),...extra]));
}
async function account(browser,url,name,password,bytes,existingContext=null) {
  const context=existingContext||await browser.newContext({baseURL:url,viewport:{width:1440,height:1000}});
  await context.addInitScript(()=>{delete globalThis.SharedWorker;});
  const response=await context.request.post(url+'/api/sys',{headers:{Origin:url,'CF-Connecting-IP':'conformance-'+name},data:{calls:[{login:{username:name,password}}]}});
  const rows=(await response.json()).results;if(rows[0].err) throw new Error('test account login failed: '+rows[0].err.errno);
  const page=await context.newPage();await ready(page,url);await uploadTool(page,bytes);
  const [creds]=await checked(page,['getcreds']);
  return {context,page,creds};
}

async function timing(page,root,alias,cross,creds) {
  const rows=[];
  requireProbeSuccess(await probe(page,'latency',root,alias,cross,creds,['prepare']),'OS latency prepare failed');
  // Cold = first invocation of this operation in this fresh filesystem/profile;
  // warm = immediate repeat. This does not claim to drop host/provider caches.
  for (const operation of operations) {
    const samples=[];
    for (const temperature of ['cold','warm']) {
      const started=performance.now();let result;
      if (operation==='ls-usr-bin') result=await exec(page,'/usr/bin/ls',['-l','/usr/bin'],root);
      else if (operation==='shell-first-prompt') {
        result=await page.evaluate(async root=>{
          let input, output='', sent=false, elapsed;const started=performance.now();
          const prompt=()=>{if(!sent&&output.includes('CONFORMANCE_PROMPT>')&&input){sent=true;elapsed=performance.now()-started;input.write('exit\n');}};
          const result=await window.os.exec([{path:'/usr/bin/sh',argv:['sh','-i']}],{cwd:root,stdin:null,tty:true,cancelled:()=>performance.now()-started>120000,environment:{PS1:'CONFORMANCE_PROMPT> '},onTty:t=>{input=t;prompt();},onOutput:(_fd,text)=>{output+=text;prompt();}});
          if(result.status!==0||!sent)throw new Error('interactive shell prompt missing');return elapsed;
        },root);
      } else {
        const op=probeOperations[operation];
        result=await probe(page,'latency',root,alias,cross,creds,[op]);
        if(result.some(row=>row.errno))throw new Error('latency I/O failed '+JSON.stringify(result));
      }
      samples.push({temperature,milliseconds:Number((operation==='shell-first-prompt'?result:performance.now()-started).toFixed(3))});
    }
    rows.push({operation,samples});
  }
  return rows;
}
export async function os() {
  run('cargo',['xtask','build','--web-only'],{stdio:'inherit'});
  run('cargo',['build','--locked','-p','os-conformance','--target','wasm32-wasip1','--release'],{stdio:'inherit'});
  run('cargo',['build','--locked','-p','os-local-helper','--release'],{stdio:'inherit'});
  run('worker-build',['--release'],{cwd:'crates/worker',stdio:'inherit'});
  const target=targetDir(), bytes=await readFile(join(target,'wasm32-wasip1/release/os-conformance.wasm'));
  // A runner killed outright leaves its processes and containers behind; stop those first.
  for(const run of await recoverInterrupted()) {
    const parts=[`stopped ${run.stopped.join(', ')||'nothing'}`];
    if(run.survived.length)parts.push('still running after SIGKILL: '+run.survived.join(', '));
    if(run.unverified.length)parts.push('leader gone, members left running: '+run.unverified.join(', '));
    if(run.processes.stopped||run.processes.remaining)parts.push(`other processes of the run stopped: ${run.processes.stopped}, still running: ${run.processes.remaining}`);
    if(run.containers)parts.push('containers: '+JSON.stringify(run.containers));
    console.error(`Recovered interrupted run ${run.state}: ${parts.join('; ')}`);
  }
  const state=await mkdtemp(join(tmpdir(),runPrefix));
  const record=new RunRecord(state);await record.save();
  const scope=new ShutdownScope();
  const previousMask=process.umask(0o022);
  scope.add('umask',()=>process.umask(previousMask),{always:true});
  let server,browser,persistent,helper,log,podman,compilerEvidence,failure,success=false,reported=false;
  const retained=()=>{if(!reported){reported=true;console.error('Run retained disposable state and logs at '+state);}};
  // This must run inside close(), before signal/error termination can exit.
  scope.add('retained state notice',()=>{if(!success||scope.fatal)retained();},{always:true});
  try {
    const [number,inspectorPort]=await ports(2),url=`http://127.0.0.1:${number}`;
    const root=resolve('.');
    let config=conformanceConfig(await readFile('wrangler.toml','utf8'),root);
    await writeFile(join(state,'wrangler.toml'),config);
    const password=randomBytes(20).toString('hex');
    await writeFile(join(state,'.dev.vars'),`ADMIN_PASSWORD=${password}\nSESSION_SECRET=${randomBytes(32).toString('hex')}\n`,{mode:0o600});
    log=await scope.acquire('log',()=>open(join(state,'server.log'),'w'),file=>file.close());
    const serverEnv={...process.env};
    if (needsPodman(serverEnv)) {
      const cache=await imageStore(process.env.OS_CONFORMANCE_PODMAN_DIR);
      const storage=join(state,'storage.conf');
      // Only images persist in the cache. Container metadata, Podman's database and mount state
      // are transient and private to this run, in its own state directory.
      await writeFile(storage,`[storage]\ndriver = "overlay"\ngraphroot = ${JSON.stringify(join(cache,'storage'))}\nrunroot = ${JSON.stringify(join(state,'podman-run'))}\ntransient_store = true\n`);
      serverEnv.CONTAINERS_STORAGE_CONF=storage;
      // Resolve the egress image before starting anything; the run fails if it cannot.
      const egress=egressImage(serverEnv,{strict:true});
      podman=await scope.acquire('Podman service',signal=>startPodman(serverEnv,{signal,socket:join(state,'podman.sock'),output:log.fd}),service=>service.close());
      await record.addGroup('Podman service',podman.pid);
      configureWrangler(serverEnv,{host:podman.socket,egress});
    }
    if(process.env.OS_CONFORMANCE_COMPILER_IMAGE) {
      const image=compilerImage(process.env.OS_CONFORMANCE_COMPILER_IMAGE);
      const inputs=['package.json','package-lock.json','containers/compiler/server.mjs','web/kernel/transform.js','web/kernel/asyncify.js','web/kernel/memory.js','web/kernel/image.js','node_modules/binaryen/index.js','node_modules/binaryen/package.json'];
      const expected=Object.fromEntries(await Promise.all(inputs.map(async path=>[path,createHash('sha256').update(await readFile(path)).digest('hex')])));
      const script=`import {readFileSync} from 'node:fs';import {createHash} from 'node:crypto';console.log(JSON.stringify(Object.fromEntries(${JSON.stringify(inputs)}.map(path=>[path,createHash('sha256').update(readFileSync('/app/'+path)).digest('hex')]))));`;
      const actual=JSON.parse(run(podman?'podman':'docker',['run','--rm','--network','none',image,'node','--input-type=module','-e',script],{env:serverEnv}));
      if(JSON.stringify(actual)!==JSON.stringify(expected))throw new Error('prebuilt compiler image differs from checkout/locked Binaryen');
      compilerEvidence={image,verified_sha256:actual};
      const dockerfile=join(state,'Compiler.Dockerfile');await writeFile(dockerfile,`FROM ${image}\n`);
      config=compilerConfig(config,root,dockerfile);
      await writeFile(join(state,'wrangler.toml'),config);
      console.log('Verified prebuilt compiler source and Binaryen bytes: '+image);
    }
    // One proxy: it labels this run's containers and, on Podman, drops the swappiness crun refuses.
    const lease=await scope.acquire('containers',()=>containerLease(serverEnv,join(state,'owned-containers.sock'),{stripMemorySwappiness:!!podman}),lease=>lease.close());
    await record.setContainers({engine:podman?'podman':'docker',label:lease.label});
    server=scope.own('server',()=>start(process.execPath,['scripts/dev.mjs','--config',join(state,'wrangler.toml'),'--local','--ip','127.0.0.1','--port',String(number),'--inspector-port',String(inspectorPort),'--persist-to',join(state,'persist')],{stdio:['ignore',log.fd,log.fd],env:serverEnv}),stop);
    await record.addGroup('server',server.pid);
    console.log(`Isolated OS at ${url}; temporary state ${state}`);
    const until=Date.now()+900000;
    while (true) {
      scope.check();
      if(server.spawnError)throw server.spawnError;
      if (server.exitCode!==null||server.signalCode!==null) throw new Error('isolated server exited; inspect '+join(state,'server.log'));
      try {
        const response=await fetch(url,{signal:AbortSignal.timeout(2000)});
        // Release the connection now; an unread body would hold its socket until garbage collection.
        await response.body?.cancel();
        if(response.ok)break;
      } catch {}
      if(Date.now()>until)throw new Error('isolated server startup timeout; inspect '+join(state,'server.log'));
      await new Promise(r=>setTimeout(r,300));
    }
    const profile=await directoryProfile(join(state,'profile'));
    persistent=await scope.acquire('browser',()=>chromium.launchPersistentContext(profile,browserOptions()),context=>context.close());
    browser=persistent.browser();
    const admin=await account(browser,url,'root',password,bytes);
    for (const name of ['conformance-a','conformance-b']) {
      const registration=await browser.newContext();
      const response=await registration.request.post(url+'/api/sys',{headers:{Origin:url,'CF-Connecting-IP':'register-'+name},data:{calls:[{useradd:{name,password,create_home:true}}]}});
      const [result]=(await response.json()).results;
      await registration.close();if(result.err)throw new Error('registration failed: '+result.err.errno);
    }
    // Give both creators exactly one common supplementary group. It differs
    // from their primary groups and permits the owner to chgrp private trees.
    await checked(admin.page,[{groupadd:{name:'conformance-shared'}}]);
    for(const name of ['conformance-a','conformance-b'])await checked(admin.page,[{usermod:{name,groups:'conformance-shared'}}]);
    const observations={},latencies={},diagnostics=[];
    for (const filesystem of filesystems) {
      console.log('Measuring '+filesystem);
      const persist=rows=>writeFile(join(state,filesystem+'-observations.json'),JSON.stringify(rows,null,2));
      const [a,b]=await Promise.all([account(browser,url,'conformance-a',password,bytes,filesystem==='directory-handle'?persistent:null),account(browser,url,'conformance-b',password,bytes)]);
      const {page,context,creds}=a;
      const neutral=creds.groups.filter(g=>g!==creds.gid);
      if(creds.gid===b.creds.gid||neutral.length!==1||neutral[0]===b.creds.gid||JSON.stringify(b.creds.groups.filter(g=>g!==b.creds.gid))!==JSON.stringify(neutral))throw new Error('two-account fixture requires distinct primary groups and one neutral supplementary group');
      const source=join(state,filesystem);await mkdir(source);
      let connection,owner,grant;
      const cross=filesystem==='browser-storage'?creds.home+'/cross-browser-storage':'/mnt/local/cross';
      if(filesystem==='browser-storage')await checked(page,[{mkdir:{path:cross,mode:0o700}}]);
      else await page.evaluate(()=>window.os.mountLocal({name:'cross',storage:true,writable:true,cloud:true}));
      // Browser storage's primary/alias intentionally share OPFS. Its crossing
      // target is cloud storage, so the third path cannot alias the same tree.
      await put(page,cross+'/target',Buffer.from('target'));
      let primary=filesystem==='cloud'?creds.home+'/probe-'+filesystem:'/mnt/local/primary';
      let alias=filesystem==='cloud'?creds.home+'/alias':'/mnt/local/alias';
      if (filesystem==='directory-handle') await mountHandle(page,context,source);
      if (filesystem==='local-helper') {
        helper=scope.own('helper',()=>start(join(target,'release/os-local-helper'),['--root',source,'--origin',url,'--write','--execute'],{stdio:['ignore','pipe',log.fd]}),stop);
        await record.addGroup('helper',helper.pid);
        connection=await helperConnection(helper);
      }
      if (filesystem==='relay') {
        owner=await account(browser,url,'conformance-a',password,bytes);
        await owner.page.evaluate(()=>window.os.mountLocal({name:'source',storage:true,writable:true,cloud:true}));
        await checked(owner.page,[{chmod:{path:'/mnt/local/source',mode:0o777}}]);
        grant=await owner.page.evaluate(()=>window.os.shareMount({path:'/mnt/local/source',name:'conformance',seconds:3600},{p2p:false}));
        primary='/mnt/shared/primary';alias='/mnt/shared/alias';
      }
      const attach=name=>page.evaluate(mountOutcome,{operation:'attach',filesystem,name,connection,address:grant?.address});
      const requireAttach=async name=>{const result=await attach(name);if(result.errno)throw new Error('fixture attach: '+result.errno);};
      if(filesystem==='cloud')await checked(page,[{mkdir:{path:primary,mode:0o700}}]);else {await requireAttach('primary');await requireAttach('alias');}
      // A shared backing tree would invalidate every crossing result. Verify
      // distinct contents before measuring rather than trusting attachment names.
      await put(page,cross+'/fixture-cross-only',Buffer.from('cross'));
      await put(page,primary+'/fixture-primary-only',Buffer.from('primary'));
      for(const path of [primary+'/fixture-cross-only',cross+'/fixture-primary-only']) {
        const [result]=await batch(page,[{stat:{path}}]);
        if(result.err?.errno!=='ENOENT')throw new Error('crossing fixture aliases the primary tree: '+path);
      }
      const rows=await probe(page,filesystem==='cloud'?'basic-cloud':'basic',primary,alias,cross,creds);
      await writeFile(join(state,filesystem+'-basic.json'),JSON.stringify(rows,null,2));

      await checked(page,[{mkdir:{path:creds.home+'/links-'+filesystem,mode:0o700}}]);
      await put(page,primary+'/target',Buffer.from('target'));
      rows.push(...await probe(page,'cloud-link',creds.home+'/links-'+filesystem,alias,filesystem==='cloud'?cross:primary,creds));
      if(filesystem!=='cloud') {
        rows.push(...await probe(page,'remount-prepare',primary,alias,cross,creds));
        const detached={case:'remount',step:'detach',call:'umount(mount)',...await page.evaluate(mountOutcome,{operation:'detach',path:primary})};
        rows.push(detached);
        await recordReattach(rows,detached,()=>attach('primary'),'remount',persist);
        rows.push(...await probe(page,'remount-observe',primary,alias,cross,creds));
        for(const mode of ['hold-open','hold-cwd']) {
          const caseName=mode==='hold-open'?'unmount-open':'unmount-cwd';
          const heldResult=await heldProbe(page,{tool,args:[mode,primary,alias,cross,String(creds.uid),String(creds.gid)],caseName,path:primary,diagnostics});
          rows.push(...heldResult.rows);
          // Never re-attach while the mount state is unknown or a cancelled probe still runs.
          if(heldResult.failure) {await persist(rows);throw heldResult.failure;}
          await recordReattach(rows,heldResult.detach,()=>attach('primary'),caseName,persist);
        }
      }
      rows.push(...await probe(page,'unsupported',primary,alias,cross,creds));
      // Two authenticated accounts create in one setgid/default-ACL directory.
      const shared=primary+'/two';
      // Export metadata is administered at its source; relay chmod is itself
      // measured above and is not a fixture-setup API.
      const setupPage=owner?.page||page, setupRoot=owner?'/mnt/local/source':primary;
      await checked(setupPage,[{chmod:{path:setupRoot,mode:0o777}},{mkdir:{path:setupRoot+'/two',mode:0o777}},{chown:{path:setupRoot+'/two',gid:neutral[0]}},{chmod:{path:setupRoot+'/two',mode:0o2777}}]);
      const acl=Buffer.from(JSON.stringify({user:7,group:5,other:0,mask:5,users:{},groups:{65534:4}})).toString('base64');
      await checked(setupPage,[{setxattr:{path:setupRoot+'/two',name:'system.posix_acl_default',value:acl}}]);
      rows.push(...await probe(page,'creator',shared,alias,cross,creds,['a']));
      let bpath=shared;
      if(filesystem==='cloud')await checked(page,[{chmod:{path:creds.home,mode:0o755}}]);
      else {
        // The only current way for another account to access this private tree is
        // an explicitly authorized export; no account credentials are swapped.
        const exportPage=owner?.page||page;
        const exportPath=owner?'/mnt/local/source/two':shared;
        const offered=await exportPage.evaluate(path=>window.os.shareMount({path,name:'two-creators',seconds:3600},{p2p:false}),exportPath);
        await b.page.evaluate(address=>window.os.attachShared({address,name:'two-creators',writable:true,cloud:true},{p2p:false}),offered.address);
        bpath='/mnt/shared/two-creators';
      }
      rows.push(...await probe(b.page,'creator',bpath,bpath,bpath,b.creds,['b']));
      await persist(rows);
      latencies[filesystem]=await timing(page,primary,alias,cross,creds);
      if(filesystem==='relay') {
        const transport=await page.evaluate(()=>window.os.mountTransports());
        if(!transport.mounts.length||transport.mounts.some(m=>m.mode!=='relay'))throw new Error('relay profile did not use relay transport');
      }
      observations[filesystem]=rows;
      if(a.context===persistent)await a.page.close();else await a.context.close();await b.context.close();await owner?.context.close();await stop(helper);helper=null;
    }
    const processRows=await processFacts(admin,url);
    const evidence=[await sourceEvidence('web/wasi/process.js',['fd_datasync: () => 0','fd_sync: () => 0']),await sourceEvidence('web/kernel/client.js',["exec([['supervise', run.file]]","exec([['init']]"])];
    success=true;return {observations,process:processRows,latencies,evidence,diagnostics,compiler:compilerEvidence??{dockerfile:'containers/compiler/Dockerfile'},browser:browser.version()};
  } catch(error) {
    failure=error;throw error;
  } finally {
    const errors=await scope.close();
    if(success&&!scope.fatal&&!errors.length)await rm(state,{recursive:true,force:true});
    else retained();
    if(errors.length&&!failure)throw new AggregateError(errors.map(e=>e.error),'conformance cleanup failed');
  }
}

async function processFacts(admin,url) {
  const {page,context}=admin;
  const ps=async(target=page)=>(await checked(target,[{proc_poll:{pids:[]}}]))[0];
  await expect.poll(async()=>(await page.evaluate(()=>window.os.machineInit()))?.reaper?.state,{timeout:30000}).toBe('running');
  const init=await page.evaluate(()=>window.os.machineInit());
  const [inspected]=await checked(page,[{machine_init:{action:{op:'inspect'}}}]);
  const initComm=await exec(page,'/usr/bin/cat',['/proc/1/cmdline']);
  const rows=[ok('startup','pid1','read /proc/1/cmdline',{comm:initComm.split('\0')[0].split('/').at(-1)})];
  const units='/root/conformance-services.json';
  await put(page,units,Buffer.from(JSON.stringify({version:1,units:[{name:'measured',argv:['sh','-c','echo CONFORMANCE_SERVICE_READY; sleep 60']}]})));
  await page.evaluate(file=>{
    const s=window.conformanceService={output:'',done:false};
    s.promise=window.os.startLoginServices(file,{tty:true,onOutput:(_fd,text)=>{s.output+=text;}})
      .then(result=>{s.status=result.status;},error=>{s.error=error.errno||'UNCLASSIFIED_ERROR';}).finally(()=>{s.done=true;});
  },units);
  await withCleanup(async()=>{
    try {
      await page.waitForFunction(()=>window.conformanceService.output.includes('CONFORMANCE_SERVICE_READY')||window.conformanceService.done,null,{timeout:60000});
    } catch(error) {
      const state=await page.evaluate(()=>({output:window.conformanceService.output,done:window.conformanceService.done,status:window.conformanceService.status,error:window.conformanceService.error}));
      throw new Error('startup service readiness: '+JSON.stringify(state),{cause:error});
    }
    const service=await page.evaluate(()=>({done:window.conformanceService.done,error:window.conformanceService.error}));
    if(service.done)throw new Error('service fixture exited before inspection: '+JSON.stringify(service));
    await expect.poll(async()=>(await page.evaluate(()=>window.os.loginSession())).session?.managed?.pid,{timeout:30000}).toBeGreaterThan(1);
    const login=await page.evaluate(()=>window.os.loginSession()), processes=await ps();
    const supervisor=processes.find(p=>p.pid===login.session.managed.pid);
    rows.push(ok('startup','ownership','inspect live init lease, login lease and managed supervisor',{
      role:inspected.execution?.role??null,reaper:init.reaper?.state??null,
      init_owner_is_current_host:!!inspected.owner&&inspected.owner===init.host,
      login_owner_is_current_host:!!login.session?.owner&&login.session.owner===login.host,
      service_host_is_login_owner:login.session.managed.host===login.session.owner,
      supervisor_path:supervisor?.path??null,supervisor_parent_is_pid1:supervisor?.ppid===1,
    }));
  },async()=>{
    await page.evaluate(async()=>{const session=(await window.os.loginSession()).session;if(session?.managed)await window.os.signalLoginServices(session);});
    await page.waitForFunction(()=>window.conformanceService.done,null,{timeout:40000});
  });
  await expect.poll(async()=>(await ps()).some(p=>p.argv?.some(a=>a.includes('conformance-services')||a.includes('CONFORMANCE_SERVICE_READY'))||p.argv?.[0]==='sleep'),{timeout:30000}).toBe(false);
  const images=rows=>[...new Set(rows.map(p=>JSON.stringify({path:p.path,argv:p.argv})))].sort().map(s=>JSON.parse(s));
  // Wait for the fixture's completed cat to be reaped before taking the idle
  // Files snapshot; otherwise scheduler timing would leak into the baseline.
  await expect.poll(async()=>(await ps()).some(p=>p.argv?.includes('/proc/1/cmdline')),{timeout:30000}).toBe(false);
  const before=images(await ps());
  await page.evaluate(()=>{void window.os.localMounts();});
  await expect(page.locator('#window-mounts')).toBeVisible();const mounts=images(await ps());
  await put(page,'/root/conformance-note.txt',Buffer.from('hello'));
  // Files and Mounts are visible; open Editor and Preview through their UI APIs.
  await page.locator('#window-mounts').getByRole('button',{name:'Close Mounts',exact:true}).click();
  await page.locator('#command').fill('vim /root/conformance-note.txt');await page.locator('#command').press('Enter');
  await expect(page.locator('#editor')).toBeVisible();const editor=images(await ps());
  await page.keyboard.press('Escape');
  await page.evaluate(()=>window.os.open('/root/conformance-note.txt'));
  await expect(page.locator('#viewer')).toBeVisible();const preview=images(await ps());
  rows.push(ok('gui-processes','ps','open Files/Mounts/Editor/Preview; inspect ps',{files_visible:await page.locator('#window-files').isVisible(),
    images_with_files:before,images_with_mounts:mounts,images_with_editor:editor,images_with_preview:preview}));
  const tab=await context.newPage();await ready(tab,url);
  await page.evaluate(()=>{window.conformanceSleep=window.os.exec([{path:'/usr/bin/sleep',argv:['sleep','60']}],{cwd:'/',stdin:''});});
  await expect.poll(async()=>(await ps()).some(isSleep),{timeout:30000}).toBe(true);
  const one=await ps(),two=await ps(tab);
  const sleep=one.find(isSleep);
  rows.push(ok('tab-pids','visibility','start sleep in tab A; ps in tab B',{other_tab_pid_visible:two.some(p=>sameSleep(p,sleep))}));
  await checked(page,[{kill:{pid:String(sleep.pid),signal:15}}]);await tab.close();
  return rows;
}

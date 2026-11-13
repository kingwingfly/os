import { chromium, expect } from '@playwright/test';
import { mkdtemp, mkdir, readFile, writeFile, rm, open } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { podmanProxy } from '../podman-proxy.mjs';
import { createInterface } from 'node:readline';
import { performance } from 'node:perf_hooks';
import { run, targetDir, jsonLines, skip, ok, port, start, stop, sourceEvidence } from './common.mjs';

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
  const [opened]=await checked(page,[{open:{path,flags:0o1101,mode:0o666}}]);
  for (let offset=0;offset<bytes.length;offset+=65536) await checked(page,[{pwrite:{fd:opened.fd,index:offset/(opened.chunk_size||65536),data:bytes.subarray(offset,offset+65536).toString('base64')}}]);
  await checked(page,[{close:{fd:opened.fd}}]);
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
async function mountHandle(page,context,dir) {
  await page.evaluate(()=>{
    addEventListener('dragover',event=>event.preventDefault());
    addEventListener('drop',event=>{event.preventDefault();window.conformanceHandle=event.dataTransfer.items[0].getAsFileSystemHandle();},{once:true});
  });
  const cdp=await context.newCDPSession(page);
  for (const type of ['dragEnter','dragOver','drop']) await cdp.send('Input.dispatchDragEvent',{type,x:500,y:300,data:{items:[],files:[dir],dragOperationsMask:1}});
  await cdp.detach();
  await page.evaluate(async ()=>{window.conformanceHandle=await window.conformanceHandle;});
  await page.mouse.click(500,300);
  const permission=await page.evaluate(()=>window.conformanceHandle.requestPermission({mode:'readwrite'}));
  if(permission!=='granted')throw new Error('host directory write grant unavailable: '+permission);
}
async function held(page,mode,root,alias,cross,creds) {
  const args=[mode,root,alias,cross,String(creds.uid),String(creds.gid)];
  await page.evaluate(({tool,args,root})=>{
    window.conformanceBarrier=null;window.conformanceOutput='';window.conformanceInput=null;
    const started=Date.now();window.conformanceHeld=window.os.exec([{path:tool,argv:[tool,...args]}],{
      cwd:'/',stdin:null,tty:true,cancelled:()=>Date.now()-started>120000,
      onTty:input=>{window.conformanceInput=input;},
      onOutput:(fd,text)=>{if(fd===1){window.conformanceOutput+=text; if(window.conformanceOutput.includes('barrier')) window.conformanceBarrier=true;}},
    });
  },{tool,args,root});
  await page.waitForFunction(()=>window.conformanceBarrier && window.conformanceInput,{},{timeout:60000});
  const row=await page.evaluate(async ({root,mode})=>{
    let row={case:mode==='hold-open'?'unmount-open':'unmount-cwd',step:'unmount',call:'umount(mount)'};
    try {await window.os.unmountLocal(root);row.ok=null;} catch(e) {row.errno=e.errno||e.message;}
    window.conformanceInput.write('continue\n');return row;
  },{root,mode});
  const output=await page.evaluate(async ()=>{const result=await window.conformanceHeld;if(result.status!==0)throw new Error('held process failed');return window.conformanceOutput;});
  const rows=jsonLines(output.replaceAll('\r','')).filter(r=>!r.barrier);rows.splice(mode==='hold-open'?1:2,0,row);return rows;
}
async function timing(page,root,alias,cross,creds) {
  const rows=[];
  await probe(page,'latency',root,alias,cross,creds,['prepare']);
  // Cold = first invocation of this operation in this fresh filesystem/profile;
  // warm = immediate repeat. This does not claim to drop host/provider caches.
  for (const operation of ['stat-eight-deep','read-1mib','write-1mib','ls-usr-bin','shell-first-prompt']) {
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
        const op={'stat-eight-deep':'stat','read-1mib':'read','write-1mib':'write'}[operation];
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
  const abi=await readFile('crates/abi/src/lib.rs','utf8');
  const calls=abi.slice(abi.indexOf('pub enum Call {'),abi.indexOf('pub enum Target'));
  if(/^    (Chroot|Mount|Umount|Unmount)\b/m.test(calls))throw new Error('Mount/chroot ABI changed: replace the unavailable probes with executable calls');
  run('cargo',['build','--locked','-p','os-conformance','--target','wasm32-wasip1','--release'],{stdio:'inherit'});
  run('cargo',['build','--locked','-p','os-local-helper'],{stdio:'inherit'});
  run('worker-build',['--release'],{cwd:'crates/worker',stdio:'inherit'});
  const target=targetDir(), bytes=await readFile(join(target,'wasm32-wasip1/release/os-conformance.wasm'));
  const state=await mkdtemp(join(tmpdir(),'os-conformance-os-'));
  const previousMask=process.umask(0o022);
  let server,browser,persistent,helper,log,podman,proxy,podmanEnv,initialContainers,compilerEvidence,success=false;
  try {
    const number=await port(),url=`http://127.0.0.1:${number}`;
    process.env.OS_TEST_URL=url;
    const root=resolve('.');
    let config=await readFile('wrangler.toml','utf8');
    config=config.replace('main = "crates/worker/entry.js"',`main = ${JSON.stringify(join(root,'crates/worker/entry.js'))}`)
      .replace(/\[build\][\s\S]*?(?=\n\[)/,'')
      .replace(/\[\[containers\]\]\nclass_name = "JobRunner"[\s\S]*?(?=\n\[)/,'')
      .replace('directory = "./dist"',`directory = ${JSON.stringify(join(root,'dist'))}`)
      .replaceAll('image_build_context = "."',`image_build_context = ${JSON.stringify(root)}`)
      .replaceAll('image = "./containers/',`image = "${root}/containers/`);
    await writeFile(join(state,'wrangler.toml'),config);
    const password=randomBytes(20).toString('hex');
    await writeFile(join(state,'.dev.vars'),`ADMIN_PASSWORD=${password}\nSESSION_SECRET=${randomBytes(32).toString('hex')}\n`,{mode:0o600});
    log=await open(join(state,'server.log'),'w');
    const serverEnv={...process.env};
    if (!serverEnv.DOCKER_HOST && !serverEnv.WRANGLER_DOCKER_HOST && run('sh',['-c','command -v docker || command -v podman']).trim().endsWith('podman')) {
      const cache=resolve(process.env.OS_CONFORMANCE_PODMAN_DIR||join(tmpdir(),'os-conformance-images-'+process.getuid()));
      await mkdir(cache,{recursive:true});
      const storage=join(state,'storage.conf');
      await writeFile(storage,`[storage]\ndriver = "overlay"\ngraphroot = ${JSON.stringify(join(cache,'storage'))}\nrunroot = ${JSON.stringify(join(cache,'run'))}\n`);
      serverEnv.CONTAINERS_STORAGE_CONF=storage;podmanEnv=serverEnv;
      initialContainers=new Set(run('podman',['--cgroup-manager=cgroupfs','ps','-aq'],{env:serverEnv}).trim().split('\n').filter(Boolean));
      const socket=join(state,'podman.sock');
      podman=start('podman',['--cgroup-manager=cgroupfs','system','service','--time=0','unix://'+socket],{stdio:['ignore',log.fd,log.fd],env:serverEnv});
      for(let i=0;i<100&&!existsSync(socket);i++)await new Promise(r=>setTimeout(r,100));
      if(!existsSync(socket))throw new Error('isolated Podman service did not start');
      const proxied=join(state,'docker.sock');proxy=podmanProxy(proxied,socket);
      serverEnv.WRANGLER_DOCKER_BIN=join(root,'scripts/podman-docker.sh');
      serverEnv.WRANGLER_DOCKER_HOST='unix://'+proxied;
      const miniflare=await readFile('node_modules/miniflare/dist/src/index.js','utf8');
      const image=miniflare.match(/DEFAULT_CONTAINER_EGRESS_INTERCEPTOR_IMAGE = "([^"]+)"/)?.[1];
      if(image)serverEnv.MINIFLARE_CONTAINER_EGRESS_IMAGE=image.split('/')[0].includes('.')?image:'docker.io/'+image;
    }
    if(process.env.OS_CONFORMANCE_COMPILER_IMAGE) {
      const image=process.env.OS_CONFORMANCE_COMPILER_IMAGE;
      if(!/^[a-zA-Z0-9_./:@-]+$/.test(image))throw new Error('invalid compiler image reference');
      const inputs=['package-lock.json','containers/compiler/server.mjs','web/kernel/transform.js','web/kernel/asyncify.js','web/kernel/memory.js','web/kernel/image.js','node_modules/binaryen/index.js','node_modules/binaryen/package.json'];
      const expected=Object.fromEntries(await Promise.all(inputs.map(async path=>[path,createHash('sha256').update(await readFile(path)).digest('hex')])));
      const script=`import {readFileSync} from 'node:fs';import {createHash} from 'node:crypto';console.log(JSON.stringify(Object.fromEntries(${JSON.stringify(inputs)}.map(path=>[path,createHash('sha256').update(readFileSync('/app/'+path)).digest('hex')]))));`;
      const actual=JSON.parse(run(podman?'podman':'docker',['run','--rm','--network','none',image,'node','--input-type=module','-e',script],{env:serverEnv}));
      if(JSON.stringify(actual)!==JSON.stringify(expected))throw new Error('prebuilt compiler image differs from checkout/locked Binaryen');
      compilerEvidence={image,verified_sha256:actual};
      const dockerfile=join(state,'Compiler.Dockerfile');await writeFile(dockerfile,`FROM ${image}\n`);
      config=config.replace(`image = "${root}/containers/compiler/Dockerfile"`,`image = ${JSON.stringify(dockerfile)}`);
      await writeFile(join(state,'wrangler.toml'),config);
      console.log('Verified prebuilt compiler source and Binaryen bytes: '+image);
    }
    server=start('node' ,['scripts/dev.mjs','--config',join(state,'wrangler.toml'),'--local','--ip','127.0.0.1','--port',String(number),'--inspector-port',String(await port()),'--persist-to',join(state,'persist')],{stdio:['ignore',log.fd,log.fd],env:serverEnv});
    console.log(`Isolated OS at ${url}; temporary state ${state}`);
    const until=Date.now()+900000;
    while (true) {
      if (server.exitCode!==null) throw new Error('isolated server exited; inspect '+join(state,'server.log'));
      try {const response=await fetch(url,{signal:AbortSignal.timeout(2000)});if(response.ok)break;} catch {}
      if(Date.now()>until)throw new Error('isolated server startup timeout; inspect '+join(state,'server.log'));
      await new Promise(r=>setTimeout(r,300));
    }
    const env={...process.env};delete env.DISPLAY;
    const profile=join(state,'profile');await mkdir(join(profile,'Default'),{recursive:true});
    // Chrome's ordinary permission context (not headless-shell's denial-only
    // delegate) gives the explicitly selected fixture a write grant. No mocked
    // handle or provider method is substituted. Incognito profiles remain separate.
    await writeFile(join(profile,'Default/Preferences'),JSON.stringify({profile:{default_content_setting_values:{file_system_read_guard:1,file_system_write_guard:1}}}));
    persistent=await chromium.launchPersistentContext(profile,{channel:'chromium',headless:true,env,viewport:{width:1440,height:1000},args:['--ozone-platform=headless','--use-gl=angle','--use-angle=swiftshader','--enable-unsafe-swiftshader']});
    browser=persistent.browser();
    const admin=await account(browser,url,'root',password,bytes);
    for (const name of ['conformance-a','conformance-b']) {
      const registration=await browser.newContext();
      const response=await registration.request.post(url+'/api/sys',{headers:{Origin:url,'CF-Connecting-IP':'register-'+name},data:{calls:[{useradd:{name,password,create_home:true}}]}});
      const [result]=(await response.json()).results;
      await registration.close();if(result.err)throw new Error('registration failed: '+result.err.errno);
    }
    const observations={},latencies={};
    for (const filesystem of ['cloud','browser-storage','directory-handle','local-helper','relay']) {
      console.log('Measuring '+filesystem);
      const a=await account(browser,url,'conformance-a',password,bytes,filesystem==='directory-handle'?persistent:null), b=await account(browser,url,'conformance-b',password,bytes);
      const {page,context,creds}=a;
      const source=join(state,filesystem);await mkdir(source);
      let connection,owner,grant;
      const cross='/mnt/local/cross';
      await page.evaluate(()=>window.os.mountLocal({name:'cross',storage:true,writable:true,cloud:true}));
      // A separate host tree is used for the provider under test; storage source
      // and cross use different subtrees for filenames even though OPFS is shared.
      await put(page,cross+'/target',Buffer.from('target'));
      let primary=filesystem==='cloud'?creds.home+'/probe-'+filesystem:'/mnt/local/primary';
      let alias=filesystem==='cloud'?creds.home+'/alias':'/mnt/local/alias';
      if (filesystem==='directory-handle') await mountHandle(page,context,source);
      if (filesystem==='local-helper') {
        helper=start(join(target,'debug/os-local-helper'),['--root',source,'--origin',url,'--write','--execute'],{stdio:['ignore','pipe','pipe']});
        connection=await new Promise((resolve,reject)=>{
          const lines=createInterface({input:helper.stdout});const timer=setTimeout(()=>reject(new Error('helper startup timeout')),10000);
          lines.once('line',line=>{clearTimeout(timer);resolve(JSON.parse(line));});helper.once('exit',()=>{clearTimeout(timer);reject(new Error('helper exited'));});
        });
      }
      if (filesystem==='relay') {
        owner=await account(browser,url,'conformance-a',password,bytes);
        await owner.page.evaluate(()=>window.os.mountLocal({name:'source',storage:true,writable:true,cloud:true}));
        await checked(owner.page,[{chmod:{path:'/mnt/local/source',mode:0o777}}]);
        grant=await owner.page.evaluate(()=>window.os.shareMount({path:'/mnt/local/source',name:'conformance',seconds:3600},{p2p:false}));
        primary='/mnt/shared/primary';alias='/mnt/shared/alias';
      }
      const attach=async name=>{
        if(filesystem==='cloud')return;
        if(filesystem==='relay')return page.evaluate(({grant,name})=>window.os.attachShared({address:grant.address,name,writable:true,cloud:true},{p2p:false}),{grant,name});
        return page.evaluate(async ({filesystem,name,connection})=>window.os.mountLocal({name,writable:true,cloud:true,
          ...(filesystem==='browser-storage'?{storage:true}:filesystem==='directory-handle'?{handle:window.conformanceHandle}:connection)}),{filesystem,name,connection});
      };
      if(filesystem==='cloud')await checked(page,[{mkdir:{path:primary,mode:0o700}}]);else {await attach('primary');await attach('alias');}
      let rows=await probe(page,'basic',primary,alias,cross,creds);
      await writeFile(join(state,filesystem+'-basic.json'),JSON.stringify(rows,null,2));
      if(filesystem==='cloud')rows=rows.filter(r=>!['alias','mount-parent'].includes(r.case)).concat(
        skip('alias','not implemented: cloud tree has no second attachment API'),
        skip('mount-parent','account home is a subdirectory; no cloud mount-root attachment API'));

      await checked(page,[{mkdir:{path:creds.home+'/links-'+filesystem,mode:0o700}}]);
      await put(page,primary+'/target',Buffer.from('target'));
      rows.push(...await probe(page,'cloud-link',creds.home+'/links-'+filesystem,alias,filesystem==='cloud'?cross:primary,creds));
      if(filesystem==='cloud') for(const name of ['remount','unmount-open','unmount-cwd'])rows.push(skip(name,'not implemented: cloud root cannot be detached through the current mount API'));
      else {
        rows.push(...await probe(page,'remount-prepare',primary,alias,cross,creds));
        await page.evaluate(path=>window.os.unmountLocal(path),primary);rows.push(ok('remount','detach','umount(mount)',null));
        await attach('primary');rows.push(ok('remount','attach','mount(source, mount)',null));
        rows.push(...await probe(page,'remount-observe',primary,alias,cross,creds));
        rows.push(...await held(page,'hold-open',primary,alias,cross,creds));await attach('primary');
        rows.push(...await held(page,'hold-cwd',primary,alias,cross,creds));await attach('primary');
      }
      rows.push(...await probe(page,'unsupported',primary,alias,cross,creds));
      // Two authenticated accounts create in one setgid/default-ACL directory.
      const shared=primary+'/two';
      // Export metadata is administered at its source; relay chmod is itself
      // measured above and is not a fixture-setup API.
      const setupPage=owner?.page||page, setupRoot=owner?'/mnt/local/source':primary;
      await checked(setupPage,[{chmod:{path:setupRoot,mode:0o777}},{mkdir:{path:setupRoot+'/two',mode:0o777}},{chmod:{path:setupRoot+'/two',mode:0o2777}}]);
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
      await writeFile(join(state,filesystem+'-observations.json'),JSON.stringify(rows,null,2));
      latencies[filesystem]=await timing(page,primary,alias,cross,creds);
      if(filesystem==='relay') {
        const transport=await page.evaluate(()=>window.os.mountTransports());
        if(!transport.mounts.length||transport.mounts.some(m=>m.mode!=='relay'))throw new Error('relay profile did not use relay transport');
      }
      observations[filesystem]=rows;
      if(a.context===persistent)await a.page.close();else await a.context.close();await b.context.close();await owner?.context.close();await stop(helper);helper=null;
    }
    const processRows=await processFacts(admin,url,bytes);
    for(const rows of Object.values(observations))rows.push(...processRows);
    const evidence=[await sourceEvidence('web/wasi/process.js',['fd_datasync: () => 0','fd_sync: () => 0']),await sourceEvidence('web/kernel/client.js',["exec([['supervise', run.file]]","exec([['init']]"])];
    success=true;return {observations,latencies,evidence,compiler:compilerEvidence??{dockerfile:'containers/compiler/Dockerfile'},browser:browser.version()};
  } finally {
    await browser?.close();await stop(helper);await stop(server);proxy?.close();
    if(podmanEnv) {
      const created=run('podman',['--cgroup-manager=cgroupfs','ps','-aq'],{env:podmanEnv}).trim().split('\n').filter(id=>id&&!initialContainers.has(id));
      if(created.length)run('podman',['--cgroup-manager=cgroupfs','rm','-f',...created],{env:podmanEnv,stdio:'ignore'});
    }
    await stop(podman);await log?.close();process.umask(previousMask);
    if(success)await rm(state,{recursive:true,force:true});
    else console.error('Failed run retained disposable state and logs at '+state);
  }
}
async function processFacts(admin,url) {
  const {page,context}=admin;
  await expect.poll(async()=>page.evaluate(()=>window.os.machineInit().then(s=>s.reaper?.state)),{timeout:60000}).toBe('running');
  const init=await page.evaluate(()=>window.os.machineInit());
  const initComm=await exec(page,'/usr/bin/cat',['/proc/1/cmdline']);
  const rows=[ok('startup','pid1','read /proc/1/cmdline',{comm:initComm.split('\0')[0].split('/').at(-1)}),ok('startup','ownership','inspect PID 1 and service launch owner',{role:'init-reaper',owner:'browser host/session',evidence:'web/kernel/client.js: boot() creates InitReaper and LoginStartup; window.os.machineInit().reaper.state',reaper:init.reaper.state})];
  const ps=async()=>(await checked(page,[{proc_poll:{pids:[]}}]))[0];
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
  rows.push(ok('gui-processes','ps','open Files/Mounts/Editor/Preview; inspect ps',{files_visible:await page.locator('#window-files').isVisible(),mounts_opened:true,editor_opened:true,preview_opened:true,
    images_with_files:before,images_with_mounts:mounts,images_with_editor:editor,images_with_preview:preview}));
  const tab=await context.newPage();await ready(tab,url);
  await page.evaluate(()=>{window.conformanceSleep=window.os.exec([{path:'/usr/bin/sleep',argv:['sleep','60']}],{cwd:'/',stdin:''});});
  await expect.poll(async()=>{const [rows]=await checked(tab,[{proc_poll:{pids:[]}}]);return rows.some(p=>p.name==='sleep'||p.comm==='sleep'||p.argv?.includes('sleep'));},{timeout:30000}).toBe(true);
  const [one]=await checked(page,[{proc_poll:{pids:[]}}]),[two]=await checked(tab,[{proc_poll:{pids:[]}}]);
  const sleep=one.find(p=>p.name==='sleep'||p.comm==='sleep'||p.argv?.includes('sleep'));
  rows.push(ok('tab-pids','visibility','start sleep in tab A; ps in tab B',{other_tab_pid_visible:two.some(p=>p.pid===sleep.pid)}));
  await checked(page,[{kill:{pid:String(sleep.pid),signal:15}}]);await tab.close();
  return rows;
}

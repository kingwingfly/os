// Explicit CDP integration: real directory drop, no OS/server state required.
import { chromium } from '@playwright/test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, writeFile, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { captureDirectoryDrop } from './fixtures.mjs';
import { ShutdownScope } from '../process.mjs';
const scope=new ShutdownScope();
let failure;
try {
  const dir=await mkdtemp(join(tmpdir(),'conformance-drop-'));scope.add('fixture',()=>rm(dir,{recursive:true,force:true}));
  await writeFile(join(dir,'source.txt'),'unchanged');
  const server=await scope.acquire('HTTP listener',()=>new Promise(resolve=>{const s=createServer((_req,res)=>res.end('<!doctype html><title>Drop fixture</title>'));s.listen(0,'127.0.0.1',()=>resolve(s));}),s=>new Promise(resolve=>s.close(resolve)));
  const browser=await scope.acquire('browser',()=>chromium.launch({channel:'chromium',headless:true,args:['--ozone-platform=headless','--use-gl=angle','--use-angle=swiftshader','--enable-unsafe-swiftshader']}),b=>b.close());
  const page=await browser.newPage();await page.goto('http://127.0.0.1:'+server.address().port);
  await page.evaluate(()=>{
    window.uploads=0;window.bubbled=0;
    // Register the application-style listener before the fixture, as in OS.
    addEventListener('drop',event=>{window.bubbled++;if(event.dataTransfer.files.length)dispatchEvent(new Event('os-files'));});
    addEventListener('os-files',()=>{window.uploads++;});
  });
  await page.evaluate(captureDirectoryDrop);
  const cdp=await page.context().newCDPSession(page);
  for(const type of ['dragEnter','dragOver','drop'])await cdp.send('Input.dispatchDragEvent',{type,x:100,y:100,data:{items:[],files:[dir],dragOperationsMask:1}});
  const result=await page.evaluate(async()=>({kind:(await window.conformanceHandle).kind,uploads:window.uploads,bubbled:window.bubbled}));
  assert.deepEqual(result,{kind:'directory',uploads:0,bubbled:0});
  assert.equal(await readFile(join(dir,'source.txt'),'utf8'),'unchanged');
  console.log('Chromium CDP drop acquired a real directory handle without triggering upload or bubbling handlers.');
} catch(error) {failure=error;throw error;} finally {const errors=await scope.close();if(errors.length&&!failure)throw new AggregateError(errors.map(e=>e.error),'browser gate cleanup');}

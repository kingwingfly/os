import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { api, mkdirp, program, put, rmrf } from './sys.js';
const origin=process.env.TERMINAL_TEST_URL || 'http://127.0.0.1:8787';
const password=(await readFile('.dev.vars','utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const headers={Origin:origin,'CF-Connecting-IP':'workspace-regression'};
const file=path=>'/api/file?path='+encodeURIComponent(path);
const run=async(page,text)=>{await expect(page.locator('.busy')).toHaveText('↵');const input=page.getByRole('combobox',{name:'Terminal command'});await input.fill(text);await input.press('Enter');};
const cmd=async(request,args)=>program(request,args);
function pdfBytes(){
 const objects=['<< /Type /Catalog /Pages 2 0 R >>','<< /Type /Pages /Kids [3 0 R 5 0 R] /Count 2 >>','<< /Type /Page /Parent 2 0 R /MediaBox [0 0 400 300] /Contents 4 0 R >>','<< /Length 33 >>\nstream\n0.2 0.6 0.3 rg 20 20 200 100 re f\nendstream','<< /Type /Page /Parent 2 0 R /MediaBox [0 0 400 300] /Contents 6 0 R >>','<< /Length 33 >>\nstream\n0.7 0.6 0.2 rg 20 20 100 200 re f\nendstream'];
 let text='%PDF-1.4\n',offsets=[0];for(let i=0;i<objects.length;i++){offsets.push(Buffer.byteLength(text));text+=`${i+1} 0 obj\n${objects[i]}\nendobj\n`;}
 const xref=Buffer.byteLength(text);text+=`xref\n0 ${objects.length+1}\n0000000000 65535 f \n`+offsets.slice(1).map(n=>String(n).padStart(10,'0')+' 00000 n \n').join('');text+=`trailer\n<< /Size ${objects.length+1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;return Buffer.from(text);
}

test('manual, large terminal, the dock, prompt/listing colors, icons and keyboard focus',async({page,request})=>{
 await page.goto('/');
 await expect(page.getByRole('combobox')).toHaveCSS('font-size','20px');
 await expect(page.locator('.transcript')).toHaveCSS('scrollbar-width','none');
 for(const width of [1440,390]){
  await page.setViewportSize({width,height:1000});
  // The dock focuses a window, minimizes the focused one, and brings it back.
  const files=page.getByRole('region',{name:'File manager',exact:true}),terminal=page.getByRole('region',{name:'Terminal',exact:true}),dock=name=>page.getByRole('navigation',{name:'Dock'}).getByRole('button',{name,exact:true});
  await dock('Files').click();await expect(files).toBeVisible();await expect(dock('Files')).toHaveAttribute('aria-pressed','true');
  await dock('Files').click();await expect(files).toBeHidden();await expect(terminal).toBeVisible();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  await dock('Files').click();await expect(files).toBeVisible();
  // A phone shows one window at a time.
  if(width<=650)await expect(terminal).toBeHidden();else await expect(terminal).toBeVisible();
  await dock('Terminal').click();await expect(terminal).toBeVisible();
 }
 // A phone shows the terminal as an app: the command line on the screen, the account on one line.
 const box=await page.getByRole('combobox').boundingBox();expect(box.y+box.height).toBeLessThanOrEqual(1000);
 expect(await page.locator('.lock').evaluate(e=>e.getBoundingClientRect().height<60)).toBe(true);
 await page.setViewportSize({width:1440,height:1000});
 await run(page,'ls');await expect(page.locator('.listing-output .entry-directory').first()).toBeVisible();await expect(page.locator('.listing-output svg').first()).toBeVisible();
 expect(await page.locator('.entry-directory').first().evaluate(e=>getComputedStyle(e).color)).not.toBe(await page.locator('.entry-file').first().evaluate(e=>getComputedStyle(e).color));
 await expect(page.locator('.command-echo .prompt-user').last()).toHaveText('guest');
 await run(page,'man chmod');await expect(page.locator('.manual h1')).toHaveText('chmod — change permissions');await expect(page.locator('.manual')).toContainText('o+r');
 // Pages have sections; options are a table.
 await expect(page.locator('.manual h2')).toHaveText(['Options','Permissions','Examples','See also']);await expect(page.locator('.manual table td').first()).toHaveText('-R, --recursive');
 const before=await page.getByRole('combobox').inputValue();await page.keyboard.type('xyz');expect(await page.getByRole('combobox').inputValue()).toBe(before);
 await page.getByRole('button',{name:'Close preview'}).click();
 await page.locator('.wordmark').click();await page.keyboard.type('pwd');await expect(page.getByRole('combobox')).toHaveValue('pwd');await page.keyboard.press('Enter');await expect(page.locator('.transcript pre').last()).toHaveText('/');
 await run(page,'login');await expect(page.getByLabel('Username',{exact:true})).toHaveCSS('background-color','rgb(8, 13, 10)');await page.getByLabel('Username',{exact:true}).fill('root');await page.getByLabel('Password',{exact:true}).fill(password);await page.locator('#auth button[type=submit]').click();await expect(page.locator('.lock')).toContainText('root');
 await page.screenshot({path:'test-results/workspace-desktop.png',fullPage:true});
});

test('vim edits highlighted Rust, saves conditionally, preserves conflicting drafts, and respects read-only permissions',async({page,request})=>{
 const base='/editor-'+Date.now();await api(request, 'login',{headers,data:{password}});await mkdirp(request, base);
 // Browser and fixture request intentionally have separate sessions.
 try{
  await page.goto('/');await run(page,'su root');await page.getByLabel('Password',{exact:true}).fill(password);await page.locator('#auth button[type=submit]').click();await expect(page.locator('.lock')).toContainText('root');
  await run(page,'vim '+base+'/main.rs');const content=page.getByRole('textbox',{name:'File contents'});await expect(content).toBeVisible();
  await content.fill('fn main() {\n    let answer = 42;\n}\n');await expect(page.locator('#editor-dirty')).toHaveText('Unsaved');
  await expect(page.locator('.cm-line span').first()).toBeVisible();
  await page.keyboard.press('Control+s');await expect(page.locator('#editor-status')).toHaveText('Saved');expect(await (await request.get(file(base+'/main.rs'))).text()).toContain('let answer = 42;');
  const original=await request.get(file(base+'/main.rs'));const etag=original.headers().etag;
  expect((await put(request, file(base+'/main.rs')+'&overwrite=true',{headers:{...headers,'If-Match':etag},data:'fn changed_elsewhere() {}'})).status()).toBe(200);
  await content.fill('fn unsaved_local() {}');await page.getByRole('button',{name:'Save Cmd / Ctrl S',exact:true}).click();await expect(page.locator('#editor-status')).toContainText('changed in another session');
  expect(await (await request.get(file(base+'/main.rs'))).text()).toBe('fn changed_elsewhere() {}');
  await page.getByRole('button',{name:'Close editor'}).click();await expect(page.getByRole('button',{name:'Discard changes'})).toBeVisible();await expect(content).toContainText('unsaved_local');await page.getByRole('button',{name:'Discard changes'}).click();await expect(page.locator('#editor')).toBeHidden();
  await run(page,'logout');await expect(page.locator('.lock')).toContainText('guest');
  await run(page,'vim '+base+'/main.rs');await expect(page.locator('#editor-status')).toContainText('Read-only');await expect(page.locator('#editor-save')).toBeDisabled();await expect(page.locator('.cm-content')).toHaveAttribute('contenteditable','false');
  await page.getByRole('button',{name:'Close editor'}).click();
 }finally{await rmrf(request, base);}
});

test('PDF pages and PNG/JPEG/WebP previews load through protected file APIs',async({page,request})=>{
 const base='/preview-'+Date.now();await api(request, 'login',{headers,data:{password}});await mkdirp(request, base);
 try{
  expect((await put(request, file(base+'/sample.pdf'),{headers,data:pdfBytes()})).status()).toBe(201);
  await page.goto('/');
  for(const [ext,mime] of [['png','image/png'],['jpeg','image/jpeg'],['webp','image/webp']]){
   const bytes=await page.evaluate(async mime=>{const canvas=document.createElement('canvas');canvas.width=8;canvas.height=8;canvas.getContext('2d').fillRect(0,0,8,8);return [...new Uint8Array(await(await fetch(canvas.toDataURL(mime))).arrayBuffer())];},mime);
   expect((await put(request, file(base+'/image.'+ext),{headers,data:Buffer.from(bytes)})).status()).toBe(201);
   await run(page,'open '+base+'/image.'+ext);await expect.poll(()=>page.locator('.media-frame img').evaluate(e=>e.naturalWidth)).toBe(8);await page.getByRole('button',{name:'Close preview'}).click();
  }
  // A PDF scrolls as one document, its pages drawn as they come near, and opens where it was left.
  await run(page,'open '+base+'/sample.pdf');await expect(page.getByLabel('PDF page 1')).toBeVisible();await expect(page.locator('.pdf-toolbar [role=status]')).toHaveText('1 / 2');
  await expect.poll(()=>page.locator('.pdf-page').evaluateAll(pages=>pages.filter(p=>p.width>0).length)).toBe(2);
  await page.getByRole('button',{name:'Next page'}).click();await expect(page.locator('.pdf-toolbar [role=status]')).toHaveText('2 / 2');await page.getByRole('button',{name:'Close preview'}).click();await expect(page.locator('#viewer')).toBeHidden();
  await run(page,'open '+base+'/sample.pdf');await expect(page.locator('.pdf-toolbar [role=status]')).toHaveText('2 / 2');await page.getByRole('button',{name:'Close preview'}).click();
 }finally{await rmrf(request, base);}
});

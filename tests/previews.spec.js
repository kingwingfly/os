import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { crc32, gzipSync } from 'node:zlib';
import { api, mkdirp, put, rmrf } from './sys.js';
const origin=process.env.TERMINAL_TEST_URL || 'http://127.0.0.1:8787';
const password=(await readFile('.dev.vars','utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const headers={Origin:origin,'CF-Connecting-IP':'preview-regression'};
const file=path=>'/api/file?path='+encodeURIComponent(path);
const run=async(page,text)=>{await expect(page.locator('.busy')).toHaveText('↵');const input=page.getByRole('combobox',{name:'Terminal command'});await input.fill(text);await input.press('Enter');};
const close=async page=>{await page.getByRole('button',{name:'Close preview'}).click();await expect(page.locator('#viewer')).toBeHidden();};
// A ZIP archive of stored files, and a tar archive, as their formats lay them out.
function zip(files){
 const parts=[],central=[];let offset=0;
 for(const [name,text] of files){
  const data=Buffer.from(text),path=Buffer.from(name),crc=crc32(data);
  const local=Buffer.alloc(30);local.writeUInt32LE(0x04034b50,0);local.writeUInt16LE(20,4);local.writeUInt32LE(crc,14);local.writeUInt32LE(data.length,18);local.writeUInt32LE(data.length,22);local.writeUInt16LE(path.length,26);
  const entry=Buffer.alloc(46);entry.writeUInt32LE(0x02014b50,0);entry.writeUInt16LE(20,4);entry.writeUInt16LE(20,6);entry.writeUInt32LE(crc,16);entry.writeUInt32LE(data.length,20);entry.writeUInt32LE(data.length,24);entry.writeUInt16LE(path.length,28);entry.writeUInt32LE(offset,42);
  parts.push(local,path,data);central.push(entry,path);offset+=30+path.length+data.length;
 }
 const directory=Buffer.concat(central),end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50,0);end.writeUInt16LE(files.length,8);end.writeUInt16LE(files.length,10);end.writeUInt32LE(directory.length,12);end.writeUInt32LE(offset,16);
 return Buffer.concat([...parts,directory,end]);
}
function tar(files){
 const blocks=[];
 for(const [name,text] of files){
  const data=Buffer.from(text),header=Buffer.alloc(512);
  header.write(name,0);header.write('0000644\0',100);header.write('0000000\0',108);header.write('0000000\0',116);header.write(data.length.toString(8).padStart(11,'0')+'\0',124);header.write('00000000000\0',136);header.write('        ',148);header.write('0',156);header.write('ustar\0',257);header.write('00',263);
  let sum=0;for(const byte of header)sum+=byte;header.write(sum.toString(8).padStart(6,'0')+'\0 ',148);
  blocks.push(header,data,Buffer.alloc((512-data.length%512)%512));
 }
 return Buffer.concat([...blocks,Buffer.alloc(1024)]);
}
function pdf(){
 const objects=['<< /Type /Catalog /Pages 2 0 R >>','<< /Type /Pages /Kids [3 0 R] /Count 1 >>','<< /Type /Page /Parent 2 0 R /MediaBox [0 0 400 300] /Contents 4 0 R >>','<< /Length 33 >>\nstream\n0.2 0.6 0.3 rg 20 20 200 100 re f\nendstream'];
 let text='%PDF-1.4\n',offsets=[];for(let i=0;i<objects.length;i++){offsets.push(Buffer.byteLength(text));text+=`${i+1} 0 obj\n${objects[i]}\nendobj\n`;}
 const xref=Buffer.byteLength(text);text+=`xref\n0 ${objects.length+1}\n0000000000 65535 f \n`+offsets.map(n=>String(n).padStart(10,'0')+' 00000 n \n').join('');text+=`trailer\n<< /Size ${objects.length+1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
 return Buffer.from(text);
}

test('Rust previews: highlighted code, diagrams, maths, links within the filesystem, tables, archives, cards, diffs, SVG and slides',async({page,request})=>{
 const base='/previews-'+Date.now();await api(request, 'login',{headers,data:{password}});await mkdirp(request, base);
 try{
  const files={
   'doc.md':'# Previews\n\n[Other notes](other.md) and [the web](https://example.com).\n\n![pixel](img/pixel.png) ![logo](logo.svg)\n\n```rust\nfn main() {\n    println!("hi");\n}\n```\n\n```mermaid\nflowchart LR\n  A[Alice] --> B[Bob]\n```\n\nInline $a^2 + b^2 = c^2$.\n\n- [x] done\n',
   'other.md':'# Other\n\nReached by a relative link.\n',
   'main.rs':'// héllo κόσμε € 😀\nfn main() {\n    let s = "wörld";\n}\n',
   'data.csv':'name,role\n"Doe, Jane",admin\nBob,user\n',
   'contact.vcf':'BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Jane Doe\r\nEMAIL:jane@example.com\r\nEND:VCARD\r\n',
   'event.ics':'BEGIN:VCALENDAR\nBEGIN:VEVENT\nSUMMARY:Lab meeting\nDTSTART:20261028T140000Z\nLOCATION:Room 2\nEND:VEVENT\nEND:VCALENDAR\n',
   'change.diff':'diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1,2 +1,2 @@\n-old line\n+new line\n same\n',
   'logo.svg':'<svg xmlns="http://www.w3.org/2000/svg" width="40" height="20"><script>window.svgRan=true</script><rect width="40" height="20" fill="#9ae6b5"/></svg>',
   'deck.slides.md':'# One\n\n```yaml\n---\nkey: value\n```\n\n---\n\n# Two\n\n--\n\n# Two, below\n\nNote: not shown\n',
  };
  for(const [name,text] of Object.entries(files))expect((await put(request, file(base+'/'+name),{headers,data:Buffer.from(text)})).status()).toBe(201);
  await mkdirp(request, base+'/img');
  expect((await put(request, file(base+'/img/pixel.png'),{headers,data:await readFile('tests/fixtures/pixel.png')})).status()).toBe(201);
  expect((await put(request, file(base+'/bundle.zip'),{headers,data:zip([['src/main.rs','fn main() {}'],['notes.txt','hello']])})).status()).toBe(201);
  expect((await put(request, file(base+'/bundle.tar.gz'),{headers,data:gzipSync(tar([['docs/a.txt','alpha']]))})).status()).toBe(201);
  expect((await put(request, file(base+'/one.pdf'),{headers,data:pdf()})).status()).toBe(201);

  const errors=[],loaded=[];page.on('pageerror',e=>errors.push(e.message));
  page.on('request',r=>{const worker=r.url().match(/\/(preview_[a-z_]+)_loader\.js$/);if(worker)loaded.push(worker[1]);});
  await page.goto('/');

  await run(page,'open '+base+'/doc.md');
  await expect(page.locator('.markdown h1')).toHaveText('Previews');
  await expect(page.locator('.markdown code .hl-keyword').first()).toHaveText('fn');
  await expect(page.locator('.markdown img.diagram')).toHaveAttribute('src',/^data:image\/svg\+xml/);
  await expect(page.locator('.markdown math')).toHaveCount(1);
  await expect.poll(()=>page.locator('.markdown img[alt=pixel]').evaluate(e=>e.naturalWidth)).toBe(1);
  // An SVG shows as an image, whose script does not run; opened by itself, it is sandboxed and downloads.
  await expect.poll(()=>page.locator('.markdown img[alt=logo]').evaluate(e=>e.naturalWidth)).toBe(40);
  expect(await page.evaluate(()=>window.svgRan)).toBeUndefined();
  const svg=(await request.get(file(base+'/logo.svg'),{headers})).headers();
  expect(svg['content-type']).toBe('image/svg+xml');expect(svg['content-security-policy']).toBe("default-src 'none'; sandbox");expect(svg['content-disposition']).toBe('attachment');
  expect(await page.locator('.markdown a',{hasText:'the web'}).getAttribute('target')).toBe('_blank');
  await expect(page.locator('.markdown')).toContainText('☑ done');
  expect(loaded.sort()).toEqual(['preview_code_systems','preview_diagram']);
  await page.locator('.markdown a',{hasText:'Other notes'}).click();
  await expect(page.locator('#viewer-title')).toHaveText(base+'/other.md');await expect(page.locator('.markdown h1')).toHaveText('Other');
  await close(page);

  await run(page,'open '+base+'/main.rs');
  await expect(page.locator('.text-preview .hl-keyword').first()).toBeVisible();
  expect(await page.locator('.text-preview .hl-keyword').allTextContents()).toEqual(['fn','let']);
  await expect(page.locator('.text-preview .hl-string')).toHaveText('"wörld"');
  await close(page);

  await run(page,'open '+base+'/data.csv');await expect(page.locator('.table-preview td')).toHaveText(['Doe, Jane','admin','Bob','user']);await close(page);
  await run(page,'open '+base+'/bundle.zip');await expect(page.locator('.archive li',{hasText:'src/main.rs'})).toBeVisible();await close(page);
  await run(page,'open '+base+'/bundle.tar.gz');await expect(page.locator('.archive li',{hasText:'docs/a.txt'})).toBeVisible();await close(page);
  expect(loaded).toContain('preview_archive');
  await run(page,'open '+base+'/contact.vcf');await expect(page.locator('.card h3')).toHaveText('Jane Doe');await close(page);
  await run(page,'open '+base+'/event.ics');await expect(page.locator('.card dd',{hasText:'2026-10-28 14:00 UTC'})).toBeVisible();await close(page);
  await run(page,'open '+base+'/change.diff');await expect(page.locator('.diff-added')).toHaveText('+new line');await close(page);

  await run(page,'open '+base+'/logo.svg');
  await expect(page.locator('.media-frame img')).toHaveAttribute('src',/^data:image\/svg\+xml/);
  await expect.poll(()=>page.locator('.media-frame img').evaluate(e=>e.naturalWidth)).toBe(40);
  expect(await page.evaluate(()=>window.svgRan)).toBeUndefined();
  await close(page);

  await run(page,'open '+base+'/deck.slides.md');
  await expect(page.locator('.slides-current .slide:visible h1')).toHaveText('One');
  // The separator in the code block is code.
  await expect(page.locator('.slides-current .slide:visible pre')).toContainText('key: value');
  expect(Number(await page.locator('.slides-current').evaluate(e=>getComputedStyle(e).getPropertyValue('--scale')))).toBeGreaterThan(0.5);
  await page.keyboard.press('ArrowRight');await expect(page.locator('.slides-current .slide:visible h1')).toHaveText('Two');
  await page.keyboard.press('ArrowDown');await expect(page.locator('.slides-current .slide:visible h1')).toHaveText('Two, below');
  await expect(page.locator('.slides-current .slide:visible')).not.toContainText('not shown');
  await expect(page.locator('.slides-bar [role=status]')).toHaveText('2 / 2 · 2 / 2');
  await close(page);

  await run(page,'open '+base+'/one.pdf');await expect(page.locator('.pdf-toolbar [role=status]')).toHaveText('1 / 1');await expect(page.locator('.pdf-page')).toBeVisible();
  await expect(page.getByRole('button',{name:'Next page'})).toBeDisabled();await close(page);
  expect(loaded).toContain('preview_pdf');
  expect(errors).toEqual([]);
 }finally{await rmrf(request, base);}
});

test('a link opens another file with a way back; slides, PDFs and text open where they were left; slide themes',async({page,request})=>{
 const base='/viewer-'+Date.now();await api(request, 'login',{headers,data:{password}});await mkdirp(request, base);
 try{
  const files={'deck.slides.md':'# One\n\n[notes](notes.md)\n\n---\n\n# Two\n\n---\n\n# Three\n','notes.md':'# Notes\n\nReached by a link.\n','long.txt':'line\n'.repeat(400)};
  for(const [name,text] of Object.entries(files))expect((await put(request, file(base+'/'+name),{headers,data:Buffer.from(text)})).status()).toBe(201);
  await page.goto('/');
  const status=page.locator('.slides-bar [role=status]'),theme=page.getByRole('combobox',{name:'Slide theme'});
  await run(page,'open '+base+'/deck.slides.md');await expect(page.locator('.slides-current .slide:visible')).toContainText('One');
  // Slides look like a presentation, light by default, in a theme chosen for every deck.
  await expect(page.locator('.slides')).toHaveAttribute('data-theme','light');await expect(theme).toHaveValue('light');
  await theme.selectOption('sepia');await expect(page.locator('.slides')).toHaveAttribute('data-theme','sepia');
  // A link opens its file in the viewer, and Back returns, to the slide it was on.
  await expect(page.locator('#viewer-back')).toBeHidden();
  await page.locator('.slides a',{hasText:'notes'}).click();
  await expect(page.locator('#viewer-title')).toHaveText(base+'/notes.md');await expect(page.locator('.markdown h1')).toHaveText('Notes');
  await page.getByRole('button',{name:'Back'}).click();
  await expect(page.locator('#viewer-title')).toHaveText(base+'/deck.slides.md');await expect(page.locator('#viewer-back')).toBeHidden();await expect(status).toHaveText('1 / 3');
  // Opened again, the deck continues at its slide, in its theme.
  await page.keyboard.press('ArrowRight');await page.keyboard.press('ArrowRight');await expect(status).toHaveText('3 / 3');
  await close(page);
  await run(page,'open '+base+'/deck.slides.md');await expect(status).toHaveText('3 / 3');await expect(theme).toHaveValue('sepia');
  await close(page);
  // Text opens scrolled where it was left.
  await run(page,'open '+base+'/long.txt');await expect(page.locator('.text-preview')).toBeVisible();
  await page.locator('#viewer-content').evaluate(content=>{content.scrollTop=2000;});
  await close(page);
  await run(page,'open '+base+'/long.txt');await expect(page.locator('.text-preview')).toBeVisible();
  await expect.poll(()=>page.locator('#viewer-content').evaluate(content=>content.scrollTop)).toBeGreaterThan(1500);
  await close(page);
 }finally{await rmrf(request, base);}
});

// A gzipped tar of one member of `size` zero bytes: gzip members of a mebibyte each, which a
// decompressor reads one after another, so that it is small to make and to send.
function expanding(size){
 const header=Buffer.alloc(512);
 header.write('large.txt',0);header.write('0000644\0',100);header.write('0000000\0',108);header.write('0000000\0',116);header.write(size.toString(8).padStart(11,'0')+'\0',124);header.write('00000000000\0',136);header.write('        ',148);header.write('0',156);header.write('ustar\0',257);header.write('00',263);
 let sum=0;for(const byte of header)sum+=byte;header.write(sum.toString(8).padStart(6,'0')+'\0 ',148);
 const mebibyte=gzipSync(Buffer.alloc(1<<20)),whole=Math.floor(size/(1<<20)),rest=size-whole*(1<<20);
 return Buffer.concat([gzipSync(header),...Array(whole).fill(mebibyte),gzipSync(Buffer.alloc(rest+(512-size%512)%512+1024))]);
}

test('an archive is listed off the page, within what it may expand to; a worker that cannot start says so, and starts again',async({page,context,request})=>{
 const base='/preview-workers-'+Date.now();await api(request, 'login',{headers,data:{password}});await mkdirp(request, base);
 try{
  expect((await put(request, file(base+'/expanded.tgz'),{headers,data:expanding(1_200_000_000)})).status()).toBe(201);
  expect((await put(request, file(base+'/one.pdf'),{headers,data:pdf()})).status()).toBe(201);
  await context.route('**/preview_pdf_bg.wasm',route=>route.fulfill({status:404,body:'gone'}));
  await page.goto('/');
  await page.evaluate(()=>{window.longest=0;new PerformanceObserver(list=>{for(const task of list.getEntries())window.longest=Math.max(window.longest,task.duration);}).observe({type:'longtask'});});
  // While its worker reads it, the page goes on: the preview closes at once.
  await run(page,'open '+base+'/expanded.tgz');await expect(page.locator('#viewer-content')).toContainText('Listing the archive...');
  const closing=Date.now();await close(page);expect(Date.now()-closing).toBeLessThan(2000);
  await run(page,'open '+base+'/expanded.tgz');
  await expect(page.locator('#viewer-content .no-preview')).toHaveText('Could not list the archive: the archive expands to more than 1 GB, more than the terminal lists',{timeout:60_000});
  await close(page);
  expect(await page.evaluate(()=>window.longest)).toBeLessThan(1000);
  // Its code missing, the PDF worker says why; once it is there, the next PDF opens.
  await run(page,'open '+base+'/one.pdf');
  await expect(page.locator('.pdf-toolbar [role=status]')).toContainText('Could not open PDF: the preview could not start',{timeout:30_000});
  await close(page);
  await context.unroute('**/preview_pdf_bg.wasm');
  await run(page,'open '+base+'/one.pdf');await expect(page.locator('.pdf-toolbar [role=status]')).toHaveText('1 / 1');await expect(page.locator('.pdf-page')).toBeVisible();
  await close(page);
 }finally{await rmrf(request, base);}
});

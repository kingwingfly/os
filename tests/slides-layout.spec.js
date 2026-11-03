import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { resolve, extname } from 'node:path';
import { fakeKernel } from './sys.js';

// Exercise the real Rust preview and shipped CSS without accounts, an R2 upload or a dev server.
test('image-only slides fit the preview and fullscreen without shrinking into Markdown', async ({ page }) => {
  const source='![Wide slide](wide.svg)\n\nNote:\nSpeaker notes.\n\n---\n\n![Portrait slide](portrait.svg)\n\n---\n\nA caption ![Inline image](wide.svg)\n\n---\n\n# A heading\n\n![Illustration](wide.svg)\n';
  const entry={name:'fit.slides.md',path:'/fit.slides.md',directory:false,kind:'slides',size:source.length,mode:420,owner:'guest',group:'guest',readable:true,writable:false};
  await page.routeWebSocket('**/api/events',()=>{});
  await page.route('**/*',async route=>{
    const url=new URL(route.request().url());
    if(url.pathname==='/api/session')return route.fulfill({json:{authenticated:false,username:'guest',uid:65534,home:'/guest',can_write:false}});
    if(url.pathname==='/api/sys')return fakeKernel({'/fit.slides.md':{size:source.length}})(route);
    if(url.pathname==='/api/file'){
      const path=url.searchParams.get('path');
      if(path==='/fit.slides.md')return route.fulfill({body:source,contentType:'text/markdown'});
      const [w,h]=path==='/portrait.svg'?[900,1600]:[1600,900];
      return route.fulfill({body:`<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}"><rect width="100%" height="100%" fill="#091012"/><text x="60" y="120" fill="#76c2aa" font-size="64">Presentation frame</text></svg>`,contentType:'image/svg+xml'});
    }
    if(url.pathname.startsWith('/api/'))return route.fulfill({status:404,json:{error:'Unexpected test request'}});
    const path=resolve('dist','.'+(url.pathname==='/'?'/index.html':decodeURIComponent(url.pathname)));
    if(!path.startsWith(resolve('dist')+'/'))return route.fulfill({status:403});
    const mime={'.html':'text/html','.js':'application/javascript','.json':'application/json','.css':'text/css','.wasm':'application/wasm'}[extname(path)]||'application/octet-stream';
    try{return await route.fulfill({body:await readFile(path),contentType:mime});}catch{return route.fulfill({status:404});}
  });
  await page.goto('/');
  const input=page.getByRole('combobox',{name:'Terminal command'});
  await input.fill('open /fit.slides.md');await input.press('Enter');
  const slide=page.locator('.slides-current .slide:visible'),image=slide.locator('img');
  await expect(slide).toHaveClass(/slide-image/);
  const fitted=async()=>{
    await expect.poll(()=>image.evaluate(e=>e.naturalWidth)).toBeGreaterThan(0);
    await expect.poll(()=>image.evaluate(e=>{
      const stage=e.closest('.enhanced').getBoundingClientRect(),frame=e.getBoundingClientRect();
      return Math.abs(frame.x-stage.x)+Math.abs(frame.y-stage.y)+Math.abs(frame.width-stage.width)+Math.abs(frame.height-stage.height);
    })).toBeLessThan(4);
    await expect(image).toHaveCSS('object-fit','contain');
    await expect.poll(()=>slide.evaluate(e=>getComputedStyle(e).zoom)).toBe('1');
    expect(await slide.evaluate(e=>e.scrollHeight-e.clientHeight)).toBeLessThan(2);
  };
  for(const size of [{width:1920,height:1080},{width:1280,height:800},{width:390,height:844}]){
    await page.setViewportSize(size);await fitted();
    await page.getByRole('button',{name:'Fullscreen',exact:true}).click();
    await expect.poll(()=>page.evaluate(()=>document.fullscreenElement?.id)).toBe('viewer-surface');
    await fitted();
    if(size.width===1920)expect((await image.boundingBox()).height).toBeGreaterThan(1000);
    await page.evaluate(()=>document.exitFullscreen());
    await expect.poll(()=>page.evaluate(()=>document.fullscreenElement===null)).toBe(true);
  }
  await page.keyboard.press('ArrowRight');await expect(image).toHaveAttribute('alt','Portrait slide');await fitted();
  await page.keyboard.press('ArrowRight');await expect(slide).not.toHaveClass(/slide-image/);await expect(slide).toContainText('A caption');await expect(image).toHaveCSS('max-height','460px');
  await page.keyboard.press('ArrowRight');await expect(slide.locator('h1')).toHaveText('A heading');await expect(slide).not.toHaveClass(/slide-image/);
});

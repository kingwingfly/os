import { test, expect, request as playwrightRequest } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { api, mkdirp, names, program, put, rmrf, sys } from './sys.js';
const origin = process.env.TERMINAL_TEST_URL || 'http://127.0.0.1:8787';
const rootPassword = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const file = path => '/api/file?path=' + encodeURIComponent(path);
let sequence = 0;
const address = name => `presenting-${name}-${Date.now()}-${++sequence}`;
const deck = '# One\n\n![Figure](figure.svg)\n\nNote:\nSay **one**.\n\n---\n\n# Two\n\nNote: Say two.\n\n--\n\n# Two, below\n\n---\n\n# Three\n';
const figure = '<svg xmlns="http://www.w3.org/2000/svg" width="800" height="450"><rect width="100%" height="100%" fill="#2a6"/></svg>';
// A PDF of three pages, each of its own color.
function pdf() {
  const colors = ['0.2 0.6 0.3', '0.7 0.6 0.2', '0.2 0.3 0.7'], kids = colors.map((_, i) => `${3 + 2 * i} 0 R`).join(' ');
  const objects = ['<< /Type /Catalog /Pages 2 0 R >>', `<< /Type /Pages /Kids [${kids}] /Count 3 >>`];
  colors.forEach((color, i) => {
    const content = `${color} rg 0 0 400 300 re f`;
    objects.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 400 300] /Contents ${4 + 2 * i} 0 R >>`, `<< /Length ${content.length} >>\nstream\n${content}\nendstream`);
  });
  let text = '%PDF-1.4\n'; const offsets = [];
  objects.forEach((object, i) => { offsets.push(Buffer.byteLength(text)); text += `${i + 1} 0 obj\n${object}\nendobj\n`; });
  const xref = Buffer.byteLength(text);
  text += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n` + offsets.map(n => String(n).padStart(10, '0') + ' 00000 n \n').join('');
  return Buffer.from(text + `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`);
}

const busy = page => page.locator('.terminal-panel:not([hidden]) .busy');
async function run(page, text) {
  await expect(busy(page)).toHaveText('↵');
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  await input.fill(text); await input.press('Enter');
}
const shown = page => page.locator('.slides-current .slide:visible');
const status = page => page.locator('.slides-bar [role=status]');
// A page of a browser of its own, signed in through the API, or a guest's.
async function device(browser, username, password, prepare = async () => {}) {
  const context = await browser.newContext({ extraHTTPHeaders: { 'CF-Connecting-IP': address(username || 'guest') } });
  if (username) expect((await api(context.request, 'login', { headers: { Origin: origin }, data: { username, password } })).ok()).toBe(true);
  const page = await context.newPage(); await prepare(page); await page.goto(origin + '/');
  await expect(page.locator('.lock')).toContainText(username || 'guest');
  return { context, page };
}

let root, base;
test.beforeAll(async () => {
  root = await playwrightRequest.newContext({ baseURL: origin, extraHTTPHeaders: { Origin: origin, 'CF-Connecting-IP': address('api') } });
  expect((await api(root, 'login', { data: { password: rootPassword } })).ok()).toBe(true);
  base = '/presenting-' + Date.now().toString(36);
  await mkdirp(root, base);
  for (const [name, data] of [['deck.slides.md', deck], ['other.slides.md', '# Bee\n\n---\n\n# Bee two\n'], ['third.slides.md', '# Sea\n'], ['figure.svg', figure], ['pages.pdf', pdf()]]) expect((await put(root, file(base + '/' + name), { data })).status()).toBe(201);
});
test.afterAll(async () => { await rmrf(root, base); await root.dispose(); });

test('slides go in order, by number and from an overview; images enlarge; the speaker view shows notes, the next slide and a clock', async ({ page }) => {
  await page.goto('/');
  await run(page, `open ${base}/deck.slides.md`);
  await expect(shown(page).locator('h1')).toHaveText('One');
  // Space, Page Up and Down, N and P go through every slide in order, those below others too.
  for (const [key, title] of [['Space', 'Two'], ['Space', 'Two, below'], ['PageDown', 'Three'], ['Shift+Space', 'Two, below'], ['p', 'Two'], ['n', 'Two, below'], ['PageUp', 'Two'], ['Home', 'One'], ['End', 'Three']]) {
    await page.keyboard.press(key); await expect(shown(page).locator('h1')).toHaveText(title);
  }
  // G asks for a slide by its number; one the deck lacks is said so.
  await page.keyboard.press('g');
  const jump = page.getByRole('textbox', { name: 'Go to slide' });
  await expect(jump).toBeFocused(); await page.keyboard.type('2.2'); await page.keyboard.press('Enter');
  await expect(shown(page).locator('h1')).toHaveText('Two, below'); await expect(status(page)).toHaveText('2 / 3 · 2 / 2');
  await page.keyboard.press('g'); await page.keyboard.type('9'); await page.keyboard.press('Enter');
  await expect(status(page)).toHaveText('No such slide');
  // The overview shows every slide, the one shown marked; Escape closes it, not the viewer.
  await page.keyboard.press('o');
  const overview = page.locator('.slides-overview');
  await expect(overview.locator('.slides-thumb')).toHaveCount(4);
  await expect(overview.locator('.slides-thumb.current')).toHaveAttribute('aria-label', 'Slide 2.2');
  await page.keyboard.press('Escape');
  await expect(overview).toBeHidden(); await expect(page.locator('#viewer')).toBeVisible();
  await page.getByRole('button', { name: 'Overview' }).click();
  await page.getByRole('button', { name: 'Slide 3', exact: true }).click();
  await expect(overview).toBeHidden(); await expect(shown(page).locator('h1')).toHaveText('Three');
  // Slides near the one shown are drawn ahead and kept: the image of the first is the same one,
  // loaded already, when the deck comes back to it.
  await page.keyboard.press('Home');
  await expect.poll(() => shown(page).locator('img').evaluate(image => image.naturalWidth)).toBeGreaterThan(0);
  await page.evaluate(() => { window.kept = document.querySelector('.slides-current .slide-frame:not([hidden]) img'); });
  await page.keyboard.press('End'); await page.keyboard.press('Home');
  expect(await page.evaluate(() => window.kept.isConnected && window.kept === document.querySelector('.slides-current .slide-frame:not([hidden]) img'))).toBe(true);
  // A click on an image shows it large; Escape closes that, and only that.
  await shown(page).locator('img').click();
  await expect(page.locator('.slides-enlarged img')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.locator('.slides-enlarged')).toBeHidden(); await expect(page.locator('#viewer')).toBeVisible();
  // A swipe left goes on.
  const swipe = (from, to) => page.locator('.slides-body').evaluate((body, [from, to]) => {
    const at = x => ({ pointerType: 'touch', clientX: x, clientY: 300, bubbles: true });
    body.dispatchEvent(new PointerEvent('pointerdown', at(from))); body.dispatchEvent(new PointerEvent('pointerup', at(to)));
  }, [from, to]);
  await swipe(700, 500); await expect(shown(page).locator('h1')).toHaveText('Two');
  await swipe(500, 700); await expect(shown(page).locator('h1')).toHaveText('One');
  // The speaker view: this slide's notes, the next slide, the time.
  await page.getByRole('button', { name: 'Speaker view' }).click();
  const speaker = page.locator('.slides-speaker');
  await expect(speaker.locator('.slides-notes strong')).toHaveText('one');
  await expect(speaker.locator('.slides-next .slide:visible h1')).toHaveText('Two');
  await expect(speaker.locator('.slides-elapsed')).toHaveText(/^\d\d:\d\d$/);
  await page.keyboard.press('ArrowRight');
  await expect(speaker.locator('.slides-notes')).toHaveText('Say two.');
  await expect(speaker.locator('.slides-next .slide:visible h1')).toHaveText('Two, below');
  await page.keyboard.press('End');
  await expect(speaker.locator('.slides-notes')).toHaveText('No notes for this slide.');
  await expect(speaker.locator('.slides-end')).toHaveText('End of the deck');
  const size = () => speaker.locator('.slides-notes').evaluate(notes => getComputedStyle(notes).fontSize);
  const before = parseInt(await size());
  await page.getByRole('button', { name: 'Larger notes' }).click();
  await expect.poll(async () => parseInt(await size())).toBe(before + 2);
  await page.getByRole('button', { name: 'Smaller notes' }).click();
});

test('the overview lays its thumbnails out in rows, none over another, wide and on a phone', async ({ page }) => {
  const path = `${base}/many.slides.md`;
  expect((await put(root, file(path), { data: Array.from({ length: 30 }, (_, i) => `# Slide ${i + 1}`).join('\n\n---\n\n') })).status()).toBe(201);
  await page.goto('/');
  await run(page, `open ${path}`);
  await expect(shown(page).locator('h1')).toHaveText('Slide 1');
  for (const size of [{ width: 1440, height: 1000 }, { width: 390, height: 844 }]) {
    await page.setViewportSize(size);
    await page.keyboard.press('o');
    const thumbs = page.locator('.slides-overview .slides-thumb');
    await expect(thumbs).toHaveCount(30);
    const boxes = await thumbs.evaluateAll(all => all.map(e => { const r = e.getBoundingClientRect(); return [r.x, r.y, r.width, r.height]; }));
    const over = boxes.flatMap((a, i) => boxes.slice(i + 1).filter(b => a[0] < b[0] + b[2] && b[0] < a[0] + a[2] && a[1] < b[1] + b[3] && b[1] < a[1] + a[3]));
    expect(over).toEqual([]);
    // Each as wide as a slide is: 16 by 9.
    expect(Math.abs(boxes[0][3] - boxes[0][2] * 9 / 16)).toBeLessThan(2);
    await page.keyboard.press('Escape'); await expect(thumbs).toHaveCount(0);
  }
  await rmrf(root, path);
});

test('S opens the speaker view in a window of its own, and the two windows follow each other', async ({ page }) => {
  await page.goto('/');
  await run(page, `open ${base}/deck.slides.md`);
  await page.keyboard.press('Home'); await expect(shown(page).locator('h1')).toHaveText('One');
  const opening = page.waitForEvent('popup');
  await page.keyboard.press('s');
  const speaker = await opening;
  await expect(speaker).toHaveTitle('Speaker view · deck.slides.md');
  await expect(speaker.locator('.slides-speaker .slides-notes strong')).toHaveText('one');
  await expect(speaker.locator('#viewer-title')).toHaveText(base + '/deck.slides.md');
  // Turned in either, both show it.
  await speaker.keyboard.press('ArrowRight');
  await expect(shown(page).locator('h1')).toHaveText('Two');
  await page.keyboard.press('ArrowDown');
  await expect(shown(speaker).locator('h1')).toHaveText('Two, below');
  await expect(speaker.locator('.slides-notes')).toHaveText('No notes for this slide.');
  // S again shows the window open already.
  await page.keyboard.press('s');
  await page.waitForTimeout(300);
  expect(page.context().pages()).toHaveLength(2);
  // Pressed in another deck, it takes that window to this deck.
  await page.getByRole('button', { name: 'Close preview' }).click();
  await run(page, `open ${base}/other.slides.md`);
  await expect(shown(page).locator('h1')).toHaveText('Bee');
  await page.keyboard.press('s');
  await expect(speaker).toHaveTitle('Speaker view · other.slides.md');
  await expect(shown(speaker).locator('h1')).toHaveText('Bee');
  expect(page.context().pages()).toHaveLength(2);
  await page.keyboard.press('ArrowRight');
  await expect(shown(speaker).locator('h1')).toHaveText('Bee two');
  await speaker.close();
});

test('the pages of one account signed in on other devices follow the slide presented, and no one else', async ({ browser }) => {
  const name = 'present' + Date.now().toString(36), password = 'presenting-password-' + Date.now();
  const command = args => program(root, args);
  expect((await command(['useradd', '-m', name])).ok()).toBe(true);
  expect((await api(root, 'passwd', { data: { username: name, password } })).ok()).toBe(true);
  const laptop = await device(browser, name, password), phone = await device(browser, name, password);
  const guest = await device(browser), other = await device(browser, 'root', rootPassword);
  try {
    for (const { page } of [laptop, phone, guest, other]) {
      await run(page, `open ${base}/deck.slides.md`);
      await page.keyboard.press('Home'); await expect(shown(page).locator('h1')).toHaveText('One');
    }
    await phone.page.keyboard.press('ArrowRight');
    await expect(shown(laptop.page).locator('h1')).toHaveText('Two');
    await laptop.page.keyboard.press('ArrowDown');
    await expect(shown(phone.page).locator('h1')).toHaveText('Two, below');
    // A guest is anyone signed out, and another account is someone else: neither follows, and
    // what they show, nobody follows.
    await guest.page.keyboard.press('End'); await other.page.keyboard.press('End');
    await laptop.page.waitForTimeout(1000);
    for (const page of [guest.page, other.page]) await expect(shown(page).locator('h1')).toHaveText('Three');
    await expect(shown(laptop.page).locator('h1')).toHaveText('Two, below');
    await laptop.page.keyboard.press('Home');
    await expect(shown(phone.page).locator('h1')).toHaveText('One');
    await other.page.waitForTimeout(500);
    for (const page of [guest.page, other.page]) await expect(shown(page).locator('h1')).toHaveText('Three');
  } finally {
    await command(['userdel', '-r', name]);
    for (const { context } of [laptop, phone, guest, other]) await context.close();
  }
});

test('a PDF presented shows one page at a time, filling the view, turned as slides are and followed by other windows', async ({ page, context }) => {
  await page.goto('/');
  await run(page, `open ${base}/pages.pdf`);
  const pdfStatus = p => p.locator('.pdf-toolbar [role=status]');
  await expect(pdfStatus(page)).toHaveText('1 / 3');
  // The toolbar's buttons are of one size, and the mode's stays where it is as the mode changes.
  const sizes = await page.locator('.pdf-toolbar button:visible').evaluateAll(all => [...new Set(all.map(e => Math.round(e.getBoundingClientRect().height)))]);
  expect(sizes).toHaveLength(1);
  const mode = page.locator('.pdf-present-button'), at = await mode.boundingBox();
  await page.getByRole('button', { name: 'Present one page at a time' }).click();
  await expect(mode).toHaveAttribute('aria-pressed', 'true');
  expect(await mode.boundingBox()).toEqual(at);
  const presented = page.locator('.pdf-present canvas');
  await expect(presented).toBeVisible(); await expect(page.locator('.pdf-stage')).toBeHidden();
  await expect(page.getByRole('button', { name: 'Zoom in' })).toBeHidden();
  // The page fills the view, drawn as wide as it shows.
  await expect.poll(() => presented.evaluate(canvas => canvas.width)).toBeGreaterThan(600);
  // The middle of the page shown is its color.
  const color = rgb => () => presented.evaluate((canvas, rgb) => {
    const pixel = canvas.getContext('2d').getImageData(canvas.width / 2, canvas.height / 2, 1, 1).data;
    return rgb.every((value, i) => Math.abs(pixel[i] - value) < 4);
  }, rgb);
  await expect.poll(color([51, 153, 77])).toBe(true);
  for (const [key, shownPage] of [['ArrowRight', '2 / 3'], ['Space', '3 / 3'], ['Space', '3 / 3'], ['Home', '1 / 3'], ['End', '3 / 3'], ['PageUp', '2 / 3']]) {
    await page.keyboard.press(key); await expect(pdfStatus(page)).toHaveText(shownPage);
  }
  await expect.poll(color([179, 153, 51])).toBe(true);
  // Another window of this browser presenting it follows.
  const second = await context.newPage(); await second.goto('/');
  await run(second, `open ${base}/pages.pdf`);
  await expect(second.locator('.pdf-present canvas')).toBeVisible();
  await expect(pdfStatus(second)).toHaveText('2 / 3');
  await page.keyboard.press('ArrowRight');
  await expect(pdfStatus(second)).toHaveText('3 / 3');
  await second.close();
  // Back to scrolling.
  await page.getByRole('button', { name: 'Scroll the pages' }).click();
  await expect(page.locator('.pdf-stage')).toBeVisible(); await expect(page.locator('.pdf-present')).toBeHidden();
  await expect(page.getByRole('button', { name: 'Zoom in' })).toBeVisible();
  expect(await mode.boundingBox()).toEqual(at);
  // Full screen, scrolling too, the toolbar floats at the bottom, under no other bar.
  await page.getByRole('button', { name: 'Fullscreen', exact: true }).click();
  await expect.poll(() => page.evaluate(() => document.fullscreenElement?.id)).toBe('viewer-surface');
  await page.mouse.move(300, 300); await page.mouse.move(310, 310);
  const [bar, tools, height] = await page.evaluate(() => [document.querySelector('.viewer-bar').getBoundingClientRect().bottom, document.querySelector('.pdf-toolbar').getBoundingClientRect(), innerHeight]);
  expect(Math.abs(tools.bottom - height)).toBeLessThan(2); expect(tools.top).toBeGreaterThan(bar);
  const zoom = await page.getByRole('button', { name: 'Zoom in' }).boundingBox();
  expect(await page.evaluate(([x, y]) => document.elementFromPoint(x, y)?.getAttribute('aria-label'), [zoom.x + zoom.width / 2, zoom.y + zoom.height / 2])).toBe('Zoom in');
  await page.evaluate(() => document.exitFullscreen());
  await expect.poll(() => page.evaluate(() => document.fullscreenElement === null)).toBe(true);
});

test('a page of the account opens a deck where the account showed it last, on any device', async ({ browser }) => {
  const name = 'where' + Date.now().toString(36), password = 'presenting-password-' + Date.now();
  const command = args => program(root, args);
  expect((await command(['useradd', '-m', name])).ok()).toBe(true);
  expect((await api(root, 'passwd', { data: { username: name, password } })).ok()).toBe(true);
  const laptop = await device(browser, name, password);
  let phone;
  try {
    await run(laptop.page, `open ${base}/deck.slides.md`);
    await expect(shown(laptop.page).locator('h1')).toHaveText('One');
    await laptop.page.keyboard.press('End'); await expect(shown(laptop.page).locator('h1')).toHaveText('Three');
    // Another device, signed in later, opens it there too, rather than where it left it.
    phone = await device(browser, name, password);
    await run(phone.page, `open ${base}/deck.slides.md`);
    await expect(shown(phone.page).locator('h1')).toHaveText('Three');
  } finally {
    await command(['userdel', '-r', name]);
    await laptop.context.close(); await phone?.context.close();
  }
});

test('present makes /dev/present/NAME, which whoever may read the file follows, guests too, and only its account turns', async ({ browser }) => {
  const name = 'speaker' + Date.now().toString(36), password = 'presenting-password-' + Date.now();
  const outsider = 'outsider' + Date.now().toString(36);
  const command = args => program(root, args);
  for (const user of [name, outsider]) {
    expect((await command(['useradd', '-m', user])).ok()).toBe(true);
    expect((await api(root, 'passwd', { data: { username: user, password } })).ok()).toBe(true);
  }
  // Readable by the presenter and by guests, as their ACL says, and by nobody else.
  const stem = 'talk' + Date.now().toString(36), talk = `${base}/${stem}.slides.md`;
  expect((await put(root, file(talk), { data: deck })).status()).toBe(201);
  for (const args of [['chmod', '600', talk], ['setfacl', '-m', `u:${name}:r,u:guest:r`, talk], ['setfacl', '-m', `u:${name}:r,u:guest:r`, base + '/pages.pdf']]) expect((await command(args)).ok()).toBe(true);
  const laptop = await device(browser, name, password), phone = await device(browser, name, password);
  const guest = await device(browser), other = await device(browser, outsider, password);
  const transcript = page => page.locator('.terminal-panel:not([hidden]) .transcript');
  const badge = page => page.locator('.presentation-badge');
  try {
    await run(laptop.page, `present ${talk}`);
    await expect(shown(laptop.page).locator('h1')).toHaveText('One');
    await laptop.page.getByRole('button', { name: 'Close preview' }).click();
    await expect(transcript(laptop.page)).toContainText(`Presenting ${talk} as /dev/present/${stem}`);
    // Guests cannot present: guest is everyone signed out.
    await run(guest.page, `present ${talk}`);
    await expect(transcript(guest.page)).toContainText('Permission denied: sign in to present');
    // A guest finds it in /dev/present, and follows it from where it is.
    await run(guest.page, 'ls /dev/present');
    await expect(transcript(guest.page)).toContainText(stem);
    await run(laptop.page, `open ${talk}`); await expect(shown(laptop.page).locator('h1')).toHaveText('One');
    await laptop.page.keyboard.press('ArrowRight'); await expect(shown(laptop.page).locator('h1')).toHaveText('Two');
    await run(guest.page, `open /dev/present/${stem}`);
    await expect(shown(guest.page).locator('h1')).toHaveText('Two');
    await expect(badge(guest.page)).toHaveText(`Following ${name}`);
    await laptop.page.keyboard.press('ArrowDown');
    await expect(shown(guest.page).locator('h1')).toHaveText('Two, below');
    // A listener's own turn pauses following, and turns nothing of the presenter's.
    await guest.page.keyboard.press('Home');
    await expect(shown(guest.page).locator('h1')).toHaveText('One');
    await expect(badge(guest.page)).toHaveText(`Follow ${name}`);
    await laptop.page.keyboard.press('End');
    await expect(shown(laptop.page).locator('h1')).toHaveText('Three');
    await guest.page.waitForTimeout(500);
    await expect(shown(guest.page).locator('h1')).toHaveText('One');
    await badge(guest.page).click();
    await expect(shown(guest.page).locator('h1')).toHaveText('Three'); await expect(badge(guest.page)).toHaveText(`Following ${name}`);
    // The presenter's phone opens it where it is, and turns it as a remote.
    await run(phone.page, `open ${talk}`);
    await expect(shown(phone.page).locator('h1')).toHaveText('Three');
    await phone.page.keyboard.press('ArrowLeft');
    await expect(shown(laptop.page).locator('h1')).toHaveText('Two');
    await expect(shown(guest.page).locator('h1')).toHaveText('Two');
    // An account that may not read the file may not follow it.
    await run(other.page, `open /dev/present/${stem}`);
    await expect(transcript(other.page)).toContainText('Permission denied');
    await expect(other.page.locator('#viewer')).toBeHidden();
    // Nor take its name.
    await run(other.page, `present -n ${stem} ${base}/deck.slides.md`);
    await expect(transcript(other.page)).toContainText('Device or resource busy');
    // A PDF presented is followed page by page.
    await laptop.page.getByRole('button', { name: 'Close preview' }).click();
    await run(laptop.page, `present -n ${stem}-paper ${base}/pages.pdf`);
    await expect(laptop.page.locator('.pdf-present canvas')).toBeVisible();
    await expect(laptop.page.locator('.pdf-toolbar [role=status]')).toHaveText('1 / 3');
    await guest.page.getByRole('button', { name: 'Close preview' }).click();
    await run(guest.page, `open /dev/present/${stem}-paper`);
    await expect(guest.page.locator('.pdf-present canvas')).toBeVisible();
    await expect(badge(guest.page)).toHaveText(`Following ${name}`);
    await laptop.page.keyboard.press('ArrowRight');
    await expect(guest.page.locator('.pdf-toolbar [role=status]')).toHaveText('2 / 3');
    // Stopped, it is gone, and its listeners are told.
    await laptop.page.getByRole('button', { name: 'Close preview' }).click();
    await run(laptop.page, `present --stop ${stem}-paper`);
    await expect(transcript(laptop.page)).toContainText(`Stopped /dev/present/${stem}-paper`);
    await expect(badge(guest.page)).toHaveText('The presentation ended');
    await run(laptop.page, `present --stop ${stem}`);
    await expect(transcript(laptop.page)).toContainText(`Stopped /dev/present/${stem}`);
    expect(await names(root, '/dev/present')).not.toContain(stem);
    // An account deleted takes its presentations with it.
    await run(laptop.page, `present ${talk}`);
    await expect(transcript(laptop.page)).toContainText(`as /dev/present/${stem}`);
    expect((await command(['userdel', '-r', name])).ok()).toBe(true);
    expect(await names(root, '/dev/present')).not.toContain(stem);
  } finally {
    for (const user of [name, outsider]) await command(['userdel', '-r', user]);
    for (const { context } of [laptop, phone, guest, other]) await context.close();
    await rmrf(root, talk);
  }
});

test('a page whose line dropped catches up, on its return, with the turns made meanwhile', async ({ browser }) => {
  const name = 'line' + Date.now().toString(36), password = 'presenting-password-' + Date.now();
  const command = args => program(root, args);
  expect((await command(['useradd', '-m', name])).ok()).toBe(true);
  expect((await api(root, 'passwd', { data: { username: name, password } })).ok()).toBe(true);
  // The phone's line to the authority, which the test drops.
  let line;
  const laptop = await device(browser, name, password);
  const phone = await device(browser, name, password, page => page.routeWebSocket(/\/api\/events$/, ws => { ws.connectToServer(); line = ws; }));
  try {
    for (const { page } of [laptop, phone]) {
      await run(page, `open ${base}/deck.slides.md`);
      await expect(shown(page).locator('h1')).toHaveText('One');
    }
    const dropped = line;
    await dropped.close();
    await laptop.page.keyboard.press('ArrowRight');
    await expect(shown(laptop.page).locator('h1')).toHaveText('Two');
    // Back on the line, the phone asks where the deck is, and shows it.
    await expect.poll(() => line !== dropped, { timeout: 10_000 }).toBe(true);
    await expect(shown(phone.page).locator('h1')).toHaveText('Two', { timeout: 10_000 });
  } finally {
    await command(['userdel', '-r', name]);
    await laptop.context.close(); await phone.context.close();
  }
});

test('a presentation that comes to show another file takes its listeners with it', async ({ browser }) => {
  const name = 'swap' + Date.now().toString(36), password = 'presenting-password-' + Date.now();
  const command = args => program(root, args);
  expect((await command(['useradd', '-m', name])).ok()).toBe(true);
  expect((await api(root, 'passwd', { data: { username: name, password } })).ok()).toBe(true);
  const laptop = await device(browser, name, password), guest = await device(browser);
  const stem = 'swap' + Date.now().toString(36);
  try {
    await run(laptop.page, `present -n ${stem} ${base}/deck.slides.md`);
    await expect(shown(laptop.page).locator('h1')).toHaveText('One');
    await run(guest.page, `open /dev/present/${stem}`);
    await expect(shown(guest.page).locator('h1')).toHaveText('One');
    // The same name, another deck: the listener goes with it, and follows it.
    await laptop.page.getByRole('button', { name: 'Close preview' }).click();
    await run(laptop.page, `present -n ${stem} ${base}/other.slides.md`);
    await expect(shown(laptop.page).locator('h1')).toHaveText('Bee');
    await expect(guest.page.locator('#viewer-title')).toHaveText(`${base}/other.slides.md`);
    await expect(shown(guest.page).locator('h1')).toHaveText('Bee');
    await expect(guest.page.locator('.presentation-badge')).toHaveText(`Following ${name}`);
    await laptop.page.keyboard.press('ArrowRight');
    await expect(shown(guest.page).locator('h1')).toHaveText('Bee two');
  } finally {
    await sys(root, [{ unlink: { path: '/dev/present/' + stem } }]);
    await command(['userdel', '-r', name]);
    await laptop.context.close(); await guest.context.close();
  }
});

test('a listener whose line was down when the presentation came to show another file goes with it on its return', async ({ browser }) => {
  const name = 'missed' + Date.now().toString(36), password = 'presenting-password-' + Date.now();
  const command = args => program(root, args);
  expect((await command(['useradd', '-m', name])).ok()).toBe(true);
  expect((await api(root, 'passwd', { data: { username: name, password } })).ok()).toBe(true);
  let line;
  const laptop = await device(browser, name, password);
  const guest = await device(browser, undefined, undefined, page => page.routeWebSocket(/\/api\/events$/, ws => { ws.connectToServer(); line = ws; }));
  const stem = 'missed' + Date.now().toString(36);
  try {
    await run(laptop.page, `present -n ${stem} ${base}/deck.slides.md`);
    await expect(shown(laptop.page).locator('h1')).toHaveText('One');
    await run(guest.page, `open /dev/present/${stem}`);
    await expect(shown(guest.page).locator('h1')).toHaveText('One');
    // While the guest's line is down, the name comes to show another deck, which turns.
    const dropped = line;
    await dropped.close();
    await laptop.page.getByRole('button', { name: 'Close preview' }).click();
    await run(laptop.page, `present -n ${stem} ${base}/other.slides.md`);
    await expect(shown(laptop.page).locator('h1')).toHaveText('Bee');
    await laptop.page.keyboard.press('ArrowRight');
    await expect(shown(laptop.page).locator('h1')).toHaveText('Bee two');
    // Back on the line, the guest learns what it shows now, and follows it.
    await expect.poll(() => line !== dropped, { timeout: 10_000 }).toBe(true);
    await expect(guest.page.locator('#viewer-title')).toHaveText(`${base}/other.slides.md`, { timeout: 10_000 });
    await expect(shown(guest.page).locator('h1')).toHaveText('Bee two');
    await expect(guest.page.locator('.presentation-badge')).toHaveText(`Following ${name}`);
  } finally {
    await sys(root, [{ unlink: { path: '/dev/present/' + stem } }]);
    await command(['userdel', '-r', name]);
    await laptop.context.close(); await guest.context.close();
  }
});

test('a replacement heard after the listener left the presentation does not take them back to it', async ({ browser }) => {
  const name = 'left' + Date.now().toString(36), password = 'presenting-password-' + Date.now();
  const command = args => program(root, args);
  expect((await command(['useradd', '-m', name])).ok()).toBe(true);
  expect((await api(root, 'passwd', { data: { username: name, password } })).ok()).toBe(true);
  const laptop = await device(browser, name, password), guest = await device(browser);
  const stem = 'left' + Date.now().toString(36);
  try {
    await run(laptop.page, `present -n ${stem} ${base}/deck.slides.md`);
    await expect(shown(laptop.page).locator('h1')).toHaveText('One');
    await run(guest.page, `open /dev/present/${stem}`);
    await expect(shown(guest.page).locator('h1')).toHaveText('One');
    // What the device shows after its replacement comes late, held by the test.
    let asked = false, release;
    const held = new Promise(resolve => { release = resolve; });
    await guest.page.route(url => url.pathname === '/api/file' && url.searchParams.get('path')?.startsWith('/dev/present/'), async route => { asked = true; await held; await route.continue().catch(() => {}); });
    await laptop.page.getByRole('button', { name: 'Close preview' }).click();
    await run(laptop.page, `present -n ${stem} ${base}/other.slides.md`);
    await expect.poll(() => asked, { timeout: 10_000 }).toBe(true);
    // Meanwhile the guest leaves it for another deck of their own.
    await guest.page.getByRole('button', { name: 'Close preview' }).click();
    await run(guest.page, `open ${base}/third.slides.md`);
    await expect(shown(guest.page).locator('h1')).toHaveText('Sea');
    release();
    await guest.page.waitForTimeout(1500);
    await expect(guest.page.locator('#viewer-title')).toHaveText(`${base}/third.slides.md`);
    await expect(shown(guest.page).locator('h1')).toHaveText('Sea');
    await expect(guest.page.locator('.presentation-badge')).toHaveCount(0);
  } finally {
    await sys(root, [{ unlink: { path: '/dev/present/' + stem } }]);
    await command(['userdel', '-r', name]);
    await laptop.context.close(); await guest.context.close();
  }
});

test('a page whose line was down when its presentation changed hands learns it on its return, and turns it if now its own', async ({ browser }) => {
  const name = 'hands' + Date.now().toString(36), password = 'presenting-password-' + Date.now();
  const command = args => program(root, args);
  expect((await command(['useradd', '-m', name])).ok()).toBe(true);
  expect((await api(root, 'passwd', { data: { username: name, password } })).ok()).toBe(true);
  let line;
  const presenter = await device(browser, name, password), guest = await device(browser);
  const listener = await device(browser, 'root', rootPassword, page => page.routeWebSocket(/\/api\/events$/, ws => { ws.connectToServer(); line = ws; }));
  const other = await device(browser, 'root', rootPassword);
  const stem = 'hands' + Date.now().toString(36);
  try {
    await run(presenter.page, `present -n ${stem} ${base}/deck.slides.md`);
    await expect(shown(presenter.page).locator('h1')).toHaveText('One');
    for (const { page } of [listener, guest]) {
      await run(page, `open /dev/present/${stem}`);
      await expect(page.locator('.presentation-badge')).toHaveText(`Following ${name}`);
    }
    // While the listener's line is down, root takes the presentation over, the same file, and
    // turns it to its end.
    const dropped = line;
    await dropped.close();
    await run(other.page, `present -n ${stem} ${base}/deck.slides.md`);
    await expect(other.page.locator('.slides-current .slide:visible')).toBeVisible();
    await other.page.keyboard.press('End');
    await expect(shown(other.page).locator('h1')).toHaveText('Three');
    await expect(guest.page.locator('.presentation-badge')).toHaveText('Following root');
    await expect(shown(guest.page).locator('h1')).toHaveText('Three');
    // Back on the line, the listener, root's, is its presenter now: no listener's badge, and
    // its turns are the presentation's.
    await expect.poll(() => line !== dropped, { timeout: 10_000 }).toBe(true);
    await expect(listener.page.locator('.presentation-badge')).toHaveCount(0, { timeout: 10_000 });
    await expect(shown(listener.page).locator('h1')).toHaveText('Three');
    await listener.page.keyboard.press('Home');
    await expect(shown(guest.page).locator('h1')).toHaveText('One');
  } finally {
    await sys(root, [{ unlink: { path: '/dev/present/' + stem } }]);
    await command(['userdel', '-r', name]);
    for (const { context } of [presenter, guest, listener, other]) await context.close();
  }
});

test('a failure heard for a replacement the listener has since gone past does not end what they follow now', async ({ browser }) => {
  const name = 'stale' + Date.now().toString(36), password = 'presenting-password-' + Date.now();
  const command = args => program(root, args);
  expect((await command(['useradd', '-m', name])).ok()).toBe(true);
  expect((await api(root, 'passwd', { data: { username: name, password } })).ok()).toBe(true);
  // A deck the presenter may read and guests may not.
  const secret = `${base}/secret-${name}.slides.md`;
  expect((await put(root, file(secret), { data: '# Secret\n' })).status()).toBe(201);
  for (const args of [['chmod', '600', secret], ['setfacl', '-m', `u:${name}:r`, secret]]) expect((await command(args)).ok()).toBe(true);
  const laptop = await device(browser, name, password), guest = await device(browser);
  const stem = 'stale' + Date.now().toString(36);
  try {
    await run(laptop.page, `present -n ${stem} ${base}/deck.slides.md`);
    await expect(shown(laptop.page).locator('h1')).toHaveText('One');
    await run(guest.page, `open /dev/present/${stem}`);
    await expect(guest.page.locator('.presentation-badge')).toHaveText(`Following ${name}`);
    // The guest may not follow the secret deck; that refusal comes late, held by the test.
    let asked = false, release;
    const held = new Promise(resolve => { release = resolve; });
    await guest.page.route(url => url.pathname === '/api/file' && url.searchParams.get('path')?.startsWith('/dev/present/'), async route => { if (!asked) { asked = true; await held; } await route.continue().catch(() => {}); });
    for (const deck of [secret, `${base}/third.slides.md`]) {
      await laptop.page.getByRole('button', { name: 'Close preview' }).click();
      await run(laptop.page, `present -n ${stem} ${deck}`);
      await expect(laptop.page.locator('#viewer-title')).toHaveText(deck);
      await expect.poll(() => asked, { timeout: 10_000 }).toBe(true);
    }
    // Meanwhile the name came to show a deck the guest may read, which they follow.
    await expect(shown(guest.page).locator('h1')).toHaveText('Sea');
    await expect(guest.page.locator('.presentation-badge')).toHaveText(`Following ${name}`);
    release();
    await guest.page.waitForTimeout(1500);
    await expect(guest.page.locator('.presentation-badge')).toHaveText(`Following ${name}`);
    await expect(guest.page.locator('.presentation-badge')).toBeEnabled();
  } finally {
    await sys(root, [{ unlink: { path: '/dev/present/' + stem } }]);
    await rmrf(root, secret);
    await command(['userdel', '-r', name]);
    await laptop.context.close(); await guest.context.close();
  }
});

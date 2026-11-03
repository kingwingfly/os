import { test, expect, request as playwrightRequest } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { api, call, descriptors, entry, errno, mkdirp, names, program, put, rmrf, sys } from './sys.js';
const origin = process.env.TERMINAL_TEST_URL || 'http://127.0.0.1:8787';
const vars = await readFile('.dev.vars', 'utf8');
const rootPassword = vars.match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const file = path => '/api/file?path=' + encodeURIComponent(path);
// Chromium's fake microphone, granted without asking; and the launch options of
// playwright.config.js, which test.use replaces.
const browserEnv = { ...process.env }; delete browserEnv.DISPLAY;
test.use({ launchOptions: { env: browserEnv, args: ['--ozone-platform=headless', '--use-gl=angle', '--use-angle=swiftshader', '--enable-unsafe-swiftshader', '--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream'] } });
let sequence = 0;
const address = name => `live-${name}-${Date.now()}-${++sequence}`;

const busy = page => page.locator('.terminal-panel:not([hidden]) .busy');
const transcript = page => page.locator('.terminal-panel:not([hidden]) .transcript');
const shown = page => page.locator('.slides-current .slide:visible');
const player = page => page.getByRole('region', { name: 'Live sound' });
async function run(page, text) {
  await expect(busy(page)).toHaveText('↵');
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  await input.fill(text); await input.press('Enter');
}
// A page of a browser of its own, signed in through the API, or a guest's; it keeps the
// connections its sounds make, to fail one.
async function device(browser, username, password) {
  const context = await browser.newContext({ permissions: ['microphone'], extraHTTPHeaders: { 'CF-Connecting-IP': address(username || 'guest') } });
  await context.addInitScript(() => {
    const Real = window.RTCPeerConnection;
    window.connections = [];
    window.RTCPeerConnection = function (config) { const pc = new Real(config); window.connections.push(pc); return pc; };
    window.RTCPeerConnection.prototype = Real.prototype;
  });
  if (username) expect((await api(context.request, 'login', { headers: { Origin: origin }, data: { username, password } })).ok()).toBe(true);
  const page = await context.newPage(); await page.goto(origin + '/');
  await expect(page.locator('.lock')).toContainText(username || 'guest');
  return { context, page };
}

let root, name, password, base;
const listed = directory => names(root, directory);
// Whether the site has a Realtime app: its keys are named in .dev.vars (their values are not
// read here).
const realtime = async () => /^REALTIME_APP_ID=.+$/m.test(vars) && /^REALTIME_APP_TOKEN=.+$/m.test(vars);
const NO_REALTIME = 'The site has no Cloudflare Realtime app (REALTIME_APP_ID, REALTIME_APP_TOKEN)';
test.beforeAll(async () => {
  root = await playwrightRequest.newContext({ baseURL: origin, extraHTTPHeaders: { Origin: origin, 'CF-Connecting-IP': address('api') } });
  expect((await api(root, 'login', { data: { password: rootPassword } })).ok()).toBe(true);
  name = 'live' + Date.now().toString(36); password = 'live-password-' + Date.now();
  expect((await program(root, ['useradd', '-m', name])).ok()).toBe(true);
  expect((await api(root, 'passwd', { data: { username: name, password } })).ok()).toBe(true);
  // The speaker's directory, which everyone may read, guests too.
  base = '/live-' + Date.now().toString(36);
  await mkdirp(root, base);
  expect((await program(root, ['chown', name, base])).ok()).toBe(true);
});
test.afterAll(async () => {
  await rmrf(root, base);
  await program(root, ['userdel', '-r', name]);
  await root.dispose();
});
// A deck of the speaker's, of its own name.
async function deck() {
  const stem = 'talk' + Date.now().toString(36) + ++sequence, path = `${base}/${stem}.slides.md`;
  expect((await put(root, file(path), { data: '# One\n\n---\n\n# Two\n' })).status()).toBe(201);
  expect((await program(root, ['chown', name, path])).ok()).toBe(true);
  return { stem, path };
}

test('Present in the bar makes /dev/present/NAME; rm of it stops it, as its account may and no one else, and its listeners and bar hear so', async ({ browser }) => {
  const { stem, path } = await deck();
  const laptop = await device(browser, name, password), phone = await device(browser, name, password), guest = await device(browser);
  const present = laptop.page.getByRole('button', { name: 'Present to others' });
  try {
    await run(laptop.page, `open ${path}`);
    await expect(shown(laptop.page).locator('h1')).toHaveText('One');
    await expect(present).toHaveAttribute('aria-pressed', 'false');
    await present.click();
    await expect(present).toHaveAttribute('aria-pressed', 'true');
    await expect(present).toHaveAttribute('title', new RegExp(`/dev/present/${stem}`));
    expect(await listed('/dev/present')).toContain(stem);
    // Another account, here everyone signed out, may not remove it.
    await run(guest.page, `rm /dev/present/${stem}`);
    await expect(transcript(guest.page)).toContainText('Permission denied: it is another account\'s');
    expect(await errno(guest.context.request, { unlink: { path: `/dev/present/${stem}` } })).toBe('EACCES');
    await run(guest.page, `open /dev/present/${stem}`);
    await expect(guest.page.locator('.presentation-badge')).toHaveText(`Following ${name}`);
    // Its account removes it, from another device: it ends, and its listeners and its bar hear so.
    await run(phone.page, `rm /dev/present/${stem}`);
    await expect(guest.page.locator('.presentation-badge')).toHaveText('The presentation ended');
    await expect(present).toHaveAttribute('aria-pressed', 'false');
    expect(await listed('/dev/present')).not.toContain(stem);
    // Present again, and the button stops it.
    await present.click(); await expect(present).toHaveAttribute('aria-pressed', 'true');
    expect(await listed('/dev/present')).toContain(stem);
    await present.click(); await expect(present).toHaveAttribute('aria-pressed', 'false');
    expect(await listed('/dev/present')).not.toContain(stem);
    // Guests have no Present: guest is everyone signed out.
    await guest.page.getByRole('button', { name: 'Close preview' }).click();
    await run(guest.page, `open ${path}`);
    await expect(shown(guest.page).locator('h1')).toHaveText('One');
    await expect(guest.page.getByRole('button', { name: 'Present to others' })).toBeHidden();
  } finally {
    await sys(root, [{ unlink: { path: '/dev/present/' + stem } }]);
    for (const { context } of [laptop, phone, guest]) await context.close();
  }
});

test('a presentation is a character device: ls -l and cat tell of it; chmod decides who follows, setfacl who turns', async ({ browser }) => {
  const { stem, path } = await deck();
  const cohost = 'cohost' + Date.now().toString(36);
  expect((await program(root, ['useradd', '-m', cohost])).ok()).toBe(true);
  expect((await api(root, 'passwd', { data: { username: cohost, password } })).ok()).toBe(true);
  const laptop = await device(browser, name, password), guest = await device(browser), helper = await device(browser, cohost, password);
  const device_ = `/dev/present/${stem}`;
  try {
    await run(laptop.page, `present ${path}`);
    await expect(shown(laptop.page).locator('h1')).toHaveText('One');
    await laptop.page.getByRole('button', { name: 'Close preview' }).click();
    // Its presenter's, made as a file is, with the file's mode.
    await run(guest.page, `ls -l ${device_}`);
    await expect(transcript(guest.page)).toContainText(new RegExp(`crw-r--r-- +1 ${name}:${name} +0 [A-Z][a-z]{2} [ \\d]\\d [ \\d:]{5} ${device_}`));
    await run(guest.page, `cat ${device_}`);
    await expect(transcript(guest.page)).toContainText(`"path":"${path}"`);
    // Its mode says who follows it: chmod 600, and guests may not.
    await run(laptop.page, `chmod 600 ${device_}`);
    await run(guest.page, `open ${device_}`);
    await expect(transcript(guest.page)).toContainText('Permission denied');
    await run(laptop.page, `chmod 644 ${device_}`);
    await run(guest.page, `open ${device_}`);
    await expect(guest.page.locator('.presentation-badge')).toHaveText(`Following ${name}`);
    // An ACL entry that lets another account write it makes a co-host, whose turns are the
    // presentation's.
    await run(laptop.page, `setfacl -m u:${cohost}:rw ${device_}`);
    await run(helper.page, `open ${device_}`);
    await expect(shown(helper.page).locator('h1')).toHaveText('One');
    await expect(helper.page.locator('.presentation-badge')).toHaveCount(0);
    await helper.page.keyboard.press('ArrowRight');
    await expect(shown(guest.page).locator('h1')).toHaveText('Two');
  } finally {
    await sys(root, [{ unlink: { path: device_ } }]);
    await program(root, ['userdel', '-r', cohost]);
    for (const { context } of [laptop, guest, helper]) await context.close();
  }
});

test('Go live in the bar, Live + record, records beside the deck; stopped, the file is whole', async ({ browser }) => {
  const { stem, path } = await deck();
  const laptop = await device(browser, name, password);
  try {
    await run(laptop.page, `open ${path}`);
    await expect(shown(laptop.page).locator('h1')).toHaveText('One');
    await laptop.page.getByRole('button', { name: 'Go live' }).click();
    await laptop.page.getByRole('menuitem', { name: 'Live + record' }).click();
    const stop = laptop.page.getByRole('button', { name: 'Stop the live sound' });
    await expect(stop).toHaveText(/● 00:0[2-9]/, { timeout: 20_000 });
    const recordings = async () => (await listed(base)).filter(entry => entry.startsWith(stem + '-') && entry.endsWith('.weba'));
    await expect.poll(recordings).toHaveLength(1);
    const [recording] = await recordings();
    expect(recording).toMatch(new RegExp(`^${stem}-\\d{8}-\\d{4}\\.weba$`));
    if (await realtime()) await expect.poll(() => listed('/dev/snd'), { timeout: 20_000 }).toContain(name);
    await stop.click();
    await expect(laptop.page.locator('.live-note')).toContainText(`Saved ${base}/${recording}`, { timeout: 30_000 });
    await expect(laptop.page.getByRole('button', { name: 'Go live' })).toBeVisible();
    const kept = await entry(root, `${base}/${recording}`);
    expect(kept.recording).toBeFalsy(); expect(kept.size).toBeGreaterThan(0);
    await expect.poll(() => listed('/dev/snd'), { timeout: 10_000 }).not.toContain(name);
  } finally {
    await laptop.context.close();
  }
});

test('stream is live as the account\'s name; its presentation\'s listeners connect by themselves; rm /dev/snd/NAME stops it', async ({ browser }) => {
  test.skip(!await realtime(), NO_REALTIME);
  const { stem, path } = await deck();
  const laptop = await device(browser, name, password), phone = await device(browser, name, password), guest = await device(browser);
  try {
    await run(laptop.page, `present ${path}`);
    await expect(shown(laptop.page).locator('h1')).toHaveText('One');
    // A listener who came before the sound has none ...
    await run(guest.page, `open /dev/present/${stem}`);
    await expect(shown(guest.page).locator('h1')).toHaveText('One');
    await expect(player(guest.page)).toBeHidden();
    // ... until the presenter goes live, from any device, under the account's name.
    await run(phone.page, 'stream');
    await expect(transcript(phone.page)).toContainText(`● live as /dev/snd/${name}`, { timeout: 20_000 });
    await expect(player(guest.page)).toHaveAttribute('data-state', /live|paused/, { timeout: 20_000 });
    await expect(guest.page.locator('#listening-name')).toHaveText(`/dev/snd/${name}`);
    // Its listener stops it; it does not come back by itself.
    await player(guest.page).getByRole('button', { name: 'Stop listening' }).click();
    await expect(player(guest.page)).toBeHidden();
    // rm of the sound, by root here, stops stream, and its listeners hear so.
    await guest.page.getByRole('button', { name: 'Close preview' }).click();
    await run(guest.page, `open /dev/present/${stem}`);
    await expect(player(guest.page)).toHaveAttribute('data-state', /live|paused/, { timeout: 20_000 });
    expect(await errno(root, { unlink: { path: `/dev/snd/${name}` } })).toBe(null);
    await expect(transcript(phone.page)).toContainText(new RegExp(`✓ /dev/snd/${name} · \\d\\d:\\d\\d`), { timeout: 30_000 });
    await expect(player(guest.page)).toBeHidden({ timeout: 10_000 });
  } finally {
    await sys(root, [{ unlink: { path: '/dev/present/' + stem } }]); await sys(root, [{ unlink: { path: '/dev/snd/' + name } }]);
    for (const { context } of [laptop, phone, guest]) await context.close();
  }
});

test('a listener asks to speak; allowed, everyone following hears them, until the presenter ends it', async ({ browser }) => {
  test.skip(!await realtime(), NO_REALTIME);
  const { stem, path } = await deck();
  const laptop = await device(browser, name, password), asker = await device(browser), other = await device(browser);
  const ask = asker.page.getByRole('button', { name: 'Ask to speak' });
  const listeners = laptop.page.getByRole('button', { name: /^Listeners:/ });
  try {
    await run(laptop.page, `present ${path}`);
    await expect(shown(laptop.page).locator('h1')).toHaveText('One');
    for (const { page } of [asker, other]) {
      await run(page, `open /dev/present/${stem}`);
      await expect(shown(page).locator('h1')).toHaveText('One');
    }
    // The presenter has no Ask; a listener has no Present.
    await expect(laptop.page.getByRole('button', { name: 'Ask to speak' })).toBeHidden();
    await expect(asker.page.getByRole('button', { name: 'Present to others' })).toBeHidden();
    // Dismissed: not now.
    await ask.click();
    await expect(ask).toHaveAttribute('aria-pressed', 'true');
    await expect(listeners).toHaveAttribute('aria-label', 'Listeners: 1 asking to speak, 0 speaking');
    await listeners.click();
    await expect(laptop.page.locator('.live-person')).toHaveText(/guest asks to speak/);
    await laptop.page.getByRole('menuitem', { name: 'Dismiss' }).click();
    await expect(asker.page.locator('.live-note')).toHaveText('Not now, says the presenter');
    await expect(listeners).toBeHidden();
    // Allowed: their voice is a sound of the presentation, the presenter's, which everyone
    // following hears, and the presenter's page too.
    await expect(ask).toHaveAttribute('aria-pressed', 'false', { timeout: 10_000 });
    // Full screen, the bars hidden, an ask shows them, and they stay while it waits.
    await laptop.page.getByRole('button', { name: 'Fullscreen', exact: true }).click();
    await expect.poll(() => laptop.page.evaluate(() => document.fullscreenElement?.id)).toBe('viewer-surface');
    const bars = () => laptop.page.locator('.slides-bar').evaluate(e => getComputedStyle(e).opacity);
    await expect.poll(bars, { timeout: 5000 }).toBe('0');
    await ask.click();
    await expect(listeners).toBeVisible();
    await expect.poll(bars).toBe('1');
    await laptop.page.waitForTimeout(2500);
    expect(await bars()).toBe('1');
    await listeners.click();
    await laptop.page.getByRole('menuitem', { name: 'Allow' }).click();
    await expect(ask).toHaveAttribute('title', /^Speaking/, { timeout: 20_000 });
    await expect.poll(() => listed('/dev/snd'), { timeout: 10_000 }).toContain(`${stem}-guest`);
    // The presenter's, a device that whoever follows the presentation hears.
    const voice = await entry(root, `/dev/snd/${stem}-guest`);
    expect([voice.owner, voice.mode]).toEqual([name, 0o644]);
    await expect(other.page.locator('#listening-name')).toHaveText('guest speaking', { timeout: 20_000 });
    await expect(player(other.page)).toHaveAttribute('data-state', /live|paused/);
    await expect.poll(() => laptop.page.evaluate(() => document.querySelectorAll('.voice-audio').length), { timeout: 20_000 }).toBe(1);
    await expect(asker.page.locator('#listening-name')).not.toHaveText(/guest speaking/);
    // Two guest browsers are one account, two sessions: the one allowed writes the
    // presentation through the descriptor passed to it; the other may not.
    expect(await errno(other.context.request, { open: { path: `/dev/present/${stem}`, flags: 1 } })).toBe('EACCES');
    expect((await descriptors(asker.context.request)).filter(fd => fd.path === `/dev/present/${stem}` && fd.flags & 1)).toHaveLength(1);
    // Ended by the presenter, the bars shown again by the pointer: the listener's microphone
    // stops, and the others hear it no more.
    await laptop.page.mouse.move(400, 300); await laptop.page.mouse.move(410, 310);
    await listeners.click();
    await expect(laptop.page.locator('.live-person.speaking')).toHaveText(/guest speaking/);
    await laptop.page.getByRole('menuitem', { name: 'End' }).click();
    await expect(ask).toHaveAttribute('aria-pressed', 'false', { timeout: 10_000 });
    await expect(ask).toHaveAttribute('title', 'Ask to speak');
    await expect(player(other.page)).toBeHidden({ timeout: 10_000 });
    expect(await listed('/dev/snd')).not.toContain(`${stem}-guest`);
    await laptop.page.evaluate(() => document.exitFullscreen());
    // No one speaks without the presenter's leave: a guest's session may not write the
    // presentation, now that its voice ended, nor speak through a descriptor that reads it.
    expect(await errno(asker.context.request, { open: { path: `/dev/present/${stem}`, flags: 1 } })).toBe('EACCES');
    const [reading] = await sys(asker.context.request, [{ open: { path: `/dev/present/${stem}`, flags: 0 } }]);
    expect(await errno(asker.context.request, { ioctl: { fd: reading.ok.fd, request: 0x5004, arg: { sdp: 'v=0', mid: '0' } } })).toBe('EBADF');
  } finally {
    await sys(root, [{ unlink: { path: '/dev/present/' + stem } }]);
    for (const { context } of [laptop, asker, other]) await context.close();
  }
});

test('a sound whose connection fails is heard again', async ({ browser }) => {
  test.skip(!await realtime(), NO_REALTIME);
  const speaker = await device(browser, name, password), guest = await device(browser);
  const sound = 'again' + Date.now().toString(36);
  let listens = 0;
  // A listen is the sound driver's request (abi::SND_LISTEN).
  guest.page.on('request', request => { if (request.url().endsWith('/api/sys') && (request.postData() || '').includes('"request":20738')) listens++; });
  try {
    await run(speaker.page, `stream -n ${sound}`);
    await expect(transcript(speaker.page)).toContainText(`● live as /dev/snd/${sound}`, { timeout: 20_000 });
    await run(guest.page, `open /dev/snd/${sound}`);
    await expect(player(guest.page)).toHaveAttribute('data-state', /live|paused/, { timeout: 20_000 });
    expect(listens).toBe(1);
    // The connection fails, as on a network that changed: the page connects again.
    await guest.page.evaluate(() => {
      const pc = window.connections.at(-1);
      Object.defineProperty(pc, 'connectionState', { get: () => 'failed' });
      pc.dispatchEvent(new Event('connectionstatechange'));
    });
    await expect.poll(() => listens, { timeout: 15_000 }).toBe(2);
    await expect(player(guest.page)).toHaveAttribute('data-state', /live|paused/, { timeout: 20_000 });
    await expect(guest.page.locator('#listening-name')).toHaveText(`/dev/snd/${sound}`);
    await speaker.page.locator('#command').press('Control+c');
    await expect(player(guest.page)).toBeHidden({ timeout: 10_000 });
  } finally {
    await sys(root, [{ unlink: { path: '/dev/snd/' + sound } }]);
    await speaker.context.close(); await guest.context.close();
  }
});

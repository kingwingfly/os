import { test, expect, request as playwrightRequest } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { api, call, entry, errno, names, program, put, rmrf, sys } from './sys.js';
const origin = process.env.TERMINAL_TEST_URL || 'http://127.0.0.1:8787';
const vars = await readFile('.dev.vars', 'utf8');
const rootPassword = vars.match(/^ADMIN_PASSWORD=(.+)$/m)[1];
// Whether the site has a Realtime app: its keys are named in .dev.vars (their values are not
// read here).
const realtime = /^REALTIME_APP_ID=.+$/m.test(vars) && /^REALTIME_APP_TOKEN=.+$/m.test(vars);
const file = path => '/api/file?path=' + encodeURIComponent(path);
// Chromium's fake microphone, which plays a tone, granted without asking; and the launch options
// of playwright.config.js, which test.use replaces.
const browserEnv = { ...process.env }; delete browserEnv.DISPLAY;
test.use({ launchOptions: { env: browserEnv, args: ['--ozone-platform=headless', '--use-gl=angle', '--use-angle=swiftshader', '--enable-unsafe-swiftshader', '--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream'] } });
let sequence = 0;
const address = name => `sound-${name}-${Date.now()}-${++sequence}`;

const busy = page => page.locator('.terminal-panel:not([hidden]) .busy');
const transcript = page => page.locator('.terminal-panel:not([hidden]) .transcript');
async function run(page, text) {
  await expect(busy(page)).toHaveText('↵');
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  await input.fill(text); await input.press('Enter');
}
async function device(browser, username, password, prepare = async () => {}) {
  const context = await browser.newContext({ permissions: ['microphone'], extraHTTPHeaders: { 'CF-Connecting-IP': address(username || 'guest') } });
  await prepare(context);
  // The microphones a page takes, to end them as if unplugged.
  await context.addInitScript(() => {
    const take = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
    navigator.mediaDevices.getUserMedia = async constraints => { const stream = await take(constraints); (window.microphones ??= []).push(stream); return stream; };
  });
  if (username) expect((await api(context.request, 'login', { headers: { Origin: origin }, data: { username, password } })).ok()).toBe(true);
  const page = await context.newPage(); await page.goto(origin + '/');
  await expect(page.locator('.lock')).toContainText(username || 'guest');
  return { context, page };
}

let root, name, password, home;
test.beforeAll(async () => {
  root = await playwrightRequest.newContext({ baseURL: origin, extraHTTPHeaders: { Origin: origin, 'CF-Connecting-IP': address('api') } });
  expect((await api(root, 'login', { data: { password: rootPassword } })).ok()).toBe(true);
  name = 'voice' + Date.now().toString(36); password = 'sound-password-' + Date.now();
  expect((await program(root, ['useradd', '-m', name])).ok()).toBe(true);
  expect((await api(root, 'passwd', { data: { username: name, password } })).ok()).toBe(true);
  home = '/home/' + name;
});
test.afterAll(async () => { await program(root, ['userdel', '-r', name]); await root.dispose(); });

test('stream records the microphone into a file that grows as it is heard, and is whole once stopped', async ({ browser }) => {
  const speaker = await device(browser, name, password);
  const page = speaker.page, recording = home + '/talk.weba';
  try {
    await run(page, 'cd ~');
    // Browsers record Opus in WebM, so a recording is a .weba.
    await run(page, 'stream talk.aac');
    await expect(transcript(page)).toContainText('browsers record Opus in WebM; name the recording NAME.weba');
    await run(page, 'stream talk.weba');
    await expect(transcript(page)).toContainText(/● \d\d:\d\d/);
    // The file is there at once, a recording, and grows, a chunk at a time.
    const stat = () => entry(root, recording);
    await expect.poll(async () => (await stat())?.recording, { timeout: 15_000 }).toBe(true);
    await expect.poll(async () => (await stat())?.size ?? 0, { timeout: 60_000, intervals: [1000] }).toBeGreaterThan(0);
    const grown = (await stat()).size;
    // jobs, in another tab, says it is recording, and how much it has.
    const other = await speaker.context.newPage(); await other.goto(origin + '/');
    await run(other, 'jobs');
    await expect(transcript(other)).toContainText(new RegExp(`recording  ${recording}  [\\d.]+ KB`));
    await other.close();
    // A writer that says no size, not appending, writes in order too: a file that is what it wrote.
    const sizeless = await call(root, { open: { path: home + '/sizeless.bin', flags: 0o101 } });
    expect([sizeless.size, sizeless.chunk_size]).toEqual([0, 8 << 20]);
    expect((await call(root, { close: { fd: sizeless.fd } })).size).toBe(0);
    // What arrived may be read meanwhile, from its start.
    const partial = await (await root.get(file(recording), { headers: { 'Accept-Encoding': 'identity' } })).body();
    expect(partial.length).toBeGreaterThanOrEqual(grown);
    expect(partial.subarray(0, 4).toString('hex')).toBe('1a45dfa3');
    // Ctrl+C stops it; the rest arrives, and it is whole.
    await page.waitForTimeout(2000);
    await page.locator('#command').press('Control+c');
    await expect(transcript(page)).toContainText(new RegExp(`✓ ${recording} · \\d\\d:\\d\\d · [\\d.]+ KB`), { timeout: 30_000 });
    const whole = await stat();
    expect(whole.recording).toBeFalsy(); expect(whole.uploaded).toBeUndefined();
    expect(whole.size).toBeGreaterThan(grown);
    const bytes = await (await root.get(file(recording), { headers: { 'Accept-Encoding': 'identity' } })).body();
    expect(bytes.length).toBe(whole.size);
    expect(bytes.subarray(0, 4).toString('hex')).toBe('1a45dfa3');
    // It is a new file: another recording does not replace it.
    await run(page, 'stream talk.weba');
    await expect(transcript(page)).toContainText('File already exists');
  } finally {
    await rmrf(root, recording);
    await speaker.context.close();
  }
});

test('a recording whose microphone stops on its own is saved, with what it heard', async ({ browser }) => {
  const speaker = await device(browser, name, password);
  const page = speaker.page, recording = home + '/unplugged.weba';
  try {
    await run(page, 'cd ~');
    await run(page, 'stream unplugged.weba');
    await expect(transcript(page)).toContainText(/● 00:0[3-9]/, { timeout: 15_000 });
    // Unplugged, or taken back by the browser: every track of the microphone ends.
    await page.evaluate(() => window.microphones.forEach(stream => stream.getTracks().forEach(track => track.stop())));
    await expect(transcript(page)).toContainText(new RegExp(`✓ ${recording} · \\d\\d:\\d\\d · [\\d.]+ KB.* · the microphone stopped`), { timeout: 30_000 });
    const whole = await entry(root, recording);
    expect(whole.recording).toBeFalsy(); expect(whole.size).toBeGreaterThan(0);
    await expect(busy(page)).toHaveText('↵');
  } finally {
    await rmrf(root, recording);
    await speaker.context.close();
  }
});

test('live sound: /dev/snd/NAME is heard by whoever may read it, and with the presentation of its name', async ({ browser }) => {
  test.skip(!realtime, 'The site has no Cloudflare Realtime app (REALTIME_APP_ID, REALTIME_APP_TOKEN)');
  const speaker = await device(browser, name, password), guest = await device(browser);
  const remote = await speaker.context.newPage(); await remote.goto(origin + '/');
  const recording = home + '/lecture.weba', deck = home + '/lecture.slides.md';
  try {
    expect((await put(root, file(deck), { data: '# One\n\n---\n\n# Two\n' })).status()).toBe(201);
    for (const args of [['chmod', '755', home], ['chmod', '644', deck]]) expect((await program(root, args)).ok()).toBe(true);
    await run(speaker.page, 'cd ~');
    await run(speaker.page, 'stream -n lecture lecture.weba');
    await expect(transcript(speaker.page)).toContainText('live as /dev/snd/lecture', { timeout: 20_000 });
    // A guest hears it, as the device, made with the umask, may be read by others.
    await run(guest.page, 'open /dev/snd/lecture');
    const player = guest.page.getByRole('region', { name: 'Live sound' });
    await expect(player).toBeVisible(); await expect(player).toHaveAttribute('data-state', /live|paused/, { timeout: 20_000 });
    await expect.poll(() => guest.page.evaluate(() => document.getElementById('listening-audio').srcObject?.getAudioTracks()[0]?.readyState), { timeout: 20_000 }).toBe('live');
    // A presentation of the same name brings its sound with it.
    await player.getByRole('button', { name: 'Stop listening' }).click();
    await expect(player).toBeHidden();
    await run(remote, `present -n lecture ${deck}`);
    await expect(remote.locator('.slides-current .slide:visible h1')).toHaveText('One');
    await run(guest.page, 'open /dev/present/lecture');
    await expect(guest.page.locator('.slides-current .slide:visible h1')).toHaveText('One');
    await expect(guest.page.getByRole('region', { name: 'Live sound' })).toBeVisible();
    // Stopped, the sound ends for its listeners.
    await speaker.page.locator('#command').press('Control+c');
    await expect(transcript(speaker.page)).toContainText(`✓ ${recording}`, { timeout: 30_000 });
    await expect(guest.page.getByRole('region', { name: 'Live sound' })).toBeHidden({ timeout: 10_000 });
  } finally {
    await rmrf(root, recording); await rmrf(root, deck);
    await sys(root, [{ unlink: { path: '/dev/present/lecture' } }]);
    await speaker.context.close(); await guest.context.close();
  }
});

test('jobs cancel stops a recording from another tab, keeping what arrived', async ({ browser }) => {
  const speaker = await device(browser, name, password);
  const page = speaker.page, recording = home + '/cancelled.weba';
  const stat = () => entry(root, recording);
  try {
    await run(page, 'cd ~');
    await run(page, 'stream cancelled.weba');
    await expect.poll(async () => (await stat())?.size ?? 0, { timeout: 60_000, intervals: [1000] }).toBeGreaterThan(0);
    const other = await speaker.context.newPage(); await other.goto(origin + '/');
    await run(other, 'jobs');
    await expect(transcript(other)).toContainText(`recording  ${recording}`);
    const listed = (await transcript(other).textContent()).match(new RegExp(`(fd\\d+) +recording  ${recording}`));
    expect(listed).toBeTruthy();
    await run(other, 'jobs cancel ' + listed[1]);
    await expect(transcript(other)).toContainText(`Stopped the recording of ${recording}; what arrived is kept`);
    // The recording's own tab hears that it was stopped; the file is there, whole.
    await expect(transcript(page)).toContainText('✕ stopped elsewhere; what arrived is kept', { timeout: 30_000 });
    const kept = await stat();
    expect(kept.recording).toBeFalsy(); expect(kept.size).toBeGreaterThan(0);
    const bytes = await (await root.get(file(recording), { headers: { 'Accept-Encoding': 'identity' } })).body();
    expect(bytes.length).toBe(kept.size);
    expect(bytes.subarray(0, 4).toString('hex')).toBe('1a45dfa3');
  } finally {
    await rmrf(root, recording);
    await speaker.context.close();
  }
});

test('a live sound that never connects leaves no device behind', async ({ browser }) => {
  test.skip(!realtime, 'The site has no Cloudflare Realtime app (REALTIME_APP_ID, REALTIME_APP_TOKEN)');
  // Relayed candidates only, and no relay: the connection never comes.
  const speaker = await device(browser, name, password, context => context.addInitScript(() => {
    const Real = window.RTCPeerConnection;
    window.RTCPeerConnection = function (config) { return new Real({ ...config, iceTransportPolicy: 'relay' }); };
    window.RTCPeerConnection.prototype = Real.prototype;
  }));
  const page = speaker.page, recording = home + '/unheard.weba';
  const listed = () => names(root, '/dev/snd');
  try {
    await run(page, 'cd ~');
    await run(page, 'stream unheard.weba');
    await expect(transcript(page)).toContainText('not live: The sound did not connect', { timeout: 30_000 });
    await expect.poll(listed, { timeout: 10_000 }).not.toContain('unheard');
    await page.locator('#command').press('Control+c');
    await expect(transcript(page)).toContainText(`✓ ${recording}`, { timeout: 30_000 });
  } finally {
    await rmrf(root, recording);
    await speaker.context.close();
  }
});

test('a page that stops its live sound leaves alone the one that took its name over', async ({ browser }) => {
  test.skip(!realtime, 'The site has no Cloudflare Realtime app (REALTIME_APP_ID, REALTIME_APP_TOKEN)');
  const laptop = await device(browser, name, password), phone = await device(browser, name, password);
  const first = home + '/first.weba', second = home + '/second.weba';
  const listed = () => names(root, '/dev/snd');
  try {
    await run(laptop.page, 'cd ~'); await run(phone.page, 'cd ~');
    await run(laptop.page, 'stream -n shared first.weba');
    await expect(transcript(laptop.page)).toContainText('live as /dev/snd/shared', { timeout: 20_000 });
    // The phone, the same account, takes the name over.
    await run(phone.page, 'stream -n shared second.weba');
    await expect(transcript(phone.page)).toContainText('live as /dev/snd/shared', { timeout: 20_000 });
    // The laptop stops: the phone's sound goes on.
    await laptop.page.locator('#command').press('Control+c');
    await expect(transcript(laptop.page)).toContainText(`✓ ${first}`, { timeout: 30_000 });
    await laptop.page.waitForTimeout(1000);
    expect(await listed()).toContain('shared');
    await phone.page.locator('#command').press('Control+c');
    await expect(transcript(phone.page)).toContainText(`✓ ${second}`, { timeout: 30_000 });
    await expect.poll(listed, { timeout: 10_000 }).not.toContain('shared');
  } finally {
    await rmrf(root, first); await rmrf(root, second);
    await laptop.context.close(); await phone.context.close();
  }
});

test('stream -m gives the recording its ACL as it is made; entries it cannot take make nothing', async ({ browser }) => {
  const speaker = await device(browser, name, password);
  const page = speaker.page, recording = home + '/shared.weba';
  try {
    await run(page, 'cd ~');
    await run(page, 'stream -m bogus:x:r refused.weba');
    await expect(transcript(page)).toContainText('stream -m: ');
    await expect.poll(() => entry(root, home + '/refused.weba')).toBe(null);
    await run(page, 'stream -m g:guest:r,o::- shared.weba');
    await expect(transcript(page)).toContainText(/● \d\d:\d\d/);
    const acl = JSON.parse(Buffer.from(await call(root, { getxattr: { path: recording, name: 'system.posix_acl_access' } }), 'base64').toString());
    expect([acl.groups[65534], acl.other]).toEqual([4, 0]);
    await page.locator('#command').press('Control+c');
    await expect(transcript(page)).toContainText(`✓ ${recording}`, { timeout: 30_000 });
  } finally {
    await rmrf(root, recording);
    await speaker.context.close();
  }
});

test('stream -n NAME is live only: /dev/snd/NAME is a file of its own, whose permissions say who hears', async ({ browser }) => {
  test.skip(!realtime, 'The site has no Cloudflare Realtime app (REALTIME_APP_ID, REALTIME_APP_TOKEN)');
  const speaker = await device(browser, name, password), guest = await device(browser);
  const open = 'open' + Date.now().toString(36), closed = 'closed' + Date.now().toString(36);
  const listed = () => names(root, '/dev/snd');
  const other = await speaker.context.newPage(); await other.goto(origin + '/');
  try {
    await run(speaker.page, `stream -n ${open}`);
    await expect(transcript(speaker.page)).toContainText(new RegExp(`● live as /dev/snd/${open} · \\d\\d:\\d\\d`), { timeout: 20_000 });
    // The speaker's, made as a file is: others may read it, and so hear it.
    const node = await entry(root, '/dev/snd/' + open);
    expect([node.directory, node.owner, node.mode, node.size]).toEqual([false, name, 0o644, 0]);
    await run(guest.page, `open /dev/snd/${open}`);
    const player = guest.page.getByRole('region', { name: 'Live sound' });
    await expect(player).toHaveAttribute('data-state', /live|paused/, { timeout: 20_000 });
    await player.getByRole('button', { name: 'Stop listening' }).click();
    // -m o::- lets no one else hear it.
    await run(other, `stream -n ${closed} -m o::-`);
    await expect(transcript(other)).toContainText(`● live as /dev/snd/${closed}`, { timeout: 20_000 });
    await run(guest.page, `open /dev/snd/${closed}`);
    await expect(transcript(guest.page)).toContainText('Permission denied');
    // Stopped, it is gone; nothing was kept.
    for (const [page, device] of [[speaker.page, open], [other, closed]]) {
      await page.locator('#command').press('Control+c');
      await expect(transcript(page)).toContainText(new RegExp(`✓ /dev/snd/${device} · \\d\\d:\\d\\d`), { timeout: 30_000 });
    }
    await expect.poll(listed, { timeout: 10_000 }).not.toContain(open);
    expect(await listed()).not.toContain(closed);
  } finally {
    await sys(root, [{ unlink: { path: '/dev/snd/' + open } }]); await sys(root, [{ unlink: { path: '/dev/snd/' + closed } }]);
    await speaker.context.close(); await guest.context.close();
  }
});

test('a chunk R2 did not take once is sent again, and the recording goes on', async ({ browser }) => {
  const speaker = await device(browser, name, password);
  const page = speaker.page, recording = home + '/retried.weba';
  let refused = 0;
  await page.route('**/api/pwrite?**', route => {
    if (refused++ === 0) return route.fulfill({ status: 400, json: { error: 'Chunk upload failed, or the chunk does not match its SHA-256; send it again' } });
    return route.continue();
  });
  try {
    await run(page, 'cd ~');
    await run(page, 'stream retried.weba');
    await expect(transcript(page)).toContainText(/● 00:0[2-9]/, { timeout: 15_000 });
    await page.locator('#command').press('Control+c');
    await expect(transcript(page)).toContainText(`✓ ${recording}`, { timeout: 30_000 });
    expect(refused).toBeGreaterThan(1);
    const whole = await entry(root, recording);
    expect(whole.recording).toBeFalsy(); expect(whole.size).toBeGreaterThan(0);
  } finally {
    await rmrf(root, recording);
    await speaker.context.close();
  }
});

import { test, expect, request as playwrightRequest } from './test.js';
import { api, call, cloudAuth, entry, names, program, put, rmrf, sys } from './sys.js';
import {
  cloudSignIn,
  runTerminal,
  terminalInput,
  terminalScreen,
  terminalViewport,
  waitForTerminalReady,
} from './ui.js';

const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const rootPassword = process.env.OS_TEST_ADMIN_PASSWORD || process.env.OS_PASSWORD || '';
const realtime = Boolean(process.env.REALTIME_APP_ID && process.env.REALTIME_APP_TOKEN);
const file = path => '/api/file?path=' + encodeURIComponent(path);
const cloudPath = path => '/mnt/cloud' + path;
// Chromium's fake microphone, which plays a tone, granted without asking; and the launch options
// of playwright.config.js, which test.use replaces.
const browserEnv = { ...process.env }; delete browserEnv.DISPLAY;
test.use({ launchOptions: { env: browserEnv, args: ['--ozone-platform=headless', '--use-gl=angle', '--use-angle=swiftshader', '--enable-unsafe-swiftshader', '--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream'] } });
let sequence = 0;
const address = name => `sound-${name}-${Date.now()}-${++sequence}`;

const screen = page => terminalScreen(page);
async function promptSeq(page) {
  return Number((await terminalViewport(page).getAttribute('data-prompt-seq')) || '0');
}
async function waitIdleAfter(page, before, timeout = 30_000) {
  await expect.poll(async () => {
    const vp = terminalViewport(page);
    return (await vp.getAttribute('data-state')) === 'idle'
      && Number((await vp.getAttribute('data-prompt-seq')) || '0') > before;
  }, { timeout }).toBe(true);
}
async function device(browser, username, password, prepare = async () => {}) {
  const context = await browser.newContext({ permissions: ['microphone'], extraHTTPHeaders: { 'CF-Connecting-IP': address(username || 'guest') } });
  await prepare(context);
  // The microphones a page takes, to end them as if unplugged.
  await context.addInitScript(() => {
    const take = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
    navigator.mediaDevices.getUserMedia = async constraints => { const stream = await take(constraints); (window.microphones ??= []).push(stream); return stream; };
  });
  const page = await context.newPage(); await page.goto(origin + '/');
  await page.waitForFunction(() => Boolean(window.os?.cloudSignIn && window.os?.exec));
  await waitForTerminalReady(page);
  if (username) {
    await cloudSignIn(page, username, password);
    await expect(page.locator('.cloud-panel-trigger')).toContainText(`Cloud: ${username}`);
  } else {
    await expect(page.locator('.cloud-panel-trigger')).toContainText('Cloud: Signed out');
  }
  return { context, page };
}

let root, name, password, home;
test.beforeAll(async () => {
  root = await playwrightRequest.newContext({ baseURL: origin, extraHTTPHeaders: { Origin: origin, 'CF-Connecting-IP': address('api') } });
  expect((await api(root, 'login', { data: { password: rootPassword } })).ok()).toBe(true);
  name = 'voice' + Date.now().toString(36); password = 'sound-password-' + Date.now();
  const regCtx = await playwrightRequest.newContext({ baseURL: origin, extraHTTPHeaders: { Origin: origin, 'CF-Connecting-IP': address('reg') } });
  try {
    const res = await cloudAuth(regCtx, 'register', { data: { username: name, password, create_home: true } });
    expect(res.ok(), await res.text()).toBe(true);
    const body = await res.json();
    home = body.home || ('/guest/' + name);
  } finally {
    await regCtx.dispose();
  }
});
test.afterAll(async () => {
  if (home) await rmrf(root, home).catch(() => {});
  await root.dispose();
});

test('stream records the microphone into a file that grows as it is heard, and is whole once stopped', async ({ browser }) => {
  const speaker = await device(browser, name, password);
  const page = speaker.page, recording = home + '/talk.weba';
  try {
    await runTerminal(page, `cd ${cloudPath(home)}`);
    // Browsers record Opus in WebM, so a recording is a .weba.
    await runTerminal(page, 'stream talk.aac');
    await expect(screen(page)).toContainText('browsers record Opus in WebM; name the recording NAME.weba');
    const seq = await promptSeq(page);
    await runTerminal(page, 'stream talk.weba', { wait: false });
    await expect(screen(page)).toContainText(/● \d\d:\d\d/, { timeout: 20_000 });
    // The file is there at once, a recording, and grows, a chunk at a time.
    const stat = () => entry(root, recording);
    await expect.poll(async () => (await stat())?.recording, { timeout: 15_000 }).toBe(true);
    await expect.poll(async () => (await stat())?.size ?? 0, { timeout: 60_000, intervals: [1000] }).toBeGreaterThan(0);
    const grown = (await stat()).size;
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
    await terminalInput(page).press('Control+c');
    await expect(screen(page)).toContainText(new RegExp(`✓ (?:${cloudPath(recording)}|${recording}) · \\d\\d:\\d\\d`), { timeout: 30_000 });
    await waitIdleAfter(page, seq);
    const whole = await stat();
    expect(whole.recording).toBeFalsy(); expect(whole.uploaded).toBeUndefined();
    expect(whole.size).toBeGreaterThan(grown);
    const bytes = await (await root.get(file(recording), { headers: { 'Accept-Encoding': 'identity' } })).body();
    expect(bytes.length).toBe(whole.size);
    expect(bytes.subarray(0, 4).toString('hex')).toBe('1a45dfa3');
    // It is a new file: another recording does not replace it.
    await runTerminal(page, 'stream talk.weba');
    await expect(screen(page)).toContainText('File already exists');
  } finally {
    await rmrf(root, recording);
    await speaker.context.close();
  }
});

test('a recording whose microphone stops on its own is saved, with what it heard', async ({ browser }) => {
  const speaker = await device(browser, name, password);
  const page = speaker.page, recording = home + '/unplugged.weba';
  try {
    await runTerminal(page, `cd ${cloudPath(home)}`);
    const seq = await promptSeq(page);
    await runTerminal(page, 'stream unplugged.weba', { wait: false });
    await expect(screen(page)).toContainText(/● 00:0[3-9]/, { timeout: 15_000 });
    // Unplugged, or taken back by the browser: every track of the microphone ends.
    await page.evaluate(() => window.microphones.forEach(stream => stream.getTracks().forEach(track => track.stop())));
    await expect(screen(page)).toContainText(new RegExp(`✓ (?:${cloudPath(recording)}|${recording}) · \\d\\d:\\d\\d[\\s\\S]* · the microphone stopped`), { timeout: 30_000 });
    const whole = await entry(root, recording);
    expect(whole.recording).toBeFalsy(); expect(whole.size).toBeGreaterThan(0);
    await waitIdleAfter(page, seq);
  } finally {
    await rmrf(root, recording);
    await speaker.context.close();
  }
});

test('live sound: /dev/snd/NAME is heard by whoever may read it, and with the presentation of its name', async ({ browser }) => {
  test.skip(!realtime, 'The site has no Cloudflare Realtime app (REALTIME_APP_ID, REALTIME_APP_TOKEN)');
  const speaker = await device(browser, name, password), guest = await device(browser);
  const remote = await speaker.context.newPage(); await remote.goto(origin + '/');
  await remote.waitForFunction(() => Boolean(window.os?.cloudSignIn));
  await waitForTerminalReady(remote);
  await cloudSignIn(remote, name, password);
  const recording = home + '/lecture.weba', deck = home + '/lecture.slides.md';
  try {
    expect((await put(root, file(deck), { data: '# One\n\n---\n\n# Two\n' })).status()).toBe(201);
    for (const args of [['chmod', '755', home], ['chmod', '644', deck]]) expect((await program(root, args)).ok()).toBe(true);
    await runTerminal(speaker.page, `cd ${cloudPath(home)}`);
    const seq = await promptSeq(speaker.page);
    await runTerminal(speaker.page, 'stream -n lecture lecture.weba', { wait: false });
    await expect(screen(speaker.page)).toContainText('live as /dev/snd/lecture', { timeout: 20_000 });
    // A guest hears it, as the device, made with the umask, may be read by others.
    await runTerminal(guest.page, 'open /dev/snd/lecture');
    const player = guest.page.getByRole('region', { name: 'Live sound' });
    await expect(player).toBeVisible(); await expect(player).toHaveAttribute('data-state', /live|paused/, { timeout: 20_000 });
    await expect.poll(() => guest.page.evaluate(() => document.getElementById('listening-audio').srcObject?.getAudioTracks()[0]?.readyState), { timeout: 20_000 }).toBe('live');
    // A presentation of the same name brings its sound with it.
    await player.getByRole('button', { name: 'Stop listening' }).click();
    await expect(player).toBeHidden();
    await runTerminal(remote, `present -n lecture ${cloudPath(deck)}`);
    await expect(remote.locator('.slides-current .slide:visible h1')).toHaveText('One');
    await runTerminal(guest.page, 'open /dev/present/lecture');
    await expect(guest.page.locator('.slides-current .slide:visible h1')).toHaveText('One');
    await expect(guest.page.getByRole('region', { name: 'Live sound' })).toBeVisible();
    // Stopped, the sound ends for its listeners.
    await terminalInput(speaker.page).press('Control+c');
    await expect(screen(speaker.page)).toContainText(new RegExp(`✓ (?:${cloudPath(recording)}|${recording})`), { timeout: 30_000 });
    await waitIdleAfter(speaker.page, seq);
    await expect(guest.page.getByRole('region', { name: 'Live sound' })).toBeHidden({ timeout: 10_000 });
  } finally {
    await rmrf(root, recording); await rmrf(root, deck);
    await sys(root, [{ unlink: { path: '/dev/present/lecture' } }]);
    await speaker.context.close(); await guest.context.close();
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
    await runTerminal(page, `cd ${cloudPath(home)}`);
    const seq = await promptSeq(page);
    await runTerminal(page, 'stream unheard.weba', { wait: false });
    await expect(screen(page)).toContainText('not live: The sound did not connect', { timeout: 30_000 });
    await expect.poll(listed, { timeout: 10_000 }).not.toContain('unheard');
    await terminalInput(page).press('Control+c');
    await expect(screen(page)).toContainText(new RegExp(`✓ (?:${cloudPath(recording)}|${recording})`), { timeout: 30_000 });
    await waitIdleAfter(page, seq);
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
    await runTerminal(laptop.page, `cd ${cloudPath(home)}`); await runTerminal(phone.page, `cd ${cloudPath(home)}`);
    const seqLaptop = await promptSeq(laptop.page);
    await runTerminal(laptop.page, 'stream -n shared first.weba', { wait: false });
    await expect(screen(laptop.page)).toContainText('live as /dev/snd/shared', { timeout: 20_000 });
    // The phone, the same account, takes the name over.
    const seqPhone = await promptSeq(phone.page);
    await runTerminal(phone.page, 'stream -n shared second.weba', { wait: false });
    await expect(screen(phone.page)).toContainText('live as /dev/snd/shared', { timeout: 20_000 });
    // The laptop stops: the phone's sound goes on.
    await terminalInput(laptop.page).press('Control+c');
    await expect(screen(laptop.page)).toContainText(new RegExp(`✓ (?:${cloudPath(first)}|${first})`), { timeout: 30_000 });
    await waitIdleAfter(laptop.page, seqLaptop);
    await laptop.page.waitForTimeout(1000);
    expect(await listed()).toContain('shared');
    await terminalInput(phone.page).press('Control+c');
    await expect(screen(phone.page)).toContainText(new RegExp(`✓ (?:${cloudPath(second)}|${second})`), { timeout: 30_000 });
    await waitIdleAfter(phone.page, seqPhone);
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
    await runTerminal(page, `cd ${cloudPath(home)}`);
    await runTerminal(page, 'stream -m bogus:x:r refused.weba');
    await expect(screen(page)).toContainText('stream -m: ');
    await expect.poll(() => entry(root, home + '/refused.weba')).toBe(null);
    const seq = await promptSeq(page);
    await runTerminal(page, 'stream -m g:65534:r,o::- shared.weba', { wait: false });
    await expect(screen(page)).toContainText(/● \d\d:\d\d/, { timeout: 20_000 });
    const acl = JSON.parse(Buffer.from(await call(root, { getxattr: { path: recording, name: 'system.posix_acl_access' } }), 'base64').toString());
    expect([acl.groups[65534], acl.other]).toEqual([4, 0]);
    await terminalInput(page).press('Control+c');
    await expect(screen(page)).toContainText(new RegExp(`✓ (?:${cloudPath(recording)}|${recording})`), { timeout: 30_000 });
    await waitIdleAfter(page, seq);
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
  await other.waitForFunction(() => Boolean(window.os?.cloudSignIn));
  await waitForTerminalReady(other);
  await cloudSignIn(other, name, password);
  try {
    const seqSpeaker = await promptSeq(speaker.page);
    await runTerminal(speaker.page, `stream -n ${open}`, { wait: false });
    await expect(screen(speaker.page)).toContainText(new RegExp(`● live as /dev/snd/${open} · \\d\\d:\\d\\d`), { timeout: 20_000 });
    // The speaker's, made as a file is: others may read it, and so hear it.
    const node = await entry(root, '/dev/snd/' + open);
    expect([node.directory, node.owner, node.mode, node.size]).toEqual([false, name, 0o644, 0]);
    await runTerminal(guest.page, `open /dev/snd/${open}`);
    const player = guest.page.getByRole('region', { name: 'Live sound' });
    await expect(player).toHaveAttribute('data-state', /live|paused/, { timeout: 20_000 });
    await player.getByRole('button', { name: 'Stop listening' }).click();
    // -m o::- lets no one else hear it.
    const seqOther = await promptSeq(other);
    await runTerminal(other, `stream -n ${closed} -m o::-`, { wait: false });
    await expect(screen(other)).toContainText(`● live as /dev/snd/${closed}`, { timeout: 20_000 });
    await runTerminal(guest.page, `open /dev/snd/${closed}`);
    await expect(screen(guest.page)).toContainText('Permission denied');
    // Stopped, it is gone; nothing was kept.
    for (const [page, deviceName, seq] of [[speaker.page, open, seqSpeaker], [other, closed, seqOther]]) {
      await terminalInput(page).press('Control+c');
      await expect(screen(page)).toContainText(new RegExp(`✓ /dev/snd/${deviceName} · \\d\\d:\\d\\d`), { timeout: 30_000 });
      await waitIdleAfter(page, seq);
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
    await runTerminal(page, `cd ${cloudPath(home)}`);
    const seq = await promptSeq(page);
    await runTerminal(page, 'stream retried.weba', { wait: false });
    await expect(screen(page)).toContainText(/● 00:0[2-9]/, { timeout: 15_000 });
    await terminalInput(page).press('Control+c');
    await expect(screen(page)).toContainText(new RegExp(`✓ (?:${cloudPath(recording)}|${recording})`), { timeout: 30_000 });
    await waitIdleAfter(page, seq);
    expect(refused).toBeGreaterThan(1);
    const whole = await entry(root, recording);
    expect(whole.recording).toBeFalsy(); expect(whole.size).toBeGreaterThan(0);
  } finally {
    await rmrf(root, recording);
    await speaker.context.close();
  }
});

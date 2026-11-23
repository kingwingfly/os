import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { Worker } from 'node:worker_threads';
import { reservedShortcut, documentSource, documentFrame } from '../web/gui/document-frame.js';
import { gestureRect, dragStatistics } from '../web/gui/host-adapter.js';
import { PixelSurface } from '../web/gui/pixel-surface.js';

const sha = s => createHash('sha256').update(s).digest('hex');
test('G-05 sealed source pins each script and the verified stylesheet', async () => {
  const bundle = { html: '<h1>Notes</h1>', css: 'h1{color:teal}', js: 'window.gui.send("ready")' };
  const doc = { bundle, script_sha256: sha(bundle.js), style_sha256: sha(bundle.css) };
  const html = await documentSource(doc, '31'.repeat(16));
  for (const rule of ["default-src 'none'", "connect-src 'none'", "form-action 'none'", "object-src 'none'", "frame-src 'none'"]) assert.ok(html.includes(rule));
  const boot = html.match(/<script>([\s\S]*?)<\/script>/)[1];
  assert.ok(html.includes("'sha256-" + createHash('sha256').update(boot).digest('base64') + "'"));
  assert.ok(html.includes("'sha256-" + Buffer.from(doc.script_sha256, 'hex').toString('base64') + "'"));
  await assert.rejects(documentSource({ ...doc, bundle: { ...bundle, js: 'changed()' } }, 'nonce'), /digest/);
});
test('G-06 move and all eight resize handles clamp at the viewport and size limits', () => {
  const start = { x: 50, y: 70, width: 180, height: 120 };
  const lease = { op: 'move', bounds: { x: 0, y: 0, width: 600, height: 400 }, min_size: { width: 120, height: 60 }, max_size: { width: 220, height: 160 } };
  assert.deepEqual(gestureRect(start, 1000, -900, lease), { ...start, x: 420, y: 0 });
  for (const edge of ['n','s','e','w','ne','nw','se','sw']) for (const delta of [-999,999]) {
    const r = gestureRect(start, delta, delta, { ...lease, op: { resize: { edge } } });
    assert.ok(r.x >= 0 && r.y >= 0 && r.x+r.width <= 600 && r.y+r.height <= 400);
    assert.ok(r.width >= 120 && r.width <= 220 && r.height >= 60 && r.height <= 160);
  }
  assert.deepEqual(dragStatistics([2,25,1,3], 12, 2000), { samples: 4, p50: 2, p95: 25, p99: 25, max: 25, dropped: 1, messages: 12, messagesPerSecond: 6 });
});
test('G-05 the private port requires the exact frame, opaque origin and one-use nonce', async t => {
  const parent = new EventTarget(), channel = [], owner = [];
  const child = { postMessage: (_, target, ports) => channel.push(...ports) };
  globalThis.window = parent;
  globalThis.document = { createElement: () => ({ contentWindow: child, setAttribute() {} }) };
  t.after(() => { delete globalThis.window; delete globalThis.document; for (const port of [...channel, ...owner]) port.close(); });
  const bundle = { html: '', css: '', js: '' };
  const frame = await documentFrame({ bundle, script_sha256: sha(''), style_sha256: sha('') }, 'Document', p => owner.push(p), new AbortController().signal);
  const nonce = frame.srcdoc.match(/\)\("([0-9a-f]{32})",/)[1];
  const ready = (source, origin, bootNonce) => parent.dispatchEvent(Object.assign(new Event('message'), {
    source, origin, data: { type: 'gui-frame-ready', bootNonce },
  }));
  ready({}, 'null', nonce); ready(child, 'https://host.invalid', nonce); ready(child, 'null', 'incorrect');
  assert.equal(owner.length, 0); ready(child, 'null', nonce); ready(child, 'null', nonce);
  assert.equal(owner.length, 1); assert.equal(channel.length, 1);
  const received = new Promise(resolve => owner[0].once('message', resolve));
  channel[0].postMessage('private endpoint'); assert.equal(await received, 'private endpoint');
});
test('G-07 composition and keyCode 229 suppress every reserved shortcut', () => {
  for (const event of [{ key: 'F4', altKey: true },{ code: 'Backquote', altKey: true },{ key: 'ArrowLeft', altKey: true, ctrlKey: true }]) {
    assert.ok(reservedShortcut(event)); assert.equal(reservedShortcut({ ...event, isComposing: true }), null);
    assert.equal(reservedShortcut({ ...event, keyCode: 229 }), null);
  }
});
test('G-08 a lost GPU context receives a fresh software canvas and stale loss is fenced', async () => {
  const events = [], contexts = [], gpu = Object.getOwnPropertyDescriptor(navigator, 'gpu');
  let lose;
  const device = { lost: new Promise(resolve => { lose = resolve; }), destroy() {} };
  Object.defineProperty(navigator, 'gpu', { configurable: true, value: { requestAdapter: async () => ({ requestDevice: async () => device }), getPreferredCanvasFormat: () => 'bgra8unorm' } });
  try {
    const renderer = new PixelSurface(e => events.push(e));
    const canvas = label => ({ width: 200, height: 120, getContext(type) { contexts.push([label,type]); return { configure() {}, fillRect() {}, beginPath() {}, arc() {}, fill() {} }; } });
    await renderer.bind({ surface_id: 5, generation: 1, canvas: canvas('first') });
    lose({ reason: 'destroyed' }); await Promise.resolve();
    assert.deepEqual(events.map(e => e.op), ['surface_ready','surface_device_lost']);
    await renderer.bind({ surface_id: 5, generation: 2, canvas: canvas('replacement'), backend: 'software2d' });
    renderer.paint(5, 2, 0x297268); await renderer.bind({ surface_id: 5, generation: 1, canvas: canvas('stale') });
    assert.deepEqual(contexts, [['first','webgpu'],['replacement','2d']]);
    assert.equal(events.at(-1).generation, 2);
  } finally { if (gpu) Object.defineProperty(navigator, 'gpu', gpu); else delete navigator.gpu; }
});

test('G-01..05, G-09..10 packaged WASI processes bind the seat, exchange private events and recover', { timeout: 60000 }, async t => {
  const worker = new Worker(new URL('./mount-service-worker.mjs', import.meta.url), { workerData: '/client-kernel.js' });
  t.after(() => worker.terminate());
  const pending = new Map(), events = []; let sequence = 0, packets = 0, wake;
  worker.on('message', m => {
    packets++;
    if (m.event) { events.push(m); wake?.(); return; }
    const waiter = pending.get(m.id); if (!waiter) return;
    pending.delete(m.id); if (m.err) waiter.reject(Object.assign(new Error(m.err.detail || m.err.errno), m.err)); else waiter.resolve(m.ok);
  });
  function call(type, args, handles = []) {
    packets++;
    return new Promise((resolve, reject) => { pending.set(++sequence, { resolve, reject }); worker.postMessage({ v: 2, id: sequence, tab: 'gui-test', type, args }, handles); });
  }
  async function until(event, predicate, after = 0) {
    const deadline = Date.now() + 12000;
    for (;;) {
      const value = events.slice(after).find(m => m.event === event && predicate(m.value))?.value;
      if (value) return value;
      if (Date.now() > deadline) assert.fail('Waiting for ' + event + ': ' + JSON.stringify(events.filter(m => m.event.startsWith('gui')).slice(-8)).slice(-2500));
      await new Promise(resolve => { const timer = setTimeout(resolve, 100); wake = () => { clearTimeout(timer); resolve(); }; });
    }
  }
  const launch = (program, argv = []) => call('gui_start', { program, argv });
  const display = (op, f = () => true, after = 0) => until('gui-display', c => c.op === op && f(c), after);
  const kill = pid => call('gui_stop', { pid });
  const comp = await launch('compositor');
  await display('set_drag_mode');
  const duplicate = await launch('compositor');
  assert.match((await until('gui-exit', v => v.pid === duplicate)).stderr, /EBUSY/);
  const doc = await launch('gui-sample-doc'), pixel = await launch('gui-sample-pixel');
  const a = await display('map', c => c.owner_pid === doc), b = await display('map', c => c.owner_pid === pixel);
  assert.equal(a.document.content_sha256, sha(await readFile(new URL('../dist/usr/share/gui/samples/doc-view.json', import.meta.url))));
  assert.equal(b.document, null); assert.notEqual(a.surface_id, b.surface_id);
  await t.test('G-06 packaged Worker drag latency in both modes', async () => {
    const bounds = { x: 0, y: 0, width: 1280, height: 800 }, id = a.surface_id;
    const input = event => call('gui_host_event', { event });
    let origin = a.rect;
    for (const mode of ['local_lease', 'roundtrip']) {
      let at = events.length;
      await call('gui_viewport', { bounds, mode }); await display('geometry', c => c.surface_id === id, at);
      await call('gui_worker_metrics', { pid: comp, start: true });
      const start = performance.now(), before = packets, samples = [];
      at = events.length;
      await input({ op: 'pointer_down', surface_id: id, hit_region: 'titlebar', pointer_id: 7, x: 40, y: 40, timestamp_ms: Date.now() });
      const { lease } = await display('begin_interactive_op', c => c.lease.surface_id === id, at);
      let rect = origin, lastProgress = -Infinity;
      for (let i = 1; i <= 120; i++) {
        await new Promise(resolve => setTimeout(resolve, Math.max(0, start + i * 1000 / 60 - performance.now())));
        const dispatch = performance.now();
        rect = gestureRect(origin, i, 0, lease);
        if (mode === 'roundtrip') {
          at = events.length;
          await input({ op: 'interactive_op_progress', surface_id: id, lease_id: lease.lease_id, rect, snap_hint: null });
          rect = (await display('drag_frame', c => c.lease_id === lease.lease_id, at)).rect;
        }
        assert.equal(rect.x, origin.x + i);
        samples.push(performance.now() - dispatch);
        if (mode === 'local_lease' && dispatch - lastProgress >= 100) {
          await input({ op: 'interactive_op_progress', surface_id: id, lease_id: lease.lease_id, rect, snap_hint: null });
          lastProgress = dispatch;
        }
      }
      at = events.length;
      await input({ op: 'interactive_op_end', surface_id: id, lease_id: lease.lease_id, rect, snap_hint: null, canceled: false });
      origin = (await display('geometry', c => c.surface_id === id, at)).rect;
      assert.deepEqual(origin, rect);
      const pageMessages = packets - before, elapsed = performance.now() - start;
      const processMessages = await call('gui_worker_metrics', { pid: comp, start: false });
      assert.ok(processMessages > 0);
      t.diagnostic('Worker drag ' + JSON.stringify({ mode, ...dragStatistics(samples, pageMessages + processMessages, elapsed), pageMessages, processMessages }));
    }
  });
  const sys = async (op, sudo = false) => (await call('mount_sys', { calls: [op], sudo }))[0];
  for (const path of ['/dev/display', '/dev/input']) {
    const stat = (await sys({ stat: { path } })).ok;
    assert.deepEqual([stat.uid, stat.gid, stat.mode & 0o777], [0, 0, 0o600]);
    assert.equal((await sys({ open: { path, flags: 0 } })).err.errno, 'EACCES');
    assert.equal((await sys({ open: { path, flags: 0 } }, true)).err.errno, 'EPERM');
    const handle = (await sys({ open: { path, flags: 0o10000000 } })).ok;
    assert.ok(handle.fd >= 0);
    assert.ok('ok' in await sys({ close: { fd: handle.fd } }));
  }
  const probe = async req => {
    const pid = await launch('gui-sample-doc',['--request', JSON.stringify(req)]);
    return JSON.parse((await until('gui-exit', v => v.pid === pid)).stdout);
  };
  for (const [request, errno] of [
    [{ op: 'hello', versions: [42], required: [] }, 'EPROTONOSUPPORT'],
    [{ op: 'hello', versions: [1], required: ['unknown'] }, 'EOPNOTSUPP'],
    [{ op: 'destroy', surface_id: a.surface_id }, 'EACCES'],
    [{ op: 'create_surface', spec: { role: 'lock', kind: 'pixel', title: '', rect: a.rect, min_size: { width: 1, height: 1 }, max_size: null, resizable: false } }, 'EPERM'],
  ]) assert.deepEqual(await probe(request), { op: 'error', errno });
  const { port1, port2 } = new MessageChannel();
  t.after(() => port1.close());
  await call('gui_surface_port', { surface_id: a.surface_id, port: port2 }, [port2]);
  const message = new Promise(resolve => port1.once('message', resolve));
  port1.postMessage({ type: 'message', text: JSON.stringify({ action: 'edit', text: '日本語' }) });
  assert.deepEqual(await message, { text: '3 characters' });
  const command = (action, extra) => port1.postMessage({ type: 'message', text: JSON.stringify({ action, ...extra }) });
  const response = () => new Promise(resolve => port1.once('message', m => resolve(m.text)));
  const sendInput = event => call('gui_host_event', { event });
  await sendInput({ op: 'focus_request', surface_id: b.surface_id });
  let reply = response(); command('pick'); assert.equal(await reply, 'EACCES');
  await sendInput({ op: 'pointer_down', hit_region: 'content', surface_id: a.surface_id, pointer_id: 1, x: 0, y: 0, timestamp_ms: Date.now() });
  command('copy', { text: 'seat clipboard' });
  await display('clipboard_write');
  reply = response(); command('paste'); assert.equal(await reply, 'EACCES');
  await sendInput({ op: 'key', surface_id: a.surface_id, paste: true });
  reply = response(); command('paste'); assert.equal(await reply, 'seat clipboard');
  command('pick');
  const pick = await display('pick_file');
  reply = response();
  await call('gui_picker_result', { surface_id: a.surface_id, request_id: pick.request_id, file: null });
  assert.equal(await reply, 'ECANCELED');
  const beforePick = events.length;
  await sendInput({ op: 'key', surface_id: a.surface_id, paste: false });
  command('pick');
  const chosen = await display('pick_file', () => true, beforePick);
  reply = response();
  await call('gui_picker_result', { surface_id: a.surface_id, request_id: chosen.request_id, file: new File(['hello'], 'chosen.txt') });
  assert.equal(await reply, 'Selected 5 bytes');
  for (const expected of ['Notification sent','Notification sent','Notification sent','EAGAIN']) {
    reply = response(); command('notify'); assert.equal(await reply, expected);
  }
  const bad = await launch('gui-sample-doc', ['--sha256', '0'.repeat(64)]);
  assert.match((await until('gui-exit', v => v.pid === bad)).stderr, /EIO/);
  const bundle = '/usr/share/gui/samples/doc-view.json';
  const req = { op: 'create_surface', spec: { role: 'window', title: 'Passed file', rect: a.rect,
    min_size: { width: 1, height: 1 }, max_size: null, resizable: false,
    kind: { document: { bundle_path: '/unopened', expected_sha256: a.document.content_sha256 } } } };
  const passed = await launch('gui-sample-doc', ['--request', JSON.stringify(req), '--fd', bundle]);
  assert.equal(JSON.parse((await until('gui-exit', v => v.pid === passed)).stdout).op, 'created');
  const beforeFocus = events.length;
  await call('gui_host_event', { event: { op: 'focus_request', surface_id: b.surface_id } });
  await display('focus', c => c.surface_id === b.surface_id, beforeFocus);
  let at = events.length; await kill(pixel); await display('unmap', c => c.surface_id === b.surface_id, at);
  await display('focus', c => c.surface_id === a.surface_id, at);
  at = events.length; await kill(comp); await display('seat_reset', () => true, at);
  const shellPid = await call('gui_start', { program: 'gui-sample-doc', securityRole: 'lock' });
  await call('gui_start', { program: 'compositor', shellPid });
  await display('set_drag_mode', () => true, at);
  const lock = await display('map', c => c.role === 'lock', at);
  assert.equal(lock.owner_pid, shellPid); assert.notEqual(lock.surface_id, a.surface_id);
  await display('focus', c => c.surface_id === lock.surface_id && c.modal, at);
});

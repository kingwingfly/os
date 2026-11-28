import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { Worker } from 'node:worker_threads';
import { reservedShortcut, documentSource, documentFrame } from '../web/gui/document-frame.js';
import { HostPresentationAdapter, gestureRect, dragStatistics } from '../web/gui/host-adapter.js';
import { enqueueSeat } from '../web/gui/seat-queue.js';
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
  assert.deepEqual(dragStatistics([2,25,1,3], 12, 2000), { samples: 4, p50: 2, p95: 25, p99: 25, max: 25, late: 1, missed: 0, messages: 12, messagesPerSecond: 6 });
});
test('G-05 the private port requires the exact frame, opaque origin and one-use nonce', async t => {
  const parent = new EventTarget(), channel = [], owner = [];
  const child = { postMessage: (_, target, ports) => channel.push(...ports) };
  globalThis.window = parent;
  globalThis.document = { createElement: () => Object.assign(new EventTarget(), { contentWindow: child, setAttribute() {} }) };
  t.after(() => { delete globalThis.window; delete globalThis.document; for (const port of [...channel, ...owner]) port.close(); });
  const bundle = { html: '', css: '', js: '' };
  let revocations = 0, controls = [];
  const adapter = Object.create(HostPresentationAdapter.prototype);
  adapter.hostControlFocus = -Infinity;
  const frame = await documentFrame({ bundle, script_sha256: sha(''), style_sha256: sha('') }, 'Document', { port: p => owner.push(p), revoke: () => { revocations++; owner[0].close(); }, control: data => controls.push(data), canPress: at => adapter.canPress(at), error: assert.fail }, new AbortController().signal);
  const nonce = frame.srcdoc.match(/\)\("([0-9a-f]{32})",/)[1];
  const ready = (source, origin, bootNonce) => parent.dispatchEvent(Object.assign(new Event('message'), {
    source, origin, data: { type: 'gui-frame-ready', bootNonce },
  }));
  ready({}, 'null', nonce); ready(child, 'https://host.invalid', nonce); ready(child, 'null', 'incorrect');
  assert.equal(owner.length, 0); ready(child, 'null', nonce); ready(child, 'null', nonce);
  assert.equal(owner.length, 0); frame.dispatchEvent(new Event('load'));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(owner.length, 1); assert.equal(channel.length, 2);
  const received = new Promise(resolve => owner[0].once('message', resolve));
  channel[0].postMessage('private endpoint'); assert.equal(await received, 'private endpoint');
  const control = async (serial, data = { op: 'focus_request' }) => {
    const ack = new Promise(resolve => channel[1].once('message', resolve));
    channel[1].postMessage({ serial, data });
    assert.equal(await ack, serial);
  };
  await control(1); assert.deepEqual(controls, []);
  document.activeElement = frame; await control(2);
  assert.deepEqual(controls, [{ op: 'focus_request' }]);
  const press = { op: 'pointer_down', pressedAt: 12 };
  adapter.hostControlFocus = 13;
  document.activeElement = { closest: () => ({}) }; // Host toolbar or chooser.
  await control(3, press);
  document.activeElement = frame;
  await control(4, press);
  assert.equal(controls.length, 1);
  document.activeElement = { closest: () => null }; // A different surface.
  await control(5, { ...press, pressedAt: 14 });
  assert.equal(controls.at(-1).op, 'pointer_down');
  frame.dispatchEvent(new Event('load')); assert.equal(revocations, 1);
});
test('mandatory seat transitions retry queue pressure and stop on a retired seat', async () => {
  let attempts = 0, wakes = 0, delivered = 0;
  await enqueueSeat(() => {
    if (++attempts <= 2) throw Object.assign(new Error('seat full'), { errno: 'EAGAIN' });
    delivered++;
  }, () => { wakes++; });
  assert.deepEqual([attempts, wakes, delivered], [3, 3, 1]);
  await assert.rejects(enqueueSeat(() => { throw Object.assign(new Error('retired'), { errno: 'ESTALE' }); }, assert.fail),
    e => e.errno === 'ESTALE');
});
test('G-07 composition and keyCode 229 suppress every reserved shortcut', () => {
  for (const event of [{ key: 'F4', altKey: true },{ code: 'Backquote', altKey: true },{ key: 'ArrowLeft', altKey: true, ctrlKey: true }]) {
    assert.ok(reservedShortcut(event)); assert.equal(reservedShortcut({ ...event, isComposing: true }), null);
    assert.equal(reservedShortcut({ ...event, keyCode: 229 }), null);
  }
});
test('Pixel key and native paste delivery requires trusted input on the focused canvas', t => {
  const handlers = new Map(), inputs = [];
  globalThis.window = { addEventListener: (event, fn) => handlers.set(event, fn) };
  globalThis.document = { createElement: () => ({ setAttribute() {} }) };
  t.after(() => { delete globalThis.window; delete globalThis.document; });
  const adapter = new HostPresentationAdapter({ append() {} }, { input: e => inputs.push(e) });
  const surface = { dataset: { surfaceId: '7' } };
  const canvas = { closest: selector => selector === '.surface' ? surface : null };
  const minimize = { closest: selector => selector === '.surface' ? surface : minimize };
  adapter.surfaces.set(7, { id: 7, canvas });
  const key = { key: 'Delete', code: 'Delete', isTrusted: true };
  let prevented = 0;
  const paste = text => ({ isTrusted: true, clipboardData: { types: ['text/plain'], getData: () => text }, preventDefault: () => prevented++ });
  document.activeElement = minimize;
  handlers.get('keydown')({ ...key, target: minimize });
  handlers.get('paste')(paste('toolbar'));
  assert.deepEqual(inputs, []);
  assert.equal(prevented, 0);
  document.activeElement = canvas;
  handlers.get('paste')({ ...paste('synthetic'), isTrusted: false });
  handlers.get('paste')(paste('界'.repeat(350000)));
  handlers.get('paste')(paste('system clipboard'));
  handlers.get('keydown')({ ...key, target: canvas });
  assert.equal(prevented, 2);
  assert.deepEqual(inputs.map(e => [e.op, e.surface_id, e.text ?? e.key]), [['paste', 7, 'system clipboard'], ['key', 7, 'Delete']]);
});
test('G-08 a lost GPU context receives a fresh software canvas and stale loss is fenced', async () => {
  const events = [], contexts = [], gpu = Object.getOwnPropertyDescriptor(navigator, 'gpu');
  let lose;
  let destroyed = 0;
  const device = { lost: new Promise(resolve => { lose = resolve; }), destroy() { destroyed++; } };
  Object.defineProperty(navigator, 'gpu', { configurable: true, value: { requestAdapter: async () => ({ requestDevice: async () => device }), getPreferredCanvasFormat: () => 'bgra8unorm' } });
  try {
    const renderer = new PixelSurface(e => events.push(e));
    const canvas = label => ({ width: 320, height: 240, getContext(type) { contexts.push([label,type]); return { configure() {}, fillRect() {}, beginPath() {}, arc() {}, fill() {} }; } });
    const initial = canvas('first');
    renderer.resize(5, 420, 300);
    await renderer.bind({ surface_id: 5, generation: 1, canvas: initial });
    assert.deepEqual([initial.width, initial.height], [420, 300]);
    assert.deepEqual([events[0].width, events[0].height], [420, 300]);
    lose({ reason: 'destroyed' }); await Promise.resolve();
    assert.deepEqual(events.map(e => e.op), ['surface_ready','surface_device_lost']);
    renderer.resize(5, 480, 310);
    renderer.dispose({ surface_id: 5, generation: 1, retainSize: true });
    assert.equal(destroyed, 1);
    assert.equal(renderer.current.size, 0);
    assert.deepEqual(renderer.desiredSizes.get(5), { width: 480, height: 310 });
    const replacement = Object.assign(new EventTarget(), canvas('replacement'));
    await renderer.bind({ surface_id: 5, generation: 2, canvas: replacement, backend: 'software2d' });
    assert.deepEqual([replacement.width, replacement.height], [480, 310]);
    assert.equal(destroyed, 1);
    renderer.paint(5, 2, 0x297268); await renderer.bind({ surface_id: 5, generation: 1, canvas: canvas('stale') });
    assert.deepEqual(contexts, [['first','webgpu'],['replacement','2d']]);
    assert.equal(events.at(-1).generation, 2);
    replacement.dispatchEvent(new Event('contextlost', { cancelable: true }));
    assert.equal(events.at(-1).op, 'surface_device_lost');
    renderer.dispose({ surface_id: 5, generation: 1 }); assert.equal(renderer.current.size, 1);
    renderer.dispose({ surface_id: 5, generation: 2 }); assert.equal(renderer.current.size, 0);
    assert.equal(renderer.desiredSizes.size, 0);
  } finally { if (gpu) Object.defineProperty(navigator, 'gpu', gpu); else delete navigator.gpu; }
});

test('packaged service modules expose only their own GUI entry points', async () => {
  const guests = (await readdir(new URL('../dist/usr/bin/', import.meta.url))).filter(name => name.endsWith('.wasm')).map(name => name.slice(0, -5));
  for (const required of ['init','supervise','mountd','exportd','compositor','desktop-shell','greeter','terminal','files','mounts','settings','editor','preview','osh','gui-sample-doc','gui-sample-pixel']) assert.ok(guests.includes(required), required);
  for (const name of guests) {
    const module = await WebAssembly.compile(await readFile(new URL('../dist/usr/bin/' + name + '.wasm', import.meta.url)));
    const imports = WebAssembly.Module.imports(module).filter(i => i.name.startsWith('gui_') || i.module.startsWith('gui')).map(i => i.module + '.' + i.name).sort();
    const exports = WebAssembly.Module.exports(module).filter(e => e.name.startsWith('gui_')).map(e => e.name);
    assert.deepEqual(imports, name === 'gui-sample-pixel' ? ['os.gui_dispatch','os.gui_paint','os.gui_resize'] : name === 'gui-sample-doc' ? ['os.gui_dispatch'] : [], name);
    assert.deepEqual(exports, name.startsWith('gui-sample-') ? ['gui_client_tick'] : [], name);
  }
  const bundleRaw = await readFile(new URL('../dist/usr/share/gui/terminal/terminal.json', import.meta.url));
  const bundle = JSON.parse(bundleRaw.toString('utf8'));
  assert.equal(typeof bundle.html, 'string');
  assert.equal(typeof bundle.css, 'string');
  assert.equal(typeof bundle.js, 'string');
  const html = await documentSource({ bundle, script_sha256: sha(bundle.js), style_sha256: sha(bundle.css) }, '42'.repeat(16));
  assert.ok(html.includes('term-input'));
  const filesBundleRaw = await readFile(new URL('../dist/usr/share/gui/files/files.json', import.meta.url));
  const filesBundle = JSON.parse(filesBundleRaw.toString('utf8'));
  assert.equal(typeof filesBundle.html, 'string');
  assert.equal(typeof filesBundle.css, 'string');
  assert.equal(typeof filesBundle.js, 'string');
  const filesHtml = await documentSource({ bundle: filesBundle, script_sha256: sha(filesBundle.js), style_sha256: sha(filesBundle.css) }, '43'.repeat(16));
  assert.ok(filesHtml.includes('files-refresh'));
  const mountsBundleRaw = await readFile(new URL('../dist/usr/share/gui/mounts/mounts.json', import.meta.url));
  const mountsBundle = JSON.parse(mountsBundleRaw.toString('utf8'));
  assert.equal(typeof mountsBundle.html, 'string');
  assert.equal(typeof mountsBundle.css, 'string');
  assert.equal(typeof mountsBundle.js, 'string');
  const mountsHtml = await documentSource({ bundle: mountsBundle, script_sha256: sha(mountsBundle.js), style_sha256: sha(mountsBundle.css) }, '44'.repeat(16));
  assert.ok(mountsHtml.includes('mount-manager'));
  const settingsBundleRaw = await readFile(new URL('../dist/usr/share/gui/settings/settings.json', import.meta.url));
  const settingsBundle = JSON.parse(settingsBundleRaw.toString('utf8'));
  assert.equal(typeof settingsBundle.html, 'string');
  assert.equal(typeof settingsBundle.css, 'string');
  assert.equal(typeof settingsBundle.js, 'string');
  const settingsHtml = await documentSource({ bundle: settingsBundle, script_sha256: sha(settingsBundle.js), style_sha256: sha(settingsBundle.css) }, '47'.repeat(16));
  assert.ok(settingsHtml.includes('settings-app'));
  const editorBundleRaw = await readFile(new URL('../dist/usr/share/gui/editor/editor.json', import.meta.url));
  const editorBundle = JSON.parse(editorBundleRaw.toString('utf8'));
  assert.equal(typeof editorBundle.html, 'string');
  assert.equal(typeof editorBundle.css, 'string');
  assert.equal(typeof editorBundle.js, 'string');
  const editorHtml = await documentSource({ bundle: editorBundle, script_sha256: sha(editorBundle.js), style_sha256: sha(editorBundle.css) }, '45'.repeat(16));
  assert.ok(editorHtml.includes('editor-save'));
  const previewBundleRaw = await readFile(new URL('../dist/usr/share/gui/preview/preview.json', import.meta.url));
  const previewBundle = JSON.parse(previewBundleRaw.toString('utf8'));
  assert.equal(typeof previewBundle.html, 'string');
  assert.equal(typeof previewBundle.css, 'string');
  assert.equal(typeof previewBundle.js, 'string');
  const previewHtml = await documentSource({ bundle: previewBundle, script_sha256: sha(previewBundle.js), style_sha256: sha(previewBundle.css) }, '46'.repeat(16));
  assert.ok(previewHtml.includes('viewer-surface'));
});

test('G-01..05, G-09..10 packaged WASI processes bind the seat, exchange private events and recover', { timeout: 60000 }, async t => {
  const fixture = new URL('./gui-kernel-worker.mjs', import.meta.url);
  const worker = new Worker(fixture, { workerData: { path: '/client-kernel.js', fixture: fixture.href } });
  t.after(() => worker.terminate());
  const pending = new Map(), events = []; let sequence = 0, packets = 0, wake;
  worker.on('message', m => {
    packets++;
    if (m.event) { m.at = performance.now(); events.push(m); wake?.(); return; }
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
  await t.test('batched OpenAt and Open route poll_oneoff through the seat devices', async () => {
    const { default: binaryen } = await import('binaryen');
    const source = await readFile(new URL('./fixtures/gui-device-poll.wat', import.meta.url), 'utf8');
    const probe = binaryen.parseText(source);
    try {
      await call('test_gui_poll_probe', { module: await WebAssembly.compile(probe.emitBinary()) });
    } finally { probe.dispose(); }
    const pid = await launch('compositor');
    const result = await until('gui-exit', e => e.pid === pid);
    assert.equal(result.status, 0, result.stderr);
  });
  const comp = await launch('compositor');
  await display('set_drag_mode');
  await assert.rejects(call('proc_openat', { pid: comp, dirfd: -100, path: '/dev/null', oflags: 0 }), e => e.errno === 'EPERM');
  const duplicate = await launch('compositor');
  assert.match((await until('gui-exit', v => v.pid === duplicate)).stderr, /EBUSY/);
  await call('test_gui_bundle', { hold: true });
  const stalled = await launch('gui-sample-doc');
  await until('test-bundle-pending', v => v);
  const bundle = '/usr/share/gui/samples/doc-view.json';
  const stalledFd = await launch('gui-sample-doc', ['--request', JSON.stringify({
    op: 'create_surface', spec: { role: 'window', title: 'Pending fd', rect: { x: 0, y: 0, width: 100, height: 100 },
      min_size: { width: 1, height: 1 }, max_size: null, resizable: false,
      kind: { document: { bundle_path: '/unopened', expected_sha256: '0'.repeat(64) } } },
  }), '--fd', bundle]);
  const pixel = await launch('gui-sample-pixel');
  const live = await display('map', c => c.owner_pid === pixel);
  await call('gui_host_event', { event: { op: 'key', surface_id: live.surface_id, key: 'x', code: 'KeyX', paste: false } });
  await display('set_a11y', c => c.surface_id === live.surface_id && c.a11y.live_announcement === 'Key x');
  assert.match((await until('gui-exit', v => v.pid === stalled)).stderr, /ETIMEDOUT/);
  assert.deepEqual(JSON.parse((await until('gui-exit', v => v.pid === stalledFd)).stdout), { op: 'error', errno: 'ETIMEDOUT' });
  await call('test_gui_bundle', { hold: false });
  const doc = await launch('gui-sample-doc');
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
      let lastProgress = -Infinity;
      const dispatches = new Map(), count = 120, cadence = performance.now();
      await Promise.all(Array.from({ length: count }, (_, index) => {
        const serial = index + 1;
        return new Promise(resolve => setTimeout(resolve, Math.max(0, cadence + serial * 1000 / 60 - performance.now()))).then(() => {
          const time = performance.now(), rect = gestureRect(origin, serial, 0, lease);
          dispatches.set(serial, time);
          if (mode === 'local_lease') {
            samples.push(performance.now() - time);
            if (time - lastProgress < 100) return;
            lastProgress = time;
          }
          return input({ op: 'interactive_op_progress', serial, surface_id: id, lease_id: lease.lease_id, rect, snap_hint: null });
        });
      }));
      const rect = gestureRect(origin, count, 0, lease);
      const firstProgress = at;
      at = events.length;
      await input({ op: 'interactive_op_end', surface_id: id, lease_id: lease.lease_id, rect, snap_hint: null, canceled: false });
      origin = (await display('geometry', c => c.surface_id === id, at)).rect;
      assert.deepEqual(origin, rect);
      if (mode === 'roundtrip') for (const m of events.slice(firstProgress)) {
        if (m.event === 'gui-display' && m.value.op === 'drag_frame' && m.value.lease_id === lease.lease_id) {
          samples.push(m.at - dispatches.get(m.value.serial));
        }
      }
      assert.ok(samples.length > 0 && samples.length <= count);
      const pageMessages = packets - before, elapsed = performance.now() - start;
      const processMessages = await call('gui_worker_metrics', { pid: comp, start: false });
      assert.ok(processMessages > 0);
      t.diagnostic('Worker drag ' + JSON.stringify({ mode, ...dragStatistics(samples, pageMessages + processMessages, elapsed, count), pageMessages, processMessages }));
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
    [{ op: 'create_surface', spec: { role: 'window', kind: { host: { component: 'terminal' } }, title: 'Terminal', rect: a.rect, min_size: { width: 280, height: 180 }, max_size: null, resizable: true, app_id: 'terminal' } }, 'EPERM'],
    [{ op: 'create_surface', spec: { role: 'window', kind: { host: { component: 'files' } }, title: 'Files', rect: a.rect, min_size: { width: 280, height: 180 }, max_size: null, resizable: true, app_id: 'files' } }, 'EPERM'],
    [{ op: 'create_surface', spec: { role: 'window', kind: { host: { component: 'mounts' } }, title: 'Mounts', rect: a.rect, min_size: { width: 280, height: 180 }, max_size: null, resizable: true, app_id: 'mounts' } }, 'EPERM'],
    [{ op: 'create_surface', spec: { role: 'window', kind: { host: { component: 'editor' } }, title: 'Editor', rect: a.rect, min_size: { width: 280, height: 180 }, max_size: null, resizable: true, app_id: 'editor' } }, 'EPERM'],
    [{ op: 'create_surface', spec: { role: 'window', kind: { host: { component: 'viewer' } }, title: 'Preview', rect: a.rect, min_size: { width: 280, height: 180 }, max_size: null, resizable: true, app_id: 'preview' } }, 'EPERM'],
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
  await sendInput({ op: 'focus_request', surface_id: a.surface_id });
  await sendInput({ op: 'host_focus' });
  for (const spoof of [{ type: 'pointerdown', pointer_id: 1 }, { type: 'key', paste: true }, { type: 'shortcut', key: 'next' }]) port1.postMessage(spoof);
  for (const [action, errno] of [['copy','EACCES'],['pick','EACCES'],['paste','EACCES'],['drag','EPERM']]) {
    const denied = response(); command(action, ['copy','drag'].includes(action) ? { text: 'sample' } : {});
    assert.equal(await denied, errno);
  }
  await sendInput({ op: 'focus_request', surface_id: b.surface_id });
  let reply = response(); command('pick'); assert.equal(await reply, 'EACCES');
  await sendInput({ op: 'pointer_down', hit_region: 'content', surface_id: a.surface_id, pointer_id: 1, x: 0, y: 0, timestamp_ms: Date.now() });
  command('copy', { text: 'seat clipboard' });
  await display('clipboard_write');
  reply = response(); command('paste'); assert.equal(await reply, 'EACCES');
  await sendInput({ op: 'key', surface_id: a.surface_id, paste: true });
  await sendInput({ op: 'key', surface_id: a.surface_id, paste: false });
  reply = response(); command('paste'); assert.equal(await reply, 'seat clipboard');
  reply = response(); await sendInput({ op: 'paste', surface_id: a.surface_id, text: 'from the host' }); assert.equal(await reply, 'from the host');
  await call('test_gui_dequeue_errors');
  reply = response();
  await sendInput({ op: 'paste', surface_id: a.surface_id, text: '\u0000'.repeat(1 << 20) });
  assert.equal(await reply, 'Pasted 1048576 bytes');
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
  const req = { op: 'create_surface', spec: { role: 'window', title: 'Passed file', rect: a.rect,
    min_size: { width: 1, height: 1 }, max_size: null, resizable: false,
    kind: { document: { bundle_path: '/unopened', expected_sha256: a.document.content_sha256 } } } };
  const passed = await launch('gui-sample-doc', ['--request', JSON.stringify(req), '--fd', bundle]);
  assert.equal(JSON.parse((await until('gui-exit', v => v.pid === passed)).stdout).op, 'created');
  await t.test('G-09 an unfocused Document starts a drag and only the drop delivers its text', async () => {
    const targetPid = await launch('gui-sample-doc');
    const target = (await display('map', c => c.owner_pid === targetPid)).surface_id;
    const ports = new MessageChannel();
    t.after(() => ports.port1.close());
    await call('gui_surface_port', { surface_id: target, port: ports.port2 }, [ports.port2]);
    const nextText = () => new Promise(resolve => ports.port1.once('message', m => resolve(m.text)));
    const after = events.length;
    await sendInput({ op: 'pointer_down', hit_region: 'content', surface_id: a.surface_id, pointer_id: 7, x: 0, y: 0, timestamp_ms: Date.now() });
    await display('focus', c => c.surface_id === a.surface_id, after);
    command('drag', { text: 'only on drop' });
    await display('dnd_tracking', c => c.active && c.pointer_id === 7, after);
    const offer = nextText();
    await sendInput({ op: 'dnd_hover', surface_id: target, pointer_id: 7, x: 10, y: 15 });
    assert.equal(await offer, 'Offered text/plain');
    const dropped = nextText();
    await sendInput({ op: 'dnd_drop', surface_id: target, pointer_id: 7, button: 0 });
    assert.equal(await dropped, 'only on drop');
    await kill(targetPid);
    await display('unmap', c => c.surface_id === target, after);
  });
  await t.test('L6a packaged /usr/bin/terminal spawns /usr/bin/osh on a PTY, streams frames and handles exit', async () => {
    const after = events.length;
    const termPid = await launch('terminal');
    const termMap = await display('map', c => c.owner_pid === termPid, after);
    assert.equal(termMap.app_id, 'terminal');
    assert.equal(termMap.compat_app, null);
    assert.equal(
      termMap.document.content_sha256,
      sha(await readFile(new URL('../dist/usr/share/gui/terminal/terminal.json', import.meta.url))),
    );
    const ports = new MessageChannel();
    t.after(() => ports.port1.close());
    await call('gui_surface_port', { surface_id: termMap.surface_id, port: ports.port2 }, [ports.port2]);
    const chunks = new Map();
    const rows = [];
    let lastState = null;
    let lastExited = null;
    let onFrame;
    const screenText = () => rows.map(r => (r || []).map(run => run[0] || '').join('')).join('\n');
    const applyDoc = msg => {
      if (msg.t === 'chunk') {
        let bucket = chunks.get(msg.id);
        if (!bucket) { bucket = new Array(msg.n).fill(null); chunks.set(msg.id, bucket); }
        bucket[msg.i] = msg.d;
        if (bucket.every(s => typeof s === 'string')) {
          chunks.delete(msg.id);
          applyDoc(JSON.parse(bucket.join('')));
        }
        return;
      }
      if (msg.t === 'frame') {
        if (msg.full) rows.length = 0;
        for (const [idx, runs] of msg.lines || []) rows[idx] = runs;
        if (rows.length > (msg.total || 0)) rows.length = msg.total || 0;
        lastState = msg.state;
        lastExited = msg.exited;
        onFrame?.();
      }
    };
    ports.port1.on('message', m => {
      if (typeof m?.text === 'string') {
        assert.ok(Buffer.byteLength(m.text, 'utf8') <= 4096);
        applyDoc(JSON.parse(m.text));
      }
    });
    const waitFrame = async (predicate, label) => {
      const deadline = Date.now() + 12000;
      while (!predicate()) {
        if (Date.now() > deadline) {
          assert.fail(`Timeout waiting for ${label}; state=${lastState} exited=${lastExited} screen=${JSON.stringify(screenText().slice(-500))}`);
        }
        await new Promise(resolve => {
          const timer = setTimeout(resolve, 100);
          onFrame = () => { clearTimeout(timer); resolve(); };
        });
      }
    };
    ports.port1.postMessage({ type: 'message', text: JSON.stringify({ t: 'ready', cols: 80, rows: 24 }) });
    await waitFrame(() => lastState === 'idle', 'initial osh prompt');
    ports.port1.postMessage({ type: 'message', text: JSON.stringify({ t: 'in', d: 'echo L6A_LIVE_OK && tty\r' }) });
    await waitFrame(() => screenText().includes('L6A_LIVE_OK') && /\/dev\/pts\/\d+/.test(screenText()), 'echo and tty output');
    ports.port1.postMessage({ type: 'message', text: JSON.stringify({ t: 'in', d: 'exit 5\r' }) });
    await waitFrame(() => lastExited === 5 && screenText().includes('[Process exited with status 5]'), 'shell exit 5 banner');
    assert.ok(!events.some(m => m.event === 'gui-exit' && m.value.pid === termPid));
    await kill(termPid);
    await display('unmap', c => c.surface_id === termMap.surface_id, after);
  });
  await t.test('L6b-1 packaged /usr/bin/files lists directories, navigates, and handles multi-file SCM_RIGHTS upload', async st => {
    const dir = '/tmp/l6b-proto-' + Date.now().toString(36);
    assert.ok('ok' in await sys({ mkdir: { path: dir, mode: 0o755 } }));
    const after = events.length;
    const filesPid = await launch('files', ['--dir', dir]);
    st.after(async () => { await kill(filesPid).catch(() => {}); });
    const filesMap = await display('map', c => c.owner_pid === filesPid, after);
    assert.equal(filesMap.app_id, 'files');
    assert.equal(filesMap.compat_app, null);
    assert.equal(
      filesMap.document.content_sha256,
      sha(await readFile(new URL('../dist/usr/share/gui/files/files.json', import.meta.url))),
    );
    const ports = new MessageChannel();
    st.after(() => ports.port1.close());
    await call('gui_surface_port', { surface_id: filesMap.surface_id, port: ports.port2 }, [ports.port2]);
    const chunks = new Map();
    let lastState = null;
    let lastProgress = null;
    let onMsg;
    const applyDoc = msg => {
      if (msg.t === 'chunk') {
        let bucket = chunks.get(msg.id);
        if (!bucket) { bucket = new Array(msg.n).fill(null); chunks.set(msg.id, bucket); }
        bucket[msg.i] = msg.d;
        if (bucket.every(s => typeof s === 'string')) {
          chunks.delete(msg.id);
          applyDoc(JSON.parse(bucket.join('')));
        }
        return;
      }
      if (msg.t === 'state') lastState = msg;
      else if (msg.t === 'progress') lastProgress = msg;
      onMsg?.();
    };
    ports.port1.on('message', m => {
      if (typeof m?.text === 'string') {
        assert.ok(Buffer.byteLength(m.text, 'utf8') <= 4096);
        applyDoc(JSON.parse(m.text));
      }
    });
    const waitDoc = async (predicate, label) => {
      const deadline = Date.now() + 12000;
      while (!predicate()) {
        if (Date.now() > deadline) {
          assert.fail(`Timeout waiting for ${label}; state=${JSON.stringify(lastState)} progress=${JSON.stringify(lastProgress)}`);
        }
        await new Promise(resolve => {
          const timer = setTimeout(resolve, 100);
          onMsg = () => { clearTimeout(timer); resolve(); };
        });
      }
    };
    ports.port1.postMessage({ type: 'message', text: JSON.stringify({ t: 'ready' }) });
    await waitDoc(() => lastState?.cwd === dir, 'initial files state');
    const beforePick = events.length;
    await sendInput({ op: 'pointer_down', hit_region: 'content', surface_id: filesMap.surface_id, pointer_id: 9, x: 10, y: 10, timestamp_ms: Date.now() });
    await sendInput({ op: 'pointer_up', surface_id: filesMap.surface_id, pointer_id: 9, button: 0, x: 10, y: 10, canceled: false });
    ports.port1.postMessage({ type: 'message', text: JSON.stringify({ t: 'upload' }) });
    const pick = await display('pick_file', c => c.surface_id === filesMap.surface_id, beforePick);
    assert.equal(pick.multiple, true);
    assert.equal(pick.cloud_dest ?? null, null);
    await call('gui_picker_result', {
      surface_id: filesMap.surface_id,
      request_id: pick.request_id,
      files: [new File(['alpha'], 'a.txt'), new File(['bravo!'], 'b.txt')],
    });
    await waitDoc(
      () => lastProgress && !lastProgress.uploading && lastProgress.text.includes('✓ a.txt') && lastProgress.text.includes('✓ b.txt'),
      'multi-file upload completion',
    );
    await waitDoc(
      () => lastState?.entries?.map(e => e.name).includes('a.txt') && lastState.entries.map(e => e.name).includes('b.txt'),
      'uploaded entries listed',
    );
    // Conflict on duplicate upload reports exact refusal message.
    const beforeConflict = events.length;
    await sendInput({ op: 'pointer_down', hit_region: 'content', surface_id: filesMap.surface_id, pointer_id: 10, x: 10, y: 10, timestamp_ms: Date.now() });
    await sendInput({ op: 'pointer_up', surface_id: filesMap.surface_id, pointer_id: 10, button: 0, x: 10, y: 10, canceled: false });
    ports.port1.postMessage({ type: 'message', text: JSON.stringify({ t: 'upload' }) });
    const conflictPick = await display('pick_file', c => c.surface_id === filesMap.surface_id, beforeConflict);
    await call('gui_picker_result', {
      surface_id: filesMap.surface_id,
      request_id: conflictPick.request_id,
      files: [new File(['overwrite'], 'a.txt')],
    });
    await waitDoc(
      () => lastProgress && !lastProgress.uploading && lastProgress.text.includes('File already exists; rename it before uploading'),
      'duplicate conflict error',
    );
    await kill(filesPid);
    await display('unmap', c => c.surface_id === filesMap.surface_id, after);
  });
  await t.test('L6b-2 packaged /usr/bin/mounts maps a sealed Document surface, fences host mount consent and exits cleanly on close', async st => {
    const after = events.length;
    const mountsPid = await launch('mounts', ['--tab', 'add']);
    st.after(async () => { await kill(mountsPid).catch(() => {}); });
    const mountsMap = await display('map', c => c.owner_pid === mountsPid, after);
    assert.equal(mountsMap.app_id, 'mounts');
    assert.equal(mountsMap.compat_app, null);
    assert.equal(
      mountsMap.document.content_sha256,
      sha(await readFile(new URL('../dist/usr/share/gui/mounts/mounts.json', import.meta.url))),
    );
    const ports = new MessageChannel();
    st.after(() => ports.port1.close());
    await call('gui_surface_port', { surface_id: mountsMap.surface_id, port: ports.port2 }, [ports.port2]);
    const chunks = new Map();
    let lastSnap = null;
    let onMsg;
    const applyDoc = msg => {
      if (msg.t === 'chunk') {
        let bucket = chunks.get(msg.id);
        if (!bucket) { bucket = new Array(msg.n).fill(null); chunks.set(msg.id, bucket); }
        bucket[msg.i] = msg.d;
        if (bucket.every(s => typeof s === 'string')) {
          chunks.delete(msg.id);
          applyDoc(JSON.parse(bucket.join('')));
        }
        return;
      }
      if (msg.t === 'snapshot') lastSnap = msg;
      onMsg?.();
    };
    ports.port1.on('message', m => {
      if (typeof m?.text === 'string') {
        assert.ok(Buffer.byteLength(m.text, 'utf8') <= 4096);
        applyDoc(JSON.parse(m.text));
      }
    });
    const waitSnap = async (predicate, label) => {
      const deadline = Date.now() + 12000;
      while (!predicate()) {
        if (Date.now() > deadline) {
          assert.fail(`Timeout waiting for ${label}; snap=${JSON.stringify(lastSnap)}`);
        }
        await new Promise(resolve => {
          const timer = setTimeout(resolve, 100);
          onMsg = () => { clearTimeout(timer); resolve(); };
        });
      }
    };
    const beforeCap = events.length;
    ports.port1.postMessage({ type: 'message', text: JSON.stringify({ t: 'ready' }) });
    const capReq = await display('portal', c => c.surface_id === mountsMap.surface_id && c.request?.portal === 'mounts' && c.request?.action?.action === 'capabilities', beforeCap);
    // Forged portal_result over gui_host_event must be refused with EACCES.
    await assert.rejects(
      sendInput({ op: 'portal_result', request_id: capReq.request_id, surface_id: mountsMap.surface_id, response: { portal: 'mounts', outcome: { status: 'canceled', errno: 'ECANCELED' } } }),
      e => e.errno === 'EACCES',
    );
    // Forged mount grant over gui_portal_result (bypassing gui_portal_commit) must be refused with EACCES.
    await assert.rejects(
      call('gui_portal_result', {
        request_id: capReq.request_id,
        surface_id: mountsMap.surface_id,
        response: { portal: 'mounts', outcome: { status: 'granted', source_id: 'fake', label: 'x', writable: true } },
      }),
      e => e.errno === 'EACCES',
    );
    await call('gui_portal_result', {
      request_id: capReq.request_id,
      surface_id: mountsMap.surface_id,
      response: {
        portal: 'mounts',
        outcome: {
          status: 'capabilities',
          host_picker: true,
          origin: 'http://127.0.0.1:8788',
          browser_label: 'Chromium',
          relay_ready: false,
          account_user: '',
          signed_in: false,
        },
      },
    });
    await waitSnap(() => lastSnap?.ready_for_consent === true && lastSnap?.tab === 'add' && lastSnap?.helper_mode === false, 'initial mounts snapshot');
    // Without a recent user gesture, mutating Mounts Portal is denied with EACCES and NEVER flips helper_mode.
    await sendInput({ op: 'host_focus' });
    ports.port1.postMessage({ type: 'message', text: JSON.stringify({ t: 'pick_host_folder', name: 'project', writable: false, execute: true, cloud: false, save: false }) });
    await waitSnap(() => /permission denied/i.test(lastSnap?.notice || '') && lastSnap?.submitting === false && lastSnap?.helper_mode === false, 'gesture-denied mount consent');
    // With a fresh pointer gesture, Mounts Portal is forwarded; Canceled must NOT flip helper_mode.
    const beforePick = events.length;
    await sendInput({ op: 'pointer_down', hit_region: 'content', surface_id: mountsMap.surface_id, pointer_id: 11, x: 10, y: 10, timestamp_ms: Date.now() });
    await sendInput({ op: 'pointer_up', surface_id: mountsMap.surface_id, pointer_id: 11, button: 0, x: 10, y: 10, canceled: false });
    ports.port1.postMessage({ type: 'message', text: JSON.stringify({ t: 'pick_host_folder', name: 'project', writable: true, execute: true, cloud: false, save: false }) });
    const pickReq = await display('portal', c => c.surface_id === mountsMap.surface_id && c.request?.portal === 'mounts' && c.request?.action?.action === 'pick_host_folder', beforePick);
    assert.equal(pickReq.request.action.writable, true);
    await call('gui_portal_result', {
      request_id: pickReq.request_id,
      surface_id: mountsMap.surface_id,
      response: { portal: 'mounts', outcome: { status: 'canceled', errno: 'ECANCELED' } },
    });
    await waitSnap(() => lastSnap?.notice === 'Cancelled.' && lastSnap?.helper_mode === false && lastSnap?.submitting === false, 'canceled pick keeps helper_mode false');
    // Only Unsupported flips helper_mode = true.
    const beforeUnsup = events.length;
    await sendInput({ op: 'pointer_down', hit_region: 'content', surface_id: mountsMap.surface_id, pointer_id: 12, x: 10, y: 10, timestamp_ms: Date.now() });
    await sendInput({ op: 'pointer_up', surface_id: mountsMap.surface_id, pointer_id: 12, button: 0, x: 10, y: 10, canceled: false });
    ports.port1.postMessage({ type: 'message', text: JSON.stringify({ t: 'pick_host_folder', name: 'project', writable: false, execute: true, cloud: false, save: false }) });
    const unsupReq = await display('portal', c => c.surface_id === mountsMap.surface_id && c.request?.portal === 'mounts' && c.request?.action?.action === 'pick_host_folder', beforeUnsup);
    await call('gui_portal_result', {
      request_id: unsupReq.request_id,
      surface_id: mountsMap.surface_id,
      response: { portal: 'mounts', outcome: { status: 'unsupported', origin: 'http://127.0.0.1:8788', detail: 'No host picker.' } },
    });
    await waitSnap(() => lastSnap?.helper_mode === true && lastSnap?.origin === 'http://127.0.0.1:8788', 'unsupported flips helper_mode');
    // CloseRequested exits cleanly with status 0 and unmaps the surface.
    const beforeClose = events.length;
    await sendInput({ op: 'chrome_action', surface_id: mountsMap.surface_id, state: null });
    const exited = await until('gui-exit', e => e.pid === mountsPid, beforeClose);
    assert.equal(exited.status, 0, exited.stderr);
    await display('unmap', c => c.surface_id === mountsMap.surface_id, beforeClose);
  });
  await t.test('Unified Portal IPC: /usr/bin/settings maps sealed Document surface, enforces gestures & cross-app isolation, persists ~/.config/os/settings.json', async st => {
    const after = events.length;
    const settingsPid = await launch('settings', ['--section', 'appearance']);
    st.after(async () => { await kill(settingsPid).catch(() => {}); });
    const settingsMap = await display('map', c => c.owner_pid === settingsPid, after);
    assert.equal(settingsMap.app_id, 'settings');
    assert.equal(settingsMap.compat_app, null);
    assert.equal(
      settingsMap.document.content_sha256,
      sha(await readFile(new URL('../dist/usr/share/gui/settings/settings.json', import.meta.url))),
    );
    const ports = new MessageChannel();
    st.after(() => ports.port1.close());
    await call('gui_surface_port', { surface_id: settingsMap.surface_id, port: ports.port2 }, [ports.port2]);
    const chunks = new Map();
    let lastSnap = null;
    let onMsg;
    const applyDoc = msg => {
      if (msg.t === 'chunk') {
        let bucket = chunks.get(msg.id);
        if (!bucket) { bucket = new Array(msg.n).fill(null); chunks.set(msg.id, bucket); }
        bucket[msg.i] = msg.d;
        if (bucket.every(s => typeof s === 'string')) {
          chunks.delete(msg.id);
          applyDoc(JSON.parse(bucket.join('')));
        }
        return;
      }
      if (msg.t === 'snapshot') lastSnap = msg;
      onMsg?.();
    };
    ports.port1.on('message', m => {
      if (typeof m?.text === 'string') {
        assert.ok(Buffer.byteLength(m.text, 'utf8') <= 4096);
        applyDoc(JSON.parse(m.text));
      }
    });
    const waitSnap = async (predicate, label) => {
      const deadline = Date.now() + 12000;
      while (!predicate()) {
        if (Date.now() > deadline) {
          assert.fail(`Timeout waiting for ${label}; snap=${JSON.stringify(lastSnap)}`);
        }
        await new Promise(resolve => {
          const timer = setTimeout(resolve, 100);
          onMsg = () => { clearTimeout(timer); resolve(); };
        });
      }
    };
    const beforeReady = events.length;
    ports.port1.postMessage({ type: 'message', text: JSON.stringify({ t: 'ready' }) });
    const [acctReq, deskReq] = await Promise.all([
      display('portal', c => c.surface_id === settingsMap.surface_id && c.request?.portal === 'account' && c.request?.action?.action === 'status', beforeReady),
      display('portal', c => c.surface_id === settingsMap.surface_id && c.request?.portal === 'desktop' && c.request?.action?.action === 'get_preferences', beforeReady),
    ]);
    await call('gui_portal_result', {
      request_id: acctReq.request_id,
      surface_id: settingsMap.surface_id,
      response: {
        portal: 'account',
        outcome: {
          status: 'state',
          local: {
            username: 'user',
            uid: 1000,
            gid: 1000,
            home: '/home/user',
            root_volume_uuid: '12345678-aaaa',
            forked_from: null,
            ephemeral_if_unmodified: false,
            can_sudo: true,
            root_fstype: 'cowfs',
          },
          cloud: {
            signed_in: false,
            cloud_user: null,
            scope: { cloud_fs: false },
            cloud_mount_active: false,
            attached_devices: [],
          },
          notice: null,
        },
      },
    });
    await call('gui_portal_result', {
      request_id: deskReq.request_id,
      surface_id: settingsMap.surface_id,
      response: {
        portal: 'desktop',
        outcome: { status: 'preferences', theme: 'light', dock_autohide: false, fullscreen: false },
      },
    });
    await waitSnap(() => lastSnap?.ready === true && lastSnap?.section === 'appearance' && lastSnap?.theme === 'light', 'initial settings snapshot');
    // Without a fresh user gesture, mutating Desktop Portal is denied with EACCES.
    await sendInput({ op: 'host_focus' });
    ports.port1.postMessage({ type: 'message', text: JSON.stringify({ t: 'set_preferences', theme: 'dark', dock_autohide: true }) });
    await waitSnap(() => /permission denied/i.test(lastSnap?.error || '') && lastSnap?.busy === false, 'gesture-denied settings portal');
    // With a fresh pointer gesture, Desktop::ApplyPreferences is forwarded and persisted to ~/.config/os/settings.json.
    const beforePref = events.length;
    await sendInput({ op: 'pointer_down', hit_region: 'content', surface_id: settingsMap.surface_id, pointer_id: 21, x: 10, y: 10, timestamp_ms: Date.now() });
    await sendInput({ op: 'pointer_up', surface_id: settingsMap.surface_id, pointer_id: 21, button: 0, x: 10, y: 10, canceled: false });
    ports.port1.postMessage({ type: 'message', text: JSON.stringify({ t: 'set_preferences', theme: 'dark', dock_autohide: true }) });
    const prefReq = await display('portal', c => c.surface_id === settingsMap.surface_id && c.request?.portal === 'desktop' && c.request?.action?.action === 'apply_preferences', beforePref);
    assert.deepEqual(prefReq.request.action, { action: 'apply_preferences', theme: 'dark', dock_autohide: true });
    await call('gui_portal_result', {
      request_id: prefReq.request_id,
      surface_id: settingsMap.surface_id,
      response: { portal: 'desktop', outcome: { status: 'preferences', theme: 'dark', dock_autohide: true, fullscreen: false } },
    });
    await waitSnap(() => lastSnap?.theme === 'dark' && lastSnap?.dock_autohide === true && lastSnap?.busy === false, 'applied dark preferences');
    // Security isolation: an unprivileged Document client (`gui-sample-doc`) attempting ANY Portal
    // (`account` or `mounts`) is immediately refused by the kernel broker (never reaches host display).
    const rogueAfter = events.length;
    const roguePid = await launch('gui-sample-doc', [
      '--request',
      JSON.stringify({ op: 'portal', surface_id: 0, request: { portal: 'account', action: { action: 'status' } } }),
    ]);
    st.after(async () => { await kill(roguePid).catch(() => {}); });
    const rogueExit = await until('gui-exit', e => e.pid === roguePid, rogueAfter);
    const leaked = events.slice(rogueAfter).some(m => m.event === 'gui-display' && m.value?.op === 'portal' && m.value?.owner_pid === roguePid);
    assert.equal(leaked, false, `unprivileged client must never reach host portal broker (exit=${JSON.stringify(rogueExit)})`);
    // CloseRequested exits cleanly with status 0 and unmaps.
    const beforeClose = events.length;
    await sendInput({ op: 'chrome_action', surface_id: settingsMap.surface_id, state: null });
    const exited = await until('gui-exit', e => e.pid === settingsPid, beforeClose);
    assert.equal(exited.status, 0, exited.stderr);
    await display('unmap', c => c.surface_id === settingsMap.surface_id, beforeClose);
  });
  await t.test('L6c-1 packaged /usr/bin/editor opens, detects ESTALE conflict, exports with gesture, and saves cleanly', async st => {
    const filePath = '/tmp/l6c-editor-proto.txt';
    const wopen = await sys({ open: { path: filePath, flags: 0o1101, mode: 0o644 } });
    assert.ok(wopen.ok, JSON.stringify(wopen));
    const pw1 = await sys({ pwrite: { fd: wopen.ok.fd, index: 0, data: Buffer.from('v1\n').toString('base64') } });
    assert.ok(pw1.ok, JSON.stringify(pw1));
    await sys({ close: { fd: wopen.ok.fd } });

    const beforeStart = events.length;
    const editorPid = await launch('editor', ['--wait', '--', filePath]);
    st.after(async () => { await kill(editorPid).catch(() => {}); });
    const editorMap = await display('map', c => c.owner_pid === editorPid, beforeStart);
    assert.equal(editorMap.app_id, 'editor');
    assert.equal(editorMap.compat_app, null);
    assert.equal(editorMap.role, 'window');
    assert.ok(editorMap.document && editorMap.document.bundle?.js);
    await documentSource(editorMap.document, 'l6c-editor-nonce');
    const ports = new MessageChannel(); st.after(() => ports.port1.close());
    await call('gui_surface_port', { surface_id: editorMap.surface_id, port: ports.port2 }, [ports.port2]);

    const chunks = new Map();
    let lastState = null;
    let onMsg = null;
    const applyDoc = msg => {
      if (msg.t === 'chunk') {
        let bucket = chunks.get(msg.id);
        if (!bucket) { bucket = new Array(msg.n); chunks.set(msg.id, bucket); }
        bucket[msg.i] = msg.d;
        if (bucket.every(s => typeof s === 'string')) {
          chunks.delete(msg.id);
          applyDoc(JSON.parse(bucket.join('')));
        }
        return;
      }
      if (msg.t === 'init' || msg.t === 'status' || msg.t === 'replace_content') lastState = msg;
      onMsg?.();
    };
    ports.port1.on('message', m => {
      if (typeof m?.text === 'string') {
        assert.ok(Buffer.byteLength(m.text, 'utf8') <= 4096);
        applyDoc(JSON.parse(m.text));
      }
    });
    const waitState = async (pred, label) => {
      const deadline = Date.now() + 12000;
      while (!pred()) {
        if (Date.now() > deadline) assert.fail(`Timeout waiting for ${label}; state=${JSON.stringify(lastState)}`);
        await new Promise(resolve => {
          const timer = setTimeout(resolve, 100);
          onMsg = () => { clearTimeout(timer); resolve(); };
        });
      }
    };
    ports.port1.postMessage({ type: 'message', text: JSON.stringify({ t: 'ready' }) });
    await waitState(() => lastState?.t === 'init' && lastState?.content === 'v1\n', 'initial editor open');

    // Externally modify the file so conditional revision save hits ESTALE conflict!
    const w2 = await sys({ open: { path: filePath, flags: 0o1001, mode: 0o644 } });
    assert.ok(w2.ok, JSON.stringify(w2));
    const pw2 = await sys({ pwrite: { fd: w2.ok.fd, index: 0, data: Buffer.from('external-v2\n').toString('base64') } });
    assert.ok(pw2.ok, JSON.stringify(pw2));
    await sys({ close: { fd: w2.ok.fd } });

    ports.port1.postMessage({ type: 'message', text: JSON.stringify({ t: 'save', content: 'editor-v2\n', force_overwrite: false }) });
    await waitState(() => lastState?.conflict === 'changed_elsewhere', 'ESTALE conflict banner');

    // Overwrite anyway resolves the conflict and updates disk.
    ports.port1.postMessage({ type: 'message', text: JSON.stringify({ t: 'save', content: 'editor-v2\n', force_overwrite: true }) });
    await waitState(() => !lastState?.conflict && lastState?.dirty === false && /Saved/i.test(lastState?.status || ''), 'forced save');

    // ExportFile requires a recent gesture; with gesture it emits DisplayCmd::ExportFile.
    const beforeExport = events.length;
    await sendInput({ op: 'pointer_down', hit_region: 'content', surface_id: editorMap.surface_id, pointer_id: 21, x: 10, y: 10, timestamp_ms: Date.now() });
    await sendInput({ op: 'pointer_up', surface_id: editorMap.surface_id, pointer_id: 21, button: 0, x: 10, y: 10, canceled: false });
    ports.port1.postMessage({ type: 'message', text: JSON.stringify({ t: 'download', content: 'editor-v2\n' }) });
    const exp = await display('export_file', c => c.surface_id === editorMap.surface_id, beforeExport);
    assert.equal(exp.filename, 'l6c-editor-proto.txt');
    assert.equal(Buffer.from(exp.data, 'base64').toString('utf8'), 'editor-v2\n');

    // Close exits cleanly with status 0 and unmaps.
    const beforeClose = events.length;
    await sendInput({ op: 'chrome_action', surface_id: editorMap.surface_id, state: null });
    const exited = await until('gui-exit', e => e.pid === editorPid, beforeClose);
    assert.equal(exited.status, 0, exited.stderr);
    await display('unmap', c => c.surface_id === editorMap.surface_id, beforeClose);
    await sys({ unlink: { path: filePath } });
  });
  await t.test('L6c-2 packaged /usr/bin/preview maps a sealed Document surface, enforces fullscreen & export gestures, rejects forged host events, and exits cleanly', async st => {
    const filePath = '/tmp/l6c-preview-proto.md';
    const wopen = await sys({ open: { path: filePath, flags: 0o1101, mode: 0o644 } });
    assert.ok(wopen.ok, JSON.stringify(wopen));
    const body = '# Preview Proto\n\nSafe local content.\n';
    const pw = await sys({ pwrite: { fd: wopen.ok.fd, index: 0, data: Buffer.from(body).toString('base64') } });
    assert.ok(pw.ok, JSON.stringify(pw));
    await sys({ close: { fd: wopen.ok.fd } });

    const beforeStart = events.length;
    const previewPid = await launch('preview', ['--', filePath]);
    st.after(async () => { await kill(previewPid).catch(() => {}); });
    const previewMap = await display('map', c => c.owner_pid === previewPid, beforeStart);
    assert.equal(previewMap.app_id, 'preview');
    assert.equal(previewMap.compat_app, null);
    assert.equal(previewMap.role, 'window');
    assert.ok(previewMap.document && previewMap.document.bundle?.js);
    await documentSource(previewMap.document, 'l6c-preview-nonce');
    const ports = new MessageChannel(); st.after(() => ports.port1.close());
    await call('gui_surface_port', { surface_id: previewMap.surface_id, port: ports.port2 }, [ports.port2]);

    const chunks = new Map();
    let lastShow = null;
    let lastFs = null;
    let lastNotice = null;
    let onMsg = null;
    const applyDoc = msg => {
      if (msg.t === 'chunk') {
        let bucket = chunks.get(msg.id);
        if (!bucket) { bucket = new Array(msg.n); chunks.set(msg.id, bucket); }
        bucket[msg.i] = msg.d;
        if (bucket.every(s => typeof s === 'string')) {
          chunks.delete(msg.id);
          applyDoc(JSON.parse(bucket.join('')));
        }
        return;
      }
      if (msg.t === 'show') lastShow = msg;
      else if (msg.t === 'fullscreen') lastFs = msg;
      else if (msg.t === 'notice') lastNotice = msg;
      onMsg?.();
    };
    ports.port1.on('message', m => {
      if (typeof m?.text === 'string') {
        assert.ok(Buffer.byteLength(m.text, 'utf8') <= 4096);
        applyDoc(JSON.parse(m.text));
      }
    });
    const waitDoc = async (pred, label) => {
      const deadline = Date.now() + 12000;
      while (!pred()) {
        if (Date.now() > deadline) {
          assert.fail(`Timeout waiting for ${label}; show=${JSON.stringify(lastShow)} fs=${JSON.stringify(lastFs)} notice=${JSON.stringify(lastNotice)}`);
        }
        await new Promise(resolve => {
          const timer = setTimeout(resolve, 100);
          onMsg = () => { clearTimeout(timer); resolve(); };
        });
      }
    };
    ports.port1.postMessage({ type: 'message', text: JSON.stringify({ t: 'ready' }) });
    await waitDoc(() => lastShow?.view === 'markdown' && lastShow?.html?.includes('Preview Proto'), 'initial markdown preview');

    // Forged privileged preview host events over gui_host_event must all be refused with EACCES.
    for (const forged of [
      { op: 'fullscreen_changed', surface_id: previewMap.surface_id, active: true, error: null },
      { op: 'preview_job_result', surface_id: previewMap.surface_id, job_id: 1, output: { kind: 'error', detail: 'forged' } },
      { op: 'media_event', surface_id: previewMap.surface_id, payload: { event: 'speaker_opened', request_id: 1, ok: true } },
      { op: 'session_event', surface_id: previewMap.surface_id, payload_json: '{}' },
    ]) {
      await assert.rejects(sendInput(forged), e => e.errno === 'EACCES');
    }

    // Fullscreen with pointer gesture emits DisplayCmd::SetFullscreen and accepts trusted gui_fullscreen_result.
    const beforeFs = events.length;
    await sendInput({ op: 'pointer_down', hit_region: 'content', surface_id: previewMap.surface_id, pointer_id: 31, x: 10, y: 10, timestamp_ms: Date.now() });
    await sendInput({ op: 'pointer_up', surface_id: previewMap.surface_id, pointer_id: 31, button: 0, x: 10, y: 10, canceled: false });
    ports.port1.postMessage({ type: 'message', text: JSON.stringify({ t: 'toggle_fullscreen', active: true }) });
    const fsCmd = await display('set_fullscreen', c => c.surface_id === previewMap.surface_id && c.active === true, beforeFs);
    assert.equal(fsCmd.active, true);
    await call('gui_fullscreen_result', { surface_id: previewMap.surface_id, active: true });
    await waitDoc(() => lastFs?.active === true, 'fullscreen entered');

    // fd-backed ExportFile download with gesture emits DisplayCmd::ExportFile with exact bytes.
    const beforeExport = events.length;
    await sendInput({ op: 'pointer_down', hit_region: 'content', surface_id: previewMap.surface_id, pointer_id: 32, x: 10, y: 10, timestamp_ms: Date.now() });
    await sendInput({ op: 'pointer_up', surface_id: previewMap.surface_id, pointer_id: 32, button: 0, x: 10, y: 10, canceled: false });
    ports.port1.postMessage({ type: 'message', text: JSON.stringify({ t: 'download' }) });
    const exp = await display('export_file', c => c.surface_id === previewMap.surface_id, beforeExport);
    assert.equal(exp.filename, 'l6c-preview-proto.md');
    const expBytes = exp.data instanceof Uint8Array ? Buffer.from(exp.data) : Buffer.from(exp.data, 'base64');
    assert.equal(expBytes.toString('utf8'), body);

    // Close exits cleanly with status 0 and unmaps.
    const beforeClose = events.length;
    await sendInput({ op: 'chrome_action', surface_id: previewMap.surface_id, state: null });
    const exited = await until('gui-exit', e => e.pid === previewPid, beforeClose);
    assert.equal(exited.status, 0, exited.stderr);
    await display('unmap', c => c.surface_id === previewMap.surface_id, beforeClose);
    await sys({ unlink: { path: filePath } });
  });
  const beforeFocus = events.length;
  await call('gui_host_event', { event: { op: 'focus_request', surface_id: b.surface_id } });
  await display('focus', c => c.surface_id === b.surface_id, beforeFocus);
  const bindCanvas = async id => {
    const { port1, port2 } = new MessageChannel(); t.after(() => port1.close());
    await call('gui_pixel_canvas', { surface_id: id, generation: 1, canvas: port2, backend: 'software2d' }, [port2]);
    await display('set_a11y', c => c.surface_id === id && c.a11y.live_announcement === 'Rendered generation 1');
  };
  await bindCanvas(b.surface_id);
  let at = events.length;
  await sendInput({ op: 'key', surface_id: b.surface_id, key: 'Delete', code: 'Delete', paste: false });
  await display('unmap', c => c.surface_id === b.surface_id, at);
  await until('test-canvas-dispose', c => c.surface_id === b.surface_id && c.generation === 1, at);
  assert.ok(!events.some(m => m.event === 'gui-exit' && m.value.pid === pixel));
  await display('focus', c => c.surface_id === a.surface_id, at);
  const survivor = await launch('gui-sample-pixel');
  const canvas = await display('map', c => c.owner_pid === survivor);
  await bindCanvas(canvas.surface_id);
  at = events.length;
  await sendInput({ op: 'focus_request', surface_id: a.surface_id });
  await sendInput({ op: 'key', surface_id: a.surface_id, paste: false });
  command('pick');
  const pendingPick = await display('pick_file', () => true, at);
  const copying = call('test_gui_slow_pick', { request_id: pendingPick.request_id, surface_id: a.surface_id });
  const canceled = assert.rejects(copying, e => e.errno === 'ECANCELED');
  await until('test-copy-pending', v => v, at);
  await kill(comp); await display('seat_reset', () => true, at);
  await until('test-canvas-dispose', c => c.surface_id === canvas.surface_id && c.generation === 1, at);
  assert.ok(!events.some(m => m.event === 'gui-exit' && m.value.pid === survivor));
  await call('test_gui_finish_copy'); await canceled;
  assert.equal((await sys({ stat: { path: '/run/gui/pick-' + pendingPick.request_id } }, true)).err.errno, 'ENOENT');
  const shellPid = await call('gui_start', { program: 'gui-sample-doc', securityRole: 'lock' });
  await call('gui_start', { program: 'compositor', shellPid });
  await display('set_drag_mode', () => true, at);
  const lock = await display('map', c => c.role === 'lock', at);
  assert.equal(lock.owner_pid, shellPid); assert.notEqual(lock.surface_id, a.surface_id);
  await display('focus', c => c.surface_id === lock.surface_id && c.modal, at);
  const shellPort = new MessageChannel(); t.after(() => shellPort.port1.close());
  await call('gui_surface_port', { surface_id: lock.surface_id, port: shellPort.port2 }, [shellPort.port2]);
  await sendInput({ op: 'key', surface_id: lock.surface_id, paste: false });
  shellPort.port1.postMessage({ type: 'message', text: '{"action":"pick"}' });
  const oldLogin = await display('pick_file', c => c.surface_id === lock.surface_id, at);
  const refused = new Promise(resolve => shellPort.port1.once('message', m => resolve(m.text)));
  await call('login_refresh');
  assert.equal(await refused, 'ECANCELED');
  await assert.rejects(call('gui_picker_result', { request_id: oldLogin.request_id, surface_id: lock.surface_id, file: new File(['old'], 'old') }), e => e.errno === 'ECANCELED');

});

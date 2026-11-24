import { test, expect } from './test.js';
import { openGui, documentWindow, beginDrag } from './gui-harness.js';
import { dragStatistics } from '../web/gui/host-adapter.js';

for (const mode of ['local-lease', 'roundtrip']) {
  test('120 pointer-to-frame commits through the ' + mode + ' path', async ({ page, context }, testInfo) => {
    // Count actual messages on this page's kernel Worker in both directions.
    // The kernel separately counts the compositor Worker's posted requests.
    await page.addInitScript(() => {
      const Native = window.Worker;
      window.guiTraffic = { active: false, sent: 0, received: 0 };
      window.Worker = class extends Native {
        constructor(...args) {
          super(...args);
          this.addEventListener('message', () => { if (window.guiTraffic.active) window.guiTraffic.received++; });
        }
        postMessage(...args) {
          if (window.guiTraffic.active) window.guiTraffic.sent++;
          return super.postMessage(...args);
        }
      };
    });
    await openGui(page, '?drag=' + mode);
    await page.waitForFunction(mode => window.guiSession.adapter.mode === mode, mode.replace('-', '_'));
    const p = await beginDrag(page, documentWindow(page).locator('.title'));
    const cdp = await context.newCDPSession(page);
    await page.evaluate(async () => {
      const { adapter, call, compositorPid } = window.guiSession;
      adapter.frames = []; adapter.messages = 0;
      await call('gui_worker_metrics', { pid: compositorPid, start: true });
      window.guiTraffic.active = true;
      window.guiTraffic.start = performance.now();
    });
    // Each unique x identifies one dispatch. The driver's clock runs independently
    // of CDP acknowledgements, the compositor and the browser's animation frames.
    const start = performance.now(), count = 120;
    const positions = Array.from({ length: count }, (_, i) => ({ x: Math.round(p.x) + (i + 1) * 2, y: Math.round(p.y) + Math.floor((i + 1) / 3) }));
    await Promise.all(positions.map(({ x, y }, i) => new Promise(resolve =>
      setTimeout(resolve, Math.max(0, start + (i + 1) * 1000 / 60 - performance.now()))
    ).then(() => cdp.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x, y, buttons: 1, pointerType: 'mouse' }))));
    const last = positions.at(-1);
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    await cdp.send('Input.dispatchMouseEvent', { type: 'mouseReleased', ...last, button: 'left', buttons: 0, pointerType: 'mouse' });
    await page.waitForFunction(() => !window.guiSession.adapter.drag);
    await cdp.detach();
    const measured = await page.evaluate(async () => {
      const { adapter, call, compositorPid } = window.guiSession;
      const traffic = window.guiTraffic;
      traffic.active = false;
      const duration = performance.now() - traffic.start;
      const compositor = await call('gui_worker_metrics', { pid: compositorPid, start: false });
      const frames = adapter.frames; adapter.frames = null;
      return { frames, gestures: adapter.messages, duration, compositor, sent: traffic.sent, received: traffic.received };
    });
    const observed = new Map(measured.frames.map(f => [f.x + ',' + f.y, f.latency]));
    const intervals = positions.map(p => observed.get(p.x + ',' + p.y)).filter(t => t != null);
    const metrics = { mode, dispatched: count, ...dragStatistics(intervals, measured.sent + measured.received + measured.compositor, measured.duration, count),
      durationMs: measured.duration, pageSent: measured.sent, pageReceived: measured.received, compositorPosted: measured.compositor,
      gestureMessages: measured.gestures };
    expect(metrics.samples).toBeGreaterThan(0);
    expect(metrics.samples + metrics.missed).toBe(count);
    expect(metrics.compositorPosted).toBeGreaterThan(0);
    expect(metrics.p50).toBeLessThanOrEqual(metrics.p95);
    expect(metrics.p95).toBeLessThanOrEqual(metrics.p99);
    expect(metrics.p99).toBeLessThanOrEqual(metrics.max);
    if (mode === 'roundtrip') expect(metrics.gestureMessages).toBeGreaterThanOrEqual(2 * metrics.samples);
    else expect(metrics.gestureMessages).toBeLessThanOrEqual(4 + Math.ceil(measured.duration / 100));
    await testInfo.attach('drag-latency-' + mode + '.json', { body: JSON.stringify(metrics, null, 2), contentType: 'application/json' });
    console.log('GUI drag ' + JSON.stringify(metrics));
  });
}

import { test, expect } from './test.js';
import { openGui, documentWindow, beginDrag, finishDrag } from './gui-harness.js';
import { dragStatistics } from '../web/gui/host-adapter.js';

for (const mode of ['local-lease', 'roundtrip']) {
  test('120 pointer-to-frame commits through the ' + mode + ' path', async ({ page }, testInfo) => {
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
    await page.evaluate(async () => {
      const { adapter, call, compositorPid } = window.guiSession;
      adapter.samples = []; adapter.messages = 0;
      await call('gui_worker_metrics', { pid: compositorPid, start: true });
      window.guiTraffic.active = true;
      window.guiTraffic.start = performance.now();
    });
    const p = await beginDrag(page, documentWindow(page).locator('.title'));
    for (let i = 1; i <= 120; ++i) {
      await page.mouse.move(p.x + i * 2, p.y + Math.floor(i / 3));
      // Waiting for this dispatch's paint prevents driver-side coalescing from
      // silently shortening the 120-step trace, including on slow hosts.
      await page.waitForFunction(n => window.guiSession.adapter.samples.length >= n, i, { polling: 'raf' });
    }
    await finishDrag(page);
    const measured = await page.evaluate(async () => {
      const { adapter, call, compositorPid } = window.guiSession;
      const traffic = window.guiTraffic;
      traffic.active = false;
      const duration = performance.now() - traffic.start;
      const compositor = await call('gui_worker_metrics', { pid: compositorPid, start: false });
      return { intervals: adapter.samples, gestures: adapter.messages, duration, compositor, sent: traffic.sent, received: traffic.received };
    });
    const metrics = { mode, ...dragStatistics(measured.intervals, measured.sent + measured.received + measured.compositor, measured.duration),
      durationMs: measured.duration, pageSent: measured.sent, pageReceived: measured.received, compositorPosted: measured.compositor,
      gestureMessages: measured.gestures };
    expect(metrics.samples).toBe(120);
    expect(metrics.compositorPosted).toBeGreaterThan(0);
    expect(metrics.p50).toBeLessThanOrEqual(metrics.p95);
    expect(metrics.p95).toBeLessThanOrEqual(metrics.p99);
    expect(metrics.p99).toBeLessThanOrEqual(metrics.max);
    if (mode === 'roundtrip') expect(metrics.gestureMessages).toBeGreaterThanOrEqual(242);
    else expect(metrics.gestureMessages).toBeLessThanOrEqual(4 + Math.ceil(measured.duration / 100));
    await testInfo.attach('drag-latency-' + mode + '.json', { body: JSON.stringify(metrics, null, 2), contentType: 'application/json' });
    console.log('GUI drag ' + JSON.stringify(metrics));
  });
}

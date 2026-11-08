import { test as base } from '@playwright/test';
export { expect, request, devices } from '@playwright/test';

// Applies to every context, including tests that create several tabs/accounts themselves.
// OS_NO_SHARED_WORKER=1 runs the complete suite under the amendment's portability gate.
export const test = base.extend({
  sharedWorkerMode: [async ({ browser }, use) => {
    const create = browser.newContext;
    const compiler = process.env.TW_TEST_COMPILER_URL;
    if (compiler && !/^http:\/\/127\.0\.0\.1:\d+$/.test(compiler)) throw new Error('test compiler must be on loopback');
    if (process.env.OS_NO_SHARED_WORKER === '1' || compiler) browser.newContext = async function (...args) {
      const context = await create.apply(this, args);
      if (process.env.OS_NO_SHARED_WORKER === '1') await context.addInitScript(() => { delete globalThis.SharedWorker; });
      // Optional component test transport when workerd's container network is unavailable.
      // This still authorizes the original bytes, then runs the real compiler. It deliberately
      // does not count as validation of ModuleCompiler's R2 cache or the full integration gate.
      if (compiler) await context.route('**/api/file?**', async route => {
        const url = new URL(route.request().url());
        if (!url.searchParams.has('compile')) return route.fallback();
        url.searchParams.delete('compile');
        const original = await route.fetch({ url: url.href });
        if (!original.ok()) return route.fulfill({ response: original });
        const response = await fetch(`${compiler}/compile`, { method: 'POST', body: await original.body() });
        await route.fulfill({ status: response.status, contentType: response.headers.get('content-type') || 'application/json', body: Buffer.from(await response.arrayBuffer()) });
      });
      return context;
    };
    try { await use(); } finally { browser.newContext = create; }
  }, { scope: 'worker', auto: true }],
});

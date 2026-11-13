import { test as base, expect } from './test.js';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// WebKit's ephemeral contexts reject OPFS. Exercise ordinary browser storage in
// a fresh persistent profile, then remove it; no existing user profile is touched.
export const test = base.extend({
  context: async ({ context, browserName, playwright, launchOptions, baseURL, viewport, ignoreHTTPSErrors }, use) => {
    if (browserName !== 'webkit') return use(context);
    const directory = await mkdtemp(join(tmpdir(), 'os-storage-webkit-'));
    const persistent = await playwright.webkit.launchPersistentContext(directory, { ...launchOptions, headless: true, baseURL, viewport, ignoreHTTPSErrors });
    try { await use(persistent); } finally { await persistent.close(); await rm(directory, { recursive: true, force: true }); }
  },
});
export { expect };

import { defineConfig } from '@playwright/test';
const env = { ...process.env };
delete env.DISPLAY;
export default defineConfig({
  testDir: './tests', testMatch: 'fullscreen.spec.js', workers: 1, timeout: 30000,
  use: { baseURL: process.env.OS_TEST_URL || 'http://127.0.0.1:8787', viewport: { width: 1280, height: 800 },
    launchOptions: { env }, screenshot: 'only-on-failure', trace: 'retain-on-failure' },
  projects: [
    { name: 'chromium', use: { browserName: 'chromium', launchOptions: { env, args: ['--ozone-platform=headless'] } } },
    { name: 'firefox', use: { browserName: 'firefox' } },
    { name: 'webkit', use: { browserName: 'webkit' } },
  ],
});

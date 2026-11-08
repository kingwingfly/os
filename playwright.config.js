import { defineConfig } from '@playwright/test';
const browserEnv = { ...process.env };
// A desktop DISPLAY can force SwiftShader to connect to an inaccessible X server.
delete browserEnv.DISPLAY;
export default defineConfig({
  testDir: './tests', testMatch: '**/*.spec.js', workers: 1, timeout: 90_000,
  use: { baseURL: process.env.TERMINAL_TEST_URL || 'http://127.0.0.1:8787', viewport: { width: 1440, height: 1000 },
    screenshot: 'only-on-failure', trace: 'retain-on-failure' },
  projects: [
    { name: 'chromium', use: { browserName: 'chromium',
      launchOptions: { env: browserEnv, args: ['--ozone-platform=headless', '--use-gl=angle', '--use-angle=swiftshader', '--enable-unsafe-swiftshader'] } } },
    // The process engine in a second browser: its calls by JSPI and by synchronous XHR, fork,
    // exec, pipes and process authorization.
    { name: 'firefox', testMatch: ['files.spec.js', 'exec.spec.js', 'fork.spec.js', 'process-security.spec.js', 'pty.spec.js', 'completion.spec.js', 'file-launch.spec.js', 'executable-resolution.spec.js', 'shell.spec.js'], use: { browserName: 'firefox', launchOptions: { env: browserEnv } } },
  ],
});

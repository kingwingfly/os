import { defineConfig } from '@playwright/test';
const browserEnv = { ...process.env };
// A desktop DISPLAY can force SwiftShader to connect to an inaccessible X server.
delete browserEnv.DISPLAY;
export default defineConfig({
  testDir: './tests', testMatch: '**/*.spec.js', workers: 1, timeout: 90_000,
  use: { baseURL: process.env.OS_TEST_URL || 'http://127.0.0.1:8787', viewport: { width: 1440, height: 1000 },
    screenshot: 'only-on-failure', trace: 'retain-on-failure' },
  projects: [
    { name: 'chromium', use: { browserName: 'chromium',
      launchOptions: { env: browserEnv, args: ['--ozone-platform=headless', '--use-gl=angle', '--use-angle=swiftshader', '--enable-unsafe-swiftshader'] } } },
    // The process engine in a second browser: its calls by JSPI and by synchronous XHR, fork,
    // exec, pipes and process authorization.
    { name: 'firefox', testMatch: ['policies.spec.js', 'resources.spec.js', 'releases.spec.js', 'pid-limits.spec.js', 'service-containment.spec.js', 'applications.spec.js', 'lifecycle-scope.spec.js', 'lifecycle.spec.js', 'session-targets.spec.js', 'login-boot.spec.js', 'init-executable.spec.js', 'login-services.spec.js', 'services.spec.js', 'seat-devices.spec.js', 'init-owner.spec.js', 'login-session.spec.js', 'console-sharing.spec.js', 'console-attachment.spec.js', 'ptmx.spec.js', 'controlling-tty.spec.js', 'byte-devices.spec.js', 'sessions.spec.js', 'identity-signals.spec.js', 'system-shell.spec.js', 'null.spec.js', 'rename.spec.js', 'archive.spec.js', 'accelerator.spec.js', 'files.spec.js', 'exec.spec.js', 'fork.spec.js', 'process-security.spec.js', 'pty.spec.js', 'completion.spec.js', 'file-launch.spec.js', 'executable-resolution.spec.js', 'shell.spec.js'], use: { browserName: 'firefox', launchOptions: { env: browserEnv } } },
  ],
});

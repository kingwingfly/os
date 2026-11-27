// Phase 10a (#86) NT-10 Chromium Playwright E2E:
// 1. Default boot starts `netd.service` (`State: active`) with ZERO `/api/net/*` or
//    `/api/service-auth` outbound network requests.
// 2. `netctl status --json` succeeds locally via `/run/netd.sock` and reports version 1 ready.
// 3. SSRF/private targets (`127.0.0.1:8787`, `169.254.169.254:80`) and ungranted public
//    targets fail closed with zero leaked network requests.
import { test, expect } from './test.js';
import { execCmd } from './ui.js';

async function runService(page, args, { sudo = false } = {}) {
  const res = await execCmd(page, ['/usr/bin/service', ...args], { sudo });
  return `${res.stdout || ''}\n${res.stderr || ''}`;
}

test('NT-10 netd.service boots cleanly with zero network calls and enforces default-deny + SSRF refusal', async ({ page }) => {
  const bootNetCalls = [];
  const onReq = req => {
    const p = new URL(req.url()).pathname;
    if (p.startsWith('/api/net/') || p === '/api/service-auth') {
      bootNetCalls.push(`${req.method()} ${p}`);
    }
  };
  page.on('request', onReq);

  await page.goto('/');
  await page.waitForFunction(() => !!window.os?.exec, null, { timeout: 30_000 });

  let statusOut = '';
  await expect.poll(async () => {
    statusOut = await runService(page, ['status', 'netd']);
    return statusOut;
  }, { timeout: 30_000 }).toMatch(/State:\s+active/i);

  // Hard invariant: ZERO `/api/net/*` or `/api/service-auth` calls during boot!
  expect(bootNetCalls).toEqual([]);

  // `netctl status --json` queries `/run/netd.sock` locally without network I/O.
  const netStatus = await execCmd(page, ['/usr/bin/netctl', 'status', '--json']);
  expect(netStatus.status, netStatus.stderr).toBe(0);
  const parsed = JSON.parse(netStatus.stdout.trim());
  expect(parsed.version).toBe(1);
  expect(parsed.ready).toBe(true);
  expect(bootNetCalls).toEqual([]);

  // SSRF / private addresses fail fast at `netd` / kernel without touching `/api/net/*`.
  const imds = await execCmd(page, ['/usr/bin/netctl', 'connect', '169.254.169.254', '80']);
  expect(imds.status).not.toBe(0);
  expect(imds.stderr).toMatch(/EACCES|prohibited|denied/i);

  const localDev = await execCmd(page, ['/usr/bin/netctl', 'connect', '127.0.0.1', '8787']);
  expect(localDev.status).not.toBe(0);
  expect(localDev.stderr).toMatch(/EACCES|prohibited|denied|ENOTCONN/i);

  // Public target without Cloud Sign-In / `RemoteScope.net` fails closed with zero `/api/net/*` calls.
  const deniedPub = await execCmd(page, ['/usr/bin/netctl', 'connect', 'example.com', '80']);
  expect(deniedPub.status).not.toBe(0);
  expect(bootNetCalls).toEqual([]);

  page.off('request', onReq);
});

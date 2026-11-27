import { test, expect } from './test.js';
import { crc32 } from 'node:zlib';
import {
  closePreview,
  pageMkdirp,
  pagePut,
  pageRmrf,
  previewContent,
  previewFrame,
  previewSurface,
  runTerminal,
  waitForTerminalReady,
} from './ui.js';

function zip(files) {
  const parts = [], central = [];
  let offset = 0;
  for (const [name, text] of files) {
    const data = Buffer.from(text), path = Buffer.from(name), crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(path.length, 26);
    const entry = Buffer.alloc(46);
    entry.writeUInt32LE(0x02014b50, 0);
    entry.writeUInt16LE(20, 4);
    entry.writeUInt16LE(20, 6);
    entry.writeUInt32LE(crc, 16);
    entry.writeUInt32LE(data.length, 20);
    entry.writeUInt32LE(data.length, 24);
    entry.writeUInt16LE(path.length, 28);
    entry.writeUInt32LE(offset, 42);
    parts.push(local, path, data);
    central.push(entry, path);
    offset += 30 + path.length + data.length;
  }
  const directory = Buffer.concat(central), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...parts, directory, end]);
}

function minimalPdf() {
  const objects = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 120] /Contents 4 0 R >>',
    '<< /Length 33 >>\nstream\n0.2 0.6 0.3 rg 10 10 100 60 re f\nendstream',
  ];
  let text = '%PDF-1.4\n';
  const offsets = [];
  for (let i = 0; i < objects.length; i++) {
    offsets.push(Buffer.byteLength(text));
    text += `${i + 1} 0 obj\n${objects[i]}\nendobj\n`;
  }
  const xref = Buffer.byteLength(text);
  text += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`
    + offsets.map(n => String(n).padStart(10, '0') + ' 00000 n \n').join('');
  text += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(text);
}

test('L6c-2 security: hostile Markdown, SVG, .game, and archive payloads execute zero script inside sealed preview', async ({ page }) => {
  const base = '/home/user/preview-sec-' + Date.now().toString(36);
  await page.goto('/');
  await waitForTerminalReady(page);
  await pageMkdirp(page, base, 0o755);
  try {
    // Verify legacy in-page dialog & globals are completely retired.
    expect(await page.evaluate(() => ({
      viewerDialog: !!document.getElementById('viewer'),
      editorDialog: !!document.getElementById('editor'),
      osPreview: typeof window.osPreview,
    }))).toEqual({
      viewerDialog: false,
      editorDialog: false,
      osPreview: 'undefined',
    });

    const hostileMd = [
      '# Hostile Payload',
      '',
      '<script>window.hostileMd = "script";</script>',
      '<iframe src="https://evil.invalid/frame"></iframe>',
      '<img src="x" onerror="window.hostileMd = \'img\'">',
      '<svg onload="window.hostileMd = \'svg\'"></svg>',
      '',
      '[Click bad](javascript:window.hostileMd="js")',
      '![hostile-svg](evil.svg)',
    ].join('\n');
    const hostileSvg = '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" onload="window.hostileSvg=1"><script>window.hostileSvg=2</script><rect width="32" height="32" fill="#2a6"/></svg>';

    await pagePut(page, base + '/hostile.md', hostileMd);
    await pagePut(page, base + '/evil.svg', hostileSvg);
    await pagePut(page, base + '/escape.game', JSON.stringify({ engine: 'bevy', entry: '../escape' }));
    await pagePut(page, base + '/hostile.zip', zip([
      ['../../etc/passwd', 'not-really-passwd'],
      ['<img src=x onerror="window.hostileZip=1">.txt', 'payload'],
    ]));

    const pf = previewFrame(page);

    // 1. Hostile Markdown + embedded hostile SVG inside sealed Document iframe.
    await runTerminal(page, `open ${base}/hostile.md`);
    await expect(previewSurface(page)).toBeVisible();
    await expect(pf.locator('.markdown h1')).toHaveText('Hostile Payload');
    await expect.poll(() => pf.locator('.markdown img[alt="hostile-svg"]').evaluate(el => el.naturalWidth)).toBe(32);

    // Inspect iframe sandbox & CSP sealing.
    const iframeMeta = await previewSurface(page).locator('iframe').first().evaluate(el => ({
      sandbox: el.getAttribute('sandbox'),
      hasCspDefaultNone: el.srcdoc.includes("default-src 'none'"),
      hasCspConnectNone: el.srcdoc.includes("connect-src 'none'"),
      hasCspFrameNone: el.srcdoc.includes("frame-src 'none'"),
    }));
    expect(iframeMeta).toEqual({
      sandbox: 'allow-scripts',
      hasCspDefaultNone: true,
      hasCspConnectNone: true,
      hasCspFrameNone: true,
    });

    expect(await pf.locator('.markdown script, .markdown iframe, .markdown [onerror], .markdown [onload], .markdown a[href^="javascript:"]').count()).toBe(0);
    expect(await page.evaluate(() => [window.hostileMd, window.hostileSvg])).toEqual([undefined, undefined]);
    expect(await pf.locator('body').evaluate(() => [window.hostileMd, window.hostileSvg])).toEqual([undefined, undefined]);
    await closePreview(page);

    // 2. Hostile standalone SVG executes zero script.
    await runTerminal(page, `open ${base}/evil.svg`);
    await expect(pf.locator('.media-frame img')).toHaveAttribute('src', /^data:image\/svg\+xml/);
    await expect.poll(() => pf.locator('.media-frame img').evaluate(el => el.naturalWidth)).toBe(32);
    expect(await page.evaluate(() => window.hostileSvg)).toBeUndefined();
    expect(await pf.locator('body').evaluate(() => window.hostileSvg)).toBeUndefined();
    await closePreview(page);

    // 3. Hostile `.game` traversal rejected with zero embed frame.
    await runTerminal(page, `open ${base}/escape.game`);
    await expect(previewContent(page)).toContainText('Game entry is not registered');
    await expect(previewSurface(page).locator('iframe.game-embed-frame')).toHaveCount(0);
    await closePreview(page);

    // 4. Hostile ZIP with path traversal & HTML filename renders as inert escaped text.
    await runTerminal(page, `open ${base}/hostile.zip`);
    await expect(pf.locator('.archive li', { hasText: '../../etc/passwd' })).toBeVisible();
    await expect(pf.locator('.archive li', { hasText: '<img src=x onerror="window.hostileZip=1">.txt' })).toBeVisible();
    expect(await pf.locator('.archive img').count()).toBe(0);
    expect(await page.evaluate(() => window.hostileZip)).toBeUndefined();
    expect(await pf.locator('body').evaluate(() => window.hostileZip)).toBeUndefined();
    await closePreview(page);
  } finally {
    await pageRmrf(page, base).catch(() => {});
  }
});

test('L6c-2 offline: local Markdown, code, and PDF previews work with zero /api network calls', async ({ page }) => {
  const base = '/home/user/preview-offline-' + Date.now().toString(36);
  await page.goto('/');
  await waitForTerminalReady(page);
  await pageMkdirp(page, base, 0o755);
  try {
    await pagePut(page, base + '/offline.md', '# Offline Works\n\n```rust\nfn ok() -> u32 { 42 }\n```\n');
    await pagePut(page, base + '/offline.pdf', minimalPdf());

    const apiRequests = [];
    await page.route('**/api/**', route => {
      apiRequests.push(route.request().url());
      return route.abort('failed');
    });

    const pf = previewFrame(page);
    await runTerminal(page, `open ${base}/offline.md`);
    await expect(pf.locator('.markdown h1')).toHaveText('Offline Works');
    await expect(pf.locator('.markdown code .hl-keyword').first()).toHaveText('fn');
    await closePreview(page);

    await runTerminal(page, `open ${base}/offline.pdf`);
    await expect(pf.locator('.pdf-toolbar [role=status]')).toHaveText('1 / 1');
    await expect(pf.locator('.pdf-page')).toBeVisible();
    await closePreview(page);

    expect(apiRequests).toEqual([]);
  } finally {
    await page.unroute('**/api/**').catch(() => {});
    await pageRmrf(page, base).catch(() => {});
  }
});

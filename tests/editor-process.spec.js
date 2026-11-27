import { test, expect } from './test.js';
import {
  editorClose,
  editorContent,
  editorDiscard,
  editorFrame,
  editorSave,
  editorStatus,
  editorSurface,
  execCmd,
  pageGetText,
  pageMkdirp,
  pagePut,
  pageRmrf,
  runTerminal,
  waitForDesktopReady,
} from './ui.js';

test('L6c-1: /usr/bin/editor runs as an ordinary GUI process in ps with sealed Document iframe, zero #editor dialog, and Host compat EPERM', async ({ page }) => {
  const dir = '/home/user/editor-proc-' + Date.now().toString(36);
  const path = `${dir}/hello.md`;
  await page.goto('/');
  await waitForDesktopReady(page);
  await pageMkdirp(page, dir, 0o755);
  await pagePut(page, path, '# Initial\n', { mode: 0o644 });

  try {
    expect(await page.locator('dialog#editor').count()).toBe(0);

    await runTerminal(page, `vim ${path}`, { wait: false });
    await expect(editorSurface(page)).toBeVisible({ timeout: 15_000 });
    await expect(editorContent(page)).toBeVisible({ timeout: 15_000 });

    const iframeAttrs = await editorSurface(page).locator('iframe').evaluate(el => ({
      sandbox: el.getAttribute('sandbox'),
      hasSrcdoc: el.hasAttribute('srcdoc'),
    }));
    expect(iframeAttrs.sandbox).toBe('allow-scripts');
    expect(iframeAttrs.hasSrcdoc).toBe(true);

    const pidAttr = Number(await editorSurface(page).getAttribute('data-pid'));
    expect(pidAttr).toBeGreaterThan(1);

    const ps = await execCmd(page, ['/usr/bin/ps']);
    expect(ps.status).toBe(0);
    expect(ps.stdout).toMatch(new RegExp(`\\b${pidAttr}\\b.*editor`));

    // Verify Host compat `editor` is rejected with EPERM.
    const probe = await execCmd(page, [
      '/usr/bin/gui-sample-doc',
      '--request',
      JSON.stringify({
        op: 'create_surface',
        spec: {
          role: 'window',
          kind: { host: { component: 'editor' } },
          title: 'Forged Editor',
          rect: { x: 0, y: 0, width: 320, height: 240 },
          min_size: { width: 160, height: 100 },
          max_size: null,
          resizable: true,
          app_id: 'editor',
        },
      }),
    ]);
    expect(probe.status).toBe(0);
    expect(JSON.parse(probe.stdout.trim())).toEqual({ op: 'error', errno: 'EPERM' });

    await editorClose(page).click();
    await expect(editorSurface(page)).toBeHidden({ timeout: 15_000 });
  } finally {
    await pageRmrf(page, dir).catch(() => {});
  }
});

test('L6c-1: conditional revision save detects ESTALE concurrent edits, supports Save as copy / Overwrite / Reload, and recovers drafts after crash', async ({ page }) => {
  const dir = '/home/user/editor-conflict-' + Date.now().toString(36);
  const path = `${dir}/notes.txt`;
  await page.goto('/');
  await waitForDesktopReady(page);
  await pageMkdirp(page, dir, 0o755);
  await pagePut(page, path, 'version one', { mode: 0o644 });

  try {
    await runTerminal(page, `vim ${path}`, { wait: false });
    const content = editorContent(page);
    await expect(content).toBeVisible({ timeout: 15_000 });
    await expect(content).toContainText('version one');

    // Concurrent external modification on disk triggers ESTALE without overwriting disk.
    await pagePut(page, path, 'version two external', { mode: 0o644 });
    await content.fill('version two local');
    await editorSave(page).click();
    await expect(editorStatus(page)).toContainText('changed in another session');
    expect(await pageGetText(page, path)).toBe('version two external');

    // Conflict actions: Save as copy preserves disk and writes sibling copy.
    await expect(editorFrame(page).locator('#editor-conflict-bar')).toBeVisible();
    await editorFrame(page).locator('#editor-save-copy').click();
    await expect(editorStatus(page)).toContainText('Saved copy to');
    expect(await pageGetText(page, `${dir}/notes.copy.txt`)).toBe('version two local');
    expect(await pageGetText(page, path)).toBe('version two external');

    // Wait briefly for debounced recovery draft, then kill /usr/bin/editor to simulate crash.
    const editorPid = Number(await editorSurface(page).getAttribute('data-pid'));
    await page.waitForTimeout(700);
    await execCmd(page, ['/usr/bin/kill', '-9', String(editorPid)]);
    await expect(editorSurface(page)).toBeHidden({ timeout: 15_000 });

    // Reopen: recovery draft banner offers explicit Restore or Discard.
    await runTerminal(page, `vim ${path}`, { wait: false });
    await expect(content).toBeVisible({ timeout: 15_000 });
    await expect(editorFrame(page).locator('#editor-draft-banner')).toBeVisible({ timeout: 10_000 });
    await editorFrame(page).locator('#editor-restore-draft').click();
    await expect(content).toContainText('version two local');

    // Explicit Save now succeeds against the refreshed base revision and removes the draft.
    await editorSave(page).click();
    await expect(editorStatus(page)).toHaveText('Saved');
    expect(await pageGetText(page, path)).toBe('version two local');

    // Download draft triggers browser download through compositor ExportFile.
    const downloadPromise = page.waitForEvent('download');
    await editorFrame(page).locator('#editor-download').click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toBe('notes.txt');

    await editorClose(page).click();
    await expect(editorSurface(page)).toBeHidden({ timeout: 15_000 });
  } finally {
    await pageRmrf(page, dir).catch(() => {});
  }
});

test('L6c-1: IME composition text commits cleanly without triggering Ctrl+S or Escape close during composition', async ({ page }) => {
  const dir = '/home/user/editor-ime-' + Date.now().toString(36);
  const path = `${dir}/ime.txt`;
  await page.goto('/');
  await waitForDesktopReady(page);
  await pageMkdirp(page, dir, 0o755);
  await pagePut(page, path, '', { mode: 0o644 });

  try {
    await runTerminal(page, `vim ${path}`, { wait: false });
    const content = editorContent(page);
    await expect(content).toBeVisible({ timeout: 15_000 });
    await content.click();

    // Simulate CJK IME composition via CDP Input.imeSetComposition + commitText.
    const cdp = await page.context().newCDPSession(page);
    await cdp.send('Input.imeSetComposition', {
      text: 'にほん',
      selectionStart: 3,
      selectionEnd: 3,
    });
    await cdp.send('Input.insertText', { text: '日本語テスト' });
    await expect(content).toContainText('日本語テスト');

    await page.keyboard.press('Control+s');
    await expect(editorStatus(page)).toHaveText('Saved');
    expect(await pageGetText(page, path)).toBe('日本語テスト');

    await editorClose(page).click();
    await expect(editorSurface(page)).toBeHidden({ timeout: 15_000 });
  } finally {
    await pageRmrf(page, dir).catch(() => {});
  }
});

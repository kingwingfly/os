import { test, expect } from './test.js';
import {
  closePreview,
  editorClose,
  editorContent,
  editorDirty,
  editorDiscard,
  editorFrame,
  editorSave,
  editorStatus,
  editorSurface,
  filesFrame,
  filesSurface,
  pageCall,
  pageGetText,
  pageMkdirp,
  pagePut,
  pageRmrf,
  previewFrame,
  runTerminal,
  terminalScreen,
  terminalSurface,
  terminalViewport,
  waitForDesktopReady,
} from './ui.js';

async function promptSeq(page) {
  return Number((await terminalViewport(page).getAttribute('data-prompt-seq')) || '0');
}
async function waitIdleAfter(page, before, timeout = 20_000) {
  await expect.poll(async () => {
    const vp = terminalViewport(page);
    return (await vp.getAttribute('data-state')) === 'idle'
      && Number((await vp.getAttribute('data-prompt-seq')) || '0') > before;
  }, { timeout }).toBe(true);
}

function pdfBytes() {
  const objects = ['<< /Type /Catalog /Pages 2 0 R >>', '<< /Type /Pages /Kids [3 0 R 5 0 R] /Count 2 >>', '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 400 300] /Contents 4 0 R >>', '<< /Length 33 >>\nstream\n0.2 0.6 0.3 rg 20 20 200 100 re f\nendstream', '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 400 300] /Contents 6 0 R >>', '<< /Length 33 >>\nstream\n0.7 0.6 0.2 rg 20 20 100 200 re f\nendstream'];
  let text = '%PDF-1.4\n', offsets = [0]; for (let i = 0; i < objects.length; i++) { offsets.push(Buffer.byteLength(text)); text += `${i + 1} 0 obj\n${objects[i]}\nendobj\n`; }
  const xref = Buffer.byteLength(text); text += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n` + offsets.slice(1).map(n => String(n).padStart(10, '0') + ' 00000 n \n').join(''); text += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`; return Buffer.from(text);
}

test('manual, dock, listing colors, and Files icons work across desktop and phone viewports', async ({ page }) => {
  await page.goto('/');
  await waitForDesktopReady(page);
  const terminal = terminalSurface(page);
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 1000 });
    // The dock focuses a window, minimizes the focused one, and brings it back.
    const files = filesSurface(page), dock = name => page.getByRole('navigation', { name: 'Dock' }).getByRole('button', { name, exact: true });
    await dock('Files').click(); await expect(files).toBeVisible(); await expect(dock('Files')).toHaveAttribute('aria-pressed', 'true');
    await dock('Files').click(); await expect(files).toBeHidden(); await expect(terminal).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await dock('Files').click(); await expect(files).toBeVisible();
    // A phone shows one window at a time.
    if (width <= 650) await expect(terminal).toBeHidden(); else await expect(terminal).toBeVisible();
    await dock('Terminal').click(); await expect(terminal).toBeVisible();
  }
  // A phone shows the terminal inside the viewport and keeps the account pill compact.
  const box = await terminal.boundingBox(); expect(box.y + box.height).toBeLessThanOrEqual(1000);
  expect(await page.locator('.cloud-panel-trigger').evaluate(e => e.getBoundingClientRect().height < 60)).toBe(true);
  await page.setViewportSize({ width: 1440, height: 1000 });
  await runTerminal(page, 'ls --color=always /');
  await expect(terminalScreen(page)).toContainText('home');
  await expect(terminalScreen(page).locator('span[style*="color:"]').first()).toBeVisible();
  await page.getByRole('navigation', { name: 'Dock' }).getByRole('button', { name: 'Files', exact: true }).click();
  await expect(filesFrame(page).locator('.files [data-kind=directory] svg').first()).toBeVisible();
  await page.getByRole('navigation', { name: 'Dock' }).getByRole('button', { name: 'Terminal', exact: true }).click();
  await runTerminal(page, 'man chmod');
  const pf = previewFrame(page);
  await expect(pf.locator('.manual h1')).toHaveText('chmod — change permissions');
  await expect(pf.locator('.manual')).toContainText('o+r');
  // Pages have sections; options are a table.
  await expect(pf.locator('.manual h2')).toHaveText(['Options', 'Permissions', 'Examples', 'See also']);
  await expect(pf.locator('.manual table td').first()).toHaveText('-R, --recursive');
  await closePreview(page);
  await page.screenshot({ path: 'test-results/workspace-desktop.png', fullPage: true });
});

test('vim edits highlighted Rust, saves conditionally, preserves conflicting drafts, and respects read-only permissions', async ({ page }) => {
  const base = '/home/user/editor-' + Date.now().toString(36);
  await page.goto('/');
  await waitForDesktopReady(page);
  await pageMkdirp(page, base, 0o755);
  try {
    // New file creation with Rust syntax highlighting and Ctrl+S save.
    let seq = await promptSeq(page);
    await runTerminal(page, 'vim ' + base + '/main.rs', { wait: false });
    const content = editorContent(page);
    await expect(content).toBeVisible({ timeout: 15_000 });
    await content.fill('fn main() {\n    let answer = 42;\n}\n');
    await expect(editorDirty(page)).toHaveText('Unsaved');
    await expect(editorFrame(page).locator('.cm-line span').first()).toBeVisible();
    await page.keyboard.press('Control+s');
    await expect(editorStatus(page)).toHaveText('Saved');
    expect(await pageGetText(page, base + '/main.rs')).toContain('let answer = 42;');

    // If an open existing file is removed elsewhere, Save refuses without silently recreating it and preserves the draft.
    await pageRmrf(page, base + '/main.rs');
    await content.fill('fn unsaved_deleted() {}');
    await editorSave(page).click();
    await expect(editorStatus(page)).toContainText('deleted or moved');
    await editorClose(page).click();
    await expect(editorDiscard(page)).toBeVisible();
    await expect(content).toContainText('unsaved_deleted');
    await editorDiscard(page).click();
    await expect(editorSurface(page)).toBeHidden();
    await waitIdleAfter(page, seq);

    // Conditional new-file create (O_CREAT|O_EXCL): if another session created the file meanwhile, refuse overwrite and keep draft.
    seq = await promptSeq(page);
    await runTerminal(page, 'vim ' + base + '/conflict.rs', { wait: false });
    await expect(content).toBeVisible({ timeout: 15_000 });
    await pagePut(page, base + '/conflict.rs', 'fn changed_elsewhere() {}', { mode: 0o644 });
    await content.fill('fn unsaved_local() {}');
    await editorSave(page).click();
    await expect(editorStatus(page)).toContainText('created by another session');
    expect(await pageGetText(page, base + '/conflict.rs')).toBe('fn changed_elsewhere() {}');
    await editorClose(page).click();
    await expect(editorDiscard(page)).toBeVisible();
    await expect(content).toContainText('unsaved_local');
    await editorDiscard(page).click();
    await expect(editorSurface(page)).toBeHidden();
    await waitIdleAfter(page, seq);

    // Read-only permissions (root-owned 0644 opened by uid 1000 user).
    await pageCall(page, { chown: { path: base + '/conflict.rs', uid: 0, gid: 0 } }, { sudo: true });
    await pageCall(page, { chmod: { path: base + '/conflict.rs', mode: 0o644 } }, { sudo: true });
    seq = await promptSeq(page);
    await runTerminal(page, 'vim ' + base + '/conflict.rs', { wait: false });
    await expect(editorStatus(page)).toContainText('Read-only', { timeout: 15_000 });
    await expect(editorSave(page)).toBeDisabled();
    await expect(editorFrame(page).locator('.cm-content')).toHaveAttribute('contenteditable', 'false');
    await editorClose(page).click();
    await expect(editorSurface(page)).toBeHidden();
    await waitIdleAfter(page, seq);
  } finally {
    await pageRmrf(page, base, { sudo: true }).catch(() => {});
  }
});

test('PDF pages and PNG/JPEG/WebP previews load through protected file APIs', async ({ page }) => {
  const base = '/home/user/preview-' + Date.now().toString(36);
  await page.goto('/');
  await waitForDesktopReady(page);
  await pageMkdirp(page, base, 0o755);
  try {
    await pagePut(page, base + '/sample.pdf', pdfBytes());
    const pf = previewFrame(page);
    for (const [ext, mime] of [['png', 'image/png'], ['jpeg', 'image/jpeg'], ['webp', 'image/webp']]) {
      const bytes = await page.evaluate(async mime => {
        const canvas = document.createElement('canvas'); canvas.width = 8; canvas.height = 8;
        canvas.getContext('2d').fillRect(0, 0, 8, 8);
        return [...new Uint8Array(await (await fetch(canvas.toDataURL(mime))).arrayBuffer())];
      }, mime);
      await pagePut(page, base + '/image.' + ext, Buffer.from(bytes));
      await runTerminal(page, 'open ' + base + '/image.' + ext);
      await expect.poll(() => pf.locator('.media-frame img').evaluate(e => e.naturalWidth)).toBe(8);
      await closePreview(page);
    }
    // A PDF scrolls as one document, its pages drawn as they come near, and opens where it was left.
    await runTerminal(page, 'open ' + base + '/sample.pdf');
    await expect(pf.getByLabel('PDF page 1')).toBeVisible();
    await expect(pf.locator('.pdf-toolbar [role=status]')).toHaveText('1 / 2');
    await expect.poll(() => pf.locator('.pdf-page').evaluateAll(pages => pages.filter(p => p.width > 0).length)).toBe(2);
    await pf.getByRole('button', { name: 'Next page' }).click();
    await expect(pf.locator('.pdf-toolbar [role=status]')).toHaveText('2 / 2');
    await closePreview(page);
    await runTerminal(page, 'open ' + base + '/sample.pdf');
    await expect(pf.locator('.pdf-toolbar [role=status]')).toHaveText('2 / 2');
    await closePreview(page);
  } finally {
    await pageRmrf(page, base).catch(() => {});
  }
});

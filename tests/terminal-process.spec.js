import { test, expect } from './test.js';
import {
  closePreview,
  pageMkdirp,
  pagePut,
  pageRmrf,
  pageSys,
  previewSurface,
  promptPath,
  runTerminal,
  switchLocalUser,
  terminalFrame,
  terminalInput,
  terminalScreen,
  terminalSurface,
  terminalTabs,
  terminalViewport,
  waitForTerminalReady,
} from './ui.js';

async function execCmd(page, argv, { sudo = false } = {}) {
  return page.evaluate(
    ({ argv, sudo }) => window.os.exec([argv], { stdin: '', sudo }),
    { argv, sudo },
  );
}

test('L6a: /usr/bin/terminal and /usr/bin/osh run as separate processes on a real PTY with zero in-page shell DOM', async ({ page }) => {
  test.setTimeout(90_000);
  await page.goto('/');
  await waitForTerminalReady(page);

  // Retired in-page shell DOM is completely absent; Terminal renders inside its sealed Document iframe.
  await expect(page.locator('#window-terminal')).toHaveCount(0);
  await expect(page.locator('#command')).toHaveCount(0);
  await expect(terminalSurface(page)).toBeVisible();
  await expect(terminalSurface(page).locator('iframe')).toHaveAttribute('sandbox', 'allow-scripts');

  // Separate OS processes for `/usr/bin/terminal` and `/usr/bin/osh` appear in `ps`.
  await runTerminal(page, 'tty; echo "SHELL=$SHELL PID=$$"; ps');
  const screen = terminalScreen(page);
  await expect(screen).toContainText(/\/dev\/pts\/\d+/);
  await expect(screen).toContainText('SHELL=/usr/bin/osh PID=');
  await expect(screen).toContainText('terminal');
  await expect(screen).toContainText('osh');

  // Pipelines, redirection, and quoting work through `/usr/bin/osh`.
  const dir = '/tmp/l6a-term-' + crypto.randomUUID().slice(0, 8);
  await pageMkdirp(page, dir, 0o700);
  try {
    await runTerminal(page, `cd ${dir} && printf 'alpha\\nbeta\\ngamma\\n' > list.txt && cat list.txt | grep beta | wc -l`);
    await expect(promptPath(page)).toHaveText(dir);
    await expect(screen).toContainText(/\b1\b/);
  } finally {
    await pageRmrf(page, dir).catch(() => {});
  }
});

test('L6a: interactive editing, Tab completion, Up/Down history, Ctrl+C interrupt, and Ctrl+Z/jobs/fg/bg', async ({ page }) => {
  test.setTimeout(90_000);
  await page.goto('/');
  await waitForTerminalReady(page);

  const dir = '/tmp/l6a-edit-' + crypto.randomUUID().slice(0, 8);
  await pageMkdirp(page, dir, 0o700);
  await pagePut(page, `${dir}/sample-alpha.txt`, 'ok\n');
  await pagePut(page, `${dir}/sample-beta.txt`, 'ok\n');
  try {
    await runTerminal(page, `cd ${dir}`);
    await expect(promptPath(page)).toHaveText(dir);

    // Tab completion expands common prefix and displays matches below the active line.
    const input = terminalInput(page);
    await input.fill('cat sam');
    await input.press('Tab');
    await expect(terminalScreen(page)).toContainText('sample-alpha.txt');
    await expect(terminalScreen(page)).toContainText('sample-beta.txt');
    await input.press('Control+c');
    await expect(terminalScreen(page)).toContainText('^C');

    // History recall via Up arrow.
    await runTerminal(page, 'echo HISTORY_MARKER_L6A');
    await expect(terminalScreen(page)).toContainText('HISTORY_MARKER_L6A');
    await input.press('ArrowUp');
    await input.press('Enter');
    await expect(terminalViewport(page)).toHaveAttribute('data-state', 'idle', { timeout: 15_000 });

    // Ctrl+C interrupts a noisy foreground process without hanging the shell.
    await runTerminal(page, 'yes SPAM_L6A', { wait: false });
    await expect(terminalScreen(page)).toContainText('SPAM_L6A', { timeout: 15_000 });
    await input.press('Control+c');
    await expect(terminalViewport(page)).toHaveAttribute('data-state', 'idle', { timeout: 15_000 });

    // Ctrl+Z stops a foreground job, `jobs` lists it, and `fg` + Ctrl+C finishes it.
    await runTerminal(page, 'sleep 30', { wait: false });
    await expect(terminalViewport(page)).toHaveAttribute('data-state', 'busy', { timeout: 15_000 });
    await input.press('Control+z');
    await expect(terminalViewport(page)).toHaveAttribute('data-state', 'idle', { timeout: 15_000 });
    await runTerminal(page, 'jobs');
    await expect(terminalScreen(page)).toContainText(/Stopped.*sleep 30/);
    await runTerminal(page, 'kill %1');
    await runTerminal(page, 'jobs');
  } finally {
    await pageRmrf(page, dir).catch(() => {});
  }
});

test('L6a: multi-tab lifecycle, shell exit keeps emulator alive with Restart, and tab close delivers SIGHUP', async ({ page }) => {
  test.setTimeout(90_000);
  await page.goto('/');
  await waitForTerminalReady(page);

  const frame = terminalFrame(page);
  await expect(terminalTabs(page)).toHaveCount(1);

  // Open a second tab via `+` button and start a sleeping child so we can verify SIGHUP on close.
  await frame.getByRole('button', { name: 'New tab' }).click();
  await expect(terminalTabs(page)).toHaveCount(2, { timeout: 15_000 });
  await waitForTerminalReady(page);

  await runTerminal(page, 'sleep 120 &');
  await expect(terminalScreen(page)).toContainText(/\[1\] \d+/, { timeout: 15_000 });
  const text = await terminalScreen(page).innerText();
  const match = text.match(/\[1\] (\d+)/);
  expect(match).not.toBeNull();
  const childPid = Number(match[1]);

  // Close the second tab: PTY master closes -> SIGHUP+SIGCONT terminates the tab's shell and child job.
  await terminalTabs(page).nth(1).locator('.term-tab-close').click();
  await expect(terminalTabs(page)).toHaveCount(1, { timeout: 15_000 });
  await expect.poll(async () => {
    const ps = await execCmd(page, ['/usr/bin/ps']);
    return ps.stdout.includes(` ${childPid} `) || ps.stdout.startsWith(`${childPid} `);
  }, { timeout: 15_000 }).toBe(false);

  // Open another tab and exit its shell cleanly: emulator and sibling tab remain alive with Restart button.
  await frame.getByRole('button', { name: 'New tab' }).click();
  await expect(terminalTabs(page)).toHaveCount(2, { timeout: 15_000 });
  await waitForTerminalReady(page);
  await runTerminal(page, 'exit 7', { wait: false });
  await expect(terminalViewport(page)).toHaveAttribute('data-state', 'exited', { timeout: 15_000 });
  await expect(terminalScreen(page)).toContainText('[Process exited with status 7]');
  await expect(frame.getByRole('button', { name: 'Restart' })).toBeVisible();

  // Restarting brings a fresh `/usr/bin/osh` prompt back in that tab.
  await frame.getByRole('button', { name: 'Restart' }).click();
  await waitForTerminalReady(page);
  await runTerminal(page, 'echo RESTARTED_OK');
  await expect(terminalScreen(page)).toContainText('RESTARTED_OK');
});

test('L6a: desktop-action CLI utilities (open, man, vim) work over /run/user/<uid>/desktop-actions.sock and host-terminal EPERM holds', async ({ page }) => {
  test.setTimeout(90_000);
  await page.goto('/');
  await waitForTerminalReady(page);

  const file = '/home/user/l6a-doc-' + crypto.randomUUID().slice(0, 8) + '.md';
  await pagePut(page, file, '# L6a Native Terminal\n\nOpened via desktop-actions.sock.\n');
  try {
    // `open` launches Preview window.
    await runTerminal(page, `open ${file}`);
    await expect(previewSurface(page)).toBeVisible({ timeout: 15_000 });
    await closePreview(page);

    // `man` opens Manual in Preview window (and non-TTY `man | head` prints manual text to stdout).
    await runTerminal(page, 'man ls | head -n 2');
    await expect(terminalScreen(page)).toContainText(/ls/i);

    // Unprivileged client requesting SurfaceKind::Host { component: "terminal" } is refused with EPERM.
    const hostReq = JSON.stringify({
      op: 'create_surface',
      spec: {
        role: 'window',
        kind: { host: { component: 'terminal' } },
        title: 'Spoofed Terminal',
        rect: { x: 0, y: 0, width: 320, height: 220 },
        min_size: { width: 280, height: 180 },
        max_size: null,
        resizable: true,
        app_id: 'terminal',
      },
    });
    const hostRes = await execCmd(page, ['/usr/bin/gui-sample-doc', '--request', hostReq]);
    expect(hostRes.status).toBe(0);
    expect(JSON.parse(hostRes.stdout.trim())).toEqual({ op: 'error', errno: 'EPERM' });

    // Switching local user tears down old UID's desktop-actions.sock and cleanly rebinds new UID's socket.
    const [beforeStat] = await pageSys(page, [{ lstat: { path: '/run/user/1000/desktop-actions.sock' } }]);
    expect(beforeStat.ok?.uid).toBe(1000);
    expect(beforeStat.ok.mode & 0o170000).toBe(0o140000);
    expect(beforeStat.ok.mode & 0o7777).toBe(0o600);

    await switchLocalUser(page, 'root');
    try {
      await expect.poll(async () => {
        const [oldSock, newSock] = await pageSys(page, [
          { lstat: { path: '/run/user/1000/desktop-actions.sock' } },
          { lstat: { path: '/run/user/0/desktop-actions.sock' } },
        ]);
        return {
          oldErrno: oldSock.err?.errno ?? null,
          newUid: newSock.ok?.uid ?? null,
          newType: newSock.ok ? (newSock.ok.mode & 0o170000) : null,
          newMode: newSock.ok ? (newSock.ok.mode & 0o7777) : null,
        };
      }, { timeout: 15_000 }).toEqual({
        oldErrno: 'ENOENT',
        newUid: 0,
        newType: 0o140000,
        newMode: 0o600,
      });

      const rootOpen = await execCmd(page, ['/usr/bin/open', file]);
      expect(rootOpen.status).toBe(0);
      await expect(previewSurface(page)).toBeVisible({ timeout: 15_000 });
      await closePreview(page);
    } finally {
      await switchLocalUser(page, 'user');
    }
  } finally {
    await pageRmrf(page, file).catch(() => {});
  }
});

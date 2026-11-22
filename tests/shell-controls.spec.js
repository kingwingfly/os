import { test, expect } from './test.js';
import {
  browse,
  pageCall,
  pageErrno,
  pageGetBytes,
  pageGetText,
  pagePut,
  switchLocalUser,
} from './ui.js';

const password = 'shell-testing-password-621';

async function bootLocal(page) {
  await page.goto('/');
  await page.waitForFunction(() => Boolean(window.os?.bootStatus && window.os?.exec));
  await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'idle', { timeout: 20_000 });
}

async function execLocal(page, argv, { sudo = false, cwd = '/', stdin = '' } = {}) {
  return page.evaluate(
    async ({ argv, sudo, cwd, stdin }) => {
      let stdout = '';
      let stderr = '';
      const result = await window.os.exec([{ argv }], {
        sudo,
        cwd,
        stdin,
        tty: false,
        onOutput: (fd, text) => {
          if (fd === 1) stdout += text;
          else stderr += text;
        },
      });
      return { status: result.status, stdout: stdout || result.stdout || '', stderr };
    },
    { argv, sudo, cwd, stdin },
  );
}

async function fixture(page) {
  await bootLocal(page);
  const name = 'shell' + Date.now().toString(36).slice(-5) + Math.random().toString(36).slice(2, 4);
  const home = '/home/' + name;
  await switchLocalUser(page, 'root');
  await pageCall(page, { useradd: { name, create_home: true, groups: 'wheel' } });
  await pageCall(page, { passwd: { username: name, password, force: true } });
  await switchLocalUser(page, 'user');
  return {
    name,
    home,
    async cleanup() {
      await switchLocalUser(page, 'root').catch(() => {});
      await pageCall(page, { userdel: { name, remove: true } }).catch(() => {});
      await pageCall(page, { groupdel: { name } }).catch(() => {});
      await switchLocalUser(page, 'user').catch(() => {});
    },
  };
}

const run = async (page, text) => {
  await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'idle', { timeout: 20_000 });
  await page.locator('#command').fill(text);
  await page.locator('#command').press('Enter');
};

test('sudo -u restores typing focus; Ctrl+C clears drafts, completion and history; forced passwd accepts short passwords', async ({ page }) => {
  const f = await fixture(page);
  try {
    await run(page, 'sudo -u ' + f.name);
    await expect(page.locator('.cloud-panel-trigger')).toContainText('Local: ' + f.name);
    await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'idle');
    await expect(page.locator('#command')).toBeFocused();
    await page.keyboard.type('pwd'); await page.keyboard.press('Enter');
    await expect(page.locator('.transcript pre').last()).toHaveText(f.home);
    await page.keyboard.type('mkdir discard-me'); await page.keyboard.press('Control+c');
    await expect(page.locator('#command')).toHaveValue('');
    await page.keyboard.press('ArrowUp'); await expect(page.locator('#command')).toHaveValue('pwd');
    await page.keyboard.press('Control+c'); await page.keyboard.press('ArrowDown');
    await expect(page.locator('#command')).toHaveValue('');
    await page.keyboard.type('su'); await page.keyboard.press('Tab');
    await expect(page.locator('#completions')).toBeVisible();
    await page.keyboard.press('Control+c');
    await expect(page.locator('#command')).toHaveValue('');
    await expect(page.locator('#completions')).toHaveCount(0);
    expect(await pageErrno(page, { stat: { path: f.home + '/discard-me' } })).toBe('ENOENT');

    // Interactive local `passwd --force` prompts on stdin and accepts short passwords.
    await run(page, 'passwd --force');
    await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'input', { timeout: 20_000 });
    await page.locator('#command').fill(password); await page.locator('#command').press('Enter');
    await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'input', { timeout: 20_000 });
    await page.locator('#command').fill('1234'); await page.locator('#command').press('Enter');
    await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'input', { timeout: 20_000 });
    await page.locator('#command').fill('1234'); await page.locator('#command').press('Enter');
    await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'idle', { timeout: 20_000 });
    await expect(page.locator('#command')).toBeFocused();

    await page.keyboard.type('whoami'); await page.keyboard.press('Enter');
    await expect(page.locator('.transcript pre').last()).toHaveText(f.name);
    await run(page, 'exit');
    await expect(page.locator('.cloud-panel-trigger')).toContainText('Local: user');

    // Verify new short password works for local `su` authentication, while old password fails.
    const suBad = await execLocal(page, ['sh', '-c', `printf '%s\\n' '${password}' | su '${f.name}' -c whoami`]);
    expect(suBad.status).not.toBe(0);
    const suOk = await execLocal(page, ['sh', '-c', `printf '1234\\n' | su '${f.name}' -c whoami`]);
    expect(suOk.status, suOk.stderr).toBe(0);
    expect(suOk.stdout.trim()).toBe(f.name);

    // Cancelling an interactive prompt with Ctrl+C returns to idle and keeps typing focus.
    await run(page, 'passwd --force');
    await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'input', { timeout: 20_000 });
    await page.locator('#command').press('Control+c');
    await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'idle', { timeout: 10_000 });
    await expect(page.locator('#command')).toBeFocused();
  } finally {
    await f.cleanup();
  }
});

test('force skips only the minimum password length, preserving identity checks', async ({ page }) => {
  const f = await fixture(page);
  try {
    await switchLocalUser(page, f.name, { password, sudo: false });
    // Too short without --force -> EINVAL.
    expect(await pageErrno(page, { passwd: { username: null, password: '1', current_password: password, force: false } })).toBe('EINVAL');
    // Unprivileged user cannot change root's password even with --force -> EPERM.
    expect(await pageErrno(page, { passwd: { username: 'root', password: '1', current_password: password, force: true } })).toBe('EPERM');
    // Wrong current password -> EACCES.
    expect(await pageErrno(page, { passwd: { username: null, password: '1', current_password: 'wrong', force: true } })).toBe('EACCES');
    // Empty or >512-byte passwords are rejected even with --force -> EINVAL.
    for (const value of ['', 'x'.repeat(513)]) {
      expect(await pageErrno(page, { passwd: { username: null, password: value, current_password: password, force: true } })).toBe('EINVAL');
    }
    // Valid short password with --force updates /etc/shadow and invalidates the old password.
    await pageCall(page, { passwd: { username: null, password: '1', current_password: password, force: true } });
    await switchLocalUser(page, 'user');
    expect(await pageErrno(page, { login: { username: f.name, password } })).toBe('EACCES');
    const logged = await pageCall(page, { login: { username: f.name, password: '1' } });
    expect(logged.user).toBe(f.name);
  } finally {
    await f.cleanup();
  }
});

test('touch creates readable empty files, preserves content, validates batches and supports sudo', async ({ page }) => {
  const f = await fixture(page);
  try {
    await switchLocalUser(page, f.name, { password, sudo: false });
    const path = f.home + '/notes.txt';
    expect((await execLocal(page, ['touch', f.home + '/notes.txt', f.home + '/README', f.home + '/notes.txt'], { cwd: f.home })).status).toBe(0);
    const emptyBytes = await pageGetBytes(page, path);
    expect(emptyBytes).toEqual(Buffer.alloc(0));
    const stat = await pageCall(page, { stat: { path } });
    expect(stat.user).toBe(f.name);
    expect(stat.mode & 0o777).toBe(0o644);
    await pagePut(page, path, 'preserve this', { mode: 0o600, overwrite: true });
    const before = await pageGetText(page, path);
    expect((await execLocal(page, ['touch', path], { cwd: f.home })).status).toBe(0);
    expect(await pageGetText(page, path)).toBe(before);
    // Each operand on its own, as GNU touch: the first is made, the second refused.
    const partial = await execLocal(page, ['touch', f.home + '/atomic.txt', '/root/blocked.txt'], { cwd: f.home });
    expect(partial.status).not.toBe(0);
    expect(await pageErrno(page, { stat: { path: f.home + '/atomic.txt' } })).toBeNull();
    expect((await execLocal(page, ['touch', '-c', f.home + '/skip.txt'], { cwd: f.home })).status).toBe(0);
    expect(await pageErrno(page, { stat: { path: f.home + '/skip.txt' } })).toBe('ENOENT');
    expect((await execLocal(page, ['touch', '--', '-h'], { cwd: f.home })).status).toBe(0);
    expect(await pageErrno(page, { stat: { path: f.home + '/-h' } })).toBeNull();
    // Its owner may set a file's times to now without write permission, as utimensat(2) has it.
    expect((await execLocal(page, ['chmod', '400', path], { cwd: f.home })).status).toBe(0);
    expect((await execLocal(page, ['touch', path], { cwd: f.home })).status).toBe(0);
    // A directory's times, as GNU touch sets them.
    expect((await execLocal(page, ['touch', f.home], { cwd: f.home })).status).toBe(0);
    // sudo creates root-owned files while keeping the active local account unchanged.
    expect((await execLocal(page, ['touch', f.home + '/root-owned.txt'], { cwd: f.home, sudo: true })).status).toBe(0);
    expect((await pageCall(page, { stat: { path: f.home + '/root-owned.txt' } })).user).toBe('root');
    expect((await pageCall(page, 'getcreds')).user).toBe(f.name);
  } finally {
    await f.cleanup();
  }
});

test('touch integrates with completion, help, preview and editing extensionless files', async ({ page }) => {
  const f = await fixture(page);
  try {
    await run(page, 'sudo -u ' + f.name);
    await expect(page.locator('.cloud-panel-trigger')).toContainText('Local: ' + f.name);
    await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'idle');
    // Completion is asynchronous: pressing Tab before its candidates arrive does nothing, so ask
    // until it completes (the only command beginning "touc" is touch).
    const command = page.locator('#command');
    await command.fill('touc');
    await expect.poll(async () => {
      if (await command.inputValue() !== 'touch ') await page.keyboard.press('Tab');
      return command.inputValue();
    }, { timeout: 15_000, intervals: [250, 500, 1_000] }).toBe('touch ');
    await run(page, 'touch README notes.md');
    await expect.poll(async () => await pageErrno(page, { stat: { path: f.home + '/README' } })).toBeNull();
    // The Files keep a directory of their own: go where the shell made the file.
    await browse(page, f.home);
    await expect(page.locator('.filename').filter({ hasText: /^README$/ })).toBeVisible();
    await run(page, 'vim README');
    await expect(page.locator('.cm-content')).toBeVisible();
    await page.locator('.cm-content').fill('hello terminal');
    await page.keyboard.press('Control+s');
    await expect(page.locator('#editor-status')).toHaveText('Saved');
    await page.keyboard.press('Escape');
    await run(page, 'touch README');
    await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'idle');
    await run(page, 'open README');
    await expect(page.locator('.text-preview')).toHaveText('hello terminal');
    await page.getByRole('button', { name: 'Close preview' }).click();
    await run(page, 'touch -h');
    await expect(page.locator('.transcript pre').last()).toContainText('missing file operand');
    await run(page, 'touch --help');
    await expect(page.locator('.transcript pre').last()).toContainText('Usage: touch');
    await expect(page.locator('.transcript pre').last()).toContainText('--no-dereference');
  } finally {
    await f.cleanup();
  }
});

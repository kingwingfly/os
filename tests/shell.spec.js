import { test, expect } from './test.js';
import {
  execSh,
  pageCall,
  pageErrno,
  pageGetText,
  pageListing,
  pageMkdirp,
  pagePut,
  pageRmrf,
  pageSys,
  promptPath,
  runTerminal,
  sendTerminalLine,
  terminalInput,
  terminalScreen,
  terminalTabs,
  terminalViewport,
  waitForTerminalReady,
} from './ui.js';

let base;

const screen = page => terminalScreen(page);
async function promptSeq(page) {
  return Number((await terminalViewport(page).getAttribute('data-prompt-seq')) || '0');
}
async function waitIdleAfter(page, before, timeout = 30_000) {
  await expect.poll(async () => {
    const vp = terminalViewport(page);
    return (await vp.getAttribute('data-state')) === 'idle'
      && Number((await vp.getAttribute('data-prompt-seq')) || '0') > before;
  }, { timeout }).toBe(true);
}
async function output(page, command) {
  const id = crypto.randomUUID().slice(0, 8);
  const start = `__S_${id}__`, end = `__E_${id}__`;
  await runTerminal(page, `echo ${start}; ${command}; echo ${end}`);
  await expect(screen(page)).toContainText(end, { timeout: 15_000 });
  const raw = '\n' + (await screen(page).innerText());
  const from = raw.lastIndexOf('\n' + start + '\n');
  expect(from, `start marker ${start} missing`).toBeGreaterThanOrEqual(0);
  const bodyStart = from + start.length + 2;
  const to = raw.indexOf(end, bodyStart);
  expect(to, `end marker ${end} missing`).toBeGreaterThanOrEqual(bodyStart);
  return raw.slice(bodyStart, to).replace(/\n$/, '').trim();
}
async function shOutput(page, script) {
  return (await execSh(page, script, { cwd: base })).stdout.trim();
}

async function terminal(page) {
  base = '/home/user/shell-' + Date.now().toString(36);
  await page.goto('/');
  await waitForTerminalReady(page);
  for (const dir of ['', '/docs', '/docs/deep', '/.hidden']) await pageMkdirp(page, base + dir, 0o755);
  const files = {
    'a.md': 'alpha\nbeta\n',
    'docs/b.md': 'one\ntwo\nthree\n',
    'docs/deep/spéctrum notes.md': 'γ\n',
    'docs/c.txt': 'TODO later\ndone\nTODO now\n',
    '.hidden/d.md': 'x\n',
    'x.tmp': ' ',
    'y.tmp': ' ',
  };
  for (const [name, text] of Object.entries(files)) {
    await pagePut(page, base + '/' + name, text, { mode: 0o644 });
  }
  await runTerminal(page, 'cd ' + base);
}
test.afterEach(async ({ page }) => {
  if (base) await pageRmrf(page, base, { sudo: true }).catch(() => {});
});

test('pipes join filters, fd finds what may be listed, and xargs and fd -x run commands on it', async ({ page }) => {
  await terminal(page);
  expect(await output(page, 'echo hello world | wc -c')).toBe('12');
  expect(await output(page, 'ls | grep -i A.md')).toBe('a.md');
  expect(await output(page, 'cat docs/b.md a.md | sort -r | head -n 2')).toBe('two\nthree');
  expect(await output(page, 'grep -c TODO docs/c.txt')).toBe('2');
  expect(await output(page, 'fd -e md | sort')).toBe('a.md\ndocs/b.md\ndocs/deep/spéctrum notes.md');
  expect(await output(page, 'fd -H -e md | wc -l')).toBe('4');
  expect(await output(page, 'fd -t d')).toBe('docs\ndocs/deep');
  expect(await output(page, 'fd -e md -X wc -l')).toContain('6 total');
  // Names with spaces and Unicode survive NUL separation.
  expect(await output(page, 'fd -0 -e md | xargs -0 wc -l')).toContain('1 docs/deep/spéctrum notes.md');
  expect(await output(page, 'fd -e md . docs -x echo {/.}')).toMatch(/^(b\nspéctrum notes|spéctrum notes\nb)$/);
  await runTerminal(page, 'cat x.md missing.md | wc -l | tee count.txt');
  expect((await pageGetText(page, base + '/count.txt')).trim()).toBe('0');
  await runTerminal(page, 'rm count.txt');
  await expect(screen(page)).toContainText('cat: missing.md');
  // Options as getopt reads them: given again, attached, or long; echo has no --.
  expect(await output(page, 'echo -- hi')).toBe('-- hi');
  expect(await output(page, 'grep -e TODO -e done docs/c.txt | wc -l')).toBe('3');
  expect(await output(page, 'echo a b c | xargs -n1 echo')).toBe('a\nb\nc');
  expect(await output(page, 'fd -e md -Hx echo {/} | sort')).toBe('a.md\nb.md\nd.md\nspéctrum notes.md');
  expect(await output(page, 'fd -x echo {} \\; tmp | sort')).toBe('x.tmp\ny.tmp');
  await runTerminal(page, 'rm -rf -f x.tmp');
  await runTerminal(page, 'fd -e tmp | xargs rm');
  await expect.poll(async () => (await pageListing(page, base)).map(e => e.name)).toEqual(['.hidden', 'docs', 'a.md']);
  // xargs with nothing to do still runs once, as GNU xargs does, unless -r.
  expect(await output(page, 'fd -e none | xargs rm')).toContain('rm: missing PATH');
  expect(await output(page, 'fd -e none | xargs -r rm')).not.toContain('missing');
});

test('wildcards expand to sorted paths as bash expands them, and rm -rf * empties a directory', async ({ page }) => {
  const names = async path => (await pageListing(page, base + path)).map(e => e.name).sort();
  await terminal(page);
  // Sorted, relative as typed, without hidden names, in osh and multi-segment POSIX sh.
  expect(await output(page, 'echo *')).toBe('a.md docs x.tmp y.tmp');
  expect(await output(page, 'echo *.tmp ?.md')).toBe('x.tmp y.tmp a.md');
  expect(await shOutput(page, 'echo docs/*/*.md')).toBe('docs/deep/spéctrum notes.md');
  expect(await shOutput(page, 'echo d*/./b.md')).toBe('docs/./b.md');
  expect(await shOutput(page, 'echo docs/*/../b.md')).toBe('docs/deep/../b.md');
  expect(await shOutput(page, 'echo docs/*/..')).toBe('docs/deep/..');
  expect(await shOutput(page, 'echo docs/*/../')).toBe('docs/deep/../');
  expect(await shOutput(page, 'echo */')).toBe('docs/');
  expect(await output(page, 'echo [xy].tmp')).toBe('x.tmp y.tmp');
  expect(await output(page, 'echo .*')).toBe('.hidden');
  expect(await output(page, 'echo ' + base + '/d*')).toBe(base + '/docs');
  // Quoted or escaped wildcards are literal; a pattern that matches nothing stays as typed.
  expect(await output(page, `echo '*' \\*.md "?.md" *.none`)).toBe('* *.md ?.md *.none');
  expect(await output(page, 'cat docs/*.md docs/*.txt | wc -l')).toBe('6');
  // Backslashes read as bash reads them: in double quotes they escape only $ ` " \ and a newline.
  expect(await output(page, String.raw`echo "a\b" 'c\d' e\\f "\$\"\\"`)).toBe('a\\b c\\d e\\f $"\\');
  expect(await output(page, String.raw`grep -c "\w+ now" docs/c.txt`)).toBe('1');
  await runTerminal(page, 'rm *.tmp');
  await expect.poll(() => names('')).toEqual(['.hidden', 'a.md', 'docs']);
  // rm -rf * leaves hidden names, as bash does; in an empty directory it does nothing.
  await runTerminal(page, 'cd docs'); await runTerminal(page, 'rm -rf *');
  await expect.poll(() => names('/docs')).toEqual([]);
  await runTerminal(page, 'rm -rf *');
  await expect(terminalViewport(page)).toHaveAttribute('data-state', 'idle');
  await runTerminal(page, 'cd ..'); await runTerminal(page, 'rm -r *');
  await expect.poll(() => names('')).toEqual(['.hidden']);
});

test('wildcard suffixes use search permission and quoted bracket characters stay literal', async ({ page }) => {
  await terminal(page);
  await runTerminal(page, 'mkdir patterns');
  await runTerminal(page, 'touch patterns/a patterns/b patterns/c patterns/- patterns/! patterns/^');
  expect(await output(page, 'echo patterns/[a"-"c]')).toBe('patterns/- patterns/a patterns/c');
  expect(await output(page, 'echo patterns/["!"a]')).toBe('patterns/! patterns/a');
  expect(await output(page, 'echo patterns/["^"a]')).toBe('patterns/^ patterns/a');
  // A literal suffix needs search permission, not permission to list its parent (root-owned 0711).
  await pageCall(page, { chown: { path: base + '/docs', uid: 0, gid: 0 } }, { sudo: true });
  await pageCall(page, { chmod: { path: base + '/docs', mode: 0o711 } }, { sudo: true });
  expect(await shOutput(page, 'echo d*/b.md')).toBe('docs/b.md');
  expect(await shOutput(page, 'echo d*/./b.md')).toBe('docs/./b.md');
  expect(await shOutput(page, 'echo d*/../a.md')).toBe('docs/../a.md');
  expect(await shOutput(page, 'echo d*/missing.md')).toBe('d*/missing.md');
  expect(await shOutput(page, 'echo d*/*.md')).toBe('d*/*.md');
  expect(await output(page, 'echo docs/../a*')).toBe('docs/../a.md');
  // A [ that closes no set is a name, which search permission finds.
  await pagePut(page, base + '/docs/x[', ' ', { mode: 0o644, sudo: true });
  expect(await shOutput(page, 'echo d*/x[')).toBe('docs/x[');
  await pageCall(page, { chmod: { path: base + '/docs', mode: 0o700 } }, { sudo: true });
  expect(await shOutput(page, 'echo d*/b.md')).toBe('d*/b.md');
  expect(await shOutput(page, 'echo d*/../a.md')).toBe('d*/../a.md');
  // Leaving a directory needs search permission in it, before a pattern as after one.
  expect(await output(page, 'echo docs/../a*')).toBe('docs/../a*');
});

test('mv and cp follow Linux defaults, ask with -i, share content, and refuse what rename would', async ({ page }) => {
  await terminal(page);
  await runTerminal(page, 'cp -r docs copy'); await runTerminal(page, 'mv a.md docs/');
  expect(await output(page, 'fd -t f -e md | sort')).toBe('copy/b.md\ncopy/deep/spéctrum notes.md\ndocs/a.md\ndocs/b.md\ndocs/deep/spéctrum notes.md');
  // Removing the original keeps the copy's content.
  await runTerminal(page, 'rm -r docs/deep');
  expect(await pageGetText(page, base + '/copy/deep/spéctrum notes.md')).toBe('γ\n');
  // An existing file is replaced, unless -n; -i asks.
  await runTerminal(page, 'cp docs/b.md copy/deep/spéctrum\\ notes.md');
  expect(await pageGetText(page, base + '/copy/deep/spéctrum notes.md')).toBe('one\ntwo\nthree\n');
  await runTerminal(page, 'mv -n docs/a.md copy/b.md');
  expect(await pageGetText(page, base + '/copy/b.md')).toBe('one\ntwo\nthree\n');

  await runTerminal(page, 'clear');
  let seq = await promptSeq(page);
  await runTerminal(page, 'mv -i docs/a.md copy/b.md', { wait: false });
  await expect(screen(page)).toContainText("mv: overwrite 'copy/b.md'?", { timeout: 15_000 });
  await sendTerminalLine(page, 'n');
  await waitIdleAfter(page, seq);
  expect(await pageErrno(page, { stat: { path: base + '/docs/a.md' } })).toBe(null);

  await runTerminal(page, 'clear');
  seq = await promptSeq(page);
  await runTerminal(page, 'mv -iv docs/a.md copy/b.md', { wait: false });
  await expect(screen(page)).toContainText("mv: overwrite 'copy/b.md'?", { timeout: 15_000 });
  await sendTerminalLine(page, 'y');
  await waitIdleAfter(page, seq);
  await expect(screen(page)).toContainText("renamed 'docs/a.md' -> 'copy/b.md'");
  expect(await pageGetText(page, base + '/copy/b.md')).toBe('alpha\nbeta\n');

  // Long options, and one given again, are kept for the replacement.
  await runTerminal(page, 'clear');
  seq = await promptSeq(page);
  await runTerminal(page, 'cp -f --interactive docs/b.md copy/b.md', { wait: false });
  await expect(screen(page)).toContainText("cp: overwrite 'copy/b.md'?", { timeout: 15_000 });
  await sendTerminalLine(page, 'y');
  await waitIdleAfter(page, seq);
  expect(await pageGetText(page, base + '/copy/b.md')).toBe('one\ntwo\nthree\n');

  for (const [line, message] of [['mv docs docs/inner', 'subdirectory of itself'], ['cp docs docs-flat', '-r not specified'], ['mv . elsewhere', 'Device or resource busy'], ['cp -r copy copy/again', 'into itself']]) {
    expect(await output(page, line)).toContain(message);
  }
  // Several sources need a directory; each failure is reported while the others proceed.
  expect(await output(page, 'mv docs/b.md copy/deep copy/b.md')).toContain("mv: target 'copy/b.md' is not a directory");
  await runTerminal(page, 'rm copy/b.md nothing.md copy/deep');
  await expect(screen(page)).toContainText("rm: cannot remove 'nothing.md': No such file or directory");
  await expect(screen(page)).toContainText("rm: cannot remove 'copy/deep': Is a directory");
  expect(await pageErrno(page, { stat: { path: base + '/copy/b.md' } })).toBe('ENOENT');
  // A batch of system calls runs each on its own, in order.
  const batch = await pageSys(page, [{ mknod: { path: base + '/n1', mode: 0o666 } }, { unlink: { path: base + '/missing' } }, { mknod: { path: base + '/n2', mode: 0o666 } }]);
  expect(batch).toEqual([{ ok: null }, { err: { errno: 'ENOENT' } }, { ok: null }]);
  expect((await pageListing(page, base)).map(e => e.name)).toEqual(expect.arrayContaining(['n1', 'n2']));
});

test('tabs run at once with their own directory and history, and Ctrl+C stops a tab between steps', async ({ page }) => {
  await terminal(page);
  for (let i = 0; i < 60; i++) await pagePut(page, `${base}/docs/n${i}.dat`, String(i), { mode: 0o644 });
  await runTerminal(page, 'pwd');
  const input = terminalInput(page);
  // A second tab starts where the first is, then goes its own way.
  await input.press('Alt+t');
  await expect(terminalTabs(page)).toHaveCount(2, { timeout: 15_000 });
  await waitForTerminalReady(page);
  await runTerminal(page, 'cd docs');
  await expect(promptPath(page)).toHaveText(base + '/docs');
  // Tab 2 runs a long xargs; tab 1 works meanwhile.
  const seqTab2 = await promptSeq(page);
  await runTerminal(page, 'fd -e dat | xargs -t -n 1 cat', { wait: false });
  await expect(screen(page)).toContainText('cat n', { timeout: 20_000 });
  await input.press('Alt+1');
  await expect(promptPath(page)).toHaveText(base, { timeout: 15_000 });
  expect(await output(page, 'pwd')).toBe(base);
  await runTerminal(page, 'echo TAB1_HISTORY_ITEM');
  await input.press('ArrowUp');
  await expect(screen(page)).toContainText(/\$ echo TAB1_HISTORY_ITEM/);
  await input.press('Control+c');
  await input.press('Alt+2');
  await expect(promptPath(page)).toHaveText(base + '/docs', { timeout: 15_000 });
  await input.press('Control+c');
  await waitIdleAfter(page, seqTab2);
  const ran = ((await screen(page).innerText()).match(/cat n\d+\.dat/g) || []).length;
  expect(ran).toBeGreaterThan(0); expect(ran).toBeLessThan(60);
  await input.press('ArrowUp');
  await expect(screen(page)).toContainText(/\$ fd -e dat \| xargs -t -n 1 cat/);
  await input.press('Control+c');
  // Closing tab 2 keeps tab 1 alive at its own directory.
  await terminalTabs(page).nth(1).locator('.term-tab-close').click();
  await expect(terminalTabs(page)).toHaveCount(1, { timeout: 15_000 });
  await expect(promptPath(page)).toHaveText(base, { timeout: 15_000 });
});

test('cp and mv -i ask as well under sudo, xargs and fd -x, about each file they would replace', async ({ page }) => {
  await terminal(page);
  const read = path => pageGetText(page, base + '/' + path);
  // cp and mv ask, as GNU's do, of the name given.
  const asked = path => `overwrite '${path}'?`;
  const startPrompt = async (cmd, question) => {
    await runTerminal(page, 'clear');
    const seq = await promptSeq(page);
    await runTerminal(page, cmd, { wait: false });
    await expect(screen(page)).toContainText(question, { timeout: 15_000 });
    return seq;
  };

  // xargs and fd -x run each cp -i on its own, which asks: no keeps the file, yes replaces it.
  let seq = await startPrompt('echo a.md | xargs -o -I {} cp -i {} docs/b.md', 'cp: ' + asked('docs/b.md'));
  await sendTerminalLine(page, 'n');
  await waitIdleAfter(page, seq);
  expect(await read('docs/b.md')).toBe('one\ntwo\nthree\n');

  seq = await startPrompt('fd -F c.txt docs -x cp -i {} docs/b.md', 'cp: ' + asked('docs/b.md'));
  await sendTerminalLine(page, 'y');
  await waitIdleAfter(page, seq);
  expect(await read('docs/b.md')).toBe('TODO later\ndone\nTODO now\n');

  // sudo asks too, and replaces as local root (passwordless for wheel user).
  seq = await startPrompt('sudo mv -iv a.md docs/b.md', "mv: overwrite 'docs/b.md'?");
  await sendTerminalLine(page, 'y');
  await waitIdleAfter(page, seq);
  await expect(screen(page)).toContainText("renamed 'a.md' -> 'docs/b.md'");
  expect(await read('docs/b.md')).toBe('alpha\nbeta\n');

  // cp -ri asks about each file below that exists, and copies the others.
  await runTerminal(page, 'cp -r docs copy');
  await pagePut(page, base + '/docs/deep/spéctrum notes.md', 'δ\n', { mode: 0o644, overwrite: true });
  await pagePut(page, base + '/docs/deep/new.md', 'new\n', { mode: 0o644 });
  seq = await startPrompt('cp -ri docs/deep copy', 'cp: ' + asked('copy/deep/spéctrum notes.md'));
  await sendTerminalLine(page, 'y');
  await waitIdleAfter(page, seq);
  expect(await read('copy/deep/spéctrum notes.md')).toBe('δ\n');
  expect(await read('copy/deep/new.md')).toBe('new\n');

  // Ctrl+C at the question replaces nothing.
  seq = await startPrompt('mv -i docs/c.txt docs/b.md', "mv: overwrite 'docs/b.md'?");
  await terminalInput(page).press('Control+c');
  await waitIdleAfter(page, seq);
  expect(await read('docs/b.md')).toBe('alpha\nbeta\n');
  expect(await pageErrno(page, { stat: { path: base + '/docs/c.txt' } })).toBe(null);
});

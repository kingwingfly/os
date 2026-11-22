import { test, expect } from './test.js';
import { pageCall, pageErrno, pageGetText, pageListing, pageMkdirp, pagePut, pageRmrf, pageSys, promptPath } from './ui.js';

let base;

async function terminal(page) {
  base = '/home/user/shell-' + Date.now().toString(36);
  await page.goto('/');
  await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'idle');
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
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  await done(page, 'cd ' + base);
  return input;
}
test.afterEach(async ({ page }) => {
  if (base) await pageRmrf(page, base, { sudo: true }).catch(() => {});
});
async function run(page, text) {
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  const busy = page.locator('#command').locator('xpath=ancestor::form');
  await expect(busy).toHaveAttribute('data-state', 'idle');
  await input.fill(text); await input.press('Enter');
}
// Run `text` to its end, for what is read of it next.
async function done(page, text) {
  await run(page, text);
  await expect(page.locator('#command').locator('xpath=ancestor::form')).toHaveAttribute('data-state', 'idle');
}
const last = page => page.locator('.terminal-panel:not([hidden]) .transcript pre').last();
async function output(page, text) { await run(page, text); await expect(page.locator('#command').locator('xpath=ancestor::form')).toHaveAttribute('data-state', 'idle'); return (await last(page).textContent()).trim(); }

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
  await done(page, 'cat x.md missing.md | wc -l | tee count.txt');
  expect((await pageGetText(page, base + '/count.txt')).trim()).toBe('0');
  await run(page, 'rm count.txt');
  await expect(page.locator('.terminal-panel:not([hidden]) .transcript')).toContainText('cat: missing.md');
  await run(page, 'ls || pwd'); await expect(last(page)).toContainText('not supported');
  // Options as getopt reads them: given again, attached, or long; echo has no --.
  expect(await output(page, 'echo -- hi')).toBe('-- hi');
  expect(await output(page, 'grep -e TODO -e done docs/c.txt | wc -l')).toBe('3');
  expect(await output(page, 'echo a b c | xargs -n1 echo')).toBe('a\nb\nc');
  expect(await output(page, 'fd -e md -Hx echo {/} | sort')).toBe('a.md\nb.md\nd.md\nspéctrum notes.md');
  expect(await output(page, 'fd -x echo {} \\; tmp | sort')).toBe('x.tmp\ny.tmp');
  await run(page, 'rm -rf -f x.tmp');
  await run(page, 'fd -e tmp | xargs rm');
  await expect.poll(async () => (await pageListing(page, base)).map(e => e.name)).toEqual(['.hidden', 'docs', 'a.md']);
  // xargs with nothing to do still runs once, as GNU xargs does, unless -r.
  await run(page, 'fd -e none | xargs rm'); await expect(last(page)).toContainText('rm: missing PATH');
  expect(await output(page, 'fd -e none | xargs -r rm')).not.toContain('missing');
});

test('wildcards expand to sorted paths as bash expands them, and rm -rf * empties a directory', async ({ page }) => {
  const names = async path => (await pageListing(page, base + path)).map(e => e.name).sort();
  await terminal(page);
  // Sorted, relative as typed, without hidden names, in every part of a path.
  expect(await output(page, 'echo *')).toBe('a.md docs x.tmp y.tmp');
  expect(await output(page, 'echo *.tmp ?.md')).toBe('x.tmp y.tmp a.md');
  expect(await output(page, 'echo docs/*/*.md')).toBe('docs/deep/spéctrum notes.md');
  expect(await output(page, 'echo d*/./b.md')).toBe('docs/./b.md');
  expect(await output(page, 'echo docs/*/../b.md')).toBe('docs/deep/../b.md');
  expect(await output(page, 'echo docs/*/..')).toBe('docs/deep/..');
  expect(await output(page, 'echo docs/*/../')).toBe('docs/deep/../');
  expect(await output(page, 'echo */')).toBe('docs/');
  expect(await output(page, 'echo [xy].tmp')).toBe('x.tmp y.tmp');
  expect(await output(page, 'echo .*')).toBe('.hidden');
  expect(await output(page, 'echo ' + base + '/d*')).toBe(base + '/docs');
  // Quoted or escaped wildcards are literal; a pattern that matches nothing stays as typed.
  expect(await output(page, `echo '*' \\*.md "?.md" *.none`)).toBe('* *.md ?.md *.none');
  expect(await output(page, 'cat docs/*.md docs/*.txt | wc -l')).toBe('6');
  // Backslashes read as bash reads them: in double quotes they escape only $ ` " \ and a newline.
  expect(await output(page, String.raw`echo "a\b" 'c\d' e\\f "\$\"\\"`)).toBe('a\\b c\\d e\\f $"\\');
  expect(await output(page, String.raw`grep -c "\w+ now" docs/c.txt`)).toBe('1');
  // Completing a later path keeps an earlier wildcard unquoted, so that it still expands.
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  await input.fill('rm *.tmp do'); await input.press('Tab');
  await expect(input).toHaveValue('rm *.tmp docs/');
  await input.press('Escape');
  await run(page, 'rm *.tmp');
  await expect.poll(() => names('')).toEqual(['.hidden', 'a.md', 'docs']);
  // rm -rf * leaves hidden names, as bash does; in an empty directory it does nothing.
  await run(page, 'cd docs'); await run(page, 'rm -rf *');
  await expect.poll(() => names('/docs')).toEqual([]);
  await run(page, 'rm -rf *');
  await expect(page.locator('#command').locator('xpath=ancestor::form')).toHaveAttribute('data-state', 'idle');
  await expect(last(page)).toHaveClass(/command-echo/);
  await run(page, 'cd ..'); await run(page, 'rm -r *');
  await expect.poll(() => names('')).toEqual(['.hidden']);
});

test('wildcard suffixes use search permission and quoted bracket characters stay literal', async ({ page }) => {
  await terminal(page);
  await done(page, 'mkdir patterns');
  await done(page, 'touch patterns/a patterns/b patterns/c patterns/- patterns/! patterns/^');
  expect(await output(page, 'echo patterns/[a"-"c]')).toBe('patterns/- patterns/a patterns/c');
  expect(await output(page, 'echo patterns/["!"a]')).toBe('patterns/! patterns/a');
  expect(await output(page, 'echo patterns/["^"a]')).toBe('patterns/^ patterns/a');
  // A literal suffix needs search permission, not permission to list its parent (root-owned 0711).
  await pageCall(page, { chown: { path: base + '/docs', uid: 0, gid: 0 } }, { sudo: true });
  await pageCall(page, { chmod: { path: base + '/docs', mode: 0o711 } }, { sudo: true });
  expect(await output(page, 'echo d*/b.md')).toBe('docs/b.md');
  expect(await output(page, 'echo d*/./b.md')).toBe('docs/./b.md');
  expect(await output(page, 'echo d*/../a.md')).toBe('docs/../a.md');
  expect(await output(page, 'echo d*/missing.md')).toBe('d*/missing.md');
  expect(await output(page, 'echo d*/*.md')).toBe('d*/*.md');
  expect(await output(page, 'echo docs/../a*')).toBe('docs/../a.md');
  // A [ that closes no set is a name, which search permission finds.
  await pagePut(page, base + '/docs/x[', ' ', { mode: 0o644, sudo: true });
  expect(await output(page, 'echo d*/x[')).toBe('docs/x[');
  await pageCall(page, { chmod: { path: base + '/docs', mode: 0o700 } }, { sudo: true });
  expect(await output(page, 'echo d*/b.md')).toBe('d*/b.md');
  expect(await output(page, 'echo d*/../a.md')).toBe('d*/../a.md');
  // Leaving a directory needs search permission in it, before a pattern as after one.
  expect(await output(page, 'echo docs/../a*')).toBe('docs/../a*');
});

test('mv and cp follow Linux defaults, ask with -i, share content, and refuse what rename would', async ({ page }) => {
  await terminal(page);
  await done(page, 'cp -r docs copy'); await done(page, 'mv a.md docs/');
  expect(await output(page, 'fd -t f -e md | sort')).toBe('copy/b.md\ncopy/deep/spéctrum notes.md\ndocs/a.md\ndocs/b.md\ndocs/deep/spéctrum notes.md');
  // Removing the original keeps the copy's content.
  await done(page, 'rm -r docs/deep');
  expect(await pageGetText(page, base + '/copy/deep/spéctrum notes.md')).toBe('γ\n');
  // An existing file is replaced, unless -n; -i asks.
  await done(page, 'cp docs/b.md copy/deep/spéctrum\\ notes.md');
  expect(await pageGetText(page, base + '/copy/deep/spéctrum notes.md')).toBe('one\ntwo\nthree\n');
  await done(page, 'mv -n docs/a.md copy/b.md');
  expect(await pageGetText(page, base + '/copy/b.md')).toBe('one\ntwo\nthree\n');
  await run(page, 'mv -i docs/a.md copy/b.md');
  await expect(last(page)).toContainText("mv: overwrite 'copy/b.md'?");
  await expect(page.locator('.terminal-panel:not([hidden]) .command-line')).toHaveAttribute('data-state', 'input');
  await page.locator('#command').fill('n'); await page.locator('#command').press('Enter');
  await expect(page.locator('.terminal-panel:not([hidden]) .command-line')).toHaveAttribute('data-state', 'idle');
  expect(await pageErrno(page, { stat: { path: base + '/docs/a.md' } })).toBe(null);
  await run(page, 'mv -iv docs/a.md copy/b.md'); await expect(page.locator('.terminal-panel:not([hidden]) .command-line')).toHaveAttribute('data-state', 'input');
  await page.locator('#command').fill('y'); await page.locator('#command').press('Enter');
  await expect(last(page)).toContainText("renamed 'docs/a.md' -> 'copy/b.md'");
  expect(await pageGetText(page, base + '/copy/b.md')).toBe('alpha\nbeta\n');
  // Long options, and one given again, are kept for the replacement.
  await run(page, 'cp -f --interactive docs/b.md copy/b.md'); await expect(page.locator('.terminal-panel:not([hidden]) .command-line')).toHaveAttribute('data-state', 'input');
  await page.locator('#command').fill('y'); await page.locator('#command').press('Enter');
  await expect(page.locator('.terminal-panel:not([hidden]) .command-line')).toHaveAttribute('data-state', 'idle');
  expect(await pageGetText(page, base + '/copy/b.md')).toBe('one\ntwo\nthree\n');
  for (const [line, message] of [['mv docs docs/inner', 'subdirectory of itself'], ['cp docs docs-flat', '-r not specified'], ['mv . elsewhere', 'Device or resource busy'], ['cp -r copy copy/again', 'into itself']]) {
    await run(page, line); await expect(last(page)).toContainText(message);
  }
  // Several sources need a directory; each failure is reported while the others proceed.
  await run(page, 'mv docs/b.md copy/deep copy/b.md'); await expect(last(page)).toContainText("mv: target 'copy/b.md' is not a directory");
  await run(page, 'rm copy/b.md nothing.md copy/deep');
  await expect(page.locator('.terminal-panel:not([hidden]) .transcript')).toContainText("rm: cannot remove 'nothing.md': No such file or directory");
  await expect(page.locator('.terminal-panel:not([hidden]) .transcript')).toContainText("rm: cannot remove 'copy/deep': Is a directory");
  expect(await pageErrno(page, { stat: { path: base + '/copy/b.md' } })).toBe('ENOENT');
  // A batch of system calls runs each on its own, in order.
  const batch = await pageSys(page, [{ mknod: { path: base + '/n1', mode: 0o666 } }, { unlink: { path: base + '/missing' } }, { mknod: { path: base + '/n2', mode: 0o666 } }]);
  expect(batch).toEqual([{ ok: null }, { err: { errno: 'ENOENT' } }, { ok: null }]);
  expect((await pageListing(page, base)).map(e => e.name)).toEqual(expect.arrayContaining(['n1', 'n2']));
});

test('tabs run at once with their own directory and history, and Ctrl+C stops a tab between steps', async ({ page }) => {
  const input = await terminal(page);
  for (let i = 0; i < 60; i++) await pagePut(page, `${base}/docs/n${i}.dat`, String(i), { mode: 0o644 });
  await run(page, 'pwd');
  // A second tab starts where the first is, then goes its own way.
  await page.keyboard.press('Alt+t');
  await expect(page.getByRole('tab')).toHaveCount(2);
  await expect(page.locator('#command')).toBeFocused();
  await run(page, 'cd docs');
  await expect(promptPath(page)).toHaveText(base + '/docs');
  // Tab 2 runs a long xargs; tab 1 works meanwhile.
  await run(page, 'fd -e dat | xargs -t -n 1 cat');
  await expect(page.locator('.terminal-panel:not([hidden]) .transcript')).toContainText('cat n');
  await page.keyboard.press('Alt+1');
  await expect(promptPath(page)).toHaveText(base);
  expect(await output(page, 'pwd')).toBe(base);
  await input.press('ArrowUp'); await expect(page.locator('#command')).toHaveValue('pwd');
  await page.keyboard.press('Alt+2');
  await page.locator('#command').press('Control+c');
  await expect(page.locator('.terminal-panel:not([hidden]) .transcript')).toContainText('^C');
  await expect(page.locator('.terminal-panel:not([hidden]) .command-line')).toHaveAttribute('data-state', 'idle');
  const ran = ((await page.locator('.terminal-panel:not([hidden]) .transcript').innerText()).match(/cat n\d+\.dat/g) || []).length;
  expect(ran).toBeGreaterThan(0); expect(ran).toBeLessThan(60);
  await page.locator('#command').press('ArrowUp'); await expect(page.locator('#command')).toHaveValue('fd -e dat | xargs -t -n 1 cat');
  // Tabs survive a reload; closing one keeps the other.
  await page.reload();
  await expect(page.getByRole('tab')).toHaveCount(2);
  await page.getByRole('button', { name: 'Close tab 2' }).click();
  await expect(page.getByRole('tab')).toHaveCount(1);
  await expect(promptPath(page)).toHaveText(base);
});

test('cp and mv -i ask as well under sudo, xargs and fd -x, about each file they would replace', async ({ page }) => {
  await terminal(page);
  const busy = page.locator('.terminal-panel:not([hidden]) .command-line');
  const transcript = page.locator('.terminal-panel:not([hidden]) .transcript');
  const answer = async text => { await expect(busy).toHaveAttribute('data-state', 'input'); await page.locator('#command').fill(text); await page.locator('#command').press('Enter'); };
  const read = path => pageGetText(page, base + '/' + path);
  // cp and mv ask, as GNU's do, of the name given.
  const asked = path => `overwrite '${path}'?`;
  // xargs and fd -x run each cp -i on its own, which asks: no keeps the file, yes replaces it.
  await run(page, 'echo a.md | xargs -o -I {} cp -i {} docs/b.md');
  await expect(transcript).toContainText('cp: ' + asked('docs/b.md'));
  await answer('n'); await expect(busy).toHaveAttribute('data-state', 'idle');
  expect(await read('docs/b.md')).toBe('one\ntwo\nthree\n');
  await run(page, 'fd -F c.txt docs -x cp -i {} docs/b.md');
  await answer('y'); await expect(busy).toHaveAttribute('data-state', 'idle');
  expect(await read('docs/b.md')).toBe('TODO later\ndone\nTODO now\n');
  // sudo asks too, and replaces as local root (passwordless for wheel user).
  await run(page, 'sudo mv -iv a.md docs/b.md');
  await expect(transcript).toContainText("mv: overwrite 'docs/b.md'?");
  await answer('y'); await expect(busy).toHaveAttribute('data-state', 'idle');
  await expect(last(page)).toContainText("renamed 'a.md' -> 'docs/b.md'");
  expect(await read('docs/b.md')).toBe('alpha\nbeta\n');
  // cp -ri asks about each file below that exists, and copies the others.
  await run(page, 'cp -r docs copy'); await expect(busy).toHaveAttribute('data-state', 'idle');
  await pagePut(page, base + '/docs/deep/spéctrum notes.md', 'δ\n', { mode: 0o644, overwrite: true });
  await pagePut(page, base + '/docs/deep/new.md', 'new\n', { mode: 0o644 });
  await run(page, 'cp -ri docs/deep copy');
  await expect(transcript).toContainText('cp: ' + asked('copy/deep/spéctrum notes.md'));
  await answer('y'); await expect(busy).toHaveAttribute('data-state', 'idle');
  expect(await read('copy/deep/spéctrum notes.md')).toBe('δ\n');
  expect(await read('copy/deep/new.md')).toBe('new\n');
  // Ctrl+C at the question replaces nothing.
  await run(page, 'mv -i docs/c.txt docs/b.md');
  await expect(busy).toHaveAttribute('data-state', 'input');
  await page.locator('#command').press('Control+c'); await expect(busy).toHaveAttribute('data-state', 'idle');
  expect(await read('docs/b.md')).toBe('alpha\nbeta\n');
  expect(await pageErrno(page, { stat: { path: base + '/docs/c.txt' } })).toBe(null);
});

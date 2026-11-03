import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { api, entry, listing, mkdirp, program, put, rmrf, sys } from './sys.js';
const origin = process.env.TERMINAL_TEST_URL || 'http://127.0.0.1:8787';
// Each test signs in as its own client, so that it does not use up others' login rate limit.
let headers;
const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const file = path => '/api/file?path=' + encodeURIComponent(path);
const command = (request, args, cwd = '/') => program(request, args, { cwd });
let base;

test.beforeEach(async ({ request, page }) => {
  base = '/shell-' + Date.now().toString(36);
  headers = { Origin: origin, 'CF-Connecting-IP': 'shell-' + base };
  await page.setExtraHTTPHeaders({ 'CF-Connecting-IP': 'shell-ui-' + base });
  expect((await api(request, 'login', { headers, data: { password } })).ok()).toBe(true);
  for (const dir of ['', '/docs', '/docs/deep', '/.hidden']) await mkdirp(request, base + dir);
  const files = { 'a.md': 'alpha\nbeta\n', 'docs/b.md': 'one\ntwo\nthree\n', 'docs/deep/spéctrum notes.md': 'γ\n', 'docs/c.txt': 'TODO later\ndone\nTODO now\n', '.hidden/d.md': 'x\n', 'x.tmp': '', 'y.tmp': '' };
  for (const [name, text] of Object.entries(files)) expect((await put(request, file(base + '/' + name), { headers, data: text || ' ' })).status()).toBe(201);
});
test.afterEach(async ({ request }) => { await rmrf(request, base); });

async function terminal(page) {
  await page.goto('/');
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  await run(page, 'su root');
  await page.getByLabel('Password', { exact: true }).fill(password); await page.locator('#auth button[type=submit]').click();
  await expect(page.locator('#auth')).not.toBeVisible();
  await run(page, 'cd ' + base);
  return input;
}
async function run(page, text) {
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  const busy = page.locator('#command').locator('xpath=ancestor::form').locator('.busy');
  await expect(busy).toHaveText('↵');
  await input.fill(text); await input.press('Enter');
}
// Run `text` to its end, for what is read of it next.
async function done(page, text) {
  await run(page, text);
  await expect(page.locator('#command').locator('xpath=ancestor::form').locator('.busy')).toHaveText('↵');
}
const last = page => page.locator('.terminal-panel:not([hidden]) .transcript pre').last();
async function output(page, text) { await run(page, text); await expect(page.locator('#command').locator('xpath=ancestor::form').locator('.busy')).toHaveText('↵'); return (await last(page).textContent()).trim(); }

test('pipes join filters, fd finds what may be listed, and xargs and fd -x run commands on it', async ({ page, request }) => {
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
  expect(await output(page, 'cat x.md missing.md | wc -l')).toBe('0');
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
  await expect.poll(async () => (await listing(request, base)).map(e => e.name)).toEqual(['.hidden', 'docs', 'a.md']);
  // xargs with nothing to do still runs once, as GNU xargs does, unless -r.
  await run(page, 'fd -e none | xargs rm'); await expect(last(page)).toContainText('rm: missing PATH');
  expect(await output(page, 'fd -e none | xargs -r rm')).not.toContain('missing');
});

test('wildcards expand to sorted paths as bash expands them, and rm -rf * empties a directory', async ({ page, request }) => {
  const names = async path => (await listing(request, base + path)).map(e => e.name).sort();
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
  await expect(input).toHaveValue('rm *.tmp "docs/"');
  await input.press('Escape');
  await run(page, 'rm *.tmp');
  await expect.poll(() => names('')).toEqual(['.hidden', 'a.md', 'docs']);
  // rm -rf * leaves hidden names, as bash does; in an empty directory it does nothing.
  await run(page, 'cd docs'); await run(page, 'rm -rf *');
  await expect.poll(() => names('/docs')).toEqual([]);
  await run(page, 'rm -rf *');
  await expect(page.locator('#command').locator('xpath=ancestor::form').locator('.busy')).toHaveText('↵');
  await expect(last(page)).toHaveClass(/command-echo/);
  await run(page, 'cd ..'); await run(page, 'rm -r *');
  await expect.poll(() => names('')).toEqual(['.hidden']);
});

test('wildcard suffixes use search permission and quoted bracket characters stay literal', async ({ page, request }) => {
  await terminal(page);
  await run(page, 'mkdir patterns');
  await run(page, 'touch patterns/a patterns/b patterns/c patterns/- patterns/! patterns/^');
  expect(await output(page, 'echo patterns/[a"-"c]')).toBe('patterns/- patterns/a patterns/c');
  expect(await output(page, 'echo patterns/["!"a]')).toBe('patterns/! patterns/a');
  expect(await output(page, 'echo patterns/["^"a]')).toBe('patterns/^ patterns/a');
  // A literal suffix needs search permission, not permission to list its parent.
  expect((await command(request, ['chmod', '711', base + '/docs'])).ok()).toBe(true);
  await run(page, 'exit');
  await run(page, 'cd ' + base);
  expect(await output(page, 'echo d*/b.md')).toBe('docs/b.md');
  expect(await output(page, 'echo d*/./b.md')).toBe('docs/./b.md');
  expect(await output(page, 'echo d*/../a.md')).toBe('docs/../a.md');
  expect(await output(page, 'echo d*/missing.md')).toBe('d*/missing.md');
  expect(await output(page, 'echo d*/*.md')).toBe('d*/*.md');
  expect(await output(page, 'echo docs/../a*')).toBe('docs/../a.md');
  // A [ that closes no set is a name, which search permission finds.
  expect((await put(request, file(base + '/docs/x['), { headers, data: ' ' })).status()).toBe(201);
  expect(await output(page, 'echo d*/x[')).toBe('docs/x[');
  expect((await command(request, ['chmod', '700', base + '/docs'])).ok()).toBe(true);
  expect(await output(page, 'echo d*/b.md')).toBe('d*/b.md');
  expect(await output(page, 'echo d*/../a.md')).toBe('d*/../a.md');
  // Leaving a directory needs search permission in it, before a pattern as after one.
  expect(await output(page, 'echo docs/../a*')).toBe('docs/../a*');
});

test('mv and cp follow Linux defaults, ask with -i, share content, and refuse what rename would', async ({ page, request }) => {
  await terminal(page);
  await done(page, 'cp -r docs copy'); await done(page, 'mv a.md docs/');
  expect(await output(page, 'fd -t f -e md | sort')).toBe('copy/b.md\ncopy/deep/spéctrum notes.md\ndocs/a.md\ndocs/b.md\ndocs/deep/spéctrum notes.md');
  // Removing the original keeps the copy's content.
  await done(page, 'rm -r docs/deep');
  expect(await (await request.get(file(base + '/copy/deep/spéctrum notes.md'))).text()).toBe('γ\n');
  // An existing file is replaced, unless -n; -i asks.
  await done(page, 'cp docs/b.md copy/deep/spéctrum\\ notes.md');
  expect(await (await request.get(file(base + '/copy/deep/spéctrum notes.md'))).text()).toBe('one\ntwo\nthree\n');
  await done(page, 'mv -n docs/a.md copy/b.md');
  expect(await (await request.get(file(base + '/copy/b.md'))).text()).toBe('one\ntwo\nthree\n');
  await run(page, 'mv -i docs/a.md copy/b.md');
  await expect(last(page)).toContainText("mv: overwrite 'copy/b.md'?");
  await expect(page.locator('.terminal-panel:not([hidden]) .busy')).toHaveText('Answer ↵');
  await page.locator('#command').fill('n'); await page.locator('#command').press('Enter');
  await expect(page.locator('.terminal-panel:not([hidden]) .busy')).toHaveText('↵');
  expect((await request.head(file(base + '/docs/a.md'))).status()).toBe(200);
  await run(page, 'mv -iv docs/a.md copy/b.md'); await expect(page.locator('.terminal-panel:not([hidden]) .busy')).toHaveText('Answer ↵');
  await page.locator('#command').fill('y'); await page.locator('#command').press('Enter');
  await expect(last(page)).toContainText("renamed 'docs/a.md' -> 'copy/b.md'");
  expect(await (await request.get(file(base + '/copy/b.md'))).text()).toBe('alpha\nbeta\n');
  // Long options, and one given again, are kept for the replacement.
  await run(page, 'cp -f --interactive docs/b.md copy/b.md'); await expect(page.locator('.terminal-panel:not([hidden]) .busy')).toHaveText('Answer ↵');
  await page.locator('#command').fill('y'); await page.locator('#command').press('Enter');
  await expect(page.locator('.terminal-panel:not([hidden]) .busy')).toHaveText('↵');
  expect(await (await request.get(file(base + '/copy/b.md'))).text()).toBe('one\ntwo\nthree\n');
  for (const [line, message] of [['mv docs docs/inner', 'subdirectory of itself'], ['cp docs docs-flat', '-r not specified'], ['mv . elsewhere', 'Device or resource busy'], ['cp -r copy copy/again', 'into itself'], ['mv /root elsewhere', '/root holds the home of root']]) {
    await run(page, line); await expect(last(page)).toContainText(message);
  }
  // Several sources need a directory; each failure is reported while the others proceed.
  await run(page, 'mv docs/b.md copy/deep copy/b.md'); await expect(last(page)).toContainText("mv: target 'copy/b.md' is not a directory");
  await run(page, 'rm copy/b.md nothing.md copy/deep');
  await expect(page.locator('.terminal-panel:not([hidden]) .transcript')).toContainText("rm: cannot remove 'nothing.md': No such file or directory");
  await expect(page.locator('.terminal-panel:not([hidden]) .transcript')).toContainText("rm: cannot remove 'copy/deep': Is a directory");
  expect(await entry(request, base + '/copy/b.md')).toBe(null);
  // A batch of system calls runs each on its own, in order.
  const batch = await sys(request, [{ mknod: { path: base + '/n1', mode: 0o666 } }, { unlink: { path: base + '/missing' } }, { mknod: { path: base + '/n2', mode: 0o666 } }]);
  expect(batch).toEqual([{ ok: null }, { err: { errno: 'ENOENT' } }, { ok: null }]);
  expect((await listing(request, base)).map(e => e.name)).toEqual(expect.arrayContaining(['n1', 'n2']));
});

test('tabs run at once with their own directory and history, and Ctrl+C stops a tab between steps', async ({ page, request }) => {
  for (let i = 0; i < 60; i++) expect((await put(request, file(`${base}/docs/n${i}.dat`), { headers, data: String(i) })).status()).toBe(201);
  const input = await terminal(page);
  await run(page, 'pwd');
  // A second tab starts where the first is, then goes its own way.
  await page.keyboard.press('Alt+t');
  await expect(page.getByRole('tab')).toHaveCount(2);
  await expect(page.locator('#command')).toBeFocused();
  await run(page, 'cd docs');
  await expect(page.locator('label[for=command] .prompt-path')).toHaveText(base + '/docs');
  // Tab 2 runs a long xargs; tab 1 works meanwhile.
  await run(page, 'fd -e dat | xargs -t -n 1 cat');
  await expect(page.locator('.terminal-panel:not([hidden]) .transcript')).toContainText('+ cat');
  await page.keyboard.press('Alt+1');
  await expect(page.locator('label[for=command] .prompt-path')).toHaveText(base);
  expect(await output(page, 'pwd')).toBe(base);
  await input.press('ArrowUp'); await expect(page.locator('#command')).toHaveValue('pwd');
  await page.keyboard.press('Alt+2');
  await page.locator('#command').press('Control+c');
  await expect(page.locator('.terminal-panel:not([hidden]) .transcript')).toContainText('^C');
  await expect(page.locator('.terminal-panel:not([hidden]) .busy')).toHaveText('↵');
  const ran = await page.locator('.terminal-panel:not([hidden]) .transcript pre', { hasText: '+ cat' }).count();
  expect(ran).toBeGreaterThan(0); expect(ran).toBeLessThan(60);
  await page.locator('#command').press('ArrowUp'); await expect(page.locator('#command')).toHaveValue('fd -e dat | xargs -t -n 1 cat');
  // Tabs survive a reload; closing one keeps the other.
  await page.reload();
  await expect(page.getByRole('tab')).toHaveCount(2);
  await page.getByRole('button', { name: 'Close tab 2' }).click();
  await expect(page.getByRole('tab')).toHaveCount(1);
  await expect(page.locator('label[for=command] .prompt-path')).toHaveText(base);
});

test('cp and mv -i ask as well under sudo, xargs and fd -x, about each file they would replace', async ({ page, request }) => {
  await terminal(page);
  const busy = page.locator('.terminal-panel:not([hidden]) .busy');
  const transcript = page.locator('.terminal-panel:not([hidden]) .transcript');
  const answer = async text => { await expect(busy).toHaveText('Answer ↵'); await page.locator('#command').fill(text); await page.locator('#command').press('Enter'); };
  const read = async path => (await request.get(file(base + '/' + path), { headers })).text();
  // cp and mv ask, as GNU's do, of the name given.
  const asked = path => `overwrite '${path}'?`;
  // xargs and fd -x run each cp -i on its own, which asks: no keeps the file, yes replaces it.
  await run(page, 'echo a.md | xargs -I {} cp -i {} docs/b.md');
  await expect(transcript).toContainText('cp: ' + asked('docs/b.md'));
  await answer('n'); await expect(busy).toHaveText('↵');
  expect(await read('docs/b.md')).toBe('one\ntwo\nthree\n');
  await run(page, 'fd -F c.txt docs -x cp -i {} docs/b.md');
  await answer('y'); await expect(busy).toHaveText('↵');
  expect(await read('docs/b.md')).toBe('TODO later\ndone\nTODO now\n');
  // sudo asks too, and replaces as root.
  await run(page, 'sudo mv -iv a.md docs/b.md');
  await expect(transcript).toContainText("mv: overwrite 'docs/b.md'?");
  await answer('y'); await expect(busy).toHaveText('↵');
  await expect(last(page)).toContainText("renamed 'a.md' -> 'docs/b.md'");
  expect(await read('docs/b.md')).toBe('alpha\nbeta\n');
  // cp -ri asks about each file below that exists, and copies the others.
  await run(page, 'cp -r docs copy'); await expect(busy).toHaveText('↵');
  expect((await put(request, file(base + '/docs/deep/spéctrum notes.md') + '&overwrite=true', { headers, data: 'δ\n' })).ok()).toBe(true);
  expect((await put(request, file(base + '/docs/deep/new.md'), { headers, data: 'new\n' })).status()).toBe(201);
  await run(page, 'cp -ri docs/deep copy');
  await expect(transcript).toContainText('cp: ' + asked('copy/deep/spéctrum notes.md'));
  await answer('y'); await expect(busy).toHaveText('↵');
  expect(await read('copy/deep/spéctrum notes.md')).toBe('δ\n');
  expect(await read('copy/deep/new.md')).toBe('new\n');
  // Ctrl+C at the question replaces nothing.
  await run(page, 'mv -i docs/c.txt docs/b.md');
  await expect(busy).toHaveText('Answer ↵');
  await page.locator('#command').press('Control+c'); await expect(busy).toHaveText('↵');
  expect(await read('docs/b.md')).toBe('alpha\nbeta\n');
  expect((await request.head(file(base + '/docs/c.txt'), { headers })).status()).toBe(200);
});

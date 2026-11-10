// Rebuild the installed shell from pinned sources, independently of the web/Rust build.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { access, copyFile, cp, mkdir, mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const pkg = join(root, 'packages/dash');
const lock = JSON.parse(await readFile(join(pkg, 'lock.json'), 'utf8'));
const { values } = parseArgs({ options: { 'out-dir': { type: 'string' } } });
const out = resolve(values['out-dir'] || join(root, 'dist'));
const cache = resolve(process.env.OS_BUILD_CACHE || join(homedir(), '.cache/os/build'));
const host = lock.sdk.hosts[`${process.platform}-${process.arch}`];
if (!host) throw new Error('Shell build needs Linux or macOS on x86_64/ARM64 (use a Linux build container on Windows)');
await mkdir(cache, { recursive: true });
const exists = path => access(path).then(() => true, () => false);
async function digest(path) {
  const hash = createHash('sha256');
  for await (const bytes of createReadStream(path)) hash.update(bytes);
  return hash.digest('hex');
}
async function archive(input) {
  const path = join(cache, input.sha256 + '.tar.gz');
  if (!(await exists(path))) {
    const temporary = path + '.' + process.pid;
    try {
      console.log('Downloading ' + input.url);
      const response = await fetch(input.url);
      if (!response.ok) throw new Error(`Download failed: ${response.status} ${input.url}`);
      await pipeline(Readable.fromWeb(response.body), createWriteStream(temporary, { flags: 'wx' }));
      if (await digest(temporary) !== input.sha256) throw new Error('SHA-256 mismatch: ' + input.url);
      await rename(temporary, path);
    } finally { await rm(temporary, { force: true }); }
  }
  if (await digest(path) !== input.sha256) throw new Error('Corrupt build cache archive: ' + path);
  return path;
}
const env = { ...process.env, LC_ALL: 'C', TZ: 'UTC', SOURCE_DATE_EPOCH: '1683676800' };
const run = (program, args, cwd) => execFileSync(program, args, { cwd, env, stdio: 'inherit' });
async function toolchain(input, archivePath) {
  const destination = join(cache, input.sha256);
  if (!(await exists(join(destination, '.complete')))) {
    const temporary = await mkdtemp(join(cache, 'extract-'));
    try {
      run('tar', ['-xzf', archivePath, '-C', temporary]);
      await writeFile(join(temporary, '.complete'), input.sha256);
      try { await rename(temporary, destination); }
      catch (error) { if (!(await exists(join(destination, '.complete')))) throw error; }
    } finally { await rm(temporary, { recursive: true, force: true }); }
  }
  return join(destination, input.directory);
}
const sdkInput = { ...host, url: lock.sdk.urlPrefix + host.name + '.tar.gz', directory: host.name };
const downloads = await Promise.allSettled([archive(lock.source), archive(lock.sysroot), archive(sdkInput)]);
for (const result of downloads) if (result.status === 'rejected') throw result.reason;
const [sourceArchive, sysrootArchive, sdkArchive] = downloads.map(result => result.value);
const sysroot = await toolchain(lock.sysroot, sysrootArchive);
const sdk = await toolchain(sdkInput, sdkArchive);
const work = await mkdtemp(join(cache, 'dash-'));
try {
  run('tar', ['-xzf', sourceArchive, '-C', work]);
  const source = join(work, lock.source.directory), src = join(source, 'src');
  // Keep upstream generated config/parser files; regenerate tokens with the source's recipe.
  env.TMPDIR = work;
  run('sh', ['mktokens'], src);
  const flags = ['--target=wasm32-wasi', `--sysroot=${sysroot}`, '-O2', '-include', '../config.h', '-I.',
    '-matomics', '-mbulk-memory', '-mmutable-globals', '-pthread', '-mthread-model', 'posix', '-ftls-model=local-exec',
    '-D_WASI_EMULATED_MMAN', '-D_WASI_EMULATED_SIGNAL', '-D_WASI_EMULATED_PROCESS_CLOCKS',
    '-Wno-incompatible-pointer-types', '-Wno-int-conversion', '-Wno-implicit-function-declaration',
    '-Wno-unused-value', '-Wno-string-plus-int',
    `-ffile-prefix-map=${work}=/build`, `-ffile-prefix-map=${root}=/os`,
    `-ffile-prefix-map=${sysroot}=/sysroot`, `-ffile-prefix-map=${sdk}=/sdk`];
  const clang = join(sdk, 'bin/clang');
  // Replace only the platform signal objects, in a private archive; never mutate
  // the verified toolchain cache. Remaining libc code stays at the pinned release.
  await copyFile(join(sysroot, 'lib/wasm32-wasi/libc.a'), join(work, 'libc.a'));
  run(join(sdk, 'bin/llvm-ar'), ['d', join(work, 'libc.a'), 'sigaction.o', 'signal.o', 'sigprocmask.o', 'pthread_sigmask.o', 'sigpending.o', 'sigsuspend.o', 'block.o']);
  // SHELL selects dash's output buffers; standalone libc printf loses redirected output.
  run(clang, [...flags, '-DSHELL', '-c', 'bltin/printf.c', '-o', join(work, 'printf.o')], src);
  const names = 'alias arith_yacc arith_yylex builtins cd error eval exec expand histedit init input jobs mail main memalloc miscbltin mystring nodes output options parser redir show signames syntax system trap var times test'.split(' ');
  const image = join(work, 'dash.wasm');
  // SDK clang otherwise runs whichever wasm-opt happens to be on PATH (including npm's).
  run(clang, [...flags, '--no-wasm-opt', '-L' + work, '-Wl,--shared-memory', '-Wl,--max-memory=4294967296', '-Wl,--import-memory',
    '-Wl,--export-dynamic', '-Wl,--export=__stack_pointer', '-Wl,--export=__heap_base',
    ...names.map(name => name + '.c'), join(work, 'printf.o'), join(pkg, 'platform.c'), join(pkg, 'signals.c'), '-o', image], src);
  await mkdir(join(out, 'usr/bin'), { recursive: true });
  await copyFile(image, join(out, 'usr/bin/dash.wasm'));
  // Distribute the exact source, modifications and recipe beside the binary, plus notices.
  const share = join(out, 'usr/share/dash');
  await mkdir(share, { recursive: true });
  await copyFile(sourceArchive, join(share, 'source.tar.gz'));
  await copyFile(fileURLToPath(import.meta.url), join(share, 'build-shell.mjs'));
  await rm(join(share, 'wait.patch'), { force: true });
  for (const name of ['lock.json', 'platform.c', 'signals.c', 'COPYING', 'GPL-2.0.txt', 'README.md']) {
    await copyFile(join(pkg, name), join(share, name));
  }
  await cp(join(pkg, 'sysroot-notices'), join(share, 'sysroot-notices'), { recursive: true });
  await writeFile(join(share, 'build.json'), JSON.stringify({ sha256: await digest(image), source: lock.source.revision,
    sysroot: lock.sysroot.revision, sdk: lock.sdk.version }, null, 2) + '\n');
  console.log('Shell built: ' + image + ' -> ' + join(out, 'usr/bin/dash.wasm'));
} finally { await rm(work, { recursive: true, force: true }); }

import { test, expect } from './test.js';
import https from 'node:https';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn, execFileSync } from 'node:child_process';
import { createInterface } from 'node:readline';

test('an HTTPS execution worker can use the origin-bound loopback filesystem adapter', async ({ browser, browserName }) => {
  const temp = await mkdtemp(join(tmpdir(), 'os-native-https-'));
  let server, helper, context;
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', temp + '/key', '-out', temp + '/cert', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'], { stdio: 'ignore' });
    const assets = new Map(await Promise.all(['native-mount.js', 'local-mounts.js', 'transform.js', 'asyncify.js', 'memory.js', 'image.js'].map(async name => ['/' + name, await readFile('web/kernel/' + name)])));
    assets.set('/worker.js', Buffer.from(`import { NativeMount } from './native-mount.js';
      onmessage = async ({ data }) => { let provider; try {
        provider = await NativeMount.connect({ ...data, name: 'secure', writable: true });
        await provider.write(provider.grant, 'hello', new TextEncoder().encode('HTTPS_WORKER'), { create: true });
        postMessage({ text: new TextDecoder().decode(await provider.read(provider.grant, 'hello', 0, 128)) });
      } catch (error) { postMessage({ error: error.message }); } finally { if (provider) provider.unmount(provider.grant); } };`));
    server = https.createServer({ key: await readFile(temp + '/key'), cert: await readFile(temp + '/cert') }, (req, res) => {
      const body = assets.get(req.url); res.writeHead(body ? 200 : req.url === '/' ? 200 : 404, { 'Content-Type': body ? 'text/javascript' : 'text/html' }); res.end(body ?? '<title>Secure adapter test</title>');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const origin = 'https://127.0.0.1:' + server.address().port;
    const adapter = process.env.OS_LOCAL_HELPER_BINARY || join(JSON.parse(execFileSync('cargo', ['metadata', '--no-deps', '--format-version=1'], { encoding: 'utf8' })).target_directory, 'debug/os-local-helper');
    await writeFile(temp + '/hello', 'before');
    helper = spawn(adapter, ['--root', temp, '--origin', origin, '--write'], { stdio: ['ignore', 'pipe', 'pipe'] });
    const connection = await new Promise((resolve, reject) => {
      const lines = createInterface({ input: helper.stdout }); const timer = setTimeout(() => reject(new Error('adapter startup timeout')), 5000);
      lines.once('line', line => { clearTimeout(timer); resolve(JSON.parse(line)); }); helper.once('exit', () => { clearTimeout(timer); reject(new Error('adapter exited')); });
    });
    context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();
    if (browserName === 'chromium') {
      // Equivalent to accepting the browser's local-network permission prompt;
      // mixed-content, CORS and origin/proof checks remain enabled.
      await context.grantPermissions(['local-network-access'], { origin });
    }
    await page.goto(origin);
    const result = await page.evaluate(connection => new Promise(resolve => {
      const worker = new Worker('/worker.js', { type: 'module' }); worker.onmessage = ({ data }) => { worker.terminate(); resolve(data); }; worker.onerror = event => resolve({ error: event.message }); worker.postMessage(connection);
    }), connection);
    expect(result).toEqual({ text: 'HTTPS_WORKER' });
    expect(await readFile(temp + '/hello', 'utf8')).toBe('HTTPS_WORKER');
  } finally {
    await context?.close(); helper?.kill('SIGTERM');
    if (helper?.exitCode === null && helper?.signalCode === null) await new Promise(resolve => helper.once('exit', resolve));
    if (server) await new Promise(resolve => server.close(resolve));
    await rm(temp, { recursive: true, force: true });
  }
});

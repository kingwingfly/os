// Delay/fail the same executable in legacy and content-addressed release views.
// Cache the predicate so unroute removes exactly the handler installed by route.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
const matchers = new Map();
export function executableAsset(name) {
  if (!matchers.has(name)) {
    const bytes = readFileSync(new URL(`../dist/usr/bin/${name}.wasm`, import.meta.url));
    const blob = '/boot/blobs/' + createHash('sha256').update(bytes).digest('hex');
    matchers.set(name, url => url.pathname.endsWith(`/usr/bin/${name}.wasm`) || url.pathname === blob);
  }
  return matchers.get(name);
}

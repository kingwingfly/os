// Stateless device reads run only after the authority identifies an opened driver.
// Each read may return a bounded prefix, as a character-device read can on Linux.
export const DEVICE_READ_MAX = 256 * 1024;
export const isByteDevice = name => ['null', 'zero', 'full', 'random', 'urandom'].includes(name);

export function readDevice(name, count, entropy = globalThis.crypto) {
  if (!isByteDevice(name) || !Number.isSafeInteger(count) || count < 0) throw new RangeError('Invalid device read');
  const bytes = new Uint8Array(name === 'null' ? 0 : Math.min(count, DEVICE_READ_MAX));
  if (name === 'random' || name === 'urandom') {
    // Never fill shared WASM memory directly or exceed Web Crypto's 64 KiB quota.
    // Failure propagates to EIO; there is no weaker random-number fallback.
    for (let at = 0; at < bytes.length; at += 65536) entropy.getRandomValues(bytes.subarray(at, at + 65536));
  }
  return bytes;
}

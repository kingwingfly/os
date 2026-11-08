// Add the runtime's state exports without changing the module's instructions or memory
// limits. A start section becomes an explicit initializer: exec calls it, fork does not.
export function prepareImage(bytes, scratch = false) {
  const leb = value => {
    const out = [];
    do { const byte = value & 127; value >>>= 7; out.push(byte | (value ? 128 : 0)); } while (value);
    return out;
  };
  const encoder = new TextEncoder();
  const text = value => { const data = encoder.encode(value); return [...leb(data.length), ...data]; };
  const cursor = data => ({ data, at: 0, u32() {
    let value = 0, shift = 0, byte;
    do { byte = this.data[this.at++]; if (byte == null || shift > 28) throw new Error('invalid wasm integer'); value |= (byte & 127) << shift; shift += 7; } while (byte & 128);
    return value >>> 0;
  }, name() { const length = this.u32(); this.at += length; } });
  const source = cursor(bytes); source.at = 8;
  const sections = [];
  let memories = 0, start;
  while (source.at < bytes.length) {
    const id = bytes[source.at++], length = source.u32();
    const data = bytes.subarray(source.at, source.at + length); source.at += length;
    const c = cursor(data);
    if (id === 2) {
      const count = c.u32();
      for (let i = 0; i < count; i++) {
        c.name(); c.name();
        const kind = data[c.at++];
        if (kind === 0) c.u32();
        else if (kind === 2) { const flags = c.u32(); c.u32(); if (flags & 1) c.u32(); memories++; }
        else throw new Error('process images may import only functions and memory');
      }
    } else if (id === 5) memories += c.u32();
    else if (id === 8) { start = c.u32(); continue; }
    sections.push({ id, data });
  }
  const extra = [];
  if (start != null) extra.push([...text('__tw_initialize'), 0, ...leb(start)]);
  for (let i = 0; i < memories; i++) extra.push([...text(`__tw_memory_${i}`), 2, ...leb(i)]);
  if (scratch) extra.push([...text('__tw_asyncify_memory'), 2, ...leb(memories - 1)]);
  const exports = sections.find(section => section.id === 7);
  if (!exports) throw new Error('process image has no exports');
  const c = cursor(exports.data), count = c.u32();
  const added = extra.flat();
  const prefix = leb(count + extra.length);
  const data = new Uint8Array(prefix.length + exports.data.length - c.at + added.length);
  data.set(prefix); data.set(exports.data.subarray(c.at), prefix.length); data.set(added, data.length - added.length);
  exports.data = data;
  const chunks = [bytes.subarray(0, 8), ...sections.flatMap(({ id, data }) => [Uint8Array.from([id, ...leb(data.length)]), data])];
  const out = new Uint8Array(chunks.reduce((n, chunk) => n + chunk.length, 0));
  let offset = 0;
  for (const chunk of chunks) { out.set(chunk, offset); offset += chunk.length; }
  return out;
}

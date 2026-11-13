import { pinImage } from './local-mounts.js';
const bad = (errno, message = errno) => Object.assign(new Error(message), { errno });
const MAX = 128 * 1024 * 1024;
const hash = async bytes => [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(n => n.toString(16).padStart(2, '0')).join('');

// A package is the ordinary xtask manifest.json + blobs/<sha256> directory. The
// shared Rust image validator supplies the composed tree and resolved symlinks.
export async function privateExtension(sources, validate) {
  const manifests = [], images = [], blobs = new Map(); let total = 0;
  const read = async (source, path, max) => {
    const stat = await source.provider.stat(source.grant, path);
    if (stat.kind !== 'file' || stat.size > max) throw bad('EFBIG', 'private package exceeds its size limit');
    const bytes = new Uint8Array(stat.size);
    for (let offset = 0; offset < bytes.length;) {
      const part = await source.provider.read(source.grant, path, offset, Math.min(1024 * 1024, bytes.length - offset));
      if (!part.length || part.length > bytes.length - offset) throw bad('ESTALE', 'package changed during activation');
      bytes.set(part, offset); offset += part.length;
    }
    return bytes;
  };
  if (!Array.isArray(sources) || sources.length < 1 || sources.length > 16) throw bad('EINVAL');
  for (const source of sources) {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(await read(source, source.prefix + 'manifest.json', 4 * 1024 * 1024));
    manifests.push(text);
  }
  const composition = await validate(manifests);
  for (let i = 0; i < sources.length; i++) {
    const image = JSON.parse(manifests[i]); images.push(image.name);
    for (const entry of image.entries) {
      if (entry.node.type !== 'file' || blobs.has(entry.node.sha256)) continue;
      total += entry.node.size; if (total > MAX) throw bad('EFBIG', 'private package exceeds 128 MiB');
      const bytes = await read(sources[i], sources[i].prefix + 'blobs/' + entry.node.sha256, entry.node.size);
      if (bytes.length !== entry.node.size || await hash(bytes) !== entry.node.sha256) throw bad('EIO', 'private package content digest mismatch');
      blobs.set(entry.node.sha256, bytes);
    }
  }
  return new PrivateExtension(composition, blobs, images);
}

class PrivateExtension {
  #grant; #active = true; #composition; #blobs;
  constructor(composition, blobs, names) {
    this.#composition = composition; this.#blobs = blobs;
    this.#grant = Object.freeze({ kind: 'private-extension', name: names.join(', '), readOnly: true, execute: true });
  }
  get grant() { return this.#grant; }
  check(grant) { if (grant !== this.#grant) throw bad('EACCES'); if (!this.#active) throw bad('ENODEV'); }
  entry(grant, path, follow = true) {
    this.check(grant);
    if (typeof path !== 'string' || /[\0\\]/.test(path) || path.startsWith('/') || path.split('/').includes('..')) throw bad('EACCES');
    const parts = path.split('/').filter(p => p && p !== '.');
    let physical = '';
    for (let i = 0; i < parts.length; i++) {
      physical += '/' + parts[i]; const node = this.#composition.entries[physical];
      if (!node) throw bad('ENOENT');
      if (follow || i < parts.length - 1) physical = this.#composition.resolved[physical];
      if (i < parts.length - 1 && this.#composition.entries[physical].node.type !== 'directory') throw bad('ENOTDIR');
    }
    physical ||= '/';
    return { physical, entry: this.#composition.entries[physical] };
  }
  async stat(grant, path, { follow = true } = {}) {
    const { entry } = this.entry(grant, path, follow);
    return { kind: entry.node.type === 'symlink' ? 'symlink' : entry.node.type, size: entry.node.size ?? 0,
      readOnly: true, executable: !!(entry.mode & 0o111), link: entry.node.target };
  }
  async read(grant, path, offset, length) {
    if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(length) || length < 0 || length > 1024 * 1024) throw bad('EINVAL');
    const { entry } = this.entry(grant, path);
    if (entry.node.type !== 'file') throw bad('EISDIR');
    return this.#blobs.get(entry.node.sha256).slice(offset, offset + length);
  }
  async list(grant, path, { offset = 0, limit = 256 } = {}) {
    const { entry, physical } = this.entry(grant, path);
    if (entry.node.type !== 'directory') throw bad('ENOTDIR');
    const prefix = physical === '/' ? '/' : physical + '/';
    const children = Object.values(this.#composition.entries).filter(e => e.path.startsWith(prefix) && !e.path.slice(prefix.length).includes('/') && e.path !== physical);
    return { entries: children.slice(offset, offset + limit).map(e => ({ name: e.path.slice(prefix.length), kind: e.node.type })), next: offset + limit < children.length ? offset + limit : null };
  }
  async pin(grant, path) {
    const { entry } = this.entry(grant, path);
    if (entry.node.type !== 'file') throw bad('EISDIR');
    if (!(entry.mode & 0o111)) throw bad('EACCES', 'package file is not executable');
    return pinImage(this.#blobs.get(entry.node.sha256), () => this.check(grant));
  }
  unmount(grant) { this.check(grant); this.#active = false; this.#blobs.clear(); }
}

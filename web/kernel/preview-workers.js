// Kernel-hosted lazy preview compute workers (`#64` `L6c-2`).
//
// Runs inside the `client-kernel` Dedicated Worker so the main page has zero preview
// dependencies and the opaque Preview iframe has `connect-src 'none'`.
// Each worker (`preview_pdf`, `preview_archive`, `preview_diagram`, `preview_code_*`)
// starts lazily on first request, enforces a 60s timeout, terminates cleanly on timeout
// or surface cancellation (e.g., closing an expanding archive bomb), and restarts on next use.
import { asset } from '../release.js';

const READY = 'ready';
const TIMEOUT_MS = 60_000;
const MAX_PDF_BYTES = 100_000_000;
const MAX_ARCHIVE_BYTES = 50_000_000;
const MAX_PDF_FRAME_BYTES = 64 * 1024 * 1024;
const PIN_CHUNK = 512 * 1024;

const WORKER_SCRIPTS = {
  pdf: '/preview_pdf_loader.js',
  archive: '/preview_archive_loader.js',
  diagram: '/preview_diagram_loader.js',
  code_web: '/preview_code_web_loader.js',
  code_systems: '/preview_code_systems_loader.js',
  code_apps: '/preview_code_apps_loader.js',
  code_scripts: '/preview_code_scripts_loader.js',
};

const WORKER_LOAD_LABELS = {
  pdf: 'Loading PDF engine…',
  archive: 'Loading archive reader…',
  diagram: 'Loading Mermaid diagram engine…',
  code_web: 'Loading Web syntax engine…',
  code_systems: 'Loading Systems syntax engine…',
  code_apps: 'Loading Apps syntax engine…',
  code_scripts: 'Loading Scripts syntax engine…',
};

let startSeq = 0;
let resetGen = 0;
let activitySeq = 0;
let activityListener = null;
const activeActivities = new Set();
const running = new Map(); // kind -> { worker, start, ready, nextId, pending: Map<id, { resolve, reject, surfaceId }> }
const surfacePdfDocs = new Map(); // surfaceId -> Map<docId, start>
const surfaceCancelGen = new Map(); // surfaceId -> number

export function setPreviewActivityListener(fn) {
  activityListener = typeof fn === 'function' ? fn : null;
}

function setPreviewActivity(id, active, label = null) {
  if (active) activeActivities.add(id);
  else activeActivities.delete(id);
  try { activityListener?.({ id, appId: 'preview', active, label }); } catch {}
}

function isJobCancelled(surfaceId, jobCancelGen, jobResetGen) {
  return resetGen !== jobResetGen || (surfaceCancelGen.get(surfaceId) ?? 0) !== jobCancelGen;
}

function stopWorker(kind, entry, reason) {
  if (running.get(kind) !== entry) return;
  running.delete(kind);
  try { entry.worker.terminate(); } catch {}
  for (const [, p] of entry.pending) {
    try { p.reject(new Error(reason)); } catch {}
  }
  entry.pending.clear();
}

function getOrStartWorker(kind) {
  const existing = running.get(kind);
  if (existing) return existing;
  const script = WORKER_SCRIPTS[kind];
  if (!script) throw new Error(`unknown preview worker: ${kind}`);
  const worker = new Worker(asset(script));
  const pending = new Map();
  let resolveReady, rejectReady;
  const ready = new Promise((resolve, reject) => {
    resolveReady = resolve;
    rejectReady = reject;
  });
  pending.set(0, { resolve: resolveReady, reject: rejectReady, surfaceId: null });
  const entry = {
    kind,
    worker,
    start: ++startSeq,
    ready,
    nextId: 1,
    pending,
  };
  worker.onmessage = event => {
    const data = event.data;
    if (data === READY) {
      const p = entry.pending.get(0);
      if (p) {
        entry.pending.delete(0);
        p.resolve();
      }
      return;
    }
    if (!Array.isArray(data) || typeof data[0] !== 'number') return;
    const [id, ok, value] = data;
    if (id === 0 && !ok) {
      stopWorker(kind, entry, `the preview could not start: ${String(value ?? 'unknown error')}`);
      return;
    }
    const p = entry.pending.get(id);
    if (!p) return;
    entry.pending.delete(id);
    if (ok) p.resolve(value);
    else p.reject(new Error(String(value ?? 'preview failed')));
  };
  worker.onerror = event => {
    event?.preventDefault?.();
    stopWorker(kind, entry, 'the preview failed');
  };
  running.set(kind, entry);
  return entry;
}

async function callWorker(kind, { start = null, surfaceId = null, method, args = [], transfer = [], onReady = null }) {
  let entry;
  if (start != null) {
    const cur = running.get(kind);
    if (!cur || cur.start !== start) {
      throw new Error('the preview restarted: open the file again');
    }
    entry = cur;
  } else {
    entry = getOrStartWorker(kind);
  }
  await entry.ready;
  onReady?.();
  if (running.get(kind) !== entry) {
    throw new Error('the preview restarted: open the file again');
  }
  const id = entry.nextId++;
  let timer = null;
  const promise = new Promise((resolve, reject) => {
    entry.pending.set(id, { resolve, reject, surfaceId });
    timer = setTimeout(() => {
      if (entry.pending.has(id)) {
        stopWorker(kind, entry, 'the preview took too long');
      }
    }, TIMEOUT_MS);
  });
  try {
    entry.worker.postMessage([id, method, ...args], transfer);
    const value = await promise;
    return { value, start: entry.start };
  } finally {
    if (timer != null) clearTimeout(timer);
  }
}

async function readPinnedBytes(kernel, surfaceId, pinId, maxBytes) {
  void surfaceId;
  const chunks = [];
  let total = 0;
  let offset = 0n;
  for (;;) {
    const part = await kernel.gui_read_pinned(BigInt(pinId), offset, PIN_CHUNK);
    const bytes = part instanceof Uint8Array ? part : new Uint8Array(part ?? []);
    if (!bytes.byteLength) break;
    total += bytes.byteLength;
    if (total > maxBytes) {
      throw new Error('The file is too large to preview; use the download button in the top right.');
    }
    chunks.push(bytes);
    offset += BigInt(bytes.byteLength);
  }
  const out = new Uint8Array(total);
  let pos = 0;
  for (const c of chunks) {
    out.set(c, pos);
    pos += c.byteLength;
  }
  return out;
}

export function cancelPreviewJobsForSurface(surfaceId) {
  surfaceCancelGen.set(surfaceId, (surfaceCancelGen.get(surfaceId) ?? 0) + 1);
  const docs = surfacePdfDocs.get(surfaceId);
  if (docs) {
    surfacePdfDocs.delete(surfaceId);
    for (const [docId, start] of docs) {
      void callWorker('pdf', { start, method: 'close', args: [docId] }).catch(() => {});
    }
  }
  // If an archive listing worker is busy for a closing surface (e.g. expanding gzip bomb),
  // terminate it immediately so closing is instant and the next archive starts clean.
  const arc = running.get('archive');
  if (arc) {
    for (const [, p] of arc.pending) {
      if (p.surfaceId === surfaceId) {
        stopWorker('archive', arc, 'cancelled');
        break;
      }
    }
  }
}

export function resetAllPreviewWorkers() {
  resetGen++;
  surfaceCancelGen.clear();
  surfacePdfDocs.clear();
  for (const id of [...activeActivities]) {
    setPreviewActivity(id, false);
  }
  for (const [kind, entry] of [...running.entries()]) {
    stopWorker(kind, entry, 'seat reset');
  }
}

export async function runPreviewJob({ kernel, surfaceId, pinId, kind, portForSurface }) {
  const jobCancelGen = surfaceCancelGen.get(surfaceId) ?? 0;
  const jobResetGen = resetGen;
  let activityId = null;
  const beginActivity = (workerKey, computeLabel) => {
    activityId = `preview:${++activitySeq}`;
    const cold = !running.has(workerKey);
    setPreviewActivity(activityId, true, cold ? (WORKER_LOAD_LABELS[workerKey] || computeLabel) : computeLabel);
    return () => {
      if (activityId && activeActivities.has(activityId)) {
        setPreviewActivity(activityId, true, computeLabel);
      }
    };
  };
  try {
    if (!kind || typeof kind.kind !== 'string') {
      return { kind: 'error', detail: 'invalid preview job' };
    }
    if (kind.kind === 'pdf_open') {
      if (pinId == null) return { kind: 'error', detail: 'missing PDF file descriptor' };
      const onReady = beginActivity('pdf', 'Opening PDF…');
      let bytes;
      try {
        bytes = await readPinnedBytes(kernel, surfaceId, pinId, MAX_PDF_BYTES);
      } finally {
        try { await kernel.gui_release_pinned(BigInt(pinId)); } catch {}
      }
      if (isJobCancelled(surfaceId, jobCancelGen, jobResetGen)) {
        return { kind: 'error', detail: 'cancelled' };
      }
      const { value, start } = await callWorker('pdf', {
        surfaceId,
        method: 'open',
        args: [bytes],
        transfer: [bytes.buffer],
        onReady,
      });
      const docId = Number(value?.[0]);
      const rawSizes = value?.[1];
      if (!Number.isInteger(docId) || !rawSizes) {
        return { kind: 'error', detail: 'no document' };
      }
      if (isJobCancelled(surfaceId, jobCancelGen, jobResetGen)) {
        void callWorker('pdf', { start, method: 'close', args: [docId] }).catch(() => {});
        return { kind: 'error', detail: 'cancelled' };
      }
      const floats = rawSizes instanceof Float64Array ? rawSizes : new Float64Array(rawSizes);
      const pages = [];
      for (let i = 0; i + 1 < floats.length; i += 2) {
        pages.push({
          width_milli: Math.max(1, Math.round(floats[i] * 1000)),
          height_milli: Math.max(1, Math.round(floats[i + 1] * 1000)),
        });
      }
      let docs = surfacePdfDocs.get(surfaceId);
      if (!docs) {
        docs = new Map();
        surfacePdfDocs.set(surfaceId, docs);
      }
      docs.set(docId, start);
      return { kind: 'pdf_opened', doc_id: docId, pages };
    }
    if (kind.kind === 'pdf_render') {
      const docId = Number(kind.doc_id);
      const page = Number(kind.page);
      const width = Math.max(1, Math.min(3840, Number(kind.width) || 1));
      const start = surfacePdfDocs.get(surfaceId)?.get(docId);
      if (start == null) {
        return { kind: 'error', detail: 'the preview restarted: open the file again' };
      }
      const { value } = await callWorker('pdf', {
        start,
        surfaceId,
        method: 'render',
        args: [docId, page, width],
      });
      const w = Number(value?.[0] ?? 0);
      const h = Number(value?.[1] ?? 0);
      const pixels = value?.[2];
      if (!w || !h || !pixels) return { kind: 'error', detail: 'no page' };
      const clamped = pixels instanceof Uint8ClampedArray ? pixels : new Uint8ClampedArray(pixels);
      if (clamped.byteLength !== w * h * 4 || clamped.byteLength > MAX_PDF_FRAME_BYTES) {
        return { kind: 'error', detail: 'invalid PDF bitmap size' };
      }
      const copy = new Uint8ClampedArray(clamped.byteLength);
      copy.set(clamped);
      const port = portForSurface(surfaceId);
      if (port) {
        port.postMessage(
          { type: 'pdf-frame', doc_id: docId, page, width: w, height: h, pixels: copy.buffer },
          [copy.buffer],
        );
      }
      return { kind: 'pdf_rendered', doc_id: docId, page, width: w, height: h };
    }
    if (kind.kind === 'pdf_close') {
      const docId = Number(kind.doc_id);
      const docs = surfacePdfDocs.get(surfaceId);
      const start = docs?.get(docId);
      docs?.delete(docId);
      if (start != null) {
        void callWorker('pdf', { start, method: 'close', args: [docId] }).catch(() => {});
      }
      return { kind: 'pdf_closed' };
    }
    if (kind.kind === 'list_archive') {
      if (pinId == null) return { kind: 'error', detail: 'missing archive file descriptor' };
      const onReady = beginActivity('archive', 'Listing archive…');
      let bytes;
      try {
        bytes = await readPinnedBytes(kernel, surfaceId, pinId, MAX_ARCHIVE_BYTES);
      } finally {
        try { await kernel.gui_release_pinned(BigInt(pinId)); } catch {}
      }
      const { value } = await callWorker('archive', {
        surfaceId,
        method: 'list',
        args: [bytes],
        transfer: [bytes.buffer],
        onReady,
      });
      const rawEntries = Array.isArray(value?.[0]) ? value[0] : [];
      const entries = rawEntries.map(m => ({
        path: String(m?.[0] ?? ''),
        size: Number(m?.[1] ?? 0),
        directory: Boolean(m?.[2]),
      }));
      return { kind: 'archive_listed', entries, more: Boolean(value?.[1]) };
    }
    if (kind.kind === 'diagram') {
      const onReady = beginActivity('diagram', 'Rendering diagram…');
      const { value } = await callWorker('diagram', {
        surfaceId,
        method: 'svg',
        args: [String(kind.source ?? '')],
        onReady,
      });
      if (typeof value !== 'string') return { kind: 'error', detail: 'no SVG' };
      return { kind: 'text', text: value };
    }
    if (kind.kind === 'highlight') {
      const group = String(kind.group ?? '');
      const workerKey = `code_${group}`;
      if (!Object.hasOwn(WORKER_SCRIPTS, workerKey)) {
        return { kind: 'error', detail: `unsupported code language group: ${group}` };
      }
      const lang = String(kind.language ?? '');
      const onReady = beginActivity(workerKey, lang ? `Highlighting ${lang}…` : 'Highlighting code…');
      const { value } = await callWorker(workerKey, {
        surfaceId,
        method: 'highlight',
        args: [lang, String(kind.text ?? '')],
        onReady,
      });
      if (typeof value !== 'string') return { kind: 'error', detail: 'no HTML' };
      return { kind: 'text', text: value };
    }
    return { kind: 'error', detail: `unsupported preview job kind: ${kind.kind}` };
  } catch (err) {
    if (pinId != null) {
      try { await kernel.gui_release_pinned(BigInt(pinId)); } catch {}
    }
    return { kind: 'error', detail: String(err?.message ?? err ?? 'preview failed') };
  } finally {
    if (activityId) setPreviewActivity(activityId, false);
  }
}

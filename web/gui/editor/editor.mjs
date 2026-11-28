import { basicSetup } from 'codemirror';
import { EditorState } from '@codemirror/state';
import { EditorView, keymap } from '@codemirror/view';
import { HighlightStyle, syntaxHighlighting, StreamLanguage } from '@codemirror/language';
import { tags } from '@lezer/highlight';
import { markdown } from '@codemirror/lang-markdown';
import { javascript } from '@codemirror/lang-javascript';
import { rust } from '@codemirror/lang-rust';
import { python } from '@codemirror/lang-python';
import { json } from '@codemirror/lang-json';
import { html } from '@codemirror/lang-html';
import { css } from '@codemirror/lang-css';
import { cpp } from '@codemirror/lang-cpp';
import { yaml } from '@codemirror/legacy-modes/mode/yaml';
import { toml } from '@codemirror/legacy-modes/mode/toml';
import { shell } from '@codemirror/legacy-modes/mode/shell';

const MAX_ASSEMBLED_BYTES = 2_600_000;
const MAX_CHUNKS = 1024;
const MAX_CHUNK_WIRE_BYTES = 4096 - 64;
const MAX_ENCODED_SLICE = MAX_CHUNK_WIRE_BYTES - 120;
const DRAFT_DEBOUNCE_MS = 500;

const $ = id => document.getElementById(id);
const titleEl = $('editor-title');
const dirtyEl = $('editor-dirty');
const statusEl = $('editor-status');
const bodyEl = $('editor-body');
const saveBtn = $('editor-save');
const discardBtn = $('editor-discard');
const downloadBtn = $('editor-download');
const closeBtn = $('editor-close');
const draftBanner = $('editor-draft-banner');
const restoreDraftBtn = $('editor-restore-draft');
const discardDraftBtn = $('editor-discard-draft');
const conflictBar = $('editor-conflict-bar');
const conflictLabel = $('editor-conflict-label');
const reloadBtn = $('editor-reload');
const saveCopyBtn = $('editor-save-copy');
const overwriteBtn = $('editor-overwrite');

const theme = EditorView.theme({
  '&': { color: 'var(--cm-fg)', backgroundColor: 'var(--cm-bg)', height: '100%', fontSize: '15px' },
  '.cm-scroller': { fontFamily: 'inherit', lineHeight: '1.65' },
  '.cm-content': { caretColor: 'var(--cm-caret)', padding: '14px 0' },
  '.cm-cursor, .cm-dropCursor': { borderLeftColor: 'var(--cm-caret)' },
  '&.cm-focused .cm-selectionBackground, .cm-selectionBackground, ::selection': { backgroundColor: 'var(--cm-selection)' },
  '.cm-activeLine': { backgroundColor: 'var(--cm-active-line)' },
  '.cm-activeLineGutter': { backgroundColor: 'var(--cm-active-line)' },
  '.cm-gutters': { backgroundColor: 'var(--cm-gutter-bg)', color: 'var(--cm-gutter-fg)', border: 'none' },
  '.cm-panels': { backgroundColor: 'var(--cm-panel-bg)', color: 'var(--cm-fg)' },
  '.cm-tooltip': { backgroundColor: 'var(--cm-panel-bg)', border: '1px solid var(--cm-tooltip-border)' },
});

const highlight = HighlightStyle.define([
  { tag: [tags.keyword, tags.operator, tags.heading], color: 'var(--cm-kw)' },
  { tag: [tags.string, tags.number, tags.bool], color: 'var(--cm-str)' },
  { tag: [tags.comment, tags.meta], color: 'var(--cm-comment)', fontStyle: 'italic' },
  { tag: [tags.typeName, tags.function(tags.variableName)], color: 'var(--cm-fn)' },
  { tag: tags.link, color: 'var(--cm-link)', textDecoration: 'underline' },
]);

function languageExtension(lang) {
  switch (lang) {
    case 'markdown': return markdown();
    case 'js': return javascript({ typescript: false, jsx: false });
    case 'jsx': return javascript({ typescript: false, jsx: true });
    case 'ts': return javascript({ typescript: true, jsx: false });
    case 'tsx': return javascript({ typescript: true, jsx: true });
    case 'rust': return rust();
    case 'python': return python();
    case 'json': return json();
    case 'html': return html();
    case 'css': return css();
    case 'cpp': return cpp();
    case 'yaml': return StreamLanguage.define(yaml);
    case 'toml': return StreamLanguage.define(toml);
    case 'shell': return StreamLanguage.define(shell);
    default: return [];
  }
}

const utf8 = new TextEncoder();
let outSeq = 0;
const sendQueue = [];
let sendTimer = null;

function flushSendQueue() {
  sendTimer = null;
  while (sendQueue.length > 0) {
    const res = window.gui?.send(sendQueue[0]);
    if (res === 'EAGAIN') {
      sendTimer = setTimeout(flushSendQueue, 10);
      return;
    }
    sendQueue.shift();
  }
}

function enqueueRaw(frameText) {
  sendQueue.push(frameText);
  if (sendTimer === null) flushSendQueue();
}

function splitChunkFrames(seq, payload) {
  if (utf8.encode(payload).byteLength <= MAX_CHUNK_WIRE_BYTES) {
    return [payload];
  }
  const slices = [];
  let start = 0;
  while (start < payload.length) {
    let end = start;
    let encodedLen = 0;
    while (end < payload.length) {
      const cp = payload.codePointAt(end);
      const step = cp > 0xffff ? 2 : 1;
      let charLen;
      if (cp === 0x22 || cp === 0x5c || cp === 0x0a || cp === 0x0d || cp === 0x09 || cp === 0x08 || cp === 0x0c) {
        charLen = 2;
      } else if (cp < 0x20) {
        charLen = 6;
      } else if (cp < 0x80) {
        charLen = 1;
      } else if (cp < 0x800) {
        charLen = 2;
      } else if (cp < 0x10000) {
        charLen = 3;
      } else {
        charLen = 4;
      }
      if (encodedLen + charLen > MAX_ENCODED_SLICE && end > start) break;
      encodedLen += charLen;
      end += step;
    }
    slices.push(payload.slice(start, end));
    start = end;
  }
  const n = slices.length;
  return slices.map((d, i) => JSON.stringify({ t: 'chunk', id: seq, i, n, d }));
}

function send(msg) {
  const payload = JSON.stringify(msg);
  const seq = ++outSeq;
  for (const frameText of splitChunkFrames(seq, payload)) {
    enqueueRaw(frameText);
  }
}

const chunks = new Map();
let chunkBytes = 0;

function resetChunks() {
  chunks.clear();
  chunkBytes = 0;
}

const state = {
  path: '',
  language: 'plain',
  view: null,
  dirty: false,
  saving: false,
  readOnly: false,
  existing: false,
  hasDraft: false,
  conflict: null,
  loadError: null,
  submittedText: null,
  draftTimer: null,
  suppressChange: false,
};

function scheduleDraftSync() {
  if (state.readOnly || !state.view || state.loadError) return;
  if (state.draftTimer !== null) clearTimeout(state.draftTimer);
  state.draftTimer = setTimeout(() => {
    state.draftTimer = null;
    if (!state.view || state.readOnly || !state.dirty) return;
    const content = state.view.state.doc.toString();
    if (utf8.encode(content).byteLength <= 2_000_000) {
      send({ t: 'draft_sync', content });
    }
  }, DRAFT_DEBOUNCE_MS);
}

function updateControls() {
  saveBtn.disabled = state.saving || state.readOnly || !state.view || Boolean(state.loadError);
  downloadBtn.disabled = !state.view || Boolean(state.loadError);
  dirtyEl.textContent = state.dirty ? 'Unsaved' : '';
  draftBanner.hidden = !state.hasDraft || state.readOnly;
  const hasConflict = Boolean(state.conflict);
  conflictBar.hidden = !hasConflict;
  if (hasConflict) {
    if (state.conflict === 'changed_elsewhere') {
      conflictLabel.textContent = 'File changed on disk since opened.';
      reloadBtn.hidden = false;
      overwriteBtn.hidden = false;
    } else if (state.conflict === 'created_elsewhere') {
      conflictLabel.textContent = 'File was created elsewhere.';
      reloadBtn.hidden = false;
      overwriteBtn.hidden = false;
    } else {
      conflictLabel.textContent = 'File was deleted or moved on disk.';
      reloadBtn.hidden = true;
      overwriteBtn.hidden = false;
      overwriteBtn.textContent = 'Recreate file';
    }
    if (state.conflict !== 'deleted_elsewhere') {
      overwriteBtn.textContent = 'Overwrite anyway';
    }
  }
}

function requestSave(opts = {}) {
  if (!state.view || state.saving || (state.readOnly && !opts.saveAsCopy) || state.loadError) return;
  const content = state.view.state.doc.toString();
  if (utf8.encode(content).byteLength > 2_000_000) {
    statusEl.textContent = 'The editor can save up to 2 MB of text. Download your draft first.';
    return;
  }
  state.saving = true;
  state.submittedText = opts.saveAsCopy ? null : content;
  updateControls();
  send({
    t: 'save',
    content,
    force_overwrite: Boolean(opts.forceOverwrite),
    save_as_copy: Boolean(opts.saveAsCopy),
  });
}

function requestClose(force = false) {
  if (state.saving) return;
  send({ t: 'close', force: Boolean(force), dirty: Boolean(state.dirty) });
}

function mountEditorView(docText) {
  state.view?.destroy();
  bodyEl.replaceChildren();
  state.view = new EditorView({
    parent: bodyEl,
    state: EditorState.create({
      doc: docText,
      extensions: [
        basicSetup,
        theme,
        syntaxHighlighting(highlight),
        languageExtension(state.language),
        EditorView.lineWrapping,
        EditorState.readOnly.of(state.readOnly),
        EditorView.editable.of(!state.readOnly),
        EditorView.contentAttributes.of({ 'aria-label': 'File contents' }),
        keymap.of([
          {
            key: 'Mod-s',
            run: view => {
              if (view.composing) return false;
              requestSave();
              return true;
            },
          },
          {
            key: 'Escape',
            run: view => {
              if (view.composing) return false;
              requestClose(false);
              return true;
            },
          },
        ]),
        EditorView.updateListener.of(update => {
          if (!update.docChanged || state.suppressChange) return;
          const wasDirty = state.dirty;
          state.dirty = true;
          updateControls();
          if (!wasDirty) send({ t: 'dirty', dirty: true });
          scheduleDraftSync();
        }),
      ],
    }),
  });
  state.view.focus();
}

function handleMessage(msg) {
  if (!msg || typeof msg.t !== 'string') return;
  if (msg.t === 'init') {
    state.path = msg.path || '';
    state.language = msg.language || 'plain';
    state.readOnly = Boolean(msg.read_only);
    state.existing = Boolean(msg.existing);
    state.dirty = Boolean(msg.dirty);
    state.hasDraft = Boolean(msg.has_draft);
    state.conflict = msg.conflict || null;
    state.loadError = msg.load_error || null;
    state.saving = false;
    titleEl.textContent = state.path;
    statusEl.textContent = msg.status || '';
    discardBtn.hidden = true;
    if (state.loadError) {
      state.view?.destroy();
      state.view = null;
      bodyEl.replaceChildren();
    } else {
      mountEditorView(typeof msg.content === 'string' ? msg.content : '');
    }
    updateControls();
    return;
  }
  if (msg.t === 'status') {
    state.saving = Boolean(msg.saving);
    state.readOnly = Boolean(msg.read_only);
    state.existing = Boolean(msg.existing);
    state.hasDraft = Boolean(msg.has_draft);
    state.conflict = msg.conflict || null;
    if (msg.saved_content_sha256 && state.view && state.submittedText !== null) {
      const current = state.view.state.doc.toString();
      const editedWhileSaving = current !== state.submittedText;
      state.submittedText = null;
      state.dirty = editedWhileSaving;
      statusEl.textContent = editedWhileSaving
        ? 'Submitted content saved; newer edits remain unsaved.'
        : (msg.status || 'Saved');
      if (editedWhileSaving) {
        send({ t: 'dirty', dirty: true });
        scheduleDraftSync();
      }
    } else {
      state.dirty = Boolean(msg.dirty);
      statusEl.textContent = msg.status || '';
    }
    discardBtn.hidden = !msg.show_discard;
    updateControls();
    return;
  }
  if (msg.t === 'replace_content') {
    state.saving = false;
    state.submittedText = null;
    state.readOnly = Boolean(msg.read_only);
    state.existing = Boolean(msg.existing);
    state.dirty = Boolean(msg.dirty);
    state.hasDraft = Boolean(msg.has_draft);
    state.conflict = msg.conflict || null;
    statusEl.textContent = msg.status || '';
    discardBtn.hidden = !msg.show_discard;
    state.suppressChange = true;
    try {
      mountEditorView(typeof msg.content === 'string' ? msg.content : '');
    } finally {
      state.suppressChange = false;
    }
    updateControls();
    return;
  }
  if (msg.t === 'focus') {
    if (state.view && document.hasFocus()) state.view.focus();
  }
}

closeBtn.addEventListener('click', () => requestClose(false));
discardBtn.addEventListener('click', () => requestClose(true));
saveBtn.addEventListener('click', () => requestSave());
downloadBtn.addEventListener('click', () => {
  if (!state.view || state.loadError) return;
  send({ t: 'download', content: state.view.state.doc.toString() });
});
restoreDraftBtn.addEventListener('click', () => send({ t: 'restore_draft' }));
discardDraftBtn.addEventListener('click', () => send({ t: 'discard_draft' }));
reloadBtn.addEventListener('click', () => send({ t: 'reload_from_disk' }));
saveCopyBtn.addEventListener('click', () => requestSave({ saveAsCopy: true }));
overwriteBtn.addEventListener('click', () => requestSave({ forceOverwrite: true }));

window.addEventListener('keydown', e => {
  if (e.isComposing || e.keyCode === 229) return;
  if (e.key === 'Escape') {
    if (state.view?.contentDOM.contains(e.target)) return;
    e.preventDefault();
    requestClose(false);
  } else if ((e.ctrlKey || e.metaKey) && (e.key === 's' || e.key === 'S')) {
    if (state.view?.contentDOM.contains(e.target)) return;
    e.preventDefault();
    requestSave();
  }
});

window.addEventListener('focus', () => {
  if (state.view && document.activeElement === document.body) {
    state.view.focus();
  }
});

window.gui.onmessage = raw => {
  let msg;
  try {
    msg = JSON.parse(raw);
  } catch {
    return;
  }
  if (msg?.t === 'chunk') {
    const { id, i, n, d } = msg;
    if (typeof id !== 'number' || typeof i !== 'number' || typeof n !== 'number' || typeof d !== 'string') return;
    if (n <= 0 || n > MAX_CHUNKS || i < 0 || i >= n) return;
    let bucket = chunks.get(id);
    if (!bucket || bucket.length !== n) {
      resetChunks();
      bucket = new Array(n).fill(null);
      chunks.set(id, bucket);
    }
    if (bucket[i] !== null) return;
    if (chunkBytes + d.length > MAX_ASSEMBLED_BYTES) {
      resetChunks();
      return;
    }
    bucket[i] = d;
    chunkBytes += d.length;
    if (bucket.every(part => typeof part === 'string')) {
      resetChunks();
      try {
        handleMessage(JSON.parse(bucket.join('')));
      } catch {}
    }
    return;
  }
  handleMessage(msg);
};

send({ t: 'ready' });

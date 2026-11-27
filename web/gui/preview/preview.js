(() => {
  'use strict';

  const SLIDE_SIZE = [1280, 720];
  const SLIDES_AHEAD = 2;
  const SWIPE = 50;
  const PDF_PIXELS = 2000;
  const PDF_PRESENT_PIXELS = 3840;
  const PDF_ZOOM_MIN = 0.5;
  const PDF_ZOOM_MAX = 3.0;
  const MATCHES_MAX = 10_000;
  const CHUNK_PAYLOAD_MAX = 3072;
  const SLIDE_THEMES = [
    ['light', 'Light'],
    ['dark', 'Dark'],
    ['sepia', 'Sepia'],
    ['night', 'Night'],
  ];
  const ICON_PATHS = {
    prev: 'M15 6l-6 6 6 6',
    next: 'M9 6l6 6-6 6',
    up: 'M6 15l6-6 6 6',
    down: 'M6 9l6 6 6-6',
    asSlides: 'M3 4h18M4 4v11a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1V4M12 16v4M8 20h8',
    asDoc: 'M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8zM14 3v5h5M9 13h6M9 17h6',
    overview: 'M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z',
    speaker: 'M3 4h18v12H3zM7 20h10M12 16v4M7 8h6M7 11h10',
    present: 'M3 8V6a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-6M3 12a8 8 0 0 1 8 8M3 16a4 4 0 0 1 4 4M3 20h.01',
    mic: 'M12 3a3 3 0 0 0-3 3v6a3 3 0 0 0 6 0V6a3 3 0 0 0-3-3zM5 11a7 7 0 0 0 14 0M12 18v3M8 21h8',
    hand: 'M8 13V5.5a1.5 1.5 0 0 1 3 0V11M11 10.5V4a1.5 1.5 0 0 1 3 0v6.5M14 10V5.5a1.5 1.5 0 0 1 3 0V13M17 9.5a1.5 1.5 0 0 1 3 0V15a7 7 0 0 1-7 7h-1a7 7 0 0 1-5.6-2.8l-3.1-3.6a1.5 1.5 0 0 1 2.3-1.9L8 16',
  };

  const surfaceEl = document.getElementById('viewer-surface');
  const backBtn = document.getElementById('viewer-back');
  const titleEl = document.getElementById('viewer-title');
  const downloadBtn = document.getElementById('download');
  const searchBtn = document.getElementById('viewer-search');
  const fullscreenBtn = document.getElementById('fullscreen');
  const closeBtn = document.getElementById('close-viewer');
  const contentEl = document.getElementById('viewer-content');
  const fsErrorEl = document.getElementById('fullscreen-error');

  // --- Chunked GUI document transport ---
  const utf8Enc = new TextEncoder();
  const utf8Dec = new TextDecoder();
  let sendSeq = 0;
  const sendQueue = [];
  let sendTimer = null;

  function pumpSend() {
    sendTimer = null;
    while (sendQueue.length) {
      const next = sendQueue[0];
      const err = window.gui.send(next);
      if (err === 'EAGAIN') {
        sendTimer = setTimeout(pumpSend, 8);
        return;
      }
      sendQueue.shift();
    }
  }

  function sendRaw(str) {
    sendQueue.push(str);
    if (!sendTimer) pumpSend();
  }

  function sendMsg(obj) {
    const json = JSON.stringify(obj);
    if (utf8Enc.encode(json).length <= 4000) {
      sendRaw(json);
      return;
    }
    const id = ++sendSeq;
    const parts = [];
    let i = 0;
    while (i < json.length) {
      let end = Math.min(json.length, i + 2600);
      if (end < json.length) {
        const code = json.charCodeAt(end - 1);
        if (code >= 0xd800 && code <= 0xdbff) end--;
      }
      while (end > i) {
        const probe = JSON.stringify({ t: 'chunk', id, i: parts.length, n: 9999, d: json.slice(i, end) });
        if (utf8Enc.encode(probe).length <= 4000) break;
        end = Math.max(i + 1, end - 256);
        if (end < json.length) {
          const code = json.charCodeAt(end - 1);
          if (code >= 0xd800 && code <= 0xdbff) end--;
        }
      }
      parts.push(json.slice(i, end));
      i = end;
    }
    for (let idx = 0; idx < parts.length; idx++) {
      sendRaw(JSON.stringify({ t: 'chunk', id, i: idx, n: parts.length, d: parts[idx] }));
    }
  }

  const rxChunks = new Map();
  function receiveText(raw) {
    let parsed;
    try { parsed = JSON.parse(raw); } catch { return; }
    if (parsed && parsed.t === 'chunk') {
      const id = parsed.id;
      const total = parsed.n;
      const idx = parsed.i;
      if (!Number.isInteger(total) || total <= 0 || total > 2048 || !Number.isInteger(idx) || idx < 0 || idx >= total) return;
      let entry = rxChunks.get(id);
      if (!entry) {
        if (rxChunks.size > 8) rxChunks.clear();
        entry = { total, parts: new Array(total), got: 0 };
        rxChunks.set(id, entry);
      }
      if (entry.parts[idx] === undefined) {
        entry.parts[idx] = String(parsed.d ?? '');
        entry.got++;
      }
      if (entry.got === entry.total) {
        rxChunks.delete(id);
        try { handleHostMsg(JSON.parse(entry.parts.join(''))); } catch {}
      }
      return;
    }
    handleHostMsg(parsed);
  }

  // --- Binary Asset & PDF Frame Reception ---
  const activeBlobUrls = new Set();
  const assetStore = new Map(); // assetId -> { chunks: Uint8Array[], total, mime, readyUrl, rangeMeta, waiters: [] }
  const rangeRequests = new Map(); // reqId -> { resolve, reject }
  let nextReqId = 1;

  function revokeAllAssets(keepAssetId = null) {
    const keepUrl = keepAssetId != null ? assetStore.get(keepAssetId)?.readyUrl : null;
    for (const url of activeBlobUrls) {
      if (url === keepUrl) continue;
      try { URL.revokeObjectURL(url); } catch {}
      activeBlobUrls.delete(url);
    }
    for (const key of [...assetStore.keys()]) {
      if (key !== keepAssetId) assetStore.delete(key);
    }
    for (const [, r] of rangeRequests) r.reject(new Error('closed'));
    rangeRequests.clear();
  }

  function bytesToDisplayUrl(bytes, mime) {
    if (mime === 'image/svg+xml') {
      const text = utf8Dec.decode(bytes);
      return 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(text);
    }
    const url = URL.createObjectURL(new Blob([bytes], { type: mime || 'application/octet-stream' }));
    activeBlobUrls.add(url);
    return url;
  }

  function ensureAssetEntry(assetId) {
    let entry = assetStore.get(assetId);
    if (!entry) {
      entry = { chunks: [], total: 0, mime: '', readyUrl: null, rangeMeta: null, waiters: [], error: null };
      assetStore.set(assetId, entry);
    }
    return entry;
  }

  function waitForAssetUrl(assetId, mimeHint) {
    const entry = ensureAssetEntry(assetId);
    if (mimeHint && !entry.mime) entry.mime = mimeHint;
    if (entry.readyUrl) return Promise.resolve({ url: entry.readyUrl, rangeMeta: entry.rangeMeta });
    if (entry.error) return Promise.reject(new Error(entry.error));
    return new Promise((resolve, reject) => {
      entry.waiters.push({ resolve, reject });
    });
  }

  function requestRangeSlice(assetId, offset, length) {
    const reqId = ++nextReqId;
    return new Promise((resolve, reject) => {
      rangeRequests.set(reqId, { resolve, reject });
      const err = window.gui.requestAssetRange(reqId, assetId, offset, length);
      if (err) {
        rangeRequests.delete(reqId);
        reject(new Error(err));
      }
    });
  }

  const pdfFrames = new Map(); // `${doc_id}:${page}` -> { width, height, imageData }
  const pdfFrameWaiters = new Map(); // `${doc_id}:${page}` -> fn[]

  function handleBinaryMsg(msg) {
    if (!msg || typeof msg.type !== 'string') return;
    if (msg.type === 'asset-chunk') {
      const entry = ensureAssetEntry(msg.asset_id);
      if (msg.mime) entry.mime = msg.mime;
      const chunk = new Uint8Array(msg.bytes);
      entry.chunks.push(chunk);
      entry.total += chunk.byteLength;
      return;
    }
    if (msg.type === 'asset-eof') {
      const entry = ensureAssetEntry(msg.asset_id);
      if (msg.mime) entry.mime = msg.mime;
      if (msg.error) {
        entry.error = String(msg.error);
        for (const w of entry.waiters.splice(0)) w.reject(new Error(entry.error));
        return;
      }
      const merged = new Uint8Array(entry.total);
      let off = 0;
      for (const c of entry.chunks) { merged.set(c, off); off += c.byteLength; }
      entry.chunks = [];
      entry.readyUrl = bytesToDisplayUrl(merged, entry.mime);
      for (const w of entry.waiters.splice(0)) w.resolve({ url: entry.readyUrl, rangeMeta: null });
      return;
    }
    if (msg.type === 'asset-ready') {
      const entry = ensureAssetEntry(msg.asset_id);
      entry.mime = msg.mime || entry.mime;
      entry.rangeMeta = { assetId: msg.asset_id, mime: entry.mime, size: Number(msg.size || 0) };
      for (const w of entry.waiters.splice(0)) w.resolve({ url: null, rangeMeta: entry.rangeMeta });
      return;
    }
    if (msg.type === 'asset-range') {
      const waiter = rangeRequests.get(msg.req_id);
      if (!waiter) return;
      rangeRequests.delete(msg.req_id);
      if (msg.error) waiter.reject(new Error(msg.error));
      else waiter.resolve(new Uint8Array(msg.bytes || []));
      return;
    }
    if (msg.type === 'pdf-frame') {
      const key = `${msg.doc_id}:${msg.page}`;
      const imageData = new ImageData(new Uint8ClampedArray(msg.pixels), msg.width, msg.height);
      pdfFrames.set(key, { width: msg.width, height: msg.height, imageData });
      const list = pdfFrameWaiters.get(key);
      if (list) {
        pdfFrameWaiters.delete(key);
        for (const fn of list) fn(imageData);
      }
    }
  }

  // --- Shared UI helpers ---
  function makeSvgIcon(pathD) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('class', 'preview-icon');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '1.5');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    svg.setAttribute('aria-hidden', 'true');
    const p = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    p.setAttribute('d', pathD);
    svg.append(p);
    return svg;
  }

  function fmtSize(bytes) {
    const n = Number(bytes) || 0;
    if (n < 1_000) return `${n} B`;
    if (n < 1_000_000) return `${(n / 1e3).toFixed(1)} KB`;
    if (n < 1_000_000_000) return `${(n / 1e6).toFixed(1)} MB`;
    return `${(n / 1e9).toFixed(1)} GB`;
  }

  function parseSlideNumber(text) {
    const trimmed = String(text || '').trim();
    if (!trimmed) return null;
    const [colStr, rowStr = '1'] = trimmed.split('.');
    if (!/^\d+$/.test(colStr) || !/^\d+$/.test(rowStr)) return null;
    const c = Number(colStr) - 1;
    const r = Number(rowStr) - 1;
    if (c < 0 || r < 0) return null;
    return [c, r];
  }

  // --- Pending async requests ---
  const localImageWaiters = new Map();
  const highlightWaiters = new Map();
  const diagramWaiters = new Map();
  const pdfRenderWaiters = new Map();

  function clearAsyncWaiters() {
    localImageWaiters.clear();
    highlightWaiters.clear();
    diagramWaiters.clear();
    pdfRenderWaiters.clear();
    pdfFrames.clear();
    pdfFrameWaiters.clear();
  }

  // --- Fullscreen & floating chrome ---
  let isFullscreen = false;
  let chromeTimer = null;
  const BARS_SEL = ':is(.viewer-bar, .preview-bar, .slides-bar, .pdf-toolbar)';

  function showChrome() {
    surfaceEl.classList.add('chrome');
    clearTimeout(chromeTimer);
    chromeTimer = setTimeout(() => {
      if (surfaceEl.querySelector(`${BARS_SEL}:hover, ${BARS_SEL}:has(:focus-visible), .live-hands.asked`)) {
        showChrome();
      } else {
        surfaceEl.classList.remove('chrome');
      }
    }, 2000);
  }

  surfaceEl.addEventListener('mousedown', e => {
    if (e.target instanceof Element && e.target.closest('button')) e.preventDefault();
  });
  for (const evType of ['pointermove', 'pointerdown']) {
    surfaceEl.addEventListener(evType, () => { if (isFullscreen) showChrome(); });
  }
  surfaceEl.addEventListener('focusin', e => {
    if (isFullscreen && e.target instanceof Element && e.target.closest(BARS_SEL)) showChrome();
  });

  backBtn.onclick = () => sendMsg({ t: 'back' });
  downloadBtn.onclick = () => sendMsg({ t: 'download' });
  fullscreenBtn.onclick = () => {
    fsErrorEl.hidden = true;
    sendMsg({ t: 'toggle_fullscreen', active: !isFullscreen });
  };
  closeBtn.onclick = () => {
    saveCurrentScrollAndMediaPlace();
    sendMsg({ t: 'close' });
  };

  // --- Active View State ---
  let currentShow = null;
  let currentVersion = 0;
  let currentSlideTheme = 'light';
  let currentNotesSize = 24;
  let currentLiveBar = { path: null, user: null, presented: [], asks: [], voices: [], sound: null, asking: null, note: '' };
  let viewCleanup = null;
  let activeController = null; // { onPdfReady, onPdfError, onArchiveReady, onArchiveError, onPresentUpdate, onAudienceUpdate, onLiveBar, onNotice, onEscape }

  function saveCurrentScrollAndMediaPlace() {
    if (!currentShow || !currentShow.path || currentShow.path === '/') return;
    if (currentShow.view === 'slides' || currentShow.view === 'pdf' || currentShow.view === 'game') return;
    const patch = { scroll: contentEl.scrollTop };
    const media = contentEl.querySelector('video,audio');
    if (media && media.currentTime > 1) patch.time = media.currentTime;
    sendMsg({ t: 'save_place', path: currentShow.path, patch });
  }

  function cleanupView(keepAssetId = null) {
    saveCurrentScrollAndMediaPlace();
    if (viewCleanup) {
      try { viewCleanup(); } catch {}
      viewCleanup = null;
    }
    activeController = null;
    clearSearchHighlights();
    searchBtn.hidden = true;
    searchBtn.onclick = null;
    for (const m of contentEl.querySelectorAll('video,audio')) {
      try { m.pause(); m.removeAttribute('src'); m.load(); } catch {}
    }
    clearAsyncWaiters();
    revokeAllAssets(keepAssetId);
    contentEl.replaceChildren();
    contentEl.classList.remove('viewer-error');
    surfaceEl.classList.remove('slides-view', 'game-view');
    fsErrorEl.hidden = true;
  }

  // --- Enhance DOM (local images, links, Mermaid diagrams, syntax highlighting) ---
  function enhanceContainer(root, version) {
    root.addEventListener('click', e => {
      const link = e.target instanceof Element ? e.target.closest('a[href]') : null;
      if (!link) return;
      const href = link.getAttribute('href') || '';
      if (href.startsWith('/api/file?path=')) {
        e.preventDefault();
        sendMsg({ t: 'follow_link', path: href });
      }
    });
    for (const link of root.querySelectorAll("a[href^='http']")) {
      link.setAttribute('target', '_blank');
      link.setAttribute('rel', 'noopener noreferrer');
    }
    for (const img of root.querySelectorAll('img[data-local-src]')) {
      const srcPath = img.getAttribute('data-local-src');
      if (!srcPath) continue;
      const reqId = ++nextReqId;
      localImageWaiters.set(reqId, {
        resolve: async ({ assetId, mime }) => {
          try {
            const { url } = await waitForAssetUrl(assetId, mime);
            if (version === currentVersion && img.isConnected && url) {
              img.setAttribute('src', url);
            }
          } catch (err) {
            if (img.isConnected) img.setAttribute('data-error', String(err?.message || err));
          }
        },
        reject: err => {
          if (img.isConnected) img.setAttribute('data-error', String(err));
        },
      });
      sendMsg({ t: 'request_local_image', req_id: reqId, path: srcPath });
    }
    for (const code of root.querySelectorAll('pre > code[data-lang]')) {
      const info = code.getAttribute('data-lang') || '';
      const text = code.textContent || '';
      if (!info) continue;
      const reqId = ++nextReqId;
      if (info.toLowerCase() === 'mermaid') {
        diagramWaiters.set(reqId, ({ svg, error }) => {
          if (version !== currentVersion || !code.isConnected) return;
          const pre = code.parentElement;
          if (error || !svg) {
            pre?.setAttribute('data-error', error || 'diagram failed');
            return;
          }
          const img = document.createElement('img');
          img.className = 'diagram';
          img.alt = 'diagram';
          img.src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg);
          pre?.replaceWith(img);
        });
        sendMsg({ t: 'request_diagram', req_id: reqId, source: text });
      } else {
        highlightWaiters.set(reqId, ({ html, error }) => {
          if (version !== currentVersion || !code.isConnected) return;
          if (error) {
            code.parentElement?.setAttribute('data-error', error);
          } else if (typeof html === 'string') {
            code.innerHTML = html;
          }
        });
        sendMsg({ t: 'request_highlight', req_id: reqId, info, text });
      }
    }
  }

  // --- Searchable text view (CSS Custom Highlight API) ---
  function clearSearchHighlights() {
    try {
      globalThis.CSS?.highlights?.delete('preview-search');
      globalThis.CSS?.highlights?.delete('preview-search-current');
    } catch {}
  }

  function applyHighlights(name, ranges) {
    if (!globalThis.CSS?.highlights || !globalThis.Highlight) return false;
    if (!ranges.length) {
      CSS.highlights.delete(name);
      return true;
    }
    const hl = new Highlight();
    for (const r of ranges) hl.add(r);
    CSS.highlights.set(name, hl);
    return true;
  }

  function escapeRegex(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  function buildSearchRegex(text, isRegex, matchCase) {
    const source = isRegex ? text : escapeRegex(text);
    const flags = matchCase ? 'gmu' : 'gmiu';
    try {
      return new RegExp(source, flags);
    } catch (err) {
      let msg = String(err?.message || 'invalid regular expression');
      if (/unterminated group|missing \)/i.test(msg)) msg = 'unclosed group';
      else if (/unterminated character class/i.test(msg)) msg = 'unclosed character class';
      throw new Error(msg);
    }
  }

  function findRanges(root, pattern) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const nodes = [];
    const pieces = [];
    let node;
    while ((node = walker.nextNode())) {
      nodes.push(node);
      pieces.push(node.nodeValue || '');
    }
    const full = pieces.join('');
    const starts = new Array(pieces.length + 1);
    let at = 0;
    for (let i = 0; i < pieces.length; i++) {
      starts[i] = at;
      at += pieces[i].length;
    }
    starts[pieces.length] = at;

    const cursor = () => ({ piece: 0 });
    const locatePos = (c, to, isEnd) => {
      while (c.piece + 1 < pieces.length && (to > starts[c.piece + 1] || (!isEnd && to === starts[c.piece + 1]))) {
        c.piece++;
      }
      return [c.piece, to - starts[c.piece]];
    };
    const sc = cursor();
    const ec = cursor();
    const ranges = [];
    pattern.lastIndex = 0;
    let m;
    while ((m = pattern.exec(full)) !== null) {
      if (m[0].length === 0) {
        pattern.lastIndex = m.index + 1;
        if (pattern.lastIndex > full.length) break;
        continue;
      }
      const [sIdx, sOff] = locatePos(sc, m.index, false);
      const [eIdx, eOff] = locatePos(ec, m.index + m[0].length, true);
      try {
        const range = document.createRange();
        range.setStart(nodes[sIdx], sOff);
        range.setEnd(nodes[eIdx], eOff);
        ranges.push(range);
      } catch {}
      if (ranges.length >= MATCHES_MAX) break;
    }
    return ranges;
  }

  function revealRange(range, scroller) {
    const r = range.getBoundingClientRect();
    const s = scroller.getBoundingClientRect();
    if (r.top < s.top + 70 || r.bottom > s.bottom - 20) scroller.scrollTop += r.top - s.top - s.height / 3;
    if (r.left < s.left || r.right > s.right) scroller.scrollLeft += r.left - s.left - s.width / 3;
  }

  function mountSearchable(childEl) {
    const cleanups = [];
    let isOpen = false;
    let isRegex = true;
    let matchCase = false;
    let ranges = [];
    let currentIdx = 0;

    const panel = document.createElement('div');
    panel.className = 'preview-search';
    panel.setAttribute('role', 'search');
    panel.hidden = true;

    const input = document.createElement('input');
    input.type = 'search';
    input.setAttribute('aria-label', 'Search the preview');
    input.placeholder = 'Regular expression';
    input.spellcheck = false;
    input.autocomplete = 'off';
    input.setAttribute('aria-invalid', 'false');

    const regexBtn = document.createElement('button');
    regexBtn.type = 'button';
    regexBtn.className = 'search-toggle';
    regexBtn.title = 'Regular expression';
    regexBtn.setAttribute('aria-label', 'Regular expression');
    regexBtn.setAttribute('aria-pressed', 'true');
    regexBtn.textContent = '.*';

    const caseBtn = document.createElement('button');
    caseBtn.type = 'button';
    caseBtn.className = 'search-toggle';
    caseBtn.title = 'Match case';
    caseBtn.setAttribute('aria-label', 'Match case');
    caseBtn.setAttribute('aria-pressed', 'false');
    caseBtn.textContent = 'Aa';

    const statusEl = document.createElement('span');
    statusEl.className = 'search-status';
    statusEl.setAttribute('role', 'status');

    const prevBtn = document.createElement('button');
    prevBtn.type = 'button';
    prevBtn.title = 'Previous match · Shift+Enter';
    prevBtn.setAttribute('aria-label', 'Previous match');
    prevBtn.textContent = '↑';

    const nextBtn = document.createElement('button');
    nextBtn.type = 'button';
    nextBtn.title = 'Next match · Enter';
    nextBtn.setAttribute('aria-label', 'Next match');
    nextBtn.textContent = '↓';

    const closeSearchBtn = document.createElement('button');
    closeSearchBtn.type = 'button';
    closeSearchBtn.title = 'Close search · Esc';
    closeSearchBtn.setAttribute('aria-label', 'Close search');
    closeSearchBtn.textContent = '×';

    panel.append(input, regexBtn, caseBtn, statusEl, prevBtn, nextBtn, closeSearchBtn);

    const searchable = document.createElement('div');
    searchable.className = 'searchable';
    searchable.append(childEl);

    function showMatches() {
      const cur = ranges[currentIdx] || null;
      const marked = applyHighlights('preview-search', ranges);
      applyHighlights('preview-search-current', cur ? [cur] : []);
      if (!marked) {
        const sel = getSelection();
        sel?.removeAllRanges();
        if (cur) sel?.addRange(cur);
      }
      if (cur) revealRange(cur, contentEl);
      if (ranges.length) {
        statusEl.textContent = `${currentIdx + 1} of ${ranges.length}${ranges.length === MATCHES_MAX ? '+' : ''}`;
      }
    }

    function clearMatches() {
      ranges = [];
      currentIdx = 0;
      clearSearchHighlights();
    }

    function runSearch(keep) {
      const q = input.value;
      if (!q) {
        clearMatches();
        statusEl.textContent = '';
        statusEl.classList.remove('search-error');
        input.setAttribute('aria-invalid', 'false');
        return;
      }
      let pat;
      try {
        pat = buildSearchRegex(q, isRegex, matchCase);
      } catch (err) {
        clearMatches();
        statusEl.textContent = err.message;
        statusEl.classList.add('search-error');
        input.setAttribute('aria-invalid', 'true');
        return;
      }
      statusEl.classList.remove('search-error');
      input.setAttribute('aria-invalid', 'false');
      const found = findRanges(searchable, pat);
      if (!found.length) {
        clearMatches();
        statusEl.textContent = 'No matches';
        return;
      }
      currentIdx = keep ? Math.min(currentIdx, found.length - 1) : 0;
      ranges = found;
      showMatches();
    }

    function step(by) {
      if (!ranges.length) return;
      currentIdx = ((currentIdx + by) % ranges.length + ranges.length) % ranges.length;
      showMatches();
    }

    function openSearch() {
      isOpen = true;
      panel.hidden = false;
      requestAnimationFrame(() => {
        input.focus();
        input.select();
      });
      runSearch(true);
    }

    function closeSearch() {
      isOpen = false;
      panel.hidden = true;
      clearMatches();
      getSelection()?.removeAllRanges();
    }

    input.addEventListener('input', () => { if (isOpen) runSearch(false); });
    input.addEventListener('keydown', e => {
      if (e.key === 'Enter') {
        e.preventDefault();
        step(e.shiftKey ? -1 : 1);
      } else if (e.key === 'Escape') {
        e.preventDefault();
        e.stopPropagation();
        closeSearch();
      }
    });
    regexBtn.onclick = () => {
      isRegex = !isRegex;
      regexBtn.setAttribute('aria-pressed', String(isRegex));
      input.placeholder = isRegex ? 'Regular expression' : 'Text';
      if (isOpen) runSearch(false);
    };
    caseBtn.onclick = () => {
      matchCase = !matchCase;
      caseBtn.setAttribute('aria-pressed', String(matchCase));
      if (isOpen) runSearch(false);
    };
    prevBtn.onclick = () => step(-1);
    nextBtn.onclick = () => step(1);
    closeSearchBtn.onclick = closeSearch;

    let mutFrame = 0;
    const observer = new MutationObserver(() => {
      cancelAnimationFrame(mutFrame);
      mutFrame = requestAnimationFrame(() => { if (isOpen) runSearch(true); });
    });
    observer.observe(searchable, { childList: true, subtree: true, characterData: true });
    cleanups.push(() => { cancelAnimationFrame(mutFrame); observer.disconnect(); });

    searchBtn.hidden = false;
    searchBtn.onclick = openSearch;

    const onKey = e => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'f') {
        e.preventDefault();
        openSearch();
      } else if (e.key === 'F3' && isOpen) {
        e.preventDefault();
        step(e.shiftKey ? -1 : 1);
      }
    };
    window.addEventListener('keydown', onKey);
    cleanups.push(() => window.removeEventListener('keydown', onKey));

    const wrap = document.createDocumentFragment();
    wrap.append(panel, searchable);

    return {
      fragment: wrap,
      handleEscape: () => {
        if (!isOpen) return false;
        closeSearch();
        return true;
      },
      cleanup: () => {
        for (const fn of cleanups) fn();
        clearSearchHighlights();
      },
    };
  }

  // --- Shared Audience Badge & Live Controls ---
  function createAudienceWidget(initialAudience, onResume) {
    let audience = initialAudience ? { ...initialAudience, paused: false, latest: null } : null;
    const slot = document.createElement('span');
    slot.style.display = 'contents';
    let btn = null;
    function render() {
      if (!audience) {
        if (btn) {
          btn.remove();
          btn = null;
        }
        return;
      }
      if (!btn) {
        btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'presentation-badge';
        btn.onclick = () => {
          if (!audience || audience.ended) return;
          audience.paused = false;
          render();
          if (audience.latest) onResume(audience.latest);
        };
        slot.append(btn);
      }
      btn.disabled = Boolean(audience.ended);
      btn.classList.toggle('paused', Boolean(audience.paused));
      btn.textContent = audience.ended
        ? 'The presentation ended'
        : audience.paused
          ? `Follow ${audience.owner}`
          : `Following ${audience.owner}`;
      btn.title = audience.paused
        ? `Back to where ${audience.device} is`
        : `${audience.device}: turn yourself to pause following`;
    }
    render();
    return {
      el: slot,
      isAudience: () => Boolean(audience),
      isEnded: () => Boolean(audience?.ended),
      heard(at) {
        if (!audience) return true;
        audience.latest = at;
        return !audience.paused;
      },
      turned(at) {
        if (!audience) return;
        audience.paused = !(audience.latest && audience.latest[0] === at[0] && audience.latest[1] === at[1]);
        render();
      },
      update(next) {
        if (!next) {
          audience = null;
        } else if (audience && audience.device === next.device) {
          audience.owner = next.owner;
          audience.ended = Boolean(next.ended);
        } else {
          audience = { ...next, paused: false, latest: null };
        }
        render();
      },
    };
  }

  function createLiveControls(path, audienceWidget) {
    const root = document.createElement('span');
    root.className = 'live-controls';
    let menu = null; // 'live' | 'people' | null
    let bar = { ...currentLiveBar };
    let tickTimer = null;

    const onOutside = e => {
      if (menu && !(e.target instanceof Element && e.target.closest('.live-controls'))) {
        menu = null;
        render();
      }
    };
    window.addEventListener('pointerdown', onOutside);

    function clockText(sinceMs) {
      const secs = Math.max(0, Math.floor((Date.now() - sinceMs) / 1000));
      return `${String(Math.floor(secs / 60)).padStart(2, '0')}:${String(secs % 60).padStart(2, '0')}`;
    }

    function render() {
      root.replaceChildren();
      if (tickTimer) { clearInterval(tickTimer); tickTimer = null; }

      if (audienceWidget.isAudience()) {
        root.classList.remove('signed-out');
        const state = bar.asking?.state || null;
        const label = state === 'asking' ? 'Asking to speak · click to withdraw'
          : state === 'connecting' ? 'Starting your microphone'
          : state === 'speaking' ? 'Speaking: everyone following hears you · click to stop'
          : state === 'denied' ? 'Not now, says the presenter'
          : state === 'error' ? (bar.asking?.error || 'Could not speak')
          : 'Ask to speak';
        const askBtn = document.createElement('button');
        askBtn.type = 'button';
        askBtn.className = 'preview-button live-ask';
        if (state === 'asking' || state === 'connecting') askBtn.classList.add('waiting');
        if (state === 'speaking') askBtn.classList.add('on');
        askBtn.setAttribute('aria-label', 'Ask to speak');
        askBtn.setAttribute('aria-pressed', String(state === 'asking' || state === 'connecting' || state === 'speaking'));
        askBtn.title = label;
        askBtn.disabled = audienceWidget.isEnded();
        askBtn.append(makeSvgIcon(ICON_PATHS.hand));
        askBtn.onclick = () => sendMsg({ t: 'ask_to_speak' });
        root.append(askBtn);
        if (state && state !== 'speaking') {
          const note = document.createElement('span');
          note.className = 'live-note';
          note.setAttribute('role', 'status');
          note.textContent = label;
          root.append(note);
        }
        if (bar.note) {
          const note = document.createElement('span');
          note.className = 'live-note';
          note.setAttribute('role', 'status');
          note.textContent = bar.note;
          root.append(note);
        }
        return;
      }

      const signedOut = !bar.user;
      root.classList.toggle('signed-out', signedOut);
      const presentedDev = bar.presented?.[0] || null;
      const sending = bar.sound || null;
      const asks = bar.asks || [];
      const voices = bar.voices || [];
      if (sending && menu === 'live') menu = null;
      if (!asks.length && !voices.length && menu === 'people') menu = null;

      const presBtn = document.createElement('button');
      presBtn.type = 'button';
      presBtn.className = 'preview-button' + (presentedDev ? ' on' : '');
      presBtn.setAttribute('aria-label', 'Present to others');
      presBtn.setAttribute('aria-pressed', String(Boolean(presentedDev)));
      presBtn.title = presentedDev
        ? `Presented as ${presentedDev}: others follow it with open ${presentedDev} · click to stop`
        : 'Present to others: they follow it with open /dev/present/NAME';
      presBtn.append(makeSvgIcon(ICON_PATHS.present));
      presBtn.onclick = () => sendMsg({ t: 'toggle_presenting', path });
      root.append(presBtn);

      if (sending) {
        const stopBtn = document.createElement('button');
        stopBtn.type = 'button';
        stopBtn.className = 'live-on';
        stopBtn.setAttribute('aria-label', 'Stop the live sound');
        let tip = sending.device && sending.recording
          ? `Live as ${sending.device}, recording into ${sending.recording} · click to stop`
          : sending.device ? `Live as ${sending.device} · click to stop`
          : sending.recording ? `Recording into ${sending.recording} · click to stop`
          : 'Starting the microphone · click to stop';
        if (sending.progress) tip += `\n${sending.progress}`;
        stopBtn.title = tip;
        stopBtn.textContent = `● ${clockText(sending.since)}`;
        stopBtn.onclick = () => sendMsg({ t: 'go_live', path, keep: false });
        root.append(stopBtn);
        tickTimer = setInterval(() => {
          stopBtn.textContent = `● ${clockText(sending.since)}`;
        }, 1000);
      } else {
        const goBtn = document.createElement('button');
        goBtn.type = 'button';
        goBtn.className = 'preview-button';
        goBtn.setAttribute('aria-label', 'Go live');
        goBtn.setAttribute('aria-haspopup', 'menu');
        goBtn.setAttribute('aria-expanded', String(menu === 'live'));
        goBtn.title = 'Go live: send your microphone to those following';
        goBtn.append(makeSvgIcon(ICON_PATHS.mic));
        goBtn.onclick = () => { menu = menu === 'live' ? null : 'live'; render(); };
        root.append(goBtn);
      }

      if (menu === 'live' && !sending) {
        const pop = document.createElement('span');
        pop.className = 'live-menu';
        pop.setAttribute('role', 'menu');
        pop.setAttribute('aria-label', 'Go live');
        const liveOnly = document.createElement('button');
        liveOnly.type = 'button';
        liveOnly.setAttribute('role', 'menuitem');
        liveOnly.title = 'Live only: nothing is kept';
        liveOnly.textContent = 'Live';
        liveOnly.onclick = () => { menu = null; render(); sendMsg({ t: 'go_live', path, keep: false }); };
        const liveRec = document.createElement('button');
        liveRec.type = 'button';
        liveRec.setAttribute('role', 'menuitem');
        liveRec.title = 'Live, and recorded beside this file as NAME-DATE-TIME.weba';
        liveRec.textContent = 'Live + record';
        liveRec.onclick = () => { menu = null; render(); sendMsg({ t: 'go_live', path, keep: true }); };
        pop.append(liveOnly, liveRec);
        root.append(pop);
      }

      if (asks.length || voices.length) {
        const handsBtn = document.createElement('button');
        handsBtn.type = 'button';
        handsBtn.className = 'preview-button live-hands' + (asks.length ? ' asked' : '');
        handsBtn.setAttribute('aria-label', `Listeners: ${asks.length} asking to speak, ${voices.length} speaking`);
        handsBtn.setAttribute('aria-haspopup', 'menu');
        handsBtn.setAttribute('aria-expanded', String(menu === 'people'));
        handsBtn.append(makeSvgIcon(ICON_PATHS.hand));
        if (asks.length) {
          const count = document.createElement('span');
          count.className = 'live-count';
          count.textContent = String(asks.length);
          handsBtn.append(count);
        }
        handsBtn.onclick = () => { menu = menu === 'people' ? null : 'people'; render(); };
        root.append(handsBtn);
      }

      if (menu === 'people') {
        const pop = document.createElement('span');
        pop.className = 'live-menu live-people';
        pop.setAttribute('role', 'menu');
        pop.setAttribute('aria-label', 'Listeners');
        for (const ask of asks) {
          const row = document.createElement('span');
          row.className = 'live-person';
          const lbl = document.createElement('span');
          lbl.textContent = `${ask.name} asks to speak`;
          const allowBtn = document.createElement('button');
          allowBtn.type = 'button';
          allowBtn.setAttribute('role', 'menuitem');
          allowBtn.textContent = 'Allow';
          allowBtn.onclick = () => sendMsg({ t: 'answer_ask', id: ask.id, allow: true });
          const dismissBtn = document.createElement('button');
          dismissBtn.type = 'button';
          dismissBtn.setAttribute('role', 'menuitem');
          dismissBtn.textContent = 'Dismiss';
          dismissBtn.onclick = () => sendMsg({ t: 'answer_ask', id: ask.id, allow: false });
          row.append(lbl, allowBtn, dismissBtn);
          pop.append(row);
        }
        for (const voice of voices) {
          const row = document.createElement('span');
          row.className = 'live-person speaking';
          const lbl = document.createElement('span');
          lbl.textContent = `${voice.speaker} speaking`;
          const endBtn = document.createElement('button');
          endBtn.type = 'button';
          endBtn.setAttribute('role', 'menuitem');
          endBtn.textContent = 'End';
          endBtn.onclick = () => sendMsg({ t: 'end_voice', device: voice.device });
          row.append(lbl, endBtn);
          pop.append(row);
        }
        root.append(pop);
      }

      if (bar.note) {
        const note = document.createElement('span');
        note.className = 'live-note';
        note.setAttribute('role', 'status');
        note.textContent = bar.note;
        root.append(note);
      }
    }

    render();
    return {
      el: root,
      update(nextBar) {
        const prevAsks = bar.asks?.length || 0;
        bar = { ...nextBar };
        render();
        if (isFullscreen && ((bar.asks?.length || 0) > prevAsks || bar.asking?.state === 'denied' || bar.asking?.state === 'error')) {
          showChrome();
        }
      },
      cleanup() {
        window.removeEventListener('pointerdown', onOutside);
        if (tickTimer) clearInterval(tickTimer);
      },
    };
  }

  // --- Slides View ---
  function mountSlides(deck, msg, version) {
    const cleanups = [];
    const order = [];
    for (let c = 0; c < deck.length; c++) {
      for (let r = 0; r < deck[c].length; r++) order.push([c, r]);
    }
    const exists = ([c, r]) => c >= 0 && c < deck.length && r >= 0 && r < deck[c].length;
    const indexOf = ([c, r]) => {
      const idx = order.findIndex(([a, b]) => a === c && b === r);
      return idx >= 0 ? idx : 0;
    };
    const slideNumberStr = ([c, r]) => deck[c].length === 1 ? String(c + 1) : `${c + 1}.${r + 1}`;

    let pos = [0, 0];
    const saved = msg.place?.slide;
    if (Array.isArray(saved) && saved.length === 2 && exists([saved[0], saved[1]])) {
      pos = [saved[0], saved[1]];
    }
    if (Array.isArray(msg.last_presented) && exists(msg.last_presented)) {
      pos = [msg.last_presented[0], msg.last_presented[1]];
    }
    const initialPos = [pos[0], pos[1]];
    const mountedAt = Date.now();
    let userTurned = false;

    let speakerOpen = Boolean(msg.speaker_mode);
    let overviewOpen = false;
    let jumping = false;
    let enlargedSrc = null;
    let noticeText = null;
    let noticeTimer = null;
    let themeMenuOpen = false;
    let startedAt = Date.now();

    const slidesEl = document.createElement('div');
    slidesEl.className = 'slides';
    slidesEl.dataset.theme = currentSlideTheme;
    slidesEl.classList.toggle('speaking', speakerOpen);

    const bodyEl = document.createElement('div');
    bodyEl.className = 'slides-body';
    bodyEl.tabIndex = -1;

    function createStage(extraClass) {
      const stage = document.createElement('div');
      stage.className = `slides-stage ${extraClass}`;
      const frames = new Map();
      const ro = new ResizeObserver(entries => {
        for (const entry of entries) {
          const w = entry.contentRect.width;
          const h = entry.contentRect.height;
          const scale = Math.max(0.05, Math.min(w / SLIDE_SIZE[0], h / SLIDE_SIZE[1]));
          stage.style.setProperty('--scale', String(scale));
        }
      });
      ro.observe(stage);
      cleanups.push(() => ro.disconnect());

      function showSlot(target) {
        if (target) {
          const idx = indexOf(target);
          const start = Math.max(0, idx - SLIDES_AHEAD);
          const end = Math.min(order.length, idx + SLIDES_AHEAD + 1);
          for (let i = start; i < end; i++) {
            const slot = order[i];
            const key = `${slot[0]}:${slot[1]}`;
            if (!frames.has(key)) {
              const slide = deck[slot[0]][slot[1]];
              const frame = document.createElement('div');
              frame.className = 'slide-frame';
              const enh = document.createElement('div');
              enh.className = 'enhanced';
              const slideDiv = document.createElement('div');
              slideDiv.className = slide.image_only ? 'slide markdown slide-image' : 'slide markdown';
              slideDiv.innerHTML = slide.html;
              enh.append(slideDiv);
              frame.append(enh);
              stage.append(frame);
              enhanceContainer(enh, version);
              frames.set(key, frame);
            }
          }
        }
        const activeKey = target ? `${target[0]}:${target[1]}` : null;
        for (const [key, frame] of frames) {
          frame.hidden = key !== activeKey;
        }
      }
      return { el: stage, showSlot };
    }

    const mainStage = createStage('slides-current');
    bodyEl.append(mainStage.el);

    // Speaker panel
    const speakerAside = document.createElement('aside');
    speakerAside.className = 'slides-speaker';
    speakerAside.setAttribute('aria-label', 'Speaker view');
    speakerAside.hidden = !speakerOpen;

    const timeRow = document.createElement('div');
    timeRow.className = 'slides-time';
    const elapsedBtn = document.createElement('button');
    elapsedBtn.type = 'button';
    elapsedBtn.className = 'slides-elapsed';
    elapsedBtn.title = 'Restart the timer';
    elapsedBtn.setAttribute('aria-label', 'Restart the timer');
    elapsedBtn.onclick = () => { startedAt = Date.now(); updateClock(); };
    const clockSpan = document.createElement('span');
    clockSpan.className = 'slides-clock';
    timeRow.append(elapsedBtn, clockSpan);

    const upcomingDiv = document.createElement('div');
    upcomingDiv.className = 'slides-upcoming';
    upcomingDiv.setAttribute('aria-label', 'Next slide');
    const nextStage = createStage('slides-next');
    const endP = document.createElement('p');
    endP.className = 'slides-end';
    endP.textContent = 'End of the deck';
    upcomingDiv.append(nextStage.el, endP);

    const notesBar = document.createElement('div');
    notesBar.className = 'slides-notes-bar';
    const notesLabel = document.createElement('span');
    notesLabel.textContent = 'Notes';
    const smallerBtn = document.createElement('button');
    smallerBtn.type = 'button';
    smallerBtn.className = 'preview-button';
    smallerBtn.setAttribute('aria-label', 'Smaller notes');
    smallerBtn.title = 'Smaller notes';
    smallerBtn.textContent = 'A−';
    const largerBtn = document.createElement('button');
    largerBtn.type = 'button';
    largerBtn.className = 'preview-button';
    largerBtn.setAttribute('aria-label', 'Larger notes');
    largerBtn.title = 'Larger notes';
    largerBtn.textContent = 'A+';
    notesBar.append(notesLabel, smallerBtn, largerBtn);

    const notesBox = document.createElement('div');
    notesBox.className = 'slides-notes';
    notesBox.style.fontSize = `${currentNotesSize}px`;
    smallerBtn.onclick = () => {
      currentNotesSize = Math.max(14, Math.min(56, currentNotesSize - 2));
      notesBox.style.fontSize = `${currentNotesSize}px`;
      sendMsg({ t: 'set_pref', notes_size: currentNotesSize });
    };
    largerBtn.onclick = () => {
      currentNotesSize = Math.max(14, Math.min(56, currentNotesSize + 2));
      notesBox.style.fontSize = `${currentNotesSize}px`;
      sendMsg({ t: 'set_pref', notes_size: currentNotesSize });
    };

    speakerAside.append(timeRow, upcomingDiv, notesBar, notesBox);
    bodyEl.append(speakerAside);

    function updateClock() {
      const s = Math.max(0, Math.floor((Date.now() - startedAt) / 1000));
      const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
      elapsedBtn.textContent = h > 0
        ? `${h}:${String(m).padStart(2, '0')}:${String(sec).padStart(2, '0')}`
        : `${String(m).padStart(2, '0')}:${String(sec).padStart(2, '0')}`;
      const d = new Date();
      clockSpan.textContent = `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
    }
    updateClock();
    const clockInt = setInterval(updateClock, 1000);
    cleanups.push(() => clearInterval(clockInt));

    // Overview & Enlarged overlays
    let overviewEl = null;
    let enlargedEl = null;

    function renderOverview() {
      if (overviewEl) { overviewEl.remove(); overviewEl = null; }
      if (!overviewOpen) return;
      overviewEl = document.createElement('div');
      overviewEl.className = 'slides-overview';
      for (const slot of order) {
        const slide = deck[slot[0]][slot[1]];
        const num = slideNumberStr(slot);
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'slides-thumb' + (pos[0] === slot[0] && pos[1] === slot[1] ? ' current' : '');
        btn.setAttribute('aria-label', `Slide ${num}`);
        const div = document.createElement('div');
        div.className = slide.image_only ? 'slide markdown slide-image' : 'slide markdown';
        div.innerHTML = slide.html;
        const badge = document.createElement('span');
        badge.className = 'slides-number';
        badge.textContent = num;
        btn.append(div, badge);
        btn.onclick = () => {
          showSlide(slot, true);
          overviewOpen = false;
          renderOverview();
          updateBar();
        };
        overviewEl.append(btn);
      }
      bodyEl.append(overviewEl);
      enhanceContainer(overviewEl, version);
      requestAnimationFrame(() => {
        overviewEl?.querySelector('.slides-thumb.current')?.scrollIntoView({ block: 'nearest' });
      });
    }

    function renderEnlarged() {
      if (enlargedEl) { enlargedEl.remove(); enlargedEl = null; }
      if (!enlargedSrc) return;
      enlargedEl = document.createElement('div');
      enlargedEl.className = 'slides-enlarged';
      enlargedEl.title = 'Close · Esc';
      const img = document.createElement('img');
      img.src = enlargedSrc;
      img.alt = 'The image, enlarged';
      enlargedEl.append(img);
      enlargedEl.onclick = () => { enlargedSrc = null; renderEnlarged(); };
      bodyEl.append(enlargedEl);
    }

    bodyEl.addEventListener('click', e => {
      const target = e.target instanceof Element ? e.target : null;
      if (!target || target.tagName !== 'IMG') return;
      if (!target.closest('.slides-current') || target.closest('a, .slide-image')) return;
      enlargedSrc = target.getAttribute('src');
      renderEnlarged();
    });

    // Swipe support
    let swipeStart = null;
    bodyEl.addEventListener('pointerdown', e => {
      if (e.pointerType !== 'mouse') swipeStart = [e.clientX, e.clientY];
    });
    bodyEl.addEventListener('pointercancel', () => { swipeStart = null; });
    bodyEl.addEventListener('pointerup', e => {
      if (!swipeStart) return;
      const [sx, sy] = swipeStart;
      swipeStart = null;
      const dx = e.clientX - sx;
      const dy = e.clientY - sy;
      if (!overviewOpen && Math.abs(dx) > SWIPE && Math.abs(dx) > 2 * Math.abs(dy)) {
        stepSlide(dx < 0 ? 1 : -1);
      }
    });

    // Bottom bar
    const barEl = document.createElement('div');
    barEl.className = 'slides-bar';
    const toolsEl = document.createElement('div');
    toolsEl.className = 'slides-tools';

    const overviewBtn = document.createElement('button');
    overviewBtn.type = 'button';
    overviewBtn.className = 'preview-button';
    overviewBtn.title = 'Overview · O';
    overviewBtn.setAttribute('aria-label', 'Overview');
    overviewBtn.setAttribute('aria-pressed', 'false');
    overviewBtn.append(makeSvgIcon(ICON_PATHS.overview));
    overviewBtn.onclick = () => { overviewOpen = !overviewOpen; renderOverview(); updateBar(); };

    const speakerBtn = document.createElement('button');
    speakerBtn.type = 'button';
    speakerBtn.className = 'preview-button';
    speakerBtn.title = 'Speaker view; S opens it in a window';
    speakerBtn.setAttribute('aria-label', 'Speaker view');
    speakerBtn.setAttribute('aria-pressed', String(speakerOpen));
    speakerBtn.append(makeSvgIcon(ICON_PATHS.speaker));
    speakerBtn.onclick = () => {
      speakerOpen = !speakerOpen;
      slidesEl.classList.toggle('speaking', speakerOpen);
      speakerAside.hidden = !speakerOpen;
      speakerBtn.setAttribute('aria-pressed', String(speakerOpen));
      if (speakerOpen) updateSpeakerPanel();
    };

    const audienceWidget = createAudienceWidget(msg.audience, at => {
      if (exists(at)) showSlide(at, false);
    });
    const liveControls = createLiveControls(msg.path, audienceWidget);
    cleanups.push(() => liveControls.cleanup());

    toolsEl.append(overviewBtn, speakerBtn, audienceWidget.el, liveControls.el);

    const hasVertical = deck.some(col => col.length > 1);
    const makeNavBtn = (label, iconKey, extraCls, onClick) => {
      const b = document.createElement('button');
      b.type = 'button';
      b.className = extraCls ? `preview-button ${extraCls}` : 'preview-button';
      b.title = label;
      b.setAttribute('aria-label', label);
      b.append(makeSvgIcon(ICON_PATHS[iconKey]));
      b.onclick = onClick;
      return b;
    };
    const prevBtn = makeNavBtn('Previous slide', 'prev', '', () => goSlide(-1, 0));
    const upBtn = hasVertical ? makeNavBtn('Slide above', 'up', 'slides-vertical', () => goSlide(0, -1)) : null;
    const downBtn = hasVertical ? makeNavBtn('Slide below', 'down', 'slides-vertical', () => goSlide(0, 1)) : null;
    const nextBtn = makeNavBtn('Next slide', 'next', '', () => goSlide(1, 0));

    const counterSlot = document.createElement('span');

    // Accessible Slide Theme combobox (`getByRole('combobox', { name: 'Slide theme' })` + `role="option"`)
    const themeWrap = document.createElement('div');
    themeWrap.className = 'slides-theme-wrap';
    const themeBtn = document.createElement('button');
    themeBtn.type = 'button';
    themeBtn.className = 'slides-theme-btn';
    themeBtn.setAttribute('role', 'combobox');
    themeBtn.setAttribute('aria-label', 'Slide theme');
    themeBtn.setAttribute('aria-haspopup', 'listbox');
    themeBtn.setAttribute('aria-expanded', 'false');
    const themeList = document.createElement('div');
    themeList.className = 'slides-theme-menu';
    themeList.setAttribute('role', 'listbox');
    themeList.setAttribute('aria-label', 'Slide theme');
    themeList.hidden = true;

    function renderThemeControl() {
      const found = SLIDE_THEMES.find(([v]) => v === currentSlideTheme) || SLIDE_THEMES[0];
      themeBtn.textContent = `${found[1]} ▾`;
      themeBtn.setAttribute('aria-expanded', String(themeMenuOpen));
      themeList.hidden = !themeMenuOpen;
      themeList.replaceChildren();
      for (const [val, label] of SLIDE_THEMES) {
        const opt = document.createElement('button');
        opt.type = 'button';
        opt.setAttribute('role', 'option');
        opt.setAttribute('aria-selected', String(val === currentSlideTheme));
        opt.textContent = label;
        opt.onclick = () => {
          currentSlideTheme = val;
          slidesEl.dataset.theme = val;
          themeMenuOpen = false;
          renderThemeControl();
          sendMsg({ t: 'set_pref', slide_theme: val });
        };
        themeList.append(opt);
      }
    }
    themeBtn.onclick = () => { themeMenuOpen = !themeMenuOpen; renderThemeControl(); };
    const closeThemeOutside = e => {
      if (themeMenuOpen && !(e.target instanceof Element && themeWrap.contains(e.target))) {
        themeMenuOpen = false;
        renderThemeControl();
      }
    };
    window.addEventListener('pointerdown', closeThemeOutside);
    cleanups.push(() => window.removeEventListener('pointerdown', closeThemeOutside));
    renderThemeControl();
    themeWrap.append(themeBtn, themeList);

    barEl.append(toolsEl, prevBtn);
    if (upBtn) barEl.append(upBtn);
    barEl.append(counterSlot);
    if (downBtn) barEl.append(downBtn);
    barEl.append(nextBtn, themeWrap);

    slidesEl.append(bodyEl, barEl);

    function sayNotice(text) {
      noticeText = text;
      updateCounter();
      clearTimeout(noticeTimer);
      noticeTimer = setTimeout(() => { noticeText = null; updateCounter(); }, 4000);
    }

    function updateCounter() {
      counterSlot.replaceChildren();
      if (jumping) {
        const inp = document.createElement('input');
        inp.className = 'slides-jump';
        inp.setAttribute('aria-label', 'Go to slide');
        inp.placeholder = '3 or 3.2';
        inp.setAttribute('enterkeyhint', 'go');
        inp.addEventListener('keydown', e => {
          if (e.key === 'Enter') {
            e.preventDefault();
            const val = inp.value;
            jumping = false;
            const target = parseSlideNumber(val);
            if (target && exists(target)) showSlide(target, true);
            else if (val.trim()) sayNotice('No such slide');
            updateCounter();
            bodyEl.focus();
          } else if (e.key === 'Escape') {
            e.preventDefault();
            e.stopPropagation();
            jumping = false;
            updateCounter();
            bodyEl.focus();
          }
        });
        inp.addEventListener('blur', () => {
          if (jumping) { jumping = false; updateCounter(); }
        });
        counterSlot.append(inp);
        requestAnimationFrame(() => inp.focus());
        return;
      }
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'slides-counter';
      btn.title = 'Go to slide · G';
      const st = document.createElement('span');
      st.setAttribute('role', 'status');
      st.textContent = noticeText || (deck[pos[0]].length === 1
        ? `${pos[0] + 1} / ${deck.length}`
        : `${pos[0] + 1} / ${deck.length} · ${pos[1] + 1} / ${deck[pos[0]].length}`);
      btn.append(st);
      btn.onclick = () => { jumping = true; updateCounter(); };
      counterSlot.append(btn);
    }

    function updateSpeakerPanel() {
      const idx = indexOf(pos);
      const nextSlot = order[idx + 1] || null;
      nextStage.showSlot(nextSlot);
      endP.hidden = nextSlot !== null;
      const notesHtml = deck[pos[0]][pos[1]].notes || '';
      notesBox.replaceChildren();
      if (!notesHtml) {
        const p = document.createElement('p');
        p.className = 'slides-no-notes';
        p.textContent = 'No notes for this slide.';
        notesBox.append(p);
      } else {
        const enh = document.createElement('div');
        enh.className = 'enhanced';
        const md = document.createElement('div');
        md.className = 'markdown';
        md.innerHTML = notesHtml;
        enh.append(md);
        notesBox.append(enh);
        enhanceContainer(enh, version);
      }
    }

    function updateBar() {
      overviewBtn.setAttribute('aria-pressed', String(overviewOpen));
      prevBtn.disabled = pos[0] === 0;
      nextBtn.disabled = pos[0] + 1 >= deck.length;
      if (upBtn) upBtn.disabled = pos[1] === 0;
      if (downBtn) downBtn.disabled = pos[1] + 1 >= deck[pos[0]].length;
      updateCounter();
    }

    function applyPos(next, userInitiated) {
      const changed = pos[0] !== next[0] || pos[1] !== next[1];
      pos = next;
      if (changed) {
        enlargedSrc = null;
        renderEnlarged();
      }
      mainStage.showSlot(pos);
      if (speakerOpen) updateSpeakerPanel();
      if (overviewOpen) {
        for (const t of overviewEl?.querySelectorAll('.slides-thumb') || []) {
          t.classList.toggle('current', t.getAttribute('aria-label') === `Slide ${slideNumberStr(pos)}`);
        }
      }
      updateBar();
      sendMsg({ t: 'save_place', path: msg.path, patch: { slide: pos } });
      if (changed && userInitiated) {
        userTurned = true;
        if (audienceWidget.isAudience()) audienceWidget.turned(pos);
        else sendMsg({ t: 'tell_presenting', path: msg.path, column: pos[0], row: pos[1] });
      }
    }

    function showSlide(next, userInitiated) {
      if (!exists(next)) return;
      applyPos(next, userInitiated);
    }

    function goSlide(right, down) {
      const [c, r] = pos;
      if (right !== 0) {
        const nc = Math.max(0, Math.min(deck.length - 1, c + right));
        showSlide(nc === c ? [c, r] : [nc, 0], true);
      } else {
        const nr = Math.max(0, Math.min(deck[c].length - 1, r + down));
        showSlide([c, nr], true);
      }
    }

    function stepSlide(by) {
      const idx = Math.max(0, Math.min(order.length - 1, indexOf(pos) + by));
      showSlide(order[idx], true);
    }

    const onKeyDown = e => {
      if (e.ctrlKey || e.metaKey || e.altKey || e.defaultPrevented) return;
      const active = document.activeElement;
      if (active && (['INPUT', 'TEXTAREA', 'SELECT'].includes(active.tagName) || active.hasAttribute('contenteditable'))) return;
      if ((e.key === ' ' && active && ['BUTTON', 'SUMMARY'].includes(active.tagName))
        || (e.key === 'Enter' && active && ['BUTTON', 'A', 'SUMMARY'].includes(active.tagName))) {
        return;
      }
      switch (e.key) {
        case 'ArrowRight': goSlide(1, 0); break;
        case 'ArrowLeft': goSlide(-1, 0); break;
        case 'ArrowDown': goSlide(0, 1); break;
        case 'ArrowUp': goSlide(0, -1); break;
        case 'Home': showSlide([0, 0], true); break;
        case 'End': showSlide(order[order.length - 1], true); break;
        case 'Enter': if (overviewOpen) { overviewOpen = false; renderOverview(); updateBar(); } else return; break;
        case 'o': case 'O': overviewOpen = !overviewOpen; renderOverview(); updateBar(); break;
        case 'g': case 'G': jumping = true; updateCounter(); break;
        case 's': case 'S':
          if (!msg.speaker_mode) sendMsg({ t: 'open_speaker', path: msg.path });
          break;
        case 'f': case 'F': fullscreenBtn.click(); break;
        case ' ': stepSlide(e.shiftKey ? -1 : 1); break;
        case 'PageDown': case 'n': case 'N': stepSlide(1); break;
        case 'PageUp': case 'p': case 'P': stepSlide(-1); break;
        default: return;
      }
      e.preventDefault();
    };
    window.addEventListener('keydown', onKeyDown);
    cleanups.push(() => window.removeEventListener('keydown', onKeyDown));

    applyPos(pos, false);
    requestAnimationFrame(() => bodyEl.focus());

    return {
      el: slidesEl,
      controller: {
        onPresentUpdate(col, row, fromWhere = false) {
          if (fromWhere && userTurned && col === initialPos[0] && row === initialPos[1] && (Date.now() - mountedAt) < 2000) {
            return;
          }
          if (exists([col, row]) && audienceWidget.heard([col, row])) {
            applyPos([col, row], false);
          }
        },
        onAudienceUpdate(aud) {
          audienceWidget.update(aud);
          liveControls.update(currentLiveBar);
        },
        onLiveBar(b) { liveControls.update(b); },
        onNotice(text) { sayNotice(text); },
        onEscape() {
          if (jumping) { jumping = false; updateCounter(); bodyEl.focus(); return true; }
          if (enlargedSrc) { enlargedSrc = null; renderEnlarged(); return true; }
          if (overviewOpen) { overviewOpen = false; renderOverview(); updateBar(); return true; }
          return false;
        },
      },
      cleanup() {
        clearTimeout(noticeTimer);
        for (const fn of cleanups) fn();
      },
    };
  }

  // --- PDF View ---
  function mountPdf(msg, version) {
    const cleanups = [];
    let pages = msg.pages || [];
    let docId = msg.doc_id || 0;
    let failure = msg.error || null;
    const saved = msg.place || {};
    const audienceWidget = createAudienceWidget(msg.audience, at => {
      if (at[0] < pages.length) setCurrentPage(at[0], false);
    });
    let presenting = saved.present === true || audienceWidget.isAudience();
    let current = 0;
    let startPage = Number.isInteger(saved.page) ? saved.page : 0;
    if (Array.isArray(msg.last_presented)) startPage = msg.last_presented[0];
    const initialPage = startPage;
    const mountedAt = Date.now();
    let userTurned = false;
    let zoom = Math.max(PDF_ZOOM_MIN, Math.min(PDF_ZOOM_MAX, Number(saved.zoom) || 1.0));

    const root = document.createElement('div');
    root.className = 'pdf-view';
    root.classList.toggle('presenting', presenting);

    const toolbar = document.createElement('div');
    toolbar.className = 'pdf-toolbar';
    const tools = document.createElement('div');
    tools.className = 'pdf-tools';

    const presentBtn = document.createElement('button');
    presentBtn.type = 'button';
    presentBtn.className = 'pdf-present-button';

    const liveControls = createLiveControls(msg.path, audienceWidget);
    cleanups.push(() => liveControls.cleanup());
    tools.append(audienceWidget.el, presentBtn, liveControls.el);

    const prevBtn = document.createElement('button');
    prevBtn.type = 'button';
    prevBtn.setAttribute('aria-label', 'Previous page');
    prevBtn.textContent = '↑';

    const statusEl = document.createElement('span');
    statusEl.setAttribute('role', 'status');

    const nextBtn = document.createElement('button');
    nextBtn.type = 'button';
    nextBtn.setAttribute('aria-label', 'Next page');
    nextBtn.textContent = '↓';

    const zoomSpan = document.createElement('span');
    zoomSpan.className = 'pdf-zoom';
    const zoomOutBtn = document.createElement('button');
    zoomOutBtn.type = 'button';
    zoomOutBtn.setAttribute('aria-label', 'Zoom out');
    zoomOutBtn.textContent = '−';
    const zoomFitBtn = document.createElement('button');
    zoomFitBtn.type = 'button';
    zoomFitBtn.setAttribute('aria-label', 'Fit width');
    const zoomInBtn = document.createElement('button');
    zoomInBtn.type = 'button';
    zoomInBtn.setAttribute('aria-label', 'Zoom in');
    zoomInBtn.textContent = '+';
    zoomSpan.append(zoomOutBtn, zoomFitBtn, zoomInBtn);

    toolbar.append(tools, prevBtn, statusEl, nextBtn, zoomSpan);

    const presentDiv = document.createElement('div');
    presentDiv.className = 'pdf-present';
    presentDiv.tabIndex = -1;
    presentDiv.hidden = !presenting;
    const presentCanvas = document.createElement('canvas');
    presentCanvas.className = 'pdf-slide';
    presentDiv.append(presentCanvas);

    const stageDiv = document.createElement('div');
    stageDiv.className = 'pdf-stage';
    stageDiv.tabIndex = 0;
    stageDiv.hidden = presenting;
    stageDiv.style.setProperty('--pdf-zoom', String(zoom));

    root.append(toolbar, presentDiv, stageDiv);

    const near = new Set();
    const drawn = new Map(); // page -> width
    let drawingScroll = false;
    let presentRoom = [0, 0];
    const readyPresent = new Map(); // page -> { pixels, imageData }
    let drawingPresent = false;
    let io = null;

    function paintCanvas(canvas, imageData) {
      if (!canvas) return;
      canvas.width = imageData.width;
      canvas.height = imageData.height;
      const ctx = canvas.getContext('2d');
      ctx?.putImageData(imageData, 0, 0);
    }

    function requestRender(pageIdx, pixelWidth) {
      const reqId = ++nextReqId;
      const key = `${docId}:${pageIdx}`;
      return new Promise((resolve, reject) => {
        let frameData = null;
        let renderedDone = false;
        const finish = () => {
          if (frameData && renderedDone) resolve(frameData);
        };
        const list = pdfFrameWaiters.get(key) || [];
        list.push(img => { frameData = img; finish(); });
        pdfFrameWaiters.set(key, list);

        pdfRenderWaiters.set(reqId, res => {
          if (res.error) {
            reject(new Error(res.error));
            return;
          }
          renderedDone = true;
          const cached = pdfFrames.get(key);
          if (!frameData && cached && cached.width === res.width && cached.height === res.height) {
            frameData = cached.imageData;
          }
          finish();
        });
        sendMsg({ t: 'request_pdf_render', req_id: reqId, doc_id: docId, page: pageIdx, width: pixelWidth });
      });
    }

    function frameEl(idx) {
      return stageDiv.querySelector(`.pdf-frame[data-index="${idx}"]`);
    }

    async function drawScrollPages() {
      if (drawingScroll || !docId || presenting) return;
      drawingScroll = true;
      const ratio = Math.min(window.devicePixelRatio || 1, 2);
      try {
        while (version === currentVersion && docId && !presenting) {
          let best = null;
          let bestDist = Infinity;
          for (const idx of near) {
            const f = frameEl(idx);
            if (!f) continue;
            const px = Math.round(Math.min(f.clientWidth * ratio, PDF_PIXELS));
            if (px > 0 && drawn.get(idx) !== px) {
              const dist = Math.abs(idx - current);
              if (dist < bestDist) { bestDist = dist; best = [idx, px]; }
            }
          }
          if (!best) break;
          const [idx, px] = best;
          try {
            const imageData = await requestRender(idx, px);
            if (version !== currentVersion || !near.has(idx)) continue;
            paintCanvas(frameEl(idx)?.querySelector('canvas'), imageData);
            drawn.set(idx, px);
          } catch (err) {
            failure = `PDF rendering failed: ${err.message}`;
            updateToolbar();
            break;
          }
        }
      } finally {
        drawingScroll = false;
      }
    }

    function presentWidthFor(idx) {
      const [rw, rh] = presentRoom;
      const p = pages[idx];
      if (!p || rw <= 0 || rh <= 0) return 0;
      const pw = p.width_milli / 1000;
      const ph = p.height_milli / 1000;
      const fit = Math.min(rw, rh * pw / ph);
      return Math.round(Math.max(0, Math.min(PDF_PRESENT_PIXELS, fit * (window.devicePixelRatio || 1))));
    }

    function showReadyPresent() {
      const hit = readyPresent.get(current);
      if (hit) paintCanvas(presentCanvas, hit.imageData);
    }

    async function drawPresentAhead() {
      if (drawingPresent || !docId || !presenting) return;
      drawingPresent = true;
      try {
        while (version === currentVersion && docId && presenting) {
          const targets = [current, current + 1, current - 1].filter(i => i >= 0 && i < pages.length);
          let nextTask = null;
          for (const idx of targets) {
            const px = presentWidthFor(idx);
            if (px > 0 && readyPresent.get(idx)?.pixels !== px) {
              nextTask = [idx, px];
              break;
            }
          }
          if (!nextTask) break;
          const [idx, px] = nextTask;
          try {
            const imageData = await requestRender(idx, px);
            if (version !== currentVersion) return;
            readyPresent.set(idx, { pixels: px, imageData });
            for (const k of [...readyPresent.keys()]) {
              if (Math.abs(k - current) > 1) readyPresent.delete(k);
            }
            if (idx === current) showReadyPresent();
          } catch (err) {
            failure = `PDF rendering failed: ${err.message}`;
            updateToolbar();
            break;
          }
        }
      } finally {
        drawingPresent = false;
      }
    }

    function savePdfPlace() {
      if (pages.length) {
        sendMsg({ t: 'save_place', path: msg.path, patch: { page: current, zoom, present: presenting } });
      }
    }

    function updateToolbar() {
      const label = presenting ? 'Scroll the pages' : 'Present one page at a time';
      presentBtn.title = label;
      presentBtn.setAttribute('aria-label', label);
      presentBtn.setAttribute('aria-pressed', String(presenting));
      presentBtn.replaceChildren(makeSvgIcon(presenting ? ICON_PATHS.asDoc : ICON_PATHS.asSlides));
      root.classList.toggle('presenting', presenting);
      presentDiv.hidden = !presenting;
      stageDiv.hidden = presenting;
      zoomSpan.hidden = presenting;
      prevBtn.disabled = current === 0;
      nextBtn.disabled = current + 1 >= pages.length;
      zoomOutBtn.disabled = zoom <= PDF_ZOOM_MIN;
      zoomInBtn.disabled = zoom >= PDF_ZOOM_MAX;
      zoomFitBtn.textContent = `${Math.round(zoom * 100)}%`;
      presentCanvas.setAttribute('aria-label', `Presented page ${current + 1}`);
      statusEl.textContent = failure || (pages.length ? `${current + 1} / ${pages.length}` : 'Loading PDF...');
    }

    function setCurrentPage(pageIdx, userInitiated) {
      const clamped = Math.max(0, Math.min(Math.max(0, pages.length - 1), pageIdx));
      const changed = clamped !== current;
      current = clamped;
      updateToolbar();
      savePdfPlace();
      if (presenting) {
        showReadyPresent();
        void drawPresentAhead();
        if (changed && userInitiated) {
          userTurned = true;
          if (audienceWidget.isAudience()) audienceWidget.turned([current, 0]);
          else sendMsg({ t: 'tell_presenting', path: msg.path, column: current, row: 0 });
        }
      } else if (userInitiated) {
        frameEl(current)?.scrollIntoView();
      }
    }

    function populatePages() {
      if (io) { io.disconnect(); io = null; }
      near.clear();
      drawn.clear();
      readyPresent.clear();
      stageDiv.replaceChildren();
      for (let i = 0; i < pages.length; i++) {
        const p = pages[i];
        const f = document.createElement('div');
        f.className = 'pdf-frame';
        f.dataset.index = String(i);
        f.style.aspectRatio = `${p.width_milli}/${p.height_milli}`;
        const c = document.createElement('canvas');
        c.className = 'pdf-page';
        c.setAttribute('aria-label', `PDF page ${i + 1}`);
        f.append(c);
        stageDiv.append(f);
      }
      if (!pages.length) return;
      io = new IntersectionObserver(entries => {
        for (const entry of entries) {
          const idx = Number(entry.target.dataset.index);
          if (entry.isIntersecting) {
            near.add(idx);
          } else {
            near.delete(idx);
            const c = entry.target.querySelector('canvas');
            if (c) { c.width = 0; c.height = 0; }
            drawn.delete(idx);
          }
        }
        void drawScrollPages();
      }, { root: stageDiv, rootMargin: '100% 0px' });
      for (const f of stageDiv.querySelectorAll('.pdf-frame')) io.observe(f);
      current = Math.min(startPage, pages.length - 1);
      updateToolbar();
      savePdfPlace();
      if (presenting) {
        showReadyPresent();
        void drawPresentAhead();
      } else {
        stageDiv.focus();
        if (current > 0) {
          requestAnimationFrame(() => frameEl(current)?.scrollIntoView());
        }
      }
    }

    presentBtn.onclick = () => {
      presenting = !presenting;
      updateToolbar();
      savePdfPlace();
      if (presenting) {
        if (!audienceWidget.isAudience()) sendMsg({ t: 'ask_where', path: msg.path });
        showReadyPresent();
        void drawPresentAhead();
      } else {
        requestAnimationFrame(() => {
          frameEl(current)?.scrollIntoView();
          void drawScrollPages();
        });
      }
    };
    prevBtn.onclick = () => setCurrentPage(current - 1, true);
    nextBtn.onclick = () => setCurrentPage(current + 1, true);
    const setZoom = z => {
      zoom = Math.max(PDF_ZOOM_MIN, Math.min(PDF_ZOOM_MAX, z));
      stageDiv.style.setProperty('--pdf-zoom', String(zoom));
      updateToolbar();
      savePdfPlace();
      frameEl(current)?.scrollIntoView();
      void drawScrollPages();
    };
    zoomOutBtn.onclick = () => setZoom(zoom / 1.25);
    zoomFitBtn.onclick = () => setZoom(1.0);
    zoomInBtn.onclick = () => setZoom(zoom * 1.25);

    stageDiv.addEventListener('scroll', () => {
      if (presenting || !pages.length) return;
      const line = stageDiv.scrollTop + stageDiv.clientHeight / 3;
      let seen = 0;
      for (let i = 0; i < pages.length; i++) {
        const f = frameEl(i);
        if (f && f.offsetTop <= line) seen = i;
        else break;
      }
      if (seen !== current) {
        current = seen;
        updateToolbar();
        savePdfPlace();
      }
    });

    const ro = new ResizeObserver(entries => {
      for (const entry of entries) {
        presentRoom = [entry.contentRect.width, entry.contentRect.height];
        if (presenting && pages.length) {
          showReadyPresent();
          void drawPresentAhead();
        }
      }
    });
    ro.observe(presentDiv);
    cleanups.push(() => ro.disconnect());

    let swipeStart = null;
    presentDiv.addEventListener('pointerdown', e => { if (e.pointerType !== 'mouse') swipeStart = [e.clientX, e.clientY]; });
    presentDiv.addEventListener('pointercancel', () => { swipeStart = null; });
    presentDiv.addEventListener('pointerup', e => {
      if (!swipeStart) return;
      const [sx, sy] = swipeStart;
      swipeStart = null;
      const dx = e.clientX - sx, dy = e.clientY - sy;
      if (Math.abs(dx) > SWIPE && Math.abs(dx) > 2 * Math.abs(dy)) {
        setCurrentPage(current + (dx < 0 ? 1 : -1), true);
      }
    });

    const onKeyDown = e => {
      if (!presenting || e.ctrlKey || e.metaKey || e.altKey || e.defaultPrevented) return;
      const active = document.activeElement;
      if (active && (['INPUT', 'TEXTAREA', 'SELECT'].includes(active.tagName) || active.hasAttribute('contenteditable'))) return;
      if ((e.key === ' ' && active && ['BUTTON', 'SUMMARY'].includes(active.tagName))
        || (e.key === 'Enter' && active && ['BUTTON', 'A', 'SUMMARY'].includes(active.tagName))) return;
      switch (e.key) {
        case 'ArrowRight': case 'ArrowDown': case 'PageDown': case 'n': case 'N': setCurrentPage(current + 1, true); break;
        case 'ArrowLeft': case 'ArrowUp': case 'PageUp': case 'p': case 'P': setCurrentPage(current - 1, true); break;
        case ' ': setCurrentPage(current + (e.shiftKey ? -1 : 1), true); break;
        case 'Home': setCurrentPage(0, true); break;
        case 'End': setCurrentPage(pages.length - 1, true); break;
        case 'f': case 'F': fullscreenBtn.click(); break;
        default: return;
      }
      e.preventDefault();
    };
    window.addEventListener('keydown', onKeyDown);
    cleanups.push(() => window.removeEventListener('keydown', onKeyDown));

    updateToolbar();
    if (pages.length) populatePages();

    return {
      el: root,
      controller: {
        onPdfReady(nextDocId, nextPages) {
          docId = nextDocId;
          pages = nextPages;
          failure = null;
          populatePages();
        },
        onPdfError(message) {
          failure = message;
          updateToolbar();
        },
        onPresentUpdate(pageIdx, _row = 0, fromWhere = false) {
          if (fromWhere && userTurned && pageIdx === initialPage && (Date.now() - mountedAt) < 2000) {
            return;
          }
          if (!presenting || !audienceWidget.heard([pageIdx, 0])) return;
          if (!pages.length) startPage = pageIdx;
          else if (pageIdx < pages.length) setCurrentPage(pageIdx, false);
        },
        onAudienceUpdate(aud) {
          audienceWidget.update(aud);
          liveControls.update(currentLiveBar);
        },
        onLiveBar(b) { liveControls.update(b); },
        onNotice() {},
        onEscape() { return false; },
      },
      cleanup() {
        if (io) io.disconnect();
        for (const fn of cleanups) fn();
      },
    };
  }

  // --- Media View (Blob or RangePull) ---
  function mountMedia(msg, version) {
    const frame = document.createElement('div');
    frame.className = 'media-frame';
    let mediaEl;
    if (msg.media_kind === 'image') {
      mediaEl = document.createElement('img');
      mediaEl.alt = msg.path;
    } else if (msg.media_kind === 'video') {
      mediaEl = document.createElement('video');
      mediaEl.controls = true;
      mediaEl.preload = 'metadata';
      mediaEl.playsInline = true;
    } else {
      mediaEl = document.createElement('audio');
      mediaEl.controls = true;
      mediaEl.preload = 'metadata';
    }
    let failedP = null;
    mediaEl.onerror = () => {
      if (!failedP) {
        failedP = document.createElement('p');
        failedP.textContent = 'This browser cannot decode the media. Download it to open locally.';
        frame.append(failedP);
      }
    };
    if ((msg.media_kind === 'video' || msg.media_kind === 'audio') && msg.place?.time > 1) {
      const savedTime = Number(msg.place.time);
      mediaEl.addEventListener('loadedmetadata', () => {
        if (Number.isFinite(mediaEl.duration) && savedTime < mediaEl.duration - 1) {
          mediaEl.currentTime = savedTime;
        }
      }, { once: true });
    }
    frame.append(mediaEl);

    void waitForAssetUrl(msg.asset_id, msg.mime).then(async ({ url, rangeMeta }) => {
      if (version !== currentVersion) return;
      if (url) {
        mediaEl.src = url;
        return;
      }
      if (rangeMeta) {
        // RangePull (> 64 MiB): stream chunks sequentially via window.gui.requestAssetRange
        // into MediaSource if supported, else accumulate up to browser limits.
        const chunkLen = 512 * 1024;
        if (window.MediaSource && MediaSource.isTypeSupported(rangeMeta.mime)) {
          const ms = new MediaSource();
          const msUrl = URL.createObjectURL(ms);
          activeBlobUrls.add(msUrl);
          mediaEl.src = msUrl;
          ms.addEventListener('sourceopen', async () => {
            try {
              const sb = ms.addSourceBuffer(rangeMeta.mime);
              let off = 0;
              while (version === currentVersion && off < rangeMeta.size) {
                const slice = await requestRangeSlice(rangeMeta.assetId, off, Math.min(chunkLen, rangeMeta.size - off));
                if (!slice.byteLength) break;
                off += slice.byteLength;
                await new Promise((res, rej) => {
                  sb.addEventListener('updateend', res, { once: true });
                  sb.addEventListener('error', rej, { once: true });
                  sb.appendBuffer(slice);
                });
              }
              if (ms.readyState === 'open') ms.endOfStream();
            } catch {}
          }, { once: true });
        } else {
          const parts = [];
          let off = 0;
          while (version === currentVersion && off < rangeMeta.size) {
            const slice = await requestRangeSlice(rangeMeta.assetId, off, Math.min(chunkLen, rangeMeta.size - off));
            if (!slice.byteLength) break;
            off += slice.byteLength;
            parts.push(slice);
          }
          if (version === currentVersion) {
            const blobUrl = URL.createObjectURL(new Blob(parts, { type: rangeMeta.mime }));
            activeBlobUrls.add(blobUrl);
            mediaEl.src = blobUrl;
          }
        }
      }
    }).catch(err => {
      if (version === currentVersion && !failedP) {
        failedP = document.createElement('p');
        failedP.textContent = String(err?.message || 'Media failed to load.');
        frame.append(failedP);
      }
    });

    return { el: frame, cleanup() {} };
  }

  // --- Archive View ---
  function renderArchiveInto(container, entries, more, error) {
    container.replaceChildren();
    if (error) {
      const wrap = document.createElement('div');
      wrap.className = 'media-frame';
      const p = document.createElement('p');
      p.className = 'no-preview';
      p.textContent = error;
      wrap.append(p);
      container.append(wrap);
      return;
    }
    const arc = document.createElement('div');
    arc.className = 'archive';
    const files = entries.filter(e => !e.directory).length;
    const total = entries.reduce((sum, e) => sum + (Number(e.size) || 0), 0);
    const note = document.createElement('p');
    note.className = 'preview-note';
    note.textContent = `${more ? 'The first ' : ''}${files} files, ${fmtSize(total)} unpacked`;
    const ul = document.createElement('ul');
    for (const entry of entries) {
      const li = document.createElement('li');
      if (entry.directory) li.className = 'directory';
      const nameSpan = document.createElement('span');
      nameSpan.textContent = entry.path;
      const lenSpan = document.createElement('span');
      lenSpan.textContent = entry.directory ? '' : fmtSize(entry.size);
      li.append(nameSpan, lenSpan);
      ul.append(li);
    }
    arc.append(note, ul);
    container.append(arc);
  }

  // --- Main View Renderer ---
  function renderShow(msg) {
    cleanupView(msg?.view === 'media' ? msg.asset_id : null);
    currentShow = msg;
    currentVersion = msg.version;
    if (msg.slide_theme) currentSlideTheme = msg.slide_theme;
    if (msg.notes_size) currentNotesSize = msg.notes_size;

    const bdi = document.createElement('bdi');
    bdi.textContent = msg.title || '';
    titleEl.replaceChildren(bdi);
    backBtn.hidden = !msg.can_back;
    backBtn.title = msg.back_title || '';
    downloadBtn.hidden = !msg.can_download;

    const version = msg.version;

    if (msg.view === 'loading') {
      const p = document.createElement('p');
      p.className = 'viewer-loading';
      p.textContent = 'Loading...';
      contentEl.append(p);
      return;
    }
    if (msg.view === 'error') {
      contentEl.classList.add('viewer-error');
      contentEl.textContent = msg.message || 'Error';
      return;
    }
    if (msg.view === 'no_preview') {
      const frame = document.createElement('div');
      frame.className = 'media-frame';
      const p = document.createElement('p');
      p.className = 'no-preview';
      p.textContent = msg.message || 'No preview for this kind of file. Download it to open it.';
      frame.append(p);
      contentEl.append(frame);
      return;
    }
    if (msg.view === 'game') {
      surfaceEl.classList.add('game-view');
      return;
    }
    if (msg.view === 'media') {
      const m = mountMedia(msg, version);
      contentEl.append(m.el);
      viewCleanup = m.cleanup;
      return;
    }
    if (msg.view === 'slides') {
      surfaceEl.classList.add('slides-view');
      const s = mountSlides(msg.slides || [], msg, version);
      contentEl.append(s.el);
      s.el.querySelector('.slides-body')?.focus?.({ preventScroll: true });
      activeController = s.controller;
      viewCleanup = s.cleanup;
      return;
    }
    if (msg.view === 'markdown') {
      if (msg.manual) {
        const article = document.createElement('article');
        article.className = 'markdown manual';
        article.innerHTML = msg.html || '';
        const enh = document.createElement('div');
        enh.className = 'enhanced';
        enh.append(article);
        enhanceContainer(enh, version);
        const search = mountSearchable(enh);
        contentEl.append(search.fragment);
        activeController = { onEscape: search.handleEscape };
        viewCleanup = search.cleanup;
        return;
      }
      let asSlides = Boolean(msg.as_slides);
      let innerCleanup = null;
      const modeBar = document.createElement('div');
      modeBar.className = 'preview-bar';
      const modeBtn = document.createElement('button');
      modeBtn.type = 'button';
      modeBtn.className = 'preview-button';
      modeBar.append(modeBtn);
      const bodySlot = document.createDocumentFragment();
      contentEl.append(modeBar);

      function renderMarkdownBody() {
        if (innerCleanup) { innerCleanup(); innerCleanup = null; }
        activeController = null;
        searchBtn.hidden = true;
        searchBtn.onclick = null;
        clearSearchHighlights();
        while (contentEl.lastChild && contentEl.lastChild !== modeBar) {
          contentEl.lastChild.remove();
        }
        const label = asSlides ? 'View as a document' : 'View as slides';
        modeBtn.title = label;
        modeBtn.setAttribute('aria-label', label);
        modeBtn.replaceChildren(makeSvgIcon(asSlides ? ICON_PATHS.asDoc : ICON_PATHS.asSlides));
        surfaceEl.classList.toggle('slides-view', asSlides);
        if (asSlides) {
          const s = mountSlides(msg.slides || [], msg, version);
          contentEl.append(s.el);
          s.el.querySelector('.slides-body')?.focus?.({ preventScroll: true });
          activeController = s.controller;
          innerCleanup = s.cleanup;
        } else {
          const enh = document.createElement('div');
          enh.className = 'enhanced';
          const article = document.createElement('article');
          article.className = 'markdown';
          article.innerHTML = msg.html || '';
          enh.append(article);
          enhanceContainer(enh, version);
          const search = mountSearchable(enh);
          contentEl.append(search.fragment);
          activeController = { onEscape: search.handleEscape };
          innerCleanup = search.cleanup;
          if (msg.place?.scroll) {
            requestAnimationFrame(() => { contentEl.scrollTop = Number(msg.place.scroll) || 0; });
          }
        }
      }
      modeBtn.onclick = () => {
        asSlides = !asSlides;
        sendMsg({ t: 'save_place', path: msg.path, patch: { slides: asSlides } });
        renderMarkdownBody();
        if (asSlides && !msg.audience) sendMsg({ t: 'ask_where', path: msg.path });
      };
      renderMarkdownBody();
      viewCleanup = () => { if (innerCleanup) innerCleanup(); };
      return;
    }
    if (msg.view === 'code') {
      const enh = document.createElement('div');
      enh.className = 'enhanced';
      const pre = document.createElement('pre');
      pre.className = 'text-preview';
      const code = document.createElement('code');
      if (msg.language) code.setAttribute('data-lang', msg.language);
      code.textContent = msg.text || '';
      pre.append(code);
      enh.append(pre);
      enhanceContainer(enh, version);
      const search = mountSearchable(enh);
      contentEl.append(search.fragment);
      activeController = { onEscape: search.handleEscape };
      viewCleanup = search.cleanup;
      if (msg.place?.scroll) {
        requestAnimationFrame(() => { contentEl.scrollTop = Number(msg.place.scroll) || 0; });
      }
      return;
    }
    if (msg.view === 'diff') {
      const pre = document.createElement('pre');
      pre.className = 'text-preview diff';
      for (const [kind, line] of msg.lines || []) {
        const span = document.createElement('span');
        span.className = `diff-${kind}`;
        span.textContent = line;
        pre.append(span);
      }
      const search = mountSearchable(pre);
      contentEl.append(search.fragment);
      activeController = { onEscape: search.handleEscape };
      viewCleanup = search.cleanup;
      if (msg.place?.scroll) {
        requestAnimationFrame(() => { contentEl.scrollTop = Number(msg.place.scroll) || 0; });
      }
      return;
    }
    if (msg.view === 'table') {
      const wrap = document.createElement('div');
      wrap.className = 'table-preview';
      const table = document.createElement('table');
      const rows = msg.table?.rows || [];
      const thead = document.createElement('thead');
      const hr = document.createElement('tr');
      for (const cell of rows[0] || []) {
        const th = document.createElement('th');
        th.textContent = cell;
        hr.append(th);
      }
      thead.append(hr);
      const tbody = document.createElement('tbody');
      for (let i = 1; i < rows.length; i++) {
        const tr = document.createElement('tr');
        for (const cell of rows[i]) {
          const td = document.createElement('td');
          td.textContent = cell;
          tr.append(td);
        }
        tbody.append(tr);
      }
      table.append(thead, tbody);
      wrap.append(table);
      if (msg.table?.more) {
        const note = document.createElement('p');
        note.className = 'preview-note';
        note.textContent = `Only the first ${msg.rows_max || 1000} rows show.`;
        wrap.append(note);
      }
      contentEl.append(wrap);
      return;
    }
    if (msg.view === 'cards') {
      const wrap = document.createElement('div');
      wrap.className = 'cards';
      for (const card of msg.cards || []) {
        const sec = document.createElement('section');
        sec.className = 'card';
        const h3 = document.createElement('h3');
        h3.textContent = card.title || 'Untitled';
        const dl = document.createElement('dl');
        for (const [k, v] of card.fields || []) {
          const dt = document.createElement('dt');
          dt.textContent = k;
          const dd = document.createElement('dd');
          dd.textContent = v;
          dl.append(dt, dd);
        }
        sec.append(h3, dl);
        wrap.append(sec);
      }
      contentEl.append(wrap);
      return;
    }
    if (msg.view === 'pdf') {
      const p = mountPdf(msg, version);
      contentEl.append(p.el);
      p.el.querySelector('.pdf-present:not([hidden]), .pdf-stage:not([hidden])')?.focus?.({ preventScroll: true });
      activeController = p.controller;
      viewCleanup = p.cleanup;
      return;
    }
    if (msg.view === 'archive') {
      const holder = document.createElement('div');
      holder.style.height = '100%';
      if (msg.loading) {
        const p = document.createElement('p');
        p.className = 'preview-note';
        p.style.padding = '24px';
        p.textContent = 'Listing the archive...';
        holder.append(p);
      } else {
        renderArchiveInto(holder, msg.entries || [], Boolean(msg.more), msg.error);
      }
      contentEl.append(holder);
      activeController = {
        onArchiveReady(entries, more) { renderArchiveInto(holder, entries, more, null); },
        onArchiveError(message) { renderArchiveInto(holder, [], false, message); },
      };
    }
  }

  function handleHostMsg(msg) {
    if (!msg || typeof msg.t !== 'string') return;
    switch (msg.t) {
      case 'show': renderShow(msg); return;
      case 'pdf_ready':
        if (msg.version === currentVersion) activeController?.onPdfReady?.(msg.doc_id, msg.pages || []);
        return;
      case 'pdf_error':
        if (msg.version === currentVersion) activeController?.onPdfError?.(msg.message);
        return;
      case 'archive_ready':
        if (msg.version === currentVersion) activeController?.onArchiveReady?.(msg.entries || [], Boolean(msg.more));
        return;
      case 'archive_error':
        if (msg.version === currentVersion) activeController?.onArchiveError?.(msg.message);
        return;
      case 'local_image_ready': {
        const w = localImageWaiters.get(msg.req_id);
        if (w) {
          localImageWaiters.delete(msg.req_id);
          void w.resolve({ assetId: msg.asset_id, mime: msg.mime });
        }
        return;
      }
      case 'local_image_error': {
        const w = localImageWaiters.get(msg.req_id);
        if (w) {
          localImageWaiters.delete(msg.req_id);
          w.reject(msg.message);
        }
        return;
      }
      case 'highlight_result': {
        const w = highlightWaiters.get(msg.req_id);
        if (w) { highlightWaiters.delete(msg.req_id); w(msg); }
        return;
      }
      case 'diagram_result': {
        const w = diagramWaiters.get(msg.req_id);
        if (w) { diagramWaiters.delete(msg.req_id); w(msg); }
        return;
      }
      case 'pdf_rendered': {
        const w = pdfRenderWaiters.get(msg.req_id);
        if (w) { pdfRenderWaiters.delete(msg.req_id); w(msg); }
        return;
      }
      case 'fullscreen': {
        isFullscreen = Boolean(msg.active);
        surfaceEl.classList.toggle('is-fullscreen', isFullscreen);
        fullscreenBtn.setAttribute('aria-label', isFullscreen ? 'Exit fullscreen' : 'Fullscreen');
        fullscreenBtn.setAttribute('aria-pressed', String(isFullscreen));
        if (msg.error) {
          fsErrorEl.textContent = `Fullscreen failed: ${msg.error}`;
          fsErrorEl.hidden = false;
        } else {
          fsErrorEl.hidden = true;
        }
        if (isFullscreen) showChrome();
        else {
          clearTimeout(chromeTimer);
          surfaceEl.classList.remove('chrome');
        }
        return;
      }
      case 'present_update':
        if (currentShow && msg.path === currentShow.path) {
          activeController?.onPresentUpdate?.(msg.column, msg.row, Boolean(msg.from_where));
        }
        return;
      case 'audience_update':
        activeController?.onAudienceUpdate?.(msg.audience ?? null);
        return;
      case 'live_bar':
        currentLiveBar = msg.bar || currentLiveBar;
        activeController?.onLiveBar?.(currentLiveBar);
        return;
      case 'notice':
        if (msg.message) {
          if (activeController?.onNotice) activeController.onNotice(msg.message);
          else {
            fsErrorEl.textContent = msg.message;
            fsErrorEl.hidden = false;
          }
        }
        return;
      case 'focus':
        surfaceEl.querySelector('.slides-body, .pdf-present:not([hidden]), .pdf-stage:not([hidden])')?.focus?.({ preventScroll: true });
        return;
    }
  }

  // Global Escape inside preview: inner overlays consume Escape first; otherwise close preview
  // (when not fullscreen; browser exits fullscreen first).
  window.addEventListener('keydown', e => {
    if (e.key !== 'Escape' || e.defaultPrevented || e.isComposing) return;
    if (activeController?.onEscape?.()) {
      e.preventDefault();
      return;
    }
    if (isFullscreen) {
      e.preventDefault();
      sendMsg({ t: 'toggle_fullscreen', active: false });
      return;
    }
    e.preventDefault();
    saveCurrentScrollAndMediaPlace();
    sendMsg({ t: 'close' });
  });

  window.gui.onmessage = receiveText;
  window.gui.onbinary = handleBinaryMsg;
  sendMsg({ t: 'ready' });
})();

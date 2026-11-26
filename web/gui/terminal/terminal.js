(() => {
  const tabListEl = document.getElementById('tab-list');
  const newTabBtn = document.getElementById('new-tab');
  const restartBtn = document.getElementById('restart-tab');
  const viewportEl = document.getElementById('viewport');
  const promptPathEl = document.getElementById('prompt-path');
  const screenEl = document.getElementById('screen');
  const inputEl = document.getElementById('term-input');
  const touchKeysEl = document.querySelector('.touch-keys');

  let activeTabId = 0;
  let tabs = [];
  let appCursor = false;
  let lastCols = 0;
  let lastRows = 0;
  let currentTotalRows = 0;
  let rowData = [];
  let cursorState = { row: 0, col: 0, visible: true };
  let stickToBottom = true;
  let composing = false;
  const chunkBuckets = new Map();
  const outQueue = [];
  let flushTimer = null;
  let copySeq = 0;
  const utf8Encoder = new TextEncoder();
  const MAX_WIRE_BYTES = 4096;
  const MAX_CLIPBOARD_BYTES = 64 * 1024;

  function enqueue(obj) {
    const text = JSON.stringify(obj);
    outQueue.push(text);
    drainQueue();
  }

  function drainQueue() {
    while (outQueue.length > 0) {
      const err = window.gui.send(outQueue[0]);
      if (err === 'EAGAIN') {
        if (!flushTimer) {
          flushTimer = setTimeout(() => {
            flushTimer = null;
            drainQueue();
          }, 12);
        }
        return;
      }
      outQueue.shift();
    }
  }

  function chunkByWireBytes(str, wrap) {
    const baseBytes = utf8Encoder.encode(JSON.stringify(wrap(''))).length;
    const chunks = [];
    let cur = '';
    let used = baseBytes;
    for (const ch of str) {
      // Exact JSON-escaped UTF-8 byte length for this code point (minus enclosing quotes).
      const chBytes = utf8Encoder.encode(JSON.stringify(ch)).length - 2;
      if (used + chBytes > MAX_WIRE_BYTES) {
        if (cur) {
          chunks.push(cur);
          cur = ch;
          used = baseBytes + chBytes;
        } else {
          // Single code point fits easily; guard against pathological wrappers.
          chunks.push(ch);
          cur = '';
          used = baseBytes;
        }
      } else {
        cur += ch;
        used += chBytes;
      }
    }
    if (cur) chunks.push(cur);
    return chunks;
  }

  function sendInput(str) {
    if (!str) return;
    // Chunk by Unicode code points so surrogate pairs are never split and every JSON frame <= 4096 UTF-8 bytes.
    for (const part of chunkByWireBytes(str, d => ({ t: 'in', d }))) {
      enqueue({ t: 'in', d: part });
    }
  }

  function sendCopy(sel) {
    if (!sel) return;
    let bounded = sel;
    if (utf8Encoder.encode(bounded).length > MAX_CLIPBOARD_BYTES) {
      let acc = '';
      let used = 0;
      for (const ch of bounded) {
        const b = utf8Encoder.encode(ch).length;
        if (used + b > MAX_CLIPBOARD_BYTES) break;
        acc += ch;
        used += b;
      }
      bounded = acc;
    }
    if (utf8Encoder.encode(JSON.stringify({ t: 'copy', text: bounded })).length <= MAX_WIRE_BYTES) {
      enqueue({ t: 'copy', text: bounded });
      return;
    }
    const id = (++copySeq) >>> 0;
    const parts = chunkByWireBytes(bounded, d => ({ t: 'copy_chunk', id, i: 65535, n: 65535, d }));
    for (let i = 0; i < parts.length; i++) {
      enqueue({ t: 'copy_chunk', id, i, n: parts.length, d: parts[i] });
    }
  }

  function focusInput() {
    if (document.activeElement !== inputEl) {
      try {
        inputEl.focus({ preventScroll: true });
      } catch {
        inputEl.focus();
      }
    }
  }

  function measureGrid() {
    const rect = viewportEl.getBoundingClientRect();
    const probe = document.createElement('span');
    probe.textContent = 'MMMMMMMMMM';
    probe.style.cssText = 'position:absolute;visibility:hidden;white-space:pre;font-size:13.5px;line-height:1.42;';
    screenEl.appendChild(probe);
    const charW = probe.getBoundingClientRect().width / 10 || 8.1;
    const lineH = probe.getBoundingClientRect().height || 19.2;
    probe.remove();
    const innerW = Math.max(80, rect.width - 20);
    const innerH = Math.max(60, rect.height - 22);
    const cols = Math.max(20, Math.min(240, Math.floor(innerW / charW)));
    const rows = Math.max(6, Math.min(120, Math.floor(innerH / lineH)));
    return { cols, rows };
  }

  function reportSize(isInitial) {
    const { cols, rows } = measureGrid();
    if (!isInitial && cols === lastCols && rows === lastRows) return;
    lastCols = cols;
    lastRows = rows;
    enqueue({ t: isInitial ? 'ready' : 'resize', cols, rows });
  }

  function renderTabs() {
    tabListEl.textContent = '';
    let activeExited = null;
    for (const tab of tabs) {
      const btn = document.createElement('div');
      btn.className = 'term-tab';
      btn.setAttribute('role', 'tab');
      btn.setAttribute('tabindex', '0');
      btn.setAttribute('aria-selected', String(tab.id === activeTabId));
      btn.dataset.tabId = String(tab.id);

      const title = document.createElement('span');
      title.className = 'term-tab-title';
      title.textContent = tab.title || ('Tab ' + tab.id);
      btn.appendChild(title);

      const close = document.createElement('button');
      close.type = 'button';
      close.className = 'term-tab-close';
      close.setAttribute('aria-label', 'Close tab ' + (tab.title || tab.id));
      close.textContent = '×';
      close.addEventListener('click', (e) => {
        e.stopPropagation();
        enqueue({ t: 'close_tab', id: tab.id });
        focusInput();
      });
      btn.appendChild(close);

      btn.addEventListener('click', () => {
        enqueue({ t: 'select_tab', id: tab.id });
        focusInput();
      });
      tabListEl.appendChild(btn);

      if (tab.id === activeTabId) {
        activeExited = tab.exited;
      }
    }
    restartBtn.hidden = activeExited === null || activeExited === undefined;
  }

  function buildRowElement(rowIdx, runs, cursorCol) {
    const div = document.createElement('div');
    div.className = 'term-row';
    div.dataset.row = String(rowIdx);
    const line = document.createElement('span');
    line.className = 'term-row-line';

    const list = Array.isArray(runs) ? runs : [];
    if (cursorCol < 0) {
      if (list.length === 0) {
        line.textContent = ' ';
      } else {
        for (const run of list) {
          const text = run[0] || '';
          const css = run[1] || '';
          const link = run[2] || '';
          if (link && /^https?:\/\//i.test(link)) {
            const a = document.createElement('a');
            a.className = 'term-link';
            a.href = link;
            a.target = '_blank';
            a.rel = 'noopener noreferrer';
            if (css) a.setAttribute('style', css);
            a.textContent = text;
            line.appendChild(a);
          } else if (css) {
            const span = document.createElement('span');
            span.setAttribute('style', css);
            span.textContent = text;
            line.appendChild(span);
          } else {
            line.appendChild(document.createTextNode(text));
          }
        }
      }
      div.appendChild(line);
      div.appendChild(document.createTextNode('\n'));
      return div;
    }

    // Active cursor row: split run containing `cursorCol` to highlight the cursor cell.
    let col = 0;
    let placed = false;
    for (const run of list) {
      const text = run[0] || '';
      const css = run[1] || '';
      const chars = Array.from(text);
      if (!placed && cursorCol >= col && cursorCol < col + chars.length) {
        const offset = cursorCol - col;
        const before = chars.slice(0, offset).join('');
        const at = chars[offset] || ' ';
        const after = chars.slice(offset + 1).join('');
        if (before) {
          const s = document.createElement('span');
          if (css) s.setAttribute('style', css);
          s.textContent = before;
          line.appendChild(s);
        }
        const cur = document.createElement('span');
        cur.className = 'term-cursor';
        cur.textContent = at;
        line.appendChild(cur);
        if (after) {
          const s = document.createElement('span');
          if (css) s.setAttribute('style', css);
          s.textContent = after;
          line.appendChild(s);
        }
        placed = true;
      } else if (css) {
        const span = document.createElement('span');
        span.setAttribute('style', css);
        span.textContent = text;
        line.appendChild(span);
      } else {
        line.appendChild(document.createTextNode(text));
      }
      col += chars.length;
    }
    if (!placed) {
      if (cursorCol > col) {
        line.appendChild(document.createTextNode(' '.repeat(cursorCol - col)));
      }
      const cur = document.createElement('span');
      cur.className = 'term-cursor';
      cur.textContent = ' ';
      line.appendChild(cur);
    }
    div.appendChild(line);
    div.appendChild(document.createTextNode('\n'));
    return div;
  }

  function applyFrame(msg) {
    if (msg.tab && activeTabId && msg.tab !== activeTabId) {
      return;
    }
    appCursor = Boolean(msg.app_cursor);
    const prevCursorRow = cursorState.row;
    const prevCursorVis = cursorState.visible;
    cursorState = msg.cursor || { row: 0, col: 0, visible: false };
    const total = Number(msg.total) || 0;

    if (msg.exited !== null && msg.exited !== undefined) {
      restartBtn.hidden = false;
    } else {
      restartBtn.hidden = true;
    }
    viewportEl.dataset.state = msg.state || (msg.exited !== null && msg.exited !== undefined ? 'exited' : 'busy');
    viewportEl.dataset.promptSeq = String(msg.prompt_seq ?? 0);
    screenEl.dataset.alternate = String(Boolean(msg.alt));
    if (typeof msg.cwd === 'string') {
      viewportEl.dataset.cwd = msg.cwd;
      if (promptPathEl) promptPathEl.textContent = msg.cwd;
    }

    if (msg.full) {
      rowData = new Array(total);
      for (const entry of msg.lines || []) {
        rowData[entry[0]] = entry[1];
      }
      const frag = document.createDocumentFragment();
      for (let r = 0; r < total; r++) {
        const curCol = (cursorState.visible && r === cursorState.row) ? cursorState.col : -1;
        frag.appendChild(buildRowElement(r, rowData[r], curCol));
      }
      screenEl.textContent = '';
      screenEl.appendChild(frag);
      currentTotalRows = total;
    } else {
      const dirtyRows = new Set();
      for (const entry of msg.lines || []) {
        rowData[entry[0]] = entry[1];
        dirtyRows.add(entry[0]);
      }
      if (prevCursorVis && prevCursorRow < total) dirtyRows.add(prevCursorRow);
      if (cursorState.visible && cursorState.row < total) dirtyRows.add(cursorState.row);

      while (screenEl.children.length > total) {
        screenEl.lastElementChild.remove();
      }
      if (rowData.length > total) rowData.length = total;
      while (screenEl.children.length < total) {
        const r = screenEl.children.length;
        const curCol = (cursorState.visible && r === cursorState.row) ? cursorState.col : -1;
        screenEl.appendChild(buildRowElement(r, rowData[r], curCol));
        dirtyRows.delete(r);
      }
      for (const r of dirtyRows) {
        if (r >= 0 && r < screenEl.children.length) {
          const curCol = (cursorState.visible && r === cursorState.row) ? cursorState.col : -1;
          screenEl.replaceChild(buildRowElement(r, rowData[r], curCol), screenEl.children[r]);
        }
      }
      currentTotalRows = total;
    }

    if (stickToBottom) {
      viewportEl.scrollTop = viewportEl.scrollHeight;
    }
  }

  function handleMessage(msg) {
    if (!msg || typeof msg !== 'object') return;
    if (msg.t === 'chunk') {
      let bucket = chunkBuckets.get(msg.id);
      if (!bucket) {
        bucket = new Array(msg.n);
        chunkBuckets.set(msg.id, bucket);
        if (chunkBuckets.size > 8) {
          const oldest = chunkBuckets.keys().next().value;
          chunkBuckets.delete(oldest);
        }
      }
      bucket[msg.i] = msg.d;
      let complete = true;
      for (let i = 0; i < msg.n; i++) {
        if (typeof bucket[i] !== 'string') {
          complete = false;
          break;
        }
      }
      if (complete) {
        chunkBuckets.delete(msg.id);
        try {
          handleMessage(JSON.parse(bucket.join('')));
        } catch {
          // ignore malformed chunk assembly
        }
      }
      return;
    }
    if (msg.t === 'focus') {
      focusInput();
      return;
    }
    if (msg.t === 'tabs') {
      activeTabId = msg.active || 0;
      tabs = Array.isArray(msg.tabs) ? msg.tabs : [];
      renderTabs();
      return;
    }
    if (msg.t === 'frame') {
      applyFrame(msg);
    }
  }

  window.gui.onmessage = (raw) => {
    try {
      handleMessage(JSON.parse(raw));
    } catch {
      // ignore non-JSON frames
    }
  };

  function encodeKeyEvent(e) {
    if (e.metaKey) return null;
    // Terminal tab shortcuts: Alt+T (new tab), Alt+W (close tab), Alt+1..9 (select tab).
    if (e.altKey && !e.ctrlKey) {
      const k = e.key.toLowerCase();
      if (k === 't') {
        e.preventDefault();
        enqueue({ t: 'new_tab' });
        return '';
      }
      if (k === 'w') {
        e.preventDefault();
        if (activeTabId) enqueue({ t: 'close_tab', id: activeTabId });
        return '';
      }
      if (k >= '1' && k <= '9') {
        const idx = Number(k) - 1;
        if (tabs[idx]) {
          e.preventDefault();
          enqueue({ t: 'select_tab', id: tabs[idx].id });
          return '';
        }
      }
    }

    // Copy selected text on Ctrl+Shift+C; plain Ctrl+C always sends SIGINT (\x03).
    if (e.ctrlKey && (e.key === 'c' || e.key === 'C')) {
      e.preventDefault();
      if (e.shiftKey) {
        const sel = window.getSelection()?.toString() || '';
        if (sel) sendCopy(sel);
        return '';
      }
      return '\x03';
    }
    if (e.ctrlKey && e.shiftKey && (e.key === 'v' || e.key === 'V')) {
      e.preventDefault();
      enqueue({ t: 'paste' });
      return '';
    }
    if (e.ctrlKey && !e.altKey) {
      const k = e.key.toLowerCase();
      if (k.length === 1 && k >= 'a' && k <= 'z') {
        if (k === 'v') return null; // let paste event / compositor handle Ctrl+V
        e.preventDefault();
        return String.fromCharCode(k.charCodeAt(0) - 96);
      }
      if (e.key === '[') { e.preventDefault(); return '\x1b'; }
      if (e.key === '\\') { e.preventDefault(); return '\x1c'; }
      if (e.key === ']') { e.preventDefault(); return '\x1d'; }
      if (e.key === ' ') { e.preventDefault(); return '\x00'; }
    }

    const prefix = appCursor ? '\x1bO' : '\x1b[';
    switch (e.key) {
      case 'Enter': e.preventDefault(); return '\r';
      case 'Backspace': e.preventDefault(); return '\x7f';
      case 'Tab': e.preventDefault(); return e.shiftKey ? '\x1b[Z' : '\t';
      case 'Escape': e.preventDefault(); return '\x1b';
      case 'ArrowUp': e.preventDefault(); return prefix + 'A';
      case 'ArrowDown': e.preventDefault(); return prefix + 'B';
      case 'ArrowRight': e.preventDefault(); return prefix + 'C';
      case 'ArrowLeft': e.preventDefault(); return prefix + 'D';
      case 'Home': e.preventDefault(); return '\x1b[H';
      case 'End': e.preventDefault(); return '\x1b[F';
      case 'Delete': e.preventDefault(); return '\x1b[3~';
      case 'PageUp': e.preventDefault(); return '\x1b[5~';
      case 'PageDown': e.preventDefault(); return '\x1b[6~';
      default:
        if (e.key.length === 1 && !e.ctrlKey && !e.metaKey) {
          e.preventDefault();
          return e.altKey ? ('\x1b' + e.key) : e.key;
        }
        return null;
    }
  }

  inputEl.addEventListener('compositionstart', () => { composing = true; });
  inputEl.addEventListener('compositionend', () => {
    composing = false;
    if (inputEl.value) {
      sendInput(inputEl.value);
      inputEl.value = '';
    }
  });
  inputEl.addEventListener('input', () => {
    if (composing) return;
    if (inputEl.value) {
      sendInput(inputEl.value);
      inputEl.value = '';
    }
  });

  document.addEventListener('keydown', (e) => {
    if (composing || e.isComposing || e.keyCode === 229) return;
    // Allow keyboard navigation on tab buttons when explicitly focused there.
    if (document.activeElement && document.activeElement.closest('.term-tabs')) {
      if (e.key === 'Enter' || e.key === ' ') return;
    }
    const seq = encodeKeyEvent(e);
    if (seq !== null) {
      if (seq.length > 0) sendInput(seq);
      focusInput();
    }
  });

  viewportEl.addEventListener('scroll', () => {
    const gap = viewportEl.scrollHeight - viewportEl.scrollTop - viewportEl.clientHeight;
    stickToBottom = gap < 24;
  });

  const focusViewportInput = () => {
    const sel = window.getSelection()?.toString() || '';
    if (!sel) focusInput();
  };
  viewportEl.addEventListener('pointerup', focusViewportInput);
  viewportEl.addEventListener('click', focusViewportInput);

  newTabBtn.addEventListener('click', () => {
    enqueue({ t: 'new_tab' });
    focusInput();
  });

  restartBtn.addEventListener('click', () => {
    if (activeTabId) enqueue({ t: 'restart_tab', id: activeTabId });
    focusInput();
  });

  if (touchKeysEl) {
    touchKeysEl.addEventListener('click', (e) => {
      const btn = e.target.closest('button[data-seq]');
      if (!btn) return;
      const raw = btn.getAttribute('data-seq') || '';
      const decoded = raw
        .replace(/\\t/g, '\t')
        .replace(/\\x1b/g, '\x1b')
        .replace(/\\x03/g, '\x03')
        .replace(/\\x04/g, '\x04');
      sendInput(decoded);
      focusInput();
    });
  }

  window.addEventListener('focus', () => focusInput());

  let resizeTimer = null;
  if (typeof ResizeObserver === 'function') {
    new ResizeObserver(() => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => reportSize(false), 40);
    }).observe(viewportEl);
  }

  // Initial handshake once layout settles. Only focus the hidden input if this
  // surface already owns focus so a late-booting terminal never steals focus
  // from another explicitly opened window (e.g. Mounts or Files).
  requestAnimationFrame(() => {
    reportSize(true);
    if (document.hasFocus()) focusInput();
  });
})();

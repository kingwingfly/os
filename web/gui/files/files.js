(() => {
  'use strict';

  const MAX_ASSEMBLED_BYTES = 256 * 1024;
  const SVG_NS = 'http://www.w3.org/2000/svg';

  const ICONS = {
    directory: ['directory', 'M3 7V5h6l2 2h10v13H3Z'],
    image: ['Image', 'M3 3h18v18H3ZM3 17l5-6 4 5 3-3 6 6M15 7h.01'],
    video: ['Video', 'M3 5h14v14H3ZM17 9l4-3v12l-4-3M8 9l4 3-4 3Z'],
    audio: ['Audio', 'M9 18V5l11-2v13M9 8l11-2M9 18a3 3 0 1 1-3-3h3M20 16a3 3 0 1 1-3-3h3'],
    game: ['Game', 'M6 7h12l3 11-3 1-4-4h-4l-4 4-3-1ZM6 11h6M9 8v6M16 10h.01M18 13h.01'],
    slides: ['Slides', 'M3 4h18v13H3ZM12 17v4M7 21h10M7 9h10M7 12h6'],
    markdown: ['Markdown', 'M3 4h18v16H3ZM6 15V9l3 3 3-3v6M17 9v6l-2-2M17 15l2-2'],
    pdf: ['PDF', 'M5 3h10l4 4v14H5ZM14 3v5h5M8 12h8M8 16h6'],
    archive: ['Archive', 'M4 4h16v4H4ZM5 8v12h14V8M10 12h4M12 3v1M12 9v2M12 13v2'],
    text: ['Text file', 'M5 3h10l4 4v14H5ZM14 3v5h5M8 12h8M8 16h6'],
  };

  function makeIcon(kind, directory) {
    const [label, d] = directory ? ICONS.directory : (ICONS[kind] || ICONS.text);
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('class', 'file-icon');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '1.5');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', label);
    const path = document.createElementNS(SVG_NS, 'path');
    path.setAttribute('d', d);
    svg.appendChild(path);
    return svg;
  }

  const locationInput = document.querySelector('.location');
  const refreshBtn = document.querySelector('.files-refresh');
  const uploadBtn = document.querySelector('.files-upload');
  const mountsBtn = document.querySelector('.files-mounts');
  const noticeEl = document.querySelector('.file-notice');
  const progressBox = document.querySelector('.file-progress');
  const progressPre = progressBox.querySelector('pre');
  const progressActionBtn = progressBox.querySelector('.progress-action');
  const filesEl = document.querySelector('.files');

  let currentCwd = '/';
  let editing = false;
  let uploading = false;
  let renderSeq = 0;
  const scrollPositions = new Map();

  // Bounded chunk reassembler matching gui_doc::chunk_document_message.
  const chunks = new Map();
  let chunkBytes = 0;

  function send(msg) {
    window.gui?.send(JSON.stringify(msg));
  }

  function measureNames() {
    for (const el of filesEl.querySelectorAll('.filename')) {
      const extra = Math.ceil(el.scrollWidth - el.clientWidth);
      if (extra > 2) {
        el.dataset.overflow = '';
        el.style.setProperty('--overflow', `-${extra}px`);
        el.style.setProperty('--duration', `${Math.min(18, Math.max(4, extra / 28 + 2.5)).toFixed(1)}s`);
      } else {
        delete el.dataset.overflow;
        el.style.removeProperty('--overflow');
        el.style.removeProperty('--duration');
      }
    }
  }

  function updateProgress(text, isUploading) {
    uploading = Boolean(isUploading);
    uploadBtn.disabled = uploading;
    const str = typeof text === 'string' ? text : '';
    progressPre.textContent = str;
    progressBox.hidden = str.length === 0;
    if (uploading) {
      progressActionBtn.textContent = 'Cancel';
      progressActionBtn.removeAttribute('aria-label');
    } else {
      progressActionBtn.textContent = '×';
      progressActionBtn.setAttribute('aria-label', 'Dismiss');
    }
  }

  function renderState(msg) {
    const prevCwd = currentCwd;
    if (filesEl.clientHeight > 0 && prevCwd) {
      scrollPositions.set(prevCwd, {
        top: filesEl.scrollTop,
        left: filesEl.scrollLeft,
      });
    }

    const nextCwd = typeof msg.cwd === 'string' ? msg.cwd : '/';
    const targetScroll = msg.keep_scroll && nextCwd === prevCwd
      ? { top: filesEl.scrollTop, left: filesEl.scrollLeft }
      : (scrollPositions.get(nextCwd) || { top: 0, left: 0 });
    if (msg.keep_scroll && nextCwd === prevCwd) {
      scrollPositions.set(nextCwd, targetScroll);
    }

    currentCwd = nextCwd;
    if (!editing || msg.keep_scroll || nextCwd !== prevCwd) {
      editing = false;
      locationInput.value = nextCwd;
    }

    if (typeof msg.notice === 'string') {
      noticeEl.textContent = msg.notice;
    }

    const frag = document.createDocumentFragment();
    if (msg.can_up) {
      const upBtn = document.createElement('button');
      upBtn.type = 'button';
      upBtn.className = 'file';
      upBtn.dataset.kind = 'directory';
      const iconWrap = document.createElement('span');
      iconWrap.className = 'file-kind';
      iconWrap.appendChild(makeIcon('directory', true));
      const label = document.createElement('span');
      label.textContent = '../';
      upBtn.append(iconWrap, label);
      upBtn.addEventListener('click', () => send({ t: 'up' }));
      frag.appendChild(upBtn);
    }

    const entries = Array.isArray(msg.entries) ? msg.entries : [];
    for (const entry of entries) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'file';
      if (entry.link != null) btn.classList.add('link');
      if (entry.denied) {
        btn.classList.add('denied');
        btn.setAttribute('aria-disabled', 'true');
      }
      btn.dataset.kind = entry.directory ? 'directory' : (entry.kind || 'text');
      if (entry.title) btn.title = entry.title;

      const iconWrap = document.createElement('span');
      iconWrap.className = 'file-kind';
      iconWrap.appendChild(makeIcon(entry.kind, entry.directory));

      const nameWrap = document.createElement('span');
      nameWrap.className = 'filename';
      const nameText = document.createElement('span');
      nameText.className = 'filename-text';
      nameText.textContent = entry.directory ? `${entry.name}/` : entry.name;
      nameWrap.appendChild(nameText);

      const sizeEl = document.createElement('span');
      sizeEl.className = 'file-size';
      sizeEl.textContent = entry.size_label || '';

      btn.append(iconWrap, nameWrap, sizeEl);
      btn.addEventListener('click', () => send({ t: 'open', name: entry.name }));
      frag.appendChild(btn);
    }

    const errText = typeof msg.error === 'string' ? msg.error : '';
    const errEl = document.createElement('p');
    errEl.className = 'directory-error';
    errEl.setAttribute('role', 'status');
    errEl.textContent = errText;
    frag.appendChild(errEl);

    if (entries.length === 0 && !errText) {
      const emptyEl = document.createElement('p');
      emptyEl.className = 'empty';
      emptyEl.textContent = 'This directory is empty. Drop files here, or upload some.';
      frag.appendChild(emptyEl);
    }

    filesEl.replaceChildren(frag);
    const seq = ++renderSeq;
    requestAnimationFrame(() => {
      if (renderSeq !== seq) return;
      filesEl.scrollLeft = targetScroll.left;
      filesEl.scrollTop = targetScroll.top;
      measureNames();
    });
  }

  function dispatch(msg) {
    if (!msg || typeof msg !== 'object') return;
    if (msg.t === 'chunk') {
      const { id, i, n, d } = msg;
      if (typeof id !== 'number' || typeof i !== 'number' || typeof n !== 'number' || typeof d !== 'string') return;
      if (n <= 0 || n > 256 || i < 0 || i >= n) return;
      let bucket = chunks.get(id);
      if (!bucket || bucket.parts.length !== n) {
        if (bucket) chunkBytes = Math.max(0, chunkBytes - bucket.bytes);
        bucket = { parts: new Array(n).fill(null), received: 0, bytes: 0 };
        chunks.set(id, bucket);
      }
      if (bucket.parts[i] !== null) return;
      if (chunkBytes + d.length > MAX_ASSEMBLED_BYTES) {
        chunks.clear();
        chunkBytes = 0;
        return;
      }
      bucket.parts[i] = d;
      bucket.received += 1;
      bucket.bytes += d.length;
      chunkBytes += d.length;
      if (bucket.received === n) {
        chunks.delete(id);
        chunkBytes = Math.max(0, chunkBytes - bucket.bytes);
        try {
          dispatch(JSON.parse(bucket.parts.join('')));
        } catch {
          // Ignore malformed reassembled payload.
        }
      }
      return;
    }
    switch (msg.t) {
      case 'state':
        renderState(msg);
        break;
      case 'notice':
        noticeEl.textContent = typeof msg.text === 'string' ? msg.text : '';
        if (!editing) {
          locationInput.value = currentCwd;
        }
        break;
      case 'progress':
        updateProgress(msg.text, msg.uploading);
        break;
      case 'focus':
        break;
      default:
        break;
    }
  }

  locationInput.addEventListener('input', () => {
    editing = true;
  });
  locationInput.addEventListener('keydown', e => {
    if (e.isComposing) return;
    if (e.key === 'Enter') {
      e.preventDefault();
      editing = false;
      const typed = locationInput.value.trim();
      if (typed) send({ t: 'nav', path: typed });
      else locationInput.value = currentCwd;
    } else if (e.key === 'Escape') {
      e.preventDefault();
      editing = false;
      locationInput.value = currentCwd;
    }
  });
  locationInput.addEventListener('blur', () => {
    editing = false;
    locationInput.value = currentCwd;
  });

  refreshBtn.addEventListener('click', () => {
    editing = false;
    locationInput.value = currentCwd;
    send({ t: 'refresh' });
  });
  uploadBtn.addEventListener('click', () => {
    send({ t: 'upload' });
  });
  mountsBtn.addEventListener('click', () => {
    send({ t: 'open_mounts' });
  });
  progressActionBtn.addEventListener('click', () => {
    if (uploading) send({ t: 'cancel_upload' });
    else send({ t: 'dismiss_progress' });
  });

  document.addEventListener('keydown', e => {
    if (e.key === 'F5' && !e.ctrlKey && !e.metaKey && !e.altKey) {
      e.preventDefault();
      editing = false;
      locationInput.value = currentCwd;
      send({ t: 'refresh' });
    }
  });

  if (typeof ResizeObserver !== 'undefined') {
    new ResizeObserver(() => measureNames()).observe(filesEl);
  }

  window.gui.onmessage = raw => {
    try {
      dispatch(JSON.parse(raw));
    } catch {
      // Ignore invalid host message.
    }
  };

  send({ t: 'ready' });
})();

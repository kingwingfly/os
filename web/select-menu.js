// One select-only combobox for the desktop, dialogs and dynamically created apps.
// Keep the original select for form values, validation and existing change handlers.
let installed = false, sequence = 0, active;
const setAttribute = (node, name, value) => { if (node.getAttribute(name) !== String(value)) node.setAttribute(name, value); };

export function installSelectMenus() {
  if (installed) return;
  installed = true;
  const controls = new Map();
  function enhance(select) {
    if (controls.has(select) || select.multiple || select.size > 1) return;
    const controller = new AbortController(), listen = (node, event, fn) => node.addEventListener(event, fn, { signal: controller.signal });
    const button = document.createElement('button'), caption = document.createElement('span'), arrow = document.createElement('span');
    const menu = document.createElement('div'), id = `os-select-${++sequence}`;
    const originalTabIndex = select.getAttribute('tabindex'), originalHidden = select.getAttribute('aria-hidden');
    button.type = 'button'; button.className = 'os-select'; button.setAttribute('role', 'combobox');
    button.setAttribute('aria-haspopup', 'listbox'); button.setAttribute('aria-expanded', 'false');
    caption.id = id + '-value'; button.setAttribute('aria-describedby', caption.id);
    arrow.textContent = '⌄'; arrow.setAttribute('aria-hidden', 'true'); button.append(caption, arrow);
    menu.className = 'os-select-menu'; menu.id = id; menu.setAttribute('role', 'listbox');
    select.classList.add('os-select-native'); select.tabIndex = -1; select.setAttribute('aria-hidden', 'true');
    select.after(button);
    let options = [], rows = [], cursor = -1, search = '', searched = 0;
    const disabled = option => option.disabled || option.parentElement?.disabled;
    function label() {
      if (select.getAttribute('aria-label')) return select.getAttribute('aria-label');
      if (select.hasAttribute('aria-labelledby')) return select.getAttribute('aria-labelledby').split(/\s+/).map(id => document.getElementById(id)?.textContent ?? '').join(' ').trim();
      return [...select.labels ?? []].map(label => {
        const copy = label.cloneNode(true); copy.querySelectorAll('select,.os-select,small').forEach(node => node.remove()); return copy.textContent.trim();
      }).join(' ') || 'Choose an option';
    }
    function sync() {
      const text = select.selectedOptions[0]?.label || '—';
      if (caption.textContent !== text) caption.textContent = text;
      button.disabled = select.matches(':disabled') || ![...select.options].some(option => !disabled(option));
      setAttribute(button, 'aria-label', label()); setAttribute(button, 'aria-required', select.required);
      if (select.validity.valid) button.removeAttribute('aria-invalid');
      if (active === control) { if (button.disabled) close(); else { render(); position(); } }
    }
    function highlight(index) {
      cursor = index;
      rows.forEach((row, i) => row.classList.toggle('active', i === index));
      if (rows[index]) {
        button.setAttribute('aria-activedescendant', rows[index].id);
        rows[index].scrollIntoView({ block: 'nearest' });
      } else button.removeAttribute('aria-activedescendant');
    }
    function render() {
      options = [...select.options]; rows = []; menu.replaceChildren(); menu.setAttribute('aria-label', label());
      for (const [index, option] of options.entries()) {
        const row = document.createElement('div'); row.id = `${id}-${index}`; row.setAttribute('role', 'option');
        row.setAttribute('aria-label', option.label); // The decorative checkmark is not part of the option name.
        row.setAttribute('aria-selected', String(option.selected)); row.setAttribute('aria-disabled', String(!!disabled(option)));
        row.textContent = option.label; row.onpointerdown = event => event.preventDefault();
        row.onpointermove = () => { if (!disabled(option) && cursor !== index) highlight(index); };
        row.onclick = () => choose(index); rows.push(row); menu.append(row);
      }
      highlight(options[cursor] && !disabled(options[cursor]) ? cursor : select.selectedIndex);
    }
    function position() {
      if (active !== control) return;
      const bounds = button.getBoundingClientRect(), viewport = window.visualViewport;
      if (!bounds.width || !bounds.height || !button.isConnected) { close(); return; }
      const left = viewport?.offsetLeft ?? 0, top = viewport?.offsetTop ?? 0;
      const width = viewport?.width ?? innerWidth, height = viewport?.height ?? innerHeight;
      const menuWidth = Math.min(Math.max(bounds.width, 180), width - 16);
      menu.style.width = `${menuWidth}px`;
      menu.style.left = `${Math.max(left + 8, Math.min(bounds.left, left + width - menuWidth - 8))}px`;
      const below = top + height - bounds.bottom - 12, above = bounds.top - top - 12;
      const up = below < Math.min(menu.scrollHeight, 220) && above > below;
      const available = Math.max(40, Math.min(320, up ? above : below));
      menu.style.maxHeight = `${available}px`;
      menu.style.top = `${up ? bounds.top - Math.min(menu.scrollHeight, available) - 4 : bounds.bottom + 4}px`;
    }
    function close() {
      if (active !== control) return;
      active = undefined; button.setAttribute('aria-expanded', 'false');
      button.removeAttribute('aria-activedescendant'); button.removeAttribute('aria-controls');
      if (menu.hidePopover) { try { menu.hidePopover(); } catch { /* Already removed by its app. */ } }
      menu.remove(); search = '';
    }
    function open() {
      if (button.disabled) return;
      active?.close(); active = control; cursor = select.selectedIndex; search = '';
      // Staying inside a modal's DOM keeps the menu interactive under its focus
      // and inert rules; popover places it above both dialogs and desktop windows.
      (select.closest('dialog') ?? document.body).append(menu);
      if (menu.showPopover) { menu.popover = 'manual'; menu.showPopover(); }
      button.setAttribute('aria-expanded', 'true'); button.setAttribute('aria-controls', id);
      render(); position(); highlight(cursor);
    }
    function choose(index) {
      if (!options[index] || disabled(options[index])) return;
      const changed = select.selectedIndex !== index; select.selectedIndex = index;
      close(); sync(); button.focus({ preventScroll: true });
      if (changed) { select.dispatchEvent(new Event('input', { bubbles: true })); select.dispatchEvent(new Event('change', { bubbles: true })); }
    }
    function step(delta) {
      let index = cursor;
      for (let count = 0; count < options.length; count++) {
        index = (index + delta + options.length) % options.length;
        if (!disabled(options[index])) { highlight(index); break; }
      }
    }
    listen(button, 'click', () => active === control ? close() : open());
    listen(button, 'keydown', event => {
      if (event.isComposing || event.ctrlKey || event.metaKey) return;
      const opened = active === control;
      if (event.key === 'Escape') { if (opened) { event.preventDefault(); event.stopPropagation(); close(); } return; }
      if (event.key === 'Tab') { if (opened) choose(cursor); return; }
      if (['Enter', ' ', 'ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) {
        event.preventDefault(); event.stopPropagation();
        if (!opened) open();
        if (event.key === 'Home') { cursor = -1; step(1); }
        else if (event.key === 'End') { cursor = 0; step(-1); }
        else if (opened && event.key === 'ArrowDown') step(1);
        else if (opened && event.key === 'ArrowUp') step(-1);
        else if (opened && (event.key === 'Enter' || event.key === ' ')) choose(cursor);
      } else if (event.key.length === 1 && !event.altKey) {
        event.preventDefault(); const now = performance.now();
        search = now - searched > 700 ? event.key : search + event.key; searched = now;
        options = [...select.options];
        const repeated = [...search].every(char => char === search[0]);
        const prefix = (repeated ? search[0] : search).toLocaleLowerCase();
        const start = repeated ? (opened ? cursor : select.selectedIndex) + 1 : 0;
        for (let offset = 0; offset < options.length; offset++) {
          const index = (start + offset) % options.length;
          if (!disabled(options[index]) && options[index].label.toLocaleLowerCase().startsWith(prefix)) {
            if (opened) highlight(index); else { const typed = search; choose(index); search = typed; } break;
          }
        }
      }
    });
    listen(select, 'change', sync);
    listen(select, 'focus', () => button.focus({ preventScroll: true }));
    listen(select, 'invalid', event => { event.preventDefault(); button.setAttribute('aria-invalid', 'true'); button.focus(); });
    if (select.form) listen(select.form, 'reset', () => queueMicrotask(sync));
    const observer = new MutationObserver(sync); observer.observe(select, { childList: true, subtree: true, attributes: true, characterData: true });
    const resize = new ResizeObserver(position); resize.observe(button);
    // Frameworks restore form state by assigning properties. Those assignments
    // emit neither change events nor DOM mutations (for example a reopened deck's
    // slide theme). Observe this element's native setters without changing the
    // prototype or emitting synthetic user changes.
    const properties = new Map();
    let scheduled = false;
    for (const name of ['value', 'selectedIndex']) {
      const own = Object.getOwnPropertyDescriptor(select, name);
      const descriptor = own ?? Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, name);
      if (!descriptor?.get || !descriptor?.set || own?.configurable === false) continue;
      properties.set(name, own);
      Object.defineProperty(select, name, { configurable: true, enumerable: descriptor.enumerable,
        get() { return descriptor.get.call(this); },
        set(value) {
          descriptor.set.call(this, value);
          if (!scheduled) { scheduled = true; queueMicrotask(() => { scheduled = false; if (!controller.signal.aborted) sync(); }); }
        },
      });
    }
    const control = { button, menu, close, position, sync, destroy() {
      close(); observer.disconnect(); resize.disconnect(); controller.abort(); button.remove();
      for (const [name, descriptor] of properties) { if (descriptor) Object.defineProperty(select, name, descriptor); else delete select[name]; }
      select.classList.remove('os-select-native');
      for (const [name, value] of [['tabindex', originalTabIndex], ['aria-hidden', originalHidden]]) {
        if (value === null) select.removeAttribute(name); else select.setAttribute(name, value);
      }
    } };
    controls.set(select, control); sync();
  }
  const scan = root => {
    if (root.nodeType !== Node.ELEMENT_NODE && root !== document) return;
    if (root.matches?.('select')) enhance(root);
    root.querySelectorAll('select').forEach(enhance);
  };
  scan(document);
  new MutationObserver(records => {
    for (const record of records) {
      for (const node of record.addedNodes) scan(node);
      if (record.type === 'attributes') for (const [select, control] of controls) if (record.target.contains(select)) control.sync();
    }
    for (const [select, control] of controls) if (!select.isConnected) { control.destroy(); controls.delete(select); }
    active?.position();
  }).observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ['open', 'hidden', 'disabled'] });
  document.addEventListener('pointerdown', event => { if (active && !active.button.contains(event.target) && !active.menu.contains(event.target)) active.close(); }, true);
  document.addEventListener('focusin', event => { if (active && event.target !== active.button && !active.menu.contains(event.target)) active.close(); });
  document.addEventListener('close', () => active?.close(), true);
  document.addEventListener('scroll', event => { if (active && !active.menu.contains(event.target)) active.position(); }, true);
  window.addEventListener('resize', () => active?.position());
  window.visualViewport?.addEventListener('resize', () => active?.position());
  window.visualViewport?.addEventListener('scroll', () => active?.position());
}

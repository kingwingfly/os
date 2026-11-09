// Preserve preferences when an existing installation adopts the OS name. New values win;
// remove an old key only after its replacement was stored successfully.
export function migratePreferences(storage) {
  for (const [old, current] of [
    ['terminal-desktop', 'os-desktop'],
    ['terminal-tabs', 'os-tabs'],
    ['terminal-files', 'os-files'],
    ['terminal-places', 'os-places'],
    ['terminal-slide-theme', 'os-slide-theme'],
    ['terminal-notes-size', 'os-notes-size'],
  ]) {
    const value = storage.getItem(old);
    if (value === null) continue;
    if (storage.getItem(current) === null) storage.setItem(current, value);
    storage.removeItem(old);
  }
}

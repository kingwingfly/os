import { test } from 'node:test';
import assert from 'node:assert/strict';
import { migratePreferences } from '../web/compat.mjs';

const storage = entries => {
  const values = new Map(entries);
  return { values, getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key) };
};
test('OS preference migration preserves values and respects already migrated preferences', () => {
  const saved = storage([['terminal-desktop', '{"terminal":{"x":12}}'],
    ['terminal-tabs', '[{"cwd":"/guest"}]'], ['terminal-places', 'old'], ['os-places', 'new'],
    ['terminal-slide-theme', 'dark'], ['terminal-notes-size', '18'], ['unrelated', 'keep']]);
  migratePreferences(saved);
  assert.deepEqual(Object.fromEntries(saved.values), { 'os-desktop': '{"terminal":{"x":12}}',
    'os-tabs': '[{"cwd":"/guest"}]', 'os-places': 'new', 'os-slide-theme': 'dark',
    'os-notes-size': '18', unrelated: 'keep' });
  migratePreferences(saved);
  assert.equal(saved.values.size, 6);
});
test('a failed preference migration retains the original value for a later retry', () => {
  const saved = storage([['terminal-desktop', 'layout']]);
  saved.setItem = () => { throw new Error('quota'); };
  assert.throws(() => migratePreferences(saved), /quota/);
  assert.equal(saved.getItem('terminal-desktop'), 'layout');
});

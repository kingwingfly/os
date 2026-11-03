// What specs do in the page, shared, so a change to the Files or the prompt is one change here.
import { expect } from '@playwright/test';

// The Files go to `path` of their own: its location typed (crates/frontend/src/files.rs).
export async function browse(page, path) {
  const location = page.getByRole('textbox', { name: 'Location' });
  await location.fill(path); await location.press('Enter');
  await expect(location).toHaveValue(path);
}

// The terminal's working directory, as its prompt shows it.
export const promptPath = page => page.locator('label[for=command] .prompt-path');

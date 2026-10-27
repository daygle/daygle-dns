// The console's colour theme: `light`, `dark`, or `system` (follow the
// device). Like the date settings, the user's own choice wins over the
// server default (Settings → General); see datetime.svelte.js, which loads
// both. The theme is applied as `data-theme` on <html>, which app.css keys
// its colours on.
//
// The last theme used is kept in this browser so the sign-in page and a
// reload start in the right colours (index.html reads it before the
// console loads).

import { display } from './datetime.svelte.js';

export const THEME_OPTIONS = [
  ['system', 'Match the Device'],
  ['light', 'Light'],
  ['dark', 'Dark'],
];
const STORAGE_KEY = 'daygle_theme';

// A theme being tried out in the Account page, else null.
let preview = $state(null);

/** Try a theme without saving it; null goes back to the saved one. */
export function previewTheme(theme) {
  preview = theme || null;
}

/** The saved theme (`system`, `light` or `dark`): the user's, else the server default. */
function savedTheme() {
  return display.mine?.theme || display.defaults.theme || 'dark';
}

const lightQuery = typeof window !== 'undefined' && window.matchMedia
  ? window.matchMedia('(prefers-color-scheme: light)')
  : null;
let deviceLight = $state(lightQuery?.matches ?? false);
lightQuery?.addEventListener?.('change', (e) => (deviceLight = e.matches));

function resolve(theme) {
  if (theme === 'system') return deviceLight ? 'light' : 'dark';
  return theme === 'light' ? 'light' : 'dark';
}

$effect.root(() => {
  $effect(() => {
    const saved = savedTheme();
    document.documentElement.dataset.theme = resolve(preview || saved);
    try {
      localStorage.setItem(STORAGE_KEY, saved);
    } catch (_) {
      /* storage unavailable */
    }
  });
});

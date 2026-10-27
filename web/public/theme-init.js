// Start in the last theme used in this browser (see src/theme.svelte.js) so
// the page does not flash dark before the console loads. A file rather than
// an inline script, which the console's Content-Security-Policy refuses.
try {
  var theme = localStorage.getItem('daygle_theme');
  if (theme === 'system') {
    theme = matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }
  document.documentElement.dataset.theme = theme === 'light' ? 'light' : 'dark';
} catch (_) {
  /* storage unavailable: app.css defaults to dark */
}

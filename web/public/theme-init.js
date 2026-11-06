// Start in the last theme used in this browser (see src/theme.svelte.js) so
// the page does not flash the wrong colours before the console loads. With
// nothing stored yet the console starts light, the default theme. A file rather than
// an inline script, which the console's Content-Security-Policy refuses.
try {
  var theme = localStorage.getItem('daygle_theme');
  if (theme === 'system') {
    theme = matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }
  document.documentElement.dataset.theme = theme === 'dark' ? 'dark' : 'light';
} catch (_) {
  document.documentElement.dataset.theme = 'light';
}

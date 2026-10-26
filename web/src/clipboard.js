// Copy text to the clipboard from anywhere the console runs.
//
// The Clipboard API (navigator.clipboard) only exists in secure contexts
// (https, or localhost). The console is regularly served over plain
// http://<lan-address>:5380, where navigator.clipboard is undefined, so
// fall back to the deprecated but still-supported
// document.execCommand('copy') through a hidden textarea - browsers allow
// that from inside a user gesture (an onclick handler) on any origin.

export async function copyText(text) {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return;
    } catch {
      // The async API can be denied even in a secure context (unfocused
      // document, dismissed permission prompt). Fall through to the
      // execCommand fallback instead of failing the click.
    }
  }
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly', '');
  ta.style.position = 'fixed';
  ta.style.top = '0';
  ta.style.opacity = '0';
  ta.style.pointerEvents = 'none';
  document.body.appendChild(ta);
  ta.select();
  try {
    if (!document.execCommand('copy')) {
      throw new Error("can't access the clipboard from this page");
    }
  } finally {
    ta.remove();
  }
}

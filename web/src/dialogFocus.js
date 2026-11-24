// Keyboard handling for the console's modal dialogs.
//
// A dialog that only draws an overlay leaves keyboard and screen-reader users
// behind it: focus stays on the page (or the button that opened it), Tab walks
// into the page underneath, and closing the dialog drops focus on the body.
// The `dialogFocus` action moves focus into the dialog when it opens, keeps
// Tab inside it, and puts focus back on the control that opened it when the
// dialog closes.

const FOCUSABLE = 'select, input, textarea, button, [href], [tabindex]:not([tabindex="-1"])';

export function dialogFocus(node) {
  const opener = typeof document === 'undefined' ? null : document.activeElement;
  // Prefer the first form field: a dialog that asks a question should land on
  // the answer, not on its close button.
  const target = node.querySelector('select, input, textarea') || node.querySelector(FOCUSABLE);
  target?.focus();

  function focusable() {
    return [...node.querySelectorAll(FOCUSABLE)].filter(
      (el) => !el.disabled && el.offsetParent !== null,
    );
  }

  function onKeydown(event) {
    if (event.key !== 'Tab') return;
    const items = focusable();
    if (!items.length) return;
    const first = items[0];
    const last = items[items.length - 1];
    const active = document.activeElement;
    if (event.shiftKey && (active === first || !node.contains(active))) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && (active === last || !node.contains(active))) {
      event.preventDefault();
      first.focus();
    }
  }

  node.addEventListener('keydown', onKeydown);
  return {
    destroy() {
      node.removeEventListener('keydown', onKeydown);
      if (opener && typeof opener.focus === 'function') opener.focus();
    },
  };
}

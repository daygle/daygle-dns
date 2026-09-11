// Sidebar visibility, shared between the app shell and the page-header menu
// buttons. On wide screens the sidebar collapses in place; on narrow screens
// it behaves as a slide-in overlay drawer with a backdrop.
//
// `$state` makes the value reactive everywhere it is read, so one click on any
// page's menu button updates every page header immediately. The state is kept
// as a mutable object (never reassigned) so it can be exported and read
// reactively from templates.

const DESKTOP = '(min-width: 900px)';

export const sidebar = $state({
  open: typeof window !== 'undefined' && window.matchMedia(DESKTOP).matches,
});

export function toggleSidebar() {
  sidebar.open = !sidebar.open;
}

export function setSidebar(next) {
  sidebar.open = next;
}

/** True when the viewport uses the overlay-drawer sidebar behaviour. */
export function isNarrow() {
  return typeof window !== 'undefined' && !window.matchMedia(DESKTOP).matches;
}
// The table columns each user has hidden (the Columns menu on data tables).
// Kept on the signed-in user's account so the choice follows them to other
// browsers; with sign-in off there is no account, so this browser keeps it.
import { api, getStoredUser } from './api.js';

const LOCAL_KEY = 'daygle_hidden_columns';

export const hiddenColumns = $state({ map: {} });

// Whose choices are loaded ('' with sign-in off), so a different sign-in
// loads its own.
let loadedFor = null;
let pending = null;

function readLocal() {
  try {
    return JSON.parse(localStorage.getItem(LOCAL_KEY) || '{}') || {};
  } catch {
    return {};
  }
}

/** Load the hidden columns (once per signed-in user). */
export function loadColumns() {
  const who = getStoredUser()?.username || '';
  if (loadedFor === who && pending) return pending;
  loadedFor = who;
  pending = (async () => {
    if (!who) {
      hiddenColumns.map = readLocal();
      return;
    }
    try {
      hiddenColumns.map = (await api.columns()).columns || {};
    } catch {
      hiddenColumns.map = {};
    }
  })();
  return pending;
}

/** Whether `column` of `table` is hidden. */
export function isHidden(table, column) {
  return (hiddenColumns.map[table] || []).includes(column);
}

/** Hide exactly `hidden` in `table` (empty: show every column). */
export async function setHidden(table, hidden) {
  const map = { ...hiddenColumns.map };
  if (hidden.length) map[table] = hidden;
  else delete map[table];
  hiddenColumns.map = map;
  if (getStoredUser()) {
    try {
      await api.saveColumns(table, hidden);
    } catch {
      // Not saved: the choice still holds until the page is reloaded.
    }
  } else {
    try {
      localStorage.setItem(LOCAL_KEY, JSON.stringify(map));
    } catch {
      // Storage unavailable: the choice lasts for this page.
    }
  }
}

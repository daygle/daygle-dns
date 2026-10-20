// Shared display preferences for dates and times.
//
// Three layers decide how a date is shown, most specific first:
//   1. the signed-in user's own preferences (stored on their account),
//   2. the server-wide defaults (Settings → Interface, admins only),
//   3. this browser's locale and time zone (`system`).
// Every layer has the same three fields: `time_zone` (`system`, `UTC` or an
// IANA zone such as `Europe/London`), `date_format` (`system`, `dmy`, `mdy`,
// `ymd`, `d_mon_y`) and `time_format` (`system`, `24h`, `12h`). In a user's
// preferences an empty field means "use the server default".
//
// `$state` makes the values reactive: every template that calls the
// formatters below re-renders when a preference changes - no refresh needed.

import { api } from './api.js';

const SYSTEM = { time_zone: 'system', date_format: 'system', time_format: 'system' };
const UNSET = { time_zone: '', date_format: '', time_format: '' };

// Older consoles kept a per-browser choice here; it is moved onto the
// account the first time the user signs in with this version.
const LEGACY_KEY = 'daygle_datetime';

export const display = $state({
  defaults: { ...SYSTEM },
  // null when there is no account to store preferences on (auth disabled).
  mine: null,
});

// Settings being previewed (see `previewDateTime`), else null.
let previewing = null;

// The effective choice for each field.
function pick(field) {
  if (previewing) return previewing[field] || 'system';
  const own = display.mine?.[field];
  if (own) return own;
  return display.defaults[field] || 'system';
}

function normalize(value, base) {
  return {
    time_zone: value?.time_zone ?? base.time_zone,
    date_format: value?.date_format ?? base.date_format,
    time_format: value?.time_format ?? base.time_format,
  };
}

/** Apply the server defaults (from Settings) without a reload. */
export function setDisplayDefaults(defaults) {
  display.defaults = normalize(defaults, SYSTEM);
}

/** Apply the signed-in user's own preferences without a reload. */
export function setMyPreferences(prefs) {
  display.mine = prefs ? normalize(prefs, UNSET) : null;
}

// Map the old per-browser `{ tz, format }` onto the new fields.
function legacyPreferences() {
  try {
    const raw = JSON.parse(localStorage.getItem(LEGACY_KEY) || 'null');
    if (!raw) return null;
    const prefs = { ...UNSET };
    if (raw.tz === 'utc') prefs.time_zone = 'UTC';
    else if (typeof raw.tz === 'string' && raw.tz !== 'system') prefs.time_zone = raw.tz;
    if (raw.format === '24h' || raw.format === '12h') prefs.time_format = raw.format;
    if (raw.format === 'iso') {
      prefs.date_format = 'ymd';
      prefs.time_format = '24h';
      if (!prefs.time_zone) prefs.time_zone = 'UTC';
    }
    return prefs;
  } catch (_) {
    return null;
  }
}

function forgetLegacy() {
  try {
    localStorage.removeItem(LEGACY_KEY);
  } catch (_) {
    /* storage unavailable */
  }
}

/**
 * Load the defaults and the user's preferences from the server. Called once
 * the console is signed in. Without a session (auth disabled), only the
 * server defaults apply.
 */
export async function loadDisplayPreferences() {
  try {
    const me = await api.me();
    setDisplayDefaults(me.display_defaults);
    setMyPreferences(me.preferences);
    const legacy = legacyPreferences();
    if (legacy && display.mine) {
      const empty = !display.mine.time_zone && !display.mine.date_format && !display.mine.time_format;
      if (empty && (legacy.time_zone || legacy.date_format || legacy.time_format)) {
        try {
          await api.savePreferences(legacy);
          setMyPreferences(legacy);
        } catch (_) {
          return; // try again next time
        }
      }
      forgetLegacy();
    }
    return;
  } catch (_) {
    /* no session: fall through to the public defaults */
  }
  try {
    const config = await api.config();
    setDisplayDefaults(config.display);
  } catch (_) {
    /* keep the browser's own settings */
  }
  setMyPreferences(null);
}

// ---- choices for the select boxes ----

// Every zone the browser knows (falls back to a short curated list).
function zoneNames() {
  try {
    return Intl.supportedValuesOf('timeZone').filter((z) => z !== 'UTC');
  } catch (_) {
    return [
      'Europe/London', 'Europe/Paris', 'Europe/Berlin', 'Europe/Moscow',
      'America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles',
      'America/Sao_Paulo', 'Asia/Dubai', 'Asia/Kolkata', 'Asia/Shanghai',
      'Asia/Tokyo', 'Asia/Singapore', 'Australia/Sydney', 'Pacific/Auckland',
    ];
  }
}

/** Time-zone choices: Device Time Zone, UTC, then every named zone. */
export function timeZoneOptions() {
  const zones = [
    ['system', 'Device Time Zone'],
    ['UTC', 'UTC'],
  ];
  return [...zones, ...zoneNames().map((z) => [z, z.replaceAll('_', ' ')])];
}

export const DATE_FORMAT_OPTIONS = [
  ['system', 'Browser Default'],
  ['dmy', 'DD/MM/YYYY'],
  ['mdy', 'MM/DD/YYYY'],
  ['ymd', 'YYYY-MM-DD'],
  ['d_mon_y', 'DD Mon YYYY'],
];

export const TIME_FORMAT_OPTIONS = [
  ['system', 'Browser Default'],
  ['24h', '24-Hour'],
  ['12h', '12-Hour (AM/PM)'],
];

/** Readable name of a stored choice, for "Server Default (...)" labels. */
export function choiceLabel(field, value) {
  if (field === 'time_zone') {
    if (!value || value === 'system') return 'Device Time Zone';
    return value.replaceAll('_', ' ');
  }
  const list = field === 'date_format' ? DATE_FORMAT_OPTIONS : TIME_FORMAT_OPTIONS;
  return list.find(([v]) => v === value)?.[1] || 'Browser Default';
}

// ---- formatting ----

function toDate(value) {
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
  if (typeof value === 'number') return new Date(value < 1e12 ? value * 1000 : value);
  if (typeof value === 'string' && value !== '') {
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? null : d;
  }
  return null;
}

// A zone the browser does not know would make Intl throw; fall back to the
// device zone instead.
const zoneCache = new Map();
function zoneArg() {
  const tz = pick('time_zone');
  if (tz === 'system') return undefined;
  if (!zoneCache.has(tz)) {
    let ok = true;
    try {
      new Intl.DateTimeFormat(undefined, { timeZone: tz });
    } catch (_) {
      ok = false;
    }
    zoneCache.set(tz, ok);
  }
  return zoneCache.get(tz) ? tz : undefined;
}

function hour12Arg() {
  const tf = pick('time_format');
  if (tf === '24h') return false;
  if (tf === '12h') return true;
  return undefined; // locale default
}

function timePart(d, withSeconds) {
  const options = { timeZone: zoneArg(), hour: '2-digit', minute: '2-digit' };
  const h12 = hour12Arg();
  // `hourCycle` keeps midnight as 00 (not 24) in 24-hour mode.
  if (h12 === false) options.hourCycle = 'h23';
  else if (h12 === true) options.hour12 = true;
  if (withSeconds) options.second = '2-digit';
  return d.toLocaleTimeString(undefined, options);
}

function datePart(d) {
  const df = pick('date_format');
  const timeZone = zoneArg();
  if (df === 'system') {
    return d.toLocaleDateString(undefined, { timeZone, year: 'numeric', month: 'short', day: '2-digit' });
  }
  const parts = {};
  for (const p of new Intl.DateTimeFormat('en-GB', {
    timeZone,
    year: 'numeric',
    month: df === 'd_mon_y' ? 'short' : '2-digit',
    day: '2-digit',
  }).formatToParts(d)) {
    parts[p.type] = p.value;
  }
  const { day, month, year } = parts;
  if (df === 'dmy') return `${day}/${month}/${year}`;
  if (df === 'mdy') return `${month}/${day}/${year}`;
  if (df === 'ymd') return `${year}-${month}-${day}`;
  return `${day} ${month} ${year}`;
}

/** Full date + time, e.g. "20/10/2026 14:05:09" (respecting the prefs). */
export function formatDateTime(value) {
  const d = toDate(value);
  if (!d) return String(value ?? '-');
  return `${datePart(d)}, ${timePart(d, true)}`;
}

/**
 * Now, formatted with `settings` instead of the effective ones (for the
 * example under a settings form). Empty fields mean the server default, as
 * in a user's preferences.
 */
export function previewDateTime(settings) {
  const field = (name) => settings[name] || display.defaults[name] || 'system';
  previewing = {
    time_zone: field('time_zone'),
    date_format: field('date_format'),
    time_format: field('time_format'),
  };
  try {
    return formatDateTime(new Date());
  } finally {
    previewing = null;
  }
}

/** Time only, e.g. "14:05:09" (chart axes, tooltips). */
export function formatTime(value) {
  const d = toDate(value);
  return d ? timePart(d, true) : String(value ?? '-');
}

/** Time only without seconds (compact chart labels). */
export function formatTimeShort(value) {
  const d = toDate(value);
  return d ? timePart(d, false) : String(value ?? '-');
}

/** Date only, e.g. "20 Oct 2026". */
export function formatDate(value) {
  const d = toDate(value);
  return d ? datePart(d) : String(value ?? '-');
}

/** Name of the zone dates are shown in, e.g. "Australia/Sydney". */
export function displayZoneName() {
  return zoneArg() || Intl.DateTimeFormat().resolvedOptions().timeZone || 'Local Time';
}

/**
 * Read a `<input type="datetime-local">` value ("2026-10-20T09:00") as a
 * time in the display zone and return it as UTC ISO 8601, for API filters.
 * Returns '' for an empty or unreadable value.
 */
export function zonedInputToIso(value) {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?/.exec(value || '');
  if (!m) return '';
  // Seconds are optional in the input.
  const [y, mo, d, h, mi, s] = m.slice(1).map((v) => Number(v || 0));
  const tz = zoneArg();
  if (!tz) return new Date(y, mo - 1, d, h, mi, s).toISOString();
  // The wall-clock time read as UTC, then corrected by the zone's offset at
  // that moment (twice, so a guess across a DST change settles).
  const wall = Date.UTC(y, mo - 1, d, h, mi, s);
  const offsetAt = (ms) => {
    const parts = {};
    for (const p of new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      hourCycle: 'h23',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    }).formatToParts(new Date(ms))) {
      parts[p.type] = Number(p.value);
    }
    return Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second) - ms;
  };
  let utc = wall - offsetAt(wall);
  utc = wall - offsetAt(utc);
  return new Date(utc).toISOString();
}

// Shared display preferences for dates and times.
//
// Preferences live in this browser (localStorage): `daygle_datetime` holds a
// JSON `{ tz, format }`. `tz` is `'system'`, `'utc'`, or an IANA zone name
// (e.g. `Europe/London`); `format` is `'system'` (locale default),
// `'24h'`, `'12h'`, or `'iso'` (UTC ISO 8601).
//
// `$state` makes the values reactive: every template that calls the
// formatters below re-renders when a preference changes on the Settings
// page - no refresh needed.

export const DATETIME_PREFS_KEY = 'daygle_datetime';

export const prefs = $state(readStored());

function readStored() {
  try {
    const raw = JSON.parse(localStorage.getItem(DATETIME_PREFS_KEY) || '{}');
    return {
      tz: typeof raw.tz === 'string' ? raw.tz : 'system',
      format: typeof raw.format === 'string' ? raw.format : 'system',
    };
  } catch (_) {
    return { tz: 'system', format: 'system' };
  }
}

export function setDateTimePrefs(next) {
  prefs.tz = next.tz || 'system';
  prefs.format = next.format || 'system';
  localStorage.setItem(DATETIME_PREFS_KEY, JSON.stringify({ tz: prefs.tz, format: prefs.format }));
}

// Time-zone choices for the Settings select: System first, then UTC, then
// every zone the browser knows (falls back to a short curated list).
export function timeZoneOptions() {
  const zones = [
    ['system', 'System Default'],
    ['utc', 'UTC'],
  ];
  let rest = [];
  try {
    rest = Intl.supportedValuesOf('timeZone').filter((z) => z !== 'UTC');
  } catch (_) {
    rest = [
      'Europe/London', 'Europe/Paris', 'Europe/Berlin', 'Europe/Moscow',
      'America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles',
      'America/Sao_Paulo', 'Asia/Dubai', 'Asia/Kolkata', 'Asia/Shanghai',
      'Asia/Tokyo', 'Asia/Singapore', 'Australia/Sydney', 'Pacific/Auckland',
    ];
  }
  return [...zones, ...rest.map((z) => [z, z.replaceAll('_', ' ')])];
}

export const FORMAT_OPTIONS = [
  ['system', 'System Default'],
  ['24h', '24-Hour'],
  ['12h', '12-Hour (AM/PM)'],
  ['iso', 'ISO 8601 (UTC)'],
];

function toDate(value) {
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
  if (typeof value === 'number') return new Date(value < 1e12 ? value * 1000 : value);
  if (typeof value === 'string' && value !== '') {
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? null : d;
  }
  return null;
}

function zoneArg() {
  if (prefs.tz === 'system') return undefined;
  if (prefs.tz === 'utc') return 'UTC';
  return prefs.tz;
}

function hour12Arg() {
  if (prefs.format === '24h') return false;
  if (prefs.format === '12h') return true;
  return undefined; // locale default
}

function partsFor(value, withSeconds, withDate) {
  const d = toDate(value);
  if (!d) return null;
  if (prefs.format === 'iso') {
    // ISO 8601 in UTC, seconds kept (they carry real information in logs).
    return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
  }
  const options = {
    timeZone: zoneArg(),
    hour12: hour12Arg(),
    hour: '2-digit',
    minute: '2-digit',
  };
  if (withSeconds) options.second = '2-digit';
  if (withDate) {
    options.year = 'numeric';
    options.month = 'short';
    options.day = '2-digit';
  }
  return d.toLocaleString(undefined, options);
}

/** Full date + time, e.g. "5 Sep 2026, 02:45:20" (respecting the prefs). */
export function formatDateTime(value) {
  const out = partsFor(value, true, true);
  return out === null ? String(value ?? '—') : out;
}

/** Time only, e.g. "02:45:20" (chart axes, tooltips). */
export function formatTime(value) {
  const out = partsFor(value, true, false);
  return out === null ? String(value ?? '—') : out;
}

/** Time only without seconds (compact chart labels). */
export function formatTimeShort(value) {
  const out = partsFor(value, false, false);
  return out === null ? String(value ?? '—') : out;
}

/** Date only, e.g. "5 Sep 2026". */
export function formatDate(value) {
  const d = toDate(value);
  if (!d) return String(value ?? '—');
  if (prefs.format === 'iso') return d.toISOString().slice(0, 10);
  return d.toLocaleDateString(undefined, {
    timeZone: zoneArg(),
    year: 'numeric',
    month: 'short',
    day: '2-digit',
  });
}

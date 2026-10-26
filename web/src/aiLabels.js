// Display helpers shared by the AI pages.

// The classification pipeline as the server names it ("heuristic",
// "fasttext", "fasttext+minilm-onnx") in plain words.
const BACKENDS = {
  heuristic: 'Built-In Heuristic Rules',
  fasttext: 'fastText Model',
  'minilm-onnx': 'MiniLM Verifier',
};

export function backendLabel(name) {
  if (!name) return '-';
  return name
    .split('+')
    .map((part) => BACKENDS[part] || part)
    .join(' + ');
}

// "phishing" -> "Phishing".
export function titleCase(s) {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
}

// 0.995 -> "99.5%", 0.3 -> "30%". Rounded to one decimal first: values
// arrive as 32-bit floats (0.3 is 0.30000001), which showed as "30.0%".
export function percent(value) {
  const pct = Math.round(Number(value || 0) * 1000) / 10;
  return `${Number.isInteger(pct) ? pct : pct.toFixed(1)}%`;
}

// 604800 -> "7 Days", 300 -> "5 Minutes".
export function duration(secs) {
  const units = [
    [86400, 'Day'],
    [3600, 'Hour'],
    [60, 'Minute'],
  ];
  for (const [size, unit] of units) {
    if (secs >= size && secs % size === 0) {
      const n = secs / size;
      return `${n} ${unit}${n === 1 ? '' : 's'}`;
    }
  }
  return `${secs} Second${secs === 1 ? '' : 's'}`;
}

// What someone typed or pasted as a domain to exempt ("https://WWW.Example.com/x",
// "*.example.com.", "example.com:443") as the bare name the server expects,
// or null when it is not a valid domain name.
export function cleanDomain(input) {
  let d = (input || '').trim().toLowerCase();
  d = d.replace(/^[a-z][a-z0-9+.-]*:\/\//, ''); // scheme
  d = d.split(/[/?#]/)[0]; // path, query, fragment
  d = d.replace(/:\d+$/, ''); // port
  d = d.replace(/^\*\./, '').replace(/\.+$/, '');
  const label = /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/;
  if (!d || d.length > 253 || !d.split('.').every((l) => label.test(l))) return null;
  return d;
}

// Scanner row statuses as the console names them.
export const STATUS_LABELS = {
  pending: 'Waiting',
  classified: 'Classified',
  skipped: 'Skipped',
};

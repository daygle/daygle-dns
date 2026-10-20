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

// 0.995 -> "99.5%", 0.3 -> "30%".
export function percent(value) {
  const pct = Number(value || 0) * 100;
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

// Scanner row statuses as the console names them.
export const STATUS_LABELS = {
  pending: 'Waiting',
  classified: 'Classified',
  skipped: 'Skipped',
};

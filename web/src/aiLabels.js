// Display helpers shared by the AI pages.

// The classification pipeline as the server names it ("heuristic",
// "fasttext", "fasttext+minilm-onnx") in plain words.
const BACKENDS = {
  heuristic: 'Built-In Heuristic Rules',
  fasttext: 'fastText Model',
  'fasttext-binary': 'Binary Name Model',
  starter: 'Starter (Monitor Only)',
  'minilm-onnx': 'MiniLM Verifier',
};

export function backendLabel(name) {
  if (!name) return '-';
  return name
    .split('+')
    .map((part) => BACKENDS[part] || part)
    .join(' + ');
}

// Category labels that are acronyms or have fixed casing, so they read
// "AI" and "CDN" rather than "Ai" and "Cdn".
const SPECIAL_CASE = {
  ai: 'AI',
  api: 'API',
  c2: 'C2',
  cdn: 'CDN',
  dns: 'DNS',
  iot: 'IoT',
  p2p: 'P2P',
  tld: 'TLD',
  url: 'URL',
  vpn: 'VPN',
};

// "phishing" -> "Phishing", "real-estate" -> "Real Estate", "ai" -> "AI".
export function titleCase(s) {
  if (!s) return s;
  // Split on the separators category labels use, never on spaces: this also
  // runs over free-text evidence, where only the first letter should change.
  return String(s)
    .split(/[-_]/)
    .map((w) => {
      const word = w.toLowerCase();
      if (SPECIAL_CASE[word]) return SPECIAL_CASE[word];
      // Plural acronyms keep the acronym's casing: "tlds" -> "TLDs".
      const singular = word.endsWith('s') ? SPECIAL_CASE[word.slice(0, -1)] : undefined;
      if (singular) return `${singular}s`;
      return w.charAt(0).toUpperCase() + w.slice(1);
    })
    .join(' ');
}

// 0.995 -> "99.5%", 0.3 -> "30%". Rounded to one decimal first: values
// arrive as 32-bit floats (0.3 is 0.30000001), which showed as "30.0%".
export function percent(value) {
  const pct = Math.round(Number(value || 0) * 1000) / 10;
  return `${Number.isInteger(pct) ? pct : pct.toFixed(1)}%`;
}

// 604800 -> "7 Days", 300 -> "5 Minutes".
export function duration(secs) {
  // A setting the server did not send (older server, scanner off) would
  // otherwise read "undefined Seconds".
  if (typeof secs !== 'number' || !Number.isFinite(secs)) return '-';
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

// The rules the page reader may follow (ai.page_rule), as the console shows
// them in the Scanner and Threats tabs.
const PAGE_RULE_LABELS = {
  evidence: 'Evidence only',
  corroborate: 'Corroborate',
  decide: 'Decide',
};

export function pageRuleLabel(rule) {
  return PAGE_RULE_LABELS[rule] || rule;
}

// The phases of an update run (must match UpdateState::is_running on the
// server). Shared by the Scanner and Language Model tabs, which both follow
// an operation through the same state.
const RUNNING_PHASES = [
  'preparing',
  'downloading',
  'cloning',
  'building',
  'installing',
  'applying',
  'restarting',
  'rolling_back',
];

export function isRunning(phase) {
  return RUNNING_PHASES.includes(phase);
}

// Bytes as "1.2 GB", "48.1 MB", "12 KB", "512 B". One implementation for
// the model files, the model sizes and the download progress, which used to
// round differently from each other.
export function formatBytes(bytes) {
  if (bytes == null) return '-';
  if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
  if (bytes >= 1024 ** 2) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${bytes} B`;
}

// A server timestamp (RFC 3339) as `format(ms)`, or "-" when it is unset:
// the API sends the UNIX epoch for a time that never happened.
export function stampTime(value, format) {
  if (!value) return '-';
  const ms = Date.parse(value);
  return Number.isNaN(ms) || ms <= 0 ? '-' : format(ms);
}

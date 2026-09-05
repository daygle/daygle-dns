// Thin API client for the Daygle REST API.
//
// Auth: when the server has console users configured, a session token from
// `POST /api/auth/login` is stored and sent as a Bearer token on every call.
// A 401 response with `login: true` raises `onUnauthorized` so the shell can
// switch to the login screen.

const BASE = '/api';
const TOKEN_KEY = 'daygle_token';
const USER_KEY = 'daygle_user';

export function getToken() {
  return localStorage.getItem(TOKEN_KEY) || '';
}

export function getStoredUser() {
  try {
    return JSON.parse(localStorage.getItem(USER_KEY) || 'null');
  } catch (_) {
    return null;
  }
}

let onUnauthorized = null;
export function setUnauthorizedHandler(fn) {
  onUnauthorized = fn;
}

async function request(method, path, body, opts = {}) {
  const init = { method, headers: {} };
  const token = getToken();
  if (token) init.headers['Authorization'] = `Bearer ${token}`;
  if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  const res = await fetch(BASE + path, init);
  if (!res.ok) {
    let detail = res.statusText;
    let needsLogin = false;
    try {
      const data = await res.json();
      detail = data.error || detail;
      needsLogin = res.status === 401 && data.login === true;
    } catch (_) { /* ignore */ }
    // Present errors sentence-cased: backend messages often start lowercase
    // (e.g. "not found: zone ...", "failed to persist ...").
    detail = detail.charAt(0).toUpperCase() + detail.slice(1);
    if (needsLogin && onUnauthorized && !opts.noLoginRedirect) {
      onUnauthorized();
    }
    const err = new Error(detail);
    err.status = res.status;
    err.needsLogin = needsLogin;
    throw err;
  }
  if (res.status === 204) return null;
  return res.json();
}

export function formatApiError(e) {
  // Views currently use `String(e.message || e)` in many places; centralize
  // here so the display shape is consistent and easy to audit/change later.
  if (e instanceof Error) return e.message;
  if (typeof e === 'string') return e;
  try {
    return JSON.stringify(e);
  } catch (_) {
    return String(e);
  }
}

export function configOk(cfg) {
  return cfg != null && typeof cfg === 'object';
}

// Render a seconds count as a compact duration (e.g. 7325 -> "2h 2m 5s",
// 65 -> "1m 5s", 3600 -> "1h"). Days are included once the server has been
// up for more than a day.
export function formatUptime(totalSecs) {
  if (totalSecs === null || totalSecs === undefined || Number.isNaN(totalSecs)) return '—';
  const secs = Math.max(0, Math.floor(totalSecs));
  const units = [
    ['d', Math.floor(secs / 86400)],
    ['h', Math.floor((secs % 86400) / 3600)],
    ['m', Math.floor((secs % 3600) / 60)],
    ['s', secs % 60],
  ];
  // Skip leading zero units, then trim a tail of zeros ("1h 0m 0s" -> "1h").
  const first = units.findIndex(([, v]) => v > 0);
  const kept = first === -1 ? [units[3]] : units.slice(first);
  let end = kept.length;
  while (end > 1 && kept[end - 1][1] === 0) end -= 1;
  return kept.slice(0, end).map(([label, v]) => `${v}${label}`).join(' ');
}

export const api = {
  // ---- auth ----
  login: async (username, password) => {
    const data = await request('POST', '/auth/login', { username, password }, { noLoginRedirect: true });
    localStorage.setItem(TOKEN_KEY, data.token);
    localStorage.setItem(USER_KEY, JSON.stringify({ username: data.username, role: data.role || 'admin' }));
    return data;
  },
  logout: async () => {
    try { await request('POST', '/auth/logout', {}); } catch (_) { /* ignore */ }
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  },
  clearLocalSession: () => {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  },
  me: () => request('GET', '/auth/me'),
  // Self-service password rotation (keeps the current session, signs out others).
  changePassword: (currentPassword, newPassword) =>
    request('POST', '/auth/password', { current_password: currentPassword, new_password: newPassword }),
  users: () => request('GET', '/users'),
  createUser: (payload) => request('POST', '/users', payload),
  updateUser: (username, payload) => request('PATCH', `/users/${encodeURIComponent(username)}`, payload),
  deleteUser: (username) => request('DELETE', `/users/${encodeURIComponent(username)}`),
  // Console-managed TLS certificates (create self-signed or upload PEM pairs).
  certificates: () => request('GET', '/certificates'),
  createCertificate: (payload) => request('POST', '/certificates', payload),
  deleteCertificate: (name) => request('DELETE', `/certificates/${encodeURIComponent(name)}`),
  // First-run setup: whether the one-time admin account still needs creating.
  authSetupStatus: () => request('GET', '/auth/setup', undefined, { noLoginRedirect: true }),
  // Create the first admin account. Returns a session, stored like a login.
  authSetup: async (username, password) => {
    const data = await request('POST', '/auth/setup', { username, password }, { noLoginRedirect: true });
    localStorage.setItem(TOKEN_KEY, data.token);
    localStorage.setItem(USER_KEY, JSON.stringify({ username: data.username, role: data.role || 'admin' }));
    return data;
  },

  // ---- data ----
  status: () => request('GET', '/status'),
  metrics: () => request('GET', '/metrics'),
  stats: (window) => request('GET', `/stats?window=${window || '1h'}`),
  config: () => request('GET', '/config'),
  updateSettings: (body) => request('PUT', '/config', body),
  logs: (n) => request('GET', `/logs?limit=${n || 200}`),
  // Searchable per-query history (SQLite-backed). `qs` is a raw query string.
  queryLogs: (qs) => request('GET', `/querylogs?${qs}`),
  clearQueryLogs: () => request('DELETE', '/querylogs'),
  zones: () => request('GET', '/zones'),
  createZone: (body) => request('POST', '/zones', body),
  deleteZone: (id) => request('DELETE', `/zones/${id}`),
  updateZoneSoa: (id, body) => request('PUT', `/zones/${id}/soa`, body),
  records: (zoneId) => request('GET', `/zones/${zoneId}/records`),
  upsertRecord: (zoneId, body) => request('PUT', `/zones/${zoneId}/records`, body),
  deleteRecord: (zoneId, recordId) =>
    request('DELETE', `/zones/${zoneId}/records/${recordId}`),
  signZone: (zoneId) => request('POST', `/zones/${zoneId}/sign`),
  unsignZone: (zoneId) => request('POST', `/zones/${zoneId}/unsign`),
  cache: () => request('GET', '/cache'),
  clearCache: () => request('POST', '/cache/clear'),
  importZone: (name, text) => request('POST', '/zones/import', { name, text }),
  blocklistSources: () => request('GET', '/policy/blocklist/sources'),
  refreshBlocklistSources: () => request('POST', '/policy/blocklist/sources'),
  replaceBlocklistSources: (sources) =>
    request('PUT', '/policy/blocklist/sources', { sources }),
  validateBlocklistSource: (url, format) =>
    request(
      'GET',
      `/policy/blocklist/sources/validate?url=${encodeURIComponent(url)}&format=${encodeURIComponent(format || 'auto')}`
    ),
  blockingGroups: () => request('GET', '/policy/blocking'),
  saveBlockingGroup: (body) => request('POST', '/policy/blocking', body),
  deleteBlockingGroup: (id) => request('DELETE', `/policy/blocking/${id}`),
  testBlocking: (client, domain) =>
    request('POST', '/policy/blocking/test', { client, domain }),
  splitHorizon: () => request('GET', '/split-horizon'),
  saveSplitHorizonNetwork: (body) => request('POST', '/split-horizon/networks', body),
  deleteSplitHorizonNetwork: (name) =>
    request('DELETE', `/split-horizon/networks/${encodeURIComponent(name)}`),
  createSplitHorizonEntry: (body) => request('POST', '/split-horizon/entries', body),
  updateSplitHorizonEntry: (id, body) =>
    request('PUT', `/split-horizon/entries/${id}`, body),
  deleteSplitHorizonEntry: (id) =>
    request('DELETE', `/split-horizon/entries/${id}`),
  moveSplitHorizonEntry: (id, direction) =>
    request('POST', `/split-horizon/entries/${id}/move`, { direction }),
};

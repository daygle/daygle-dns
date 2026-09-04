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

function configOk(cfg) {
  return cfg != null && typeof cfg === 'object';
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

  // ---- data ----
  status: () => request('GET', '/status'),
  metrics: () => request('GET', '/metrics'),
  stats: (window) => request('GET', `/stats?window=${window || '1h'}`),
  config: () => request('GET', '/config'),
  updateSettings: (body) => request('PUT', '/config', body),
  logs: (n) => request('GET', `/logs?limit=${n || 200}`),
  zones: () => request('GET', '/zones'),
  createZone: (body) => request('POST', '/zones', body),
  deleteZone: (id) => request('DELETE', `/zones/${id}`),
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

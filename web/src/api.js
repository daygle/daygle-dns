// Thin API client for the Daygle REST API.

const BASE = '/api';

async function request(method, path, body) {
  const init = { method, headers: {} };
  const token = localStorage.getItem('daygle_token');
  if (token) init.headers['Authorization'] = `Bearer ${token}`;
  if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  const res = await fetch(BASE + path, init);
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const data = await res.json();
      detail = data.error || detail;
    } catch (_) { /* ignore */ }
    throw new Error(detail);
  }
  return res.json();
}

export const api = {
  status: () => request('GET', '/status'),
  metrics: () => request('GET', '/metrics'),
  config: () => request('GET', '/config'),
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
  clearCache: () => request('POST', '/cache/clear'),
  importZone: (name, text) => request('POST', '/zones/import', { name, text }),
};

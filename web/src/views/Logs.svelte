<script>
  import { api } from '../api.js';
  import { formatDateTime } from '../datetime.svelte.js';

  // Two tabs: the in-memory server log and the searchable per-query history.
  let tab = $state('server');

  // ---- Server log ----
  let logs = $state([]);
  let error = $state(null);

  async function refresh() {
    error = null;
    try {
      logs = await api.logs(300);
    } catch (e) {
      error = String(e.message || e);
    }
  }

  // ---- Query logs ----
  const QTYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'PTR', 'SRV', 'CAA', 'DS', 'DNSKEY', 'ANY'];
  const PROTOCOLS = ['udp', 'tcp', 'tls', 'https', 'quic'];
  const OUTCOMES = [
    ['authoritative', 'Authoritative'],
    ['recursive', 'Recursive'],
    ['split_horizon', 'Split Horizon'],
    ['blocked', 'Blocked'],
    ['rate_limited', 'Rate Limited'],
    ['error', 'Error'],
  ];
  const RCODES = ['NOERROR', 'NXDOMAIN', 'SERVFAIL', 'REFUSED', 'FORMERR', 'NOTIMP'];

  // Filter form model. `qname` supports `*` wildcards and substring match.
  let fClient = $state('');
  let fQname = $state('');
  let fQtype = $state('');
  let fProtocol = $state('');
  let fOutcome = $state('');
  let fRcode = $state('');
  let fFrom = $state('');
  let fTo = $state('');
  let perPage = $state(50);
  let page = $state(1);

  let qEntries = $state([]);
  let qTotal = $state(0);
  let qError = $state(null);
  let qLoading = $state(false);
  let live = $state(false);
  let liveTimer = null;

  function buildQuery(overrides = {}) {
    const params = new URLSearchParams();
    const put = (key, value) => { if (String(value).trim() !== '') params.set(key, String(value).trim()); };
    put('client', fClient);
    put('qname', fQname);
    put('qtype', fQtype);
    put('protocol', fProtocol);
    put('outcome', fOutcome);
    put('rcode', fRcode);
    put('from', fFrom);
    put('to', fTo);
    for (const [key, value] of Object.entries(overrides)) put(key, value);
    return params.toString();
  }

  function currentQuery(overrides = {}) {
    return buildQuery({ page, per_page: perPage, ...overrides });
  }

  async function runQuery(newPage = 1) {
    page = newPage;
    qLoading = true;
    qError = null;
    try {
      const data = await api.queryLogs(currentQuery());
      qEntries = data.entries || [];
      qTotal = data.total || 0;
    } catch (e) {
      qError = String(e.message || e);
    } finally {
      qLoading = false;
    }
  }

  function resetFilters() {
    fClient = fQname = fQtype = fProtocol = fOutcome = fRcode = fFrom = fTo = '';
    runQuery(1);
  }

  function totalPages() {
    return Math.max(1, Math.ceil(qTotal / perPage));
  }

  function exportCsv() {
    const qs = buildQuery({ format: 'csv' });
    const token = localStorage.getItem('daygle_token') || '';
    fetch(`/api/querylogs?${qs}`, { headers: { Authorization: `Bearer ${token}` } })
      .then((res) => { if (!res.ok) throw new Error(res.statusText); return res.blob(); })
      .then((blob) => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'query-logs.csv';
        a.click();
        URL.revokeObjectURL(url);
      })
      .catch((e) => { qError = String(e.message || e); });
  }

  async function clearLog() {
    if (!window.confirm('Delete every recorded query? This cannot be undone.')) return;
    try {
      await api.clearQueryLogs();
      runQuery(1);
    } catch (e) {
      qError = String(e.message || e);
    }
  }

  function toggleLive() {
    live = !live;
    if (liveTimer) { clearInterval(liveTimer); liveTimer = null; }
    if (live) liveTimer = setInterval(() => runQuery(page), 3000);
  }

  function fmtTime(ts) {
    return formatDateTime(ts);
  }

  // Full-word, title-case severity names for the Level column.
  function levelLabel(level) {
    switch (level) {
      case 'debug': return 'Debug';
      case 'info': return 'Information';
      case 'warn': return 'Warning';
      case 'error': return 'Error';
      default: return level;
    }
  }

  function outcomeClass(outcome) {
    if (outcome === 'blocked') return 'err';
    if (outcome === 'error' || outcome === 'rate_limited') return 'warn';
    return 'ok';
  }

  function outcomeLabel(outcome) {
    return outcome.replaceAll('_', ' ').replace(/\b\w/g, (c) => c.toUpperCase());
  }

  $effect(() => { refresh(); });
  $effect(() => { if (tab === 'queries' && qTotal === 0 && qEntries.length === 0 && !qError && !qLoading) runQuery(1); });
</script>

<h1>Logs</h1>

<div class="tabs">
  <button class="tab" class:active={tab === 'server'} onclick={() => { tab = 'server'; refresh(); }}>Server Log</button>
  <button class="tab" class:active={tab === 'queries'} onclick={() => { tab = 'queries'; runQuery(1); }}>Query Logs</button>
</div>

{#if tab === 'server'}
  <div class="row" style="margin-bottom: 14px">
    <button class="secondary" onclick={refresh}>Refresh</button>
    <span class="muted">Showing the most recent {logs.length} entries</span>
  </div>

  {#if error}
    <div class="card" style="border-color: var(--danger); color: var(--danger)">{error}</div>
  {:else}
    <div class="card" style="padding: 0; overflow: auto; max-height: 70vh">
      <table>
        <thead>
          <tr><th>Time</th><th>Level</th><th>Component</th><th>Message</th></tr>
        </thead>
        <tbody>
          {#each logs as entry (entry.timestamp + entry.component + entry.message)}
            <tr>
              <td style="white-space: nowrap">{fmtTime(entry.timestamp)}</td>
              <td><span class:pill={true} class:ok={entry.level === 'info'} class:err={entry.level === 'error'} class:warn={entry.level === 'warn'}>
                {levelLabel(entry.level)}
              </span></td>
              <td>{entry.component}</td>
              <td><code>{entry.message}</code></td>
            </tr>
          {/each}
        </tbody>
      </table>
      {#if logs.length === 0}
        <p class="muted" style="padding: 14px">No log entries yet.</p>
      {/if}
    </div>
  {/if}
{:else}
  <div class="card" style="margin-bottom: 14px">
    <form onsubmit={(e) => { e.preventDefault(); runQuery(1); }}>
      <div class="filter-grid">
        <label>Client IP
          <input placeholder="192.168.1.20" bind:value={fClient} />
        </label>
        <label>Domain
          <input placeholder="example.com or *example.com" bind:value={fQname} />
        </label>
        <label>Type
          <select bind:value={fQtype}>
            <option value="">Any</option>
            {#each QTYPES as t}<option value={t}>{t}</option>{/each}
          </select>
        </label>
        <label>Protocol
          <select bind:value={fProtocol}>
            <option value="">Any</option>
            {#each PROTOCOLS as p}<option value={p}>{p.toUpperCase()}</option>{/each}
          </select>
        </label>
        <label>Response
          <select bind:value={fOutcome}>
            <option value="">Any</option>
            {#each OUTCOMES as [value, label]}<option value={value}>{label}</option>{/each}
          </select>
        </label>
        <label>Rcode
          <select bind:value={fRcode}>
            <option value="">Any</option>
            {#each RCODES as r}<option value={r}>{r}</option>{/each}
          </select>
        </label>
        <label>From
          <input type="datetime-local" bind:value={fFrom} />
        </label>
        <label>To
          <input type="datetime-local" bind:value={fTo} />
        </label>
        <label>Per Page
          <select bind:value={perPage}>
            <option value={25}>25</option>
            <option value={50}>50</option>
            <option value={100}>100</option>
            <option value={200}>200</option>
          </select>
        </label>
      </div>
      <div class="row" style="margin-top: 10px; gap: 8px">
        <button type="submit">Query</button>
        <button type="button" class="secondary" onclick={exportCsv}>Export</button>
        <button type="button" class="secondary" onclick={resetFilters}>Reset</button>
        <button type="button" class="danger" onclick={clearLog}>Clear Log</button>
        <label class="row" style="gap: 6px; align-items: center; margin-left: 8px">
          <input type="checkbox" checked={live} onchange={toggleLive} />
          <span>Live Update</span>
        </label>
      </div>
    </form>
  </div>

  {#if qError}
    <div class="card" style="border-color: var(--danger); color: var(--danger)">{qError}</div>
  {/if}

  <div class="card" style="padding: 0; overflow: auto">
    <table>
      <thead>
        <tr><th>Time</th><th>Client</th><th>Domain</th><th>Type</th><th>Protocol</th><th>Response</th><th>Rcode</th><th style="text-align: right">Took</th></tr>
      </thead>
      <tbody>
        {#each qEntries as entry (entry.id)}
          <tr>
            <td style="white-space: nowrap">{fmtTime(entry.ts)}</td>
            <td><code>{entry.client}</code></td>
            <td><code>{entry.qname}</code></td>
            <td>{entry.qtype}</td>
            <td>{entry.protocol.toUpperCase()}</td>
            <td><span class:pill={true} class:ok={outcomeClass(entry.outcome) === 'ok'} class:err={outcomeClass(entry.outcome) === 'err'} class:warn={outcomeClass(entry.outcome) === 'warn'}>
              {outcomeLabel(entry.outcome)}
            </span></td>
            <td>{entry.rcode || '—'}</td>
            <td style="text-align: right">{entry.elapsed_ms} ms</td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if !qLoading && qEntries.length === 0 && !qError}
      <p class="muted" style="padding: 14px">
        No queries recorded yet{qTotal === 0 && buildQuery() === '' ? ' - make a DNS query or check that query logging is enabled in Settings' : ''}.
      </p>
    {/if}
  </div>

  <div class="row" style="margin-top: 10px; gap: 10px; align-items: center">
    <button class="secondary" disabled={page <= 1} onclick={() => runQuery(page - 1)}>← Prev</button>
    <span class="muted">Page {page} of {totalPages()} · {qTotal} quer{qTotal === 1 ? 'y' : 'ies'}</span>
    <button class="secondary" disabled={page >= totalPages()} onclick={() => runQuery(page + 1)}>Next →</button>
  </div>
{/if}

<style>
  .tabs {
    display: flex;
    gap: 4px;
    margin-bottom: 14px;
    border-bottom: 1px solid var(--border);
  }
  .tab {
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    padding: 8px 14px;
    cursor: pointer;
    color: var(--muted);
  }
  .tab.active {
    color: var(--text);
    border-bottom-color: var(--accent);
  }
  .filter-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
    gap: 10px 14px;
  }
  .filter-grid label {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 0.85rem;
  }
  .danger {
    color: var(--danger);
  }
  .pill.warn {
    color: #e0a34e;
    border-color: #e0a34e;
  }
</style>

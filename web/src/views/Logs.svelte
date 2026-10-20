<script>
  import { onDestroy, onMount } from 'svelte';
  import { api, getToken, formatApiError } from '../api.js';
  import PageHeader from '../PageHeader.svelte';
  import { icons } from '../icons.svelte.js';
  import { formatDateTime, displayZoneName, zonedInputToIso } from '../datetime.svelte.js';

  // Two tabs: the searchable per-query history and the in-memory server log.
  // Query Log opens first: it is what the Logs page is used for day to day.
  const TABS = [
    {
      id: 'queries',
      label: 'Query Log',
      tagline:
        'Every query the server answered, newest first. Filter by client, domain, type or result, export the matches as CSV, or follow new queries live. Click a client or domain to filter by it.',
    },
    {
      id: 'server',
      label: 'Server Log',
      tagline:
        "The server's own messages: startup, zone transfers, blocklist refreshes, settings changes and errors. Kept in memory, so it starts empty after a restart.",
    },
  ];
  let tab = $state('queries');
  const current = $derived(TABS.find((t) => t.id === tab));

  function openTab(id) {
    tab = id;
    if (id === 'queries') runQuery(1);
    else {
      stopLive();
      refresh();
    }
  }

  // ---- Server log ----
  let logs = $state([]);
  let error = $state(null);
  let logLevel = $state('');
  let logSearch = $state('');
  const LEVELS = [
    ['error', 'Errors'],
    ['warn', 'Warnings and Errors'],
    ['info', 'Information and Above'],
  ];
  const RANK = { debug: 0, info: 1, warn: 2, error: 3 };
  // Newest first, like the query log.
  const shownLogs = $derived(
    logs
      .filter((e) => !logLevel || (RANK[e.level] ?? 0) >= RANK[logLevel])
      .filter((e) => {
        const q = logSearch.trim().toLowerCase();
        return !q || e.message.toLowerCase().includes(q) || e.component.toLowerCase().includes(q);
      })
      .slice()
      .reverse(),
  );

  async function refresh() {
    error = null;
    try {
      logs = await api.logs(500);
    } catch (e) {
      error = formatApiError(e);
    }
  }

  // ---- Query log ----
  const QTYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'PTR', 'SRV', 'CAA', 'HTTPS', 'SVCB', 'DS', 'DNSKEY', 'ANY'];
  const PROTOCOLS = [
    ['udp', 'UDP'],
    ['tcp', 'TCP'],
    ['tls', 'DNS over TLS'],
    ['https', 'DNS over HTTPS'],
    ['quic', 'DNS over QUIC'],
  ];
  const PROTOCOL_SHORT = { udp: 'UDP', tcp: 'TCP', tls: 'DoT', https: 'DoH', quic: 'DoQ' };
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
  let qNotice = $state(null);
  let qLoading = $state(false);
  let qLoaded = $state(false);
  let live = $state(false);
  let liveTimer = null;

  const filtersActive = $derived(
    !!(fClient.trim() || fQname.trim() || fQtype || fProtocol || fOutcome || fRcode || fFrom || fTo),
  );

  function buildQuery(overrides = {}) {
    const params = new URLSearchParams();
    const put = (key, value) => { if (String(value).trim() !== '') params.set(key, String(value).trim()); };
    put('client', fClient);
    put('qname', fQname);
    put('qtype', fQtype);
    put('protocol', fProtocol);
    put('outcome', fOutcome);
    put('rcode', fRcode);
    // The pickers show the display time zone; the API wants UTC.
    put('from', zonedInputToIso(fFrom));
    put('to', zonedInputToIso(fTo));
    for (const [key, value] of Object.entries(overrides)) put(key, value);
    return params.toString();
  }

  async function runQuery(newPage = 1) {
    page = newPage;
    qLoading = true;
    qError = null;
    try {
      const data = await api.queryLogs(buildQuery({ page, per_page: perPage }));
      qEntries = data.entries || [];
      qTotal = data.total || 0;
    } catch (e) {
      qError = formatApiError(e);
    } finally {
      qLoading = false;
      qLoaded = true;
    }
  }

  // Selects apply as soon as they change; text and time fields on Enter or
  // Search.
  function apply() {
    qNotice = null;
    runQuery(1);
  }

  function resetFilters() {
    fClient = fQname = fQtype = fProtocol = fOutcome = fRcode = fFrom = fTo = '';
    apply();
  }

  function filterBy(field, value) {
    if (field === 'client') fClient = value;
    else fQname = value;
    apply();
  }

  function totalPages() {
    return Math.max(1, Math.ceil(qTotal / perPage));
  }

  function exportCsv() {
    const qs = buildQuery({ format: 'csv' });
    const token = getToken();
    const headers = token ? { Authorization: `Bearer ${token}` } : {};
    fetch(`/api/querylogs?${qs}`, { headers })
      .then(async (res) => {
        if (!res.ok) {
          let detail = res.statusText;
          try { detail = (await res.json()).error || detail; } catch (_) { /* not JSON */ }
          throw new Error(detail);
        }
        return res.blob();
      })
      .then((blob) => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'query-logs.csv';
        a.click();
        // Revoking synchronously can cancel the download in some browsers.
        setTimeout(() => URL.revokeObjectURL(url), 0);
      })
      .catch((e) => { qError = formatApiError(e); });
  }

  async function clearLog() {
    if (!window.confirm('Delete every recorded query? This cannot be undone.')) return;
    qNotice = null;
    try {
      const res = await api.clearQueryLogs();
      qNotice = `Query log cleared (${Number(res?.deleted || 0).toLocaleString()} entries deleted).`;
      runQuery(1);
    } catch (e) {
      qError = formatApiError(e);
    }
  }

  function stopLive() {
    live = false;
    if (liveTimer) { clearInterval(liveTimer); liveTimer = null; }
  }

  // Live update follows the newest queries, so it shows the first page.
  function toggleLive() {
    if (live) { stopLive(); return; }
    live = true;
    runQuery(1);
    liveTimer = setInterval(() => runQuery(1), 3000);
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

  function fmt(n) {
    return Number(n || 0).toLocaleString();
  }

  // Stop live polling when the view is left; the interval would otherwise
  // keep querying (and stack up) after navigating away.
  onDestroy(stopLive);

  // Load the first page once. (Re-running whenever the list came back empty
  // would poll the server in a loop while the log is empty, and an effect
  // would re-run on every keystroke in the filter fields it reads.)
  onMount(() => runQuery(1));
</script>

<PageHeader icon={icons.logs} title="Logs" tagline={current.tagline} />

<div class="tabs">
  {#each TABS as t (t.id)}
    <button class="tab" class:active={tab === t.id} onclick={() => openTab(t.id)}>{t.label}</button>
  {/each}
</div>

{#if tab === 'server'}
  {#if error}
    <div class="card" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">{error}</div>
  {/if}
  <div class="card">
    <div class="spread" style="margin-bottom: 10px; gap: 10px; flex-wrap: wrap">
      <h3 style="margin: 0">Server Log ({fmt(shownLogs.length)}{shownLogs.length !== logs.length ? ` of ${fmt(logs.length)}` : ''})</h3>
      <div class="row" style="gap: 8px; flex-wrap: wrap">
        <input type="search" placeholder="Search Messages" bind:value={logSearch} style="min-width: 200px" />
        <select bind:value={logLevel} aria-label="Level">
          <option value="">All Levels</option>
          {#each LEVELS as [value, label] (value)}<option value={value}>{label}</option>{/each}
        </select>
        <button class="secondary" onclick={refresh}>Reload</button>
      </div>
    </div>
    <div class="table-wrap" style="max-height: 70vh; overflow-y: auto">
      <table>
        <thead>
          <tr><th title={`Shown in ${displayZoneName()}`}>Time</th><th>Level</th><th>Component</th><th>Message</th></tr>
        </thead>
        <tbody>
          {#each shownLogs as entry, i (i)}
            <tr>
              <td style="white-space: nowrap">{formatDateTime(entry.timestamp)}</td>
              <td><span class:pill={true} class:ok={entry.level === 'info'} class:err={entry.level === 'error'} class:warn={entry.level === 'warn'}>
                {levelLabel(entry.level)}
              </span></td>
              <td>{entry.component}</td>
              <td class="message">{entry.message}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    {#if logs.length === 0}
      <p class="muted">No log entries yet.</p>
    {:else if shownLogs.length === 0}
      <p class="muted">No entries match this search.</p>
    {/if}
    <p class="muted help">Newest first. Shows the last 500 entries; older ones are dropped.</p>
  </div>
{:else}
  <div class="card" style="margin-bottom: 14px">
    <form onsubmit={(e) => { e.preventDefault(); apply(); }}>
      <div class="filter-grid">
        <label>Client IP
          <input placeholder="192.168.1.20" bind:value={fClient} />
        </label>
        <label>Domain
          <input placeholder="example.com or *.example.com" bind:value={fQname} />
        </label>
        <label>Type
          <select bind:value={fQtype} onchange={apply}>
            <option value="">Any</option>
            {#each QTYPES as t (t)}<option value={t}>{t}</option>{/each}
          </select>
        </label>
        <label>Protocol
          <select bind:value={fProtocol} onchange={apply}>
            <option value="">Any</option>
            {#each PROTOCOLS as [value, label] (value)}<option value={value}>{label}</option>{/each}
          </select>
        </label>
        <label>Result
          <select bind:value={fOutcome} onchange={apply}>
            <option value="">Any</option>
            {#each OUTCOMES as [value, label] (value)}<option value={value}>{label}</option>{/each}
          </select>
        </label>
        <label>Response Code
          <select bind:value={fRcode} onchange={apply}>
            <option value="">Any</option>
            {#each RCODES as r (r)}<option value={r}>{r}</option>{/each}
          </select>
        </label>
        <label>From <span class="tz">{displayZoneName()}</span>
          <input type="datetime-local" bind:value={fFrom} />
        </label>
        <label>To <span class="tz">{displayZoneName()}</span>
          <input type="datetime-local" bind:value={fTo} />
        </label>
      </div>
      <div class="spread" style="margin-top: 12px; gap: 8px; flex-wrap: wrap">
        <div class="row" style="gap: 8px">
          <button type="submit">Search</button>
          <button type="button" class="secondary" onclick={resetFilters} disabled={!filtersActive}>Reset Filters</button>
          <label class="live">
            <input type="checkbox" checked={live} onchange={toggleLive} />
            <span>Live Update</span>
          </label>
        </div>
        <div class="row" style="gap: 8px">
          <button type="button" class="secondary" onclick={exportCsv} title="Download every matching query as CSV">Export CSV</button>
          <button type="button" class="danger" onclick={clearLog}>Clear Log</button>
        </div>
      </div>
    </form>
  </div>

  {#if qNotice}
    <div class="card" style="border-color: var(--ok); margin-bottom: 14px">{qNotice}</div>
  {/if}
  {#if qError}
    <div class="card" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">{qError}</div>
  {/if}

  <div class="card">
    <div class="spread" style="margin-bottom: 10px; gap: 10px; flex-wrap: wrap">
      <h3 style="margin: 0">{filtersActive ? 'Matching Queries' : 'Queries'} ({fmt(qTotal)})</h3>
      <label class="per-page">Per Page
        <select bind:value={perPage} onchange={apply}>
          <option value={25}>25</option>
          <option value={50}>50</option>
          <option value={100}>100</option>
          <option value={200}>200</option>
        </select>
      </label>
    </div>
    <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th title={`Shown in ${displayZoneName()}`}>Time</th>
          <th>Client</th>
          <th>Domain</th>
          <th>Type</th>
          <th>Protocol</th>
          <th>Result</th>
          <th>Response Code</th>
          <th class="num">Took</th>
        </tr>
      </thead>
      <tbody>
        {#each qEntries as entry (entry.id)}
          <tr>
            <td style="white-space: nowrap">{formatDateTime(entry.ts)}</td>
            <td><button type="button" class="link" onclick={() => filterBy('client', entry.client)} title="Show only this client"><code>{entry.client}</code></button></td>
            <td><button type="button" class="link" onclick={() => filterBy('qname', entry.qname)} title="Show only this domain"><code>{entry.qname}</code></button></td>
            <td>{entry.qtype}</td>
            <td title={PROTOCOLS.find(([v]) => v === entry.protocol)?.[1] || ''}>{PROTOCOL_SHORT[entry.protocol] || entry.protocol.toUpperCase()}</td>
            <td><span class:pill={true} class:ok={outcomeClass(entry.outcome) === 'ok'} class:err={outcomeClass(entry.outcome) === 'err'} class:warn={outcomeClass(entry.outcome) === 'warn'}>
              {outcomeLabel(entry.outcome)}
            </span></td>
            <td>{entry.rcode || '-'}</td>
            <td class="num">{entry.elapsed_ms} ms</td>
          </tr>
        {/each}
      </tbody>
    </table>
    </div>
    {#if qLoaded && !qLoading && qEntries.length === 0 && !qError}
      {#if filtersActive}
        <p class="muted">No queries match these filters.</p>
      {:else}
        <p class="muted">
          No queries recorded yet. Queries appear here as clients use the
          server. If they never do, check that <code>query_db_enabled</code>
          is on in the <code>[logging]</code> section of the config file.
        </p>
      {/if}
    {/if}

    {#if qTotal > perPage}
      <div class="row pager">
        <button class="secondary" disabled={page <= 1 || live} onclick={() => runQuery(page - 1)}>← Prev</button>
        <span class="muted">Page {page} of {fmt(totalPages())}</span>
        <button class="secondary" disabled={page >= totalPages() || live} onclick={() => runQuery(page + 1)}>Next →</button>
      </div>
    {/if}
  </div>
{/if}

<style>
  .filter-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
    gap: 10px 14px;
  }
  .filter-grid label, .per-page {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 0.85rem;
    color: var(--muted);
  }
  .filter-grid label { position: relative; }
  .tz { position: absolute; right: 0; top: 0; font-size: 0.72rem; }
  .per-page { flex-direction: row; align-items: center; gap: 8px; }
  .live { display: flex; flex-direction: row; gap: 6px; align-items: center; margin-left: 8px; }
  .live input { width: auto; }
  .pager { margin-top: 12px; gap: 10px; align-items: center; }
  .message { word-break: break-word; }
  .help { margin-bottom: 0; }
  /* Table values that filter the list when clicked. */
  .link {
    background: none;
    border: none;
    padding: 0;
    color: inherit;
    cursor: pointer;
    text-align: left;
  }
  .link:hover code { color: var(--accent); text-decoration: underline; }
  .pill.warn {
    color: #e0a34e;
    border-color: #e0a34e;
  }
</style>

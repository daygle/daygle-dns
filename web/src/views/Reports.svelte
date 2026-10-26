<script>
  import { api, formatApiError } from '../api.js';
  import { formatDateTime } from '../datetime.svelte.js';

  // `onShowQueries(client)` opens the Query Log filtered to one device.
  let { onShowQueries = null } = $props();

  const PERIODS = [
    [24, 'Last 24 Hours'],
    [24 * 7, 'Last 7 Days'],
    [24 * 30, 'Last 30 Days'],
  ];

  let hours = $state(24);
  let report = $state(null);
  let logEnabled = $state(true);
  let error = $state(null);
  let loading = $state(false);
  // The device being looked at, and its own report.
  let device = $state(null);
  let deviceReport = $state(null);

  async function load() {
    loading = true;
    error = null;
    try {
      const data = await api.report(hours);
      report = data.report;
      logEnabled = data.query_log_enabled !== false;
      if (device) await loadDevice(device);
    } catch (e) {
      error = formatApiError(e);
    } finally {
      loading = false;
    }
  }

  async function loadDevice(client) {
    device = client;
    deviceReport = null;
    try {
      deviceReport = (await api.report(hours, client)).report;
    } catch (e) {
      error = formatApiError(e);
    }
  }

  function fmt(n) {
    return Number(n || 0).toLocaleString();
  }

  function percent(part, whole) {
    return whole ? `${((part * 100) / whole).toFixed(1)}%` : '0%';
  }

  $effect(() => {
    hours;
    load();
  });
</script>

{#if error}
  <div class="card" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">{error}</div>
{/if}

<div class="card" style="margin-bottom: 14px">
  <div class="spread" style="gap: 10px; flex-wrap: wrap">
    <h3 style="margin: 0">Summary</h3>
    <div class="row" style="gap: 8px">
      <select bind:value={hours} aria-label="Period">
        {#each PERIODS as [value, label] (value)}<option value={value}>{label}</option>{/each}
      </select>
      <button class="secondary" onclick={load} disabled={loading}>Reload</button>
    </div>
  </div>
  {#if report}
    <div class="tiles">
      <div class="tile"><div class="value">{fmt(report.queries)}</div><div class="muted">Queries</div></div>
      <div class="tile"><div class="value">{fmt(report.blocked)}</div><div class="muted">Blocked ({percent(report.blocked, report.queries)})</div></div>
      <div class="tile"><div class="value">{fmt(report.clients_seen)}</div><div class="muted">Devices</div></div>
    </div>
  {/if}
  {#if !logEnabled}
    <p class="muted help">
      The query log database is off (Settings → Logging), so there is nothing
      to report on.
    </p>
  {/if}
  <p class="muted help">
    Totals from the query log. A daily or weekly summary can also be sent
    by email or webhook under Settings → Alerts.
  </p>
</div>

{#if report}
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">Devices</h3>
    {#if report.clients.length}
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>Device</th><th class="num">Queries</th><th class="num">Blocked</th><th class="num">Blocked %</th><th>Last Seen</th><th class="num">Actions</th></tr>
          </thead>
          <tbody>
            {#each report.clients as c (c.client)}
              <tr class:selected={device === c.client}>
                <td><code>{c.client}</code></td>
                <td class="num">{fmt(c.queries)}</td>
                <td class="num">{fmt(c.blocked)}</td>
                <td class="num">{percent(c.blocked, c.queries)}</td>
                <td class="muted nowrap">{formatDateTime(c.last_seen)}</td>
                <td class="num">
                  <div class="row" style="gap: 6px; justify-content: flex-end">
                    <button class="secondary" onclick={() => loadDevice(c.client)}>Details</button>
                    {#if onShowQueries}<button class="secondary" onclick={() => onShowQueries(c.client)}>Queries</button>{/if}
                  </div>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {:else}
      <p class="muted">No queries in this period.</p>
    {/if}
    <p class="muted help">The most active devices first. Details shows a device's own most asked and most blocked domains.</p>
  </div>

  {#if device}
    <div class="card" style="margin-bottom: 14px">
      <div class="spread" style="margin-bottom: 10px">
        <h3 style="margin: 0">Device <code>{device}</code></h3>
        <button class="secondary" onclick={() => { device = null; deviceReport = null; }} aria-label="Close device details">✕</button>
      </div>
      {#if deviceReport}
        <p class="muted" style="margin: 0 0 10px">
          {fmt(deviceReport.queries)} queries, {fmt(deviceReport.blocked)} blocked ({percent(deviceReport.blocked, deviceReport.queries)}).
        </p>
        <div class="split">
          {@render names('Most Asked', deviceReport.top_domains)}
          {@render names('Most Blocked', deviceReport.top_blocked)}
        </div>
      {:else}
        <p class="muted">Loading...</p>
      {/if}
    </div>
  {/if}

  <div class="card">
    <div class="split">
      {@render names('Most Asked Domains', report.top_domains)}
      {@render names('Most Blocked Domains', report.top_blocked)}
    </div>
  </div>
{:else if loading}
  <div class="card"><p class="muted">Loading...</p></div>
{/if}

{#snippet names(title, rows)}
  <div>
    <h3 style="margin: 0 0 10px">{title}</h3>
    {#if rows.length}
      <table>
        <tbody>
          {#each rows as r, i (r.name)}
            <tr><td class="muted rank">{i + 1}</td><td><code>{r.name}</code></td><td class="num">{fmt(r.count)}</td></tr>
          {/each}
        </tbody>
      </table>
    {:else}
      <p class="muted">None.</p>
    {/if}
  </div>
{/snippet}

<style>
  .tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 10px; margin-top: 12px; }
  .tile { border: 1px solid var(--border); border-radius: 10px; padding: 12px 14px; }
  .value { font-size: 1.5rem; font-weight: 600; }
  .split { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  .rank { width: 2em; }
  .nowrap { white-space: nowrap; }
  tr.selected td { background: color-mix(in srgb, var(--accent) 10%, transparent); }
  code { word-break: break-all; }
  @media (max-width: 760px) {
    .split { grid-template-columns: 1fr; }
  }
</style>

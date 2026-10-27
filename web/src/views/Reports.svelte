<script>
  import IconButton from '../IconButton.svelte';
  import PageHeader from '../PageHeader.svelte';
  import { icons } from '../icons.svelte.js';
  import { api, formatApiError } from '../api.js';
  import { formatDate, formatDateTime, formatTimeShort } from '../datetime.svelte.js';
  import ClientLabel from '../ClientLabel.svelte';
  import ColumnPicker from '../ColumnPicker.svelte';
  import { isHidden } from '../columns.svelte.js';
  import { blockSourceLabel } from '../blockSources.js';

  const COLUMNS = [
    { key: 'device', label: 'Device', locked: true },
    { key: 'queries', label: 'Queries' },
    { key: 'blocked', label: 'Blocked' },
    { key: 'blocked-percent', label: 'Blocked %' },
    { key: 'last-seen', label: 'Last Seen' },
  ];
  const show = (key) => !isHidden('report-devices', key);

  // `onShowQueries(client)` opens the Query Log filtered to one device;
  // `onOpenSettings(tab)` opens a Settings tab (null for read-only accounts).
  let { onShowQueries = null, onOpenSettings = null } = $props();

  const PERIODS = [
    [24, 'Last 24 Hours'],
    [24 * 7, 'Last 7 Days'],
    [24 * 30, 'Last 30 Days'],
  ];

  const TABS = [
    {
      id: 'overview',
      label: 'Overview',
      tagline: 'What the query log adds up to over a period: how much traffic there was and when, and how the server answered it.',
    },
    {
      id: 'devices',
      label: 'Devices',
      tagline: 'The most active devices, with their own most asked and most blocked domains.',
    },
    {
      id: 'domains',
      label: 'Domains',
      tagline: 'The most asked and the most blocked domains, for every device.',
    },
    {
      id: 'blocking',
      label: 'Blocking',
      tagline: 'What is doing the blocking: each kind of block, and the lists, entries, services, AI categories and zones that blocked most.',
    },
    {
      id: 'responses',
      label: 'Responses',
      tagline: 'The response codes the server answered with, and the domains that most often failed to resolve.',
    },
  ];
  let tab = $state('overview');
  const current = $derived(TABS.find((t) => t.id === tab));

  let hours = $state(24);
  let report = $state(null);
  let logEnabled = $state(true);
  let error = $state(null);
  let loading = $state(false);
  // When the shown report was fetched (the end of its period).
  let loadedAt = $state(Date.now());
  // The device being looked at, and its own report.
  let device = $state(null);
  let deviceReport = $state(null);

  async function load() {
    loading = true;
    error = null;
    try {
      const data = await api.report(hours);
      report = data.report;
      loadedAt = Date.now();
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

  // How a query was answered (the query log's outcome).
  const OUTCOMES = {
    recursive: 'Resolved',
    authoritative: 'Your Zones',
    split_horizon: 'Split Horizon',
    blocked: 'Blocked',
    rate_limited: 'Rate Limited',
    error: 'Error',
  };
  const outcomeLabel = (o) => OUTCOMES[o] || o.replaceAll('_', ' ');

  // Response codes, with what they mean.
  const RCODES = {
    NOERROR: 'answered',
    NXDOMAIN: 'name does not exist',
    SERVFAIL: 'server failure',
    REFUSED: 'refused',
    FORMERR: 'malformed query',
    NOTIMP: 'not implemented',
  };
  const rcodeLabel = (r) => (r ? (RCODES[r] ? `${r} (${RCODES[r]})` : r) : 'Not Recorded');
  const sourceLabel = (s) => (s ? blockSourceLabel(s) : 'Unknown (logged before reasons were kept)');

  // Queries per hour (24 hours) or per day in the display time zone (longer
  // periods), with the empty ones filled in. The server counts per UTC hour.
  const HOUR = 3600 * 1000;
  const buckets = $derived.by(() => {
    if (!report) return [];
    const byHour = new Map((report.timeline || []).map((h) => [h.hour, h]));
    const end = Math.floor(loadedAt / HOUR) * HOUR;
    const out = [];
    for (let t = end - (hours - 1) * HOUR; t <= end; t += HOUR) {
      const key = `${new Date(t).toISOString().slice(0, 13)}:00:00Z`;
      const h = byHour.get(key);
      const daily = hours > 48;
      const label = daily ? formatDate(t) : formatTimeShort(t);
      const last = out[out.length - 1];
      if (daily && last && last.label === label) {
        last.queries += h?.queries || 0;
        last.blocked += h?.blocked || 0;
      } else {
        out.push({ key, label, title: daily ? label : formatDateTime(t), queries: h?.queries || 0, blocked: h?.blocked || 0 });
      }
    }
    return out;
  });
  const peak = $derived(Math.max(1, ...buckets.map((b) => b.queries)));
  // Evenly spaced axis labels, about one per 110px of chart so they never
  // overlap on a phone.
  let chartWidth = $state(0);
  const axis = $derived.by(() => {
    const n = buckets.length;
    if (!n) return [];
    const fit = Math.max(2, Math.floor((chartWidth || 600) / 110));
    const step = Math.max(1, Math.ceil(n / fit));
    return buckets.map((b, i) => (i % step === 0 ? b.label : ''));
  });

  $effect(() => {
    hours;
    load();
  });
</script>

<PageHeader icon={icons.reports} title="Reports" tagline={current.tagline} />

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
    by email or webhook under
    {#if onOpenSettings}
      <button type="button" class="link" onclick={() => onOpenSettings('alerts')}>Settings → Alerts</button>.
    {:else}
      Settings → Alerts.
    {/if}
  </p>
</div>

<div class="tabs">
  {#each TABS as t (t.id)}
    <button class="tab" class:active={tab === t.id} onclick={() => (tab = t.id)}>{t.label}</button>
  {/each}
</div>

{#if report}
  {#if tab === 'overview'}
    <div class="card" style="margin-bottom: 14px">
      <div class="spread" style="margin-bottom: 10px; gap: 10px; flex-wrap: wrap">
        <h3 style="margin: 0">Activity</h3>
        <span class="muted small">
          <span class="key queries"></span> Queries
          <span class="key blocked"></span> Blocked
          · per {hours > 48 ? 'day' : 'hour'}
        </span>
      </div>
      {#if report.queries}
        <div class="bars" bind:clientWidth={chartWidth} role="img" aria-label="Queries and blocks per {hours > 48 ? 'day' : 'hour'}">
          {#each buckets as b (b.key)}
            <div class="bar" title="{b.title}: {fmt(b.queries)} queries, {fmt(b.blocked)} blocked">
              <div class="bar-q" style="height: {(b.queries * 100) / peak}%">
                <div class="bar-b" style="height: {b.queries ? (b.blocked * 100) / b.queries : 0}%"></div>
              </div>
            </div>
          {/each}
        </div>
        <div class="axis" aria-hidden="true">
          {#each axis as label, i (i)}<span>{label}</span>{/each}
        </div>
        <p class="muted help">Busiest {hours > 48 ? 'day' : 'hour'}: {fmt(peak)} queries. Hover a bar for its numbers.</p>
      {:else}
        <p class="muted">No queries in this period.</p>
      {/if}
    </div>

    <div class="card">
      <h3 style="margin: 0 0 10px">How Queries Were Answered</h3>
      {@render shares(report.outcomes, report.queries, outcomeLabel)}
      <p class="muted help">
        Resolved covers answers from the cache and from upstream; Your Zones are
        answers from the zones this server hosts.
      </p>
    </div>
  {:else if tab === 'devices'}
    <div class="card" style="margin-bottom: 14px">
      <div class="spread" style="margin-bottom: 10px">
        <h3 style="margin: 0">Devices</h3>
        <ColumnPicker table="report-devices" columns={COLUMNS} />
      </div>
      {#if report.clients.length}
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Device</th>
                {#if show('queries')}<th class="num">Queries</th>{/if}
                {#if show('blocked')}<th class="num">Blocked</th>{/if}
                {#if show('blocked-percent')}<th class="num">Blocked %</th>{/if}
                {#if show('last-seen')}<th>Last Seen</th>{/if}
                <th class="num">Actions</th>
              </tr>
            </thead>
            <tbody>
              {#each report.clients as c (c.client)}
                <tr class:selected={device === c.client}>
                  <td><ClientLabel address={c.client} /></td>
                  {#if show('queries')}<td class="num">{fmt(c.queries)}</td>{/if}
                  {#if show('blocked')}<td class="num">{fmt(c.blocked)}</td>{/if}
                  {#if show('blocked-percent')}<td class="num">{percent(c.blocked, c.queries)}</td>{/if}
                  {#if show('last-seen')}<td class="muted nowrap">{formatDateTime(c.last_seen)}</td>{/if}
                  <td class="num">
                    <div class="row" style="gap: 6px; justify-content: flex-end">
                      <IconButton icon="info" label="Details" onclick={() => loadDevice(c.client)} />
                      {#if onShowQueries}<IconButton icon="list" label="Show this client's queries" onclick={() => onShowQueries(c.client)} />{/if}
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
      <div class="card">
        <div class="spread" style="margin-bottom: 10px">
          <h3 style="margin: 0">Device <ClientLabel address={device} /></h3>
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
  {:else if tab === 'domains'}
    <div class="card">
      <div class="split">
        {@render names('Most Asked Domains', report.top_domains)}
        {@render names('Most Blocked Domains', report.top_blocked)}
      </div>
    </div>
  {:else if tab === 'blocking'}
    <div class="card" style="margin-bottom: 14px">
      <h3 style="margin: 0 0 10px">Blocked By</h3>
      {@render shares(report.block_sources, report.blocked, sourceLabel)}
    </div>
    <div class="card">
      <h3 style="margin: 0 0 10px">Top Blocking Rules</h3>
      {#if report.block_rules.length}
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Blocked By</th><th>Matched</th><th>Filtering Group</th><th class="num">Blocked</th><th class="num">Share</th></tr>
            </thead>
            <tbody>
              {#each report.block_rules as r, i (i)}
                <tr>
                  <td>{sourceLabel(r.source)}</td>
                  <td>{#if r.matched}<code>{r.matched}</code>{:else}<span class="muted">-</span>{/if}</td>
                  <td>{r.group || '-'}</td>
                  <td class="num">{fmt(r.count)}</td>
                  <td class="num">{percent(r.count, report.blocked)}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        <p class="muted help">
          Matched is the blocklist, list entry, service, AI category or zone that
          blocked the query. A blocklist that never shows up here may not be worth
          keeping.
        </p>
      {:else}
        <p class="muted">Nothing was blocked in this period.</p>
      {/if}
    </div>
  {:else if tab === 'responses'}
    <div class="card" style="margin-bottom: 14px">
      <h3 style="margin: 0 0 10px">Response Codes</h3>
      {@render shares(report.rcodes, report.queries, rcodeLabel)}
      <p class="muted help">
        Blocked queries are counted under the code the block answers with
        (usually NXDOMAIN). A rise in SERVFAIL points at upstream or DNSSEC
        trouble.
      </p>
    </div>
    <div class="card">
      <h3 style="margin: 0 0 10px">Most Failing Domains</h3>
      {#if report.failing.length}
        <table>
          <tbody>
            {#each report.failing as f, i (f.name + f.rcode)}
              <tr>
                <td class="muted rank">{i + 1}</td>
                <td><code>{f.name}</code></td>
                <td><span class="pill">{f.rcode}</span></td>
                <td class="num">{fmt(f.count)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
        <p class="muted help">
          Names answered NXDOMAIN, SERVFAIL or REFUSED, not counting blocks and
          rate limiting. A device asking for many names that do not exist is
          often misconfigured, or infected.
        </p>
      {:else}
        <p class="muted">No failed lookups in this period.</p>
      {/if}
    </div>
  {/if}
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

{#snippet shares(rows, whole, label)}
  {#if rows.length}
    {#each rows as r (r.name)}
      <div class="share-row">
        <span class="share-label">{label(r.name)}</span>
        <div class="share-bar" aria-hidden="true"><div class="share-fill" style="width: {whole ? (r.count * 100) / whole : 0}%"></div></div>
        <span class="share-val">{fmt(r.count)} · {percent(r.count, whole)}</span>
      </div>
    {/each}
  {:else}
    <p class="muted">None in this period.</p>
  {/if}
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
  /* An inline link to another page, in running text. */
  .link { background: none; border: none; padding: 0; font: inherit; color: var(--accent); cursor: pointer; }
  .link:hover { text-decoration: underline; }

  /* Activity: one bar per hour or day, the blocked part drawn inside it. */
  .bars { display: flex; align-items: flex-end; gap: 2px; height: 170px; border-bottom: 1px solid var(--border); }
  .bar { flex: 1 1 0; min-width: 0; height: 100%; display: flex; align-items: flex-end; }
  .bar-q {
    width: 100%;
    min-height: 1px;
    background: color-mix(in srgb, var(--accent) 70%, transparent);
    border-radius: 2px 2px 0 0;
    display: flex;
    align-items: flex-end;
  }
  .bar:hover .bar-q { background: var(--accent); }
  .bar-b { width: 100%; background: var(--danger); }
  .axis { display: flex; gap: 2px; margin-top: 4px; font-size: 0.72rem; color: var(--muted); }
  .axis span { flex: 1 1 0; min-width: 0; overflow: visible; white-space: nowrap; }
  .key { display: inline-block; width: 9px; height: 9px; border-radius: 2px; margin: 0 3px 0 8px; vertical-align: -1px; }
  .key.queries { background: var(--accent); }
  .key.blocked { background: var(--danger); }

  /* Breakdowns: label, share bar, count and percentage. */
  /* A fixed value column so every row's bar starts and ends in line. */
  .share-row { display: grid; grid-template-columns: minmax(120px, 34%) minmax(0, 1fr) 10em; gap: 12px; align-items: center; padding: 5px 0; }
  .share-label { font-size: 0.88rem; }
  .share-bar { height: 8px; border-radius: 4px; background: color-mix(in srgb, var(--accent) 12%, transparent); overflow: hidden; }
  .share-fill { height: 100%; background: var(--accent); border-radius: 4px; }
  .share-val { font-size: 0.85rem; font-variant-numeric: tabular-nums; text-align: right; white-space: nowrap; }

  @media (max-width: 760px) {
    .split { grid-template-columns: 1fr; }
    .share-row { grid-template-columns: minmax(0, 1fr) auto; }
    .share-bar { grid-column: 1 / -1; grid-row: 2; }
  }
</style>

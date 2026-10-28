<script>
  import { onMount } from 'svelte';
  import { api, formatApiError, formatUptime, getStoredUser } from '../api.js';
  import PageHeader from '../PageHeader.svelte';
  import ResolverDashboard from './ResolverDashboard.svelte';
  import { icons, actionIcons } from '../icons.svelte.js';
  import { formatTime, formatTimeShort, formatDateTime } from '../datetime.svelte.js';
  import WhyBlocked from '../WhyBlocked.svelte';
  import ClientLabel from '../ClientLabel.svelte';

  // Navigate to the Update page (passed by the app shell).
  let { onOpenUpdate = null } = $props();

  let status = $state(null);
  let metrics = $state(null);
  let stats = $state(null);
  // Host resource readings (optional endpoint): null until the first
  // response, and kept as-is when a later fetch fails.
  let host = $state(null);
  // Why the host stats could not be fetched (shown on the Server card).
  let hostError = $state(null);
  // The Top Blocked row being explained: after a lookup of that domain's
  // newest blocked query-log row, the same Block Details modal the Query
  // Log shows ({ qname, client, qtype, ts, block, note }).
  let why = $state(null);

  async function openWhyBlocked(row) {
    try {
      const data = await api.queryLogs(
        `qname=${encodeURIComponent(row.key)}&outcome=blocked&per_page=1`,
      );
      const entry = (data.entries || [])[0];
      why = entry
        ? { qname: entry.qname, client: entry.client, qtype: entry.qtype, ts: entry.ts, block: entry.block }
        : { qname: row.key, client: '', qtype: 'A', ts: null, block: null, note: 'No blocked query for this domain in the kept query log.' };
    } catch (e) {
      why = { qname: row.key, client: '', qtype: 'A', ts: null, block: null, note: formatApiError(e) };
    }
  }
  // Host stats are admin-only; a viewer's request would only ever be refused.
  const isAdmin = getStoredUser()?.role !== 'viewer';
  let window_ = $state('1h');
  let error = $state(null);
  // When the data on screen was fetched (shown if a later refresh fails).
  let loadedAt = $state(null);

  // Plain variable, not state: it only guards against overlapping requests.
  let inFlight = false;
  // Bumped on every refresh so the resolver dashboard reloads with the page.
  let refreshKey = $state(0);

  async function refresh() {
    // Skip if a previous refresh is still in flight: the interval keeps firing,
    // but we don't want overlapping requests stacking up if the server stalls.
    if (inFlight) return;
    inFlight = true;
    error = null;
    try {
      const [s, m, st] = await Promise.all([
        api.status(),
        api.metrics(),
        api.stats(window_),
      ]);
      status = s;
      metrics = m;
      stats = st;
      // Host stats ride along on the same cadence but must never fail the
      // page: an error keeps whatever is already on screen and says why.
      // A host that reported it cannot collect them is not asked again.
      if (isAdmin && host?.supported !== false) {
        api
          .hostStats()
          .then((h) => {
            host = h;
            hostError = null;
          })
          .catch((e) => (hostError = formatApiError(e)));
      }
      loadedAt = Date.now();
      refreshKey += 1;
    } catch (e) {
      error = formatApiError(e);
    } finally {
      inFlight = false;
    }
  }

  // Refresh on mount and every 10 s afterwards. (An $effect here would
  // track the state `refresh` reads and re-run it after every response,
  // polling the server continuously.)
  onMount(() => {
    refresh();
    const id = setInterval(refresh, 10_000);
    return () => clearInterval(id);
  });

  const WINDOWS = [
    ['1h', '1 Hour', 'the last hour'],
    ['6h', '6 Hours', 'the last 6 hours'],
    ['24h', '24 Hours', 'the last 24 hours'],
  ];
  const windowText = $derived(WINDOWS.find(([w]) => w === window_)?.[2] || '');

  function chooseWindow(w) {
    window_ = w;
    refresh();
  }

  const cards = $derived([
    { label: 'Total Queries', value: metrics?.total_queries ?? 0 },
    { label: 'Authoritative', value: metrics?.authoritative ?? 0 },
    { label: 'Recursive', value: metrics?.recursive ?? 0 },
    { label: 'Blocked', value: metrics?.blocked ?? 0 },
    { label: 'Errors', value: metrics?.errors ?? 0 },
  ]);

  // ---- chart geometry ------------------------------------------------------
  // The SVG is drawn at the container's real pixel width (measured via
  // `bind:clientWidth`) so a 1:1 viewBox keeps strokes crisp and markers round
  // - a fixed viewBox with `preserveAspectRatio="none"` would stretch them.
  let cw = $state(720); // measured container width in px
  let hover = $state(null); // nearest-point readout under the cursor
  const H = 190;
  const PAD = 10; // top / right / bottom padding
  const PAD_L = 40; // left padding - room for the y-axis labels
  const W = $derived(Math.max(320, Math.round(cw)));

  const series = $derived(stats?.series ?? []);
  const totals = $derived({
    queries: series.reduce((a, p) => a + p.queries, 0),
    blocked: series.reduce((a, p) => a + p.blocked, 0),
    errors: series.reduce((a, p) => a + p.errors, 0),
    rate_limited: series.reduce((a, p) => a + p.rate_limited, 0),
  });

  const chart = $derived.by(() => {
    if (!series.length) return null;
    const n = series.length;
    const maxQ = Math.max(4, ...series.map((p) => p.queries));
    const maxB = Math.max(4, ...series.map((p) => p.blocked));
    const maxY = Math.max(maxQ, maxB * 2);
    const innerH = H - 2 * PAD;
    const step = (W - PAD_L - PAD) / Math.max(1, n - 1);
    const y = (v) => H - PAD - (v / maxY) * innerH;
    const x = (i) => PAD_L + i * step;
    const pts = (key) =>
      series.map((p, i) => `${x(i).toFixed(1)},${y(p[key]).toFixed(1)}`).join(' ');
    const area = (key) =>
      `${x(0).toFixed(1)},${H - PAD} ${pts(key)} ${x(n - 1).toFixed(1)},${H - PAD}`;
    // Label every sixth point with the wall-clock time.
    const every = Math.max(1, Math.round(n / 6));
    const labels = series
      .map((p, i) => ({ i, t: p.t }))
      .filter(({ i }) => i % every === 0)
      .map(({ i, t }) => ({
        x: x(i),
        label: formatTimeShort(t * 1000),
      }));
    const grid = [0, 0.25, 0.5, 0.75, 1].map((f) => ({
      y: y(maxY * f),
      label: Math.round(maxY * f),
    }));
    return {
      n,
      step,
      x,
      y,
      queriesPts: pts('queries'),
      blockedPts: pts('blocked'),
      queriesArea: area('queries'),
      labels,
      grid,
    };
  });

  // Map the cursor to the nearest bucket and record its values for the tooltip.
  function onMove(ev) {
    const c = chart;
    if (!c) return;
    const rect = ev.currentTarget.getBoundingClientRect();
    const px = ((ev.clientX - rect.left) / rect.width) * W;
    let i = Math.round((px - PAD_L) / c.step);
    i = Math.max(0, Math.min(c.n - 1, i));
    const p = series[i];
    const xi = c.x(i);
    const ratio = xi / W;
    hover = {
      x: xi,
      qy: c.y(p.queries),
      by: c.y(p.blocked),
      t: p.t,
      queries: p.queries,
      blocked: p.blocked,
      authoritative: p.authoritative,
      recursive: p.recursive,
      errors: p.errors,
      rate_limited: p.rate_limited,
      align: ratio < 0.18 ? 'l' : ratio > 0.82 ? 'r' : 'c',
    };
  }
  function onLeave() {
    hover = null;
  }

  function fmt(n) {
    return n.toLocaleString();
  }
  function clockLabel(t) {
    return formatTime(t * 1000);
  }

  // ---- host resources (Server card, from /api/host-stats) -------------------
  // A kibibyte count from the kernel as a compact string; '?' when absent.
  function fmtKb(kb) {
    if (kb == null || Number.isNaN(kb)) return '?';
    const gib = kb / 1024 / 1024;
    if (gib >= 1) return `${gib >= 100 ? Math.round(gib) : gib.toFixed(1)} GiB`;
    return `${Math.round(kb / 1024)} MiB`;
  }

  const hostRows = $derived.by(() => {
    if (!host?.supported) return [];
    const mem = host.memory ?? {};
    const memUsed =
      mem.total_kb != null &&
      mem.available_kb != null &&
      mem.total_kb >= mem.available_kb
        ? mem.total_kb - mem.available_kb
        : null;
    const disk = host.disks?.find((d) => d.mount === '/') ?? host.disks?.[0];
    const rows = [
      {
        label: 'CPU',
        pct: host.cpu?.usage_percent ?? null,
        value:
          host.cpu?.usage_percent == null
            ? `${host.cpu?.cores ?? '?'} cores`
            : `${host.cpu.usage_percent}% · ${host.cpu.cores ?? '?'} cores`,
      },
      {
        label: 'Load',
        pct: null,
        value:
          host.load?.one == null
            ? '?'
            : `${host.load.one} / ${host.load.five} / ${host.load.fifteen}`,
        hint: '(1 / 5 / 15 min)',
      },
      {
        label: 'Memory',
        pct: mem.used_percent ?? null,
        value:
          memUsed == null ? (mem.used_percent != null ? `${mem.used_percent}%` : '?') : `${fmtKb(memUsed)} / ${fmtKb(mem.total_kb)}`,
      },
    ];
    if (disk?.total_kb != null) {
      rows.push({
        label: 'Disk /',
        pct: disk.used_percent ?? null,
        value: `${fmtKb(disk.used_kb)} / ${fmtKb(disk.total_kb)}`,
      });
    }
    return rows;
  });
</script>

<PageHeader icon={icons.status} title="Server Status" tagline="Live traffic and health at a glance. Updates every 10 seconds." />

{#if status?.update_available}
  <div class="card update-available">
    <div class="spread">
      <div>
        <strong>Update available</strong>
        <p class="muted small" style="margin: 2px 0 0">
          Release v{status.latest_release} is available; this server runs
          v{status.version}. Open the Update page to install it.
        </p>
      </div>
      {#if onOpenUpdate}
        <button class="secondary" onclick={onOpenUpdate}>Open Update</button>
      {/if}
    </div>
  </div>
{/if}
{#if error}
  <div class="card" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">
    Could not refresh ({error.replace(/\.$/, '')}).{#if loadedAt}{' '}Showing the data from {formatDateTime(loadedAt)}.{/if}
  </div>
{/if}
{#if !status}
  <div class="card">
    <p class="muted">Loading...</p>
  </div>
{:else}
  <p class="muted since">Since the server started {formatUptime(status.uptime_secs)} ago:</p>
  <div class="grid">
    {#each cards as card (card.label)}
      <div class="card stat">
        <div class="muted">{card.label}</div>
        <div class="big">{card.value.toLocaleString()}</div>
      </div>
    {/each}
  </div>

  {#if hostRows.length || (isAdmin && (host || hostError))}
    <div class="card" style="margin-top: 14px">
      <div class="spread" style="margin-bottom: 10px">
        <h3 style="margin: 0">Server</h3>
        {#if hostRows.length}
          <span class="muted small">
            {#if host.hostname}{host.hostname} · {/if}up
            {host.uptime_secs == null ? '?' : formatUptime(host.uptime_secs)}
          </span>
        {/if}
      </div>
      {#if host && !host.supported}
        <p class="muted small" style="margin: 0">
          Server resource usage is not available: {host.reason || 'this host does not report it'}.
        </p>
      {:else if hostError}
        <p class="muted small" style="margin: {hostRows.length ? '0 0 8px' : '0'}">
          {hostRows.length ? 'Could not refresh' : 'Could not load'} server resource usage: {hostError}
        </p>
      {/if}
      {#each hostRows as row (row.label)}
        <div class="host-row">
          <span class="host-label muted">{row.label}</span>
          <div class="host-bar" aria-hidden="true">
            {#if row.pct != null}
              <div
                class="host-fill"
                class:warn={row.pct >= 80}
                class:danger={row.pct >= 92}
                style="width: {row.pct}%"
              ></div>
            {/if}
          </div>
          <span class="host-val">{row.value} {row.hint ? row.hint : ''}</span>
        </div>
      {/each}
    </div>
  {/if}

  <div class="card" style="margin-top: 14px">
    <div class="spread" style="margin-bottom: 10px">
      <h3 style="margin: 0">Query Volume</h3>
      <div class="row" role="group" aria-label="Time window">
        {#each WINDOWS as [w, label] (w)}
          <button
            class="secondary"
            class:sel={window_ === w}
            aria-pressed={window_ === w}
            style="padding: 4px 10px"
            onclick={() => chooseWindow(w)}
          >{label}</button>
        {/each}
      </div>
    </div>

    <div class="row" style="margin-bottom: 8px; font-size: 0.85rem">
      <span class="legend"><span class="dot accent"></span> {fmt(totals.queries)} queries</span>
      <span class="legend"><span class="dot danger"></span> {fmt(totals.blocked)} blocked</span>
      <span class="legend muted">{fmt(totals.errors)} errors · {fmt(totals.rate_limited)} rate-limited · in {windowText}, per minute</span>
    </div>

    {#if chart}
      <div class="chart-wrap" bind:clientWidth={cw}>
        <svg
          viewBox="0 0 {W} {H}"
          class="chart"
          role="img"
          aria-label="Queries per minute"
          onpointermove={onMove}
          onpointerleave={onLeave}
        >
          <defs>
            <linearGradient id="qfill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" class="grad-top" />
              <stop offset="100%" class="grad-bottom" />
            </linearGradient>
          </defs>
          {#each chart.grid as g (g.y)}
            <line x1={PAD_L} x2={W - PAD} y1={g.y} y2={g.y} class="gridline"></line>
            <text x={PAD_L - 8} y={g.y} class="ylabel">{fmt(g.label)}</text>
          {/each}
          <polygon points={chart.queriesArea} class="fill"></polygon>
          <polyline points={chart.queriesPts} class="line queries"></polyline>
          <polyline points={chart.blockedPts} class="line blocked"></polyline>
          {#if hover}
            <line x1={hover.x} x2={hover.x} y1={PAD} y2={H - PAD} class="crosshair"></line>
            <circle cx={hover.x} cy={hover.by} r="3.5" class="marker blocked"></circle>
            <circle cx={hover.x} cy={hover.qy} r="3.5" class="marker queries"></circle>
          {/if}
        </svg>
        {#if hover}
          <div
            class="tip"
            class:tl={hover.align === 'l'}
            class:tr={hover.align === 'r'}
            style="left: {(hover.x / W) * 100}%"
          >
            <div class="tip-t">{clockLabel(hover.t)}</div>
            <div class="tip-row"><span class="dot accent"></span> Queries <b>{fmt(hover.queries)}</b></div>
            <div class="tip-row"><span class="dot danger"></span> Blocked <b>{fmt(hover.blocked)}</b></div>
            <div class="tip-sub">{fmt(hover.authoritative)} auth · {fmt(hover.recursive)} recursive</div>
            <div class="tip-sub">{fmt(hover.errors)} errors · {fmt(hover.rate_limited)} rate-limited</div>
          </div>
        {/if}
      </div>
      <div class="axis">
        {#each chart.labels as l (l.x)}
          <span style="left: {(l.x / W) * 100}%">{l.label}</span>
        {/each}
      </div>
    {:else}
      <p class="muted">No traffic yet - the chart fills in as queries arrive.</p>
    {/if}
  </div>

  <div class="tops">
    <div class="card">
      <h3 style="margin: 0 0 10px">Top Clients <span class="muted small-h">Since Start</span></h3>
      {#if stats?.top_clients?.length}
        <table>
          <tbody>
            {#each stats.top_clients as row, i (row.key)}
              <tr><td class="muted">#{i + 1}</td><td><ClientLabel address={row.key} /></td><td class="num">{fmt(row.count)}</td></tr>
            {/each}
          </tbody>
        </table>
      {:else}
        <p class="muted">No clients yet.</p>
      {/if}
    </div>
    <div class="card">
      <h3 style="margin: 0 0 10px">Top Domains <span class="muted small-h">Since Start</span></h3>
      {#if stats?.top_domains?.length}
        <table>
          <tbody>
            {#each stats.top_domains as row, i (row.key)}
              <tr><td class="muted">#{i + 1}</td><td><code>{row.key}</code></td><td class="num">{fmt(row.count)}</td></tr>
            {/each}
          </tbody>
        </table>
      {:else}
        <p class="muted">No domains yet.</p>
      {/if}
    </div>
    <div class="card">
      <h3 style="margin: 0 0 10px">Top Blocked <span class="muted small-h">Since Start</span></h3>
      {#if stats?.top_blocked?.length}
        <table>
          <tbody>
            {#each stats.top_blocked as row, i (row.key)}
              <tr>
                <td class="muted">#{i + 1}</td>
                <td>
                  <code>{row.key}</code>
                  <button type="button" class="link why" onclick={() => openWhyBlocked(row)} title="Block details: every check this domain meets for this device, and which one decides the block" aria-label="Block details">
                    <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d={actionIcons.info} /></svg>
                  </button>
                </td>
                <td class="num">{fmt(row.count)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {:else}
        <p class="muted">Nothing blocked yet.</p>
      {/if}
    </div>
  </div>

  <ResolverDashboard {refreshKey} />

  <div class="card" style="margin-top: 14px">
    <h3 style="margin: 0 0 10px">Runtime</h3>
    <table>
      <tbody>
        <tr><td class="muted">Uptime</td><td>{formatUptime(status.uptime_secs)}</td></tr>
        <tr><td class="muted">Zones</td><td>{status.zones}</td></tr>
        <tr><td class="muted">Records</td><td>{status.records}</td></tr>
        {#each [['DNS over TLS', status.dot_enabled], ['DNS over HTTPS', status.doh_enabled], ['DNS over QUIC', status.doq_enabled]] as [label, on] (label)}
          <tr>
            <td class="muted">{label}</td>
            <td><span class="pill" class:ok={on}>{on ? 'On' : 'Off'}</span></td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}

{#if why}
  <div class="modal-backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && (why = null)}>
    <div class="modal card wide" role="dialog" aria-modal="true" aria-labelledby="why-title">
      <div class="spread" style="margin-bottom: 10px">
        <h3 id="why-title" style="margin: 0">Block Details: {why.qname}</h3>
        <button class="secondary" style="padding: 2px 10px" onclick={() => (why = null)} aria-label="Close">✕</button>
      </div>
      {#if why.block}
        <p style="margin-top: 0">At {formatDateTime(why.ts)}: {why.block.reason}.</p>
      {:else if why.note}
        <p class="muted" style="margin-top: 0">{why.note}</p>
      {/if}
      <p class="muted help" style="margin-top: 0">How the server treats it now:</p>
      <WhyBlocked domain={why.qname} client={why.client} qtype={why.qtype} auto={Boolean(why.client)} />
    </div>
  </div>
{/if}

<style>
  .update-available { border-color: var(--warn); background: color-mix(in srgb, var(--warn) 8%, transparent); margin-bottom: 14px; }
  .update-available strong { color: var(--warn); }

  /* Block Details: the same info link and modal the Query Log has. */
  .why { margin-left: 6px; padding: 0; line-height: 0; vertical-align: middle; }
  .modal-backdrop { position: fixed; inset: 0; background: rgb(0 0 0 / 0.65); display: grid; place-items: center; padding: 16px; z-index: 50; }
  .modal.wide { width: min(980px, 100%); max-height: calc(100vh - 32px); overflow: auto; }
  .help { margin-bottom: 0; }

  /* Five tiles: one row, or rows of three and two, or (on phones) Total
     Queries across the top over two rows of two - never a lone tile. */
  .grid {
    display: grid;
    grid-template-columns: repeat(5, minmax(0, 1fr));
    gap: 12px;
  }
  @media (max-width: 1180px) {
    .grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
  }
  @media (max-width: 560px) {
    .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .grid > :first-child { grid-column: 1 / -1; }
  }
  .stat .big { font-size: 1.6rem; font-weight: 700; margin-top: 6px; }
  .since { margin: 0 0 8px; font-size: 0.85rem; }
  .small-h { font-size: 0.72rem; font-weight: 500; margin-left: 6px; }

  /* Server card: one row per reading (label, bar, value). The bar has a
     fixed height and round caps like the resolver dashboard's. */
  .host-row {
    display: grid;
    grid-template-columns: 90px minmax(0, 1fr) auto;
    gap: 12px;
    align-items: center;
    padding: 5px 0;
  }
  .host-label { font-size: 0.85rem; }
  .host-bar {
    height: 8px;
    border-radius: 4px;
    background: color-mix(in srgb, var(--accent) 12%, transparent);
    overflow: hidden;
  }
  .host-fill {
    height: 100%;
    min-width: 0;
    background: var(--accent);
    border-radius: 4px;
    transition: width 0.4s ease;
  }
  .host-fill.warn { background: var(--warn); }
  .host-fill.danger { background: var(--danger); }
  .host-val { font-size: 0.85rem; font-variant-numeric: tabular-nums; text-align: right; }

  .chart-wrap { position: relative; }
  .chart { width: 100%; height: 190px; display: block; touch-action: none; }
  .gridline { stroke: var(--border); stroke-width: 1; }
  .ylabel {
    fill: var(--muted);
    font-size: 9px;
    text-anchor: end;
    dominant-baseline: middle;
  }
  .fill { fill: url(#qfill); }
  .grad-top { stop-color: var(--accent); stop-opacity: 0.28; }
  .grad-bottom { stop-color: var(--accent); stop-opacity: 0; }
  .line { fill: none; stroke-width: 2; stroke-linejoin: round; stroke-linecap: round; }
  .line.queries { stroke: var(--accent); }
  .line.blocked { stroke: var(--danger); }
  .crosshair { stroke: var(--muted); stroke-width: 1; stroke-dasharray: 3 3; opacity: 0.65; }
  .marker { stroke: var(--panel); stroke-width: 1.5; }
  .marker.queries { fill: var(--accent); }
  .marker.blocked { fill: var(--danger); }

  .tip {
    position: absolute;
    top: 8px;
    transform: translateX(-50%);
    background: var(--panel-2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 6px 9px;
    font-size: 0.72rem;
    line-height: 1.35;
    pointer-events: none;
    white-space: nowrap;
    box-shadow: 0 6px 20px rgba(0, 0, 0, 0.32);
    z-index: 2;
  }
  .tip.tl { transform: translateX(0); }
  .tip.tr { transform: translateX(-100%); }
  .tip-t { color: var(--muted); margin-bottom: 3px; }
  .tip-row { display: flex; align-items: center; gap: 6px; }
  .tip-row b { margin-left: auto; padding-left: 12px; font-variant-numeric: tabular-nums; }
  .tip-sub { color: var(--muted); margin-top: 2px; }

  .axis { position: relative; height: 18px; font-size: 0.7rem; color: var(--muted); }
  .axis span { position: absolute; transform: translateX(-50%); }

  .legend { display: inline-flex; align-items: center; gap: 6px; }
  .dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }
  .dot.accent { background: var(--accent); }
  .dot.danger { background: var(--danger); }

  button.sel { border-color: var(--accent); color: var(--accent); }

  .tops {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 12px;
    margin-top: 14px;
  }
</style>

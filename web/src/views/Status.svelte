<script>
  import { api, formatApiError, formatUptime } from '../api.js';

  let status = $state(null);
  let metrics = $state(null);
  let stats = $state(null);
  let window_ = $state('1h');
  let error = $state(null);

  let inFlight = $state(false);

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
    } catch (e) {
      error = formatApiError(e);
    } finally {
      inFlight = false;
    }
  }

  // Refresh on mount, on window change, and every 10 s afterwards.
  $effect(() => {
    refresh();
    const id = setInterval(refresh, 10_000);
    return () => clearInterval(id);
  });

  const cards = $derived([
    { label: 'Total Queries', value: metrics?.total_queries ?? 0 },
    { label: 'Authoritative', value: metrics?.authoritative ?? 0 },
    { label: 'Recursive', value: metrics?.recursive ?? 0 },
    { label: 'Cache Hits', value: metrics?.cache_hits ?? 0 },
    { label: 'Cache Misses', value: metrics?.cache_misses ?? 0 },
    { label: 'Blocked', value: metrics?.blocked ?? 0 },
    { label: 'DNSSEC Validated', value: metrics?.dnssec_validated ?? 0 },
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
        label: new Date(t * 1000).toLocaleTimeString([], {
          hour: '2-digit',
          minute: '2-digit',
        }),
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
    return new Date(t * 1000).toLocaleTimeString();
  }
</script>

<h1>Server Status</h1>

{#if error}
  <div class="card" style="border-color: var(--danger); color: var(--danger)">
    Failed to load status: {error}
  </div>
{:else if !status}
  <p class="muted">Loading…</p>
{:else}
  <div class="grid">
    {#each cards as card (card.label)}
      <div class="card stat">
        <div class="muted">{card.label}</div>
        <div class="big">{card.value.toLocaleString()}</div>
      </div>
    {/each}
  </div>

  <div class="card" style="margin-top: 18px">
    <div class="spread" style="margin-bottom: 10px">
      <h3 style="margin: 0">Query Volume</h3>
      <div class="row">
        {#each ['1h', '6h', '24h'] as w (w)}
          <button
            class="secondary"
            class:sel={window_ === w}
            style="padding: 4px 10px"
            onclick={() => (window_ = w)}
          >{w}</button>
        {/each}
      </div>
    </div>

    <div class="row" style="margin-bottom: 8px; font-size: 0.85rem">
      <span class="legend"><span class="dot accent"></span> {fmt(totals.queries)} queries</span>
      <span class="legend"><span class="dot danger"></span> {fmt(totals.blocked)} blocked</span>
      <span class="legend muted">{fmt(totals.errors)} errors · {fmt(totals.rate_limited)} rate-limited</span>
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
      <h3 style="margin-top: 0">Top Clients</h3>
      {#if stats?.top_clients?.length}
        <table>
          <tbody>
            {#each stats.top_clients as row, i (row.key)}
              <tr><td class="muted">#{i + 1}</td><td><code>{row.key}</code></td><td class="num">{fmt(row.count)}</td></tr>
            {/each}
          </tbody>
        </table>
      {:else}
        <p class="muted">No clients yet.</p>
      {/if}
    </div>
    <div class="card">
      <h3 style="margin-top: 0">Top Domains</h3>
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
      <h3 style="margin-top: 0">Top Blocked</h3>
      {#if stats?.top_blocked?.length}
        <table>
          <tbody>
            {#each stats.top_blocked as row, i (row.key)}
              <tr><td class="muted">#{i + 1}</td><td><code>{row.key}</code></td><td class="num">{fmt(row.count)}</td></tr>
            {/each}
          </tbody>
        </table>
      {:else}
        <p class="muted">Nothing blocked yet.</p>
      {/if}
    </div>
  </div>

  <div class="card" style="margin-top: 18px">
    <h3 style="margin-top: 0">Runtime</h3>
    <table>
      <tbody>
        <tr><td>Version</td><td><code>{status.version}</code></td></tr>
        <tr><td>Uptime</td><td>{formatUptime(status.uptime_secs)}</td></tr>
        <tr><td>Zones</td><td>{status.zones}</td></tr>
        <tr><td>Records</td><td>{status.records}</td></tr>
        <tr>
          <td>Recursion</td>
          <td><span class:pill={true} class:ok={status.recursion} class:err={!status.recursion}>
            {status.recursion ? 'Enabled' : 'Disabled'}
          </span></td>
        </tr>
        <tr>
          <td>DNSSEC validation</td>
          <td><span class:pill={true} class:ok={status.dnssec} class:err={!status.dnssec}>
            {status.dnssec ? 'Enabled' : 'Disabled'}
          </span></td>
        </tr>
        <tr>
          <td>DoT</td>
          <td><span class:pill={true} class:ok={status.dot_enabled} class:err={!status.dot_enabled}>
            {status.dot_enabled ? 'Enabled' : 'Disabled'}
          </span></td>
        </tr>
        <tr>
          <td>DoQ</td>
          <td><span class:pill={true} class:ok={status.doq_enabled} class:err={!status.doq_enabled}>
            {status.doq_enabled ? 'Enabled' : 'Disabled'}
          </span></td>
        </tr>
      </tbody>
    </table>
  </div>
{/if}

<style>
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
    gap: 12px;
  }
  .stat .big { font-size: 1.6rem; font-weight: 700; margin-top: 6px; }

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
    margin-top: 18px;
  }
  .num { text-align: right; font-variant-numeric: tabular-nums; }
</style>

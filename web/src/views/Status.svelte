<script>
  import { api } from '../api.js';

  let status = $state(null);
  let metrics = $state(null);
  let stats = $state(null);
  let window_ = $state('1h');
  let error = $state(null);

  async function refresh() {
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
      error = String(e.message || e);
    }
  }

  // Refresh on mount, on window change, and every 10 s afterwards.
  $effect(() => {
    refresh();
    const id = setInterval(refresh, 10_000);
    return () => clearInterval(id);
  });

  const cards = $derived([
    { label: 'Total queries', value: metrics?.total_queries ?? 0 },
    { label: 'Authoritative', value: metrics?.authoritative ?? 0 },
    { label: 'Recursive', value: metrics?.recursive ?? 0 },
    { label: 'Cache hits', value: metrics?.cache_hits ?? 0 },
    { label: 'Cache misses', value: metrics?.cache_misses ?? 0 },
    { label: 'Blocked', value: metrics?.blocked ?? 0 },
    { label: 'DNSSEC validated', value: metrics?.dnssec_validated ?? 0 },
    { label: 'Errors', value: metrics?.errors ?? 0 },
  ]);

  // ---- chart geometry ------------------------------------------------------
  const W = 720;
  const H = 190;
  const PAD = 8;

  const series = $derived(stats?.series ?? []);
  const totals = $derived({
    queries: series.reduce((a, p) => a + p.queries, 0),
    blocked: series.reduce((a, p) => a + p.blocked, 0),
    errors: series.reduce((a, p) => a + p.errors, 0),
    rate_limited: series.reduce((a, p) => a + p.rate_limited, 0),
  });

  const chart = $derived.by(() => {
    if (!series.length) return null;
    const maxQ = Math.max(4, ...series.map((p) => p.queries));
    const maxB = Math.max(4, ...series.map((p) => p.blocked));
    const maxY = Math.max(maxQ, maxB * 2);
    const step = (W - 2 * PAD) / Math.max(1, series.length - 1);
    const y = (v) => H - PAD - (v / maxY) * (H - 2 * PAD);
    const x = (i) => PAD + i * step;
    const pts = (key) =>
      series.map((p, i) => `${x(i).toFixed(1)},${y(p[key]).toFixed(1)}`).join(' ');
    const area = (key) =>
      `${PAD},${H - PAD} ${pts(key)} ${(W - PAD).toFixed(1)},${H - PAD}`;
    // Label every sixth point with the wall-clock time.
    const every = Math.max(1, Math.round(series.length / 6));
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
    return { queriesPts: pts('queries'), blockedPts: pts('blocked'), queriesArea: area('queries'), labels, grid };
  });

  function fmt(n) {
    return n.toLocaleString();
  }
</script>

<h1>Server status</h1>

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
      <h3 style="margin: 0">Queries over time</h3>
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
      <svg viewBox="0 0 {W} {H}" preserveAspectRatio="none" class="chart" role="img" aria-label="Queries per minute">
        {#each chart.grid as g (g.y)}
          <line x1={PAD} x2={W - PAD} y1={g.y} y2={g.y} class="gridline"></line>
        {/each}
        <polygon points={chart.queriesArea} class="fill"></polygon>
        <polyline points={chart.queriesPts} class="line queries"></polyline>
        <polyline points={chart.blockedPts} class="line blocked"></polyline>
      </svg>
      <div class="axis">
        {#each chart.labels as l (l.x)}
          <span style="left: {(l.x / W) * 100}%">{l.label}</span>
        {/each}
      </div>
    {:else}
      <p class="muted">No traffic yet — the chart fills in as queries arrive.</p>
    {/if}
  </div>

  <div class="tops">
    <div class="card">
      <h3 style="margin-top: 0">Top clients</h3>
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
      <h3 style="margin-top: 0">Top domains</h3>
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
      <h3 style="margin-top: 0">Top blocked</h3>
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
        <tr><td>Uptime</td><td>{status.uptime_secs}s</td></tr>
        <tr><td>Zones</td><td>{status.zones}</td></tr>
        <tr><td>Records</td><td>{status.records}</td></tr>
        <tr>
          <td>Recursion</td>
          <td><span class:pill={true} class:ok={status.recursion} class:err={!status.recursion}>
            {status.recursion ? 'enabled' : 'disabled'}
          </span></td>
        </tr>
        <tr>
          <td>DNSSEC validation</td>
          <td><span class:pill={true} class:ok={status.dnssec} class:err={!status.dnssec}>
            {status.dnssec ? 'enabled' : 'disabled'}
          </span></td>
        </tr>
        <tr>
          <td>DoT</td>
          <td><span class:pill={true} class:ok={status.dot_enabled} class:err={!status.dot_enabled}>
            {status.dot_enabled ? 'enabled' : 'disabled'}
          </span></td>
        </tr>
        <tr>
          <td>DoQ</td>
          <td><span class:pill={true} class:ok={status.doq_enabled} class:err={!status.doq_enabled}>
            {status.doq_enabled ? 'enabled' : 'disabled'}
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

  .chart { width: 100%; height: 190px; display: block; }
  .gridline { stroke: var(--border); stroke-width: 1; }
  .fill { fill: var(--accent); opacity: 0.12; }
  .line { fill: none; stroke-width: 2; }
  .line.queries { stroke: var(--accent); }
  .line.blocked { stroke: var(--danger); }

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

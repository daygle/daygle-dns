<script>
  import { api } from '../api.js';

  // Resolver dashboard (GET /api/resolver): how lookups were routed and how
  // they ended, latency, DNSSEC and the recursor's transports. Counters run
  // since the server started.
  let { refreshKey = 0 } = $props();
  let data = $state(null);
  let hover = $state(null); // latency bucket under the cursor

  async function load() {
    try {
      data = await api.resolver();
    } catch {
      data = null;
    }
  }

  $effect(() => {
    refreshKey;
    load();
  });

  const fmt = (n) => (n ?? 0).toLocaleString();
  const pct = (part, whole) => (whole > 0 ? `${((part / whole) * 100).toFixed(part === whole || part === 0 ? 0 : 1)}%` : '-');
  const ms = (v) => (v == null ? '-' : v >= 1000 ? `< ${v / 1000} s` : `< ${v} ms`);

  const stats = $derived(data?.stats);
  const routes = $derived(
    stats
      ? [
          ['Recursive (Root Servers)', stats.routes.recursive],
          ['Forwarded (Upstreams)', stats.routes.forwarding],
          ['Conditional Forwarders', stats.routes.conditional],
          ['Stub Zones', stats.routes.stub],
          ['Client Policies', stats.routes.client_policy],
          ['Local Root NXDOMAIN', stats.routes.local_root],
        ].filter(([, n]) => n > 0)
      : [],
  );
  const lookups = $derived(routes.reduce((sum, [, n]) => sum + n, 0));
  const outcomes = $derived(
    stats
      ? [
          ['Answer', stats.outcomes.noerror],
          ['NODATA', stats.outcomes.nodata],
          ['NXDOMAIN', stats.outcomes.nxdomain],
          ['SERVFAIL', stats.outcomes.servfail],
          ['REFUSED', stats.outcomes.refused],
          ['Other Error', stats.outcomes.other],
          ['No Answer (Timeout)', stats.outcomes.failures],
        ].filter(([, n]) => n > 0)
      : [],
  );
  const outcomeTotal = $derived(outcomes.reduce((sum, [, n]) => sum + n, 0));
  const conns = $derived(stats?.connections);
  const connTotal = $derived(conns ? conns.udp + conns.tcp + conns.tls + conns.quic : 0);
  const encrypted = $derived(conns ? conns.tls + conns.quic : 0);

  // Latency histogram: one column per bucket ("< 1 ms" ... "2.5 s+").
  const buckets = $derived(
    stats
      ? stats.latency.counts.map((count, i) => {
          const hi = stats.latency.bounds_ms[i];
          const lo = i === 0 ? 0 : stats.latency.bounds_ms[i - 1];
          // Columns are labelled by their upper bound; the last has none.
          const label = hi == null ? 'more' : hi >= 1000 ? `${hi / 1000} s` : `${hi}`;
          const range = hi == null ? `${lo} ms or more` : `${lo}–${hi} ms`;
          return { count, label, range };
        })
      : [],
  );
  const latencyTotal = $derived(buckets.reduce((sum, b) => sum + b.count, 0));
  const latencyMax = $derived(Math.max(1, ...buckets.map((b) => b.count)));

  const modeLabel = $derived(
    !data?.enabled ? 'Disabled' : data.mode === 'recursive' ? 'Recursive' : 'Forwarding',
  );
</script>

{#if data}
  <div class="card" style="margin-top: 14px">
    <div class="spread" style="margin-bottom: 12px; flex-wrap: wrap; gap: 8px">
      <h3 style="margin: 0">Resolver</h3>
      <div class="row" style="gap: 6px; flex-wrap: wrap">
        <span class="pill">{modeLabel}</span>
        <span class="pill" class:ok={data.dnssec_validation}>{data.dnssec_validation ? 'DNSSEC Validating' : 'DNSSEC Off'}</span>
        {#if data.mode === 'recursive' || data.client_policies}
          <span class="pill" class:ok={data.opportunistic_encryption}>{data.opportunistic_encryption ? 'Opportunistic Encryption' : 'Encryption Off'}</span>
        {/if}
        {#if data.local_root.enabled}
          <span class="pill" class:ok={data.local_root.serving}>{data.local_root.serving ? `Local Root Serial ${data.local_root.serial}` : 'Local Root Not in Use'}</span>
        {/if}
        {#if data.client_policies}<span class="pill">{data.client_policies} Client {data.client_policies === 1 ? 'Policy' : 'Policies'}</span>{/if}
      </div>
    </div>

    <div class="tiles">
      <div class="tile"><div class="muted">Lookups</div><div class="big">{fmt(lookups)}</div></div>
      <div class="tile"><div class="muted">Median Latency</div><div class="big">{ms(stats.latency.p50_ms)}</div></div>
      <div class="tile"><div class="muted">90th Percentile</div><div class="big">{ms(stats.latency.p90_ms)}</div></div>
      <div class="tile"><div class="muted">99th Percentile</div><div class="big">{ms(stats.latency.p99_ms)}</div></div>
      <div class="tile"><div class="muted">DNSSEC Validated</div><div class="big">{pct(data.dnssec_validated, data.queries)}</div></div>
      {#if connTotal > 0}
        <div class="tile" title="{fmt(encrypted)} of {fmt(connTotal)} outbound connections used TLS or QUIC">
          <div class="muted">Encrypted Connections</div><div class="big">{pct(encrypted, connTotal)}</div>
        </div>
      {/if}
      {#if stats.outcomes.stale_served}
        <div class="tile"><div class="muted">Stale Answers Served</div><div class="big">{fmt(stats.outcomes.stale_served)}</div></div>
      {/if}
    </div>

    {#if lookups === 0}
      <p class="muted" style="margin: 12px 0 0">No lookups yet - this fills in as the resolver answers queries.</p>
    {:else}
      <div class="panels">
        <div>
          <h4>Routes</h4>
          {#each routes as [label, n] (label)}
            <div class="barrow" title="{label}: {fmt(n)} lookups ({pct(n, lookups)})">
              <span class="label">{label}</span>
              <span class="track"><span class="bar" style="width: {(n / lookups) * 100}%"></span></span>
              <span class="value">{fmt(n)}</span>
            </div>
          {/each}
        </div>
        <div>
          <h4>Outcomes</h4>
          {#each outcomes as [label, n] (label)}
            <div class="barrow" title="{label}: {fmt(n)} ({pct(n, outcomeTotal)})">
              <span class="label">{label}</span>
              <span class="track"><span class="bar" style="width: {(n / outcomeTotal) * 100}%"></span></span>
              <span class="value">{pct(n, outcomeTotal)}</span>
            </div>
          {/each}
          {#if stats.outcomes.failures_replayed}
            <p class="muted small" style="margin: 6px 0 0">Plus {fmt(stats.outcomes.failures_replayed)} failures answered from the failure cache.</p>
          {/if}
        </div>
        <div>
          <h4>Latency (ms)</h4>
          <div class="hist" role="img" aria-label="Lookup latency histogram" onpointerleave={() => (hover = null)}>
            {#each buckets as b, i (i)}
              <div
                class="col"
                role="presentation"
                onpointerenter={() => (hover = { ...b, i })}
              >
                <span class="colbar" class:hot={hover?.i === i} style="height: {b.count ? Math.max(2, (b.count / latencyMax) * 100) : 0}%"></span>
              </div>
            {/each}
            {#if hover}
              <div class="tip" style="left: {((hover.i + 0.5) / buckets.length) * 100}%">
                <div class="muted">{hover.range}</div>
                <b>{fmt(hover.count)}</b> lookups · {pct(hover.count, latencyTotal)}
              </div>
            {/if}
          </div>
          <div class="hist-axis">
            {#each buckets as b, i (i)}<span>{b.label}</span>{/each}
          </div>
          <p class="muted small" style="margin: 6px 0 0">Lookups answered from cache land in the first column.</p>
        </div>
      </div>
    {/if}
  </div>
{/if}

<style>
  .tiles {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
    gap: 10px;
  }
  .tile { background: var(--panel-2); border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; }
  .tile .big { font-size: 1.3rem; font-weight: 700; margin-top: 4px; font-variant-numeric: tabular-nums; }
  .small { font-size: 0.78rem; font-weight: 400; }
  .panels {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 18px;
    margin-top: 14px;
  }
  h4 { margin: 0 0 8px; font-size: 0.8rem; color: var(--muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
  .barrow {
    display: grid;
    grid-template-columns: minmax(0, 11rem) 1fr 3.6rem;
    align-items: center;
    gap: 8px;
    font-size: 0.85rem;
    padding: 3px 0;
  }
  .label { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .track { height: 8px; background: var(--panel-2); border-radius: 4px; overflow: hidden; }
  .bar { display: block; height: 100%; min-width: 2px; background: var(--accent); border-radius: 4px; }
  .value { text-align: right; font-variant-numeric: tabular-nums; color: var(--muted); }
  .hist {
    position: relative;
    display: flex;
    align-items: flex-end;
    gap: 2px;
    height: 110px;
    border-bottom: 1px solid var(--border);
  }
  .col { flex: 1; height: 100%; display: flex; align-items: flex-end; cursor: default; }
  .colbar { display: block; width: 100%; background: var(--accent); border-radius: 4px 4px 0 0; }
  .colbar.hot { background: color-mix(in srgb, var(--accent) 75%, white); }
  .hist-axis { display: flex; gap: 2px; margin-top: 4px; }
  .hist-axis span { flex: 1; text-align: center; font-size: 0.62rem; color: var(--muted); white-space: nowrap; }
  .tip {
    position: absolute;
    top: 0;
    transform: translateX(-50%);
    background: var(--panel-2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 5px 8px;
    font-size: 0.72rem;
    white-space: nowrap;
    pointer-events: none;
    box-shadow: 0 6px 20px rgba(0, 0, 0, 0.32);
  }
</style>

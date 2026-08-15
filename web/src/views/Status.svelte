<script>
  import { api } from '../api.js';

  let status = $state(null);
  let metrics = $state(null);
  let error = $state(null);

  async function refresh() {
    error = null;
    try {
      const [s, m] = await Promise.all([api.status(), api.metrics()]);
      status = s;
      metrics = m;
    } catch (e) {
      error = String(e.message || e);
    }
  }

  $effect(() => { refresh(); });

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
</style>

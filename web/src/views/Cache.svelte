<script>
  import { api, formatApiError } from '../api.js';
  import PageHeader from '../PageHeader.svelte';
  import { icons } from '../icons.svelte.js';

  // The cache is configured in Settings -> Cache; this page
  // shows how it is doing and flushes it (whole or one name).
  let { onOpenSettings = null } = $props();

  let cache = $state(null);
  let busy = $state(false);
  let error = $state(null);
  let notice = $state(null);
  let inFlight = $state(false);
  let flushName = $state('');
  let flushType = $state('');

  // Record types offered for a single-name flush ('' = all common types).
  const TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'PTR', 'SRV', 'CAA', 'HTTPS', 'SVCB', 'DS', 'DNSKEY', 'TLSA', 'NAPTR'];

  async function load() {
    if (inFlight) return;
    inFlight = true;
    error = null;
    try {
      cache = await api.cache();
    } catch (e) {
      error = formatApiError(e);
    } finally {
      inFlight = false;
    }
  }

  async function flush() {
    if (!confirm('Flush the whole cache? Every name is fetched again on its next query.')) return;
    busy = true;
    error = null;
    notice = null;
    try {
      await api.clearCache();
      notice = 'Cache flushed.';
      await load();
    } catch (e) {
      error = formatApiError(e);
    } finally {
      busy = false;
    }
  }

  async function flushOne() {
    const name = flushName.trim();
    if (!name) return;
    busy = true;
    error = null;
    notice = null;
    try {
      const result = await api.flushCacheName(name, flushType);
      const what = flushType ? `${name} (${flushType})` : name;
      notice = result.complete
        ? `Flushed ${what} from the cache.`
        : `Flushed ${what} from the forwarding caches. Recursive mode keeps its own copy until it expires; use Flush Cache to drop it now.`;
      flushName = '';
      await load();
    } catch (e) {
      error = formatApiError(e);
    } finally {
      busy = false;
    }
  }

  $effect(() => {
    load();
    const id = setInterval(load, 10000);
    return () => clearInterval(id);
  });

  const total = $derived((cache?.hits || 0) + (cache?.misses || 0));
  const hitRate = $derived(total ? ((cache.hits / total) * 100).toFixed(1) : '0.0');

  function duration(secs) {
    if (!secs) return 'Off';
    if (secs % 86400 === 0) return `${secs / 86400} d`;
    if (secs % 3600 === 0) return `${secs / 3600} h`;
    if (secs % 60 === 0) return `${secs / 60} min`;
    return `${secs} s`;
  }
</script>

<PageHeader
  icon={icons.cache}
  title="Cache"
  tagline="The resolver caches positive and negative DNS answers to reduce upstream traffic and improve response times. Cache entries are kept in memory and are cleared when the service restarts."
/>

{#if notice}
  <div class="card" style="border-color: var(--ok); margin-bottom: 14px">{notice}</div>
{/if}
{#if error}
  <div class="card" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">{error}</div>
{/if}

{#if cache}
  <div class="grid">
    <div class="card stat"><div class="muted">Cache Hits</div><div class="big">{cache.hits.toLocaleString()}</div></div>
    <div class="card stat"><div class="muted">Cache Misses</div><div class="big">{cache.misses.toLocaleString()}</div></div>
    <div class="card stat"><div class="muted">Hit Rate</div><div class="big">{hitRate}%</div></div>
    <div class="card stat"><div class="muted">Tracked Names</div><div class="big">{cache.tracked_names.toLocaleString()}</div></div>
  </div>

  <div class="card" style="margin-top: 14px">
    <div class="spread" style="margin-bottom: 10px">
      <h3 style="margin: 0">Cache Controls</h3>
      <button class="danger" onclick={flush} disabled={busy || !cache.enabled}>Flush Cache</button>
    </div>
    {#if !cache.enabled}
      <p class="muted">Recursive resolution is disabled, so there is no active cache.</p>
    {:else}
      <div class="summary">
        <span><span class="muted">Capacity</span> {cache.capacity.toLocaleString()} Entries</span>
        <span><span class="muted">Serve-Stale Window</span> {duration(cache.serve_stale_secs)}</span>
        <span><span class="muted">Refresh Popular Names Early</span> {cache.prefetch_enabled ? 'On' : 'Off'}</span>
        {#if onOpenSettings}
          <button class="secondary" onclick={() => onOpenSettings('cache')}>Settings</button>
        {/if}
      </div>
      <p class="muted help">
        Cache size, TTL limits, serve-stale and prefetch are configured in
        Settings → Cache.
      </p>
    {/if}
  </div>

  {#if cache.enabled}
    <div class="card" style="margin-top: 14px">
      <h3 style="margin: 0 0 10px">Flush a Name</h3>
      <form class="flush" onsubmit={(e) => { e.preventDefault(); flushOne(); }}>
        <label class="name"><span>Domain Name</span><input placeholder="www.example.com" bind:value={flushName} /></label>
        <label><span>Record Type</span>
          <select bind:value={flushType}>
            <option value="">All Types</option>
            {#each TYPES as type (type)}<option value={type}>{type}</option>{/each}
          </select>
        </label>
        <button type="submit" disabled={busy || !flushName.trim()}>Flush</button>
      </form>
      <p class="muted help">
        Drops the cached answers for one name so its next query is fetched
        fresh, for example after changing a record at your DNS provider.
        {#if cache.mode === 'recursive'}
          In recursive mode the resolver's own cache cannot drop a single
          name: this clears conditional forwarders, stub zones, forwarding
          policies and serve-stale copies, and the recursive copy expires on
          its own (or use Flush Cache).
        {/if}
      </p>
    </div>
  {/if}
{:else}
  <div class="card">
    <p class="muted">Loading...</p>
  </div>
{/if}

<style>
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }
  .stat .big { font-size: 1.6rem; font-weight: 700; margin-top: 6px; }
  .summary { display: flex; flex-wrap: wrap; align-items: center; gap: 8px 22px; }
  .summary .muted { margin-right: 6px; }
  .summary button { margin-left: auto; }
  .flush { display: grid; grid-template-columns: minmax(0, 1fr) 160px auto; gap: 12px; align-items: end; }
  @media (max-width: 640px) {
    .flush { grid-template-columns: 1fr; }
  }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; }
  label span { color: var(--muted); }
</style>

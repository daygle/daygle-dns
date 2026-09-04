<script>
  import { api } from '../api.js';

  let cache = $state(null);
  let config = $state(null);
  let busy = $state(false);
  let error = $state(null);
  let notice = $state(null);
  let cacheSize = $state(8192);
  let prefetchEnabled = $state(false);
  let serveStale = $state(0);
  let inFlight = $state(false);

  async function load() {
    if (inFlight) return;
    inFlight = true;
    error = null;
    try {
      const [status, cfg] = await Promise.all([api.cache(), api.config()]);
      cache = status;
      config = cfg;
      if (configOk(cfg)) {
        cacheSize = cfg.recursive.cache_size;
        prefetchEnabled = !!cfg.recursive.prefetch_enabled;
        serveStale = cfg.recursive.serve_stale_secs;
      }
    } catch (e) {
      error = formatApiError(e);
    } finally {
      inFlight = false;
    }
  }

  async function flush() {
    busy = true;
    error = null;
    notice = null;
    try {
      await api.clearCache();
      notice = 'Recursive cache flushed.';
      await load();
    } catch (e) {
      error = formatApiError(e);
    } finally {
      busy = false;
    }
  }

  async function save() {
    busy = true;
    error = null;
    notice = null;
    try {
      await api.updateSettings({
        recursive: {
          cache_size: Number(cacheSize),
          prefetch_enabled: !!prefetchEnabled,
          serve_stale_secs: Number(serveStale),
        },
      });
      notice = 'Cache settings saved and applied live.';
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
</script>

<h1>Cache</h1>
<p class="muted" style="max-width: 75ch">
  The recursive resolver caches positive and negative DNS answers to reduce
  upstream traffic and improve response times. Cache entries are kept in memory
  and are cleared when the service restarts.
</p>

{#if notice}
  <div class="card" style="border-color: var(--ok); margin-bottom: 14px">{notice}</div>
{/if}
{#if error}
  <div class="card" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">{error}</div>
{/if}

{#if cache}
  <div class="grid">
    <div class="card stat"><div class="muted">Cache hits</div><div class="big">{cache.hits.toLocaleString()}</div></div>
    <div class="card stat"><div class="muted">Cache misses</div><div class="big">{cache.misses.toLocaleString()}</div></div>
    <div class="card stat"><div class="muted">Hit rate</div><div class="big">{hitRate}%</div></div>
    <div class="card stat"><div class="muted">Tracked names</div><div class="big">{cache.tracked_names.toLocaleString()}</div></div>
  </div>

  <div class="card" style="margin-top: 18px; margin-bottom: 14px">
    <div class="spread">
      <h3 style="margin-top: 0">Cache controls</h3>
      <button class="danger" onclick={flush} disabled={busy || !cache.enabled}>Flush cache</button>
    </div>
    {#if !cache.enabled}
      <p class="muted">Recursive resolution is disabled, so there is no active cache.</p>
    {:else}
      <div class="form-grid">
        <label>
          <span>Cache capacity (entries)</span>
          <input type="number" min="1" bind:value={cacheSize} />
        </label>
        <label>
          <span>Serve stale for (seconds)</span>
          <input type="number" min="0" bind:value={serveStale} />
        </label>
        <label class="check">
          <input type="checkbox" bind:checked={prefetchEnabled} />
          <span>Prefetch popular names</span>
        </label>
      </div>
      <p class="muted small">Changing capacity rebuilds the resolver and may briefly interrupt recursive lookups.</p>
      <button onclick={save} disabled={busy}>{busy ? 'Saving…' : 'Save cache settings'}</button>
    {/if}
  </div>
{:else}
  <p class="muted">Loading…</p>
{/if}

<style>
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }
  .stat .big { font-size: 1.6rem; font-weight: 700; margin-top: 6px; }
  .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; align-items: end; margin-bottom: 14px; }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; }
  label span { color: var(--muted); }
  label.check { flex-direction: row; align-items: center; gap: 8px; padding-bottom: 8px; }
  label.check span { color: var(--text); }
  .small { font-size: 0.8rem; }
</style>

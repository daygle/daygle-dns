<script>
  import { api, formatApiError } from '../api.js';
  import SettingsForm from './SettingsForm.svelte';

  // Cache -> Settings: how long answers are kept, how many, and refreshing
  // and serve-stale. Saved on its own as a partial `recursive` update, so
  // the resolver settings (Settings -> Resolver) are never touched here.
  // `onSaved` lets the page refresh its overview.
  let { onSaved = () => {} } = $props();

  const KEYS = ['min_cache_ttl', 'negative_cache_ttl', 'max_cache_ttl', 'failure_cache_ttl', 'cache_size',
    'prefetch_enabled', 'prefetch_ttl_fraction_pct', 'prefetch_min_queries', 'prefetch_window_secs',
    'serve_stale_secs'];

  let recursive = $state(null);
  let savedBody = $state('');
  let busy = $state(false);
  let notice = $state(null);
  let error = $state(null);
  const dirty = $derived(recursive != null && savedBody !== '' && JSON.stringify(buildBody()) !== savedBody);

  function buildBody() {
    return Object.fromEntries(
      KEYS.map((k) => [k, k === 'prefetch_enabled' ? !!recursive[k] : Number(recursive[k])]),
    );
  }

  async function load() {
    error = null;
    try {
      const config = await api.config();
      recursive = Object.fromEntries(KEYS.map((k) => [k, config.recursive?.[k]]));
      savedBody = JSON.stringify(buildBody());
    } catch (e) {
      error = formatApiError(e);
    }
  }

  function reload() {
    if (dirty && !confirm('Discard your unsaved changes?')) return;
    notice = null;
    load();
  }

  async function save() {
    busy = true;
    notice = null;
    error = null;
    try {
      await api.updateSettings({ recursive: buildBody() });
      notice = 'Cache settings saved and applied.';
      await load();
      onSaved();
    } catch (e) {
      error = formatApiError(e);
    } finally {
      busy = false;
    }
  }

  async function reset() {
    if (!confirm('Reset the cache settings to their defaults? Nothing is saved until you click Save Changes.')) return;
    notice = null;
    error = null;
    try {
      const d = await api.configDefaults();
      recursive = Object.fromEntries(KEYS.map((k) => [k, d.recursive[k]]));
      notice = 'Cache settings reset to their defaults. Click Save Changes to apply them.';
    } catch (e) {
      error = formatApiError(e);
    }
  }

  $effect(() => {
    load();
  });
</script>

<SettingsForm loaded={recursive != null} {dirty} {busy} {notice} {error} onSave={save} onReload={reload} onReset={reset}>
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">Cache Lifetimes</h3>
    <div class="recursive-cache-grid">
      <label><span>Minimum Cache TTL (Seconds)</span><input type="number" min="0" bind:value={recursive.min_cache_ttl} /></label>
      <label><span>Negative Cache TTL (Seconds)</span><input type="number" min="0" bind:value={recursive.negative_cache_ttl} /></label>
      <label><span>Maximum Cache TTL (Seconds)</span><input type="number" min="0" bind:value={recursive.max_cache_ttl} /></label>
      <label><span>Failure Cache TTL (Seconds)</span><input type="number" min="0" bind:value={recursive.failure_cache_ttl} /></label>
      <label><span>Cache Size (Entries)</span><input type="number" min="0" bind:value={recursive.cache_size} /></label>
    </div>
    <p class="muted help">
      Minimum and negative TTLs bound how long records stay in cache. Maximum TTL
      clamps positive answers at insert time so tracking-heavy domains cannot pin
      themselves in cache for weeks. Failure Cache TTL caches SERVFAIL and other
      upstream errors briefly so a broken upstream is not hammered on every query;
      set it to 0 to disable.
    </p>
  </div>
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">Refreshing and Stale Answers</h3>
    <div class="recursive-cache-grid">
      <label class="check"><input type="checkbox" bind:checked={recursive.prefetch_enabled} /> <span>Refresh Popular Names Early</span></label>
      <label><span>Refresh When TTL Left Is Below (%)</span><input type="number" min="1" max="99" bind:value={recursive.prefetch_ttl_fraction_pct} disabled={!recursive.prefetch_enabled} /></label>
      <label><span>Refresh Names Queried At Least (Times)</span><input type="number" min="1" bind:value={recursive.prefetch_min_queries} disabled={!recursive.prefetch_enabled} /></label>
      <label><span>Counted Over (Seconds)</span><input type="number" min="1" bind:value={recursive.prefetch_window_secs} disabled={!recursive.prefetch_enabled} /></label>
      <label><span>Serve-Stale Window (Seconds)</span><input type="number" min="0" bind:value={recursive.serve_stale_secs} /></label>
    </div>
    <p class="muted help">
      Refreshing popular names early re-fetches a name before it expires once
      it has been asked for often enough within the counting window, so
      clients rarely wait. Serve-stale
      answers from an expired entry for this long when the upstream cannot be
      reached, or when a lookup outlasts the Client Timeout (Settings → Resolver).
      The Overview tab shows hit rates and can flush the cache.
    </p>
  </div>
</SettingsForm>

<script>
  import { api, formatApiError } from '../api.js';
  import PageHeader from '../PageHeader.svelte';
  import { icons } from '../icons.svelte.js';

  let status = $state(null);
  let loading = $state(true);
  let error = $state(null);
  let notice = $state(null);

  // Override editor (allow exempt / clear existing override).
  let overrideDomain = $state('');
  let overrideReason = $state('');
  let overrideBusy = $state(false);

  async function load() {
    loading = true;
    error = null;
    try {
      status = await api.aiStatus();
    } catch (e) {
      status = null;
      // 404 means the [ai] section is disabled: an empty state, not a failure.
      error = e.status === 404 ? null : formatApiError(e);
    } finally {
      loading = false;
    }
  }

  async function rescan() {
    notice = null;
    error = null;
    try {
      await api.aiRescan();
      notice = 'Rescan requested - the scanner starts a cycle now.';
      setTimeout(() => {
        notice = null;
        load();
      }, 1500);
    } catch (e) {
      error = formatApiError(e);
    }
  }

  async function saveOverride(action) {
    const domain = overrideDomain.trim().replace(/\.+$/, '');
    if (!domain) {
      error = 'Enter a domain for the override.';
      return;
    }
    overrideBusy = true;
    notice = null;
    error = null;
    try {
      await api.aiOverride(domain, action, overrideReason.trim());
      notice =
        action === 'allow'
          ? `${domain} is now AI-exempt.`
          : `Override cleared for ${domain}.`;
      overrideDomain = '';
      overrideReason = '';
      await load();
    } catch (e) {
      error = formatApiError(e);
    } finally {
      overrideBusy = false;
    }
  }

  // status_counts keys are scanner row statuses; rename for display and keep
  // a stable order. Unknown keys (a future format) still surface.
  function countFor(key) {
    return status?.status_counts?.[key] ?? 0;
  }

  function fmt(n) {
    return Number(n || 0).toLocaleString();
  }

  $effect(() => {
    load();
  });
</script>

<PageHeader
  icon={icons.ai}
  title="AI Safety Scanner"
  tagline="The background scanner classifies domains from live query traffic into categories (using the heuristic rules or a fastText model) and threat verdicts can auto-block. Overrides here take precedence over verdicts."
/>

{#if notice}
  <div class="card" style="border-color: var(--ok); margin-bottom: 14px">{notice}</div>
{/if}
{#if error}
  <div class="card" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">{error}</div>
{/if}

{#if loading}
  <div class="card">
    <p class="muted">Loading…</p>
  </div>
{:else if !status}
  <div class="card">
    <h3 style="margin-top: 0">AI Subsystem Disabled</h3>
    <p class="muted" style="max-width: 70ch">
      The <code>[ai]</code> section of the configuration is not enabled, so no
      domains are being classified. Enable it to activate the scanner.
    </p>
  </div>
{:else}
  <div class="grid">
    <div class="card stat">
      <div class="muted">Snapshot Domains</div>
      <div class="big">{fmt(status.snapshot_len)}</div>
    </div>
    <div class="card stat">
      <div class="muted">Pending Classification</div>
      <div class="big">{fmt(countFor('pending'))}</div>
    </div>
    <div class="card stat">
      <div class="muted">Classified</div>
      <div class="big">{fmt(countFor('classified'))}</div>
    </div>
    <div class="card stat">
      <div class="muted">Skipped (No Signal)</div>
      <div class="big">{fmt(countFor('skipped'))}</div>
    </div>
  </div>

  <div class="row" style="margin: 14px 0">
    <button onclick={rescan}>Rescan Now</button>
    <span class="muted">
      Mode <span class="pill">{status.mode}</span> · backend
      <span class="pill">{status.backend}</span> · {status.workers} worker{status.workers === 1 ? '' : 's'} ·
      every {status.scan_interval_secs}s
    </span>
  </div>

  <div class="two-col">
    <div class="card">
      <h3 style="margin-top: 0">Threat Categories</h3>
      {#if Object.keys(status.threat_counts || {}).length}
        <table>
          <thead>
            <tr><th>Category</th><th style="text-align: right">Domains</th></tr>
          </thead>
          <tbody>
            {#each Object.entries(status.threat_counts) as [category, n] (category)}
              <tr>
                <td><code>{category}</code></td>
                <td class="num">{fmt(n)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {:else}
        <p class="muted">No threat verdicts yet.</p>
      {/if}
    </div>

    <div class="card">
      <h3 style="margin-top: 0">Enforcement</h3>
      <table>
        <tbody>
          <tr><td>Blocking threshold</td><td class="num">{status.block_threshold}</td></tr>
          <tr><td>Category verdict TTL</td><td class="num">{status.category_ttl_secs}s</td></tr>
          <tr><td>Threat verdict TTL</td><td class="num">{status.threat_ttl_secs}s</td></tr>
          <tr>
            <td>Auto-block categories</td>
            <td>
              {#if status.auto_block_categories?.length}
                {#each status.auto_block_categories as c, i (c)}
                  <span class="pill">{c}</span>{i < status.auto_block_categories.length - 1 ? ' ' : ''}
                {/each}
              {:else}
                <span class="muted">none</span>
              {/if}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

  <div class="card" style="margin-top: 18px">
    <h3 style="margin-top: 0">Domain Override</h3>
    <p class="muted" style="margin-top: 4px">
      <strong>Allow</strong> exempts a domain from every AI verdict (it is
      never auto-blocked). <strong>Clear</strong> removes an existing override
      so the verdict applies again.
    </p>
    <form class="override-row" onsubmit={(e) => { e.preventDefault(); saveOverride('allow'); }}>
      <input
        bind:value={overrideDomain}
        placeholder="domain e.g. news.example.com"
        style="flex: 1; min-width: 200px"
      />
      <input
        bind:value={overrideReason}
        placeholder="reason (optional)"
        style="flex: 1; min-width: 160px"
      />
      <button type="submit" disabled={overrideBusy}>Allow</button>
      <button
        type="button"
        class="secondary"
        onclick={() => saveOverride('clear')}
        disabled={overrideBusy}
      >Clear Override</button>
    </form>
  </div>
{/if}

<style>
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
    gap: 12px;
  }
  .stat .big { font-size: 1.6rem; font-weight: 700; margin-top: 6px; }
  .two-col {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 12px;
    margin-top: 18px;
  }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border); }
  th { font-size: 0.78rem; color: var(--muted); font-weight: 600; }
  .num { text-align: right; font-variant-numeric: tabular-nums; }
  .override-row { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 10px; }
</style>

<script>
  import { api, formatApiError } from '../api.js';
  import PageHeader from '../PageHeader.svelte';
  import { icons } from '../icons.svelte.js';
  import { formatTime } from '../datetime.svelte.js';

  const PER_PAGE = 50;
  const STATUS_FILTERS = [
    { value: '', label: 'All Statuses' },
    { value: 'pending', label: 'Pending' },
    { value: 'classified', label: 'Classified' },
    { value: 'skipped', label: 'Skipped' },
  ];

  let rows = $state([]);
  let total = $state(0);
  let page = $state(1); // 1-based; mirrors the server's clamped parameter
  let statusFilter = $state('');
  let loading = $state(true);
  let error = $state(null);
  let notice = $state(null);
  let disabled = $state(false); // true when the [ai] section is off (404)

  function qs() {
    const params = new URLSearchParams();
    if (statusFilter) params.set('status', statusFilter);
    params.set('page', String(page));
    params.set('per_page', String(PER_PAGE));
    return params.toString();
  }

  async function load() {
    loading = true;
    error = null;
    try {
      const data = await api.aiVerdicts(qs());
      rows = data.entries || [];
      total = data.total || 0;
      disabled = false;
      // The server clamps the page; adopt its answer so Prev/Next stay honest.
      page = data.page || page;
    } catch (e) {
      rows = [];
      total = 0;
      // 404 means the [ai] section is disabled: an empty state, not a failure.
      if (e.status === 404) {
        disabled = true;
      } else {
        error = formatApiError(e);
      }
    } finally {
      loading = false;
    }
  }

  function goPage(next) {
    page = Math.max(1, page + next);
    load();
  }

  async function override(domain, action) {
    notice = null;
    error = null;
    try {
      await api.aiOverride(domain, action);
      notice =
        action === 'allow'
          ? `${domain} is now AI-exempt.`
          : `Override cleared for ${domain}.`;
      await load();
    } catch (e) {
      error = formatApiError(e);
    }
  }

  // Severity and status are lowercase enum values; show them capitalized.
  function title(s) {
    return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
  }

  function pages() {
    return Math.max(1, Math.ceil(total / PER_PAGE));
  }

  function fmt(n) {
    return Number(n || 0).toLocaleString();
  }

  function when(stamp) {
    if (!stamp) return '-';
    const ms = Date.parse(stamp);
    return Number.isNaN(ms) ? '-' : formatTime(ms);
  }

  // Severity pills: threats red, classified green, everything else neutral.

  // Reload on mount and whenever the status filter changes (page resets to 1
  // because the filter changed the meaning of the list).
  $effect(() => {
    statusFilter;
    page = 1;
    load();
  });
</script>

<PageHeader
  icon={icons.ai}
  title="AI Verdicts"
  tagline="Per-domain classifications from the AI scanner, newest activity first. Allow overrides a verdict permanently; every auto-block decision respects cleared and allow overrides."
/>

{#if notice}
  <div class="card" style="border-color: var(--ok); margin-bottom: 14px">{notice}</div>
{/if}
{#if error}
  <div class="card" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">{error}</div>
{/if}

<div class="row" style="margin-bottom: 14px">
  <select bind:value={statusFilter} style="min-width: 150px">
    {#each STATUS_FILTERS as f (f.label)}
      <option value={f.value}>{f.label}</option>
    {/each}
  </select>
  <button class="secondary" onclick={load}>Refresh</button>
  {#if !disabled}
    <span class="muted">{fmt(total)} verdict{total === 1 ? '' : 's'}</span>
  {/if}
</div>

{#if loading}
  <div class="card">
    <p class="muted">Loading…</p>
  </div>
{:else if disabled}
  <div class="card">
    <h3 style="margin-top: 0">AI Subsystem Disabled</h3>
    <p class="muted" style="max-width: 70ch">
      The <code>[ai]</code> section of the configuration is not enabled, so
      there are no verdicts.
    </p>
  </div>
{:else if !rows.length}
  <div class="card">
    <p class="muted">
      No verdicts{statusFilter ? ` with status "${statusFilter}"` : ''} yet -
      they appear as the scanner classifies domains from live traffic.
    </p>
  </div>
{:else}
  <div class="card" style="padding: 0; overflow: auto">
    <table>
      <thead>
        <tr>
          <th>Domain</th>
          <th>Category</th>
          <th>Severity</th>
          <th>Status</th>
          <th style="text-align: right">Confidence</th>
          <th>Backend</th>
          <th>Evidence</th>
          <th>Classified</th>
          <th>Expires</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each rows as r (r.domain)}
          <tr>
            <td><code>{r.domain}</code></td>
            <td>
              {#if r.category}{r.category}{:else}<span class="muted">-</span>{/if}
            </td>
            <td>
              <span class="pill" class:err={r.severity === 'threat'}>
                {title(r.severity)}
              </span>
            </td>
            <td>
              <span class="pill" class:ok={r.status === 'classified'}>
                {title(r.status)}
              </span>
            </td>
            <td class="num">{r.confidence.toFixed(3)}</td>
            <td class="muted">{r.backend || '-'}</td>
            <td class="muted evidence">{r.evidence || '-'}</td>
            <td class="muted">{when(r.classified_at)}</td>
            <td class="muted">{when(r.expires_at)}</td>
            <td class="num">
              <button class="secondary" onclick={() => override(r.domain, 'allow')}>
                Allow
              </button>
              <button class="secondary" onclick={() => override(r.domain, 'clear')}>
                Clear
              </button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>

  <div class="row" style="margin-top: 12px">
    <button class="secondary" onclick={() => goPage(-1)} disabled={page <= 1}>
      ← Prev
    </button>
    <span class="muted">Page {page} of {pages()}</span>
    <button class="secondary" onclick={() => goPage(1)} disabled={page >= pages()}>
      Next →
    </button>
  </div>
{/if}

<style>
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border); vertical-align: middle; }
  th { font-size: 0.78rem; color: var(--muted); font-weight: 600; white-space: nowrap; }
  .num { text-align: right; white-space: nowrap; font-variant-numeric: tabular-nums; }
  .muted { color: var(--muted); }
  .evidence { max-width: 260px; font-size: 0.78rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .pill.ok { color: var(--ok); border-color: var(--ok); }
  .pill.err { color: var(--danger); border-color: var(--danger); }
</style>

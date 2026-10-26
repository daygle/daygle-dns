<script>
  import { api, formatApiError, getStoredUser } from '../api.js';
  import { formatDate, formatDateTime } from '../datetime.svelte.js';
  import { backendLabel, percent, STATUS_LABELS, titleCase } from '../aiLabels.js';

  const PER_PAGE = 50;
  const STATUS_FILTERS = [
    { value: '', label: 'All Statuses' },
    { value: 'classified', label: 'Classified' },
    { value: 'pending', label: 'Waiting' },
    { value: 'skipped', label: 'Skipped' },
  ];

  let rows = $state([]);
  let total = $state(0);
  let page = $state(1); // 1-based; mirrors the server's clamped parameter
  let statusFilter = $state('');
  let search = $state('');
  let loading = $state(true);
  let error = $state(null);
  let notice = $state(null);
  let disabled = $state(false); // true when the scanner is off (404)

  // Viewers are read-only (the server refuses their exemption changes);
  // with sign-in off there is no stored user at all.
  const isAdmin = getStoredUser()?.role !== 'viewer';

  function qs() {
    const params = new URLSearchParams();
    if (statusFilter) params.set('status', statusFilter);
    if (search.trim()) params.set('q', search.trim());
    params.set('page', String(page));
    params.set('per_page', String(PER_PAGE));
    return params.toString();
  }

  async function load() {
    loading = rows.length === 0;
    error = null;
    try {
      const data = await api.aiVerdicts(qs());
      rows = data.entries || [];
      total = data.total || 0;
      disabled = false;
      page = data.page || page;
      // Past the end (verdicts were dropped or exempted since the page was
      // opened): show the last page instead of an empty one.
      if (!rows.length && total > 0 && page > 1) {
        page = pages();
        return load();
      }
    } catch (e) {
      rows = [];
      total = 0;
      // 404 means the scanner is off: an empty state, not a failure.
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

  async function setExempt(domain, exempt) {
    notice = null;
    error = null;
    try {
      await api.aiOverride(domain, exempt ? 'allow' : 'clear');
      notice = exempt
        ? `${domain} and its subdomains are now exempt from AI blocking.`
        : `${domain} is no longer exempt.`;
      await load();
    } catch (e) {
      error = formatApiError(e);
    }
  }

  function pages() {
    return Math.max(1, Math.ceil(total / PER_PAGE));
  }

  function fmt(n) {
    return Number(n || 0).toLocaleString();
  }

  // Unset times come back as the UNIX epoch.
  function stamp(value, format) {
    if (!value) return '-';
    const ms = Date.parse(value);
    return Number.isNaN(ms) || ms <= 0 ? '-' : format(ms);
  }

  // Reload on mount and whenever a filter changes (back to page 1, since the
  // filter changed the list). Typing in the search box waits for a pause.
  let searchTimer;
  $effect(() => {
    statusFilter;
    search;
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      page = 1;
      load();
    }, 250);
    return () => clearTimeout(searchTimer);
  });
</script>

{#if notice}
  <div class="card" style="border-color: var(--ok); margin-bottom: 14px">{notice}</div>
{/if}
{#if error}
  <div class="card" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">{error}</div>
{/if}

{#if loading}
  <div class="card">
    <p class="muted">Loading...</p>
  </div>
{:else if disabled}
  <div class="card">
    <h3 style="margin: 0 0 10px">AI Scanner Is Off</h3>
    <p class="muted" style="margin: 0">
      There are no verdicts. Turn the scanner on in Settings → AI Scanner; it
      starts after the next restart.
    </p>
  </div>
{:else}
  <div class="card">
    <div class="spread" style="margin-bottom: 10px; gap: 10px; flex-wrap: wrap">
      <h3 style="margin: 0">Verdicts ({fmt(total)})</h3>
      <div class="row" style="gap: 8px; flex-wrap: wrap">
        <input type="search" placeholder="Search Domains" bind:value={search} style="min-width: 200px" />
        <select bind:value={statusFilter} style="min-width: 150px">
          {#each STATUS_FILTERS as f (f.label)}
            <option value={f.value}>{f.label}</option>
          {/each}
        </select>
        <button class="secondary" onclick={load}>Reload</button>
      </div>
    </div>
    <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Domain</th>
          <th>Category</th>
          <th>Status</th>
          <th class="num">Confidence</th>
          <th class="num" title="In how many scans the domain showed up in your DNS traffic">Seen</th>
          <th>Evidence</th>
          <th title="When the verdict expires: it is checked again if the domain is still being queried, and dropped otherwise">Re-Check</th>
          {#if isAdmin}<th class="num">Actions</th>{/if}
        </tr>
      </thead>
      <tbody>
        {#each rows as r (r.domain)}
          <tr>
            <td>
              <code>{r.domain}</code>{#if r.overridden}<span class="pill ok tag" title="Never auto-blocked by the AI">Exempt</span>{/if}
            </td>
            <td>
              {#if r.category}
                {titleCase(r.category)} {#if r.severity === 'threat'}<span class="pill err">Threat</span>{:else if r.severity === 'disputed'}<span class="pill" title="The verifier disagreed: this verdict never auto-blocks">Disputed</span>{/if}
              {:else}<span class="muted">-</span>{/if}
            </td>
            <td>
              <span
                class="pill"
                class:ok={r.status === 'classified'}
                title={r.status === 'pending' ? 'Classified on the next scan' : `${stamp(r.classified_at, formatDateTime)} by ${backendLabel(r.backend)}`}
              >{STATUS_LABELS[r.status] || titleCase(r.status)}</span>
            </td>
            <td class="num">
              {r.status === 'pending' || !r.category ? '-' : percent(r.confidence)}
            </td>
            <td class="num">{fmt(r.observations)}</td>
            <td class="muted evidence" title={r.evidence}>{r.evidence || '-'}</td>
            <td class="muted nowrap">{stamp(r.expires_at, formatDate)}</td>
            {#if isAdmin}
              <td class="num">
                {#if r.overridden}
                  <button class="secondary" onclick={() => setExempt(r.domain, false)} title="Let the AI block this domain again">Unexempt</button>
                {:else}
                  <button class="secondary" onclick={() => setExempt(r.domain, true)} title="Never let the AI block this domain or its subdomains">Exempt</button>
                {/if}
              </td>
            {/if}
          </tr>
        {/each}
      </tbody>
    </table>
    </div>
    {#if !rows.length}
      <p class="muted">
        {#if search.trim() || statusFilter}
          No verdicts match these filters.
        {:else}
          No verdicts yet - they appear as the scanner classifies domains from
          your DNS traffic.
        {/if}
      </p>
    {/if}
  </div>

  {#if total > PER_PAGE}
    <div class="row" style="margin-top: 12px">
      <button class="secondary" onclick={() => goPage(-1)} disabled={page <= 1}>← Prev</button>
      <span class="muted">Page {page} of {pages()}</span>
      <button class="secondary" onclick={() => goPage(1)} disabled={page >= pages()}>Next →</button>
    </div>
  {/if}
{/if}

<style>
  .nowrap { white-space: nowrap; }
  .tag { margin-left: 6px; }
  .evidence { max-width: 200px; font-size: 0.78rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>

<script>
  import IconButton from '../IconButton.svelte';
  import { api, formatApiError, getStoredUser } from '../api.js';
  import { formatDate, formatDateTime } from '../datetime.svelte.js';
  import { backendLabel, percent, titleCase } from '../aiLabels.js';
  import ColumnPicker from '../ColumnPicker.svelte';
  import { isHidden } from '../columns.svelte.js';
  import AiExemptionDialog from './AiExemptionDialog.svelte';

  const COLUMNS = [
    { key: 'domain', label: 'Domain', locked: true },
    { key: 'category', label: 'Category' },
    { key: 'state', label: 'State' },
    { key: 'confidence', label: 'Confidence' },
    { key: 'seen', label: 'Seen' },
    { key: 'evidence', label: 'Evidence' },
    { key: 're-check', label: 'Re-Check' },
  ];
  const show = (key) => !isHidden('ai-threats', key);

  const PER_PAGE = 50;
  const SEVERITY_FILTERS = [
    { value: '', label: 'All Severity' },
    { value: 'threat', label: 'Threat' },
    { value: 'disputed', label: 'Disputed' },
  ];
  const EXEMPTION_FILTERS = [
    { value: '', label: 'All Threats' },
    { value: 'exempt', label: 'Exempt' },
    { value: 'not_exempt', label: 'Not Exempt' },
  ];

  let rows = $state([]);
  let total = $state(0);
  let page = $state(1); // 1-based; mirrors the server's clamped parameter
  let search = $state('');
  let categoryFilter = $state('');
  let categories = $state([]);
  let severityFilter = $state('');
  let exemptionFilter = $state('');
  let loading = $state(true);
  let error = $state(null);
  let notice = $state(null);
  let exemptionDomain = $state(null);
  let disabled = $state(false); // true when the scanner is off (404)

  // Viewers are read-only (the server refuses their exemption changes);
  // with sign-in off there is no stored user at all.
  const isAdmin = getStoredUser()?.role !== 'viewer';

  async function loadCategories() {
    try {
      const status = await api.aiStatus();
      categories = [...new Set(status?.backend_categories || [])].sort();
    } catch {
      categories = [];
    }
  }

  function qs() {
    const params = new URLSearchParams();
    if (search.trim()) params.set('q', search.trim());
    if (categoryFilter.trim()) params.set('category', categoryFilter.trim());
    if (severityFilter) params.set('severity', severityFilter);
    if (exemptionFilter) params.set('exemption', exemptionFilter);
    params.set('page', String(page));
    params.set('per_page', String(PER_PAGE));
    return params.toString();
  }

  async function load() {
    loading = rows.length === 0;
    error = null;
    try {
      const data = await api.aiThreats(qs());
      rows = data.entries || [];
      total = data.total || 0;
      disabled = false;
      page = data.page || page;
      // Past the end (verdicts expired or were exempted since the page
      // was opened): show the last page instead of an empty one.
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

  function setExempt(domain, exempt) {
    if (exempt) {
      exemptionDomain = domain;
      return;
    }
    applyExemption(domain, false, '');
  }

  async function applyExemption(domain, exempt, reason) {
    exemptionDomain = null;
    notice = null;
    error = null;
    try {
      await api.aiOverride(domain, exempt ? 'allow' : 'clear', reason);
      notice = exempt
        ? `${domain} and its subdomains are now exempt from AI blocking.`
        : `${domain} is no longer exempt; blocking applies again once a fresh threat qualifies.`;
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

  // Reload on mount and whenever the search box changes (back to page 1,
  // since the filter changed the list). Typing waits for a pause.
  let searchTimer;
  loadCategories();

  $effect(() => {
    search;
    categoryFilter;
    severityFilter;
    exemptionFilter;
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
      There are no threats. Turn the scanner on in Settings → AI Scanner; it
      starts after the next restart.
    </p>
  </div>
{:else}
  <div class="card">
    <div class="spread" style="margin-bottom: 10px; gap: 10px; flex-wrap: wrap">
      <h3 style="margin: 0">Detected Threats ({fmt(total)})</h3>
      <div class="row" style="gap: 8px; flex-wrap: wrap">
        <input type="search" placeholder="Search Domains" bind:value={search} style="min-width: 200px" />
        <select bind:value={categoryFilter} aria-label="Filter by category" style="min-width: 150px">
          <option value="">All Categories</option>
          {#each categories as category (category)}
            <option value={category}>{titleCase(category)}</option>
          {/each}
        </select>
        <select bind:value={severityFilter} aria-label="Filter by severity" style="min-width: 145px">
          {#each SEVERITY_FILTERS as f (f.label)}
            <option value={f.value}>{f.label}</option>
          {/each}
        </select>
        <select bind:value={exemptionFilter} aria-label="Filter by exemption" style="min-width: 145px">
          {#each EXEMPTION_FILTERS as f (f.label)}
            <option value={f.value}>{f.label}</option>
          {/each}
        </select>
        <button class="secondary" onclick={load}>Reload</button>
        <ColumnPicker table="ai-threats" columns={COLUMNS} />
      </div>
    </div>
    <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Domain</th>
          {#if show('category')}<th>Category</th>{/if}
          {#if show('state')}<th>State</th>{/if}
          {#if show('confidence')}<th class="num">Confidence</th>{/if}
          {#if show('seen')}<th class="num" title="In how many scans the domain showed up in your DNS traffic">Seen</th>{/if}
          {#if show('evidence')}<th>Evidence</th>{/if}
          {#if show('re-check')}<th title="When the threat expires: it is checked again if the domain is still being queried, and dropped otherwise">Re-Check</th>{/if}
          {#if isAdmin}<th class="num">Actions</th>{/if}
        </tr>
      </thead>
      <tbody>
        {#each rows as r (r.domain)}
          <tr>
            <td>
              <code>{r.domain}</code>
            </td>
            {#if show('category')}
            <td>{#if r.category}{titleCase(r.category)}{:else}<span class="muted">-</span>{/if}</td>
            {/if}
            {#if show('state')}
            <td>
              {#if r.severity === 'disputed'}
                <span class="pill" title="The verifier disagreed with this threat detection: the domain is never auto-blocked">Disputed</span>
              {:else if r.blocked}
                <span class="pill err" title="In the current block snapshot: auto-blocked in enforce mode">Auto-Blocked</span>
              {:else if r.overridden}
                <span class="pill ok tag" title="Exempt: the operator's allow override vetoed blocking for this domain">Exempt</span>
              {:else}
                <span class="pill" title="Not in the block snapshot: below the block threshold, not an auto-block category, or expired">Not Blocked</span>
              {/if}
            </td>
            {/if}
            {#if show('confidence')}
              <td class="num">{percent(r.confidence)}</td>
            {/if}
            {#if show('seen')}<td class="num">{fmt(r.observations)}</td>{/if}
            {#if show('evidence')}
              <td class="muted evidence" title={titleCase(r.evidence)}>{r.evidence || '-'}</td>
            {/if}
            {#if show('re-check')}<td class="muted nowrap">{stamp(r.expires_at, formatDate)}</td>{/if}
            {#if isAdmin}
              <td class="num">
                {#if r.overridden}
                  <IconButton icon="disallow" label="Unexempt: let the AI block this domain again" onclick={() => setExempt(r.domain, false)} />
                {:else}
                  <IconButton icon="allow" label="Exempt: never let the AI block this domain or its subdomains" onclick={() => setExempt(r.domain, true)} />
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
        {#if search.trim() || categoryFilter.trim() || severityFilter || exemptionFilter}
          No threats match these filters.
        {:else}
          No threats yet - benign lookups never appear here; entries
          show up when the scanner classifies a domain badly enough to matter.
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

{#if exemptionDomain}
  <AiExemptionDialog
    domain={exemptionDomain}
    onCancel={() => (exemptionDomain = null)}
    onConfirm={(reason) => applyExemption(exemptionDomain, true, reason)}
  />
{/if}

<style>
  .nowrap { white-space: nowrap; }
  .evidence { max-width: 200px; font-size: 0.78rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>

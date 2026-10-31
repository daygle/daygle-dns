<script>
  import IconButton from '../IconButton.svelte';
  import { api, formatApiError, getStoredUser } from '../api.js';
  import { formatDateTime } from '../datetime.svelte.js';

  let rows = $state([]);
  let loading = $state(true);
  let error = $state(null);
  let notice = $state(null);
  let search = $state('');
  let reasonFilter = $state('');

  const isAdmin = getStoredUser()?.role !== 'viewer';
  const filtered = $derived.by(() => {
    const q = search.trim().toLowerCase();
    const reasonQuery = reasonFilter.trim().toLowerCase();
    return rows.filter((r) => {
      const matchesSearch = !q || r.domain.toLowerCase().includes(q) || (r.reason || '').toLowerCase().includes(q);
      const hasReason = !!(r.reason || '').trim();
      const matchesReason = !reasonQuery || (reasonQuery === 'provided' ? hasReason : !hasReason);
      return matchesSearch && matchesReason;
    });
  });

  async function load() {
    loading = true;
    error = null;
    try {
      rows = (await api.aiOverrides())?.overrides || [];
    } catch (e) {
      rows = [];
      if (e.status !== 404) error = formatApiError(e);
    } finally {
      loading = false;
    }
  }

  async function removeExemption(domain) {
    if (!confirm(`Remove the AI exemption for ${domain}? The AI may block it and its subdomains again if a future threat qualifies.`)) return;
    notice = null;
    error = null;
    try {
      await api.aiOverride(domain, 'clear');
      notice = `${domain} is no longer exempt; blocking applies again once a fresh threat qualifies.`;
      await load();
    } catch (e) {
      error = formatApiError(e);
    }
  }

  function stamp(value) {
    const ms = Date.parse(value || '');
    return Number.isNaN(ms) || ms <= 0 ? '-' : formatDateTime(ms);
  }

  load();
</script>

{#if notice}
  <div class="card" style="border-color: var(--ok); margin-bottom: 14px">{notice}</div>
{/if}
{#if error}
  <div class="card" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">{error}</div>
{/if}

<div class="card">
  <div class="spread" style="margin-bottom: 10px; gap: 10px; flex-wrap: wrap">
    <h3 style="margin: 0">Exempt Domains ({filtered.length})</h3>
    <div class="row" style="gap: 8px; flex-wrap: wrap">
      <input type="search" placeholder="Search Domains or Reasons" bind:value={search} style="min-width: 200px" />
      <select bind:value={reasonFilter} aria-label="Filter by reason">
        <option value="">All Reasons</option>
        <option value="provided">Reason Provided</option>
        <option value="empty">No Reason</option>
      </select>
      <button class="secondary" onclick={load}>Reload</button>
    </div>
  </div>
  <p class="muted" style="margin: 0 0 12px">
    Exemptions prevent AI blocking for the listed domain and its subdomains. Remove one to let future qualifying threats block again.
  </p>
  {#if loading}
    <p class="muted">Loading...</p>
  {:else if rows.length === 0}
    <p class="muted" style="margin-bottom: 0">No domains are exempt from AI blocking.</p>
  {:else if filtered.length === 0}
    <p class="muted" style="margin-bottom: 0">No exempt domains match these filters.</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Domain</th>
            <th>Reason</th>
            <th>Added</th>
            {#if isAdmin}<th class="num">Actions</th>{/if}
          </tr>
        </thead>
        <tbody>
          {#each filtered as row (row.domain)}
            <tr>
              <td><code>{row.domain}</code></td>
              <td>{#if row.reason}{row.reason}{:else}<span class="muted">Not provided</span>{/if}</td>
              <td class="muted nowrap">{stamp(row.created_at)}</td>
              {#if isAdmin}
                <td class="num">
                  <IconButton icon="disallow" label={`Remove AI exemption for ${row.domain}`} onclick={() => removeExemption(row.domain)} />
                </td>
              {/if}
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

<style>
  .nowrap { white-space: nowrap; }
</style>

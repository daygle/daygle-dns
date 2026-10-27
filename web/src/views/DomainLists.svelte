<script>
  import { api, formatApiError, getStoredUser } from '../api.js';

  // One of the two lists: kind is 'allow' (policy.allowlist) or 'block'
  // (policy.blocklist). Each change is saved and applied at once.
  let { kind } = $props();

  const KINDS = {
    allow: {
      key: 'allowlist',
      other: 'blocklist',
      title: 'Allow List',
      otherTitle: 'Block List',
      help: 'Never blocked by the blocklists, the Block List or the AI.',
      placeholder: 'updates.example.com',
    },
    block: {
      key: 'blocklist',
      other: 'allowlist',
      title: 'Block List',
      otherTitle: 'Allow List',
      help: 'Blocked for every client, whatever the blocklists say. A domain on the Allow List is still allowed.',
      placeholder: 'ads.example.com',
    },
  };
  const k = $derived(KINDS[kind]);

  // Viewers are read-only (the server refuses their changes).
  const isAdmin = getStoredUser()?.role !== 'viewer';

  let entries = $state([]);
  let otherEntries = $state([]);
  let loaded = $state(false);
  let busy = $state(false);
  let error = $state(null);
  let notice = $state(null);
  let search = $state('');
  let adding = $state('');
  let bulk = $state(null); // text of the Bulk Add box while it is open

  const norm = (d) => d.trim().toLowerCase().replace(/\.$/, '');
  const otherSet = $derived(new Set(otherEntries.map(norm)));
  const shown = $derived.by(() => {
    const q = search.trim().toLowerCase();
    const list = q ? entries.filter((d) => d.toLowerCase().includes(q)) : entries;
    return [...list].sort((a, b) => a.replace(/^\*\./, '').localeCompare(b.replace(/^\*\./, '')));
  });

  async function load() {
    error = null;
    try {
      const config = await api.config();
      entries = config?.policy?.[k.key] || [];
      otherEntries = config?.policy?.[k.other] || [];
      loaded = true;
    } catch (e) {
      error = formatApiError(e);
    }
  }

  // Domains from typed or pasted text: split on new lines, commas and
  // spaces, with hosts-file addresses and comments dropped.
  function parse(text) {
    return (text || '')
      .split('\n')
      .map((line) => line.replace(/#.*/, ''))
      .flatMap((line) => line.split(/[\s,]+/))
      .map((s) => s.trim())
      .filter((s) => s && !/^(\d+\.){3}\d+$/.test(s) && !/^[0-9a-f]*:[0-9a-f:.]*$/i.test(s));
  }

  async function save(next, message) {
    busy = true;
    error = null;
    notice = null;
    try {
      await api.updateSettings({ policy: { [k.key]: next } });
      notice = message;
      await load();
      return true;
    } catch (e) {
      error = formatApiError(e);
      return false;
    } finally {
      busy = false;
    }
  }

  // The domains in `text` that are not on the list yet.
  function fresh(text) {
    const have = new Set(entries.map(norm));
    return [...new Map(parse(text).map((d) => [norm(d), d])).values()].filter((d) => !have.has(norm(d)));
  }
  const bulkCount = $derived(bulk === null ? 0 : fresh(bulk).length);

  async function add(text) {
    const added = fresh(text);
    if (added.length === 0) {
      notice = null;
      error = 'Nothing new to add: every domain given is already on the list.';
      return false;
    }
    const message =
      added.length === 1 ? `${added[0]} was added.` : `${added.length} domains were added.`;
    return save([...entries, ...added], message);
  }

  async function addOne(e) {
    e.preventDefault();
    if (await add(adding)) adding = '';
  }

  async function addBulk() {
    if (await add(bulk)) bulk = null;
  }

  function remove(domain) {
    save(entries.filter((d) => d !== domain), `${domain} was removed.`);
  }

  $effect(() => {
    kind;
    search = '';
    bulk = null;
    notice = null;
    load();
  });
</script>

{#if notice}
  <div class="card" style="border-color: var(--ok); margin-bottom: 14px">{notice}</div>
{/if}
{#if error}
  <div class="card" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">{error}</div>
{/if}

<div class="card">
  <div class="spread" style="margin-bottom: 10px; gap: 10px; flex-wrap: wrap">
    <h3 style="margin: 0">{k.title} ({entries.length})</h3>
    <div class="row" style="gap: 8px; flex-wrap: wrap">
      <input class="search" bind:value={search} placeholder="Search domains" aria-label="Search domains" />
      {#if isAdmin}
        <form class="row" style="gap: 6px" onsubmit={addOne}>
          <input bind:value={adding} placeholder={k.placeholder} aria-label="Domain to add" disabled={busy} />
          <button type="submit" disabled={busy || !adding.trim()}>Add</button>
        </form>
        <button class="secondary" onclick={() => (bulk = bulk === null ? '' : null)} disabled={busy}>Bulk Add</button>
      {/if}
    </div>
  </div>

  {#if bulk !== null}
    <div class="bulk">
      <textarea rows="8" bind:value={bulk} placeholder={'One domain per line (a hosts file or a comma separated list also works)\nexample.com\n*.example.net'} aria-label="Domains to add"></textarea>
      <div class="row" style="gap: 6px; margin-top: 8px">
        <button onclick={addBulk} disabled={busy || bulkCount === 0}>Add {bulkCount || ''} {bulkCount === 1 ? 'Domain' : 'Domains'}</button>
        <button class="secondary" onclick={() => (bulk = null)} disabled={busy}>Cancel</button>
      </div>
    </div>
  {/if}

  {#if !loaded}
    {#if !error}<p class="muted">Loading...</p>{/if}
  {:else if entries.length === 0}
    <p class="muted">No domains yet.</p>
  {:else if shown.length === 0}
    <p class="muted">No domains match the search.</p>
  {:else}
    <div class="table-wrap" style="max-height: 70vh; overflow-y: auto">
      <table>
        <thead>
          <tr>
            <th>Domain</th>
            <th>Matches</th>
            {#if isAdmin}<th class="num">Actions</th>{/if}
          </tr>
        </thead>
        <tbody>
          {#each shown as domain (domain)}
            <tr>
              <td>
                <code>{domain}</code>
                {#if otherSet.has(norm(domain))}
                  <span class="pill" title="The Allow List wins, so this domain is allowed">Also on {k.otherTitle}</span>
                {/if}
              </td>
              <td class="muted">
                {#if domain.startsWith('*.')}
                  Every subdomain of {domain.slice(2)}
                {:else}
                  This name only
                {/if}
              </td>
              {#if isAdmin}
                <td class="num">
                  <button class="secondary" onclick={() => remove(domain)} disabled={busy}>Remove</button>
                </td>
              {/if}
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}

  <p class="muted help">
    {k.help} <code>example.com</code> matches that name only, and
    <code>*.example.com</code> matches every subdomain of it (but not
    <code>example.com</code> itself), so add both to cover a whole domain.
    Changes apply immediately.
  </p>
</div>

<style>
  .search { min-width: 200px; }
  form input { min-width: 200px; }
  .bulk { margin-bottom: 12px; }
  .bulk textarea { width: 100%; padding: 8px; }
  code { word-break: break-all; }
</style>

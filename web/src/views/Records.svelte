<script>
  import { api, formatApiError } from '../api.js';

  // The zone to preselect, passed when coming from the Zones page.
  let { zoneId = null, onSelectZone = () => {} } = $props();

  const TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'PTR', 'CAA'];

  let zones = $state([]);
  let zonesLoaded = $state(false);
  let selected = $state(null);
  let records = $state([]);
  let recordsLoading = $state(false);
  let error = $state(null);
  let notice = $state(null);
  let edit = $state(null);

  // Searchable zone picker state.
  let query = $state('');
  let pickerOpen = $state(false);
  let pickerBlurTimer;

  // Matches the typed text (case-insensitive). While the box simply shows the
  // name of the selected zone (no active search) the full list is offered so a
  // different zone can be picked without first clearing the input.
  const zoneMatches = $derived(
    query === (selected?.name ?? '')
      ? zones
      : zones.filter((z) => z.name.toLowerCase().includes(query.trim().toLowerCase()))
  );

  async function loadZones() {
    error = null;
    try {
      zones = await api.zones();
      zonesLoaded = true;
      if (zoneId != null) {
        const match = zones.find((z) => String(z.id) === String(zoneId));
        if (match) await select(match, { notify: false });
      }
    } catch (e) {
      error = formatApiError(e);
    }
  }

  async function select(zone, { notify = true } = {}) {
    selected = zone;
    query = zone.name;
    pickerOpen = false;
    edit = null;
    notice = null;
    if (notify) onSelectZone(zone.id);
    await loadRecords(zone.id);
  }

  async function loadRecords(zoneId) {
    recordsLoading = true;
    error = null;
    try {
      records = await api.records(zoneId);
    } catch (e) {
      error = formatApiError(e);
      records = [];
    } finally {
      recordsLoading = false;
    }
  }

  function openPicker() {
    pickerOpen = true;
  }

  function closePicker() {
    pickerOpen = false;
    // Dropping focus without picking leaves a clean box: revert to the
    // selected zone's name (or empty when nothing is selected).
    query = selected?.name ?? '';
  }

  function onPickerBlur() {
    clearTimeout(pickerBlurTimer);
    // Delay so a click on a list item registers before the list closes.
    pickerBlurTimer = setTimeout(closePicker, 120);
  }

  function onPickerKeydown(e) {
    if (e.key === 'Enter') {
      const first = zoneMatches[0];
      if (first) {
        e.preventDefault();
        select(first);
      }
    } else if (e.key === 'Escape') {
      e.preventDefault();
      closePicker();
    }
  }

  function startEdit(record) {
    edit = record
      ? { ...record, isNew: false }
      : { name: '', rtype: 'A', content: '', ttl: 3600, priority: 0, isNew: true };
  }

  async function saveEdit() {
    if (!edit || !selected) return;
    notice = null;
    try {
      await api.upsertRecord(selected.id, {
        name: edit.name,
        rtype: edit.rtype,
        content: edit.content,
        ttl: Number(edit.ttl) || 3600,
        priority: Number(edit.priority) || 0,
      });
      edit = null;
      notice = 'Record saved and applied live.';
      await loadRecords(selected.id);
    } catch (e) {
      notice = formatApiError(e);
    }
  }

  async function removeRecord(record) {
    if (!selected) return;
    if (!confirm(`Delete the ${record.rtype} record for "${record.name}"?`)) return;
    notice = null;
    try {
      await api.deleteRecord(selected.id, record.id);
      await loadRecords(selected.id);
    } catch (e) {
      notice = formatApiError(e);
    }
  }

  $effect(() => { loadZones(); });
</script>

<h1>Records</h1>
<p class="muted" style="max-width: 75ch">
  View and edit the DNS records of an authoritative zone. Pick a zone below;
  secondary zones are refreshed from their master and are read-only here.
</p>

{#if notice}
  <div class="card notice" class:error={notice.startsWith('Error:')}>{notice}</div>
{/if}
{#if error}
  <div class="card notice error">{error}</div>
{/if}

{#if !zonesLoaded}
  <p class="muted">Loading…</p>
{:else if zones.length === 0}
  <div class="card">
    <p class="muted" style="margin: 0">
      No zones yet. Create a zone on the Zones page, then come back here to add records.
    </p>
  </div>
{:else}
  <div class="row picker">
    <label for="zone-search" class="picker-label">Zone</label>
    <div class="picker-box">
      <input
        id="zone-search"
        class="zone-search"
        type="text"
        role="combobox"
        aria-expanded={pickerOpen}
        aria-controls="zone-list"
        aria-autocomplete="list"
        autocomplete="off"
        spellcheck="false"
        placeholder="Search zones…"
        bind:value={query}
        onfocus={openPicker}
        onblur={onPickerBlur}
        oninput={() => (pickerOpen = true)}
        onkeydown={onPickerKeydown}
      />
      {#if pickerOpen}
        <div id="zone-list" class="picker-list" role="listbox" onmousedown={(e) => e.preventDefault()}>
          {#if zoneMatches.length === 0}
            <div class="picker-empty">No zones match “{query.trim()}”</div>
          {:else}
            {#each zoneMatches as z (z.id)}
              <button
                type="button"
                class="picker-option"
                class:sel={selected?.id === z.id}
                role="option"
                aria-selected={selected?.id === z.id}
                onclick={() => select(z)}
              >
                <code>{z.name}</code>
                {#if z.zone_type === 'secondary'}<span class="pill">Secondary</span>{/if}
              </button>
            {/each}
          {/if}
        </div>
      {/if}
    </div>
    {#if selected}
      <span class="pill">{selected.zone_type === 'secondary' ? 'Secondary' : 'Primary'}</span>
      <span class:pill={true} class:ok={selected.dnssec}>{selected.dnssec ? 'Signed' : 'Unsigned'}</span>
    {/if}
  </div>

  {#if !selected}
    <p class="muted">Select a zone to view and edit its records.</p>
  {:else}
    <div class="card">
      <div class="spread" style="margin-bottom: 12px">
        <strong>Records for <code>{selected.name}</code></strong>
        {#if selected.zone_type !== 'secondary'}
          <button onclick={() => startEdit(null)}>+ Record</button>
        {/if}
      </div>

      {#if selected.zone_type === 'secondary'}
        <p class="muted zone-help">This is a read-only secondary zone. It is refreshed from: {selected.masters?.join(', ') || 'configured masters'}.</p>
      {/if}

      <div class="table-wrap">
        <table>
          <thead><tr><th>Name</th><th>Type</th><th>Value</th><th>TTL</th><th class="num"></th></tr></thead>
          <tbody>
            {#each records as record (record.id)}
              <tr>
                <td><code>{record.name}</code></td>
                <td>{record.rtype}</td>
                <td><code>{record.content}</code></td>
                <td>{record.ttl}</td>
                <td class="num">
                  {#if selected.zone_type !== 'secondary'}
                    <div class="row" style="gap: 6px; justify-content: flex-end">
                      <button class="secondary" onclick={() => startEdit(record)}>Edit</button>
                      <button class="danger" onclick={() => removeRecord(record)}>✕</button>
                    </div>
                  {:else}
                    <span class="muted">Read-only</span>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      {#if recordsLoading}
        <p class="muted">Loading records…</p>
      {:else if records.length === 0}
        <p class="muted">No records yet. Add one with the + Record button.</p>
      {/if}

      {#if edit}
        <div class="card" style="margin-top: 14px; background: var(--panel-2)">
          <h4 style="margin-top: 0">{edit.isNew ? 'New Record' : 'Edit Record'}</h4>
          <div class="grid2">
            <label>Name <input placeholder="www" bind:value={edit.name} /></label>
            <label>Type<select bind:value={edit.rtype}>{#each TYPES as t (t)}<option value={t}>{t}</option>{/each}</select></label>
            <label>Value <input placeholder="192.0.2.1" bind:value={edit.content} /></label>
            <label>TTL <input type="number" bind:value={edit.ttl} /></label>
            {#if edit.rtype === 'MX' || edit.rtype === 'SRV'}
              <label>Priority <input type="number" bind:value={edit.priority} /></label>
            {/if}
          </div>
          <div class="row" style="margin-top: 10px">
            <button onclick={saveEdit}>Save</button>
            <button class="secondary" onclick={() => (edit = null)}>Cancel</button>
          </div>
        </div>
      {/if}
    </div>
  {/if}
{/if}

<style>
  .picker { margin-bottom: 14px; gap: 10px; align-items: center; }
  .picker-label { font-size: 0.85rem; color: var(--muted); margin: 0; }
  .picker-box { position: relative; flex: 0 1 340px; min-width: 240px; }
  .zone-search {
    width: 100%;
    background: var(--panel-2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 6px 8px;
    font: inherit;
    color: inherit;
  }
  .picker-list {
    position: absolute;
    top: calc(100% + 4px);
    left: 0;
    right: 0;
    z-index: 20;
    display: flex;
    flex-direction: column;
    gap: 2px;
    max-height: 300px;
    overflow: auto;
    padding: 4px;
    background: var(--panel-2);
    border: 1px solid var(--border);
    border-radius: 8px;
    box-shadow: 0 10px 30px rgb(0 0 0 / 0.4);
  }
  .picker-option {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    background: none;
    border: none;
    border-radius: 6px;
    padding: 7px 8px;
    cursor: pointer;
    color: var(--text);
    font-size: 0.85rem;
    text-align: left;
  }
  .picker-option code { font-size: 0.9rem; }
  .picker-option:hover, .picker-option.sel { background: rgb(91 140 255 / 0.18); }
  .picker-option .pill { margin-left: auto; }
  .picker-empty { padding: 8px; color: var(--muted); font-size: 0.85rem; }
  .notice { margin-bottom: 14px; }
  .notice.error { border-color: var(--danger); color: var(--danger); }
  .zone-help { margin-top: -4px; }
  .table-wrap { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border); vertical-align: middle; }
  th { font-size: 0.78rem; color: var(--muted); font-weight: 600; }
  .num { text-align: right; white-space: nowrap; }
  td.num button { padding: 4px 9px; }
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; color: var(--muted); }
</style>

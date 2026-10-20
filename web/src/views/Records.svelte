<script>
  import { api, formatApiError } from '../api.js';
  import { duration } from '../aiLabels.js';

  // The zone to preselect, passed when coming from the Zones page.
  let { zoneId = null, onSelectZone = () => {} } = $props();

  // Server-wide default TTL (Settings → Zones), used to pre-fill
  // the TTL field of new records.
  let defaultTtl = $state(3600);

  // Value examples in zone-file presentation format, which is what the server
  // parses. MX and SRV carry their priority inside the value.
  const EXAMPLES = {
    A: '192.0.2.1',
    AAAA: '2001:db8::1',
    CNAME: 'target.example.com.',
    ALIAS: 'myapp.cdn.example.net.',
    MX: '10 mail.example.com.',
    TXT: '"v=spf1 mx -all"',
    NS: 'ns1.example.com.',
    SRV: '10 5 5060 sip.example.com.',
    PTR: 'host.example.com.',
    CAA: '0 issue "letsencrypt.org"',
    HTTPS: '1 . alpn=h2,h3',
    SVCB: '1 svc.example.com. port=8443',
    DS: '12345 13 2 3F2A6B1C…',
    TLSA: '3 1 1 0C72AC70B745…',
    SSHFP: '4 2 9F6B2C1D0E3A…',
    NAPTR: '100 10 "S" "SIP+D2U" "" _sip._udp.example.com.',
  };
  const TYPES = Object.keys(EXAMPLES);

  let zones = $state([]);
  let zonesLoaded = $state(false);
  let selected = $state(null);
  let records = $state([]);
  let recordsLoading = $state(false);
  // `error` shows in red, `notice` (success) in green; failures while the
  // record dialog is open show inside it.
  let error = $state(null);
  let notice = $state(null);
  let dialogError = $state(null);
  let saving = $state(false);
  let edit = $state(null);

  // Record list filter.
  let filterText = $state('');
  let filterType = $state('');
  const typesPresent = $derived([...new Set(records.map((r) => r.rtype))].sort());
  const shown = $derived(
    records.filter((r) => {
      if (filterType && r.rtype !== filterType) return false;
      const q = filterText.trim().toLowerCase();
      return !q || r.name.toLowerCase().includes(q) || r.content.toLowerCase().includes(q);
    }),
  );

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
    filterText = '';
    filterType = '';
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

  // Names are stored fully qualified; show them relative to the zone the
  // way zone files do ("www", "@" for the zone itself).
  function relativeName(name) {
    if (!selected) return name;
    const zone = selected.name.replace(/\.$/, '').toLowerCase();
    const n = name.replace(/\.$/, '').toLowerCase();
    if (n === zone) return '@';
    if (n.endsWith(`.${zone}`)) return name.slice(0, n.length - zone.length - 1);
    return name;
  }

  function startEdit(record) {
    notice = null;
    error = null;
    dialogError = null;
    edit = record
      ? { ...record, name: relativeName(record.name), isNew: false }
      : { name: '', rtype: 'A', content: '', ttl: defaultTtl, priority: 0, isNew: true };
  }

  function closeEdit() {
    if (!saving) edit = null;
  }

  async function saveEdit() {
    if (!edit || !selected) return;
    dialogError = null;
    saving = true;
    try {
      const body = {
        name: edit.name,
        rtype: edit.rtype,
        content: edit.content,
        ttl: Number(edit.ttl) || defaultTtl,
        priority: Number(edit.priority) || 0,
      };
      // Editing replaces the record in place; only new records are added.
      if (edit.isNew) await api.upsertRecord(selected.id, body);
      else await api.replaceRecord(selected.id, edit.id, body);
      notice = `${body.rtype} record ${edit.isNew ? 'added' : 'saved'} and applied live.`;
      edit = null;
      await loadRecords(selected.id);
    } catch (e) {
      dialogError = formatApiError(e);
    } finally {
      saving = false;
    }
  }

  async function removeRecord(record) {
    if (!selected) return;
    if (!confirm(`Delete the ${record.rtype} record for "${relativeName(record.name)}"?`)) return;
    notice = null;
    error = null;
    try {
      await api.deleteRecord(selected.id, record.id);
      notice = `${record.rtype} record for "${relativeName(record.name)}" deleted.`;
      await loadRecords(selected.id);
    } catch (e) {
      error = formatApiError(e);
    }
  }

  // A disabled record stays in the zone but is not served.
  async function toggleDisabled(record) {
    if (!selected) return;
    notice = null;
    error = null;
    try {
      await api.setRecordDisabled(selected.id, record.id, !record.disabled);
      notice = record.disabled
        ? `${record.rtype} record for "${relativeName(record.name)}" enabled.`
        : `${record.rtype} record for "${relativeName(record.name)}" disabled: kept in the zone but not served.`;
      await loadRecords(selected.id);
    } catch (e) {
      error = formatApiError(e);
    }
  }

  $effect(() => {
    loadZones();
    api.config().then((cfg) => {
      const ttl = cfg?.authoritative?.default_record_ttl;
      if (Number(ttl) > 0) defaultTtl = Number(ttl);
    }).catch(() => {});
  });
</script>

{#if notice}
  <div class="card notice ok">{notice}</div>
{/if}
{#if error}
  <div class="card notice error">{error}</div>
{/if}

{#if !zonesLoaded}
  <div class="card">
    <p class="muted">Loading…</p>
  </div>
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
    <div class="card">
      <p class="muted" style="margin: 0">Select a zone to view and edit its records.</p>
    </div>
  {:else}
    <div class="card">
      <div class="spread" style="margin-bottom: 10px">
        <h3 style="margin: 0">Records for <code>{selected.name}</code> ({records.length})</h3>
        {#if selected.zone_type !== 'secondary'}
          <button onclick={() => startEdit(null)}>Add Record</button>
        {/if}
      </div>

      {#if selected.zone_type === 'secondary'}
        <p class="muted zone-help">This is a read-only secondary zone. It is refreshed from: {selected.masters?.join(', ') || 'configured masters'}.</p>
      {/if}

      {#if records.length > 0}
        <div class="row filters">
          <input type="search" placeholder="Filter by Name or Value" bind:value={filterText} />
          <select bind:value={filterType} aria-label="Record type">
            <option value="">All Types</option>
            {#each typesPresent as t (t)}<option value={t}>{t}</option>{/each}
          </select>
          {#if shown.length !== records.length}<span class="muted">Showing {shown.length} of {records.length}</span>{/if}
        </div>
      {/if}

      <div class="table-wrap">
        <table>
          <thead><tr><th>Name</th><th>Type</th><th>Value</th><th class="num">TTL</th><th class="num">Actions</th></tr></thead>
          <tbody>
            {#each shown as record (record.id)}
              <tr class:disabled={record.disabled}>
                <td>
                  <code title={record.name}>{relativeName(record.name)}</code>
                  {#if record.disabled}<span class="pill">Disabled</span>{/if}
                </td>
                <td>{record.rtype}</td>
                <td class="value"><code>{record.content}</code></td>
                <td class="num" title={duration(record.ttl)}>{record.ttl}</td>
                <td class="num">
                  {#if selected.zone_type !== 'secondary'}
                    <div class="row" style="gap: 6px; justify-content: flex-end; flex-wrap: nowrap">
                      <button class="secondary" onclick={() => startEdit(record)}>Edit</button>
                      <button
                        class="secondary"
                        onclick={() => toggleDisabled(record)}
                        title={record.disabled ? 'Serve this record again' : 'Stop serving this record but keep it'}
                      >{record.disabled ? 'Enable' : 'Disable'}</button>
                      <button class="danger" onclick={() => removeRecord(record)} aria-label="Delete record">✕</button>
                    </div>
                  {:else}
                    <span class="muted">Read-Only</span>
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
        <p class="muted">No records yet. Add one with the Add Record button.</p>
      {:else if shown.length === 0}
        <p class="muted">No records match this filter.</p>
      {/if}
      <p class="muted help">
        Names are shown relative to the zone; <code>@</code> is the zone itself.
        Every change is applied live and increments the zone's serial.
      </p>
    </div>
  {/if}
{/if}

{#if edit}
  <div class="modal-backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && closeEdit()}>
    <form
      class="modal card"
      role="dialog"
      aria-modal="true"
      aria-labelledby="record-title"
      onsubmit={(e) => { e.preventDefault(); saveEdit(); }}
    >
      <div class="spread modal-title">
        <h3 id="record-title" style="margin: 0">{edit.isNew ? `Add Record - ${selected.name}` : `Edit Record - ${selected.name}`}</h3>
        <button type="button" class="secondary" style="padding: 2px 10px" onclick={closeEdit} aria-label="Close">✕</button>
      </div>
      {#if dialogError}<p class="dialog-error">{dialogError}</p>{/if}
      <div class="grid2">
        <label>Name <input placeholder="www, or @ for {selected.name}" bind:value={edit.name} /></label>
        <label>Type<select bind:value={edit.rtype}>{#each TYPES as t (t)}<option value={t}>{t}</option>{/each}</select></label>
      </div>
      <label class="full">Value <input placeholder={EXAMPLES[edit.rtype]} bind:value={edit.content} /></label>
      <p class="muted help value-help">
        Format: <code>{EXAMPLES[edit.rtype]}</code>{#if edit.rtype === 'MX' || edit.rtype === 'SRV'} (the priority is the first number){/if}.
        {#if edit.rtype === 'ALIAS'}
          Like a CNAME, but allowed at the zone's own name (<code>@</code>) and
          next to its other records: A and AAAA questions are answered with the
          target's current addresses. The name cannot also have A, AAAA or
          CNAME records, and a DNSSEC-signed zone cannot have ALIAS records.
        {/if}
        End a host name with a dot when it is a full name.
      </p>
      <div class="grid2" style="margin-top: 10px">
        <label>TTL (Seconds) <span class="hint">{duration(Number(edit.ttl) || 0)}</span><input type="number" min="0" bind:value={edit.ttl} /></label>
      </div>
      <div class="row actions">
        <button type="submit" disabled={saving || !edit.content.trim()}>{saving ? 'Saving…' : edit.isNew ? 'Add Record' : 'Save Record'}</button>
        <button type="button" class="secondary" onclick={closeEdit} disabled={saving}>Cancel</button>
      </div>
    </form>
  </div>
{/if}

<style>
  .value-help { margin-top: 8px; }
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
  .notice.ok { border-color: var(--ok); }
  .notice.error { border-color: var(--danger); color: var(--danger); }
  .dialog-error { color: var(--danger); margin: 0 0 10px; }
  .filters { gap: 8px; margin-bottom: 10px; flex-wrap: wrap; }
  .filters input { flex: 0 1 280px; min-width: 180px; }
  .value { word-break: break-all; }
  .full { margin-top: 10px; }
  .modal-backdrop { position: fixed; inset: 0; background: rgb(0 0 0 / 0.65); display: grid; place-items: center; padding: 20px; z-index: 10; }
  .modal { width: min(640px, 100%); max-height: calc(100vh - 40px); overflow: auto; }
  .modal-title { margin-bottom: 12px; }
  .actions { margin-top: 18px; padding-top: 14px; border-top: 1px solid var(--border); }
  .hint { position: absolute; right: 0; top: 0; font-size: 0.75rem; }
  label:has(.hint) { position: relative; }
  .zone-help { margin-top: -4px; }
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; color: var(--muted); }
  @media (max-width: 640px) {
    .grid2 { grid-template-columns: 1fr; }
  }
</style>

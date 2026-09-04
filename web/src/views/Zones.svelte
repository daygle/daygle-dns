<script>
  import { api } from '../api.js';

  let zones = $state([]);
  let selected = $state(null);
  let records = $state([]);
  let error = $state(null);
  let notice = $state(null);
  let showAdd = $state(false);
  let savingZone = $state(false);
  let zoneFileName = $state('');

  let newZone = $state({
    name: '',
    zone_type: 'primary',
    primary_ns: '',
    admin_mailbox: '',
    serial: 1,
    refresh: 3600,
    retry: 600,
    expire: 86400,
    minimum: 3600,
    serial_date_scheme: false,
    import_text: null,
    mastersText: '',
    refresh_secs: 3600,
  });

  let edit = $state(null);
  const TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'PTR', 'CAA'];

  async function loadZones() {
    error = null;
    try {
      zones = await api.zones();
    } catch (e) {
      error = String(e.message || e);
    }
  }

  async function selectZone(zone) {
    selected = zone;
    records = [];
    try {
      records = await api.records(zone.id);
    } catch (e) {
      error = String(e.message || e);
    }
  }

  function resetZoneForm() {
    newZone = {
      name: '',
      zone_type: 'primary',
      primary_ns: '',
      admin_mailbox: '',
      serial: 1,
      refresh: 3600,
      retry: 600,
      expire: 86400,
      minimum: 3600,
      serial_date_scheme: false,
      import_text: null,
      mastersText: '',
      refresh_secs: 3600,
    };
    zoneFileName = '';
  }

  function openAddZone() {
    notice = null;
    resetZoneForm();
    showAdd = true;
  }

  function closeAddZone() {
    if (!savingZone) showAdd = false;
  }

  async function chooseZoneFile(event) {
    const file = event.currentTarget.files?.[0];
    if (!file) return;
    zoneFileName = file.name;
    try {
      newZone.import_text = await file.text();
    } catch (e) {
      newZone.import_text = null;
      notice = `Error: ${e.message || e}`;
    }
  }

  async function createZone() {
    const name = newZone.name.trim();
    if (!name) {
      notice = 'Error: Zone name is required';
      return;
    }
    const masters = newZone.mastersText
      .split(/[\n,]+/)
      .map((value) => value.trim())
      .filter(Boolean);
    if (newZone.zone_type === 'secondary' && masters.length === 0) {
      notice = 'Error: Add at least one master server for a secondary zone';
      return;
    }
    savingZone = true;
    notice = null;
    try {
      await api.createZone({
        name,
        zone_type: newZone.zone_type,
        primary_ns: newZone.primary_ns.trim() || null,
        admin_mailbox: newZone.admin_mailbox.trim() || null,
        serial: newZone.serial_date_scheme ? null : Number(newZone.serial) || 1,
        refresh: Number(newZone.refresh) || 3600,
        retry: Number(newZone.retry) || 600,
        expire: Number(newZone.expire) || 86400,
        minimum: Number(newZone.minimum) || 3600,
        serial_date_scheme: newZone.serial_date_scheme,
        import_text: newZone.import_text,
        masters,
        refresh_secs: Number(newZone.refresh_secs) || 3600,
      });
      showAdd = false;
      resetZoneForm();
      notice = 'Zone created successfully';
      await loadZones();
    } catch (e) {
      notice = `Error: ${e.message || e}`;
    } finally {
      savingZone = false;
    }
  }

  async function removeZone(zone) {
    if (!confirm(`Delete zone ${zone.name} and all its records?`)) return;
    try {
      await api.deleteZone(zone.id);
      selected = null;
      records = [];
      await loadZones();
    } catch (e) {
      notice = `Error: ${e.message || e}`;
    }
  }

  function startEdit(record) {
    edit = record
      ? { ...record, isNew: false }
      : { name: '', rtype: 'A', content: '', ttl: 3600, priority: 0, isNew: true };
  }

  async function saveEdit() {
    if (!edit) return;
    try {
      await api.upsertRecord(selected.id, {
        name: edit.name,
        rtype: edit.rtype,
        content: edit.content,
        ttl: Number(edit.ttl) || 3600,
        priority: Number(edit.priority) || 0,
      });
      edit = null;
      records = await api.records(selected.id);
    } catch (e) {
      notice = `Error: ${e.message || e}`;
    }
  }

  async function removeRecord(record) {
    try {
      await api.deleteRecord(selected.id, record.id);
      records = await api.records(selected.id);
    } catch (e) {
      notice = `Error: ${e.message || e}`;
    }
  }

  async function toggleSign() {
    if (!selected) return;
    try {
      if (selected.dnssec) await api.unsignZone(selected.id);
      else await api.signZone(selected.id);
      await loadZones();
      const refreshed = zones.find((z) => z.id === selected.id);
      if (refreshed) selected = refreshed;
    } catch (e) {
      notice = `Error: ${e.message || e}`;
    }
  }

  $effect(() => { loadZones(); });
</script>

<h1>Zones &amp; records</h1>

{#if notice}
  <div class="card notice" class:error={notice.startsWith('Error:')}>{notice}</div>
{/if}
{#if error}
  <div class="card notice error">{error}</div>
{/if}

<div class="split">
  <div class="card">
    <div class="spread" style="margin-bottom: 10px">
      <strong>Zones ({zones.length})</strong>
      <button onclick={openAddZone}>+ Add zone</button>
    </div>

    <table>
      <thead>
        <tr><th>Name</th><th>Type</th><th>DNSSEC</th><th>Serial</th><th></th></tr>
      </thead>
      <tbody>
        {#each zones as zone (zone.id)}
          <tr
            style="cursor:pointer"
            class:active={selected?.id === zone.id}
            onclick={() => selectZone(zone)}
          >
            <td><code>{zone.name}</code></td>
            <td><span class="pill">{zone.zone_type || 'primary'}</span></td>
            <td><span class:pill={true} class:ok={zone.dnssec}>{zone.dnssec ? 'signed' : 'unsigned'}</span></td>
            <td>{zone.serial}</td>
            <td>
              <button class="danger" onclick={(e) => { e.stopPropagation(); removeZone(zone); }}>✕</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if zones.length === 0}
      <p class="muted">No zones yet. Add a primary or secondary zone to get started.</p>
    {/if}
  </div>

  <div class="card">
    {#if !selected}
      <p class="muted">Select a zone to manage its records.</p>
    {:else}
      <div class="spread" style="margin-bottom: 12px">
        <strong>Records for <code>{selected.name}</code></strong>
        <div class="row">
          {#if selected.zone_type !== 'secondary'}
            <button class="secondary" onclick={toggleSign}>{selected.dnssec ? 'Unsign' : 'Sign (DNSSEC)'}</button>
            <button onclick={() => startEdit(null)}>+ Record</button>
          {/if}
        </div>
      </div>

      {#if selected.zone_type === 'secondary'}
        <p class="muted zone-help">This is a read-only secondary zone. It is refreshed from: {selected.masters?.join(', ') || 'configured masters'}.</p>
      {/if}
      <table>
        <thead><tr><th>Name</th><th>Type</th><th>Value</th><th>TTL</th><th></th></tr></thead>
        <tbody>
          {#each records as record (record.id)}
            <tr>
              <td><code>{record.name}</code></td>
              <td>{record.rtype}</td>
              <td><code>{record.content}</code></td>
              <td>{record.ttl}</td>
              <td>
                {#if selected.zone_type !== 'secondary'}
                  <div class="row">
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

      {#if edit}
        <div class="card" style="margin-top: 14px; background: var(--panel-2)">
          <h4 style="margin-top: 0">{edit.isNew ? 'New record' : 'Edit record'}</h4>
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
    {/if}
  </div>
</div>

{#if showAdd}
  <div class="modal-backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && closeAddZone()}>
    <div class="modal card" role="dialog" aria-modal="true" aria-labelledby="add-zone-title">
      <div class="spread modal-title">
        <h2 id="add-zone-title">Add zone</h2>
        <button class="secondary" onclick={closeAddZone} aria-label="Close">✕</button>
      </div>

      <div class="grid2">
        <label>Zone name <input placeholder="example.com" bind:value={newZone.name} /></label>
        <label>Zone type
          <select bind:value={newZone.zone_type}>
            <option value="primary">Primary zone</option>
            <option value="secondary">Secondary zone</option>
          </select>
        </label>
      </div>

      <div class="section-title">SOA settings</div>
      <div class="grid2">
        <label>Primary nameserver <input placeholder="ns1.example.com." bind:value={newZone.primary_ns} /></label>
        <label>Administrator mailbox <input placeholder="admin.example.com." bind:value={newZone.admin_mailbox} /></label>
        <label>Serial <input type="number" min="1" bind:value={newZone.serial} disabled={newZone.serial_date_scheme} /></label>
        <label class="checkbox"><span>Use SOA serial date scheme</span><input type="checkbox" bind:checked={newZone.serial_date_scheme} /></label>
        <label>Refresh (seconds) <input type="number" min="1" bind:value={newZone.refresh} /></label>
        <label>Retry (seconds) <input type="number" min="1" bind:value={newZone.retry} /></label>
        <label>Expire (seconds) <input type="number" min="1" bind:value={newZone.expire} /></label>
        <label>Minimum TTL (seconds) <input type="number" min="1" bind:value={newZone.minimum} /></label>
      </div>

      {#if newZone.zone_type === 'secondary'}
        <div class="section-title">Secondary masters</div>
        <label>Master servers <textarea rows="3" placeholder="192.0.2.10&#10;192.0.2.11:5353" bind:value={newZone.mastersText}></textarea></label>
        <label>Refresh interval (seconds) <input type="number" min="1" bind:value={newZone.refresh_secs} /></label>
        <p class="muted help">The first reachable master is used for AXFR/IXFR. Secondary records are read-only and refresh automatically.</p>
      {:else}
        <div class="section-title">Import (optional)</div>
        <label>Import zone file
          <input type="file" accept=".zone,.db,.txt,text/plain" onchange={chooseZoneFile} />
        </label>
        {#if zoneFileName}<p class="muted help">Selected: {zoneFileName}. SOA values found in the file will be used unless you override them above.</p>{/if}
      {/if}

      <div class="row actions">
        <button onclick={createZone} disabled={savingZone || !newZone.name.trim()}>{savingZone ? 'Creating…' : 'Create zone'}</button>
        <button class="secondary" onclick={closeAddZone} disabled={savingZone}>Cancel</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .split { display: grid; grid-template-columns: 360px 1fr; gap: 16px; align-items: start; }
  @media (max-width: 900px) { .split { grid-template-columns: 1fr; } }
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; color: var(--muted); }
  textarea { font: inherit; color: inherit; background: var(--panel-2); border: 1px solid var(--border); border-radius: 6px; padding: 6px 8px; resize: vertical; }
  tr.active { background: var(--panel-2); }
  .notice { margin-bottom: 14px; }
  .notice.error { border-color: var(--danger); color: var(--danger); }
  .zone-help { margin-top: -4px; }
  .modal-backdrop { position: fixed; inset: 0; background: rgb(0 0 0 / 0.65); display: grid; place-items: center; padding: 20px; z-index: 10; }
  .modal { width: min(760px, 100%); max-height: calc(100vh - 40px); overflow: auto; }
  .modal-title { margin-bottom: 18px; }
  .modal-title h2 { margin: 0; }
  .section-title { color: var(--text); font-weight: 600; margin: 20px 0 10px; padding-top: 14px; border-top: 1px solid var(--border); }
  .checkbox { flex-direction: row; align-items: center; justify-content: space-between; padding-top: 22px; }
  .checkbox input { width: auto; }
  .help { font-size: 0.8rem; margin: 6px 0 0; }
  .actions { margin-top: 22px; padding-top: 14px; border-top: 1px solid var(--border); }
</style>

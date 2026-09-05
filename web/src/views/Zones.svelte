<script>
  import { api, formatApiError } from '../api.js';

  let { onOpenRecords = () => {} } = $props();

  let zones = $state([]);
  let error = $state(null);
  let notice = $state(null);
  let showAdd = $state(false);
  let savingZone = $state(false);
  let zoneFileName = $state('');

  // In-progress SOA editor for an existing primary zone, or null when closed.
  let soaEdit = $state(null);
  let savingSoa = $state(false);

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

  async function loadZones() {
    error = null;
    try {
      zones = await api.zones();
    } catch (e) {
      error = formatApiError(e);
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

  function openSoa(zone) {
    notice = null;
    soaEdit = {
      zone,
      primary_ns: zone.primary_ns || '',
      admin_mailbox: zone.admin_mailbox || '',
      serial: zone.serial,
      refresh: zone.refresh,
      retry: zone.retry,
      expire: zone.expire,
      minimum: zone.minimum,
      bumpSerial: true,
    };
  }

  function closeSoa() {
    if (!savingSoa) soaEdit = null;
  }

  async function saveSoa() {
    if (!soaEdit) return;
    const form = soaEdit;
    savingSoa = true;
    notice = null;
    try {
      const body = {
        primary_ns: form.primary_ns.trim(),
        admin_mailbox: form.admin_mailbox.trim(),
        refresh: Number(form.refresh) || form.refresh,
        retry: Number(form.retry) || form.retry,
        expire: Number(form.expire) || form.expire,
        minimum: Number(form.minimum) || form.minimum,
        bump_serial: form.bumpSerial,
      };
      if (!form.bumpSerial) body.serial = Number(form.serial) || form.serial;
      await api.updateZoneSoa(form.zone.id, body);
      soaEdit = null;
      notice = 'SOA settings saved and applied live.';
      await loadZones();
    } catch (e) {
      notice = formatApiError(e);
    } finally {
      savingSoa = false;
    }
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
      notice = formatApiError(e);
    } finally {
      savingZone = false;
    }
  }

  async function removeZone(zone) {
    if (!confirm(`Delete zone ${zone.name} and all its records?`)) return;
    notice = null;
    try {
      await api.deleteZone(zone.id);
      await loadZones();
    } catch (e) {
      notice = formatApiError(e);
    }
  }

  async function toggleSign(zone) {
    notice = null;
    try {
      if (zone.dnssec) await api.unsignZone(zone.id);
      else await api.signZone(zone.id);
      await loadZones();
    } catch (e) {
      notice = formatApiError(e);
    }
  }

  $effect(() => { loadZones(); });
</script>

<h1>Zones</h1>
<p class="muted" style="max-width: 75ch">
  Host authoritative zones backed by SQLite. Add a primary zone to serve
  records directly, or a secondary zone replicated from a master via AXFR/IXFR.
  Manage a zone's DNS records from the Records page.
</p>

{#if notice}
  <div class="card notice" class:error={notice.startsWith('Error:')}>{notice}</div>
{/if}
{#if error}
  <div class="card notice error">{error}</div>
{/if}

<div class="row" style="margin-bottom: 14px">
  <button onclick={openAddZone}>+ Add Zone</button>
  <span class="muted">{zones.length} zone{zones.length === 1 ? '' : 's'}</span>
</div>

<div class="card" style="padding: 0; overflow: auto">
  <div class="table-wrap">
    <table>
      <thead>
        <tr><th>Name</th><th>Type</th><th>DNSSEC</th><th>Serial</th><th class="num">Actions</th></tr>
      </thead>
      <tbody>
        {#each zones as zone (zone.id)}
          <tr>
            <td><code>{zone.name}</code></td>
            <td><span class="pill">{zone.zone_type === 'secondary' ? 'Secondary' : 'Primary'}</span></td>
            <td><span class:pill={true} class:ok={zone.dnssec}>{zone.dnssec ? 'Signed' : 'Unsigned'}</span></td>
            <td>{zone.serial}</td>
            <td class="num">
              <div class="row" style="gap: 6px; justify-content: flex-end">
                <button class="secondary" onclick={() => onOpenRecords(zone.id)}>Records</button>
                {#if zone.zone_type !== 'secondary'}
                  <button class="secondary" onclick={() => openSoa(zone)}>SOA</button>
                  <button class="secondary" onclick={() => toggleSign(zone)}>{zone.dnssec ? 'Unsign' : 'Sign'}</button>
                {/if}
                <button class="danger" onclick={() => removeZone(zone)}>✕</button>
              </div>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
  {#if zones.length === 0}
    <p class="muted" style="padding: 14px">No zones yet. Add a primary or secondary zone to get started.</p>
  {/if}
</div>

{#if showAdd}
  <div class="modal-backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && closeAddZone()}>
    <div class="modal card" role="dialog" aria-modal="true" aria-labelledby="add-zone-title">
      <div class="spread modal-title">
        <h2 id="add-zone-title">Add Zone</h2>
        <button class="secondary" onclick={closeAddZone} aria-label="Close">✕</button>
      </div>

      <div class="grid2">
        <label>Zone Name <input placeholder="example.com" bind:value={newZone.name} /></label>
        <label>Zone Type
          <select bind:value={newZone.zone_type}>
            <option value="primary">Primary Zone</option>
            <option value="secondary">Secondary Zone</option>
          </select>
        </label>
      </div>

      <div class="section-title">SOA Settings</div>
      <div class="grid2">
        <label>Primary Nameserver <input placeholder="ns1.example.com." bind:value={newZone.primary_ns} /></label>
        <label>Administrator Mailbox <input placeholder="admin.example.com." bind:value={newZone.admin_mailbox} /></label>
        <label>Serial <input type="number" min="1" bind:value={newZone.serial} disabled={newZone.serial_date_scheme} /></label>
        <label class="checkbox"><span>Use SOA Serial Date Scheme</span><input type="checkbox" bind:checked={newZone.serial_date_scheme} /></label>
        <label>Refresh (Seconds) <input type="number" min="1" bind:value={newZone.refresh} /></label>
        <label>Retry (Seconds) <input type="number" min="1" bind:value={newZone.retry} /></label>
        <label>Expire (Seconds) <input type="number" min="1" bind:value={newZone.expire} /></label>
        <label>Minimum TTL (Seconds) <input type="number" min="1" bind:value={newZone.minimum} /></label>
      </div>

      {#if newZone.zone_type === 'secondary'}
        <div class="section-title">Secondary Masters</div>
        <label>Master Servers <textarea rows="3" placeholder="192.0.2.10&#10;192.0.2.11:5353" bind:value={newZone.mastersText}></textarea></label>
        <label>Refresh Interval (Seconds) <input type="number" min="1" bind:value={newZone.refresh_secs} /></label>
        <p class="muted help">The first reachable master is used for AXFR/IXFR. Secondary records are read-only and refresh automatically.</p>
      {:else}
        <div class="section-title">Import (Optional)</div>
        <label>Import Zone File
          <input type="file" accept=".zone,.db,.txt,text/plain" onchange={chooseZoneFile} />
        </label>
        {#if zoneFileName}<p class="muted help">Selected: {zoneFileName}. SOA values found in the file will be used unless you override them above.</p>{/if}
      {/if}

      <div class="row actions">
        <button onclick={createZone} disabled={savingZone || !newZone.name.trim()}>{savingZone ? 'Creating…' : 'Create Zone'}</button>
        <button class="secondary" onclick={closeAddZone} disabled={savingZone}>Cancel</button>
      </div>
    </div>
  </div>
{/if}

{#if soaEdit}
  <div class="modal-backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && closeSoa()}>
    <div class="modal card" role="dialog" aria-modal="true" aria-labelledby="edit-soa-title">
      <div class="spread modal-title">
        <h2 id="edit-soa-title">Edit SOA - {soaEdit.zone.name}</h2>
        <button class="secondary" onclick={closeSoa} aria-label="Close">✕</button>
      </div>

      <div class="section-title">SOA Parameters</div>
      <div class="grid2">
        <label>Primary Nameserver <input placeholder="ns1.example.com." bind:value={soaEdit.primary_ns} /></label>
        <label>Administrator Mailbox <input placeholder="admin.example.com." bind:value={soaEdit.admin_mailbox} /></label>
        <label>Serial <input type="number" min="1" bind:value={soaEdit.serial} disabled={soaEdit.bumpSerial} /></label>
        <label class="checkbox"><span>Increment Serial on Save</span><input type="checkbox" bind:checked={soaEdit.bumpSerial} /></label>
        <label>Refresh (Seconds) <input type="number" min="1" bind:value={soaEdit.refresh} /></label>
        <label>Retry (Seconds) <input type="number" min="1" bind:value={soaEdit.retry} /></label>
        <label>Expire (Seconds) <input type="number" min="1" bind:value={soaEdit.expire} /></label>
        <label>Minimum TTL (Seconds) <input type="number" min="1" bind:value={soaEdit.minimum} /></label>
      </div>
      {#if soaEdit.bumpSerial}
        <p class="muted help">The serial is incremented automatically so downstream secondaries and transfers pick up the change.</p>
      {:else}
        <p class="muted help">Serial is set exactly to the value above. Prefer automatic increments unless you know the zone's history.</p>
      {/if}

      <div class="row actions">
        <button onclick={saveSoa} disabled={savingSoa}>{savingSoa ? 'Saving…' : 'Save SOA'}</button>
        <button class="secondary" onclick={closeSoa} disabled={savingSoa}>Cancel</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .table-wrap { overflow-x: auto; }
  .table-wrap th, .table-wrap td { padding: 8px 6px; font-size: 0.85rem; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; border-bottom: 1px solid var(--border); vertical-align: middle; }
  th { font-size: 0.78rem; color: var(--muted); font-weight: 600; }
  .num { text-align: right; white-space: nowrap; }
  td.num button { padding: 4px 9px; }
  .notice { margin-bottom: 14px; }
  .notice.error { border-color: var(--danger); color: var(--danger); }
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; color: var(--muted); }
  textarea { font: inherit; color: inherit; background: var(--panel-2); border: 1px solid var(--border); border-radius: 6px; padding: 6px 8px; resize: vertical; }
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

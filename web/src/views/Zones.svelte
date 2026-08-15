<script>
  import { api } from '../api.js';

  let zones = $state([]);
  let selected = $state(null);
  let records = $state([]);
  let error = $state(null);
  let notice = $state(null);

  // create-zone form
  let newZone = $state('');
  // record editor form
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

  async function createZone() {
    if (!newZone.trim()) return;
    notice = null;
    try {
      await api.createZone({ name: newZone.trim() });
      newZone = '';
      await loadZones();
    } catch (e) {
      notice = `Error: ${e.message || e}`;
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
  <div class="card" style="border-color: var(--danger); color: var(--danger)">{notice}</div>
{/if}

<div class="split">
  <div class="card">
    <div class="spread" style="margin-bottom: 10px">
      <strong>Zones ({zones.length})</strong>
    </div>
    <div class="row" style="margin-bottom: 12px">
      <input
        placeholder="example.com"
        bind:value={newZone}
        onkeydown={(e) => e.key === 'Enter' && createZone()}
      />
      <button onclick={createZone} disabled={!newZone.trim()}>Add zone</button>
    </div>

    <table>
      <thead>
        <tr><th>Name</th><th>DNSSEC</th><th>Serial</th></tr>
      </thead>
      <tbody>
        {#each zones as zone (zone.id)}
          <tr
            style="cursor:pointer"
            class:active={selected?.id === zone.id}
            onclick={() => selectZone(zone)}
          >
            <td><code>{zone.name}</code></td>
            <td><span class:pill={true} class:ok={zone.dnssec}>{zone.dnssec ? 'signed' : 'unsigned'}</span></td>
            <td>{zone.serial}</td>
            <td>
              <button class="danger" onclick={(e) => { e.stopPropagation(); removeZone(zone); }}>
                ✕
              </button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if zones.length === 0}
      <p class="muted">No zones yet. Add one above or import a zone file.</p>
    {/if}
  </div>

  <div class="card">
    {#if !selected}
      <p class="muted">Select a zone to manage its records.</p>
    {:else}
      <div class="spread" style="margin-bottom: 12px">
        <strong>Records for <code>{selected.name}</code></strong>
        <div class="row">
          <button class="secondary" onclick={toggleSign}>
            {selected.dnssec ? 'Unsign' : 'Sign (DNSSEC)'}
          </button>
          <button onclick={() => startEdit(null)}>+ Record</button>
        </div>
      </div>

      <table>
        <thead>
          <tr><th>Name</th><th>Type</th><th>Value</th><th>TTL</th><th></th></tr>
        </thead>
        <tbody>
          {#each records as record (record.id)}
            <tr>
              <td><code>{record.name}</code></td>
              <td>{record.rtype}</td>
              <td><code>{record.content}</code></td>
              <td>{record.ttl}</td>
              <td>
                <div class="row">
                  <button class="secondary" onclick={() => startEdit(record)}>Edit</button>
                  <button class="danger" onclick={() => removeRecord(record)}>✕</button>
                </div>
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
            <label>Type
              <select bind:value={edit.rtype}>
                {#each TYPES as t (t)}<option value={t}>{t}</option>{/each}
              </select>
            </label>
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

<style>
  .split {
    display: grid;
    grid-template-columns: 360px 1fr;
    gap: 16px;
    align-items: start;
  }
  @media (max-width: 900px) { .split { grid-template-columns: 1fr; } }
  .grid2 {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
  }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; color: var(--muted); }
  tr.active { background: var(--panel-2); }
</style>

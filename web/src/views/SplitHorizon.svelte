<script>
  import { api, formatApiError } from '../api.js';
  import { duration } from '../aiLabels.js';
  import { formatDateTime } from '../datetime.svelte.js';
  import NetworkPicker from '../NetworkPicker.svelte';

  // Opens Settings on a tab (absent for read-only accounts).
  let { onOpenSettings = null } = $props();

  let networks = $state([]);
  let entries = $state([]);
  // `error` shows in red, `notice` (success) in green; failures while the
  // entry dialog is open show inside it.
  let error = $state(null);
  let notice = $state(null);
  let dialogError = $state(null);
  let saving = $state(false);

  // Entry dialog, or null when closed.
  let edit = $state(null);

  const RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'SRV'];
  const PLACEHOLDERS = {
    A: '10.0.0.5',
    AAAA: 'fd00::5',
    MX: '10 mail.example.com.',
    TXT: 'hello world',
    CNAME: 'target.example.com.',
    SRV: '0 5 5060 sip.example.com.',
  };

  async function load() {
    try {
      const data = await api.splitHorizon();
      networks = data.networks;
      entries = data.entries;
    } catch (e) {
      error = formatApiError(e);
    }
  }

  function clearMessages() {
    notice = null;
    error = null;
  }

  // An entry's networks are named networks (ticked in the dialog) plus any
  // literal CIDRs (typed).
  function startEdit(entry) {
    clearMessages();
    dialogError = null;
    edit = entry
      ? {
          id: entry.id,
          domain: entry.domain,
          networks: [...entry.networks],
          // The store keeps ips and records in sync; fall back to deriving
          // A/AAAA records for legacy entries that only carry ips.
          records: (entry.records.length
            ? entry.records
            : entry.ips.map((ip) => ({
                rtype: ip.includes(':') ? 'AAAA' : 'A',
                content: ip,
              }))
          ).map((r) => ({ rtype: r.rtype, content: r.content })),
          ttl: entry.ttl,
          disabled: entry.disabled,
          isNew: false,
        }
      : {
          id: null,
          domain: '',
          networks: [],
          records: [{ rtype: 'A', content: '' }],
          ttl: 60,
          disabled: false,
          isNew: true,
        };
  }

  function closeEdit() {
    if (!saving) edit = null;
  }

  function addRecord() {
    edit.records = [...edit.records, { rtype: 'A', content: '' }];
  }

  function removeRecordAt(i) {
    edit.records = edit.records.filter((_, idx) => idx !== i);
  }

  async function saveEntry() {
    if (!edit) return;
    const body = {
      domain: edit.domain.trim(),
      networks: edit.networks,
      records: edit.records
        .filter((r) => r.rtype && r.content.trim())
        .map((r) => ({ rtype: r.rtype, content: r.content.trim() })),
      ttl: Number(edit.ttl) || 60,
      disabled: edit.disabled,
    };
    saving = true;
    dialogError = null;
    try {
      if (edit.isNew) await api.createSplitHorizonEntry(body);
      else await api.updateSplitHorizonEntry(edit.id, body);
      notice = edit.isNew ? `Entry for ${body.domain} added and applied live.` : `Entry for ${body.domain} saved and applied live.`;
      edit = null;
      await load();
    } catch (e) {
      dialogError = formatApiError(e);
    } finally {
      saving = false;
    }
  }

  async function removeEntry(entry) {
    if (!confirm(`Delete this entry for ${entry.domain}?`)) return;
    clearMessages();
    try {
      await api.deleteSplitHorizonEntry(entry.id);
      notice = `Entry for ${entry.domain} deleted.`;
      await load();
    } catch (e) {
      error = formatApiError(e);
    }
  }

  async function moveEntry(entry, direction) {
    clearMessages();
    try {
      await api.moveSplitHorizonEntry(entry.id, direction);
      await load();
    } catch (e) {
      error = formatApiError(e);
    }
  }

  // Entries arrive ordered by (domain, position); a button is only usable
  // when a same-domain neighbour exists on that side.
  function indexOf(entry) {
    return entries.findIndex((e) => e.id === entry.id);
  }
  function canMoveUp(entry) {
    const i = indexOf(entry);
    return i > 0 && entries[i - 1].domain === entry.domain;
  }
  function canMoveDown(entry) {
    const i = indexOf(entry);
    return i >= 0 && i < entries.length - 1 && entries[i + 1].domain === entry.domain;
  }

  $effect(() => {
    load();
  });
</script>

{#if notice}
  <div class="card" style="border-color: var(--ok); margin-bottom: 14px">{notice}</div>
{/if}
{#if error}
  <div class="card" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">{error}</div>
{/if}

<div class="split">
  <div class="card">
    <div class="spread" style="margin-bottom: 10px">
      <h3 style="margin: 0">Domain Entries ({entries.length})</h3>
      <div class="row" style="gap: 8px">
        {#if onOpenSettings}
          <button class="secondary" onclick={() => onOpenSettings('networks')}>Manage Networks</button>
        {/if}
        <button onclick={() => startEdit(null)}>Add Entry</button>
      </div>
    </div>
    <p class="muted help" style="margin: 0 0 10px">
      Each entry answers the clients in the networks it names. Networks such
      as LAN or VPN are set up once in Settings → Networks and shared with the
      other settings that take client networks.
    </p>
    {#if entries.length === 0}
      <p class="muted">
        No entries yet. Add one with a domain, the networks that get the
        special answer, and the answer to return.
      </p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Domain</th>
              <th>Networks</th>
              <th>Answers</th>
              <th class="num">TTL</th>
              <th>Status</th>
              <th>Last Used</th>
              <th>Last Modified</th>
              <th class="num">Actions</th>
            </tr>
          </thead>
          <tbody>
            {#each entries as entry (entry.id)}
              <tr class:disabled={entry.disabled}>
                <td><code>{entry.domain}</code></td>
                <td>
                  {#if entry.networks.length === 0}
                    <span class="muted">All Clients</span>
                  {:else}
                    <div class="row" style="gap: 6px">
                      {#each entry.networks as n (n)}
                        <span class="pill">{n}</span>
                      {/each}
                    </div>
                  {/if}
                </td>
                <td>
                  <div class="answers">
                    {#each entry.records as r (r.rtype + r.content)}
                      <div><span class="pill">{r.rtype}</span> <code>{r.content}</code></div>
                    {/each}
                  </div>
                </td>
                <td class="num" title={duration(entry.ttl)}>{entry.ttl}</td>
                <td>
                  <span class="pill" class:ok={!entry.disabled}>
                    {entry.disabled ? 'Disabled' : 'Active'}
                  </span>
                </td>
                <td class="muted" title={entry.last_used_at || ''}>
                  {entry.last_used_at ? formatDateTime(entry.last_used_at) : 'Never'}
                </td>
                <td class="muted" title={entry.last_modified_at || ''}>
                  {entry.last_modified_at ? formatDateTime(entry.last_modified_at) : '-'}
                </td>
                <td class="num">
                  <div class="row" style="gap: 6px; justify-content: flex-end; flex-wrap: nowrap">
                    <button
                      class="secondary"
                      title="Move up (checked earlier)"
                      aria-label="Move up"
                      onclick={() => moveEntry(entry, 'up')}
                      disabled={!canMoveUp(entry)}
                    >↑</button>
                    <button
                      class="secondary"
                      title="Move down (checked later)"
                      aria-label="Move down"
                      onclick={() => moveEntry(entry, 'down')}
                      disabled={!canMoveDown(entry)}
                    >↓</button>
                    <button class="secondary" onclick={() => startEdit(entry)}>Edit</button>
                    <button class="danger" onclick={() => removeEntry(entry)} aria-label="Delete entry">✕</button>
                  </div>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
    <p class="muted help">
      For each query, entries for the domain are checked top to bottom and the
      first whose networks contain the client answers. Put the internal views
      first and the public fallback (no networks, so every client) last; ↑/↓
      reorder entries of the same domain. An entry answers queries of the types
      it lists, and a CNAME answers every type.
    </p>
  </div>
</div>

{#if edit}
  <div class="modal-backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && closeEdit()}>
    <form
      class="modal card"
      role="dialog"
      aria-modal="true"
      aria-labelledby="entry-title"
      onsubmit={(e) => { e.preventDefault(); saveEntry(); }}
    >
      <div class="spread modal-title">
        <h3 id="entry-title" style="margin: 0">{edit.isNew ? 'Add Entry' : `Edit Entry - ${edit.domain}`}</h3>
        <button type="button" class="secondary" style="padding: 2px 10px" onclick={closeEdit} aria-label="Close">✕</button>
      </div>
      {#if dialogError}<p class="dialog-error">{dialogError}</p>{/if}
      <div class="grid2">
        <label>Domain <input placeholder="intranet.example.com" bind:value={edit.domain} /></label>
        <label>TTL (Seconds) <span class="hint">{duration(Number(edit.ttl) || 0)}</span><input type="number" min="0" bind:value={edit.ttl} /></label>
      </div>

      <div class="section-title">Clients</div>
      <NetworkPicker {networks} bind:value={edit.networks} />
      <p class="muted help">
        {#if edit.networks.length === 0}
          No networks chosen: this entry answers <strong>every client</strong> (a public fallback).
        {:else}
          Only clients in the chosen networks get this answer.
        {/if}
      </p>

      <div class="section-title">Answers</div>
      {#each edit.records as rec, i (i)}
        <div class="row" style="gap: 6px; margin-top: 6px; flex-wrap: nowrap">
          <select bind:value={rec.rtype} style="width: 110px" aria-label="Answer type">
            {#each RECORD_TYPES as t (t)}
              <option value={t}>{t}</option>
            {/each}
          </select>
          <input placeholder={PLACEHOLDERS[rec.rtype]} bind:value={rec.content} style="flex: 1" aria-label="Answer value" />
          <button type="button" class="danger" onclick={() => removeRecordAt(i)} aria-label="Remove answer" disabled={edit.records.length === 1}>✕</button>
        </div>
      {/each}
      <div><button type="button" class="secondary" onclick={addRecord} style="margin-top: 8px">Add Answer</button></div>
      <p class="muted help">One answer per type; a CNAME answers every type.</p>

      <label class="checkbox">
        <input type="checkbox" bind:checked={edit.disabled} />
        <span>Disabled (Keep for Later)</span>
      </label>
      <div class="row actions">
        <button
          type="submit"
          disabled={saving || !edit.domain.trim() || edit.records.filter((r) => r.rtype && r.content.trim()).length === 0}
        >
          {saving ? 'Saving...' : edit.isNew ? 'Add Entry' : 'Save Entry'}
        </button>
        <button type="button" class="secondary" onclick={closeEdit} disabled={saving}>Cancel</button>
      </div>
    </form>
  </div>
{/if}

<style>
  .split {
    display: grid;
    grid-template-columns: 1fr;
    gap: 16px;
    align-items: start;
  }
  .grid2 {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
  }
  label {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 0.85rem;
    color: var(--muted);
  }
  .help { max-width: 90ch; }
  .answers { display: flex; flex-direction: column; gap: 4px; }
  .checkbox { flex-direction: row; align-items: center; gap: 8px; margin-top: 12px; }
  .checkbox input { width: auto; }
  .checkbox span { color: var(--text); }
  .modal-backdrop { position: fixed; inset: 0; background: rgb(0 0 0 / 0.65); display: grid; place-items: center; padding: 20px; z-index: 10; }
  .modal { width: min(640px, 100%); max-height: calc(100vh - 40px); overflow: auto; }
  .modal-title { margin-bottom: 12px; }
  .section-title {
    margin: 14px 0 8px;
    padding-top: 12px;
    border-top: 1px solid var(--border);
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
  }
  .actions { margin-top: 18px; padding-top: 14px; border-top: 1px solid var(--border); }
  .dialog-error { color: var(--danger); margin: 0 0 10px; }
  .hint { position: absolute; right: 0; top: 0; font-size: 0.75rem; }
  label:has(.hint) { position: relative; }
  @media (max-width: 640px) {
    .grid2 { grid-template-columns: 1fr; }
  }
</style>

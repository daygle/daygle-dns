<script>
  import { api } from '../api.js';

  let networks = $state([]);
  let entries = $state([]);
  let error = $state(null);
  let notice = $state(null);

  // network form
  let netName = $state('');
  let netCidrs = $state('');
  // entry form
  let edit = $state(null);

  async function load() {
    error = null;
    try {
      const data = await api.splitHorizon();
      networks = data.networks;
      entries = data.entries;
    } catch (e) {
      error = String(e.message || e);
    }
  }

  function parseList(text) {
    return text
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
  }

  async function saveNetwork() {
    if (!netName.trim()) return;
    notice = null;
    try {
      await api.saveSplitHorizonNetwork({
        name: netName.trim(),
        cidrs: parseList(netCidrs),
      });
      netName = '';
      netCidrs = '';
      await load();
    } catch (e) {
      notice = `Error: ${e.message || e}`;
    }
  }

  async function removeNetwork(network) {
    if (!confirm(`Delete network "${network.name}"? Entries referencing it will stop matching.`)) return;
    try {
      await api.deleteSplitHorizonNetwork(network.name);
      await load();
    } catch (e) {
      notice = `Error: ${e.message || e}`;
    }
  }

  function startEdit(entry) {
    edit = entry
      ? {
          id: entry.id,
          domain: entry.domain,
          networks: entry.networks.join(', '),
          ips: entry.ips.join(', '),
          ttl: entry.ttl,
          disabled: entry.disabled,
          isNew: false,
        }
      : {
          id: null,
          domain: '',
          networks: '',
          ips: '',
          ttl: 60,
          disabled: false,
          isNew: true,
        };
  }

  async function saveEntry() {
    if (!edit) return;
    const body = {
      domain: edit.domain.trim(),
      networks: parseList(edit.networks),
      ips: parseList(edit.ips),
      ttl: Number(edit.ttl) || 60,
      disabled: edit.disabled,
    };
    try {
      if (edit.isNew) await api.createSplitHorizonEntry(body);
      else await api.updateSplitHorizonEntry(edit.id, body);
      edit = null;
      await load();
    } catch (e) {
      notice = `Error: ${e.message || e}`;
    }
  }

  async function removeEntry(entry) {
    try {
      await api.deleteSplitHorizonEntry(entry.id);
      await load();
    } catch (e) {
      notice = `Error: ${e.message || e}`;
    }
  }

  $effect(() => {
    load();
  });
</script>

<h1>Split horizon</h1>
<p class="muted">
  Serve different answers for the same domain depending on the client's
  network — e.g. clients on <code>LAN</code> get
  <code>10.0.0.5</code> for <code>intranet.example.com</code> while everyone
  else gets the public address. Entries are matched in order: the first entry
  whose domain matches and whose networks contain the client wins. An entry
  with no networks matches every client, so it can act as the public
  fallback.
</p>

{#if notice}
  <div class="card" style="border-color: var(--danger); color: var(--danger)">{notice}</div>
{/if}
{#if error}
  <div class="card" style="border-color: var(--danger); color: var(--danger)">{error}</div>
{/if}

<div class="split">
  <div class="card">
    <div class="spread" style="margin-bottom: 10px">
      <strong>Networks ({networks.length})</strong>
    </div>
    <div class="row" style="margin-bottom: 12px">
      <input placeholder="LAN" bind:value={netName} style="width: 90px" />
      <input
        placeholder="192.168.20.0/24, 10.0.0.0/8"
        bind:value={netCidrs}
        style="flex: 1; min-width: 160px"
        onkeydown={(e) => e.key === 'Enter' && saveNetwork()}
      />
      <button onclick={saveNetwork} disabled={!netName.trim()}>Add</button>
    </div>
    <table>
      <thead>
        <tr><th>Name</th><th>CIDRs</th><th></th></tr>
      </thead>
      <tbody>
        {#each networks as network (network.id)}
          <tr>
            <td><code>{network.name}</code></td>
            <td>
              <div class="row" style="gap: 6px">
                {#each network.cidrs as c (c)}
                  <span class="pill">{c}</span>
                {/each}
              </div>
            </td>
            <td>
              <button class="danger" onclick={() => removeNetwork(network)}>✕</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if networks.length === 0}
      <p class="muted">
        No networks. Name your client groups (LAN, VPN, IoT…) and list their
        CIDRs above.
      </p>
    {/if}
  </div>

  <div class="card">
    <div class="spread" style="margin-bottom: 12px">
      <strong>Domain entries ({entries.length})</strong>
      <button onclick={() => startEdit(null)}>+ Entry</button>
    </div>
    <table>
      <thead>
        <tr>
          <th>Domain</th>
          <th>Networks</th>
          <th>IPs</th>
          <th>TTL</th>
          <th>Status</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each entries as entry (entry.id)}
          <tr>
            <td><code>{entry.domain}</code></td>
            <td>
              {#if entry.networks.length === 0}
                <span class="muted">all clients</span>
              {:else}
                <div class="row" style="gap: 6px">
                  {#each entry.networks as n (n)}
                    <span class="pill">{n}</span>
                  {/each}
                </div>
              {/if}
            </td>
            <td>
              <div class="row" style="gap: 6px">
                {#each entry.ips as ip (ip)}
                  <code>{ip}</code>
                {/each}
              </div>
            </td>
            <td>{entry.ttl}</td>
            <td>
              <span class="pill" class:ok={!entry.disabled}>
                {entry.disabled ? 'disabled' : 'active'}
              </span>
            </td>
            <td>
              <div class="row" style="gap: 6px">
                <button class="secondary" onclick={() => startEdit(entry)}>Edit</button>
                <button class="danger" onclick={() => removeEntry(entry)}>✕</button>
              </div>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if entries.length === 0}
      <p class="muted">
        No entries. Add one: pick a domain, the networks that see the special
        answer, and the IPs to return.
      </p>
    {/if}

    {#if edit}
      <div class="card" style="margin-top: 14px; background: var(--panel-2)">
        <h4 style="margin-top: 0">{edit.isNew ? 'New entry' : 'Edit entry'}</h4>
        <div class="grid2">
          <label>
            Domain
            <input placeholder="intranet.example.com" bind:value={edit.domain} />
          </label>
          <label>
            Networks (names or CIDRs, comma-separated; empty = all)
            <input placeholder="LAN, VPN, 10.0.0.0/8" bind:value={edit.networks} />
          </label>
          <label>
            IPs (comma-separated)
            <input placeholder="10.0.0.5, fd00::1" bind:value={edit.ips} />
          </label>
          <label>
            TTL
            <input type="number" bind:value={edit.ttl} />
          </label>
        </div>
        <label style="margin-top: 8px; flex-direction: row; align-items: center">
          <input type="checkbox" bind:checked={edit.disabled} />
          Disabled (keep for later)
        </label>
        <div class="row" style="margin-top: 10px">
          <button
            onclick={saveEntry}
            disabled={!edit.domain.trim() || parseList(edit.ips).length === 0}
          >
            Save
          </button>
          <button class="secondary" onclick={() => (edit = null)}>Cancel</button>
        </div>
      </div>
    {/if}
  </div>
</div>

<style>
  .split {
    display: grid;
    grid-template-columns: 340px 1fr;
    gap: 16px;
    align-items: start;
  }
  @media (max-width: 900px) {
    .split { grid-template-columns: 1fr; }
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
</style>

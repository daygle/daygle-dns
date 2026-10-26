<script>
  import { api, formatApiError } from '../api.js';

  // Named networks (LAN, VPN, IoT...) that settings taking client networks
  // can name instead of repeating the addresses. Saved on their own, like
  // the Backup tab.
  let networks = $state([]);
  let loading = $state(true);
  let error = $state(null);
  let notice = $state(null);
  let saving = $state(false);
  // The network being added or edited, or null when the dialog is closed.
  let edit = $state(null);
  let dialogError = $state(null);

  async function load() {
    try {
      networks = (await api.networks()).networks || [];
    } catch (e) {
      error = formatApiError(e);
    } finally {
      loading = false;
    }
  }

  function startEdit(network) {
    error = null;
    notice = null;
    dialogError = null;
    edit = network
      ? {
          originalName: network.name,
          name: network.name,
          cidrs: network.cidrs.join('\n'),
          description: network.description || '',
          usedBy: network.used_by || [],
        }
      : { originalName: null, name: '', cidrs: '', description: '', usedBy: [] };
  }

  function closeEdit() {
    if (!saving) edit = null;
  }

  async function save() {
    if (!edit) return;
    const name = edit.name.trim();
    saving = true;
    dialogError = null;
    try {
      await api.saveNetwork({
        original_name: edit.originalName,
        name,
        cidrs: edit.cidrs.split(/[\n,]/).map((c) => c.trim()).filter(Boolean),
        description: edit.description.trim(),
      });
      const renamed = edit.originalName && edit.originalName !== name;
      notice = edit.originalName
        ? `Network "${name}" saved${renamed ? `; settings that used "${edit.originalName}" now use "${name}"` : ''}.`
        : `Network "${name}" added.`;
      edit = null;
      await load();
    } catch (e) {
      dialogError = formatApiError(e);
    } finally {
      saving = false;
    }
  }

  async function remove(network) {
    if (!confirm(`Delete network "${network.name}"?`)) return;
    error = null;
    notice = null;
    try {
      await api.deleteNetwork(network.name);
      notice = `Network "${network.name}" deleted.`;
      await load();
    } catch (e) {
      error = formatApiError(e);
    }
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

<div class="card">
  <div class="spread" style="margin-bottom: 10px">
    <h3 style="margin: 0">Networks ({networks.length})</h3>
    <button onclick={() => startEdit(null)}>Add Network</button>
  </div>
  {#if loading}
    <p class="muted">Loading...</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>Name</th><th>Addresses</th><th>Used By</th><th class="num">Actions</th></tr>
        </thead>
        <tbody>
          {#each networks as n (n.name)}
            <tr>
              <td>
                <strong>{n.name}</strong>
                {#if n.builtin}<span class="pill">Built-In</span>{/if}
                {#if n.description}<div class="muted small">{n.description}</div>{/if}
              </td>
              <td>
                <div class="row" style="gap: 6px; flex-wrap: wrap">
                  {#each n.cidrs as c (c)}<span class="pill">{c}</span>{/each}
                </div>
              </td>
              <td class="muted small">
                {#if n.used_by.length}
                  {#each n.used_by as u (u)}<div>{u}</div>{/each}
                {:else}
                  Not Used
                {/if}
              </td>
              <td class="num">
                {#if !n.builtin}
                  <div class="row" style="gap: 6px; justify-content: flex-end">
                    <button class="secondary" onclick={() => startEdit(n)}>Edit</button>
                    <button
                      class="danger"
                      onclick={() => remove(n)}
                      disabled={n.used_by.length > 0}
                      title={n.used_by.length ? 'In use: remove it from the settings listed first' : 'Delete'}
                      aria-label="Delete {n.name}">✕</button>
                  </div>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
  <p class="muted help">
    Name your networks once (LAN, VPN, IoT...) and pick them wherever a setting
    asks for client networks: split horizon, filtering groups, resolution policies,
    recursion access and more. Changing a network's addresses changes every
    setting that uses it straight away; renaming it keeps them pointing at it.
    A network in use cannot be deleted. The built-in networks cannot be
    changed.
  </p>
</div>

{#if edit}
  <div class="modal-backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && closeEdit()}>
    <div class="modal card" role="dialog" aria-modal="true" aria-labelledby="network-title">
      <div class="spread" style="margin-bottom: 12px">
        <h3 id="network-title" style="margin: 0">{edit.originalName ? `Edit Network - ${edit.originalName}` : 'Add Network'}</h3>
        <button class="secondary" style="padding: 2px 10px" onclick={closeEdit} aria-label="Close">✕</button>
      </div>
      {#if dialogError}<p class="dialog-error">{dialogError}</p>{/if}
      <div class="grid2">
        <label>Name <input bind:value={edit.name} placeholder="LAN" maxlength="64" /></label>
        <label>Description (Optional) <input bind:value={edit.description} placeholder="Home devices" /></label>
      </div>
      <label style="margin-top: 10px">Addresses
        <textarea rows="4" bind:value={edit.cidrs} placeholder={'192.168.20.0/24\nfd00:20::/64\n10.0.0.5'}></textarea>
      </label>
      <p class="muted help">CIDR networks or single addresses, one per line.</p>
      {#if edit.usedBy.length}
        <p class="muted help">
          Used by {edit.usedBy.join(', ')}. A change applies to all of them at
          once.
        </p>
      {/if}
      <div class="row actions">
        <button onclick={save} disabled={saving || !edit.name.trim() || !edit.cidrs.trim()}>
          {saving ? 'Saving...' : edit.originalName ? 'Save Network' : 'Add Network'}
        </button>
        <button class="secondary" onclick={closeEdit} disabled={saving}>Cancel</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .pill { margin-left: 6px; }
  td .row .pill { margin-left: 0; }
  textarea { width: 100%; }
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; color: var(--muted); }
  .modal-backdrop { position: fixed; inset: 0; background: rgb(0 0 0 / 0.65); display: grid; place-items: center; padding: 20px; z-index: 10; }
  .modal { width: min(620px, 100%); max-height: calc(100vh - 40px); overflow: auto; }
  .actions { margin-top: 18px; padding-top: 14px; border-top: 1px solid var(--border); }
  .dialog-error { color: var(--danger); margin: 0 0 10px; }
  @media (max-width: 640px) {
    .grid2 { grid-template-columns: 1fr; }
  }
</style>

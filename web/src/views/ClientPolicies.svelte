<script>
  import IconButton from '../IconButton.svelte';
  import { api, formatApiError } from '../api.js';
  import NetworkPicker from '../NetworkPicker.svelte';
  import { formatDateTime } from '../datetime.svelte.js';

  // Client resolution policies (recursive.client_policies). Saved on their
  // own, like the Zones page's forwarders, so editing them never touches the
  // unsaved Settings form around this card.
  let policies = $state([]);
  // Named networks (Clients -> Networks) for the client picker.
  let networks = $state([]);
  // `error` shows in red, `notice` (success) in green; failures while the
  // dialog is open show inside it.
  let notice = $state(null);
  let error = $state(null);
  let dialogError = $state(null);
  let saving = $state(false);
  // The policy being edited (a form copy), or null when the dialog is closed.
  let form = $state(null);

  const ACTIONS = {
    forward: 'Forward to Upstreams',
    recursive: 'Resolve from Root Servers',
    refuse: 'Refuse Recursion',
  };

  async function load() {
    api.networks().then((data) => { networks = data.networks || []; }).catch(() => {});
    try {
      const config = await api.config();
      policies = config?.recursive?.client_policies || [];
    } catch (e) {
      error = formatApiError(e);
    }
  }

  function lines(text) {
    return (text || '').split(/[\n,]+/).map((v) => v.trim()).filter(Boolean);
  }

  function clearMessages() {
    notice = null;
    error = null;
    dialogError = null;
  }

  function openAdd() {
    clearMessages();
    form = { index: null, name: '', enabled: true, clients: [], action: 'forward', upstreamsText: '' };
  }

  function openEdit(index) {
    clearMessages();
    const p = policies[index];
    form = {
      index,
      name: p.name,
      enabled: p.enabled,
      clients: [...p.clients],
      action: p.action,
      upstreamsText: p.upstreams.join('\n'),
    };
  }

  function close() {
    if (!saving) form = null;
  }

  // Replace the whole list (re-read first so a concurrent change survives).
  async function store(update) {
    const fresh = (await api.config())?.recursive?.client_policies || [];
    const list = update(fresh.map((p) => ({ ...p })));
    await api.updateSettings({ recursive: { client_policies: list } });
    policies = list;
  }

  async function save() {
    const name = form.name.trim();
    const policy = {
      name,
      enabled: form.enabled,
      clients: [...form.clients],
      action: form.action,
      upstreams: form.action === 'forward' ? lines(form.upstreamsText) : [],
    };
    if (!name) return (dialogError = 'Give the policy a name.');
    if (policy.clients.length === 0) return (dialogError = 'Add at least one client network.');
    if (form.action === 'forward' && policy.upstreams.length === 0) {
      return (dialogError = 'Add at least one upstream server.');
    }
    saving = true;
    dialogError = null;
    const editing = form.index;
    try {
      await store((list) => {
        const original = editing === null ? null : policies[editing]?.name;
        const at = list.findIndex((p) => p.name === original);
        if (list.some((p, i) => i !== at && p.name.toLowerCase() === name.toLowerCase())) {
          throw new Error(`A policy named ${name} already exists`);
        }
        if (at >= 0) list[at] = policy;
        else list.push(policy);
        return list;
      });
      form = null;
      notice = editing === null ? `Policy ${name} added and applied live.` : `Policy ${name} saved and applied live.`;
    } catch (e) {
      dialogError = formatApiError(e);
    } finally {
      saving = false;
    }
  }

  async function remove(index) {
    const name = policies[index].name;
    if (!confirm(`Delete resolution policy ${name}?`)) return;
    clearMessages();
    try {
      await store((list) => list.filter((p) => p.name !== name));
      notice = `Policy ${name} deleted.`;
    } catch (e) {
      error = formatApiError(e);
    }
  }

  // The first matching policy wins, so order matters.
  async function move(index, delta) {
    const name = policies[index].name;
    clearMessages();
    try {
      await store((list) => {
        const from = list.findIndex((p) => p.name === name);
        const to = from + delta;
        if (from < 0 || to < 0 || to >= list.length) return list;
        [list[from], list[to]] = [list[to], list[from]];
        return list;
      });
    } catch (e) {
      error = formatApiError(e);
    }
  }

  function describe(p) {
    if (p.action === 'forward') return `→ ${p.upstreams.join(', ')}`;
    return p.action === 'recursive' ? 'Resolved from Root Servers' : 'Recursion Refused';
  }

  $effect(() => {
    load();
  });
</script>

<div class="card" style="margin-bottom: 14px">
  <div class="spread" style="margin-bottom: 10px">
    <h3 style="margin: 0">Resolution Policies ({policies.length})</h3>
    <button onclick={openAdd}>Add Policy</button>
  </div>
  {#if notice}
    <p class="notice ok">{notice}</p>
  {/if}
  {#if error}
    <p class="notice error">{error}</p>
  {/if}
  {#if policies.length}
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>Name</th><th>Clients</th><th>Resolution</th><th>Last Modified</th><th class="num">Actions</th></tr>
        </thead>
        <tbody>
          {#each policies as p, i (p.name)}
            <tr class:disabled={!p.enabled}>
              <td>
                {p.name}
                {#if !p.enabled}<span class="pill">Disabled</span>{/if}
              </td>
              <td class="muted">{p.clients.join(', ')}</td>
              <td class="muted">{describe(p)}</td>
              <td class="muted" style="white-space: nowrap">{p.modified_at ? formatDateTime(p.modified_at) : '-'}</td>
              <td class="num">
                <div class="row" style="gap: 6px; justify-content: flex-end">
                  <IconButton icon="up" label="Move up" onclick={() => move(i, -1)} disabled={i === 0} />
                  <IconButton icon="down" label="Move down" onclick={() => move(i, 1)} disabled={i === policies.length - 1} />
                  <IconButton icon="edit" label="Edit" onclick={() => openEdit(i)} />
                  <IconButton icon="delete" variant="danger" label="Delete {p.name}" onclick={() => remove(i)} />
                </div>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {:else}
    <p class="muted">No resolution policies. Every client is resolved the default way.</p>
  {/if}
  <p class="muted help">
    Resolve some clients differently: send a network's queries to its own
    upstreams (a filtering DNS service for the kids' devices, say), resolve
    them from the root servers whatever the resolver's mode (Settings →
    Resolver), or refuse them
    recursion. The first enabled matching policy wins. Recursion Access
    (Clients → Access) still
    decides who may use recursion at all, and conditional forwarders and stub
    zones still answer for their own names.
  </p>
</div>

{#if form}
  <div class="modal-backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && close()}>
    <div class="modal card" role="dialog" aria-modal="true" aria-labelledby="policy-title">
      <div class="spread modal-title">
        <h3 id="policy-title" style="margin: 0">{form.index === null ? 'Add Resolution Policy' : `Edit Resolution Policy - ${policies[form.index].name}`}</h3>
        <button class="secondary" style="padding: 2px 10px" onclick={close} aria-label="Close">✕</button>
      </div>
      {#if dialogError}<p class="notice error">{dialogError}</p>{/if}
      <div class="grid2">
        <label>Name <input placeholder="Kids' Devices" bind:value={form.name} /></label>
        <label>Resolution
          <select bind:value={form.action}>
            {#each Object.entries(ACTIONS) as [value, label]}
              <option {value}>{label}</option>
            {/each}
          </select>
        </label>
      </div>
      <label class="checkbox"><input type="checkbox" bind:checked={form.enabled} /><span>Enabled</span></label>
      <div class="section-title">Clients</div>
      <NetworkPicker {networks} devices bind:value={form.clients} />
      <p class="muted help">Tick named networks and/or type addresses.</p>
      {#if form.action === 'forward'}
        <div class="section-title">Upstreams</div>
        <label>Upstream Servers <textarea rows="3" placeholder={'1.1.1.3\ntls://1.1.1.3:853@family.cloudflare-dns.com'} bind:value={form.upstreamsText}></textarea></label>
        <p class="muted help">Same forms as the default upstreams, one per line.</p>
      {/if}
      <div class="row actions">
        <button onclick={save} disabled={saving}>{saving ? 'Saving...' : form.index === null ? 'Add Policy' : 'Save Policy'}</button>
        <button class="secondary" onclick={close} disabled={saving}>Cancel</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .notice { margin: 0 0 10px; }
  .notice.error { color: var(--danger); }
  .notice.ok { color: var(--ok); }
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; color: var(--muted); }
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
  .checkbox { flex-direction: row; align-items: center; gap: 8px; margin-top: 10px; }
  .checkbox input { width: auto; }
  .checkbox span { color: var(--text); }
  .actions { margin-top: 22px; padding-top: 14px; border-top: 1px solid var(--border); }
</style>

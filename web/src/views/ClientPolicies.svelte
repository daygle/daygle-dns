<script>
  import { api, formatApiError } from '../api.js';

  // Client resolution policies (recursive.client_policies). Saved on their
  // own, like the Zones page's forwarders, so editing them never touches the
  // unsaved Settings form around this card.
  let policies = $state([]);
  let notice = $state(null);
  let saving = $state(false);
  // The policy being edited (a form copy), or null when the dialog is closed.
  let form = $state(null);

  const ACTIONS = {
    forward: 'Forward to Upstreams',
    recursive: 'Resolve from the Root Servers',
    refuse: 'Refuse Recursion',
  };

  async function load() {
    try {
      const config = await api.config();
      policies = config?.recursive?.client_policies || [];
    } catch (e) {
      notice = formatApiError(e);
    }
  }

  function lines(text) {
    return (text || '').split(/[\n,]+/).map((v) => v.trim()).filter(Boolean);
  }

  function openAdd() {
    notice = null;
    form = { index: null, name: '', enabled: true, clientsText: '', action: 'forward', upstreamsText: '' };
  }

  function openEdit(index) {
    notice = null;
    const p = policies[index];
    form = {
      index,
      name: p.name,
      enabled: p.enabled,
      clientsText: p.clients.join('\n'),
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
      clients: lines(form.clientsText),
      action: form.action,
      upstreams: form.action === 'forward' ? lines(form.upstreamsText) : [],
    };
    if (!name) return (notice = 'Error: Name is required');
    if (policy.clients.length === 0) return (notice = 'Error: Add at least one client network');
    if (form.action === 'forward' && policy.upstreams.length === 0) {
      return (notice = 'Error: Add at least one upstream server');
    }
    saving = true;
    notice = null;
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
      notice = editing === null ? 'Policy added and applied live.' : 'Policy updated and applied live.';
    } catch (e) {
      notice = formatApiError(e);
    } finally {
      saving = false;
    }
  }

  async function remove(index) {
    const name = policies[index].name;
    if (!confirm(`Delete client policy ${name}?`)) return;
    notice = null;
    try {
      await store((list) => list.filter((p) => p.name !== name));
    } catch (e) {
      notice = formatApiError(e);
    }
  }

  // The first matching policy wins, so order matters.
  async function move(index, delta) {
    const name = policies[index].name;
    notice = null;
    try {
      await store((list) => {
        const from = list.findIndex((p) => p.name === name);
        const to = from + delta;
        if (from < 0 || to < 0 || to >= list.length) return list;
        [list[from], list[to]] = [list[to], list[from]];
        return list;
      });
    } catch (e) {
      notice = formatApiError(e);
    }
  }

  function describe(p) {
    if (p.action === 'forward') return `→ ${p.upstreams.join(', ')}`;
    return p.action === 'recursive' ? 'Resolved from the root servers' : 'Recursion refused';
  }

  $effect(() => {
    load();
  });
</script>

<div class="card" style="margin-bottom: 14px">
  <div class="spread" style="margin-bottom: 10px">
    <h3 style="margin: 0">Client Resolution Policies ({policies.length})</h3>
    <button onclick={openAdd}>Add Policy</button>
  </div>
  {#if notice}
    <p class="notice" class:error={notice.startsWith('Error:')}>{notice}</p>
  {/if}
  {#if policies.length}
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>Name</th><th>Clients</th><th>Resolution</th><th class="num">Actions</th></tr>
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
              <td class="num">
                <div class="row" style="gap: 6px; justify-content: flex-end">
                  <button class="secondary" onclick={() => move(i, -1)} disabled={i === 0} aria-label="Move up">↑</button>
                  <button class="secondary" onclick={() => move(i, 1)} disabled={i === policies.length - 1} aria-label="Move down">↓</button>
                  <button class="secondary" onclick={() => openEdit(i)}>Edit</button>
                  <button class="danger" onclick={() => remove(i)}>✕</button>
                </div>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {:else}
    <p class="muted">No client policies. Every client is resolved the default way.</p>
  {/if}
  <p class="muted help">
    Resolve some clients differently: send a network's queries to its own
    upstreams (a filtering DNS service for the kids' devices, say), resolve
    them from the root servers whatever the mode above, or refuse them
    recursion. The first enabled matching policy wins. Recursion Access still
    decides who may use recursion at all, and conditional forwarders and stub
    zones still answer for their own names.
  </p>
</div>

{#if form}
  <div class="modal-backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && close()}>
    <div class="modal card" role="dialog" aria-modal="true" aria-labelledby="policy-title">
      <div class="spread modal-title">
        <h3 id="policy-title" style="margin: 0">{form.index === null ? 'Add Client Policy' : `Edit Client Policy - ${policies[form.index].name}`}</h3>
        <button class="secondary" style="padding: 2px 10px" onclick={close} aria-label="Close">✕</button>
      </div>
      <div class="grid2">
        <label>Name <input placeholder="Kids' devices" bind:value={form.name} /></label>
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
      <label>Client Networks <textarea rows="3" placeholder={'192.168.1.64/27\n192.168.1.20'} bind:value={form.clientsText}></textarea></label>
      <p class="muted help">CIDRs or single IPs, one per line.</p>
      {#if form.action === 'forward'}
        <div class="section-title">Upstreams</div>
        <label>Upstream Servers <textarea rows="3" placeholder={'1.1.1.3\ntls://1.1.1.3:853@family.cloudflare-dns.com'} bind:value={form.upstreamsText}></textarea></label>
        <p class="muted help">Same forms as the default upstreams, one per line.</p>
      {/if}
      <div class="row actions">
        <button onclick={save} disabled={saving}>{saving ? 'Saving…' : form.index === null ? 'Add Policy' : 'Save Policy'}</button>
        <button class="secondary" onclick={close} disabled={saving}>Cancel</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .notice { margin: 0 0 10px; }
  .notice.error { color: var(--danger); }
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

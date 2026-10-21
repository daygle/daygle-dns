<script>
  import { api, formatApiError } from '../api.js';

  let groups = $state([]);
  // Blocklists (Filtering -> Blocklists) set to apply to selected groups only.
  let groupLists = $state([]);
  let error = $state(null);
  let notice = $state(null);
  let saving = $state(false);

  // The group being edited (a form copy), or null when the dialog is closed.
  let edit = $state(null);

  // Tester.
  let testClient = $state('');
  let testDomain = $state('');
  let testResult = $state(null);

  const RESPONSES = [
    { value: 'nx_domain', label: 'NXDOMAIN (Does Not Exist)' },
    { value: 'refused', label: 'REFUSED' },
    { value: 'no_data', label: 'NODATA (Empty Answer)' },
    { value: 'redirect', label: 'Redirect to Address' },
  ];

  async function load() {
    try {
      groups = await api.blockingGroups();
    } catch (e) {
      error = formatApiError(e);
    }
    try {
      const data = await api.blocklistSources();
      groupLists = (data.sources || []).filter((s) => s.scope === 'groups');
    } catch {
      // 404: no blocklists configured.
      groupLists = [];
    }
  }

  function toggleList(name) {
    edit.blocklists = edit.blocklists.includes(name)
      ? edit.blocklists.filter((n) => n !== name)
      : [...edit.blocklists, name];
  }

  // Split a textarea into a trimmed list on newlines or commas.
  function parseList(text) {
    return (text || '')
      .split(/[\n,]/)
      .map((s) => s.trim())
      .filter(Boolean);
  }

  function startEdit(group) {
    notice = null;
    error = null;
    edit = group
      ? {
          id: group.id,
          originalName: group.name,
          name: group.name,
          enabled: group.enabled,
          clients: group.clients.join('\n'),
          allow: group.allow.join('\n'),
          block: group.block.join('\n'),
          allow_regex: group.allow_regex.join('\n'),
          block_regex: group.block_regex.join('\n'),
          blocklists: [...(group.blocklists || [])],
          responseKind: group.response?.kind || 'nx_domain',
          redirectAddr: group.response?.address || '0.0.0.0',
        }
      : {
          id: null,
          originalName: null,
          name: '',
          enabled: true,
          clients: '',
          allow: '',
          block: '',
          allow_regex: '',
          block_regex: '',
          blocklists: [],
          responseKind: 'nx_domain',
          redirectAddr: '0.0.0.0',
        };
  }

  function closeEdit() {
    if (!saving) edit = null;
  }

  async function saveGroup() {
    if (!edit) return;
    const name = edit.name.trim();
    if (!name) {
      error = 'Error: Give the group a name.';
      return;
    }
    const response =
      edit.responseKind === 'redirect'
        ? { kind: 'redirect', address: edit.redirectAddr.trim() }
        : { kind: edit.responseKind };
    const body = {
      // The id makes this an edit of that group, so renaming it works.
      id: edit.id,
      name,
      enabled: edit.enabled,
      clients: parseList(edit.clients),
      allow: parseList(edit.allow),
      block: parseList(edit.block),
      allow_regex: parseList(edit.allow_regex),
      block_regex: parseList(edit.block_regex),
      blocklists: edit.blocklists,
      response,
    };
    saving = true;
    error = null;
    try {
      await api.saveBlockingGroup(body);
      const added = !edit.id;
      edit = null;
      notice = added ? `Group "${name}" added and applied live.` : `Group "${name}" saved and applied live.`;
      await load();
    } catch (e) {
      error = formatApiError(e);
    } finally {
      saving = false;
    }
  }

  async function removeGroup(group) {
    if (!confirm(`Delete client group "${group.name}"?`)) return;
    notice = null;
    error = null;
    try {
      await api.deleteBlockingGroup(group.id);
      notice = `Group "${group.name}" deleted.`;
      await load();
    } catch (e) {
      error = formatApiError(e);
    }
  }

  async function move(group, direction) {
    notice = null;
    error = null;
    try {
      groups = await api.moveBlockingGroup(group.id, direction);
    } catch (e) {
      error = formatApiError(e);
    }
  }

  async function runTest() {
    testResult = null;
    error = null;
    try {
      testResult = await api.testBlocking(testClient.trim(), testDomain.trim());
    } catch (e) {
      error = formatApiError(e);
    }
  }

  function responseLabel(response) {
    if (!response) return '-';
    if (response.kind === 'redirect') return `Redirect → ${response.address}`;
    return RESPONSES.find((r) => r.value === response.kind)?.label || response.kind;
  }

  function count(n, word) {
    return `${n} ${word}${n === 1 ? '' : 's'}`;
  }

  $effect(() => {
    load();
  });
</script>

{#if notice}
  <div class="card" style="border-color: var(--ok); margin-bottom: 14px">{notice}</div>
{/if}
{#if error && !edit}
  <div class="card" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">{error}</div>
{/if}

<div class="card" style="margin-bottom: 14px">
  <div class="spread" style="margin-bottom: 10px">
    <h3 style="margin: 0">Client Groups ({groups.length})</h3>
    <button onclick={() => startEdit(null)}>Add Group</button>
  </div>

  {#if groups.length === 0}
    <p class="muted">
      No client groups yet. Add one to give a set of devices (by IP or network)
      their own allow and block rules.
    </p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>Name</th><th>Clients</th><th>Rules</th><th>Blocked Response</th><th class="num">Actions</th></tr>
        </thead>
        <tbody>
          {#each groups as g, i (g.id)}
            <tr class:disabled={!g.enabled}>
              <td>
                <strong>{g.name}</strong>
                {#if !g.enabled}<span class="pill">Disabled</span>{/if}
              </td>
              <td class="muted">{g.clients.length ? g.clients.join(', ') : 'All Clients'}</td>
              <td class="muted">
                {count(g.allow.length + g.allow_regex.length, 'Allow Rule')} ·
                {count(g.block.length + g.block_regex.length, 'Block Rule')}
                {#if g.blocklists?.length}
                  <div title={g.blocklists.join(', ')}>{count(g.blocklists.length, 'Blocklist')}</div>
                {/if}
              </td>
              <td class="muted">{responseLabel(g.response)}</td>
              <td class="num">
                <div class="row" style="gap: 6px; justify-content: flex-end">
                  <button class="secondary" onclick={() => move(g, 'up')} disabled={i === 0} aria-label="Move {g.name} up">↑</button>
                  <button class="secondary" onclick={() => move(g, 'down')} disabled={i === groups.length - 1} aria-label="Move {g.name} down">↓</button>
                  <button class="secondary" onclick={() => startEdit(g)}>Edit</button>
                  <button class="danger" onclick={() => removeGroup(g)} aria-label="Delete {g.name}">✕</button>
                </div>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
  <p class="muted help">
    Groups covering the client are checked top to bottom. The first one that
    lists the domain decides: on its allow list, the domain is never blocked
    (later groups are skipped); on its block list or one of its blocklists,
    it is blocked with that group's response. Otherwise the next group is
    checked. A group with no client networks covers every client.
  </p>
</div>

<div class="card">
  <h3 style="margin: 0 0 10px">Test a Query</h3>
  <p class="muted help" style="margin: 0 0 10px">
    Check what the client groups would do with a domain asked by a given client.
  </p>
  <form class="row" style="flex-wrap: wrap; gap: 8px" onsubmit={(e) => { e.preventDefault(); runTest(); }}>
    <input style="flex: 1; min-width: 160px" bind:value={testClient} placeholder="Client IP, e.g. 192.168.1.50" />
    <input style="flex: 1; min-width: 160px" bind:value={testDomain} placeholder="Domain, e.g. ads.example.com" />
    <button type="submit" disabled={!testClient.trim() || !testDomain.trim()}>Test</button>
  </form>
  {#if testResult}
    <div class="result">
      <span class="pill" class:err={testResult.blocked} class:ok={!testResult.blocked}>
        {testResult.blocked ? 'Blocked' : 'Allowed'}
      </span>
      {#if testResult.blocked && testResult.group}
        <span class="pill group">By {testResult.group}</span>
      {/if}
      <span class="muted">{testResult.reason}</span>
    </div>
  {/if}
</div>

{#if edit}
  <div class="modal-backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && closeEdit()}>
    <div class="modal card" role="dialog" aria-modal="true" aria-labelledby="group-title">
      <div class="spread modal-title">
        <h3 id="group-title" style="margin: 0">{edit.id ? `Edit Client Group - ${edit.originalName}` : 'Add Client Group'}</h3>
        <button class="secondary" style="padding: 2px 10px" onclick={closeEdit} aria-label="Close">✕</button>
      </div>
      {#if error}
        <p class="dialog-error">{error}</p>
      {/if}
      <div class="grid2">
        <label>Name <input bind:value={edit.name} placeholder="Kids' Devices" /></label>
        <label>Blocked Response
          <select bind:value={edit.responseKind}>
            {#each RESPONSES as r (r.value)}<option value={r.value}>{r.label}</option>{/each}
          </select>
        </label>
        {#if edit.responseKind === 'redirect'}
          <label>Redirect Address <input bind:value={edit.redirectAddr} placeholder="0.0.0.0" /></label>
        {/if}
      </div>
      <label class="checkbox"><input type="checkbox" bind:checked={edit.enabled} /><span>Enabled</span></label>

      <div class="section-title">Clients</div>
      <label>Client Networks <textarea rows="2" bind:value={edit.clients} placeholder={'192.168.1.0/24\n10.0.0.5'}></textarea></label>
      <p class="muted help">CIDRs or single IPs, one per line. Leave empty for every client.</p>

      <div class="section-title">Blocklists</div>
      {#if groupLists.length}
        <div class="lists">
          {#each groupLists as l (l.name)}
            <label class="checkbox">
              <input type="checkbox" checked={edit.blocklists.includes(l.name)} onchange={() => toggleList(l.name)} />
              <span>{l.name}</span>
              <span class="muted small">{Number(l.domains || 0).toLocaleString()} domains{l.enabled ? '' : ' · Disabled'}</span>
            </label>
          {/each}
        </div>
        <p class="muted help">
          Blocks the domains on the ticked lists for this group's clients; the
          Allow list below still wins. Lists set to Everyone already apply to
          every client.
        </p>
      {:else}
        <p class="muted help">
          No blocklists are set to apply to selected client groups. On the
          Blocklists tab, add or edit a list and set <strong>Applies To</strong>
          to <strong>Selected Client Groups Only</strong>, then tick it here.
        </p>
      {/if}

      <div class="section-title">Domains</div>
      <div class="grid2">
        <label>Allow <textarea rows="4" bind:value={edit.allow} placeholder={'school.example.com\n*.work.example'}></textarea></label>
        <label>Block <textarea rows="4" bind:value={edit.block} placeholder={'*.doubleclick.net\ngames.example'}></textarea></label>
      </div>
      <p class="muted help">One per line; <code>*.example.com</code> covers the subdomains. Allow beats block.</p>

      <div class="section-title">Patterns (Optional)</div>
      <div class="grid2">
        <label>Allow Regex <textarea rows="2" bind:value={edit.allow_regex} placeholder={'^cdn\\d+\\.'}></textarea></label>
        <label>Block Regex <textarea rows="2" bind:value={edit.block_regex} placeholder={'^ads?[0-9]*\\.'}></textarea></label>
      </div>
      <p class="muted help">Regular expressions matched against the full domain name, one per line.</p>

      <div class="row actions">
        <button onclick={saveGroup} disabled={saving || !edit.name.trim()}>
          {saving ? 'Saving…' : edit.id ? 'Save Group' : 'Add Group'}
        </button>
        <button class="secondary" onclick={closeEdit} disabled={saving}>Cancel</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .help { max-width: 90ch; }
  textarea { width: 100%; }
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; color: var(--muted); }
  .modal-backdrop { position: fixed; inset: 0; background: rgb(0 0 0 / 0.65); display: grid; place-items: center; padding: 20px; z-index: 10; }
  .modal { width: min(720px, 100%); max-height: calc(100vh - 40px); overflow: auto; }
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
  .checkbox span.muted { color: var(--muted); }
  .lists { display: flex; flex-direction: column; gap: 2px; }
  .lists .checkbox { margin-top: 4px; }
  .actions { margin-top: 22px; padding-top: 14px; border-top: 1px solid var(--border); }
  .dialog-error { color: var(--danger); margin: 0 0 10px; }
  .result { margin-top: 12px; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .pill.group { border-color: var(--accent); color: var(--accent); }
  @media (max-width: 640px) {
    .grid2 { grid-template-columns: 1fr; }
  }
</style>

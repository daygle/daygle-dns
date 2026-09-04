<script>
  import { api } from '../api.js';

  let groups = $state([]);
  let filterAaaa = $state(false);
  let filterAaaaExcept = $state('');
  let error = $state(null);
  let notice = $state(null);

  let edit = $state(null);

  // tester
  let testClient = $state('');
  let testDomain = $state('');
  let testResult = $state(null);

  const RESPONSES = [
    { value: 'nx_domain', label: 'NXDOMAIN (does not exist)' },
    { value: 'refused', label: 'REFUSED' },
    { value: 'no_data', label: 'NODATA (empty answer)' },
    { value: 'redirect', label: 'Redirect to address' },
  ];

  async function load() {
    error = null;
    try {
      const [g, cfg] = await Promise.all([api.blockingGroups(), api.config()]);
      groups = g;
      filterAaaa = !!cfg.policy?.filter_aaaa;
      filterAaaaExcept = (cfg.policy?.filter_aaaa_except || []).join('\n');
    } catch (e) {
      error = String(e.message || e);
    }
  }

  // Split a textarea/field into a trimmed list on newlines or commas.
  function parseList(text) {
    return (text || '')
      .split(/[\n,]/)
      .map((s) => s.trim())
      .filter(Boolean);
  }

  async function saveFilterAaaa() {
    notice = null;
    try {
      await api.updateSettings({
        policy: {
          filter_aaaa: filterAaaa,
          filter_aaaa_except: parseList(filterAaaaExcept),
        },
      });
      notice = 'Filter AAAA settings saved.';
    } catch (e) {
      notice = `Error: ${e.message || e}`;
    }
  }

  function startEdit(group) {
    testResult = null;
    edit = group
      ? {
          id: group.id,
          name: group.name,
          enabled: group.enabled,
          clients: group.clients.join('\n'),
          allow: group.allow.join('\n'),
          block: group.block.join('\n'),
          allow_regex: group.allow_regex.join('\n'),
          block_regex: group.block_regex.join('\n'),
          responseKind: group.response?.kind || 'nx_domain',
          redirectAddr: group.response?.address || '0.0.0.0',
          isNew: false,
        }
      : {
          id: null,
          name: '',
          enabled: true,
          clients: '',
          allow: '',
          block: '',
          allow_regex: '',
          block_regex: '',
          responseKind: 'nx_domain',
          redirectAddr: '0.0.0.0',
          isNew: true,
        };
  }

  async function saveGroup() {
    if (!edit || !edit.name.trim()) return;
    notice = null;
    const response =
      edit.responseKind === 'redirect'
        ? { kind: 'redirect', address: edit.redirectAddr.trim() }
        : { kind: edit.responseKind };
    const body = {
      name: edit.name.trim(),
      enabled: edit.enabled,
      clients: parseList(edit.clients),
      allow: parseList(edit.allow),
      block: parseList(edit.block),
      allow_regex: parseList(edit.allow_regex),
      block_regex: parseList(edit.block_regex),
      response,
    };
    try {
      await api.saveBlockingGroup(body);
      edit = null;
      await load();
    } catch (e) {
      notice = `Error: ${e.message || e}`;
    }
  }

  async function removeGroup(group) {
    if (!confirm(`Delete blocking group "${group.name}"?`)) return;
    notice = null;
    try {
      await api.deleteBlockingGroup(group.id);
      await load();
    } catch (e) {
      notice = `Error: ${e.message || e}`;
    }
  }

  async function runTest() {
    testResult = null;
    notice = null;
    try {
      testResult = await api.testBlocking(testClient.trim(), testDomain.trim());
    } catch (e) {
      notice = `Error: ${e.message || e}`;
    }
  }

  function responseLabel(response) {
    if (!response) return '-';
    if (response.kind === 'redirect') return `redirect → ${response.address}`;
    return RESPONSES.find((r) => r.value === response.kind)?.label || response.kind;
  }

  $effect(() => {
    load();
  });
</script>

<h1>Advanced Blocking</h1>
<p class="muted">
  Per-client-group allow/block policies. Each group targets a set of client
  networks and applies its own allow list, block list and regex patterns; allow
  rules win over block rules, and groups are evaluated top to bottom.
</p>

{#if error}
  <div class="card" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">
    Failed to load: {error}
  </div>
{/if}
{#if notice}
  <div class="card" style="border-color: var(--accent); margin-bottom: 14px">{notice}</div>
{/if}

<!-- Filter AAAA -->
<div class="card" style="margin-bottom: 14px">
  <div class="spread">
    <h3 style="margin: 0">Filter AAAA (force IPv4)</h3>
    <label class="check">
      <input type="checkbox" bind:checked={filterAaaa} /> <span>Enabled</span>
    </label>
  </div>
  <p class="muted" style="margin: 8px 0">
    Answer AAAA (IPv6) queries with an empty response so dual-stack clients fall
    back to IPv4. List any names - one per line, <code>*.suffix</code> allowed -
    that must keep their IPv6 answers.
  </p>
  <textarea
    rows="3"
    placeholder={'*.ipv6.example.com\nnas.home.arpa'}
    bind:value={filterAaaaExcept}
  ></textarea>
  <div class="row" style="margin-top: 8px">
    <button onclick={saveFilterAaaa}>Save Filter AAAA</button>
  </div>
</div>

<!-- Groups -->
<div class="card" style="margin-bottom: 14px">
  <div class="spread">
    <h3 style="margin: 0">Blocking groups</h3>
    <button onclick={() => startEdit(null)}>New group</button>
  </div>

  {#if groups.length === 0}
    <p class="muted">No blocking groups yet.</p>
  {:else}
    <table>
      <thead>
        <tr><th>Name</th><th>Clients</th><th>Allow / Block</th><th>Response</th><th></th></tr>
      </thead>
      <tbody>
        {#each groups as g (g.id)}
          <tr class:disabled={!g.enabled}>
            <td>
              <strong>{g.name}</strong>
              {#if !g.enabled}<span class="pill">disabled</span>{/if}
            </td>
            <td class="muted">{g.clients.length ? g.clients.join(', ') : 'all clients'}</td>
            <td class="muted">
              {g.allow.length + g.allow_regex.length} allow ·
              {g.block.length + g.block_regex.length} block
            </td>
            <td class="muted">{responseLabel(g.response)}</td>
            <td class="num">
              <button class="secondary" onclick={() => startEdit(g)}>Edit</button>
              <button class="danger" onclick={() => removeGroup(g)}>Delete</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<!-- Editor -->
{#if edit}
  <div class="card" style="border-color: var(--accent); margin-bottom: 14px">
    <h3 style="margin-top: 0">{edit.isNew ? 'New group' : `Edit "${edit.name}"`}</h3>
    <div class="form-grid">
      <label><span>Name</span><input bind:value={edit.name} placeholder="Kids devices" /></label>
      <label class="check" style="align-self: end">
        <input type="checkbox" bind:checked={edit.enabled} /> <span>Enabled</span>
      </label>
      <label class="wide">
        <span>Client networks (one per line; blank = all clients)</span>
        <textarea rows="2" bind:value={edit.clients} placeholder={'192.168.1.0/24\n10.0.0.5'}></textarea>
      </label>
      <label>
        <span>Allow - domains (override block)</span>
        <textarea rows="4" bind:value={edit.allow} placeholder={'safe.example.com\n*.work.example'}></textarea>
      </label>
      <label>
        <span>Block - domains</span>
        <textarea rows="4" bind:value={edit.block} placeholder={'*.doubleclick.net\ntracker.test'}></textarea>
      </label>
      <label>
        <span>Allow - regex (override block)</span>
        <textarea rows="3" bind:value={edit.allow_regex} placeholder={'^cdn\\d+\\.'}></textarea>
      </label>
      <label>
        <span>Block - regex</span>
        <textarea rows="3" bind:value={edit.block_regex} placeholder={'^ads?[0-9]*\\.'}></textarea>
      </label>
      <label>
        <span>Response when blocked</span>
        <select bind:value={edit.responseKind}>
          {#each RESPONSES as r (r.value)}<option value={r.value}>{r.label}</option>{/each}
        </select>
      </label>
      {#if edit.responseKind === 'redirect'}
        <label><span>Redirect address</span><input bind:value={edit.redirectAddr} placeholder="0.0.0.0" /></label>
      {/if}
    </div>
    <div class="row" style="margin-top: 12px">
      <button onclick={saveGroup}>Save group</button>
      <button class="secondary" onclick={() => (edit = null)}>Cancel</button>
    </div>
  </div>
{/if}

<!-- Tester -->
<div class="card">
  <h3 style="margin-top: 0">Test a query</h3>
  <p class="muted" style="margin: 8px 0">
    Check what the live groups would do with a given client and domain.
  </p>
  <div class="row" style="flex-wrap: wrap; gap: 8px">
    <input style="flex: 1; min-width: 140px" bind:value={testClient} placeholder="client IP e.g. 192.168.1.50" />
    <input style="flex: 1; min-width: 140px" bind:value={testDomain} placeholder="domain e.g. ads.example.com" />
    <button onclick={runTest}>Test</button>
  </div>
  {#if testResult}
    <div class="result" class:blocked={testResult.blocked}>
      <span class="pill" class:err={testResult.blocked} class:ok={!testResult.blocked}>
        {testResult.blocked ? testResult.action : 'allowed'}
      </span>
      <span class="muted">{testResult.reason}</span>
    </div>
  {/if}
</div>

<style>
  p { max-width: 70ch; }
  table { width: 100%; border-collapse: collapse; margin-top: 10px; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
  th { font-size: 0.78rem; color: var(--muted); font-weight: 600; }
  tr.disabled { opacity: 0.55; }
  .num { text-align: right; white-space: nowrap; }
  .check { display: inline-flex; align-items: center; gap: 6px; }
  textarea {
    width: 100%;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 0.82rem;
    resize: vertical;
  }
  .form-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 12px;
  }
  .form-grid label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; }
  .form-grid label.wide { grid-column: 1 / -1; }
  .form-grid label > span { color: var(--muted); }
  .result { margin-top: 12px; display: flex; align-items: center; gap: 10px; }
  @media (max-width: 640px) {
    .form-grid { grid-template-columns: 1fr; }
  }
</style>

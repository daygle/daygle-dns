<script>
  import IconButton from '../IconButton.svelte';
  import { api, formatApiError, getStoredUser } from '../api.js';
  import { formatDateTime } from '../datetime.svelte.js';

  // Viewers are read-only (the server refuses their changes).
  const isAdmin = getStoredUser()?.role !== 'viewer';

  const SOURCES = [
    { value: 'local', label: 'Rules Typed Here' },
    { value: 'url', label: 'Zone File From a URL' },
    { value: 'transfer', label: 'Zone Transfer (AXFR) From a Feed' },
  ];
  const POLICIES = [
    { value: 'given', label: 'As Written in the Zone' },
    { value: 'disabled', label: 'Log Only (Count Matches, Act on None)' },
    { value: 'nxdomain', label: 'NXDOMAIN for Every Match' },
    { value: 'nodata', label: 'NODATA for Every Match' },
    { value: 'drop', label: 'Drop Every Match (No Answer)' },
    { value: 'tcp_only', label: 'TCP-Only for Every Match' },
    { value: 'passthru', label: 'Passthru for Every Match' },
    { value: 'cname', label: 'Redirect Every Match (Walled Garden)' },
  ];

  let zones = $state([]); // saved configuration, in order
  let status = $state([]); // live state from /api/rpz
  let tsigKeys = $state([]);
  let loaded = $state(false);
  let error = $state(null);
  let notice = $state(null);
  let saving = $state(false);
  let edit = $state(null); // the zone being edited (a form copy)

  let testClient = $state('');
  let testDomain = $state('');
  let testResult = $state(null);

  async function load() {
    error = null;
    try {
      const cfg = await api.config();
      zones = cfg.rpz || [];
      tsigKeys = (cfg.authoritative?.tsig_keys || []).map((k) => k.name);
      await loadStatus();
      loaded = true;
    } catch (e) {
      error = formatApiError(e);
    }
  }

  async function loadStatus() {
    try {
      status = (await api.rpzStatus()).zones || [];
    } catch {
      status = [];
    }
  }

  function statusOf(name) {
    return status.find((s) => s.name.toLowerCase() === name.toLowerCase());
  }

  function ruleCount(s) {
    if (!s?.rules) return 0;
    const r = s.rules;
    return r.qname + r.wildcard + r.client_ip + r.response_ip + (r.nsdname || 0) + (r.nsip || 0);
  }

  async function saveAll(next, message) {
    saving = true;
    error = null;
    notice = null;
    try {
      await api.updateSettings({ rpz: next });
      zones = next;
      notice = message;
      edit = null;
      // Remote zones load in the background; give them a moment.
      await loadStatus();
      setTimeout(loadStatus, 1500);
    } catch (e) {
      error = formatApiError(e);
    } finally {
      saving = false;
    }
  }

  function startEdit(index) {
    notice = null;
    error = null;
    const z = index === null ? null : zones[index];
    edit = {
      index,
      name: z?.name || '',
      enabled: z ? z.enabled !== false : true,
      source: z?.source || 'local',
      rules: z?.rules || '',
      url: z?.url || '',
      primaries: (z?.primaries || []).join('\n'),
      tsig_key: z?.tsig_key || '',
      refresh_secs: z?.refresh_secs || 3600,
      policy: z?.policy || 'given',
      cname_target: z?.cname_target || '',
    };
  }

  function closeEdit() {
    if (!saving) edit = null;
  }

  function saveZone() {
    const zone = {
      name: edit.name.trim(),
      enabled: edit.enabled,
      source: edit.source,
      rules: edit.source === 'local' ? edit.rules : '',
      url: edit.source === 'url' ? edit.url.trim() : '',
      primaries:
        edit.source === 'transfer'
          ? edit.primaries.split(/[\n,]/).map((s) => s.trim()).filter(Boolean)
          : [],
      tsig_key: edit.source === 'transfer' ? edit.tsig_key : '',
      refresh_secs: Number(edit.refresh_secs) || 3600,
      policy: edit.policy,
      cname_target: edit.policy === 'cname' ? edit.cname_target.trim() : '',
    };
    const next = [...zones];
    if (edit.index === null) next.push(zone);
    else next[edit.index] = zone;
    saveAll(next, edit.index === null ? `Zone "${zone.name}" added.` : `Zone "${zone.name}" saved.`);
  }

  function removeZone(index) {
    const name = zones[index].name;
    if (!confirm(`Delete response policy zone "${name}"?`)) return;
    saveAll(zones.filter((_, i) => i !== index), `Zone "${name}" deleted.`);
  }

  function move(index, by) {
    const next = [...zones];
    const [z] = next.splice(index, 1);
    next.splice(index + by, 0, z);
    saveAll(next, 'Order saved.');
  }

  async function refreshNow() {
    notice = null;
    error = null;
    try {
      await api.rpzRefresh();
      notice = 'Checking the zones for changes...';
      setTimeout(loadStatus, 1500);
    } catch (e) {
      error = formatApiError(e);
    }
  }

  async function runTest() {
    testResult = null;
    error = null;
    try {
      testResult = await api.rpzTest(testClient.trim(), testDomain.trim());
    } catch (e) {
      error = formatApiError(e);
    }
  }

  function sourceLabel(z) {
    if (z.source === 'url') return 'URL';
    if (z.source === 'transfer') return 'Zone Transfer';
    return 'Local Rules';
  }

  function policyLabel(value) {
    return POLICIES.find((p) => p.value === value)?.label || value;
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

{#if !loaded}
  {#if !error}<div class="card"><p class="muted">Loading...</p></div>{/if}
{:else}
  <div class="card" style="margin-bottom: 14px">
    <div class="spread" style="margin-bottom: 10px; gap: 10px; flex-wrap: wrap">
      <h3 style="margin: 0">Response Policy Zones ({zones.length})</h3>
      <div class="row" style="gap: 8px">
        <button class="secondary" onclick={loadStatus}>Reload</button>
        {#if isAdmin}
          {#if zones.some((z) => z.source !== 'local')}
            <button class="secondary" onclick={refreshNow}>Check for Changes Now</button>
          {/if}
          <button onclick={() => startEdit(null)}>Add Zone</button>
        {/if}
      </div>
    </div>
    {#if zones.length === 0}
      <p class="muted">
        No response policy zones yet. Add one to use a threat-intelligence
        feed (by zone transfer or URL), or to write your own DNS firewall
        rules.
      </p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>Zone</th><th>Source</th><th>Policy</th><th class="num">Rules</th><th>Loaded</th><th class="num">Matches</th>{#if isAdmin}<th class="num">Actions</th>{/if}</tr>
          </thead>
          <tbody>
            {#each zones as z, i (z.name)}
              {@const s = statusOf(z.name)}
              <tr class:disabled={z.enabled === false}>
                <td>
                  <strong>{z.name}</strong>
                  {#if z.enabled === false}<span class="pill">Disabled</span>{/if}
                  {#if s?.last_error}<div class="err small" title={s.last_error}>{s.last_error}</div>{/if}
                </td>
                <td class="muted">{sourceLabel(z)}</td>
                <td class="muted">{policyLabel(z.policy || 'given')}</td>
                <td class="num" title={s?.rules ? `${s.rules.qname} names, ${s.rules.wildcard} wildcards, ${s.rules.client_ip} client IPs, ${s.rules.response_ip} answer IPs, ${s.rules.nsdname || 0} name server names, ${s.rules.nsip || 0} name server IPs${s.rules.unsupported ? `, ${s.rules.unsupported} unsupported (skipped)` : ''}` : ''}>
                  {s?.loaded ? ruleCount(s).toLocaleString() : '-'}
                </td>
                <td class="muted nowrap">
                  {#if s?.last_loaded}{formatDateTime(s.last_loaded)}{#if s.serial != null}<div class="small">Serial {s.serial}</div>{/if}{:else}{z.enabled === false ? '-' : 'Not yet'}{/if}
                </td>
                <td class="num">{(s?.hits || 0).toLocaleString()}</td>
                {#if isAdmin}
                  <td class="num">
                    <div class="row" style="gap: 6px; justify-content: flex-end">
                      <IconButton icon="up" label="Move {z.name} up" onclick={() => move(i, -1)} disabled={i === 0 || saving} />
                      <IconButton icon="down" label="Move {z.name} down" onclick={() => move(i, 1)} disabled={i === zones.length - 1 || saving} />
                      <IconButton icon="edit" label="Edit" onclick={() => startEdit(i)} />
                      <IconButton icon="delete" variant="danger" label="Delete {z.name}" onclick={() => removeZone(i)} />
                    </div>
                  </td>
                {/if}
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
    <p class="muted help">
      A response policy zone (RPZ) is a DNS firewall written as a zone: each
      rule names a trigger (a domain, <code>*.domain</code>, a client address
      or an address in the answer) and an action (NXDOMAIN, NODATA, drop,
      TCP-only, passthru, or records to answer with instead). Zones are
      checked top to bottom and the first match decides. They apply to what
      the blocklists and filtering groups let through, and a name on the
      allow list is never affected. A zone whose source cannot be loaded
      keeps its last loaded rules.
    </p>
  </div>

  <div class="card">
    <h3 style="margin: 0 0 10px">Test a Query</h3>
    <p class="muted help" style="margin: 0 0 10px">
      Check which zones match a domain asked by a given client (client-IP and
      domain rules; rules on answer addresses and name servers need the real
      answer).
    </p>
    <form class="row" style="flex-wrap: wrap; gap: 8px" onsubmit={(e) => { e.preventDefault(); runTest(); }}>
      <input style="flex: 1; min-width: 160px" bind:value={testClient} placeholder="Client IP, e.g. 192.168.1.50" />
      <input style="flex: 1; min-width: 160px" bind:value={testDomain} placeholder="Domain, e.g. bad.example.com" />
      <button type="submit" disabled={!testClient.trim() || !testDomain.trim()}>Test</button>
    </form>
    {#if testResult}
      <div class="result">
        {#if testResult.allowlisted}
          <span class="pill ok">Allowed</span><span class="muted">The domain is on the allow list, so no zone applies.</span>
        {:else if !testResult.matches.length}
          <span class="pill ok">No Match</span><span class="muted">No zone matches this query.</span>
        {:else}
          {#each testResult.matches as m, i (i)}
            <div class="match">
              <span class="pill" class:err={!m.log_only && i === testResult.matches.findIndex((x) => !x.log_only)}>{m.action}</span>
              <span><strong>{m.zone}</strong> <span class="muted">{m.trigger}</span></span>
              {#if m.log_only}<span class="muted">(log only)</span>{:else if i !== testResult.matches.findIndex((x) => !x.log_only)}<span class="muted">(an earlier zone decides)</span>{/if}
            </div>
          {/each}
        {/if}
      </div>
    {/if}
  </div>
{/if}

{#if edit}
  <div class="modal-backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && closeEdit()}>
    <div class="modal card" role="dialog" aria-modal="true" aria-labelledby="rpz-title">
      <div class="spread modal-title">
        <h3 id="rpz-title" style="margin: 0">{edit.index === null ? 'Add Response Policy Zone' : `Edit Zone - ${zones[edit.index].name}`}</h3>
        <button class="secondary" style="padding: 2px 10px" onclick={closeEdit} aria-label="Close">✕</button>
      </div>
      {#if error}<p class="dialog-error">{error}</p>{/if}
      <div class="grid2">
        <label>Zone Name <input bind:value={edit.name} placeholder="rpz.example.com" spellcheck="false" /></label>
        <label>Rules From
          <select bind:value={edit.source}>
            {#each SOURCES as s (s.value)}<option value={s.value}>{s.label}</option>{/each}
          </select>
        </label>
      </div>
      <label class="checkbox"><input type="checkbox" bind:checked={edit.enabled} /><span>Enabled</span></label>

      {#if edit.source === 'local'}
        <div class="section-title">Rules</div>
        <textarea rows="10" class="mono" bind:value={edit.rules} spellcheck="false" placeholder={'; One rule per line: trigger, then the action.\nbad.example.com          CNAME .\n*.ads.example.com        CNAME .\nok.ads.example.com       CNAME rpz-passthru.\nquiet.example.com        CNAME rpz-drop.\nempty.example.com        CNAME *.\nlocal.example.com        A 192.0.2.80\nwalled.example.com       CNAME garden.example.net.\n32.7.1.168.192.rpz-client-ip  CNAME rpz-drop.\n24.0.113.0.203.rpz-ip    CNAME .'}></textarea>
        <p class="muted help">
          Zone-file lines (owner names relative to the zone). Actions:
          <code>CNAME .</code> NXDOMAIN, <code>CNAME *.</code> NODATA,
          <code>CNAME rpz-passthru.</code> exempt, <code>CNAME rpz-drop.</code>
          no answer, <code>CNAME rpz-tcp-only.</code> retry over TCP; any other
          records are answered instead (a <code>CNAME</code> to another name
          is a walled garden). Triggers: a domain or <code>*.domain</code>; a
          client address as <code>prefix.reversed-address.rpz-client-ip</code>
          (<code>32.7.1.168.192</code> is 192.168.1.7); an answer address as
          <code>prefix.reversed-address.rpz-ip</code>; a name server of the
          answer's domain as <code>ns.example.rpz-nsdname</code> (or
          <code>*.example.rpz-nsdname</code>) or by address as
          <code>prefix.reversed-address.rpz-nsip</code>. IPv6 words are
          reversed too, with <code>zz</code> for <code>::</code>.
        </p>
      {:else if edit.source === 'url'}
        <div class="section-title">Source</div>
        <div class="grid2">
          <label>Zone File URL <input bind:value={edit.url} placeholder="https://feed.example/rpz.zone" spellcheck="false" /></label>
          <label>Check for Changes Every (Seconds) <input type="number" min="60" bind:value={edit.refresh_secs} /></label>
        </div>
      {:else}
        <div class="section-title">Source</div>
        <div class="grid2">
          <label>Feed Servers <textarea rows="2" bind:value={edit.primaries} placeholder={'192.0.2.53\n[2001:db8::53]:53'} spellcheck="false"></textarea></label>
          <label>TSIG Key
            <select bind:value={edit.tsig_key}>
              <option value="">None</option>
              {#each tsigKeys as k (k)}<option value={k}>{k}</option>{/each}
            </select>
          </label>
          <label>Check for Changes Every (Seconds) <input type="number" min="60" bind:value={edit.refresh_secs} /></label>
        </div>
        <p class="muted help">
          The zone is transferred (AXFR) from the first server that answers,
          and again only when its SOA serial changes. Feeds that sign
          transfers need their TSIG key, added under Settings → Zones.
        </p>
      {/if}

      <div class="section-title">Policy</div>
      <div class="grid2">
        <label>Action
          <select bind:value={edit.policy}>
            {#each POLICIES as p (p.value)}<option value={p.value}>{p.label}</option>{/each}
          </select>
        </label>
        {#if edit.policy === 'cname'}
          <label>Redirect To <input bind:value={edit.cname_target} placeholder="blocked.example.net" spellcheck="false" /></label>
        {/if}
      </div>
      <p class="muted help">
        Overrides the actions written in the zone. Log Only is a safe way to
        try a new feed: matches are counted in the Matches column, and
        queries are answered as if the zone were not there.
      </p>

      <div class="row actions">
        <button onclick={saveZone} disabled={saving || !edit.name.trim()}>
          {saving ? 'Saving...' : edit.index === null ? 'Add Zone' : 'Save Zone'}
        </button>
        <button class="secondary" onclick={closeEdit} disabled={saving}>Cancel</button>
      </div>
    </div>
  </div>
{/if}

<style>
  textarea { width: 100%; }
  .mono { font-family: ui-monospace, "Cascadia Code", monospace; font-size: 0.82rem; }
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; color: var(--muted); }
  .modal-backdrop { position: fixed; inset: 0; background: rgb(0 0 0 / 0.65); display: grid; place-items: center; padding: 20px; z-index: 50; }
  .modal { width: min(760px, 100%); max-height: calc(100vh - 40px); overflow: auto; }
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
  .dialog-error { color: var(--danger); margin: 0 0 10px; }
  .result { margin-top: 12px; display: flex; flex-direction: column; gap: 8px; }
  .match { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .nowrap { white-space: nowrap; }
  .small { font-size: 0.78rem; }
  .err { color: var(--danger); max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  tr.disabled td { opacity: 0.6; }
  @media (max-width: 640px) {
    .grid2 { grid-template-columns: 1fr; }
  }
</style>

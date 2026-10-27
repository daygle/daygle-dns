<script>
  import IconButton from '../IconButton.svelte';
  import { api, formatApiError } from '../api.js';
  import NetworkPicker from '../NetworkPicker.svelte';
  import { formatDateTime } from '../datetime.svelte.js';
  import { deviceName, loadDeviceNames } from '../devices.svelte.js';

  let groups = $state([]);
  // Named networks (Clients -> Networks) for the client picker.
  let networks = $state([]);
  // Blocklists (Filtering -> Blocklists) set to apply to selected groups only.
  let groupLists = $state([]);
  // Services a group can block with one tick, and their categories in order.
  let services = $state([]);
  const serviceCategories = $derived([...new Set(services.map((s) => s.category))]);
  let error = $state(null);
  let notice = $state(null);
  let saving = $state(false);

  // The group being edited (a form copy), or null when the dialog is closed.
  let edit = $state(null);

  // Tester.
  let testClient = $state('');
  let testDomain = $state('');
  let testListener = $state('');
  let testResult = $state(null);

  const DAYS = [
    ['mon', 'Mon'], ['tue', 'Tue'], ['wed', 'Wed'], ['thu', 'Thu'],
    ['fri', 'Fri'], ['sat', 'Sat'], ['sun', 'Sun'],
  ];

  const RESPONSES = [
    { value: 'nx_domain', label: 'NXDOMAIN (Does Not Exist)' },
    { value: 'refused', label: 'REFUSED' },
    { value: 'no_data', label: 'NODATA (Empty Answer)' },
    { value: 'redirect', label: 'Redirect to Address' },
  ];

  async function load() {
    api.networks().then((data) => { networks = data.networks || []; }).catch(() => {});
    api.blockableServices().then((data) => { services = data.services || []; }).catch(() => {});
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
          clients: [...group.clients],
          allow: group.allow.join('\n'),
          block: group.block.join('\n'),
          allow_regex: group.allow_regex.join('\n'),
          block_regex: group.block_regex.join('\n'),
          blocklists: [...(group.blocklists || [])],
          responseKind: group.response?.kind || 'nx_domain',
          redirectAddr: group.response?.address || '0.0.0.0',
          ai_blocking: group.ai_blocking !== false,
          safe_search: !!group.safe_search,
          youtube_restricted: !!group.youtube_restricted,
          schedule: (group.schedule || []).map((w) => ({ ...w, days: [...(w.days || [])] })),
          blocked_services: [...(group.blocked_services || [])],
        }
      : {
          id: null,
          originalName: null,
          name: '',
          enabled: true,
          clients: [],
          allow: '',
          block: '',
          allow_regex: '',
          block_regex: '',
          blocklists: [],
          responseKind: 'nx_domain',
          redirectAddr: '0.0.0.0',
          ai_blocking: true,
          safe_search: false,
          youtube_restricted: false,
          schedule: [],
          blocked_services: [],
        };
  }

  function toggleService(id) {
    edit.blocked_services = edit.blocked_services.includes(id)
      ? edit.blocked_services.filter((s) => s !== id)
      : [...edit.blocked_services, id];
  }

  function serviceNames(ids) {
    return ids.map((id) => services.find((s) => s.id === id)?.name || id).join(', ');
  }

  function addWindow() {
    edit.schedule = [
      ...edit.schedule,
      { days: ['mon', 'tue', 'wed', 'thu', 'fri'], start: '08:00', end: '15:00' },
    ];
  }

  function toggleDay(w, day) {
    w.days = w.days.includes(day)
      ? w.days.filter((d) => d !== day)
      : DAYS.map(([d]) => d).filter((d) => d === day || w.days.includes(d));
  }

  // "Mon-Fri 08:00-15:00" for the list's tooltip.
  function describeWindow(w) {
    const days = w.days?.length
      ? DAYS.filter(([d]) => w.days.includes(d)).map(([, l]) => l).join(', ')
      : 'Every day';
    return `${days} ${w.start}-${w.end}`;
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
      clients: [...edit.clients],
      allow: parseList(edit.allow),
      block: parseList(edit.block),
      allow_regex: parseList(edit.allow_regex),
      block_regex: parseList(edit.block_regex),
      blocklists: edit.blocklists,
      response,
      ai_blocking: edit.ai_blocking,
      safe_search: edit.safe_search,
      youtube_restricted: edit.youtube_restricted,
      schedule: edit.schedule,
      blocked_services: edit.blocked_services,
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
    if (!confirm(`Delete filtering group "${group.name}"?`)) return;
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
      testResult = await api.testBlocking(
        testClient.trim(),
        testDomain.trim(),
        testListener || undefined,
      );
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
    loadDeviceNames();
  });

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
    <h3 style="margin: 0">Filtering Groups ({groups.length})</h3>
    <button onclick={() => startEdit(null)}>Add Group</button>
  </div>

  {#if groups.length === 0}
    <p class="muted">
      No filtering groups yet. Add one to give a set of devices (by IP or network)
      their own allow and block rules.
    </p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>Name</th><th>Clients</th><th>Rules</th><th>Blocked Response</th><th>Last Modified</th><th class="num">Actions</th></tr>
        </thead>
        <tbody>
          {#each groups as g, i (g.id)}
            <tr class:disabled={!g.enabled}>
              <td>
                <strong>{g.name}</strong>
                {#if !g.enabled}<span class="pill">Disabled</span>{/if}
                {#if g.ai_blocking === false}<span class="pill" title="The AI never auto-blocks these clients' queries">AI Off</span>{/if}
                {#if g.safe_search}<span class="pill" title="Google, Bing and DuckDuckGo always use Safe Search for these clients">Safe Search</span>{/if}
                {#if g.youtube_restricted}<span class="pill" title="YouTube always uses Restricted Mode for these clients">YouTube Restricted</span>{/if}
                {#if g.schedule?.length}<span class="pill" title={'Applies only: ' + g.schedule.map(describeWindow).join('; ')}>Scheduled</span>{/if}
              </td>
              <td class="muted">{g.clients.length ? g.clients.map((c) => (deviceName(c) ? `${deviceName(c)} (${c})` : c)).join(', ') : 'All Clients'}</td>
              <td class="muted">
                {count(g.allow.length + g.allow_regex.length, 'Allow Rule')} ·
                {count(g.block.length + g.block_regex.length, 'Block Rule')}
                {#if g.blocklists?.length}
                  <div title={g.blocklists.join(', ')}>{count(g.blocklists.length, 'Blocklist')}</div>
                {/if}
                {#if g.blocked_services?.length}
                  <div title={serviceNames(g.blocked_services)}>{count(g.blocked_services.length, 'Blocked Service')}</div>
                {/if}
              </td>
              <td class="muted">{responseLabel(g.response)}</td>
              <td class="muted nowrap" title={g.last_modified_at || ''}>
                {g.last_modified_at ? formatDateTime(g.last_modified_at) : '-'}
              </td>
              <td class="num">
                <div class="row" style="gap: 6px; justify-content: flex-end">
                  <IconButton icon="up" label="Move {g.name} up" onclick={() => move(g, 'up')} disabled={i === 0} />
                  <IconButton icon="down" label="Move {g.name} down" onclick={() => move(g, 'down')} disabled={i === groups.length - 1} />
                  <IconButton icon="edit" label="Edit" onclick={() => startEdit(g)} />
                  <IconButton icon="delete" variant="danger" label="Delete {g.name}" onclick={() => removeGroup(g)} />
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
    checked. A group with no client networks covers every client. AI
    auto-blocking, Safe Search and YouTube Restricted Mode follow the first
    group covering the client: a group can turn AI auto-blocking off, or Safe
    Search on, for its clients.
  </p>
</div>

<div class="card">
  <h3 style="margin: 0 0 10px">Test a Query</h3>
  <p class="muted help" style="margin: 0 0 10px">
    Check what the filtering groups would do with a domain asked by a given client.
  </p>
  <form class="row" style="flex-wrap: wrap; gap: 8px" onsubmit={(e) => { e.preventDefault(); runTest(); }}>
    <input style="flex: 1; min-width: 160px" bind:value={testClient} placeholder="Client IP, e.g. 192.168.1.50" />
    <input style="flex: 1; min-width: 160px" bind:value={testDomain} placeholder="Domain, e.g. ads.example.com" />
    <select bind:value={testListener} title="Listener the query arrives on">
      <option value="">Plain DNS</option>
      <option value="dot">DoT</option>
      <option value="doh">DoH</option>
      <option value="doq">DoQ</option>
    </select>
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
      {#if testResult.ai_blocking !== undefined}
        <span class="muted ai-note">
          AI auto-blocking: {testResult.ai_blocking ? 'On' : 'Off'}
          {testResult.ai_group ? `(group "${testResult.ai_group}")` : '(client is in no group)'}
        </span>
      {/if}
      {#if testResult.scheduled_off?.length}
        <span class="muted ai-note">
          Outside their schedule now, so skipped: {testResult.scheduled_off.join(', ')}
        </span>
      {/if}
      {#if testResult.safe_search_target}
        <span class="muted ai-note">
          Safe Search: answered with <code>{testResult.safe_search_target}</code>
        </span>
      {/if}
    </div>
  {/if}
</div>

{#if edit}
  <div class="modal-backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && closeEdit()}>
    <div class="modal card" role="dialog" aria-modal="true" aria-labelledby="group-title">
      <div class="spread modal-title">
        <h3 id="group-title" style="margin: 0">{edit.id ? `Edit Filtering Group - ${edit.originalName}` : 'Add Filtering Group'}</h3>
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
      <NetworkPicker {networks} listeners devices bind:value={edit.clients} />
      <p class="muted help">
        Tick named networks, pick named devices (Clients → Devices) and/or
        type addresses. A device is matched by its address, so give it a
        DHCP reservation to keep the address fixed. DoT, DoH and DoQ match any
        client connecting over that encrypted listener, wherever it is - use
        them (alone or combined) to give public/remote users their own rules.
        Leave empty for every client.
      </p>

      <div class="section-title">Schedule</div>
      {#each edit.schedule as w, i (i)}
        <div class="window">
          <div class="days">
            {#each DAYS as [day, label] (day)}
              <label class="day" class:on={w.days.includes(day)}>
                <input type="checkbox" checked={w.days.includes(day)} onchange={() => toggleDay(w, day)} />{label}
              </label>
            {/each}
          </div>
          <label class="time">From <input type="time" bind:value={w.start} required /></label>
          <label class="time">Until <input type="time" bind:value={w.end} required /></label>
          <button class="secondary" onclick={() => (edit.schedule = edit.schedule.filter((_, j) => j !== i))} aria-label="Remove time window">✕</button>
        </div>
      {/each}
      <button class="secondary" style="margin-top: 4px" onclick={addWindow}>Add Time Window</button>
      <p class="muted help">
        {#if edit.schedule.length}
          The group applies only inside these windows; at other times it is
          skipped as if it did not exist, so the next group covering the
          client (or nothing) applies.
        {:else}
          The group applies all the time. Add a time window to apply it only
          at certain times, such as school hours or bedtime.
        {/if}
        A window ending earlier than it starts runs past midnight (21:00
        until 07:00 on Friday covers Friday night into Saturday morning).
        Times use the server's time zone under Settings → General → Date &amp;
        Time Defaults.
      </p>

      <div class="section-title">Blocked Services</div>
      {#each serviceCategories as category (category)}
        <div class="service-category">{category}</div>
        <div class="services">
          {#each services.filter((s) => s.category === category) as s (s.id)}
            <label class="service" class:on={edit.blocked_services.includes(s.id)} title={s.domains.join(', ')}>
              <input type="checkbox" checked={edit.blocked_services.includes(s.id)} onchange={() => toggleService(s.id)} />{s.name}
            </label>
          {/each}
        </div>
      {/each}
      <p class="muted help">
        Blocks every domain the service uses, and their subdomains (hover a
        service to see them). Combine with a schedule to block, for example,
        games and social media at bedtime only. The Allow list below still
        wins. Apps change their domains from time to time, so a blocked
        service may occasionally work partly until the list is updated.
      </p>

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
          No blocklists are set to apply to selected filtering groups. Under
          Filtering → Blocklists, add or edit a list and set <strong>Applies To</strong>
          to <strong>Selected Filtering Groups Only</strong>, then tick it here.
        </p>
      {/if}

      <div class="section-title">AI Auto-Blocking</div>
      <label class="checkbox"><input type="checkbox" bind:checked={edit.ai_blocking} /><span>Let the AI auto-block these clients' queries</span></label>
      <p class="muted help">
        Applies when the AI scanner is in Enforce mode. A client follows the
        first group (from the top) that covers it; clients in no group are
        covered. To use the AI for some groups only, add a group covering every
        client with this off and move it to the bottom.
      </p>

      <div class="section-title">Safe Search</div>
      <label class="checkbox"><input type="checkbox" bind:checked={edit.safe_search} /><span>Force Safe Search on Google, Bing and DuckDuckGo</span></label>
      <label class="checkbox"><input type="checkbox" bind:checked={edit.youtube_restricted} /><span>Force YouTube Restricted Mode</span></label>
      <p class="muted help">
        Hides explicit results whatever the device or account settings say.
        A client follows the first group that covers it. To turn these on for
        every client, use Filtering → Response Filters instead.
      </p>

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
          {saving ? 'Saving...' : edit.id ? 'Save Group' : 'Add Group'}
        </button>
        <button class="secondary" onclick={closeEdit} disabled={saving}>Cancel</button>
      </div>
    </div>
  </div>
{/if}

<style>
  textarea { width: 100%; }
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; color: var(--muted); }
  .modal-backdrop { position: fixed; inset: 0; background: rgb(0 0 0 / 0.65); display: grid; place-items: center; padding: 20px; z-index: 50; }
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
  .ai-note { flex-basis: 100%; }
  .window { display: flex; align-items: flex-end; gap: 10px; flex-wrap: wrap; margin-bottom: 8px; }
  .days { display: flex; gap: 4px; flex-wrap: wrap; }
  .day { flex-direction: row; align-items: center; gap: 0; padding: 5px 8px; border: 1px solid var(--border); border-radius: 6px; cursor: pointer; color: var(--muted); }
  .day.on { border-color: var(--accent); color: var(--accent); }
  .day input { position: absolute; opacity: 0; width: 1px; height: 1px; }
  .day:focus-within { outline: 2px solid var(--accent); outline-offset: 1px; }
  .time { width: 120px; }
  .service-category { font-size: 0.78rem; color: var(--muted); margin: 8px 0 4px; }
  .services { display: flex; flex-wrap: wrap; gap: 6px; }
  .service { flex-direction: row; align-items: center; gap: 0; padding: 5px 10px; border: 1px solid var(--border); border-radius: 999px; cursor: pointer; color: var(--text); font-size: 0.82rem; }
  .service.on { border-color: var(--danger); color: var(--danger); }
  .service input { position: absolute; opacity: 0; width: 1px; height: 1px; }
  .service:focus-within { outline: 2px solid var(--accent); outline-offset: 1px; }
  @media (max-width: 640px) {
    .grid2 { grid-template-columns: 1fr; }
  }
</style>

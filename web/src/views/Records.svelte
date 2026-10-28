<script>
  import IconButton from '../IconButton.svelte';
  import { api, formatApiError } from '../api.js';
  import { formatDateTime } from '../datetime.svelte.js';
  import { duration } from '../aiLabels.js';
  import { defaultReverseZone, reverseRecordName } from '../reverseZone.js';
  import ColumnPicker from '../ColumnPicker.svelte';
  import { isHidden } from '../columns.svelte.js';

  const COLUMNS = [
    { key: 'name', label: 'Name', locked: true },
    { key: 'type', label: 'Type' },
    { key: 'value', label: 'Value' },
    { key: 'ttl', label: 'TTL' },
    { key: 'status', label: 'Status' },
    { key: 'last-used', label: 'Last Used' },
    { key: 'last-modified', label: 'Last Modified' },
  ];
  const show = (key) => !isHidden('records', key);

  // The zone to preselect, passed when coming from the Zones page.
  let { zoneId = null, onSelectZone = () => {} } = $props();

  // Server-wide default TTL (Settings → Zones), used to pre-fill
  // the TTL field of new records.
  let defaultTtl = $state(3600);

  // Value examples in zone-file presentation format, which is what the server
  // parses. MX and SRV carry their priority inside the value.
  const EXAMPLES = {
    A: '192.0.2.1',
    AAAA: '2001:db8::1',
    CNAME: 'target.example.com.',
    ALIAS: 'myapp.cdn.example.net.',
    MX: '10 mail.example.com.',
    TXT: '"v=spf1 mx -all"',
    NS: 'ns1.example.com.',
    SRV: '10 5 5060 sip.example.com.',
    PTR: 'host.example.com.',
    AUTOPTR: 'ip-{ip}.home.arpa.',
    CAA: '0 issue "letsencrypt.org"',
    HTTPS: '1 . alpn=h2,h3',
    SVCB: '1 svc.example.com. port=8443',
    DS: '12345 13 2 3F2A6B1C...',
    TLSA: '3 1 1 0C72AC70B745...',
    SSHFP: '4 2 9F6B2C1D0E3A...',
    NAPTR: '100 10 "S" "SIP+D2U" "" _sip._udp.example.com.',
  };
  const TYPES = Object.keys(EXAMPLES);

  let zones = $state([]);
  const ptrTarget = $derived.by(() => {
    if (!edit || !['A', 'AAAA'].includes(edit.rtype)) return null;
    const name = reverseRecordName(edit.content);
    if (!name) return null;
    const lowerName = name.toLowerCase();
    const zone = zones
      .filter((candidate) => {
        if (candidate.enabled === false) return false;
        const zoneName = candidate.name.replace(/\.$/, '').toLowerCase();
        return lowerName === zoneName || lowerName.endsWith(`.${zoneName}`);
      })
      .sort((a, b) => b.name.length - a.name.length)[0] || null;
    const zoneName = zone?.name.replace(/\.$/, '').toLowerCase();
    const owner = zone
      ? lowerName === zoneName
        ? '@'
        : name.slice(0, name.length - zoneName.length - 1)
      : null;
    return { name, zone, owner };
  });
  let zonesLoaded = $state(false);
  let selected = $state(null);
  let records = $state([]);
  let recordsLoading = $state(false);
  // `error` shows in red, `notice` (success) in green; failures while the
  // record dialog is open show inside it.
  let error = $state(null);
  let notice = $state(null);
  let dialogError = $state(null);
  let saving = $state(false);
  let edit = $state(null);
  // Health checks of this zone's records, by record id, and the one being
  // edited (null when the dialog is closed).
  let health = $state({});
  let healthEdit = $state(null);
  // Load-balancing weights of this zone's records, by record id.
  let weights = $state({});

  // Record list filter.
  let filterText = $state('');
  let filterType = $state('');
  const typesPresent = $derived([...new Set(records.map((r) => r.rtype))].sort());
  const shown = $derived(
    records.filter((r) => {
      if (filterType && r.rtype !== filterType) return false;
      const q = filterText.trim().toLowerCase();
      return !q || r.name.toLowerCase().includes(q) || r.content.toLowerCase().includes(q);
    }),
  );

  // Searchable zone picker state.
  let query = $state('');
  let pickerOpen = $state(false);
  let pickerBlurTimer;

  // Matches the typed text (case-insensitive). While the box simply shows the
  // name of the selected zone (no active search) the full list is offered so a
  // different zone can be picked without first clearing the input.
  const zoneMatches = $derived(
    query === (selected?.name ?? '')
      ? zones
      : zones.filter((z) => z.name.toLowerCase().includes(query.trim().toLowerCase()))
  );

  async function loadZones() {
    error = null;
    try {
      zones = await api.zones();
      zonesLoaded = true;
      if (zoneId != null) {
        const match = zones.find((z) => String(z.id) === String(zoneId));
        if (match) await select(match, { notify: false });
      }
    } catch (e) {
      error = formatApiError(e);
    }
  }

  async function select(zone, { notify = true } = {}) {
    selected = zone;
    query = zone.name;
    pickerOpen = false;
    edit = null;
    notice = null;
    filterText = '';
    filterType = '';
    if (notify) onSelectZone(zone.id);
    await loadRecords(zone.id);
  }

  async function loadRecords(zoneId) {
    recordsLoading = true;
    error = null;
    try {
      records = await api.records(zoneId);
      const checks = await api.healthChecks().catch(() => []);
      health = Object.fromEntries(checks.filter((c) => c.zone_id === zoneId).map((c) => [c.record_id, c]));
      weights = await api.recordWeights().catch(() => ({}));
    } catch (e) {
      error = formatApiError(e);
      records = [];
    } finally {
      recordsLoading = false;
    }
  }

  function openPicker() {
    pickerOpen = true;
  }

  function closePicker() {
    pickerOpen = false;
    // Dropping focus without picking leaves a clean box: revert to the
    // selected zone's name (or empty when nothing is selected).
    query = selected?.name ?? '';
  }

  function onPickerBlur() {
    clearTimeout(pickerBlurTimer);
    // Delay so a click on a list item registers before the list closes.
    pickerBlurTimer = setTimeout(closePicker, 120);
  }

  function onPickerKeydown(e) {
    if (e.key === 'Enter') {
      const first = zoneMatches[0];
      if (first) {
        e.preventDefault();
        select(first);
      }
    } else if (e.key === 'Escape') {
      e.preventDefault();
      closePicker();
    }
  }

  // Names are stored fully qualified; show them relative to the zone the
  // way zone files do ("www", "@" for the zone itself).
  function relativeName(name) {
    if (!selected) return name;
    const zone = selected.name.replace(/\.$/, '').toLowerCase();
    const n = name.replace(/\.$/, '').toLowerCase();
    if (n === zone) return '@';
    if (n.endsWith(`.${zone}`)) return name.slice(0, n.length - zone.length - 1);
    return name;
  }

  function startEdit(record) {
    notice = null;
    error = null;
    dialogError = null;
    // The dialog owns a record's staged (disabled) state, so remember what it
    // was to tell a real toggle from an untouched checkbox.
    edit = record
      ? {
          ...record,
          name: relativeName(record.name),
          updatePtr: true,
          createZone: false,
          isNew: false,
          disabledBefore: Boolean(record.disabled),
          weight: weights[record.id] || 0,
          weightBefore: weights[record.id] || 0,
        }
      : {
          name: '',
          rtype: 'A',
          content: '',
          ttl: defaultTtl,
          priority: 0,
          updatePtr: true,
          createZone: false,
          isNew: true,
          disabled: false,
          disabledBefore: false,
          weight: 0,
          weightBefore: 0,
        };
  }

  function closeEdit() {
    if (!saving) edit = null;
  }

  async function saveEdit() {
    if (!edit || !selected) return;
    dialogError = null;
    saving = true;
    try {
      const body = {
        name: edit.name,
        rtype: edit.rtype,
        content: edit.content,
        ttl: Number(edit.ttl) || defaultTtl,
        priority: Number(edit.priority) || 0,
      };
      // The server keeps the PTR record in step (and can create the
      // reverse zone) for A and AAAA records.
      const ptrQuery =
        ['A', 'AAAA'].includes(edit.rtype) && edit.updatePtr && ptrTarget
          ? `update_ptr=true${!ptrTarget.zone && edit.createZone ? '&create_reverse_zone=true' : ''}`
          : '';
      // Editing replaces the record in place; only new records are added.
      const savedRecord = edit.isNew
        ? await api.upsertRecord(selected.id, body, ptrQuery)
        : await api.replaceRecord(selected.id, edit.id, body, ptrQuery);
      // Saving keeps a record's staged state, so only a checkbox that moved
      // needs the separate endpoint (the serial is bumped with it).
      let stagedNotice = '';
      let staged = null;
      if (Boolean(edit.disabled) !== edit.disabledBefore) {
        // A disabled record's PTR goes too, and comes back with it.
        staged = await api.setRecordDisabled(
          selected.id,
          savedRecord.id,
          Boolean(edit.disabled),
          ptrQuery ? 'update_ptr=true' : '',
        );
        stagedNotice = edit.disabled ? ' It is disabled, so it is not served.' : ' It is served again.';
      }
      // The weight is kept beside the record (like its health check).
      const weight = Math.max(0, Math.round(Number(edit.weight) || 0));
      if (['A', 'AAAA'].includes(body.rtype) && weight !== edit.weightBefore) {
        await api.setRecordWeight(selected.id, savedRecord.id, weight);
      }
      const ptrNotice = reverseNotice(combineReverse(savedRecord?.reverse, staged?.reverse));
      // A new reverse zone: refresh the list (the PTR option looks there).
      if (savedRecord?.reverse?.zone_created) zones = await api.zones();
      notice = `${body.rtype} record ${edit.isNew ? 'added' : 'saved'} and applied live.${stagedNotice}${ptrNotice}`;
      edit = null;
      await loadRecords(selected.id);
    } catch (e) {
      dialogError = formatApiError(e);
    } finally {
      saving = false;
    }
  }

  // The PTR changes of a save and the disable/enable after it, together: a
  // PTR added by the save and removed by disabling the new record is no
  // change at all.
  function combineReverse(first, second) {
    if (!first || !second) return first || second;
    const added = [...(first.added || []), ...(second.added || [])];
    const removed = [...(first.removed || []), ...(second.removed || [])];
    return {
      added: added.filter((name) => !removed.includes(name)),
      removed: removed.filter((name) => !added.includes(name)),
      zone_created: first.zone_created || second.zone_created,
      problem: second.problem || first.problem,
    };
  }

  // What the server did with the PTR record, as a sentence for the notice.
  function reverseNotice(reverse) {
    if (!reverse) return '';
    const parts = [];
    if (reverse.zone_created) parts.push(`The reverse zone ${reverse.zone_created} was created.`);
    if (reverse.removed?.length) parts.push(`PTR record ${reverse.removed.join(', ')} removed.`);
    if (reverse.added?.length) parts.push(`PTR record ${reverse.added.join(', ')} added.`);
    if (reverse.problem) parts.push(`${reverse.problem.charAt(0).toUpperCase()}${reverse.problem.slice(1)}.`);
    return parts.length ? ` ${parts.join(' ')}` : '';
  }

  async function removeRecord(record) {
    if (!selected) return;
    const address = ['A', 'AAAA'].includes(record.rtype);
    const question = `Delete the ${record.rtype} record for "${relativeName(record.name)}"?`;
    if (!confirm(address ? `${question} Its PTR record, if it points to this name, is removed too.` : question)) return;
    notice = null;
    error = null;
    try {
      const result = await api.deleteRecord(selected.id, record.id, address ? 'update_ptr=true' : '');
      notice = `${record.rtype} record for "${relativeName(record.name)}" deleted.${reverseNotice(result?.reverse)}`;
      await loadRecords(selected.id);
    } catch (e) {
      error = formatApiError(e);
    }
  }

  function openHealth(record) {
    dialogError = null;
    const c = health[record.id];
    healthEdit = {
      record,
      exists: !!c,
      kind: c?.kind || 'tcp',
      port: c?.port || 443,
      path: c?.path || '/',
      host: c?.host || '',
      interval_secs: c?.interval_secs || 30,
    };
  }

  async function saveHealth() {
    if (!healthEdit || !selected) return;
    dialogError = null;
    saving = true;
    try {
      const h = healthEdit;
      await api.setHealthCheck(selected.id, h.record.id, {
        kind: h.kind,
        port: Number(h.port),
        path: h.kind === 'tcp' ? '' : h.path,
        host: h.host.trim(),
        interval_secs: Number(h.interval_secs),
      });
      notice = `Health check saved for ${h.record.content}.`;
      healthEdit = null;
      await loadRecords(selected.id);
    } catch (e) {
      dialogError = formatApiError(e);
    } finally {
      saving = false;
    }
  }

  async function removeHealth() {
    if (!healthEdit || !selected) return;
    saving = true;
    try {
      await api.deleteHealthCheck(selected.id, healthEdit.record.id);
      notice = `Health check removed: ${healthEdit.record.content} is served again whatever its state.`;
      healthEdit = null;
      await loadRecords(selected.id);
    } catch (e) {
      dialogError = formatApiError(e);
    } finally {
      saving = false;
    }
  }

  $effect(() => {
    loadZones();
    api.config().then((cfg) => {
      const ttl = cfg?.authoritative?.default_record_ttl;
      if (Number(ttl) > 0) defaultTtl = Number(ttl);
    }).catch(() => {});
  });
</script>

{#if notice}
  <div class="card notice ok">{notice}</div>
{/if}
{#if error}
  <div class="card notice error">{error}</div>
{/if}

{#if !zonesLoaded}
  <div class="card">
    <p class="muted">Loading...</p>
  </div>
{:else if zones.length === 0}
  <div class="card">
    <p class="muted" style="margin: 0">
      No zones yet. Create a zone on the Zones page, then come back here to add records.
    </p>
  </div>
{:else}
  <div class="row picker">
    <label for="zone-search" class="picker-label">Zone</label>
    <div class="picker-box">
      <input
        id="zone-search"
        class="zone-search"
        type="text"
        role="combobox"
        aria-expanded={pickerOpen}
        aria-controls="zone-list"
        aria-autocomplete="list"
        autocomplete="off"
        spellcheck="false"
        placeholder="Search zones..."
        bind:value={query}
        onfocus={openPicker}
        onblur={onPickerBlur}
        oninput={() => (pickerOpen = true)}
        onkeydown={onPickerKeydown}
      />
      <span class="picker-chevron" class:open={pickerOpen} aria-hidden="true">▾</span>
      {#if pickerOpen}
        <div id="zone-list" class="picker-list" role="listbox" tabindex="-1" onmousedown={(e) => e.preventDefault()}>
          {#if zoneMatches.length === 0}
            <div class="picker-empty">No zones match “{query.trim()}”</div>
          {:else}
            {#each zoneMatches as z (z.id)}
              <button
                type="button"
                class="picker-option"
                class:sel={selected?.id === z.id}
                role="option"
                aria-selected={selected?.id === z.id}
                onclick={() => select(z)}
              >
                <code>{z.name}</code>
                {#if z.zone_type === 'secondary'}<span class="pill">Secondary</span>{/if}
              </button>
            {/each}
          {/if}
        </div>
      {/if}
    </div>
    {#if selected}
      <span class="pill">{selected.zone_type === 'secondary' ? 'Secondary' : 'Primary'}</span>
      <span class:pill={true} class:ok={selected.dnssec}>{selected.dnssec ? 'Signed' : 'Unsigned'}</span>
    {/if}
  </div>

  {#if !selected}
    <div class="card">
      <p class="muted" style="margin: 0">Select a zone to view and edit its records.</p>
    </div>
  {:else}
    <div class="card">
      <div class="spread" style="margin-bottom: 10px">
        <h3 style="margin: 0">Records for <code>{selected.name}</code> ({records.length})</h3>
        {#if selected.zone_type !== 'secondary'}
          <div class="row" style="gap: 8px">
            <ColumnPicker table="records" columns={COLUMNS} />
            <button onclick={() => startEdit(null)}>Add Record</button>
          </div>
        {/if}
      </div>

      {#if selected.zone_type === 'secondary'}
        <p class="muted zone-help">This is a read-only secondary zone. It is refreshed from: {selected.masters?.join(', ') || 'configured masters'}.</p>
      {/if}

      {#if records.length > 0}
        <div class="row filters">
          <input type="search" placeholder="Filter by Name or Value" bind:value={filterText} />
          <select bind:value={filterType} aria-label="Record type">
            <option value="">All Types</option>
            {#each typesPresent as t (t)}<option value={t}>{t}</option>{/each}
          </select>
          {#if shown.length !== records.length}<span class="muted">Showing {shown.length} of {records.length}</span>{/if}
        </div>
      {/if}

      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              {#if show('type')}<th>Type</th>{/if}
              {#if show('value')}<th>Value</th>{/if}
              {#if show('ttl')}<th class="num">TTL</th>{/if}
              {#if show('status')}<th>Status</th>{/if}
              {#if show('last-used')}<th>Last Used</th>{/if}
              {#if show('last-modified')}<th>Last Modified</th>{/if}
              <th class="num">Actions</th>
            </tr>
          </thead>
          <tbody>
            {#each shown as record (record.id)}
              <tr class:disabled={record.disabled}>
                <td><code title={record.name}>{relativeName(record.name)}</code></td>
                {#if show('type')}<td>{record.rtype}</td>{/if}
                {#if show('value')}<td class="value"><code>{record.content}</code></td>{/if}
                {#if show('ttl')}<td class="num" title={duration(record.ttl)}>{record.ttl}</td>{/if}
                {#if show('status')}
                <td>
                  <span class="pill" class:ok={!record.disabled} title={record.disabled ? 'Not served until enabled' : 'Record is active'}>{record.disabled ? 'Disabled' : 'Enabled'}</span>
                  {#if health[record.id]}
                    <span
                      class="pill"
                      class:ok={health[record.id].healthy}
                      class:bad={!health[record.id].healthy}
                      title={health[record.id].last_error || `${health[record.id].kind.toUpperCase()} check on port ${health[record.id].port}`}
                    >{health[record.id].healthy ? 'Healthy' : 'Down'}{record.priority ? ` · Backup ${record.priority}` : ''}</span>
                  {/if}
                  {#if weights[record.id]}
                    <span class="pill" title="Load balanced: answers hold one address, picked in proportion to the weights">Weight {weights[record.id]}</span>
                  {/if}
                </td>
                {/if}
                {#if show('last-used')}<td class="muted" title={record.last_used_at || ''}>{record.last_used_at ? formatDateTime(record.last_used_at) : 'Never'}</td>{/if}
                {#if show('last-modified')}<td class="muted" title={record.last_modified_at || ''}>{record.last_modified_at ? formatDateTime(record.last_modified_at) : '-'}</td>{/if}
                <td class="num">
                  {#if selected.zone_type !== 'secondary'}
                    <div class="row" style="gap: 6px; justify-content: flex-end; flex-wrap: nowrap">
                      <IconButton icon="edit" label="Edit" onclick={() => startEdit(record)} />
                      {#if record.rtype === 'A' || record.rtype === 'AAAA'}
                        <IconButton icon="health" label="Health check: check this address and fail over when it is down" onclick={() => openHealth(record)} />
                      {/if}
                      <IconButton icon="delete" variant="danger" label="Delete record" onclick={() => removeRecord(record)} />
                    </div>
                  {:else}
                    <span class="muted">Read-Only</span>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      {#if recordsLoading}
        <p class="muted">Loading records...</p>
      {:else if records.length === 0}
        <p class="muted">No records yet. Add one with the Add Record button.</p>
      {:else if shown.length === 0}
        <p class="muted">No records match this filter.</p>
      {/if}
      <p class="muted help">
        Names are shown relative to the zone; <code>@</code> is the zone itself.
        Every change is applied live and increments the zone's serial.
      </p>
    </div>
  {/if}
{/if}

{#if edit}
  <div class="modal-backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && closeEdit()}>
    <div class="modal card" role="dialog" aria-modal="true" aria-labelledby="record-title">
      <form onsubmit={(e) => { e.preventDefault(); saveEdit(); }}>
        <div class="spread modal-title">
          <h3 id="record-title" style="margin: 0">{edit.isNew ? `Add Record - ${selected.name}` : `Edit Record - ${selected.name}`}</h3>
          <button type="button" class="secondary" style="padding: 2px 10px" onclick={closeEdit} aria-label="Close">✕</button>
        </div>
        {#if dialogError}<p class="dialog-error">{dialogError}</p>{/if}
        <div class="grid2">
          <label>Name <input placeholder="www, or @ for {selected.name}" bind:value={edit.name} /></label>
          <label>Type<select bind:value={edit.rtype}>{#each TYPES as t (t)}<option value={t}>{t}</option>{/each}</select></label>
        </div>
        <label class="full">Value <input placeholder={EXAMPLES[edit.rtype]} bind:value={edit.content} /></label>
        {#if (edit.rtype === 'A' || edit.rtype === 'AAAA') && ptrTarget}
          {#if ptrTarget.zone && ptrTarget.zone.zone_type === 'secondary'}
            <p class="muted help">The matching reverse zone <code>{ptrTarget.zone.name}</code> is secondary and read-only; add PTR records on its master.</p>
          {:else}
            <label class="checkbox option">
              <input type="checkbox" bind:checked={edit.updatePtr} />
              <span>
                Update reverse (PTR) record{#if ptrTarget.zone} in <code>{ptrTarget.zone.name}</code>{/if}
              </span>
            </label>
            {#if edit.updatePtr && !ptrTarget.zone}
              <label class="checkbox option">
                <input type="checkbox" bind:checked={edit.createZone} />
                <span>Create reverse zone <code>{defaultReverseZone(ptrTarget.name)}</code> for the PTR record</span>
              </label>
            {/if}
            <p class="muted help">
              The PTR record follows this record: it moves when the address
              or name changes and is removed with it. A PTR record for another
              name at this address is left as it is.
              {#if !ptrTarget.zone && !edit.createZone}No reverse zone covering this address is hosted yet.{/if}
            </p>
          {/if}
        {/if}
        <p class="muted help value-help">
          Format: <code>{EXAMPLES[edit.rtype]}</code>{#if edit.rtype === 'MX' || edit.rtype === 'SRV'} (the priority is the first number){/if}.
          {#if edit.rtype === 'ALIAS'}
            Like a CNAME, but allowed at the zone's own name (<code>@</code>) and
            next to its other records: A and AAAA questions are answered with the
            target's current addresses. The name cannot also have A, AAAA or
            CNAME records, and a DNSSEC-signed zone cannot have ALIAS records.
          {/if}
          {#if edit.rtype === 'AUTOPTR'}
            In a reverse zone: every address under this name without a PTR
            record of its own is answered with the host name the template
            makes, <code>{'{ip}'}</code> becoming the address with dashes
            (<code>ip-192-168-1-47.home.arpa.</code>). Use <code>@</code> to
            cover the whole zone. A DNSSEC-signed zone cannot have AUTOPTR
            records.
          {/if}
          End a host name with a dot when it is a full name.
        </p>
        <div class="grid2" style="margin-top: 10px">
          <label>TTL (Seconds) <span class="hint">{duration(Number(edit.ttl) || 0)}</span><input type="number" min="0" bind:value={edit.ttl} /></label>
          {#if edit.rtype === 'A' || edit.rtype === 'AAAA'}
            <label>Failover Priority <span class="hint">0 = primary</span><input type="number" min="0" bind:value={edit.priority} /></label>
            <label>Load-Balancing Weight <span class="hint">0 = off</span><input type="number" min="0" max="10000" bind:value={edit.weight} /></label>
          {/if}
        </div>
        {#if (edit.rtype === 'A' || edit.rtype === 'AAAA') && Number(edit.weight) > 0}
          <p class="muted help">
            Answers for this name hold one of its weighted addresses, picked
            in proportion to the weights (3 gets three times the share of 1);
            addresses without a weight get none. Failover still leaves out
            addresses that are down. DNSSEC-signed zones always answer with
            every address.
          </p>
        {/if}
        <label class="checkbox option">
          <input type="checkbox" bind:checked={edit.disabled} />
          <span>Disabled (Keep for Later)</span>
        </label>
        <div class="row actions">
          <button type="submit" disabled={saving || !edit.content.trim()}>{saving ? 'Saving...' : edit.isNew ? 'Add Record' : 'Save Record'}</button>
          <button type="button" class="secondary" onclick={closeEdit} disabled={saving}>Cancel</button>
        </div>
      </form>
    </div>
  </div>
{/if}

{#if healthEdit}
  <div class="modal-backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && !saving && (healthEdit = null)}>
    <div class="modal card" role="dialog" aria-modal="true" aria-labelledby="health-title">
      <form onsubmit={(e) => { e.preventDefault(); saveHealth(); }}>
        <div class="spread modal-title">
          <h3 id="health-title" style="margin: 0">Health Check - {relativeName(healthEdit.record.name)} {healthEdit.record.rtype} {healthEdit.record.content}</h3>
          <button type="button" class="secondary" style="padding: 2px 10px" onclick={() => (healthEdit = null)} aria-label="Close">✕</button>
        </div>
        {#if dialogError}<p class="dialog-error">{dialogError}</p>{/if}
        <div class="grid2">
          <label>Check
            <select bind:value={healthEdit.kind}>
              <option value="tcp">TCP Connection</option>
              <option value="http">HTTP Request</option>
              <option value="https">HTTPS Request</option>
            </select>
          </label>
          <label>Port <input type="number" min="1" max="65535" bind:value={healthEdit.port} /></label>
          {#if healthEdit.kind !== 'tcp'}
            <label>Path <input placeholder="/health" bind:value={healthEdit.path} /></label>
            <label>Host Name <input placeholder={relativeName(healthEdit.record.name) === '@' ? selected.name : healthEdit.record.name} bind:value={healthEdit.host} /></label>
          {/if}
          <label>Every (Seconds) <input type="number" min="5" max="86400" bind:value={healthEdit.interval_secs} /></label>
        </div>
        <p class="muted help">
          The address is checked on this schedule; after 2 failures in a row it is
          left out of answers, and it returns after 2 passes. At a name with
          several addresses, only the healthy ones with the lowest Failover
          Priority are served (set a higher priority on a record to make it a
          backup). If every address is down, all are served. HTTP(S) checks pass
          on any status below 400 and do not verify certificates.
        </p>
        <div class="row actions">
          <button type="submit" disabled={saving}>{saving ? 'Saving...' : 'Save Check'}</button>
          {#if healthEdit.exists}
            <button type="button" class="danger" onclick={removeHealth} disabled={saving}>Remove Check</button>
          {/if}
          <button type="button" class="secondary" onclick={() => (healthEdit = null)} disabled={saving}>Cancel</button>
        </div>
      </form>
    </div>
  </div>
{/if}

<style>
  .value-help { margin-top: 8px; }
  .option { flex-direction: row; align-items: center; gap: 8px; margin-top: 10px; }
  .option input { width: auto; }
  .option span { color: var(--text); }
  .picker { margin-bottom: 14px; gap: 10px; align-items: center; }
  .picker-label { font-size: 0.85rem; color: var(--muted); margin: 0; }
  .picker-box { position: relative; flex: 0 1 340px; min-width: 240px; }
  .zone-search {
    width: 100%;
    background: var(--panel-2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 6px 26px 6px 8px;
    font: inherit;
    color: inherit;
  }
  .picker-chevron {
    position: absolute;
    right: 9px;
    top: 50%;
    transform: translateY(-50%);
    pointer-events: none;
    color: var(--muted);
    font-size: 0.8rem;
    transition: transform 0.12s ease;
  }
  .picker-chevron.open { transform: translateY(-50%) rotate(180deg); }
  .picker-list {
    position: absolute;
    top: calc(100% + 4px);
    left: 0;
    right: 0;
    z-index: 20;
    display: flex;
    flex-direction: column;
    gap: 2px;
    max-height: 300px;
    overflow: auto;
    padding: 4px;
    background: var(--panel-2);
    border: 1px solid var(--border);
    border-radius: 8px;
    box-shadow: 0 10px 30px rgb(0 0 0 / 0.4);
  }
  .picker-option {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    background: none;
    border: none;
    border-radius: 6px;
    padding: 7px 8px;
    cursor: pointer;
    color: var(--text);
    font-size: 0.85rem;
    text-align: left;
  }
  .picker-option code { font-size: 0.9rem; }
  .picker-option:hover, .picker-option.sel { background: rgb(91 140 255 / 0.18); }
  .picker-option .pill { margin-left: auto; }
  .picker-empty { padding: 8px; color: var(--muted); font-size: 0.85rem; }
  .notice { margin-bottom: 14px; }
  .notice.ok { border-color: var(--ok); }
  .notice.error { border-color: var(--danger); color: var(--danger); }
  .dialog-error { color: var(--danger); margin: 0 0 10px; }
  .filters { gap: 8px; margin-bottom: 10px; flex-wrap: wrap; }
  .filters input { flex: 0 1 280px; min-width: 180px; }
  .value { word-break: break-all; }
  .full { margin-top: 10px; }
  .modal-backdrop { position: fixed; inset: 0; background: rgb(0 0 0 / 0.65); display: grid; place-items: center; padding: 20px; z-index: 50; }
  .modal { width: min(640px, 100%); max-height: calc(100vh - 40px); overflow: auto; }
  .modal-title { margin-bottom: 12px; }
  .actions { margin-top: 18px; padding-top: 14px; border-top: 1px solid var(--border); }
  .hint { position: absolute; right: 0; top: 0; font-size: 0.75rem; }
  label:has(.hint) { position: relative; }
  .zone-help { margin-top: -4px; }
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; color: var(--muted); }
  @media (max-width: 640px) {
    .grid2 { grid-template-columns: 1fr; }
  }
</style>

<script>
  import { api, formatApiError } from '../api.js';
  import { reverseZoneName } from '../reverseZone.js';
  import { formatDateTime } from '../datetime.svelte.js';
  import { duration } from '../aiLabels.js';

  let { onOpenRecords = () => {} } = $props();

  let zones = $state([]);
  // Server config: supplies the stub and forwarder zones and the default
  // primary nameserver.
  let config = $state(null);
  // Page-level messages: `error` in red, `notice` (success) in green. While a
  // dialog is open its own failures show inside it (`dialogError`), where
  // they can be seen.
  let error = $state(null);
  let notice = $state(null);
  let dialogError = $state(null);
  let showAdd = $state(false);
  let savingZone = $state(false);
  let zoneFileName = $state('');

  // In-progress SOA editor for an existing primary zone, or null when closed.
  let soaEdit = $state(null);
  let savingSoa = $state(false);

  let newZone = $state({
    name: '',
    zone_type: 'primary',
    primary_ns: '',
    admin_mailbox: '',
    serial: 1,
    refresh: 3600,
    retry: 600,
    expire: 86400,
    minimum: 3600,
    serial_date_scheme: false,
    import_text: null,
    mastersText: '',
    refresh_secs: 3600,
    nssText: '',
    upstreamsText: '',
    stubEnabled: true,
    sourcesText: '',
  });
  // Name of the stub/forwarder being edited, or null when adding a zone.
  let editingName = $state(null);

  // Stub and conditional-forwarder zones live in the server settings, not
  // the zone database, so they come from the config rather than /zones.
  const stubs = $derived(config?.authoritative?.stub_zones || []);
  const forwarders = $derived(config?.recursive?.conditional_zones || []);
  // The Secondary ROOT Zone (RFC 8806) is a resolver setting too, with its
  // transfer state from /local-root.
  const localRoot = $derived(config?.recursive?.local_root || null);
  const rootEnabled = $derived(!!localRoot?.enabled);
  let rootStatus = $state(null);
  const rowCount = $derived(zones.length + stubs.length + forwarders.length + (rootEnabled ? 1 : 0));
  const isSettingsZone = $derived(
    newZone.zone_type === 'stub' || newZone.zone_type === 'forwarder' || newZone.zone_type === 'root',
  );
  // Live preview when the Zone Name is a network such as 192.168.0.0/24.
  const reverse = $derived(reverseZoneName(newZone.name));

  async function loadConfig() {
    try {
      config = await api.config();
    } catch {
      // The zone list still works; stub/forwarder rows just stay hidden.
    }
  }

  async function loadRootStatus() {
    try {
      rootStatus = await api.localRoot();
    } catch {
      rootStatus = null;
    }
  }

  async function loadZones() {
    error = null;
    try {
      zones = await api.zones();
    } catch (e) {
      error = formatApiError(e);
    }
  }

  function resetZoneForm() {
    newZone = {
      name: '',
      zone_type: 'primary',
      primary_ns: '',
      admin_mailbox: '',
      serial: 1,
      refresh: 3600,
      retry: 600,
      expire: 86400,
      minimum: 3600,
      serial_date_scheme: false,
      import_text: null,
      mastersText: '',
      refresh_secs: 3600,
      nssText: '',
      upstreamsText: '',
      stubEnabled: true,
      sourcesText: '',
    };
    zoneFileName = '';
    editingName = null;
  }

  function splitLines(text) {
    return (text || '')
      .split(/[\n,]+/)
      .map((value) => value.trim())
      .filter(Boolean);
  }

  function clearMessages() {
    notice = null;
    error = null;
    dialogError = null;
  }

  function openEditStub(stub) {
    clearMessages();
    resetZoneForm();
    editingName = stub.name;
    newZone.zone_type = 'stub';
    newZone.name = stub.name;
    newZone.nssText = stub.nss.join('\n');
    newZone.refresh_secs = stub.refresh_secs;
    newZone.stubEnabled = stub.enabled;
    showAdd = true;
  }

  function openEditRoot() {
    clearMessages();
    resetZoneForm();
    editingName = '.';
    newZone.zone_type = 'root';
    newZone.name = '.';
    newZone.sourcesText = (localRoot?.sources || []).join('\n');
    showAdd = true;
  }

  // The root zone has no name of its own to type.
  function chooseZoneType() {
    if (newZone.zone_type === 'root') newZone.name = '.';
    else if (newZone.name === '.') newZone.name = '';
  }

  async function refreshRoot() {
    clearMessages();
    try {
      await api.refreshLocalRoot();
      notice = 'Checking the root zone sources for a newer copy.';
      setTimeout(loadRootStatus, 2000);
    } catch (e) {
      error = formatApiError(e);
    }
  }

  function openEditForwarder(fwd) {
    clearMessages();
    resetZoneForm();
    editingName = fwd.name;
    newZone.zone_type = 'forwarder';
    newZone.name = fwd.name;
    newZone.upstreamsText = fwd.upstreams.join('\n');
    showAdd = true;
  }

  // Save a stub or forwarder by replacing that whole list in the settings.
  // The list is re-read first so a concurrent change is not overwritten.
  async function saveSettingsZone(name) {
    const fresh = await api.config();
    const key = (n) => n.trim().replace(/\.$/, '').toLowerCase();
    const others = (list) => list.filter((z) => key(z.name) !== key(editingName || name));
    if (newZone.zone_type === 'root') {
      if (editingName === null && fresh.recursive?.local_root?.enabled) {
        throw new Error('A Secondary ROOT Zone already exists');
      }
      await api.updateSettings({
        recursive: { local_root: { enabled: true, sources: splitLines(newZone.sourcesText) } },
      });
    } else if (newZone.zone_type === 'stub') {
      const list = others(fresh.authoritative?.stub_zones || []);
      if (list.some((z) => key(z.name) === key(name))) throw new Error(`A stub zone named ${name} already exists`);
      list.push({
        name,
        nss: splitLines(newZone.nssText),
        refresh_secs: Number(newZone.refresh_secs) || 3600,
        enabled: newZone.stubEnabled,
      });
      await api.updateSettings({ authoritative: { stub_zones: list } });
    } else {
      const list = others(fresh.recursive?.conditional_zones || []);
      if (list.some((z) => key(z.name) === key(name))) throw new Error(`A conditional forwarder for ${name} already exists`);
      list.push({ name, upstreams: splitLines(newZone.upstreamsText) });
      await api.updateSettings({ recursive: { conditional_zones: list } });
    }
  }

  async function removeSettingsZone(kind, name) {
    const message = {
      stub: `Delete stub zone ${name}?`,
      forwarder: `Delete conditional forwarder ${name}?`,
      root: 'Delete the Secondary ROOT Zone? Root queries go back to the root servers.',
    }[kind];
    if (!confirm(message)) return;
    clearMessages();
    try {
      const fresh = await api.config();
      if (kind === 'root') {
        const sources = fresh.recursive?.local_root?.sources || [];
        await api.updateSettings({ recursive: { local_root: { enabled: false, sources } } });
        rootStatus = null;
      } else if (kind === 'stub') {
        const list = (fresh.authoritative?.stub_zones || []).filter((z) => z.name !== name);
        await api.updateSettings({ authoritative: { stub_zones: list } });
      } else {
        const list = (fresh.recursive?.conditional_zones || []).filter((z) => z.name !== name);
        await api.updateSettings({ recursive: { conditional_zones: list } });
      }
      notice = kind === 'root' ? 'Secondary ROOT Zone deleted.' : `Zone ${name} deleted.`;
      await loadConfig();
    } catch (e) {
      error = formatApiError(e);
    }
  }

  // SOA values a new zone gets when left alone (Settings, else this
  // server's host name and the first administrator's email).
  let zoneDefaults = $state(null);

  async function openAddZone() {
    clearMessages();
    resetZoneForm();
    showAdd = true;
    try {
      zoneDefaults = await api.zoneDefaults();
    } catch {
      zoneDefaults = null;
    }
    // Pre-fill, so the values the zone will get are visible and editable.
    if (!newZone.primary_ns) newZone.primary_ns = zoneDefaults?.primary_ns || '';
    if (!newZone.admin_mailbox) {
      newZone.admin_mailbox = zoneDefaults?.admin_email || zoneDefaults?.admin_mailbox || '';
    }
  }

  // jane\.doe.example.com. -> jane.doe@example.com when the split is clear
  // (mirrors the server's rname_to_email), else the SOA form unchanged.
  function mailboxForDisplay(rname) {
    const text = (rname || '').trim().replace(/\.$/, '');
    let local = '';
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (c === '\\' && i + 1 < text.length) local += text[++i];
      else if (c === '.') {
        const domain = text.slice(i + 1);
        return local && domain.includes('.') ? `${local}@${domain}` : rname;
      } else local += c;
    }
    return rname;
  }

  function closeAddZone() {
    if (!savingZone) showAdd = false;
  }

  function openSoa(zone) {
    clearMessages();
    soaEdit = {
      zone,
      primary_ns: zone.primary_ns || '',
      admin_mailbox: mailboxForDisplay(zone.admin_mailbox || ''),
      serial: zone.serial,
      refresh: zone.refresh,
      retry: zone.retry,
      expire: zone.expire,
      minimum: zone.minimum,
      bumpSerial: true,
    };
  }

  function closeSoa() {
    if (!savingSoa) soaEdit = null;
  }

  async function saveSoa() {
    if (!soaEdit) return;
    const form = soaEdit;
    savingSoa = true;
    dialogError = null;
    try {
      const body = {
        primary_ns: form.primary_ns.trim(),
        admin_mailbox: form.admin_mailbox.trim(),
        refresh: Number(form.refresh) || form.refresh,
        retry: Number(form.retry) || form.retry,
        expire: Number(form.expire) || form.expire,
        minimum: Number(form.minimum) || form.minimum,
        bump_serial: form.bumpSerial,
      };
      if (!form.bumpSerial) body.serial = Number(form.serial) || form.serial;
      await api.updateZoneSoa(form.zone.id, body);
      soaEdit = null;
      notice = `SOA for ${form.zone.name} saved and applied live.`;
      await loadZones();
    } catch (e) {
      dialogError = formatApiError(e);
    } finally {
      savingSoa = false;
    }
  }

  async function chooseZoneFile(event) {
    const file = event.currentTarget.files?.[0];
    if (!file) return;
    zoneFileName = file.name;
    // Pre-filled defaults would override the file's own SOA; clear any the
    // user has not changed.
    if (newZone.primary_ns === (zoneDefaults?.primary_ns || '')) newZone.primary_ns = '';
    if ([zoneDefaults?.admin_email, zoneDefaults?.admin_mailbox].includes(newZone.admin_mailbox)) newZone.admin_mailbox = '';
    try {
      newZone.import_text = await file.text();
    } catch (e) {
      newZone.import_text = null;
      dialogError = `Could not read ${file.name}: ${e.message || e}`;
    }
  }

  async function createZone() {
    dialogError = null;
    if (reverse?.error) {
      dialogError = reverse.error;
      return;
    }
    const name = reverse?.name || newZone.name.trim();
    if (!name) {
      dialogError = 'Enter a zone name.';
      return;
    }
    if (isSettingsZone) {
      if (newZone.zone_type === 'stub' && newZone.stubEnabled && splitLines(newZone.nssText).length === 0) {
        dialogError = 'Add at least one nameserver for the stub zone.';
        return;
      }
      if (newZone.zone_type === 'forwarder' && splitLines(newZone.upstreamsText).length === 0) {
        dialogError = 'Add at least one upstream server for the forwarder.';
        return;
      }
      savingZone = true;
      const newZoneWasRoot = newZone.zone_type === 'root';
      try {
        const editing = editingName !== null;
        await saveSettingsZone(name);
        showAdd = false;
        resetZoneForm();
        notice = editing ? `Zone ${name} updated and applied live.` : `Zone ${name} created and applied live.`;
        await loadConfig();
        if (newZoneWasRoot && !editing) {
          notice = 'Secondary ROOT Zone added. The root zone is being transferred and verified.';
          await loadRootStatus();
        }
      } catch (e) {
        dialogError = formatApiError(e);
      } finally {
        savingZone = false;
      }
      return;
    }
    const masters = newZone.mastersText
      .split(/[\n,]+/)
      .map((value) => value.trim())
      .filter(Boolean);
    if (newZone.zone_type === 'secondary' && masters.length === 0) {
      dialogError = 'Add at least one master server for a secondary zone.';
      return;
    }
    savingZone = true;
    const createdType = newZone.zone_type;
    try {
      await api.createZone({
        name,
        zone_type: newZone.zone_type,
        primary_ns: newZone.primary_ns.trim() || null,
        admin_mailbox: newZone.admin_mailbox.trim() || null,
        serial: newZone.serial_date_scheme ? null : Number(newZone.serial) || 1,
        refresh: Number(newZone.refresh) || 3600,
        retry: Number(newZone.retry) || 600,
        expire: Number(newZone.expire) || 86400,
        minimum: Number(newZone.minimum) || 3600,
        serial_date_scheme: newZone.serial_date_scheme,
        import_text: newZone.import_text,
        masters,
        refresh_secs: Number(newZone.refresh_secs) || 3600,
      });
      showAdd = false;
      resetZoneForm();
      notice =
        createdType === 'secondary'
          ? `Zone ${name} created. Its records are being transferred from the master.`
          : `Zone ${name} created. Add its records on the Records tab.`;
      await loadZones();
    } catch (e) {
      dialogError = formatApiError(e);
    } finally {
      savingZone = false;
    }
  }

  async function removeZone(zone) {
    if (!confirm(`Delete zone ${zone.name} and all its records? Export it first if you may need it again.`)) return;
    clearMessages();
    try {
      await api.deleteZone(zone.id);
      notice = `Zone ${zone.name} deleted.`;
      await loadZones();
    } catch (e) {
      error = formatApiError(e);
    }
  }

  async function toggleSign(zone) {
    // Unsigning while the parent zone still publishes a DS record makes the
    // zone fail validation everywhere, so say so before doing it.
    if (
      zone.dnssec &&
      !confirm(
        `Stop signing ${zone.name}? If the parent zone has a DS record for it, remove that first, or validating resolvers will treat the zone as bogus.`,
      )
    ) {
      return;
    }
    clearMessages();
    try {
      if (zone.dnssec) {
        await api.unsignZone(zone.id);
        notice = `${zone.name} is no longer signed.`;
      } else {
        await api.signZone(zone.id);
        notice = `${zone.name} is now signed. Publish its DS record at the parent zone to complete the chain of trust.`;
      }
      await loadZones();
    } catch (e) {
      error = formatApiError(e);
    }
  }

  // Download the zone as a BIND-style zone file (a full backup that imports
  // back through Add Zone).
  async function exportZone(zone) {
    clearMessages();
    try {
      const text = await api.exportZone(zone.id);
      const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = `${zone.name}.zone`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) {
      error = formatApiError(e);
    }
  }

  // DNS Server Domain (Settings -> Zones) pre-fills and
  // placeholders the SOA Primary Nameserver for new zones.
  let dnsServerDomain = $derived(zoneDefaults?.primary_ns || config?.authoritative?.default_primary_ns || '');

  $effect(() => {
    loadZones();
    loadConfig();
    loadRootStatus();
  });

  // While the root zone is being fetched, check on it every few seconds.
  $effect(() => {
    if (!rootEnabled || rootStatus?.serving || rootStatus?.last_error) return;
    const timer = setInterval(loadRootStatus, 3000);
    return () => clearInterval(timer);
  });

  function formatTime(value) {
    return value ? formatDateTime(value) : '-';
  }

  // "3600" -> "1 Hour", shown beside the seconds fields.
  function hint(secs) {
    const n = Number(secs);
    return Number.isInteger(n) && n > 0 ? duration(n) : '';
  }
</script>

{#if notice}
  <div class="card notice ok">{notice}</div>
{/if}
{#if error}
  <div class="card notice error">{error}</div>
{/if}

<div class="card">
  <div class="spread" style="margin-bottom: 10px">
    <h3 style="margin: 0">Zones ({rowCount})</h3>
    <button onclick={openAddZone}>Add Zone</button>
  </div>
  <div class="table-wrap">
    <table>
      <thead>
        <tr><th>Name</th><th>Type</th><th>Details</th><th>DNSSEC</th><th class="num">Actions</th></tr>
      </thead>
      <tbody>
        {#each zones as zone (zone.id)}
          <tr>
            <td><code>{zone.name}</code></td>
            <td><span class="pill">{zone.zone_type === 'secondary' ? 'Secondary' : 'Primary'}</span></td>
            <td class="muted">
              Serial {zone.serial}{#if zone.zone_type === 'secondary' && zone.masters?.length}{` · from ${zone.masters.join(', ')}`}{/if}
            </td>
            <td><span class:pill={true} class:ok={zone.dnssec}>{zone.dnssec ? 'Signed' : 'Unsigned'}</span></td>
            <td class="num">
              <div class="row" style="gap: 6px; justify-content: flex-end">
                <button class="secondary" onclick={() => onOpenRecords(zone.id)}>Records</button>
                {#if zone.zone_type !== 'secondary'}
                  <button class="secondary" onclick={() => openSoa(zone)} title="Edit the zone's SOA (nameserver, contact, timers)">SOA</button>
                  <button class="secondary" onclick={() => toggleSign(zone)} title={zone.dnssec ? 'Stop DNSSEC signing' : 'Sign the zone with DNSSEC'}>{zone.dnssec ? 'Unsign' : 'Sign'}</button>
                {/if}
                <button class="secondary" onclick={() => exportZone(zone)} title="Download as a zone file">Export</button>
                <button class="danger" onclick={() => removeZone(zone)} aria-label="Delete {zone.name}">✕</button>
              </div>
            </td>
          </tr>
        {/each}
        {#each stubs as stub (stub.name)}
          <tr class:disabled={!stub.enabled}>
            <td><code>{stub.name}</code></td>
            <td>
              <span class="pill">Stub</span>
              {#if !stub.enabled}<span class="pill">Disabled</span>{/if}
            </td>
            <td class="muted">NS {stub.nss.join(', ') || '-'}</td>
            <td class="muted">-</td>
            <td class="num">
              <div class="row" style="gap: 6px; justify-content: flex-end">
                <button class="secondary" onclick={() => openEditStub(stub)}>Edit</button>
                <button class="danger" onclick={() => removeSettingsZone('stub', stub.name)} aria-label="Delete {stub.name}">✕</button>
              </div>
            </td>
          </tr>
        {/each}
        {#if rootEnabled}
          <tr>
            <td><code>.</code></td>
            <td><span class="pill" style="white-space: nowrap">Secondary ROOT</span></td>
            <td class="muted">
              {#if rootStatus?.serving}
                <span title={`Last checked ${formatTime(rootStatus.last_checked)} · from ${rootStatus.source}`}>
                  Serial {rootStatus.serial} · {rootStatus.tlds} TLDs
                </span>
              {:else if rootStatus?.last_error}
                <span style="color: var(--danger)">Not in Use: {rootStatus.last_error}</span>
              {:else}
                Transferring and Verifying the Root Zone…
              {/if}
            </td>
            <td>
              {#if rootStatus?.serving}
                <span class="pill ok" title="ZONEMD digest and DNSSEC signatures verified">Verified</span>
              {:else}
                <span class="muted">-</span>
              {/if}
            </td>
            <td class="num">
              <div class="row" style="gap: 6px; justify-content: flex-end">
                <button class="secondary" onclick={refreshRoot}>Refresh</button>
                <button class="secondary" onclick={openEditRoot}>Edit</button>
                <button class="danger" onclick={() => removeSettingsZone('root', '.')} aria-label="Delete the Secondary ROOT Zone">✕</button>
              </div>
            </td>
          </tr>
        {/if}
        {#each forwarders as fwd (fwd.name)}
          <tr>
            <td><code>{fwd.name}</code></td>
            <td><span class="pill">Forwarder</span></td>
            <td class="muted">→ {fwd.upstreams.join(', ')}</td>
            <td class="muted">-</td>
            <td class="num">
              <div class="row" style="gap: 6px; justify-content: flex-end">
                <button class="secondary" onclick={() => openEditForwarder(fwd)}>Edit</button>
                <button class="danger" onclick={() => removeSettingsZone('forwarder', fwd.name)} aria-label="Delete {fwd.name}">✕</button>
              </div>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
  {#if rowCount === 0}
    <p class="muted">
      No zones yet. Add a primary zone to serve your own records, or a
      secondary, stub or forwarder zone for names hosted elsewhere.
    </p>
  {/if}
</div>

{#if showAdd}
  <div class="modal-backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && closeAddZone()}>
    <div class="modal card" role="dialog" aria-modal="true" aria-labelledby="add-zone-title">
      <div class="spread modal-title">
        <h3 id="add-zone-title" style="margin: 0">{editingName ? `Edit Zone - ${editingName}` : 'Add Zone'}</h3>
        <button class="secondary" style="padding: 2px 10px" onclick={closeAddZone} aria-label="Close">✕</button>
      </div>
      {#if dialogError}<p class="dialog-error">{dialogError}</p>{/if}

      <div class="grid2">
        <label>Zone Name <input placeholder="example.com or 192.168.0.0/24" bind:value={newZone.name} disabled={newZone.zone_type === 'root'} /></label>
        <label>Zone Type
          <select bind:value={newZone.zone_type} onchange={chooseZoneType} disabled={editingName !== null}>
            <option value="primary">Primary Zone</option>
            <option value="secondary">Secondary Zone</option>
            <option value="stub">Stub Zone</option>
            <option value="forwarder">Conditional Forwarder Zone</option>
            <option value="root" disabled={rootEnabled && editingName === null}>Secondary ROOT Zone</option>
          </select>
        </label>
      </div>
      {#if reverse?.name}
        <p class="muted help">Creates the reverse zone <code>{reverse.name}</code>.</p>
      {:else if reverse?.error}
        <p class="help" style="color: var(--danger)">{reverse.error}</p>
      {/if}

      {#if newZone.zone_type === 'stub'}
        <div class="section-title">Stub Nameservers</div>
        <label>Nameservers <textarea rows="3" placeholder={'192.0.2.53\nns1.branch.example.com'} bind:value={newZone.nssText}></textarea></label>
        <div class="grid2">
          <label>Refresh Interval (Seconds) <span class="hint">{hint(newZone.refresh_secs)}</span><input type="number" min="60" bind:value={newZone.refresh_secs} /></label>
          <label class="checkbox"><input type="checkbox" bind:checked={newZone.stubEnabled} /><span>Enabled</span></label>
        </div>
        <p class="muted help">
          Queries for this zone go straight to its own nameservers instead of the
          upstreams. Use IPs, IP:port, or hostnames (resolved when the zone is
          applied). One per line.
        </p>
      {:else if newZone.zone_type === 'root'}
        <div class="section-title">Root Zone Sources</div>
        <label>Transfer Servers <textarea rows="3" placeholder={'Leave empty for the IANA defaults\n(ICANN transfer servers and root servers b, c, d, f, g, k)'} bind:value={newZone.sourcesText}></textarea></label>
        <p class="muted help">
          Keeps a local copy of the root zone (RFC 8806), transferred over AXFR
          and accepted only when its ZONEMD digest and DNSSEC signatures verify
          against the root trust anchor. In recursive mode root queries are
          answered from it; in forwarding mode names under top-level domains
          that do not exist are answered NXDOMAIN without asking the upstreams
          (use a conditional forwarder for private TLDs such as
          <code>.lan</code>). Refreshed on the zone's own schedule; a copy
          that cannot be refreshed for a week stops being used. Use IP,
          IP:port or [IPv6]:port, one per line.
        </p>
      {:else if newZone.zone_type === 'forwarder'}
        <div class="section-title">Forwarder Upstreams</div>
        <label>Upstream Servers <textarea rows="3" placeholder={'10.0.0.53\ntls://10.0.0.53:853@dns.corp.example'} bind:value={newZone.upstreamsText}></textarea></label>
        <p class="muted help">
          Queries for this zone and its subdomains are resolved through these
          servers instead of the default upstreams. Accepts the same forms as
          Settings → Resolver. One per line.
        </p>
      {:else}
      <div class="section-title">SOA Settings</div>
      <div class="grid2">
        <label>Primary Nameserver <input placeholder={dnsServerDomain || 'ns1.example.com.'} bind:value={newZone.primary_ns} /></label>
        <label>Administrator Email <input placeholder={`admin@${newZone.name.trim().replace(/\.$/, '') || 'example.com'}`} bind:value={newZone.admin_mailbox} /></label>
        <label>Serial <input type="number" min="1" bind:value={newZone.serial} disabled={newZone.serial_date_scheme} /></label>
        <label class="checkbox"><input type="checkbox" bind:checked={newZone.serial_date_scheme} /><span>Date-Based Serial (YYYYMMDDnn)</span></label>
        <label>Refresh (Seconds) <span class="hint">{hint(newZone.refresh)}</span><input type="number" min="1" bind:value={newZone.refresh} /></label>
        <label>Retry (Seconds) <span class="hint">{hint(newZone.retry)}</span><input type="number" min="1" bind:value={newZone.retry} /></label>
        <label>Expire (Seconds) <span class="hint">{hint(newZone.expire)}</span><input type="number" min="1" bind:value={newZone.expire} /></label>
        <label>Minimum TTL (Seconds) <span class="hint">{hint(newZone.minimum)}</span><input type="number" min="1" bind:value={newZone.minimum} /></label>
      </div>
      <p class="muted help">
        Pre-filled from Settings → Zones, or when those are
        empty, this server's name and the first administrator's email. The
        timers tell secondary servers how often to check for changes; the
        defaults suit most zones.
      </p>

      {#if newZone.zone_type === 'secondary'}
        <div class="section-title">Secondary Masters</div>
        <label>Master Servers <textarea rows="3" placeholder="192.0.2.10&#10;192.0.2.11:5353" bind:value={newZone.mastersText}></textarea></label>
        <label>Refresh Interval (Seconds) <span class="hint">{hint(newZone.refresh_secs)}</span><input type="number" min="1" bind:value={newZone.refresh_secs} /></label>
        <p class="muted help">The first reachable master is used for AXFR/IXFR. Secondary records are read-only and refresh automatically.</p>
      {:else}
        <div class="section-title">Import (Optional)</div>
        <label>Import Zone File
          <input type="file" accept=".zone,.db,.txt,text/plain" onchange={chooseZoneFile} />
        </label>
        {#if zoneFileName}
          <p class="muted help">Selected: {zoneFileName}. SOA values found in the file will be used unless you override them above.</p>
        {:else}
          <p class="muted help">A BIND-style zone file, such as one downloaded with Export. Leave empty to start with an empty zone.</p>
        {/if}
      {/if}
      {/if}

      <div class="row actions">
        <button onclick={createZone} disabled={savingZone || !newZone.name.trim()}>
          {savingZone ? 'Saving…' : editingName ? 'Save Zone' : 'Create Zone'}
        </button>
        <button class="secondary" onclick={closeAddZone} disabled={savingZone}>Cancel</button>
      </div>
    </div>
  </div>
{/if}

{#if soaEdit}
  <div class="modal-backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && closeSoa()}>
    <div class="modal card" role="dialog" aria-modal="true" aria-labelledby="edit-soa-title">
      <div class="spread modal-title">
        <h3 id="edit-soa-title" style="margin: 0">Edit SOA - {soaEdit.zone.name}</h3>
        <button class="secondary" style="padding: 2px 10px" onclick={closeSoa} aria-label="Close">✕</button>
      </div>
      {#if dialogError}<p class="dialog-error">{dialogError}</p>{/if}

      <div class="section-title">SOA Parameters</div>
      <div class="grid2">
        <label>Primary Nameserver <input placeholder={dnsServerDomain || 'ns1.example.com.'} bind:value={soaEdit.primary_ns} /></label>
        <label>Administrator Email <input placeholder="hostmaster@example.com" bind:value={soaEdit.admin_mailbox} /></label>
        <label>Serial <input type="number" min="1" bind:value={soaEdit.serial} disabled={soaEdit.bumpSerial} /></label>
        <label class="checkbox"><input type="checkbox" bind:checked={soaEdit.bumpSerial} /><span>Increment Serial on Save</span></label>
        <label>Refresh (Seconds) <span class="hint">{hint(soaEdit.refresh)}</span><input type="number" min="1" bind:value={soaEdit.refresh} /></label>
        <label>Retry (Seconds) <span class="hint">{hint(soaEdit.retry)}</span><input type="number" min="1" bind:value={soaEdit.retry} /></label>
        <label>Expire (Seconds) <span class="hint">{hint(soaEdit.expire)}</span><input type="number" min="1" bind:value={soaEdit.expire} /></label>
        <label>Minimum TTL (Seconds) <span class="hint">{hint(soaEdit.minimum)}</span><input type="number" min="1" bind:value={soaEdit.minimum} /></label>
      </div>
      {#if soaEdit.bumpSerial}
        <p class="muted help">The serial is incremented automatically so downstream secondaries and transfers pick up the change.</p>
      {:else}
        <p class="muted help">Serial is set exactly to the value above. Prefer automatic increments unless you know the zone's history.</p>
      {/if}

      <div class="row actions">
        <button onclick={saveSoa} disabled={savingSoa}>{savingSoa ? 'Saving…' : 'Save SOA'}</button>
        <button class="secondary" onclick={closeSoa} disabled={savingSoa}>Cancel</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .notice { margin-bottom: 14px; }
  .notice.ok { border-color: var(--ok); }
  .notice.error { border-color: var(--danger); color: var(--danger); }
  .dialog-error { color: var(--danger); margin: 0 0 10px; }
  /* The friendly duration beside a seconds field, e.g. "1 Hour". */
  .hint { position: absolute; right: 0; top: 0; font-size: 0.75rem; }
  label:has(.hint) { position: relative; }
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; color: var(--muted); }
  .modal-backdrop { position: fixed; inset: 0; background: rgb(0 0 0 / 0.65); display: grid; place-items: center; padding: 20px; z-index: 10; }
  .modal { width: min(760px, 100%); max-height: calc(100vh - 40px); overflow: auto; }
  .modal-title { margin-bottom: 12px; }
  /* Matches the Users dialog section headings. */
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
  .checkbox { flex-direction: row; align-items: center; gap: 8px; padding-top: 22px; }
  .checkbox input { width: auto; }
  .checkbox span { color: var(--text); }
  .actions { margin-top: 22px; padding-top: 14px; border-top: 1px solid var(--border); }
  @media (max-width: 640px) {
    .grid2 { grid-template-columns: 1fr; }
  }
</style>
